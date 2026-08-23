using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task 14c of A4-minimal: the Application send path - the ACK RFC 9000 s13.2.1 has always
// required, the PATH_RESPONSE task 9b could record and not emit, and the pump entry that can
// send without receiving first.
//
// THE SAME PARTIAL CLASS AS 9a-ii's AND 9b's, for the reason those two give: Spec, Connection,
// TlsClient and Server are reused rather than copied, and a copy of any of them would be a
// second packet writer, which this phase bans by name.
//
// ============================================================================
// WHAT THESE ASSERTIONS PIN, AND WHAT THEY CANNOT.
// ============================================================================
//
//   THE PEER OPENING OUR 1-RTT PACKET PROVES SEQUENCING, NOT BYTES. LoopbackQuicPeer writes
//   its own short header by hand precisely so that it is not TlsQuicPacketBuilder's - see the
//   note on BuildShortHeaderDatagram - but both halves still share TlsQuicPacketHeader,
//   TlsQuicHeaderProtection and TlsQuicPacketProtection, and RFC 9001 Appendix A publishes NO
//   1-RTT vector. A defect in the sample offset or the nonce that is symmetric across those
//   three cancels exactly here, and task 7's inverted AEAD nonce - which killed 0 of 11
//   loopback tests and 18 elsewhere - is the measured precedent. The byte-level evidence for
//   a short header lives in TlsQuicPacketHeaderTests and TlsQuicPacketBuilderTests, against
//   hand-derived layouts read off s17.3.1.
//
//   THE PACKET NUMBER ROUND TRIP IS NOT SYMMETRIC, AND THAT IS THE STRONGEST THING HERE. The
//   number this connection chose is read back off three independent places: its own counter,
//   the peer's view of what it opened, and - after the peer's ACK - the connection's own
//   Application-space largest-acknowledged, which is TlsQuicAckTracker's and not the packet
//   layer's. A packet layer that agreed with itself about the wrong number would still have
//   to carry that number through s19.3's ACK encoding and back.
public sealed partial class TlsQuicConnectionTests
{
    [Fact]
    public async Task AOneRttPacketThisConnectionSentIsAcknowledgedByTheLoopbackPeer()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // NOTHING ACKNOWLEDGED IN THE APPLICATION SPACE YET, which is what stops the last
        // assertion in this test from reading a value that was already there. RFC 9000 s12.3
        // gives 0-RTT and 1-RTT one space, and nothing has been sent in it.
        Assert.Null(connection.LargestAcknowledged(TlsQuicEncryptionLevel.Application));

        var oneRtt = connection.NextPacketNumber(TlsQuicEncryptionLevel.Application);
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // RFC 9000 s13.2.1's MUST, met at last: an ack-eliciting 1-RTT packet arrived and this
        // connection answered it in the same pump. s12.3 forbids reusing a number in a space,
        // so the counter moves by exactly one.
        Assert.Equal(oneRtt + 1, connection.NextPacketNumber(TlsQuicEncryptionLevel.Application));

        // AND THE PEER OPENS IT. False because the peer has no CRYPTO data to answer with -
        // this datagram carries an ACK and nothing else - and opening it at all means the
        // short header parsed, RFC 9001 s5.4's header protection came off at the right offset,
        // and s5.3's AEAD verified the header it covers as associated data.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(oneRtt, serverPeer.LargestApplicationPacketNumberReceived);
        Assert.Contains(
            (TlsQuicEncryptionLevel.Application, TlsQuicFrameType.Ack),
            serverPeer.LastDatagramFrames);

        // THE ROUND TRIP CLOSES HERE. The peer acknowledges the number it saw, in a 1-RTT
        // packet of its own, and this connection's Application-space largest-acknowledged -
        // TlsQuicAckTracker's, moved by ProcessAckFrame - becomes the number it chose.
        await serverPeer.SendAckAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(oneRtt, connection.LargestAcknowledged(TlsQuicEncryptionLevel.Application));

        // THE THREE BITS OF OUR SHORT HEADER THAT ARE NOT UNDER HEADER PROTECTION, READ OFF
        // THE WIRE. RFC 9001 s5.4.1 masks "the least significant five bits of byte 0" of a
        // short header, so bits 0x80, 0x40 and 0x20 arrive in the clear and are the ONLY
        // byte-level evidence about a 1-RTT packet available without keys. RFC 9000 s17.3.1
        // names all three: Header Form is 0 for a short header, the Fixed Bit is 1 - "Packets
        // containing a zero value for this bit are not valid packets in this version" - and
        // the Latency Spin Bit (s17.4) is 0, which is this connection's stated choice rather
        // than a value anything derives.
        var oneRttDatagram = clientTransport.Sent[^1];
        Assert.Equal(0x00, oneRttDatagram[0] & 0x80);
        Assert.Equal(0x40, oneRttDatagram[0] & 0x40);
        Assert.Equal(0x00, oneRttDatagram[0] & 0x20);

        // AND NOTHING WENT BACK OUT FOR IT. RFC 9000 s13.2.1: "An endpoint MUST NOT send a
        // non-ack-eliciting packet in response to a non-ack-eliciting packet, even if there
        // are packet gaps that precede the received packet. This avoids an infinite feedback
        // loop of acknowledgments." An ACK-only packet is exactly that case, and this
        // assertion is the loop not starting.
        Assert.Equal(oneRtt + 1, connection.NextPacketNumber(TlsQuicEncryptionLevel.Application));
    }

    [Fact]
    public async Task OnlyOneHandshakeDoneArrivesBecauseTheOneRttPacketIsAcknowledged()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // THE COUNTER THAT MEASURED THE VIOLATION IS THE ONE THAT SHOULD NOW SIT AT ONE. Task
        // 13's live run recorded tls3.peet.ws sending seven HANDSHAKE_DONE frames in 14.9
        // seconds against the version of this connection that never acknowledged a 1-RTT
        // packet. LoopbackQuicPeer does not retransmit, so this asserts the counter's meaning
        // rather than a server's patience - the retransmission half is only observable against
        // a real endpoint, which is task 13's harness and not this one.
        Assert.Equal(1, connection.HandshakeDoneFramesReceived);
        Assert.True(connection.IsHandshakeConfirmed);
    }

    // BOTH ROWS OF TlsQuicConnectionSpec.AckLeadsInPacket, because the knob defaults to true
    // and a single row cannot tell an honoured knob from a hardcoded lead. It is the same knob
    // the long-header answer already honours; this is the 1-RTT packet claiming it too, and
    // the frame order inside a packet is only visible from the receiving side because the AEAD
    // closes over it.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task APathChallengeIsAnsweredWithAPathResponseInAOneRttPacket(bool ackLeads)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = Spec().PaddingTarget,
            SourceConnectionIdLength = Spec().SourceConnectionIdLength,
            AckLeadsInPacket = ackLeads,
        };
        await using var connection = Connection(clientTransport, serverTransport, pki, spec);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // NOTHING PENDING AND NOTHING ANSWERED UNTIL ONE ARRIVES, which is what stops the
        // assertions below from reading a field's own initialiser.
        Assert.Null(connection.PendingPathResponseData);
        Assert.Null(serverPeer.LastPathResponseData);

        // RFC 9000 s12.4 Table 3 gives PATH_CHALLENGE the row "__01": a server can only put one
        // in a 1-RTT packet, so it rides beside HANDSHAKE_DONE in the only 1-RTT packet this
        // peer builds. The eight bytes exist nowhere else.
        var challenge = Convert.FromHexString("0011223344556677");
        var sentBefore = clientTransport.Sent.Count;
        await serverPeer.SendHandshakeDoneAsync(
            SentAt, cancellation.Token, pathChallengeData: challenge);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // AND THE ANSWER GOES OUT. THIS ASSERTION WAS INVERTED BY A4 TASK 14c; UNTIL THEN IT
        // READ `Assert.Equal(sentBefore, clientTransport.Sent.Count)` AND ITS REASON WAS THAT
        // Table 3 GIVES PATH_RESPONSE THE ROW "___1" - a 1-RTT packet and nothing else - WHILE
        // TlsQuicPacketBuilder BUILT NO SHORT HEADER. Task 14b built one. The reason is gone,
        // so the assertion is the other way round rather than deleted: what used to be a
        // knowingly violated MUST is now the behaviour, and the row it was recorded under is
        // the thing a reader should be able to find changing.
        Assert.Equal(sentBefore + 1, clientTransport.Sent.Count);

        // RFC 9000 s19.17: "The recipient of this frame MUST generate a PATH_RESPONSE frame
        // (Section 19.18) containing the same Data value, unless constrained by congestion
        // control." NOT PENDING ANY MORE, because it was answered rather than dropped - the
        // two are distinguished by the peer's copy below and not by this line alone.
        Assert.Null(connection.PendingPathResponseData);

        // THE EIGHT BYTES ARRIVE, BYTE FOR BYTE, AT A PEER THAT DID NOT BUILD THE PACKET. This
        // is the assertion the whole inversion is for: s19.18 makes PATH_RESPONSE's Data the
        // echo of the challenge, and the value came off a frame that aliased our receiver's
        // scratch, went through the send path, and came back out of the peer's.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(challenge, serverPeer.LastPathResponseData!.Value.ToArray());

        // IN WIRE ORDER, WHICH IS WHAT THE KNOB DECIDES. An Assert.Contains here would pass
        // against a 1-RTT packet that hardcoded the ACK first, and the ACK's position is a
        // TlsQuicConnectionSpec dimension that task 11 reports - a knob the connection fixes
        // is a knob the readout cannot report.
        Assert.Equal(
            ackLeads
                ? new[]
                {
                    (TlsQuicEncryptionLevel.Application, TlsQuicFrameType.Ack),
                    (TlsQuicEncryptionLevel.Application, TlsQuicFrameType.PathResponse),
                }
                : [
                    (TlsQuicEncryptionLevel.Application, TlsQuicFrameType.PathResponse),
                    (TlsQuicEncryptionLevel.Application, TlsQuicFrameType.Ack),
                ],
            serverPeer.LastDatagramFrames);

        // AND IT IS ANSWERED ONCE. A4-minimal has no retransmission at all, and RFC 9000
        // s13.3's loss rules do not resend a PATH_RESPONSE anyway; a second send here would
        // mean the record was never cleared.
        Assert.False(await connection.SendPendingAsync(cancellation.Token));
        Assert.Equal(sentBefore + 1, clientTransport.Sent.Count);
    }

    // BOTH ROWS OF TlsQuicConnectionSpec.CoalesceAscendingByLevel, and the FALSE one is the
    // reason this test exists: with it false the answer's long-header packets are ordered
    // Handshake-then-Initial, and a 1-RTT packet placed in that order would come FIRST -
    // which RFC 9000 s12.2 forbids and TlsQuicDatagramBuilder rejects. The connection would
    // then throw on a datagram a conforming server is entitled to send.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AHandshakePacketCoalescedWithAOneRttOneIsAnsweredAtBothLevels(bool ascending)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = Spec().PaddingTarget,
            SourceConnectionIdLength = Spec().SourceConnectionIdLength,
            CoalesceAscendingByLevel = ascending,
        };
        await using var connection = Connection(clientTransport, serverTransport, pki, spec);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // THE PEER DOES NOT PUMP THE CLIENT'S FINISHED HERE, AND THAT OMISSION IS THE WHOLE
        // REASON THIS TEST CAN EXIST. Processing it is what makes the peer discard its
        // Handshake keys under RFC 9001 s4.9.2, and a peer with no Handshake write keys cannot
        // build the coalesced datagram below - measured, not predicted: with that pump in
        // place this test failed with "the level is Discarded".
        //
        // SO THE PEER SENDS HANDSHAKE_DONE EARLIER THAN A CONFORMING SERVER WOULD, and that is
        // named rather than hidden. What is under test is the CLIENT'S answer to a datagram
        // shape s12.2 permits outright - a Handshake packet coalesced in front of a 1-RTT one,
        // which is what a server retransmitting its Handshake flight beside HANDSHAKE_DONE
        // produces - and the client cannot see when the peer decided to send it.

        // RFC 9000 s12.2's coalescing, from a peer: an ack-eliciting Handshake packet in front
        // of the 1-RTT packet carrying HANDSHAKE_DONE. This connection now owes an ACK at two
        // levels out of one datagram, which is the only state in which the short header's
        // position inside its own answer is decided by anything.
        await serverPeer.SendHandshakePingCoalescedWithHandshakeDoneAsync(
            SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // TWO PACKETS IN ONE DATAGRAM, LONG THEN SHORT, READ BACK OFF OUR OWN BYTES WITH NO
        // KEYS AT ALL. RFC 9000 s12.2: "packets with a short header (Section 17.3) do not
        // contain a Length field and so cannot be followed by other packets in the same UDP
        // datagram." The long header's Length field is cleartext, so TlsQuicDatagramReader can
        // walk the boundary and report each packet's form without opening either - which is
        // exactly the vantage point an on-path observer has, and it is why this assertion is
        // made here rather than at the peer, whose Handshake READ keys go with its write ones.
        //
        // UNDER THE MUTANT THAT BUILDS THE 1-RTT PACKET INSIDE THE LEVEL LOOP, the ascending
        // row still passes and the DESCENDING row throws out of TlsQuicDatagramBuilder before
        // this line - on a datagram a conforming peer sent. That asymmetry is the whole reason
        // both rows are here.
        var answer = clientTransport.Sent[^1];
        var kinds = TlsQuicDatagramReader.Read(answer)
            .Select(coalesced => coalesced.Kind)
            .ToList();
        Assert.Equal(
            [TlsQuicCoalescedPacketKind.Long, TlsQuicCoalescedPacketKind.Short], kinds);
    }

    [Fact]
    public async Task TheSendEntryReturnsWithoutWaitingForADatagramToArrive()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // THE PEER IS SILENT FROM HERE ON, AND THAT IS THE WHOLE POINT OF THE TEST. Nothing
        // will ever arrive at this connection again, so a send entry implemented on top of
        // PumpOnceAsync - or one that took a datagram before deciding what to send - hangs
        // until the handshake deadline and this test fails on the timeout rather than on an
        // assertion. That failure mode IS the witness: it is what separates "sends when there
        // is something to send" from "answers what it receives".
        var sentBefore = clientTransport.Sent.Count;
        Assert.False(await connection.SendPendingAsync(cancellation.Token));

        // AND NOTHING WENT OUT, because nothing was owed. RFC 9000 s13.2.1 is explicit that an
        // ACK may not be synthesised out of nothing - "An endpoint MUST NOT send a
        // non-ack-eliciting packet in response to a non-ack-eliciting packet" - and s19.3's
        // mandatory First ACK Range means an ACK naming no packets has no encoding at all.
        Assert.Equal(sentBefore, clientTransport.Sent.Count);

        // Called twice, because "returns false" and "returns false and stays that way" are
        // different claims and only the second rules out a latch that fires once.
        Assert.False(await connection.SendPendingAsync(cancellation.Token));
        Assert.Equal(sentBefore, clientTransport.Sent.Count);
    }

    [Fact]
    public async Task TheSendEntryRefusesBeforeStartAndAfterDispose()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        var connection = Connection(clientTransport, serverTransport, pki);

        // The same three preconditions PumpOnceAsync has, reached through the other entry -
        // which is the point of them being one method rather than two copies.
        var notStarted = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.SendPendingAsync(cancellation.Token));
        Assert.Contains("Start the connection", notStarted.Message, StringComparison.Ordinal);

        await connection.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(
            async () => await connection.SendPendingAsync(cancellation.Token));

        await serverTransport.DisposeAsync();
        await clientTransport.DisposeAsync();
    }

    [Fact]
    public async Task TheSendEntryRefusesWhileDraining()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // RFC 9000 s10.2.1: an endpoint that sends a CONNECTION_CLOSE enters the closing
        // state. s10.2.2 gives the draining state the same rule this connection implements for
        // both: "an endpoint in the draining state MUST NOT send any packets."
        await connection.CloseAsync(TlsQuicTransportError.NoError, reason: null, cancellation.Token);
        Assert.True(connection.IsDraining);

        var draining = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.SendPendingAsync(cancellation.Token));
        Assert.Contains("closing or draining", draining.Message, StringComparison.Ordinal);
    }
}
