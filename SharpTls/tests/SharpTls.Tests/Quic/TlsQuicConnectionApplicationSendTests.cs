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

    // ---- RFC 8899 / RFC 9000 s14.3: the path MTU search, end to end -----------------------

    [Fact]
    public async Task PathMtuDiscoveryProbesAndRaisesTheDatagramSize()
    {
        // RFC 9000 s14.3 with s14.4's probe: "PMTU probes are ack-eliciting packets" and
        // "Endpoints could limit the content of PMTU probes to PING and PADDING frames". The
        // state machine is tested on its own in TlsQuicPathMtuTests; what needs two endpoints
        // is that a probe is BUILT at the size the search asked for, SURVIVES the wire, and is
        // ACKNOWLEDGED in a way the search recognises.
        //
        // DISCOVERY IS TURNED ON EXPLICITLY, because the default is off - see
        // TlsQuicConnectionSpec.PathMtuDiscovery for why. That default is also what keeps every
        // other test in this file reading the datagram sequence it was written against.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = Spec().PaddingTarget,
            SourceConnectionIdLength = Spec().SourceConnectionIdLength,
            PathMtuDiscovery = true,
        };
        await using var connection = Connection(clientTransport, serverTransport, pki, spec);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // THE PEER'S INBOX IS DRAINED FIRST, and leaving it full is how this test failed once.
        // Answering HANDSHAKE_DONE put an acknowledgment datagram on the wire; LoopbackQuicPeer
        // reads exactly ONE datagram per pump, so a peer pumped once after the probe went out
        // would open that stale answer instead and acknowledge a packet number below the
        // probe's. The search would then be handed an acknowledgment that was truthful and
        // irrelevant.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // NOTHING IS RAISED ON HOPE. s5.1.3 calls PROBED_SIZE "a tentative value for the
        // PLPMTU, which is awaiting confirmation by an acknowledgment", so until the peer
        // answers, every datagram is still bounded by BASE_PLPMTU.
        Assert.Equal(spec.BasePathMtu, connection.CurrentMaxDatagramSize);

        // APPLICATION DATA IS WHAT MAKES A PROBE DUE, which is RFC 8899 s5.1.1's condition:
        // "DPLPMTUD MAY inhibit sending probe packets when no application data has been sent
        // since the previous probe packet." A connection that has sent nothing does not probe.
        var before = clientTransport.Sent.Count;
        var stream = connection.Streams.OpenBidirectional();
        connection.Streams.Send(stream, new byte[] { 0x11, 0x22, 0x33 });
        Assert.True(await connection.SendPendingAsync(cancellation.Token));

        // TWO DATAGRAMS, IN THIS ORDER, FROM ONE PASS: the data, then the probe behind it. The
        // probe rides the same send pass rather than waiting for the next one, and it goes
        // SECOND - RFC 9000 s14.4 warns that "PMTU probes consume congestion window, which
        // could delay subsequent transmission by an application", so a probe must never take
        // the place of data that was already ready to go.
        var sent = clientTransport.Sent.Skip(before).ToArray();
        Assert.Equal(2, sent.Length);
        Assert.Equal(1, connection.PathMtuProbesSent);

        // THE PROBE WENT OUT AT MAX_PLPMTU, which is s5.3.2's "maximize the gain in PLPMTU from
        // each search step" taken on the first step. Its size is asserted on the wire rather
        // than on a counter: a probe built at the wrong size is the one defect this whole
        // feature turns on. And the data datagram beside it is still bounded by BASE_PLPMTU,
        // which is what keeps the probe the ONLY oversized thing on this connection.
        Assert.Equal(spec.MaximumPathMtu, sent[1].Length);
        Assert.True(
            sent[0].Length <= spec.BasePathMtu,
            $"the data datagram was {sent[0].Length} bytes, over the {spec.BasePathMtu} ceiling");

        // The peer opens both - a 1472-byte PING-and-PADDING datagram is an ordinary 1-RTT
        // packet - and acknowledges them.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendCumulativeAckAsync(cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // s5.3.1: the acknowledgment "confirms that the PROBED_SIZE is supported, and the
        // PROBED_SIZE value is then assigned to the PLPMTU".
        Assert.Equal(spec.MaximumPathMtu, connection.CurrentMaxDatagramSize);
        Assert.Equal(TlsQuicPathMtuState.SearchComplete, connection.PathMtu.State);
        Assert.Equal(1, connection.PathMtu.Raises);

        // AND THE SEARCH STOPS. s5.2 exits SEARCHING when "a probe of size MAX_PLPMTU is
        // acknowledged"; a client that kept probing would spend a datagram per pass forever.
        Assert.False(await connection.SendPendingAsync(cancellation.Token));
        Assert.Equal(1, connection.PathMtuProbesSent);
    }

    [Fact]
    public async Task NoProbeIsSentWhenPathMtuDiscoveryIsOff()
    {
        // THE DEFAULT, ASSERTED RATHER THAN ASSUMED. RFC 9000 s14.2 makes discovery a SHOULD,
        // and this client declines it by default because a probe is a wire-visible behaviour
        // no capture in this repository records the imitated client performing. A regression
        // that turned it on would be invisible in every other test - they would simply see one
        // more datagram - so the absence is pinned here.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        var spec = SpecWithoutPathMtuSearch();
        await using var connection = Connection(clientTransport, serverTransport, pki, spec);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // THE SAME APPLICATION DATA THE POSITIVE TEST SENDS, so this proves the KNOB is what
        // stops the probe. Without it the test would pass on RFC 8899 s5.1.1's inhibition
        // instead - true, but a different rule, and it would keep passing if the knob stopped
        // being read at all.
        var stream = connection.Streams.OpenBidirectional();
        connection.Streams.Send(stream, new byte[] { 0x11, 0x22, 0x33 });
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        var before = clientTransport.Sent.Count;
        Assert.False(await connection.SendPendingAsync(cancellation.Token));

        Assert.Equal(before, clientTransport.Sent.Count);
        Assert.Equal(0, connection.PathMtuProbesSent);
        Assert.Equal(1200, connection.CurrentMaxDatagramSize);
    }

    // ---- RFC 9001 s6: following a peer-initiated key update, end to end -------------------

    [Fact]
    public async Task APeerInitiatedKeyUpdateIsFollowedAndTheAnswerCarriesTheNewPhase()
    {
        // s6.2: "If a packet is successfully processed using the next key and IV, then the
        // peer has initiated a key update.  The endpoint MUST update its send keys to the
        // corresponding key phase in response.  Sending keys MUST be updated before sending an
        // acknowledgment for the packet that was received with updated keys."
        //
        // BOTH HALVES ARE HERE AND THE SECOND IS THE ONE A UNIT TEST CANNOT REACH. That the
        // client can OPEN a rotated packet is TlsQuicPacketReceiverTests' subject; that its
        // ANSWER goes out under the rotated keys, and is readable by a peer that has itself
        // rotated, needs both endpoints. The peer's read keys are generation n+1 by then, so a
        // client that acknowledged under the old keys would produce a datagram this peer
        // simply could not open - which is what the final pump proves it does not.
        //
        // THE PEER DERIVES ITS GENERATION WITH THE SAME TlsQuicKeySet THE CLIENT USES. That is
        // deliberate and is the one place this file's usual "two implementations" rule bends:
        // "quic ku" is a KDF label, not a behaviour, and two hand-rolled copies would agree
        // with each other while both being wrong about the label. What is genuinely doubled
        // here is the state machine either side of it.
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

        // s6: "The Key Phase bit is initially set to 0 for the first set of 1-RTT packets."
        // Asserted before anything rotates, so the assertions after it cannot be satisfied by
        // a connection that started at phase 1 by accident.
        Assert.False(connection.WriteKeyPhase);
        Assert.Equal(0, connection.KeyUpdatesApplied);

        // s6.1: the peer moves first. Its next 1-RTT packet is sealed under generation n+1 and
        // announces the flipped bit.
        serverPeer.UpdateKeys();
        Assert.True(serverPeer.WriteKeyPhase);
        await serverPeer.SendOneRttFramesAsync(
            [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            cancellation.Token);

        var sentBefore = clientTransport.Sent.Count;
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // s6.2's response, both halves.
        Assert.Equal(1, connection.KeyUpdatesApplied);
        Assert.True(connection.WriteKeyPhase);

        // AND THE ANSWER WENT OUT. A PING is ack-eliciting (s19.2), so the client owes an ACK
        // and the datagram below is that acknowledgment - the very packet s6.2 requires to be
        // protected with the updated keys.
        Assert.Equal(sentBefore + 1, clientTransport.Sent.Count);

        // THE PEER OPENS IT, which is the whole test. Its read keys are generation n+1; a
        // client that had acknowledged under the old ones would leave this pump unable to
        // open anything, and LoopbackQuicPeer's own guard turns that into a throw rather than
        // a quiet zero.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Contains(
            (TlsQuicEncryptionLevel.Application, TlsQuicFrameType.Ack),
            serverPeer.LastDatagramFrames);

        // NOTHING FAILED AUTHENTICATION ON THE WAY. s6.6's counter is the cheapest witness
        // that the update was followed rather than survived: a client that discarded the
        // rotated packet and answered for some other reason would show a failure here.
        Assert.Equal(0, connection.AuthenticationFailures);
    }

    [Fact]
    public async Task AKeyUpdateIsFollowedTwiceInARow()
    {
        // ONE UPDATE CAN PASS WITHOUT THE NEXT GENERATION EVER BEING RE-ARMED. The receiver
        // starts with current and next in hand, so the first rotation is served out of state
        // that existed before any code ran; only the second proves that TlsQuicKeySet advanced
        // its own read secret in step and derived a fresh generation afterwards.
        //
        // s6.3 is what makes re-arming a requirement rather than an optimisation: "endpoints
        // MUST be able to retain two sets of packet protection keys for receiving packets: the
        // current and the next" - after the first update, "the next" is generation n+2 and
        // nothing else can produce it.
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

        for (var round = 1; round <= 2; round++)
        {
            serverPeer.UpdateKeys();
            await serverPeer.SendOneRttFramesAsync(
                [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
                cancellation.Token);
            Assert.True(await connection.PumpOnceAsync(cancellation.Token));

            Assert.Equal(round, connection.KeyUpdatesApplied);

            // s6: "toggled to signal each subsequent key update". Odd rounds are phase 1 and
            // even rounds phase 0, so a client that only ever set the bit would pass round one
            // and fail round two.
            Assert.Equal(round % 2 == 1, connection.WriteKeyPhase);
            Assert.Equal(0, connection.AuthenticationFailures);

            // The peer reads the client's acknowledgment at its own new generation, closing
            // the round in both directions rather than only in the one under test.
            Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        }
    }

    [Fact]
    public async Task ALocallyInitiatedKeyUpdateSealsTheCrossingPacketWithTheNewGeneration()
    {
        // s6.6: "Endpoints MUST initiate a key update before sending more protected packets
        // than the confidentiality limit for the selected AEAD permits." BEFORE, so the packet
        // that crosses the limit is itself protected with the NEW keys - and s6.1 says which
        // ones those are: "The endpoint toggles the value of the Key Phase bit and uses the
        // updated key and IV to protect all subsequent packets."
        //
        // THE PAIR IS THE SUBJECT, NOT THE UPDATE. That a key update happens at the limit is
        // arithmetic; that the packet carrying the toggled bit is sealed with the generation
        // that bit names is the part the send path can get wrong, and did. Building the packet
        // plan is what RUNS this update - ShortHeaderPlan reads the phase through
        // ProtectOneMoreApplicationPacket - so a send path that took its key material before
        // the plan and used it after paired generation n's key with generation n+1's phase
        // bit. Worse, the outgoing keys are zeroed as they are replaced, so before
        // TlsQuicWriteKeyMaterial owned its copies the packet went out under an ALL-ZERO key:
        // undecryptable, and per s6.6's integrity counter indistinguishable from a forgery.
        //
        // THE PEER IS THE ORACLE AND IT IS NOT LOOKING AT THE BIT. LoopbackQuicPeer's receiver
        // reads the phase bit, reaches for the generation that bit names, and opens the packet
        // or does not. It cannot be satisfied by a client that agrees with itself about the
        // wrong generation, which is what an assertion on WriteKeyPhase alone would be.
        //
        // THE LIMIT IS LOWERED TO REACH THE CROSSING AT ALL. 2^23 packets is not a test, so
        // TlsQuicConnectionSpec.AesGcmConfidentialityLimit carries s6.6's figure as its default
        // and this is the one caller that moves it. Two, not one: the first 1-RTT packet then
        // sits below the limit and the second crosses it, so a limit read as ">" rather than
        // ">=" - or a counter that never accumulated - shows up as no update at all.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(
            clientTransport, serverTransport, pki, Spec(aesGcmConfidentialityLimit: 2));
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // HANDSHAKE_DONE is ack-eliciting, so the answer is the first 1-RTT packet this
        // connection ever protects - one below the limit, and still at s6's initial phase 0.
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.ApplicationPacketsProtectedWithCurrentKeys);
        Assert.Equal(0, connection.KeyUpdatesApplied);
        Assert.False(connection.WriteKeyPhase);
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // AND THE SECOND CROSSES IT. The PING is ack-eliciting too, so the client owes an
        // acknowledgment; that acknowledgment is the packet whose plan trips s6.6.
        await serverPeer.SendOneRttFramesAsync(
            [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // s6: "The Key Phase bit ... is toggled to signal each subsequent key update", and
        // s6.1's update is this endpoint's own rather than a response to the peer - the peer
        // has not rotated, so nothing but the limit could have caused it.
        Assert.Equal(1, connection.KeyUpdatesApplied);
        Assert.True(connection.WriteKeyPhase);

        // THE PEER OPENS THE CROSSING PACKET, WHICH IS THE WHOLE TEST. Its read keys for the
        // toggled phase are s6.3's armed next generation - "endpoints MUST be able to retain
        // two sets of packet protection keys for receiving packets: the current and the next"
        // - so a client that sealed under generation n while announcing n+1 leaves this pump
        // with nothing it can open, and LoopbackQuicPeer's own guard turns that into a throw
        // rather than a quiet zero.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Contains(
            (TlsQuicEncryptionLevel.Application, TlsQuicFrameType.Ack),
            serverPeer.LastDatagramFrames);

        // NOTHING FAILED AUTHENTICATION IN THE OTHER DIRECTION EITHER. s6.1 updates the
        // receiving keys of the endpoint that initiates - "The endpoint that initiates a key
        // update also updates the keys that it uses for receiving packets" - while this peer
        // is still writing at the old phase, and s6.3's retained previous generation is what
        // keeps that readable. A client that dropped the old read keys on its own update would
        // count every subsequent peer packet here.
        Assert.Equal(0, connection.AuthenticationFailures);
    }

    // ---- RFC 9001 s6.6: the AEAD counts and their limits ----------------------------------

    [Theory]
    [InlineData(false, 1L << 23, 1L << 52)]
    [InlineData(true, 1L << 62, 1L << 36)]
    public void TheAeadLimitsAreTheFiguresSection66States(
        bool chaCha20, long confidentiality, long integrity)
    {
        // The cipher arrives as a bool because TlsQuicPacketProtectionCipher is internal and
        // an xUnit theory method must be public. Named for the one that is not the default, so
        // the rows read as "AES-GCM" and "ChaCha20" rather than as false and true.
        var cipher = chaCha20
            ? TlsQuicPacketProtectionCipher.ChaCha20Poly1305
            : TlsQuicPacketProtectionCipher.AesGcm;

        // s6.6, quoted for each number rather than summarised, because a transcription is the
        // only way these can be wrong and a summary would hide which one moved:
        //
        //   "For AEAD_AES_128_GCM and AEAD_AES_256_GCM, the confidentiality limit is 2^23
        //    encrypted packets ... For AEAD_CHACHA20_POLY1305, the confidentiality limit is
        //    greater than the number of possible packets (2^62) and so can be disregarded."
        //
        //   "For AEAD_AES_128_GCM and AEAD_AES_256_GCM, the integrity limit is 2^52 invalid
        //    packets ... For AEAD_CHACHA20_POLY1305, the integrity limit is 2^36 invalid
        //    packets."
        //
        // THE FOUR ARE PINNED AND THE BRANCHES ARE NOT, deliberately. What is at risk here is
        // the arithmetic - 2^23 against 2^32, or the confidentiality and integrity figures
        // swapped, both of which this catches and neither of which a branch test would.
        //
        // THE CONFIDENTIALITY HALF IS NOW READ OFF A DEFAULT-CONSTRUCTED SPEC, because that is
        // where the figure lives: TlsQuicConnectionSpec.AesGcmConfidentialityLimit and its
        // ChaCha20 sibling are the single source, and TlsQuicConnection reads them. This
        // paragraph used to say that making the limit injectable "would be a knob no shipped
        // code path uses"; that is no longer true, and
        // TlsQuicConnectionTests.ALocallyInitiatedKeyUpdateSealsTheCrossingPacketWithTheNewGeneration
        // is what the knob bought - the crossing itself, which 2^23 packets otherwise puts out of
        // reach of any test. What this assertion still owns is that lowering the knob for that
        // one test did not move the DEFAULT.
        //
        // THE TWO CIPHERS ARE THE OPPOSITE WAY ROUND FOR THE TWO LIMITS, which is the shape a
        // swap would break: ChaCha20 has the LARGER confidentiality limit and the SMALLER
        // integrity limit.
        Assert.Equal(confidentiality, new TlsQuicConnectionSpec().ConfidentialityLimitFor(cipher));
        Assert.Equal(integrity, TlsQuicConnection.IntegrityLimitFor(cipher));
    }

    // ---- RFC 9001 s6.6's "MUST stop using the connection" -------------------------------
    //
    // ONE STATE, TWO REACTIONS, AND THE SPLIT IS THE WHOLE POINT OF THESE TWO TESTS. s6.6:
    // "If a key update is not possible or integrity limits are reached, the endpoint MUST stop
    // using the connection and only send stateless resets in response to receiving packets. It
    // is RECOMMENDED that endpoints immediately close the connection with a connection error of
    // type AEAD_LIMIT_REACHED before reaching a state where key updates are not possible." The
    // ordinary send edge owes the caller an exception; the close owes the caller a close, and a
    // close that throws is the one outcome the RECOMMENDED half cannot survive.
    //
    // REACHING THE STATE AT ALL TAKES TWO CROSSINGS AND NO ACKNOWLEDGMENT BETWEEN THEM. The
    // first crossing finds s6.1's gate open - "An endpoint MUST NOT initiate a subsequent key
    // update unless it has received an acknowledgment for a packet that was sent protected with
    // keys from the current key phase", and before any update there is no such phase to wait on
    // - so it updates. The second finds the gate shut, because this peer never acknowledges the
    // packet the first one produced, and s6.6's "if a key update is not possible" is then true.
    // A limit of one is what makes both crossings cost one packet each instead of 2^23.

    /// <summary>
    /// The send edge's half. Nothing about this changed: a caller with application data to send
    /// is owed the reason it will not go, and RFC 9000 s20.1 names it - AEAD_LIMIT_REACHED
    /// (0x0F): "An endpoint has reached the confidentiality or integrity limit for the AEAD
    /// algorithm used by the given connection."
    /// </summary>
    [Fact]
    public async Task AConfidentialityLimitWithNoKeyUpdateAvailableThrowsOnTheOrdinarySendEdge()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(
            clientTransport, serverTransport, pki, Spec(aesGcmConfidentialityLimit: 1));
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // THE FIRST CROSSING, which s6.1 permits: the acknowledgment this answers is the first
        // 1-RTT packet this connection protects, and no phase has been waited on yet.
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.KeyUpdatesApplied);
        Assert.False(connection.MustStopUsingConnection);

        // THE SECOND, WITH THE GATE SHUT. The peer has acknowledged nothing at 1-RTT, so
        // s6.1's condition on the current phase cannot be met and s6.6's state is reached.
        await serverPeer.SendOneRttFramesAsync(
            [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            cancellation.Token);

        var error = await Assert.ThrowsAsync<TlsQuicTransportException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(TlsQuicTransportError.AeadLimitReached, error.Error);
        Assert.Contains("s6.6", error.Message, StringComparison.Ordinal);
        Assert.True(connection.MustStopUsingConnection);

        // STILL ONE UPDATE. The second crossing did not rotate anything - that is what "a key
        // update is not possible" means - so a connection that had quietly updated behind the
        // shut gate would show two here.
        Assert.Equal(1, connection.KeyUpdatesApplied);
    }

    /// <summary>
    /// The close's half, and the finding. <c>BuildCloseDatagram</c> reaches the same plan
    /// builder as every other short-header packet, so the throw above used to come out of
    /// <c>CloseAsync</c> - past the send and short of the line that records RFC 9000 s10.2's
    /// "After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the closing
    /// state". The connection was then neither closed nor draining, which is worse than a close
    /// nobody could send: the close path states three times over that it may not throw.
    /// <para>THE DEGRADATION IS ONE THAT PATH ALREADY DOCUMENTS. A close with no usable write
    /// keys, and a transport error code s20 cannot encode, both take the same
    /// <c>written == 0</c> exit - nothing on the wire, closing state entered regardless. s6.6's
    /// state joins them rather than inventing a fourth behaviour.</para>
    /// </summary>
    [Fact]
    public async Task AConfidentialityLimitReachedWhileClosingStillEntersTheClosingState()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(
            clientTransport, serverTransport, pki, Spec(aesGcmConfidentialityLimit: 1));
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // THE STATE IS REACHED THROUGH THE SEND EDGE, because that is the only door to it -
        // the limit is a count of packets SENT. Its exception is the sibling test's claim and
        // is swallowed here; what this test is about starts on the next line.
        await serverPeer.SendOneRttFramesAsync(
            [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            cancellation.Token);
        await Assert.ThrowsAsync<TlsQuicTransportException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        Assert.True(connection.MustStopUsingConnection);
        Assert.False(connection.IsDraining);

        // AND THE CLOSE GOES THROUGH. Not a throw, which is what this used to be, and s10.2's
        // closing state is entered either way: "After sending a CONNECTION_CLOSE frame, an
        // endpoint immediately enters the closing state", and the state is the endpoint's own
        // rather than something the peer has to have heard.
        var sentBefore = clientTransport.Sent.Count;
        var spentBefore = connection.NextPacketNumber(TlsQuicEncryptionLevel.Application);

        await connection.CloseAsync(
            TlsQuicTransportError.NoError, "bye", cancellation.Token);

        Assert.True(connection.IsDraining);

        // NOTHING ON THE WIRE, which is the documented degradation rather than a silent loss:
        // s6.6 forbids protecting another packet, and a CONNECTION_CLOSE is a packet.
        Assert.Equal(sentBefore, clientTransport.Sent.Count);

        // AND NOTHING WAS SPENT ON IT EITHER. RFC 9000 s12.3 forbids reusing a packet number in
        // a space; the plan gate refuses before drawing one, so a close in this state costs no
        // number.
        Assert.Equal(
            spentBefore, connection.NextPacketNumber(TlsQuicEncryptionLevel.Application));
    }

    [Fact]
    public async Task ProtectedOneRttPacketsAreCountedAndAKeyUpdateRestartsTheCount()
    {
        // s6.6: "Endpoints MUST count the number of encrypted packets for each set of keys."
        // FOR EACH SET, which is why the count restarts rather than accumulating - a running
        // total across generations would trip the confidentiality limit on keys that had
        // protected almost nothing.
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

        // NOTHING IS COUNTED BEFORE A 1-RTT PACKET EXISTS. The handshake flight is Initial and
        // Handshake packets, and s6.1's Note keeps them out of this entirely: "Keys of packets
        // other than the 1-RTT packets are never updated". A counter that fired on every
        // packet would already be non-zero here.
        Assert.Equal(0, connection.ApplicationPacketsProtectedWithCurrentKeys);

        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // HANDSHAKE_DONE is ack-eliciting, so the client answered with a 1-RTT packet.
        var afterFirst = connection.ApplicationPacketsProtectedWithCurrentKeys;
        Assert.True(afterFirst > 0, $"expected at least one 1-RTT packet, counted {afterFirst}");

        await serverPeer.SendOneRttFramesAsync(
            [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(
            afterFirst + 1, connection.ApplicationPacketsProtectedWithCurrentKeys);

        // AND THE KEY UPDATE RESTARTS IT. The count after the update is exactly the ONE packet
        // the answer to the update was - s6.2's acknowledgment, protected with the new keys -
        // rather than that packet plus everything the old keys had protected.
        serverPeer.UpdateKeys();
        await serverPeer.SendOneRttFramesAsync(
            [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.KeyUpdatesApplied);
        Assert.Equal(1, connection.ApplicationPacketsProtectedWithCurrentKeys);
    }

    [Fact]
    public async Task AForgedOneRttPacketIsCountedAsAnAuthenticationFailureAndNotFatal()
    {
        // s6.6: "In addition to counting packets sent, endpoints MUST count the number of
        // received packets that fail authentication during the lifetime of a connection."
        //
        // AND THE COUNT IS NOT THE CLOSE. The limit is 2^52 for AES-GCM, so one forgery must
        // leave the connection working - RFC 9000 s12.2 has a receiver "discard" what it
        // cannot open, and a client that closed on the first stray datagram would be trivially
        // killable from off path. This test is as much about the connection surviving as about
        // the counter moving.
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

        Assert.Equal(0, connection.AuthenticationFailures);

        // A SHORT HEADER WITH THIS CONNECTION'S DESTINATION CONNECTION ID AND RANDOM BYTES
        // AFTER IT. It reaches the AEAD - the header is well formed enough to be routed to the
        // Application level - and fails there, which is the state s6.6 counts. Bytes that
        // failed to parse would be discarded earlier and would prove nothing about this
        // counter.
        var forged = new byte[64];
        forged[0] = 0x40;
        await serverTransport.SendAsync(
            clientTransport.LocalEndPoint, forged, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.AuthenticationFailures);

        // STILL USABLE. One more real exchange after the forgery, which a connection that had
        // closed could not complete.
        await serverPeer.SendOneRttFramesAsync(
            [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.AuthenticationFailures);
    }

    // ---- s19.16 and s19.4: frame types the dispatch used to drop ---------------------------

    [Theory]
    [InlineData(0, 0UL)]
    [InlineData(0, 9UL)]
    [InlineData(5, 0UL)]
    [InlineData(5, 9UL)]
    public async Task ARetireConnectionIdFrameIsRefusedAsAProtocolViolation(
        int sourceConnectionIdLength, ulong sequenceNumber)
    {
        // FOUR ROWS BECAUSE TWO DIFFERENT SENTENCES REACH THE SAME VERDICT, and a single row
        // could not tell them apart.
        //
        // Length 0 - TlsQuicConnectionSpec.SourceConnectionIdLength's default and what the
        // shipped profiles use - is s19.16's "An endpoint that provides a zero-length
        // connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection
        // error of type PROTOCOL_VIOLATION", which does not look at the number at all.
        //
        // Length 5 is the rest of s19.16: this endpoint never sends a NEW_CONNECTION_ID frame,
        // so sequence number 0 is the only one ever provided. Number 9 is then "a sequence
        // number greater than any previously sent to the peer", a MUST; number 0 refers to the
        // Destination Connection ID of the packet carrying the frame, which s19.16 lets the
        // peer treat as PROTOCOL_VIOLATION and this endpoint does.
        //
        // ZERO IS IN BOTH LENGTH ROWS ON PURPOSE. An implementation that only compared against
        // the highest issued number would pass rows 2 and 4 and let row 1 and row 3 through.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = Spec().PaddingTarget,
            SourceConnectionIdLength = sourceConnectionIdLength,
        };
        await using var connection = Connection(clientTransport, serverTransport, pki, spec);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        await serverPeer.SendOneRttFramesAsync(
            [
                new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.RetireConnectionId,
                    SequenceNumber = sequenceNumber,
                },
            ],
            cancellation.Token);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        // THE MESSAGE IS ASSERTED, NOT JUST THE TYPE. This frame used to fall into the frame
        // switch's default arm and be dropped silently; an InvalidOperationException from
        // anywhere else in the receive path would satisfy Assert.ThrowsAsync alone.
        Assert.Contains("RETIRE_CONNECTION_ID", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AResetStreamFrameOnOurOwnUnidirectionalStreamClosesTheConnection()
    {
        // s19.4: "An endpoint that receives a RESET_STREAM frame for a send-only stream MUST
        // terminate the connection with error STREAM_STATE_ERROR." Stream 2 is s2.1's
        // client-initiated unidirectional identifier and this endpoint is the client.
        //
        // THE RULE ITSELF IS TESTED IN TlsQuicStreamsTests, five ways. THIS TEST IS ABOUT THE
        // DISPATCH: RESET_STREAM, STOP_SENDING and STREAM_DATA_BLOCKED all reached the frame
        // switch's default arm and were dropped, so a stream set that refused them perfectly
        // still never saw one. One frame type is enough to prove the arm exists, because all
        // three share it.
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

        await serverPeer.SendOneRttFramesAsync(
            [
                new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.ResetStream,
                    StreamId = 2,
                },
            ],
            cancellation.Token);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        Assert.Contains("ResetStream", error.Message, StringComparison.Ordinal);
        Assert.Contains("StreamStateError", error.Message, StringComparison.Ordinal);
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
