using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task A3-1 of the loss recovery phase, the half that needs keys. ImpairingDatagramTransport's
// own tests pin what its script MEANS; this file pins that the script reaches real Initial,
// Handshake and 1-RTT packets - which is the entire reason the instrument had to be written.
//
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's AND 14c's, for the reason those give: Spec,
// Connection, TlsClient and Server are reused rather than copied.
//
// ============================================================================
// WHY NOT ScriptedDatagramTransport, WHICH THE PARENT SCOPING POINTED AT.
// ============================================================================
//
// The A3 parent scoping said loss, reordering and duplication "are simulated by a test
// implementation of ITlsQuicDatagramTransport - the interface subsystem D already shipped. No
// network needed." The interface shipped; the implementation did not. ScriptedDatagramTransport
// had said in its own remarks, for weeks before that sentence was written, that it "cannot
// fabricate a Handshake or 1-RTT packet: those keys descend from the client ephemeral share,
// which differs on every run", and that "record-and-replay is dead past the first flight". Both
// sentences were in the repository at the same time.
//
// A decorator has no such ceiling because it fabricates nothing. TlsQuicConnection and
// LoopbackQuicPeer agree keys with each other; ImpairingDatagramTransport only decides which of
// the datagrams they produced actually arrive. Every packet impaired below is a packet one of
// them really built and the other really opens.
//
// ============================================================================
// WHICH ORDINAL CARRIES WHICH LEVEL, AND HOW THAT IS KNOWN RATHER THAN ASSUMED.
// ============================================================================
//
// The client's send sequence over this harness is fixed by RFC 9001 s4's flight structure:
//
//   ordinal 1  Initial              - StartAsync's opening flight, carrying ClientHello.
//   ordinal 2  Initial + Handshake  - the answer to the server's flight, COALESCED.
//   ordinal 3  1-RTT                - the ACK owed for HANDSHAKE_DONE, RFC 9000 s13.2.1.
//
// ORDINAL 2 IS COALESCED, AND THAT WAS MEASURED RATHER THAN PREDICTED. This comment first said
// "ordinal 2 Handshake", and the assertion written to check it read the Long Packet Type out
// of the datagram's first byte and found 0x00 - Initial - where it expected 0x20. RFC 9000
// s12.2 is why: the client owes an Initial-level ACK for the server's Initial packet and a
// Handshake packet carrying Finished, and it puts both in one datagram. So a datagram carries
// LEVELS, plural, and the first byte only names the first packet in it. A test that dropped
// "the Handshake packet" by ordinal and cited a first-byte assertion would have been citing a
// check that does not say what it appears to say.
//
// SO THE PIN IS THE FAR SIDE'S REPORT, NOT A BYTE. TlsQuicConnectionTests.TheImpairedClient
// SendSequenceCarriesInitialThenHandshakeThenOneRtt drives the peer pump by pump and reads
// LoopbackQuicPeer.LastDatagramFrames, which records the encryption level of the packet that
// carried each frame - so "ordinal 2 contains a Handshake packet" is the receiving endpoint's
// own statement, made after opening it with Handshake read keys, and cannot be true of a
// datagram that did not contain one.
public sealed partial class TlsQuicConnectionTests
{
    [Fact]
    public async Task TheImpairedClientSendSequenceCarriesInitialThenHandshakeThenOneRtt()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        await using var connection = Connection(impaired, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        // ORDINAL 1. Nothing but Initial - the client has no other keys yet.
        await connection.StartAsync(cancellation.Token);
        Assert.Single(impaired.Offered);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(
            [TlsQuicEncryptionLevel.Initial],
            serverPeer.LastDatagramFrames.Select(static f => f.Level).Distinct());

        // ORDINAL 2. Initial AND Handshake in one datagram, RFC 9000 s12.2. The Handshake half
        // is what ScriptedDatagramTransport cannot reach at all, and the whole datagram is what
        // an ordinal names - so dropping ordinal 2 drops a Handshake packet.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(2, impaired.Offered.Count);
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        var secondLevels = serverPeer.LastDatagramFrames.Select(static f => f.Level).ToArray();
        Assert.Contains(TlsQuicEncryptionLevel.Initial, secondLevels);
        Assert.Contains(TlsQuicEncryptionLevel.Handshake, secondLevels);
        Assert.True(server.IsHandshakeComplete);

        // ORDINAL 3. A 1-RTT packet, which s17.3.1 gives a short header - the one level claim
        // the first byte CAN settle on its own, because Header Form is outside s5.4.1's mask.
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(3, impaired.Offered.Count);
        Assert.Equal(0x80, impaired.Offered[0][0] & 0x80);
        Assert.Equal(0x80, impaired.Offered[1][0] & 0x80);
        Assert.Equal(0x00, impaired.Offered[2][0] & 0x80);

        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(
            [TlsQuicEncryptionLevel.Application],
            serverPeer.LastDatagramFrames.Select(static f => f.Level).Distinct());
    }

    // ============================================================================
    // THE MOST IMPORTANT TEST IN THIS TASK.
    // ============================================================================
    //
    // An instrument that changes behaviour when it is doing nothing invalidates every result
    // taken with it, and no later assertion about loss recovery could be distinguished from an
    // artefact of the harness. So this is AOneRttPacketThisConnectionSentIsAcknowledgedByThe
    // LoopbackPeer re-pointed at the wrapper with an empty script, asserting the same facts.
    //
    // AND TWO STRONGER ONES IT COULD NOT MAKE. The bytes the wrapper was offered are compared
    // to the bytes the inner transport actually delivered, index by index - so a wrapper that
    // truncated, reordered, re-sent or corrupted anything fails here even though the handshake
    // would still complete. A byte-for-byte comparison against a DIFFERENT RUN is not possible
    // and never will be: the client's ephemeral share is fresh every attempt, so two runs of
    // this handshake share no ciphertext. The comparison that is available is between the two
    // sides of the wrapper within one run, and it is the exact claim - the wrapper altered
    // nothing - that "byte-identical" was reaching for.
    [Fact]
    public async Task AnUnscriptedWrapperCarriesAWholeHandshakeAndOneRttExchangeUnchanged()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        await using var connection = Connection(impaired, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Null(connection.LargestAcknowledged(TlsQuicEncryptionLevel.Application));

        var oneRtt = connection.NextPacketNumber(TlsQuicEncryptionLevel.Application);
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(oneRtt + 1, connection.NextPacketNumber(TlsQuicEncryptionLevel.Application));

        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(oneRtt, serverPeer.LargestApplicationPacketNumberReceived);
        Assert.Contains(
            (TlsQuicEncryptionLevel.Application, TlsQuicFrameType.Ack),
            serverPeer.LastDatagramFrames);

        await serverPeer.SendAckAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(oneRtt, connection.LargestAcknowledged(TlsQuicEncryptionLevel.Application));
        Assert.True(connection.IsHandshakeConfirmed);

        // THE WRAPPER ITSELF DID NOTHING. Delivered is every ordinal, once, in order; nothing
        // was dropped, held or failed; and each delivered datagram is byte-identical to what
        // was offered.
        Assert.Equal(
            Enumerable.Range(1, impaired.Offered.Count).ToArray(), impaired.Delivered.ToArray());
        Assert.Empty(impaired.Dropped);
        Assert.Empty(impaired.Held);
        Assert.Empty(impaired.ReleaseFailures);
        Assert.Equal(impaired.Offered.Count, clientTransport.Sent.Count);
        for (var i = 0; i < impaired.Offered.Count; i++)
        {
            Assert.Equal(impaired.Offered[i], clientTransport.Sent[i]);
        }
    }

    // ============================================================================
    // DROP, DUPLICATE AND REORDER AT HANDSHAKE AND AT 1-RTT LEVEL.
    // ============================================================================
    //
    // Ordinal 2 is the Handshake packet and ordinal 3 the 1-RTT one, both pinned by
    // TlsQuicConnectionTests.TheImpairedClientSendSequenceCarriesInitialThenHandshakeThenOneRtt.
    // ScriptedDatagramTransport can reach neither, which is the gap this task closes.

    [Fact]
    public async Task TheClientsHandshakePacketIsDroppedAndTheServerNeverCompletes()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        impaired.Drop(2);
        await using var connection = Connection(impaired, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // THE CLIENT IS DONE AND THE SERVER IS NOT, WHICH IS WHAT A LOST FINISHED LOOKS LIKE.
        // RFC 9001 s4.1.2 completes the client on its own Finished; the server completes on
        // RECEIVING it, and it never arrived. A drop this test could see only as a smaller
        // Delivered list would prove nothing about a QUIC endpoint; this is the far side's TLS
        // state machine reporting the loss.
        Assert.True(connection.IsHandshakeComplete);
        Assert.False(server.IsHandshakeComplete);
        Assert.Equal(new[] { 2 }, impaired.Dropped);
        Assert.Equal(new[] { 1 }, impaired.Delivered);

        // AND NOTHING IS RESENT, which is the whole of A3's remaining work. When A3-8 adds
        // retransmission this assertion is the one that has to change, and it is here so that
        // the improvement is attributable rather than assumed.
        Assert.Equal(2, impaired.Offered.Count);
    }

    [Fact]
    public async Task TheClientsOneRttAckIsDroppedAndThePeerNeverSeesTheAcknowledgement()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        impaired.Drop(3);
        await using var connection = Connection(impaired, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await RunToOneRttAsync(connection, serverPeer, cancellation.Token);

        // THE CONNECTION BUILT ITS 1-RTT PACKET AND THE PEER NEVER SAW IT. The counter moving
        // is the client's own claim; LargestApplicationPacketNumberReceived staying null is the
        // peer's, and only a drop makes the two disagree. Task 13's live run measured a server
        // sending seven HANDSHAKE_DONE frames in 14.9 seconds against exactly this state.
        Assert.Equal(1UL, connection.NextPacketNumber(TlsQuicEncryptionLevel.Application));
        Assert.Null(serverPeer.LargestApplicationPacketNumberReceived);
        Assert.Equal(new[] { 3 }, impaired.Dropped);
    }

    [Fact]
    public async Task TheClientsHandshakePacketIsDeliveredTwiceAndTheServerCompletesOnce()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        impaired.Duplicate(2);
        await using var connection = Connection(impaired, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // THE FIRST COPY COMPLETES THE SERVER, and both copies are on the wire.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.True(server.IsHandshakeComplete);
        Assert.Equal(new[] { 1, 2, 2 }, impaired.Delivered);

        // AND THE SECOND ARRIVES AT A PEER THAT NO LONGER HAS THE KEYS FOR ITS FIRST PACKET.
        //
        // MEASURED, NOT PREDICTED, AND IT CORRECTED THIS TEST. The assertion written here first
        // said the duplicate would be opened and discarded quietly, on the reasoning that RFC
        // 9000 s12.3 forbids reusing a packet number. What happens is earlier than that: ordinal
        // 2 is an Initial packet coalesced with a Handshake one (s12.2), and RFC 9001 s4.9.1 has
        // the client's Handshake packet make the server DISCARD its Initial keys - so by the
        // time the copy arrives its leading Initial packet cannot be opened at all, and
        // LoopbackQuicPeer says so by name rather than silently counting it.
        //
        // THE THROW IS THE WITNESS THAT THE DUPLICATE REALLY ARRIVED. A datagram that was not
        // delivered twice would leave this pump waiting on an empty inbox until the test's own
        // token fired, which is a different failure with a different message.
        var refused = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Contains("for want of keys", refused.Message, StringComparison.Ordinal);
        Assert.True(server.IsHandshakeComplete);
    }

    [Fact]
    public async Task TheClientsOneRttPacketIsDeliveredTwiceAndThePeerOpensOnlyTheFirst()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        impaired.Duplicate(3);
        await using var connection = Connection(impaired, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await RunToOneRttAsync(connection, serverPeer, cancellation.Token);

        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(0UL, serverPeer.LargestApplicationPacketNumberReceived);
        Assert.Contains(
            (TlsQuicEncryptionLevel.Application, TlsQuicFrameType.Ack),
            serverPeer.LastDatagramFrames);

        // AND THE SECOND COPY IS OPENED AND PROCESSED AGAIN - NOTHING DEDUPLICATES IT TODAY.
        //
        // MEASURED, NOT PREDICTED, AND IT CORRECTED THIS TEST. The assertion here first said the
        // duplicate would be dropped before its frames were opened, because RFC 9000 s12.3
        // forbids reusing a packet number in a space and s13.1 requires a receiver to tolerate
        // one arriving anyway. Neither this peer nor TlsQuicPacketReceiver keeps a received
        // packet number set, so the copy opens cleanly and raises its ACK frame a second time.
        //
        // THIS IS PINNED RATHER THAN FIXED BECAUSE IT IS NOT A3-1's TO FIX, AND IT IS WRITTEN
        // DOWN BECAUSE IT IS A3's TO CARE ABOUT: an RTT sample taken from a duplicated ACK is a
        // sample of nothing, and RFC 9002 s5.1's "an endpoint generates an RTT sample on
        // receiving an ACK frame that newly acknowledges" is the clause that has to hold the
        // line once A3-4 lands. A3 now has an instrument that can produce the duplicate on
        // demand, which is why the gap is visible at all.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Contains(
            (TlsQuicEncryptionLevel.Application, TlsQuicFrameType.Ack),
            serverPeer.LastDatagramFrames);
        Assert.Equal(0UL, serverPeer.LargestApplicationPacketNumberReceived);
        Assert.Equal(new[] { 1, 2, 3, 3 }, impaired.Delivered);
    }

    [Fact]
    public async Task TheClientsOneRttPacketOvertakesItsHandshakePacket()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        // THE HANDSHAKE PACKET HELD BEHIND THE 1-RTT ONE - a reorder ACROSS RFC 9000 s12.3's
        // packet number spaces, which is the case a single-space receiver gets wrong and the
        // one ScriptedDatagramTransport can reach at neither end.
        impaired.HoldUntilAfter(2, releaseAfterOrdinal: 3);
        await using var connection = Connection(impaired, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // The Handshake packet is in the wrapper, not on the wire. The server has had the
        // client's Initial and nothing since.
        Assert.Equal(new[] { 2 }, impaired.Held);
        Assert.False(server.IsHandshakeComplete);

        // The client owes an ACK for the server's HANDSHAKE_DONE and sends it at 1-RTT level,
        // which releases the Handshake packet behind it.
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(new[] { 1, 3, 2 }, impaired.Delivered);
        Assert.Empty(impaired.Held);

        // AND THE SERVER OPENS THEM IN THE ORDER THEY ARRIVED, 1-RTT first. The 1-RTT packet
        // opens against keys the Handshake flight it overtook had already established on the
        // previous round trip, so this is a genuine out-of-order delivery and not a packet the
        // receiver had no keys for.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(0UL, serverPeer.LargestApplicationPacketNumberReceived);
        Assert.False(server.IsHandshakeComplete);

        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.True(server.IsHandshakeComplete);
    }

    [Fact]
    public async Task TheClientsHandshakePacketIsDelayedAndArrivesWhenTheFakeClockPassesTheDelay()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        impaired.DelayBy(2, TimeSpan.FromSeconds(2));

        // ONE CLOCK FOR BOTH, which is the half of task A3-1 that is not the transport: the
        // connection's deadlines and the script's delays read the same instants, so a delay
        // that outran the handshake deadline would end the attempt rather than silently
        // extending it.
        await using var connection = Connection(impaired, serverTransport, pki, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(new[] { 2 }, impaired.Held);
        Assert.False(server.IsHandshakeComplete);

        // TWO SECONDS OF FAKE TIME, WELL INSIDE THE TEN-SECOND HANDSHAKE DEADLINE, so the
        // attempt survives the delay - the difference between a slow path and a dead one.
        impaired.Clock.Advance(TimeSpan.FromSeconds(2));
        Assert.Equal(new[] { 1, 2 }, impaired.Delivered);
        Assert.Empty(impaired.ReleaseFailures);

        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.True(server.IsHandshakeComplete);
    }

    // ============================================================================
    // TODAY'S BEHAVIOUR UNDER LOSS, PINNED BEFORE A3-8 CHANGES IT.
    // ============================================================================
    [Fact]
    public async Task ADroppedInitialEndsTheAttemptOnTheHandshakeDeadlineRatherThanRecovering()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        impaired.Drop(1);
        await using var connection = Connection(impaired, serverTransport, pki, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        Assert.NotNull(serverPeer);

        await connection.StartAsync(cancellation.Token);
        Assert.Equal(new[] { 1 }, impaired.Dropped);
        Assert.Empty(impaired.Delivered);

        // PAST THE TEN-SECOND HANDSHAKE DEADLINE AND SHORT OF THE THIRTY-SECOND IDLE TIMEOUT,
        // so the failure is attributable to the deadline. Both are TlsQuicConnectionOptions
        // defaults and neither is restated here.
        var wallClock = System.Diagnostics.Stopwatch.StartNew();
        impaired.Clock.Advance(TimeSpan.FromSeconds(11));
        var error = await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        wallClock.Stop();

        // A TIMEOUT, NOT A RETRANSMISSION, and the message says so because A3-8 has not landed.
        // THIS ASSERTION IS THE ONE A3-8 MUST BREAK: a connection that recovered from a lost
        // Initial would not reach here at all. It is written down now so that the improvement
        // is measured against a pinned baseline instead of a remembered one.
        Assert.Contains("NOT A RETRANSMISSION", error.Message, StringComparison.Ordinal);
        Assert.True(
            wallClock.Elapsed < TimeSpan.FromSeconds(30),
            $"The deadline took {wallClock.Elapsed} of wall-clock time, so it did not fire off "
                + "the injected clock.");
    }

    // Drives the shared prefix: handshake to completion, then the server's HANDSHAKE_DONE and
    // the 1-RTT ACK the client owes for it. Leaves the client's 1-RTT packet as ordinal 3.
    private static async Task RunToOneRttAsync(
        TlsQuicConnection connection,
        LoopbackQuicPeer serverPeer,
        CancellationToken cancellationToken)
    {
        await connection.StartAsync(cancellationToken);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellationToken));
        Assert.False(await connection.PumpOnceAsync(cancellationToken));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellationToken));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellationToken);
        Assert.True(await connection.PumpOnceAsync(cancellationToken));
    }
}
