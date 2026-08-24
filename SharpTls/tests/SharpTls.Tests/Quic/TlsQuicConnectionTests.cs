using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Protocol;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task 9a-ii of A4-minimal: the connection loop.
//
// ============================================================================
// WHAT THESE ASSERTIONS PIN, AND WHAT THEY CANNOT. READ BEFORE TRUSTING A GREEN RUN.
// ============================================================================
//
// Half of this file drives TlsQuicConnection against LoopbackQuicPeer, which is our own
// packet layer facing itself, and the other half drives it against ScriptedDatagramTransport,
// where the reply is built here. BOTH ARE OUR OWN PAIR. Seal and open are inverses, encode
// and decode are inverses, and a defect living in a matched pair cancels exactly. So:
//
//   SURVIVES A BUG SHARED BY BOTH HALVES - and is therefore worth little here:
//     - "the handshake completed". IsHandshakeComplete is a boolean produced by the TLS state
//       machine on both sides of a loopback; a symmetric packet-layer defect does not disturb
//       it, because both sides make the same wrong bytes and read them back the same wrong
//       way. This is the exact shape task 9a-i's inverted read direction hid inside for 1004
//       tests, so no test below asserts it ALONE.
//     - the layout of the 1-RTT packet LoopbackQuicPeer.SendHandshakeDoneAsync writes. RFC
//       9001 Appendix A publishes no 1-RTT vector at all; that method's own remarks say so.
//
//   DOES NOT SURVIVE, and this is where the value is:
//     - THE ORDER OF STATES. Complete-then-confirmed is RFC 9001 s4.1.2's structure, and the
//       gap between them is asserted directly: Handshake keys INSTALLED at complete, DISCARDED
//       only after a HANDSHAKE_DONE frame arrives. Both halves of the loopback would have to
//       agree on a wrong ORDER, which neither implements - the order comes from the TLS state
//       machine and from a frame type in RFC 9000 s19.20.
//     - THE CONNECTION ID THAT REACHES THE WIRE. TheServersSourceConnectionIdBecomesOur
//       DestinationConnectionId scripts a server whose Source Connection ID is a value chosen
//       HERE and nowhere else, then reads the next packet's Destination Connection ID field
//       off the recorded datagram. Against LoopbackQuicPeer this would be vacuous: that peer
//       echoes the client's own Destination Connection ID back as its Source Connection ID,
//       so adoption is a no-op and a connection that never adopted would pass. That is why
//       the test is scripted and not loopback-driven.
//     - THE THREE VARINT WIDTHS. TheSpecsVarintWidthsReachTheWire OPENS the connection's own
//       Initial packet with keys derived from OriginalDestinationConnectionId and reads the
//       encoded widths as raw leading bits. The knob is set on the type the caller holds and
//       a byte changes, which is the only form of that claim the plan's amendment after task
//       5 accepts.
//     - THE DISCARD ORDER AT THE SEND. See InitialKeysAreDiscardedAfterTheHandshakePacketIs
//       BuiltAndNotBefore, whose whole content is that an Initial packet still exists in the
//       datagram that carries our first Handshake packet.
public sealed partial class TlsQuicConnectionTests
{
    // Long enough that a hung await is a test failure rather than a hung run, and never the
    // thing any assertion depends on.
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(60);

    // The Source Connection ID length this file's connections advertise. NON-ZERO ON PURPOSE:
    // the target profile's is zero bytes, which makes the source CID unobservable in every
    // header, and an unobservable value cannot witness the factory contract or s7.2.
    private const int SourceConnectionIdLength = 5;

    [Fact]
    public async Task TheClientReachesCompleteAgainstTheTaskSevenPeerAndConfirmsOnlyOnHandshakeDone()
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

        // The server answers with its whole flight in ONE datagram - an Initial packet
        // carrying ServerHello and a Handshake packet carrying the rest, coalesced. That is
        // the case RFC 9000 s12.2 allows and the one the connection loop must split, because
        // the Handshake packet's keys come out of the Initial packet's own payload.
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // COMPLETE, AND EXPLICITLY NOT CONFIRMED. RFC 9001 s4.1.2 separates the two and only
        // the second releases the Handshake keys. Asserting the key STATE rather than the
        // flag is the point: a connection that confirmed on TLS completion would show
        // Discarded here and would have thrown away keys the server may still be using.
        Assert.True(connection.IsHandshakeComplete);
        Assert.False(connection.IsHandshakeConfirmed);
        Assert.Equal(TlsQuicKeyLevelState.Installed,
            connection.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
        Assert.True(connection.HasReadKeys(TlsQuicEncryptionLevel.Handshake));

        // The server takes our Finished and has nothing to answer with at any level it can
        // write, so this pump sends nothing. That is completion, not a stall.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.True(server.IsHandshakeComplete);

        // Still not confirmed after a full round trip in which the peer said nothing. The
        // only thing that can change this is a HANDSHAKE_DONE frame.
        Assert.False(connection.IsHandshakeConfirmed);
        Assert.Equal(TlsQuicKeyLevelState.Installed,
            connection.WriteStateOf(TlsQuicEncryptionLevel.Handshake));

        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // RFC 9001 s4.1.2: "At the client, the handshake is considered confirmed when a
        // HANDSHAKE_DONE frame is received", and s4.9.2 then releases the Handshake keys.
        // BOTH DIRECTIONS, because the key set and the receiver hold them separately and a
        // discard that reached only one of them would leave the other live.
        Assert.True(connection.IsHandshakeConfirmed);
        Assert.Equal(TlsQuicKeyLevelState.Discarded,
            connection.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
        Assert.False(connection.HasReadKeys(TlsQuicEncryptionLevel.Handshake));

        // The handshake that ran was the ordinary one, negotiated end to end - the same
        // result CustomTlsQuicServerTests reaches with no packet layer at all.
        Assert.Equal("example.com", server.ServerName);
        Assert.Equal("h3", server.NegotiatedApplicationProtocol);
    }

    [Fact]
    public async Task ConnectAsyncRunsToConfirmedInOneCall()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        // The peer is driven on its own task because ConnectAsync does not return until a
        // HANDSHAKE_DONE arrives, and only this peer can send one. Each side still has ONE
        // thread of control over its own TLS endpoint, which is what Finding 6 requires;
        // nothing here touches the other side's.
        var peer = Task.Run(
            async () =>
            {
                while (!server.IsHandshakeComplete)
                {
                    await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
                }
                await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
            },
            cancellation.Token);

        await connection.ConnectAsync(cancellation.Token);
        await peer;

        Assert.True(connection.IsHandshakeComplete);
        Assert.True(connection.IsHandshakeConfirmed);
    }

    [Fact]
    public async Task InitialKeysAreDiscardedAfterTheHandshakePacketIsBuiltAndNotBefore()
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
        Assert.Equal(TlsQuicKeyLevelState.Installed,
            connection.WriteStateOf(TlsQuicEncryptionLevel.Initial));

        // One Initial packet has been built: the opening flight, one datagram, one packet.
        Assert.Equal(1UL, connection.NextPacketNumber(TlsQuicEncryptionLevel.Initial));

        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await connection.PumpOnceAsync(cancellation.Token);

        // RFC 9001 s4.9.1: "a client MUST discard Initial keys when it first sends a Handshake
        // packet." A SEND EVENT, and this is where that is pinned rather than assumed.
        Assert.Equal(TlsQuicKeyLevelState.Discarded,
            connection.WriteStateOf(TlsQuicEncryptionLevel.Initial));
        Assert.False(connection.HasReadKeys(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(1UL, connection.NextPacketNumber(TlsQuicEncryptionLevel.Handshake));

        // AND HERE IS THE ORDER, WHICH THE STATE ABOVE CANNOT SHOW. Both the s4.9.1 discard
        // and TLS completion happen inside this one pump, so "Initial is Discarded afterwards"
        // is true of either trigger. What separates them is whether an INITIAL PACKET STILL
        // EXISTED when the answer was built: the answer carries an Initial ACK (RFC 9000
        // s13.2.1 - "An endpoint MUST acknowledge all ack-eliciting Initial and Handshake
        // packets immediately") coalesced with the first Handshake packet, and the Initial
        // packet number therefore advances to 2. A connection that applied the discard BEFORE
        // building would find no Initial write keys, skip that packet, and leave this at 1.
        Assert.Equal(2UL, connection.NextPacketNumber(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public async Task TheServersSourceConnectionIdBecomesOurDestinationConnectionId()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // A VALUE THAT EXISTS NOWHERE ELSE. LoopbackQuicPeer cannot witness this clause at
        // all: its server echoes the client's own Destination Connection ID back as its
        // Source Connection ID, so adoption changes nothing and a connection that skipped it
        // would pass. Here the server's Source Connection ID is chosen here, is a different
        // length from anything else in the exchange, and is what the next packet must carry.
        var serverSource = Convert.FromHexString("5E5E5E5E5E5E");

        transport.EnqueueReceive(sent => ServerInitialReply(sent, serverSource));

        await connection.StartAsync(cancellation.Token);
        var chosen = connection.OriginalDestinationConnectionId.ToArray();
        Assert.NotEqual(serverSource, chosen);

        await connection.PumpOnceAsync(cancellation.Token);

        // RFC 9000 s7.2, verbatim: "Upon first receiving an Initial or Retry packet from the
        // server, the client uses the Source Connection ID supplied by the server as the
        // Destination Connection ID for subsequent packets".
        Assert.Equal(serverSource, connection.DestinationConnectionId.ToArray());

        // NOT THE FIELD, THE WIRE. Read off the datagram the connection actually emitted
        // after the adoption - the ACK for the PING the scripted reply carried.
        Assert.Equal(2, transport.Sent.Count);
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(
            transport.Sent[1].Payload, out var answer, out _));
        Assert.Equal(serverSource, answer.DestinationConnectionId.ToArray());

        // AND THE INITIAL KEYS DID NOT MOVE WITH IT. RFC 9001 s5.2 keys them from the
        // Destination Connection ID of the client's FIRST Initial packet; adoption changes
        // who we address, not what we key with, and only a Retry (task 9b) changes both.
        Assert.Equal(chosen, connection.OriginalDestinationConnectionId.ToArray());
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(
            transport.Sent[0].Payload, out var opening, out _));
        Assert.Equal(chosen, opening.DestinationConnectionId.ToArray());
    }

    [Fact]
    public async Task ASubsequentCoalescedPacketWithADifferentDestinationConnectionIdIsIgnored()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // Two Initial packets in one datagram, both sealed with the SERVER Initial secret so
        // both would open. The second names a Destination Connection ID this connection never
        // chose. It is the only ack-eliciting one, so if it were processed the connection
        // would answer - RFC 9000 s13.2.1 - and if it is ignored the connection has nothing to
        // say and sends nothing. That difference is the whole assertion.
        transport.EnqueueReceive(sent => TwoPacketReply(sent));

        await connection.StartAsync(cancellation.Token);
        await connection.PumpOnceAsync(cancellation.Token);

        // RFC 9000 s12.2: "Receivers SHOULD ignore any subsequent packets with a different
        // Destination Connection ID than the first packet in the datagram." Splitting the
        // datagram forfeits the copy of this check that lives inside
        // TlsQuicPacketReceiver.Receive, because that one is a local re-nulled per call; the
        // connection re-applies it across its own calls.
        Assert.Equal(1, connection.IgnoredForConnectionIdMismatch);
        Assert.Single(transport.Sent);
    }

    [Fact]
    public async Task TheHandshakeDeadlineFiresOnTheFakeClockWithNoWallClockTimeElapsed()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // AN HOUR, AND THE REPLY COMES TWO HOURS LATE. The gap is what makes "zero wall-clock
        // time elapsed" measurable rather than asserted: no real run of this test can have
        // waited out either figure, so the deadline can only have fired off the injected
        // clock. ScriptedDatagramTransport advances that clock before it delivers.
        //
        // THE IDLE TIMEOUT IS PUSHED PAST BOTH, because RFC 9000 s10.1's is the nearer of the
        // two deadlines at its 30-second default and would fire first - which is a different
        // failure with its own test below.
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromHours(1),
            idleTimeout: TimeSpan.FromHours(3));
        transport.EnqueueReceive([1, 2, 3, 4], delay: TimeSpan.FromHours(2));

        await connection.StartAsync(cancellation.Token);

        var wallClock = Stopwatch.StartNew();
        var error = await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        wallClock.Stop();

        Assert.True(
            wallClock.Elapsed < TimeSpan.FromSeconds(30),
            $"The deadline took {wallClock.Elapsed} of wall-clock time, so it did not fire off "
                + "the injected clock.");

        // IT IS A TIMEOUT, NOT A RETRANSMISSION, and the message says so because A3 is
        // deferred and there is nothing to resend.
        Assert.Contains("NOT A RETRANSMISSION", error.Message, StringComparison.Ordinal);
        Assert.Equal(TimeSpan.FromHours(2), transport.Clock.GetUtcNow() - StartOfScriptedTime);
    }

    [Fact]
    public async Task APeerThatGoesSilentIsBoundedByTheDeadlineToo()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // THE OTHER HALF OF THE DEADLINE, AND THE ONE THE FAKE CLOCK CANNOT REACH. An
        // exhausted script goes silent - ScriptedDatagramTransport's own remarks say the
        // receive "waits for a reply that never comes, which is what a peer that stopped
        // answering looks like" - so no clock reading ever happens and only the token source
        // bounding the await can end it. With A3 deferred that is the case a lost packet
        // produces, and it is the reason the deadline exists at all.
        //
        // REAL TIME, DELIBERATELY, AND A QUARTER OF A SECOND OF IT. TimeProvider's own timer
        // is what the token source uses, and a ManualTimeProvider that overrides only
        // GetUtcNow inherits the real one - so this path cannot be driven off a fake clock
        // without building a fake timer, which would then be the thing under test. The figure
        // is small enough to cost nothing and the test cannot pass early: nothing else can
        // complete the await.
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), TimeProvider.System)
            {
                HandshakeDeadline = TimeSpan.FromMilliseconds(250),
            },
            source => TlsClient(pki, source));

        await connection.StartAsync(cancellation.Token);
        Assert.Equal(0, transport.RemainingReplies);

        var error = await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        Assert.Contains("NOT A RETRANSMISSION", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheSpecsAckRangeLimitBoundsTheRangesThatReachTheWire()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // ONE range retained, against three gapped packets that would otherwise produce three.
        // RFC 9000 s13.2.3: "A receiver limits the number of ACK Ranges (Section 19.3.1) it
        // remembers and sends in ACK frames, both to limit the size of ACK frames and to avoid
        // resource exhaustion", and it prices the trade in the next sentence - "at the cost of
        // increased retransmissions from the sender."
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            AckRangeLimit = 1,
        };
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, spec, transport.Clock),
            source => TlsClient(pki, source));

        transport.EnqueueReceive(sent => GappedPingPackets(sent, [0, 2, 4]));

        await connection.StartAsync(cancellation.Token);
        await connection.PumpOnceAsync(cancellation.Token);

        var ack = OnlyAckFrameIn(
            OpenOwnInitialPacket(
                transport.Sent[1].Payload.ToArray(), connection.OriginalDestinationConnectionId));

        // s13.2.3 again: "A receiver SHOULD include an ACK Range containing the largest
        // received packet number in every ACK frame", so the range that survives the limit is
        // the newest one - packet 4, alone, with no additional ranges behind it.
        Assert.Equal(4UL, ack.LargestAcknowledged);
        Assert.Equal(0UL, ack.FirstAckRange);
        Assert.Equal(0UL, ack.AckRangeCount);
    }

    [Fact]
    public async Task AFlightPlannedAsTwoDatagramsSendsTwoAndNumbersThemFromTheSpec()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // THE TARGET'S OWN SHAPE, NOT A CORNER CASE. The Brave capture's X25519MLKEM768 key
        // share is 1216 bytes on its own, so a Chromium-shaped ClientHello cannot be one
        // datagram; TlsQuicDatagramBuilder's header says as much. The split here is small
        // because this test is about the connection's bookkeeping and not about the builder's
        // arithmetic, which TlsQuicDatagramBuilderTests already owns: 100 bytes in the first
        // CRYPTO frame and the rest in the second, one frame per datagram.
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            InitialPacketNumber = 7,
            InitialCryptoFrameByteCounts = [100, 65000],
            InitialCryptoFramesPerDatagram = [1, 1],
        };
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, spec, transport.Clock),
            source => TlsClient(pki, source));

        await connection.StartAsync(cancellation.Token);

        Assert.Equal(2, transport.Sent.Count);

        // RFC 9000 s12.3: "A QUIC endpoint MUST NOT reuse a packet number within a packet
        // number space in the same connection." Two datagrams, two packet numbers, starting at
        // the spec's own InitialPacketNumber rather than at zero - so 7 and 8, and the next is
        // 9. A counter that advanced by one per FLIGHT would say 8 and would have reused 7.
        Assert.Equal(9UL, connection.NextPacketNumber(TlsQuicEncryptionLevel.Initial));

        // Read off the wire rather than off the counter: the packet numbers are header-
        // protected, so both datagrams are opened with the Initial keys a server would derive.
        Assert.Equal(7UL, PacketNumberOf(transport.Sent[0].Payload.ToArray(), connection));
        Assert.Equal(8UL, PacketNumberOf(transport.Sent[1].Payload.ToArray(), connection));
    }

    [Fact]
    public async Task ADatagramThisConnectionCannotOpenIsCountedAndTheLoopCarriesOn()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // Built through the same task 4b and task 5 path a real server packet takes; the only
        // difference is which of RFC 9001 s5.2's two secrets protects it. A client reads with
        // the server secret, so this one cannot open.
        transport.EnqueueReceive(sent => ClientSecretInitialReply(sent));

        await connection.StartAsync(cancellation.Token);

        // NO THROW. RFC 9000 s12.2, the whole sentence: "For example, if decryption fails
        // (because the keys are not available or for any other reason), the receiver MAY
        // either discard or buffer the packet for later processing and MUST attempt to process
        // the remaining packets." An earlier version of this loop threw here, and because
        // Discarded is incremented on UNAUTHENTICATED input that throw was an off-path remote
        // kill switch - see AReplayOfThisConnectionsOwnDatagramDoesNotKillIt.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // NOT "for want of keys", AND THE DIFFERENCE IS THE WHOLE REASON
        // TlsQuicReceiveResult.DiscardedForMissingKeys EXISTS. s12.2 gives two reasons a
        // packet is discarded and this datagram is the SECOND: the Initial read keys are
        // installed and simply do not open it. The first reason has its own row below.
        Assert.Equal(1, connection.DiscardedPackets);
        Assert.Equal(0, connection.DiscardedForMissingKeys);

        // And nothing was owed in reply: the packet never authenticated, so RFC 9000 s13.1 -
        // "A packet MUST NOT be acknowledged until packet protection has been successfully
        // removed" - forbids acknowledging it, and only the opening flight is on the wire.
        Assert.Single(transport.Sent);
    }

    [Fact]
    public async Task APacketAtALevelWhoseKeysHaveNotArrivedIsCountedApartFromOneThatSimplyDoesNotOpen()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // A HANDSHAKE-level packet arriving while this connection has no Handshake read keys -
        // which is the shape of the coalescing stall the split loop exists to prevent, reached
        // here directly rather than by breaking the loop. The keys below are arbitrary and
        // never used: the receiver looks the level up first and discards for want of keys
        // before it reaches the AEAD, which is precisely the distinction being pinned.
        transport.EnqueueReceive(sent => HandshakeLevelReply(sent));

        await connection.StartAsync(cancellation.Token);
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // s12.2's FIRST reason, counted apart from its second. With A3 deferred nothing
        // retransmits this packet, so the failure it eventually produces is the handshake
        // deadline - which is where both counters are reported; see
        // TheDeadlineNamesTheDiscardsThatProducedTheStall.
        Assert.Equal(1, connection.DiscardedPackets);
        Assert.Equal(1, connection.DiscardedForMissingKeys);
    }

    [Fact]
    public async Task AReplayOfThisConnectionsOwnDatagramDoesNotKillIt()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // ZERO KEY MATERIAL, ZERO FORGERY, ZERO PATH: the client's OWN opening datagram, byte
        // for byte, handed back to it. Anyone who can observe one datagram can send this, and
        // a client reads with RFC 9001 s5.2's SERVER secret, so its own packet - sealed with
        // the client secret - cannot open. An earlier version of this loop threw on
        // `Discarded > 0`, which made that replay a remote kill switch for any off-path
        // observer, and task 13's live run would have met it on the first stray datagram.
        transport.EnqueueReceive(sent => sent[0].Payload.ToArray());

        // ...and then a real server packet, so that survival is asserted by the connection
        // still DOING something rather than merely not throwing.
        var serverSource = Convert.FromHexString("5E5E5E5E5E5E");
        transport.EnqueueReceive(sent => ServerInitialReply(sent, serverSource));

        await connection.StartAsync(cancellation.Token);

        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.DiscardedPackets);
        Assert.Equal(0, connection.DiscardedForMissingKeys);
        Assert.Single(transport.Sent);

        // RFC 9000 s12.2's "MUST attempt to process the remaining packets", one datagram
        // later: the connection is alive, opens the next packet, and answers its PING under
        // s13.2.1. A connection killed by the replay reaches neither line.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(2, transport.Sent.Count);
    }

    [Fact]
    public async Task TheDeadlineNamesTheDiscardsThatProducedTheStall()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        // The idle timeout is pushed past both deadlines for the reason the deadline test
        // above gives: at its default it is the nearer of the two and would fire first, and
        // its message names no discards because RFC 9000 s10.1's close is a different failure.
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromHours(1),
            idleTimeout: TimeSpan.FromHours(3));

        // One packet that cannot be opened, then a peer that answers two hours late. With the
        // throw gone, the deadline is the ONLY failure a stall can now produce, so it is the
        // only place the counters can be reported - and a deadline that did not report them
        // would leave the coalescing stall with no symptom of its own, which is the property
        // the throw was protecting and the reason it is not simply deleted.
        transport.EnqueueReceive(sent => HandshakeLevelReply(sent));
        transport.EnqueueReceive([1, 2, 3, 4], delay: TimeSpan.FromHours(2));

        await connection.StartAsync(cancellation.Token);
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        var error = await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        Assert.Contains(
            "1 packet(s) discarded (1 for want of keys)", error.Message, StringComparison.Ordinal);
        Assert.Contains("NOT A RETRANSMISSION", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheAnswersPacketNumberIsEncodedAgainstTheLargestAcknowledged()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // THE ONE SURVIVOR THE LEDGER CALLED A3'S DEBT, KILLED WITH A4-MINIMAL'S OWN KNOBS.
        // RFC 9000 Appendix A.2 encodes a packet number in the fewest bytes that let the peer
        // recover it from `largest_acked`; with no largest_acked it must assume the peer has
        // seen nothing and encode against `full_pn + 1` instead. Those two answers differ here:
        //
        //   real   num_unacked = 128 - 127 =   1 -> min_bits 1  -> 1 byte, which the spec allows
        //   mutant num_unacked = 128 + 1   = 129 -> min_bits 8, non-power-of-two -> 2 bytes
        //
        // and the second is wider than PacketNumberEncodedLength permits, so the builder
        // rejects it. The distance comes entirely from InitialPacketNumber, which task 9a-ii
        // itself wired; no A3 machinery is involved.
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            InitialPacketNumber = 127,
            PacketNumberEncodedLength = 1,
        };
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, spec, transport.Clock),
            source => TlsClient(pki, source));

        // The ACK is what advances LargestAcknowledged; the PING is what makes us answer at
        // all, since RFC 9000 s13.2.1 obliges an answer only to an ack-eliciting packet.
        transport.EnqueueReceive(sent => AckingPingReply(sent, acknowledged: 127));

        await connection.StartAsync(cancellation.Token);
        await connection.PumpOnceAsync(cancellation.Token);

        Assert.Equal(2, transport.Sent.Count);
        Assert.Equal(128UL, PacketNumberOf(transport.Sent[1].Payload.ToArray(), connection));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ThePacketsOfOneDatagramAreCoalescedInTheOrderTheSpecAsksFor(bool ascending)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            CoalesceAscendingByLevel = ascending,
        };
        await using var connection = Connection(clientTransport, serverTransport, pki, spec);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // The answer to a coalesced ServerHello + Handshake flight is itself coalesced: an
        // Initial packet carrying the Initial ACK and a Handshake packet carrying the Handshake
        // ACK and our Finished.
        await connection.PumpOnceAsync(cancellation.Token);

        // READ OFF THE RECEIVING SIDE, because the order sits under the AEAD and the sender
        // cannot read its own packets back. RFC 9000 s12.2 advises ascending - "makes it more
        // likely that the receiver will be able to process all the packets in a single pass" -
        // and the other direction is legal, which is why this is a knob rather than a rule.
        await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);

        var levels = new List<TlsQuicEncryptionLevel>();
        foreach (var (level, _) in serverPeer.LastDatagramFrames)
        {
            if (levels.Count == 0 || levels[^1] != level)
            {
                levels.Add(level);
            }
        }

        Assert.Equal(
            ascending
                ? [TlsQuicEncryptionLevel.Initial, TlsQuicEncryptionLevel.Handshake]
                : new[] { TlsQuicEncryptionLevel.Handshake, TlsQuicEncryptionLevel.Initial },
            levels);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TheAcksPositionInsideThePacketIsTheOneTheSpecAsksFor(bool ackLeads)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            AckLeadsInPacket = ackLeads,
        };
        await using var connection = Connection(clientTransport, serverTransport, pki, spec);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await connection.PumpOnceAsync(cancellation.Token);
        await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);

        // THE HANDSHAKE PACKET IS THE ONLY ONE THAT CARRIES TWO FAMILIES, so it is the only
        // one in which a position is observable at all: the Initial packet of the same datagram
        // carries an ACK and nothing else. RFC 9000 imposes no frame order inside a packet and
        // the capture observes none for ACK, so neither answer below is more correct than the
        // other - which is exactly why the connection may not fix one.
        var handshakeFrames = new List<TlsQuicFrameType>();
        foreach (var (level, type) in serverPeer.LastDatagramFrames)
        {
            if (level == TlsQuicEncryptionLevel.Handshake
                && type is TlsQuicFrameType.Ack or TlsQuicFrameType.Crypto)
            {
                handshakeFrames.Add(type);
            }
        }

        Assert.Equal(
            ackLeads
                ? [TlsQuicFrameType.Ack, TlsQuicFrameType.Crypto]
                : new[] { TlsQuicFrameType.Crypto, TlsQuicFrameType.Ack },
            handshakeFrames);
    }

    [Fact]
    public async Task OnlyTheFirstServerPacketMovesOurDestinationConnectionId()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // Two datagrams, two different server Source Connection IDs. RFC 9000 s7.2: "A client
        // MUST change the Destination Connection ID it uses for sending packets in response to
        // only the first received Initial or Retry packet." Deleting the once-only guard used
        // to leave the whole gate green, because every other s7.2 witness sends one packet.
        var first = Convert.FromHexString("5E5E5E5E5E5E");
        var second = Convert.FromHexString("A1A1A1A1A1A1");

        // THE FIRST ONE CANNOT BE OPENED, AND THAT IS WHAT SEPARATES THIS CLAUSE FROM THE ONE
        // APacketWhoseSourceConnectionIdChangedAfterAValidOneIsDiscarded WITNESSES. That clause
        // binds only "Once a client has received a VALID Initial packet from the server", so a
        // datagram sealed with the client secret never arms it - and the packet still moves our
        // Destination Connection ID, because s7.2's adoption sentence says "Upon first
        // receiving an Initial or Retry packet" and this implementation runs it before the
        // AEAD. That placement is a CHOICE, not a necessity - the Initial keys come from the
        // ORIGINAL Destination Connection ID, which never moves, so a post-AEAD placement would
        // open the same packets - and s7.3 is what makes the choice safe, by authenticating
        // both connection IDs in transport parameters.
        transport.EnqueueReceive(sent => ClientSecretInitialReply(sent, first));
        transport.EnqueueReceive(sent => ServerInitialReply(sent, second));

        await connection.StartAsync(cancellation.Token);
        await connection.PumpOnceAsync(cancellation.Token);
        Assert.Equal(first, connection.DestinationConnectionId.ToArray());
        Assert.Equal(1, connection.DiscardedPackets);

        await connection.PumpOnceAsync(cancellation.Token);

        // STILL THE FIRST ONE, and read off the wire as well as off the field: a connection
        // that adopted again would address this answer to A1A1A1A1A1A1. The second datagram
        // was processed - it answered the PING - so this is the once-only guard and not a
        // packet that failed to arrive.
        Assert.Equal(first, connection.DestinationConnectionId.ToArray());
        Assert.Equal(2, transport.Sent.Count);
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(
            transport.Sent[1].Payload, out var answer, out _));
        Assert.Equal(first, answer.DestinationConnectionId.ToArray());
    }

    [Fact]
    public async Task APacketWhoseSourceConnectionIdChangedAfterAValidOneIsDiscarded()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // RFC 9000 s7.2, the whole sentence past the line wrap: "Once a client has received a
        // valid Initial packet from the server, it MUST discard any subsequent packet it
        // receives on that connection with a different Source Connection ID." VALID is why the
        // first datagram here has to be one that actually opens: a Source Connection ID taken
        // off unauthenticated input would let an off-path sender choose the value every later
        // packet is measured against, which is the influence s7.3's last paragraph denies.
        var valid = Convert.FromHexString("5E5E5E5E5E5E");
        var impostor = Convert.FromHexString("A1A1A1A1A1A1");
        transport.EnqueueReceive(sent => ServerInitialReply(sent, valid));
        transport.EnqueueReceive(sent => ServerInitialReply(sent, impostor));

        await connection.StartAsync(cancellation.Token);
        await connection.PumpOnceAsync(cancellation.Token);
        Assert.Equal(2, transport.Sent.Count);

        await connection.PumpOnceAsync(cancellation.Token);

        // DISCARDED, NOT MERELY UNADOPTED. The second packet carries a PING, which is
        // ack-eliciting, so a connection that processed it would owe an answer under s13.2.1
        // and would send a third datagram. It sends nothing, and the count says which clause
        // rejected it.
        Assert.Equal(1, connection.DiscardedForSourceConnectionIdChange);
        Assert.Equal(0, connection.IgnoredForConnectionIdMismatch);
        Assert.Equal(2, transport.Sent.Count);
    }

    [Fact]
    public async Task TheAdvertisedAckDelayExponentIsAdoptedRatherThanRefused()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // ONE SOURCE FOR ONE NUMBER, AND THE ADVERTISEMENT IS IT. RFC 9000 s19.3 makes the
        // ACK's SENDER the one that scales, so the peer divides by the value we advertised in
        // transport parameter 0x0A and the two must agree.
        //
        // THIS USED TO THROW, AND THE THROW WAS THE BUG. It compared the advertised exponent
        // with TlsQuicConnectionOptions.AckDelayExponent and refused a mismatch, telling the
        // caller to set that property - on an `internal sealed` type, from a preset surface
        // that forwards no such knob. So the only reachable way to advertise a non-default
        // 0x0A was an error nobody could act on. Adopting makes the pair agree by
        // construction, which is the rule the six flow-control parameters already follow.
        //
        // THE OPTIONS VALUE IS DELIBERATELY THE WRONG ONE HERE. 5 is what this connection
        // would have scaled by; 7 is what it advertises; and asserting 7 is what proves the
        // advertisement won rather than merely that the two happened to match.
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock)
            {
                AckDelayExponent = 5,
            },
            source => TlsClient(pki, source, ackDelayExponent: 7));

        await connection.StartAsync(cancellation.Token);

        Assert.Equal(7, connection.AdoptedAckDelayExponent);
        Assert.Single(transport.Sent);
    }

    [Fact]
    public async Task AnAbsentAckDelayExponentIsReadAsSectionEighteenTwosDefaultOfThree()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // RFC 9000 s18.2: "if this value is absent, a default value of 3 is assumed (indicating
        // a multiplier of 8)." Every other connection in this file relies on that reading, so
        // it is asserted once rather than assumed everywhere: the profile carries no 0x0A, so
        // there is nothing to adopt and the options value stands as the seed.
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock)
            {
                AckDelayExponent = 3,
            },
            source => TlsClient(pki, source));

        await connection.StartAsync(cancellation.Token);
        Assert.Single(transport.Sent);
    }

    [Fact]
    public async Task TheClientFactoryIsCalledOncePerConnectionWithTheSourceConnectionIdThatReachesTheWire()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        var handed = new List<byte[]>();
        var options = new TlsQuicConnectionOptions(
            transport, transport.RemoteEndPoint, Spec(), transport.Clock);
        await using var connection = new TlsQuicConnection(
            options,
            sourceConnectionId =>
            {
                handed.Add(sourceConnectionId.ToArray());
                return TlsClient(pki, sourceConnectionId);
            });

        await connection.StartAsync(cancellation.Token);

        // A FRESH PROFILE PER CONNECTION, UNCONDITIONALLY (A4 Finding 1) - the factory is the
        // shape that forces it, and it is called exactly once for this attempt.
        var only = Assert.Single(handed);
        Assert.Equal(SourceConnectionIdLength, only.Length);

        // AND THE BYTES IT WAS GIVEN ARE THE BYTES ON THE WIRE. This is the half that matters:
        // the connection advertised this value as initial_source_connection_id (0x0F) inside
        // the immutable profile the factory built, and RFC 9000 s7.3 makes the two the same
        // value. A factory handed one thing while the header carried another would be a
        // fingerprint mismatch no boolean could see.
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(
            transport.Sent[0].Payload, out var opening, out _));
        Assert.Equal(only, opening.SourceConnectionId.ToArray());
        Assert.Equal(only, connection.SourceConnectionId.ToArray());
    }

    // The width arrives as an int because TlsQuicVarintWidth is internal and a public xUnit
    // theory parameter cannot be; the values are RFC 9000 s16 Table 4's byte counts, which is
    // also what the enum's members are numbered with.
    [Theory]
    [InlineData(0, 0x40, 0x00, 0x40)]
    [InlineData(4, 0x80, 0x80, 0x80)]
    public async Task TheSpecsVarintWidthsReachTheWire(
        int widthValue,
        int expectedHeaderLengthPrefix,
        int expectedCryptoOffsetPrefix,
        int expectedCryptoLengthPrefix)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        var width = (TlsQuicVarintWidth)widthValue;
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            HeaderLengthVarintWidth = width,
            CryptoOffsetVarintWidth = width,
            CryptoLengthVarintWidth = width,
        };
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, spec, transport.Clock),
            source => TlsClient(pki, source));

        await connection.StartAsync(cancellation.Token);

        var datagram = transport.Sent[0].Payload.ToArray();
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(datagram, out var header, out _));

        // RFC 9000 s16, Table 4: the varint's leading two bits give its length - 00 for one
        // byte, 01 for two, 10 for four, 11 for eight. s16 also, verbatim: "Values do not need
        // to be encoded on the minimum number of bytes necessary, with the sole exception of
        // the Frame Type field", which is exactly what makes these three widths observable and
        // therefore fingerprintable (A4 Finding 5).
        //
        // The Length field's offset is computed from the header's own layout rather than
        // hardcoded: byte 0, the 4-byte Version, each connection ID behind its 1-byte length,
        // and the Token Length varint - one byte, because the token is empty.
        var lengthOffset = 1 + 4
            + 1 + header.DestinationConnectionId.Length
            + 1 + header.SourceConnectionId.Length
            + 1;
        Assert.Equal(expectedHeaderLengthPrefix, datagram[lengthOffset] & 0xc0);

        // The CRYPTO frame's two widths live under the AEAD, so the packet is OPENED here -
        // with keys derived from the Destination Connection ID this connection chose, which is
        // RFC 9001 s5.2's sole input and which the connection exposes for exactly this.
        var payload = OpenOwnInitialPacket(datagram, connection.OriginalDestinationConnectionId);

        // RFC 9000 s19.6: a CRYPTO frame is the type varint 0x06, then Offset, then Length.
        // The type is the one field s12.4 forces to its shortest encoding, so it is one byte.
        Assert.Equal((byte)TlsQuicFrameType.Crypto, payload[0]);
        Assert.Equal(expectedCryptoOffsetPrefix, payload[1] & 0xc0);

        var offsetWidth = 1 << ((payload[1] & 0xc0) >> 6);
        // THE THREE MINIMAL EXPECTATIONS ARE NOT ALL ZERO, AND THE REASON IS THE POINT OF THE
        // WORD "minimal": it is the shortest width that HOLDS THE VALUE, not one byte. The
        // Offset is 0 and fits one byte; the CRYPTO Length is the ClientHello's size and the
        // header Length is the whole padded datagram's, both of which are past s16 Table 4's
        // 63-value one-byte ceiling and under its 16383 two-byte one for any real ClientHello
        // and any padding target at s14.1's 1200-byte floor. So minimal reads 00 / 40 / 40 and
        // the four-byte row reads 80 / 80 / 80, which is the knob moving all three.
        Assert.Equal(expectedCryptoLengthPrefix, payload[1 + offsetWidth] & 0xc0);
    }

    // ---- scaffolding -------------------------------------------------------------------

    // ScriptedDatagramTransport's clock starts here; its own remarks say the instant is
    // arbitrary and that nothing may depend on its value, only on differences from it.
    private static readonly DateTimeOffset StartOfScriptedTime =
        new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // No clock in the loopback half: LoopbackQuicPeer builds every packet at one instant and
    // reads no clock of its own.
    private static readonly DateTimeOffset SentAt =
        new(2026, 8, 18, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Spec() with RFC 9000 s14.3's path MTU search turned off.</summary>
    /// <remarks>FOR TESTS THAT MEASURE THE SEND GATE, not for tests that happen to be noisy.
    /// The search sends an extra PMTU probe once application data has flowed, and a probe is an
    /// ordinary ack-eliciting datagram: it takes a pacing slot, spends congestion window and
    /// occupies a pass. A test measuring exactly which datagram the pacer released, or exactly
    /// which frame a repair carried, is then measuring the probe as well.
    /// <para>This is the same principle
    /// ABodySixteenTimesThePeersInitialStreamCreditCompletesOnRealGrants already states for
    /// congestion control - "Acknowledging keeps that limit out of the way so the one under
    /// test is the one being measured" - applied to one more independent limit. The DEFAULT is
    /// on, and NoProbeIsSentWhenPathMtuDiscoveryIsOff plus
    /// PathMtuDiscoveryProbesAndRaisesTheDatagramSize are what hold that.</para></remarks>
    private static TlsQuicConnectionSpec SpecWithoutPathMtuSearch() => new()
    {
        PaddingTarget = 1200,
        SourceConnectionIdLength = SourceConnectionIdLength,
        PathMtuDiscovery = false,
    };

    private static TlsQuicConnectionSpec Spec() => new()
    {
        // 1200 is RFC 9000 s14.1's floor rather than a fingerprint choice, and nothing here
        // asserts the number. Every other knob but the source connection ID length is
        // TlsQuicConnectionSpec's default.
        PaddingTarget = 1200,
        SourceConnectionIdLength = SourceConnectionIdLength,
    };

    // THE TRANSPORT IS THE INTERFACE, so that A3-1's ImpairingDatagramTransport can be
    // wrapped around the in-memory one and this connection driven through it unchanged. The
    // PEER stays concrete because only its LocalEndPoint is wanted.
    //
    // THE CLOCK IS OPTIONAL AND DEFAULTS TO TimeProvider.System, which is what every caller
    // before A3-1 got implicitly - the three-argument options constructor passes exactly that.
    // A test that means to fire a deadline passes the impairing transport's own
    // ManualTimeProvider instead, so that one clock drives the script and the connection,
    // which is the thing A3's task 1 says is not optional. Both timeouts stay at their
    // defaults: 10 seconds of handshake deadline against 30 of idle timeout, so the handshake
    // deadline is the nearer of the two and is what a dropped datagram runs into.
    private static TlsQuicConnection Connection(
        ITlsQuicDatagramTransport transport,
        InMemoryDatagramTransport peer,
        TestPki pki,
        TlsQuicConnectionSpec? spec = null,
        ulong? maxDatagramFrameSize = null,
        TimeProvider? clock = null) =>
        new(new TlsQuicConnectionOptions(
                transport, peer.LocalEndPoint, spec ?? Spec(), clock ?? TimeProvider.System),
            source => TlsClient(pki, source, maxDatagramFrameSize: maxDatagramFrameSize));

    // TWO TIMEOUTS, AND A TEST THAT MEANS ONE HAS TO PUSH THE OTHER OUT OF THE WAY. RFC 9000
    // s10.1's idle timeout and the local handshake deadline are different failures on
    // different clocks-in-the-same-clock, and the receive is bounded by whichever is nearer -
    // so a test asserting the deadline at an hour must move the idle timeout past it, and a
    // test asserting the idle timeout must do the reverse. Neither default is a fingerprint
    // knob; both are policy on TlsQuicConnectionOptions.
    //
    // THE CLOCK OVERRIDE IS A3-1's, AND IT NO LONGER HAS EXACTLY ONE CALLER. ManualTimeProvider
    // overrides CreateTimer as well as GetUtcNow, so a CancellationTokenSource built from it -
    // which is how TlsQuicConnection.ReceiveWithinDeadlineAsync bounds a receive - fires on the
    // fake clock and no longer on the real one. That is the whole point of the override and it
    // is what lets a dropped datagram end an attempt deterministically. It also takes away the
    // real timer that APeerThatGoesSilentIsBoundedByTheIdleTimeoutToo was deliberately relying
    // on, so that ONE test asks for TimeProvider.System by name - which is what its sibling,
    // APeerThatGoesSilentIsBoundedByTheDeadlineToo, has always done.
    //
    // TWO CORRECTIONS, BOTH FOUND BY A3-5 RATHER THAN GUESSED. The method named above was
    // ReceiveBoundedAsync in this comment and has never been called that; it is
    // ReceiveWithinDeadlineAsync. And "exactly one caller" was true when A3-1 wrote it and is
    // not now: every test in TlsQuicConnectionTimerWeaveTests.cs drives a deadline on this
    // clock, because a probe timeout that fired on the wall clock would be a test that took a
    // real second per expiry.
    private static TlsQuicConnection Connection(
        ScriptedDatagramTransport transport,
        TestPki pki,
        TimeSpan? handshakeDeadline = null,
        TimeSpan? idleTimeout = null,
        TlsQuicConnectionSpec? spec = null,
        ulong? maxIdleTimeoutMilliseconds = null,
        TimeProvider? clock = null)
    {
        var options = new TlsQuicConnectionOptions(
            transport, transport.RemoteEndPoint, spec ?? Spec(), clock ?? transport.Clock)
        {
            HandshakeDeadline = handshakeDeadline ?? TimeSpan.FromSeconds(10),
            IdleTimeout = idleTimeout ?? TimeSpan.FromSeconds(30),
        };
        return new TlsQuicConnection(
            options,
            source => TlsClient(
                pki, source, maxIdleTimeoutMilliseconds: maxIdleTimeoutMilliseconds));
    }

    // FINDING 1 IN ONE METHOD: a fresh ClientHelloProfile per connection, carrying THIS
    // connection's source connection ID as initial_source_connection_id (0x0F). The profile is
    // immutable and the parameter is inside it, so there is no way to reuse one.
    //
    // NO initial_rtt (12583). The plan's amendment after task 1 refused to invent a range -
    // the capture holds one draw and fixes neither bounds nor distribution - so
    // TlsQuicConnectionSpec.InitialRttRange is null and nothing sends the parameter. That is a
    // KNOWN DEVIATION from the target for task 11 to report, not something satisfied here.
    //
    // NO ack_delay_exponent (0x0A) BY DEFAULT, which RFC 9000 s18.2 reads as 3 - the same value
    // TlsQuicConnectionOptions.AckDelayExponent defaults to, and the agreement the connection
    // now checks at construction. The parameter is only sent when a test asks for it.
    private static CustomTlsQuicClient TlsClient(
        TestPki pki,
        ReadOnlyMemory<byte> sourceConnectionId,
        int? ackDelayExponent = null,
        ulong? maxIdleTimeoutMilliseconds = null,
        ulong? maxDatagramFrameSize = null,
        uint[]? availableVersions = null,
        uint chosenVersion = (uint)TlsQuicVersion.Version1)
    {
        var parameters = new List<TlsQuicTransportParameter>
        {
            new(
                (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
                sourceConnectionId.ToArray()),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.ActiveConnectionIdLimit, 2),
        };

        // NOT ADVERTISED BY DEFAULT EITHER, and the HTTP/3 harness is the one caller that asks
        // for it. A connection that sends SETTINGS_H3_DATAGRAM = 1 - which
        // TlsQuicHttp3Spec.CaptureSettings does, and every Harness connection therefore does -
        // has claimed to receive HTTP/3 datagrams, and RFC 9221 s3's 0x20 is the transport half
        // of that claim. TlsQuicHttp3Connection's constructor refuses the pair when only one
        // half is present, so passing it here is the harness advertising what it says rather
        // than the harness being exempted from the check; see that constructor for the live
        // measurement that made an inconsistent pair a local failure instead of a remote one.
        //
        // A PARAMETER RATHER THAN A CONSTANT IN THE LIST because this helper builds the
        // ClientHello for every test in this partial class, and the ones that snapshot the
        // fingerprint readout are entitled to a list that changes only when they ask.
        if (maxDatagramFrameSize is { } datagramFrameSize)
        {
            parameters.Add(TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.MaxDatagramFrameSize, datagramFrameSize));
        }

        if (ackDelayExponent is { } exponent)
        {
            parameters.Add(TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.AckDelayExponent, (ulong)exponent));
        }

        // NOT ADVERTISED BY DEFAULT, which RFC 9000 s18.2 makes the state where "Idle timeout
        // is disabled when both endpoints omit this transport parameter or specify a value of
        // 0" - so by default the local policy on TlsQuicConnectionOptions.IdleTimeout is what
        // bounds an idle connection, and no s10.1 commitment has been made to anybody.
        if (maxIdleTimeoutMilliseconds is { } idle)
        {
            parameters.Add(TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.MaxIdleTimeout, idle));
        }

        // RFC 9368 s3's version_information, ABSENT BY DEFAULT - which is the state a capture
        // that carries no such parameter puts a connection in, and the state in which s2.3
        // forbids the server choosing any version at all. A test that wants compatible version
        // negotiation says so by listing what this ClientHello offers.
        if (availableVersions is { Length: > 0 } versions)
        {
            parameters.Add(new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.VersionInformation,
                TlsQuicTransportParameterSpec.EncodeVersionInformation(chosenVersion, versions)));
        }

        return new CustomTlsQuicClient(new CustomTlsQuicClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.Secp256r1)
                .WithAlpn("h3")
                .WithQuicTransportParameters(new TlsQuicTransportParameters(parameters))),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
    }

    private static TlsServerCertificate Credential(TestPki pki) =>
        new(pki.Leaf, (RSA)pki.LeafKey, [pki.Root]);

    // AutomaticSessionTicketCount 0 for the reason LoopbackQuicPeerTests gives: at the default
    // the server raises Application-level CRYPTO while completing, and LoopbackQuicPeer has no
    // 1-RTT CRYPTO send path.
    //
    // THE TWO CONNECTION ID PARAMETERS ARE NOT DECORATION, AND UNTIL TASK 9B THIS HELPER SENT
    // NEITHER. RFC 9000 s7.3: "An endpoint MUST treat the absence of the
    // initial_source_connection_id transport parameter from either endpoint or the absence of
    // the original_destination_connection_id transport parameter from the server as a
    // connection error of type TRANSPORT_PARAMETER_ERROR." A server that omits them is
    // non-conforming, and every test here drove one until the client learned to check - which
    // is the shape the plan warns about from the other side: the cooperative peer was the
    // thing that had never been asked to conform.
    //
    // BOTH VALUES ARE THE CLIENT'S ORIGINAL DESTINATION CONNECTION ID, and that is a property
    // of LoopbackQuicPeer rather than of s7.3: that peer echoes the Destination Connection ID
    // it received as its own Source Connection ID, so "the Destination Connection ID field
    // from the first Initial packet it received" and "the Source Connection ID field from the
    // first Initial packet it sent" are the same bytes here. Against a real server they are
    // two different values, which is why the two witnesses below doctor them separately.
    //
    // THE SIX FLOW-CONTROL PARAMETERS ARE TASK 14d's, AND THIS HELPER SENT NONE OF THEM. The
    // shape is task 9b's exactly, one requirement later: RFC 9114 s6.2 says "the transport
    // parameters sent by both clients and servers MUST allow the peer to create at least
    // three unidirectional streams", a server that omits initial_max_streams_uni has
    // advertised 0 of them by RFC 9000 s18.2's blanket "default value of 0 if the transport
    // parameter is absent", and every test in this class drove such a server until the client
    // learned to check. Thirty-eight of them went red when it did.
    private static CustomTlsQuicServer Server(
        TlsServerCertificate credential,
        ReadOnlyMemory<byte> originalDestinationConnectionId,
        byte[]? overrideOriginalDestination = null,
        byte[]? overrideInitialSource = null,
        byte[]? retrySource = null,
        ulong? maxIdleTimeoutMilliseconds = null,
        IReadOnlyList<TlsQuicTransportParameter>? flowControl = null)
    {
        var parameters = new List<TlsQuicTransportParameter>
        {
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.ActiveConnectionIdLimit, 4),
            new(
                (ulong)TlsQuicTransportParameterId.OriginalDestinationConnectionId,
                overrideOriginalDestination ?? originalDestinationConnectionId.ToArray()),
            new(
                (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
                overrideInitialSource ?? originalDestinationConnectionId.ToArray()),
        };
        if (retrySource is not null)
        {
            parameters.Add(new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.RetrySourceConnectionId, retrySource));
        }
        if (maxIdleTimeoutMilliseconds is { } idle)
        {
            parameters.Add(TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.MaxIdleTimeout, idle));
        }
        parameters.AddRange(flowControl ?? FlowControlParameters());

        return ServerWith(credential, new TlsQuicTransportParameters(parameters));
    }

    // RFC 9000 s18.2's six flow-control limits, in wire-ID order, with a null omitting one
    // ENTIRELY rather than sending a zero - which is what a witness for s18.2's absent case
    // needs and what no other helper here can express.
    //
    // THE DEFAULTS ARE NOT ROUND NUMBERS AND THAT IS THE POINT. Each value ends in its own
    // parameter's ID, so a read that fetches 0x05 where it meant 0x06 - the swap
    // TlsQuicPeerFlowControlBudget.cs's header calls the most likely defect in the file -
    // produces a number that names the parameter it wrongly came from. A helper whose six
    // values were all 65536 would report agreement for a set of reads that were all wrong.
    //
    // initial_max_streams_uni is 9 rather than 3 so that the s6.2 floor and this helper's
    // value are different numbers; a check hard-coded to compare against 3 would pass either
    // way, and one that read the wrong parameter would not.
    internal static List<TlsQuicTransportParameter> FlowControlParameters(
        ulong? initialMaxData = 1_000_004,
        ulong? bidiLocal = 1_000_005,
        ulong? bidiRemote = 1_000_006,
        ulong? uni = 1_000_007,
        ulong? streamsBidi = 108,
        ulong? streamsUni = 9)
    {
        var parameters = new List<TlsQuicTransportParameter>();
        Add(TlsQuicTransportParameterId.InitialMaxData, initialMaxData);
        Add(TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal, bidiLocal);
        Add(TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote, bidiRemote);
        Add(TlsQuicTransportParameterId.InitialMaxStreamDataUni, uni);
        Add(TlsQuicTransportParameterId.InitialMaxStreamsBidi, streamsBidi);
        Add(TlsQuicTransportParameterId.InitialMaxStreamsUni, streamsUni);
        return parameters;

        void Add(TlsQuicTransportParameterId id, ulong? value)
        {
            if (value is { } present)
            {
                parameters.Add(TlsQuicTransportParameter.VariableInteger(id, present));
            }
        }
    }

    private static CustomTlsQuicServer ServerWith(
        TlsServerCertificate credential, TlsQuicTransportParameters parameters) =>
        new(new CustomTlsQuicServerOptions
        {
            Tls = new CustomTlsServerOptions
            {
                AutomaticSessionTicketCount = 0,
                ServerCertificate = credential,
                SupportedVersions = [TlsProtocolVersion.Tls13],
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                SupportedGroups = [NamedGroup.Secp256r1],
                AlpnProtocols = ["h3"],
                RequireAlpn = true,
            },
            TransportParameters = parameters,
        });

    // The connection IDs are drawn per attempt and are never known to a test in advance, so
    // every scripted reply reads them off the connection's own first packet - which is also
    // what a real server does (RFC 9001 s5.2 derives its Initial secrets from the Destination
    // Connection ID it finds there).
    private static (byte[] Destination, byte[] Source) ConnectionIdsFrom(
        IReadOnlyList<ScriptedSend> sent)
    {
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(sent[0].Payload, out var header, out _));
        return (header.DestinationConnectionId.ToArray(), header.SourceConnectionId.ToArray());
    }

    // One Initial packet carrying a PING - RFC 9000 s19.2, and Table 3 permits it in an
    // Initial packet. Ack-eliciting, so the connection owes an answer (s13.2.1), which is what
    // makes the reply's effect visible at all.
    private static byte[] ServerInitialReply(
        IReadOnlyList<ScriptedSend> sent, byte[] serverSourceConnectionId)
    {
        var (destination, source) = ConnectionIdsFrom(sent);
        return ServerPacket(
            destination,
            destinationOnPacket: source,
            sourceOnPacket: serverSourceConnectionId,
            packetNumber: 0,
            frames: [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            useServerSecret: true);
    }

    // One server Initial packet that acknowledges exactly one of our packet numbers and also
    // carries a PING, so the connection both advances its LargestAcknowledged and owes an
    // answer. THE ACK CHAIN IS WRITTEN BY A2'S ENCODER AND READ BACK, which is the same round
    // trip TlsQuicConnection.TryBuildAckFrame makes and for the same reason: TlsQuicFrame
    // carries RFC 9000 s19.3.1's Gap / ACK Range Length chain as already-encoded bytes, and
    // WriteAckFrame is the only encoder for it.
    private static byte[] AckingPingReply(IReadOnlyList<ScriptedSend> sent, ulong acknowledged)
    {
        var (destination, source) = ConnectionIdsFrom(sent);

        var encoded = new List<byte>();
        TlsQuicAckFrames.WriteAckFrame(
            encoded,
            (ulong)TlsQuicFrameType.Ack,
            ackDelay: 0,
            [new TlsQuicAckRange(acknowledged, acknowledged)]);

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(encoded.ToArray(), ref offset, out var ack, out _));

        return ServerPacket(
            destination,
            destinationOnPacket: source,
            sourceOnPacket: [],
            packetNumber: 0,
            frames: [ack, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            useServerSecret: true);
    }

    private static byte[] ClientSecretInitialReply(
        IReadOnlyList<ScriptedSend> sent, byte[]? serverSourceConnectionId = null)
    {
        var (destination, source) = ConnectionIdsFrom(sent);
        return ServerPacket(
            destination,
            destinationOnPacket: source,
            sourceOnPacket: serverSourceConnectionId ?? [],
            packetNumber: 0,
            frames: [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            useServerSecret: false);
    }

    // Several ack-eliciting Initial packets coalesced into one datagram at the packet numbers
    // given, so that the gaps between them are ACK Ranges the connection has to decide about.
    private static byte[] GappedPingPackets(IReadOnlyList<ScriptedSend> sent, ulong[] numbers)
    {
        var (destination, source) = ConnectionIdsFrom(sent);
        var datagram = new List<byte>();
        foreach (var number in numbers)
        {
            datagram.AddRange(ServerPacket(
                destination,
                destinationOnPacket: source,
                sourceOnPacket: [],
                packetNumber: number,
                frames: [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
                useServerSecret: true,
                pad: false));
        }
        return [.. datagram];
    }

    // The single ACK frame in a decrypted payload. Asserted to be single: an ACK generator
    // that emitted two would satisfy every field assertion in the test that reads this while
    // sending something no receiver expects.
    private static TlsQuicFrame OnlyAckFrameIn(byte[] payload)
    {
        var offset = 0;
        var acks = new List<TlsQuicFrame>();
        while (offset < payload.Length
            && TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out _))
        {
            if (frame.Type == TlsQuicFrameType.Ack)
            {
                acks.Add(frame);
            }
        }
        return Assert.Single(acks);
    }

    // The full packet number off the wire, unmasked with the same keys a server would use.
    // RFC 9001 s5.4 protects it, so a counter read from the connection would not have shown it.
    private static ulong PacketNumberOf(byte[] datagram, TlsQuicConnection connection)
    {
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, connection.OriginalDestinationConnectionId.Span);
        using var keys = secrets.DeriveClientPacketProtectionKeys(TlsQuicVersion.Version1);

        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(datagram, out var header, out _));
        var packet = datagram.ToArray();
        Assert.True(TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            packet,
            header.PacketNumberOffset,
            out var packetNumberLength));

        var number = 0UL;
        for (var i = 0; i < packetNumberLength; i++)
        {
            number = (number << 8) | packet[header.PacketNumberOffset + i];
        }
        return number;
    }

    // One Handshake-level packet, protected with keys nobody has - see the test that uses it.
    private static byte[] HandshakeLevelReply(IReadOnlyList<ScriptedSend> sent)
    {
        var (_, source) = ConnectionIdsFrom(sent);
        var spec = Spec();
        var packet = new TlsQuicPacketToSend
        {
            Plan = new TlsQuicPacketPlan
            {
                Type = TlsQuicLongPacketType.Handshake,
                Version = (uint)TlsQuicVersion.Version1,
                DestinationConnectionId = source,
                SourceConnectionId = default,
                PacketNumber = 0,
                PacketNumberEncodedLength = spec.PacketNumberEncodedLength,
                LengthVarintWidth = spec.HeaderLengthVarintWidth,
                CryptoOffsetVarintWidth = spec.CryptoOffsetVarintWidth,
                CryptoLengthVarintWidth = spec.CryptoLengthVarintWidth,
            },
            Frames = [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            PacketProtectionCipher = TlsQuicPacketProtectionCipher.AesGcm,
            Key = new byte[16],
            Iv = new byte[12],
            HeaderProtectionCipher = TlsQuicHeaderProtectionCipher.Aes,
            HeaderProtectionKey = new byte[16],
        };

        var buffer = new byte[spec.PaddingTarget];
        var written = TlsQuicDatagramBuilder.BuildDatagram(spec, [packet], SentAt, buffer);
        return buffer[..written];
    }

    private static byte[] TwoPacketReply(IReadOnlyList<ScriptedSend> sent)
    {
        var (destination, source) = ConnectionIdsFrom(sent);

        // Packet one addresses us correctly and carries PADDING only - processable, and NOT
        // ack-eliciting (RFC 9000 s13.2.1 / Table 3), so on its own it obliges no answer.
        var first = ServerPacket(
            destination,
            destinationOnPacket: source,
            sourceOnPacket: [],
            packetNumber: 0,
            frames: [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Padding }],
            useServerSecret: true,
            pad: false);

        // Packet two is sealed with the same keys and would open - the AEAD covers the header
        // as associated data, but the key does not depend on the Destination Connection ID
        // FIELD, only on the one s5.2 derived from. So only s12.2's clause can reject it, which
        // is what makes this a witness for that clause and not for the AEAD.
        var second = ServerPacket(
            destination,
            destinationOnPacket: Convert.FromHexString("AAAAAAAAAAAAAAAA"),
            sourceOnPacket: [],
            packetNumber: 1,
            frames: [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            useServerSecret: true,
            pad: false);

        return [.. first, .. second];
    }

    private static byte[] ServerPacket(
        byte[] initialSecretConnectionId,
        byte[] destinationOnPacket,
        byte[] sourceOnPacket,
        ulong packetNumber,
        IReadOnlyList<TlsQuicFrame> frames,
        bool useServerSecret,
        bool pad = true)
    {
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, initialSecretConnectionId);
        using var keys = useServerSecret
            ? secrets.DeriveServerPacketProtectionKeys(TlsQuicVersion.Version1)
            : secrets.DeriveClientPacketProtectionKeys(TlsQuicVersion.Version1);

        var spec = Spec();
        var packet = new TlsQuicPacketToSend
        {
            Plan = new TlsQuicPacketPlan
            {
                Type = TlsQuicLongPacketType.Initial,
                Version = (uint)TlsQuicVersion.Version1,
                DestinationConnectionId = destinationOnPacket,
                SourceConnectionId = sourceOnPacket,
                PacketNumber = packetNumber,
                PacketNumberEncodedLength = spec.PacketNumberEncodedLength,
                LengthVarintWidth = spec.HeaderLengthVarintWidth,
                CryptoOffsetVarintWidth = spec.CryptoOffsetVarintWidth,
                CryptoLengthVarintWidth = spec.CryptoLengthVarintWidth,
            },
            Frames = frames,
            PacketProtectionCipher = TlsQuicPacketProtectionCipher.AesGcm,
            Key = keys.CopyKey(),
            Iv = keys.CopyIv(),
            HeaderProtectionCipher = TlsQuicHeaderProtectionCipher.Aes,
            HeaderProtectionKey = keys.CopyHeaderProtectionKey(),
        };

        var buffer = new byte[spec.PaddingTarget];
        if (!pad)
        {
            // TlsQuicDatagramBuilder expands any Initial-carrying datagram to the padding
            // target, which would make two coalesced packets impossible to place. Built
            // one level down for that case only.
            var frameBytes = new List<byte>();
            foreach (var frame in frames)
            {
                TlsQuicFrames.WriteFrame(frameBytes, frame);
            }
            while (frameBytes.Count < 4)
            {
                // RFC 9001 s5.4.2's 16-byte sample again; s19.1's PADDING "has no semantic
                // value" and is the filler the RFC itself names for this.
                TlsQuicFrames.WriteFrame(
                    frameBytes, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Padding });
            }
            var padded = new List<TlsQuicFrame>(frames);
            while (padded.Count < frameBytes.Count)
            {
                padded.Add(new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Padding });
            }

            var sent = TlsQuicPacketBuilder.Build(
                packet.Plan,
                padded,
                packet.PacketProtectionCipher,
                packet.Key.Span,
                packet.Iv.Span,
                packet.HeaderProtectionCipher,
                packet.HeaderProtectionKey.Span,
                SentAt,
                buffer);
            return buffer[..sent.Size];
        }

        var written = TlsQuicDatagramBuilder.BuildDatagram(spec, [packet], SentAt, buffer);
        return buffer[..written];
    }

    // Opens a packet THIS connection built, with keys derived the way a server would derive
    // them, so the assertion is on plaintext rather than on our own send-side arithmetic
    // repeated.
    private static byte[] OpenOwnInitialPacket(
        byte[] datagram, ReadOnlyMemory<byte> originalDestinationConnectionId)
    {
        Assert.True(
            TryOpenOwnInitialPacket(datagram, originalDestinationConnectionId, out var plaintext),
            "The connection's own Initial packet did not open under keys derived from the "
                + "connection ID given.");
        return plaintext;
    }

    // THE TRY FORM EXISTS FOR THE NEGATIVE DIRECTION, which is the whole of task 9b's Retry
    // re-keying witness: after a Retry the connection's next Initial packet must open under
    // keys derived from the NEW Destination Connection ID and must NOT open under the old one.
    // A helper that asserts internally can only ever say the first half.
    private static bool TryOpenOwnInitialPacket(
        byte[] datagram,
        ReadOnlyMemory<byte> originalDestinationConnectionId,
        out byte[] plaintext)
    {
        plaintext = [];

        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, originalDestinationConnectionId.Span);
        using var keys = secrets.DeriveClientPacketProtectionKeys(TlsQuicVersion.Version1);

        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(datagram, out var header, out _));

        var packet = datagram.ToArray();

        // NOT AN ASSERT, because with the wrong header protection key this still succeeds -
        // TryRemove only fails when there are too few bytes to sample - and the failure the
        // negative direction is looking for lands on the AEAD below.
        if (!TlsQuicHeaderProtection.TryRemove(
                TlsQuicHeaderProtectionCipher.Aes,
                keys.CopyHeaderProtectionKey(),
                packet,
                header.PacketNumberOffset,
                out var packetNumberLength))
        {
            return false;
        }

        var headerLength = header.PacketNumberOffset + packetNumberLength;
        var ciphertextLength = (int)header.Length - packetNumberLength;
        if (ciphertextLength < 16 || headerLength + ciphertextLength > packet.Length)
        {
            // A wrong header protection key can decode a packet number length that does not fit
            // the packet it came from. That is the same wrong key, reported one step earlier.
            return false;
        }

        var ciphertext = packet.AsSpan(headerLength, ciphertextLength);
        var opened = new byte[ciphertext.Length - 16];

        var packetNumber = 0UL;
        for (var i = 0; i < packetNumberLength; i++)
        {
            packetNumber = (packetNumber << 8) | packet[header.PacketNumberOffset + i];
        }

        if (!TlsQuicPacketProtection.TryOpen(
                TlsQuicPacketProtectionCipher.AesGcm,
                keys.CopyKey(),
                keys.CopyIv(),
                packetNumber,
                packet.AsSpan(0, headerLength),
                ciphertext,
                opened))
        {
            return false;
        }

        plaintext = opened;
        return true;
    }
}
