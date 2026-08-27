using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task A3-3: RFC 9002 A.1's sent_packets and A.4's bytes_in_flight, on TlsQuicConnection.
//
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's AND 14c's, for the reason those files give: Spec,
// Connection, TlsClient and Server are reused rather than copied.
//
// ============================================================================
// WHAT THESE ASSERTIONS PIN, AND WHAT THEY CANNOT. READ BEFORE TRUSTING A GREEN RUN.
// ============================================================================
//
// The file has two halves and NEITHER IS SUFFICIENT ALONE, which is why both are here.
//
//   THE DIRECT HALF drives TlsQuicConnection.OnPacketSent and OnAckReceived - RFC 9002 A.1's
//   and A.7's own entry points - with packets and ACK frames built here. It can reach states
//   no handshake produces: a PADDING-only packet, an ACK naming a range spanning the whole
//   62-bit space, three spaces holding the same packet number at once, and the retention cap.
//   WHAT IT CANNOT SEE is whether the send path calls OnPacketSent at all. Every one of these
//   tests passes against a connection that never wires the builder's list up.
//
//   THE LOOPBACK HALF drives a real handshake and reads the same two properties. It is what
//   fails if the ICollection is not passed at a call site, and it is where the flags come
//   from TlsQuicPacketBuilder rather than from a literal in this file. WHAT IT CANNOT SEE is
//   any of the direct half's states: a handshake sends no PADDING-only packet, never fills
//   1024 slots, and never puts two spaces in conflict for long enough to observe.
//
//   THE FLAGS THEMSELVES ARE NOT PINNED HERE. Whether a PADDING-only packet is in flight and
//   whether an ACK-only one is not are TlsQuicPacketBuilder's answers, witnessed by
//   TlsQuicPacketBuilderTests.PaddingOnlyPacketsAreNotAckElicitingButAreStillInFlight and
//   .AckOnlyPacketsAreNeitherAckElicitingNorInFlight against RFC 9000 s12.4 Table 3. What is
//   pinned here is that this connection HONOURS them and does not re-derive either.
public sealed partial class TlsQuicConnectionTests
{
    // ========================================================================
    // THE DIRECT HALF
    // ========================================================================

    // RFC 9002 A.4, verbatim from rfc9002-appendix-a-and-b-pseudocode-and-constants.txt:
    // "Packets only containing ACK frames do not count toward bytes_in_flight to ensure
    // congestion control does not impede congestion feedback."
    //
    // THE HARDEST CLAUSE IN THIS TASK TO SEE FAIL, because an implementation that counts them
    // is wrong only in a number nothing reads yet. THE SECOND PACKET IS WHY THIS IS NOT
    // VACUOUS: without it, a connection whose bytes_in_flight never moved at all would pass.
    [Fact]
    public async Task AnAckOnlyPacketIsRetainedButDoesNotCountTowardBytesInFlight()
    {
        await using var connection = Idle();

        // A.1's OnPacketSent stores EVERY packet - "sent_packets[pn_space][packet_number] =
        // ..." with no in_flight guard around it - and gates only the accounting below. So
        // the ACK-only packet is expected in the list and absent from the count, which is a
        // pair of assertions and not one.
        connection.OnPacketSent(Packet(
            TlsQuicEncryptionLevel.Application, 0, size: 40, ackEliciting: false, inFlight: false));

        Assert.Single(connection.SentPackets(TlsQuicEncryptionLevel.Application));
        Assert.Equal(0, connection.BytesInFlight);

        connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.Application, 1, size: 1200));

        Assert.Equal(2, connection.SentPackets(TlsQuicEncryptionLevel.Application).Count);

        // 1200 AND NOT 1240. A mutant that counts the ACK-only packet reports 1240 here and
        // passes every other assertion in this file.
        Assert.Equal(1200, connection.BytesInFlight);
    }

    // RFC 9000 s13.2.7: "Packets containing PADDING frames are considered to be in flight for
    // congestion control purposes" - and PADDING elicits nothing. The two booleans answer
    // different questions, and this is the shape where they disagree.
    //
    // A WITNESS PER FLAG, run as four cases rather than one: a mutant that gated retention on
    // IsAckEliciting instead of IsInFlight is killed by the third row, and one that counted
    // every retained packet regardless is killed by the first.
    [Theory]
    [InlineData(false, false, 0)]   // ACK-only: retained, not counted.
    [InlineData(true, true, 1200)]  // CRYPTO or STREAM: retained and counted.
    [InlineData(false, true, 1200)] // PADDING-only: s13.2.7's case - in flight, elicits none.
    [InlineData(true, false, 0)]    // Not a shape Table 3 produces; the two flags are still
                                    // read independently, which is the point of the row.
    public async Task RetentionReadsTheTwoFlagsIndependently(
        bool ackEliciting, bool inFlight, long expectedBytesInFlight)
    {
        await using var connection = Idle();

        connection.OnPacketSent(Packet(
            TlsQuicEncryptionLevel.Application,
            0,
            size: 1200,
            ackEliciting: ackEliciting,
            inFlight: inFlight));

        // RETAINED IN EVERY ROW. A.1 tracks the packet; A.4 decides whether its bytes count.
        var retained = Assert.Single(connection.SentPackets(TlsQuicEncryptionLevel.Application));
        Assert.Equal(ackEliciting, retained.IsAckEliciting);
        Assert.Equal(inFlight, retained.IsInFlight);
        Assert.Equal(expectedBytesInFlight, connection.BytesInFlight);
    }

    // RFC 9002 A.1: "Sent packets are tracked for each packet number space, and ACK processing
    // only applies to a single space." RFC 9000 s13.1 is the same rule from the other side.
    //
    // EVERY ORDERED PAIR OF THE THREE SPACES, and every packet carries THE SAME NUMBER - which
    // is the whole test. A retention keyed on the packet number alone, or one that merged the
    // spaces into a single list, passes an "it was removed" assertion and fails this one.
    [Theory]
    [InlineData(TlsQuicEncryptionLevel.Initial, TlsQuicEncryptionLevel.Handshake)]
    [InlineData(TlsQuicEncryptionLevel.Initial, TlsQuicEncryptionLevel.Application)]
    [InlineData(TlsQuicEncryptionLevel.Handshake, TlsQuicEncryptionLevel.Initial)]
    [InlineData(TlsQuicEncryptionLevel.Handshake, TlsQuicEncryptionLevel.Application)]
    [InlineData(TlsQuicEncryptionLevel.Application, TlsQuicEncryptionLevel.Initial)]
    [InlineData(TlsQuicEncryptionLevel.Application, TlsQuicEncryptionLevel.Handshake)]
    public async Task AnAckInOneSpaceRemovesNothingFromAnother(
        TlsQuicEncryptionLevel acknowledged, TlsQuicEncryptionLevel untouched)
    {
        await using var connection = Idle();

        connection.OnPacketSent(Packet(acknowledged, 7, size: 100));
        connection.OnPacketSent(Packet(untouched, 7, size: 900));
        Assert.Equal(1000, connection.BytesInFlight);

        connection.OnAckReceived(acknowledged, AckFrame(new TlsQuicAckRange(7, 7)));

        Assert.Empty(connection.SentPackets(acknowledged));

        var survivor = Assert.Single(connection.SentPackets(untouched));
        Assert.Equal(7UL, survivor.PacketNumber);
        Assert.Equal(untouched, survivor.Level);

        // 900 AND NOT 0. The bytes leave with the packet they belong to and no others.
        Assert.Equal(900, connection.BytesInFlight);
    }

    // RFC 9000 s12.3: "Packets that are protected with 0-RTT keys and packets that are
    // protected with 1-RTT keys are part of the same packet number space." FOUR LEVELS, THREE
    // SPACES - the one collapse an ordinal cast would get right by accident and a
    // level-indexed array would get wrong.
    [Fact]
    public async Task AZeroRttPacketAndAOneRttPacketShareOneSpace()
    {
        await using var connection = Idle();

        connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.EarlyData, 3, size: 500));

        // READ BACK AT THE OTHER LEVEL. Same space, therefore same list.
        var retained = Assert.Single(connection.SentPackets(TlsQuicEncryptionLevel.Application));
        Assert.Equal(TlsQuicEncryptionLevel.EarlyData, retained.Level);

        // AND AN ACK ARRIVING AT 1-RTT RETIRES IT, which is what s12.3 means in practice: a
        // server acknowledges 0-RTT packets in the 1-RTT space because there is only one.
        connection.OnAckReceived(
            TlsQuicEncryptionLevel.Application, AckFrame(new TlsQuicAckRange(3, 3)));

        Assert.Empty(connection.SentPackets(TlsQuicEncryptionLevel.EarlyData));
        Assert.Equal(0, connection.BytesInFlight);
    }

    // THE BOUND. RFC 9002 A.11 empties Initial and Handshake on key discard, and asserts it is
    // never called for the application space - so nothing but this cap stops a peer that takes
    // datagrams and acknowledges none from growing the application list forever.
    //
    // THE EXPECTATION IS DERIVED FROM THE CAP, never written beside it: a test asserting 1024
    // would keep passing and stop meaning anything the day the constant moved.
    [Fact]
    public async Task RetentionIsCappedPerSpaceAndTheOldestPacketIsTheOneDropped()
    {
        await using var connection = Idle();

        const int overshoot = 5;
        var total = TlsQuicConnection.MaxRetainedPacketsPerSpace + overshoot;
        for (var i = 0; i < total; i++)
        {
            connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.Application, (ulong)i, size: 10));
        }

        var retained = connection.SentPackets(TlsQuicEncryptionLevel.Application);
        Assert.Equal(TlsQuicConnection.MaxRetainedPacketsPerSpace, retained.Count);

        // THE OLDEST WENT, NOT THE NEWEST. Dropping the newest would forget the packet most
        // likely still to be acknowledged and keep the ones already beyond hope.
        Assert.Equal((ulong)overshoot, retained[0].PacketNumber);
        Assert.Equal((ulong)(total - 1), retained[^1].PacketNumber);

        // AND THE DROPPED PACKETS' BYTES WENT WITH THEM. A cap that trimmed the list without
        // calling Forget would leave 50 bytes of phantom congestion here forever, which is
        // exactly the leak the cap exists to prevent - in a different form.
        Assert.Equal(10L * TlsQuicConnection.MaxRetainedPacketsPerSpace, connection.BytesInFlight);
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // RFC 9000 s19.3.1's ACK Range fields are 62-bit varints, so a peer may name a range
    // covering the entire packet number space in a handful of bytes. AN IMPLEMENTATION THAT
    // WALKED FROM Smallest TO Largest WOULD HANG HERE - which is a remote stall for the price
    // of one datagram, and the reason removal iterates the retained side instead.
    //
    // THE WAIT IS WHAT MAKES THE HANG A FAILURE rather than a hung run: a synchronous loop of
    // 2^62 iterations is not something a CancellationToken can interrupt.
    [Fact]
    public async Task AnAckSpanningTheWholePacketNumberSpaceIsAnsweredWithoutWalkingIt()
    {
        await using var connection = Idle();

        connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.Application, 0, size: 100));
        connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.Application, 4611686018427387903, size: 100));

        // s19.3's Largest Acknowledged is a varint, whose maximum is 2^62 - 1.
        var everything = AckFrame(new TlsQuicAckRange(4611686018427387903, 0));
        var work = Task.Run(() =>
            connection.OnAckReceived(TlsQuicEncryptionLevel.Application, everything));

        await work.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Empty(connection.SentPackets(TlsQuicEncryptionLevel.Application));
        Assert.Equal(0, connection.BytesInFlight);
    }

    // NOTHING ON THIS PATH THROWS FOR ANY INPUT, because every input is the peer's choice. The
    // four rows are the four ways TlsQuicAckFrames can refuse a frame plus the one way a
    // well-formed frame can name nothing of ours; all five leave retention exactly as it was.
    [Theory]
    [InlineData(RefusedAck.NotAnAckFrame)]
    [InlineData(RefusedAck.RangeCountWithoutRangeBytes)]
    [InlineData(RefusedAck.FirstRangeBelowZero)]
    [InlineData(RefusedAck.TruncatedRangeChain)]
    [InlineData(RefusedAck.WellFormedButNamesNothingWeSent)]
    public async Task AnAckThisConnectionCannotUseChangesNothingAndDoesNotThrow(RefusedAck shape)
    {
        await using var connection = Idle();

        connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.Handshake, 2, size: 700));
        connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.Handshake, 3, size: 800));

        connection.OnAckReceived(TlsQuicEncryptionLevel.Handshake, Refused(shape));

        Assert.Equal(2, connection.SentPackets(TlsQuicEncryptionLevel.Handshake).Count);
        Assert.Equal(1500, connection.BytesInFlight);
    }

    // A PARTIAL ACK LEAVES THE REST. The removal walks every retained packet against every
    // range, so a mutant that stopped at the first match, or one that cleared the space on any
    // ACK at all, is killed here and by nothing else in this file.
    [Fact]
    public async Task AnAckRemovesTheNamedPacketsAndOnlyThose()
    {
        await using var connection = Idle();

        for (var i = 0UL; i < 6; i++)
        {
            connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.Initial, i, size: 100));
        }

        // s19.3.1's ranges are descending and disjoint: 4-5 and 0-1, skipping 2 and 3.
        connection.OnAckReceived(
            TlsQuicEncryptionLevel.Initial,
            AckFrame(new TlsQuicAckRange(5, 4), new TlsQuicAckRange(1, 0)));

        Assert.Equal(
            new ulong[] { 2, 3 },
            connection.SentPackets(TlsQuicEncryptionLevel.Initial).Select(p => p.PacketNumber));
        Assert.Equal(200, connection.BytesInFlight);
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // A SECOND ACK NAMING THE SAME PACKETS IS A NO-OP, not a second subtraction. A conforming
    // peer retransmits its ACK frames (s13.2.1), so this is the ordinary case and not an edge
    // one - and a bytes_in_flight that went negative here would be invisible to every other
    // assertion in this file, because nothing else subtracts twice.
    [Fact]
    public async Task ADuplicateAckDoesNotSubtractTheSameBytesTwice()
    {
        await using var connection = Idle();

        connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.Application, 9, size: 1200));
        var ack = AckFrame(new TlsQuicAckRange(9, 9));

        connection.OnAckReceived(TlsQuicEncryptionLevel.Application, ack);
        connection.OnAckReceived(TlsQuicEncryptionLevel.Application, ack);

        Assert.Equal(0, connection.BytesInFlight);
        Assert.Empty(connection.SentPackets(TlsQuicEncryptionLevel.Application));
    }

    // THE SCRATCH LIST IS CLEARED BEFORE EACH USE, AND THIS IS THE ONLY TEST THAT SEES IT.
    // One reused List is what keeps the receive path from allocating per ACK frame; a missing
    // Clear turns it into an accumulator, so the SECOND ACK would retire everything the FIRST
    // one named as well - in a space that ACK never mentioned.
    //
    // TWO SPACES, DELIBERATELY. A leak within one space is invisible: the numbers an earlier
    // ACK named are already gone, so replaying them removes nothing. Number 7 has to survive
    // at Handshake while an Initial ACK names it for the leak to have anything to take.
    [Fact]
    public async Task RangesFromAnEarlierAckDoNotLeakIntoTheNext()
    {
        await using var connection = Idle();

        connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.Initial, 7, size: 100));
        connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.Handshake, 7, size: 200));
        connection.OnPacketSent(Packet(TlsQuicEncryptionLevel.Handshake, 9, size: 300));

        connection.OnAckReceived(
            TlsQuicEncryptionLevel.Initial, AckFrame(new TlsQuicAckRange(7, 7)));
        connection.OnAckReceived(
            TlsQuicEncryptionLevel.Handshake, AckFrame(new TlsQuicAckRange(9, 9)));

        // 7 SURVIVES AT HANDSHAKE. The Handshake ACK named 9 and nothing else; only a leaked
        // range from the Initial ACK could have taken it.
        var survivor = Assert.Single(connection.SentPackets(TlsQuicEncryptionLevel.Handshake));
        Assert.Equal(7UL, survivor.PacketNumber);
        Assert.Equal(200, connection.BytesInFlight);
    }

    // The CONNECTION_CLOSE send is the third BuildDatagram call site and the only one that is
    // not on the handshake path, so nothing else in this file reaches it.
    //
    // RETAINED AND IN FLIGHT, BUT NOT FOR THE REASON THIS COMMENT USED TO GIVE. It used to read
    // that RFC 9000 s12.4 Table 3 prints C - "do not count toward bytes in flight" - against ACK
    // alone and CONNECTION_CLOSE carries N without it, so the close packet must be in flight.
    // That inverts the marking: C says which frames CANNOT put a packet in flight, never that
    // every unmarked frame can. RFC 9002 s2 is the positive definition - "Packets are considered
    // in flight when they are ack-eliciting or contain a PADDING frame" - and CONNECTION_CLOSE
    // is neither, so it contributes nothing here.
    //
    // The flag is still true, because THE PADDING makes it true: only Initial keys exist at this
    // point, and RFC 9000 s14.1 requires a datagram carrying a client Initial to be padded to at
    // least 1200 bytes, so the close goes out beside PADDING frames every time. The assertion
    // survived the IsInFlight correction unchanged and its rationale did not; keeping the old
    // wording would have left a true assertion resting on a false rule, which is the shape that
    // silently stops witnessing anything once the padding requirement moves.
    // TlsQuicPacketBuilderTests.ConnectionCloseOnlyPacketsAreNeitherAckElicitingNorInFlight is
    // where the close-alone row is pinned, on a packet with no padding to confuse it.
    [Fact]
    public async Task TheConnectionClosePacketIsRetainedLikeAnyOther()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);

        await connection.StartAsync(cancellation.Token);
        var before = connection.SentPackets(TlsQuicEncryptionLevel.Initial).Count;
        var bytesBefore = connection.BytesInFlight;

        // Only Initial keys exist at this point, so s10.2's immediate close goes out at
        // Initial - the same space the opening flight is retained in.
        await connection.CloseAsync(TlsQuicTransportError.NoError, "done", cancellation.Token);

        var retained = connection.SentPackets(TlsQuicEncryptionLevel.Initial);
        Assert.Equal(before + 1, retained.Count);

        var close = retained[^1];
        Assert.False(close.IsAckEliciting);
        Assert.True(close.IsInFlight);
        Assert.Equal(bytesBefore + close.Size, connection.BytesInFlight);
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // The space mapping's default arm. UNREACHABLE FROM THE SEND PATH - TlsQuicSentPacket.Level
    // is set by TlsQuicPacketBuilder.LevelOf, which produces the four levels and throws for
    // anything else - so this is the reachability witness for a branch that would otherwise be
    // dead code with no evidence either way.
    [Fact]
    public async Task AskingForASpaceOutsideTheFourEncryptionLevelsIsRefusedByName()
    {
        await using var connection = Idle();

        var refused = Assert.Throws<ArgumentOutOfRangeException>(
            () => connection.SentPackets((TlsQuicEncryptionLevel)99));

        Assert.Contains("three packet number spaces", refused.Message, StringComparison.Ordinal);
    }

    // ========================================================================
    // THE LOOPBACK HALF - where the send path itself is on trial
    // ========================================================================

    // THE CALL SITE THE A3 PLAN'S TASK TEXT DOES NOT NAME. BuildInitialFlight takes the same
    // ICollection as BuildDatagram and produces the FIRST packets any connection sends; a
    // wiring that covered only the two BuildDatagram sites leaves this empty, and every
    // Initial-space assertion below would then pass against an empty list.
    [Fact]
    public async Task TheOpeningFlightIsRetainedInTheInitialSpaceAndCountedInFlight()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);

        Assert.Empty(connection.SentPackets(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(0, connection.BytesInFlight);

        await connection.StartAsync(cancellation.Token);

        // ONE RETAINED PACKET PER DATAGRAM THAT WENT OUT, counted off the transport rather
        // than predicted here: RFC 9000 s12.3 forbids reusing a packet number in a space, so
        // BuildInitialFlight advances the number once per datagram.
        var retained = connection.SentPackets(TlsQuicEncryptionLevel.Initial);
        Assert.Equal(clientTransport.Sent.Count, retained.Count);
        Assert.NotEmpty(retained);

        // A CRYPTO-CARRYING PACKET IS BOTH, and the flags came off TlsQuicPacketBuilder rather
        // than off a literal in this file - this is the only half of the file where they do.
        Assert.All(retained, p =>
        {
            Assert.True(p.IsAckEliciting);
            Assert.True(p.IsInFlight);
            Assert.Equal(TlsQuicEncryptionLevel.Initial, p.Level);
        });

        // AND THE SIZES ARE THE DATAGRAMS' OWN. RFC 9002 A.1.1's sent_bytes is "the number of
        // bytes sent in the packet, not including UDP or IP overhead, but including QUIC
        // framing overhead", and each Initial datagram here holds exactly one packet, so the
        // two numbers are the same number read off two sides.
        Assert.Equal(
            clientTransport.Sent.Sum(d => (long)d.Length),
            connection.BytesInFlight);
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // RFC 9002 A.11 OnPacketNumberSpaceDiscarded: "RemoveFromBytesInFlight(sent_packets
    // [pn_space])" then "sent_packets[pn_space].clear()". A retained Initial packet that
    // outlives its keys can be neither retransmitted nor acknowledged, so it would sit in
    // bytes_in_flight forever on a connection that never completes.
    //
    // THE NON-EMPTY ASSERTION BEFORE EACH DISCARD IS LOAD-BEARING: without it a connection
    // that retained nothing at all would pass every "empty afterwards" line below.
    [Fact]
    public async Task DiscardingALevelsKeysEmptiesThatSpaceAndReturnsItsBytes()
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
        Assert.NotEmpty(connection.SentPackets(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(TlsQuicKeyLevelState.Installed,
            connection.WriteStateOf(TlsQuicEncryptionLevel.Initial));

        // The server's flight; our answer to it carries our first Handshake packet, which RFC
        // 9001 s4.9.1 makes the moment Initial keys are discarded.
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(TlsQuicKeyLevelState.Discarded,
            connection.WriteStateOf(TlsQuicEncryptionLevel.Initial));
        Assert.Empty(connection.SentPackets(TlsQuicEncryptionLevel.Initial));

        // AND THE HANDSHAKE SPACE IS WHERE THOSE BYTES WENT, not nowhere: the count is still
        // positive, so the discard subtracted the Initial packets and not everything.
        Assert.NotEmpty(connection.SentPackets(TlsQuicEncryptionLevel.Handshake));
        Assert.True(connection.BytesInFlight > 0);
        AssertBytesInFlightAgreesWithRetention(connection);

        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // RFC 9001 s4.9.2: confirmation releases the Handshake keys, and A.11 takes that
        // space's packets with them.
        Assert.True(connection.IsHandshakeConfirmed);
        Assert.Equal(TlsQuicKeyLevelState.Discarded,
            connection.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
        Assert.Empty(connection.SentPackets(TlsQuicEncryptionLevel.Handshake));
    }

    // THE INVARIANT THE A3 PLAN NAMES, AND THE ONE A MUTANT THAT NEVER REMOVES ANYTHING FAILS.
    // "The list is non-empty after sending" would pass such a mutant; EXACTLY ZERO after a
    // whole handshake would not, and neither would it tolerate an off-by-one in any single
    // packet's size, because every byte added has to be subtracted by the space that owns it.
    [Fact]
    public async Task BytesInFlightIsExactlyZeroAfterACompleteHandshake()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        var pumping = Task.Run(
            async () =>
            {
                while (!connection.IsHandshakeConfirmed)
                {
                    if (!await serverPeer.PumpOnceAsync(SentAt, cancellation.Token)
                        && server.IsHandshakeComplete)
                    {
                        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
                    }
                }
            },
            cancellation.Token);

        await connection.ConnectAsync(cancellation.Token);
        await pumping;

        // It ran, and it retained. Without this the zero below is the zero of a connection
        // that never counted anything.
        Assert.True(connection.IsHandshakeConfirmed);
        Assert.NotEmpty(clientTransport.Sent);

        // EXACTLY ZERO. Everything sent at Initial and Handshake left with its keys (A.11),
        // and the only application-space packet a handshake produces is the ACK for
        // HANDSHAKE_DONE, which A.4 excludes.
        Assert.Equal(0, connection.BytesInFlight);
        AssertBytesInFlightAgreesWithRetention(connection);

        // AND THE ACK-ONLY PACKET IS STILL THERE - retained, uncounted. This is the exclusion
        // witnessed end to end, with the flags coming off TlsQuicPacketBuilder: a connection
        // that counted ACK-only packets would report a positive total on the line above while
        // this list holds exactly the same packets.
        var application = connection.SentPackets(TlsQuicEncryptionLevel.Application);
        Assert.NotEmpty(application);
        Assert.All(application, p =>
        {
            Assert.False(p.IsInFlight);
            Assert.False(p.IsAckEliciting);
        });
    }

    // REMOVAL ON ACKNOWLEDGEMENT, END TO END AND WITH NO KEY DISCARD INVOLVED. The application
    // space is the one A.11 never clears, so the return to zero here can only have come from
    // an ACK the peer actually sent.
    //
    // PATH_RESPONSE IS THE VEHICLE because RFC 9000 s12.4 Table 3 makes it ack-eliciting and
    // 1-RTT-only, which is the one ack-eliciting application packet this connection can be
    // made to send without a stream.
    [Fact]
    public async Task AnAcknowledgedApplicationPacketLeavesTheListAndItsBytesLeaveTheCount()
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

        // HANDSHAKE_DONE with a PATH_CHALLENGE beside it: confirmation empties the Handshake
        // space, and the answer we send carries a PATH_RESPONSE, which is ack-eliciting.
        await serverPeer.SendHandshakeDoneAsync(
            SentAt, cancellation.Token, pathChallengeData: Convert.FromHexString("0011223344556677"));
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        Assert.True(connection.IsHandshakeConfirmed);

        var inFlight = connection.SentPackets(TlsQuicEncryptionLevel.Application)
            .Where(p => p.IsInFlight)
            .ToArray();
        var carrier = Assert.Single(inFlight);
        Assert.True(carrier.IsAckEliciting);
        Assert.Equal(carrier.Size, connection.BytesInFlight);

        // The peer opens it and acknowledges it by number - s19.3's Largest Acknowledged is
        // the number it read off our header, not one this test supplied.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(carrier.PacketNumber, serverPeer.LargestApplicationPacketNumberReceived);

        await serverPeer.SendAckAsync(SentAt, cancellation.Token);
        await connection.PumpOnceAsync(cancellation.Token);

        // GONE, AND ITS BYTES WITH IT. A mutant that retains and never removes fails here and
        // at BytesInFlightIsExactlyZeroAfterACompleteHandshake, and at nothing else.
        Assert.DoesNotContain(
            connection.SentPackets(TlsQuicEncryptionLevel.Application),
            p => p.PacketNumber == carrier.PacketNumber);
        Assert.Equal(0, connection.BytesInFlight);
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // ========================================================================
    // HELPERS
    // ========================================================================

    // RFC 9002 A.4's definition, recomputed from the retained set rather than trusted: "the
    // sum of the size in bytes of all sent packets that contain at least one ack-eliciting or
    // PADDING frame and have not been acknowledged or declared lost".
    //
    // WHY THE COUNTER IS NOT SIMPLY THIS SUM IN THE FIRST PLACE: an identity that is computed
    // on demand can never disagree with itself, so it can never catch a subtraction that was
    // skipped. Held separately and checked here, a skipped Forget is a visible divergence.
    private static void AssertBytesInFlightAgreesWithRetention(TlsQuicConnection connection)
    {
        var expected = 0L;
        foreach (var level in new[]
                 {
                     TlsQuicEncryptionLevel.Initial,
                     TlsQuicEncryptionLevel.Handshake,
                     TlsQuicEncryptionLevel.Application,
                 })
        {
            foreach (var packet in connection.SentPackets(level))
            {
                if (packet.IsInFlight)
                {
                    expected += packet.Size;
                }
            }
        }

        Assert.Equal(expected, connection.BytesInFlight);

        // NEGATIVE IS THE FAILURE THIS SIGNS OFF ON, and it is why BytesInFlight is signed:
        // an unsigned counter that over-subtracted would wrap to a plausible enormous number
        // and the equality above would be the only thing that ever noticed.
        Assert.True(connection.BytesInFlight >= 0);
    }

    // A connection that exists and has done nothing. StartAsync is never called, so no TLS
    // client is built and no packet is sent - the retention state is the field initialisers,
    // which is what the direct half wants to drive from.
    private static TlsQuicConnection Idle()
    {
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        return new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                clientTransport, serverTransport.LocalEndPoint, Spec(), TimeProvider.System),
            _ => throw new InvalidOperationException(
                "An idle connection builds no TLS client; this test must not call StartAsync."));
    }

    private static TlsQuicSentPacket Packet(
        TlsQuicEncryptionLevel level,
        ulong number,
        int size,
        bool ackEliciting = true,
        bool inFlight = true) =>
        new(level, number, size, ackEliciting, inFlight, SentAt);

    // Built through A2's writer and read back through the frame reader, exactly as
    // LoopbackQuicPeer.SendAckAsync does: s19.3.1's Gap / ACK Range Length chain has one
    // encoder in this tree and a hand-rolled one here would be a second.
    private static TlsQuicFrame AckFrame(params TlsQuicAckRange[] ranges)
    {
        var encoded = new List<byte>();
        TlsQuicAckFrames.WriteAckFrame(encoded, (ulong)TlsQuicFrameType.Ack, ackDelay: 0, ranges);

        var bytes = encoded.ToArray();
        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(bytes, ref offset, out var ack, out _));
        return ack;
    }

    public enum RefusedAck
    {
        NotAnAckFrame,
        RangeCountWithoutRangeBytes,
        FirstRangeBelowZero,
        TruncatedRangeChain,
        WellFormedButNamesNothingWeSent,
    }

    private static TlsQuicFrame Refused(RefusedAck shape) => shape switch
    {
        // TryGetRanges' own type gate. A PING is what the frame dispatcher would never route
        // here, so this is the defensive arm rather than a reachable one.
        RefusedAck.NotAnAckFrame => new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping },

        // s19.3's ACK Range Count promises ranges that the AckRanges bytes do not carry.
        RefusedAck.RangeCountWithoutRangeBytes => new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Ack,
            LargestAcknowledged = 5,
            AckDelay = 0,
            AckRangeCount = 3,
            FirstAckRange = 0,
            AckRanges = Array.Empty<byte>(),
        },

        // s19.3.1: "If any computed packet number is negative, an endpoint MUST generate a
        // connection error of type FRAME_ENCODING_ERROR." Largest 0 less a First ACK Range of
        // 5 is that computation.
        RefusedAck.FirstRangeBelowZero => new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Ack,
            LargestAcknowledged = 0,
            AckDelay = 0,
            AckRangeCount = 0,
            FirstAckRange = 5,
        },

        // A chain that starts and stops mid-varint.
        RefusedAck.TruncatedRangeChain => new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Ack,
            LargestAcknowledged = 20,
            AckDelay = 0,
            AckRangeCount = 1,
            FirstAckRange = 0,
            AckRanges = new byte[] { 0xC0 },
        },

        // THE ONE THAT IS NOT MALFORMED AT ALL. A peer may acknowledge a number we never sent
        // - RFC 9000 s13.1 makes that a PROTOCOL_VIOLATION the endpoint MAY raise, and A3-4
        // owns that decision. What this row pins is that retention neither removes anything
        // nor throws while the decision is still open.
        RefusedAck.WellFormedButNamesNothingWeSent => AckFrame(new TlsQuicAckRange(9000, 9000)),

        _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, null),
    };
}
