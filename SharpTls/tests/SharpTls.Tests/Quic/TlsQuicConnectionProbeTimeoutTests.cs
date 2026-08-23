using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task A3-7 of the loss recovery phase: RFC 9002 s6.2's probe timeout - the period, the
// backoff, s6.2.2.1's before-address-validation rules and s6.2.4's probe contents - together
// with RFC 9000 s8.1's anti-deadlock probe, which is the ONE s8.1 sentence a client owes that
// A4 did not already ship.
//
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's, 14c's, A3-1's, A3-3's, A3-5's AND A3-6's, for the
// reason those files give: Spec, Connection, TlsClient, Server, IdleOn, FakeClock, PacketAt,
// AckFrame and AssertBytesInFlightAgreesWithRetention are reused rather than copied.
//
// ============================================================================
// WHAT A3-7 IS ACTUALLY FOR, AND WHY THREE CALL LINES ARE MOST OF IT.
// ============================================================================
//
// A3-6 built RFC 9002 s6.1's loss detection and could not wire it: A.10's two call sites and
// A.8's rung 1 all live in TlsQuicConnection.cs, which that task could not open, and it said so
// in its own header rather than working around it. A3-7 wrote those three lines. THE
// CONSEQUENCE IS VISIBLE IN A FILE THIS ONE DOES NOT OWN: every direct-half test in
// the loss detection tests file now reads a pass the PRODUCTION receive path ran, not
// one the test invoked, because A.7 runs A.10 itself; see that file's Acknowledge helper.
// TlsQuicConnectionTests.ADroppedDatagramsPacketIsDeclaredLostByARealAcknowledgement is the
// live witness - a datagram A3-1's decorator really dropped, an acknowledgement the peer really
// wrote, and a packet this connection really declared lost with nothing in the test calling
// detection at all.
//
// ============================================================================
// WHAT THIS FILE PINS THAT NO OTHER FILE CAN, AND WHAT IT DELIBERATELY CANNOT.
// ============================================================================
//
//   THE ARITHMETIC HALF drives OnPacketSent, ProcessAckFrame and OnAckReceived on a frozen
//   clock. It is the only half that can put smoothed_rtt and rttvar at chosen values - which
//   is what the PTO formula is stated in - and it is where s6.2.1's terms are separated from
//   each other. WHAT IT CANNOT SEE is whether a probe ever reaches a transport.
//
//   THE LIVE HALF runs a real handshake over A3-1's decorator on A3-1's clock and reads the
//   BYTES that left. It is what fails if the probe is built but never sent, sent at the wrong
//   level, or sent in a datagram RFC 9000 s8.1 would reject. WHAT IT CANNOT SEE is any
//   boundary: a handshake takes the round trips it takes.
//
// NO EXPECTED PERIOD BELOW IS TYPED. Every one is recomputed from the connection's own
// TlsQuicAckTracker - which is A3-4's live estimator, not a seed this file restates - plus the
// TlsQuicRecoverySpec the connection was built with. A test that compared against 999 ms would
// pass against a connection that ignored every knob it has.
//
// AND THE CALIBRATION CONTROL FOR THE FILE IS A PAIR OF NEAR-IDENTICAL SETUPS:
// AClientWhoseAddressTheServerHasValidatedSendsNoProbeWithNothingInFlight is
// APtoWithNoHandshakeKeysSendsAnInitialPacketOfAtLeastTwelveHundredBytes with ONE difference -
// a Handshake acknowledgement - and it asserts that NOTHING goes out. A client that probed
// whenever a timer could be armed passes every "a probe is sent" test in this file and fails
// that one, which is the failure s6.2.2.1's two halves are about: probing after validation
// spams a server that is not blocked, and not probing before it is the deadlock s8.1 exists to
// break.
public sealed partial class TlsQuicConnectionTests
{
    // ========================================================================
    // RFC 9000 s8.1's ANTI-DEADLOCK PROBE - THE CLIENT MUST A4 DID NOT SHIP.
    // ========================================================================
    //
    // rfc9000-section8-address-validation-and-amplification.txt lines 48-59: "Loss of an
    // Initial or Handshake packet from the server can cause a deadlock if the client does not
    // send additional Initial or Handshake packets. A deadlock could occur when the server
    // reaches its anti-amplification limit and the client has received acknowledgments for all
    // the data it has sent. In this case, when the client has no reason to send additional
    // packets, the server will be unable to send more data because it has not validated the
    // client's address. To prevent this deadlock, clients MUST send a packet on a Probe Timeout
    // (PTO); see Section 6.2 of [QUIC-RECOVERY]. Specifically, the client MUST send an Initial
    // packet in a UDP datagram that contains at least 1200 bytes if it does not have Handshake
    // keys, and otherwise send a Handshake packet."
    //
    // THE STATE THAT SENTENCE DESCRIBES IS BUILT HERE EXACTLY: the client's whole Initial
    // flight is acknowledged - "the client has received acknowledgments for all the data it has
    // sent" - the handshake is not confirmed and no Handshake packet has been acknowledged, so
    // s6.2.2.1's PeerCompletedAddressValidation is false. There is nothing left for this client
    // to say, and s8.1's whole point is that it must say something anyway.
    //
    // NO THREE-TIMES BYTE COUNTER IS ASSERTED ANYWHERE IN THIS FILE, and its absence is the
    // point rather than an omission. s8.1's limit binds SERVERS - "Prior to validating the
    // client address, servers MUST NOT send more than three times as many bytes as the number
    // of bytes they have received" - and the section closes "Clients are only constrained by
    // the congestion controller." A counter on this type would be unreachable by construction
    // while reading as conformance.
    [Fact]
    public async Task APtoWithNoHandshakeKeysSendsAnInitialPacketOfAtLeastTwelveHundredBytes()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        await using var connection = Connection(
            impaired, serverTransport, pki, clock: impaired.Clock);

        await connection.StartAsync(cancellation.Token);
        AcknowledgeEverythingRetainedIn(
            connection, TlsQuicEncryptionLevel.Initial, impaired.Clock.GetUtcNow());

        // s8.1's "the client has received acknowledgments for all the data it has sent", and
        // s6.2.2.1's "the client has not received an acknowledgment for any of its Handshake
        // packets and the handshake is not confirmed". Both stated as assertions, because the
        // whole test is about what a client does in exactly this state.
        Assert.Equal(0L, connection.BytesInFlight);
        Assert.Null(connection.LargestAcknowledged(TlsQuicEncryptionLevel.Handshake));
        Assert.False(connection.IsHandshakeConfirmed);

        // s6.2.2.1: "the client MUST set the PTO timer ... EVEN IF THERE ARE NO PACKETS IN
        // FLIGHT." A.8's rung 3 is what does that and it is A3-5's; this is the precondition
        // for the send, asserted so that a cancelled timer fails here rather than silently
        // making the rest of the test vacuous.
        var armed = Assert.IsType<DateTimeOffset>(connection.LossDetectionTimer);

        var offeredBefore = impaired.Offered.Count;
        impaired.Clock.Advance(armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // ONE DATAGRAM AND NOT knob 10's TWO. A.9's anti-deadlock arm names
        // SendOneAckElicitingPaddedInitialPacket, singular; s6.2.4's "up to two full-sized
        // datagrams" is the OTHER arm. Asserting the count as one rather than as non-zero is
        // what tells the two arms apart here.
        Assert.Equal(1, connection.ProbeDatagramsSent);
        Assert.Equal(1, impaired.Offered.Count - offeredBefore);
        Assert.Equal(TlsQuicEncryptionLevel.Initial, connection.LastProbeLevel);
        Assert.Equal(2, Spec().Recovery.ProbePacketsPerPto);

        // s8.1's "a UDP datagram that contains at least 1200 bytes", READ OFF THE WIRE and not
        // off the connection's own opinion of what it built. THE NUMBER COMPARED AGAINST IS THE
        // KNOB rather than a literal: TlsQuicConnectionSpec.PaddingTarget's own floor IS s8.1's
        // 1200 - it "rejects anything below MinimumInitialDatagramSize", which
        // TlsQuicConnectionSpecTests pins - so a datagram at or above the target satisfies the
        // sentence for every spec this library will build.
        var datagram = impaired.Offered[^1];
        Assert.Equal(connection.LastProbeDatagramBytes, datagram.Length);
        Assert.True(
            datagram.Length >= Spec().PaddingTarget,
            $"s8.1's anti-deadlock probe was {datagram.Length} bytes, below the "
                + $"{Spec().PaddingTarget} target s8.1's 1200-byte floor sets.");

        // AND IT IS AN INITIAL PACKET, which "at least 1200 bytes" alone does not say: s8.1
        // names the packet type as well as the size, and a padded Handshake packet would
        // satisfy the length assertion above while failing the sentence.
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(datagram, out var header, out _));
        Assert.Equal(TlsQuicLongPacketType.Initial, header.Type);
    }

    // THE CALIBRATION CONTROL, AND IT IS THE SETUP ABOVE WITH ONE ACKNOWLEDGEMENT ADDED.
    // s6.2.2.1's client MUST is conditional - "if the client has not received an acknowledgment
    // for any of its Handshake packets and the handshake is not confirmed" - and A.8's rung 3
    // reads the negation: "There is nothing to detect lost, so no timer is set." A client that
    // probed whenever it had nothing in flight would keep waking a server that is not blocked,
    // for as long as the connection lived.
    [Fact]
    public async Task AClientWhoseAddressTheServerHasValidatedSendsNoProbeWithNothingInFlight()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        await using var connection = Connection(
            impaired, serverTransport, pki, clock: impaired.Clock);

        await connection.StartAsync(cancellation.Token);
        AcknowledgeEverythingRetainedIn(
            connection, TlsQuicEncryptionLevel.Initial, impaired.Clock.GetUtcNow());

        // THE ONE DIFFERENCE. A Handshake-space acknowledgement makes A.8's
        // PeerCompletedAddressValidation true - "return has received Handshake ACK ||
        // handshake confirmed". The packet it retires is put there through A3-3's seam,
        // because A.7 returns before re-arming anything when a frame newly acknowledges
        // nothing - "Nothing to do if there are no newly acked packets" - so an ACK naming a
        // packet number this client never sent would leave the timer exactly as it was and
        // this control would be testing A.7's guard instead of A.8's rung 3.
        connection.OnPacketSent(PacketAt(
            TlsQuicEncryptionLevel.Handshake, 0, impaired.Clock.GetUtcNow()));
        var handshakeAck = AckFrame(new TlsQuicAckRange(0, 0));
        Assert.True(connection.Acks.ProcessAckFrame(
            TlsQuicEncryptionLevel.Handshake,
            handshakeAck,
            impaired.Clock.GetUtcNow(),
            out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        connection.OnAckReceived(TlsQuicEncryptionLevel.Handshake, handshakeAck);

        Assert.Equal(0L, connection.BytesInFlight);
        Assert.NotNull(connection.LargestAcknowledged(TlsQuicEncryptionLevel.Handshake));

        // A.8's rung 3 cancelled it, so there is no deadline for the pump to wake on and the
        // attempt runs into the handshake deadline instead. THAT IS THE ASSERTION: not that a
        // probe was small or late, but that the pump's only way out was an abandonment.
        Assert.Null(connection.LossDetectionTimer);

        var offeredBefore = impaired.Offered.Count;
        impaired.Clock.Advance(TimeSpan.FromSeconds(11));
        await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(0, connection.ProbeDatagramsSent);
        Assert.Equal(0, impaired.Offered.Count - offeredBefore);
    }

    // s8.1's OTHER half: "otherwise send a Handshake packet". The client here has Handshake
    // write keys - it installed them out of the server's flight and answered at that level -
    // and its Handshake packet is unacknowledged, so A.8's loop picks the Handshake space and
    // A.9's PTO arm probes there.
    //
    // THIS IS THE PTO ARM RATHER THAN THE ANTI-DEADLOCK ONE, AND THE DIFFERENCE IS WORTH
    // NAMING BECAUSE THE SENTENCE IS THE SAME. A.9's anti-deadlock arm with Handshake keys
    // needs Handshake keys AND nothing ack-eliciting in flight AND no Handshake
    // acknowledgement, and this client cannot reach that state: the pump that installs
    // Handshake keys is the pump that answers at Handshake level, so the keys and the in-flight
    // packet arrive together, and anything that retires that packet is itself the Handshake
    // acknowledgement that ends the condition. The BRANCH is A3-5's and lives in
    // GetPtoTimeAndSpace; what A3-7 owes and what this pins is that a probe fired with
    // Handshake keys is a Handshake packet on the wire.
    [Fact]
    public async Task APtoWithHandshakeKeysSendsAHandshakePacket()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        await using var connection = Connection(
            impaired, serverTransport, pki, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // THE PRECONDITION, ASSERTED. The client answered at Handshake level, so it holds
        // Handshake write keys and has an ack-eliciting Handshake packet outstanding.
        Assert.NotEmpty(connection.SentPackets(TlsQuicEncryptionLevel.Handshake));
        Assert.Null(connection.LargestAcknowledged(TlsQuicEncryptionLevel.Handshake));
        Assert.False(connection.IsHandshakeConfirmed);

        var armed = Assert.IsType<DateTimeOffset>(connection.LossDetectionTimer);
        Assert.Equal(TlsQuicEncryptionLevel.Handshake, connection.LossDetectionSpace);

        var offeredBefore = impaired.Offered.Count;
        impaired.Clock.Advance(armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // s6.2.4's "up to two full-sized datagrams", which is knob 10 - and TWO here against
        // the anti-deadlock arm's ONE above, which is the pair that makes the two arms
        // distinguishable rather than merely differently commented.
        Assert.Equal(Spec().Recovery.ProbePacketsPerPto, connection.ProbeDatagramsSent);
        Assert.Equal(
            Spec().Recovery.ProbePacketsPerPto, impaired.Offered.Count - offeredBefore);
        Assert.Equal(TlsQuicEncryptionLevel.Handshake, connection.LastProbeLevel);

        // s8.1's "otherwise send a Handshake packet", read off the wire.
        foreach (var datagram in impaired.Offered.Skip(offeredBefore))
        {
            Assert.True(TlsQuicPacketHeader.TryReadLongHeader(datagram, out var header, out _));
            Assert.Equal(TlsQuicLongPacketType.Handshake, header.Type);
        }

        // AND THE DEBT IS DISCHARGED EXACTLY ONCE, WHICH IS A CLAIM ABOUT LATER PUMPS AND IS
        // ASSERTED ON THE STATE THAT DECIDES THEM. A.9 owes a probe per EXPIRY - "When a PTO
        // timer expires, a sender MUST send at least one ack-eliciting packet" - so a debt left
        // standing after the send makes EVERY later pump emit another probe with no timer
        // having fired at all, which is the spam s6.2.2.1's two halves are drawn to avoid.
        //
        // ON OwedProbe RATHER THAN ON A SECOND PUMP, AND THE REASON IS A MEASUREMENT: a second
        // pump here has nothing to receive. The peer has read the client's Handshake flight and
        // answers nothing further at this point in the exchange, so a pump written to observe
        // the debt behaviourally blocks on its receive and is ended by the test's own token
        // after a wall-clock minute - a test that fails for the wrong reason and costs a sweep
        // a minute per mutant. The debt itself is the state SendOwedProbeAsync's next call
        // reads, and it is nulled before the first send precisely so that a send which throws
        // cannot leave one standing.
        Assert.Null(connection.OwedProbe);
    }

    // ========================================================================
    // s6.2.1's PERIOD, RECOMPUTED FROM THE LIVE ESTIMATOR RATHER THAN COMPARED
    // AGAINST A LITERAL.
    // ========================================================================
    //
    // "PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay", with max_ack_delay
    // zero for Initial and Handshake - "the peer is expected to not delay these packets
    // intentionally".
    //
    // THE SAMPLES ARE REAL. Each one is a packet retained by A3-3's OnPacketSent and an ACK
    // frame handed to A3-4's ProcessAckFrame with that retained list, which is the overload
    // that takes an RTT sample; the seed A.4 puts in the tracker's constructor is overwritten
    // by the first of them. So smoothed_rtt and rttvar below are A3-4's arithmetic and not
    // this file's.
    [Fact]
    public async Task ThePtoPeriodIsRecomputedFromTheLiveEstimatorAndNotFromTheInitialSeed()
    {
        var clock = FakeClock();
        var recovery = new TlsQuicRecoverySpec();
        await using var connection = ProbeConnectionOn(clock, recovery);

        var sample = TimeSpan.FromMilliseconds(40);
        TakeRoundTripSamples(connection, clock, sample, count: 4);

        // THE ESTIMATOR MOVED OFF ITS SEED, which is what makes the rest of this test about the
        // live estimator rather than about kInitialRtt under another name.
        Assert.NotEqual(TlsQuicRecoverySpec.KInitialRtt, connection.Acks.SmoothedRtt);
        Assert.Equal(sample, connection.Acks.LatestRtt);

        // One ack-eliciting packet left in flight, so A.8's loop has a space to arm from.
        var sentAt = clock.GetUtcNow();
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 100, sentAt));

        Assert.Equal(
            sentAt + PtoPeriodOf(connection, recovery, TimeSpan.Zero),
            connection.LossDetectionTimer);
        Assert.Equal(TlsQuicEncryptionLevel.Handshake, connection.LossDetectionSpace);
    }

    // LEDGER ROW 160, WHICH A3-5 RECORDED AS UNWITNESSED AND NAMED THE MISSING STATE FOR:
    // "`max(4 * rttvar, kGranularity)` and `4 * rttvar` differ only when 4 * rttvar is under a
    // millisecond AND smoothed_rtt is over one ... That is a stable connection with a
    // low-variance RTT, which this suite has no path to."
    //
    // A3-6's own header then corrected the row's PREDICTION - it said A3-6 would witness the
    // term through s6.1.2, and s6.1.2 has no rttvar term at all - and named A3-7 as where it
    // becomes witnessable. THIS IS THAT WITNESS, AND THE PATH IS ARITHMETIC RATHER THAN LUCK:
    // A.7's UpdateRtt is `rttvar = 3/4 * rttvar + 1/4 * abs(smoothed_rtt - adjusted_rtt)`, so a
    // run of IDENTICAL samples drives the second term to zero and leaves rttvar decaying by
    // three quarters per sample while smoothed_rtt sits still. Twenty-five samples of 40 ms
    // take rttvar from 20 ms to 20 * (3/4)^25 ~= 15 microseconds, which is comfortably inside
    // the window the row describes.
    //
    // BOTH CANDIDATE NUMBERS ARE ASSERTED, not merely that they differ - the standing rule for
    // a place where two readings of one expression are both plausible.
    [Fact]
    public async Task TheFourRttvarTermIsFlooredAtTheTimerGranularityAndTheFlooredValueIsWhatIsArmed()
    {
        var clock = FakeClock();
        var recovery = new TlsQuicRecoverySpec();
        await using var connection = ProbeConnectionOn(clock, recovery);

        var sample = TimeSpan.FromMilliseconds(40);
        TakeRoundTripSamples(connection, clock, sample, count: 25);

        // THE WINDOW ROW 160 NAMES, ASSERTED RATHER THAN ASSUMED: four rttvars below the
        // granularity, and a smoothed RTT far above it. Without both, the two candidate periods
        // below coincide and this test proves nothing.
        var fourRttvar = connection.Acks.RttVariation * 4;
        Assert.True(
            fourRttvar < TlsQuicConnection.KGranularity,
            $"4 * rttvar is {fourRttvar}, which is not below the {TlsQuicConnection.KGranularity} "
                + "granularity - the floor cannot be what decides the period.");
        Assert.True(connection.Acks.SmoothedRtt > TlsQuicConnection.KGranularity);

        var sentAt = clock.GetUtcNow();
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 100, sentAt));

        var floored = connection.Acks.SmoothedRtt + TlsQuicConnection.KGranularity;
        var unfloored = connection.Acks.SmoothedRtt + fourRttvar;
        Assert.NotEqual(floored, unfloored);

        Assert.Equal(sentAt + floored, connection.LossDetectionTimer);
        Assert.NotEqual(sentAt + unfloored, connection.LossDetectionTimer);
    }

    // ========================================================================
    // KNOB 1 - THE INITIAL RTT, AND FINDING 6's DIVERGENCE.
    // ========================================================================
    //
    // RFC 9002 s6.2.2: "When no previous RTT is available, the initial RTT SHOULD be set to 333
    // milliseconds." TlsQuicRecoverySpec.DrawInitialRtt's remarks record why a spec that names
    // a range has made one available and is therefore conforming, and TlsQuicConnectionSpec.
    // InitialRttRange is the knob the transport-parameter preset already advertises a draw from
    // as parameter 12583.
    //
    // A WITNESS PER BRANCH, which is the clause a straight RFC transcription fails: a
    // connection that read kInitialRtt unconditionally passes the null row and fails the other,
    // and the RANGE IS CHOSEN TO EXCLUDE 333 ms so that no arithmetic coincidence can hide it.
    [Theory]
    [InlineData(false)]   // no range: RFC 9002 s6.2.2's 333 ms, which is the shipped default.
    [InlineData(true)]    // a range: the draw, and 333 ms is outside it.
    public async Task TheFirstPtoIsArmedFromTheSpecsInitialRttRangeAndOnlyFallsBackToKInitialRtt(
        bool rangeIsSet)
    {
        var clock = FakeClock();

        // A DEGENERATE RANGE - one value - so that the expectation is exact rather than an
        // interval. DrawInitialRtt's draw is inclusive of both bounds, so a range whose bounds
        // are equal has exactly one outcome; the draw itself is witnessed as a draw by
        // TlsQuicRecoverySpecTests.DrawInitialRttDrawsAfreshAndDefaultsItsRandomSource.
        var drawn = TimeSpan.FromMilliseconds(193);
        Assert.NotEqual(TlsQuicRecoverySpec.KInitialRtt, drawn);

        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            InitialRttRange = rangeIsSet ? (drawn, drawn) : null,
        };

        await using var connection = IdleOn(clock, spec);

        var expectedRtt = rangeIsSet ? drawn : TlsQuicRecoverySpec.KInitialRtt;

        // A.4's seeds, reached through the connection's own tracker: "smoothed_rtt =
        // kInitialRtt" and "rttvar = kInitialRtt / 2", with the recovery spec's answer standing
        // in for kInitialRtt.
        Assert.Equal(expectedRtt, connection.Acks.SmoothedRtt);
        Assert.Equal(new TimeSpan(expectedRtt.Ticks / 2), connection.Acks.RttVariation);
        Assert.Null(connection.Acks.FirstRttSampleAt);

        var sentAt = clock.GetUtcNow();
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 0, sentAt));

        var expectedPeriod =
            expectedRtt + Longer(new TimeSpan(expectedRtt.Ticks / 2 * 4), TlsQuicConnection.KGranularity);
        Assert.Equal(sentAt + expectedPeriod, connection.LossDetectionTimer);

        // AND THE OTHER CANDIDATE IS NAMED, in both directions, so neither row can pass by
        // landing on the value the other row expects.
        var otherRtt = rangeIsSet ? TlsQuicRecoverySpec.KInitialRtt : drawn;
        var otherPeriod =
            otherRtt + Longer(new TimeSpan(otherRtt.Ticks / 2 * 4), TlsQuicConnection.KGranularity);
        Assert.NotEqual(sentAt + otherPeriod, connection.LossDetectionTimer);
    }

    // ========================================================================
    // s6.2.1's BACKOFF - ONE WITNESS PER DIRECTION.
    // ========================================================================
    //
    // "When a PTO timer expires, the PTO backoff MUST be increased, resulting in the PTO period
    // being set to twice its current value. The PTO backoff factor is reset when an
    // acknowledgment is received, except in the following case." The exception - an
    // acknowledgement in an Initial packet, at a client whose address is not yet validated - is
    // A3-5's AnAcknowledgementInAnInitialPacketDoesNotResetThePtoBackoff. THIS IS THE OTHER
    // DIRECTION: an acknowledgement that DOES reset, and A3-5 had no state that reached it.
    [Fact]
    public async Task AnAcknowledgementThatCompletesAddressValidationResetsThePtoBackoff()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromHours(1),
            idleTimeout: TimeSpan.FromHours(2));

        await connection.StartAsync(cancellation.Token);

        // TWO REAL EXPIRIES FIRST, so the number being reset is two rather than one - a reset
        // to zero from one is also what "subtract one" produces, and this tells them apart.
        for (var expiry = 1; expiry <= 2; expiry++)
        {
            var armed = connection.LossDetectionTimer!.Value;
            transport.Clock.Advance(
                armed - transport.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
            Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        }

        Assert.Equal(2, connection.PtoCount);

        // A HANDSHAKE-SPACE ACKNOWLEDGEMENT THAT RETIRES SOMETHING, which is both halves A.7
        // requires: the newly-acked guard, and PeerCompletedAddressValidation's "has received
        // Handshake ACK". The packet is put there through A3-3's seam because this client has
        // not reached its Handshake flight.
        connection.OnPacketSent(PacketAt(
            TlsQuicEncryptionLevel.Handshake, 0, transport.Clock.GetUtcNow()));
        var ack = AckFrame(new TlsQuicAckRange(0, 0));
        Assert.True(connection.Acks.ProcessAckFrame(
            TlsQuicEncryptionLevel.Handshake,
            ack,
            transport.Clock.GetUtcNow(),
            out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        connection.OnAckReceived(TlsQuicEncryptionLevel.Handshake, ack);

        Assert.Equal(0, connection.PtoCount);
        Assert.NotEqual(2, connection.PtoCount);
    }

    // LEDGER ROW 168, WHICH A3-5 RECORDED AS "UNWITNESSED AND IS THE GUARD A3-7 WILL NEED":
    // "A.7 gates its pto_count reset behind `if (newly_acked_packets.empty()): return`, and
    // without it a DUPLICATE ACK - one naming only packets already retired - resets a backoff
    // consecutive PTOs earned. Reaching that needs a confirmed handshake, a fired probe timeout
    // and then a redundant ACK, and nothing in this suite strings the three together."
    //
    // IT NEEDS NO CONFIRMED HANDSHAKE, WHICH IS THE PART THE ROW GOT WRONG: what the guard
    // protects is reachable with any acknowledgement that validates the address, so the state
    // is the test above followed by the SAME frame a second time. The second arrival names a
    // packet number nothing retains any more, so A.7 must return before the reset - and before
    // A.10, which is why PacketsDeclaredLost is asserted not to move either.
    [Fact]
    public async Task ADuplicateAcknowledgementDoesNotResetAPtoBackoffEarnedAfterIt()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromHours(1),
            idleTimeout: TimeSpan.FromHours(2));

        await connection.StartAsync(cancellation.Token);

        // The address is validated FIRST, so that the reset is not being refused for s6.2.1's
        // other reason - which is the trap row 167's witness fell into and row 168 names.
        connection.OnPacketSent(PacketAt(
            TlsQuicEncryptionLevel.Handshake, 0, transport.Clock.GetUtcNow()));
        var ack = AckFrame(new TlsQuicAckRange(0, 0));
        Assert.True(connection.Acks.ProcessAckFrame(
            TlsQuicEncryptionLevel.Handshake, ack, transport.Clock.GetUtcNow(), out _));
        connection.OnAckReceived(TlsQuicEncryptionLevel.Handshake, ack);
        Assert.NotNull(connection.LargestAcknowledged(TlsQuicEncryptionLevel.Handshake));

        // THEN a probe timeout earns a backoff.
        var armed = connection.LossDetectionTimer!.Value;
        transport.Clock.Advance(
            armed - transport.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.PtoCount);

        var declaredBefore = connection.PacketsDeclaredLost;

        // THE SAME FRAME AGAIN. It is legal, it is what a retransmitted ACK looks like, and it
        // newly acknowledges nothing.
        Assert.True(connection.Acks.ProcessAckFrame(
            TlsQuicEncryptionLevel.Handshake, ack, transport.Clock.GetUtcNow(), out _));
        connection.OnAckReceived(TlsQuicEncryptionLevel.Handshake, ack);

        Assert.Equal(1, connection.PtoCount);
        Assert.NotEqual(0, connection.PtoCount);
        Assert.Equal(declaredBefore, connection.PacketsDeclaredLost);
    }

    // ========================================================================
    // s6.2.4's PROBE CONTENTS - KNOB 11, AND THE SAME PTO UNDER TWO SPECS.
    // ========================================================================
    //
    // s6.2.4 leaves the contents open in as many words - "Implementations MAY use alternative
    // strategies for determining the content of probe packets" - with one hard rule: "All probe
    // packets sent on a PTO MUST be ack-eliciting." TlsQuicProbeContents is that choice and
    // this is the pair that makes it a knob rather than a comment: ONE state, TWO specs, TWO
    // different datagrams on the wire.
    //
    // AT HANDSHAKE LEVEL AND NOT AT Initial, and that is a property of the builder rather than
    // a convenience. TlsQuicDatagramBuilder expands any datagram carrying an Initial packet to
    // TlsQuicConnectionSpec.PaddingTarget on its own - which is how s8.1's 1200 is met - so at
    // Initial the two knob values produce the same bytes by construction. The knob is
    // observable exactly where s8.1 does not already decide the size.
    //
    // THE ROW IS A bool AND NOT THE ENUM, for a C# reason rather than a design one:
    // TlsQuicProbeContents is internal and an xUnit theory method must be public, which
    // CS0051 rejects. The mapping is one line and is the first line of the body.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheProbesContentsFollowKnobElevenRatherThanAConstant(bool padded)
    {
        var contents = padded
            ? TlsQuicProbeContents.PingWithPadding
            : TlsQuicProbeContents.Ping;

        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            Recovery = new TlsQuicRecoverySpec { ProbeContents = contents },
        };

        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(TlsQuicEncryptionLevel.Handshake, connection.LossDetectionSpace);

        var armed = connection.LossDetectionTimer!.Value;
        var offeredBefore = impaired.Offered.Count;
        impaired.Clock.Advance(armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        var probe = impaired.Offered[offeredBefore];

        if (contents == TlsQuicProbeContents.PingWithPadding)
        {
            // s6.2.4's "full-sized datagrams". The target is a floor, not a ceiling - s14.1:
            // "Datagrams containing Initial packets MAY exceed 1200 bytes" - and a Length
            // varint that widens under the added PADDING can overshoot it by a byte or three,
            // so the bound is stated the way s14.1 states it.
            Assert.True(
                probe.Length >= spec.PaddingTarget,
                $"A padded probe was {probe.Length} bytes, below the {spec.PaddingTarget} "
                    + "target.");
        }
        else
        {
            // s6.2.4's other arm: "the sender SHOULD send a PING or other ack-eliciting frame
            // in a SINGLE PACKET". A PING is one byte, so this datagram is nowhere near the
            // target - asserted against the target rather than against a size, so the two rows
            // cannot both pass on the same bytes.
            Assert.True(
                probe.Length < spec.PaddingTarget,
                $"An unpadded probe was {probe.Length} bytes, at or above the "
                    + $"{spec.PaddingTarget} target - the knob changed nothing.");
        }
    }

    // KNOB 10, WHICH IS s6.2.4's "up to two": "An endpoint MAY send up to two full-sized
    // datagrams containing ack-eliciting packets to avoid an expensive consecutive PTO
    // expiration due to a single lost datagram." One row per legal value, and the count read
    // off the transport rather than off the connection.
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ProbePacketsPerPtoDecidesHowManyDatagramsLeaveOnOneExpiry(int probes)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            Recovery = new TlsQuicRecoverySpec { ProbePacketsPerPto = probes },
        };

        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        var armed = connection.LossDetectionTimer!.Value;
        var offeredBefore = impaired.Offered.Count;
        impaired.Clock.Advance(armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(probes, impaired.Offered.Count - offeredBefore);
        Assert.Equal(probes, connection.ProbeDatagramsSent);

        // AND EACH IS ITS OWN PACKET NUMBER. s12.3: "A QUIC endpoint MUST NOT reuse a packet
        // number within a packet number space in the same connection", and two probes built
        // from one expiry are the obvious place to break it.
        var numbers = connection.SentPackets(TlsQuicEncryptionLevel.Handshake)
            .Select(static p => p.PacketNumber)
            .ToArray();
        Assert.Equal(numbers.Length, numbers.Distinct().Count());
    }

    // ========================================================================
    // s6.2's TWO "MUST NOT"s, WHICH ARE ABOUT WHAT A PTO IS NOT.
    // ========================================================================

    // s6.2: "A PTO timer expiration event does not indicate packet loss and MUST NOT cause
    // prior unacknowledged packets to be marked as lost."
    //
    // A.9 gets that from its structure - the loss arm RETURNS before the probe arm - and the
    // structure is what a transcription flattens. THE PACKET HERE IS OLD ENOUGH TO BE
    // DECLARED LOST BY THE TIME THRESHOLD IF ANYTHING ASKED, which is what makes this more than
    // a restatement of "nothing was lost": the loss delay has NOT elapsed against the probe's
    // own period, so the PTO fires first, and a connection that ran detection on the PTO arm
    // would declare it.
    [Fact]
    public async Task APtoExpiryDeclaresNothingLost()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromHours(1),
            idleTimeout: TimeSpan.FromHours(2));

        await connection.StartAsync(cancellation.Token);
        Assert.NotEmpty(connection.SentPackets(TlsQuicEncryptionLevel.Initial));

        var armed = connection.LossDetectionTimer!.Value;
        transport.Clock.Advance(
            armed - transport.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.LossDetectionTimeouts);
        Assert.Equal(0, connection.PacketsDeclaredLost);
        Assert.Empty(connection.LastDetectedLost);

        // AND THE PACKETS ARE STILL THERE TO BE LOST LATER, which "nothing was declared" alone
        // does not say - A.11's RemoveFromBytesInFlight would empty the list without reporting
        // anything.
        Assert.NotEmpty(connection.SentPackets(TlsQuicEncryptionLevel.Initial));
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // s6.2.1: "The PTO timer MUST NOT be set if a timer is set for time threshold loss
    // detection; see Section 6.1.2." A.8 makes that a rung ORDER - GetLossTimeAndSpace first,
    // with a return - and A3-7's rung 1 is what implements it.
    //
    // THE TWO INSTANTS ARE MADE FAR APART DELIBERATELY. s6.2.1's own reason for the rule is
    // that a loss timer "will expire earlier than the PTO timer in most cases", so a test whose
    // two candidates happened to coincide would pass against a connection with no rung 1 at
    // all. Here the packet threshold is pushed out of reach and the time threshold is what
    // remains, and the PTO period is inflated by a backoff ceiling far above it.
    [Fact]
    public async Task ALossTimerSuppressesThePtoTimerRatherThanRacingIt()
    {
        var clock = FakeClock();
        var recovery = new TlsQuicRecoverySpec { PacketThreshold = int.MaxValue };
        await using var connection = ProbeConnectionOn(clock, recovery);

        var sentAt = clock.GetUtcNow();
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 0, sentAt));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 1, sentAt));

        var ptoWouldArmAt = connection.LossDetectionTimer;

        var ack = AckFrame(new TlsQuicAckRange(1, 1));
        Assert.True(connection.Acks.ProcessAckFrame(
            TlsQuicEncryptionLevel.Handshake, ack, clock.GetUtcNow(), out _));
        connection.OnAckReceived(TlsQuicEncryptionLevel.Handshake, ack);

        // A.10's else branch put a loss_time on the space, which is the precondition.
        var lossTime = Assert.IsType<DateTimeOffset>(
            connection.LossTime(TlsQuicEncryptionLevel.Handshake));
        Assert.Equal(0, connection.PacketsDeclaredLost);

        // THE ARMED INSTANT IS THE LOSS TIME AND NOT THE PTO'S, and both candidates are named.
        Assert.Equal(lossTime, connection.LossDetectionTimer);
        Assert.NotEqual(ptoWouldArmAt, connection.LossDetectionTimer);
        Assert.Equal(TlsQuicEncryptionLevel.Handshake, connection.LossDetectionSpace);

        // AND THE WAKE IT PRODUCES IS A LOSS EVENT RATHER THAN A PROBE: A.9's rung 1 declares
        // the packet and RETURNS, so pto_count does not move and no probe is owed. That return
        // is exactly what s6.2's "A PTO timer expiration event does not indicate packet loss"
        // requires in the other direction.
        clock.Advance(lossTime - clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        connection.OnLossDetectionTimeout();

        Assert.Equal(1, connection.PacketsDeclaredLost);
        Assert.Equal([0UL], connection.LastDetectedLost.Select(static p => p.PacketNumber));
        Assert.Equal(0, connection.PtoCount);
        Assert.Null(connection.OwedProbe);
    }

    // ========================================================================
    // NOTHING THROWS, AND A HANG IS IMPOSSIBLE.
    // ========================================================================

    // Every input to s6.2.1's period is peer-influenced or clock-influenced, and A3-2's knobs
    // widen the range further than any peer can: a backoff factor at the top of the double
    // range, a ceiling at one tick, a time threshold at double.MaxValue. THE PROBE PATH IS
    // DRIVEN THROUGH ALL OF THEM, on both ends of the calendar, and the assertion is that a
    // datagram still leaves rather than merely that nothing threw - a probe path that swallowed
    // its own arithmetic would satisfy "no exception" and break s8.1.
    [Theory]
    [InlineData(1.0)]
    [InlineData(double.MaxValue)]
    public async Task TheProbePathSurvivesEverySaturatingKnobAndStillPutsADatagramOnTheWire(
        double backoffFactor)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            Recovery = new TlsQuicRecoverySpec
            {
                PtoBackoff = (backoffFactor, TimeSpan.FromTicks(1)),
                TimeThreshold = double.MaxValue,
                PacketThreshold = int.MaxValue,
            },
        };

        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await connection.StartAsync(cancellation.Token);

        // A CEILING OF ONE TICK, RAISED TO kGranularity BY s6.2.1's "The PTO period MUST be at
        // least kGranularity to avoid the timer expiring immediately" - which is the clamp
        // A3-5 applied after the ceiling for exactly this input. Five expiries, each of which
        // must move the clock by at least a granularity, so a period that collapsed to zero
        // would spin here rather than pass.
        var offeredBefore = impaired.Offered.Count;
        for (var expiry = 1; expiry <= 5; expiry++)
        {
            var armed = connection.LossDetectionTimer!.Value;
            Assert.True(
                armed > impaired.Clock.GetUtcNow(),
                $"Expiry {expiry} was armed at {armed}, which is not after the clock - the "
                    + "next pump would spin.");
            impaired.Clock.Advance(
                armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
            Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        }

        Assert.Equal(5, connection.LossDetectionTimeouts);
        Assert.Equal(
            5 * spec.Recovery.ProbePacketsPerPto, impaired.Offered.Count - offeredBefore);
        Assert.Equal(5 * spec.Recovery.ProbePacketsPerPto, connection.ProbeDatagramsSent);
    }

    // THE ONE INPUT ON THE PROBE PATH THAT WOULD THROW, DRIVEN RATHER THAN REASONED ABOUT.
    // TlsQuicConnectionSpec.PaddingTarget's upper bound is 65527, which is exactly the send
    // buffer's length, so a padder that filled to the target and then paid for a Length varint
    // that widened under its own PADDING would hand TlsQuicPacketBuilder.Build a span too small
    // and be met with an ArgumentException naming `destination`. The clamp in
    // TryBuildProbeDatagram is what stops that, and this is it at the exact target where it
    // binds - one below the maximum and the clamp is inert.
    //
    // AT Handshake LEVEL, WHICH IS WHERE THE MANUAL PADDER RUNS AT ALL: an Initial-carrying
    // datagram is expanded by the builder's own solver and never reaches the loop.
    [Fact]
    public async Task AProbePaddedToTheLargestTargetTheSpecAcceptsStillFitsTheSendBuffer()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var spec = new TlsQuicConnectionSpec
        {
            // The largest value the setter accepts - s18.2's UDP payload ceiling.
            PaddingTarget = 65527,
            SourceConnectionIdLength = SourceConnectionIdLength,
            Recovery = new TlsQuicRecoverySpec
            {
                ProbeContents = TlsQuicProbeContents.PingWithPadding,
            },
        };

        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(TlsQuicEncryptionLevel.Handshake, connection.LossDetectionSpace);

        var armed = connection.LossDetectionTimer!.Value;
        var offeredBefore = impaired.Offered.Count;
        impaired.Clock.Advance(armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));

        // NO EXCEPTION, AND A DATAGRAM. "Nothing threw" alone would be satisfied by a probe path
        // that gave up, which is the failure s8.1 is about.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(spec.Recovery.ProbePacketsPerPto, connection.ProbeDatagramsSent);

        var probe = impaired.Offered[offeredBefore];

        // WITHIN THE BUFFER, AND WITHIN SEVEN BYTES OF THE TARGET. The upper bound is the
        // assertion the clamp exists for; the lower bound is what stops the clamp from being
        // satisfiable by not padding at all.
        Assert.True(
            probe.Length <= spec.PaddingTarget,
            $"A probe padded to {spec.PaddingTarget} came out at {probe.Length} bytes, past the "
                + "send buffer.");
        Assert.True(
            probe.Length > spec.PaddingTarget - TlsQuicConnection.MaximumVarintWidth,
            $"A probe padded to {spec.PaddingTarget} came out at {probe.Length} bytes, which is "
                + "more than one varint's worth short of the target.");
    }

    // THE HANG PROOF FOR THE PROBE, WHICH IS A DIFFERENT CLAIM FROM A3-5's. A3-5 proved the
    // timer never arms in the past; A3-7 adds a SEND to every expiry, and a send moves A.3's
    // time_of_last_ack_eliciting_packet - so the question "does the next period still move
    // forward" has to be asked again with the probe in the loop. IT IS ASKED THE ONLY WAY THAT
    // SETTLES IT: the clock is advanced to each armed instant and no further, so a period that
    // failed to move would leave the next pump waiting on an instant that never arrives, and
    // the test's own token would be what ended it.
    //
    // AND THE RETENTION CAP IS THE OTHER HALF. Two probes per expiry over enough expiries is
    // what would grow _sentPackets without bound if A3-3's cap were not the single exit; the
    // invariant is checked at the end rather than argued.
    [Fact]
    public async Task ManyConsecutiveProbeTimeoutsNeitherSpinNorGrowRetentionWithoutBound()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // KNOB 9's CEILING IS WHAT MAKES THIS LOOP ABOUT SPINNING RATHER THAN ABOUT THE
        // HANDSHAKE DEADLINE, and finding that out cost a red test worth recording. Without a
        // ceiling the period doubles per expiry, so by the sixty-fourth it is 999 ms times
        // 2^63 - and s6.2.1 says exactly what happens then: "The total length of time over
        // which consecutive PTOs expire is limited by the idle timeout." The attempt is
        // abandoned long before the cap is reached, which is CORRECT and is not the property
        // this test is for. A one-second ceiling keeps every period equal and finite, so
        // seventy expiries cost seventy seconds of fake time and the only way to fail is to
        // arm at or before the clock.
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            Recovery = new TlsQuicRecoverySpec
            {
                PtoBackoff = (TlsQuicRecoverySpec.DefaultPtoBackoffFactor, TimeSpan.FromSeconds(1)),
            },
        };

        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromDays(1),
            idleTimeout: TimeSpan.FromDays(2),
            spec: spec);

        await connection.StartAsync(cancellation.Token);

        var previous = connection.LossDetectionTimer!.Value;
        for (var expiry = 1; expiry <= TlsQuicConnection.MaximumPtoCount + 6; expiry++)
        {
            transport.Clock.Advance(
                previous - transport.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
            Assert.False(await connection.PumpOnceAsync(cancellation.Token));

            var armed = connection.LossDetectionTimer!.Value;
            Assert.True(
                armed > transport.Clock.GetUtcNow(),
                $"Expiry {expiry} re-armed at {armed}, which is not after the clock's "
                    + $"{transport.Clock.GetUtcNow()} - the next pump would spin.");
            previous = armed;
        }

        // A.9's cap, which is what keeps `2 ^ pto_count` from wrapping negative and inverting
        // the backoff into a speed-up: forty expiries are more than the cap, so this is the cap
        // observed rather than the counter.
        Assert.Equal(TlsQuicConnection.MaximumPtoCount, connection.PtoCount);

        Assert.True(
            connection.SentPackets(TlsQuicEncryptionLevel.Initial).Count
                <= TlsQuicConnection.MaxRetainedPacketsPerSpace,
            "Probes grew retention past A3-3's cap.");
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // ========================================================================
    // HELPERS
    // ========================================================================

    // An idle connection carrying A3-2's knobs, for the arithmetic half. The two spec values
    // every connection test in this partial sets are kept where they are.
    private static TlsQuicConnection ProbeConnectionOn(
        ManualTimeProvider clock, TlsQuicRecoverySpec recovery) =>
        IdleOn(clock, new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            Recovery = recovery,
        });

    // s6.2.1's period, recomputed from the connection's OWN estimator rather than from a seed
    // this file restates: "PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay",
    // with the backoff applied as knob 9's factor to the power of pto_count.
    private static TimeSpan PtoPeriodOf(
        TlsQuicConnection connection, TlsQuicRecoverySpec recovery, TimeSpan maxAckDelay)
    {
        var variation = Longer(connection.Acks.RttVariation * 4, TlsQuicConnection.KGranularity);
        var period = connection.Acks.SmoothedRtt + variation + maxAckDelay;
        var scaled = new TimeSpan(
            (long)(period.Ticks * Math.Pow(recovery.PtoBackoff.Factor, connection.PtoCount)));
        if (recovery.PtoBackoff.Maximum is { } ceiling && scaled > ceiling)
        {
            scaled = ceiling;
        }

        return Longer(scaled, TlsQuicConnection.KGranularity);
    }

    // One round trip per iteration, through A3-3's retention and A3-4's sampling overload: a
    // packet is sent, the clock moves by the sample, and an ACK naming that packet arrives.
    // A.7's UpdateRtt is what turns the pair into smoothed_rtt and rttvar; nothing here
    // computes either.
    private static void TakeRoundTripSamples(
        TlsQuicConnection connection,
        ManualTimeProvider clock,
        TimeSpan sample,
        int count)
    {
        for (var number = 0UL; number < (ulong)count; number++)
        {
            connection.OnPacketSent(
                PacketAt(TlsQuicEncryptionLevel.Handshake, number, clock.GetUtcNow()));
            clock.Advance(sample);

            var frame = AckFrame(new TlsQuicAckRange(number, number));
            Assert.True(connection.Acks.ProcessAckFrame(
                TlsQuicEncryptionLevel.Handshake,
                frame,
                clock.GetUtcNow(),
                connection.SentPackets(TlsQuicEncryptionLevel.Handshake),
                out var error));
            Assert.Equal(TlsQuicTransportError.NoError, error);
            connection.OnAckReceived(TlsQuicEncryptionLevel.Handshake, frame);
        }
    }

    // Every packet this connection still retains in one space, acknowledged in one frame -
    // s8.1's "the client has received acknowledgments for all the data it has sent".
    private static void AcknowledgeEverythingRetainedIn(
        TlsQuicConnection connection, TlsQuicEncryptionLevel level, DateTimeOffset now)
    {
        var retained = connection.SentPackets(level);
        Assert.NotEmpty(retained);

        var largest = retained.Max(static p => p.PacketNumber);
        var smallest = retained.Min(static p => p.PacketNumber);
        var frame = AckFrame(new TlsQuicAckRange(largest, smallest));

        Assert.True(connection.Acks.ProcessAckFrame(level, frame, now, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        connection.OnAckReceived(level, frame);
        Assert.Empty(connection.SentPackets(level));
    }
}
