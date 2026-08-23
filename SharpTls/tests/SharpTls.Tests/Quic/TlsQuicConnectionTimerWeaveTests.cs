using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task A3-5 of the loss recovery phase: the timer weave. RFC 9002 A.8's SetLossDetectionTimer
// and the half of A.9 that is a WAKE rather than a probe.
//
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's, 14c's, A3-1's AND A3-3's, for the reason those give:
// Spec, Connection, TlsClient, Server and RunToOneRttAsync are reused rather than copied.
//
// ============================================================================
// WHAT THIS FILE PINS THAT NO OTHER FILE CAN, AND WHAT IT DELIBERATELY CANNOT.
// ============================================================================
//
// THE CRUX IS ONE ASSERTION AND IT IS EASY TO MISS AMONG THE ARITHMETIC ONES: a pump that
// returns having received NO DATAGRAM AT ALL. Every other test of this connection in this tree
// drives it by putting bytes in front of it. ADeadlineFiresWithNoDatagramArrivingAndThePump
// RunsASendPass puts none in front of it, ever - the script is empty and RemainingReplies is
// asserted to be zero on both sides of the pump - and the pump still completes. Before A3-5 the
// same setup produced a TimeoutException, which is what ADroppedInitialEndsTheAttemptOnThe
// HandshakeDeadlineRatherThanRecovering still pins for the case where the deadline that fires
// IS an abandonment.
//
// THE ARITHMETIC TESTS USE OnPacketSent DIRECTLY, WHICH IS A3-3's SEAM AND CARRIES A3-3's
// CAVEAT WITH IT: "WHAT IT CANNOT SEE is whether the send path calls OnPacketSent at all. Every
// one of these tests passes against a connection that never wires the builder's list up." The
// same is true of every timer this file arms through that door. What covers the other half is
// the crux test and the loopback ones below it, which arm the timer through a real StartAsync
// and a real handshake and read the same property.
//
// ONE NUMBER RECURS AND IT IS NOT A LITERAL CHOSEN HERE. RFC 9002 A.4 seeds smoothed_rtt at
// kInitialRtt and rttvar at half of it, and TlsQuicAckTracker's constructor does exactly that
// from TlsQuicRecoverySpec.KInitialRtt (333 ms). s6.2.1's period is then
// 333 + max(4 * 166.5, 1) = 333 + 666 = 999 ms before any sample exists, which is the "PTO of
// 1 second" s6.2.2 says a handshake starts with. Every expected instant below is built from
// TlsQuicRecoverySpec.KInitialRtt rather than from 999, so a change to the constant moves the
// tests with the code instead of against it.
public sealed partial class TlsQuicConnectionTests
{
    // RFC 9002 s6.2.1's period before any RTT sample exists, computed rather than typed:
    // smoothed_rtt = kInitialRtt, rttvar = kInitialRtt / 2, so the period is
    // kInitialRtt + max(4 * (kInitialRtt / 2), kGranularity).
    private static readonly TimeSpan InitialPtoPeriod =
        TlsQuicRecoverySpec.KInitialRtt + Longer(
            new TimeSpan(TlsQuicRecoverySpec.KInitialRtt.Ticks / 2 * 4),
            TlsQuicConnection.KGranularity);

    private static TimeSpan Longer(TimeSpan a, TimeSpan b) => a > b ? a : b;

    // ========================================================================
    // THE CRUX: A DEADLINE THAT FIRES WITH NOTHING ON THE WIRE.
    // ========================================================================

    [Fact]
    public async Task ADeadlineFiresWithNoDatagramArrivingAndThePumpRunsASendPass()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // AN HOUR OF HANDSHAKE DEADLINE AND TWO OF IDLE TIMEOUT, so that neither abandonment
        // deadline can be what fires. Without this the ten-second default is nearer than the
        // second PTO and the test would be pinning the deadline it is trying to get out of the
        // way - the same trap the Connection helper's own remarks warn about for the pair.
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromHours(1),
            idleTimeout: TimeSpan.FromHours(2));

        var start = transport.Clock.GetUtcNow();
        await connection.StartAsync(cancellation.Token);

        // ARMED BY THE SEND, WITH NOTHING RECEIVED. RFC 9002 A.5's closing SetLossDetectionTimer
        // reached through OnPacketSent, off the Initial flight StartAsync just sent.
        Assert.Equal(start + InitialPtoPeriod, connection.LossDetectionTimer);
        Assert.Equal(TlsQuicEncryptionLevel.Initial, connection.LossDetectionSpace);
        Assert.Equal(0, connection.PtoCount);
        Assert.Equal(0, connection.LossDetectionTimeouts);

        // THE SCRIPT IS EMPTY AND STAYS EMPTY. This is the assertion the whole task is about:
        // there is nothing for the connection to receive, before the pump or after it.
        Assert.Equal(0, transport.RemainingReplies);

        transport.Clock.Advance(InitialPtoPeriod + TimeSpan.FromMilliseconds(1));

        var wallClock = System.Diagnostics.Stopwatch.StartNew();
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        wallClock.Stop();

        Assert.Equal(0, transport.RemainingReplies);

        // A.9 RAN, ONCE. Not "a deadline passed" - the timeout handler itself executed, which
        // is the thing a receive-driven loop could not reach.
        Assert.Equal(1, connection.LossDetectionTimeouts);
        Assert.Equal(1, connection.PtoCount);

        // AND IT RE-ARMED, DOUBLED. s6.2.1: "When a PTO timer expires, the PTO backoff MUST be
        // increased, resulting in the PTO period being set to twice its current value." The
        // period is measured from the same Initial send, so the new instant is start plus TWICE
        // the period rather than now plus it. THE SECOND ASSERTION IS WHAT MAKES THIS NOT
        // VACUOUS: a mutant that re-armed at the same instant, or one that never incremented
        // pto_count, lands on start + InitialPtoPeriod and is named here rather than caught by
        // an inequality that any other value would also satisfy.
        // A3-7 MOVED THE BASE FROM THE INITIAL FLIGHT TO THE PROBE, because A.9 now sends one
        // and A.1's OnPacketSent re-arms from it; see ConsecutiveProbeTimeoutsBackOffAndNever
        // ArmInThePast for the same correction with its own reasoning. The DOUBLING is still
        // what is asserted, and the second line still names the un-doubled instant as wrong.
        var probeSentAt = transport.Clock.GetUtcNow();
        Assert.Equal(probeSentAt + (InitialPtoPeriod * 2), connection.LossDetectionTimer);
        Assert.NotEqual(probeSentAt + InitialPtoPeriod, connection.LossDetectionTimer);

        // ON THE INJECTED CLOCK AND NOT ON THE WALL, which is the second half of A3-1's point:
        // one clock drives the script and the connection, and a full PTO of fake time cost no
        // real time at all.
        Assert.True(
            wallClock.Elapsed < TimeSpan.FromSeconds(5),
            $"The probe timeout took {wallClock.Elapsed} of wall-clock time, so it did not fire "
                + "off the injected clock.");
    }

    // ========================================================================
    // THE TWO ABANDONMENT DEADLINES STILL WIN WHEN THEY ARE NEARER.
    // ========================================================================

    // THIS TEST EXISTS BECAUSE A MUTATION CONTROL SURVIVED WHEN IT SHOULD NOT HAVE, AND THE
    // REASON IS WORTH MORE THAN THE TEST. The known-bad control for A3-5's sweep dropped the
    // idle timeout out of EarliestDeadline's table, expecting APeerThatGoesSilentIsBoundedBy
    // TheIdleTimeoutToo to fail. IT PASSED. That test runs on the real clock with a 250 ms idle
    // bound and a 30-second handshake deadline, and A3-5 arms a probe timeout at about ONE
    // SECOND off the Initial flight it sends - so with the idle entry gone the receive was
    // still ended, at one second instead of at 250 milliseconds, by the recovery timer, and the
    // test's "under ten seconds" assertion could not tell the two apart. THE PROBE TIMEOUT WAS
    // MASKING THE IDLE ENTRY. Behaviour was never wrong - the check after the receive re-reads
    // both abandonment deadlines and abandons - but the ENTRY had become unwitnessed, and an
    // entry nothing witnesses is one a later task deletes.
    //
    // SO THE PIN IS AN ORDERING THE PROBE TIMEOUT CANNOT SUPPLY: an abandonment deadline
    // NEARER than the probe timeout, on a clock that is advanced past it and no further. If the
    // entry is dropped the receive is armed at the probe timeout instead, that instant never
    // arrives on a clock nobody advances again, and the pump blocks - so the mutant is caught by
    // the wrong exception type rather than by a number.
    //
    // FIVE SECONDS OF OUTER TOKEN AND NOT SIXTY. A mutant that blocks must FAIL, and it must
    // fail quickly: a sweep that spends a minute per blocked mutant is a sweep that gets
    // abandoned. The five seconds are wall-clock and bound only the failure path; the passing
    // path costs no real time at all.
    [Theory]
    [InlineData(true)]    // the idle timeout is the nearer of the two.
    [InlineData(false)]   // the handshake deadline is.
    public async Task TheNearerAbandonmentDeadlineStillBoundsTheReceiveWhenTheProbeIsLater(
        bool idleIsNearer)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        var near = TimeSpan.FromMilliseconds(100);
        var far = TimeSpan.FromHours(1);
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: idleIsNearer ? far : near,
            idleTimeout: idleIsNearer ? near : far);

        var start = transport.Clock.GetUtcNow();
        await connection.StartAsync(cancellation.Token);

        // THE PROBE TIMEOUT IS LATER THAN THE NEARER DEADLINE, WHICH IS THE PRECONDITION THE
        // WHOLE TEST RESTS ON. Asserted rather than assumed: if kInitialRtt ever dropped below
        // a third of `near`, this test would silently stop testing anything.
        Assert.Equal(start + InitialPtoPeriod, connection.LossDetectionTimer);
        Assert.True(InitialPtoPeriod > near);

        transport.Clock.Advance(near + TimeSpan.FromMilliseconds(50));

        var error = await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        // AND THE RIGHT ONE OF THE TWO FIRED. AbandonAsync attributes by which deadline is
        // nearer, so a table that armed the wrong entry would still throw here - the
        // attribution is what separates them.
        Assert.Equal(idleIsNearer, connection.IdleTimedOut);
        Assert.Contains(
            idleIsNearer ? "s10.1" : "did not confirm within", error.Message,
            StringComparison.Ordinal);

        // A.9 NEVER RAN. The wake was an abandonment and not a probe, which is the distinction
        // the whole weave turns on.
        Assert.Equal(0, connection.LossDetectionTimeouts);
    }

    // ========================================================================
    // THE HANG PROOF, MEASURED RATHER THAN ARGUED.
    // ========================================================================

    // A timer that re-armed in the past would wake the pump again immediately, and the pump
    // would send nothing (probe contents are A3-7's), and re-arm in the past again - an
    // unbounded loop that neither abandonment deadline ends because on a frozen clock neither
    // moves. THE FLOOR IN SetLossDetectionTimer IS WHAT MAKES THAT UNREACHABLE, and this drives
    // five consecutive expiries to check it holds every time rather than once.
    //
    // BOUNDED IN THREE WAYS SO A REGRESSION FAILS RATHER THAN WEDGES, which matters because a
    // wedged test is what a mutation sweep cannot score: the outer token is TestTimeout; each
    // pump is preceded by exactly one Advance and so can wake at most once; and the assertion
    // that the armed instant is strictly in the future is checked BEFORE the next pump, so a
    // regression is reported by an assertion rather than by a hang.
    [Fact]
    public async Task ConsecutiveProbeTimeoutsBackOffAndNeverArmInThePast()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromHours(1),
            idleTimeout: TimeSpan.FromHours(2));

        var start = transport.Clock.GetUtcNow();
        await connection.StartAsync(cancellation.Token);

        var previous = connection.LossDetectionTimer!.Value;
        for (var expiry = 1; expiry <= 5; expiry++)
        {
            transport.Clock.Advance(
                previous - transport.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));

            // THE INSTANT THE PROBE GOES OUT AT, which A3-7 made the one the next period is
            // measured from. The clock does not move again inside the pump, so this reading and
            // the one TryBuildProbeDatagram takes are the same value.
            var probeSentAt = transport.Clock.GetUtcNow();

            Assert.False(await connection.PumpOnceAsync(cancellation.Token));

            Assert.Equal(expiry, connection.LossDetectionTimeouts);
            Assert.Equal(expiry, connection.PtoCount);

            // A3-7: s6.2.4's "a sender MUST send at least one ack-eliciting packet in the
            // packet number space as a probe", knob 10 times per expiry. BEFORE A3-7 THIS
            // NUMBER WAS ZERO AT EVERY EXPIRY - the pump woke, sent nothing and re-armed - so
            // this is the assertion that separates a probe timeout from a wake-up.
            Assert.Equal(
                expiry * Spec().Recovery.ProbePacketsPerPto,
                connection.ProbeDatagramsSent);

            var armed = connection.LossDetectionTimer!.Value;

            // STRICTLY LATER THAN THE ONE THAT JUST FIRED, and strictly later than NOW - two
            // different claims, and only the second one bounds the loop.
            Assert.True(
                armed > previous,
                $"Expiry {expiry} re-armed at {armed}, which is not after {previous}.");
            Assert.True(
                armed > transport.Clock.GetUtcNow(),
                $"Expiry {expiry} re-armed at {armed}, which is not after the clock's "
                    + $"{transport.Clock.GetUtcNow()} - the next pump would spin.");

            // s6.2.1's doubling, from the send instant, exactly. A power rather than a
            // comparison, so a backoff that grew by any other law is caught.
            //
            // THE SEND INSTANT IS NOW THE PROBE'S RATHER THAN StartAsync's, AND THAT IS A3-7's
            // DOING RATHER THAN A LOOSENED ASSERTION. A.9 sends its probe and only then calls
            // SetLossDetectionTimer, so A.3's time_of_last_ack_eliciting_packet has moved to
            // the probe by the time the next period is computed; before A3-7 nothing was sent,
            // the Initial flight stayed the latest ack-eliciting send, and every expiry
            // measured from `start`. The doubling itself is unchanged and is still the claim -
            // `start` is asserted below to no longer be the base, so this cannot silently
            // become the old expectation again.
            Assert.Equal(probeSentAt + (InitialPtoPeriod * Math.Pow(2, expiry)), armed);
            Assert.NotEqual(start + (InitialPtoPeriod * Math.Pow(2, expiry)), armed);
            previous = armed;
        }
    }

    // ========================================================================
    // ONE THREAD OF CONTROL: A DATAGRAM AND AN EXPIRED TIMER IN THE SAME PUMP.
    // ========================================================================

    // ONE SEND PASS PER PUMP, WHICHEVER ARM RESOLVES IT, AND THE ARM THAT RESOLVES IT WAS
    // MEASURED RATHER THAN ASSUMED. When the token is ALREADY cancelled and a datagram is
    // ALREADY queued, InMemoryDatagramTransport.ReceiveAsync throws rather than serving the
    // queued datagram - a channel read observes the cancellation first. So the timer arm wins,
    // and the first version of this test deadlocked its own last line by expecting the server
    // to have something to read. THAT DEADLOCK IS THE FINDING AND IT IS PINNED HERE RATHER THAN
    // ARGUED AWAY: a pump that wakes on a probe timeout does not consume the datagram waiting
    // behind it, and the datagram is NOT lost - the very next pump reads it.
    //
    // THE PRIMARY EVIDENCE FOR "NOT TWO CONCURRENT PASSES" IS STRUCTURAL AND IS IN THE CODE,
    // NOT HERE: the CancellationTokenSource is created inside ReceiveWithinDeadlineAsync,
    // disposed by its own using before that method returns, and never given a callback - so no
    // timer can touch connection state while PumpOnceAsync walks a datagram, and there is
    // nothing for a second send pass to be scheduled from. THIS TEST IS THE GUARD AGAINST AN
    // EDIT THAT ADDS ONE, which is exactly the change a plausible A3-6 or A3-7 might reach for:
    // it counts datagrams out of the client per pump, and two passes in one pump would be two.
    [Fact]
    public async Task ADatagramAndAnExpiredProbeTimeoutInOnePumpProduceOneSendPass()
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

        // THE SERVER'S FLIGHT IS NOW SITTING IN THE CLIENT'S INBOUND QUEUE AND THE PROBE TIMEOUT
        // IS NOW IN THE PAST. One pump, two things eligible to end its receive.
        var armed = connection.LossDetectionTimer!.Value;
        impaired.Clock.Advance(
            armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));

        var sentBefore = impaired.Delivered.Count;
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // THE TIMER ARM RAN, EXACTLY ONCE, AND WHAT WENT OUT WAS THE PROBE AND ONLY THE PROBE.
        // A.9 twice, or two send passes, would both show up in one of these numbers - which is
        // the whole point of counting them per pump rather than at the end. BEFORE A3-7 THE
        // SECOND NUMBER WAS ZERO; it is knob 10's now, and the third line is what keeps this a
        // count of probes rather than a count of whatever happened to leave.
        var probes = Spec().Recovery.ProbePacketsPerPto;
        Assert.Equal(1, connection.LossDetectionTimeouts);
        Assert.Equal(probes, impaired.Delivered.Count - sentBefore);
        Assert.Equal(probes, connection.ProbeDatagramsSent);

        // AND THE DATAGRAM IS STILL THERE. A probe timeout that consumed the peer's flight would
        // be a loss this connection caused itself, which is the failure mode worth a name: the
        // next pump reads it and answers it, once - and sends no second probe, which is what
        // the unchanged ProbeDatagramsSent below says.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(probes + 1, impaired.Delivered.Count - sentBefore);
        Assert.Equal(1, connection.LossDetectionTimeouts);
        Assert.Equal(probes, connection.ProbeDatagramsSent);

        // THE CONNECTION IS STILL COHERENT AFTERWARDS, which is the assertion that would fail on
        // torn state rather than on a doubled count: the exchange can be driven on.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
    }

    // ========================================================================
    // A.8's ARMING LADDER, ACROSS THE THREE PACKET NUMBER SPACES.
    // ========================================================================

    // RFC 9002 s6.2.1: "When ack-eliciting packets in multiple packet number spaces are in
    // flight, the timer MUST be set to the EARLIER value of the Initial and Handshake packet
    // number spaces." A.8 gets that from a minimum over the spaces rather than from a rule of
    // its own, so the test that says the minimum is really taken is the one that swaps which
    // space holds it - a mutant that always returns Initial passes the first row and fails the
    // second, and one that always returns Handshake does the reverse.
    [Theory]
    [InlineData(0, 500, TlsQuicEncryptionLevel.Initial)]
    [InlineData(500, 0, TlsQuicEncryptionLevel.Handshake)]
    public async Task TheTimerTakesTheEarlierOfTheInitialAndHandshakeSpaces(
        int initialOffsetMilliseconds,
        int handshakeOffsetMilliseconds,
        TlsQuicEncryptionLevel expected)
    {
        var clock = FakeClock();
        await using var connection = IdleOn(clock);

        var start = clock.GetUtcNow();
        var initialAt = start + TimeSpan.FromMilliseconds(initialOffsetMilliseconds);
        var handshakeAt = start + TimeSpan.FromMilliseconds(handshakeOffsetMilliseconds);

        connection.OnPacketSent(
            new TlsQuicSentPacket(
                TlsQuicEncryptionLevel.Initial, 0, 1200, true, true, initialAt));
        connection.OnPacketSent(
            new TlsQuicSentPacket(
                TlsQuicEncryptionLevel.Handshake, 0, 1200, true, true, handshakeAt));

        var earlier = initialAt < handshakeAt ? initialAt : handshakeAt;
        Assert.Equal(expected, connection.LossDetectionSpace);
        Assert.Equal(earlier + InitialPtoPeriod, connection.LossDetectionTimer);
    }

    // RFC 9002 s6.2.1's MUST NOT, and THE FIRST OF THE TWO PLACES A.8's PSEUDOCODE AND ITS OWN
    // PROSE DISAGREE. A.8's GetPtoTimeAndSpace returns while still holding `pto_timeout =
    // infinite` when Application Data is the only space with anything in flight and the
    // handshake is not confirmed, and SetLossDetectionTimer then calls
    // `loss_detection_timer.update(timeout)` on that infinity. The prose says the opposite -
    // "An endpoint MUST NOT set its PTO timer for the Application Data packet number space
    // until the handshake is confirmed" - and a timer set to infinity is set. THE PROSE IS
    // FOLLOWED.
    //
    // BOTH CANDIDATE VALUES ARE ASSERTED, not merely one. DateTimeOffset.MaxValue is what a
    // literal transcription would arm, and it is also what would throw the moment
    // ReceiveWithinDeadlineAsync subtracted now from it, so a mutant that arms it is caught
    // here by a name rather than downstream by an ArgumentOutOfRangeException in an unrelated
    // test.
    [Fact]
    public async Task AnApplicationDataOnlyFlightBeforeConfirmationLeavesTheTimerUnarmed()
    {
        var clock = FakeClock();
        await using var connection = IdleOn(clock);

        connection.OnPacketSent(
            new TlsQuicSentPacket(
                TlsQuicEncryptionLevel.Application, 0, 1200, true, true, clock.GetUtcNow()));

        Assert.Null(connection.LossDetectionTimer);
        Assert.NotEqual(DateTimeOffset.MaxValue, connection.LossDetectionTimer);
        Assert.Null(connection.LossDetectionSpace);
    }

    // RFC 9002 s6.2.2.1's client MUST, and the clause in it that is easy to read past: "the
    // client MUST set the PTO timer if the client has not received an acknowledgment for any of
    // its Handshake packets and the handshake is not confirmed ... EVEN IF THERE ARE NO PACKETS
    // IN FLIGHT." A.8 encodes it as the AND in rung 3 and as the anti-deadlock arm of
    // GetPtoTimeAndSpace, whose own comment says "Anti-deadlock PTO starts from the current
    // time" - which is why the expected instant below is measured from NOW and not from the
    // packet's send time, unlike every other test in this file.
    //
    // TWO SHAPES REACH IT AND THEY ARE HERE AS TWO ROWS BECAUSE THE CONDITION IS A CONJUNCTION.
    // An ACK-only packet is neither ack-eliciting nor in flight (RFC 9002 A.4 keeps it out of
    // bytes_in_flight, RFC 9000 s13.2.4 makes it elicit nothing); a PADDING-only packet IS in
    // flight and still elicits nothing (s13.2.7). Both leave "no ack-eliciting packets in
    // flight" true, and a mutant that answered A.8's question with bytes_in_flight instead - or
    // that read the two booleans with an OR - passes the first row and fails the second.
    [Theory]
    [InlineData(false)]   // ACK-only: not in flight either.
    [InlineData(true)]    // PADDING-only: in flight, eliciting nothing.
    public async Task AClientWithNothingInFlightStillArmsThePtoFromTheCurrentTime(bool inFlight)
    {
        var clock = FakeClock();
        await using var connection = IdleOn(clock);

        var sentAt = clock.GetUtcNow() - TimeSpan.FromSeconds(30);
        connection.OnPacketSent(
            new TlsQuicSentPacket(
                TlsQuicEncryptionLevel.Application, 0, 40, false, inFlight, sentAt));

        // FROM NOW, NOT FROM THE SEND. The thirty-second gap is what tells the two apart: an
        // implementation that measured from the send instant would arm thirty seconds in the
        // past, which is the second value asserted.
        Assert.Equal(clock.GetUtcNow() + InitialPtoPeriod, connection.LossDetectionTimer);
        Assert.NotEqual(sentAt + InitialPtoPeriod, connection.LossDetectionTimer);

        // NO HANDSHAKE KEYS ON AN UNSTARTED CONNECTION, so A.9's "otherwise it MUST send an
        // Initial packet" is the arm named.
        Assert.Equal(TlsQuicEncryptionLevel.Initial, connection.LossDetectionSpace);
    }

    // ========================================================================
    // s6.2.1's kGranularity FLOOR, WHICH IS THE SECOND PROSE-BEATS-PSEUDOCODE CALL.
    // ========================================================================

    // s6.2.1: "The PTO period MUST be at least kGranularity to avoid the timer expiring
    // immediately." A.8 has no clamp for it and does not need one - its own expression already
    // dominates kGranularity. IT IS NEEDED HERE because A3-2 added a knob RFC 9002 does not
    // have: TlsQuicRecoverySpec.PtoBackoff's ceiling, whose own remarks call it "an
    // implementation choice a caller may take". A ceiling of one tick produces exactly the
    // immediately-expiring timer the MUST forbids.
    //
    // THREE VALUES PER ROW, AND THE SECOND ROW IS WHAT STOPS THE FLOOR FROM BEING AN EXCUSE FOR
    // IGNORING THE CEILING ALTOGETHER: a five-millisecond ceiling is honoured exactly, so the
    // clamp is a floor and not a bypass. Row one asserts kGranularity AND asserts it is not the
    // one tick that was asked for, which are the two candidate answers to the disagreement.
    [Theory]
    [InlineData(1L, 10_000L)]        // one tick asked for; kGranularity's 10 000 ticks armed.
    [InlineData(50_000L, 50_000L)]   // five milliseconds asked for and honoured exactly.
    public async Task ThePtoBackoffCeilingIsHonouredButNeverBelowTheTimerGranularity(
        long ceilingTicks, long expectedTicks)
    {
        var clock = FakeClock();
        await using var connection = IdleOn(
            clock,
            new TlsQuicConnectionSpec
            {
                Recovery = new TlsQuicRecoverySpec
                {
                    PtoBackoff = (
                        TlsQuicRecoverySpec.DefaultPtoBackoffFactor,
                        TimeSpan.FromTicks(ceilingTicks)),
                },
            });

        var sentAt = clock.GetUtcNow();
        connection.OnPacketSent(
            new TlsQuicSentPacket(TlsQuicEncryptionLevel.Initial, 0, 1200, true, true, sentAt));

        Assert.Equal(sentAt + TimeSpan.FromTicks(expectedTicks), connection.LossDetectionTimer);

        // AND NOT THE UNCAPPED PERIOD, which is the mutant that drops the ceiling entirely
        // rather than the one that honours it too literally.
        Assert.NotEqual(sentAt + InitialPtoPeriod, connection.LossDetectionTimer);
    }

    // The half of the row above that an equality alone cannot state: the pseudocode's answer
    // for a one-tick ceiling is one tick, and it is named here so the choice between the two
    // candidate numbers is written down rather than implied by which one happens to pass.
    [Fact]
    public async Task AOneTickPtoCeilingArmsAtTheGranularityAndNotAtOneTick()
    {
        var clock = FakeClock();
        await using var connection = IdleOn(
            clock,
            new TlsQuicConnectionSpec
            {
                Recovery = new TlsQuicRecoverySpec
                {
                    PtoBackoff =
                        (TlsQuicRecoverySpec.DefaultPtoBackoffFactor, TimeSpan.FromTicks(1)),
                },
            });

        var sentAt = clock.GetUtcNow();
        connection.OnPacketSent(
            new TlsQuicSentPacket(TlsQuicEncryptionLevel.Initial, 0, 1200, true, true, sentAt));

        Assert.Equal(sentAt + TlsQuicConnection.KGranularity, connection.LossDetectionTimer);
        Assert.NotEqual(sentAt + TimeSpan.FromTicks(1), connection.LossDetectionTimer);
    }

    // ========================================================================
    // THE TWO SEAMS A3-4 LEFT FOR THIS TASK TO WIRE.
    // ========================================================================

    // RFC 9000 s18.2's max_ack_delay (0x0b) was parsed and discarded by this connection until
    // A3-5; TlsQuicAckTracker.OnPeerAckParameters says so in its own remarks and names this
    // task as the one that owes the wiring. s6.2.1 is what needs it: the PTO period carries a
    // max_ack_delay term "to account for the maximum time by which a receiver might delay
    // sending an acknowledgment", and the same paragraph zeroes it for Initial and Handshake
    // "since the peer is expected to not delay these packets intentionally".
    //
    // A DIFFERENCE RATHER THAN TWO ABSOLUTE INSTANTS, because after a real handshake
    // smoothed_rtt is A3-4's business and not this test's. The difference between the two
    // spaces' periods is max_ack_delay and nothing else, whatever the estimator has decided.
    //
    // AND THE VALUE IS THE ABSENT-VALUE DEFAULT, WHICH IS THE POINT RATHER THAN A SHORTCUT. The
    // captured s6.2 extract opens with it: "Chromium sends no max_ack_delay transport parameter,
    // so RFC 9000 s18.2's default applies and reading the term as zero would compute a PTO
    // shorter than the peer's." This test's server advertises none either, so zero and 25 ms
    // are the two candidate answers and both are asserted.
    [Fact]
    public async Task ThePeersMaxAckDelayIsAddedForApplicationDataAndNotForHandshake()
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

        await RunToOneRttAsync(connection, serverPeer, cancellation.Token);
        Assert.True(connection.IsHandshakeConfirmed);

        var sentAt = impaired.Clock.GetUtcNow();
        connection.OnPacketSent(
            new TlsQuicSentPacket(
                TlsQuicEncryptionLevel.Application, 7, 1200, true, true, sentAt));
        var application = connection.LossDetectionTimer!.Value;
        Assert.Equal(TlsQuicEncryptionLevel.Application, connection.LossDetectionSpace);

        // THE SAME INSTANT IN THE HANDSHAKE SPACE, which is therefore the earlier of the two and
        // becomes the armed one.
        connection.OnPacketSent(
            new TlsQuicSentPacket(
                TlsQuicEncryptionLevel.Handshake, 7, 1200, true, true, sentAt));
        var handshake = connection.LossDetectionTimer!.Value;
        Assert.Equal(TlsQuicEncryptionLevel.Handshake, connection.LossDetectionSpace);

        Assert.Equal(TlsQuicAckTracker.DefaultMaxAckDelay, application - handshake);
        Assert.NotEqual(TimeSpan.Zero, application - handshake);
    }

    // RFC 9002 A.8's PeerCompletedAddressValidation, the client arm: "return has received
    // Handshake ACK || handshake confirmed". Once it holds and nothing ack-eliciting is in
    // flight, A.8's rung 3 cancels: "There is nothing to detect lost, so no timer is set."
    //
    // THE LOOPBACK HALF OF THIS FILE, and what it adds over the direct half is that the
    // condition is reached by a REAL handshake rather than by a property this test set. The
    // 1-RTT ACK the client owes for HANDSHAKE_DONE is ACK-only, so it leaves nothing in flight,
    // and the timer must therefore be cancelled rather than merely pushed out.
    [Fact]
    public async Task AConfirmedHandshakeWithNothingInFlightCancelsTheTimer()
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

        // RunToOneRttAsync's own sequence, opened out rather than called, because the timer has
        // to be read WHILE the handshake is still in flight - which is what makes the null at
        // the end a change of state rather than a timer that was never set at all.
        await connection.StartAsync(cancellation.Token);
        Assert.NotNull(connection.LossDetectionTimer);

        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        Assert.True(connection.IsHandshakeConfirmed);
        Assert.Equal(0, connection.BytesInFlight);
        Assert.Null(connection.LossDetectionTimer);
        Assert.Null(connection.LossDetectionSpace);
    }

    // ========================================================================
    // THE FLOOR, WHICH IS THE ONE PLACE THIS IMPLEMENTATION LEAVES A.8's LETTER.
    // ========================================================================

    // A.8: "This algorithm may result in the timer being set in the past, particularly if timers
    // wake up late. Timers set in the past fire immediately." On a wall clock that is
    // self-limiting. On an INJECTED clock a test can hold still, and then a timer computed from
    // a fixed send instant is in the past for ever - the pump wakes, sends nothing, re-arms at
    // the same instant and wakes again. SetLossDetectionTimer floors every armed instant at
    // kGranularity in the future so that cannot happen, and this is the witness for the floor
    // itself rather than for its consequence.
    //
    // THIRTY SECONDS IN THE PAST IS WHAT MAKES THE TWO ANSWERS FAR APART: A.8's literal answer
    // is an instant twenty-nine seconds before now, and this implementation's is one
    // millisecond after it. Both are asserted.
    [Fact]
    public async Task ATimerComputedInThePastIsArmedAtTheGranularityInsteadOfImmediately()
    {
        var clock = FakeClock();
        await using var connection = IdleOn(clock);

        var sentAt = clock.GetUtcNow() - TimeSpan.FromSeconds(30);
        connection.OnPacketSent(
            new TlsQuicSentPacket(TlsQuicEncryptionLevel.Initial, 0, 1200, true, true, sentAt));

        Assert.Equal(
            clock.GetUtcNow() + TlsQuicConnection.KGranularity, connection.LossDetectionTimer);
        Assert.NotEqual(sentAt + InitialPtoPeriod, connection.LossDetectionTimer);
        Assert.True(connection.LossDetectionTimer > clock.GetUtcNow());
    }

    // RFC 9002 A.3's time_of_last_ack_eliciting_packet[pn_space] is the LAST one, and this
    // implementation derives it from the retained list rather than holding a field. A derivation
    // that took the first retained packet instead of the latest would be invisible on every
    // other test in this file, because each of those puts exactly one packet in each space.
    //
    // THE ANSWER FLIPS BETWEEN SPACES, WHICH IS WHY THE ASSERTION IS A SPACE AND NOT ONLY AN
    // INSTANT: with the LATEST Initial send at 800 ms the Handshake space at 500 ms is the
    // earlier of the two, and with the FIRST Initial send at 0 ms it would be Initial.
    [Fact]
    public async Task TheTimerMeasuresFromTheLatestAckElicitingSendInASpace()
    {
        var clock = FakeClock();
        await using var connection = IdleOn(clock);

        var start = clock.GetUtcNow();
        connection.OnPacketSent(
            new TlsQuicSentPacket(TlsQuicEncryptionLevel.Initial, 0, 1200, true, true, start));
        connection.OnPacketSent(
            new TlsQuicSentPacket(
                TlsQuicEncryptionLevel.Handshake,
                0,
                1200,
                true,
                true,
                start + TimeSpan.FromMilliseconds(500)));
        connection.OnPacketSent(
            new TlsQuicSentPacket(
                TlsQuicEncryptionLevel.Initial,
                1,
                1200,
                true,
                true,
                start + TimeSpan.FromMilliseconds(800)));

        Assert.Equal(TlsQuicEncryptionLevel.Handshake, connection.LossDetectionSpace);
        Assert.Equal(
            start + TimeSpan.FromMilliseconds(500) + InitialPtoPeriod,
            connection.LossDetectionTimer);
        Assert.NotEqual(start + InitialPtoPeriod, connection.LossDetectionTimer);
    }

    // RFC 9002 s6.2.1's exception, which is the half of the backoff reset that is easy to drop:
    // "The PTO backoff factor is reset when an acknowledgment is received, EXCEPT in the
    // following case ... a client does not reset the PTO backoff factor on receiving
    // acknowledgments in Initial packets." A.7 states the same rule as a predicate rather than
    // as a level - "if (PeerCompletedAddressValidation()): pto_count = 0" - and this
    // connection follows A.7's form, so the test drives the state the predicate reads.
    //
    // A REAL EXPIRY FIRST, so that the number being protected is non-zero. A test that
    // acknowledged something while pto_count was already zero would pass against a connection
    // that reset unconditionally, which is the mutant this exists to catch.
    [Fact]
    public async Task AnAcknowledgementInAnInitialPacketDoesNotResetThePtoBackoff()
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
        transport.Clock.Advance(InitialPtoPeriod + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.PtoCount);

        // AN ACK THAT REALLY RETIRES SOMETHING: packet 0 of the Initial flight StartAsync sent.
        // Without that the newly-acked guard would be what kept the count, and the rule under
        // test would be untouched.
        Assert.NotEmpty(connection.SentPackets(TlsQuicEncryptionLevel.Initial));
        connection.OnAckReceived(
            TlsQuicEncryptionLevel.Initial, AckFrame(new TlsQuicAckRange(0, 0)));

        // PACKET 0 IS GONE AND THE PROBES ARE NOT, which is what A3-7 changed here: the expiry
        // above put knob 10's worth of Initial probe packets on the wire, so this space is no
        // longer emptied by retiring the one packet StartAsync sent. The probes are ABOVE the
        // largest acknowledged, so A.10 skips them rather than declaring them lost.
        Assert.DoesNotContain(
            connection.SentPackets(TlsQuicEncryptionLevel.Initial), p => p.PacketNumber == 0);
        Assert.Equal(
            Spec().Recovery.ProbePacketsPerPto,
            connection.SentPackets(TlsQuicEncryptionLevel.Initial).Count);
        Assert.Equal(0, connection.PacketsDeclaredLost);

        // ONE AND NOT ZERO. Zero is what an unconditional reset produces and is the other
        // candidate answer to this rule.
        Assert.Equal(1, connection.PtoCount);
        Assert.NotEqual(0, connection.PtoCount);
    }

    // ========================================================================
    // THE FIFTH ENTRY - RFC 9000 s13.2.1's max_ack_delay - A3-13.
    // ========================================================================

    // WITHOUT THIS ENTRY KNOB 12's SECOND VALUE WOULD BE A VIOLATION WEARING THE NAME OF THE
    // RULE IT BREAKS, and that is what this test is for rather than "the ACK eventually goes
    // out". TlsQuicAckTracker withholds the acknowledgement; nothing but EarliestDeadline's
    // fifth entry brings it back out when the peer sends nothing else. s13.2.1 prices the
    // difference exactly - "an endpoint promises to never intentionally delay acknowledgments
    // of an ack-eliciting packet by more than the indicated value. If it does, any excess
    // accrues to the RTT estimate and could result in spurious or delayed retransmissions from
    // the peer" - so a delay bounded by the peer's next datagram is the defect and a delay
    // bounded by a timer is the feature.
    //
    // HANDSHAKE_DONE IS THE ACK-ELICITING 1-RTT PACKET, which is why this does not use the
    // shared ConfirmedHandshake helper: that helper asserts the pump answering HANDSHAKE_DONE
    // SENDS - true for every other test in the suite, and false here by design. The sequence is
    // inlined so the one assertion that differs is visible rather than buried in scaffolding,
    // and the difference IS the wiring.
    [Fact]
    public async Task AHeldAcknowledgementWakesThePumpAtMaxAckDelayWithoutRunningTheTimeout()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var spec = new TlsQuicConnectionSpec
        {
            SourceConnectionIdLength = SourceConnectionIdLength,
            Recovery = new TlsQuicRecoverySpec
            {
                AckPolicy = TlsQuicAckPolicy.DelayedToMaxAckDelay,
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
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);

        var sentBefore = clientTransport.Sent.Count;
        var timeouts = connection.LossDetectionTimeouts;
        var serverPeerLargestBefore = serverPeer.LargestApplicationPacketNumberReceived;

        // THE PUMP PROCESSED AN ACK-ELICITING 1-RTT PACKET AND SENT NOTHING, which is the
        // knob biting end to end through a real handshake rather than through the tracker
        // alone. Under the shipped default this same pass puts exactly one datagram on the
        // wire - see ConfirmedHandshake, whose trailing serverPeer pump exists to drain it.
        //
        // THE COUNT IS THE ASSERTION AND THE BOOL IS NOT. PumpOnceAsync returns whether the
        // handshake is now CONFIRMED, not whether a datagram left; the two coincide for most
        // of this file and come apart here, so the send is counted on the transport where it
        // can actually be seen.
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.True(connection.IsHandshakeConfirmed);
        Assert.Equal(sentBefore, clientTransport.Sent.Count);

        // AND THE DEBT IS RECORDED WITH ITS DUE INSTANT, so the wake is armed rather than the
        // acknowledgement merely dropped. The two are indistinguishable from the line above.
        var due = Assert.IsType<DateTimeOffset>(connection.Acks.DelayedAckDeadline);
        Assert.Equal(
            impaired.Clock.GetUtcNow() + TlsQuicAckTracker.DefaultMaxAckDelay, due);

        // AND IT IS THE ONLY NON-ABANDONMENT ENTRY IN THE TABLE, which is what makes the wake
        // below attributable to THIS entry rather than merely coincident with it. A3-11's own
        // deadline test names the same thing by showing its release is nearer than A.8's timer;
        // here there is no A.8 timer to be nearer than. Everything this client sent has been
        // acknowledged, so A.8 armed nothing and the pacer holds nothing - and the two
        // remaining entries are abandonments, which RAISE rather than send. A datagram leaving
        // at `due` therefore cannot have come from any other row.
        Assert.Null(connection.LossDetectionTimer);
        Assert.Null(connection.PacingReleaseAt);

        impaired.Clock.Advance(due - impaired.Clock.GetUtcNow());

        // THE WAKE, WITH NOTHING TO RECEIVE. Nothing is in flight toward this client; only the
        // deadline can end this receive, and the ordinary send pass it returns to is what emits
        // the ACK. The bool is discarded for the reason given above - it answers a different
        // question - and the datagram count answers this one.
        _ = await connection.PumpOnceAsync(cancellation.Token);
        Assert.Equal(sentBefore + 1, clientTransport.Sent.Count);
        Assert.Null(connection.Acks.DelayedAckDeadline);

        // AND A.9 DID NOT RUN. TlsQuicDeadlineKind.DelayedAck is Pacing's kind and not
        // Recovery's; a build that reused the recovery branch would put a probe on the wire and
        // advance pto_count for a timer that never expired.
        Assert.Equal(timeouts, connection.LossDetectionTimeouts);

        // AND IT REACHED THE PEER AS AN OPENABLE 1-RTT PACKET THAT DREW NO ANSWER, which is
        // the shape of an ACK-only packet and of nothing else this connection sends. The peer
        // had opened no 1-RTT packet at all before this pass - every datagram this client sent
        // during the handshake was Initial or Handshake - so the number below going from absent
        // to present is the held acknowledgement arriving, and the False is s13.2.1's "An
        // endpoint MUST NOT send a non-ack-eliciting packet in response to a non-ack-eliciting
        // packet" holding at the other end.
        Assert.Null(serverPeerLargestBefore);
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.NotNull(serverPeer.LargestApplicationPacketNumberReceived);
    }

    private static ManualTimeProvider FakeClock() =>
        new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

    // A connection with no TLS client and a clock a test can move, for the arithmetic half.
    // A3-3's Idle() is the same idea on TimeProvider.System, which is exactly what a timer test
    // cannot use: every instant below would then be measured against a clock that moves under
    // the assertion.
    private static TlsQuicConnection IdleOn(
        ManualTimeProvider clock, TlsQuicConnectionSpec? spec = null)
    {
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        return new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                clientTransport, serverTransport.LocalEndPoint, spec ?? Spec(), clock),
            _ => throw new InvalidOperationException(
                "An idle connection builds no TLS client; this test must not call StartAsync."));
    }
}
