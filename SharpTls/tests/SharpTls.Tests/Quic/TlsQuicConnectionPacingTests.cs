using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task A3-11 of the loss recovery phase: RFC 9002 s7.7's PACER, and the s7 send gate A3-8
// handed over. Two jobs in one file because they are one decision at one line - see
// TlsQuicApplicationSendPath's SendGateAdmits, which answers "may this leave" and "may it leave
// NOW" in that order.
//
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's, 14c's, A3-1's, A3-3's, A3-5's, A3-6's, A3-7's AND
// A3-8's, for the reason those files give: Spec, Connection, TlsClient, Server, Credential,
// ConfirmedHandshake and FakeClock are reused rather than copied.
//
// ============================================================================
// WHAT A PASSING TRANSFER DOES NOT PROVE, WHICH IS WHY EVERY LIVE TEST HERE COUNTS SOMETHING.
// ============================================================================
//
// A3-8 recorded the trap in its own words: its first loss test "completed in 220 ms with
// nothing lost and passed; only asserting PacketsDeclaredLost > 0 caught it". The pacing
// analogue is worse, because a pacer that never engages is INVISIBLE - the transfer completes,
// the bytes are right, the order is right, and the only difference is timing nobody measured.
// So every test below that drives a live connection asserts one of
// SendsRefusedByCongestionWindow, SendsDeferredByPacer or RecoveryWindowExemptionsUsed moved,
// and the byte-identity test asserts the paced run deferred at all before it compares anything.
//
// ============================================================================
// AND THE TWO WAYS THIS TASK COULD WEDGE A CONNECTION, EACH WITH ITS OWN TEST.
// ============================================================================
//
//   A WINDOW THAT NEVER OPENS. Closed for ever, the gate would hold every byte for ever - but
//   RFC 9002 s7.5's probe is exempt, so the connection keeps asking and the answers are what
//   reopen the window. AProbeLeavesThroughAWindowThatIsClosedToEverythingElse is the witness,
//   and AnAckOnlyAnswerStillLeavesThroughAClosedWindow is the second limb: the peer's own
//   window keeps moving because acknowledgements are never gated.
//
//   A PACER THAT NEVER RELEASES. Bounded three ways, and each is asserted rather than argued:
//   the release instant is strictly in the future and never more than one smoothed RTT away
//   (ADeferredReleaseIsAlwaysInTheFutureAndNeverBeyondOneSmoothedRtt), it joins
//   EarliestDeadline's table so the pump wakes for it with no datagram received
//   (APacingReleaseWakesThePumpWithoutRunningTheLossDetectionTimeout), and it can never mask an
//   abandonment (AnAbandonmentDeadlineStillEndsAnAttemptWithPacedDataHeld).
public sealed partial class TlsQuicConnectionTests
{
    // A smoothed RTT and a congestion window that make s7.7's arithmetic exact rather than
    // approximate: 1.25 * 12000 / 0.1 s = 150000 bytes per second, and 150000 * 0.008 s = 1200
    // bytes. Every number below is recomputed from these two rather than typed.
    private static readonly TimeSpan PacerRtt = TimeSpan.FromMilliseconds(100);

    private const long PacerWindow = 12000;

    private const int PacerDatagram = 1200;

    // ========================================================================
    // THE PACER, AS ARITHMETIC. s7.7 HAS NO PSEUDOCODE, SO THESE RECOMPUTE THE PROSE.
    // ========================================================================

    // KNOB 14's OFF POSITION, AND IT IS THE ONE THE WHOLE TASK TURNS ON. The user's standing
    // directive makes pacing a settable knob rather than a behaviour, because whether a client
    // paces at all is visible in a pcap and differs between browsers. Off must mean OFF: no
    // clock read, no credit, no deferral, no deadline entry.
    [Fact]
    public void APacerWithNoBurstIsOffAndAdmitsEverythingWithoutDeferringOnce()
    {
        var pacer = new TlsQuicPacer(
            new TlsQuicRecoverySpec { PacingBurstDatagrams = null }, PacerDatagram);

        Assert.False(pacer.IsEnabled);
        Assert.Equal(0, pacer.CapacityBytes);
        Assert.Equal(0, pacer.BurstDatagrams);

        var now = FakeClock().GetUtcNow();
        for (var i = 0; i < 1000; i++)
        {
            Assert.True(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));
        }

        // NOT MERELY "IT ADMITTED". A pacer that admitted everything but still armed a release
        // would put an entry in EarliestDeadline's table and change when a pump wakes, which is
        // an observable difference from a build with no pacer in it.
        Assert.Equal(0, pacer.Deferrals);
        Assert.Null(pacer.ReleaseAt);
    }

    // THE BUCKET, s7.7 lines 378-381: "the capacity of the bucket is limited to the maximum
    // burst size". Ten datagrams of burst is ten datagrams of credit and not eleven, and the
    // eleventh is the first one held.
    [Fact]
    public void TheBucketStartsAtTheSpecsBurstAndTheFirstSendPastItIsHeld()
    {
        var now = FakeClock().GetUtcNow();
        var spec = new TlsQuicRecoverySpec { PacingBurstDatagrams = 10 };
        var pacer = new TlsQuicPacer(spec, PacerDatagram);

        Assert.True(pacer.IsEnabled);
        Assert.Equal(10 * PacerDatagram, pacer.CapacityBytes);
        Assert.Equal(10, pacer.BurstDatagrams);
        Assert.Equal(10 * PacerDatagram, pacer.CreditBytes);

        for (var i = 0; i < 10; i++)
        {
            Assert.True(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));
            Assert.Equal((10 - i - 1) * PacerDatagram, pacer.CreditBytes);
        }

        Assert.False(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));
        Assert.Equal(1, pacer.Deferrals);

        // THE CREDIT IS NOT SPENT BY A REFUSAL, which is what lets the send path ask and then
        // not send without silently consuming an allowance.
        Assert.Equal(0, pacer.CreditBytes);
    }

    // s7.7 line 361, RECOMPUTED RATHER THAN COMPARED TO A LITERAL: rate = N * congestion_window
    // / smoothed_rtt, so the credit that accrues over an interval is that rate times the
    // interval. THE UNITS ARE THE POINT - a version of this that mixed ticks and seconds would
    // be wrong by ten million and would still pace.
    [Fact]
    public void TheRefillIsSectionSevenSevensRateTimesTheElapsedTime()
    {
        var clock = FakeClock();
        var spec = new TlsQuicRecoverySpec { PacingBurstDatagrams = 10 };
        var pacer = new TlsQuicPacer(spec, PacerDatagram);

        // Drain the bucket first, so what is measured below is refill and not the initial fill.
        for (var i = 0; i < 10; i++)
        {
            Assert.True(
                pacer.TryTake(PacerDatagram, clock.GetUtcNow(), PacerWindow, PacerRtt));
        }

        Assert.Equal(0, pacer.CreditBytes);

        var elapsed = TimeSpan.FromMilliseconds(20);
        clock.Advance(elapsed);

        var rate = spec.PacingIntervalScale * PacerWindow / PacerRtt.TotalSeconds;
        var expected = (long)(rate * elapsed.TotalSeconds);

        // The take is what refills, so it is asked for a single byte and the credit is read
        // back with that byte's spend added again.
        Assert.True(pacer.TryTake(1, clock.GetUtcNow(), PacerWindow, PacerRtt));
        Assert.Equal(expected, pacer.CreditBytes + 1);

        // AND NOT THE OTHER CANDIDATE ANSWER. A pacer that ignored N would accrue
        // PacerWindow * elapsed / rtt, which this names as wrong rather than leaving to an
        // inequality any value would satisfy.
        Assert.NotEqual((long)(PacerWindow * elapsed.TotalSeconds / PacerRtt.TotalSeconds),
            pacer.CreditBytes + 1);
    }

    // KNOB 14, TWO SPECS, TWO BEHAVIOURS - the plan's done-when in one test. The burst is read
    // off the spec and nothing else, so a build that hard-coded the RFC's ten would pass every
    // other test in this file and fail this one.
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(7)]
    public void TheBurstIsTheSpecsAndTheHoldHappensExactlyThere(int burst)
    {
        var now = FakeClock().GetUtcNow();
        var pacer = new TlsQuicPacer(
            new TlsQuicRecoverySpec { PacingBurstDatagrams = burst }, PacerDatagram);

        for (var i = 0; i < burst; i++)
        {
            Assert.True(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));
        }

        Assert.False(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));
        Assert.Equal(burst, pacer.BurstDatagrams);
    }

    // KNOB 15, TWO SPECS, TWO SPACINGS. The burst and the data are identical in both rows; only
    // s7.7's N differs, and the gap between one datagram and the next moves with it - which is
    // the whole reason the scale needed a member of its own. Doubling N halves the wait.
    [Fact]
    public void TheIntervalScaleIsTheSpecsAndTwoScalesSpaceTheSameDataDifferently()
    {
        var now = FakeClock().GetUtcNow();

        var slow = HeldAt(1.25, now);
        var fast = HeldAt(2.5, now);

        // RECOMPUTED, BOTH: wait = deficit / (N * cwnd / rtt), with a deficit of one whole
        // datagram because the bucket held exactly one and it was spent.
        Assert.Equal(
            now + TimeSpan.FromSeconds(PacerDatagram / (1.25 * PacerWindow / PacerRtt.TotalSeconds)),
            slow);
        Assert.Equal(
            now + TimeSpan.FromSeconds(PacerDatagram / (2.5 * PacerWindow / PacerRtt.TotalSeconds)),
            fast);

        // AND THE DIRECTION, NAMED. A build that divided by N instead of multiplying would give
        // two different answers too, and would give them the wrong way round.
        Assert.True(fast < slow);
    }

    // FACT (iii) OF THE ANTI-WEDGE PROOF, ASSERTED. A pacer that never releases is a hang, so
    // the release instant is bounded above by one smoothed RTT and below by the present instant
    // - for every input, including one asking for more bytes than the bucket can ever hold.
    [Theory]
    [InlineData(1)]
    [InlineData(PacerDatagram)]
    [InlineData(int.MaxValue)]
    public void ADeferredReleaseIsAlwaysInTheFutureAndNeverBeyondOneSmoothedRtt(int bytes)
    {
        var now = FakeClock().GetUtcNow();
        var pacer = new TlsQuicPacer(
            new TlsQuicRecoverySpec { PacingBurstDatagrams = 1 }, PacerDatagram);

        // Empty the bucket, then ask for the row's size against no credit at all.
        Assert.True(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));
        Assert.False(pacer.TryTake(bytes, now, PacerWindow, PacerRtt));

        var release = Assert.IsType<DateTimeOffset>(pacer.ReleaseAt);
        Assert.True(release > now, $"The release {release} is not after {now}.");
        Assert.True(
            release <= now + PacerRtt,
            $"The release {release} is more than one smoothed RTT past {now}.");
    }

    // FACT (ii). Without a positive window and a positive RTT there is no rate s7.7 defines,
    // and "wait until credit accrues" would mean "wait for ever". Both are ADMITTED, and the
    // congestion window is refused separately by s7's own gate.
    [Fact]
    public void NoRateMeansAdmitRatherThanWaitForEver()
    {
        var now = FakeClock().GetUtcNow();
        var pacer = new TlsQuicPacer(
            new TlsQuicRecoverySpec { PacingBurstDatagrams = 1 }, PacerDatagram);

        Assert.True(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));
        Assert.False(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));

        // A closed window, and a connection that has taken no RTT sample.
        Assert.True(pacer.TryTake(PacerDatagram, now, 0, PacerRtt));
        Assert.True(pacer.TryTake(PacerDatagram, now, PacerWindow, TimeSpan.Zero));

        // Admitting clears the deferral, so no stale entry is left in the deadline table.
        Assert.Null(pacer.ReleaseAt);
    }

    // TimeProvider makes no monotonicity promise about GetUtcNow. A negative elapsed times the
    // rate would DRAIN the bucket for a reason that has nothing to do with sending.
    //
    // ONE BYTE AND NOT ZERO, AND THE MUTATION SWEEP IS WHY. The first version of this test asked
    // for ZERO bytes, which TryTake answers before it ever reaches the refill - so the mutation
    // that lets a backwards clock drain the bucket SURVIVED it, and the test was scoring an
    // early return rather than the guard it named. A single byte is the smallest ask that
    // actually refills.
    [Fact]
    public void AClockThatGoesBackwardsNeitherDrainsTheBucketNorThrows()
    {
        var clock = FakeClock();
        var now = clock.GetUtcNow();
        var pacer = new TlsQuicPacer(
            new TlsQuicRecoverySpec { PacingBurstDatagrams = 4 }, PacerDatagram);

        Assert.True(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));
        var credit = pacer.CreditBytes;

        // ADMITTED, AND THE BUCKET IS DOWN BY EXACTLY THE ONE BYTE ASKED FOR. A drained bucket
        // would refuse this outright, so the two assertions catch the mutation twice.
        Assert.True(pacer.TryTake(1, now - TimeSpan.FromHours(1), PacerWindow, PacerRtt));
        Assert.Equal(credit - 1, pacer.CreditBytes);

        // And the zero-byte ask is still answered, which is what the first version of this test
        // was accidentally about.
        Assert.True(pacer.TryTake(0, now - TimeSpan.FromHours(1), PacerWindow, PacerRtt));
    }

    // s7.7 lines 378-381 bound the bucket: "the capacity of the bucket is limited to the maximum
    // burst size". WITHOUT THE CAP THE BURST STOPS BEING THE KNOB'S - an idle connection would
    // accumulate credit for as long as it was idle and then emit a burst sized by the silence
    // rather than by the spec, which is a fingerprint no caller asked for and one a pcap sees
    // immediately.
    [Fact]
    public void TheBucketNeverAccumulatesPastTheSpecsBurstHoweverLongItIsIdle()
    {
        var clock = FakeClock();
        var pacer = new TlsQuicPacer(
            new TlsQuicRecoverySpec { PacingBurstDatagrams = 2 }, PacerDatagram);

        Assert.True(
            pacer.TryTake(2 * PacerDatagram, clock.GetUtcNow(), PacerWindow, PacerRtt));
        Assert.Equal(0, pacer.CreditBytes);

        // AN HOUR AT THIS RATE IS FIVE HUNDRED MEGABYTES OF CREDIT if nothing caps it, against
        // a burst of 2400 bytes.
        clock.Advance(TimeSpan.FromHours(1));

        // One byte forces the refill and reads the ceiling back.
        Assert.True(pacer.TryTake(1, clock.GetUtcNow(), PacerWindow, PacerRtt));
        Assert.Equal((2 * PacerDatagram) - 1, pacer.CreditBytes);

        // AND THE BURST THAT FOLLOWS IS THE SPEC'S RATHER THAN THE SILENCE'S: one more datagram
        // fits, two do not.
        Assert.True(pacer.TryTake(PacerDatagram, clock.GetUtcNow(), PacerWindow, PacerRtt));
        Assert.False(
            pacer.TryTake(2 * PacerDatagram, clock.GetUtcNow(), PacerWindow, PacerRtt));
    }

    // A DEFERRAL THAT IS NEVER WITHDRAWN IS A SPIN, NOT A HANG - which is why it needs a test of
    // its own rather than a timeout. TlsQuicConnection.EarliestDeadline reads PacingReleaseAt on
    // every pass, so a release instant left standing after the send it was armed for keeps
    // winning the race: the pump wakes, finds nothing held, sends nothing, and wakes again on
    // the same stale instant for the life of the connection.
    [Fact]
    public void AnAdmittedTakeClearsTheDeferralSoThePumpDoesNotWakeForNothing()
    {
        var clock = FakeClock();
        var pacer = new TlsQuicPacer(
            new TlsQuicRecoverySpec { PacingBurstDatagrams = 1 }, PacerDatagram);

        Assert.True(pacer.TryTake(PacerDatagram, clock.GetUtcNow(), PacerWindow, PacerRtt));
        Assert.False(pacer.TryTake(PacerDatagram, clock.GetUtcNow(), PacerWindow, PacerRtt));

        var release = Assert.IsType<DateTimeOffset>(pacer.ReleaseAt);
        clock.Advance(release - clock.GetUtcNow());

        Assert.True(pacer.TryTake(PacerDatagram, clock.GetUtcNow(), PacerWindow, PacerRtt));
        Assert.Null(pacer.ReleaseAt);
    }

    // THE ONE-TICK FLOOR, AND THE FAILURE IT PREVENTS IS A SPIN RATHER THAN A STALL. At a rate
    // high enough that s7.7's own arithmetic gives a wait below one tick, TimeSpan.FromSeconds
    // rounds it to zero and the release instant becomes an instant the pump has ALREADY passed -
    // so the deadline fires immediately, the pass is held again for the same reason, and the
    // loop runs as fast as the machine will let it. A timeout would never catch that; only an
    // assertion that the instant is strictly later than now does.
    //
    // 1e12 IS NOT A PLAUSIBLE SPEC AND IS NOT MEANT TO BE. Knob 15 bounds N only by "finite and
    // positive", so a caller CAN set this, and the point of the row is that the floor holds for
    // the whole declared range rather than for the values a fingerprint would use.
    [Fact]
    public void ADeferralAtAnImmenseRateStillNamesAnInstantStrictlyAfterNow()
    {
        var now = FakeClock().GetUtcNow();
        var pacer = new TlsQuicPacer(
            new TlsQuicRecoverySpec
            {
                PacingBurstDatagrams = 1,
                PacingIntervalScale = 1e12,
            },
            PacerDatagram);

        Assert.True(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));
        Assert.False(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));

        var release = Assert.IsType<DateTimeOffset>(pacer.ReleaseAt);
        Assert.True(release > now, $"The release {release} is not strictly after {now}.");
    }

    // TOTALITY: NOTHING HERE THROWS, FOR ANY INPUT. The pacer sits on the send path and its
    // inputs are a live congestion window and a live RTT estimate, both of which are computed
    // from what the peer did. A throw would take a connection down at the moment the network
    // was already misbehaving - the same argument ITlsQuicCongestionController's remarks make.
    [Fact]
    public void NoShapeOfInputMakesThePacerThrow()
    {
        var now = FakeClock().GetUtcNow();

        foreach (var burst in new int?[] { null, 1, int.MaxValue })
        {
            foreach (var scale in new[] { double.Epsilon, 1.0, 1e300 })
            {
                var pacer = new TlsQuicPacer(
                    new TlsQuicRecoverySpec
                    {
                        PacingBurstDatagrams = burst,
                        PacingIntervalScale = scale,
                    },
                    PacerDatagram);

                foreach (var bytes in new[] { int.MinValue, -1, 0, 1, int.MaxValue })
                {
                    foreach (var window in new[] { long.MinValue, -1L, 0L, 1L, long.MaxValue })
                    {
                        foreach (var rtt in new[]
                        {
                            TimeSpan.MinValue,
                            TimeSpan.Zero,
                            TimeSpan.FromTicks(1),
                            TimeSpan.MaxValue,
                        })
                        {
                            _ = pacer.TryTake(bytes, now, window, rtt);
                            _ = pacer.CreditBytes;
                            _ = pacer.ReleaseAt;
                        }
                    }
                }
            }
        }
    }

    // Construction IS allowed to throw, for the reason the controller's is: a mis-built pacer
    // is a programming error rather than a network event.
    [Fact]
    public void ThePacerRejectsAMisbuiltConstructionRatherThanPacingWrongly()
    {
        Assert.Throws<ArgumentNullException>(() => new TlsQuicPacer(null!, PacerDatagram));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicPacer(new TlsQuicRecoverySpec(), 0));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicPacer(new TlsQuicRecoverySpec(), -1));

        // And knob 15 refuses the two values that would make a rate meaningless.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { PacingIntervalScale = 0 });
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { PacingIntervalScale = -1 });
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { PacingIntervalScale = double.NaN });
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { PacingIntervalScale = double.PositiveInfinity });
    }

    // ========================================================================
    // s7's SEND GATE, ON A LIVE CONNECTION. THE REFUSAL, AND THE THREE EXCEPTIONS.
    // ========================================================================

    // THE HANDOVER, CLOSED. rfc9002-section7-congestion-control.txt lines 46-47: "An endpoint
    // MUST NOT send a packet if it would cause bytes_in_flight ... to be larger than the
    // congestion window". Before this task the window was live and correct and NOTHING ASKED
    // IT on the new-data path - A3-8 said so in its handover and TlsQuicLossDetection.cs says
    // so in its closing note.
    //
    // AND THE REFUSED FRAMES STAY QUEUED. That is what makes a gate in front of a queue safe:
    // the second half of this test opens the window and the same bytes arrive, in order, with
    // nothing re-generated by the caller.
    [Fact]
    public async Task ASendThatWouldExceedTheCongestionWindowIsRefusedAndTheBytesStayQueued()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var gate = new ScriptedSendGate { Open = false };
        var spec = GatedSpec(gate);
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenBidirectional();
        connection.Streams.Send(stream, new byte[] { 1, 2, 3, 4 });
        Assert.True(connection.Streams.HasPendingFrames);

        var offeredBefore = impaired.Offered.Count;
        _ = await connection.SendPendingAsync(cancellation.Token);

        // THE GATE ENGAGED - not "the transfer was slow". A build that never asked would leave
        // this at zero and pass every completion assertion below.
        Assert.True(
            connection.SendsRefusedByCongestionWindow > 0,
            "The congestion window refused nothing, so the rest of this test is vacuous.");

        // DEFERRED, NOT DROPPED - AND NOTHING AT ALL LEFT THIS SIDE. The peer is deliberately
        // NOT pumped here: there is no datagram for it to receive, and a pump that waited for
        // one would hang rather than fail. The offered count is the assertion that says so,
        // and it is a stronger one than an empty frame list would be.
        Assert.True(connection.Streams.HasPendingFrames);
        Assert.Equal(offeredBefore, impaired.Offered.Count);

        // AND THE SAME BYTES ARRIVE WHEN THE WINDOW OPENS.
        gate.Open = true;
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.False(connection.Streams.HasPendingFrames);
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);

        var arrived = Assert.Single(serverPeer.ReceivedStreamFrames);
        Assert.Equal(stream.Id, arrived.StreamId);
        Assert.Equal(0UL, arrived.Offset);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, arrived.Data);

        // The datagram that carried it is one this side actually offered to the wire.
        Assert.True(impaired.Offered.Count > offeredBefore);
    }

    // EXCEPTION 1 OF 2, s7 lines 47-48's first clause and s7.5 lines 195-196: "Probe packets
    // MUST NOT be blocked by the congestion controller."
    //
    // THIS IS THE ANTI-DEADLOCK WITNESS AND NOT A CONFORMANCE DETAIL. A window closes when
    // bytes are in flight and reopens only when the peer says something; a peer says something
    // only when it is asked; and the probe is what asks. A gate that blocked it would hold every
    // byte for ever - which is the exact stall RFC 9000 s8.1's anti-deadlock probe exists to
    // break and which task A3-7 closed.
    [Fact]
    public async Task AProbeLeavesThroughAWindowThatIsClosedToEverythingElse()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var gate = new ScriptedSendGate { Open = true };
        var spec = GatedSpec(gate);
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        // A 1-RTT packet goes out while the window is open, so something is in flight and RFC
        // 9002 A.8 arms the probe timeout against it.
        var stream = connection.Streams.OpenBidirectional();
        connection.Streams.Send(stream, new byte[] { 9 });
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        var armed = Assert.IsType<DateTimeOffset>(connection.LossDetectionTimer);

        // NOW THE WINDOW SHUTS COMPLETELY. Every ordinary send from here is refused.
        gate.Open = false;
        connection.Streams.Send(stream, new byte[] { 8 });
        _ = await connection.SendPendingAsync(cancellation.Token);
        Assert.True(connection.Streams.HasPendingFrames);
        Assert.True(connection.SendsRefusedByCongestionWindow > 0);

        var offeredBeforeProbe = impaired.Offered.Count;

        // s6.2's expiry, on the fake clock and BEFORE the pump, so the receive is already past
        // its deadline and wakes without waiting on anything real.
        impaired.Clock.Advance(
            armed + TimeSpan.FromMilliseconds(1) - impaired.Clock.GetUtcNow());
        _ = await connection.PumpOnceAsync(cancellation.Token);

        // A.9 RAN AND A DATAGRAM LEFT, through a controller that refuses everything.
        Assert.Equal(1, connection.LossDetectionTimeouts);
        Assert.True(
            impaired.Offered.Count > offeredBeforeProbe,
            "The congestion window blocked the probe, which is a deadlock and not conformance.");

        // AND IT WAS ACK-ELICITING, which is s6.2.4 line 192's one hard rule for a probe -
        // a datagram carrying only an ACK would satisfy the count above and probe nothing.
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        Assert.Contains(
            serverPeer.LastDatagramFrames,
            f => f.Type is TlsQuicFrameType.Ping or TlsQuicFrameType.Crypto
                or TlsQuicFrameType.Stream);
    }

    // EXCEPTION 2 OF 2, s7 lines 48-49's second clause, pointing at s7.3.2 lines 149-151: "If
    // the congestion window is reduced immediately, A SINGLE PACKET CAN BE SENT PRIOR TO
    // REDUCTION." A SINGLE packet - so the third row below is the one that makes this a
    // one-shot exemption rather than a hole in the gate.
    [Fact]
    public async Task EnteringRecoveryCarriesExactlyOnePacketPastAClosedWindow()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var gate = new ScriptedWindow { Open = false, Window = PacerWindow };
        var spec = GatedSpec(gate);
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenBidirectional();

        // ROW 1: a steady window that is simply closed. Nothing entered recovery, so nothing is
        // exempt, and the send is refused.
        connection.Streams.Send(stream, new byte[] { 1 });
        _ = await connection.SendPendingAsync(cancellation.Token);
        Assert.True(connection.Streams.HasPendingFrames);
        Assert.Equal(0, connection.RecoveryWindowExemptionsUsed);

        // ROW 2: the controller REDUCES its window, which is s7.3.2's "reduced immediately upon
        // entering a recovery period" seen through the one member of the seam every controller
        // has. One packet goes.
        gate.Window = PacerWindow / 2;
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.False(connection.Streams.HasPendingFrames);
        Assert.Equal(1, connection.RecoveryWindowExemptionsUsed);

        // ROW 3, AND THE WORD "SINGLE" IS WHAT IT PINS. The window has not moved again, so the
        // exemption is spent and the gate is closed once more.
        connection.Streams.Send(stream, new byte[] { 2 });
        _ = await connection.SendPendingAsync(cancellation.Token);
        Assert.True(connection.Streams.HasPendingFrames);
        Assert.Equal(1, connection.RecoveryWindowExemptionsUsed);

        // The one packet that did go carried the first chunk and only it.
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        var arrived = Assert.Single(serverPeer.ReceivedStreamFrames);
        Assert.Equal(new byte[] { 1 }, arrived.Data);
    }

    // EXCEPTION 3, AND IT IS NOT AN EXCEPTION AT ALL BUT A NON-APPLICATION. RFC 9002 B.2 lines
    // 507-509: "Packets only containing ACK frames do not count toward bytes_in_flight", so
    // such a packet cannot cause bytes_in_flight to be larger than anything and s7's sentence
    // has no purchase on it. s7.7 lines 353-355 say the same for the pacer.
    //
    // AND THIS IS THE SECOND LIMB OF THE ANTI-DEADLOCK ARGUMENT: a connection whose window is
    // shut still acknowledges, so the PEER's window keeps moving and the peer keeps sending.
    [Fact]
    public async Task AnAckOnlyAnswerStillLeavesThroughAClosedWindow()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        // SHUT TO EVERYTHING AND PACED AT ONE DATAGRAM, so that if either the gate or the pacer
        // touched an ACK-only pass this test would see it.
        var gate = new ScriptedSendGate { Open = false };
        var spec = GatedSpec(gate, pacingBurstDatagrams: 1);
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenBidirectional();
        var offeredBefore = impaired.Offered.Count;

        // The peer sends data. The only thing this side owes in return is an acknowledgement.
        await serverPeer.SendStreamFramesAsync(
            [PeerStreamFrame(stream.Id, 0, [0x11, 0x22])], cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        Assert.True(
            impaired.Offered.Count > offeredBefore,
            "A closed window swallowed an acknowledgement, which stalls the peer instead.");

        // NEITHER GATE WAS EVEN ASKED, which is the structural claim rather than a lucky
        // outcome: the send path consults them only where it is about to add in-flight frames.
        Assert.Equal(0, connection.SendsRefusedByCongestionWindow);
        Assert.Equal(0, connection.SendsDeferredByPacer);

        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        Assert.Contains(
            serverPeer.LastDatagramFrames,
            f => f.Level == TlsQuicEncryptionLevel.Application
                && f.Type == TlsQuicFrameType.Ack);
    }

    // THE ORDER OF THE TWO GATES, AND IT IS NOT COSMETIC. s7.3.2 grants ONE packet, so a build
    // that spent the grant on a pass s7.7 then held would lose it: the release pass finds the
    // window still shut and the exemption already gone, and the one packet the RFC allows is
    // never sent. The grant is a MAY, so this is not a conformance failure - it is the grant
    // not taken, and its stated purpose is to "speed up loss recovery if the data in the lost
    // packet is retransmitted", which is exactly the send being lost here.
    //
    // AN EARLIER DRAFT OF THIS FILE HAD THE OTHER ORDER, and a comment claiming "the packet
    // still leaves". It did not. This test is what the comment should have been.
    [Fact]
    public async Task TheRecoveryExemptionSurvivesAPassThePacerHoldsAndIsSpentOnTheRelease()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var gate = new ScriptedWindow { Open = true, Window = PacerWindow };
        var spec = GatedSpec(gate, pacingBurstDatagrams: 1);
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenBidirectional();

        // ONE SEND WITH THE WINDOW OPEN, which drains the one-datagram bucket. Both gates have
        // to be shut for the next pass to be the case this test is about.
        connection.Streams.Send(stream, new byte[] { 1 });
        Assert.True(await connection.SendPendingAsync(cancellation.Token));

        // THE WINDOW SHUTS AND REDUCES IN THE SAME BREATH, which is s7.3.2's own shape: the
        // reduction IS the entry into recovery, and the grant comes with it.
        gate.Open = false;
        gate.Window = PacerWindow / 2;

        connection.Streams.Send(stream, new byte[] { 2 });
        _ = await connection.SendPendingAsync(cancellation.Token);

        // HELD BY s7.7, NOT REFUSED BY s7 - and the grant is still owed.
        Assert.Equal(1, connection.SendsDeferredByPacer);
        Assert.Equal(0, connection.RecoveryWindowExemptionsUsed);
        Assert.True(connection.Streams.HasPendingFrames);

        var release = Assert.IsType<DateTimeOffset>(connection.PacingReleaseAt);
        impaired.Clock.Advance(release - impaired.Clock.GetUtcNow());

        // THE RELEASE PASS SPENDS IT. The window has not moved again, so nothing arms a SECOND
        // exemption; the one that survived the hold is what carries this packet.
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.Equal(1, connection.RecoveryWindowExemptionsUsed);
        Assert.False(connection.Streams.HasPendingFrames);

        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        Assert.Equal(
            [new byte[] { 1 }, new byte[] { 2 }],
            serverPeer.ReceivedStreamFrames.Select(f => f.Data));
    }

    // ========================================================================
    // THE PACER, ON A LIVE CONNECTION, THROUGH A3-1's IMPAIRING TRANSPORT.
    // ========================================================================

    // THE DEADLINE ENTRY, WITNESSED - and the branch that distinguishes it from A3-5's. RFC
    // 9002 s7.7's release is a wake-up like the loss detection timer and carries NO obligation
    // to run A.9, so a pump that woke on it must send and must not advance pto_count. A build
    // that reused the recovery branch would pass "the data arrived" and fail the second
    // assertion, which is why both are here.
    [Fact]
    public async Task APacingReleaseWakesThePumpWithoutRunningTheLossDetectionTimeout()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        // ONE DATAGRAM OF BURST, so that the second send of the pass is held. The default of ten
        // would need eleven sends to say the same thing.
        var spec = GatedSpec(controller: null, pacingBurstDatagrams: 1);
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenBidirectional();

        connection.Streams.Send(stream, new byte[] { 1 });
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.Equal(0, connection.SendsDeferredByPacer);

        // THE HOLD. The bucket held one datagram and the pass above spent it.
        connection.Streams.Send(stream, new byte[] { 2 });
        _ = await connection.SendPendingAsync(cancellation.Token);
        Assert.Equal(1, connection.SendsDeferredByPacer);
        Assert.True(connection.Streams.HasPendingFrames);

        var release = Assert.IsType<DateTimeOffset>(connection.PacingReleaseAt);
        var timeouts = connection.LossDetectionTimeouts;

        // THE RELEASE IS NEARER THAN A.8's TIMER, so it is the entry that wins the race. Named
        // rather than assumed: if the loss timer were nearer this test would be pinning A3-5's
        // branch and not A3-11's.
        Assert.True(release < connection.LossDetectionTimer);

        impaired.Clock.Advance(release - impaired.Clock.GetUtcNow());
        _ = await connection.PumpOnceAsync(cancellation.Token);

        // THE PUMP SENT WITH NO DATAGRAM RECEIVED, which is A3-5's mechanism reused.
        Assert.False(connection.Streams.HasPendingFrames);

        // AND A.9 DID NOT RUN. A spurious OnLossDetectionTimeout would advance pto_count and put
        // a probe on the wire for a timer that never expired.
        Assert.Equal(timeouts, connection.LossDetectionTimeouts);

        // TWO DATAGRAMS ARE OUTSTANDING AND ONE PUMP TAKES ONE, so the peer is pumped twice.
        // The count is derived from what this side offered rather than typed, so a build that
        // split or merged the two would fail here rather than silently read the first.
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        Assert.Equal(
            [new byte[] { 1 }, new byte[] { 2 }],
            serverPeer.ReceivedStreamFrames.Select(f => f.Data));
    }

    // THE PLAN'S OWN CLAUSE, IN ONE PUMP: "pacing NEVER delays a PTO probe, with a witness -
    // s8.1's anti-deadlock probe exists to break a stall and a pacer that held it would
    // reintroduce exactly the deadlock A3-7 closes". RFC 9002 s7.5 says it of the congestion
    // controller - "Probe packets MUST NOT be blocked" - and s7.7 never exempts the probe in as
    // many words, so this is the plan's reading of the two together and it is implemented
    // structurally: SendOwedProbeAsync does not consult the pacer, so there is no argument a
    // caller could pass wrongly.
    //
    // THE WITNESS IS ONE PUMP CARRYING BOTH VERDICTS AT ONCE, which is stronger than two pumps
    // would be: in the SAME pass the pacer refuses the ordinary 1-RTT frames and the probe
    // datagram leaves anyway.
    //
    // THE INTERVAL SCALE IS MICROSCOPIC ON PURPOSE. At knob 15's default the bucket refills a
    // whole datagram inside the clamp, so the release pass would send and there would be no
    // "still holding" to observe. A rate this low means the clamp - one smoothed RTT, fact
    // (iii) of the anti-wedge proof - is what ends every wait, and the credit that accrues in
    // it is a rounding error. That is also this file's only test of the clamp on a live
    // connection rather than on the pacer alone.
    [Fact]
    public async Task APacerHoldingOrdinaryDataDoesNotHoldThePtoProbeInTheSamePump()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var spec = GatedSpec(
            controller: null, pacingBurstDatagrams: 1, pacingIntervalScale: 1e-6);
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenBidirectional();

        connection.Streams.Send(stream, new byte[] { 1 });
        Assert.True(await connection.SendPendingAsync(cancellation.Token));

        connection.Streams.Send(stream, new byte[] { 2 });
        _ = await connection.SendPendingAsync(cancellation.Token);
        Assert.Equal(1, connection.SendsDeferredByPacer);

        // s6.2's expiry, driven directly so that this test pins the PROBE against the pacer
        // rather than re-pinning A3-5's deadline race, which its own tests already own.
        connection.OnLossDetectionTimeout();
        Assert.NotNull(connection.OwedProbe);

        var release = Assert.IsType<DateTimeOffset>(connection.PacingReleaseAt);
        var offeredBefore = impaired.Offered.Count;
        impaired.Clock.Advance(release - impaired.Clock.GetUtcNow());

        _ = await connection.PumpOnceAsync(cancellation.Token);

        // THE PACER IS STILL HOLDING - at this rate the clamp released the wait long before the
        // credit arrived, so the ordinary frames are refused a second time...
        Assert.Equal(2, connection.SendsDeferredByPacer);
        Assert.True(connection.Streams.HasPendingFrames);

        // ...AND THE PROBE WENT OUT OF THE SAME PUMP ANYWAY.
        Assert.Null(connection.OwedProbe);
        Assert.True(
            impaired.Offered.Count > offeredBefore,
            "The pacer held the PTO probe, which is the deadlock task A3-7 closed.");
    }

    // THE ONE PROPERTY A PACER MUST NOT COST: an attempt that would have ended still ends. RFC
    // 9000 s10.1's idle timeout and the handshake deadline are re-read on EVERY wake, so a
    // pacing entry can shorten a wait and never lengthen one - which is the argument
    // EarliestDeadline's own remarks already make for A3-5's third entry, re-asserted here for
    // the fourth because held data is exactly the state in which a wedge would be invisible.
    [Fact]
    public async Task AnAbandonmentDeadlineStillEndsAnAttemptWithPacedDataHeld()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var spec = GatedSpec(controller: null, pacingBurstDatagrams: 1);
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenBidirectional();
        connection.Streams.Send(stream, new byte[] { 1 });
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        connection.Streams.Send(stream, new byte[] { 2 });
        _ = await connection.SendPendingAsync(cancellation.Token);

        Assert.Equal(1, connection.SendsDeferredByPacer);
        Assert.NotNull(connection.PacingReleaseAt);

        // PAST BOTH ABANDONMENTS AND FAR PAST THE PACING RELEASE. The nearer of the two
        // abandonments is what must be reported, not the pacing entry.
        impaired.Clock.Advance(TimeSpan.FromHours(2));

        var wallClock = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<Exception>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        wallClock.Stop();

        // ON THE FAKE CLOCK, so this is a proof about the deadline table and not about the
        // sixty-second bound the token source above carries.
        Assert.True(
            wallClock.Elapsed < TimeSpan.FromSeconds(10),
            $"The abandonment took {wallClock.Elapsed} of wall-clock time.");
    }

    // ========================================================================
    // THE PIN: PACING OFF EMITS WHAT TODAY EMITS, AND PACING ON EMITS THE SAME BYTES LATER.
    // ========================================================================
    //
    // The plan's done-when: "disabling pacing changes no byte of any packet, only its departure
    // time, asserted by comparing the recorded payloads".
    //
    // WHAT IS COMPARED, AND WHY IT IS NOT A RAW MEMCMP OF THE DATAGRAMS. Every connection draws
    // a fresh random Source Connection ID and a fresh Original Destination Connection ID, so
    // two runs differ in those bytes by construction and a memcmp would fail for a reason that
    // has nothing to do with pacing. What IS compared is every dimension a fingerprint reader
    // could measure and pacing could plausibly disturb: the NUMBER of datagrams, the LENGTH of
    // each one in order, and the frames the peer decoded out of them - stream, offset, bytes and
    // FIN. A pacer that split, merged, reordered, padded or dropped anything moves one of those.
    //
    // AND THE TIMING, WHICH IS THE THING THAT IS ALLOWED TO DIFFER, IS ASSERTED TO DIFFER. On
    // A3-1's fake clock the unpaced run advances the clock by exactly nothing; the paced run
    // advances it by the sum of its own releases. Exact, not statistical.
    [Fact]
    public async Task PacingOffEmitsExactlyWhatPacingOnEmitsAndOnlyTheDepartureTimesMove()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);

        var unpaced = await RunPacingScriptAsync(null, cancellation.Token);
        var paced = await RunPacingScriptAsync(1, cancellation.Token);

        // NOT VACUOUS: the paced run really was held, and the unpaced run really was not.
        Assert.Equal(0, unpaced.Deferrals);
        Assert.True(
            paced.Deferrals > 0,
            "The paced run never deferred, so this test compares two identical runs.");

        // THE BYTES. Same count, same lengths in the same order, same decoded frames.
        Assert.Equal(unpaced.DatagramLengths, paced.DatagramLengths);
        Assert.Equal(unpaced.Frames, paced.Frames);

        // THE TIME. Off costs nothing at all; on costs the sum of its releases.
        Assert.Equal(TimeSpan.Zero, unpaced.Elapsed);
        Assert.True(
            paced.Elapsed > TimeSpan.Zero,
            "Pacing on and pacing off produced the same send timings.");
    }

    // ------------------------------------------------------------------------
    // Helpers.
    // ------------------------------------------------------------------------

    // ONE SCRIPT, TWO SPECS. Everything the connection does is identical in both runs; the only
    // difference is knob 14, and the only thing the run does about a hold is wait for it.
    private static async Task<(
        IReadOnlyList<int> DatagramLengths,
        IReadOnlyList<string> Frames,
        int Deferrals,
        TimeSpan Elapsed)> RunPacingScriptAsync(
        int? pacingBurstDatagrams, CancellationToken cancellationToken)
    {
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        var spec = GatedSpec(controller: null, pacingBurstDatagrams: pacingBurstDatagrams);
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);
        await ConfirmedHandshake(connection, serverPeer, cancellationToken);

        var startedAt = impaired.Clock.GetUtcNow();
        var delivered = impaired.Delivered.Count;
        var stream = connection.Streams.OpenBidirectional();

        for (var chunk = 0; chunk < 6; chunk++)
        {
            connection.Streams.Send(stream, new[] { (byte)chunk });
            _ = await connection.SendPendingAsync(cancellationToken);

            // THE RELEASE LOOP, AND IT IS BOUNDED. Each pass either sends or names an instant
            // strictly later than this one and no more than a smoothed RTT away, so the count
            // is a formality that turns a hypothetical wedge into a named failure rather than
            // a hung suite.
            for (var attempt = 0; connection.Streams.HasPendingFrames; attempt++)
            {
                Assert.True(attempt < 32, "The pacer never released a datagram.");
                var release = Assert.IsType<DateTimeOffset>(connection.PacingReleaseAt);
                impaired.Clock.Advance(release - impaired.Clock.GetUtcNow());
                _ = await connection.SendPendingAsync(cancellationToken);
            }
        }

        // THE PEER IS DRAINED BY COUNT AND NOT ONCE PER CHUNK, because the two runs do not
        // spend the same NUMBER of send passes - the paced one takes a release pass for every
        // hold - and a peer pumped a fixed number of times would read a different prefix of
        // each run. One pump takes one datagram, so the count is the transport's own.
        while (delivered < impaired.Delivered.Count)
        {
            delivered++;
            _ = await serverPeer.PumpOnceAsync(SentAt, cancellationToken);
        }

        // FIELD BY FIELD AND NOT AS A TUPLE, and this file learned it the way
        // TlsQuicConnectionStreamTests' AssertStreamFrame did: ValueTuple's equality compares
        // the byte[] element by REFERENCE, so comparing two runs' frame tuples fails for every
        // correct frame and a version that happened to pass would be comparing identity rather
        // than content. Rendered to a string so that Assert.Equal reports the difference.
        return (
            impaired.Offered.Select(datagram => datagram.Length).ToArray(),
            serverPeer.ReceivedStreamFrames
                .Select(f => $"{f.StreamId}/{f.Offset}/{Convert.ToHexString(f.Data)}/{f.Fin}")
                .ToArray(),
            connection.SendsDeferredByPacer,
            impaired.Clock.GetUtcNow() - startedAt);
    }

    // The instant a pacer holding one datagram of burst names for the second one, at the given
    // s7.7 N. Shared by the two rows of the interval-scale test so that they differ in nothing
    // else at all.
    private static DateTimeOffset HeldAt(double intervalScale, DateTimeOffset now)
    {
        var pacer = new TlsQuicPacer(
            new TlsQuicRecoverySpec
            {
                PacingBurstDatagrams = 1,
                PacingIntervalScale = intervalScale,
            },
            PacerDatagram);

        Assert.True(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));
        Assert.False(pacer.TryTake(PacerDatagram, now, PacerWindow, PacerRtt));
        return Assert.IsType<DateTimeOffset>(pacer.ReleaseAt);
    }

    // A spec whose congestion controller and pacing are both the test's. PACING DEFAULTS TO OFF
    // HERE and not to the shipped default, so that a gate test says nothing about the pacer and
    // a pacer test says nothing about the gate.
    private static TlsQuicConnectionSpec GatedSpec(
        ITlsQuicCongestionController? controller,
        int? pacingBurstDatagrams = null,
        double? pacingIntervalScale = null) => new()
        {
            PaddingTarget = PacerDatagram,
            SourceConnectionIdLength = SourceConnectionIdLength,
            Recovery = new TlsQuicRecoverySpec
            {
                CongestionController = controller is null ? null : () => controller,
                PacingBurstDatagrams = pacingBurstDatagrams,
                PacingIntervalScale =
                    pacingIntervalScale ?? TlsQuicRecoverySpec.DefaultPacingIntervalScale,
            },
        };

    // A controller whose window a test MOVES. ScriptedSendGate reports a constant zero, which
    // is exactly what s7's second exception cannot be detected from - the exemption is armed by
    // a window going DOWN, so a test for it needs a window that can.
    private sealed class ScriptedWindow : ITlsQuicCongestionController
    {
        internal bool Open { get; set; }

        internal long Window { get; set; }

        public string Name => "scripted-window";

        public long CongestionWindowBytes => Window;

        public long BytesInFlight => 0;

        public bool CanSend(int bytes) => Open;

        public void OnPacketSent(in TlsQuicSentPacket sent)
        {
        }

        public void OnPacketsAcked(IReadOnlyList<TlsQuicSentPacket>? ackedPackets)
        {
        }

        public void OnPacketsLost(IReadOnlyList<TlsQuicSentPacket>? lostPackets)
        {
        }

        public void OnPersistentCongestion()
        {
        }

        public void OnPacketsDiscarded(IReadOnlyList<TlsQuicSentPacket>? discardedPackets)
        {
        }
    }
}
