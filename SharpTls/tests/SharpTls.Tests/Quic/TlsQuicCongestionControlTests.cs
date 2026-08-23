using SharpTls.Tests.Certificates;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// WHAT THESE TESTS ARE FOR, AND THE MUTANT THE A3 PLAN NAMES FOR THIS TASK.
//
// Finding 11's constant-window controller - one that reports a plausible window, never grows
// it and never reduces it - SATISFIES EVERY ARITHMETIC INVARIANT anyone can state about
// congestion control. The window is never negative. It never falls below the minimum. Bytes in
// flight never exceed it. A suite built out of invariants scores that mutant green. The only
// tests that kill it are the ones that name the EVENT: an acknowledgement in slow start, a
// loss, an acknowledgement after the recovery period. So each of the three states below has a
// witness at its own event, and each of Figure 1's transitions has one at the event that
// causes it, and that is the shape of this file rather than a list of properties.
//
// AND NOT ONE NUMBER HERE IS A REMEMBERED CONSTANT. Every expectation is computed from the
// TlsQuicRecoverySpec the controller was built with, or written as a pair of candidate numbers
// where two readings of RFC 9002 disagree - so that a test which merely agreed with the
// implementation's mistake would have to spell the mistake out.
public sealed class TlsQuicCongestionControlTests
{
    // 1200 IS NOT A CONGESTION CONSTANT AND IS NOT READ OUT OF THE EXTRACT AS ONE. It is this
    // file's max_datagram_size, a property of a path rather than a fingerprint - RFC 9002 B.2
    // lines 490-495 - and it is a test fixture. The congestion numbers all come off a spec.
    private const int MaxDatagramSize = 1200;

    private static readonly DateTimeOffset Origin =
        new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ------------------------------------------------------------------------------
    // SLOW START - the state, and the event that grows it.
    // ------------------------------------------------------------------------------

    [Fact]
    public void AFreshControllerIsInSlowStartAtTheSpecsInitialWindow()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out _);

        // RFC 9002 s7.3.1 lines 119-120: "A sender begins in slow start because the slow start
        // threshold is initialized to an infinite value." B.3 line 532: `ssthresh = infinite`.
        Assert.Equal(TlsQuicCongestionState.SlowStart, controller.State);
        Assert.Equal(long.MaxValue, controller.SlowStartThresholdBytes);
        Assert.Equal(
            TlsQuicNewRenoCongestionController.InitialWindowFor(spec, MaxDatagramSize),
            controller.CongestionWindowBytes);
        Assert.Equal(0, controller.BytesInFlight);
        Assert.Equal("NewReno", controller.Name);
    }

    [Fact]
    public void AnAcknowledgementInSlowStartGrowsTheWindowByExactlyTheBytesAcknowledged()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        var window = controller.CongestionWindowBytes;

        // THE WINDOW MUST BE FULL OR s7.8 SUPPRESSES THE GROWTH, which is the whole reason
        // this test sends a windowful rather than one packet. That suppression has its own
        // test below; here it would be a silent explanation for a green bar.
        var sent = FillWindow(controller, clock.GetUtcNow());
        Assert.Equal(window, controller.BytesInFlight);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked(sent);

        // B.5 line 575: `congestion_window += acked_packet.sent_bytes`, once per packet. A
        // windowful acknowledged therefore DOUBLES the window - s7.3.1 lines 124-125's
        // "exponential growth" - and the doubling is what a constant-window mutant cannot fake.
        Assert.Equal(window * 2, controller.CongestionWindowBytes);
        Assert.Equal(0, controller.BytesInFlight);
        Assert.Equal(TlsQuicCongestionState.SlowStart, controller.State);
    }

    // ------------------------------------------------------------------------------
    // SLOW START -> RECOVERY, witnessed at the loss.
    // ------------------------------------------------------------------------------

    [Fact]
    public void ALossInSlowStartEntersRecoveryAndReducesTheWindowByTheSpecsFactor()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        var window = controller.CongestionWindowBytes;

        var sent = FillWindow(controller, clock.GetUtcNow());
        clock.Advance(TimeSpan.FromMilliseconds(1));

        controller.OnPacketsLost([sent[0]]);

        // s7.3.1 lines 127-129: "The sender MUST exit slow start and enter a recovery period
        // when a packet is lost". B.6 lines 596-597.
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);
        Assert.Equal(
            (long)(window * spec.LossReductionFactor), controller.SlowStartThresholdBytes);
        Assert.Equal(
            Math.Max(
                (long)(window * spec.LossReductionFactor),
                (long)spec.MinimumCongestionWindowDatagrams * MaxDatagramSize),
            controller.CongestionWindowBytes);

        // B.8 lines 622-623: the lost packet leaves bytes in flight.
        Assert.Equal(window - sent[0].Size, controller.BytesInFlight);
    }

    // ------------------------------------------------------------------------------
    // RECOVERY -> CONGESTION AVOIDANCE, witnessed at the acknowledgement that ends it,
    // and CONGESTION AVOIDANCE's own growth event.
    // ------------------------------------------------------------------------------

    [Fact]
    public void AnAcknowledgementOfAPacketSentDuringRecoveryEntersCongestionAvoidance()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        var sent = FillWindow(controller, clock.GetUtcNow());
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([sent[0]]);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);

        // A packet sent AFTER the recovery period opened. s7.3.2 lines 160-162: "A recovery
        // period ends and the sender enters congestion avoidance when a packet sent during the
        // recovery period is acknowledged."
        clock.Advance(TimeSpan.FromMilliseconds(1));
        var during = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(during);

        // AND ONE SENT BEFORE IT, ACKNOWLEDGED FIRST, WHICH MUST NOT END ANYTHING. Without
        // this the test would pass against an implementation that ended the period on any
        // acknowledgement at all, which is the same class of error as re-entering recovery on
        // an old loss.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([sent[1]]);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);

        controller.OnPacketsAcked([during]);
        Assert.Equal(TlsQuicCongestionState.CongestionAvoidance, controller.State);

        // s7.3.3 lines 168-170: at or above the threshold, and not in a recovery period. B.6
        // line 597 left the window at exactly the threshold, so "at or above" is what put it
        // here rather than "above".
        Assert.Equal(
            controller.SlowStartThresholdBytes, controller.CongestionWindowBytes);
    }

    [Fact]
    public void CongestionAvoidanceAddsOneDatagramPerWindowAcknowledgedAndNotOnePerPacket()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        EnterCongestionAvoidance(controller, clock);
        var window = controller.CongestionWindowBytes;

        clock.Advance(TimeSpan.FromMilliseconds(1));
        var sent = FillWindow(controller, clock.GetUtcNow());
        Assert.Equal(5, sent.Count);
        Assert.Equal(window, controller.BytesInFlight);

        // PART OF A WINDOW FIRST, WHICH MUST MOVE NOTHING. s7.3.3 lines 172-175 limit the
        // increase "to at most one maximum datagram size for each congestion window that is
        // acknowledged" - so a controller that added a datagram per ACK, or per packet, is
        // caught here and not by the second half.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked(sent.Take(2).ToList());
        Assert.Equal(window, controller.CongestionWindowBytes);

        // THE SENDER REFILLS, WHICH IS WHAT A SEND PATH DOES AND WHAT KEEPS s7.8 OUT OF THIS
        // TEST. Without the refill the next acknowledgement finds a half-drained window and is
        // correctly judged application limited, and this test would be measuring that instead.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        var refill = SendAt(controller, clock.GetUtcNow(), 2);
        Assert.Equal(window, controller.BytesInFlight);

        // THE REST OF THE WINDOW, WHICH TAKES THE RUNNING TOTAL PAST ONE WHOLE WINDOW AND
        // MOVES IT BY EXACTLY ONE DATAGRAM.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([.. sent.Skip(2), .. refill]);

        Assert.Equal(window + MaxDatagramSize, controller.CongestionWindowBytes);
        Assert.Equal(TlsQuicCongestionState.CongestionAvoidance, controller.State);

        // A PER-PACKET CONTROLLER'S ANSWER, SPELLED. Seven packets were acknowledged; adding a
        // datagram for each would have given 14,400 instead of 7,200, and "the window grew"
        // cannot tell the two apart.
        Assert.Equal(14_400, window + (7 * MaxDatagramSize));
    }

    // THE DIVERGENCE FROM APPENDIX B THAT WOULD HAVE SHIPPED A DEFECT, PINNED WITH BOTH
    // CANDIDATE NUMBERS.
    //
    // B.5 lines 578-580 write the congestion avoidance increase as
    // `congestion_window += max_datagram_size * acked_packet.sent_bytes / congestion_window`.
    // In integer arithmetic that quotient is ZERO once the window exceeds
    // max_datagram_size * sent_bytes - 1,440,000 bytes here - so a literal transcription stops
    // growing permanently and reports a perfectly ordinary window while doing it. B.5's own
    // lines 549-552 warn about exactly this and point at RFC 3465 s2.1's byte counter, which
    // is what this implementation uses.
    //
    // BOTH NUMBERS ARE WRITTEN OUT because "the window grew" would pass against either reading
    // at a small window, and "the window is not 2,400,000" is a verdict with no named
    // alternative. The literal reading's answer and the counter's answer are both spelled.
    [Fact]
    public void CongestionAvoidanceStillGrowsWhereAppendixBsLiteralQuotientWouldBeZero()
    {
        // A spec whose initial window is large enough that one halving still leaves the window
        // above max_datagram_size squared. Nothing about the number is an RFC value; it is
        // chosen to reach the regime where the two readings differ.
        var spec = new TlsQuicRecoverySpec
        {
            InitialCongestionWindow = (DatagramMultiplier: 4000, ByteCap: 6_000_000),
        };
        var controller = Controller(spec, out var clock);
        EnterCongestionAvoidance(controller, clock);

        var window = controller.CongestionWindowBytes;
        Assert.Equal(2_400_000, window);

        // The regime: one full-size packet's contribution under B.5's literal expression.
        Assert.True(MaxDatagramSize * (long)MaxDatagramSize < window);
        Assert.Equal(0, MaxDatagramSize * (long)MaxDatagramSize / window);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        var windowful = FillWindow(controller, clock.GetUtcNow());
        controller.OnPacketsAcked(windowful);

        // THE COUNTER'S ANSWER: one whole window acknowledged, so one maximum datagram size.
        Assert.Equal(2_401_200, controller.CongestionWindowBytes);

        // THE LITERAL TRANSCRIPTION'S ANSWER, spelled so the two cannot be confused: every one
        // of those 2000 acknowledgements would have added zero.
        Assert.Equal(2_400_000, window + (windowful.Count * (MaxDatagramSize * (long)MaxDatagramSize / window)));
    }

    // ------------------------------------------------------------------------------
    // CONGESTION AVOIDANCE -> RECOVERY, witnessed at the loss.
    // ------------------------------------------------------------------------------

    [Fact]
    public void ALossInCongestionAvoidanceReentersRecovery()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        EnterCongestionAvoidance(controller, clock);
        var window = controller.CongestionWindowBytes;

        clock.Advance(TimeSpan.FromMilliseconds(1));
        var fresh = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(fresh);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([fresh]);

        // s7.3.3 lines 177-179: "The sender exits congestion avoidance and enters a recovery
        // period when a packet is lost".
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);
        Assert.Equal(
            Math.Max(
                (long)(window * spec.LossReductionFactor),
                (long)spec.MinimumCongestionWindowDatagrams * MaxDatagramSize),
            controller.CongestionWindowBytes);
    }

    // ------------------------------------------------------------------------------
    // s7.3.2's ONCE PER ROUND TRIP - the classic place NewReno is written wrong.
    // ------------------------------------------------------------------------------

    [Fact]
    public void APacketSentBeforeRecoveryStartedDoesNotReduceTheWindowASecondTime()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        var window = controller.CongestionWindowBytes;
        Assert.Equal(12_000, window);

        var sent = FillWindow(controller, clock.GetUtcNow());
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([sent[0]]);
        Assert.Equal(6_000, controller.CongestionWindowBytes);

        // A SECOND LOSS OF A PACKET FROM THE SAME FLIGHT. s7.3.2 lines 155-158: "The recovery
        // period aims to limit congestion window reduction to once per round trip. Therefore,
        // during a recovery period, the congestion window does not change in response to new
        // losses". B.6 lines 591-592 return early on it.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([sent[1], sent[2]]);

        // BOTH CANDIDATES SPELLED. 6,000 is one reduction; 3,000 is what a controller that
        // reacted to the second batch would report, and it is an entirely plausible-looking
        // congestion window that no invariant in this file would flag.
        Assert.Equal(6_000, controller.CongestionWindowBytes);
        Assert.Equal(3_000, (long)(6_000 * spec.LossReductionFactor));

        // AND THE BYTES STILL LEAVE FLIGHT. B.8 lines 621-623 are outside the early return, so
        // "no reaction" means no WINDOW reaction - a controller that skipped the whole of
        // OnPacketsLost while in recovery would leak bytes in flight forever.
        Assert.Equal(window - (sent[0].Size + sent[1].Size + sent[2].Size), controller.BytesInFlight);
    }

    // THE CALIBRATION CONTROL FOR THE TEST ABOVE. Without it, a controller that never reduced
    // the window twice for ANY reason - including one that never reduced it a second time at
    // all - passes. This one loses a packet sent AFTER the recovery period opened and requires
    // the second reduction to happen.
    [Fact]
    public void APacketSentAfterRecoveryStartedDoesReduceTheWindowASecondTime()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        var sent = FillWindow(controller, clock.GetUtcNow());
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([sent[0]]);
        Assert.Equal(6_000, controller.CongestionWindowBytes);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        var later = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(later);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([later]);

        Assert.Equal(3_000, controller.CongestionWindowBytes);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);
    }

    // AND THE ONE THAT CATCHES THE FLAG-AND-TIMESTAMP CONFUSION. Once a recovery period has
    // ENDED, its start time is still the boundary that says which packets predate it. A
    // controller that guarded OnCongestionEvent with "am I in recovery AND is this old" opens
    // a second period for a straggler from the first flight, halving the window twice for one
    // round trip's losses. Only a test that ends the period before the straggler arrives can
    // see it, which is why this is not folded into the test above.
    [Fact]
    public void AStragglingLossFromBeforeAnEndedRecoveryPeriodStartsNoNewOne()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        var sent = FillWindow(controller, clock.GetUtcNow());
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([sent[0]]);
        Assert.Equal(6_000, controller.CongestionWindowBytes);

        // End the period.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        var during = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(during);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([during]);
        Assert.Equal(TlsQuicCongestionState.CongestionAvoidance, controller.State);

        // The straggler, from the flight that caused the first reduction.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([sent[1]]);

        Assert.Equal(TlsQuicCongestionState.CongestionAvoidance, controller.State);
        Assert.Equal(6_000, controller.CongestionWindowBytes);
        Assert.Equal(3_000, (long)(6_000 * spec.LossReductionFactor));
    }

    // ------------------------------------------------------------------------------
    // s7.2 - the initial window, the byte cap, and the minimum.
    // ------------------------------------------------------------------------------

    // s7.2 lines 63-66: "Endpoints SHOULD use an initial congestion window of ten times the
    // maximum datagram size (max_datagram_size), while limiting the window to the larger of
    // 14,720 bytes or twice the maximum datagram size."
    //
    // TWO OPERATIONS THAT NEST IN ONE ORDER ONLY, and every row here is a case where a
    // different nesting gives a different number - so the theory cannot be satisfied by
    // getting it backwards. The "backwards" column is the answer a max-of-the-multiple
    // reading produces, and it is asserted as a number so the two readings are both named.
    [Theory]
    // Ten 1200-byte datagrams is 12,000, under the 14,720 cap: the multiple binds.
    [InlineData(1200, 10, 14720, 12_000, 14_720)]
    // Ten 1500-byte datagrams is 15,000, over it: the cap binds. THE ROW THAT MATTERS.
    [InlineData(1500, 10, 14720, 14_720, 15_000)]
    // A zero byte cap, where s7.2's "larger of" falls back on the datagram multiple floor.
    [InlineData(1200, 3, 0, 2_400, 3_600)]
    // ...and the floor NOT clamping the window up, because s7.2 lines 83-85 scope the minimum
    // to reductions. A one-datagram initial window is a fingerprint, not a mistake - and the
    // backwards reading would raise it to the floor, which is why this row is here.
    [InlineData(1200, 1, 0, 1_200, 2_400)]
    public void TheInitialWindowIsTheMultipleHeldDownToTheLargerOfTheCapAndTheFloor(
        int maxDatagramSize, int multiplier, int byteCap, long expected, long backwards)
    {
        var spec = new TlsQuicRecoverySpec
        {
            InitialCongestionWindow = (DatagramMultiplier: multiplier, ByteCap: byteCap),
        };

        var actual = TlsQuicNewRenoCongestionController.InitialWindowFor(spec, maxDatagramSize);
        Assert.Equal(expected, actual);

        // The reading that takes the LARGER of the ten-times figure and the cap instead of
        // holding the first down to the second, spelled out rather than merely excluded.
        var floor = (long)spec.MinimumCongestionWindowDatagrams * maxDatagramSize;
        Assert.Equal(
            backwards, Math.Max((long)multiplier * maxDatagramSize, Math.Max(byteCap, floor)));

        // And the controller starts at the value, so this is not a test of a static helper
        // nothing calls.
        Assert.Equal(
            expected,
            new TlsQuicNewRenoCongestionController(spec, maxDatagramSize).CongestionWindowBytes);
    }

    // KNOB 2 AND KNOB 3 ARE KNOBS AND NOT CONSTANTS WITH GETTERS. Two specs, two send
    // behaviours, asserted through CanSend rather than through the window property - a
    // controller that reported a spec-derived window but gated on a hardcoded one would pass a
    // property comparison and fail this.
    [Fact]
    public void TwoSpecsDriveTwoDifferentSendBehavioursFromTheSameData()
    {
        var narrow = new TlsQuicRecoverySpec
        {
            InitialCongestionWindow = (DatagramMultiplier: 2, ByteCap: 0),
        };
        var wide = new TlsQuicRecoverySpec
        {
            InitialCongestionWindow = (DatagramMultiplier: 20, ByteCap: 60_000),
        };

        var narrowController = Controller(narrow, out var narrowClock);
        var wideController = Controller(wide, out var wideClock);

        var sentNarrow = SendAt(narrowController, narrowClock.GetUtcNow(), 2);
        var sentWide = SendAt(wideController, wideClock.GetUtcNow(), 2);
        Assert.Equal(2, sentNarrow.Count);
        Assert.Equal(2, sentWide.Count);

        // Same two packets, same sizes, same clock offsets - and one controller is full while
        // the other has eighteen datagrams of room.
        Assert.False(narrowController.CanSend(MaxDatagramSize));
        Assert.True(wideController.CanSend(MaxDatagramSize));
    }

    [Fact]
    public void TheWindowNeverFallsBelowTheSpecsMinimumAcrossALongLossSequence()
    {
        var spec = new TlsQuicRecoverySpec { MinimumCongestionWindowDatagrams = 3 };
        var controller = Controller(spec, out var clock);
        var minimum = (long)spec.MinimumCongestionWindowDatagrams * MaxDatagramSize;

        // Forty independent congestion events, each on a packet sent after the previous
        // period opened, so each is a real reduction and not one B.6 returns early on.
        for (var i = 0; i < 40; i++)
        {
            clock.Advance(TimeSpan.FromMilliseconds(1));
            var packet = Packet(MaxDatagramSize, clock.GetUtcNow());
            controller.OnPacketSent(packet);
            clock.Advance(TimeSpan.FromMilliseconds(1));
            controller.OnPacketsLost([packet]);

            // CHECKED EVERY ITERATION AND AGAINST THE SPEC OBJECT, not once at the end and not
            // against a remembered 2,400. s7.2 lines 83-86.
            Assert.True(
                controller.CongestionWindowBytes >= minimum,
                $"Iteration {i} left the window at {controller.CongestionWindowBytes}, "
                    + $"below the spec's minimum of {minimum}.");
        }

        // AND IT REACHED THE FLOOR RATHER THAN STOPPING SOMEWHERE COMFORTABLE ABOVE IT, which
        // is what makes the loop above a test of the clamp instead of a test of forty
        // halvings that never got near it.
        Assert.Equal(minimum, controller.CongestionWindowBytes);
        Assert.Equal(3_600, minimum);
    }

    // ------------------------------------------------------------------------------
    // s7.3.2's PROSE AGAINST B.6's PSEUDOCODE.
    // ------------------------------------------------------------------------------

    // s7.3.2 lines 142-144 say a sender "MUST set the slow start threshold to HALF the value
    // of the congestion window when loss is detected" - the number 0.5, in the prose. B.6 line
    // 596 says `ssthresh = congestion_window * kLossReductionFactor`, and B.1 lines 477-479
    // call that a constant "Section 7 recommends a value of 0.5" for. THIS IMPLEMENTATION
    // FOLLOWS B.6: a recommended value is a knob, and A3-2 made it one.
    //
    // Both candidate numbers are asserted. A spec carrying a quarter reduces to 3,000, and the
    // prose's literal half would have given 6,000; a test that only checked "the window went
    // down" cannot tell those apart, and neither can one that checks the default spec, where
    // the two readings agree by construction.
    [Fact]
    public void TheReductionFollowsTheSpecsFactorAndNotTheProsesLiteralHalf()
    {
        var quarter = new TlsQuicRecoverySpec { LossReductionFactor = 0.25 };
        var controller = Controller(quarter, out var clock);
        var window = controller.CongestionWindowBytes;
        Assert.Equal(12_000, window);

        var sent = FillWindow(controller, clock.GetUtcNow());
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([sent[0]]);

        // B.6's answer, with this spec.
        Assert.Equal(3_000, controller.CongestionWindowBytes);
        Assert.Equal(3_000, controller.SlowStartThresholdBytes);

        // The prose's answer, spelled, and demonstrated to be what the DEFAULT spec produces -
        // which is why following B.6 costs nothing at the default and everything at a knob.
        var half = Controller(new TlsQuicRecoverySpec(), out var halfClock);
        var halfSent = FillWindow(half, halfClock.GetUtcNow());
        halfClock.Advance(TimeSpan.FromMilliseconds(1));
        half.OnPacketsLost([halfSent[0]]);
        Assert.Equal(6_000, half.CongestionWindowBytes);
    }

    // ------------------------------------------------------------------------------
    // s7.8 - IsAppOrFlowControlLimited, which RFC 9002 calls and never defines.
    // ------------------------------------------------------------------------------

    [Fact]
    public void AnAppLimitedSenderDoesNotGrowItsWindow()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        var window = controller.CongestionWindowBytes;

        // One packet against a ten-datagram window: s7.8 lines 384-387's "insufficient
        // application data".
        var lonely = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(lonely);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([lonely]);

        // s7.8 line 388: "the congestion window SHOULD NOT be increased in either slow start
        // or congestion avoidance."
        Assert.Equal(window, controller.CongestionWindowBytes);
        Assert.Equal(0, controller.BytesInFlight);
    }

    // THE CALIBRATION CONTROL. A controller that never grew in slow start at all passes the
    // test above; this one requires that the identical acknowledgement DOES grow the window
    // when the window was full, so the difference is the predicate and not the growth path.
    [Fact]
    public void ASenderThatFilledItsWindowIsNotAppLimitedAndDoesGrow()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        var window = controller.CongestionWindowBytes;

        var sent = FillWindow(controller, clock.GetUtcNow());
        clock.Advance(TimeSpan.FromMilliseconds(1));

        // The SAME single-packet acknowledgement as the app-limited test, against a full
        // window instead of an empty one.
        controller.OnPacketsAcked([sent[0]]);
        Assert.Equal(window + MaxDatagramSize, controller.CongestionWindowBytes);
    }

    // THE CASE THAT KILLS THE LITERAL READING OF s7.8's FIRST CLAUSE. Taken at its word -
    // "bytes in flight is smaller than the congestion window" - a sender whose window is not a
    // whole number of datagrams is under-utilised FOREVER: it fills to 12,000 of a 12,500-byte
    // window, cannot fit an eleventh packet, and never grows again in either state. The
    // definition this file uses asks whether another whole datagram would have fitted.
    [Fact]
    public void AWindowThatIsNotAWholeNumberOfDatagramsIsStillFullyUtilised()
    {
        // Eleven 1200-byte datagrams is 13,200, held down to a cap of 12,500 - which is not a
        // whole number of datagrams. Nothing about either number is an RFC value; they are
        // chosen so that a full window leaves 500 bytes no packet can occupy.
        var spec = new TlsQuicRecoverySpec
        {
            InitialCongestionWindow = (DatagramMultiplier: 11, ByteCap: 12_500),
        };
        var controller = Controller(spec, out var clock);
        Assert.Equal(12_500, controller.CongestionWindowBytes);

        var sent = FillWindow(controller, clock.GetUtcNow());

        // Ten packets, 12,000 bytes, 500 bytes of window the sender cannot use.
        Assert.Equal(10, sent.Count);
        Assert.Equal(12_000, controller.BytesInFlight);
        Assert.True(controller.BytesInFlight < controller.CongestionWindowBytes);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked(sent);

        // BOTH READINGS SPELLED. The literal one - "bytes in flight is smaller than the
        // congestion window", which is true here - suppresses every increase and leaves
        // 12,500 forever. This one grows by the windowful acknowledged.
        Assert.Equal(24_500, controller.CongestionWindowBytes);
    }

    // ------------------------------------------------------------------------------
    // s7 and A.4's ACK-ONLY EXCLUSION, from both sides.
    // ------------------------------------------------------------------------------

    [Fact]
    public void AnAckOnlyPacketNeitherCountsInFlightNorGrowsTheWindowWhenAcknowledged()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        var window = controller.CongestionWindowBytes;

        // Fill the window first, so that the acknowledgement below is NOT suppressed by
        // s7.8 - otherwise this test would pass for the wrong reason entirely.
        var real = FillWindow(controller, clock.GetUtcNow());
        Assert.Equal(window, controller.BytesInFlight);

        var ackOnly = Packet(MaxDatagramSize, clock.GetUtcNow(), inFlight: false);
        controller.OnPacketSent(ackOnly);

        // B.2 lines 507-509: "Packets only containing ACK frames do not count toward
        // bytes_in_flight to ensure congestion control does not impede congestion feedback."
        Assert.Equal(window, controller.BytesInFlight);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([ackOnly]);

        // B.5 lines 562-563 return before everything else. s7 lines 32-33: such packets "are
        // not congestion controlled".
        Assert.Equal(window, controller.CongestionWindowBytes);
        Assert.Equal(window, controller.BytesInFlight);
        Assert.NotEmpty(real);
    }

    [Fact]
    public void LosingAnAckOnlyPacketIsNotACongestionEvent()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        var window = controller.CongestionWindowBytes;

        var ackOnly = Packet(MaxDatagramSize, clock.GetUtcNow(), inFlight: false);
        controller.OnPacketSent(ackOnly);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([ackOnly]);

        // B.8 line 622's `if lost_packet.in_flight` gates the whole body, so
        // sent_time_of_last_loss never moves and B.6 is never reached. s7 lines 34-37 make
        // reacting a MAY that "this document does not describe a mechanism for".
        Assert.Equal(TlsQuicCongestionState.SlowStart, controller.State);
        Assert.Equal(window, controller.CongestionWindowBytes);
        Assert.Equal(0, controller.BytesInFlight);

        // THE CALIBRATION: the identical loss of an IN-FLIGHT packet does enter recovery, so
        // the assertion above is about the exclusion and not about losses being ignored.
        var inFlight = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(inFlight);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([inFlight]);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);
    }

    // ------------------------------------------------------------------------------
    // s7's SEND GATE, and B.9's DISCARD.
    // ------------------------------------------------------------------------------

    [Fact]
    public void TheSendGateAdmitsAPacketLandingExactlyOnTheWindowAndRefusesTheNextByte()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        var window = controller.CongestionWindowBytes;

        var room = (int)(window - MaxDatagramSize);
        controller.OnPacketSent(Packet(room, clock.GetUtcNow()));

        // s7 lines 46-47: "MUST NOT send a packet if it would cause bytes_in_flight ... to be
        // LARGER than the congestion window". Larger, so landing exactly on it is permitted -
        // and a controller written with `<` instead of `<=` refuses a legal send at every
        // window boundary for the life of the connection.
        Assert.True(controller.CanSend(MaxDatagramSize));
        Assert.False(controller.CanSend(MaxDatagramSize + 1));

        controller.OnPacketSent(Packet(MaxDatagramSize, clock.GetUtcNow()));
        Assert.Equal(window, controller.BytesInFlight);
        Assert.False(controller.CanSend(1));
        Assert.True(controller.CanSend(0));
    }

    [Fact]
    public void BytesInFlightNeverExceedTheWindowWhenEverySendAsksTheGateFirst()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        // A scripted sequence of mixed sizes, acknowledgements and losses, with the gate
        // consulted before every send exactly as a send path would.
        var sizes = new[] { 1200, 400, 1200, 900, 1200, 1200, 50, 1200 };
        var outstanding = new List<TlsQuicSentPacket>();

        for (var round = 0; round < 12; round++)
        {
            foreach (var size in sizes)
            {
                if (!controller.CanSend(size))
                {
                    continue;
                }

                var packet = Packet(size, clock.GetUtcNow());
                controller.OnPacketSent(packet);
                outstanding.Add(packet);

                Assert.True(
                    controller.BytesInFlight <= controller.CongestionWindowBytes,
                    $"Round {round} put {controller.BytesInFlight} bytes in flight against a "
                        + $"window of {controller.CongestionWindowBytes}.");
            }

            clock.Advance(TimeSpan.FromMilliseconds(1));

            if (round % 4 == 3 && outstanding.Count > 0)
            {
                controller.OnPacketsLost([outstanding[0]]);
                outstanding.RemoveAt(0);
            }

            controller.OnPacketsAcked(outstanding);
            outstanding.Clear();
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        Assert.Equal(0, controller.BytesInFlight);
    }

    [Fact]
    public void DiscardingAPacketRemovesItFromFlightWithoutTouchingTheWindow()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        var window = controller.CongestionWindowBytes;

        var initial = Packet(MaxDatagramSize, clock.GetUtcNow());
        var ackOnly = Packet(MaxDatagramSize, clock.GetUtcNow(), inFlight: false);
        controller.OnPacketSent(initial);
        controller.OnPacketSent(ackOnly);
        Assert.Equal(MaxDatagramSize, controller.BytesInFlight);

        controller.OnPacketsDiscarded([initial, ackOnly]);

        // B.9 lines 650-654 touch bytes in flight and nothing else: a discarded packet is
        // neither delivered nor lost, so no state changes and no window changes.
        Assert.Equal(0, controller.BytesInFlight);
        Assert.Equal(window, controller.CongestionWindowBytes);
        Assert.Equal(TlsQuicCongestionState.SlowStart, controller.State);
    }

    // ------------------------------------------------------------------------------
    // THE SEAM.
    // ------------------------------------------------------------------------------

    // A3-2's knob is a FACTORY, and s7 lines 39-41 say why: "The congestion controller is per
    // path, so packets sent on other paths do not alter the current path's congestion
    // controller." One instance shared between connections would be one path's controller
    // driven by several.
    [Fact]
    public void TheSpecsFactoryKnobProducesAFreshControllerPerCall()
    {
        var spec = new TlsQuicRecoverySpec
        {
            CongestionController = () =>
                new TlsQuicNewRenoCongestionController(
                    new TlsQuicRecoverySpec(), MaxDatagramSize),
        };

        var first = spec.CongestionController!();
        var second = spec.CongestionController!();

        Assert.NotSame(first, second);
        Assert.Equal("NewReno", first.Name);
        Assert.Equal(first.CongestionWindowBytes, second.CongestionWindowBytes);
    }

    // THE SEAM STILL ADMITS A CONTROLLER THAT IS NOT NEWRENO, which is the property the A3
    // plan says matters most about this file - Chromium is reported to run BBR and a seam that
    // only fits NewReno makes that change expensive. This controller has no slow start
    // threshold, no recovery period and no notion of any of the three states, and it satisfies
    // the interface completely.
    [Fact]
    public void TheSeamAdmitsAControllerWithNoSlowStartThresholdAndNoRecoveryPeriod()
    {
        var spec = new TlsQuicRecoverySpec
        {
            CongestionController = () => new FixedRateController(30_000),
        };

        var controller = spec.CongestionController!();
        Assert.Equal("FixedRate", controller.Name);
        Assert.Equal(30_000, controller.CongestionWindowBytes);

        // And it answers every signal the widened seam declares, with a spec whose
        // LossReductionFactor it never reads.
        var signals = Assert.IsAssignableFrom<ITlsQuicCongestionController>(controller);
        var packet = Packet(MaxDatagramSize, Origin);
        signals.OnPacketSent(packet);
        Assert.Equal(MaxDatagramSize, signals.BytesInFlight);
        signals.OnPacketsLost([packet]);
        Assert.Equal(30_000, signals.CongestionWindowBytes);
        Assert.True(signals.CanSend(30_000));
    }

    // ------------------------------------------------------------------------------
    // THE EQUAL-INSTANT BOUNDARIES, AND THE OTHER GAPS A MUTATION SWEEP FOUND. Every
    // test above advances the fake clock between a send and the loss that follows it,
    // so both of s7.3.2's boundary comparisons could be moved by one notch and nothing
    // noticed. A real sender coalesces a send and a loss detection into one clock
    // reading routinely; the fake clock only makes it exact.
    // ------------------------------------------------------------------------------

    [Fact]
    public void APacketSentAtTheVeryInstantRecoveryBeganIsAnOldPacketOnBothBoundaries()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        // THREE PACKETS AND NO CLOCK MOVEMENT AT ALL, so every send time equals the
        // instant the recovery period will start at.
        var opener = Packet(MaxDatagramSize, clock.GetUtcNow());
        var acked = Packet(MaxDatagramSize, clock.GetUtcNow());
        var straggler = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(opener);
        controller.OnPacketSent(acked);
        controller.OnPacketSent(straggler);

        controller.OnPacketsLost([opener]);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);
        Assert.Equal(6_000, controller.CongestionWindowBytes);

        // BOUNDARY ONE - B.5 line 555's `sent_time <= congestion_recovery_start_time`.
        // This packet was sent AT the start instant, so it was not "sent during the
        // recovery period" and does not end it. Moving that comparison by one notch
        // ends the period here.
        controller.OnPacketsAcked([acked]);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);

        // BOUNDARY TWO - B.6 lines 591-592's guard, the same comparison from the loss
        // side. Moving it to < opens a second recovery period and halves 6,000 to 3,000.
        controller.OnPacketsLost([straggler]);
        Assert.Equal(6_000, controller.CongestionWindowBytes);
        Assert.Equal(3_000, (long)(6_000 * spec.LossReductionFactor));

        // THE CALIBRATION FOR BOTH: one tick later, the same two events do what the
        // assertions above deny. Without it, a controller frozen in recovery forever
        // passes everything here.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        var afterwards = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(afterwards);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([afterwards]);
        Assert.Equal(TlsQuicCongestionState.CongestionAvoidance, controller.State);
    }

    // s7.3.2 lines 155-158 from the ACKNOWLEDGEMENT side, which B.5 lines 570-572
    // implement: the window does not change in response to acknowledgements of packets
    // sent before the recovery period either. A WHOLE WINDOW of old packets is what
    // makes the difference visible - acknowledging one would accumulate too little to
    // move the window even with the suppression gone.
    [Fact]
    public void AWindowfulOfPacketsSentBeforeRecoveryDoesNotGrowTheWindowDuringIt()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        var sent = FillWindow(controller, clock.GetUtcNow());
        Assert.Equal(10, sent.Count);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([sent[0]]);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);
        Assert.Equal(6_000, controller.CongestionWindowBytes);

        // Nine old packets, 10,800 bytes - nearly two of the reduced window.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([.. sent.Skip(1)]);

        // Without the suppression these nine add a datagram to the window; both numbers
        // are spelled, and 7,200 is an entirely ordinary-looking congestion window.
        Assert.Equal(6_000, controller.CongestionWindowBytes);
        Assert.Equal(7_200, 6_000 + MaxDatagramSize);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);
    }

    // B.6 line 595 sets congestion_recovery_start_time to NOW, not to the send time of
    // the packet whose loss opened the period. The difference is every packet already on
    // the wire when the loss was detected: those were sent before the period began and
    // must not end it. AN EARLIER DRAFT OF THIS FILE USED THE LOST PACKET'S SEND TIME
    // and no test in it could tell.
    [Fact]
    public void TheRecoveryPeriodRunsFromTheDetectionInstantAndNotTheLostPacketsSendTime()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        var lost = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(lost);

        // Sent AFTER the packet that will be lost, and BEFORE the loss is detected.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        var inTheAir = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(inTheAir);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([lost]);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);

        // Its send time is later than the lost packet's and earlier than the detection,
        // so it ends the period under the wrong reading and not under B.6's.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([inTheAir]);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);

        // THE CALIBRATION: a packet sent after the detection does end it.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        var afterwards = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(afterwards);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([afterwards]);
        Assert.Equal(TlsQuicCongestionState.CongestionAvoidance, controller.State);
    }

    // B.8 lines 624-625 take the MAXIMUM send time across the lost packets, and B.6's
    // guard is what makes the choice matter: a batch mixing one straggler from before
    // the current recovery period with one genuinely new loss must open a new period on
    // the strength of the new one.
    [Fact]
    public void ALossBatchIsJudgedByItsNewestPacketAndNotItsOldest()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        var opener = Packet(MaxDatagramSize, clock.GetUtcNow());
        var straggler = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(opener);
        controller.OnPacketSent(straggler);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([opener]);
        Assert.Equal(6_000, controller.CongestionWindowBytes);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        var fresh = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(fresh);

        // ONE BATCH, TWO ERAS. The straggler predates the recovery period; the fresh
        // packet postdates it. B.8's max picks the fresh one and a second reduction
        // follows; a min picks the straggler, B.6 returns early, and 6,000 stands.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([straggler, fresh]);

        Assert.Equal(3_000, controller.CongestionWindowBytes);
        Assert.Equal(6_000, 3_000 * 2);
    }

    // A congestion event halves the window, so a partial window of acknowledged bytes
    // accumulated under the OLD window is no longer a fraction of anything. Carried
    // over, it grants the next state an increase earned against a window twice the size.
    [Fact]
    public void ACongestionEventDiscardsTheCongestionAvoidanceAccumulator()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        EnterCongestionAvoidance(controller, clock);
        Assert.Equal(6_000, controller.CongestionWindowBytes);

        // Four fifths of a window acknowledged: enough to be carried, not enough to grow.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        var sent = FillWindow(controller, clock.GetUtcNow());
        Assert.Equal(5, sent.Count);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([.. sent.Take(4)]);
        Assert.Equal(6_000, controller.CongestionWindowBytes);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        var doomed = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(doomed);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([doomed]);
        Assert.Equal(3_000, controller.CongestionWindowBytes);

        // One packet acknowledged against the new window. With the accumulator reset it
        // is 1,200 of 3,000 and moves nothing; carried over it is 6,000 of 3,000 and
        // grants a datagram immediately.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        var next = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(next);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([next]);

        Assert.Equal(3_000, controller.CongestionWindowBytes);
        Assert.Equal(4_200, 3_000 + MaxDatagramSize);
    }

    // B.5 line 575 grows the window by THE BYTES ACKNOWLEDGED, not by a datagram. Every
    // other slow start test here sends maximum-size packets, where the two are the same
    // number - so this is the only place the distinction is visible, and a sweep is what
    // showed the distinction was untested.
    [Fact]
    public void SlowStartGrowsByTheBytesAcknowledgedAndNotByAWholeDatagram()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);
        Assert.Equal(12_000, controller.CongestionWindowBytes);

        // Nine full datagrams and one short one, filling 11,200 of 12,000 - with no room
        // for an eleventh, so s7.8 does not call this sender application limited.
        var full = SendAt(controller, clock.GetUtcNow(), 9);
        var runt = Packet(400, clock.GetUtcNow());
        controller.OnPacketSent(runt);
        Assert.Equal(9, full.Count);
        Assert.Equal(11_200, controller.BytesInFlight);
        Assert.False(controller.CanSend(MaxDatagramSize));

        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([runt]);

        // 400 bytes acknowledged, 400 bytes of growth. A datagram's worth would be 13,200.
        Assert.Equal(12_400, controller.CongestionWindowBytes);
        Assert.Equal(13_200, 12_000 + MaxDatagramSize);
        Assert.Equal(TlsQuicCongestionState.SlowStart, controller.State);
    }

    // ------------------------------------------------------------------------------
    // TOTALITY.
    // ------------------------------------------------------------------------------

    // NOTHING ON A SIGNAL PATH THROWS FOR ANY INPUT. A controller that threw on an
    // acknowledgement would take the connection down at the exact moment the network was
    // already misbehaving, and the send path has no recovery from it.
    [Fact]
    public void NoSignalThrowsForAnyInputIncludingFabricatedAndDegenerateOnes()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        var exception = Record.Exception(() =>
        {
            controller.OnPacketsAcked(null);
            controller.OnPacketsLost(null);
            controller.OnPacketsDiscarded(null);
            controller.OnPacketsAcked([]);
            controller.OnPacketsLost([]);
            controller.OnPacketsDiscarded([]);

            // Sizes no builder produces.
            foreach (var size in new[] { 0, -1, int.MinValue, int.MaxValue })
            {
                var packet = Packet(size, clock.GetUtcNow());
                controller.OnPacketSent(packet);
                controller.OnPacketsAcked([packet]);
                controller.OnPacketsLost([packet]);
                controller.OnPacketsDiscarded([packet]);
                _ = controller.CanSend(size);
                _ = controller.State;
                _ = controller.SlowStartThresholdBytes;
            }

            // Times no clock produces, including the zero instant B.8's sentinel collides
            // with and the far end of the range.
            foreach (var when in new[] { DateTimeOffset.MinValue, DateTimeOffset.MaxValue })
            {
                var packet = Packet(MaxDatagramSize, when);
                controller.OnPacketSent(packet);
                controller.OnPacketsLost([packet]);
                controller.OnPacketsAcked([packet]);
            }

            // The same packet reported twice, which no RFC 9002 rule forbids a caller doing
            // because the deduplicating function A.7 names is one the document never defines.
            var twice = Packet(MaxDatagramSize, clock.GetUtcNow());
            controller.OnPacketSent(twice);
            controller.OnPacketsAcked([twice, twice]);
            controller.OnPacketsLost([twice, twice]);
            controller.OnPacketsDiscarded([twice, twice]);

            // Saturation: enough fabricated maximum-size packets to overflow a long.
            for (var i = 0; i < 8; i++)
            {
                controller.OnPacketSent(Packet(int.MaxValue, clock.GetUtcNow()));
                controller.OnPacketsAcked([Packet(int.MaxValue, clock.GetUtcNow())]);
            }

            _ = controller.CanSend(int.MaxValue);
        });

        Assert.Null(exception);

        // AND THE INVARIANT THAT MATTERS SURVIVED IT. A negative bytes-in-flight or a negative
        // window would open the send gate to everything, which is the one failure a congestion
        // controller exists to prevent, and "it did not throw" would not have noticed.
        Assert.True(controller.BytesInFlight >= 0);
        Assert.True(controller.CongestionWindowBytes >= 0);
        Assert.True(controller.SlowStartThresholdBytes >= 0);
    }

    [Fact]
    public void ConstructionRejectsWhatIsAProgrammingErrorRatherThanANetworkEvent()
    {
        Assert.Throws<ArgumentNullException>(
            () => new TlsQuicNewRenoCongestionController(null!, MaxDatagramSize));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicNewRenoCongestionController(new TlsQuicRecoverySpec(), 0));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicNewRenoCongestionController(new TlsQuicRecoverySpec(), -1));
        Assert.Throws<ArgumentNullException>(
            () => TlsQuicNewRenoCongestionController.InitialWindowFor(null!, MaxDatagramSize));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => TlsQuicNewRenoCongestionController.InitialWindowFor(
                new TlsQuicRecoverySpec(), 0));
    }

    // ------------------------------------------------------------------------------
    // s7.6 PERSISTENT CONGESTION - the duration, then the four clauses, then the collapse.
    //
    // NOTHING BELOW CAN BE CHECKED AGAINST PSEUDOCODE, WHICH CHANGES WHAT THESE TESTS HAVE TO
    // DO. rfc9002-appendix-a-and-b-pseudocode-and-constants.txt lines 21-28 record that
    // InPersistentCongestion is "called and never defined anywhere in this document" and that
    // s7.6.1's duration has no pseudocode at all. So every expectation here is written from
    // s7.6's PROSE, and wherever a different reading of that prose would give a different
    // number, BOTH numbers are spelled out - so a test that merely agreed with the
    // implementation's mistake would have to state the mistake.
    //
    // AND THE MUTANT THIS BLOCK EXISTS FOR is the one A3-9 refused to write: a predicate that
    // takes only s7.6.2's duration clause and ignores the other three. It collapses the window
    // on any two losses far enough apart, and it passes every "persistent congestion collapses
    // the window" assertion. The tests that kill it are the four negative ones - single loss,
    // ACK-only loss, an acknowledgement inside the blackout, and no RTT sample - not the
    // positive one.
    // ------------------------------------------------------------------------------

    [Fact]
    public void ThePersistentCongestionDurationIsSection761sFormulaOverALiveEstimator()
    {
        var spec = new TlsQuicRecoverySpec();
        var (smoothedRtt, rttVariation, _) = LiveEstimator();
        var maxAckDelay = TlsQuicAckTracker.DefaultMaxAckDelay;

        var duration = TlsQuicPersistentCongestion.DurationFor(
            spec, smoothedRtt, rttVariation, maxAckDelay);

        // rfc9002-section7-congestion-control.txt lines 209-214, transcribed here independently
        // of the implementation and out of the estimator's OWN numbers rather than any literal:
        //   (smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay)
        //       * kPersistentCongestionThreshold
        var expected = new TimeSpan(
            (smoothedRtt.Ticks
                + Math.Max(4 * rttVariation.Ticks, TlsQuicConnection.KGranularity.Ticks)
                + maxAckDelay.Ticks)
            * spec.PersistentCongestionThreshold);

        Assert.Equal(expected, duration);

        // AND THE THRESHOLD IS KNOB 8 AND NOT THE LITERAL 3. A second spec with a different
        // multiplier must move the duration by exactly that ratio, which a hard-coded 3 cannot.
        var doubled = new TlsQuicRecoverySpec
        {
            PersistentCongestionThreshold = spec.PersistentCongestionThreshold * 2,
        };

        Assert.Equal(
            duration * 2,
            TlsQuicPersistentCongestion.DurationFor(
                doubled, smoothedRtt, rttVariation, maxAckDelay));
    }

    [Fact]
    public void TheDurationDoesNotCarrySection621sProbeBackoffAndTheTwoCandidatesAreSpelledOut()
    {
        // s7.6.1 lines 236-242: "This design does not use consecutive PTO events to establish
        // persistent congestion, since application patterns impact PTO expiration ... The use of
        // a duration enables a sender to establish persistent congestion without depending on PTO
        // expiration." A duration built by calling into s6.2.1's PTO computation would carry
        // `PtoBackoff.Factor ^ pto_count` with it and grow every time the sender probed.
        var spec = new TlsQuicRecoverySpec();
        var (smoothedRtt, rttVariation, _) = LiveEstimator();
        var maxAckDelay = TlsQuicAckTracker.DefaultMaxAckDelay;

        var actual = TlsQuicPersistentCongestion.DurationFor(
            spec, smoothedRtt, rttVariation, maxAckDelay);

        var ptoPeriod = smoothedRtt.Ticks
            + Math.Max(4 * rttVariation.Ticks, TlsQuicConnection.KGranularity.Ticks)
            + maxAckDelay.Ticks;

        // CANDIDATE A - s7.6.1's reading: the unbacked-off period times the threshold.
        var withoutBackoff = new TimeSpan(ptoPeriod * spec.PersistentCongestionThreshold);

        // CANDIDATE B - the reading that reuses s6.2.1 after two probes have already expired.
        var afterTwoProbes = new TimeSpan(
            (long)(ptoPeriod * Math.Pow(spec.PtoBackoff.Factor, 2))
            * spec.PersistentCongestionThreshold);

        Assert.NotEqual(withoutBackoff, afterTwoProbes);
        Assert.Equal(withoutBackoff, actual);
        Assert.NotEqual(afterTwoProbes, actual);
    }

    [Fact]
    public void TheDurationIncludesMaxAckDelayForEverySpaceAndBothCandidatesAreSpelledOut()
    {
        // s7.6.1 lines 216-219: "Unlike the PTO computation in Section 6.2, this duration
        // includes the max_ack_delay IRRESPECTIVE of the packet number spaces in which losses
        // are established." A.8 adds max_ack_delay for Application Data only, and
        // TlsQuicConnection.PtoDuration is called with zero for Initial and Handshake - so a
        // handshake-space blackout under s6.2.1's rule would be judged against a SHORTER
        // duration and declared persistently congested sooner than s7.6 allows.
        var spec = new TlsQuicRecoverySpec();
        var (smoothedRtt, rttVariation, _) = LiveEstimator();
        var maxAckDelay = TlsQuicAckTracker.DefaultMaxAckDelay;

        var withDelay = TlsQuicPersistentCongestion.DurationFor(
            spec, smoothedRtt, rttVariation, maxAckDelay);
        var withoutDelay = TlsQuicPersistentCongestion.DurationFor(
            spec, smoothedRtt, rttVariation, TimeSpan.Zero);

        // The two candidates differ by exactly the term, times the threshold.
        Assert.Equal(
            new TimeSpan(maxAckDelay.Ticks * spec.PersistentCongestionThreshold),
            withDelay - withoutDelay);
        Assert.True(withDelay > withoutDelay);

        // AND THE SIGNATURE ITSELF IS THE STATEMENT: there is no packet number space parameter
        // to pass, so there is no space for which the term can be dropped. Nothing to assert
        // beyond the two numbers, which is why they are both here.
    }

    [Fact]
    public void TheFourRttvarTermIsFlooredAtTheTimerGranularityAndNotTheWholeSum()
    {
        // The parentheses in s7.6.1's line put max(...) around the rttvar term ALONE. A tiny
        // rttvar therefore contributes kGranularity and not zero - and the floor must not be
        // applied to the sum, which would be invisible whenever smoothed_rtt already exceeded it.
        var spec = new TlsQuicRecoverySpec();
        var maxAckDelay = TlsQuicAckTracker.DefaultMaxAckDelay;
        var smoothedRtt = TimeSpan.FromMilliseconds(40);
        var tinyVariation = new TimeSpan(TlsQuicConnection.KGranularity.Ticks / 8);

        Assert.True(4 * tinyVariation.Ticks < TlsQuicConnection.KGranularity.Ticks);

        var actual = TlsQuicPersistentCongestion.DurationFor(
            spec, smoothedRtt, tinyVariation, maxAckDelay);

        // CANDIDATE A - the floor on the term, which is what the parentheses say.
        var flooredTerm = new TimeSpan(
            (smoothedRtt.Ticks + TlsQuicConnection.KGranularity.Ticks + maxAckDelay.Ticks)
            * spec.PersistentCongestionThreshold);

        // CANDIDATE B - no floor at all, which is what a transcription that dropped the max
        // would give. This is the defect already found once in this subsystem at s6.2.1.
        var unfloored = new TimeSpan(
            (smoothedRtt.Ticks + (4 * tinyVariation.Ticks) + maxAckDelay.Ticks)
            * spec.PersistentCongestionThreshold);

        Assert.NotEqual(flooredTerm, unfloored);
        Assert.Equal(flooredTerm, actual);
    }

    [Fact]
    public void TheDurationIsTotalAndStrictlyPositiveForEveryInputIncludingNonsensicalOnes()
    {
        var spec = new TlsQuicRecoverySpec();

        // A negative smoothed_rtt cannot come from A3-4's estimator, and it is guarded anyway
        // because the failure is one-sided: a non-positive duration makes EVERY pair of losses
        // exceed it and collapses the window on any loss at all.
        TimeSpan[] hostile =
        [
            TimeSpan.Zero,
            TimeSpan.MinValue,
            TimeSpan.MaxValue,
            new TimeSpan(-1),
            new TimeSpan(1),
            TimeSpan.FromDays(1000),
        ];

        foreach (var a in hostile)
        {
            foreach (var b in hostile)
            {
                foreach (var c in hostile)
                {
                    var duration = TlsQuicPersistentCongestion.DurationFor(spec, a, b, c);
                    Assert.True(
                        duration > TimeSpan.Zero,
                        $"DurationFor({a}, {b}, {c}) returned {duration}, which would make every "
                            + "loss persistent congestion.");
                    Assert.True(duration >= TlsQuicConnection.KGranularity);
                }
            }
        }

        // The spec is the one programming error rather than a network event, exactly as
        // InitialWindowFor treats its own.
        Assert.Throws<ArgumentNullException>(
            () => TlsQuicPersistentCongestion.DurationFor(
                null!, TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero));
    }

    // ---- s7.6.2's four clauses, one negative witness each -------------------------

    [Fact]
    public void ABlackoutSpanningMoreThanTheDurationIsPersistentCongestion()
    {
        var spec = new TlsQuicRecoverySpec();
        var duration = Duration(spec, out var firstRttSampleAt);

        // Two ack-eliciting packets, one gap, strictly longer than the duration.
        var oldest = Packet(MaxDatagramSize, firstRttSampleAt + OneTick);
        var newest = Packet(MaxDatagramSize, oldest.SentAt + duration + OneTick);

        Assert.True(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, newest], firstRttSampleAt, default, duration));
    }

    [Fact]
    public void ABlackoutExactlyEqualToTheDurationIsNotPersistentCongestionBecauseExceedsIsStrict()
    {
        // s7.6.2 line 255: "the duration between the send times of these two packets EXCEEDS the
        // persistent congestion duration". s7.6.3's worked example is 7 against 6 and never
        // touches the boundary, so the word is the only evidence there is. Written >= this
        // declares persistent congestion one tick early, and no test built out of round numbers
        // would ever see it.
        var spec = new TlsQuicRecoverySpec();
        var duration = Duration(spec, out var firstRttSampleAt);

        var oldest = Packet(MaxDatagramSize, firstRttSampleAt + OneTick);
        var exactly = Packet(MaxDatagramSize, oldest.SentAt + duration);
        var oneTickMore = Packet(MaxDatagramSize, oldest.SentAt + duration + OneTick);

        Assert.False(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, exactly], firstRttSampleAt, default, duration));

        // ONE TICK APART, AND THE VERDICTS DIFFER: the boundary is where it is claimed to be
        // rather than merely somewhere in a wide gap.
        Assert.True(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, oneTickMore], firstRttSampleAt, default, duration));
    }

    [Fact]
    public void ASingleAckElicitingLossIsNeverPersistentCongestionHoweverOldItIs()
    {
        // s7.6.2 line 247: "TWO packets that are ack-eliciting are declared lost". One packet
        // spans no interval at all, whatever the blackout around it looked like.
        var spec = new TlsQuicRecoverySpec();
        var duration = Duration(spec, out var firstRttSampleAt);

        var only = Packet(MaxDatagramSize, firstRttSampleAt + duration + duration);

        Assert.False(TlsQuicPersistentCongestion.IsEstablished(
            [only], firstRttSampleAt, default, duration));

        // AND NOT BY REPETITION EITHER. The same packet listed twice is still one send time.
        Assert.False(TlsQuicPersistentCongestion.IsEstablished(
            [only, only], firstRttSampleAt, default, duration));
    }

    [Fact]
    public void ABlackoutOfAckOnlyPacketsIsNotPersistentCongestion()
    {
        // s7.6.2 lines 258-261: "These two packets MUST be ack-eliciting, since a receiver is
        // required to acknowledge only ack-eliciting packets within its maximum acknowledgment
        // delay". B.8's own pc_lost list applies no such filter, so a body written to match B.8's
        // call site drops this clause - and then a long silence of ACK-only packets, which the
        // peer was never obliged to acknowledge, reads as a blackout.
        var spec = new TlsQuicRecoverySpec();
        var duration = Duration(spec, out var firstRttSampleAt);

        var oldest = Packet(MaxDatagramSize, firstRttSampleAt + OneTick, inFlight: false);
        var newest = Packet(
            MaxDatagramSize, oldest.SentAt + duration + duration, inFlight: false);

        Assert.False(oldest.IsAckEliciting);
        Assert.False(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, newest], firstRttSampleAt, default, duration));

        // THE SAME TWO SEND TIMES, ACK-ELICITING THIS TIME, DO QUALIFY - so the verdict turns on
        // the flag and not on the times.
        Assert.True(TlsQuicPersistentCongestion.IsEstablished(
            [Packet(MaxDatagramSize, oldest.SentAt), Packet(MaxDatagramSize, newest.SentAt)],
            firstRttSampleAt,
            default,
            duration));
    }

    [Fact]
    public void AnAcknowledgementInsideTheBlackoutPreventsPersistentCongestion()
    {
        // s7.6.2 lines 251-253: "across all packet number spaces, NONE of the packets sent
        // between the send times of these two packets are acknowledged". A path that delivered
        // something in the middle was not blacked out, and B.8's pc_lost argument carries no way
        // to know it - which is why this predicate takes the acknowledgement's send time.
        var spec = new TlsQuicRecoverySpec();
        var duration = Duration(spec, out var firstRttSampleAt);

        var oldest = Packet(MaxDatagramSize, firstRttSampleAt + OneTick);
        var newest = Packet(MaxDatagramSize, oldest.SentAt + duration + duration);
        var acknowledgedInTheMiddle = oldest.SentAt + duration;

        Assert.True(acknowledgedInTheMiddle > oldest.SentAt);
        Assert.True(acknowledgedInTheMiddle < newest.SentAt);

        Assert.False(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, newest], firstRttSampleAt, acknowledgedInTheMiddle, duration));

        // s7.6.3's OWN EXAMPLE IS THE OTHER SIDE OF THIS. Packet #1 is acknowledged at t=1.2 but
        // was SENT at t=0, before the lost run began - so an acknowledgement of something sent
        // BEFORE the window does not disqualify it.
        Assert.True(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, newest], firstRttSampleAt, oldest.SentAt - OneTick, duration));

        // AND THE BOUNDARY IS EXACTLY WHERE THE WORD BETWEEN PUTS IT, pinned one tick either
        // side. s7.6.2 line 252 says "sent BETWEEN the send times of these two packets", and
        // between excludes its endpoints: an acknowledgement of a packet sent at the very instant
        // the oldest LOST packet was sent is not between them, and one tick later is. A sender
        // that fills its window in a burst puts several packets on one timestamp constantly, so
        // reading this boundary the other way throws away whole qualifying blackouts.
        Assert.True(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, newest], firstRttSampleAt, oldest.SentAt, duration));
        Assert.False(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, newest], firstRttSampleAt, oldest.SentAt + OneTick, duration));
    }

    [Fact]
    public void WithNoRttSampleYetNothingIsPersistentCongestion()
    {
        // B.8 line 635: `if (first_rtt_sample == 0): return`. s7.6.2 lines 262-267 give the
        // reason - before the first sample the PTO is armed off an INITIAL RTT that "could be
        // substantially larger than the actual RTT", so the sender has probed too few times to
        // have learned anything.
        var spec = new TlsQuicRecoverySpec();
        var duration = Duration(spec, out var firstRttSampleAt);

        var oldest = Packet(MaxDatagramSize, firstRttSampleAt + OneTick);
        var newest = Packet(MaxDatagramSize, oldest.SentAt + duration + duration);

        Assert.False(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, newest], firstRttSampleAt: null, default, duration));

        // The identical loss, once a sample exists, does qualify.
        Assert.True(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, newest], firstRttSampleAt, default, duration));
    }

    [Fact]
    public void PacketsSentBeforeTheFirstRttSampleAreNotCandidatesEvenOnceASampleExists()
    {
        // THE SECOND HALF OF B.8's RULE, AND THE ONE AN IMPLEMENTATION FORGETS. Lines 636-638:
        // `for lost in lost_packets: if lost.time_sent > first_rtt_sample: pc_lost.insert(lost)`.
        // Keeping only the early return leaves a sender that got its first sample late still able
        // to declare persistent congestion over a stretch it sent while it was guessing.
        var spec = new TlsQuicRecoverySpec();
        var duration = Duration(spec, out var firstRttSampleAt);

        var beforeTheSample = Packet(MaxDatagramSize, firstRttSampleAt - duration - duration);
        var atTheSample = Packet(MaxDatagramSize, firstRttSampleAt);
        var afterTheSample = Packet(MaxDatagramSize, firstRttSampleAt + OneTick);
        var farAfterTheSample =
            Packet(MaxDatagramSize, afterTheSample.SentAt + duration + OneTick);

        // EVERY PAIR BELOW SPANS MORE THAN THE DURATION, which is what makes the three verdicts
        // turn on the filter alone. A pair whose span was short would answer false for the
        // filter's reasons and for the duration's at the same time, and would then survive any
        // mutation of either.
        Assert.True(farAfterTheSample.SentAt - beforeTheSample.SentAt > duration);
        Assert.True(farAfterTheSample.SentAt - atTheSample.SentAt > duration);
        Assert.True(farAfterTheSample.SentAt - afterTheSample.SentAt > duration);

        // Only one of these two is a candidate - so there are not two, and there is no
        // persistent congestion however far apart they were sent.
        Assert.False(TlsQuicPersistentCongestion.IsEstablished(
            [beforeTheSample, farAfterTheSample], firstRttSampleAt, default, duration));

        // AT the sample is not AFTER it. B.8 line 637 is `if lost.time_sent > first_rtt_sample`,
        // strictly - and this pair is the one-tick witness for it, because moving the boundary
        // by a single tick admits atTheSample and turns this verdict over.
        Assert.False(TlsQuicPersistentCongestion.IsEstablished(
            [atTheSample, farAfterTheSample], firstRttSampleAt, default, duration));

        // One tick later, and it qualifies.
        Assert.True(TlsQuicPersistentCongestion.IsEstablished(
            [afterTheSample, farAfterTheSample], firstRttSampleAt, default, duration));
    }

    [Fact]
    public void NoPersistentCongestionInputThrowsIncludingFabricatedAndDegenerateOnes()
    {
        var spec = new TlsQuicRecoverySpec();
        var duration = Duration(spec, out var firstRttSampleAt);
        var controller = Controller(spec, out _);

        List<TlsQuicSentPacket> extremes =
        [
            Packet(int.MinValue, DateTimeOffset.MinValue),
            Packet(int.MaxValue, DateTimeOffset.MaxValue),
            Packet(0, firstRttSampleAt),
            Packet(-1, firstRttSampleAt + duration, inFlight: false),
        ];

        // A NULL LIST, AN EMPTY ONE, AND THE HOSTILE ONE - and a non-positive duration, which
        // only a caller that did not use DurationFor can produce and whose safe answer is "no".
        TimeSpan[] durations = [duration, TimeSpan.Zero, TimeSpan.MinValue, new TimeSpan(-1)];
        DateTimeOffset?[] samples = [null, firstRttSampleAt, DateTimeOffset.MaxValue];

        foreach (var d in durations)
        {
            foreach (var sample in samples)
            {
                _ = TlsQuicPersistentCongestion.IsEstablished(null, sample, default, d);
                _ = TlsQuicPersistentCongestion.IsEstablished([], sample, default, d);
                _ = TlsQuicPersistentCongestion.IsEstablished(
                    extremes, sample, DateTimeOffset.MaxValue, d);
                _ = TlsQuicPersistentCongestion.IsEstablished(
                    extremes, sample, DateTimeOffset.MinValue, d);
            }
        }

        // A NON-POSITIVE DURATION MUST NOT COLLAPSE ANYTHING. Without the guard, a zero duration
        // turns this predicate into "any two ack-eliciting losses at different times", which is
        // exactly the half-implementation A3-9 declined to write.
        var oldest = Packet(MaxDatagramSize, firstRttSampleAt + OneTick);
        var newest = Packet(MaxDatagramSize, oldest.SentAt + OneTick);
        Assert.False(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, newest], firstRttSampleAt, default, TimeSpan.Zero));
        Assert.False(TlsQuicPersistentCongestion.IsEstablished(
            [oldest, newest], firstRttSampleAt, default, new TimeSpan(-1)));

        // And the collapse itself is total and idempotent on a controller that never sent.
        controller.OnPersistentCongestion();
        controller.OnPersistentCongestion();
        Assert.Equal(
            (long)spec.MinimumCongestionWindowDatagrams * MaxDatagramSize,
            controller.CongestionWindowBytes);
    }

    // ---- s7.6.2's collapse ---------------------------------------------------------

    [Fact]
    public void PersistentCongestionCollapsesTheWindowToExactlyTheSpecsMinimumAndReEntersSlowStart()
    {
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        EnterCongestionAvoidance(controller, clock);
        var beforeCollapse = controller.CongestionWindowBytes;
        var threshold = controller.SlowStartThresholdBytes;
        var minimum = (long)spec.MinimumCongestionWindowDatagrams * MaxDatagramSize;

        Assert.True(beforeCollapse > minimum);
        Assert.Equal(TlsQuicCongestionState.CongestionAvoidance, controller.State);

        controller.OnPersistentCongestion();

        // s7.6.2 lines 276-279: "the sender's congestion window MUST be reduced to the minimum
        // congestion window (kMinimumWindow)". EXACTLY the minimum, from A3-2's knob - not a
        // further halving, and not a floor that happens to be near it.
        Assert.Equal(minimum, controller.CongestionWindowBytes);

        // s7.3.1 lines 131-133: "A sender re-enters slow start any time the congestion window is
        // less than ssthresh, which only occurs after persistent congestion is declared." This is
        // the transition, and it is DERIVED: the threshold was not touched.
        Assert.Equal(threshold, controller.SlowStartThresholdBytes);
        Assert.True(controller.CongestionWindowBytes < controller.SlowStartThresholdBytes);
        Assert.Equal(TlsQuicCongestionState.SlowStart, controller.State);
    }

    [Fact]
    public void TheCollapseAssignsTheMinimumRatherThanReducingTowardIt()
    {
        // THE MUTATION THIS TEST EXISTS FOR is Math.Min, which is the natural shape for a word
        // like "collapse" and is silently wrong. It is only visible through a spec whose window
        // starts BELOW its own minimum - which A3-9 deliberately allows, because s7.2 lines 83-85
        // scope the minimum to reductions and a one-datagram initial window is a fingerprint
        // rather than a mistake (A39-M04). s7.6.2's MUST names the value, not a direction.
        var spec = new TlsQuicRecoverySpec
        {
            InitialCongestionWindow = (1, 1),
            MinimumCongestionWindowDatagrams = 8,
        };
        var controller = Controller(spec, out _);

        var minimum = (long)spec.MinimumCongestionWindowDatagrams * MaxDatagramSize;
        Assert.True(controller.CongestionWindowBytes < minimum);

        controller.OnPersistentCongestion();

        Assert.Equal(minimum, controller.CongestionWindowBytes);
    }

    [Fact]
    public void TheCollapseEndsTheRecoveryPeriodSoTheNextLossReducesAgain()
    {
        // B.8 line 640: `congestion_recovery_start_time = 0`. B has no recovery flag - B.5 line
        // 555 derives the period from the timestamp - so this class must clear both, and clearing
        // only the timestamp would leave State reporting Recovery forever.
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        var first = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(first);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([first]);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);

        controller.OnPersistentCongestion();
        Assert.NotEqual(TlsQuicCongestionState.Recovery, controller.State);

        // AND THE PERIOD IS GENUINELY GONE, not merely unreported: a later loss opens a NEW
        // period, which B.6's guard would have refused while the old start time survived.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        var second = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(second);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([second]);

        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);
    }

    [Fact]
    public void TheCollapseLeavesBytesInFlightAlone()
    {
        // Persistent congestion is a statement about the WINDOW. The packets that established it
        // were already removed from flight by OnPacketsLost; zeroing the counter here would
        // double-subtract them and open the send gate to everything.
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        var sent = SendAt(controller, clock.GetUtcNow(), 3);
        var inFlight = controller.BytesInFlight;
        Assert.Equal(sent.Count * (long)MaxDatagramSize, inFlight);

        controller.OnPersistentCongestion();

        Assert.Equal(inFlight, controller.BytesInFlight);
    }

    [Fact]
    public void TheCollapseDiscardsTheRecoveryPeriodsStartTimeSoAStragglerStillOpensANewOne()
    {
        // THE ROW THIS TEST EXISTS FOR SURVIVED THE FIRST SWEEP. Clearing the recovery FLAG and
        // leaving B.8 line 640's `congestion_recovery_start_time = 0` undone looks harmless -
        // State reports slow start either way, because State consults the flag first. The
        // difference is invisible until a loss arrives whose packet was sent BEFORE the period
        // that has just been discarded: B.6's guard is `sent_time <=
        // congestion_recovery_start_time`, so a start time left standing refuses that loss
        // outright and the sender takes no congestion event for it at all.
        var spec = new TlsQuicRecoverySpec();
        var controller = Controller(spec, out var clock);

        var straggler = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(straggler);
        clock.Advance(TimeSpan.FromMilliseconds(5));
        var newer = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(newer);

        clock.Advance(TimeSpan.FromMilliseconds(5));
        controller.OnPacketsLost([newer]);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);

        controller.OnPersistentCongestion();
        Assert.Equal(TlsQuicCongestionState.SlowStart, controller.State);

        // The straggler was sent BEFORE the period the collapse just discarded, so it is exactly
        // the loss the stale start time would swallow.
        Assert.True(straggler.SentAt < newer.SentAt);
        controller.OnPacketsLost([straggler]);

        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);
    }

    [Fact]
    public void TheCollapseDiscardsTheCongestionAvoidanceAccumulator()
    {
        // ALSO A FIRST-SWEEP SURVIVOR, and reachable rather than vacuous - it just needs the
        // controller to land in congestion avoidance ON the collapse rather than in slow start,
        // which happens whenever the spec's minimum window is at or above the surviving ssthresh.
        // A3-9 argued the same point for OnCongestionEvent: bytes counted toward one whole
        // congestion window are meaningless once the window has become a different size, and
        // carrying them over grants the next state an increase earned under the old one.
        var spec = new TlsQuicRecoverySpec { MinimumCongestionWindowDatagrams = 6 };
        var controller = Controller(spec, out var clock);
        EnterCongestionAvoidance(controller, clock);

        var window = controller.CongestionWindowBytes;
        var minimum = (long)spec.MinimumCongestionWindowDatagrams * MaxDatagramSize;
        Assert.Equal(minimum, window);
        Assert.Equal(TlsQuicCongestionState.CongestionAvoidance, controller.State);

        // Fill the window and acknowledge all but one, which accumulates almost a whole window
        // without completing one - so the window has not moved and the accumulator is loaded.
        var sent = FillWindow(controller, clock.GetUtcNow());
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked(sent.Take(sent.Count - 1).ToList());
        Assert.Equal(window, controller.CongestionWindowBytes);

        // Refill so the last acknowledgement is not suppressed by s7.8, then collapse. The window
        // is ALREADY the minimum here, so the collapse moves no bytes at all and the accumulator
        // is the only thing it can be observed through.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        _ = FillWindow(controller, clock.GetUtcNow());
        controller.OnPersistentCongestion();
        Assert.Equal(window, controller.CongestionWindowBytes);
        Assert.Equal(TlsQuicCongestionState.CongestionAvoidance, controller.State);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([sent[^1]]);

        // ONE DATAGRAM'S WORTH IS NOT A WINDOW'S WORTH. With the accumulator carried over it
        // would have been, and the window would have grown by a whole datagram on a single
        // acknowledgement - s7.3.3 lines 172-175's "at most one maximum datagram size for each
        // congestion window that is acknowledged", charged against a window that no longer exists.
        Assert.Equal(window, controller.CongestionWindowBytes);
    }

    // ---- THE BLACKOUT, THROUGH A3-1's IMPAIRING TRANSPORT ---------------------------
    //
    // Every predicate test above hands IsEstablished a list this file built. These two do not:
    // the datagrams go through ImpairingDatagramTransport, the SCRIPT decides which never reach
    // the far side, and the loss list is read back out of the transport's own Dropped ledger.
    // The two tests differ in ONE scripted drop - the length of the blackout - and in nothing
    // else, so the verdict cannot be coming from anywhere but the duration.

    [Fact]
    public async Task AScriptedBlackoutThroughTheImpairingTransportCollapsesTheWindow()
    {
        var (controller, spec, window, minimum, established) =
            await RunScriptedBlackoutAsync(overshootIntervals: 1);

        Assert.True(established);
        Assert.Equal(minimum, controller.CongestionWindowBytes);
        Assert.True(controller.CongestionWindowBytes < window);
        Assert.Equal(TlsQuicCongestionState.SlowStart, controller.State);
        Assert.Equal(
            (long)spec.MinimumCongestionWindowDatagrams * MaxDatagramSize,
            controller.CongestionWindowBytes);
    }

    [Fact]
    public async Task AScriptedBlackoutOneIntervalShorterIsLossButNotPersistentCongestion()
    {
        // THE ONE-SIDED TEST IS WHAT AN OFF-BY-ONE SURVIVES. This run drops one datagram fewer,
        // so the span between the oldest and newest lost packets is at most the duration rather
        // than more than it. The window still HALVES - it is a real loss and s7.5's congestion
        // event still fires - but it does not collapse, and the difference between "reduced" and
        // "minimum" is the whole assertion.
        var (controller, spec, window, minimum, established) =
            await RunScriptedBlackoutAsync(overshootIntervals: 0);

        Assert.False(established);
        Assert.NotEqual(minimum, controller.CongestionWindowBytes);
        Assert.True(controller.CongestionWindowBytes > minimum);
        Assert.Equal(
            Math.Max((long)(window * spec.LossReductionFactor), minimum),
            controller.CongestionWindowBytes);
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);
    }

    // ------------------------------------------------------------------------------
    // HELPERS.
    // ------------------------------------------------------------------------------

    // The smallest interval DateTimeOffset can express, which is what a boundary test written
    // against "exceeds" has to move by. A test that stepped by a millisecond would pass against
    // >= as happily as against >.
    private static readonly TimeSpan OneTick = new(1);

    // A3-4's RTT ESTIMATOR, DRIVEN RATHER THAN IMITATED. The plan's done-when for this task asks
    // that the duration be recomputed "from A3-4's live estimator and A3-2's threshold rather
    // than from a literal", and this is where the live half comes from: a real ACK frame, encoded
    // by TlsQuicAckFrames and read back through TlsQuicFrames.TryReadFrame, carrying a real round
    // trip against a real sent packet. Nothing here sets smoothed_rtt or rttvar directly.
    private static (TimeSpan SmoothedRtt, TimeSpan RttVariation, DateTimeOffset FirstRttSampleAt)
        LiveEstimator()
    {
        var tracker = new TlsQuicAckTracker();

        var first = Packet(MaxDatagramSize, Origin, number: 0);
        var firstAckedAt = Origin + TimeSpan.FromMilliseconds(40);
        Assert.True(tracker.ProcessAckFrame(
            TlsQuicEncryptionLevel.Application,
            AckFrame(new TlsQuicAckRange(0, 0)),
            firstAckedAt,
            [first],
            out _));

        // A SECOND SAMPLE, AND IT IS NOT DECORATION. s5.3 resets the estimator on the first
        // sample - rttvar becomes exactly smoothed_rtt / 2 - and a duration computed against that
        // relationship would agree with a transcription that had put the 4 somewhere else. One
        // more round trip, of a different length, breaks the tie.
        var second = Packet(MaxDatagramSize, firstAckedAt, number: 1);
        var secondAckedAt = firstAckedAt + TimeSpan.FromMilliseconds(52);
        Assert.True(tracker.ProcessAckFrame(
            TlsQuicEncryptionLevel.Application,
            AckFrame(new TlsQuicAckRange(1, 1)),
            secondAckedAt,
            [second],
            out _));

        Assert.True(tracker.RttVariation > TimeSpan.Zero);
        Assert.NotEqual(tracker.SmoothedRtt.Ticks / 2, tracker.RttVariation.Ticks);
        Assert.Equal(firstAckedAt, tracker.FirstRttSampleAt);

        return (tracker.SmoothedRtt, tracker.RttVariation, firstAckedAt);
    }

    // Builds a real ACK frame the way a peer would and reads it back, so ProcessAckFrame sees
    // exactly what TlsQuicFrames.TryReadFrame produces. The same shape TlsQuicAckTrackerTests
    // uses, because an estimator driven through a shortcut is not the estimator.
    private static TlsQuicFrame AckFrame(params TlsQuicAckRange[] ranges)
    {
        List<byte> encoded = [];
        TlsQuicAckFrames.WriteAckFrame(encoded, (ulong)TlsQuicFrameType.Ack, 0, ranges);
        var offset = 0;
        ReadOnlyMemory<byte> wire = encoded.ToArray();
        Assert.True(TlsQuicFrames.TryReadFrame(wire, ref offset, out var frame, out _));
        return frame;
    }

    private static TimeSpan Duration(TlsQuicRecoverySpec spec, out DateTimeOffset firstRttSampleAt)
    {
        var (smoothedRtt, rttVariation, sampleAt) = LiveEstimator();
        firstRttSampleAt = sampleAt;
        return TlsQuicPersistentCongestion.DurationFor(
            spec, smoothedRtt, rttVariation, TlsQuicAckTracker.DefaultMaxAckDelay);
    }

    // ONE SCRIPTED BLACKOUT, WITH ITS LENGTH DERIVED FROM THE DURATION RATHER THAN CHOSEN. The
    // probe interval is a fixture - how often this sender retries into the silence, and s7.5
    // lines 195-197 make probes exempt from the send gate, which is why nothing here calls
    // CanSend. The NUMBER of probes is computed: floor(duration / interval) intervals cannot
    // exceed the duration, and one more always does. So overshootIntervals 0 and 1 differ by
    // exactly one scripted drop and by nothing else in this method.
    private static async Task<(
        TlsQuicNewRenoCongestionController Controller,
        TlsQuicRecoverySpec Spec,
        long WindowBeforeTheLoss,
        long Minimum,
        bool Established)>
        RunScriptedBlackoutAsync(int overshootIntervals)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        var spec = new TlsQuicRecoverySpec();
        var clock = new ManualTimeProvider(Origin);
        var controller = new TlsQuicNewRenoCongestionController(spec, MaxDatagramSize, clock);

        var (smoothedRtt, rttVariation, firstRttSampleAt) = LiveEstimator();
        var duration = TlsQuicPersistentCongestion.DurationFor(
            spec, smoothedRtt, rttVariation, TlsQuicAckTracker.DefaultMaxAckDelay);

        var interval = TimeSpan.FromMilliseconds(60);
        var spanIntervals = (int)(duration.Ticks / interval.Ticks) + overshootIntervals;
        Assert.True(spanIntervals > 1);

        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var far = server;
        await using var impaired = new ImpairingDatagramTransport(client, clock);

        // ORDINAL 1 SURVIVES AND EVERYTHING AFTER IT IS DROPPED. The surviving one is what gives
        // the run an acknowledgement to anchor s7.6.2's second clause against.
        for (var ordinal = 2; ordinal <= spanIntervals + 2; ordinal++)
        {
            _ = impaired.Drop(ordinal);
        }

        clock.Advance(firstRttSampleAt - Origin + OneTick);

        var sentByOrdinal = new Dictionary<int, TlsQuicSentPacket>();
        var anchor = await SendOneAsync(
            impaired, far, controller, clock, sentByOrdinal, cancellation.Token);
        controller.OnPacketsAcked([anchor]);

        for (var i = 1; i <= spanIntervals + 1; i++)
        {
            clock.Advance(interval);
            _ = await SendOneAsync(
                impaired, far, controller, clock, sentByOrdinal, cancellation.Token);
        }

        // NOTHING IN THIS METHOD DECIDES WHAT WAS LOST. The transport's own ledgers do, and they
        // are asserted against the script before they are believed.
        Assert.Equal([1], impaired.Delivered);
        Assert.Equal(Enumerable.Range(2, spanIntervals + 1), impaired.Dropped);
        Assert.Empty(impaired.Held);
        Assert.Empty(impaired.ReleaseFailures);

        var lost = impaired.Dropped.Select(ordinal => sentByOrdinal[ordinal]).ToList();
        var span = lost[^1].SentAt - lost[0].SentAt;
        Assert.Equal(spanIntervals * interval, span);
        Assert.Equal(overshootIntervals == 1, span > duration);

        var windowBeforeTheLoss = controller.CongestionWindowBytes;

        // B.8's ORDER: the congestion event first, the persistent-congestion verdict second. The
        // collapse discards the recovery period the congestion event just opened, so running them
        // the other way round would leave the window at the minimum and the period alive.
        controller.OnPacketsLost(lost);
        var established = TlsQuicPersistentCongestion.IsEstablished(
            lost, firstRttSampleAt, anchor.SentAt, duration);

        if (established)
        {
            controller.OnPersistentCongestion();
        }

        return (
            controller,
            spec,
            windowBeforeTheLoss,
            (long)spec.MinimumCongestionWindowDatagrams * MaxDatagramSize,
            established);
    }

    private static async Task<TlsQuicSentPacket> SendOneAsync(
        ImpairingDatagramTransport impaired,
        InMemoryDatagramTransport destination,
        TlsQuicNewRenoCongestionController controller,
        ManualTimeProvider clock,
        Dictionary<int, TlsQuicSentPacket> sentByOrdinal,
        CancellationToken cancellationToken)
    {
        await impaired
            .SendAsync(destination.LocalEndPoint, new byte[MaxDatagramSize], cancellationToken)
            .ConfigureAwait(false);

        var ordinal = impaired.Offered.Count;
        var packet = Packet(MaxDatagramSize, clock.GetUtcNow(), number: (ulong)ordinal);
        controller.OnPacketSent(packet);
        sentByOrdinal[ordinal] = packet;
        return packet;
    }


    private static TlsQuicNewRenoCongestionController Controller(
        TlsQuicRecoverySpec spec, out ManualTimeProvider clock)
    {
        clock = new ManualTimeProvider(Origin);
        return new TlsQuicNewRenoCongestionController(spec, MaxDatagramSize, clock);
    }

    private static TlsQuicSentPacket Packet(
        int size, DateTimeOffset sentAt, bool inFlight = true, ulong number = 0) =>
        new(TlsQuicEncryptionLevel.Application, number, size, inFlight, inFlight, sentAt);

    // Sends until the gate refuses, which is what a send path does and what makes the result a
    // FULL window rather than a number this file chose.
    //
    // AND IT IS BOUNDED, WHICH A MUTATION SWEEP IS WHAT FORCED. A controller whose CanSend
    // ignores bytes in flight never refuses, so an unbounded version of this loop HANGS the
    // whole test host - and a hung suite produces no verdict at all, not a failing one. That
    // is strictly worse than a wrong answer: the sweep row scored it as a timeout rather than
    // as the kill it should have been, and every row after it went unrun. The bound is far
    // above any window these tests build, so it can only be reached by a controller that has
    // stopped gating, and reaching it is a failure with a name.
    private static List<TlsQuicSentPacket> FillWindow(
        TlsQuicNewRenoCongestionController controller, DateTimeOffset sentAt)
    {
        const int AbsurdlyMoreSendsThanAnyWindowHereNeeds = 20_000;
        var sent = new List<TlsQuicSentPacket>();
        while (controller.CanSend(MaxDatagramSize))
        {
            var packet = Packet(MaxDatagramSize, sentAt, number: (ulong)sent.Count);
            controller.OnPacketSent(packet);
            sent.Add(packet);

            Assert.True(
                sent.Count < AbsurdlyMoreSendsThanAnyWindowHereNeeds,
                $"CanSend admitted {sent.Count} datagrams against a window of "
                    + $"{controller.CongestionWindowBytes} with {controller.BytesInFlight} bytes "
                    + "already in flight: the send gate has stopped gating.");
        }

        return sent;
    }

    private static List<TlsQuicSentPacket> SendAt(
        TlsQuicNewRenoCongestionController controller, DateTimeOffset sentAt, int count)
    {
        var sent = new List<TlsQuicSentPacket>();
        for (var i = 0; i < count; i++)
        {
            var packet = Packet(MaxDatagramSize, sentAt, number: (ulong)i);
            controller.OnPacketSent(packet);
            sent.Add(packet);
        }

        return sent;
    }

    // One loss to open a recovery period, one acknowledgement of a packet sent inside it to
    // close it - which is exactly the route Figure 1 draws into congestion avoidance, and the
    // only one, since s7.3.1 lines 131-133 make re-entry into slow start persistent
    // congestion's business alone.
    private static void EnterCongestionAvoidance(
        TlsQuicNewRenoCongestionController controller, ManualTimeProvider clock)
    {
        var first = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(first);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsLost([first]);

        clock.Advance(TimeSpan.FromMilliseconds(1));
        var during = Packet(MaxDatagramSize, clock.GetUtcNow());
        controller.OnPacketSent(during);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        controller.OnPacketsAcked([during]);

        Assert.Equal(TlsQuicCongestionState.CongestionAvoidance, controller.State);
    }

    // A controller that is not NewReno, for the seam test. It has no threshold, no recovery
    // period and no states; it holds a window and counts bytes, which is everything
    // ITlsQuicCongestionController asks of anyone.
    private sealed class FixedRateController(long window) : ITlsQuicCongestionController
    {
        private long _bytesInFlight;

        public string Name => "FixedRate";

        public long CongestionWindowBytes { get; } = window;

        public long BytesInFlight => _bytesInFlight;

        public bool CanSend(int bytes) => _bytesInFlight + bytes <= CongestionWindowBytes;

        public void OnPacketSent(in TlsQuicSentPacket sent)
        {
            if (sent.IsInFlight)
            {
                _bytesInFlight += sent.Size;
            }
        }

        public void OnPacketsAcked(IReadOnlyList<TlsQuicSentPacket>? ackedPackets) =>
            Remove(ackedPackets);

        public void OnPacketsLost(IReadOnlyList<TlsQuicSentPacket>? lostPackets) =>
            Remove(lostPackets);

        // s7.6.2's MUST names kMinimumWindow, and a controller with no window to reduce has
        // already met it. The member is on the seam so a controller that HAS one can be told.
        public void OnPersistentCongestion()
        {
        }

        public void OnPacketsDiscarded(IReadOnlyList<TlsQuicSentPacket>? discardedPackets) =>
            Remove(discardedPackets);

        private void Remove(IReadOnlyList<TlsQuicSentPacket>? packets)
        {
            if (packets is null)
            {
                return;
            }

            foreach (var packet in packets)
            {
                if (packet.IsInFlight)
                {
                    _bytesInFlight = Math.Max(0, _bytesInFlight - packet.Size);
                }
            }
        }
    }
}

// THE ONLY FOREIGN-CODE EVIDENCE THIS TASK CAN REACH, AND THE ONLY LOSS HERE THAT IS REAL.
//
// Every other test in this file hands the controller a TlsQuicSentPacket the test built. RFC
// 9002 publishes no test vectors at all - the extract's own header says so at lines 9-12 - so
// a suite of synthetic events can only ever prove that this implementation agrees with this
// test's reading. The substitute the extract names first, at lines 14-16, is "an independent
// implementation - System.Net.Quic.QuicListener over MsQuic, which is genuinely foreign code".
//
// So this test drops a real datagram with A3-1's impairing transport, on a real 1-RTT exchange
// with a real MsQuic server, and drives the controller from the packets THE CONNECTION
// retained and the acknowledgement THE PEER sent. Nothing here decides what was lost: the
// transport dropped it, the server never saw it, and the server's own ACK frame is what says
// which packet numbers arrived.
public sealed partial class TlsQuicConnectionTests
{
    [Fact]
    public async Task ADatagramTheImpairingTransportDropsDrivesTheControllerIntoRecovery()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        // ORDINAL 5. RunToOneRttAsync spends ordinals 1 to 3, so the four PATH_RESPONSE
        // datagrams below are 4, 5, 6 and 7 - and the second of them never reaches the server.
        impaired.Drop(5);

        await using var connection = Connection(impaired, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await RunToOneRttAsync(connection, serverPeer, cancellation.Token);
        Assert.Equal(3, impaired.Offered.Count);

        // FOUR ACK-ELICITING 1-RTT PACKETS FROM THE CLIENT. A PATH_CHALLENGE is answered with
        // a PATH_RESPONSE in a 1-RTT packet of its own (RFC 9000 s19.17), and a PATH_RESPONSE
        // is ack-eliciting - so unlike a repeated HANDSHAKE_DONE, which draws only an ACK,
        // these are packets RFC 9002 B.2 counts toward bytes in flight.
        var numbers = new List<ulong>();
        for (var i = 0; i < 4; i++)
        {
            numbers.Add(connection.NextPacketNumber(TlsQuicEncryptionLevel.Application));
            await serverPeer.SendHandshakeDoneAsync(
                SentAt,
                cancellation.Token,
                pathChallengeData: [(byte)i, 1, 2, 3, 4, 5, 6, 7]);
            Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        }

        Assert.Equal(7, impaired.Offered.Count);
        Assert.Equal(new[] { 5 }, impaired.Dropped);

        // THE CONTROLLER IS DRIVEN BY THE CONNECTION'S OWN RETAINED PACKETS. A3-3 built this
        // list on the send path; nothing in this test constructed a TlsQuicSentPacket.
        var spec = new TlsQuicRecoverySpec();
        var controller = new TlsQuicNewRenoCongestionController(spec, 1200);
        var retained = connection
            .SentPackets(TlsQuicEncryptionLevel.Application)
            .ToList();

        foreach (var sent in retained)
        {
            controller.OnPacketSent(sent);
        }

        // TWO INDEPENDENTLY MAINTAINED COUNTERS THAT MUST AGREE. A3-3's bytes_in_flight on the
        // connection and this controller's own are computed from the same packets by different
        // code, including A.4's exclusion of ACK-only packets - which is live here, because the
        // 1-RTT packet RunToOneRttAsync drew is ACK-only and the four PATH_RESPONSEs are not.
        Assert.Equal(connection.BytesInFlight, controller.BytesInFlight);

        // THE SERVER SEES THREE OF THE FOUR, AND SAYS SO. Nothing else in this test asserts
        // which packet was lost; this is the foreign implementation's own account of it.
        for (var i = 0; i < 4; i++)
        {
            Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        }

        Assert.Equal(numbers[3], serverPeer.LargestApplicationPacketNumberReceived);
        await serverPeer.SendAckAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(
            numbers[3],
            connection.LargestAcknowledged(TlsQuicEncryptionLevel.Application));

        var window = controller.CongestionWindowBytes;

        var acked = retained.Where(p => p.PacketNumber == numbers[3]).ToList();
        Assert.Single(acked);
        controller.OnPacketsAcked(acked);

        // RFC 9002 s6.1.1's packet threshold, applied in the test because loss detection is
        // task A3-6's and has not landed: the dropped packet's number is more than
        // kPacketThreshold below a number the peer acknowledged, so it is lost. The DROP is
        // real; only the rule that names it is here.
        var lost = retained.Where(p => p.PacketNumber == numbers[1]).ToList();
        Assert.Single(lost);
        Assert.True(numbers[3] - numbers[1] >= (ulong)spec.PacketThreshold - 1);
        controller.OnPacketsLost(lost);

        // AND THE CONTROLLER REACTS TO A LOSS NOTHING IN THIS TEST INVENTED.
        Assert.Equal(TlsQuicCongestionState.Recovery, controller.State);
        Assert.Equal(
            Math.Max(
                (long)(window * spec.LossReductionFactor),
                (long)spec.MinimumCongestionWindowDatagrams * 1200),
            controller.CongestionWindowBytes);
        Assert.True(controller.CongestionWindowBytes < window);

        // THE EXCHANGE SURVIVED THE LOSS. The two datagrams after the dropped one were
        // delivered and opened by MsQuic, so this is a controller reacting to loss on a
        // connection that is still running rather than one that fell over.
        Assert.Equal(new[] { 1, 2, 3, 4, 6, 7 }, impaired.Delivered);
    }
}
