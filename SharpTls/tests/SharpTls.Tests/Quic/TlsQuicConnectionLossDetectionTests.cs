using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task A3-6 of the loss recovery phase: RFC 9002 s6.1's two thresholds, A.10's
// DetectAndRemoveLostPackets, and A.8's rung-1 helper GetLossTimeAndSpace.
//
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's, 14c's, A3-1's, A3-3's AND A3-5's, for the reason
// those files give: Spec, Connection, TlsClient, Server, IdleOn, RunToOneRttAsync, Packet and
// AckFrame are reused rather than copied.
//
// ============================================================================
// WHAT THIS FILE PINS THAT NO OTHER FILE CAN, AND WHAT IT DELIBERATELY CANNOT.
// ============================================================================
//
// THE TWO HALVES ARE A3-3's TWO HALVES AND NEITHER IS SUFFICIENT ALONE.
//
//   THE DIRECT HALF drives OnPacketSent, ProcessAckFrame, OnAckReceived and
//   DetectAndRemoveLostPackets with packets and ACK frames built here. It is the only half
//   that can put a packet EXACTLY on a threshold, on either side of it, and it is where every
//   boundary claim lives. WHAT IT CANNOT SEE is whether anything on the live path ever calls
//   loss detection - and today nothing does, which this file says out loud rather than leaves
//   for a reader to discover; see TlsQuicLossDetection.cs's header for the three call sites
//   that live in a file A3-6 may not edit.
//
//   THE LOOPBACK HALF drops a real datagram with A3-1's decorator, runs a real handshake
//   through the gap, and declares the missing packet lost from an acknowledgement that came
//   off the wire. It is what fails if the packet numbers, the send instants or the in-flight
//   flags this connection retains are not the ones a real send produced. WHAT IT CANNOT SEE
//   is any boundary: a handshake sends the packet numbers it sends.
//
// NO EXPECTED NUMBER BELOW IS TYPED. Every threshold is recomputed from the
// TlsQuicRecoverySpec the connection was built with, and every instant from that spec plus
// TlsQuicConnection.KGranularity. A test that compared against 3, against 1.125 or against
// 374ms would pass against a hardcoded implementation, which is the whole failure mode the
// A3 plan's "the test recomputes the boundary from the spec object rather than from a
// literal" is about.
//
// EVERY BOUNDARY IS TWO-SIDED. A one-sided test passes an off-by-one, so each threshold has a
// witness that IS declared lost and a sibling one step short that is NOT, and the two are
// asserted against each other rather than each in isolation.
//
// AND THE CALIBRATION CONTROL FOR THE WHOLE FILE IS A PAIR:
// TlsQuicConnectionTests.AReorderedPacketThatIsAcknowledgedLaterIsNeverDeclaredLost on the
// direct side and TlsQuicConnectionTests.AnAcknowledgedRunOverTheSameScriptDeclaresNothingLost
// on the loopback side. A mutant that declares every unacknowledged packet lost the moment any
// ACK arrives passes every "loss is detected" test in this file and fails only those two. They
// are the reason the thresholds are not dead code dressed as conformance.
public sealed partial class TlsQuicConnectionTests
{
    // ========================================================================
    // THE PACKET THRESHOLD - RFC 9002 s6.1.1, KNOB 6.
    // ========================================================================

    // A.10: "largest_acked_packet[pn_space] >= unacked.packet_number + kPacketThreshold".
    //
    // BOTH SIDES IN ONE TEST, ON TWO CONNECTIONS, so the pair cannot drift apart and so the
    // gap that is one short of the threshold is asserted to leave the packet RETAINED rather
    // than merely un-listed.
    [Fact]
    public async Task APacketIsDeclaredLostAtExactlyThePacketThresholdAndNotOnePacketEarlier()
    {
        // The multiplier is pushed out of the way so that only s6.1.1 can fire here: the
        // clock does not move in this test, but a reader should not have to prove that.
        var recovery = new TlsQuicRecoverySpec { TimeThreshold = 1e6 };
        var threshold = (ulong)recovery.PacketThreshold;

        var clock = FakeClock();
        await using var atTheThreshold = LossDetectionConnectionOn(clock, recovery);
        await using var oneShort = LossDetectionConnectionOn(clock, recovery);

        foreach (var connection in new[] { atTheThreshold, oneShort })
        {
            for (var number = 0UL; number <= threshold; number++)
            {
                connection.OnPacketSent(
                    PacketAt(TlsQuicEncryptionLevel.Application, number, clock.GetUtcNow()));
            }
        }

        // A GAP OF EXACTLY kPacketThreshold. Packet zero is kPacketThreshold behind the
        // largest acknowledged, which is A.10's condition met with no slack.
        var lost = Acknowledge(atTheThreshold, TlsQuicEncryptionLevel.Application, threshold);
        Assert.Equal([0UL], lost.Select(static p => p.PacketNumber));

        // A GAP OF ONE LESS, AND NOTHING IS LOST. This is the assertion an off-by-one fails.
        Assert.Empty(Acknowledge(oneShort, TlsQuicEncryptionLevel.Application, threshold - 1));

        // AND IT IS STILL THERE TO BE LOST LATER, which "the list was empty" alone does not
        // say: a detector that removed the packet without reporting it would pass the line
        // above and fail this one.
        Assert.Contains(
            oneShort.SentPackets(TlsQuicEncryptionLevel.Application),
            p => p.PacketNumber == 0);

        // A.10's else branch: the packet that was spared is waiting on the TIME threshold, at
        // its own send instant plus the loss delay. Recomputed, not typed.
        Assert.Equal(
            clock.GetUtcNow() + LossDelayOf(recovery),
            oneShort.LossTime(TlsQuicEncryptionLevel.Application));
    }

    // A.10's `if (unacked.packet_number > largest_acked_packet[pn_space]): continue`, which is
    // s6.1's "was sent prior to an acknowledged packet".
    //
    // AND IT IS ALSO WHAT MAKES THE PACKET THRESHOLD'S ARITHMETIC SAFE. See hazard 1 in
    // TlsQuicLossDetection.cs: A.10's `unacked.packet_number + kPacketThreshold` wraps for a
    // packet number near the top of the ulong range, and this `continue` is the reason no such
    // packet ever reaches the comparison. RFC 9000 s16 caps a variable-length integer - and so
    // largest_acked - at 2^62-1, so a retained ulong.MaxValue is above it by construction.
    [Fact]
    public async Task APacketNewerThanTheLargestAcknowledgedIsNotDeclaredLost()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Application, ulong.MaxValue, clock.GetUtcNow()));
        for (var number = 0UL; number < 4; number++)
        {
            connection.OnPacketSent(
                PacketAt(TlsQuicEncryptionLevel.Application, number, clock.GetUtcNow()));
        }

        // Packet zero is four behind and goes; ulong.MaxValue is AHEAD of the largest
        // acknowledged and is skipped, however far behind the subtraction would make it look.
        var lost = Acknowledge(connection, TlsQuicEncryptionLevel.Application, 3);
        Assert.Equal([0UL], lost.Select(static p => p.PacketNumber));
        Assert.Contains(
            connection.SentPackets(TlsQuicEncryptionLevel.Application),
            p => p.PacketNumber == ulong.MaxValue);
    }

    // ========================================================================
    // THE TIME THRESHOLD - RFC 9002 s6.1.2, KNOB 7.
    // ========================================================================

    // A.10: "lost_send_time = now() - loss_delay" and "if (unacked.time_sent <=
    // lost_send_time || ...)".
    //
    // THE COMPARISON IS `<=` AND THAT IS THE CLAIM THIS TEST EXISTS FOR. s6.1.2's prose says
    // only "sent a threshold amount of time in the past", which is silent on the instant
    // itself; A.10 is not, and A.10 is followed. The two connections are one tick apart, so
    // nothing but the boundary can distinguish them.
    [Fact]
    public async Task APacketSentExactlyTheLossDelayAgoIsDeclaredLostAndOneTickShortIsNot()
    {
        // s6.1.1 pushed out of the way so that only s6.1.2 can fire: a gap of one packet is
        // far below a threshold of int.MaxValue.
        var recovery = new TlsQuicRecoverySpec { PacketThreshold = int.MaxValue };
        var delay = LossDelayOf(recovery);

        var atTheBoundary = FakeClock();
        var oneTickShort = FakeClock();
        await using var lost = LossDetectionConnectionOn(atTheBoundary, recovery);
        await using var spared = LossDetectionConnectionOn(oneTickShort, recovery);

        var sentAt = atTheBoundary.GetUtcNow();
        Assert.Equal(sentAt, oneTickShort.GetUtcNow());

        foreach (var connection in new[] { lost, spared })
        {
            connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Application, 0, sentAt));
            connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Application, 1, sentAt));
            Acknowledge(connection, TlsQuicEncryptionLevel.Application, 1);
        }

        atTheBoundary.Advance(delay);
        oneTickShort.Advance(delay - TimeSpan.FromTicks(1));

        Assert.Equal(
            [0UL],
            lost.DetectAndRemoveLostPackets(TlsQuicEncryptionLevel.Application)
                .Select(static p => p.PacketNumber));

        Assert.Empty(spared.DetectAndRemoveLostPackets(TlsQuicEncryptionLevel.Application));
        Assert.Contains(
            spared.SentPackets(TlsQuicEncryptionLevel.Application),
            p => p.PacketNumber == 0);

        // A.10's else branch again, and this is the value A.8's rung 1 would arm a timer from:
        // the one remaining tick.
        Assert.Equal(sentAt + delay, spared.LossTime(TlsQuicEncryptionLevel.Application));
    }

    // s6.1.2: "max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)", and its own
    // reason for the inner max - it "protects from the two following cases: the latest RTT
    // sample is lower than the smoothed RTT ... the latest RTT sample is higher than the
    // smoothed RTT".
    //
    // BOTH DIRECTIONS, AND EACH ASSERTS THE OTHER CANDIDATE IS NOT WHAT CAME OUT. A min in
    // place of the max produces the other number, and "not equal to the right answer" would
    // not distinguish a min from a typo.
    [Theory]
    [InlineData(400, 100)]
    [InlineData(100, 400)]
    public void TheLossDelayTakesTheLargerOfTheSmoothedAndLatestRoundTripTimes(
        int smoothedMilliseconds, int latestMilliseconds)
    {
        var recovery = new TlsQuicRecoverySpec();
        var smoothed = TimeSpan.FromMilliseconds(smoothedMilliseconds);
        var latest = TimeSpan.FromMilliseconds(latestMilliseconds);

        var larger = smoothed > latest ? smoothed : latest;
        var smaller = smoothed > latest ? latest : smoothed;

        Assert.Equal(
            new TimeSpan((long)(larger.Ticks * recovery.TimeThreshold)),
            TlsQuicConnection.LossDelay(recovery, smoothed, latest));
        Assert.NotEqual(
            new TimeSpan((long)(smaller.Ticks * recovery.TimeThreshold)),
            TlsQuicConnection.LossDelay(recovery, smoothed, latest));
    }

    // s6.1.2: "To avoid declaring packets as lost too early, this time threshold MUST be set
    // to at least the local timer granularity, as indicated by the kGranularity constant. The
    // time threshold is: max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)".
    //
    // THE FLOOR IS ON THE PRODUCT AND NOT ON THE RTT TERM, and the difference is exactly
    // kTimeThreshold - one millisecond against nine eighths of one. BOTH CANDIDATE NUMBERS ARE
    // ASSERTED, because the wrong placement is a value that differs by 12.5% and would look
    // entirely plausible in any log.
    [Fact]
    public void TheTimeThresholdIsFlooredAtTheTimerGranularityAndNotAtNineEighthsOfIt()
    {
        var recovery = new TlsQuicRecoverySpec();

        var delay = TlsQuicConnection.LossDelay(recovery, TimeSpan.Zero, TimeSpan.Zero);

        Assert.Equal(TlsQuicConnection.KGranularity, delay);
        Assert.NotEqual(
            new TimeSpan((long)(TlsQuicConnection.KGranularity.Ticks * recovery.TimeThreshold)),
            delay);
    }

    // ========================================================================
    // ONE THRESHOLD WITHOUT THE OTHER. NEITHER IS DEAD CODE.
    // ========================================================================
    //
    // The two tests above each silence one threshold with an extreme knob, which proves the
    // OTHER fires but says nothing about the default spec. These two use TlsQuicRecoverySpec's
    // own defaults and separate the thresholds by the state alone.

    [Fact]
    public async Task ThePacketThresholdFiresWhileTheTimeThresholdHasNotElapsed()
    {
        var recovery = new TlsQuicRecoverySpec();
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock, recovery);

        var sentAt = clock.GetUtcNow();
        for (var number = 0UL; number <= (ulong)recovery.PacketThreshold; number++)
        {
            connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Application, number, sentAt));
        }

        var lost = Acknowledge(
            connection, TlsQuicEncryptionLevel.Application, (ulong)recovery.PacketThreshold);

        // THE CLOCK HAS NOT MOVED, so the time threshold cannot have elapsed - stated as an
        // assertion rather than left implicit, because it is the whole content of the test.
        Assert.True(clock.GetUtcNow() - sentAt < LossDelayOf(recovery));

        Assert.Equal([0UL], lost.Select(static p => p.PacketNumber));
    }

    [Fact]
    public async Task TheTimeThresholdFiresWhileThePacketThresholdIsNotReached()
    {
        var recovery = new TlsQuicRecoverySpec();
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock, recovery);

        var sentAt = clock.GetUtcNow();
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Application, 0, sentAt));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Application, 1, sentAt));
        Acknowledge(connection, TlsQuicEncryptionLevel.Application, 1);

        // A GAP OF ONE, WHICH THE DEFAULT PACKET THRESHOLD TOLERATES. Asserted from the spec.
        Assert.True(1UL < (ulong)recovery.PacketThreshold);
        Assert.Empty(connection.DetectAndRemoveLostPackets(TlsQuicEncryptionLevel.Application));

        clock.Advance(LossDelayOf(recovery));

        Assert.Equal(
            [0UL],
            connection.DetectAndRemoveLostPackets(TlsQuicEncryptionLevel.Application)
                .Select(static p => p.PacketNumber));
    }

    // ========================================================================
    // THE CALIBRATION CONTROL: REORDERING IS NOT LOSS.
    // ========================================================================
    //
    // s6.1: "The acknowledgment indicates that a packet sent later was delivered, and the
    // packet and time thresholds provide some tolerance for packet reordering."
    //
    // A MUTANT THAT DECLARES EVERY UNACKNOWLEDGED PACKET LOST AS SOON AS ANY ACK ARRIVES
    // PASSES EVERY OTHER TEST IN THIS FILE. It fails here, and it fails at the second
    // acknowledgement rather than the first - which is why this test does not stop once
    // nothing has been declared lost.
    [Fact]
    public async Task AReorderedPacketThatIsAcknowledgedLaterIsNeverDeclaredLost()
    {
        var recovery = new TlsQuicRecoverySpec();
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock, recovery);

        var sentAt = clock.GetUtcNow();
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Application, 0, sentAt));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Application, 1, sentAt));

        // The later packet is acknowledged first: the earlier one overtook nothing, it was
        // overtaken. Its acknowledgement is still in flight.
        Acknowledge(connection, TlsQuicEncryptionLevel.Application, 1);
        Assert.Empty(connection.DetectAndRemoveLostPackets(TlsQuicEncryptionLevel.Application));
        Assert.NotNull(connection.LossTime(TlsQuicEncryptionLevel.Application));

        // AND THEN IT ARRIVES. Nothing was ever lost, and the pending time threshold is
        // cleared because the packet it was waiting on has been retired.
        Acknowledge(connection, TlsQuicEncryptionLevel.Application, 0);
        Assert.Empty(connection.DetectAndRemoveLostPackets(TlsQuicEncryptionLevel.Application));
        Assert.Empty(connection.SentPackets(TlsQuicEncryptionLevel.Application));
        Assert.Null(connection.LossTime(TlsQuicEncryptionLevel.Application));
    }

    // ========================================================================
    // PER SPACE - RFC 9002 s6's opening, AND A WITNESS PER SPACE PAIR.
    // ========================================================================
    //
    // s6: "Loss detection is separate per packet number space, unlike RTT measurement and
    // congestion control, because RTT and congestion control are properties of the path,
    // whereas loss detection also relies upon key availability."
    //
    // THE SAME PACKET NUMBERS IN ALL THREE SPACES, which is the state that tells a per-space
    // detector from one that walks a single list: RFC 9000 s12.3 gives every space its own
    // numbering, so packet 0 exists three times and they are three different packets.
    [Theory]
    [InlineData(TlsQuicEncryptionLevel.Initial, TlsQuicEncryptionLevel.Handshake)]
    [InlineData(TlsQuicEncryptionLevel.Initial, TlsQuicEncryptionLevel.Application)]
    [InlineData(TlsQuicEncryptionLevel.Handshake, TlsQuicEncryptionLevel.Application)]
    public async Task LossInOneSpaceLeavesTheOtherUntouched(
        TlsQuicEncryptionLevel losing, TlsQuicEncryptionLevel bystander)
    {
        var recovery = new TlsQuicRecoverySpec();
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock, recovery);

        var sentAt = clock.GetUtcNow();
        foreach (var level in new[] { losing, bystander })
        {
            for (var number = 0UL; number <= (ulong)recovery.PacketThreshold; number++)
            {
                connection.OnPacketSent(PacketAt(level, number, sentAt));
            }
        }

        var retainedBefore = connection.SentPackets(bystander).Count;

        Assert.Equal(
            [0UL],
            Acknowledge(connection, losing, (ulong)recovery.PacketThreshold)
                .Select(static p => p.PacketNumber));

        // THE BYSTANDER KEEPS ITS OWN PACKET ZERO, and its loss_time is untouched - an
        // implementation that indexed loss_time by anything but the space would have written
        // the losing space's instant into it.
        Assert.Equal(retainedBefore, connection.SentPackets(bystander).Count);
        Assert.Contains(connection.SentPackets(bystander), p => p.PacketNumber == 0);
        Assert.Null(connection.LossTime(bystander));

        // AND RUNNING DETECTION ON THE BYSTANDER DECLARES NOTHING, because no acknowledgement
        // has arrived there. A.10's opening assert, as this file's return.
        Assert.Empty(connection.DetectAndRemoveLostPackets(bystander));
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // RFC 9002 A.8's GetLossTimeAndSpace: "if (loss_time[pn_space] != 0 && (time == 0 ||
    // loss_time[pn_space] < time))".
    [Fact]
    public async Task TheEarliestLossTimeAcrossTheSpacesIsTheOneAppendixEightWouldArm()
    {
        var recovery = new TlsQuicRecoverySpec { PacketThreshold = int.MaxValue };
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock, recovery);
        var delay = LossDelayOf(recovery);

        // NOTHING PENDING TO START WITH, which is what stops the assertions below from
        // reading a field's own initialiser.
        Assert.Null(connection.GetLossTimeAndSpace());

        // TWO PACKETS AT DIFFERENT INSTANTS IN ONE SPACE, which is what makes A.10's own
        // `min` witnessable: with both sent at the same instant a maximum and a minimum are
        // the same number and the else branch's arithmetic is unpinned.
        var early = clock.GetUtcNow();
        var stagger = TimeSpan.FromMilliseconds(2);
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 0, early));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 1, early + stagger));
        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Handshake, 2, early + stagger + stagger));

        var late = early + TimeSpan.FromMilliseconds(1);
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Application, 0, late));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Application, 1, late));

        Acknowledge(connection, TlsQuicEncryptionLevel.Handshake, 2);
        Acknowledge(connection, TlsQuicEncryptionLevel.Application, 1);
        Assert.Empty(connection.DetectAndRemoveLostPackets(TlsQuicEncryptionLevel.Handshake));
        Assert.Empty(connection.DetectAndRemoveLostPackets(TlsQuicEncryptionLevel.Application));

        // A.10: "loss_time[pn_space] = min(loss_time[pn_space], unacked.time_sent +
        // loss_delay)". THE EARLIEST OF THE TWO PACKETS STILL WAITING, and the later one's
        // instant is asserted NOT to be the answer - a maximum would produce exactly it.
        Assert.Equal(early + delay, connection.LossTime(TlsQuicEncryptionLevel.Handshake));
        Assert.NotEqual(
            early + stagger + delay, connection.LossTime(TlsQuicEncryptionLevel.Handshake));

        // THE EARLIER OF THE TWO SPACES, AND WHICH SPACE IT CAME FROM. Asserting the instant
        // alone would pass on an implementation that always answered Initial.
        var earliest = connection.GetLossTimeAndSpace();
        Assert.NotNull(earliest);
        Assert.Equal(early + delay, earliest.Value.At);
        Assert.Equal(TlsQuicEncryptionLevel.Handshake, earliest.Value.Space);

        // AND THE OTHER SPACE'S ENTRY IS STILL THERE - the answer is a minimum ACROSS the
        // spaces, not the only entry that exists.
        Assert.Equal(late + delay, connection.LossTime(TlsQuicEncryptionLevel.Application));
    }

    // ========================================================================
    // bytes_in_flight - RFC 9002 A.4, THROUGH A3-3's Forget AND NOT BESIDE IT.
    // ========================================================================

    [Fact]
    public async Task ANewlyLostPacketLeavesBytesInFlightThroughTheSameForgetPathAnAcknowledgementUses()
    {
        var recovery = new TlsQuicRecoverySpec();
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock, recovery);

        var sentAt = clock.GetUtcNow();
        for (var number = 0UL; number <= (ulong)recovery.PacketThreshold; number++)
        {
            connection.OnPacketSent(
                PacketAt(TlsQuicEncryptionLevel.Application, number, sentAt, size: 100));
        }

        Acknowledge(
            connection, TlsQuicEncryptionLevel.Application, (ulong)recovery.PacketThreshold);
        AssertBytesInFlightAgreesWithRetention(connection);

        var before = connection.BytesInFlight;
        var lost = connection.DetectAndRemoveLostPackets(TlsQuicEncryptionLevel.Application);

        // EXACTLY THE LOST BYTES AND NOT MERELY FEWER, which is what a second removal path
        // that forgot to subtract - or subtracted twice - would fail.
        Assert.Equal(before - lost.Sum(static p => (long)p.Size), connection.BytesInFlight);
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // s6.1's FIRST condition is "The packet is unacknowledged, IN FLIGHT, and was sent prior
    // to an acknowledged packet"; A.10's loop has no in-flight test at all. THE DISAGREEMENT
    // IS REAL AND A.10 IS FOLLOWED - see TlsQuicLossDetection.cs's header for the three
    // reasons. This is that choice pinned, and it asserts the COUNT rather than merely that
    // something happened, so a later reader who prefers s6.1's reading fails this test rather
    // than silently changing what the tree means.
    [Fact]
    public async Task AnAckOnlyPacketIsDeclaredLostByAppendixATenAndDoesNotMoveBytesInFlight()
    {
        var recovery = new TlsQuicRecoverySpec();
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock, recovery);

        var sentAt = clock.GetUtcNow();

        // RFC 9002 A.4: "Packets only containing ACK frames do not count toward
        // bytes_in_flight". TlsQuicPacketBuilderTests.AckOnlyPacketsAreNeitherAckElicitingNor
        // InFlight is where those two flags come from on a real packet.
        connection.OnPacketSent(PacketAt(
            TlsQuicEncryptionLevel.Application,
            0,
            sentAt,
            size: 100,
            ackEliciting: false,
            inFlight: false));
        for (var number = 1UL; number <= (ulong)recovery.PacketThreshold; number++)
        {
            connection.OnPacketSent(
                PacketAt(TlsQuicEncryptionLevel.Application, number, sentAt, size: 100));
        }

        // Only the ack-eliciting packets are counted; the ACK-only one never entered.
        Assert.Equal(100L * recovery.PacketThreshold, connection.BytesInFlight);

        // THE BYTES BEFORE THE ACKNOWLEDGEMENT'S OWN REMOVAL AND THE LOSS ARE SEPARATED BY
        // ARITHMETIC RATHER THAN BY A SECOND CALL, since A3-7 made A.7 run A.10: the ACK
        // retires packet kPacketThreshold (100 in-flight bytes) and the same pass declares
        // packet 0 lost (0 in-flight bytes), so `before` is reconstructed by adding the
        // acknowledged packet's bytes back to what is left.
        var beforeAck = connection.BytesInFlight;
        var lost = Acknowledge(
            connection, TlsQuicEncryptionLevel.Application, (ulong)recovery.PacketThreshold);
        var before = connection.BytesInFlight;
        Assert.Equal(beforeAck - 100L, before);

        Assert.Single(lost);
        Assert.Equal(0UL, lost[0].PacketNumber);
        Assert.False(lost[0].IsInFlight);

        // THE COUNTER DID NOT MOVE FOR THE LOSS, because the packet was never in it - which
        // is the beforeAck - 100 assertion above, one packet's worth for the acknowledgement
        // and nothing for the lost one. A detector that subtracted a not-in-flight packet's
        // size would land 100 lower and fail both of these.
        Assert.Equal(before, connection.BytesInFlight);
        Assert.Equal(100L * (recovery.PacketThreshold - 1), connection.BytesInFlight);
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // ========================================================================
    // NOTHING THROWS FOR ANY INPUT.
    // ========================================================================
    //
    // Every input here is the peer's or the clock's: largest_acked comes off an ACK frame the
    // peer wrote, the RTT terms are computed from instants its timing chose, and the send
    // instants are whatever the retained records carry. A throw on this path is a connection
    // killed by arithmetic.
    [Theory]
    [InlineData(TlsQuicEncryptionLevel.Initial)]
    [InlineData(TlsQuicEncryptionLevel.EarlyData)]
    [InlineData(TlsQuicEncryptionLevel.Handshake)]
    [InlineData(TlsQuicEncryptionLevel.Application)]
    public async Task LossDetectionSurvivesEverySaturatingInput(TlsQuicEncryptionLevel level)
    {
        // The largest multiplier the knob accepts, which turns A.10's `kTimeThreshold * max(
        // latest_rtt, smoothed_rtt)` into an infinity and `now() - loss_delay` into a date
        // before the calendar starts. Both saturate; TimeSpan and DateTimeOffset would throw.
        var recovery = new TlsQuicRecoverySpec
        {
            TimeThreshold = double.MaxValue,
            PacketThreshold = int.MaxValue,
        };

        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock, recovery);

        // NO ACKNOWLEDGEMENT YET: A.10's opening assert, which is a return here.
        Assert.Empty(connection.DetectAndRemoveLostPackets(level));
        Assert.Null(connection.LossTime(level));
        Assert.Null(connection.GetLossTimeAndSpace());

        connection.OnPacketSent(new TlsQuicSentPacket(
            level, 0, int.MaxValue, true, true, DateTimeOffset.MinValue));
        connection.OnPacketSent(new TlsQuicSentPacket(
            level, 1, int.MaxValue, true, true, DateTimeOffset.MaxValue));
        connection.OnPacketSent(new TlsQuicSentPacket(
            level, 2, 0, false, false, clock.GetUtcNow()));

        var lostByTheAcknowledgement = Acknowledge(connection, level, 2);

        // MEASURED RATHER THAN PREDICTED, AND IT CORRECTED THIS TEST. The comment here first
        // said a saturated loss delay declares NOTHING lost by time, because lost_send_time
        // saturates to the start of the calendar. It declares exactly one thing lost: the
        // packet whose send instant IS the start of the calendar, because A.10's comparison is
        // `unacked.time_sent <= lost_send_time` and DateTimeOffset.MinValue satisfies it
        // against itself. That is A.10 followed rather than a defect, and it is pinned here
        // rather than smoothed over - the point of this test is that no input THROWS, and the
        // answer to "what does it do instead" has to be written down to be checked.
        Assert.Equal(
            [0UL], lostByTheAcknowledgement.Select(static p => p.PacketNumber));
        Assert.Equal([1UL], connection.SentPackets(level).Select(static p => p.PacketNumber));

        // AddSaturating's end of the same arithmetic: a packet sent at the end of the calendar
        // plus an effectively infinite delay is still a representable instant.
        Assert.Equal(DateTimeOffset.MaxValue, connection.LossTime(level));

        // IDEMPOTENT. A.10 removes what it declares, so a second pass over the same state
        // declares nothing a second time - a detector that reported the same packet twice
        // would double-subtract from bytes_in_flight.
        Assert.Empty(connection.DetectAndRemoveLostPackets(level));
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // The rejecting path's zero-allocation property, which A3-6 must preserve rather than
    // assume: A.10 "returns a list of packets newly detected as lost", and a fresh list per
    // ACK would be an allocation on the receive path sized by however many packets the peer's
    // acknowledgement pattern leaves outstanding.
    [Fact]
    public async Task RepeatedLossDetectionAllocatesNothing()
    {
        var recovery = new TlsQuicRecoverySpec();
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock, recovery);

        var sentAt = clock.GetUtcNow();
        for (var number = 0UL; number < 8; number++)
        {
            connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Application, number, sentAt));
        }

        Acknowledge(connection, TlsQuicEncryptionLevel.Application, 7);

        // WARMED FIRST, so the internal list has grown to its working size and the measurement
        // below is of the steady state rather than of the first call's growth.
        connection.DetectAndRemoveLostPackets(TlsQuicEncryptionLevel.Application);

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < 64; i++)
        {
            connection.DetectAndRemoveLostPackets(TlsQuicEncryptionLevel.Application);
        }

        Assert.Equal(0L, GC.GetAllocatedBytesForCurrentThread() - before);
    }

    // ========================================================================
    // THE LOOPBACK HALF: LOSS FROM A DATAGRAM THAT WAS REALLY DROPPED.
    // ========================================================================

    // A3-1's decorator drops the client's first 1-RTT datagram. The client then answers a
    // second PATH_CHALLENGE, that answer is delivered, and the peer acknowledges it - so the
    // acknowledgement that moves largest_acked past the dropped packet came off the wire and
    // was written by a peer that does not share this connection's send path.
    //
    // kPacketThreshold IS ONE HERE, AND IT IS A KNOB RATHER THAN A CONVENIENCE. A handshake
    // sends the packet numbers it sends, and getting three 1-RTT packets past a dropped one
    // needs a stream this phase does not have. s6.1.1's "SHOULD NOT use a packet threshold
    // less than 3" is a SHOULD NOT, which TlsQuicRecoverySpec.PacketThreshold's remarks
    // already record as accepted rather than rejected, and the threshold the test compares
    // against is read back off the spec.
    [Fact]
    public async Task ADroppedDatagramsPacketIsDeclaredLostByARealAcknowledgement()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        impaired.Drop(3);

        var spec = LossDetectionSpec(new TlsQuicRecoverySpec { PacketThreshold = 1 });
        await using var connection = Connection(impaired, serverTransport, pki, spec);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        var retainedBefore = await DriveTwoOneRttPacketsAsync(
            connection, serverPeer, impaired, peerPumps: 1, cancellation.Token);

        // LOSS DETECTION IS LIVE, AND THIS IS THE LINE THAT SAYS SO. Nothing in this test calls
        // DetectAndRemoveLostPackets - the pump inside the helper above did, through A.7,
        // because a real acknowledgement written by the peer arrived on a real transport that
        // had really dropped a datagram. Before A3-7 this line read
        // `connection.DetectAndRemoveLostPackets(...)` and the test could not tell a wired
        // detector from an unwired one.
        var lost = connection.LastDetectedLost.ToArray();
        Assert.Equal(1, connection.PacketsDeclaredLost);

        // THE DROPPED PACKET, BY NUMBER, AND IT WAS IN FLIGHT - a PATH_RESPONSE makes the
        // client's answer ack-eliciting, so this is a packet bytes_in_flight was counting.
        Assert.Equal([0UL], lost.Select(static p => p.PacketNumber));
        Assert.True(lost[0].IsInFlight);
        Assert.Equal([3], impaired.Dropped);

        // AND THE THRESHOLD IT CROSSED IS THE SPEC'S. Recomputed here so that a hardcoded 3
        // in the detector fails this test instead of passing it.
        Assert.Equal(
            1UL,
            connection.LargestAcknowledged(TlsQuicEncryptionLevel.Application)!.Value
                - lost[0].PacketNumber);
        Assert.Equal(1, spec.Recovery.PacketThreshold);

        // AND ITS BYTES LEFT bytes_in_flight - exactly its bytes, through A3-3's Forget.
        //
        // TWO REMOVALS IN ONE PASS SINCE A3-7, AND THE ARITHMETIC SEPARATES THEM RATHER THAN
        // SUMMING THEM. The acknowledgement retires packet 1 and the SAME pass declares packet
        // 0 lost, so the counter falls by both; naming each term is what keeps this an
        // assertion about the loss. A Forget that subtracted the wrong packet's size, or
        // subtracted the lost one twice, lands somewhere else.
        var inFlightBefore = retainedBefore.Where(static p => p.IsInFlight).Sum(p => (long)p.Size);
        var acknowledgedBytes =
            retainedBefore.Single(static p => p.PacketNumber == 1UL).Size;
        Assert.Equal(
            inFlightBefore - acknowledgedBytes - lost[0].Size, connection.BytesInFlight);
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // THE LOOPBACK CALIBRATION CONTROL, AND IT IS THE SAME SCRIPT AS THE TEST ABOVE WITH ONE
    // KNOB CHANGED. The datagram is delivered rather than dropped, so nothing is lost - and a
    // detector that declared every unacknowledged packet lost would pass the test above and
    // fail this one on a connection that lost nothing at all.
    [Fact]
    public async Task AnAcknowledgedRunOverTheSameScriptDeclaresNothingLost()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        // HELD, NOT DROPPED: the client's first 1-RTT datagram arrives AFTER its second, which
        // is s6.1's "tolerance for packet reordering" produced by the only thing in this tree
        // that can produce it.
        impaired.HoldUntilAfter(3, releaseAfterOrdinal: 4);

        var spec = LossDetectionSpec(new TlsQuicRecoverySpec());
        await using var connection = Connection(impaired, serverTransport, pki, spec);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        _ = await DriveTwoOneRttPacketsAsync(
            connection, serverPeer, impaired, peerPumps: 2, cancellation.Token);

        // THE LIVE PATH'S OWN VERDICT, for the reason its sibling above states: A3-7 wired A.10
        // into A.7, so the pass this reads is the one the acknowledgement ran.
        var lost = connection.LastDetectedLost;

        Assert.Empty(lost);
        Assert.Equal(0, connection.PacketsDeclaredLost);
        Assert.Empty(impaired.Dropped);
        Assert.Contains(3, impaired.Delivered);

        // AND IT IS WAITING ON THE TIME THRESHOLD RATHER THAN FORGOTTEN, which is A.10's else
        // branch reached from a real handshake.
        Assert.NotNull(connection.LossTime(TlsQuicEncryptionLevel.Application));
        Assert.Contains(
            connection.SentPackets(TlsQuicEncryptionLevel.Application),
            p => p.PacketNumber == 0);
        AssertBytesInFlightAgreesWithRetention(connection);
    }

    // ========================================================================
    // HELPERS
    // ========================================================================

    // Runs the handshake, makes the client send TWO ack-eliciting 1-RTT packets - a
    // PATH_RESPONSE is the only ack-eliciting 1-RTT frame this phase's client emits, and RFC
    // 9000 s12.4 Table 3 gives PATH_CHALLENGE the row "__01", so the peer has to ride each one
    // beside a HANDSHAKE_DONE - and then acknowledges the second.
    //
    // ORDINAL 3 IS THE FIRST OF THE TWO AND ORDINAL 4 THE SECOND, which is what the two tests
    // above script against.
    /// <returns>The Application space's retained packets immediately before the pump that
    /// delivers the peer's acknowledgement - the instant A3-7's wiring made unreachable from
    /// the caller, since the retirement and the loss now happen in the same pass.</returns>
    private static async Task<TlsQuicSentPacket[]> DriveTwoOneRttPacketsAsync(
        TlsQuicConnection connection,
        LoopbackQuicPeer serverPeer,
        ImpairingDatagramTransport impaired,
        int peerPumps,
        CancellationToken cancellationToken)
    {
        await connection.StartAsync(cancellationToken);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellationToken));
        Assert.False(await connection.PumpOnceAsync(cancellationToken));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellationToken));

        await serverPeer.SendHandshakeDoneAsync(
            SentAt, cancellationToken, pathChallengeData: Convert.FromHexString("A0A1A2A3A4A5A6A7"));
        Assert.True(await connection.PumpOnceAsync(cancellationToken));
        Assert.Equal(3, impaired.Offered.Count);

        await serverPeer.SendHandshakeDoneAsync(
            SentAt, cancellationToken, pathChallengeData: Convert.FromHexString("B0B1B2B3B4B5B6B7"));
        Assert.True(await connection.PumpOnceAsync(cancellationToken));
        Assert.Equal(4, impaired.Offered.Count);

        // THE PEER HAS TO HAVE OPENED THE SECOND ONE for its acknowledgement to name it. The
        // count is the caller's because it is the script's: a dropped datagram leaves one to
        // open and a held one leaves two, and pumping a peer with nothing in front of it is
        // what the other tests in this class avoid by counting.
        for (var i = 0; i < peerPumps; i++)
        {
            await serverPeer.PumpOnceAsync(SentAt, cancellationToken);
        }

        Assert.Equal(1UL, serverPeer.LargestApplicationPacketNumberReceived);

        // THE ACKNOWLEDGEMENT, OFF THE WIRE AND WRITTEN BY THE PEER. Whether the client
        // answers it is not asserted, and the reason is a MEASUREMENT: it does. An ACK-only
        // 1-RTT packet is not ack-eliciting, so RFC 9000 s13.2.1 does not require an
        // acknowledgement for it, and this client sends one anyway. That is worth knowing and
        // it is not A3-6's to change, so it is recorded here and the packet it produces is
        // harmless to every assertion above - its number is ABOVE largest_acked, which is the
        // one branch of A.10 that skips a packet outright.
        await serverPeer.SendAckAsync(SentAt, cancellationToken);

        // CAPTURED BEFORE THE PUMP THAT DELIVERS THE ACKNOWLEDGEMENT, and returned, because
        // A3-7 wired A.10 into A.7: the retirement AND the loss now both happen inside the pump
        // below, so a caller measuring anything after it is measuring the two together. A COPY
        // rather than the list, because SentPackets hands back the live one.
        var retainedBeforeTheAck =
            connection.SentPackets(TlsQuicEncryptionLevel.Application).ToArray();

        await connection.PumpOnceAsync(cancellationToken);
        Assert.Equal(
            1UL, connection.LargestAcknowledged(TlsQuicEncryptionLevel.Application));
        return retainedBeforeTheAck;
    }

    // A3-2's knobs reached through the spec seam TlsQuicConnectionSpec.Recovery, with the two
    // knobs every other test in this class sets left where they are.
    private static TlsQuicConnectionSpec LossDetectionSpec(TlsQuicRecoverySpec recovery) => new()
    {
        PaddingTarget = 1200,
        SourceConnectionIdLength = SourceConnectionIdLength,
        Recovery = recovery,
    };

    private static TlsQuicConnection LossDetectionConnectionOn(
        ManualTimeProvider clock, TlsQuicRecoverySpec? recovery = null) =>
        IdleOn(clock, LossDetectionSpec(recovery ?? new TlsQuicRecoverySpec()));

    // A3-3's Packet with the send instant made a parameter: every time-threshold claim here is
    // about the distance between a send instant and the clock, and A3-3's fixed SentAt is in a
    // different month from FakeClock's start.
    private static TlsQuicSentPacket PacketAt(
        TlsQuicEncryptionLevel level,
        ulong number,
        DateTimeOffset sentAt,
        int size = 100,
        bool ackEliciting = true,
        bool inFlight = true) =>
        new(level, number, size, ackEliciting, inFlight, sentAt);

    // The two halves of an acknowledgement arriving, in the order the receive path runs them:
    // TlsQuicAckTracker.ProcessAckFrame advances RFC 9002 A.3's largest_acked_packet, and
    // A.7's OnAckReceived retires what the frame names.
    //
    // BOTH, BECAUSE NEITHER ALONE IS AN ACKNOWLEDGEMENT. A3-3's seam moves retention without
    // moving largest_acked, and A.10's first line reads largest_acked - so a test that called
    // only OnAckReceived would be testing the early return and nothing else.
    //
    // sentPackets IS NULL, which is ProcessAckFrame's "validate the frame and advance
    // LargestAcked without sampling the RTT". The RTT terms these tests compute their expected
    // loss delays from are then A.4's seeds, which is what makes those expectations
    // recomputable from TlsQuicRecoverySpec alone.
    // A3-7 CHANGED WHAT THIS RETURNS AND THE REASON IS THE WHOLE OF A3-7's FIRST CALL LINE.
    // A.7 now runs A.10 itself, so by the time this method returns the acknowledgement has
    // ALREADY declared whatever it declares; a caller that then called
    // DetectAndRemoveLostPackets would be running a second pass over a set the first one had
    // emptied, and would read [] for every packet the live path had just lost. So the packets
    // are read off LastDetectedLost, which is that first pass's own list, and COPIED - it is
    // borrowed and the next pass clears it.
    //
    // THIS IS STRICTLY MORE THAN THE TESTS USED TO PIN. Before A3-7 every assertion below was
    // about a pass the test itself invoked; now every one of them is about a pass the
    // production receive path invoked, and a connection that stopped calling A.10 from A.7
    // fails them rather than passing quietly.
    private static IReadOnlyList<TlsQuicSentPacket> Acknowledge(
        TlsQuicConnection connection, TlsQuicEncryptionLevel level, ulong largest)
    {
        var frame = AckFrame(new TlsQuicAckRange(largest, largest));
        Assert.True(connection.Acks.ProcessAckFrame(level, frame, SentAt, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);

        var before = connection.PacketsDeclaredLost;
        connection.OnAckReceived(level, frame);
        var lost = connection.LastDetectedLost.ToArray();

        // THE CUMULATIVE COUNTER AND THE BORROWED LIST AGREE, checked here rather than in one
        // test: a wiring that called A.10 twice per ACK - once through A.7 and once through the
        // closing SetLossDetectionTimer, say - would leave the list holding only the second
        // pass's find while the counter had moved by both.
        Assert.Equal(before + lost.Length, connection.PacketsDeclaredLost);
        return lost;
    }

    // s6.1.2's threshold for a connection that has taken no RTT sample: A.4 seeds smoothed_rtt
    // at kInitialRtt and leaves latest_rtt at zero, so the inner max is the seed and the
    // expression collapses to max(kTimeThreshold * kInitialRtt, kGranularity).
    //
    // RECOMPUTED FROM THE KNOBS AND NOT THROUGH TlsQuicConnection.LossDelay, deliberately.
    // Routing it through the production method would move every boundary expectation below
    // in step with any mutation of that method, and the boundary tests would then be
    // arithmetic identities. The formula IS pinned against the production one - twice, by
    // TlsQuicConnectionTests.TheLossDelayTakesTheLargerOfTheSmoothedAndLatestRoundTripTimes
    // and .TheTimeThresholdIsFlooredAtTheTimerGranularityAndNotAtNineEighthsOfIt - so this
    // second statement of it is checked rather than merely repeated.
    private static TimeSpan LossDelayOf(TlsQuicRecoverySpec recovery)
    {
        var product =
            new TimeSpan((long)(TlsQuicRecoverySpec.KInitialRtt.Ticks * recovery.TimeThreshold));
        return product > TlsQuicConnection.KGranularity
            ? product
            : TlsQuicConnection.KGranularity;
    }
}
