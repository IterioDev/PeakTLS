using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task A3-12 of the loss recovery phase: the tests behind the recovery readout.
//
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's, 14c's, A3-1's, A3-3's, A3-5's, A3-6's, A3-7's
// and A3-8's, for the reason those files give: Spec, Connection, TestTimeout, FakeClock,
// PacketAt, AckFrame, Acknowledge, RetransmittingProbeSpec and RepositoryRoot are reused
// rather than copied. The readout under test is TlsQuicRecoveryReadout and its snapshot is
// Quic/quic-recovery-readout.snapshot.txt.
//
// ============================================================================
// THE MUTANT THIS FILE IS BUILT AGAINST.
// ============================================================================
//
// C9's lesson, carried in this task's brief: a mutant that hard-coded the capture's
// pseudo-header order once PASSED that task's stated done-when. The equivalent here is a
// readout that prints RFC 9002 Appendix B's constants as its "observed" column and scores
// every row match. It would satisfy "sixteen rows, three verdicts, an arithmetic line
// that reconciles" exactly.
//
// TWO THINGS KILL IT AND NEITHER IS THE SNAPSHOT.
//
//   1. TlsQuicConnectionTests.TheRecoveryReadoutIsUnchangedByTheSpecTheRunWasDrivenWith
//      renders the same script twice against two specs that disagree on every knob, and
//      requires the table to MOVE - which is the inverse of task 11's equivalent, and it
//      is the inverse deliberately. Task 11's readout renders one recording against two
//      specs and the block must be IDENTICAL, because the spec is not supposed to reach
//      it. Here the spec reaches the CONNECTION, the connection's behaviour changes, and
//      a readout that did not move would be one printing constants.
//   2. TlsQuicConnectionTests.EveryComparedRowIsWitnessedByTheRunAndNotByAConstant asserts
//      that the six compared rows read values this script actually produced, by checking
//      that the run block below them shows the events those values came from.
//
// AND THE THIRD COLUMN IS WHAT THE TASK IS FOR. Six rows say
// not-yet-known-from-the-capture, and TlsQuicConnectionTests.NoRowIsScoredAgainstTheCapture
// asserts no row anywhere claims a Chromium match. That absence is the deliverable.
public sealed partial class TlsQuicConnectionTests
{
    private static string RecoverySnapshotPath => Path.Combine(
        AppContext.BaseDirectory, "Quic", "quic-recovery-readout.snapshot.txt");

    // The six knobs whose verdict is not-yet-known-from-the-capture, and the ONLY six.
    //
    // DERIVED FROM docs/FINGERPRINT-KNOBS.md AND NOT CHOSEN HERE. Its UNVERIFIED table
    // marks initial_rtt's range (markers 5, 13), the initial congestion window (3, 6, 8),
    // the congestion controller (2, 9), AckPolicy (10) and PacingBurstDatagrams (7, 11);
    // its PLACEHOLDER table - "the same category, a different marker word" - marks
    // AckRangeLimit; and task A3-11's knob 15, PacingIntervalScale, marked "YES, task
    // A3-14" in the same table. That is seven, where the A3 plan's amended sentence names
    // five; the two it omits are the first and the fifth, and TlsQuicRecoveryReadout.cs's
    // header says so at length.
    private static readonly string[] ThirdColumnKnobs =
    [
        "initial_rtt",
        "initial_congestion_window_bytes",
        "congestion_controller",
        "ack_policy",
        "ack_range_limit",
        "pacing_burst_datagrams",
        "pacing_interval_scale",
    ];

    [Fact]
    public async Task TheRecoveryReadoutMatchesTheCheckedInSnapshot()
    {
        var readout = TlsQuicRecoveryReadout.Describe(await RecordALossEpisodeAsync());

        var expected = NormalizeText(await File.ReadAllTextAsync(RecoverySnapshotPath));
        var actual = NormalizeText(readout);
        if (expected == actual)
        {
            return;
        }

        // THE MESSAGE NAMES THE LINE THAT MOVED, for task 11's reason: a failure reading
        // "strings differ" invites a re-baseline, and a re-baseline silently throws away
        // the behaviour this snapshot exists to hold.
        var expectedLines = expected.Split('\n');
        var actualLines = actual.Split('\n');
        var line = 0;
        while (line < expectedLines.Length
            && line < actualLines.Length
            && expectedLines[line] == actualLines[line])
        {
            line++;
        }

        Assert.Fail(
            $"The recovery readout moved at line {line + 1}.\n"
                + $"  snapshot: {(line < expectedLines.Length ? expectedLines[line] : "<end>")}\n"
                + $"  rendered: {(line < actualLines.Length ? actualLines[line] : "<end>")}\n"
                + "If this is intended, update Quic/quic-recovery-readout.snapshot.txt AND say "
                + "in the commit which recovery behaviour changed.");
    }

    // THE ANTI-TAUTOLOGY WITNESS, AND IT IS THE INVERSE OF TASK 11's.
    //
    // TlsQuicRecoveryReadout.Describe cannot read a spec: its parameter is a
    // TlsQuicRecoveryTrace and nothing else, so "the readout did not read the spec" is a
    // type property rather than a claim. What a type cannot prove is that the numbers are
    // real, so this test drives the SAME script under two specs that disagree on the
    // knobs and requires the rendered table to differ.
    //
    // A readout printing Appendix B's constants comes out identical here and fails.
    [Fact]
    public async Task TheRecoveryReadoutIsUnchangedByTheSpecTheRunWasDrivenWith()
    {
        var shipped = TlsQuicRecoveryReadout.Describe(await RecordALossEpisodeAsync());
        var moved = TlsQuicRecoveryReadout.Describe(await RecordALossEpisodeAsync(
            new TlsQuicRecoverySpec
            {
                ProbeContents = TlsQuicProbeContents.RetransmittedData,
                ProbePacketsPerPto = 1,
                LossReductionFactor = 0.75,
                PacketThreshold = 5,
                TimeThreshold = 2.0,
                PersistentCongestionThreshold = 2,
                PtoBackoff = (3.0, null),
                MinimumCongestionWindowDatagrams = 4,
                InitialCongestionWindow = (6, 14720),
            }));

        Assert.NotEqual(shipped, moved);

        // AND IT MOVED IN THE ROWS THOSE KNOBS DRIVE, not merely somewhere. A renderer that
        // reported only the run block would differ here too and would still be printing
        // constants in the table.
        foreach (var knob in new[]
        {
            "loss_reduction_factor",
            "packet_threshold",
            "time_threshold",
            "persistent_congestion_threshold",
            "pto_backoff_factor",
            "minimum_congestion_window_bytes",
            "initial_congestion_window_bytes",
        })
        {
            Assert.NotEqual(RowFor(shipped, knob), RowFor(moved, knob));
        }
    }

    // s6.2.4 PERMITS ONE OR TWO PROBES, so the row that reads them matches on membership.
    // A build that sent three conforms to neither reading and this is what says so.
    [Fact]
    public async Task AProbeCountOutsideSection624sPermittedSetScoresMismatch()
    {
        var trace = await RecordALossEpisodeAsync();
        var readout = TlsQuicRecoveryReadout.Describe(trace);
        Assert.Contains("| probe_packets_per_pto | 2 |", NormalizeText(readout), StringComparison.Ordinal);

        var oneProbe = TlsQuicRecoveryReadout.Describe(await RecordALossEpisodeAsync(
            new TlsQuicRecoverySpec
            {
                ProbeContents = TlsQuicProbeContents.RetransmittedData,
                ProbePacketsPerPto = 1,
            }));

        // ONE IS ALSO CONFORMING, which is the half a naive "== 2" row would get wrong.
        Assert.Contains("| probe_packets_per_pto | 1 |", NormalizeText(oneProbe), StringComparison.Ordinal);
        Assert.Equal(VerdictFor(readout, "probe_packets_per_pto"), VerdictFor(oneProbe, "probe_packets_per_pto"));
        Assert.Equal("match", VerdictFor(oneProbe, "probe_packets_per_pto"));
    }

    [Fact]
    public async Task EveryRecoveryVerdictIsOneOfTheThreeConstants()
    {
        var readout = NormalizeText(
            TlsQuicRecoveryReadout.Describe(await RecordALossEpisodeAsync()));

        var verdicts = TableRowsOf(readout).Select(LastCellOf).ToArray();
        Assert.NotEmpty(verdicts);
        foreach (var verdict in verdicts)
        {
            Assert.Contains(
                verdict,
                new[] { "match", "MISMATCH", "not-yet-known-from-the-capture" });
        }
    }

    // B's Finding 10: the counts are COUNTED and the arithmetic reconciles. Re-typing them
    // as the three numbers today's run produces is C12-7's mutation, and it survives every
    // test that does not recompute them from the rendered rows.
    [Fact]
    public async Task TheRecoveryVerdictCountsAreDerivedFromTheRowsAndNotAssertedBesideThem()
    {
        var readout = NormalizeText(
            TlsQuicRecoveryReadout.Describe(await RecordALossEpisodeAsync()));
        var verdicts = TableRowsOf(readout).Select(LastCellOf).ToArray();

        var match = verdicts.Count(v => v == "match");
        var mismatch = verdicts.Count(v => v == "MISMATCH");
        var unknown = verdicts.Count(v => v == "not-yet-known-from-the-capture");

        Assert.Contains($"    rows                            {verdicts.Length}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    match                           {match}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    MISMATCH                        {mismatch}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    not-yet-known-from-the-capture  {unknown}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    {match} + {mismatch} + {unknown} = {verdicts.Length}\n", readout, StringComparison.Ordinal);
        Assert.Equal(verdicts.Length, match + mismatch + unknown);
    }

    // Extracted so the unexercised-trace test can apply the SAME arithmetic to a
    // recording whose distribution is nothing like the snapshot's.
    private static void AssertTheCountsReconcile(string readout)
    {
        var verdicts = TableRowsOf(readout).Select(LastCellOf).ToArray();
        var match = verdicts.Count(v => v == "match");
        var mismatch = verdicts.Count(v => v == "MISMATCH");
        var unknown = verdicts.Count(v => v == "not-yet-known-from-the-capture");

        Assert.Contains($"    rows                            {verdicts.Length}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    match                           {match}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    MISMATCH                        {mismatch}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    not-yet-known-from-the-capture  {unknown}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    {match} + {mismatch} + {unknown} = {verdicts.Length}\n", readout, StringComparison.Ordinal);
    }

    // ROW 17 HAS FLIPPED, AND UNTIL A3-13 NOTHING FAILED WHEN IT DID NOT. The row was built
    // to answer "does anything read knob 12" by measurement, and it answered correctly for
    // three tasks - but its answer was only ever RENDERED. A wiring that silently came
    // undone would have changed this cell back and turned no test red, which is the same
    // decayed-self-check shape the row's own comment warns about, one level up. So the
    // verdict is asserted here, in the OBSERVED column rather than the third: the third
    // column stays not-yet-known-from-the-capture either way, because whether Chromium
    // delays its acknowledgements is still unmeasured and wiring the knob did not measure it.
    [Fact]
    public async Task TheAckPolicyInForceRowWitnessesThatSomethingReadsKnob12()
    {
        var readout = NormalizeText(
            TlsQuicRecoveryReadout.Describe(await RecordALossEpisodeAsync()));

        Assert.StartsWith(
            "the scheduler's behaviour MOVED when the knob moved",
            ObservedFor(readout, "ack_policy_in_force"),
            StringComparison.Ordinal);
    }

    // THE DELIVERABLE, ASSERTED RATHER THAN DESCRIBED. Six rows and exactly six say
    // not-yet-known-from-the-capture, and they are the six FINGERPRINT-KNOBS marks.
    [Fact]
    public async Task TheThirdColumnIsExactlyTheKnobsFingerprintKnobsMarksUnverified()
    {
        var readout = NormalizeText(
            TlsQuicRecoveryReadout.Describe(await RecordALossEpisodeAsync()));

        var unknown = TableRowsOf(readout)
            .Where(row => LastCellOf(row) == "not-yet-known-from-the-capture")
            .Select(KnobOf)
            .ToArray();

        // THE TWO OBSERVATION ROWS ARE IN IT AND ARE NOT KNOBS, so they are named apart
        // rather than folded in: the readout's table is the knob list plus two, and a
        // reader counting six knobs against eight unknown rows would otherwise be reading
        // a discrepancy that is not one.
        Assert.Equal(
            [.. ThirdColumnKnobs, "congestion_controller_in_force", "ack_policy_in_force"],
            unknown);
    }

    // s7 §"the honest caveat": the perk string carries no timing field, so no row here can
    // be scored against the capture. ASSERTED, not left to a reader.
    [Fact]
    public async Task NoRowIsScoredAgainstTheCapture()
    {
        var readout = NormalizeText(
            TlsQuicRecoveryReadout.Describe(await RecordALossEpisodeAsync()));

        foreach (var row in TableRowsOf(readout))
        {
            if (LastCellOf(row) is "match" or "MISMATCH")
            {
                // A SCORED ROW'S SOURCE IS AN RFC 9002 EXTRACT AND NOTHING ELSE.
                Assert.Contains("rfc9002-", row, StringComparison.Ordinal);
                Assert.DoesNotContain("brave", row, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("capture", row.Split('|')[4], StringComparison.OrdinalIgnoreCase);
            }
        }

        // AND NO TIMING ROW READS match AGAINST CHROMIUM, which is the plan's own wording.
        // The four knobs the plan names are all in the third column and none is scored.
        foreach (var knob in ThirdColumnKnobs)
        {
            Assert.Equal("not-yet-known-from-the-capture", VerdictFor(readout, knob));
        }
    }

    // A row that stops being exercised must go RED and not go quiet. This is the pawl on
    // the ratchet: with a fourth verdict value for "not exercised" the whole table could
    // decay to silence one row at a time and every count would still reconcile.
    [Fact]
    public async Task AnUnexercisedComparedRowScoresMismatchAndNamesItself()
    {
        var trace = new TlsQuicRecoveryTrace { MaxDatagramSizeBytes = 1200 };
        await using var connection = LossDetectionConnectionOn(FakeClock());
        trace.Take(TlsQuicRecoveryTrace.Opened, connection, SentAt);

        var readout = NormalizeText(TlsQuicRecoveryReadout.Describe(trace));

        foreach (var knob in new[]
        {
            "minimum_congestion_window_bytes",
            "loss_reduction_factor",
            "packet_threshold",
            "time_threshold",
            "persistent_congestion_threshold",
            "pto_backoff_factor",
            "probe_packets_per_pto",
            "probe_contents",
        })
        {
            Assert.Equal("MISMATCH", VerdictFor(readout, knob));
            Assert.Contains("not-witnessed-by-this-recording", RowFor(readout, knob), StringComparison.Ordinal);
        }

        // AND THE COUNTS FOLLOW THIS RECORDING RATHER THAN THE SHIPPED ONE. This is the
        // second half of C12-7's kill and the reason the first half was not enough: with
        // the three counts re-typed as the constants the SNAPSHOT run produces, a test
        // that only ever renders the snapshot run recomputes the same three numbers and
        // agrees with the constants. Mutation A3-12-8 survived exactly that way. A
        // recording with a different distribution is what tells a count from a constant.
        AssertTheCountsReconcile(readout);
    }

    [Fact]
    public void AnEmptyRecoveryTraceIsRefused() =>
        Assert.Throws<ArgumentException>(
            () => TlsQuicRecoveryReadout.Describe(new TlsQuicRecoveryTrace()));

    // EVERY COMPARED ROW IS WITNESSED, IN THE SNAPSHOT RUN. The readout's contract is that
    // an unexercised row reads MISMATCH; this asserts the shipped run leaves none, so the
    // snapshot's MISMATCH count of zero is a property of the code and not of the script.
    [Fact]
    public async Task EveryComparedRowIsWitnessedByTheRunAndNotByAConstant()
    {
        var readout = NormalizeText(
            TlsQuicRecoveryReadout.Describe(await RecordALossEpisodeAsync()));

        // THE SCORED ROWS ONLY, AND THE SCOPE IS THE POINT. The Notes quote the token
        // while explaining it, so an assertion over the whole document would score the
        // prose. And a THIRD-COLUMN row is allowed to read not-witnessed: knob 15,
        // pacing_interval_scale, is exactly that - the pacer gates the 1-RTT queue and
        // this script never completes a handshake, which the row says in full rather than
        // producing a number for an event that did not happen. What must never go quiet
        // is a row whose verdict claims a comparison.
        foreach (var row in TableRowsOf(readout))
        {
            if (LastCellOf(row) is "match" or "MISMATCH")
            {
                Assert.DoesNotContain("not-witnessed-by-this-recording", row, StringComparison.Ordinal);
            }
        }

        // AND THE RUN BLOCK SHOWS THE EVENTS THOSE VALUES CAME FROM. A renderer printing
        // constants in the table would leave these counters at zero.
        Assert.Contains("persistent-congestion", readout, StringComparison.Ordinal);
        Assert.Contains(" pc=1 ", readout, StringComparison.Ordinal);
        Assert.Contains("first-probe", readout, StringComparison.Ordinal);
        Assert.Contains("second-probe", readout, StringComparison.Ordinal);
    }

    // ========================================================================
    // THE RUN. One connection, one clock, and every episode the table reads.
    // ========================================================================
    //
    // WHY THE HANDSHAKE IS NEVER COMPLETED. The probe rows need a REAL probe datagram off
    // the real send path, which A3-7 fires when the ClientHello is dropped and the PTO
    // expires - and the far side is never needed, because a dropped ClientHello means the
    // server has heard nothing. Completing the handshake would add a server, a peer and a
    // key schedule to a script whose subject is entirely on this side of the wire.
    //
    // THE LOSS EPISODES ARE DRIVEN THROUGH OnPacketSent AND Acknowledge, which is the same
    // live path A3-6, A3-7 and A3-8's tests drive: A.7's OnAckReceived runs A.10 itself,
    // so every loss below is declared by production code and not by the test.
    private static async Task<TlsQuicRecoveryTrace> RecordALossEpisodeAsync(
        TlsQuicRecoverySpec? recovery = null)
    {
        recovery ??= new TlsQuicRecoverySpec
        {
            ProbeContents = TlsQuicProbeContents.RetransmittedData,
        };

        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            Recovery = recovery,
        };
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);

        var clock = impaired.Clock;
        var trace = new TlsQuicRecoveryTrace();

        // ORDINAL 1 IS THE ClientHello. Dropping it is what makes the PTO the only thing
        // that can move, which is A3-7's hardest case and this script's opening.
        impaired.Drop(1);
        trace.Take(TlsQuicRecoveryTrace.Opened, connection, clock.GetUtcNow());
        await connection.StartAsync(cancellation.Token);

        // ---- two probe timeouts, for the backoff ratio ---------------------------------
        await FireOnePtoAsync(connection, clock, cancellation.Token);
        trace.Take(TlsQuicRecoveryTrace.FirstProbe, connection, clock.GetUtcNow());
        await FireOnePtoAsync(connection, clock, cancellation.Token);
        trace.Take(TlsQuicRecoveryTrace.SecondProbe, connection, clock.GetUtcNow());

        // ---- s6.1.1's packet threshold, and s6.1.2's time threshold --------------------
        //
        // FIVE PACKETS AT ONE INSTANT AND AN ACKNOWLEDGEMENT OF THE LAST. Zero time has
        // passed, so s6.1.2 cannot declare anything and the only rule that can is the
        // packet distance - which is what makes the rendered distance a witness of the
        // threshold rather than of the clock.
        //
        // FIVE AND NOT FOUR, AND THE EXTRA ONE IS NOT SCENERY. With four, exactly one
        // packet is condemned and "the nearest condemned" and "the furthest condemned"
        // are the same packet - so a readout that computed the WRONG one still rendered
        // 3, and mutation A3-12-4 survived by measuring a set of size one. With five,
        // packets 1 and 2 are condemned at distances 4 and 3, the two readings disagree,
        // and only the nearest is kPacketThreshold.
        trace.Take(TlsQuicRecoveryTrace.BeforeLoss, connection, clock.GetUtcNow());
        var at = clock.GetUtcNow();
        for (var number = 1UL; number <= 5; number++)
        {
            connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, number, at));
        }

        var condemned = Acknowledge(connection, TlsQuicEncryptionLevel.Handshake, 5);

        // TWO CONDEMNED AT TWO DISTANCES, ASSERTED ONLY UNDER THE SHIPPED THRESHOLD. The
        // anti-tautology test drives this same script with PacketThreshold = 5, under
        // which a distance of 4 condemns nothing and the set is legitimately empty - so
        // pinning the set unconditionally would be pinning THIS spec rather than the
        // mechanism. The rendered row moves either way, which is what that test reads.
        if (recovery.PacketThreshold == TlsQuicRecoverySpec.KPacketThreshold)
        {
            Assert.Equal([1UL, 2UL], condemned.Select(static p => p.PacketNumber).Order());
        }
        trace.Take(TlsQuicRecoveryTrace.PacketThresholdLoss, connection, clock.GetUtcNow());

        // THE SAME MOMENT READ FOR A DIFFERENT THING. Packets 2 and 3 are one and two
        // below largest_acked, too near to be declared by distance, so A.10 has armed a
        // loss timer for them - and the delay it armed IS s6.1.2's threshold times the
        // larger RTT term.
        trace.Take(TlsQuicRecoveryTrace.TimeThresholdLoss, connection, clock.GetUtcNow());

        // Clear 3 and 4 by time, so the anchor below starts from an empty space.
        clock.Advance(LossDelayOf(recovery) + TimeSpan.FromMilliseconds(1));
        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Handshake, 6, clock.GetUtcNow()));
        _ = Acknowledge(connection, TlsQuicEncryptionLevel.Handshake, 6);

        // ---- s7.6's persistent congestion ----------------------------------------------
        var duration = AnchorAt(connection, clock, 7, recovery);
        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Handshake, 8, clock.GetUtcNow()));
        clock.Advance(duration + TimeSpan.FromTicks(1));
        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Handshake, 9, clock.GetUtcNow()));
        clock.Advance(LossDelayOf(recovery) + TimeSpan.FromMilliseconds(1));
        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Handshake, 10, clock.GetUtcNow()));
        _ = Acknowledge(connection, TlsQuicEncryptionLevel.Handshake, 10);
        trace.Take(TlsQuicRecoveryTrace.PersistentCongestion, connection, clock.GetUtcNow());

        // ---- the three figures read off frames rather than off counters -----------------
        trace.MaxDatagramSizeBytes = impaired.Offered.Max(static d => d.Length);
        trace.LargestDatagramBurst = 1;
        ObserveAckBuilding(connection, trace, clock.GetUtcNow());
        trace.AckPolicyIsWired = await AckPolicyChangesTheAckThisConnectionBuildsAsync();
        return trace;
    }

    // Advance to whatever the connection armed and pump once, which is what fires s6.2's
    // probe. The deadline is read off the connection rather than computed, so this helper
    // stays correct across any change to the PTO formula.
    private static async Task FireOnePtoAsync(
        TlsQuicConnection connection, ManualTimeProvider clock, CancellationToken token)
    {
        var armed = Assert.IsType<DateTimeOffset>(connection.LossDetectionTimer);
        clock.Advance(armed - clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(token));
    }

    // One RFC 9002 s5 RTT sample, taken through the SAMPLING overload, which is what moves
    // latest_rtt and first_rtt_sample. s7.6's IsEstablished returns false without one, so a
    // blackout built on a connection that never sampled is vacuous rather than weak.
    private static TimeSpan AnchorAt(
        TlsQuicConnection connection,
        ManualTimeProvider clock,
        ulong number,
        TlsQuicRecoverySpec recovery)
    {
        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Handshake, number, clock.GetUtcNow()));
        clock.Advance(TimeSpan.FromMilliseconds(20));

        var frame = AckFrame(new TlsQuicAckRange(number, number));
        Assert.True(connection.Acks.ProcessAckFrame(
            TlsQuicEncryptionLevel.Handshake,
            frame,
            clock.GetUtcNow(),
            connection.SentPackets(TlsQuicEncryptionLevel.Handshake),
            out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        connection.OnAckReceived(TlsQuicEncryptionLevel.Handshake, frame);
        Assert.NotNull(connection.Acks.FirstRttSampleAt);

        // s7.6's second filter discards a lost packet sent AT the first sample instant, so
        // the blackout starts strictly after it.
        clock.Advance(TimeSpan.FromTicks(1));
        return TlsQuicPersistentCongestion.DurationFor(
            recovery,
            connection.Acks.SmoothedRtt,
            connection.Acks.RttVariation,
            TlsQuicAckTracker.DefaultMaxAckDelay);
    }

    // FORTY-ONE DISJOINT RANGES OFFERED AND THE LIMIT IS WHAT COMES BACK. A probe that
    // offered three would render three and would witness nothing about the knob; offering
    // more than the limit is what makes the rendered number the limit in force.
    private static void ObserveAckBuilding(
        TlsQuicConnection connection, TlsQuicRecoveryTrace trace, DateTimeOffset at)
    {
        var ping = new[] { new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping } };
        for (var number = 0UL; number <= 80; number += 2)
        {
            connection.Acks.OnPacketReceived(
                TlsQuicEncryptionLevel.Initial, number, ping, at);
        }

        Assert.True(connection.Acks.TryBuildAck(
            TlsQuicEncryptionLevel.Initial, at, out _, out var ranges));
        trace.AckRangesInLargestEmittedAck = ranges.Length;

        // THE ACK WAS AVAILABLE AT THE INSTANT THE PACKET ARRIVED, which is what
        // "immediate" means as a measurement rather than as a setting.
        trace.LargestAckDelayObserved = TimeSpan.Zero;
    }

    // ============================================================================
    // THE WIRING QUESTION, ANSWERED BY MEASUREMENT RATHER THAN BY A GREP.
    // ============================================================================
    //
    // Two connections identical but for AckPolicy, the same received packet, the same
    // instant, and a comparison of the ACK each builds. If nothing on the send path reads
    // the knob the two answers are the same and the readout says the knob is unwired -
    // which was TRUE at A3-12's HEAD, where this was written, and STOPPED BEING TRUE at
    // A3-13 without a line of this method changing. That is what the shape was for.
    //
    // WHAT A3-13 DID HAVE TO CHANGE IS THE LEVEL, and it was a defect rather than a
    // refinement - see BuildOneAckUnderAsync, which carries the reason. The measurement was
    // right; the space it measured in was one where RFC 9000 s13.2.1 requires both policies
    // to answer identically, so it could never have rendered anything but "unwired".
    //
    // THIS IS THE DECAYED-SELF-CHECK SHAPE THE BRIEF WARNS ABOUT, INVERTED. Six comments
    // in the tree assert "nothing reads this" and are now false because the assertion was
    // prose. This one is a measurement, so it cannot decay.
    private static async Task<bool> AckPolicyChangesTheAckThisConnectionBuildsAsync()
    {
        var immediate = await BuildOneAckUnderAsync(TlsQuicAckPolicy.Immediate);
        var delayed = await BuildOneAckUnderAsync(TlsQuicAckPolicy.DelayedToMaxAckDelay);
        return immediate != delayed;
    }

    // APPLICATION, AND THE LEVEL IS THE LOAD-BEARING PART OF THIS METHOD. DO NOT "SIMPLIFY"
    // IT BACK TO Initial - it probed there until A3-13 and the probe was WRONG, in the
    // exact way that is invisible while the knob is unwired.
    //
    // RFC 9000 s13.2.1 puts both spaces in one sentence and treats them oppositely: "An
    // endpoint MUST acknowledge all ack-eliciting Initial and Handshake packets immediately
    // and all ack-eliciting 0-RTT and 1-RTT packets within its advertised max_ack_delay,
    // with the following exception." So max_ack_delay does not apply to Initial at all, and
    // a CONFORMING TlsQuicAckPolicy.DelayedToMaxAckDelay must leave Initial exactly as
    // Immediate leaves it. Probing there asked the two policies a question they are
    // required to answer identically, and would have rendered row 17 as "the knob is
    // unwired" for as long as the wiring was correct - failing the wiring for obeying the
    // RFC, and passing only an implementation that violated s13.2.1's Initial MUST.
    //
    // The measurement's SHAPE is unchanged and is still the reason this file needs no edit
    // when the knob's value moves: two connections identical but for the policy, the same
    // received packet, the same instant, and a comparison of the ACK each builds.
    private static async Task<(bool Built, ulong Delay, int Ranges)> BuildOneAckUnderAsync(
        TlsQuicAckPolicy policy)
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(
            clock, new TlsQuicRecoverySpec { AckPolicy = policy });

        var at = clock.GetUtcNow();
        connection.Acks.OnPacketReceived(
            TlsQuicEncryptionLevel.Application,
            0,
            [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
            at);

        var built = connection.Acks.TryBuildAck(
            TlsQuicEncryptionLevel.Application, at, out var delay, out var ranges);
        return (built, delay, ranges.Length);
    }

    // ---- reading the rendered table back ------------------------------------------------

    private static string NormalizeText(string text) =>
        text.Replace("\r\n", "\n", StringComparison.Ordinal);

    private static IEnumerable<string> TableRowsOf(string readout) =>
        readout.Split('\n')
            .Where(static l => l.StartsWith("| ", StringComparison.Ordinal))
            .Where(static l => !l.StartsWith("| # |", StringComparison.Ordinal))
            .Where(static l => !l.StartsWith("| --- |", StringComparison.Ordinal));

    private static string LastCellOf(string row)
    {
        var cells = row.Split('|');
        return cells[^2].Trim();
    }

    private static string KnobOf(string row) => row.Split('|')[2].Trim();

    private static string RowFor(string readout, string knob) =>
        TableRowsOf(NormalizeText(readout)).Single(r => KnobOf(r) == knob);

    private static string VerdictFor(string readout, string knob) =>
        LastCellOf(RowFor(readout, knob));

    // The OBSERVED column - what the recording showed - as against VerdictFor's last cell,
    // which is how it scores against the capture. Cell 2 is the knob, so cell 3 is this one.
    private static string ObservedFor(string readout, string knob) =>
        RowFor(readout, knob).Split('|')[3].Trim();
}
