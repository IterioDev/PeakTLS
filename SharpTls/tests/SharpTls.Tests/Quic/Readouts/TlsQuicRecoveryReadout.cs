using System.Globalization;
using System.Text;

namespace SharpTls.Quic;

// Task A3-12 of the loss recovery phase: the recovery fingerprint readout.
//
// ============================================================================
// WHY THIS IS A NEW FILE AND NOT AN EXTENSION OF TlsQuicFingerprintReadout.cs.
// ============================================================================
//
// The plan named TlsQuicFingerprintReadout.cs. Three things made a separate file the
// smaller change rather than the larger one, and they are named here because the
// deviation is deliberate.
//
//   1. THE INPUT IS A DIFFERENT KIND OF THING. That readout is a pure function of a
//      byte recording: hand it the datagrams and it re-derives every row by parsing
//      them. Recovery has almost nothing in the datagrams - a congestion window is not
//      a field, a loss-reduction factor is not a field - so its evidence is a sequence
//      of OBSERVATIONS taken off a live connection while it was losing packets. Bolting
//      a second, differently-shaped entry point onto a file whose whole contract is
//      "bytes in, rows out" would have blurred the one property that makes that file
//      trustworthy.
//   2. THAT FILE IS ALREADY 1,385 LINES. This one adds roughly four hundred.
//   3. THE SNAPSHOTS ARE SEPARATE ARTEFACTS. quic-fingerprint-readout.snapshot.txt pins
//      an opening flight; this one pins a loss episode. One file rendering both would
//      make either snapshot move when the other subsystem moved.
//
// The three verdict constants are still TlsQuicHttp3FingerprintReadout's, imported and
// not re-declared, for the reason that file gives: a second copy of the string
// "MISMATCH" is how two readouts start disagreeing about what a verdict is.
//
// ============================================================================
// THE RULE THIS FILE IS BUILT AROUND, AND THE FORM IT IS ENFORCED IN.
// ============================================================================
//
// A3-12's done-when: "every rendered value is derived from the connection's live
// recovery state and not from the spec object". A readout of the values a caller typed
// in is a restatement of its own input and is evidence about nothing.
//
// THE ENFORCEMENT IS STRUCTURAL AND NOT A CONVENTION: Describe's signature does not
// admit a TlsQuicRecoverySpec, a TlsQuicConnectionSpec or a TlsQuicConnection. It takes
// a TlsQuicRecoveryTrace, which is a sequence of samples of live counters plus two
// figures measured off emitted frames. There is no reachable path from a rendered row
// back to a settable knob, so the anti-tautology property is a type error rather than a
// test - which is strictly stronger than task 11's
// TlsQuicFingerprintReadoutTests.TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith,
// whose equivalent is still asserted here as
// TlsQuicConnectionTests.TheRecoveryReadoutIsUnchangedByTheSpecTheRunWasDrivenWith
// because a type error proves the spec was not READ and that test proves the numbers
// actually MOVE with behaviour.
//
// ============================================================================
// THE VERDICT COLUMN HAS EXACTLY THREE VALUES, AND HERE IS WHAT EACH MEANS.
// ============================================================================
//
// The plan offered a choice - "a fourth verdict value, or an explicit 'source: RFC 9002
// default, not the capture' column, is this task's design call". This file takes the
// second: FOUR columns, three verdicts.
//
//   match    - this recording WITNESSED a value, and the cited RFC 9002 extract states
//              that value. It is a match against a document, never against the capture.
//   MISMATCH - this recording witnessed a value the cited extract contradicts, OR the
//              recording did not witness the row at all. A row that stops being
//              exercised turns red rather than turning silent, which is the difference
//              between a snapshot and a snapshot with a pawl.
//   not-yet-known-from-the-capture
//            - NOTHING external states a value for this knob. Not the Brave capture,
//              which has no timing field at all, and not RFC 9002, which either leaves
//              the choice open or states a value this project has explicitly recorded
//              as unmeasured against Chromium. These rows name the task that would
//              settle them.
//
// THE DISCRIMINATOR FOR THE THIRD COLUMN IS NOT INVENTED HERE. A row is third-column
// if and only if docs/FINGERPRINT-KNOBS.md carries an UNVERIFIED or PLACEHOLDER marker
// for that knob. That list is the project's, it is maintained, and tying the column to
// it means the two cannot drift apart silently -
// TlsQuicConnectionTests.TheThirdColumnIsExactlyTheKnobsFingerprintKnobsMarksUnverified
// re-derives the set from this file and fails if a row is added to one and not the
// other.
//
// AND THE COUNT IS SEVEN, WHERE THE PLAN SAYS FIVE. The plan's amended list is the
// initial congestion window, the controller identity, the ACK policy, the pacing burst
// and - since task A3-11 landed underneath this one - the pacing interval scale.
// FINGERPRINT-KNOBS marks two more that the plan's sentence omits, and both are real:
//
//   - THE INITIAL RTT RANGE. Markers 5 and 13 (initial_rtt's range;
//     Brave151InitialRttRange, "the only genuinely invented bound in this file"). The
//     preset draws from a 100-300 ms interval whose WIDTH is arbitrary. RFC 9002
//     App. B states 333 ms and this library's default is that, but a knob whose
//     shipped preset is an invented interval is exactly what the third column is for.
//   - AckRangeLimit. It sits in FINGERPRINT-KNOBS' PLACEHOLDER table rather than its
//     UNVERIFIED table - a different marker word for the same category, as that file
//     says in as many words - and TlsQuicFingerprintReadout.cs's deviation note 4
//     already puts it "in the same not-yet-known-from-the-capture category as the
//     initial packet number and the initial_rtt range". Scoring it any other way would
//     make two readouts in the same subsystem disagree about the same knob.
//
// ============================================================================
// THE HONEST CAVEAT, WHICH IS THE MOST VALUABLE THING THIS FILE PRODUCES.
// ============================================================================
//
// NO ENDPOINT THIS PROJECT CAN REACH OBSERVES ANY OF THESE KNOBS. The perk string has
// four segments - h3 SETTINGS, pseudo-header order, transport parameters in wire order,
// CID lengths - and not one of them is a timing field. So no row here can ever read
// "match" against Chromium, and TlsQuicConnectionTests.NoRowIsScoredAgainstTheCapture
// asserts the absence rather than leaving a reader to check it: every row's source cell
// names an RFC 9002 extract or names the task that would settle it, and none names the
// capture.
//
// A row scored "match" therefore says "we do what RFC 9002 says", which is a real and
// falsifiable claim, and says NOTHING about whether we do what Chromium does. Task
// A3-14 is what changes that, and it is named in every third-column row.
// ============================================================================
// MUTATION LEDGER - task A3-12, 22 cases.
// ============================================================================
//
// Run in a private worktree at c085032, one case at a time, each restored before
// the next. KILLED-BY-COMPILER is assigned from the BUILD exit code and never
// inferred from a test log; every case here built, so none was one. The sweep was
// never piped, so the exit code reported was the harness's own. Harness:
// mutate-a3-12.py, floor 22 cases, which aborts rather than reporting a short run.
//
// 21 killed + 1 survived = 22 cases.
//
// AN EARLIER RUN OF THIS SWEEP AT ebdcc89 REPORTED 15 KILLED AND 4 SURVIVED, and
// three of those four survivors are why the code below reads as it does. A3-12-4
// was not a weak test - it was a WRONG READOUT: the packet-threshold row took the
// distance to the furthest condemned packet when kPacketThreshold is the distance
// to the NEAREST, and the run condemned exactly one packet so the two coincided and
// the bug was invisible. A3-12-8 was C12-7's shape surviving because every test
// rendered the same recording, so re-typed constants and recomputed counts agreed.
// A3-12-11 was unreachable by construction: no ROW read the armed PTO at a sample
// where a loss timer was in force. The fixes are, in order: the correct reading and
// a two-packet condemnation that separates it from the wrong one; the arithmetic
// asserted on a second recording with a different distribution; and both timer
// kinds rendered as their own columns in the run block.
//
//   1. Compared's verdict inverted
//        Killed by 2.
//   2. an unexercised row scores match instead of MISMATCH
//        Killed by 1.
//   3. Ratio inverted - before/after
//        Killed by 1.
//   4. packet distance taken from the FURTHEST condemned packet - the shipped bug this sweep's first run found, now witnessed by a two-packet condemnation
//        Killed by 1.
//   5. s6.1.2's max(smoothed, latest) read as min
//        Killed by 3.
//   6. s7.6's 4*rttvar read as 2*rttvar
//        Killed by 1.
//   7. probe shape's repair test inverted, so a repairing probe reads PING-only
//        Killed by 1.
//   8. C12-7's shape: the counts written as today's three constants
//        Killed by 3.
//   9. the match count counts every row
//        Killed by 3.
//   10. the sample reads latest_rtt where it means smoothed_rtt
//        Killed by 3.
//   11. A.8's two timer kinds conflated
//        Killed by 1.
//   12. s6.2.4's permitted SET scored as equality with its first member
//        Killed by 2.
//   13. ack_policy scored match against a capture that cannot see it
//        Killed by 3.
//   14. Plural always plural
//        Killed by 1.
//   15. the rendered initial RTT gains a decimal place
//        Killed by 1.
//   16. an immediate ACK reported as delayed
//        Killed by 1.
//   17. the controller-in-force row reads the OPENING sample
//        Killed by 1.
//   18. CALIBRATION known-bad: s6.1.1's cited threshold mistyped
//        Killed by 1.
//   19. CALIBRATION inert: a comment above the class declaration
//        SURVIVED by 0.
//   20. s7.7's off switch inverted, so a running pacer reports no pacer
//        Killed by 1.
//   21. the pacer's burst reported in BYTES rather than in datagrams
//        Killed by 1.
//   22. an unarmed timer rendered as an armed one at zero
//        Killed by 1.
//
// THE SURVIVORS, EACH CLASSIFIED RATHER THAN LISTED.
//   A3-12-19 is VACUOUS BY CONSTRUCTION and is the harness's own proof: an inert
//   comment reporting KILLED would mean the runs were not measuring the binary
//   they had just built. Its partner, A3-12-18, is the known-bad control and was
//   killed. Every other case died.
// ============================================================================
internal static class TlsQuicRecoveryReadout
{
    // ---- the cited figures ---------------------------------------------------------
    //
    // EVERY CONSTANT IN THIS SECTION HAS AN EXTERNAL SOURCE, which is the whole
    // difference between this block and the snapshot the tests hold. The paths are the
    // RFC 9002 extracts task A3-0 put in the tree.

    private const string AppendixB =
        "rfc9002-appendix-a-and-b-pseudocode-and-constants.txt";

    private const string Section61 = "rfc9002-section6-loss-detection.txt";

    private const string Section62 = "rfc9002-section6.2-probe-timeout.txt";

    private const string Section7 = "rfc9002-section7-congestion-control.txt";

    // App. B: kInitialRtt = 333ms, kLossReductionFactor = 0.5, kPacketThreshold = 3,
    // kTimeThreshold = 9/8, kPersistentCongestionThreshold = 3, kMinimumWindow =
    // 2 * max_datagram_size.
    private const double CitedLossReductionFactor = 0.5;

    private const int CitedPacketThreshold = 3;

    private const double CitedTimeThreshold = 9.0 / 8.0;

    private const int CitedPersistentCongestionThreshold = 3;

    private const int CitedMinimumWindowDatagrams = 2;

    // s6.2.1: "the PTO backoff factor ... doubles". Two clients diverge by the third
    // probe, so the factor is measured off two consecutive arms rather than assumed.
    private const double CitedPtoBackoffFactor = 2.0;

    // s6.2.4 permits either, in its own words: "a sender MUST send at least one
    // ack-eliciting packet in the packet number space as a probe" and "an endpoint MAY
    // send up to two full-sized datagrams". So one AND two are conforming, and this row
    // matches on membership rather than on equality - a build that sent three would not.
    private static readonly int[] CitedProbePacketsPerPto = [1, 2];

    // RFC 9000 s8.1's floor, used to tell a padded probe from a bare one WITHOUT reading
    // TlsQuicConnectionSpec.PaddingTarget. The number is the RFC's, not the spec's.
    private const int Section81PaddingFloor = 1200;

    private const string A314 = "task A3-14 - acquire the timing capture";

    private const string B12 = "task B12 - the capture request";

    private const string NotWitnessed = "not-witnessed-by-this-recording";

    // ---- rendering -------------------------------------------------------------------

    // One rendered row. Verdict is one of TlsQuicHttp3FingerprintReadout's three
    // constants and nothing else, which
    // TlsQuicConnectionTests.EveryRecoveryVerdictIsOneOfTheThreeConstants checks over
    // the rendered text rather than over this type.
    private sealed record Row(string Knob, string Observed, string Source, string Verdict);

    internal static string Describe(TlsQuicRecoveryTrace trace)
    {
        ArgumentNullException.ThrowIfNull(trace);
        if (trace.Samples.Count == 0)
        {
            throw new ArgumentException(
                "A recovery readout needs at least one observation. An empty trace would "
                    + "render every row as an absence, which is a different claim from a "
                    + "connection that never lost anything.",
                nameof(trace));
        }

        return Render(BuildRows(trace), trace);
    }

    private static List<Row> BuildRows(TlsQuicRecoveryTrace trace)
    {
        var opened = trace.Samples[0];
        var probe1 = trace.Find(TlsQuicRecoveryTrace.FirstProbe);
        var probe2 = trace.Find(TlsQuicRecoveryTrace.SecondProbe);
        var packetLoss = trace.Find(TlsQuicRecoveryTrace.PacketThresholdLoss);
        var timeLoss = trace.Find(TlsQuicRecoveryTrace.TimeThresholdLoss);
        var beforeLoss = trace.Find(TlsQuicRecoveryTrace.BeforeLoss);
        var collapse = trace.Find(TlsQuicRecoveryTrace.PersistentCongestion);

        return
        [
            // ---- knob 1 ---------------------------------------------------------------
            //
            // A.4 seeds smoothed_rtt at kInitialRtt and takes no sample until an
            // acknowledgement arrives, so the estimator's own reading BEFORE the first
            // sample is the drawn initial RTT and nothing else. Reading it any later
            // would read a measured RTT and call it a knob.
            new Row(
                "initial_rtt",
                opened.HasRttSample
                    ? NotWitnessed + " (this sample already carried an RTT measurement)"
                    : Milliseconds(opened.SmoothedRtt),
                $"{AppendixB} kInitialRtt = 333 ms; the PRESET's RANGE is invented - "
                    + $"FINGERPRINT-KNOBS markers 5 and 13, {B12}",
                TlsQuicHttp3FingerprintReadout.NotYetKnown),

            // ---- knob 2 ---------------------------------------------------------------
            new Row(
                "initial_congestion_window_bytes",
                opened.CongestionWindowBytes.ToString(CultureInfo.InvariantCulture),
                $"App. B states min(10 * max_datagram, max(14720, 2 * max_datagram)); what "
                    + $"CHROMIUM uses is unmeasured - FINGERPRINT-KNOBS markers 3, 6, 8, "
                    + $"{A314}",
                TlsQuicHttp3FingerprintReadout.NotYetKnown),

            // ---- knob 3 ---------------------------------------------------------------
            //
            // WITNESSED BY A COLLAPSE AND NOT BY A CONSTRUCTOR. s7.6's persistent
            // congestion is the only event that drives the window to kMinimumWindow, so
            // this row is rendered from the window AFTER a blackout that established one.
            Compared(
                "minimum_congestion_window_bytes",
                collapse is { } c
                    ? c.CongestionWindowBytes.ToString(CultureInfo.InvariantCulture)
                    : NotWitnessed,
                (CitedMinimumWindowDatagrams * (long)trace.MaxDatagramSizeBytes)
                    .ToString(CultureInfo.InvariantCulture),
                $"{Section7} s7.6 / App. B kMinimumWindow = 2 * max_datagram_size, and this "
                    + $"recording's max_datagram_size is {trace.MaxDatagramSizeBytes} bytes "
                    + "as the transport reported it"),

            // ---- knob 4 ---------------------------------------------------------------
            //
            // THE LARGEST SINGLE FINGERPRINT IN A3, AND THE ONE NOTHING CAN SCORE. s7 makes
            // the controller replaceable in its own words; which one Chromium runs is a
            // widely repeated claim this project has not measured.
            new Row(
                "congestion_controller",
                opened.ControllerName,
                $"{Section7} s7 makes the controller replaceable; which one CHROMIUM runs is "
                    + $"unmeasured - FINGERPRINT-KNOBS markers 2, 9, {A314}",
                TlsQuicHttp3FingerprintReadout.NotYetKnown),

            // ---- knob 5 ---------------------------------------------------------------
            //
            // MEASURED AS A RATIO OF TWO WINDOWS AND NOT READ OFF ANYTHING. NewReno halves
            // on loss and BBR does not, so one recovery episode is enough to tell them
            // apart - which is precisely why the ratio and not the setting is the evidence.
            Compared(
                "loss_reduction_factor",
                Ratio(
                    beforeLoss?.CongestionWindowBytes,
                    packetLoss?.CongestionWindowBytes),
                CitedLossReductionFactor.ToString("0.000", CultureInfo.InvariantCulture),
                $"{AppendixB} kLossReductionFactor = 0.5"),

            // ---- knob 6 ---------------------------------------------------------------
            //
            // s6.1.1's REORDERING TOLERANCE, read as the packet-number distance below
            // largest_acked at which this recording actually declared something lost. A
            // build with a different threshold declares at a different distance and this
            // row moves; a build that stopped declaring at all renders NotWitnessed and
            // the row turns red rather than silent.
            Compared(
                "packet_threshold",
                Distance(packetLoss),
                CitedPacketThreshold.ToString(CultureInfo.InvariantCulture),
                $"{Section61} s6.1.1 kPacketThreshold = 3"),

            // ---- knob 7 ---------------------------------------------------------------
            //
            // THE SAME TOLERANCE ON THE TIME AXIS, read as the loss delay this connection
            // ARMED divided by the larger of its two RTT terms. s6.1.2's expression is
            // max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity), so the
            // quotient is the threshold whenever the product clears the granularity floor.
            Compared(
                "time_threshold",
                TimeThresholdOf(timeLoss),
                CitedTimeThreshold.ToString("0.000", CultureInfo.InvariantCulture),
                $"{Section61} s6.1.2 kTimeThreshold = 9/8"),

            // ---- knob 8 ---------------------------------------------------------------
            //
            // DERIVED FROM THE BLACKOUT THIS RECORDING SURVIVED, by dividing the span
            // between the oldest and newest packet the collapse condemned by the PTO
            // period the estimator implied at that moment. s7.6's duration is
            // (smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay) * threshold,
            // and every term but the threshold is a live reading.
            Compared(
                "persistent_congestion_threshold",
                PersistentCongestionThresholdOf(collapse),
                CitedPersistentCongestionThreshold.ToString(CultureInfo.InvariantCulture),
                $"{Section7} s7.6 kPersistentCongestionThreshold = 3"),

            // ---- knob 9 ---------------------------------------------------------------
            //
            // TWO ARMS AND A DIVISION. One PTO tells you nothing about a backoff; the
            // second arm divided by the first is the exponential's base, and it is what a
            // pcap of two consecutive probes measures directly.
            Compared(
                "pto_backoff_factor",
                Ratio(probe1?.ArmedPtoIn?.Ticks, probe2?.ArmedPtoIn?.Ticks),
                CitedPtoBackoffFactor.ToString("0.000", CultureInfo.InvariantCulture),
                $"{Section62} s6.2.1's backoff doubles; its CAP is an implementation choice "
                    + "the RFC does not state, and this recording did not run long enough to "
                    + "reach one"),

            // ---- knob 10 --------------------------------------------------------------
            Member(
                "probe_packets_per_pto",
                probe1 is { } p1 ? p1.ProbeDatagramsSent - opened.ProbeDatagramsSent : (int?)null,
                CitedProbePacketsPerPto,
                $"{Section62} s6.2.4 permits one or two, so this row matches on MEMBERSHIP "
                    + "of that set and not on equality with either"),

            // ---- knob 11 --------------------------------------------------------------
            //
            // READ OFF THE PROBE DATAGRAM ITSELF: whether it repaired anything, and how
            // big it was. s6.2.4 leaves the contents open, so the three shapes it names
            // are the cited set. The padding test uses RFC 9000 s8.1's 1200-byte floor
            // and NOT TlsQuicConnectionSpec.PaddingTarget, which would be the spec.
            Member(
                "probe_contents",
                ProbeShapeOf(opened, probe1),
                ["PING-only", "PING-with-padding", "retransmitted-data"],
                $"{Section62} s6.2.4 leaves the contents open; the three shapes it names are "
                    + "the cited set. TASK A3-13's LIVE RUN FOUND THIS IS NOT A FREE CHOICE "
                    + "IN PRACTICE: fp.impersonate.pro answered a PING-only probe with "
                    + "CONNECTION_CLOSE 0x0a PROTOCOL_VIOLATION 4/4 while tls3.peet.ws ACKed "
                    + "the identical probe and completed 4/4, and commit 2195e93 moved the "
                    + "shipped default to RetransmittedData because of it. THE RUN BEHIND "
                    + "THIS TABLE SETS THE KNOB EXPLICITLY AND DID SO BEFORE THAT COMMIT, "
                    + "so this row measures the probe rather than the default of the day"),

            // ---- knob 12 --------------------------------------------------------------
            //
            // THE ROW WHOSE OBSERVED CELL IS THE POINT. A4 decided "immediate at every
            // level" and A3 reopened it; the knob exists, and what this recording shows is
            // how the connection actually behaved, which is not the same claim.
            new Row(
                "ack_policy",
                AckPolicyObservedIn(trace),
                $"Chromium's is unmeasured - FINGERPRINT-KNOBS marker 10, {A314}",
                TlsQuicHttp3FingerprintReadout.NotYetKnown),

            // ---- knob 13 --------------------------------------------------------------
            new Row(
                "ack_range_limit",
                trace.AckRangesInLargestEmittedAck.ToString(CultureInfo.InvariantCulture)
                    + " ranges in the largest ACK frame this recording built",
                "the Brave capture says nothing about ACK ranges and no published vector "
                    + "does either - FINGERPRINT-KNOBS' PLACEHOLDER table, and "
                    + "TlsQuicFingerprintReadout.cs's deviation note 4",
                TlsQuicHttp3FingerprintReadout.NotYetKnown),

            // ---- knob 14 --------------------------------------------------------------
            //
            // MEASURED AS A BURST AND NOT AS A SETTING, which is what makes this row
            // survive A3-11 landing underneath it: if a pacer starts restricting the send
            // path the largest burst falls, and if none does the row says so.
            new Row(
                "pacing_burst_datagrams",
                PacingBurstOf(LastOf(trace), trace),
                $"{Section7} s7.7 is a SHOULD, not a MUST; that Chromium paces at all is a "
                    + $"widely repeated claim this project has not measured - "
                    + $"FINGERPRINT-KNOBS markers 7, 11, {A314}",
                TlsQuicHttp3FingerprintReadout.NotYetKnown),

            // ---- knob 15, WHICH ARRIVED UNDER THIS TASK -------------------------------
            //
            // ADDED BY TASK A3-11 WHILE THIS READOUT WAS BEING BUILT, and rendered rather
            // than folded into knob 14 for A3-11's own reason: the burst decides how many
            // datagrams leave together and the scale decides how fast the next allowance
            // arrives, and a pcap measures the second as a GAP between departures. Neither
            // congestion_window nor smoothed_rtt is settable, so a caller who can set only
            // the burst cannot change the spacing at all.
            //
            // WHAT THIS RECORDING CAN AND CANNOT SHOW, SAID PLAINLY. The pacer gates the
            // 1-RTT frame queue, and this script never completes a handshake - it is built
            // around a DROPPED ClientHello, which is what makes the probe rows real. So the
            // gap is rendered where one was scheduled and the absence is named where none
            // was, rather than a number being produced for an event that did not happen.
            new Row(
                "pacing_interval_scale",
                PacingIntervalOf(LastOf(trace)),
                $"{Section7} s7.7's rate = N * congestion_window / smoothed_rtt, whose only "
                    + "stated bound is \"small, but at least 1 (for example, 1.25)\" - "
                    + $"FINGERPRINT-KNOBS knob 15, {A314}",
                TlsQuicHttp3FingerprintReadout.NotYetKnown),

            // ---- observation 1, which is NOT a knob -----------------------------------
            //
            // THE CONTROLLER IN FORCE, AS A NAMED STRING. Knob 4 above is the FACTORY
            // SEAM - what a caller may supply. This row is what actually ran and what it
            // actually did, and the two are separable: a seam that is never consulted
            // leaves knob 4 reading one thing and this row reading another.
            new Row(
                "congestion_controller_in_force",
                $"{LastOf(trace).ControllerName}, which held a window of "
                    + $"{LastOf(trace).CongestionWindowBytes} bytes against "
                    + $"{LastOf(trace).BytesInFlight} bytes in flight after "
                    + $"{Plural(LastOf(trace).PacketsDeclaredLost, "declared loss", "declared losses")} and "
                    + $"{Plural(LastOf(trace).PersistentCongestionEvents, "persistent-congestion event")}",
                $"no fingerprint endpoint this project can reach sees a send-rate curve - "
                    + $"{A314}",
                TlsQuicHttp3FingerprintReadout.NotYetKnown),

            // ---- observation 2, which is NOT a knob -----------------------------------
            //
            // AND THIS ROW EXISTS BECAUSE THE TWO CAN AGREE BY ACCIDENT. Knob 12 renders
            // the behaviour the scheduler showed; this row renders whether anything in
            // src/ consults the knob at all, measured by whether a recording that CHANGED
            // the knob changed the behaviour. Where nothing reads it, "Immediate" and
            // "observed immediate" agree for no reason, and a readout that printed only
            // the first would be reporting a wiring it does not have.
            new Row(
                "ack_policy_in_force",
                trace.AckPolicyIsWired
                    ? "the scheduler's behaviour MOVED when the knob moved, so the knob is "
                        + "wired"
                    : "the scheduler's behaviour did NOT move when the knob moved - nothing "
                        + "on the send path consults it, so knob 12 above and this row agree "
                        + "by accident and not by wiring",
                $"the wiring is this project's to fix; the VALUE is {A314}'s",
                TlsQuicHttp3FingerprintReadout.NotYetKnown),
        ];
    }

    // ---- the four cell builders ------------------------------------------------------

    // A row whose verdict is a live comparison against a cited figure. NotWitnessed
    // never equals a cited value, so an unexercised row scores MISMATCH - deliberately,
    // and see this file's header for why silence is the worse failure.
    private static Row Compared(string knob, string observed, string cited, string source) =>
        new(knob, observed, source + $" -> {cited}",
            observed == cited
                ? TlsQuicHttp3FingerprintReadout.Match
                : TlsQuicHttp3FingerprintReadout.Mismatch);

    private static Row Member(string knob, int? observed, int[] cited, string source) =>
        Member(
            knob,
            observed?.ToString(CultureInfo.InvariantCulture) ?? NotWitnessed,
            [.. cited.Select(static v => v.ToString(CultureInfo.InvariantCulture))],
            source);

    private static Row Member(string knob, string observed, string[] cited, string source) =>
        new(knob, observed, source + $" -> one of [{string.Join(", ", cited)}]",
            cited.Contains(observed)
                ? TlsQuicHttp3FingerprintReadout.Match
                : TlsQuicHttp3FingerprintReadout.Mismatch);

    private static string Optional(TimeSpan? span) =>
        span is { } value ? Milliseconds(value) : "none";

    private static string Plural(int count, string singular, string? plural = null) =>
        count.ToString(CultureInfo.InvariantCulture) + " "
            + (count == 1 ? singular : plural ?? singular + "s");

    private static string Milliseconds(TimeSpan span) =>
        span.TotalMilliseconds.ToString("0.0", CultureInfo.InvariantCulture) + " ms";

    // after / before, to three places. Either side missing, or a zero denominator, is
    // NotWitnessed rather than a fabricated 0.000.
    private static string Ratio(long? before, long? after) =>
        before is > 0 && after is { } a
            ? ((double)a / before.Value).ToString("0.000", CultureInfo.InvariantCulture)
            : NotWitnessed;

    // The packet-number distance from largest_acked to the NEAREST packet this pass
    // condemned, which IS kPacketThreshold: s6.1.1 declares a packet lost once
    // largest_acked - pn is at least the threshold, so the nearest one condemned sits
    // exactly at it and every other one sits further out.
    //
    // THIS READ Min AND WAS WRONG, and mutation A3-12-4 is how it was found rather than
    // reasoned out. The first version of the run condemned exactly ONE packet, so Min and
    // Max coincided, the row rendered 3 either way, and inverting it changed nothing -
    // the mutant SURVIVED. The run now condemns two at different distances, which makes
    // the two readings disagree and makes this the only correct one.
    private static string Distance(TlsQuicRecoverySample? sample)
    {
        if (sample is not { } s
            || s.LargestAcked is not { } largest
            || s.JustDeclaredLost.Count == 0)
        {
            return NotWitnessed;
        }

        var nearest = s.JustDeclaredLost.Max(p => p.PacketNumber);
        return (largest - nearest).ToString(CultureInfo.InvariantCulture);
    }

    private static string TimeThresholdOf(TlsQuicRecoverySample? sample)
    {
        if (sample is not { } s || s.ArmedLossDelay is not { } delay)
        {
            return NotWitnessed;
        }

        var rtt = s.SmoothedRtt > s.LatestRtt ? s.SmoothedRtt : s.LatestRtt;
        return Ratio(rtt.Ticks, delay.Ticks);
    }

    // s7.6's duration, inverted. Every term but the threshold is a live reading, so
    // dividing the blackout this recording actually survived by the period the estimator
    // implied recovers the threshold - and recovers a DIFFERENT number if the code moved.
    private static string PersistentCongestionThresholdOf(TlsQuicRecoverySample? sample)
    {
        if (sample is not { } s || s.JustDeclaredLost.Count < 2)
        {
            return NotWitnessed;
        }

        var oldest = s.JustDeclaredLost.Min(p => p.SentAt);
        var newest = s.JustDeclaredLost.Max(p => p.SentAt);
        var variation = 4 * s.RttVariation;
        var period = s.SmoothedRtt
            + (variation > TlsQuicConnection.KGranularity
                ? variation
                : TlsQuicConnection.KGranularity)
            + TlsQuicAckTracker.DefaultMaxAckDelay;
        if (period <= TimeSpan.Zero)
        {
            return NotWitnessed;
        }

        // The blackout is driven one tick PAST the duration, so the quotient sits a hair
        // above the threshold; rounding to a whole multiple is what makes the row a
        // threshold rather than a stopwatch reading. A build with a different threshold
        // rounds to a different whole number.
        return Math.Round((newest - oldest) / period, MidpointRounding.AwayFromZero)
            .ToString(CultureInfo.InvariantCulture);
    }

    private static string ProbeShapeOf(
        TlsQuicRecoverySample opened, TlsQuicRecoverySample? probe)
    {
        if (probe is not { } p || p.ProbeDatagramsSent == opened.ProbeDatagramsSent)
        {
            return NotWitnessed;
        }

        if (p.FramesRetransmitted > opened.FramesRetransmitted)
        {
            return "retransmitted-data";
        }

        return p.LastProbeDatagramBytes >= Section81PaddingFloor
            ? "PING-with-padding"
            : "PING-only";
    }

    // THE PACER'S OWN CAPACITY, plus what this recording saw it do with it. A burst of
    // zero is s7.7's off switch and is rendered as the absence it is.
    private static string PacingBurstOf(
        TlsQuicRecoverySample last, TlsQuicRecoveryTrace trace) =>
        last.PacerIsEnabled
            ? $"{Plural(last.PacerBurstDatagrams, "datagram")} of burst capacity, which "
                + $"deferred {Plural(last.SendsDeferredByPacer, "pass", "passes")} in this "
                + $"recording; at most {Plural(trace.LargestDatagramBurst, "datagram")} was "
                + "offered to the transport without the clock advancing"
            : "no pacer - the send path was never held";

    private static string PacingIntervalOf(TlsQuicRecoverySample last) =>
        last.PacingReleaseIn is { } release
            ? $"a release scheduled {Milliseconds(release)} out, at a congestion window of "
                + $"{last.CongestionWindowBytes} bytes and a smoothed RTT of "
                + $"{Milliseconds(last.SmoothedRtt)}"
            : $"{NotWitnessed} - the pacer gates the 1-RTT queue and this run never "
                + "completed a handshake, so no release was scheduled; the terms it would "
                + $"have used are a window of {last.CongestionWindowBytes} bytes and a "
                + $"smoothed RTT of {Milliseconds(last.SmoothedRtt)}";

    private static string AckPolicyObservedIn(TlsQuicRecoveryTrace trace) =>
        trace.LargestAckDelayObserved is { } delay
            ? delay <= TimeSpan.Zero
                ? "immediate - every ACK this recording built was available in the same "
                    + "instant the packet eliciting it arrived"
                : $"delayed by up to {Milliseconds(delay)}"
            : NotWitnessed;

    private static TlsQuicRecoverySample LastOf(TlsQuicRecoveryTrace trace) =>
        trace.Samples[^1];

    // ---- the rendered document ---------------------------------------------------------

    private static string Render(List<Row> rows, TlsQuicRecoveryTrace trace)
    {
        var text = new StringBuilder();
        text.Append(Preamble);

        text.Append("| # | knob | observed on the wire or in the run | source | verdict |\n")
            .Append("| --- | --- | --- | --- | --- |\n");
        for (var i = 0; i < rows.Count; i++)
        {
            text.Append("| ").Append((i + 1).ToString(CultureInfo.InvariantCulture))
                .Append(" | ").Append(rows[i].Knob)
                .Append(" | ").Append(rows[i].Observed)
                .Append(" | ").Append(rows[i].Source)
                .Append(" | ").Append(rows[i].Verdict)
                .Append(" |\n");
        }

        AppendCounts(text, rows);
        AppendRun(text, trace);
        text.Append(Notes);
        return text.ToString();
    }

    // B's Finding 10: growing the table must keep the arithmetic line reconciling, and
    // the three counts are COUNTED off the rendered rows rather than written beside them.
    // TlsQuicConnectionTests.TheRecoveryVerdictCountsAreDerivedFromTheRowsAndNotAssertedBesideThem
    // is what stops them being re-typed as constants.
    private static void AppendCounts(StringBuilder text, List<Row> rows)
    {
        var match = rows.Count(r => r.Verdict == TlsQuicHttp3FingerprintReadout.Match);
        var mismatch = rows.Count(r => r.Verdict == TlsQuicHttp3FingerprintReadout.Mismatch);
        var unknown = rows.Count(r => r.Verdict == TlsQuicHttp3FingerprintReadout.NotYetKnown);
        text.Append("\n## Verdict counts, derived from the rows above\n\n")
            .Append("    rows                            ")
            .Append(rows.Count.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("    match                           ")
            .Append(match.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("    MISMATCH                        ")
            .Append(mismatch.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("    not-yet-known-from-the-capture  ")
            .Append(unknown.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("    ").Append(match.ToString(CultureInfo.InvariantCulture))
            .Append(" + ").Append(mismatch.ToString(CultureInfo.InvariantCulture))
            .Append(" + ").Append(unknown.ToString(CultureInfo.InvariantCulture))
            .Append(" = ").Append(rows.Count.ToString(CultureInfo.InvariantCulture))
            .Append('\n');
    }

    // THE RUN ITSELF, so a reader can tell an unexercised row from an exercised one
    // without taking the table's word for it.
    private static void AppendRun(StringBuilder text, TlsQuicRecoveryTrace trace)
    {
        text.Append("\n## The run the rows above were read off (measured)\n\n");
        foreach (var s in trace.Samples)
        {
            text.Append("  ").Append(s.Label.PadRight(24))
                .Append(" cwnd=").Append(s.CongestionWindowBytes.ToString(CultureInfo.InvariantCulture))
                .Append(" in_flight=").Append(s.BytesInFlight.ToString(CultureInfo.InvariantCulture))
                .Append(" lost=").Append(s.PacketsDeclaredLost.ToString(CultureInfo.InvariantCulture))
                .Append(" pc=").Append(s.PersistentCongestionEvents.ToString(CultureInfo.InvariantCulture))
                .Append(" pto=").Append(s.PtoCount.ToString(CultureInfo.InvariantCulture))
                .Append(" probes=").Append(s.ProbeDatagramsSent.ToString(CultureInfo.InvariantCulture))
                .Append(" repairs=").Append(s.FramesRetransmitted.ToString(CultureInfo.InvariantCulture))
                // A.8 ARMS EITHER A LOSS TIMER OR A PTO AND NEVER BOTH, so the two are
                // rendered as separate columns rather than as one "armed" number. A
                // sample that showed both would be a build that had conflated them, and
                // this is where that shows - mutation A3-12-11 survived until these two
                // columns existed, because no ROW reads the PTO field at a sample where a
                // loss timer is in force.
                .Append(" pto_in=").Append(Optional(s.ArmedPtoIn))
                .Append(" loss_delay=").Append(Optional(s.ArmedLossDelay))
                .Append('\n');
        }
    }

    private const string Preamble =
        "# QUIC recovery and congestion readout - SNAPSHOT\n"
        + "\n"
        + "SNAPSHOT. Every figure below was produced by TlsQuicRecoveryReadout from a live\n"
        + "connection driven through induced loss, two probe timeouts and a blackout long\n"
        + "enough to establish RFC 9002 s7.6's persistent congestion. NONE of it has an\n"
        + "external source in the sense the Brave capture is one. Per A2's standing rule, a\n"
        + "checked-in number with no external source is a snapshot and is labelled one.\n"
        + "\n"
        + "THE VERDICT COLUMN SCORES AGAINST RFC 9002 AND NEVER AGAINST THE CAPTURE. No\n"
        + "endpoint this project can reach observes any of these knobs: the perk string's\n"
        + "four segments are h3 SETTINGS, pseudo-header order, transport parameters in wire\n"
        + "order and CID lengths, and not one of them is a timing field. So a `match` here\n"
        + "says \"this build does what RFC 9002 says\" and says nothing whatever about\n"
        + "Chromium. The third column is the list of what task A3-14 must go and capture,\n"
        + "and it is the most valuable thing on this page.\n"
        + "\n"
        + "EVERY CELL IS READ OFF LIVE RECOVERY STATE OR OFF AN EMITTED FRAME. Describe's\n"
        + "signature does not admit a spec of any kind, so no row here can be a restatement\n"
        + "of what a caller typed in.\n"
        + "\n";

    private const string Notes =
        "\n## Notes\n"
        + "\n"
        + "A MISMATCH HERE IS ABOUT THIS BUILD AND NOT ABOUT CHROMIUM. The rows score what\n"
        + "this connection did against what the RFC 9002 extracts in\n"
        + "docs/superpowers/specs/reference-captures/ state. A row reading MISMATCH means\n"
        + "this build deviates from the RFC - which a caller reproducing a non-conforming\n"
        + "client may want deliberately - and a row reading match means nothing more than\n"
        + "conformance.\n"
        + "\n"
        + "AN UNEXERCISED ROW SCORES MISMATCH, DELIBERATELY. `not-witnessed-by-this-recording`\n"
        + "never equals a cited figure, so a change that stops driving one of these episodes\n"
        + "turns its row red. The alternative - a fourth verdict value for \"not exercised\" -\n"
        + "would let a row go quiet, and a quiet row in a fingerprint readout is the failure\n"
        + "mode this whole subsystem exists to avoid.\n"
        + "\n"
        + "THE THIRD COLUMN IS TIED TO docs/FINGERPRINT-KNOBS.md AND NOT CHOSEN HERE. A row\n"
        + "is third-column exactly when that file marks its knob UNVERIFIED or PLACEHOLDER.\n"
        + "Seven rows qualify: initial_rtt (markers 5, 13),\n"
        + "initial_congestion_window_bytes (3, 6, 8), congestion_controller (2, 9),\n"
        + "ack_policy (10), ack_range_limit (the PLACEHOLDER table),\n"
        + "pacing_burst_datagrams (7, 11) and pacing_interval_scale (knob 15, added by\n"
        + "task A3-11 while this readout was being built). The plan's sentence names five\n"
        + "of those seven; the two it omits are initial_rtt's invented range and\n"
        + "AckRangeLimit, and both are marked in the tree.\n"
        + "\n"
        + "FINGERPRINT-KNOBS' OWN MARKER COUNT WAS STALE BY THREE FOR THREE COMMITS, AND\n"
        + "IS NOT ANY MORE. That file stated 13 markers and tabulated thirteen. It returned\n"
        + "13 at 2769d10 and ebdcc89 and 16 at c9a86cb: task A3-11 added markers for\n"
        + "PacingIntervalScale in TlsQuicRecoverySpec.cs, for the send gate in\n"
        + "TlsQuicApplicationSendPath.cs, and a second in TlsQuicRecoverySpec.cs, without\n"
        + "moving the count. The table now reads 20 hits of which 16 mark a value - the\n"
        + "other four are this file talking ABOUT the marker word - and carries rows 14-16\n"
        + "for the three it had been missing.\n"
        + "\n"
        + "THE EPISODE IS LEFT RENDERED HERE RATHER THAN DELETED, because it is the whole\n"
        + "argument for the discriminator above. For three commits this readout and that\n"
        + "table disagreed about the same set, and the readout was right BECAUSE it counts\n"
        + "markers in the source rather than rows in a document. A rule that only ever\n"
        + "agrees with the document it is checked against has never been tested.\n"
        + "\n"
        + "THE LAST TWO ROWS ARE OBSERVATIONS AND NOT KNOBS, which is why the table is\n"
        + "longer than the knob list by exactly two. They exist because a knob's SETTING and\n"
        + "the behaviour in force can agree BY ACCIDENT, and AckPolicy is the worked example:\n"
        + "for as long as nothing read TlsQuicRecoverySpec.AckPolicy, `Immediate` and an\n"
        + "observed immediate ACK agreed for no reason at all, and only the second-to-last\n"
        + "pair of rows could say so.\n"
        + "\n"
        + "TASK A3-13 WIRED IT, AND THE ROWS ARE WHAT SHOWED THE DIFFERENCE. The reader is\n"
        + "TlsQuicAckTracker.IsWithheldAt; the behaviour-in-force row MOVED when the knob\n"
        + "moved, which is the whole claim, and it moved without a line of the measurement\n"
        + "changing. A row that renders the same string whether or not the knob is read\n"
        + "would have said nothing on either side of that commit.\n";
}

/// <summary>One reading of a connection's live loss-recovery and congestion state, taken
/// at a named moment during a run.</summary>
/// <remarks>
/// <para>EVERY FIELD IS A COUNTER OR AN ESTIMATE THE CONNECTION ITSELF MAINTAINS, and none
/// is a setting. That is the point: <see cref="TlsQuicRecoveryReadout.Describe"/> renders
/// from a sequence of these and has no other input, so there is no path from a rendered
/// row back to <see cref="TlsQuicRecoverySpec"/>.</para>
/// <para>THE SAMPLE IS TAKEN RATHER THAN CONSTRUCTED. <see cref="TlsQuicRecoveryTrace.Take"/>
/// is the only way to build one from a connection; the primary constructor exists so the
/// record is a value, not so a test can fabricate a reading.</para>
/// </remarks>
internal readonly record struct TlsQuicRecoverySample(
    string Label,
    string ControllerName,
    long CongestionWindowBytes,
    long BytesInFlight,
    bool HasRttSample,
    TimeSpan SmoothedRtt,
    TimeSpan LatestRtt,
    TimeSpan RttVariation,
    int PacketsDeclaredLost,
    int PersistentCongestionEvents,
    int FramesRetransmitted,
    int PtoCount,
    int ProbeDatagramsSent,
    int LastProbeDatagramBytes,
    TimeSpan? ArmedPtoIn,
    TimeSpan? ArmedLossDelay,
    ulong? LargestAcked,
    IReadOnlyList<TlsQuicSentPacket> JustDeclaredLost,
    bool PacerIsEnabled,
    int PacerBurstDatagrams,
    int SendsDeferredByPacer,
    TimeSpan? PacingReleaseIn);

/// <summary>The observations one run produced: a sequence of
/// <see cref="TlsQuicRecoverySample"/>s plus the few figures that are read off emitted
/// frames rather than off a counter.</summary>
/// <remarks>
/// <para>THIS TYPE IS THE READOUT'S ONLY INPUT and it deliberately cannot carry a spec.
/// See TlsQuicRecoveryReadout.cs's header for why that is structural rather than a
/// convention.</para>
/// <para>THE LABELS ARE CONSTANTS AND NOT FREE STRINGS. A row that looks its sample up by
/// a mistyped label renders <c>not-witnessed-by-this-recording</c> and scores MISMATCH,
/// which is loud; naming them here makes the typo a compile error instead.</para>
/// </remarks>
internal sealed class TlsQuicRecoveryTrace
{
    internal const string Opened = "opened";

    internal const string FirstProbe = "first-probe";

    internal const string SecondProbe = "second-probe";

    internal const string BeforeLoss = "before-loss";

    internal const string PacketThresholdLoss = "packet-threshold-loss";

    internal const string TimeThresholdLoss = "time-threshold-loss";

    internal const string PersistentCongestion = "persistent-congestion";

    private readonly List<TlsQuicRecoverySample> _samples = [];

    internal IReadOnlyList<TlsQuicRecoverySample> Samples => _samples;

    /// <summary>The largest datagram this run actually put on the wire, which is what a
    /// reader of a capture would use for RFC 9002's <c>max_datagram_size</c>.</summary>
    /// <remarks>MEASURED AND NOT READ OFF <see cref="TlsQuicConnectionSpec.PaddingTarget"/>,
    /// which is the same number by construction and would be the spec.</remarks>
    internal int MaxDatagramSizeBytes { get; set; }

    /// <summary>How many ACK ranges the largest ACK frame this run built carried.</summary>
    internal int AckRangesInLargestEmittedAck { get; set; }

    /// <summary>The most datagrams offered to the transport without the clock moving - the
    /// burst a pacer would be the thing to cap.</summary>
    internal int LargestDatagramBurst { get; set; }

    /// <summary>The largest gap this run showed between a packet arriving and the ACK for
    /// it leaving. Zero is an immediate policy; null means no ACK was built.</summary>
    internal TimeSpan? LargestAckDelayObserved { get; set; }

    /// <summary>Whether moving <c>AckPolicy</c> moved the behaviour, established by running
    /// the same script twice under the two policies and comparing.</summary>
    /// <remarks>A BOOLEAN ABOUT THE WIRING AND NOT ABOUT THE VALUE. See the readout's last
    /// row for why the distinction is the row's whole reason to exist.</remarks>
    internal bool AckPolicyIsWired { get; set; }

    internal TlsQuicRecoverySample? Find(string label)
    {
        foreach (var sample in _samples)
        {
            if (sample.Label == label)
            {
                return sample;
            }
        }

        return null;
    }

    /// <summary>Reads the connection's live recovery state at this instant and appends it
    /// under <paramref name="label"/>.</summary>
    internal TlsQuicRecoveryTrace Take(
        string label, TlsQuicConnection connection, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(connection);

        // THE ARMED TIMER IS SPLIT INTO ITS TWO KINDS, because A.8 arms EITHER a loss timer
        // or a PTO and the two rows that read it want different ones. GetLossTimeAndSpace
        // returning non-null is what says which is in force, and the loss delay is measured
        // from the acknowledgement it hangs off rather than from now - s6.1.2's threshold is
        // a delay after largest_acked's send instant, not after the clock.
        var lossTime = connection.GetLossTimeAndSpace();
        TimeSpan? armedLossDelay = lossTime is { } l
                && connection.SentPackets(l.Space) is { Count: > 0 } unacked
            ? l.At - unacked.Min(static p => p.SentAt)
            : null;
        TimeSpan? armedPtoIn = lossTime is null && connection.LossDetectionTimer is { } pto
            ? pto - now
            : null;

        _samples.Add(new TlsQuicRecoverySample(
            label,
            connection.CongestionControl.Name,
            connection.CongestionControl.CongestionWindowBytes,
            connection.CongestionControl.BytesInFlight,
            connection.Acks.FirstRttSampleAt is not null,
            connection.Acks.SmoothedRtt,
            connection.Acks.LatestRtt,
            connection.Acks.RttVariation,
            connection.PacketsDeclaredLost,
            connection.PersistentCongestionEvents,
            connection.FramesRetransmitted,
            connection.PtoCount,
            connection.ProbeDatagramsSent,
            connection.LastProbeDatagramBytes,
            armedPtoIn,
            armedLossDelay,
            connection.Acks.LargestAcked(
                connection.LastDetectedLost.Count > 0
                    ? connection.LastDetectedLost[0].Level
                    : lossTime?.Space ?? TlsQuicEncryptionLevel.Handshake),
            [.. connection.LastDetectedLost],
            connection.Pacer.IsEnabled,
            connection.Pacer.BurstDatagrams,
            connection.SendsDeferredByPacer,
            connection.PacingReleaseAt is { } release ? release - now : null));
        return this;
    }
}
