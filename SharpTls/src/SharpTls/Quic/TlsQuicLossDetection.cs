namespace SharpTls.Quic;

// ============================================================================
// TASK A3-6: RFC 9002 s6.1's ACKNOWLEDGMENT-BASED LOSS DETECTION.
// ============================================================================
//
// A PARTIAL OF TlsQuicConnection RATHER THAN A TYPE OF ITS OWN, and the reason is not style.
// A.10's DetectAndRemoveLostPackets "operates on the sent_packets for that packet number
// space" and REMOVES from it, and this brief's own instruction is to "coordinate with A3-3's
// Forget path rather than writing a second removal". Forget is private to TlsQuicConnection
// and is, in its own words, "the single exit from retention, so that 'leaves the list' and
// 'leaves bytes_in_flight' cannot come apart". A separate class could not call it, so it would
// have had to be handed the List and the byte counter - which is the second removal the brief
// forbids. TlsQuicConnection.cs's own closing note names this shape: "The partial-class
// precedent TlsQuicApplicationSendPath.cs set is the obvious shape for it."
//
// ============================================================================
// WHAT IS NOT WIRED, AND WHY IT IS NAMED RATHER THAN QUIETLY ABSENT.
// ============================================================================
//
// A.10 opens: "DetectAndRemoveLostPackets is called every time an ACK is received or the time
// threshold loss detection timer expires." NEITHER CALL SITE IS HERE, and both live in
// TlsQuicConnection.cs, which A3-6's brief forbids this task to edit:
//
//   * A.7's OnAckReceived - TlsQuicConnection.OnAckReceived - would call this after its
//     removal loop and before its closing SetLossDetectionTimer.
//   * A.9's OnLossDetectionTimeout - TlsQuicConnection.OnLossDetectionTimeout - would call it
//     as its FIRST rung, which A3-5's comment there already names as "A3-6's".
//   * A.8's rung 1 - SetLossDetectionTimer - would open with GetLossTimeAndSpace and arm the
//     timer from it, which A3-5's comment there also already names as "A3-6's ... A3-6 adds
//     the array, the rung and its witness together".
//
// THE ARRAY, THE ALGORITHM AND THE RUNG-1 HELPER ARE ALL HERE AND ALL WITNESSED. What is
// missing is three call lines in a file this task may not open, and that is reported to the
// caller rather than worked around: a second copy of A.8's ladder in this file, or an
// OnAckReceived wrapper that shadowed the real one, would be a fourth place to keep in step
// with the first three and would read as conformance while changing nothing on the live path.
//
// ============================================================================
// A3-7 WROTE THE THREE LINES. THIS SECTION IS AMENDED RATHER THAN DELETED.
// ============================================================================
//
// All three are in TlsQuicConnection.cs, exactly where the paragraphs above predicted:
// OnAckReceived calls DetectAndRemoveLostPackets behind A.7's newly-acked guard,
// SetLossDetectionTimer opens with GetLossTimeAndSpace as A.8's rung 1, and
// OnLossDetectionTimeout opens with the same helper as A.9's rung 1 - which RETURNS before
// pto_count++, because s6.2 says "A PTO timer expiration event does not indicate packet loss".
//
// LOSS IS NOW DETECTED ON A LIVE PATH, AND THE WITNESS IS THE ONE THIS HEADER ASKED FOR.
// TlsQuicConnectionTests.ADroppedDatagramsPacketIsDeclaredLostByARealAcknowledgement no longer
// calls detection at all: A3-1's decorator really drops a datagram, a real handshake runs
// through the gap, the peer writes a real acknowledgement, and the packet is declared lost
// inside PumpOnceAsync. Mutation row 171 - the call line deleted - is killed by fourteen tests.
//
// THE DIRECT HALF STILL DRIVES THE internal ENTRY POINTS, and still carries A3-3's caveat -
// "WHAT IT CANNOT SEE is whether the send path calls OnPacketSent at all" - but its
// observation point moved: since A.7 runs A.10 itself, a test that acknowledged and then called
// DetectAndRemoveLostPackets would be running a SECOND pass over a set the first had emptied.
// LastDetectedLost and PacketsDeclaredLost below are what those tests read instead, and that
// makes every one of them a claim about the production path rather than about its own call.
//
// ============================================================================
// s6 PROSE AGAINST A.10, READ AGAINST EACH OTHER RATHER THAN EITHER ALONE.
// ============================================================================
//
// A3-4 and A3-5 each found a place where RFC 9002's prose and its appendix disagree, so the
// two were compared clause by clause here. THEY AGREE ON THE ARITHMETIC AND DISAGREE ON ONE
// CONDITION.
//
//   AGREE - THE TIME THRESHOLD'S SHAPE. s6.1.2: "max(kTimeThreshold * max(smoothed_rtt,
//   latest_rtt), kGranularity)". A.10: "loss_delay = kTimeThreshold * max(latest_rtt,
//   smoothed_rtt)" then "loss_delay = max(loss_delay, kGranularity)". Same expression; the
//   floor is on the PRODUCT in both, not on the RTT term. That distinction is load-bearing -
//   flooring the RTT term instead would leave the delay at 9/8 of a millisecond rather than at
//   one, and TlsQuicConnectionTests.TheTimeThresholdIsFlooredAtTheTimerGranularityAndNotAt
//   NineEighthsOfIt asserts BOTH candidate numbers rather than merely that they differ.
//
//   AGREE - THE PACKET THRESHOLD'S BOUNDARY. s6.1.1 states the threshold as a count and A.10
//   as "largest_acked_packet[pn_space] >= unacked.packet_number + kPacketThreshold". A gap of
//   exactly kPacketThreshold is lost, a gap of one less is not.
//
//   DISAGREE - WHETHER A PACKET THAT IS NOT IN FLIGHT CAN BE DECLARED LOST. s6.1's conditions
//   are a conjunction and the FIRST one reads "The packet is unacknowledged, IN FLIGHT, and
//   was sent prior to an acknowledged packet". A.10's loop has no in-flight test at all: it
//   walks every retained packet and removes any that meets the thresholds. A.4 defines
//   bytes_in_flight to EXCLUDE ACK-only packets, so the two really do differ on a real packet
//   this connection really sends - TlsQuicPacketBuilderTests.AckOnlyPacketsAreNeitherAck
//   ElicitingNorInFlight pins that such packets exist.
//
//   A.10 IS FOLLOWED, DELIBERATELY, AND THE CHOICE IS PINNED. Reasons, in order of weight:
//   (1) A.10 is the removal half of retention - a packet left in sent_packets for ever because
//   it was never in flight is a leak of the bounded list A3-3 built, and A3-3's cap would then
//   silently evict it anyway with no loss ever declared. (2) s6.1's "in flight" qualifies WHEN
//   A PACKET IS DECLARED LOST, and what s6's opening paragraph says loss detection is FOR is
//   "the QUIC transport needs to recover from that loss, such as by retransmitting the data,
//   sending an updated frame, or discarding the frame"; an ACK-only packet's information is
//   re-derived on the next ACK, so declaring it lost costs nothing and retaining it for ever
//   costs a slot. (3) The one consumer of the difference is the congestion controller, and
//   RFC 9002 B.8's OnPacketsLost already re-tests in_flight itself before touching the window,
//   so the narrower reading is available downstream without being imposed here.
//   TlsQuicConnectionTests.AnAckOnlyPacketIsDeclaredLostByAppendixATenAndDoesNotMoveBytesIn
//   Flight is the witness, and it asserts the count as one rather than as non-zero, so a
//   change to s6.1's reading fails it rather than passing quietly.
//
// ============================================================================
// THE C# HAZARDS THE PSEUDOCODE CANNOT SEE. THREE, AND ONLY TWO OF THEM REACHABLE.
// ============================================================================
//
//   1. `unacked.packet_number + kPacketThreshold` CAN WRAP, AND THE HONEST ACCOUNT OF IT IS
//      THAT THE WRAP IS UNREACHABLE HERE RATHER THAN THAT IT IS GUARDED. Packet numbers are
//      ulong and A3-3's own tests already retain ulong.MaxValue, so the sum overflows for a
//      packet number within kPacketThreshold of the top - and `largest_acked >= 2` then holds
//      against the wrapped value, declaring that packet lost. What makes it unreachable is
//      that largest_acked comes off an ACK frame, RFC 9000 s16 caps a variable-length integer
//      at 2^62-1, and a packet number that large is ALWAYS above largest_acked and therefore
//      already skipped by A.10's own `continue`. THE SUBTRACTION IS STILL USED -
//      `largestAcked - unacked.PacketNumber >= threshold` - because it cannot wrap at all once
//      that `continue` has run, and it costs nothing. NO TEST CLAIMS THE WRAP: none can be
//      written. What IS witnessed is the `continue` that makes it unreachable, by
//      TlsQuicConnectionTests.APacketNewerThanTheLargestAcknowledgedIsNotDeclaredLost - remove
//      that line and a retained ulong.MaxValue is declared lost by either form.
//
//   2. `kTimeThreshold * max(...)` THROWS. TlsQuicRecoverySpec.TimeThreshold accepts any
//      finite positive double, so a caller may set 1e300; TimeSpan's operator* throws
//      OverflowException on the product. A3-5's FromTicksSaturating already exists for exactly
//      this and is reused rather than reinvented.
//
//   3. `now() - loss_delay` THROWS. A saturated loss_delay is TimeSpan.MaxValue and
//      DateTimeOffset's operator- leaves the calendar. SubtractSaturating is AddSaturating's
//      mirror, and the saturated end is the RIGHT answer rather than merely a safe one: an
//      effectively infinite loss delay should declare nothing lost by time, which a
//      lost_send_time of DateTimeOffset.MinValue produces.
//
// NOTHING HERE THROWS FOR ANY INPUT, and the inputs are the peer's: largest_acked comes off an
// ACK frame the peer wrote, and the RTT terms are computed from instants the peer's timing
// chose. TlsQuicConnectionTests.LossDetectionSurvivesEverySaturatingInput is the
// sweep, over every packet number space and over both ends of the calendar.
// ============================================================================
// ---- A3-6 ROUND: RFC 9002 s6.1 LOSS DETECTION. 24 rows, numbered 201-224 ----
// ============================================================================
//
// Run in a private git worktree detached at 1a17be7 - pristine HEAD for this task - carrying
// ONLY this file and its tests, so no other agent's uncommitted work in the shared tree could
// account for a verdict. A second sweep was running in a SEPARATE worktree at the same time and
// is the reason the early rows took minutes rather than seconds; it touched no file of this
// one's. Gate `dotnet test --filter "FullyQualifiedName~Quic"`, measured rather than inherited:
// 2236 passed / 0 failed / 5 skipped = 2241 total at pristine HEAD, and 2258 / 0 / 5 = 2263
// after. 2241 + 22 = 2263, and 22 is exactly this task's own case count - 13 [Fact] methods plus
// three [Theory] methods contributing 2 + 3 + 4 = 9, and 13 + 9 = 22. NO EXISTING CASE MOVED.
//
// VERDICTS ARE ASSIGNED STRUCTURALLY. The harness branches on the BUILD's exit code before any
// test process starts, so a compile failure can only ever produce KILLED-BY-COMPILER and can
// never be published as a kill against a named test. `if (false)` is never written - CS0162 is
// an error in this tree - and `COND && false` is used where a branch has to be disabled.
//
// EVERY SCORED RUN REPORTED 2263 TOTAL, against a floor of 2250 the harness checks before it
// scores anything; a run under the floor aborts the sweep rather than publishing a figure
// counted against a different suite. Every row also asserts its anchor occurs EXACTLY once and
// that the rewritten file differs from the original, so a mutation that matched nothing cannot
// reach a verdict at all.
//
// THE HARNESS WAS CALIBRATED IN BOTH DIRECTIONS AND THE FIRST CALIBRATION FAILED, WHICH IS THE
// MOST USEFUL THING IT DID. Row 900 - pristine source, no mutation - returns SURVIVED with 0
// failed of 2263. Row 901 - a known-bad edit - must return KILLED. The FIRST 901 inserted
// `if (true) { return _lostPackets; }` and came back KILLED-BY-COMPILER, because everything
// after it is unreachable and CS0162 is an error here: a control that the compiler rejects
// proves nothing about the tests, and had it been scored the whole sweep would have rested on a
// self-check that never ran a single case. It was replaced with one the compiler accepts -
// detection walks a fresh empty list, so it can never declare anything - and that returns KILLED
// with 18 failed of 2263. Neither calibration row is counted below.
//
//  201. LossDelay's inner max becomes a min             4 tests
//  202. LossDelay drops latest_rtt, reads smoothed alone  ONLY TlsQuicConnectionTests.TheLossDelayTakesTheLargerOfTheSmoothedAndLatestRoundTripTimes
//  203. LossDelay drops smoothed_rtt, reads latest alone  4 tests
//  204. the kGranularity floor removed from the delay    ONLY TlsQuicConnectionTests.TheTimeThresholdIsFlooredAtTheTimerGranularityAndNotAtNineEighthsOfIt
//  205. the kGranularity floor becomes a ceiling        5 tests
//  206. kTimeThreshold replaced by a hardcoded 9/8       ONLY TlsQuicConnectionTests.APacketIsDeclaredLostAtExactlyThePacketThresholdAndNotOnePacketEarlier
//  207. the kTimeThreshold multiplier dropped           4 tests
//  208. the instance LossDelay reads rttvar for smoothed_rtt  3 tests
//  209. A.10's largest-acked assert reads "nothing acknowledged" as "everything acknowledged"  ONLY TlsQuicConnectionTests.LossInOneSpaceLeavesTheOtherUntouched
//  210. loss_time not cleared before the pass rebuilds it  ONLY TlsQuicConnectionTests.AReorderedPacketThatIsAcknowledgedLaterIsNeverDeclaredLost
//  211. the newer-than-largest-acked skip disabled      2 tests
//  212. the time threshold becomes exclusive: <= to <   3 tests
//  213. the packet threshold becomes exclusive: >= to >  6 tests
//  214. the packet threshold fires one packet early     5 tests
//  215. kPacketThreshold replaced by a hardcoded 3       ONLY TlsQuicConnectionTests.ADroppedDatagramsPacketIsDeclaredLostByARealAcknowledgement
//  216. a lost packet is reported but never Forgotten   3 tests
//  217. loss_time computed from now(), not time_sent    2 tests
//  218. A.10's min over loss_time becomes a max         ONLY TlsQuicConnectionTests.TheEarliestLossTimeAcrossTheSpacesIsTheOneAppendixEightWouldArm
//  219. A.8's earliest-across-spaces becomes latest      ONLY TlsQuicConnectionTests.TheEarliestLossTimeAcrossTheSpacesIsTheOneAppendixEightWouldArm
//  220. lost_send_time is now() PLUS the loss delay     11 tests
//  221. SubtractSaturating stops saturating and throws   ONLY TlsQuicConnectionTests.LossDetectionSurvivesEverySaturatingInput
//  222. the returned list is not cleared between passes  2 tests
//  223. LossTime always reads the Initial space's slot   7 tests
//  224. detection always operates on the Initial space  12 tests
//
// 24 KILLED, 0 SURVIVED. 24 + 0 = 24, which is the row count above and the length of the
// harness's own list.
//
// ---- A3-7 ROUND, THIS FILE's SHARE: 2 rows, numbered 225-226 ----
//
//  225. PacketsDeclaredLost never moves                 15 tests
//  226. LastDetectedLost reports nothing                15 tests
//
// 2 KILLED, 0 SURVIVED. 2 + 0 = 2, and 21 + 2 = 23, which is A3-7's whole sweep - the other 21
// rows are 171-191 in TlsQuicConnection.cs, where that task's gate arithmetic, calibration and
// survivor classification are carried. Fifteen tests apiece is not padding: these two members
// are how every direct-half witness in the loss detection tests file observes a pass it
// no longer invokes, so a member that lied would take the whole file with it.
//
// A CLEAN SWEEP IS A CLAIM ABOUT THE TESTS, NOT A BOAST, AND IT IS BOUNDED BY WHAT THE SWEEP
// COULD REACH. It mutated THIS FILE ONLY. Rows 141-170 in TlsQuicConnection.cs are A3-5's and
// were not re-run, because re-running them means editing that file's ledger and this task may
// not open it - but nothing here changes a line of it either, so those verdicts stand as
// measured. ONE OF THEM IS NOW KNOWN TO BE MIS-PREDICTED AND THE PREDICTION WAS ABOUT THIS TASK:
// row 160's note says `max(4 * rttvar, kGranularity)` is unwitnessed and that "A3-6 needs the
// same term for s6.1.2 and is where it becomes witnessable". IT DOES NOT. s6.1.2's threshold is
// `max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)` - it has no rttvar term at
// all, and it is not PtoDuration, which the same comment block also says A3-6 reads. Row 160
// stays unwitnessed and A3-7, which computes the PTO period, is where it can become witnessable.
//
// A3-7 DID IT, AND THE PATH WAS ARITHMETIC RATHER THAN A NEW STATE MACHINE: A.7's
// `rttvar = 3/4 * rttvar + 1/4 * abs(smoothed_rtt - adjusted_rtt)` decays rttvar by three
// quarters for every IDENTICAL sample while smoothed_rtt sits still, which is exactly the window
// row 160 named. TlsQuicConnectionTests.TheFourRttvarTermIsFlooredAtTheTimerGranularityAndThe
// FlooredValueIsWhatIsArmed is the witness and row 160 is now a kill.
//
// AND NO EXISTING TEST'S WITNESS IS MASKED BY THIS TASK, which is checkable by construction
// rather than by argument: nothing on any live path calls into this file - see the header - so
// no existing assertion can be satisfied by a code path added here. The only other production
// change is the Acks getter, which adds no behaviour. The gate arithmetic above is the
// corroboration: 2241 -> 2263 is this file's 22 cases and nothing else moved.
//
// THAT LAST CLAUSE STOPPED BEING TRUE AT A3-7 AND IS AMENDED RATHER THAN LEFT TO ROT. Live paths
// do call into this file now, so the construction argument no longer holds - and what it
// predicted would be safe was not: wiring A.10 into A.7 turned sixteen green tests red in one
// run, because every one of them observed a pass it had invoked itself. They were rewritten to
// observe the LIVE pass instead, which is a stronger claim than the one they used to make. The
// gate went 2263 -> 2282 with A3-7's own nineteen cases and nothing else moved.
//
internal sealed partial class TlsQuicConnection
{
    // RFC 9002 A.3's loss_time, "The time at which the next packet in that packet number space
    // in the packet number space will be considered lost based on exceeding the reordering
    // window in time" - one entry per space, which is why it is an array here while latest_rtt
    // and its siblings are scalars on TlsQuicAckTracker. A.3's own list draws the same line.
    //
    // NULL IS A.10's ZERO. A.10 writes `loss_time[pn_space] = 0` for "nothing pending" and
    // tests it as `if (loss_time[pn_space] == 0)`, and zero is a real instant in C# -
    // DateTimeOffset.MinValue - that a badly built TlsQuicSentPacket can carry. A nullable
    // keeps "no packet is waiting on the time threshold" and "a packet sent at the start of
    // the calendar is waiting" apart, which A.10's sentinel cannot.
    private readonly DateTimeOffset?[] _lossTime = new DateTimeOffset?[3];

    // ONE LIST FOR THE LIFETIME OF THE CONNECTION, cleared per call, for the reason
    // _ackedRanges gives four hundred lines up: A.10 "returns a list of packets newly detected
    // as lost", and a fresh list per ACK would be an allocation on the receive path whose size
    // the peer picks. The count is bounded by MaxRetainedPacketsPerSpace either way, but the
    // allocation is not, and this path runs once per ACK frame.
    private readonly List<TlsQuicSentPacket> _lostPackets = [];

    /// <summary>RFC 9002 A.3's <c>loss_time</c> for the packet number space
    /// <paramref name="level"/> belongs to: when the earliest packet not yet declared lost
    /// there will cross s6.1.2's time threshold, or <see langword="null"/> for A.10's
    /// <c>loss_time[pn_space] = 0</c>.</summary>
    internal DateTimeOffset? LossTime(TlsQuicEncryptionLevel level) => _lossTime[SpaceOf(level)];

    /// <summary>The packets the last <see cref="DetectAndRemoveLostPackets"/> pass declared
    /// lost - which, since A3-7 wired the two call sites, is normally a pass the LIVE path
    /// ran rather than a test's.</summary>
    /// <remarks>ADDED BY A3-7 AND IT ADDS NO STATE. It is the same borrowed list
    /// <see cref="DetectAndRemoveLostPackets"/> returns, exposed under a name a caller that
    /// did not make the call can read. It exists because wiring A.10 into
    /// <see cref="OnAckReceived"/> and <see cref="OnLossDetectionTimeout"/> moved the pass
    /// off the test's own stack: before A3-7 a test called detection and read the return,
    /// and after it the live path calls detection and the test has to read what the live path
    /// found. CLEARED AT THE START OF THE NEXT PASS, so a caller that needs it past one must
    /// copy it - the same caveat <see cref="DetectAndRemoveLostPackets"/> already states.
    /// <see cref="PacketsDeclaredLost"/> is the cumulative form for callers that only need to
    /// know that a pass found something.</remarks>
    internal IReadOnlyList<TlsQuicSentPacket> LastDetectedLost => _lostPackets;

    /// <summary>How many packets this connection has declared lost over its whole life,
    /// across every packet number space.</summary>
    /// <remarks>COUNTED INSIDE <see cref="DetectAndRemoveLostPackets"/> RATHER THAN AT ITS
    /// CALL SITES, so that no call site can declare a packet lost without the count moving -
    /// which is the property that makes "loss detection is live" checkable from outside
    /// rather than by reading the three call lines.</remarks>
    internal int PacketsDeclaredLost { get; private set; }

    /// <summary>RFC 9002 s5's estimator and RFC 9000 s13.2's acknowledgement state, as this
    /// connection keeps them.</summary>
    /// <remarks>EXPOSED BY A3-6 AND THE REASON IS A GAP IN WHAT A3-3's SEAM CAN REACH.
    /// <see cref="OnAckReceived"/> retires packets but does not touch this tracker -
    /// <c>largest_acked</c> is advanced by <c>ProcessAckFrame</c>, which the RECEIVE path
    /// calls - so a test driving retention through <see cref="OnPacketSent"/> and
    /// <see cref="OnAckReceived"/> alone leaves <c>largest_acked</c> null, and A.10's first
    /// line then returns before anything can be observed. The alternatives were worse: a
    /// second entry point here that forwarded to the tracker would be a copy of the receive
    /// path's call, and a settable largest-acked would be a fake standing in for the one piece
    /// of state s6.1's whole rule is stated against. This exposes the object the connection
    /// already owns and adds no behaviour; <see cref="LargestAcknowledged"/> was already a
    /// narrower window onto the same thing.</remarks>
    internal TlsQuicAckTracker Acks => _acks;

    // RFC 9002 A.8's GetLossTimeAndSpace, which A3-5 named as this task's and left out:
    // "time = loss_time[Initial]; space = Initial; for pn_space in [Handshake, ApplicationData]:
    // if (loss_time[pn_space] != 0 && (time == 0 || loss_time[pn_space] < time)): ...".
    //
    // A TUPLE-OR-NULL RATHER THAN A PAIR WITH A SENTINEL, matching how A3-5 rendered A.8's
    // `infinite`: A.8's `time == 0` is "no space has one", and returning (MinValue, Initial)
    // for that would be a real instant that compares EARLIER than every armed timer - the
    // exact shape of the bug A3-5 found in A.8's `pto_timeout = infinite` reaching update().
    /// <summary>RFC 9002 A.8's <c>GetLossTimeAndSpace</c>: the earliest
    /// <see cref="LossTime"/> across the three packet number spaces and which space holds it,
    /// or <see langword="null"/> when no space has one.</summary>
    /// <remarks>THIS IS A.8's RUNG 1 AND NOTHING CALLS IT YET; see this file's header for the
    /// three call sites that live in a file A3-6 may not edit.</remarks>
    internal (DateTimeOffset At, TlsQuicEncryptionLevel Space)? GetLossTimeAndSpace()
    {
        (DateTimeOffset At, TlsQuicEncryptionLevel Space)? earliest = null;

        foreach (var level in PtoSpaces)
        {
            if (_lossTime[SpaceOf(level)] is not { } at)
            {
                continue;
            }

            if (earliest is not { } best || at < best.At)
            {
                earliest = (at, level);
            }
        }

        return earliest;
    }

    /// <summary>RFC 9002 s6.1.2's time threshold:
    /// <c>max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)</c>.</summary>
    /// <remarks>
    /// <para>STATIC AND GIVEN ITS THREE INPUTS, so that the two directions of s6.1.2's inner
    /// <c>max</c> are witnessable without a connection that has taken the corresponding RTT
    /// samples. s6.1.2 spells out why that <c>max</c> is not a preference: it "protects from
    /// the two following cases: the latest RTT sample is lower than the smoothed RTT ... the
    /// latest RTT sample is higher than the smoothed RTT". Each case is one direction, and
    /// TlsQuicConnectionTests.TheLossDelayTakesTheLargerOfTheSmoothedAndLatestRoundTripTimes
    /// drives both.</para>
    /// <para>THE MULTIPLIER IS KNOB 7 AND THE FLOOR IS NOT A KNOB. See
    /// <see cref="TlsQuicRecoverySpec.KTimeThreshold"/> for why the A3 plan's fixed table
    /// keeps <c>kGranularity</c> out of the spec, and <see cref="KGranularity"/> for the debt
    /// A3-5 recorded about where the constant lives. It is READ from there rather than
    /// declared a second time here, which is what that note asked for; MOVING it to
    /// TlsQuicRecoverySpec.cs is an edit to a file A3-6 may not open either.</para>
    /// </remarks>
    /// <param name="recovery">A3-2's knobs; <see cref="TlsQuicRecoverySpec.TimeThreshold"/> is
    /// the multiplier.</param>
    /// <param name="smoothedRtt">RFC 9002 s5.3's <c>smoothed_rtt</c>.</param>
    /// <param name="latestRtt">RFC 9002 s5.1's <c>latest_rtt</c>.</param>
    internal static TimeSpan LossDelay(
        TlsQuicRecoverySpec recovery, TimeSpan smoothedRtt, TimeSpan latestRtt)
    {
        ArgumentNullException.ThrowIfNull(recovery);

        // A.10's `max(latest_rtt, smoothed_rtt)`, on ticks rather than on TimeSpan so that the
        // multiply below never builds an intermediate TimeSpan that could throw.
        var rtt = Math.Max(smoothedRtt.Ticks, latestRtt.Ticks);

        // Hazard 2. TimeSpan's operator* would throw on a spec carrying a large multiplier;
        // A3-5's saturating conversion is the one this file reuses.
        var delay = FromTicksSaturating(rtt * recovery.TimeThreshold);

        // s6.1.2's floor, and s6.1.2 states it as a MUST in its own words: "To avoid declaring
        // packets as lost too early, this time threshold MUST be set to at least the local
        // timer granularity, as indicated by the kGranularity constant." ON THE PRODUCT.
        return delay < KGranularity ? KGranularity : delay;
    }

    // The instance form, reading A3-2's knob and A3-4's live estimator. Both terms come from
    // the two places that own them - nothing here re-derives an RTT or restates a threshold.
    private TimeSpan LossDelay() =>
        LossDelay(_options.Spec.Recovery, _acks.SmoothedRtt, _acks.LatestRtt);

    /// <summary>RFC 9002 A.10's <c>DetectAndRemoveLostPackets</c> for one packet number space:
    /// declares every retained packet that meets s6.1's conditions lost, removes it through
    /// the same <c>Forget</c> path an acknowledgement uses so its bytes leave
    /// <see cref="BytesInFlight"/>, and sets <see cref="LossTime"/> for the earliest packet
    /// that has not crossed the time threshold yet.</summary>
    /// <remarks>
    /// <para>NOTHING HERE THROWS FOR ANY STATE, for the same reason
    /// <see cref="OnAckReceived"/> does not: every input is the peer's or the clock's. A.10's
    /// opening <c>assert(largest_acked_packet[pn_space] != infinite)</c> is a RETURN here and
    /// not a throw - s6.1's first condition is "was sent prior to an acknowledged packet", so
    /// a space that has acknowledged nothing has nothing to declare, and an assert would turn
    /// a caller ordering question into a dead connection.</para>
    /// <para>THE RESULT IS BORROWED. It is the same list on every call; a caller that needs it
    /// past the next call must copy it.</para>
    /// </remarks>
    /// <param name="level">Any level; RFC 9000 s12.3's space is what is operated on, so 0-RTT
    /// and 1-RTT name the one Application Data space between them.</param>
    /// <returns>The packets newly declared lost, in no particular order.</returns>
    internal IReadOnlyList<TlsQuicSentPacket> DetectAndRemoveLostPackets(
        TlsQuicEncryptionLevel level)
    {
        var space = SpaceOf(level);
        _lostPackets.Clear();

        // A.10's assert, as the return this method's remarks explain.
        if (_acks.LargestAcked(level) is not { } largestAcked)
        {
            return _lostPackets;
        }

        // A.10's `loss_time[pn_space] = 0`, BEFORE the loop and not after it: the loop rebuilds
        // it from what is still retained, so a stale entry for a packet that has since been
        // acknowledged must not survive the pass.
        _lossTime[space] = null;

        var lossDelay = LossDelay();

        // A.10's `lost_send_time = now() - loss_delay`, saturating - hazard 3.
        var lostSendTime = SubtractSaturating(_options.TimeProvider.GetUtcNow(), lossDelay);

        // A3-2's knob 6, read rather than typed.
        var packetThreshold = (ulong)_options.Spec.Recovery.PacketThreshold;

        var retained = _sentPackets[space];

        // BACKWARDS, for OnAckReceived's reason: Forget removes by index, so a forward walk
        // would skip the element after every removal. A.10 walks forwards because its
        // pseudocode removes by packet number from an associative collection.
        for (var i = retained.Count - 1; i >= 0; i--)
        {
            var unacked = retained[i];

            // A.10: "if (unacked.packet_number > largest_acked_packet[pn_space]): continue".
            // This is s6.1's "was sent prior to an acknowledged packet", and it is also what
            // makes the subtraction below safe.
            if (unacked.PacketNumber > largestAcked)
            {
                continue;
            }

            // A.10's two disjuncts. The time one is `<=` there, so a packet sent EXACTLY
            // loss_delay ago is lost rather than spared;
            // TlsQuicConnectionTests.APacketSentExactlyTheLossDelayAgoIsDeclaredLostAndOneTick
            // ShortIsNot pins that boundary against its neighbour rather than in isolation.
            // The packet one is the subtraction of hazard 1, not A.10's addition.
            if (unacked.SentAt <= lostSendTime
                || largestAcked - unacked.PacketNumber >= packetThreshold)
            {
                // A.10's `sent_packets[pn_space].remove(...)` and `lost_packets.insert(...)`.
                // Forget is A3-3's single exit from retention and is what takes the bytes out
                // of bytes_in_flight; this file adds no removal of its own.
                _lostPackets.Add(unacked);

                // TASK A3-8's ONE LINE IN A.10's LOOP, AND ITS POSITION IS THE WHOLE POINT.
                // RFC 9000 s13.3: "the information that might be carried in frames is sent
                // again in new frames as needed" - so this is where a declared loss becomes an
                // owed repair. BEFORE Forget, because Forget is retention's single exit and
                // takes this packet's repair ledger entry with it.
                QueueRepairsFor(unacked);
                Forget(retained, i);
                continue;
            }

            // A.10's else: "loss_time[pn_space] = min(loss_time[pn_space],
            // unacked.time_sent + loss_delay)", with A.10's zero test folded into the null.
            var at = AddSaturating(unacked.SentAt, lossDelay);
            if (_lossTime[space] is not { } pending || at < pending)
            {
                _lossTime[space] = at;
            }
        }

        PacketsDeclaredLost += _lostPackets.Count;

        // RFC 8899 s4.3's black hole detection and s5.3.1's failed probe, both fed from the one
        // place a packet is declared lost so that neither call site can be added without the
        // other. The state machine sorts them out: a lost PROBE advances PROBE_COUNT, a lost
        // ordinary packet larger than BASE_PLPMTU counts toward "excessive loss of data sent
        // with a specific packet size", and anything at or below BASE_PLPMTU says nothing about
        // size at all.
        //
        // THE SIZE IS THE DATAGRAM'S, which is what TlsQuicSentPacket.Size records and what
        // s4.3's indicator is about. A frame count or a payload length would make the same call
        // shape mean a different thing.
        foreach (var lost in _lostPackets)
        {
            if (lost.Level == TlsQuicEncryptionLevel.Application)
            {
                _pathMtu.OnPacketLost(lost.PacketNumber, lost.Size);
            }
        }

        // RFC 9002 A.7's "if (!lost_packets.empty()): OnPacketsLost(lost_packets)" and B.8,
        // which A3-7 recorded as a seam it could not close: "A.7's consumer of the list is
        // OnPacketsLost, which is the congestion controller's (task A3-9) and the
        // retransmitter's (task A3-8)". Both halves exist now, and so does the controller they
        // were waiting for - see Congestion.
        // A.7's OWN GUARD, TRANSCRIBED: "lost_packets = DetectAndRemoveLostPackets(pn_space);
        // if (!lost_packets.empty()): OnPacketsLost(lost_packets)". The interface treats an
        // empty list as none, so dropping the guard would be harmless arithmetic - and it would
        // still be wrong, because every acknowledgement that declares nothing would raise a
        // congestion EVENT the controller has to decide is a no-op, and any controller that
        // counted its calls would see a loss on every ACK. Found by a test that asserted WHICH
        // seam members were called rather than only that the window moved.
        if (_lostPackets.Count == 0)
        {
            return _lostPackets;
        }

        var controller = Congestion;
        controller.OnPacketsLost(_lostPackets);

        // ====================================================================
        // A3-10's THREE OWED CALL LINES, IN B.8's ORDER AND AT ITS CALL SITE.
        // ====================================================================
        //
        // A3-10 built RFC 9002 s7.6's predicate and could not wire it, and said so in its own
        // closing note: "Nothing calls TlsQuicPersistentCongestion from TlsQuicConnection.cs or
        // TlsQuicLossDetection.cs. Both files were being edited by another task while this one
        // ran ... The call site is three lines - OnPacketsLost, then IsEstablished, then
        // OnPersistentCongestion, in B.8's order - and the shape is pinned by
        // RunScriptedBlackoutAsync." This IS that shape, against the live loss pass. It is the
        // same debt A3-6 carried until A3-7 wrote its three lines, and leaving it would have
        // left s7.6.2's MUST inert exactly as loss detection was before A3-7.
        //
        // THE ORDER IS B.8's AND NOT A CONVENIENCE. OnPacketsLost is what takes the lost bytes
        // OUT of the controller's bytes_in_flight; a collapse evaluated before it would reduce
        // the window while the packets that provoked it were still counted against it, and the
        // minimum window would then be reached with the flight still nominally in the air.
        //
        // EVERY ARGUMENT COMES FROM ITS OWNER AND NONE IS RE-DERIVED HERE. The estimator owns
        // the RTT terms and the first-sample instant, TlsQuicPersistentCongestion owns the
        // duration formula, and the peer's advertised max_ack_delay is the connection's own
        // field - the same one A.8's PtoDuration reads, so the two cannot drift.
        if (TlsQuicPersistentCongestion.IsEstablished(
                _lostPackets,
                _acks.FirstRttSampleAt,
                _latestAcknowledgedSendTime,
                TlsQuicPersistentCongestion.DurationFor(
                    _options.Spec.Recovery,
                    _acks.SmoothedRtt,
                    _acks.RttVariation,
                    _peerMaxAckDelay)))
        {
            PersistentCongestionEvents++;
            controller.OnPersistentCongestion();
        }

        return _lostPackets;
    }

    // AddSaturating's mirror, and the same argument applies: DateTimeOffset's operator- throws
    // when the difference leaves the calendar, and a loss delay saturated at TimeSpan.MaxValue
    // reaches that in one step.
    private static DateTimeOffset SubtractSaturating(DateTimeOffset at, TimeSpan span) =>
        span > at - DateTimeOffset.MinValue ? DateTimeOffset.MinValue : at - span;

    // ========================================================================
    // TASK A3-8: THE REPAIR LEDGER, AND WHY IT SITS BESIDE _sentPackets.
    // ========================================================================
    //
    // TlsQuicPacketBuilder.cs:37-46 refuses to put a byte range on TlsQuicSentPacket, because
    // "a range here would be a second place to keep in step with the first". A dictionary keyed
    // by packet number is not a second place: it is written by the same build step that appends
    // to _justSent and removed by the same Forget that removes the packet, so the two cannot
    // come apart, and RFC 9000 s12.3 forbids reusing a packet number within a space, so the key
    // is unique for the life of that space.
    //
    // WHAT IS STORED IS THE FRAMES s13.3 CAN REPAIR, AND ONLY THOSE. A packet that carried an
    // ACK and a PING gets no entry at all, because s13.3 repairs neither - which is also what
    // makes this cheap on the steady-state ACK path.
    //
    // THE BYTES ARE COPIED, AND THAT IS LOAD-BEARING RATHER THAN CAUTIOUS. A CRYPTO frame's
    // Data is a view of a TlsQuicCryptoDataEvent's buffer, and SendAnswerAsync disposes every
    // result in a finally block on the way out of the pump; a repair holding that view would
    // retransmit whatever the buffer held next. Finding 1 states the same thing from the other
    // end - CustomTlsQuicClient "hands over the only copy" - and this is where a second copy
    // starts existing, which is exactly the task the plan assigned here rather than to A3-3.
    private readonly Dictionary<ulong, List<TlsQuicFrame>>[] _repairable =
        [new Dictionary<ulong, List<TlsQuicFrame>>(),
         new Dictionary<ulong, List<TlsQuicFrame>>(),
         new Dictionary<ulong, List<TlsQuicFrame>>()];

    // The repairs owed but not yet handed to a packet builder, PER LEVEL rather than per space.
    // The ledger above is per space because that is what a packet number identifies; this is
    // per level because that is what decides which packet a frame may travel in - s12.4 Table 3
    // is a per-level table, and 0-RTT and 1-RTT share a space while accepting different frames.
    //
    // FOUR ENTRIES, ONE PER TlsQuicEncryptionLevel, AND THE EarlyData ONE IS NEVER FILLED.
    // Nothing in this client sends a 0-RTT packet (BuildAnswerDatagram skips the level outright)
    // so no 0-RTT packet is ever retained, so no 0-RTT frame is ever repairable. The slot exists
    // because the index is a cast of the enum and a three-entry array would make that cast a
    // trap for whoever adds 0-RTT.
    private readonly List<TlsQuicFrame>[] _repairsOwed = [[], [], [], []];

    /// <summary>How many frames this connection has put back on the wire because RFC 9000
    /// s13.3 said their information had to be sent again.</summary>
    /// <remarks>
    /// <para>COUNTED WHEN THE FRAME IS HANDED TO A BUILDER, not when it is queued: a repair
    /// that is owed and never sent is not a retransmission, and the difference between the two
    /// is exactly what a congestion gate or a discarded key level produces.</para>
    /// <para>TWO SUMMANDS BECAUSE THERE ARE TWO DRAINS. Initial and Handshake repairs leave
    /// through <see cref="TakeRepairsInto"/> here; 1-RTT repairs leave through
    /// <c>TlsQuicStreamSet.TakePendingFrames</c>, which is the existing 1-RTT frame drain and
    /// is reached from a file this task may not open. Adding the stream set's own count rather
    /// than counting at the queue keeps the "handed to a builder" meaning true of both.</para>
    /// </remarks>
    internal int FramesRetransmitted =>
        _framesRetransmitted + (_streams?.RepairsSent ?? 0);

    private int _framesRetransmitted;

    /// <summary>How many times RFC 9002 s7.6's persistent congestion has been declared on this
    /// connection.</summary>
    /// <remarks>A COUNTER RATHER THAN A FLAG, because s7.6 can be established more than once on
    /// one connection and a flag would report a second blackout as the first. It moves only when
    /// a controller is configured, for the reason <see cref="Congestion"/> gives - which is also
    /// why it is a separate witness from the controller's own window: a test can watch the
    /// DECISION without owning a controller that responds to it.</remarks>
    internal int PersistentCongestionEvents { get; private set; }

    /// <summary>How many frames of lost packets RFC 9000 s13.3 said to send nothing for.</summary>
    /// <remarks>THE WITNESS FOR s13.3's THIRD GROUP, and it needs to be a counter rather than an
    /// absence: "no PATH_RESPONSE was retransmitted" is also true of a build that retransmits
    /// nothing at all, and the two must be told apart. This counts the frames that were seen,
    /// classified, and deliberately not repaired.</remarks>
    internal int FramesNotRepaired { get; private set; }

    /// <summary>The repairs owed at one level and not yet handed to a builder.</summary>
    /// <remarks>BORROWED: it is the live list, and the next send pass at that level empties it.
    /// At Application it is the stream set's queue rather than this type's, for the reason
    /// <see cref="FramesRetransmitted"/> gives about the two drains; a connection that has never
    /// opened a stream has no such queue and owes nothing there.</remarks>
    internal IReadOnlyList<TlsQuicFrame> RepairsOwed(TlsQuicEncryptionLevel level) =>
        QueueFor(level);

    // The one place that decides which of the two queues a level's repairs live in, so that the
    // writer and the reader cannot disagree about it.
    //
    // THE FALLBACK AT Application IS UNREACHABLE IN PRODUCTION AND IS DELIBERATELY KEPT. Every
    // 1-RTT frame s13.3 repairs - STREAM, MAX_DATA, MAX_STREAM_DATA - is queued by the stream
    // set, so a connection with no stream set has never sent one; the other frames a 1-RTT
    // packet of this client carries are ACK, PATH_RESPONSE and PING, and s13.3 drops all three.
    // What the fallback buys is that a repair can never be written to one queue and read from
    // the other, which is the failure that would make a repair invisible rather than merely
    // undrained.
    private List<TlsQuicFrame> QueueFor(TlsQuicEncryptionLevel level) =>
        level == TlsQuicEncryptionLevel.Application && _streams is { } streams
            ? streams.RepairsOwed
            : _repairsOwed[(int)level];

    // ========================================================================
    // A3-9's CONTROLLER, CONSTRUCTED - THE THIRD WIRING DEBT IN THIS SUBSYSTEM.
    // ========================================================================
    //
    // A3-6 built loss detection and could not wire it; A3-7 wrote its three call lines. A3-10
    // built persistent congestion and could not wire it; this file writes its three. A3-9 built
    // TlsQuicNewRenoCongestionController behind knob 4 and NOTHING EVER CALLED THE FACTORY -
    // grep for CongestionController under src/ before this task returned one hit, the knob's own
    // declaration. Every one of those agents reported the gap rather than reaching into a file
    // another held, which is why this subsystem's history is clean; none of them was assigned
    // the wiring.
    //
    // NULL RESOLVES TO NEWRENO, WHICH IS WHAT THE KNOB ALREADY SAYS IT MEANS. Knob 4's own
    // remarks: "null - the shipped default - means the NewReno controller RFC 9002 s7 specifies,
    // which task A3-9 supplies". Leaving null as "no congestion control at all" would have made
    // that sentence false and would have left this task's own requirement - that a
    // retransmission respects CanSend - unmeetable by construction, because there would have
    // been nothing to ask.
    //
    // THE SEAM STAYS A SEAM. A caller that names a factory gets its controller, untouched: the
    // fallback is only reached when the knob is null. Nothing here type-tests, unwraps or
    // special-cases NewReno, because knob 4 is the single largest behavioural fingerprint in the
    // subsystem - RFC 9002 specifies NewReno and Chromium is said to run BBR - and a connection
    // that hard-coded one would make the knob decorative. See TlsQuicRecoverySpec's remarks and
    // task A3-14, which is what would settle which is right.
    //
    // max_datagram_size IS THE PADDING TARGET AND NOT A LITERAL 1200. RFC 9002 B.2 defines it as
    // "the sender's current maximum payload size"; TlsQuicConnectionSpec.PaddingTarget is the
    // size this client actually expands a datagram to, its floor IS s14.1's 1200, and it is a
    // knob - so the initial window moves with the spec instead of with a constant nobody can
    // check.
    //
    // WHAT THIS DOES NOT DO, NAMED SO IT IS NOT MISTAKEN FOR DONE. s7's "An endpoint MUST NOT
    // send a packet if it would cause bytes_in_flight ... to be larger than the congestion
    // window" is NOT yet enforced on the new-data send path: this task gates the REPAIR drain
    // (see TakeRepairsInto) and drives every signal the controller needs, so the window it
    // reports is live and correct, but BuildAnswerDatagram and TryBuildApplicationPacket still
    // build without asking. That gate belongs with A3-11's pacer, which is the task that owns
    // when a send may leave rather than only whether it may; the latter file is also not this
    // task's to open. A partial landing said out loud beats an overlarge one.
    private ITlsQuicCongestionController? _congestion;

    private ITlsQuicCongestionController Congestion =>
        _congestion ??= _options.Spec.Recovery.CongestionController?.Invoke()
            ?? new TlsQuicNewRenoCongestionController(
                _options.Spec.Recovery, _options.Spec.PaddingTarget, _options.TimeProvider);

    /// <summary>The RFC 9002 s7 controller this connection runs: knob 4's, or the NewReno one
    /// s7 specifies when the knob is null.</summary>
    /// <remarks>CONSTRUCTED ON FIRST USE rather than in the constructor, for the reason
    /// <c>Streams</c> gives about its own: a connection that is built and never started should
    /// not run a factory the caller supplied. The instance is then fixed for the connection's
    /// life, which is what knob 4 means by "a factory called once per connection".</remarks>
    internal ITlsQuicCongestionController CongestionControl => Congestion;

    /// <summary>Records what RFC 9000 s13.3 could repair out of one packet this connection just
    /// built, so that declaring it lost later has something to send again.</summary>
    /// <remarks>
    /// <para>CALLED BESIDE <see cref="RetainSentPackets"/> AT EVERY BUILD SITE, and it takes the
    /// frames rather than reading them off <see cref="TlsQuicSentPacket"/> because that record
    /// deliberately does not carry them.</para>
    /// <para>NOTHING HERE THROWS. The frames are ones this connection built, but the DATA in
    /// them came from the TLS engine and from the peer's flow-control decisions, and a null
    /// list is answered rather than rejected.</para>
    /// </remarks>
    /// <param name="level">The level the packet was protected at.</param>
    /// <param name="packetNumber">The packet's number in its space - s12.3 makes it unique
    /// there, which is what lets it be the key.</param>
    /// <param name="frames">The frames the packet carried.</param>
    internal void RecordRepairable(
        TlsQuicEncryptionLevel level, ulong packetNumber, IReadOnlyList<TlsQuicFrame>? frames)
    {
        if (frames is null)
        {
            return;
        }

        List<TlsQuicFrame>? repairable = null;
        foreach (var frame in frames)
        {
            if (TlsQuicRetransmission.ActionFor(frame.Type) == TlsQuicRepairAction.Drop)
            {
                continue;
            }

            repairable ??= [];

            // The copy this type's field comment calls load-bearing. ToArray on an empty
            // ReadOnlyMemory allocates nothing worth avoiding and keeps the branch out.
            repairable.Add(frame with { Data = frame.Data.ToArray() });
        }

        if (repairable is null)
        {
            return;
        }

        _repairable[SpaceOf(level)][packetNumber] = repairable;
    }

    /// <summary>RFC 9000 s13.3's repair for one packet loss detection has just declared lost:
    /// every frame it carried whose information s13.3 says to send again is queued for the next
    /// packet built at that level.</summary>
    /// <remarks>CALLED BEFORE <see cref="Forget"/> AND NOT AFTER, because Forget is retention's
    /// single exit and takes this packet's ledger entry with it. The ordering is the whole
    /// reason this is a method rather than two lines in A.10's loop.</remarks>
    private void QueueRepairsFor(in TlsQuicSentPacket lost)
    {
        if (!_repairable[SpaceOf(lost.Level)].TryGetValue(lost.PacketNumber, out var frames))
        {
            return;
        }

        foreach (var frame in frames)
        {
            QueueRepair(lost.Level, frame);
        }
    }

    // s13.3's rule for ONE frame, applied. Never throws: every field read below came off a
    // frame this connection built, and the two that consult live state - the flow-control
    // grants - go through a Try-shaped call that answers rather than rejects.
    private void QueueRepair(TlsQuicEncryptionLevel level, in TlsQuicFrame lost)
    {
        var action = TlsQuicRetransmission.ActionFor(lost.Type);
        if (action == TlsQuicRepairAction.Drop)
        {
            FramesNotRepaired++;
            return;
        }

        var repaired = lost;

        // s13.3's Refresh SECOND SHAPE, and the only two members of it this client ever sends.
        // "An updated value is sent in a MAX_DATA frame if the packet containing the most
        // recently sent MAX_DATA frame is declared lost" - the value comes from the stream set,
        // which owns the limits, and not from the lost frame. A connection with no stream set
        // never sent one of these, so the false branch is unreachable rather than lossy; it is
        // counted rather than ignored so that a build which silently stopped repairing grants
        // would move a number.
        if (lost.Type is TlsQuicFrameType.MaxData or TlsQuicFrameType.MaxStreamData)
        {
            if (_streams is not { } streams || !streams.TryRefreshGrant(lost, out repaired))
            {
                FramesNotRepaired++;
                return;
            }
        }

        // THE ANSWER TO "the same information is never sent twice concurrently at two offsets".
        // Two lost packets can carry the same repairable information - the opening flight splits
        // one CRYPTO stream across datagrams and this ledger records the whole stream against
        // each of them, see BuildInitialFlight - and a queue that took both would put the same
        // bytes in one packet twice. The comparison is on the four fields that identify the
        // INFORMATION rather than on the bytes, because s13.3's whole point is that the frame
        // may differ while the information does not.
        var owed = QueueFor(level);

        foreach (var already in owed)
        {
            if (already.Type == repaired.Type
                && already.StreamId == repaired.StreamId
                && already.Offset == repaired.Offset
                && already.Data.Length == repaired.Data.Length)
            {
                return;
            }
        }

        // BOUNDED, SO THAT A PEER THAT ACKNOWLEDGES NOTHING CANNOT GROW THIS WITHOUT LIMIT. The
        // bound is MaxRetainedPacketsPerSpace and not a new constant: a repair can only be
        // queued by a packet leaving retention, retention is capped at that number per space,
        // and reusing it means the two caps cannot drift. Dropping the excess rather than
        // evicting the oldest is the conservative direction - the oldest repair is the one the
        // peer has been waiting longest for.
        if (owed.Count >= MaxRetainedPacketsPerSpace)
        {
            FramesNotRepaired++;
            return;
        }

        // s13.3 line 148: "Endpoints SHOULD prioritize retransmission of data over sending new
        // data, unless priorities specified by the application indicate otherwise". At Initial
        // and Handshake this list is drained ahead of the pass's own CRYPTO, which is that
        // sentence; at Application the stream set puts its repairs ahead of its pending frames
        // for the same reason. Neither is a sort - queue order is send order in both, which is
        // what keeps two frames on one stream in offset order.
        owed.Add(repaired);
    }

    /// <summary>Hands the repairs owed at one level to a packet being built, as many as fit.
    /// </summary>
    /// <param name="level">The level whose queue to drain.</param>
    /// <param name="frames">The packet's frame list, appended to.</param>
    /// <param name="payloadBudget">Bytes of frame payload this datagram has left. What does not
    /// fit STAYS OWED and goes out in the next one.</param>
    /// <remarks>
    /// <para>THE CONGESTION GATE IS HERE AND NOT AT THE QUEUE, because RFC 9002 s7's rule is
    /// about sending: "An endpoint MUST NOT send a packet if it would cause bytes_in_flight ...
    /// to be larger than the congestion window". A refused repair STAYS OWED and is offered
    /// again on the next pass - it is not dropped, which would turn a full window into a lost
    /// handshake.</para>
    /// <para>THE SIZE PASSED TO THE GATE IS A LOWER BOUND AND IS SAID TO BE ONE. The packet's
    /// real size is TlsQuicPacketBuilder's, and it is not known until after the build; the sum
    /// of the repairs' payloads is what this pass is about to add and is the honest quantity
    /// available here. A gate that under-estimates admits a packet at the boundary that a
    /// byte-exact one would refuse, which s7's "larger than" already permits for the exact
    /// case; A3-11's pacing task is where a send path acquires a byte-exact gate.</para>
    /// <para>NOT USED BY THE PROBE PATH, and that is s7.5 rather than an omission:
    /// "Probe packets MUST NOT be blocked by the congestion controller."</para>
    /// <para>THE BUDGET IS RFC 9000 s14.2's, AND IT WAS MISSING. This used to be
    /// <c>frames.AddRange(owed)</c> - every owed repair into one packet, gated on the
    /// congestion window and on nothing else. The congestion window is not a size limit: it
    /// bounds bytes IN FLIGHT across packets and says nothing about whether one datagram fits
    /// the path. A client whose ClientHello was split into a 999-byte CRYPTO frame and a
    /// ~492-byte one - two datagrams of 1200, because that is what fitted - repaired both into
    /// ONE datagram of about 1525, which a DF-set socket refuses outright with
    /// SocketError.MessageSize. The split that made the original flight legal was undone by the
    /// repair that was supposed to reproduce it.</para>
    /// <para>AND <see cref="AppendProbeData"/> HAD THIS ALL ALONG, twenty lines below: fill to
    /// a budget, leave the remainder owed. Two drains of the same queue answered the same
    /// question differently and only one of them was right; this is the other one brought into
    /// line rather than a new idea.</para>
    /// <para>A REFUSED FRAME IS NEVER DROPPED - it stays at the head of the queue in send
    /// order, so the next datagram takes it and two frames on one stream keep their offsets.
    /// Dropping the overflow would pass every size assertion and stall the handshake, which is
    /// a worse failure than the one being fixed.</para>
    /// <para>INTERNAL FOR THE REASON <see cref="OnPacketSent"/> GIVES ABOUT ITS OWN: this IS
    /// the drain <c>BuildAnswerDatagram</c> calls for every Initial and Handshake packet it
    /// builds, so a test driving it drives the same code the send path does. What such a test
    /// does NOT prove is that the send path calls it; the loopback witnesses cover that half
    /// and neither half is sufficient alone.</para>
    /// </remarks>
    internal void TakeRepairsInto(
        TlsQuicEncryptionLevel level, List<TlsQuicFrame> frames, int payloadBudget)
    {
        var owed = _repairsOwed[(int)level];
        if (owed.Count == 0)
        {
            return;
        }

        // HOW MANY FIT, DECIDED BEFORE THE CONGESTION GATE IS ASKED. The gate's question is
        // "may these bytes be sent"; asking it about bytes this datagram was never going to
        // carry would refuse a repair that fits on a window that could have taken it.
        var take = 0;
        var bytes = 0;
        while (take < owed.Count && bytes + owed[take].Data.Length <= payloadBudget)
        {
            bytes += owed[take].Data.Length;
            take++;
        }

        // A CRYPTO FRAME THAT DOES NOT FIT IS SPLIT, AND THE CLAIM THAT IT COULD NOT BE WAS
        // THIS METHOD'S OWN AND WAS WRONG. RFC 9000 s19.6 gives CRYPTO an explicit Offset, so a
        // frame carrying the tail of a message is complete in itself - which is exactly why the
        // fresh-CRYPTO arm in BuildAnswerDatagram chunks. What the offsets being "the TLS
        // endpoint's" rules out is INVENTING one, not advancing a known one by the bytes
        // already taken.
        //
        // THIS IS THE ARM THE FIELD REPORTS LANDED ON. SendInitialFlightAsync records the whole
        // ClientHello as ONE repairable frame at offset 0 - deliberately, so the ledger carries
        // no second copy of the builder's chunking - so a lost opening flight comes back as a
        // single ~1486-byte repair. The escape below then took it whole and built a 1525-byte
        // Initial packet that a DF-set socket refuses, at a budget that had already said 1170.
        TlsQuicFrame? split = null;
        if (take < owed.Count && owed[take].Type == TlsQuicFrameType.Crypto)
        {
            var room = payloadBudget - bytes - CryptoRepairFrameOverheadBound;
            if (room > 0)
            {
                var head = owed[take];
                split = head with { Data = head.Data[..room] };
                owed[take] = head with
                {
                    Offset = head.Offset + (ulong)room,
                    Data = head.Data[room..],
                };
                bytes += room;
            }
        }

        // AND THE ESCAPE STAYS FOR EVERYTHING ELSE. A MAX_DATA is one value, not a byte range;
        // splitting it has no meaning. Such a frame goes out oversized and the send path reports
        // a legible refusal, which beats a queue that never drains and a handshake that hangs.
        if (take == 0 && split is null)
        {
            take = 1;
            bytes = owed[0].Data.Length;
        }

        if (!Congestion.CanSend(bytes))
        {
            return;
        }

        for (var i = 0; i < take; i++)
        {
            frames.Add(owed[i]);
        }

        // AFTER the whole frames and never instead of them: the split head is the NEXT frame in
        // queue order, and s13.3's order is what keeps two frames on one stream in offset order.
        if (split is { } prefix)
        {
            frames.Add(prefix);
            _framesRetransmitted++;
        }

        owed.RemoveRange(0, take);
        _framesRetransmitted += take;
    }

    /// <summary>An upper bound on a CRYPTO frame's own framing, RFC 9000 s19.6.</summary>
    /// <remarks>Type byte plus Offset and Length at s16 Table 4's widest eight bytes each.
    /// Pessimistic on purpose - it is subtracted from a budget, so over-stating it costs a few
    /// bytes and under-stating it builds the datagram that cannot be sent.</remarks>
    private const int CryptoRepairFrameOverheadBound = 1 + 8 + 8;

    /// <summary>RFC 9002 s6.2.4's "Previously sent data MAY be sent if no new data can be sent":
    /// fills a probe packet with the information the probed space is still waiting on.</summary>
    /// <remarks>
    /// <para>TWO SOURCES, IN s6.2.4's OWN ORDER. Anything already owed because loss detection
    /// declared it lost goes first; only if there is none does this reach into packets that are
    /// still retained and unacknowledged, which is what "previously sent data" names. Reaching
    /// into retention DOES NOT DECLARE ANYTHING LOST and does not remove anything: s6.2.4 offers
    /// marking in-flight packets lost as a separate alternative and warns what it costs -
    /// "increases the risk that loss is declared too aggressively, resulting in an unnecessary
    /// rate reduction by the congestion controller" - so taking the probe arm and the loss arm
    /// at once would pay that price twice.</para>
    /// <para>BOUNDED BY ONE FULL-SIZED DATAGRAM, which is s6.2.4's own unit: "An endpoint MAY
    /// send up to two full-sized datagrams containing ack-eliciting packets". The bound is what
    /// makes the throw-free claim structural rather than probabilistic - every frame taken here
    /// already fitted in a datagram this connection built once, and the running total stops
    /// before a second one could be added past the target.</para>
    /// <para>THE PROBE IS NOT GATED. s7.5: "Probe packets MUST NOT be blocked by the congestion
    /// controller."</para>
    /// </remarks>
    private void AppendProbeData(TlsQuicEncryptionLevel level, List<TlsQuicFrame> frames)
    {
        var budget = _options.Spec.PaddingTarget;
        var used = 0;

        var owed = _repairsOwed[(int)level];
        for (var i = 0; i < owed.Count; i++)
        {
            if (used + owed[i].Data.Length > budget)
            {
                break;
            }

            used += owed[i].Data.Length;
            frames.Add(owed[i]);
            _framesRetransmitted++;
            owed.RemoveAt(i--);
        }

        if (used > 0)
        {
            return;
        }

        // s6.2.4's "previously sent data": the oldest packet in this space that is still
        // retained and still carries something s13.3 can repair. OLDEST, because the peer has
        // been waiting on it longest and s13.3's own closing advice is to avoid retransmitting
        // information from packets once they are acknowledged - the oldest unacknowledged one is
        // the least likely to have been.
        var retained = _sentPackets[SpaceOf(level)];
        var ledger = _repairable[SpaceOf(level)];
        foreach (var sent in retained)
        {
            if (sent.Level != level
                || !ledger.TryGetValue(sent.PacketNumber, out var repairable))
            {
                continue;
            }

            foreach (var frame in repairable)
            {
                if (TlsQuicRetransmission.ActionFor(frame.Type) == TlsQuicRepairAction.Drop
                    || used + frame.Data.Length > budget)
                {
                    continue;
                }

                used += frame.Data.Length;
                frames.Add(frame);
                _framesRetransmitted++;
            }

            if (used > 0)
            {
                return;
            }
        }
    }
}

// ============================================================================
// TASK A3-8: RFC 9000 s13.3's THREE-WAY SPLIT, AS DATA.
// ============================================================================
//
// rfc9000-section13.3-retransmission-of-information.txt lines 21-25, verbatim: "QUIC packets
// that are determined to be lost are not retransmitted whole. The same applies to the frames
// that are contained within lost packets. Instead, the information that might be carried in
// frames is sent again in new frames as needed."
//
// THAT SENTENCE IS WHY A3-3 RETAINED PACKETS AND NOT FRAMES, and it is why this needs a table
// rather than a rule. s13.3 then spends fifteen bullets saying different things about different
// frame types, and they fall into three groups - which is the ONE distinction this task exists
// to get right, because a build that repaired everything the same way would repair a transfer,
// pass every completion test, and still be wrong on the wire.

/// <summary>What RFC 9000 s13.3 does with the information one frame carried, once the packet
/// carrying it has been declared lost.</summary>
/// <remarks>THREE MEMBERS BECAUSE s13.3 MAKES THREE DISTINCTIONS, not because three is a tidy
/// number. Read <see cref="TlsQuicRetransmission.ActionFor"/>: every row there is quoted
/// against the bullet that assigns it, and no frame type is classified from memory.</remarks>
internal enum TlsQuicRepairAction
{
    /// <summary>The frame goes again with its contents unchanged. s13.3 says so in those words
    /// for RESET_STREAM, whose "content ... MUST NOT change when it is sent again", and for
    /// NEW_CONNECTION_ID, whose "retransmissions of this frame carry the same sequence number
    /// value"; and it says "retransmitted if the packet containing them is lost" of
    /// RETIRE_CONNECTION_ID and NEW_TOKEN, "MUST be retransmitted until it is acknowledged" of
    /// HANDSHAKE_DONE, and "sent until the receiving part of the stream enters either a "Data
    /// Recvd" or "Reset Recvd" state" of STOP_SENDING.</summary>
    Resend,

    /// <summary>The INFORMATION goes again in a new frame, which need not be byte-identical to
    /// the lost one. Two shapes, and s13.3 gives both: a byte range, where the new frame
    /// carries the same offset and the same bytes - "Data sent in CRYPTO frames is retransmitted
    /// ... until all data has been acknowledged" and "Application data sent in STREAM frames is
    /// retransmitted in new STREAM frames"; and a current value, where re-sending the LOST
    /// number would be the defect - "An updated value is sent in a MAX_DATA frame if the packet
    /// containing the most recently sent MAX_DATA frame is declared lost", the same sentence
    /// again for MAX_STREAM_DATA and MAX_STREAMS, and for the three blocked signals "These
    /// frames always include the limit that is causing blocking at the time that they are
    /// transmitted."</summary>
    Refresh,

    /// <summary>Nothing is sent. s13.3 is explicit for every member: ACK, because "resending
    /// old ACK frames can cause the peer to generate an inflated RTT sample or unnecessarily
    /// disable ECN"; CONNECTION_CLOSE, whose signals "are not sent again when packet loss is
    /// detected"; PATH_RESPONSE, "sent just once"; PATH_CHALLENGE, which runs on its own
    /// periodic schedule and "include[s] a different payload each time"; and PING and PADDING,
    /// which "contain no information, so lost PING or PADDING frames do not require
    /// repair."</summary>
    Drop,
}

/// <summary>RFC 9000 s13.3's frame-by-frame retransmission rules, read out of
/// <c>rfc9000-section13.3-retransmission-of-information.txt</c> and encoded as a
/// table.</summary>
/// <remarks>
/// <para>A TABLE AND NOT A HEURISTIC. s13.3's bullets do not follow from any property of a
/// frame that this code could compute - PATH_CHALLENGE and NEW_CONNECTION_ID are both a fixed
/// run of opaque bytes the peer must see, and they land in different groups - so the only
/// correct implementation is a transcription, and the only way to check a transcription is to
/// quote the line each row came from. Every row below does.</para>
/// <para>NOTHING HERE THROWS, FOR ANY INPUT, INCLUDING A FRAME TYPE s13.3 NEVER HEARD OF. The
/// argument is a <see cref="TlsQuicFrame.Type"/>, derived from a wire varint, so it can be any
/// of s16's 2^62 values. An unlisted type is <see cref="TlsQuicRepairAction.Drop"/> and the
/// direction of that default is deliberate: s13.3 is an enumeration, so a type it does not name
/// is one this endpoint has no rule for, and putting bytes back on the wire under no rule is
/// the failure that cannot be taken back. Withholding them costs at most a repair the peer will
/// ask for again.</para>
/// <para>THE ONE TYPE THIS TREE CAN SEND THAT s13.3 DOES NOT COVER IS DATAGRAM, and it is named
/// rather than left to the default so that a reader does not take its absence for an oversight.
/// The value IS the default: RFC 9221 is the authority for that frame and it is NOT in this
/// repository's reference captures, so no rule for it can be quoted here.</para>
/// </remarks>
internal static class TlsQuicRetransmission
{
    /// <summary>Reads RFC 9000 s13.3's rule for one frame type.</summary>
    /// <param name="type">The s12.4 Table 3 base type, as <see cref="TlsQuicFrame.Type"/>
    /// derives it - so a STREAM frame's OFF, LEN and FIN bits and an ACK frame's ECN bit are
    /// already off.</param>
    /// <returns>What s13.3 says to do with that frame's information.</returns>
    internal static TlsQuicRepairAction ActionFor(TlsQuicFrameType type) => type switch
    {
        // "Data sent in CRYPTO frames is retransmitted according to the rules in
        // [QUIC-RECOVERY], until all data has been acknowledged." A byte range, so the repair
        // is a NEW frame carrying the same offset and the same bytes - see
        // TlsQuicPacketBuilder.cs:37-46 for why that range lives beside TlsQuicSentPacket
        // rather than on it.
        TlsQuicFrameType.Crypto => TlsQuicRepairAction.Refresh,

        // "Application data sent in STREAM frames is retransmitted in new STREAM frames unless
        // the endpoint has sent a RESET_STREAM for that stream." IN NEW STREAM FRAMES, in those
        // words, which is why this is Refresh and not Resend even though the bytes are the same
        // ones. The RESET_STREAM exception is stated at the one place that would have to
        // honour it - TlsQuicStreamSet.QueueRepair - rather than hidden in a row here.
        TlsQuicFrameType.Stream => TlsQuicRepairAction.Refresh,

        // "The current connection maximum data is sent in MAX_DATA frames. An updated value is
        // sent in a MAX_DATA frame if the packet containing the most recently sent MAX_DATA
        // frame is declared lost or when the endpoint decides to update the limit." AN UPDATED
        // VALUE: re-sending the lost frame's own number would be legal - "A receiver MUST accept
        // packets containing an outdated frame, such as a MAX_DATA frame carrying a smaller
        // maximum data value than one found in an older packet" - and would still be the wrong
        // half of the sentence.
        TlsQuicFrameType.MaxData => TlsQuicRepairAction.Refresh,

        // "The current maximum stream data offset is sent in MAX_STREAM_DATA frames. Like
        // MAX_DATA, an updated value is sent when the packet containing the most recent
        // MAX_STREAM_DATA frame for a stream is lost or when the limit is updated". AND THIS IS
        // THE ROW THAT IS A DEADLOCK RATHER THAN A DELAY - TlsQuicStreams.cs:120-126 wrote the
        // failure down before anything could repair it: "if the datagram carrying it is lost
        // the peer stops at the old limit, sends nothing more, and nothing on this side crosses
        // a threshold again - the two ends wait on each other."
        TlsQuicFrameType.MaxStreamData => TlsQuicRepairAction.Refresh,

        // "The limit on streams of a given type is sent in MAX_STREAMS frames. Like MAX_DATA,
        // an updated value is sent when a packet containing the most recent MAX_STREAMS for a
        // stream type frame is declared lost or when the limit is updated".
        TlsQuicFrameType.MaxStreams => TlsQuicRepairAction.Refresh,

        // "Blocked signals are carried in DATA_BLOCKED, STREAM_DATA_BLOCKED, and
        // STREAMS_BLOCKED frames ... A new frame is sent if a packet containing the most recent
        // frame for a scope is lost, but only while the endpoint is blocked on the
        // corresponding limit. These frames always include the limit that is causing blocking
        // at the time that they are transmitted." A NEW FRAME carrying the limit as it stands
        // when it is transmitted, which is Refresh's second shape exactly.
        TlsQuicFrameType.DataBlocked => TlsQuicRepairAction.Refresh,
        TlsQuicFrameType.StreamDataBlocked => TlsQuicRepairAction.Refresh,
        TlsQuicFrameType.StreamsBlocked => TlsQuicRepairAction.Refresh,

        // "Cancellation of stream transmission, as carried in a RESET_STREAM frame, is sent
        // until acknowledged or until all stream data is acknowledged by the peer ... The
        // content of a RESET_STREAM frame MUST NOT change when it is sent again." MUST NOT
        // CHANGE is the whole difference between this group and the one above it.
        TlsQuicFrameType.ResetStream => TlsQuicRepairAction.Resend,

        // "Similarly, a request to cancel stream transmission, as encoded in a STOP_SENDING
        // frame, is sent until the receiving part of the stream enters either a "Data Recvd" or
        // "Reset Recvd" state".
        TlsQuicFrameType.StopSending => TlsQuicRepairAction.Resend,

        // "New connection IDs are sent in NEW_CONNECTION_ID frames and retransmitted if the
        // packet containing them is lost. Retransmissions of this frame carry the same sequence
        // number value. Likewise, retired connection IDs are sent in RETIRE_CONNECTION_ID
        // frames and retransmitted if the packet containing them is lost."
        TlsQuicFrameType.NewConnectionId => TlsQuicRepairAction.Resend,
        TlsQuicFrameType.RetireConnectionId => TlsQuicRepairAction.Resend,

        // "NEW_TOKEN frames are retransmitted if the packet containing them is lost. No special
        // support is made for detecting reordered and duplicated NEW_TOKEN frames other than a
        // direct comparison of the frame contents."
        TlsQuicFrameType.NewToken => TlsQuicRepairAction.Resend,

        // "The HANDSHAKE_DONE frame MUST be retransmitted until it is acknowledged." The one
        // MUST in s13.3's whole frame list, and a server's obligation rather than a client's -
        // which is why this row is classified and not exercised by any send path here.
        TlsQuicFrameType.HandshakeDone => TlsQuicRepairAction.Resend,

        // "ACK frames carry the most recent set of acknowledgments and the acknowledgment delay
        // from the largest acknowledged packet, as described in Section 13.2.1. Delaying the
        // transmission of packets containing ACK frames or resending old ACK frames can cause
        // the peer to generate an inflated RTT sample or unnecessarily disable ECN." A LOST ACK
        // IS REPAIRED BY THE NEXT ACK, which TlsQuicAckTracker already builds from the ranges it
        // still holds; a repair here would be a second, stale, ACK writer.
        TlsQuicFrameType.Ack => TlsQuicRepairAction.Drop,

        // "Connection close signals, including packets that contain CONNECTION_CLOSE frames,
        // are not sent again when packet loss is detected. Resending these signals is described
        // in Section 10."
        TlsQuicFrameType.ConnectionClose => TlsQuicRepairAction.Drop,

        // "Responses to path validation using PATH_RESPONSE frames are sent just once. The peer
        // is expected to send more PATH_CHALLENGE frames as necessary to evoke additional
        // PATH_RESPONSE frames." THIS ROW UPGRADES A CITATION THIS TREE MARKED WEAK: the comment
        // beside PendingPathResponseData in TlsQuicApplicationSendPath.cs reads "NOT QUOTED,
        // BECAUSE s13.3 IS NOT IN THIS REPO'S REFERENCE CAPTURES". A3-0 landed the extract and
        // the sentence above is what it says.
        TlsQuicFrameType.PathResponse => TlsQuicRepairAction.Drop,

        // "A liveness or path validation check using PATH_CHALLENGE frames is sent periodically
        // until a matching PATH_RESPONSE frame is received or until there is no remaining need
        // for liveness or path validation checking. PATH_CHALLENGE frames include a different
        // payload each time they are sent." A DIFFERENT PAYLOAD EACH TIME, so re-sending the
        // lost one would violate the sentence that describes it. The repair is the periodic
        // schedule, which is not loss detection's and is not this task's.
        TlsQuicFrameType.PathChallenge => TlsQuicRepairAction.Drop,

        // "PING and PADDING frames contain no information, so lost PING or PADDING frames do
        // not require repair." One sentence covering both rows.
        TlsQuicFrameType.Ping => TlsQuicRepairAction.Drop,
        TlsQuicFrameType.Padding => TlsQuicRepairAction.Drop,

        // RFC 9221's frame, which RFC 9000 s13.3 does not mention because it postdates it. See
        // this type's remarks: the value is the default and the reason is that no rule for it
        // can be quoted from this repository's captures.
        TlsQuicFrameType.Datagram => TlsQuicRepairAction.Drop,

        // Every frame type s13.3 does not enumerate. See this type's remarks for why the
        // conservative direction is the safe one.
        _ => TlsQuicRepairAction.Drop,
    };
}
// ============================================================================
// TASK A3-8 - MUTATION LEDGER. 55 rows: 2 calibration + 17 the s13.3 table +
// 14 the ledger and the two queues + 9 the connection's call sites + 6 the stream set +
// 4 A3-10's persistent congestion + 3 A3-9's controller.
// 2 + 17 + 14 + 9 + 6 + 4 + 3 = 55. Killed 49, killed by the compiler 1, survived 5.
// 49 + 1 + 5 = 55.
// ============================================================================
//
// Swept in a private git worktree detached at fdf1b9d - pristine HEAD - because another task
// was editing TlsQuicCongestionControl.cs and TlsQuicRecoverySpec.cs in the shared tree while
// this one ran, and a sweep there would have been scoring their work. THE BASELINE WAS MEASURED
// IN THAT WORKTREE AND NOT INHERITED: 2334 passing at pristine fdf1b9d, 2373 after this task,
// 2373 - 2334 = 39 cases added (32 facts and one 7-row theory: 32 + 7 = 39).
//
// AND MEASURED AGAIN AT THE COMMIT THIS LANDS ON, because the branch moved twice while this task
// ran: 2367 passing at pristine 1e8b5e6, 2406 after this task, 2406 - 2367 = 39. The same 39,
// which is the corroboration - a change that had disturbed anything would not add the same
// number against two different baselines. The brief this task was given said the baseline was
// 2277; it was 2313 at the commit named there, and inheriting that figure rather than measuring
// it would have made every arithmetic claim in this block wrong by 36.
//
// EVERY ROW REBUILT --no-incremental AND THEN TESTED --no-build, as two commands. That is not
// decoration: `dotnet test --no-incremental` is NOT a valid switch - it fails with MSB1001 AND
// EXITS 0 - so a harness that passed it there would have scored every row against a stale
// assembly while reporting success. Verified here rather than assumed.
//
// KILLED-BY-COMPILER IS ASSIGNED STRUCTURALLY, from the build's exit code, before any test
// runs. A run executing fewer than 2371 cases was rejected as ABORTED rather than recorded, so
// a runner that died early could not be read as a survivor.
//
// THIS LEDGER IS ONE SWEEP OF ONE CODE STATE. An earlier sweep of an earlier state was
// discarded rather than stitched onto this one when the code changed under it, and a second was
// discarded when the host process died mid-row - which left a mutant applied in the worktree,
// caught by the gate rather than by inspection. Only comment text has changed since the sweep
// below, and comments cannot move a verdict.
//
// THE ROWS
//
//   CALIBRATION - 2 rows
//   A38-M01 an inert comment word changed .............. SURVIVED  the harness's own control.
//                                                                  It edits the file, compiles
//                                                                  and changes nothing, which
//                                                                  is what a survivor should
//                                                                  look like. NOT written as
//                                                                  `if (true)`: CS0162 is an
//                                                                  error here, so both constant
//                                                                  arms give KILLED-BY-COMPILER
//                                                                  and the control never runs.
//   A38-M02 the repair queue yields nothing ............ KILLED    5 tests, incl. the MsQuic one
//
//   RFC 9000 s13.3's TABLE - 17 rows (M03-M19)
//   A38-M03 CRYPTO -> Drop ............................. KILLED    16 tests
//   A38-M04 STREAM -> Drop ............................. KILLED    3 tests
//   A38-M05 MAX_STREAM_DATA -> Resend .................. KILLED    EveryFrameTypeIsInTheGroup
//   A38-M06 MAX_DATA -> Resend ......................... KILLED    EveryFrameTypeIsInTheGroup
//   A38-M07 MAX_STREAMS -> Resend ...................... KILLED    EveryFrameTypeIsInTheGroup
//   A38-M08 DATA_BLOCKED -> Drop ....................... KILLED    EveryFrameTypeIsInTheGroup
//   A38-M09 PATH_RESPONSE -> Resend .................... KILLED    2 tests
//   A38-M10 ACK -> Resend .............................. KILLED    3 tests
//   A38-M11 PING -> Resend ............................. KILLED    2 tests
//   A38-M12 PADDING -> Resend .......................... KILLED    2 tests
//   A38-M13 CONNECTION_CLOSE -> Resend ................. KILLED    2 tests
//   A38-M14 PATH_CHALLENGE -> Resend ................... KILLED    EveryFrameTypeIsInTheGroup
//   A38-M15 HANDSHAKE_DONE -> Drop ..................... KILLED    EveryFrameTypeIsInTheGroup
//   A38-M16 NEW_TOKEN -> Drop .......................... KILLED    2 tests
//   A38-M17 RESET_STREAM -> Refresh .................... KILLED    EveryFrameTypeIsInTheGroup
//   A38-M18 the unlisted default flips to Resend ....... KILLED    5 theory rows
//   A38-M19 the whole table collapses to one answer .... KILLED    10 tests
//
//   SEVEN OF THOSE SEVENTEEN ARE KILLED BY ONE TEST, AND THAT IS THE DESIGN RATHER THAN A
//   WEAKNESS. Resend and Refresh reach the same mechanism for every frame type except the two
//   flow-control grants, so a row that swaps them changes no behaviour this connection can
//   produce - only the CLASSIFICATION, which is exactly what
//   EveryFrameTypeIsInTheGroupTheCapturedSectionPutsItIn reads, and it reads it against the
//   sentence in the captured extract rather than against a retyped constant.
//
//   THE LEDGER AND THE TWO QUEUES - 14 rows (M20-M33)
//   A38-M20 RecordRepairable stops filtering ........... KILLED    2 tests
//   A38-M21 the defensive copy of Data deleted ......... KILLED    ARepairCarriesTheBytesAsThey
//                                                                  WereSent. SURVIVED the first
//                                                                  sweep; the field comment
//                                                                  called the copy "load-
//                                                                  bearing" with no test behind
//                                                                  it, so the test was written
//                                                                  and the sweep re-run.
//   A38-M22 a declared loss queues nothing ............. KILLED    14 tests
//   A38-M23 the duplicate check dropped ................ KILLED    InformationTwoLostPackets
//   A38-M24 the duplicate check ignores the offset ..... KILLED    TheSameBytesAtTwoOffsets
//   A38-M25 a lost grant is replayed, not refreshed .... KILLED    NoShapeOfRecordedFrame
//   A38-M26 the drain does not empty the queue ......... KILLED    RepairingARepairTerminates
//   A38-M27 the drain ignores s7's send gate ........... KILLED    ARepairIsWithheldWhile
//   A38-M28 a refused repair is discarded .............. KILLED    ARepairIsWithheldWhile
//   A38-M29 the gate is asked about zero bytes ......... KILLED    ARepairIsWithheldWhile
//   A38-M30 the probe carries no previously-sent data .. KILLED    4 tests
//   A38-M31 the probe never reaches into retention ..... KILLED    4 tests
//   A38-M32 the probe's full-datagram bound removed .... SURVIVED  UNWITNESSED. The bound is a
//                                                                  ceiling: reaching it needs a
//                                                                  repair queue summing past
//                                                                  s18.2's payload maximum,
//                                                                  which is fifty-odd lost
//                                                                  packets each carrying a
//                                                                  full CRYPTO frame. Nothing
//                                                                  in this gate approaches it,
//                                                                  and a test that built one
//                                                                  would be testing the
//                                                                  datagram builder's bound
//                                                                  rather than this one.
//   A38-M33 B.8's OnPacketsLost not raised ............. KILLED    3 tests
//
//   THE CONNECTION'S CALL SITES - 9 rows (M34-M42)
//   A38-M34 Forget leaves the ledger entry behind ...... SURVIVED  UNREACHABLE BY CONSTRUCTION,
//                                                                  and it corrected a comment.
//                                                                  Every reader of _repairable
//                                                                  looks up by the number of a
//                                                                  RETAINED packet, so an entry
//                                                                  a forgotten packet left
//                                                                  behind can never be read.
//                                                                  s13.3's "avoid retransmitting
//                                                                  information from packets once
//                                                                  they are acknowledged" is met
//                                                                  by the RemoveAt beside it,
//                                                                  not by this line; the line
//                                                                  bounds memory. The comment
//                                                                  claiming otherwise is fixed.
//   A38-M35 a key discard leaves the repairs owed ...... KILLED    RepairsOwedAtALevelDoNot
//   A38-M36 the answer stops draining repairs .......... KILLED    the MsQuic loss test
//   A38-M37 s13.3's priority inverted .................. KILLED    the MsQuic loss test
//   A38-M38 the opening flight records nothing ......... KILLED    ADroppedClientHelloIsRe
//                                                                  transmitted. SURVIVED the
//                                                                  first sweep - every other
//                                                                  repair test starts from a
//                                                                  handshake already past the
//                                                                  opening flight - so the
//                                                                  ClientHello test was written
//                                                                  and the sweep re-run.
//   A38-M39 the 1-RTT packet records nothing ........... KILLED    2 tests
//   A38-M40 the answer packets record nothing .......... KILLED    4 tests
//   A38-M41 the probe stops carrying s6.2.4's data ..... KILLED    4 tests
//   A38-M42 B.4's OnPacketSentCC not raised ............ KILLED    2 tests
//
//   THE STREAM SET - 6 rows (M43-M48)
//   A38-M43 the grant repair replays the stream limit .. KILLED    ALostMaximumStreamData
//   A38-M44 the grant repair replays the conn limit .... KILLED    ALostMaximumDataGrant
//   A38-M45 s13.3's Size Known SHOULD ignored .......... KILLED    AGrantIsNotRepairedOnce
//   A38-M46 the 1-RTT drain puts repairs after new data  KILLED    RepairsLeaveTheOneRttDrain
//   A38-M47 the 1-RTT drain discards the repairs ....... KILLED    3 tests
//   A38-M48 HasPendingFrames stops seeing the repairs .. SURVIVED  UNREACHABLE BY CONSTRUCTION.
//                                                                  The property has no
//                                                                  production caller at all -
//                                                                  grep returns tests only - so
//                                                                  no send decision depends on
//                                                                  it and no test of it could
//                                                                  witness live behaviour. The
//                                                                  test comment that claimed a
//                                                                  send path reads it is fixed.
//           SUPERSEDED BY TASK A3-11 - THE PREMISE WENT, AND THE ROW IS RE-RUN RATHER THAN LEFT
//           STANDING ON IT. "No production caller at all" stopped being true the moment
//           TryBuildApplicationPacket started asking HasPendingFrames before consulting RFC 9002
//           s7's send gate: the property IS a send decision now, because it is what keeps an
//           ACK-only pass from spending the pacer's credit and arming a pacing deadline for a
//           datagram that does not exist. A3-11's ledger re-runs this mutation as A311-M29 and
//           records the verdict there; the classification above is correct for A3-8's tree and
//           wrong for this one, which is why it is annotated rather than edited.
//
//   A3-10's PERSISTENT CONGESTION - 4 rows (M49-M52)
//   A38-M49 A.7's !lost_packets.empty() guard dropped .. KILLED    2 blackout tests. THE ROW
//                                                                  THAT FOUND A REAL DEFECT:
//                                                                  the guard was missing from
//                                                                  the first draft, and the
//                                                                  blackout test caught it by
//                                                                  asserting WHICH seam members
//                                                                  were called rather than only
//                                                                  that the window moved.
//   A38-M50 OnPersistentCongestion never called ........ KILLED    ABlackoutLongerThan
//   A38-M51 s7.6's anchor moves BEFORE the loss pass ... KILLED    ABlackoutLongerThan. This is
//                                                                  the ordering defect the live
//                                                                  wiring would otherwise have
//                                                                  shipped: the ACK that
//                                                                  declares a blackout lost is
//                                                                  necessarily for a packet
//                                                                  sent AFTER it, so folding it
//                                                                  into the anchor first
//                                                                  discards every candidate and
//                                                                  s7.6 could never fire.
//   A38-M52 s7.6's anchor stops being monotonic ........ SURVIVED  UNWITNESSED. Witnessing it
//                                                                  needs an ACK that newly
//                                                                  acknowledges a STRICTLY
//                                                                  OLDER packet after a newer
//                                                                  one - legal under s19.3's
//                                                                  ranges - followed by a
//                                                                  blackout straddling the two.
//                                                                  Reachable but obscure, and
//                                                                  named here rather than left
//                                                                  as an unexplained green.
//
//   A3-9's CONTROLLER - 3 rows (M53-M55)
//   A38-M53 knob 4 re-invoked per call ................. KILLED-BY-COMPILER
//   A38-M54 B.5's OnPacketsAcked not raised ............ KILLED    2 tests
//   A38-M55 B.9's OnPacketsDiscarded not raised ........ KILLED    AKeyDiscardTakesItsPackets
//
// THREE ROWS FOUND SOMETHING RATHER THAN CONFIRMING IT, which is the only reason to run a
// sweep at all: M21 and M38 were survivors whose comments claimed load-bearing behaviour with
// no test behind them, and M49 was a missing guard. All three are now killed.
