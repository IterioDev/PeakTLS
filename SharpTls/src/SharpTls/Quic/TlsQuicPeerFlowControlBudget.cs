namespace SharpTls.Quic;

// ============================================================================
// THE PEER'S SIX FLOW-CONTROL LIMITS, RETAINED, AND THE STATIC BUDGET THEY BOUND.
// ============================================================================
//
// Task 14d of A4-minimal, closing the C-scoping plan's Finding 6. Before this file
// TlsQuicConnection.ApplyPeerTransportParametersAsync read exactly ONE parameter off the
// peer's set - max_idle_timeout (0x01) - and the six flow-control limits were parsed,
// addressable through TlsQuicTransportParameters.Get, and then dropped on the floor. A4
// task 14's promise that "flow control is a static budget taken from the peer's advertised
// initial limits" had nothing to read.
//
// WHY THIS IS ITS OWN FILE. A4's file-size constraint caps TlsQuicConnection.cs at 1000 code
// lines through task 14 - the measurement is `grep -vcE '^\s*(//|$)'`, per file - and that
// file stood at 960 when this task began. Unlike task 14c's send path this is NOT the shared
// mutable connection state TlsQuicApplicationSendPath.cs's remarks defend: nothing here reads
// or writes _keys, _acks, _nextPacketNumber or _destinationConnectionId, so it does not need
// to be a partial of TlsQuicConnection at all. A plain internal type is the honest split and
// it leaves the connection's remaining line budget to task 14e.
//
// ============================================================================
// THE DATA LIMITS GROW; THE STREAM COUNTS STILL DO NOT.
// ============================================================================
//
// This file shipped with a budget fixed at the peer's advertised transport parameters that
// NEVER GREW, and the ~6 MB request-body ceiling that produced was the whole reason for the
// A4-complete task that changed it. The two DATA limits now move:
//
//   - initial_max_data (0x04) is raised by a received MAX_DATA (RFC 9000 s19.9) through
//     TryRaiseConnectionLimit, and ConnectionLimit is the value in force.
//   - the per-stream limit is raised by a received MAX_STREAM_DATA (s19.10) through
//     TlsQuicStreamBudget.TryRaiseLimit.
//
// Both are running MAXIMA - a stale, smaller grant is discarded rather than obeyed - and each
// method's remarks quote the sentence it is built on, including the one place s19.9 is silent
// and the reading had to be chosen and pinned.
//
// THE TWO STREAM COUNTS ARE STILL STATIC. Nothing here handles a MAX_STREAMS frame (s19.11)
// or sends a STREAMS_BLOCKED (s19.14), so OpenUnidirectionalStream and OpenBidirectionalStream
// still throw when the peer's advertised count is spent and their messages still say so. That
// is a scope cut and not an oversight: this task removed the BYTE ceiling.
//
// ============================================================================
// ABSENT AND ZERO ARE THE SAME VALUE FOR ALL SIX, AND THE TASK BRIEF SAID OTHERWISE.
// ============================================================================
//
// The brief for this task asserted that "s18.2's limits have defaults when absent that differ
// from an explicit 0". For these six that is FALSE, and reference-captures/
// rfc9000-section18-transport-parameters.txt says so three separate times:
//
//   - line 62-64, the blanket rule that governs unless a parameter overrides it: "Transport
//     parameters have a default value of 0 if the transport parameter is absent, unless
//     otherwise stated." None of the six states otherwise.
//   - lines 139 and 148, for the two stream-count limits, which fold the two cases into one
//     sentence: "If this parameter is absent or zero, the peer cannot open bidirectional
//     streams until a MAX_STREAMS frame is sent" (and the same for unidirectional).
//   - lines 250-252, past the wrap, for the three per-stream data limits: "If the transport
//     parameter is absent, streams of that type start with a flow control limit of 0."
//
// The parameters that DO carry a non-zero absent default are the four this task does not
// touch - max_udp_payload_size (65527), ack_delay_exponent (3), max_ack_delay (25 ms) and
// active_connection_id_limit (2) - and reading the brief's warning onto the six would have
// invented four defaults the RFC does not grant.
//
// SO THE DISTINCTION IS NOT DISCARDED, IT IS RESOLVED THE WAY s18.2 RESOLVES IT: absent reads
// as 0 rather than as "unknown, therefore permissive". A peer that omits initial_max_streams_uni
// has NOT advertised an unbounded stream allowance, and it fails RequiredUnidirectionalStreams
// below for exactly the same reason an explicit 0 does. Witnessed by
// AnAbsentFlowControlLimitReadsAsZeroExactlyLikeAnExplicitZero and by
// AnAbsentInitialMaxStreamsUniFailsSection62ExactlyLikeAnExplicitZero.
//
// ============================================================================
// 0x05 AND 0x06 ARE NAMED FROM THE SENDER'S SIDE AND APPLY FROM OURS.
// ============================================================================
//
// The six properties below carry their WIRE names, because that is the only naming under
// which "did parameter 0x06 reach the budget?" is a question with one answer. The
// perspective flip lives in exactly one place - the three Open/Accept methods - and s18.2
// states it twice, in the two paragraphs a reader is most likely to conflate:
//
//   - initial_max_stream_data_bidi_local (0x05) "applies to newly created bidirectional
//     streams opened by the endpoint that SENDS the transport parameter" (extract lines
//     110-111). We are the client; the peer sends it; so 0x05 bounds what we may send on a
//     SERVER-initiated bidirectional stream.
//   - initial_max_stream_data_bidi_remote (0x06) "applies to newly created bidirectional
//     streams opened by the endpoint that RECEIVES the transport parameter" (lines 120-121).
//     We receive it, so 0x06 - not 0x05 - is the limit on the request streams WE open.
//
// Taking 0x05 for our own request stream is the single most likely defect in this file and it
// would be invisible against any peer that advertises the two equally. Witnessed by
// AnOutgoingBidirectionalStreamTakesItsLimitFromBidiRemoteAndNotBidiLocal.
//
// ============================================================================
// THE MUTATION LEDGER
// ============================================================================
//
//   ROWS BELOW                   23  = numbered 1-23 with no gaps
//   KILLED WHEN FIRST RUN        23  = 23 rows, less 0 [WAS-SURVIVOR] and 0 [SURVIVED]
//   SURVIVED, THEN FIXED OR       0
//     WITNESSED
//   SURVIVING STILL               0
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' TlsQuicPeerFlowControlBudget.cs`                    must return 23
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicPeerFlowControlBudget.cs`   must return 0
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' TlsQuicPeerFlowControlBudget.cs`       must return 0
//
// ALL TWENTY-THREE WERE RUN AGAINST TASK 14d's 1166-CASE GATE, in one sweep, in a git
// worktree that was removed afterwards. Counts are per xUnit CASE, so a six-row Theory failing
// in five of them counts 5. NOT ONE SURVIVED, which is the first sweep in this phase with no
// survivor at all and is worth reading sceptically rather than proudly: it is what a file
// whose entire content is six reads and four guards should produce, and the interesting
// figures are not the kills but the SHAPES - rows 1-7 each kill their own named witness and
// no other read's, rows 9 and 11 kill exactly one test each, and rows 19 and 21 kill only the
// connection-level test while rows 18 and 20 kill only the per-stream ones.
//
// THE MUTATIONS THAT EDIT TlsQuicConnection.cs ARE IN ITS LEDGER (its new rows 93-97) and the
// one that edits TlsQuicConnectionOptions.cs is in that file's. One ledger per file, so that
// each file's three greps stay about that file.
//
// WHERE A ROW SAYS ONLY, that test was the entire failure set.
//
// ---- the six reads, one row each ----
//    1. initial_max_data (0x04) never read       9 tests
//    2. initial_max_stream_data_bidi_local (0x05) never read  7 tests
//    3. initial_max_stream_data_bidi_remote (0x06) never read  7 tests
//    4. initial_max_stream_data_uni (0x07) never read  11 tests
//    5. initial_max_streams_bidi (0x08) never read  9 tests
//    6. initial_max_streams_uni (0x09) never read  50 tests
//    7. 0x05 and 0x06 swapped at the read        10 tests
//
// ROW 6 IS THE ONE THAT LOOKS WRONG AND IS NOT. Fifty is an order of magnitude above rows 1-5
// because a peer whose initial_max_streams_uni reads as 0 fails s6.2, so every handshake in
// the suite is refused - which is the check doing its job, not the witness being coarse.
// InitialMaxStreamsUniReachesTheBudget is still in that fifty, and rows 9-11 are the ones
// that separate "the parameter was read" from "the floor was applied".
//
// ROW 7 IS THE SWAP, AND ITS TEN ARE THE PROOF THAT NO SINGLE TEST COVERS IT. The four that
// name a direction - InitialMaxStreamDataBidiLocalReachesTheBudget,
// InitialMaxStreamDataBidiRemoteReachesTheBudget,
// AnOutgoingBidirectionalStreamTakesItsLimitFromBidiRemoteAndNotBidiLocal and
// AnIncomingBidirectionalStreamTakesItsLimitFromBidiLocal - all four fail together and none of
// the other four reads' witnesses does. Against a peer advertising 0x05 and 0x06 equally the
// row would kill nothing at all.
//
// ---- s18.2's absent case, and s6.2's floor ----
//    8. an absent limit reads as unlimited instead of s18.2's 0  7 tests
//    9. the s6.2 floor is exclusive: >= becomes >  2 tests
//   10. the s6.2 check never fires               4 tests
//   11. the s6.2 check ignores the option and hard-codes 3  ONLY ACallerThatDoesNotSpeakHttp3CanLowerTheSection62Floor
//
// ROW 9 IS WHY THE BOUNDARY TEST EXISTS. s6.2 says "at least three", so a peer advertising
// exactly three conforms; every other peer in the suite advertises nine, and without
// AServerAdvertisingExactlyThreeUnidirectionalStreamsIsAccepted this off-by-one is invisible.
// ROW 11 IS WHY THE OPTION IS NOT A CONSTANT: with 3 hard-coded the whole suite is green
// except the one test that lowers the floor.
//
// ---- the budget is spent ----
//   12. the uni stream-count exhaustion guard never fires  ONLY OpeningMoreUnidirectionalStreamsThanThePeerAllowedFailsRatherThanExceedingIt
//   13. opening a uni stream spends nothing      ONLY OpeningMoreUnidirectionalStreamsThanThePeerAllowedFailsRatherThanExceedingIt
//   14. the bidi stream-count exhaustion guard never fires  ONLY OpeningMoreBidirectionalStreamsThanThePeerAllowedFailsRatherThanExceedingIt
//   15. our own bidi stream takes 0x05 instead of 0x06  ONLY AnOutgoingBidirectionalStreamTakesItsLimitFromBidiRemoteAndNotBidiLocal
//   16. a peer-opened bidi stream takes 0x06 instead of 0x05  ONLY AnIncomingBidirectionalStreamTakesItsLimitFromBidiLocal
//   17. a uni stream takes initial_max_data instead of 0x07  3 tests
//   18. the per-stream data guard never fires    2 tests
//   19. only the stream is charged, never the connection  ONLY SendingPastTheConnectionLimitFailsEvenWhenEveryStreamFitsItsOwn
//   20. the per-stream guard is off by one: > becomes >=  2 tests
//   21. the connection-level guard never fires   ONLY SendingPastTheConnectionLimitFailsEvenWhenEveryStreamFitsItsOwn
//   22. the connection is charged before the stream guard runs  2 tests
//   23. accepting a peer-opened stream spends our own bidi allowance  ONLY AcceptingAPeerOpenedStreamSpendsNoneOfOurOwnStreamAllowance
//
// ============================================================================
// THE A4-COMPLETE MUTATION LEDGER - THE LIMITS THAT NOW GROW, SEPARATELY PREFIXED
// ============================================================================
//
//   ROWS BELOW                    9  = numbered A4C-01 to A4C-09 with no gaps
//   KILLED WHEN FIRST RUN         8  = 9 rows, less 1 [WAS-SURVIVOR] and 0 [SURVIVED]
//   SURVIVED, THEN WITNESSED      1  = row A4C-04
//   SURVIVING STILL               0
//
// Three greps, anchored to the A4C prefix so they neither match these lines nor collide with
// the 1-23 ledger above. Run from this file's directory:
//   `grep -cE '^// +A4C-[0-9]+\. ' TlsQuicPeerFlowControlBudget.cs`                  = 9
//   `grep -cE '^// +A4C-[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicPeerFlowControlBudget.cs` = 1
//   `grep -cE '^// +A4C-[0-9]+\..*\[SURVIVED\]' TlsQuicPeerFlowControlBudget.cs`     = 0
//
// RUN BY mutate-maxdata.py IN A PRIVATE WORKTREE, one mutation at a time, each built with
// `dotnet build --no-incremental` and then gated with `dotnet test --no-build --filter
// FullyQualifiedName~Quic`. KILLED-BY-COMPILER is assigned STRUCTURALLY from the build's exit
// code and never by reading its text; the gate's exit code is read directly rather than
// through a pipe, because a pipeline's exit code is the last command's. Every run is checked
// against a case floor of 2,400 - a run below it is a broken harness, not a kill - and all
// nine saw 2,473 cases on the first sweep and 2,475 on the re-run. Counts are per xUnit CASE.
//
// TWO CALIBRATION ROWS RAN IN THE SAME SWEEP AND BOTH DIED, which is what makes a zero here
// mean "nothing to find" rather than "nothing measured": `budget.Consume((ulong)chunk.Length)`
// to `Consume(0)` killed 9, and `_remainingConnectionData -= bytes` to `-= 0` killed 5.
//
// ---- the per-stream limit ----
//   A4C-01. TryRaiseLimit: `<=` becomes `<`, so an equal grant reports movement  1 test
//   A4C-02. the new limit is ASSIGNED to _remaining, refunding every byte already sent  4 tests
//   A4C-03. the limit moves but no credit is added  8 tests
//
// ---- the connection-level limit ----
//   A4C-04. [WAS-SURVIVOR] TryRaiseConnectionLimit: `<=` becomes `<`  1 test
//   A4C-05. the new limit is ASSIGNED to _remainingConnectionData  1 test
//   A4C-06. the raise happens but returns false, so nothing drains on it  5 tests
//   A4C-09. ConnectionLimit starts at 0 instead of initial_max_data  2 tests
//
// ---- Available, which is where the two meet ----
//   A4C-07. Available reads only the stream's credit  3 tests
//   A4C-08. Available reads only the connection's pool  8 tests
//
// A4C-04 IS THE ONE THAT SURVIVED AND IT IS THE MOST INSTRUCTIVE ROW IN THIS FILE. Its stream
// twin A4C-01 died immediately because AStaleOrEqualMaxStreamDataNeitherShrinksTheWindowNor
// ReportsMovement is a Theory whose third row replays the CURRENT limit; the connection test
// beside it replayed only a strictly SMALLER one, so `<=` and `<` were indistinguishable and
// the whole 2,473-case gate stayed green. The fix is three lines in
// AStaleSmallerMaxDataIsIgnoredAndTheAlternativeReadingIsNamed, and the lesson is that a
// boundary needs the boundary VALUE and not merely a value on the far side of it.
//
// A4C-07 AND A4C-08 ARE THE PAIR THAT PROVES BOTH LIMITS ARE READ, and their counts differ by
// design rather than by luck: dropping the connection term (07) is invisible to every test
// whose connection pool is roomy, while dropping the stream term (08) breaks every test whose
// per-stream limit is the tight one - which, in a suite written around a per-stream ceiling,
// is most of them.

// ROWS 19 AND 21 ARE THE PAIR THE TWO-LEVEL SCHEME NEEDS, and each is killed by exactly one
// test - the one whose three streams each fit their own limit and exhaust initial_max_data
// between them. A suite that tested only "sending too much fails" would have let both live.
// ROW 22 IS THE ORDER-OF-OPERATIONS ONE: charging the connection before the per-stream guard
// leaks credit on every refusal, leaves the exception type and message unchanged, and is
// visible only in ARefusedSendMovesNeitherCounter's state assertions afterwards.

/// <summary>The peer's six advertised RFC 9000 s18.2 flow-control limits, and the
/// connection-level and per-stream send budget they open. The two DATA limits grow with every
/// larger MAX_DATA (s19.9) and MAX_STREAM_DATA (s19.10) received; the two stream COUNTS remain
/// static, because nothing here handles a MAX_STREAMS frame.</summary>
internal sealed class TlsQuicPeerFlowControlBudget
{
    private ulong _remainingConnectionData;
    private ulong _remainingBidirectionalStreams;
    private ulong _remainingUnidirectionalStreams;

    private TlsQuicPeerFlowControlBudget(TlsQuicTransportParameters parameters)
    {
        InitialMaxData = Limit(parameters, TlsQuicTransportParameterId.InitialMaxData);
        InitialMaxStreamDataBidiLocal = Limit(
            parameters, TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal);
        InitialMaxStreamDataBidiRemote = Limit(
            parameters, TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote);
        InitialMaxStreamDataUni = Limit(
            parameters, TlsQuicTransportParameterId.InitialMaxStreamDataUni);
        InitialMaxStreamsBidi = Limit(
            parameters, TlsQuicTransportParameterId.InitialMaxStreamsBidi);
        InitialMaxStreamsUni = Limit(
            parameters, TlsQuicTransportParameterId.InitialMaxStreamsUni);

        _remainingConnectionData = InitialMaxData;
        ConnectionLimit = InitialMaxData;
        _remainingBidirectionalStreams = InitialMaxStreamsBidi;
        _remainingUnidirectionalStreams = InitialMaxStreamsUni;
    }

    /// <summary>RFC 9114 s6.2's floor: "the transport parameters sent by both clients and
    /// servers MUST allow the peer to create at least three unidirectional streams" - the
    /// HTTP control stream plus QPACK's encoder and decoder.</summary>
    internal const ulong Http3RequiredUnidirectionalStreams = 3;

    /// <summary>RFC 9114 s6.2's next sentence, and it is a SHOULD rather than a MUST: "These
    /// transport parameters SHOULD also provide at least 1,024 bytes of flow-control credit
    /// to each unidirectional stream." Nothing rejects a peer below it - a SHOULD is not a
    /// failure - and this constant exists so the number is stated once and is reachable by a
    /// test that pins the non-enforcement.</summary>
    internal const ulong Http3RecommendedUnidirectionalStreamCredit = 1024;

    /// <summary>Gets initial_max_data (0x04): the connection-level limit on everything we
    /// send across every stream combined.</summary>
    internal ulong InitialMaxData { get; }

    /// <summary>Gets initial_max_stream_data_bidi_local (0x05). Sender's perspective: it
    /// bounds streams the PEER opens, so from ours it bounds what we may send on a
    /// server-initiated bidirectional stream.</summary>
    internal ulong InitialMaxStreamDataBidiLocal { get; }

    /// <summary>Gets initial_max_stream_data_bidi_remote (0x06). It bounds streams the
    /// receiver of the parameter opens, so it bounds the request streams WE open.</summary>
    internal ulong InitialMaxStreamDataBidiRemote { get; }

    /// <summary>Gets initial_max_stream_data_uni (0x07): the per-stream limit on each
    /// unidirectional stream we open - HTTP/3's control, QPACK encoder and QPACK decoder
    /// streams.</summary>
    internal ulong InitialMaxStreamDataUni { get; }

    /// <summary>Gets initial_max_streams_bidi (0x08): how many bidirectional streams we may
    /// open at all.</summary>
    internal ulong InitialMaxStreamsBidi { get; }

    /// <summary>Gets initial_max_streams_uni (0x09): how many unidirectional streams we may
    /// open at all. RFC 9114 s6.2 requires at least three of them for HTTP/3.</summary>
    internal ulong InitialMaxStreamsUni { get; }

    /// <summary>Gets the connection-level credit not yet spent.</summary>
    internal ulong RemainingConnectionData => _remainingConnectionData;

    /// <summary>Gets the connection-level limit currently in force: initial_max_data (0x04),
    /// raised by every larger MAX_DATA since.</summary>
    /// <remarks>SEPARATE FROM <see cref="InitialMaxData"/> RATHER THAN REPLACING IT, because
    /// that property is named for what the peer ADVERTISED and two callers read it as exactly
    /// that - the RFC 9114 request pre-flight and this file's own refusal messages. A property
    /// called "initial" that moved would make both of them lie.</remarks>
    internal ulong ConnectionLimit { get; private set; }

    /// <summary>Raises the connection-level limit to <paramref name="maximumData"/>, crediting
    /// the difference, and reports whether the window actually moved.</summary>
    /// <remarks>
    /// <para>A SMALLER VALUE IS IGNORED, AND s19.9 DOES NOT SAY SO IN SO MANY WORDS. This is
    /// the one place in this task where the extract had to be read against itself, so the
    /// reading is recorded rather than assumed. rfc9000-section19-frame-formats.txt s19.9 has
    /// no "largest" and no ignore-rule at all: its strongest sentence is "An endpoint MUST
    /// terminate a connection with an error of type FLOW_CONTROL_ERROR if it receives more
    /// data than the maximum data value that it has sent", which a stale lower MAX_DATA also
    /// satisfies. s19.10 DOES carry the word - "the LARGEST maximum stream data value
    /// advertised by the receiver" - and s19.11 spells the rule out as a MUST for MAX_STREAMS
    /// together with its cause, "Loss or reordering can cause an endpoint to receive a
    /// MAX_STREAMS frame with a lower stream limit than was previously received."
    /// <para>THE RUNNING MAXIMUM IS FOLLOWED FOR MAX_DATA TOO, on s19.11's stated cause rather
    /// than on s19.9's silence: the reordering that produces a stale MAX_STREAMS produces a
    /// stale MAX_DATA on the same wire, and the alternative reading - obey the latest value -
    /// would shrink a window the peer never meant to shrink and strand bytes already granted.
    /// The other candidate is pinned rather than argued: see
    /// AStaleSmallerMaxDataIsIgnoredAndTheAlternativeReadingIsNamed, which asserts the
    /// remaining credit under BOTH readings so that a future change of mind is a test edit and
    /// not a silent behaviour change.</para></para>
    /// <para>Overflow-free and delta-credited for the reasons
    /// <see cref="TlsQuicStreamBudget.TryRaiseLimit"/> gives.</para>
    /// </remarks>
    internal bool TryRaiseConnectionLimit(ulong maximumData)
    {
        if (maximumData <= ConnectionLimit)
        {
            return false;
        }

        _remainingConnectionData += maximumData - ConnectionLimit;
        ConnectionLimit = maximumData;
        return true;
    }

    /// <summary>Gets the unidirectional stream openings not yet spent.</summary>
    internal ulong RemainingUnidirectionalStreams => _remainingUnidirectionalStreams;

    /// <summary>Gets the bidirectional stream openings not yet spent.</summary>
    internal ulong RemainingBidirectionalStreams => _remainingBidirectionalStreams;

    /// <summary>Reads the peer's six s18.2 flow-control limits. An absent parameter reads as
    /// 0, which is s18.2's own default and not a stand-in for "unknown".</summary>
    /// <exception cref="ArgumentNullException"><paramref name="parameters"/> is
    /// <see langword="null"/>.</exception>
    internal static TlsQuicPeerFlowControlBudget FromPeerParameters(
        TlsQuicTransportParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        return new TlsQuicPeerFlowControlBudget(parameters);
    }

    /// <summary>Describes an RFC 9114 s6.2 violation in the peer's advertised unidirectional
    /// stream allowance, or returns <see langword="null"/> when the peer conforms.</summary>
    /// <remarks>A separate method rather than a constructor check because the connection has
    /// to CLOSE before it throws, and the budget knows nothing about closing. Returning the
    /// detail string keeps the whole RFC 9114 citation in this file, next to the constant it
    /// cites.</remarks>
    internal string? DescribeSection62Violation(ulong required)
    {
        if (InitialMaxStreamsUni >= required)
        {
            return null;
        }

        // The count is not arbitrary and the message says where it comes from, because the
        // alternative is a reader assuming 3 is a tuning knob. reference-captures/
        // rfc9114-section6-stream-mapping-and-usage.txt lines 101-108, read past the wrap
        // after "at least three": "Each endpoint needs to create at least one unidirectional
        // stream for the HTTP control stream.  QPACK requires two additional unidirectional
        // streams, and other extensions might require further streams.  Therefore, the
        // transport parameters sent by both clients and servers MUST allow the peer to create
        // at least three unidirectional streams."
        return "RFC 9114 s6.2 requires that \"the transport parameters sent by both clients "
            + "and servers MUST allow the peer to create at least three unidirectional "
            + $"streams\" - the HTTP control stream and QPACK's encoder and decoder - and the "
            + $"peer advertised initial_max_streams_uni (0x09) of {InitialMaxStreamsUni} "
            + $"against the {required} this connection needs. A client that opened the three "
            + "anyway would exceed a limit the peer never granted and then wait forever for a "
            + "MAX_STREAMS this phase does not handle, so the attempt ends here instead.";
    }

    /// <summary>Spends one unidirectional stream opening and returns that stream's own
    /// budget, taken from initial_max_stream_data_uni (0x07).</summary>
    /// <remarks>THE ALLOWANCE DOES NOT REPLENISH. A4-minimal handles no MAX_STREAMS frame
    /// (RFC 9000 s19.11) and sends no STREAMS_BLOCKED (s19.14), so once
    /// initial_max_streams_uni openings are spent there is no path by which more become
    /// available - that is A4-complete's. Throwing here is the whole point: it is the
    /// alternative to opening a stream the peer never permitted.</remarks>
    /// <exception cref="InvalidOperationException">The peer's initial_max_streams_uni is
    /// exhausted.</exception>
    internal TlsQuicStreamBudget OpenUnidirectionalStream()
    {
        if (_remainingUnidirectionalStreams == 0)
        {
            throw new InvalidOperationException(
                "The peer's initial_max_streams_uni (0x09) allowance of "
                    + $"{InitialMaxStreamsUni} unidirectional stream(s) is exhausted. This "
                    + "budget is static: A4-minimal handles no MAX_STREAMS frame, so nothing "
                    + "will raise it.");
        }

        _remainingUnidirectionalStreams--;
        return new TlsQuicStreamBudget(this, InitialMaxStreamDataUni, "initial_max_stream_data_uni (0x07)");
    }

    /// <summary>Spends one bidirectional stream opening and returns that stream's own budget,
    /// taken from initial_max_stream_data_bidi_REMOTE (0x06) - the parameter s18.2 scopes to
    /// streams opened by the endpoint that receives it, which is us.</summary>
    /// <remarks>Static for the same reason <see cref="OpenUnidirectionalStream"/> is.</remarks>
    /// <exception cref="InvalidOperationException">The peer's initial_max_streams_bidi is
    /// exhausted.</exception>
    internal TlsQuicStreamBudget OpenBidirectionalStream()
    {
        if (_remainingBidirectionalStreams == 0)
        {
            throw new InvalidOperationException(
                "The peer's initial_max_streams_bidi (0x08) allowance of "
                    + $"{InitialMaxStreamsBidi} bidirectional stream(s) is exhausted. This "
                    + "budget is static: A4-minimal handles no MAX_STREAMS frame, so nothing "
                    + "will raise it.");
        }

        _remainingBidirectionalStreams--;
        return new TlsQuicStreamBudget(
            this, InitialMaxStreamDataBidiRemote, "initial_max_stream_data_bidi_remote (0x06)");
    }

    /// <summary>Returns the send budget for a bidirectional stream the PEER opened, taken
    /// from initial_max_stream_data_bidi_local (0x05).</summary>
    /// <remarks>Spends no stream-count allowance: initial_max_streams_bidi bounds the streams
    /// WE open, and a peer-opened stream is spent against the allowance we advertised to
    /// it.</remarks>
    internal TlsQuicStreamBudget AcceptBidirectionalStream() => new(
        this, InitialMaxStreamDataBidiLocal, "initial_max_stream_data_bidi_local (0x05)");

    // Spends connection-level credit. Private because a caller with no stream has nothing to
    // spend it on - RFC 9000 s4.1 counts only STREAM frame data against initial_max_data - so
    // every path in reaches it through TlsQuicStreamBudget.Consume, which charges both limits
    // in the one place they can disagree.
    private void ConsumeConnectionData(ulong bytes, string streamLimitName)
    {
        if (bytes > _remainingConnectionData)
        {
            throw new InvalidOperationException(
                $"Sending {bytes} byte(s) against {streamLimitName} would exceed the peer's "
                    + $"initial_max_data (0x04) of {InitialMaxData} raised to "
                    + $"{ConnectionLimit} by MAX_DATA, of which {_remainingConnectionData} "
                    + "remain. A caller with more bytes than credit must queue the excess "
                    + "against TlsQuicStreamBudget.Available and let a MAX_DATA release it, "
                    + "not hand them here.");
        }

        _remainingConnectionData -= bytes;
    }

    private static ulong Limit(
        TlsQuicTransportParameters parameters, TlsQuicTransportParameterId id) =>
        parameters.Get((ulong)id)?.GetVariableInteger() ?? 0;

    /// <summary>One stream's share of the peer's static budget: its own s18.2 per-stream
    /// limit, charged together with the connection-level initial_max_data.</summary>
    internal sealed class TlsQuicStreamBudget
    {
        private readonly TlsQuicPeerFlowControlBudget _connection;
        private readonly string _limitName;
        private ulong _remaining;

        internal TlsQuicStreamBudget(
            TlsQuicPeerFlowControlBudget connection, ulong limit, string limitName)
        {
            _connection = connection;
            Limit = limit;
            _limitName = limitName;
            _remaining = limit;
        }

        /// <summary>Gets the per-stream limit currently in force: the s18.2 parameter this
        /// stream was opened under, raised by every larger MAX_STREAM_DATA since.</summary>
        internal ulong Limit { get; private set; }

        /// <summary>Gets this stream's credit not yet spent.</summary>
        internal ulong Remaining => _remaining;

        /// <summary>Gets the bytes that may be sent on this stream RIGHT NOW: the smaller of
        /// this stream's own credit and the connection-level pool it shares.</summary>
        /// <remarks>RFC 9000 s19.9 and s19.10 are two limits and not one, and a sender is
        /// bound by BOTH - s19.9's "All data sent in STREAM frames counts toward this limit"
        /// applies to the same bytes s19.10's "The data sent on a stream MUST NOT exceed the
        /// largest maximum stream data value advertised by the receiver" applies to. The
        /// minimum is the only value that satisfies both, and reading either one alone is the
        /// defect <see cref="Consume"/>'s two guards exist to catch.</remarks>
        internal ulong Available =>
            Math.Min(_remaining, _connection._remainingConnectionData);

        /// <summary>Raises this stream's limit to <paramref name="maximumStreamData"/>,
        /// crediting the difference, and reports whether the window actually moved.</summary>
        /// <remarks>
        /// <para>A SMALLER VALUE IS IGNORED, AND s19.10 IS WHERE THAT COMES FROM. The extract
        /// rfc9000-section19-frame-formats.txt line 511, read past the wrap: "The data sent on
        /// a stream MUST NOT exceed the LARGEST maximum stream data value advertised by the
        /// receiver." Largest, not latest - so the window is the running maximum, and a
        /// MAX_STREAM_DATA that arrives late carrying a value the peer has already exceeded
        /// cannot take credit back. s19.11 states the same thing for MAX_STREAMS as an
        /// explicit MUST and gives the reason in one sentence - "Loss or reordering can cause
        /// an endpoint to receive a MAX_STREAMS frame with a lower stream limit than was
        /// previously received" - and A3-8's outbound repair is built on the mirror of it:
        /// <c>TlsQuicStreamSet.TryRefreshGrant</c> re-sends the CURRENT limit rather than the
        /// lost one precisely because a peer reading this rule would discard the stale one.
        /// EQUAL IS ALSO IGNORED: an unchanged limit grants nothing, so returning true for it
        /// would report a window movement that did not happen.</para>
        /// <para>THE DIFFERENCE IS CREDITED, NOT THE WHOLE LIMIT. <see cref="_remaining"/> is
        /// limit-minus-spent, so adding the delta leaves the bytes already sent still
        /// charged; assigning the new limit to it would refund every byte on the stream.</para>
        /// <para>CANNOT OVERFLOW. Both values are s16 variable-length integers, so each is at
        /// most 2^62-1 and the sum of a delta and a remainder is at most 2^63-2.</para>
        /// </remarks>
        internal bool TryRaiseLimit(ulong maximumStreamData)
        {
            if (maximumStreamData <= Limit)
            {
                return false;
            }

            _remaining += maximumStreamData - Limit;
            Limit = maximumStreamData;
            return true;
        }

        /// <summary>Charges <paramref name="bytes"/> of stream data against both this
        /// stream's limit and the connection-level initial_max_data.</summary>
        /// <remarks>THE POINT AT WHICH THE BUDGET IS SPENT, AND THE THROW IS NOW AN INVARIANT
        /// GUARD RATHER THAN THE POLICY. Both limits refill: a receiver raises them with
        /// MAX_STREAM_DATA (s19.10) or MAX_DATA (s19.9), and this budget applies both through
        /// <see cref="TryRaiseLimit"/> and
        /// <see cref="TlsQuicPeerFlowControlBudget.TryRaiseConnectionLimit"/>. What replaced
        /// the refusal is <c>TlsQuicStreamSet.Send</c>, which splits a write at
        /// <see cref="Available"/>, sends the part that fits and holds the rest until a grant
        /// arrives - so no caller inside this library reaches either guard below. THEY ARE
        /// KEPT AND WITNESSED ANYWAY, by direct tests on this type: silently sending past the
        /// limit is the flow-control violation s19.9 and s19.10 both answer with
        /// FLOW_CONTROL_ERROR, and a future caller that computed its own split wrongly should
        /// meet a throw rather than put the byte on the wire.
        /// <para>BOTH LIMITS ARE CHARGED, AND THE STREAM ONE FIRST. Charging only the
        /// per-stream limit lets a few streams that each fit exceed initial_max_data between
        /// them; charging only the connection limit lets one stream run past its own. The
        /// order matters for the message rather than the outcome - whichever is reported, the
        /// send does not happen and neither counter moves.</para></remarks>
        /// <exception cref="InvalidOperationException">Either limit would be
        /// exceeded.</exception>
        internal void Consume(ulong bytes)
        {
            if (bytes > _remaining)
            {
                throw new InvalidOperationException(
                    $"Sending {bytes} byte(s) would exceed the peer's {_limitName}, currently "
                        + $"{Limit} for this stream, of which {_remaining} remain. A caller "
                        + "with more bytes than credit must queue the excess against "
                        + "Available and let a MAX_STREAM_DATA release it, not hand them "
                        + "here.");
            }

            _connection.ConsumeConnectionData(bytes, _limitName);
            _remaining -= bytes;
        }
    }
}
