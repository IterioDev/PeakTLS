namespace SharpTls.Quic;

// ============================================================================
// A4 TASK 14e - MINIMAL STREAMS.
// ============================================================================
//
// RFC 9000 s2.1's stream identifiers, s19.8's STREAM frames carried both ways over the
// Application send path task 14c built, and the peer-initiated unidirectional streams
// subsystem C cannot connect without. No stream state machine beyond open/data/fin: no
// RESET_STREAM (s19.4), no STOP_SENDING (s19.5), no MAX_STREAM_DATA (s19.10), no
// STREAM_DATA_BLOCKED (s19.13). Those are A4-complete's.
//
// WHY A PLAIN TYPE PLUS A THIN PARTIAL, AND NOT ONE OR THE OTHER. TlsQuicPeerFlowControlBudget
// .cs argued that a component touching none of the connection's shared private state should be
// a plain internal type rather than a partial, and TlsQuicApplicationSendPath.cs argued the
// reverse for one that touches _keys and _nextPacketNumber. Streams are both things at once:
// TlsQuicStreamSet below reads nothing but the budget, so it is a plain type; the three lines
// that reach _peerFlowControl and hand frames to the send path are shared private state, so
// they are a partial of TlsQuicConnection at the bottom of this file. TlsQuicConnection.cs
// itself takes 8 code lines - the s19.8 dispatch arm, the local it writes and the failure it
// raises - and stands at 982 of its 1000-line cap afterwards, measured the way the constraint
// names: `grep -vcE '^\s*(//|$)' TlsQuicConnection.cs`.
//
// ============================================================================
// RFC 9000 s2.1 IS CITED AND NOT QUOTED, AND THAT IS A WEAKER CITATION.
// ============================================================================
//
// This repository's docs/superpowers/specs/reference-captures/ has no extract of RFC 9000
// section 2, so every s2.1 claim below - the two type bits, their assignment, and the ordinal
// living in the third and higher bits - is stated from the RFC rather than checked against a
// capture in the tree. That is the same weaker footing TlsQuicApplicationSendPath.cs records
// for s13.3 and s17.4, and it is labelled here rather than dressed up with a quotation nobody
// in this repository can resolve. What IS quotable is s19.8, which is in
// rfc9000-section19-frame-formats.txt and is where every bit-level claim about the FRAME
// comes from, and s20.1, which is in rfc9000-section20-transport-error-codes.txt and is where
// all four of this task's new error codes are read from.
//
// THE ARITHMETIC IS RECOVERABLE WITHOUT THE CAPTURE ANYWAY, which is why the four
// combinations below are pinned against hand-written constants rather than against a formula.
// s19.8 IS in the tree and it points at s2.1 for the Stream ID field; the four ids for
// ordinal 0 are 0, 1, 2 and 3, and a test that asserts those four numbers is checking the
// same thing a capture would let it quote.
//
// ============================================================================
// WHAT IS OURS TO RECEIVE, AND WHY THE PEER-INITIATED HALF EXISTS AT ALL.
// ============================================================================
//
// This endpoint is always the CLIENT (TlsQuicConnection has no server mode), so s2.1's four
// combinations divide as:
//
//   0x00 client-initiated bidirectional  - we open it, both halves are ours
//   0x01 server-initiated bidirectional  - the peer opens it; we may send and receive
//   0x02 client-initiated unidirectional - we open it, SEND ONLY; a STREAM frame arriving on
//                                          one is s19.8's "send-only stream" and is refused
//   0x03 server-initiated unidirectional - the peer opens it, RECEIVE ONLY
//
// THE 0x03 ROW IS THE ONE SUBSYSTEM C CANNOT START WITHOUT, and A4 task 14's original text
// missed it. RFC 9204 s4.2, last clause, in rfc9204-section4.1-4.2-primitives-and-streams.txt -
// cited without a line number because that extract is subsystem C's and still being written:
// "An endpoint MUST allow its peer to create an encoder stream and a decoder stream even if
// the connection's settings prevent their use." An HTTP/3 server opens its
// control stream and those two QPACK streams unconditionally, before it has heard anything
// from us, so a client that refused 0x03 would refuse every conforming server.
//
// ============================================================================
// NOTHING HERE THROWS ON PEER INPUT. THE SEND SIDE THROWS ON OURS.
// ============================================================================
//
// TryReceive is Try-shaped in A2's sense: it returns false with an s20.1 code for every input,
// well-formed or not, and never throws - not for a stream id we never opened, not for an
// offset near 2^62, not for a retransmission that overlaps what was already delivered, not for
// a FIN that contradicts an earlier one. 9a-ii shipped an off-path remote kill switch by
// throwing on unauthenticated input; a peer-initiated stream is peer-CONTROLLED even when it
// is authenticated, so a throw here would be a kill switch its own peer could pull.
//
// The send side is the other half of that split and takes the other rule, the one
// TlsQuicStreamFrames.WriteStreamFrameFields already states: caller-chosen input, so every
// rejection throws. Exhausting the peer's budget is the case that matters and it is covered
// at Send below.
//
// ============================================================================
// THE TWO BOUNDS THAT WERE OURS ARE NOW THE ONES WE ADVERTISE. C9's FINDING 2.
// ============================================================================
//
// This section used to declare MaximumReceivedBytesPerStream (1 MiB) and
// MaximumPeerInitiatedStreams (64) as placeholders, on the argument that "this connection
// cannot read its own [transport parameters] back: the client's transport parameters are a
// ClientHello extension blob carried on TlsQuicConnectionSpec.QuicTransportParameters, and
// nothing parses them back into a structure the connection can consult."
//
// BOTH HALVES OF THAT WERE WRONG, AND THE CONSEQUENCE WAS A LIE ON THE WIRE. There is no
// QuicTransportParameters member on TlsQuicConnectionSpec - it is on ClientHelloSpec, which
// DOES parse the blob back (ClientHelloSpec.cs:67-71, TlsQuicTransportParameters.Parse). And
// enforcing a number other than the advertised one is not a placeholder, it is a divergence:
// RFC 9000 s19.9 gives the peer "the maximum amount of data that can be sent on the entire
// connection" from what WE sent it, so a peer sending its 1,000,001st byte inside a limit we
// advertised as 15728640 was conforming and we would have closed the connection on it. The
// HTTP/3 spike's 4,943-byte response fit under both numbers, which is the only reason this
// passed.
//
// SO THE LIMITS ARE NOW READ FROM TlsQuicConnectionSpec.LocalFlowControl, the same object that
// EMITS the parameters (TlsQuicLocalFlowControlSpec.ToTransportParameters), and enforcement
// and advertisement cannot drift because they are one number. The s20.1 codes are unchanged
// and were always the right ones: FLOW_CONTROL_ERROR for data past a limit, STREAM_LIMIT_ERROR
// for a stream identifier past one.
//
// AND THE LIMITS NOW MOVE. s19.9 and s19.10's whole purpose is that a receiver raises them as
// it consumes, and A4-minimal sent neither frame - so a transfer larger than the initial
// window could not complete no matter what was advertised. TlsQuicStream.CreditReceiveWindow
// and TlsQuicStreamSet.CreditConnectionWindow queue those two frames onto the same pending
// list the STREAM frames use, so they ride the 1-RTT packet task 14c already builds. WHEN to
// send one is the single thing here no capture bounds and it is declared as such on
// TlsQuicLocalFlowControlSpec.ReceiveWindowUpdateDivisor.
//
// WHAT IS STILL NOT SENT IS MAX_STREAMS (s19.11). The stream-count limit is enforced at the
// value we advertised and never rises, so a peer that opens initial_max_streams_uni streams
// gets no more - which is A4-complete's, and is bounded rather than wrong: RFC 9114 s6.2 needs
// three and the advertised default is 103.
//
// AND A LOST GRANT IS A STALLED TRANSFER, WHICH IS A3's AND NOT THIS TASK'S. A grant is
// computed once per threshold crossing, so if the datagram carrying it is lost the peer stops
// at the old limit, sends nothing more, and nothing on this side crosses a threshold again -
// the two ends wait on each other. A4-minimal retransmits no frame at all (task 13 measured
// 0/10 attempts losing a packet, which is why that deferral is survivable), and the fix is
// retransmission rather than anything here: a receiver that re-sent grants on a timer would be
// duplicating A3's loss detection in one frame type's private schedule.

// ============================================================================
// THE MUTATION LEDGER
// ============================================================================
//
//   ROWS BELOW                   42  = numbered 1-42 with no gaps
//   KILLED WHEN FIRST RUN        36  = 42 rows, less 3 [WAS-SURVIVOR] and 3 [SURVIVED]
//   SURVIVED, THEN FIXED OR       3  = rows 24, 32, 42
//     WITNESSED
//   SURVIVING STILL               3  = rows 14, 30, 31, every one of them classified below
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' TlsQuicStreams.cs`                    must return 42
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicStreams.cs`   must return 3
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' TlsQuicStreams.cs`       must return 3
//
// ALL FORTY-TWO WERE RE-RUN AT ONE GATE - 1303 cases, 1302 passing and 1 skipped, in a git
// worktree that was removed afterwards. Counts are per xUnit CASE, so a six-row Theory failing
// in two of them counts 2. THE RE-RUN WAS NECESSARY AND NOT CEREMONY: rows 24, 32 and 42
// survived their first pass, three new tests were written for them, and every earlier row's
// number was then measured against a suite that had grown - row 29 moved from 5 to 6 on that
// alone.
//
// THE MUTATIONS THAT EDIT ANOTHER FILE ARE IN ITS LEDGER, which is this repository's
// convention and the reason TlsQuicPeerFlowControlBudget.cs's header points at
// TlsQuicConnection.cs's rows 93-97 rather than restating them: TlsQuicConnection.cs's new
// rows 98-99, TlsQuicApplicationSendPath.cs's new row 13, and LoopbackQuicPeer.cs's new rows
// 25-27. One ledger per file, so that each file's three greps stay about that file.
//
// A NOTE ON THE MUTANT FORM, because it changed a measurement. This build treats CS0162 as an
// error, so `if (false)` does not compile where the body is anything but a throw - eleven rows
// were reported as BUILD-ERROR on the first pass before being rewritten as `COND && false`,
// which is not a compile-time constant and so leaves the body reachable to the compiler and
// unreachable at run time. A sweep that had recorded those eleven as "no result" and moved on
// would have left every guard in TryReceive unmeasured.
//
// WHERE A ROW SAYS ONLY, that test was the entire failure set.
//
// ---- RFC 9000 s2.1: the two type bits and the ordinal above them ----
//    1. the two type bits swapped in From        10 tests
//    2. From never sets the initiator bit         4 tests
//    3. From never sets the direction bit        12 tests
//    4. the ordinal is shifted one bit, not two   8 tests
//    5. InitiatorOf reads the direction bit      14 tests
//    6. DirectionOf reads the initiator bit       5 tests
//    7. OrdinalOf shifts by one                   4 tests
//    8. From's ordinal-range guard never fires   ONLY TheLargestStreamIdIsTheLargestVariableLengthInteger
//    9. From's Enum.IsDefined on the initiator never fires  ONLY AnUndefinedInitiatorOrDirectionIsRejected
//
// ROW 1 IS THE ONE THAT SHOWS THE FOUR WITNESSES ARE FOUR AND NOT ONE, and its ten are worth
// reading for what is NOT in them: AClientInitiatedBidirectionalStreamIdHasBothTypeBitsClear
// stays GREEN under a swap of the two bits, because 4n has both bits clear either way. A suite
// that had asserted the four combinations in one test would have reported a swap as "the
// stream ids are wrong" without being able to say which two. Rows 2 and 3 divide the same way
// from the other side - row 2 kills only the two SERVER rows and row 3 only the two
// UNIDIRECTIONAL ones, and neither kills the client-bidirectional witness, because 0x00 is the
// combination that both bits being wrong leaves alone.
//
// ---- what may be sent, and on what ----
//   10. CanSend is always true                    2 tests
//   11. CanReceive is always true                 2 tests
//   12. the ordinal never advances                3 tests
//   13. the already-sent-FIN guard never fires   ONLY SendingAfterTheFinIsRefusedBecauseTheFinalSizeIsFixed
//   14. Send's `!stream.CanSend` disjunct dropped  [SURVIVED] 0 of 1303 - UNREACHABLE BY
//       CONSTRUCTION, and no test is written for it. A stream has CanSend false exactly when it
//       is server-initiated and unidirectional, which is exactly when TlsQuicStreamSet gives it
//       a null Budget, so the second disjunct alone refuses every input the first would. The
//       disjunct is kept because it says WHY in the language of s2.1 rather than leaving a
//       reader to derive it from a null, and because the two would come apart the moment
//       anything constructs a TlsQuicStream directly.
//
// ---- the peer's static budget, spent ----
//   15. the budget is charged AFTER the frame is queued  3 tests
//   21. TakePendingFrames does not empty the queue  ONLY ExhaustingTheStreamsOwnCreditFailsCleanlyRatherThanSendingPastThePeersLimit
//
// ROW 15 IS THE ORDER-OF-OPERATIONS ONE and it is the counterpart of
// TlsQuicPeerFlowControlBudget.cs's row 22. Queuing first and charging second still throws, and
// still throws the same message - what changes is that the refused frame is already in the
// pending list and goes out on the next packet, which is the silent flow-control violation the
// whole guard exists to prevent. It is caught only because all three exhaustion tests assert
// the state AFTER the throw.
//
// ---- RFC 9000 s19.8's three type bits, on the way out ----
//   16. the OFF bit is always set                ONLY AStreamsFirstFrameOmitsTheOffsetFieldAndItsSecondCarriesIt
//   17. the OFF bit is never set                  2 tests
//   18. the LEN bit is never set                  2 tests
//   19. the FIN bit is never set                  3 tests
//   20. the send offset never advances            5 tests
//
// ROWS 16 AND 17 ARE THE ZERO-VERSUS-ABSENT PAIR ON THE OFFSET FIELD, and they are asymmetric
// for a reason that is s19.8's rather than this file's. Always setting OFF is a LEGAL frame
// that decodes to the same values, so only the test that reads the bit off the frame notices;
// never setting it is a frame whose second write claims offset 0, which the loopback peer sees
// as bytes at the wrong place. One kill versus two is the difference between a wire form and a
// wire error.
//
// ---- RFC 9000 s20.1's FINAL_SIZE_ERROR, one row per numbered case ----
//   22. the offset+length overflow check never fires  ONLY NoPeerControlledStreamFrameMakesTryReceiveThrow
//   23. case (1), data past an established final size, never fires  ONLY DataPastAnEstablishedFinalSizeIsFinalSizeError
//   24. case (3), a different final size, never fires  [WAS-SURVIVOR] ONLY ASecondFinBelowTheFirstWhileTheStreamIsStillEmptyIsFinalSizeErrorToo
//   25. case (2) compares only the undelivered end  ONLY AFinBelowWhatWasAlreadyReceivedIsFinalSizeError
//   26. case (2) compares only the delivered prefix  ONLY AFinBelowBytesHeldButNotYetDeliveredIsAlsoFinalSizeError
//   29. the final size is never recorded          6 tests
//
// ROW 24 IS THE ONE WORTH READING. It survived the first sweep outright, and the reason was not
// that the check is redundant - it was that every input the suite had reached case (1) or case
// (2) FIRST. A different final size ABOVE the established one is case (1)'s "exceeded"; one
// BELOW is case (2)'s "lower than the size of stream data that was already received" - unless
// nothing has been received, which happens exactly when a FIN overtakes its own stream data.
// That is the shape the new test builds, and it is the only shape in which s20.1's case (3) is
// the sole cause. ROWS 25 AND 26 ARE THE SAME LESSON APPLIED IN ADVANCE: case (2)'s two
// comparisons look like one condition and are two, and each has the witness the other cannot
// give.
//
// ---- our own two bounds, which are not read off the wire ----
//   27. the receive-byte bound never fires        2 tests
//   28. the receive-byte bound is inclusive: > becomes >=  ONLY AnOffsetPastWhatThisEndpointWillHoldIsRefusedRatherThanAllocated
//   37. the peer-initiated stream cap never fires  ONLY MorePeerInitiatedStreamsThanThisEndpointTracksIsStreamLimitError
//
// ---- reassembly, and delivering in order ----
//   30. a zero-length frame is buffered as a piece  [SURVIVED] 0 of 1303 - VACUOUS, and no test
//       is written for it, because a test would pass against the mutant and become a false
//       witness. An empty piece stored at any offset is removed by the first Drain pass that
//       reaches it and appends nothing, so the mutant's behaviour is identical for every input.
//       The guard is kept because it makes that argument unnecessary rather than load-bearing.
//   31. Buffer's already-delivered short circuit deleted  [SURVIVED] 0 of 1303 - VACUOUS for
//       the same reason and measured the same way. A piece entirely below the delivered prefix
//       takes the same path: Drain computes a skip at least as long as the piece, appends
//       nothing, and drops it. What the short circuit saves is an allocation and a dictionary
//       write, not an outcome.
//   32. Buffer keeps the SHORTER piece at a known offset  [WAS-SURVIVOR] ONLY ARetransmissionBehindAGapThatCarriesMoreBytesReplacesTheShorterOne
//   33. Drain's contiguity test is >= instead of >  13 tests
//   34. Drain runs once instead of to a fixed point  5 tests
//   35. Drain appends the whole piece instead of trimming the overlap  ONLY AnOverlappingRetransmissionDeliversOnlyTheBytesBeyondWhatWasAlreadyDelivered
//
// ROW 32 SURVIVED FOR THE REASON ROW 24 DID - the branch was unreachable in the suite rather
// than in the code. Two pieces only coexist at one offset BEHIND A GAP; every overlap the file
// had resolved at an offset Drain reached immediately, so the second piece was compared against
// nothing. ROW 33 IS THE OFF-BY-ONE THAT STOPS EVERY STREAM AT ITS FIRST FRAME, and its
// thirteen are what a boundary that is wrong in the common direction looks like.
//
// ROWS 30 TO 35 WERE WRITTEN AGAINST A REPRESENTATION THAT NO LONGER EXISTS, and the rows are
// left at their numbers because the three greps above are about the LIST and renumbering would
// make "must return 42" false. What changed is under them: _undelivered was a
// Dictionary<ulong, byte[]> keyed by arrival offset and is now a sorted list of non-overlapping
// ranges - see the field's own comment for the quadratic memory that forced it. The rows
// translate rather than lapse:
//
//   * ROW 31's "already-delivered short circuit" and ROW 35's front-trim are now the SAME
//     branch, both in Buffer, and row 35's witness still kills it.
//   * ROW 32's "keeps the SHORTER piece at a known offset" is now "the held bytes win and only
//     the tail is stored"; ARetransmissionBehindAGapThatCarriesMoreBytesReplacesTheShorterOne
//     still separates the two, because the longer retransmission's extra bytes have to reach
//     the application either way.
//   * ROW 34, "Drain runs once instead of to a fixed point", IS NOW EQUIVALENT BY CONSTRUCTION
//     and its five kills are historical: sorted, gap-free pieces make the drainable set a
//     prefix of the list, so one pass IS the fixed point. The mutation that replaced it is
//     Buffer's insertion order, and BUFFERED BYTES STAY WITHIN THE ADVERTISED WINDOW UNDER A
//     DESCENDING OVERLAP FLOOD is the row that measures what row 34 used to stand for.
//
// ---- RFC 9000 s19.8's two STREAM_STATE_ERROR cases, and accepting the peer's streams ----
//   36. the locally-initiated-not-created check never fires  4 tests
//   38. the send-only check never fires           2 tests
//   39. a peer-opened stream's budget branch inverted  2 tests
//   40. a peer-opened stream is not recorded in PeerInitiated  20 tests
//   41. ReceiveStreamFrame never reports a refusal  2 tests
//   42. ReceiveStreamFrame reports the LAST refusal instead of the first  [WAS-SURVIVOR] ONLY WhenOneDatagramCarriesTwoUnacceptableStreamFramesTheFirstIsReported
//
// ROWS 36 AND 38 ARE s19.8's ONE SENTENCE READ AS TWO CHECKS - "a locally initiated stream that
// has not yet been created, OR ... a send-only stream" - and they are separate rows because
// they are reached by different inputs and neither test can stand in for the other. ROW 42
// survived its first pass because no test put two unacceptable STREAM frames in ONE datagram,
// which RFC 9000 s12.2's "MUST attempt to process the remaining packets" makes an ordinary
// thing for a peer to do.

// ============================================================================
// THE A4-COMPLETE MUTATION LEDGER - THE SPLIT SEND, SEPARATELY PREFIXED
// ============================================================================
//
//   ROWS BELOW                   20  = numbered A4C-10 to A4C-28 and A4C-30, no gaps
//                                      (A4C-01..09 are TlsQuicPeerFlowControlBudget.cs's and
//                                       A4C-29 is TlsQuicConnection.cs's - one ledger per file)
//   KILLED WHEN FIRST RUN        12  = 20 rows, less 5 [WAS-SURVIVOR], 1 [SURVIVED]
//                                      and 2 [COMPILER]
//   KILLED BY THE COMPILER        2  = rows A4C-15 and A4C-20. Both are CS0162 or CS0649,
//                                      which Directory.Build.props makes errors; the verdict
//                                      is the build's EXIT CODE and not a reading of its text
//   SURVIVED, THEN WITNESSED      5  = rows A4C-13, A4C-16, A4C-18, A4C-21, A4C-27
//   SURVIVING STILL               1  = row A4C-23, classified below as EQUIVALENT
//
//   12 + 2 + 5 + 1 = 20, which is the row count above.
//
// Four greps, anchored to the A4C prefix so they collide with neither the 1-42 ledger above
// nor the C9-01..33 one below. Run from this file's directory:
//   `grep -cE '^// +A4C-[0-9]+\. ' TlsQuicStreams.cs`                     = 20
//   `grep -cE '^// +A4C-[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicStreams.cs`    = 5
//   `grep -cE '^// +A4C-[0-9]+\..*\[SURVIVED\]' TlsQuicStreams.cs`        = 1
//   `grep -cE '^// +A4C-[0-9]+\..*\[COMPILER\]' TlsQuicStreams.cs`        = 2
//
// SAME HARNESS AS THE BUDGET FILE'S LEDGER, and its paragraph on the method applies verbatim:
// mutate-maxdata.py, a private worktree, one mutation at a time, KILLED-BY-COMPILER taken
// STRUCTURALLY from the build's exit code, the gate's exit code read directly rather than
// through a pipe, a 2,400-case floor honoured on every run (2,473 first sweep, 2,475 on the
// re-runs), and two calibration rows that both died in the same sweep.
//
// ---- the split, and what bounds it ----
//   A4C-10. Drain reads budget.Remaining instead of Available, ignoring initial_max_data  2 tests
//   A4C-17. TryTakeSendable's `take < head.Length` becomes `<=`, so every take is partial  34 tests
//
// ---- the blocked signals, s19.12 and s19.13 ----
//   A4C-11. STREAM_DATA_BLOCKED is never queued  3 tests
//   A4C-12. DATA_BLOCKED is never queued  2 tests
//   A4C-13. [WAS-SURVIVOR] STREAM_DATA_BLOCKED carries 0 instead of the send offset  1 test
//   A4C-14. DATA_BLOCKED carries 0 instead of the connection limit  1 test
//   A4C-15. [COMPILER] the HasBlockedData guard is removed, so an unblocked stream signals
//   A4C-19. the per-stream signal never latches, so every write re-signals  1 test
//   A4C-27. [WAS-SURVIVOR] the connection signal stays latched after a raise  1 test
//
// ---- the FIN, which is the part a split can steal ----
//   A4C-16. [WAS-SURVIVOR] a PARTIAL take carries the FIN  1 test
//   A4C-18. [WAS-SURVIVOR] a FULL take of a NON-LAST entry carries it  1 test
//   A4C-20. [COMPILER] QueueForSend drops the FIN entirely
//   A4C-21. [WAS-SURVIVOR] Send's guard reads FinSent instead of FinQueued  1 test
//
// ---- receiving s19.10's grant ----
//   A4C-22. a MAX_STREAM_DATA for an uncreated LOCAL stream is accepted, not refused  2 tests
//   A4C-23. [SURVIVED] the receive-only check drops its `!stream.CanSend` clause  0 tests
//   A4C-24. the grant raises the limit but nothing drains behind it  5 tests
//   A4C-25. the grant drains but the blocked signal stays latched  1 test
//
// ---- receiving s19.9's grant ----
//   A4C-26. no stream is drained when the connection limit rises  2 tests
//   A4C-28. the raise test is inverted, so only a REFUSED grant proceeds  2 tests
//   A4C-30. the two grants are dispatched to each other's handler  6 tests
//
// A4C-23 IS THE ONLY SURVIVOR AND IT IS EQUIVALENT, NOT UNWITNESSED. s19.10 has two MUSTs and
// TryReceiveMaxStreamData tests for both in one condition - `!stream.CanSend || stream.Budget
// is not { } budget` - and the two halves cannot disagree in this tree. The only stream for
// which CanSend is false is a server-initiated unidirectional one (s2.1's 0x03 row), and
// TryReceive constructs exactly that stream with a NULL budget, because
// TlsQuicPeerFlowControlBudget has no Accept method for a stream we can never send on. So the
// second half already refuses everything the first half would, the mutation removes a clause
// that cannot fire on its own, and AMaxStreamDataThatSection1910RefusesClosesWithStreamState
// Error's third Theory row still passes with it gone. The clause is kept as defence in depth
// against a future stream type that has a budget and no send permission; it is EQUIVALENT BY
// CONSTRUCTION and no test can be written that separates the two, which is why none is.
//
// A4C-17'S THIRTY-FOUR IS THE OUTLIER AND IT IS THE CHECK DOING ITS JOB. Making every take
// partial means no take ever removes an entry, so no stream ever emits a FIN and every
// zero-length frame stalls - which breaks every HTTP/3 test that completes a request, not just
// the flow-control ones. A row that kills a third of the file's dependents is not a coarse
// witness, it is a load-bearing line.
//
// THE FOUR THAT SURVIVED THE FIRST SWEEP ALL SHARE ONE CAUSE, worth naming because it is a
// gap a reader can repeat. Every one of them - A4C-13, A4C-16, A4C-18, A4C-27 - is a value or
// an edge that only EXISTS once a write is split, and the suite that existed before this task
// never split one: it asserted that a frame arrived, not what its FIN bit or its blocked-limit
// field said, because until now a Send produced exactly one frame carrying exactly what it was
// given. A4C-21 is the same gap seen from the caller's side. The lesson is that adding a state
// (bytes queued but not sent) adds assertions everywhere that state is observable, and the
// mutation sweep is what found the four places nobody thought to look.
//
// ============================================================================
// THE C9 MUTATION LEDGER - THE RECEIVE SIDE, SEPARATELY NUMBERED
// ============================================================================
//
// A SECOND LEDGER RATHER THAN ROWS 43-75 OF THE FIRST, and the reason is the three greps above.
// Renumbering into 14e's list would make its "must return 42" false, and every reader who runs
// that grep would be told the ledger is broken when nothing about it changed. These rows carry
// a C9- prefix so both sets of greps stay true of their own list.
//
//   ROWS BELOW                   33  = numbered C9-01 to C9-33 with no gaps
//   KILLED WHEN FIRST RUN        28  = 33 rows, less 2 [WAS-SURVIVOR], 1 [BUILD-ERROR]
//                                      and 2 [SURVIVED]
//   SURVIVED, THEN WITNESSED      2  = rows C9-09 and C9-24
//   BUILD-ERROR, THEN REWRITTEN   1  = row C9-14
//     AND KILLED
//   SURVIVING STILL               2  = rows C9-12 and C9-27, both classified below
//
// Three greps, anchored to a numbered row so these lines do not match themselves. Run from
// this file's directory:
//   `grep -cE '^// +C9-[0-9]+\. ' TlsQuicStreams.cs`                    must return 33
//   `grep -cE '^// +C9-[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicStreams.cs`   must return 2
//   `grep -cE '^// +C9-[0-9]+\..*\[SURVIVED\]' TlsQuicStreams.cs`       must return 2
//
// ALL THIRTY-THREE WERE RUN IN A GIT WORKTREE THAT WAS REMOVED AFTERWARDS, against
// `dotnet test --filter "FullyQualifiedName~Quic"`. Counts are per xUnit CASE. THE GATE GREW
// UNDER THE SWEEP - two other agents were committing to this branch throughout - so rows C9-09,
// C9-14 and C9-24, which were re-run after the fix round, were measured against a larger suite
// than the other thirty. That does not change any verdict and it does change the counts, which
// is why it is stated rather than smoothed over.
//
// THE HARNESS WAS CHECKED BEFORE ANY ROW WAS BELIEVED, in both directions: a deliberate
// known-bad edit (initial_max_streams_uni 103 -> 1) reported KILLED with 10 failures, and an
// inert comment rewording reported SURVIVED with 0. A sweep that cannot produce a survivor and
// a sweep that cannot produce a kill look identical from a list of kills.
//
// ---- what a stream is allowed to receive ----
//  C9-01. the per-stream window comes from initial_max_data, not from the stream's type  3 tests
//  C9-02. the per-stream receive guard never fires  3 tests
//  C9-03. the per-stream receive guard is off by one: > becomes >=  6 tests
//  C9-04. a retransmission is charged at its full length  2 tests
//  C9-05. the connection-level admission never refuses  1 test
//  C9-06. the largest received offset never advances  2 tests
//
// ROW C9-04 IS s19.10's SENTENCE ABOUT REORDERING MADE INTO A DEFECT - "an endpoint accounts
// for the largest received offset" - and it is invisible to any test whose peer never
// retransmits, which is every test written before C9.
//
// ---- crediting the window back ----
//  C9-07. the connection window is never credited  2 tests
//  C9-08. bytes already credited are credited again  2 tests
//  C9-09. the per-stream threshold is off by one: >= becomes >  [WAS-SURVIVOR] ONLY OutstandingCreditExactlyOnTheUpdateThresholdQueuesNothing
//  C9-10. the per-stream window is never raised  2 tests
//  C9-11. the per-stream window does not slide with what was consumed  2 tests
//  C9-12. the per-stream clamp is removed  [SURVIVED] UNREACHABLE BY CONSTRUCTION
//  C9-13. MAX_STREAM_DATA is never marked owed  2 tests
//  C9-14. MAX_STREAM_DATA is always claimed owed  2 tests
//  C9-23. the connection delivered total never advances  2 tests
//  C9-24. the connection threshold is off by one: >= becomes >  [WAS-SURVIVOR] ONLY OutstandingCreditExactlyOnTheUpdateThresholdQueuesNothing
//  C9-25. the connection window is never raised  2 tests
//  C9-26. the connection window does not slide with what was consumed  2 tests
//  C9-27. the connection clamp is removed  [SURVIVED] UNREACHABLE BY CONSTRUCTION
//  C9-28. MAX_DATA is never marked owed  2 tests
//
// ROWS C9-09 AND C9-24 ARE THE PAIR THE SWEEP EARNED. Both survived the whole gate, because no
// test happened to leave exactly half a window outstanding and equality is the only input that
// separates >= from >. One test lands both levels on the boundary at once and kills both. A
// sweep that had reported them as "no reachable difference" would have been wrong twice.
//
// ROWS C9-12 AND C9-27 ARE UNREACHABLE BY CONSTRUCTION, NOT UNWITNESSED, and no test is written
// for either. Both clamps fire only when delivered + window would pass 2^62-1. The threshold
// above has to be crossed first, which needs delivered to exceed half the window, so reaching
// either clamp means having actually received on the order of 2^61 bytes into a List<byte>.
// That is not a test, it is an out-of-memory. The clamps stay because without them a window
// advertised near the varint ceiling would turn a received frame into a throw on the path this
// file's header keeps throw-free - a guard against an input no test can supply is still the
// right guard when the alternative is an exception.
//
// ROW C9-14 READ BUILD-ERROR FIRST, with CS0414: replacing `var owed = _maximumStreamDataOwed`
// with a constant left the field written and never read, and CS0414 is an error in this build.
// Rewritten as `_maximumStreamDataOwed || true`, which keeps the read, it kills two. A sweep
// recording the first attempt as "no result" would have left the flag unmeasured, which is the
// exact trap 14e's ledger warns about.
//
// ---- what the connection is allowed to receive, and which streams may exist ----
//  C9-15. the connection receive limit starts unbounded  3 tests
//  C9-16. the peer-initiated stream-id guard never fires  3 tests
//  C9-17. the peer-initiated stream-id guard is off by one: >= becomes >  2 tests
//  C9-18. one shared stream-count limit rather than one per direction  ONLY TheStreamCountLimitIsPerDirectionAndNotOneSharedCounter
//  C9-19. flow-control updates are never queued  2 tests
//  C9-20. the connection-level guard never refuses  ONLY TwoStreamsInsideTheirOwnLimitsCanStillExceedTheAdvertisedConnectionLimit
//  C9-21. the connection-level guard is off by one: > becomes >=  2 tests
//  C9-22. connection-level bytes are never charged  ONLY TwoStreamsInsideTheirOwnLimitsCanStillExceedTheAdvertisedConnectionLimit
//
// ROW C9-17 IS s19.11's WORKED EXAMPLE AS A TEST - "permitted to open streams 3, 7, and 11, but
// not stream 15" - and it is the row that decides whether the limit is on the identifier or on
// a count. ROW C9-18 kills exactly one test, which is the one whose peer opens streams of both
// directions; every other test in the file uses one direction and cannot see the difference.
//
// ---- the two frames themselves ----
//  C9-29. the MAX_DATA owed flag is never cleared  ONLY CrossingTheUpdateThresholdQueuesOneMaxStreamDataAndOneMaxData
//  C9-30. MAX_STREAM_DATA is queued with MAX_DATA's type  2 tests
//  C9-31. MAX_STREAM_DATA names stream 0  ONLY CrossingTheUpdateThresholdQueuesOneMaxStreamDataAndOneMaxData
//  C9-32. MAX_STREAM_DATA carries 0 instead of the new limit  ONLY CrossingTheUpdateThresholdQueuesOneMaxStreamDataAndOneMaxData
//  C9-33. MAX_DATA carries 0 instead of the new limit  ONLY CrossingTheUpdateThresholdQueuesOneMaxStreamDataAndOneMaxData
//
// THE LAST FOUR ARE WHY THAT TEST ASSERTS VALUES AND NOT PRESENCE. A grant carrying 0, or
// naming the wrong stream, is a frame s19.10 tells the peer to ignore - "MAX_STREAM_DATA frames
// that do not increase the stream limit MUST be ignored" - so a test that only counted frames
// would pass against all four mutants while the transfer stalled.

/// <summary>Which endpoint opened a stream - RFC 9000 s2.1's low type bit.</summary>
internal enum TlsQuicStreamInitiator
{
    /// <summary>Bit 0x00 of the stream id: a client-initiated stream.</summary>
    Client = 0,

    /// <summary>Bit 0x01 of the stream id: a server-initiated stream.</summary>
    Server = 1,
}

/// <summary>Whether a stream carries data one way or both - RFC 9000 s2.1's second type
/// bit.</summary>
internal enum TlsQuicStreamDirection
{
    /// <summary>Bit 0x00 of the stream id: both endpoints may send.</summary>
    Bidirectional = 0,

    /// <summary>Bit 0x02 of the stream id: only the initiator may send.</summary>
    Unidirectional = 1,
}

/// <summary>RFC 9000 s2.1's stream identifier: two type bits and an ordinal above
/// them.</summary>
internal static class TlsQuicStreamId
{
    /// <summary>RFC 9000 s2.1's least significant bit: 0 for a client-initiated stream, 1 for
    /// a server-initiated one.</summary>
    internal const ulong ServerInitiatedBit = 0x01;

    /// <summary>RFC 9000 s2.1's second bit: 0 for a bidirectional stream, 1 for a
    /// unidirectional one.</summary>
    internal const ulong UnidirectionalBit = 0x02;

    /// <summary>How far the ordinal sits above the two type bits.</summary>
    internal const int OrdinalShift = 2;

    /// <summary>The four RFC 9000 s2.1 combinations at ordinal 0, in the order s2.1's table
    /// lists them.</summary>
    /// <remarks>NOT USED TO DERIVE ANYTHING - <see cref="From"/> computes the id from the bits
    /// rather than indexing this. It exists so that the table s2.1 prints is written down once
    /// in a form a reader can compare against, and so a test can assert the derivation and the
    /// table agree without either one being the other's source.</remarks>
    internal static ReadOnlySpan<ulong> FirstOfEachType => [0x00, 0x01, 0x02, 0x03];

    /// <summary>Derives the stream id for one of RFC 9000 s2.1's four combinations at the
    /// given ordinal.</summary>
    /// <remarks>CALLER-CHOSEN INPUT, so it throws - the split
    /// <see cref="TlsQuicStreamFrames.WriteStreamFrameFields"/> states. The ordinal bound is
    /// s2.1's consequence rather than a separate rule: the id is a variable-length integer, so
    /// it cannot exceed <see cref="QuicVariableLengthInteger.MaximumValue"/>, and two of those
    /// 62 bits are spent on the type.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">The initiator or direction is not a
    /// defined value, or the ordinal does not fit in the 60 bits above the type
    /// bits.</exception>
    internal static ulong From(
        TlsQuicStreamInitiator initiator, TlsQuicStreamDirection direction, ulong ordinal)
    {
        if (!Enum.IsDefined(initiator))
        {
            throw new ArgumentOutOfRangeException(nameof(initiator));
        }

        if (!Enum.IsDefined(direction))
        {
            throw new ArgumentOutOfRangeException(nameof(direction));
        }

        if (ordinal > QuicVariableLengthInteger.MaximumValue >> OrdinalShift)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ordinal),
                ordinal,
                "RFC 9000 s2.1 puts a stream's ordinal in the bits above the two type bits of "
                    + "a variable-length integer, so it cannot exceed "
                    + $"{QuicVariableLengthInteger.MaximumValue >> OrdinalShift}.");
        }

        return (ordinal << OrdinalShift)
            | (initiator == TlsQuicStreamInitiator.Server ? ServerInitiatedBit : 0)
            | (direction == TlsQuicStreamDirection.Unidirectional ? UnidirectionalBit : 0);
    }

    /// <summary>Reads RFC 9000 s2.1's initiator bit off a stream id.</summary>
    internal static TlsQuicStreamInitiator InitiatorOf(ulong streamId) =>
        (streamId & ServerInitiatedBit) != 0
            ? TlsQuicStreamInitiator.Server
            : TlsQuicStreamInitiator.Client;

    /// <summary>Reads RFC 9000 s2.1's direction bit off a stream id.</summary>
    internal static TlsQuicStreamDirection DirectionOf(ulong streamId) =>
        (streamId & UnidirectionalBit) != 0
            ? TlsQuicStreamDirection.Unidirectional
            : TlsQuicStreamDirection.Bidirectional;

    /// <summary>Reads the ordinal off a stream id - RFC 9000 s2.1's position of the stream
    /// within its own type.</summary>
    internal static ulong OrdinalOf(ulong streamId) => streamId >> OrdinalShift;
}

/// <summary>One QUIC stream: an RFC 9000 s2.1 identifier, a send offset with the peer's
/// s18.2 budget behind it, and an offset-aware receive buffer that delivers in order.</summary>
internal sealed class TlsQuicStream
{
    // WHY NOT TlsQuicCryptoStreamReassembler, WHICH DOES ALMOST EXACTLY THIS. It THROWS -
    // TlsQuicTransportException, three times - and its codes and messages are CRYPTO's:
    // CRYPTO_BUFFER_EXCEEDED for an overrun, "Overlapping CRYPTO data does not match", a
    // Discard() concept a stream does not have. Reaching it through a translating catch would
    // put a throw back on the peer-input path this file's header rules out, and would report a
    // stream overrun with the code s20.1 assigns to the CRYPTO buffer. The Try-shaped version
    // below is about thirty lines and says the true thing.
    //
    // SORTED BY OFFSET AND NON-OVERLAPPING, AND BOTH HALVES OF THAT ARE LOAD-BEARING RATHER
    // THAN TIDINESS. This used to be a Dictionary<ulong, byte[]> keyed by the offset the frame
    // arrived at, which stored every DISTINCT offset verbatim and deduplicated nothing else.
    // RFC 9000 s19.9 charges the connection window for "the largest received offset" only - see
    // the `advance` in TryReceive - so a peer that sends (offset=1, len=W-1), (offset=2,
    // len=W-2), (offset=3, len=W-3) ... and puts (offset=0, len=W) LAST pays flow control once,
    // for W bytes, while nothing drains until the final frame arrives: every earlier one starts
    // past the delivered prefix. The dictionary held all of them, so W bytes of advertised
    // credit bought roughly W^2/2 bytes of our memory - about 32 GB at a 256 KiB window and
    // half a terabyte at 1 MiB.
    //
    // COALESCING ON INSERT IS WHAT MAKES THE BOUND HOLD, AND IT IS THE WINDOW'S OWN BOUND
    // rather than a second cap that would need a number nobody can derive. Every byte held here
    // lies in [_delivered.Count, _largestReceivedOffset), each byte is stored exactly once
    // because the ranges do not overlap, and s19.10's per-stream limit already refuses a frame
    // whose end passes _receiveLimit - so the total retained is at most _receiveWindow, by
    // construction and not by inspection. UndeliveredBytes is the observable of that.
    //
    // AND IT IS WHY Drain IS ONE FORWARD PASS. The old fixed-point loop -
    // `do { foreach (var offset in _undelivered.Keys.ToList()) ... } while (moved)` - allocated
    // a fresh key list per pass and needed one pass per buffered piece in the worst order, so k
    // out-of-order chunks cost O(k^2) time and k allocations. Sorted and gap-free, the pieces
    // that are now contiguous are exactly a prefix of this list.
    private readonly List<(ulong Offset, byte[] Data)> _undelivered = [];
    private readonly List<byte> _delivered = [];

    // THE BYTES THIS ENDPOINT HAS ACCEPTED FOR SENDING AND THE PEER HAS NOT YET GRANTED CREDIT
    // FOR, in stream order. A LIST OF MEMORIES RATHER THAN A List<byte>: the whole point of
    // this queue is a body larger than the peer's initial per-stream credit, so a
    // byte-by-byte copy of it is the one data structure the task cannot afford. Each entry is
    // a window onto the caller's own buffer, sliced rather than copied as credit arrives.
    private readonly List<ReadOnlyMemory<byte>> _blocked = [];
    private readonly TlsQuicStreamSet _set;
    private readonly ulong _receiveWindow;

    // ONE FLAG FOR THE WHOLE QUEUE AND NOT ONE PER ENTRY, because RFC 9000 s19.8's FIN "marks
    // the end of the stream" and TlsQuicStreamSet.Send refuses a write after one has been
    // accepted - so a FIN can only ever belong to the LAST entry, and there is only ever one.
    private bool _blockedFin;

    // s19.13's SHOULD, damped. "A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15)
    // when it wishes to send data but is unable to do so due to stream-level flow control" is
    // about the CONDITION arising, not about every Send call made while it holds: a caller
    // writing a body in a thousand chunks against an exhausted limit would otherwise queue a
    // thousand identical frames. Cleared when the limit moves, so the next block signals
    // again - which is s13.3's "only while the endpoint is blocked on the corresponding limit".
    private bool _streamDataBlockedSignalled;
    private ulong? _finalSize;
    private ulong _receiveLimit;
    private ulong _largestReceivedOffset;
    private ulong _creditedToConnection;

    private bool _receiveCompleteReported;
    private bool _maximumStreamDataOwed;

    // RFC 9000 s19.4's and s19.5's Application Protocol Error Code, held as a nullable rather
    // than beside a bool because ZERO IS A LEGAL CODE - s20.2 makes the application error space
    // "defined by the application protocol", and RFC 9114 s8.1 assigns H3_NO_ERROR = 0x0100 but
    // leaves 0 to whatever the peer means by it. `is not null` is therefore the arrival test and
    // the value is the peer's, unmapped, for the reason TlsQuicConnection.PeerCloseErrorCode
    // gives for s19.19's.
    private ulong? _resetErrorCode;
    private ulong? _stopSendingErrorCode;

    internal TlsQuicStream(
        ulong id, TlsQuicPeerFlowControlBudget.TlsQuicStreamBudget? budget, TlsQuicStreamSet set)
    {
        Id = id;
        Budget = budget;
        _set = set;

        // OUR advertised per-stream limit for THIS stream's s2.1 type, and the window every
        // later MAX_STREAM_DATA re-grants. Fixed at construction because s18.2's per-stream
        // parameters are "equivalent to sending a MAX_STREAM_DATA frame on every stream of the
        // corresponding type immediately after opening" - the initial grant is a property of
        // the type, not of the stream.
        _receiveWindow = set.LocalFlowControl.ReceiveLimitFor(id);
        _receiveLimit = _receiveWindow;
    }

    /// <summary>Gets this stream's RFC 9000 s2.1 identifier.</summary>
    internal ulong Id { get; }

    /// <summary>Gets which endpoint opened this stream.</summary>
    internal TlsQuicStreamInitiator Initiator => TlsQuicStreamId.InitiatorOf(Id);

    /// <summary>Gets whether this stream carries data one way or both.</summary>
    internal TlsQuicStreamDirection Direction => TlsQuicStreamId.DirectionOf(Id);

    /// <summary>Gets this stream's share of the peer's static budget, or
    /// <see langword="null"/> for a receive-only stream, on which we never send and so spend
    /// nothing.</summary>
    internal TlsQuicPeerFlowControlBudget.TlsQuicStreamBudget? Budget { get; }

    /// <summary>Gets whether this endpoint may send on this stream: everything except a
    /// server-initiated unidirectional stream, which RFC 9000 s2.1 makes receive-only for
    /// us.</summary>
    internal bool CanSend => Direction == TlsQuicStreamDirection.Bidirectional
        || Initiator == TlsQuicStreamInitiator.Client;

    /// <summary>Gets whether this endpoint may receive on this stream: everything except a
    /// client-initiated unidirectional stream, which is s19.8's "send-only stream".</summary>
    internal bool CanReceive => Direction == TlsQuicStreamDirection.Bidirectional
        || Initiator == TlsQuicStreamInitiator.Server;

    /// <summary>Gets the offset the next byte we send will carry - RFC 9000 s19.8's "the
    /// offset of the next byte that would be sent".</summary>
    internal ulong SendOffset { get; private set; }

    /// <summary>Gets whether we have already sent a frame with s19.8's FIN bit, after which
    /// the stream has no more of our bytes to carry.</summary>
    internal bool FinSent { get; private set; }

    /// <summary>Gets whether the peer has sent a frame with s19.8's FIN bit.</summary>
    internal bool FinReceived => _finalSize is not null;

    /// <summary>Gets the stream's final size once the peer's FIN has arrived - s19.8: "The
    /// final size of the stream is the sum of the offset and the length of this
    /// frame."</summary>
    internal ulong? FinalSize => _finalSize;

    /// <summary>Gets the bytes delivered so far, in stream order. Bytes that arrived out of
    /// order are not here until the gap before them is filled.</summary>
    internal IReadOnlyList<byte> Received => _delivered;

    /// <summary>Gets the RFC 9000 s19.4 Application Protocol Error Code the peer abandoned its
    /// sending half with, or <see langword="null"/> if no RESET_STREAM has arrived.</summary>
    /// <remarks>THE OBSERVABLE THE HTTP/3 LAYER NEEDS, and it is the error code rather than a
    /// bare flag because RFC 9114 s8.1 gives the codes meaning a request has to act on -
    /// H3_REQUEST_CANCELLED (0x010c) is retryable on a new connection and H3_MESSAGE_ERROR
    /// (0x010e) is not. Reported as the number the peer sent, not mapped onto
    /// <see cref="TlsQuicTransportError"/>: s19.4's code is the APPLICATION's space and
    /// TlsQuicTransportError lists only what this library raises.</remarks>
    internal ulong? ResetErrorCode => _resetErrorCode;

    /// <summary>Gets whether the peer has reset this stream's receive half with an RFC 9000
    /// s19.4 RESET_STREAM.</summary>
    internal bool ResetReceived => _resetErrorCode is not null;

    /// <summary>Gets the RFC 9000 s19.5 Application Protocol Error Code the peer asked this
    /// endpoint to stop sending with, or <see langword="null"/> if no STOP_SENDING has
    /// arrived.</summary>
    internal ulong? StopSendingErrorCode => _stopSendingErrorCode;

    /// <summary>Gets whether the peer has asked this endpoint to stop sending on this stream,
    /// after which <see cref="TlsQuicStreamSet.Send"/> queues nothing more on it.</summary>
    internal bool SendStopped => _stopSendingErrorCode is not null;

    /// <summary>Gets whether this stream will deliver nothing further: the peer's FIN has
    /// arrived AND every byte before it has been delivered, or the peer reset the stream.
    /// </summary>
    /// <remarks>
    /// <para>FIN ARRIVING IS NOT THE SAME AS THE STREAM BEING DONE, because s19.8's FIN
    /// rides on a frame that may overtake an earlier one. The two are separate properties for
    /// that reason.</para>
    /// <para>A RESET IS COMPLETE AT WHATEVER IT DELIVERED, which is why it is a separate
    /// disjunct rather than something the length comparison could express. RFC 9000 s3.2 puts
    /// the receiving part in "Reset Recvd" on a RESET_STREAM and s4.5 says the final size is
    /// still established there - but the bytes below it never arrive, so
    /// <c>_finalSize == _delivered.Count</c> stays false forever and a caller waiting on this
    /// would wait until the idle timeout. That hang is the audit's finding 3.</para>
    /// </remarks>
    internal bool ReceiveComplete =>
        _resetErrorCode is not null || _finalSize == (ulong)_delivered.Count;

    // Advances the send offset and records the FIN. Separate from the frame building so that
    // TlsQuicStreamSet.Send charges the budget FIRST and moves nothing when the charge is
    // refused - the order TlsQuicPeerFlowControlBudget's row 22 exists to protect.
    internal void RecordSent(int length, bool fin)
    {
        SendOffset += (ulong)length;
        FinSent |= fin;
    }

    /// <summary>Gets whether this stream is holding bytes the peer has not granted credit
    /// for.</summary>
    internal bool HasBlockedData => _blocked.Count > 0;

    /// <summary>Gets how many bytes are held waiting for a grant.</summary>
    internal ulong BlockedBytes
    {
        get
        {
            var total = 0UL;
            foreach (var chunk in _blocked)
            {
                total += (ulong)chunk.Length;
            }

            return total;
        }
    }

    /// <summary>Gets whether a FIN has been accepted for sending, whether or not it has left
    /// yet.</summary>
    /// <remarks>THE TEST <c>TlsQuicStreamSet.Send</c> REFUSES ON, and it is this rather than
    /// <see cref="FinSent"/> because a FIN can now sit in the blocked queue for as long as the
    /// peer withholds credit. Accepting a second write in that window would put bytes after
    /// the end of the stream.</remarks>
    internal bool FinQueued => FinSent || _blockedFin;

    // Appends to the blocked queue. EVERY WRITE IS KEPT, INCLUDING AN EMPTY ONE THAT CARRIES NO
    // FIN: s19.8 says "When a Stream Data field has a length of 0, the offset in the STREAM
    // frame is the offset of the next byte that would be sent", which makes a zero-length frame
    // a frame with a meaning rather than a no-op to optimise away.
    // AZeroLengthStreamFrameIsQueuedRatherThanSkipped is the witness.
    internal void QueueForSend(ReadOnlyMemory<byte> data, bool fin)
    {
        _blocked.Add(data);
        _blockedFin |= fin;
    }

    // Takes as much of the head of the blocked queue as `available` covers, and reports
    // whether anything at all came out. Returns false rather than an empty chunk when the
    // queue is empty or the head is blocked, which is what ends TlsQuicStreamSet's drain loop.
    //
    // A ZERO-LENGTH HEAD IS ALWAYS TAKEN, because the only one that can exist carries the FIN
    // and RFC 9000 s19.8's FIN costs no flow-control credit - "All data sent in STREAM frames
    // counts toward this limit" (s19.9) counts data, and there is none. A body whose last
    // write was fin-only would otherwise stall behind an exhausted limit forever.
    internal bool TryTakeSendable(ulong available, out ReadOnlyMemory<byte> chunk, out bool fin)
    {
        chunk = default;
        fin = false;

        if (_blocked.Count == 0)
        {
            return false;
        }

        var head = _blocked[0];
        var take = (int)Math.Min((ulong)head.Length, available);

        if (take < head.Length)
        {
            if (take == 0)
            {
                return false;
            }

            // A PARTIAL TAKE NEVER CARRIES THE FIN, whatever the caller asked for: s19.8's
            // FIN "indicates that the frame marks the end of the stream", and the tail of this
            // entry has not left yet.
            chunk = head[..take];
            _blocked[0] = head[take..];
            return true;
        }

        chunk = head;
        _blocked.RemoveAt(0);
        fin = _blocked.Count == 0 && _blockedFin;
        return true;
    }

    // The two halves of s13.3's "only while the endpoint is blocked on the corresponding
    // limit", as a claim and a release. Claim returns true the FIRST time the condition holds
    // and false while it keeps holding; Release is called when the limit moves.
    internal bool TryClaimStreamDataBlockedSignal()
    {
        if (_streamDataBlockedSignalled)
        {
            return false;
        }

        _streamDataBlockedSignalled = true;
        return true;
    }

    internal void ReleaseStreamDataBlockedSignal() => _streamDataBlockedSignalled = false;

    // Takes one s19.8 STREAM frame's fields. Try-shaped: never throws, for any input.
    //
    // ORDER OF THE THREE CHECKS IS LOAD-BEARING and each is constructed so only it can reject
    // the input its own test supplies - the final-size checks come before the buffer bound so
    // that a frame past the final size is FINAL_SIZE_ERROR rather than whichever the buffer
    // happened to notice, and the buffer bound comes before any allocation.
    internal bool TryReceive(
        ulong offset, ReadOnlySpan<byte> data, bool fin, out TlsQuicTransportError error)
    {
        error = TlsQuicTransportError.NoError;

        // s19.8's own 2^62-1 bound is already enforced by TlsQuicStreamFrames.TryReadStream
        // before a frame reaches here, so this addition cannot overflow for a frame that came
        // off the wire. It is still written to be safe against a caller that hand-built one.
        var end = offset + (ulong)data.Length;
        if (end < offset)
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // s20.1 FINAL_SIZE_ERROR (0x06), all three of its numbered cases, in the order s20.1
        // prints them: "(1) An endpoint received a STREAM frame containing data that exceeded
        // the previously established final size, (2) an endpoint received a STREAM frame or a
        // RESET_STREAM frame containing a final size that was lower than the size of stream
        // data that was already received, or (3) an endpoint received a STREAM frame or a
        // RESET_STREAM frame containing a different final size to the one already
        // established."
        //
        // Case (1). A frame past a final size we already know, whether or not it carries a FIN
        // of its own.
        if (_finalSize is { } known && end > known)
        {
            error = TlsQuicTransportError.FinalSizeError;
            return false;
        }

        if (fin)
        {
            // Case (3), the different-final-size one. Checked before the delivered-length
            // comparison because a second FIN that agrees with the first is a legal
            // retransmission and must not be refused.
            if (_finalSize is { } established && established != end)
            {
                error = TlsQuicTransportError.FinalSizeError;
                return false;
            }

            // Case (2). A FIN whose final size is below what has ALREADY been delivered - the
            // one direction case (1) cannot catch, because on the first FIN there is no
            // established size to exceed.
            if (end < (ulong)_delivered.Count || end < HighestUndeliveredEnd())
            {
                error = TlsQuicTransportError.FinalSizeError;
                return false;
            }
        }

        // OUR BOUND, AND NOW IT IS THE ONE WE ADVERTISED - see this file's header. s20.1
        // FLOW_CONTROL_ERROR (0x03): "An endpoint received more data than it permitted in its
        // advertised data limits". Before any allocation, so an absurd offset is a refusal
        // rather than a request for a terabyte.
        if (end > _receiveLimit)
        {
            error = TlsQuicTransportError.FlowControlError;
            return false;
        }

        // AND THE CONNECTION-LEVEL ONE, WHICH DID NOT EXIST BEFORE C9. s19.9: "All data sent
        // in STREAM frames counts toward this limit." Charged in the units s19.10 names for
        // the per-stream limit - "an endpoint accounts for the largest received offset of data
        // that is sent or received on the stream. Loss or reordering can mean that the largest
        // received offset on a stream can be greater than the total size of data received on
        // that stream" - so a retransmission of bytes we already hold advances nothing and
        // costs nothing.
        var advance = end > _largestReceivedOffset ? end - _largestReceivedOffset : 0;
        if (!_set.TryAdmitConnectionData(advance))
        {
            error = TlsQuicTransportError.FlowControlError;
            return false;
        }

        _largestReceivedOffset = Math.Max(_largestReceivedOffset, end);

        if (fin)
        {
            _finalSize = end;
        }

        // s19.8: "When a Stream Data field has a length of 0, the offset in the STREAM frame
        // is the offset of the next byte that would be sent." A zero-length frame therefore
        // carries no bytes to buffer and is NOT a gap: it is legal, it is how a FIN with no
        // data arrives, and storing an empty piece would leave an entry no drain could ever
        // consume. This is the zero-versus-absent case for the DATA field, and it is different
        // from an absent Offset, which s19.8 gives the value 0.
        if (data.Length > 0)
        {
            Buffer(offset, data);
            Drain();
        }

        CreditReceiveWindow();
        return true;
    }

    // Takes one s19.4 RESET_STREAM frame's two fields. Try-shaped like TryReceive and for the
    // same reason: this is peer input.
    //
    // THE THREE CHECKS ARE s20.1's FINAL_SIZE_ERROR CASES, WHICH NAME RESET_STREAM EXPLICITLY -
    // "(2) an endpoint received a STREAM frame OR A RESET_STREAM FRAME containing a final size
    // that was lower than the size of stream data that was already received, or (3) an endpoint
    // received a STREAM frame OR A RESET_STREAM FRAME containing a different final size to the
    // one already established." Case (1) is about a STREAM frame's data and has no analogue
    // here: a RESET_STREAM carries no bytes to exceed anything with.
    //
    // AND THE FINAL SIZE IS CHARGED FOR, WHICH IS THE HALF A DIRECTION CHECK CANNOT DO. s4.5:
    // "A receiver MUST use the final size of the stream to account for all bytes sent on the
    // stream in its connection level flow controller." So a reset at offset N spends the same
    // credit N bytes of STREAM frames would have, and a reset claiming a final size past the
    // limit we advertised is s20.1's FLOW_CONTROL_ERROR exactly as those bytes would have been.
    // Without this a peer could reset a stream at 2^62-1 and pay nothing.
    //
    // ORDER IS LOAD-BEARING, as it is in TryReceive: the final-size checks come before the
    // flow-control ones so that a contradictory reset is FINAL_SIZE_ERROR rather than whichever
    // limit happened to notice, and nothing is mutated until every check has passed.
    internal bool TryReceiveReset(
        ulong finalSize, ulong applicationProtocolErrorCode, out TlsQuicTransportError error)
    {
        error = TlsQuicTransportError.NoError;

        // Case (3), the different-final-size one. A second RESET_STREAM agreeing with the first
        // is a legal retransmission and must not be refused - s13.3 gives RESET_STREAM the
        // "resend" treatment on loss, so a duplicate is ordinary rather than hostile.
        if (_finalSize is { } established && established != finalSize)
        {
            error = TlsQuicTransportError.FinalSizeError;
            return false;
        }

        // Case (2). Both comparisons, for the reason TryReceive's pair of them exists: the
        // delivered prefix and the pieces held behind a gap are two different quantities and a
        // final size can be below either one alone.
        if (finalSize < (ulong)_delivered.Count || finalSize < HighestUndeliveredEnd())
        {
            error = TlsQuicTransportError.FinalSizeError;
            return false;
        }

        if (finalSize > _receiveLimit)
        {
            error = TlsQuicTransportError.FlowControlError;
            return false;
        }

        var advance = finalSize > _largestReceivedOffset
            ? finalSize - _largestReceivedOffset
            : 0;
        if (!_set.TryAdmitConnectionData(advance))
        {
            error = TlsQuicTransportError.FlowControlError;
            return false;
        }

        _largestReceivedOffset = Math.Max(_largestReceivedOffset, finalSize);
        _finalSize = finalSize;
        _resetErrorCode = applicationProtocolErrorCode;

        // s4.5's SHOULD, taken: "A receiver SHOULD discard any data it already received on that
        // stream." The delivered prefix is NOT discarded - it is already the application's and
        // Received is a read-only view a caller may be holding - but the pieces stranded behind
        // a gap can never be completed now that the sender has stopped, so holding them is the
        // finding-2 amplification with a different name.
        _undelivered.Clear();

        // The credit for everything below the final size falls due at once - see CreditedPrefix
        // - and this is also what reports the stream finished for s4.6's MAX_STREAMS purposes.
        CreditReceiveWindow();
        return true;
    }

    // RFC 9000 s19.5's frame, applied. Returns the final size the answering RESET_STREAM has to
    // carry, which s3.5 makes the bytes this endpoint has already put on the wire.
    //
    // LATCHED, NOT COUNTED. A second STOP_SENDING for the same stream is refused by the caller
    // rather than answered twice, so this is only ever reached once per stream.
    internal ulong StopSending(ulong applicationProtocolErrorCode)
    {
        _stopSendingErrorCode = applicationProtocolErrorCode;

        // s3.5: "the sender ... [can] discard any data that is still pending". The queue holds
        // slices of the CALLER's buffer rather than copies - see QueueForSend - so this frees a
        // reference rather than memory; what it really does is make HasBlockedData false, so
        // Drain's s19.13 STREAM_DATA_BLOCKED arm cannot ask the peer for credit to send bytes
        // the peer has just said it does not want.
        _blocked.Clear();
        return SendOffset;
    }

    // Raises this stream's limit, and the connection's, to cover what has been delivered.
    //
    // DELIVERED IS THE UNIT, NOT RECEIVED. s19.10 counts the largest received offset against
    // the limit, but a window is only free to re-grant once the bytes are out of the
    // reassembler and in the application's hands - _delivered is exactly that set, so a stream
    // sitting on a gap does not credit the peer for bytes it cannot yet use.
    //
    // MONOTONIC BY CONSTRUCTION. _delivered never shrinks, so the new limit is never below the
    // old one, and s19.10 needs that: "MAX_STREAM_DATA frames that do not increase the stream
    // limit MUST be ignored" - a frame that lowered it would be discarded and the transfer
    // would stall at the old value with nothing to say why.
    private void CreditReceiveWindow()
    {
        var delivered = CreditedPrefix;
        _set.CreditConnectionWindow(delivered - _creditedToConnection);
        _creditedToConnection = delivered;

        // RFC 9000 s4.6's OTHER credit, and this is the one place that can know it is due. A
        // stream is finished for receive purposes when its final size is established AND every
        // byte up to it has reached the application - the same "delivered, not received"
        // distinction this method already turns on. Reported once; _finalSize cannot move
        // afterwards, because a second FIN at a different offset is a FINAL_SIZE_ERROR.
        if (!_receiveCompleteReported && _finalSize is { } finalSize && delivered >= finalSize)
        {
            _receiveCompleteReported = true;
            _set.OnStreamReceiveComplete(this);
        }

        // Outstanding credit still above the threshold, so nothing is owed. A window of 0
        // takes this branch for every input - 0 - 0 is not below 0 / 2 - which is right: an
        // endpoint that granted nothing has nothing to re-grant, and the only frame that
        // reaches here on such a stream is a zero-length one.
        if (_receiveLimit - delivered
            >= _receiveWindow / TlsQuicLocalFlowControlSpec.ReceiveWindowUpdateDivisor)
        {
            return;
        }

        // CLAMPED, BECAUSE THE FRAME CANNOT CARRY MORE. s19.10's Maximum Stream Data is a
        // variable-length integer, so s16 caps it at 2^62-1; a caller advertising a window
        // near that maximum would otherwise reach TlsQuicFlowControlFrames' write-side bound
        // and turn a received frame into a throw, which this file's header forbids. The clamp
        // is not a refusal: at that point the peer may send every byte a stream can carry.
        _receiveLimit = delivered > QuicVariableLengthInteger.MaximumValue - _receiveWindow
            ? QuicVariableLengthInteger.MaximumValue
            : delivered + _receiveWindow;
        _maximumStreamDataOwed = true;
    }

    // How much of this stream's window CreditReceiveWindow may hand back, and it is the
    // delivered prefix everywhere except after a reset.
    //
    // RFC 9000 s4.5 IS WHY THE RESET CASE IS THE FINAL SIZE AND NOT ZERO: "A receiver MUST use
    // the final size of the stream to account for all bytes sent on the stream in its
    // connection level flow controller." Those bytes were charged when the reset arrived and no
    // byte below the final size will ever be delivered, so a credit that stayed at
    // _delivered.Count would leak the difference out of the connection window for the lifetime
    // of the connection - one reset stream at a time, until a transfer that had credit stalled
    // with nothing to say why.
    private ulong CreditedPrefix => _resetErrorCode is not null && _finalSize is { } size
        ? size
        : (ulong)_delivered.Count;

    // Takes the pending MAX_STREAM_DATA grant, if the last receive earned one. Try-shaped and
    // one-shot: the set queues at most one frame per grant, and s19.10's "frames that do not
    // increase the stream limit MUST be ignored" makes a repeat harmless but pointless.
    internal bool TryTakeMaximumStreamData(out ulong maximumStreamData)
    {
        maximumStreamData = _receiveLimit;
        var owed = _maximumStreamDataOwed;
        _maximumStreamDataOwed = false;
        return owed;
    }

    // Stores only the bytes of [offset, offset + data.Length) that no held piece and no
    // delivered byte already covers, as one or more pieces that keep _undelivered sorted and
    // gap-free of each other. NEVER stores a byte twice, which is the whole of the memory bound
    // the field comment states.
    //
    // ponytail: the scan for the insertion point is linear, not a binary search, and the insert
    // is a List memmove - so a stream holding k pieces costs O(k) per frame. k is bounded by
    // the per-stream window in BYTES, so the ceiling is a peer that sends a window's worth of
    // one-byte frames in descending order. Make it a binary search over a gap list if a stream
    // ever legitimately holds thousands of pieces; the memory bound, which is what the
    // amplification defect was about, does not depend on it.
    private void Buffer(ulong offset, ReadOnlySpan<byte> data)
    {
        var delivered = (ulong)_delivered.Count;

        // ALREADY DELIVERED IN FULL: a retransmission of bytes the application has. RFC 9000
        // s2.2 makes a comparison OPTIONAL here - "An endpoint MAY treat receipt of different
        // data at the same offset within a stream as a connection error of type
        // PROTOCOL_VIOLATION" - and this endpoint takes the other branch of the MAY and
        // ignores the duplicate. Stated rather than silent, because a reader looking for the
        // comparison should find out that its absence is a choice s2.2 grants.
        if (offset + (ulong)data.Length <= delivered)
        {
            return;
        }

        // PARTIALLY DELIVERED: the front is trimmed rather than the piece being rejected. A
        // retransmission that starts before the delivered end and runs past it carries bytes we
        // do not have, and dropping it would strand them. Trimming HERE rather than in Drain is
        // what lets Drain assume every held piece begins at or after the delivered prefix.
        if (offset < delivered)
        {
            data = data[(int)(delivered - offset)..];
            offset = delivered;
        }

        // The first held piece that could overlap: everything before it ends at or before this
        // frame's start, so no comparison against it can subtract anything.
        var index = 0;
        while (index < _undelivered.Count && EndOf(_undelivered[index]) <= offset)
        {
            index++;
        }

        while (!data.IsEmpty)
        {
            // Past the last held piece, or entirely inside the gap in front of the next one:
            // what is left is new in full and goes in as one piece.
            if (index == _undelivered.Count
                || _undelivered[index].Offset >= offset + (ulong)data.Length)
            {
                _undelivered.Insert(index, (offset, data.ToArray()));
                return;
            }

            var held = _undelivered[index];

            // A gap in front of the next held piece takes the bytes that fall in it, and the
            // walk then resumes at that piece with what is left.
            if (held.Offset > offset)
            {
                var gap = (int)(held.Offset - offset);
                _undelivered.Insert(index, (offset, data[..gap].ToArray()));
                index++;
                data = data[gap..];
                offset = held.Offset;
            }

            // The held piece now starts at or before this offset and ends past it, so it
            // already covers the next `overlap` bytes. THE HELD COPY WINS, which is the same
            // branch of s2.2's MAY the delivered-prefix check above takes: differing data at
            // one offset is ignored rather than made a PROTOCOL_VIOLATION.
            var overlap = EndOf(held) - offset;
            if (overlap >= (ulong)data.Length)
            {
                return;
            }

            data = data[(int)overlap..];
            offset = EndOf(held);
            index++;
        }
    }

    private static ulong EndOf((ulong Offset, byte[] Data) piece) =>
        piece.Offset + (ulong)piece.Data.Length;

    // Moves every piece that is now contiguous with the delivered prefix into it.
    //
    // ONE FORWARD PASS, NOT A FIXED POINT, and that is Buffer's invariant being spent rather
    // than an optimisation. The pieces are sorted and none overlaps another, so the ones that
    // are contiguous with _delivered are exactly a PREFIX of the list: the first piece that
    // starts past the delivered end is a gap, and every piece after it starts later still.
    private void Drain()
    {
        var taken = 0;
        while (taken < _undelivered.Count
            // STRICTLY GREATER ENDS THE PASS, so a piece that starts exactly where the
            // delivered prefix ends is taken. `<` here - `>=` in the old form - would stall
            // every stream on its first frame.
            && _undelivered[taken].Offset <= (ulong)_delivered.Count)
        {
            var (offset, piece) = _undelivered[taken];

            // Buffer trims against the delivered prefix on the way in and the pieces do not
            // overlap, so this skip is 0 for every input this class can produce. It is kept so
            // that the two are independent: a piece that did start behind the prefix would be
            // appended at the wrong place rather than caught, and that is silent corruption.
            var skip = (int)((ulong)_delivered.Count - offset);
            if (skip < piece.Length)
            {
                _delivered.AddRange(piece.AsSpan(skip));
            }

            taken++;
        }

        if (taken > 0)
        {
            _undelivered.RemoveRange(0, taken);
        }
    }

    private ulong HighestUndeliveredEnd() =>
        _undelivered.Count == 0 ? 0 : EndOf(_undelivered[^1]);

    /// <summary>Gets how many bytes this stream is holding out of order, waiting for the gap in
    /// front of them to be filled.</summary>
    /// <remarks>BOUNDED BY THIS STREAM'S RECEIVE WINDOW, which is the property the reassembly
    /// exists to have and the one a test can assert. Every byte here lies below
    /// <see cref="ReceiveLimit"/> and is stored exactly once, so a peer cannot buy more of this
    /// endpoint's memory than it holds RFC 9000 s19.10 credit for. Computed rather than
    /// counted, on <see cref="BlockedBytes"/>'s reasoning: the piece list is short and nothing
    /// on the receive path reads this.</remarks>
    internal ulong UndeliveredBytes
    {
        get
        {
            var total = 0UL;
            foreach (var piece in _undelivered)
            {
                total += (ulong)piece.Data.Length;
            }

            return total;
        }
    }

    /// <summary>Gets the offset this endpoint currently permits the peer to reach on this
    /// stream: the limit it advertised for this stream's type, raised by every MAX_STREAM_DATA
    /// sent since.</summary>
    internal ulong ReceiveLimit => _receiveLimit;

    /// <summary>Gets the highest offset any received frame reached, which is the quantity RFC
    /// 9000 s19.10 counts against the limit.</summary>
    internal ulong LargestReceivedOffset => _largestReceivedOffset;
}

/// <summary>Every stream on one connection: the ones we opened against the peer's RFC 9000
/// s18.2 allowance, and the ones the peer opened by sending a STREAM frame on them.</summary>
internal sealed class TlsQuicStreamSet
{
    private readonly TlsQuicPeerFlowControlBudget _budget;
    private readonly Dictionary<ulong, TlsQuicStream> _streams = [];
    private readonly List<TlsQuicStream> _peerInitiated = [];
    private readonly List<TlsQuicFrame> _pending = [];

    // TASK A3-8's 1-RTT REPAIR QUEUE, AND IT IS A SECOND LIST RATHER THAN AN INSERT INTO THE
    // FIRST. RFC 9000 s13.3: "Endpoints SHOULD prioritize retransmission of data over sending
    // new data, unless priorities specified by the application indicate otherwise." A repair
    // pushed to the front of _pending would satisfy that sentence and break the one
    // TakePendingFrames already makes - "QUEUE ORDER IS SEND ORDER, and it is preserved rather
    // than sorted" - because inserting at the front of a queue of two consecutive STREAM frames
    // reorders them relative to each other on the second repair. Two lists concatenated in
    // order preserve both.
    private readonly List<TlsQuicFrame> _repairs = [];
    private ulong _nextClientBidirectionalOrdinal;
    private ulong _nextClientUnidirectionalOrdinal;
    private ulong _connectionReceiveLimit;
    private ulong _connectionReceived;
    private ulong _connectionDelivered;
    private bool _maximumDataOwed;

    // The connection-scoped half of s13.3's "only while the endpoint is blocked on the
    // corresponding limit"; TlsQuicStream carries the stream-scoped one. See Drain.
    private bool _dataBlockedSignalled;

    // RFC 9000 s14.2's smallest allowed maximum datagram size, which s14.3 makes DPLPMTUD's
    // BASE_PLPMTU. The floor a connection that has discovered nothing may still send at.
    private const int DefaultDatagramPayloadBudget = 1200;

    // The most one STREAM frame can cost on top of its data inside a 1-RTT datagram, summed
    // from the widest legal form of every field rather than from the shape this client happens
    // to send:
    //
    //   1  s17.3.1 short header first byte
    //   20 Destination Connection ID, s17.3.1's maximum
    //   4  packet number, s17.1's "encoded in 1 to 4 bytes"
    //   1  s19.8 STREAM frame type
    //   8  Stream ID varint, s16 Table 4's widest
    //   8  Offset varint
    //   8  Length varint
    //   16 s5.3 AEAD tag
    //
    // OVERSHOOTING IS THE SAFE DIRECTION and is why the widest form is used throughout: this is
    // subtracted from a budget, so a figure that is too large costs a few bytes of payload per
    // datagram while one that is too small builds a datagram over the path MTU. The shipped
    // presets use an 8-byte connection ID and a 1-byte packet number, so the real cost is
    // around 40 and this reserves 66.
    private const int OneRttStreamFrameOverheadBound = 1 + 20 + 4 + 1 + 8 + 8 + 8 + 16;

    // Reused by TakePendingFrames so the packing loop allocates once per stream set rather
    // than once per frame measured.
    private readonly List<byte> _measureScratch = new(64);

    /// <param name="budget">The PEER's advertised RFC 9000 s18.2 limits, which bound what this
    /// endpoint may send.</param>
    /// <param name="local">OUR advertised s18.2 limits, which bound what the peer may send and
    /// are the same object the ClientHello's transport parameters are emitted from. Defaulted
    /// so a test that cares only about the send side need not state it; the default is the
    /// client capture's, exactly as it is on the spec.</param>
    /// <exception cref="ArgumentNullException"><paramref name="budget"/> is
    /// <see langword="null"/>.</exception>
    internal TlsQuicStreamSet(
        TlsQuicPeerFlowControlBudget budget, TlsQuicLocalFlowControlSpec? local = null)
    {
        ArgumentNullException.ThrowIfNull(budget);
        _budget = budget;
        LocalFlowControl = local ?? new TlsQuicLocalFlowControlSpec();
        _connectionReceiveLimit = LocalFlowControl.InitialMaxData;
    }

    /// <summary>The bytes of QUIC payload one datagram may carry - the connection's current
    /// path MTU less whatever the transport prepends. Bounds how much stream data one STREAM
    /// frame is allowed to take.</summary>
    /// <remarks>
    /// <para>SETTABLE, BECAUSE IT MOVES. RFC 8899's search raises the PLPMTU as probes are
    /// acknowledged and black hole detection drops it back, so this is a value the connection
    /// pushes in rather than one this type derives once.</para>
    /// <para>THE DEFAULT IS THE RFC's FLOOR AND NOT AN UNBOUNDED VALUE. A stream set that
    /// nobody configured must not be the one that builds a 32-kilobyte datagram; 1200 is what
    /// RFC 9000 s14.2 permits without any discovery at all, so the unconfigured case is the
    /// conservative one.</para>
    /// </remarks>
    internal int DatagramPayloadBudget { get; set; } = DefaultDatagramPayloadBudget;

    /// <summary>Gets the s18.2 limits this endpoint advertised, which every receive-side
    /// refusal below is measured against.</summary>
    internal TlsQuicLocalFlowControlSpec LocalFlowControl { get; }

    /// <summary>Gets the total across every stream that this endpoint currently permits the
    /// peer to send: our initial_max_data, raised by every MAX_DATA sent since.</summary>
    internal ulong ConnectionReceiveLimit => _connectionReceiveLimit;

    /// <summary>Gets the streams the peer opened, in the order their first STREAM frame
    /// arrived.</summary>
    internal IReadOnlyList<TlsQuicStream> PeerInitiated => _peerInitiated;

    /// <summary>Gets a stream by its RFC 9000 s2.1 identifier, or <see langword="null"/> if
    /// neither endpoint has opened it.</summary>
    internal TlsQuicStream? Find(ulong streamId) =>
        _streams.TryGetValue(streamId, out var stream) ? stream : null;

    /// <summary>Opens the next client-initiated unidirectional stream, spending one of the
    /// peer's initial_max_streams_uni (0x09) openings.</summary>
    /// <remarks>THE ALLOWANCE IS STATIC. A4-minimal handles no MAX_STREAMS frame and sends no
    /// STREAMS_BLOCKED, so once the peer's advertised count is spent nothing raises it -
    /// TlsQuicPeerFlowControlBudget.OpenUnidirectionalStream throws rather than opening a
    /// stream the peer never permitted.</remarks>
    /// <exception cref="InvalidOperationException">The peer's initial_max_streams_uni is
    /// exhausted.</exception>
    internal TlsQuicStream OpenUnidirectional() => Open(
        TlsQuicStreamDirection.Unidirectional,
        ref _nextClientUnidirectionalOrdinal,
        _budget.OpenUnidirectionalStream);

    /// <summary>Opens the next client-initiated bidirectional stream, spending one of the
    /// peer's initial_max_streams_bidi (0x08) openings and taking its per-stream credit from
    /// initial_max_stream_data_bidi_remote (0x06).</summary>
    /// <remarks>Static for the same reason <see cref="OpenUnidirectional"/> is.</remarks>
    /// <exception cref="InvalidOperationException">The peer's initial_max_streams_bidi is
    /// exhausted.</exception>
    internal TlsQuicStream OpenBidirectional() => Open(
        TlsQuicStreamDirection.Bidirectional,
        ref _nextClientBidirectionalOrdinal,
        _budget.OpenBidirectionalStream);

    // THE ORDINAL ADVANCES ONLY AFTER THE BUDGET IS SPENT. A refused open that had already
    // taken an ordinal would leave a hole in s2.1's numbering, and RFC 9000 s3.2 makes a
    // stream id the peer has not seen opened a stream it must open implicitly - so the hole
    // would become a stream on the peer's side that nothing on ours ever sends to.
    private TlsQuicStream Open(
        TlsQuicStreamDirection direction,
        ref ulong ordinal,
        Func<TlsQuicPeerFlowControlBudget.TlsQuicStreamBudget> spend)
    {
        var budget = spend();
        var stream = new TlsQuicStream(
            TlsQuicStreamId.From(TlsQuicStreamInitiator.Client, direction, ordinal),
            budget,
            this);
        ordinal++;
        _streams.Add(stream.Id, stream);
        return stream;
    }

    /// <summary>Queues RFC 9000 s19.8 STREAM frames for the next 1-RTT packet, sending as much
    /// as the peer's credit covers and holding the rest until a grant raises it.</summary>
    /// <remarks>
    /// <para>THIS NO LONGER REFUSES A WRITE LARGER THAN THE CREDIT, AND THAT IS THE TASK. The
    /// old contract threw, on the reasoning that "A4-minimal has no MAX_STREAM_DATA or MAX_DATA
    /// to wait for - so there is no 'later' in which the send could succeed". There is now:
    /// <c>ReceiveFlowControlFrame</c> applies both, so the write is split at
    /// <see cref="TlsQuicPeerFlowControlBudget.TlsQuicStreamBudget.Available"/>, the part that
    /// fits is queued and the tail waits on the stream. NOTHING IS EVER SENT PAST A LIMIT -
    /// the split is what keeps the FLOW_CONTROL_ERROR the old throw was avoiding off the wire;
    /// what changed is that the excess is deferred instead of rejected.</para>
    /// <para>THE QUEUE IS NOT BOUNDED, AND THAT IS THE POINT RATHER THAN AN OVERSIGHT. A cap
    /// would be the ceiling this task removed, wearing a different number. What it holds is
    /// slices of the CALLER's own buffer - see <c>TlsQuicStream.QueueForSend</c> - so the bytes
    /// are the application's already and nothing is copied; a peer that never grants cannot
    /// make this grow, it can only stop it shrinking, and the wait is bounded by the
    /// connection's deadline. A caller that queues more than it can afford has an application
    /// problem, not a flow-control one.</para>
    /// <para>AND THE PEER IS TOLD, which is the half without which the deferral is a hang.
    /// s19.13: "A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15) when it wishes to
    /// send data but is unable to do so due to stream-level flow control", and s19.12 says the
    /// same for DATA_BLOCKED and connection-level. A peer that is never told has no reason to
    /// grant, so the blocked signal is what turns "wait" into "wait for something".</para>
    /// <para>THE LEN BIT IS ALWAYS SET. s19.8's implicit form - "If this bit is set to 0, the
    /// Length field is absent and the Stream Data field extends to the end of the packet" -
    /// would confine the frame to the end of its packet, and TryBuildApplicationPacket may put
    /// an ACK after it when TlsQuicConnectionSpec.AckLeadsInPacket is false.</para>
    /// <para>THE OFF BIT FOLLOWS THE OFFSET. s19.8 makes offset 0 expressible either way -
    /// "When the Offset field is absent, the offset is 0" - so a stream's first frame omits
    /// the field and every later one carries it. That is a choice, not a derivation, and it is
    /// the shortest of the two encodings.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="stream"/> is
    /// <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">The stream is receive-only, or its FIN has
    /// already been accepted for sending.</exception>
    internal void Send(TlsQuicStream stream, ReadOnlyMemory<byte> data, bool fin = false)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (!stream.CanSend || stream.Budget is not { })
        {
            throw new InvalidOperationException(
                $"Stream {stream.Id} is server-initiated and unidirectional, so RFC 9000 s2.1 "
                    + "makes it receive-only for this endpoint and there is nothing to send "
                    + "on it.");
        }

        if (stream.FinQueued)
        {
            throw new InvalidOperationException(
                $"Stream {stream.Id} has already carried RFC 9000 s19.8's FIN bit, which "
                    + "\"indicates that the frame marks the end of the stream\", so its final "
                    + "size is fixed and no further byte can be sent on it.");
        }

        // RFC 9000 s3.5's whole point, and it is a DROP rather than a throw. The peer asked us
        // to stop writing and s19.5's answer has already gone out with a final size; accepting
        // the bytes would put them past the end of a stream we told the peer was finished. It
        // is not the caller's mistake either - a STOP_SENDING can arrive between two of its
        // writes - so the send side's usual "caller-chosen input, so it throws" rule does not
        // apply. SendStopped and StopSendingErrorCode are how a caller finds out; nothing in
        // this assembly can make the write and the frame race differently.
        if (stream.SendStopped)
        {
            return;
        }

        stream.QueueForSend(data, fin);
        Drain(stream);
    }

    // Moves whatever the peer's credit now covers out of one stream's blocked queue and into
    // the pending list, then signals whichever limit stopped it. THE ONE PLACE BOTH THE FIRST
    // SEND AND A LATER GRANT GO THROUGH, so a byte cannot leave by a path that skips a limit.
    //
    // Available IS RE-READ EVERY TURN and not hoisted: Consume charges the connection pool as
    // well as the stream, so two streams draining in one pass see each other's spending.
    private void Drain(TlsQuicStream stream)
    {
        if (stream.Budget is not { } budget)
        {
            return;
        }

        // The second half of the s3.5 stop, and it is the one a GRANT reaches: ReceiveMaxData
        // and TryReceiveMaxStreamData both drain every blocked stream, so a limit rising after
        // a STOP_SENDING would otherwise flush exactly the bytes the peer refused.
        if (stream.SendStopped)
        {
            return;
        }

        // RFC 8899 s4.4: "A PL is unable to send a packet (other than a probe packet) with a
        // size larger than the current PLPMTU at the network layer. To avoid this, a PL MAY be
        // designed to segment data blocks larger than the MPS into multiple datagrams." This
        // take is that segmentation, and the cap is the MPS.
        //
        // TWO LIMITS, AND THEY ARE INDEPENDENT. The peer's flow-control credit says how many
        // bytes it will ACCEPT; the datagram budget says how many will FIT on the path. Before
        // the second one existed this loop took everything the first allowed - which for a
        // request body under a generous initial_max_stream_data meant one STREAM frame of the
        // whole body and one datagram to match.
        var perFrame = (ulong)Math.Max(1, DatagramPayloadBudget - OneRttStreamFrameOverheadBound);

        while (stream.TryTakeSendable(
            Math.Min(budget.Available, perFrame), out var chunk, out var fin))
        {
            var rawType = (ulong)TlsQuicFrameType.Stream | TlsQuicStreamFrames.LengthBit;
            if (stream.SendOffset != 0)
            {
                rawType |= TlsQuicStreamFrames.OffsetBit;
            }

            if (fin)
            {
                rawType |= TlsQuicStreamFrames.FinBit;
            }

            budget.Consume((ulong)chunk.Length);
            _pending.Add(new TlsQuicFrame
            {
                RawType = rawType,
                StreamId = stream.Id,
                Offset = stream.SendOffset,
                Data = chunk,
            });
            stream.RecordSent(chunk.Length, fin);
        }

        if (!stream.HasBlockedData)
        {
            return;
        }

        // WHICH FRAME IS DECIDED BY WHICH LIMIT IS AT ZERO, and both can be, in which case
        // both are sent: s19.12 and s19.13 name two different scopes and a peer that raised
        // only the one it was told about would leave the sender blocked on the other. Guarded
        // by HasBlockedData above so that a write that fitted exactly signals nothing - the
        // sender is not blocked, it is finished.
        if (budget.Remaining == 0 && stream.TryClaimStreamDataBlockedSignal())
        {
            // s19.13's field is "the OFFSET of the stream at which the blocking occurred",
            // where s19.12's is "the connection-level LIMIT at which blocking occurred" - a
            // real asymmetry in the extract, not a paraphrase. The two readings coincide
            // HERE and only because of the guard one line up: reaching this with
            // budget.Remaining at 0 means every granted byte has been sent, so the send offset
            // IS the limit. AStreamDataBlockedFrameCarriesTheOffsetWhichIsAlsoTheLimit asserts
            // it against both, so a future stream that blocks with credit to spare - a
            // datagram-sized cap, say - would fail rather than quietly pick one.
            _pending.Add(new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.StreamDataBlocked,
                StreamId = stream.Id,
                MaximumStreamData = stream.SendOffset,
            });
        }

        if (_budget.RemainingConnectionData == 0 && !_dataBlockedSignalled)
        {
            _dataBlockedSignalled = true;
            _pending.Add(new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.DataBlocked,
                MaximumData = _budget.ConnectionLimit,
            });
        }
    }

    /// <summary>Gets whether anything is queued for the next 1-RTT packet.</summary>
    internal bool HasPendingFrames => _pending.Count > 0 || _repairs.Count > 0;

    /// <summary>Queues one connection-scoped 1-RTT frame onto the same pending list the
    /// flow-control grants use.</summary>
    /// <remarks>
    /// <para>THE STREAM SET OWNS THE ONLY 1-RTT FRAME QUEUE IN THIS ASSEMBLY, which is why a
    /// connection-scoped frame comes through here rather than getting a second one. Everything
    /// that queue already does - the datagram budget in TakePendingFrames, coalescing behind an
    /// ACK, and s13.3 repair on loss - is machinery a private list on the connection would have
    /// to grow again and would grow worse.</para>
    /// <para>Used by RETIRE_CONNECTION_ID (RFC 9000 s19.16). Both it and MAX_STREAMS below
    /// arrive only after the handshake, by which point this set exists.</para>
    /// </remarks>
    /// <param name="frame">The frame to send on the next 1-RTT packet that has room.</param>
    internal void QueueConnectionFrame(in TlsQuicFrame frame) => _pending.Add(frame);

    /// <summary>Reports that a stream has received everything it ever will, so a peer-initiated one can be credited back under RFC 9000 s4.6.</summary>
    /// <param name="stream">The stream whose receive side is finished.</param>
    internal void OnStreamReceiveComplete(TlsQuicStream stream)
    {
        // ponytail: linear scan over the peer-initiated list. Plain h3 opens three of them and
        // the list is never pruned, so this is three comparisons once per stream; make it a
        // HashSet if server push or WebTransport ever puts real numbers through here.
        if (!_peerInitiated.Contains(stream))
        {
            return;
        }

        CreditPeerStream(TlsQuicStreamId.DirectionOf(stream.Id));
    }

    /// <summary>
    /// RFC 9000 s4.6: credits the peer one more stream of <paramref name="direction"/>, and
    /// queues MAX_STREAMS when enough have accumulated to be worth a frame.
    /// </summary>
    /// <remarks>
    /// <para>CUMULATIVE, NOT A LIVE COUNT. s19.11's Maximum Streams is "a count of the
    /// cumulative number of streams of the corresponding type that can be opened over the
    /// lifetime of the connection", so the grant is the initial limit plus the number of peer
    /// streams that have finished - which is why nothing has to be removed from
    /// <c>_streams</c> for this to be correct.</para>
    /// <para>THE THRESHOLD IS THE SAME SHAPE THE DATA GRANTS USE - a fraction of the window
    /// rather than one frame per stream - so a peer that opens and closes streams steadily gets
    /// grants at a rate proportional to the limit rather than one per close. Like
    /// <c>TlsQuicLocalFlowControlSpec.ReceiveWindowUpdateDivisor</c>, the fraction is this
    /// library's choice and no capture bounds it.</para>
    /// <para>ADVERTISED LIMIT ZERO MEANS NO GRANT, EVER. A limit that was never advertised is
    /// zero under s18.2 - see TlsQuicLocalFlowControlSpec.AsAdvertisedBy - and raising it from
    /// this side would hand the peer a budget the ClientHello said it did not have.</para>
    /// </remarks>
    /// <param name="direction">The direction of the stream that finished.</param>
    internal void CreditPeerStream(TlsQuicStreamDirection direction)
    {
        var index = direction == TlsQuicStreamDirection.Unidirectional ? 1 : 0;
        var initial = LocalFlowControl.PeerStreamLimitFor(direction);
        if (initial == 0)
        {
            return;
        }

        _peerStreamsFinished[index]++;
        var granted = PeerStreamLimitNow(direction);
        var wanted = initial + _peerStreamsFinished[index];

        // s19.11's Maximum Streams "MUST NOT exceed 2^60", and a grant above that is a
        // FRAME_ENCODING_ERROR at the peer rather than generosity.
        if (wanted > MaximumStreamsCeiling)
        {
            wanted = MaximumStreamsCeiling;
        }

        if (wanted - granted < Math.Max(1UL, initial / StreamCreditUpdateDivisor))
        {
            return;
        }

        _peerStreamGranted[index] = wanted;
        _pending.Add(new TlsQuicFrame
        {
            RawType = (ulong)(direction == TlsQuicStreamDirection.Unidirectional
                ? TlsQuicFrameType.MaxStreams | (TlsQuicFrameType)1
                : TlsQuicFrameType.MaxStreams),
            MaximumStreams = wanted,
        });
    }

    /// <summary>The stream count of <paramref name="direction"/> this endpoint has actually
    /// told the peer it may open: the s19.11 MAX_STREAMS grant if one has been sent, and the
    /// s18.2 initial parameter otherwise.</summary>
    /// <remarks>
    /// <para>THE ONE SOURCE FOR BOTH SIDES OF THE NUMBER, and that is the point rather than a
    /// tidying. Advertisement and enforcement drifting apart is exactly the shape of C9's
    /// finding 2, recorded in this file's header - "enforcing a number other than the
    /// advertised one is not a placeholder, it is a divergence" - and it came back at the
    /// stream COUNT once MAX_STREAMS started moving: CreditPeerStream raised the advertised
    /// limit and TryReceive kept refusing at the initial one.</para>
    /// <para>ZERO MEANS NO GRANT HAS BEEN SENT, not a grant of zero. s19.11's Maximum Streams
    /// is cumulative and CreditPeerStream never queues a frame below <c>initial</c>, so the
    /// two readings cannot collide: a grant that had genuinely lowered the limit to zero is a
    /// frame this endpoint does not build.</para>
    /// </remarks>
    private ulong PeerStreamLimitNow(TlsQuicStreamDirection direction)
    {
        var granted = _peerStreamGranted[
            direction == TlsQuicStreamDirection.Unidirectional ? 1 : 0];
        return granted == 0 ? LocalFlowControl.PeerStreamLimitFor(direction) : granted;
    }

    /// <summary>RFC 9000 s19.11: "This value cannot exceed 2^60, as it is not possible to
    /// encode stream IDs larger than 2^62-1."</summary>
    private const ulong MaximumStreamsCeiling = 1UL << 60;

    /// <summary>How much of the advertised stream limit has to come free before MAX_STREAMS is
    /// worth a frame. Declared, not measured - see <see cref="CreditPeerStream"/>.</summary>
    private const ulong StreamCreditUpdateDivisor = 2;

    private readonly ulong[] _peerStreamsFinished = new ulong[2];

    private readonly ulong[] _peerStreamGranted = new ulong[2];

    /// <summary>The RFC 9000 s13.3 repairs owed on 1-RTT frames and not yet taken.</summary>
    /// <remarks>BORROWED AND MUTABLE, because <c>TlsQuicConnection.QueueRepair</c> is the only
    /// writer and it needs to check what is already owed before adding to it - the duplicate
    /// check that keeps one copy of a byte range that two lost packets both carried.</remarks>
    internal List<TlsQuicFrame> RepairsOwed => _repairs;

    /// <summary>How many repaired frames this set has handed to a 1-RTT packet.</summary>
    /// <remarks>Read by <c>TlsQuicConnection.FramesRetransmitted</c>, which sums it with the
    /// Initial and Handshake drain's own count; see there for why the two are separate.</remarks>
    internal int RepairsSent { get; private set; }

    /// <summary>RFC 9000 s13.3's repair for one lost flow-control grant: the CURRENT limit, in a
    /// new frame.</summary>
    /// <remarks>
    /// <para>s13.3 on MAX_DATA: "An updated value is sent in a MAX_DATA frame if the packet
    /// containing the most recently sent MAX_DATA frame is declared lost or when the endpoint
    /// decides to update the limit." And on MAX_STREAM_DATA: "Like MAX_DATA, an updated value is
    /// sent when the packet containing the most recent MAX_STREAM_DATA frame for a stream is
    /// lost". UPDATED, so the lost frame supplies the stream it names and nothing else.</para>
    /// <para>AND THE ONE SHOULD THAT SAYS NOT TO. s13.3: "An endpoint SHOULD stop sending
    /// MAX_STREAM_DATA frames when the receiving part of the stream enters a "Size Known" or
    /// "Reset Recvd" state." Size Known is s3.2's state on the peer's FIN, which is exactly
    /// <see cref="TlsQuicStream.FinReceived"/>. RESET RECVD IS COVERED BY THE SAME TEST RATHER
    /// THAN BY A SECOND ONE, and this paragraph used to say it did not arise at all because
    /// "nothing in this tree receives a RESET_STREAM yet". It does now:
    /// <c>TryReceiveReset</c> establishes the final size, so a stream in s3.2's "Reset Recvd"
    /// has FinReceived true as well and this refuses to repair its grant on the same line. So
    /// the FIN test is both halves of the SHOULD, and a false return is a refusal to repair
    /// rather than a failure to.</para>
    /// <para>NEVER THROWS, FOR ANY FRAME. The argument is a frame this endpoint built, but it
    /// reaches here after a loss declaration whose timing the peer controls, and a stream it
    /// names may have been forgotten in between.</para>
    /// <para>AND THE TWO BLOCKED FRAMES ARE NOT ROUTED HERE, WHICH IS A KNOWN AND RECORDED GAP.
    /// s13.3 asks the same freshness of them - "A new frame is sent if a packet containing the
    /// most recent frame for a scope is lost, but only while the endpoint is blocked on the
    /// corresponding limit. These frames always include the limit that is causing blocking at
    /// the time that they are transmitted" - and <c>TlsQuicRetransmission.ActionFor</c> already
    /// gives DATA_BLOCKED and STREAM_DATA_BLOCKED the Refresh action. But
    /// <c>TlsQuicConnection.QueueRepair</c> sends only MAX_DATA and MAX_STREAM_DATA through
    /// this method, so a lost blocked signal is replayed VERBATIM: it carries the offset or
    /// limit that held when it was first built, and it is re-sent even if the grant that
    /// unblocked it has since arrived. Both are conservative - a stale blocked signal asks for
    /// credit that has already been given - and correcting either means editing
    /// TlsQuicLossDetection.cs, which A4-complete's flow-control task does not own.</para>
    /// </remarks>
    /// <param name="lost">The MAX_DATA or MAX_STREAM_DATA frame whose packet was lost.</param>
    /// <param name="repaired">The frame to send instead.</param>
    /// <returns><see langword="false"/> for any other frame type, for a stream this set no
    /// longer holds, and for the SHOULD above.</returns>
    internal bool TryRefreshGrant(in TlsQuicFrame lost, out TlsQuicFrame repaired)
    {
        repaired = default;

        switch (lost.Type)
        {
            case TlsQuicFrameType.MaxData:
                repaired = new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.MaxData,
                    MaximumData = _connectionReceiveLimit,
                };
                return true;

            case TlsQuicFrameType.MaxStreamData:
                if (Find(lost.StreamId) is not { } stream || stream.FinReceived)
                {
                    return false;
                }

                repaired = new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.MaxStreamData,
                    StreamId = lost.StreamId,
                    MaximumStreamData = stream.ReceiveLimit,
                };
                return true;

            default:
                return false;
        }
    }

    /// <summary>Takes the queued STREAM frames, in the order they were queued, and empties the
    /// queue.</summary>
    /// <remarks>QUEUE ORDER IS SEND ORDER, and it is preserved rather than sorted: two frames
    /// on one stream carry consecutive offsets, so reordering them would arrive out of order
    /// at a peer that reassembles by offset - which works, and hides a defect that would not
    /// work against a peer counting on s2.2's "QUIC makes no guarantees about the order of
    /// delivery of data between streams" applying BETWEEN streams and not within
    /// one.</remarks>
    /// <summary>Takes as many queued frames as fit in <paramref name="payloadBudget"/> bytes of
    /// packet payload, leaving the rest queued in order for the next datagram.</summary>
    /// <remarks>
    /// <para>THE SEGMENTATION IN <see cref="Drain"/> IS NOT ENOUGH ON ITS OWN. That bounds each
    /// STREAM frame to one datagram's worth; this bounds the NUMBER of them that go into one
    /// datagram. A body chopped into ten conforming frames still makes one oversized datagram
    /// if all ten are handed to the same packet.</para>
    /// <para>NO FRAME IS ADMITTED UNMEASURED, AND THE FIRST ONE USED TO BE. The test read
    /// <c>taken.Count > 0 &amp;&amp; spent + size > payloadBudget</c>, so the head of the queue
    /// went into every datagram whatever its size. The claim justifying that - "it cannot arise
    /// from the segmentation above, which sizes frames against this same budget" - was false in
    /// two ways at once: <see cref="Drain"/> chunks at QUEUE time against
    /// <see cref="DatagramPayloadBudget"/> as it stood then, and the caller passes
    /// <c>budget - spent</c>, already reduced by an ACK and by RFC 9000 s12.2's coalesced
    /// Initial or Handshake prefix. A frame queued under a larger PMTU, or one queued before a
    /// prefix appeared in front of it, therefore overran the budget it was measured against and
    /// surfaced downstream as TlsQuicPacketBuilder.Build's "Packet needs N bytes, destination
    /// has M" or as a datagram a DF-set socket refuses with WSAEMSGSIZE.</para>
    /// <para>AN OVERSIZED STREAM HEAD IS SPLIT RATHER THAN REFUSED OR STALLED, on exactly the
    /// argument TlsQuicLossDetection.TakeRepairsInto now makes for a CRYPTO repair: RFC 9000
    /// s19.8 gives STREAM an explicit Offset, so a frame carrying the tail of a stream is
    /// complete in itself and advancing a known offset by the bytes already taken invents
    /// nothing. That is what keeps progress guaranteed - the queue cannot stall behind a frame
    /// that is too big for today's datagram and small enough for yesterday's.</para>
    /// <para>AND THE STARVATION ESCAPE STAYS FOR FRAMES THAT GENUINELY CANNOT BE SPLIT. A
    /// MAX_DATA is one value, not a byte range. If nothing has been taken and the head is one
    /// of those, it goes out oversized and the send path reports a legible refusal naming the
    /// frame and the budget - which beats a queue that never drains and a connection that hangs
    /// with nothing to say why. Every such frame this set queues is a few tens of bytes, so the
    /// escape needs a budget smaller than a single varint triple to fire at all.</para>
    /// <para>ORDER IS PRESERVED ACROSS THE SPLIT: repairs before new data, s13.3's
    /// "prioritize retransmission of data over sending new data", and the remainder keeps its
    /// place at the head of its own queue.</para>
    /// </remarks>
    internal IReadOnlyList<TlsQuicFrame> TakePendingFrames(int payloadBudget)
    {
        var taken = new List<TlsQuicFrame>();
        var spent = 0;

        // Repairs first, then new data. One loop over the two queues in that order, so a
        // repair can never be left behind while newer data goes out ahead of it.
        for (var source = 0; source < 2; source++)
        {
            var queue = source == 0 ? _repairs : _pending;
            while (queue.Count > 0)
            {
                var size = TlsQuicFrames.MeasureFrame(_measureScratch, queue[0]);
                if (spent + size > payloadBudget)
                {
                    // s19.8's explicit Offset makes the tail of a stream a frame in its own
                    // right, so the head is cut to what the budget covers and the remainder
                    // keeps its place at the front of the queue. The datagram is full by
                    // construction afterwards - the split took every byte that fitted - so
                    // there is nothing left to measure.
                    if (TrySplitStreamHead(queue, size, payloadBudget - spent, out var head))
                    {
                        taken.Add(head);
                        if (source == 0)
                        {
                            RepairsSent++;
                        }
                    }
                    else if (taken.Count == 0)
                    {
                        // The escape, and it is now the LAST resort rather than the first: a
                        // frame that cannot be split and cannot fit goes out oversized so the
                        // queue drains, and the send path names it. Reached only when nothing
                        // else has been taken, so a datagram that is already carrying frames
                        // never grows past its budget.
                        taken.Add(queue[0]);
                        queue.RemoveAt(0);
                        if (source == 0)
                        {
                            RepairsSent++;
                        }
                    }

                    return taken;
                }

                spent += size;
                taken.Add(queue[0]);
                queue.RemoveAt(0);
                if (source == 0)
                {
                    RepairsSent++;
                }
            }
        }

        return taken;
    }

    // Cuts the head of `queue` down to `room` bytes if it is an s19.8 STREAM frame with data,
    // leaving the remainder at the front of the queue. Reports whether it did.
    //
    // THE FIN GOES WITH THE REMAINDER AND NEVER WITH THE HEAD, which is TryTakeSendable's rule
    // stated a second time because this is a second place a write gets split: s19.8's FIN
    // "indicates that the frame marks the end of the stream", and the tail has not left yet.
    //
    // THE REMAINDER ALWAYS CARRIES THE OFF BIT. Its offset is the head's plus what was taken,
    // so it is non-zero even when the head's was zero - and s19.8's implicit form, "When the
    // Offset field is absent, the offset is 0", would put the tail back at the start of the
    // stream. That is silent corruption rather than a size error, because a peer reassembles
    // by offset, which is why it is stated rather than left to the caller to notice.
    private bool TrySplitStreamHead(
        List<TlsQuicFrame> queue, int size, int room, out TlsQuicFrame head)
    {
        head = default;

        var frame = queue[0];
        if (frame.Type != TlsQuicFrameType.Stream || frame.Data.Length == 0)
        {
            return false;
        }

        // What the frame costs beyond its payload, MEASURED rather than recomputed - the same
        // reason MeasureFrame exists at all. Conservative in the safe direction too: s16 lets
        // the Length varint get shorter as the payload shrinks and never longer, so the head
        // built below is never larger than the room it was cut to.
        var take = room - (size - frame.Data.Length);
        if (take <= 0)
        {
            return false;
        }

        head = frame with
        {
            RawType = frame.RawType & ~TlsQuicStreamFrames.FinBit,
            Data = frame.Data[..take],
        };

        queue[0] = frame with
        {
            RawType = frame.RawType | TlsQuicStreamFrames.OffsetBit,
            Offset = frame.Offset + (ulong)take,
            Data = frame.Data[take..],
        };

        return true;
    }

    internal IReadOnlyList<TlsQuicFrame> TakePendingFrames()
    {
        if (_repairs.Count == 0)
        {
            var taken = _pending.ToArray();
            _pending.Clear();
            return taken;
        }

        // s13.3's "prioritize retransmission of data over sending new data", as a concatenation
        // rather than a sort - see the field comment on _repairs for why the order of the two
        // lists is preserved inside each of them.
        //
        // AND THIS IS WHY A LOST GRANT IS REPAIRED WITHOUT A TIMER OF ITS OWN.
        // TlsQuicStreams.cs's own header ruled the alternative out - "a receiver that re-sent
        // grants on a timer would be duplicating A3's loss detection in one frame type's private
        // schedule" - and the queue below is the other option: A3-6 declares the loss, s13.3
        // says what to send, and this is the existing 1-RTT drain carrying it.
        var all = new List<TlsQuicFrame>(_repairs.Count + _pending.Count);
        all.AddRange(_repairs);
        all.AddRange(_pending);
        RepairsSent += _repairs.Count;
        _repairs.Clear();
        _pending.Clear();
        return all;
    }

    /// <summary>Takes one received RFC 9000 s19.8 STREAM frame, creating the stream if the
    /// peer opened it, and reports the s20.1 code to close with if it cannot be
    /// accepted.</summary>
    /// <remarks>NEVER THROWS, for any input. See this file's header: an authenticated frame on
    /// a peer-initiated stream is still peer-CONTROLLED, so every rejection below is a return
    /// value.</remarks>
    internal bool TryReceive(in TlsQuicFrame frame, out TlsQuicTransportError error)
    {
        var id = frame.StreamId;

        if (!_streams.TryGetValue(id, out var stream))
        {
            if (TlsQuicStreamId.InitiatorOf(id) == TlsQuicStreamInitiator.Client)
            {
                // s19.8: "An endpoint MUST terminate the connection with error
                // STREAM_STATE_ERROR if it receives a STREAM frame for a locally initiated
                // stream that has not yet been created, or for a send-only stream." This is
                // the first half - we are the client, so a client-initiated id we do not hold
                // is a locally initiated stream that was never created.
                error = TlsQuicTransportError.StreamStateError;
                return false;
            }

            // s20.1 STREAM_LIMIT_ERROR (0x04): "An endpoint received a frame for a stream
            // identifier that exceeded its advertised stream limit for the corresponding
            // stream type." OUR limit, and since C9 it is literally the parameter we
            // advertised. Checked before the stream is created, so a peer opening streams
            // without end is refused rather than tracked.
            //
            // THE IDENTIFIER, NOT THE COUNT, AND PER TYPE. s19.11 works the example: "a server
            // that receives a unidirectional stream limit of 3 is permitted to open streams 3,
            // 7, and 11, but not stream 15" - ordinals 0, 1 and 2 against a limit of 3, so the
            // test is ordinal >= limit. A count of live streams would let a peer that opened
            // and abandoned streams keep going forever, and s19.11 rules that out in the same
            // breath: "The limit includes streams that have been closed as well as those that
            // are open." The two directions are counted separately because s18.2 gives them
            // separate parameters.
            // AND IT IS THE LIMIT WE HAVE ADVERTISED, NOT THE ONE WE STARTED FROM, which is the
            // audit's finding 8. CreditPeerStream sends s19.11 MAX_STREAMS frames raising the
            // peer's allowance to initial + finished, and this test read
            // PeerStreamLimitFor - initial_max_streams_uni / _bidi, verbatim and immovable - so
            // a peer that spent credit WE GAVE IT was killed with STREAM_LIMIT_ERROR. s19.11
            // makes MAX_STREAMS the definition of the limit the moment one is sent: "the
            // maximum number of streams of a given type that the receiver permits", cumulative
            // over the connection. Refusing inside it is a protocol violation on OUR side, and
            // it is the failure mode that only appears after a connection has been up long
            // enough to close a stream - which is why nothing before this reached it.
            if (TlsQuicStreamId.OrdinalOf(id)
                >= PeerStreamLimitNow(TlsQuicStreamId.DirectionOf(id)))
            {
                error = TlsQuicTransportError.StreamLimitError;
                return false;
            }

            // s19.8: "STREAM frames implicitly create a stream". THIS IS THE HALF A4 TASK 14's
            // ORIGINAL TEXT MISSED AND SUBSYSTEM C CANNOT START WITHOUT - RFC 9204 s4.2: "An
            // endpoint MUST allow its peer to create an encoder stream and a decoder stream
            // even if the connection's settings prevent their use."
            //
            // A SERVER-INITIATED BIDIRECTIONAL STREAM GETS A SEND BUDGET AND A UNIDIRECTIONAL
            // ONE DOES NOT, which is the whole reason TlsQuicPeerFlowControlBudget has an
            // AcceptBidirectionalStream separate from its two Open methods: s18.2 scopes
            // initial_max_stream_data_bidi_local (0x05) to "streams the peer opens", and a
            // server-initiated unidirectional stream is one we can never send on at all.
            stream = new TlsQuicStream(
                id,
                TlsQuicStreamId.DirectionOf(id) == TlsQuicStreamDirection.Bidirectional
                    ? _budget.AcceptBidirectionalStream()
                    : null,
                this);
            _streams.Add(id, stream);
            _peerInitiated.Add(stream);
        }

        if (!stream.CanReceive)
        {
            // s19.8's second half, "or for a send-only stream": a client-initiated
            // unidirectional stream is ours to send on and the peer may not send back.
            // Reached only for a stream we DID open, which is why it is separate from the
            // not-created check above.
            error = TlsQuicTransportError.StreamStateError;
            return false;
        }

        if (!stream.TryReceive(
            frame.Offset,
            frame.Data.Span,
            TlsQuicStreamFrames.IsFin(frame.RawType),
            out error))
        {
            return false;
        }

        // AFTER THE FRAME IS ACCEPTED, NEVER AFTER A REFUSAL. A refused frame delivered
        // nothing, so there is no credit to re-grant, and queueing a MAX_* frame on the way to
        // closing the connection would put a grant in the same packet as the close.
        QueueFlowControlUpdates(stream);
        return true;
    }

    /// <summary>Takes one received RFC 9000 s19.10 MAX_STREAM_DATA frame, raising that
    /// stream's send limit, and reports the s20.1 code to close with if it cannot be
    /// accepted.</summary>
    /// <remarks>
    /// <para>THE MIRROR OF <see cref="TryRefreshGrant"/>, AND IT IS THE SAME RULE FROM THE
    /// OTHER SIDE. That method re-sends the CURRENT limit after a loss rather than the lost
    /// one, because a peer applying s19.10's "the LARGEST maximum stream data value advertised
    /// by the receiver" would discard a replayed stale value; this is the code that discards
    /// it. <see cref="TlsQuicPeerFlowControlBudget.TlsQuicStreamBudget.TryRaiseLimit"/> holds
    /// the comparison and quotes the sentence.</para>
    /// <para>TWO MUSTs, BOTH FROM s19.10, BOTH CONNECTION ERRORS. "Receiving a MAX_STREAM_DATA
    /// frame for a locally initiated stream that has not yet been created MUST be treated as a
    /// connection error of type STREAM_STATE_ERROR", and "An endpoint that receives a
    /// MAX_STREAM_DATA frame for a receive-only stream MUST terminate the connection with
    /// error STREAM_STATE_ERROR". Receive-only is read from OUR side, because the frame grants
    /// US credit to send: it is <see cref="TlsQuicStream.CanSend"/> being false, which s2.1
    /// makes true of exactly the server-initiated unidirectional streams.</para>
    /// <para>A GRANT FOR A PEER-INITIATED STREAM WE HAVE NOT SEEN IS IGNORED, AND s19.10 DOES
    /// NOT COVER IT. Its two MUSTs are the locally initiated case and the receive-only case,
    /// and a server-initiated bidirectional stream the server has granted credit on before
    /// sending on it is neither. Ignoring loses only credit we could not have spent - nothing
    /// in this tree sends on a server-initiated bidirectional stream at all - where implicitly
    /// creating one would spend the peer stream limit s19.8 spends only for a STREAM frame.
    /// A conservative no-op, not an oversight.</para>
    /// <para>NEVER THROWS, for any input. This is the peer-input path this file's header keeps
    /// throw-free; every rejection is a return value.</para>
    /// </remarks>
    internal bool TryReceiveMaxStreamData(in TlsQuicFrame frame, out TlsQuicTransportError error)
    {
        error = TlsQuicTransportError.NoError;

        if (Find(frame.StreamId) is not { } stream)
        {
            if (TlsQuicStreamId.InitiatorOf(frame.StreamId) == TlsQuicStreamInitiator.Client)
            {
                error = TlsQuicTransportError.StreamStateError;
                return false;
            }

            return true;
        }

        if (!stream.CanSend || stream.Budget is not { } budget)
        {
            error = TlsQuicTransportError.StreamStateError;
            return false;
        }

        if (budget.TryRaiseLimit(frame.MaximumStreamData))
        {
            // s13.3's "only while the endpoint is blocked": the limit moved, so the last
            // STREAM_DATA_BLOCKED no longer describes the present and a later block is a new
            // signal rather than a repeat of that one.
            stream.ReleaseStreamDataBlockedSignal();
            Drain(stream);
        }

        return true;
    }

    /// <summary>Takes one received RFC 9000 s19.4 RESET_STREAM, s19.5 STOP_SENDING or s19.13
    /// STREAM_DATA_BLOCKED frame and reports the s20.1 code to close with when the stream's
    /// DIRECTION forbids that frame.</summary>
    /// <remarks>
    /// <para>FOUR MUSTs, ONE METHOD, because all four are the same test on different frames.
    /// s19.4: "An endpoint that receives a RESET_STREAM frame for a send-only stream MUST
    /// terminate the connection with error STREAM_STATE_ERROR." s19.13 says exactly that of
    /// STREAM_DATA_BLOCKED. s19.5 says the mirror of STOP_SENDING - "An endpoint that receives
    /// a STOP_SENDING frame for a receive-only stream MUST terminate the connection with error
    /// STREAM_STATE_ERROR" - plus "Receiving a STOP_SENDING frame for a locally initiated
    /// stream that has not yet been created MUST be treated as a connection error of type
    /// STREAM_STATE_ERROR".</para>
    /// <para>THE DIRECTION IS READ OFF THE IDENTIFIER, NOT OFF A STREAM OBJECT, which is the
    /// difference from <see cref="TryReceive"/>. s2.1 makes direction a property of the id, and
    /// every rule here binds on streams this endpoint may never have created - a RESET_STREAM
    /// for a send-only stream we never opened is still a RESET_STREAM for a send-only stream.
    /// Consulting <see cref="Find"/> first would make the verdict depend on whether the peer
    /// had previously made us allocate one.</para>
    /// <para>THE OPPOSITE PAIRING IS THE POINT AND IS EASY TO INVERT. RESET_STREAM and
    /// STREAM_DATA_BLOCKED are refused on SEND-ONLY streams; STOP_SENDING is refused on
    /// RECEIVE-ONLY ones. A STOP_SENDING on a stream we can only send on is the peer's whole
    /// purpose for the frame, and a RESET_STREAM on a stream we can only receive on is the peer
    /// resetting its own sending. Swapping the two tests would reject exactly the legal
    /// traffic.</para>
    /// <para>AND THE FRAME IS NOW ACTED ON, WHICH IS THE AUDIT'S FINDING 3. This paragraph used
    /// to read "ACCEPTING THE FRAME IS NOT ACTING ON IT ... the pre-existing behaviour - drop
    /// the frame - is what a true return still means", and dropping it cost four separate
    /// things: <see cref="TlsQuicStream.FinalSize"/> was never set, so
    /// <see cref="TlsQuicStream.ReceiveComplete"/> could not become true and an awaiting HTTP/3
    /// caller waited out the idle timeout on a stream the server had already abandoned; the
    /// application error code the peer sent was decoded by
    /// <c>TlsQuicConnectionFrames.TryReadResetStream</c> and discarded; s4.5's final-size
    /// accounting never ran, so a RESET_STREAM contradicting data already received was not the
    /// FINAL_SIZE_ERROR s20.1 makes it; and STOP_SENDING left this endpoint queueing STREAM
    /// frames on a stream the peer had asked it to stop writing.</para>
    /// <para>WHAT IS STILL NOT DONE IS s3.2's FULL STATE MACHINE. There is no "Reset Sent"
    /// versus "Reset Recvd" enumeration here and no send-side reset this endpoint originates on
    /// its own; what exists is the receive half terminating, the send half stopping, and the one
    /// frame s3.5 makes mandatory in answer.</para>
    /// <para>NEVER THROWS, for any input, like every other peer-input path in this file.</para>
    /// </remarks>
    internal bool TryReceiveStreamStateSignal(
        in TlsQuicFrame frame, out TlsQuicTransportError error)
    {
        error = TlsQuicTransportError.NoError;

        var id = frame.StreamId;
        var unidirectional =
            TlsQuicStreamId.DirectionOf(id) == TlsQuicStreamDirection.Unidirectional;
        var locallyInitiated =
            TlsQuicStreamId.InitiatorOf(id) == TlsQuicStreamInitiator.Client;

        // s2.1's two one-way cases, from THIS endpoint's side. We are the client, so a
        // client-initiated unidirectional stream is s19.8's "send-only stream" and a
        // server-initiated one is s19.10's "receive-only stream". A bidirectional stream is
        // neither and no rule here touches it.
        var sendOnly = unidirectional && locallyInitiated;
        var receiveOnly = unidirectional && !locallyInitiated;

        var forbidden = frame.Type switch
        {
            TlsQuicFrameType.ResetStream or TlsQuicFrameType.StreamDataBlocked => sendOnly,
            TlsQuicFrameType.StopSending =>
                receiveOnly || (locallyInitiated && Find(id) is null),
            _ => false,
        };

        if (forbidden)
        {
            error = TlsQuicTransportError.StreamStateError;
            return false;
        }

        // THE DIRECTION RULES ARE THE GATE AND THIS IS THE EFFECT, in that order: a frame s19.4
        // or s19.5 forbids outright must close the connection rather than change any state on
        // the way out.
        return frame.Type switch
        {
            TlsQuicFrameType.ResetStream => TryApplyReset(frame, out error),
            TlsQuicFrameType.StopSending => ApplyStopSending(frame),

            // s19.13's STREAM_DATA_BLOCKED, and there is nothing to do with it beyond the
            // direction rule above. It says the peer wants more of OUR window, which
            // CreditReceiveWindow already grants on its own threshold as the application
            // consumes - and s19.13's "does not open the connection to a denial of service"
            // note is about the receiver being free to ignore one. Sending a MAX_STREAM_DATA
            // just because the peer asked would hand out credit on the peer's schedule.
            _ => true,
        };
    }

    // s19.4's frame, applied to the stream it names.
    //
    // A RESET FOR A STREAM THIS SET DOES NOT HOLD IS ACCEPTED AND DROPPED, on the reasoning
    // TryReceiveMaxStreamData's third paragraph gives for its own no-op: the direction rules
    // above have already closed every case s19.4 makes a MUST, and implicitly creating a stream
    // here would spend the s19.11 peer-stream limit that s19.8 spends only for a STREAM frame -
    // on a stream that by definition will never carry one. Nothing is lost: with no stream
    // there is no consumer awaiting a final size and no buffered byte to discard.
    private bool TryApplyReset(in TlsQuicFrame frame, out TlsQuicTransportError error)
    {
        error = TlsQuicTransportError.NoError;

        if (Find(frame.StreamId) is not { } stream)
        {
            return true;
        }

        if (!stream.TryReceiveReset(
            frame.FinalSize, frame.ApplicationProtocolErrorCode, out error))
        {
            return false;
        }

        // AFTER THE FRAME IS ACCEPTED, NEVER AFTER A REFUSAL - TryReceive's rule, and the same
        // reason: queueing a grant on the way to closing the connection would put it in the
        // same packet as the close.
        QueueFlowControlUpdates(stream);
        return true;
    }

    // s19.5's frame, applied. Always returns true: every STOP_SENDING this reaches has passed
    // the two direction MUSTs above, and s19.5 states no other error case.
    //
    // RFC 9000 s3.5 IS WHY A FRAME GOES BACK: "An endpoint that receives a STOP_SENDING frame
    // MUST send a RESET_STREAM frame if the stream is in the 'Ready' or 'Send' state." The
    // error code is copied because the same section says to - "An endpoint SHOULD copy the
    // error code from the STOP_SENDING frame to the RESET_STREAM frame it sends" - and the
    // final size is s19.4's "final size of the stream", which for our sending half is exactly
    // the offset the next byte would have carried.
    //
    // ONE ANSWER PER STREAM, WHICH IS THE SendStopped GUARD. s13.3 gives STOP_SENDING the
    // resend treatment on loss, so a duplicate is ordinary; answering each copy would put a
    // second RESET_STREAM on the wire with a final size that had not moved, and s3.2's "Reset
    // Sent" is a state entered once.
    //
    // A STREAM WE DO NOT HOLD IS DROPPED, and unlike the reset case that is not a judgement
    // call: the only STOP_SENDING that can reach here for an unknown stream is one for a
    // PEER-initiated stream, because the locally-initiated-not-created case is s19.5's own MUST
    // and was refused above. We have sent nothing on a stream we never created, so there is no
    // send half to stop and no non-zero final size to report.
    private bool ApplyStopSending(in TlsQuicFrame frame)
    {
        if (Find(frame.StreamId) is not { } stream || stream.SendStopped)
        {
            return true;
        }

        var finalSize = stream.StopSending(frame.ApplicationProtocolErrorCode);
        _pending.Add(new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.ResetStream,
            StreamId = stream.Id,
            ApplicationProtocolErrorCode = frame.ApplicationProtocolErrorCode,
            FinalSize = finalSize,
        });

        return true;
    }

    /// <summary>Takes one received RFC 9000 s19.9 MAX_DATA frame, raising the connection-level
    /// send limit and releasing every stream that was waiting on it.</summary>
    /// <remarks>
    /// <para>NO ERROR CASE AND NO RETURN VALUE, because s19.9 defines none: the frame carries
    /// no stream id, so none of s19.10's two MUSTs has an analogue here, and a value that does
    /// not increase is discarded rather than rejected - see
    /// <see cref="TlsQuicPeerFlowControlBudget.TryRaiseConnectionLimit"/>, where the reading
    /// s19.9 leaves open is chosen and cited.</para>
    /// <para>EVERY BLOCKED STREAM IS DRAINED AND IN IDENTIFIER ORDER. The pool is shared, so
    /// one MAX_DATA can release several streams and cannot release all of them; ordering by
    /// s2.1 identifier makes which one gets the bytes a decision rather than a dictionary's
    /// enumeration order, and lets a test assert it.</para>
    /// </remarks>
    internal void ReceiveMaxData(in TlsQuicFrame frame)
    {
        if (!_budget.TryRaiseConnectionLimit(frame.MaximumData))
        {
            return;
        }

        _dataBlockedSignalled = false;

        foreach (var stream in _streams.Values.OrderBy(each => each.Id).ToArray())
        {
            if (stream.HasBlockedData)
            {
                Drain(stream);
            }
        }
    }

    // Charges bytes against OUR initial_max_data, and reports rather than throws: the caller
    // is on the peer-input path this file's header keeps throw-free.
    //
    // s19.9: "An endpoint MUST terminate a connection with an error of type FLOW_CONTROL_ERROR
    // if it receives more data than the maximum data value that it has sent."
    internal bool TryAdmitConnectionData(ulong advance)
    {
        if (advance > _connectionReceiveLimit - _connectionReceived)
        {
            return false;
        }

        _connectionReceived += advance;
        return true;
    }

    // Re-grants connection-level credit for bytes a stream has delivered, on the same rule and
    // the same threshold TlsQuicStream.CreditReceiveWindow uses per stream. The two are
    // separate windows and both have to move: a transfer larger than either one stalls if only
    // the other is topped up.
    internal void CreditConnectionWindow(ulong delivered)
    {
        _connectionDelivered += delivered;
        var window = LocalFlowControl.InitialMaxData;
        if (_connectionReceiveLimit - _connectionDelivered
            >= window / TlsQuicLocalFlowControlSpec.ReceiveWindowUpdateDivisor)
        {
            return;
        }

        // Clamped for the reason CreditReceiveWindow's is - s19.9's Maximum Data is a
        // variable-length integer and the write side refuses one that will not encode.
        _connectionReceiveLimit =
            _connectionDelivered > QuicVariableLengthInteger.MaximumValue - window
                ? QuicVariableLengthInteger.MaximumValue
                : _connectionDelivered + window;
        _maximumDataOwed = true;
    }

    // Queues whichever of s19.10's MAX_STREAM_DATA and s19.9's MAX_DATA the last receive
    // earned, onto the same list the s19.8 STREAM frames use - so they leave in the next 1-RTT
    // packet TlsQuicApplicationSendPath builds, with no second path to keep in step. s12.4
    // Table 3 gives both types the row "__01", which is where TlsQuicFrameLegality already
    // puts them.
    private void QueueFlowControlUpdates(TlsQuicStream stream)
    {
        if (stream.TryTakeMaximumStreamData(out var maximumStreamData))
        {
            _pending.Add(new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.MaxStreamData,
                StreamId = stream.Id,
                MaximumStreamData = maximumStreamData,
            });
        }

        if (!_maximumDataOwed)
        {
            return;
        }

        _maximumDataOwed = false;
        _pending.Add(new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.MaxData,
            MaximumData = _connectionReceiveLimit,
        });
    }
}

/// <content>The three places streams touch the connection's shared private state: the budget
/// they are opened against, the s19.8 dispatch arm, and the frames the 1-RTT packet
/// carries.</content>
internal sealed partial class TlsQuicConnection
{
    private TlsQuicStreamSet? _streams;

    /// <summary>Gets this connection's streams, opened against the peer's advertised RFC 9000
    /// s18.2 budget.</summary>
    /// <remarks>CREATED ON FIRST USE rather than in the constructor, because the budget it is
    /// built from does not exist until the peer's transport parameters arrive - the same
    /// not-yet-arrived guard <see cref="PeerFlowControl"/> carries, reached through it rather
    /// than duplicated.</remarks>
    /// <exception cref="InvalidOperationException">The peer's transport parameters have not
    /// arrived.</exception>
    internal TlsQuicStreamSet Streams => _streams ??=
        new TlsQuicStreamSet(
            PeerFlowControl,
            // AS ADVERTISED, NOT AS SPECIFIED. See TlsQuicLocalFlowControlSpec.AsAdvertisedBy:
            // a limit the transport-parameter list never emits is zero to the peer under RFC
            // 9000 s18.2, and enforcing the spec's default for it would police a budget the
            // peer was never given.
            _options.Spec.LocalFlowControl.AsAdvertisedBy(_options.Spec.TransportParameters))
        {
            // SET AT CONSTRUCTION AND NOT ONLY AT SEND TIME. Drain runs when the application
            // WRITES, which is before any datagram is built, so a set that learned its budget
            // only in TryBuildApplicationPacket would already have carved the whole body into
            // one frame by the time it was told. The send path refreshes it every pass because
            // path MTU discovery moves it.
            DatagramPayloadBudget = DatagramPayloadBudget,
        };

    // The s19.8 dispatch arm's body, here rather than in TlsQuicConnection.cs's frame switch so
    // that the STREAM-specific prose lives beside the code it describes and that file spends 6
    // code lines on this task rather than twenty.
    //
    // THE DATA IS COPIED OUT OF THE RECEIVER'S SCRATCH, for the reason the PATH_CHALLENGE arm
    // beside it gives: frame.Data is a window onto TlsQuicPacketReceiver's decrypt buffer,
    // which the next Receive refills, and these bytes are held on a stream until the
    // application reads them. TryReceive takes a span and copies what it keeps, so the copy is
    // that method's rather than a second one here.
    //
    // BEFORE THE BUDGET EXISTS THIS IS A REFUSAL AND NOT A THROW. A 1-RTT packet cannot be
    // opened before the handshake produced Application read keys, and the peer's parameters
    // arrive with the handshake, so _peerFlowControl is never null here - but reaching
    // PeerFlowControl's throw on peer input would be exactly the off-path kill switch 9a-ii
    // shipped, so the null is a refusal instead. Unreachable and deliberately unwitnessed.
    private void ReceiveStreamFrame(in TlsQuicFrame frame, ref string? failure)
    {
        if (_peerFlowControl is null)
        {
            failure ??= "A STREAM frame arrived before the peer's transport parameters, so "
                + "there is no RFC 9000 s18.2 budget to receive it against.";
            return;
        }

        if (!Streams.TryReceive(frame, out var error))
        {
            // FIRST FAILURE WINS. A datagram may carry several STREAM frames and the one that
            // ended the connection is the one worth reporting; a later frame's code would
            // describe a state the first refusal already made meaningless.
            failure ??= $"The peer sent a STREAM frame this connection cannot accept "
                + $"(RFC 9000 s19.8), so it is closing with {error}: stream {frame.StreamId}, "
                + $"offset {frame.Offset}, {frame.Data.Length} byte(s), FIN "
                + $"{TlsQuicStreamFrames.IsFin(frame.RawType)}.";
        }
    }

    // The s19.4 RESET_STREAM, s19.5 STOP_SENDING and s19.13 STREAM_DATA_BLOCKED dispatch arm's
    // body, here for the reason the two below are: the prose belongs beside the code.
    //
    // NO NULL-BUDGET GUARD, unlike its two neighbours, and that is not an omission. Those two
    // need _peerFlowControl because they spend or raise a budget; this one reads a direction
    // off a stream identifier, which is defined before any transport parameter arrives.
    //
    // BEFORE THIS ARM ALL FOUR MUSTs WENT UNENFORCED, all three frame types falling into the
    // frame switch's default. The audit recorded one of them - s19.13's - in that arm's own
    // comment and left the other three unnamed, which is how a subsystem-level "streams are
    // compliant" verdict can be true of this file and false of the dispatch that reaches it.
    //
    // AND THE REFUSALS ARE NO LONGER ONLY ABOUT DIRECTION, which is why the message names the
    // frame's fields. TryReceiveStreamStateSignal now applies a RESET_STREAM as well as
    // policing it, so this can also close with s20.1's FINAL_SIZE_ERROR - a final size below
    // what already arrived, or different from one already established - or FLOW_CONTROL_ERROR
    // for a final size past the limit we advertised. A message that said only "whose direction
    // forbids it" would name the wrong rule for two of the three codes it can now carry.
    private void ReceiveStreamStateSignal(in TlsQuicFrame frame, ref string? failure)
    {
        if (!Streams.TryReceiveStreamStateSignal(frame, out var error))
        {
            // FIRST FAILURE WINS, sharing the slot its neighbours use for the reason they give.
            failure ??= $"The peer sent a {frame.Type} frame this connection cannot accept "
                + "(RFC 9000 s19.4, s19.5 and s19.13), so it is closing with "
                + $"{error}: stream {frame.StreamId}, final size {frame.FinalSize}, "
                + $"application error code {frame.ApplicationProtocolErrorCode}.";
        }
    }

    // The s19.9 MAX_DATA and s19.10 MAX_STREAM_DATA dispatch arms' bodies, here for the reason
    // ReceiveStreamFrame's is: the prose belongs beside the code and TlsQuicConnection.cs is
    // over its line cap.
    //
    // THESE TWO ARE WHY A BODY LARGER THAN THE PEER'S INITIAL CREDIT COMPLETES. Before them
    // both types were parsed by TlsQuicFrames, reached the frame switch, fell into its default
    // arm and were dropped - so the send budget could only ever go down, and a request larger
    // than initial_max_stream_data_bidi_remote was refused by name. s12.4 Table 3 gives both
    // the row "__01", which TlsQuicFrameLegality already enforces, so a grant at any other
    // encryption level never reaches here.
    //
    // THE NULL BUDGET IS A REFUSAL AND NOT A THROW, exactly as it is for STREAM: unreachable,
    // because 1-RTT keys imply the peer's parameters arrived, and deliberately unwitnessed.
    private void ReceiveFlowControlFrame(in TlsQuicFrame frame, ref string? failure)
    {
        if (_peerFlowControl is null)
        {
            failure ??= "A flow-control grant arrived before the peer's transport parameters, "
                + "so there is no RFC 9000 s18.2 budget to apply it to.";
            return;
        }

        if (frame.Type == TlsQuicFrameType.MaxData)
        {
            Streams.ReceiveMaxData(frame);
            return;
        }

        if (!Streams.TryReceiveMaxStreamData(frame, out var error))
        {
            // FIRST FAILURE WINS, sharing ReceiveStreamFrame's slot for the reason it gives:
            // the frame that ended the connection is the one worth reporting.
            failure ??= "The peer sent a MAX_STREAM_DATA frame this connection cannot accept "
                + $"(RFC 9000 s19.10), so it is closing with {error}: stream "
                + $"{frame.StreamId}, maximum stream data {frame.MaximumStreamData}.";
        }
    }
}
