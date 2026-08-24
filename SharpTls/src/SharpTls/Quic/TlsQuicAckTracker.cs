namespace SharpTls.Quic;

// WHEN to send an ACK frame, and which packet numbers it names - RFC 9000 s13.1
// (packet processing), s13.2 (generating acknowledgements) and s13.2.5 (host
// delay). The complement of TlsQuicAckFrames, which decides how an ACK frame is
// spelled on the wire and nothing about when one is due.
//
// THIS FILE EXISTS BECAUSE THE A2 PLAN HAD A HOLE. ACK generation was item 11 of
// the original scoping document; the A2 plan omitted it, and A2's stated
// architecture - "pure functions - no connection state, no ACK generation policy,
// no loss detection", TlsQuicAckFrames' own header - meant no review of A2 could
// have caught the omission, because A2 was complete against the plan it was given.
// The consequence is not cosmetic: without this file a server re-arms its PTO
// against a peer that is acknowledging nothing, and under s8.1's anti-amplification
// limit it can stop sending altogether.
//
// TWO PLACES THE TASK TEXT THAT COMMISSIONED THIS FILE DISAGREES WITH THE RFC.
// Both are recorded here rather than implemented, because the extract is the
// authority and a later reader comparing this file to that text needs to know
// which way the difference runs.
//
//   1. The task text says "ACKs for Initial and Handshake packets MUST be sent
//      immediately". s13.2.1 says: "An endpoint MUST acknowledge all ack-eliciting
//      Initial and Handshake packets immediately and all ack-eliciting 0-RTT and
//      1-RTT packets within its advertised max_ack_delay, with the following
//      exception." The MUST is scoped to ACK-ELICITING packets - a packet carrying
//      only PADDING, ACK and CONNECTION_CLOSE frames obliges nothing, however
//      Initial it is - and the sentence does not end where the paraphrase ends.
//      See THE s13.2.1 EXCEPTION CLAUSE below for the half it drops.
//   2. The task text says to encode ack_delay "with the exponent from the peer's
//      transport parameters". s19.3 says the field "is decoded by multiplying the
//      value in the field by 2 to the power of the ack_delay_exponent transport
//      parameter SENT BY THE SENDER OF THE ACK FRAME". We are the sender of the
//      ACKs this class generates, so the exponent that scales them is OUR OWN
//      advertised value. Using the peer's would mis-scale every delay we report by
//      2^(theirs - ours) - silently, since both values are legal and the frame
//      still parses. The peer's exponent is what decodes an ACK we RECEIVE; that
//      belongs to ProcessAckFrame's RTT sampling, not here, and the two are
//      deliberately not the same field. Task A3-4 built that side - see
//      DecodeAckDelay and OnPeerAckParameters - so both exponents now exist in
//      this class and neither may be reached for by the other's path.
//
// THE s13.2.1 EXCEPTION CLAUSE - HANDLED BY CONSTRUCTION, NOT DEFERRED. The
// sentence continues: "with the following exception. Prior to handshake
// confirmation, an endpoint might not have packet protection keys for decrypting
// Handshake, 0-RTT, or 1-RTT packets when they are received. It might therefore
// buffer them and acknowledge them when the requisite keys become available."
//
// It describes an endpoint that BUFFERS. This one does not: TlsQuicPacketReceiver
// takes the other branch of the choice s12.2 offers - "if decryption fails
// (because the keys are not available or for any other reason), the receiver MAY
// either discard or buffer the packet" - and increments `discarded`. A discarded
// packet is never processed, and s13.1 gates acknowledgement on processing: "A
// packet MUST NOT be acknowledged until packet protection has been successfully
// removed and all frames contained in the packet have been processed." So a
// keyless packet never reaches OnPacketReceived, the exception has no state to
// describe, and there is nothing here to defer. It is NOT that the clause was
// judged out of scope - it is that the receiver's existing choice makes it
// vacuous. Adding buffering to the receiver is what would make it live, and that
// change would also make s13.2.5's companion sentence live: "endpoints SHOULD
// include buffering delays caused by unavailability of decryption keys, since
// these delays can be large and are likely to be non-repeating" - which
// TryBuildAck would satisfy for free, because it measures from the timestamp
// OnPacketReceived was given rather than from any clock of its own. That is why
// receivedAt is a parameter and not read from a TimeProvider inside.
//
// NO DELAYED-ACK TIMER, AND ITS ABSENCE IS A DECISION RATHER THAN AN OVERSIGHT.
// s13.2.1 gives the budget only to the application data space: "An endpoint MUST
// acknowledge all ack-eliciting Initial and Handshake packets immediately and all
// ack-eliciting 0-RTT and 1-RTT packets within its advertised max_ack_delay."
// Everything A4 sends and receives is Initial and Handshake, where the requirement
// is "immediately" and a timer would be a way of complying less well. A4-minimal
// never sends 1-RTT application data, so the delayed branch has no traffic to
// serve. A LATER IMPLEMENTER SHOULD NOT ADD ONE SPECULATIVELY: it is only needed
// once 1-RTT data flows, its natural home is the connection loop that owns
// TimeProvider (TlsQuicConnectionOptions), not this class, and this class already
// reports the delay that such a timer would create - see TryBuildAck's ackDelay.
//
// THE CLOCK IS NOT HERE, for the same reason it is not in TlsQuicPacketBuilder:
// timestamps arrive as parameters (receivedAt, now), and TimeProvider lives on
// TlsQuicConnectionOptions where the connection loop owns it. A tracker holding a
// clock of its own would be a second, untestable one.
// MUTATION RECORD. Run in a git worktree and reverted, each against
// `dotnet test --filter "FullyQualifiedName~Quic"`.
//
// EVERY FIGURE HERE IS DERIVED FROM THE LIST UNDER IT, never asserted beside it.
// Count the rows in a section, subtract the ones carrying the re-listed marker,
// and the number must fall out. Stricter than "never write a count you cannot
// recompute", and it is stricter because that rule was not enough: the previous
// revision of this block claimed "42 mutations" and "KILLED (37)", neither figure
// appeared in any list, both were wrong, and both survived two review passes -
// because a total standing next to a list reads as though it came from the list.
//
//   KILLED ON THE FIRST SWEEP    35  = 40 rows below, less the 5 re-listed ones
//   SURVIVED THEN WITNESSED       5  = 5 rows
//   SURVIVED, CLASSIFIED          3  = 3 rows
//                                ---
//   DISTINCT MUTATIONS           43  = 35 + 5 + 3, numbered 1-43 with no gaps
//
// Plus the FIX-ROUND MUTATIONS at the end of this block, numbered 44-51 and
// counted the same way.
//
// SIX OF THE 43 FIRST CAME BACK BUILD-FAIL rather than a verdict, because
// disabling a branch with `if (false)` is CS0162 under TreatWarningsAsErrors.
// They were re-run with a runtime-false, non-constant condition and are recorded
// below with the verdicts from that re-run - not as kills, which is what leaving
// a compile error in the ledger would have quietly claimed.
//
// THE SIX ARE MUTATIONS 2, 4, 5, 7, 10 AND 18 - the record did not say, which is
// the traceability gap this note closes, so the set is RECONSTRUCTED and then
// CHECKED rather than asserted. Reconstruction: exactly six rows in the list
// disable the BODY of an `if`, and they are those six - the downward adjacency
// branch, the upward adjacency branch, the downward coalesce, the containment
// guard, the insert-position guard, and the floor check. Every other row deletes
// a statement (36-39, 41, 31), flips an operator, or rewrites a term in a
// condition, and none of those makes anything unreachable.
//
// Checked, because the first attempt at this derivation was wrong in a way only
// running it exposed: `if (false && cond)` compiles CLEAN - the reachability rule
// keys on the condition being the constant `false` itself, not on it folding to
// false - so it kills mutation 7 as an ordinary verdict and produces no CS0162 at
// all. The bare `if (false)` was then run against three of the six (2, 7 and 18)
// and each returned CS0162, which is the form the original record must have used.
// It is also, usefully, the form to AVOID: `if (false && cond)` is the
// runtime-false, non-constant condition that re-run needed in the first place.
//
// KILLED ON THE FIRST SWEEP. Forty rows, five of them re-listed from SURVIVED
// THEN WITNESSED below, so thirty-five distinct. The marker below appears on
// those five rows and NOWHERE ELSE in this file, so the subtraction is a grep:
// `grep -c '\[RE-LISTED\]'` over this file must return 5 - the bracketed form,
// because the bare string also matches this sentence. Named by the test
// that fires, or by the count where several do:
//
//    1. downward adjacency +1 -> +2                      9 tests
//    2. downward adjacency branch deleted                9 tests
//    3. upward adjacency +1 -> +2                        7 tests
//    4. upward adjacency branch deleted                  4 tests
//    5. downward coalesce deleted                        ONLY FillingAOnePacketHoleCoalescesTheRangesOnBothSidesOfIt
//    6. coalesce condition Largest+1 -> Largest          ONLY FillingAOnePacketHoleCoalescesTheRangesOnBothSidesOfIt
//    7. containment guard deleted                        4 tests
//    8. containment lower bound >= -> >                  2 tests   [RE-LISTED]
//    9. containment upper bound <= -> <                  ONLY ADuplicatePacketNumberChangesNothing
//   10. insert-position guard deleted                    6 tests
//   11. insert at index+1 (descending order broken)      5 tests
//   12. tail Add -> Insert(0) (descending order broken)  6 tests
//   13. prune threshold <= -> <                          ONLY ARangeSetExactlyAtTheLimitIsNotPrunedAndRaisesNoFloor   [RE-LISTED]
//   14. prune drops the NEWEST ranges, not the oldest    4 tests
//   15. s13.2.3 floor never raised                       ONLY APacketBelowTheFloorLeftByAPruneIsNotReadmitted
//   16. floor set from Largest instead of Smallest       ONLY TheFloorIsTheSmallestOfTheLowestRetainedRangeNotItsLargest   [RE-LISTED]
//   17. floor check < -> <=                              8 tests
//   18. floor check deleted                              ONLY APacketBelowTheFloorLeftByAPruneIsNotReadmitted
//   19. ack_delay shift right -> left                    4 tests
//   20. ack_delay exponent ignored                       4 tests
//   21. ack_delay rounds half-up, not truncating         ONLY AckDelayTruncatesRatherThanRoundingToNearest
//   22. negative-elapsed clamp deleted                   ONLY AnAckBuiltBeforeThePacketArrivedReportsZeroDelayRatherThanWrapping
//   23. TicksPerMicrosecond 10 -> 1                      4 tests
//   24. delay clock stamped on every arrival             ONLY AckDelayIsMeasuredFromTheLargestPacketNumberNotTheLatestArrival
//   25. delay clock > -> >=                              ONLY ADuplicateOfTheLargestPacketDoesNotRestartTheDelayClock   [RE-LISTED]
//   26. pending flag |= -> =                             ONLY ANonAckElicitingPacketDoesNotCancelAnEarlierPacketsObligation
//   27. ack-eliciting forced true (shared table unused)  2 tests
//   28. force term dropped from the build gate           4 tests
//   29. pending term dropped from the build gate         4 tests
//   30. empty-space term dropped from the build gate     ONLY ForcingAnAckOnASpaceThatHasReceivedNothingStillBuildsNothing
//   31. pending flag not consumed on build               2 tests
//   32. largest-acked null term dropped                  4 tests
//   33. largest-acked monotonicity dropped               ONLY AReorderedAckNamingALowerLargestDoesNotLowerLargestAcked
//   34. largest-acked > -> >=                            ONLY ARepeatedAckAtTheSameLargestDoesNotMoveTheRttTimestamp   [RE-LISTED]
//   35. TryGetRanges' result ignored                     2 tests
//   36. packet-number ceiling check deleted              ONLY APacketNumberAboveTheSection123CeilingIsDroppedRatherThanThrowing
//       (the test was named ...IsRejected when this row was written; the check
//       threw then and drops now - see mutations 46 and 47)
//   37. ack_delay_exponent upper bound deleted           ONLY AnAckDelayExponentAboveTwentyIsRejected
//   38. ack_delay_exponent negative check deleted        ONLY ANegativeAckDelayExponentIsRejected
//   39. maximumAckRanges >= 1 check deleted              ONLY ARangeLimitBelowOneIsRejected
//   40. SpaceOf from the enum ordinal (EarlyData/Handshake swapped)
//                                                        ONLY ZeroRttAndOneRttShareTheOneApplicationDataSpace
//
// (Recompute: forty rows, less the five re-listed ones - 8, 13, 16, 25 and
// 34 - is thirty-five. They appear here because they kill NOW, and are COUNTED
// in the next section because they did not on the first sweep. Marking them is
// what makes the subtraction checkable; the previous revision listed them twice
// unmarked and then asserted a total that matched neither reading.)
//
// SURVIVED THEN WITNESSED (5). Five rows. Each survived the first sweep with the whole Quic
// suite green, which is the finding: five separate defects would have shipped
// behind a passing gate. A test was added per survivor and the mutation re-run
// to confirm the kill - the [REGRESSION] rows above are those re-runs.
//
//    8. containment lower bound >= -> >   Every duplicate tested landed at a
//       range's Largest or strictly inside it, never on its Smallest. Fixed by
//       ADuplicateOfTheSmallestPacketInAWideRangeChangesNothing.
//   13. prune threshold <= -> <           At Count == limit the RemoveRange it
//       reaches removes zero entries, so the sole effect is the s13.2.3 floor
//       rising when nothing was discarded. Every other limit test sat strictly
//       OVER the limit, where both readings behave identically. Fixed by
//       ARangeSetExactlyAtTheLimitIsNotPrunedAndRaisesNoFloor.
//   16. floor from Largest not Smallest   Every prune test pruned down to
//       ONE-PACKET ranges, where the two fields hold the same number. Fixed by
//       TheFloorIsTheSmallestOfTheLowestRetainedRangeNotItsLargest.
//   25. delay clock > -> >=               THE DOC-VERSUS-IMPLEMENTATION CASE:
//       the comparison's own comment said a duplicate of the largest does not
//       restart s13.2.5's clock, and nothing tested it, so code and comment
//       agreed with nothing to arbitrate. Fixed by
//       ADuplicateOfTheLargestPacketDoesNotRestartTheDelayClock.
//   34. largest-acked > -> >=             Reassigns the same number, so only
//       LargestAckedAt moves - A3's RTT sample would grow by the interval
//       between a peer's repeated ACKs. Fixed by
//       ARepeatedAckAtTheSameLargestDoesNotMoveTheRttTimestamp.
//
// SURVIVED, CLASSIFIED (3). Three rows. No test is written for any of these:
// each would pass against its own mutant and become a false witness.
//
//   41. ack_delay varint cap deleted      VACUOUS, and the cap is now deleted
//       rather than kept - see TryBuildAck for the arithmetic showing the widest
//       expressible delay is ~14x below the narrowest unencodable value.
//   42. insert-position > -> >=           UNREACHABLE BY CONSTRUCTION. Reaching
//       that line with packetNumber == range.Largest is impossible: the
//       containment guard above tests `packetNumber <= Largest && >= Smallest`,
//       and Smallest <= Largest == packetNumber satisfies both, so it returns
//       first. The two operators are equal on every input that gets there.
//   43. SpaceOf Initial and Handshake swapped   VACUOUS. Both are private array
//       indices, and the swap is a consistent bijective relabelling - every
//       write and every read moves together, so no caller can observe it. NOT
//       the same as mutation 40, which is killed: swapping EarlyData with
//       Handshake breaks the grouping s13.2.6 requires, since EarlyData and
//       Application must share one slot.
//
// (Recompute the total: 35 + 5 + 3 = 43, which is the highest number used and
// there are no gaps, so the numbering and the arithmetic agree. The previous
// revision said "forty-three numbered entries for forty-two mutations" and gave
// two reasons - the ack_delay cap appearing once, mutation 10's guard being
// mutated two ways - both of which explain why the entries are DISTINCT, and
// neither of which merges any two of them. There was never a forty-second
// mutation; there were forty-three.)
//
// ---- FIX-ROUND MUTATIONS (8). Eight rows, numbered 44-51, none re-listed ----
//
// Run after the two review passes, against the fixes in this round. Same
// worktree, same gate.
//
//   44. Prune never called at all (runtime-false guard on the OnPacketReceived
//       call, so no CS0162)              7 tests
//   45. Prune moved back to TryBuildAck, the pre-fix arrangement - the bound
//       exists but only at send time
//                                        ONLY TheRangeLimitIsAppliedOnArrivalNotOnlyWhenAnAckIsBuilt
//   46. s12.3 ceiling drop > -> >=       ONLY ThePacketNumberCeilingItselfIsAccepted
//   47. s12.3 ceiling drop deleted       ONLY APacketNumberAboveTheSection123CeilingIsDroppedRatherThanThrowing
//   48. gap operand ranges[i].Largest -> .Smallest  (the mutation that survived
//       the test named for the formula before this round widened its ranges)
//                                        7 tests - 4 here, 3 in TlsQuicAckFramesTests -
//                                        including TheGapIsPreviousSmallestMinusLargestMinus
//                                        TwoAndNotTheReverse, which SURVIVED this same
//                                        mutation until this round widened its ranges
//   49. downward coalesce Largest + 1 -> Largest + 2, the OVER-merge direction
//                                        2 tests
//   50. TlsQuicConnectionSpec.AckRangeLimit's ThrowIfLessThan(value, 1) deleted
//                                        ONLY ARangeLimitBelowOneIsRejectedBySpecTooNotOnlyByTheTracker
//   51. ProcessAckFrame's TryGetRanges call skipped, so the validate-only null
//       path never runs                  2 tests
//
// ---- A3-4 ROUND: RFC 9002 s5 RTT ESTIMATION. 47 rows, numbered 52-98 ----
//
// Run in a private worktree at 0e4d07c carrying ONLY this file and its tests, so
// no other agent's uncommitted work in the shared tree could account for a
// verdict. Gate `dotnet test --filter "FullyQualifiedName~Quic"`: 2166 passing at
// pristine HEAD, 2190 after, which is the 24 tests this task adds and no existing
// case altered.
//
// VERDICTS ARE ASSIGNED STRUCTURALLY, NOT PARSED OUT OF A LOG. The harness
// branches on the build's exit code BEFORE any test process starts, so a compile
// failure can only produce KILLED-BY-COMPILER and can never be published as a kill
// against a named test. Written down because the obvious alternative - matching
// `(KILLED|SURVIVED|KILLED-BY-COMPILER)` over output - lets KILLED shadow
// KILLED-BY-COMPILER on every compiler kill, and the note above records six rows of
// the first sweep that were exactly that mistake.
//
// THREE ROWS CAME BACK KILLED-BY-COMPILER AND ARE RECORDED AS RECAST, NOT AS KILLS.
// 60 and 75 delete a field's only assignment, which is CS0649 here; 85 self-assigns,
// which is CS1717. Each was re-expressed as a runtime-wrong assignment - `= null`,
// `= TimeSpan.Zero`, `= false` - and the verdict below is from that form. `if (false)`
// is never written: CS0162 is an error in this tree and returns KILLED-BY-COMPILER,
// which proves nothing. `COND && false` is used throughout.
//
// THE HARNESS WAS CALIBRATED IN BOTH DIRECTIONS, and the calibration itself had to be
// re-run. A known-bad edit - the min_rtt comparison inverted - returns KILLED with 10
// failures; an inert comment added to UpdateRtt returns SURVIVED with 0. Neither is
// counted below. The first attempt at that calibration was WORTHLESS, and it says so
// here because the only reason anyone knows is that its numbers were read rather than
// trusted: its two rows were 4-tuples unpacked by a loop written for a different
// 4-tuple, so the text it searched for was the MUTATED string, the replace matched
// nothing, the file was never modified, and both rows reported SURVIVED against
// pristine source. The uniqueness assertion that would have caught it was applied to
// the real cases and not to the calibration rows - the check was skipped in exactly
// the place where the check was the entire point.
//
//   KILLED AS FIRST WRITTEN         43  = 47 rows, less 3 recast, less 1 survivor
//   KILLED ONLY AFTER RECAST         3  = rows 60, 75, 85
//   SURVIVED THEN WITNESSED          1  = row 98
//                                  ---
//   A3-4 MUTATIONS                  47  = 43 + 3 + 1, numbered 52-98 with no gaps
//
// Plus 3 RE-VERIFICATION rows at the end. They are NOT new mutations and are not in
// the 47: they are existing ledger pins whose lines this task rewrote, re-run because
// a kill recorded against code that no longer exists is a claim about a deleted file.
//
// Named by the test that fires, or by the count where several do:
//
//   52. s5.1 first condition dropped, sample on every ACK
//                                    ONLY ADuplicatedAcknowledgementProducesNoSecondRttSample
//   53. s5.1 ack-eliciting term dropped               2 tests
//   54. negative-elapsed guard dropped
//                                    ONLY AnAcknowledgementArrivingBeforeItsPacketWasSentProducesNoSample
//   55. largest-newly-acked > -> >=                   2 tests - including ARepeatedAckAtTheSame
//                                    LargestDoesNotMoveTheRttTimestamp, the existing pin for row 34
//   56. sample measured from the ACK's arrival, not the send time        17 tests
//   57. first-sample branch disabled (runtime-false, not CS0162)         15 tests
//   58. first sample does not set min_rtt              6 tests
//   59. first sample rttvar = whole sample             2 tests
//   60. [RECAST] first_rtt_sample never recorded, so every sample initialises   14 tests
//   61. min_rtt comparison inverted                   10 tests
//   62. min_rtt never updated after the first sample   2 tests
//   63. min_rtt lowered by the peer's raw reported delay
//                                    ONLY SmoothedRttStaysBetweenMinRttAndTheLargestSampleAcrossALongSequence
//   64. max_ack_delay cap applied unconditionally      5 tests
//   65. max_ack_delay cap never applied                2 tests
//   66. cap takes the greater, not the lesser          2 tests
//   67. below-min_rtt guard removed, always subtract   4 tests
//   68. below-min_rtt guard >= read as >
//                                    ONLY AnAcknowledgementDelayThatLandsExactlyOnMinRttIsStillSubtracted
//   69. below-min_rtt guard never subtracts            5 tests
//   70. s5.3 PROSE ORDER: smoothed_rtt updated before rttvar is measured
//                                                      2 tests - see DEPARTURE 4 on UpdateRtt
//   71. smoothed_rtt weight 7/8 read as 3/4            9 tests
//   72. rttvar weight 3/4 read as 7/8                  2 tests
//   73. rttvar sample signed, abs() dropped            3 tests
//   74. smoothed_rtt never moves after the first sample                 10 tests
//   75. [RECAST] latest_rtt never recorded             8 tests
//   76. ack_delay decoded with OUR exponent instead of the peer's        2 tests
//   77. ack_delay decode shifts right, not left        5 tests
//   78. s5.3's Initial-packet MAY dropped
//                                    ONLY AnInitialPacketsAcknowledgementDelayIsIgnored
//   79. the Initial-only MAY widened to Handshake      5 tests
//   80. saturation bound removed, the shift wraps
//                                    ONLY AnAcknowledgementDelayAtTheVarintMaximumNeitherThrowsNorWraps
//   81. peer ack_delay_exponent not clamped
//                                    ONLY OnPeerAckParametersClampsOutOfRangeValuesRatherThanThrowing
//   82. peer max_ack_delay upper clamp dropped         ONLY OnPeerAckParametersClamps... (as above)
//   83. peer max_ack_delay negative clamp dropped      ONLY OnPeerAckParametersClamps... (as above)
//   84. s18.2's 25 ms max_ack_delay default read as zero
//                                    ONLY MaxAckDelayCapsTheReportedDelayOnlyAfterTheHandshakeIsConfirmed
//   85. [RECAST] OnHandshakeConfirmed does nothing     2 tests
//   86. range membership always true
//                                    ONLY ARetainedPacketOutsideTheAcknowledgedRangesDoesNotMakeTheSampleEligible
//   87. Covers upper bound > read as >=               17 tests
//   88. Covers lower bound >= read as >               17 tests
//   89. ack-eliciting accumulated with = instead of |=
//                                    ONLY AnUnsortedSentPacketListStillAnswersBothOfSection51sQuestions
//   90. the largest match accepts any newly acked packet                 2 tests
//   91. the reusable range list is never cleared                        10 tests
//   92. ranges never decoded, so the sampling path sees an empty list    20 tests
//   93. rttvar seeded with the whole initial RTT, not half
//                                    ONLY BeforeAnySampleTheEstimatorHoldsAppendixA4sInitialisation
//   94. smoothed_rtt not seeded from the initial RTT                     5 tests
//   95. the initial RTT read from TlsQuicTransportParameterSpec.Brave151InitialRttRange
//       instead of TlsQuicRecoverySpec.KInitialRtt                       5 tests
//   96. the negative-seed rejection removed            ONLY ANegativeInitialRttIsRejected
//   97. microsecond-to-tick conversion dropped from the ack_delay decode  5 tests
//   98. the validate-only path allocates a list instead of passing null   [A34-RE-LISTED]
//                                    ONLY TheValidateOnlyPathWalksTheRangeChainWithoutAllocating
//
// (Recompute: the list above holds 48 numbered lines for 47 distinct mutations,
// because row 98 appears here AND in the section below - it kills NOW, and it is
// COUNTED there because it did not on the first pass. The marker sits on that one
// row and NOWHERE ELSE in this file, so the subtraction is a grep:
// `grep -c '\[A34-RE-LISTED\]'` over this file must return 1, and 48 - 1 = 47 is
// the total the arithmetic above states. The escaped bracketed form is used for
// the reason the re-listed note above gives - written plainly, the pattern would
// match this sentence too and the check would count itself. That note's own grep
// is unaffected: its marker and this one are different strings.)
//
// SURVIVED THEN WITNESSED (1). One row. It survived with the whole Quic suite green,
// which is the finding: the property it breaks was asserted in a comment and by
// nothing else.
//
//   98. the validate-only path allocates   UNWITNESSED, NOT VACUOUS AND NOT UNREACHABLE.
//       Passing a real list where ProcessAckFrame passes null CHANGES NO OUTPUT AT ALL
//       - every behavioural assertion in TlsQuicAckTrackerTests still passed - it
//       merely allocates on every ACK this endpoint receives and never releases, which
//       is the "allocation on the receive path whose size is the attacker's to pick"
//       that method's own remark exists to forbid. No behavioural test can see it, so
//       the witness measures GC.GetAllocatedBytesForCurrentThread across a thousand
//       calls after a warmup. Fixed by TheValidateOnlyPathWalksTheRangeChainWithout
//       Allocating, and the mutation re-run to confirm the kill.
//
// SURVIVED, CLASSIFIED (0). No row. One candidate was considered and DELIBERATELY NOT
// RUN, because it is equivalent by construction rather than merely unwitnessed, and a
// SURVIVED verdict against it would have meant nothing while looking like a finding:
//
//   min_rtt computed from adjusted_rtt instead of latest_rtt. s5.2 forbids it - "An
//   endpoint uses only locally observed times in computing the min_rtt" - but the two
//   readings cannot differ. Whenever latest_rtt is the new minimum, latest_rtt -
//   min_rtt is zero, so s5.3's guard refuses every nonzero ack_delay and adjusted_rtt
//   IS latest_rtt; and whenever latest_rtt is not the new minimum, min_rtt does not
//   move under either reading. Row 63 is the REACHABLE neighbour of this - min_rtt
//   lowered by the peer's raw reported delay, which that guard does not gate - and it
//   is killed.
//
// ---- RE-VERIFICATION OF EXISTING PINS (3). Not counted in the 47 above ----
//
// Every one sits on a line A3-4 rewrote, so its original kill was recorded against
// code that no longer exists in that form.
//
//   34. largest-acked > -> >=              2 tests - STILL KILLED. The comparison is now
//       also s5.1's first condition, and both its original witness and this task's
//       duplicate-ACK test fire on it.
//   35. TryGetRanges' result ignored       2 tests - STILL KILLED, through the rewritten
//       call that now passes a list rather than always null.
//   40. SpaceOf from the enum ordinal     57 tests - STILL KILLED after the widening from
//       private to internal, led by ZeroRttAndOneRttShareTheOneApplicationDataSpace.
//
// ============================================================================
// TASK A3-13 - THE AckPolicy MUTATION LEDGER, SEPARATELY PREFIXED
// ============================================================================
//
//   ROWS BELOW                   27  = 2 controls + 25 mutants, A313-C1..C2 and A313-M01..M25,
//                                      numbered with no gaps
//   KILLED                       23  = 27 rows, less the 4 that survived
//   SURVIVED                      4  = A313-C1, A313-M13, A313-M23, A313-M24 - every one
//                                      classified below as unreachable, vacuous or unwitnessed
//   2 + 25 = 27, and 23 + 4 = 27.
//
// Two greps, anchored on the prefix so that the numbered rows ABOVE - which belong to an
// earlier task and use a different form - cannot match. Run from this file's directory:
//   `grep -cE '^// A313-(C|M)[0-9]+ ' TlsQuicAckTracker.cs`            must return 27
//   `grep -cE '^// A313-(C|M)[0-9]+ .*SURVIVED' TlsQuicAckTracker.cs`  must return 4
//
// SIX OF THE 27 ROWS MUTATE TlsQuicConnection.cs AND ONE MUTATES A TEST FILE, and they are
// here rather than split three ways because the knob is one seam: the tracker decides, the
// connection plumbs and schedules, and A3-12's readout probe is what proves the pair wired.
// Splitting the ledger by file would put the deadline entry in a different document from the
// withholding it exists to bound.
//
// MEASURED IN A PRIVATE WORKTREE AT efdb125, floor 2490. Gate 2471 passing at pristine
// efdb125, 2484 after this task: 2484 - 2471 = 13 cases added, which is this task's 13 new
// tests exactly. Every run rebuilt --no-incremental and was rejected unless the runner
// reported at least 2490 executed cases.
//
// AND THE FIRST SWEEP OF THIS TASK WAS THROWN AWAY, which is recorded because the reason is
// reusable. It was hard-killed mid-row; that orphaned its testhost; the orphan held a lock on
// SharpTls.dll; every later build then failed MSB3027 and the harness, which assigns
// KILLED-BY-COMPILER structurally from the build's exit code, scored 23 rows as compiler
// kills they had not earned. THE INERT CONTROL IS WHAT CAUGHT IT - A313-C1 cannot fail to
// compile, so its REVIEW flag was the whole signal. Three changes followed and are in
// mutate-ackpolicy.py: the harness re-seeds every touchable file from the authoritative tree
// at STARTUP (a finally and an atexit do not survive a hard kill), it reaps leftover
// build and test processes matched on the WORKTREE PATH in their command line rather than on
// the image name, and a build that fails MSB3027/MSB3021 is scored ABORTED rather than
// credited to the mutant - a file lock is not a compile error. The structural rule stands;
// it now has one named exception and this is the reason for it.
//
// -- the controls, proved before anything else was trusted -- 2 rows -----------------
// A313-C1 an inert comment added to this class ....... SURVIVED  by construction. The row
//         that voided the first sweep by refusing to survive it.
// A313-C2 IsWithheldAt forced false (&& false) ....... KILLED  7 tests
//
// -- IsWithheldAt, one row per term -- 5 rows ---------------------------------------
// A313-M01 the policy test inverted (== to !=) ....... KILLED  the gate hung past 300s. A
//          HANG IS A KILL AND NOT A HEDGE: under this mutant the SHIPPED DEFAULT withholds
//          every 1-RTT ACK with no deadline armed to release it, so dozens of tests wait on
//          real deadlines. The gate did not go green inside the budget.
// A313-M02 the space test weakened to `space >= 0` ... KILLED  1 test, EveryPolicyAcknowledges
//          InitialAndHandshakeInTheArrivalInstant - RFC 9000 s13.2.1's Initial MUST, and the
//          one row that proves the knob cannot reach two of the three spaces.
// A313-M03 the bound relaxed (< to <=) .............. KILLED  4 tests
// A313-M04 the bound inverted (< to >) .............. KILLED  7 tests
// A313-M05 anchored on _largestReceivedAt instead ... KILLED  1 test, TheDelayedDeadlineIs
//          AnchoredOnTheOldestUnacknowledgedPacketNotTheNewest
//
// -- the call into it, in TryBuildAck -- 2 rows -------------------------------------
// A313-M06 the force bypass deleted ................. KILLED  1 test, AForcedBuildIsNever
//          Withheld
// A313-M07 the whole withholding block deleted ...... KILLED  7 tests
//
// -- the receive path's record of when the debt began -- 3 rows ---------------------
// A313-M08 the pendingSince write deleted ........... KILLED  9 tests
// A313-M09 the false-to-true edge guard dropped ..... KILLED  1 test, the oldest-not-newest
//          witness again - the only row that separates the two fields.
// A313-M10 pendingSince written as default .......... KILLED  9 tests
//
// -- DelayedAckDeadline, one row per term -- 5 rows ---------------------------------
// A313-M11 the policy conjunct forced true .......... KILLED  2 tests
// A313-M12 the pending conjunct forced true ......... KILLED  3 tests
// A313-M13 the range-count conjunct forced true ..... SURVIVED  UNREACHABLE BY CONSTRUCTION,
//          and PREDICTED AS SUCH IN THIS FILE BEFORE THE SWEEP RAN - see DelayedAckDeadline's
//          third remark. A range is inserted before the debt is recorded and Prune never
//          empties a space it kept, so "a debt with no ranges" cannot arise to be tested. The
//          conjunct is KEPT rather than deleted: it closes a spin in which the deadline fires,
//          the build returns false, and the pump re-arms on the same past instant every pass.
//          A test for it would have to construct a state that cannot exist.
// A313-M14 the bound added as a subtraction ......... KILLED  5 tests
// A313-M15 anchored on _largestReceivedAt instead ... KILLED  1 test
//
// -- the constant and the constructor -- 3 rows -------------------------------------
// A313-M16 ApplicationSpace derived from Initial .... KILLED  10 tests
// A313-M17 the ctor argument dropped on the floor ... KILLED  9 tests
// A313-M18 the ctor default flipped to Delayed ...... KILLED  4 tests. THE DEFAULT-PARITY ROW:
//          the shipped default's emitted bytes are pinned as a byte array, so moving the
//          default cannot pass as a timing change.
//
// -- TlsQuicConnection.cs: the plumbing and the deadline entry -- 6 rows -------------
// A313-M19 the ctor passes Immediate, ignoring spec . KILLED  3 tests
// A313-M20 the fifth EarliestDeadline entry deleted . KILLED  1 test, AHeldAcknowledgement
//          WakesThePumpAtMaxAckDelayWithoutRunningTheTimeout. ONE TEST AND IT IS THE RIGHT
//          ONE: nothing else in the suite can tell a held ACK from a dropped one.
// A313-M21 the wake kind changed to Recovery ........ KILLED  1 test - the same test's
//          LossDetectionTimeouts assertion, which exists for exactly this mutant.
// A313-M22 the wake kind changed to Abandonment ..... KILLED  1 test
// A313-M23 the entry's tie-break relaxed (< to <=) .. SURVIVED  VACUOUS. It differs only when
//          the held ACK falls due on the very same tick as the nearest other deadline. No test
//          constructs that tie and none should: the two instants are computed from unrelated
//          quantities, so the tie is an accident of arithmetic rather than a state worth
//          pinning. Named rather than left as an unexplained green row.
// A313-M24 the pacing early-return restored .......... SURVIVED  UNWITNESSED, AND IT IS THE
//          EVIDENCE FOR A CLAIM THIS TASK MADE IN PROSE. EarliestDeadline's pacing branch was
//          rewritten from `return` to an assignment so the ACK entry could follow it, and the
//          new comment there calls that "behaviour-preserving by inspection". This row tests
//          the inspection: the two forms diverge only when a pacing release AND a held ACK are
//          outstanding together with pacing the nearer of the two, and no test puts a
//          connection in both states at once. So the claim holds everywhere the suite looks,
//          and the one state that would separate them is now named instead of merely absent.
//
// -- A3-12's readout probe, which is this task's acceptance test -- 1 row ------------
// A313-M25 the probe moved back to Initial .......... KILLED  2 tests - the snapshot and
//          TheAckPolicyInForceRowWitnessesThatSomethingReadsKnob12. This row is why that
//          second test was added: before it, moving the probe changed only what the readout
//          RENDERED and turned nothing red.
//
internal sealed class TlsQuicAckTracker
{
    // RFC 9000 s12.3's three spaces: Initial, Handshake, and the one Application
    // data space that 0-RTT and 1-RTT packets share. The same collapse
    // TlsQuicPacketReceiver.SpaceOf makes, and for the same reason - s13.2.6:
    // "Packets that a client sends with 0-RTT packet protection MUST be
    // acknowledged by the server in packets protected by 1-RTT keys", so the two
    // levels are one space and cannot have separate range sets.
    private const int PacketNumberSpaceCount = 3;

    // RFC 9000 s18.2, ack_delay_exponent (0x0a): "If this value is absent, a
    // default value of 3 is assumed (indicating a multiplier of 8)." Named so the
    // tests that use a NON-default exponent can say which value they are departing
    // from without restating the number.
    internal const int DefaultAckDelayExponent = 3;

    // s18.2 again: "Values above 20 are invalid." The same bound
    // TlsQuicTransportParameters enforces when parsing a peer's block; enforced
    // again here because this value arrives from a caller, not from that parser.
    internal const int MaximumAckDelayExponent = 20;

    // RFC 9000 s18.2, max_ack_delay (0x0b): "If this value is absent, a default of
    // 25 milliseconds is assumed. Values of 2^14 or greater are invalid."
    //
    // THE DEFAULT IS THE OPERATIVE VALUE HERE, NOT A FALLBACK NOBODY REACHES. The
    // A3 plan's Finding 7 checked Brave 151's fourteen transport parameters and
    // max_ack_delay is not among them, so a Chromium-shaped peer sends none and
    // this default is what s5.3's "the peer's max_ack_delay" resolves to for the
    // whole connection. Both numbers are read off
    // rfc9000-section18-transport-parameters.txt rather than recalled.
    internal static readonly TimeSpan DefaultMaxAckDelay = TimeSpan.FromMilliseconds(25);

    // "Values of 2^14 or greater are invalid", so the largest legal one is 2^14-1.
    internal static readonly TimeSpan MaximumMaxAckDelay =
        TimeSpan.FromMilliseconds((1 << 14) - 1);

    private readonly List<TlsQuicAckRange>[] _ranges =
        [.. Enumerable.Range(0, PacketNumberSpaceCount).Select(_ => new List<TlsQuicAckRange>())];

    // Whether an ack-eliciting packet has arrived in this space that no ACK frame
    // has yet been built for. NOT the same question as "are there ranges": s13.2
    // separates them explicitly - "Endpoints acknowledge all packets they receive
    // and process. However, only ack-eliciting packets cause an ACK frame to be
    // sent within the maximum ack delay. Packets that are not ack-eliciting are
    // only acknowledged when an ACK frame is sent for other reasons." A space can
    // therefore hold ranges and still owe no ACK, which is exactly the state a
    // single "is the range set empty" test would collapse.
    private readonly bool[] _ackElicitingPending = new bool[PacketNumberSpaceCount];

    // When the debt above was INCURRED - the arrival of the first ack-eliciting packet
    // since the last ACK was built for this space. Meaningless while the flag beside it
    // is false, and never read then.
    //
    // NOT _largestReceivedAt, AND THE DIFFERENCE IS THE WHOLE OF s13.2.1's BOUND. That
    // field is s13.2.5's - the arrival of the LARGEST packet number - and it moves
    // forward every time a higher-numbered packet lands. An ACK deadline anchored on it
    // would be pushed back by every new packet, so a peer sending a steady stream would
    // never see an acknowledgement at all: the deadline would recede exactly as fast as
    // the clock advanced. s13.2.1's promise is per packet - "ack-eliciting packets MUST
    // be acknowledged at least once within the maximum delay an endpoint communicated
    // using the max_ack_delay transport parameter" - so the bound belongs to the OLDEST
    // unacknowledged one, which is this. The two fields are therefore both kept and both
    // used, for two different sentences, and TheDelayedDeadlineIsAnchoredOnTheOldest
    // UnacknowledgedPacketAndNotTheNewest is the witness that they have not been merged.
    private readonly DateTimeOffset[] _ackElicitingPendingSince =
        new DateTimeOffset[PacketNumberSpaceCount];

    // s12.3's application data space, derived from the mapping rather than written as a
    // 2. It is the only space TlsQuicRecoverySpec.AckPolicy can reach - see IsWithheldAt
    // - and a literal here would be a second transcription of SpaceOf that could drift
    // away from it silently.
    private static readonly int ApplicationSpace =
        SpaceOf(TlsQuicEncryptionLevel.Application);

    // KNOB 12 - TlsQuicRecoverySpec.AckPolicy - AND THIS FIELD IS ITS ONLY READER IN THE
    // ASSEMBLY. Everything the knob does is IsWithheldAt and DelayedAckDeadline below.
    //
    // NOT VALIDATED HERE, AND NOT ABLE TO THROW. TlsQuicRecoverySpec.AckPolicy's init
    // rejects an undeclared cast at the seam a caller reaches, so a value arriving here
    // has already been through ThrowIfNotDefined. What defends this class independently
    // is that both readers test for DelayedToMaxAckDelay by EQUALITY rather than
    // switching with a throwing default: an undeclared value that reached this field by
    // some other route acknowledges immediately, which is the shipped behaviour, rather
    // than killing a connection on the receive path.
    private readonly TlsQuicAckPolicy _ackPolicy;

    // When the packet bearing the LARGEST packet number in this space arrived -
    // s13.2.5: "An endpoint measures the delays intentionally introduced between
    // the time the packet with the largest packet number is received and the time
    // an acknowledgment is sent." The largest, not the latest: a reordered packet
    // arriving afterwards with a smaller number must not restart this clock, or
    // the reported delay shrinks by the reordering interval and the peer's RTT
    // estimate inherits the error.
    private readonly DateTimeOffset[] _largestReceivedAt =
        new DateTimeOffset[PacketNumberSpaceCount];

    // The floor s13.2.3 requires once ranges are dropped: "A receiver MUST retain
    // an ACK Range unless it can ensure that it will not subsequently accept
    // packets with numbers in that range. Maintaining a minimum packet number that
    // increases as ranges are discarded is one way to achieve this with minimal
    // state." This is that minimum, and Prune is the only thing that raises it.
    // Zero until the first drop, which costs nothing: packet number 0 is >= 0, so
    // an untouched space accepts everything.
    private readonly ulong[] _minimumPacketNumber = new ulong[PacketNumberSpaceCount];

    // Largest Acknowledged across every ACK frame this endpoint has RECEIVED in
    // this space - the read side, unrelated to the ranges above. Nullable because
    // "no ACK has ever arrived" is not "an ACK acknowledged packet 0": packet
    // number 0 is a real, sendable, acknowledgeable packet (s17.1 gives the field
    // no lower exclusion), so a plain ulong defaulting to 0 could not tell the two
    // apart, and task 4b's packet-number encoding reads this to decide how many
    // bytes it needs.
    private readonly ulong?[] _largestAcked = new ulong?[PacketNumberSpaceCount];

    private readonly DateTimeOffset[] _largestAckedAt =
        new DateTimeOffset[PacketNumberSpaceCount];

    // ---- RFC 9002 s5's RTT estimator ---------------------------------------
    //
    // NOT PER SPACE, AND THAT IS THE ONE STRUCTURAL DECISION s5 MAKES FOR US.
    // Everything above this line is an array of three because s12.3 splits it;
    // these five are scalars because s5 opens "An endpoint computes the following
    // three values FOR EACH PATH", and Appendix A.3 lists latest_rtt,
    // smoothed_rtt, rttvar, min_rtt and first_rtt_sample as plain variables while
    // listing largest_acked_packet, loss_time, sent_packets and
    // time_of_last_ack_eliciting_packet as [kPacketNumberSpace] arrays. A
    // per-space estimator would be four estimators for one path, each with a
    // quarter of the history, and s5.1 already warns that too little history is
    // the failure mode: "doing so might result in inadequate history in
    // smoothed_rtt and rttvar."
    //
    // A.4's initialization, one field per line there: latest_rtt = 0,
    // smoothed_rtt = kInitialRtt, rttvar = kInitialRtt / 2, min_rtt = 0,
    // first_rtt_sample = 0.
    private TimeSpan _latestRtt;
    private TimeSpan _minimumRtt;
    private TimeSpan _smoothedRtt;
    private TimeSpan _rttVariation;

    // A.3: "first_rtt_sample: The time that the first RTT sample was obtained."
    // ONE FIELD RATHER THAN A bool PLUS A DateTimeOffset, because A.7 tests it as
    // a flag - `if (first_rtt_sample == 0)` - and s7.6's persistent congestion
    // reads it as a time. Two fields would be two things to keep in step for a
    // question that has one answer.
    private DateTimeOffset? _firstRttSampleAt;

    // The PEER'S ack_delay_exponent and max_ack_delay, which are not ours and not
    // interchangeable with ours. See ProcessAckFrame and OnPeerAckParameters.
    // s18.2's absent-value defaults until the peer's parameters arrive - which for
    // max_ack_delay is very likely forever; see DefaultMaxAckDelay.
    private int _peerAckDelayExponent = DefaultAckDelayExponent;
    private TimeSpan _peerMaxAckDelay = DefaultMaxAckDelay;

    // s5.3: "SHOULD ignore the peer's max_ack_delay until the handshake is
    // confirmed". False until OnHandshakeConfirmed, and it only ever goes true.
    private bool _handshakeConfirmed;

    // ONE LIST FOR THE LIFETIME OF THE TRACKER, not one per ACK frame. The remark
    // on ProcessAckFrame's TryGetRanges call records why the ranges were being
    // discarded at all: "an allocation on the receive path whose size is the
    // attacker's to pick". A3 needs the ranges now, and reusing one cleared list
    // keeps that sentence true - the peer chooses how far this grows within one
    // datagram's worth of ACK Ranges, but not how many such allocations exist, and
    // the rejecting path still allocates nothing at all because the validate-only
    // overload passes null exactly as before.
    private readonly List<TlsQuicAckRange> _decodedRanges = [];

    // NOT readonly. Its final value is this endpoint's ADVERTISED ack_delay_exponent, and the
    // ClientHello that carries it does not exist when this tracker is constructed - the
    // connection draws its source connection ID first, then builds the profile around it. The
    // constructor seeds s18.2's default and OnLocalAckParameters replaces it once the
    // advertisement is readable. See TlsQuicConnection.AdoptLocalAckParameters.
    private int _ackDelayExponent;

    // This endpoint's own max_ack_delay, for the same reason and by the same route. It used to
    // be the DefaultMaxAckDelay constant read directly at both of the two sites below, which
    // made a preset advertising 0x0B ignored: the wire said one bound and the ACK timer waited
    // another. s13.2.1 binds the timer to the ADVERTISED value, so the advertisement wins.
    private TimeSpan _localMaxAckDelay = DefaultMaxAckDelay;

    /// <summary>This endpoint's <c>ack_delay_exponent</c>, after
    /// <see cref="OnLocalAckParameters"/> has adopted the advertised one.</summary>
    internal int AckDelayExponent => _ackDelayExponent;

    /// <summary>This endpoint's <c>max_ack_delay</c>, after
    /// <see cref="OnLocalAckParameters"/> has adopted the advertised one. The bound
    /// <see cref="DelayedAckDeadline"/> waits under
    /// <see cref="TlsQuicAckPolicy.DelayedToMaxAckDelay"/>.</summary>
    internal TimeSpan LocalMaxAckDelay => _localMaxAckDelay;
    private readonly int _maximumAckRanges;

    /// <param name="ackDelayExponent">
    /// THIS ENDPOINT'S OWN advertised <c>ack_delay_exponent</c>, not the peer's -
    /// see the second numbered note on this class. RFC 9000 s18.2 defaults it to 3
    /// and invalidates values above 20.
    /// </param>
    /// <param name="maximumAckRanges">
    /// How many ACK Ranges this tracker retains and reports per space. BOTH
    /// verbs, and the retention half is enforced on the receive path - see
    /// <see cref="OnPacketReceived"/>, which prunes after every insert. An
    /// earlier revision bounded only what was reported, which left the sentence
    /// below half implemented in the half an attacker picks.
    ///
    /// RFC 9000 s13.2.3 STATES NO NUMBER. It states only that a bound exists - "A
    /// receiver limits the number of ACK Ranges (Section 19.3.1) it remembers and
    /// sends in ACK frames, both to limit the size of ACK frames and to avoid
    /// resource exhaustion" - and which end to drop from: "If it does not [fit
    /// within a single QUIC packet], then older ranges (those with the smallest
    /// packet numbers) are omitted." So the count is a sender's choice, the
    /// direction of omission is not, and only the direction is implemented as a
    /// rule; the count comes from here. See <c>TlsQuicConnectionSpec.AckRangeLimit</c>
    /// for why it is a spec knob and not a constant.
    ///
    /// Counted in inclusive packet-number ranges, which is one MORE than the wire's
    /// ACK Range Count field: s19.3 spends the first range on Largest Acknowledged
    /// and First ACK Range, and "ACK Range Count" counts only the Gap/Length pairs
    /// after it. The ambiguity is real - s13.2.3 says "ACK Ranges" and s19.3.1's
    /// "ACK Range" is the pair - and it is resolved toward what is actually
    /// retained, because that is what the sentence's "remembers" and "avoid
    /// resource exhaustion" are about. A limit of 1 is therefore legal and means
    /// "the newest contiguous run only", which still satisfies s13.2.3's "A
    /// receiver SHOULD include an ACK Range containing the largest received packet
    /// number in every ACK frame".
    /// </param>
    /// <param name="initialRtt">
    /// RFC 9002 A.4's <c>kInitialRtt</c> seed for <see cref="SmoothedRtt"/> and
    /// <see cref="RttVariation"/> before any sample exists, or <see langword="null"/>
    /// for <see cref="TlsQuicRecoverySpec.KInitialRtt"/>.
    ///
    /// THIS READS THE RECOVERY SPEC'S ANSWER AND NOT THE TRANSPORT PARAMETER'S, and
    /// naming which is the point of this paragraph, because there are currently two.
    /// <see cref="TlsQuicRecoverySpec.DrawInitialRtt"/> is the one source of an
    /// initial RTT for the RECOVERY side: it reads
    /// <c>TlsQuicConnectionSpec.InitialRttRange</c> when that names a range and
    /// falls back to <see cref="TlsQuicRecoverySpec.KInitialRtt"/> when it does not.
    /// The OTHER number - <c>TlsQuicTransportParameterSpec.Brave151InitialRttRange</c>,
    /// 100 to 300 ms - is the fallback of the transport-parameter ENTRY that
    /// advertises <c>initial_rtt</c> to the peer, and its 300 ms maximum sits below
    /// <see cref="TlsQuicRecoverySpec.KInitialRtt"/>'s 333 ms, which is precisely
    /// what makes the divergence observable rather than academic: an unconfigured
    /// client advertises a number it does not itself start from.
    ///
    /// <para>THIS TASK DOES NOT RESOLVE THAT, and takes care not to deepen it. The
    /// tracker does not call <see cref="TlsQuicRecoverySpec.DrawInitialRtt"/>
    /// itself: a draw is per connection and a second draw here would be a THIRD
    /// answer, differing from the advertised one by construction rather than by
    /// oversight. It takes the already-drawn value from whoever owns the connection
    /// spec, so there is exactly one draw per connection and this class holds no
    /// opinion about which range it came from. Deciding whether the two defaults
    /// should agree by construction is task A3-7's, as
    /// <see cref="TlsQuicRecoverySpec.DrawInitialRtt"/>'s own remarks record.</para>
    /// </param>
    /// <param name="ackPolicy">
    /// <see cref="TlsQuicRecoverySpec.AckPolicy"/> - knob 12 - which decides whether an
    /// ack-eliciting 0-RTT or 1-RTT packet is acknowledged in the instant it is processed
    /// or held back to <see cref="DefaultMaxAckDelay"/>. Initial and Handshake are
    /// unaffected by either value; RFC 9000 s13.2.1 makes them immediate outright.
    ///
    /// THE BOUND IS NOT A PARAMETER AND THAT IS DERIVED, NOT ASSUMED.
    /// <see cref="TlsQuicAckPolicy"/>'s own remarks refuse to carry the delay - "the
    /// bound this client is entitled to use is the one it advertised" - and this client
    /// advertises none: max_ack_delay (0x0B) is absent from
    /// <c>TlsQuicTransportParameterSpec</c>'s entry list, so s18.2's "If this value is
    /// absent, a default of 25 milliseconds is assumed" IS what it advertised.
    /// <see cref="DefaultMaxAckDelay"/> is therefore the advertised value rather than a
    /// stand-in for it, and a second number here would be the very duplication that type
    /// forbids. This client now DOES send 0x0B when a preset advertises it, and the bound did
    /// not become a parameter on this line: the ClientHello carrying it does not exist when
    /// this tracker is constructed, so <see cref="OnLocalAckParameters"/> supplies both it and
    /// the exponent once it does. This parameter is the seed for a profile that advertises
    /// neither.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The exponent is negative or above 20, the range limit is below 1, or the
    /// initial RTT is negative.
    /// </exception>
    internal TlsQuicAckTracker(
        int ackDelayExponent = DefaultAckDelayExponent,
        int maximumAckRanges = TlsQuicConnectionSpec.DefaultAckRangeLimit,
        TimeSpan? initialRtt = null,
        TlsQuicAckPolicy ackPolicy = TlsQuicAckPolicy.Immediate)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(ackDelayExponent);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            ackDelayExponent, MaximumAckDelayExponent, nameof(ackDelayExponent));

        // One, not zero. s19.3 Figure 25 makes First ACK Range a mandatory field,
        // so the smallest ACK frame that exists still names one range - a tracker
        // permitted to retain zero could only ever produce a frame
        // TlsQuicAckFrames.WriteAckFrame rejects.
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumAckRanges, 1, nameof(maximumAckRanges));

        // A caller's value, not a peer's, so this throws where OnPacketReceived's
        // rejections drop. A negative seed would put smoothed_rtt below zero and
        // make s6.2.1's PTO negative before a single sample existed.
        if (initialRtt is { } seed && seed < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(initialRtt), seed, "The initial RTT cannot be negative.");
        }

        _ackDelayExponent = ackDelayExponent;
        _maximumAckRanges = maximumAckRanges;

        // NO GUARD ABOVE THIS LINE, DELIBERATELY. See the field's own remarks: an
        // undeclared value degrades to the shipped behaviour instead of throwing, and the
        // rejecting seam is TlsQuicRecoverySpec.AckPolicy's init.
        _ackPolicy = ackPolicy;

        // A.4: "smoothed_rtt = kInitialRtt" and "rttvar = kInitialRtt / 2".
        // min_rtt and latest_rtt stay at A.4's zero, and first_rtt_sample at its
        // null, which is what makes the FIRST sample take A.7's initialising
        // branch rather than smoothing against a value no measurement produced.
        //
        // NOT KEPT AS A FIELD. The seed's only reader is the estimator it seeds,
        // and A.7's first sample overwrites both values outright, so a retained
        // copy would be a number that goes stale the first time it matters.
        var seedRtt = initialRtt ?? TlsQuicRecoverySpec.KInitialRtt;
        _smoothedRtt = seedRtt;
        _rttVariation = new TimeSpan(seedRtt.Ticks / 2);
    }

    /// <summary>
    /// Records one packet that has been fully processed, per RFC 9000 s13.1: "A
    /// packet MUST NOT be acknowledged until packet protection has been
    /// successfully removed and all frames contained in the packet have been
    /// processed." CALL THIS AFTER PROCESSING, NOT ON RECEIPT - the name says
    /// received because that is the timestamp s13.2.5 wants, but the ordering
    /// obligation is the caller's.
    /// </summary>
    /// <param name="level">The encryption level the packet was protected at, mapped
    /// onto one of RFC 9000 s12.3's three packet number spaces.</param>
    /// <param name="packetNumber">The full, reconstructed packet number - not the
    /// truncated wire form.</param>
    /// <param name="frames">
    /// Every frame the packet carried, used only to ask whether the packet is
    /// ack-eliciting. Not retained - these alias the receive buffer (see
    /// TlsQuicPacketReceiver.Receive) and this call does not outlive the pass.
    /// </param>
    /// <param name="receivedAt">When the packet arrived, for s13.2.5's delay
    /// measurement. Kept only if this is the largest packet number so far.</param>
    /// <remarks>
    /// THROWS FOR NOTHING A PEER CAN SEND. Every rejection this method makes -
    /// a packet number above s12.3's ceiling, a packet number below the floor
    /// <see cref="Prune"/> raised - is a silent drop, because a peer picks both
    /// values and a throw on the receive path is a one-datagram remote kill for
    /// the connection loop that calls this. The two <c>ArgumentOutOfRangeException</c>
    /// and <c>ArgumentNullException</c> paths that remain are on
    /// <paramref name="frames"/> and <paramref name="level"/>, which a caller
    /// supplies and a peer does not.
    /// </remarks>
    internal void OnPacketReceived(
        TlsQuicEncryptionLevel level,
        ulong packetNumber,
        IReadOnlyList<TlsQuicFrame> frames,
        DateTimeOffset receivedAt)
    {
        ArgumentNullException.ThrowIfNull(frames);

        // s12.3: "The packet number is an integer in the range 0 to 2^62-1."
        //
        // EFFECTIVELY UNREACHABLE, NOT REACHABLE - the earlier label overstated
        // it and the throw it justified is now a drop. The number comes from
        // TlsQuicPacketNumber.Decode, whose plain return path carries no 2^62
        // ceiling of its own, which is what "reachable" was reasoning from; but
        // Decode reconstructs AROUND the largest received so far, so producing a
        // value this large needs a largest-received already up near 2^62, and no
        // sequence of packets a peer can send walks it there. The check stays,
        // because "effectively" is not "provably" and this is the one place that
        // can still see the value: TlsQuicAckFrames.ValidateRanges would raise it
        // at SEND time instead, in the middle of building an unrelated frame.
        //
        // DROPPED RATHER THAN THROWN, which is the half that matters. A peer
        // picks this number, and a throw on the receive path is a one-datagram
        // remote kill for task 9a-ii's loop - the hazard s17.3.1 names for the
        // reserved bits, "Discarding such a packet after only removing header
        // protection can expose the endpoint to attacks." Silently dropping is
        // also the only self-consistent answer: a number this class cannot name
        // in an ACK frame is a number it cannot acknowledge, which is exactly
        // what the below-floor case below already does with the same shape.
        if (packetNumber > QuicVariableLengthInteger.MaximumValue)
        {
            return;
        }

        var space = SpaceOf(level);

        // Below the floor Prune raised: s13.2.3's "A receiver MUST retain an ACK
        // Range unless it can ensure that it will not subsequently accept packets
        // with numbers in that range." Re-admitting a number from a discarded range
        // is exactly the state that sentence forbids, so it is dropped - s13.2.3
        // prices this: "at the cost of increased retransmissions from the sender."
        //
        // Strictly below, so the floor itself is still accepted. The floor is set
        // to the smallest packet number STILL RETAINED, which is a number we do
        // acknowledge.
        if (packetNumber < _minimumPacketNumber[space])
        {
            return;
        }

        var ranges = _ranges[space];

        // s13.2.5's clock, and the comparison that keeps it on the largest packet
        // number rather than the latest arrival. Strictly greater, so a duplicate
        // of the current largest does not restart it either.
        if (ranges.Count == 0 || packetNumber > ranges[0].Largest)
        {
            _largestReceivedAt[space] = receivedAt;
        }

        Insert(ranges, packetNumber);

        // s13.2.3's bound, ENFORCED HERE AND NOWHERE ELSE. It used to run in
        // TryBuildAck, and the sentence it implements has two verbs: "A receiver
        // limits the number of ACK Ranges (Section 19.3.1) it REMEMBERS AND
        // SENDS in ACK frames, both to limit the size of ACK frames and to avoid
        // RESOURCE EXHAUSTION." Bounding only at send time satisfies the second
        // verb and not the first, and the gap is not theoretical: TryBuildAck
        // returns before pruning whenever nothing ack-eliciting is outstanding,
        // so a stream of PADDING-only packets on scattered numbers - all of them
        // recorded, none of them ever building an ACK - grew this list without
        // any limit at all. Twenty thousand such packets held twenty thousand
        // ranges, and the first forced build then pruned to the limit, which is
        // the shape of a bound that exists only where nobody is attacking it.
        //
        // It also makes Insert's cost claim true rather than aspirational: the
        // list is now at most _maximumAckRanges + 1 entries when Insert scans it,
        // so the descending-arrival walk that used to be quadratic in the number
        // of packets received is linear in a constant.
        //
        // WHAT MOVED WITH IT IS THE FLOOR. _minimumPacketNumber now ratchets on
        // ARRIVAL rather than on send, so a packet below a range this method just
        // discarded is refused immediately instead of at the next build. That is
        // a real behaviour change and it costs acknowledgements: holding (5,5)
        // and (3,3) at a limit of 2, packet 1 is now recorded, pruned, and the
        // floor put at 3, so a later packet 2 is refused where it once merged.
        // s13.2.3 prices exactly that trade - "A receiver can discard
        // unacknowledged ACK Ranges to limit ACK frame size, at the cost of
        // increased retransmissions from the sender" - and the MUST above it is
        // untouched, because the floor is still set from the smallest number
        // STILL RETAINED: "A receiver MUST retain an ACK Range unless it can
        // ensure that it will not subsequently accept packets with numbers in
        // that range." An unreceived packet still cannot be acknowledged; the
        // set of received packets that CAN be is smaller, sooner.
        //
        // Packet number 0 is unaffected, which is the zero-versus-absent case
        // worth stating: the floor starts at 0, Prune only ever raises it to a
        // number that is still retained, and the check below it is strict - so an
        // untouched space accepts packet 0 exactly as before.
        Prune(space);

        // s12.4 Table 3's N marking, via the one transcription of it this codebase
        // has. NOT a second table: TlsQuicFrameLegality transcribes Table 3's
        // "Pkts" column and says in its own header that the "Spec" column is out of
        // scope there, so ack-eliciting is NOT derivable from it - but
        // TlsQuicPacketBuilder already transcribes the N rows for the send side,
        // with a mutation record covering all four of them including the PING row
        // that is easiest to get wrong. Reused rather than copied, because that
        // file's comment promises "the rows are named above and nowhere else" and a
        // second copy here would quietly falsify it.
        //
        // OR-ed, never assigned: s13.2 makes the flag a debt, and a later
        // non-ack-eliciting packet does not discharge a debt an earlier
        // ack-eliciting one created. Assignment would let an ACK-only packet
        // arriving second cancel the obligation the first packet imposed.
        // STILL AN OR AND NOT AN ASSIGNMENT - the paragraph above is untouched by knob 12.
        // What the `if` adds is the INSTANT the debt was incurred, which only the
        // false-to-true edge can supply: a second ack-eliciting packet arriving while a
        // debt is already outstanding does not restart s13.2.1's clock, because the
        // promise it bounds belongs to the FIRST packet, which is already waiting.
        if (TlsQuicPacketBuilder.IsAckEliciting(frames) && !_ackElicitingPending[space])
        {
            _ackElicitingPending[space] = true;
            _ackElicitingPendingSince[space] = receivedAt;
        }
    }

    /// <summary>
    /// Builds the ACK frame arguments owed for one space, or reports that none is
    /// owed. False means no ACK-ELICITING packet is outstanding - which is not the
    /// same as no packet, and RFC 9000 s13.2 draws that line: "Packets that are not
    /// ack-eliciting are only acknowledged when an ACK frame is sent for other
    /// reasons." A caller sending a packet for another reason should acknowledge
    /// what it has anyway - s13.2: "When sending a packet for any reason, an
    /// endpoint SHOULD attempt to include an ACK frame if one has not been sent
    /// recently" - and reaches it through the <c>force</c> overload rather than by
    /// reading the ranges directly.
    /// </summary>
    /// <param name="level">The space to acknowledge in. s13.2.6: "ACK frames MUST only
    /// be carried in a packet that has the same packet number space as the packet being
    /// acknowledged."</param>
    /// <param name="now">When the ACK is about to be sent, for s13.2.5's delay.</param>
    /// <param name="ackDelay">The ACK Delay field, already scaled by this endpoint's
    /// ack_delay_exponent and ready for TlsQuicAckFrames.WriteAckFrame.</param>
    /// <param name="ranges">The acknowledged ranges, descending, largest first.</param>
    /// <remarks>
    /// CONSUMES the pending state on success: s13.2.1 - "Since packets containing
    /// only ACK frames are not congestion controlled, an endpoint MUST NOT send
    /// more than one such packet in response to receiving an ack-eliciting packet."
    /// One build, one ACK. A caller that builds an ACK and then fails to send it
    /// has a bug this class cannot see; the alternative - a separate OnAckSent -
    /// splits one obligation across two calls a caller can forget to pair.
    /// <para>The ranges are DESCENDING and ready for
    /// TlsQuicAckFrames.WriteAckFrame, which turns them into s19.3.1's relative
    /// Gap / ACK Range Length chain. That arithmetic is A2's and is not repeated
    /// here.</para>
    /// </remarks>
    internal bool TryBuildAck(
        TlsQuicEncryptionLevel level,
        DateTimeOffset now,
        out ulong ackDelay,
        out TlsQuicAckRange[] ranges) =>
        TryBuildAck(level, now, force: false, out ackDelay, out ranges);

    /// <inheritdoc cref="TryBuildAck(TlsQuicEncryptionLevel, DateTimeOffset, out ulong, out TlsQuicAckRange[])"/>
    /// <param name="level"><inheritdoc cref="TryBuildAck(TlsQuicEncryptionLevel, DateTimeOffset, out ulong, out TlsQuicAckRange[])" path="/param[@name='level']"/></param>
    /// <param name="now"><inheritdoc cref="TryBuildAck(TlsQuicEncryptionLevel, DateTimeOffset, out ulong, out TlsQuicAckRange[])" path="/param[@name='now']"/></param>
    /// <param name="ackDelay"><inheritdoc cref="TryBuildAck(TlsQuicEncryptionLevel, DateTimeOffset, out ulong, out TlsQuicAckRange[])" path="/param[@name='ackDelay']"/></param>
    /// <param name="ranges"><inheritdoc cref="TryBuildAck(TlsQuicEncryptionLevel, DateTimeOffset, out ulong, out TlsQuicAckRange[])" path="/param[@name='ranges']"/></param>
    /// <param name="force">
    /// Build an ACK for whatever ranges exist even with nothing ack-eliciting
    /// outstanding - RFC 9000 s13.2's "When sending a packet for any reason, an
    /// endpoint SHOULD attempt to include an ACK frame if one has not been sent
    /// recently. Doing so helps with timely loss detection at the peer."
    ///
    /// STILL FALSE FOR AN EMPTY SPACE, and that is the whole reason this is a
    /// parameter rather than the caller reading a range list: s13.2.1 forbids
    /// synthesising an ACK out of nothing - "An endpoint MUST NOT send a
    /// non-ack-eliciting packet in response to a non-ack-eliciting packet, even if
    /// there are packet gaps that precede the received packet. This avoids an
    /// infinite feedback loop of acknowledgments" - and s19.3's mandatory First ACK
    /// Range field means an ACK naming no packets has no encoding at all.
    /// </param>
    internal bool TryBuildAck(
        TlsQuicEncryptionLevel level,
        DateTimeOffset now,
        bool force,
        out ulong ackDelay,
        out TlsQuicAckRange[] ranges)
    {
        var space = SpaceOf(level);
        ackDelay = 0;
        ranges = [];

        if (_ranges[space].Count == 0 || (!force && !_ackElicitingPending[space]))
        {
            return false;
        }

        // KNOB 12, AND IT SITS BELOW THE LINE ABOVE RATHER THAN INSIDE IT. There has to be
        // a debt before there is anything to hold back, so the two conditions are not
        // interchangeable: folded into the disjunction above, a space with ranges and no
        // debt would take the withheld path and the distinction s13.2 draws between "no
        // ACK is owed" and "an ACK is owed but not yet due" would be lost.
        //
        // `force` BYPASSES IT, WHICH IS NOT A HOLE. The force overload is s13.2's "When
        // sending a packet for any reason, an endpoint SHOULD attempt to include an ACK
        // frame if one has not been sent recently" - a caller that is already sending, so
        // the ACK costs no packet. Acknowledging EARLY can never break a promise not to
        // acknowledge LATE: s13.2.1's contract is "an endpoint promises to never
        // intentionally delay acknowledgments of an ack-eliciting packet by more than the
        // indicated value", which bounds the delay from above and not from below.
        if (!force && IsWithheldAt(space, now))
        {
            return false;
        }

        // NO Prune HERE. It runs on every arrival instead - see OnPacketReceived
        // for why, and for what moved with it. Pruning in both places would be
        // dead work: the receive path leaves the list at or under the limit after
        // every insert, so there is never anything here to drop.

        // s13.2.5: the delay between the largest packet number's arrival and this
        // ACK's departure, in microseconds, then scaled by our own exponent.
        //
        // Clamped at zero rather than trusted: `now` is a caller's parameter and
        // TimeProvider gives no guarantee it never goes backwards across a
        // machine's clock adjustment, and a negative TimeSpan would wrap into an
        // enormous positive ulong here - a delay of several thousand years, which
        // s13.2.5's reader would fold straight into its RTT estimate.
        var elapsed = now - _largestReceivedAt[space];
        var microseconds = elapsed > TimeSpan.Zero ? (ulong)(elapsed.Ticks / TicksPerMicrosecond) : 0;

        // s19.3, ACK Delay: "It is decoded by multiplying the value in the field by
        // 2 to the power of the ack_delay_exponent transport parameter sent by the
        // sender of the ACK frame". The encode direction is therefore a right
        // shift, and it TRUNCATES - s19.3 names the trade: "this encoding allows
        // for a larger range of values within the same number of bytes, at the cost
        // of lower resolution." Rounding up instead would report a delay longer
        // than the one taken, which s13.2.5 forbids by implication ("An endpoint
        // MUST NOT include delays that it does not control").
        ackDelay = microseconds >> _ackDelayExponent;

        // NO VARINT BOUND ON ackDelay, AND THAT IS DERIVED RATHER THAN ASSUMED.
        // An earlier revision capped it at QuicVariableLengthInteger.MaximumValue
        // "in case a `now` far in the future overflowed the field" - a mutation
        // sweep deleted the cap and nothing failed, which sent the arithmetic
        // back through:
        //
        //   DateTimeOffset spans at most DateTimeOffset.MaxValue - MinValue,
        //   which is 3652058 days. That is 3652058 * 86400 * 10^6 microseconds,
        //   about 3.155e17.
        //   s16 leaves a varint 62 value bits, so the field holds 2^62-1, about
        //   4.612e18.
        //
        // The widest delay the type can express is therefore about fourteen times
        // SMALLER than the narrowest value the field cannot hold, and that is at
        // exponent 0 - the worst case, since the shift above only ever divides.
        // The cap was unreachable by construction, so no test is written for it:
        // one would have to construct a state that cannot exist, and would pass
        // against the mutant that removed the cap. It is deleted instead of kept
        // and commented, because dead validation reads like an invariant is
        // enforced here when it is really enforced by the range of the type.
        ranges = [.. _ranges[space]];
        _ackElicitingPending[space] = false;
        return true;
    }

    /// <summary>
    /// When RFC 9000 s13.2.1's promise falls due - the instant an acknowledgement this
    /// tracker is holding back MUST be available - or <see langword="null"/> when nothing
    /// is being held back.
    /// </summary>
    /// <remarks>
    /// <para>WITHOUT THIS THE POLICY WOULD BE A VIOLATION WEARING THE NAME OF THE RULE IT
    /// BREAKS. Holding an acknowledgement back is only legal because something guarantees
    /// it goes out by the bound; a tracker that withheld an ACK and waited for the peer's
    /// next datagram to flush it would exceed max_ack_delay by however long the peer
    /// stayed quiet, which is precisely the excess s13.2.1 prices - "any excess accrues to
    /// the RTT estimate and could result in spurious or delayed retransmissions from the
    /// peer". <c>TlsQuicConnection.EarliestDeadline</c> races this against its other four,
    /// so the wake exists whether or not a datagram arrives.</para>
    /// <para>APPLICATION SPACE ONLY, WHICH IS THE SAME SENTENCE <see cref="IsWithheldAt"/>
    /// READS. Nothing is ever withheld at Initial or Handshake, so a deadline for either
    /// would arm a wake for an acknowledgement that already left.</para>
    /// <para>THE RANGE COUNT IS TESTED AS WELL AS THE DEBT, pairing this with
    /// <see cref="TryBuildAck(TlsQuicEncryptionLevel, DateTimeOffset, bool, out ulong, out TlsQuicAckRange[])"/>'s
    /// first guard. The two cannot disagree today - a range is inserted before the debt is
    /// recorded, and Prune never empties a space it kept - but a deadline that fired for a
    /// build that then returned false would leave the debt standing with its instant
    /// already past, and the pump would re-arm on the same past instant every pass. That
    /// spin is bounded by the idle timeout rather than endless, and it is closed here
    /// rather than left to that bound.</para>
    /// </remarks>
    internal DateTimeOffset? DelayedAckDeadline =>
        _ackPolicy == TlsQuicAckPolicy.DelayedToMaxAckDelay
            && _ackElicitingPending[ApplicationSpace]
            && _ranges[ApplicationSpace].Count > 0
            ? _ackElicitingPendingSince[ApplicationSpace] + _localMaxAckDelay
            : null;

    // RFC 9000 s13.2.1, and the two halves of one sentence read in one place: "An endpoint
    // MUST acknowledge all ack-eliciting Initial and Handshake packets IMMEDIATELY and all
    // ack-eliciting 0-RTT and 1-RTT packets WITHIN ITS ADVERTISED max_ack_delay, with the
    // following exception." The emphasis is added; the split is the RFC's.
    //
    // SO THE KNOB CANNOT REACH TWO OF THE THREE SPACES, AND THAT IS A RULE RATHER THAN A
    // CONSERVATISM. max_ack_delay is not a bound that happens to be zero for Initial and
    // Handshake - it does not apply to them at all, and an endpoint that delayed a
    // Handshake ACK would be violating a MUST no setting of this knob is entitled to
    // waive. 0-RTT and 1-RTT share s12.3's application data space, which is why one
    // comparison covers both.
    //
    // STRICTLY LESS THAN, so an ACK becomes available AT the bound and not one tick after
    // it. "within the maximum delay" includes the maximum: a build at exactly
    // pendingSince + max_ack_delay has delayed by max_ack_delay, which is the largest
    // delay the promise permits, not the smallest it forbids.
    //
    // NOT IMPLEMENTED HERE, AND NAMED SO THAT ITS ABSENCE IS A CHOICE: s13.2.1's two
    // SHOULDs about releasing an ACK without delay on a reordering or a gap, s13.2.2's
    // SHOULD about acknowledging after every second ack-eliciting packet, and the SHOULD
    // about ECN CE. All three would make a delayed ACK leave EARLIER than this, so none of
    // them can turn a conforming policy into a violating one, and s13.2.1 itself labels
    // the group as guidance - "The algorithms in [QUIC-RECOVERY] are expected to be
    // resilient to receivers that do not follow the guidance offered above." They are
    // worth having and they are a second behaviour, not a second correctness argument.
    //
    // AND ONE MORE, WHICH IS A KNOWN CEILING RATHER THAN AN OMISSION. s13.2 says "When
    // sending a packet for any reason, an endpoint SHOULD attempt to include an ACK frame
    // if one has not been sent recently", and this client's 1-RTT send path reaches
    // TryBuildAck through the NON-force overload - see TlsQuicApplicationSendPath - so
    // under DelayedToMaxAckDelay a held ACK is NOT picked up by a data packet that happens
    // to leave inside the bound. Two reasons it stays that way. First, "recently" is
    // undefined and the hold is at most 25 ms, so the SHOULD is arguably satisfied.
    // Second, and decisively, routing that call through `force` would change the SHIPPED
    // DEFAULT's emitted bytes: the force overload builds an ACK with no ack-eliciting debt
    // outstanding, so an Immediate client would start emitting ACK frames it does not emit
    // today. Default parity outranks a SHOULD whose bound is already met.
    private bool IsWithheldAt(int space, DateTimeOffset now) =>
        _ackPolicy == TlsQuicAckPolicy.DelayedToMaxAckDelay
        && space == ApplicationSpace
        && now - _ackElicitingPendingSince[space] < _localMaxAckDelay;

    /// <summary>
    /// The largest packet number any ACK frame received in this space has
    /// acknowledged, or null if none has. Task 4b's packet-number encoding reads
    /// this; RFC 9000 s17.1 makes it the input that decides how few bytes a
    /// truncated packet number can safely use.
    /// </summary>
    internal ulong? LargestAcked(TlsQuicEncryptionLevel level) => _largestAcked[SpaceOf(level)];

    /// <summary>When the ACK frame that set <see cref="LargestAcked"/> arrived.
    /// A3's RTT sample is this minus the send time of that packet.</summary>
    internal DateTimeOffset LargestAckedAt(TlsQuicEncryptionLevel level) =>
        _largestAckedAt[SpaceOf(level)];

    /// <summary>RFC 9002 s5.1's <c>latest_rtt</c>: the most recent sample, as
    /// measured, with no acknowledgement delay removed. <see cref="TimeSpan.Zero"/>
    /// until the first sample, per A.4's <c>latest_rtt = 0</c>.</summary>
    internal TimeSpan LatestRtt => _latestRtt;

    /// <summary>RFC 9002 s5.2's <c>min_rtt</c>. <see cref="TimeSpan.Zero"/> until the
    /// first sample, per A.4's <c>min_rtt = 0</c>. s5.2: "An endpoint uses only
    /// locally observed times in computing the min_rtt and does not adjust for
    /// acknowledgment delays reported by the peer", which is why this can only ever
    /// be a raw <see cref="LatestRtt"/> and never an adjusted one.</summary>
    internal TimeSpan MinimumRtt => _minimumRtt;

    /// <summary>RFC 9002 s5.3's <c>smoothed_rtt</c>. Seeded from the initial RTT
    /// before any sample exists - see the constructor's <c>initialRtt</c> - and
    /// RESET rather than smoothed by the first one.</summary>
    internal TimeSpan SmoothedRtt => _smoothedRtt;

    /// <summary>RFC 9002 s5.3's <c>rttvar</c>, the mean variation. Named in full
    /// because "var" in C# is a keyword-shaped noise word and the RFC's own prose
    /// calls it "variation in the rest of this document".</summary>
    internal TimeSpan RttVariation => _rttVariation;

    /// <summary>RFC 9002 A.3's <c>first_rtt_sample</c>: "The time that the first RTT
    /// sample was obtained", or null if none has been. Null is A.7's
    /// <c>first_rtt_sample == 0</c> test, and s7.6's persistent congestion will read
    /// the time.</summary>
    internal DateTimeOffset? FirstRttSampleAt => _firstRttSampleAt;

    /// <summary>
    /// Adopts THIS endpoint's advertised <c>ack_delay_exponent</c> (0x0a) and
    /// <c>max_ack_delay</c> (0x0b), once the ClientHello carrying them exists.
    /// </summary>
    /// <remarks>
    /// <para>THE ADVERTISEMENT IS THE SOURCE, NOT A SECOND KNOB TO KEEP IN STEP. This used to
    /// be a comparison: the connection read the advertised exponent, compared it with
    /// <c>TlsQuicConnectionOptions.AckDelayExponent</c>, and threw
    /// <see cref="InvalidOperationException"/> when they disagreed - naming a property on an
    /// `internal sealed` type that no preset and no public API could set. So the only way to
    /// advertise a non-default 0x0a was to hit an error that could not be acted on. Adopting
    /// the advertised value instead makes the two agree by construction, which is the same
    /// rule the six flow-control parameters already follow.</para>
    /// <para>ONE-WAY AND IDEMPOTENT, like <see cref="OnHandshakeConfirmed"/>. The ClientHello
    /// is fixed for the life of the connection, so the values it carries cannot change.</para>
    /// </remarks>
    /// <param name="ackDelayExponent">This endpoint's advertised exponent. Clamped to 0..20,
    /// which is s18.2's "values above 20 are invalid" applied to our own number rather than
    /// only to the peer's.</param>
    /// <param name="maxAckDelay">This endpoint's advertised max_ack_delay. Clamped to
    /// zero..<see cref="MaximumMaxAckDelay"/>.</param>
    internal void OnLocalAckParameters(int ackDelayExponent, TimeSpan maxAckDelay)
    {
        _ackDelayExponent = Math.Clamp(ackDelayExponent, 0, MaximumAckDelayExponent);
        _localMaxAckDelay =
            maxAckDelay < TimeSpan.Zero ? TimeSpan.Zero
            : maxAckDelay > MaximumMaxAckDelay ? MaximumMaxAckDelay
            : maxAckDelay;
    }

    /// <summary>
    /// Takes the two acknowledgement-related transport parameters the PEER sent, per
    /// RFC 9000 s18.2. Until this is called the s18.2 absent-value defaults apply,
    /// which is correct rather than merely safe: they are what s18.2 says an endpoint
    /// assumes, and for <c>max_ack_delay</c> against a Chromium-shaped peer they are
    /// what applies for the whole connection.
    /// </summary>
    /// <remarks>
    /// <para>THIS IS THE SEAM AND NOT THE WIRING. Nothing calls this yet. The peer's
    /// parameters arrive on <c>TlsQuicPeerTransportParametersEvent</c>, which
    /// <c>TlsQuicConnection.ApplyPeerTransportParametersAsync</c> handles - it retains
    /// <c>max_idle_timeout</c> and, since task 14d, the six flow-control limits, and
    /// it retains NEITHER of these two. That was checked rather than assumed, and the
    /// A3 plan predicted it. Adding the two lines there is a change to
    /// <c>TlsQuicConnection.cs</c>, which this task does not own; A3-5 or A3-7 does.
    /// The seam is here so that when they do, the s18.2 defaults and bounds are in one
    /// place rather than restated at the call site.</para>
    /// <para>CLAMPS, DOES NOT THROW. Both values are the peer's, and s7.4 makes an
    /// out-of-range one a TRANSPORT_PARAMETER_ERROR - which
    /// <c>TlsQuicTransportParameters.ValidatePeer</c> already raises, before this event
    /// is ever built, for both of these identifiers. So a value out of range here means
    /// a caller bypassed that parser, and throwing would convert a caller's bug into a
    /// connection kill on the peer's numbers. The exponent clamp is load-bearing rather
    /// than decorative: <c>ackDelay &lt;&lt; exponent</c> with an exponent of 64 or more
    /// is <c>exponent &amp; 63</c> in C#, so an unclamped 64 would decode every ACK Delay
    /// as itself and be silently, exactly wrong.</para>
    /// </remarks>
    /// <param name="ackDelayExponent">The peer's <c>ack_delay_exponent</c>, s18.2
    /// (0x0a). Clamped to 0..20.</param>
    /// <param name="maxAckDelay">The peer's <c>max_ack_delay</c>, s18.2 (0x0b).
    /// Clamped to zero..<see cref="MaximumMaxAckDelay"/>.</param>
    internal void OnPeerAckParameters(int ackDelayExponent, TimeSpan maxAckDelay)
    {
        _peerAckDelayExponent = Math.Clamp(ackDelayExponent, 0, MaximumAckDelayExponent);
        _peerMaxAckDelay =
            maxAckDelay < TimeSpan.Zero ? TimeSpan.Zero
            : maxAckDelay > MaximumMaxAckDelay ? MaximumMaxAckDelay
            : maxAckDelay;
    }

    /// <summary>
    /// RFC 9002 s5.3's condition: "the endpoint SHOULD ignore max_ack_delay until the
    /// handshake is confirmed, as defined in Section 4.1.2 of [QUIC-TLS]". Call this
    /// once, when it is. Idempotent, and one-way - nothing unconfirms a handshake.
    /// </summary>
    /// <remarks>A SEPARATE CALL RATHER THAN A PER-ACK PARAMETER, because it is a
    /// property of the connection at a moment and not of the frame: threading it
    /// through every ProcessAckFrame call would let two call sites disagree about the
    /// same instant. Like <see cref="OnPeerAckParameters"/> this is a seam A3-5 or
    /// A3-7 wires; until it is called the estimator takes s5.3's pre-confirmation
    /// arm, which is the conservative one - it does not cap the peer's reported delay,
    /// so it never removes more from a sample than the peer claimed.</remarks>
    internal void OnHandshakeConfirmed() => _handshakeConfirmed = true;

    /// <summary>
    /// Takes in an ACK frame this endpoint received. In A4-minimal this validates
    /// the frame's range chain and advances <see cref="LargestAcked"/>, and does
    /// nothing else.
    /// </summary>
    /// <remarks>
    /// <para>A3'S INSERTION POINT, AND TASK A3-4 HAS TAKEN IT. The two things this
    /// paragraph used to list as absent are now one done and one still deferred, so
    /// that a reader does not mistake either for the other:</para>
    /// <para>RTT SAMPLING - DONE, on the overload that takes a sent-packet list.
    /// s13.2.5's ACK Delay field is decoded with the PEER'S ack_delay_exponent -
    /// "the ack_delay_exponent transport parameter sent by the sender of the ACK
    /// frame", and here the peer is that sender, which is the mirror of the value
    /// <see cref="TlsQuicAckTracker(int, int, TimeSpan?, TlsQuicAckPolicy)"/> takes. The paragraph's
    /// old last sentence - "a sample also needs the send time of the acknowledged
    /// packet, which lives in the sent-packet list A3 owns" - is exactly why the
    /// list is a parameter: task A3-3 built it, and this method reads it without
    /// owning it. RFC 9002 s5 and A.7 are implemented in
    /// <see cref="UpdateRtt"/>; the results are <see cref="LatestRtt"/>,
    /// <see cref="MinimumRtt"/>, <see cref="SmoothedRtt"/> and
    /// <see cref="RttVariation"/>. The FOUR-argument overload samples nothing, so
    /// every existing caller behaves exactly as before.</para>
    /// <para>LOSS DETECTION - STILL DEFERRED, to A3-6, and s13.1's
    /// PROTOCOL_VIOLATION with it: "An endpoint SHOULD treat receipt of an
    /// acknowledgment for a packet it did not send as a connection error of type
    /// PROTOCOL_VIOLATION, if it is able to detect the condition." The trailing
    /// clause still governs, and now for a sharper reason than "this class does not
    /// have the set" - it has a bounded, lossy view of it, which is worse than none
    /// for this particular question. See <see cref="TryFindLargestNewlyAcked"/> for
    /// the argument in full and for why an unaccountable packet number yields no
    /// sample and no error. What IS checked is that the chain is internally
    /// well-formed, via TlsQuicAckFrames.TryGetRanges - s19.3.1's "If any computed
    /// packet number is negative, an endpoint MUST generate a connection error of
    /// type FRAME_ENCODING_ERROR".</para>
    /// </remarks>
    /// <param name="level">
    /// The encryption level of the packet the ACK ARRIVED IN, which s13.2.6 makes
    /// the space it refers to: "ACK frames MUST only be carried in a packet that
    /// has the same packet number space as the packet being acknowledged."
    ///
    /// NOT OPTIONAL, AND NOT IN THE SIGNATURE THE TASK TEXT ASKED FOR. That
    /// signature was ProcessAckFrame(in TlsQuicFrame, DateTimeOffset) with no
    /// space. Largest-acked is per space - the same s12.3 split that gives
    /// TlsQuicPacketReceiver three largest-received counters - so a single
    /// space-less counter would let a Handshake ACK raise the figure task 4b uses
    /// to encode Initial packet numbers, and a too-large largest-acked makes the
    /// encoder pick FEWER bytes than the peer needs to decode.
    /// </param>
    /// <param name="frame">The ACK frame, as TlsQuicFrames.TryReadFrame produced it.
    /// Its range chain is walked here and must be well-formed.</param>
    /// <param name="receivedAt">When the packet carrying this ACK arrived. Retained as
    /// <see cref="LargestAckedAt"/> when the frame advances largest-acked; A3's RTT
    /// sample is the far end of that subtraction.</param>
    /// <param name="error">The s19.3.1 / s12.4 transport error to close the connection
    /// with when this returns false; <c>NoError</c> otherwise.</param>
    /// <returns>False, with <paramref name="error"/> set, if the frame is not an
    /// ACK or its range chain is malformed. State is unchanged on false.</returns>
    internal bool ProcessAckFrame(
        TlsQuicEncryptionLevel level,
        in TlsQuicFrame frame,
        DateTimeOffset receivedAt,
        out TlsQuicTransportError error) =>
        ProcessAckFrame(level, frame, receivedAt, sentPackets: null, out error);

    /// <inheritdoc cref="ProcessAckFrame(TlsQuicEncryptionLevel, in TlsQuicFrame, DateTimeOffset, out TlsQuicTransportError)"/>
    /// <param name="level"><inheritdoc cref="ProcessAckFrame(TlsQuicEncryptionLevel, in TlsQuicFrame, DateTimeOffset, out TlsQuicTransportError)" path="/param[@name='level']"/></param>
    /// <param name="frame"><inheritdoc cref="ProcessAckFrame(TlsQuicEncryptionLevel, in TlsQuicFrame, DateTimeOffset, out TlsQuicTransportError)" path="/param[@name='frame']"/></param>
    /// <param name="receivedAt"><inheritdoc cref="ProcessAckFrame(TlsQuicEncryptionLevel, in TlsQuicFrame, DateTimeOffset, out TlsQuicTransportError)" path="/param[@name='receivedAt']"/></param>
    /// <param name="error"><inheritdoc cref="ProcessAckFrame(TlsQuicEncryptionLevel, in TlsQuicFrame, DateTimeOffset, out TlsQuicTransportError)" path="/param[@name='error']"/></param>
    /// <param name="sentPackets">
    /// The packets still retained for THIS space, as task A3-3 keeps them - or
    /// <see langword="null"/> to validate the frame and advance
    /// <see cref="LargestAcked"/> without sampling the RTT, which is the four-argument
    /// overload's behaviour and what A4-minimal did.
    ///
    /// <para>Not retained, not mutated, and not required to be sorted. Removing the
    /// packets this ACK acknowledges is the CALLER'S - RFC 9002 A.7 splits the two
    /// deliberately, <c>DetectAndRemoveAckedPackets</c> then <c>UpdateRtt</c>, and the
    /// remover is the same object that maintains bytes_in_flight. What this class needs
    /// from the list is only s5.1's two questions: when the largest acknowledged packet
    /// was sent, and whether anything newly acknowledged was ack-eliciting.</para>
    /// </param>
    internal bool ProcessAckFrame(
        TlsQuicEncryptionLevel level,
        in TlsQuicFrame frame,
        DateTimeOffset receivedAt,
        IReadOnlyList<TlsQuicSentPacket>? sentPackets,
        out TlsQuicTransportError error)
    {
        // Reused, not reimplemented: TryGetRanges already walks s19.3.1's chain,
        // enforces the underflow rules both formulas need, and rolls back what it
        // added on rejection. It is also the read side's only bounds check, so
        // skipping it here would let a chain that decodes to negative packet
        // numbers set largest-acked.
        //
        // NULL WHEN THERE IS NOTHING TO MATCH THEM AGAINST, which is still most
        // callers. The original note here read: "It used to pass a fresh List
        // sized, one entry at a time, by however many Gap / ACK Range Length
        // pairs the peer chose to send: an allocation on the receive path whose
        // size is the attacker's to pick [...] When A3 does need the ranges it
        // passes a list here and nothing else changes." A3 needs them now, and
        // the promise held: the only change is WHICH list. It is the tracker's
        // own, cleared and reused, so the per-ACK allocation the note objected to
        // never comes back, and the validate-only path below is byte-for-byte the
        // path it was - null in, nothing allocated, nothing allocated on
        // rejection either.
        List<TlsQuicAckRange>? decoded = null;
        if (sentPackets is not null)
        {
            _decodedRanges.Clear();
            decoded = _decodedRanges;
        }

        if (!TlsQuicAckFrames.TryGetRanges(frame, decoded, out error))
        {
            return false;
        }

        var space = SpaceOf(level);
        var largest = frame.LargestAcknowledged;

        // s19.3: "QUIC acknowledgments are irrevocable. Once acknowledged, a packet
        // remains acknowledged, even if it does not appear in a future ACK frame."
        // So this only ever rises. A reordered ACK naming a lower Largest
        // Acknowledged is not new information and must not lower it - which would
        // be worse than useless to task 4b, whose encoded length shrinks as this
        // grows and would then encode too few bytes for the peer to decode.
        //
        // `is null ||` rather than a comparison against a zero default: packet
        // number 0 is acknowledgeable, so an ACK naming Largest Acknowledged 0 is
        // real news the first time and must set this.
        var isLargestNewlyAcknowledged = _largestAcked[space] is null || largest > _largestAcked[space];
        if (isLargestNewlyAcknowledged)
        {
            _largestAcked[space] = largest;
            _largestAckedAt[space] = receivedAt;
        }

        // s5.1's FIRST CONDITION, AND THE ONE THAT IS INVISIBLE ON A CLEAN PATH.
        // "An endpoint generates an RTT sample on receiving an ACK frame that meets
        // the following two conditions: * the largest acknowledged packet number is
        // newly acknowledged, and * at least one of the newly acknowledged packets
        // was ack-eliciting", reinforced by "To avoid generating multiple RTT
        // samples for a single packet, an ACK frame SHOULD NOT be used to update RTT
        // estimates if it does not newly acknowledge the largest acknowledged
        // packet."
        //
        // The reuse of isLargestNewlyAcknowledged is the whole implementation of the
        // first condition, and it is deliberately the SAME boolean that gates
        // largest-acked above rather than a second test of the same idea: they are
        // one question - is this ACK news about the largest - and two spellings of
        // it could drift apart. Mutation 34 already pins the `>` as strict.
        //
        // WHY THIS MATTERS MORE THAN IT LOOKS: nothing in this codebase
        // deduplicates a received packet number, so a duplicated datagram is opened
        // twice and the ACK inside it is processed twice. A second UpdateRtt from
        // the same acknowledgement would measure a real send time against a LATER
        // arrival time and feed the duplication interval into smoothed_rtt and
        // rttvar as though it were path delay. On a clean path no test can see the
        // difference, because there are no duplicates to see.
        if (isLargestNewlyAcknowledged &&
            sentPackets is not null &&
            TryFindLargestNewlyAcked(sentPackets, decoded!, largest, out var sentAt, out var ackEliciting) &&
            ackEliciting &&
            receivedAt >= sentAt)
        {
            // s5.1: "latest_rtt = ack_time - send_time_of_largest_acked", and
            // A.7's "latest_rtt = now() - newly_acked_packets.largest().time_sent".
            UpdateRtt(receivedAt - sentAt, frame.AckDelay, level, receivedAt);
        }

        return true;
    }

    // s5.1's two questions asked in one pass over the retained packets, plus the
    // guard that keeps the answer honest when the peer names a packet we cannot
    // account for.
    //
    // s13.1'S PROTOCOL_VIOLATION IS DELIBERATELY NOT RAISED, and this is the stated
    // decision rather than an omission. The sentence is conditional: "An endpoint
    // SHOULD treat receipt of an acknowledgment for a packet it did not send as a
    // connection error of type PROTOCOL_VIOLATION, IF IT IS ABLE TO DETECT THE
    // CONDITION." We are not able, and the reason is structural rather than
    // temporary: the list handed in is what is STILL RETAINED, so a packet number
    // absent from it is "never sent" OR "already acknowledged and removed" OR
    // "dropped by A3-3's retention bound". Those are three different facts with one
    // observation, and s19.3's "QUIC acknowledgments are irrevocable. Once
    // acknowledged, a packet remains acknowledged, even if it does not appear in a
    // future ACK frame" makes the middle one ordinary, legal peer behaviour - every
    // repeated ACK names packets we have already forgotten. Raising here would close
    // healthy connections on the commonest event there is, and the duplicating paths
    // the impairing transport can now produce would trip it on the first duplicate.
    // Detecting the real condition needs a high-water mark of what was ever sent,
    // which is the send side's to keep and not derivable from a pruned list.
    //
    // An unaccountable largest therefore yields no sample and no error: false out of
    // here, `true` out of ProcessAckFrame, and largest-acked still advanced, because
    // s17.1's encoder input is about what the PEER claims to have seen and is
    // correct to move on a claim we cannot corroborate.
    //
    // ponytail: the scan is ranges x retained-packets in the worst case, and it is
    // walked from the newest end because the largest acknowledged is very nearly
    // always the last packet sent - so the common case exits after one or two
    // iterations. Both lists are already bounded (the ranges by one datagram's
    // bytes, the retained packets by A3-3's cap); revisit only if that cap grows.
    private static bool TryFindLargestNewlyAcked(
        IReadOnlyList<TlsQuicSentPacket> sentPackets,
        List<TlsQuicAckRange> decoded,
        ulong largest,
        out DateTimeOffset sentAt,
        out bool includesAckEliciting)
    {
        sentAt = default;
        includesAckEliciting = false;
        var found = false;

        for (var index = sentPackets.Count - 1; index >= 0; index--)
        {
            var sent = sentPackets[index];
            if (!Covers(decoded, sent.PacketNumber))
            {
                continue;
            }

            if (sent.PacketNumber == largest)
            {
                sentAt = sent.SentAt;
                found = true;
            }

            // A.7's IncludesAckEliciting over newly_acked_packets, not over the
            // largest alone. s5.1 says "at least ONE of the newly acknowledged
            // packets", so an ACK whose largest is an ACK-only packet still yields a
            // sample when something else it newly acknowledges was ack-eliciting -
            // and the sample is still measured from the largest, because s5.1 also
            // says "An RTT sample is generated using only the largest acknowledged
            // packet in the received ACK frame."
            includesAckEliciting |= sent.IsAckEliciting;

            if (found && includesAckEliciting)
            {
                break;
            }
        }

        return found;
    }

    // Whether a descending, non-overlapping, non-adjacent range list holds one
    // packet number. The early return is not an optimisation but the correctness
    // of the walk: the list descends, so once a range's Largest has fallen below
    // the number, every range after it is lower still and the number sits in a gap.
    private static bool Covers(List<TlsQuicAckRange> ranges, ulong packetNumber)
    {
        for (var index = 0; index < ranges.Count; index++)
        {
            var range = ranges[index];
            if (packetNumber > range.Largest)
            {
                return false;
            }

            if (packetNumber >= range.Smallest)
            {
                return true;
            }
        }

        return false;
    }

    // RFC 9002 A.7's UpdateRtt, transcribed line for line, with three departures
    // that are arithmetic rather than behavioural and one that is neither. All four
    // are named here because a reader comparing this to the pseudocode must be able
    // to see which lines are the RFC's and which are C#'s.
    //
    //   A.7:  UpdateRtt(ack_delay):
    //           if (first_rtt_sample == 0):
    //             min_rtt = latest_rtt
    //             smoothed_rtt = latest_rtt
    //             rttvar = latest_rtt / 2
    //             first_rtt_sample = now()
    //             return
    //           min_rtt = min(min_rtt, latest_rtt)
    //           if (handshake confirmed):
    //             ack_delay = min(ack_delay, max_ack_delay)
    //           adjusted_rtt = latest_rtt
    //           if (latest_rtt >= min_rtt + ack_delay):
    //             adjusted_rtt = latest_rtt - ack_delay
    //           rttvar = 3/4 * rttvar + 1/4 * abs(smoothed_rtt - adjusted_rtt)
    //           smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
    //
    // DEPARTURE 1 - `latest_rtt >= min_rtt + ack_delay` IS TESTED AS
    // `latest_rtt - min_rtt >= ack_delay`. Algebraically the same over integers,
    // and it is the same manoeuvre Insert makes above for the same reason, in the
    // opposite direction: there an addition avoids an underflow, here a
    // subtraction avoids an overflow. ack_delay is the peer's, decoded from a
    // varint that can express 2^62-1 microseconds and then SHIFTED LEFT by an
    // exponent up to 20, so `min_rtt + ack_delay` as written would overflow
    // TimeSpan and throw on the receive path. The rewritten form cannot: min_rtt
    // was just set to at most latest_rtt on the line above, so the left side is a
    // non-negative TimeSpan no larger than latest_rtt.
    //
    // DEPARTURE 2 - THE TWO WEIGHTED AVERAGES ARE WRITTEN AS INCREMENTS.
    // `7/8 * s + 1/8 * a` is `s + (a - s)/8` exactly, and `3/4 * v + 1/4 * x` is
    // `v + (x - v)/4` exactly. Written the RFC's way, `7 * s.Ticks` overflows a
    // long for any s above about 1.3e18 ticks - fifteen centuries, but reachable
    // from a caller's clock, and the wrap is silent and negative. Written this way
    // both stay inside [0, TimeSpan.MaxValue] for every input in that interval:
    // the increment is at most an eighth of the distance to a bound already inside
    // it. Integer truncation makes the two forms differ by at most one tick.
    //
    // DEPARTURE 3 - TimeSpan, NOT A UNIT. Everything is ticks, so `/ 2`, `/ 4` and
    // `/ 8` are integer divisions of a tick count and there is no floating point
    // anywhere on this path - which is the failure A3-2's mutation round found in
    // its own knobs: a NaN compares false against every bound and passes every
    // guard written as a comparison.
    //
    // DEPARTURE 4 - THE ORDER OF THE LAST TWO LINES, AND IT IS NOT COSMETIC.
    // s5.3's PROSE and A.7's PSEUDOCODE DISAGREE, in the same document. s5.3:
    //
    //     smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
    //     rttvar_sample = abs(smoothed_rtt - adjusted_rtt)
    //     rttvar = 3/4 * rttvar + 1/4 * rttvar_sample
    //
    // - smoothed_rtt first, and the variation measured against the ALREADY UPDATED
    // value. A.7 computes rttvar first, against the smoothed_rtt from before this
    // sample. They are not two spellings of one rule; they give different numbers,
    // and by a fixed factor rather than a rounding: with s the old smoothed_rtt and
    // a the adjusted sample, s5.3's new smoothed_rtt is (7s + a)/8, so
    // |new_s - a| = 7/8 * |s - a|. s5.3's prose therefore feeds rttvar a variation
    // sample exactly 7/8 of A.7's, every time, and rttvar converges 12.5% low.
    // That is not a number that stays in the estimator: s6.2.1's PTO is
    // smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay, so a
    // systematically low rttvar arms probe timeouts early and spends the
    // connection's send budget on probes the path did not ask for.
    //
    // A.7 IS FOLLOWED, and the reason is not merely that A3-4's task text names it.
    // rttvar is a MEAN DEVIATION estimator - s5.3's own words, "the mean deviation
    // (referred to as 'variation' [...]) in the observed RTT samples" - and a
    // deviation is of a sample from a predictor made BEFORE the sample was seen.
    // Measuring it against a smoothed_rtt that has already been pulled an eighth of
    // the way toward that same sample measures the residual after fitting, which is
    // a different and smaller quantity. Recorded rather than silently chosen,
    // because a reader holding s5.3 open will otherwise read these two lines as
    // transposed by accident. Witnessed by
    // TlsQuicAckTrackerTests.RttVariationIsMeasuredAgainstTheSmoothedRttFromBefore
    // ThisSample, which asserts the 7/8 relationship in both directions so that
    // swapping these two statements fails rather than merely shifting a number.
    private void UpdateRtt(
        TimeSpan latestRtt,
        ulong encodedAckDelay,
        TlsQuicEncryptionLevel level,
        DateTimeOffset receivedAt)
    {
        _latestRtt = latestRtt;

        // A.7's first branch. s5.3: "On the first RTT sample after initialization,
        // the estimator is reset using that sample. This ensures that the estimator
        // retains no history of past samples." An initial RTT is a guess, and
        // smoothing a real measurement against a guess would leave 7/8 of the guess
        // in smoothed_rtt after the first round trip.
        if (_firstRttSampleAt is null)
        {
            _minimumRtt = latestRtt;
            _smoothedRtt = latestRtt;
            _rttVariation = new TimeSpan(latestRtt.Ticks / 2);
            _firstRttSampleAt = receivedAt;
            return;
        }

        // s5.2: "min_rtt MUST be set to the lesser of min_rtt and latest_rtt on all
        // other samples" - and "An endpoint uses only locally observed times in
        // computing the min_rtt and does not adjust for acknowledgment delays
        // reported by the peer", which is why this reads latestRtt and not the
        // adjusted value computed below it. Adjusting first would let a misreporting
        // peer drive min_rtt down and, through the guard below, unlock further
        // underestimation of every later sample.
        if (latestRtt < _minimumRtt)
        {
            _minimumRtt = latestRtt;
        }

        var ackDelay = DecodeAckDelay(encodedAckDelay, level);

        // s5.3: "MUST use the lesser of the acknowledgment delay and the peer's
        // max_ack_delay AFTER the handshake is confirmed", and before it "SHOULD
        // ignore the peer's max_ack_delay". Conditional, not unconditional: s5.3
        // explains that pre-confirmation delays "are likely to be non-repeating and
        // limited to the handshake. The endpoint can therefore use them without
        // limiting them to the max_ack_delay, avoiding unnecessary inflation of the
        // RTT estimate."
        if (_handshakeConfirmed && ackDelay > _peerMaxAckDelay)
        {
            ackDelay = _peerMaxAckDelay;
        }

        // s5.3's last bullet: "MUST NOT subtract the acknowledgment delay from the
        // RTT sample if the resulting value is smaller than the min_rtt. This limits
        // the underestimation of the smoothed_rtt due to a misreporting peer." See
        // DEPARTURE 1 above for why the comparison is subtraction and not addition.
        var adjustedRtt = latestRtt;
        if (latestRtt - _minimumRtt >= ackDelay)
        {
            adjustedRtt = latestRtt - ackDelay;
        }

        // rttvar BEFORE smoothed_rtt, against the smoothed_rtt from before this
        // sample - A.7, and DEPARTURE 4 above for why not s5.3's prose order.
        var variationSample = (_smoothedRtt - adjustedRtt).Duration();
        _rttVariation += new TimeSpan((variationSample - _rttVariation).Ticks / 4);
        _smoothedRtt += new TimeSpan((adjustedRtt - _smoothedRtt).Ticks / 8);
    }

    // s19.3: the ACK Delay field "is decoded by multiplying the value in the field
    // by 2 to the power of the ack_delay_exponent transport parameter sent by the
    // sender of the ACK frame". The peer sent this frame, so the exponent is the
    // PEER'S - the exact mirror of TryBuildAck's, which uses ours because we send
    // those. The class header's second numbered note spells out that a mismatch is
    // silent in both directions: both values are legal and every frame still parses.
    //
    // SATURATES INSTEAD OF WRAPPING. The field is a varint, so the peer can name
    // 2^62-1 microseconds and then have it multiplied by up to 2^20; both the shift
    // and the conversion to ticks would wrap a ulong silently, and a wrapped
    // ack_delay is a small positive number rather than an obviously wrong one. The
    // bound below is the largest microsecond count TimeSpan can hold, and anything
    // above it decodes to TimeSpan.MaxValue - which the min_rtt guard above then
    // refuses to subtract, so an absurd delay is ignored rather than believed.
    private TimeSpan DecodeAckDelay(ulong encoded, TlsQuicEncryptionLevel level)
    {
        // s5.3's first bullet, a MAY THIS TAKES: "MAY ignore the acknowledgment delay
        // for Initial packets, since these acknowledgments are not delayed by the
        // peer (Section 13.2.1 of [QUIC-TRANSPORT])". s13.2.1 is the sentence this
        // file's own header quotes - "An endpoint MUST acknowledge all ack-eliciting
        // Initial and Handshake packets immediately" - so a nonzero ACK Delay on an
        // Initial packet describes a delay the peer was not entitled to take.
        // Ignoring it is the arm that cannot deflate a sample, and taking the MAY
        // rather than passing over it silently is the point of writing it out.
        //
        // INITIAL ONLY, NOT HANDSHAKE, even though s13.2.1's "immediately" covers
        // both: s5.3's bullet names Initial packets alone, and widening an RFC's
        // enumeration because a neighbouring sentence seems to permit it is how a
        // rule stops being checkable against its source.
        if (level == TlsQuicEncryptionLevel.Initial)
        {
            return TimeSpan.Zero;
        }

        // The peer cannot reach this with an exponent above 20 - OnPeerAckParameters
        // clamps - so the shift below is never a C# `count & 63` in disguise.
        const ulong MaximumMicroseconds = (ulong)(long.MaxValue / TicksPerMicrosecond);
        if (encoded > MaximumMicroseconds >> _peerAckDelayExponent)
        {
            return TimeSpan.MaxValue;
        }

        return new TimeSpan((long)(encoded << _peerAckDelayExponent) * TicksPerMicrosecond);
    }

    // TimeSpan.Ticks are 100ns; s19.3's ACK Delay is "in microseconds".
    private const long TicksPerMicrosecond = 10;

    // s13.2.3's two rules about which ranges go, in the order it states them:
    // "ACK frames SHOULD always acknowledge the most recently received packets
    // [...] If it does not [fit], then older ranges (those with the smallest packet
    // numbers) are omitted", and "A receiver SHOULD include an ACK Range containing
    // the largest received packet number in every ACK frame." Ranges are held
    // descending, so both amount to truncating the tail.
    private void Prune(int space)
    {
        var ranges = _ranges[space];
        if (ranges.Count <= _maximumAckRanges)
        {
            return;
        }

        ranges.RemoveRange(_maximumAckRanges, ranges.Count - _maximumAckRanges);

        // s13.2.3's minimum-packet-number mechanism, quoted on the field. Set to
        // the smallest number still retained, so the surviving ranges stay
        // acceptable and everything below the cut is refused for good.
        _minimumPacketNumber[space] = ranges[^1].Smallest;
    }

    // Adds one packet number to a descending, non-overlapping, non-adjacent list of
    // inclusive ranges, merging where the number touches a neighbour.
    //
    // THIS IS THE ARITHMETIC THAT CAN ACKNOWLEDGE A PACKET THAT WAS NEVER SENT, and
    // it is the reason the merge tests are byte-exact rather than round-trips. A
    // merge condition that is one too loose in either direction swallows the
    // unreceived number between two ranges and puts it on the wire as
    // acknowledged - s19.3's "QUIC acknowledgments are irrevocable" means the peer
    // may then retire a packet it never got through, permanently. The two
    // conditions below are therefore written as ADDITIONS on the incoming number
    // rather than subtractions on the stored bound: `packetNumber + 1 ==
    // range.Smallest` cannot underflow when Smallest is 0, whereas the algebraically
    // identical `packetNumber == range.Smallest - 1` wraps to 2^64-1 there and makes
    // packet number 0 adjacent to nothing at all.
    //
    // Linear in _maximumAckRanges, not in the number of packets received, and
    // that distinction is the whole of this paragraph. The bound holds only
    // because OnPacketReceived prunes after EVERY insert, so this list is at most
    // _maximumAckRanges + 1 entries long on entry here. While the prune ran at
    // send time instead, this claim was false at the one call site that matters:
    // packets arriving in descending order take the loop to its last index every
    // time, so the scan was quadratic in an attacker-controlled count - about
    // 287 ms for 5000 packets in Debug - on the receive path task 9a-ii's loop
    // inherits. A binary search would still be a second index to get wrong for a
    // list of tens of entries.
    // ponytail: linear scan, bounded by _maximumAckRanges; revisit if that limit
    // ever grows past the low hundreds.
    private static void Insert(List<TlsQuicAckRange> ranges, ulong packetNumber)
    {
        for (var index = 0; index < ranges.Count; index++)
        {
            var range = ranges[index];

            // Already acknowledged. s19.3's irrevocability makes a duplicate a
            // no-op rather than an error - the packet was received, it is still
            // received, and nothing about the range set changes.
            if (packetNumber <= range.Largest && packetNumber >= range.Smallest)
            {
                return;
            }

            // Immediately below this range: extend it down, and then check whether
            // doing so made it touch the range beneath, in which case the two are
            // now one.
            //
            // THE COALESCE IS NOT OPTIONAL, AND AN EARLIER REVISION OF THIS METHOD
            // OMITTED IT - the bug is recorded because the reasoning that produced
            // it is easy to repeat. That revision argued "the range below is at
            // least two lower, or the two would already be one range", which is
            // true of the range as it stood and false of the range as extended:
            // holding (5,5) and (3,3) with packet 4 missing is legal, and filling
            // 4 makes the first range (5,4), which is adjacent to (3,3). s19.3.1
            // cannot encode adjacent ranges at all - "The number of packets in the
            // gap is one higher than the encoded value of the Gap field", so even a
            // zero Gap skips a packet - and TlsQuicAckFrames.ValidateRanges throws.
            // The symptom was not a wrong ACK but no ACK: an exception thrown while
            // building one, on the single commonest reordering pattern there is, a
            // one-packet hole filled by a retransmission.
            // Witnessed by
            // TlsQuicAckTrackerTests.FillingAOnePacketHoleCoalescesTheRangesOnBothS
            // idesOfIt.
            if (packetNumber + 1 == range.Smallest)
            {
                ranges[index] = range with { Smallest = packetNumber };
                if (index + 1 < ranges.Count && ranges[index + 1].Largest + 1 == packetNumber)
                {
                    ranges[index] = ranges[index] with { Smallest = ranges[index + 1].Smallest };
                    ranges.RemoveAt(index + 1);
                }
                return;
            }

            // Immediately above this range: extend it up.
            //
            // NO COALESCE WITH THE RANGE ABOVE, and unlike the case above that is
            // not an omission - it is unreachable. Reaching this line at index i
            // means the branch above did not fire at i-1, so ranges[i-1].Smallest
            // != packetNumber + 1; and the merge condition that would be tested
            // here is exactly ranges[i-1].Smallest == packetNumber + 1. The two
            // are the same predicate on the same values, and the descending scan
            // always visits i-1 first. Deliberately unwitnessed: a test for the
            // missing merge would have to construct a state that cannot occur, and
            // would pass against a mutant that added the dead branch back.
            if (packetNumber == range.Largest + 1)
            {
                ranges[index] = range with { Largest = packetNumber };
                return;
            }

            // Strictly between this range and the one below, touching neither: a
            // new single-packet range goes here, keeping the list descending.
            if (packetNumber > range.Largest)
            {
                ranges.Insert(index, new TlsQuicAckRange(packetNumber, packetNumber));
                return;
            }
        }

        // Below every range held, touching none - or the very first packet in this
        // space, which is the same insertion into an empty list.
        ranges.Add(new TlsQuicAckRange(packetNumber, packetNumber));
    }

    // RFC 9000 s12.3's three spaces, collapsing 0-RTT and 1-RTT onto the one
    // application data space they share. Written out rather than cast from the
    // enum's ordinal for the reason TlsQuicFrameLegality.Column gives: the enum
    // declares its members in handshake order (Initial, EarlyData, Handshake,
    // Application) so an ordinal would put EarlyData where Handshake belongs.
    //
    // INTERNAL RATHER THAN PRIVATE, AND THAT IS HALF A FIX WITH THE OTHER HALF
    // NAMED. Task A3-3 found three private copies of this mapping and declined to
    // add a fourth silently: TlsQuicAckTracker (here),
    // TlsQuicPacketReceiver.SpaceOf, and TlsQuicConnection.SpaceOf - whose own
    // comment records the blocker as "TlsQuicAckTracker.SpaceOf is private, and
    // this task's brief forbids editing that file." This file IS A3-4's, so the
    // blocker is removed here. Collapsing the other two is not, because doing so
    // edits TlsQuicConnection.cs and TlsQuicPacketReceiver.cs, which A3-4 does not
    // own either - so this is deliberately the widening without the collapse, and
    // the next task to touch those two files should delete their copies and call
    // this. Widened rather than left private because the alternative was leaving a
    // comment in another file citing an accessibility that one keyword fixes, and
    // because a fourth copy is the outcome that becomes likelier every task this
    // stays shut.
    //
    // The three copies do agree today - that was checked, not assumed - which is
    // why this is tidying rather than a defect: mutation 40 in the ledger above
    // pins THIS copy's EarlyData/Handshake grouping, and TlsQuicConnection's
    // mutation 138 records the same swap being vacuous there for the same reason.
    internal static int SpaceOf(TlsQuicEncryptionLevel level) => level switch
    {
        TlsQuicEncryptionLevel.Initial => 0,
        TlsQuicEncryptionLevel.Handshake => 1,
        TlsQuicEncryptionLevel.EarlyData or TlsQuicEncryptionLevel.Application => 2,
        _ => throw new ArgumentOutOfRangeException(
            nameof(level),
            level,
            "Not one of the four encryption levels RFC 9000 s12.3's three packet number spaces cover."),
    };
}
