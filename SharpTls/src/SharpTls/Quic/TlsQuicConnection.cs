using System.Security.Cryptography;

namespace SharpTls.Quic;

// ============================================================================
// THE MUTATION LEDGER
// ============================================================================
//
//   ROWS BELOW                  170  = numbered 1-170 with no gaps
//   KILLED WHEN FIRST RUN       129  = 170 rows, less 18 [WAS-SURVIVOR] and 23 [SURVIVED]
//   SURVIVED, THEN FIXED OR      18  =  rows 3, 9, 10, 11, 13, 17, 23, 26, 27, 33, 34, 36,
//     WITNESSED                        65, 69, 70, 71, 82, 143
//   SURVIVING STILL              23  =  rows 21, 25, 28, 30, 31, 32, 43, 44, 45, 46, 89,
//                                      90, 115, 117, 133, 134, 138, 145, 151, 160, 161,
//                                      166, 168 - every one classified below
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' TlsQuicConnection.cs`                    must return 170
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicConnection.cs`   must return 18
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' TlsQuicConnection.cs`       must return 23
//
// THOSE THREE GREPS DO NOT HOLD AND DID NOT HOLD BEFORE A4-COMPLETE TOUCHED THIS FILE. Run at
// pristine 69bd925, in a worktree, before a single line of the MAX_DATA task was written, they
// return 191, 20 and 22 against the 170, 18 and 23 stated above. Some earlier task added rows
// without moving the summary. IT IS RECORDED HERE RATHER THAN REPAIRED: correcting the three
// figures would need each of the twenty-one unaccounted rows traced to the sweep that produced
// it, and inventing a total to make the grep pass would be worse than a total that is visibly
// wrong. A4-complete's own row is prefixed and counted separately below, precisely so that it
// cannot be mistaken for a repair of this.
//
// ============================================================================
// THE A4-COMPLETE MUTATION LEDGER - THE DISPATCH ARM, SEPARATELY PREFIXED
// ============================================================================
//
//   ROWS BELOW                    1  = A4C-29. The other twenty-nine A4C rows belong to
//                                      TlsQuicStreams.cs and TlsQuicPeerFlowControlBudget.cs,
//                                      one ledger per file, because this task spends exactly
//                                      four code lines here.
//   KILLED BY THE COMPILER        1  = row A4C-29, from the build's EXIT CODE
//   SURVIVING STILL               0
//
//   `grep -cE '^// +A4C-[0-9]+\. ' TlsQuicConnection.cs`                 = 1
//   `grep -cE '^// +A4C-[0-9]+\..*\[SURVIVED\]' TlsQuicConnection.cs`    = 0
//
//   A4C-29. [COMPILER] both new case labels get a `when false` guard, so MAX_DATA and
//           MAX_STREAM_DATA fall back into the default arm and every grant is dropped again -
//           which is exactly the defect this task removed. IT NEVER REACHED THE GATE, AND THE
//           REASON WAS RE-RUN RATHER THAN GUESSED: the first draft of this row asserted
//           CS8120; rebuilding the mutant reports CS0162 (unreachable code detected), because
//           two `when false` labels make the arm's body unreachable rather than the labels
//           themselves ill-formed. This tree makes CS0162 an error. The row is therefore
//           evidence that the arm cannot be disabled
//           without the compiler noticing, and NOT evidence that any test covers it. What
//           covers the arm is A4C-30 in TlsQuicStreams.cs, which routes the two grants to each
//           other's handler and kills 6 cases - a mutation the compiler cannot see.
//
// ROWS 121-140 ARE TASK A3-3's - sent-packet retention and bytes in flight - run against a
// 2120-CASE gate: the 2092 this task inherited at HEAD 2304698 plus the 28 witnesses it adds.
// 17 KILLED, 3 SURVIVED, and all three survivors are VACUOUS with the proof written out below
// rather than asserted. Every run reported 2120 total, which the sweep checks before scoring
// anything - a run that misses the floor is retried, and a second miss aborts the sweep.
//
// THE FIRST TWO ATTEMPTS AT THIS SWEEP WERE THROWN AWAY, AND THE REASON IS WORTH THE LINES.
// A sweep process from an earlier launch was still alive when a second was started against the
// SAME worktree. Two processes applying and reverting mutations to one file produced 14 rows
// of KILLED-BY-COMPILER, which is the verdict that proves nothing. Neither run was scored.
// The fix was NOT `taskkill /F /IM testhost.exe` - three agents had test hosts on this machine
// and that command matches every one of them; that step is what aborted two runs of the task
// 14 sweep at 178 and 171 counted cases. Processes were identified by COMMAND LINE, the two
// belonging to this task were allowed to finish, and one clean pass was then run alone.
// THE CASE-COUNT FLOOR IS WHAT MADE THE CORRUPTION VISIBLE AT ALL.
//
// A SECOND DEFECT WAS IN THE SCORING SCRIPT ITSELF, and it would have published false
// witnesses: the verdict regex read `(KILLED|SURVIVED|KILLED-BY-COMPILER)`, and since every
// group after it was optional, `KILLED` matched the prefix of `KILLED-BY-COMPILER` and won.
// Every compiler kill would have been recorded as a genuine kill against a named test. Found
// by reading the alternation rather than by any run, fixed by ordering the longest first, and
// re-checked against all three verdict shapes before the clean sweep was scored.
//
// ROWS 100-120 ARE THE 1-RTT CONNECTION_CLOSE TASK'S, 21 of them, run against a 1728-CASE
// gate - the 1721 this file's task inherited plus the 7 witnesses it added. 19 KILLED, 2
// SURVIVED, and every single run reported 1728 total, which is the stale-binary check the
// sweep applies to its own output before scoring anything.
//
// THE SWEEP RAN AGAINST AN ISOLATED COPY OF THE TREE, NOT THE WORKING TREE, and that is worth
// recording because it changed a verdict. Two other agents were editing this repository at the
// time; a build one of them broke mid-sweep would have been scored as a kill, and their
// in-progress tests would have moved the case count under every row. The copy carries this
// task's changes and nothing else, which is what makes 1728 mean 1721 + 7.
//
// THE HARNESS WAS PROVED IN BOTH DIRECTIONS BEFORE ANY ROW WAS SCORED, and the first attempt
// FAILED that proof rather than passing it: the known-bad control reported no summary at all,
// twice. The cause was the recipe's own `taskkill /F /IM testhost.exe` step, which matches
// EVERY agent's test host and not just this sweep's - two runs were aborted at 178 and 171
// counted cases by another agent's kill, and this sweep's kills were aborting theirs. The kill
// step is a no-op here (the copy has its own bin, which nothing else touches) and run_gate
// retries an aborted run instead of scoring it. Re-proved after that: known-bad -> KILLED
// (7 failed of 1728), inert comment -> SURVIVED (0 failed of 1728).
//
// ROWS 93-97 ARE TASK 14d's, run against its 1166-CASE gate, and every one of the five KILLED.
//
// ROWS 1-92 WERE NOT RE-MEASURED AT 1166, AND THAT IS A STATED CLAIM RATHER THAN A SILENCE.
// Task 14c re-ran its rows 19, 20, 68 and 89 because that task changed what all four MEAN;
// task 14d changes what none of them means. It adds a check to
// ApplyPeerTransportParametersAsync and adds thirty test cases that drive the same handshake
// forty existing cases already drove - no packet build, no ACK, no coalescing, no key
// discard, no close path is touched, and those are what rows 1-92 mutate. THE PART OF THAT
// CLAIM THAT COULD BE WRONG IS THE TWELVE SURVIVORS: if any of them now kills, this ledger
// overstates the gap. Each was classified as unreachable by construction, unwitnessable,
// vacuous or deliberately unwitnessed, none of them about transport parameters, and 14d's new
// cases exercise none of the code they mutate - so the risk is judged low and is recorded
// here rather than measured, which is the honest form. They were not reconstructed because
// twelve edits rebuilt from one-line descriptions across 2495 lines is a likelier source of a
// wrong figure than the figure it would replace.
//
// ROWS 90-92 ARE TASK 14c's, run against its 1136-test gate, and rows 19, 20, 68 and 89 were
// RE-RUN in the same sweep because that task changed what all four mean. EVERY FIGURE HERE WAS
// RE-MEASURED AT 1136 AFTER THE LAST TEST OF THAT TASK LANDED, and the re-measurement moved
// four of them - row 20 read 4 against the 1133-test gate it was first run at. A ledger whose
// figures were counted against an earlier suite is the flaw LoopbackQuicPeer.cs's ledger names,
// and it was nearly shipped again here. Counts are per xUnit CASE, so a two-row Theory that
// fails in both rows counts 2. The rest of task
// 14c's sweep is not here: twelve of its mutations edit TlsQuicApplicationSendPath.cs and are
// recorded in that file's own ledger, and two edit LoopbackQuicPeer.cs and are in its. One
// ledger per file, so that each file's three greps stay about that file.
//
// ROW 20 IS THE ONE THAT MATTERED IN TASK 14c, AND THE ROW ITSELF INVERTED WITH THE CODE. It
// used to read "the Application skip removed" and its two kills were tests asserting that
// A4-minimal did NOT acknowledge a 1-RTT packet - which is to say the row measured a
// KNOWINGLY VIOLATED MUST holding. RFC 9000 s13.2.1 requires the acknowledgement, the skip is
// gone, and the mutation that means the same thing now is the opposite edit: put it back.
// ROWS 86-89 ARE TASK 9b's REVIEW FIX ROUND'S, run against the 1108-test gate (1104 plus the
// four witnesses that round added). ROW 71 WAS RE-RUN in the same sweep and is now a kill: it
// was recorded as unreachable by construction, the recorded REASON was false, and fixing the
// s10.1 divergence that made it unfireable is what made it reachable. See the note below it.
//
// ROWS 33-46 ARE THE FIX ROUND'S, run against the final 1054-test gate. Rows 1-32 were run
// against the 1043-test gate the task shipped with; the ones the fix round's edits touched -
// 4, 5, 6, 22, 23 - were RE-RUN against 1054 and their entries below say what the re-run
// found, which is not always what the first run found. Rows 3, 9, 10 and 11 cannot be re-run:
// the code they mutated no longer exists, and in rows 9-11's case removing it is the fix.
// Where a row says ONLY, that test was the entire failure set.
//
//    1. Confirm keyed on TLS completion too      ONLY TheClientReachesCompleteAgainstTheTaskSevenPeerAndConfirmsOnlyOnHandshakeDone
//    2. NotifyHandshakePacketSent never called   ONLY InitialKeysAreDiscardedAfterTheHandshakePacketIsBuiltAndNotBefore
//    3. The results' discards applied before the send  [WAS-SURVIVOR] 0 of 1040 -> the code is gone; see row 31
//    4. s12.2's connection ID check neutered     ONLY ASubsequentCoalescedPacketWithADifferentDestinationConnectionIdIsIgnored (re-run at 1054)
//    5. s7.2 adopts the peer's Destination CID   ONLY TheServersSourceConnectionIdBecomesOurDestinationConnectionId
//    6. s7.2 adoption removed entirely           2 tests at 1054, was ONLY TheServersSourceConnectionIdBecomesOurDestinationConnectionId
//    7. Secrets installed after the datagram     3 tests
//    8. The whole datagram in one Receive call   5 tests
//    9. The guard's `Processed == 0` dropped     [WAS-SURVIVOR] 0 of 1043 -> the guard is gone; see rows 40-42
//   10. The guard's `Discarded > 0` dropped      [WAS-SURVIVOR] 0 of 1043 -> the guard is gone; it was a kill switch, see below
//   11. The guard's `Unprocessed != None` dropped  [WAS-SURVIVOR] 0 of 1043 -> the guard is gone; see rows 40-42
//   12. The post-receive deadline check dropped  ONLY TheHandshakeDeadlineFiresOnTheFakeClockWithNoWallClockTimeElapsed
//   13. The deadline stops bounding the await    [WAS-SURVIVOR] -> now ONLY APeerThatGoesSilentIsBoundedByTheDeadlineToo
//   14. HeaderLengthVarintWidth ignored          ONLY TheSpecsVarintWidthsReachTheWire
//   15. CryptoOffsetVarintWidth ignored          ONLY TheSpecsVarintWidthsReachTheWire
//   16. CryptoLengthVarintWidth ignored          ONLY TheSpecsVarintWidthsReachTheWire
//   17. AckRangeLimit not wired to the tracker   [WAS-SURVIVOR] -> now ONLY TheSpecsAckRangeLimitBoundsTheRangesThatReachTheWire
//   18. The answer's packet number never advances  ONLY InitialKeysAreDiscardedAfterTheHandshakePacketIsBuiltAndNotBefore
//   19. The EarlyData skip removed               18 tests at 1136, was 2
//   20. The Application skip PUT BACK            7 tests at 1136; see the note above - the
//       edit inverted with the code, and the row's first run measured the skip's removal
//   21. A discarded level throws instead of being skipped  [SURVIVED] 0 of 1043 - unreachable by construction
//   22. The ACK frame never added to a flight    11 tests at 1054, was 3
//   23. LargestAcknowledged never reported       [WAS-SURVIVOR] 0 of 1043 -> now ONLY TheAnswersPacketNumberIsEncodedAgainstTheLargestAcknowledged
//   24. Initial keys derived as a server         10 tests
//   25. The receive buffer pooled across datagrams  [SURVIVED] 0 of 1043 - unwitnessable
//   26. The flight advances the number by one    [WAS-SURVIVOR] -> now ONLY AFlightPlannedAsTwoDatagramsSendsTwoAndNumbersThemFromTheSpec
//   27. InitialPacketNumber not read             [WAS-SURVIVOR] -> now ONLY AFlightPlannedAsTwoDatagramsSendsTwoAndNumbersThemFromTheSpec
//   28. The flight's contiguity check deleted    [SURVIVED] 0 of 1043 - unreachable by construction
//   29. The peer stamps key phase 1 on its 1-RTT packet  2 tests
//   30. The peer's 1-RTT packet number frozen    [SURVIVED] 0 of 1043 - vacuous
//   31. The ProcessCryptoDataAsync discard check deleted  [SURVIVED] 0 of 1043 - deliberately unwitnessed
//   32. AckDelayExponent not wired to the tracker  [SURVIVED] 0 of 1043 - vacuous
//   33. The coalescing order knob ignored        [WAS-SURVIVOR] -> now ONLY ThePacketsOfOneDatagramAreCoalescedInTheOrderTheSpecAsksFor(False)
//   34. The ACK-position knob ignored            [WAS-SURVIVOR] -> now ONLY TheAcksPositionInsideThePacketIsTheOneTheSpecAsksFor(False)
//   35. The trailing-ACK branch deleted          ONLY TheAcksPositionInsideThePacketIsTheOneTheSpecAsksFor(False)
//   36. s7.2's once-only adoption guard neutered  [WAS-SURVIVOR] -> now ONLY OnlyTheFirstServerPacketMovesOurDestinationConnectionId
//   37. s7.2's changed-Source-CID discard deleted  ONLY APacketWhoseSourceConnectionIdChangedAfterAValidOneIsDiscarded
//   38. s7.2's "valid" dropped - the Source CID recorded before the AEAD  2 tests
//   39. The ack_delay_exponent reconciliation deleted  ONLY AnAdvertisedAckDelayExponentThatDisagreesWithTheOneWeScaleByIsRefused
//   40. DiscardedPackets never accumulated       5 tests
//   41. DiscardedForMissingKeys never accumulated  2 tests
//   42. The deadline stops reporting the counters  ONLY TheDeadlineNamesTheDiscardsThatProducedTheStall
//   43. `_confirmed` set before ConfirmHandshake  [SURVIVED] 0 of 1054 - unreachable by construction
//   44. The lazy-iterator window check deleted   [SURVIVED] 0 of 1054 - unreachable by construction
//   45. The CloseError throw deleted             [SURVIVED] 0 of 1054 - unwitnessable through the writer
//   46. NotifyHandshakePacketSent moved between the build and the send  [SURVIVED] 0 of 1054 - vacuous
//
//   47. A Retry announcing another QUIC version honoured          ONLY ARetryAnnouncingAnotherQuicVersionIsIgnored
//   48. s17.2.5.2's at-most-one-Retry half dropped                ONLY ASecondRetryIsIgnoredEvenThoughItsIntegrityTagValidates
//   49. s17.2.5.2's no-Retry-after-a-processed-packet half dropped ONLY ARetryThatFollowsASuccessfullyProcessedServerPacketIsIgnored
//   50. s17.2.5.2 zero-length Retry Token check deleted           ONLY ARetryWithAZeroLengthTokenIsIgnored
//   51. s17.2.5.1's Source-CID-equals-our-Destination check deleted ONLY ARetryWhoseSourceConnectionIdEqualsOurDestinationIsIgnored
//   52. s5.8 Retry Integrity Tag never checked                    ONLY ARetryWhoseIntegrityTagDoesNotValidateIsIgnored
//   53. Initial keys not re-derived from the Retry CID            4 tests
//   54. the original Destination CID not retained past a Retry    4 tests
//   55. s17.2.5.3 packet number reset after a Retry               ONLY AValidRetryMovesTheConnectionIdAndTokenAndRederivesTheInitialKeys
//   56. no Initial packet sent in answer to a Retry               5 tests
//   57. the Retry Token never reaches the wire                    ONLY AValidRetryMovesTheConnectionIdAndTokenAndRederivesTheInitialKeys
//   58. RetrySourceConnectionId back to the never-null form       3 tests
//   59. a VN packet honoured after a processed packet             ONLY AVersionNegotiationPacketAfterASuccessfullyProcessedPacketIsIgnored
//   60. s17.2.1's Destination echo not checked                    ONLY AVersionNegotiationPacketThatDoesNotEchoBothConnectionIdsIsIgnored
//   61. s17.2.1's Source echo not checked                         ONLY AVersionNegotiationPacketThatDoesNotEchoBothConnectionIdsIsIgnored
//   62. a VN packet recorded but the attempt continues            ONLY AVersionNegotiationPacketEndsTheAttemptAndNamesTheVersionsOffered
//   63. the close always REPORTS NO_ERROR                         9 tests
//   64. the CONNECTION_CLOSE frame always CARRIES NO_ERROR        ONLY ClosingSendsAConnectionCloseCarryingTheSection201CodeItWasGiven
//   65. s10.2.3 highest-level-first inverted for the close        [WAS-SURVIVOR] -> now ONLY AServerConnectionIdParameterThatDoesNotMatchClosesWithTransportParameterError
//   66. a peer CONNECTION_CLOSE does not enter draining           ONLY APeerConnectionCloseEntersDrainingAndStopsSendingAndDelivering
//   67. s10.2.2 MUST NOT send: the answer goes out while draining ONLY APeerConnectionCloseEntersDrainingAndStopsSendingAndDelivering
//   68. PATH_CHALLENGE data not recorded                          ONLY both rows of APathChallengeIsAnsweredWithAPathResponseInAOneRttPacket (2 at 1136; the killer was renamed and made a Theory when 14c inverted it)
//   69. the idle deadline does not bound the receive              [WAS-SURVIVOR] -> now ONLY APeerThatGoesSilentIsBoundedByTheIdleTimeoutToo
//   70. the idle timer not restarted on a processed packet        [WAS-SURVIVOR] -> now ONLY AProcessedPacketRestartsTheIdleTimer
//   71. the idle timer restarted on EVERY ack-eliciting send      [WAS-SURVIVOR] -> now ONLY ARetryAnswerDoesNotRestartTheIdleTimerBecauseNothingHasBeenReceived
//   72. the abandonment attributes by expiry, not by which is nearer ONLY APeerThatGoesSilentIsBoundedByTheIdleTimeoutToo
//   73. s10.1 effective idle timeout is always ours               ONLY TheEffectiveIdleTimeoutIsTheMinimumOfTheTwoAdvertisedValues
//   74. s10.1 effective idle timeout is always the peer's         ONLY TheEffectiveIdleTimeoutIsTheMinimumOfTheTwoAdvertisedValues
//   75. the max_idle_timeout saturation cap removed               ONLY APeerAdvertisingTheLargestVarintIdleTimeoutSaturatesRatherThanOverflowing
//   76. s10.1's silent close dropped - a frame goes out on idle   ONLY TheIdleTimeoutFiresOnTheFakeClockWithNoWallClockTimeElapsed
//   77. s10.1's commitment to an immediate close not honoured     ONLY AbandoningBeforeTheAdvertisedIdleTimeoutSendsTheCloseItCommittedTo
//   78. s7.3 value comparison replaced with a constant            4 tests
//   79. s7.3 compares LENGTHS instead of bytes                    4 tests
//   80. s7.3 absence not treated as an error                      3 tests
//   81. s7.3 retry_source without a Retry accepted                ONLY ARetrySourceConnectionIdSentWithoutARetryClosesWithTransportParameterError
//   82. s7.3 initial_source compared against the OBSERVED CID     [WAS-SURVIVOR] -> now ONLY AnInjectedFirstInitialThatMovedTheAdoptionIsCaughtBySection73
//   83. s7.3 original_destination compared against the current CID 4 tests
//   84. s7.3 retry_source never checked after a Retry             ONLY AHandshakeAfterARetryValidatesRetrySourceConnectionId
//   85. "successfully processed" never becomes true               2 tests
//   86. s6.2's lists-our-version discard deleted                  2 tests
//   87. s17.2.5.1 compared against the CURRENT destination CID    ONLY ARetryWhoseSourceConnectionIdEqualsOurFirstInitialsDestinationIsIgnored
//   88. StartAsync's opening flight not recorded as a send        ONLY ARetryAnswerDoesNotRestartTheIdleTimerBecauseNothingHasBeenReceived
//   89. the answer datagram's ack-eliciting condition dropped     [SURVIVED] 0 of 1136 - re-run at 14c, still unreachable; see below
//   90. the ack-eliciting test reverts to `crypto.Count > 0`      [SURVIVED] 0 of 1136 - the same classification as row 89
//   91. the 1-RTT packet built inside the level loop              ONLY the ascending:false row of AHandshakePacketCoalescedWithAOneRttOneIsAnsweredAtBothLevels
//   92. SendAnswerAsync always reports that it sent               3 tests
//   93. the budget is never built from the peer's parameters      40 tests
//   94. the s6.2 check runs before s7.3 instead of after          ONLY both rows of AServerThatOmitsAConnectionIdParameterClosesWithTransportParameterError
//   95. the s6.2 refusal closes with TRANSPORT_PARAMETER_ERROR    4 tests
//   96. the s6.2 refusal closes but does not throw                4 tests
//   97. the not-yet-arrived guard on PeerFlowControl removed      ONLY TheBudgetIsUnreachableBeforeThePeersParametersArrive
//   98. task 14e's s19.8 STREAM dispatch arm deleted              4 tests
//   99. the STREAM refusal is recorded and never thrown           2 tests
//
//  100. the confirmed arm sends at Handshake, not 1-RTT          7 tests
//  101. 1-RTT taken whether or not the handshake is confirmed    5 tests
//  102. the unconfirmed arm loses its Initial fallback           3 tests
//  103. s19.19's 0x1d never written, the form collapses to 0x1c  2 tests
//  104. s19.19's 0x1d written at every level, Table 3 ignored    18 tests
//  105. s10.2.3's conversion drops its packet-type test          ONLY AnApplicationCloseBeforeOneRttKeysIsConvertedToType0x1cAndLosesItsReason
//  106. s10.2.3's conversion drops its encodability test         ONLY AnUnencodableApplicationErrorCodeIsConvertedRatherThanThrown
//  107. a converted frame keeps the application error code       2 tests
//  108. a converted frame keeps its Reason Phrase                2 tests
//  109. s19.19's Frame Type written as 1 instead of 0            2 tests
//  110. s20's 62-bit ceiling made exclusive, not inclusive       ONLY TheLargestEncodableApplicationErrorCodeIsSentRatherThanConverted
//  111. an unencodable transport code reaches the varint writer  ONLY AnUnencodableTransportErrorCodeSendsNothingAndStillEntersTheClosingState
//  112. the Reason Phrase cap raised past what a packet holds    2 tests
//  113. the Reason Phrase cut by a byte slice, not a UTF-8 one   ONLY AThreeByteCharacterStraddlingTheReasonPhraseCapIsDroppedWhole
//  114. the Reason Phrase dropped entirely                       6 tests
//  115. the close recorded even when no datagram was written     [SURVIVED] 0 of 1728 - unreachable by construction
//         TlsQuicDatagramBuilder.BuildDatagram throws on an empty packet list and this call
//         site always hands it exactly one packet, which always produces bytes. So `written`
//         is > 0 at every execution that reaches the recording block, and the guard's false
//         branch cannot be entered. The two ways BuildCloseDatagram yields 0 - an unencodable
//         transport code, and no write keys at any candidate level - both return BEFORE that
//         block rather than through it. Row 111 is the witness that the first of the two
//         records nothing, which is the property this guard would protect if it were live.
//  116. ClosedWith records the requested code, not the frame's   2 tests
//  117. ClosedWithApplicationErrorCode records the requested code  [SURVIVED] 0 of 1728 - vacuous
//         That line runs only when sentAsApplicationForm is true, which is `application &&
//         !convert`, and on the not-converted arm the frame's ErrorCode is assigned
//         `errorCode` verbatim. The two expressions are therefore the same value wherever the
//         line executes, and no input distinguishes them. NO TEST IS OWED FOR IT: one that
//         could tell them apart would have to construct a state the code makes impossible.
//         It is mutated and recorded anyway because its SIBLING - row 116, on the 0x1c arm -
//         is NOT vacuous, since s10.2.3's conversion makes frame.ErrorCode differ from
//         errorCode there. A reader comparing the two lines is entitled to know that the
//         asymmetry was measured rather than assumed.
//  118. the two report properties swapped                        20 tests
//  119. CloseAsync routed through the application form           13 tests
//  120. CloseWithApplicationErrorAsync routed through transport  4 tests
//  121. BuildInitialFlight's sent-packet list dropped        2 tests
//  122. BuildAnswerDatagram's sent-packet list dropped       3 tests
//  123. the CONNECTION_CLOSE send's list dropped             ONLY TheConnectionClosePacketIsRetainedLikeAnyOther
//  124. the packet never added to its space                  15 tests
//  125. ACK-only packets counted toward bytes in flight      5 tests
//  126. bytes in flight gated on IsAckEliciting              2 tests
//  127. the retention cap removed                            ONLY RetentionIsCappedPerSpaceAndTheOldestPacketIsTheOneDropped
//  128. the cap drops the newest, not the oldest             ONLY RetentionIsCappedPerSpaceAndTheOldestPacketIsTheOneDropped
//  129. acknowledgement never removes anything               ONLY AnAcknowledgedApplicationPacketLeavesTheListAndItsBytesLeaveTheCount
//  130. removal walks forwards over a shrinking list         2 tests
//  131. s19.3.1 range membership made exclusive              7 tests
//  132. the decoded-range scratch never cleared              ONLY RangesFromAnEarlierAckDoNotLeakIntoTheNext
//  133. TryGetRanges' verdict ignored                        [SURVIVED] 0 of 2120 - VACUOUS, proved below
//  134. removal acts on ACKs the tracker rejected            [SURVIVED] 0 of 2120 - VACUOUS, proved below
//  135. key discard leaves the space populated               3 tests
//  136. key discard clears without returning bytes           3 tests
//  137. Forget removes without returning the bytes           8 tests
//  138. SpaceOf swaps Initial and Handshake                  [SURVIVED] 0 of 2120 - VACUOUS, proved below
//  139. 0-RTT given Handshake's space                        ONLY AZeroRttPacketAndAOneRttPacketShareOneSpace
//  140. removal ignores the ACK's own space                  3 tests
//  141. the loss timer never enters the deadline race    4 tests
//  142. the loss timer wins even when it is LATER        2 tests, both TheNearerAbandonmentDeadlineStillBoundsTheReceiveWhenTheProbeIsLater
//  143. the idle deadline stops entering the race        [WAS-SURVIVOR] -> now ONLY TheNearerAbandonmentDeadlineStillBoundsTheReceiveWhenTheProbeIsLater(idleIsNearer: True)
//  144. a recovery wake abandons like any other deadline  4 tests
//  145. nothing abandons in the catch at all             [SURVIVED] 0 of 2241 - VACUOUS, proved below
//  146. the post-wake abandonment check skipped after a recovery wake  ONLY ADroppedInitialEndsTheAttemptOnTheHandshakeDeadlineRatherThanRecovering
//  147. A.9 never runs on a recovery wake                4 tests
//  148. A.8 rung 3 drops PeerCompletedAddressValidation  2 tests, both AClientWithNothingInFlightStillArmsThePtoFromTheCurrentTime
//  149. A.8 rung 3 drops the in-flight half             ONLY ThePeersMaxAckDelayIsAddedForApplicationDataAndNotForHandshake
//  150. address validation forgets a confirmed handshake  ONLY AConfirmedHandshakeWithNothingInFlightCancelsTheTimer
//  151. address validation forgets the Handshake ACK     [SURVIVED] 0 of 2241 - unwitnessed, proved below
//  152. A.8's infinite pto_timeout armed, not cancelled  ONLY AnApplicationDataOnlyFlightBeforeConfirmationLeavesTheTimerUnarmed
//  153. the kGranularity floor on the armed INSTANT gone  2 tests
//  154. HasAckElicitingPacketsInFlight reads either flag  ONLY AClientWithNothingInFlightStillArmsThePtoFromTheCurrentTime(inFlight: True)
//  155. the Application Data skip before confirmation gone  ONLY AnApplicationDataOnlyFlightBeforeConfirmationLeavesTheTimerUnarmed
//  156. max_ack_delay not added for Application Data     ONLY ThePeersMaxAckDelayIsAddedForApplicationDataAndNotForHandshake
//  157. the anti-deadlock PTO measured from the send      2 tests, both AClientWithNothingInFlightStillArmsThePtoFromTheCurrentTime
//  158. time_of_last_ack_eliciting takes the FIRST send   ONLY TheTimerMeasuresFromTheLatestAckElicitingSendInASpace
//  159. the space is always Initial, not the minimum's    3 tests
//  160. 4 * rttvar loses its kGranularity floor          [WAS-SURVIVOR] -> now ONLY TheFourRttvarTermIsFlooredAtTheTimerGranularityAndTheFlooredValueIsWhatIsArmed
//  161. the PTO PERIOD's kGranularity floor removed      [SURVIVED] 0 of 2241 - VACUOUS, proved below
//  162. the PtoBackoff ceiling ignored                   3 tests
//  163. the backoff never grows: 2 ^ pto_count is 1       2 tests
//  164. A.9 never increments pto_count                   3 tests
//  165. the timer is never armed on a send              17 tests
//  166. no re-arm when a key discard clears a space      [SURVIVED] 0 of 2241 - unwitnessed, proved below
//  167. s6.2.1's exception dropped: any ACK resets       ONLY AnAcknowledgementInAnInitialPacketDoesNotResetThePtoBackoff
//  168. A.7's newly-acked guard dropped                  [WAS-SURVIVOR] -> now ONLY ADuplicateAcknowledgementDoesNotResetAPtoBackoffEarnedAfterIt
//  169. the peer's max_ack_delay read as zero            ONLY ThePeersMaxAckDelayIsAddedForApplicationDataAndNotForHandshake
//  170. SpaceOf un-collapsed, with 0-RTT in Handshake's slot  2 tests
//
//  171. A.7's DetectAndRemoveLostPackets call deleted   14 tests
//  172. A.7 detects in the Initial space, not the ACK's  11 tests
//  173. A.8's rung 1 deleted                            ONLY ALossTimerSuppressesThePtoTimerRatherThanRacingIt
//  174. A.8's rung 1 falls through, arming a PTO too    ONLY the same
//  175. A.9's rung 1 deleted                            ONLY the same
//  176. A.9's rung 1 does not return, so a loss wake backs off  ONLY the same
//  177. A.9's anti-deadlock condition inverted          8 tests
//  178. s8.1's anti-deadlock probe sends knob 10's count  ONLY APtoWithNoHandshakeKeysSendsAnInitialPacketOfAtLeastTwelveHundredBytes
//  179. knob 10 ignored: every PTO sends one datagram   7 tests
//  180. the debt is owed for zero datagrams             12 tests
//  181. the probe debt is never cleared                 ONLY APtoWithHandshakeKeysSendsAHandshakePacket
//  182. s6.2.4's ack-eliciting MUST broken: PING to PADDING  2 tests
//  183. the probe is always built at Initial            5 tests
//  184. knob 11 ignored: PingWithPadding never pads     ONLY TheProbesContentsFollowKnobElevenRatherThanAConstant
//  185. s12.3's packet number not advanced between probes  ONLY ProbePacketsPerPtoDecidesHowManyDatagramsLeaveOnOneExpiry
//  186. the probe is not retained, so A.1 never re-arms  3 tests
//  187. only the first probe datagram of an expiry sent  7 tests
//  188. the pump never discharges the probe debt        12 tests
//  189. knob 1 ignored: the initial RTT is kInitialRtt  ONLY TheFirstPtoIsArmedFromTheSpecsInitialRttRangeAndOnlyFallsBackToKInitialRtt
//  190. s6.2.2's key discard leaves loss_time armed     [SURVIVED] 0 of 2282 - unwitnessed, proved below
//  191. the probe padder's send-buffer clamp removed    ONLY AProbePaddedToTheLargestTargetTheSpecAcceptsStillFitsTheSendBuffer
//
// ROWS 171-191 ARE TASK A3-7's - the probe timeout, s8.1's anti-deadlock probe, and the three
// call lines A3-6 could not write. 21 rows, 20 KILLED and 1 SURVIVED. 20 + 1 = 21, which is the
// row count above and the length of the harness's own list for this file; the sweep's other two
// rows are TlsQuicLossDetection.cs's 225 and 226, carried in that file's ledger, for 23 in all.
//
// GATE, MEASURED AT PRISTINE HEAD RATHER THAN INHERITED. A private worktree detached at 2d805be
// - this task's pristine HEAD - carrying ONLY this file, TlsQuicLossDetection.cs and their
// tests, so no other agent's uncommitted work in the shared tree could account for a verdict.
// `dotnet test --filter "FullyQualifiedName~Quic"`: 2258 passed / 0 failed / 5 skipped = 2263
// total BEFORE, and 2277 / 0 / 5 = 2282 AFTER. 2263 + 19 = 2282, and 19 is exactly A3-7's own
// case count - 11 [Fact] methods plus four [Theory] methods contributing 2 rows each, and
// 11 + 8 = 19. NO EXISTING CASE MOVED, which is a stronger statement here than usual, because
// SIXTEEN EXISTING CASES WENT RED IN THE FIRST RUN and were repaired rather than deleted.
//
// THE BRIEF'S WARNING ABOUT MASKING HAPPENED, LOUDLY, AND IN BOTH DIRECTIONS. Wiring A.10 into
// A.7 meant every direct-half test in the loss detection tests file was calling
// detection on a set the live path had already emptied; adding a probe to every expiry moved the
// instant A3-5's backoff tests measure from, because A.3's time_of_last_ack_eliciting_packet is
// now the PROBE's send rather than StartAsync's flight. Both classes of failure are the feature
// being right, and neither was silent. Every repaired assertion is STRICTLY STRONGER than the
// one it replaced: the loss tests now observe a pass the production receive path ran, and the
// backoff tests now name the probe's instant AND assert the old base is no longer the answer.
//
// VERDICTS ARE ASSIGNED STRUCTURALLY. The harness branches on the BUILD's exit code before any
// test process starts, so a compile failure can only ever produce KILLED-BY-COMPILER and can
// never be published as a kill against a named test. `if (false)` is never written - CS0162 is
// an error in this tree - and `COND && false` is used where a branch has to be disabled; rows
// 173, 175 and 184 are that form, and rows 180 and 187 scale a count instead, because a disabled
// branch there would have made the code after it unreachable and scored as a compiler kill.
//
// EVERY SCORED RUN REPORTED ITS RUN'S OWN TOTAL against a floor of 2270 the harness checks
// before it scores anything; a run under the floor aborts rather than publishing a figure
// counted against a different suite. Every row also asserts its anchor occurs EXACTLY once and
// that the rewritten file differs from the original - checked for all 23 rows in a pre-flight
// pass before the first build - so a mutation that matched nothing cannot reach a verdict.
//
// THE HARNESS WAS CALIBRATED IN BOTH DIRECTIONS, IN BOTH RUNS. Row 900 - pristine source, no
// mutation - returns SURVIVED with 0 failed. Row 901 - `LossDetectionTimeouts++` becomes
// `+= 2`, which compiles and changes behaviour - returns KILLED with 6 failed. Neither is
// counted above. The control is deliberately NOT of the `if (true) { return; }` shape A3-6's
// first attempt used: that came back KILLED-BY-COMPILER, and a control the compiler rejects
// proves nothing at all about the tests.
//
// TWO RUNS, AND THE SECOND IS WHY THE FIRST STILL STANDS. Rows 171-190 and 225-226 were scored
// at a source differing from HEAD by exactly one production line - the send-buffer clamp in
// TryBuildProbeDatagram - and its two witnessing cases, at a gate of 2281. Adding a line and two
// cases can only ADD failures to a mutant, so a KILLED there is a KILLED here. What it CAN
// change is a SURVIVOR, so both survivors were re-scored against the final source at 2282,
// together with the clamp's own row 191: 181 became a kill and 190 did not.
//
//   181 WAS A REAL GAP AND THE SWEEP IS WHAT FOUND IT. Leaving _owedProbe standing after the
//   send makes every LATER pump emit another probe with no timer having fired, and nothing
//   caught it: a pump that follows a first expiry in this suite either has an expiry of its own
//   - so the counts coincide - or has just discarded the Initial keys the stale debt names, so
//   TryBuildProbeDatagram returns false and the extra probe silently does not happen.
//   APtoWithHandshakeKeysSendsAHandshakePacket now asserts OwedProbe is null, ON THE STATE
//   RATHER THAN ON A SECOND PUMP, and that choice is a measurement: a second pump there has
//   nothing to receive and is ended by the test's own token a wall-clock minute later, which
//   fails for the wrong reason and costs a sweep a minute per mutant.
//
//   190 IS UNWITNESSED AND THE MISSING STATE IS NAMEABLE - IT IS ROW 166's, ONE LAYER DOWN.
//   s6.2.2's MUST is that BOTH timers are reset on a key discard, and A3-7 added the loss_time
//   half of it in ForgetSpace. Separating it from the SetLossDetectionTimer call beside it needs
//   a space with a PENDING loss_time whose keys are then discarded with no send after - and row
//   166 already records why this suite cannot reach that: "every discard in this suite is
//   immediately followed by a send". Reaching it from a test would mean a new internal door onto
//   ApplyDiscards or ForgetSpace, both private, which is a test-only seam onto a private path
//   and is a worse trade than the row. IT CANNOT HANG, and that is arithmetic rather than hope:
//   A.10 clears loss_time[space] before its loop, and the one path that returns before doing so
//   is the largest_acked check - which cannot be null in a space that HAS a loss_time, because
//   A.10 is the only writer of loss_time and writes it below that check. So a stale entry costs
//   exactly one wake and then clears itself. The line stays: deleting an implementation of a
//   MUST to score a row is the wrong trade.
//
// ROWS 141-170 ARE TASK A3-5's - the timer weave - run against a 2241-CASE gate: the 2223 this
// task inherited in the working tree plus the 18 witnesses it adds. 24 KILLED, 6 SURVIVED, and
// every run reported 2241 total, which the sweep checks before scoring anything; a run that
// misses the floor is retried once and a second miss aborts the sweep rather than publishing a
// figure counted against a different suite.
//
// THE FIRST SWEEP WAS THROWN AWAY BECAUSE ITS KNOWN-BAD CONTROL SURVIVED, AND THAT SURVIVAL IS
// THE MOST USEFUL THING THIS TASK MEASURED. The control dropped RFC 9000 s10.1's idle timeout
// out of EarliestDeadline's table and expected APeerThatGoesSilentIsBoundedByTheIdleTimeoutToo
// to go red. IT STAYED GREEN, and the reason is this task's own doing: that test runs on the
// real clock with a 250 ms idle bound against a 30-second handshake deadline, and A3-5 arms a
// probe timeout at about ONE SECOND off the Initial flight StartAsync sends - so with the idle
// entry gone the receive was still ended, at one second instead of at 250 milliseconds, by the
// recovery timer, and that test's "under ten seconds" assertion cannot tell the two apart. THE
// NEW TIMER WAS MASKING THE ENTRY THE OLD ROW WITNESSED. Nothing behaved wrongly - the check
// after the receive re-reads both abandonment deadlines and abandons either way - but ledger row
// 69 stopped being witnessed by the test it names, and an entry nothing witnesses is one a later
// task deletes.
//
//   WHAT WAS DONE ABOUT IT. TheNearerAbandonmentDeadlineStillBoundsTheReceiveWhenTheProbeIsLater
//   was written, as two rows: an abandonment deadline NEARER than the probe timeout, on a fake
//   clock advanced past it and no further, so a dropped entry arms the receive at an instant
//   that never arrives and the pump is caught by the wrong exception rather than by a number.
//   Its outer token is FIVE seconds rather than sixty, because a mutant that blocks must fail
//   QUICKLY - a sweep that spends a minute per blocked mutant is a sweep that gets abandoned,
//   and row 141 still cost 230 seconds against 50 for every other row. Row 143 is that same
//   mutation re-run in the scored sweep, and it is now a kill.
//
//   THE CONTROL WAS THEN REPLACED with one whose kill does not depend on any table entry at all,
//   and the harness was re-proved in both directions before a row was scored: known-bad ->
//   KILLED (3 failed of 2241), inert comment -> SURVIVED (0 failed of 2241). Both directions
//   were re-proved a second time in the short re-run that scored row 165, whose first anchor
//   matched nothing - ANCHOR-MISS is reported as its own verdict rather than folded into
//   SURVIVED, which is the same defect class as the verdict regex this file's rows 121-140
//   record: a mutation that never applied must not be published as a mutation that survived.
//
// ROW 69 IS THEREFORE AMENDED RATHER THAN LEFT STANDING. Its text - "the idle deadline does not
// bound the receive [WAS-SURVIVOR] -> now ONLY APeerThatGoesSilentIsBoundedByTheIdleTimeoutToo"
// - was true when it was written and is no longer the whole truth: that test alone no longer
// kills it, and row 143's witness is what does. The same reading applies to row 13, whose
// mutation "the deadline stops bounding the await" now has to be expressed as an edit to
// EarliestDeadline rather than to a two-way minimum.
//
// ROW 138 CANNOT BE RE-RUN IN THIS FILE AND THAT IS THIS TASK'S DOING. It mutated
// TlsQuicConnection.SpaceOf's private array indices; A3-4 widened TlsQuicAckTracker.SpaceOf to
// internal, this task collapsed the copy into a forward, and there are no longer any indices
// here to permute. The row's classification is not lost - TlsQuicAckTracker.cs's ledger row 43
// carries the identical vacuity proof for the mapping's one remaining definition. ROW 139's
// control moved with it: row 170 puts a local copy BACK with 0-RTT given Handshake's slot, which
// is the same edit row 139 scored, and it is killed by the same test.
//
// THE SIX SURVIVORS, EACH CLASSIFIED RATHER THAN LISTED. Two are vacuous with a proof that is
// checkable by reading; four are unwitnessed, and each names the state that would witness it.
//
//   145 IS VACUOUS BECAUSE THE CHECK AFTER THE RECEIVE RE-DERIVES THE SAME VERDICT. The mutation
//   removes the `if (!isRecovery) throw AbandonAsync(...)` from the catch, so every timer wake
//   falls through. It cannot be observed, and the argument is arithmetic rather than empirical:
//   the source is armed at exactly `EarliestDeadline().At - now`, so when it fires the clock has
//   reached that instant, and if the winning entry was the handshake deadline or the idle
//   timeout then RemainingBeforeDeadline() or RemainingBeforeIdleTimeout() is non-positive and
//   the very next statement abandons. THE GUARD IS BELT AND BRACES TODAY AND IS KEPT ANYWAY, for
//   the reason rows 133 and 134 are kept: it stops being equivalent the moment a TimeProvider
//   exists whose timer fires without its clock reading having moved. ONE SUCH PROVIDER USED TO
//   EXIST HERE - AbandonAsync's own remark still described it before this task corrected it -
//   and A3-1 removed it by overriding CreateTimer.
//
//   161 IS VACUOUS BECAUSE THE INSTANT FLOOR DOMINATES THE PERIOD FLOOR. PtoDuration's closing
//   `scaled < KGranularity ? KGranularity : scaled` can only matter when the period is under a
//   millisecond, and SetLossDetectionTimer then floors the armed INSTANT at now + kGranularity.
//   Every send instant is at or before now, so `sentAt + period` with a sub-granularity period
//   is strictly before now + kGranularity and the instant floor raises it; the anti-deadlock arm
//   computes now + period and is dominated for the same reason. ROW 153 IS THE CONTROL THAT
//   MAKES THIS A CLASSIFICATION AND NOT AN EXCUSE: it removes the dominating floor and is
//   killed. The period floor is kept because it is where s6.2.1's MUST is about - the PERIOD -
//   and because s6.2.1's floor is a MUST about the period however the period is reached.
//
//   THE SECOND HALF OF THAT SENTENCE WAS WRONG AND A3-7 CORRECTS IT RATHER THAN LEAVING IT.
//   It read "and because A3-6 reads PtoDuration for s6.1.2's time threshold, where no instant
//   floor runs." A3-6 does not read PtoDuration at all: s6.1.2's threshold is
//   `max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)`, which has no rttvar
//   term and no backoff, and A3-6 gave it its own LossDelay in TlsQuicLossDetection.cs. A3-6's
//   header found this and said so; this line is the one it could not edit.
//
//   160 IS NO LONGER UNWITNESSED. [WAS-SURVIVOR] -> now ONLY TlsQuicConnectionTests.TheFour
//   RttvarTermIsFlooredAtTheTimerGranularityAndTheFlooredValueIsWhatIsArmed. The row named the
//   missing state exactly - "`max(4 * rttvar, kGranularity)` and `4 * rttvar` differ only when
//   4 * rttvar is under a millisecond AND smoothed_rtt is over one" - and then predicted A3-6
//   would supply it, which A3-6 disproved. A3-7 supplies it, and the path is arithmetic rather
//   than luck: A.7's `rttvar = 3/4 * rttvar + 1/4 * abs(smoothed_rtt - adjusted_rtt)` decays
//   rttvar by three quarters per IDENTICAL sample while smoothed_rtt sits still, so twenty-five
//   samples of 40 ms take rttvar from 20 ms to about 15 microseconds. Both candidate periods
//   are asserted, not merely their difference.
//
//   151 IS UNWITNESSED BECAUSE THE TWO DISJUNCTS COINCIDE WHEREVER THE SUITE REACHES RUNG 3.
//   PeerCompletedAddressValidation is "has received Handshake ACK || handshake confirmed", and
//   the only test that reaches A.8's rung 3 with it true is
//   AConfirmedHandshakeWithNothingInFlightCancelsTheTimer, where BOTH hold. Separating them
//   needs a peer that acknowledges the client's Handshake flight and then says nothing further,
//   and LoopbackQuicPeer's next act is always HANDSHAKE_DONE. Row 150 is the same mutation on
//   the other disjunct and IS killed, so the member is not unwitnessed - one of its two arms is.
//
//   166 IS UNWITNESSED AND THE WINDOW IS REAL RATHER THAN THEORETICAL. s6.2.2's MUST - "When
//   Initial or Handshake keys are discarded, the PTO and loss detection timers MUST be reset" -
//   is the only one of s6.2.1's three arming triggers stated as a MUST, and dropping the re-arm
//   in ForgetSpace leaves the timer pointing at a send in a space whose retained packets have
//   just been cleared. It survives because every discard in this suite is immediately followed
//   by a send, and OnPacketSent re-arms - so the stale window closes before anything can look
//   into it. Witnessing it needs a discard with no send after it, which is A3-6's or A3-7's
//   shape and not one this task can reach.
//
//   168 WAS UNWITNESSED AND A3-7 WITNESSED IT, AND THE ROW'S OWN DIAGNOSIS WAS HALF WRONG.
//   A.7 gates its pto_count reset behind `if (newly_acked_packets.empty()): return`, and without
//   it a DUPLICATE ACK - one naming only packets already retired - resets a backoff consecutive
//   PTOs earned. The row said reaching that "needs a confirmed handshake": IT DOES NOT. What it
//   needs is any acknowledgement that makes PeerCompletedAddressValidation true, and A.8 makes
//   a Handshake-space ACK one of those on its own - "return has received Handshake ACK ||
//   handshake confirmed". So the state is: validate the address, earn a backoff, then deliver
//   the SAME frame again. ADuplicateAcknowledgementDoesNotResetAPtoBackoffEarnedAfterIt is that
//   sequence, and it asserts PacketsDeclaredLost has not moved either - because A3-7 put A.10
//   behind the same guard, so a dropped guard now runs loss detection on a duplicate ACK too.
//
// A NOTE ON THE FILE-SIZE RULE, MEASURED RATHER THAN ARGUED. A4's plan set this file's cap at
// "1000 code lines through task 14", measured with `grep -vcE '^\s*(//|$)'`. It read 962 when
// that was written, 1133 at A3-5's HEAD - A3-3 carried it past the cap without recording that it
// had - and 1306 after this task. THE CAP IS NOW 31% OVER AND WAS 13% OVER BEFORE THIS TASK
// TOUCHED IT. A4's own plan says what to do about that and it is not this: "Whoever wants it
// should take it as its own task with its own sweep, not as a side effect of a size complaint."
// The partial-class precedent TlsQuicApplicationSendPath.cs set is the obvious shape for it.
// Recorded here so the number is a measurement in the tree rather than something a later reader
// rediscovers.
//
//   A3-7 RE-MEASURED IT AND DID NOT ATTEMPT THE SPLIT, per A4's own instruction above: 1404 code
//   lines by the same `grep -vcE '^\s*(//|$)'`, which is 40% over the 1000-line cap, from 1306
//   before. The 98 lines are A.9's two send rungs, the probe builder and the three call lines
//   A3-6 could not write; TlsQuicLossDetection.cs shows what the split would look like and A3-6
//   already took the loss half of this file into it.
//
//   A3-11 RE-MEASURED IT AGAIN AND ALSO DID NOT SPLIT, AND THE RE-MEASUREMENT IS THE POINT.
//   A3-8 landed between A3-7's count and this one without re-measuring, so the figure 1404 was
//   inherited by every task after it and was wrong for all of them: at pristine ebdcc89 the same
//   `grep -vcE '^\s*(//|$)'` returns 1443. A3-11 adds 17 - EarliestDeadline's fourth entry, the
//   deadline kind it needed, and the branch on it in ReceiveWithinDeadlineAsync - for 1460, 46%
//   over the cap. THE LESSON IS THE ONE A3-7 WROTE DOWN AND THE NEXT TASK STILL HAS TO OBEY:
//   re-measure rather than quote, because the number is quoted in briefs and a stale one is
//   indistinguishable from a fresh one. Everything else this task added went into
//   TlsQuicApplicationSendPath.cs (85 code lines to 126) and TlsQuicCongestionControl.cs, both
//   of which are far under the cap, which is where the send gate and the pacer belong anyway.
//
// ============================================================================
// s6.2's PROSE AGAINST A.8 AND A.9, READ AGAINST EACH OTHER RATHER THAN EITHER ALONE - A3-7.
// ============================================================================
//
// A3-4, A3-5 and A3-6 each found a place where RFC 9002's prose and its appendix disagree, and
// the standing instruction is not to trust A3-0's "line-by-line transcribable". THREE MORE ARE
// HERE, and where they disagree the choice is named at the line and pinned by a test.
//
//   A.8's GetLossTimeAndSpace IS WRONG AS PRINTED, AND IT IS THE ONE THAT WOULD HAVE HUNG.
//   rfc9002-appendix-a-and-b-pseudocode-and-constants.txt prints
//   "for pn_space in [ Handshake, ApplicationData ]: if (time == 0 || loss_time[pn_space] <
//   time)" - with NO test that loss_time[pn_space] is itself non-zero. So a space with nothing
//   pending compares 0 < time and WINS the minimum against a space that really has one, and
//   A.8's rung 1 then arms the timer at zero, which in C# is DateTimeOffset.MinValue: a timer
//   permanently in the past, floored to now + kGranularity, firing for ever against a space
//   with nothing to declare. A3-6's own header quotes the ERRATA-CORRECTED form, which is not
//   what the extract prints, and implemented that; A3-7's rung 1 is what made the difference
//   observable. ALossTimerSuppressesThePtoTimerRatherThanRacingIt is the pin: it puts a
//   loss_time in Handshake and none in Initial or Application, which is exactly the state the
//   printed form gets wrong, and asserts BOTH the instant and the space.
//
//   A.9's `assert(!lost_packets.empty())` CANNOT BE TRANSCRIBED, and it is the same class of
//   defect A3-5 found in A.8's `pto_timeout = infinite`. A.8 arms rung 1 from loss_time, and
//   between the arming and the firing an acknowledgement can retire the very packet that
//   loss_time was computed for - OnAckReceived re-runs A.10, which rebuilds loss_time - while
//   the wake that was already armed still happens. The assert would kill a healthy connection
//   for an event whose meaning is "nothing left to lose". It is a no-op here; see
//   OnLossDetectionTimeout.
//
//   A.9's pto_count++ IS INSIDE ITS PROBE ARM AND A3-5's WAS NOT, and s6.2's prose settles it
//   from the other side: "A PTO timer expiration event does not indicate packet loss and MUST
//   NOT cause prior unacknowledged packets to be marked as lost." The two arms are different
//   events sharing one timer - the loss arm declares and does not back off, the PTO arm backs
//   off and declares nothing - and A.9 gets that from a `return` A3-5 had no rung 1 to write.
//   Rows 174 and 176 are the two directions of losing it.
//
//   AND ONE PLACE THEY AGREE THAT IS EASY TO MISS. s6.2.1's "The PTO timer MUST NOT be set if a
//   timer is set for time threshold loss detection" is not a separate rule to add: it IS A.8's
//   rung-1 return. Falling through to rung 4 after arming from loss_time is that MUST NOT
//   verbatim, which is row 174.
//
// ROWS 133, 134 AND 138 ARE A3-3's THREE SURVIVORS, AND ALL THREE ARE VACUOUS - equivalent
// mutations rather than gaps in the tests. Each proof is a statement about the code, so each
// is checkable by reading rather than by running anything.
//
//   133 AND 134 ARE ONE FACT TWICE. Row 133 drops OnAckReceived's `if (!TryGetRanges) return`;
//   row 134 drops the `else` that gates the call on TlsQuicAckTracker.ProcessAckFrame having
//   accepted the frame. Both are equivalent TODAY because two things are true together:
//   ProcessAckFrame returns false ONLY when TlsQuicAckFrames.TryGetRanges does - it has no
//   other rejection - and TryGetRanges' RollBack "removes only what this call added".
//   OnAckReceived clears its list before every walk, so `added` is zero and a rejected frame
//   leaves that list EMPTY. The removal loop then iterates an empty range set and retires
//   nothing, which is exactly what the guarded code does. No test can separate them.
//
//   WHY BOTH LINES STAY ANYWAY, AND IT IS NOT SENTIMENT: A3-4 adds RFC 9000 s13.1's refusal of
//   an ACK naming a packet that was never sent. That is a SEMANTIC rejection rather than a walk
//   failure, so the day it lands ProcessAckFrame gains a false that TryGetRanges does not
//   share, both mutations stop being equivalent, and the `else` becomes the only thing keeping
//   a refused ACK from retiring packets. Deleting them now to score two more kills would be
//   removing a guard exactly one task before it starts mattering.
//
//   138 IS A CONSISTENT BIJECTIVE RELABELLING, and the sibling ledger already carries this
//   exact row: TlsQuicAckTracker.cs's mutation 43, in its own words - "Both are private array
//   indices, and the swap is a consistent bijective relabelling - every write and every read
//   moves together, so no caller can observe it." The three slots of _sentPackets are
//   anonymous and every access goes through SpaceOf, so permuting two of them is invisible.
//   ROW 139 IS THE CONTROL THAT MAKES THIS A CLASSIFICATION AND NOT AN EXCUSE: giving 0-RTT
//   Handshake's slot is NOT a relabelling - it breaks s12.3's requirement that 0-RTT and 1-RTT
//   share ONE space - and it is killed. That tracker's ledger draws the same distinction
//   between its rows 43 and 40; the pair was reached independently here.
//
// ROWS 98 AND 99 ARE TASK 14e's WHOLE FOOTPRINT IN THIS FILE - eight code lines, 974 to 982 of
// the 1000-line cap - and they are two rows rather than one because they fail in opposite
// directions. Row 98 makes every STREAM frame vanish: the bytes never reach a stream and the
// hostile ones never reach a check. Row 99 keeps the checks and drops the CONSEQUENCE, which is
// the more dangerous of the two, because a connection that has decided the peer violated RFC
// 9000 s19.8 and then carries on is exactly the state the refusal exists to end. The rest of
// the task is in TlsQuicStreams.cs's own ledger, rows 1-42.
//
// ROW 94 IS THE ORDERING ROW AND IT IS NOT HYPOTHETICAL: the s6.2 check was FIRST WRITTEN
// above the s7.3 call, both of those tests went red, and the two witnesses that had been about
// s7.3 became witnesses about s6.2 instead. That is the plan's "a test that exercises two
// checks pins only whichever fires first" happening in the direction that HIDES a check rather
// than reports it - the s7.3 witnesses would have kept passing on a connection that no longer
// authenticated connection IDs at all, because refusing for the other reason still throws.
// The row is the mutation that puts the order back.
//
// ROW 93 IS COARSE ON PURPOSE and its 40 is not evidence of anything: a budget built from an
// empty parameter set advertises no unidirectional streams, so every handshake in the suite is
// refused. The rows that say something about retention are TlsQuicPeerFlowControlBudget.cs's
// 1-7, which kill their own witness and no other's.
//
// ROW 3 IS THE ONE THAT MATTERED, and it is the only row here that found a defect in prose
// rather than in a guard. This file's install/send/discard remark claimed the ordering was
// load-bearing because "the completion result carries our Finished at the Handshake level,
// and applying its discard first would leave nothing to protect it with." That describes
// CustomTlsQuicServer, which does raise a discard from ProcessCryptoDataAsync (:154), and NOT
// CustomTlsQuicClient, whose only two sources are NotifyHandshakePacketSent (:327) and
// ConfirmHandshake (:347). So the loop had nothing to apply, applying it early changed
// nothing, and the comment was describing a mechanism that was not there. The apply is now a
// CHECK on that assumption (row 31), and the remark says what actually makes the order
// load-bearing - which is s4.9.1's SEND trigger, not the results.
//
// ROWS 9, 10 AND 11 WERE THE THREE-DISJUNCT GUARD, AND THE RIGHT READING OF THEIR SURVIVAL
// WAS NOT THE ONE THIS LEDGER FIRST GAVE. It said they were unreachable as sole cause and
// worth keeping for A3. They were worse than that: `Discarded > 0` threw on input that had
// NOT AUTHENTICATED - the AEAD and header-protection failures both increment it - so the
// guard handed any off-path observer a way to end the connection by replaying one of our own
// datagrams back at us, with no key material at all. RFC 9000 s12.2 requires the opposite
// ("MUST attempt to process the remaining packets"), TlsQuicPacketReceiver's contract said so
// too, and BuildAnswerDatagram argued the same rule 280 lines below while this guard did the
// reverse. THE MUTATIONS DID NOT FIND THIS; A REVIEWER READING WHAT `Discarded` MEANS DID -
// which is the honest lesson of the row. The guard is gone; the counters that replaced it are
// rows 40-42, and the replay is witnessed by AReplayOfThisConnectionsOwnDatagramDoesNotKillIt.
//
// ROW 23 WAS CLASSIFIED AS A3'S DEBT AND IT WAS A4-MINIMAL'S. The ledger said reaching it
// needed "a peer acknowledging a packet number far behind, which no test here builds", and
// concluded A3 owed the witness because A3 is what makes the distance grow. Both halves were
// wrong: the distance is `full_pn - largest_acked`, and InitialPacketNumber - a knob task
// 9a-ii itself wired - sets `full_pn` directly. Spec { InitialPacketNumber = 127,
// PacketNumberEncodedLength = 1 } plus a scripted ACK of 127 makes the real code want 1 byte
// (num_unacked = 1) and the mutant want 2 (num_unacked = 129, which trips
// TlsQuicPacketNumber.EncodedLength's non-power-of-two bump at an 8-bit boundary), and the
// second is wider than the spec permits. NO A3 MACHINERY IS INVOLVED. An argument about
// reachability is worth less than forty lines of test; this row is the proof.
//
// ROW 25 IS THE HAZARD THIS FILE CANNOT SEE, and it is task 7's row 18 one layer up. Pooling
// the receive buffer is a real defect - a retained alias becomes a read of the next datagram -
// and it survives because of a TIMING accident: each pump consumes its datagram's CRYPTO
// chunks, which are copied out, before any later receive can refill anything. A test written
// today would have to introduce the buffering it warns about and would then be testing its own
// scaffold. Recorded rather than given a test that would not be one.
//
// ROWS 33, 34 AND 36 ARE WHAT THE FIRST SWEEP DID NOT THINK TO MUTATE, and all three were
// hardcoded behaviour rather than a guard, which is why a sweep aimed at guards missed them.
// Two were layout decisions the plan's design constraints forbid as literals - the coalescing
// order and the ACK's position inside a packet - and the second was declared ungrounded in a
// comment and then fixed anyway, which is the accepted-and-ignored defect with an extra step.
// Both are now knobs on TlsQuicConnectionSpec. The third, s7.2's "only the first received
// Initial or Retry packet", was a MUST implemented correctly and never measured. THE LESSON
// FOR THE NEXT LEDGER: mutate the choices, not only the checks.
//
// ROW 45 IS THE ONE SURVIVOR HERE THAT NO TEST IN THIS TREE CAN REACH, and the reason is a
// design constraint rather than an accident. CloseError is set by exactly two things - a frame
// that does not decode, and a frame RFC 9000 s12.4 Table 3 forbids at its level - and the
// plan requires TlsQuicFrameLegality.Permits to gate every frame ON THE SEND PATH too, so
// TlsQuicPacketBuilder refuses to build either packet. A witness would have to hand-roll a
// second packet writer, which this phase bans by name. Attempted and abandoned, rather than
// assumed: the test was written, and it failed with the builder's own ArgumentException.
//
// ROWS 43, 44 AND 46 ARE THE THREE WHERE THE FIX IS STILL RIGHT AND THE MUTATION IS STILL
// GREEN, which is a combination worth naming rather than hiding. 43 sets `_confirmed` after
// ConfirmHandshake instead of before; the old order could report RFC 9001 s4.1.2's confirmed
// state with the Handshake keys still installed, but only if ConfirmHandshake throws, which
// the packet layer makes unreachable - see ConfirmIfHandshakeDoneArrived. 44 checks that the
// datagram reader's slice and this loop's window are the same bytes; the arithmetic is
// correct, so a test would have to introduce the drift it detects. 46 moves the s4.9.1 discard
// to between the build and the send; the bytes are identical and there is no window, so it is
// VACUOUS and gets no test - the ordering that is load-bearing is the one against the BUILD,
// and that one has a witness.
//
// ROWS 47-85 ARE TASK 9B'S, run against the 1104-test gate in a worktree. Every row is a
// deletion or a neutering of ONE check, restored before the next; a neutered branch is written
// against a `Mutant()` helper rather than `false`, because this repo builds CS0162 (unreachable
// code) as an error and a mutation that does not compile measures nothing.
//
// ROW 82 IS THE ONE THAT MATTERED, AND IT WAS A SURVIVOR THAT TURNED OUT TO BE A DEFECT RATHER
// THAN A MISSING TEST. s7.3's initial_source_connection_id was first compared against the Source
// Connection ID this connection had OBSERVED on a packet the AEAD opened, and the sweep reported
// that swapping it for the connection ID we ADDRESS changed nothing: against any peer that
// behaves the two are the same bytes. s7.3's own sentences separate them - the parameter must
// match "the values that an endpoint used in the Destination and Source Connection ID fields of
// Initial packets that it sent", which after s7.2's adoption is the adopted value - and the
// purpose clause says which reading is meant: "Including connection ID values in transport
// parameters and verifying them ensures that an attacker cannot influence the choice of
// connection ID for a successful connection by injecting packets carrying attacker-chosen
// connection IDs during the handshake." Under the observed-value reading an injected first
// Initial moves the adoption, the parameter still agrees with the honest server's Source
// Connection ID, and THE CONNECTION SUCCEEDS WHILE ADDRESSING THE ATTACKER'S VALUE. The witness
// costs zero key material: a datagram sealed with RFC 9001 s5.2's CLIENT secret cannot open at a
// client, and s7.2's adoption necessarily runs before the AEAD.
//
// ROWS 69, 70 AND 65 WERE SURVIVORS OF THE FIRST RUN AND ARE KILLED NOW, each by a test written
// because the sweep said the check was unmeasured: the idle deadline bounding the receive (a
// peer that goes SILENT, which only a real timer reaches), the idle timer restarting on a
// processed packet (two replies fifty seconds apart against a sixty-second timeout), and the
// close going out at the HIGHEST level with keys (read off the protected packet, since RFC 9000
// s17.2's Long Packet Type bits sit above the four bits RFC 9001 s5.4.1 masks).
//
// TWO MUTANTS MEASURED SOMETHING OTHER THAN WHAT THEY NAMED, and both are recorded because the
// correction is the lesson. The first form of row 66 INVERTED the peer-close branch instead of
// deleting it, so every packet entered draining and 37 tests died - a number that says nothing
// about the check. And the first form of row 53 anchored on a line that appears TWICE, so it
// neutered StartAsync's Initial key installation rather than the Retry's re-derivation and
// killed 72. A mutation is only evidence when its anchor is unique and its edit is a deletion.
//
// ROW 71 IS THE ONE THAT MATTERED IN THE REVIEW FIX ROUND, AND ITS RECORDED REASON WAS FALSE.
// It was filed [SURVIVED] - unreachable by construction, because "this loop makes at most one
// ack-eliciting send per received packet, so the flag is never already set when a second send
// happens". That is not true and never was: StartAsync's opening flight (:693) and
// HandleRetryAsync's answer (:1453) are two ack-eliciting sends with no processed packet
// between them, because a Retry reaches no AEAD and therefore sets neither
// _processedServerPacket nor _idleSince. What actually made the guard unfireable was that
// StartAsync wrote _idleSince directly and never set _sentAckElicitingSinceReceive - so the
// flag was still false at the second send, and the guard it protects could not fire.
//
// THAT OMISSION WAS ITSELF A s10.1 DIVERGENCE, WHICH IS WHY THIS IS A FIX AND NOT A RECLASSING.
// s10.1's condition - "if no other ack-eliciting packets have been sent since last receiving and
// processing a packet" - is FALSE at the Retry answer, so the timer must not restart there; it
// did. Two contradictory readings of the same sentence each passed the whole gate: leaving the
// flag false, and setting it true, were both 1104/1104 green. Row 88 is the mutant that pins the
// reading now, and rows 71 and 88 share one killer because they are the two halves of one
// mechanism - the flag being SET, and the guard that READS it.
//
// A SURVIVOR WHOSE JUSTIFICATION IS FALSE IS WORSE THAN AN UNRECORDED ONE, because the next
// reader trusts it. A3 adds retransmission, which is a second ack-eliciting send in exactly this
// silence; without this round it would have inherited a flag whose initial state was wrong AND a
// ledger row saying the path could not be reached.
//
// ROW 89 IS A SURVIVOR AND THE REVIEWER'S REASON FOR IT COVERS ONLY HALF OF IT. The mutant makes
// an ACK-only answer datagram restart the idle timer, dropping s10.1's ack-eliciting condition.
// The reviewer called it vacuous on the ground that RestartIdleTimerOnAckElicitingSend is handed
// the same `now` that :972 already assigned to _idleSince - and for _idleSince that is exactly
// right, and it is airtight rather than probable: `written > 0` with no CRYPTO means the datagram
// carries an ACK, an ACK means something was processed in this pump, and processing is what runs
// :969. So the deadline cannot move. BUT THE CALL ALSO SETS _sentAckElicitingSinceReceive, from
// the false :973 left it at to true, and that is a real state difference. It is unobservable only
// because A4-minimal has no second ack-eliciting send between a processed packet and the next one
// - the Retry answer is the only candidate and a Retry after a processed packet is discarded, and
// CONNECTION_CLOSE is not ack-eliciting (s2). So: VACUOUS on the timer, UNREACHABLE BY
// CONSTRUCTION on the flag, and A3's retransmission is what makes it reachable. No test now.
//
// ROW 89 WAS RE-RUN AT TASK 14c AND ROW 90 IS THE HALF OF IT THAT TASK CREATED. 14c gave this
// connection a second ack-eliciting frame - PATH_RESPONSE - so the old condition
// `crypto.Count > 0` stopped meaning "this datagram is ack-eliciting" and started merely
// coinciding with it. The condition was replaced with TlsQuicPacketBuilder.IsAckEliciting over
// the frames actually going out, which is the same predicate TlsQuicAckTracker applies on the
// receive side. ROW 90 IS THE OLD CONDITION PUT BACK, AND IT SURVIVES: the one datagram that
// separates the two - the answer carrying an ACK and a PATH_RESPONSE and no CRYPTO - is built
// in a pump that has already processed a packet, so `now` has already been written to
// _idleSince and the deadline still cannot move, and _sentAckElicitingSinceReceive is still
// unobservable for want of a second ack-eliciting send. SO THE FIX IS NOT WITNESSED AND IS
// MADE ANYWAY, because the old line's own comment claimed CRYPTO was the only ack-eliciting
// frame this connection sends, and that claim became false. A condition that is right by
// coincidence is the shape row 71 was.
//
// A DELETION THAT DOES NOT COMPILE MEASURES NOTHING, AND THIS ROUND FOUND A SECOND FORM OF THAT.
// The plan already records CS0162 (unreachable code) killing `if (false)`. Row 71's mutant hits
// CS0414 instead: the guard is the field's only READ, so deleting it makes
// _sentAckElicitingSinceReceive write-only and warnings-as-errors fails the build. The mutant was
// re-run as `_ = _sentAckElicitingSinceReceive;` in place of the guard - the early return gone,
// which is the deletion's whole behaviour, with the read kept so the build stands.

/// <summary>One client QUIC connection attempt, from the first Initial packet to RFC 9001
/// s4.1.2's <i>handshake confirmed</i>.</summary>
/// <remarks>
/// <para>ONE LOOP, ONE THREAD OF CONTROL. A4 Finding 6:
/// <see cref="CustomTlsQuicClient"/>'s <c>StartHandshake</c>,
/// <c>NotifyHandshakePacketSent</c> and <c>ConfirmHandshake</c> mutate state without taking
/// the semaphore that guards <c>ProcessCryptoDataAsync</c>, and
/// <see cref="TlsQuicPacketReceiver"/> says the same thing about its own <c>_keys</c>,
/// <c>_largestReceived</c> and <c>_scratch</c>. Both requirements are satisfied by the same
/// single loop below: there is no send pump and no separate receive pump, and no method here
/// may be called from two threads.</para>
/// <para>ONE-SHOT, because <see cref="CustomTlsQuicClient"/> is: any exception latches its
/// <c>_failed</c> and poisons the instance permanently. A second attempt is a new
/// connection, a new client and - per Finding 1 - a new <c>ClientHelloProfile</c>.</para>
/// <para>WHAT THIS DOES NOT DO, so that an absence is not read as an oversight. Retry,
/// Version Negotiation and CONNECTION_CLOSE are task 9b's; 1-RTT <i>sending</i> arrived in
/// task 14c and lives in TlsQuicApplicationSendPath.cs, streams are still task 14's; loss
/// detection, retransmission and congestion control are A3's and are
/// deferred by the user's decision, which is why the handshake deadline below exists at all
/// and why it is a timeout rather than a repair.</para>
/// </remarks>
/// <summary>Which of the deadlines <c>EarliestDeadline</c> races won, and therefore what waking
/// on it means.</summary>
/// <remarks>THE DISTINCTION IS "IS THIS A FAILURE", AND THEN "IS THIS AN OBLIGATION". Task A3-5
/// introduced the first when it wove RFC 9002 A.8's loss detection timer in beside the two
/// abandonments, and a bool carried it. Task A3-11 introduced the second: s7.7's pacing release
/// is not a failure and not an obligation either - the pump must run its ordinary send pass and
/// must not run A.9 - so the answer stopped being a yes/no and became this.</remarks>
internal enum TlsQuicDeadlineKind
{
    /// <summary>The handshake deadline or RFC 9000 s10.1's idle timeout. The attempt is over.
    /// </summary>
    Abandonment,

    /// <summary>RFC 9002 A.8's <c>loss_detection_timer</c>. A.9's <c>OnLossDetectionTimeout</c>
    /// runs, then the ordinary send pass.</summary>
    Recovery,

    /// <summary>RFC 9002 s7.7's pacing release. The ordinary send pass runs and nothing else.
    /// </summary>
    Pacing,

    /// <summary>RFC 9000 s13.2.1's <c>max_ack_delay</c> falling due on an acknowledgement
    /// <see cref="TlsQuicRecoverySpec.AckPolicy"/> held back. The ordinary send pass runs and
    /// nothing else.</summary>
    /// <remarks>THE SAME KIND AS <see cref="Pacing"/> AND STILL NOT THE SAME MEMBER. Both mean
    /// "run the send pass, do not run A.9", so folding them together would compile and would
    /// pass every test here. What would be lost is the only thing either name carries: which
    /// rule armed the wake. A pacing release is RFC 9002 s7.7's PERMISSION to send something
    /// already queued; this is RFC 9000 s13.2.1's OBLIGATION to have sent something by now, and
    /// a connection waking on a deadline it cannot name is a connection whose stall nobody can
    /// attribute. A3-11 made this method's answer an enum rather than a bool for exactly that
    /// reason, one kind earlier.</remarks>
    DelayedAck,
}

internal sealed partial class TlsQuicConnection : IAsyncDisposable
{
    // RFC 9000 s18.2's max_udp_payload_size ceiling: "The maximum value is 65527". One
    // receive buffer of this size is allocated PER DATAGRAM and never pooled - see the
    // allocation site, and TlsQuicPacketReceiver.Receive's contract (3), which is what
    // forbids the pool.
    private const int DatagramBufferSize = 65527;

    /// <summary>RFC 9000 s16 Table 4's widest variable-length integer encoding, in bytes.
    /// </summary>
    /// <remarks>A3-7's probe padder is the only reader: it reserves the difference between
    /// this and the narrowest encoding so that a Length field which widens under the PADDING
    /// it just added cannot push the datagram past <see cref="DatagramBufferSize"/>. Table 4's
    /// four rows are 1, 2, 4 and 8 bytes.</remarks>
    internal const int MaximumVarintWidth = 8;

    // A4-minimal is version 1 only. RFC 9369 defines a second version this project targets
    // and both the receiver and the key set take it as a parameter for that reason; the
    // connection has no version-negotiation state to choose from yet, which is task 9b's.
    private const TlsQuicVersion Version = TlsQuicVersion.Version1;

    // WHAT BOUNDS RETENTION, AND THE ONLY THING THAT BOUNDS THE APPLICATION SPACE.
    //
    // RFC 9002 A.11 empties the Initial and Handshake spaces when their keys are discarded,
    // and ApplyDiscards below does exactly that - so those two are bounded by the handshake
    // itself. A.11 opens with `assert(pn_space != ApplicationData)`, which is the spec saying
    // in code that the application space is never emptied that way. Nothing else in this
    // phase removes a packet except an acknowledgement, so a peer that accepts datagrams and
    // acknowledges none would otherwise grow that list for as long as the connection lives.
    // Loss detection (A3-6) and a congestion window (A3-9) will each remove packets sooner,
    // but neither exists yet, and a cap that only holds once they land is not a cap.
    //
    // WHY DROPPING THE OLDEST IS SAFE. Forgetting a packet costs exactly two things: it can
    // no longer be retransmitted, and its bytes leave bytes_in_flight - which the drop does
    // explicitly, through Forget, rather than leaking them. Both are outcomes the peer had
    // already forced by never acknowledging it. A.1 states the retention window is finite:
    // "After a packet is declared lost, the endpoint can still maintain state for it for an
    // amount of time to allow for packet reordering". The cap is chosen so that reaching it
    // is not a state a working path produces: 1024 unacknowledged packets at RFC 9000 s14.1's
    // 1200-byte floor is over 1.2 MB outstanding, an order of magnitude past any window
    // A3-9's initial congestion window (10 datagrams) can open, and the memory ceiling is the
    // three spaces' 3072 records - a TlsQuicSentPacket is six fields of value type.
    //
    // A CONST AND NOT A SPEC KNOB, DELIBERATELY. This is a memory ceiling, not a fingerprint
    // dimension - it changes no byte on the wire - so it is not one of subsystem B's knobs.
    // A3-12 owns the recovery knob table; if this ever needs to be settable it belongs there,
    // beside the constants that DO change what goes out.
    // INTERNAL SO THE BOUND'S TEST DERIVES ITS EXPECTATION FROM THE CAP rather than writing
    // 1024 beside it - a test that hard-coded the number would keep passing if the cap moved
    // and stop meaning anything the day it did.
    internal const int MaxRetainedPacketsPerSpace = 1024;

    // RFC 9002 A.2's kGranularity: "Timer granularity. This is a system-dependent value, and
    // Section 6.1.2 recommends a value of 1 ms."
    //
    // IT IS HERE AND NOT ON TlsQuicRecoverySpec, WHICH IS WHERE IT BELONGS. That type carries
    // the other seven A.2 constants - kPacketThreshold, kTimeThreshold, kInitialRtt and the
    // rest - and quotes this one's sentence twice in prose without declaring it. Adding a
    // member there is an edit to a file A3-5 does not own, so the constant is declared at the
    // one place that needs it today and A3-6, which needs the same number for s6.1.2's time
    // threshold floor, should move it rather than declare a second copy. RECORDED AS A DEBT
    // RATHER THAN LEFT AS A COINCIDENCE.
    internal static readonly TimeSpan KGranularity = TimeSpan.FromMilliseconds(1);

    // The ceiling on RFC 9002 A.3's pto_count, and it is about C# rather than about QUIC.
    // A.9 increments pto_count with no bound at all and the RFC bounds it only in prose -
    // s6.2.1's "The total length of time over which consecutive PTOs expire is limited by the
    // idle timeout" - so a transcription of A.9 grows an int without limit. At 2^31 the
    // increment WRAPS NEGATIVE, Math.Pow(factor, negative) is a fraction, and the PTO period
    // would COLLAPSE to kGranularity instead of growing: an unbounded backoff transcribed
    // literally turns into no backoff at all. 64 is past the point where every finite factor
    // above one has saturated TimeSpan.MaxValue, so the cap costs nothing a real connection
    // could observe.
    internal const int MaximumPtoCount = 64;

    private readonly TlsQuicConnectionOptions _options;
    private readonly Func<ReadOnlyMemory<byte>, CustomTlsQuicClient> _clientFactory;
    private readonly TlsQuicPacketReceiver _receiver;
    private readonly TlsQuicKeySet _keys;
    private readonly TlsQuicAckTracker _acks;

    // One send buffer for the life of the connection. Unlike the receive buffer this one is
    // safe to reuse: nothing parses out of it and nothing aliases it past the SendAsync that
    // consumes it. The Initial flight is the exception and allocates its own, because
    // TlsQuicDatagramBuilder.BuildInitialFlight hands back one array per datagram.
    private readonly byte[] _sendBuffer = new byte[DatagramBufferSize];

    // Indexed by TlsQuicEncryptionLevel. RFC 9000 s12.3's three packet number spaces are
    // Initial, Handshake and Application; EarlyData shares Application's and is unused here
    // because A4-minimal sends no 0-RTT.
    private readonly ulong[] _nextPacketNumber = new ulong[4];
    // RFC 9002 A.1's sent_packets, one list per RFC 9000 s12.3 packet number space rather
    // than one per encryption level - A.1: "Sent packets are tracked for each packet number
    // space, and ACK processing only applies to a single space." The four levels collapse
    // onto three spaces through SpaceOf below; keying by level would give 0-RTT a fourth
    // space it does not have and let a 0-RTT packet number sit beside an identical 1-RTT one.
    //
    // A LIST, ASCENDING BY PACKET NUMBER, RATHER THAN A DICTIONARY KEYED ON IT. A.1 expects
    // access "by packet number and crypto context", and a dictionary is the literal reading,
    // but every operation this connection performs walks the whole space anyway: an ACK frame
    // names RANGES and not numbers, a key discard takes all of them, and the cap below drops
    // the oldest. The order is free - packet numbers within a space only ever increase, so
    // appending IS sorting - and index 0 is therefore always the oldest retained packet.
    private readonly List<TlsQuicSentPacket>[] _sentPackets = [[], [], []];

    // The scratch TlsQuicDatagramBuilder appends to. ONE LIST REUSED, not one per datagram:
    // BuildDatagram and BuildInitialFlight take an ICollection and Add to it, and all three
    // call sites here drain it into _sentPackets in the same synchronous step. Nothing holds
    // a reference past that drain.
    private readonly List<TlsQuicSentPacket> _justSent = [];

    // The scratch TlsQuicAckFrames.TryGetRanges decodes an incoming ACK frame into. ALSO
    // REUSED, and it is on the receive path, so the PEER decides how many ranges arrive: it
    // is cleared before each use and never pre-sized from the frame's own AckRangeCount,
    // which is the rule TlsQuicAckFrames states for its callers.
    private readonly List<TlsQuicAckRange> _ackedRanges = [];

    // RFC 9002 A.4's bytes_in_flight. ONE TOTAL ACROSS THE THREE SPACES, because that is what
    // A.4 declares it to be - one path, one congestion controller - and kept by addition and
    // subtraction rather than by summing _sentPackets on demand, so that a retained packet
    // whose bytes were never subtracted is a DIVERGENCE a test can catch rather than an
    // arithmetic identity that can never fail. TlsQuicConnectionTests.AssertBytesInFlight
    // AgreesWithRetention is that check, and it is why this is not a computed property.
    private long _bytesInFlight;

    private CustomTlsQuicClient? _client;
    private byte[] _sourceConnectionId = [];
    private byte[] _destinationConnectionId = [];

    // RFC 9000 s7.2's "a valid Initial packet from the server": the Source Connection ID off a
    // packet that AUTHENTICATED, which is a different and later thing than the one adoption
    // reads. Null until such a packet arrives; see AcceptedUnderSection122.
    private byte[]? _validatedServerSourceConnectionId;

    // RFC 9000 s17.2.5.2's Retry state. The token is copied onto every later Initial packet -
    // s17.2.5.3: "The value of the Token field is copied to all subsequent Initial packets" -
    // and the Source Connection ID is what s7.3's retry_source_connection_id must equal. The
    // latter is non-null EXACTLY when a Retry was honoured, which is also the condition s7.3
    // uses to decide whether that parameter must be present at all, so the two cannot drift.
    private byte[] _retryToken = [];
    private byte[]? _retrySourceConnectionId;

    // s17.2.5.3: "A client MUST use the same cryptographic handshake message it included in
    // this packet." Retained rather than asked for a second time, because
    // CustomTlsQuicClient.StartHandshake is one-shot and a second call would build a second
    // ClientHello.
    private byte[] _clientHello = [];

    // OUR advertised max_idle_timeout (0x01), read from the profile the factory built - the
    // one place it is written. s18.2: "Idle timeout is disabled when both endpoints omit this
    // transport parameter or specify a value of 0", so a zero and an absence are one state
    // here and both are null.
    private TimeSpan? _ourMaxIdleTimeout;
    private TimeSpan? _peerMaxIdleTimeout;

    // Task 14d: the peer's six s18.2 flow-control limits, which Finding 6 found parsed and
    // discarded. Null until EncryptedExtensions arrives, because until then no limit has been
    // advertised and 0 would be a lie in the other direction. See
    // TlsQuicPeerFlowControlBudget.cs for why absent reads as 0 once they HAVE arrived.
    private TlsQuicPeerFlowControlBudget? _peerFlowControl;

    private DateTimeOffset _deadline;
    private DateTimeOffset _idleSince;

    // RFC 9002 A.3's loss_detection_timer - "Multi-modal timer used for loss detection" - held
    // as the INSTANT it is set to rather than as a timer object, because this connection has
    // one thread of control and no callbacks: the timer IS the deadline the next receive is
    // raced against, and A.8's `loss_detection_timer.cancel()` is null here. See
    // EarliestDeadline for the race and SetLossDetectionTimer for A.8's arming ladder.
    private DateTimeOffset? _lossDetectionTimer;

    // Which space armed it, per A.8's `GetPtoTimeAndSpace` returning a pair. A3-5 does not USE
    // the space - what to put in a probe is A3-7's - so it is exposed rather than consumed,
    // and LossDetectionSpace is the witness for s6.2.1's "the timer MUST be set to the earlier
    // value of the Initial and Handshake packet number spaces".
    private TlsQuicEncryptionLevel? _lossDetectionSpace;

    // RFC 9002 A.3's pto_count: "The number of times a PTO has been sent without receiving an
    // acknowledgment." Capped; see MaximumPtoCount for the signed-overflow reason.
    private int _ptoCount;

    // The PEER's max_ack_delay (RFC 9000 s18.2, 0x0b), which s6.2.1's PTO formula needs and
    // which nothing in this file retained before A3-5 - the A3 plan predicted that and A3-4
    // left the seam. s18.2's absent-value default is 25 ms and TlsQuicAckTracker owns the
    // number, so it is read from there rather than restated. THE TRACKER IS TOLD THE SAME
    // VALUE at the same moment (OnPeerAckParameters), so the estimator's copy and this one
    // cannot drift; this field exists because the tracker exposes no getter for it and A3-5
    // may not edit that file.
    private TimeSpan _peerMaxAckDelay = TlsQuicAckTracker.DefaultMaxAckDelay;
    private bool _started;
    private bool _adoptedServerConnectionId;
    private bool _adoptedFromRetry;
    private bool _processedServerPacket;
    private bool _sentAckElicitingSinceReceive;
    private bool _draining;
    private bool _sentHandshakePacket;
    private bool _handshakeDoneReceived;
    private bool _confirmed;
    private bool _disposed;

    /// <param name="options">The transport, the peer, the layout spec and the clock.</param>
    /// <param name="clientFactory">
    /// Builds the TLS client for THIS attempt, given the Source Connection ID this attempt
    /// drew.
    /// <para>A FACTORY RATHER THAN A CLIENT, because A4 Finding 1 requires a fresh
    /// <c>ClientHelloProfile</c> per connection unconditionally, and the profile is
    /// immutable and carries the QUIC transport parameters - among them
    /// <c>initial_source_connection_id</c> (0x0F), which is this connection's Source
    /// Connection ID and cannot be known before the connection exists. So the source CID is
    /// drawn here, where the spec's length knob lives, and handed to the factory rather than
    /// the other way round; that is the only ordering in which the parameter we advertise
    /// and the bytes in our packet headers cannot disagree.</para>
    /// <para>WHAT FINDING 1'S OTHER PER-CONNECTION PARAMETER WOULD HAVE ADDED, AND WHY IT
    /// ADDS NOTHING TODAY. <c>initial_rtt</c> (12583) is randomised per connection by the
    /// target, and it lives in the same immutable profile - so it is the reason the factory
    /// takes a whole profile's worth of work rather than being a cached instance. But
    /// <see cref="TlsQuicConnectionSpec.InitialRttRange"/> is <see langword="null"/> and
    /// stays null: the capture holds a single draw, which fixes neither bounds nor
    /// distribution, and the plan's amendment after task 1 refused to invent a range because
    /// a fabricated one is a fingerprint that is confidently wrong. So this connection sends
    /// no <c>initial_rtt</c> at all, which is a KNOWN DEVIATION from the target for task 11
    /// to report, and the visible per-connection input to the profile reduces to the source
    /// CID alone - which for the actual target is zero bytes long. The factory shape is
    /// therefore right and currently unobservable from the outside; both halves are stated
    /// because only the first one is usually said.</para>
    /// </param>
    /// <exception cref="ArgumentNullException">Either argument is
    /// <see langword="null"/>.</exception>
    internal TlsQuicConnection(
        TlsQuicConnectionOptions options,
        Func<ReadOnlyMemory<byte>, CustomTlsQuicClient> clientFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(clientFactory);

        _options = options;
        _clientFactory = clientFactory;

        // The receiver is told OUR connection ID length, because RFC 9000 s17.3.1 gives a
        // short header's Destination Connection ID field no length prefix and a 1-RTT packet
        // from the server carries our Source Connection ID there. Getting it from the spec
        // rather than from a constant is the whole reason it is a parameter one layer down.
        _receiver = new TlsQuicPacketReceiver(
            (uint)Version, options.Spec.SourceConnectionIdLength);
        _keys = new TlsQuicKeySet(_receiver, Version);

        // THE TASK-8 WIRING. Before this line nothing under src/ constructed a tracker from a
        // spec, so TlsQuicConnectionSpec.AckRangeLimit was a present-but-inert knob: setting
        // it changed no byte. It now bounds the ranges this connection remembers and sends.
        // A3-7's THIRD ARGUMENT, AND IT IS THE HALF OF FINDING 6's DIVERGENCE THIS TASK CAN
        // REACH. TlsQuicRecoverySpec.DrawInitialRtt reads
        // TlsQuicConnectionSpec.InitialRttRange when that names a range and falls back to
        // RFC 9002 s6.2.2's 333 ms when it does not, and until this line NOTHING under src/
        // called it: knob 1 changed the transport parameter this client ADVERTISES and
        // changed nothing about the PTO it retransmits on. It now feeds both, which is what
        // DrawInitialRtt's own remarks ask for - "A caller who cares sets
        // TlsQuicConnectionSpec.InitialRttRange, which makes the two agree."
        //
        // THE SHIPPED DEFAULT IS UNCHANGED BY CONSTRUCTION, and that is deliberate rather
        // than incidental: InitialRttRange defaults to null, so DrawInitialRtt returns
        // kInitialRtt and every existing expectation built on 333 ms holds. What is left
        // open is the DEFAULT half of Finding 6 - an unconfigured client advertises a draw
        // from 100-300 ms and starts from 333 - and closing that means changing
        // TlsQuicConnectionSpec._initialRttRange's initialiser, which is a file A3-7 may not
        // open. The divergence is therefore now a choice of default rather than a structural
        // gap: one knob drives both ends, and only its default disagrees with the parameter
        // preset's own fallback.
        //
        // ONE DRAW PER CONNECTION, HERE, which is what TlsQuicAckTracker's own remarks
        // require: "a draw is per connection and a second draw here would be a THIRD answer."
        //
        // AND THE FOURTH ARGUMENT IS THE SECOND KNOB THIS LINE MADE REACHABLE. Knob 12 -
        // TlsQuicRecoverySpec.AckPolicy - was read by nothing in src/ until A3-13, for a
        // structural reason and not an oversight: TlsQuicAckTracker is sealed, holds the whole
        // ACK decision in TryBuildAck, and this is its ONLY construction site in the assembly,
        // so this is the one place a recovery spec and that tracker meet. See
        // TlsQuicAckTracker's ackPolicy parameter for why the max_ack_delay bound is NOT
        // passed beside it.
        _acks = new TlsQuicAckTracker(
            options.AckDelayExponent,
            options.Spec.AckRangeLimit,
            TlsQuicRecoverySpec.DrawInitialRtt(options.Spec),
            options.Spec.Recovery.AckPolicy);

        // RFC 9000 s7.2: "When an Initial packet is sent by a client that has not previously
        // received an Initial or Retry packet from the server, the client populates the
        // Destination Connection ID field with an unpredictable value. This Destination
        // Connection ID MUST be at least 8 bytes in length." The 8-byte floor is enforced by
        // TlsQuicConnectionSpec.DestinationConnectionIdLength, where the knob is; the
        // unpredictability is enforced here, by a CSPRNG rather than a counter.
        //
        // s7.2 also: "The client populates the Source Connection ID field with a value of its
        // choosing" - no floor at all, and Chromium's is zero bytes, which
        // RandomNumberGenerator.GetBytes(0) returns as an empty array.
        //
        // DRAWN HERE RATHER THAN IN StartAsync, because these two values are this attempt's
        // IDENTITY and a peer needs them before the first packet exists: RFC 9000 s7.3 makes
        // the server's original_destination_connection_id the Destination Connection ID we
        // drew, so anything standing in for a server has to know it in advance to be
        // conforming. The ordering the client factory depends on is untouched - the Source
        // Connection ID still exists before the factory that must advertise it is called,
        // which is the only sequencing Finding 1 constrains.
        _destinationConnectionId = RandomNumberGenerator.GetBytes(
            options.Spec.DestinationConnectionIdLength);
        _sourceConnectionId = RandomNumberGenerator.GetBytes(options.Spec.SourceConnectionIdLength);
        OriginalDestinationConnectionId = _destinationConnectionId;

        // s12.3's spaces are independent, and only the Initial one has a spec knob:
        // InitialPacketNumber is documented as "the packet number this client's first Initial
        // packet carries". Handshake and Application start at 0, which is not a knob because
        // neither the capture nor RFC 9000 offers ground truth for anything else - the same
        // reason BuildInitialFlight's step is 1 rather than a parameter.
        _nextPacketNumber[(int)TlsQuicEncryptionLevel.Initial] = options.Spec.InitialPacketNumber;
    }

    /// <summary>Whether TLS has finished - RFC 9001 s4.1.2's handshake <i>complete</i>. Not
    /// the same as <see cref="IsHandshakeConfirmed"/>.</summary>
    internal bool IsHandshakeComplete => _client is { IsHandshakeComplete: true };

    /// <summary>RFC 9001 s4.1.2, verbatim: "At the client, the handshake is considered
    /// confirmed when a HANDSHAKE_DONE frame is received."</summary>
    internal bool IsHandshakeConfirmed => _confirmed;

    /// <summary>RFC 9221 s3's <c>max_datagram_frame_size</c> (0x20) as this connection's
    /// ClientHello actually advertised it, or <see langword="null"/> when it advertised none or
    /// advertised zero - s3 makes those one state.</summary>
    /// <remarks>A pass-through to <c>CustomTlsQuicClient.AdvertisedMaxDatagramFrameSize</c>,
    /// which is where the value is read off the profile that went on the wire; see its comment
    /// for why the spec's copy is not a substitute. Null before <c>ConnectAsync</c>, because
    /// the client - and therefore the ClientHello - does not exist until then.</remarks>
    internal ulong? AdvertisedMaxDatagramFrameSize => _client?.AdvertisedMaxDatagramFrameSize;

    /// <summary>The Source Connection ID this connection drew and puts on its packets; it is
    /// also what it advertised as <c>initial_source_connection_id</c>, because the factory
    /// was handed these exact bytes.</summary>
    internal ReadOnlyMemory<byte> SourceConnectionId => _sourceConnectionId;

    /// <summary>The Destination Connection ID currently on our outgoing packets. RFC 9000
    /// s7.2: our own unpredictable choice until the server's first packet, the server's
    /// Source Connection ID afterwards.</summary>
    internal ReadOnlyMemory<byte> DestinationConnectionId => _destinationConnectionId;

    /// <summary>The Destination Connection ID this connection chose for its first Initial
    /// packet, which RFC 9001 s5.2 makes the sole input to the Initial secrets. Retained
    /// separately because <see cref="DestinationConnectionId"/> moves at s7.2's adoption and
    /// the Initial keys do not move with it.</summary>
    internal ReadOnlyMemory<byte> OriginalDestinationConnectionId { get; private set; }

    /// <summary>Write-key state at one level; the discard witnesses read this.</summary>
    internal TlsQuicKeyLevelState WriteStateOf(TlsQuicEncryptionLevel level) =>
        _keys.WriteStateOf(level);

    /// <summary>Whether read keys are installed at one level.</summary>
    internal bool HasReadKeys(TlsQuicEncryptionLevel level) => _receiver.HasReadKeys(level);

    /// <summary>How many pieces of CRYPTO stream have been handed to the TLS client.</summary>
    internal int DeliveredCryptoChunks { get; private set; }

    /// <summary>How many coalesced packets were ignored under RFC 9000 s12.2's Destination
    /// Connection ID clause; see <see cref="PumpOnceAsync"/>.</summary>
    internal int IgnoredForConnectionIdMismatch { get; private set; }

    /// <summary>How many packets were discarded under RFC 9000 s7.2's "Once a client has
    /// received a valid Initial packet from the server, it MUST discard any subsequent packet
    /// it receives on that connection with a different Source Connection ID."</summary>
    internal int DiscardedForSourceConnectionIdChange { get; private set; }

    /// <summary>How many packets this connection could not open, for either of RFC 9000
    /// s12.2's two reasons. NOT AN ERROR COUNT: s12.2 requires the loop to carry on, and this
    /// is what makes a stall diagnosable instead - see <see cref="DeadlineExceeded"/>.
    /// </summary>
    internal int DiscardedPackets { get; private set; }

    /// <summary>The subset of <see cref="DiscardedPackets"/> that met no read keys at their
    /// level - s12.2's "because the keys are not available", which is the coalescing stall's
    /// signature.</summary>
    internal int DiscardedForMissingKeys { get; private set; }

    /// <summary>How many HANDSHAKE_DONE frames were received, not whether one was. A conforming
    /// server retransmits an unacknowledged one, and until task 14c this connection never
    /// acknowledged a 1-RTT packet at all (RFC 9000 s13.2.1's MUST, knowingly violated), so
    /// anything above one used to be that violation being paid for - task 13's live run
    /// measured seven from tls3.peet.ws in 14.9 seconds. It is kept now that the ACK is sent
    /// because it is the only thing that would show the ACK failing to arrive. Counted rather
    /// than predicted because <c>_handshakeDoneReceived</c> is a latch and a latch cannot
    /// measure a cost.</summary>
    internal int HandshakeDoneFramesReceived { get; private set; }

    /// <summary>How many packets were parsed but never handed to the packet protection layer
    /// - a Version Negotiation packet or a Retry, whether it was honoured or discarded, since
    /// neither packet type has protected fields to process.</summary>
    internal int UnprocessedPackets { get; private set; }

    /// <summary>How many Retry packets were discarded rather than honoured, under any of RFC
    /// 9000 s17.2.5.2's three MUSTs or s17.2.5.1's fourth.</summary>
    internal int IgnoredRetryPackets { get; private set; }

    /// <summary>How many Version Negotiation packets were ignored - because a packet for this
    /// connection had already been processed (RFC 9000 s6.2), or because the packet did not
    /// echo this connection's own connection IDs (s17.2.1).</summary>
    internal int IgnoredVersionNegotiationPackets { get; private set; }

    /// <summary>RFC 9000 s17.2.5's Retry Token, empty until a Retry is honoured. Copied onto
    /// every Initial packet sent afterwards.</summary>
    internal ReadOnlyMemory<byte> RetryToken => _retryToken;

    /// <summary>The Source Connection ID field of the Retry packet this connection honoured,
    /// which RFC 9000 s7.3 makes <c>retry_source_connection_id</c>'s only legal value.
    /// <see langword="null"/> when no Retry was honoured, which is the same condition s7.3
    /// uses to require the parameter's absence.</summary>
    /// <remarks>THE CAST ON THE NULL BRANCH IS LOAD-BEARING, AND A FAILING TEST FOUND IT.
    /// <see cref="ReadOnlyMemory{T}"/> declares an implicit conversion from <c>T[]?</c>, so in
    /// <c>x is { } v ? new ReadOnlyMemory&lt;byte&gt;(v) : null</c> the conditional's natural
    /// type is <c>ReadOnlyMemory&lt;byte&gt;</c> and not the nullable: the null literal
    /// converts through that operator into an EMPTY memory, which is then lifted into a
    /// nullable that HAS a value. That form and the plainer <c>=&gt; _retrySourceConnectionId</c>
    /// both report "a Retry happened, carrying a zero-length connection ID" for every
    /// connection that never saw one - and RFC 9000 s7.3 turns on exactly that distinction,
    /// since "If a zero-length connection ID is selected, the corresponding transport parameter
    /// is included with a zero-length value". Absent and empty are different states here.
    /// </remarks>
    internal ReadOnlyMemory<byte>? RetrySourceConnectionId =>
        _retrySourceConnectionId is { } value
            ? new ReadOnlyMemory<byte>(value)
            : (ReadOnlyMemory<byte>?)null;

    /// <summary>The eight bytes of the last PATH_CHALLENGE received, which RFC 9000 s19.18
    /// requires a PATH_RESPONSE to echo, held until the next 1-RTT packet carries them out.
    /// <see langword="null"/> once answered - see <c>TryBuildApplicationPacket</c> in
    /// TlsQuicApplicationSendPath.cs, which is what clears it.</summary>
    internal ReadOnlyMemory<byte>? PendingPathResponseData { get; private set; }

    /// <summary>RFC 9000 s10.2.2's draining state, entered on receiving a CONNECTION_CLOSE
    /// frame, and s10.2.1's closing state, entered on sending one. Both mean the same two
    /// things here: stop sending, stop delivering.</summary>
    internal bool IsDraining => _draining;

    /// <summary>The RFC 9000 s20.1 code this endpoint put in the CONNECTION_CLOSE frame it
    /// sent, or <see langword="null"/> if it sent none - or if what it sent was s19.19's
    /// APPLICATION form, whose Error Code is not from s20.1's space at all; see
    /// <see cref="ClosedWithApplicationErrorCode"/>.</summary>
    internal TlsQuicTransportError? ClosedWith { get; private set; }

    /// <summary>The application error code this endpoint put in a CONNECTION_CLOSE frame of
    /// RFC 9000 s19.19's type 0x1d, or <see langword="null"/> if it sent no such frame.</summary>
    /// <remarks>
    /// A SECOND PROPERTY RATHER THAN A WIDENED <see cref="ClosedWith"/>, because s19.19 makes
    /// the two Error Code fields draws from DIFFERENT SPACES: "A CONNECTION_CLOSE frame of type
    /// 0x1c uses codes from the space defined in Section 20.1. A CONNECTION_CLOSE frame of type
    /// 0x1d uses codes defined by the application protocol; see Section 20.2." Reporting an
    /// application code as a <see cref="TlsQuicTransportError"/> would name HTTP/3's
    /// H3_MISSING_SETTINGS (0x010a) as s20.1's CRYPTO_ERROR range, which is a different error.
    /// The two are therefore never both set, and which one is set says which frame type left.
    /// </remarks>
    internal ulong? ClosedWithApplicationErrorCode { get; private set; }

    /// <summary>The RFC 9000 s20.1 code the PEER put in a CONNECTION_CLOSE frame it sent, or
    /// <see langword="null"/> if none arrived.</summary>
    internal ulong? PeerCloseErrorCode { get; private set; }

    /// <summary>Whether the attempt ended on RFC 9000 s10.1's idle timeout rather than on the
    /// handshake deadline. The two are different failures - see
    /// <see cref="EffectiveIdleTimeout"/>.</summary>
    internal bool IdleTimedOut { get; private set; }

    /// <summary>The versions a Version Negotiation packet offered, recorded when one ends the
    /// attempt. A4-minimal reports rather than negotiates - see
    /// <see cref="HandleVersionNegotiation"/>.</summary>
    internal IReadOnlyList<uint>? OfferedVersions { get; private set; }

    /// <summary>The next packet number this connection will use at <paramref name="level"/>.
    /// </summary>
    internal ulong NextPacketNumber(TlsQuicEncryptionLevel level) =>
        _nextPacketNumber[(int)level];

    /// <summary>RFC 9002 A.1's <c>sent_packets</c> for the packet number space
    /// <paramref name="level"/> belongs to: every packet sent at that space and not yet
    /// acknowledged, key-discarded, or dropped by the retention cap.</summary>
    /// <remarks>KEYED BY SPACE AND NOT BY LEVEL, so asking at
    /// <see cref="TlsQuicEncryptionLevel.EarlyData"/> and at
    /// <see cref="TlsQuicEncryptionLevel.Application"/> returns the SAME list - RFC 9000
    /// s12.3 gives 0-RTT and 1-RTT one space between them. Live, not a snapshot: the next
    /// send or acknowledgement moves it.</remarks>
    internal IReadOnlyList<TlsQuicSentPacket> SentPackets(TlsQuicEncryptionLevel level) =>
        _sentPackets[SpaceOf(level)];

    /// <summary>RFC 9002 A.4's <c>bytes_in_flight</c>: the summed
    /// <see cref="TlsQuicSentPacket.Size"/> of every retained packet whose
    /// <see cref="TlsQuicSentPacket.IsInFlight"/> is set, across all three spaces.</summary>
    /// <remarks>A.4 excludes packets that carry nothing but ACK frames, and this therefore
    /// does NOT equal the summed size of <see cref="SentPackets"/> - those packets are
    /// retained and not counted. SIGNED rather than unsigned so that a subtraction bug
    /// reports a negative total instead of wrapping to a plausible-looking enormous one.
    /// </remarks>
    internal long BytesInFlight => _bytesInFlight;

    /// <summary>Runs one whole handshake attempt: the opening flight, then datagrams until
    /// RFC 9001 s4.1.2's HANDSHAKE_DONE arrives.</summary>
    /// <remarks>RETURNS AT CONFIRMED, NOT AT COMPLETE, because confirmation is what releases
    /// the Handshake keys and a caller that stopped at complete would leave them installed
    /// forever. The loop terminates because every iteration takes a datagram and every
    /// datagram is bounded by the handshake deadline.</remarks>
    /// <exception cref="TimeoutException">The handshake deadline passed.</exception>
    internal async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
    {
        await StartAsync(cancellationToken).ConfigureAwait(false);
        while (!_confirmed)
        {
            await PumpOnceAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Draws the connection IDs, builds this attempt's TLS client, installs the
    /// Initial keys and sends the opening flight.</summary>
    /// <exception cref="InvalidOperationException">Already started, or the factory returned
    /// <see langword="null"/>.</exception>
    internal async ValueTask StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_started)
        {
            throw new InvalidOperationException(
                "This connection has already been started; a QUIC connection attempt is "
                    + "one-shot, because CustomTlsQuicClient is.");
        }
        _started = true;

        // The connection IDs were drawn in the constructor - see there for why - so this
        // method's first act is the one thing that could not be done before it: building the
        // TLS client that must advertise the Source Connection ID as
        // initial_source_connection_id (0x0F).
        _client = _clientFactory(_sourceConnectionId)
            ?? throw new InvalidOperationException(
                "The client factory returned null; it must build one CustomTlsQuicClient "
                    + "whose transport parameters carry the Source Connection ID it was given.");

        // TWO SOURCES FOR ONE NUMBER, AND NOTHING USED TO TIE THEM. The exponent this
        // connection SCALES its ACK delays by is TlsQuicConnectionOptions.AckDelayExponent;
        // the exponent it ADVERTISES is transport parameter 0x0A inside the immutable
        // ClientHelloProfile the factory just built, which is the only place a transport
        // parameter may live (see TlsQuicConnectionSpec.AckRangeLimit's remarks: "a second
        // copy on the spec would be a second source of truth for one advertised value").
        // Nothing reconciled them, and the mismatch is currently MASKED because this loop
        // reads the clock once per pump and every ack_delay it reports is therefore
        // structurally zero - a zero scales to zero under any exponent.
        //
        // WHICH IS EXACTLY WHY IT FAILS LOUDLY HERE RATHER THAN LATER. RFC 9000 s19.3's
        // direction is that the SENDER of the ACK scales, so the sender's own advertised
        // exponent is the one the peer must divide by; the moment task 14 or A3 reads the
        // clock twice, a mismatched pair becomes a 2^n error in the peer's RTT estimate with
        // no symptom on either side. s18.2's default is what an absent parameter means: "if
        // this value is absent, a default value of 3 is assumed (indicating a multiplier of
        // 8)."
        var advertised = (int)(_client.AdvertisedAckDelayExponent
            ?? TlsQuicAckTracker.DefaultAckDelayExponent);
        if (advertised != _options.AckDelayExponent)
        {
            throw new InvalidOperationException(
                $"This connection scales its ACK delays by 2^{_options.AckDelayExponent} but "
                    + $"advertises ack_delay_exponent (0x0A) as {advertised}. RFC 9000 s19.3 "
                    + "makes the ACK's sender the one that scales, so the peer will divide by "
                    + "the advertised value and the two must agree. Set "
                    + "TlsQuicConnectionOptions.AckDelayExponent to match the transport "
                    + "parameter in the ClientHelloProfile the factory builds, or leave both "
                    + "at s18.2's default of 3.");
        }

        // RFC 9001 s5.2: "The secrets are derived from the Destination Connection ID field of
        // the client's first Initial packet", which is the one just drawn. Installed BEFORE
        // StartHandshake because the flight it produces is protected with these keys.
        _keys.InstallInitialKeys(_destinationConnectionId, isClient: true);

        // RFC 9000 s10.1's own half of the same pairing: max_idle_timeout (0x01) is advertised
        // in the profile and nowhere else, and s18.2 makes a zero and an absence one state -
        // "Idle timeout is disabled when both endpoints omit this transport parameter or
        // specify a value of 0" - so both map to null. Unlike ack_delay_exponent this pair is
        // not required to AGREE: s10.1 defines the effective value as the minimum of the two,
        // so a disagreement is the ordinary case and EffectiveIdleTimeout resolves it.
        _ourMaxIdleTimeout = ToIdleTimeout(_client.AdvertisedMaxIdleTimeout);

        // The clock starts at the first packet, and it is read from the injected
        // TimeProvider rather than DateTimeOffset.UtcNow - see TlsQuicConnectionOptions.
        var startedAt = _options.TimeProvider.GetUtcNow();
        _deadline = startedAt + _options.HandshakeDeadline;
        _idleSince = startedAt;

        using var start = _client.StartHandshake();
        InstallSecrets(start);

        // s17.2.5.3's "A client MUST use the same cryptographic handshake message it included
        // in this packet" is why this is retained: a Retry replays THESE bytes rather than
        // asking the TLS client for a second ClientHello.
        _clientHello = CollectCryptoStream(start, TlsQuicEncryptionLevel.Initial);
        await SendInitialFlightAsync(_clientHello, cancellationToken).ConfigureAwait(false);

        // THE OPENING FLIGHT IS AN ACK-ELICITING SEND AND HAS TO BE RECORDED AS ONE. It carries
        // CRYPTO, and RFC 9000 s2 makes every frame but ACK, PADDING and CONNECTION_CLOSE
        // ack-eliciting, so s10.1's send-side clause has already been spent by the time this
        // returns: "An endpoint also restarts its idle timer when sending an ack-eliciting
        // packet IF NO OTHER ACK-ELICITING PACKETS HAVE BEEN SENT SINCE LAST RECEIVING AND
        // PROCESSING A PACKET." Nothing has been received at all yet, so the next ack-eliciting
        // send in this silence - the Retry answer, and A3's retransmissions after it - must NOT
        // restart the timer, and only this flag can say so.
        //
        // IT DOES NOT MOVE _idleSince. The call is passed the same startedAt assigned above, so
        // the deadline is unchanged and the whole effect is the flag. The assignment above is
        // kept rather than folded in here because it must hold even if the send throws.
        //
        // WRITING _idleSince = startedAt AND LEAVING THE FLAG FALSE - which is what stood here
        // until now - is a s10.1 divergence and was measured as one: a Retry answered nine
        // minutes into a ten-minute idle bound moved the deadline out to nineteen, because at
        // that answer the flag still said no ack-eliciting packet had been sent. It also made
        // RestartIdleTimerOnAckElicitingSend's own guard unfireable, which is why the mutation
        // ledger's row 71 survived and why its recorded reason - "this loop makes at most one
        // ack-eliciting send per received packet" - was false: this flight and the Retry answer
        // are two such sends with no processed packet between them.
        RestartIdleTimerOnAckElicitingSend(startedAt);

        ApplyDiscards(start);
    }

    /// <summary>Takes exactly one datagram, feeds its CRYPTO to TLS, and sends whatever that
    /// produced. Returns whether the handshake is now confirmed.</summary>
    /// <remarks>
    /// <para>ONE COALESCED PACKET AT A TIME, WITH EACH RESULT'S KEYS INSTALLED BEFORE THE
    /// NEXT IS OPENED - and that split is a PERMANENT CALLER RESPONSIBILITY, not a
    /// workaround. <see cref="TlsQuicPacketReceiver.Receive"/> does walk coalesced packets
    /// itself (RFC 9000 s12.2: "Receivers MUST be able to process coalesced packets"), but it
    /// is synchronous by construction and installing Handshake keys needs an <c>await</c>
    /// into TLS, so it cannot install keys mid-walk. A server that coalesces ServerHello (an
    /// Initial packet) with its Handshake flight - which is what real servers do - therefore
    /// has its Handshake packet met by no Handshake keys and discarded. With A3 deferred
    /// nothing ever retransmits it, so the handshake stalls with every packet accounted for
    /// and NOTHING WRONG ON THE WIRE. Read <c>Receive</c>'s own remarks; they are longer than
    /// this and they are the contract.</para>
    /// <para>THE GUARD BELOW IS SHAPED FOR THAT STALL AND NOT FOR THE OBVIOUS CASE. The naive
    /// <c>Processed == 0</c> cannot fire on it: the stall's shape is <c>Processed=1,
    /// Discarded=1</c>. <see cref="TlsQuicReceiveResult.DiscardedForMissingKeys"/> exists so
    /// it can be detected rather than inferred, and it is used.</para>
    /// <para>SPLITTING FORFEITS s12.2's CONNECTION ID CLAUSE UNLESS THE CALLER RE-ADDS IT,
    /// AND THIS CALLER RE-ADDS IT. "Receivers SHOULD ignore any subsequent packets with a
    /// different Destination Connection ID than the first packet in the datagram." That check
    /// lives inside <c>Receive</c> as a local, re-nulled per call, so one call per packet
    /// means one "first packet" per packet and the clause never applies. It is re-applied
    /// here, across the calls, because it is the same clause task 6 implemented and dropping
    /// it silently at a layer boundary is how a SHOULD becomes a regression nobody records.
    /// Ignored packets are counted by
    /// <see cref="IgnoredForConnectionIdMismatch"/>.</para>
    /// <para>THE RECEIVE BUFFER IS FRESH PER DATAGRAM AND NEVER POOLED - <c>Receive</c>'s
    /// contract (3). The frames dispatched to the handler alias it and the receiver's own
    /// scratch, so the handler copies the CRYPTO payload out and retains nothing else but
    /// frame TYPES; see the handler.</para>
    /// </remarks>
    /// <exception cref="TimeoutException">The handshake deadline passed.</exception>
    /// <exception cref="InvalidOperationException">A packet could not be accounted for, or a
    /// frame the peer sent is malformed.</exception>
    internal async ValueTask<bool> PumpOnceAsync(CancellationToken cancellationToken = default)
    {
        // The same three preconditions SendPendingAsync needs; see EnsureSendable in
        // TlsQuicApplicationSendPath.cs, which is where they moved so both entries share one.
        EnsureSendable();

        // A FRESH BUFFER PER DATAGRAM, NEVER POOLED. TlsQuicPacketReceiver.Receive's contract
        // (3) states why in full: a pooled buffer handed back and refilled turns every
        // retained alias into a read of the NEXT datagram, with no compiler error and no
        // exception. Pooling is an A3-era optimisation and is exactly the change that would
        // break this silently.
        var buffer = new byte[DatagramBufferSize];

        var received = await ReceiveWithinDeadlineAsync(buffer, cancellationToken)
            .ConfigureAwait(false);
        var datagram = buffer.AsMemory(0, received.Length);

        // ONE INSTANT PER PUMP, AND THAT MAKES EVERY ACK DELAY WE REPORT ZERO. RFC 9000
        // s13.2.5 wants the gap between the largest acknowledged packet's ARRIVAL and the
        // ACK's DEPARTURE, and this value is handed to both TlsQuicAckTracker.OnPacketReceived
        // and TryBuildAck, so the subtraction is always of an instant from itself.
        //
        // DELIBERATE, AND SAFE IN ONE DIRECTION ONLY. s13.2.5's reader subtracts the reported
        // delay from its RTT sample, so under-reporting makes the peer's estimate LARGER and
        // therefore more conservative; over-reporting would shrink it and could drive a peer's
        // PTO below the real round trip. A4-minimal has no timing to be accurate about - A3
        // owns RTT - so the safe direction is taken rather than a second clock read whose only
        // observable effect today would be scheduling jitter in the number.
        //
        // A CONSEQUENCE WORTH NAMING: TlsQuicConnectionOptions.AckDelayExponent therefore
        // scales a zero, so no wire byte moves when it changes. It is wired and validated but
        // it is not yet OBSERVABLE, which is the weaker of the two claims the plan's task-5
        // amendment separates - task 11 reports it that way.
        var now = _options.TimeProvider.GetUtcNow();

        var results = new List<TlsQuicProcessResult>();
        try
        {
            var offset = 0;
            byte[]? firstDestinationConnectionId = null;

            // THIS LOOP AWAITS INSIDE A LAZY ITERATOR, which TlsQuicDatagramReader.Read's own
            // contract forbids in general. It is sound here for the same two arithmetic
            // reasons LoopbackQuicPeer.PumpOnceAsync writes out: (1) the reader's cursor only
            // moves forward and everything the receive does to the buffer - s5.4 header
            // protection removal, in place - lands strictly behind it, so the bytes it has
            // yet to read are byte-for-byte identical when it resumes; and (2) there is
            // exactly one writer of this buffer, the ReceiveAsync above, and this type has
            // one thread of control, so no await here can let another receive refill it.
            // Both are load-bearing: (1) alone fails against a second writer, and (2) alone
            // fails against a body that wrote forward of the cursor.
            foreach (var coalesced in TlsQuicDatagramReader.Read(datagram))
            {
                // The reader hands back a read-only view; the receiver needs the writable one,
                // because header protection is removed in place.
                var packet = buffer.AsMemory(offset, coalesced.Packet.Length);
                offset += packet.Length;

                // GROUND (1), CHECKED RATHER THAN ONLY ARGUED. The reader's slice and this
                // writable window must be the same bytes; they are compared BEFORE this packet
                // is processed, so the in-place header protection removal that is about to
                // happen is not what is being compared. It costs one span compare per packet
                // and it is the only thing standing between the offset arithmetic above and a
                // silent hand-off of the wrong bytes to the AEAD.
                if (!coalesced.Packet.Span.SequenceEqual(packet.Span))
                {
                    throw new InvalidOperationException(
                        $"The datagram reader's {coalesced.Packet.Length}-byte slice and this "
                            + $"loop's window at offset {offset - packet.Length} are different "
                            + "bytes, so the cursor arithmetic here has drifted from the "
                            + "reader's.");
                }

                // THE TWO UNAUTHENTICATED PACKET TYPES ARE DECIDED HERE AND NEVER REACH THE
                // RECEIVER, and that is the whole shape of both. A Version Negotiation packet
                // has no cryptographic protection at all (RFC 9001 s5) and a Retry packet
                // "does not contain any protected fields" (RFC 9000 s17.2.5), so each is peer
                // input no key authenticates, and each moves connection state. Nothing below
                // may throw on either: s12.2's rule for input we cannot open is to carry on.
                //
                // A SECOND HEADER PARSE, DELIBERATELY. AcceptedUnderSection122 parses the same
                // header again for the packets that survive this dispatch; both parses are
                // pure Try-shaped walks over the same unmodified bytes, and the alternative -
                // an "accepted" predicate that returns false for a packet it accepted, through
                // a second out parameter - trades a cheap parse for a name that lies.
                if (coalesced.Kind == TlsQuicCoalescedPacketKind.VersionNegotiation)
                {
                    HandleVersionNegotiation(packet);
                    continue;
                }

                if (TlsQuicPacketHeader.TryReadLongHeader(packet, out var maybeRetry, out _)
                    && maybeRetry.Type == TlsQuicLongPacketType.Retry)
                {
                    await HandleRetryAsync(maybeRetry, packet, cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

                if (!AcceptedUnderSection122(
                        packet, ref firstDestinationConnectionId, out var packetSourceConnectionId))
                {
                    continue;
                }

                var chunks = new List<CryptoChunk>();
                var frameTypes = new List<ulong>();
                TlsQuicReceivedPacket? acknowledgeable = null;
                TlsQuicTransportError? frameError = null;

                // SEPARATE FROM frameError BECAUSE THE MESSAGE BELOW NAMES THE FRAME. Folding
                // a STREAM refusal into the ACK one would report an s19.8 failure as a
                // malformed ACK. Task 14e; the text is ReceiveStreamFrame's, in
                // TlsQuicStreams.cs.
                string? streamFailure = null;
                string? protocolFailure = null;
                var peerClosed = false;

                var outcome = _receiver.Receive(
                    packet,
                    (in TlsQuicFrame frame, in TlsQuicReceivedPacket source) =>
                    {
                        acknowledgeable = source;

                        // ONLY THE FRAME TYPE IS RETAINED PAST THIS CALL. A TlsQuicFrame
                        // aliases the receiver's decrypt scratch, which the NEXT Receive call
                        // refills, and the ack tracker is told about this packet only after
                        // the awaits below - RFC 9000 s13.1: "A packet MUST NOT be
                        // acknowledged until packet protection has been successfully removed
                        // and all frames contained in the packet have been processed." The
                        // tracker reads nothing but the type (s13.2's ack-eliciting test), so
                        // the type is what is copied. Keeping the frames themselves would
                        // work today and break the first time anything reads their Data.
                        frameTypes.Add(frame.RawType);

                        switch (frame.Type)
                        {
                            case TlsQuicFrameType.Crypto:
                                // .ToArray() COPIES OUT OF THE RECEIVER'S SCRATCH, which is an
                                // instance field reused by every later Receive. These chunks
                                // are consumed across awaits below, so the copy is not
                                // defensive here - it is required.
                                chunks.Add(new CryptoChunk(
                                    source.Level, frame.Offset, frame.Data.ToArray()));
                                break;

                            case TlsQuicFrameType.Ack:
                                // Task 8's entry point. A4-minimal wants only the verdict and
                                // the largest-acked advance that task 4b's packet-number
                                // encoding reads; A3 fills in the RTT sample behind it.
                                if (!_acks.ProcessAckFrame(source.Level, frame, now, out var error))
                                {
                                    frameError = error;
                                }
                                else
                                {
                                    // RFC 9002 A.5's removal, gated on the tracker having
                                    // accepted the frame first.
                                    //
                                    // THE GATE CHANGES NOTHING TODAY, AND THE LEDGER SAYS SO
                                    // RATHER THAN THE COMMENT CLAIMING OTHERWISE. Rows 133 and
                                    // 134 are equivalent mutations, proved: ProcessAckFrame
                                    // returns false only when TlsQuicAckFrames.TryGetRanges
                                    // does, and TryGetRanges' RollBack removes everything the
                                    // call added - so after any rejection OnAckReceived's own
                                    // freshly cleared list is empty and its loop retires
                                    // nothing either way.
                                    //
                                    // IT IS HERE FOR THE REJECTION THAT DOES NOT EXIST YET.
                                    // A3-4 adds s13.1's "if a packet number was never issued",
                                    // which is a semantic refusal rather than a walk failure;
                                    // on the day it lands the two mutations stop being
                                    // equivalent and this line is what keeps a refused ACK from
                                    // retiring packets. Writing it afterwards would mean
                                    // finding this call site again.
                                    //
                                    // THE FRAME IS SAFE TO READ HERE for the same reason the
                                    // tracker may read it - OnAckReceived retains nothing but
                                    // the numbers, and the note above about aliasing the
                                    // decrypt scratch is about holding the frame past this
                                    // call, which it does not.
                                    OnAckReceived(source.Level, frame);
                                }

                                break;

                            case TlsQuicFrameType.HandshakeDone:
                                // RFC 9001 s4.1.2: "At the client, the handshake is considered
                                // confirmed when a HANDSHAKE_DONE frame is received." Recorded
                                // here and acted on after the send below, never inside the
                                // handler - ConfirmHandshake releases keys and this callback
                                // runs mid-datagram.
                                //
                                // NO LEVEL CHECK HERE, and that is not an omission: RFC 9000
                                // s12.4 Table 3 permits HANDSHAKE_DONE in 1-RTT packets only,
                                // and TlsQuicPacketReceiver already gates every dispatched
                                // frame through TlsQuicFrameLegality.Permits, so a
                                // HANDSHAKE_DONE at any other level never reaches this line.
                                _handshakeDoneReceived = true;
                                HandshakeDoneFramesReceived++;
                                break;

                            case TlsQuicFrameType.ConnectionClose:
                                // RFC 9000 s10.2: "After receiving a CONNECTION_CLOSE frame,
                                // endpoints enter the draining state." Recorded here and acted
                                // on after this datagram is walked, for the same reason
                                // HANDSHAKE_DONE is: this callback runs mid-datagram and
                                // s12.2 still requires the remaining packets to be processed.
                                //
                                // THE ERROR CODE IS COPIED OUT, NOT INTERPRETED. s19.19's code
                                // is a 62-bit integer over two open spaces (s20.1's and the
                                // application's), so it is reported as the number it is rather
                                // than mapped onto TlsQuicTransportError, which lists only the
                                // codes this library RAISES.
                                PeerCloseErrorCode = frame.ErrorCode;
                                peerClosed = true;
                                break;

                            case TlsQuicFrameType.PathChallenge:
                                // RFC 9000 s19.17: "The recipient of this frame MUST generate
                                // a PATH_RESPONSE frame (Section 19.18) containing the same
                                // Data value." THE DATA IS COPIED because it aliases the
                                // receiver's scratch and the answer is built after this
                                // datagram is walked, not inside this callback. The answer
                                // itself is TryBuildApplicationPacket's, in
                                // TlsQuicApplicationSendPath.cs; task 9b could record this and
                                // not send it because s12.4 Table 3 gives PATH_RESPONSE the row
                                // "___1" and no short header could be built then.
                                PendingPathResponseData = frame.Data.ToArray();
                                break;

                            case TlsQuicFrameType.Stream:
                                // Task 14e's entry point. RFC 9000 s19.8; the whole of the
                                // handling, and its reasons, are in TlsQuicStreams.cs.
                                ReceiveStreamFrame(frame, ref streamFailure);
                                break;

                            case TlsQuicFrameType.MaxData:
                            case TlsQuicFrameType.MaxStreamData:
                                // The peer raising OUR send limit - RFC 9000 s19.9 and s19.10.
                                // One arm for both because the two differ only in scope, and
                                // ReceiveFlowControlFrame in TlsQuicStreams.cs is where that
                                // difference and every rule behind it lives. Until this arm
                                // existed both frames fell into the default below and the send
                                // budget could only shrink.
                                ReceiveFlowControlFrame(frame, ref streamFailure);
                                break;

                            case TlsQuicFrameType.ResetStream:
                            case TlsQuicFrameType.StopSending:
                            case TlsQuicFrameType.StreamDataBlocked:
                                // The four s19.4, s19.5 and s19.13 direction rules, whose whole
                                // content lives in ReceiveStreamStateSignal in
                                // TlsQuicStreams.cs beside the two receive-side rules it
                                // mirrors. One arm for three types because all four MUSTs are
                                // the same test on a stream identifier.
                                //
                                // s19.12's DATA_BLOCKED IS DELIBERATELY NOT HERE. It carries
                                // no stream id, so it has no direction to be wrong about and
                                // s19.12 states no rule of this shape; it stays in the default
                                // arm with the reason that arm gives.
                                //
                                // ACCEPTING IS STILL NOT ACTING. A RESET_STREAM this endpoint
                                // does not refuse is dropped exactly as it was before, because
                                // s3.2's state transitions are separate work. What changed is
                                // that the ones the RFC says to close on now close.
                                ReceiveStreamStateSignal(frame, ref streamFailure);
                                break;

                            case TlsQuicFrameType.RetireConnectionId:
                                // s19.16, and for this client every path through it ends in
                                // the same place - but for two different reasons, which is why
                                // the length is tested rather than assumed.
                                //
                                // ZERO-LENGTH SOURCE CONNECTION ID, which is
                                // TlsQuicConnectionSpec.SourceConnectionIdLength's default and
                                // what the shipped profiles use: "An endpoint that provides a
                                // zero-length connection ID MUST treat receipt of a
                                // RETIRE_CONNECTION_ID frame as a connection error of type
                                // PROTOCOL_VIOLATION." Unconditional - the sequence number is
                                // not even consulted, because there is no connection ID it
                                // could name.
                                //
                                // NON-ZERO SOURCE CONNECTION ID, which the spec permits and a
                                // future profile may want: this endpoint never sends a
                                // NEW_CONNECTION_ID frame, so sequence number 0 - the one the
                                // handshake provided - is the only one ever "sent to the
                                // peer". s19.16: "Receipt of a RETIRE_CONNECTION_ID frame
                                // containing a sequence number greater than any previously
                                // sent to the peer MUST be treated as a connection error of
                                // type PROTOCOL_VIOLATION", which makes every number above 0 a
                                // violation.
                                //
                                // AND SEQUENCE NUMBER 0 IS REFUSED UNDER s19.16's MAY, not
                                // under a MUST. "The sequence number specified in a
                                // RETIRE_CONNECTION_ID frame MUST NOT refer to the Destination
                                // Connection ID field of the packet in which the frame is
                                // contained.  The peer MAY treat this as a connection error of
                                // type PROTOCOL_VIOLATION." The MUST NOT binds the SENDER and
                                // this client never sends the frame, so the MAY is the only
                                // receive-side action the rule offers. With one connection ID
                                // issued and every 1-RTT packet from the server carrying it as
                                // the Destination Connection ID, number 0 always refers to
                                // that field, so the option always applies. Exercising it
                                // needs no per-packet context, which is why this is a length
                                // test and not a comparison against the packet in hand.
                                protocolFailure ??=
                                    "The peer sent a RETIRE_CONNECTION_ID frame (RFC 9000 "
                                    + "s19.16) naming sequence number "
                                    + $"{frame.SequenceNumber}, which this endpoint never "
                                    + "issued: its source connection ID is "
                                    + $"{_sourceConnectionId.Length} byte(s) long and no "
                                    + "NEW_CONNECTION_ID frame is ever sent.";
                                break;

                            default:
                                // PADDING, PING and anything else the peer legally sends
                                // during a handshake need no action from A4-minimal.
                                //
                                // s19.12's DATA_BLOCKED IS STILL HERE, DELIBERATELY. It is the
                                // peer saying it wants to send more than OUR advertised limits
                                // allow, and this endpoint already raises those limits on
                                // delivery rather than on request -
                                // TlsQuicStream.CreditReceiveWindow and
                                // TlsQuicStreamSet.CreditConnectionWindow - so there is
                                // nothing for the signal to trigger that has not already
                                // happened. s19.12 calls it "input to tuning of flow control
                                // algorithms", which is what a receiver with an adaptive
                                // window would use it for and this one has not got.
                                //
                                // ITS SIBLING STREAM_DATA_BLOCKED LEFT THIS ARM, and the two
                                // are no longer symmetric: s19.13 attaches a MUST to a
                                // stream's direction and s19.12, carrying no stream id, cannot.
                                break;
                        }
                    });

                if (frameError is { } malformed)
                {
                    // A CONNECTION-LEVEL FAILURE, NOT A LOOP KILL. Task 9b turns this into an
                    // RFC 9000 s10.2 immediate close carrying the code; until then a poisoned
                    // one-shot attempt that throws is what a close would have achieved minus
                    // the frame on the wire.
                    throw new InvalidOperationException(
                        $"The peer sent a malformed ACK frame: {malformed}.");
                }

                // The same connection-level failure, for the same reason, one frame type
                // along. Task 14e.
                if (streamFailure is { } badStream)
                {
                    throw new InvalidOperationException(badStream);
                }

                // And once more for the frames whose rule is not about a stream at all. Kept
                // separate from streamFailure rather than folded into it because the two carry
                // different s20.1 codes - STREAM_STATE_ERROR and PROTOCOL_VIOLATION - and task
                // 9b's immediate close will need to tell them apart.
                if (protocolFailure is { } violation)
                {
                    throw new InvalidOperationException(violation);
                }

                AccountForPacket(outcome);

                if (outcome.Processed > 0)
                {
                    // RFC 9000 s17.2.5.2's "After the client has received and processed an
                    // Initial or Retry packet from the server, it MUST discard any subsequent
                    // Retry packets that it receives", and the same word in
                    // TlsQuicVersionNegotiation's contract: a Version Negotiation packet "MUST
                    // be ignored once a packet for the connection has been successfully
                    // processed". PROCESSED IS THE AEAD'S VERDICT, not the parser's, which is
                    // what stops an off-path sender arming either rule with a forgery.
                    _processedServerPacket = true;

                    // RFC 9000 s10.1: "An endpoint restarts its idle timer when a packet from
                    // its peer is received and processed successfully."
                    _idleSince = now;
                    _sentAckElicitingSinceReceive = false;
                }

                if (peerClosed)
                {
                    // s10.2.2: "While otherwise identical to the closing state, an endpoint in
                    // the draining state MUST NOT send any packets." Set before the send below
                    // rather than after it, which is the whole content of the MUST here.
                    _draining = true;
                }

                if (outcome.Processed > 0 && packetSourceConnectionId is { } validated)
                {
                    // RFC 9000 s7.2's "a valid Initial packet from the server", and VALID is
                    // why this sits after the AEAD rather than beside the adoption. A Source
                    // Connection ID taken off unauthenticated input would let an off-path
                    // sender choose the value every later packet is measured against, which is
                    // the influence s7.3's last paragraph exists to deny.
                    _validatedServerSourceConnectionId ??= validated;
                }

                foreach (var chunk in chunks)
                {
                    var result = await _client!
                        .ProcessCryptoDataAsync(
                            chunk.Level, chunk.Offset, chunk.Data, cancellationToken)
                        .ConfigureAwait(false);
                    results.Add(result);
                    DeliveredCryptoChunks++;

                    // BEFORE THE NEXT PACKET OF THIS DATAGRAM IS OPENED, not after the whole
                    // datagram is done - the Handshake packet coalesced behind ServerHello is
                    // protected with keys this very result carries.
                    InstallSecrets(result);
                    await ApplyPeerTransportParametersAsync(result, cancellationToken)
                        .ConfigureAwait(false);
                }

                if (acknowledgeable is { } source2)
                {
                    // s13.1's ordering: after every frame of the packet has been processed,
                    // which for CRYPTO means after the awaits above.
                    _acks.OnPacketReceived(
                        source2.Level, source2.PacketNumber, TypeOnlyFrames(frameTypes), now);
                }
            }

            if (!_draining)
            {
                _ = await SendAnswerAsync(results, now, cancellationToken).ConfigureAwait(false);

                // A3-7's probe, on the send pass A3-5 built for it and AFTER the ordinary
                // answer rather than instead of it. s6.2.4 makes the probe an obligation of its
                // own - "a sender MUST send at least one ack-eliciting packet in the packet
                // number space as a probe" - so a datagram that happened to go out for another
                // reason does not discharge it; and going second means the probe's send instant
                // is the latest one, which is the instant A.9's closing SetLossDetectionTimer
                // arms the next period from.
                //
                // INSIDE THE !_draining GUARD for the reason every other send is: RFC 9000
                // s10.2.2 leaves a draining endpoint nothing to send.
                await SendOwedProbeAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            // AFTER the send, never before: TlsQuicProcessResult.Dispose zeroes the traffic
            // secrets it carries, and TlsQuicKeySet.InstallFromTrafficSecret rejects an
            // all-zero secret precisely so this ordering mistake is a throw rather than a
            // handshake that stalls behind structurally valid keys nobody can decrypt.
            foreach (var result in results)
            {
                result.Dispose();
            }
        }

        if (PeerCloseErrorCode is { } peerCode)
        {
            // THE ATTEMPT IS OVER, AND THIS THROW IS ON AUTHENTICATED INPUT. A
            // CONNECTION_CLOSE frame is only ever dispatched to the handler out of a packet
            // the AEAD opened, so no off-path sender can reach this line - the distinction
            // AccountForPacket's remark draws between CloseError and a failed decrypt, applied
            // to the frame that says the same thing in words. RFC 9000 s10.2.2 leaves nothing
            // else to do: we may not send, and the peer is gone.
            throw new InvalidOperationException(
                $"The peer closed the connection with error code 0x{peerCode:x} (RFC 9000 "
                    + "s19.19 CONNECTION_CLOSE), so this attempt is draining and can neither "
                    + "send nor complete.");
        }

        return _confirmed;
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return ValueTask.CompletedTask;
        }
        _disposed = true;

        _keys.Dispose();
        _receiver.Dispose();

        // The transport is NOT disposed: TlsQuicConnectionOptions.Transport documents it as
        // "Not owned: the caller disposes it."
        return _client?.DisposeAsync() ?? ValueTask.CompletedTask;
    }

    private readonly record struct CryptoChunk(
        TlsQuicEncryptionLevel Level, ulong Offset, ReadOnlyMemory<byte> Data);

    // Frames stripped to the one field TlsQuicAckTracker.OnPacketReceived reads. See the
    // handler for why the real ones cannot be kept.
    private static List<TlsQuicFrame> TypeOnlyFrames(List<ulong> rawTypes)
    {
        var frames = new List<TlsQuicFrame>(rawTypes.Count);
        foreach (var rawType in rawTypes)
        {
            frames.Add(new TlsQuicFrame { RawType = rawType });
        }
        return frames;
    }

    private static byte[] CollectCryptoStream(
        TlsQuicProcessResult result, TlsQuicEncryptionLevel level)
    {
        var stream = new List<byte>();
        foreach (var raised in result.Events)
        {
            if (raised is not TlsQuicCryptoDataEvent data || data.Level != level)
            {
                continue;
            }

            // The offsets are the TLS endpoint's and are never recomputed here - a running
            // total kept by this class would be a second piece of offset arithmetic, wrong in
            // the same way as the first. Contiguity is checked instead, because
            // TlsQuicDatagramBuilder.PlanInitialCryptoFrames carves ONE stream starting at
            // offset 0 and a gap would silently shift every frame after it.
            if (data.Offset != (ulong)stream.Count)
            {
                throw new InvalidOperationException(
                    $"The opening flight's CRYPTO stream is not contiguous: a chunk at offset "
                        + $"{data.Offset} follows {stream.Count} bytes.");
            }
            stream.AddRange(data.Data);
        }

        if (stream.Count == 0)
        {
            throw new InvalidOperationException(
                $"StartHandshake produced no {level} CRYPTO data to send.");
        }
        return [.. stream];
    }

    // RFC 9000 s12.2: "Receivers SHOULD ignore any subsequent packets with a different
    // Destination Connection ID than the first packet in the datagram." Re-applied here
    // because splitting the datagram forfeits Receive's own copy of it; see PumpOnceAsync's
    // remarks. Also RFC 9000 s7.2's adoption point, because both need the same parse and
    // doing it twice would be two reads of one header.
    private bool AcceptedUnderSection122(
        ReadOnlyMemory<byte> packet,
        ref byte[]? firstDestinationConnectionId,
        out byte[]? packetSourceConnectionId)
    {
        packetSourceConnectionId = null;

        if (!TryReadDestinationConnectionId(packet, out var destination, out var header))
        {
            // Unparseable at this layer - a Version Negotiation packet, a Retry, or plain
            // rubbish. s12.2's clause judges Destination Connection IDs and this packet has
            // none we can read, so it is passed through to Receive, whose job is to discard
            // or report it. Deciding here would be a second parser.
            return true;
        }

        if (firstDestinationConnectionId is null)
        {
            firstDestinationConnectionId = destination;
        }
        else if (!firstDestinationConnectionId.AsSpan().SequenceEqual(destination))
        {
            IgnoredForConnectionIdMismatch++;
            return false;
        }

        if (header is not { } longHeader)
        {
            // RFC 9000 s17.3.1 gives a short header no Source Connection ID field at all, so
            // neither s7.2 clause below has anything to read off this packet.
            return true;
        }

        packetSourceConnectionId = longHeader.SourceConnectionId.ToArray();

        // RFC 9000 s7.2, the whole sentence past the line wrap at lines 58-61 of the extract:
        // "Once a client has received a valid Initial packet from the server, it MUST discard
        // any subsequent packet it receives on that connection with a different Source
        // Connection ID." VALID is the load-bearing word, which is why the value compared
        // against is recorded in PumpOnceAsync after the AEAD has opened a packet and not
        // here. Before that first valid packet there is nothing to compare against and the
        // clause does not bind - so this is not the guard that decides the FIRST adoption.
        //
        // s7.2 gives the same rule a second time from the server's side and states the reason:
        // "Any further changes to the Destination Connection ID are only permitted if the
        // values are taken from NEW_CONNECTION_ID frames; if subsequent Initial packets
        // include a different Source Connection ID, they MUST be discarded. This avoids
        // unpredictable outcomes that might otherwise result from stateless processing of
        // multiple Initial packets with different Source Connection IDs."
        if (_validatedServerSourceConnectionId is { } known
            && !known.AsSpan().SequenceEqual(packetSourceConnectionId))
        {
            DiscardedForSourceConnectionIdChange++;
            return false;
        }

        // RFC 9000 s7.2, verbatim from the extract: "Upon first receiving an Initial or Retry
        // packet from the server, the client uses the Source Connection ID supplied by the
        // server as the Destination Connection ID for subsequent packets". Get this wrong and
        // the handshake fails with no useful error.
        //
        // ONLY THE FIRST, AND THAT IS ITS OWN SENTENCE OF s7.2 rather than an optimisation:
        // "A client MUST change the Destination Connection ID it uses for sending packets in
        // response to only the first received Initial or Retry packet." The flag below is that
        // MUST, and it is witnessed rather than assumed - deleting it used to leave the whole
        // gate green.
        //
        // ONLY THE INITIAL KEYS' INPUT STAYS PUT. s5.2 of [QUIC-TLS] derives them from the
        // Destination Connection ID of the client's FIRST Initial packet, which is
        // OriginalDestinationConnectionId and is not touched here. Adoption changes what we
        // ADDRESS, not what we key with. (Retry is the one thing that moves both, and it is
        // task 9b's.)
        //
        // AND IT READS UNAUTHENTICATED INPUT, DELIBERATELY - BUT NOT BECAUSE IT HAS TO. The
        // earlier draft of this remark argued that the adoption "necessarily precedes the AEAD"
        // because the Initial keys cannot be derived from a value this packet supplies. That
        // does not follow. The Initial keys come from OriginalDestinationConnectionId, which
        // never moves, so the AEAD can open this packet whether or not the adoption has already
        // run - and _validatedServerSourceConnectionId, recorded in PumpOnceAsync only after
        // outcome.Processed > 0, is the standing proof that a post-AEAD hook exists and is
        // usable. Placing the adoption here is a CHOICE: s7.2 phrases it on "upon FIRST
        // receiving an Initial or Retry packet from the server", and a Retry never reaches an
        // AEAD at all, so one placement covers both triggers.
        //
        // WHAT MAKES THE CHOICE SAFE IS s7.3, NOT AN IMPOSSIBILITY. RFC 9000 s7.3 authenticates
        // both connection IDs in transport parameters at the end of the handshake, and says why
        // in as many words - "Including connection ID values in transport parameters and
        // verifying them ensures
        // that an attacker cannot influence the choice of connection ID for a successful
        // connection by injecting packets carrying attacker-chosen connection IDs during the
        // handshake." An injected first packet therefore costs this attempt, and cannot cost
        // more than this attempt.
        if (!_adoptedServerConnectionId)
        {
            _destinationConnectionId = longHeader.SourceConnectionId.ToArray();
            _adoptedServerConnectionId = true;
        }

        return true;
    }

    // RFC 9000 s17.2.1. THE LEAST TRUSTWORTHY PACKET ON THE WIRE - RFC 9001 s5 gives it no
    // cryptographic protection whatsoever - and it is also the one this connection ends the
    // attempt on, which is a combination that has to be justified rather than assumed.
    //
    // TWO GUARDS STAND BETWEEN AN OFF-PATH DATAGRAM AND THAT ENDING, and both are the RFC's
    // own. The first is the rule TlsQuicVersionNegotiation's contract states: a Version
    // Negotiation packet may be used "only to pick a version for a fresh connection attempt,
    // and MUST be ignored once a packet for the connection has been successfully processed" -
    // and successfully processed here means the AEAD opened it, not that a parser liked it.
    // The second is s17.2.1's echo requirement, quoted whole below; it is what turns "anyone
    // who can send us a datagram" into "someone who saw our Initial packet", and s17.2.1 says
    // so in as many words: "Echoing both connection IDs gives clients some assurance that the
    // server received the packet and that the Version Negotiation packet was not generated by
    // an entity that did not observe the Initial packet."
    //
    // AN ON-PATH ATTACKER STILL WINS, AND THAT IS THE RFC'S POSITION, NOT A GAP HERE. s10.2.3:
    // "QUIC does not include defensive measures for on-path attacks during the handshake."
    //
    // A4-MINIMAL REPORTS AND FAILS RATHER THAN NEGOTIATING. Choosing another version means
    // starting a fresh attempt with a different TlsQuicVersion, and every key in this object
    // was derived under the current one; the offered list is recorded in OfferedVersions so
    // the caller that owns attempt policy can act on it.
    private void HandleVersionNegotiation(ReadOnlyMemory<byte> packet)
    {
        UnprocessedPackets++;

        if (!TlsQuicVersionNegotiation.TryRead(packet, out var negotiation))
        {
            // Shaped like a Version Negotiation packet to the datagram reader (Header Form set,
            // Version 0) and not one to the parser. Nothing to report and nothing to act on.
            IgnoredVersionNegotiationPackets++;
            return;
        }

        if (_processedServerPacket)
        {
            IgnoredVersionNegotiationPackets++;
            return;
        }

        // s17.2.1, both sentences: "The server MUST include the value from the Source
        // Connection ID field of the packet it receives in the Destination Connection ID
        // field. The value for Source Connection ID MUST be copied from the Destination
        // Connection ID of the received packet, which is initially randomly selected by a
        // client."
        //
        // WHICH Destination Connection ID WE SENT depends on whether a Retry has landed: after
        // one, s17.2.5.3 has us sending Initial packets with the Retry's Source Connection ID,
        // so a Version Negotiation packet answering THAT Initial echoes the new value while one
        // answering the first echoes the original. Both are packets we sent, so both are
        // accepted, and no third value is.
        if (!negotiation.DestinationConnectionId.Span.SequenceEqual(_sourceConnectionId)
            || !(negotiation.SourceConnectionId.Span.SequenceEqual(
                    OriginalDestinationConnectionId.Span)
                || negotiation.SourceConnectionId.Span.SequenceEqual(_destinationConnectionId)))
        {
            IgnoredVersionNegotiationPackets++;
            return;
        }

        // RFC 9000 s6.2's THIRD normative rule, and the one that closes the attacker the echo
        // check above leaves standing. Read past the line wrap, all three sentences: "A client
        // that supports only this version of QUIC MUST abandon the current connection attempt
        // if it receives a Version Negotiation packet, with the following two exceptions. A
        // client MUST discard any Version Negotiation packet if it has received and
        // successfully processed any other packet, including an earlier Version Negotiation
        // packet. A client MUST discard a Version Negotiation packet that lists the QUIC
        // version selected by the client."
        //
        // THE ECHO CHECK ABOVE STOPS THE UNOBSERVED ATTACKER; THIS ONE STOPS THE OBSERVED ONE.
        // s17.2.1's echo requirement turns "anyone who can send us a datagram" into "someone
        // who saw our Initial packet" - it cannot do more than that, and an off-path sender
        // who DID observe our Initial can echo both connection IDs perfectly. Without this
        // rule such a sender ends the attempt with a packet whose version list contains only
        // the version we are already speaking, which is self-contradictory on its face: a
        // server that supports our version does not answer with Version Negotiation. s6.2 says
        // to discard it rather than reason about it.
        if (negotiation.SupportedVersions.Contains((uint)Version))
        {
            IgnoredVersionNegotiationPackets++;
            return;
        }

        OfferedVersions = negotiation.SupportedVersions;
        throw new InvalidOperationException(
            "The server sent a Version Negotiation packet (RFC 9000 s17.2.1): it does not "
                + $"support QUIC version 0x{(uint)Version:x8}. It offers "
                + $"[{string.Join(", ", negotiation.SupportedVersions.Select(v => $"0x{v:x8}"))}]. "
                + "A4-minimal reports rather than negotiates - selecting one of these means a "
                + "fresh connection attempt built for that version, because every key here was "
                + "derived under the current one.");
    }

    // RFC 9000 s17.2.5 and RFC 9001 s5.8. LIKE VERSION NEGOTIATION, THIS IS UNAUTHENTICATED
    // INPUT - s17.2.5: "A Retry packet does not contain any protected fields" - so nothing
    // here throws: every rejection is a discard and a count, exactly as s12.2 requires of
    // input that cannot be opened.
    //
    // THE ORDER OF THE FIVE CHECKS IS NOT ARBITRARY. (FIVE, not four: the version check below
    // was restored in a08a76d after intercepting Retry ahead of the receiver took it away, and
    // this count was not updated with it.) The version check leads because a Retry labelled
    // with another version is not addressed to a connection this endpoint has at all, and it
    // says so at its own line. The once-only rule comes next because it is the one that must
    // hold even against a Retry whose tag verifies - a second VALID Retry is still discarded -
    // and because it is what makes the re-derivation below reachable at all; see the note
    // there about s4.9.1.
    private async ValueTask HandleRetryAsync(
        TlsQuicLongHeader retry, ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
    {
        UnprocessedPackets++;

        // THE VERSION CHECK COMES FIRST, AND INTERCEPTING RETRY AHEAD OF THE RECEIVER TOOK IT
        // AWAY UNTIL THIS LINE PUT IT BACK. TlsQuicPacketReceiver tests the Version field
        // BEFORE it recognises a Retry, and says why at that line - "those two decide whether
        // the walk can continue at all". A4-minimal speaks version 1 only, so a Retry labelled
        // with any other version is not addressed to a connection this endpoint has.
        //
        // AND IT IS NOT COVERED BY THE INTEGRITY TAG BELOW, which is the part worth writing
        // down: TlsQuicRetry is handed OUR version rather than the packet's - deliberately,
        // because the constants are version-specific and honouring a v2 Retry on a v1
        // connection would be a version negotiation nobody performed - so a Retry that
        // announces version 2 while carrying a tag computed with version 1's constants
        // verifies perfectly well. Only this check can reject it.
        if (retry.Version != (uint)Version)
        {
            IgnoredRetryPackets++;
            return;
        }

        // s17.2.5.2: "A client MUST accept and process at most one Retry packet for each
        // connection attempt. After the client has received and processed an Initial or Retry
        // packet from the server, it MUST discard any subsequent Retry packets that it
        // receives." Two conditions, one for each half of that sentence.
        if (_adoptedFromRetry || _processedServerPacket)
        {
            IgnoredRetryPackets++;
            return;
        }

        // s17.2.5.2: "A client MUST discard a Retry packet with a zero-length Retry Token
        // field." A separate MUST from the tag, and reachable with a perfectly valid tag.
        if (retry.Token.Length == 0)
        {
            IgnoredRetryPackets++;
            return;
        }

        // s17.2.5.1: "This value MUST NOT be equal to the Destination Connection ID field of
        // the packet sent by the client. A client MUST discard a Retry packet that contains a
        // Source Connection ID field that is identical to the Destination Connection ID field
        // of its Initial packet."
        //
        // COMPARED AGAINST OriginalDestinationConnectionId, NOT AGAINST _destinationConnectionId,
        // AND THE TWO COME APART UNDER EXACTLY THE ATTACK s7.3 NAMES. "Its Initial packet" is
        // the client's own first Initial, whose Destination Connection ID is the value we drew
        // and never moves. _destinationConnectionId is what we are CURRENTLY addressing, and
        // s7.2's adoption moves it off unauthenticated input: an injected Initial that never
        // opens still takes the once-only adoption with it, and _processedServerPacket stays
        // false, so control still reaches this line with the operand replaced by a value the
        // attacker chose. Under the old operand a Retry whose Source Connection ID equals our
        // ORIGINAL Destination Connection ID - precisely what s17.2.5.1 forbids - compares
        // unequal and is accepted. The faithful operand is the one the RFC names.
        if (retry.SourceConnectionId.Span.SequenceEqual(OriginalDestinationConnectionId.Span))
        {
            IgnoredRetryPackets++;
            return;
        }

        // RFC 9000 s17.2.5.2: "Clients MUST discard Retry packets that have a Retry Integrity
        // Tag that cannot be validated." RFC 9001 s5.8's pseudo-packet is this packet with its
        // tag removed, prefixed by the ORIGINAL Destination Connection ID - the one value a
        // forger who did not see our first Initial packet cannot know, which is the whole
        // reason OriginalDestinationConnectionId is retained separately.
        var withoutTag = packet[..(packet.Length - retry.RetryIntegrityTag.Length)];
        if (!TlsQuicRetry.TryVerify(
                Version,
                OriginalDestinationConnectionId.Span,
                withoutTag.Span,
                retry.RetryIntegrityTag.Span))
        {
            IgnoredRetryPackets++;
            return;
        }

        // s17.2.5.2: "A client sets the Destination Connection ID field of this Initial packet
        // to the value from the Source Connection ID field in the Retry packet. Changing the
        // Destination Connection ID field also results in a change to the keys used to protect
        // the Initial packet. It also sets the Token field to the token provided in the Retry
        // packet. The client MUST NOT change the Source Connection ID because the server could
        // include the connection ID as part of its token validation logic."
        //
        // s7.2 GIVES THIS ITS OWN ADOPTION FLAG, and re-running the 8-byte floor here would be
        // a defect rather than a check. That floor binds "an Initial packet ... sent by a
        // client that has not previously received an Initial or Retry packet from the server";
        // this value is the server's choice, not ours, and s7.2's "a client might have to
        // change the connection ID it sets in the Destination Connection ID field twice during
        // connection establishment: once in response to a Retry packet and once in response to
        // an Initial packet from the server" is why the flag is separate from
        // _adoptedServerConnectionId rather than shared with it.
        _retrySourceConnectionId = retry.SourceConnectionId.ToArray();
        _retryToken = retry.Token.ToArray();
        _destinationConnectionId = _retrySourceConnectionId;
        _adoptedFromRetry = true;

        // RFC 9001 s5.2 keys Initial from a Destination Connection ID that has just moved, and
        // s7.2 says the same thing from the other side: "These keys change after receiving a
        // Retry packet."
        //
        // THIS IS THE CALL TlsQuicKeySet.InstallInitialKeys THROWS OUT OF ONCE INITIAL HAS
        // BEEN DISCARDED, AND THE ORDERING THAT KEEPS IT REACHABLE IS THE ONCE-ONLY GUARD
        // ABOVE, NOT AN ASSUMPTION. s4.9.1 discards Initial when this client first SENDS a
        // Handshake packet; sending one requires Handshake write keys; those come out of a
        // server Initial packet that the AEAD opened, which sets _processedServerPacket. So
        // every state in which the discard has happened is a state in which the first guard
        // above has already returned. The dependency is one-way and checked here rather than
        // trusted: if that guard is ever widened, this throw is what it costs.
        _keys.InstallInitialKeys(_destinationConnectionId, isClient: true);

        // s17.2.5.2: "The client responds to a Retry packet with an Initial packet that
        // includes the provided Retry token to continue connection establishment", and
        // s17.2.5.3: "A client MUST use the same cryptographic handshake message it included in
        // this packet." The bytes are the ones StartAsync kept, not a second ClientHello.
        //
        // AND THE PACKET NUMBER DOES NOT GO BACK. s17.2.5.3: "A client MUST NOT reset the
        // packet number for any packet number space after processing a Retry packet." Nothing
        // here touches _nextPacketNumber, and SendInitialFlightAsync advances it as usual -
        // the reset would have to be written in on purpose.
        await SendInitialFlightAsync(_clientHello, cancellationToken).ConfigureAwait(false);
        RestartIdleTimerOnAckElicitingSend(_options.TimeProvider.GetUtcNow());
    }

    private bool TryReadDestinationConnectionId(
        ReadOnlyMemory<byte> packet,
        out byte[] destinationConnectionId,
        out TlsQuicLongHeader? longHeader)
    {
        destinationConnectionId = [];
        longHeader = null;

        if (TlsQuicPacketHeader.TryReadLongHeader(packet, out var parsed, out _))
        {
            destinationConnectionId = parsed.DestinationConnectionId.ToArray();
            longHeader = parsed;
            return true;
        }

        if (TlsQuicPacketHeader.TryReadShortHeader(
                packet, _options.Spec.SourceConnectionIdLength, out var shortHeader, out _))
        {
            destinationConnectionId = shortHeader.DestinationConnectionId.ToArray();
            return true;
        }

        return false;
    }

    // A DISCARD IS COUNTED, NOT THROWN, AND AN EARLIER VERSION OF THIS METHOD THREW.
    //
    // THAT THROW WAS AN OFF-PATH REMOTE KILL SWITCH. TlsQuicReceiveResult.Discarded is
    // incremented on header-protection-removal failure and on AEAD failure, both of which run
    // on UNAUTHENTICATED input, so a throw on `Discarded > 0` handed anyone who could copy one
    // of our datagrams a way to end the connection with ZERO key material: a client reads with
    // RFC 9001 s5.2's SERVER secret, so this client's own Initial packet replayed back at it
    // cannot open, and 0 processed / 1 discarded ended the attempt. No forgery, no path, no
    // secret - a pure replay, and the first stray internet datagram does it by accident.
    //
    // RFC 9000 s12.2, the whole sentence past the line wrap: "For example, if decryption fails
    // (because the keys are not available or for any other reason), the receiver MAY either
    // discard or buffer the packet for later processing and MUST attempt to process the
    // remaining packets." TlsQuicPacketReceiver's contract says it again in its own words - "a
    // failed decrypt is NOT an error and never sets CloseError" - and BuildAnswerDatagram
    // already argues the same rule 280 lines below, where a throw on a peer's conforming
    // HANDSHAKE_DONE is refused as "a one-datagram kill of the connection". This method used
    // to reach the opposite conclusion about the same hazard in the same file.
    //
    // DIAGNOSABILITY IS NOT LOST, IT MOVES. The failure a stall actually produces once nothing
    // kills the connection early is the handshake deadline, so the counters below are folded
    // into DeadlineExceeded's message. A non-zero DiscardedForMissingKeys there is the
    // coalescing stall PumpOnceAsync's remarks describe, told apart from a packet that simply
    // did not open, exactly as before.
    private void AccountForPacket(TlsQuicReceiveResult outcome)
    {
        if (outcome.CloseError is { } closeError)
        {
            // THE ONE THING HERE THAT STILL THROWS, AND THE ONE THING HERE THAT IS
            // AUTHENTICATED: per Receive, CloseError is set only by a check that ran on an
            // AEAD-authenticated packet, so no off-path sender can reach it. Task 9b turns it
            // into an s10.2 immediate close.
            throw new InvalidOperationException(
                $"The peer's packet requires the connection to close with {closeError}: "
                    + $"{outcome.CloseReason}");
        }

        DiscardedPackets += outcome.Discarded;
        DiscardedForMissingKeys += outcome.DiscardedForMissingKeys;
        if (outcome.Unprocessed != TlsQuicUnprocessedPacket.None)
        {
            // A Version Negotiation or a Retry packet. Both are task 9b's and neither is an
            // error here; counted so the deadline can say one arrived and was ignored.
            UnprocessedPackets++;
        }
    }

    private void InstallSecrets(TlsQuicProcessResult result)
    {
        // INSTALL, SEND, THEN DISCARD, in that order and at three separate points.
        //
        // Install first and PER RESULT rather than per datagram, because a flight is routinely
        // protected by keys the same result delivered: the Handshake packet coalesced behind
        // ServerHello is opened with secrets the ServerHello's own CRYPTO produced.
        //
        // Discard last because RFC 9001 s4.9 releases a level once its keys are "no longer
        // needed", and for this client that is after the send: s4.9.1's trigger is literally
        // sending the first Handshake packet, and the datagram that carries it also carries an
        // Initial ACK. THE ORDER IS LOAD-BEARING WITH RESPECT TO THE BUILD, AND NOT WITH
        // RESPECT TO THE SEND, and the two halves are separated here because an earlier
        // version of this remark claimed both. Discarding before BuildAnswerDatagram loses the
        // Initial ACK and is witnessed by
        // InitialKeysAreDiscardedAfterTheHandshakePacketIsBuiltAndNotBefore. Moving the
        // discard to between the build and the SendAsync changes no byte and leaves the whole
        // gate green, because the datagram is already assembled and TryGetWriteKeys is never
        // consulted again - there is no window. Recorded as a vacuous mutation rather than
        // given a test that would witness nothing.
        //
        // AND NOT BECAUSE THE RESULTS CARRY DISCARDS - they do not; see the check in
        // SendAnswerAsync, and the measurement that corrected an earlier version of this very
        // comment.
        foreach (var raised in result.Events)
        {
            if (raised is TlsQuicTrafficSecretEvent secret)
            {
                _keys.InstallFromTrafficSecret(secret.Secret);
            }
        }
    }

    // The peer's transport parameters reach this loop exactly once, on the result that
    // completes the handshake, and two things here read them: RFC 9000 s10.1's effective idle
    // timeout and s7.3's connection ID authentication. Both are done in one pass because both
    // want the same event and neither wants to be the reason the other was forgotten.
    //
    // THE VALUES ARE ALREADY WELL FORMED. EncryptedExtensionsParser calls
    // TlsQuicTransportParameters.ValidatePeer(TlsQuicEndpointRole.Server) before this event is
    // ever raised, so max_idle_timeout is a readable varint here rather than something
    // GetVariableInteger could throw on. What ValidatePeer cannot check is AGREEMENT with the
    // connection IDs actually used, because it holds no connection state - which is exactly
    // what s7.3 is about and why the second call below is not a duplicate of it.
    private async ValueTask ApplyPeerTransportParametersAsync(
        TlsQuicProcessResult result, CancellationToken cancellationToken)
    {
        foreach (var raised in result.Events)
        {
            if (raised is not TlsQuicPeerTransportParametersEvent peer)
            {
                continue;
            }

            _peerMaxIdleTimeout = ToIdleTimeout(
                peer.Parameters
                    .Get((ulong)TlsQuicTransportParameterId.MaxIdleTimeout)
                    ?.GetVariableInteger());

            // A3-4's SEAM, WIRED HERE, AND THE THIRD PARAMETER THIS METHOD RETAINS. RFC 9000
            // s18.2's two acknowledgement parameters - ack_delay_exponent (0x0a) and
            // max_ack_delay (0x0b) - arrived on this event and were dropped on the floor.
            // TlsQuicAckTracker.OnPeerAckParameters says so in its own remarks: "THIS IS THE
            // SEAM AND NOT THE WIRING. Nothing calls this yet ... Adding the two lines there is
            // a change to TlsQuicConnection.cs, which this task does not own; A3-5 or A3-7
            // does." A3-5 needs max_ack_delay for RFC 9002 s6.2.1's PTO period, so A3-5 is the
            // one that owes it.
            //
            // ABSENT IS NOT ZERO, AND FOR max_ack_delay THAT IS THE WHOLE POINT. The captured
            // s6.2 extract opens by saying it: "Chromium sends no max_ack_delay transport
            // parameter, so RFC 9000 s18.2's default applies and reading the term as zero would
            // compute a PTO shorter than the peer's." So the default is applied on absence
            // rather than a zero, and both defaults are TlsQuicAckTracker's constants rather
            // than literals restated here.
            //
            // THE TRACKER IS TOLD THE SAME PAIR IN THE SAME STEP. It clamps them itself and
            // exposes neither, so the connection clamps its own copy of max_ack_delay with the
            // tracker's own bound - the two lines below cannot disagree about a value because
            // they are computed from one expression.
            _peerMaxAckDelay = ToMaxAckDelay(
                peer.Parameters
                    .Get((ulong)TlsQuicTransportParameterId.MaxAckDelay)
                    ?.GetVariableInteger());
            _acks.OnPeerAckParameters(
                ToAckDelayExponent(
                    peer.Parameters
                        .Get((ulong)TlsQuicTransportParameterId.AckDelayExponent)
                        ?.GetVariableInteger()),
                _peerMaxAckDelay);

            // TASK 14d, AND THE ONE LINE FINDING 6 SAYS WAS MISSING. Everything about the six
            // limits - which parameter maps to which stream, what an absent one means, and why
            // the budget never grows - is in TlsQuicPeerFlowControlBudget.cs.
            _peerFlowControl = TlsQuicPeerFlowControlBudget.FromPeerParameters(peer.Parameters);

            await ValidateConnectionIdsUnderSection73(peer.Parameters, cancellationToken)
                .ConfigureAwait(false);

            // RFC 9114 s6.2's three-unidirectional-stream MUST, checked HERE rather than where
            // task 14e will open the streams, because there it is already too late to fail
            // cleanly: the budget would be exhausted mid-open with the control stream up and
            // QPACK's two not, and the connection would wait for a MAX_STREAMS this phase
            // never handles. That wait is the hang the task's done-when names.
            //
            // AFTER s7.3 AND NOT BEFORE IT, WHICH IS AN ORDERING WITH A CONSEQUENCE. A
            // parameter set can fail both checks, and the plan's own warning is that "a test
            // that exercises two checks pins only whichever fires first" - so the order is
            // chosen rather than inherited. s7.3 is RFC 9000's and authenticates the peer's
            // connection IDs; s6.2 is RFC 9114's and only asks whether HTTP/3 can proceed
            // over a peer already established as the one we addressed. Answering the second
            // about an unauthenticated peer would be answering the wrong question, and it
            // would also have converted two existing s7.3 witnesses into s6.2 ones - which is
            // exactly how the ordering was found, since both went red when this check was
            // first written above the s7.3 call.
            //
            // APPLICATION_ERROR AND NOT TRANSPORT_PARAMETER_ERROR. s20.1: "APPLICATION_ERROR
            // (0x0c):  The application or application protocol caused the connection to be
            // closed." The peer's parameters are perfectly legal QUIC - a 0 or a 2 is inside
            // every s18.2 bound - and it is HTTP/3 that cannot proceed on them, so reporting
            // a TRANSPORT_PARAMETER_ERROR would accuse the peer of a violation it did not
            // commit. The RFC 9114 s8.1 code that says this exactly, H3_GENERAL_PROTOCOL_ERROR
            // (0x0101), rides a CONNECTION_CLOSE of type 0x1d, which is subsystem C's frame.
            if (_peerFlowControl.DescribeSection62Violation(
                    _options.RequiredPeerUnidirectionalStreams) is { } violation)
            {
                await CloseAsync(
                        TlsQuicTransportError.ApplicationError, violation, cancellationToken)
                    .ConfigureAwait(false);
                throw new InvalidOperationException(violation);
            }
        }
    }

    /// <summary>Gets the peer's advertised flow-control budget, available once the peer's
    /// transport parameters have arrived in EncryptedExtensions.</summary>
    /// <exception cref="InvalidOperationException">The peer has not been heard from
    /// yet.</exception>
    internal TlsQuicPeerFlowControlBudget PeerFlowControl => _peerFlowControl
        ?? throw new InvalidOperationException(
            "The peer's transport parameters have not arrived yet, so it has advertised no "
                + "flow-control limits. Nothing may be sent on a stream before they do.");

    private void ApplyDiscards(TlsQuicProcessResult result)
    {
        foreach (var raised in result.Events)
        {
            if (raised is TlsQuicDiscardKeysEvent discard)
            {
                _keys.DiscardKeys(discard.Level);

                // RFC 9002 A.11 OnPacketNumberSpaceDiscarded, in its own order:
                // "RemoveFromBytesInFlight(sent_packets[pn_space])" and then
                // "sent_packets[pn_space].clear()". Both, and here rather than beside a
                // caller, because this is the ONE place a level's keys are discarded - the
                // two explicit calls that can raise the event (NotifyHandshakePacketSent for
                // Initial, ConfirmHandshake for Handshake) both funnel through it. A retained
                // Initial packet that outlives its keys can never be retransmitted - there is
                // nothing left to encrypt it with - and can never be acknowledged, since the
                // peer's ACK would arrive at a level whose read keys are gone, so it would
                // sit in bytes_in_flight forever on a connection that never completes.
                //
                // A.11's `assert(pn_space != ApplicationData)` is not transcribed as a throw:
                // TlsQuicKeySet.DiscardKeys is what decides which levels may be discarded and
                // it already refuses Application, so a check here would guard a state the
                // line above has made unreachable. The application space is bounded by
                // MaxRetainedPacketsPerSpace instead; see there.
                ForgetSpace(discard.Level);
            }
        }
    }

    // RFC 9002 A.1's OnPacketSent, drained from the scratch TlsQuicDatagramBuilder appended
    // to. Called in the same synchronous step as the build and BEFORE the await that sends,
    // which is what TlsQuicSentPacket's own remark relies on: "the connection loop builds and
    // sends in one synchronous step and passes the timestamp it is about to send with". A
    // send that throws leaves the packet retained, which over-counts bytes_in_flight for a
    // connection that is about to fail anyway; the alternative - retaining after the await -
    // would under-count for every packet already on the wire, which is the error that costs.
    private void RetainSentPackets()
    {
        foreach (var sent in _justSent)
        {
            OnPacketSent(sent);
        }

        _justSent.Clear();
    }

    /// <summary>RFC 9002 A.1's <c>OnPacketSent</c>: retain one packet in its space, and add
    /// its bytes to <see cref="BytesInFlight"/> if it counts toward them.</summary>
    /// <remarks>INTERNAL, AND NOT A TEST SEAM BOLTED ONTO A PRIVATE PATH - this IS the entry
    /// point <see cref="RetainSentPackets"/> calls for every packet the builder produced, so a
    /// test driving it drives the same code the send path does. What such a test does NOT
    /// prove is that the send path calls it; the loopback witnesses cover that half, and
    /// neither half is sufficient alone.</remarks>
    internal void OnPacketSent(in TlsQuicSentPacket sent)
    {
        var retained = _sentPackets[SpaceOf(sent.Level)];

        // The cap, applied BEFORE the Add so the list never exceeds it even momentarily.
        // A while rather than an if because the cap is read once per Add and any future
        // shrink would otherwise take one send per packet to converge; with a const cap
        // the loop body runs at most once, which is a property of the constant rather
        // than of this code, and that is exactly why the loop and not the if.
        while (retained.Count >= MaxRetainedPacketsPerSpace)
        {
            Forget(retained, 0);
        }

        retained.Add(sent);

        // RFC 9002 A.1's `if (in_flight): OnPacketSentCC(sent_bytes)`, and the ONE place
        // the two booleans are told apart. IsAckEliciting is not consulted here at all:
        // A.4 defines bytes_in_flight over "all sent packets that contain at least one
        // ack-eliciting or PADDING frame", and s13.2.7 makes a PADDING-only packet one of
        // them - in flight, eliciting nothing. TlsQuicPacketBuilder answers both
        // questions off the frames, and this reads its answers rather than re-deriving
        // either.
        //
        // THE EXCLUSION THAT IS INVISIBLE ON A HAPPY PATH: A.4's "Packets only containing
        // ACK frames do not count toward bytes_in_flight to ensure congestion control
        // does not impede congestion feedback." Such a packet is still RETAINED - A.1's
        // OnPacketSent stores every packet and gates only the accounting - so the list
        // growing while the counter does not move is the correct pair, and a test that
        // watched only the list would see nothing at all.
        if (sent.IsInFlight)
        {
            _bytesInFlight += sent.Size;
        }

        // RFC 9002 B.4's OnPacketSentCC, on A3-9's controller. It keeps its OWN bytes_in_flight
        // - its interface says so and says why: "a controller that took the connection's counter
        // could not be driven at all without a connection" - and this hands it every packet,
        // IsInFlight included, because B.2's exclusion is the controller's to apply.
        Congestion.OnPacketSent(sent);

        // RFC 9002 A.5's closing `SetLossDetectionTimer()`, and s6.2.1's "A sender SHOULD
        // restart its PTO timer every time an ack-eliciting packet is SENT or acknowledged, or
        // when Initial or Handshake keys are discarded." All three triggers reach the timer,
        // and this is the first: here rather than in RetainSentPackets so that the ONE entry
        // point A3-3 built for retention is also the one entry point for arming - the three
        // call sites A3-3 wired, BuildInitialFlight among them, are covered without any of
        // them knowing there is a timer. A.5 arms on every packet rather than only on an
        // ack-eliciting one; the condition lives in SetLossDetectionTimer, where A.8 puts it.
        SetLossDetectionTimer();
    }

    // RFC 9002 A.7's OnAckReceived, reduced to the one thing this task owns:
    // "newly_acked_packets = DetermineNewlyAckedPackets(ack, pn_space)" and then A.5's
    // `sent_packets[pn_space].remove(...)`. The RTT sample and the loss detection A.7 wraps
    // around it are A3-4's and A3-6's.
    //
    // THE SPACE COMES FROM THE ACK FRAME'S OWN LEVEL. RFC 9000 s13.1 confines an ACK frame to
    // the space it arrived in, so an ACK opened at Handshake can only ever remove Handshake
    // packets - never the Initial packet carrying the same number, which is a different
    // packet that happens to share a number.
    /// <summary>RFC 9002 A.7's <c>OnAckReceived</c>, reduced to A.5's removal: every retained
    /// packet in <paramref name="level"/>'s space that <paramref name="frame"/> names leaves
    /// the list, and its bytes leave <see cref="BytesInFlight"/>.</summary>
    /// <remarks>Internal for the same reason as <see cref="OnPacketSent"/>. NOTHING HERE
    /// THROWS FOR ANY FRAME: the argument is whatever the peer chose to send.</remarks>
    internal void OnAckReceived(TlsQuicEncryptionLevel level, in TlsQuicFrame frame)
    {
        _ackedRanges.Clear();

        // The second walk of the same chain. TlsQuicAckTracker.ProcessAckFrame walks it with
        // a null list because it needs only the verdict; this one needs the numbers. Reusing
        // TlsQuicAckFrames rather than decoding s19.3.1's Gap / ACK Range Length chain here
        // keeps the single decoder this phase requires. A false here cannot happen after
        // ProcessAckFrame returned true - same walker, same bytes - so it is a return and not
        // a throw: nothing on this path may throw on what the peer chose to send.
        if (!TlsQuicAckFrames.TryGetRanges(frame, _ackedRanges, out _))
        {
            return;
        }

        var retained = _sentPackets[SpaceOf(level)];
        var newlyAcked = false;

        // RFC 9002 A.7's newly_acked_packets. A3-3 needed no list because Forget did all the
        // work; B.5's OnPacketsAcked takes the packets themselves, so the loop below collects
        // them for it.
        var acked = new List<TlsQuicSentPacket>();

        // RFC 9002 s7.6's later anchor for THIS acknowledgement, kept local until the loss pass
        // below has run. See the assignment after DetectAndRemoveLostPackets.
        var latestAckedNow = DateTimeOffset.MinValue;

        // BACKWARDS, so the RemoveAt inside Forget cannot skip the element after a removal.
        //
        // AND OVER THE RETAINED PACKETS RATHER THAN OVER THE RANGES' CONTENTS. s19.3.1's
        // ranges are 62-bit numbers, so a peer may legally name a range spanning 2^62 packet
        // numbers in a handful of bytes; a loop from Smallest to Largest would be a remote
        // stall for the price of one datagram. The retained side is bounded by
        // MaxRetainedPacketsPerSpace and the range side by what fits in one frame, so this
        // costs the product of two bounded numbers and the peer can raise neither.
        for (var i = retained.Count - 1; i >= 0; i--)
        {
            if (Acknowledges(retained[i].PacketNumber))
            {
                // RFC 9002 s7.6's anchor, COLLECTED HERE AND APPLIED BELOW - see the
                // assignment after DetectAndRemoveLostPackets for why the order is the whole
                // point.
                if (retained[i].SentAt > latestAckedNow)
                {
                    latestAckedNow = retained[i].SentAt;
                }

                acked.Add(retained[i]);
                Forget(retained, i);
                newlyAcked = true;
            }
        }

        // B.5's OnPacketsAcked. BEFORE A.7's newly-acked return below, because a duplicate ACK
        // has an empty list here and the interface documents null and empty as the same thing -
        // so the call is harmless in the case the return would skip, and putting it above the
        // return keeps it beside the loop that built its argument.
        Congestion.OnPacketsAcked(acked);

        // RFC 9002 A.7's closing three lines, which A3-3 could not transcribe because there was
        // no timer to set: "// Reset pto_count unless the client is unsure if the server has
        // validated the client's address. if (PeerCompletedAddressValidation()): pto_count = 0
        // SetLossDetectionTimer()".
        //
        // A.7 GUARDS BOTH WITH `if (newly_acked_packets.empty()): return` SEVERAL LINES ABOVE,
        // and that guard is reproduced here as newlyAcked rather than dropped, because without
        // it a DUPLICATE ACK - one naming only packets already retired - would reset a backoff
        // that consecutive PTOs had earned. s6.2.1's own words for the same rule are narrower
        // than A.7's and would have permitted that: "a client does not reset the PTO backoff
        // factor on receiving acknowledgments in Initial packets" names the LEVEL, while A.7
        // names the predicate. For a client the two coincide - an ACK arriving at Handshake
        // level sets largest_acked for that space, which is the first disjunct of
        // PeerCompletedAddressValidation - so A.7's form is followed as the more precise
        // statement of the same rule rather than as a different one.
        if (!newlyAcked)
        {
            return;
        }

        // A.7's "lost_packets = DetectAndRemoveLostPackets(pn_space); if
        // (!lost_packets.empty()): OnPacketsLost(lost_packets)". THE FIRST OF THE THREE CALL
        // LINES A3-6 COULD NOT WRITE, and s6.2's prose says the same thing in words: "When an
        // acknowledgment is received that newly acknowledges packets, loss detection proceeds
        // as dictated by the packet and time threshold mechanisms; see Section 6.1."
        //
        // BEHIND A.7's newly-acked GUARD, which is where A.7 puts it - several lines below the
        // `if (newly_acked_packets.empty()): return` above. A duplicate ACK names nothing new,
        // so it moves neither largest_acked nor the retained set, and re-running A.10 on it
        // could only ever repeat the previous pass's verdict at a later now() - which is a
        // time threshold evaluated against a clock that has moved for no reason of the peer's.
        //
        // ITS RETURN IS DROPPED HERE AND THAT IS A SEAM RATHER THAN AN OMISSION. A.7's
        // consumer of the list is OnPacketsLost, which is the congestion controller's
        // (task A3-9) and the retransmitter's (task A3-8); neither exists and neither is
        // A3-7's file. What the list is NOT allowed to be is invisible, so
        // LastDetectedLost and PacketsDeclaredLost expose it - see TlsQuicLossDetection.cs.
        DetectAndRemoveLostPackets(level);

        // ====================================================================
        // s7.6's ANCHOR MOVES AFTER THE LOSS PASS, NOT DURING THE RETIRE LOOP.
        // ====================================================================
        //
        // TlsQuicPersistentCongestion.IsEstablished discards any lost packet whose send time is
        // BELOW latestAcknowledgedSendTime, so the anchor decides which lost packets are inside
        // the period at all. The acknowledgement that DECLARES a blackout lost is, by
        // construction, one that names a packet sent AFTER the blackout - it has to be, because
        // A.10 only considers packets below largest_acked. Folding that packet's send time into
        // the anchor before the loss pass would therefore discard every candidate the pass had
        // just produced, and s7.6 could never be established on a live connection at all.
        //
        // THIS IS NOT A JUDGEMENT CALL - IT IS THE SHAPE A3-10's OWN HARNESS PINS.
        // RunScriptedBlackoutAsync acknowledges an anchor packet, then loses a span, then calls
        // IsEstablished with `anchor.SentAt` - the packet acknowledged BEFORE the span, never
        // the one that ended it. One line later and this connection would disagree with the
        // test that defines the predicate, while every arithmetic assertion still passed.
        if (latestAckedNow > _latestAcknowledgedSendTime)
        {
            _latestAcknowledgedSendTime = latestAckedNow;
        }

        if (PeerCompletedAddressValidation())
        {
            _ptoCount = 0;
        }

        SetLossDetectionTimer();
    }

    private bool Acknowledges(ulong packetNumber)
    {
        foreach (var range in _ackedRanges)
        {
            // TlsQuicAckRange is inclusive at both ends - s19.3.1's ranges name the largest
            // and the smallest packet number they cover, not a half-open interval.
            if (packetNumber >= range.Smallest && packetNumber <= range.Largest)
            {
                return true;
            }
        }

        return false;
    }

    // RFC 9002 A.11's RemoveFromBytesInFlight over a whole space, and then its clear.
    /// <summary>RFC 9002 A.11's <c>OnPacketNumberSpaceDiscarded</c> for one space: the
    /// packets, their bytes in flight, and - since A3-8 - the RFC 9000 s13.3 repairs owed at
    /// that level all go.</summary>
    /// <remarks>INTERNAL SINCE A3-8, for the reason <see cref="OnPacketSent"/> gives about its
    /// own: this IS the method <see cref="ApplyDiscards"/> calls when a level's keys go, so a
    /// test driving it drives the same code a key discard does. s13.3's "Data in CRYPTO frames
    /// for Initial and Handshake packets is discarded when keys for the corresponding packet
    /// number space are discarded" is a claim about this method, and it had no witness at all
    /// while the method was private - the alternative was a test that fabricated a
    /// TlsQuicProcessResult carrying a discard event, which would have been witnessing its own
    /// fake.</remarks>
    internal void ForgetSpace(TlsQuicEncryptionLevel level)
    {
        var retained = _sentPackets[SpaceOf(level)];
        foreach (var sent in retained)
        {
            if (sent.IsInFlight)
            {
                _bytesInFlight -= sent.Size;
            }
        }

        // RFC 9002 B.9's RemoveFromBytesInFlight, which A3-9's interface spells out as
        // OnPacketsDiscarded and calls "NOT A CONGESTION EVENT". Before the Clear, because the
        // list is the argument. WITHOUT THIS THE WINDOW JAMS, in that interface's own words: "a
        // handshake's worth of Initial bytes stays in flight for the life of the connection and
        // permanently shrinks the room CanSend reports".
        Congestion.OnPacketsDiscarded(retained);

        retained.Clear();

        // A3-8's TWO CLEARS, AND THE SECOND IS A SENTENCE OF s13.3 RATHER THAN HOUSEKEEPING.
        // The ledger goes because the packets it describes have gone. The owed repairs go
        // because s13.3 says so in as many words: "Data in CRYPTO frames for Initial and
        // Handshake packets is discarded when keys for the corresponding packet number space
        // are discarded." Without the second line a repair owed at Initial would outlive the
        // keys that could protect it, and BuildAnswerDatagram's discarded-level arm would drop
        // it silently on every pass for the life of the connection.
        _repairable[SpaceOf(level)].Clear();
        _repairsOwed[(int)level].Clear();

        // A3-7's ONE LINE HERE, AND IT IS THE HALF OF s6.2.2's MUST THAT ONLY BECAME REACHABLE
        // WHEN loss_time GAINED A WRITER. "the PTO and loss detection timers MUST be reset" -
        // A.3's loss_time[pn_space] is the loss detection timer's state, and clearing the
        // retained list without clearing it would leave A.8's rung 1 arming from an instant
        // computed for a packet that no longer exists, in a space that can no longer
        // acknowledge anything. It cannot hang - the wake re-runs A.10, which walks an empty
        // list and clears the entry itself - but it is a wake owed to nothing, and s6.2.2 is
        // explicit that BOTH timers are reset.
        _lossTime[SpaceOf(level)] = null;

        // RFC 9002 s6.2.2, the third of s6.2.1's three triggers and the only one stated as a
        // MUST rather than a SHOULD: "When Initial or Handshake keys are discarded, the PTO and
        // loss detection timers MUST be reset, because discarding keys indicates forward
        // progress and the loss detection timer might have been set for a now-discarded packet
        // number space." A timer left armed for a space whose retained packets have just been
        // cleared would fire against nothing.
        SetLossDetectionTimer();
    }

    // The single exit from retention, so that "leaves the list" and "leaves bytes_in_flight"
    // cannot come apart. Every removal - acknowledged, capped, or key-discarded - goes
    // through here or through ForgetSpace, which is these same two lines over a whole space.
    private void Forget(List<TlsQuicSentPacket> retained, int index)
    {
        if (retained[index].IsInFlight)
        {
            _bytesInFlight -= retained[index].Size;
        }

        // A3-8's third line, and it is here rather than at the three call sites for exactly the
        // reason the two above it are: "leaves the list", "leaves bytes_in_flight" and "leaves
        // the repair ledger" cannot come apart if one method does all three.
        //
        // WHAT THIS LINE DOES AND DOES NOT DO, CORRECTED AFTER A MUTATION SWEEP SURVIVED IT.
        // An earlier version of this comment claimed the line enforced RFC 9000 s13.3's "A
        // sender SHOULD avoid retransmitting information from packets once they are
        // acknowledged". IT DOES NOT, and the survivor proved it: every reader of _repairable
        // looks the entry up by the number of a packet that is still RETAINED - A.10's loop and
        // AppendProbeData's second source are the only two - so an entry left behind by a
        // forgotten packet is unreachable, and s13.3's SHOULD is satisfied by the RemoveAt
        // below rather than by this line. What this line actually buys is that the ledger stays
        // bounded by retention instead of growing for the life of the connection. That is worth
        // having and it is not the same claim.
        _repairable[SpaceOf(retained[index].Level)].Remove(retained[index].PacketNumber);

        retained.RemoveAt(index);
    }

    // RFC 9000 s12.3's three spaces, collapsing 0-RTT and 1-RTT onto the one application data
    // space they share.
    //
    // THE THIRD COPY IS GONE, AND THIS RECORDS THAT THE BLOCKER WENT WITH IT. A3-3 wrote a
    // private copy here and named the reason in its own comment - "TlsQuicAckTracker.SpaceOf
    // is private, and this task's brief forbids editing that file". A3-4 widened that method
    // to internal, so the first half of the reason stopped being true and the second half no
    // longer costs anything: reusing it is a read, not an edit. The copy is now a forward to
    // the tracker's, which is the reuse the A3 plan asked A3-3 for and A3-3 could not have.
    //
    // TWO COPIES REMAIN IN THE ASSEMBLY, NOT ONE, AND THIS TASK DELIBERATELY LEAVES THE OTHER.
    // TlsQuicPacketReceiver holds a private one of its own. It is not this task's file and
    // collapsing it is a separate edit with its own gate; it is named here so the remaining
    // duplication is a recorded choice rather than something nobody noticed.
    //
    // TlsQuicConnectionTests.AZeroRttPacketAndAOneRttPacketShareOneSpace pins the collapse
    // from outside, and it pins it through THIS forward, so a divergence between the two
    // mappings can no longer exist to be pinned.
    private static int SpaceOf(TlsQuicEncryptionLevel level) => TlsQuicAckTracker.SpaceOf(level);

    private TimeSpan RemainingBeforeDeadline() =>
        _deadline - _options.TimeProvider.GetUtcNow();

    // ============================================================================
    // THE TIMER WEAVE - A3-5. AN ADDITION TO THIS LOOP, NOT A SPLIT OF IT, AND THE
    // MEASUREMENT THAT SETTLED THAT IS RECORDED HERE RATHER THAN THE ARGUMENT FOR IT.
    // ============================================================================
    //
    // The A3 scoping named this task's shape as the phase's largest single uncertainty: is a
    // deadline that fires with no datagram to trigger it an ADDITION to the single loop or a
    // SPLIT of it? The plan's own suggested way to find out was to drive the EXISTING idle
    // timeout through a new deadline entry before writing any recovery code and see what that
    // cost. That was done first, as its own gate run: the two deadlines that already bounded
    // the receive - the handshake deadline and RFC 9000 s10.1's idle timeout - were routed
    // through one earliest-of table, and the whole Quic gate stayed green with ELEVEN LINES
    // ADDED, SIX REMOVED AND NOT ONE TEST TOUCHED. A third entry therefore costs one more
    // comparison in this method and no new thread, no pump, no synchronisation.
    //
    // THE REASON IT IS THAT CHEAP IS THAT THE MECHANISM WAS ALREADY HERE. ReceiveWithinDeadline
    // Async has raced the receive against a CancellationTokenSource built on the injected
    // TimeProvider since A4-minimal - that is how a silent peer is bounded at all. A3-5 does
    // not add a timer; it adds an ENTRY to the set of deadlines that timer is armed from, and
    // a branch on which entry won. ONE LOOP, ONE THREAD OF CONTROL survives untouched, because
    // a CancellationTokenSource built this way has no callback into connection state: the only
    // thing it can do is end an await THIS thread is sitting in.
    //
    // AND THAT IS ALSO THE ANSWER TO "a timer that fires while a datagram is being processed
    // must not produce two concurrent send passes". It cannot, by construction rather than by
    // locking. The source is created inside ReceiveWithinDeadlineAsync, is disposed by its own
    // using before that method returns, and is never given a callback - so while PumpOnceAsync
    // is walking a datagram there is no armed source in existence, and if there were,
    // cancelling it would touch nothing. The witness is a test that puts a released datagram
    // and an expired timer in the same pump and asserts exactly one datagram left the client.
    //
    // A FOURTH ENTRY SINCE A3-11, AND IT IS A THIRD KIND. The two abandonments END the attempt
    // and A.8's recovery timer means "run A.9". RFC 9002 s7.7's pacing release means neither:
    // it says "the datagram you held may leave now", so the wake must run the ordinary send
    // pass and must NOT run OnLossDetectionTimeout - a spurious A.9 would advance pto_count and
    // send a probe for a timer that never expired. The bool this method used to return could
    // not say that, which is why it is an enum now; the two existing callers branch on the
    // three cases and nothing else reads it.
    //
    // AND THE PACING ENTRY IS WHAT MAKES THE PACER SAFE. Without it a connection holding paced
    // data and receiving nothing would sit in the receive until an abandonment deadline fired -
    // a pacer that never releases, which is the second of the two ways this task could wedge a
    // connection. With it the release instant is raced like every other, and the minimum
    // argument above still holds: a fourth entry can only ever SHORTEN the wait.
    private (DateTimeOffset At, TlsQuicDeadlineKind Kind) EarliestDeadline()
    {
        var at = _deadline;

        var idle = IdleDeadline();
        if (idle < at)
        {
            at = idle;
        }

        // STRICTLY EARLIER, so a recovery timer that merely TIES with an abandonment deadline
        // loses. The tie broken the other way would answer a probe on an attempt that has run
        // out of time; the post-wake check would then abandon on the very next pass, so the
        // only difference is one pointless datagram on the wire per tie.
        var kind = TlsQuicDeadlineKind.Abandonment;
        if (_lossDetectionTimer is { } loss && loss < at)
        {
            at = loss;
            kind = TlsQuicDeadlineKind.Recovery;
        }

        // STRICTLY EARLIER AGAIN, so pacing loses every tie it is in. A tie with an abandonment
        // is decided the way the loss timer's is; a tie with the loss timer goes to the loss
        // timer, because A.9 is an obligation and a pacing release is a permission - and the
        // pass A.9 wakes for runs the ordinary send anyway, so the paced datagram leaves on
        // that wake too.
        if (PacingReleaseAt is { } release && release < at)
        {
            at = release;
            kind = TlsQuicDeadlineKind.Pacing;
        }

        // A FIFTH ENTRY - RFC 9000 s13.2.1's max_ack_delay - AND IT IS WHAT MAKES KNOB 12's
        // SECOND VALUE LEGAL RATHER THAN MERELY DIFFERENT. TlsQuicAckTracker withholds the
        // acknowledgement; nothing but this line brings it back out when no datagram arrives to
        // flush it, and a delay with no bound is the violation s13.2.1 names rather than the
        // batching it permits. Null under the shipped default, so every path that does not set
        // the knob reaches the return below exactly as it did before.
        //
        // STRICTLY EARLIER ONCE MORE, so this loses every tie it is in - including against
        // pacing, whose early return above became an assignment for this one line. That
        // rewrite is behaviour-preserving by inspection: with no ACK held back the condition
        // below is false and `at`/`kind` carry pacing's own answer to the same return.
        //
        // A TIE THAT GOES TO AN ABANDONMENT IS NOT A MISSED ACK. The attempt ends on that
        // pass, so the acknowledgement has no connection left to travel on; the promise
        // s13.2.1 makes is to a peer this endpoint is about to stop talking to.
        if (_acks.DelayedAckDeadline is { } ackDue && ackDue < at)
        {
            return (ackDue, TlsQuicDeadlineKind.DelayedAck);
        }

        return (at, kind);
    }

    /// <summary>RFC 9002 A.3's <c>loss_detection_timer</c> as an instant, or
    /// <see langword="null"/> when A.8 cancelled it.</summary>
    internal DateTimeOffset? LossDetectionTimer => _lossDetectionTimer;

    /// <summary>The packet number space A.8's <c>GetPtoTimeAndSpace</c> named when it armed
    /// <see cref="LossDetectionTimer"/>, or <see langword="null"/> when nothing is armed.
    /// </summary>
    internal TlsQuicEncryptionLevel? LossDetectionSpace => _lossDetectionSpace;

    /// <summary>RFC 9002 A.3's <c>pto_count</c>.</summary>
    internal int PtoCount => _ptoCount;

    /// <summary>How many times A.9's <c>OnLossDetectionTimeout</c> has run - which is how many
    /// times this loop woke on a deadline with no datagram to wake it.</summary>
    internal int LossDetectionTimeouts { get; private set; }

    // RFC 9002 A.8's SetLossDetectionTimer, rung by rung, with the two rungs this task does
    // not own named rather than silently absent.
    //
    // RUNG 1 - GetLossTimeAndSpace - IS WIRED BY A3-7 AND IS THE SECOND OF THE THREE CALL
    // LINES A3-6 COULD NOT WRITE. A.8 opens with "earliest_loss_time, _ =
    // GetLossTimeAndSpace(); if (earliest_loss_time != 0): loss_detection_timer.update(
    // earliest_loss_time); return", and loss_time[] is written by exactly one thing - A.10's
    // DetectAndRemoveLostPackets, which A3-6 built and A3-7 called. THE RETURN IS s6.2.1's
    // MUST NOT, not a shortcut: "The PTO timer MUST NOT be set if a timer is set for time
    // threshold loss detection; see Section 6.1.2. A timer that is set for time threshold loss
    // detection will expire earlier than the PTO timer in most cases and is less likely to
    // spuriously retransmit data." Falling through to rung 4 would arm a PTO while a loss
    // timer was owed, which is that MUST NOT verbatim.
    //
    // RUNG 2 - "if (server is at anti-amplification limit)" - CANNOT APPLY TO THIS TYPE. RFC
    // 9000 s8.1's three-times limit binds a SERVER, and s6.2.2.1 says so twice: "the amount of
    // data IT can send", "the SERVER's PTO timer MUST NOT be armed". This is a client. The
    // client's half of that same section is the opposite instruction - it MUST arm the timer
    // to unblock the server - and that is rung 3's condition, which is transcribed.
    //
    // RUNGS 1, 3 AND 4 ARE ALL HERE; RUNG 2 IS THE ONLY ONE THAT IS NOT.
    private void SetLossDetectionTimer()
    {
        // A.8's rung 1. A.10 only ever writes a loss_time STRICTLY IN THE FUTURE - it sets
        // `unacked.time_sent + loss_delay` on the else arm of a test whose true arm is
        // `time_sent <= now - loss_delay`, so the two are exact complements - which is why
        // this needs no separate argument for terminating. The kGranularity floor is applied
        // anyway, through the same ArmAt the other two arming rungs use, so that EVERY wait
        // this weave produces is strictly positive on the connection's own clock however the
        // instant was computed; see ArmAt.
        if (GetLossTimeAndSpace() is { } earliestLoss)
        {
            ArmAt(earliestLoss.At, earliestLoss.Space);
            return;
        }

        // A.8: "if (no ack-eliciting packets in flight && PeerCompletedAddressValidation()):
        // There is nothing to detect lost, so no timer is set. However, the client needs to
        // arm the timer if the server might be blocked by the anti-amplification limit."
        if (!HasAckElicitingPacketsInFlight() && PeerCompletedAddressValidation())
        {
            _lossDetectionTimer = null;
            _lossDetectionSpace = null;
            return;
        }

        var (at, space) = GetPtoTimeAndSpace();

        // A.8's `pto_timeout = infinite` REACHING `loss_detection_timer.update(timeout)` IS THE
        // FIRST OF THIS TASK'S PROSE-BEATS-PSEUDOCODE CALLS, AND IT IS ALSO A C# HAZARD.
        // GetPtoTimeAndSpace's loop returns early, still holding infinite, when the only space
        // with ack-eliciting packets in flight is Application Data and the handshake is not
        // confirmed. A.8 then hands that infinity to update(). s6.2.1's prose is a MUST NOT in
        // the other direction - "An endpoint MUST NOT set its PTO timer for the Application
        // Data packet number space until the handshake is confirmed" - and set-to-infinity is
        // not not-set, it is a timer. THE PROSE IS FOLLOWED: the timer is cancelled. In C# the
        // pseudocode is not merely wrong, it throws - infinity is DateTimeOffset.MaxValue, and
        // MaxValue minus now is a TimeSpan no CancellationTokenSource will accept.
        // AnApplicationDataOnlyFlightBeforeConfirmationLeavesTheTimerUnarmed pins the null AND
        // pins that it is not MaxValue, because "not equal to MaxValue" would pass on a timer
        // armed anywhere else at all.
        if (at == DateTimeOffset.MaxValue)
        {
            _lossDetectionTimer = null;
            _lossDetectionSpace = null;
            return;
        }

        // AND THE ONE PLACE THIS DEPARTS FROM A.8's LETTER FOR A REASON A.8 CANNOT SEE. A.8:
        // "This algorithm may result in the timer being set in the past, particularly if timers
        // wake up late. Timers set in the past fire immediately." On a wall clock that is
        // self-limiting, because the NEXT period is computed from a later now(). This
        // connection runs on an INJECTED TimeProvider and A3-1's ManualTimeProvider can hold it
        // perfectly still - and then a timer computed from a fixed send instant is in the past
        // for ever: the pump wakes, sends nothing (probe CONTENTS are A3-7's, so
        // time_of_last_ack_eliciting_packet does not move), re-arms at the same instant and
        // wakes again, an unbounded loop no deadline ends because no deadline moves either.
        // THE FLOOR IS WHY THAT CANNOT HAPPEN, and it is a floor rather than an argument: an
        // armed timer is always at least kGranularity in the future on the connection's own
        // clock, so every wait this weave produces is strictly positive and a repeat costs the
        // caller a clock advance. On a wall clock the floor is a one-millisecond rounding.
        ArmAt(at, space);
    }

    // The two arming rungs' one landing place, extracted by A3-7 when rung 1 became a third
    // caller. The floor and its whole argument are A3-5's and are unchanged.
    private void ArmAt(DateTimeOffset at, TlsQuicEncryptionLevel space)
    {
        var floor = AddSaturating(_options.TimeProvider.GetUtcNow(), KGranularity);
        _lossDetectionTimer = at < floor ? floor : at;
        _lossDetectionSpace = space;
    }

    // RFC 9002 A.8's PeerCompletedAddressValidation, the CLIENT arm of it. A.8: "Assume clients
    // validate the server's address implicitly. if (endpoint is server): return true ... return
    // has received Handshake ACK || handshake confirmed."
    //
    // s6.2.2.1 states the same condition as the client's MUST, in the negative and in prose:
    // "the client MUST set the PTO timer if the client has not received an acknowledgment for
    // any of its Handshake packets and the handshake is not confirmed ... EVEN IF THERE ARE NO
    // PACKETS IN FLIGHT." That last clause is exactly why rung 3 is an AND of two conditions
    // and not a test for in-flight packets alone, and it is the whole reason a client arms a
    // PTO at all before it has heard anything back.
    private bool PeerCompletedAddressValidation() =>
        _acks.LargestAcked(TlsQuicEncryptionLevel.Handshake) is not null || _confirmed;

    // A.8's "no ack-eliciting packets in flight", over all three spaces. NOT BytesInFlight == 0,
    // and the difference is A.4's: bytes_in_flight counts a PADDING-only packet, which is in
    // flight and elicits nothing, and excludes an ACK-only packet, which is neither. The two
    // booleans are already told apart on TlsQuicSentPacket; this reads both rather than
    // re-deriving either.
    private bool HasAckElicitingPacketsInFlight()
    {
        foreach (var space in _sentPackets)
        {
            foreach (var sent in space)
            {
                if (sent.IsAckEliciting && sent.IsInFlight)
                {
                    return true;
                }
            }
        }

        return false;
    }

    // RFC 9002 A.8's GetPtoTimeAndSpace, transcribed with the arithmetic made C#-safe.
    private (DateTimeOffset At, TlsQuicEncryptionLevel Space) GetPtoTimeAndSpace()
    {
        // A.8's duration, with max_ack_delay ZERO. s6.2.1: "When the PTO is armed for Initial
        // or Handshake packet number spaces, the max_ack_delay in the PTO period computation is
        // set to 0, since the peer is expected to not delay these packets intentionally." The
        // Application Data arm below is the only one that adds it back.
        var duration = PtoDuration(TimeSpan.Zero);

        // A.8's anti-deadlock PTO, and its own comment: "Anti-deadlock PTO starts from the
        // current time". A.8 asserts !PeerCompletedAddressValidation() here; that assert is not
        // transcribed as a throw, because the only caller checked the same predicate one method
        // up and a throw would turn a caller ordering bug into a dead connection on the one
        // path whose whole job is to keep one alive. The space is the one A.9 would probe in -
        // a Handshake packet if we can build one, otherwise a padded Initial.
        if (!HasAckElicitingPacketsInFlight())
        {
            var antiDeadlockSpace =
                _keys.TryGetWriteKeys(TlsQuicEncryptionLevel.Handshake, out _, out _)
                    ? TlsQuicEncryptionLevel.Handshake
                    : TlsQuicEncryptionLevel.Initial;
            return (
                AddSaturating(_options.TimeProvider.GetUtcNow(), duration), antiDeadlockSpace);
        }

        // A.8's `pto_timeout = infinite; pto_space = Initial`.
        var at = DateTimeOffset.MaxValue;
        var space = TlsQuicEncryptionLevel.Initial;

        foreach (var level in PtoSpaces)
        {
            // A.8: "if (no ack-eliciting packets in flight in space): continue". PER SPACE, and
            // that is what makes s6.2.1's "the timer MUST be set to the EARLIER value of the
            // Initial and Handshake packet number spaces" fall out of a minimum rather than
            // need a rule of its own - a space with nothing in flight cannot win a minimum it
            // never enters.
            if (LastAckElicitingSendIn(level) is not { } sentAt)
            {
                continue;
            }

            var levelDuration = duration;
            if (level == TlsQuicEncryptionLevel.Application)
            {
                // A.8: "Skip Application Data until handshake confirmed" - and A.8 RETURNS
                // rather than continues, which matters because Application is last: the return
                // carries whatever Initial and Handshake decided, or infinite if neither had
                // anything in flight. See SetLossDetectionTimer for what is done with that
                // infinity and why it is not what A.8 says.
                if (!_confirmed)
                {
                    return (at, space);
                }

                // A.8: "Include max_ack_delay and backoff for Application Data."
                levelDuration = PtoDuration(_peerMaxAckDelay);
            }

            var t = AddSaturating(sentAt, levelDuration);
            if (t < at)
            {
                at = t;
                space = level;
            }
        }

        return (at, space);
    }

    // A.3's time_of_last_ack_eliciting_packet[pn_space], DERIVED rather than held in a field of
    // its own. A.8 reads it only inside the arm that has already established there are
    // ack-eliciting packets in flight in this space, and for that arm the latest send time
    // among exactly those packets is the same number - so a field would be a second source of
    // truth for something the retained list already knows. Null is A.8's continue.
    private DateTimeOffset? LastAckElicitingSendIn(TlsQuicEncryptionLevel level)
    {
        DateTimeOffset? latest = null;
        foreach (var sent in _sentPackets[SpaceOf(level)])
        {
            if (sent.IsAckEliciting && sent.IsInFlight && (latest is null || sent.SentAt > latest))
            {
                latest = sent.SentAt;
            }
        }

        return latest;
    }

    // RFC 9002 s6.2.1's PTO period, with s6.2.1's own backoff applied and every step saturating
    // instead of throwing.
    //
    //   "PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay"
    //
    // and, for the backoff, "When a PTO timer expires, the PTO backoff MUST be increased,
    // resulting in the PTO period being set to twice its current value." A.8 writes that as
    // `duration = (smoothed_rtt + max(4 * rttvar, kGranularity)) * (2 ^ pto_count)` with
    // `duration += max_ack_delay * (2 ^ pto_count)` for Application Data - the same thing,
    // since both terms carry the same power. The two agree once the wrap is read past. The
    // factor is TlsQuicRecoverySpec.PtoBackoff's rather than a literal 2, which is knob 9.
    //
    // THE SECOND PROSE-BEATS-PSEUDOCODE CALL IS THE FLOOR. s6.2.1: "The PTO period MUST be at
    // least kGranularity to avoid the timer expiring immediately." A.8 has no such clamp, and
    // in A.8 it is redundant - max(4 * rttvar, kGranularity) already dominates kGranularity and
    // 2^pto_count never shrinks it. IT IS NOT REDUNDANT HERE, because A3-2 added a knob the RFC
    // does not have: PtoBackoff.Maximum, a ceiling, which its own remarks call an
    // implementation choice a caller may take. A ceiling below kGranularity would produce
    // exactly the immediately-expiring timer the MUST forbids. THE PROSE IS FOLLOWED: the clamp
    // is applied after the ceiling, so a ceiling can shorten the period but not below the
    // floor. ACeilingBelowTheTimerGranularityIsRaisedToItRatherThanHonoured pins that the armed
    // period is kGranularity and NOT the one-tick ceiling that was asked for.
    private TimeSpan PtoDuration(TimeSpan maxAckDelay)
    {
        // DOUBLE TICKS THROUGHOUT, AND THAT IS A C# HAZARD RATHER THAN A STYLE. Every input
        // here is peer-influenced or clock-influenced: smoothed_rtt and rttvar come from sample
        // arithmetic on an injected clock, max_ack_delay is a transport parameter, and pto_count
        // is A.9's unbounded counter. TimeSpan's own * and + operators THROW on overflow, and
        // this method sits on the path a silent peer takes - so a throw here would be a
        // connection killed by arithmetic on numbers a peer chose.
        var variation = Math.Max((double)_acks.RttVariation.Ticks * 4.0, KGranularity.Ticks);
        var period = (double)_acks.SmoothedRtt.Ticks + variation + maxAckDelay.Ticks;

        var backoff = _options.Spec.Recovery.PtoBackoff;
        var scaled = FromTicksSaturating(period * Math.Pow(backoff.Factor, _ptoCount));

        if (backoff.Maximum is { } ceiling && scaled > ceiling)
        {
            scaled = ceiling;
        }

        return scaled < KGranularity ? KGranularity : scaled;
    }

    // Saturating, and never NaN: Math.Pow overflows to positive infinity long before pto_count
    // reaches its cap, and infinity times a zero period is NaN, which compares false against
    // every bound and would slip through a pair of range checks written the obvious way.
    private static TimeSpan FromTicksSaturating(double ticks) =>
        double.IsNaN(ticks) || ticks <= 0 ? TimeSpan.Zero
        : ticks >= long.MaxValue ? TimeSpan.MaxValue
        : new TimeSpan((long)ticks);

    // DateTimeOffset's operator+ throws when the sum leaves the calendar; every instant this
    // adds to is a real send time and every span is PtoDuration's, which saturates at
    // TimeSpan.MaxValue, so the sum overflowing is reachable rather than theoretical.
    private static DateTimeOffset AddSaturating(DateTimeOffset at, TimeSpan span) =>
        span > DateTimeOffset.MaxValue - at ? DateTimeOffset.MaxValue : at + span;

    // A.8's `for space in [ Initial, Handshake, ApplicationData ]`, in that order, which the
    // Application arm's early return makes load-bearing rather than cosmetic.
    private static readonly TlsQuicEncryptionLevel[] PtoSpaces =
    [
        TlsQuicEncryptionLevel.Initial,
        TlsQuicEncryptionLevel.Handshake,
        TlsQuicEncryptionLevel.Application,
    ];

    // RFC 9002 A.9's OnLossDetectionTimeout, COMPLETE AS OF A3-7 except for OnPacketsLost.
    //
    // WHAT A3-5 LEFT: A.9's `pto_count++`, its closing `SetLossDetectionTimer()`, and the fact
    // of the wake itself - the caller returns an empty receive result and PumpOnceAsync then
    // runs its ordinary send pass with no datagram received.
    //
    // WHAT A3-7 ADDS: A.9's first rung - the THIRD of the three call lines A3-6 could not write
    // - and both send rungs. THE FIRST RUNG'S `return` IS LOAD-BEARING AND IS EASY TO
    // TRANSCRIBE AWAY. A.9 returns out of the loss arm BEFORE `pto_count++`, so a wake caused
    // by the time threshold does not back the PTO off; s6.2 states the same separation in
    // prose, from the other side: "A PTO timer expiration event does not indicate packet loss
    // and MUST NOT cause prior unacknowledged packets to be marked as lost." The two arms are
    // different events that share one timer, and both halves of that sentence are structural
    // here - the loss arm declares and does not back off, the PTO arm backs off and declares
    // nothing.
    //
    // A.9's `assert(!lost_packets.empty())` IS NOT TRANSCRIBED, and it is a third RFC self-
    // contradiction rather than a liberty. A.8's rung 1 arms from loss_time, and A.10 sets
    // loss_time to `time_sent + loss_delay` for a packet it did NOT declare lost; between the
    // arming and the firing an acknowledgement can retire that very packet through
    // OnAckReceived, which re-runs A.10 and rebuilds loss_time - but a timer already armed for
    // a now-empty space still fires, because SetLossDetectionTimer's floor may hold the new
    // instant later without cancelling the old wake. The assert would then kill a healthy
    // connection for an event that means "nothing left to lose". It is a no-op instead.
    //
    // A.9's `assert(!PeerCompletedAddressValidation())` is likewise not transcribed, for the
    // reason GetPtoTimeAndSpace gives about its twin.
    /// <summary>RFC 9002 A.9's <c>OnLossDetectionTimeout</c>.</summary>
    /// <remarks>INTERNAL SINCE A3-7, for the reason <see cref="OnPacketSent"/> gives about its
    /// own: this IS the entry point <see cref="ReceiveWithinDeadlineAsync"/> calls on a
    /// recovery wake, so a test driving it drives the same code the pump does. What such a
    /// test does NOT prove is that the pump calls it, or that the probe this leaves owed ever
    /// reaches a transport; the live witnesses in TlsQuicConnectionProbeTimeoutTests cover
    /// both halves and neither half is sufficient alone.</remarks>
    internal void OnLossDetectionTimeout()
    {
        LossDetectionTimeouts++;

        // A.9's rung 1: "earliest_loss_time, pn_space = GetLossTimeAndSpace(); if
        // (earliest_loss_time != 0): lost_packets = DetectAndRemoveLostPackets(pn_space);
        // ... SetLossDetectionTimer(); return".
        if (GetLossTimeAndSpace() is { } earliestLoss)
        {
            DetectAndRemoveLostPackets(earliestLoss.Space);
            SetLossDetectionTimer();
            return;
        }

        // A.9's two send rungs, DECIDED HERE AND SENT BY THE PUMP. The split is A3-5's design
        // and its comment at the call site states it: "A.9 runs BEFORE the send pass and on
        // this same thread, so pto_count and the re-armed timer are settled by the time
        // PumpOnceAsync builds anything." This method is synchronous because A.1's OnPacketSent
        // path is; the probe is a datagram and a datagram needs an await.
        //
        // THE TWO RUNGS ARE NOT THE SAME EVENT AND CONFLATING THEM COSTS IN BOTH DIRECTIONS.
        //
        //   ANTI-DEADLOCK (nothing in flight). A.9: "Client sends an anti-deadlock packet:
        //   Initial is padded to earn more anti-amplification credit, a Handshake packet proves
        //   address ownership." RFC 9000 s8.1 states it as the client's MUST: "To prevent this
        //   deadlock, clients MUST send a packet on a Probe Timeout (PTO) ... Specifically, the
        //   client MUST send an Initial packet in a UDP datagram that contains at least 1200
        //   bytes if it does not have Handshake keys, and otherwise send a Handshake packet."
        //   ONE packet - A.9's names are SendOneAckElicitingHandshakePacket and
        //   SendOneAckElicitingPaddedInitialPacket, both singular. Reaching this arm at all
        //   requires A.8 rung 3 to have armed the timer with nothing in flight, which it does
        //   only while PeerCompletedAddressValidation() is false. A client that probed with
        //   nothing in flight AFTER validation would be spamming a server that is not blocked;
        //   one that did not probe BEFORE it is the deadlock s8.1 exists to break.
        //
        //   PTO (something in flight). A.9: "_, pn_space = GetPtoTimeAndSpace();
        //   SendOneOrTwoAckElicitingPackets(pn_space)", and s6.2.4's "An endpoint MAY send up
        //   to two full-sized datagrams containing ack-eliciting packets" is knob 10.
        //
        // THE SPACE IS GetPtoTimeAndSpace's IN BOTH ARMS, which is not a simplification: its
        // own anti-deadlock arm already returns "a Handshake packet if we can build one,
        // otherwise a padded Initial", which is s8.1's sentence, and its loop returns the space
        // whose PTO expired otherwise. Recomputing that choice here would be a second place to
        // keep s8.1 in step with A.8.
        var antiDeadlock = !HasAckElicitingPacketsInFlight();
        var (_, probeSpace) = GetPtoTimeAndSpace();
        _owedProbe = (
            probeSpace,
            antiDeadlock ? 1 : _options.Spec.Recovery.ProbePacketsPerPto);

        // A.9's `pto_count++`, capped. See MaximumPtoCount: uncapped, the transcription
        // eventually wraps negative and the backoff inverts into a speed-up.
        //
        // AFTER the probe is decided and before the re-arm, which is A.9's order. It matters:
        // GetPtoTimeAndSpace above reads pto_count through PtoDuration, and A.9 chooses the
        // probe's space with the count that produced the expiry rather than with its successor.
        if (_ptoCount < MaximumPtoCount)
        {
            _ptoCount++;
        }

        SetLossDetectionTimer();
    }

    /// <summary>The packet number space A.9 last chose to probe in and how many datagrams it
    /// owed, or <see langword="null"/> when no probe is outstanding.</summary>
    /// <remarks>A DEBT RATHER THAN A SEND, because A.9 is synchronous and a datagram is not.
    /// <see cref="SendOwedProbeAsync"/> is what discharges it, on the pump's own send pass.
    /// </remarks>
    internal (TlsQuicEncryptionLevel Space, int Datagrams)? OwedProbe => _owedProbe;

    private (TlsQuicEncryptionLevel Space, int Datagrams)? _owedProbe;

    // RFC 9002 s7.6's anchor: the send time of the latest packet acknowledged BEFORE the
    // acknowledgement currently being processed. See OnAckReceived, which explains why "before"
    // is load-bearing rather than incidental.
    //
    // SEEDED AT MinValue, WHICH IS NOT A SENTINEL AND NEEDS NO NULL. Before any acknowledgement
    // the predicate filters nothing on this term - and it cannot fire at all, because its own
    // first test is that an RTT sample exists and a sample needs an acknowledgement. Read only
    // by DetectAndRemoveLostPackets, through TlsQuicPersistentCongestion.IsEstablished.
    private DateTimeOffset _latestAcknowledgedSendTime = DateTimeOffset.MinValue;

    /// <summary>How many probe datagrams this connection has put on the wire because a probe
    /// timeout expired.</summary>
    internal int ProbeDatagramsSent { get; private set; }

    /// <summary>The encryption level of the last probe packet built, or
    /// <see langword="null"/> if none has been.</summary>
    internal TlsQuicEncryptionLevel? LastProbeLevel { get; private set; }

    /// <summary>The byte length of the last probe DATAGRAM built - RFC 9000 s8.1's "a UDP
    /// datagram that contains at least 1200 bytes" is a claim about this number and not about
    /// the packet inside it.</summary>
    internal int LastProbeDatagramBytes { get; private set; }

    // RFC 9002 A.9's SendOneAckElicitingHandshakePacket, SendOneAckElicitingPaddedInitialPacket
    // and SendOneOrTwoAckElicitingPackets, which differ here only in the space and the count -
    // see OnLossDetectionTimeout for why the space is A.8's answer in all three cases.
    //
    // NOTHING HERE THROWS AND NOTHING HERE LOOPS UNBOUNDED. The count is knob 10, which
    // TlsQuicRecoverySpec bounds to 1 or 2 at the setter; the level's keys may be absent, which
    // is a return rather than a throw, because "the level whose PTO expired has had its keys
    // discarded" is an ordinary race with RFC 9001 s4.9's discards and not a defect. AND THE
    // DEBT IS CLEARED BEFORE THE FIRST SEND, so a send that throws cannot leave a probe owed
    // for ever - the next expiry re-owes it, which is what the backoff is for.
    private async ValueTask SendOwedProbeAsync(CancellationToken cancellationToken)
    {
        if (_owedProbe is not { } owed)
        {
            return;
        }

        _owedProbe = null;

        for (var i = 0; i < owed.Datagrams; i++)
        {
            if (!TryBuildProbeDatagram(owed.Space, out var written))
            {
                return;
            }

            await _options.Transport
                .SendAsync(
                    _options.RemoteEndPoint,
                    _sendBuffer.AsMemory(0, written),
                    cancellationToken)
                .ConfigureAwait(false);

            ProbeDatagramsSent++;

            // RFC 9000 s10.1's restart on "the first ack-eliciting packet sent after receiving
            // a packet"; s6.2.4's "All probe packets sent on a PTO MUST be ack-eliciting" makes
            // every datagram this method sends one, so the condition SendAnswerAsync tests is
            // a constant here.
            RestartIdleTimerOnAckElicitingSend(_options.TimeProvider.GetUtcNow());
        }
    }

    // s6.2.4's probe CONTENTS, which is knob 11 - TlsQuicProbeContents - and not a constant.
    // s6.2.4 leaves the choice open in as many words: "Implementations MAY use alternative
    // strategies for determining the content of probe packets", with one hard rule at line 192
    // - "All probe packets sent on a PTO MUST be ack-eliciting" - which every arm satisfies
    // because every arm carries a PING. RFC 9000 s19.2 is why PING is the frame: "The receiver
    // of this frame simply needs to acknowledge it", and s12.4 Table 3 gives it the row "IH01",
    // so it is legal in every space this method can be asked for.
    private bool TryBuildProbeDatagram(TlsQuicEncryptionLevel space, out int written)
    {
        written = 0;

        if (!_keys.TryGetWriteKeys(space, out var keys, out _))
        {
            return false;
        }

        var frames = new List<TlsQuicFrame>
        {
            new() { RawType = (ulong)TlsQuicFrameType.Ping },
        };

        var packet = new TlsQuicPacketToSend
        {
            Plan = space == TlsQuicEncryptionLevel.Application
                ? ShortHeaderPlan()
                : PlanFor(space, _nextPacketNumber[(int)space]++),
            Frames = frames,
            PacketProtectionCipher = keys.PacketCipher,
            Key = keys.Key.ToArray(),
            Iv = keys.Iv.ToArray(),
            HeaderProtectionCipher = keys.HeaderCipher,
            HeaderProtectionKey = keys.HeaderProtectionKey.ToArray(),
        };

        var now = _options.TimeProvider.GetUtcNow();

        // KNOB 11's PingWithPadding, AND IT IS A NO-OP AT Initial BY CONSTRUCTION RATHER THAN
        // BY OVERSIGHT. TlsQuicDatagramBuilder.BuildDatagram expands the LAST packet of any
        // datagram that carries an Initial one out to TlsQuicConnectionSpec.PaddingTarget,
        // whose floor is s14.1's 1200 - which is how RFC 9000 s8.1's "a UDP datagram that
        // contains at least 1200 bytes" is met here without a second padder. So at Initial the
        // two knob values produce the same bytes and the padding below would fight the
        // builder's own solver for the same budget; the other spaces are where the knob is
        // observable, and where s6.2.4's "full-sized datagrams" would otherwise not be.
        //
        // MEASURED RATHER THAN SOLVED. The exact frame count is TlsQuicDatagramBuilder's
        // SolvePaddingFrameCount, which is private to a file A3-7 may not open; a copy of its
        // Table 4 fixed-point search here would be the second solver this phase bans. One
        // throwaway build with a null sent-packet list gives the size directly, and PADDING is
        // one byte per frame (s19.1: "The PADDING frame ... has no content"), so the deficit is
        // the count. A Length varint that widens under the extra bytes overshoots the target by
        // at most three, which s14.1 permits - the target is a floor: "Datagrams containing
        // Initial packets MAY exceed 1200 bytes".
        if (_options.Spec.Recovery.ProbeContents == TlsQuicProbeContents.PingWithPadding
            && space != TlsQuicEncryptionLevel.Initial)
        {
            var bare = TlsQuicDatagramBuilder.BuildDatagram(
                _options.Spec, [packet], now, _sendBuffer, null);

            // AND THE TARGET IS CLAMPED, WHICH IS NOT DEFENSIVENESS - IT IS THE ONE INPUT ON
            // THIS PATH THAT WOULD THROW. TlsQuicConnectionSpec.PaddingTarget's upper bound is
            // 65527, which is EXACTLY DatagramBufferSize, so padding to the target and then
            // paying for a Length varint that widened under the added bytes overshoots the
            // buffer - and TlsQuicPacketBuilder.Build bounds every packet against the span it
            // is handed and throws ArgumentException naming `destination`. RFC 9000 s16 Table 4
            // gives a variable-length integer four widths, 1 to 8 bytes, so the widening costs
            // at most seven bytes; reserving that much leaves the built datagram inside the
            // buffer for every target the spec accepts. The clamp only binds within seven bytes
            // of the maximum target and changes nothing below it.
            var target = Math.Min(
                _options.Spec.PaddingTarget, DatagramBufferSize - MaximumVarintWidth + 1);
            for (var i = bare; i < target; i++)
            {
                // TlsQuicFrame's default is s19.1's PADDING - RawType 0 - which is the same
                // value TlsQuicDatagramBuilder.Expand appends for the Initial case.
                frames.Add(default);
            }
        }

        // KNOB 11's RetransmittedData, WHICH A3-7 LEFT AS A PING AND NAMED THIS TASK FOR.
        // s6.2.4 lines 205-206: "An endpoint SHOULD include new data in packets that are sent
        // on PTO expiration. Previously sent data MAY be sent if no new data can be sent."
        // AppendProbeData is that MAY, in s6.2.4's own two-source order; see its remarks.
        //
        // THE PING STAYS IN FRONT OF IT RATHER THAN BEING REPLACED BY IT. s6.2.4 line 192 is
        // the section's one hard rule - "All probe packets sent on a PTO MUST be ack-eliciting"
        // - and a repair that AppendProbeData declines to supply (nothing owed, nothing
        // retained, or a budget already spent) would otherwise leave a probe with no frame in
        // it at all. Keeping the PING makes the MUST structural instead of conditional, and
        // s19.2's "The receiver of this frame simply needs to acknowledge it" costs one byte.
        if (_options.Spec.Recovery.ProbeContents == TlsQuicProbeContents.RetransmittedData)
        {
            AppendProbeData(space, frames);
        }

        // WHAT s6.2.4's FALLBACK STILL COVERS, AND IT IS NOT DEAD PROSE. s6.2.4 lines 215-217:
        // NOT AS A KNOB QUIETLY IGNORED. s6.2.4: "It is possible the sender has no new or
        // previously sent data to send ... When there is no data to send, the sender SHOULD
        // send a PING or other ack-eliciting frame in a single packet, rearming the PTO timer."
        // A3-7 recorded that sentence as covering the WHOLE arm, because "this connection has
        // no retransmission queue to draw from" was true then. It is no longer: A3-8 built the
        // ledger, and the sentence now covers the narrower case it actually describes - a probe
        // for which there is genuinely nothing owed and nothing retained. The frame list still
        // holds the PING above, so that case needs no code of its own.

        RecordRepairable(space, packet.Plan.PacketNumber, frames);

        written = TlsQuicDatagramBuilder.BuildDatagram(
            _options.Spec, [packet], now, _sendBuffer, _justSent);
        RetainSentPackets();

        LastProbeLevel = space;
        LastProbeDatagramBytes = written;
        return true;
    }

    // THE COUNTERS BELONG HERE AND NOWHERE ELSE. A discarded packet is not a failure - RFC
    // 9000 s12.2 requires the loop to carry on past one - so the only failure it can ever
    // produce is this deadline, and a deadline that did not say how many packets went
    // unopened would leave the coalescing stall with no symptom of its own. See
    // AccountForPacket for what used to happen instead and why it was worse.
    private TimeoutException DeadlineExceeded() => new(
        $"The QUIC handshake did not confirm within {_options.HandshakeDeadline}. "
            + $"{DiscardedPackets} packet(s) discarded ({DiscardedForMissingKeys} for want of "
            + $"keys), {UnprocessedPackets} unprocessed, "
            + $"{IgnoredForConnectionIdMismatch} ignored for a Destination Connection ID "
            + $"mismatch, {DiscardedForSourceConnectionIdChange} for a changed Source "
            + "Connection ID. A non-zero want-of-keys count is the coalescing stall "
            + "PumpOnceAsync's remarks describe. "
            + "THIS IS A TIMEOUT, NOT A RETRANSMISSION: A3 is deferred, so nothing here "
            + "resents a lost packet and there is nothing to resend - recovering from one "
            + "means starting a new attempt at the process level.");

    private async ValueTask<TlsQuicDatagramReceiveResult> ReceiveWithinDeadlineAsync(
        byte[] buffer, CancellationToken cancellationToken)
    {
        // THREE DEADLINES SINCE A3-5, AND THE EARLIEST ONE BOUNDS THE RECEIVE. Two of them are
        // ABANDONMENTS and are different failures from each other: the handshake deadline is
        // local policy that never moves, and RFC 9000 s10.1's idle timeout restarts on every
        // packet processed and on the first ack-eliciting packet sent after one. AbandonAsync
        // decides which of those two fired and whether a frame is owed. The third is RFC 9002
        // A.8's loss detection timer and is not a failure at all - see EarliestDeadline.
        var (deadlineAt, deadlineKind) = EarliestDeadline();
        var remaining = deadlineAt - _options.TimeProvider.GetUtcNow();

        // TWO PATHS TO THE SAME FAILURE, AND THEY COVER DIFFERENT PEERS.
        //
        // The token source below bounds a peer that goes SILENT - the case A3's absence makes
        // unrecoverable, since a lost packet is never resent and the receive would otherwise
        // wait forever. It fires on TimeProvider's own timer.
        //
        // The check after the receive bounds a peer that answers LATE. It reads GetUtcNow
        // directly, which is why it fires deterministically on a fake clock with zero
        // wall-clock time elapsed.
        //
        // AND THE SENTENCE THAT USED TO FOLLOW WAS TRUE OF A NARROWER THING THAN IT NAMED. It
        // read: "a test provider that overrides GetUtcNow AND NOTHING ELSE inherits
        // TimeProvider's real-time timer, so the token source is not the path such a test
        // exercises". The clause in capitals was the whole of it, and A3-1 removed the only
        // provider it described - ManualTimeProvider now overrides CreateTimer as well, so a
        // CancellationTokenSource built from it fires on the FAKE clock. The token source is
        // therefore exactly the path a fake-clock test exercises today, and A3-5's wake-on-
        // deadline entry below depends on that being so. What survives of the old sentence is
        // narrower still and is worth keeping: the check after the receive needs no timer of
        // any kind, so it holds even for a provider that fakes only the clock reading.
        //
        // A non-positive remaining becomes an already-cancelled source rather than a throw
        // here, so that one call site produces the deadline failure and not two.
        using var deadlineSource = new CancellationTokenSource(
            remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero, _options.TimeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, deadlineSource.Token);

        TlsQuicDatagramReceiveResult received = default;
        var wokeOnRecoveryTimer = false;
        var wokeOnDeadline = false;
        try
        {
            received = await _options.Transport
                .ReceiveAsync(buffer, linked.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (deadlineSource.IsCancellationRequested
            && !cancellationToken.IsCancellationRequested)
        {
            // WHICH DEADLINE ARMED THE TOKEN DECIDES WHETHER THIS IS A FAILURE OR A WAKE-UP,
            // AND THAT IS THE WHOLE OF THE WEAVE. Before A3-5 there were only two entries and
            // both were abandonments, so this catch could throw unconditionally. A recovery
            // deadline is the third kind: it means "there is something to do", not "this
            // attempt is over". Note that when _lossDetectionTimer is null - which it is for
            // every path that has nothing in flight, and for the whole of every test written
            // before this task - EarliestDeadline returns IsRecovery false and this branch is
            // byte-for-byte the behaviour it replaced.
            //
            // AND A3-11 ADDS A THIRD ANSWER TO THE SAME QUESTION. A pacing release is a wake-up
            // like the recovery timer - it means "there is something to do" - but unlike the
            // recovery timer it carries no obligation to run A.9. So it falls out of this catch
            // with wokeOnRecoveryTimer still false, which returns the zero-length datagram below
            // WITHOUT running OnLossDetectionTimeout, and the pump's ordinary send pass is what
            // releases the held frames.
            //
            // AND A3-13's DelayedAck ADDS NO FOURTH ANSWER, WHICH IS WHY NOTHING BELOW MOVED.
            // RFC 9000 s13.2.1's max_ack_delay falling due wants the same two things a pacing
            // release wants - run the send pass, do not run A.9 - so it is carried by the two
            // lines already here rather than by a branch of its own. The knob is wired in
            // EarliestDeadline and in TlsQuicAckTracker; this catch needed only to keep
            // treating "not Abandonment, not Recovery" as a wake-up, which it already did. That
            // the fifth entry costs zero lines here is the strongest evidence available that
            // A3-5's weave was an addition to this loop rather than a split of it.
            if (deadlineKind == TlsQuicDeadlineKind.Abandonment)
            {
                throw await AbandonAsync(cancellationToken).ConfigureAwait(false);
            }

            wokeOnDeadline = true;
            wokeOnRecoveryTimer = deadlineKind == TlsQuicDeadlineKind.Recovery;
        }

        // UNCHANGED, AND IT IS HALF THE PROOF THAT THIS CANNOT HANG. Both abandonment
        // deadlines are re-read here on EVERY wake, recovery or not, so the attempt still ends
        // on the earlier of them no matter how many times a recovery timer fires first. The
        // other half is EarliestDeadline returning a MINIMUM: a minimum is no greater than any
        // of its inputs, so adding a third entry can only ever SHORTEN a wait that already
        // terminated at HEAD, never lengthen one. Nothing here waits on the recovery timer -
        // it is raced against, never awaited alone.
        if (RemainingBeforeDeadline() <= TimeSpan.Zero
            || RemainingBeforeIdleTimeout() <= TimeSpan.Zero)
        {
            throw await AbandonAsync(cancellationToken).ConfigureAwait(false);
        }

        if (!wokeOnDeadline)
        {
            return received;
        }

        if (wokeOnRecoveryTimer)
        {
            // A.9 runs BEFORE the send pass and on this same thread, so pto_count and the
            // re-armed timer are settled by the time PumpOnceAsync builds anything. A3-7's probe
            // contents are read out of that settled state rather than racing it.
            //
            // A PACING WAKE SKIPS THIS AND ONLY THIS. Everything below - the zero-length
            // datagram, and the send pass PumpOnceAsync runs on it - is shared, which is what
            // makes s7.7's release cost one branch rather than a second wake-up path.
            OnLossDetectionTimeout();
        }

        // A ZERO-LENGTH DATAGRAM IS THE WAKE-UP, AND NO NEW BRANCH IN PumpOnceAsync IS NEEDED
        // TO CARRY IT. TlsQuicDatagramReader.Read's walk is `while (offset < datagram.Length)`,
        // so an empty datagram yields no coalesced packets, the whole per-packet body is
        // skipped, and the pump falls through to the `if (!_draining)` send pass it always
        // runs - which is precisely "run a send pass with no datagram received". The endpoint
        // is filled in rather than left default so that no consumer of this struct can meet a
        // null RemoteEndPoint on a path that never had one.
        return new TlsQuicDatagramReceiveResult(0, _options.RemoteEndPoint);
    }

    private async ValueTask SendInitialFlightAsync(
        ReadOnlyMemory<byte> cryptoStream, CancellationToken cancellationToken)
    {
        var datagrams = BuildInitialFlight(cryptoStream);
        foreach (var datagram in datagrams)
        {
            await _options.Transport
                .SendAsync(_options.RemoteEndPoint, datagram, cancellationToken)
                .ConfigureAwait(false);
        }

        // BuildInitialFlight advances the packet number by one per datagram from the template
        // (RFC 9000 s12.3 forbids reuse within a space), so the counter moves by the datagram
        // count and not by one.
        _nextPacketNumber[(int)TlsQuicEncryptionLevel.Initial] += (ulong)datagrams.Count;
    }

    // NOT async, and it cannot be: TlsQuicWriteKeyMaterial is a ref struct, so key material
    // never lives in an async state machine.
    private List<byte[]> BuildInitialFlight(ReadOnlyMemory<byte> cryptoStream)
    {
        if (!_keys.TryGetWriteKeys(TlsQuicEncryptionLevel.Initial, out var keys, out var state))
        {
            throw new InvalidOperationException(
                $"No Initial write keys for the opening flight; the level is {state}.");
        }

        var template = new TlsQuicPacketToSend
        {
            Plan = PlanFor(
                TlsQuicEncryptionLevel.Initial,
                _nextPacketNumber[(int)TlsQuicEncryptionLevel.Initial]),
            Frames = [],
            PacketProtectionCipher = keys.PacketCipher,
            Key = keys.Key.ToArray(),
            Iv = keys.Iv.ToArray(),
            HeaderProtectionCipher = keys.HeaderCipher,
            HeaderProtectionKey = keys.HeaderProtectionKey.ToArray(),
        };

        // THE THIRD CALL SITE, WHICH THE A3 PLAN'S TASK TEXT DOES NOT NAME. It names the two
        // BuildDatagram calls; BuildInitialFlight takes the same ICollection for the same
        // reason and produces the FIRST packets this connection ever sends. Leaving it out
        // would have left the opening flight - the one flight guaranteed to exist on every
        // connection - untracked, and every Initial-space test below would have passed on an
        // empty list.
        var datagrams = TlsQuicDatagramBuilder.BuildInitialFlight(
            _options.Spec, template, cryptoStream, _options.TimeProvider.GetUtcNow(), _justSent);

        // A3-8's LEDGER FOR THE OPENING FLIGHT, AND IT IS AN OVER-APPROXIMATION THAT IS SAID TO
        // BE ONE. The CRYPTO split across this flight's datagrams is TlsQuicDatagramBuilder's -
        // PlanInitialCryptoFrames decides it, and it is private to a file this task may not
        // open - so the per-packet offsets are not visible here. What IS visible is that the
        // whole stream went out in this flight, so the whole stream at offset 0 is recorded
        // against every packet of it: losing any one of them re-sends the whole ClientHello.
        //
        // OVER-SENDING IS LEGAL AND UNDER-REPAIRING IS NOT, which is the direction that settled
        // it. RFC 9000 s13.3's own closing paragraph permits the coarser choice - "it is not
        // forbidden to retransmit copies of frames from lost packets" - and the peer's CRYPTO
        // reassembler discards a duplicate offset range. Recording a guess at the split would
        // be a second copy of the builder's arithmetic, which is the divergence
        // TlsQuicPacketBuilder.cs:37-46 refuses in the same breath.
        //
        // AND THE DUPLICATE IT WOULD OTHERWISE CAUSE IS HANDLED WHERE IT ARISES: a two-datagram
        // flight both of whose packets are lost queues the same information twice, and
        // QueueRepair's identity check is what keeps one copy.
        foreach (var sent in _justSent)
        {
            RecordRepairable(
                TlsQuicEncryptionLevel.Initial,
                sent.PacketNumber,
                [new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.Crypto,
                    Offset = 0,
                    Data = cryptoStream,
                }]);
        }

        RetainSentPackets();
        return datagrams;
    }

    /// <returns><see langword="true"/> if a datagram went out. Read by
    /// <see cref="SendPendingAsync"/>, which has no received datagram to report on instead.
    /// </returns>
    private async ValueTask<bool> SendAnswerAsync(
        IReadOnlyList<TlsQuicProcessResult> results,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var crypto = new List<TlsQuicCryptoDataEvent>();
        foreach (var result in results)
        {
            foreach (var raised in result.Events)
            {
                if (raised is TlsQuicCryptoDataEvent data)
                {
                    crypto.Add(data);
                }
            }
        }

        var written = BuildAnswerDatagram(
            crypto, now, out var carriedHandshakePacket, out var carriedAckElicitingFrame);
        if (written > 0)
        {
            await _options.Transport
                .SendAsync(_options.RemoteEndPoint, _sendBuffer.AsMemory(0, written), cancellationToken)
                .ConfigureAwait(false);

            // RFC 9000 s10.1's second restart, and the condition is what makes it a restart
            // rather than a reset. s2 makes every frame but ACK, PADDING and CONNECTION_CLOSE
            // ack-eliciting, so a datagram carrying CRYPTO or PATH_RESPONSE restarts the idle
            // timer and one carrying only an ACK does not - which is the difference between a
            // connection that is doing something and one that is merely acknowledging.
            if (carriedAckElicitingFrame)
            {
                RestartIdleTimerOnAckElicitingSend(now);
            }
        }

        // RFC 9001 s4.9.1: "a client MUST discard Initial keys when it first sends a Handshake
        // packet". A SEND EVENT, not a TLS-state event, and it is why this call sits after the
        // SendAsync above and not next to the handshake's completion.
        if (carriedHandshakePacket && !_sentHandshakePacket)
        {
            _sentHandshakePacket = true;
            using var notified = _client!.NotifyHandshakePacketSent();
            ApplyDiscards(notified);
        }

        // A CHECK, NOT AN APPLY, AND THE DIFFERENCE WAS MEASURED RATHER THAN REASONED.
        // Applying these results' discards BEFORE the send above survives the whole gate,
        // because there is nothing in them to apply: CustomTlsQuicClient raises
        // TlsQuicDiscardKeysEvent from exactly two places, and both are the explicit calls
        // this method already makes - NotifyHandshakePacketSent for Initial (s4.9.1) and
        // ConfirmHandshake for Handshake (s4.9.2). ProcessCryptoDataAsync never raises one.
        // CustomTlsQuicServer does raise one from its own ProcessCryptoDataAsync, which is
        // where the opposite intuition comes from and why the assumption is checked here
        // rather than written down and hoped for.
        //
        // DELIBERATELY UNWITNESSED. It cannot fire against the current client, so a test for
        // it would have to fabricate the event and would then be witnessing its own fake -
        // the same classification LoopbackQuicPeer's identical check carries.
        foreach (var result in results)
        {
            foreach (var raised in result.Events)
            {
                if (raised is TlsQuicDiscardKeysEvent discard)
                {
                    throw new InvalidOperationException(
                        $"ProcessCryptoDataAsync raised a {discard.Level} key discard. This "
                            + "loop takes discards from NotifyHandshakePacketSent and "
                            + "ConfirmHandshake only; see the note here before widening it.");
                }
            }
        }

        ConfirmIfHandshakeDoneArrived();
        return written > 0;
    }

    private void ConfirmIfHandshakeDoneArrived()
    {
        if (!_handshakeDoneReceived || _confirmed)
        {
            return;
        }

        // RFC 9001 s4.1.2, verbatim: "At the client, the handshake is considered confirmed
        // when a HANDSHAKE_DONE frame is received." That frame, and only that frame, releases
        // the Handshake keys here - confirming on TLS-complete instead would discard keys the
        // server may still be using, which is the specific mistake Finding 8 was written to
        // stop.
        //
        // s4.1.2 ALSO PERMITS A SECOND TRIGGER AND THIS DOES NOT IMPLEMENT IT: a client MAY
        // consider the handshake confirmed on an acknowledgement of a 1-RTT packet it sent.
        // A4-minimal sends no 1-RTT packet at all (task 14 is where that arrives), so the
        // trigger has nothing to fire on; it is named here rather than omitted silently.
        //
        // NO IsHandshakeComplete GUARD, and it is not an oversight. ConfirmHandshake throws if
        // TLS has not finished, and the ordering that would provoke it is unreachable: a
        // HANDSHAKE_DONE arrives in a 1-RTT packet, whose read keys this connection installs
        // only from the Application traffic secret the completing result carries, so the AEAD
        // cannot open such a packet before completion. A guard here would be a check for a
        // state the packet layer has already made impossible.
        //
        // _confirmed IS SET LAST, AND THE ORDER IS THE WHOLE POINT OF THE LINE. Setting it
        // first meant that a throw out of ConfirmHandshake left IsHandshakeConfirmed reporting
        // true with the Handshake keys still installed - a client claiming RFC 9001 s4.1.2's
        // confirmed state while holding keys s4.9.2 says confirmation releases. There is no
        // re-entrancy to protect against here (one thread of control, no await between these
        // three lines), so nothing wanted the early set.
        using var confirmed = _client!.ConfirmHandshake();
        ApplyDiscards(confirmed);
        _confirmed = true;

        // A3-4's OTHER SEAM, WIRED AT THE ONE INSTANT IT IS ABOUT. Its remarks: "Call this
        // once, when it is. Idempotent, and one-way - nothing unconfirms a handshake ... this
        // is a seam A3-5 or A3-7 wires." RFC 9002 s5.3's condition it turns on - "the endpoint
        // SHOULD ignore max_ack_delay until the handshake is confirmed" - is about the same
        // moment RFC 9001 s4.1.2 defines two dozen lines above, so a second notion of
        // "confirmed" is not created here; the existing one is forwarded.
        //
        // AFTER _confirmed AND NOT BEFORE IT, for the reason the paragraph above gives about
        // that line's own placement: ConfirmHandshake can throw, and a tracker told the
        // handshake was confirmed by an attempt that then died holding Handshake keys would be
        // capping ack_delay on a connection that never reached the state.
        _acks.OnHandshakeConfirmed();

        // CONFIRMATION MOVES TWO OF A.8's INPUTS AT ONCE, so the timer is re-armed rather than
        // left reading a state that no longer holds: PeerCompletedAddressValidation flips true
        // by its second disjunct, and s6.2.1's "An endpoint MUST NOT set its PTO timer for the
        // Application Data packet number space until the handshake is confirmed" stops
        // binding. ApplyDiscards above has usually already re-armed through ForgetSpace - the
        // Handshake keys are released here - but that is a consequence of what this connection
        // happens to discard and not a rule, so the arming is not left to depend on it.
        SetLossDetectionTimer();
    }

    // RFC 9000 s18.2's ack_delay_exponent (0x0a), with s18.2's absent-value default. The
    // narrowing is saturating rather than a cast: ValidatePeer already refuses a value above
    // 20 and OnPeerAckParameters clamps whatever reaches it, but an unchecked (int) of a 62-bit
    // varint can land INSIDE the legal range with the wrong value, which is the one failure
    // shape neither of those two catches.
    private static int ToAckDelayExponent(ulong? exponent) =>
        exponent is not { } value ? TlsQuicAckTracker.DefaultAckDelayExponent
        : value > int.MaxValue ? int.MaxValue
        : (int)value;

    // RFC 9000 s18.2's max_ack_delay (0x0b), in milliseconds, with s18.2's absent-value default
    // and s18.2's own ceiling: "Values of 2^14 or greater are invalid." Saturates at that
    // ceiling for the same reason ToIdleTimeout saturates at its own - the value is a peer's
    // 62-bit varint and TimeSpan.FromMilliseconds throws on one large enough, which would be a
    // remote kill switch reachable from one legal-shaped transport parameter.
    private static TimeSpan ToMaxAckDelay(ulong? milliseconds) =>
        milliseconds is not { } value ? TlsQuicAckTracker.DefaultMaxAckDelay
        : value >= (ulong)TlsQuicAckTracker.MaximumMaxAckDelay.TotalMilliseconds
            ? TlsQuicAckTracker.MaximumMaxAckDelay
        : TimeSpan.FromMilliseconds(value);

    // Every LONG-HEADER level, in both orders, WITH THE SKIPPED ONE STILL PRESENT. EarlyData
    // is not filtered out here because its skip carries its own reason and its own witness
    // inside the loop, and a list that quietly omitted it would delete both.
    //
    // APPLICATION IS ABSENT FOR THE OPPOSITE REASON: it is not skipped, it is built after the
    // loop. RFC 9000 s12.2 puts the short-header packet last in its datagram, so its position
    // is fixed by the spec and these two orders - which subsystem B varies - would otherwise
    // claim to move it. Naming it here in either order would be a knob that lies.
    private static readonly TlsQuicEncryptionLevel[] AscendingLevels =
    [
        TlsQuicEncryptionLevel.Initial,
        TlsQuicEncryptionLevel.EarlyData,
        TlsQuicEncryptionLevel.Handshake,
    ];

    private static readonly TlsQuicEncryptionLevel[] DescendingLevels =
    [
        TlsQuicEncryptionLevel.Handshake,
        TlsQuicEncryptionLevel.EarlyData,
        TlsQuicEncryptionLevel.Initial,
    ];

    // NOT async, for the same ref struct reason as BuildInitialFlight.
    private int BuildAnswerDatagram(
        IReadOnlyList<TlsQuicCryptoDataEvent> crypto,
        DateTimeOffset now,
        out bool carriedHandshakePacket,
        out bool carriedAckElicitingFrame)
    {
        carriedHandshakePacket = false;
        var packets = new List<TlsQuicPacketToSend>();

        // THE ORDER IS THE SPEC'S, NOT THIS METHOD'S, and it used to be an ascending `for`
        // loop over the enum ordinal. RFC 9000 s12.2's coalescing rule is about connection IDs
        // rather than order, but it does say ascending order "makes it more likely that the
        // receiver will be able to process all the packets in a single pass" - and a peer
        // meeting our Handshake packet before the Initial one would have to buffer. That is a
        // good default and not a law: the order is plainly visible on the wire, it is one of
        // the dimensions subsystem B varies, and the plan's design constraints put
        // "per-datagram flight plan" on the list of things nothing may read a literal for.
        // Reversing this loop used to leave 1043 of 1043 green.
        foreach (var level in _options.Spec.CoalesceAscendingByLevel
            ? AscendingLevels
            : DescendingLevels)
        {
            // EARLY DATA IS SKIPPED, AND NOT BECAUSE A4-MINIMAL HAPPENS NOT TO SEND 0-RTT.
            // RFC 9000 s12.3 gives 0-RTT and 1-RTT ONE packet number space, so the ack
            // tracker - which is indexed by space, correctly - offers the Application space's
            // ranges at this level too. s12.4 Table 3 forbids ACK in a 0-RTT packet, so
            // building one here would produce a packet TlsQuicPacketBuilder rejects, and it
            // would be right to. Found by running it: without this the first answer threw
            // "No write keys at EarlyData".
            if (level == TlsQuicEncryptionLevel.EarlyData)
            {
                continue;
            }

            // APPLICATION IS NOT SKIPPED HERE, IT IS BUILT AFTER THIS LOOP - see
            // TryBuildApplicationPacket in TlsQuicApplicationSendPath.cs for why RFC 9000
            // s12.2 makes that a position rather than an omission. The skip that used to sit
            // here was A4-minimal's one KNOWINGLY VIOLATED MUST and task 14c is where it ends:
            // s13.2.1's "An endpoint MUST acknowledge all ack-eliciting Initial and Handshake
            // packets immediately and all ack-eliciting 0-RTT and 1-RTT packets within its
            // advertised max_ack_delay, with the following exception" is ONE MUST WITH TWO
            // CONJUNCTS, and an earlier comment here read it truncated at its line wrap and
            // concluded the opposite. The exception never applied - it is "an endpoint might
            // not have packet protection keys", and we had decrypted the packet.
            //
            // THE COST WAS MEASURED, NOT ARGUED. Task 13's live run recorded tls3.peet.ws
            // sending seven HANDSHAKE_DONE retransmissions in 14.9 seconds and still going at
            // the deadline; fp.impersonate.pro sent none. HandshakeDoneFramesReceived counts
            // exactly that, and it is what should now stay at one.

            var frames = new List<TlsQuicFrame>();

            // THE ACK'S POSITION IS THE SPEC'S, NOT THIS METHOD'S, and it used to be hardcoded
            // first. RFC 9000 imposes no frame order inside a packet and the capture observes
            // none for ACK, so neither position is derived from ground truth - which an
            // earlier version of this comment said, and then hardcoded one anyway. DECLARED IS
            // NOT KNOBBED: task 11 cannot report a field the connection fixes, and moving the
            // ACK from first to last used to leave 1043 of 1043 green. The default is still
            // first, for the reason it always was - s13.2.1's "MUST acknowledge all
            // ack-eliciting Initial and Handshake packets immediately" makes the ACK the part
            // of the packet that must not be squeezed out by anything else.
            var hasAck = TryBuildAckFrame(level, now, out var ack);
            if (hasAck && _options.Spec.AckLeadsInPacket)
            {
                frames.Add(ack);
            }

            // TASK A3-8's REPAIR, AND ITS POSITION IS RFC 9000 s13.3's: "Endpoints SHOULD
            // prioritize retransmission of data over sending new data, unless priorities
            // specified by the application indicate otherwise". Ahead of this pass's own CRYPTO
            // and inside whichever bracket the ACK knob leaves, which is where the STREAM
            // frames sit in the 1-RTT packet for the same reason.
            //
            // AND THIS IS WHY RETRANSMISSION NEEDED NO SEND PATH OF ITS OWN. A repaired CRYPTO
            // frame is a frame in the ordinary answer datagram: it is protected by the same
            // keys, numbered by the same counter, retained by the same RetainSentPackets, and
            // becomes repairable again by the same ledger if it is lost in turn.
            TakeRepairsInto(level, frames);

            foreach (var data in crypto)
            {
                if (data.Level != level)
                {
                    continue;
                }

                // The offset is the TLS endpoint's and is never recomputed here.
                frames.Add(new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.Crypto,
                    Offset = data.Offset,
                    Data = data.Data,
                });
            }

            if (hasAck && !_options.Spec.AckLeadsInPacket)
            {
                frames.Add(ack);
            }

            if (frames.Count == 0)
            {
                continue;
            }

            if (!_keys.TryGetWriteKeys(level, out var keys, out var state))
            {
                // RFC 9001 s4.9.1: "Endpoints MUST NOT send Initial packets after this point."
                // A pending ACK for a level whose keys have gone is DROPPED, not sent and not
                // an error - that is the ordinary post-discard steady state, and it is the one
                // case where a missing key is correct rather than a sequencing bug.
                //
                // UNREACHABLE TODAY, MEASURED: narrowing this to NeverInstalled - so that a
                // discarded level throws instead - leaves 1043 of 1043 green, and the reason
                // is that TlsQuicKeySet.DiscardKeys takes the READ keys with the write ones.
                // After the Initial discard no further Initial packet can be opened, so no
                // further Initial packet is ever recorded, so the ack tracker never has
                // anything ack-eliciting pending at that level again and TryBuildAck returns
                // false before this line is reached. It is kept for the two paths that break
                // that argument - task 9b's Retry, which re-keys Initial, and A3's
                // retransmission, which resends at a level after the fact - and it is
                // deliberately unwitnessed, because a test would have to build one of them.
                if (state == TlsQuicKeyLevelState.Discarded)
                {
                    continue;
                }

                throw new InvalidOperationException(
                    $"No write keys at {level} for a flight that carries {level} data; "
                        + $"the level is {state}.");
            }

            RecordRepairable(level, _nextPacketNumber[(int)level], frames);

            packets.Add(new TlsQuicPacketToSend
            {
                Plan = PlanFor(level, _nextPacketNumber[(int)level]++),
                Frames = frames,
                PacketProtectionCipher = keys.PacketCipher,
                Key = keys.Key.ToArray(),
                Iv = keys.Iv.ToArray(),
                HeaderProtectionCipher = keys.HeaderCipher,
                HeaderProtectionKey = keys.HeaderProtectionKey.ToArray(),
            });

            carriedHandshakePacket |= level == TlsQuicEncryptionLevel.Handshake;
        }

        // LAST, ALWAYS, AND OUTSIDE THE LOOP THAT THE SPEC'S ORDER KNOB DRIVES. RFC 9000
        // s12.2: "packets with a short header (Section 17.3) do not contain a Length field
        // and so cannot be followed by other packets in the same UDP datagram." That is not
        // a dimension anything may vary, so the 1-RTT packet is not one of the levels above.
        if (TryBuildApplicationPacket(now, out var oneRtt))
        {
            // A3-8's ledger for the 1-RTT packet, RECORDED HERE RATHER THAN WHERE THE PACKET IS
            // BUILT. TryBuildApplicationPacket lives in TlsQuicApplicationSendPath.cs, which is
            // not one of this task's files; the plan's file list is the reason, and the packet's
            // own plan carries the number so nothing is lost by recording it one line later.
            // The 1-RTT REPAIRS themselves reach that method the way every other 1-RTT frame
            // does - through TlsQuicStreamSet.TakePendingFrames - which is what let this task
            // repair a lost grant without opening that file.
            RecordRepairable(
                TlsQuicEncryptionLevel.Application, oneRtt.Plan.PacketNumber, oneRtt.Frames);

            packets.Add(oneRtt);
        }

        // RFC 9000 s2's ack-eliciting test, asked of the frames that are actually going out
        // rather than inferred from what produced them. THE INFERENCE USED TO LIVE IN
        // SendAnswerAsync as `crypto.Count > 0`, and it was true only while CRYPTO was the
        // one ack-eliciting frame this connection could send; PATH_RESPONSE is a second, so
        // the test now reads the packets. TlsQuicPacketBuilder.IsAckEliciting is the same
        // predicate TlsQuicAckTracker applies on the receive side - one owner, both
        // directions. Mutation ledger row 89 is re-run against this.
        carriedAckElicitingFrame = false;
        foreach (var built in packets)
        {
            carriedAckElicitingFrame |= TlsQuicPacketBuilder.IsAckEliciting(built.Frames);
        }

        if (packets.Count == 0)
        {
            return 0;
        }

        var written = TlsQuicDatagramBuilder.BuildDatagram(
            _options.Spec, packets, now, _sendBuffer, _justSent);
        RetainSentPackets();
        return written;
    }

    // Turns the tracker's ranges into the frame shape the builder takes. THE CHAIN IS ENCODED
    // BY A2'S WRITER AND READ BACK, rather than computed here: TlsQuicFrame carries s19.3.1's
    // Gap / ACK Range Length chain as already-encoded bytes, TlsQuicAckFrames.WriteAckFrame is
    // the only encoder for it, and re-deriving the chain here would be the second encoder this
    // phase bans. The round trip is the price of the two shapes not meeting.
    private bool TryBuildAckFrame(
        TlsQuicEncryptionLevel level, DateTimeOffset now, out TlsQuicFrame frame)
    {
        frame = default;

        if (!_acks.TryBuildAck(level, now, out var ackDelay, out var ranges))
        {
            return false;
        }

        var encoded = new List<byte>();
        TlsQuicAckFrames.WriteAckFrame(encoded, (ulong)TlsQuicFrameType.Ack, ackDelay, ranges);

        var offset = 0;
        if (!TlsQuicFrames.TryReadFrame(encoded.ToArray(), ref offset, out frame, out var error))
        {
            // UNREACHABLE BY CONSTRUCTION and deliberately unwitnessed: the bytes were written
            // by WriteAckFrame one line above, which validates every field before it writes
            // any of them. A test would have to forge input this method cannot receive.
            throw new InvalidOperationException(
                $"An ACK frame this connection just encoded did not read back: {error}.");
        }

        return true;
    }

    // RFC 9000 s19.19's Reason Phrase, capped - and the cap is what keeps s10.2's close path
    // total. The field is a caller-supplied string and the frame goes into ONE packet:
    // s19.19 says so - "Because a CONNECTION_CLOSE frame cannot be split between packets, any
    // limits on packet size will also limit the space available for a reason phrase" - so a
    // long enough reason is not a large close, it is a close that cannot be built at all.
    //
    // 512 BYTES, AND THE NUMBER IS DERIVED RATHER THAN PICKED. s14.1 requires the path to
    // carry a 1200-byte datagram before a handshake can complete, so 512 bytes of diagnostics
    // plus a header and an AEAD tag fit in a packet at EVERY level this connection can send at,
    // with room to spare. TRUNCATION RATHER THAN A THROW is what s19.19 licenses: the Reason
    // Phrase is "Additional diagnostic information for the closure. This can be zero length if
    // the sender chooses not to give details beyond the Error Code value" - so a shortened one
    // is a weaker close, while a thrown one is no close at all and leaves the peer to time out.
    //
    // TRUNCATED ON A UTF-8 BOUNDARY, because s19.19 says the phrase "SHOULD be a UTF-8 encoded
    // string [RFC3629]" and a cut through a multi-byte sequence would not be one. Encoder.
    // Convert's flush:false is what finds the boundary; slicing the byte array would not.
    private const int MaximumReasonPhraseBytes = 512;

    private static ReadOnlyMemory<byte> ReasonPhraseBytes(string? reason)
    {
        if (string.IsNullOrEmpty(reason))
        {
            return default;
        }

        var encoder = System.Text.Encoding.UTF8.GetEncoder();
        var buffer = new byte[MaximumReasonPhraseBytes];
        encoder.Convert(
            reason, buffer, flush: false, out _, out var bytesUsed, out _);
        return buffer.AsMemory(0, bytesUsed);
    }

    // RFC 9000 s20: "QUIC transport error codes and application error codes are 62-bit
    // unsigned integers." A caller holding a ulong can hand over a wider one, and the frame
    // writer's RequireEncodableVarint would throw on it - on the close path, which is the one
    // path that must not throw, because it is what runs when everything else already failed.
    private static bool IsEncodableErrorCode(ulong errorCode) =>
        errorCode <= QuicVariableLengthInteger.MaximumValue;


    // RFC 9000 s10.2's immediate close, in the TRANSPORT form - s19.19's type 0x1c, whose
    // "Error Code" is "a variable-length integer that indicates the reason for closing this
    // connection ... uses codes from the space defined in Section 20.1". For the application
    // form see <see cref="CloseWithApplicationErrorAsync"/>.
    internal ValueTask CloseAsync(
        TlsQuicTransportError errorCode,
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        CloseCoreAsync(application: false, (ulong)errorCode, reason, cancellationToken);

    // RFC 9000 s19.19's APPLICATION form, type 0x1d: "The CONNECTION_CLOSE frame with a type of
    // 0x1d is used to signal an error with the application that uses QUIC", and its Error Code
    // "uses codes defined by the application protocol; see Section 20.2". s10.2 names this as
    // the close an application protocol asks for: "When QUIC consequently closes the
    // connection, a CONNECTION_CLOSE frame with an application-supplied error code will be used
    // to signal closure to the peer."
    //
    // A ulong AND NOT AN ENUM, because s20.2's space belongs to whatever protocol ALPN
    // selected - HTTP/3's s8.1 codes here, something else on another connection - and this
    // layer has no business naming it. It is validated rather than trusted; see
    // <see cref="IsEncodableErrorCode"/>.
    internal ValueTask CloseWithApplicationErrorAsync(
        ulong errorCode,
        string? reason = null,
        CancellationToken cancellationToken = default) =>
        CloseCoreAsync(application: true, errorCode, reason, cancellationToken);

    private async ValueTask CloseCoreAsync(
        bool application, ulong errorCode, string? reason, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_draining || !_started)
        {
            // s10.2.2: "an endpoint in the draining state MUST NOT send any packets", and a
            // connection that never started has no keys to protect one with.
            _draining = true;
            return;
        }

        var written = BuildCloseDatagram(application, errorCode, reason);
        if (written > 0)
        {
            await _options.Transport
                .SendAsync(
                    _options.RemoteEndPoint, _sendBuffer.AsMemory(0, written), cancellationToken)
                .ConfigureAwait(false);
        }

        // s10.2: "After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the
        // closing state." Entered even when nothing could be sent - a connection with no
        // usable write keys is closing whether or not the peer can be told.
        _draining = true;
    }

    // NOT async, for the same ref struct reason as BuildInitialFlight.
    //
    // THE LEVEL IS CHOSEN BY CONFIRMATION, NOT BY "HIGHEST AVAILABLE", AND THAT DISTINCTION IS
    // WHAT s10.2.3 SPENDS ITS THIRD BULLET ON. The section opens with a Generally - "Generally,
    // this means sending the frame in a packet with the highest level of packet protection to
    // avoid the packet being discarded" - and then splits on confirmation:
    //
    //   CONFIRMED: "After the handshake is confirmed (see Section 4.1.2 of [QUIC-TLS]), an
    //   endpoint MUST send any CONNECTION_CLOSE frames in a 1-RTT packet." A MUST, and 1-RTT
    //   alone; the levels below are not fallbacks here, they are forbidden.
    //
    //   NOT CONFIRMED: "Prior to confirming the handshake, a peer might be unable to process
    //   1-RTT packets, so an endpoint SHOULD send a CONNECTION_CLOSE frame in both Handshake
    //   and 1-RTT packets." A 1-RTT close is NOT the safer choice here even when this endpoint
    //   has the keys for one, because the constraint is on what the PEER can open - so the
    //   Handshake half is the one to send if only one is sent, and this sends that.
    //
    // WHICH IS WHY THIS IS A BRANCH AND NOT ONE DESCENDING LIST. A single [Application,
    // Handshake, Initial] walk looks like the Generally and satisfies the MUST, but it takes
    // 1-RTT in exactly the window where the SHOULD warns against it: the client has Application
    // write keys from the moment its own handshake completes, which is BEFORE the server's
    // HANDSHAKE_DONE confirms it. Measured rather than reasoned - that list turned
    // AServerConnectionIdParameterThatDoesNotMatchClosesWithTransportParameterError from a
    // Handshake close into a short-header one, and its s10.2.3 assertion caught it.
    //
    // THE CONFIRMED ARM USED TO BE UNSATISFIABLE AND IS NOW SATISFIED TWICE OVER. This walk
    // read [Handshake, Initial] and said "Application is absent because no short header can be
    // built"; A4 task 14b built one and 14c gave this connection ShortHeaderPlan, so the reason
    // was stale rather than the rule. RFC 9001 s4.9.2 discards the Handshake keys AT
    // confirmation and s4.9.1 discarded Initial before that, so on the confirmed arm Application
    // is not merely the level named - it is the only level TryGetWriteKeys could answer for
    // anyway. EarlyData is absent from both arms because this client never sends 0-RTT.
    //
    // ONE PACKET AND NOT TWO, WHICH IS A NAMED AND NARROWER DEVIATION THAN IT WAS: only the
    // unconfirmed arm's SHOULD is still unmet, and only in its "both" half. s10.2.3 permits the
    // pair to be coalesced ("CONNECTION_CLOSE frames sent in multiple packet types can be
    // coalesced into a single UDP datagram"), so the debt is a second TlsQuicPacketToSend in
    // the list below rather than anything structural.
    private int BuildCloseDatagram(bool application, ulong errorCode, string? reason)
    {
        // A TRANSPORT CODE THAT WILL NOT ENCODE SENDS NOTHING, AND THAT IS THE ABSENCE OF A
        // SUBSTITUTE RATHER THAN A CHOICE BETWEEN SUBSTITUTES. s10.2.3 nominates a replacement
        // code for exactly one situation - converting a 0x1d frame - and names none for a
        // s20.1 code outside s20's "62-bit unsigned integers"; every value this enum defines
        // is inside it, so reaching here means a caller cast something s20.1 never assigned.
        // Sending NO_ERROR would tell the peer the opposite of the truth and sending some other
        // code would invent one, so the frame is dropped and s10.2's closing state is entered
        // regardless - the same outcome, and the same code path, as having no write keys at
        // all. THROWING IS THE ONE OPTION RULED OUT: this is the teardown path.
        if (!application && !IsEncodableErrorCode(errorCode))
        {
            return 0;
        }

        ReadOnlySpan<TlsQuicEncryptionLevel> candidates = _confirmed
            ? [TlsQuicEncryptionLevel.Application]
            : [TlsQuicEncryptionLevel.Handshake, TlsQuicEncryptionLevel.Initial];

        foreach (var candidate in candidates)
        {
            if (!_keys.TryGetWriteKeys(candidate, out var keys, out _))
            {
                continue;
            }

            // s12.4 Table 3 gives 0x1d the row "__01" - a 0-RTT or 1-RTT packet and nothing
            // else - and s10.2.3 says what to do about it rather than leaving the frame
            // undeliverable: "A CONNECTION_CLOSE of type 0x1d MUST be replaced by a
            // CONNECTION_CLOSE of type 0x1c when sending the frame in Initial or Handshake
            // packets. Otherwise, information about the application state might be revealed.
            // Endpoints MUST clear the value of the Reason Phrase field and SHOULD use the
            // APPLICATION_ERROR code when converting to a CONNECTION_CLOSE of type 0x1c."
            // All three halves of that are below, and the Reason Phrase clearing is the one
            // that is a MUST about a field rather than about a type.
            //
            // AND AN UNENCODABLE CODE CONVERTS THE SAME WAY, for the same reason rather than by
            // analogy: s20 bounds an application error code to 62 bits, so one that exceeds it
            // is a code this frame cannot carry - the identical situation to a level that
            // cannot carry the type. s20.1's APPLICATION_ERROR is "The application or
            // application protocol caused the connection to be closed", which stays true when
            // the code itself is dropped, and it is what s10.2.3 already nominates here.
            var convert = application
                && (candidate != TlsQuicEncryptionLevel.Application
                    || !IsEncodableErrorCode(errorCode));

            var sentAsApplicationForm = application && !convert;

            var frame = new TlsQuicFrame
            {
                // s19.19: "Type (i) = 0x1c..0x1d". TlsQuicFrameType.ConnectionClose is the low
                // end and TlsQuicConnectionFrames.ApplicationErrorBit is the bit s19.19's range
                // spends on the distinction, so 0x1d is named rather than written as a literal.
                RawType = sentAsApplicationForm
                    ? (ulong)TlsQuicFrameType.ConnectionClose
                        | TlsQuicConnectionFrames.ApplicationErrorBit
                    : (ulong)TlsQuicFrameType.ConnectionClose,

                // s10.2.3's "SHOULD use the APPLICATION_ERROR code when converting to a
                // CONNECTION_CLOSE of type 0x1c", and s20.1 defines APPLICATION_ERROR (0x0c) as
                // "The application or application protocol caused the connection to be closed",
                // which stays true of a converted frame even though the code itself is dropped.
                ErrorCode = convert
                    ? (ulong)TlsQuicTransportError.ApplicationError
                    : errorCode,

                // s19.19, Frame Type: 0 is not a placeholder for absent - it is the value that
                // means "the frame type is unknown", which is what a close raised by transport
                // parameters rather than by a frame is. It is ALSO the only value the 0x1d form
                // tolerates, since s19.19 gives that form no such field at all and
                // TlsQuicConnectionFrames.WriteConnectionCloseFrameFields throws on a non-zero
                // one - so this line is load-bearing for both arms above, not just the 0x1c one.
                TriggerFrameType = 0,

                // s10.2.3's "Endpoints MUST clear the value of the Reason Phrase field ... when
                // converting to a CONNECTION_CLOSE of type 0x1c".
                ReasonPhrase = convert ? default : ReasonPhraseBytes(reason),
            };

            var written = TlsQuicDatagramBuilder.BuildDatagram(
                _options.Spec,
                [
                    new TlsQuicPacketToSend
                    {
                        // RFC 9000 s17.3.1's short header has none of the four long-header
                        // fields PlanFor sets, so the 1-RTT arm takes the plan the application
                        // send path already builds rather than a fifth arm of PlanFor - which
                        // is why PlanFor throws for Application rather than answering.
                        Plan = candidate == TlsQuicEncryptionLevel.Application
                            ? ShortHeaderPlan()
                            : PlanFor(candidate, _nextPacketNumber[(int)candidate]++),
                        Frames = [frame],
                        PacketProtectionCipher = keys.PacketCipher,
                        Key = keys.Key.ToArray(),
                        Iv = keys.Iv.ToArray(),
                        HeaderProtectionCipher = keys.HeaderCipher,
                        HeaderProtectionKey = keys.HeaderProtectionKey.ToArray(),
                    },
                ],
                _options.TimeProvider.GetUtcNow(),
                _sendBuffer,
                _justSent);
            RetainSentPackets();

            // RECORDED FROM THE FRAME THAT WAS BUILT, NOT FROM THE ARGUMENTS, so that the
            // s10.2.3 conversion above is visible to a reader of these properties rather than
            // hidden behind them: a 0x1d close that went out at Handshake reports the s20.1
            // code it actually carried and no application code, because that is what left.
            if (written > 0)
            {
                if (sentAsApplicationForm)
                {
                    ClosedWithApplicationErrorCode = frame.ErrorCode;
                }
                else
                {
                    ClosedWith = (TlsQuicTransportError)frame.ErrorCode;
                }
            }

            return written;
        }

        return 0;
    }

    // RFC 9000 s7.3, and the reason it is here rather than on TlsQuicTransportParameters: every
    // value it compares against is CONNECTION state - the Destination Connection ID this
    // attempt drew, the Source Connection ID the server is using, the Retry it honoured - and
    // TlsQuicTransportParameters.ValidatePeer sees none of them. That type checks formats and
    // sender roles; this checks agreement with the wire.
    //
    // WHY IT IS WORTH BUILDING AGAINST A SERVER THAT ALWAYS PASSES: s7.3 says it. "Including
    // connection ID values in transport parameters and verifying them ensures that an attacker
    // cannot influence the choice of connection ID for a successful connection by injecting
    // packets carrying attacker-chosen connection IDs during the handshake." The adoption in
    // AcceptedUnderSection122 reads unauthenticated input and cannot not; this is the check
    // that makes that safe, and skipping it deletes the only thing standing behind it.
    //
    // THE CODE IS TRANSPORT_PARAMETER_ERROR EVERYWHERE, and s7.3 offers a choice on three of
    // the five arms: "An endpoint MUST treat the following as a connection error of type
    // TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION". s20.1 settles it, because the two
    // definitions are not symmetrical. TRANSPORT_PARAMETER_ERROR (0x08) is "An endpoint
    // received transport parameters that were badly formatted, included an invalid value,
    // omitted a mandatory transport parameter, included a forbidden transport parameter, or
    // were otherwise in error" - a mismatch is "an invalid value", an absence after a Retry is
    // "omitted a mandatory transport parameter", and a presence without one is "included a
    // forbidden transport parameter", so all three are named clauses of 0x08. PROTOCOL_VIOLATION
    // (0x0a) is "an error with protocol compliance that was not covered by more specific error
    // codes", which defers by its own words wherever 0x08 applies. The other two arms are not a
    // choice at all: s7.3 names TRANSPORT_PARAMETER_ERROR alone for the two absences.
    private async ValueTask ValidateConnectionIdsUnderSection73(
        TlsQuicTransportParameters parameters, CancellationToken cancellationToken)
    {
        // s7.3: "A server includes the Destination Connection ID field from the first Initial
        // packet it received from the client in the original_destination_connection_id
        // transport parameter; if the server sent a Retry packet, this refers to the first
        // Initial packet received before sending the Retry packet." Either way it is the
        // Destination Connection ID we drew, which is why OriginalDestinationConnectionId does
        // not move when Retry moves DestinationConnectionId.
        await RequireParameterAsync(
            parameters,
            TlsQuicTransportParameterId.OriginalDestinationConnectionId,
            OriginalDestinationConnectionId,
            "original_destination_connection_id (0x00)",
            cancellationToken).ConfigureAwait(false);

        // s7.3: "Each endpoint includes the value of the Source Connection ID field from the
        // first Initial packet it sent in the initial_source_connection_id transport
        // parameter."
        //
        // COMPARED AGAINST THE CONNECTION ID WE ARE ADDRESSING, AND THE FIRST DRAFT COMPARED
        // AGAINST THE ONE WE MERELY OBSERVED. The two are the same value against any peer that
        // behaves, which is why the difference survived a mutation sweep as a "no test can
        // separate these" - and then s7.3's own sentences separated them. "The values provided
        // by a peer for these transport parameters MUST match the values that an endpoint used
        // in the Destination and Source Connection ID fields of Initial packets that it sent",
        // and after s7.2's adoption the Destination Connection ID field we USE is
        // _destinationConnectionId. The purpose clause settles which reading is meant:
        // "Including connection ID values in transport parameters and verifying them ensures
        // that an attacker cannot influence the choice of connection ID for a successful
        // connection by injecting packets carrying attacker-chosen connection IDs during the
        // handshake." Under the observed-value reading, an injected first Initial moves the
        // adoption, the parameter still agrees with the honest server's Source Connection ID,
        // and the connection SUCCEEDS while addressing the attacker's value - the exact
        // outcome that sentence exists to deny. Witnessed by
        // AnInjectedFirstInitialThatMovedTheAdoptionIsCaughtBySection73.
        await RequireParameterAsync(
            parameters,
            TlsQuicTransportParameterId.InitialSourceConnectionId,
            _destinationConnectionId,
            "initial_source_connection_id (0x0F)",
            cancellationToken).ConfigureAwait(false);

        // s7.3: "If it sends a Retry packet, a server also includes the Source Connection ID
        // field from the Retry packet in the retry_source_connection_id transport parameter",
        // and both directions of its absence are errors: "absence of the
        // retry_source_connection_id transport parameter from the server after receiving a
        // Retry packet" and "presence of the retry_source_connection_id transport parameter
        // when no Retry packet was received".
        var retrySource = parameters.Get(
            (ulong)TlsQuicTransportParameterId.RetrySourceConnectionId);
        if (_retrySourceConnectionId is { } honoured)
        {
            await RequireParameterAsync(
                parameters,
                TlsQuicTransportParameterId.RetrySourceConnectionId,
                honoured,
                "retry_source_connection_id (0x10)",
                cancellationToken).ConfigureAwait(false);
        }
        else if (retrySource is not null)
        {
            await CloseUnderSection73Async(
                "retry_source_connection_id (0x10) is present although no Retry packet was "
                    + "received",
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask RequireParameterAsync(
        TlsQuicTransportParameters parameters,
        TlsQuicTransportParameterId id,
        ReadOnlyMemory<byte> expected,
        string label,
        CancellationToken cancellationToken)
    {
        var parameter = parameters.Get((ulong)id);
        if (parameter is null)
        {
            await CloseUnderSection73Async($"{label} is absent", cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        // BYTES, NOT LENGTHS. s7.3: "The values provided by a peer for these transport
        // parameters MUST match the values that an endpoint used in the Destination and Source
        // Connection ID fields of Initial packets that it sent". A length comparison here would
        // report agreement for entirely different connection IDs, which is the exact defect
        // TlsQuicFingerprintReadout's own source-CID verdict was found to carry.
        if (!parameter.ValueSpan.SequenceEqual(expected.Span))
        {
            await CloseUnderSection73Async(
                $"{label} is {Hex(parameter.ValueSpan)} and the connection ID it must match is "
                    + Hex(expected.Span),
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask CloseUnderSection73Async(
        string detail, CancellationToken cancellationToken)
    {
        var message =
            "RFC 9000 s7.3 requires the peer's connection ID transport parameters to match the "
                + $"connection IDs actually used, and {detail}. Closing with "
                + $"{TlsQuicTransportError.TransportParameterError}.";

        await CloseAsync(
                TlsQuicTransportError.TransportParameterError, message, cancellationToken)
            .ConfigureAwait(false);

        throw new InvalidOperationException(message);
    }

    private static string Hex(ReadOnlySpan<byte> value) =>
        value.Length == 0 ? "empty" : Convert.ToHexStringLower(value);

    // RFC 9000 s10.1: "the connection is silently closed and its state is discarded when it
    // remains idle for longer than the minimum of the max_idle_timeout value advertised by
    // both endpoints", and, past the wrap that makes the one-sided case easy to miss: "the
    // effective value at an endpoint is computed as the minimum of the two advertised values
    // (or the sole advertised value, if only one endpoint advertises a non-zero value)."
    //
    // NULL MEANS s18.2's "Idle timeout is disabled when both endpoints omit this transport
    // parameter or specify a value of 0" - at which point the local policy on
    // TlsQuicConnectionOptions.IdleTimeout is what bounds the attempt instead, and no s10.1
    // commitment has been made to anybody.
    //
    // s10.1'S THIRD PARAGRAPH IS NOT IMPLEMENTED, AND IT IS A KNOWN GAP: "endpoints MUST
    // increase the idle timeout period to be at least three times the current Probe Timeout
    // (PTO)". The PTO is loss recovery's, which the user's decision defers to A3, so there is
    // no current PTO to take three of. The consequence is one-directional - this connection can
    // give up EARLIER than the RFC's floor, never later - and it is bounded below by the
    // handshake deadline anyway.
    internal TimeSpan? EffectiveIdleTimeout() => (_ourMaxIdleTimeout, _peerMaxIdleTimeout) switch
    {
        ({ } ours, { } theirs) => ours <= theirs ? ours : theirs,
        ({ } ours, null) => ours,
        (null, { } theirs) => theirs,
        _ => null,
    };

    // s18.2: "The maximum idle timeout is a value in milliseconds that is encoded as an
    // integer", over the full 62-bit varint range - which is 146 million years and overflows
    // both TimeSpan and every DateTimeOffset sum built from one. A PEER CHOOSES THIS NUMBER,
    // so a conversion that threw would be a remote kill switch of exactly the shape the
    // discard guard was; it saturates instead. The cap is a year because anything past it is
    // indistinguishable from s18.2's "disabled" for an attempt the handshake deadline already
    // bounds in seconds.
    private static TimeSpan? ToIdleTimeout(ulong? milliseconds)
    {
        if (milliseconds is not { } value || value == 0)
        {
            return null;
        }

        var year = TimeSpan.FromDays(365);
        return value >= (ulong)year.TotalMilliseconds ? year : TimeSpan.FromMilliseconds(value);
    }

    private DateTimeOffset IdleDeadline() =>
        _idleSince + (EffectiveIdleTimeout() ?? _options.IdleTimeout);

    private TimeSpan RemainingBeforeIdleTimeout() =>
        IdleDeadline() - _options.TimeProvider.GetUtcNow();

    // s10.1: "An endpoint also restarts its idle timer when sending an ack-eliciting packet if
    // no other ack-eliciting packets have been sent since last receiving and processing a
    // packet. Restarting this timer when sending a packet ensures that connections are not
    // closed after new activity is initiated." The condition is the whole of the flag: a
    // second ack-eliciting packet in the same silence does NOT restart it.
    private void RestartIdleTimerOnAckElicitingSend(DateTimeOffset now)
    {
        if (_sentAckElicitingSinceReceive)
        {
            return;
        }
        _idleSince = now;
        _sentAckElicitingSinceReceive = true;
    }

    // s10.1 twice over, and the two arms differ in whether a frame goes on the wire.
    //
    // IDLE, AT THE EFFECTIVE VALUE: "the connection is SILENTLY closed and its state is
    // discarded". No CONNECTION_CLOSE - the peer's own timer is running out at the same
    // moment, which is what the minimum-of-both rule buys.
    //
    // ANY OTHER ABANDONMENT, HAVING ADVERTISED ONE: "By announcing a max_idle_timeout, an
    // endpoint commits to initiating an immediate close (Section 10.2) if it abandons the
    // connection prior to the effective value." The handshake deadline is exactly that
    // abandonment - it is local policy with no RFC source, and it is shorter than any
    // max_idle_timeout worth advertising - so the commitment is honoured with a NO_ERROR
    // close. s20.1: "An endpoint uses this with CONNECTION_CLOSE to signal that the connection
    // is being closed abruptly in the absence of any error."
    private async ValueTask<TimeoutException> AbandonAsync(CancellationToken cancellationToken)
    {
        // WHICHEVER DEADLINE IS NEARER IS THE ONE THAT FIRED, and this is a comparison rather
        // than a test for "has it passed". When a peer answers LATE both remainings are negative
        // and the more negative one expired first; when a peer goes SILENT the token source ends
        // the receive and the ORDER is what says which bound armed it.
        //
        // AND THE CASE THIS USED TO NAME NO LONGER EXISTS, which is worth the correction rather
        // than the deletion. It read "a peer that goes SILENT ends the receive through the token
        // source, which runs on TimeProvider's own timer, WHILE GetUtcNow ON A FAKE CLOCK HAS
        // NOT MOVED AT ALL. Both remainings are then still positive". That described a test
        // provider overriding GetUtcNow and nothing else, and A3-1's ManualTimeProvider - now
        // the only fake clock this tree has - overrides CreateTimer too and sets its reading TO
        // each timer's due instant before firing it. So on every provider in this tree the two
        // move together and the fired deadline's remaining is non-positive by the time this
        // line runs. THE COMPARISON IS STILL THE RIGHT SHAPE - it is what picks between two
        // deadlines that have BOTH passed - but it is no longer standing in for a clock that
        // did not move. A3-5's row 145 is the mutation that measures the difference, and it
        // survives for exactly this reason.
        var idle = RemainingBeforeIdleTimeout() <= RemainingBeforeDeadline();
        IdleTimedOut = idle;

        if (idle && EffectiveIdleTimeout() is not null)
        {
            _draining = true;
            return IdleTimeoutExceeded();
        }

        if (_ourMaxIdleTimeout is not null)
        {
            await CloseAsync(
                    TlsQuicTransportError.NoError,
                    "RFC 9000 s10.1: this endpoint advertised a max_idle_timeout and is "
                        + "abandoning the connection before the effective value, so it owes an "
                        + "immediate close.",
                    cancellationToken).ConfigureAwait(false);
        }

        _draining = true;
        return idle ? IdleTimeoutExceeded() : DeadlineExceeded();
    }

    private TimeoutException IdleTimeoutExceeded() => new(
        $"The QUIC connection was idle for longer than {EffectiveIdleTimeout() ?? _options.IdleTimeout}"
            + " and was closed under RFC 9000 s10.1. "
            + (EffectiveIdleTimeout() is null
                ? "That period is TlsQuicConnectionOptions.IdleTimeout, local policy: neither "
                    + "endpoint advertised a non-zero max_idle_timeout, which s18.2 makes the "
                    + "state in which idle timeout is disabled."
                : "That period is s10.1's minimum of the two advertised max_idle_timeout "
                    + "values, so the close is silent and carries no CONNECTION_CLOSE frame."));

    // RFC 9000 s17.2.5.3: "The value of the Token field is copied to all subsequent Initial
    // packets." Before a Retry the spec's knob is what a client carries - s8.1's NEW_TOKEN
    // token, which A4-minimal never receives and subsystem B varies - and after one the Retry
    // token replaces it. There is no state in which both apply, so this is a choice rather
    // than a concatenation.
    private ReadOnlyMemory<byte> TokenForInitial =>
        _retryToken.Length > 0 ? _retryToken : _options.Spec.Token;

    private TlsQuicPacketPlan PlanFor(TlsQuicEncryptionLevel level, ulong packetNumber) => new()
    {
        Type = level switch
        {
            TlsQuicEncryptionLevel.Initial => TlsQuicLongPacketType.Initial,
            TlsQuicEncryptionLevel.Handshake => TlsQuicLongPacketType.Handshake,

            // EarlyData means 0-RTT, which A4-minimal never sends. APPLICATION IS NO LONGER
            // HERE: task 14c added the short header, and its plan is ShortHeaderPlan's in
            // TlsQuicApplicationSendPath.cs, because a 1-RTT packet has no Version, no Source
            // Connection ID, no Token and no Length - four of the fields this initialiser
            // sets - so routing it through here would build a plan the builder rejects.
            //
            // UNREACHABLE BY CONSTRUCTION AND DELIBERATELY UNWITNESSED: BuildAnswerDatagram is
            // this method's only caller and AscendingLevels/DescendingLevels no longer name
            // Application at all, so EarlyData is the only level that could reach this arm and
            // the loop skips it for its own stated reason. A test would have to call a private
            // method or re-add the skip it deleted.
            _ => throw new NotSupportedException(
                $"This connection builds no long header packet for {level} data."),
        },
        Version = (uint)Version,
        DestinationConnectionId = _destinationConnectionId,
        SourceConnectionId = _sourceConnectionId,

        // RFC 9000 s17.2.2's Token, Initial packets only, and a client holds one only after a
        // Retry or a NEW_TOKEN frame.
        Token = level == TlsQuicEncryptionLevel.Initial ? TokenForInitial : default,
        PacketNumber = packetNumber,
        PacketNumberEncodedLength = _options.Spec.PacketNumberEncodedLength,

        // Task 8's ProcessAckFrame is what advances this; RFC 9000 Appendix A.2 uses it to
        // bound the encoded packet number length from below.
        LargestAcknowledged = _acks.LargestAcked(level),

        // FINGERPRINT FIELD 7, AND THIS IS THE MAPPING THAT MAKES IT HONOURED. The plan's
        // amendment after task 5 records that all three of these spec properties were
        // validated, stored, and read by nothing under src/ - "a knob is honoured only if a
        // caller setting it on the type the caller holds changes a byte", and this is the
        // caller that closes that gap for TlsQuicConnectionSpec.
        LengthVarintWidth = _options.Spec.HeaderLengthVarintWidth,
        CryptoOffsetVarintWidth = _options.Spec.CryptoOffsetVarintWidth,
        CryptoLengthVarintWidth = _options.Spec.CryptoLengthVarintWidth,
    };
}
