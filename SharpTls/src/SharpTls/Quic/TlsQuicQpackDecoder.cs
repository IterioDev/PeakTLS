namespace SharpTls.Quic;

// ============================================================================
// THE MUTATION LEDGER - TASK C8 (this file)
// ============================================================================
//
//   ROWS BELOW                   16  = numbered 1-16 with no gaps
//   KILLED WHEN FIRST RUN        15  = 16 rows, less 0 [WAS-SURVIVOR] and 1 [SURVIVED]
//   SURVIVED, THEN FIXED OR       0  = none
//     WITNESSED
//   SURVIVING STILL               1  = row 15, classified below
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' TlsQuicQpackDecoder.cs`                  must return 16
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicQpackDecoder.cs` must return 0
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' TlsQuicQpackDecoder.cs`     must return 1
//
// Every row was run in a `git worktree` of its own, one edit at a time, each restored before
// the next, against `dotnet test --filter FullyQualifiedName~Qpack`. Counts are per xUnit
// CASE. See TlsQuicQpackEncoder.cs's ledger for the harness defect this sweep started with.
//
//   1. The s4.5.2 T-bit check deleted, so a dynamic indexed field line is read as a static
//      one. Killed by 3 including .OnlyTheTBitSeparatesARejectionFromADecodedField.
//   2. The s4.5.4 T-bit check deleted. Killed by 3.
//   3. The s4.5.6 pattern widened from `001` to `001 or 0001`, so s4.5.3's post-Base indexed
//      field line is swallowed by the literal branch and read as a field. This is the
//      "misread rather than reject" failure named in the task, in code. Killed by 2 including
//      .AllSixSubsectionsOfSection45AreRecognised.
//   4. The Required Insert Count check deleted. Killed by 4.
//   5. The s4.5.1.2 Sign/Delta Base check deleted. Killed by 4.
//   6. The same check inverted to `!sign`, which rejects every WELL-FORMED prefix. Killed by
//      37 - the widest blast radius in the sweep, and the reason it is here: a guard that
//      fires on everything is as broken as one that fires on nothing, and only a test that
//      decodes a legal section notices. .AClearSignBitAcceptsAnyDeltaBase is that test.
//   7. The static index clamp `(int)Math.Min(index, int.MaxValue)` -> `(int)index`, so an
//      index of 2^32 + 1 truncates to 1 and hands back `:path` `/`. Killed by exactly one
//      case, .AStaticIndexPastTheTableIsRejected at that value - the other three values in
//      that Theory all still reject under the mutation, which is why the fourth was added.
//   8. RFC 9114 s4.2.2's 32-byte per-field overhead -> 0. Killed by 3.
//   9. The limit comparison `>` -> `>=`, an off-by-one at the exact advertised size. Killed
//      by 3.
//  10. The accounted size taken from the octets CONSUMED rather than from the uncompressed
//      name and value, which s4.2.2 requires. Invisible unless a Huffman-coded field is
//      measured, which is what .TheAccountedSizeIsTheUncompressedOne does. Killed by 3.
//  11. The section total assigned rather than accumulated, so the limit becomes per field
//      line instead of per section. Killed by exactly one case,
//      .TheLimitAccumulatesAcrossFieldLines.
//  12. The `lines` full check deleted, so a full output span is written past. Killed by
//      exactly one case, .AShortOutputBufferIsALocalAnswerAndNotAConnectionError.
//  13. TryAppend's bound deleted. Killed by 2 including .NoShortInputThrows.
//  14. TryGetHttp3ErrorCode mapping DestinationTooSmall to QPACK_DECOMPRESSION_FAILED, which
//      would close a healthy connection over our own buffer size. Killed by 1.
//  15. [SURVIVED] TryDecodeFieldLine's `source.IsEmpty` guard deleted. UNREACHABLE BY
//      CONSTRUCTION, not unwitnessed: the method is private and its only caller loops on
//      `offset < source.Length`, so `source[offset..]` is never empty. NO TEST IS WRITTEN
//      FOR IT. The guard stays because the method is one refactor away from being called
//      with an empty span and `source[0]` on an empty span is a throw, not a rejection - see
//      the note at the guard itself.
//  16. The prefix's `rest.IsEmpty` guard deleted, which throws on a one-octet field section.
//      Reachable, unlike row 15, because the prefix reader is entered on any input at all.
//      Killed by 3 including .NoShortInputThrows.
//
// ============================================================================

// ============================================================================
// THE MUTATION LEDGER - TASK C15 (this file: s4.4's decoder instructions, s4.5.1.1's
// Required Insert Count, s4.5.1.2's Base, and the four dynamic field-line arms)
// ============================================================================
//
//   ROWS BELOW                   45  = C15-1 to C15-45 with no gaps
//   KILLED WHEN FIRST RUN        41  = 45 rows, less 3 [WAS-SURVIVOR] and 1 [SURVIVED]
//     of which killed at BUILD    2  = C15-44 and C15-45, both [RESTATED] to compile and
//                                      then killed by tests; a build failure is a weaker
//                                      verdict than a test failure, and C14's row 39 is the
//                                      precedent for restating rather than banking one
//   SURVIVED, THEN WITNESSED      3  = C15-21, C15-26, C15-29
//   SURVIVING STILL               1  = C15-25, classified below
//
//   41 + 3 + 1 = 45. The other 5 rows of this task are in TlsQuicHttp3Streams.cs's C15
//   ledger, C15-46 to C15-50; 45 + 5 = 50 rows for the task.
//
// A UNIQUE ROW PREFIX, because C8's ledger above counts itself with
// `grep -cE '^// +[0-9]+\. '` and must keep returning 16. These rows carry `C15-` so that
// grep does not see them. Their own three, run from this file's directory:
//   `grep -cE '^// +C15-[0-9]+\. ' TlsQuicQpackDecoder.cs`                  must return 45
//   `grep -cE '^// +C15-[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicQpackDecoder.cs` must return 3
//   `grep -cE '^// +C15-[0-9]+\..*\[SURVIVED\]' TlsQuicQpackDecoder.cs`     must return 1
//
// Every row was run against C15's gate, `dotnet test --filter "FullyQualifiedName~Quic"`, in
// a private worktree, one edit at a time, each restored before the next, with
// `--no-incremental` builds and `--no-build` tests. Counts are per xUnit CASE. The harness
// rejects any run whose executed-case total falls below 95% of the unmutated baseline of
// 2032, because an aborted run prints an ordinary `Failed: 0, Passed: <m>` line and would
// otherwise read as a survivor that never ran. It was calibrated in BOTH directions before
// the sweep: a known-bad edit (s4.4.1's prefix 7 -> 1) was KILLED in 9 cases, and an inert
// comment above TlsQuicQpackDecoderStream SURVIVED.
//
// --- s4.4's opcode prefix tree (7 rows) ---
//
//   C15-1. s4.4.1's stream-id prefix 7 -> 6. Killed by 5, the
//        .TheSectionAcknowledgmentPrefixIsSevenBitsWide Theory. Appendix B's published stream
//        id of 4 does NOT kill it - 4 sits below both masks - which is why that Theory exists.
//   C15-2. s4.4.2's stream-id prefix 6 -> 5. Killed by 5.
//   C15-3. s4.4.3's Increment prefix 6 -> 7. THE SILENT WIDENING: s4.4.3's pattern contributes
//        no set bits, so a wider prefix does not collide with the opcode and TryEncodeInteger
//        does not object. Killed by 4, and only by the rows at 63 and above.
//   C15-4. s4.4.3's Increment prefix 6 -> 5. Killed by 4.
//   C15-5. s4.4.2's '01' pattern -> '00', so a Stream Cancellation is shaped as an Insert
//        Count Increment. Killed by 8.
//   C15-6. s4.4.1's '1' pattern dropped. Killed by 10.
//   C15-7. s4.4.3 written under s4.4.2's pattern. Killed by 9.
//
// --- s4.4.1's and s4.4.3's suppressions, and s2.1.4's count (9 rows) ---
//
//   C15-8. s4.4.1's non-zero condition removed, so EVERY field section is acknowledged - the
//        first of the two traps the capture's header flags. Killed by 2.
//   C15-9. s4.4.3's suppression `<=` -> `<`, which emits an Increment of exactly zero at
//        equality - the second flagged trap, at the one value that reaches it. Killed by 4.
//  C15-10. s4.4.3's suppression removed entirely. Killed by 4.
//  C15-11. s4.4.3 sends the running total rather than the difference. Still a well-formed
//        instruction, and wrong. Killed by 4.
//  C15-12. s2.1.4's "greater than" dropped, so an acknowledgment walks the Known Received
//        Count BACKWARDS. Killed by exactly one case,
//        .AnAcknowledgmentNeverWalksTheKnownReceivedCountBackwards, which is the only row
//        where a later acknowledgment carries a smaller Required Insert Count.
//  C15-13. s2.1.4's acknowledgment raise removed. Killed by 8.
//  C15-14. s2.1.4's increment raise removed. Killed by 4.
//  C15-15. The acknowledgment's raise moved BEFORE the encode, so a destination too short
//        still moves the count. Killed by exactly one case, .AShortDestinationIsRefusedAnd
//        MovesNothing - the desynchronisation nothing downstream could ever notice.
//  C15-16. [RE-LISTED as a different edit of the same line as C15-14] the increment's raise
//        made unreachable rather than deleted. Killed by 4.
//
// --- s4.5.1.1's Required Insert Count (11 rows) ---
//
//  C15-17. MaxEntries divisor 32 -> 64. Killed by 2.
//  C15-18. FullRange `2 * MaxEntries` -> `MaxEntries`. Killed by 8.
//  C15-19. The conformance bound `>` -> `>=`. Killed by 1.
//  C15-20. The conformance bound removed, which is ALSO the division-by-zero guard: at a
//        maximum capacity below 32 both MaxEntries and FullRange are zero. Killed by 1, and
//        killed as a throw rather than a wrong answer, which is the claim the ordering
//        comment at the guard makes.
//  C15-21. [WAS-SURVIVOR] MaxValue loses its MaxEntries term.
//        SURVIVED THE WHOLE CAPTURE-ANCHORED WALK AND s4.5.1.1'S OWN WORKED EXAMPLE. B.2 and
//        B.4 have MaxWrapped = 0 with or without the term. The worked example is worse: at
//        100 bytes and 10 inserts, MaxValue 13 gives MaxWrapped 12 and candidate 15, which
//        the wrap correction pulls back to 9; MaxValue 10 gives MaxWrapped 6 and candidate 9
//        with NO correction - two different routes to the same published answer.
//        Witnessed by .ARequiredInsertCountAheadOfOurOwnInsertsStillReconstructs, at an
//        EncodedInsertCount of 1: 12 correctly, 6 under the mutant. The term is exactly what
//        lets a Required Insert Count AHEAD of our inserts reconstruct, which is what s2.2.1's
//        blocked decoding is for - so the blind spot and the unimplemented feature are the
//        same gap. Now killed, in 2 cases.
//  C15-22. MaxWrapped not floored to a multiple of FullRange. Killed by 7.
//  C15-23. The `- 1` dropped. Killed by 8.
//  C15-24. The "wrapped one fewer time" correction removed. Killed by exactly one case, the
//        worked example - the only vector in the RFC that reaches it.
//  C15-25. [SURVIVED] The correction's inner bound `candidate <= fullRange` -> `<`.
//        UNREACHABLE BY CONSTRUCTION, and the proof is short. That bound is read only inside
//        `candidate > maxValue`, and the two widths differ only at `candidate == fullRange`.
//        Write MaxWrapped as k * FullRange. If k == 0 then candidate = EncodedInsertCount - 1
//        <= FullRange - 1, so it cannot equal FullRange. If k >= 1 then MaxValue >= MaxWrapped
//        >= FullRange, and candidate == FullRange forces MaxWrapped == FullRange and
//        EncodedInsertCount == 1, giving candidate == FullRange <= MaxValue - so
//        `candidate > maxValue` is false and the bound is never read. NO TEST IS WRITTEN FOR
//        IT; one would have to assert a value the reconstruction cannot produce. The `<=` is
//        kept because it is what the capture's pseudocode says, and a decoder is not the place
//        to improve on transcribed arithmetic.
//  C15-26. [WAS-SURVIVOR] "Value of 0 must be encoded as 0" removed.
//        Survived because reaching it needs an Insert Count BELOW MaxEntries - candidate is
//        zero only when MaxWrapped is zero and EncodedInsertCount is 1 - and every table in
//        the tests had been filled first. Witnessed inside
//        .AnEncodedInsertCountNoConformantEncoderCouldProduceIsRejected with a FRESH 100-byte
//        table, where an EncodedInsertCount of 1 must be refused and 2 must decode to 1. Now
//        killed, in 1 case.
//  C15-27. The `EncodedInsertCount == 0` short-circuit removed. Killed by 1.
//
// --- s4.5.1.2's Base (4 rows) ---
//
//  C15-28. The subtracting arm loses its `- 1`. Killed by 2.
//  C15-29. [WAS-SURVIVOR] The adding arm ignores Delta Base.
//        EVERY PUBLISHED VECTOR SETS DELTA BASE TO ZERO, and s4.5.1.2 says why - "setting
//        Delta Base to zero is one of the most efficient encodings" - so B.4's `0500` and
//        every prefix in the tests put the Base at the Required Insert Count whether or not
//        the addition happens. C14's row-5 shape exactly: the capture cannot witness its own
//        blind spot. Witnessed by .AClearSignBitAddsDeltaBaseToTheRequiredInsertCount, at
//        Delta Base 2, which moves the resolved entry two rows. Now killed, in 1 case.
//  C15-30. The two arms swapped. Killed by 7.
//  C15-31. s4.5.1.2's MUST "less than or equal to" -> "less than". Killed by 3.
//
// --- s4.5.2 to s4.5.5's dynamic arms (9 rows) ---
//
//  C15-32. s4.5.3's post-Base index prefix 4 -> 3. Killed by 1.
//  C15-33. s4.5.3's post-Base index prefix 4 -> 5. Killed by 3.
//  C15-34. s4.5.5's post-Base name prefix 3 -> 4, which swallows the 'N' bit. Killed by
//        exactly one case, .ThePostBasePrefixesAreFourBitsAndThreeBitsAndTheNBitStraddlesThe
//        Narrower - and only by its N-SET vectors, because with 'N' clear the two widths
//        decode index 6 identically. This is C14's row 5 reproduced deliberately.
//  C15-35. s4.5.3 and s4.5.5 separated by the 'N' bit rather than by their opcode bit.
//        Killed by 3.
//  C15-36. s4.5.2's T = 0 resolved as a post-Base index - s3.2.5's subtraction replaced by
//        s3.2.6's addition. Killed by 3.
//  C15-37. s4.5.3 resolved as a field-relative index, the same swap the other way. Killed
//        by 5.
//  C15-38. s4.5.4's T = 0 name resolved as a post-Base index. Killed by 2.
//  C15-39. s4.5.5's name resolved as a field-relative index. Killed by 4.
//  C15-40. s4.5.2's T = 0 index read at s4.5.4's 4-bit width rather than its own 6-bit one.
//        Killed by 2.
//
// --- resolution, copying, and the two arms (5 rows) ---
//
//  C15-41. s3.2.5 and s3.2.6 exchanged inside TryResolveDynamic, so BOTH callers of each are
//        wrong at once. Killed by 7.
//  C15-42. The resolution result ignored, so an index that resolved to nothing is looked up
//        anyway. Killed by 2.
//  C15-43. TryCopyPair's name and value slices exchanged. Killed by 104 - the widest blast
//        radius in the sweep, and unsurprising: every dynamic field line in every test reads
//        back reversed.
//  C15-44. [RESTATED] The two prefix arms exchanged, so a table selects the zero-only rule and
//        no table selects the reconstruction. As first written it did not COMPILE - the null
//        arm would pass a null table to a non-nullable parameter - which is a weaker verdict
//        than a test failure. Restated with `table!` so it compiles and faults at runtime;
//        killed by 17.
//  C15-45. [RESTATED] s4.5.2's null-arm rejection deleted. Same story, same fix: restated with
//        `table!` and killed by 7.
//
// ============================================================================

// RFC 9204 s4.5's field line representations, decoding side. See
// reference-captures/rfc9204-section4.5-field-line-representations.txt,
// reference-captures/rfc9204-section3-reference-tables.txt and
// reference-captures/rfc9204-section5-6-configuration-and-error-handling.txt.
//
// It recognises all five line representations plus the s4.5.1 prefix - six subsections in
// all - and the recognition is EXHAUSTIVE over the first octet, so nothing arrives here and
// gets misread as something else:
//
//   1 T ......   s4.5.2 Indexed Field Line                    T = 1 static, T = 0 dynamic
//   0 1 N T ..   s4.5.4 Literal With Name Reference           T = 1 static, T = 0 dynamic
//   0 0 1 N ..   s4.5.6 Literal With Literal Name             no table reference at all
//   0 0 0 1 ..   s4.5.3 Indexed With Post-Base Index          dynamic-only by shape
//   0 0 0 0 ..   s4.5.5 Literal With Post-Base Name Reference dynamic-only by shape
//
// Those five branches partition the octet: the top bit splits it once, then '01', '001',
// '0001' and '0000' exhaust what is left. There is no default arm because there is nothing
// for one to catch.
//
// TWO ARMS, CHOSEN BY WHETHER A TlsQuicQpackDynamicTable IS PASSED IN. C15 added the second.
//
//   * table == null - the STATIC-ONLY arm C8 built. The Required Insert Count must be zero
//     and all four dynamic shapes above are rejected with DynamicTableReference. Legal only
//     while SETTINGS_QPACK_MAX_TABLE_CAPACITY is zero; see the note in
//     TryDecodeFieldSectionPrefix, which C8 wrote as a warning and which C15 has now made
//     true of one arm rather than of the file.
//   * table != null - all six subsections resolve. The Required Insert Count is
//     reconstructed by s4.5.1.1's algorithm, the Base by s4.5.1.2's, and the three indexing
//     modes are C14's TryResolveFieldRelative, TryResolvePostBase and TryLookupAbsolute. The
//     TABLE IS NEVER MUTATED HERE - it is the peer's encoder stream that drives it, in
//     TlsQuicQpackDynamicTable.TryReadEncoderInstructions.
//
// C16 ADDED s2.2.1'S BLOCKING, AND WITH IT TWO MORE MUSTs.
//
//   * s2.2.1: a field section whose Required Insert Count exceeds our Insert Count answers
//     TlsQuicQpackError.Blocked instead of failing its references. Blocked is NOT a connection
//     error - TryGetHttp3ErrorCode refuses to map it - and the caller re-presents the SAME
//     bytes once the encoder stream has caught up. TlsQuicQpackBlockedStreams, at the foot of
//     this file, is where a caller parks one and where s2.1.2's bound on how many may be
//     parked at once is enforced.
//   * s2.2.3 and s2.2.1 together: every dynamic reference's ABSOLUTE index must be below the
//     declared Required Insert Count. See TryResolveDynamic, which argues there why that one
//     comparison is both sentences.
//
// WHAT IT STILL DOES NOT DO. s2.2.1's "If it encounters a Required Insert Count larger than
// expected, it MAY treat this as a connection error of type QPACK_DECOMPRESSION_FAILED" is a
// MAY and this decoder DECLINES it. The MUST half beside it is enforced; taking the MAY would
// mean refusing a section whose declared count is higher than its references need - which
// costs a peer's encoder nothing to avoid and costs us a closed connection if our idea of
// "expected" is ever off by one. A declined MAY is a decision, so it is written down here
// rather than left as an absence.
//
// NOTHING HERE THROWS on any `source`. Every field is read through
// TlsQuicQpackPrimitives.TryDecodeInteger, TlsQuicQpackPrimitives.TryDecodeStringLiteral or
// TlsQuicQpackHuffman.TryDecode, all three of which are total over their input, and every
// index is bounds-checked before it reaches either table. NOTHING HERE ALLOCATES either, on
// any path - names and values are written into a caller-supplied buffer and C14's table hands
// back spans over arrays it already owns - so the rejecting path allocates zero bytes for the
// same reason the accepting one does.
internal static class TlsQuicQpackDecoder
{
    // RFC 9204 s6: "QPACK_DECOMPRESSION_FAILED (0x0200): The decoder failed to interpret an
    // encoded field section and is not able to continue decoding that field section."
    internal const ulong QpackDecompressionFailed = 0x0200;

    private const byte IndexedFieldLineFlag = 0b1000_0000;
    private const byte IndexedFieldLineStaticFlag = 0b0100_0000;
    private const byte LiteralNameReferenceFlag = 0b0100_0000;
    private const byte LiteralNameReferenceStaticFlag = 0b0001_0000;
    private const byte LiteralLiteralNameFlag = 0b0010_0000;
    private const byte PostBaseIndexFlag = 0b0001_0000;
    private const byte SignFlag = 0b1000_0000;

    private const int IndexedFieldLinePrefixBits = 6;
    private const int NameReferencePrefixBits = 4;
    private const int NameLiteralPrefixBits = 4;
    private const int ValueLiteralPrefixBits = 8;
    private const int RequiredInsertCountPrefixBits = 8;
    private const int DeltaBasePrefixBits = 7;

    // s4.5.3's Figure 14 - '0001' then a 4-bit prefix - and s4.5.5's Figure 16 - '0000', then
    // the 'N' bit, then a 3-bit prefix. THE TWO WIDTHS DIFFER BY ONE because s4.5.5 spends a
    // bit on 'N' and s4.5.3 has none, which is the kind of neighbouring pair a single test
    // vector cannot separate; see the boundary vectors in the tests.
    private const int PostBaseIndexPrefixBits = 4;
    private const int PostBaseNameReferencePrefixBits = 3;

    // RFC 9114 s4.2.2: "an overhead of 32 bytes for each field". A constant of the size
    // accounting and not of the wire format, which is why it lives with the decoder that
    // enforces the limit rather than with the representations.
    private const long FieldSectionSizeOverheadPerField = 32;

    // Every rejection this decoder can produce is a failure to interpret an encoded field
    // section, so every one of them maps to the same s6 code. THREE ANSWERS ARE NOT
    // REJECTIONS and must not be mapped: None, DestinationTooSmall - the CALLER's buffer was
    // short, not the peer wrong - and C16's Blocked, which says the encoder stream has not
    // caught up yet. Blocked is the newest and the most dangerous to get wrong: s2.1.2 exists
    // precisely because "QUIC does not guarantee order between data on different streams", so
    // a decoder that closed the connection on one would close it on ordinary reordering.
    internal static bool TryGetHttp3ErrorCode(TlsQuicQpackError error, out ulong code)
    {
        code = QpackDecompressionFailed;
        return error is not (TlsQuicQpackError.None
            or TlsQuicQpackError.DestinationTooSmall
            or TlsQuicQpackError.Blocked);
    }

    // Decodes a whole encoded field section.
    //
    // `buffer` receives every decoded name and value back to back, and each entry of `lines`
    // points into it. Static table entries are copied in alongside the literals so that the
    // output has ONE backing store and a caller never has to ask where a given field came
    // from. `maximumFieldSectionSize` is RFC 9114 s4.2.2's limit, applied to the
    // UNCOMPRESSED sizes as that section requires; pass long.MaxValue for no limit.
    internal static bool TryDecodeFieldSection(
        ReadOnlySpan<byte> source,
        Span<byte> buffer,
        Span<TlsQuicQpackDecodedFieldLine> lines,
        long maximumFieldSectionSize,
        out int lineCount,
        out int bufferUsed,
        out TlsQuicQpackError error) =>
        TryDecodeFieldSectionAgainstTable(
            source, buffer, lines, maximumFieldSectionSize, null, out lineCount, out bufferUsed, out _, out error);

    // The same decode with C14's dynamic table behind it, and with the Required Insert Count
    // the section DECLARED handed back.
    //
    // A DIFFERENT NAME RATHER THAN AN OVERLOAD, which is not a style choice: three files this
    // task does not own carry `<see cref="TlsQuicQpackDecoder.TryDecodeFieldSection"/>`, and a
    // second method of that name makes every one of them CS0419, which is an error here. The
    // name change is confined to this file; the seven-argument entry point above is untouched.
    //
    // THE REQUIRED INSERT COUNT IS AN OUTPUT AND NOT A DETAIL. s4.4.1 emits a Section
    // Acknowledgment "After processing an encoded field section whose declared Required Insert
    // Count is not zero" and emits NOTHING otherwise, so a caller that cannot see this number
    // cannot obey that sentence. It is the reconstructed value, not the octet on the wire -
    // s4.5.1.1 transforms one into the other and only the reconstructed one is comparable with
    // s2.1.4's Known Received Count. See TlsQuicQpackDecoderStream, which consumes it.
    //
    // `table` may be null, which selects the static-only arm; see the two-arm note above the
    // class. A non-null table is READ and never written.
    internal static bool TryDecodeFieldSectionAgainstTable(
        ReadOnlySpan<byte> source,
        Span<byte> buffer,
        Span<TlsQuicQpackDecodedFieldLine> lines,
        long maximumFieldSectionSize,
        TlsQuicQpackDynamicTable? table,
        out int lineCount,
        out int bufferUsed,
        out ulong requiredInsertCount,
        out TlsQuicQpackError error)
    {
        lineCount = 0;
        bufferUsed = 0;

        if (!TryDecodeFieldSectionPrefix(
                source, table, out requiredInsertCount, out ulong baseValue, out int offset, out error))
        {
            return false;
        }

        // s2.2.1's first two sentences, and the whole of C16 in three lines: "Upon receipt of
        // an encoded field section, the decoder examines the Required Insert Count. When the
        // Required Insert Count is less than or equal to the decoder's Insert Count, the field
        // section can be processed immediately. Otherwise, the stream on which the field
        // section was received becomes blocked."
        //
        // DECIDED FROM THE PREFIX ALONE, BEFORE ANY REPRESENTATION IS READ, because that is
        // what the sentence says and because it is the only reading that is stable: a section
        // that happens to reference nothing still blocks if it DECLARED a count we cannot
        // reach, and a decoder that looked at the representations first would answer
        // differently depending on how far it got.
        //
        // NOTHING IS COMMITTED HERE. lineCount and bufferUsed are still zero and
        // `requiredInsertCount` is already set, which is what lets a caller park the section
        // and re-present the SAME bytes later - see TlsQuicQpackBlockedStreams for why the
        // count it parks is this one and not one reconstructed a second time.
        if (table is not null && requiredInsertCount > table.InsertCount)
        {
            error = TlsQuicQpackError.Blocked;
            return false;
        }

        long sectionSize = 0;
        while (offset < source.Length)
        {
            if (lineCount == lines.Length)
            {
                error = TlsQuicQpackError.DestinationTooSmall;
                return false;
            }

            if (!TryDecodeFieldLine(
                    source[offset..],
                    buffer,
                    table,
                    baseValue,
                    requiredInsertCount,
                    ref bufferUsed,
                    out TlsQuicQpackDecodedFieldLine line,
                    out int consumed,
                    out error))
            {
                return false;
            }

            // s4.2.2's arithmetic, in long and before anything is committed, so a section
            // that would overflow an int total is rejected rather than wrapping into a small
            // number that passes.
            sectionSize += line.NameLength + line.ValueLength + FieldSectionSizeOverheadPerField;
            if (sectionSize > maximumFieldSectionSize)
            {
                error = TlsQuicQpackError.FieldSectionTooLarge;
                return false;
            }

            lines[lineCount] = line;
            lineCount++;
            offset += consumed;
        }

        error = TlsQuicQpackError.None;
        return true;
    }

    // RFC 9204 s4.5.1's two integers.
    private static bool TryDecodeFieldSectionPrefix(
        ReadOnlySpan<byte> source,
        TlsQuicQpackDynamicTable? table,
        out ulong requiredInsertCount,
        out ulong baseValue,
        out int consumed,
        out TlsQuicQpackError error)
    {
        consumed = 0;
        requiredInsertCount = 0;
        baseValue = 0;
        if (!TlsQuicQpackPrimitives.TryDecodeInteger(
                source,
                RequiredInsertCountPrefixBits,
                out ulong encodedInsertCount,
                out int countLength,
                out error))
        {
            return false;
        }

        // ============================================================================
        // THE COUPLING TO SETTINGS_QPACK_MAX_TABLE_CAPACITY. READ THIS BEFORE RAISING IT.
        // ============================================================================
        // With no table this decoder has nowhere to resolve a dynamic reference, and that is
        // legal ONLY while we advertise a maximum capacity of zero. RFC 9204 s3.2.3: "When the
        // maximum table capacity is zero, the encoder MUST NOT insert entries into the dynamic
        // table and MUST NOT send any encoder instructions on the encoder stream." s5 makes
        // SETTINGS_QPACK_MAX_TABLE_CAPACITY default to zero, so a conformant peer's encoder
        // cannot reference a dynamic entry and cannot need a non-zero Required Insert Count.
        //
        // C8 WROTE "IF SOMEONE RAISES THAT SETTING, THIS DECODER BECOMES WRONG", AND SOMEONE
        // HAD. TlsQuicHttp3Spec.CaptureSettings - which is the DEFAULT of TlsQuicHttp3Spec
        // .Settings, not an alternative to it - carries QpackMaxTableCapacityIdentifier at
        // 65536, so this stack has been advertising a 65536-byte dynamic table and refusing
        // every field section that used one. C14 built the table; passing one in is the fix,
        // and the null arm below survives only for a spec that really does advertise zero.
        if (table is null)
        {
            if (encodedInsertCount != 0)
            {
                error = TlsQuicQpackError.RequiredInsertCountNotZero;
                return false;
            }
        }
        else if (!TryReconstructRequiredInsertCount(
                     encodedInsertCount, table, out requiredInsertCount, out error))
        {
            return false;
        }

        ReadOnlySpan<byte> rest = source[countLength..];
        if (rest.IsEmpty)
        {
            error = TlsQuicQpackError.Truncated;
            return false;
        }

        bool sign = (rest[0] & SignFlag) != 0;
        if (!TlsQuicQpackPrimitives.TryDecodeInteger(
                rest,
                DeltaBasePrefixBits,
                out ulong deltaBase,
                out int baseLength,
                out error))
        {
            return false;
        }

        // s4.5.1.2: "An endpoint MUST treat a field block with a Sign bit of 1 as invalid if
        // the value of Required Insert Count is less than or equal to the value of Delta
        // Base." C8 wrote this comparison out rather than folding it to `if (sign)` so that it
        // would still read correctly once the Required Insert Count check relaxed. It has, and
        // it does: on the null arm Required Insert Count is pinned at 0 and every set Sign bit
        // is still invalid outright, while on the table arm this is the real MUST.
        if (sign && requiredInsertCount <= deltaBase)
        {
            error = TlsQuicQpackError.InvalidBase;
            return false;
        }

        // s4.5.1.2's two-line formula, copied from the capture:
        //     if Sign == 0:  Base = ReqInsertCount + DeltaBase
        //     else:          Base = ReqInsertCount - DeltaBase - 1
        // The subtracting arm cannot underflow: the MUST above has already refused every case
        // where Required Insert Count is not strictly greater than Delta Base. The adding arm
        // is guarded instead, because two values each up to s4.1.1's 2^62-1 sum inside a ulong
        // but a caller-supplied table with an implausible Insert Count must not wrap into a
        // small Base that then resolves.
        if (sign)
        {
            baseValue = requiredInsertCount - deltaBase - 1;
        }
        else
        {
            if (deltaBase > ulong.MaxValue - requiredInsertCount)
            {
                error = TlsQuicQpackError.InvalidBase;
                return false;
            }

            baseValue = requiredInsertCount + deltaBase;
        }

        consumed = countLength + baseLength;
        error = TlsQuicQpackError.None;
        return true;
    }

    // s4.5.1.1's reconstruction, transcribed from
    // reference-captures/rfc9204-section4.5-field-line-representations.txt rather than
    // rederived. The capture's pseudocode, verbatim in shape:
    //
    //     FullRange = 2 * MaxEntries
    //     if EncodedInsertCount == 0:  ReqInsertCount = 0
    //     else:
    //        if EncodedInsertCount > FullRange:  Error
    //        MaxValue = TotalNumberOfInserts + MaxEntries
    //        MaxWrapped = floor(MaxValue / FullRange) * FullRange
    //        ReqInsertCount = MaxWrapped + EncodedInsertCount - 1
    //        if ReqInsertCount > MaxValue:
    //           if ReqInsertCount <= FullRange:  Error
    //           ReqInsertCount -= FullRange
    //        if ReqInsertCount == 0:  Error
    //
    // THE ORDER OF THE FIRST TWO TESTS IS WHAT KEEPS THIS TOTAL. At a maximum capacity below
    // 32, MaxEntries and FullRange are both zero and the division would be by zero - but any
    // non-zero EncodedInsertCount is `> 0` and is refused one line earlier, and a zero one
    // returned two lines before that. Reordering them is a crash, not a wrong answer.
    //
    // "If the decoder encounters a value of EncodedInsertCount that could not have been
    // produced by a conformant encoder, it MUST treat this as a connection error of type
    // QPACK_DECOMPRESSION_FAILED" - which every member of TlsQuicQpackError maps to, so the
    // three Error arms report through the member named for this field. Its NAME is now
    // narrower than its meaning; see the note in the ledger.
    private static bool TryReconstructRequiredInsertCount(
        ulong encodedInsertCount,
        TlsQuicQpackDynamicTable table,
        out ulong requiredInsertCount,
        out TlsQuicQpackError error)
    {
        requiredInsertCount = 0;
        error = TlsQuicQpackError.None;

        if (encodedInsertCount == 0)
        {
            return true;
        }

        // "MaxEntries is calculated as: MaxEntries = floor( MaxTableCapacity / 32 )", and the
        // 32 is s3.2.1's entry overhead by the capture's own reasoning - "The smallest entry
        // has empty name and value strings and has the size of 32" - so C14's constant is
        // reused rather than a second 32 written here.
        ulong maxEntries = (ulong)table.MaximumCapacity / TlsQuicQpackDynamicTable.EntrySizeOverhead;
        ulong fullRange = 2 * maxEntries;
        if (encodedInsertCount > fullRange)
        {
            error = TlsQuicQpackError.RequiredInsertCountNotEncodable;
            return false;
        }

        ulong maxValue = table.InsertCount + maxEntries;
        ulong maxWrapped = maxValue / fullRange * fullRange;
        ulong candidate = maxWrapped + encodedInsertCount - 1;
        if (candidate > maxValue)
        {
            if (candidate <= fullRange)
            {
                error = TlsQuicQpackError.RequiredInsertCountNotEncodable;
                return false;
            }

            candidate -= fullRange;
        }

        // "Value of 0 must be encoded as 0." A non-zero EncodedInsertCount that reconstructs
        // to zero is a value no conformant encoder produces.
        if (candidate == 0)
        {
            error = TlsQuicQpackError.RequiredInsertCountNotEncodable;
            return false;
        }

        requiredInsertCount = candidate;
        return true;
    }

    private static bool TryDecodeFieldLine(
        ReadOnlySpan<byte> source,
        Span<byte> buffer,
        TlsQuicQpackDynamicTable? table,
        ulong baseValue,
        ulong requiredInsertCount,
        ref int bufferUsed,
        out TlsQuicQpackDecodedFieldLine line,
        out int consumed,
        out TlsQuicQpackError error)
    {
        line = default;
        consumed = 0;

        // The caller loops while `offset < source.Length`, so this cannot be empty; the
        // guard is here anyway because this method is reachable from a test with any span
        // and a span read past its end is not a rejection, it is a crash.
        if (source.IsEmpty)
        {
            error = TlsQuicQpackError.Truncated;
            return false;
        }

        byte first = source[0];

        if ((first & IndexedFieldLineFlag) != 0)
        {
            // s4.5.2. T = 0 is a RELATIVE INDEX INTO THE DYNAMIC TABLE and NOT a static one:
            // the same six bits mean a different entry, so reading one as the other yields a
            // plausible wrong field rather than a visible failure. With no table there is
            // nowhere to resolve it, which is the null arm's rejection.
            if ((first & IndexedFieldLineStaticFlag) == 0)
            {
                if (table is null)
                {
                    error = TlsQuicQpackError.DynamicTableReference;
                    return false;
                }

                if (!TlsQuicQpackPrimitives.TryDecodeInteger(
                        source,
                        IndexedFieldLinePrefixBits,
                        out ulong relativeIndex,
                        out consumed,
                        out error))
                {
                    return false;
                }

                return TryResolveDynamic(table, baseValue, requiredInsertCount, relativeIndex, postBase: false, out ReadOnlySpan<byte> dynamicName, out ReadOnlySpan<byte> dynamicValue, out error)
                    && TryCopyPair(dynamicName, dynamicValue, buffer, ref bufferUsed, out line, out error);
            }

            if (!TlsQuicQpackPrimitives.TryDecodeInteger(
                    source,
                    IndexedFieldLinePrefixBits,
                    out ulong index,
                    out consumed,
                    out error))
            {
                return false;
            }

            return TryCopyStaticEntry(index, buffer, ref bufferUsed, out line, out error);
        }

        if ((first & LiteralNameReferenceFlag) != 0)
        {
            // s4.5.4. Same T bit, same meaning, and only the NAME comes from the table -
            // "Only the field name is taken from the dynamic table entry; the field value is
            // encoded as an 8-bit prefix string literal".
            bool dynamicNameReference = (first & LiteralNameReferenceStaticFlag) == 0;
            if (dynamicNameReference && table is null)
            {
                error = TlsQuicQpackError.DynamicTableReference;
                return false;
            }

            if (!TlsQuicQpackPrimitives.TryDecodeInteger(
                    source,
                    NameReferencePrefixBits,
                    out ulong nameIndex,
                    out int headerLength,
                    out error))
            {
                return false;
            }

            ReadOnlySpan<byte> name;
            if (dynamicNameReference)
            {
                if (!TryResolveDynamic(table!, baseValue, requiredInsertCount, nameIndex, postBase: false, out name, out _, out error))
                {
                    return false;
                }
            }
            else if (!TlsQuicQpackStaticTable.TryLookup((int)Math.Min(nameIndex, (ulong)int.MaxValue), out name, out _))
            {
                error = TlsQuicQpackError.StaticIndexOutOfRange;
                return false;
            }

            if (!TryAppend(name, buffer, ref bufferUsed, out int nameOffset))
            {
                error = TlsQuicQpackError.DestinationTooSmall;
                return false;
            }

            if (!TryDecodeString(
                    source[headerLength..],
                    ValueLiteralPrefixBits,
                    buffer,
                    ref bufferUsed,
                    out int valueOffset,
                    out int valueLength,
                    out int valueConsumed,
                    out error))
            {
                return false;
            }

            line = new TlsQuicQpackDecodedFieldLine(nameOffset, name.Length, valueOffset, valueLength);
            consumed = headerLength + valueConsumed;
            return true;
        }

        if ((first & LiteralLiteralNameFlag) != 0)
        {
            // s4.5.6. No table reference of any kind, so nothing about the dynamic table
            // arises here.
            if (!TryDecodeString(
                    source,
                    NameLiteralPrefixBits,
                    buffer,
                    ref bufferUsed,
                    out int nameOffset,
                    out int nameLength,
                    out int nameConsumed,
                    out error))
            {
                return false;
            }

            if (!TryDecodeString(
                    source[nameConsumed..],
                    ValueLiteralPrefixBits,
                    buffer,
                    ref bufferUsed,
                    out int valueOffset,
                    out int valueLength,
                    out int valueConsumed,
                    out error))
            {
                return false;
            }

            line = new TlsQuicQpackDecodedFieldLine(nameOffset, nameLength, valueOffset, valueLength);
            consumed = nameConsumed + valueConsumed;
            return true;
        }

        // What is left is '0001' - s4.5.3, indexed with post-Base index - and '0000' -
        // s4.5.5, literal with post-Base name reference. Both index the dynamic table by
        // construction: s3.2.6's post-Base index has no meaning against the static table,
        // which has no Base. On the null arm the two collapse to one rejection, which is what
        // C8 wrote; with a table they are two different representations of two different
        // widths and the flag that separates them is load-bearing.
        if (table is null)
        {
            error = TlsQuicQpackError.DynamicTableReference;
            return false;
        }

        if ((first & PostBaseIndexFlag) != 0)
        {
            // s4.5.3, Figure 14: '0001' then the post-Base index on a 4-bit prefix.
            if (!TlsQuicQpackPrimitives.TryDecodeInteger(
                    source,
                    PostBaseIndexPrefixBits,
                    out ulong postBaseIndex,
                    out consumed,
                    out error))
            {
                return false;
            }

            return TryResolveDynamic(table, baseValue, requiredInsertCount, postBaseIndex, postBase: true, out ReadOnlySpan<byte> postName, out ReadOnlySpan<byte> postValue, out error)
                && TryCopyPair(postName, postValue, buffer, ref bufferUsed, out line, out error);
        }

        // s4.5.5, Figure 16: '0000', the 'N' bit, then the post-Base index on a 3-bit prefix.
        // The 'N' bit sits ABOVE that prefix, so decoding at three bits masks it away without
        // a separate test - which is also why a fourth bit of prefix here would silently read
        // 'N' as the top bit of the index.
        if (!TlsQuicQpackPrimitives.TryDecodeInteger(
                source,
                PostBaseNameReferencePrefixBits,
                out ulong postBaseNameIndex,
                out int postHeaderLength,
                out error))
        {
            return false;
        }

        if (!TryResolveDynamic(table, baseValue, requiredInsertCount, postBaseNameIndex, postBase: true, out ReadOnlySpan<byte> postBaseName, out _, out error))
        {
            return false;
        }

        if (!TryAppend(postBaseName, buffer, ref bufferUsed, out int postBaseNameOffset))
        {
            error = TlsQuicQpackError.DestinationTooSmall;
            return false;
        }

        if (!TryDecodeString(
                source[postHeaderLength..],
                ValueLiteralPrefixBits,
                buffer,
                ref bufferUsed,
                out int postBaseValueOffset,
                out int postBaseValueLength,
                out int postBaseValueConsumed,
                out error))
        {
            return false;
        }

        line = new TlsQuicQpackDecodedFieldLine(
            postBaseNameOffset, postBaseName.Length, postBaseValueOffset, postBaseValueLength);
        consumed = postHeaderLength + postBaseValueConsumed;
        return true;
    }

    // s3.2.5's field-section relative index and s3.2.6's post-Base index, both resolved
    // against the Base and then looked up by s3.2.4's absolute index. C14 owns all three
    // arithmetics and this method chooses between two of them; nothing is recomputed here.
    //
    // THREE FAILURES ARE ONE ERROR AND THE FOURTH IS NOT. s2.2.3 makes an unresolvable
    // reference in a FIELD SECTION "a connection error of type QPACK_DECOMPRESSION_FAILED"
    // whether the index underflowed the Base, ran past the insertion point or named an entry
    // already evicted, so distinguishing those three here would produce three names for one
    // outcome. C16's bound is the fourth and it is a different statement about the peer - the
    // entry is there and the section had no right to name it - so it carries its own member.
    // Every one of them still maps to the same s6 code; the names are for whoever reads a
    // failing test. C14's own TlsQuicQpackEncoderStreamError is deliberately discarded: it
    // names the ENCODER stream's error code, and these bytes came off a request stream.
    private static bool TryResolveDynamic(
        TlsQuicQpackDynamicTable table,
        ulong baseValue,
        ulong requiredInsertCount,
        ulong index,
        bool postBase,
        out ReadOnlySpan<byte> name,
        out ReadOnlySpan<byte> value,
        out TlsQuicQpackError error)
    {
        name = default;
        value = default;

        bool resolved = postBase
            ? table.TryResolvePostBase(baseValue, index, out ulong absolute, out _)
            : table.TryResolveFieldRelative(baseValue, index, out absolute, out _);

        if (!resolved)
        {
            error = TlsQuicQpackError.DynamicTableReference;
            return false;
        }

        // s2.2.3's second clause, and s2.2.1's "smaller than expected" MUST with it - C16's
        // check, and the reason it is HERE rather than in a pass of its own. s2.1.2 defines
        // the expected Required Insert Count as "one larger than the largest absolute index of
        // all referenced dynamic table entries", so "the declared count is smaller than
        // expected" and "some reference has an absolute index >= the declared count" are the
        // same statement. Testing it per reference tests it once; a section-level maximum
        // computed afterwards would be a second transcription of the same sentence.
        //
        // BEFORE THE LOOKUP, NOT AFTER, so that a section which names an index it had no right
        // to name is refused for THAT rather than for whether the entry happens to still be
        // in the table. The two differ: at Required Insert Count 0 - s2.1.2's "For a field
        // section encoded with no references to the dynamic table, the Required Insert Count
        // is zero" - EVERY dynamic reference is at or above it, including ones that resolve
        // perfectly well.
        if (absolute >= requiredInsertCount)
        {
            error = TlsQuicQpackError.ReferenceAtOrAboveRequiredInsertCount;
            return false;
        }

        if (!table.TryLookupAbsolute(absolute, out name, out value, out _))
        {
            error = TlsQuicQpackError.DynamicTableReference;
            return false;
        }

        error = TlsQuicQpackError.None;
        return true;
    }

    private static bool TryCopyPair(
        ReadOnlySpan<byte> name,
        ReadOnlySpan<byte> value,
        Span<byte> buffer,
        ref int bufferUsed,
        out TlsQuicQpackDecodedFieldLine line,
        out TlsQuicQpackError error)
    {
        line = default;

        if (!TryAppend(name, buffer, ref bufferUsed, out int nameOffset) ||
            !TryAppend(value, buffer, ref bufferUsed, out int valueOffset))
        {
            error = TlsQuicQpackError.DestinationTooSmall;
            return false;
        }

        line = new TlsQuicQpackDecodedFieldLine(nameOffset, name.Length, valueOffset, value.Length);
        error = TlsQuicQpackError.None;
        return true;
    }

    private static bool TryCopyStaticEntry(
        ulong index,
        Span<byte> buffer,
        ref int bufferUsed,
        out TlsQuicQpackDecodedFieldLine line,
        out TlsQuicQpackError error)
    {
        line = default;

        // Clamped rather than cast, so an index near 2^62 cannot wrap into a small int that
        // then resolves to a real row. TryLookup rejects anything at or past the table's 99
        // entries.
        if (!TlsQuicQpackStaticTable.TryLookup(
                (int)Math.Min(index, (ulong)int.MaxValue),
                out ReadOnlySpan<byte> name,
                out ReadOnlySpan<byte> value))
        {
            error = TlsQuicQpackError.StaticIndexOutOfRange;
            return false;
        }

        if (!TryAppend(name, buffer, ref bufferUsed, out int nameOffset) ||
            !TryAppend(value, buffer, ref bufferUsed, out int valueOffset))
        {
            error = TlsQuicQpackError.DestinationTooSmall;
            return false;
        }

        line = new TlsQuicQpackDecodedFieldLine(nameOffset, name.Length, valueOffset, value.Length);
        error = TlsQuicQpackError.None;
        return true;
    }

    // A string literal, Huffman-decoded into `buffer` if H is set and copied verbatim if it
    // is not. RFC 9204 s4.1.2 makes H a per-string choice of the SENDER, so both arms are
    // live on received bytes whatever this endpoint's encoder does.
    private static bool TryDecodeString(
        ReadOnlySpan<byte> source,
        int prefixBits,
        Span<byte> buffer,
        ref int bufferUsed,
        out int offset,
        out int length,
        out int consumed,
        out TlsQuicQpackError error)
    {
        offset = 0;
        length = 0;

        if (!TlsQuicQpackPrimitives.TryDecodeStringLiteral(
                source,
                prefixBits,
                out bool huffman,
                out ReadOnlySpan<byte> data,
                out consumed,
                out error))
        {
            return false;
        }

        if (!huffman)
        {
            // A zero-length literal lands here with `data` empty, and that is a field value
            // of length zero, not a missing one. It appends nothing and reports offset =
            // bufferUsed, length = 0, which is a well-formed empty slice.
            if (!TryAppend(data, buffer, ref bufferUsed, out offset))
            {
                error = TlsQuicQpackError.DestinationTooSmall;
                return false;
            }

            length = data.Length;
            return true;
        }

        offset = bufferUsed;
        if (!TlsQuicQpackHuffman.TryDecode(data, buffer[bufferUsed..], out length, out error))
        {
            return false;
        }

        bufferUsed += length;
        return true;
    }

    private static bool TryAppend(
        ReadOnlySpan<byte> data,
        Span<byte> buffer,
        ref int bufferUsed,
        out int offset)
    {
        offset = bufferUsed;
        if (buffer.Length - bufferUsed < data.Length)
        {
            return false;
        }

        data.CopyTo(buffer.Slice(bufferUsed, data.Length));
        bufferUsed += data.Length;
        return true;
    }
}

// One decoded field line, as a pair of slices into the caller's buffer. Offsets rather than
// spans so that this is an ordinary struct and can live in a `Span<T>`; a `ref struct` of two
// spans cannot.
//
// A length of zero is an EMPTY name or value, not an absent one. The static table has 21 rows
// whose value is empty, and a zero-length string literal on the wire is legal, so both reach
// here as `Length == 0` and must not be read as "no value".
internal readonly record struct TlsQuicQpackDecodedFieldLine(
    int NameOffset,
    int NameLength,
    int ValueOffset,
    int ValueLength);

// RFC 9204 s4.4's three decoder instructions - the ones WE send, on the s4.2 decoder stream
// (type 0x03). See reference-captures/rfc9204-section4.4-decoder-instructions.txt for the
// three figures and reference-captures/rfc9204-section2-compression-process-overview.txt for
// s2.1.4's Known Received Count and s2.2.2's three events.
//
// WHY THIS STREAM IS NOT OPTIONAL FOR US. s4.2 permits omitting it "if its decoder sets the
// maximum capacity of the dynamic table to zero". TlsQuicHttp3Spec.CaptureSettings, the
// default, sets SETTINGS_QPACK_MAX_TABLE_CAPACITY to 65536.
//
// THE OPCODES ARE A PREFIX TREE OF THREE DIFFERENT WIDTHS, like s4.3's four:
//   1xxxxxxx  Section Acknowledgment  s4.4.1, stream ID on a 7-bit prefix
//   01xxxxxx  Stream Cancellation     s4.4.2, stream ID on a 6-bit prefix
//   00xxxxxx  Insert Count Increment  s4.4.3, Increment on a 6-bit prefix
// Reading them is the peer's problem; writing them means the pattern and the width must be
// paired correctly, and the two 6-bit ones differ only in a bit the width does not cover.
//
// TWO INSTRUCTIONS MUST SOMETIMES NOT BE SENT AT ALL, and each is a MUST at the RECEIVING
// encoder rather than here, which is why a round trip through our own reader would notice
// neither:
//
//   * s4.4.1 acknowledges only "an encoded field section whose declared Required Insert Count
//     is not zero". A section that used no dynamic entry gets no acknowledgment, and one sent
//     anyway refers "to a stream on which every encoded field section with a non-zero Required
//     Insert Count has already been acknowledged" - vacuously true when there have been none -
//     which s4.4.1 makes "a connection error of type QPACK_DECODER_STREAM_ERROR".
//   * s4.4.3: "An encoder that receives an Increment field equal to zero ... MUST treat this
//     as a connection error of type QPACK_DECODER_STREAM_ERROR." A zero Increment is never a
//     legal no-op, so the natural "flush whatever changed" loop must suppress itself.
//
// Both are reported the same way: `true` with `written` = 0, meaning THERE IS NOTHING TO SEND.
// `false` means only that `destination` was too short. NOTHING HERE THROWS and nothing here
// allocates - the whole instruction is built by TlsQuicQpackPrimitives.TryEncodeInteger into
// the caller's span.
internal sealed class TlsQuicQpackDecoderStream
{
    // s4.4.1's Figure 9, s4.4.2's Figure 10 and s4.4.3's Figure 11. The Insert Count Increment
    // pattern is all-zero and is still named and still passed, because `0` written inline is a
    // pattern nobody can tell from an oversight.
    private const byte SectionAcknowledgmentPattern = 0b1000_0000;
    private const byte StreamCancellationPattern = 0b0100_0000;
    private const byte InsertCountIncrementPattern = 0b0000_0000;

    private const int SectionAcknowledgmentPrefixBits = 7;
    private const int StreamCancellationPrefixBits = 6;
    private const int InsertCountIncrementPrefixBits = 6;

    // Every instruction here is one prefixed integer and nothing else, so the longest one is
    // the longest integer. Taken from the codec rather than restated.
    internal const int MaximumInstructionLength = TlsQuicQpackPrimitives.MaximumIntegerEncodedLength;

    // s2.1.4: "The Known Received Count is the total number of dynamic table insertions and
    // duplications acknowledged by the decoder ... The decoder tracks the Known Received Count
    // in order to be able to send Insert Count Increment instructions."
    internal ulong KnownReceivedCount { get; private set; }

    // s4.4.1. `requiredInsertCount` is the RECONSTRUCTED value the section declared - what
    // TlsQuicQpackDecoder.TryDecodeFieldSection hands back - and not the octet on the wire.
    internal bool TryWriteSectionAcknowledgment(
        ulong streamId,
        ulong requiredInsertCount,
        Span<byte> destination,
        out int written)
    {
        written = 0;

        // s4.4.1's opening clause, as a guard rather than as a comment: "After processing an
        // encoded field section whose declared Required Insert Count is not zero".
        if (requiredInsertCount == 0)
        {
            return true;
        }

        if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                streamId,
                SectionAcknowledgmentPrefixBits,
                SectionAcknowledgmentPattern,
                destination,
                out written))
        {
            return false;
        }

        // s2.1.4: "If the Required Insert Count of the acknowledged field section is greater
        // than the current Known Received Count, the Known Received Count is updated to that
        // Required Insert Count value." GREATER, not different - s2.2.2.1 lets the encoder
        // acknowledge "the earliest unacknowledged field section" on a stream, so a later
        // acknowledgment can carry a SMALLER Required Insert Count and must not walk the count
        // backwards. Raised only after the bytes are known to fit, so a destination too short
        // leaves this object exactly as it was.
        if (requiredInsertCount > KnownReceivedCount)
        {
            KnownReceivedCount = requiredInsertCount;
        }

        return true;
    }

    // s4.4.2, emitted on s2.2.2.2's event: "When an endpoint receives a stream reset before
    // the end of a stream or before all encoded field sections are processed on that stream,
    // or when it abandons reading of a stream".
    //
    // IT DOES NOT TOUCH THE KNOWN RECEIVED COUNT, and that is stated rather than merely
    // omitted: s2.2.2.2 ends "An encoder cannot infer from this instruction that any updates
    // to the dynamic table have been received." There is also no suppression clause here -
    // s4.4.2 has no equivalent of s4.4.1's non-zero condition, and a cancelled stream that
    // referenced nothing is still cancelled.
    internal bool TryWriteStreamCancellation(ulong streamId, Span<byte> destination, out int written) =>
        TlsQuicQpackPrimitives.TryEncodeInteger(
            streamId,
            StreamCancellationPrefixBits,
            StreamCancellationPattern,
            destination,
            out written);

    // s4.4.3, emitted on s2.2.2.3's event. `insertCount` is the table's total insertions and
    // duplications - TlsQuicQpackDynamicTable.InsertCount - and NOT the increment; the
    // increment is derived, because s4.4.3 says "The decoder should send an Increment value
    // that increases the Known Received Count to the total number of dynamic table insertions
    // and duplications processed so far" and only this object knows where that count stands.
    //
    // THAT DERIVATION IS THE SUPPRESSION. s2.2.2.3 says a delayed increment may be replaced
    // "entirely with Section Acknowledgments", which is exactly the case where an
    // acknowledgment has already pulled the Known Received Count up to the insert count and
    // the increment would be zero. Appendix B.3 is the published witness: two entries are
    // acknowledged by B.2's `84`, a third is inserted, and the decoder sends `01` - an
    // Increment of one, not of three.
    internal bool TryWriteInsertCountIncrement(ulong insertCount, Span<byte> destination, out int written)
    {
        written = 0;

        // One comparison for two things. Equal is s4.4.3's forbidden zero Increment. Less than
        // is a caller handing back a count below one it already acknowledged, which no table
        // this decoder drives can produce and which would underflow the subtraction below into
        // an enormous, legal-looking Increment.
        if (insertCount <= KnownReceivedCount)
        {
            return true;
        }

        if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                insertCount - KnownReceivedCount,
                InsertCountIncrementPrefixBits,
                InsertCountIncrementPattern,
                destination,
                out written))
        {
            return false;
        }

        KnownReceivedCount = insertCount;
        return true;
    }
}

// RFC 9204 s2.2.1's blocked streams, and s2.1.2's bound on how many may be blocked at once.
// See reference-captures/rfc9204-section2-compression-process-overview.txt.
//
// WHAT THIS HOLDS AND WHY IT IS ONE NUMBER PER STREAM. s2.2.1: "A stream becomes unblocked
// when the Insert Count becomes greater than or equal to the Required Insert Count for all
// encoded field sections the decoder has started reading from the stream." A reader that
// STOPS at the first section it cannot process has started reading exactly one such section,
// so "for all" collapses to "for that one" - which is why this is a ulong per stream rather
// than a list. TryHold raises and never lowers, so the collapse stays true even if a caller
// ever does present a second section on a stream that is already held.
//
// THE COUNT PARKED IS THE ONE RECONSTRUCTED ON RECEIPT, AND THAT IS NOT AN OPTIMISATION.
// s4.5.1.1's reconstruction reads TotalNumberOfInserts, so the SAME encoded prefix
// reconstructs to a DIFFERENT Required Insert Count once the table has advanced far enough:
// the algorithm returns the largest value congruent to the encoder's modulo FullRange that is
// at most InsertCount + MaxEntries, and that value jumps by FullRange once InsertCount passes
// the true count by MaxEntries. s2.2.1 says "Upon receipt of an encoded field section, the
// decoder examines the Required Insert Count" - on receipt, once - so the number parked here
// is the answer from then, and the unblock test compares it against the live Insert Count
// rather than recomputing it.
//
// s2.1.2's BOUND IS ON STREAMS BLOCKED AT ONCE, not on how often a stream blocks: "An encoder
// MUST limit the number of streams that could become blocked to the value of
// SETTINGS_QPACK_BLOCKED_STREAMS at all times. If a decoder encounters more blocked streams
// than it promised to support, it MUST treat this as a connection error of type
// QPACK_DECOMPRESSION_FAILED." So a stream already held costs nothing further, a released one
// gives its slot back, and a value of zero - s5's default - refuses the FIRST block outright.
//
// NOTHING HERE THROWS and the REFUSING path allocates nothing: the dictionary is not touched
// on the rejection. Holding one does allocate, because holding one is remembering something.
internal sealed class TlsQuicQpackBlockedStreams
{
    private readonly Dictionary<ulong, ulong> _held = [];
    private readonly ulong _maximumBlockedStreams;

    /// <summary>Creates the registry for a decoder advertising
    /// <paramref name="maximumBlockedStreams"/> as <c>SETTINGS_QPACK_BLOCKED_STREAMS</c>.</summary>
    internal TlsQuicQpackBlockedStreams(ulong maximumBlockedStreams) =>
        _maximumBlockedStreams = maximumBlockedStreams;

    /// <summary>Gets the value this decoder advertised.</summary>
    internal ulong MaximumBlockedStreams => _maximumBlockedStreams;

    /// <summary>Gets how many streams are blocked right now.</summary>
    internal int Count => _held.Count;

    /// <summary>Parks a stream on s2.2.1's block, or refuses because s2.1.2's promised bound is
    /// already met.</summary>
    /// <remarks>A stream already held is re-held rather than double-counted, and its parked
    /// Required Insert Count is RAISED and never lowered - a stream is unblocked only once the
    /// Insert Count covers every section started on it.</remarks>
    internal bool TryHold(ulong streamId, ulong requiredInsertCount, out TlsQuicQpackError error)
    {
        error = TlsQuicQpackError.None;

        if (_held.TryGetValue(streamId, out ulong alreadyHeld))
        {
            if (requiredInsertCount > alreadyHeld)
            {
                _held[streamId] = requiredInsertCount;
            }

            return true;
        }

        // ">=" and not ">": the count is what is ALREADY held, so at the advertised value the
        // slot being asked for is the one past the promise. At zero this fires on the first
        // block, with nothing held, which is the boundary s5's default sits on.
        if ((ulong)_held.Count >= _maximumBlockedStreams)
        {
            error = TlsQuicQpackError.BlockedStreamLimitExceeded;
            return false;
        }

        _held.Add(streamId, requiredInsertCount);
        return true;
    }

    /// <summary>Gets whether <paramref name="streamId"/> is blocked, and on what Required Insert
    /// Count.</summary>
    internal bool IsHeld(ulong streamId, out ulong requiredInsertCount) =>
        _held.TryGetValue(streamId, out requiredInsertCount);

    /// <summary>Gives the stream's slot back.</summary>
    /// <remarks>Releasing a stream that is not held is a no-op rather than a fault, which is
    /// what lets a caller release unconditionally on teardown - s2.2.2.2's abandonment - without
    /// first asking whether the stream ever blocked.</remarks>
    internal void Release(ulong streamId) => _held.Remove(streamId);
}


// ============================================================================
// THE MUTATION LEDGER - TASK C16 (this file: s2.2.1's block, s2.2.3's bound,
// s6's mapping, and TlsQuicQpackBlockedStreams)
// ============================================================================
//
//   ROWS BELOW                   11  = C16-1 to C16-11 with no gaps
//   KILLED WHEN FIRST RUN        10  = 11 rows, less 0 [WAS-SURVIVOR] and 1 [SURVIVED]
//   SURVIVING STILL               1  = row C16-3, classified at the row
//
//   10 + 1 = 11. The task's other 24 rows are in TlsQuicQpackPrimitives.cs (2),
//   TlsQuicHttp3Request.cs (7), TlsQuicHttp3Streams.cs (7), TlsQuicHttp3Connection.cs (6) and
//   TlsQuicHttp3Frames.cs (2). 11 + 2 + 7 + 7 + 6 + 2 = 35 rows for the task.
//
// A UNIQUE ROW PREFIX, because C8's ledger at the top of this file counts itself with
// `grep -cE '^// +[0-9]+\. '` and must keep returning 16, and C15's counts itself with
// `^// +C15-[0-9]+\. ` and must keep returning 45. These rows carry `C16-` so neither sees
// them. Their own three, run from this file's directory:
//   `grep -cE '^// +C16-[0-9]+\. ' TlsQuicQpackDecoder.cs`                  must return 11
//   `grep -cE '^// +C16-[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicQpackDecoder.cs` must return 0
//   `grep -cE '^// +C16-[0-9]+\..*\[SURVIVED\]' TlsQuicQpackDecoder.cs`     must return 1
//
// THE SWEEP RAN IN A PRIVATE WORKTREE, one edit at a time, each restored before the next,
// `--no-incremental` build then `--no-build` test, gate `dotnet test --filter
// "FullyQualifiedName~Quic"`. NO `taskkill`: it matches every concurrent agent's testhost and
// not only this one's, which is what C10c's and C11's ledgers record it breaking.
//
// THREE HARNESS DEFECTS WERE FOUND AND FIXED BEFORE ANY ROW WAS BELIEVED, and each one would
// otherwise have produced a clean-looking sweep that measured nothing:
//
//   * A LITERAL `false` DOES NOT DELETE CODE HERE. CS0162 is an error in this repo, so every
//     deletion-shaped mutant failed to COMPILE and came back KILLED-BY-COMPILER - a verdict
//     that says the mutant is unwritable, not that a test caught it. Every one was restated
//     with `string.Empty.Length > 0`: provably false, and not constant-folded, because
//     string.Empty is a static readonly field rather than a literal.
//   * AN INTERRUPTED SWEEP LEAVES ITS MUTANT ON DISK. Two runs were killed mid-row and both
//     left the edit in the worktree, so every later row would have measured TWO mutations
//     while reporting one. The harness now snapshots every target file once and re-checks all
//     of them BEFORE each row, aborting the whole sweep on any difference.
//   * A LOCKED FILE IS NOT A COMPILER REJECTION. An orphaned testhost.exe still holding the
//     previous run's SharpTls.dll makes the build fail MSB3021 and leaves the output directory
//     half-written, so the test run then aborts for a second, unrelated reason. That is
//     recorded ABORTED, never KILLED, and the sweep was moved to a fresh worktree rather than
//     killing the process.
//
// THE CASE-COUNT FLOOR IS PER RUN and is 1800 against a 2086-case gate. An aborted run prints
// an ordinary `Failed: 0, Passed: <m>` line and would otherwise read as a survivor that never
// ran - the exact shape C14's floor caught on a worktree that compiled nothing. It fired here
// too, on the MSB3021 run above. Every row below reports 2082 or 2086 executed cases; the two
// figures differ only because six rows were re-run after their witnesses were written.
//
// BLOCKING IS A HANG HAZARD IN A SWEEP and every wait is bounded twice. The gate gets 900
// wall-clock seconds per run, and no C16 test waits on a clock: the one that pumps a section
// which never unblocks - .ASectionThatNeverUnblocksStaysBlockedAcrossManyPumpsWithNoError -
// is bounded by a COUNT of 64 pumps, so a mutant that never unblocks fails the run instead of
// wedging it. Nothing in TryProcess waits at all.
//
// CALIBRATED IN BOTH DIRECTIONS BEFORE THE FIRST ROW. A known-bad edit - s2.2.1's block check
// inverted - came back KILLED with 19 failures; an inert comment came back SURVIVED with 0.
//
// --- s2.2.1's block, decided from the prefix (3 rows) ---
//
//   C16-1. s2.2.1's `>` weakened to `>=`, so a section needing exactly the entries we hold
//        blocks instead of being "processed immediately". Killed by 30. NO PUBLISHED VECTOR
//        KILLS THIS: every Appendix B example feeds its encoder stream before its field
//        section, so the Insert Count is always already at or above the Required Insert Count
//        and the two comparisons never disagree. The witness is
//        .TheBlockIsDecidedAgainstTheInsertCountAtTheBoundary's count-of-2 row against an
//        Insert Count of 2, invented locally for exactly this boundary.
//   C16-2. s2.2.1's block deleted, so a section ahead of the table falls through and its
//        references simply fail to resolve - which is C15's behaviour and the defect C16
//        exists to remove. Killed by 15. [RESTATED] As first written it used a literal `false`
//        and did not compile; restated with `string.Empty.Length > 0`.
//   C16-3. [SURVIVED] The null-table guard dropped from the block check, so the static-only arm
//        would block on a non-zero Required Insert Count instead of rejecting it.
//        UNREACHABLE BY CONSTRUCTION, AND NO TEST IS WRITTEN. TryDecodeFieldSectionPrefix
//        rejects a non-zero EncodedInsertCount on the null arm before this line is reached, so
//        `requiredInsertCount` is necessarily 0 here and both forms compute `0 > 0`. The
//        conjunct is kept and is NOT dead code: without it `table.InsertCount` is a null
//        dereference. What is unobservable is its effect on the ANSWER, not its necessity - so
//        this is a survivor to classify rather than a guard to delete, unlike C16-23.
//
// --- s2.2.3's bound on a reference's absolute index (3 rows) ---
//
//   C16-4. s2.2.3's `>=` weakened to `>`, so a reference AT the declared Required Insert Count
//        is accepted. Killed by 3. The killing vector holds THREE entries and declares TWO, so
//        the entry at absolute 2 is PRESENT and the section still has no right to name it -
//        under `>` the comparison passes, the lookup then succeeds, and nothing complains.
//   C16-5. s2.2.3's bound deleted, so any reference the table can resolve is accepted whatever
//        the section declared. Killed by 4, including
//        .ADeclaredCountOfZeroRefusesADynamicReferenceThatResolvesPerfectlyWell.
//        [RESTATED] for the literal-`false` reason above.
//   C16-6. s2.2.3's bound moved AFTER the lookup. Killed by 2. THE ORDER IS THE ROW: a
//        reference the table cannot resolve is then reported as absent rather than as outside
//        the section's declared range, and s2.1.2's zero-count case - where EVERY dynamic
//        reference is at or above the count, including ones that resolve perfectly well - is
//        decided by whether the entry happens to still be there.
//
// --- s6's mapping (1 row) ---
//
//   C16-7. Blocked restored to the connection-error mapping. Killed by 3. THIS IS THE LIVE BUG
//        C16 FOUND. TryGetHttp3ErrorCode writes QPACK_DECOMPRESSION_FAILED into its out
//        parameter unconditionally and answers false to say "do not use this", and
//        TlsQuicHttp3Response.TryDecodeFieldSection DISCARDED that answer - so the moment
//        Blocked could be returned, ordinary QUIC stream reordering closed the connection with
//        0x0200. See C16-14 for the caller's half, which is where it was witnessed failing.
//
// --- s2.1.2's bound on streams blocked at once (4 rows) ---
//
//   C16-8. s2.1.2's `>=` weakened to `>`, so an endpoint advertising N lets N + 1 streams
//        block. Killed by 7. The row that does the work is the ADVERTISED-ZERO one - s5's
//        default - where the mutant permits one blocked stream against a promise of none.
//   C16-9. A held stream's parked Required Insert Count LOWERED rather than raised, losing
//        s2.2.1's "for all encoded field sections the decoder has started reading from the
//        stream". Killed by exactly one case,
//        .AHeldStreamsRequiredInsertCountRisesAndNeverFalls. The plan predicted this raise was
//        unreachable and should be classified rather than tested; it is directly reachable at
//        the registry, so it is tested.
//  C16-10. Release made a no-op, so a slot is never given back. Killed by 2 here, and see
//        C16-30 for the same property witnessed at the connection.
//  C16-11. The already-held early return deleted, so a stream re-presented on every pump is
//        counted afresh each time and exhausts the bound by itself - which at an advertised 1
//        closes the connection on the second pump of the FIRST blocked stream. Killed by 3.
//        [RESTATED] for the literal-`false` reason above.
//
// ============================================================================
