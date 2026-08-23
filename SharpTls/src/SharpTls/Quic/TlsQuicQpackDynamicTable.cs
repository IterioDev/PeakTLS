namespace SharpTls.Quic;

// ============================================================================
// THE MUTATION LEDGER
// ============================================================================
//
//   ROWS BELOW                   41  = numbered 1-41 with no gaps
//   KILLED WHEN FIRST RUN        34  = 41 rows, less 6 [WAS-SURVIVOR] and 1 [SURVIVED]
//   SURVIVED, THEN FIXED OR       6  = rows 5, 6, 7, 29, 39, 41
//     WITNESSED
//   SURVIVING STILL               1  = row 18, classified below
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry
// the markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' TlsQuicQpackDynamicTable.cs`                  must return 41
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicQpackDynamicTable.cs` must return 6
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' TlsQuicQpackDynamicTable.cs`     must return 1
//
// Every row was run against task C14's gate, `dotnet test --filter "FullyQualifiedName~Quic"`,
// in a private copy of the tree, one edit at a time, each restored before the next. Counts
// are per xUnit CASE, so a Theory that fails in five rows counts 5. The harness rejects any
// run whose executed-case total falls below 95% of the unmutated baseline, because an aborted
// run prints an ordinary `Failed: 0, Passed: <m>` line and would otherwise read as a survivor
// that never ran - and it did fire once, on a first attempt whose tree was missing tools/ and
// so compiled nothing at all. It was calibrated in both directions before the sweep: a
// known-bad edit (`Size += plan.EntrySize` -> `Size += 0`) was KILLED in 8 cases, and an inert
// comment above the class declaration SURVIVED.
//
// --- s4.3's opcode prefix tree (8 rows) ---
//
//    1. `TryReadOneInstruction`: hoist the '001' test above the '01' test.
//       THE ORDER IS THE DECODER. s4.3's four opcodes have three different prefix lengths, so
//       0x60-0x7F carry both the '01' bit and the '001' bits and only the order says which
//       one they are. The mutant reads 64 of the 256 first octets as a capacity change.
//       Killed by TlsQuicQpackDynamicTableTests.OnlyTheSetCapacityBranchOfThePrefixTreeMay
//       ChangeTheCapacity, in 1 case.
//    2. `TryReadOneInstruction`: hoist the '01' test above the '1' test.
//       The same fault one level up, and the one the capacity sweep CANNOT see: 0xC0 inserts
//       either way and leaves the capacity alone either way. Only the resulting name differs -
//       s3.1's entry 0 under the correct reading, an empty literal under the mutant.
//       Killed by AnOctetSettingBothInsertBitsIsReadAsTheNameReference and by the Appendix B
//       walk, in 12 cases.
//    3. `SetCapacityPrefixBits`: 5 -> 6.
//       B.2's `3fbd01` fills a 5-bit prefix (31) and spills into two continuation octets for
//       31 + 61 + 128 = 220. At 6 bits, 0x3F is 63, which does not fill, so the mutant reads
//       63 and then misreads `bd` and `01` as two more instructions.
//       Killed by TheCapacityDecodedFromB2MatchesTheCaptureAnnotation and the walk, in 14 cases.
//    4. `InsertNameIndexPrefixBits`: 6 -> 5.
//       Killed by the Appendix B walk, in 1 case.
//    5. `InsertLiteralNamePrefixBits`: 6 -> 5. [WAS-SURVIVOR]
//       SURVIVED THE WHOLE CAPTURE-ANCHORED WALK, and the reason is arithmetic rather than
//       oversight: B.3's only literal name is 10 bytes, and `10 & 0x1F` equals `10 & 0x0F`,
//       so the two widths decode it identically. The H bit moves too - bit 5 at the correct
//       width, bit 4 at the mutant's - and at length 10 it is clear either way.
//       Witnessed by ALiteralNameAtTheSixBitPrefixBoundaryIsNotReadAtFiveBits, which uses a
//       name of length 16: 16 sets bit 4, so the mutant reads a Huffman name of length 0 and
//       stores an empty name where sixteen bytes belong. Now killed, in 1 case.
//    6. `InsertValuePrefixBits`: 8 -> 7. [WAS-SURVIVOR]
//       Same shape, same reason: B.2's longest published value is 15 bytes and every other is
//       shorter, and `15 & 0x7F` equals `15 & 0x3F`.
//       Witnessed by AValueAtTheEightBitPrefixBoundaryIsNotReadAtSevenBits, which uses a value
//       of length 64 - the first length that sets bit 6 - so the mutant reads a Huffman value
//       of length 0. Now killed, in 1 case.
//    7. `DuplicateIndexPrefixBits`: 5 -> 6. [WAS-SURVIVOR]
//       Same reason a third time: B.4's Duplicate index is 2, and `2 & 0x1F` equals `2 & 0x3F`.
//       Witnessed by ADuplicateIndexAtTheFiveBitPrefixBoundaryIsNotReadAtSixBits, which builds
//       33 entries with distinct static names and duplicates relative index 32. At 5 bits that
//       is two octets (31 fills, then a continuation of 1) resolving to 33 - 32 - 1 = 0; at
//       6 bits it is one octet meaning 31, resolving to 33 - 31 - 1 = 1, and the leftover
//       continuation octet is then misread as a second Duplicate. Now killed, in 1 case.
//    8. `TryReadInsertWithNameReference`: the T bit inverted.
//       s4.3.2: "When T=1, the number represents the static table index; when T=0, the number
//       is the relative index of the entry in the dynamic table." Two different tables.
//       Killed by the Appendix B walk, in 16 cases.
//
// --- s3.2.1's size accounting (2 rows) ---
//
//    9. `EntrySizeOverhead`: 32 -> 31.
//       The published sizes are the oracle: B.2's 106 is 57 + 49, and each of those carries
//       the 32 exactly once. At 31 the walk sees 104 where the capture prints 106.
//       Killed by the walk and EveryPublishedSizeIsTheSumOfItsPublishedRows, in 5 cases.
//   10. `TryPlanInsert`: entry size drops the name length.
//       Killed by the walk, in 10 cases.
//
// --- s3.2.2's eviction (9 rows) ---
//
//   11. `TryPlanInsert`: evict to `Capacity` rather than to `Capacity - entrySize`.
//       s3.2.2 evicts "until the size of the dynamic table is less than or equal to (table
//       capacity - size of new entry)", not until it is under the capacity. B.5 separates
//       them: 217 <= 220 already, so the mutant evicts nothing and then stores 272 bytes in a
//       220-byte table.
//       Killed by AppendixB5EvictsExactlyTheOneEntryTheBoundaryForces, in 5 cases.
//   12. `TryPlanEviction`: evict from the insertion point rather than the dropping point.
//       "Evicted from the END of the dynamic table" is s3.2.5's dropping point, the LOW
//       absolute index. B.5 is the witness that says which end: the capture's rows after B.5
//       start at absolute 1, so entry 0 went and the duplicate at 3 stayed.
//       Killed by the walk, in 3 cases.
//   13. `TryPlanEviction`: `while (running > target)` -> `>=`.
//       Evicts one entry too many. At B.5 that would take entry 1 as well, leaving 111 where
//       the capture prints 215.
//       Killed by AppendixB5EvictsExactlyTheOneEntryTheBoundaryForces, in 5 cases.
//   14. `TryPlanInsert`: the oversized-entry check against free space rather than capacity.
//       s3.2.2 checks "larger than the dynamic table capacity", so an entry that fits the
//       capacity but not the CURRENT free space is legal and simply evicts. The mutant rejects
//       B.5 outright.
//       Killed by the walk and AnEntryLargerThanTheCapacityIsRejectedOnAnEmptyTable, in 9 cases.
//   15. `TryPlanInsert`: `if (entrySize > Capacity)` -> `>=`.
//       The boundary itself. AnEntryLargerThanTheCapacityIsRejectedOnAnEmptyTable sets the
//       capacity to exactly the entry's 54 bytes in one run and to 53 in the other, so the
//       mutant fails the accepting half.
//       Killed by that test, in 2 cases.
//   16. `TrySetCapacity`: skip the eviction on a capacity REDUCTION.
//       s4.3.1's own sentence, not only s3.2.2's: "Reducing the dynamic table capacity can
//       cause entries to be evicted." A table that evicts only on insert leaves entries above
//       the new capacity.
//       Killed by ACapacityReductionIsRejectedWhileTheDoomedEntryIsReferenced and
//       ACapacityOfZeroClearsTheTableAndCanBeRestored, in 3 cases.
//   17. `TryPlanEviction`: apply the eviction measured so far before rejecting a referenced
//       entry.
//       A partially evicted table after a rejection is a state corruption no error code
//       describes. The witness has to reach the SECOND entry of the run for the mutant to have
//       anything to apply, which is why that test exists at all - see row 23's note.
//       Killed by AReferenceOnTheSecondEntryOfTheEvictionRunIsAlsoRespected, in 1 case.
//   18. `Commit`: add the new entry BEFORE applying the eviction rather than after. [SURVIVED]
//       EQUIVALENT, AND UNREACHABLE BY CONSTRUCTION rather than unwitnessed. The eviction
//       removes `count` entries from the FRONT and the insert appends to the BACK, and `count`
//       was measured before the append, so `count <= entries.Count` at that moment and the
//       appended entry is never among the first `count`. The two operations commute for every
//       input, including the case that evicts the whole table: removing all n and then
//       appending, and appending and then removing the first n, both leave exactly the new
//       entry. Size, InsertCount and DroppedCount are untouched by the swap. No test is
//       written for it, because there is no input that could tell the two orders apart.
//   19. `TryReadInsertWithLiteralName`: copy the name and value to the heap BEFORE validating.
//       Behaviourally identical and ALLOCATION-visible, which is the point: it is the shape a
//       straightforward implementation takes, and it lets a peer make us allocate once per
//       instruction it already knows we will refuse.
//       Killed by TheRejectingPathAllocatesZeroBytes, in 1 case.
//
// --- s4.3.1 and s3.2.3's ceiling (3 rows) ---
//
//   20. `TrySetCapacity`: `if (newCapacity > maximumCapacity)` -> `>=`.
//       Killed by ACapacityAtTheAdvertisedMaximumIsAcceptedAndOneAboveItIsRejected, whose four
//       Theory rows each set the capacity to exactly the maximum first, in 7 cases.
//   21. `TrySetCapacity`: compare after narrowing to int rather than in ulong.
//       s4.1.1 lets the peer send up to 2^62-1 here. Narrowed to int, 2^32 becomes 0 and
//       2^62-1 becomes -1, and both pass a signed comparison.
//       Killed by ACapacityNearTheSixtyTwoBitCeilingIsRejectedRatherThanNarrowed, in 2 cases.
//   22. `TrySetCapacity`: drop the ceiling entirely.
//       Killed by the same two tests, in 6 cases.
//
// --- s2.1.1's evictability (2 rows) ---
//
//   23. `TryPlanEviction`: drop the outstanding-reference check.
//       Killed by TheInsertionThatEvictsIsRejectedWhileTheDoomedEntryIsReferenced,
//       ACapacityReductionIsRejectedWhileTheDoomedEntryIsReferenced and
//       AReferenceOnTheSecondEntryOfTheEvictionRunIsAlsoRespected, in 3 cases.
//       THE THIRD OF THOSE IS NOT REDUNDANT. In the first two the referenced entry is the
//       oldest, so it is the FIRST candidate the eviction run reaches; an implementation that
//       checked only the head of the run would pass both. The third forces a two-entry run -
//       after B.5 the table holds 49 + 54 + 57 + 55 = 215 under a capacity of 220, and an
//       arriving 60-byte entry needs the size down to 160, which one eviction (leaving 166)
//       does not reach and two (leaving 112) do - and references the SECOND of the two.
//   24. `TryPlanEviction`: the reference check inverted.
//       Killed by the walk, in 11 cases.
//
// --- s3.2.4, s3.2.5, s3.2.6's three indexing modes (11 rows) ---
//
//   25. `TryResolveEncoderRelative`: drop the -1.
//       Killed by EveryEncoderRelativeArithmeticInTheCaptureResolves and the walk, in 9 cases.
//   26. `TryResolveEncoderRelative`: add where s3.2.5 subtracts.
//       Killed by the same, in 12 cases.
//   27. `TryResolveEncoderRelative`: `if (relativeIndex >= InsertCount)` -> `>`.
//       Killed by ARelativeIndexPastTheInsertionPointIsRejected, in 1 case.
//   28. `TryResolveFieldRelative`: drop the -1.
//       Killed by EveryFieldRelativeArithmeticInTheCaptureResolves, in 2 cases.
//   29. `TryResolveFieldRelative`: `if (relativeIndex >= baseValue)` -> `>`. [WAS-SURVIVOR]
//       SURVIVED UNWITNESSED. Appendix B's field-relative examples are Base(4) with indices 0
//       and 1; neither is at the boundary, and no test reached relativeIndex == baseValue.
//       That case is not a harmless off-by-one: `baseValue - baseValue - 1` in ulong does not
//       go negative, it wraps to 2^64-1, which is an ordinary-looking absolute index.
//       Witnessed by AFieldRelativeIndexAtTheBaseIsRejectedRatherThanWrapped, which also pins
//       that the out value stays 0 on rejection, and by AtBaseZeroNoFieldRelativeIndexResolves.
//       Now killed, in 5 cases.
//   30. `TryResolvePostBase`: subtract where s3.2.6 adds.
//       s3.2.6 is the one mode that increases "in the same direction as the absolute index".
//       Killed by EveryPostBaseArithmeticInTheCaptureResolves, in 2 cases.
//   31. `TryResolvePostBase`: off by one.
//       Killed by the same, in 2 cases.
//   32. `TryGetEntry`: ignore the dropping point.
//       s3.2.4's indices are "fixed for the lifetime of that entry", and after B.5's eviction
//       absolute 0 is gone rather than aliased to whatever now sits at list position 0.
//       Killed by the walk and EveryPublishedRowIsReachableByItsAbsoluteIndex, in 4 cases.
//   33. `TryGetEntry`: `absoluteIndex >= InsertCount` -> `>`, one past the insertion point.
//       Killed by EveryPublishedRowIsReachableByItsAbsoluteIndex, in 1 case.
//   34. `TryGetEntry`: absolute indices shuffle down on eviction.
//       Killed by the walk, in 3 cases.
//   35. `ApplyEviction`: DroppedCount not advanced.
//       Killed by the walk, in 10 cases.
//
// --- the stream boundary (3 rows) ---
//
//   36. `TryReadEncoderInstructions`: report the whole buffer as consumed regardless.
//       Killed by FeedingTheStreamOneOctetAtATimeReachesTheSameState, in 9 cases.
//   37. `TryReadEncoderInstructions`: treat a partial instruction as a hard error.
//       The encoder stream is a byte stream; an instruction split across two reads is not a
//       malformed one.
//       Killed by FeedingTheStreamOneOctetAtATimeReachesTheSameState and
//       EveryTruncationOfThePublishedStreamIsHandledWithoutThrowing, in 3 cases.
//   38. `TryReadEncoderInstructions`: accept any fault as a complete instruction.
//       The mirror image, and the more dangerous one: it turns every rejection into silence.
//       Killed by 14 cases.
//
// --- s3.2.2's shared-storage caution, and s6's codes (3 rows) ---
//
//   39. `ApplyEviction`: zero an evicted entry's bytes as it is dropped. [WAS-SURVIVOR]
//       THE ROW'S FIRST FORM WAS ITSELF EQUIVALENT and that is worth recording. It assigned
//       `dropped.Name = []`, which replaces the FIELD and not the bytes, and every holder of
//       the array - the duplicate that shares it - still had its own reference. Restated as
//       `Array.Clear(dropped.Name)`, which mutates the bytes the duplicate is reading, it dies
//       at once. s3.2.2: "Implementations are cautioned to avoid deleting the referenced name
//       or value if the referenced entry is evicted from the dynamic table prior to inserting
//       the new entry."
//       Killed by the walk (B.4's duplicate at absolute 3 shares absolute 0's arrays, and B.5
//       evicts absolute 0) and by DuplicatingTheOnlyEntryEvictsItAndKeepsItsBytes, in 3 cases.
//   40. `QpackEncoderStreamError`: 0x0201 -> 0x0200.
//       s6 gives the encoder stream its own code; 0x0200 is QPACK_DECOMPRESSION_FAILED, which
//       belongs to a field section.
//       Killed by TheEncoderStreamErrorCodeIsTheOneTheCaptureNames, in 1 case.
//   41. `TryGetHttp3ErrorCode`: map NeedMoreData to a connection error. [WAS-SURVIVOR]
//       SURVIVED UNWITNESSED, and unwitnessed for a structural reason: NeedMoreData never
//       escapes TryReadEncoderInstructions, which converts it to None and returns true, so
//       nothing in the test file passed it to TryGetHttp3ErrorCode. It is still reachable -
//       task C15's stream wiring resolves faults itself - and a caller that took the mutant's
//       answer would close the connection over an instruction that had merely not finished
//       arriving.
//       Witnessed by OnlyRealFaultsMapToAConnectionErrorCode, which walks the whole enum
//       rather than the members that happen to arise elsewhere. Now killed, in 1 case.

// RFC 9204 s3.2's dynamic table and s4.3's encoder-stream reader.
//
// EXTRACTS THIS FILE IS ANCHORED TO, all under docs/superpowers/specs/reference-captures/:
//   rfc9204-section3-reference-tables.txt          s3.2.1 size, s3.2.2 eviction,
//                                                  s3.2.3 maximum, s3.2.4/5/6 indexing
//   rfc9204-section4.3-encoder-instructions.txt    the four instructions (captured by C14)
//   rfc9204-section2-compression-process-overview.txt  s2.1.1 evictability
//   rfc9204-appendix-b-encoding-and-decoding-examples.txt  B.2-B.5, the published states
//
// THIS TABLE IS DECODER-SIDE ONLY, AND THAT IS NOT A SHORTFALL. s3.2.3: "the encoder MUST
// NOT set a dynamic table capacity that exceeds this maximum, but it can choose to use a
// lower dynamic table capacity" - and s4.2 lets an endpoint omit its encoder stream
// entirely "if its encoder does not wish to use the dynamic table". Our encoder takes that
// option in both arms, so there is no insert path here for OUR entries; every mutation is
// driven by an instruction the PEER sent us. The table the peer's encoder drives is the
// only one that has to exist.
//
// ON THE DIRECTION OF s3.2.3's LIMIT. The ceiling checked in TrySetCapacity is the value
// WE advertised in SETTINGS_QPACK_MAX_TABLE_CAPACITY, not one the peer told us. It is easy
// to read s4.3.1's "this limit is the value of the SETTINGS_QPACK_MAX_TABLE_CAPACITY
// parameter (Section 5) received from the decoder" and wire it the wrong way round: in
// that sentence WE are the decoder, so it is the parameter we sent. A table that obeyed
// the peer's advertisement instead would be unbounded from our side, which is precisely
// the memory bound s3.2.3 exists to establish.
internal enum TlsQuicQpackEncoderStreamError
{
    None = 0,

    // NOT AN ERROR, and the reason this enum exists separately from TlsQuicQpackError.
    // The encoder stream is a byte stream, so an instruction may be split across reads and
    // TlsQuicQpackError.Truncated at the end of a buffer means "ask again with more bytes",
    // not "the peer is wrong". TryReadEncoderInstructions never reports this: it stops at
    // the last COMPLETE instruction and reports that count in `consumed`. It is named here
    // so that a caller resolving a fault has a member to compare against rather than a
    // bare `false`, and so that mapping to an HTTP/3 code has something to exclude.
    NeedMoreData,

    // s4.3.1: "The decoder MUST treat a new dynamic table capacity value that exceeds this
    // limit as a connection error of type QPACK_ENCODER_STREAM_ERROR", where the limit is
    // s3.2.3's SETTINGS_QPACK_MAX_TABLE_CAPACITY. This is the MUST that bounds our memory.
    CapacityAboveMaximum,

    // s3.2.2: "It is an error if the encoder attempts to add an entry that is larger than
    // the dynamic table capacity; the decoder MUST treat this as a connection error of type
    // QPACK_ENCODER_STREAM_ERROR." Note that this is checked against the CAPACITY and not
    // against the free space, so it fires even on an empty table, and it makes every insert
    // at capacity 0 an error - which is the same sentence that lets a decoder advertising
    // zero refuse the whole dynamic arm without a second rule.
    EntryLargerThanCapacity,

    // s3.2.2: "The encoder MUST NOT cause a dynamic table entry to be evicted unless that
    // entry is evictable; see Section 2.1.1." s4.3.1 repeats it for a capacity REDUCTION:
    // "This MUST NOT cause the eviction of entries that are not evictable". One rule, two
    // instructions - a table that enforced it only on insert would let a Set Dynamic Table
    // Capacity=0 drop entries a field section still points at.
    //
    // s2.1.1's full test is "the insertion ... has been acknowledged and there are no
    // outstanding references to the entry in unacknowledged representations". The
    // acknowledgment half is the ENCODER's view of a round trip it is waiting on; on this
    // side we are the party that acknowledges, so an entry we hold is processed by
    // definition and only the reference half is ours to check. Dropping the acknowledgment
    // half here is a consequence of the direction, not a simplification of the rule.
    EvictionOfReferencedEntry,

    // An index that resolves to no entry: an absolute index below the dropping point or at
    // or past the insertion point (s3.2.4), a relative index that would underflow past the
    // start (s3.2.5), or a post-base index past the insertion point (s3.2.6). RFC 9204 s2.2.3
    // calls a reference to a dropped entry "a connection error of type
    // QPACK_DECOMPRESSION_FAILED" when it appears in a FIELD SECTION; arriving in an ENCODER
    // INSTRUCTION it is s4.3's stream that is malformed, so it is reported here and the
    // caller picks the code from the stream it came off. See TryGetHttp3ErrorCode.
    IndexOutOfRange,

    // A fault raised by TlsQuicQpackPrimitives or TlsQuicQpackHuffman while reading an
    // instruction: an integer past s4.1.1's 62 bits, a Huffman string carrying EOS, bad
    // padding. Every one of them is a malformed encoder stream and s4.3 gives them all the
    // same treatment, so they collapse to one member rather than being mirrored one for one
    // out of TlsQuicQpackError.
    MalformedInstruction,
}

internal sealed class TlsQuicQpackDynamicTable
{
    // RFC 9204 s6: "QPACK_ENCODER_STREAM_ERROR (0x0201): The decoder failed to interpret an
    // encoder instruction received on the encoder stream." Read out of
    // reference-captures/rfc9204-section5-6-configuration-and-error-handling.txt rather than
    // typed from memory; TlsQuicQpackDynamicTableTests.TheEncoderStreamErrorCodeIsTheOne
    // TheCaptureNames re-parses that file and fails if this constant drifts.
    internal const ulong QpackEncoderStreamError = 0x0201;

    // s3.2.1: "The size of an entry is the sum of its name's length in bytes, its value's
    // length in bytes, and 32 additional bytes." The same 32 RFC 9114 s4.2.2 uses for field
    // section size, and a DIFFERENT accounting from it - this one is over the table, that
    // one over a section - so the two constants are deliberately not shared.
    internal const int EntrySizeOverhead = 32;

    private const byte InsertWithNameReferenceFlag = 0b1000_0000;
    private const byte InsertWithNameReferenceStaticFlag = 0b0100_0000;
    private const byte InsertWithLiteralNameFlag = 0b0100_0000;
    private const byte SetCapacityFlag = 0b0010_0000;

    private const int InsertNameIndexPrefixBits = 6;
    private const int InsertLiteralNamePrefixBits = 6;
    private const int InsertValuePrefixBits = 8;
    private const int SetCapacityPrefixBits = 5;
    private const int DuplicateIndexPrefixBits = 5;

    private sealed class Entry
    {
        internal byte[] Name = [];
        internal byte[] Value = [];
        internal int References;
    }

    private readonly List<Entry> entries = [];
    private readonly int maximumCapacity;

    // Grown on demand, never shrunk, and reused across every Huffman literal on the stream.
    // Sized from TlsQuicQpackHuffman.GetMaximumDecodedLength, so the growth is bounded by the
    // declared length of a literal the peer already had to send us the bytes of. Reused
    // rather than rented per call so that a stream of same-sized literals - which is what a
    // real encoder sends - allocates once and then never again, which is what makes the
    // rejecting path allocation-free in steady state.
    //
    // TWO buffers rather than one because s4.3.3 carries two literals in wire order and the
    // first must stay readable while the second is decoded; see TryReadInsertWithLiteralName.
    private byte[] nameScratch = [];
    private byte[] valueScratch = [];

    // The constructor is the one member here that throws, and it throws only on a value a
    // CALLER chose. Wire input never reaches it: `maximumCapacity` is the number we put in
    // our own SETTINGS frame. Everything reachable from the encoder stream reports through
    // `out TlsQuicQpackEncoderStreamError` and returns false.
    internal TlsQuicQpackDynamicTable(int maximumCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maximumCapacity);
        this.maximumCapacity = maximumCapacity;
    }

    // s3.2.3's limit, the value we advertise in SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    internal int MaximumCapacity => maximumCapacity;

    // s3.2.2: "The initial capacity of the dynamic table is zero. The encoder sends a Set
    // Dynamic Table Capacity instruction (Section 4.3.1) with a non-zero capacity to begin
    // using the dynamic table." So this starts at 0 even when MaximumCapacity is 65536, and
    // an insert before the first Set Dynamic Table Capacity is EntryLargerThanCapacity.
    internal int Capacity { get; private set; }

    // s3.2.1: "The size of the dynamic table is the sum of the size of its entries."
    internal int Size { get; private set; }

    // s3.2.4: "The first entry inserted has an absolute index of 0; indices increase by one
    // with each insertion." So this doubles as the absolute index the next insert will take,
    // and as s3.2.5's `n`.
    internal ulong InsertCount { get; private set; }

    // s3.2.5's `d`, the count of entries dropped. The lowest absolute index still present.
    internal ulong DroppedCount { get; private set; }

    internal int Count => entries.Count;

    // Every fault this table can raise came off the encoder stream, so every one of them is
    // s6's QPACK_ENCODER_STREAM_ERROR. NeedMoreData is not a fault and None is not either.
    internal static bool TryGetHttp3ErrorCode(TlsQuicQpackEncoderStreamError error, out ulong code)
    {
        code = QpackEncoderStreamError;
        return error is not (TlsQuicQpackEncoderStreamError.None or TlsQuicQpackEncoderStreamError.NeedMoreData);
    }

    // ========================================================================
    // s4.3, the encoder stream
    // ========================================================================

    // Reads as many COMPLETE instructions as `source` holds and reports how many octets they
    // took. A partial instruction at the end is left unconsumed and is not an error - see
    // TlsQuicQpackEncoderStreamError.NeedMoreData - so a caller feeding a stream keeps the
    // unconsumed tail and prepends it to the next read. Returning true with consumed = 0 on
    // an empty or wholly-partial buffer is the normal case, not a stall to guard against.
    internal bool TryReadEncoderInstructions(
        ReadOnlySpan<byte> source,
        out int consumed,
        out TlsQuicQpackEncoderStreamError error)
    {
        consumed = 0;
        error = TlsQuicQpackEncoderStreamError.None;

        while (consumed < source.Length)
        {
            if (!TryReadOneInstruction(source[consumed..], out int used, out error))
            {
                if (error == TlsQuicQpackEncoderStreamError.NeedMoreData)
                {
                    error = TlsQuicQpackEncoderStreamError.None;
                    return true;
                }

                return false;
            }

            consumed += used;
        }

        return true;
    }

    // s4.3's four opcodes are a PREFIX TREE and not a fixed-width tag, so the order of these
    // tests is load-bearing: 1xxxxxxx, then 01xxxxxx, then 001xxxxx, then 000xxxxx. Testing
    // the 3-bit patterns first would swallow every instruction whose top bit happens to be
    // set, and testing 001 before 01 would misread half of s4.3.3 as a capacity change.
    private bool TryReadOneInstruction(
        ReadOnlySpan<byte> source,
        out int consumed,
        out TlsQuicQpackEncoderStreamError error)
    {
        consumed = 0;
        byte first = source[0];

        if ((first & InsertWithNameReferenceFlag) != 0)
        {
            return TryReadInsertWithNameReference(source, out consumed, out error);
        }

        if ((first & InsertWithLiteralNameFlag) != 0)
        {
            return TryReadInsertWithLiteralName(source, out consumed, out error);
        }

        if ((first & SetCapacityFlag) != 0)
        {
            return TryReadSetCapacity(source, out consumed, out error);
        }

        return TryReadDuplicate(source, out consumed, out error);
    }

    // s4.3.1: '001' then the new capacity as a 5-bit prefix integer.
    private bool TryReadSetCapacity(
        ReadOnlySpan<byte> source,
        out int consumed,
        out TlsQuicQpackEncoderStreamError error)
    {
        if (!TlsQuicQpackPrimitives.TryDecodeInteger(
                source,
                SetCapacityPrefixBits,
                out ulong newCapacity,
                out consumed,
                out TlsQuicQpackError primitive))
        {
            error = Translate(primitive);
            return false;
        }

        return TrySetCapacity(newCapacity, out error);
    }

    // s4.3.2: '1', then T, then a 6-bit prefix name index, then the value as a string
    // literal with an 8-bit prefix. "When T=1, the number represents the static table index;
    // when T=0, the number is the relative index of the entry in the dynamic table" - and
    // that relative index is s3.2.5's ENCODER-STREAM flavour, counted back from the
    // insertion point, not the field-section flavour counted back from a Base.
    private bool TryReadInsertWithNameReference(
        ReadOnlySpan<byte> source,
        out int consumed,
        out TlsQuicQpackEncoderStreamError error)
    {
        consumed = 0;
        bool useStatic = (source[0] & InsertWithNameReferenceStaticFlag) != 0;

        if (!TlsQuicQpackPrimitives.TryDecodeInteger(
                source,
                InsertNameIndexPrefixBits,
                out ulong nameIndex,
                out int indexLength,
                out TlsQuicQpackError primitive))
        {
            error = Translate(primitive);
            return false;
        }

        if (!TryReadStringLiteral(
                source[indexLength..],
                InsertValuePrefixBits,
                ref valueScratch,
                out ReadOnlySpan<byte> value,
                out int valueLength,
                out error))
        {
            return false;
        }

        // The NAME is resolved before any eviction, because s3.2.2 warns that the referenced
        // entry may be one of the entries this very insert evicts: "Implementations are
        // cautioned to avoid deleting the referenced name or value if the referenced entry is
        // evicted from the dynamic table prior to inserting the new entry." B.5 is exactly
        // that case in the published examples. `shared` is the existing entry's array when the
        // reference is dynamic, so the duplicate and its source keep sharing storage.
        if (!TryResolveInsertName(useStatic, nameIndex, out ReadOnlySpan<byte> name, out byte[]? shared, out error))
        {
            return false;
        }

        if (!TryPlanInsert(name.Length, value.Length, out InsertPlan plan, out error))
        {
            return false;
        }

        Commit(plan, shared ?? name.ToArray(), value.ToArray());
        consumed = indexLength + valueLength;
        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    // s4.3.3: '01', then the name as a 6-bit prefix string literal (H is bit 2, so the length
    // has a 5-bit prefix), then the value as an 8-bit prefix string literal.
    private bool TryReadInsertWithLiteralName(
        ReadOnlySpan<byte> source,
        out int consumed,
        out TlsQuicQpackEncoderStreamError error)
    {
        consumed = 0;

        // The name and the value decode into SEPARATE scratch buffers. One buffer would be
        // enough for the bytes but not for the ordering: the name is on the wire first and the
        // value's Huffman decode would overwrite it, which would force the name to be copied
        // to the heap before the entry is known to be legal at all. Two buffers keep both
        // spans alive until the size check has run, which is what makes the rejecting path
        // allocation-free.
        if (!TryReadStringLiteral(
                source,
                InsertLiteralNamePrefixBits,
                ref nameScratch,
                out ReadOnlySpan<byte> name,
                out int nameLength,
                out error))
        {
            return false;
        }

        if (!TryReadStringLiteral(
                source[nameLength..],
                InsertValuePrefixBits,
                ref valueScratch,
                out ReadOnlySpan<byte> value,
                out int valueLength,
                out error))
        {
            return false;
        }

        if (!TryPlanInsert(name.Length, value.Length, out InsertPlan plan, out error))
        {
            return false;
        }

        Commit(plan, name.ToArray(), value.ToArray());
        consumed = nameLength + valueLength;
        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    // s4.3.4: '000' then a 5-bit prefix relative index. "The existing entry is reinserted
    // into the dynamic table without resending either the name or the value."
    private bool TryReadDuplicate(
        ReadOnlySpan<byte> source,
        out int consumed,
        out TlsQuicQpackEncoderStreamError error)
    {
        consumed = 0;

        if (!TlsQuicQpackPrimitives.TryDecodeInteger(
                source,
                DuplicateIndexPrefixBits,
                out ulong relativeIndex,
                out int length,
                out TlsQuicQpackError primitive))
        {
            error = Translate(primitive);
            return false;
        }

        if (!TryResolveEncoderRelative(relativeIndex, out ulong absolute, out error) ||
            !TryGetEntry(absolute, out Entry? original))
        {
            error = TlsQuicQpackEncoderStreamError.IndexOutOfRange;
            return false;
        }

        // The SAME arrays go into the new entry, not copies. They are never mutated after
        // insertion, so the duplicate and its original share storage for as long as both
        // live - which is what makes B.4's duplicate cost only its 32 bytes of overhead plus
        // the name and value lengths again in the SIZE accounting, while costing nothing
        // extra in memory. s3.2.1 counts the bytes twice; the heap does not have to.
        if (!TryPlanInsert(original.Name.Length, original.Value.Length, out InsertPlan plan, out error))
        {
            return false;
        }

        Commit(plan, original.Name, original.Value);
        consumed = length;
        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    // Resolves s4.3.2's name reference WITHOUT copying. `shared` is non-null exactly when the
    // reference was dynamic, and is then the existing entry's own array: the new entry reuses
    // it rather than duplicating the bytes, which is both cheaper and what keeps the name
    // alive when the referenced entry is itself evicted by this insert. A static reference
    // has no array to share, so its bytes are copied by the caller - but only after
    // TryPlanInsert has agreed the entry is legal.
    private bool TryResolveInsertName(
        bool useStatic,
        ulong index,
        out ReadOnlySpan<byte> name,
        out byte[]? shared,
        out TlsQuicQpackEncoderStreamError error)
    {
        name = default;
        shared = null;

        if (useStatic)
        {
            if (index > int.MaxValue ||
                !TlsQuicQpackStaticTable.TryLookup((int)index, out ReadOnlySpan<byte> staticName, out _))
            {
                error = TlsQuicQpackEncoderStreamError.IndexOutOfRange;
                return false;
            }

            name = staticName;
            error = TlsQuicQpackEncoderStreamError.None;
            return true;
        }

        if (!TryResolveEncoderRelative(index, out ulong absolute, out error) ||
            !TryGetEntry(absolute, out Entry? entry))
        {
            error = TlsQuicQpackEncoderStreamError.IndexOutOfRange;
            return false;
        }

        shared = entry.Name;
        name = shared;
        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    // s4.1.2's string literal, with the H bit honoured. The decoded bytes are handed back as
    // a span into `scratch` when H = 1 and as a slice of `source` when H = 0. Either way the
    // span is only valid until the next literal read into the SAME scratch buffer, which is
    // why the two literals of s4.3.3 use two different ones.
    private static bool TryReadStringLiteral(
        ReadOnlySpan<byte> source,
        int prefixBits,
        ref byte[] scratch,
        out ReadOnlySpan<byte> data,
        out int consumed,
        out TlsQuicQpackEncoderStreamError error)
    {
        data = default;

        if (!TlsQuicQpackPrimitives.TryDecodeStringLiteral(
                source,
                prefixBits,
                out bool huffman,
                out ReadOnlySpan<byte> raw,
                out consumed,
                out TlsQuicQpackError primitive))
        {
            error = Translate(primitive);
            return false;
        }

        if (!huffman)
        {
            data = raw;
            error = TlsQuicQpackEncoderStreamError.None;
            return true;
        }

        int needed = TlsQuicQpackHuffman.GetMaximumDecodedLength(raw.Length);
        if (scratch.Length < needed)
        {
            scratch = new byte[needed];
        }

        if (!TlsQuicQpackHuffman.TryDecode(raw, scratch, out int written, out primitive))
        {
            error = Translate(primitive);
            return false;
        }

        data = scratch.AsSpan(0, written);
        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    // TlsQuicQpackError.Truncated is the only member that is not a fault here: on a stream it
    // means the instruction has not arrived in full yet. DestinationTooSmall cannot occur -
    // the scratch buffer is sized from GetMaximumDecodedLength immediately above the only call -
    // and is mapped to MalformedInstruction rather than left to fall through as None, so that
    // a future change that CAN produce it fails closed instead of silently accepting.
    private static TlsQuicQpackEncoderStreamError Translate(TlsQuicQpackError error) =>
        error == TlsQuicQpackError.Truncated
            ? TlsQuicQpackEncoderStreamError.NeedMoreData
            : TlsQuicQpackEncoderStreamError.MalformedInstruction;

    // ========================================================================
    // s3.2.2, capacity and eviction
    // ========================================================================

    internal bool TrySetCapacity(ulong newCapacity, out TlsQuicQpackEncoderStreamError error)
    {
        // s4.3.1: "The new capacity MUST be lower than or equal to the limit described in
        // Section 3.2.3." Compared in ulong BEFORE any narrowing, so a capacity near 2^62
        // cannot wrap into a small int and pass.
        if (newCapacity > (ulong)maximumCapacity)
        {
            error = TlsQuicQpackEncoderStreamError.CapacityAboveMaximum;
            return false;
        }

        // s3.2.2: "Whenever the dynamic table capacity is reduced by the encoder
        // (Section 4.3.1), entries are evicted from the end of the dynamic table until the
        // size of the dynamic table is less than or equal to the new table capacity."
        int target = (int)newCapacity;
        if (!TryPlanEviction(target, out int count, out int running, out error))
        {
            return false;
        }

        ApplyEviction(count, running);
        Capacity = target;
        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    // What an insert would cost and what it would displace, worked out BEFORE anything is
    // allocated or mutated. Splitting the decision from the commit is what lets the whole
    // rejecting path run without a single allocation - the name and value are still spans
    // into the source buffer or into a scratch buffer at this point, and are only copied to
    // the heap once this has said yes.
    private readonly record struct InsertPlan(int EntrySize, int EvictCount, int RemainingSize);

    private bool TryPlanInsert(
        int nameLength,
        int valueLength,
        out InsertPlan plan,
        out TlsQuicQpackEncoderStreamError error)
    {
        int entrySize = nameLength + valueLength + EntrySizeOverhead;
        plan = default;

        // s3.2.2: "It is an error if the encoder attempts to add an entry that is larger than
        // the dynamic table capacity". Against the CAPACITY, not the free space, and checked
        // before any eviction so that an oversized entry cannot empty the table on its way to
        // being rejected.
        if (entrySize > Capacity)
        {
            error = TlsQuicQpackEncoderStreamError.EntryLargerThanCapacity;
            return false;
        }

        // s3.2.2: "entries are evicted from the end of the dynamic table until the size of
        // the dynamic table is less than or equal to (table capacity - size of new entry)."
        // The subtraction cannot go negative: entrySize <= Capacity was just established.
        if (!TryPlanEviction(Capacity - entrySize, out int count, out int running, out error))
        {
            return false;
        }

        plan = new InsertPlan(entrySize, count, running);
        return true;
    }

    private void Commit(InsertPlan plan, byte[] name, byte[] value)
    {
        ApplyEviction(plan.EvictCount, plan.RemainingSize);
        entries.Add(new Entry { Name = name, Value = value });
        Size += plan.EntrySize;
        InsertCount++;
    }

    // "Evicted from the END of the dynamic table" is the OLDEST entry - s3.2.5's dropping
    // point, the low absolute index - and not the most recent one. The figure in s3.2.5 puts
    // absolute index n-1 at the insertion point and d at the dropping point, so the end that
    // gives way is index 0 of this list.
    //
    // This MEASURES and does not mutate. A rejected instruction must leave the table exactly
    // as it was: a partially evicted table after a rejection would be a silent state
    // corruption that no error code could describe.
    private bool TryPlanEviction(
        int target,
        out int count,
        out int running,
        out TlsQuicQpackEncoderStreamError error)
    {
        running = Size;
        count = 0;

        while (running > target)
        {
            if (count >= entries.Count)
            {
                // Unreachable while the size accounting is exact - emptying the table drives
                // `running` to 0 and every target is non-negative - but a bound on a loop
                // that indexes a list is not something to leave to an invariant.
                error = TlsQuicQpackEncoderStreamError.EntryLargerThanCapacity;
                return false;
            }

            Entry candidate = entries[count];
            if (candidate.References != 0)
            {
                error = TlsQuicQpackEncoderStreamError.EvictionOfReferencedEntry;
                return false;
            }

            running -= candidate.Name.Length + candidate.Value.Length + EntrySizeOverhead;
            count++;
        }

        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    private void ApplyEviction(int count, int running)
    {
        if (count != 0)
        {
            entries.RemoveRange(0, count);
            Size = running;
            DroppedCount += (ulong)count;
        }
    }

    // ========================================================================
    // s3.2.4, s3.2.5, s3.2.6 - the three indexing modes
    // ========================================================================

    // s3.2.4: absolute indices are fixed for the lifetime of an entry, so an entry is present
    // exactly when DroppedCount <= index < InsertCount.
    internal bool TryLookupAbsolute(
        ulong absoluteIndex,
        out ReadOnlySpan<byte> name,
        out ReadOnlySpan<byte> value,
        out TlsQuicQpackEncoderStreamError error)
    {
        name = default;
        value = default;

        if (!TryGetEntry(absoluteIndex, out Entry? entry))
        {
            error = TlsQuicQpackEncoderStreamError.IndexOutOfRange;
            return false;
        }

        name = entry.Name;
        value = entry.Value;
        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    // s3.2.5, ENCODER-INSTRUCTION flavour: "a relative index of 0 refers to the most recently
    // inserted value in the dynamic table". B.4 spells the arithmetic out - "Absolute Index =
    // Insert Count(3) - Index(2) - 1 = 0".
    //
    // "Note that this means the entry referenced by a given relative index will change while
    // interpreting instructions on the encoder stream" - which is why this reads InsertCount
    // live rather than taking a snapshot, and why B.5's Relative Index = 1 resolves against
    // an Insert Count of 4 rather than the 3 it had one instruction earlier.
    internal bool TryResolveEncoderRelative(
        ulong relativeIndex,
        out ulong absoluteIndex,
        out TlsQuicQpackEncoderStreamError error)
    {
        absoluteIndex = 0;

        if (relativeIndex >= InsertCount)
        {
            error = TlsQuicQpackEncoderStreamError.IndexOutOfRange;
            return false;
        }

        absoluteIndex = InsertCount - relativeIndex - 1;
        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    // s3.2.5, FIELD-SECTION flavour, and a DIFFERENT function from the one above despite the
    // shared name in the RFC: "Unlike in encoder instructions, relative indices in field line
    // representations are relative to the Base at the beginning of the encoded field section
    // ... a relative index of 0 refers to the entry with absolute index equal to Base - 1."
    // B.4's stream 8 shows it: "Absolute Index = Base(4) - Index(0) - 1 = 3".
    internal bool TryResolveFieldRelative(
        ulong baseValue,
        ulong relativeIndex,
        out ulong absoluteIndex,
        out TlsQuicQpackEncoderStreamError error)
    {
        absoluteIndex = 0;

        if (relativeIndex >= baseValue)
        {
            error = TlsQuicQpackEncoderStreamError.IndexOutOfRange;
            return false;
        }

        absoluteIndex = baseValue - relativeIndex - 1;
        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    // s3.2.6: post-base indices start "at 0 for the entry with absolute index equal to Base
    // and increasing in the SAME direction as the absolute index" - so this one adds where
    // the other two subtract. B.2's stream 4 is the witness: "Absolute Index = Base(0) +
    // Index(1) = 1".
    internal bool TryResolvePostBase(
        ulong baseValue,
        ulong postBaseIndex,
        out ulong absoluteIndex,
        out TlsQuicQpackEncoderStreamError error)
    {
        absoluteIndex = 0;

        // Added in ulong with an explicit overflow test rather than in a checked block: the
        // sum of two values each up to s4.1.1's 2^62-1 fits a ulong, but a caller handing in
        // two near-ulong.MaxValue values must not wrap into a valid-looking small index.
        if (postBaseIndex > ulong.MaxValue - baseValue)
        {
            error = TlsQuicQpackEncoderStreamError.IndexOutOfRange;
            return false;
        }

        absoluteIndex = baseValue + postBaseIndex;
        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    // ========================================================================
    // s2.1.1, outstanding references
    // ========================================================================

    // Taken when a field section starts using an entry and released when that section is done
    // with it. While a reference is outstanding the entry is not evictable, so an insert or a
    // capacity reduction that would reach it is rejected rather than silently dropping an
    // entry a section still points at.
    internal bool TryAddReference(ulong absoluteIndex, out TlsQuicQpackEncoderStreamError error)
    {
        if (!TryGetEntry(absoluteIndex, out Entry? entry))
        {
            error = TlsQuicQpackEncoderStreamError.IndexOutOfRange;
            return false;
        }

        entry.References++;
        error = TlsQuicQpackEncoderStreamError.None;
        return true;
    }

    // Releasing a reference to an entry that is gone, or one that was never taken, is a no-op
    // rather than a fault. An entry cannot be evicted while referenced, so a live reference is
    // always releasable; the tolerant shape exists for the unwind path, where a field section
    // being torn down after a failure releases whatever it managed to take without having to
    // remember how far it got.
    internal void ReleaseReference(ulong absoluteIndex)
    {
        if (TryGetEntry(absoluteIndex, out Entry? entry) && entry.References > 0)
        {
            entry.References--;
        }
    }

    internal int ReferenceCountAt(ulong absoluteIndex) =>
        TryGetEntry(absoluteIndex, out Entry? entry) ? entry.References : 0;

    private bool TryGetEntry(ulong absoluteIndex, out Entry entry)
    {
        if (absoluteIndex < DroppedCount || absoluteIndex >= InsertCount)
        {
            entry = null!;
            return false;
        }

        entry = entries[(int)(absoluteIndex - DroppedCount)];
        return true;
    }
}
