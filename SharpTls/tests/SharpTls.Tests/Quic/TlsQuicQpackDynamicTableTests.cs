using System.Text;
using System.Text.RegularExpressions;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// RFC 9204 s3.2's dynamic table and s4.3's encoder-stream reader.
//
// EVERY VECTOR IN THIS FILE IS PARSED OUT OF A CAPTURE AT TEST TIME, and none of the
// published numbers - not a byte string, not a table row, not a size, not an index
// arithmetic - is typed into this file as a literal. That is the C6 lesson applied: an
// encode/decode round trip reads the same tables in both directions, so a wrong table makes
// both halves wrong identically and the round trip still passes. C6's row 13 swapped two
// 28-bit Huffman codes, left the code complete and prefix-free with Kraft still summing to
// 1, and all 256 round trips passed; only the capture witness killed it. This file has no
// round trip at all to hide behind - our encoder never emits an encoder instruction - so the
// capture is the ONLY oracle, and it is re-read rather than remembered.
//
// The four Appendix B sections are ONE continuous example and are walked as one: B.2 sets a
// capacity of 220 and inserts two entries, B.3 adds a literal-name entry, B.4 duplicates,
// and B.5 inserts an entry that does not fit and evicts. Each step asserts the table state
// the capture prints for that step - the Abs/Ref/Name/Value rows AND the Size line - so a
// mutant that decodes the bytes correctly but accounts for size or eviction wrongly is
// caught at the step where the two diverge rather than at the end.
public sealed class TlsQuicQpackDynamicTableTests
{
    // The maximum capacity the walk runs under. Deliberately far above B.2's capacity of 220
    // so that s3.2.3's ceiling plays NO part in the eviction the walk witnesses: every
    // eviction in B.2-B.5 is driven by the 220 the encoder set, and a mutant that confused
    // the two limits cannot hide behind them being equal.
    private const int WalkMaximumCapacity = 4096;

    // ========================================================================
    // CAPTURE-ANCHORED: Appendix B.2-B.5, the published table states
    // ========================================================================

    [Fact]
    public void TheAppendixBWalkReproducesEveryPublishedTableState()
    {
        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        IReadOnlyList<AppendixBStep> steps = AppendixBSteps();

        // The four steps exist at all. Without this a regex that silently matched nothing
        // would make the whole walk vacuously green.
        Assert.Equal(4, steps.Count);

        foreach (AppendixBStep step in steps)
        {
            Assert.True(
                table.TryReadEncoderInstructions(step.Octets, out int consumed, out TlsQuicQpackEncoderStreamError error),
                $"{step.Label} was rejected with {error}.");
            Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);

            // Every octet of the section's encoder stream is accounted for. A mutant that
            // under-reports `consumed` would leave a tail and re-read it as a fresh
            // instruction, so this is not redundant with the state assertions below.
            Assert.Equal(step.Octets.Length, consumed);

            AssertTableMatches(table, step);
        }
    }

    // B.2's capacity, read back from the instruction rather than from the annotation, and
    // then checked AGAINST the annotation. `3fbd01` is s4.3.1's '001' pattern with a 5-bit
    // prefix that fills (31) plus a two-octet continuation (61 + 128) = 220, and the capture
    // labels that same line "Set Dynamic Table Capacity=220". Two independent readings of one
    // instruction, and they have to agree.
    [Fact]
    public void TheCapacityDecodedFromB2MatchesTheCaptureAnnotation()
    {
        string section = AppendixBSection("B.2");
        Match annotation = Regex.Match(section, @"Set Dynamic Table Capacity=(?<capacity>\d+)");
        Assert.True(annotation.Success, "B.2's capacity annotation not found in the capture.");
        int announced = int.Parse(annotation.Groups["capacity"].Value);

        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.Equal(0, table.Capacity);

        Assert.True(table.TryReadEncoderInstructions(
            AppendixBSteps()[0].Octets,
            out _,
            out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
        Assert.Equal(announced, table.Capacity);
    }

    // B.5's eviction, with the boundary shown rather than asserted.
    //
    // THE STRADDLE, in numbers taken from the capture's own rows: entering B.5 the table
    // holds 217 bytes under a capacity of 220. The new entry (custom-key=custom-value2) costs
    // 10 + 13 + 32 = 55. s3.2.2 evicts until size <= capacity - new entry, that is until
    // size <= 220 - 55 = 165. 217 > 165, so at least one eviction is FORCED. The oldest entry
    // (:authority=www.example.com) costs 57, leaving 217 - 57 = 160, and 160 <= 165, so the
    // eviction stops after EXACTLY one. Both halves matter: without the first the test would
    // be vacuous, and without the second a mutant that evicts greedily until the table is
    // empty would pass.
    [Fact]
    public void AppendixB5EvictsExactlyTheOneEntryTheBoundaryForces()
    {
        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        IReadOnlyList<AppendixBStep> steps = AppendixBSteps();

        foreach (AppendixBStep step in steps.Take(3))
        {
            Assert.True(table.TryReadEncoderInstructions(step.Octets, out _, out _));
        }

        AppendixBStep beforeEviction = steps[2];
        AppendixBStep afterEviction = steps[3];

        int sizeBefore = table.Size;
        Assert.Equal(beforeEviction.Size, sizeBefore);
        Assert.Equal(0UL, table.DroppedCount);

        // The entry that is about to go, and the entry that is about to arrive, both sized
        // from the capture's rows by s3.2.1's rule rather than from the implementation.
        AppendixBRow oldest = beforeEviction.Rows[0];
        AppendixBRow arriving = afterEviction.Rows[^1];
        int oldestSize = RowSize(oldest);
        int arrivingSize = RowSize(arriving);

        // Eviction is forced...
        Assert.True(sizeBefore > table.Capacity - arrivingSize);
        // ...and one eviction is enough.
        Assert.True(sizeBefore - oldestSize <= table.Capacity - arrivingSize);

        Assert.True(table.TryReadEncoderInstructions(afterEviction.Octets, out _, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);

        // Exactly one entry left, and it was the OLDEST - s3.2.2's "evicted from the end of
        // the dynamic table", which s3.2.5's figure puts at the low absolute index. A mutant
        // that evicted from the insertion point instead would drop the duplicate at absolute
        // index 3 and leave 0 in place, and the capture's rows say otherwise.
        Assert.Equal(1UL, table.DroppedCount);
        Assert.Equal(0UL, oldest.Absolute);
        Assert.False(table.TryLookupAbsolute(oldest.Absolute, out _, out _, out TlsQuicQpackEncoderStreamError gone));
        Assert.Equal(TlsQuicQpackEncoderStreamError.IndexOutOfRange, gone);
        Assert.Equal(afterEviction.Rows[0].Absolute, table.DroppedCount);

        Assert.Equal(sizeBefore - oldestSize + arrivingSize, table.Size);
        Assert.Equal(afterEviction.Size, table.Size);
    }

    // The capture prints a Size line for each state, and the rows it prints alongside imply a
    // size of their own under s3.2.1. Deriving the number a second way and requiring the two
    // to agree is what makes the Size assertions in the walk mean something: a Size line
    // copied wrongly into the extract, or a row copied wrongly, would show up here as the two
    // derivations disagreeing rather than as a silently wrong expectation.
    [Fact]
    public void EveryPublishedSizeIsTheSumOfItsPublishedRows()
    {
        IReadOnlyList<AppendixBStep> steps = AppendixBSteps();
        Assert.NotEmpty(steps);

        foreach (AppendixBStep step in steps)
        {
            Assert.NotEmpty(step.Rows);
            Assert.Equal(step.Size, step.Rows.Sum(RowSize));
        }
    }

    // ========================================================================
    // CAPTURE-ANCHORED: s3.2.4, s3.2.5, s3.2.6 - a witness per indexing mode
    // ========================================================================
    //
    // Appendix B writes its index arithmetic out longhand in three distinct shapes, one per
    // mode, and each is parsed here and used to drive the resolver it belongs to. This is the
    // strongest oracle available for indexing: the two relative modes SUBTRACT and the
    // post-base mode ADDS, so a mutant that swaps an operator, or that routes one mode
    // through another's resolver, contradicts a sentence in the file.

    // s3.2.5, encoder-instruction flavour: "Insert Count(n) - Index(i) - 1 = a".
    [Fact]
    public void EveryEncoderRelativeArithmeticInTheCaptureResolves()
    {
        MatchCollection matches = Regex.Matches(
            AppendixBText(),
            @"Insert Count\((?<count>\d+)\)\s*-\s*Index\((?<index>\d+)\)\s*-\s*1\s*=\s*(?<absolute>\d+)");
        Assert.NotEmpty(matches);

        foreach (Match match in matches)
        {
            ulong count = ulong.Parse(match.Groups["count"].Value);
            ulong index = ulong.Parse(match.Groups["index"].Value);
            ulong expected = ulong.Parse(match.Groups["absolute"].Value);

            // Driven through a table wound forward to the capture's Insert Count, because
            // s3.2.5 says the answer depends on it: "the entry referenced by a given relative
            // index will change while interpreting instructions on the encoder stream".
            TlsQuicQpackDynamicTable table = TableWithInsertCount(count);
            Assert.Equal(count, table.InsertCount);
            Assert.True(table.TryResolveEncoderRelative(index, out ulong absolute, out TlsQuicQpackEncoderStreamError error));
            Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
            Assert.Equal(expected, absolute);
        }
    }

    // s3.2.5, field-line-representation flavour: "Base(b) - Index(i) - 1 = a". A DIFFERENT
    // function from the one above - the RFC gives them the same name and different origins -
    // and it must not consult InsertCount at all, which is why the table here is left empty.
    [Fact]
    public void EveryFieldRelativeArithmeticInTheCaptureResolves()
    {
        MatchCollection matches = Regex.Matches(
            AppendixBText(),
            @"Base\((?<base>\d+)\)\s*-\s*Index\((?<index>\d+)\)\s*-\s*1\s*=\s*(?<absolute>\d+)");
        Assert.NotEmpty(matches);

        var empty = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        foreach (Match match in matches)
        {
            ulong baseValue = ulong.Parse(match.Groups["base"].Value);
            ulong index = ulong.Parse(match.Groups["index"].Value);
            ulong expected = ulong.Parse(match.Groups["absolute"].Value);

            Assert.True(empty.TryResolveFieldRelative(baseValue, index, out ulong absolute, out TlsQuicQpackEncoderStreamError error));
            Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
            Assert.Equal(expected, absolute);
        }
    }

    // s3.2.6: "Base(b) + Index(i) = a". The one mode that adds.
    [Fact]
    public void EveryPostBaseArithmeticInTheCaptureResolves()
    {
        MatchCollection matches = Regex.Matches(
            AppendixBText(),
            @"Base\((?<base>\d+)\)\s*\+\s*Index\((?<index>\d+)\)\s*=\s*(?<absolute>\d+)");
        Assert.NotEmpty(matches);

        var empty = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        foreach (Match match in matches)
        {
            ulong baseValue = ulong.Parse(match.Groups["base"].Value);
            ulong index = ulong.Parse(match.Groups["index"].Value);
            ulong expected = ulong.Parse(match.Groups["absolute"].Value);

            Assert.True(empty.TryResolvePostBase(baseValue, index, out ulong absolute, out TlsQuicQpackEncoderStreamError error));
            Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
            Assert.Equal(expected, absolute);
        }
    }

    // The three modes disagree with each other on the same inputs, which is what makes the
    // three tests above three tests rather than one repeated. Pinned so that a mutant that
    // aliased two of the resolvers onto one implementation cannot pass all three by luck.
    [Fact]
    public void TheThreeIndexingModesDisagreeOnTheSameInputs()
    {
        TlsQuicQpackDynamicTable table = TableWithInsertCount(4);

        Assert.True(table.TryResolveEncoderRelative(1, out ulong encoderRelative, out _));
        Assert.True(table.TryResolveFieldRelative(2, 1, out ulong fieldRelative, out _));
        Assert.True(table.TryResolvePostBase(2, 1, out ulong postBase, out _));

        // s3.2.5 encoder: 4 - 1 - 1 = 2. s3.2.5 representation: 2 - 1 - 1 = 0. s3.2.6: 2 + 1 = 3.
        Assert.Equal(2UL, encoderRelative);
        Assert.Equal(0UL, fieldRelative);
        Assert.Equal(3UL, postBase);
        Assert.Equal(3, new[] { encoderRelative, fieldRelative, postBase }.Distinct().Count());
    }

    // The LOWER boundary of the field-section relative index, which the capture's worked
    // examples never reach because none of them sits at it.
    //
    // s3.2.5: "a relative index of 0 refers to the entry with absolute index equal to
    // Base - 1", so with Base = b the legal relative indices are 0 through b-1 and b itself
    // would name absolute index -1. There are no negative absolute indices, and in ulong the
    // subtraction does not go negative - it wraps to 2^64-1, which is a perfectly ordinary
    // -looking index that no bounds check downstream would question. The rejection has to
    // happen here.
    //
    // Written for the sweep's row 29, which flipped this bound from `>=` to `>` and survived
    // unwitnessed.
    [Theory]
    [InlineData(1UL)]
    [InlineData(2UL)]
    [InlineData(4UL)]
    [InlineData(220UL)]
    public void AFieldRelativeIndexAtTheBaseIsRejectedRatherThanWrapped(ulong baseValue)
    {
        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);

        // The last legal one resolves to absolute 0.
        Assert.True(table.TryResolveFieldRelative(baseValue, baseValue - 1, out ulong lowest, out _));
        Assert.Equal(0UL, lowest);

        // One past it is rejected, and the out value stays at 0 rather than carrying the
        // wrapped 2^64-1 out to a caller that only checked the return value.
        Assert.False(table.TryResolveFieldRelative(baseValue, baseValue, out ulong wrapped, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.IndexOutOfRange, error);
        Assert.Equal(0UL, wrapped);

        Assert.False(table.TryResolveFieldRelative(baseValue, ulong.MaxValue, out _, out _));
    }

    // Base = 0 is the case a field section that uses no dynamic entry actually sends, and at
    // Base 0 there is no legal relative index at all.
    [Fact]
    public void AtBaseZeroNoFieldRelativeIndexResolves()
    {
        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.False(table.TryResolveFieldRelative(0, 0, out _, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.IndexOutOfRange, error);
    }

    // s3.2.4: absolute indices are "fixed for the lifetime of that entry", so after B.5 drops
    // absolute 0 the SURVIVING entries keep the indices they were given - they do not shuffle
    // down. The capture's B.5 rows start at 1 for exactly that reason, and this walks every
    // row of every step back out by absolute index.
    [Fact]
    public void EveryPublishedRowIsReachableByItsAbsoluteIndex()
    {
        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        int checkedRows = 0;

        foreach (AppendixBStep step in AppendixBSteps())
        {
            Assert.True(table.TryReadEncoderInstructions(step.Octets, out _, out _));

            foreach (AppendixBRow row in step.Rows)
            {
                Assert.True(
                    table.TryLookupAbsolute(row.Absolute, out ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value, out _),
                    $"{step.Label} absolute index {row.Absolute} did not resolve.");
                Assert.Equal(row.Name, Encoding.ASCII.GetString(name));
                Assert.Equal(row.Value, Encoding.ASCII.GetString(value));
                checkedRows++;
            }

            // One past the insertion point and one below the dropping point are both absent.
            Assert.False(table.TryLookupAbsolute(table.InsertCount, out _, out _, out _));
            if (table.DroppedCount != 0)
            {
                Assert.False(table.TryLookupAbsolute(table.DroppedCount - 1, out _, out _, out _));
            }
        }

        // 2 + 3 + 4 + 4 rows across the four steps. Asserted so that a parser that returned
        // empty row lists could not make the loop above vacuous.
        Assert.Equal(13, checkedRows);
    }

    // ========================================================================
    // CAPTURE-ANCHORED: s4.3.1's ceiling and s6's error code
    // ========================================================================

    // The code is read out of the capture, not typed here. s6's body line is
    // "QPACK_ENCODER_STREAM_ERROR (0x0201):  The decoder failed to interpret an encoder
    // instruction received on the encoder stream."
    [Fact]
    public void TheEncoderStreamErrorCodeIsTheOneTheCaptureNames()
    {
        string capture = File.ReadAllText(
            QpackCaptures.Path("rfc9204-section5-6-configuration-and-error-handling.txt"));
        Match match = Regex.Match(capture, @"QPACK_ENCODER_STREAM_ERROR \(0x(?<code>[0-9a-fA-F]{4})\)");
        Assert.True(match.Success, "s6's QPACK_ENCODER_STREAM_ERROR definition not found in the capture.");

        ulong published = Convert.ToUInt64(match.Groups["code"].Value, 16);
        Assert.Equal(TlsQuicQpackDynamicTable.QpackEncoderStreamError, published);

        // And it is the code every fault on this stream maps to. s6 gives the encoder stream
        // its own code precisely so that it is NOT QPACK_DECOMPRESSION_FAILED, the code
        // TlsQuicQpackDecoder uses for a field section.
        Assert.NotEqual(TlsQuicQpackDecoder.QpackDecompressionFailed, published);
    }

    // Which members are connection errors and which are not, over the WHOLE enum rather than
    // over the members that happen to arise in the tests above.
    //
    // NeedMoreData is the one that matters and the one a sweep catches: it never escapes
    // TryReadEncoderInstructions, which converts it to None and returns true, so nothing else
    // in this file ever passes it to TryGetHttp3ErrorCode. That made the sweep's row 41 - which
    // dropped NeedMoreData from the exclusion - survive unwitnessed. A caller that resolves a
    // fault itself, as task C15's stream wiring will, would be turning a half-arrived
    // instruction into a closed connection.
    [Fact]
    public void OnlyRealFaultsMapToAConnectionErrorCode()
    {
        TlsQuicQpackEncoderStreamError[] notErrors =
        [
            TlsQuicQpackEncoderStreamError.None,
            TlsQuicQpackEncoderStreamError.NeedMoreData,
        ];

        foreach (TlsQuicQpackEncoderStreamError error in Enum.GetValues<TlsQuicQpackEncoderStreamError>())
        {
            bool isFault = TlsQuicQpackDynamicTable.TryGetHttp3ErrorCode(error, out ulong code);
            Assert.Equal(!notErrors.Contains(error), isFault);
            if (isFault)
            {
                Assert.Equal(TlsQuicQpackDynamicTable.QpackEncoderStreamError, code);
            }
        }

        // The enum really does have both kinds in it, so neither half of the loop is vacuous.
        Assert.Equal(2, notErrors.Length);
        Assert.True(Enum.GetValues<TlsQuicQpackEncoderStreamError>().Length > notErrors.Length);
    }

    // s4.3.1: "The decoder MUST treat a new dynamic table capacity value that exceeds this
    // limit as a connection error of type QPACK_ENCODER_STREAM_ERROR."
    //
    // THE STRADDLE: the limit itself is accepted and the limit plus one is rejected, on the
    // same table, so a mutant using > where >= belongs (or the reverse) fails one half.
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(220)]
    [InlineData(65536)]
    public void ACapacityAtTheAdvertisedMaximumIsAcceptedAndOneAboveItIsRejected(int maximum)
    {
        var table = new TlsQuicQpackDynamicTable(maximum);
        Assert.Equal(maximum, table.MaximumCapacity);

        Assert.True(table.TryReadEncoderInstructions(
            SetCapacity((ulong)maximum),
            out _,
            out TlsQuicQpackEncoderStreamError atLimit));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, atLimit);
        Assert.Equal(maximum, table.Capacity);

        Assert.False(table.TryReadEncoderInstructions(
            SetCapacity((ulong)maximum + 1),
            out _,
            out TlsQuicQpackEncoderStreamError above));
        Assert.Equal(TlsQuicQpackEncoderStreamError.CapacityAboveMaximum, above);

        // The rejection names the code, and the capacity is left where it was rather than
        // half-applied.
        Assert.True(TlsQuicQpackDynamicTable.TryGetHttp3ErrorCode(above, out ulong code));
        Assert.Equal(TlsQuicQpackDynamicTable.QpackEncoderStreamError, code);
        Assert.Equal(maximum, table.Capacity);
    }

    // The ceiling holds at the far end of s4.1.1's integer range too, where a narrowing
    // conversion is what would break it: 2^62-1 fits a ulong and does not fit an int, and a
    // comparison made after the narrowing would see a small - or negative - number and let it
    // through. TrySetCapacity compares in ulong before narrowing for this reason.
    [Fact]
    public void ACapacityNearTheSixtyTwoBitCeilingIsRejectedRatherThanNarrowed()
    {
        var table = new TlsQuicQpackDynamicTable(65536);

        foreach (ulong capacity in new ulong[] { int.MaxValue, (1UL << 32), (1UL << 62) - 1 })
        {
            Assert.False(table.TryReadEncoderInstructions(SetCapacity(capacity), out _, out TlsQuicQpackEncoderStreamError error));
            Assert.Equal(TlsQuicQpackEncoderStreamError.CapacityAboveMaximum, error);
            Assert.Equal(0, table.Capacity);
        }
    }

    // ========================================================================
    // CAPTURE-ANCHORED: s3.2.2's evictability rule, both instructions
    // ========================================================================

    // s3.2.2: "The encoder MUST NOT cause a dynamic table entry to be evicted unless that
    // entry is evictable; see Section 2.1.1."
    //
    // THE STRADDLE: this is B.5, the one insertion in the published example that evicts, run
    // twice against the same B.4 state. With no reference outstanding it succeeds and drops
    // absolute index 0; with a reference on absolute index 0 it is rejected and the table is
    // untouched. The two runs differ in exactly one bit of state, so the test cannot pass
    // vacuously on a table that never reaches capacity - the same bytes reach capacity in
    // both runs.
    [Fact]
    public void TheInsertionThatEvictsIsRejectedWhileTheDoomedEntryIsReferenced()
    {
        IReadOnlyList<AppendixBStep> steps = AppendixBSteps();
        AppendixBStep eviction = steps[3];
        ulong doomed = steps[2].Rows[0].Absolute;

        TlsQuicQpackDynamicTable held = WalkThrough(steps, 3);
        Assert.True(held.TryAddReference(doomed, out TlsQuicQpackEncoderStreamError referenced));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, referenced);
        Assert.Equal(1, held.ReferenceCountAt(doomed));

        int sizeBefore = held.Size;
        ulong insertCountBefore = held.InsertCount;

        Assert.False(held.TryReadEncoderInstructions(eviction.Octets, out int consumed, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.EvictionOfReferencedEntry, error);
        Assert.True(TlsQuicQpackDynamicTable.TryGetHttp3ErrorCode(error, out ulong code));
        Assert.Equal(TlsQuicQpackDynamicTable.QpackEncoderStreamError, code);

        // Nothing was half-done: no eviction, no insertion, no consumed octets.
        Assert.Equal(0, consumed);
        Assert.Equal(sizeBefore, held.Size);
        Assert.Equal(insertCountBefore, held.InsertCount);
        Assert.Equal(0UL, held.DroppedCount);
        Assert.True(held.TryLookupAbsolute(doomed, out _, out _, out _));

        // Released, the very same bytes are accepted - so the rejection was about the
        // reference and not about the instruction.
        held.ReleaseReference(doomed);
        Assert.Equal(0, held.ReferenceCountAt(doomed));
        Assert.True(held.TryReadEncoderInstructions(eviction.Octets, out _, out TlsQuicQpackEncoderStreamError after));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, after);
        Assert.Equal(1UL, held.DroppedCount);
        Assert.Equal(eviction.Size, held.Size);

        // And the unreferenced run, for the other half of the straddle.
        TlsQuicQpackDynamicTable free = WalkThrough(steps, 3);
        Assert.True(free.TryReadEncoderInstructions(eviction.Octets, out _, out _));
        Assert.Equal(1UL, free.DroppedCount);
    }

    // s4.3.1 puts the same rule on a capacity REDUCTION: "Reducing the dynamic table capacity
    // can cause entries to be evicted ... This MUST NOT cause the eviction of entries that are
    // not evictable". A table that enforced evictability only on insert would pass every test
    // above and drop a referenced entry here.
    //
    // THE STRADDLE: the reduction is to a capacity that is strictly below the current size,
    // so it FORCES an eviction - a reduction that changed nothing would witness nothing.
    [Fact]
    public void ACapacityReductionIsRejectedWhileTheDoomedEntryIsReferenced()
    {
        IReadOnlyList<AppendixBStep> steps = AppendixBSteps();
        TlsQuicQpackDynamicTable table = WalkThrough(steps, 3);
        ulong oldest = steps[2].Rows[0].Absolute;

        // Reduce to just under the current size, which is the smallest reduction that must
        // evict at all: size - 1 < size, so the oldest entry has to go.
        ulong reduced = (ulong)table.Size - 1;
        Assert.True(reduced < (ulong)table.Size);

        Assert.True(table.TryAddReference(oldest, out _));
        Assert.False(table.TryReadEncoderInstructions(SetCapacity(reduced), out _, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.EvictionOfReferencedEntry, error);
        Assert.Equal(steps[2].Size, table.Size);
        Assert.Equal(0UL, table.DroppedCount);

        table.ReleaseReference(oldest);
        Assert.True(table.TryReadEncoderInstructions(SetCapacity(reduced), out _, out TlsQuicQpackEncoderStreamError released));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, released);
        Assert.Equal(1UL, table.DroppedCount);
        Assert.True((ulong)table.Size <= reduced);
    }

    // The reference check has to scan the WHOLE eviction run, not just its head. A table that
    // looked only at the oldest entry would pass every other reference test in this file,
    // because in all of them the referenced entry happens to be the first one eviction
    // reaches.
    //
    // THE STRADDLE, arithmetic from the capture's own rows: after B.5 the table holds
    // 49 + 54 + 57 + 55 = 215 under a capacity of 220. An arriving entry of 60 bytes needs the
    // size down to 220 - 60 = 160. Evicting the oldest (49) leaves 166, still above 160, so a
    // SECOND eviction is forced; evicting the next (54) leaves 112, which is under. So the run
    // is exactly two entries long and the entry that is referenced here is the second of them.
    // A head-only check sees an unreferenced first entry, evicts it, and proceeds.
    [Fact]
    public void AReferenceOnTheSecondEntryOfTheEvictionRunIsAlsoRespected()
    {
        IReadOnlyList<AppendixBStep> steps = AppendixBSteps();
        TlsQuicQpackDynamicTable table = WalkThrough(steps, 4);

        AppendixBStep afterEviction = steps[3];
        ulong first = afterEviction.Rows[0].Absolute;
        ulong second = afterEviction.Rows[1].Absolute;
        int firstSize = RowSize(afterEviction.Rows[0]);
        int secondSize = RowSize(afterEviction.Rows[1]);

        // An entry sized so that the run is two long: static name index 0 plus a value chosen
        // to land the total between the one-eviction and two-eviction boundaries.
        // One byte past the size at which a single eviction would suffice, which is the
        // smallest entry that forces the run to reach the second one.
        int nameLength = TlsQuicQpackStaticTable.NameAt(0).Length;
        int arriving = table.Capacity - (table.Size - firstSize) + 1;
        Assert.InRange(arriving, 1, table.Capacity - (table.Size - firstSize - secondSize));

        int valueLength = arriving - nameLength - TlsQuicQpackDynamicTable.EntrySizeOverhead;
        Assert.True(valueLength > 0, $"the forced entry size {arriving} leaves no room for a value.");

        // One eviction is not enough...
        Assert.True(table.Size - firstSize > table.Capacity - arriving);
        // ...and two are.
        Assert.True(table.Size - firstSize - secondSize <= table.Capacity - arriving);

        byte[] instruction = InsertWithStaticName(0, new byte[valueLength]);
        Assert.Equal(0, table.ReferenceCountAt(first));
        Assert.True(table.TryAddReference(second, out _));

        int sizeBefore = table.Size;
        ulong insertsBefore = table.InsertCount;
        ulong droppedBefore = table.DroppedCount;
        Assert.False(table.TryReadEncoderInstructions(instruction, out _, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.EvictionOfReferencedEntry, error);

        // Nothing moved - in particular the UNREFERENCED first entry of the run is still
        // there, which is the assertion a head-only check fails.
        Assert.Equal(sizeBefore, table.Size);
        Assert.Equal(insertsBefore, table.InsertCount);
        Assert.Equal(droppedBefore, table.DroppedCount);
        Assert.True(table.TryLookupAbsolute(first, out _, out _, out _));
        Assert.True(table.TryLookupAbsolute(second, out _, out _, out _));

        // Released, the same instruction goes through and takes both.
        table.ReleaseReference(second);
        Assert.True(table.TryReadEncoderInstructions(instruction, out _, out TlsQuicQpackEncoderStreamError after));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, after);
        Assert.Equal(droppedBefore + 2, table.DroppedCount);
        Assert.False(table.TryLookupAbsolute(first, out _, out _, out _));
        Assert.False(table.TryLookupAbsolute(second, out _, out _, out _));
    }

    // s3.2.2's "This mechanism can be used to completely clear entries from the dynamic table
    // by setting a capacity of 0, which can subsequently be restored."
    [Fact]
    public void ACapacityOfZeroClearsTheTableAndCanBeRestored()
    {
        IReadOnlyList<AppendixBStep> steps = AppendixBSteps();
        TlsQuicQpackDynamicTable table = WalkThrough(steps, 4);
        ulong insertCountBefore = table.InsertCount;

        Assert.True(table.TryReadEncoderInstructions(SetCapacity(0), out _, out _));
        Assert.Equal(0, table.Size);
        Assert.Equal(0, table.Count);
        Assert.Equal(insertCountBefore, table.DroppedCount);

        // s3.2.4: absolute indices are fixed for the lifetime of an entry, and clearing the
        // table does not rewind the insertion point. The next insert takes the NEXT index.
        Assert.Equal(insertCountBefore, table.InsertCount);

        Assert.True(table.TryReadEncoderInstructions(SetCapacity(220), out _, out _));
        Assert.Equal(220, table.Capacity);
        Assert.Equal(0, table.Size);
    }

    // ========================================================================
    // CAPTURE-ANCHORED: s3.2.2's oversized entry
    // ========================================================================

    // s3.2.2: "It is an error if the encoder attempts to add an entry that is larger than the
    // dynamic table capacity". Checked against the CAPACITY rather than the free space, so it
    // fires on an EMPTY table where no eviction could ever make room.
    //
    // THE STRADDLE: B.3's literal-name entry costs 54 bytes under s3.2.1, so the capacity is
    // set to exactly 54 in one run and to 53 in the other. Same instruction, adjacent
    // capacities, opposite outcomes.
    [Fact]
    public void AnEntryLargerThanTheCapacityIsRejectedOnAnEmptyTable()
    {
        AppendixBStep speculative = AppendixBSteps()[1];
        AppendixBRow inserted = speculative.Rows[^1];
        int entrySize = RowSize(inserted);
        Assert.Equal(inserted.Name.Length + inserted.Value.Length + TlsQuicQpackDynamicTable.EntrySizeOverhead, entrySize);

        var fits = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.True(fits.TryReadEncoderInstructions(SetCapacity((ulong)entrySize), out _, out _));
        Assert.True(fits.TryReadEncoderInstructions(speculative.Octets, out _, out TlsQuicQpackEncoderStreamError ok));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, ok);
        Assert.Equal(entrySize, fits.Size);
        Assert.Equal(1, fits.Count);

        var tooSmall = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.True(tooSmall.TryReadEncoderInstructions(SetCapacity((ulong)entrySize - 1), out _, out _));
        Assert.False(tooSmall.TryReadEncoderInstructions(speculative.Octets, out int consumed, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.EntryLargerThanCapacity, error);
        Assert.Equal(0, consumed);
        Assert.Equal(0, tooSmall.Size);
        Assert.Equal(0, tooSmall.Count);
    }

    // s3.2.2: "The initial capacity of the dynamic table is zero. The encoder sends a Set
    // Dynamic Table Capacity instruction (Section 4.3.1) with a non-zero capacity to begin
    // using the dynamic table." So an insert that arrives BEFORE any capacity instruction is
    // the oversized case, and needs no separate rule.
    [Fact]
    public void AnInsertBeforeAnyCapacityInstructionIsRejected()
    {
        AppendixBStep speculative = AppendixBSteps()[1];
        var table = new TlsQuicQpackDynamicTable(65536);

        Assert.Equal(0, table.Capacity);
        Assert.False(table.TryReadEncoderInstructions(speculative.Octets, out _, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.EntryLargerThanCapacity, error);
        Assert.Equal(0UL, table.InsertCount);
    }

    // ========================================================================
    // SELF-DERIVED: s4.3's opcode prefix tree
    // ========================================================================

    // s4.3's four opcodes have three different prefix lengths, so recognising them is a walk
    // down a prefix tree and not a mask-and-switch, and the ORDER of the tests is
    // load-bearing. This sweeps all 256 possible first octets and asserts the one property
    // that holds whether or not the rest of the instruction turns out to be well formed:
    //
    //   ONLY 001xxxxx MAY CHANGE THE CAPACITY, AND 001xxxxx MAY NEVER INSERT.
    //
    // Stating it that way rather than "each octet must succeed as its own opcode" is what
    // makes the sweep possible at all. A first octet does not determine a valid instruction -
    // 0x5F is s4.3.3 with a Huffman name 31 octets long, which the padding here cannot
    // satisfy - so an outcome-based sweep would be asserting well-formedness, not
    // classification. Capacity and InsertCount are the two effects that are unique to
    // disjoint halves of the tree, so they classify without requiring success.
    //
    // Every reordering mutant of the dispatch chain shows up here: hoisting the 001 test
    // above the 01 test routes 0x60-0x7F into Set Dynamic Table Capacity, and above the
    // 1 test routes 0xA0-0xBF and 0xE0-0xFF there too. Both change a capacity that the tree
    // says must not change.
    [Fact]
    public void OnlyTheSetCapacityBranchOfThePrefixTreeMayChangeTheCapacity()
    {
        // Enough trailing zero octets that a short instruction always completes, without
        // pretending that every one of them does.
        byte[] padding = new byte[64];
        int capacityChanges = 0;
        int insertions = 0;

        for (int first = 0; first <= 0xFF; first++)
        {
            // A table with one entry and ample capacity, so that every opcode has something
            // legal to reach for and the sweep is not confounded by an empty table.
            var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
            Assert.True(table.TryReadEncoderInstructions(SetCapacity(1024), out _, out _));
            Assert.True(table.TryReadEncoderInstructions(AppendixBSteps()[1].Octets, out _, out _));
            ulong insertsBefore = table.InsertCount;

            byte[] octets = [(byte)first, .. padding];
            table.TryReadEncoderInstructions(octets, out _, out _);

            bool inserted = table.InsertCount != insertsBefore;
            bool capacityChanged = table.Capacity != 1024;
            bool isSetCapacity = (first & 0xE0) == 0x20;

            if (isSetCapacity)
            {
                Assert.True(capacityChanged, $"0x{first:x2} is 001xxxxx and must set the capacity.");
                Assert.False(inserted, $"0x{first:x2} is 001xxxxx and must not insert.");
                capacityChanges++;
            }
            else
            {
                Assert.False(capacityChanged, $"0x{first:x2} is not 001xxxxx and must not touch the capacity.");
                insertions += inserted ? 1 : 0;
            }
        }

        // 32 octets carry the '001' pattern, and every one of them changed the capacity.
        Assert.Equal(32, capacityChanges);

        // And the other three quarters really do reach an insert path, so the second half of
        // the assertion above is not vacuously true of a sweep that never inserted anything.
        Assert.True(insertions > 0, "no first octet outside 001xxxxx ever reached an insert.");
    }

    // The other half of the dispatch order, which the capacity sweep cannot see: 0xC0 sets
    // BOTH the s4.3.2 bit and the s4.3.3 bit, so a mutant that tested '01' before '1' would
    // read it as an Insert With Literal Name with an empty name rather than as an Insert With
    // Name Reference to static index 0. Both insert, both leave the capacity alone, and only
    // the resulting NAME tells them apart.
    //
    // The expected name is s3.1's static entry 0, taken from the static table rather than
    // spelled here - and B.2's own annotation says that is what `c0` means.
    [Fact]
    public void AnOctetSettingBothInsertBitsIsReadAsTheNameReference()
    {
        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.True(table.TryReadEncoderInstructions(SetCapacity(1024), out _, out _));

        // s4.3.2, T=1, static index 0, empty value: `c0 00`.
        Assert.True(table.TryReadEncoderInstructions([0xC0, 0x00], out int consumed, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
        Assert.Equal(2, consumed);

        Assert.True(table.TryLookupAbsolute(0, out ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value, out _));
        Assert.Equal(TlsQuicQpackStaticTable.NameAt(0), Encoding.ASCII.GetString(name));
        Assert.Empty(value.ToArray());

        // Read as s4.3.3 instead it would be an empty name, which is what the misordered
        // mutant produces - and s3.1's entry 0 is not the empty string.
        Assert.NotEmpty(TlsQuicQpackStaticTable.NameAt(0));

        // And static index 0 is the name B.2's first insert produces, so the two octets here
        // are the same shape the capture annotates as "Static Table, Index=0". Taken from the
        // capture's own first row rather than spelled out, like everything else in this file.
        Assert.Equal(AppendixBSteps()[0].Rows[0].Name, TlsQuicQpackStaticTable.NameAt(0));
    }

    // s4.3.4: "The existing entry is reinserted into the dynamic table without resending
    // either the name or the value." B.4 is the published case; this is the harder one
    // s3.2.2 warns about - "A new entry can reference an entry in the dynamic table that will
    // be evicted when adding this new entry into the dynamic table. Implementations are
    // cautioned to avoid deleting the referenced name or value if the referenced entry is
    // evicted from the dynamic table prior to inserting the new entry."
    //
    // THE STRADDLE: the capacity is set to exactly one entry's worth, so duplicating the only
    // entry MUST evict the very entry being duplicated. A capacity with room to spare would
    // witness nothing.
    [Fact]
    public void DuplicatingTheOnlyEntryEvictsItAndKeepsItsBytes()
    {
        AppendixBStep speculative = AppendixBSteps()[1];
        AppendixBRow row = speculative.Rows[^1];
        int entrySize = RowSize(row);

        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.True(table.TryReadEncoderInstructions(SetCapacity((ulong)entrySize), out _, out _));
        Assert.True(table.TryReadEncoderInstructions(speculative.Octets, out _, out _));
        Assert.Equal(1, table.Count);

        // s4.3.4 Duplicate, relative index 0 - the most recently inserted entry, which here
        // is also the oldest and so is the one eviction will take.
        Assert.True(table.TryReadEncoderInstructions([0x00], out int consumed, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
        Assert.Equal(1, consumed);

        Assert.Equal(1, table.Count);
        Assert.Equal(1UL, table.DroppedCount);
        Assert.Equal(2UL, table.InsertCount);
        Assert.Equal(entrySize, table.Size);

        // The duplicate's bytes survived its source's eviction.
        Assert.True(table.TryLookupAbsolute(1, out ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value, out _));
        Assert.Equal(row.Name, Encoding.ASCII.GetString(name));
        Assert.Equal(row.Value, Encoding.ASCII.GetString(value));
    }

    // EVERY LITERAL IN APPENDIX B IS TOO SHORT TO PIN ITS OWN PREFIX WIDTH, and the sweep
    // said so: rows 5, 6 and 7 narrowed a prefix by one bit each and all three survived the
    // whole capture-anchored walk.
    //
    // The reason is arithmetic, not oversight. B.3's name is 10 bytes and `10 & 0x1F` equals
    // `10 & 0x0F`; B.2's value is 15 bytes and `15 & 0x7F` equals `15 & 0x3F`; B.4's Duplicate
    // index is 2 and `2 & 0x1F` equals `2 & 0x3F`. A value below the NARROWER mask decodes
    // identically at both widths, and every published value is. The H bit moves too, and at
    // these values it is clear either way.
    //
    // THE STRADDLE: each of these picks a value that is at or above the narrower mask, so the
    // two widths disagree. They are built through TlsQuicQpackPrimitives rather than
    // hand-assembled, so the test cannot encode something the project's own codec would not.
    [Fact]
    public void ALiteralNameAtTheSixBitPrefixBoundaryIsNotReadAtFiveBits()
    {
        // Name length 16. At s4.3.3's correct 6-bit prefix the H bit is bit 5 and is clear,
        // and the length occupies the low 5 bits. Read at a 5-bit prefix the H bit would be
        // bit 4 - which the value 16 sets - so the mutant sees a Huffman name of length 0.
        byte[] name = Encoding.ASCII.GetBytes(new string('n', 16));
        Assert.Equal(0x10, name.Length);

        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.True(table.TryReadEncoderInstructions(SetCapacity(1024), out _, out _));
        Assert.True(table.TryReadEncoderInstructions(InsertWithLiteralName(name, []), out _, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);

        Assert.True(table.TryLookupAbsolute(0, out ReadOnlySpan<byte> stored, out _, out _));
        Assert.Equal(name, stored.ToArray());
        Assert.Equal(name.Length + TlsQuicQpackDynamicTable.EntrySizeOverhead, table.Size);
    }

    [Fact]
    public void AValueAtTheEightBitPrefixBoundaryIsNotReadAtSevenBits()
    {
        // Value length 64. At s4.3.2/4.3.3's correct 8-bit prefix the H bit is bit 7 and is
        // clear, and 64 fits the 7-bit length. Read at a 7-bit prefix the H bit would be
        // bit 6 - which 64 sets - so the mutant sees a Huffman value of length 0.
        byte[] value = Encoding.ASCII.GetBytes(new string('v', 64));
        Assert.Equal(0x40, value.Length);

        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.True(table.TryReadEncoderInstructions(SetCapacity(1024), out _, out _));
        Assert.True(table.TryReadEncoderInstructions(InsertWithStaticName(0, value), out _, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);

        Assert.True(table.TryLookupAbsolute(0, out _, out ReadOnlySpan<byte> stored, out _));
        Assert.Equal(value, stored.ToArray());
        Assert.Equal(
            TlsQuicQpackStaticTable.NameAt(0).Length + value.Length + TlsQuicQpackDynamicTable.EntrySizeOverhead,
            table.Size);
    }

    [Fact]
    public void ADuplicateIndexAtTheFiveBitPrefixBoundaryIsNotReadAtSixBits()
    {
        // A Duplicate whose relative index is 32: at s4.3.4's correct 5-bit prefix that fills
        // the prefix (31) and spills into a continuation octet, two octets in all. Read at a
        // 6-bit prefix, 31 does not fill and the instruction is one octet long meaning 31 -
        // so the mutant both resolves a different entry AND leaves the continuation octet to
        // be misread as a second Duplicate.
        const int entries = 33;
        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.True(table.TryReadEncoderInstructions(SetCapacity(4096), out _, out _));

        // Distinct static names, so that which entry got duplicated is visible in the bytes.
        for (int i = 0; i < entries; i++)
        {
            Assert.True(table.TryReadEncoderInstructions(InsertWithStaticName((ulong)i, []), out _, out _));
        }

        Assert.Equal((ulong)entries, table.InsertCount);
        byte[] instruction = Duplicate(32);
        Assert.Equal(2, instruction.Length);

        Assert.True(table.TryReadEncoderInstructions(instruction, out int consumed, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
        Assert.Equal(2, consumed);
        Assert.Equal((ulong)entries + 1, table.InsertCount);

        // s3.2.5: absolute = Insert Count(33) - Index(32) - 1 = 0, whose name is static 0.
        // At a 6-bit prefix the mutant reads 31, giving 33 - 31 - 1 = 1, whose name is
        // static 1 - and s3.1's entries 0 and 1 are different names.
        Assert.True(table.TryLookupAbsolute((ulong)entries, out ReadOnlySpan<byte> stored, out _, out _));
        Assert.Equal(TlsQuicQpackStaticTable.NameAt(0), Encoding.ASCII.GetString(stored));
        Assert.NotEqual(TlsQuicQpackStaticTable.NameAt(0), TlsQuicQpackStaticTable.NameAt(1));
    }

    // s3.2.5's "the entry referenced by a given relative index will change while interpreting
    // instructions on the encoder stream", exercised where it bites: a relative index at or
    // past the insertion point resolves to nothing.
    [Fact]
    public void ARelativeIndexPastTheInsertionPointIsRejected()
    {
        IReadOnlyList<AppendixBStep> steps = AppendixBSteps();
        TlsQuicQpackDynamicTable table = WalkThrough(steps, 2);
        Assert.Equal(3UL, table.InsertCount);

        // Relative index 2 is the last legal one; 3 is one past.
        Assert.True(table.TryResolveEncoderRelative(2, out ulong oldest, out _));
        Assert.Equal(0UL, oldest);
        Assert.False(table.TryResolveEncoderRelative(3, out _, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.IndexOutOfRange, error);

        // And the same boundary reached through s4.3.4's Duplicate instruction, which is how
        // it arrives off the wire.
        Assert.True(table.TryReadEncoderInstructions([0x02], out _, out _));
        Assert.False(table.TryReadEncoderInstructions([0x04], out _, out TlsQuicQpackEncoderStreamError wire));
        Assert.Equal(TlsQuicQpackEncoderStreamError.IndexOutOfRange, wire);
    }

    // s4.3.2 with T=1 indexes s3.1's static table, which has 99 entries; index 99 is one past.
    [Fact]
    public void AStaticNameIndexPastTheStaticTableIsRejected()
    {
        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.True(table.TryReadEncoderInstructions(SetCapacity(1024), out _, out _));

        int last = TlsQuicQpackStaticTable.Count - 1;
        Assert.True(table.TryReadEncoderInstructions(InsertWithStaticName((ulong)last, []), out _, out TlsQuicQpackEncoderStreamError ok));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, ok);

        Assert.False(table.TryReadEncoderInstructions(
            InsertWithStaticName((ulong)TlsQuicQpackStaticTable.Count, []),
            out _,
            out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.IndexOutOfRange, error);
    }

    // ========================================================================
    // SELF-DERIVED: the stream boundary
    // ========================================================================

    // The encoder stream is a byte stream, so an instruction may be split across reads. Fed
    // one octet at a time, the walk must reach exactly the state it reaches when fed whole -
    // and every intermediate call must report success with a `consumed` that never runs ahead
    // of the complete instructions available.
    //
    // This is the test that gives `consumed` teeth. A mutant that reported the whole buffer
    // as consumed regardless would pass every state assertion in the whole-buffer walk and
    // desynchronise here at the first split instruction.
    [Fact]
    public void FeedingTheStreamOneOctetAtATimeReachesTheSameState()
    {
        IReadOnlyList<AppendixBStep> steps = AppendixBSteps();
        byte[] whole = [.. steps.SelectMany(s => s.Octets)];

        var reference = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.True(reference.TryReadEncoderInstructions(whole, out int wholeConsumed, out _));
        Assert.Equal(whole.Length, wholeConsumed);

        var dripped = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        List<byte> pending = [];
        int partialCalls = 0;

        foreach (byte octet in whole)
        {
            pending.Add(octet);
            byte[] buffer = [.. pending];
            Assert.True(dripped.TryReadEncoderInstructions(buffer, out int consumed, out TlsQuicQpackEncoderStreamError error));
            Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
            Assert.InRange(consumed, 0, buffer.Length);
            if (consumed < buffer.Length)
            {
                partialCalls++;
            }

            pending.RemoveRange(0, consumed);
        }

        Assert.Empty(pending);
        Assert.Equal(reference.InsertCount, dripped.InsertCount);
        Assert.Equal(reference.DroppedCount, dripped.DroppedCount);
        Assert.Equal(reference.Size, dripped.Size);
        Assert.Equal(reference.Capacity, dripped.Capacity);
        Assert.Equal(reference.Count, dripped.Count);

        // Multi-octet instructions really were split - otherwise this test would prove only
        // that a stream of single-octet instructions works.
        Assert.True(partialCalls > 0, "no instruction was ever split, so the boundary was never exercised.");
    }

    // ========================================================================
    // SELF-DERIVED: nothing on this path throws, for any input
    // ========================================================================

    // Every prefix of the published stream, at every length, including the ones that stop
    // inside an integer continuation chain and inside a string literal.
    [Fact]
    public void EveryTruncationOfThePublishedStreamIsHandledWithoutThrowing()
    {
        byte[] whole = [.. AppendixBSteps().SelectMany(s => s.Octets)];
        Assert.NotEmpty(whole);

        for (int length = 0; length <= whole.Length; length++)
        {
            var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
            bool accepted = table.TryReadEncoderInstructions(whole.AsSpan(0, length), out int consumed, out TlsQuicQpackEncoderStreamError error);
            Assert.True(accepted, $"prefix of length {length} was rejected with {error}.");
            Assert.InRange(consumed, 0, length);
        }
    }

    // Arbitrary bytes, on a table whose capacity is already live so that the insert paths are
    // reachable rather than being short-circuited by an empty capacity. Deterministic seed so
    // that a failure is reproducible.
    [Fact]
    public void ArbitraryEncoderStreamBytesNeverThrow()
    {
        var random = new Random(9204);
        int rejections = 0;
        int acceptances = 0;

        for (int trial = 0; trial < 4000; trial++)
        {
            var table = new TlsQuicQpackDynamicTable(4096);
            Assert.True(table.TryReadEncoderInstructions(SetCapacity(1024), out _, out _));

            byte[] octets = new byte[random.Next(1, 24)];
            random.NextBytes(octets);

            if (table.TryReadEncoderInstructions(octets, out int consumed, out TlsQuicQpackEncoderStreamError error))
            {
                Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
                Assert.InRange(consumed, 0, octets.Length);
                acceptances++;
            }
            else
            {
                Assert.NotEqual(TlsQuicQpackEncoderStreamError.None, error);
                Assert.NotEqual(TlsQuicQpackEncoderStreamError.NeedMoreData, error);
                Assert.True(TlsQuicQpackDynamicTable.TryGetHttp3ErrorCode(error, out ulong code));
                Assert.Equal(TlsQuicQpackDynamicTable.QpackEncoderStreamError, code);
                rejections++;
            }

            // Whatever happened, the table's own accounting still holds.
            Assert.InRange(table.Size, 0, table.Capacity);
            Assert.Equal(table.Count, (int)(table.InsertCount - table.DroppedCount));
        }

        // Both outcomes really occur. A fuzz that only ever rejected, or only ever accepted,
        // would be exercising one branch and claiming two.
        Assert.True(rejections > 0, "no random input was ever rejected.");
        Assert.True(acceptances > 0, "no random input was ever accepted.");
    }

    // ========================================================================
    // SELF-DERIVED: allocation
    // ========================================================================

    // The rejecting path allocates zero bytes, the same property
    // TlsQuicQpackDecoderTests.TheRejectingPathAllocatesZeroBytes pins for the field-section
    // decoder, and measured the same way rather than argued from the source. It is what
    // forces the size and evictability checks to run BEFORE the name and value are copied to
    // the heap: a table that copied first and validated second would be green on every other
    // test in this file and would let a peer make us allocate once per instruction it already
    // knows we will refuse.
    //
    // The accepting path is a different matter and DOES allocate - an entry has to be stored
    // somewhere - so this is not a claim that the table never allocates.
    [Fact]
    public void TheRejectingPathAllocatesZeroBytes()
    {
        AppendixBStep speculative = AppendixBSteps()[1];

        // A capacity strictly below B.3's 54-byte entry, so that the oversized-entry rejection
        // below really is one. Every vector here is asserted to reject at the end of the test,
        // because a vector that quietly succeeded would be measuring the accepting path.
        int capacity = RowSize(speculative.Rows[^1]) - 1;
        var table = new TlsQuicQpackDynamicTable(capacity);
        Assert.True(table.TryReadEncoderInstructions(SetCapacity((ulong)capacity), out _, out _));

        byte[][] rejects =
        [
            SetCapacity((ulong)capacity + 1),       // s4.3.1 above the advertised maximum
            speculative.Octets,                     // s3.2.2 entry larger than the capacity
            [0x00],                                 // s4.3.4 duplicate of an entry that is not there
            [0xFF, 0xFF, 0xFF, 0x00, 0x00],         // s4.3.2 static index far past the table
            [0x80, 0x00],                           // s4.3.2 dynamic relative index on an empty table
            [0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],   // s4.3.1 capacity near the 62-bit ceiling
        ];

        // Warm up, so that JIT allocation and the one-time growth of the scratch buffers are
        // not counted. Both are genuinely one-time: the buffers are never shrunk.
        for (int i = 0; i < 4; i++)
        {
            foreach (byte[] reject in rejects)
            {
                Assert.False(table.TryReadEncoderInstructions(reject, out _, out _));
            }
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100; i++)
        {
            foreach (byte[] reject in rejects)
            {
                table.TryReadEncoderInstructions(reject, out _, out _);
            }
        }

        Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);

        // And every one of those really was a rejection, so the measurement is not of a loop
        // that quietly succeeded six hundred times.
        foreach (byte[] reject in rejects)
        {
            Assert.False(table.TryReadEncoderInstructions(reject, out _, out TlsQuicQpackEncoderStreamError error));
            Assert.NotEqual(TlsQuicQpackEncoderStreamError.None, error);
        }

        Assert.Equal(0UL, table.InsertCount);
    }

    // The one member that does throw, and it throws on a value a caller chose rather than on
    // anything from the wire.
    [Fact]
    public void ANegativeMaximumCapacityIsACallerErrorAndThrows()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicQpackDynamicTable(-1));
        Assert.Equal(0, new TlsQuicQpackDynamicTable(0).MaximumCapacity);
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static int RowSize(AppendixBRow row) =>
        row.Name.Length + row.Value.Length + TlsQuicQpackDynamicTable.EntrySizeOverhead;

    private static void AssertTableMatches(TlsQuicQpackDynamicTable table, AppendixBStep step)
    {
        Assert.Equal(step.Size, table.Size);
        Assert.Equal(step.Rows.Count, table.Count);
        Assert.Equal(step.Rows[0].Absolute, table.DroppedCount);
        Assert.Equal(step.Rows[^1].Absolute + 1, table.InsertCount);

        foreach (AppendixBRow row in step.Rows)
        {
            Assert.True(
                table.TryLookupAbsolute(row.Absolute, out ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value, out _),
                $"{step.Label} absolute index {row.Absolute} did not resolve.");
            Assert.Equal(row.Name, Encoding.ASCII.GetString(name));
            Assert.Equal(row.Value, Encoding.ASCII.GetString(value));
        }
    }

    private static TlsQuicQpackDynamicTable WalkThrough(IReadOnlyList<AppendixBStep> steps, int count)
    {
        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        foreach (AppendixBStep step in steps.Take(count))
        {
            Assert.True(table.TryReadEncoderInstructions(step.Octets, out _, out TlsQuicQpackEncoderStreamError error));
            Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
        }

        return table;
    }

    // A table wound forward to a given InsertCount by inserting minimal entries, used by the
    // encoder-relative witness. Each entry is an empty-valued static name reference, so it
    // costs its name plus the 32-byte overhead and nothing else.
    private static TlsQuicQpackDynamicTable TableWithInsertCount(ulong count)
    {
        var table = new TlsQuicQpackDynamicTable(WalkMaximumCapacity);
        Assert.True(table.TryReadEncoderInstructions(SetCapacity(WalkMaximumCapacity), out _, out _));

        for (ulong i = 0; i < count; i++)
        {
            Assert.True(table.TryReadEncoderInstructions(InsertWithStaticName(0, []), out _, out TlsQuicQpackEncoderStreamError error));
            Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
        }

        return table;
    }

    // s4.3.1's instruction, built through the shared primitive rather than by hand, so that
    // these helpers cannot encode an instruction the decoder half of this project would
    // disagree with.
    private static byte[] SetCapacity(ulong capacity)
    {
        Span<byte> destination = stackalloc byte[TlsQuicQpackPrimitives.MaximumIntegerEncodedLength];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(capacity, 5, 0b0010_0000, destination, out int written));
        return destination[..written].ToArray();
    }

    // s4.3.2 with T = 1: '1', then '1', then a 6-bit prefix static index, then the value as an
    // 8-bit prefix string literal with H = 0.
    private static byte[] InsertWithStaticName(ulong index, byte[] value)
    {
        byte[] destination = new byte[value.Length + (2 * TlsQuicQpackPrimitives.MaximumIntegerEncodedLength)];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(index, 6, 0b1100_0000, destination, out int written));
        Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(value, 8, 0, huffman: false, destination.AsSpan(written), out int valueWritten));
        return destination[..(written + valueWritten)];
    }

    // s4.3.3 with both literals: '01', then the name as a 6-bit prefix string literal with
    // H = 0, then the value as an 8-bit prefix string literal with H = 0.
    private static byte[] InsertWithLiteralName(byte[] name, byte[] value)
    {
        byte[] destination = new byte[name.Length + value.Length + (2 * TlsQuicQpackPrimitives.MaximumIntegerEncodedLength)];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(name, 6, 0b0100_0000, huffman: false, destination, out int written));
        Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(value, 8, 0, huffman: false, destination.AsSpan(written), out int valueWritten));
        return destination[..(written + valueWritten)];
    }

    // s4.3.4: '000' then the relative index as a 5-bit prefix integer.
    private static byte[] Duplicate(ulong relativeIndex)
    {
        Span<byte> destination = stackalloc byte[TlsQuicQpackPrimitives.MaximumIntegerEncodedLength];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(relativeIndex, 5, 0, destination, out int written));
        return destination[..written].ToArray();
    }

    // ========================================================================
    // The Appendix B parser
    // ========================================================================

    private sealed record AppendixBRow(ulong Absolute, string Name, string Value);

    private sealed record AppendixBStep(string Label, byte[] Octets, IReadOnlyList<AppendixBRow> Rows, int Size);

    private static string AppendixBText() =>
        File.ReadAllText(QpackCaptures.Path("rfc9204-appendix-b-encoding-and-decoding-examples.txt"));

    private static string AppendixBSection(string label)
    {
        string capture = AppendixBText();
        int start = capture.IndexOf("\n" + label + ".", StringComparison.Ordinal);
        Assert.True(start >= 0, $"{label} not found in the capture.");

        string next = "B." + (int.Parse(label[2..]) + 1) + ".";
        int end = capture.IndexOf("\n" + next, start, StringComparison.Ordinal);
        return end < 0 ? capture[start..] : capture[start..end];
    }

    // A hex line is one that carries hex groups and then the annotation bar. Close to the
    // shape TlsQuicQpackEncoderTests.AppendixB1 uses, but NOT the same and not shared: that
    // one caps a group at four hex characters, and B.2 opens with `3fbd01`, a group of six.
    // A four-character cap does not merely mis-slice that line, it fails to match it at all
    // and silently drops it - and dropping it drops the Set Dynamic Table Capacity
    // instruction, leaving a capacity of 0 and turning the whole of B.2 into an
    // oversized-entry rejection. The cap is eight here, and ParseStep asserts that every
    // line of an encoder block either matched or carried no hex, so a wider group in some
    // future capture fails loudly instead of quietly.
    private static readonly Regex HexLine = new(
        @"^ +((?:[0-9a-f]{2,8} )*[0-9a-f]{2,8}) +\|",
        RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly Regex StateRow = new(
        @"^\s+(?<absolute>\d+)\s+(?<ref>\d+)\s+(?<name>\S+)\s+(?<value>\S+)\s*$",
        RegexOptions.Compiled);

    // Each of B.2-B.5 opens with a "Stream: Encoder" block followed by the table state that
    // block produces. Both are read out of the file; nothing here is remembered.
    private static IReadOnlyList<AppendixBStep> AppendixBSteps() =>
        [.. new[] { "B.2", "B.3", "B.4", "B.5" }.Select(ParseStep)];

    private static AppendixBStep ParseStep(string label)
    {
        string section = AppendixBSection(label);
        int encoder = section.IndexOf("Stream: Encoder", StringComparison.Ordinal);
        Assert.True(encoder >= 0, $"{label} has no encoder stream block.");

        string[] lines = section[encoder..].Split('\n');

        // The encoder's octets: hex lines up to the state block header.
        var hex = new StringBuilder();
        int index = 1;
        for (; index < lines.Length && !lines[index].Contains("Abs Ref Name", StringComparison.Ordinal); index++)
        {
            Match match = HexLine.Match(lines[index]);
            if (match.Success)
            {
                hex.Append(match.Groups[1].Value.Replace(" ", string.Empty));
                continue;
            }

            // THE GUARD THAT MAKES A DROPPED LINE LOUD. A line whose indent is followed by
            // two hex characters is an octet line by construction, so failing to match one is
            // a parser bug and not a line to skip. Without this the four-character cap that
            // dropped `3fbd01` would have shown up only as a puzzling rejection three frames
            // away, which is exactly how it did show up the first time.
            Assert.False(
                Regex.IsMatch(lines[index], @"^ +[0-9a-f]{2}"),
                $"{label}: an octet line was not matched by HexLine: {lines[index]}");
        }

        Assert.True(index < lines.Length, $"{label}'s encoder block is not followed by a table state.");
        Assert.True(hex.Length > 0, $"{label}'s encoder block carried no octets.");

        // The state block: rows until the Size line.
        List<AppendixBRow> rows = [];
        int size = -1;
        for (index++; index < lines.Length; index++)
        {
            string line = lines[index].TrimEnd('\r');
            Match sizeMatch = Regex.Match(line, @"^\s*Size=(?<size>\d+)\s*$");
            if (sizeMatch.Success)
            {
                size = int.Parse(sizeMatch.Groups["size"].Value);
                break;
            }

            Match row = StateRow.Match(line);
            if (row.Success)
            {
                rows.Add(new AppendixBRow(
                    ulong.Parse(row.Groups["absolute"].Value),
                    row.Groups["name"].Value,
                    row.Groups["value"].Value));
            }
        }

        Assert.True(size >= 0, $"{label}'s table state has no Size line.");
        Assert.NotEmpty(rows);

        // The rows are contiguous in absolute index, which is what s3.2.4 guarantees and what
        // the walk's DroppedCount and InsertCount assertions rely on.
        for (int i = 1; i < rows.Count; i++)
        {
            Assert.Equal(rows[i - 1].Absolute + 1, rows[i].Absolute);
        }

        return new AppendixBStep(label, Convert.FromHexString(hex.ToString()), rows, size);
    }
}
