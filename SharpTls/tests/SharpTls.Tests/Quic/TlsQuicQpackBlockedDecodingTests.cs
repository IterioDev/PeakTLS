using System.Text;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// ============================================================================
// TASK C16 - RFC 9204 s2.1.2, s2.2.1 and s2.2.3
// ============================================================================
//
// EVERY VECTOR HERE IS INVENTED LOCALLY, AND THAT IS THE POINT OF THE FILE.
// Appendix B is the only published QPACK vector set and it cannot witness any
// of these three sections' boundaries:
//
//   * every Appendix B example feeds the "Stream: Encoder" block BEFORE the
//     field section that needs it, so the Insert Count is always already at or
//     above the Required Insert Count and s2.2.1's "greater than" is never
//     distinguished from "greater than or equal";
//   * every Appendix B field section has a Delta Base of 0 or reaches its Base
//     by a second route, so s4.5.1.2's Sign = 1 arithmetic landing a post-Base
//     reference BELOW the Required Insert Count is unwitnessed;
//   * no Appendix B section declares a Required Insert Count smaller than the
//     largest absolute index it references, because a conformant encoder never
//     does - which is exactly the peer defect s2.2.3's MUST is about.
//
// C14 lost three mutants to this blind spot and C15 lost three more. Each
// straddle below therefore carries BOTH sides: the row that must be accepted
// and the row one step past it that must be refused. A single-sided test
// passes against the off-by-one it exists to catch.
//
// THE ARITHMETIC, ONCE, FOR EVERY PREFIX IN THE FILE. s4.5.1.1:
// `EncInsertCount = (ReqInsertCount mod (2 * MaxEntries)) + 1`, with
// `MaxEntries = floor(MaxTableCapacity / 32)`. The capacity this stack
// advertises is 65536, so MaxEntries is 2048 and FullRange is 4096; every
// Required Insert Count used here is under 64, so EncInsertCount is the count
// plus one and the reconstruction returns it unwrapped. s4.5.1.2: Sign 0 gives
// `Base = ReqInsertCount + DeltaBase`, Sign 1 gives
// `Base = ReqInsertCount - DeltaBase - 1`.
public sealed class TlsQuicQpackBlockedDecodingTests
{
    // ========================================================================
    // s2.2.3's bound on a reference's absolute index
    // ========================================================================

    // s2.2.3: "If the decoder encounters a reference in a field line
    // representation to a dynamic table entry that has already been evicted or
    // that has an absolute index greater than or equal to the declared Required
    // Insert Count (Section 4.5.1), it MUST treat this as a connection error of
    // type QPACK_DECOMPRESSION_FAILED."
    //
    // THE TABLE HOLDS THREE ENTRIES AND THE SECTION DECLARES TWO, so the entry
    // at absolute index 2 is PRESENT and the section still has no right to name
    // it. That separates s2.2.3's second clause from its first - "already been
    // evicted" - which is what an implementation checking only the lookup would
    // conflate. It is also the only shape that kills `>=` weakened to `>`:
    // at absolute 2 against a declared count of 2, `>` answers false and the
    // lookup then succeeds, so the section decodes and nothing complains.
    [Theory]
    [InlineData(1ul, true)]
    [InlineData(2ul, false)]
    public void AReferenceIsRefusedAtTheDeclaredRequiredInsertCountAndAcceptedOneBelowIt(
        ulong absolute, bool expectAccepted)
    {
        var table = TableWith(3);

        // Required Insert Count 2, Delta Base 0, so the Base is 2. s3.2.5's
        // relative index reaches absolute 1 at index 0; s3.2.6's post-Base
        // index reaches absolute 2 at index 0.
        byte[] section = absolute == 1
            ? [EncodedInsertCount(2), 0x00, Relative(0)]
            : [EncodedInsertCount(2), 0x00, PostBase(0)];

        var (accepted, error, fields) = Decode(section, table);

        Assert.Equal(expectAccepted, accepted);
        if (expectAccepted)
        {
            Assert.Equal(TlsQuicQpackError.None, error);
            Assert.Equal([("n1", "v1")], fields);
        }
        else
        {
            Assert.Equal(TlsQuicQpackError.ReferenceAtOrAboveRequiredInsertCount, error);
        }
    }

    // s2.1.2: "For a field section encoded with no references to the dynamic
    // table, the Required Insert Count is zero." So a section declaring ZERO
    // has promised it references nothing dynamic, and EVERY dynamic reference
    // in it is at or above that count - including one that resolves perfectly
    // well against a table that holds the entry.
    //
    // NO RFC VECTOR REACHES THIS. Appendix B's zero-count sections carry no
    // dynamic reference at all, because a conformant encoder cannot produce
    // one. It is the case that proves the check runs BEFORE the lookup rather
    // than after it: an implementation that looked the entry up first would
    // find it and accept.
    [Fact]
    public void ADeclaredCountOfZeroRefusesADynamicReferenceThatResolvesPerfectlyWell()
    {
        var table = TableWith(3);

        // Required Insert Count 0. s4.5.1.2: "A field section that was encoded
        // without references to the dynamic table can use any value for the
        // Base" - Sign 0 with a Delta Base of 3 puts the Base at 3, from which
        // relative index 0 is absolute 2, an entry this table holds.
        var (accepted, error, _) = Decode([0x00, 0x03, Relative(0)], table);

        Assert.False(accepted);
        Assert.Equal(TlsQuicQpackError.ReferenceAtOrAboveRequiredInsertCount, error);

        // And the entry really is resolvable: the same relative index against a
        // section that declares a count covering it decodes.
        var (reachable, _, fields) = Decode([EncodedInsertCount(3), 0x00, Relative(0)], table);
        Assert.True(reachable);
        Assert.Equal([("n2", "v2")], fields);
    }

    // s4.5.1.2's Sign = 1: "the decoder subtracts the value of Delta Base from
    // the Required Insert Count and also subtracts one to determine the value
    // of the Base", so a Required Insert Count of 3 with a Delta Base of 1 puts
    // the Base at 1 and s3.2.6's post-Base indices then run 1, 2, 3.
    //
    // UNWITNESSED BY APPENDIX B, which sets Delta Base to zero everywhere it
    // uses post-Base indexing - so no published vector has a post-Base
    // reference landing BELOW the Required Insert Count, and none reaches the
    // boundary where the next index crosses it. Indices 0 and 1 must be
    // accepted and index 2, at absolute 3, must not.
    [Theory]
    [InlineData(0, true, "n1", "v1")]
    [InlineData(1, true, "n2", "v2")]
    [InlineData(2, false, "", "")]
    public void PostBaseIndexingUnderASignOfOneStraddlesTheDeclaredCount(
        int postBaseIndex, bool expectAccepted, string name, string value)
    {
        var table = TableWith(3);

        // Required Insert Count 3; Sign 1 with Delta Base 1 gives Base = 3 - 1 - 1 = 1.
        var (accepted, error, fields) =
            Decode([EncodedInsertCount(3), 0x81, PostBase(postBaseIndex)], table);

        Assert.Equal(expectAccepted, accepted);
        if (expectAccepted)
        {
            Assert.Equal([(name, value)], fields);
        }
        else
        {
            Assert.Equal(TlsQuicQpackError.ReferenceAtOrAboveRequiredInsertCount, error);
        }
    }

    // ========================================================================
    // s2.2.1's block, at the decoder
    // ========================================================================

    // s2.2.1: "When the Required Insert Count is less than or equal to the
    // decoder's Insert Count, the field section can be processed immediately.
    // Otherwise, the stream on which the field section was received becomes
    // blocked." At an Insert Count of 2, a count of 2 is processable and a
    // count of 3 blocks - and the count-of-2 row is the only thing that
    // separates `>` from `>=`.
    [Theory]
    [InlineData(2ul, false)]
    [InlineData(3ul, true)]
    public void TheBlockIsDecidedAgainstTheInsertCountAtTheBoundary(
        ulong requiredInsertCount, bool expectBlocked)
    {
        var table = TableWith(2);

        // Base = count, and a relative index of 0 is the entry at Base - 1 -
        // which for a count of 2 is absolute 1, the largest s2.1.2 permits.
        var (accepted, error, _) =
            Decode([EncodedInsertCount(requiredInsertCount), 0x00, Relative(0)], table);

        Assert.Equal(!expectBlocked, accepted);
        Assert.Equal(
            expectBlocked ? TlsQuicQpackError.Blocked : TlsQuicQpackError.None,
            error);
    }

    // s2.2.1 decides "upon receipt of an encoded field section" from the
    // Required Insert Count alone. A section that BLOCKS must therefore block
    // whatever follows its prefix - including bytes that are not a legal
    // representation at all - because the decoder has not read them and by the
    // time it can, they may decode fine.
    [Fact]
    public void TheBlockIsDecidedFromThePrefixBeforeAnyRepresentationIsRead()
    {
        var table = TableWith(1);

        // 0x21 is s4.3.1's Set Dynamic Table Capacity opcode, an ENCODER-stream
        // instruction and not an s4.5 representation; it decodes to nothing
        // legal on a field section. The block still wins.
        var (_, error, _) = Decode([EncodedInsertCount(4), 0x00, 0x21, 0xff, 0xff], table);
        Assert.Equal(TlsQuicQpackError.Blocked, error);

        // Once the table has caught up the same trailing bytes ARE read, and
        // are refused - which is what says the first answer came from the
        // prefix and not from the representations.
        InsertNumbered(table, 1, 3);
        var (_, later, _) = Decode([EncodedInsertCount(4), 0x00, 0x21, 0xff, 0xff], table);
        Assert.NotEqual(TlsQuicQpackError.Blocked, later);
        Assert.NotEqual(TlsQuicQpackError.None, later);
    }

    // s2.2.1's Blocked is a "not yet" and not a rejection, so it must never
    // reach s6's connection error - the same line TryGetHttp3ErrorCode already
    // draws for DestinationTooSmall. Everything else this decoder can answer
    // still maps, and the loop below is over the enum itself rather than a list
    // typed here, so a member added later is covered without this test being
    // edited.
    [Fact]
    public void OnlyNoneAndDestinationTooSmallAndBlockedAreExemptFromTheConnectionError()
    {
        foreach (TlsQuicQpackError error in Enum.GetValues<TlsQuicQpackError>())
        {
            var exempt = error is TlsQuicQpackError.None
                or TlsQuicQpackError.DestinationTooSmall
                or TlsQuicQpackError.Blocked;

            Assert.Equal(
                !exempt,
                TlsQuicQpackDecoder.TryGetHttp3ErrorCode(error, out var code));
            Assert.Equal(0x0200ul, code);
        }
    }

    // THE MEMBERS THAT SHARE A WIRE CODE MUST NOT SHARE A VALUE, and the sweep is why this
    // exists: aliasing ReferenceAtOrAboveRequiredInsertCount onto DynamicTableReference
    // SURVIVED every other test in this file, because every assertion compares one member
    // against another and two aliases compare equal. s2.2.3 names two defects in one sentence
    // - an entry "that has already been evicted" and one "that has an absolute index greater
    // than or equal to the declared Required Insert Count" - and C16 split them precisely so a
    // failing test says WHICH. That split is only real if the values differ.
    //
    // s6 GIVES THEM THE SAME CODE, WHICH IS THE POINT. The second assertion pins that too, so
    // this is not a test asking the two to diverge on the wire; it asks them to stay
    // distinguishable to a reader while staying identical to a peer.
    [Fact]
    public void TheTwoInvalidReferenceMembersAreDistinctThoughTheyShareOneWireCode()
    {
        Assert.NotEqual(
            TlsQuicQpackError.DynamicTableReference,
            TlsQuicQpackError.ReferenceAtOrAboveRequiredInsertCount);

        // And the three C16 added are distinct from each other and from None, so that no
        // failing test can name one of them while meaning another.
        var added = new[]
        {
            TlsQuicQpackError.None,
            TlsQuicQpackError.Blocked,
            TlsQuicQpackError.BlockedStreamLimitExceeded,
            TlsQuicQpackError.RequiredInsertCountNotEncodable,
            TlsQuicQpackError.RequiredInsertCountNotZero,
            TlsQuicQpackError.ReferenceAtOrAboveRequiredInsertCount,
        };
        Assert.Equal(added.Length, added.Distinct().Count());

        Assert.True(TlsQuicQpackDecoder.TryGetHttp3ErrorCode(
            TlsQuicQpackError.DynamicTableReference, out var evicted));
        Assert.True(TlsQuicQpackDecoder.TryGetHttp3ErrorCode(
            TlsQuicQpackError.ReferenceAtOrAboveRequiredInsertCount, out var outOfRange));
        Assert.Equal(evicted, outOfRange);
    }

    // THE REJECTING PATH ALLOCATES NOTHING, which is this project's house rule
    // for anything a peer can drive as often as it likes. Measured rather than
    // reasoned: a blocked section is the cheapest thing a hostile peer can send
    // in bulk, since it commits no table state and can be repeated forever.
    //
    // THE ACCEPTING MEASUREMENT IS HERE TO MAKE THE ZERO NON-VACUOUS. Both
    // paths write into caller-supplied spans and neither allocates in the
    // decoder itself, so a bare "Blocked allocates 0" would pass against an
    // implementation that never ran at all. What is asserted instead is that
    // the accepting path did real work - it produced a field - while still
    // costing nothing, and that the blocked path cost nothing either.
    [Fact]
    public void TheBlockedPathAllocatesNothing()
    {
        var table = TableWith(1);
        byte[] blocked = [EncodedInsertCount(2), 0x00, Relative(0)];
        byte[] accepted = [EncodedInsertCount(1), 0x00, Relative(0)];
        var buffer = new byte[256];
        var lines = new TlsQuicQpackDecodedFieldLine[8];

        // Warmed first: the very first call through a code path pays for JIT
        // and for TlsQuicQpackDynamicTable's one-time scratch, neither of which
        // is what this test is about.
        Run(blocked);
        Run(accepted);

        // NOT ONE ASSERTION INSIDE THE LOOP. xUnit's Assert.Equal builds an
        // AssertEqualityComparer and boxes both operands, which costs about 520
        // bytes a call - so a measured loop containing one reports the test's
        // own allocation and never the decoder's. The first draft of this test
        // did exactly that and read 33280 bytes for 64 blocked decodes.
        var last = TlsQuicQpackError.None;
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < 64; i++)
        {
            last = Run(blocked);
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(TlsQuicQpackError.Blocked, last);
        Assert.Equal(0, allocated);

        // And the accepting path really did decode, so the zero above is not
        // the zero of a decoder that answered without looking.
        Assert.Equal(TlsQuicQpackError.None, Run(accepted));
        Assert.Equal("n0", Encoding.ASCII.GetString(buffer, lines[0].NameOffset, lines[0].NameLength));

        TlsQuicQpackError Run(byte[] section)
        {
            TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
                section, buffer, lines, long.MaxValue, table,
                out _, out _, out _, out var error);
            return error;
        }
    }

    // ========================================================================
    // s2.1.2's bound on streams blocked at once
    // ========================================================================

    // s2.1.2: "An encoder MUST limit the number of streams that could become
    // blocked to the value of SETTINGS_QPACK_BLOCKED_STREAMS at all times. If a
    // decoder encounters more blocked streams than it promised to support, it
    // MUST treat this as a connection error of type
    // QPACK_DECOMPRESSION_FAILED."
    //
    // THE BOUND IS STRADDLED AT EVERY VALUE FROM ZERO. The zero row is s5's
    // default - "The initial value ... is zero" - and refuses the FIRST block
    // with nothing held at all, which is the row that separates `>=` from `>`:
    // under `>` a decoder advertising 0 would permit one blocked stream.
    [Theory]
    [InlineData(0ul)]
    [InlineData(1ul)]
    [InlineData(2ul)]
    [InlineData(100ul)]
    public void ExactlyTheAdvertisedNumberOfStreamsMayBlockAtOnce(ulong advertised)
    {
        var blocked = new TlsQuicQpackBlockedStreams(advertised);
        Assert.Equal(advertised, blocked.MaximumBlockedStreams);

        // s6.1's client-initiated bidirectional ids, 0, 4, 8..., so the ids are
        // the ones a real request stream would carry.
        for (var i = 0ul; i < advertised; i++)
        {
            Assert.True(blocked.TryHold(i * 4, i + 1, out var error));
            Assert.Equal(TlsQuicQpackError.None, error);
            Assert.Equal((int)i + 1, blocked.Count);
        }

        Assert.False(blocked.TryHold(advertised * 4, 1, out var refused));
        Assert.Equal(TlsQuicQpackError.BlockedStreamLimitExceeded, refused);
        Assert.Equal((int)advertised, blocked.Count);
    }

    // s2.1.2's bound is on streams blocked AT ONCE, not on how often a stream
    // blocks, so a stream already held costs no further slot however many times
    // it is presented - which is what makes re-presenting a parked section on
    // every pump safe at an advertised value of 1.
    [Fact]
    public void AStreamAlreadyHeldTakesNoSecondSlotHoweverOftenItIsPresented()
    {
        var blocked = new TlsQuicQpackBlockedStreams(1);

        for (var pump = 0; pump < 32; pump++)
        {
            Assert.True(blocked.TryHold(0, 5, out var error));
            Assert.Equal(TlsQuicQpackError.None, error);
        }

        Assert.Equal(1, blocked.Count);
        Assert.False(blocked.TryHold(4, 5, out _));

        // And releasing gives the slot back, which is s2.2.1's unblock and
        // s2.2.2.2's abandonment reaching the same place.
        blocked.Release(0);
        Assert.Equal(0, blocked.Count);
        Assert.True(blocked.TryHold(4, 5, out _));
    }

    // s2.2.1: "A stream becomes unblocked when the Insert Count becomes greater
    // than or equal to the Required Insert Count for ALL encoded field sections
    // the decoder has started reading from the stream." So a second section on
    // a held stream RAISES the count and never lowers it - a decoder that took
    // the newest value would unblock a stream whose earlier section still
    // cannot be decoded.
    [Fact]
    public void AHeldStreamsRequiredInsertCountRisesAndNeverFalls()
    {
        var blocked = new TlsQuicQpackBlockedStreams(4);

        Assert.True(blocked.TryHold(0, 7, out _));
        Assert.True(blocked.IsHeld(0, out var held));
        Assert.Equal(7ul, held);

        Assert.True(blocked.TryHold(0, 3, out _));
        Assert.True(blocked.IsHeld(0, out held));
        Assert.Equal(7ul, held);

        Assert.True(blocked.TryHold(0, 9, out _));
        Assert.True(blocked.IsHeld(0, out held));
        Assert.Equal(9ul, held);
    }

    // Releasing a stream that never blocked is a no-op rather than a fault,
    // which is what lets a caller release unconditionally on s2.2.2.2's
    // abandonment without first asking whether the stream ever blocked.
    [Fact]
    public void ReleasingAStreamThatNeverBlockedIsANoOp()
    {
        var blocked = new TlsQuicQpackBlockedStreams(1);

        blocked.Release(0);
        blocked.Release(4);
        Assert.Equal(0, blocked.Count);
        Assert.False(blocked.IsHeld(0, out var count));
        Assert.Equal(0ul, count);

        Assert.True(blocked.TryHold(0, 1, out _));
        blocked.Release(0);
        blocked.Release(0);
        Assert.Equal(0, blocked.Count);
    }

    // THE REFUSING PATH ALLOCATES NOTHING AND THE HOLDING PATH DOES, which is
    // the contrast that makes the zero mean something: a peer that opens
    // streams and blocks each one must not be able to make the refusal itself
    // cost memory, while remembering a stream is remembering something and is
    // allowed to.
    [Fact]
    public void TheRefusedHoldAllocatesNothingWhileAnAcceptedOneDoes()
    {
        var blocked = new TlsQuicQpackBlockedStreams(1);
        Assert.True(blocked.TryHold(0, 1, out _));

        // Warmed, so the measurement is not paying for this call path's JIT.
        Assert.False(blocked.TryHold(4, 1, out _));

        // Nothing is asserted inside the loop - see TheBlockedPathAllocatesNothing
        // for why an Assert.Equal in here would measure xUnit rather than this
        // registry.
        var held = true;
        var error = TlsQuicQpackError.None;
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < 256; i++)
        {
            held = blocked.TryHold(4, 1, out error);
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.False(held);
        Assert.Equal(TlsQuicQpackError.BlockedStreamLimitExceeded, error);
        Assert.Equal(0, allocated);

        // The accepting side grows a dictionary and is not asked to be free.
        var growing = new TlsQuicQpackBlockedStreams(4096);
        Assert.True(growing.TryHold(0, 1, out _));
        var beforeHolds = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 1ul; i < 512; i++)
        {
            growing.TryHold(i * 4, 1, out _);
        }

        Assert.True(GC.GetAllocatedBytesForCurrentThread() - beforeHolds > 0);
        Assert.Equal(512, growing.Count);
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    // s4.5.2's Indexed Field Line with T = 0: the 1 pattern, then a 0 for the
    // dynamic table, then s3.2.5's relative index on a 6-bit prefix.
    private static byte Relative(int index) => (byte)(0b1000_0000 | index);

    // s4.5.3's Indexed Field Line with Post-Base Index: the 0001 pattern, then
    // s3.2.6's post-Base index on a 4-bit prefix.
    private static byte PostBase(int index) => (byte)(0b0001_0000 | index);

    // s4.5.1.1's transform. Every count here is well under FullRange, so the
    // modulo is the identity and the encoded octet is the count plus one; the
    // range assertion is what says so rather than leaving it to be noticed.
    private static byte EncodedInsertCount(ulong requiredInsertCount)
    {
        Assert.InRange(requiredInsertCount, 1ul, 63ul);
        return (byte)(requiredInsertCount + 1);
    }

    private static (bool Accepted, TlsQuicQpackError Error, (string, string)[] Fields) Decode(
        byte[] section, TlsQuicQpackDynamicTable table)
    {
        var buffer = new byte[4096];
        var lines = new TlsQuicQpackDecodedFieldLine[64];

        var accepted = TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
            section, buffer, lines, long.MaxValue, table,
            out var lineCount, out _, out _, out var error);

        var fields = new (string, string)[accepted ? lineCount : 0];
        for (var i = 0; i < fields.Length; i++)
        {
            var line = lines[i];
            fields[i] = (
                Encoding.ASCII.GetString(buffer, line.NameOffset, line.NameLength),
                Encoding.ASCII.GetString(buffer, line.ValueOffset, line.ValueLength));
        }

        return (accepted, error, fields);
    }

    // A table at the capacity this stack advertises, so s4.5.1.1's MaxEntries
    // here is the one a real peer would compute, holding `count` entries.
    private static TlsQuicQpackDynamicTable TableWith(int count)
    {
        var table = new TlsQuicQpackDynamicTable((int)SharpTls.Tests.Quic.TestHttp3Settings.DatagramCapable
            .Single(setting =>
                setting.Identifier == TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier)
            .Value);

        var instruction = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(
            (ulong)table.MaximumCapacity, 5, 0b0010_0000, instruction, out var written));
        Feed(table, instruction[..written]);

        InsertNumbered(table, 0, count);
        return table;
    }

    // s4.3.3's Insert With Literal Name, with distinct names so a misread index
    // produces a WRONG field rather than a plausible one.
    private static void InsertNumbered(TlsQuicQpackDynamicTable table, int first, int count)
    {
        for (var i = first; i < first + count; i++)
        {
            var instruction = new byte[128];
            Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
                Encoding.ASCII.GetBytes($"n{i}"), 6, 0b0100_0000, huffman: false,
                instruction, out var nameLength));
            Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
                Encoding.ASCII.GetBytes($"v{i}"), 8, 0, huffman: false,
                instruction.AsSpan(nameLength), out var valueLength));
            Feed(table, instruction[..(nameLength + valueLength)]);
        }

        Assert.Equal((ulong)(first + count), table.InsertCount);
    }

    private static void Feed(TlsQuicQpackDynamicTable table, byte[] instructions)
    {
        Assert.True(table.TryReadEncoderInstructions(
            instructions, out var consumed, out var error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
        Assert.Equal(instructions.Length, consumed);
    }
}
