using System.Text;
using System.Text.RegularExpressions;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// RFC 9204 s4.5's field line representations, decoding side, static-only.
//
// WHICH TESTS ARE EXTERNALLY ANCHORED. Two:
// AppendixB1DecodesBackToItsFieldLine, whose bytes and expected field line are parsed out of
// reference-captures/rfc9204-appendix-b-encoding-and-decoding-examples.txt, and
// TheErrorCodeForADynamicReferenceIsTheOneSection6Names, whose 0x0200 is parsed out of
// reference-captures/rfc9204-section5-6-configuration-and-error-handling.txt. Everything else
// is SELF-DERIVED from the s4.5 figures. There is no published QPACK vector for any of the
// rejections, so they cannot be anchored and are not claimed to be.
public sealed class TlsQuicQpackDecoderTests
{
    // The s4.5.1 prefix in this arm: Required Insert Count 0, Sign 0, Delta Base 0.
    private static ReadOnlySpan<byte> Prefix => [0x00, 0x00];

    // ========================================================================
    // EXTERNALLY ANCHORED
    // ========================================================================

    [Fact]
    public void AppendixB1DecodesBackToItsFieldLine()
    {
        (byte[] octets, string name, string value, _) = TlsQuicQpackEncoderTests.AppendixB1();

        Assert.Equal([(name, value)], TlsQuicQpackEncoderTests.Decode(octets));
        Assert.Equal([(":path", "/index.html")], TlsQuicQpackEncoderTests.Decode(octets));
    }

    // RFC 9204 s6's code, read out of the capture rather than typed, and reached by an actual
    // dynamic reference rather than asserted about the constant.
    [Fact]
    public void TheErrorCodeForADynamicReferenceIsTheOneSection6Names()
    {
        string capture = File.ReadAllText(QpackCaptures.Path("rfc9204-section5-6-configuration-and-error-handling.txt"));
        Match match = Regex.Match(capture, @"QPACK_DECOMPRESSION_FAILED \(0x(?<code>[0-9a-fA-F]+)\)");
        Assert.True(match.Success, "s6's QPACK_DECOMPRESSION_FAILED not found in the capture.");
        ulong captured = Convert.ToUInt64(match.Groups["code"].Value, 16);

        // Written as Assert.True rather than Assert.Equal because the CAPTURE is the expected
        // value here and the constant is what is under test; xUnit2000 would insist on the
        // reverse and invert the meaning.
        Assert.True(
            captured == TlsQuicQpackDecoder.QpackDecompressionFailed,
            $"s6 says 0x{captured:X4}, the source says 0x{TlsQuicQpackDecoder.QpackDecompressionFailed:X4}.");

        // s4.5.2 with T = 0: 1000_0001, a relative index into the dynamic table.
        Assert.Equal(TlsQuicQpackError.DynamicTableReference, ErrorFrom([0x00, 0x00, 0b1000_0001]));
        Assert.True(TlsQuicQpackDecoder.TryGetHttp3ErrorCode(TlsQuicQpackError.DynamicTableReference, out ulong code));
        Assert.Equal(captured, code);
    }

    // ========================================================================
    // SELF-DERIVED: all six s4.5 subsections
    // ========================================================================

    // s4.5.1 the prefix, then s4.5.2 to s4.5.6. Three resolve and two are rejected, and the
    // rejection is the CORRECT reading of those two rather than a fallthrough: s4.5.3's
    // post-Base index and s4.5.5's post-Base name reference are dynamic-only by shape, since
    // s3.2.6's post-Base indexing is defined against a Base the static table does not have.
    [Fact]
    public void AllSixSubsectionsOfSection45AreRecognised()
    {
        // s4.5.1: the prefix alone is a legal, empty field section.
        Assert.Equal([], Decode([0x00, 0x00]));

        // s4.5.2, T = 1: static row 1 is `:path` `/`.
        Assert.Equal([(":path", "/")], Decode([0x00, 0x00, 0b1100_0001]));

        // s4.5.3, '0001': indexed with post-Base index.
        Assert.Equal(TlsQuicQpackError.DynamicTableReference, ErrorFrom([0x00, 0x00, 0b0001_0000]));

        // s4.5.4, T = 1: name from static row 0, value a two-octet literal.
        Assert.Equal(
            [(":authority", "ab")],
            Decode([0x00, 0x00, 0b0101_0000, 0x02, (byte)'a', (byte)'b']));

        // s4.5.5, '0000': literal with post-Base name reference.
        Assert.Equal(TlsQuicQpackError.DynamicTableReference, ErrorFrom([0x00, 0x00, 0b0000_0000]));

        // s4.5.6, '001': both name and value as literals.
        Assert.Equal(
            [("a-b", "v")],
            Decode([0x00, 0x00, 0b0010_0011, (byte)'a', (byte)'-', (byte)'b', 0x01, (byte)'v']));
    }

    // THE THREE DYNAMIC REPRESENTATIONS, one witness each, with the octet spelled out so the
    // input can only be read as that representation.
    //
    // Note there are four dynamic SHAPES across three s4.5 subsections: s4.5.2 and s4.5.4
    // each have a T bit that can select the dynamic table, and s4.5.3 and s4.5.5 are dynamic
    // whatever their payload.
    [Theory]
    [InlineData(0b1000_0001, "s4.5.2 indexed field line, T = 0, relative dynamic index 1")]
    [InlineData(0b0100_0001, "s4.5.4 literal with name reference, T = 0, relative dynamic index 1")]
    [InlineData(0b0001_0001, "s4.5.3 indexed field line with post-Base index 1")]
    [InlineData(0b0000_0001, "s4.5.5 literal with post-Base name reference, index 1")]
    public void EveryDynamicRepresentationIsRejectedRatherThanMisread(byte first, string witness)
    {
        Assert.NotEmpty(witness);

        // Enough octets follow that a decoder which ignored the dynamic bit and read on would
        // find a well-formed representation and SUCCEED. That is the failure this guards: a
        // misread resolves to a plausible wrong field, not to a visible error.
        byte[] source = [0x00, 0x00, first, 0x02, (byte)'a', (byte)'b'];
        Assert.Equal(TlsQuicQpackError.DynamicTableReference, ErrorFrom(source));
    }

    // The T bit and nothing else. Each pair below differs in exactly one bit, and that one bit
    // is the difference between a rejection and a decoded field - which is what makes the
    // rejections above specific rather than a blanket refusal to decode anything.
    //
    // The static twins carry only their own octets: an s4.5.2 indexed field line is ONE octet
    // long, so trailing bytes would be read as a second representation rather than as its
    // payload.
    [Fact]
    public void OnlyTheTBitSeparatesARejectionFromADecodedField()
    {
        // s4.5.2, bit 6.
        Assert.Equal(TlsQuicQpackError.DynamicTableReference, ErrorFrom([0x00, 0x00, 0b1000_0001]));
        Assert.Equal([(":path", "/")], Decode([0x00, 0x00, 0b1100_0001]));

        // s4.5.4, bit 4.
        Assert.Equal(
            TlsQuicQpackError.DynamicTableReference,
            ErrorFrom([0x00, 0x00, 0b0100_0001, 0x02, (byte)'a', (byte)'b']));
        Assert.Equal(
            [(":path", "ab")],
            Decode([0x00, 0x00, 0b0101_0001, 0x02, (byte)'a', (byte)'b']));
    }

    // ========================================================================
    // SELF-DERIVED: the prefix's own guards
    // ========================================================================

    // s4.5.1.1's Required Insert Count. Non-zero is rejected in this arm because we advertise
    // SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0 and s3.2.3 forbids a conformant peer from needing
    // a dynamic entry; see the note at the rejection site.
    [Theory]
    [InlineData(0x01)]
    [InlineData(0x7F)]
    [InlineData(0xFF)]
    public void ANonZeroRequiredInsertCountIsRejected(byte count)
    {
        // 0xFF fills the 8-bit prefix and continues, so the continuation octet is supplied.
        byte[] source = count == 0xFF
            ? [0xFF, 0x01, 0x00, 0b1100_0001]
            : [count, 0x00, 0b1100_0001];
        Assert.Equal(TlsQuicQpackError.RequiredInsertCountNotZero, ErrorFrom(source));

        // The same bytes with a zero count decode, so this is the count and nothing else.
        Assert.Equal([(":path", "/")], Decode([0x00, 0x00, 0b1100_0001]));
    }

    // s4.5.1.2: "An endpoint MUST treat a field block with a Sign bit of 1 as invalid if the
    // value of Required Insert Count is less than or equal to the value of Delta Base." With
    // Required Insert Count pinned at 0 and Delta Base non-negative, 0 <= Delta Base holds
    // for every Delta Base, so a set Sign bit is invalid outright - including at Delta Base 0.
    [Theory]
    [InlineData(0b1000_0000)]
    [InlineData(0b1000_0001)]
    [InlineData(0b1111_1110)]
    public void ASignBitOfOneIsRejectedAtEveryDeltaBase(byte deltaBase)
    {
        Assert.Equal(TlsQuicQpackError.InvalidBase, ErrorFrom([0x00, deltaBase, 0b1100_0001]));
    }

    // The other half: a CLEAR Sign bit takes any Delta Base, because s4.5.1.2 says "A field
    // section that was encoded without references to the dynamic table can use any value for
    // the Base". A decoder that rejected a non-zero Delta Base would be wrong.
    [Theory]
    [InlineData(0b0000_0000)]
    [InlineData(0b0000_0001)]
    [InlineData(0b0111_1110)]
    public void AClearSignBitAcceptsAnyDeltaBase(byte deltaBase)
    {
        Assert.Equal([(":path", "/")], Decode([0x00, deltaBase, 0b1100_0001]));
    }

    // ========================================================================
    // SELF-DERIVED: hostile input
    // ========================================================================

    // An index past the table's 99 entries. 99 is the first one that does not exist, which is
    // the boundary that matters; the 6-bit prefix fills at 63 so both of these need the
    // continuation chain, and the huge one is there to show the clamp holds.
    //
    // 2^32 + 1 is the one that matters most: it is past the table by a mile, but its low 32
    // bits are 1, so a decoder that CAST the index to int instead of clamping it would land
    // on static row 1 and hand back `:path` `/` as though the peer had asked for it.
    [Theory]
    [InlineData(99)]
    [InlineData(255)]
    [InlineData(4294967297L)]
    [InlineData(long.MaxValue >> 3)]
    public void AStaticIndexPastTheTableIsRejected(long index)
    {
        Assert.Equal(TlsQuicQpackError.StaticIndexOutOfRange, ErrorFrom(IndexedFieldLine(index)));

        // 98 is the last that resolves, so the boundary is where it is claimed to be.
        Assert.Equal(TlsQuicQpackError.None, ErrorFrom(IndexedFieldLine(98)));
    }

    // The same, through s4.5.4's 4-bit name index.
    [Fact]
    public void ANameReferencePastTheTableIsRejected()
    {
        // 0x5F fills the 4-bit prefix at 15; the continuation carries 84, so the index is 99.
        Assert.Equal(
            TlsQuicQpackError.StaticIndexOutOfRange,
            ErrorFrom([0x00, 0x00, 0x5F, 84, 0x01, (byte)'v']));

        // 83 gives index 98, which resolves.
        Assert.Equal(TlsQuicQpackError.None, ErrorFrom([0x00, 0x00, 0x5F, 83, 0x01, (byte)'v']));
    }

    // EVERY PROPER PREFIX of B.1's octets. A truncated field section is the commonest hostile
    // input there is, and each of these must reject without throwing.
    [Fact]
    public void EveryTruncationOfAppendixB1IsRejectedWithoutThrowing()
    {
        (byte[] octets, _, _, _) = TlsQuicQpackEncoderTests.AppendixB1();

        // ZERO VERSUS ABSENT, at the top of the section. A buffer that stops inside the
        // s4.5.1 prefix is truncated; a buffer that stops exactly AT the end of it is a legal
        // field section carrying no field lines, which s4.5 allows outright - "a prefix and a
        // possibly empty sequence of representations". Those two are one octet apart and must
        // not be conflated.
        Assert.Equal(TlsQuicQpackError.Truncated, ErrorFrom(octets[..0]));
        Assert.Equal(TlsQuicQpackError.Truncated, ErrorFrom(octets[..1]));
        Assert.Equal(TlsQuicQpackError.None, ErrorFrom(octets[..2]));
        Assert.Empty(TlsQuicQpackEncoderTests.Decode(octets[..2]));

        // Every truncation that lands inside the representation itself.
        for (int length = TlsQuicQpackEncoder.FieldSectionPrefixLength + 1; length < octets.Length; length++)
        {
            Assert.Equal(TlsQuicQpackError.Truncated, ErrorFrom(octets[..length]));
        }

        Assert.Equal(TlsQuicQpackError.None, ErrorFrom(octets));
    }

    // A declared literal length that runs past the end of the buffer, at both the 4-bit name
    // prefix and the 8-bit value prefix, and at a length near 2^62 that would wrap if it were
    // narrowed to int before the comparison.
    [Fact]
    public void ALengthThatOverrunsTheBufferIsRejected()
    {
        // s4.5.6 declaring a 7-octet name with 3 octets left.
        Assert.Equal(TlsQuicQpackError.Truncated, ErrorFrom([0x00, 0x00, 0b0010_0111, (byte)'a', (byte)'b', (byte)'c']));

        // s4.5.4 declaring a 127-octet value with 2 left.
        Assert.Equal(TlsQuicQpackError.Truncated, ErrorFrom([0x00, 0x00, 0x50, 0x7F, 0x00, 0x00]));

        // A length whose continuation chain reaches 2^62 - 1.
        byte[] huge = [0x00, 0x00, 0x50, 0x7F, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];
        TlsQuicQpackError error = ErrorFrom(huge);
        Assert.True(
            error is TlsQuicQpackError.Truncated or TlsQuicQpackError.IntegerOverflow,
            $"expected a rejection, got {error}");
    }

    // RFC 7541 s5.2's three Huffman rejections, reached through a field line rather than
    // through the codec directly, so this is about the decoder wiring and not about C6.
    //
    // "A Huffman code that never terminates" cannot be constructed and no test claims to: the
    // table is complete and the longest code is 30 bits, so any 30 bits reach a leaf. What an
    // attacker can actually send is the EOS symbol, over-long padding, or padding that is not
    // the EOS prefix, and those are the three below.
    [Fact]
    public void TheThreeHostileHuffmanInputsAreRejectedThroughAFieldLine()
    {
        // EOS is 30 one-bits; four 0xFF octets contain it.
        Assert.Equal(
            TlsQuicQpackError.EosSymbol,
            ErrorFrom([0x00, 0x00, 0x50, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]));

        // `a` is 00011 (5 bits); three more bits of padding fill the octet, and a whole
        // further octet of padding is strictly longer than 7 bits.
        Assert.Equal(
            TlsQuicQpackError.PaddingTooLong,
            ErrorFrom([0x00, 0x00, 0x50, 0x82, 0b0001_1111, 0xFF]));

        // A trailing 110 is short enough but is not the EOS prefix, which is all ones.
        Assert.Equal(
            TlsQuicQpackError.PaddingNotEos,
            ErrorFrom([0x00, 0x00, 0x50, 0x81, 0b0001_1110]));
    }

    // NOTHING THROWS ON ANY SHORT HOSTILE INPUT. Exhaustive over every 0-, 1-, 2- and 3-octet
    // buffer: 1 + 256 + 65536 + 16777216 = 16843009 inputs, every one of which is either
    // decoded or rejected, and none of which throws. Three octets is enough to reach past the
    // two-octet prefix into the first octet of a representation, so every one of the five
    // representation branches is entered somewhere in this sweep.
    [Fact]
    public void NoShortInputThrows()
    {
        byte[] buffer = new byte[64];
        TlsQuicQpackDecodedFieldLine[] lines = new TlsQuicQpackDecodedFieldLine[8];
        byte[] source = new byte[3];

        long inputs = 0;
        for (int length = 0; length <= 3; length++)
        {
            int combinations = 1 << (8 * length);
            for (int value = 0; value < combinations; value++)
            {
                for (int i = 0; i < length; i++)
                {
                    source[i] = (byte)(value >> (8 * i));
                }

                // The call itself is the assertion: an exception escaping here fails the test.
                TlsQuicQpackDecoder.TryDecodeFieldSection(
                    source.AsSpan(0, length),
                    buffer,
                    lines,
                    long.MaxValue,
                    out _,
                    out _,
                    out _);
                inputs++;
            }
        }

        // Derived: 256^0 + 256^1 + 256^2 + 256^3.
        Assert.Equal(1 + 256 + 65536 + 16777216, inputs);
        Assert.Equal(16843009, inputs);
    }

    // ========================================================================
    // SELF-DERIVED: RFC 9114 s4.2.2's limit
    // ========================================================================

    // "The size of a field list is calculated based on the uncompressed size of fields,
    // including the length of the name and value in bytes plus an overhead of 32 bytes for
    // each field."
    //
    // The witness is chosen so the 32-byte overhead is the ONLY thing that pushes it over: the
    // field's name and value are 5 and 1 octets, so the raw size is 6 and the accounted size
    // is 38. A limit of 37 must reject and 38 must accept - a decoder that forgot the overhead
    // would accept both.
    [Fact]
    public void TheThirtyTwoByteOverheadIsPartOfTheAccountedSize()
    {
        byte[] source = [0x00, 0x00, 0b1100_0001];   // `:path` `/`, 5 + 1 uncompressed
        Assert.Equal(6, ":path".Length + "/".Length);

        Assert.Equal(TlsQuicQpackError.FieldSectionTooLarge, ErrorFrom(source, maximum: 37));
        Assert.Equal(TlsQuicQpackError.None, ErrorFrom(source, maximum: 38));
        Assert.Equal(TlsQuicQpackError.FieldSectionTooLarge, ErrorFrom(source, maximum: 6));
        Assert.Equal(TlsQuicQpackError.FieldSectionTooLarge, ErrorFrom(source, maximum: 0));
    }

    // The size is UNCOMPRESSED, so a Huffman-coded value counts for what it decodes to and not
    // for what it cost on the wire. `example.com` is 11 octets uncompressed and 8 coded; a
    // limit of 8 + 10 + 32 = 50 would pass if the compressed size were used, and must not.
    [Fact]
    public void TheAccountedSizeIsTheUncompressedOne()
    {
        byte[] source = TlsQuicQpackEncoderTests.Encode(
            [(":authority", "example.com")],
            huffman: TlsQuicQpackHuffmanPolicy.Always,
            preferNameReference: true);

        Assert.True(source.Length < 10 + 11 + 32);
        Assert.Equal(TlsQuicQpackError.FieldSectionTooLarge, ErrorFrom(source, maximum: 52));
        Assert.Equal(TlsQuicQpackError.None, ErrorFrom(source, maximum: 53));
    }

    // The limit is on the SECTION, so it accumulates across field lines rather than applying
    // per line. Two copies of a 38-byte field are 76.
    [Fact]
    public void TheLimitAccumulatesAcrossFieldLines()
    {
        byte[] source = [0x00, 0x00, 0b1100_0001, 0b1100_0001];
        Assert.Equal(TlsQuicQpackError.FieldSectionTooLarge, ErrorFrom(source, maximum: 75));
        Assert.Equal(TlsQuicQpackError.None, ErrorFrom(source, maximum: 76));
    }

    // ========================================================================
    // SELF-DERIVED: the sizing answers are not peer errors
    // ========================================================================

    // A short output buffer says the CALLER was wrong, not the peer, so it must not map to a
    // connection error. Closing a healthy connection over our own buffer size would be the bug
    // this guards.
    [Fact]
    public void AShortOutputBufferIsALocalAnswerAndNotAConnectionError()
    {
        byte[] source = [0x00, 0x00, 0b1100_0001];

        Assert.False(TlsQuicQpackDecoder.TryDecodeFieldSection(
            source, new byte[3], new TlsQuicQpackDecodedFieldLine[4], long.MaxValue, out _, out _, out TlsQuicQpackError tooSmall));
        Assert.Equal(TlsQuicQpackError.DestinationTooSmall, tooSmall);
        Assert.False(TlsQuicQpackDecoder.TryGetHttp3ErrorCode(tooSmall, out _));

        Assert.False(TlsQuicQpackDecoder.TryDecodeFieldSection(
            source, new byte[64], [], long.MaxValue, out _, out _, out TlsQuicQpackError noLines));
        Assert.Equal(TlsQuicQpackError.DestinationTooSmall, noLines);

        // And None is not a connection error either.
        Assert.False(TlsQuicQpackDecoder.TryGetHttp3ErrorCode(TlsQuicQpackError.None, out _));

        // Every other member is - EXCEPT C16's Blocked, which joined this exemption for the
        // same reason DestinationTooSmall is in it: s2.2.1's block says the encoder stream has
        // not caught up, not that the peer was wrong, and the same bytes decode once it does.
        // TlsQuicQpackBlockedDecodingTests.OnlyNoneAndDestinationTooSmallAndBlockedAreExempt
        // FromTheConnectionError is the same sweep from C16's side.
        foreach (TlsQuicQpackError error in Enum.GetValues<TlsQuicQpackError>())
        {
            bool expected = error is not (TlsQuicQpackError.None
                or TlsQuicQpackError.DestinationTooSmall
                or TlsQuicQpackError.Blocked);
            Assert.Equal(expected, TlsQuicQpackDecoder.TryGetHttp3ErrorCode(error, out ulong code));
            Assert.Equal(TlsQuicQpackDecoder.QpackDecompressionFailed, code);
        }
    }

    // ========================================================================
    // SELF-DERIVED: allocation
    // ========================================================================

    // The rejecting path allocates zero bytes. Measured rather than asserted from the source,
    // because "it looks allocation-free" is how a hidden boxing or a closure gets in.
    [Fact]
    public void TheRejectingPathAllocatesZeroBytes()
    {
        byte[][] rejects =
        [
            [0x00, 0x00, 0b1000_0001],              // dynamic indexed
            [0x00, 0x00, 0b0100_0001, 0x01, 0x61],  // dynamic name reference
            [0x00, 0x00, 0b0001_0001],              // post-Base index
            [0x00, 0x00, 0b0000_0001],              // post-Base name reference
            [0x01, 0x00, 0b1100_0001],              // non-zero Required Insert Count
            [0x00, 0x80, 0b1100_0001],              // Sign bit set
            [0x00, 0x00, 0b1111_1111, 36],          // static index 99
            [0x00, 0x00, 0x50, 0x7F],               // truncated literal
            [0x00],                                 // truncated prefix
        ];

        byte[] buffer = new byte[64];
        TlsQuicQpackDecodedFieldLine[] lines = new TlsQuicQpackDecodedFieldLine[8];

        // Warm up, so JIT allocation is not counted.
        foreach (byte[] reject in rejects)
        {
            Assert.False(TlsQuicQpackDecoder.TryDecodeFieldSection(reject, buffer, lines, long.MaxValue, out _, out _, out _));
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100; i++)
        {
            foreach (byte[] reject in rejects)
            {
                TlsQuicQpackDecoder.TryDecodeFieldSection(reject, buffer, lines, long.MaxValue, out _, out _, out _);
            }
        }

        Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);
    }

    // ========================================================================
    // C15: RFC 9204 s4.4's decoder instructions
    // ========================================================================
    //
    // EXTERNALLY ANCHORED, and unusually well: Appendix B publishes all three instructions -
    // B.2's `84`, B.3's `01` and B.4's `48` - together with the parameter each carries. Both
    // halves are parsed out of the capture below, so neither the octet nor the number is
    // retyped here.
    //
    // ANCHORED IS NOT ENOUGH, and C14's rows 5-7 are why: three prefix-width mutants survived
    // its entire Appendix B walk because every literal the RFC publishes sits below the
    // narrower mask. The published parameters here are 4, 1 and 8 - all far below every prefix
    // boundary in s4.4 - so the capture cannot witness a width error either. The boundary
    // vectors further down are hand-derived from RFC 7541 s5.1's pseudocode for exactly that
    // gap, one straddling pair per prefix.

    [Fact]
    public void TheThreeDecoderInstructionsAppendixBPublishesAreReproduced()
    {
        (byte[] ack, ulong ackStream) = AppendixBDecoderInstruction("B.2", @"Section Acknowledgment \(stream=(?<n>\d+)\)");
        (byte[] increment, ulong incrementValue) = AppendixBDecoderInstruction("B.3", @"Insert Count Increment \((?<n>\d+)\)");
        (byte[] cancel, ulong cancelStream) = AppendixBDecoderInstruction("B.4", @"Stream Cancellation \(Stream=(?<n>\d+)\)");

        var stream = new TlsQuicQpackDecoderStream();
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];

        // B.2's section on stream 4 declares Required Insert Count 2; the capture's own prefix
        // annotation is what says so.
        (ulong requiredInsertCount, _) = AppendixBSectionPrefixAnnotation("B.2");
        Assert.True(stream.TryWriteSectionAcknowledgment(ackStream, requiredInsertCount, destination, out int written));
        Assert.Equal(ack, destination[..written]);

        // s2.1.4: the acknowledgment raised the Known Received Count to that section's
        // Required Insert Count.
        Assert.Equal(requiredInsertCount, stream.KnownReceivedCount);

        // B.3 inserts a THIRD entry and the published Increment is 1, not 3. That difference
        // is the whole of s2.2.2.3's "replace them entirely with Section Acknowledgments": a
        // decoder that did not track the Known Received Count would send 3 here.
        Assert.True(stream.TryWriteInsertCountIncrement(3, destination, out written));
        Assert.Equal(increment, destination[..written]);
        Assert.Equal(incrementValue, 3 - requiredInsertCount);
        Assert.Equal(3ul, stream.KnownReceivedCount);

        // B.4 cancels stream 8. s2.2.2.2: "An encoder cannot infer from this instruction that
        // any updates to the dynamic table have been received", so the count does not move.
        Assert.True(stream.TryWriteStreamCancellation(cancelStream, destination, out written));
        Assert.Equal(cancel, destination[..written]);
        Assert.Equal(3ul, stream.KnownReceivedCount);
    }

    // s4.4.1's opening clause is a condition and not a description: "After processing an
    // encoded field section whose declared Required Insert Count is not zero, the decoder
    // emits a Section Acknowledgment instruction." A section that used no dynamic entry is NOT
    // acknowledged, and one acknowledged anyway refers to a stream on which every non-zero
    // Required Insert Count section has already been acknowledged - vacuously, since there
    // have been none - which s4.4.1 makes a QPACK_DECODER_STREAM_ERROR at the peer's encoder.
    //
    // A WITNESS PER BRANCH: one stream id, one Required Insert Count either side of the
    // boundary, so this cannot pass by never reaching the emitting arm.
    [Fact]
    public void ASectionWithARequiredInsertCountOfZeroIsNotAcknowledgedAndOneWithOneIs()
    {
        var stream = new TlsQuicQpackDecoderStream();
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];

        // Nothing to send, and NOT a failure - `true` with nothing written.
        Assert.True(stream.TryWriteSectionAcknowledgment(4, 0, destination, out int written));
        Assert.Equal(0, written);
        Assert.Equal(0ul, stream.KnownReceivedCount);

        // One is not zero. Stream id 4 on a 7-bit prefix: 4 < 127, so 0b1000_0000 | 4.
        Assert.True(stream.TryWriteSectionAcknowledgment(4, 1, destination, out written));
        Assert.Equal([0b1000_0100], destination[..written]);
        Assert.Equal(1ul, stream.KnownReceivedCount);
    }

    // s4.4.3: "An encoder that receives an Increment field equal to zero ... MUST treat this
    // as a connection error of type QPACK_DECODER_STREAM_ERROR." The suppression is the
    // subtraction: once an acknowledgment has pulled the Known Received Count up to the insert
    // count there is nothing left to increment by.
    [Fact]
    public void AZeroIncrementIsSuppressedAndANonZeroOneIsSent()
    {
        var stream = new TlsQuicQpackDecoderStream();
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];

        Assert.True(stream.TryWriteSectionAcknowledgment(4, 2, destination, out _));
        Assert.Equal(2ul, stream.KnownReceivedCount);

        // The table has inserted exactly what was acknowledged. The Increment would be 0.
        Assert.True(stream.TryWriteInsertCountIncrement(2, destination, out int written));
        Assert.Equal(0, written);
        Assert.Equal(2ul, stream.KnownReceivedCount);

        // One more insertion. 1 on a 6-bit prefix under the '00' pattern: 1 < 63, one octet.
        Assert.True(stream.TryWriteInsertCountIncrement(3, destination, out written));
        Assert.Equal([0b0000_0001], destination[..written]);
        Assert.Equal(3ul, stream.KnownReceivedCount);
    }

    // The Increment is a DIFFERENCE and not the running total, which is the one arithmetic
    // s4.4.3 states and which a "send what the table says" implementation gets wrong in a way
    // that still produces a well-formed instruction.
    [Fact]
    public void TheIncrementIsTheDifferenceAndNotTheTotal()
    {
        var stream = new TlsQuicQpackDecoderStream();
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];

        // 5 insertions, nothing acknowledged: Increment = 5 - 0 = 5.
        Assert.True(stream.TryWriteInsertCountIncrement(5, destination, out int written));
        Assert.Equal([0b0000_0101], destination[..written]);

        // 9 insertions in total now: Increment = 9 - 5 = 4, NOT 9.
        Assert.True(stream.TryWriteInsertCountIncrement(9, destination, out written));
        Assert.Equal([0b0000_0100], destination[..written]);
        Assert.Equal(9ul, stream.KnownReceivedCount);
    }

    // s2.1.4: "If the Required Insert Count of the acknowledged field section is GREATER than
    // the current Known Received Count, the Known Received Count is updated to that Required
    // Insert Count value." Greater, not different - s2.2.2.1 lets the encoder resolve an
    // acknowledgment against "the earliest unacknowledged field section" on a stream, so a
    // later acknowledgment can legitimately carry a smaller Required Insert Count. A plain
    // assignment passes every other row in this file and fails only here.
    [Fact]
    public void AnAcknowledgmentNeverWalksTheKnownReceivedCountBackwards()
    {
        var stream = new TlsQuicQpackDecoderStream();
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];

        Assert.True(stream.TryWriteSectionAcknowledgment(4, 5, destination, out _));
        Assert.Equal(5ul, stream.KnownReceivedCount);

        // A smaller Required Insert Count on another stream. The instruction is still sent -
        // s4.4.1 has no suppression clause for this - but the count does not fall.
        Assert.True(stream.TryWriteSectionAcknowledgment(8, 3, destination, out int written));
        Assert.NotEqual(0, written);
        Assert.Equal(5ul, stream.KnownReceivedCount);

        // And the count having stayed at 5 is what suppresses the increment at 5.
        Assert.True(stream.TryWriteInsertCountIncrement(5, destination, out written));
        Assert.Equal(0, written);
    }

    // ========================================================================
    // C15: the three prefixes, straddled
    // ========================================================================
    //
    // Every expected byte below is derived from RFC 7541 s5.1's encoding pseudocode BY HAND
    // and not produced by this codebase and read back. The arithmetic is written out per row.

    // s4.4.1's Figure 9: '1' then a 7-bit prefix, so the prefix holds 2^7 - 1 = 127.
    //
    //   126:  126 < 127, one octet.      0b1000_0000 | 126 = 0xFE
    //   127:  127 == 127, does not fit.  0b1000_0000 | 127 = 0xFF
    //         then 127 - 127 = 0, < 128:                     0x00
    //   128:  0xFF, then 128 - 127 = 1:                      0x01
    //   254:  0xFF, then 254 - 127 = 127, < 128:             0x7F
    //   255:  0xFF, then 255 - 127 = 128, >= 128:
    //           128 % 128 + 128 = 128 -> 0x80; 128 / 128 = 1 -> 0x01.
    //
    // 126 AND 127 ARE THE POINT. At a 6-bit prefix, 126 becomes 0xBF 0x3F and 127 becomes
    // 0xBF 0x40, so the pair separates 7 from 6 - which B.2's published stream id of 4 does
    // not, since 4 sits below both masks exactly as C14's row 5 literal did.
    [Theory]
    [InlineData(126ul, new byte[] { 0xFE })]
    [InlineData(127ul, new byte[] { 0xFF, 0x00 })]
    [InlineData(128ul, new byte[] { 0xFF, 0x01 })]
    [InlineData(254ul, new byte[] { 0xFF, 0x7F })]
    [InlineData(255ul, new byte[] { 0xFF, 0x80, 0x01 })]
    public void TheSectionAcknowledgmentPrefixIsSevenBitsWide(ulong streamId, byte[] expected)
    {
        var stream = new TlsQuicQpackDecoderStream();
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];

        Assert.True(stream.TryWriteSectionAcknowledgment(streamId, 1, destination, out int written));
        Assert.Equal(expected, destination[..written]);
    }

    // s4.4.2's Figure 10: '01' then a 6-bit prefix, so the prefix holds 2^6 - 1 = 63.
    //
    //   62:   62 < 63, one octet.      0b0100_0000 | 62 = 0x7E
    //   63:   63 == 63, does not fit.  0b0100_0000 | 63 = 0x7F, then 63 - 63 = 0 -> 0x00
    //   64:   0x7F, then 64 - 63 = 1 -> 0x01
    //   190:  0x7F, then 190 - 63 = 127, < 128 -> 0x7F
    //   191:  0x7F, then 191 - 63 = 128, >= 128 -> 0x80 then 0x01
    [Theory]
    [InlineData(62ul, new byte[] { 0x7E })]
    [InlineData(63ul, new byte[] { 0x7F, 0x00 })]
    [InlineData(64ul, new byte[] { 0x7F, 0x01 })]
    [InlineData(190ul, new byte[] { 0x7F, 0x7F })]
    [InlineData(191ul, new byte[] { 0x7F, 0x80, 0x01 })]
    public void TheStreamCancellationPrefixIsSixBitsWide(ulong streamId, byte[] expected)
    {
        var stream = new TlsQuicQpackDecoderStream();
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];

        Assert.True(stream.TryWriteStreamCancellation(streamId, destination, out int written));
        Assert.Equal(expected, destination[..written]);
    }

    // s4.4.3's Figure 11: '00' then a 6-bit prefix. The pattern contributes NO set bits, which
    // makes this the one of the three where a wider mutant prefix does not collide with the
    // opcode and so would encode silently: at 7 bits, 63 becomes the single octet 0x3F instead
    // of 0x3F 0x00. That is why 63 is here and why it is the row that turns on it.
    //
    //   62:   62 < 63, one octet.      0b0000_0000 | 62 = 0x3E
    //   63:   63 == 63, does not fit.  0b0000_0000 | 63 = 0x3F, then 63 - 63 = 0 -> 0x00
    //   64:   0x3F, then 64 - 63 = 1 -> 0x01
    //   191:  0x3F, then 191 - 63 = 128, >= 128 -> 0x80 then 0x01
    [Theory]
    [InlineData(62ul, new byte[] { 0x3E })]
    [InlineData(63ul, new byte[] { 0x3F, 0x00 })]
    [InlineData(64ul, new byte[] { 0x3F, 0x01 })]
    [InlineData(191ul, new byte[] { 0x3F, 0x80, 0x01 })]
    public void TheInsertCountIncrementPrefixIsSixBitsWide(ulong increment, byte[] expected)
    {
        var stream = new TlsQuicQpackDecoderStream();
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];

        Assert.True(stream.TryWriteInsertCountIncrement(increment, destination, out int written));
        Assert.Equal(expected, destination[..written]);
    }

    // The three opcodes are a PREFIX TREE, so what has to hold is that no instruction of one
    // kind can be read as another. Swept rather than checked at one value, because the pattern
    // bits and the prefix width interact: a Stream Cancellation whose pattern was mistyped as
    // 0b1000_0000 reads as a Section Acknowledgment for EVERY stream id, and a single-value
    // test catches that only by luck.
    [Fact]
    public void NoInstructionOfOneKindCanBeReadAsAnother()
    {
        var stream = new TlsQuicQpackDecoderStream();
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];

        for (ulong value = 0; value < 300; value++)
        {
            Assert.True(stream.TryWriteStreamCancellation(value, destination, out int cancelled));
            Assert.Equal(0b0100_0000, destination[0] & 0b1100_0000);

            Assert.True(stream.TryWriteSectionAcknowledgment(value, value + 1, destination, out int acked));
            Assert.Equal(0b1000_0000, destination[0] & 0b1000_0000);

            // The increment is derived, so it has to outrun the count the line above just set.
            Assert.True(stream.TryWriteInsertCountIncrement(
                stream.KnownReceivedCount + value + 1, destination, out int incremented));
            Assert.Equal(0b0000_0000, destination[0] & 0b1100_0000);

            Assert.All(
                [cancelled, acked, incremented],
                length => Assert.InRange(length, 1, TlsQuicQpackDecoderStream.MaximumInstructionLength));
        }
    }

    // A destination too short is the ONLY false these three return, and it must leave the
    // object untouched: a Known Received Count raised for an instruction that was never
    // written desynchronises s2.1.4 permanently and nothing downstream can notice.
    [Fact]
    public void AShortDestinationIsRefusedAndMovesNothing()
    {
        var stream = new TlsQuicQpackDecoderStream();

        Assert.False(stream.TryWriteSectionAcknowledgment(4, 2, [], out int written));
        Assert.Equal(0, written);
        Assert.Equal(0ul, stream.KnownReceivedCount);

        Assert.False(stream.TryWriteInsertCountIncrement(7, [], out written));
        Assert.Equal(0, written);
        Assert.Equal(0ul, stream.KnownReceivedCount);

        Assert.False(stream.TryWriteStreamCancellation(4, [], out written));
        Assert.Equal(0, written);

        // The same calls against a sufficient destination still work, so the refusals above
        // were about the buffer and not about the state.
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];
        Assert.True(stream.TryWriteSectionAcknowledgment(4, 2, destination, out written));
        Assert.Equal([0b1000_0100], destination[..written]);
        Assert.Equal(2ul, stream.KnownReceivedCount);
    }

    // ========================================================================
    // C15: a field section that really references C14's table
    // ========================================================================

    // B.2's stream 4, decoded against the table B.2's own encoder stream builds. Post-Base
    // indexing throughout - "Absolute Index = Base(0) + Index(0)" - which is the one of s3.2's
    // three modes that ADDS, and the only field section in the RFC that uses it.
    [Fact]
    public void AppendixB2sFieldSectionDecodesAgainstTheTableItsEncoderStreamBuilt()
    {
        var table = new TlsQuicQpackDynamicTable(CaptureMaximumCapacity);
        FeedEncoderStream(table, "B.2");
        Assert.Equal(2ul, table.InsertCount);

        (ulong expectedRequiredInsertCount, ulong expectedBase) = AppendixBSectionPrefixAnnotation("B.2");
        (var fields, ulong requiredInsertCount) = DecodeAgainst(AppendixBFieldSection("B.2"), table);

        Assert.Equal(expectedRequiredInsertCount, requiredInsertCount);
        Assert.Equal(AppendixBFieldAnnotations("B.2"), fields);

        // B.2's prefix is `0381`: the Sign bit is SET and Delta Base is 1, so this is
        // s4.5.1.2's SUBTRACTING arm - Base = 2 - 1 - 1 = 0 - which is the arm the static-only
        // decoder rejects outright and which no other vector in the RFC exercises.
        Assert.Equal(0ul, expectedBase);
    }

    // B.4's stream 8, which mixes the modes that matter: a field-relative dynamic reference, a
    // STATIC one, and another field-relative one, all under a non-zero Base.
    //
    // DELIBERATELY OUT OF B.4'S NARRATIVE ORDER. B.4 delays the encoder packet and cancels the
    // stream before it arrives, so in the RFC's telling this section is never decoded at all.
    // Blocking on a late encoder stream is s2.2.1's and the plan gives it to C16; what is
    // checked here is that the octets B.4 publishes resolve against the table B.4's own
    // instructions produce, which is a claim about indexing and not about arrival order.
    [Fact]
    public void AppendixB4sFieldSectionDecodesAgainstTheTableItsEncoderStreamBuilt()
    {
        var table = new TlsQuicQpackDynamicTable(CaptureMaximumCapacity);
        FeedEncoderStream(table, "B.2");
        FeedEncoderStream(table, "B.3");
        FeedEncoderStream(table, "B.4");
        Assert.Equal(4ul, table.InsertCount);

        (ulong expectedRequiredInsertCount, ulong expectedBase) = AppendixBSectionPrefixAnnotation("B.4");
        (var fields, ulong requiredInsertCount) = DecodeAgainst(AppendixBFieldSection("B.4"), table);

        Assert.Equal(expectedRequiredInsertCount, requiredInsertCount);
        Assert.Equal(4ul, expectedBase);
        Assert.Equal(AppendixBFieldAnnotations("B.4"), fields);

        // And this section is acknowledgeable BECAUSE its Required Insert Count is not zero,
        // which is the whole coupling between this file's two halves.
        var stream = new TlsQuicQpackDecoderStream();
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];
        Assert.True(stream.TryWriteSectionAcknowledgment(8, requiredInsertCount, destination, out int written));
        Assert.NotEqual(0, written);
        Assert.Equal(requiredInsertCount, stream.KnownReceivedCount);
    }

    // s4.5.1.1's own worked example, which is the ONLY published vector for the wrapping arm:
    // "if the dynamic table is 100 bytes, then the Required Insert Count will be encoded
    // modulo 6. If a decoder has received 10 inserts, then an encoded value of 4 indicates
    // that the Required Insert Count is 9 for the field section."
    //
    // NEITHER B.2 NOR B.4 REACHES THAT ARM. Both have MaxWrapped = 0 and both take the
    // Required Insert Count straight from EncodedInsertCount - 1, so an implementation that
    // dropped the wrap entirely still reproduces the whole appendix. This is the blind spot
    // the capture cannot witness, and 100 / 10 / 4 is the RFC filling it in itself.
    //
    //   MaxEntries = floor(100 / 32) = 3;  FullRange = 6
    //   MaxValue   = 10 + 3 = 13
    //   MaxWrapped = floor(13 / 6) * 6 = 2 * 6 = 12
    //   candidate  = 12 + 4 - 1 = 15, which is > 13; 15 > 6, so 15 - 6 = 9.
    [Fact]
    public void TheWorkedExampleInSection4511ReconstructsAWrappedRequiredInsertCount()
    {
        string capture = File.ReadAllText(QpackCaptures.Path("rfc9204-section4.5-field-line-representations.txt"));
        // EVERY GAP IS \s+, NOT A SPACE. The capture is hard-wrapped at ~72 columns and this
        // sentence wraps twice - between "received 10" and "inserts", and between "the
        // Required" and "Insert Count is 9". A pattern written with literal spaces matches
        // neither, which is the standing rule about reading past the wrap, in a regex.
        Match example = Regex.Match(
            capture,
            @"if\s+the\s+dynamic\s+table\s+is\s+(?<bytes>\d+)\s+bytes.*?"
                + @"decoder\s+has\s+received\s+(?<inserts>\d+)\s+inserts,\s+then\s+an\s+encoded\s+"
                + @"value\s+of\s+(?<encoded>\d+)\s+indicates\s+that\s+the\s+Required\s+"
                + @"Insert\s+Count\s+is\s+(?<required>\d+)",
            RegexOptions.Singleline);
        Assert.True(example.Success, "s4.5.1.1's worked example was not found in the capture.");

        int capacity = int.Parse(example.Groups["bytes"].Value);
        int inserts = int.Parse(example.Groups["inserts"].Value);
        ulong encoded = ulong.Parse(example.Groups["encoded"].Value);
        ulong required = ulong.Parse(example.Groups["required"].Value);

        var table = new TlsQuicQpackDynamicTable(capacity);
        InsertEmptyEntries(table, capacity, inserts);
        Assert.Equal((ulong)inserts, table.InsertCount);

        Assert.Equal(required, RequiredInsertCountOf(table, encoded));

        // The neighbours differ by one in the same direction, so this is not passing on a
        // constant: encoded 3 and 5 reconstruct to 8 and 10 by the same arithmetic.
        Assert.Equal(required - 1, RequiredInsertCountOf(table, encoded - 1));
        Assert.Equal(required + 1, RequiredInsertCountOf(table, encoded + 1));
    }

    // s4.5.1.1: "if EncodedInsertCount > FullRange: Error". A value no conformant encoder
    // could have produced MUST be a connection error rather than something decoded to a
    // plausible number. FullRange here is 2 * floor(100 / 32) = 6, so 7 is the first refused.
    [Fact]
    public void AnEncodedInsertCountNoConformantEncoderCouldProduceIsRejected()
    {
        var table = new TlsQuicQpackDynamicTable(100);
        InsertEmptyEntries(table, 100, 10);

        // 6 IS THE LAST ACCEPTABLE VALUE, AND C16 CHANGED WHAT ACCEPTABLE LOOKS LIKE HERE. It
        // reconstructs to a Required Insert Count of 11 against an Insert Count of 10, so
        // s2.2.1 now BLOCKS it rather than answering None. Blocked is not a rejection - it is
        // the "not yet" this whole task added - so the pair below still straddles the same
        // boundary: 6 is a value a conformant encoder could have produced and 7 is not.
        Assert.Equal(TlsQuicQpackError.Blocked, ErrorAgainst([6, 0x00], table));
        Assert.Equal(
            TlsQuicQpackError.RequiredInsertCountNotEncodable, ErrorAgainst([7, 0x00], table));

        // s4.5.1.1's LAST guard: "Value of 0 must be encoded as 0." A non-zero
        // EncodedInsertCount that reconstructs to zero is a value no conformant encoder
        // produces, and without this arm it would decode as a section that referenced nothing.
        //
        // REACHING IT NEEDS AN INSERT COUNT BELOW MaxEntries, which is why no test above gets
        // there: candidate is zero only when MaxWrapped is zero AND EncodedInsertCount is 1,
        // and MaxWrapped is zero only while MaxValue < FullRange, i.e. InsertCount < 3 here.
        //   fresh table: MaxValue = 0 + 3 = 3;  MaxWrapped = floor(3 / 6) * 6 = 0
        //                candidate = 0 + 1 - 1 = 0, which is not > 3, so the zero arm decides.
        var fresh = new TlsQuicQpackDynamicTable(100);
        Assert.Equal(0ul, fresh.InsertCount);
        Assert.Equal(
            TlsQuicQpackError.RequiredInsertCountNotEncodable, ErrorAgainst([0x01, 0x00], fresh));

        // And 2 at the same insert count is a Required Insert Count of 1, which is legal - so
        // the arm above rejects one specific value rather than the whole low end. Against an
        // Insert Count of 0 that legal count is one C16 BLOCKS on rather than rejects, which
        // is the difference this whole task turns on: the octet is fine and the table is not
        // ready, and the reconstruction still reports 1 either way.
        Assert.Equal(TlsQuicQpackError.Blocked, ErrorAgainst([0x02, 0x00], fresh));
        Assert.Equal(1ul, RequiredInsertCountOf(fresh, 2));

        // A maximum capacity below one entry makes MaxEntries and FullRange both zero, so
        // every non-zero encoded count is refused - AND THE REFUSAL HAPPENS BEFORE the
        // division that would otherwise be by zero. A zero one still decodes, to zero.
        var tiny = new TlsQuicQpackDynamicTable(31);
        Assert.Equal(TlsQuicQpackError.None, ErrorAgainst([0x00, 0x00], tiny));
        Assert.Equal(
            TlsQuicQpackError.RequiredInsertCountNotEncodable, ErrorAgainst([0x01, 0x00], tiny));
    }

    // s4.5.1.1's MaxValue is "TotalNumberOfInserts + MaxEntries", and the MaxEntries term is
    // what lets a Required Insert Count AHEAD of our own inserts reconstruct - which is the
    // whole point of the field, since s2.2.1's blocked decoding exists precisely because the
    // encoder may reference entries whose insertions have not reached us yet.
    //
    // NO PUBLISHED VECTOR REACHES IT. B.2 and B.4 both have MaxWrapped = 0 either way, and
    // s4.5.1.1's worked example lands on 9 with the term and 9 without it, so a MaxValue of
    // just TotalNumberOfInserts survives every one of them. This is the arithmetic that
    // separates them:
    //
    //   capacity 100 -> MaxEntries 3, FullRange 6; 10 inserts; EncodedInsertCount 1.
    //   correct:  MaxValue = 13, MaxWrapped = floor(13 / 6) * 6 = 12, ReqInsertCount = 12.
    //   without:  MaxValue = 10, MaxWrapped = floor(10 / 6) * 6 =  6, ReqInsertCount =  6.
    //
    // And 12 is the right answer: (12 mod 6) + 1 = 1 is exactly what s4.5.1.1's encoder
    // transform produces for a Required Insert Count of 12.
    [Fact]
    public void ARequiredInsertCountAheadOfOurOwnInsertsStillReconstructs()
    {
        var table = new TlsQuicQpackDynamicTable(100);
        InsertEmptyEntries(table, 100, 10);

        Assert.Equal(12ul, RequiredInsertCountOf(table, 1));

        // It reconstructs, and it is NOT yet decodable against the table - 12 references
        // entries 10 and 11, which have not arrived. s2.2.1 says such a stream becomes
        // BLOCKED, and C16 REPLACED THE GAP THIS ASSERTION USED TO RECORD: the answer was
        // DynamicTableReference, a rejection, and is now Blocked, a "not yet" that
        // TryGetHttp3ErrorCode refuses to map to a connection error at all.
        Assert.Equal(10ul, table.InsertCount);
        Assert.Equal(TlsQuicQpackError.Blocked, ErrorAgainst([1, 0x00, 0b1000_0000], table));
        Assert.False(TlsQuicQpackDecoder.TryGetHttp3ErrorCode(TlsQuicQpackError.Blocked, out _));
    }

    // s4.5.1.2's ADDING arm: "if Sign == 0: Base = ReqInsertCount + DeltaBase".
    //
    // EVERY PUBLISHED VECTOR SETS DELTA BASE TO ZERO, which is not an accident - s4.5.1.2 says
    // "setting Delta Base to zero is one of the most efficient encodings" - so B.4's `0500`
    // and every prefix in the tests above put the Base at the Required Insert Count whether or
    // not Delta Base is added at all. A non-zero one is needed to see the addition happen.
    //
    //   Required Insert Count 14 encodes as (14 mod 4096) + 1 = 15.
    //   Sign 0, Delta Base 2 on a 7-bit prefix: 2 < 127, so the octet is 0x02.
    //   Base = 14 + 2 = 16, so s4.5.2's relative 0 is absolute 16 - 0 - 1 = 15.
    //   Ignoring Delta Base leaves Base at 14 and resolves absolute 13 instead - a different
    //   entry, and a plausible one, which is the failure that matters.
    [Fact]
    public void AClearSignBitAddsDeltaBaseToTheRequiredInsertCount()
    {
        var table = new TlsQuicQpackDynamicTable(CaptureMaximumCapacity);
        InsertNumberedEntries(table, 16);

        // C16 CHANGED THIS VECTOR, AND THE OLD ONE WAS NOT CONFORMANT. It read relative index
        // 0 against a Base of 16, which is absolute 15 - one ABOVE the Required Insert Count
        // of 14 that the same prefix declared. s2.1.2 makes the count "one larger than the
        // largest absolute index of all referenced dynamic table entries", so no conformant
        // encoder emits that pair and s2.2.3's MUST now refuses it. The addition is witnessed
        // here instead by holding the RELATIVE index fixed and moving Delta Base: at index 2 a
        // Base of 16 resolves absolute 13, and a Base of 14 resolves absolute 11.
        (var fields, ulong requiredInsertCount) = DecodeAgainst([15, 0x02, 0x82], table);
        Assert.Equal(14ul, requiredInsertCount);
        Assert.Equal([("n13", "v13")], fields);

        // Delta Base 0 at the same Required Insert Count puts the Base at 14 and resolves the
        // entry two rows earlier, so the pair pins the addition rather than one value of it.
        Assert.Equal([("n11", "v11")], DecodeLinesAgainst([15, 0x00, 0x82], table));
    }

    // s4.5.3's Figure 14 gives the post-Base index a 4-bit prefix; s4.5.5's Figure 16 gives it
    // a 3-bit one, because s4.5.5 spends a bit on 'N' and s4.5.3 has none. Two neighbouring
    // widths on two representations one bit apart in their opcode is exactly the shape C14's
    // rows 5-7 died of, so each gets a vector that STRADDLES its own boundary.
    //
    //   s4.5.3, pattern '0001', 4-bit prefix, mask 15:
    //     index 14:  14 < 15, one octet.  0b0001_0000 | 14 = 0x1E
    //                At 3 bits that octet reads 0x1E & 0x07 = 6; at 5 bits, 30. Both wrong.
    //     index 15:  fills.               0b0001_1111 = 0x1F, then 15 - 15 = 0 -> 0x00
    //
    //   s4.5.5, pattern '0000' then 'N', 3-bit prefix, mask 7:
    //     index 6 with N SET:  0b0000_1000 | 6 = 0x0E, and 6 < 7 so one octet.
    //       THE 'N' BIT IS THE STRADDLE. With N clear the octet is 0x06 and a 4-bit prefix
    //       reads 6 as well - identical, exactly as C14's row 5 found. With N SET, a 4-bit
    //       prefix reads 0x0E & 0x0F = 14 and resolves a different entry entirely.
    //     index 7 with N set:  fills.     0b0000_1111 = 0x0F, then 7 - 7 = 0 -> 0x00
    [Fact]
    public void ThePostBasePrefixesAreFourBitsAndThreeBitsAndTheNBitStraddlesTheNarrower()
    {
        // Sixteen entries so that indices 6, 7, 14 and 15 all resolve to DIFFERENT known rows
        // and a misread yields a wrong field rather than a rejection - the failure mode
        // s4.5.2's own source comment names as the dangerous one.
        var table = new TlsQuicQpackDynamicTable(CaptureMaximumCapacity);
        InsertNumberedEntries(table, 16);

        // Required Insert Count 16 encodes as (16 mod 4096) + 1 = 17. Delta Base 0 with a
        // clear Sign bit would put the Base at 16, so the Sign bit is SET with Delta Base 15:
        // Base = 16 - 15 - 1 = 0, and then every post-Base index is Base + index = index.
        byte[] prefix = [17, 0b1000_1111];

        Assert.Equal([("n14", "v14")], DecodeLinesAgainst([.. prefix, 0x1E], table));
        Assert.Equal([("n15", "v15")], DecodeLinesAgainst([.. prefix, 0x1F, 0x00], table));

        // s4.5.5 carries a literal value after the name reference: an 8-bit prefix string
        // literal with H clear, length 1, then 'x'.
        Assert.Equal([("n6", "x")], DecodeLinesAgainst([.. prefix, 0x0E, 0x01, (byte)'x'], table));
        Assert.Equal([("n7", "x")], DecodeLinesAgainst([.. prefix, 0x0F, 0x00, 0x01, (byte)'x'], table));

        // And the two representations really are told apart by that one bit: 0x1E is s4.5.3
        // and takes its value from the TABLE, 0x0E is s4.5.5 and takes it from the WIRE. If
        // both had been routed to one branch, 0x1E would need a trailing literal too.
        Assert.Equal(TlsQuicQpackError.None, ErrorAgainst([.. prefix, 0x1E], table));
    }

    // s4.5.2 with T = 0 and s4.5.4 with T = 0 resolve against the Base by SUBTRACTING -
    // s3.2.5's "a relative index of 0 refers to the entry with absolute index equal to
    // Base - 1" - the opposite direction from the post-Base pair above. B.4 witnesses s4.5.2;
    // s4.5.4's dynamic arm has no published vector at all, so it is derived here.
    [Fact]
    public void ADynamicNameReferenceTakesOnlyTheNameFromTheTable()
    {
        var table = new TlsQuicQpackDynamicTable(CaptureMaximumCapacity);
        InsertNumberedEntries(table, 16);

        // Required Insert Count 16 encoded as 17; Sign clear, Delta Base 0, so Base = 16.
        byte[] prefix = [17, 0b0000_0000];

        // s4.5.4, Figure 15: '01', N = 0, T = 0, then the name index on a 4-bit prefix.
        // Relative index 1 -> absolute Base(16) - 1 - 1 = 14. Then the value as an 8-bit
        // prefix string literal: H clear, length 1, 'x'.   0b0100_0000 | 1 = 0x41
        Assert.Equal([("n14", "x")], DecodeLinesAgainst([.. prefix, 0x41, 0x01, (byte)'x'], table));

        // s4.5.2, Figure 13: '1', T = 0, then the index on a 6-bit prefix. Relative index 0 ->
        // absolute 15, and BOTH name and value come from the table.   0b1000_0000 | 0 = 0x80
        Assert.Equal([("n15", "v15")], DecodeLinesAgainst([.. prefix, 0x80], table));

        // The same octet with T SET is STATIC index 0, a different field entirely. This is the
        // misread s4.5.2's source comment names, made visible.
        Assert.Equal([(":authority", "")], DecodeLinesAgainst([.. prefix, 0b1100_0000], table));
    }

    // s2.2.3 makes an unresolvable reference in a field section a connection error rather than
    // something to skip, and there are three shapes that can be unresolvable. All three are
    // refused, and refused as a PEER error rather than as a local sizing answer.
    //
    // C16 SPLIT TWO OF THE THREE ONTO A DIFFERENT MEMBER, and the split is the point rather
    // than an inconvenience. s2.2.3 names two defects in one sentence - a reference to an
    // entry "that has already been evicted" and one "that has an absolute index greater than
    // or equal to the declared Required Insert Count" - and the second is checked BEFORE the
    // lookup, so a post-Base index at the Base of a section declaring that same count is now
    // refused for naming an index it had no right to name rather than for the entry being
    // absent. Both still map to QPACK_DECOMPRESSION_FAILED, which the assertions at the foot
    // of this test check for both members; what changed is what a failing test tells you.
    [Fact]
    public void AReferenceThatResolvesToNoEntryIsRejected()
    {
        var table = new TlsQuicQpackDynamicTable(CaptureMaximumCapacity);
        InsertNumberedEntries(table, 16);
        byte[] prefix = [17, 0b0000_0000]; // Required Insert Count 16, Base 16.

        // A field-relative index AT the Base underflows: Base(16) - 16 - 1 would be negative.
        // 0b1001_0000 is s4.5.2 with T = 0 and a 6-bit index of 16.
        Assert.Equal(TlsQuicQpackError.DynamicTableReference, ErrorAgainst([.. prefix, 0b1001_0000], table));

        // A post-Base index past the insertion point: Base(16) + 0 = 16, which is the index
        // the NEXT insert will take and so is not present - and which is also AT the declared
        // Required Insert Count of 16, so C16's bound reaches it first.
        Assert.Equal(
            TlsQuicQpackError.ReferenceAtOrAboveRequiredInsertCount,
            ErrorAgainst([.. prefix, 0b0001_0000], table));

        // A post-Base NAME reference past the insertion point: same arithmetic, other opcode.
        Assert.Equal(
            TlsQuicQpackError.ReferenceAtOrAboveRequiredInsertCount,
            ErrorAgainst([.. prefix, 0b0000_0000, 0x01, (byte)'x'], table));

        // s6 gives all three the same code, and it is a connection error - which is what says
        // C16's split renamed an answer without changing any wire behaviour.
        Assert.True(TlsQuicQpackDecoder.TryGetHttp3ErrorCode(TlsQuicQpackError.DynamicTableReference, out ulong code));
        Assert.Equal(TlsQuicQpackDecoder.QpackDecompressionFailed, code);
        Assert.True(TlsQuicQpackDecoder.TryGetHttp3ErrorCode(
            TlsQuicQpackError.ReferenceAtOrAboveRequiredInsertCount, out ulong aboveCode));
        Assert.Equal(TlsQuicQpackDecoder.QpackDecompressionFailed, aboveCode);
    }

    // THE NULL ARM IS UNCHANGED, which is the claim the live path still rests on: C15 added a
    // second arm, it did not relax the first. Every dynamic shape that now resolves against a
    // table is still refused without one, and refused for the same reason as before.
    [Fact]
    public void WithoutATableEveryDynamicShapeIsStillRejected()
    {
        var table = new TlsQuicQpackDynamicTable(CaptureMaximumCapacity);
        InsertNumberedEntries(table, 16);

        byte[][] shapes =
        [
            [17, 0b0000_0000, 0b1000_0000],            // s4.5.2, T = 0, relative 0
            [17, 0b0000_0000, 0x41, 0x01, (byte)'x'],  // s4.5.4, T = 0, relative 1
            [17, 0b1000_1111, 0x1E],                   // s4.5.3, post-Base 14
            [17, 0b1000_1111, 0x0E, 0x01, (byte)'x'],  // s4.5.5, post-Base name 6
        ];

        foreach (byte[] shape in shapes)
        {
            Assert.Equal(TlsQuicQpackError.None, ErrorAgainst(shape, table));

            // Without a table the Required Insert Count is refused before the representation
            // is ever reached, which is the older and blunter rejection.
            Assert.Equal(TlsQuicQpackError.RequiredInsertCountNotZero, ErrorFrom(shape));

            // With a zero/zero prefix in front, each shape is then refused for what it IS.
            byte[] atZero = [0x00, 0x00, .. shape.AsSpan(2)];
            Assert.Equal(TlsQuicQpackError.DynamicTableReference, ErrorFrom(atZero));
        }
    }

    // NOTHING ON THE TABLE ARM THROWS EITHER. The static-only arm's guarantee is stated at the
    // top of the source; adding four resolving branches and two new integer reads is exactly
    // the change that could break it, so it is re-swept with a table in place.
    [Fact]
    public void NoInputThrowsAgainstATable()
    {
        var table = new TlsQuicQpackDynamicTable(CaptureMaximumCapacity);
        InsertNumberedEntries(table, 16);

        byte[] buffer = new byte[4096];
        var lines = new TlsQuicQpackDecodedFieldLine[64];

        // Every one-, two- and three-octet input. 256 + 65536 + a sample of three-octet ones
        // would be slow; the first two are exhaustive and the third sweeps the opcode octet
        // against a fixed tail, which is where the new branches live.
        for (int first = 0; first < 256; first++)
        {
            Decode([(byte)first]);
            for (int second = 0; second < 256; second++)
            {
                Decode([(byte)first, (byte)second]);
                Decode([17, (byte)first, (byte)second]);
                Decode([17, 0b1000_1111, (byte)first, (byte)second]);
            }
        }

        void Decode(byte[] source) =>
            TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
                source, buffer, lines, long.MaxValue, table, out _, out _, out _, out _);
    }

    // The rejecting path allocates zero bytes WITH A TABLE TOO. C8's row measures the
    // static-only arm; four resolving branches and a table lookup are exactly the change that
    // could put a boxed enumerator or a copied array on that path, and "it looks
    // allocation-free" is how one gets in.
    [Fact]
    public void TheRejectingPathAgainstATableAllocatesZeroBytes()
    {
        var table = new TlsQuicQpackDynamicTable(CaptureMaximumCapacity);
        InsertNumberedEntries(table, 16);

        byte[][] rejects =
        [
            [17, 0b0000_0000, 0b1001_0000],            // s4.5.2, T = 0, index past the Base
            [17, 0b0000_0000, 0b0001_0000],            // s4.5.3, post-Base past the insert point
            [17, 0b0000_0000, 0b0000_0000, 0x01, 0x61],// s4.5.5, same
            [17, 0b0000_0000, 0x4F, 0x01, 0x61],       // s4.5.4, T = 0, name index past the Base
            [0xFF, 0x82, 0x1E, 0x00],                  // EncodedInsertCount 4097, past FullRange
            [17, 0x90],                                // Sign set with Delta Base 16 >= Required 16
            [17],                                      // truncated prefix
        ];

        byte[] buffer = new byte[256];
        var lines = new TlsQuicQpackDecodedFieldLine[8];

        foreach (byte[] reject in rejects)
        {
            Assert.False(TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
                reject, buffer, lines, long.MaxValue, table, out _, out _, out _, out _));
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100; i++)
        {
            foreach (byte[] reject in rejects)
            {
                TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
                    reject, buffer, lines, long.MaxValue, table, out _, out _, out _, out _);
            }
        }

        Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);
    }

    // The three writers are total over a ulong, which is wider than RFC 9000 s16's varint can
    // carry - so the largest value any of them can be handed still has to fit
    // MaximumInstructionLength rather than run off the end of the caller's span.
    //
    // ulong.MaxValue on a 7-bit prefix: 0xFF, then 2^64 - 1 - 127 spread seven bits at a time.
    // floor(log128(2^64)) = 9, so nine continuation octets and a terminator: 1 + 9 + 1 = 11,
    // which is MaximumIntegerEncodedLength exactly. There is no slack, which is the point.
    [Fact]
    public void TheLargestPossibleParameterStillFitsTheInstructionBuffer()
    {
        var stream = new TlsQuicQpackDecoderStream();
        byte[] destination = new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];

        Assert.True(stream.TryWriteSectionAcknowledgment(ulong.MaxValue, 1, destination, out int acked));
        Assert.Equal(TlsQuicQpackDecoderStream.MaximumInstructionLength, acked);

        Assert.True(stream.TryWriteStreamCancellation(ulong.MaxValue, destination, out int cancelled));
        Assert.Equal(TlsQuicQpackDecoderStream.MaximumInstructionLength, cancelled);

        Assert.True(stream.TryWriteInsertCountIncrement(ulong.MaxValue, destination, out int incremented));
        Assert.Equal(TlsQuicQpackDecoderStream.MaximumInstructionLength, incremented);
        Assert.Equal(ulong.MaxValue, stream.KnownReceivedCount);

        // And once the count is at the top, the next increment is suppressed rather than
        // wrapping - the subtraction's other end, which no smaller value reaches.
        Assert.True(stream.TryWriteInsertCountIncrement(ulong.MaxValue, destination, out int again));
        Assert.Equal(0, again);
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    // s4.5.2 with T = 1 at an arbitrary index, built through the C5 integer encoder so the
    // continuation chain is not this test's guess.
    private static byte[] IndexedFieldLine(long index)
    {
        byte[] destination = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger((ulong)index, 6, 0b1100_0000, destination, out int written));
        return [.. Prefix, .. destination.AsSpan(0, written)];
    }

    private static TlsQuicQpackError ErrorFrom(ReadOnlySpan<byte> source, long maximum = long.MaxValue)
    {
        TlsQuicQpackDecoder.TryDecodeFieldSection(
            source,
            new byte[4096],
            new TlsQuicQpackDecodedFieldLine[64],
            maximum,
            out _,
            out _,
            out TlsQuicQpackError error);
        return error;
    }

    private static (string Name, string Value)[] Decode(byte[] source) =>
        TlsQuicQpackEncoderTests.Decode(source);

    // ------------------------------------------------------------------------
    // C15 helpers
    // ------------------------------------------------------------------------

    // The maximum capacity this stack advertises, read from the spec rather than typed, so
    // that s4.5.1.1's MaxEntries here is the one a real peer would compute. It is also what
    // makes the arithmetic in the tests above checkable: floor(65536 / 32) = 2048, FullRange
    // 4096, which is wider than every Required Insert Count Appendix B uses - which is exactly
    // why the wrapping arm needs s4.5.1.1's own worked example instead.
    private static int CaptureMaximumCapacity =>
        (int)TlsQuicHttp3Spec.CaptureSettings
            .Single(setting => setting.Identifier == TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier)
            .Value;

    // s4.5.1.1's reconstruction, observed through the only door there is: decode a field
    // section that is nothing BUT a prefix, and read the Required Insert Count it reports.
    // C16 MADE THIS TOLERATE Blocked, and the reason is the whole shape of s2.2.1's check. A
    // prefix declaring a count ahead of our Insert Count now answers Blocked - but the count
    // is reconstructed BEFORE that decision and is reported either way, which is precisely
    // what lets a caller park the section and re-present the same bytes. Blocked is not a
    // rejection, so accepting it here is not a loosened assertion; it names the second of the
    // two non-rejections this door can answer.
    private static ulong RequiredInsertCountOf(TlsQuicQpackDynamicTable table, ulong encodedInsertCount)
    {
        bool accepted = TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
            [(byte)encodedInsertCount, 0x00],
            new byte[64],
            new TlsQuicQpackDecodedFieldLine[4],
            long.MaxValue,
            table,
            out int lineCount,
            out _,
            out ulong requiredInsertCount,
            out TlsQuicQpackError error);

        Assert.Equal(accepted, error == TlsQuicQpackError.None);
        Assert.Contains(error, new[] { TlsQuicQpackError.None, TlsQuicQpackError.Blocked });
        Assert.Equal(0, lineCount);
        return requiredInsertCount;
    }

    private static ((string Name, string Value)[] Fields, ulong RequiredInsertCount) DecodeAgainst(
        byte[] source, TlsQuicQpackDynamicTable table)
    {
        byte[] buffer = new byte[4096];
        var lines = new TlsQuicQpackDecodedFieldLine[64];

        Assert.True(TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
            source,
            buffer,
            lines,
            long.MaxValue,
            table,
            out int lineCount,
            out _,
            out ulong requiredInsertCount,
            out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackError.None, error);

        var fields = new (string, string)[lineCount];
        for (int i = 0; i < lineCount; i++)
        {
            TlsQuicQpackDecodedFieldLine line = lines[i];
            fields[i] = (
                Encoding.ASCII.GetString(buffer, line.NameOffset, line.NameLength),
                Encoding.ASCII.GetString(buffer, line.ValueOffset, line.ValueLength));
        }

        return (fields, requiredInsertCount);
    }

    private static (string Name, string Value)[] DecodeLinesAgainst(
        byte[] source, TlsQuicQpackDynamicTable table) =>
        DecodeAgainst(source, table).Fields;

    private static TlsQuicQpackError ErrorAgainst(byte[] source, TlsQuicQpackDynamicTable table)
    {
        TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
            source,
            new byte[4096],
            new TlsQuicQpackDecodedFieldLine[64],
            long.MaxValue,
            table,
            out _,
            out _,
            out _,
            out TlsQuicQpackError error);
        return error;
    }

    // `count` entries whose names are n0..n{count-1} and values v0..v{count-1}, inserted
    // through s4.3.3's Insert With Literal Name so that C14's table does the inserting and
    // this helper only supplies bytes. Distinct names because a misread index must produce a
    // WRONG field rather than a plausible one.
    private static void InsertNumberedEntries(TlsQuicQpackDynamicTable table, int count)
    {
        SetCapacity(table, table.MaximumCapacity);
        for (int i = 0; i < count; i++)
        {
            InsertLiteral(table, $"n{i}", $"v{i}");
        }

        Assert.Equal((ulong)count, table.InsertCount);
    }

    // `count` insertions of the SMALLEST entry there is - s4.5.1.1's "The smallest entry has
    // empty name and value strings and has the size of 32" - which is how a 100-byte table
    // reaches an Insert Count of 10 while holding at most three entries at a time.
    private static void InsertEmptyEntries(TlsQuicQpackDynamicTable table, int capacity, int count)
    {
        SetCapacity(table, capacity);
        for (int i = 0; i < count; i++)
        {
            InsertLiteral(table, string.Empty, string.Empty);
        }
    }

    // s4.3.1's Set Dynamic Table Capacity: '001' then the capacity on a 5-bit prefix.
    private static void SetCapacity(TlsQuicQpackDynamicTable table, int capacity)
    {
        byte[] instruction = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger((ulong)capacity, 5, 0b0010_0000, instruction, out int written));
        Feed(table, instruction[..written]);
    }

    // s4.3.3's Insert With Literal Name: '01' then the name as a 6-bit prefix string literal,
    // then the value as an 8-bit prefix one.
    private static void InsertLiteral(TlsQuicQpackDynamicTable table, string name, string value)
    {
        byte[] instruction = new byte[128];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
            Encoding.ASCII.GetBytes(name), 6, 0b0100_0000, huffman: false, instruction, out int nameLength));
        Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
            Encoding.ASCII.GetBytes(value), 8, 0, huffman: false, instruction.AsSpan(nameLength), out int valueLength));
        Feed(table, instruction[..(nameLength + valueLength)]);
    }

    private static void Feed(TlsQuicQpackDynamicTable table, byte[] instructions)
    {
        Assert.True(table.TryReadEncoderInstructions(instructions, out int consumed, out TlsQuicQpackEncoderStreamError error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
        Assert.Equal(instructions.Length, consumed);
    }

    private static void FeedEncoderStream(TlsQuicQpackDynamicTable table, string label) =>
        Feed(table, AppendixBOctets(label, "Stream: Encoder"));

    // ------------------------------------------------------------------------
    // The Appendix B block parser
    // ------------------------------------------------------------------------
    //
    // A SECOND PARSER, and deliberately not a share of C14's. That one reads only the
    // "Stream: Encoder" blocks and the table-state rows beneath them, and it lives in
    // TlsQuicQpackDynamicTableTests as a private member of another task's file. This one reads
    // a NAMED block - the request-stream ones and the decoder-stream ones - and the
    // annotations to their right, which C14's never needed.

    private static string AppendixBSection(string label)
    {
        string capture = File.ReadAllText(QpackCaptures.Path("rfc9204-appendix-b-encoding-and-decoding-examples.txt"));
        int start = capture.IndexOf("\n" + label + ".", StringComparison.Ordinal);
        Assert.True(start >= 0, $"{label} was not found in the capture.");

        int end = capture.IndexOf("\nB." + (int.Parse(label[2..]) + 1) + ".", start, StringComparison.Ordinal);
        return end < 0 ? capture[start..] : capture[start..end];
    }

    // One "Stream: X" block, ending at the table-state header that follows every one of them.
    private static string AppendixBBlock(string label, string blockName)
    {
        string section = AppendixBSection(label);
        int start = section.IndexOf(blockName, StringComparison.Ordinal);
        Assert.True(start >= 0, $"{label} has no \"{blockName}\" block.");

        string rest = section[start..];
        int end = rest.IndexOf("Abs Ref Name", StringComparison.Ordinal);
        return end < 0 ? rest : rest[..end];
    }

    // The left-hand hex of a block. The group cap is EIGHT rather than four for the reason
    // C14's parser gives: B.2 opens with `3fbd01`, a group of six, and a four-character cap
    // does not mis-slice that line, it fails to match it and silently drops the instruction.
    private static readonly Regex AppendixBHexLine = new(
        @"^ +((?:[0-9a-f]{2,8} )*[0-9a-f]{2,8}) +\|",
        RegexOptions.Multiline | RegexOptions.Compiled);

    private static byte[] AppendixBOctets(string label, string blockName)
    {
        string block = AppendixBBlock(label, blockName);
        var hex = new StringBuilder();
        foreach (Match match in AppendixBHexLine.Matches(block))
        {
            hex.Append(match.Groups[1].Value.Replace(" ", string.Empty));
        }

        Assert.True(hex.Length > 0, $"{label}'s \"{blockName}\" block carried no octets.");
        return Convert.FromHexString(hex.ToString());
    }

    // A decoder-stream block: its octets, and the number its annotation names. Both come out
    // of the capture, so a test using this retypes neither the instruction nor its parameter.
    private static (byte[] Octets, ulong Parameter) AppendixBDecoderInstruction(string label, string annotation)
    {
        string block = AppendixBBlock(label, "Stream: Decoder");
        Match match = Regex.Match(block, annotation);
        Assert.True(match.Success, $"{label}'s decoder block does not match /{annotation}/.");
        return (AppendixBOctets(label, "Stream: Decoder"), ulong.Parse(match.Groups["n"].Value));
    }

    // The request-stream block of B.2 (stream 4) and B.4 (stream 8), by the number the section
    // itself names, so the block header is not typed here either.
    private static byte[] AppendixBFieldSection(string label) =>
        AppendixBOctets(label, "Stream: " + AppendixBFieldSectionStreamId(label));

    private static ulong AppendixBFieldSectionStreamId(string label)
    {
        Match match = Regex.Match(AppendixBSection(label), @"Stream: (?<n>\d+)\r?\n");
        Assert.True(match.Success, $"{label} names no numbered stream.");
        return ulong.Parse(match.Groups["n"].Value);
    }

    // "Required Insert Count = 4, Base = 4", from the field section's own first annotation.
    private static (ulong RequiredInsertCount, ulong Base) AppendixBSectionPrefixAnnotation(string label)
    {
        Match match = Regex.Match(
            AppendixBBlock(label, "Stream: " + AppendixBFieldSectionStreamId(label)),
            @"Required Insert Count = (?<required>\d+), Base = (?<base>\d+)");
        Assert.True(match.Success, $"{label}'s field section has no prefix annotation.");
        return (ulong.Parse(match.Groups["required"].Value), ulong.Parse(match.Groups["base"].Value));
    }

    // The `(name=value)` annotations under a field section, in wire order - the expected
    // decode, read out of the capture rather than restated.
    private static (string Name, string Value)[] AppendixBFieldAnnotations(string label) =>
        [.. Regex.Matches(
                AppendixBBlock(label, "Stream: " + AppendixBFieldSectionStreamId(label)),
                @"^\s*\|\s+\((?<name>[^=)]+)=(?<value>[^)]*)\)\s*$",
                RegexOptions.Multiline)
            .Select(match => (match.Groups["name"].Value, match.Groups["value"].Value))];
}
