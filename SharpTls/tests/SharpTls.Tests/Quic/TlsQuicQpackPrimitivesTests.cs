using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// RFC 7541 s5.1's prefixed integer and s5.2's string literal, as adopted by RFC 9204
// s4.1.1 and s4.1.2. See src/SharpTls/Quic/TlsQuicQpackPrimitives.cs.
//
// WHICH OF THESE ARE EXTERNALLY ANCHORED, AND WHICH ARE NOT. Only three cases in this
// file come from a published vector: RFC 7541 C.1.1, C.1.2 and C.1.3, driven from
// PublishedIntegerVectors below. Everything else is DERIVED FROM s5.1's pseudocode by
// hand and the expected octets are written out literally, because the three published
// vectors between them cover exactly two prefix widths (5 and 8), one continuation chain
// (two octets) and no boundary at all - 10 is well inside a 5-bit prefix, 42 is well
// inside an 8-bit one, and 1337 is well past the fill point rather than on it. A codec
// that passes only C.1.1-C.1.3 can still have `<` written as `<=` at the fill boundary,
// which is the ledger's rows 1, 2 and 14.
//
// NO EXPECTED VALUE IN THIS FILE IS PRODUCED BY THE CODEC UNDER TEST. Where a round trip
// appears it is in addition to a hand-derived byte string and never instead of one - a
// round trip proves the encoder and the decoder agree, including about a bug they share.
public sealed class TlsQuicQpackPrimitivesTests
{
    // RFC 7541 Appendix C.1, all three examples, from
    // reference-captures/rfc7541-appendix-c.1-integer-representation-examples.txt.
    //
    //   C.1.1  "The value 10 is to be encoded with a 5-bit prefix" -> 0b???01010
    //   C.1.2  "The value I=1337 is to be encoded with a 5-bit prefix" -> the RFC prints
    //          the three octets as 0b???11111, 0b10011010, 0b00001010
    //   C.1.3  "The value 42 is to be encoded starting at an octet boundary", 8-bit
    //          prefix -> 0b00101010
    //
    // The X bits of C.1.1 and C.1.2 are the previous field's and are taken as zero here,
    // which is what makes the octet comparable at all.
    public static TheoryData<ulong, int, byte[]> PublishedIntegerVectors => new()
    {
        { 10, 5, [0x0A] },
        { 1337, 5, [0x1F, 0x9A, 0x0A] },
        { 42, 8, [0x2A] },
    };

    [Theory]
    [MemberData(nameof(PublishedIntegerVectors))]
    public void TheThreePublishedIntegerVectorsEncodeToTheirRfcBytes(ulong value, int prefixBits, byte[] expected)
    {
        Span<byte> buffer = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(value, prefixBits, 0, buffer, out int written));
        Assert.Equal(expected.Length, written);
        Assert.Equal(expected, buffer[..written].ToArray());
    }

    [Theory]
    [MemberData(nameof(PublishedIntegerVectors))]
    public void TheThreePublishedIntegerVectorsDecodeToTheirRfcValues(ulong expected, int prefixBits, byte[] encoded)
    {
        Assert.True(TlsQuicQpackPrimitives.TryDecodeInteger(
            encoded, prefixBits, out ulong value, out int consumed, out TlsQuicQpackError error));
        Assert.Equal(expected, value);
        Assert.Equal(encoded.Length, consumed);
        Assert.Equal(TlsQuicQpackError.None, error);
    }

    // THE PREFIX-FILL BOUNDARY, and the reason this file exists at all. s5.1: the value is
    // encoded in the prefix only "If the integer value is small enough, i.e., strictly
    // less than 2^N-1". So 2^N-1 itself does NOT fit: the prefix is filled with ones and a
    // single continuation octet carrying zero follows. This is the case none of C.1.1-C.1.3
    // reaches, and the one an off-by-one silently gets wrong in both directions at once.
    //
    // The expected octets are computed by hand from the definition, one row per legal N:
    //   N=1 -> mask 1,   value 1   -> 0x01 0x00
    //   N=2 -> mask 3,   value 3   -> 0x03 0x00
    //   ...
    //   N=8 -> mask 255, value 255 -> 0xFF 0x00
    [Theory]
    [InlineData(1, 1, (byte)0x01)]
    [InlineData(2, 3, (byte)0x03)]
    [InlineData(3, 7, (byte)0x07)]
    [InlineData(4, 15, (byte)0x0F)]
    [InlineData(5, 31, (byte)0x1F)]
    [InlineData(6, 63, (byte)0x3F)]
    [InlineData(7, 127, (byte)0x7F)]
    [InlineData(8, 255, (byte)0xFF)]
    public void AValueThatExactlyFillsThePrefixSpillsIntoAZeroContinuationOctet(
        int prefixBits, ulong fill, byte filledPrefix)
    {
        Span<byte> buffer = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(fill, prefixBits, 0, buffer, out int written));
        Assert.Equal(2, written);
        Assert.Equal([filledPrefix, 0x00], buffer[..2].ToArray());
        Assert.Equal(2, TlsQuicQpackPrimitives.GetIntegerEncodedLength(fill, prefixBits));

        // And read back: `consumed` is the half a decoder that stopped at the prefix would
        // get wrong even while reporting the right value.
        Assert.True(TlsQuicQpackPrimitives.TryDecodeInteger(
            buffer[..2], prefixBits, out ulong value, out int consumed, out _));
        Assert.Equal(fill, value);
        Assert.Equal(2, consumed);
    }

    // The other side of the same boundary: 2^N-2 is strictly less than 2^N-1 and so stays
    // in the prefix as one octet. Together with the test above this pins `<` exactly.
    [Theory]
    [InlineData(2, 2, (byte)0x02)]
    [InlineData(5, 30, (byte)0x1E)]
    [InlineData(8, 254, (byte)0xFE)]
    public void AValueOneBelowTheFillBoundaryStaysInThePrefix(int prefixBits, ulong value, byte expected)
    {
        Span<byte> buffer = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(value, prefixBits, 0, buffer, out int written));
        Assert.Equal(1, written);
        Assert.Equal(expected, buffer[0]);
        Assert.Equal(1, TlsQuicQpackPrimitives.GetIntegerEncodedLength(value, prefixBits));
    }

    // ZERO IS NOT ABSENT. A prefixed integer of 0 is one octet whose prefix bits are clear;
    // an absent integer is no octet at all and is the `false` on the next test. The two are
    // one byte apart and a decoder that conflates them reads a field that is not there.
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(8)]
    public void AZeroValuedIntegerIsOneOctetAndNotNoOctets(int prefixBits)
    {
        Span<byte> buffer = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(0, prefixBits, 0, buffer, out int written));
        Assert.Equal(1, written);
        Assert.Equal(0x00, buffer[0]);
        Assert.True(TlsQuicQpackPrimitives.TryDecodeInteger(
            buffer[..1], prefixBits, out ulong value, out int consumed, out _));
        Assert.Equal(0UL, value);
        Assert.Equal(1, consumed);
    }

    // Derived from the pseudocode: after the prefix is filled the remainder is written
    // base-128, so at N=5 the values 31..158 cost exactly one continuation octet (158-31 =
    // 127, the largest remainder with no continuation bit) and 159 is the first that costs
    // two (159-31 = 128). All four octet strings below are hand-computed.
    [Theory]
    [InlineData(31UL, 5, new byte[] { 0x1F, 0x00 })]
    [InlineData(158UL, 5, new byte[] { 0x1F, 0x7F })]
    [InlineData(159UL, 5, new byte[] { 0x1F, 0x80, 0x01 })]
    [InlineData(16415UL, 5, new byte[] { 0x1F, 0x80, 0x80, 0x01 })]
    public void AContinuationChainGrowsAtTheDerivedBaseOneTwentyEightBoundaries(
        ulong value, int prefixBits, byte[] expected)
    {
        Span<byte> buffer = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(value, prefixBits, 0, buffer, out int written));
        Assert.Equal(expected, buffer[..written].ToArray());
        Assert.True(TlsQuicQpackPrimitives.TryDecodeInteger(
            expected, prefixBits, out ulong decoded, out int consumed, out _));
        Assert.Equal(value, decoded);
        Assert.Equal(expected.Length, consumed);
    }

    // RFC 9204 s4.1.1's ceiling, hand-derived at an 8-bit prefix. 2^62-1 = 4611686018427387903.
    // Subtracting the 255 the prefix absorbs leaves 4611686018427387648, whose base-128
    // digits little-endian are 0x00, 0x7E, 0x7F x7, 0x3F - the low nine get their
    // continuation bit set, the tenth does not.
    [Fact]
    public void TheSixtyTwoBitCeilingItselfIsAcceptedInBothDirections()
    {
        byte[] expected =
        [
            0xFF, 0x80, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F,
        ];

        Span<byte> buffer = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(
            TlsQuicQpackPrimitives.MaximumInteger, 8, 0, buffer, out int written));
        Assert.Equal(expected, buffer[..written].ToArray());

        Assert.True(TlsQuicQpackPrimitives.TryDecodeInteger(
            expected, 8, out ulong value, out int consumed, out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackPrimitives.MaximumInteger, value);
        Assert.Equal(10, consumed);
        Assert.Equal(TlsQuicQpackError.None, error);
    }

    // One above the ceiling, which is the SAME ten octets with the second one incremented.
    // Only the sum bound can reject it: no single chunk is too wide for its shift, and the
    // chain is nine continuation octets, which is inside the shift bound.
    [Fact]
    public void AnIntegerOneAboveTheSixtyTwoBitCeilingIsRejected()
    {
        byte[] encoded =
        [
            0xFF, 0x81, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F,
        ];

        Assert.False(TlsQuicQpackPrimitives.TryDecodeInteger(
            encoded, 8, out ulong value, out int consumed, out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackError.IntegerOverflow, error);
        Assert.Equal(0UL, value);
        Assert.Equal(0, consumed);
    }

    // The single-octet value bound, constructed so nothing else can fire. Nine continuation
    // octets, so the shift bound is never reached; every chunk but the last is zero, so the
    // running sum stays at 255; and the last chunk is 64 at shift 56, which alone is 2^62
    // and one past the ceiling. 63 there would be legal, which is what makes this a bound
    // rather than a range check.
    [Fact]
    public void AFinalContinuationOctetWiderThanTheRemainingBitsIsRejected()
    {
        byte[] encoded =
        [
            0xFF, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x40,
        ];

        Assert.False(TlsQuicQpackPrimitives.TryDecodeInteger(
            encoded, 8, out _, out _, out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackError.IntegerOverflow, error);

        // The same chain with 0x3F in the last position is the largest legal value at this
        // shape, so the rejection above is about the 64 and not about the chain.
        byte[] legal =
        [
            0xFF, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x3F,
        ];

        Assert.True(TlsQuicQpackPrimitives.TryDecodeInteger(legal, 8, out ulong value, out _, out _));
        Assert.Equal(255UL + (63UL << 56), value);
    }

    // THE CONTINUATION CHAIN THAT NEVER ENDS - s5.1's own named attack, "an encoder to send
    // a large number of zero values, which can waste octets and could be used to overflow
    // integer values". Ten 0x80 octets contribute nothing at all and then a terminator; the
    // tenth sits at shift 63, past 62 bits of payload, and must be refused there rather
    // than wrapped around by C#'s masking of the shift count.
    [Fact]
    public void AContinuationChainLongerThanSixtyTwoBitsIsRejectedWithoutAThrow()
    {
        byte[] encoded = new byte[12];
        encoded[0] = 0xFF;
        for (int i = 1; i <= 10; i++)
        {
            encoded[i] = 0x80;
        }

        encoded[11] = 0x00;

        Assert.False(TlsQuicQpackPrimitives.TryDecodeInteger(
            encoded, 8, out _, out _, out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackError.IntegerOverflow, error);
    }

    // ZERO IS NOT ABSENT, the decoder half. An empty buffer is not an integer of 0.
    [Fact]
    public void AnEmptyBufferIsRejectedRatherThanReadAsZero()
    {
        Assert.False(TlsQuicQpackPrimitives.TryDecodeInteger(
            [], 5, out ulong value, out int consumed, out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackError.Truncated, error);
        Assert.Equal(0UL, value);
        Assert.Equal(0, consumed);
    }

    // A filled prefix promises a continuation chain; a buffer that ends inside one is
    // truncated, not a value. 0x1F alone and 0x1F 0x80 are both mid-chain.
    [Theory]
    [InlineData(new byte[] { 0x1F })]
    [InlineData(new byte[] { 0x1F, 0x80 })]
    [InlineData(new byte[] { 0x1F, 0x80, 0x80 })]
    public void ATruncatedContinuationChainIsRejectedWithoutAThrow(byte[] encoded)
    {
        Assert.False(TlsQuicQpackPrimitives.TryDecodeInteger(
            encoded, 5, out _, out int consumed, out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackError.Truncated, error);
        Assert.Equal(0, consumed);
    }

    // The sizing helper is a SEPARATE derivation of s5.1's pseudocode from the encoder's,
    // which is the only reason checking one against the other says anything. Driven over a
    // spread that crosses every fill boundary and both base-128 boundaries.
    [Fact]
    public void TheSizingHelperAgreesWithWhatTheEncoderActuallyWrote()
    {
        ulong[] values =
        [
            0, 1, 2, 3, 6, 7, 14, 15, 30, 31, 62, 63, 126, 127, 128, 129, 158, 159, 254,
            255, 256, 1337, 16414, 16415, 16416, 2097151, 2097152,
            TlsQuicQpackPrimitives.MaximumInteger,
        ];

        int checkedRows = 0;
        Span<byte> buffer = new byte[32];
        foreach (ulong value in values)
        {
            for (int prefixBits = 1; prefixBits <= 8; prefixBits++)
            {
                Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(
                    value, prefixBits, 0, buffer, out int written));
                Assert.Equal(TlsQuicQpackPrimitives.GetIntegerEncodedLength(value, prefixBits), written);
                checkedRows++;
            }
        }

        Assert.Equal(values.Length * 8, checkedRows);
        Assert.Equal(224, checkedRows);
    }

    // The scratch buffer the encoder builds into is sized for the whole ulong range, not
    // just for RFC 9204's 62 bits. ulong.MaxValue at N = 1 is the worst case: the prefix
    // absorbs 1 and the remaining 2^64-2 needs ten base-128 digits.
    [Fact]
    public void TheScratchBufferHoldsTheWidestEncodingAnyUlongCanProduce()
    {
        int widest = 0;
        for (int prefixBits = 1; prefixBits <= 8; prefixBits++)
        {
            widest = Math.Max(widest, TlsQuicQpackPrimitives.GetIntegerEncodedLength(ulong.MaxValue, prefixBits));
        }

        Assert.Equal(11, widest);
        Assert.Equal(TlsQuicQpackPrimitives.MaximumIntegerEncodedLength, widest);

        Span<byte> exact = new byte[11];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(ulong.MaxValue, 1, 0, exact, out int written));
        Assert.Equal(11, written);
    }

    // A destination that cannot hold the encoding is refused, and refused BEFORE anything
    // is written - a caller that reuses a buffer must not have to guess which prefix of it
    // this method touched on the way to returning false.
    [Fact]
    public void AnEncodeIntoATooSmallBufferReturnsFalseAndLeavesTheBufferUntouched()
    {
        // 1337 at a 5-bit prefix is three octets; every destination shorter than that must
        // be refused, and the two-octet one is the case a mid-chain bail would scribble on.
        for (int size = 0; size < 3; size++)
        {
            byte[] buffer = new byte[size];
            Array.Fill(buffer, (byte)0xCC);
            Assert.False(TlsQuicQpackPrimitives.TryEncodeInteger(1337, 5, 0, buffer, out int written));
            Assert.Equal(0, written);
            Assert.All(buffer, b => Assert.Equal(0xCC, b));
        }

        Span<byte> exact = new byte[3];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(1337, 5, 0, exact, out int fits));
        Assert.Equal(3, fits);
    }

    // RFC 9204 s4.1.2's N-bit prefix string literal: "The string uses one bit for the
    // Huffman flag, followed by the length of the encoded string as a (N-1)-bit prefix
    // integer." So H is bit N-1 of the octet, NOT bit 7, except at N = 8 where they are the
    // same bit - which is exactly why the N = 8 row alone would witness nothing.
    //
    // Each expected header is hand-built: preceding bits, then H at 1 << (N-1), then the
    // length as an (N-1)-bit prefix integer.
    //   N=8, pre 0x00, len 5   -> 0x05 / 0x85       (H at bit 7)
    //   N=7, pre 0x80, len 5   -> 0x85 / 0xC5       (H at bit 6)
    //   N=5, pre 0xE0, len 5   -> 0xE5 / 0xF5       (H at bit 4)
    //   N=4, pre 0xF0, len 7   -> 0xF7 0x00 / 0xFF 0x00  (7 fills the 3-bit length prefix)
    [Theory]
    [InlineData(8, (byte)0x00, 5, new byte[] { 0x05 }, new byte[] { 0x85 })]
    [InlineData(7, (byte)0x80, 5, new byte[] { 0x85 }, new byte[] { 0xC5 })]
    [InlineData(5, (byte)0xE0, 5, new byte[] { 0xE5 }, new byte[] { 0xF5 })]
    [InlineData(4, (byte)0xF0, 7, new byte[] { 0xF7, 0x00 }, new byte[] { 0xFF, 0x00 })]
    public void TheHuffmanFlagSitsAtTheTopOfTheNBitWindow(
        int prefixBits, byte precedingBits, int length, byte[] plainHeader, byte[] huffmanHeader)
    {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++)
        {
            data[i] = (byte)('a' + i);
        }

        Span<byte> buffer = new byte[32];

        Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
            data, prefixBits, precedingBits, huffman: false, buffer, out int plainWritten));
        Assert.Equal(plainHeader, buffer[..plainHeader.Length].ToArray());
        Assert.Equal(plainHeader.Length + length, plainWritten);

        Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
            data, prefixBits, precedingBits, huffman: true, buffer, out int huffmanWritten));
        Assert.Equal(huffmanHeader, buffer[..huffmanHeader.Length].ToArray());
        Assert.Equal(huffmanHeader.Length + length, huffmanWritten);

        // The two headers must DIFFER, which is the part a wrong bit position breaks: a
        // flag written into a bit the preceding field already owns is invisible.
        Assert.NotEqual(plainHeader, huffmanHeader);

        // And read back off the hand-built octets, not off what was just encoded.
        byte[] plainWire = [.. plainHeader, .. data];
        Assert.True(TlsQuicQpackPrimitives.TryDecodeStringLiteral(
            plainWire, prefixBits, out bool plainFlag, out ReadOnlySpan<byte> plainData, out int plainConsumed, out _));
        Assert.False(plainFlag);
        Assert.Equal(data, plainData.ToArray());
        Assert.Equal(plainWire.Length, plainConsumed);

        byte[] huffmanWire = [.. huffmanHeader, .. data];
        Assert.True(TlsQuicQpackPrimitives.TryDecodeStringLiteral(
            huffmanWire, prefixBits, out bool huffmanFlag, out ReadOnlySpan<byte> huffmanData, out int huffmanConsumed, out _));
        Assert.True(huffmanFlag);
        Assert.Equal(data, huffmanData.ToArray());
        Assert.Equal(huffmanWire.Length, huffmanConsumed);
    }

    // Every prefix width RFC 9204 s4.1.2 permits, "between 2 and 8, inclusive", across
    // lengths that straddle the (N-1)-bit fill boundary in each. The preceding bits are set
    // to all ones so that a flag or a length leaking upward out of its window would collide
    // with a bit that is already set and be caught here rather than silently tolerated.
    [Fact]
    public void ANonHuffmanStringLiteralRoundTripsAtEveryPrefixWidthFromTwoToEight()
    {
        int cases = 0;
        Span<byte> buffer = new byte[512];
        for (int prefixBits = TlsQuicQpackPrimitives.MinimumStringPrefixBits;
             prefixBits <= TlsQuicQpackPrimitives.MaximumPrefixBits;
             prefixBits++)
        {
            byte precedingBits = (byte)(0xFF << prefixBits);
            int fill = (1 << (prefixBits - 1)) - 1;
            foreach (int length in new[] { 0, 1, fill - 1, fill, fill + 1, 200 })
            {
                byte[] data = new byte[length];
                for (int i = 0; i < length; i++)
                {
                    data[i] = (byte)(i * 7 % 256);
                }

                foreach (bool huffman in new[] { false, true })
                {
                    Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
                        data, prefixBits, precedingBits, huffman, buffer, out int written));

                    // The preceding bits survive the encode untouched.
                    Assert.Equal(precedingBits, (byte)(buffer[0] & (0xFF << prefixBits)));

                    Assert.True(TlsQuicQpackPrimitives.TryDecodeStringLiteral(
                        buffer[..written], prefixBits, out bool flag, out ReadOnlySpan<byte> decoded,
                        out int consumed, out TlsQuicQpackError error));
                    Assert.Equal(huffman, flag);
                    Assert.Equal(data, decoded.ToArray());
                    Assert.Equal(written, consumed);
                    Assert.Equal(TlsQuicQpackError.None, error);
                    cases++;
                }
            }
        }

        // 7 widths (N = 2..8) x 6 lengths x 2 flag values = 84. THE FIRST VERSION OF THIS
        // LINE SAID 82, on a hand derivation that assumed N=2 would skip a row because
        // fill-1 would go negative. It does not: at N=2 the length prefix is 1 bit, so fill
        // is 2^1-1 = 1 and fill-1 is 0, a legal length that simply repeats the row above it.
        // The test failed on the count and the count was what was wrong.
        Assert.Equal(84, cases);
        Assert.Equal(7 * 6 * 2, cases);
    }

    // ZERO IS NOT ABSENT, the literal half. A declared length of 0 is a legal empty field
    // value: the decode succeeds, `data` is empty, and `consumed` is the header alone. The
    // `false` return means the literal was not there at all, which is a different answer.
    [Theory]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(8)]
    public void AZeroLengthStringLiteralDecodesToAnEmptySpanRatherThanBeingAbsent(int prefixBits)
    {
        Span<byte> buffer = new byte[8];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
            [], prefixBits, 0, huffman: false, buffer, out int written));
        Assert.Equal(1, written);
        Assert.Equal(0x00, buffer[0]);

        Assert.True(TlsQuicQpackPrimitives.TryDecodeStringLiteral(
            buffer[..1], prefixBits, out bool huffman, out ReadOnlySpan<byte> data, out int consumed,
            out TlsQuicQpackError error));
        Assert.False(huffman);
        Assert.True(data.IsEmpty);
        Assert.Equal(1, consumed);
        Assert.Equal(TlsQuicQpackError.None, error);

        // Absent, for contrast: no octet at all.
        Assert.False(TlsQuicQpackPrimitives.TryDecodeStringLiteral(
            [], prefixBits, out _, out _, out _, out TlsQuicQpackError absent));
        Assert.Equal(TlsQuicQpackError.Truncated, absent);
    }

    // THE LENGTH THAT OVERRUNS. A declared length one past what is there, and a declared
    // length of 2^62-1 with three octets behind it - the second is the one that must not be
    // narrowed to an int before being compared.
    [Fact]
    public void AStringLiteralWhoseDeclaredLengthOverrunsTheBufferIsRejectedWithoutAThrow()
    {
        // 8-bit prefix, H = 0, length 5, but only four octets of data follow.
        byte[] shortByOne = [0x05, 0x61, 0x62, 0x63, 0x64];
        Assert.False(TlsQuicQpackPrimitives.TryDecodeStringLiteral(
            shortByOne, 8, out _, out _, out int consumed, out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackError.Truncated, error);
        Assert.Equal(0, consumed);

        // The same length, exactly satisfied, to show the rejection is about the one
        // missing octet and not about the shape.
        byte[] exact = [0x05, 0x61, 0x62, 0x63, 0x64, 0x65];
        Assert.True(TlsQuicQpackPrimitives.TryDecodeStringLiteral(
            exact, 8, out _, out ReadOnlySpan<byte> data, out int exactConsumed, out _));
        Assert.Equal(5, data.Length);
        Assert.Equal(6, exactConsumed);

        // A length at the 62-bit ceiling, three octets of data. If the comparison narrowed
        // first this would slice a negative or wrapped count and throw.
        byte[] enormous =
        [
            0x7F, 0x80, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, 0x61, 0x62, 0x63,
        ];
        Assert.False(TlsQuicQpackPrimitives.TryDecodeStringLiteral(
            enormous, 8, out _, out _, out _, out TlsQuicQpackError huge));
        Assert.Equal(TlsQuicQpackError.Truncated, huge);
    }

    // NOTHING THROWS ON HOSTILE INPUT. Every two-octet buffer there is, at every legal
    // prefix width, through both decoders - 65536 x 8 for the integer and 65536 x 7 for the
    // literal. Two octets is enough to reach the prefix guard, the first continuation
    // octet, the mid-chain truncation and the declared-length overrun; the longer hostile
    // shapes have their own named tests above.
    [Fact]
    public void NoTwoOctetBufferMakesEitherDecoderThrow()
    {
        byte[] buffer = new byte[2];
        int integerCases = 0;
        int literalCases = 0;
        for (int first = 0; first < 256; first++)
        {
            for (int second = 0; second < 256; second++)
            {
                buffer[0] = (byte)first;
                buffer[1] = (byte)second;
                for (int prefixBits = 1; prefixBits <= 8; prefixBits++)
                {
                    TlsQuicQpackPrimitives.TryDecodeInteger(buffer, prefixBits, out _, out _, out _);
                    integerCases++;
                    if (prefixBits >= TlsQuicQpackPrimitives.MinimumStringPrefixBits)
                    {
                        TlsQuicQpackPrimitives.TryDecodeStringLiteral(buffer, prefixBits, out _, out _, out _, out _);
                        literalCases++;
                    }
                }
            }
        }

        Assert.Equal(65536 * 8, integerCases);
        Assert.Equal(65536 * 7, literalCases);
    }
}
