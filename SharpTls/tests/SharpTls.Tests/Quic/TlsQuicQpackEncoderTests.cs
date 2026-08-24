using System.Text;
using System.Text.RegularExpressions;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// RFC 9204 s4.5's field line representations, encoding side.
//
// WHICH TESTS ARE EXTERNALLY ANCHORED. Exactly two:
// AppendixB1ReproducesTheCapturedOctetsExactly and
// AppendixB1IsFifteenOctetsNotSixteen, both driven by
// reference-captures/rfc9204-appendix-b-encoding-and-decoding-examples.txt - the octets, the
// field line and the static index are all parsed out of the file, none is typed here.
// Everything else in this file is SELF-DERIVED: hand-computed byte strings from the s4.5
// figures, or structural sweeps. That distinction matters because B.1 is a single 15-octet
// vector that exercises one representation with one non-Huffman string, so it cannot be the
// only evidence - 13 of task 4b's 24 mutations left its published vectors green.
public sealed class TlsQuicQpackEncoderTests
{
    // ========================================================================
    // EXTERNALLY ANCHORED
    // ========================================================================

    // RFC 9204 Appendix B.1. The plaintext, the static index and the expected octets are all
    // read out of the capture, so this test cannot agree with a plan that misquoted any of
    // them.
    [Fact]
    public void AppendixB1ReproducesTheCapturedOctetsExactly()
    {
        (byte[] expected, string name, string value, int staticIndex) = AppendixB1();

        Assert.Equal(":path", name);
        Assert.Equal("/index.html", value);
        Assert.Equal(1, staticIndex);

        // The capture's own annotation says the name reference is static index 1, and the
        // table agrees - so the encoder's choice of representation is pinned by the file too,
        // not only its output bytes.
        Assert.True(TlsQuicQpackStaticTable.TryFindName(Encoding.ASCII.GetBytes(name), out int found));
        Assert.Equal(staticIndex, found);
        Assert.False(TlsQuicQpackStaticTable.TryFindNameAndValue(
            Encoding.ASCII.GetBytes(name),
            Encoding.ASCII.GetBytes(value),
            out _));

        Assert.Equal(expected, Encode([(name, value)], huffman: TlsQuicQpackHuffmanPolicy.Never, preferNameReference: true));
    }

    // The brief this task arrived with called B.1 "one 16-byte vector". It is fifteen:
    // 0000 510b 2f69 6e64 6578 2e68 746d 6c is 2 + 4 + 4 + 4 + ... counted properly, 2 prefix
    // octets and 13 representation octets. Derived from the file rather than argued.
    [Fact]
    public void AppendixB1IsFifteenOctetsNotSixteen()
    {
        (byte[] expected, _, string value, _) = AppendixB1();

        Assert.Equal(15, expected.Length);

        // And the fifteen decompose exactly as s4.5 says they must: two prefix octets, one
        // s4.5.4 pattern-plus-index octet, one string-literal header octet, and the value.
        Assert.Equal(TlsQuicQpackEncoder.FieldSectionPrefixLength + 1 + 1 + value.Length, expected.Length);
    }

    // ========================================================================
    // SELF-DERIVED: hand-computed byte strings from the s4.5 figures
    // ========================================================================

    // s4.5.1: Required Insert Count 0 at an 8-bit prefix is `00`; Sign 0 with Delta Base 0 at
    // a 7-bit prefix is `00`.
    [Fact]
    public void TheFieldSectionPrefixIsTwoZeroOctets()
    {
        Span<byte> destination = stackalloc byte[4];
        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(destination, out int written));
        Assert.Equal(2, written);
        Assert.Equal(TlsQuicQpackEncoder.FieldSectionPrefixLength, written);
        Assert.Equal(new byte[] { 0x00, 0x00 }, destination[..written].ToArray());
    }

    // s4.5.2 Figure 13: `1 T Index(6+)`. `:path` `/` is static row 1, so T = 1 and the six
    // bits carry 1: 1100_0001 = 0xC1. Nothing else follows - that is the point of the
    // representation.
    [Fact]
    public void AFullMatchOnNameAndValueEmitsAnIndexedFieldLine()
    {
        Assert.Equal(new byte[] { 0x00, 0x00, 0xC1 }, Encode([(":path", "/")], TlsQuicQpackHuffmanPolicy.Never, true));
    }

    // Still s4.5.2, but at a row whose index needs the continuation chain: 62 fits in six
    // bits, 63 is the prefix-fill boundary and 64 does not. Picked because the 6-bit prefix
    // boundary is the one place the indexed representation grows.
    [Fact]
    public void AnIndexedFieldLineSpansThePrefixFillBoundary()
    {
        Assert.Equal([0xC0 | 62], IndexedOctetsFor(62));
        Assert.Equal([0xC0 | 63, 0x00], IndexedOctetsFor(63));
        Assert.Equal([0xC0 | 63, 0x01], IndexedOctetsFor(64));
        Assert.Equal([0xC0 | 63, 35], IndexedOctetsFor(98));
    }

    // s4.5.4 Figure 15: `0 1 N T NameIndex(4+)` then `H ValueLength(7+)` then the value.
    // `:authority` is static row 0, N = 0, T = 1, so the first octet is 0101_0000 = 0x50; the
    // value `example.com` is 11 octets non-Huffman, so the header is 0000_1011 = 0x0B.
    [Fact]
    public void ANameOnlyMatchEmitsALiteralWithNameReference()
    {
        byte[] expected = [0x00, 0x00, 0x50, 0x0B, .. Encoding.ASCII.GetBytes("example.com")];
        Assert.Equal(expected, Encode([(":authority", "example.com")], TlsQuicQpackHuffmanPolicy.Never, true));
    }

    // s4.5.6 Figure 17: `0 0 1 N H NameLen(3+)` then the name, then `H ValueLength(7+)` then
    // the value. `x-custom` is not in the table at all. N = 0, H = 0, and the name is 8
    // octets - which does not fit the 3-bit length prefix, so the prefix fills to 7 and one
    // continuation octet carries 1. First octet 0010_0111 = 0x27, then 0x01.
    [Fact]
    public void NoStaticMatchEmitsALiteralWithLiteralName()
    {
        byte[] expected =
        [
            0x00, 0x00,
            0x27, 0x01, .. Encoding.ASCII.GetBytes("x-custom"),
            0x02, .. Encoding.ASCII.GetBytes("ab"),
        ];
        Assert.Equal(expected, Encode([("x-custom", "ab")], TlsQuicQpackHuffmanPolicy.Never, true));
    }

    // A name short enough to sit inside the 3-bit prefix, so the continuation octet in the
    // test above is not an artefact of the representation always needing one. `a-b` is 3
    // octets: 0010_0011 = 0x23.
    [Fact]
    public void AShortLiteralNameFitsInsideTheThreeBitPrefix()
    {
        byte[] expected = [0x00, 0x00, 0x23, .. Encoding.ASCII.GetBytes("a-b"), 0x01, (byte)'v'];
        Assert.Equal(expected, Encode([("a-b", "v")], TlsQuicQpackHuffmanPolicy.Never, true));
    }

    // The s4.5.4-versus-s4.5.6 knob the plan's task C1 owns. Same field, both settings, and
    // the bytes differ - so the flag is a real choice and not decoration.
    [Fact]
    public void PreferNameReferenceSelectsBetweenSection454AndSection456()
    {
        byte[] withReference = Encode([(":authority", "example.com")], TlsQuicQpackHuffmanPolicy.Never, preferNameReference: true);
        byte[] withoutReference = Encode([(":authority", "example.com")], TlsQuicQpackHuffmanPolicy.Never, preferNameReference: false);

        Assert.NotEqual(withReference, withoutReference);
        Assert.Equal(0x50, withReference[2]);          // s4.5.4, '01' pattern with T = 1
        Assert.Equal(0b0010_0000, withoutReference[2] & 0b1111_0000); // s4.5.6, '001' pattern

        // A full name-and-value match is s4.5.2 EITHER WAY - the knob only reaches the
        // name-reference decision, and this pins that it does not leak further.
        Assert.Equal(Encode([(":path", "/")], TlsQuicQpackHuffmanPolicy.Never, true), Encode([(":path", "/")], TlsQuicQpackHuffmanPolicy.Never, false));
    }

    // The Huffman flag, same header encoded both ways in one test. `example.com` Huffman-codes
    // to 8 octets from 11, so the length header changes as well as the payload, and H is set:
    // 1000_1000 = 0x88.
    [Fact]
    public void TheHuffmanFlagIsAParameterAndChangesTheBytes()
    {
        byte[] plain = Encode([(":authority", "example.com")], huffman: TlsQuicQpackHuffmanPolicy.Never, preferNameReference: true);
        byte[] coded = Encode([(":authority", "example.com")], huffman: TlsQuicQpackHuffmanPolicy.Always, preferNameReference: true);

        Assert.NotEqual(plain, coded);
        Assert.Equal(0x0B, plain[3]);
        Assert.Equal(0x80, coded[3] & 0x80);

        // The coded payload really is the Huffman codec's output for that string, and the
        // declared length really is its length - RFC 9204 s4.1.2's "the indicated length is
        // the size of the string after encoding".
        byte[] value = Encoding.ASCII.GetBytes("example.com");
        int codedLength = TlsQuicQpackHuffman.GetEncodedLength(value);
        Assert.Equal(codedLength, coded[3] & 0x7F);
        byte[] payload = new byte[codedLength];
        Assert.True(TlsQuicQpackHuffman.TryEncode(value, payload, out int payloadWritten));
        Assert.Equal(codedLength, payloadWritten);
        Assert.Equal(payload, coded[4..]);

        // And it is UNCONDITIONAL, not "when it comes out shorter": `zz` Huffman-codes to no
        // fewer octets than it started with, and the flag still applies. A size heuristic
        // would make the wire bytes depend on the header value.
        byte[] longer = Encode([("x-a", "zz")], huffman: TlsQuicQpackHuffmanPolicy.Always, preferNameReference: true);
        Assert.Equal(0x08, longer[2] & 0x08);
    }

    // Both Huffman settings decode back to the same field, through task C8's decoder rather
    // than back through the encoder.
    [Theory]
    [InlineData(TlsQuicQpackHuffmanPolicy.Never)]
    [InlineData(TlsQuicQpackHuffmanPolicy.Always)]
    public void BothHuffmanSettingsReadBackToTheSameField(TlsQuicQpackHuffmanPolicy huffman)
    {
        byte[] encoded = Encode([(":authority", "example.com")], huffman, true);
        Assert.Equal([(":authority", "example.com")], Decode(encoded));
    }

    // ZERO VERSUS ABSENT, on the encoder side. `:authority` with an EMPTY value is static row
    // 0 and must come out as a three-octet indexed field line - not as a literal with a
    // zero-length string, and not as a name-only match.
    [Fact]
    public void AnEmptyValueIsAValueAndMatchesTheEmptyValuedRow()
    {
        Assert.Equal(new byte[] { 0x00, 0x00, 0xC0 }, Encode([(":authority", "")], TlsQuicQpackHuffmanPolicy.Never, true));

        // The contrast: a NON-empty value at the same name falls through to s4.5.4, so the
        // empty case above is not just "everything at :authority is 0xC0".
        Assert.Equal(0x50, Encode([(":authority", "x")], TlsQuicQpackHuffmanPolicy.Never, true)[2]);

        // And a zero-length literal value, where the name is not in the table at all, is a
        // declared length of zero rather than an omitted string.
        byte[] literal = Encode([("x-a", "")], TlsQuicQpackHuffmanPolicy.Never, true);
        Assert.Equal([0x00, 0x00, 0x23, (byte)'x', (byte)'-', (byte)'a', 0x00], literal);
    }

    // ========================================================================
    // SELF-DERIVED: structural sweeps
    // ========================================================================

    // THE ENCODER NEVER EMITS A DYNAMIC REFERENCE. Swept over every static row - as an
    // indexed match, as a name-only match with a value that is not in the table, and as a
    // literal - plus a name that is in no row at all. In every case the first octet's
    // representation-and-T bits must be one of the three static shapes, and the decoder,
    // which rejects every dynamic shape, must accept it.
    [Fact]
    public void TheEncoderNeverEmitsADynamicTableReference()
    {
        int cases = 0;
        for (int i = 0; i < TlsQuicQpackStaticTable.Count; i++)
        {
            string name = TlsQuicQpackStaticTable.NameAt(i);
            foreach (string value in new[] { TlsQuicQpackStaticTable.ValueAt(i), "not-in-the-table" })
            {
                foreach (bool prefer in new[] { true, false })
                {
                    // All three, not two: ShorterOfTheTwo is the shipped default and the
                    // only one of the three whose output depends on the string.
                    foreach (var huffman in new[]
                    {
                        TlsQuicQpackHuffmanPolicy.Always,
                        TlsQuicQpackHuffmanPolicy.Never,
                        TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo,
                    })
                    {
                        AssertStaticShape(Encode([(name, value)], huffman, prefer));
                        cases++;
                    }
                }
            }
        }

        foreach (bool prefer in new[] { true, false })
        {
            AssertStaticShape(Encode([("x", "y")], TlsQuicQpackHuffmanPolicy.Never, prefer));
            cases++;
        }

        // 99 rows x 2 values x 3 Huffman policies x 2 name-reference knobs, plus the two
        // no-match cases. THE MIDDLE 3 WAS A 2: TlsQuicQpackHuffmanPolicy replaced a bool, and
        // ShorterOfTheTwo is a third dimension value rather than an alias for one of the
        // others - it is the only one of the three whose output depends on the string.
        Assert.Equal((99 * 2 * 3 * 2) + 2, cases);
    }

    // Every static row survives a trip out through the encoder and back through the decoder,
    // at both Huffman settings and both name-reference settings. This is a ROUND TRIP and so
    // proves nothing about the table's contents - see TlsQuicQpackStaticTableTests for that -
    // but it does prove the representations agree end to end on all 99 rows.
    [Theory]
    [InlineData(TlsQuicQpackHuffmanPolicy.Never, false)]
    [InlineData(TlsQuicQpackHuffmanPolicy.Never, true)]
    [InlineData(TlsQuicQpackHuffmanPolicy.Always, false)]
    [InlineData(TlsQuicQpackHuffmanPolicy.Always, true)]
    public void EveryStaticRowRoundTripsThroughTheDecoder(TlsQuicQpackHuffmanPolicy huffman, bool preferNameReference)
    {
        for (int i = 0; i < TlsQuicQpackStaticTable.Count; i++)
        {
            string name = TlsQuicQpackStaticTable.NameAt(i);
            string value = TlsQuicQpackStaticTable.ValueAt(i);
            Assert.Equal([(name, value)], Decode(Encode([(name, value)], huffman, preferNameReference)));
        }
    }

    // The non-Huffman string path is byte-for-byte the C5 primitive it is meant to be reusing.
    // Without this the encoder's private writer could drift from TryEncodeStringLiteral and
    // nothing would notice, because the decoder reads the header the same way either wrote it.
    [Fact]
    public void TheNonHuffmanStringPathAgreesWithThePrimitive()
    {
        // `:path` rather than `:authority` because `:authority` with an EMPTY value is static
        // row 0 and would come out as an indexed field line with no string literal in it at
        // all - the empty case would then be measuring nothing. `:path` holds only `/`, so
        // every value here takes the s4.5.4 arm.
        foreach (string value in new[] { "", "a", "example.com", new string('z', 200) })
        {
            byte[] data = Encoding.ASCII.GetBytes(value);
            byte[] viaEncoder = Encode([(":path", value)], huffman: TlsQuicQpackHuffmanPolicy.Never, preferNameReference: true);
            Assert.Equal(0x51, viaEncoder[2]);

            byte[] viaPrimitive = new byte[viaEncoder.Length];
            Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
                data,
                8,
                0,
                huffman: false,
                viaPrimitive.AsSpan(3),
                out int written));

            // Skip the two prefix octets and the s4.5.4 name-reference octet.
            Assert.Equal(viaEncoder[3..], viaPrimitive.AsSpan(3, written).ToArray());
        }
    }

    // A destination one octet short fails and writes nothing, at every representation. The
    // encoder's inputs are all ours, so sizing is its only failure mode; it must still not
    // half-write, because a caller that retries with a bigger buffer would otherwise duplicate
    // the head of the field line.
    [Theory]
    [InlineData(":path", "/")]
    [InlineData(":authority", "example.com")]
    [InlineData("x-custom", "ab")]
    public void ADestinationOneOctetShortFailsWithoutWriting(string name, string value)
    {
        byte[] full = Encode([(name, value)], TlsQuicQpackHuffmanPolicy.Never, true);
        int lineLength = full.Length - TlsQuicQpackEncoder.FieldSectionPrefixLength;

        for (int size = 0; size < lineLength; size++)
        {
            byte[] destination = new byte[size];
            Assert.False(TlsQuicQpackEncoder.TryEncodeFieldLine(
                Encoding.ASCII.GetBytes(name),
                Encoding.ASCII.GetBytes(value),
                huffman: TlsQuicQpackHuffmanPolicy.Never,
                preferNameReference: true,
                destination,
                out int written));
            Assert.Equal(0, written);
        }

        byte[] exact = new byte[lineLength];
        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldLine(
            Encoding.ASCII.GetBytes(name),
            Encoding.ASCII.GetBytes(value),
            huffman: TlsQuicQpackHuffmanPolicy.Never,
            preferNameReference: true,
            exact,
            out int exactWritten));
        Assert.Equal(lineLength, exactWritten);
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static void AssertStaticShape(byte[] encoded)
    {
        byte first = encoded[TlsQuicQpackEncoder.FieldSectionPrefixLength];

        if ((first & 0b1000_0000) != 0)
        {
            Assert.Equal(0b0100_0000, first & 0b0100_0000);   // s4.5.2 with T = 1
        }
        else if ((first & 0b0100_0000) != 0)
        {
            Assert.Equal(0b0001_0000, first & 0b0001_0000);   // s4.5.4 with T = 1
        }
        else
        {
            Assert.Equal(0b0010_0000, first & 0b1110_0000);   // s4.5.6, no table reference
        }

        // And the decoder, which rejects every dynamic shape there is, takes it.
        Assert.NotEmpty(Decode(encoded));
    }

    private static byte[] IndexedOctetsFor(int index)
    {
        string name = TlsQuicQpackStaticTable.NameAt(index);
        string value = TlsQuicQpackStaticTable.ValueAt(index);

        // Only meaningful if this row is the FIRST match for that pair; otherwise the encoder
        // would legitimately pick a lower index.
        Assert.True(TlsQuicQpackStaticTable.TryFindNameAndValue(
            Encoding.ASCII.GetBytes(name),
            Encoding.ASCII.GetBytes(value),
            out int found));
        Assert.Equal(index, found);

        return Encode([(name, value)], TlsQuicQpackHuffmanPolicy.Never, true)[TlsQuicQpackEncoder.FieldSectionPrefixLength..];
    }

    internal static byte[] Encode((string Name, string Value)[] fields, TlsQuicQpackHuffmanPolicy huffman, bool preferNameReference)
    {
        byte[] destination = new byte[8192];
        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(destination, out int total));

        foreach ((string name, string value) in fields)
        {
            Assert.True(TlsQuicQpackEncoder.TryEncodeFieldLine(
                Encoding.ASCII.GetBytes(name),
                Encoding.ASCII.GetBytes(value),
                huffman,
                preferNameReference,
                destination.AsSpan(total),
                out int written));
            total += written;
        }

        return destination[..total];
    }

    internal static (string Name, string Value)[] Decode(byte[] encoded)
    {
        byte[] buffer = new byte[16384];
        TlsQuicQpackDecodedFieldLine[] lines = new TlsQuicQpackDecodedFieldLine[64];
        Assert.True(TlsQuicQpackDecoder.TryDecodeFieldSection(
            encoded,
            buffer,
            lines,
            long.MaxValue,
            out int lineCount,
            out _,
            out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackError.None, error);

        return [.. lines[..lineCount].Select(l => (
            Encoding.ASCII.GetString(buffer, l.NameOffset, l.NameLength),
            Encoding.ASCII.GetString(buffer, l.ValueOffset, l.ValueLength)))];
    }

    // RFC 9204 Appendix B.1, read out of the capture. The octet dump is annotated on the
    // right of a '|', so the hex is what stands to the left of it; the field line and the
    // static index come from the annotation.
    internal static (byte[] Octets, string Name, string Value, int StaticIndex) AppendixB1()
    {
        string capture = File.ReadAllText(QpackCaptures.Path("rfc9204-appendix-b-encoding-and-decoding-examples.txt"));
        int start = capture.IndexOf("\nB.1.", StringComparison.Ordinal);
        int end = capture.IndexOf("\nB.2.", StringComparison.Ordinal);
        Assert.InRange(start, 0, end);
        string section = capture[start..end];

        string hex = string.Concat(
            Regex.Matches(section, @"^ +((?:[0-9a-f]{2,4} )*[0-9a-f]{2,4}) +\|", RegexOptions.Multiline)
                .Select(m => m.Groups[1].Value.Replace(" ", string.Empty)));
        Assert.NotEmpty(hex);

        Match field = Regex.Match(section, @"\((?<name>:[a-z]+)=(?<value>[^)\s]+)\)");
        Assert.True(field.Success, "B.1's field line annotation not found in the capture.");
        Match index = Regex.Match(section, @"Index=(?<index>\d+)");
        Assert.True(index.Success, "B.1's static index annotation not found in the capture.");

        return (
            Convert.FromHexString(hex),
            field.Groups["name"].Value,
            field.Groups["value"].Value,
            int.Parse(index.Groups["index"].Value));
    }
}
