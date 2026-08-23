using System.Text;
using System.Text.RegularExpressions;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// RFC 7541 Appendix B's Huffman code and s5.2's rules for using it, adopted unmodified by
// RFC 9204 s4.1.2. See src/SharpTls/Quic/TlsQuicQpackHuffman.cs.
//
// WHICH OF THESE ARE EXTERNALLY ANCHORED. Two: the twelve Huffman-coded strings of RFC 7541
// C.4 and C.6, decoded and re-encoded. They are the only Huffman vectors that exist
// anywhere, and between them they exercise 55 of the 256 octet symbols at code lengths 5,
// 6, 7 and 8 - a measured figure, asserted in
// TlsQuicQpackHuffmanTests.ThePublishedVectorsCoverOnlyTheShortCodesAndTheTestSaysSo, not
// an estimate. The 201 symbols whose codes are 10 bits or wider, EOS included, have no
// external witness at all.
//
// WHAT STANDS IN FOR THE MISSING 201. Not a round trip, which would agree with itself while
// both halves shared a wrong row. Instead the table is re-derived from the capture on disk
// at test time, row by row, against the THREE redundant columns RFC 7541 prints for each
// code - the binary split into 8-bit groups, the hex, and the bracketed bit count - and
// none of that touches the encoder. Kraft equality over the 257 lengths is checked the same
// way, and it is what makes a single altered length detectable at all.
public sealed class TlsQuicQpackHuffmanTests
{
    // Every Huffman-coded string RFC 7541 publishes: four from C.4 (the request examples)
    // and eight from C.6 (the response examples), each as the RFC prints the encoded octets
    // and the plaintext they decode to.
    //
    // THREE OF THESE PLAINTEXTS ARE UNWRAPPED, and that is where a transcription of this
    // list goes wrong. The RFC's "Decoded:" column is 26 characters wide and breaks a longer
    // value across lines - and for two of them across a PAGE BREAK, with a footer, a form
    // feed and a running header interposed. Reading the column alone yields
    // "Mon, 21 Oct 2013 20:13:21" and a separate "GMT", and "...max-age=3600; versi" with
    // its "on=1" on the far side of page 53.
    //
    // The unwrapped forms below are taken from a DIFFERENT part of the same capture rather
    // than from this decoder: C.6's closing "Decoded header list:" prints
    // "set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" and
    // "date: Mon, 21 Oct 2013 20:13:22 GMT" on unbroken lines, and C.6.1's "Dynamic Table
    // (after decoding)" does the same for the 20:13:21 one.
    public static TheoryData<string, string> PublishedHuffmanStrings => new()
    {
        // C.4.1 - :authority
        { "f1e3c2e5f23a6ba0ab90f4ff", "www.example.com" },

        // C.4.2 - cache-control
        { "a8eb10649cbf", "no-cache" },

        // C.4.3 - custom-key and its value
        { "25a849e95ba97d7f", "custom-key" },
        { "25a849e95bb8e8b4bf", "custom-value" },

        // C.6.1 - :status, cache-control, date, location
        { "6402", "302" },
        { "aec3771a4b", "private" },
        { "d07abe941054d444a8200595040b8166e082a62d1bff", "Mon, 21 Oct 2013 20:13:21 GMT" },
        { "9d29ad171863c78f0b97c8e9ae82ae43d3", "https://www.example.com" },

        // C.6.2 - :status
        { "640eff", "307" },

        // C.6.3 - date, content-encoding, set-cookie
        { "d07abe941054d444a8200595040b8166e084a62d1bff", "Mon, 21 Oct 2013 20:13:22 GMT" },
        { "9bd9ab", "gzip" },
        {
            "94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
            "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
        },
    };

    [Theory]
    [MemberData(nameof(PublishedHuffmanStrings))]
    public void ThePublishedVectorsDecodeToTheirRfcPlaintext(string encodedHex, string expected)
    {
        byte[] encoded = Convert.FromHexString(encodedHex);
        byte[] buffer = new byte[TlsQuicQpackHuffman.GetMaximumDecodedLength(encoded.Length)];

        Assert.True(TlsQuicQpackHuffman.TryDecode(
            encoded, buffer, out int written, out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackError.None, error);
        Assert.Equal(expected, Encoding.ASCII.GetString(buffer, 0, written));
    }

    [Theory]
    [MemberData(nameof(PublishedHuffmanStrings))]
    public void ThePublishedVectorsReEncodeToTheirRfcBytes(string expectedHex, string plaintext)
    {
        byte[] value = Encoding.ASCII.GetBytes(plaintext);
        byte[] expected = Convert.FromHexString(expectedHex);

        Assert.Equal(expected.Length, TlsQuicQpackHuffman.GetEncodedLength(value));

        byte[] buffer = new byte[expected.Length];
        Assert.True(TlsQuicQpackHuffman.TryEncode(value, buffer, out int written));
        Assert.Equal(expected.Length, written);
        Assert.Equal(expected, buffer);
    }

    // THE TABLE, WITNESSED AGAINST THE CAPTURE AND NOT AGAINST THE ENCODER. Each row of RFC
    // 7541 Appendix B prints the code three times - binary in 8-bit groups, hex, and a
    // bracketed bit count - and this reads all three off the file on disk, checks they agree
    // with each other, and only then checks them against the two arrays in the source.
    //
    // A transcription error is invisible to a round trip because both directions share it.
    // This is the test that would see one, and it is the only evidence the 201 symbols the
    // published vectors never touch have at all.
    [Fact]
    public void TheTableMatchesTheCapturedAppendixBRowForRow()
    {
        int rows = 0;
        foreach (Match row in CapturedAppendixBRows())
        {
            int symbol = int.Parse(row.Groups["index"].Value);
            string binary = row.Groups["binary"].Value.Replace("|", string.Empty);
            uint fromHex = Convert.ToUInt32(row.Groups["hex"].Value, 16);
            int bracketed = int.Parse(row.Groups["length"].Value);

            // The capture agreeing with itself, first: the three columns are redundant and a
            // misread of one is caught by the other two.
            Assert.Equal(bracketed, binary.Length);
            Assert.Equal(fromHex, Convert.ToUInt32(binary, 2));

            // Then the source agreeing with the capture.
            Assert.Equal(bracketed, TlsQuicQpackHuffman.CodeLengths[symbol]);
            Assert.Equal(fromHex, TlsQuicQpackHuffman.Codes[symbol]);
            rows++;
        }

        Assert.Equal(257, rows);
        Assert.Equal(257, TlsQuicQpackHuffman.Codes.Length);
        Assert.Equal(257, TlsQuicQpackHuffman.CodeLengths.Length);
    }

    // THE ROW COUNT, DERIVED. Not "the table has 257 rows because the plan says so": the
    // capture's body has some number of lines that end in a bracketed bit count, those lines
    // carry a parenthesised index each, and the indices turn out to be exactly 0..256 with
    // no gap and no duplicate - so max - min + 1 reconciles with the line count and the
    // count is 257 because of what is in the file.
    //
    // The regex is safe despite the page footers interior to the range: a footer ends
    // "[Page 51]" and P is not a digit, so it cannot match. Six footers fall inside; a count
    // that came out at 263 would have matched them.
    [Fact]
    public void TheRowCountIsDerivedFromTheCaptureRatherThanAsserted()
    {
        List<int> indices = [.. CapturedAppendixBRows().Select(m => int.Parse(m.Groups["index"].Value))];

        int lineCount = indices.Count;
        Assert.Equal(lineCount, indices.Distinct().Count());
        Assert.Equal(0, indices.Min());
        Assert.Equal(256, indices.Max());
        Assert.Equal(lineCount, indices.Max() - indices.Min() + 1);
        Assert.Equal(lineCount, TlsQuicQpackHuffman.Codes.Length);

        // Only now is the number itself written down, and it is written down having been
        // computed twice.
        Assert.Equal(257, lineCount);

        // The footers really are in the range and really do not match.
        string capture = File.ReadAllText(CapturePath());
        Assert.Equal(6, Regex.Matches(capture, @"^.*\[Page \d+\]\s*$", RegexOptions.Multiline).Count);
    }

    // KRAFT EQUALITY, which is what makes a single wrong LENGTH detectable. For a complete
    // prefix code the sum of 2^-length over all symbols is exactly 1; change one row's
    // length by one bit and the sum moves off 1 and this fails. Computed in integers scaled
    // by 2^30, the longest code, so there is no floating point in it.
    //
    // Also prefix-freeness, directly: no code is a prefix of another. Together they say the
    // 257 codes tile the space exactly, which is the property the decoder's lack of an
    // absent-child branch depends on.
    [Fact]
    public void TheTableSatisfiesKraftEqualityAndIsPrefixFree()
    {
        int longest = 0;
        foreach (byte length in TlsQuicQpackHuffman.CodeLengths)
        {
            longest = Math.Max(longest, length);
        }

        Assert.Equal(30, longest);

        long kraft = 0;
        foreach (byte length in TlsQuicQpackHuffman.CodeLengths)
        {
            kraft += 1L << (longest - length);
        }

        Assert.Equal(1L << longest, kraft);

        // Prefix-freeness. Each code is normalised to its `longest`-bit left-aligned form
        // plus its length; one code is a prefix of another exactly when their leading bits
        // agree for the shorter length.
        var normalised = new List<(ulong Aligned, int Length)>(257);
        for (int symbol = 0; symbol < TlsQuicQpackHuffman.Codes.Length; symbol++)
        {
            int length = TlsQuicQpackHuffman.CodeLengths[symbol];
            normalised.Add(((ulong)TlsQuicQpackHuffman.Codes[symbol] << (longest - length), length));
        }

        normalised.Sort((a, b) => a.Aligned != b.Aligned ? a.Aligned.CompareTo(b.Aligned) : a.Length.CompareTo(b.Length));
        for (int i = 1; i < normalised.Count; i++)
        {
            (ulong previousAligned, int previousLength) = normalised[i - 1];
            (ulong aligned, _) = normalised[i];
            ulong mask = previousLength == 0 ? 0 : ulong.MaxValue << (longest - previousLength);
            Assert.NotEqual(previousAligned & mask, aligned & mask);
        }
    }

    // The measured coverage of the only external anchors there are. Stated as a test so the
    // figure in the source comment cannot drift away from the vectors it describes.
    [Fact]
    public void ThePublishedVectorsCoverOnlyTheShortCodesAndTheTestSaysSo()
    {
        var symbols = new HashSet<byte>();
        foreach (object[] row in PublishedHuffmanStrings)
        {
            foreach (byte octet in Encoding.ASCII.GetBytes((string)row[1]))
            {
                symbols.Add(octet);
            }
        }

        Assert.Equal(55, symbols.Count);

        var lengths = new HashSet<int>();
        foreach (byte symbol in symbols)
        {
            lengths.Add(TlsQuicQpackHuffman.CodeLengths[symbol]);
        }

        Assert.Equal([5, 6, 7, 8], lengths.Order());
        Assert.Equal(201, 256 - symbols.Count);
    }

    // EVERY SINGLE-SYMBOL CODE, all 256 of them, one octet at a time. This is a round trip
    // and is recorded as one: it proves the encoder and the decoder agree about each row,
    // which is a real property - a row present in one table and absent from the other, or a
    // length that disagrees between them, fails here - and it proves nothing at all about
    // whether that row matches the RFC. TheTableMatchesTheCapturedAppendixBRowForRow is what
    // does that.
    [Fact]
    public void EverySingleSymbolCodeRoundTripsThroughBothDirections()
    {
        Span<byte> encoded = new byte[8];
        Span<byte> decoded = new byte[8];
        for (int symbol = 0; symbol < 256; symbol++)
        {
            byte[] value = [(byte)symbol];
            int expectedLength = (TlsQuicQpackHuffman.CodeLengths[symbol] + 7) / 8;
            Assert.Equal(expectedLength, TlsQuicQpackHuffman.GetEncodedLength(value));

            Assert.True(TlsQuicQpackHuffman.TryEncode(value, encoded, out int written));
            Assert.Equal(expectedLength, written);

            Assert.True(TlsQuicQpackHuffman.TryDecode(
                encoded[..written], decoded, out int read, out TlsQuicQpackError error));
            Assert.Equal(TlsQuicQpackError.None, error);
            Assert.Equal(1, read);
            Assert.Equal((byte)symbol, decoded[0]);
        }
    }

    // RFC 7541 s5.2: "A Huffman-encoded string literal containing the EOS symbol MUST be
    // treated as a decoding error." EOS is 30 one-bits, so 0xFFFFFFFF is EOS followed by two
    // bits of padding - and the IN THE MIDDLE case is the one that matters, because a
    // decoder that treated EOS as an end marker would accept it and silently truncate.
    [Fact]
    public void TheEosSymbolIsRejectedRatherThanEndingTheString()
    {
        // 30 one-bits then two more: EOS at the very end of the input.
        Assert.False(TlsQuicQpackHuffman.TryDecode(
            [0xFF, 0xFF, 0xFF, 0xFF], new byte[64], out int written, out TlsQuicQpackError trailing));
        Assert.Equal(TlsQuicQpackError.EosSymbol, trailing);
        Assert.Equal(0, written);

        // EOS with real data after it. 30 one-bits, then 'a' (00011, five bits), then three
        // bits of padding: 11111111 11111111 11111111 11110001 1111 -> five octets.
        // A decoder that stopped at EOS would report one symbol and no error.
        byte[] middle = [0xFF, 0xFF, 0xFF, 0xFF, 0x1F];
        Assert.False(TlsQuicQpackHuffman.TryDecode(
            middle, new byte[64], out _, out TlsQuicQpackError interior));
        Assert.Equal(TlsQuicQpackError.EosSymbol, interior);
    }

    // RFC 7541 s5.2: "A padding strictly longer than 7 bits MUST be treated as a decoding
    // error." Constructed so ONLY the length can reject it: a whole extra 0xFF octet is
    // eight bits of padding whose bits are a perfectly good EOS prefix, so the
    // not-corresponding-to-EOS rule has nothing to say about it.
    [Fact]
    public void PaddingLongerThanSevenBitsIsRejected()
    {
        // 'a' is 00011 at five bits; 00011 111 is 0x1F and is a valid one-symbol encoding
        // with three bits of padding.
        Assert.True(TlsQuicQpackHuffman.TryDecode(
            [0x1F], new byte[8], out int written, out TlsQuicQpackError none));
        Assert.Equal(TlsQuicQpackError.None, none);
        Assert.Equal(1, written);

        // The same encoding with one more all-ones octet appended: eleven bits of trailing
        // padding, which is over seven and must be refused. Every one of those eleven bits
        // is a legitimate EOS prefix bit, so the length is the only thing wrong with it and
        // the not-corresponding-to-EOS rule cannot be what rejects this.
        Assert.False(TlsQuicQpackHuffman.TryDecode(
            [0x1F, 0xFF], new byte[8], out _, out TlsQuicQpackError tooLong));
        Assert.Equal(TlsQuicQpackError.PaddingTooLong, tooLong);

        // EXACTLY EIGHT BITS OF PADDING, which is the case that pins the bound at 7 rather
        // than merely somewhere below 11. Eight '0' symbols at five bits each is 40 bits and
        // lands on an octet boundary with no padding at all, so one appended 0xFF is a pad
        // of exactly 8 - one bit over the limit and nothing else wrong with it.
        //
        // THE FIRST VERSION OF THIS TEST DID NOT HAVE THIS CASE and the mutation sweep
        // caught it: relaxing the bound from `depth > 7` to `depth > 8` SURVIVED, because
        // the 0x1F 0xFF case above is an 11-bit pad that a bound of 8 still rejects.
        byte[] onBoundary = new byte[5];
        Assert.True(TlsQuicQpackHuffman.TryEncode("00000000"u8, onBoundary, out _));
        byte[] eightBitPad = [.. onBoundary, 0xFF];
        Assert.False(TlsQuicQpackHuffman.TryDecode(
            eightBitPad, new byte[16], out _, out TlsQuicQpackError eight));
        Assert.Equal(TlsQuicQpackError.PaddingTooLong, eight);

        // SEVEN BITS IS THE LARGEST LEGAL PAD and must still pass, which is what makes the
        // bound "strictly longer than 7" rather than "7 or more". Five '0' symbols at five
        // bits each is 25 bits, so the encoding fills four octets with exactly seven bits of
        // padding - the only run short of eight that lands there.
        byte[] fiveZeros = new byte[4];
        Assert.True(TlsQuicQpackHuffman.TryEncode("00000"u8, fiveZeros, out int fiveWritten));
        Assert.Equal(4, fiveWritten);
        Assert.Equal(7, (fiveWritten * 8) - (5 * TlsQuicQpackHuffman.CodeLengths['0']));
        Assert.True(TlsQuicQpackHuffman.TryDecode(
            fiveZeros, new byte[16], out int fiveRead, out TlsQuicQpackError sevenBits));
        Assert.Equal(TlsQuicQpackError.None, sevenBits);
        Assert.Equal(5, fiveRead);
    }

    // RFC 7541 s5.2: "A padding not corresponding to the most significant bits of the code
    // for the EOS symbol MUST be treated as a decoding error." Constructed so ONLY the bit
    // pattern can reject it: three bits of padding is well inside the seven-bit bound, so
    // the length rule has nothing to say.
    [Fact]
    public void PaddingThatIsNotTheEosPrefixIsRejected()
    {
        // 'a' (00011) with 111 padding is 0x1F and legal; with 110 it is 0x1E and is not.
        Assert.True(TlsQuicQpackHuffman.TryDecode(
            [0x1F], new byte[8], out _, out TlsQuicQpackError good));
        Assert.Equal(TlsQuicQpackError.None, good);

        Assert.False(TlsQuicQpackHuffman.TryDecode(
            [0x1E], new byte[8], out int written, out TlsQuicQpackError bad));
        Assert.Equal(TlsQuicQpackError.PaddingNotEos, bad);
        Assert.Equal(0, written);

        // And every other wrong three-bit pad, so this is about the pattern and not about
        // one unlucky value. 000..110 all fail, 111 passes.
        for (int pad = 0; pad < 8; pad++)
        {
            byte octet = (byte)(0x03 << 3 | pad);
            bool ok = TlsQuicQpackHuffman.TryDecode(
                [octet], new byte[8], out _, out TlsQuicQpackError error);
            Assert.Equal(pad == 7, ok);
            Assert.Equal(pad == 7 ? TlsQuicQpackError.None : TlsQuicQpackError.PaddingNotEos, error);
        }
    }

    // The encoder's half of the same rule: the padding it writes is the EOS prefix, taken
    // from row 256 of the table. Checked by reading the trailing bits back out of the
    // encoded octet directly rather than by handing them to the decoder, which would accept
    // its own mistake if both halves used the same wrong constant.
    [Fact]
    public void TheEncoderPadsWithTheMostSignificantBitsOfEos()
    {
        // '0' is 00000 at five bits, so one symbol leaves three bits of padding, and those
        // three bits must be the top three of EOS - which is 30 one-bits, so 111.
        byte[] buffer = new byte[1];
        Assert.True(TlsQuicQpackHuffman.TryEncode("0"u8, buffer, out int written));
        Assert.Equal(1, written);
        Assert.Equal(0x07, buffer[0] & 0x07);
        Assert.Equal(0x00, buffer[0] >> 3);

        // The claim that the pad bits come from EOS, restated against the table.
        uint eos = TlsQuicQpackHuffman.Codes[TlsQuicQpackHuffman.EosSymbol];
        int eosLength = TlsQuicQpackHuffman.CodeLengths[TlsQuicQpackHuffman.EosSymbol];
        Assert.Equal(30, eosLength);
        Assert.Equal(0x3FFFFFFFu, eos);
        Assert.Equal(eos >> (eosLength - 3), (uint)(buffer[0] & 0x07));
    }

    // A payload whose encoding lands exactly on an octet boundary has NO padding, and the
    // padding rules must then say nothing at all. Zero pad bits versus some pad bits is the
    // zero-versus-absent case here. '3' and '0' and '2' are five, five and five bits, and
    // "302" is the C.6.1 vector, which the RFC prints as exactly two octets - 15 bits would
    // not be a boundary, so this uses a run that is.
    [Fact]
    public void AnEncodingThatEndsOnAnOctetBoundaryCarriesNoPaddingAtAll()
    {
        // Eight '0' symbols at five bits each is 40 bits, exactly five octets.
        byte[] value = "00000000"u8.ToArray();
        Assert.Equal(5, TlsQuicQpackHuffman.GetEncodedLength(value));

        byte[] buffer = new byte[5];
        Assert.True(TlsQuicQpackHuffman.TryEncode(value, buffer, out int written));
        Assert.Equal(5, written);
        Assert.All(buffer, b => Assert.Equal(0x00, b));

        Assert.True(TlsQuicQpackHuffman.TryDecode(
            buffer, new byte[16], out int read, out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackError.None, error);
        Assert.Equal(8, read);

        // And the empty string: no octets in, no octets out, no padding decision to make.
        Assert.Equal(0, TlsQuicQpackHuffman.GetEncodedLength([]));
        Assert.True(TlsQuicQpackHuffman.TryEncode([], [], out int emptyWritten));
        Assert.Equal(0, emptyWritten);
        Assert.True(TlsQuicQpackHuffman.TryDecode([], [], out int emptyRead, out TlsQuicQpackError empty));
        Assert.Equal(0, emptyRead);
        Assert.Equal(TlsQuicQpackError.None, empty);
    }

    // A destination too small is answered, not thrown, and answered with the one member of
    // TlsQuicQpackError that is about this process rather than about the peer.
    [Fact]
    public void ADestinationTooSmallIsReportedRatherThanThrown()
    {
        byte[] encoded = Convert.FromHexString("f1e3c2e5f23a6ba0ab90f4ff");
        Assert.False(TlsQuicQpackHuffman.TryDecode(
            encoded, new byte[14], out int written, out TlsQuicQpackError error));
        Assert.Equal(TlsQuicQpackError.DestinationTooSmall, error);
        Assert.Equal(0, written);

        // Fifteen is exactly enough - "www.example.com" - so the refusal above is about the
        // one missing octet.
        Assert.True(TlsQuicQpackHuffman.TryDecode(
            encoded, new byte[15], out int fits, out TlsQuicQpackError none));
        Assert.Equal(15, fits);
        Assert.Equal(TlsQuicQpackError.None, none);

        // The advertised bound is genuinely an upper bound on what these octets can produce.
        Assert.True(TlsQuicQpackHuffman.GetMaximumDecodedLength(encoded.Length) >= 15);

        // The encoder refuses the same way.
        Assert.False(TlsQuicQpackHuffman.TryEncode("www.example.com"u8, new byte[11], out int shortWrite));
        Assert.Equal(0, shortWrite);
    }

    // NOTHING THROWS ON HOSTILE INPUT. Every one- and two-octet buffer there is, then every
    // three-octet one, then a deterministic sweep out to sixteen octets which is long enough
    // to contain EOS (30 bits), an over-long pad and a wrong pad. The destination is always
    // sized from GetMaximumDecodedLength, so a throw here would be a real defect and not a
    // sizing mistake in the test.
    [Fact]
    public void NoInputMakesTheDecoderThrow()
    {
        byte[] destination = new byte[TlsQuicQpackHuffman.GetMaximumDecodedLength(16) + 1];
        int cases = 0;

        byte[] three = new byte[3];
        for (int a = 0; a < 256; a++)
        {
            three[0] = (byte)a;
            TlsQuicQpackHuffman.TryDecode(three.AsSpan(0, 1), destination, out _, out _);
            cases++;
            for (int b = 0; b < 256; b++)
            {
                three[1] = (byte)b;
                TlsQuicQpackHuffman.TryDecode(three.AsSpan(0, 2), destination, out _, out _);
                cases++;
                for (int c = 0; c < 256; c++)
                {
                    three[2] = (byte)c;
                    TlsQuicQpackHuffman.TryDecode(three, destination, out _, out _);
                    cases++;
                }
            }
        }

        Assert.Equal(256 + (256 * 256) + (256 * 256 * 256), cases);

        // Fixed seed so a failure is reproducible.
        var random = new Random(7541);
        byte[] longer = new byte[16];
        for (int i = 0; i < 200_000; i++)
        {
            random.NextBytes(longer);
            int length = random.Next(4, longer.Length + 1);

            // Half the draws get a long all-ones run spliced in, which is what reaches EOS
            // and the over-long pad; uniform random bytes almost never produce 30 one-bits.
            if ((i & 1) == 0)
            {
                int at = random.Next(0, length - 3);
                for (int j = at; j < Math.Min(at + 4, length); j++)
                {
                    longer[j] = 0xFF;
                }
            }

            TlsQuicQpackHuffman.TryDecode(longer.AsSpan(0, length), destination, out _, out _);
        }
    }

    // Composition with the C5 layer, which is the shape C7 and C8 will use: an H = 1 string
    // literal whose payload is Huffman-coded. RFC 9204 s4.1.2 - "the indicated length is the
    // size of the string after encoding" - so the literal's length prefix counts the
    // Huffman octets, not the plaintext ones. The C.4.1 vector is the check: RFC 7541 prints
    // the whole literal as 8c f1e3 c2e5 f23a 6ba0 ab90 f4ff, a 0x8c header meaning H = 1 and
    // length 12 over the fifteen characters of "www.example.com".
    [Fact]
    public void AHuffmanStringLiteralCarriesTheEncodedLengthAndNotThePlaintextLength()
    {
        byte[] expected = Convert.FromHexString("8cf1e3c2e5f23a6ba0ab90f4ff");

        byte[] plaintext = "www.example.com"u8.ToArray();
        Assert.Equal(15, plaintext.Length);

        byte[] huffman = new byte[TlsQuicQpackHuffman.GetEncodedLength(plaintext)];
        Assert.Equal(12, huffman.Length);
        Assert.True(TlsQuicQpackHuffman.TryEncode(plaintext, huffman, out _));

        byte[] literal = new byte[32];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
            huffman, 8, 0, huffman: true, literal, out int written));
        Assert.Equal(expected, literal[..written].ToArray());

        // And back, off the RFC's octets rather than off what was just built.
        Assert.True(TlsQuicQpackPrimitives.TryDecodeStringLiteral(
            expected, 8, out bool flag, out ReadOnlySpan<byte> data, out int consumed, out _));
        Assert.True(flag);
        Assert.Equal(12, data.Length);
        Assert.Equal(expected.Length, consumed);

        byte[] decoded = new byte[TlsQuicQpackHuffman.GetMaximumDecodedLength(data.Length)];
        Assert.True(TlsQuicQpackHuffman.TryDecode(data, decoded, out int read, out _));
        Assert.Equal("www.example.com", Encoding.ASCII.GetString(decoded, 0, read));
    }

    // A row of RFC 7541 Appendix B: an optional symbol column, the index in parentheses, the
    // code in binary split into 8-bit groups by | characters, the code in hex, and the bit
    // count in brackets. Anchored at end-of-line on the bracketed count, which is what keeps
    // the six interior page footers out - they end "[Page 51]" and P is not a digit.
    private static readonly Regex AppendixBRow = new(
        @"^.{0,10}?\(\s*(?<index>\d+)\)\s+\|(?<binary>[01|]+)\s+(?<hex>[0-9a-f]+)\s+\[\s*(?<length>\d+)\]\s*$",
        RegexOptions.Multiline | RegexOptions.Compiled);

    private static IEnumerable<Match> CapturedAppendixBRows() =>
        AppendixBRow.Matches(File.ReadAllText(CapturePath())).Cast<Match>();

    private static string CapturePath()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !Directory.Exists(Path.Combine(directory.FullName, "src", "SharpTls", "Quic")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        string path = Path.Combine(
            directory.FullName,
            "docs",
            "superpowers",
            "specs",
            "reference-captures",
            "rfc7541-appendix-b-huffman-code.txt");
        Assert.True(File.Exists(path), $"RFC 7541 Appendix B capture not found at {path}.");
        return path;
    }
}
