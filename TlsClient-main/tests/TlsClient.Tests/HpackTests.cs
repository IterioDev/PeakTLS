using System.Text;

namespace TlsClient.Tests;

public sealed class HpackTests
{
    [Fact]
    public void HuffmanDecoder_DecodesRfc7541Vector()
    {
        var source = Convert.FromHexString("f1e3c2e5f23a6ba0ab90f4ff");
        var destination = new byte[32];

        var length = HpackHuffman.Decode(source, ref destination);

        Assert.Equal("www.example.com", Encoding.ASCII.GetString(destination, 0, length));
    }

    [Theory]
    // "a" (00011) then the 30-bit EOS symbol then five bits of padding. RFC 7541 section 5.2:
    // "A Huffman-encoded string literal containing the EOS symbol MUST be treated as a decoding
    // error."
    [InlineData("1fffffffff")]
    // "a" (00011) then three bits of padding, then a whole octet of it. Section 5.2: "A padding
    // strictly longer than 7 bits MUST be treated as a decoding error."
    [InlineData("1fff")]
    // "a" (00011) then three zero bits. Section 5.2: "A padding not corresponding to the most
    // significant bits of the code for the EOS symbol MUST be treated as a decoding error."
    [InlineData("18")]
    public void HuffmanDecoder_RejectsTheThreeDecodingErrorsSection52Names(string encoded)
    {
        var source = Convert.FromHexString(encoded);
        var destination = new byte[32];

        var exception = Assert.Throws<TlsHttpProtocolException>(
            () => HpackHuffman.Decode(source, ref destination));

        // RFC 9113 section 4.3: "A decoding error in a field block MUST be treated as a
        // connection error (Section 5.4.1) of type COMPRESSION_ERROR."
        Assert.Equal(Http2ErrorCode.CompressionError, exception.Http2ErrorCode);
        Assert.False(exception.IsStreamScoped);
    }

    [Fact]
    public void Decoder_LeavesTheDynamicTableUntouchedWhenTheHeaderListIsRejected()
    {
        // RFC 7541 section 4.1 makes the dynamic table a mirror of the encoder's, so a block
        // this decoder refuses must not leave an entry behind: index 62 would then mean one
        // thing here and another at the peer. The first block is a literal with incremental
        // indexing ("a: b"), whose section 4.1 size of 32 + 1 + 1 exceeds the one-octet header
        // list bound it is decoded under.
        var decoder = new HpackDecoder(4096);
        byte[] rejected = [0x40, 0x01, (byte)'a', 0x01, (byte)'b'];
        Assert.Throws<TlsHttpProtocolException>(() => decoder.Decode(rejected, 1));

        // 0xbe is an indexed field naming index 62, the first dynamic entry. There must be none.
        Assert.Throws<TlsHttpProtocolException>(() => decoder.Decode([0xbe], 16 * 1024));
    }

    [Fact]
    public void Decoder_PreservesDynamicTableAcrossRfc7541RequestBlocks()
    {
        var decoder = new HpackDecoder(4096);

        var first = decoder.Decode(
            Convert.FromHexString("828684410f7777772e6578616d706c652e636f6d"),
            16 * 1024);
        var second = decoder.Decode(
            Convert.FromHexString("828684be58086e6f2d6361636865"),
            16 * 1024);

        Assert.Collection(
            first,
            header => Assert.Equal(new HpackHeader(":method", "GET"), header),
            header => Assert.Equal(new HpackHeader(":scheme", "http"), header),
            header => Assert.Equal(new HpackHeader(":path", "/"), header),
            header => Assert.Equal(new HpackHeader(":authority", "www.example.com"), header));
        Assert.Contains(second, header =>
            header.Name == ":authority" && header.Value == "www.example.com");
        Assert.Contains(second, header =>
            header.Name == "cache-control" && header.Value == "no-cache");
    }

    [Fact]
    public void Encoder_RoundTripsHuffmanAndNeverIndexedFields()
    {
        var encoder = new HpackEncoder(new TlsHpackOptions().Snapshot());
        var decoder = new HpackDecoder(4096);
        HpackHeader[] expected =
        [
            new(":method", "GET"),
            new(":scheme", "https"),
            new(":authority", "www.example.com"),
            new(":path", "/resource?q=managed"),
            new("authorization", "Bearer secret"),
        ];

        var block = encoder.Encode(expected);
        var actual = decoder.Decode(block, 16 * 1024);

        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// Six octets from the network. C#'s <c>checked</c> governs the arithmetic operators
    /// and the numeric conversions but not <c>&lt;&lt;</c>, so at the last permitted
    /// iteration <c>127 &lt;&lt; 28</c> truncated to -268435456 and the accumulator went
    /// negative without ever overflowing; the indexed-field path then reached the
    /// static-table branch with a negative index and raised
    /// <c>IndexOutOfRangeException</c> — a type the connection layer cannot recognise as a
    /// protocol failure, so it answered with no GOAWAY at all. RFC 7541 section 7.4
    /// requires a limit on the values accepted for integers, and section 4.3 requires a
    /// decoding error to be a connection error of type COMPRESSION_ERROR.
    /// </summary>
    [Fact]
    public void Decoder_RejectsAnIntegerWhoseContinuationOverflowsTheShift()
    {
        var decoder = new HpackDecoder(4096);

        var failure = Assert.Throws<TlsHttpProtocolException>(() =>
            decoder.Decode([0xFF, 0x80, 0x80, 0x80, 0x80, 0x7F], 16 * 1024));

        Assert.Contains("HPACK integer", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The same truncation reached through a literal field's name index (RFC 7541 section
    /// 6.2.1), which is the second call site that hands the decoded integer straight to the
    /// header table.
    /// </summary>
    [Fact]
    public void Decoder_RejectsAnOverflowingIntegerInALiteralNameIndex()
    {
        var decoder = new HpackDecoder(4096);

        Assert.Throws<TlsHttpProtocolException>(() =>
            decoder.Decode([0x7F, 0x80, 0x80, 0x80, 0x80, 0x7F], 16 * 1024));
    }

    [Fact]
    public void Decoder_RejectsTableResizeAfterHeaderField()
    {
        var decoder = new HpackDecoder(4096);

        Assert.Throws<TlsHttpProtocolException>(() =>
            decoder.Decode([0x82, 0x20], 16 * 1024));
    }

    [Fact]
    public void Encoder_EmitsDynamicTableSizeChangesAtBlockStart()
    {
        var encoder = new HpackEncoder(new TlsHpackOptions().Snapshot());
        var decoder = new HpackDecoder(4096);
        _ = decoder.Decode(encoder.Encode([new("x-state", "one")]), 16 * 1024);

        encoder.SetMaximumDynamicTableSize(0);
        var reduced = encoder.Encode([new HpackHeader("x-state", "two")]);
        var reducedHeaders = decoder.Decode(reduced, 16 * 1024);
        encoder.SetMaximumDynamicTableSize(4096);
        var restored = encoder.Encode([new HpackHeader("x-state", "three")]);
        var restoredHeaders = decoder.Decode(restored, 16 * 1024);

        Assert.Equal(0x20, reduced[0]);
        Assert.Equal(0x20, restored[0] & 0xe0);
        Assert.Equal("two", Assert.Single(reducedHeaders).Value);
        Assert.Equal("three", Assert.Single(restoredHeaders).Value);
    }
}
