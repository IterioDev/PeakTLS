using System.Text;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// RFC 9204 s4.3's encoder instructions and the s4.5 representations the dynamic arm needs,
// encoding side. See src/SharpTls/Quic/TlsQuicQpackEncoder.cs.
//
// EVERY EXPECTED BYTE STRING HERE IS EXTERNAL TO THE CODE UNDER TEST. The instruction vectors
// are the wire bytes of the 2026-09-26 capture of Spotify 9.1.86.2428 on iOS 27.0, decoded in
// docs/superpowers/specs/reference-captures/2026-09-26-spotify-9.1.86-ios27-pcapng.md s6 —
// connection 61's encoder stream, verbatim. The prefix and index vectors are derived by hand
// from s4.5.1 through s4.5.3 and written out as octets. Nothing is produced by the encoder
// and read back as its own expectation.
public sealed class TlsQuicQpackEncoderInstructionTests
{
    private static byte[] Ascii(string text) => Encoding.ASCII.GetBytes(text);

    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes);

    // Conn 61, stream 6, first frame after the type byte: `3f e1 1f`. s4.3.1's 5-bit prefix
    // fills at 31, the remainder 4065 = 0x61 + (0x1f << 7) rides in two continuation octets.
    [Fact]
    public void SetDynamicTableCapacity4096IsTheCapturedThreeOctets()
    {
        Span<byte> buffer = stackalloc byte[8];

        Assert.True(TlsQuicQpackEncoder.TryEncodeSetDynamicTableCapacity(4096, buffer, out int written));

        Assert.Equal("3FE11F", Hex(buffer[..written]));
    }

    // Conn 61, insert #0: Insert With Name Reference, T = 1, static index 0 (:authority),
    // value `spclient.wg.spotify.com` Huffman-coded to 17 octets behind an H = 1 length.
    [Fact]
    public void InsertWithStaticNameReferenceMatchesTheCapturedAuthorityInsert()
    {
        Span<byte> buffer = stackalloc byte[64];

        Assert.True(TlsQuicQpackEncoder.TryEncodeInsertWithStaticNameReference(
            0,
            Ascii("spclient.wg.spotify.com"),
            TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo,
            buffer,
            out int written));

        Assert.Equal("C0914564A0C5A92BF8997456749A5F4B90F4FF", Hex(buffer[..written]));
    }

    // Conn 61, insert #1: Insert With Literal Name, H = 1 and 14-octet Huffman name
    // `spotify-app-version`, then H = 1 and 8-octet Huffman value `9.1.86.2428`.
    [Fact]
    public void InsertWithLiteralNameMatchesTheCapturedAppVersionInsert()
    {
        Span<byte> buffer = stackalloc byte[64];

        Assert.True(TlsQuicQpackEncoder.TryEncodeInsertWithLiteralName(
            Ascii("spotify-app-version"),
            Ascii("9.1.86.2428"),
            TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo,
            buffer,
            out int written));

        Assert.Equal("6E456749A5F4B0EBAD6EE5B1063D5F887D70AEF38B89A13D", Hex(buffer[..written]));
    }

    // Conn 61, insert #3: `app-platform: iOS`. The name Huffman-codes to 9 octets and goes
    // H = 1; `iOS` Huffman-codes to 3 octets, no shorter than raw, so ShorterOfTheTwo sends
    // it raw with H = 0 - `03 69 4f 53`. The capture is the witness that ties go raw.
    [Fact]
    public void ARawValueUnderShorterOfTheTwoMatchesTheCapturedAppPlatformInsert()
    {
        Span<byte> buffer = stackalloc byte[64];

        Assert.True(TlsQuicQpackEncoder.TryEncodeInsertWithLiteralName(
            Ascii("app-platform"),
            Ascii("iOS"),
            TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo,
            buffer,
            out int written));

        Assert.Equal("691D75AD5D034CA7B29F03694F53", Hex(buffer[..written]));
    }

    // s4.5.1.1: EncInsertCount = 0 for RIC 0, else (RIC mod 2*MaxEntries) + 1. s4.5.1.2: Sign
    // set when Base < RIC with Delta = RIC - Base - 1, clear otherwise with Delta = Base - RIC.
    // The first three rows are the capture's own prefixes (conn 61 streams 0, 8 and 12).
    [Theory]
    [InlineData(0UL, 0UL, 128UL, "0000")]
    [InlineData(9UL, 0UL, 128UL, "0A88")]
    [InlineData(9UL, 9UL, 128UL, "0A00")]
    [InlineData(10UL, 12UL, 128UL, "0B02")]
    [InlineData(300UL, 300UL, 128UL, "2D00")]     // 300 mod 256 = 44, +1 = 45
    [InlineData(300UL, 300UL, 511UL, "FF2E00")]   // 300 mod 1022 = 300, +1 = 301 = 255 + 46
    [InlineData(1100UL, 1100UL, 511UL, "4F00")]   // 1100 mod 1022 = 78, +1 = 79
    public void TheFieldSectionPrefixEncodesRicAndBasePerSection451(
        ulong requiredInsertCount, ulong @base, ulong maxEntries, string expected)
    {
        Span<byte> buffer = stackalloc byte[8];

        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(
            requiredInsertCount, @base, maxEntries, buffer, out int written));

        Assert.Equal(expected, Hex(buffer[..written]));
    }

    [Fact]
    public void ANonZeroRicWithNoMaxEntriesIsACallerBugNotADivideByZero()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            Span<byte> buffer = stackalloc byte[8];
            TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(1, 0, 0, buffer, out _);
        });
    }

    [Fact]
    public void TheZeroArgumentPrefixAndTheStaticOnlyPrefixAgree()
    {
        Span<byte> zero = stackalloc byte[8];
        Span<byte> explicitPrefix = stackalloc byte[8];

        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(zero, out int a));
        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(0, 0, 128, explicitPrefix, out int b));

        Assert.Equal(Hex(zero[..a]), Hex(explicitPrefix[..b]));
    }

    // s4.5.2 with T = 0 is `10xxxxxx` over a 6-bit prefix; s4.5.3 is `0001xxxx` over a 4-bit
    // one. The second row of each pair sits on the prefix fill boundary, where a writer with
    // the wrong prefix width first shows.
    [Fact]
    public void IndexedDynamicAndPostBaseLinesCarryTheirPatterns()
    {
        Span<byte> buffer = stackalloc byte[8];

        Assert.True(TlsQuicQpackEncoder.TryEncodeIndexedDynamic(0, buffer, out int a));
        Assert.Equal("80", Hex(buffer[..a]));
        Assert.True(TlsQuicQpackEncoder.TryEncodeIndexedDynamic(63, buffer, out a));
        Assert.Equal("BF00", Hex(buffer[..a]));

        Assert.True(TlsQuicQpackEncoder.TryEncodeIndexedPostBase(0, buffer, out int b));
        Assert.Equal("10", Hex(buffer[..b]));
        Assert.True(TlsQuicQpackEncoder.TryEncodeIndexedPostBase(15, buffer, out b));
        Assert.Equal("1F00", Hex(buffer[..b]));
    }

    [Fact]
    public void ADestinationTooShortFailsWithoutWriting()
    {
        Span<byte> two = stackalloc byte[2];
        Assert.False(TlsQuicQpackEncoder.TryEncodeSetDynamicTableCapacity(4096, two, out int written));
        Assert.Equal(0, written);

        Span<byte> ten = stackalloc byte[10];
        Assert.False(TlsQuicQpackEncoder.TryEncodeInsertWithStaticNameReference(
            0, Ascii("spclient.wg.spotify.com"), TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo, ten, out written));
        Assert.Equal(0, written);
    }
}
