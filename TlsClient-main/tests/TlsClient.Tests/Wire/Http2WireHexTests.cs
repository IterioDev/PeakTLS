namespace TlsClient.Tests.Wire;

public sealed class Http2WireHexTests
{
    // Magic, then SETTINGS(4, 16777216), then WINDOW_UPDATE(16711681) — the
    // okhttp4-android-11 preface.
    private const string AndroidPreface =
        "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a" +
        "000006040000000000" + "000401000000" +
        "000004080000000000" + "00ff0001";

    [Fact]
    public void ParseAcceptsWhitespaceAndColonSeparators()
    {
        Assert.Equal(new byte[] { 0x00, 0xef, 0x00, 0x01 }, Http2WireHex.Parse("00 ef 00 01"));
        Assert.Equal(new byte[] { 0x00, 0xef, 0x00, 0x01 }, Http2WireHex.Parse("00:ef:00:01"));
        Assert.Equal(new byte[] { 0x00, 0xef, 0x00, 0x01 }, Http2WireHex.Parse("00ef0001"));
    }

    [Fact]
    public void ParseRejectsOddLength()
    {
        var failure = Assert.Throws<FormatException>(() => Http2WireHex.Parse("00e"));
        Assert.Contains("even", failure.Message);
    }

    [Fact]
    public void ParseFramesSplitsPrefaceIntoFrames()
    {
        var frames = Http2WireHex.ParseFrames(AndroidPreface);

        Assert.Equal(2, frames.Count);
        Assert.Equal(Http2FrameType.Settings, frames[0].Type);
        Assert.Equal(6, frames[0].Payload.Length);
        Assert.Equal(Http2FrameType.WindowUpdate, frames[1].Type);
        Assert.Equal(new byte[] { 0x00, 0xff, 0x00, 0x01 }, frames[1].Payload);
    }

    [Fact]
    public void ParseFramesRejectsAMissingPrefaceWhenExpected()
    {
        var failure = Assert.Throws<FormatException>(
            () => Http2WireHex.ParseFrames("000006040000000000000401000000"));
        Assert.Contains("preface", failure.Message);
    }

    [Fact]
    public void ParseFramesWithoutPrefaceReadsFramesDirectly()
    {
        var frames = Http2WireHex.ParseFrames(
            "000004080000000000" + "00ff0001",
            expectPreface: false);

        Assert.Single(frames);
        Assert.Equal(Http2FrameType.WindowUpdate, frames[0].Type);
    }

    [Fact]
    public void ParseFramesRejectsATruncatedPayload()
    {
        var failure = Assert.Throws<FormatException>(
            () => Http2WireHex.ParseFrames("000004080000000000" + "00ff", expectPreface: false));
        Assert.Contains("truncated", failure.Message);
    }

    [Fact]
    public void ParseRejectsWiresharkHexDumpFormatWithOffsetAndAscii()
    {
        // Wireshark's "Copy as Hex Dump" (not "Hex Stream") includes offset columns
        // with valid hex digits and an ASCII trailer. A pasted dump would silently
        // corrupt the payload by reading the offset column as bytes.
        var wiresharkDump = "0000   00 01 02 03  ....";
        var failure = Assert.Throws<FormatException>(() => Http2WireHex.Parse(wiresharkDump));
        Assert.Contains("unexpected", failure.Message);
        Assert.Contains("Hex Stream", failure.Message);
    }

    [Fact]
    public void ParseRejectsStrayNonHexCharacterWithPositionalDiagnostic()
    {
        // A stray 'x' in the middle (e.g., from a mistyped character or documentation table)
        // should fail with its position in the original string.
        var failure = Assert.Throws<FormatException>(() => Http2WireHex.Parse("00 ef x0 01"));
        Assert.Contains("unexpected", failure.Message);
        Assert.Contains("'x'", failure.Message);
        // The index should be 6 (counting from 0: "00 ef " = 6 characters)
        Assert.Contains("6", failure.Message);
    }

    [Fact]
    public void ParseRejectsStrayNonHexCharacterIndexIsInOriginalString()
    {
        // When separators appear before the bad character, the index must be from
        // the original string, not from a "cleaned" string.
        var failure = Assert.Throws<FormatException>(() => Http2WireHex.Parse("00:ef:x0"));
        Assert.Contains("index", failure.Message);
        // The index should be 6 in the original string (0,0,:,e,f,:,x = index 6)
        Assert.Contains("6", failure.Message);
    }
}
