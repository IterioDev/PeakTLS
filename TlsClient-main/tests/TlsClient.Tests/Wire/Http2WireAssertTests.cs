namespace TlsClient.Tests.Wire;

public sealed class Http2WireAssertTests
{
    [Fact]
    public void EqualBytesPassesOnIdenticalInput()
    {
        Http2WireAssert.EqualBytes([0x00, 0xff], new byte[] { 0x00, 0xff }, "preface");
    }

    [Fact]
    public void EqualBytesReportsFirstDifferingOffsetAndBothValues()
    {
        var failure = Assert.Throws<Xunit.Sdk.XunitException>(() =>
            Http2WireAssert.EqualBytes(
                [0x00, 0x01, 0x02],
                new byte[] { 0x00, 0x99, 0x02 },
                "preface"));

        Assert.Contains("preface", failure.Message);
        Assert.Contains("offset 1", failure.Message);
        Assert.Contains("01", failure.Message);
        Assert.Contains("99", failure.Message);
    }

    [Fact]
    public void EqualBytesReportsLengthMismatch()
    {
        var failure = Assert.Throws<Xunit.Sdk.XunitException>(() =>
            Http2WireAssert.EqualBytes([0x00, 0x01], new byte[] { 0x00 }, "preface"));

        Assert.Contains("length", failure.Message);
    }

    [Fact]
    public void ToHexGroupsBytesInSpaceSeparatedPairs()
    {
        Assert.Equal("00 0f ff", Http2WireAssert.ToHex(new byte[] { 0x00, 0x0f, 0xff }));
    }

    [Fact]
    public void EqualFramesPassesForEqualByValueFramesFromSeparateParses()
    {
        // Two independent ParseFrames calls on the same hex allocate two distinct
        // byte[] payloads. Plain Assert.Equal would fail here because CapturedFrame's
        // generated equality compares Payload by reference; EqualFrames is the fix.
        const string hex =
            "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a" +
            "000006040000000000" + "4a4a00000000";

        var first = Http2WireHex.ParseFrames(hex);
        var second = Http2WireHex.ParseFrames(hex);

        Assert.NotSame(first[0].Payload, second[0].Payload);
        Http2WireAssert.EqualFrames(first, second, "frames");
    }

    [Fact]
    public void EqualFramesFailsWhenOnePayloadByteDiffers()
    {
        var expected = new[] { new CapturedFrame(Http2FrameType.Settings, 0, 0, [0x00, 0x01]) };
        var actual = new[] { new CapturedFrame(Http2FrameType.Settings, 0, 0, [0x00, 0x99]) };

        var failure = Assert.Throws<Xunit.Sdk.XunitException>(() =>
            Http2WireAssert.EqualFrames(expected, actual, "frames"));

        Assert.Contains("frame[0]", failure.Message);
        Assert.Contains("offset 1", failure.Message);
    }
}
