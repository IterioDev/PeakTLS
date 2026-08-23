namespace TlsClient.Tests.Wire;

public sealed class Http2WirePeetTests
{
    private const string ChromePreface =
        "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a" +
        "000018040000000000" +
        "000100010000" + "000200000000" + "000400600000" + "000600040000" +
        "000004080000000000" + "00ef0001";

    [Fact]
    public void DescribesSettingsWithRegistryNames()
    {
        var frames = Http2WireHex.ParseFrames(ChromePreface);

        var described = Http2WirePeet.Describe(frames);

        Assert.Equal("SETTINGS", described[0].FrameType);
        Assert.Equal(24, described[0].Length);
        Assert.Equal(
            [
                "HEADER_TABLE_SIZE = 65536",
                "ENABLE_PUSH = 0",
                "INITIAL_WINDOW_SIZE = 6291456",
                "MAX_HEADER_LIST_SIZE = 262144",
            ],
            described[0].Settings);
    }

    [Fact]
    public void DescribesWindowUpdateIncrement()
    {
        var described = Http2WirePeet.Describe(Http2WireHex.ParseFrames(ChromePreface));

        Assert.Equal("WINDOW_UPDATE", described[1].FrameType);
        Assert.Equal(15_663_105u, described[1].Increment);
    }

    [Fact]
    public void DescribesUnknownSettingIdentifierWithoutLosingIt()
    {
        // A single GREASE setting, id 0x4a4a, value 0.
        var frames = Http2WireHex.ParseFrames(
            "000006040000000000" + "4a4a00000000",
            expectPreface: false);

        var described = Http2WirePeet.Describe(frames);

        Assert.Equal(["UNKNOWN(0x4a4a) = 0"], described[0].Settings);
    }

    [Fact]
    public void AkamaiFingerprintMatchesTheDocumentedChromeValue()
    {
        var frames = Http2WireHex.ParseFrames(ChromePreface);

        var fingerprint = Http2WirePeet.AkamaiFingerprint(
            frames,
            [":method", ":authority", ":scheme", ":path"]);

        Assert.Equal("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", fingerprint);
    }

    [Fact]
    public void AkamaiPrioritySegmentUsesPriorityFramesNotHeadersFlags()
    {
        // HEADERS on stream 1 carrying a priority payload, but no PRIORITY frame.
        var frames = Http2WireHex.ParseFrames(
            "000005012000000001" + "0000000028",
            expectPreface: false);

        var fingerprint = Http2WirePeet.AkamaiFingerprint(frames, [":method"]);

        // Assert the whole string, not a substring. This fixture has no SETTINGS and no
        // WINDOW_UPDATE, so it renders a leading "|0|" whatever the priority segment
        // contains — a Contains check would be satisfied by that prefix alone and would
        // pass even if the priority logic read the HEADERS flag instead of PRIORITY
        // frames, which is the one thing this test exists to rule out.
        Assert.Equal("|0|0|m", fingerprint);
    }

    [Fact]
    public void DescribesFrameFlagsByName()
    {
        var frames = Http2WireHex.ParseFrames(
            "000001010500000001" + "88",
            expectPreface: false);

        var described = Http2WirePeet.Describe(frames);

        Assert.Equal(["EndStream (0x1)", "EndHeaders (0x4)"], described[0].Flags);
        Assert.Equal(1, described[0].StreamId);
    }

    [Fact]
    public void DescribesBit0x1AsAckOnSettingsAndPingButEndStreamElsewhere()
    {
        // SETTINGS ACK: length 0, flags 0x1, stream 0. This is exactly the frame
        // Http2Connection emits in response to the server's initial SETTINGS.
        var settingsAck = Http2WireHex.ParseFrames("000000040100000000", expectPreface: false);
        // PING ACK: length 8, flags 0x1, stream 0.
        var pingAck = Http2WireHex.ParseFrames(
            "000008060100000000" + "0000000000000000",
            expectPreface: false);
        // HEADERS with END_STREAM: bit 0x1 means something else entirely here.
        var headersEndStream = Http2WireHex.ParseFrames(
            "000001010100000001" + "88",
            expectPreface: false);

        Assert.Equal(["Ack (0x1)"], Http2WirePeet.Describe(settingsAck)[0].Flags);
        Assert.Equal(["Ack (0x1)"], Http2WirePeet.Describe(pingAck)[0].Flags);
        Assert.Equal(["EndStream (0x1)"], Http2WirePeet.Describe(headersEndStream)[0].Flags);
    }

    [Fact]
    public void DescribesPriorityUpdateFrameType()
    {
        // PRIORITY_UPDATE (0x10): length 5, flags 0, stream 0, prioritized stream id 1
        // followed by the "u=3" priority field value.
        var frames = Http2WireHex.ParseFrames(
            "000005100000000000" + "00000001" + "75",
            expectPreface: false);

        var described = Http2WirePeet.Describe(frames);

        Assert.Equal("PRIORITY_UPDATE", described[0].FrameType);
    }
}
