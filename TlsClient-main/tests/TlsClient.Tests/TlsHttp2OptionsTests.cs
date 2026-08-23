namespace TlsClient.Tests;

public sealed class TlsHttp2OptionsTests
{
    [Fact]
    public void Snapshot_PreservesExactPrefaceAndPseudoHeaderOrder()
    {
        var options = new TlsHttp2Options
        {
            Preface =
            [
                new TlsHttp2SettingsFrame
                {
                    Settings = [new(0x2, 0), new(0x1, 4096)],
                },
                new TlsHttp2WindowUpdateFrame { Increment = 65_535 },
            ],
            PseudoHeaderOrder = [":scheme", ":method", ":path", ":authority"],
            PriorityUpdate = "u=2",
        };

        var snapshot = options.Snapshot();

        Assert.Equal([0x4, 0x8], snapshot.Preface.Select(frame => frame.Type));
        Assert.Equal(
            [
                0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x10, 0x00,
            ],
            snapshot.Preface[0].Payload);
        Assert.Equal([0x00, 0x00, 0xff, 0xff], snapshot.Preface[1].Payload);
        Assert.Equal(options.PseudoHeaderOrder, snapshot.PseudoHeaders.Order);
        Assert.Equal("u=2", snapshot.PriorityUpdate);
    }

    [Fact]
    public void Snapshot_AllowsASingleSettingForProfilesThatCancelPush()
    {
        var options = new TlsHttp2Options
        {
            Preface = [new TlsHttp2SettingsFrame { Settings = [new(0x4, 16_777_216)] }],
        };

        var snapshot = options.Snapshot();

        Assert.Equal([0x00, 0x04, 0x01, 0x00, 0x00, 0x00], Assert.Single(snapshot.Preface).Payload);

        // ENABLE_PUSH is absent, so RFC 9113's default of 1 leaves push enabled and an
        // inbound PUSH_PROMISE is decoded and cancelled rather than treated as an error.
        Assert.True(snapshot.LocalEnablePush);
    }

    [Fact]
    public void Snapshot_RejectsSelfDependentPrefacePriorityFrame()
    {
        var options = new TlsHttp2Options
        {
            Preface =
            [
                new TlsHttp2PrefacePriorityFrame
                {
                    StreamId = 3,
                    Priority = new TlsHttp2Priority { StreamDependency = 3 },
                },
            ],
        };

        Assert.Throws<ArgumentException>(() => options.Snapshot());
    }

    /// <summary>
    /// A peer must not react specially to an unknown code (RFC 9113 section 7), so an
    /// undefined value is harmless on the wire — but it is far likelier a typo than an
    /// intention, and nothing here can distinguish the two.
    /// </summary>
    [Theory]
    [InlineData("GoAwayErrorCode")]
    [InlineData("CancellationResetCode")]
    [InlineData("LocalFailureResetCode")]
    [InlineData("PushRejectionResetCode")]
    public void Snapshot_RejectsAnUndefinedErrorCode(string propertyName)
    {
        var options = new TlsHttp2Options();
        var property = typeof(TlsHttp2ShutdownOptions).GetProperty(propertyName);
        Assert.NotNull(property);
        property.SetValue(options.Shutdown, (Http2ErrorCode)0xdead);

        Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
    }

    /// <summary>
    /// The GOAWAY payload spends 8 octets on Last-Stream-ID and Error Code (RFC 9113
    /// section 6.8), and section 4.2 lets a peer declare a maximum frame size as small as
    /// 16384, so 16377 octets of debug data cannot be guaranteed to fit.
    /// </summary>
    [Fact]
    public void Snapshot_RejectsDebugDataThatCannotFitTheSmallestPermittedFrame()
    {
        var options = new TlsHttp2Options();
        options.Shutdown.GoAwayDebugData = new byte[16_377];

        Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
    }

    /// <summary>
    /// 5 is the largest size that cannot work. The header block writer takes the 5-octet
    /// RFC 9113 section 6.3 priority payload out of the fragment's own budget, so 1 to 5
    /// leaves nothing for the field block, and priority is a per-request override the session
    /// cannot see — the floor is therefore enforced whether or not one is declared here.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(16_777_216)]
    public void Snapshot_RejectsAFragmentSizeOutsideTheUsableRange(int fragmentSize)
    {
        var options = new TlsHttp2Options { HeaderBlockFragmentSize = fragmentSize };

        Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
    }

    /// <summary>
    /// 6 is the smallest usable size: five octets of priority payload and one of field block.
    /// The upper bound is SETTINGS_MAX_FRAME_SIZE's own, RFC 9113 section 4.2.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(6)]
    [InlineData(16_777_215)]
    public void Snapshot_KeepsAFragmentSizeInsideTheUsableRange(int? fragmentSize)
    {
        var options = new TlsHttp2Options { HeaderBlockFragmentSize = fragmentSize };

        Assert.Equal(fragmentSize, options.Snapshot().HeaderBlockFragmentSize);
    }
}
