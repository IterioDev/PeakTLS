namespace TlsClient.Tests;

public sealed class TlsHttp2RequestFrameTests
{
    private const string Parameter = "FramesBeforeHeaders";

    private static TlsHttp2RequestFrameConfiguration FreezeOne(TlsHttp2RequestFrame frame) =>
        Assert.Single(TlsHttp2RequestFrameList.Freeze([frame], Parameter));

    [Fact]
    public void Freeze_StreamPriorityEmitsTheFiveOctetPriorityPayloadOnTheRequestStream()
    {
        var frozen = FreezeOne(new TlsHttp2StreamPriorityFrame
        {
            Priority = new TlsHttp2Priority
            {
                StreamDependency = 13,
                Exclusive = true,
                Weight = 220,
            },
            FlushAfter = true,
        });

        // PRIORITY is frame type 0x2 with no flags (RFC 9113 section 6.3); the payload is
        // Exclusive(1) | Stream Dependency(31) then Weight-1 as the raw 8-bit wire value.
        Assert.Equal(0x2, frozen.Type);
        Assert.Equal(0, frozen.Flags);
        Assert.Equal(0, frozen.StreamId);
        Assert.Equal([0x80, 0x00, 0x00, 0x0d, 0xdb], frozen.Payload);
        Assert.True(frozen.FlushAfter);
        Assert.True(frozen.TargetsRequestStream);
    }

    [Fact]
    public void Freeze_PriorityUpdateEmitsAZeroedPrioritizedStreamIdThenTheAsciiValue()
    {
        var frozen = FreezeOne(new TlsHttp2PriorityUpdateFrame { Value = "u=3, i" });

        // RFC 9218 section 7.1: type 0x10, frame stream identifier 0, payload is the
        // Prioritized Stream ID followed by the Priority Field Value in ASCII.
        Assert.Equal(0x10, frozen.Type);
        Assert.Equal(0, frozen.Flags);
        Assert.Equal(0, frozen.StreamId);
        Assert.Equal(
            [0x00, 0x00, 0x00, 0x00, 0x75, 0x3d, 0x33, 0x2c, 0x20, 0x69],
            frozen.Payload);
        Assert.False(frozen.FlushAfter);
        Assert.True(frozen.TargetsRequestStream);
    }

    [Fact]
    public void Freeze_PingEmitsEightOpaqueOctetsOnStreamZero()
    {
        var frozen = FreezeOne(new TlsHttp2PingFrame
        {
            Payload = [1, 2, 3, 4, 5, 6, 7, 8],
        });

        Assert.Equal(0x6, frozen.Type);
        Assert.Equal(0, frozen.Flags);
        Assert.Equal(0, frozen.StreamId);
        Assert.Equal([1, 2, 3, 4, 5, 6, 7, 8], frozen.Payload);
        Assert.False(frozen.TargetsRequestStream);
    }

    [Fact]
    public void Freeze_RawFrameEmitsItsDeclaredOctetsVerbatim()
    {
        var frozen = FreezeOne(new TlsHttp2RequestRawFrame
        {
            Type = 0x0b,
            Flags = 0x21,
            StreamId = 7,
            Payload = [0xde, 0xad],
        });

        Assert.Equal(0x0b, frozen.Type);
        Assert.Equal(0x21, frozen.Flags);
        Assert.Equal(7, frozen.StreamId);
        Assert.Equal([0xde, 0xad], frozen.Payload);

        // A raw frame's stream identifier is written verbatim: it is how a frame that really
        // targets stream 0 is declared, so it never takes the request's stream.
        Assert.False(frozen.TargetsRequestStream);
    }

    [Theory]
    [InlineData(0x0)]
    [InlineData(0x1)]
    [InlineData(0x3)]
    [InlineData(0x5)]
    [InlineData(0x7)]
    [InlineData(0x9)]
    public void Freeze_RejectsRawFrameTypesTheRequestMachineryOwns(byte type)
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            FreezeOne(new TlsHttp2RequestRawFrame { Type = type }));

        Assert.Contains("cannot use frame type", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(9)]
    public void Freeze_RejectsAPingPayloadThatIsNotExactlyEightOctets(int length)
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            FreezeOne(new TlsHttp2PingFrame { Payload = new byte[length] }));

        // RFC 9113 section 6.7 makes a length other than 8 a FRAME_SIZE_ERROR.
        Assert.Contains("FRAME_SIZE_ERROR", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Freeze_RejectsARawPingPayloadThatIsNotExactlyEightOctets()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            FreezeOne(new TlsHttp2RequestRawFrame { Type = 0x6, Payload = new byte[4] }));

        Assert.Contains("FRAME_SIZE_ERROR", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Freeze_RejectsAPingThatTargetsAStreamOtherThanZero()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            FreezeOne(new TlsHttp2RequestRawFrame
            {
                Type = 0x6,
                StreamId = 5,
                Payload = new byte[8],
            }));

        // A different failure from the length rule, and RFC 9113 section 6.7 gives it a
        // different code: PROTOCOL_ERROR, not FRAME_SIZE_ERROR.
        Assert.Contains("PROTOCOL_ERROR", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("FRAME_SIZE_ERROR", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// RFC 9113 section 6.3 fixes the PRIORITY payload at Exclusive (1), Stream Dependency
    /// (31), and Weight (8): "A PRIORITY frame with a length other than 5 octets MUST be
    /// treated as a stream error (Section 5.4.2) of type FRAME_SIZE_ERROR."
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(6)]
    public void Freeze_RejectsARawPriorityPayloadThatIsNotExactlyFiveOctets(int length)
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            FreezeOne(new TlsHttp2RequestRawFrame
            {
                Type = 0x2,
                StreamId = 5,
                Payload = new byte[length],
            }));

        Assert.Contains("FRAME_SIZE_ERROR", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("PROTOCOL_ERROR", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// RFC 9113 section 6.3: "The PRIORITY frame always identifies a stream. If a PRIORITY
    /// frame is received with a stream identifier of 0x00, the recipient MUST respond with a
    /// connection error (Section 5.4.1) of type PROTOCOL_ERROR." A verbatim stream identifier
    /// is the point of a raw frame, so stream 0 stays expressible for every other type and is
    /// refused only for this one.
    /// </summary>
    [Fact]
    public void Freeze_RejectsARawPriorityThatTargetsStreamZero()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            FreezeOne(new TlsHttp2RequestRawFrame
            {
                Type = 0x2,
                StreamId = 0,
                Payload = new byte[5],
            }));

        // A different failure from the length rule, and section 6.3 gives it a different code.
        Assert.Contains("PROTOCOL_ERROR", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("FRAME_SIZE_ERROR", exception.Message, StringComparison.Ordinal);

        // The legal shape still freezes verbatim, so neither check refuses a valid frame.
        var frozen = FreezeOne(new TlsHttp2RequestRawFrame
        {
            Type = 0x2,
            StreamId = 5,
            Payload = [0x80, 0, 0, 3, 200],
        });
        Assert.Equal(5, frozen.StreamId);
        Assert.Equal([0x80, 0, 0, 3, 200], frozen.Payload);
    }

    [Theory]
    [InlineData("")]
    [InlineData("u=3\n")]
    [InlineData("u=é")]
    public void Freeze_RejectsAPriorityUpdateValueOutsideVisibleAscii(string value)
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            FreezeOne(new TlsHttp2PriorityUpdateFrame { Value = value }));

        Assert.Contains("visible ASCII", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Freeze_RejectsAPriorityUpdateValueLongerThan256Characters()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            FreezeOne(new TlsHttp2PriorityUpdateFrame { Value = new string('u', 257) }));

        Assert.Contains("visible ASCII", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Freeze_AcceptsAPriorityUpdateValueOfExactly256Characters()
    {
        var frozen = FreezeOne(new TlsHttp2PriorityUpdateFrame
        {
            Value = new string('u', 256),
        });

        Assert.Equal(260, frozen.Payload.Length);
    }

    [Fact]
    public void Freeze_RejectsMoreThanSixteenFramesInOneList()
    {
        var frames = Enumerable.Range(0, 17)
            .Select(_ => (TlsHttp2RequestFrame)new TlsHttp2PingFrame())
            .ToArray();

        var exception = Assert.Throws<ArgumentException>(() =>
            TlsHttp2RequestFrameList.Freeze(frames, Parameter));

        Assert.Contains("at most 16 frames", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Freeze_AcceptsSixteenFramesInOneList()
    {
        var frames = Enumerable.Range(0, 16)
            .Select(_ => (TlsHttp2RequestFrame)new TlsHttp2PingFrame())
            .ToArray();

        Assert.Equal(16, TlsHttp2RequestFrameList.Freeze(frames, Parameter).Length);
    }

    [Fact]
    public void Freeze_CopiesADeclaredPayloadSoLaterMutationCannotChangeTheWire()
    {
        var payload = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var frame = new TlsHttp2PingFrame { Payload = payload };

        var frozen = FreezeOne(frame);
        payload[0] = 0xff;

        Assert.Equal([1, 2, 3, 4, 5, 6, 7, 8], frozen.Payload);
    }
}
