using System.Buffers.Binary;
using System.Net;
using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

/// <summary>
/// How the client cuts its own request body into DATA frames: the declared cap, its
/// interaction with the peer's advertised maximum, and its interaction with a declared pad.
/// </summary>
public sealed class Http2DataFramingTests
{
    /// <summary>The RFC 9113 section 6.5.2 default for SETTINGS_MAX_FRAME_SIZE.</summary>
    private const int DefaultMaximumFrameSize = 16_384;

    /// <summary>
    /// What the harness advertises in these tests. Larger than the default so that a client
    /// which ignored the declared cap would put the whole body in one frame — without this
    /// the peer's own maximum would produce the expected split on its own and the assertion
    /// could not fail.
    /// </summary>
    private const int AdvertisedMaximumFrameSize = 65_536;

    /// <summary>The body the END_STREAM placement tests send.</summary>
    private const int BodyOctets = 10_000;

    /// <summary>
    /// Read size for a streamed body, small enough that <see cref="BodyOctets"/> needs
    /// several reads and so several DATA frames.
    /// </summary>
    private const int StreamingChunk = 4_096;

    /// <summary>
    /// The declared cap only ever makes the client's own frames smaller, so with the peer
    /// advertising four times the default the split is the client's decision alone.
    /// </summary>
    [Fact]
    public async Task DeclaredMaxDataFrameSize_SizesEveryFrameAtThatSize()
    {
        var body = NewBody(40_000);

        var lengths = await PostAndCaptureDataAsync(
            body,
            maxDataFrameSize: DefaultMaximumFrameSize,
            padding: null);

        Assert.Equal(
            [DefaultMaximumFrameSize, DefaultMaximumFrameSize, 7_232],
            lengths.Select(frame => frame.Payload.Length));
    }

    /// <summary>
    /// The default is today's behaviour: frame as large as the peer permits. The same body
    /// and the same peer as the test above, with no cap declared, leaves in one frame.
    /// </summary>
    [Fact]
    public async Task NoDeclaredMaxDataFrameSize_FramesAtThePeersMaximum()
    {
        var body = NewBody(40_000);

        var lengths = await PostAndCaptureDataAsync(body, maxDataFrameSize: null, padding: null);

        Assert.Equal(body.Length, Assert.Single(lengths).Payload.Length);
    }

    /// <summary>
    /// The other side of the clamp: a declared cap can only ever make the client's frames
    /// smaller, never larger than the peer permits. RFC 9113 section 4.2 — "All implementations
    /// MUST be capable of receiving and minimally processing frames up to 2^14 octets in
    /// length, plus the 9-octet frame header... The size of a frame payload is limited by the
    /// maximum size that a receiver advertises in the SETTINGS_MAX_FRAME_SIZE setting" — and
    /// "An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds the size
    /// defined in SETTINGS_MAX_FRAME_SIZE". So the peer's advertised value wins over the
    /// declared cap whenever it is the smaller of the two.
    /// </summary>
    /// <remarks>
    /// The peer advertises 20000 rather than leaving the section 6.5.2 default of 16384 in
    /// force, so a client that ignored the SETTINGS frame and fell back on the fixed
    /// pre-SETTINGS floor would produce 16384-octet frames and fail this too. Only honouring
    /// what the peer actually said produces 20000.
    /// </remarks>
    [Fact]
    public async Task PeerMaximumFrameSize_BelowTheDeclaredCap_BindsInsteadOfIt()
    {
        const int PeerMaximum = 20_000;
        const int Cap = 40_000;
        // Under the 65535-octet initial send window RFC 9113 section 6.9.2 leaves in force,
        // so no WINDOW_UPDATE is needed and the split below is the frame-size decision alone.
        var body = NewBody(50_000);

        var lengths = await PostAndCaptureDataAsync(
            body,
            maxDataFrameSize: Cap,
            padding: null,
            advertisedMaximumFrameSize: PeerMaximum);

        Assert.Equal(
            [PeerMaximum, PeerMaximum, 10_000],
            lengths.Select(frame => frame.Payload.Length));
    }

    /// <summary>
    /// The pad comes out of the cap rather than being added on top of it. RFC 9113 section
    /// 6.1 puts the Pad Length octet and the padding inside the DATA frame payload and
    /// section 4.2 measures that whole payload, so a client that capped only the body octets
    /// would emit frames of <c>cap + 1 + padLength</c>.
    /// </summary>
    [Fact]
    public async Task MaxDataFrameSize_WithPadding_KeepsThePadInsideTheCap()
    {
        const int Cap = 4_096;
        const int Padding = 100;
        var body = NewBody(10_000);

        var frames = await PostAndCaptureDataAsync(body, Cap, Padding);

        Assert.All(
            frames,
            frame => Assert.InRange(frame.Payload.Length, 1, Cap));
        // Every frame but the remainder fills the cap exactly, pad included.
        Assert.Equal(Cap, frames[0].Payload.Length);
        Assert.All(frames, frame => Assert.Equal(Padding, frame.Payload[0]));
        // And the body still arrived whole: the pad is overhead, not lost body.
        Assert.Equal(
            body,
            frames.SelectMany(frame => frame.Payload[1..^Padding]).ToArray());
    }

    /// <summary>
    /// A cap too small to hold the pad and one octet of body can never produce a frame, so it
    /// fails as a request rather than waiting on flow-control credit that cannot help. Only a
    /// declared cap reaches this: the peer's maximum is at least 16384 (RFC 9113 section
    /// 6.5.2) and a pad costs at most 256 octets including its length field.
    /// </summary>
    [Fact]
    public async Task MaxDataFrameSize_SmallerThanItsPad_FailsInsteadOfStalling()
    {
        var body = NewBody(64);
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.Data.MaxDataFrameSize = 32;

        await Assert.ThrowsAsync<HttpRequestException>(() => Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new ByteArrayContent(body),
                };
                request.AddHeader("content-length", "-1");
                var requestOptions = TlsRequestOptions.For(request);
                requestOptions.DataPadding = 64;
                // The rejection lands after HEADERS, so a retry would open a second stream
                // the single-accept harness would wait out to its full timeout.
                requestOptions.EnableRetries = false;
                return await session.SendAsync(request, cancellationToken);
            },
            BodyExchange));
    }

    /// <summary>
    /// The ceiling is SETTINGS_MAX_FRAME_SIZE's own upper bound (RFC 9113 section 4.2). The
    /// floor is 1, not 16384: section 4.2's lower bound binds what an endpoint must be able
    /// to receive, not how small a sender may frame.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(16_777_216)]
    public void MaxDataFrameSize_OutsideItsRange_IsRejected(int size)
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.Data.MaxDataFrameSize = size;

        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsSession(options));
    }

    /// <summary>
    /// The default, and today's behaviour for a body supplied as a buffer: one DATA frame
    /// carrying the whole body and the flag.
    /// </summary>
    [Fact]
    public async Task BufferedBody_UnderTheDefault_ClosesOnItsLastDataFrame()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        Assert.Equal(
            TlsHttp2EndStreamPlacement.OnLastDataFrame,
            options.Http2.Data.NonEmptyBody);

        var frames = await CaptureDataAsync(options, PostBufferedAsync);

        var data = Assert.Single(frames);
        Assert.Equal(BodyOctets, data.Payload.Length);
        Assert.Equal(Http2FrameFlags.EndStream, data.Flags & Http2FrameFlags.EndStream);
    }

    /// <summary>
    /// The same buffered body under the other placement. RFC 9113 section 6.9.1 names the
    /// empty DATA frame carrying END_STREAM explicitly, so closing this way is conformant.
    /// </summary>
    [Fact]
    public async Task BufferedBody_UnderSeparateEmptyDataFrame_ClosesWithAnEmptyFrame()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.Data.NonEmptyBody = TlsHttp2EndStreamPlacement.SeparateEmptyDataFrame;

        var frames = await CaptureDataAsync(options, PostBufferedAsync);

        Assert.Equal(2, frames.Length);
        Assert.Equal(BodyOctets, frames[0].Payload.Length);
        Assert.Equal(0, frames[0].Flags & Http2FrameFlags.EndStream);
        Assert.Empty(frames[1].Payload);
        Assert.Equal(Http2FrameFlags.EndStream, frames[1].Flags & Http2FrameFlags.EndStream);
    }

    /// <summary>
    /// The placement is the persona's, not the body-supplying code path's: a streamed body
    /// under the default closes on its last DATA frame, where before this it always closed
    /// with a separate empty one.
    /// </summary>
    [Fact]
    public async Task StreamedBody_UnderOnLastDataFrame_ClosesOnItsLastDataFrame()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };

        var frames = await CaptureDataAsync(options, PostStreamedAsync);

        Assert.True(frames.Length > 1, "the streamed body did not need several frames");
        Assert.All(frames, frame => Assert.NotEmpty(frame.Payload));
        Assert.Equal(
            Http2FrameFlags.EndStream,
            frames[^1].Flags & Http2FrameFlags.EndStream);
        Assert.Equal(BodyOctets, frames.Sum(frame => frame.Payload.Length));
    }

    /// <summary>The same streamed body under the other placement.</summary>
    [Fact]
    public async Task StreamedBody_UnderSeparateEmptyDataFrame_ClosesWithAnEmptyFrame()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.Data.NonEmptyBody = TlsHttp2EndStreamPlacement.SeparateEmptyDataFrame;

        var frames = await CaptureDataAsync(options, PostStreamedAsync);

        Assert.Empty(frames[^1].Payload);
        Assert.Equal(
            Http2FrameFlags.EndStream,
            frames[^1].Flags & Http2FrameFlags.EndStream);
        Assert.All(frames[..^1], frame => Assert.Equal(0, frame.Flags & Http2FrameFlags.EndStream));
        Assert.Equal(BodyOctets, frames.Sum(frame => frame.Payload.Length));
    }

    /// <summary>
    /// A streamed body whose length the caller never declared cannot honour
    /// <see cref="TlsHttp2EndStreamPlacement.OnLastDataFrame"/>: the last chunk is only
    /// recognisable after the read that returns nothing, and holding the previous chunk
    /// across that read is the deadlock 892f951 removed. The separate empty frame is the
    /// fallback, and it is the persona's cost of not declaring a length.
    /// </summary>
    [Fact]
    public async Task StreamedBodyOfUnknownLength_KeepsTheSeparateEmptyFrame()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };

        var frames = await CaptureDataAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var content = new StreamContent(new UnseekableStream(NewBody(BodyOctets)));
                using var message = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = content,
                };
                message.AddHeader("transfer-encoding", "chunked");
                Assert.Null(content.Headers.ContentLength);
                await using var responseBody = new MemoryStream();
                return await session.SendStreamingAsync(
                    message,
                    responseBody,
                    new TlsStreamingOptions { BufferSize = StreamingChunk },
                    cancellationToken);
            });

        Assert.Empty(frames[^1].Payload);
        Assert.Equal(
            Http2FrameFlags.EndStream,
            frames[^1].Flags & Http2FrameFlags.EndStream);
        Assert.Equal(BodyOctets, frames.Sum(frame => frame.Payload.Length));
    }

    /// <summary>The default: a request with no body ends its stream on HEADERS.</summary>
    [Fact]
    public async Task EmptyBodyEndsOnHeaders_True_LeavesNoDataFrameBehind()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        Assert.True(options.Http2.Data.EmptyBodyEndsOnHeaders);

        var frames = await CaptureFramesAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                return await session.SendAsync(request, cancellationToken);
            },
            Http2WireCapture.MinimalExchange);

        var headers = frames.Single(frame => frame.Type == Http2FrameType.Headers);
        Assert.Equal(Http2FrameFlags.EndStream, headers.Flags & Http2FrameFlags.EndStream);
        Assert.DoesNotContain(frames, frame => frame.Type == Http2FrameType.Data);
    }

    /// <summary>
    /// With it off the header block leaves without the flag and a zero-length DATA frame
    /// carries it. That frame is never padded even though the request declares a pad: RFC
    /// 9113 section 6.9.1 exempts a zero-length END_STREAM frame from flow control, and
    /// padding it would make it need credit this path never reserves.
    /// </summary>
    [Fact]
    public async Task EmptyBodyEndsOnHeaders_False_ClosesWithAnUnpaddedEmptyDataFrame()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.Data.EmptyBodyEndsOnHeaders = false;

        var frames = await CaptureFramesAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                TlsRequestOptions.For(request).DataPadding = 8;
                return await session.SendAsync(request, cancellationToken);
            },
            BodyExchange);

        var headers = frames.Single(frame => frame.Type == Http2FrameType.Headers);
        Assert.Equal(0, headers.Flags & Http2FrameFlags.EndStream);
        var data = Assert.Single(frames, frame => frame.Type == Http2FrameType.Data);
        Assert.Empty(data.Payload);
        Assert.Equal(Http2FrameFlags.EndStream, data.Flags & Http2FrameFlags.EndStream);
        Assert.Equal(0, data.Flags & Http2FrameFlags.Padded);
    }

    /// <summary>
    /// The empty frame the other placement adds is exempt for the same reason, and is
    /// reachable from the buffered path for the first time since Task 14.
    /// </summary>
    [Fact]
    public async Task SeparateEmptyDataFrame_IsNeverPadded()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.Data.NonEmptyBody = TlsHttp2EndStreamPlacement.SeparateEmptyDataFrame;

        var frames = await CaptureDataAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new ByteArrayContent(NewBody(BodyOctets)),
                };
                request.AddHeader("content-length", "-1");
                TlsRequestOptions.For(request).DataPadding = 8;
                return await session.SendAsync(request, cancellationToken);
            });

        Assert.Equal(Http2FrameFlags.Padded, frames[0].Flags & Http2FrameFlags.Padded);
        Assert.Empty(frames[^1].Payload);
        Assert.Equal(0, frames[^1].Flags & Http2FrameFlags.Padded);
    }

    /// <summary>Every enum-typed option is checked for being a defined value.</summary>
    [Fact]
    public void NonEmptyBody_OutsideItsEnum_IsRejected()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.Data.NonEmptyBody = (TlsHttp2EndStreamPlacement)7;

        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsSession(options));
    }

    private static Task<TlsResponse> PostBufferedAsync(
        TlsSession session,
        string url,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new ByteArrayContent(NewBody(BodyOctets)),
        };
        request.AddHeader("content-length", "-1");
        return session.SendAsync(request, cancellationToken);
    }

    private static async Task<TlsResponse> PostStreamedAsync(
        TlsSession session,
        string url,
        CancellationToken cancellationToken)
    {
        using var content = new StreamContent(new MemoryStream(NewBody(BodyOctets)));
        using var message = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        message.AddHeader("transfer-encoding", "chunked");
        await using var responseBody = new MemoryStream();
        return await session.SendStreamingAsync(
            message,
            responseBody,
            new TlsStreamingOptions { BufferSize = StreamingChunk },
            cancellationToken);
    }

    private static async Task<CapturedFrame[]> CaptureDataAsync(
        TlsSessionOptions options,
        Func<TlsSession, string, CancellationToken, Task<TlsResponse>> request)
    {
        var frames = await CaptureFramesAsync(options, request, BodyExchange);
        return [.. frames.Where(frame => frame.Type == Http2FrameType.Data)];
    }

    private static async Task<CapturedFrame[]> CaptureFramesAsync(
        TlsSessionOptions options,
        Func<TlsSession, string, CancellationToken, Task<TlsResponse>> request,
        Http2ServerScript script)
    {
        var result = await Http2WireCapture.RunAsync(options, request, script);
        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        return [.. result.ClientFrames];
    }

    /// <summary>
    /// A read-only stream that cannot report its length, so <see cref="StreamContent"/>
    /// leaves <c>Content-Length</c> undeclared.
    /// </summary>
    private sealed class UnseekableStream(byte[] content) : Stream
    {
        private int _position;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = Math.Min(count, content.Length - _position);
            content.AsSpan(_position, read).CopyTo(buffer.AsSpan(offset, read));
            _position += read;
            return read;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    private static byte[] NewBody(int length)
    {
        var body = new byte[length];
        // Deterministic and non-uniform, so a frame boundary that moved shows up as a
        // content mismatch rather than as identical octets in a different place.
        for (var index = 0; index < body.Length; index++)
        {
            body[index] = (byte)(index * 31 % 251);
        }
        return body;
    }

    /// <summary>
    /// POSTs <paramref name="body"/> over a connection whose peer has already advertised
    /// <see cref="AdvertisedMaximumFrameSize"/>, and returns the DATA frames it produced.
    /// </summary>
    private static async Task<CapturedFrame[]> PostAndCaptureDataAsync(
        byte[] body,
        int? maxDataFrameSize,
        int? padding,
        int advertisedMaximumFrameSize = AdvertisedMaximumFrameSize)
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.Data.MaxDataFrameSize = maxDataFrameSize;

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                // A completed first response is what makes the peer's SETTINGS observable to
                // the request below. The client writes its own preface and first request
                // without waiting for the peer, so a POST issued straight away would race the
                // read loop's application of SETTINGS_MAX_FRAME_SIZE; a response cannot
                // arrive before the SETTINGS frame written ahead of it has been processed.
                using var warmup = new HttpRequestMessage(HttpMethod.Get, url);
                await session.SendAsync(warmup, cancellationToken);

                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new ByteArrayContent(body),
                };
                request.AddHeader("content-length", "-1");
                TlsRequestOptions.For(request).DataPadding = padding;
                return await session.SendAsync(request, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);
                await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
                var settings = new byte[6];
                BinaryPrimitives.WriteUInt16BigEndian(settings, 0x5);
                BinaryPrimitives.WriteUInt32BigEndian(
                    settings.AsSpan(2),
                    (uint)advertisedMaximumFrameSize);
                await server.WriteFrameAsync(
                    Http2FrameType.Settings,
                    0,
                    0,
                    settings,
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                var warmup = await server.ReadUntilAsync(
                    Http2FrameType.Headers,
                    cancellationToken);
                await CompleteAsync(server, warmup.StreamId, cancellationToken);

                var headers = await server.ReadUntilAsync(
                    Http2FrameType.Headers,
                    cancellationToken);
                await ReadToEndOfBodyAsync(server, cancellationToken);
                await CompleteAsync(server, headers.StreamId, cancellationToken);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        return [.. result.ClientFrames.Where(frame => frame.Type == Http2FrameType.Data)];
    }

    /// <summary>
    /// Reads the client's request through the DATA frame carrying END_STREAM, then answers
    /// 200. Counting frames instead would race the SETTINGS ACK the read loop writes on its
    /// own clock.
    /// </summary>
    private static readonly Http2ServerScript BodyExchange =
        async (server, cancellationToken) =>
        {
            await server.ReadPrefaceAsync(cancellationToken);
            await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
            await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
            await server.FlushAsync(cancellationToken);
            var headers = await server.ReadUntilAsync(Http2FrameType.Headers, cancellationToken);
            await ReadToEndOfBodyAsync(server, cancellationToken);
            await CompleteAsync(server, headers.StreamId, cancellationToken);
        };

    private static async Task ReadToEndOfBodyAsync(
        Http2WireServer server,
        CancellationToken cancellationToken)
    {
        CapturedFrame frame;
        do
        {
            frame = await server.ReadFrameAsync(cancellationToken);
        }
        while (frame.Type != Http2FrameType.Data ||
            (frame.Flags & Http2FrameFlags.EndStream) == 0);
    }

    private static async Task CompleteAsync(
        Http2WireServer server,
        int streamId,
        CancellationToken cancellationToken)
    {
        // 0x88 is the static-table entry for ":status: 200".
        await server.WriteFrameAsync(
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
            streamId,
            [0x88],
            cancellationToken);
        await server.FlushAsync(cancellationToken);
    }
}
