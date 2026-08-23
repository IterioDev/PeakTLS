using System.Buffers.Binary;
using System.Net;
using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

/// <summary>
/// The WINDOW_UPDATE frames a server actually observes for each declared credit policy.
/// </summary>
/// <remarks>
/// <para>
/// Every test here downloads a body several times the size of one DATA frame and asserts
/// the increments the client returned, plus that the transfer <em>completed</em>. The
/// second half is not decoration: RFC 9113 section 6.9.1 has a peer send only what the
/// advertised window permits, so any policy that withholds credit the peer is waiting on
/// hangs the connection rather than producing wrong bytes.
/// </para>
/// <para>
/// The declared windows are widened in the preface so the whole body fits inside them.
/// That is what lets the server script send the body in one go and read the client's
/// credit afterwards, instead of interleaving the two and having to know the answer in
/// order to observe it.
/// </para>
/// </remarks>
public sealed class Http2FlowControlTests
{
    private const int Chunk = 16_384;
    private const int Chunks = 6;
    private const int BodyLength = Chunk * Chunks;
    private const int DeclaredWindow = 1_048_576;
    private const ushort InitialWindowSizeSetting = 0x4;

    /// <summary>
    /// How long a drain waits for one more frame before calling the trace complete. The
    /// client and server share a loopback socket, so this is three orders of magnitude
    /// more than a frame in flight needs; it bounds the negative direction only.
    /// </summary>
    private static readonly TimeSpan Quiet = TimeSpan.FromMilliseconds(500);

    [Fact]
    public async Task Default_CreditsEveryDataFrameAtItsOwnLength()
    {
        var updates = await DownloadAsync(WideWindows());

        Assert.Equal(Enumerable.Repeat(Chunk, Chunks), Increments(updates, 0));
        // One short of Chunks: the stream update for the DATA frame carrying END_STREAM is
        // suppressed by default.
        Assert.Equal(Enumerable.Repeat(Chunk, Chunks - 1), Increments(updates, 1));
    }

    [Fact]
    public async Task Threshold_WithholdsCreditUntilTheDeclaredAmountIsOutstanding()
    {
        var options = WideWindows();
        options.Http2.FlowControl.ConnectionWindowUpdateThreshold = 2 * Chunk;
        options.Http2.FlowControl.StreamWindowUpdateThreshold = 2 * Chunk;

        var updates = await DownloadAsync(options);

        // Six frames, so the threshold is crossed on the second, fourth and sixth.
        Assert.Equal(Enumerable.Repeat(2 * Chunk, 3), Increments(updates, 0));
        // The sixth carries END_STREAM, so its stream-level crossing is suppressed.
        Assert.Equal(Enumerable.Repeat(2 * Chunk, 2), Increments(updates, 1));
    }

    [Fact]
    public async Task Fixed_ReturnsTheDeclaredIncrementWhateverArrived()
    {
        const uint Declared = 40_000;
        var options = WideWindows();
        options.Http2.FlowControl.Increment = TlsHttp2WindowUpdateIncrement.Fixed;
        options.Http2.FlowControl.FixedIncrement = Declared;

        var updates = await DownloadAsync(options);

        Assert.Equal(Enumerable.Repeat((int)Declared, Chunks), Increments(updates, 0));
        Assert.Equal(Enumerable.Repeat((int)Declared, Chunks - 1), Increments(updates, 1));
    }

    [Fact]
    public async Task RefillToInitial_ReturnsEverythingTheWindowIsShortOfItsDeclaredSize()
    {
        var options = WideWindows();
        options.Http2.FlowControl.Increment = TlsHttp2WindowUpdateIncrement.RefillToInitial;

        // The application is parked holding the first frame while the rest of the body
        // arrives, so the window is short the whole body by the time any credit is
        // computed. BytesAccounted would still return the parked frame's own 16384.
        var connection = await DownloadParkedAsync(options, streamId: 0);

        Assert.Empty(connection.WhileParked);
        Assert.Equal(Enumerable.Repeat(BodyLength, 1), connection.AfterRelease);
    }

    [Fact]
    public async Task RefillToInitial_RestoresTheStreamWindowInOneUpdateToo()
    {
        var options = WideWindows();
        options.Http2.FlowControl.Increment = TlsHttp2WindowUpdateIncrement.RefillToInitial;

        var stream = await DownloadParkedAsync(options, streamId: 1);

        Assert.Empty(stream.WhileParked);
        Assert.Equal(Enumerable.Repeat(BodyLength, 1), stream.AfterRelease);
    }

    [Fact]
    public async Task OnReceive_CreditsBeforeTheApplicationHasAcceptedAnything()
    {
        var options = WideWindows();
        options.Http2.FlowControl.Trigger = TlsHttp2WindowUpdateTrigger.OnReceive;

        var connection = await DownloadParkedAsync(options, streamId: 0);

        // Every increment was returned while the application was provably still holding
        // the first frame...
        Assert.Equal(Enumerable.Repeat(Chunk, Chunks), connection.WhileParked);
        // ...and none of it is returned a second time once the application catches up.
        Assert.Empty(connection.AfterRelease);
    }

    [Fact]
    public async Task OnReceive_CreditsTheStreamAtReceiptToo()
    {
        var options = WideWindows();
        options.Http2.FlowControl.Trigger = TlsHttp2WindowUpdateTrigger.OnReceive;

        var stream = await DownloadParkedAsync(options, streamId: 1);

        // One short of Chunks: the update for the END_STREAM frame is suppressed.
        Assert.Equal(Enumerable.Repeat(Chunk, Chunks - 1), stream.WhileParked);
        Assert.Empty(stream.AfterRelease);
    }

    [Fact]
    public async Task OnConsume_ReturnsNothingWhileTheApplicationIsHoldingTheOctets()
    {
        // The same harness with the default trigger, so the two halves are exchanged.
        var connection = await DownloadParkedAsync(WideWindows(), streamId: 0);

        Assert.Empty(connection.WhileParked);
        Assert.Equal(Enumerable.Repeat(Chunk, Chunks), connection.AfterRelease);
    }

    [Fact]
    public async Task Order_ConnectionFirstByDefault()
    {
        var updates = await DownloadAsync(WideWindows());

        // Five pairs, then the sixth frame's connection update alone: the stream update
        // for the frame carrying END_STREAM is suppressed.
        Assert.Equal([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0], StreamIds(updates));
    }

    [Fact]
    public async Task Order_StreamFirst_PutsTheStreamUpdateAhead()
    {
        var options = WideWindows();
        options.Http2.FlowControl.Order = TlsHttp2WindowUpdateOrder.StreamFirst;

        var updates = await DownloadAsync(options);

        Assert.Equal([1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0], StreamIds(updates));
    }

    [Fact]
    public async Task Coalesce_PutsBothUpdatesInOneRecord()
    {
        var coalesced = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        coalesced.Http2.FlowControl.CoalesceConnectionAndStream = true;

        // Two WINDOW_UPDATE frames are 2 * (9 + 4) octets. Separately written they are two
        // records and one read sees only the first.
        Assert.Equal(26, await FirstCreditRecordAsync(coalesced));
        Assert.Equal(13, await FirstCreditRecordAsync(
            new TlsSessionOptions { Profile = TlsProfiles.Modern }));
    }

    [Fact]
    public async Task SuppressStreamUpdateOnEndStream_False_CreditsTheClosedStreamAnyway()
    {
        var options = WideWindows();
        options.Http2.FlowControl.SuppressStreamUpdateOnEndStream = false;

        var updates = await DownloadAsync(options);

        Assert.Equal(Enumerable.Repeat(Chunk, Chunks), Increments(updates, 0));
        // RFC 9113 section 6.9 permits a WINDOW_UPDATE on a stream the client has already
        // seen END_STREAM on, so all six are emitted rather than five.
        Assert.Equal(Enumerable.Repeat(Chunk, Chunks), Increments(updates, 1));
    }

    [Fact]
    public void StreamThreshold_AboveTheDeclaredInitialWindowIsRejected()
    {
        var options = new TlsHttp2Options
        {
            Preface =
            [
                new TlsHttp2SettingsFrame
                {
                    Settings = [new TlsHttp2SettingValue(InitialWindowSizeSetting, 32_768)],
                },
            ],
        };
        options.FlowControl.StreamWindowUpdateThreshold = 32_769;

        // One octet past the window it draws on: the peer spends the window before the
        // threshold is reached, so no credit is ever returned and the stream stalls for
        // good.
        var exception = Assert.Throws<ArgumentException>(() => options.Snapshot());
        Assert.Equal(nameof(TlsHttp2Options.FlowControl), exception.ParamName);

        options.FlowControl.StreamWindowUpdateThreshold = 32_768;
        Assert.Equal(32_768, options.Snapshot().FlowControl.StreamWindowUpdateThreshold);
    }

    [Fact]
    public void ConnectionThreshold_AboveTheDeclaredConnectionWindowIsRejected()
    {
        var options = new TlsHttp2Options
        {
            Preface =
            [
                new TlsHttp2SettingsFrame(),
                // SETTINGS_INITIAL_WINDOW_SIZE does not cover the connection window
                // (RFC 9113 section 6.9.2), so its 65535 only moves by this.
                new TlsHttp2WindowUpdateFrame { Increment = 1_000 },
            ],
        };
        options.FlowControl.ConnectionWindowUpdateThreshold = 66_536;

        var exception = Assert.Throws<ArgumentException>(() => options.Snapshot());
        Assert.Equal(nameof(TlsHttp2Options.FlowControl), exception.ParamName);

        // 65535 + 1000 exactly, which is reachable and so must be accepted.
        options.FlowControl.ConnectionWindowUpdateThreshold = 66_535;
        Assert.Equal(66_535, options.Snapshot().FlowControl.ConnectionWindowUpdateThreshold);
    }

    [Fact]
    public void FixedIncrement_OfZeroIsRejected()
    {
        var options = new TlsHttp2Options();
        options.FlowControl.Increment = TlsHttp2WindowUpdateIncrement.Fixed;
        options.FlowControl.FixedIncrement = 0;

        // RFC 9113 section 6.9 makes a zero increment a PROTOCOL_ERROR at the receiver.
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
        Assert.Equal(nameof(TlsHttp2FlowControlOptions.FixedIncrement), exception.ParamName);
    }

    [Fact]
    public void FixedIncrement_WiderThanTheFieldIsRejected()
    {
        var options = new TlsHttp2Options();
        options.FlowControl.Increment = TlsHttp2WindowUpdateIncrement.Fixed;
        options.FlowControl.FixedIncrement = (uint)int.MaxValue + 1;

        // The Window Size Increment field is 31 bits (RFC 9113 section 6.9, Figure 11).
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
        Assert.Equal(nameof(TlsHttp2FlowControlOptions.FixedIncrement), exception.ParamName);
    }

    [Fact]
    public void FixedIncrement_OfZeroIsAcceptedWhenTheIncrementIsNotFixed()
    {
        // Its default of 0 is out of the legal range, so rejecting it unconditionally would
        // reject every configuration that never emits one. Anything inside the range must
        // then reach the frozen configuration unchanged whatever the mode, which is what the
        // second half asserts — 2147483647 is neither the property default nor a value any
        // other field could supply.
        var options = new TlsHttp2Options();
        options.FlowControl.Increment = TlsHttp2WindowUpdateIncrement.RefillToInitial;

        Assert.Equal(0, options.Snapshot().FlowControl.FixedIncrement);

        options.FlowControl.FixedIncrement = int.MaxValue;
        Assert.Equal(int.MaxValue, options.Snapshot().FlowControl.FixedIncrement);
    }

    [Fact]
    public void FixedIncrement_WiderThanTheFieldIsRejectedWhateverTheIncrementIs()
    {
        var options = new TlsHttp2Options();
        options.FlowControl.Increment = TlsHttp2WindowUpdateIncrement.BytesAccounted;
        options.FlowControl.FixedIncrement = 3_000_000_000;

        // The upper bound is not mode-gated. The frozen configuration narrows the field to
        // int, so an unchecked 3000000000 would freeze as -1294967296 and wait there for the
        // next mode that reads it — an increment RFC 9113 section 6.9 has no encoding for,
        // since the field is 31 bits and its legal range starts at 1.
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
        Assert.Equal(nameof(TlsHttp2FlowControlOptions.FixedIncrement), exception.ParamName);
    }

    /// <summary>
    /// A stream that dies with DATA still queued has already spent that DATA's share of the
    /// connection window, so RFC 9113 section 6.9.1 — which has a receiver account every
    /// flow-controlled frame against the connection window so the two ends' views cannot
    /// drift — leaves the client owing it back. Unreturned, the window is permanently smaller
    /// for every later stream on the connection.
    /// </summary>
    /// <remarks>
    /// The parked destination is what makes this deterministic rather than a race: the pump
    /// cannot take a second frame while blocked on the first, so all six DATA frames are
    /// provably accounted and uncredited when the reset arrives. The second request is not
    /// decoration either — the harness accepts one socket, so it can only be answered on the
    /// same connection, which is the connection whose window is at stake.
    /// </remarks>
    [Fact]
    public async Task ResetStream_ReturnsTheConnectionCreditItsUndrainedFramesSpent()
    {
        List<CapturedFrame> recovered = [];
        await using var destination = new ParkingStream();
        var result = await Http2WireCapture.RunAsync(
            WideWindows(),
            async (session, url, cancellationToken) =>
            {
                using var abandoned = new HttpRequestMessage(HttpMethod.Get, url);
                // A reset stream is not a transport failure, so a retry would be replayed onto
                // a second connection the single-accept harness cannot provide.
                TlsRequestOptions.For(abandoned).EnableRetries = false;
                await Assert.ThrowsAsync<HttpRequestException>(
                    () => session.SendStreamingAsync(
                        abandoned,
                        destination,
                        new TlsStreamingOptions(),
                        cancellationToken));

                return await session.GetAsync(url, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                var opened = await SendBodyAsync(server, cancellationToken);
                await destination.Parked.WaitAsync(cancellationToken);

                // A PING is answered from the read loop in arrival order (RFC 9113 section
                // 6.7), so its acknowledgement proves every DATA frame above was already
                // charged to the connection window before the reset below.
                await server.WriteFrameAsync(
                    Http2FrameType.Ping,
                    0,
                    0,
                    [1, 2, 3, 4, 5, 6, 7, 8],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
                var reader = new FrameReader(server, cancellationToken);
                while ((await reader.NextAsync()).Type != Http2FrameType.Ping)
                {
                }

                // Nothing has been credited yet: the application is holding the first frame
                // and the default trigger credits on consumption.
                Assert.Empty(await DrainAsync(reader));

                var code = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(code, (uint)Http2ErrorCode.Cancel);
                await server.WriteFrameAsync(
                    Http2FrameType.RstStream,
                    0,
                    opened.StreamId,
                    code,
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                // The recovery credit and the second request's header block race each other,
                // so both phases are collected rather than one being read past.
                CapturedFrame second;
                while (true)
                {
                    var frame = await reader.NextAsync();
                    if (frame.Type == Http2FrameType.Headers)
                    {
                        second = frame;
                        break;
                    }
                    if (frame.Type == Http2FrameType.WindowUpdate)
                    {
                        recovered.Add(frame);
                    }
                }
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    second.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
                recovered.AddRange(await DrainAsync(reader));
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        // The second response is empty, so every octet credited after the reset is the dead
        // stream's — all six frames of it, in one update.
        Assert.Equal([BodyLength], Increments(recovered, 0));
    }

    /// <summary>Widens both declared receive windows so the whole body fits in them.</summary>
    private static TlsSessionOptions WideWindows()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.Preface =
        [
            // SETTINGS_INITIAL_WINDOW_SIZE, RFC 9113 section 6.5.2.
            new TlsHttp2SettingsFrame
            {
                Settings = [new TlsHttp2SettingValue(InitialWindowSizeSetting, DeclaredWindow)],
            },
            // The connection window is not covered by that setting (section 6.9.2), so it
            // is topped up from its own 65535 separately.
            new TlsHttp2WindowUpdateFrame { Increment = DeclaredWindow - 65_535 },
        ];
        return options;
    }

    /// <summary>The streams a client's WINDOW_UPDATE frames addressed, in order.</summary>
    private static int[] StreamIds(IEnumerable<CapturedFrame> updates) =>
        updates.Select(frame => frame.StreamId).ToArray();

    /// <summary>
    /// Answers one 16384-octet DATA frame and returns the size of the first record the
    /// client wrote afterwards, which is its credit for that frame.
    /// </summary>
    private static async Task<int> FirstCreditRecordAsync(TlsSessionOptions options)
    {
        var delivered = 0;
        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, cancellationToken) => session.GetAsync(url, cancellationToken),
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);
                var headers = await server.ReadUntilAsync(
                    Http2FrameType.Headers,
                    cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders,
                    headers.StreamId,
                    [0x88],
                    cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Data,
                    0,
                    headers.StreamId,
                    new byte[Chunk],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                // The client writes nothing else between the request and this credit, so
                // one read is exactly the batch the credit was written in.
                delivered = await server.ReadOnceAsync(64, cancellationToken);

                // A zero-length END_STREAM frame is exempt from flow control (RFC 9113
                // section 6.9.1), so finishing this way adds no further credit to observe.
                await server.WriteFrameAsync(
                    Http2FrameType.Data,
                    Http2FrameFlags.EndStream,
                    headers.StreamId,
                    [],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal(Chunk, result.Response.Body.Length);
        return delivered;
    }

    /// <summary>The increments a client returned on <paramref name="streamId"/>, in order.</summary>
    private static int[] Increments(IEnumerable<CapturedFrame> updates, int streamId) =>
        updates
            .Where(frame => frame.StreamId == streamId)
            .Select(frame => BinaryPrimitives.ReadInt32BigEndian(frame.Payload))
            .ToArray();

    /// <summary>
    /// Downloads <see cref="BodyLength"/> octets into a buffered response and returns every
    /// WINDOW_UPDATE the client wrote.
    /// </summary>
    private static async Task<IReadOnlyList<CapturedFrame>> DownloadAsync(TlsSessionOptions options)
    {
        List<CapturedFrame> updates = [];
        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, cancellationToken) => session.GetAsync(url, cancellationToken),
            async (server, cancellationToken) =>
            {
                await SendBodyAsync(server, cancellationToken);
                updates.AddRange(await DrainAsync(new FrameReader(server, cancellationToken)));
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal(BodyLength, result.Response.Body.Length);
        return updates;
    }

    /// <summary>
    /// Downloads the same body into a destination that parks on its first write, so the
    /// application is provably holding the first frame while the rest of the body arrives,
    /// and splits the client's WINDOW_UPDATE trace at the moment the application is
    /// released.
    /// </summary>
    /// <remarks>
    /// Both halves matter. The first says what the client credited for octets nobody had
    /// accepted; the second says what it credited afterwards, which is where a policy that
    /// credits the same octets twice — inflating the peer's view of the window past
    /// anything that was consumed — shows up.
    /// </remarks>
    private static async Task<(int[] WhileParked, int[] AfterRelease)> DownloadParkedAsync(
        TlsSessionOptions options,
        int streamId)
    {
        List<CapturedFrame> parked = [];
        List<CapturedFrame> released = [];
        await using var destination = new ParkingStream();
        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var message = new HttpRequestMessage(HttpMethod.Get, url);
                return await session.SendStreamingAsync(
                    message,
                    destination,
                    new TlsStreamingOptions(),
                    cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                await SendBodyAsync(server, cancellationToken);

                // The pump cannot credit anything it has not taken off the channel, and it
                // cannot take a second frame while parked on the first.
                await destination.Parked.WaitAsync(cancellationToken);

                // A PING is answered from the read loop in arrival order (RFC 9113 section
                // 6.7), so its acknowledgement proves every DATA frame above was already
                // accounted. Without it the drain would be racing the reader rather than
                // observing a settled state.
                await server.WriteFrameAsync(
                    Http2FrameType.Ping,
                    0,
                    0,
                    [1, 2, 3, 4, 5, 6, 7, 8],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
                var reader = new FrameReader(server, cancellationToken);
                while (true)
                {
                    var frame = await reader.NextAsync();
                    if (frame.Type == Http2FrameType.Ping)
                    {
                        break;
                    }
                    parked.Add(frame);
                }
                parked.AddRange(await DrainAsync(reader));

                destination.Release();
                released.AddRange(await DrainAsync(reader));
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal(BodyLength, destination.Written);
        return (Increments(parked, streamId), Increments(released, streamId));
    }

    /// <summary>
    /// Answers the client's request with <see cref="Chunks"/> DATA frames, the last of them
    /// carrying END_STREAM, and returns the HEADERS frame that opened the stream.
    /// </summary>
    private static async Task<CapturedFrame> SendBodyAsync(
        Http2WireServer server,
        CancellationToken cancellationToken)
    {
        await server.ReadPrefaceAsync(cancellationToken);
        var headers = await server.ReadUntilAsync(Http2FrameType.Headers, cancellationToken);
        await server.WriteFrameAsync(
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders,
            headers.StreamId,
            [0x88],
            cancellationToken);
        var chunk = new byte[Chunk];
        for (var index = 0; index < Chunks; index++)
        {
            await server.WriteFrameAsync(
                Http2FrameType.Data,
                index == Chunks - 1 ? Http2FrameFlags.EndStream : (byte)0,
                headers.StreamId,
                chunk,
                cancellationToken);
        }
        await server.FlushAsync(cancellationToken);
        return headers;
    }

    /// <summary>Reads WINDOW_UPDATE frames until <see cref="Quiet"/> passes without one.</summary>
    private static async Task<List<CapturedFrame>> DrainAsync(FrameReader reader)
    {
        List<CapturedFrame> frames = [];
        while (await reader.TryNextAsync(Quiet) is { } frame)
        {
            if (frame.Type == Http2FrameType.WindowUpdate)
            {
                frames.Add(frame);
            }
        }
        return frames;
    }

    /// <summary>
    /// A one-frame lookahead over <see cref="Http2WireServer"/>. Exactly one read is ever
    /// outstanding and a read is never cancelled, so a frame that misses a probe's bound is
    /// handed to the next call instead of being lost to a half-consumed read.
    /// </summary>
    private sealed class FrameReader(Http2WireServer server, CancellationToken cancellationToken)
    {
        private Task<CapturedFrame>? _pending;

        public async Task<CapturedFrame> NextAsync()
        {
            var pending = _pending ??= server.ReadFrameAsync(cancellationToken);
            _pending = null;
            return await pending;
        }

        public async Task<CapturedFrame?> TryNextAsync(TimeSpan within)
        {
            var pending = _pending ??= server.ReadFrameAsync(cancellationToken);
            if (await Task.WhenAny(pending, Task.Delay(within, CancellationToken.None)) != pending)
            {
                return null;
            }
            _pending = null;
            return await pending;
        }
    }

    /// <summary>
    /// A response destination that blocks on its first write until released, parking the
    /// body pump with octets the application has not accepted.
    /// </summary>
    private sealed class ParkingStream : Stream
    {
        private readonly TaskCompletionSource _parked =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private long _written;

        public Task Parked => _parked.Task;

        public long Written => Interlocked.Read(ref _written);

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public void Release() => _release.TrySetResult();

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            _parked.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            Interlocked.Add(ref _written, buffer.Length);
        }

        public override Task WriteAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override void Write(byte[] buffer, int offset, int count) =>
            WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            Release();
            base.Dispose(disposing);
        }
    }
}
