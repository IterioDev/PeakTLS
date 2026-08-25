using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;
using System.Threading.Channels;

namespace TlsClient;

internal sealed class Http2Connection : IHttpConnection
{
    private static readonly byte[] ClientPreface =
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    /// <summary>
    /// How many frames one field block may span — the HEADERS or PUSH_PROMISE frame plus
    /// its CONTINUATION frames (RFC 9113 sections 4.3, 6.10).
    /// </summary>
    /// <remarks>
    /// The octet cap in <see cref="AppendHeaderFragment"/> cannot bound the loop on its
    /// own: a peer that withholds END_HEADERS and then sends zero-length CONTINUATION
    /// frames forever never advances it, and the read loop is the only reader for every
    /// stream on the connection. That is the CONTINUATION flood of CVE-2024-27316, and
    /// RFC 9113 section 10.5 is what permits closing on it ("An endpoint can also close a
    /// connection using the ENHANCE_YOUR_CALM error code if the peer sends field blocks
    /// that are excessively large").
    /// <para>
    /// 256 is chosen against what a legitimate peer needs. Section 6.5.2 floors
    /// SETTINGS_MAX_FRAME_SIZE at 16384 octets, so a peer fragmenting at its own advertised
    /// minimum carries at least 4 MiB of compressed field block within this count — far
    /// past <c>MaximumResponseHeaderBytes</c>, which bounds the same block and is what
    /// legitimately rejects an oversized one. Only a peer fragmenting far below the floor
    /// it advertised can reach this bound, and that is the attack, not a real client.
    /// </para>
    /// </remarks>
    private const int MaximumHeaderBlockFrames = 256;

    /// <summary>
    /// How many rejected push streams may be outstanding before the connection is ended.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This client never accepts a push, so every PUSH_PROMISE is answered with a RST_STREAM and
    /// its promised identifier is remembered until the peer stops sending frames for it. The set
    /// is therefore driven entirely by the peer and needs a ceiling. RFC 9113 section 5.4.1
    /// permits one: "An endpoint can end a connection at any time. In particular, an endpoint MAY
    /// choose to treat a stream error as a connection error."
    /// </para>
    /// <para>
    /// The code is ENHANCE_YOUR_CALM rather than PROTOCOL_ERROR because section 7 defines it for
    /// exactly this condition — "The endpoint detected that its peer is exhibiting a behavior
    /// that might be generating excessive load" — and nothing about the peer's frames is
    /// malformed. 1024 is well past what a real origin promises before the first of them
    /// retires; only a peer promising faster than it can be told no reaches it. It is a constant
    /// rather than an option because it bounds this client's own memory, not its wire image: no
    /// byte of the request or of the RST_STREAM answers changes with it.
    /// </para>
    /// </remarks>
    private const int MaximumRejectedPushStreams = 1024;

    private readonly SharpTlsTransport _transport;
    private readonly Http2WriteBatch _writeBatch;
    private readonly TlsSessionConfiguration _configuration;
    private readonly int _localMaximumFrameSize;
    private readonly int _localInitialWindowSize;
    private readonly int _streamIdStep;
    private readonly uint _headerListDecodeBound;
    private readonly TlsHttp2SettingsAckPlacement _settingsAckPlacement;
    private readonly TlsHttp2FlowControlConfiguration _flowControl;
    private readonly TlsHttp2ShutdownConfiguration _shutdown;
    private readonly int _declaredConnectionReceiveWindow;
    private readonly HpackEncoder _encoder;
    private readonly HpackDecoder _decoder;
    private readonly ConcurrentDictionary<int, Http2StreamState> _streams = new();
    private readonly ConcurrentDictionary<int, byte> _rejectedPushStreams = new();
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly SemaphoreSlim _windowSignal = new(0, int.MaxValue);
    private readonly SemaphoreSlim _streamSlotSignal = new(0, int.MaxValue);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _flowSync = new();
    private Task? _readerTask;
    private int _nextStreamId;
    private int _peerMaximumFrameSize = 16 * 1024;
    private int _peerInitialWindowSize = 65_535;
    private int _peerMaximumConcurrentStreams = int.MaxValue;
    private int _highestPromisedStreamId;
    private int _connectionSendWindow = 65_535;
    private int _connectionReceiveWindow;
    private int _pendingConnectionCredit;
    private int _activeStreams;
    private int _pendingSettingsAck;
    private int _hasCompletedRequest;
    private int _isReusable = 1;
    private int _disposed;

    private Http2Connection(
        SharpTlsTransport transport,
        TlsSessionConfiguration configuration)
    {
        _transport = transport;
        _writeBatch = new Http2WriteBatch(transport.Stream);
        _configuration = configuration;

        // A client is bound by what it advertises, so every local receive bound comes
        // from the declared preface script rather than from a separate property.
        var http2 = configuration.Http2;
        _localMaximumFrameSize = http2.LocalMaxFrameSize;
        _localInitialWindowSize = http2.LocalInitialWindowSize;
        _encoder = new HpackEncoder(http2.Hpack);
        _decoder = new HpackDecoder(http2.LocalHeaderTableSize);
        _connectionReceiveWindow = http2.ConnectionReceiveWindow;
        _declaredConnectionReceiveWindow = http2.ConnectionReceiveWindow;
        _flowControl = http2.FlowControl;
        _shutdown = http2.Shutdown;
        _headerListDecodeBound = http2.LocalMaxHeaderListSize is { } declared
            ? Math.Min(declared, (uint)configuration.MaximumResponseHeaderBytes)
            : (uint)configuration.MaximumResponseHeaderBytes;
        _streamIdStep = http2.StreamIdStep;
        _settingsAckPlacement = http2.SettingsAckPlacement;
        _nextStreamId = http2.InitialStreamId - http2.StreamIdStep;
        LastUsed = DateTimeOffset.UtcNow;
    }

    public TlsConnectionInfo TlsInfo => _transport.TlsInfo;

    public DateTimeOffset LastUsed { get; private set; }

    public bool HasCompletedRequest => Volatile.Read(ref _hasCompletedRequest) != 0;

    public bool IsReusable => Volatile.Read(ref _isReusable) != 0;

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    public bool HasActiveRequests => !_streams.IsEmpty;

    public int MaximumConcurrentRequests =>
        Math.Max(0, Volatile.Read(ref _peerMaximumConcurrentStreams));

    public static async ValueTask<Http2Connection> CreateAsync(
        SharpTlsTransport transport,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var connection = new Http2Connection(transport, configuration);
        try
        {
            await connection.SendClientPrefaceAsync(cancellationToken).ConfigureAwait(false);
            connection._readerTask = connection.ReadLoopAsync();
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask<ParsedHttpResponse> SendAsync(
        BufferedRequest request,
        StreamingResponseContext? streamingResponse,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        if (!IsReusable)
        {
            throw new StaleHttpConnectionException(
                "The HTTP/2 connection no longer accepts new streams.");
        }

        await AcquireStreamSlotAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!IsReusable)
            {
                throw new StaleHttpConnectionException(
                    "The HTTP/2 connection stopped accepting streams.");
            }
            var streamId = Interlocked.Add(ref _nextStreamId, _streamIdStep);
            if (streamId <= 0)
            {
                Volatile.Write(ref _isReusable, 0);
                throw new HttpRequestException("The HTTP/2 stream identifier space is exhausted.");
            }
            var state = new Http2StreamState(
                streamId,
                request.Method,
                Volatile.Read(ref _peerInitialWindowSize),
                _localInitialWindowSize,
                configuration.MaximumResponseBodyBytes,
                configuration.MaximumResponseHeaderBytes,
                configuration.MaximumResponseHeaderCount,
                streamingResponse,
                CreditConsumedReceiveWindowAsync,
                ReturnStrandedConnectionCreditAsync,
                SignalWindow,
                cancellationToken,
                _lifetime.Token);
            if (!_streams.TryAdd(streamId, state))
            {
                throw new InvalidOperationException("The HTTP/2 stream identifier was reused.");
            }

            try
            {
                try
                {
                    await SendRequestAsync(
                        state,
                        request,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Http2ResponseCompletedException)
                {
                    // A final response can legitimately stop a flow-controlled upload.
                    if (state.FinalResponse.Task.IsCompletedSuccessfully)
                    {
                        await TryResetStreamAsync(streamId, _shutdown.CancellationResetCode)
                            .ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    state.TryFail(exception);
                    if (state.HasStartedRequest)
                    {
                        await TryResetStreamAsync(streamId, _shutdown.LocalFailureResetCode)
                            .ConfigureAwait(false);
                    }
                    else if (exception is IOException)
                    {
                        Volatile.Write(ref _isReusable, 0);
                        SignalWindow();
                        SignalStreamSlot();
                    }
                    throw;
                }
                var response = await state.Completion.Task.WaitAsync(cancellationToken)
                    .ConfigureAwait(false);
                Interlocked.Exchange(ref _hasCompletedRequest, 1);
                LastUsed = DateTimeOffset.UtcNow;
                return response;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                state.TryFail(new OperationCanceledException(cancellationToken));
                await TryResetStreamAsync(streamId, _shutdown.CancellationResetCode)
                    .ConfigureAwait(false);
                throw;
            }
            finally
            {
                _streams.TryRemove(streamId, out _);
                state.Dispose();
                if (!IsReusable && _streams.IsEmpty)
                {
                    await DisposeAsync().ConfigureAwait(false);
                }
                else if (_streams.IsEmpty)
                {
                    await FlushDeferredSettingsAckOnIdleAsync().ConfigureAwait(false);
                }
            }
        }
        finally
        {
            ReleaseStreamSlot();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        // Before the lifetime token is cancelled and the transport goes away, because both
        // of those make the write impossible. RFC 9113 section 6.8: "Endpoints SHOULD always
        // send a GOAWAY frame before closing a connection so that the remote peer can know
        // whether a stream has been partially processed or not."
        if (_shutdown.SendGoAwayOnDispose)
        {
            await TrySendGoAwayAsync(
                _shutdown.GoAwayErrorCode,
                _shutdown.GoAwayDebugData).ConfigureAwait(false);
        }

        Volatile.Write(ref _isReusable, 0);
        _lifetime.Cancel();
        FailAll(new ObjectDisposedException(nameof(Http2Connection)));
        await _transport.DisposeAsync().ConfigureAwait(false);
        if (_readerTask is not null)
        {
            try
            {
                await _readerTask.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The read loop reports its failure to active streams.
            }
        }
        _lifetime.Dispose();
        _writeGate.Dispose();
        _windowSignal.Dispose();
        _streamSlotSignal.Dispose();
    }

    private async ValueTask SendClientPrefaceAsync(CancellationToken cancellationToken)
    {
        // Not a coalescing batch: CreateAsync starts the read loop only once this
        // returns, so no peer SETTINGS has been seen and no acknowledgement can be
        // pending. The preface is written exactly as declared, with nothing inserted.
        // It is still one batch, so the magic and the frames that declare no boundary
        // leave in a single write.
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _writeBatch.WriteAsync(ClientPreface, cancellationToken).ConfigureAwait(false);

            foreach (var frame in _configuration.Http2.Preface)
            {
                await WriteFrameLockedAsync(
                    (Http2FrameType)frame.Type,
                    frame.Flags,
                    frame.StreamId,
                    frame.Payload,
                    cancellationToken).ConfigureAwait(false);
                if (frame.FlushAfter)
                {
                    // Ends this batch and opens the next, so the boundary lands between
                    // frames rather than inside one.
                    await _writeBatch.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            await _writeBatch.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private async ValueTask SendRequestAsync(
        Http2StreamState state,
        BufferedRequest request,
        CancellationToken cancellationToken)
    {
        var headers = BuildRequestHeaders(request);
        // Where END_STREAM lands is the persona's decision, not the body-supplying code
        // path's. An empty body ends on HEADERS only when the persona says so; when it does
        // not, the zero-length DATA frame written after the body loop carries the flag.
        var data = _configuration.Http2.Data;
        var headerBlockEndsStream = data.EmptyBodyEndsOnHeaders &&
            (!request.HasPayload || request.ContentLength == 0 && !request.HasTrailers);
        var expectsContinue = request.HasContent && Http11RequestWriter.Has100Continue(request);
        // Both lists are checked before a byte is written, so a rejected script cannot leave a
        // half-open stream behind.
        ValidateRequestFrames(request.FramesBeforeHeaders, state.StreamId);
        ValidateRequestFrames(request.FramesAfterHeaders, state.StreamId);
        await EnterWriteBatchAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var block = _encoder.Encode(headers);
            if (block.Length > _configuration.MaximumRequestHeaderBytes)
            {
                Volatile.Write(ref _isReusable, 0);
                throw new HttpRequestException(
                    "The compressed HTTP/2 request headers exceed the configured limit.");
            }
            // The declared script surrounds the header block and never enters it: RFC 9113
            // section 4.3 requires a field block to be a contiguous sequence of frames "with no
            // interleaved frames of any other type or from any other stream", and sections 6.2
            // and 6.10 make a violation a connection error of type PROTOCOL_ERROR. Both lists
            // share the request's write batch, so declared batching still applies.
            await WriteRequestFramesLockedAsync(
                request.FramesBeforeHeaders,
                state.StreamId,
                cancellationToken).ConfigureAwait(false);
            await WriteHeaderBlockLockedAsync(
                state.StreamId,
                block,
                headerBlockEndsStream,
                cancellationToken,
                request.HeaderPriority ?? _configuration.Http2.HeaderPriority,
                request.HeadersPadding)
                .ConfigureAwait(false);
            state.MarkRequestStarted();
            // After the final CONTINUATION, not after the HEADERS frame: the loop above only
            // returns once the block carries END_HEADERS.
            await WriteRequestFramesLockedAsync(
                request.FramesAfterHeaders,
                state.StreamId,
                cancellationToken).ConfigureAwait(false);
            // The session-level value is a fallback. A request that declares a PRIORITY_UPDATE
            // of its own owns the placement, including ahead of the header block: RFC 9218
            // section 7 states "A client MAY send a PRIORITY_UPDATE frame before the stream
            // that it references is open", and section 7.1 names 'idle' among the states a
            // prioritized stream may be in. Emitting the session's as well would put two
            // frames on the wire for one stream, and section 7 defines each as "a complete
            // set of all priority parameters" rather than a delta, so the second silently
            // replaces the first.
            if (!DeclaresPriorityUpdate(request) &&
                (request.PriorityUpdate ?? _configuration.Http2.PriorityUpdate) is
                    { } priorityUpdate)
            {
                var value = Encoding.ASCII.GetBytes(priorityUpdate);
                var payload = new byte[value.Length + 4];
                BinaryPrimitives.WriteInt32BigEndian(payload, state.StreamId);
                value.CopyTo(payload, 4);
                await WriteFrameLockedAsync(
                    Http2FrameType.PriorityUpdate,
                    0,
                    0,
                    payload,
                    cancellationToken).ConfigureAwait(false);
            }
            // The header block ends its batch when the persona declares it, when it is the
            // last thing this request writes, or when the client is about to wait on the
            // peer: RFC 9110 section 10.1.1 has a client with Expect: 100-continue wait for
            // an interim response, and the peer cannot send one for octets it never got.
            if (_configuration.Http2.FlushAfterHeaderBlock ||
                headerBlockEndsStream ||
                expectsContinue)
            {
                await FlushWriteBatchLockedAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _writeGate.Release();
        }

        if (expectsContinue &&
            !await ShouldSendExpectedBodyAsync(
                state,
                _configuration.Expect100ContinueTimeout,
                cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        if (request.IsStreaming)
        {
            await SendStreamingRequestBodyAsync(state, request, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        // RFC 9113 section 8.1 has a trailing field block end the stream, so a request with
        // trailers never puts END_STREAM on DATA whatever the persona declares.
        var endStreamRidesLastData = !request.HasTrailers &&
            data.NonEmptyBody == TlsHttp2EndStreamPlacement.OnLastDataFrame;
        var offset = 0;
        while (offset < request.Body.Length)
        {
            var length = await ReserveSendWindowAsync(
                state,
                request.Body.Length - offset,
                request.DataPadding,
                cancellationToken).ConfigureAwait(false);
            await EnterWriteBatchAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var endStream = endStreamRidesLastData &&
                    offset + length == request.Body.Length;
                var flags = endStream ? Http2FrameFlags.EndStream : (byte)0;
                if (request.DataPadding is not null)
                {
                    flags |= Http2FrameFlags.Padded;
                }
                await WriteFrameLockedAsync(
                    Http2FrameType.Data,
                    flags,
                    state.StreamId,
                    PadDataPayload(request.Body.AsMemory(offset, length), request.DataPadding),
                    cancellationToken).ConfigureAwait(false);
                if (_configuration.Http2.FlushAfterEveryDataFrame || endStream)
                {
                    await FlushWriteBatchLockedAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                _writeGate.Release();
            }
            offset += length;
        }
        if (request.HasTrailers)
        {
            if (state.FinalResponse.Task.IsCompleted)
            {
                throw new Http2ResponseCompletedException();
            }
            await SendRequestTrailersAsync(state, request, cancellationToken)
                .ConfigureAwait(false);
        }
        else if (!headerBlockEndsStream &&
            !(endStreamRidesLastData && request.Body.Length > 0))
        {
            // Nothing written so far carried END_STREAM: either the persona keeps it off the
            // body's frames, or there were no body frames because the persona also kept it
            // off HEADERS. SendDataAsync leaves an empty frame unpadded, which RFC 9113
            // section 6.9.1 requires of a frame this path never reserves credit for.
            await SendDataAsync(
                state,
                ReadOnlyMemory<byte>.Empty,
                endStream: true,
                request.DataPadding,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask SendStreamingRequestBodyAsync(
        Http2StreamState state,
        BufferedRequest request,
        CancellationToken cancellationToken)
    {
        var data = _configuration.Http2.Data;
        if (request.ContentLength == 0 && !request.HasTrailers)
        {
            if (!data.EmptyBodyEndsOnHeaders)
            {
                // The header block left without END_STREAM, so something has to close the
                // stream and there is no body to close it with.
                await SendDataAsync(
                    state,
                    ReadOnlyMemory<byte>.Empty,
                    endStream: true,
                    request.DataPadding,
                    cancellationToken).ConfigureAwait(false);
            }
            return;
        }
        using var uploadCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            state.FinalResponseToken);
        var source = await request.OpenStreamingContentAsync(uploadCancellation.Token)
            .ConfigureAwait(false);
        var buffer = ArrayPool<byte>.Shared.Rent(request.StreamingBufferSize);
        long total = 0;
        // A streamed chunk can only be known to be the last one before it is written when the
        // caller declared a Content-Length, which is what the running total is compared
        // against below - an undeclared length never matches, so it falls back to the
        // separate empty frame. Reading one chunk ahead to find out instead would hold
        // written octets across a blocking read of the caller's producer, which is exactly
        // the deadlock 892f951 removed, so the persona's placement is not bought with a hang.
        var endStreamRidesLastData = !request.HasTrailers &&
            data.NonEmptyBody == TlsHttp2EndStreamPlacement.OnLastDataFrame;
        var endStreamSent = false;
        try
        {
            while (true)
            {
                var read = await source.ReadAsync(
                    buffer.AsMemory(0, request.StreamingBufferSize),
                    uploadCancellation.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                total = checked(total + read);
                if (total > _configuration.MaximumRequestBodyBytes ||
                    request.ContentLength is { } declaredLength && total > declaredLength)
                {
                    throw new HttpRequestException(
                        "The streaming request body exceeds its declared or configured limit.");
                }
                endStreamSent = endStreamRidesLastData && request.ContentLength == total;
                await SendDataAsync(
                    state,
                    buffer.AsMemory(0, read),
                    endStream: endStreamSent,
                    request.DataPadding,
                    uploadCancellation.Token).ConfigureAwait(false);

                // The next statement blocks on the caller's content stream, which is the
                // second place this path waits on something outside the connection. A
                // producer whose next chunk depends on the peer having received this one -
                // a duplex relay, a stream with an application-level acknowledgement -
                // cannot produce it while the octets sit in the batch, so the batch closes
                // here whatever the persona declared. This is the same argument RFC 9113
                // section 6.9.1 makes for flow-control credit: a peer reacts only to what
                // it has received. The coalescing inside SendDataAsync survives untouched -
                // a read larger than the peer's SETTINGS_MAX_FRAME_SIZE is split into
                // several DATA frames that still leave as one write.
                await FlushPendingWriteBatchAsync(uploadCancellation.Token)
                    .ConfigureAwait(false);
            }

            if (request.ContentLength is { } expectedLength && total != expectedLength)
            {
                throw new HttpRequestException(
                    $"The streaming request body produced {total} bytes instead of " +
                    $"the declared {expectedLength} bytes.");
            }
            if (request.HasTrailers)
            {
                await SendRequestTrailersAsync(state, request, uploadCancellation.Token)
                    .ConfigureAwait(false);
            }
            else if (!endStreamSent)
            {
                await SendDataAsync(
                    state,
                    ReadOnlyMemory<byte>.Empty,
                    endStream: true,
                    request.DataPadding,
                    uploadCancellation.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (state.FinalResponse.Task.IsCompleted)
        {
            throw new Http2ResponseCompletedException();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async ValueTask SendRequestTrailersAsync(
        Http2StreamState state,
        BufferedRequest request,
        CancellationToken cancellationToken)
    {
        var trailers = new List<HpackHeader>();
        long headerListSize = 0;
        foreach (var trailer in request.Trailers)
        {
            var name = trailer.Name.ToLowerInvariant();
            TlsRequestOptions.ValidateTrailerName(name);
            foreach (var value in trailer.Values)
            {
                Http11RequestWriter.ValidateHeaderValue(value);
                headerListSize = checked(
                    headerListSize + 32 + Encoding.UTF8.GetByteCount(name) +
                    Encoding.UTF8.GetByteCount(value));
                trailers.Add(new HpackHeader(name, value));
            }
        }
        if (headerListSize > _configuration.MaximumRequestHeaderBytes)
        {
            throw new HttpRequestException(
                "The HTTP/2 request trailers exceed the configured header limit.");
        }

        await EnterWriteBatchAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var block = _encoder.Encode(trailers);
            if (block.Length > _configuration.MaximumRequestHeaderBytes)
            {
                throw new HttpRequestException(
                    "The compressed HTTP/2 request trailers exceed the configured limit.");
            }
            await WriteHeaderBlockLockedAsync(
                state.StreamId,
                block,
                endStream: true,
                cancellationToken).ConfigureAwait(false);
            await FlushWriteBatchLockedAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private static async ValueTask<bool> ShouldSendExpectedBodyAsync(
        Http2StreamState state,
        TimeSpan expectTimeout,
        CancellationToken cancellationToken)
    {
        if (expectTimeout == TimeSpan.Zero)
        {
            return true;
        }
        var delay = Task.Delay(expectTimeout, cancellationToken);
        var completed = await Task.WhenAny(
            state.Continue.Task,
            state.FinalResponse.Task,
            state.Completion.Task,
            delay).ConfigureAwait(false);
        if (completed == state.Continue.Task)
        {
            return true;
        }
        if (completed == state.FinalResponse.Task)
        {
            return false;
        }
        if (completed == state.Completion.Task)
        {
            _ = await state.Completion.Task.ConfigureAwait(false);
            return false;
        }
        await delay.ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Frames one DATA payload around its declared pad, or hands the data straight back when
    /// no pad is declared. RFC 9113 section 6.1, Figure 3 fixes the order: Pad Length, then
    /// Data, then Padding. The pad octets are left as allocated because section 6.1 requires
    /// "Padding octets MUST be set to zero when sending", and a receiver "MAY treat non-zero
    /// padding as a connection error of type PROTOCOL_ERROR".
    /// </summary>
    private static ReadOnlyMemory<byte> PadDataPayload(ReadOnlyMemory<byte> data, int? padding)
    {
        if (padding is not { } padLength)
        {
            return data;
        }
        var framed = new byte[data.Length + padLength + 1];
        framed[0] = (byte)padLength;
        data.Span.CopyTo(framed.AsSpan(1));
        return framed;
    }

    private async ValueTask SendDataAsync(
        Http2StreamState state,
        ReadOnlyMemory<byte> data,
        bool endStream,
        int? padding,
        CancellationToken cancellationToken)
    {
        if (data.IsEmpty)
        {
            // The declared pad is deliberately not applied to an empty end-of-stream frame.
            // RFC 9113 section 6.9.1 exempts exactly this frame from flow control — "Frames
            // with zero length with the END_STREAM flag set (that is, an empty DATA frame) MAY
            // be sent if there is no available space in either flow-control window" — and
            // padding it would make it a frame that needs credit, which this path never
            // reserves. A pad here would strand a request whose window is exhausted.
            await EnterWriteBatchAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await WriteFrameLockedAsync(
                    Http2FrameType.Data,
                    endStream ? Http2FrameFlags.EndStream : (byte)0,
                    state.StreamId,
                    data,
                    cancellationToken).ConfigureAwait(false);
                // A frame carrying END_STREAM closes the batch whatever the persona
                // declares: nothing further is written on this stream to coalesce with, so
                // a withheld flush would strand the request in the buffer.
                if (_configuration.Http2.FlushAfterEveryDataFrame || endStream)
                {
                    await FlushWriteBatchLockedAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                _writeGate.Release();
            }
            return;
        }

        var offset = 0;
        while (offset < data.Length)
        {
            var length = await ReserveSendWindowAsync(
                state,
                data.Length - offset,
                padding,
                cancellationToken).ConfigureAwait(false);
            await EnterWriteBatchAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var isFinalFrame = endStream && offset + length == data.Length;
                var flags = isFinalFrame ? Http2FrameFlags.EndStream : (byte)0;
                if (padding is not null)
                {
                    flags |= Http2FrameFlags.Padded;
                }
                await WriteFrameLockedAsync(
                    Http2FrameType.Data,
                    flags,
                    state.StreamId,
                    PadDataPayload(data.Slice(offset, length), padding),
                    cancellationToken).ConfigureAwait(false);
                if (_configuration.Http2.FlushAfterEveryDataFrame || isFinalFrame)
                {
                    await FlushWriteBatchLockedAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                _writeGate.Release();
            }
            offset += length;
        }
    }

    private List<HpackHeader> BuildRequestHeaders(BufferedRequest request)
    {
        var regular = Http11RequestWriter.MergeHeaders(request);
        var pseudoHeaders = _configuration.Http2.PseudoHeaders;
        var authorityMode = request.AuthorityMode ?? pseudoHeaders.AuthorityMode;
        var host = regular.FirstOrDefault(header =>
            string.Equals(header.Name, "Host", StringComparison.OrdinalIgnoreCase));
        var authority = host?.Values.FirstOrDefault() ?? Http11RequestWriter.AuthorityFor(request);
        // A declared override reaches the wire verbatim, which is the only way to express the
        // asterisk form RFC 9113 section 8.3.1 requires of an OPTIONS request whose target URI
        // has no path component. No URI can produce that string.
        string path = request.PathOverride ??
            request.Url.GetComponents(UriComponents.PathAndQuery, UriFormat.UriEscaped);
        if (path.Length == 0)
        {
            path = "/";
        }

        var pseudoValues = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [":method"] = request.Method,
            [":authority"] = authority,
            [":scheme"] = request.Scheme ?? pseudoHeaders.Scheme,
            [":path"] = path,
        };
        if (request.Protocol is { } protocol)
        {
            pseudoValues[":protocol"] = protocol;
        }
        var output = new List<HpackHeader>();
        // The order declares which pseudo-headers are emitted as well as their sequence, so a
        // name it omits is never written. RFC 9113 section 8.3 requires only that they all
        // precede the regular fields, which writing this list first guarantees.
        foreach (var name in request.PseudoHeaderOrder ?? pseudoHeaders.Order)
        {
            // RFC 9113 section 8.3.1 requires a client generating requests directly to convey
            // authority in :authority; HostHeaderOnly reproduces a client that does not.
            if (name == ":authority" && authorityMode == TlsHttp2AuthorityMode.HostHeaderOnly)
            {
                continue;
            }
            // RFC 8441 section 4 makes :protocol optional — "MAY be included on request
            // HEADERS" — so declaring it in the order costs nothing until a request sets it.
            if (name == ":protocol" && request.Protocol is null)
            {
                continue;
            }
            output.Add(new HpackHeader(name, pseudoValues[name]));
        }
        // Which pseudo-headers are legal depends on the method, so the check is per request at
        // send time rather than one Snapshot() could make. SendRequestAsync calls this before it
        // enters the write batch, so a request rejected here has put no byte on the wire and
        // leaves no half-open stream behind.
        ValidatePseudoHeaders(request.Method, output, authorityMode, authority, host);

        foreach (var header in regular)
        {
            var name = header.Name.ToLowerInvariant();
            if (name is "connection" or "proxy-connection" or "keep-alive" or
                "upgrade" or "transfer-encoding" or "proxy-authorization")
            {
                continue;
            }
            // The host field survives only when the declared mode asks for it. Under Both it
            // carries the same value as :authority by construction — both are read from this
            // very field when the request supplies one — which is what RFC 9113 section 8.3.1
            // requires: "Clients MUST NOT generate a request with a Host header field that
            // differs from the ':authority' pseudo-header field."
            if (name == "host" && authorityMode == TlsHttp2AuthorityMode.AuthorityOnly)
            {
                continue;
            }
            if (name == "te" && header.Values.Any(value =>
                    !string.Equals(value.Trim(), "trailers", StringComparison.OrdinalIgnoreCase)))
            {
                throw new HttpRequestException(
                    "HTTP/2 permits TE only with the value 'trailers'.");
            }
            // Which fields are held out of the dynamic table is a persona-level decision
            // now, so it lives in TlsHpackOptions.PerHeader rather than being hardcoded
            // here. Its defaults carry the former authorization and cookie rule.
            var hpack = _configuration.Http2.Hpack;
            var multiValue = hpack.PerHeaderMultiValue.TryGetValue(name, out var perHeader)
                ? perHeader
                : hpack.MultiValue;
            // cookie is not a comma-separated list field: RFC 6265 section 5.4 joins its
            // crumbs with "; ", and a server given ", " reads one malformed crumb. Joining
            // cookie therefore uses the cookie separator, which makes join and crumble
            // exact inverses of each other.
            var joinSeparator = name == "cookie"
                ? hpack.CookieCrumbSeparator
                : hpack.MultiValueJoinSeparator;
            string[] values = multiValue == TlsHpackMultiValue.Join && header.Values.Length > 1
                ? [string.Join(joinSeparator, header.Values)]
                : header.Values;
            foreach (var value in values)
            {
                // RFC 9113 section 8.2.3 permits a cookie to arrive as several fields, so
                // a stack that indexes individual crumbs can be reproduced. HTTP/1.1 is
                // untouched — there the header is one line by definition.
                if (name == "cookie" && hpack.CrumbleCookies)
                {
                    foreach (var crumb in value.Split(
                        hpack.CookieCrumbSeparator,
                        StringSplitOptions.RemoveEmptyEntries))
                    {
                        output.Add(new HpackHeader(name, crumb));
                    }
                    continue;
                }
                output.Add(new HpackHeader(name, value));
            }
        }
        long headerListSize = 0;
        foreach (var header in output)
        {
            headerListSize = checked(
                headerListSize + 32 + Encoding.UTF8.GetByteCount(header.Name) +
                Encoding.UTF8.GetByteCount(header.Value));
        }
        if (headerListSize > _configuration.MaximumRequestHeaderBytes)
        {
            throw new HttpRequestException(
                "The HTTP/2 request header list exceeds the configured limit.");
        }
        return output;
    }

    /// <summary>
    /// Rejects a pseudo-header set the request's method does not allow, before a byte is
    /// written. The declared order decides which pseudo-headers are emitted, but only the
    /// method decides which of them are legal, so the same order is valid for a GET and
    /// malformed for a CONNECT. <c>pseudoHeaders</c> is the emitted pseudo-header list, which
    /// is all <c>output</c> holds at the call site — RFC 9113 section 8.3 puts every one of
    /// them before the first regular field.
    /// </summary>
    private static void ValidatePseudoHeaders(
        string method,
        List<HpackHeader> pseudoHeaders,
        TlsHttp2AuthorityMode authorityMode,
        string authority,
        HeaderEntry? host)
    {
        // RFC 9113 section 8.5 builds a CONNECT header section "as defined in Section 8.3.1
        // ('Request Pseudo-Header Fields'), with a few differences": ":method" is CONNECT, "The
        // ':scheme' and ':path' pseudo-header fields MUST be omitted", and ":authority" carries
        // "the host and port to connect to". RFC 8441 section 4 puts the two back for extended
        // CONNECT — "On requests that contain the :protocol pseudo-header field, the :scheme
        // and :path pseudo-header fields of the target URI […] MUST also be included" — and
        // :authority stays required there (RFC 8441 section 5: "required on every HTTP/2
        // transaction"). Every other method follows RFC 9113 section 8.3.1: "All HTTP/2
        // requests MUST include exactly one valid value for the ':method', ':scheme', and
        // ':path' pseudo-header fields, unless they are CONNECT requests", with :authority
        // permitted and in fact required of a client that has authority information to convey.
        var isConnect = string.Equals(method, "CONNECT", StringComparison.Ordinal);
        var isExtendedConnect = isConnect &&
            pseudoHeaders.Exists(header => header.Name == ":protocol");
        string[] required;
        string[] forbidden;
        string citation;
        if (isExtendedConnect)
        {
            required = [":method", ":authority", ":scheme", ":path", ":protocol"];
            forbidden = [];
            citation = "RFC 8441 section 4";
        }
        else if (isConnect)
        {
            required = [":method", ":authority"];
            forbidden = [":scheme", ":path"];
            citation = "RFC 9113 section 8.5";
        }
        else
        {
            // No forbidden set: section 8.3.1 names no pseudo-header a normal request may not
            // carry, and inventing one here would reject wire images this fork exists to
            // reproduce.
            required = [":method", ":scheme", ":path"];
            forbidden = [];
            citation = "RFC 9113 section 8.3.1";
        }

        foreach (var name in required)
        {
            if (!pseudoHeaders.Exists(header => header.Name == name))
            {
                throw new HttpRequestException(
                    "An HTTP/2 " + method + " request must carry the " + name +
                    " pseudo-header (" + citation + ").");
            }
        }
        foreach (var name in forbidden)
        {
            if (pseudoHeaders.Exists(header => header.Name == name))
            {
                throw new HttpRequestException(
                    "An HTTP/2 " + method + " request must not carry the " + name +
                    " pseudo-header (" + citation + ").");
            }
        }

        // Section 8.5's third restriction, which the comment above quotes: ":authority" carries
        // "the host and port to connect to (equivalent to the authority-form of the
        // request-target of CONNECT requests; see Section 3.2.3 of [HTTP/1.1])". RFC 9112
        // section 3.2.3 gives that form as "authority-form = uri-host ':' port", so a portless
        // authority is not equivalent to it and the request is malformed. The seeded authority
        // carries the port (Http11RequestWriter.MergeHeaders); a caller-pinned host field
        // reaches ":authority" verbatim, which is the shape that arrives here without one.
        // Extended CONNECT is exempt: RFC 8441 section 4 reads ":authority" under section 8.3.1
        // instead, where a default port is elided as usual.
        //
        // The port separator is the last colon after any IPv6 literal's closing bracket, so
        // "[::1]" is portless while "[::1]:443" is not. A separator alone is not enough:
        // RFC 9112 section 3.2.3's "authority-form = uri-host ':' port" takes its port
        // production from RFC 3986 section 3.2.3, which admits digits only, so "example.com:"
        // names no port and "example.com:abc" is outside the grammar. Both are as portless as
        // a bare host for section 8.5's purpose — "the host and port to connect to".
        if (isConnect && !isExtendedConnect && !HasAuthorityPort(authority))
        {
            throw new HttpRequestException(
                "An HTTP/2 " + method + " request must carry a port in its :authority " +
                "pseudo-header (RFC 9113 section 8.5, RFC 9112 section 3.2.3).");
        }

        // RFC 9113 section 8.3.1: "Clients MUST NOT generate a request with a Host header field
        // that differs from the ':authority' pseudo-header field", and a server given both
        // "SHOULD treat a request as malformed" when they identify different entities. A peer
        // that resolves the disagreement by trusting one field over the other is a
        // request-smuggling seam, which is why divergence is rejected rather than reconciled.
        //
        // Do not delete this as unreachable. It is all but unreachable through today's builder —
        // :authority is read from the first value of this very field when the request carries
        // one, and from the request URI otherwise — so it guards against a future divergence
        // rather than against a bug that exists now. A multi-valued host field is the one shape
        // that reaches it today.
        if (authorityMode == TlsHttp2AuthorityMode.Both &&
            host is not null &&
            pseudoHeaders.Exists(header => header.Name == ":authority"))
        {
            foreach (var value in host.Values)
            {
                if (!string.Equals(value, authority, StringComparison.Ordinal))
                {
                    throw new HttpRequestException(
                        "An HTTP/2 " + method + " request must not carry a host field that " +
                        "differs from its :authority pseudo-header (RFC 9113 section 8.3.1).");
                }
            }
        }
    }

    /// <summary>
    /// Whether <paramref name="authority"/> ends in the <c>':' port</c> a plain CONNECT's
    /// <c>:authority</c> owes RFC 9113 section 8.5.
    /// </summary>
    /// <remarks>
    /// The separator is the last colon after any IPv6 literal's closing bracket. RFC 9112
    /// section 3.2.3 gives the form as "authority-form = uri-host ':' port", whose port
    /// production (RFC 3986 section 3.2.3) is digits only — so an empty or non-numeric tail
    /// names no port at all.
    /// </remarks>
    private static bool HasAuthorityPort(string authority)
    {
        var separator = authority.LastIndexOf(':');
        if (separator <= authority.LastIndexOf(']'))
        {
            return false;
        }
        var port = authority.AsSpan(separator + 1);
        if (port.IsEmpty)
        {
            return false;
        }
        foreach (var character in port)
        {
            if (!char.IsAsciiDigit(character))
            {
                return false;
            }
        }
        return true;
    }

    private async Task ReadLoopAsync()
    {
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                var frame = await ReadFrameAsync(_lifetime.Token).ConfigureAwait(false);
                await HandleFrameAsync(frame, _lifetime.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            Volatile.Write(ref _isReusable, 0);
            if (exception is TlsHttpProtocolException protocolException)
            {
                // RFC 9113 section 5.4.1 leaves the code to the condition that was
                // detected, so the GOAWAY carries the one the throw site declared rather
                // than a blanket PROTOCOL_ERROR.
                await TrySendGoAwayAsync(protocolException.Http2ErrorCode).ConfigureAwait(false);
            }
            FailAll(
                exception is TlsHttpProtocolException
                    ? exception
                    : new IOException("The HTTP/2 connection failed.", exception),
                preserveEndedStreams: true);
            SignalStreamSlot();
        }
    }

    private async ValueTask<Http2Frame> ReadFrameAsync(CancellationToken cancellationToken)
    {
        var header = new byte[9];
        await ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        var parsed = Http2FrameParser.ParseHeader(header, _localMaximumFrameSize);
        var payload = new byte[parsed.Length];
        await ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        return new Http2Frame(parsed.Type, parsed.Flags, parsed.StreamId, payload);
    }

    private async ValueTask HandleFrameAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        try
        {
            await DispatchFrameAsync(frame, cancellationToken).ConfigureAwait(false);
        }
        catch (TlsHttpProtocolException exception)
            when (exception.IsStreamScoped && frame.StreamId != 0)
        {
            await FailStreamAsync(frame, exception, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Terminates one stream after a stream error, leaving the connection and every other
    /// stream running.
    /// </summary>
    /// <remarks>
    /// RFC 9113 section 5.4.2: "A stream error is an error related to a specific stream that
    /// does not affect processing of other streams. An endpoint that detects a stream error
    /// sends a RST_STREAM frame (Section 6.4) that contains the stream identifier of the
    /// stream where the error occurred." The write follows the read loop's existing shape —
    /// SETTINGS and PING acknowledgements already take <c>_writeGate</c> from here.
    /// </remarks>
    private async ValueTask FailStreamAsync(
        Http2Frame frame,
        TlsHttpProtocolException exception,
        CancellationToken cancellationToken)
    {
        if (_streams.TryGetValue(frame.StreamId, out var state))
        {
            state.TryFail(exception);
        }
        if (frame.Type == Http2FrameType.Data)
        {
            // The frame is discarded, but its octets were already charged to the connection
            // window on arrival. RFC 9113 section 6.9.1 keeps the two ends' views of that
            // window in step only if every accounted octet is credited back, so a discarded
            // frame is credited exactly like the one on a stream that is already gone.
            await SendWindowUpdateAsync(0, frame.Payload.Length, cancellationToken)
                .ConfigureAwait(false);
            lock (_flowSync)
            {
                _connectionReceiveWindow += frame.Payload.Length;
            }
        }
        if (IsIdleStream(frame.StreamId))
        {
            // RFC 9113 section 6.4: "RST_STREAM frames MUST NOT be sent for a stream in the
            // 'idle' state." The stream error still costs only this stream, it simply has no
            // frame to announce it with.
            return;
        }
        await TryResetStreamAsync(frame.StreamId, exception.Http2ErrorCode).ConfigureAwait(false);
    }

    private async ValueTask DispatchFrameAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        switch (frame.Type)
        {
            case Http2FrameType.Data:
                await HandleDataAsync(frame, cancellationToken).ConfigureAwait(false);
                break;
            case Http2FrameType.Headers:
                await HandleHeadersAsync(frame, cancellationToken).ConfigureAwait(false);
                break;
            case Http2FrameType.Priority:
                // RFC 9113 section 6.3 scopes the two rules differently. "If a PRIORITY frame
                // is received with a stream identifier of 0x00, the recipient MUST respond
                // with a connection error (Section 5.4.1) of type PROTOCOL_ERROR", but "A
                // PRIORITY frame with a length other than 5 octets MUST be treated as a
                // stream error (Section 5.4.2) of type FRAME_SIZE_ERROR" — one stray
                // deprecated frame must not cost the connection its other requests.
                if (frame.StreamId == 0)
                {
                    throw new TlsHttpProtocolException("A PRIORITY frame used stream zero.");
                }
                if (frame.Payload.Length != 5)
                {
                    throw new TlsHttpProtocolException("A PRIORITY frame has an invalid length.")
                    {
                        Http2ErrorCode = Http2ErrorCode.FrameSizeError,
                        IsStreamScoped = true,
                    };
                }
                break;
            case Http2FrameType.RstStream:
                HandleReset(frame);
                break;
            case Http2FrameType.Settings:
                await HandleSettingsAsync(frame, cancellationToken).ConfigureAwait(false);
                break;
            case Http2FrameType.PushPromise:
                await HandlePushPromiseAsync(frame, cancellationToken).ConfigureAwait(false);
                break;
            case Http2FrameType.Ping:
                await HandlePingAsync(frame, cancellationToken).ConfigureAwait(false);
                break;
            case Http2FrameType.GoAway:
                HandleGoAway(frame);
                break;
            case Http2FrameType.WindowUpdate:
                HandleWindowUpdate(frame);
                break;
            case Http2FrameType.Continuation:
                throw new TlsHttpProtocolException("An unexpected CONTINUATION frame was received.");
            default:
                // Unknown extension frames are ignored as required by RFC 9113.
                break;
        }
    }

    private async ValueTask HandleDataAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        if (frame.StreamId == 0)
        {
            throw new TlsHttpProtocolException("A DATA frame used stream zero.");
        }
        var payloadLength = frame.Payload.Length;
        Http2StreamState? state;
        lock (_flowSync)
        {
            _connectionReceiveWindow -= payloadLength;
            if (_connectionReceiveWindow < 0)
            {
                // RFC 9113 section 6.9.1: "A receiver MUST treat the receipt of a
                // flow-controlled frame in excess of the available window as a connection
                // error (Section 5.4.1) of type FLOW_CONTROL_ERROR."
                throw new TlsHttpProtocolException(
                    "The peer exceeded the HTTP/2 connection receive window.")
                {
                    Http2ErrorCode = Http2ErrorCode.FlowControlError,
                };
            }
            if (_streams.TryGetValue(frame.StreamId, out state))
            {
                state.ReceiveWindow -= payloadLength;
                if (state.ReceiveWindow < 0)
                {
                    // Section 6.9.1: "errors on the flow-control window of a stream MUST be
                    // treated as a stream error (Section 5.4.2) of type FLOW_CONTROL_ERROR."
                    throw new TlsHttpProtocolException(
                        "The peer exceeded an HTTP/2 stream receive window.")
                    {
                        Http2ErrorCode = Http2ErrorCode.FlowControlError,
                        IsStreamScoped = true,
                    };
                }
            }
        }
        if (state is null)
        {
            if (IsIdleStream(frame.StreamId))
            {
                throw new TlsHttpProtocolException("DATA was received for an idle HTTP/2 stream.");
            }
            await SendWindowUpdateAsync(0, payloadLength, cancellationToken)
                .ConfigureAwait(false);
            lock (_flowSync)
            {
                _connectionReceiveWindow += payloadLength;
            }
            if ((frame.Flags & Http2FrameFlags.EndStream) != 0)
            {
                _rejectedPushStreams.TryRemove(frame.StreamId, out _);
            }
            return;
        }
        var data = RemovePadding(frame);
        var endStream = (frame.Flags & Http2FrameFlags.EndStream) != 0;
        state.EnqueueBody(data, frame.Payload.Length, endStream);
        if (_flowControl.Trigger == TlsHttp2WindowUpdateTrigger.OnReceive)
        {
            // The whole payload is what flow control charges — RFC 9113 section 6.9.1
            // exempts only the 9-octet frame header, so the padding this frame carried is
            // credited with the rest of it (section 6.1).
            await RestoreReceiveWindowAsync(
                state,
                frame.Payload.Length,
                endStream,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask HandleHeadersAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        if (frame.StreamId == 0)
        {
            throw new TlsHttpProtocolException("A HEADERS frame used stream zero.");
        }
        var streamId = frame.StreamId;
        var endStream = (frame.Flags & Http2FrameFlags.EndStream) != 0;
        var fragment = ExtractHeaderFragment(frame);
        using var block = new MemoryStream();
        var frames = 0;
        AppendHeaderFragment(block, fragment, ref frames);
        while ((frame.Flags & Http2FrameFlags.EndHeaders) == 0)
        {
            frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
            if (frame.Type != Http2FrameType.Continuation ||
                frame.StreamId != streamId)
            {
                throw new TlsHttpProtocolException(
                    "A header block was interrupted before END_HEADERS.");
            }
            AppendHeaderFragment(block, frame.Payload, ref frames);
        }

        var headers = _decoder.Decode(
            block.GetBuffer().AsSpan(0, checked((int)block.Length)),
            _headerListDecodeBound);
        if (_streams.TryGetValue(streamId, out var state))
        {
            var trailers = state.ApplyHeaders(headers);
            if (trailers && !endStream)
            {
                // Section 8.1 requires END_STREAM on a trailer section, and section 8.1.1
                // makes a malformed response a stream error of type PROTOCOL_ERROR.
                throw new TlsHttpProtocolException("HTTP/2 trailers must carry END_STREAM.")
                {
                    IsStreamScoped = true,
                };
            }
            if (endStream)
            {
                state.EnqueueEnd();
            }
        }
        else if (IsIdleStream(streamId))
        {
            throw new TlsHttpProtocolException("HEADERS was received for an idle HTTP/2 stream.");
        }
        else if (endStream)
        {
            _rejectedPushStreams.TryRemove(streamId, out _);
        }
    }

    private async ValueTask HandlePushPromiseAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        if (!_configuration.Http2.LocalEnablePush)
        {
            throw new TlsHttpProtocolException(
                "The peer sent PUSH_PROMISE although server push was disabled.");
        }
        if (frame.StreamId == 0)
        {
            throw new TlsHttpProtocolException("A PUSH_PROMISE frame used stream zero.");
        }

        var associatedStreamId = frame.StreamId;
        var (promisedStreamId, fragment) = ExtractPushPromiseFragment(frame);
        if (promisedStreamId == 0 || (promisedStreamId & 1) != 0)
        {
            throw new TlsHttpProtocolException(
                "A PUSH_PROMISE used an invalid promised stream identifier.");
        }
        if (!_streams.ContainsKey(associatedStreamId))
        {
            throw new TlsHttpProtocolException(
                "A PUSH_PROMISE referenced an idle or closed associated stream.");
        }
        if (promisedStreamId <= _highestPromisedStreamId)
        {
            throw new TlsHttpProtocolException(
                "A PUSH_PROMISE reused or reordered a promised stream identifier.");
        }
        if (_rejectedPushStreams.Count >= MaximumRejectedPushStreams)
        {
            throw new TlsHttpProtocolException(
                "Too many rejected HTTP/2 push streams remain outstanding.")
            {
                Http2ErrorCode = Http2ErrorCode.EnhanceYourCalm,
            };
        }
        // Volatile: a GOAWAY written from DisposeAsync reads this from another thread.
        Volatile.Write(ref _highestPromisedStreamId, promisedStreamId);
        using var block = new MemoryStream();
        var frames = 0;
        AppendHeaderFragment(block, fragment, ref frames);
        while ((frame.Flags & Http2FrameFlags.EndHeaders) == 0)
        {
            frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
            if (frame.Type != Http2FrameType.Continuation ||
                frame.StreamId != associatedStreamId)
            {
                throw new TlsHttpProtocolException(
                    "A PUSH_PROMISE header block was interrupted before END_HEADERS.");
            }
            AppendHeaderFragment(block, frame.Payload, ref frames);
        }

        _ = _decoder.Decode(
            block.GetBuffer().AsSpan(0, checked((int)block.Length)),
            _headerListDecodeBound);
        _rejectedPushStreams.TryAdd(promisedStreamId, 0);
        await TryResetStreamAsync(promisedStreamId, _shutdown.PushRejectionResetCode)
            .ConfigureAwait(false);
    }

    private async ValueTask HandleSettingsAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        if (frame.StreamId != 0)
        {
            throw new TlsHttpProtocolException("A SETTINGS frame used a non-zero stream.");
        }
        if (frame.Payload.Length % 6 != 0)
        {
            // RFC 9113 section 6.5: "A SETTINGS frame with a length other than a multiple of
            // 6 octets MUST be treated as a connection error (Section 5.4.1) of type
            // FRAME_SIZE_ERROR."
            throw new TlsHttpProtocolException("A SETTINGS frame has an invalid length.")
            {
                Http2ErrorCode = Http2ErrorCode.FrameSizeError,
            };
        }
        if ((frame.Flags & Http2FrameFlags.Ack) != 0)
        {
            if (frame.Payload.Length != 0)
            {
                // Section 6.5: "Receipt of a SETTINGS frame with the ACK flag set and a
                // length field value other than 0 MUST be treated as a connection error
                // (Section 5.4.1) of type FRAME_SIZE_ERROR."
                throw new TlsHttpProtocolException("A SETTINGS ACK contained a payload.")
                {
                    Http2ErrorCode = Http2ErrorCode.FrameSizeError,
                };
            }
            return;
        }

        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Deferral bound: a further SETTINGS supersedes values the peer has not yet
            // seen acknowledged, so any deferred acknowledgement is written standalone
            // before the newer values are applied. Acknowledgements then stay in
            // one-to-one order with the SETTINGS frames that produced them, and at most
            // one is ever outstanding.
            if (Volatile.Read(ref _pendingSettingsAck) != 0)
            {
                await WriteDeferredSettingsAckLockedAsync(cancellationToken)
                    .ConfigureAwait(false);
                await _writeBatch.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            for (var offset = 0; offset < frame.Payload.Length; offset += 6)
            {
                var identifier = BinaryPrimitives.ReadUInt16BigEndian(
                    frame.Payload.AsSpan(offset, 2));
                var value = BinaryPrimitives.ReadUInt32BigEndian(
                    frame.Payload.AsSpan(offset + 2, 4));
                switch (identifier)
                {
                    case 0x1: // SETTINGS_HEADER_TABLE_SIZE
                        _encoder.SetMaximumDynamicTableSize(value);
                        break;
                    case 0x2: // SETTINGS_ENABLE_PUSH
                        // "A server cannot set the SETTINGS_ENABLE_PUSH setting to a value
                        // other than 0" (RFC 9113 section 8.4), so 0 is the one value a
                        // server may legally send and is how it announces it will never
                        // push. Anything else — including the initial value 1 and every
                        // value section 6.5.2 outlaws outright — is a connection error of
                        // type PROTOCOL_ERROR.
                        if (value != 0)
                        {
                            throw new TlsHttpProtocolException(
                                "A server sent an invalid SETTINGS_ENABLE_PUSH.");
                        }
                        break;
                    case 0x3: // SETTINGS_MAX_CONCURRENT_STREAMS
                        lock (_flowSync)
                        {
                            _peerMaximumConcurrentStreams =
                                value > int.MaxValue ? int.MaxValue : (int)value;
                        }
                        SignalStreamSlot();
                        break;
                    case 0x4: // SETTINGS_INITIAL_WINDOW_SIZE
                        if (value > int.MaxValue)
                        {
                            throw new TlsHttpProtocolException(
                                "SETTINGS_INITIAL_WINDOW_SIZE is invalid.");
                        }
                        ApplyInitialWindowSize((int)value);
                        break;
                    case 0x5: // SETTINGS_MAX_FRAME_SIZE
                        if (value is < 16 * 1024 or > 16_777_215)
                        {
                            throw new TlsHttpProtocolException("SETTINGS_MAX_FRAME_SIZE is invalid.");
                        }
                        Volatile.Write(ref _peerMaximumFrameSize, (int)value);
                        break;
                    case 0x8 when value > 1: // SETTINGS_ENABLE_CONNECT_PROTOCOL
                    case 0x9 when value > 1: // SETTINGS_NO_RFC7540_PRIORITIES
                        throw new TlsHttpProtocolException("A boolean SETTINGS value is invalid.");
                }
            }

            if (_settingsAckPlacement != TlsHttp2SettingsAckPlacement.Standalone)
            {
                // The acknowledgement's position is a declared value, so it is handed to
                // the write path rather than emitted here. Deferral is bounded by the
                // connection's own writes: the next write batch carries it, and
                // FlushDeferredSettingsAckOnIdleAsync emits it standalone once no stream
                // is left to produce one.
                Volatile.Write(ref _pendingSettingsAck, 1);
                return;
            }

            await WriteFrameLockedAsync(
                Http2FrameType.Settings,
                Http2FrameFlags.Ack,
                0,
                ReadOnlyMemory<byte>.Empty,
                cancellationToken).ConfigureAwait(false);
            await _writeBatch.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private async ValueTask HandlePingAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        ValidateFrame(frame, streamMustBeZero: true, length: 8);
        if ((frame.Flags & Http2FrameFlags.Ack) != 0)
        {
            return;
        }
        await EnterWriteBatchAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteFrameLockedAsync(
                Http2FrameType.Ping,
                Http2FrameFlags.Ack,
                0,
                frame.Payload,
                cancellationToken).ConfigureAwait(false);
            await FlushWriteBatchLockedAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private void HandleReset(Http2Frame frame)
    {
        ValidateFrame(frame, streamMustBeZero: false, length: 4);
        if (_streams.TryGetValue(frame.StreamId, out var state))
        {
            var error = (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(frame.Payload);
            state.TryFail(new HttpRequestException(
                $"The peer reset HTTP/2 stream {frame.StreamId} with {error}."));
        }
        else if (IsIdleStream(frame.StreamId))
        {
            throw new TlsHttpProtocolException("RST_STREAM was received for an idle stream.");
        }
        _rejectedPushStreams.TryRemove(frame.StreamId, out _);
        SignalWindow();
    }

    private void HandleGoAway(Http2Frame frame)
    {
        if (frame.StreamId != 0)
        {
            throw new TlsHttpProtocolException("A GOAWAY frame used a non-zero stream.");
        }
        if (frame.Payload.Length < 8)
        {
            // Too small for the mandatory Last-Stream-ID and Error Code, which RFC 9113
            // section 4.2 makes a FRAME_SIZE_ERROR.
            throw new TlsHttpProtocolException("A GOAWAY frame has an invalid length.")
            {
                Http2ErrorCode = Http2ErrorCode.FrameSizeError,
            };
        }
        Volatile.Write(ref _isReusable, 0);
        var lastStreamId = BinaryPrimitives.ReadInt32BigEndian(frame.Payload) & 0x7fff_ffff;
        var error = (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(frame.Payload.AsSpan(4));
        foreach (var pair in _streams)
        {
            if (pair.Value.HasReceivedEndStream)
            {
                // RFC 9113 section 6.8: "Activity on streams numbered lower than or equal to
                // the last stream identifier might still complete successfully." A stream
                // whose END_STREAM has already arrived is fully received, so failing it would
                // hand the caller a truncated body it had already earned. This mirrors the
                // read loop's own FailAll(preserveEndedStreams: true).
                continue;
            }
            if (pair.Key > lastStreamId || error != Http2ErrorCode.NoError)
            {
                pair.Value.TryFail(new HttpRequestException(
                    $"The peer closed the HTTP/2 connection with {error}."));
            }
        }
        SignalWindow();
        SignalStreamSlot();
    }

    private void HandleWindowUpdate(Http2Frame frame)
    {
        if (frame.Payload.Length != 4)
        {
            // RFC 9113 section 6.9: "A WINDOW_UPDATE frame with a length other than 4 octets
            // MUST be treated as a connection error (Section 5.4.1) of type
            // FRAME_SIZE_ERROR."
            throw new TlsHttpProtocolException("A WINDOW_UPDATE frame has an invalid length.")
            {
                Http2ErrorCode = Http2ErrorCode.FrameSizeError,
            };
        }
        if (frame.StreamId != 0 && IsIdleStream(frame.StreamId))
        {
            // The stream's state settles the scope before its increment is even read. RFC 9113
            // section 5.1, idle: "Receiving any frame other than HEADERS or PRIORITY on a
            // stream in this state MUST be treated as a connection error (Section 5.4.1) of
            // type PROTOCOL_ERROR." WINDOW_UPDATE is neither, so the frame is a connection
            // error whatever it carries, and section 6.9's "increment of 0 ... as a stream
            // error (Section 5.4.2)" never gets to demote it: that rule grades the increment,
            // not the state, and claims no exemption from section 5.1. Where section 6.9 does
            // mean to override the state rules it says so outright — a WINDOW_UPDATE on a
            // half-closed or closed stream is one a "receiver MUST NOT treat as an error (see
            // Section 5.1)" — and it grants idle no such sentence. Idle is not closed.
            throw new TlsHttpProtocolException(
                "WINDOW_UPDATE was received for an idle stream.");
        }
        var increment = BinaryPrimitives.ReadInt32BigEndian(frame.Payload) & 0x7fff_ffff;
        if (increment == 0)
        {
            // Section 6.9: "A receiver MUST treat the receipt of a WINDOW_UPDATE frame with a
            // flow-control window increment of 0 as a stream error (Section 5.4.2) of type
            // PROTOCOL_ERROR; errors on the connection flow-control window MUST be treated as
            // a connection error (Section 5.4.1)."
            throw new TlsHttpProtocolException("A WINDOW_UPDATE increment was zero.")
            {
                IsStreamScoped = frame.StreamId != 0,
            };
        }
        lock (_flowSync)
        {
            if (frame.StreamId == 0)
            {
                // Section 6.9.1: "A sender MUST NOT allow a flow-control window to exceed
                // 2^31-1 octets. ... for the connection, a GOAWAY frame with an error code of
                // FLOW_CONTROL_ERROR is sent." `checked` would raise an OverflowException,
                // which is not a protocol exception, so the read loop sent no GOAWAY at all.
                if ((long)_connectionSendWindow + increment > int.MaxValue)
                {
                    throw new TlsHttpProtocolException(
                        "A WINDOW_UPDATE overflowed the HTTP/2 connection flow-control window.")
                    {
                        Http2ErrorCode = Http2ErrorCode.FlowControlError,
                    };
                }
                _connectionSendWindow += increment;
            }
            else if (_streams.TryGetValue(frame.StreamId, out var state))
            {
                // Section 6.9.1: "For streams, the sender sends a RST_STREAM with an error
                // code of FLOW_CONTROL_ERROR." The throw leaves the lock before
                // HandleFrameAsync writes that frame, which it could not do while holding it.
                if ((long)state.SendWindow + increment > int.MaxValue)
                {
                    throw new TlsHttpProtocolException(
                        "A WINDOW_UPDATE overflowed an HTTP/2 stream flow-control window.")
                    {
                        Http2ErrorCode = Http2ErrorCode.FlowControlError,
                        IsStreamScoped = true,
                    };
                }
                state.SendWindow += increment;
            }

            // Anything left is a stream this connection has finished with. Section 6.9:
            // "WINDOW_UPDATE can be sent by a peer that has sent a frame with the END_STREAM
            // flag set. ... A receiver MUST NOT treat this as an error (see Section 5.1)." So
            // it is dropped, not raised. Idle streams were rejected above and cannot reach
            // here.
        }
        SignalWindow();
    }

    private void ApplyInitialWindowSize(int value)
    {
        lock (_flowSync)
        {
            var delta = value - _peerInitialWindowSize;
            foreach (var state in _streams.Values)
            {
                // RFC 9113 section 6.9.2: "An endpoint MUST treat a change to
                // SETTINGS_INITIAL_WINDOW_SIZE that causes any flow-control window to exceed
                // the maximum size as a connection error (Section 5.4.1) of type
                // FLOW_CONTROL_ERROR." A window driven negative is required, not an error, so
                // only the upper bound is tested.
                var updated = (long)state.SendWindow + delta;
                if (updated > int.MaxValue)
                {
                    throw new TlsHttpProtocolException(
                        "SETTINGS_INITIAL_WINDOW_SIZE overflowed a stream flow-control window.")
                    {
                        Http2ErrorCode = Http2ErrorCode.FlowControlError,
                    };
                }
                state.SendWindow = (int)updated;
            }
            Volatile.Write(ref _peerInitialWindowSize, value);
        }
        SignalWindow();
    }

    /// <summary>
    /// Reserves send-window credit for one DATA frame and returns how many octets of
    /// <paramref name="requested"/> may be carried in it.
    /// </summary>
    /// <remarks>
    /// The pad is charged, not just the data. RFC 9113 section 6.1: "The entire DATA frame
    /// payload is included in flow control, including the Pad Length and Padding fields." So a
    /// padded frame costs <c>data + 1 + padLength</c> against both the stream and the
    /// connection window, and the same total is what RFC 9113 section 4.2 measures against
    /// SETTINGS_MAX_FRAME_SIZE. Reserving only the data octets over-sends both windows, and
    /// the peer answers a window overrun with FLOW_CONTROL_ERROR (section 6.9.1).
    /// </remarks>
    private async ValueTask<int> ReserveSendWindowAsync(
        Http2StreamState state,
        int requested,
        int? padding,
        CancellationToken cancellationToken)
    {
        var padOverhead = padding is null ? 0 : padding.Value + 1;
        var declaredFrameSize = _configuration.Http2.Data.MaxDataFrameSize ?? int.MaxValue;
        // The pad is part of the payload the cap measures, so a cap that cannot hold the pad
        // and at least one octet of body can never produce a frame. Only a declared cap can
        // reach this: the peer's maximum is at least 16384 (RFC 9113 section 6.5.2) and a pad
        // is at most 256 octets including its length field. Left unchecked the loop below
        // would wait on a window signal that no credit can satisfy.
        if (padOverhead >= declaredFrameSize)
        {
            throw new HttpRequestException(
                $"A DATA pad of {padding} octets does not fit a declared MaxDataFrameSize " +
                $"of {declaredFrameSize}.");
        }
        while (true)
        {
            if (state.Completion.Task.IsCompleted)
            {
                throw new Http2ResponseCompletedException();
            }
            lock (_flowSync)
            {
                // The declared cap joins the peer's maximum inside the same minimum, so the
                // pad subtracted below comes out of whichever of the two binds. RFC 9113
                // section 4.2 measures the whole payload against SETTINGS_MAX_FRAME_SIZE and
                // section 6.1 puts the Pad Length octet and the padding inside it, so a
                // capped frame carries min(cap, peer) - 1 - padLength octets of body.
                var frameBudget = Math.Min(
                    Volatile.Read(ref _peerMaximumFrameSize),
                    declaredFrameSize);
                var length = Math.Min(
                    requested,
                    Math.Min(
                        frameBudget,
                        Math.Min(_connectionSendWindow, state.SendWindow)) - padOverhead);
                if (length > 0)
                {
                    _connectionSendWindow -= length + padOverhead;
                    state.SendWindow -= length + padOverhead;
                    return length;
                }
            }
            using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            try
            {
                // The batch may still hold DATA the peer has not seen, and RFC 9113
                // section 6.9.1 has a peer send WINDOW_UPDATE for octets it has received.
                // Waiting on credit while withholding the octets that earn it deadlocks,
                // so the batch closes before the wait however the persona declared it.
                await FlushPendingWriteBatchAsync(linkedCancellation.Token)
                    .ConfigureAwait(false);
                await _windowSignal.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                _lifetime.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new ObjectDisposedException(nameof(Http2Connection));
            }
            if (state.Completion.Task.IsCompleted)
            {
                throw new Http2ResponseCompletedException();
            }
        }
    }

    private async ValueTask AcquireStreamSlotAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            if (!IsReusable)
            {
                SignalStreamSlot();
                throw new StaleHttpConnectionException(
                    "The HTTP/2 connection stopped accepting streams.");
            }
            var acquired = false;
            var wakeAnotherWaiter = false;
            lock (_flowSync)
            {
                if (_activeStreams < _peerMaximumConcurrentStreams)
                {
                    _activeStreams++;
                    acquired = true;
                    wakeAnotherWaiter = _activeStreams < _peerMaximumConcurrentStreams;
                }
            }
            if (acquired)
            {
                if (wakeAnotherWaiter)
                {
                    SignalStreamSlot();
                }
                return;
            }
            using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            try
            {
                await _streamSlotSignal.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                _lifetime.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new ObjectDisposedException(nameof(Http2Connection));
            }
        }
    }

    private void ReleaseStreamSlot()
    {
        lock (_flowSync)
        {
            _activeStreams--;
        }
        SignalStreamSlot();
    }

    private async ValueTask SendWindowUpdateAsync(
        int streamId,
        int increment,
        CancellationToken cancellationToken)
    {
        if (increment == 0)
        {
            return;
        }
        var payload = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(payload, increment);
        await EnterWriteBatchAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteFrameLockedAsync(
                Http2FrameType.WindowUpdate,
                0,
                streamId,
                payload,
                cancellationToken).ConfigureAwait(false);
            await FlushWriteBatchLockedAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    /// <summary>
    /// Returns credit for octets the application has accepted. Inert when the declared
    /// trigger is <see cref="TlsHttp2WindowUpdateTrigger.OnReceive"/>, which credits from
    /// <see cref="HandleDataAsync"/> instead — crediting from both would return the octets
    /// twice and grow the peer's view of the window past what was ever consumed.
    /// </summary>
    private ValueTask CreditConsumedReceiveWindowAsync(
        Http2StreamState state,
        int increment,
        bool endStream,
        CancellationToken cancellationToken) =>
        _flowControl.Trigger == TlsHttp2WindowUpdateTrigger.OnConsume
            ? RestoreReceiveWindowAsync(state, increment, endStream, cancellationToken)
            : ValueTask.CompletedTask;

    /// <summary>
    /// Decides how much credit the declared policy returns for <paramref name="pending"/>
    /// uncredited octets, or <c>0</c> to keep accumulating.
    /// </summary>
    private int CreditFor(int pending, int threshold, int currentWindow, int declaredWindow)
    {
        // A threshold of 0 emits on every accounted octet, which is today's behaviour.
        // Above that the octets accumulate silently until the declared amount is
        // outstanding. TlsHttp2Options.Snapshot rejects a threshold larger than the window
        // it draws on, so this can never withhold credit the peer is waiting on: the
        // threshold is always reached before the window is exhausted.
        if (pending < threshold)
        {
            return 0;
        }
        var increment = _flowControl.Increment switch
        {
            // The deficit, which is never less than `pending` — everything uncredited is
            // part of it — so this mode cannot under-credit.
            TlsHttp2WindowUpdateIncrement.RefillToInitial => declaredWindow - currentWindow,
            TlsHttp2WindowUpdateIncrement.Fixed => _flowControl.FixedIncrement,
            _ => pending,
        };

        // RFC 9113 section 6.9.1: "A sender MUST NOT allow a flow-control window to exceed
        // 2^31-1 octets. If a sender receives a WINDOW_UPDATE that causes a flow-control
        // window to exceed this maximum, it MUST terminate either the stream or the
        // connection" with FLOW_CONTROL_ERROR. A declared Fixed increment can overshoot,
        // so it is clamped to the headroom rather than allowed to kill the connection.
        return Math.Clamp(increment, 0, int.MaxValue - currentWindow);
    }

    private async ValueTask RestoreReceiveWindowAsync(
        Http2StreamState state,
        int increment,
        bool endStream,
        CancellationToken cancellationToken)
    {
        if (increment == 0)
        {
            return;
        }

        int connectionIncrement;
        int streamIncrement;

        // The decision and the mutation share one lock. CreditFor sizes its clamp against the
        // window it reads, so releasing the lock before applying would let two streams' body
        // pumps both size a Fixed or RefillToInitial increment against the same headroom and
        // both send it — pushing the peer's window past the 2^31-1 ceiling RFC 9113 section
        // 6.9.1 makes a FLOW_CONTROL_ERROR. Crediting first also means a WINDOW_UPDATE that
        // fails to reach the transport leaves the local window larger than the peer's, never
        // smaller, so the error can only ever be to accept octets that were advertised.
        lock (_flowSync)
        {
            _pendingConnectionCredit += increment;
            connectionIncrement = CreditFor(
                _pendingConnectionCredit,
                _flowControl.ConnectionWindowUpdateThreshold,
                _connectionReceiveWindow,
                _declaredConnectionReceiveWindow);
            if (connectionIncrement != 0)
            {
                _pendingConnectionCredit = 0;
                _connectionReceiveWindow += connectionIncrement;
            }

            // By default the stream-level update is skipped for the frame that ends the
            // stream: no further DATA can arrive on it, so no peer is waiting on that
            // credit. Sending it anyway is explicitly not an error — RFC 9113 section 6.9
            // has a receiver "MUST NOT treat this as an error" for a WINDOW_UPDATE on a
            // half-closed or closed stream — so the choice is declared, not fixed.
            if (endStream && _flowControl.SuppressStreamUpdateOnEndStream)
            {
                streamIncrement = 0;
            }
            else
            {
                state.PendingReceiveCredit += increment;
                streamIncrement = CreditFor(
                    state.PendingReceiveCredit,
                    _flowControl.StreamWindowUpdateThreshold,
                    state.ReceiveWindow,
                    _localInitialWindowSize);
                if (streamIncrement != 0)
                {
                    state.PendingReceiveCredit = 0;
                    state.ReceiveWindow += streamIncrement;
                }
            }
        }

        if (connectionIncrement == 0 && streamIncrement == 0)
        {
            return;
        }

        // RFC 9113 section 6.9 constrains neither the order of the two levels — the
        // connection window is addressed by stream 0 and each is accounted independently —
        // nor whether they share a transport write, so both are declared.
        (int StreamId, int Increment) connection = (0, connectionIncrement);
        (int StreamId, int Increment) stream = (state.StreamId, streamIncrement);
        var updates = _flowControl.Order == TlsHttp2WindowUpdateOrder.StreamFirst
            ? new[] { stream, connection }
            : new[] { connection, stream };

        try
        {
            if (_flowControl.CoalesceConnectionAndStream)
            {
                await SendWindowUpdateBatchAsync(updates, cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                foreach (var update in updates)
                {
                    await SendWindowUpdateAsync(
                        update.StreamId,
                        update.Increment,
                        cancellationToken).ConfigureAwait(false);
                }
            }
        }
        catch (Exception exception) when (
            state.HasReceivedEndStream && exception is not OperationCanceledException)
        {
            // The full response is already queued locally and the peer closed the connection.
            Volatile.Write(ref _isReusable, 0);
        }
    }

    /// <summary>
    /// Returns connection-level credit for octets that were accounted against the connection
    /// window on receipt but whose stream ended before the body pump could credit them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 9113 section 6.9.1 requires a receiver to account every flow-controlled frame it
    /// receives against the connection window unless it treats the frame as a connection
    /// error, precisely so the two ends' views of that window cannot drift apart. A stream
    /// that fails with DATA still queued — a peer RST_STREAM, a cancelled request, an
    /// abandoned streaming body — has already spent the connection window on those octets, so
    /// without this the window shrinks by the stranded amount for the rest of the connection's
    /// life and a long-lived connection degrades until it stalls.
    /// </para>
    /// <para>
    /// The declared threshold is deliberately bypassed: the stream is gone, so nothing further
    /// will ever accumulate against it, and octets held back here would never be emitted at
    /// all. Only the connection level is credited — a WINDOW_UPDATE on the dead stream would
    /// be legal (section 6.9) but has no window left to feed.
    /// </para>
    /// <para>
    /// Inert under <see cref="TlsHttp2WindowUpdateTrigger.OnReceive"/>: that trigger credits
    /// from <see cref="HandleDataAsync"/> when the frame arrives, so nothing a stream leaves
    /// undrained is uncredited and returning it again would advertise octets twice.
    /// </para>
    /// </remarks>
    private async ValueTask ReturnStrandedConnectionCreditAsync(int octets)
    {
        if (octets <= 0 ||
            _flowControl.Trigger == TlsHttp2WindowUpdateTrigger.OnReceive ||
            IsDisposed ||
            _lifetime.IsCancellationRequested)
        {
            return;
        }
        try
        {
            await SendWindowUpdateAsync(0, octets, _lifetime.Token).ConfigureAwait(false);
            lock (_flowSync)
            {
                _connectionReceiveWindow += octets;
            }
        }
        catch (Exception)
        {
            // This credit only matters to a connection that will carry further streams, and
            // one that cannot take the frame will carry none.
            Volatile.Write(ref _isReusable, 0);
        }
    }

    /// <summary>
    /// Writes both levels' WINDOW_UPDATE frames into one write batch, so the pair reaches
    /// the peer in a single transport write rather than one record each.
    /// </summary>
    private async ValueTask SendWindowUpdateBatchAsync(
        (int StreamId, int Increment)[] updates,
        CancellationToken cancellationToken)
    {
        await EnterWriteBatchAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            foreach (var update in updates)
            {
                if (update.Increment == 0)
                {
                    continue;
                }
                var payload = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(payload, update.Increment);
                await WriteFrameLockedAsync(
                    Http2FrameType.WindowUpdate,
                    0,
                    update.StreamId,
                    payload,
                    cancellationToken).ConfigureAwait(false);
            }

            // Closed unconditionally, and before returning: RFC 9113 section 6.9.1 has the
            // peer grant credit only for octets it has received, so credit left sitting in
            // the batch is credit the peer is still waiting on.
            await FlushWriteBatchLockedAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private async ValueTask TryResetStreamAsync(int streamId, Http2ErrorCode errorCode)
    {
        if (IsDisposed || !IsReusable)
        {
            return;
        }
        var payload = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(payload, (uint)errorCode);
        try
        {
            await EnterWriteBatchAsync(_lifetime.Token).ConfigureAwait(false);
            try
            {
                await WriteFrameLockedAsync(
                    Http2FrameType.RstStream,
                    0,
                    streamId,
                    payload,
                    _lifetime.Token).ConfigureAwait(false);
                await FlushWriteBatchLockedAsync(_lifetime.Token).ConfigureAwait(false);
            }
            finally
            {
                _writeGate.Release();
            }
        }
        catch (Exception) when (_lifetime.IsCancellationRequested)
        {
        }
    }

    private async ValueTask TrySendGoAwayAsync(
        Http2ErrorCode errorCode,
        byte[]? debugData = null)
    {
        // Deliberately not gated on IsDisposed: DisposeAsync claims that flag first and
        // then calls this, and the cancellation of _lifetime it performs immediately
        // afterwards is what actually closes the window on writing.
        if (_lifetime.IsCancellationRequested)
        {
            return;
        }

        // Last-Stream-ID names the last *peer*-initiated stream, not this client's own.
        // RFC 9113 section 6.8: "the GOAWAY contains the stream identifier of the last
        // peer-initiated stream that was or might be processed on the sending endpoint in
        // this connection. For instance, if the server sends a GOAWAY frame, the identified
        // stream is the highest-numbered stream initiated by the client." Server-initiated
        // streams are even (section 5.1.1), so a client's GOAWAY names the highest promised
        // stream and is 0 whenever the server pushed nothing — which is the normal case.
        // Do not "fix" this back to _nextStreamId.
        var payload = new byte[8 + (debugData?.Length ?? 0)];
        BinaryPrimitives.WriteInt32BigEndian(
            payload,
            Volatile.Read(ref _highestPromisedStreamId));
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(4), (uint)errorCode);
        debugData?.CopyTo(payload.AsSpan(8));
        try
        {
            // Not a coalescing batch: this runs from the read loop's failure handler or
            // from disposal, announcing that the connection is over. A deferred
            // acknowledgement of settings the connection will never act on has nothing to
            // say here.
            await _writeGate.WaitAsync(_lifetime.Token).ConfigureAwait(false);
            try
            {
                await WriteFrameLockedAsync(
                    Http2FrameType.GoAway,
                    0,
                    0,
                    payload,
                    _lifetime.Token).ConfigureAwait(false);
                await _writeBatch.FlushAsync(_lifetime.Token).ConfigureAwait(false);
            }
            finally
            {
                _writeGate.Release();
            }
        }
        catch (Exception)
        {
            // The protocol error may have arrived with an already-failed transport.
        }
    }

    private async ValueTask WriteHeaderBlockLockedAsync(
        int streamId,
        byte[] block,
        bool endStream,
        CancellationToken cancellationToken,
        TlsHttp2PriorityConfiguration? headerPriority = null,
        int? padding = null)
    {
        // min(declared, peer), never max: RFC 9113 section 4.2 makes an oversized field-block
        // frame a connection error of type FRAME_SIZE_ERROR, so a declared size above the
        // peer's advertised maximum is clamped down rather than honoured. _peerMaximumFrameSize
        // is seeded with the section 6.5.2 default of 16384 and only rises once the peer's
        // SETTINGS is processed, so the pre-SETTINGS clamp is that fixed default rather than
        // whatever happened to arrive while the first request was being written.
        var maximumFrameSize = Math.Min(
            Volatile.Read(ref _peerMaximumFrameSize),
            _configuration.Http2.HeaderBlockFragmentSize ?? int.MaxValue);
        var offset = 0;
        var first = true;
        do
        {
            // Only the leading HEADERS frame can carry priority: CONTINUATION has no PRIORITY
            // flag (RFC 9113 section 6.10). Trailers pass null — a trailing field block is not
            // a request and prioritizing a stream that is about to close says nothing.
            var priority = first ? headerPriority : null;
            var priorityLength = priority is null ? 0 : 5;
            // Nor can a CONTINUATION frame be padded: RFC 9113 section 6.10, Figure 12 gives it
            // no PADDED flag and no Pad Length field. The pad is therefore paid once, on the
            // leading HEADERS frame, and every later fragment gets the peer's whole budget.
            var pad = first ? padding : null;
            // RFC 9113 section 4.2 limits the whole frame payload, so the Pad Length octet, the
            // priority payload and the padding all come out of the fragment's share. Overrunning
            // it here would be a connection error of type FRAME_SIZE_ERROR rather than a stream
            // error, because HEADERS carries a field block (section 4.2).
            var padOverhead = pad is null ? 0 : pad.Value + 1;
            // At least one octet of field block per frame. TlsHttp2Options floors a declared
            // fragment size at 6, which covers the priority payload, but the pad is a
            // per-request value the session cannot see and takes up to another 256 octets, so
            // the budget can still go negative. Carrying one octet anyway overruns the
            // client's own declared fragment size and nothing else: pad plus priority plus one
            // is at most 262, and RFC 9113 section 4.2 floors SETTINGS_MAX_FRAME_SIZE at
            // 16384, so the peer's real limit stays intact. It also keeps the loop advancing.
            var length = Math.Min(
                Math.Max(maximumFrameSize - priorityLength - padOverhead, 1),
                block.Length - offset);
            var last = offset + length == block.Length;
            var flags = last ? Http2FrameFlags.EndHeaders : (byte)0;
            if (first && endStream)
            {
                flags |= Http2FrameFlags.EndStream;
            }
            ReadOnlyMemory<byte> payload;
            if (priority is null && pad is null)
            {
                payload = block.AsMemory(offset, length);
            }
            else
            {
                // RFC 9113 section 6.2, Figure 4 fixes the order: Pad Length, then the priority
                // payload, then the field block fragment, then the padding.
                var framed = new byte[padOverhead + priorityLength + length];
                var cursor = 0;
                if (pad is not null)
                {
                    flags |= Http2FrameFlags.Padded;
                    framed[cursor++] = (byte)pad.Value;
                }
                if (priority is not null)
                {
                    flags |= Http2FrameFlags.Priority;
                    BuildPriorityPayload(priority, streamId).CopyTo(framed, cursor);
                    cursor += 5;
                }
                block.AsSpan(offset, length).CopyTo(framed.AsSpan(cursor));
                // The trailing pad octets are left as allocated: RFC 9113 section 6.2 requires
                // "Padding octets MUST be set to zero when sending".
                payload = framed;
            }
            await WriteFrameLockedAsync(
                first ? Http2FrameType.Headers : Http2FrameType.Continuation,
                flags,
                streamId,
                payload,
                cancellationToken).ConfigureAwait(false);
            first = false;
            offset += length;
        }
        while (offset < block.Length);
    }

    /// <summary>
    /// Writes one declared per-request frame list. A frozen frame carries 0 wherever it names
    /// the request's own stream, because the identifier is not allocated until now; this is
    /// where that placeholder is resolved. The destination differs by frame type: for PRIORITY
    /// it is the frame header's stream identifier, while for PRIORITY_UPDATE it is the
    /// Prioritized Stream ID field in the first four payload octets, since RFC 9218 section 7.1
    /// pins that frame's own header identifier to 0 and makes any other value a connection
    /// error of type PROTOCOL_ERROR.
    /// </summary>
    private async ValueTask WriteRequestFramesLockedAsync(
        TlsHttp2RequestFrameConfiguration[] frames,
        int streamId,
        CancellationToken cancellationToken)
    {
        foreach (var frame in frames)
        {
            var frameStreamId = frame.StreamId;
            ReadOnlyMemory<byte> payload = frame.Payload;
            if (frame.TargetsRequestStream)
            {
                if (frame.Type == (byte)Http2FrameType.PriorityUpdate)
                {
                    // A copy, not an in-place edit: the frozen configuration is shared by every
                    // send of this request, including a redirect or a retry onto a different
                    // stream identifier.
                    var resolved = frame.Payload.ToArray();
                    BinaryPrimitives.WriteInt32BigEndian(resolved, streamId);
                    payload = resolved;
                }
                else
                {
                    frameStreamId = streamId;
                }
            }
            await WriteFrameLockedAsync(
                (Http2FrameType)frame.Type,
                frame.Flags,
                frameStreamId,
                payload,
                cancellationToken).ConfigureAwait(false);
            if (frame.FlushAfter)
            {
                await FlushWriteBatchLockedAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Whether the request declares a PRIORITY_UPDATE for its own stream in either frame list,
    /// which makes the session-level <see cref="TlsHttp2Options.PriorityUpdate"/> a fallback
    /// rather than an addition. A <see cref="TlsHttp2RequestRawFrame"/> carrying type 0x10 is
    /// deliberately not counted: its stream identifier and Prioritized Stream ID are written
    /// verbatim, so it prioritizes whatever stream it names rather than this one.
    /// </summary>
    private static bool DeclaresPriorityUpdate(BufferedRequest request) =>
        Array.Exists(request.FramesBeforeHeaders, IsRequestStreamPriorityUpdate) ||
        Array.Exists(request.FramesAfterHeaders, IsRequestStreamPriorityUpdate);

    private static bool IsRequestStreamPriorityUpdate(
        TlsHttp2RequestFrameConfiguration frame) =>
        frame is { Type: (byte)Http2FrameType.PriorityUpdate, TargetsRequestStream: true };

    /// <summary>
    /// Rejects a declared PRIORITY frame that makes the request's stream depend on itself.
    /// RFC 7540 section 5.3.1: "A stream cannot depend on itself. An endpoint MUST treat this
    /// as a stream error (Section 5.4.2) of type PROTOCOL_ERROR." RFC 9113 dropped the
    /// dependency-tree text and so states no such rule, but it retains the wire fields
    /// (section 5.3.2) and peers implementing RFC 7540 still enforce it. The check belongs
    /// here rather than where the frame is declared, because a stream cannot be compared
    /// against an identifier that has not been allocated yet.
    /// </summary>
    private static void ValidateRequestFrames(
        TlsHttp2RequestFrameConfiguration[] frames,
        int streamId)
    {
        foreach (var frame in frames)
        {
            if (frame is { Type: (byte)Http2FrameType.Priority, TargetsRequestStream: true } &&
                (BinaryPrimitives.ReadInt32BigEndian(frame.Payload) & 0x7fff_ffff) == streamId)
            {
                throw new HttpRequestException("An HTTP/2 stream cannot depend on itself.");
            }
        }
    }

    /// <summary>
    /// Opens a write batch: acquires the write gate and, under
    /// <see cref="TlsHttp2SettingsAckPlacement.BeforeNextBatch"/>, emits a deferred
    /// SETTINGS acknowledgement ahead of everything the caller is about to write. Every
    /// batch is opened here and closed by <see cref="FlushWriteBatchLockedAsync"/>, so
    /// the acknowledgement can only ever land on a batch boundary — never between a
    /// HEADERS frame and its CONTINUATION frames, which RFC 9113 sections 6.2 and 6.10
    /// forbid.
    /// </summary>
    private async ValueTask EnterWriteBatchAsync(CancellationToken cancellationToken)
    {
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (_settingsAckPlacement != TlsHttp2SettingsAckPlacement.BeforeNextBatch ||
            Volatile.Read(ref _pendingSettingsAck) == 0)
        {
            return;
        }
        try
        {
            await WriteDeferredSettingsAckLockedAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // The caller never entered its try/finally, so the gate is ours to release.
            _writeGate.Release();
            throw;
        }
    }

    /// <summary>
    /// Closes a write batch: under <see cref="TlsHttp2SettingsAckPlacement.AfterNextBatch"/>
    /// a deferred SETTINGS acknowledgement joins the batch behind its last frame, and the
    /// whole batch then leaves as a single write followed by a single flush — which is
    /// what makes a declared boundary observable as a record boundary.
    /// </summary>
    private async ValueTask FlushWriteBatchLockedAsync(CancellationToken cancellationToken)
    {
        if (_settingsAckPlacement == TlsHttp2SettingsAckPlacement.AfterNextBatch &&
            Volatile.Read(ref _pendingSettingsAck) != 0)
        {
            await WriteDeferredSettingsAckLockedAsync(cancellationToken).ConfigureAwait(false);
        }
        await _writeBatch.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Closes whatever batch is open, from outside the write gate. Only for callers that
    /// are about to block on the peer: bytes the peer has not received cannot earn the
    /// response those callers are waiting for.
    /// </summary>
    private async ValueTask FlushPendingWriteBatchAsync(CancellationToken cancellationToken)
    {
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _writeBatch.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    /// <summary>
    /// Writes a deferred SETTINGS acknowledgement if one is outstanding. Every caller
    /// already holds <c>_writeGate</c>, which is also the only place
    /// <c>_pendingSettingsAck</c> is set, so the acknowledgement cannot be claimed twice
    /// and no caller ever waits on a lock it already owns.
    /// </summary>
    private ValueTask WriteDeferredSettingsAckLockedAsync(CancellationToken cancellationToken) =>
        Interlocked.Exchange(ref _pendingSettingsAck, 0) == 0
            ? ValueTask.CompletedTask
            : WriteFrameLockedAsync(
                Http2FrameType.Settings,
                Http2FrameFlags.Ack,
                0,
                ReadOnlyMemory<byte>.Empty,
                cancellationToken);

    /// <summary>
    /// Bounds acknowledgement deferral at the far end: once the last stream closes the
    /// connection has no queued work left to coalesce with, so a deferred acknowledgement
    /// is written standalone rather than waiting for a batch that may never come.
    /// </summary>
    private async ValueTask FlushDeferredSettingsAckOnIdleAsync()
    {
        if (Volatile.Read(ref _pendingSettingsAck) == 0 ||
            IsDisposed ||
            _lifetime.IsCancellationRequested)
        {
            return;
        }
        try
        {
            await _writeGate.WaitAsync(_lifetime.Token).ConfigureAwait(false);
            try
            {
                await WriteDeferredSettingsAckLockedAsync(_lifetime.Token).ConfigureAwait(false);
                await _writeBatch.FlushAsync(_lifetime.Token).ConfigureAwait(false);
            }
            finally
            {
                _writeGate.Release();
            }
        }
        catch (Exception)
        {
            // This runs on a request's completion path, where the request's own result
            // has already been decided. A transport that cannot take the acknowledgement
            // is a connection that is going away, and the read loop reports that.
            Volatile.Write(ref _isReusable, 0);
        }
    }

    private async ValueTask WriteFrameLockedAsync(
        Http2FrameType type,
        byte flags,
        int streamId,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        if (payload.Length > 16_777_215)
        {
            throw new ArgumentOutOfRangeException(nameof(payload));
        }
        var header = new byte[9];
        header[0] = (byte)(payload.Length >> 16);
        header[1] = (byte)(payload.Length >> 8);
        header[2] = (byte)payload.Length;
        header[3] = (byte)type;
        header[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(5), streamId & 0x7fff_ffff);
        await _writeBatch.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        if (payload.Length != 0)
        {
            await _writeBatch.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask ReadExactlyAsync(
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await _transport.Stream.ReadAsync(destination[offset..], cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The HTTP/2 connection closed unexpectedly.");
            }
            offset += read;
        }
    }

    private static ReadOnlyMemory<byte> RemovePadding(Http2Frame frame)
    {
        if ((frame.Flags & Http2FrameFlags.Padded) == 0)
        {
            return frame.Payload;
        }
        if (frame.Payload.Length == 0 || frame.Payload[0] >= frame.Payload.Length)
        {
            throw new TlsHttpProtocolException("An HTTP/2 padding length is invalid.");
        }
        return frame.Payload.AsMemory(1, frame.Payload.Length - frame.Payload[0] - 1);
    }

    private static ReadOnlyMemory<byte> ExtractHeaderFragment(Http2Frame frame)
    {
        var offset = 0;
        var padding = 0;
        if ((frame.Flags & Http2FrameFlags.Padded) != 0)
        {
            if (frame.Payload.Length == 0)
            {
                throw new TlsHttpProtocolException("A padded HEADERS frame is empty.");
            }
            padding = frame.Payload[offset++];
        }
        if ((frame.Flags & Http2FrameFlags.Priority) != 0)
        {
            offset += 5;
        }
        if (offset > frame.Payload.Length || padding > frame.Payload.Length - offset)
        {
            throw new TlsHttpProtocolException("A HEADERS frame has invalid padding or priority.");
        }
        return frame.Payload.AsMemory(offset, frame.Payload.Length - offset - padding);
    }

    /// <summary>
    /// Accumulates one field-block fragment, bounding both the octets and — through
    /// <paramref name="frames"/>, which the caller carries across the whole block — the
    /// number of frames it arrived in. See <see cref="MaximumHeaderBlockFrames"/> for why
    /// the octet cap alone cannot terminate the CONTINUATION loop.
    /// </summary>
    private void AppendHeaderFragment(
        MemoryStream block,
        ReadOnlyMemory<byte> fragment,
        ref int frames)
    {
        if (++frames > MaximumHeaderBlockFrames)
        {
            throw new TlsHttpProtocolException(
                "The HTTP/2 header block spanned too many frames.");
        }
        if (block.Length + fragment.Length > _configuration.MaximumResponseHeaderBytes)
        {
            throw new TlsHttpProtocolException(
                "The compressed HTTP/2 header block exceeded the configured limit.");
        }
        block.Write(fragment.Span);
    }

    private bool IsIdleStream(int streamId) => (streamId & 1) != 0
        ? streamId > Volatile.Read(ref _nextStreamId)
        : streamId > _highestPromisedStreamId;

    private static (int PromisedStreamId, ReadOnlyMemory<byte> Fragment)
        ExtractPushPromiseFragment(Http2Frame frame)
    {
        var offset = 0;
        var padding = 0;
        if ((frame.Flags & Http2FrameFlags.Padded) != 0)
        {
            if (frame.Payload.Length == 0)
            {
                throw new TlsHttpProtocolException("A padded PUSH_PROMISE frame is empty.");
            }
            padding = frame.Payload[offset++];
        }
        if (frame.Payload.Length - offset < 4)
        {
            throw new TlsHttpProtocolException("A PUSH_PROMISE frame is truncated.");
        }
        var promisedStreamId = BinaryPrimitives.ReadInt32BigEndian(
            frame.Payload.AsSpan(offset, 4)) & 0x7fff_ffff;
        offset += 4;
        if (padding > frame.Payload.Length - offset)
        {
            throw new TlsHttpProtocolException("A PUSH_PROMISE padding length is invalid.");
        }
        return (
            promisedStreamId,
            frame.Payload.AsMemory(offset, frame.Payload.Length - offset - padding));
    }

    /// <summary>
    /// Enforces the stream-identifier and length rules RFC 9113 section 6 gives PING and
    /// RST_STREAM, both of which are connection errors — only the code differs.
    /// </summary>
    /// <remarks>
    /// Section 4.2: "An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame
    /// exceeds the size defined in SETTINGS_MAX_FRAME_SIZE, exceeds any limit defined for the
    /// frame type, or is too small to contain mandatory frame data." A misplaced stream
    /// identifier is a PROTOCOL_ERROR instead (sections 6.4, 6.7), so the two are separate.
    /// PRIORITY does not come through here: section 6.3 makes its length rule a stream error.
    /// </remarks>
    private static void ValidateFrame(Http2Frame frame, bool streamMustBeZero, int length)
    {
        if (streamMustBeZero ? frame.StreamId != 0 : frame.StreamId == 0)
        {
            throw new TlsHttpProtocolException(
                $"A {frame.Type} frame used an invalid stream identifier.");
        }
        if (frame.Payload.Length != length)
        {
            throw new TlsHttpProtocolException($"A {frame.Type} frame has an invalid length.")
            {
                Http2ErrorCode = Http2ErrorCode.FrameSizeError,
            };
        }
    }

    private static byte[] BuildPriorityPayload(
        TlsHttp2PriorityConfiguration priority,
        int streamId)
    {
        if (priority.StreamDependency == streamId)
        {
            throw new HttpRequestException("An HTTP/2 stream cannot depend on itself.");
        }
        return priority.BuildPayload();
    }

    private void FailAll(Exception exception, bool preserveEndedStreams = false)
    {
        foreach (var stream in _streams.Values)
        {
            if (!preserveEndedStreams || !stream.HasReceivedEndStream)
            {
                stream.TryFail(exception);
            }
        }
        SignalWindow();
    }

    private void SignalWindow()
    {
        try
        {
            _windowSignal.Release();
        }
        catch (SemaphoreFullException)
        {
        }
        catch (ObjectDisposedException)
        {
            // A final stream may race the connection's deterministic shutdown.
        }
    }

    private void SignalStreamSlot()
    {
        try
        {
            _streamSlotSignal.Release();
        }
        catch (SemaphoreFullException)
        {
        }
        catch (ObjectDisposedException)
        {
            // A final stream may race the connection's deterministic shutdown.
        }
    }
}

internal sealed class Http2StreamState : IDisposable
{
    private readonly MemoryStream _body = new();
    private readonly int _maximumBodyBytes;
    private readonly int _maximumHeaderBytes;
    private readonly int _maximumHeaderCount;
    private readonly StreamingResponseContext? _streamingResponse;
    private readonly Func<Http2StreamState, int, bool, CancellationToken, ValueTask>
        _restoreReceiveWindow;
    private readonly Func<int, ValueTask> _returnStrandedConnectionCredit;
    private readonly Action _signalStateChange;
    private readonly CancellationTokenSource _responseCancellation;
    private readonly CancellationTokenSource _finalResponseCancellation = new();
    private readonly Channel<QueuedHttp2Data> _incoming = Channel.CreateUnbounded<QueuedHttp2Data>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true,
            AllowSynchronousContinuations = false,
        });
    private readonly Task _bodyPump;
    private TlsHeaders? _headers;
    private TlsHeaders? _trailers;
    private HttpStatusCode? _statusCode;
    private int _headerBytes;
    private long _bodyLength;
    private long _receivedBodyLength;
    private int _completed;
    private int _endReceived;
    private int _stateChangeSignaled;
    private int _requestStarted;

    public Http2StreamState(
        int streamId,
        string requestMethod,
        int sendWindow,
        int receiveWindow,
        int maximumBodyBytes,
        int maximumHeaderBytes,
        int maximumHeaderCount,
        StreamingResponseContext? streamingResponse,
        Func<Http2StreamState, int, bool, CancellationToken, ValueTask> restoreReceiveWindow,
        Func<int, ValueTask> returnStrandedConnectionCredit,
        Action signalStateChange,
        CancellationToken requestCancellation,
        CancellationToken connectionCancellation)
    {
        StreamId = streamId;
        RequestMethod = requestMethod;
        SendWindow = sendWindow;
        ReceiveWindow = receiveWindow;
        _maximumBodyBytes = maximumBodyBytes;
        _maximumHeaderBytes = maximumHeaderBytes;
        _maximumHeaderCount = maximumHeaderCount;
        _streamingResponse = streamingResponse;
        _restoreReceiveWindow = restoreReceiveWindow;
        _returnStrandedConnectionCredit = returnStrandedConnectionCredit;
        _signalStateChange = signalStateChange;
        _responseCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            requestCancellation,
            connectionCancellation);
        _bodyPump = PumpBodyAsync();
    }

    public int StreamId { get; }

    public string RequestMethod { get; }

    public int SendWindow { get; set; }

    public int ReceiveWindow { get; set; }

    /// <summary>
    /// Octets accounted on this stream that no WINDOW_UPDATE has credited yet. Guarded by
    /// the connection's flow lock, like <see cref="ReceiveWindow"/>.
    /// </summary>
    public int PendingReceiveCredit { get; set; }

    public bool HasReceivedEndStream => Volatile.Read(ref _endReceived) != 0;

    public bool HasStartedRequest => Volatile.Read(ref _requestStarted) != 0;

    public CancellationToken FinalResponseToken => _finalResponseCancellation.Token;

    public TaskCompletionSource<ParsedHttpResponse> Completion { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public TaskCompletionSource Continue { get; } = new(
        TaskCreationOptions.RunContinuationsAsynchronously);

    public TaskCompletionSource FinalResponse { get; } = new(
        TaskCreationOptions.RunContinuationsAsynchronously);

    public void MarkRequestStarted() => Interlocked.Exchange(ref _requestStarted, 1);

    /// <summary>
    /// A malformed response, which RFC 9113 section 8.1.1 makes a stream error of type
    /// PROTOCOL_ERROR.
    /// </summary>
    /// <remarks>
    /// Section 8.1.1: "A malformed request or response is one that is an otherwise valid
    /// sequence of HTTP/2 frames but is invalid due to the presence of extraneous frames,
    /// prohibited fields or pseudo-header fields, the absence of mandatory pseudo-header
    /// fields, the inclusion of uppercase field names, or invalid field names and/or
    /// values. ... Malformed requests or responses that are detected MUST be treated as a
    /// stream error (Section 5.4.2) of type PROTOCOL_ERROR." Nothing here meets section
    /// 5.4.1's connection-error test: the frame layer is intact, the HPACK decoder has
    /// already consumed the block, and flow control is already accounted — so resetting the
    /// one stream is both sufficient and all the RFC allows.
    /// </remarks>
    private static TlsHttpProtocolException Malformed(string message) =>
        new(message) { IsStreamScoped = true };

    /// <summary>
    /// Applies the minimal field validation RFC 9113 section 8.2.1 makes mandatory on
    /// receipt.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Section 8.2.1: "Failure to validate fields can be exploited for request smuggling
    /// attacks. In particular, unvalidated fields might enable attacks when messages are
    /// forwarded using HTTP/1.1, where characters such as carriage return (CR), line feed
    /// (LF), and COLON are used as delimiters. Implementations MUST perform the following
    /// minimal validation of field names and values: A field name MUST NOT contain
    /// characters in the ranges 0x00-0x20, 0x41-0x5a, or 0x7f-0xff (all ranges inclusive).
    /// ... With the exception of pseudo-header fields (Section 8.3), which have a name that
    /// starts with a single colon, field names MUST NOT include a colon (ASCII COLON, 0x3a).
    /// A field value MUST NOT contain the zero value (ASCII NUL, 0x00), line feed (ASCII LF,
    /// 0x0a), or carriage return (ASCII CR, 0x0d) at any position." Section 8.1.1 makes each
    /// of these a stream error, which is what <see cref="Malformed"/> raises.
    /// </para>
    /// <para>
    /// A name decoded from HPACK is a string, so an octet above 0x7f arrives as a char above
    /// 0x7f — one test covers both the 0x7f-0xff range and any multi-byte sequence.
    /// </para>
    /// <para>
    /// The encoder's <c>ValidateHeader</c> is deliberately not reused. It is a send-side
    /// subset — it never tests 0x01-0x1f, the high range, or a misplaced colon — and
    /// widening it would change what this client is permitted to emit, which is a separate
    /// decision from what it is willing to accept from an untrusted peer. Section 8.2.1's
    /// leading and trailing SP/HTAB rule for values is also left out here: it is not one of
    /// the delimiter injections this closes, and rejecting it would fail responses real
    /// origins emit. <c>BuildHeaders</c> trims it off instead, which is what RFC 9110 section
    /// 5.5 asks a parser to do with it.
    /// </para>
    /// </remarks>
    private static void ValidateReceivedField(HpackHeader field)
    {
        var name = field.Name;
        if (name.Length == 0)
        {
            throw Malformed("An HTTP/2 response field name is empty.");
        }
        for (var index = 0; index < name.Length; index++)
        {
            var character = name[index];
            if (character <= 0x20 || character >= 0x7f ||
                character is >= 'A' and <= 'Z' ||
                (character == ':' && index != 0))
            {
                throw Malformed(
                    "An HTTP/2 response field name contains a prohibited character.");
            }
        }
        foreach (var character in field.Value)
        {
            if (character is '\0' or '\n' or '\r')
            {
                throw Malformed("An HTTP/2 response field value contains NUL, CR, or LF.");
            }
        }
    }

    public bool ApplyHeaders(IReadOnlyList<HpackHeader> fields)
    {
        var pseudoEnded = false;
        string? status = null;
        var regular = new List<HpackHeader>();
        foreach (var field in fields)
        {
            ValidateReceivedField(field);
            if (field.Name.StartsWith(':'))
            {
                if (pseudoEnded || field.Name != ":status" || status is not null)
                {
                    throw Malformed("The HTTP/2 response pseudo-headers are invalid.");
                }
                status = field.Value;
            }
            else
            {
                pseudoEnded = true;
                if (field.Name is "connection" or "proxy-connection" or "keep-alive" or
                    "upgrade" or "transfer-encoding")
                {
                    throw Malformed(
                        $"The HTTP/2 response contains forbidden header '{field.Name}'.");
                }
                if (field.Name == "te" && !string.Equals(
                        field.Value.Trim(),
                        "trailers",
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw Malformed("The HTTP/2 TE header is invalid.");
                }
                regular.Add(field);
            }
        }

        if (_headers is null)
        {
            if (status is null || status.Length != 3 ||
                !int.TryParse(status, NumberStyles.None, CultureInfo.InvariantCulture, out var code) ||
                code is < 100 or > 999)
            {
                throw Malformed("The HTTP/2 response has no valid :status.");
            }
            if (code is >= 100 and < 200)
            {
                if (code == 101)
                {
                    throw Malformed(
                        "HTTP/2 does not permit a 101 Switching Protocols response.");
                }
                if (code == 100)
                {
                    Continue.TrySetResult();
                }
                return false;
            }
            _statusCode = (HttpStatusCode)code;
            _headers = BuildHeaders(regular);
            FinalResponse.TrySetResult();
            _finalResponseCancellation.Cancel();
            _streamingResponse?.Begin(_statusCode.Value, _headers);
        }
        else
        {
            if (status is not null)
            {
                throw Malformed("HTTP/2 trailers contained :status.");
            }
            _trailers = BuildHeaders(regular);
            return true;
        }
        return false;
    }

    public async ValueTask AppendBodyAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken)
    {
        if (_headers is null)
        {
            throw Malformed("HTTP/2 DATA arrived before response headers.");
        }
        var bodyLength = checked(_bodyLength + data.Length);
        if (bodyLength > _maximumBodyBytes)
        {
            throw Malformed(
                "The HTTP/2 response body exceeds the configured limit.");
        }
        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _responseCancellation.Token);
        if (_streamingResponse is null)
        {
            await _body.WriteAsync(data, linkedCancellation.Token).ConfigureAwait(false);
        }
        else
        {
            await _streamingResponse.WriteAsync(data, linkedCancellation.Token)
                .ConfigureAwait(false);
        }
        _bodyLength = bodyLength;
    }

    public void EnqueueBody(ReadOnlyMemory<byte> data, int flowControlledLength, bool endStream)
    {
        if (Volatile.Read(ref _endReceived) != 0)
        {
            // RFC 9113 section 5.1, half-closed (remote): "If an endpoint receives
            // additional frames, other than WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a
            // stream that is in this state, it MUST respond with a stream error
            // (Section 5.4.2) of type STREAM_CLOSED."
            throw new TlsHttpProtocolException("HTTP/2 DATA arrived after END_STREAM.")
            {
                Http2ErrorCode = Http2ErrorCode.StreamClosed,
                IsStreamScoped = true,
            };
        }
        if (_headers is null)
        {
            throw Malformed("HTTP/2 DATA arrived before response headers.");
        }
        var receivedLength = checked(_receivedBodyLength + data.Length);
        if (receivedLength > _maximumBodyBytes)
        {
            throw Malformed(
                "The HTTP/2 response body exceeds the configured limit.");
        }
        _receivedBodyLength = receivedLength;
        if (endStream)
        {
            Interlocked.Exchange(ref _endReceived, 1);
        }
        if (!_incoming.Writer.TryWrite(new QueuedHttp2Data(
                data,
                flowControlledLength,
                endStream)))
        {
            throw new IOException("The HTTP/2 response body queue was closed.");
        }
    }

    public void EnqueueEnd()
    {
        if (Interlocked.Exchange(ref _endReceived, 1) != 0)
        {
            // A second END_STREAM is a frame on a half-closed (remote) stream, which
            // RFC 9113 section 5.1 makes a stream error of type STREAM_CLOSED.
            throw new TlsHttpProtocolException("HTTP/2 END_STREAM was received twice.")
            {
                Http2ErrorCode = Http2ErrorCode.StreamClosed,
                IsStreamScoped = true,
            };
        }
        if (!_incoming.Writer.TryWrite(new QueuedHttp2Data(
                ReadOnlyMemory<byte>.Empty,
                0,
                true)))
        {
            throw new IOException("The HTTP/2 response body queue was closed.");
        }
    }

    public async ValueTask CompleteAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _completed, 1) != 0)
        {
            return;
        }
        if (_headers is null || _statusCode is null)
        {
            TryFail(Malformed("The HTTP/2 stream ended before final response headers."));
            return;
        }
        try
        {
            using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _responseCancellation.Token);
            if (_streamingResponse is not null)
            {
                await _streamingResponse.CompleteAsync(linkedCancellation.Token)
                    .ConfigureAwait(false);
            }
            var hasBody = RequestMethod != "HEAD" &&
                (int)_statusCode is not (>= 100 and < 200) and not 204 and not 304;
            var body = hasBody && _streamingResponse is null
                ? _body.ToArray()
                : [];
            ValidateContentLength(hasBody ? _bodyLength : 0);
            Completion.TrySetResult(new ParsedHttpResponse(
                HttpVersion.Version20,
                _statusCode.Value,
                string.Empty,
                _headers,
                _trailers ?? new TlsHeaders(),
                body,
                true,
                _headerBytes));
            SignalStateChange();
        }
        catch (Exception exception)
        {
            TryFail(exception);
            throw;
        }
    }

    public void TryFail(Exception exception)
    {
        Interlocked.Exchange(ref _completed, 1);
        _incoming.Writer.TryComplete(exception);
        _streamingResponse?.Abort(exception);
        _responseCancellation.Cancel();
        _finalResponseCancellation.Cancel();
        Completion.TrySetException(exception);
        SignalStateChange();
    }

    public void Dispose()
    {
        _incoming.Writer.TryComplete();
        _responseCancellation.Dispose();
        _finalResponseCancellation.Dispose();
        _body.Dispose();
    }

    private async Task PumpBodyAsync()
    {
        // Octets this pump has taken off the channel but not yet handed to the credit path.
        // The hand-off zeroes it before the await, so a credit that fails in flight is never
        // returned twice — over-crediting would advertise a window the peer may then overrun,
        // which is the one direction RFC 9113 section 6.9.1 makes fatal.
        var owned = 0;
        try
        {
            await foreach (var item in _incoming.Reader.ReadAllAsync(
                _responseCancellation.Token).ConfigureAwait(false))
            {
                owned = item.FlowControlledLength;
                await AppendBodyAsync(item.Data, _responseCancellation.Token)
                    .ConfigureAwait(false);
                owned = 0;
                await _restoreReceiveWindow(
                    this,
                    item.FlowControlledLength,
                    item.EndStream,
                    _responseCancellation.Token).ConfigureAwait(false);
                if (item.EndStream)
                {
                    await CompleteAsync(_responseCancellation.Token).ConfigureAwait(false);
                    _incoming.Writer.TryComplete();
                    return;
                }
            }
        }
        catch (OperationCanceledException) when (_responseCancellation.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            TryFail(exception);
        }
        finally
        {
            // Whatever this pump never credited is still spent against the connection window,
            // so it is handed back before the pump goes away. On the ordinary END_STREAM exit
            // the channel is empty and nothing is owed. This pump is the channel's only
            // reader and it is past reading, so draining here cannot race one.
            while (_incoming.Reader.TryRead(out var pending))
            {
                owned += pending.FlowControlledLength;
            }
            await _returnStrandedConnectionCredit(owned).ConfigureAwait(false);
        }
    }

    private TlsHeaders BuildHeaders(List<HpackHeader> fields)
    {
        if (fields.Count > _maximumHeaderCount)
        {
            throw Malformed("Too many HTTP/2 response headers were received.");
        }
        var headers = new TlsHeaders();
        foreach (var field in fields)
        {
            _headerBytes = checked(_headerBytes + field.Name.Length + field.Value.Length + 2);
            if (_headerBytes > _maximumHeaderBytes)
            {
                throw Malformed(
                    "The HTTP/2 response headers exceeded the configured limit.");
            }
            // RFC 9110 section 5.5: "A field value does not include leading or trailing
            // whitespace. When a specific version of HTTP allows such whitespace to appear in a
            // message, a field parsing implementation MUST exclude such whitespace prior to
            // evaluating the field value." Trimmed rather than rejected, for the reason
            // ValidateReceivedField records: real origins emit padded values. The HTTP/1.1
            // reader has always trimmed here, so this is also what makes the two versions hand
            // a caller the same string for the same field.
            headers.Add(field.Name, field.Value.Trim(' ', '\t'));
        }
        return headers;
    }

    private void ValidateContentLength(long bodyLength)
    {
        if (_headers is null || !_headers.TryGetValues("Content-Length", out var values))
        {
            return;
        }
        if (values.Count != 1 || !long.TryParse(
                values[0],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var declared) || declared < 0 ||
            RequestMethod != "HEAD" && declared != bodyLength)
        {
            throw Malformed("The HTTP/2 Content-Length is invalid.");
        }
    }

    private void SignalStateChange()
    {
        if (Interlocked.Exchange(ref _stateChangeSignaled, 1) == 0)
        {
            _signalStateChange();
        }
    }
}

internal sealed class Http2ResponseCompletedException : Exception;

internal readonly record struct QueuedHttp2Data(
    ReadOnlyMemory<byte> Data,
    int FlowControlledLength,
    bool EndStream);

internal readonly record struct Http2Frame(
    Http2FrameType Type,
    byte Flags,
    int StreamId,
    byte[] Payload);

internal readonly record struct Http2FrameHeader(
    int Length,
    Http2FrameType Type,
    byte Flags,
    int StreamId);

internal static class Http2FrameParser
{
    public static Http2FrameHeader ParseHeader(
        ReadOnlySpan<byte> header,
        int maximumFrameSize)
    {
        if (header.Length != 9)
        {
            throw new TlsHttpProtocolException("An HTTP/2 frame header must be exactly 9 bytes.");
        }
        if (maximumFrameSize is < 16_384 or > 16_777_215)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumFrameSize));
        }

        var length = header[0] << 16 | header[1] << 8 | header[2];
        if (length > maximumFrameSize)
        {
            // RFC 9113 section 4.2: "An endpoint MUST send an error code of FRAME_SIZE_ERROR
            // if a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE."
            throw new TlsHttpProtocolException("An HTTP/2 frame exceeded SETTINGS_MAX_FRAME_SIZE.")
            {
                Http2ErrorCode = Http2ErrorCode.FrameSizeError,
            };
        }
        var streamId = BinaryPrimitives.ReadInt32BigEndian(header[5..]) & 0x7fff_ffff;
        return new Http2FrameHeader(
            length,
            (Http2FrameType)header[3],
            header[4],
            streamId);
    }
}

internal enum Http2FrameType : byte
{
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
    PriorityUpdate = 0x10,
}

internal static class Http2FrameFlags
{
    public const byte EndStream = 0x1;
    public const byte Ack = 0x1;
    public const byte EndHeaders = 0x4;
    public const byte Padded = 0x8;
    public const byte Priority = 0x20;
}
