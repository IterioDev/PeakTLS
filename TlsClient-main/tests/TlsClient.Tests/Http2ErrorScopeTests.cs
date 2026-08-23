using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

/// <summary>
/// Proves the RFC 9113 section 5.4 split: a stream error costs exactly one stream and every
/// other request on the connection completes, while a connection error reports the code the
/// condition names rather than a blanket PROTOCOL_ERROR.
/// </summary>
/// <remarks>
/// Each stream-scoped case runs two concurrent requests over one connection, breaks the
/// first, and requires the second to complete normally. The survivor is the assertion that
/// matters: before this split one malformed response failed every stream on the connection
/// and retired the connection from the pool.
/// </remarks>
public sealed class Http2ErrorScopeTests
{
    [Fact]
    public async Task UppercaseResponseHeader_ResetsOneStreamAndSparesTheOthers()
    {
        // RFC 9113 section 8.1.1 lists "the inclusion of uppercase field names" as malformed,
        // and "Malformed requests or responses that are detected MUST be treated as a stream
        // error (Section 5.4.2) of type PROTOCOL_ERROR."
        await AssertStreamErrorIsIsolatedAsync(
            async (stream, streamId, cancellationToken) =>
            {
                // Literal without indexing, new name: "X" -> "1".
                byte[] block = [0x00, 0x01, (byte)'X', 0x01, (byte)'1'];
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders,
                    streamId,
                    block,
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            },
            Http2ErrorCode.ProtocolError);
    }

    [Fact]
    public async Task ForbiddenConnectionHeader_ResetsOneStreamAndSparesTheOthers()
    {
        // RFC 9113 section 8.2.2: "Any message containing connection-specific header fields
        // MUST be treated as malformed (Section 8.1.1)" — and so a stream error.
        await AssertStreamErrorIsIsolatedAsync(
            async (stream, streamId, cancellationToken) =>
            {
                // :status 200, then "connection" -> "close".
                byte[] block =
                [
                    0x88,
                    0x00, 0x0a,
                    (byte)'c', (byte)'o', (byte)'n', (byte)'n', (byte)'e',
                    (byte)'c', (byte)'t', (byte)'i', (byte)'o', (byte)'n',
                    0x05, (byte)'c', (byte)'l', (byte)'o', (byte)'s', (byte)'e',
                ];
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders,
                    streamId,
                    block,
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            },
            Http2ErrorCode.ProtocolError);
    }

    [Fact]
    public async Task ResponseFieldNameWithAnEmbeddedColon_ResetsOneStreamAndSparesTheOthers()
    {
        // RFC 9113 section 8.2.1: "With the exception of pseudo-header fields (Section 8.3),
        // which have a name that starts with a single colon, field names MUST NOT include a
        // colon (ASCII COLON, 0x3a)."
        await AssertStreamErrorIsIsolatedAsync(
            async (stream, streamId, cancellationToken) =>
            {
                // :status 200, then "a:b" -> "1".
                byte[] block =
                [
                    0x88,
                    0x00, 0x03, (byte)'a', (byte)':', (byte)'b',
                    0x01, (byte)'1',
                ];
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders,
                    streamId,
                    block,
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            },
            Http2ErrorCode.ProtocolError);
    }

    [Fact]
    public async Task ResponseFieldNameThatIsEmpty_ResetsOneStreamAndSparesTheOthers()
    {
        // An empty name is neither a pseudo-header nor a valid token, and section 8.1.1 makes
        // "invalid field names and/or values" malformed. It used to slip past the
        // uppercase-only check into the caller's header collection.
        await AssertStreamErrorIsIsolatedAsync(
            async (stream, streamId, cancellationToken) =>
            {
                byte[] block = [0x88, 0x00, 0x00, 0x01, (byte)'1'];
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders,
                    streamId,
                    block,
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            },
            Http2ErrorCode.ProtocolError);
    }

    [Fact]
    public async Task ResponseFieldValueWithCrLf_ResetsOneStreamAndSparesTheOthers()
    {
        // RFC 9113 section 8.2.1: "A field value MUST NOT contain the zero value (ASCII NUL,
        // 0x00), line feed (ASCII LF, 0x0a), or carriage return (ASCII CR, 0x0d) at any
        // position." Section 8.2.1 names request smuggling as the risk this closes, and the
        // encoder already refuses to emit exactly this.
        await AssertStreamErrorIsIsolatedAsync(
            async (stream, streamId, cancellationToken) =>
            {
                // :status 200, then "a" -> "x\r\ny".
                byte[] block =
                [
                    0x88,
                    0x00, 0x01, (byte)'a',
                    0x04, (byte)'x', 0x0d, 0x0a, (byte)'y',
                ];
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders,
                    streamId,
                    block,
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            },
            Http2ErrorCode.ProtocolError);
    }

    [Fact]
    public async Task PriorityWithAWrongLength_ResetsOneStreamAndSparesTheOthers()
    {
        // RFC 9113 section 6.3: "A PRIORITY frame with a length other than 5 octets MUST be
        // treated as a stream error (Section 5.4.2) of type FRAME_SIZE_ERROR."
        await AssertStreamErrorIsIsolatedAsync(
            async (stream, streamId, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Priority,
                    0,
                    streamId,
                    new byte[4],
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            },
            Http2ErrorCode.FrameSizeError);
    }

    [Fact]
    public async Task ZeroWindowUpdateOnAStream_ResetsOneStreamAndSparesTheOthers()
    {
        // RFC 9113 section 6.9: "A receiver MUST treat the receipt of a WINDOW_UPDATE frame
        // with a flow-control window increment of 0 as a stream error (Section 5.4.2) of type
        // PROTOCOL_ERROR; errors on the connection flow-control window MUST be treated as a
        // connection error (Section 5.4.1)."
        await AssertStreamErrorIsIsolatedAsync(
            async (stream, streamId, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.WindowUpdate,
                    0,
                    streamId,
                    new byte[4],
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            },
            Http2ErrorCode.ProtocolError);
    }

    [Fact]
    public async Task StreamSendWindowOverflow_ResetsOneStreamAndSparesTheOthers()
    {
        // RFC 9113 section 6.9.1: "For streams, the sender sends a RST_STREAM with an error
        // code of FLOW_CONTROL_ERROR; for the connection, a GOAWAY frame with an error code
        // of FLOW_CONTROL_ERROR is sent."
        await AssertStreamErrorIsIsolatedAsync(
            async (stream, streamId, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.WindowUpdate,
                    0,
                    streamId,
                    Increment(int.MaxValue),
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            },
            Http2ErrorCode.FlowControlError);
    }

    [Fact]
    public async Task DataBeyondTheStreamReceiveWindow_ResetsOneStreamAndSparesTheOthers()
    {
        // RFC 9113 section 6.9.1: "errors on the flow-control window of a stream MUST be
        // treated as a stream error (Section 5.4.2) of type FLOW_CONTROL_ERROR." The client
        // advertises a 1024-octet stream window here and the peer sends twice that.
        await AssertStreamErrorIsIsolatedAsync(
            async (stream, streamId, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Data,
                    0,
                    streamId,
                    new byte[2048],
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            },
            Http2ErrorCode.FlowControlError,
            initialWindowSize: 1024);
    }

    [Fact]
    public void DataAfterEndStream_IsAStreamErrorOfTypeStreamClosed()
    {
        // RFC 9113 section 5.1, half-closed (remote): "If an endpoint receives additional
        // frames, other than WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream that is in
        // this state, it MUST respond with a stream error (Section 5.4.2) of type
        // STREAM_CLOSED." Asserted on the stream state directly because END_STREAM also
        // retires the stream, so a loopback script cannot order the two deterministically.
        using var state = CreateStreamState();
        _ = state.ApplyHeaders([new HpackHeader(":status", "200")]);
        state.EnqueueBody(new byte[1], 1, endStream: true);

        var exception = Assert.Throws<TlsHttpProtocolException>(
            () => state.EnqueueBody(new byte[1], 1, endStream: false));

        Assert.Equal(Http2ErrorCode.StreamClosed, exception.Http2ErrorCode);
        Assert.True(exception.IsStreamScoped);
    }

    [Fact]
    public void SecondEndStream_IsAStreamErrorOfTypeStreamClosed()
    {
        using var state = CreateStreamState();
        _ = state.ApplyHeaders([new HpackHeader(":status", "200")]);
        state.EnqueueEnd();

        var exception = Assert.Throws<TlsHttpProtocolException>(state.EnqueueEnd);

        Assert.Equal(Http2ErrorCode.StreamClosed, exception.Http2ErrorCode);
        Assert.True(exception.IsStreamScoped);
    }

    [Fact]
    public async Task OversizeFrame_ReportsFrameSizeError()
    {
        // RFC 9113 section 4.2: "An endpoint MUST send an error code of FRAME_SIZE_ERROR if a
        // frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE."
        var error = await CaptureGoAwayCodeAsync(
            async (stream, streamId, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Data,
                    0,
                    streamId,
                    new byte[16 * 1024 + 1],
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            });

        Assert.Equal(Http2ErrorCode.FrameSizeError, error);
    }

    [Fact]
    public async Task PingWithAWrongLength_ReportsFrameSizeError()
    {
        // RFC 9113 section 6.7: "Receipt of a PING frame with a length field value other than
        // 8 MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR."
        var error = await CaptureGoAwayCodeAsync(
            async (stream, _, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Ping,
                    0,
                    0,
                    new byte[9],
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            });

        Assert.Equal(Http2ErrorCode.FrameSizeError, error);
    }

    [Fact]
    public async Task SettingsWithAWrongLength_ReportsFrameSizeError()
    {
        // RFC 9113 section 6.5: "A SETTINGS frame with a length other than a multiple of 6
        // octets MUST be treated as a connection error (Section 5.4.1) of type
        // FRAME_SIZE_ERROR."
        var error = await CaptureGoAwayCodeAsync(
            async (stream, _, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Settings,
                    0,
                    0,
                    new byte[5],
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            });

        Assert.Equal(Http2ErrorCode.FrameSizeError, error);
    }

    [Fact]
    public async Task GoAwayWithAWrongLength_ReportsFrameSizeError()
    {
        // A GOAWAY too small for its mandatory Last-Stream-ID and Error Code is "too small to
        // contain mandatory frame data" (RFC 9113 section 4.2), so FRAME_SIZE_ERROR.
        var error = await CaptureGoAwayCodeAsync(
            async (stream, _, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.GoAway,
                    0,
                    0,
                    new byte[4],
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            });

        Assert.Equal(Http2ErrorCode.FrameSizeError, error);
    }

    [Fact]
    public async Task HpackDecodingFailure_ReportsCompressionError()
    {
        // RFC 9113 section 4.3: "A decoding error in a field block MUST be treated as a
        // connection error (Section 5.4.1) of type COMPRESSION_ERROR." RFC 7541 section 6.1
        // makes index 0 in an indexed field a decoding error.
        var error = await CaptureGoAwayCodeAsync(
            async (stream, streamId, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders,
                    streamId,
                    [0x80],
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            });

        Assert.Equal(Http2ErrorCode.CompressionError, error);
    }

    [Fact]
    public async Task ConnectionSendWindowOverflow_ReportsFlowControlError()
    {
        // RFC 9113 section 6.9.1: "for the connection, a GOAWAY frame with an error code of
        // FLOW_CONTROL_ERROR is sent." This surfaced as an OverflowException before, which is
        // not a protocol exception, so no GOAWAY was sent at all.
        var error = await CaptureGoAwayCodeAsync(
            async (stream, _, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.WindowUpdate,
                    0,
                    0,
                    Increment(int.MaxValue),
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            });

        Assert.Equal(Http2ErrorCode.FlowControlError, error);
    }

    [Fact]
    public async Task InitialWindowSizeOverflow_ReportsFlowControlError()
    {
        // RFC 9113 section 6.9.2: "An endpoint MUST treat a change to
        // SETTINGS_INITIAL_WINDOW_SIZE that causes any flow-control window to exceed the
        // maximum size as a connection error (Section 5.4.1) of type FLOW_CONTROL_ERROR."
        var error = await CaptureGoAwayCodeAsync(
            async (stream, streamId, cancellationToken) =>
            {
                // Lift the stream's send window off its 65535 default first, so the delta the
                // new initial window applies pushes it past 2^31-1.
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.WindowUpdate,
                    0,
                    streamId,
                    Increment(1000),
                    cancellationToken);
                var settings = new byte[6];
                BinaryPrimitives.WriteUInt16BigEndian(settings, 0x4);
                BinaryPrimitives.WriteUInt32BigEndian(settings.AsSpan(2), int.MaxValue);
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Settings,
                    0,
                    0,
                    settings,
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            });

        Assert.Equal(Http2ErrorCode.FlowControlError, error);
    }

    [Fact]
    public async Task MoreRejectedPushesThanTheCapAllows_ReportsEnhanceYourCalm()
    {
        // This client declines every push, and a declined promise stays remembered until the
        // peer stops sending frames for it, so the set needs a ceiling. RFC 9113 section 5.4.1
        // permits ending the connection for it — "An endpoint can end a connection at any
        // time" — and section 7 names the code: ENHANCE_YOUR_CALM (0x0b), "the endpoint
        // detected that its peer is exhibiting a behavior that might be generating excessive
        // load". Nothing about these frames is malformed, so PROTOCOL_ERROR would misreport it.
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var serverTask = RunPushFloodServerAsync(listener, serverCredential, 1025, timeout.Token);

        var options = CreateOptions(certificates.Root, 65_535);
        // Omitting SETTINGS_ENABLE_PUSH (0x2) leaves push at its section 6.5.2 default of
        // enabled, which is what lets a PUSH_PROMISE reach the backlog at all.
        options.Http2.Preface =
        [
            new TlsHttp2SettingsFrame { Settings = [new(0x4, 65_535)] },
        ];
        await using var session = new TlsSession(options);

        await Assert.ThrowsAnyAsync<Exception>(
            () => session.GetAsync($"https://127.0.0.1:{port}/pushed", timeout.Token));

        Assert.Equal(Http2ErrorCode.EnhanceYourCalm, await serverTask);
    }

    [Fact]
    public async Task GoAway_LeavesAnAlreadyCompleteResponseIntact()
    {
        // RFC 9113 section 6.8: "Activity on streams numbered lower than or equal to the last
        // stream identifier might still complete successfully." A stream whose END_STREAM has
        // already arrived is one of those, whatever error code the GOAWAY carries.
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var finished = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = RunGoAwayAfterResponseServerAsync(
            listener,
            serverCredential,
            finished.Task,
            timeout.Token);

        var options = CreateOptions(certificates.Root, 65_535);
        await using var session = new TlsSession(options);

        var response = await session.GetAsync($"https://127.0.0.1:{port}/done", timeout.Token);
        finished.TrySetResult();
        await serverTask;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("1", response.Text);
    }

    [Fact]
    public async Task DataPastTheConnectionReceiveWindow_ReportsFlowControlError()
    {
        // RFC 9113 section 6.9.1: "A receiver MUST treat the receipt of a flow-controlled
        // frame in excess of the available window as a connection error (Section 5.4.1) of
        // type FLOW_CONTROL_ERROR."
        //
        // The connection window is the 65535-octet default: CreateOptions replaces the preface
        // with SETTINGS alone, so no WINDOW_UPDATE ever lifts it. The stream window is raised
        // to 1 MiB instead, which leaves the connection window the only one this frame can
        // drive negative — the stream check sits behind it under the same lock and would
        // otherwise mask which of the two fired. Sending 65536 octets in a single frame, which
        // the matching SETTINGS_MAX_FRAME_SIZE permits, also keeps the overrun off any race
        // with the client crediting the window back between frames.
        var error = await CaptureGoAwayCodeAsync(
            async (stream, streamId, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.Data,
                    0,
                    streamId,
                    new byte[65_536],
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            },
            initialWindowSize: 1 << 20,
            maximumFrameSize: 1 << 20);

        Assert.Equal(Http2ErrorCode.FlowControlError, error);
    }

    [Fact]
    public async Task ZeroWindowUpdateOnAnIdleStream_IsAConnectionErrorNotAStreamError()
    {
        // The case where section 5.1 and section 6.9 both speak. Section 6.9 would make a zero
        // increment naming a stream "a stream error (Section 5.4.2) of type PROTOCOL_ERROR",
        // but section 5.1's idle state rules the frame out before its payload is read:
        // "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST
        // be treated as a connection error (Section 5.4.1) of type PROTOCOL_ERROR." A GOAWAY
        // arriving at all is the assertion — a stream error would have sent RST_STREAM and
        // left the connection up.
        var error = await CaptureGoAwayCodeAsync(
            async (stream, streamId, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.WindowUpdate,
                    0,
                    IdleStreamIdAbove(streamId),
                    Increment(0),
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            });

        Assert.Equal(Http2ErrorCode.ProtocolError, error);
    }

    [Fact]
    public async Task WindowUpdateOnAnIdleStream_IsAConnectionError()
    {
        // The same section 5.1 rule with nothing in section 6.9 competing: a well-formed
        // increment does not make the frame legal on a stream that was never opened.
        var error = await CaptureGoAwayCodeAsync(
            async (stream, streamId, cancellationToken) =>
            {
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.WindowUpdate,
                    0,
                    IdleStreamIdAbove(streamId),
                    Increment(1024),
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
            });

        Assert.Equal(Http2ErrorCode.ProtocolError, error);
    }

    /// <summary>
    /// A client-initiated identifier the client has not reached yet, which is what RFC 9113
    /// section 5.1 calls "idle".
    /// </summary>
    /// <remarks>
    /// It must stay odd and stay above the next identifier the client would use. An odd
    /// identifier *below* that one is "closed" rather than idle — section 5.1.1: "an endpoint
    /// may skip a stream identifier, with the effect being that the skipped stream is
    /// immediately closed" — and section 6.9 forbids treating a WINDOW_UPDATE on a closed
    /// stream as an error at all, so the two states must not be confused here.
    /// </remarks>
    private static int IdleStreamIdAbove(int activeStreamId) => activeStreamId + 100;

    private static async Task AssertStreamErrorIsIsolatedAsync(
        Func<Stream, int, CancellationToken, Task> offend,
        Http2ErrorCode expectedResetCode,
        int initialWindowSize = 65_535)
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var firstStreamReady = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var streamsReady = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var finished = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = RunStreamErrorServerAsync(
            listener,
            serverCredential,
            firstStreamReady,
            streamsReady,
            finished.Task,
            offend,
            timeout.Token);

        var options = CreateOptions(certificates.Root, initialWindowSize);
        await using var session = new TlsSession(options);
        var origin = $"https://127.0.0.1:{port}";

        var doomed = session.GetAsync($"{origin}/doomed", timeout.Token);
        await firstStreamReady.Task.WaitAsync(timeout.Token);
        var survivor = session.GetAsync($"{origin}/survivor", timeout.Token);
        await streamsReady.Task.WaitAsync(timeout.Token);

        await Assert.ThrowsAnyAsync<IOException>(() => doomed);
        var survivingResponse = await survivor;
        finished.TrySetResult();
        var capture = await serverTask;

        Assert.Equal(HttpStatusCode.OK, survivingResponse.StatusCode);
        Assert.Equal("3", survivingResponse.Text);
        Assert.Equal(1, capture.StreamId);
        Assert.Equal(expectedResetCode, capture.Error);
    }

    private static async Task<Http2ErrorCode> CaptureGoAwayCodeAsync(
        Func<Stream, int, CancellationToken, Task> offend,
        int initialWindowSize = 65_535,
        int maximumFrameSize = 16_384)
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serverTask = RunGoAwayServerAsync(listener, serverCredential, offend, timeout.Token);

        var options = CreateOptions(certificates.Root, initialWindowSize, maximumFrameSize);
        await using var session = new TlsSession(options);

        await Assert.ThrowsAnyAsync<Exception>(
            () => session.GetAsync($"https://127.0.0.1:{port}/broken", timeout.Token));
        return await serverTask;
    }

    private static async Task<CapturedReset> RunStreamErrorServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        TaskCompletionSource firstStreamReady,
        TaskCompletionSource streamsReady,
        Task finished,
        Func<Stream, int, CancellationToken, Task> offend,
        CancellationToken cancellationToken)
    {
        await using var connection = await AcceptAsync(listener, credential, cancellationToken);
        var stream = connection.Stream;
        var streamIds = new List<int>();
        while (streamIds.Count < 2)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers)
            {
                streamIds.Add(frame.StreamId);
                (streamIds.Count == 1 ? firstStreamReady : streamsReady).TrySetResult();
            }
        }

        await offend(stream, streamIds[0], cancellationToken);
        Http2Frame reset;
        do
        {
            reset = await ReadFrameAsync(stream, cancellationToken);
        }
        while (reset.Type != Http2FrameType.RstStream);

        await SendOneByteResponseAsync(stream, streamIds[1], cancellationToken);
        await finished.WaitAsync(cancellationToken);
        listener.Stop();
        return new CapturedReset(
            reset.StreamId,
            (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(reset.Payload));
    }

    private static async Task<Http2ErrorCode> RunGoAwayServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        Func<Stream, int, CancellationToken, Task> offend,
        CancellationToken cancellationToken)
    {
        await using var connection = await AcceptAsync(listener, credential, cancellationToken);
        var stream = connection.Stream;
        var streamId = 0;
        while (streamId == 0)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers)
            {
                streamId = frame.StreamId;
            }
        }

        await offend(stream, streamId, cancellationToken);
        Http2Frame goAway;
        do
        {
            goAway = await ReadFrameAsync(stream, cancellationToken);
        }
        while (goAway.Type != Http2FrameType.GoAway);

        listener.Stop();
        return (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(goAway.Payload.AsSpan(4));
    }

    /// <summary>
    /// Promises <paramref name="pushes"/> streams the client will decline, and returns the code
    /// on the GOAWAY that ends the connection once the backlog cap is passed.
    /// </summary>
    /// <remarks>
    /// The promises are written in lockstep with the RST_STREAM answers rather than all at once.
    /// The client answers each promise from the same read loop that consumes them, so a thousand
    /// unread answers would stall its write, which stalls its read, which stalls this write —
    /// the deadlock this connection class is prone to. One promise, one drain, no backlog.
    /// </remarks>
    private static async Task<Http2ErrorCode> RunPushFloodServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        int pushes,
        CancellationToken cancellationToken)
    {
        await using var connection = await AcceptAsync(listener, credential, cancellationToken);
        var stream = connection.Stream;
        var streamId = 0;
        while (streamId == 0)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers)
            {
                streamId = frame.StreamId;
            }
        }

        try
        {
            for (var promised = 2; promised <= pushes * 2; promised += 2)
            {
                // 0x82 is one indexed field (":method: GET") from the static table: a complete,
                // legal field block, so the client rejects the push on its own policy rather
                // than on a decoding error.
                var payload = new byte[5];
                BinaryPrimitives.WriteInt32BigEndian(payload, promised);
                payload[4] = 0x82;
                await WriteFrameAsync(
                    stream,
                    Http2FrameType.PushPromise,
                    Http2FrameFlags.EndHeaders,
                    streamId,
                    payload,
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
                while (true)
                {
                    var frame = await ReadFrameAsync(stream, cancellationToken);
                    if (frame.Type == Http2FrameType.GoAway)
                    {
                        return (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(
                            frame.Payload.AsSpan(4));
                    }
                    if (frame.Type == Http2FrameType.RstStream)
                    {
                        break;
                    }
                }
            }
        }
        finally
        {
            listener.Stop();
        }

        throw new InvalidOperationException(
            $"The client accepted {pushes} rejected pushes without ending the connection.");
    }

    private static async Task RunGoAwayAfterResponseServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        Task finished,
        CancellationToken cancellationToken)
    {
        await using var connection = await AcceptAsync(listener, credential, cancellationToken);
        var stream = connection.Stream;
        var streamId = 0;
        while (streamId == 0)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers)
            {
                streamId = frame.StreamId;
            }
        }

        await SendOneByteResponseAsync(stream, streamId, cancellationToken);
        var goAway = new byte[8];
        BinaryPrimitives.WriteInt32BigEndian(goAway, streamId);
        BinaryPrimitives.WriteUInt32BigEndian(
            goAway.AsSpan(4),
            (uint)Http2ErrorCode.InternalError);
        await WriteFrameAsync(stream, Http2FrameType.GoAway, 0, 0, goAway, cancellationToken);
        await stream.FlushAsync(cancellationToken);
        await finished.WaitAsync(cancellationToken);
        listener.Stop();
    }

    private static async Task<ServerConnection> AcceptAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["h2"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(tcpClient.GetStream(), leaveOpen: false, cancellationToken);
        var stream = server.AsStream(leaveServerOpen: true);
        var preface = new byte[24];
        await ReadExactlyAsync(stream, preface, cancellationToken);
        _ = await ReadFrameAsync(stream, cancellationToken);
        await WriteFrameAsync(stream, Http2FrameType.Settings, 0, 0, [], cancellationToken);
        await stream.FlushAsync(cancellationToken);
        return new ServerConnection(tcpClient, server, stream);
    }

    private static Http2StreamState CreateStreamState() => new(
        1,
        "GET",
        65_535,
        65_535,
        1 << 20,
        1 << 16,
        64,
        null,
        (_, _, _, _) => ValueTask.CompletedTask,
        _ => ValueTask.CompletedTask,
        () => { },
        CancellationToken.None,
        CancellationToken.None);

    private static byte[] Increment(int value)
    {
        var payload = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(payload, value);
        return payload;
    }

    private static TlsSessionOptions CreateOptions(
        X509Certificate2 trustRoot,
        int initialWindowSize,
        int maximumFrameSize = 16_384)
    {
        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            HttpVersionPolicy = TlsHttpVersionPolicy.Http2Only,
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [trustRoot];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        };

        // A retry would open a second connection the scripted servers below never accept.
        options.Retry.MaximumAttempts = 1;
        options.Retry.RetryConnectionFailures = false;
        options.Http2.Preface =
        [
            new TlsHttp2SettingsFrame
            {
                Settings =
                [
                    new(0x1, 65_536),
                    new(0x2, 0),
                    new(0x4, (uint)initialWindowSize),
                    new(0x5, (uint)maximumFrameSize),
                    new(0x6, 262_144),
                ],
            },
        ];
        return options;
    }

    private static async ValueTask SendOneByteResponseAsync(
        Stream stream,
        int streamId,
        CancellationToken cancellationToken)
    {
        byte[] responseHeaders = [0x88, 0x5c, 0x01, 0x31];
        await WriteFrameAsync(
            stream,
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders,
            streamId,
            responseHeaders,
            cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Data,
            Http2FrameFlags.EndStream,
            streamId,
            [(byte)('0' + streamId)],
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async ValueTask<Http2Frame> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        await ReadExactlyAsync(stream, header, cancellationToken);
        var length = header[0] << 16 | header[1] << 8 | header[2];
        var payload = new byte[length];
        await ReadExactlyAsync(stream, payload, cancellationToken);
        return new Http2Frame(
            (Http2FrameType)header[3],
            header[4],
            BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(5)) & 0x7fff_ffff,
            payload);
    }

    private static async ValueTask WriteFrameAsync(
        Stream stream,
        Http2FrameType type,
        byte flags,
        int streamId,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        header[0] = (byte)(payload.Length >> 16);
        header[1] = (byte)(payload.Length >> 8);
        header[2] = (byte)payload.Length;
        header[3] = (byte)type;
        header[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(5), streamId);
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(payload, cancellationToken);
    }

    private static async ValueTask ReadExactlyAsync(
        Stream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(destination[offset..], cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
        }
    }

    private sealed record CapturedReset(int StreamId, Http2ErrorCode Error);

    private sealed class ServerConnection(
        TcpClient client,
        CustomTlsServer server,
        Stream stream) : IAsyncDisposable
    {
        public Stream Stream { get; } = stream;

        public async ValueTask DisposeAsync()
        {
            await Stream.DisposeAsync();
            await server.DisposeAsync();
            client.Dispose();
        }
    }
}
