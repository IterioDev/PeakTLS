using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests.Wire;

internal sealed record Http2WireResult(
    byte[] ClientBytes,
    IReadOnlyList<CapturedFrame> ClientFrames,
    TlsResponse Response,
    IReadOnlyList<int> ReadSegmentLengths);

internal delegate Task Http2ServerScript(
    Http2WireServer server,
    CancellationToken cancellationToken);

/// <summary>
/// Runs a real TlsSession against a scripted loopback HTTP/2 server and returns the
/// exact decrypted bytes the client wrote.
/// </summary>
internal static class Http2WireCapture
{
    /// <summary>
    /// Reads the preface, acknowledges with an empty SETTINGS frame, waits for the
    /// request header block, and replies 200 with END_STREAM.
    /// </summary>
    public static Http2ServerScript MinimalExchange { get; } = async (server, cancellationToken) =>
    {
        var preface = await server.ReadPrefaceAsync(cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray(), preface);

        await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
        await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
        await server.FlushAsync(cancellationToken);

        var headers = await server.ReadUntilAsync(Http2FrameType.Headers, cancellationToken);
        var frame = headers;
        while ((frame.Flags & Http2FrameFlags.EndHeaders) == 0)
        {
            frame = await server.ReadFrameAsync(cancellationToken);
        }

        // 0x88 is the static-table entry for ":status: 200".
        await server.WriteFrameAsync(
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
            headers.StreamId,
            [0x88],
            cancellationToken);
        await server.FlushAsync(cancellationToken);
    };

    public static async Task<Http2WireResult> RunAsync(
        TlsSessionOptions options,
        Func<TlsSession, string, CancellationToken, Task<TlsResponse>> request,
        Http2ServerScript? script = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(request);
        script ??= MinimalExchange;

        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));

        var responseReceived = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = RunServerAsync(
            listener,
            serverCredential,
            script,
            responseReceived.Task,
            timeout.Token);

        options.HttpVersionPolicy = TlsHttpVersionPolicy.Http2Only;
        var existingConfigure = options.ConfigureTls;
        options.ConfigureTls = tls =>
        {
            existingConfigure?.Invoke(tls);
            tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
            tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
            tls.CertificateValidation.DisableCertificateDownloads = true;
        };

        await using var session = new TlsSession(options);
        var requestTask = request(
            session,
            $"https://127.0.0.1:{port}/capture",
            timeout.Token);

        // The server script only finishes after the client's response arrives, so it
        // cannot win this race unless it faulted. Observing it here surfaces the real
        // assertion failure immediately, instead of letting the client block until the
        // 15-second timeout and report a misleading cancellation.
        if (await Task.WhenAny(requestTask, serverTask).ConfigureAwait(false) == serverTask)
        {
            await serverTask.ConfigureAwait(false);
        }

        TlsResponse response;
        try
        {
            response = await requestTask.ConfigureAwait(false);
        }
        finally
        {
            // Must run whether or not the request faulted. RunServerAsync is parked on
            // responseReceived.WaitAsync and has no other way to notice the client is
            // done — without this, a faulting request leaves the server task (and the
            // TcpClient/CustomTlsServer/TLS stream it owns) stuck until the process
            // exits, since `using var timeout` above disposes the CancelAfter timer as
            // soon as this method unwinds, so the token can never fire either.
            responseReceived.TrySetResult();
        }

        var capture = await serverTask.ConfigureAwait(false);
        return new Http2WireResult(
            capture.ClientBytes,
            capture.Frames,
            response,
            capture.ReadSegmentLengths);
    }

    private static async Task<(
        byte[] ClientBytes,
        IReadOnlyList<CapturedFrame> Frames,
        IReadOnlyList<int> ReadSegmentLengths)>
        RunServerAsync(
            TcpListener listener,
            TlsServerCertificate credential,
            Http2ServerScript script,
            Task responseReceived,
            CancellationToken cancellationToken)
    {
        using var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["h2"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(
            tcpClient.GetStream(),
            leaveOpen: false,
            cancellationToken);

        await using var tlsStream = server.AsStream(leaveServerOpen: true);
        await using var recording = new RecordingStream(tlsStream);
        var wire = new Http2WireServer(recording);

        await script(wire, cancellationToken);
        await responseReceived.WaitAsync(cancellationToken);

        // Each read segment is one plaintext record the client flushed, so the segment
        // lengths are where a declared FlushAfter boundary becomes observable.
        return (recording.ReadBytes, wire.ClientFrames, recording.ReadSegmentLengths);
    }
}
