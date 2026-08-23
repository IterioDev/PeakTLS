using System.Net;

namespace TlsClient.Tests.Wire;

public sealed class Http2WireCaptureTests
{
    [Fact]
    public async Task CapturesConnectionPrefaceMagicExactly()
    {
        var options = new TlsSessionOptions();

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, ct) => session.GetAsync(url, ct));

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal(
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray(),
            result.ClientBytes[..24]);
    }

    [Fact]
    public async Task CapturesClientFramesInArrivalOrder()
    {
        // The preface is declared here rather than inherited from a preset: the assertion
        // below is about ORDER, so the frames it expects have to be ones this test asked for.
        var options = new TlsSessionOptions();
        options.Http2.Preface =
        [
            new TlsHttp2SettingsFrame { Settings = [new(0x1, 65_536), new(0x4, 6_291_456)] },
            new TlsHttp2WindowUpdateFrame { Increment = 15_663_105 },
        ];

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, ct) => session.GetAsync(url, ct));

        Assert.Equal(Http2FrameType.Settings, result.ClientFrames[0].Type);
        Assert.Equal(Http2FrameType.WindowUpdate, result.ClientFrames[1].Type);
        Assert.Contains(result.ClientFrames, frame => frame.Type == Http2FrameType.Headers);
    }

    [Fact]
    public async Task CapturedBytesContainEveryCapturedFrame()
    {
        var options = new TlsSessionOptions();

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, ct) => session.GetAsync(url, ct));

        // Magic plus each frame's 9-byte header and payload must account for the
        // recorded stream exactly. Every byte the server reads is recorded, and every
        // frame it parses comes from those same reads, so the two totals move together.
        // An inequality here would be silent on a recorder that duplicated bytes, which
        // is precisely the failure this harness exists to catch.
        var expected = 24 + result.ClientFrames.Sum(frame => 9 + frame.Payload.Length);
        Assert.Equal(expected, result.ClientBytes.Length);
    }

    [Fact]
    public async Task SurfacesServerScriptExceptionInsteadOfClientTimeout()
    {
        var options = new TlsSessionOptions();

        var brokenScript = new Http2ServerScript((_, _) =>
            throw new InvalidOperationException("broken server script"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Http2WireCapture.RunAsync(
                options,
                (session, url, ct) => session.GetAsync(url, ct),
                brokenScript));

        Assert.Equal("broken server script", exception.Message);
    }

    [Fact]
    public async Task PropagatesClientRequestFailureInsteadOfHanging()
    {
        var options = new TlsSessionOptions();

        // A request delegate that makes a real request but then throws reproduces the
        // client-failure path: the server script completes (reaching responseReceived.WaitAsync),
        // then requestTask faults. If RunAsync's finally does not complete responseReceived,
        // the server stays parked forever. Bound this test with its own short timeout so a
        // regression fails fast instead of hanging the suite for the harness's own 15-second bound.
        using var testTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // Must make a real request first so the server actually reaches responseReceived.WaitAsync
        // (not just stuck on AcceptTcpClientAsync). Then throw to test that RunAsync's finally
        // block completes responseReceived even when the request faults.
        static async Task<TlsResponse> BrokenRequestAsync(
            TlsSession session, string url, CancellationToken cancellationToken)
        {
            // Make a successful request first, letting the server script complete
            var response = await session.GetAsync(url, cancellationToken);

            // Now throw after the server is actually waiting on responseReceived
            throw new InvalidOperationException("broken request");
        }

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Http2WireCapture.RunAsync(
                options,
                BrokenRequestAsync,
                cancellationToken: testTimeout.Token));

        Assert.Equal("broken request", exception.Message);
    }
}
