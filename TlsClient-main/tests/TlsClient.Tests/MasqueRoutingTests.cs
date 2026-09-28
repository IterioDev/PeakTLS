using SharpTls.Quic;

namespace TlsClient.Tests;

#pragma warning disable TLSCLIENT3 // Http3Only is [Experimental]; ProxyUsageDocTests does the same
public sealed class MasqueRoutingTests
{
    [Fact]
    public async Task AMasqueProxyInTheTcpSlotIsRefusedByName()
    {
        await using var transport = new MemoryStream();
        var exception = await Assert.ThrowsAsync<NotSupportedException>(async () =>
            await ProxyTunnel.EstablishAsync(
                transport, new Uri("https://example.com/"),
                TlsProxy.Masque("https://masque.example:50000", "u", "p"), 4096, CancellationToken.None));
        Assert.Contains("options.Quic.Proxy", exception.Message);
    }

    [Fact]
    public void AnHttpProxyBesideAMasqueQuicProxyIsALegalSession()
    {
        var options = new TlsSessionOptions { Proxy = TlsProxy.Http("http://127.0.0.1:8080") };
        options.Quic.Proxy = TlsProxy.Masque("https://masque.example:50000", "u", "p");
        var configuration = options.Snapshot();
        HttpConnectionFactory.ThrowIfProxyCannotCarryHttp3(options.Proxy, configuration.Quic);
    }

    [Fact]
    public void AnHttpProxyAloneStillCannotCarryHttp3()
    {
        var options = new TlsSessionOptions { Proxy = TlsProxy.Http("http://127.0.0.1:8080") };
        Assert.Throws<NotSupportedException>(() =>
            HttpConnectionFactory.ThrowIfProxyCannotCarryHttp3(options.Proxy, options.Snapshot().Quic));
    }

    [Fact]
    public async Task AMasqueDialThatCannotReachTheProxyFailsByName()
    {
        // 127.0.0.1:1 answers nothing; the 2 s HandshakeDeadline bounds the outer dial, which
        // reports MasqueTunnelRefused "did not come up within". Http3Only because the default
        // policy prefers h2 and would dial TCP; no connection retry because one attempt is the
        // point.
        var options = new TlsSessionOptions { HttpVersionPolicy = TlsHttpVersionPolicy.Http3Only };
        options.Quic.Proxy = TlsProxy.Masque("https://127.0.0.1:1", "u", "p");
        options.Quic.HandshakeDeadline = TimeSpan.FromSeconds(2);
        options.Timeout = TimeSpan.FromSeconds(10);
        options.Retry.RetryConnectionFailures = false;
        await using var session = new TlsSession(options);

        var exception = await Assert.ThrowsAnyAsync<Exception>(
            () => session.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://example.com/")));

        Exception? cursor = exception;
        while (cursor is not null && cursor is not TlsQuicProxyException)
        {
            cursor = cursor.InnerException;
        }
        var proxyFailure = Assert.IsType<TlsQuicProxyException>(cursor);
        Assert.Equal(TlsQuicProxyError.MasqueTunnelRefused, proxyFailure.Error);
        Assert.Contains("did not come up within", proxyFailure.Message);
    }
}
#pragma warning restore TLSCLIENT3
