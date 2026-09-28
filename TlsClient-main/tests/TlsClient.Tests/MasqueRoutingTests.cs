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
}
#pragma warning restore TLSCLIENT3
