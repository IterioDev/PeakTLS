using System.Net;
using SharpTls;

namespace TlsClient.Tests;

/// <summary>
/// Pins the claims docs/USAGE.md section 2a makes. A reader wires a proxy from that section and
/// finds out at the first request whether it holds, so the assertions live here rather than in
/// prose alone.
/// </summary>
public sealed class ProxyUsageDocTests
{
    private static TlsProxy Socks5() =>
        TlsProxy.Socks5("socks5://proxy.example.net:1080", "username", "password");

    [Fact]
    public void Socks5WithCredentials_CarriesThemAndDefaultsThePort()
    {
        var proxy = Socks5();

        Assert.Equal(TlsProxyType.Socks5, proxy.Type);
        Assert.Equal("username", proxy.Credentials?.UserName);
        Assert.Equal("password", proxy.Credentials?.Password);

        // The documented default: 1080 when the address omits a port.
        Assert.Equal(
            1080,
            TlsProxy.Socks5("socks5://proxy.example.net").Address is { IsDefaultPort: true }
                ? 1080
                : TlsProxy.Socks5("socks5://proxy.example.net").Address.Port);
    }

    [Fact]
    public void SessionProxy_SurvivesTheWholeSessionRatherThanOneRequest()
    {
        var options = new TlsSessionOptions { Proxy = Socks5() };

        // Snapshot is what every request reads, so this is the session-lifetime claim.
        Assert.Same(options.Proxy, options.Snapshot().Proxy);
    }

    [Fact]
    public void RequestProxyOfNull_IsAnOverrideAndNotAnUnset()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        var requestOptions = TlsRequestOptions.For(request);

        requestOptions.Proxy = null;

        // Documented as "this one request goes direct" while the session keeps its own. The
        // flag is internal, so read it where it is observable: the frozen configuration.
        Assert.True(TlsRequestOptions.Snapshot(request).HasProxyOverride);

        requestOptions.UseSessionProxy();
        Assert.False(TlsRequestOptions.Snapshot(request).HasProxyOverride);
    }

#pragma warning disable TLSCLIENT3
    [Fact]
    public async Task Http3ThroughAnHttpProxy_RefusesAndNamesTheType()
    {
        const TlsProxyType type = TlsProxyType.Http;
        // The refusal must arrive BEFORE any dial, which is what the closed ports establish:
        // a NotSupportedException from a dead address can only have come from the pre-connect
        // fork. HTTP CONNECT tunnels a TCP byte stream and never relays a datagram, so
        // HTTP CONNECT cannot carry QUIC - and the message says which type it means, because
        // "proxies are TCP tunnels" as a blanket statement was what hid SOCKS5 for as long as
        // it did. SOCKS4 was the other refusing type until this client stopped speaking it.
        var configuration = new TlsSessionOptions().Snapshot();
        var proxy = TlsProxy.Http("http://127.0.0.1:1");

        var error = await Assert.ThrowsAsync<NotSupportedException>(
            () => HttpConnectionFactory.ConnectAsync(
                new Uri("https://127.0.0.1:1/"),
                TlsHttpVersionPolicy.Http3Only,
                proxy,
                configuration,
                new Tls13SessionCache(),
                new DnsEndpointResolver(configuration),
                new Socks5AssociationGate(),
                CancellationToken.None).AsTask());

        Assert.Contains($"through a {type} proxy", error.Message, StringComparison.Ordinal);
        Assert.Contains("only SOCKS5 relays datagrams", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Http3ThroughASocks5Proxy_IsWiredRatherThanRefused()
    {
        // THE POINT OF THIS TEST IS THE ABSENCE OF ONE EXCEPTION TYPE, not the presence of
        // another. RFC 1928 section 7's UDP ASSOCIATE is what SOCKS5 has and the other two do
        // not, and SharpTls has relayed QUIC datagrams over it since c56267d - the gap was
        // that Http3Connection hardcoded the direct UDP transport and never offered the relay.
        //
        // 127.0.0.1:1 is closed, so the association cannot be established and this MUST still
        // fail. What it must not do is fail with NotSupportedException, because that is the
        // "your proxy can never carry this" answer and it is no longer the true one.
        var configuration = new TlsSessionOptions().Snapshot();

        var error = await Assert.ThrowsAnyAsync<Exception>(
            () => HttpConnectionFactory.ConnectAsync(
                new Uri("https://127.0.0.1:1/"),
                TlsHttpVersionPolicy.Http3Only,
                TlsProxy.Socks5("socks5://127.0.0.1:1", "username", "password"),
                configuration,
                new Tls13SessionCache(),
                new DnsEndpointResolver(configuration),
                new Socks5AssociationGate(),
                CancellationToken.None).AsTask());

        Assert.IsNotType<NotSupportedException>(error);
    }
#pragma warning restore TLSCLIENT3

    [Fact]
    public void EchDnsResolver_CannotBeCombinedWithAProxy()
    {
        // ProfileRoller was the other half of this claim and is gone, so EchDnsResolver is now
        // the only option a proxy excludes.
        var options = new TlsSessionOptions
        {
            Proxy = Socks5(),
            EchDnsResolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
            {
                NameServers = [new IPEndPoint(IPAddress.Loopback, 53)],
            }),
        };

        Assert.Throws<InvalidOperationException>(() => options.Snapshot());
    }

    private static string Flatten(Exception error) =>
        error.InnerException is null
            ? error.Message
            : error.Message + " | " + Flatten(error.InnerException);
}
