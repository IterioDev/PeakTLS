using System.Net;
using System.Text.Json;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>Dials through a real MASQUE proxy. Runs only when TLSCLIENT_LIVE_MASQUE holds
/// https://user:pass@host:port; the credential never lives in this repository.</summary>
/// <remarks>Without that variable each test returns green rather than skipping, so a pass
/// proves nothing unless the variable was set.</remarks>
public sealed class MasqueLiveTests
{
    private static TlsSessionOptions? Options(Action<TlsSessionOptions>? adjust = null)
    {
        if (Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_MASQUE") is not { } url)
        {
            return null;
        }
        var proxy = new Uri(url);
        var credentials = proxy.UserInfo.Split(':', 2);
        var options = TlsPresets.Spotify.CreateOptions();
        options.Timeout = TimeSpan.FromSeconds(30);
        options.Quic.Proxy = TlsProxy.Masque(
            $"https://{proxy.Host}:{proxy.Port}",
            Uri.UnescapeDataString(credentials[0]),
            Uri.UnescapeDataString(credentials[1]));
        adjust?.Invoke(options);
        return options;
    }

    /// <summary>sphynx's shape: one sticky session id on the SOCKS5 proxy for h2 and on the
    /// MASQUE proxy for h3, with the h2 request first. Without the MASQUE-first binding this
    /// failed 10 sessions out of 10 on 2026-09-28 (a TCP TLS alert answering the inner Initial);
    /// with it, both hops share one exit. Needs TLSCLIENT_LIVE_SOCKS5 as well
    /// (socks5://user:pass@host:port, same account).</summary>
    [Fact]
    public async Task ASessionUsedOverSocks5FirstStillCarriesHttp3()
    {
        if (Options() is not { } options
            || Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_SOCKS5") is not { } socksUrl)
        {
            return;
        }
        var socks = new Uri(socksUrl);
        var masqueUser = options.Quic.Proxy!.GetCredentials()!.UserName;
        var fresh = System.Text.RegularExpressions.Regex.Replace(
            masqueUser, @"sessid-\d+", $"sessid-{Random.Shared.NextInt64(1_000_000_000, 9_999_999_999)}");
        var password = options.Quic.Proxy.GetCredentials()!.Password;
        var masque = TlsProxy.Masque(
            $"https://{new Uri(Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_MASQUE")!).Host}:50000",
            fresh,
            password);

        var events = new List<TlsConnectEventKind>();
        var h2 = TlsPresets.SpotifyH2.CreateOptions();
        h2.Proxy = TlsProxy.Socks5($"socks5://{socks.Host}:{socks.Port}", fresh, password);
        h2.Quic.Proxy = masque;
        h2.ConnectObserver = e => { lock (events) { events.Add(e.Kind); } };
        h2.Timeout = TimeSpan.FromSeconds(30);
        await using (var session = new TlsSession(h2))
        {
            var response = await session.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://ip.oxylabs.io/json"));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(HttpVersion.Version20, response.HttpVersion);
        }
        Assert.Contains(TlsConnectEventKind.MasqueSessionBound, events);

        var h3 = TlsPresets.Spotify.CreateOptions();
        h3.Quic.Proxy = masque;
        h3.Timeout = TimeSpan.FromSeconds(30);
        await using var session3 = new TlsSession(h3);
        var request = new HttpRequestMessage(HttpMethod.Get, "https://spclient.wg.spotify.com/");
        request.AddHeader("user-agent", "Spotify/9.1.86 iOS/27.0 (iPhone17,2)");
        var answer = await session3.SendAsync(request);
        Assert.Equal(HttpVersion.Version30, answer.HttpVersion);
    }

    [Fact]
    public async Task TheTargetSeesTheHandsetThroughTheTunnel()
    {
        if (Options() is not { } options) return;
        await using var session = new TlsSession(options);
        var response = await session.SendAsync(SpotifyPresetLiveParityTests.NewRequest());
        Assert.Equal(HttpVersion.Version30, response.HttpVersion);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(response.Text);
        SpotifyPresetLiveParityTests.AssertHandsetFingerprint(document);
    }

    [Fact]
    public async Task ThreeRequestsOnOneTunnelledConnectionAllDecode()
    {
        if (Options() is not { } options) return;
        await using var session = new TlsSession(options);
        for (var i = 0; i < 3; i++)
        {
            var response = await session.SendAsync(SpotifyPresetLiveParityTests.NewRequest());
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    /// <summary>One live tunnel per outer connection: two origins whose h3 connections both stay
    /// pooled cost two outer dials and two tunnels, and neither waits on the other's traffic.
    /// </summary>
    [Fact]
    public async Task EachLiveTunnelRidesAnOuterConnectionOfItsOwn()
    {
        var events = new List<TlsConnectEventKind>();
        if (Options(o => o.ConnectObserver = e => { lock (events) { events.Add(e.Kind); } }) is not { } options)
        {
            return;
        }
        await using var session = new TlsSession(options);

        var first = await session.SendAsync(SpotifyPresetLiveParityTests.NewRequest());
        Assert.Equal(HttpVersion.Version30, first.HttpVersion);
        var request = new HttpRequestMessage(HttpMethod.Get, "https://spclient.wg.spotify.com/");
        request.AddHeader("user-agent", "Spotify/9.1.86 iOS/27.0 (iPhone17,2)");
        var second = await session.SendAsync(request);
        Assert.Equal(HttpVersion.Version30, second.HttpVersion);

        lock (events)
        {
            Assert.Equal(2, events.Count(k => k == TlsConnectEventKind.MasqueConnectionOpened));
            Assert.Equal(2, events.Count(k => k == TlsConnectEventKind.MasqueTunnelOpened));
        }
    }

    [Fact]
    public async Task AGoogleHostedTargetAnswersThroughTheTunnel()
    {
        if (Options() is not { } options) return;
        await using var session = new TlsSession(options);
        var request = new HttpRequestMessage(HttpMethod.Get, "https://spclient.wg.spotify.com/");
        request.AddHeader("user-agent", "Spotify/9.1.86 iOS/27.0 (iPhone17,2)");
        var response = await session.SendAsync(request);
        Assert.Equal(HttpVersion.Version30, response.HttpVersion);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Contains("envoy", response.Headers["server"]); // TlsHeaders indexer
    }

    [Fact]
    public async Task AWrongPasswordIsRefusedByName()
    {
        if (Options(o => o.Quic.Proxy = TlsProxy.Masque(
                $"https://{o.Quic.Proxy!.Address.Host}:{o.Quic.Proxy.Address.Port}",
                o.Quic.Proxy.Credentials!.UserName,
                "wrong")) is not { } options) return;
        await using var session = new TlsSession(options);
        var exception = await Assert.ThrowsAnyAsync<Exception>(
            () => session.SendAsync(SpotifyPresetLiveParityTests.NewRequest()));
        Exception? cursor = exception;
        while (cursor is not null && cursor is not TlsQuicProxyException) cursor = cursor.InnerException;
        var proxyFailure = Assert.IsType<TlsQuicProxyException>(cursor);
        Assert.Equal(TlsQuicProxyError.MasqueAuthenticationRejected, proxyFailure.Error);
    }
}
