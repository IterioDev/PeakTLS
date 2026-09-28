using System.Net;
using System.Text.Json;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>Dials through a real MASQUE proxy. Runs only when TLSCLIENT_LIVE_MASQUE holds
/// https://user:pass@host:port; the credential never lives in this repository.</summary>
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

        // TlsQuicProxyError.MasqueAuthenticationRejected does not exist on this branch yet (it
        // lands with the MASQUE transport, on another lane). Until then this only pins that the
        // failure surfaces as a named proxy exception, not any particular reason.
        // TODO(masque): assert Error == MasqueAuthenticationRejected once the enum member merges
        Assert.IsType<TlsQuicProxyException>(cursor);
    }
}
