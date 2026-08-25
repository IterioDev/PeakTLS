namespace TlsClient.Tests;

/// <summary>
/// HTTP/3 against BoringSSL peers, which are stricter than the h3 endpoint
/// <see cref="Http3LiveTests"/> uses.
/// </summary>
/// <remarks>
/// THIS FILE EXISTS BECAUSE ITS ABSENCE COST A RELEASE. Every QUIC ClientHello carried a
/// 32-byte legacy_session_id, which RFC 9001 s8.4 forbids: QUIC has no TLS compatibility mode.
/// Google, Cloudflare and every Spotify host answered CRYPTO_ERROR with alert 47
/// (illegal_parameter) before a single request. The offline suite could not see it - the bytes
/// were well-formed - and the one live h3 test pointed at a lenient peer that accepted them.
/// A strict peer is the only thing that catches a rule like this.
/// <para>Requires network access; skipped unless <c>TLSCLIENT_LIVE_TESTS=1</c>.</para>
/// </remarks>
public sealed class Http3BoringSslInteropTests
{
    private static bool Enabled => Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_TESTS") == "1";

#pragma warning disable TLSCLIENT3
    [Theory]
    [InlineData("www.google.com")]
    [InlineData("cloudflare-quic.com")]
    public async Task TheDefaultQuicHelloIsAcceptedByABoringSslPeer(string host)
    {
        if (!Enabled) { return; }

        // Library defaults, no persona: the rule under test is QUIC's, so a preset must not be
        // what makes it pass.
        var options = new TlsSessionOptions
        {
            HttpVersionPolicy = TlsHttpVersionPolicy.Http3Only,
            Timeout = TimeSpan.FromSeconds(30),
        };
        await using var session = new TlsSession(options);

        var response = await session.GetAsync($"https://{host}/");

        Assert.Equal("3", response.HttpVersion.ToString().Split('.')[0]);
        Assert.True((int)response.StatusCode < 400, $"{host} answered {(int)response.StatusCode}");
    }

    [Fact]
    public async Task TheSpotifyPresetIsAcceptedByTheHostsItImpersonatesTraffic()
    {
        if (!Enabled) { return; }

        // A 404 is a PASS here. These are API hosts and the path is "/": what is under test is
        // that the QUIC handshake completes and an HTTP/3 response comes back at all.
        foreach (var host in new[] { "gew1-spclient.spotify.com", "login5.spotify.com" })
        {
            var options = TlsPresets.Spotify.CreateOptions();
            options.Timeout = TimeSpan.FromSeconds(30);
            await using var session = new TlsSession(options);

            var request = new HttpRequestMessage(HttpMethod.Get, $"https://{host}/");
            request.AddHeader("accept", "*/*");
            var response = await session.SendAsync(request);

            Assert.Equal("3", response.HttpVersion.ToString().Split('.')[0]);
        }
    }
#pragma warning restore TLSCLIENT3
}
