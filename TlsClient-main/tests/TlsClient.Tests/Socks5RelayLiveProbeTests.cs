using System.Net;
using System.Text.Json;
using Xunit.Abstractions;

namespace TlsClient.Tests;

/// <summary>
/// Dials through a real SOCKS5 proxy and reports what each path does, so a provider's UDP
/// ASSOCIATE can be judged on the wire rather than on its brochure. Runs only when
/// <c>TLSCLIENT_LIVE_SOCKS5</c> holds a <c>socks5://user:pass@host:port</c> URL; the credential
/// never lives in this repository.
/// </summary>
public sealed class Socks5RelayLiveProbeTests(ITestOutputHelper output)
{
    private static string? ProxyUrl => Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_SOCKS5");

    [Theory]
    [InlineData("h3", "https://fp.impersonate.pro/api/http3")]
    [InlineData("h3", "https://spclient.wg.spotify.com/")]
    [InlineData("h2", "https://spclient.wg.spotify.com/")]
    [InlineData("h2", "https://tls3.peet.ws/api/all")]
    public async Task ReportWhatTheRelayDoes(string protocol, string url)
    {
        if (ProxyUrl is not { } proxyUrl)
        {
            return;
        }

        var proxy = new Uri(proxyUrl);
        var credentials = proxy.UserInfo.Split(':', 2);
        var preset = protocol == "h3" ? TlsPresets.Spotify : TlsPresets.SpotifyH2;
        var options = preset.CreateOptions();
        options.Timeout = TimeSpan.FromSeconds(30);
        options.Proxy = TlsProxy.Socks5(
            $"socks5://{proxy.Host}:{proxy.Port}",
            Uri.UnescapeDataString(credentials[0]),
            Uri.UnescapeDataString(credentials[1]));
        await using var session = new TlsSession(options);

        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.AddHeader("spotify-app-version", "9.1.86.2428");
        request.AddHeader("accept", "*/*");
        request.AddHeader("user-agent", "Spotify/9.1.86 iOS/27.0 (iPhone17,2)");

        var started = DateTime.UtcNow;
        try
        {
            var response = await session.SendAsync(request);
            var body = response.Text.Length > 160 ? response.Text[..160] : response.Text;
            output.WriteLine(
                $"PROBE {protocol} {url}: {response.HttpVersion} {(int)response.StatusCode} "
                + $"in {(DateTime.UtcNow - started).TotalMilliseconds:F0} ms; body: {body.ReplaceLineEndings(" ")}");
        }
        catch (Exception exception)
        {
            var chain = new List<string>();
            for (var e = exception; e is not null; e = e.InnerException)
            {
                var message = e.Message.Length > 400 ? e.Message[..400] : e.Message;
                chain.Add($"{e.GetType().Name}: {message.ReplaceLineEndings(" ")}");
            }
            output.WriteLine(
                $"PROBE {protocol} {url}: FAILED in {(DateTime.UtcNow - started).TotalMilliseconds:F0} ms; "
                + string.Join(" <- ", chain));
        }
    }
}
