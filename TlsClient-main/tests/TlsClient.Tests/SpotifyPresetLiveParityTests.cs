using System.Globalization;
using System.Net;
using System.Text.Json;

namespace TlsClient.Tests;

/// <summary>
/// The Spotify iOS 27 HTTP/3 preset, dialled for real against <c>fp.impersonate.pro/api/http3</c>
/// and read back through that server's eyes, field by field against the 2026-09-26 capture of
/// the handset (docs/superpowers/specs/reference-captures/2026-09-26-spotify-9.1.86-ios27-pcapng.md
/// in SharpTls).
/// </summary>
/// <remarks>
/// <para>Requires network access and is skipped unless <c>TLSCLIENT_LIVE_TESTS=1</c>, like the
/// other live tests. Everything here is ALSO pinned offline — the hello bytes in SharpTls's
/// SpotifyIosQuicCaptureParityTests, the SETTINGS and pseudo-header order in TlsPresetTests —
/// so this file adds one thing: the server's reading of the whole flight, which is what a
/// fingerprinting endpoint on the other side of the internet will compute.</para>
/// <para>WHAT THE ENDPOINT CANNOT SEE, AND THIS TEST THEREFORE CANNOT PROVE. It reports the
/// ClientHello, the transport parameters, the SETTINGS and the request header names and
/// order. It reports nothing about the QPACK encoder — whether the dynamic table was used,
/// what was inserted — so the known gap there (the phone inserts, this client does not)
/// passes through this test unseen. A green run means "the fingerprint the server publishes
/// matches", not "the wire is identical".</para>
/// <para>GREASE VALUES ARE NONCES; THEIR EQUALITY PATTERN IS NOT. Which 0x?a?a value a slot
/// draws is redrawn per connection on the phone and here, so no literal is asserted. That
/// supported_groups and key_share draw the SAME value while every other slot draws its own is a
/// class pattern the phone shows in 14 of 14 exactly-listed hellos and 80 of 80 QUIC ones, so
/// that is asserted.</para>
/// <para>THE TRANSPORT-PARAMETER ORDER IS ONE OF SEVEN, NOT ONE. The phone ships a cyclic
/// rotation of the seven known parameters, redrawn per connection, with the vendor entry pinned
/// last; the preset does the same. The assertion therefore accepts any rotation and rejects a
/// shuffle, a fixed order that is not a rotation, or the vendor entry anywhere but last.</para>
/// </remarks>
public sealed class SpotifyPresetLiveParityTests
{
    private const string Endpoint = "https://fp.impersonate.pro/api/http3";

    /// <summary>The handset's JA3 over QUIC, as the capture and the endpoint both compute it.</summary>
    private const string CapturedJa3Hash = "48d08f334704479db85d91df80039756";

    /// <summary>The seven known transport parameters in the rotation base order.</summary>
    private static readonly string[] RotationBase = ["4", "5", "6", "7", "9", "14", "15"];

    private static bool Enabled =>
        Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_TESTS") == "1";

    private static bool IsGrease(int value) =>
        (value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xFF);

    /// <summary>The 9.1.86 spclient GET image without the per-account credentials: the same
    /// sequence samples/TlsClient.SpotifyIos26/Program.cs adds, and USAGE.md section 3c shows.</summary>
    private static HttpRequestMessage NewRequest()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, Endpoint);
        request.AddHeader("spotify-app-version", "9.1.86.2428");
        request.AddHeader("accept", "*/*");
        request.AddHeader("time-zone", "Europe/Athens");
        request.AddHeader("app-platform", "iOS");
        request.AddHeader("priority", "u=3, i");
        request.AddHeader("accept-language", "en-GB,en;q=0.9");
        request.AddHeader("accept-encoding", "gzip, deflate, br");
        request.AddHeader("user-agent", "Spotify/9.1.86 iOS/27.0 (iPhone17,2)");
        return request;
    }

    /// <summary>The second and third requests on one connection are where the QPACK dynamic
    /// table does its work: the capacity has been announced, pairs are inserted on their second
    /// use, and the sections reference them. Only a real decoder can say those bytes were right,
    /// and one request per connection, which the other facts here use, never inserts.</summary>
    [Fact]
    public async Task ThreeRequestsOnOneConnectionAllDecodeAtTheServer()
    {
        if (!Enabled)
        {
            return;
        }

        var options = TlsPresets.Spotify.CreateOptions();
        options.Timeout = TimeSpan.FromSeconds(30);
        await using var session = new TlsSession(options);

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var response = await session.SendAsync(NewRequest());

            Assert.Equal(HttpVersion.Version30, response.HttpVersion);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var document = JsonDocument.Parse(response.Text);
            Assert.Equal(
                CapturedJa3Hash,
                document.RootElement.GetProperty("tls").GetProperty("ja3").GetProperty("hash").GetString());
        }
    }

    private static async Task<JsonDocument> DialAsync()
    {
        var options = TlsPresets.Spotify.CreateOptions();
        options.Timeout = TimeSpan.FromSeconds(30);
        await using var session = new TlsSession(options);

        var request = NewRequest();

        var response = await session.SendAsync(request);

        Assert.Equal(HttpVersion.Version30, response.HttpVersion);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(response.Text);
    }

    [Fact]
    public async Task TheEndpointSeesTheHandsetsHelloSettingsTransportParametersAndHeaderOrder()
    {
        if (!Enabled)
        {
            return;
        }

        using var document = await DialAsync();
        var root = document.RootElement;
        var tls = root.GetProperty("tls");
        var http3 = root.GetProperty("http3");

        // TLS: the hash the phone produces, and the lists behind it.
        Assert.Equal(CapturedJa3Hash, tls.GetProperty("ja3").GetProperty("hash").GetString());
        Assert.Equal(
            "771,4866-4867-4865,0-10-16-5-13-18-51-45-43-57-27,4588-29-23-24-25,",
            tls.GetProperty("ja3").GetProperty("text").GetString());

        var ciphers = tls.GetProperty("cipher_suites").EnumerateArray()
            .Select(c => c.GetProperty("value").GetInt32()).ToArray();
        Assert.Equal(4, ciphers.Length);
        Assert.True(IsGrease(ciphers[0]), "the cipher list leads with a GREASE value");
        Assert.Equal([0x1302, 0x1303, 0x1301], ciphers[1..]);

        var extensions = tls.GetProperty("extensions").EnumerateArray().ToArray();
        var extensionIds = extensions.Select(e => e.GetProperty("id").GetInt32()).ToArray();
        Assert.Equal(13, extensionIds.Length);
        Assert.True(IsGrease(extensionIds[0]) && IsGrease(extensionIds[^1]), "GREASE brackets the extensions");
        Assert.Equal([0, 10, 16, 5, 13, 18, 51, 45, 43, 57, 27], extensionIds[1..^1]);

        JsonElement Extension(int id) => extensions.Single(e => e.GetProperty("id").GetInt32() == id);

        var groups = Extension(10).GetProperty("data").GetProperty("groups").EnumerateArray()
            .Select(g => g.GetProperty("value").GetInt32()).ToArray();
        Assert.True(IsGrease(groups[0]), "supported_groups leads with a GREASE value");
        Assert.Equal([4588, 29, 23, 24, 25], groups[1..]);

        var shares = Extension(51).GetProperty("data").GetProperty("shares").EnumerateArray().ToArray();
        var shareGroups = shares.Select(s => s.GetProperty("group").GetProperty("value").GetInt32()).ToArray();
        var shareLengths = shares.Select(s => s.GetProperty("key_length").GetInt32()).ToArray();
        Assert.Equal(groups[0], shareGroups[0]);            // the class pattern: one value, two slots
        Assert.Equal([4588, 29], shareGroups[1..]);
        Assert.Equal([1, 1216, 32], shareLengths);

        var versions = Extension(43).GetProperty("data").EnumerateArray()
            .Select(v => v.GetProperty("value").GetInt32()).ToArray();
        Assert.Equal(2, versions.Length);
        Assert.True(IsGrease(versions[0]), "supported_versions leads with a GREASE value");
        Assert.Equal(0x0304, versions[1]);

        var algorithms = Extension(13).GetProperty("data").GetProperty("algorithms").EnumerateArray()
            .Select(a => a.GetProperty("value").GetInt32()).ToArray();
        Assert.Equal(
            [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
            algorithms);

        Assert.Equal("020001", Extension(27).GetProperty("data").GetProperty("raw").GetString());

        // Every GREASE slot other than the groups/key_share pair draws independently; asserting
        // they are all DIFFERENT would fail one run in 16 or so per pair, so only the pair is
        // pinned. The values themselves are nonces and are not compared to the capture.

        // QUIC: transport parameters in a cyclic rotation of the seven, vendor entry last.
        var parameters = Extension(57).GetProperty("data").EnumerateArray()
            .Select(p => p.GetProperty("id").GetInt64()).ToArray();
        Assert.Equal(8, parameters.Length);
        Assert.Equal(4278716424L, parameters[^1]);
        var rotation = parameters[..^1].Select(p => p.ToString(CultureInfo.InvariantCulture)).ToArray();
        var offset = Array.IndexOf(RotationBase, rotation[0]);
        Assert.True(offset >= 0, $"unknown leading parameter {rotation[0]}");
        Assert.Equal(
            RotationBase.Skip(offset).Concat(RotationBase.Take(offset)).ToArray(),
            rotation);

        // HTTP/3: the perk segments the endpoint hashes.
        var perk = http3.GetProperty("perk_text").GetString()!.Split('|');
        Assert.Equal(4, perk.Length);
        Assert.Equal("1:16383;7:100;GREASE", perk[0]);
        Assert.Equal("m,s,a,p", perk[1]);
        Assert.Equal("0,8", perk[3]);

        var settings = http3.GetProperty("settings").EnumerateArray().ToArray();
        Assert.Equal(3, settings.Length);
        Assert.Equal(16383, settings[0].GetProperty("value").GetInt64());
        Assert.Equal(100, settings[1].GetProperty("value").GetInt64());
        var reservedId = settings[2].GetProperty("id").GetInt64();
        Assert.Equal(0, (reservedId - 0x21) % 0x1f);
        Assert.InRange((reservedId - 0x21) / 0x1f, 0, uint.MaxValue);
        Assert.InRange(settings[2].GetProperty("value").GetInt64(), 0, uint.MaxValue);

        // The request image: insertion order is wire order, pseudo-headers first in m,s,a,p.
        Assert.Equal(
            [
                ":method", ":scheme", ":authority", ":path",
                "spotify-app-version", "accept", "time-zone", "app-platform", "priority",
                "accept-language", "accept-encoding", "user-agent",
            ],
            http3.GetProperty("header_order").EnumerateArray().Select(h => h.GetString()!).ToArray());

        var quic = root.GetProperty("quic");
        Assert.Equal(0, quic.GetProperty("client_connection_id_length").GetInt32());
        Assert.Equal(8, quic.GetProperty("server_connection_id_length").GetInt32());
    }

    /// <summary>
    /// The HTTP/2 half, read back by <c>tls3.peet.ws/api/all</c>: the TCP hello's JA3 and the
    /// Akamai-style h2 fingerprint — SETTINGS in wire order, WINDOW_UPDATE increment, PRIORITY
    /// count, pseudo-header order — against the 2026-09-26 capture's h2 connections.
    /// </summary>
    /// <remarks>peet.ws rather than fp.impersonate.pro because only peet publishes the h2
    /// frame image. Its JA3 omits GREASE, so the expected string is the capture's with the
    /// GREASE entries removed.</remarks>
    [Fact]
    public async Task TheEndpointSeesTheHandsetsTcpHelloAndHttp2Preface()
    {
        if (!Enabled)
        {
            return;
        }

        var options = TlsPresets.SpotifyH2.CreateOptions();
        options.Timeout = TimeSpan.FromSeconds(30);
        await using var session = new TlsSession(options);

        // The gew1-spclient GET image of the capture, credentials left out.
        var request = new HttpRequestMessage(HttpMethod.Get, "https://tls3.peet.ws/api/all");
        request.AddHeader("spotify-app-version", "9.1.86.2428");
        request.AddHeader("accept", "*/*");
        request.AddHeader("time-zone", "Europe/Athens");
        request.AddHeader("app-platform", "iOS");
        request.AddHeader("priority", "u=3, i");
        request.AddHeader("accept-language", "en-GB,en;q=0.9");
        request.AddHeader("accept-encoding", "gzip, deflate, br");
        request.AddHeader("user-agent", "Spotify/9.1.86 iOS/27.0 (iPhone17,2)");

        var response = await session.SendAsync(request);
        Assert.Equal(HttpVersion.Version20, response.HttpVersion);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var document = JsonDocument.Parse(response.Text);
        var root = document.RootElement;
        Assert.Equal("h2", root.GetProperty("http_version").GetString());

        Assert.Equal(
            "771,4866-4867-4865-49196-49200-49195-52393-49199-52392-49162-49161-49172-49171,"
            + "0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0",
            root.GetProperty("tls").GetProperty("ja3").GetString());

        var http2 = root.GetProperty("http2");
        Assert.Equal(
            "2:0;4:2097152;3:100;9:1|10485760|0|m,s,p,a",
            http2.GetProperty("akamai_fingerprint").GetString());

        var frameTypes = http2.GetProperty("sent_frames").EnumerateArray()
            .Select(f => f.GetProperty("frame_type").GetString()!).ToArray();
        Assert.Equal(["SETTINGS", "WINDOW_UPDATE", "HEADERS"], frameTypes);
    }
}
