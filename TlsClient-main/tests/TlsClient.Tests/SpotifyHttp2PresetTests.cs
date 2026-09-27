namespace TlsClient.Tests;

using SharpTls;

/// <summary>
/// The HTTP/2 half of the Spotify iOS client. The TLS half is pinned against the first-party
/// pcapng capture of 2026-09-26 (Spotify 9.1.86.2428, iOS 27.0, 53 TCP hellos); the HTTP/2
/// preface is still pinned against the fingerprint record it was transcribed from. Every value
/// here is one a later tidy-up could plausibly "normalise" — sort the SETTINGS, drop the one
/// with no name, collapse the duplicate signature algorithm — and every one of those would
/// move the fingerprint silently.
/// </summary>
public sealed class SpotifyHttp2PresetTests
{
    /// <summary>
    /// The capture's JA3, GREASE REMOVED. <see cref="TlsFingerprintDiagnostics"/> normalises
    /// GREASE out of its JA3 string on purpose — its own tests assert a plain hello and a
    /// GREASE'd one hash alike — so the GREASE entries the capture carries cannot appear here.
    /// Their placement is asserted separately below, against the wire lists.
    /// <para>The TLS 1.3 trio is <c>0x1302, 0x1303, 0x1301</c> — the same order the QUIC hello
    /// carries. The transcribed record had <c>0x1302, 0x1301, 0x1303</c>; all 17 captured
    /// hellos of this shape disagree with it, so the record was wrong on this one axis.</para>
    /// </summary>
    private const string ExpectedJa3 =
        "771,4866-4867-4865-49196-49200-49195-52393-49199-52392-49162-49161-49172-49171," +
        "0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0";

    private static TlsClientHelloFingerprint Inspect() =>
        TlsFingerprintDiagnostics.InspectHandshake(
            TlsClientHello.BuildSnapshotForTesting(
                TlsProfiles.Spotify918602428IOS270Tcp,
                "example.com",
                new byte[32]).GetEncodedHandshake());

    private static bool IsGrease(ushort value) =>
        (value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xFF);

    [Fact]
    public void TheTcpHelloReproducesTheRecordedJa3()
    {
        Assert.Equal(ExpectedJa3, Inspect().Ja3String);
    }

    /// <summary>
    /// GREASE placement, which the JA3 string above cannot carry. The capture shows one slot in
    /// the cipher list, one leading the curves, and two bracketing the extensions. The VALUES
    /// are drawn per connection and are deliberately not asserted — pinning one would be
    /// pinning a nonce.
    /// </summary>
    [Fact]
    public void TheTcpHelloCarriesGreaseInEverySlotTheRecordShows()
    {
        var print = Inspect();

        Assert.Single(print.CipherSuites, IsGrease);
        Assert.Single(print.SupportedGroups, IsGrease);
        Assert.Equal(2, print.ExtensionTypes.Count(IsGrease));
    }

    [Fact]
    public void TheTcpHelloOffersHttp2ThenHttp11()
    {
        Assert.Equal(["h2", "http/1.1"], Inspect().AlpnProtocols);
    }

    /// <summary>
    /// The preface is a SCRIPT: a SETTINGS frame whose four identifiers are in the captured
    /// order — 0x4 before 0x3, so a sort would move the fingerprint — then the connection
    /// WINDOW_UPDATE. Identifier 0x9 is RFC 9218 SETTINGS_NO_RFC7540_PRIORITIES = 1. Measured in
    /// 10 of 10 decrypted h2 connections of the 2026-09-26 capture; the transcribed record's
    /// seven settings and 15663105 increment were wrong.
    /// </summary>
    [Fact]
    public void ThePrefaceCarriesTheCapturedSettingsInOrderThenTheWindowUpdate()
    {
        var options = TlsPresets.SpotifyH2.CreateOptions();

        var settings = Assert.IsType<TlsHttp2SettingsFrame>(options.Http2.Preface[0]);
        Assert.Equal(
            "0x2=0, 0x4=2097152, 0x3=100, 0x9=1",
            string.Join(", ", settings.Settings.Select(s => $"0x{s.Id:X}={s.Value}")));

        var window = Assert.IsType<TlsHttp2WindowUpdateFrame>(options.Http2.Preface[1]);
        Assert.Equal(10_485_760u, window.Increment);
        Assert.Equal(2, options.Http2.Preface.Count);
    }

    /// <summary>
    /// The HPACK policy the capture shows: incremental indexing by default; <c>:path</c>,
    /// <c>content-length</c> and <c>if-none-match</c> literal without indexing;
    /// <c>authorization</c> never indexed. A tidy-up that indexed everything, or nothing,
    /// would move every request's bytes.
    /// </summary>
    [Fact]
    public void TheHpackPolicyLeavesPathAndContentLengthOutOfTheTableAndNeverIndexesAuthorization()
    {
        var hpack = TlsPresets.SpotifyH2.CreateOptions().Http2.Hpack;

        Assert.Equal(TlsHpackRepresentation.Indexed, hpack.DefaultRepresentation);
        Assert.Equal(TlsHpackRepresentation.LiteralIncrementalIndexing, hpack.IndexedFallback);
        Assert.True(hpack.UseDynamicTable);
        Assert.Equal(TlsHpackRepresentation.LiteralWithoutIndexing, hpack.PerHeader[":path"]);
        Assert.Equal(TlsHpackRepresentation.LiteralWithoutIndexing, hpack.PerHeader["content-length"]);
        Assert.Equal(TlsHpackRepresentation.LiteralWithoutIndexing, hpack.PerHeader["if-none-match"]);
        Assert.Equal(TlsHpackRepresentation.LiteralNeverIndexed, hpack.PerHeader["authorization"]);
    }

    /// <summary>
    /// m, s, p, a — NOT the m, s, a, p its own QUIC half sends. RFC 9113 section 8.3 fixes no
    /// order among the pseudo-headers, so the two halves of one client genuinely differ and
    /// neither may be derived from the other.
    /// </summary>
    [Fact]
    public void ThePseudoHeaderOrderIsTheHttp2OneAndNotTheHttp3One()
    {
        Assert.Equal(
            [":method", ":scheme", ":path", ":authority"],
            TlsPresets.SpotifyH2.CreateOptions().Http2.PseudoHeaderOrder);
    }

    /// <summary>
    /// PreferHttp2 rather than Http2Only, because the hello itself offers http/1.1 after h2.
    /// Pinning h2 would misrepresent a client that accepts the fallback.
    /// </summary>
    [Fact]
    public void ThePresetPrefersHttp2RatherThanPinningIt()
    {
        var options = TlsPresets.SpotifyH2.CreateOptions();

        Assert.Equal(TlsHttpVersionPolicy.PreferHttp2, options.HttpVersionPolicy);
        Assert.Same(TlsProfiles.Spotify918602428IOS270Tcp, options.Profile);
    }

    [Fact]
    public void TheAliasPointsAtTheCurrentPinnedVersion() =>
        Assert.Same(TlsPresets.Spotify918602428IOS270Http2, TlsPresets.SpotifyH2);

    /// <summary>
    /// The two halves of one client are two different hellos, and the catalogue says so. Three
    /// cipher suites over QUIC to thirteen over TCP is the cheapest witness that nothing
    /// derived one from the other.
    /// </summary>
    [Fact]
    public void TheTcpAndQuicHalvesAreDistinctHellos()
    {
        var tcp = Inspect();
        var quic = TlsFingerprintDiagnostics.InspectHandshake(
            TlsClientHello.BuildSnapshotForTesting(
                TlsProfiles.Spotify918602428IOS270Quic,
                "example.com",
                new byte[32]).GetEncodedHandshake());

        Assert.NotEqual(quic.Ja3String, tcp.Ja3String);
        Assert.Equal(13, tcp.CipherSuites.Count(value => !IsGrease(value)));
        Assert.Equal(3, quic.CipherSuites.Count(value => !IsGrease(value)));
    }
}
