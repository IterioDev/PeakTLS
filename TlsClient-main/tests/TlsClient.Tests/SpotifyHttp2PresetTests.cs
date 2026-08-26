namespace TlsClient.Tests;

using SharpTls;

/// <summary>
/// The HTTP/2 half of the Spotify iOS client, pinned against the fingerprint record it was
/// transcribed from. Every value here is one a later tidy-up could plausibly "normalise" —
/// sort the SETTINGS, drop the one with no name, collapse the duplicate signature algorithm —
/// and every one of those would move the fingerprint silently.
/// </summary>
public sealed class SpotifyHttp2PresetTests
{
    /// <summary>
    /// The record's JA3, GREASE REMOVED. <see cref="TlsFingerprintDiagnostics"/> normalises
    /// GREASE out of its JA3 string on purpose — its own tests assert a plain hello and a
    /// GREASE'd one hash alike — so the four <c>2570</c> entries the record carries cannot
    /// appear here. Their placement is asserted separately below, against the wire lists.
    /// </summary>
    private const string ExpectedJa3 =
        "771,4866-4865-4867-49196-49200-49195-52393-49199-52392-49162-49161-49172-49171," +
        "0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0";

    private static TlsClientHelloFingerprint Inspect() =>
        TlsFingerprintDiagnostics.InspectHandshake(
            TlsClientHello.BuildSnapshotForTesting(
                TlsProfiles.Spotify917602050IOS270Tcp,
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
    /// GREASE placement, which the JA3 string above cannot carry. The record shows one slot in
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
    /// The preface is a SCRIPT: a SETTINGS frame whose seven identifiers are in the recorded
    /// order, then the connection WINDOW_UPDATE. Identifier 0x8 is RFC 8441
    /// ENABLE_CONNECT_PROTOCOL, sent explicitly as 0 — declining extended CONNECT by statement
    /// rather than by omission, which is itself a distinguisher.
    /// </summary>
    [Fact]
    public void ThePrefaceCarriesTheRecordedSettingsInOrderThenTheWindowUpdate()
    {
        var options = TlsPresets.SpotifyH2.CreateOptions();

        var settings = Assert.IsType<TlsHttp2SettingsFrame>(options.Http2.Preface[0]);
        Assert.Equal(
            "0x1=4096, 0x2=0, 0x3=100, 0x4=2097152, 0x5=16384, 0x6=4294967295, 0x8=0",
            string.Join(", ", settings.Settings.Select(s => $"0x{s.Id:X}={s.Value}")));

        var window = Assert.IsType<TlsHttp2WindowUpdateFrame>(options.Http2.Preface[1]);
        Assert.Equal(15_663_105u, window.Increment);
        Assert.Equal(2, options.Http2.Preface.Count);
    }

    /// <summary>
    /// m, s, p, a — NOT the m, a, s, p its own QUIC half sends. RFC 9113 section 8.3 fixes no
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
        Assert.Same(TlsProfiles.Spotify917602050IOS270Tcp, options.Profile);
    }

    [Fact]
    public void TheAliasPointsAtTheCurrentPinnedVersion() =>
        Assert.Same(TlsPresets.Spotify917602050IOS270Http2, TlsPresets.SpotifyH2);

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
                TlsProfiles.Spotify917602050IOS270Quic,
                "example.com",
                new byte[32]).GetEncodedHandshake());

        Assert.NotEqual(quic.Ja3String, tcp.Ja3String);
        Assert.Equal(13, tcp.CipherSuites.Count(value => !IsGrease(value)));
        Assert.Equal(3, quic.CipherSuites.Count(value => !IsGrease(value)));
    }
}
