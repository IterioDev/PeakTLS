using SharpTls;
using System.Net;

namespace TlsClient;

/// <summary>A named SharpTls ClientHello profile used by an HTTP session.</summary>
public sealed class TlsProfile
{
    private readonly Lazy<ClientHelloProfile> _http11Profile;
    private readonly Lazy<ClientHelloProfile> _http11IpProfile;
    private readonly Lazy<ClientHelloProfile> _http2Profile;
    private readonly Lazy<ClientHelloProfile> _http2IpProfile;
    private readonly Lazy<ClientHelloProfile> _http2OnlyProfile;
    private readonly Lazy<ClientHelloProfile> _http2OnlyIpProfile;
    private readonly Lazy<ClientHelloProfile> _http3OnlyProfile;
    private readonly Lazy<ClientHelloProfile> _http3OnlyIpProfile;

    private TlsProfile(
        string name,
        ClientHelloProfile clientHello,
        string sharpTlsProfileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(clientHello);
        Name = name;
        ClientHello = clientHello;
        SharpTlsProfileName = sharpTlsProfileName;
        _http11Profile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: true, "http/1.1"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        _http11IpProfile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: false, "http/1.1"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        _http2Profile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: true, "h2", "http/1.1"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        _http2IpProfile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: false, "h2", "http/1.1"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        _http2OnlyProfile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: true, "h2"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        _http2OnlyIpProfile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: false, "h2"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        // "h3" is offered on its own and never alongside "h2"/"http/1.1": the QUIC and TCP
        // transports are separate dials, so a mixed list could only serve a fallback that
        // TlsClient deliberately does not implement.
        _http3OnlyProfile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: true, "h3"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        _http3OnlyIpProfile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: false, "h3"),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <summary>Gets the stable display name.</summary>
    public string Name { get; }

    /// <summary>Gets the original, unmodified SharpTls profile.</summary>
    public ClientHelloProfile ClientHello { get; }

    /// <summary>Gets the SharpTls built-in property name, or "custom".</summary>
    public string SharpTlsProfileName { get; }

    /// <summary>Wraps any SharpTls profile with a diagnostic name.</summary>
    public static TlsProfile Create(string name, ClientHelloProfile clientHello) =>
        new(name, clientHello, "custom");

    internal static TlsProfile CreateBuiltIn(
        string name,
        string sharpTlsProfileName,
        ClientHelloProfile clientHello) => new(name, clientHello, sharpTlsProfileName);

    /// <inheritdoc />
    public override string ToString() => Name;

    internal ClientHelloProfile Http11ClientHello => _http11Profile.Value;

    internal ClientHelloProfile GetHttp11ClientHello(string host) =>
        IPAddress.TryParse(host, out _) ? _http11IpProfile.Value : _http11Profile.Value;

    internal ClientHelloProfile GetClientHello(string host, TlsHttpVersionPolicy policy)
    {
        var ipAddress = IPAddress.TryParse(host, out _);
#pragma warning disable TLSCLIENT3 // HTTP/3 is experimental; the policy switch must still route it.
        return policy switch
        {
            TlsHttpVersionPolicy.Http11Only =>
                ipAddress ? _http11IpProfile.Value : _http11Profile.Value,
            TlsHttpVersionPolicy.Http2Only =>
                ipAddress ? _http2OnlyIpProfile.Value : _http2OnlyProfile.Value,
            TlsHttpVersionPolicy.Http3Only =>
                ipAddress ? _http3OnlyIpProfile.Value : _http3OnlyProfile.Value,
            _ => ipAddress ? _http2IpProfile.Value : _http2Profile.Value,
        };
#pragma warning restore TLSCLIENT3
    }
}

/// <summary>Curated browser-family profiles backed directly by SharpTls.</summary>
public static class TlsProfiles
{
    /// <summary>Gets SharpTls's conservative modern TLS 1.3 profile.</summary>
    public static TlsProfile Modern { get; } =
        TlsProfile.CreateBuiltIn(
            "modern-tls13",
            nameof(ClientHelloProfiles.ModernTls13),
            ClientHelloProfiles.ModernTls13);

    /// <summary>
    /// Gets the passively-captured Spotify 9.1.76.2050 on iOS 27.0 (iPhone17,2) QUIC profile.
    /// Unlike the other built-ins this is not a uTLS transcription: it is decoded from the
    /// Initial CRYPTO frames of 80 first-party captured connections.
    /// <para>QUIC only. Over h3 this is NOT what drives the ClientHello — RFC 9001 §8.4 gives
    /// QUIC its own, configured through <see cref="TlsQuicOptions.ConfigureClientHello"/>,
    /// which <c>TlsPresets.Spotify</c> wires to the same shape. This profile exists so the
    /// preset's <see cref="TlsPreset.Profile"/> names the client it impersonates rather than
    /// an unrelated browser.</para>
    /// </summary>
    public static TlsProfile Spotify917602050IOS270Quic { get; } =
        TlsProfile.CreateBuiltIn(
            "spotify-9.1.76-ios-27.0-quic",
            nameof(ClientHelloProfiles.Spotify917602050IOS270Quic),
            ClientHelloProfiles.Spotify917602050IOS270Quic);

    /// <summary>
    /// Gets the TCP ClientHello of the same Spotify 9.1.76.2050 iOS build — the hello its
    /// HTTP/2 legs dial with, paired with <see cref="TlsPresets.SpotifyH2"/>.
    /// </summary>
    /// <remarks>Transcribed from a supplied fingerprint record rather than decoded from a
    /// first-party capture, unlike <see cref="Spotify917602050IOS270Quic"/>. Thirteen cipher
    /// suites to that one's three, and a different extension set; the two are not derivable
    /// from each other.</remarks>
    public static TlsProfile Spotify917602050IOS270Tcp { get; } =
        TlsProfile.CreateBuiltIn(
            "spotify-9.1.76-ios-27.0-tcp",
            nameof(ClientHelloProfiles.Spotify917602050IOS270Tcp),
            ClientHelloProfiles.Spotify917602050IOS270Tcp);

    /// <summary>Gets every built-in TlsClient profile in stable name order.</summary>
    /// <remarks>THREE ENTRIES, AND THAT IS THE WHOLE CATALOGUE - one honest shape and the two
    /// halves of one client. The browser transcriptions - Chrome, Firefox, Edge, Safari, iOS,
    /// Android and their pinned versions - were removed along with the uTLS profiles they were
    /// built on. <see cref="Modern"/> is not an impersonation: it is SharpTls's conservative
    /// TLS 1.3 shape and exists so <c>TlsSessionOptions.Profile</c> has a default that
    /// negotiates rather than imitates. Anything else you want to look like comes from a
    /// capture, through <c>ClientHelloProfiles.Custom</c>.</remarks>
    public static IReadOnlyList<TlsProfile> All { get; } = Array.AsReadOnly(
        new TlsProfile[]
        {
            Modern,
            Spotify917602050IOS270Quic,
            Spotify917602050IOS270Tcp,
        });
}
