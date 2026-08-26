using System.Security.Cryptography;
using SharpTls;

namespace TlsClient;

/// <summary>
/// A coherent preset pairing a SharpTls ClientHello with HTTP/2 settings, flow control,
/// priorities and pseudo-header order.
/// <para>A preset carries NO headers and no header order. Every field on the wire is one the
/// caller added to the request with <c>AddHeader</c>, in the order they added it. Nothing is
/// sent on the caller's behalf.</para>
/// </summary>
public sealed class TlsPreset
{
    private readonly Action<TlsHttp2Options> _configureHttp2;
    private readonly TlsHttpVersionPolicy _versionPolicy;
    private readonly Action<TlsSessionOptions>? _configureTransport;

    internal TlsPreset(
        string name,
        TlsProfile profile,
        Action<TlsHttp2Options> configureHttp2,
        TlsHttpVersionPolicy versionPolicy = TlsHttpVersionPolicy.PreferHttp2,
        Action<TlsSessionOptions>? configureTransport = null)
    {
        Name = name;
        Profile = profile;
        _configureHttp2 = configureHttp2;
        _versionPolicy = versionPolicy;
        _configureTransport = configureTransport;
    }

    /// <summary>Gets the stable, versioned preset name.</summary>
    public string Name { get; }

    /// <summary>Gets the SharpTls ClientHello profile paired with this preset.</summary>
    public TlsProfile Profile { get; }

    /// <summary>Creates an independent, caller-mutable options object.</summary>
    public TlsSessionOptions CreateOptions() => new(this);

    /// <inheritdoc />
    public override string ToString() => Name;

    internal void ApplyTo(TlsSessionOptions options)
    {
        options.Profile = Profile;
        options.HttpVersionPolicy = _versionPolicy;
        _configureHttp2(options.Http2);

        // An h3 preset's shape lives in options.Quic and options.Http3, neither of which the
        // HTTP/2 hook can reach. A preset that does not speak QUIC leaves this null.
        _configureTransport?.Invoke(options);
    }
}

/// <summary>Versioned TLS and HTTP/2 presets backed by SharpTls profiles.</summary>
public static class TlsPresets
{
    /// <summary>
    /// Gets the passively-captured Spotify 9.1.76.2050 on iOS 27.0 (iPhone17,2) HTTP/3 preset.
    /// Its provenance differs from the other built-ins: it is decoded from the QUIC Initial
    /// CRYPTO frames of 80 first-party captured connections to <c>*.spotify.com</c>, with the
    /// HTTP/3 SETTINGS taken from proxy captures of the same handset. Reproduces the phone's
    /// JA3 <c>48d08f334704479db85d91df80039756</c> and JA4
    /// <c>q13d0311h3_55b375c5d22e_f2a83c8e78ae</c>. A second image hashes to
    /// <c>2f9431e877b01e163774ae4ae0df9ded</c>: a different cipher order that always travels with
    /// the vendor transport parameter absent. JA4 does not distinguish them.
    /// <para>THIS IS AN iOS 27 PRESET AND THE VERSION IN ITS NAME IS LOAD-BEARING. The second
    /// image is what the same app sends on iOS 26 - measured on the same proxy path that produced
    /// the first, which is what rules out the capture path as the explanation. Dialling this
    /// preset while claiming an iOS 26 user agent ships a hello that build does not send. There
    /// is no iOS 26 preset; author one with <see cref="TlsProfiles"/> if you need that shape.</para>
    /// <para>This preset is <see cref="TlsHttpVersionPolicy.Http3Only"/>: the shape it carries
    /// is QUIC's, and applying it to a TCP dial would impersonate nothing. The same app's
    /// HTTP/2 legs are a different ClientHello; over HTTP/2 its <c>login5.spotify.com</c> leg
    /// also uses a different User-Agent, though over HTTP/3 that host carries this same one.</para>
    /// <para>The QUIC and TLS shape here is per-CONNECTION, not per-host or per-endpoint: across
    /// 41 QUIC captures spanning seven hostnames, every cipher, extension, group, signature
    /// algorithm and transport-parameter set was identical, with only the rotation offset and
    /// the GREASE values differing. That is why one preset covers every endpoint, and why there
    /// are no per-endpoint variants of it — those would have differed only in header order, and
    /// header order is the caller's — a field reaches the wire only when
    /// <c>request.AddHeader</c> put it there.</para>
    /// <para>The Authorization and X-Client-Id slots are per-account credentials and are left
    /// empty; set them on the session and they take their captured positions. See
    /// docs/PRESETS.md for what remains unmeasured — every value under
    /// <see cref="TlsQuicOptions.Recovery"/>, and the QPACK encoding choices.</para>
    /// </summary>
#pragma warning disable TLSCLIENT3 // Http3Only: these presets exist to carry a QUIC shape.
    public static TlsPreset Spotify917602050IOS270Http3 { get; } = new(
        "spotify-9.1.76-ios-27.0-h3",
        TlsProfiles.Spotify917602050IOS270Quic,
        static _ => { },

        TlsHttpVersionPolicy.Http3Only,
        ConfigureSpotifyIos270Quic);

    /// <summary>
    /// Gets the same Spotify 9.1.76.2050 client captured on iOS 26 (iPhone17,2) over HTTP/3.
    /// JA3 <c>2f9431e877b01e163774ae4ae0df9ded</c>, JA4
    /// <c>q13d0311h3_55b375c5d22e_f2a83c8e78ae</c>.
    /// </summary>
    /// <remarks>
    /// <para>THE TLS SHAPE IS THE ONLY THING THAT MOVES. Against
    /// <see cref="Spotify917602050IOS270Http3"/>: cipher order 0x1302, 0x1301, 0x1303 and no
    /// vendor <c>0xff080808</c> transport parameter. Every QUIC packet dimension — connection-id
    /// lengths, packet-number length, 1200-byte Initial padding, the 999-byte CRYPTO budget, the
    /// varint widths — and the whole HTTP/3 layer — SETTINGS, the reserved-identifier draw, the
    /// <c>m,s,a,p</c> pseudo-header order — are byte-identical in both captures, so they are
    /// shared code here rather than a second copy.</para>
    /// <para>ONE CAPTURE BEHIND IT, against the other preset's 80 plus 41. The
    /// transport-parameter rotation and the GREASE class pattern are INHERITED from the iOS 27
    /// measurement, not measured here: one hello lands on one of seven rotation offsets whatever
    /// the client does, and cannot separate a GREASE class pattern from coincidence. Everything
    /// under <see cref="TlsQuicOptions.Recovery"/> and the QPACK choices are unmeasured for both.
    /// Pin this against your own captures before trusting those axes.</para>
    /// </remarks>
    public static TlsPreset Spotify917602050IOS260Http3 { get; } = new(
        "spotify-9.1.76-ios-26.0-h3",
        TlsProfiles.Spotify917602050IOS260Quic,
        static _ => { },

        TlsHttpVersionPolicy.Http3Only,
        ConfigureSpotifyIos260Quic);

#pragma warning restore TLSCLIENT3

    /// <summary>
    /// Gets the HTTP/2 half of the same Spotify 9.1.76.2050 iOS 27.0 client: the TCP
    /// ClientHello its h2 legs dial with, plus the HTTP/2 SETTINGS, connection-window
    /// increment and pseudo-header order recorded alongside it.
    /// </summary>
    /// <remarks>
    /// <para>TRANSCRIBED, NOT FIRST-PARTY CAPTURED, which is the opposite of
    /// <see cref="Spotify917602050IOS270Http3"/> and is the distinction docs/PRESETS.md is
    /// organised around. It is read from a fingerprint record supplied in bogdanfinn/tls-client's
    /// JSON format, whose collection method is not recorded. Pin it against your own capture
    /// before trusting it.</para>
    /// <para>PreferHttp2 rather than Http2Only ON PURPOSE: the hello offers
    /// <c>http/1.1</c> after <c>h2</c>, so pinning h2 would misrepresent a client that accepts
    /// the fallback. The app negotiates TLS 1.3 in practice, which matters because the hello
    /// also offers ten TLS 1.2 suites that SharpTls will not complete on - see the profile's
    /// own remarks.</para>
    /// <para>No header order, for the reason every preset here carries none: a field reaches
    /// the wire only when <c>request.AddHeader</c> put it there, in the order it was added.
    /// The captured header images live in docs/USAGE.md.</para>
    /// </remarks>
    public static TlsPreset Spotify917602050IOS270Http2 { get; } = new(
        "spotify-9.1.76-ios-27.0-h2",
        TlsProfiles.Spotify917602050IOS270Tcp,
        ConfigureSpotifyIosHttp2,
        TlsHttpVersionPolicy.PreferHttp2);

    /// <summary>Gets the current SharpTls Spotify-family preset.</summary>
    public static TlsPreset Spotify => Spotify917602050IOS270Http3;

    /// <summary>Gets the current Spotify-family HTTP/2 preset.</summary>
    public static TlsPreset SpotifyH2 => Spotify917602050IOS270Http2;

    /// <summary>Applies the recorded HTTP/2 shape of the Spotify iOS client.</summary>
    private static void ConfigureSpotifyIosHttp2(TlsHttp2Options http2)
    {
        // THE PREFACE IS A SCRIPT AND THE ORDER IS THE FINGERPRINT. These seven settings are in
        // the record's declared order, which is ascending here but is not required to be and is
        // not treated as sortable. Identifier 0x8 is RFC 8441 ENABLE_CONNECT_PROTOCOL; the
        // record calls it UNKNOWN_SETTING_8 because its own table has no name for it, and
        // sending it with value 0 is a real client declining extended CONNECT explicitly rather
        // than by omission - which is itself a distinguisher, so it is kept.
        http2.Preface =
        [
            new TlsHttp2SettingsFrame
            {
                Settings =
                [
                    new TlsHttp2SettingValue(0x1, 4_096),          // HEADER_TABLE_SIZE
                    new TlsHttp2SettingValue(0x2, 0),              // ENABLE_PUSH
                    new TlsHttp2SettingValue(0x3, 100),            // MAX_CONCURRENT_STREAMS
                    new TlsHttp2SettingValue(0x4, 2_097_152),      // INITIAL_WINDOW_SIZE
                    new TlsHttp2SettingValue(0x5, 16_384),         // MAX_FRAME_SIZE
                    new TlsHttp2SettingValue(0x6, uint.MaxValue),  // MAX_HEADER_LIST_SIZE
                    new TlsHttp2SettingValue(0x8, 0),              // ENABLE_CONNECT_PROTOCOL
                ],
            },
            new TlsHttp2WindowUpdateFrame { Increment = 15_663_105 },
        ];

        // m, s, p, a — NOT the m, a, s, p the QUIC half sends. RFC 9113 section 8.3 fixes no
        // order among the pseudo-headers, so the choice is pure fingerprint and the two halves
        // of this client genuinely differ.
        http2.PseudoHeaderOrder = [":method", ":scheme", ":path", ":authority"];
    }

    private static TlsQuicTransportParameterEntry[] SpotifyTransportParameters() =>
    [
        TlsQuicTransportParameterEntry.Placed(0x04),  // initial_max_data
        TlsQuicTransportParameterEntry.Placed(0x05),  // initial_max_stream_data_bidi_local
        TlsQuicTransportParameterEntry.Placed(0x06),  // initial_max_stream_data_bidi_remote
        TlsQuicTransportParameterEntry.Placed(0x07),  // initial_max_stream_data_uni
        TlsQuicTransportParameterEntry.Placed(0x09),  // initial_max_streams_uni
        TlsQuicTransportParameterEntry.Literal(0x0E, [0x40, 0x40]),  // acl = 64
        TlsQuicTransportParameterEntry.Placed(0x0F),  // initial_source_connection_id
    ];

    private static void ConfigureSpotifyIos270Quic(TlsSessionOptions options) =>
        ConfigureSpotifyIosQuic(
            options,
            ClientHelloProfiles.ApplySpotify917602050IOS270QuicClientHello,
            vendorTransportParameter: true);

    private static void ConfigureSpotifyIos260Quic(TlsSessionOptions options) =>
        ConfigureSpotifyIosQuic(
            options,
            ClientHelloProfiles.ApplySpotify917602050IOS260QuicClientHello,
            vendorTransportParameter: false);

    /// <summary>
    /// Applies the measured QUIC and HTTP/3 shape. Values not reachable from any capture we
    /// hold — everything under <c>Quic.Recovery</c> and the QPACK encoding choices — are
    /// deliberately left at their defaults rather than given invented numbers.
    /// <para>ONE METHOD FOR BOTH OS BUILDS. The iOS 26 and iOS 27 captures agree on every
    /// packet dimension, every flow-control value and the whole HTTP/3 layer; they differ in
    /// the ClientHello callback and in whether <c>0xff080808</c> is appended. A second copy of
    /// this method would let the agreeing 90% drift apart silently, which is the failure this
    /// file has already had once.</para>
    /// </summary>
    private static void ConfigureSpotifyIosQuic(
        TlsSessionOptions options,
        Action<ClientHelloBuilder> configureClientHello,
        bool vendorTransportParameter)
    {
        var quic = options.Quic;

        // Packet and datagram shape, identical across all 80 captured connections.
        quic.SourceConnectionIdLength = 0;
        quic.DestinationConnectionIdLength = 8;
        quic.PacketNumberEncodedLength = 1;
        quic.Token = ReadOnlyMemory<byte>.Empty;
        quic.PaddingTarget = 1200;

        // OFF, AND THAT IS A FINGERPRINT DECISION BEFORE IT IS A PATH ONE. RFC 9000 s14.2 makes
        // discovery a SHOULD and offers the same sentence's other half to anyone who declines -
        // "In the absence of these mechanisms, QUIC endpoints SHOULD NOT send datagrams larger
        // than the smallest allowed maximum datagram size" - so both answers conform and this
        // one picks the half that puts nothing extra on the wire. A probe is a PING-and-PADDING
        // datagram at a size nothing else in the flight uses, on a schedule this library
        // invented, and NO CAPTURE IN THIS REPOSITORY RECORDS WHETHER THE IMITATED CLIENT SENDS
        // ONE, at what size, or how often. TlsQuicConnectionSpec.PathMtuDiscovery's own remarks
        // name that cost and say a connection which has to match a capture byte for byte should
        // set this false. This is that connection.
        //
        // THE PATH ARGUMENT AGREES WITH IT RATHER THAN DRIVING IT. Every datagram now stays at
        // BasePathMtu's 1200, which is under every tunnel MTU worth naming - WireGuard 1420,
        // Tailscale 1280, PPPoE 1492 - with room to spare for a SOCKS5 relay's RFC 1928 section
        // 7 header on top. A ceiling ABOVE what the local interface carries is refused by a
        // DF-set socket with WSAEMSGSIZE (10040), and RFC 9000 s14 requires that DF bit, so the
        // only safe ceiling is one no route can undercut. 1200 is the only number with that
        // property, because s14.1 already requires every path to carry it.
        //
        // It costs throughput on a genuine 1500-byte path, and that is the whole cost. The
        // captured Initial datagrams are 1200 either way.
        quic.PathMtuDiscovery = false;

        // INERT WHILE THE LINE ABOVE IS FALSE, and kept rather than deleted so that a caller who
        // turns discovery back on gets a tunnel-safe ceiling instead of the library's 1472 -
        // which is the UDP payload of a 1500-byte Ethernet MTU exactly, and therefore too large
        // for every tunnelled path this preset is usually dialled through.
        quic.MaximumPathMtu = 1392;

        quic.HeaderLengthVarintWidth = TlsQuicVarintWidth.TwoBytes;
        quic.CryptoLengthVarintWidth = TlsQuicVarintWidth.TwoBytes;
        quic.CryptoOffsetVarintWidth = TlsQuicVarintWidth.Minimal;

        // The first Initial CRYPTO frame is exactly 999 bytes in every capture and the second
        // is the remainder — 464 + len(SNI). So 999 is a per-datagram budget whose final
        // element is allowed to run short, not a fixed pair of sizes.
        quic.InitialCryptoFrameByteCounts = [999, 999];
        quic.InitialCryptoFramesPerDatagram = [1, 1];
        quic.CoalesceAscendingByLevel = false;
        quic.AckLeadsInPacket = true;

        quic.FlowControl.InitialMaxData = 16_777_216;
        quic.FlowControl.InitialMaxStreamDataBidiLocal = 2_097_152;
        quic.FlowControl.InitialMaxStreamDataBidiRemote = 2_097_152;
        quic.FlowControl.InitialMaxStreamDataUni = 2_097_152;
        quic.FlowControl.InitialMaxStreamsUni = 8;

        // 91 captured connections produced exactly 7 transport-parameter orders and every one
        // was a cyclic rotation of the sequence above — never a shuffle, which would have
        // drawn from 7! = 5040. A fixed order would match one connection in seven.
        //
        // THE ROTATION IS DECLARED, NOT PERFORMED HERE, and that is the fix rather than a
        // refactor. This block used to draw an offset and rotate the array on the spot, which
        // happens once per OPTIONS OBJECT: every connection in a pooled session then shipped
        // the same order for the session's whole life - one of seven instead of one of one,
        // but still a constant, and a server that sees two connections from this client saw
        // one order twice where the real one shows two. CyclicRotationLength moves the draw
        // into TlsQuicTransportParameterSpec.Compose, which runs once per CONNECTION.
        // The seven known parameters rotate. 0xff080808 does NOT join the rotation: it sits
        // last in 4 of 4 proxy captures regardless of where the rotation started, so it is
        // appended after the rotated block rather than being an eighth rotating element.
        // Its 10 encoded bytes (8-byte varint id + length + one payload byte) are exactly the
        // 487 -> 497 growth measured in the second Initial CRYPTO frame, which is what
        // identified it. iOS 26 does not send it at all, which is why it is a parameter here.
        //
        // THE ROTATION IS INHERITED BY iOS 26, NOT MEASURED THERE. The 91 connections are all
        // iOS 27; the single iOS 26 capture landed on offset 0, which a rotating client produces
        // one time in seven and a fixed-order client produces always. Neither reading is
        // excluded, so the shape that is measured for the family is carried over rather than
        // replaced with a guess in the other direction.
        quic.TransportParameters.Entries = vendorTransportParameter
            ?
            [
                .. SpotifyTransportParameters(),
                TlsQuicTransportParameterEntry.Literal(0xFF08_0808, [0x09]),
            ]
            : [.. SpotifyTransportParameters()];
        quic.TransportParameters.CyclicRotationLength = SpotifyRotatingParameterCount;

        quic.AlpnProtocols = ["h3"];
        quic.ConfigureClientHello = configureClientHello;

        // QPACK_MAX_TABLE_CAPACITY, QPACK_BLOCKED_STREAMS, then one reserved setting — that
        // order in 10 proxy captures out of 10. There is no SETTINGS_MAX_FIELD_SECTION_SIZE:
        // this client omits it, so the default list is replaced rather than extended.
        options.Http3.Settings =
        [
            new TlsHttp3Setting(0x01, 16_383),
            new TlsHttp3Setting(0x07, 100),
            // DRAWN, NOT DRAWN-ONCE. Same fix as the transport-parameter rotation above:
            // calling the draw here would freeze one identifier/value pair onto this options
            // object and ship it on every connection the session makes.
            TlsHttp3Setting.Drawn(DrawReservedHttp3Setting),
        ];

        // MEASURED: control, then qpack_encoder, then qpack_decoder, in 4 of 4 proxy captures
        // carrying 1-RTT. SharpTls ships this same order as a DECLARED PLACEHOLDER, so pinning
        // it here is not redundant: the preset must state a measurement rather than inherit a
        // guess that happened to agree, or a later correction to the library default would
        // silently move this fingerprint.
        options.Http3.UnidirectionalStreamOpenOrder =
        [
            TlsHttp3StreamType.Control,
            TlsHttp3StreamType.QpackEncoder,
            TlsHttp3StreamType.QpackDecoder,
        ];

        // MEASURED: m,s,a,p, not the library default m,a,s,p. RFC 9114 section 4.3 fixes no
        // order among the pseudo-headers, which is exactly why the choice fingerprints. Seen in
        // 41 of 41 proxy captures across two days; a pcapng cannot reach 1-RTT, so the proxy
        // path is the only source for this one.
        options.Http3.PseudoHeaderOrder =
        [
            TlsHttp3PseudoHeader.Method,
            TlsHttp3PseudoHeader.Scheme,
            TlsHttp3PseudoHeader.Authority,
            TlsHttp3PseudoHeader.Path,
        ];
    }

    /// <summary>
    /// Draws the reserved HTTP/3 SETTINGS entry: RFC 9114 §7.2.4.1's <c>0x1f * N + 0x21</c>
    /// with a random N, carrying a random value. Every captured identifier had that form, and
    /// the largest observed N needed 32 bits.
    /// </summary>
    /// <remarks>REDRAWN PER CONNECTION, through <see cref="TlsHttp3Setting.Drawn"/>. An
    /// earlier revision called this method directly in the settings list, which drew once per
    /// options object - and this remark recorded that as a gap
    /// <see cref="TlsHttp3Options.Settings"/> "cannot express: it is a list of literal pairs
    /// with no drawn slot". It has one now.</remarks>
    /// <summary>The number of Spotify transport parameters that rotate; the Google-private
    /// <c>0xff080808</c> entry sits after them and does not.</summary>
    private const int SpotifyRotatingParameterCount = 7;

    private static TlsHttp3Setting DrawReservedHttp3Setting() =>
        new((0x1FUL * DrawWide32()) + 0x21UL, DrawWide32());

    /// <summary>Draws a value spanning the full 32 bits the capture's numbers needed.</summary>
    /// <remarks>
    /// TWO CALLS, NOT ONE DOUBLED. <see cref="RandomNumberGenerator.GetInt32(int)"/> tops out
    /// one short of <see cref="int.MaxValue"/>, so a single call reaches 31 bits and the
    /// doubling widens it to 32 - but the doubling also clears the low bit, and the second
    /// call is what puts it back. Without it the draw is uniform over the EVEN values only,
    /// which is one standing bit of signal in a field whose entire purpose is to carry none.
    /// The identifier had this shape from the start; the VALUE did not, and read
    /// <c>GetInt32(int.MaxValue) * 2</c> - every reserved SETTINGS value this preset ever
    /// emitted was even.
    /// </remarks>
    private static ulong DrawWide32() =>
        ((ulong)RandomNumberGenerator.GetInt32(int.MaxValue) * 2)
            + (ulong)RandomNumberGenerator.GetInt32(2);
}
