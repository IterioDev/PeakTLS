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
    /// <c>q13d0311h3_55b375c5d22e_f2a83c8e78ae</c>. That JA3 is the proxy-path image; the direct
    /// captures hash to <c>2f9431e877b01e163774ae4ae0df9ded</c>. JA4 does not distinguish them.
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
#pragma warning disable TLSCLIENT3 // Http3Only: this preset exists to carry a QUIC shape.
    public static TlsPreset Spotify917602050IOS270Http3 { get; } = new(
        "spotify-9.1.76-ios-27.0-h3",
        TlsProfiles.Spotify917602050IOS270Quic,
        static _ => { },

        TlsHttpVersionPolicy.Http3Only,
        ConfigureSpotifyIosQuic);

#pragma warning restore TLSCLIENT3

    /// <summary>Gets the current SharpTls Spotify-family preset.</summary>
    public static TlsPreset Spotify => Spotify917602050IOS270Http3;

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

    /// <summary>
    /// Applies the measured QUIC and HTTP/3 shape. Values not reachable from any capture we
    /// hold — everything under <c>Quic.Recovery</c> and the QPACK encoding choices — are
    /// deliberately left at their defaults rather than given invented numbers.
    /// </summary>

    private static void ConfigureSpotifyIosQuic(TlsSessionOptions options)
    {
        var quic = options.Quic;

        // Packet and datagram shape, identical across all 80 captured connections.
        quic.SourceConnectionIdLength = 0;
        quic.DestinationConnectionIdLength = 8;
        quic.PacketNumberEncodedLength = 1;
        quic.Token = ReadOnlyMemory<byte>.Empty;
        quic.PaddingTarget = 1200;
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
        // identified it. Absent from all 80 direct connections; see the cipher-order note.
        quic.TransportParameters.Entries =
        [
            .. SpotifyTransportParameters(),
            TlsQuicTransportParameterEntry.Literal(0xFF08_0808, [0x09]),
        ];
        quic.TransportParameters.CyclicRotationLength = SpotifyRotatingParameterCount;

        quic.AlpnProtocols = ["h3"];
        quic.ConfigureClientHello =
            ClientHelloProfiles.ApplySpotify917602050IOS270QuicClientHello;

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
