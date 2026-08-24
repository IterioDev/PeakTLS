using System.Collections.Immutable;
using SharpTls;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace TlsClient;

/// <summary>How wide a QUIC variable-length integer field is encoded, beyond its minimum.</summary>
/// <remarks>Mirrors <c>SharpTls.Quic.TlsQuicVarintWidth</c> value for value; that type is
/// internal to SharpTls and cannot appear on a public TlsClient API.</remarks>
public enum TlsQuicVarintWidth
{
    /// <summary>The narrowest encoding that holds the value.</summary>
    Minimal = 0,

    /// <summary>Always one byte.</summary>
    OneByte = 1,

    /// <summary>Always two bytes.</summary>
    TwoBytes = 2,

    /// <summary>Always four bytes.</summary>
    FourBytes = 4,

    /// <summary>Always eight bytes.</summary>
    EightBytes = 8,
}

/// <summary>What a PTO probe packet carries.</summary>
/// <remarks>Mirrors <c>SharpTls.Quic.TlsQuicProbeContents</c> value for value.</remarks>
public enum TlsQuicProbeContents
{
    /// <summary>A bare PING.</summary>
    Ping = 0,

    /// <summary>A PING padded out to the datagram target.</summary>
    PingWithPadding = 1,

    /// <summary>The oldest unacknowledged data, retransmitted.</summary>
    RetransmittedData = 2,
}

/// <summary>When an acknowledgement is sent.</summary>
/// <remarks>Mirrors <c>SharpTls.Quic.TlsQuicAckPolicy</c> value for value.</remarks>
public enum TlsQuicAckPolicy
{
    /// <summary>As soon as the packet that elicits it is processed.</summary>
    Immediate = 0,

    /// <summary>Held back up to the advertised <c>max_ack_delay</c>.</summary>
    DelayedToMaxAckDelay = 1,
}

/// <summary>
/// Configures the six QUIC local flow-control limits this client advertises.
/// </summary>
/// <remarks>These are the values the six <c>Placed</c> transport-parameter slots carry, which
/// is why they live here and not as literal bytes in
/// <see cref="TlsQuicTransportParameterOptions.Entries"/> — typing them in both places would
/// let a caller set two different numbers for one wire field. Every default is read from
/// SharpTls's own spec rather than re-typed.</remarks>
public sealed class TlsQuicFlowControlOptions
{
    private static readonly TlsQuicLocalFlowControlSpec SpecDefaults = new();

    /// <summary>Gets or sets <c>initial_max_data</c>.</summary>
    public ulong InitialMaxData { get; set; } = SpecDefaults.InitialMaxData;

    /// <summary>Gets or sets <c>initial_max_stream_data_bidi_local</c>.</summary>
    public ulong InitialMaxStreamDataBidiLocal { get; set; } =
        SpecDefaults.InitialMaxStreamDataBidiLocal;

    /// <summary>Gets or sets <c>initial_max_stream_data_bidi_remote</c>.</summary>
    public ulong InitialMaxStreamDataBidiRemote { get; set; } =
        SpecDefaults.InitialMaxStreamDataBidiRemote;

    /// <summary>Gets or sets <c>initial_max_stream_data_uni</c>.</summary>
    public ulong InitialMaxStreamDataUni { get; set; } = SpecDefaults.InitialMaxStreamDataUni;

    /// <summary>Gets or sets <c>initial_max_streams_bidi</c>.</summary>
    public ulong InitialMaxStreamsBidi { get; set; } = SpecDefaults.InitialMaxStreamsBidi;

    /// <summary>Gets or sets <c>initial_max_streams_uni</c>.</summary>
    public ulong InitialMaxStreamsUni { get; set; } = SpecDefaults.InitialMaxStreamsUni;

    internal TlsQuicLocalFlowControlSpec Snapshot() => new()
    {
        InitialMaxData = InitialMaxData,
        InitialMaxStreamDataBidiLocal = InitialMaxStreamDataBidiLocal,
        InitialMaxStreamDataBidiRemote = InitialMaxStreamDataBidiRemote,
        InitialMaxStreamDataUni = InitialMaxStreamDataUni,
        InitialMaxStreamsBidi = InitialMaxStreamsBidi,
        InitialMaxStreamsUni = InitialMaxStreamsUni,
    };
}

/// <summary>
/// Configures QUIC loss detection and congestion control — every settable knob of SharpTls's
/// <c>TlsQuicRecoverySpec</c> except its congestion-controller factory.
/// </summary>
/// <remarks>
/// <para>THIS IS FINGERPRINT SURFACE, NOT TUNING. Recovery behaviour is observable from the
/// outside: when a probe goes out, how large the first flight is, whether acknowledgements are
/// immediate. Two clients with identical bytes and different recovery constants are
/// distinguishable by timing.</para>
/// <para>THE CONGESTION CONTROLLER ITSELF IS NOT REACHABLE FROM HERE. SharpTls's
/// <c>CongestionController</c> is a <c>Func&lt;ITlsQuicCongestionController&gt;</c> over an
/// <see langword="internal"/> interface with exactly one implementation (NewReno), so a
/// TlsClient consumer can neither name the type nor write another. Making it reachable needs
/// SharpTls to make <c>ITlsQuicCongestionController</c> public; until then a caller cannot
/// select, for example, the BBR that Chromium runs.</para>
/// </remarks>
public sealed class TlsQuicRecoveryOptions
{
    private static readonly TlsQuicRecoverySpec SpecDefaults = new();

    /// <summary>
    /// Gets or sets the initial congestion window as a datagram multiplier and a byte cap.
    /// </summary>
    public (int DatagramMultiplier, int ByteCap) InitialCongestionWindow { get; set; } =
        SpecDefaults.InitialCongestionWindow;

    /// <summary>Gets or sets the floor the congestion window may not shrink below.</summary>
    public int MinimumCongestionWindowDatagrams { get; set; } =
        SpecDefaults.MinimumCongestionWindowDatagrams;

    /// <summary>Gets or sets the multiplier applied to the window on a congestion event.</summary>
    public double LossReductionFactor { get; set; } = SpecDefaults.LossReductionFactor;

    /// <summary>Gets or sets RFC 9002's <c>kPacketThreshold</c>.</summary>
    public int PacketThreshold { get; set; } = SpecDefaults.PacketThreshold;

    /// <summary>Gets or sets RFC 9002's <c>kTimeThreshold</c>.</summary>
    public double TimeThreshold { get; set; } = SpecDefaults.TimeThreshold;

    /// <summary>Gets or sets RFC 9002's <c>kPersistentCongestionThreshold</c>.</summary>
    public int PersistentCongestionThreshold { get; set; } =
        SpecDefaults.PersistentCongestionThreshold;

    /// <summary>
    /// Gets or sets the PTO backoff factor and the optional ceiling the backoff stops at.
    /// </summary>
    public (double Factor, TimeSpan? Maximum) PtoBackoff { get; set; } =
        SpecDefaults.PtoBackoff;

    /// <summary>Gets or sets how many probe packets one PTO expiry sends.</summary>
    public int ProbePacketsPerPto { get; set; } = SpecDefaults.ProbePacketsPerPto;

    /// <summary>Gets or sets what a probe packet carries.</summary>
    public TlsQuicProbeContents ProbeContents { get; set; } =
        (TlsQuicProbeContents)SpecDefaults.ProbeContents;

    /// <summary>Gets or sets when an acknowledgement is sent.</summary>
    public TlsQuicAckPolicy AckPolicy { get; set; } = (TlsQuicAckPolicy)SpecDefaults.AckPolicy;

    /// <summary>
    /// Gets or sets the pacing burst in datagrams, or <see langword="null"/> for no pacing.
    /// </summary>
    public int? PacingBurstDatagrams { get; set; } = SpecDefaults.PacingBurstDatagrams;

    /// <summary>
    /// Gets or sets RFC 9002 section 7.7's <c>N</c>, the factor the paced sending interval is
    /// scaled by. Without it the burst is settable and the spacing between the datagrams in
    /// that burst is not, because neither <c>congestion_window</c> nor <c>smoothed_rtt</c> —
    /// section 7.7's other two terms — is a knob.
    /// </summary>
    public double PacingIntervalScale { get; set; } = SpecDefaults.PacingIntervalScale;

    /// <summary>
    /// Gets or sets the congestion controller this connection runs, or <see langword="null"/>
    /// for RFC 9002 section 7's New Reno.
    /// </summary>
    /// <remarks>
    /// <para>FINGERPRINT SURFACE, NOT A TUNING KNOB. Reno, CUBIC and BBR answer the same loss
    /// with different send cadences, so a persona whose real client runs one of the other two
    /// cannot be matched by a spec that can only run Reno.</para>
    /// <para>INTERNAL BECAUSE <c>ITlsQuicCongestionController</c> IS. A public property cannot
    /// expose an internal type, and publishing the interface would drag
    /// <c>TlsQuicSentPacket</c> and the rest of the recovery surface public with it - the
    /// commitment <c>SharpTls/Properties/AssemblyInfo.cs</c> deliberately defers. Reachable
    /// today from TlsClient and both test assemblies; when SharpTls's public QUIC surface is
    /// designed this becomes public with it.</para>
    /// <para>It used to be unreachable from ANYWHERE, which is the bug this closes:
    /// <see cref="Snapshot"/> copied twelve fields and silently dropped the thirteenth, so a
    /// controller set here was discarded on the way to the spec and
    /// <c>TlsQuicLossDetection</c> built New Reno regardless.</para>
    /// </remarks>
    internal Func<SharpTls.Quic.ITlsQuicCongestionController>? CongestionController
    {
        get;
        set;
    }

    internal TlsQuicRecoverySpec Snapshot() =>
        new TlsQuicRecoverySpec
        {
            CongestionController = CongestionController,
            InitialCongestionWindow = InitialCongestionWindow,
            MinimumCongestionWindowDatagrams = MinimumCongestionWindowDatagrams,
            LossReductionFactor = LossReductionFactor,
            PacketThreshold = PacketThreshold,
            TimeThreshold = TimeThreshold,
            PersistentCongestionThreshold = PersistentCongestionThreshold,
            PtoBackoff = PtoBackoff,
            ProbePacketsPerPto = ProbePacketsPerPto,
            ProbeContents = (SharpTls.Quic.TlsQuicProbeContents)ProbeContents,
            AckPolicy = (SharpTls.Quic.TlsQuicAckPolicy)AckPolicy,
            PacingBurstDatagrams = PacingBurstDatagrams,
            PacingIntervalScale = PacingIntervalScale,
        };
}

/// <summary>
/// Configures the QUIC connection and the TLS half of the HTTP/3 ClientHello — everything
/// <see cref="TlsSessionOptions.Profile"/> cannot reach because a <c>TlsProfile</c> describes a
/// TCP ClientHello.
/// </summary>
/// <remarks>
/// <para>WHY THIS IS SEPARATE FROM <see cref="TlsSessionOptions.Profile"/>. A
/// <c>TlsProfile</c> carries TLS 1.2 suites, session tickets and ALPS, and several of its
/// extensions are ones RFC 9001 section 8.4 forbids over QUIC. It therefore does not and must
/// not drive the h3 ClientHello. <see cref="ConfigureClientHello"/> is how an HTTP/3 persona's
/// TLS half is set.</para>
/// <para>Every default is read from a freshly constructed SharpTls spec rather than re-typed,
/// so nothing here can drift away from the cited preset it mirrors.</para>
/// </remarks>
public sealed class TlsQuicOptions
{
    private static readonly TlsQuicConnectionSpec SpecDefaults = new();

    // Not a const: CA2208 only accepts a compile-time paramName that names a parameter of the
    // throwing method, and this rejection belongs to the AlpnProtocols property.
    private static readonly string AlpnParameter = nameof(AlpnProtocols);

    // THE FOUR MTU DEFAULTS BELOW READ SpecDefaults LIKE EVERY OTHER PROPERTY IN THIS CLASS.
    // They used to be two local constants - 1200 and 1472 - re-typed here beside a spec that
    // already declares both. That is four silent drift hazards: change TlsQuicConnectionSpec's
    // default and these stay put, agreeing with nothing and citing no capture.

    /// <summary>
    /// Gets or sets a callback that configures the TLS half of an HTTP/3 connection: client
    /// certificates, Encrypted ClientHello, the resumption cache, 0-RTT, and parser limits.
    /// </summary>
    /// <remarks>
    /// <para>THE QUIC-SHAPED TWIN OF <see cref="TlsSessionOptions.ConfigureTls"/>, which this
    /// path cannot use: that one is <c>Action&lt;CustomTlsClientOptions&gt;</c> and describes a
    /// TCP handshake, and RFC 9001 section 8.4 forbids over QUIC several TLS features that are
    /// legal over TCP. One delegate covering both would be wrong on one of them.</para>
    /// <para>RUNS BEFORE the session's <see cref="TlsSessionOptions.ClientCertificates"/> and
    /// before the shared resumption cache is attached, so both can detect a conflict rather
    /// than overwrite one. It is also the seam through which Encrypted ClientHello reaches
    /// HTTP/3 today: <see cref="TlsSessionOptions.EchDnsResolver"/> drives the TCP path's
    /// HTTPS-record lookup and retry, and that flow has no HTTP/3 twin yet, so a caller with an
    /// ECH configuration in hand sets it on the options here.</para>
    /// <para>DO NOT set <c>ClientHello</c> from it. The profile is composed per connection
    /// around this connection's source connection ID; replacing it re-sends another
    /// connection's <c>initial_source_connection_id</c>. Use
    /// <see cref="ConfigureClientHello"/> for the ClientHello's shape.</para>
    /// </remarks>
    public Action<CustomTlsQuicClientOptions>? ConfigureTls { get; set; }

    /// <summary>
    /// Gets or sets how long the QUIC handshake may take before the connection abandons it, or
    /// <see langword="null"/> for SharpTls's own default.
    /// </summary>
    /// <remarks>
    /// A KNOB OF ITS OWN BECAUSE IT WAS BEING FED AN UNRELATED ONE. The h3 dial used to pass
    /// <c>PooledConnectionLifetime</c> here - how long a healthy pooled connection may be
    /// REUSED, five to ten minutes - as the deadline for a handshake that SharpTls defaults to
    /// ten seconds. The internal deadline could then never fire and the real bound was the
    /// outer handshake CTS, so the configuration was dead and its name at the call site said
    /// otherwise.
    /// </remarks>
    public TimeSpan? HandshakeDeadline { get; set; }

    /// <summary>
    /// Gets or sets what this client writes into RFC 9000 section 17.4's latency spin bit on
    /// 1-RTT packets. The default is <see cref="TlsQuicSpinBitPolicy.Zero"/>.
    /// </summary>
    /// <remarks>ZERO IS THE MAJORITY BEHAVIOUR, NOT A PLACEHOLDER. Section 17.4 permits any
    /// value once an endpoint disables the spin bit, and Chromium sends zero. The knob exists
    /// so a client that draws instead can be imitated; before it, the value was a literal in
    /// the send path with no property at all.</remarks>
    public TlsQuicSpinBitPolicy SpinBit { get; set; } = (TlsQuicSpinBitPolicy)SpecDefaults.SpinBit;

    /// <summary>
    /// Gets or sets the QUIC version this client's first flight uses — RFC 9368 section 3's
    /// Chosen Version. The default is <see cref="TlsQuicVersion.Version1"/>.
    /// </summary>
    /// <remarks>
    /// <para>THE VERSION MAY STILL MOVE AFTER THIS. RFC 9368 section 2.3 lets the server answer
    /// the first flight in any version the client listed as AVAILABLE, and this client adopts
    /// it when it does. Setting this only decides where the connection starts.</para>
    /// <para>WHAT THE CLIENT OFFERS IS A TRANSPORT PARAMETER, NOT THIS. The Available Versions
    /// list lives in <c>version_information</c> (0x11) inside
    /// <see cref="TransportParameters"/>, because it is a captured wire field like any other. A
    /// profile that sends no such parameter cannot negotiate at all - which is the correct
    /// reading of a capture that does not carry one, and is the shipped Spotify preset's case.
    /// </para>
    /// <para>VERSION 2 IS SPEAKABLE BUT NOT COMPLETE: RFC 9369's Retry integrity constants are
    /// not transcribed, so a Retry on a version 2 connection throws.</para>
    /// </remarks>
    public TlsQuicVersion Version { get; set; } = SpecDefaults.Version;

    /// <summary>
    /// Gets or sets whether this client draws RFC 9000 section 17.2's QUIC Bit per 1-RTT packet
    /// when the peer has advertised RFC 9287's <c>grease_quic_bit</c>. Off by default.
    /// </summary>
    /// <remarks>
    /// <para>THIS IS THE SEND HALF ONLY. Advertising <c>grease_quic_bit</c> yourself is a
    /// transport-parameter entry - <c>TlsQuicTransportParameterEntry.Literal(0x2AB2, [])</c> in
    /// <see cref="TransportParameters"/> - and doing so obliges the receive path to accept a
    /// greased packet, which it now does automatically because the obligation follows the
    /// advertisement rather than a second knob.</para>
    /// <para>Off by default because neither shipped capture greases, and the bit sits outside
    /// header protection - it is plainly visible to a passive observer.</para>
    /// </remarks>
    public bool GreaseQuicBit { get; set; } = SpecDefaults.GreaseQuicBit;

    /// <summary>Gets or sets the source connection ID length in bytes.</summary>
    public int SourceConnectionIdLength { get; set; } = SpecDefaults.SourceConnectionIdLength;

    /// <summary>Gets or sets the initial destination connection ID length in bytes.</summary>
    public int DestinationConnectionIdLength { get; set; } =
        SpecDefaults.DestinationConnectionIdLength;

    /// <summary>Gets or sets the first packet number this client uses.</summary>
    public ulong InitialPacketNumber { get; set; } = SpecDefaults.InitialPacketNumber;

    /// <summary>Gets or sets how many bytes a packet number is encoded in.</summary>
    public int PacketNumberEncodedLength { get; set; } = SpecDefaults.PacketNumberEncodedLength;

    /// <summary>Gets or sets the address-validation token replayed in the Initial packet.</summary>
    public ReadOnlyMemory<byte> Token { get; set; } = SpecDefaults.Token;

    /// <summary>
    /// Gets or sets the byte length Initial datagrams are padded to. The default is RFC 9000
    /// section 14.1's 1200-byte minimum.
    /// </summary>
    public int PaddingTarget { get; set; } = SpecDefaults.PaddingTarget;

    /// <summary>
    /// Gets or sets the byte ceiling every outgoing datagram is bounded by before path MTU
    /// discovery confirms anything larger - RFC 8899's BASE_PLPMTU. The default is RFC 9000
    /// section 14.2's smallest allowed maximum datagram size, 1200 bytes.
    /// </summary>
    /// <remarks>
    /// THE CEILING, WHERE <see cref="PaddingTarget"/> IS THE FLOOR. They share a default and
    /// do opposite jobs: PaddingTarget expands an Initial datagram UP to 1200 because section
    /// 14.1 requires it, this bounds every datagram DOWN because section 14.2 says an endpoint
    /// without discovery "SHOULD NOT send datagrams larger than the smallest allowed maximum
    /// datagram size". A request body larger than this is split across datagrams rather than
    /// sent as one oversized one.
    /// </remarks>
    public int BasePathMtu { get; set; } = SpecDefaults.BasePathMtu;

    /// <summary>
    /// Gets or sets the largest datagram size path MTU discovery will search up to - RFC 8899's
    /// MAX_PLPMTU. The default is 1472, which is 1500 minus the 20-byte IPv4 and 8-byte UDP
    /// headers.
    /// </summary>
    /// <remarks>
    /// Lower this on a path with a smaller MTU - a VPN or a tunnelled proxy - so the search
    /// does not spend probes on sizes the path cannot carry. It is NOT the advertised
    /// <c>max_udp_payload_size</c>, which tells a server what this client will RECEIVE; the
    /// two are deliberately separate, and the peer's own value still applies on top.
    /// </remarks>
    public int MaximumPathMtu { get; set; } = SpecDefaults.MaximumPathMtu;

    /// <summary>
    /// Gets or sets whether RFC 8899 path MTU discovery runs, searching upward from
    /// <see cref="BasePathMtu"/> toward <see cref="MaximumPathMtu"/>. On by default.
    /// </summary>
    /// <remarks>
    /// ON SO THAT A PATH LARGER THAN 1200 BYTES IS USED WITHOUT ANYONE REMEMBERING TO ASK. A
    /// large upload then moves in roughly a fifth the datagrams. The cost is that a probe is
    /// observable - an extra PING-and-PADDING datagram at a size nothing else in the flight
    /// uses, on a schedule this library chose rather than one measured from a capture - so set
    /// it false when a connection has to match a capture byte for byte. The probe waits until
    /// application data has been sent, so it never appears in the opening flight, and the
    /// search normally ends after one probe.
    /// </remarks>
    public bool PathMtuDiscovery { get; set; } = SpecDefaults.PathMtuDiscovery;

    /// <summary>
    /// Gets or sets the exact byte count of each CRYPTO frame in the Initial flight, in order.
    /// Empty means one frame carrying everything.
    /// </summary>
    public IList<int> InitialCryptoFrameByteCounts { get; set; } =
        [.. SpecDefaults.InitialCryptoFrameByteCounts];

    /// <summary>
    /// Gets or sets how many CRYPTO frames each Initial datagram carries, in order. Empty means
    /// SharpTls packs them.
    /// </summary>
    public IList<int> InitialCryptoFramesPerDatagram { get; set; } =
        [.. SpecDefaults.InitialCryptoFramesPerDatagram];

    /// <summary>
    /// Gets or sets the frame types in an Initial packet, in exact emission order, by their
    /// RFC 9000 section 12.4 wire codes. A bare <see cref="ulong"/> rather than an enum so a
    /// frame type this library does not name can still be ordered.
    /// </summary>
    public IList<ulong> InitialFrameOrder { get; set; } =
        [.. SpecDefaults.InitialFrameOrder.Select(type => (ulong)type)];

    /// <summary>Gets or sets the width of a long-header packet's Length field.</summary>
    public TlsQuicVarintWidth HeaderLengthVarintWidth { get; set; } =
        (TlsQuicVarintWidth)SpecDefaults.HeaderLengthVarintWidth;

    /// <summary>Gets or sets the width of a CRYPTO frame's Offset field.</summary>
    public TlsQuicVarintWidth CryptoOffsetVarintWidth { get; set; } =
        (TlsQuicVarintWidth)SpecDefaults.CryptoOffsetVarintWidth;

    /// <summary>Gets or sets the width of a CRYPTO frame's Length field.</summary>
    public TlsQuicVarintWidth CryptoLengthVarintWidth { get; set; } =
        (TlsQuicVarintWidth)SpecDefaults.CryptoLengthVarintWidth;

    /// <summary>
    /// Gets or sets the range a per-connection <c>initial_rtt</c> is drawn from, or
    /// <see langword="null"/> to use RFC 9002's fixed initial RTT.
    /// </summary>
    public (TimeSpan Minimum, TimeSpan Maximum)? InitialRttRange { get; set; } =
        SpecDefaults.InitialRttRange;

    /// <summary>Gets or sets how many ACK ranges one ACK frame reports.</summary>
    public int AckRangeLimit { get; set; } = SpecDefaults.AckRangeLimit;

    /// <summary>
    /// Gets or sets whether coalesced packets in one datagram ascend by encryption level.
    /// </summary>
    public bool CoalesceAscendingByLevel { get; set; } = SpecDefaults.CoalesceAscendingByLevel;

    /// <summary>Gets or sets whether an ACK frame leads the packet that carries it.</summary>
    public bool AckLeadsInPacket { get; set; } = SpecDefaults.AckLeadsInPacket;

    /// <summary>Gets the six local flow-control limits.</summary>
    public TlsQuicFlowControlOptions FlowControl { get; } = new();

    /// <summary>Gets the transport parameters, as an ordered list of slots.</summary>
    public TlsQuicTransportParameterOptions TransportParameters { get; } = new();

    /// <summary>Gets the loss-detection and congestion-control knobs.</summary>
    public TlsQuicRecoveryOptions Recovery { get; } = new();

    /// <summary>
    /// Gets or sets the ALPN protocols offered in the QUIC ClientHello, in exact order. The
    /// HTTP/3 connection still requires the peer to select <c>h3</c>.
    /// </summary>
    public IList<string> AlpnProtocols { get; set; } =
        [TlsQuicClientHelloProfileFactory.Http3AlpnToken];

    /// <summary>
    /// Gets or sets the TLS half of the HTTP/3 ClientHello — cipher suites, supported groups,
    /// key shares, signature algorithms, GREASE policy, extension order and extension layout.
    /// <see langword="null"/> applies <see cref="ApplyDefaultClientHello"/>; a non-null value
    /// REPLACES it, so call <see cref="ApplyDefaultClientHello"/> first to extend rather than
    /// replace.
    /// </summary>
    public Action<ClientHelloBuilder>? ConfigureClientHello { get; set; }

    /// <summary>
    /// Applies the default HTTP/3 ClientHello shape: TLS 1.3, two suites and two groups, which
    /// is what SharpTls's live run against the reference endpoint used.
    /// </summary>
    /// <param name="builder">The builder to configure.</param>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
    public static void ApplyDefaultClientHello(ClientHelloBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder
            .WithTls13()
            .WithCipherSuites(
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsAes256GcmSha384)
            .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.X25519);
    }

    internal TlsQuicConfiguration Snapshot(TlsHttp3Options http3)
    {
        ArgumentNullException.ThrowIfNull(http3);
        ArgumentNullException.ThrowIfNull(FlowControl, nameof(FlowControl));
        ArgumentNullException.ThrowIfNull(TransportParameters, nameof(TransportParameters));
        ArgumentNullException.ThrowIfNull(Recovery, nameof(Recovery));
        ArgumentNullException.ThrowIfNull(
            InitialCryptoFrameByteCounts,
            nameof(InitialCryptoFrameByteCounts));
        ArgumentNullException.ThrowIfNull(
            InitialCryptoFramesPerDatagram,
            nameof(InitialCryptoFramesPerDatagram));
        ArgumentNullException.ThrowIfNull(InitialFrameOrder, nameof(InitialFrameOrder));
        ArgumentNullException.ThrowIfNull(AlpnProtocols, nameof(AlpnProtocols));

        // No Enum.IsDefined guard on the three varint widths: TlsQuicConnectionSpec's own
        // ValidateVarintWidth already rejects an undefined one under the same paramName. See
        // TlsHttp3Options.Snapshot for the sweep result that established this.

        var alpn = AlpnProtocols.ToArray();
        if (alpn.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException(
                $"{AlpnParameter} must contain no null or empty tokens.",
                AlpnParameter);
        }

        var connectionSpec = new TlsQuicConnectionSpec
        {
            SourceConnectionIdLength = SourceConnectionIdLength,
            DestinationConnectionIdLength = DestinationConnectionIdLength,
            InitialPacketNumber = InitialPacketNumber,
            PacketNumberEncodedLength = PacketNumberEncodedLength,
            Token = Token,
            PaddingTarget = PaddingTarget,
            BasePathMtu = BasePathMtu,
            MaximumPathMtu = MaximumPathMtu,
            PathMtuDiscovery = PathMtuDiscovery,
            SpinBit = (SharpTls.Quic.TlsQuicSpinBitPolicy)SpinBit,
            GreaseQuicBit = GreaseQuicBit,
            Version = Version,
            InitialCryptoFrameByteCounts = [.. InitialCryptoFrameByteCounts],
            InitialCryptoFramesPerDatagram = [.. InitialCryptoFramesPerDatagram],
            InitialFrameOrder =
                [.. InitialFrameOrder.Select(type => (TlsQuicFrameType)type)],
            HeaderLengthVarintWidth =
                (SharpTls.Quic.TlsQuicVarintWidth)HeaderLengthVarintWidth,
            CryptoOffsetVarintWidth =
                (SharpTls.Quic.TlsQuicVarintWidth)CryptoOffsetVarintWidth,
            CryptoLengthVarintWidth =
                (SharpTls.Quic.TlsQuicVarintWidth)CryptoLengthVarintWidth,
            InitialRttRange = InitialRttRange,
            AckRangeLimit = AckRangeLimit,
            CoalesceAscendingByLevel = CoalesceAscendingByLevel,
            AckLeadsInPacket = AckLeadsInPacket,
            LocalFlowControl = FlowControl.Snapshot(),
            TransportParameters = TransportParameters.Snapshot(),
            Recovery = Recovery.Snapshot(),
        };

        var configureClientHello = ConfigureClientHello ?? ApplyDefaultClientHello;
        return new TlsQuicConfiguration(
            connectionSpec,
            http3.Snapshot(),
            alpn,
            configureClientHello,
            ConfigureTls,
            HandshakeDeadline);
    }
}

/// <summary>The immutable QUIC and HTTP/3 shape one session dials with.</summary>
/// <remarks>Carries SharpTls's own spec objects rather than a second copy of their fields.
/// They are immutable, and every per-connection value they hold — the three drawn transport
/// parameters, the drawn <c>initial_rtt</c> — is redrawn by <c>Compose</c> at connect time
/// rather than frozen here.</remarks>
internal sealed record TlsQuicConfiguration(
    TlsQuicConnectionSpec ConnectionSpec,
    TlsQuicHttp3Spec Http3Spec,
    string[] AlpnProtocols,
    Action<ClientHelloBuilder> ConfigureClientHello,
    Action<CustomTlsQuicClientOptions>? ConfigureTls,
    TimeSpan? HandshakeDeadline);
