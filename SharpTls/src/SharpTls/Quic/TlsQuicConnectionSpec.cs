using System.Collections.Immutable;

namespace SharpTls.Quic;

/// <summary>The encoded width a variable-length integer is written at, when the sender
/// deliberately declines the shortest form.</summary>
/// <remarks>
/// RFC 9000 s16, verbatim from rfc9000-section16-variable-length-integers.txt line 44:
/// "Values do not need to be encoded on the minimum number of bytes necessary, with the
/// sole exception of the Frame Type field; see Section 12.4."
/// <para>So the width of a CRYPTO frame's Offset or Length, or of a long header's Length,
/// is a sender choice rather than a derived value, and is therefore observable on the wire
/// and fingerprintable. The frame type itself is excluded by that same sentence and is not
/// a knob here; nothing in this file offers one.</para>
/// <para>The member values are the byte counts of s16's Table 4 (1, 2, 4 and 8), so a
/// non-<see cref="Minimal"/> member casts directly to the width it names.</para>
/// </remarks>
internal enum TlsQuicVarintWidth
{
    /// <summary>Write the shortest form that holds the value - what
    /// <see cref="QuicVariableLengthInteger.GetEncodedLength(ulong)"/> computes.</summary>
    Minimal = 0,

    /// <summary>One byte; holds values up to 63.</summary>
    OneByte = 1,

    /// <summary>Two bytes; holds values up to 16383.</summary>
    TwoBytes = 2,

    /// <summary>Four bytes; holds values up to 1073741823.</summary>
    FourBytes = 4,

    /// <summary>Eight bytes; holds values up to
    /// <see cref="QuicVariableLengthInteger.MaximumValue"/>.</summary>
    EightBytes = 8,
}

// ADDING A PROPERTY HERE? TWO THINGS ARE OWED BEFORE IT LANDS, and this notice is
// at the top of this file rather than only in the plan because this is the file
// the author of the next knob has open. Both have now been missed twice - by
// task 5's varint widths, closed in its fix round, and by AckRangeLimit below.
//
//   1. WITNESS THE GUARD. Every guard on a spec field is reachable, because
//      subsystem B populates the spec from outside this library, so a value the
//      guard rejects is a value a caller can write. A guard with no test is an
//      unwitnessed mutation waiting to be found by a reviewer.
//   2. SAY WHETHER ANYTHING READS IT. Run `grep -rn "spec\.<YourProperty>" src/`.
//      If nothing does, the property does not do what its doc-comment implies,
//      and the doc-comment must say so and NAME THE TASK THAT WILL WIRE IT. The
//      task-4b amendment ruled on the alternative: "Do not quietly leave the
//      knobs present-but-inert: a knob that accepts a value and ignores it is
//      worse than an absent one." A knob is honoured only if a caller setting it
//      on the type the caller holds changes a byte; "the writer accepts a width"
//      is a different and weaker claim.

/// <summary>Every packet-layout decision a QUIC client makes that a peer or an observer can
/// see. Subsystem B populates one of these to imitate a particular browser; nothing below
/// the connection layer may read a layout literal instead.</summary>
/// <remarks>
/// <para>THE THREE SIZE NUMBERS THAT LIVE NEAR EACH OTHER AND MUST NOT BE DERIVED FROM ONE
/// ANOTHER. Getting this wrong looks like ordinary configuration and is not:</para>
/// <list type="number">
/// <item><description><b>The advertised <c>max_udp_payload_size</c> transport parameter
/// (0x03).</b> a captured client advertises 1472. It is not in this type at all - transport
/// parameters ride inside the ClientHello and are set through
/// <c>ClientHelloBuilder.WithQuicTransportParameters</c>. RFC 9000 s18.2: "The maximum UDP
/// payload size parameter is an integer value that limits the size of UDP payloads that the
/// endpoint is willing to receive", default 65527, "Values below 1200 are invalid". It says
/// what we are willing to <i>receive</i>.</description></item>
/// <item><description><b><see cref="PaddingTarget"/>, the floor this client expands an
/// Initial-carrying datagram up to.</b> RFC 9000 s14.1 sets it at 1200. It says what we
/// <i>send</i>.</description></item>
/// <item><description><b>The transport's real send ceiling,
/// <see cref="ITlsQuicDatagramTransport.MaxDatagramPayloadSize"/>.</b> A property of the
/// encapsulation - the SOCKS5 transport reports 65527 less its own header. It says what we
/// <i>can</i> send.</description></item>
/// </list>
/// <para>A client capture is explicit that the first and third are unrelated: "Advertised
/// parameter and actual ceiling are separate concerns and must not be wired together." A
/// Chrome-imitating client advertises 1472 regardless of what its transport can carry, and
/// pads to 1200 regardless of both. Three numbers, three meanings, no arithmetic between
/// them anywhere in this codebase.</para>
/// <para>WHAT IS DELIBERATELY NOT HERE: <c>initial_rtt</c> (Chromium's private parameter
/// 12583) is a transport parameter and so lives in the immutable ClientHello profile, not
/// in this spec. The capture records 192859 and warns that it "is not a constant to copy -
/// uQUIC models this as ChromeRandomInitialRTT(). A fixed value here would itself be a
/// fingerprint." The spec therefore holds the randomisation <i>policy</i> and never a value;
/// see <see cref="InitialRttRange"/>. Because that parameter is baked into the profile, a
/// fresh profile is required per connection - which is task 9a-ii's obligation, not this
/// type's.</para>
/// <para>An instance is immutable once constructed and every bound is enforced as it is
/// set, so a spec that exists is a spec that is in range. There is no separate validate
/// step to forget.</para>
/// </remarks>
internal sealed class TlsQuicConnectionSpec
{
    // RFC 9000 s17.2: the long header's Source/Destination Connection ID Length fields.
    // TlsQuicPacketHeader already owns this ceiling for the parse direction; the send
    // direction shares the constant rather than restating the number.
    private const int MaximumConnectionIdLength = TlsQuicPacketHeader.MaximumConnectionIdLength;

    // RFC 9000 s7.2, verbatim from rfc9000-section7-connection-id-negotiation.txt
    // lines 31-37:
    //
    //   "When an Initial packet is sent by a client that has not previously received an
    //    Initial or Retry packet from the server, the client populates the Destination
    //    Connection ID field with an unpredictable value.  This Destination Connection ID
    //    MUST be at least 8 bytes in length.  Until a packet is received from the server,
    //    the client MUST use the same Destination Connection ID value on all packets in
    //    this connection."
    //
    // THIS IS THE ONE BOUND THE TARGET CAPTURE CANNOT REVEAL. that client's destination
    // connection ID length is 8 - exactly the floor - so every observed value satisfies
    // the rule and nothing in the capture hints that 4 is illegal. A reader who derived
    // the knob's range from the capture alone would make it a free parameter.
    //
    // NOTE THE SCOPE, because it is narrower than "the first packet" and task 9b can
    // misuse it: the MUST binds "a client that has not previously received an Initial or
    // Retry packet from the server", so it covers every Initial in that opening window, not
    // one packet. And it stops applying once a server packet arrives - s7.2 line 53: "the
    // client uses the Source Connection ID supplied by the server as the Destination
    // Connection ID". A post-Retry destination connection ID is the server's choice, not
    // self-chosen, so this floor is not a check to re-run against it.
    //
    // Note the asymmetry with the source connection ID, which has no such floor. s7.2 line
    // 44: "The client populates the Source Connection ID field with a value of its
    // choosing" - no MUST, and zero is what Chromium uses. The two fields look symmetric on
    // the wire and are not symmetric in the RFC.
    //
    // Witnessed on both sides of the boundary by
    // TlsQuicConnectionSpecTests.DestinationConnectionIdLengthBelowTheSectionSevenTwoFloorIsRejected
    // and TlsQuicConnectionSpecTests.DestinationConnectionIdLengthFromTheFloorToTheSectionSeventeenCeilingIsAccepted,
    // and the asymmetry by TlsQuicConnectionSpecTests.SourceConnectionIdLengthHasNoFloorAndZeroIsLegal.
    private const int MinimumClientDestinationConnectionIdLength = 8;

    // RFC 9000 s14.1, verbatim from rfc9000-section14-datagram-size-and-pmtu.txt
    // lines 65-68:
    //
    //   "A client MUST expand the payload of all UDP datagrams carrying Initial packets to
    //    at least the smallest allowed maximum datagram size of 1200 bytes by adding
    //    PADDING frames to the Initial packet or by coalescing the Initial packet; see
    //    Section 12.2."
    //
    // "all UDP datagrams" - per datagram, not per flight. Task 5 owns honouring it; this
    // constant is only the floor a spec may declare.
    internal const int MinimumInitialDatagramSize = 1200;

    // RFC 9000 s17.1, verbatim from rfc9000-packet-formats-and-pn-pseudocode.txt line 184:
    // "Packet Number:  This field is 1 to 4 bytes long."  Named rather than written inline
    // at the guard so that, like every other bound here, the number sits next to its
    // citation instead of in the middle of an argument list.
    private const int MinimumPacketNumberEncodedLength = 1;
    private const int MaximumPacketNumberEncodedLength = 4;

    // RFC 9000 s18.2, from rfc9000-section18-transport-parameters.txt line 93: "The default
    // for this parameter is the maximum permitted UDP payload of 65527." That is the largest
    // payload a UDP datagram can carry at all, so it bounds any padding target from above.
    //
    // DECLARED LOCALLY, AND THAT IS THE POINT. An earlier revision aliased
    // TlsQuicUdpDatagramTransport.MaximumUdpPayload - which is the symbol backing that type's
    // MaxDatagramPayloadSize, in other words number 3 of the three numbers this type exists
    // to keep apart. Sharing one symbol between number 2's ceiling and number 3 is exactly
    // the wiring the capture warns against, and it would have propagated the day a transport
    // reported a smaller ceiling. 65527 has its own source, quoted above; it is written from
    // that source and connected to nothing.
    private const int MaximumUdpPayload = 65527;

    // 1500 - 20 - 8. Not a constant of any RFC: it is the UDP payload that fits an untunnelled
    // Ethernet frame, which is why it is the default ceiling for a search and NOT a floor
    // anything relies on. A path with a smaller MTU is exactly what the search exists to find.
    private const int EthernetMaximumUdpPayload = 1472;

    private readonly int _sourceConnectionIdLength;
    private readonly int _destinationConnectionIdLength = MinimumClientDestinationConnectionIdLength;
    private readonly ulong _initialPacketNumber;
    private readonly int _packetNumberEncodedLength = MaximumPacketNumberEncodedLength;
    private readonly int _paddingTarget = MinimumInitialDatagramSize;

    // RFC 8899 s5.1.2's BASE_PLPMTU: "a configured size expected to work for most paths ...
    // When using IPv4, there is no currently equivalent size specified, and a default
    // BASE_PLPMTU of 1200 bytes is RECOMMENDED." RFC 9000 s14.3 ties it to QUIC's own floor:
    // "Endpoints SHOULD set the initial value of BASE_PLPMTU ... to be consistent with QUIC's
    // smallest allowed maximum datagram size."
    private readonly int _basePathMtu = MinimumInitialDatagramSize;

    // RFC 8899 s5.1.2's MAX_PLPMTU: "the largest size of PLPMTU. This has to be less than or
    // equal to the maximum size of the PL packet that can be sent on the outgoing interface
    // (constrained by the local interface MTU)." 1472 is 1500 - 20 (IPv4 header) - 8 (UDP
    // header), the ordinary Ethernet ceiling, and it is also the figure
    // TlsQuicTransportParameterSpec's preset advertises as max_udp_payload_size -
    // so the search stops where the capture says the client it imitates expects to stop.
    private readonly int _maximumPathMtu = EthernetMaximumUdpPayload;
    private readonly ImmutableArray<int> _initialCryptoFrameByteCounts = [];
    private readonly ImmutableArray<int> _initialCryptoFramesPerDatagram = [];
    private readonly ImmutableArray<TlsQuicFrameType> _initialFrameOrder =
        [TlsQuicFrameType.Crypto, TlsQuicFrameType.Padding];
    private readonly TlsQuicVarintWidth _headerLengthVarintWidth;
    private readonly TlsQuicVarintWidth _cryptoOffsetVarintWidth;
    private readonly TlsQuicVarintWidth _cryptoLengthVarintWidth;
    private readonly (TimeSpan Minimum, TimeSpan Maximum)? _initialRttRange;
    private readonly int _ackRangeLimit = DefaultAckRangeLimit;
    private readonly TlsQuicLocalFlowControlSpec _localFlowControl = new();
    private readonly TlsQuicTransportParameterSpec _transportParameters = new();
    private readonly TlsQuicRecoverySpec _recovery = new();

    /// <summary>Gets the length in bytes of the connection ID this client asks the peer to
    /// send back to it. Zero means the client is not routed by connection ID.</summary>
    /// <remarks>
    /// <para>RFC 9000 s17.2 bounds it at <see cref="MaximumConnectionIdLength"/>. There is
    /// no lower bound, and s7.2 says so in the same breath as the floor it puts on the
    /// other field: "The client populates the Source Connection ID field with a value of
    /// its choosing and sets the Source Connection ID Length field to indicate the length."
    /// A value of its choosing, with no MUST attached - which is the whole asymmetry.</para>
    /// <para>s7.3 confirms zero is a real choice rather than an oversight: "If a zero-length
    /// connection ID is selected, the corresponding transport parameter is included with a
    /// zero-length value." That sentence is s7.3's, not s7.2's - an earlier revision of this
    /// comment attributed it to s7.2, which sent a reader checking the asymmetry argument to
    /// a section that does not contain it. Section attributions are not checkable by any
    /// test in this repo; only a reader opening the extract catches one.</para>
    /// <para>The default of 0 is a client capture's
    /// <c>client_connection_id_length</c>.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Outside 0 to
    /// <see cref="MaximumConnectionIdLength"/>.</exception>
    public int SourceConnectionIdLength
    {
        get => _sourceConnectionIdLength;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value, nameof(SourceConnectionIdLength));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                value, MaximumConnectionIdLength, nameof(SourceConnectionIdLength));
            _sourceConnectionIdLength = value;
        }
    }

    /// <summary>Gets the length in bytes of the unpredictable connection ID this client
    /// puts in the Destination Connection ID field of the Initial packets it sends before
    /// it has received an Initial or Retry packet from the server.</summary>
    /// <remarks>Bounded below at 8 by RFC 9000 s7.2's MUST and above at
    /// <see cref="MaximumConnectionIdLength"/> by s17.2 - see the citation on
    /// <see cref="MinimumClientDestinationConnectionIdLength"/>, which quotes s7.2 in full
    /// and explains why the capture cannot show the floor. The default of 8 is the that client
    /// 151 capture's <c>server_connection_id_length</c>, which sits exactly on it.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Below 8 or above
    /// <see cref="MaximumConnectionIdLength"/>.</exception>
    public int DestinationConnectionIdLength
    {
        get => _destinationConnectionIdLength;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(
                value,
                MinimumClientDestinationConnectionIdLength,
                nameof(DestinationConnectionIdLength));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                value, MaximumConnectionIdLength, nameof(DestinationConnectionIdLength));
            _destinationConnectionIdLength = value;
        }
    }

    /// <summary>Gets the packet number this client's first Initial packet carries.</summary>
    /// <remarks>RFC 9000 s12.3: "The packet number is an integer in the range 0 to
    /// 2^62-1." That range is already named by
    /// <see cref="QuicVariableLengthInteger.MaximumValue"/>. Zero is the ordinary choice
    /// and is the default; the capture does not observe this field, so the default is not
    /// evidence about Chromium - see the remark on
    /// <see cref="PacketNumberEncodedLength"/>.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Above 2^62-1.</exception>
    public ulong InitialPacketNumber
    {
        get => _initialPacketNumber;
        init
        {
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                value, QuicVariableLengthInteger.MaximumValue, nameof(InitialPacketNumber));
            _initialPacketNumber = value;
        }
    }

    /// <summary>Gets how many bytes the truncated packet number is written in, regardless of
    /// how few would suffice.</summary>
    /// <remarks>
    /// <para>RFC 9000 s17.1: "Packet Number: This field is 1 to 4 bytes long." The sender
    /// picks; <see cref="TlsQuicPacketNumber.EncodedLength"/> computes the <i>smallest</i>
    /// safe choice, and a client is free to send a longer one, which makes this
    /// observable.</para>
    /// <para>The default of 4 comes from RFC 9001 Appendix A.2, whose client Initial encodes
    /// packet number 2 in four bytes - a deliberately non-minimal choice, and the only
    /// externally sourced value available. A client capture explicitly does not inspect
    /// "initial packet number and its encoded length", so this default is a vector-derived
    /// placeholder and NOT evidence about Chromium. Task 11 reports it in the
    /// not-yet-known-from-the-capture category.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Outside 1 to 4.</exception>
    public int PacketNumberEncodedLength
    {
        get => _packetNumberEncodedLength;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(
                value, MinimumPacketNumberEncodedLength, nameof(PacketNumberEncodedLength));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                value, MaximumPacketNumberEncodedLength, nameof(PacketNumberEncodedLength));
            _packetNumberEncodedLength = value;
        }
    }

    /// <summary>Gets the token this client puts in its Initial packets. Empty is the
    /// ordinary case for a first flight.</summary>
    /// <remarks>
    /// <para>RFC 9000 s17.2.2: an Initial packet carries a Token Length varint followed by
    /// the token. A client sends a token only when it holds one from a Retry or a NEW_TOKEN
    /// frame, so on a first flight this is empty - which is also what RFC 9001 A.2 shows,
    /// with a token length of <c>00</c>.</para>
    /// <para>DOCUMENTED, NOT VALIDATED, and deliberately: the RFC states no length bound on
    /// a token beyond what a varint can express, and a varint outruns any datagram by
    /// forty-odd orders of magnitude, so a bound here would be a guard no caller could
    /// reach. The real constraint is that the token plus the rest of the packet must fit the
    /// datagram, which only task 5 knows, because only task 5 knows the flight.</para>
    /// <para>LIFETIME: not copied. The caller keeps the memory alive and unmutated for the
    /// life of the spec, matching how this namespace treats every other
    /// <c>ReadOnlyMemory&lt;byte&gt;</c>.</para>
    /// </remarks>
    public ReadOnlyMemory<byte> Token { get; init; }

    /// <summary>Gets the size in bytes every UDP datagram carrying an Initial packet is
    /// expanded to.</summary>
    /// <remarks>Bounded below at 1200 by RFC 9000 s14.1's MUST - quoted in full on
    /// <see cref="MinimumInitialDatagramSize"/> - and above by the 65527-byte maximum UDP
    /// payload of s18.2. s14.1 also permits going higher: "Datagrams containing Initial
    /// packets MAY exceed 1200 bytes if the sender believes that the network path and peer
    /// both support the size", which is why the upper bound is the physical one and not
    /// 1200.
    /// <para>HOW the floor is reached is a separate layout choice, and s14.1 names two legal
    /// ways: "by adding PADDING frames to the Initial packet or by coalescing the Initial
    /// packet; see Section 12.2. Initial packets can even be coalesced with invalid packets,
    /// which a receiver will discard." Chromium uses PADDING frames. That is the eighth
    /// candidate fingerprint field, and it is deliberately NOT a knob here: this phase
    /// implements the PADDING route only, so a knob would have exactly one legal value.
    /// Adding it is where the coalescing route lands.</para>
    /// <para>This is not <c>max_udp_payload_size</c> and not the transport's ceiling. See
    /// the three-numbers list on this type.</para></remarks>
    /// <exception cref="ArgumentOutOfRangeException">Below 1200 or above 65527.</exception>
    public int PaddingTarget
    {
        get => _paddingTarget;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(
                value, MinimumInitialDatagramSize, nameof(PaddingTarget));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                value, MaximumUdpPayload, nameof(PaddingTarget));
            _paddingTarget = value;
        }
    }

    /// <summary>Gets the datagram size RFC 8899 s5.1.2 calls BASE_PLPMTU - the size every
    /// datagram is bounded by before path MTU discovery has confirmed anything larger.</summary>
    /// <remarks>
    /// <para>THIS IS THE CEILING, WHERE <see cref="PaddingTarget"/> IS THE FLOOR, and they are
    /// separate numbers that happen to share a default. PaddingTarget expands a datagram
    /// carrying an Initial packet UP to 1200 because RFC 9000 s14.1 requires it; this bounds
    /// every datagram DOWN, because s14.2 says "In the absence of these mechanisms, QUIC
    /// endpoints SHOULD NOT send datagrams larger than the smallest allowed maximum datagram
    /// size". Before this knob existed there was no ceiling at all: an outgoing datagram was
    /// bounded only by the 65527-byte send buffer, and a 32 KB request body produced one
    /// 32837-byte datagram that a DF-set IPv4 socket refuses with SocketError.MessageSize.
    /// </para>
    /// <para>RFC 8899 s5.1.2 recommends exactly this value - "a default BASE_PLPMTU of 1200
    /// bytes is RECOMMENDED" - and RFC 9000 s14.3 makes MIN_PLPMTU the same as BASE_PLPMTU,
    /// which is why the lower bound here is s14's own 1200 and not something smaller.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Below 1200 or above 65527.</exception>
    public int BasePathMtu
    {
        get => _basePathMtu;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(
                value, MinimumInitialDatagramSize, nameof(BasePathMtu));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                value, MaximumUdpPayload, nameof(BasePathMtu));
            _basePathMtu = value;
        }
    }

    /// <summary>Gets whether RFC 8899 path MTU discovery runs, searching upward from
    /// <see cref="BasePathMtu"/> toward <see cref="MaximumPathMtu"/>. On by default.</summary>
    /// <remarks>
    /// <para>ON BY DEFAULT, WHICH IS A DELIBERATE CHOICE BETWEEN TWO CONFORMANT ANSWERS. RFC
    /// 9000 s14.2 makes discovery a SHOULD - "An endpoint SHOULD use DPLPMTUD (Section 14.3) or
    /// PMTUD (Section 14.2.1)" - so running it follows the SHOULD, and declining it falls back
    /// on the same sentence's other half: "In the absence of these mechanisms, QUIC endpoints
    /// SHOULD NOT send datagrams larger than the smallest allowed maximum datagram size", which
    /// is what <see cref="BasePathMtu"/> enforces. Both are legal; the default decides which
    /// one a caller gets without asking.</para>
    /// <para>THE COST IS OBSERVABILITY, AND IT IS REAL. A probe is an extra PING-and-PADDING
    /// datagram at a size nothing else in the flight uses, sent on a schedule chosen by this
    /// implementation - and no capture in this repository records when the imitated client
    /// sends one, at what sizes, or how many. A connection that has to match a capture byte for
    /// byte should set this false; a caller who forgets it exists gets the conformant,
    /// higher-throughput behaviour rather than a silently capped one.</para>
    /// <para>TWO THINGS KEEP THAT COST SMALL. The probe waits for RFC 8899 s5.1.1's condition -
    /// "no application data has been sent since the previous probe packet" - so it never
    /// appears in the opening flight, which is the part of a connection an observer is most
    /// likely to be reading; and the search normally ends after ONE probe, because s5.3.2's
    /// "maximize the gain in PLPMTU from each search step" is taken literally and the first
    /// probe goes straight to <see cref="MaximumPathMtu"/>.</para>
    /// </remarks>
    public bool PathMtuDiscovery { get; init; } = true;

    /// <summary>
    /// Gets what this endpoint writes into RFC 9000 section 17.4's latency spin bit on 1-RTT
    /// packets. The default is <see cref="TlsQuicSpinBitPolicy.Zero"/>.
    /// </summary>
    /// <remarks>ZERO IS NOT A PLACEHOLDER HERE. s17.4 permits any value once the spin bit is
    /// disabled, and always-zero is what Chromium sends, so it is the majority behaviour rather
    /// than an outlier. The knob exists because a client that draws instead cannot otherwise be
    /// imitated - the value used to be a `false` literal in the send path with no property at
    /// all.</remarks>
    /// <summary>
    /// Gets the QUIC version this client's first flight uses - RFC 9368 section 3's Chosen
    /// Version. The default is <see cref="TlsQuicVersion.Version1"/>.
    /// </summary>
    /// <remarks>
    /// <para>THE VERSION MAY STILL MOVE AFTER THIS, and this property does not decide that.
    /// RFC 9368 section 2.3 lets the server answer the first flight in any version the client
    /// listed as available, and this client adopts it when it does. What this sets is where the
    /// connection STARTS.</para>
    /// <para>WHAT THE CLIENT OFFERS IS A TRANSPORT PARAMETER, NOT THIS. The Available Versions
    /// list lives in <c>version_information</c> (0x11) inside
    /// <c>TlsQuicTransportParameterSpec.Parameters</c>, because it is a captured wire field
    /// like any other - see <c>TlsQuicTransportParameterSpec.DrawnVersionInformation</c>. A
    /// profile that sends no such parameter cannot negotiate at all, which is the correct
    /// reading of a capture that does not carry one.</para>
    /// <para>VERSION 2 IS SPEAKABLE BUT NOT COMPLETE: RFC 9369's Retry integrity constants are
    /// not transcribed, so a Retry on a version 2 connection throws. See
    /// <c>TlsQuicRetry</c>.</para>
    /// </remarks>
    public TlsQuicVersion Version { get; init; } = TlsQuicVersion.Version1;

    public TlsQuicSpinBitPolicy SpinBit { get; init; } = TlsQuicSpinBitPolicy.Zero;

    /// <summary>
    /// Gets whether this endpoint draws RFC 9000 section 17.2's QUIC Bit per 1-RTT packet when
    /// the peer has advertised RFC 9287's <c>grease_quic_bit</c>. Off by default.
    /// </summary>
    /// <remarks>
    /// <para>1-RTT ONLY, AND THAT IS THE RFC'S SHAPE RATHER THAN A SHORTCUT. RFC 9287 s3 lets
    /// an endpoint clear the bit only once its PEER has advertised the parameter, and the
    /// peer's transport parameters do not arrive until its EncryptedExtensions - so there is no
    /// packet before the handshake completes on which this could legally be done.</para>
    /// <para>TWO INDEPENDENT HALVES, and this is only one of them. Advertising
    /// <c>grease_quic_bit</c> is a transport-parameter entry - <c>Literal(0x2AB2, [])</c> - and
    /// obliges the RECEIVE path to accept a greased packet; that half needs no knob because the
    /// parameter list already says it. This half is what this endpoint SENDS, and it is off by
    /// default because neither shipped capture greases.</para>
    /// <para>The bit is outside header protection - s5.4.2 masks 0x0f of a long header's first
    /// byte and 0x1f of a short header's, and this is 0x40 - so the choice is plainly visible
    /// to a passive observer rather than inferred.</para>
    /// </remarks>
    public bool GreaseQuicBit { get; init; }

    /// <summary>Gets the largest datagram size path MTU discovery will search up to - RFC 8899
    /// s5.1.2's MAX_PLPMTU.</summary>
    /// <remarks>
    /// <para>Defaults to 1472, which is 1500 - 20 - 8: the UDP payload that fits an
    /// untunnelled Ethernet frame. It is also what a client capture advertises as
    /// max_udp_payload_size, so a search that stops here stops where the imitated client
    /// expects to.</para>
    /// <para>NOT THE SAME THING AS THE ADVERTISED PARAMETER, and deliberately not wired to it.
    /// max_udp_payload_size tells the PEER what this endpoint will RECEIVE; this bounds what it
    /// SENDS. The capture's own note is that "Advertised parameter and actual ceiling are
    /// separate concerns and must not be wired together" - a client may advertise one figure
    /// and send at another, and wiring them would make changing what we tell a server silently
    /// change what we put on the wire.</para>
    /// <para>THE PEER'S OWN max_udp_payload_size STILL BINDS, at run time and independently:
    /// RFC 9000 s14 makes it "an additional limit on the maximum datagram size", so the
    /// effective ceiling is the smaller of this knob, the peer's parameter and what the
    /// transport can carry. This is the local half of that minimum.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Below 1200 or above 65527.</exception>
    public int MaximumPathMtu
    {
        get => _maximumPathMtu;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(
                value, MinimumInitialDatagramSize, nameof(MaximumPathMtu));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                value, MaximumUdpPayload, nameof(MaximumPathMtu));
            _maximumPathMtu = value;
        }
    }

    /// <summary>Gets the byte counts of the successive CRYPTO frames the Initial CRYPTO
    /// stream is carved into. Empty means one frame carrying everything.</summary>
    /// <remarks>
    /// <para>RFC 9000 s19.6 lets a sender split a CRYPTO stream at any offsets it likes, so
    /// where the splits fall is a sender choice and observable. A client capture forces the
    /// issue: the X25519MLKEM768 key share alone is 1216 bytes, so a Chromium-shaped
    /// ClientHello cannot be one datagram and the split is not a corner case.</para>
    /// <para>The final element may be short if the stream runs out; every element must be at
    /// least 1, because a zero-length frame consumes no stream and would let a flight plan
    /// declare progress it does not make.</para>
    /// <para>EMPTY IS NOT "UNSPECIFIED" HERE. It says one frame, which pins the frame count
    /// at one - so an empty value still constrains
    /// <see cref="InitialCryptoFramesPerDatagram"/>, and the cross-check enforces that
    /// rather than skipping. The two empties differ; see the remark on that property.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Any element is below 1.</exception>
    /// <exception cref="ArgumentException">The array is default-valued rather than empty, or
    /// it is set together with an <see cref="InitialCryptoFramesPerDatagram"/> whose elements
    /// do not sum to this array's frame count.</exception>
    public ImmutableArray<int> InitialCryptoFrameByteCounts
    {
        get => _initialCryptoFrameByteCounts;
        init
        {
            ThrowIfDefault(value, nameof(InitialCryptoFrameByteCounts));
            for (var i = 0; i < value.Length; i++)
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(
                    value[i], 1, nameof(InitialCryptoFrameByteCounts));
            }
            ValidateFlightPlanAgree(
                value, _initialCryptoFramesPerDatagram, nameof(InitialCryptoFrameByteCounts));
            _initialCryptoFrameByteCounts = value;
        }
    }

    /// <summary>Gets how many consecutive CRYPTO frames each successive Initial-carrying
    /// datagram holds. Empty means one datagram holding all of them.</summary>
    /// <remarks>
    /// <para>Distinct from <see cref="InitialCryptoFrameByteCounts"/> and not derivable from
    /// it: a client that splits its CRYPTO stream into two frames may put both in one
    /// datagram or one in each, and the two produce different wire images. Both degrees of
    /// freedom are subsystem B's. Note the units differ too - that property counts bytes per
    /// frame, this one counts frames per datagram, which is why neither name says "count"
    /// on its own.</para>
    /// <para>Every element must be at least 1, because a datagram carrying no CRYPTO frame is
    /// not part of a CRYPTO flight. Empty here IS unspecified - any number of frames, in one
    /// datagram - which is the asymmetry with the other property: this one can say nothing,
    /// and that one cannot.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Any element is below 1.</exception>
    /// <exception cref="ArgumentException">The array is default-valued rather than empty, or
    /// it is set together with an <see cref="InitialCryptoFrameByteCounts"/> whose length this
    /// array's elements do not sum to.</exception>
    public ImmutableArray<int> InitialCryptoFramesPerDatagram
    {
        get => _initialCryptoFramesPerDatagram;
        init
        {
            ThrowIfDefault(value, nameof(InitialCryptoFramesPerDatagram));
            for (var i = 0; i < value.Length; i++)
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(
                    value[i], 1, nameof(InitialCryptoFramesPerDatagram));
            }
            ValidateFlightPlanAgree(
                _initialCryptoFrameByteCounts, value, nameof(InitialCryptoFramesPerDatagram));
            _initialCryptoFramesPerDatagram = value;
        }
    }

    /// <summary>Gets the order frame families are written in within one packet.</summary>
    /// <remarks>
    /// <para>WHAT THIS LIST DECIDES TODAY, stated narrowly because a broader statement was
    /// not true of any code. Nothing reorders the frames a caller supplies - that is the
    /// contract <see cref="TlsQuicPacketBuilder"/> keeps, and this spec does not override it.
    /// The single decision this list drives is whether the PADDING
    /// <see cref="TlsQuicDatagramBuilder"/> adds ITSELF leads or trails those frames, and the
    /// rule is: <b>PADDING leads only when this list names PADDING and also names, after it,
    /// some family the packet actually carries.</b> A family absent from this list therefore
    /// moves nothing - a packet whose families are all absent gets trailing PADDING, which is
    /// the default and what RFC 9001 A.2 shows.</para>
    /// <para>An earlier wording said a family absent from this list "is written after every
    /// listed one". That described no behaviour: absent families are not written anywhere in
    /// particular, and read as a rule about PADDING placement it says the opposite of what
    /// the builder does. Task 11's readout quotes this property, so it says only what holds.
    /// </para>
    /// <para>The default is CRYPTO then PADDING, which is the order RFC 9001 A.2's client
    /// Initial uses - one CRYPTO frame at offset 0 followed by PADDING. A family may appear
    /// at most once: a repeat would make the order it declares ambiguous, and an ambiguous
    /// spec is a fingerprint bug that only shows up as a peer's complaint.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">An element is not a defined
    /// <see cref="TlsQuicFrameType"/>.</exception>
    /// <exception cref="ArgumentException">A frame type appears more than once, or the array
    /// is default-valued rather than empty.</exception>
    public ImmutableArray<TlsQuicFrameType> InitialFrameOrder
    {
        get => _initialFrameOrder;
        init
        {
            ThrowIfDefault(value, nameof(InitialFrameOrder));
            for (var i = 0; i < value.Length; i++)
            {
                // The same argument the varint widths make, applied here too: an enum in C#
                // holds any value its underlying type can, a cast from an arbitrary int is
                // the reachable path, and subsystem B is the caller. An undefined family
                // orders nothing today, so the effect is currently harmless - which is
                // exactly the kind of typo that survives until a later task starts keying
                // real behaviour off this list.
                if (!Enum.IsDefined(value[i]))
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(InitialFrameOrder),
                        value[i],
                        "Not a frame type RFC 9000 s19 defines.");
                }
                if (value.IndexOf(value[i]) != i)
                {
                    throw new ArgumentException(
                        $"Frame type {value[i]} appears more than once in the frame order.",
                        nameof(InitialFrameOrder));
                }
            }
            _initialFrameOrder = value;
        }
    }

    /// <summary>Gets the width the long header's Length field is written at. RFC 9000 s16
    /// permits any width that holds the value; see <see cref="TlsQuicVarintWidth"/>.
    /// </summary>
    /// <remarks>RFC 9001 A.2 encodes it as <c>449e</c> - two bytes, and minimal - so the
    /// phase's one external vector gives this knob no coverage at a non-default value.
    /// Whether the width the requested member names is wide enough for the value being
    /// written is a per-packet question the writer answers, not a property of the spec.
    /// <para>THE WRITER IS OPEN; THIS PROPERTY IS NOT YET CONNECTED TO IT, and the two
    /// halves are stated separately because an earlier revision of this remark ran them
    /// together and claimed the knob was honoured. <see cref="TlsQuicPacketHeader"/> and
    /// <see cref="TlsQuicPacketBuilder"/> do carry a Length width all the way to the wire -
    /// witnessed at every legal width by
    /// TlsQuicPacketBuilderTests.TheHeaderLengthVarintIsWrittenAtTheWidthTheSpecAsksFor
    /// (A4 task 4b) - but the width they carry is <c>TlsQuicPacketPlan.LengthVarintWidth</c>,
    /// set per packet by whoever builds the plan. NOTHING IN <c>src/</c> READS THIS
    /// PROPERTY. A4 task 9a-ii is what turns a spec into a <c>TlsQuicPacketPlan</c>, and the
    /// mapping arrives with it.</para>
    /// <para>THE SAME IS TRUE OF <see cref="CryptoOffsetVarintWidth"/> AND
    /// <see cref="CryptoLengthVarintWidth"/>, so fingerprint field 7 is HALF DELIVERABLE
    /// TODAY: A4 task 5 widened the CRYPTO writer, so every varint width in field 7 is
    /// reachable from a <c>TlsQuicPacketPlan</c>, and none is reachable from a
    /// <c>TlsQuicConnectionSpec</c>. The plan's amendments after task 5 record that split.
    /// This is an ordinary not-yet-wired-up rather than a writer discarding a value it was
    /// handed, but it is written down here rather than left silent, because a knob whose
    /// documentation claims a path it does not have is the accepted-and-ignored defect with
    /// an extra step.</para></remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not a defined
    /// <see cref="TlsQuicVarintWidth"/>.</exception>
    public TlsQuicVarintWidth HeaderLengthVarintWidth
    {
        get => _headerLengthVarintWidth;
        init => _headerLengthVarintWidth =
            ValidateVarintWidth(value, nameof(HeaderLengthVarintWidth));
    }

    /// <summary>Gets the width a CRYPTO frame's Offset field is written at. RFC 9000 s16;
    /// see <see cref="TlsQuicVarintWidth"/>.</summary>
    /// <remarks>THE WRITER HAS BEEN OPEN SINCE A4 TASK 5; THIS PROPERTY IS NOT YET
    /// CONNECTED TO IT. The path that exists runs
    /// <see cref="TlsQuicPacketPlan.CryptoOffsetVarintWidth"/> to
    /// <see cref="TlsQuicDatagramBuilder"/> to <see cref="TlsQuicFrames.WriteFrame"/> to
    /// <see cref="TlsQuicStreamFrames.WriteCryptoFrameFields"/>, which resolves the width
    /// through
    /// <see cref="QuicVariableLengthInteger.GetEncodedLength(ulong, TlsQuicVarintWidth)"/>.
    /// It starts at the PLAN. Before task 5 the writer always picked the shortest form and
    /// no code path carried a width at all; task 5 fixed the writer, and the spec-to-plan
    /// mapping that would let this property reach it belongs to A4 task 9a-ii, which does
    /// not exist yet. See <see cref="HeaderLengthVarintWidth"/> for what that means for
    /// fingerprint field 7.
    /// <para>A width too narrow for the offset being written is a caller error and throws
    /// from the writer, not from here: whether 1 byte holds an offset is a per-frame
    /// question and this property is set once, before any offset exists. Witnessed at a
    /// non-minimal width, on the plan, by
    /// TlsQuicDatagramBuilderTests.CryptoOffsetAndLengthVarintsAreWrittenAtTheWidthsThePlanAsksFor.
    /// </para></remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not a defined
    /// <see cref="TlsQuicVarintWidth"/>.</exception>
    public TlsQuicVarintWidth CryptoOffsetVarintWidth
    {
        get => _cryptoOffsetVarintWidth;
        init => _cryptoOffsetVarintWidth =
            ValidateVarintWidth(value, nameof(CryptoOffsetVarintWidth));
    }

    /// <summary>Gets the width a CRYPTO frame's Length field is written at. RFC 9000 s16;
    /// see <see cref="TlsQuicVarintWidth"/>.</summary>
    /// <remarks>THE SAME STATE AS <see cref="CryptoOffsetVarintWidth"/>, by the same path:
    /// the writer takes a width, the width comes from the plan, and nothing maps this
    /// property onto one yet. See that remark; it is not repeated here.
    /// <para>RFC 9001 A.2 encodes this field as <c>40f1</c>, minimal, so the vector is
    /// blind to it either way - which is why the witness named there is hand-derived
    /// rather than leg 1.</para></remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not a defined
    /// <see cref="TlsQuicVarintWidth"/>.</exception>
    public TlsQuicVarintWidth CryptoLengthVarintWidth
    {
        get => _cryptoLengthVarintWidth;
        init => _cryptoLengthVarintWidth =
            ValidateVarintWidth(value, nameof(CryptoLengthVarintWidth));
    }

    /// <summary>Gets the inclusive range a fresh <c>initial_rtt</c> is drawn from for each
    /// connection, or <see langword="null"/> when the client does not advertise one.
    /// </summary>
    /// <remarks>
    /// <para>A POLICY, NEVER A VALUE. Chromium's private transport parameter 12583 is drawn
    /// per connection - uQUIC models it as <c>ChromeRandomInitialRTT()</c> - so pinning it
    /// is itself a fingerprint. A client capture renders it <c>12583:AUTO</c> rather than
    /// embedding the number for exactly that reason.</para>
    /// <para>The default is <see langword="null"/>, and that is deliberate rather than a
    /// missing constant: the capture publishes one observed draw, 192859, and one sample is
    /// not a range. Nothing in the repo states the bounds Chromium draws between, so
    /// inventing them here would put an unsourced constant in the one field whose whole
    /// point is that it must not be a constant. Subsystem B supplies the range when a
    /// capture or uQUIC's source establishes it.</para>
    /// <para>NULL NO LONGER MEANS THE PARAMETER IS NOT SENT, and task B5 is where that
    /// changed. <c>TlsQuicTransportParameterSpec</c>'s <c>DrawnInitialRtt</c> entry reads this
    /// field per composition and falls back to the range the parameter profile itself
    /// declares when it is null - so a preset emits a fresh draw either way, and this
    /// field's job is to OVERRIDE that profile's range rather than to switch the parameter on.
    /// A caller wanting no <c>initial_rtt</c> at all builds the entry with no fallback range,
    /// or leaves the entry out of the list; both are decisions taken in the parameter list,
    /// where the rest of the wire order lives.</para>
    /// <para>THE VALUE IS STILL NEVER WRITTEN HERE. This field is a policy - two bounds - and
    /// the microseconds that reach the wire are drawn inside <c>Compose</c>, once per
    /// connection, which is why a spec may be reused across connections without pinning the
    /// parameter. The composed set does not reach a ClientHello until task B8 wires it.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">The minimum is not positive, or the
    /// maximum is below the minimum.</exception>
    public (TimeSpan Minimum, TimeSpan Maximum)? InitialRttRange
    {
        get => _initialRttRange;
        init
        {
            if (value is { } range)
            {
                ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(
                    range.Minimum, TimeSpan.Zero, nameof(InitialRttRange));
                ArgumentOutOfRangeException.ThrowIfLessThan(
                    range.Maximum, range.Minimum, nameof(InitialRttRange));
            }
            _initialRttRange = value;
        }
    }

    /// <summary>The default <see cref="AckRangeLimit"/>. Named, and referenced by
    /// <see cref="TlsQuicAckTracker"/>'s own constructor default, so that the two cannot
    /// drift into disagreeing about what an unconfigured tracker does.</summary>
    internal const int DefaultAckRangeLimit = 32;

    /// <summary>Gets how many ACK Ranges this endpoint retains and reports per packet
    /// number space.</summary>
    /// <remarks>
    /// <para>RFC 9000 s13.2.3 REQUIRES A BOUND AND NAMES NO NUMBER: "A receiver limits
    /// the number of ACK Ranges (Section 19.3.1) it remembers and sends in ACK frames,
    /// both to limit the size of ACK frames and to avoid resource exhaustion." It fixes
    /// only which end is dropped - "If it does not [fit within a single QUIC packet],
    /// then older ranges (those with the smallest packet numbers) are omitted" - which
    /// <see cref="TlsQuicAckTracker"/> implements as a rule. The count itself is a
    /// receiver's choice.</para>
    /// <para>A KNOB RATHER THAN A CONSTANT because it is observable. How many ranges an
    /// ACK frame carries, and therefore how often the peer sees an acknowledgement
    /// silently dropped off the bottom, is visible to anyone reading the wire, and it
    /// varies between stacks - so it is a candidate fingerprint field on the same
    /// footing as <see cref="PacketNumberEncodedLength"/>, not a detail this library gets
    /// to fix. The sibling choice, ack_delay_exponent, is deliberately NOT here: it is a
    /// transport parameter, already carried in
    /// <see cref="TlsQuicTransportParameters"/>, and a second copy on the spec would be
    /// a second source of truth for one advertised value.</para>
    /// <para>THE DEFAULT OF 32 IS A PLACEHOLDER, NOT EVIDENCE. A client capture
    /// (the preset that measured it)
    /// says nothing about ACK ranges, and there is no published vector for one, so this
    /// belongs in task 11's not-yet-known-from-the-capture category alongside the initial
    /// packet number. It is large enough that the A4 handshake, whose flights are a
    /// handful of packets per space, never reaches it.</para>
    /// <para>Counted in retained inclusive ranges, which is one more than the wire's ACK
    /// Range Count field; see <see cref="TlsQuicAckTracker"/>'s constructor for why that
    /// reading of s13.2.3's "ACK Ranges" was chosen.</para>
    /// <para>NOT YET READ BY ANYTHING UNDER <c>src/</c>, AND SAYING SO IS THE POINT.
    /// <see cref="TlsQuicAckTracker"/> defaults its own <c>maximumAckRanges</c> parameter off
    /// <see cref="DefaultAckRangeLimit"/>, so an unconfigured tracker behaves as this property
    /// says - but nothing constructs a tracker FROM a spec, so setting this property changes
    /// no byte. <b>Task 9a-ii owns that wiring</b>, together with the
    /// <see cref="HeaderLengthVarintWidth"/> / <see cref="CryptoOffsetVarintWidth"/> /
    /// <see cref="CryptoLengthVarintWidth"/> mapping the task-5 amendment assigned it: this is
    /// the same defect and it is recorded the same way rather than left to be rediscovered.
    /// The check is one grep - <c>spec\.AckRangeLimit</c> - and the task-4b amendment already
    /// ruled on the alternative: "Do not quietly leave the knobs present-but-inert: a knob
    /// that accepts a value and ignores it is worse than an absent one." It is kept rather
    /// than deleted because the tracker parameter it will feed already exists and is
    /// witnessed; what is missing is one line of construction, not a design.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Below 1. s19.3 makes First ACK Range
    /// mandatory, so every ACK frame names at least one range.</exception>
    public int AckRangeLimit
    {
        get => _ackRangeLimit;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1, nameof(AckRangeLimit));
            _ackRangeLimit = value;
        }
    }

    /// <summary>Gets whether packets coalesced into one datagram are ordered by ascending
    /// encryption level.</summary>
    /// <remarks>
    /// <para>RFC 9000 s12.2 imposes no ordering - its coalescing rules are about connection
    /// IDs and about the last packet being the only one that may omit a Length - but it does
    /// give a reason for ascending: "Senders SHOULD order packets in a datagram in increasing
    /// order of encryption level", because it "makes it more likely that the receiver will be
    /// able to process all the packets in a single pass". A peer meeting our Handshake packet
    /// ahead of the Initial one that carries the keys for it would have to buffer.</para>
    /// <para>SO WHY IS IT A KNOB AND NOT A CONSTANT. The order is plainly visible to anyone
    /// reading the wire and it is not the same in every stack, which puts it on the same
    /// footing as <see cref="InitialFrameOrder"/> and <see cref="PacketNumberEncodedLength"/>:
    /// a fingerprint dimension subsystem B varies, and the one the plan's design constraints
    /// name as "per-datagram flight plan". <see langword="false"/> emits descending order,
    /// which is legal and which s12.2 advises against; nothing in this library chooses it.
    /// </para>
    /// <para>READ BY <see cref="TlsQuicConnection"/>'s answer builder, and witnessed there in
    /// the strong sense the notice at the top of this file asks for: setting it changes which
    /// packet a peer meets first in the datagram this client sends. There is no guard to
    /// witness - a <see cref="bool"/> has no out-of-range value.</para>
    /// </remarks>
    public bool CoalesceAscendingByLevel { get; init; } = true;

    /// <summary>Gets whether an ACK frame is written before the CRYPTO frames of the same
    /// packet rather than after them.</summary>
    /// <remarks>
    /// <para>RFC 9000 IMPOSES NO FRAME ORDER INSIDE A PACKET, AND THE CAPTURE OBSERVES NONE
    /// FOR ACK, so neither value here is derived from ground truth - which is exactly why it
    /// is a knob. The default is <see langword="true"/> because s13.2.1's "An endpoint MUST
    /// acknowledge all ack-eliciting Initial and Handshake packets immediately" makes the ACK
    /// the part of the packet that must not be squeezed out by anything else, but that is a
    /// preference and not a rule, and an earlier revision of the connection loop hardcoded it
    /// while declaring it ungrounded. Declared is not knobbed: task 11 cannot report a field
    /// the connection fixes.</para>
    /// <para>DISTINCT FROM <see cref="InitialFrameOrder"/>, which decides only whether the
    /// PADDING <see cref="TlsQuicDatagramBuilder"/> adds ITSELF leads or trails, and which
    /// says nothing about frames a caller supplies. This property is about the caller's own
    /// list, so the two cannot be folded together without changing what one of them means.
    /// </para>
    /// <para>READ BY <see cref="TlsQuicConnection"/>'s answer builder, and witnessed there by
    /// decrypting this client's own packet and reading the frame order out of the plaintext.
    /// There is no guard to witness - a <see cref="bool"/> has no out-of-range value.</para>
    /// </remarks>
    public bool AckLeadsInPacket { get; init; } = true;

    /// <summary>Gets the six RFC 9000 s18.2 flow-control limits this client advertises, and
    /// therefore also the limits it enforces on what the peer sends.</summary>
    /// <remarks>
    /// <para>THE ONE SET OF TRANSPORT PARAMETERS THAT IS IN THIS TYPE, AND THIS TYPE'S HEADER
    /// SAYS THE OPPOSITE. That header's claim - "transport parameters ride inside the
    /// ClientHello and are set through ClientHelloBuilder.WithQuicTransportParameters" - is
    /// still true of where the BYTES go, and <see cref="TlsQuicLocalFlowControlSpec"/> emits
    /// exactly those bytes. What is different about these six is that the connection has to
    /// read them back: RFC 9000 s4.1 makes a receiver's limits the ones IT advertised, so the
    /// number <see cref="TlsQuicStreamSet"/> enforces and the number on the wire must be the
    /// same number. Typing it twice is how they diverge, and Finding 2 of the HTTP/3 spike is
    /// what that divergence looked like.</para>
    /// <para>WIRE ORDER IS NOT SETTLED HERE.
    /// <see cref="TlsQuicLocalFlowControlSpec.ToTransportParameters"/> emits ascending by id
    /// and a client capture's order is neither ascending nor the RFC's presentation order -
    /// "This ordering is the fingerprint." Matching it is subsystem B's, which owns the whole
    /// parameter list including the four this spec does not carry.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Set to <see langword="null"/>.</exception>
    public TlsQuicLocalFlowControlSpec LocalFlowControl
    {
        get => _localFlowControl;
        init => _localFlowControl = value
            ?? throw new ArgumentNullException(nameof(LocalFlowControl));
    }

    /// <summary>Gets the ordered transport-parameter list this client emits, including the
    /// six <see cref="LocalFlowControl"/> places into it.</summary>
    /// <remarks>
    /// <para>THE ANSWER TO THE PARAGRAPH ABOVE, which says wire order "is not settled here"
    /// and that the whole list belongs to subsystem B.
    /// <see cref="TlsQuicTransportParameterSpec"/> is that list, and it lives on this type so
    /// that one object carries both the six numbers and the order they go out in - which is
    /// what lets <see cref="TlsQuicTransportParameterSpec.Compose"/> PLACE those six rather
    /// than restate them. Read that type's remarks before adding a value to it.</para>
    /// <para>IT IS READ, as of task B8 (<c>f83331f</c>).
    /// <see cref="SharpTls.TlsQuicClientHelloProfileFactory"/> passes
    /// <see cref="TlsQuicTransportParameterSpec.Compose"/>'s result to
    /// <c>ClientHelloBuilder.WithQuicTransportParameters</c>, and task B11 (<c>2247128</c>)
    /// proved it on the wire: reordering this list moved <c>perk_hash</c> at
    /// <c>fp.impersonate.pro</c> and left <c>perk_hash_normalized</c> byte-identical, over
    /// 12 attempts.</para>
    /// <para>THE PRIOR TEXT HERE WAS A SELF-CHECKING COMMENT WHOSE CHECK DECAYED FIRST.
    /// It said "NOTHING READS IT YET" and offered
    /// <c>grep -rn "spec\.TransportParameters" src/</c> as the proof. That grep is
    /// case-sensitive and never matched the actual call site,
    /// <c>_connectionSpec.TransportParameters</c> - so it returned nothing both before and
    /// after B8, and went on reading as confirmation while the claim it guarded turned false.
    /// A grep pinned to one spelling of a receiver is not a check. Found by task B10.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Set to <see langword="null"/>.</exception>
    public TlsQuicTransportParameterSpec TransportParameters
    {
        get => _transportParameters;
        init => _transportParameters = value
            ?? throw new ArgumentNullException(nameof(TransportParameters));
    }

    /// <summary>Gets the loss-recovery and congestion-control values this client's behaviour
    /// is shaped by: twelve of the A3 plan's fourteen knobs, the other two being
    /// <see cref="InitialRttRange"/> and <see cref="AckRangeLimit"/>, which already live on
    /// this type.</summary>
    /// <remarks>
    /// <para>A SUB-SPEC RATHER THAN TWELVE MORE PROPERTIES, following
    /// <see cref="LocalFlowControl"/> and <see cref="TransportParameters"/>, which are this
    /// type's two precedents for one. Read <see cref="TlsQuicRecoverySpec"/>'s remarks before
    /// adding a value to it - in particular why every one of these is on the SPEC and not on
    /// <see cref="TlsQuicConnectionOptions"/>, which is the opposite of where a recovery
    /// implementer reaches.</para>
    /// <para>NOTHING READS IT YET, and the grep that would catch that changing is
    /// <c>Spec\.Recovery</c> - written case-insensitively on the receiver, because task B10
    /// found the previous self-checking comment on this type pinned to one spelling of a
    /// receiver and therefore matching nothing both before and after the wiring it claimed to
    /// guard. Tasks A3-3 through A3-11 wire these one at a time and task A3-12 renders
    /// them.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Set to <see langword="null"/>.</exception>
    public TlsQuicRecoverySpec Recovery
    {
        get => _recovery;
        init => _recovery = value ?? throw new ArgumentNullException(nameof(Recovery));
    }

    // The one rule that spans two properties: a per-datagram frame count plan must account
    // for every CRYPTO chunk and no others.
    //
    // WHY IT IS CHECKED IN BOTH SETTERS RATHER THAN IN A Validate() METHOD. An object
    // initialiser runs its setters in source order, so whichever of the two is written
    // second is the one that sees both values - and putting the check in both means it does
    // not matter which that is. A Validate() the caller must remember to call would leave
    // every spec built directly by tasks 4b and 5 unchecked, which is most of them.
    //
    // THE SKIP IS NOT SYMMETRIC, because the two empties do not mean the same thing. An
    // empty datagram plan is genuinely unspecified - any number of frames, in one datagram -
    // so it claims nothing and the check has nothing to check. An empty byte-count list is
    // NOT unspecified: it means one CRYPTO frame carrying the whole stream, which pins the
    // frame count at exactly one. An earlier revision skipped on either, and so accepted a
    // datagram plan claiming two frames next to a split declaring one.
    //
    // A witness per order:
    // TlsQuicConnectionSpecTests.FrameCountsThatDoNotAccountForEveryChunkAreRejectedWhenTheChunksComeSecond
    // and TlsQuicConnectionSpecTests.FrameCountsThatDoNotAccountForEveryChunkAreRejectedWhenTheCountsComeSecond,
    // with the skip itself pinned by
    // TlsQuicConnectionSpecTests.EitherHalfOfTheFlightPlanAloneIsAccepted.
    //
    // The comparison is an equality and not a one-sided bound, because an over-count is as
    // wrong as an under-count: it tells a datagram to carry a CRYPTO frame the split never
    // produced. Weakening it to `<` survived a mutation sweep until
    // TlsQuicConnectionSpecTests.FrameCountsThatClaimMoreChunksThanTheSplitProducesAreRejected
    // was added.
    private static void ValidateFlightPlanAgree(
        ImmutableArray<int> frameByteCounts,
        ImmutableArray<int> framesPerDatagram,
        string paramName)
    {
        // IsEmpty, not IsDefaultOrEmpty: ThrowIfDefault rejects a default-valued array in
        // both setters before either reaches here, and both fields initialise to an empty
        // array rather than a default one, so no default value can arrive. A defensive
        // IsDefaultOrEmpty would be a branch no input can take.
        if (framesPerDatagram.IsEmpty)
        {
            return;
        }
        var declared = frameByteCounts.IsEmpty ? 1 : frameByteCounts.Length;
        var planned = 0L;
        for (var i = 0; i < framesPerDatagram.Length; i++)
        {
            planned += framesPerDatagram[i];
        }
        if (planned != declared)
        {
            throw new ArgumentException(
                $"The per-datagram CRYPTO frame counts account for {planned} frames but the " +
                $"CRYPTO split declares {declared}.",
                paramName);
        }
    }

    // default(ImmutableArray<T>) wraps a null array, so every member of it - Length, IsEmpty,
    // the indexer - throws NullReferenceException. That is reachable from a hand-populated
    // spec (an uninitialised field, a helper that returns one on a miss), and letting it
    // through would break this type's promise that a spec which exists is a spec in range,
    // with the least diagnosable exception in .NET and no ParamName. It is rejected the way
    // every sibling here rejects bad input.
    //
    // Witnessed once per array property:
    // TlsQuicConnectionSpecTests.ADefaultValuedCryptoSplitIsRejected,
    // TlsQuicConnectionSpecTests.ADefaultValuedDatagramFrameCountPlanIsRejected and
    // TlsQuicConnectionSpecTests.ADefaultValuedFrameOrderIsRejected.
    private static void ThrowIfDefault<T>(ImmutableArray<T> value, string paramName)
    {
        if (value.IsDefault)
        {
            throw new ArgumentException(
                "A default-valued array carries no elements and no length; pass an empty one "
                + "to mean unspecified.",
                paramName);
        }
    }

    // Enum.IsDefined rather than a range test: TlsQuicVarintWidth's members are 0, 1, 2, 4
    // and 8, so 3, 5, 6 and 7 all sit inside any range that admits the legal ones. A cast
    // from an arbitrary int is the reachable path, and subsystem B is the caller.
    private static TlsQuicVarintWidth ValidateVarintWidth(TlsQuicVarintWidth value, string paramName)
    {
        if (!Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(
                paramName, value, "Not a variable-length integer width RFC 9000 s16 defines.");
        }
        return value;
    }
}

// ============================================================================
// THE C9 MUTATION LEDGER - THE TYPE BELOW
// ============================================================================
//
// PREFIXED C9- RATHER THAN PLAINLY NUMBERED, because this file already carries a numbered
// two-item checklist above (WITNESS THE GUARD / SAY WHETHER ANYTHING READS IT) which the
// ordinary ledger grep matches. The prefix keeps each list countable on its own.
//
//   ROWS BELOW                   22  = numbered C9-01 to C9-22 with no gaps
//   KILLED WHEN FIRST RUN        22  = 22 rows, less 0 [WAS-SURVIVOR] and 0 [SURVIVED]
//   SURVIVED, THEN WITNESSED      0
//   SURVIVING STILL               0
//
// Three greps, anchored to a numbered row so these lines do not match themselves. Run from
// this file's directory:
//   `grep -cE '^// +C9-[0-9]+\. ' TlsQuicConnectionSpec.cs`                    must return 22
//   `grep -cE '^// +C9-[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicConnectionSpec.cs`   must return 0
//   `grep -cE '^// +C9-[0-9]+\..*\[SURVIVED\]' TlsQuicConnectionSpec.cs`       must return 0
//
// Run in a git worktree that was removed afterwards, against
// `dotnet test --filter "FullyQualifiedName~Quic"`, counts per xUnit CASE. NO SURVIVOR HERE IS
// NOT A BOAST: this type is six fields, two range guards and three total functions, so a clean
// sweep is what it should produce. The interesting figures are the SHAPES - rows C9-01 to
// C9-06 each kill exactly one theory case and no other row's, and the emit rows kill a
// different test from the read rows, which is what says the two are separately witnessed.
//
// THE HARNESS WAS CHECKED IN BOTH DIRECTIONS FIRST - a known-bad edit reported KILLED with 10
// failures and an inert comment rewording reported SURVIVED with 0 - because a harness that
// cannot report a survivor makes a clean sweep meaningless.
//
// ---- the six capture defaults, one row each ----
//  C9-01. initial_max_data default moved by one    ONLY EveryFlowControlDefaultIsSectionEighteenTwosZero
//  C9-02. initial_max_stream_data_bidi_local default moved by one  ONLY EveryFlowControlDefaultIsSectionEighteenTwosZero
//  C9-03. initial_max_stream_data_bidi_remote default moved by one  ONLY EveryFlowControlDefaultIsSectionEighteenTwosZero
//  C9-04. initial_max_stream_data_uni default moved by one  ONLY EveryFlowControlDefaultIsSectionEighteenTwosZero
//  C9-05. initial_max_streams_bidi default moved by one  ONLY EveryFlowControlDefaultIsSectionEighteenTwosZero
//  C9-06. initial_max_streams_uni default moved by one  ONLY EveryFlowControlDefaultIsSectionEighteenTwosZero
//
// MOVED BY ONE AND NOT ZEROED, deliberately. Zeroing a default breaks half the suite and proves
// only that something reads it; a default off by one fails exactly the theory case that names
// that parameter and nothing else, which is what proves the capture value itself is pinned.
//
// ---- the one declared placeholder ----
//  C9-07. ReceiveWindowUpdateDivisor 2 -> 1        ONLY CrossingTheUpdateThresholdQueuesOneMaxStreamDataAndOneMaxData
//  C9-08. ReceiveWindowUpdateDivisor 2 -> 4        ONLY CrossingTheUpdateThresholdQueuesOneMaxStreamDataAndOneMaxData
//
// A PLACEHOLDER IS STILL A CONSTANT WITH BEHAVIOUR, so it is mutated in both directions. The
// value is not evidence about Chromium and the tests do not claim it is - what they pin is
// that the divisor is the number the threshold is computed from, so changing it changes when a
// grant goes out and a reader cannot mistake it for decoration.
//
// ---- the two range guards ----
//  C9-09. the varint guard never fires             4 tests
//  C9-10. the varint guard is off by one: > becomes >=  6 tests
//  C9-11. the stream-count guard never fires       2 tests
//  C9-12. the stream-count guard is off by one: > becomes >=  2 tests
//
// ROWS C9-10 AND C9-12 ARE WHY BOTH BOUNDARY VALUES ARE ASSERTED. s19.11's "cannot exceed 2^60"
// makes 2^60 itself legal, and a guard that refused it would be rejecting a caller the RFC
// permits; without the accepted-at-the-ceiling half of those tests the strictness is unpinned.
// ROW C9-10's six are four validation cases plus two from the streams file, which reads a limit
// set to the varint maximum.
//
// ---- what actually reaches the wire ----
//  C9-13. initial_max_data is not emitted at all   3 tests
//  C9-14. 0x05 is emitted carrying 0x06's value    2 tests
//  C9-15. 0x09 is emitted carrying 0x08's value    3 tests
//
// THESE ARE THE ROWS THAT MAKE THE KNOB A KNOB. A field that validates and is then dropped on
// the way to the ClientHello is exactly the defect C9 exists to close, so the emit path is
// mutated separately from the reads. ROW C9-14 is the 0x05/0x06 swap in the direction this
// file owns; the other direction lives in TlsQuicPeerFlowControlBudget's ledger.
//
// ---- the two total functions, and the property ----
//  C9-16. ReceiveLimitFor: client bidi takes 0x06  ONLY ReceiveLimitForPicksTheParameterSection182ScopesToThatStreamType
//  C9-17. ReceiveLimitFor: server bidi takes 0x05  2 tests
//  C9-18. ReceiveLimitFor: server uni takes initial_max_data  3 tests
//  C9-19. ReceiveLimitFor: the send-only row grants credit  ONLY ReceiveLimitForPicksTheParameterSection182ScopesToThatStreamType
//  C9-20. PeerStreamLimitFor: the two directions swapped  2 tests
//  C9-21. the LocalFlowControl null guard never fires  ONLY ANullLocalFlowControlSpecIsRejectedRatherThanLeavingTheConnectionUnlimited
//  C9-22. the spec's default LocalFlowControl is not a default one  3 tests
//
// ROW C9-19 IS THE ROW THAT LOOKS POINTLESS AND IS NOT. The 0x02 arm returns 0 for a stream
// nothing can legally receive on, so it is tempting to call it unreachable and leave it
// unwitnessed - but the theory row that asserts the 0 kills the mutant, and without it a later
// edit could hand a send-only stream a receive window with nothing objecting.

/// <summary>The six RFC 9000 s18.2 flow-control limits this client advertises: the bytes it
/// puts on the wire, and the same numbers the receive side enforces against the peer.</summary>
/// <remarks>
/// <para>WHY THIS EXISTS AT ALL - THE DEFECT IT CLOSES. Before it,
/// <c>QuicPublicEndpointInteropTests</c> advertised two parameters, neither of them one of
/// these six, and s18.2's blanket rule made every one of them 0: "Transport parameters have a
/// default value of 0 if the transport parameter is absent, unless otherwise stated"
/// (rfc9000-section18-transport-parameters.txt lines 62-64), reinforced for these six at lines
/// 139 and 148 - "If this parameter is absent or zero, the peer cannot open bidirectional
/// streams until a MAX_STREAMS frame is sent" - and at lines 250-252, "If the transport
/// parameter is absent, streams of that type start with a flow control limit of 0." A server
/// under those limits may open no stream and send no byte, so HTTP/3 cannot start. A
/// handshake-only test never notices, which is how it survived to the first GET.</para>
/// <para>EVERY DEFAULT BELOW IS A CLIENT CAPTURE'S, and the capture bounds all six -
/// <c>the preset that measured it</c>,
/// the "QUIC transport parameters, in wire order" table, rows 4, 5, 6, 7, 11 and 12. There is
/// no placeholder among the six. The one declared placeholder in this type is
/// <see cref="ReceiveWindowUpdateDivisor"/>, which the capture cannot bound because it is not
/// a parameter.</para>
/// <para>VALIDATED AS SET, like every other knob in this file, so a spec that exists is a spec
/// in range. The three byte limits and initial_max_data are bounded only by what a
/// variable-length integer can carry (s16's 2^62-1); the two stream counts are bounded by
/// s19.11's 2^60, quoted on <see cref="TlsQuicFlowControlFrames.MaximumStreamCount"/>, because
/// s18.2 makes setting one "equivalent to sending a MAX_STREAMS ... with the same value" and a
/// value a MAX_STREAMS frame may not carry is not one a parameter may claim either.</para>
/// </remarks>
internal sealed class TlsQuicLocalFlowControlSpec
{
    // RFC 9000 s18.2's DEFAULT FOR AN ABSENT PARAMETER, transcribed from
    // reference-captures/rfc9000-section18-transport-parameters.txt rather than recalled. The
    // section says it three times, and all three land on zero:
    //
    //   line 63, the preamble covering every integer parameter including initial_max_data:
    //     "Transport parameters have a default value of 0 if the transport parameter is
    //      absent, unless otherwise stated."
    //   line 251, the three stream-data limits:
    //     "If the transport parameter is absent, streams of that type start with a flow
    //      control limit of 0."
    //   lines 139 and 148, the two stream counts:
    //     "If this parameter is absent or zero, the peer cannot open bidirectional /
    //      unidirectional streams until a MAX_STREAMS frame is sent."
    //
    // ZERO IS THE HONEST DEFAULT NOW THAT THE LIBRARY ADVERTISES NOTHING. These six used to
    // hold a captured browser's numbers, which meant a spec that advertised none of the six
    // still ENFORCED that browser's limits - the advertise/enforce split
    // TlsQuicLocalFlowControlSpec.AsAdvertisedBy exists to close. Matching s18.2 makes the
    // stored value and the enforced value agree by construction for a spec that lists no
    // slots, which is what the default list is.
    //
    // A PERSONA SETS ALL SIX AND PLACES THE SLOTS FOR THEM. Leaving one unset is now visible
    // as a limit of zero rather than invisible as somebody else's number.
    private readonly ulong _initialMaxData;
    private readonly ulong _initialMaxStreamDataBidiLocal;
    private readonly ulong _initialMaxStreamDataBidiRemote;
    private readonly ulong _initialMaxStreamDataUni;
    private readonly ulong _initialMaxStreamsBidi;
    private readonly ulong _initialMaxStreamsUni;

    /// <summary>How much of a receive window is spent before this endpoint sends a MAX_DATA or
    /// MAX_STREAM_DATA raising it: an update goes out once the credit still outstanding falls
    /// below the window divided by this.</summary>
    /// <remarks>A DECLARED PLACEHOLDER, and it is the only one in this type. RFC 9000 s19.9
    /// and s19.10 say what the frames mean and never say when to send one, and the that client
    /// capture observes a ClientHello - it cannot observe a mid-connection frame at all, so
    /// there is no value here that the capture bounds. 2 means "top the window up once half of
    /// it is gone", which is the ordinary shape and is small enough that a transfer never
    /// stalls waiting for credit; it is NOT evidence about Chromium and task C12's readout
    /// carries it in the not-known-from-the-capture column. The task that could settle it is a
    /// capture of a large response body, which this repository does not have.</remarks>
    internal const ulong ReceiveWindowUpdateDivisor = 2;

    /// <summary>Gets initial_max_data (0x04): every byte the peer may send us across every
    /// stream combined, before a MAX_DATA raises it.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Above
    /// <see cref="QuicVariableLengthInteger.MaximumValue"/>.</exception>
    internal ulong InitialMaxData
    {
        get => _initialMaxData;
        init => _initialMaxData = Bytes(value, nameof(InitialMaxData));
    }

    /// <summary>Gets initial_max_stream_data_bidi_local (0x05). s18.2 scopes it to "newly
    /// created bidirectional streams opened by the endpoint that sends the transport
    /// parameter" - we send it, so it bounds what the peer may send us on the bidirectional
    /// streams WE open, s2.1's 0x00 type.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Above
    /// <see cref="QuicVariableLengthInteger.MaximumValue"/>.</exception>
    internal ulong InitialMaxStreamDataBidiLocal
    {
        get => _initialMaxStreamDataBidiLocal;
        init => _initialMaxStreamDataBidiLocal =
            Bytes(value, nameof(InitialMaxStreamDataBidiLocal));
    }

    /// <summary>Gets initial_max_stream_data_bidi_remote (0x06). s18.2 scopes it to streams
    /// "opened by the endpoint that receives the transport parameter" - the peer - so it
    /// bounds server-initiated bidirectional streams, s2.1's 0x01 type.</summary>
    /// <remarks>THE MIRROR IMAGE OF THE FLIP <see cref="TlsQuicPeerFlowControlBudget"/> CALLS
    /// ITS MOST LIKELY DEFECT. There the parameter is the peer's and we are the receiver;
    /// here it is ours and we are the sender, so the two files take opposite members for the
    /// same stream type. Both are right and neither is a copy of the other.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Above
    /// <see cref="QuicVariableLengthInteger.MaximumValue"/>.</exception>
    internal ulong InitialMaxStreamDataBidiRemote
    {
        get => _initialMaxStreamDataBidiRemote;
        init => _initialMaxStreamDataBidiRemote =
            Bytes(value, nameof(InitialMaxStreamDataBidiRemote));
    }

    /// <summary>Gets initial_max_stream_data_uni (0x07): what the peer may send on each
    /// unidirectional stream it opens - s2.1's 0x03 type, which is where an HTTP/3 server's
    /// control, QPACK encoder and QPACK decoder streams arrive.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Above
    /// <see cref="QuicVariableLengthInteger.MaximumValue"/>.</exception>
    internal ulong InitialMaxStreamDataUni
    {
        get => _initialMaxStreamDataUni;
        init => _initialMaxStreamDataUni = Bytes(value, nameof(InitialMaxStreamDataUni));
    }

    /// <summary>Gets initial_max_streams_bidi (0x08): how many bidirectional streams the peer
    /// may open against us.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Above
    /// <see cref="TlsQuicFlowControlFrames.MaximumStreamCount"/>.</exception>
    internal ulong InitialMaxStreamsBidi
    {
        get => _initialMaxStreamsBidi;
        init => _initialMaxStreamsBidi = Streams(value, nameof(InitialMaxStreamsBidi));
    }

    /// <summary>Gets initial_max_streams_uni (0x09): how many unidirectional streams the peer
    /// may open against us. RFC 9114 s6.2 needs at least three of them for HTTP/3.</summary>
    /// <remarks>NOT FLOORED AT THREE HERE. s6.2's requirement is HTTP/3's and this type is
    /// QUIC's; the connection carries the HTTP/3 floor as
    /// <c>TlsQuicConnectionOptions.RequiredPeerUnidirectionalStreams</c>, in the direction
    /// where a violation is the PEER's and can actually be refused. A floor here would refuse
    /// our own caller for a rule about someone else's parameters.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Above
    /// <see cref="TlsQuicFlowControlFrames.MaximumStreamCount"/>.</exception>
    internal ulong InitialMaxStreamsUni
    {
        get => _initialMaxStreamsUni;
        init => _initialMaxStreamsUni = Streams(value, nameof(InitialMaxStreamsUni));
    }

    /// <summary>Emits these six as RFC 9000 s18.2 transport parameters, ready to go into the
    /// ClientHello through <c>ClientHelloBuilder.WithQuicTransportParameters</c>.</summary>
    /// <remarks>ASCENDING BY ID, WHICH IS NOT THE CAPTURE'S ORDER. The capture's table is
    /// headed "in wire order" and says "This ordering is the fingerprint. It is not sorted,
    /// and it is not the RFC's presentation order." Matching it needs the whole list -
    /// including google_connection_options, the GREASE entry, version_information and
    /// initial_rtt, none of which is here - so it belongs to subsystem B and not to a method
    /// that knows six of the fourteen. Ascending is stated so nobody reads the order of these
    /// six as evidence.</remarks>
    internal TlsQuicTransportParameter[] ToTransportParameters() =>
    [
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.InitialMaxData, InitialMaxData),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal,
            InitialMaxStreamDataBidiLocal),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote,
            InitialMaxStreamDataBidiRemote),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.InitialMaxStreamDataUni, InitialMaxStreamDataUni),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.InitialMaxStreamsBidi, InitialMaxStreamsBidi),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.InitialMaxStreamsUni, InitialMaxStreamsUni),
    ];

    /// <summary>The limit this endpoint advertised for data arriving on one stream, chosen by
    /// that stream's RFC 9000 s2.1 type.</summary>
    /// <remarks>THE 0x02 ROW RETURNS 0 AND IS NOT REACHED BY ANY LEGAL FRAME: a
    /// client-initiated unidirectional stream is send-only for us, so s19.8 makes a STREAM
    /// frame on one a STREAM_STATE_ERROR that <see cref="TlsQuicStreamSet.TryReceive"/>
    /// refuses before any limit is asked for. It is written rather than thrown on so this
    /// method is total for every ulong.</remarks>
    internal ulong ReceiveLimitFor(ulong streamId) =>
        (TlsQuicStreamId.InitiatorOf(streamId), TlsQuicStreamId.DirectionOf(streamId)) switch
        {
            (TlsQuicStreamInitiator.Client, TlsQuicStreamDirection.Bidirectional) =>
                InitialMaxStreamDataBidiLocal,
            (TlsQuicStreamInitiator.Server, TlsQuicStreamDirection.Bidirectional) =>
                InitialMaxStreamDataBidiRemote,
            (TlsQuicStreamInitiator.Server, TlsQuicStreamDirection.Unidirectional) =>
                InitialMaxStreamDataUni,
            _ => 0,
        };

    /// <summary>
    /// This same set of limits with every value zeroed that <paramref name="parameters"/> does
    /// not put on the wire.
    /// </summary>
    /// <remarks>
    /// <para>ADVERTISEMENT IS THE AUTHORITY, AND SILENCE IS AN ADVERTISEMENT OF ZERO. RFC 9000
    /// s18.2 gives all six of these a default of 0 when the parameter is absent, so a peer that
    /// never received <c>initial_max_streams_bidi</c> believes it may open no bidirectional
    /// streams at all. This object, meanwhile, is where the spec's own defaults live - 100 for
    /// that one - and <c>TlsQuicStreamSet</c> enforced them whether or not they had ever been
    /// sent. A peer opening a stream it had not been permitted was therefore accepted, on a
    /// budget it had never been told about.</para>
    /// <para>WHY NOT MAKE THE SPEC ADVERTISE THEM INSTEAD. Because omitting them can be
    /// CORRECT: the Spotify capture carries exactly seven transport parameters and 0x08 is not
    /// among them, so adding a slot to satisfy the enforcement side would put an eighth
    /// parameter on the wire and break the replication this library exists for. The
    /// advertisement is the measurement; enforcement follows it.</para>
    /// <para>ONE CALL SITE, at <c>TlsQuicConnection.Streams</c>, so every limit any stream ever
    /// consults has already been through here.</para>
    /// </remarks>
    internal TlsQuicLocalFlowControlSpec AsAdvertisedBy(
        TlsQuicTransportParameterSpec parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        ulong Advertised(TlsQuicTransportParameterId id, ulong value) =>
            parameters.Places((ulong)id) ? value : 0;

        return new TlsQuicLocalFlowControlSpec
        {
            InitialMaxData =
                Advertised(TlsQuicTransportParameterId.InitialMaxData, InitialMaxData),
            InitialMaxStreamDataBidiLocal = Advertised(
                TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal,
                InitialMaxStreamDataBidiLocal),
            InitialMaxStreamDataBidiRemote = Advertised(
                TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote,
                InitialMaxStreamDataBidiRemote),
            InitialMaxStreamDataUni = Advertised(
                TlsQuicTransportParameterId.InitialMaxStreamDataUni, InitialMaxStreamDataUni),
            InitialMaxStreamsBidi = Advertised(
                TlsQuicTransportParameterId.InitialMaxStreamsBidi, InitialMaxStreamsBidi),
            InitialMaxStreamsUni = Advertised(
                TlsQuicTransportParameterId.InitialMaxStreamsUni, InitialMaxStreamsUni),
        };
    }

    /// <summary>How many streams of one direction this endpoint advertised that the peer may
    /// open.</summary>
    internal ulong PeerStreamLimitFor(TlsQuicStreamDirection direction) =>
        direction == TlsQuicStreamDirection.Unidirectional
            ? InitialMaxStreamsUni
            : InitialMaxStreamsBidi;

    private static ulong Bytes(ulong value, string paramName)
    {
        // s16 caps a variable-length integer at 2^62-1 and s18.2 gives these four no tighter
        // bound, so this is the whole range check. Reachable: subsystem B sets these.
        if (value > QuicVariableLengthInteger.MaximumValue)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                value,
                "An RFC 9000 s18.2 flow-control limit is a variable-length integer, so it "
                    + $"cannot exceed {QuicVariableLengthInteger.MaximumValue}.");
        }

        return value;
    }

    private static ulong Streams(ulong value, string paramName)
    {
        // s19.11's 2^60, and "cannot exceed" makes 2^60 itself legal - the same strictness
        // TlsQuicFlowControlFrames uses against the same constant. s18.2 makes setting one of
        // these "equivalent to sending a MAX_STREAMS (Section 19.11) of the corresponding type
        // with the same value", so a count the frame may not carry is one the parameter may
        // not claim.
        if (value > TlsQuicFlowControlFrames.MaximumStreamCount)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                value,
                "An RFC 9000 s18.2 stream-count limit is equivalent to a MAX_STREAMS frame of "
                    + "the same value, so s19.11 caps it at "
                    + $"{TlsQuicFlowControlFrames.MaximumStreamCount}.");
        }

        return value;
    }
}
