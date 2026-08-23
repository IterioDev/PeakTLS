using System.Collections.Immutable;

namespace SharpTls.Quic;

/// <summary>An HTTP/3 request pseudo-header field, in the naming of RFC 9114 s4.3.1.</summary>
/// <remarks>The members exist so <see cref="TlsQuicHttp3Spec.PseudoHeaderOrder"/> can be an
/// ordered list of them. The capture's order is <c>:method, :authority, :scheme, :path</c>,
/// rendered <c>m,a,s,p</c> in the fingerprint string - see
/// 2026-08-16-brave-151-http3-impersonate-pro.md line 70. Declaration order here is that
/// order, but nothing reads declaration order; the list does.</remarks>
internal enum TlsQuicHttp3PseudoHeader
{
    /// <summary><c>:method</c>.</summary>
    Method = 0,

    /// <summary><c>:authority</c>.</summary>
    Authority = 1,

    /// <summary><c>:scheme</c>.</summary>
    Scheme = 2,

    /// <summary><c>:path</c>.</summary>
    Path = 3,
}

/// <summary>The stream-type varint that opens a unidirectional stream, RFC 9114 s6.2.</summary>
/// <remarks>
/// <para>The member values ARE the wire values, so a member casts directly to the varint
/// s6.2's "Unidirectional Stream Header { Stream Type (i) }" carries. Control 0x00 and Push
/// 0x01 are RFC 9114 s11.2.4 Table 5; QpackEncoder 0x02 and QpackDecoder 0x03 are RFC 9204
/// s4.2.</para>
/// <para>0x02 and 0x03 are checkable in repo:
/// rfc9204-section4.1-4.2-primitives-and-streams.txt, "An encoder stream is a unidirectional
/// stream of type 0x02" and "A decoder stream is a unidirectional stream of type 0x03". An
/// earlier draft of this comment said that section had no extract; it does, and the values
/// below were verified against it rather than against the plan's citation of it.</para>
/// <para>Reserved (GREASE) stream types are NOT members: s6.2.3 reserves the whole
/// 0x1f * N + 0x21 family, which is 2^57-ish values and cannot be an enum. They are
/// recognised by recomputation - see
/// <see cref="TlsQuicHttp3Frames.IsReservedIdentifier(ulong)"/>.</para>
/// </remarks>
internal enum TlsQuicHttp3StreamType : ulong
{
    /// <summary>The HTTP control stream, RFC 9114 s6.2.1: "A control stream is indicated by a
    /// stream type of 0x00."</summary>
    Control = 0x00,

    /// <summary>A server push stream, RFC 9114 s6.2.2. A client never opens one - "Only
    /// servers can push; if a server receives a client-initiated push stream, this MUST be
    /// treated as a connection error of type H3_STREAM_CREATION_ERROR" - so
    /// <see cref="TlsQuicHttp3Spec.UnidirectionalStreamOpenOrder"/> rejects it.</summary>
    Push = 0x01,

    /// <summary>The QPACK encoder stream, RFC 9204 s4.2.</summary>
    QpackEncoder = 0x02,

    /// <summary>The QPACK decoder stream, RFC 9204 s4.2.</summary>
    QpackDecoder = 0x03,
}

/// <summary>Which QPACK field line representation an encoder reaches for when a header's NAME
/// matches a static table entry but its VALUE does not.</summary>
/// <remarks>Both are legal and both are observable, because they produce different bytes for
/// the same header. rfc9204-section4.5-field-line-representations.txt carries both headings:
/// "4.5.4. Literal Field Line with Name Reference" and "4.5.6. Literal Field Line with
/// Literal Name".</remarks>
internal enum TlsQuicQpackNameMatchPolicy
{
    /// <summary>Prefer RFC 9204 s4.5.4, referencing the static entry's name.</summary>
    NameReference = 0,

    /// <summary>Always spell the name out, RFC 9204 s4.5.6.</summary>
    LiteralName = 1,
}

/// <summary>One RFC 9114 s7.2.4 "Setting { Identifier (i), Value (i) }" - a POSITION in a
/// sequence, not a named property.</summary>
/// <remarks>WHY A PAIR AND NOT A PROPERTY. s7.2.4's payload "consists of zero or more
/// parameters" laid down in whatever order the sender chooses, and the order is on the wire
/// and therefore fingerprintable. A design with one named property per setting - a bool for
/// datagram support, an int for the table capacity - can express which settings are sent and
/// what they say, and cannot express the one remaining degree of freedom. It also cannot
/// express a reserved (GREASE) identifier at all, since that identifier has no name.</remarks>
/// <param name="Identifier">The s7.2.4 Identifier field. At most
/// <see cref="QuicVariableLengthInteger.MaximumValue"/>.</param>
/// <param name="Value">The s7.2.4 Value field. At most
/// <see cref="QuicVariableLengthInteger.MaximumValue"/>.</param>
internal readonly record struct TlsQuicHttp3Setting(ulong Identifier, ulong Value);

// ADDING A PROPERTY HERE? THE SAME TWO THINGS ARE OWED AS IN TlsQuicConnectionSpec.cs,
// whose header states the rule in full and is the authority. In short:
//
//   1. WITNESS THE GUARD, because subsystem B populates this from outside the library.
//   2. SAY WHETHER ANYTHING READS IT. Run `grep -rn "Spec.<YourProperty>" src/`. If
//      nothing does, the doc-comment must say so and NAME THE TASK THAT WILL WIRE IT.
//
// The wiring table for THIS file as it stands, so the next author does not have to
// re-derive it - each row was produced by that grep, not by intent:
//
//   Settings                        read by TlsQuicHttp3Settings.Encode
//   UnidirectionalStreamOpenOrder   read by TlsQuicHttp3Streams.OpenLocalStreams
//   PseudoHeaderOrder               read by TlsQuicHttp3Request.TryBuildFieldLines
//   QpackHuffmanStringLiterals      read by TlsQuicHttp3Request.TryEncodeFieldSection
//   QpackNameMatchPolicy            read by TlsQuicHttp3Request.TryEncodeFieldSection
//   SendReservedFramesOnRequestStreams  read by TlsQuicHttp3Request.TryEncode
//
// Task C9 wired the last four, which C1-C4 had left recording a value and changing no byte.
// Each has a test that sets it on a spec and reads the BYTES change - the rule is that a
// knob is honoured only if a caller setting it changes the wire, and the four witnesses are
// listed in TlsQuicHttp3RequestTests' header.

/// <summary>Every HTTP/3 layout decision a client makes that a peer or an observer can see.
/// Subsystem B populates one of these to imitate a particular browser; nothing in subsystem C
/// may read a layout literal instead. No behaviour lives here.</summary>
/// <remarks>
/// <para>THE DEFAULTS SPLIT IN TWO, and the split is the point. Where the Brave 151 capture
/// bounds a default it is taken and the capture line is cited. Where the capture CANNOT see
/// the choice - because the fingerprint string records the settings sorted-or-not
/// indistinguishably, records nothing about stream-open order, and records nothing about
/// QPACK's internal encoding choices - the default is a DECLARED PLACEHOLDER, marked as one
/// in its own doc comment, naming the task that would settle it. A plausible number invented
/// here would be indistinguishable from a measured one a month later.</para>
/// <para>THE `51:1` DECISION IS RECORDED ON <see cref="Settings"/>. It is a decision and not
/// a copied value; read that property's remarks before changing it.</para>
/// </remarks>
internal sealed class TlsQuicHttp3Spec
{
    // ------------------------------------------------------------------------------
    // THE DEFAULTS BLOCK. Every numeric layout literal in this file is below this line
    // and above the end of this region; the properties themselves carry none.
    // ------------------------------------------------------------------------------

    /// <summary>The capture's HTTP/3 SETTINGS, in the capture's printed order.</summary>
    /// <remarks>
    /// 2026-08-16-brave-151-http3-impersonate-pro.md lines 64-68 and the fingerprint string on
    /// line 47, <c>1:65536;6:262144;7:100;51:1;GREASE</c>. The reserved pair's two numbers are
    /// line 68's, 126585778853 and 2585972839; that identifier satisfies s7.2.4.1's
    /// 0x1f * N + 0x21 form at N = 4083412220, which
    /// TlsQuicHttp3SpecTests.TheCapturesGreaseSettingIdentifierIsAReservedOne recomputes
    /// rather than asserting.
    /// </remarks>
    internal static readonly ImmutableArray<TlsQuicHttp3Setting> CaptureSettings =
    [
        new(QpackMaxTableCapacityIdentifier, 65536),
        new(MaxFieldSectionSizeIdentifier, 262144),
        new(QpackBlockedStreamsIdentifier, 100),
        new(H3DatagramIdentifier, 1),
        new(126585778853, 2585972839),
    ];

    /// <summary>RFC 9114 s11.2.2 Table 3's <c>MAX_FIELD_SECTION_SIZE</c>, 0x06.</summary>
    internal const ulong MaxFieldSectionSizeIdentifier = 0x06;

    /// <summary><c>SETTINGS_QPACK_MAX_TABLE_CAPACITY</c>, identifier 1.</summary>
    /// <remarks>rfc9204-section5-6-configuration-and-error-handling.txt:
    /// "SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01): The default value is zero." The Brave
    /// capture's line 64 names the same identifier and sends 65536, so the browser is
    /// departing from the RFC's default rather than restating it - which is why the number
    /// belongs in the defaults block and not in a constant named after the RFC. RFC 9114
    /// s11.2.2 Table 3 independently leaves 0x01 unlisted, so it is not a reserved HTTP/2
    /// identifier.</remarks>
    internal const ulong QpackMaxTableCapacityIdentifier = 1;

    /// <summary><c>SETTINGS_QPACK_BLOCKED_STREAMS</c>, identifier 7.</summary>
    /// <remarks>rfc9204-section5-6-configuration-and-error-handling.txt:
    /// "SETTINGS_QPACK_BLOCKED_STREAMS (0x07): The default value is zero." The capture's
    /// line 66 sends 100.</remarks>
    internal const ulong QpackBlockedStreamsIdentifier = 7;

    /// <summary><c>SETTINGS_H3_DATAGRAM</c>, RFC 9297 s2.1.1's 0x33 - the capture's decimal
    /// 51.</summary>
    /// <remarks>rfc9297-section2.1-http3-datagrams.txt names it 0x33 and the capture line 67
    /// prints 51; 0x33 == 51, so the two are one identifier and the capture's number is
    /// checkable rather than copied.</remarks>
    internal const ulong H3DatagramIdentifier = 0x33;

    /// <summary>The three unidirectional streams RFC 9114 s6.2 requires an endpoint to be
    /// able to open, in the order this client opens them.</summary>
    /// <remarks>PLACEHOLDER. See <see cref="UnidirectionalStreamOpenOrder"/>.</remarks>
    internal static readonly ImmutableArray<TlsQuicHttp3StreamType> DefaultStreamOpenOrder =
    [
        TlsQuicHttp3StreamType.Control,
        TlsQuicHttp3StreamType.QpackEncoder,
        TlsQuicHttp3StreamType.QpackDecoder,
    ];

    /// <summary>The capture's pseudo-header order, <c>m,a,s,p</c>.</summary>
    /// <remarks>2026-08-16-brave-151-http3-impersonate-pro.md line 70.</remarks>
    internal static readonly ImmutableArray<TlsQuicHttp3PseudoHeader> CapturePseudoHeaderOrder =
    [
        TlsQuicHttp3PseudoHeader.Method,
        TlsQuicHttp3PseudoHeader.Authority,
        TlsQuicHttp3PseudoHeader.Scheme,
        TlsQuicHttp3PseudoHeader.Path,
    ];

    // ------------------------------------------------------------------------------
    // End of the defaults block.
    // ------------------------------------------------------------------------------

    private readonly ImmutableArray<TlsQuicHttp3Setting> _settings = CaptureSettings;
    private readonly ImmutableArray<TlsQuicHttp3StreamType> _unidirectionalStreamOpenOrder =
        DefaultStreamOpenOrder;
    private readonly ImmutableArray<TlsQuicHttp3PseudoHeader> _pseudoHeaderOrder =
        CapturePseudoHeaderOrder;
    private readonly TlsQuicQpackNameMatchPolicy _qpackNameMatchPolicy =
        TlsQuicQpackNameMatchPolicy.NameReference;

    /// <summary>Gets the SETTINGS frame's parameters, in the order they go on the wire.</summary>
    /// <remarks>
    /// <para>ORDER IS NOT SORTED. RFC 9114 s7.2.4 fixes no order, so the sequence is a sender
    /// choice and therefore a fingerprint dimension. The capture's five identifiers happen to
    /// be strictly ascending, which means the capture CANNOT distinguish "the browser wrote
    /// them in this order" from "the browser sorted them" - so this list expresses the
    /// freedom, the encoder is forbidden to sort, and no test here claims to know which of
    /// the two the browser did.</para>
    /// <para>THE RESERVED (GREASE) SETTING IS AN ORDINARY ELEMENT, which is why there is no
    /// separate "emit a GREASE setting" flag and no separate "where" index: a list already
    /// says both, and a flag plus an index would be a second, weaker way to say the same
    /// thing that could disagree with the list. s7.2.4.1: "Endpoints SHOULD include at least
    /// one such setting in their SETTINGS frame." Identify one by recomputation, not by a
    /// table - <see cref="TlsQuicHttp3Frames.IsReservedIdentifier(ulong)"/>.</para>
    /// <para>THE `51:1` DECISION, made rather than copied. RFC 9297 s2.1.1's "It is
    /// RECOMMENDED that implementations that support receiving HTTP/3 Datagrams always send
    /// the SETTINGS_H3_DATAGRAM setting with a value of 1 ... This helps to avoid 'sticking
    /// out'" is CONDITIONED on supporting receipt, and this stack has no HTTP/3 datagram
    /// receive path - <see cref="TlsQuicFrameType"/> has no RFC 9221 DATAGRAM member at all.
    /// So the RECOMMENDED does not reach us, and the default of 1 rests on the CAPTURE
    /// (line 67) and on nothing else: it is a deliberate fingerprint choice that goes past
    /// what s2.1.1 recommends, stated here rather than smuggled in as a constant. Two things
    /// keep it honest. First, s2.1.1's MUST that the value "be either 0 or 1" is enforced
    /// below, so a caller who does not want to advertise willingness writes 0 or drops the
    /// pair. Second, s2.1.1's "QUIC DATAGRAM frames MUST NOT be sent until the
    /// SETTINGS_H3_DATAGRAM setting has been both sent and received with a value of 1" is
    /// enforced separately by
    /// <see cref="TlsQuicHttp3Streams.Http3DatagramsPermittedToSend"/>, which requires BOTH
    /// halves - sending 1 here licenses nothing on its own.</para>
    /// </remarks>
    /// <exception cref="ArgumentException">The array is default-valued rather than empty, an
    /// identifier appears more than once (s7.2.4: "The same setting identifier MUST NOT occur
    /// more than once in the SETTINGS frame"), or an identifier is one RFC 9114 s11.2.2
    /// reserves from HTTP/2 (s7.2.4.1: "These reserved settings MUST NOT be sent").</exception>
    /// <exception cref="ArgumentOutOfRangeException">An identifier or value exceeds
    /// <see cref="QuicVariableLengthInteger.MaximumValue"/>, or
    /// <see cref="H3DatagramIdentifier"/> carries a value other than 0 or 1 (RFC 9297 s2.1.1:
    /// "The value of the SETTINGS_H3_DATAGRAM setting MUST be either 0 or 1").</exception>
    internal ImmutableArray<TlsQuicHttp3Setting> Settings
    {
        get => _settings;
        init
        {
            ThrowIfDefault(value, nameof(Settings));
            for (var i = 0; i < value.Length; i++)
            {
                var setting = value[i];
                ArgumentOutOfRangeException.ThrowIfGreaterThan(
                    setting.Identifier, QuicVariableLengthInteger.MaximumValue, nameof(Settings));
                ArgumentOutOfRangeException.ThrowIfGreaterThan(
                    setting.Value, QuicVariableLengthInteger.MaximumValue, nameof(Settings));

                if (TlsQuicHttp3Frames.IsHttp2ReservedSettingIdentifier(setting.Identifier))
                {
                    throw new ArgumentException(
                        $"Setting identifier 0x{setting.Identifier:x} is reserved from HTTP/2 by "
                            + "RFC 9114 s11.2.2 and MUST NOT be sent.",
                        nameof(Settings));
                }

                // s2.1.1's MUST is on the RECEIVER - "the receiver MUST terminate the
                // connection with error H3_SETTINGS_ERROR" - so refusing to SEND such a value
                // is stricter than the letter. It is the right strictness: the only thing a
                // sender gains from 2 is a peer that closes the connection, and a fingerprint
                // library whose whole purpose is to not stand out has no use for that.
                if (setting.Identifier == H3DatagramIdentifier && setting.Value > 1)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(Settings),
                        setting.Value,
                        "RFC 9297 s2.1.1: \"The value of the SETTINGS_H3_DATAGRAM setting MUST "
                            + "be either 0 or 1.\"");
                }

                for (var j = 0; j < i; j++)
                {
                    if (value[j].Identifier == setting.Identifier)
                    {
                        throw new ArgumentException(
                            $"Setting identifier 0x{setting.Identifier:x} occurs more than once.",
                            nameof(Settings));
                    }
                }
            }
            _settings = value;
        }
    }

    /// <summary>Gets whether <c>SETTINGS_H3_DATAGRAM</c> = 1 may be sent on a connection whose
    /// ClientHello advertised no non-zero <c>max_datagram_frame_size</c> (RFC 9221 s3's
    /// 0x20).</summary>
    /// <remarks>
    /// <para>THE TWO HALVES OF ONE CLAIM, AND NOTHING USED TO TIE THEM. Advertising willingness
    /// to receive HTTP/3 datagrams is <see cref="Settings"/>'s 0x33; advertising the QUIC
    /// transport that would carry them is a transport parameter inside the ClientHello, one
    /// layer down and owned by a different spec. A fingerprint composed from both can say yes
    /// to one and no to the other, and NOTHING IN ANY RFC FORBIDS THAT - RFC 9297 as published
    /// does not mention <c>max_datagram_frame_size</c> at all outside its reference list, which
    /// task C17 checked by full-text search of rfc9297.txt rather than by reading the section
    /// that looked most likely. What exists is a DEPLOYED SERVER BEHAVIOUR: quic-go's
    /// <c>http3/conn.go</c> closes with H3_SETTINGS_ERROR and the reason string "missing QUIC
    /// Datagram support" when a peer's SETTINGS say 1 and its transport parameters do not.</para>
    /// <para>SO THIS IS A DEFAULT AND NOT A RULE, which is why it is a knob. C17 measured it
    /// live at fp.impersonate.pro, one variable per arm, three whole connections each: the
    /// shipped SETTINGS without 0x20 failed 0/3 with 0x109, the same SETTINGS with 0x20 added
    /// completed 3/3, and dropping 0x33 or sending it as 0 completed 3/3 with 0x20 still
    /// absent. Removing the GREASE pair, <c>1:65536</c> or <c>7:100</c> while leaving
    /// <c>51:1</c> in place still failed 0/3, so none of those is the cause.</para>
    /// <para>SET IT TO <see langword="true"/> TO SEND THE PAIR ANYWAY. A client that genuinely
    /// emits the inconsistent combination must remain reproducible - that is what this library
    /// is for - and the cost is a peer that may or may not close the connection. The default is
    /// <see langword="false"/> because the failure is remote, silent and several layers away
    /// from the line that caused it, and because no shipped preset needs the exemption: the
    /// Brave 151 capture advertises BOTH halves, <c>51:1</c> in its SETTINGS and
    /// <c>32 max_datagram_frame_size = 65536</c> in its transport parameters.</para>
    /// <para>NOTE WHAT THIS IS NOT. It does not force, insert or alter a transport parameter -
    /// only <see cref="TlsQuicTransportParameterSpec"/> and the ClientHello may do that, and a
    /// fingerprint library that silently added a parameter to make a check pass would be
    /// changing the bytes it exists to reproduce.</para>
    /// </remarks>
    internal bool AllowDatagramSettingWithoutTransportParameter { get; init; }

    /// <summary>Gets the unidirectional streams this client opens at the start of the
    /// connection, in open order.</summary>
    /// <remarks>
    /// <para>PLACEHOLDER DEFAULT. RFC 9114 s6.2 says only "Endpoints SHOULD create the HTTP
    /// control stream as well as the unidirectional streams required by mandatory extensions
    /// (such as the QPACK encoder and decoder streams) first, and then create additional
    /// streams as allowed by their peer" - which fixes the three as a GROUP and leaves the
    /// order WITHIN the group free. The capture cannot see it either: the fingerprint string
    /// records settings, pseudo-headers, transport parameters and connection id lengths, and
    /// no stream-open order. Control-then-encoder-then-decoder began as this project's declared
    /// placeholder; proxy captures of the Spotify iOS client's first flight later measured that
    /// same order in 4 of 4, so it is no longer a guess. It stays a library DEFAULT rather than
    /// a fact about any client: presets that mean the measurement pin it themselves.</para>
    /// <para>Read by <see cref="TlsQuicHttp3Streams.OpenLocalStreams"/>.</para>
    /// </remarks>
    /// <exception cref="ArgumentException">The array is default-valued rather than empty, a
    /// type appears more than once, <see cref="TlsQuicHttp3StreamType.Control"/> is absent
    /// (RFC 9114 s6.2.1: "Each side MUST initiate a single control stream"), or
    /// <see cref="TlsQuicHttp3StreamType.Push"/> is present (s6.2.2: "Only servers can
    /// push").</exception>
    /// <exception cref="ArgumentOutOfRangeException">An element is not a defined
    /// <see cref="TlsQuicHttp3StreamType"/>.</exception>
    internal ImmutableArray<TlsQuicHttp3StreamType> UnidirectionalStreamOpenOrder
    {
        get => _unidirectionalStreamOpenOrder;
        init
        {
            ThrowIfDefault(value, nameof(UnidirectionalStreamOpenOrder));
            for (var i = 0; i < value.Length; i++)
            {
                // Enum.IsDefined and not a range test, for the reason TlsQuicConnectionSpec
                // gives: a C# enum holds any value its underlying type can, and a cast from
                // an arbitrary ulong is the reachable path when subsystem B is the caller.
                if (!Enum.IsDefined(value[i]))
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(UnidirectionalStreamOpenOrder),
                        value[i],
                        "Not a stream type RFC 9114 s11.2.4 or RFC 9204 s4.2 defines.");
                }
                if (value[i] == TlsQuicHttp3StreamType.Push)
                {
                    throw new ArgumentException(
                        "RFC 9114 s6.2.2: \"Only servers can push\" - a client-initiated push "
                            + "stream is H3_STREAM_CREATION_ERROR at the peer.",
                        nameof(UnidirectionalStreamOpenOrder));
                }
                if (value.IndexOf(value[i]) != i)
                {
                    throw new ArgumentException(
                        $"Stream type {value[i]} appears more than once in the open order.",
                        nameof(UnidirectionalStreamOpenOrder));
                }
            }
            if (!value.Contains(TlsQuicHttp3StreamType.Control))
            {
                throw new ArgumentException(
                    "RFC 9114 s6.2.1: \"Each side MUST initiate a single control stream at the "
                        + "beginning of the connection and send its SETTINGS frame as the first "
                        + "frame on this stream.\"",
                    nameof(UnidirectionalStreamOpenOrder));
            }
            _unidirectionalStreamOpenOrder = value;
        }
    }

    /// <summary>Gets the order the request's pseudo-header fields are emitted in.</summary>
    /// <remarks>
    /// <para>The default is the capture's, line 70: <c>:method, :authority, :scheme, :path</c>,
    /// which the fingerprint string abbreviates <c>m,a,s,p</c>. Unlike the SETTINGS order this
    /// one IS settled by the capture, because the four names have no natural sort that would
    /// produce that sequence.</para>
    /// <para>Read by <see cref="TlsQuicHttp3Request.TryEncode"/>, which emits the pseudo-header
    /// field lines in exactly this sequence and holds no fallback order of its own. RFC 9114
    /// s4.3's only ordering rule is that "All pseudo-header fields MUST appear in the header
    /// section before regular header fields" - it says nothing about the sequence among them,
    /// which is why this list is a fingerprint dimension rather than a conformance question.
    /// TlsQuicHttp3RequestTests.EveryPermutationOfTheFourPseudoHeadersIsEmittedAsGiven decodes
    /// all twenty-four orders back and would fail against any canonical sequence.</para>
    /// </remarks>
    /// <exception cref="ArgumentException">The array is default-valued rather than empty, or a
    /// pseudo-header appears more than once.</exception>
    /// <exception cref="ArgumentOutOfRangeException">An element is not a defined
    /// <see cref="TlsQuicHttp3PseudoHeader"/>.</exception>
    internal ImmutableArray<TlsQuicHttp3PseudoHeader> PseudoHeaderOrder
    {
        get => _pseudoHeaderOrder;
        init
        {
            ThrowIfDefault(value, nameof(PseudoHeaderOrder));
            for (var i = 0; i < value.Length; i++)
            {
                if (!Enum.IsDefined(value[i]))
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(PseudoHeaderOrder),
                        value[i],
                        "Not a pseudo-header RFC 9114 s4.3.1 defines for a request.");
                }
                if (value.IndexOf(value[i]) != i)
                {
                    throw new ArgumentException(
                        $"Pseudo-header {value[i]} appears more than once in the order.",
                        nameof(PseudoHeaderOrder));
                }
            }
            _pseudoHeaderOrder = value;
        }
    }

    /// <summary>Gets whether the QPACK encoder Huffman-codes the string literals it
    /// emits.</summary>
    /// <remarks>
    /// <para>PLACEHOLDER DEFAULT of <see langword="true"/>, and the "per string" freedom RFC
    /// 9204 s4.1.2's H bit gives is deliberately NOT modelled: one flag for the whole
    /// connection is the smallest thing that expresses the dimension, and a per-string
    /// predicate would be a policy interface with one implementation. The capture cannot see
    /// this at all - the fingerprint string carries no QPACK bytes - so the default is a
    /// declared placeholder for task C12's not-yet-known column, settled only by a packet
    /// capture.</para>
    /// <para>Read by <see cref="TlsQuicHttp3Request.TryEncode"/>, which hands it to
    /// <see cref="TlsQuicQpackEncoder.TryEncodeFieldLine"/> as that method's <c>huffman</c>
    /// argument. Witnessed by TlsQuicHttp3RequestTests.TurningHuffmanOffChangesTheBytes and
    /// TlsQuicHttp3RequestTests.TheHuffmanFlagDecidesWhetherTheAuthorityIsOnTheWireAsAscii,
    /// the second of which reads which of the two representations came out rather than
    /// inferring it from an inequality.</para>
    /// </remarks>
    internal bool QpackHuffmanStringLiterals { get; init; } = true;

    /// <summary>Gets which representation the QPACK encoder prefers when a header's name
    /// matches a static entry but its value does not.</summary>
    /// <remarks>
    /// <para>PLACEHOLDER DEFAULT of <see cref="TlsQuicQpackNameMatchPolicy.NameReference"/>,
    /// unseen by the capture for the same reason as
    /// <see cref="QpackHuffmanStringLiterals"/>.</para>
    /// <para>Read by <see cref="TlsQuicHttp3Request.TryEncode"/>, which turns it into
    /// <see cref="TlsQuicQpackEncoder.TryEncodeFieldLine"/>'s <c>preferNameReference</c>
    /// argument. Witnessed by TlsQuicHttp3RequestTests.TheLiteralNamePolicyChangesTheBytes;
    /// TlsQuicHttp3RequestTests.ThePolicyDoesNotDisturbAFullStaticMatch pins the other half,
    /// that a name AND value match still takes s4.5.2 under either policy.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not a defined
    /// <see cref="TlsQuicQpackNameMatchPolicy"/>.</exception>
    internal TlsQuicQpackNameMatchPolicy QpackNameMatchPolicy
    {
        get => _qpackNameMatchPolicy;
        init
        {
            if (!Enum.IsDefined(value))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(QpackNameMatchPolicy),
                    value,
                    "Not a name-match policy RFC 9204 s4.5.4 or s4.5.6 defines.");
            }
            _qpackNameMatchPolicy = value;
        }
    }

    /// <summary>Gets whether a reserved (GREASE) frame is sent on a request stream, RFC 9114
    /// s7.2.8.</summary>
    /// <remarks>
    /// <para>PLACEHOLDER DEFAULT of <see langword="false"/>. s7.2.8's reserved frames "MAY be
    /// sent on any stream where frames are allowed to be sent", so both answers conform, and
    /// the capture's fingerprint string records the SETTINGS list and not the request stream's
    /// frames - it cannot settle this. bogdanfinn exposes the same dimension as
    /// <c>h3SendGreaseFrames</c>, which is evidence the dimension is real and no evidence at
    /// all about the browser's value. Task C12's not-yet-known column.</para>
    /// <para>Read by <see cref="TlsQuicHttp3Request.TryEncode"/>, which prefixes the HEADERS
    /// frame with one reserved frame when this is <see langword="true"/>. THE FLAG IS THE ONLY
    /// KNOB - the reserved frame's N, its payload and its position before the HEADERS frame
    /// are all placeholders declared on
    /// <see cref="TlsQuicHttp3Request.ReservedRequestStreamFrameType"/>, because s7.2.8 leaves
    /// all three free and nothing in the capture bounds them. Witnessed by
    /// TlsQuicHttp3RequestTests.TheReservedFrameIsPresentOnlyWhenTheSpecAsks.</para>
    /// </remarks>
    internal bool SendReservedFramesOnRequestStreams { get; init; }

    // Copied in shape from TlsQuicConnectionSpec.ThrowIfDefault and for its reason: a
    // default-valued ImmutableArray is not an empty one, it is a null reference wearing a
    // struct, and every member access on it throws NullReferenceException at some unrelated
    // later line. Witnessed once per array property:
    // TlsQuicHttp3SpecTests.ADefaultValuedSettingsListIsRejected,
    // TlsQuicHttp3SpecTests.ADefaultValuedStreamOpenOrderIsRejected and
    // TlsQuicHttp3SpecTests.ADefaultValuedPseudoHeaderOrderIsRejected.
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
}
