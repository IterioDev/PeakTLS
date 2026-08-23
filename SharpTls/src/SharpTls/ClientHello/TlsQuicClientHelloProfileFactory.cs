using SharpTls.Quic;

namespace SharpTls;

// ============================================================================
// THE MUTATION LEDGER - TASK B8 (this file, and TlsQuicHttp3FingerprintReadout's ALPN row)
// ============================================================================
//
//   ROWS BELOW                   18  = B8-1 to B8-18 with no gaps
//   KILLED                       18  = 18 rows, less 0 survivors
//   SURVIVED                      0
//                                     18 + 0 = 18
//
//   HOW. mutate-b8.py in a private git worktree; every run rebuilt with
//   `dotnet build --no-incremental` and then ran `dotnet test --filter
//   FullyQualifiedName~Quic --no-build`. Each run's TOTAL case count was checked against a
//   floor of 1900 and a run below it would have been REJECTED rather than read - an aborted
//   run prints an ordinary "Failed: 0, Passed: <m>" line that is indistinguishable from a
//   survivor. All twenty runs reported 1919 cases.
//
//   THE HARNESS WAS PROVED IN BOTH DIRECTIONS BEFORE THE ROWS, and neither control is counted
//   among them. A known-bad edit - the readout's CaptureAlpn constant changed from h3 to h2 -
//   was KILLED. An inert edit - one added comment line in this file - SURVIVED.
//
//   1  Create composes once and reuses the blob on every connection      KILLED
//   2  Create memoises the whole profile                                 KILLED
//   3  the caller's TLS half runs last instead of first                  KILLED
//   4  the ALPN call is dropped                                          KILLED
//   5  ALPN is hard-coded to h3 and the knob is ignored                  KILLED
//   6  the transport-parameter call is dropped                           KILLED
//   7  Compose runs against a default spec, ignoring ConnectionSpec      KILLED
//   8  the source connection ID is dropped on the way to Compose         KILLED
//   9  the null-element check on AlpnProtocols is removed                KILLED
//   10 AlpnProtocols accepts null                                        KILLED
//   11 ConnectionSpec accepts null                                       KILLED
//   12 Tls accepts null                                                  KILLED
//   13 the ALPN verdict becomes a containment test                       KILLED
//   14 the ALPN row goes back to the third column                        KILLED
//   15 an unparsable ClientHello throws instead of becoming a row        KILLED
//   16 an absent ALPN renders as an empty cell rather than absent        KILLED
//   17 Describe accepts a null ClientHello                               KILLED
//   18 the ALPN row is rendered after the subsystem B rows               KILLED
//
//   ROWS 1 AND 2 ARE THE ONES THIS TASK EXISTS FOR, and neither is killed by chance. Both are
//   caching mutants, and both are caught by a test whose draw is a COUNTER rather than a
//   random value - so the two emitted values are 0 and 1 by construction. A "two connections
//   differ" assertion over the real preset would also catch them, but only with probability,
//   and the plan's own standing rule says a randomised witness is not a witness.
// ============================================================================

/// <summary>Builds one <see cref="ClientHelloProfile"/> per QUIC connection: the caller's TLS
/// half, the ALPN token RFC 9114 s3.2 names, and the transport parameters
/// <c>TlsQuicConnectionSpec.TransportParameters</c> composes for THIS connection's source
/// connection ID.</summary>
/// <remarks>
/// <para>A FACTORY AND NOT A PROFILE, for two reasons that are both about time.
/// <c>ClientHelloBuilder.WithQuicTransportParameters</c> bakes the encoded blob into an
/// immutable profile, and three of the fourteen parameters the preset lists are redrawn per
/// connection - <c>initial_rtt</c>, the reserved identifier, and the GREASE version inside
/// <c>version_information</c>. A profile built once and reused therefore puts ONE draw of each
/// on every connection it is used for, and a pinned per-connection field is itself a
/// fingerprint. <c>initial_source_connection_id</c> makes the same point without any
/// fingerprinting argument at all: it carries the connection's own source connection ID, so a
/// reused profile advertises a stale one and RFC 9000 s7.3's receive-side check is entitled to
/// close the connection over it.</para>
/// <para>WHAT THIS TYPE OWNS AND WHAT IT DOES NOT. It owns exactly the two things subsystem B
/// owns: the composed transport-parameter blob (extension 57's BODY) and the ALPN token. The
/// TLS half - cipher suites, supported groups, key shares, extension wire order, ECH, ALPS -
/// is subsystem E's and is not written into this file. It arrives through <see cref="Tls"/> as
/// a caller's <c>ClientHelloBuilder</c> configuration and passes through untouched, so nothing
/// here can silently disagree with a profile written from a capture.</para>
/// <para>ORDER OF APPLICATION, AND WHY IT IS THIS WAY ROUND. <see cref="Tls"/> runs FIRST and
/// this type's own two calls run AFTER it, because those two are the ones
/// <c>CustomTlsQuicClientOptions.Snapshot</c> hard-requires - a QUIC ClientHello without
/// semantic ALPN or without extension 57 is rejected there. Running them last means a
/// <see cref="Tls"/> that forgets either still produces a usable profile. The cost is that a
/// <c>.WithAlpn(...)</c> or <c>.WithQuicTransportParameters(...)</c> inside <see cref="Tls"/>
/// is overwritten rather than honoured, which is why both are knobs on THIS type
/// (<see cref="AlpnProtocols"/>, and <c>TlsQuicConnectionSpec.TransportParameters</c>) rather
/// than things a caller expresses through the builder.</para>
/// <para>THE EXTENSION'S POSITION IS STILL THE PROFILE'S. <c>WithQuicTransportParameters</c>
/// enables the semantic slot; where that slot sits in the wire order is decided by
/// <c>WithExtensionLayout</c> inside <see cref="Tls"/>, exactly as it is for every other
/// extension. This type supplies the body and takes no view on the position.</para>
/// <para>INTERNAL BECAUSE ITS COLLABORATORS ARE. <c>TlsQuicConnectionSpec</c>,
/// <c>TlsQuicTransportParameterSpec</c> and <c>TlsQuicConnection</c> are all internal today, so
/// a public factory over them could not be called by anyone this assembly does not already
/// trust. Making the QUIC stack public is a release decision and not this one.</para>
/// </remarks>
internal sealed class TlsQuicClientHelloProfileFactory
{
    /// <summary>RFC 9114 s3.2, rfc9114-section3.2-connection-establishment.txt: "During
    /// connection establishment, HTTP/3 support is indicated by selecting the ALPN token
    /// \"h3\" in the TLS handshake."</summary>
    internal const string Http3AlpnToken = "h3";

    private readonly TlsQuicConnectionSpec _connectionSpec = new();
    private readonly string[] _alpnProtocols = [Http3AlpnToken];
    private readonly Action<ClientHelloBuilder> _tls = static _ => { };

    /// <summary>Gets the connection spec whose <c>TransportParameters</c> this factory composes
    /// and whose <c>SourceConnectionIdLength</c> fixes the length
    /// <see cref="Create(ReadOnlySpan{byte})"/> accepts.</summary>
    /// <remarks>
    /// <para>THE SAME OBJECT THE CONNECTION IS CONSTRUCTED WITH, or the six flow-control
    /// numbers advertised here and the six <c>TlsQuicStreamSet</c> enforces are two sets of
    /// numbers. <c>TlsQuicTransportParameterSpec.Compose</c> places the advertised ones from
    /// this spec's <c>LocalFlowControl</c> precisely so that they cannot be typed twice; handing
    /// this factory a different spec from the one passed to <c>TlsQuicConnectionOptions</c>
    /// re-opens that gap from the outside.</para>
    /// <para>IT IS ALSO WHERE THE INITIAL FLIGHT PLAN LIVES, which matters on this type
    /// because a profile it builds is the input that forces one. A ClientHello offering the
    /// capture's X25519MLKEM768 share spends 1216 bytes on that share alone, so its CRYPTO
    /// stream does not fit one datagram inside the <c>max_udp_payload_size</c> of 1472 the
    /// capture advertises - and yet the DEFAULT spec here leaves
    /// <c>TlsQuicConnectionSpec.InitialCryptoFrameByteCounts</c> and
    /// <c>InitialCryptoFramesPerDatagram</c> empty, which means one frame in one oversized
    /// datagram. That is legal under RFC 9000 s14.1, throws nothing, and is not what Chromium
    /// sends; the capture's lines 30-33 put per-datagram Initial flight plans among what
    /// neither verification endpoint inspects, so no live run reports it either. A caller who
    /// wants the split passes a spec carrying it, and
    /// <c>TlsQuicDatagramBuilder.PlanInitialFlightSplit</c> derives the two arrays from the
    /// encoded ClientHello's length and a per-datagram byte budget - the capture's being
    /// <c>TlsQuicDatagramBuilder.Brave151InitialCryptoStreamBytesPerDatagram</c>, whose exact
    /// value task B12 settles. THE SPLIT IS NOT THIS TYPE'S DEFAULT because those arrays are
    /// absolute byte counts and nothing here knows, at the moment a spec is constructed, how
    /// long the ClientHello it is about to build will turn out to be.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Set to <see langword="null"/>.</exception>
    public TlsQuicConnectionSpec ConnectionSpec
    {
        get => _connectionSpec;
        init => _connectionSpec = value ?? throw new ArgumentNullException(nameof(ConnectionSpec));
    }

    /// <summary>Gets the ALPN protocols offered, in wire order. Defaults to
    /// <see cref="Http3AlpnToken"/> alone.</summary>
    /// <remarks>
    /// <para>A LIST AND NOT A BOOLEAN, because RFC 9114 s3.2 says so in the sentence after the
    /// one that names the token: "Support for other application-layer protocols MAY be offered
    /// in the same handshake." A client offering <c>h3, h3-29</c> and a client offering <c>h3</c>
    /// are different clients on the wire, and this library's job is to be able to be either.</para>
    /// <para>AN EMPTY LIST IS REFUSED ONE LAYER DOWN, AND THAT IS A LIMIT WORTH KNOWING.
    /// <c>ClientHelloBuilder.WithAlpn</c> defines an empty list as "remove the extension", but
    /// <c>ClientHelloBuilder.BuildConfiguration</c> then rejects any ClientHello that carries
    /// extension 57 and no ALPN. So <see cref="Create(ReadOnlySpan{byte})"/> throws
    /// <see cref="InvalidOperationException"/> for an empty list rather than emitting a QUIC
    /// ClientHello without ALPN: a client that offers none is a fingerprint this library cannot
    /// currently express. The refusal is not this type's and is deliberately not swallowed here
    /// - hiding it would turn a stated limit into a silently different ClientHello. Witnessed by
    /// <c>TlsQuicClientHelloProfileFactoryTests</c>.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Set to <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">An element is <see langword="null"/>.</exception>
    public IReadOnlyList<string> AlpnProtocols
    {
        get => _alpnProtocols;
        init
        {
            ArgumentNullException.ThrowIfNull(value, nameof(AlpnProtocols));
            var protocols = value.ToArray();
            // Checked here rather than left to the encoder: ClientHelloBuilder.WithAlpn clones
            // the array without inspecting its elements, so a null would surface as a
            // NullReferenceException from inside ClientHelloEncoder with no parameter name on
            // it - several frames away from the initialiser that caused it.
            if (Array.IndexOf(protocols, null) >= 0)
            {
                throw new ArgumentException(
                    "An ALPN protocol is null. Pass an empty list to offer no ALPN at all.",
                    nameof(AlpnProtocols));
            }
            _alpnProtocols = protocols;
        }
    }

    /// <summary>Gets the TLS half of the profile - everything except ALPN and extension 57's
    /// body. Defaults to a no-op, which is <c>ClientHelloBuilder</c>'s own defaults.</summary>
    /// <remarks>THE DEFAULT IS NOT A CHOICE THIS FILE MAKES. A no-op leaves whatever
    /// <c>ClientHelloBuilder</c> already ships as its defaults, which are TLS-1.3-only and are
    /// tested where they live. Writing a browser's suites and groups here instead would put
    /// subsystem E's profile content in subsystem B's factory and give the repo two places that
    /// claim to know what a captured client sends.</remarks>
    /// <exception cref="ArgumentNullException">Set to <see langword="null"/>.</exception>
    public Action<ClientHelloBuilder> Tls
    {
        get => _tls;
        init => _tls = value ?? throw new ArgumentNullException(nameof(Tls));
    }

    /// <summary>Builds one profile for one connection, composing the transport parameters
    /// afresh and drawing every per-connection value again.</summary>
    /// <param name="sourceConnectionId">The connection's own source connection ID, which
    /// becomes <c>initial_source_connection_id</c>. Its length must be
    /// <c>ConnectionSpec.SourceConnectionIdLength</c>.</param>
    /// <remarks>NOTHING IS CACHED AND NOTHING IS MEMOISED, deliberately: two calls with the
    /// same arguments produce two profiles whose encoded transport parameters differ, because
    /// three of the preset's entries are drawn per composition. Witnessed by
    /// <c>TlsQuicClientHelloProfileFactoryTests</c>, which traces the differing bytes to each
    /// of the three drawn parameters separately rather than to "some byte changed".</remarks>
    /// <exception cref="ArgumentException"><paramref name="sourceConnectionId"/>'s length is
    /// not the connection spec's declared length, or the parameter list is one
    /// <c>TlsQuicTransportParameterSpec.Compose</c> refuses.</exception>
    public ClientHelloProfile Create(ReadOnlySpan<byte> sourceConnectionId)
    {
        var parameters = _connectionSpec.TransportParameters.Compose(
            _connectionSpec, sourceConnectionId);

        // Read into locals so the closure captures the two values and not `this`, which keeps
        // the whole factory - and the connection spec hanging off it - out of the delegate's
        // lifetime. ClientHelloProfiles.Custom runs the action synchronously, so this is a
        // shape choice and not a correctness one.
        var alpn = _alpnProtocols;
        var tls = _tls;
        return ClientHelloProfiles.Custom(builder =>
        {
            tls(builder);
            builder
                .WithAlpn(alpn)
                .WithQuicTransportParameters(parameters)

                // RFC 9001 s8.4: QUIC does not use TLS compatibility mode, so the ClientHello's
                // legacy_session_id MUST be empty; a server treats a non-empty one as a protocol
                // violation. Forced HERE, alongside ALPN and the transport parameters, because it
                // is the same kind of rule - QUIC's, not the persona's - and a caller's TLS half
                // cannot be trusted to have got it right.
                //
                // EMPTY IS NOT null. ClientHelloBuilder.WithSessionId(null) means UNSPECIFIED,
                // and ClientHelloEncoder then fills 32 random bytes for TLS 1.3 compatibility
                // mode. That default is correct over TCP and illegal over QUIC, and it is what
                // made BoringSSL peers - www.google.com, cloudflare-quic.com, every Spotify
                // host - answer CRYPTO_ERROR with alert 47 (illegal_parameter) before any
                // request. Lenient stacks accepted it, which is why offline tests and
                // fp.impersonate.pro never showed it.
                .WithSessionId([]);
        });
    }
}
