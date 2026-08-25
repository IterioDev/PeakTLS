namespace TlsClient;

/// <summary>Controls behavior that belongs to one <see cref="HttpRequestMessage"/>.</summary>
public sealed class TlsRequestOptions
{
    private static readonly HttpRequestOptionsKey<TlsRequestOptions> OptionsKey =
        new("TlsClient.RequestOptions");
    private TlsRequestReplayPolicy _replayPolicy;
    private TlsProxy? _proxy;
    private bool _hasProxyOverride;

    /// <summary>
    /// Gets the request's header fields. This collection is the sole source of the wire's field
    /// section: a field reaches the wire if and only if it appears here, in the order it was
    /// added. Nothing is synthesised — an absent <c>Host</c> means no <c>Host</c> field, and an
    /// absent <c>Cookie</c> means the session container contributes nothing.
    /// </summary>
    /// <remarks>
    /// <para>Values are stored verbatim. Nothing passes through <c>HttpRequestHeaders</c>, which
    /// is what keeps <c>accept-encoding: gzip, deflate, br</c> a single field line carrying
    /// those exact bytes rather than the three that collection's reflow produces.</para>
    /// <para><c>Content-Length</c> and <c>Transfer-Encoding</c> are the one exception, and it
    /// covers the value only: whichever of the two is added reserves the position, and the
    /// computed framing field replaces it there.</para>
    /// </remarks>
    public TlsHeaders Headers { get; } = new();

    /// <summary>Gets request trailer fields sent after the content body.</summary>
    public TlsHeaders Trailers { get; } = new();

    /// <summary>
    /// Gets or sets how a streamed request body may be made replayable. The default never
    /// buffers a streaming source.
    /// </summary>
    public TlsRequestReplayPolicy ReplayPolicy
    {
        get => _replayPolicy;
        set
        {
            if (!Enum.IsDefined(value))
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }
            _replayPolicy = value;
        }
    }

    /// <summary>
    /// Gets or sets the proxy for this request. Leaving the property untouched inherits the
    /// session proxy; assigning null explicitly selects a direct connection.
    /// </summary>
    public TlsProxy? Proxy
    {
        get => _proxy;
        set
        {
            _proxy = value;
            _hasProxyOverride = true;
        }
    }

    /// <summary>
    /// Gets or sets whether retries are enabled for this request. Null inherits session policy.
    /// </summary>
    public bool? EnableRetries { get; set; }

    /// <summary>
    /// Gets or sets the HTTP/2 frames written immediately before this request's header block.
    /// Empty by default, which is what keeps the emitted request image unchanged.
    /// </summary>
    /// <remarks>
    /// A declared frame's stream identifier is <c>0</c> as a sentinel meaning "this request's
    /// stream", resolved when the frame is written because the identifier is not allocated
    /// until then. That is why a frame which genuinely targets stream 0 — a connection-level
    /// frame such as PING, SETTINGS or WINDOW_UPDATE — is declared as
    /// <see cref="TlsHttp2RequestRawFrame"/>, whose stream identifier is written verbatim and
    /// never substituted. The sentinel applies only to the frame classes whose natural target
    /// is the request's own stream.
    /// </remarks>
    public IReadOnlyList<TlsHttp2RequestFrame> FramesBeforeHeaders { get; set; } = [];

    /// <summary>
    /// Gets or sets the HTTP/2 frames written immediately after this request's header block,
    /// which means after the final CONTINUATION frame rather than after the HEADERS frame:
    /// RFC 9113 section 4.3 requires a field block to be a contiguous sequence with no
    /// interleaved frames of any other type or from any other stream. Empty by default.
    /// </summary>
    /// <remarks>
    /// The stream-identifier sentinel described on <see cref="FramesBeforeHeaders"/> applies
    /// here identically.
    /// </remarks>
    public IReadOnlyList<TlsHttp2RequestFrame> FramesAfterHeaders { get; set; } = [];

    /// <summary>
    /// Gets or sets the preferred header order for this request. Null inherits
    /// <see cref="TlsSessionOptions.HeaderOrder"/>.
    /// </summary>
    /// <remarks>
    /// Unlike the other overrides here, this one applies to HTTP/1.1 as well as HTTP/2: the
    /// HTTP/1.1 writer and the HTTP/2 header builder already share one ordering routine, and
    /// splitting the semantics by protocol would be surprising.
    /// </remarks>
    public IReadOnlyList<string>? HeaderOrder { get; set; }

    /// <summary>
    /// Gets or sets the pseudo-header wire order for this request. Null inherits
    /// <see cref="TlsHttp2PseudoHeaderOptions.Order"/>. HTTP/2 only.
    /// </summary>
    /// <remarks>
    /// Ignored rather than rejected on an HTTP/1.1 connection, which has no pseudo-headers,
    /// so a persona survives a version fallback intact. The same applies to
    /// <see cref="HeaderPriority"/> and <see cref="PriorityUpdate"/>.
    /// </remarks>
    public IReadOnlyList<string>? PseudoHeaderOrder { get; set; }

    /// <summary>
    /// Gets or sets the RFC 7540 priority data embedded in this request's HEADERS frame.
    /// Null inherits <see cref="TlsHttp2Options.HeaderPriority"/>. HTTP/2 only, and ignored
    /// on an HTTP/1.1 connection.
    /// </summary>
    public TlsHttp2Priority? HeaderPriority { get; set; }

    /// <summary>
    /// Gets or sets the RFC 9218 Priority Field Value sent in a PRIORITY_UPDATE frame after
    /// this request's header block, for example <c>u=3, i</c>. Null inherits
    /// <see cref="TlsHttp2Options.PriorityUpdate"/>. HTTP/2 only, and ignored on an HTTP/1.1
    /// connection.
    /// </summary>
    /// <remarks>
    /// A <see cref="TlsHttp2PriorityUpdateFrame"/> declared in <see cref="FramesBeforeHeaders"/>
    /// or <see cref="FramesAfterHeaders"/> suppresses this value as well as the session's,
    /// because the declared frame owns the placement.
    /// </remarks>
    public string? PriorityUpdate { get; set; }

    /// <summary>
    /// Gets or sets the padding written on this request's HEADERS frame, or null for a frame
    /// with no PADDED flag at all. Valid values are 0 to 255. HTTP/2 only, and ignored on an
    /// HTTP/1.1 connection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Null and <c>0</c> are two different wire images, which is the whole reason this is
    /// nullable rather than an <see cref="int"/> defaulting to zero. Null clears the PADDED
    /// flag and the frame carries no Pad Length field; <c>0</c> sets PADDED with an empty pad,
    /// and RFC 9113 section 6.2 calls that out directly: "A frame can be increased in size by
    /// one octet by including a Pad Length field with a value of zero."
    /// </para>
    /// <para>
    /// The upper bound is 255 because the Pad Length field is a single octet (RFC 9113
    /// section 6.2). The pad comes out of the frame's payload budget along with the Pad Length
    /// octet and the priority payload, so a padded header block fragments sooner. Only the
    /// leading HEADERS frame is padded: CONTINUATION has neither a PADDED flag nor a Pad
    /// Length field (RFC 9113 section 6.10), so the pad is paid once however many fragments
    /// the block needs. Request trailers are a separate field block and are never padded by
    /// this value.
    /// </para>
    /// </remarks>
    public int? HeadersPadding { get; set; }

    /// <summary>
    /// Gets or sets the padding written on each of this request's DATA frames, or null for
    /// frames with no PADDED flag at all. Valid values are 0 to 255. HTTP/2 only, and ignored
    /// on an HTTP/1.1 connection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Nullable for the same reason as <see cref="HeadersPadding"/> — RFC 9113 section 6.1
    /// carries the same "increased in size by one octet" note for DATA — and bounded to 0-255
    /// by the same one-octet Pad Length field.
    /// </para>
    /// <para>
    /// The pad costs flow-control credit. RFC 9113 section 6.1: "The entire DATA frame payload
    /// is included in flow control, including the Pad Length and Padding fields." A padded
    /// upload therefore consumes more of the peer's advertised window than its body length and
    /// is split across more frames than the same body unpadded.
    /// </para>
    /// <para>
    /// The zero-length DATA frame that closes a streamed request is left unpadded. RFC 9113
    /// section 6.9.1 permits sending an empty END_STREAM frame "if there is no available space
    /// in either flow-control window", and padding it would turn a free end-of-stream marker
    /// into a frame that needs credit the client may not have.
    /// </para>
    /// </remarks>
    public int? DataPadding { get; set; }

    /// <summary>
    /// Gets or sets the value written as <c>:scheme</c> for this request. Null inherits
    /// <see cref="TlsHttp2PseudoHeaderOptions.Scheme"/>. HTTP/2 only, and ignored on an
    /// HTTP/1.1 connection.
    /// </summary>
    /// <remarks>
    /// Emitted only when <c>:scheme</c> appears in the effective pseudo-header order, which
    /// is how a plain CONNECT — RFC 9113 section 8.5 requires <c>:scheme</c> and <c>:path</c>
    /// be omitted — remains expressible alongside this override.
    /// </remarks>
    public string? Scheme { get; set; }

    /// <summary>
    /// Gets or sets the RFC 8441 section 4 <c>:protocol</c> pseudo-header value for this
    /// request, for example <c>websocket</c>. Null emits no <c>:protocol</c>. HTTP/2 only,
    /// and ignored on an HTTP/1.1 connection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The field is written only when this value is set <em>and</em> <c>:protocol</c> appears
    /// in the effective pseudo-header order. RFC 8441 section 4 also requires that "On
    /// requests that contain the :protocol pseudo-header field, the :scheme and :path
    /// pseudo-header fields of the target URI MUST also be included", so an order that omits
    /// them produces a malformed extended CONNECT.
    /// </para>
    /// <para>
    /// Setting it emits the field and nothing more: TlsClient does not implement the
    /// bidirectional tunnel RFC 8441 bootstraps, does not gate emission on the peer's
    /// <c>SETTINGS_ENABLE_CONNECT_PROTOCOL</c> (RFC 8441 section 3), and keeps the stream's
    /// ordinary request lifetime. A peer that has not advertised the setting answers a stream
    /// error, exactly as RFC 8441 section 3 describes.
    /// </para>
    /// </remarks>
    public string? Protocol { get; set; }

    /// <summary>
    /// Gets or sets the exact value written as <c>:path</c> for this request, or as the
    /// request-target on an HTTP/1.1 connection. Null derives it from the request URI as usual.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The value reaches the wire verbatim and is not normalised against the request URI,
    /// which is what makes the asterisk form expressible: RFC 9113 section 8.3.1 requires
    /// "an OPTIONS request for an 'http' or 'https' URI that does not include a path
    /// component" to carry a <c>:path</c> of <c>*</c>, and no URI can produce that string.
    /// RFC 9112 section 3.2.4 is the HTTP/1.1 half of the same rule — "asterisk-form = '*'",
    /// "only used for a server-wide OPTIONS request" — so the override is honoured on both
    /// versions and a version fallback does not turn <c>OPTIONS *</c> into <c>OPTIONS /</c>,
    /// which addresses a different resource.
    /// </para>
    /// <para>
    /// A CONNECT request ignores it. RFC 9112 section 3.2.3 makes that method's target an
    /// authority rather than a path, so there is nothing here to override.
    /// </para>
    /// </remarks>
    public string? PathOverride { get; set; }

    /// <summary>
    /// Gets or sets how this request conveys its target authority. Null inherits
    /// <see cref="TlsHttp2PseudoHeaderOptions.AuthorityMode"/>. HTTP/2 only, and ignored on
    /// an HTTP/1.1 connection, which always carries a <c>Host</c> field.
    /// </summary>
    public TlsHttp2AuthorityMode? AuthorityMode { get; set; }

    /// <summary>Restores inheritance of the session-wide proxy.</summary>
    public void UseSessionProxy()
    {
        _proxy = null;
        _hasProxyOverride = false;
    }

    /// <summary>
    /// The request's header names, in the order they were added, read WITHOUT parsing the
    /// values.
    /// </summary>
    /// <remarks>
    /// <para>USE THIS INSTEAD OF <c>request.Headers.Select(header =&gt; header.Key)</c>, which
    /// silently rewrites the request. Enumerating <see cref="HttpRequestMessage.Headers"/> is
    /// the VALIDATED view, and .NET parses every known structured header the first time that
    /// view is read - then keeps the parsed form and discards the string you supplied. One
    /// caller value becomes several, and the request goes out with several field lines where a
    /// real client sends one:</para>
    /// <code>
    /// accept-encoding: gzip, deflate, br    -&gt; "gzip" "deflate" "br"      (3 field lines)
    /// user-agent: Spotify/9.1.76 iOS/27.0   -&gt; "Spotify/9.1.76" "iOS/27.0" (2 field lines)
    /// accept-language: en-US,en;q=0.9       -&gt; "en-US" "en; q=0.9"         (2, and a space
    ///                                                                        appears inside
    ///                                                                        the second)
    /// </code>
    /// <para>IT CANNOT BE UNDONE AFTERWARDS, which is why this exists rather than a repair.
    /// The separators differ per header - a comma for Accept-Encoding, a space for User-Agent -
    /// and the Accept-Language case above shows .NET also reflows whitespace INSIDE a value, so
    /// no rejoin reproduces the bytes that were handed in. The only fix is not to lose them.
    /// </para>
    /// <para>This reads <c>NonValidated</c>, which returns the stored strings and leaves them
    /// stored, so a request whose names are taken this way still sends exactly what its caller
    /// wrote. Content headers follow the request's own, and a name appearing in both is listed
    /// once - <see cref="TlsSessionOptions.HeaderOrder"/> requires distinct names.</para>
    /// </remarks>
    /// <param name="request">The request whose header names are wanted.</param>
    /// <returns>The header names, in insertion order.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is
    /// <see langword="null"/>.</exception>
    public static string[] HeaderNamesOf(HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var names = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var header in request.Headers.NonValidated)
        {
            if (seen.Add(header.Key))
            {
                names.Add(header.Key);
            }
        }

        if (request.Content is { } content)
        {
            foreach (var header in content.Headers.NonValidated)
            {
                if (seen.Add(header.Key))
                {
                    names.Add(header.Key);
                }
            }
        }

        return [.. names];
    }

    /// <summary>Gets or creates the TlsClient options attached to a request.</summary>
    public static TlsRequestOptions For(HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Options.TryGetValue(OptionsKey, out var options))
        {
            return options;
        }
        options = new TlsRequestOptions();
        request.Options.Set(OptionsKey, options);
        return options;
    }

    internal static TlsRequestConfiguration Snapshot(HttpRequestMessage request)
    {
        if (!request.Options.TryGetValue(OptionsKey, out var options))
        {
            return new TlsRequestConfiguration(
                [],
                TlsRequestReplayPolicy.Never,
                false,
                null,
                null,
                [],
                [],
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null);
        }
        var trailers = options.Trailers.Snapshot();
        foreach (var trailer in trailers)
        {
            ValidateTrailerName(trailer.Name);
        }
        return new TlsRequestConfiguration(
            trailers,
            options.ReplayPolicy,
            options._hasProxyOverride,
            options._proxy,
            options.EnableRetries,
            TlsHttp2RequestFrameList.Freeze(
                options.FramesBeforeHeaders,
                nameof(FramesBeforeHeaders)),
            TlsHttp2RequestFrameList.Freeze(
                options.FramesAfterHeaders,
                nameof(FramesAfterHeaders)),
            // Null stays null all the way to the send path, where it selects the session
            // value. Validating a declared override here rather than at the connection means
            // an illegal one is rejected whichever protocol the request ends up on.
            options.HeaderOrder is null
                ? null
                : TlsSessionOptions.ValidateHeaderOrder(
                    options.HeaderOrder,
                    nameof(HeaderOrder)),
            options.PseudoHeaderOrder is null
                ? null
                : TlsHttp2PseudoHeaderOptions.ValidateOrder(
                    options.PseudoHeaderOrder,
                    nameof(PseudoHeaderOrder)),
            options.HeaderPriority?.Snapshot(),
            ValidatedPriorityUpdate(options.PriorityUpdate),
            ValidatedPadding(options.HeadersPadding, nameof(HeadersPadding)),
            ValidatedPadding(options.DataPadding, nameof(DataPadding)),
            options.Scheme is null
                ? null
                : TlsHttp2PseudoHeaderOptions.ValidateScheme(options.Scheme, nameof(Scheme)),
            ValidatedProtocol(options.Protocol),
            ValidatedPathOverride(options.PathOverride),
            ValidatedAuthorityMode(options.AuthorityMode, nameof(AuthorityMode)));
    }

    private static string? ValidatedProtocol(string? value)
    {
        TlsHttp2PseudoHeaderOptions.ValidateProtocol(value, nameof(Protocol));
        return value;
    }

    private static string? ValidatedPathOverride(string? value)
    {
        TlsHttp2PseudoHeaderOptions.ValidatePathOverride(value, nameof(PathOverride));
        return value;
    }

    private static TlsHttp2AuthorityMode? ValidatedAuthorityMode(
        TlsHttp2AuthorityMode? value,
        string parameterName)
    {
        if (value is { } mode && !Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                "AuthorityMode must be a defined value.");
        }
        return value;
    }

    private static string? ValidatedPriorityUpdate(string? value)
    {
        TlsHttp2Options.ValidatePriorityUpdate(value, nameof(PriorityUpdate));
        return value;
    }

    /// <summary>
    /// Bounds a declared pad to what the wire can carry. The Pad Length field is one octet on
    /// both DATA and HEADERS (RFC 9113 sections 6.1 and 6.2), so 255 is the largest pad any
    /// frame can describe; null stays null and means the PADDED flag is not set at all.
    /// </summary>
    private static int? ValidatedPadding(int? value, string name)
    {
        if (value is < 0 or > 255)
        {
            throw new ArgumentOutOfRangeException(
                name,
                value,
                "HTTP/2 frame padding must be between 0 and 255 octets.");
        }
        return value;
    }

    internal static void ValidateTrailerName(string name)
    {
        if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("TE", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Trailer", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"The '{name}' field is not permitted in request trailers.",
                nameof(name));
        }
    }
}

/// <summary>Controls whether a streaming upload may be replayed.</summary>
public enum TlsRequestReplayPolicy
{
    /// <summary>Never buffers the source; resend-required redirects and retries fail.</summary>
    Never,

    /// <summary>Buffers the complete request body within the session request-body limit.</summary>
    Buffer,
}

internal sealed record TlsRequestConfiguration(
    HeaderEntry[] Trailers,
    TlsRequestReplayPolicy ReplayPolicy,
    bool HasProxyOverride,
    TlsProxy? Proxy,
    bool? EnableRetries,
    TlsHttp2RequestFrameConfiguration[] FramesBeforeHeaders,
    TlsHttp2RequestFrameConfiguration[] FramesAfterHeaders,
    string[]? HeaderOrder,
    string[]? PseudoHeaderOrder,
    TlsHttp2PriorityConfiguration? HeaderPriority,
    string? PriorityUpdate,
    int? HeadersPadding,
    int? DataPadding,
    string? Scheme,
    string? Protocol,
    string? PathOverride,
    TlsHttp2AuthorityMode? AuthorityMode);
