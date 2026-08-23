namespace TlsClient;

/// <summary>Selects how a request conveys the authority of its target URI.</summary>
/// <remarks>
/// RFC 9113 section 8.3.1 governs the choice, and the three modes are not equally
/// conformant. The mode exists as an axis because real stacks differ, not because the
/// specification leaves it open.
/// </remarks>
public enum TlsHttp2AuthorityMode
{
    /// <summary>
    /// Emits <c>:authority</c> and drops any <c>host</c> field. This is the conformant
    /// choice and the default. RFC 9113 section 8.3.1: "Clients that generate HTTP/2
    /// requests directly MUST use the ':authority' pseudo-header field to convey authority
    /// information, unless there is no authority information to convey (in which case it
    /// MUST NOT generate ':authority')."
    /// </summary>
    AuthorityOnly,

    /// <summary>
    /// Emits a regular <c>host</c> field and no <c>:authority</c>.
    /// <para>
    /// <b>This mode deliberately violates a MUST.</b> The RFC 9113 section 8.3.1 sentence
    /// quoted on <see cref="AuthorityOnly"/> requires a client that generates HTTP/2
    /// requests directly to convey authority in <c>:authority</c>; a client is excused only
    /// when there is genuinely no authority information to convey, which is not the case
    /// for a normal origin request. Section 8.3.1 defines no server fallback to <c>host</c>
    /// when <c>:authority</c> is absent, so whether a peer even routes the request is
    /// server-dependent.
    /// </para>
    /// <para>
    /// It is offered because TlsClient reproduces the wire image of clients that exist,
    /// including non-conformant ones — some intermediaries and hand-rolled HTTP/2 stacks
    /// forward the <c>host</c> field they received and never synthesise <c>:authority</c>,
    /// and a capture of one cannot be replayed without this mode. Choose it only to
    /// reproduce such a client, never for a client of your own design.
    /// </para>
    /// </summary>
    HostHeaderOnly,

    /// <summary>
    /// Emits <c>:authority</c> and keeps the <c>host</c> field as well.
    /// <para>
    /// Conformant only while the two carry the same value. RFC 9113 section 8.3.1: "Clients
    /// MUST NOT generate a request with a Host header field that differs from the
    /// ':authority' pseudo-header field", and a server "SHOULD treat a request as malformed"
    /// when they identify different entities. TlsClient derives both from one value — the
    /// request's <c>Host</c> field when it carries one, otherwise the authority of the
    /// request URI — so they agree by construction.
    /// </para>
    /// </summary>
    Both,
}

/// <summary>
/// Declares which request pseudo-headers are emitted, in what order, and how the authority
/// and scheme are conveyed.
/// </summary>
public sealed class TlsHttp2PseudoHeaderOptions
{
    /// <summary>
    /// The request pseudo-headers RFC 9113 section 8.3.1 and RFC 8441 section 4 define.
    /// RFC 9113 section 8.3: "Endpoints MUST NOT generate pseudo-header fields other than
    /// those defined in this document", and <c>:status</c> is response-only (section 8.3.2),
    /// so it is not among them.
    /// </summary>
    private static readonly string[] KnownRequestPseudoHeaders =
        [":method", ":scheme", ":authority", ":path", ":protocol"];

    /// <summary>
    /// Gets or sets the pseudo-headers this session emits, in exact wire order.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The list declares <em>which</em> pseudo-headers are emitted as well as their
    /// sequence: a name absent from it is never written. That is what makes a plain CONNECT
    /// header block — <c>:method</c> and <c>:authority</c> alone, RFC 9113 section 8.5
    /// requiring <c>:scheme</c> and <c>:path</c> be omitted — expressible at all.
    /// </para>
    /// <para>
    /// Order itself is unconstrained by the RFC. Only "All pseudo-header fields MUST appear
    /// in a field block before all regular field lines" is normative (RFC 9113 section 8.3),
    /// which TlsClient guarantees by writing this list first; any permutation of it is legal
    /// and is a pure fingerprint. A name may not repeat — section 8.3 makes a repeated
    /// pseudo-header field name malformed.
    /// </para>
    /// <para>
    /// <c>:protocol</c> (RFC 8441 section 4) is emitted only when it appears here
    /// <em>and</em> <see cref="TlsRequestOptions.Protocol"/> supplies a value, so declaring
    /// it in the order costs nothing on the requests that do not use it.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> Order { get; set; } =
        [":method", ":authority", ":scheme", ":path"];

    /// <summary>
    /// Gets or sets how the target authority is conveyed. The default,
    /// <see cref="TlsHttp2AuthorityMode.AuthorityOnly"/>, is the mode RFC 9113
    /// section 8.3.1 requires of a client generating HTTP/2 requests directly.
    /// </summary>
    public TlsHttp2AuthorityMode AuthorityMode { get; set; } = TlsHttp2AuthorityMode.AuthorityOnly;

    /// <summary>
    /// Gets or sets the value written as <c>:scheme</c>. The default is <c>https</c>.
    /// </summary>
    /// <remarks>
    /// Not restricted to <c>http</c> and <c>https</c>. RFC 9113 section 8.3.1: "':scheme' is
    /// not restricted to 'http' and 'https' schemed URIs. A proxy or gateway can translate
    /// requests for non-HTTP schemes, enabling the use of HTTP to interact with non-HTTP
    /// services." The value is checked against the RFC 3986 section 3.1 scheme grammar.
    /// </remarks>
    public string Scheme { get; set; } = "https";

    internal TlsHttp2PseudoHeaderConfiguration Snapshot()
    {
        if (!Enum.IsDefined(AuthorityMode))
        {
            throw new ArgumentOutOfRangeException(
                nameof(AuthorityMode),
                "AuthorityMode must be a defined value.");
        }
        return new TlsHttp2PseudoHeaderConfiguration(
            ValidateOrder(Order, nameof(Order)),
            AuthorityMode,
            ValidateScheme(Scheme, nameof(Scheme)));
    }

    /// <summary>
    /// Validates a pseudo-header order, session-wide or per request. Shared so a
    /// <see cref="TlsRequestOptions.PseudoHeaderOrder"/> override cannot declare a set the
    /// session would have rejected.
    /// </summary>
    internal static string[] ValidateOrder(IReadOnlyList<string>? order, string parameterName)
    {
        var declared = order?.ToArray() ?? throw new ArgumentNullException(parameterName);
        foreach (var name in declared)
        {
            if (Array.IndexOf(KnownRequestPseudoHeaders, name) < 0)
            {
                throw new ArgumentException(
                    "A pseudo-header order may only name :method, :scheme, :authority, " +
                    ":path, and :protocol. RFC 9113 section 8.3 forbids generating any " +
                    "other pseudo-header field, and :status is response-only.",
                    parameterName);
            }
        }
        if (declared.ToHashSet(StringComparer.Ordinal).Count != declared.Length)
        {
            throw new ArgumentException(
                "A pseudo-header order cannot repeat a name. RFC 9113 section 8.3: \"The " +
                "same pseudo-header field name MUST NOT appear more than once in a field " +
                "block.\"",
                parameterName);
        }
        return declared;
    }

    /// <summary>
    /// Validates a <c>:scheme</c> value against the RFC 3986 section 3.1 grammar
    /// <c>scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )</c>.
    /// </summary>
    internal static string ValidateScheme(string? scheme, string parameterName)
    {
        if (string.IsNullOrEmpty(scheme) ||
            !char.IsAsciiLetter(scheme[0]) ||
            !scheme.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '+' or '-' or '.'))
        {
            throw new ArgumentException(
                "A :scheme value must match the RFC 3986 section 3.1 scheme grammar: a " +
                "letter followed by letters, digits, '+', '-', or '.'.",
                parameterName);
        }
        return scheme;
    }

    /// <summary>
    /// Validates a <c>:protocol</c> value. RFC 8441 section 4 draws it from the HTTP Upgrade
    /// Token Registry, whose entries are protocol names — RFC 9110 section 7.8 defines those
    /// as tokens.
    /// </summary>
    internal static void ValidateProtocol(string? protocol, string parameterName)
    {
        if (protocol is null)
        {
            return;
        }
        if (protocol.Length == 0 || !protocol.All(IsTokenCharacter))
        {
            throw new ArgumentException(
                "A :protocol value must be a non-empty RFC 9110 section 5.6.2 token, the " +
                "shape of an entry in the HTTP Upgrade Token Registry RFC 8441 section 4 " +
                "draws it from.",
                parameterName);
        }
    }

    /// <summary>
    /// Validates a <c>:path</c> override. The value reaches the wire verbatim so that the
    /// asterisk form RFC 9113 section 8.3.1 requires of an authority-less OPTIONS request is
    /// expressible, but it may not be empty and may not carry a character that HTTP/2 forbids
    /// in a field value: RFC 9113 section 8.2.1 rejects a field value containing NUL, CR, or
    /// LF, and neither may it contain a space, which would split the request target.
    /// </summary>
    internal static void ValidatePathOverride(string? path, string parameterName)
    {
        if (path is null)
        {
            return;
        }
        if (path.Length == 0 || path.Any(character => character is < '!' or > '~'))
        {
            throw new ArgumentException(
                "A :path override must be non-empty visible ASCII. RFC 9113 section 8.2.1 " +
                "makes a field value containing NUL, CR, or LF malformed.",
                parameterName);
        }
    }

    /// <summary>RFC 9110 section 5.6.2 tchar.</summary>
    private static bool IsTokenCharacter(char character) =>
        char.IsAsciiLetterOrDigit(character) ||
        character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or
            '^' or '_' or '`' or '|' or '~';
}

/// <summary>The frozen pseudo-header composition a connection writes from.</summary>
internal sealed record TlsHttp2PseudoHeaderConfiguration(
    string[] Order,
    TlsHttp2AuthorityMode AuthorityMode,
    string Scheme);
