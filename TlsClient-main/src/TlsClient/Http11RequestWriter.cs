using System.Buffers;
using System.Text;

namespace TlsClient;

internal static class Http11RequestWriter
{
    private static readonly SearchValues<char> InvalidMethodCharacters = SearchValues.Create(
        "()<>@,;:\\\"/[]?={} \t\r\n");

    public static byte[] SerializeHeaders(BufferedRequest request)
    {
        // No Connection field is generated. RFC 9112 section 9.3 makes HTTP/1.1 persistent by
        // default, so a request that does not add one simply does not send one — and an
        // unrequested keep-alive is a field no capture shows.
        var headers = MergeHeaders(request);

        // RFC 9112 section 3.2.3: "When making a CONNECT request to establish a tunnel through
        // one or more proxies, a client MUST send only the host and port of the tunnel
        // destination as the request-target ... except that it sends the scheme's default port
        // if the target URI elides the port." That is the same authority string MergeHeaders
        // seeds into Host above, and the request.Protocol guard mirrors it: an RFC 8441 extended
        // CONNECT has no HTTP/1.1 expression, so it is left in origin-form rather than mangled.
        // A declared path override reaches the request-line verbatim, exactly as it reaches
        // :path on HTTP/2. RFC 9112 section 3.2.4 gives the one target no URI can produce —
        // "asterisk-form = '*'", "only used for a server-wide OPTIONS request" — and the
        // difference between OPTIONS * and OPTIONS / is which resource is addressed, not
        // cosmetics, so a version fallback must not quietly turn one into the other. CONNECT
        // still wins: its target is an authority by section 3.2.3, and there is no path to
        // override.
        var target = string.Equals(request.Method, "CONNECT", StringComparison.Ordinal) &&
                request.Protocol is null
            ? FormatAuthority(request.Url, includeDefaultPort: true)
            : request.PathOverride ??
                request.Url.GetComponents(UriComponents.PathAndQuery, UriFormat.UriEscaped);
        if (target.Length == 0)
        {
            target = "/";
        }

        var builder = new StringBuilder(512);
        builder.Append(request.Method).Append(' ').Append(target).Append(" HTTP/1.1\r\n");
        foreach (var header in headers)
        {
            ValidateHeaderName(header.Name);
            foreach (var value in header.Values)
            {
                ValidateHeaderValue(value);
                builder.Append(header.Name).Append(": ").Append(value).Append("\r\n");
            }
        }
        builder.Append("\r\n");
        return Encoding.Latin1.GetBytes(builder.ToString());
    }

    // No Trailer field is generated either. RFC 9110 section 6.6.2 defines one for announcing
    // trailers, and a request that wants it adds it — which is also why the session-level
    // switch that used to decide this is gone.
    internal static List<HeaderEntry> MergeHeaders(BufferedRequest request)
    {
        // Every field is the request's own, in the order the caller added it. There is no
        // session-level header set to merge over, so nothing can silently take a position the
        // caller did not choose.
        //
        // The origin-bound filter stays. It used to guard session headers; with those gone the
        // credentials it protects are the caller's own, and a cross-origin redirect must still
        // not carry Authorization or Cookie to the new host.
        var headers = new List<HeaderEntry>(request.Headers.Length);
        foreach (var header in request.Headers)
        {
            if (request.SuppressSensitiveSessionHeaders && IsOriginBoundHeader(header.Name))
            {
                continue;
            }
            BufferedRequest.AddOrReplace(headers, header);
        }

        Remove(headers, "Proxy-Authorization");

        // No Host is synthesised and no Cookie is injected. A request sends the fields it added
        // and no others, so an absent Host — malformed over HTTP/1.1 by RFC 9112 section 3.2 —
        // is the caller's to fix rather than this routine's to paper over, and the session's
        // cookie container records Set-Cookie without ever contributing a request field.
        // FormatAuthority survives for the HTTP/2 and HTTP/3 :authority fallback, which reads
        // the Host field when one was added and derives the authority from the URL when not.
        if (request.HasPayload)
        {
            // The caller reserves the body-framing field's POSITION by adding Content-Length or
            // Transfer-Encoding with any value at all — the value is always recomputed, so a
            // placeholder like "-1" is fine and only the slot survives. Without a slot the field
            // would have to be appended, which no captured client does: real ones interleave it,
            // so an appended one is a distinguisher. The NAME chosen there decides the framing.
            var index = IndexOfFraming(headers);
            if (index < 0)
            {
                throw new InvalidOperationException(
                    "The request has a body, but its header list names neither Content-Length " +
                    "nor Transfer-Encoding. Call request.AddHeader with one of them to place " +
                    "the body-framing field.");
            }
            var lengthKnown = !request.HasTrailers && request.ContentLength is not null;
            var chunked = headers[index].Name.Equals(
                "Transfer-Encoding", StringComparison.OrdinalIgnoreCase);
            if (!chunked && !lengthKnown)
            {
                throw new InvalidOperationException(
                    "The request names Content-Length, but its body length is not known in " +
                    "advance. Name Transfer-Encoding instead.");
            }
            headers[index] = chunked
                ? new HeaderEntry("Transfer-Encoding", ["chunked"])
                : new HeaderEntry(
                    "Content-Length",
                    [request.ContentLength!.Value.ToString(
                        System.Globalization.CultureInfo.InvariantCulture)]);
        }
        return headers;
    }

    internal static bool Has100Continue(BufferedRequest request)
    {
        var headers = MergeHeaders(request);
        return headers
            .Where(header => header.Name.Equals("Expect", StringComparison.OrdinalIgnoreCase))
            .SelectMany(header => header.Values)
            .SelectMany(value => value.Split(','))
            .Any(value => value.Trim().Equals("100-continue", StringComparison.OrdinalIgnoreCase));
    }

    internal static byte[] SerializeTrailers(BufferedRequest request)
    {
        if (!request.HasTrailers)
        {
            return [];
        }
        var builder = new StringBuilder();
        builder.Append("0\r\n");
        foreach (var trailer in request.Trailers)
        {
            ValidateHeaderName(trailer.Name);
            foreach (var value in trailer.Values)
            {
                ValidateHeaderValue(value);
                builder.Append(trailer.Name).Append(": ").Append(value).Append("\r\n");
            }
        }
        builder.Append("\r\n");
        return Encoding.Latin1.GetBytes(builder.ToString());
    }

    public static void ValidateMethod(string method)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        if (!method.All(character => character is > '\u001f' and < '\u007f') ||
            method.AsSpan().IndexOfAny(InvalidMethodCharacters) >= 0)
        {
            throw new ArgumentException("The HTTP method is not a valid token.", nameof(method));
        }
    }

    /// <summary>
    /// Formats the authority of <paramref name="uri"/>, eliding a default port as an origin-form
    /// request does. <paramref name="includeDefaultPort"/> keeps it, which the authority-form of
    /// a CONNECT request-target requires: RFC 9112 section 3.2.3 gives that form as
    /// "authority-form = uri-host ':' port", with no default to fall back on.
    /// </summary>
    internal static string FormatAuthority(Uri uri, bool includeDefaultPort = false)
    {
        var host = uri.HostNameType == UriHostNameType.IPv6 ? $"[{uri.IdnHost}]" : uri.IdnHost;
        return uri.IsDefaultPort && !includeDefaultPort ? host : $"{host}:{uri.Port}";
    }

    /// <summary>
    /// The authority a request conveys when it added no Host field of its own — the value the
    /// HTTP/2 and HTTP/3 <c>:authority</c> fallback uses.
    /// </summary>
    /// <remarks>
    /// RFC 9113 section 8.5 defines a plain CONNECT's <c>:authority</c> as "the host and port to
    /// connect to (equivalent to the authority-form of the request-target of CONNECT requests;
    /// see Section 3.2.3 of [HTTP/1.1])", and RFC 9112 section 3.2.3 makes the port mandatory in
    /// that form, so a default port elided here reaches the wire as a CONNECT that "does not
    /// conform to these restrictions" and is therefore malformed. RFC 8441 section 4 hands
    /// <c>:authority</c> back to ordinary section 8.3.1 semantics once <c>:protocol</c> is
    /// present, so an extended CONNECT elides a default port like every other method.
    /// <para>The rule lives here rather than in the field section because <c>:authority</c> is a
    /// pseudo-header: nothing synthesises a Host field, so a request that wants one adds it, and
    /// the value it added wins over this.</para>
    /// </remarks>
    internal static string AuthorityFor(BufferedRequest request) => FormatAuthority(
        request.Url,
        string.Equals(request.Method, "CONNECT", StringComparison.Ordinal) &&
            request.Protocol is null);

    /// <summary>
    /// Reports the index of the framing slot the caller reserved, or -1. The NAME chosen there
    /// decides the framing, not only the position: Transfer-Encoding forces chunked whatever the
    /// body's length, and Content-Length takes the computed length.
    /// </summary>
    private static int IndexOfFraming(List<HeaderEntry> headers) =>
        headers.FindIndex(header =>
            header.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
            header.Name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase));

    internal static bool Contains(List<HeaderEntry> headers, string name) => headers.Any(
        header => string.Equals(header.Name, name, StringComparison.OrdinalIgnoreCase));

    internal static void Remove(List<HeaderEntry> headers, string name) => headers.RemoveAll(
        header => string.Equals(header.Name, name, StringComparison.OrdinalIgnoreCase));

    private static bool IsOriginBoundHeader(string name) =>
        name.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Host", StringComparison.OrdinalIgnoreCase);

    internal static void ValidateHeaderName(string name)
    {
        var headers = new TlsHeaders();
        headers.Set(name, string.Empty);
    }

    internal static void ValidateHeaderValue(string value)
    {
        if (value.Any(character => character > '\u00ff' ||
            (character < '\u0020' && character != '\t') || character == '\u007f'))
        {
            throw new ArgumentException(
                "HTTP/1.1 header values must contain only Latin-1 text without control characters.",
                nameof(value));
        }
    }
}
