using System.Buffers;
using System.Text;

namespace TlsClient;

internal static class Http11RequestWriter
{
    private static readonly SearchValues<char> InvalidMethodCharacters = SearchValues.Create(
        "()<>@,;:\\\"/[]?={} \t\r\n");

    public static byte[] SerializeHeaders(
        BufferedRequest request,
        string[] preferredOrder,
        string? cookieHeader)
    {
        var headers = MergeHeaders(request, cookieHeader);
        if (!Contains(headers, "Connection"))
        {
            headers.Add(new HeaderEntry("Connection", ["keep-alive"]));
        }

        headers = Order(headers, preferredOrder);
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

    // emitTrailerHeader decides whether a request carrying trailers also gets a Trailer
    // field naming them, the field RFC 9110 section 6.6.2 defines for that purpose. Only the
    // HTTP/2 header builder ever passes false: the switch lives on
    // TlsHttp2Options.EmitTrailerHeader because it is HTTP/2 clients that generally omit the
    // field, and the HTTP/1.1 callers here have no HTTP/2 session to read it from.
    internal static List<HeaderEntry> MergeHeaders(
        BufferedRequest request,
        string? cookieHeader,
        bool emitTrailerHeader = true)
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

        // A caller may reserve the body-framing field's POSITION by declaring Content-Length or
        // Transfer-Encoding with any value at all — the value is always recomputed, so a
        // placeholder like "-1" is fine and only the slot survives. Without this the generated
        // field is appended, which no captured client does: real ones interleave it.
        var framingAnchor = FramingAnchor(headers);
        Remove(headers, "Content-Length");
        Remove(headers, "Transfer-Encoding");

        if (!Contains(headers, "Host"))
        {
            // RFC 9113 section 8.5 defines a plain CONNECT's ":authority" as "the host and port
            // to connect to (equivalent to the authority-form of the request-target of CONNECT
            // requests; see Section 3.2.3 of [HTTP/1.1])", and RFC 9112 section 3.2.3 makes the
            // port mandatory in that form. Http2Connection.BuildRequestHeaders reads
            // ":authority" out of this very field, so a default port elided here reaches the
            // wire as a CONNECT that "does not conform to these restrictions" and is therefore
            // malformed (section 8.5). RFC 8441 section 4 hands ":authority" back to ordinary
            // section 8.3.1 semantics once ":protocol" is present, so extended CONNECT elides a
            // default port like every other method.
            var connectAuthority =
                string.Equals(request.Method, "CONNECT", StringComparison.Ordinal) &&
                request.Protocol is null;
            headers.Insert(
                0,
                new HeaderEntry("Host", [FormatAuthority(request.Url, connectAuthority)]));
        }
        if (!Contains(headers, "Cookie") && !string.IsNullOrEmpty(cookieHeader))
        {
            headers.Add(new HeaderEntry("Cookie", [cookieHeader]));
        }
        if (request.HasPayload)
        {
            if (!request.HasTrailers && request.ContentLength is { } contentLength)
            {
                InsertFraming(
                    headers,
                    framingAnchor,
                    new HeaderEntry(
                        "Content-Length",
                        [contentLength.ToString(System.Globalization.CultureInfo.InvariantCulture)]));
            }
            else
            {
                InsertFraming(
                    headers,
                    framingAnchor,
                    new HeaderEntry("Transfer-Encoding", ["chunked"]));
            }
            if (request.HasTrailers)
            {
                // Dropped whether or not one is generated, so a caller-supplied Trailer field
                // cannot survive the suppression and reach the wire in its place.
                Remove(headers, "Trailer");
                if (emitTrailerHeader)
                {
                    headers.Add(new HeaderEntry(
                        "Trailer",
                        [string.Join(", ", request.Trailers.Select(trailer => trailer.Name))]));
                }
            }
        }
        return headers;
    }

    internal static bool Has100Continue(
        BufferedRequest request,
        string? cookieHeader)
    {
        var headers = MergeHeaders(request, cookieHeader);
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

    internal static List<HeaderEntry> Order(List<HeaderEntry> headers, string[] preferredOrder)
    {
        if (preferredOrder.Length == 0)
        {
            return headers;
        }

        var ordered = new List<HeaderEntry>(headers.Count);
        foreach (var name in preferredOrder)
        {
            var index = headers.FindIndex(header =>
                string.Equals(header.Name, name, StringComparison.OrdinalIgnoreCase));
            if (index < 0)
            {
                continue;
            }
            ordered.Add(headers[index]);
            headers.RemoveAt(index);
        }
        ordered.AddRange(headers);
        return ordered;
    }

    /// <summary>
    /// Reports the slot a caller reserved for the body-framing field: the name of the header it
    /// sat behind, or null when it was first. <c>Reserved</c> is false when no slot was declared,
    /// in which case the generated field is appended as before.
    /// </summary>
    private static (bool Reserved, string? Behind) FramingAnchor(List<HeaderEntry> headers)
    {
        for (var index = 0; index < headers.Count; index++)
        {
            var name = headers[index].Name;
            if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
            {
                return (true, index == 0 ? null : headers[index - 1].Name);
            }
        }
        return (false, null);
    }

    /// <summary>
    /// Places the generated body-framing field in the slot <see cref="FramingAnchor"/> found, or
    /// appends it when the caller reserved none.
    /// </summary>
    private static void InsertFraming(
        List<HeaderEntry> headers,
        (bool Reserved, string? Behind) anchor,
        HeaderEntry entry)
    {
        if (!anchor.Reserved)
        {
            headers.Add(entry);
            return;
        }
        if (anchor.Behind is null)
        {
            // The slot was first. Host is synthesised at index 0 for HTTP/1.1 and must stay
            // there, so land immediately after it when it is present.
            headers.Insert(Contains(headers, "Host") ? 1 : 0, entry);
            return;
        }
        var behind = headers.FindIndex(header =>
            string.Equals(header.Name, anchor.Behind, StringComparison.OrdinalIgnoreCase));
        headers.Insert(behind < 0 ? headers.Count : behind + 1, entry);
    }

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
