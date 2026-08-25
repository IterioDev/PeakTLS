using System.Collections.Immutable;
using System.Globalization;
using System.Net;
using System.Text;
using SharpTls.Quic;

namespace TlsClient;

/// <summary>
/// Translates between TlsClient's request and response shapes and RFC 9114 field sections.
/// </summary>
/// <remarks>
/// Split out of <see cref="Http3Connection"/> because everything here is a pure function of
/// its arguments: the whole of the field mapping is testable without a socket, a QUIC
/// handshake or a peer, while SharpTls ships no loopback HTTP/3 peer TlsClient.Tests can
/// reach. <c>Http3Connection.BuildRequestAsync</c> is split out for the same reason and joins
/// these fields to the body and the trailer section, so a whole request's wire image — not
/// only its field section — can be encoded and read back offline.
/// </remarks>
internal static class Http3FieldMapper
{
    /// <summary>
    /// RFC 9114 section 4.2's connection-specific fields, which "MUST NOT be generated" over
    /// HTTP/3, plus <c>proxy-authorization</c> — a hop-by-hop credential that belongs to the
    /// proxy CONNECT tunnel and not to the request carried inside it. The same list
    /// <see cref="Http2Connection"/> drops, spelled lowercase because that is the only casing
    /// HTTP/3 permits on the wire (section 4.2).
    /// </summary>
    private static readonly string[] ConnectionSpecificFields =
    [
        "connection",
        "proxy-connection",
        "keep-alive",
        "upgrade",
        "transfer-encoding",
        "proxy-authorization",
    ];

    /// <summary>
    /// Builds the ordinary field lines of a request, in the order they reach the wire, and
    /// reports the <c>:authority</c> value the caller must pair them with.
    /// </summary>
    /// <remarks>
    /// The merge and the ordering are <see cref="Http11RequestWriter"/>'s, so a persona's
    /// declared header order means the same thing on all three versions. What differs is
    /// after it: HTTP/3 has no Host field (section 4.3.1 carries authority in the
    /// pseudo-header), no connection-specific fields, and no uppercase field name.
    /// </remarks>
    /// <exception cref="HttpRequestException">A field HTTP/3 forbids was declared, or the
    /// field section exceeds the configured request header limit.</exception>
    public static ImmutableArray<TlsQuicHttp3Field> BuildRequestFields(
        BufferedRequest request,
        TlsSessionConfiguration configuration,
        out string authority)
    {
        var merged = Http11RequestWriter.MergeHeaders(request);

        var host = merged.FirstOrDefault(header =>
            string.Equals(header.Name, "Host", StringComparison.OrdinalIgnoreCase));
        authority = host?.Values.FirstOrDefault() ??
            Http11RequestWriter.AuthorityFor(request);

        var fields = ImmutableArray.CreateBuilder<TlsQuicHttp3Field>();
        foreach (var header in merged)
        {
            var name = header.Name.ToLowerInvariant();
            // Section 4.3.1 gives authority its own pseudo-header, and the value above is read
            // from this very field when the request supplies one, so dropping it here cannot
            // lose the caller's choice.
            if (name == "host" || Array.IndexOf(ConnectionSpecificFields, name) >= 0)
            {
                continue;
            }
            if (name == "te")
            {
                // Section 4.2's one exception: "may be sent if the value is 'trailers'".
                if (header.Values.Any(value => !string.Equals(
                        value.Trim(),
                        "trailers",
                        StringComparison.OrdinalIgnoreCase)))
                {
                    throw new HttpRequestException(
                        "HTTP/3 permits TE only with the value 'trailers'.");
                }
            }
            if (name == "cookie")
            {
                // RFC 6265 section 5.4 joins crumbs with "; ". RFC 9114 section 4.2.1 also
                // permits splitting them across field lines; not done here, because the
                // splitting policy that exists is TlsHpackOptions', which is HPACK's and
                // describes an HTTP/2 encoder rather than a QPACK one.
                fields.Add(new TlsQuicHttp3Field(name, string.Join("; ", header.Values)));
                continue;
            }
            foreach (var value in header.Values)
            {
                fields.Add(new TlsQuicHttp3Field(name, value));
            }
        }

        // Section 4.2.2's size, which is the same arithmetic RFC 9113 section 6.5.2 defines
        // and Http2Connection already applies: "the length of the field name, the length of
        // the field value, and 32 additional bytes". Measured against the caller's own limit
        // so that a request too large is refused here rather than by the peer.
        long size = 0;
        foreach (var field in fields)
        {
            size = checked(
                size + 32 + Encoding.UTF8.GetByteCount(field.Name) +
                Encoding.UTF8.GetByteCount(field.Value));
        }
        // The four pseudo-headers the caller pairs with these fields are part of the same
        // section; approximated by their names and the authority, which are all this method
        // can see.
        size = checked(size + 4 * 32 + Encoding.UTF8.GetByteCount(authority));
        if (size > configuration.MaximumRequestHeaderBytes)
        {
            throw new HttpRequestException(
                "The HTTP/3 request field section exceeds the configured limit.");
        }
        return fields.ToImmutable();
    }

    /// <summary>
    /// Builds the trailing field section of a request — RFC 9114 section 4.1's second HEADERS
    /// frame — or an empty section when the request declares no trailers.
    /// </summary>
    /// <remarks>
    /// <para>The same validation <see cref="Http2Connection"/> applies to an HTTP/2 trailer
    /// block, for the same reasons, plus HTTP/3's lowercase rule. It is deliberately a SECOND
    /// pass over names <c>TlsRequestOptions</c> already checked: a <see cref="BufferedRequest"/>
    /// can also be built directly, and a trailer that names <c>content-length</c> would
    /// otherwise contradict the header section's.</para>
    /// <para>NO PSEUDO-HEADER FILTER HERE. A name beginning with a colon is not dropped and not
    /// diagnosed here — <c>TlsQuicHttp3Request.TryEncode</c> refuses the whole request with
    /// <c>PseudoHeaderInTrailerSection</c>, which is section 4.3's rule stated once rather than
    /// twice, and silently dropping the field would send a trailer section the caller did not
    /// write.</para>
    /// </remarks>
    /// <exception cref="ArgumentException">A trailer names a field that may not be trailed.
    /// </exception>
    /// <exception cref="HttpRequestException">A trailer value carries a delimiter, or the
    /// trailer section exceeds the configured request header limit.</exception>
    public static ImmutableArray<TlsQuicHttp3Field> BuildTrailerFields(
        BufferedRequest request,
        TlsSessionConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(configuration);
        if (!request.HasTrailers)
        {
            return [];
        }

        var fields = ImmutableArray.CreateBuilder<TlsQuicHttp3Field>();
        long size = 0;
        foreach (var trailer in request.Trailers)
        {
            var name = trailer.Name.ToLowerInvariant();
            TlsRequestOptions.ValidateTrailerName(name);
            foreach (var value in trailer.Values)
            {
                Http11RequestWriter.ValidateHeaderValue(value);
                size = checked(
                    size + 32 + Encoding.UTF8.GetByteCount(name) +
                    Encoding.UTF8.GetByteCount(value));
                fields.Add(new TlsQuicHttp3Field(name, value));
            }
        }
        if (size > configuration.MaximumRequestHeaderBytes)
        {
            throw new HttpRequestException(
                "The HTTP/3 request trailers exceed the configured limit.");
        }
        return fields.ToImmutable();
    }

    /// <summary>Reads RFC 9114 section 4.3.2's <c>:status</c>.</summary>
    /// <exception cref="TlsHttpProtocolException">The peer sent no status, or one outside
    /// the three-digit range.</exception>
    public static HttpStatusCode ReadStatus(int status)
    {
        if (status is < 100 or > 999)
        {
            throw Malformed("The HTTP/3 response has no valid :status.");
        }
        return (HttpStatusCode)status;
    }

    /// <summary>
    /// Turns one field section into headers, dropping pseudo-headers and rejecting the field
    /// names and values RFC 9114 section 4.2 forbids a peer to send.
    /// </summary>
    /// <remarks>
    /// <para>PSEUDO-HEADERS ARE NOT HEADERS. <c>TlsQuicHttp3Response.HeaderFields</c> keeps
    /// <c>:status</c> in the section it decoded, and a caller reading
    /// <c>response.Headers[":status"]</c> would be reading a wire artefact rather than an
    /// HTTP field — RFC 9114 section 4.3: "Pseudo-header fields are not HTTP fields."
    /// HTTP/1.1 and HTTP/2 both hand the caller a TlsHeaders without one, and this keeps the
    /// three the same.</para>
    /// <para>The byte count runs across both calls for one response, header section and
    /// trailer section together, which is why it is a <c>ref</c> parameter: the configured
    /// limit is a limit on what one response may spend, not on each of its sections.</para>
    /// </remarks>
    /// <exception cref="TlsHttpProtocolException">A field name or value is one section 4.2
    /// forbids, or the section passes the configured limits.</exception>
    public static TlsHeaders BuildHeaders(
        ImmutableArray<TlsQuicHttp3Field> fields,
        int maximumBytes,
        int maximumCount,
        ref int consumedBytes)
    {
        var headers = new TlsHeaders();
        var count = 0;
        foreach (var field in fields)
        {
            if (field.Name.StartsWith(':'))
            {
                continue;
            }
            ValidateReceivedField(field);
            if (++count > maximumCount)
            {
                throw Malformed("Too many HTTP/3 response headers were received.");
            }
            consumedBytes = checked(
                consumedBytes + field.Name.Length + field.Value.Length + 2);
            if (consumedBytes > maximumBytes)
            {
                throw Malformed("The HTTP/3 response headers exceeded the configured limit.");
            }
            // RFC 9110 section 5.5: "A field value does not include leading or trailing
            // whitespace." Trimmed rather than rejected, so that the same origin hands a
            // caller the same string over all three versions.
            headers.Add(field.Name, field.Value.Trim(' ', '\t'));
        }
        return headers;
    }

    /// <summary>
    /// Gets whether a response to <paramref name="method"/> with this status carries content.
    /// </summary>
    /// <remarks>RFC 9110 sections 9.3.2, 15.3.5 and 15.4.5, which is the same rule
    /// <see cref="Http2Connection"/> applies: a HEAD response, an informational response, a
    /// 204 and a 304 have no content however many body octets arrive.</remarks>
    public static bool HasResponseBody(string method, HttpStatusCode status) =>
        method != "HEAD" &&
        (int)status is not (>= 100 and < 200) and not 204 and not 304;

    /// <summary>Applies RFC 9114 section 4.1.2's Content-Length rule.</summary>
    /// <exception cref="TlsHttpProtocolException">The field is unparsable, repeated, or
    /// disagrees with the octets received.</exception>
    public static void ValidateContentLength(
        TlsHeaders headers,
        string method,
        long bodyLength)
    {
        if (!headers.TryGetValues("Content-Length", out var values))
        {
            return;
        }
        if (values.Count != 1 || !long.TryParse(
                values[0],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var declared) || declared < 0 ||
            (method != "HEAD" && declared != bodyLength))
        {
            throw Malformed("The HTTP/3 Content-Length is invalid.");
        }
    }

    /// <summary>
    /// Applies the field validation RFC 9114 section 4.2 makes mandatory on a received field.
    /// </summary>
    /// <remarks>
    /// The same rules <see cref="Http2Connection"/> applies to an HPACK-decoded field, for the
    /// same reason: a name carrying a delimiter, a control character or an uppercase letter,
    /// or a value carrying NUL, CR or LF, is a request-splitting vector the moment a caller
    /// copies it into another protocol. QPACK's decoder is not asked to be the only guard.
    /// </remarks>
    private static void ValidateReceivedField(TlsQuicHttp3Field field)
    {
        var name = field.Name;
        if (name.Length == 0)
        {
            throw Malformed("An HTTP/3 response field name is empty.");
        }
        for (var index = 0; index < name.Length; index++)
        {
            var character = name[index];
            if (character <= 0x20 || character >= 0x7f ||
                character is >= 'A' and <= 'Z' || character == ':')
            {
                throw Malformed(
                    "An HTTP/3 response field name contains a prohibited character.");
            }
        }
        foreach (var character in field.Value)
        {
            if (character is '\0' or '\n' or '\r')
            {
                throw Malformed("An HTTP/3 response field value contains NUL, CR, or LF.");
            }
        }
    }

    private static TlsHttpProtocolException Malformed(string message) =>
        new(message) { IsStreamScoped = true };
}
