namespace TlsClient;

/// <summary>Adds header fields to an <see cref="HttpRequestMessage"/>.</summary>
public static class TlsRequestHeaderExtensions
{
    /// <summary>
    /// Adds a header field to <paramref name="request"/>.
    /// </summary>
    /// <remarks>
    /// <para>This is the only way a field reaches the wire. <c>request.Headers</c> and
    /// <c>request.Content.Headers</c> are not read: .NET rejects the <c>Content-*</c> family on
    /// the former and appends the latter, so neither can express the position a captured client
    /// puts a content field in. Both also reflow values on the way in, which cannot be undone
    /// afterwards.</para>
    /// <para>Nothing is synthesised to fill a gap. A request with no <c>Host</c> sends no
    /// <c>Host</c> field, which RFC 9112 section 3.2 makes malformed over HTTP/1.1 — add one.
    /// A request with a body must add <c>Content-Length</c> or <c>Transfer-Encoding</c> to
    /// place the framing field; the value there is a placeholder, since the real one is always
    /// computed.</para>
    /// </remarks>
    /// <param name="request">The request.</param>
    /// <param name="name">The field name. Must be a valid token.</param>
    /// <param name="value">The field value, sent verbatim.</param>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> or
    /// <paramref name="value"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a valid token, or
    /// <paramref name="value"/> carries CR, LF, or surrounding whitespace.</exception>
    public static void AddHeader(this HttpRequestMessage request, string name, string value)
    {
        ArgumentNullException.ThrowIfNull(request);
        TlsRequestOptions.For(request).Headers.Add(name, value);
    }
}
