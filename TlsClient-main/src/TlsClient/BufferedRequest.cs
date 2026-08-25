using System.Net;
using System.Net.Http.Headers;

namespace TlsClient;

internal sealed record BufferedRequest(
    string Method,
    Uri Url,
    HeaderEntry[] Headers,
    byte[] Body,
    bool HasContent,
    TlsHttpVersionPolicy HttpVersionPolicy = TlsHttpVersionPolicy.PreferHttp2,
    HttpContent? StreamingContent = null,
    int StreamingBufferSize = 64 * 1024)
{
    public HeaderEntry[] Trailers { get; init; } = [];

    public TlsRequestReplayPolicy ReplayPolicy { get; init; }

    public bool HasProxyOverride { get; init; }

    public TlsProxy? Proxy { get; init; }

    public bool? EnableRetries { get; init; }

    public bool SuppressSensitiveSessionHeaders { get; init; }

    /// <summary>Frames written immediately before the HTTP/2 header block. Ignored on HTTP/1.1.</summary>
    public TlsHttp2RequestFrameConfiguration[] FramesBeforeHeaders { get; init; } = [];

    /// <summary>Frames written immediately after the HTTP/2 header block. Ignored on HTTP/1.1.</summary>
    public TlsHttp2RequestFrameConfiguration[] FramesAfterHeaders { get; init; } = [];

    /// <summary>
    /// Header order for this request, or null for the session value. The one per-request
    /// override that applies to HTTP/1.1 as well, because both writers share one routine.
    /// </summary>
    public string[]? HeaderOrder { get; init; }

    /// <summary>Pseudo-header order, or null for the session value. Ignored on HTTP/1.1.</summary>
    public string[]? PseudoHeaderOrder { get; init; }

    /// <summary>HEADERS priority data, or null for the session value. Ignored on HTTP/1.1.</summary>
    public TlsHttp2PriorityConfiguration? HeaderPriority { get; init; }

    /// <summary>PRIORITY_UPDATE value, or null for the session value. Ignored on HTTP/1.1.</summary>
    public string? PriorityUpdate { get; init; }

    /// <summary>
    /// Pad written on the HEADERS frame, or null for no PADDED flag. The two are distinct wire
    /// images (RFC 9113 section 6.2). Ignored on HTTP/1.1.
    /// </summary>
    public int? HeadersPadding { get; init; }

    /// <summary>
    /// Pad written on every DATA frame, or null for no PADDED flag. Charged to the send window
    /// along with the data (RFC 9113 section 6.1). Ignored on HTTP/1.1.
    /// </summary>
    public int? DataPadding { get; init; }

    /// <summary><c>:scheme</c> value, or null for the session value. Ignored on HTTP/1.1.</summary>
    public string? Scheme { get; init; }

    /// <summary>
    /// RFC 8441 section 4 <c>:protocol</c> value, or null to emit no <c>:protocol</c>.
    /// Ignored on HTTP/1.1.
    /// </summary>
    public string? Protocol { get; init; }

    /// <summary>
    /// Verbatim <c>:path</c> value, or null to derive it from the URI. Honoured on HTTP/1.1 too,
    /// where it becomes the request-target — including RFC 9112 section 3.2.4's asterisk-form,
    /// which no URI can produce. CONNECT is the exception: RFC 9112 section 3.2.3 makes its
    /// target an authority, so there is no path for this to override.
    /// </summary>
    public string? PathOverride { get; init; }

    /// <summary>
    /// How the authority is conveyed, or null for the session value. Ignored on HTTP/1.1.
    /// </summary>
    public TlsHttp2AuthorityMode? AuthorityMode { get; init; }

    public bool IsIdempotent => Method is "GET" or "HEAD" or "OPTIONS" or "TRACE" or "PUT" or "DELETE";

    public bool IsStreaming => StreamingContent is not null;

    public bool IsReplayable => StreamingContent is null;

    public bool HasTrailers => Trailers.Length != 0;

    public bool HasPayload => HasContent || HasTrailers;

    public long? ContentLength => !HasContent
        ? null
        : StreamingContent is null
            ? Body.LongLength
            : StreamingContent.Headers.ContentLength;

    public BufferedRequest Redirect(Uri url, string method, bool dropBody, bool originChanged)
    {
        if (!dropBody && StreamingContent is not null)
        {
            throw new HttpRequestException(
                "A redirect requires replaying a streaming request body. Buffer the content " +
                "or disable automatic redirects for this request.");
        }
        var headers = Headers
            .Where(entry => !originChanged ||
                !string.Equals(entry.Name, "Authorization", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(entry.Name, "Cookie", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(entry.Name, "Host", StringComparison.OrdinalIgnoreCase))
            .Where(entry => !dropBody || !IsContentHeader(entry.Name))
            .Select(entry => new HeaderEntry(entry.Name, (string[])entry.Values.Clone()))
            .ToArray();

        return this with
        {
            Method = method,
            Url = url,
            Headers = headers,
            Body = dropBody ? [] : Body,
            HasContent = dropBody ? false : HasContent,
            StreamingContent = dropBody ? null : StreamingContent,
            Trailers = dropBody ? [] : Trailers,
            SuppressSensitiveSessionHeaders = SuppressSensitiveSessionHeaders || originChanged,
        };
    }

    public static async ValueTask<BufferedRequest> CreateAsync(
        HttpRequestMessage request,
        int maximumBodyBytes,
        TlsHttpVersionPolicy sessionVersionPolicy,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var requestConfiguration = TlsRequestOptions.Snapshot(request);
        var url = request.RequestUri ??
            throw new ArgumentException("The request must have a RequestUri.", nameof(request));
        if (!url.IsAbsoluteUri)
        {
            throw new ArgumentException("The request URI must be absolute.", nameof(request));
        }
        if (!string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException("TlsClient accepts only https:// request URLs.");
        }
        var versionPolicy = ResolveVersionPolicy(request, sessionVersionPolicy);

        var method = request.Method.Method;
        Http11RequestWriter.ValidateMethod(method);

        // ponytail: transitional fallback, deleted in Task 6 of the sealed-AddHeader plan.
        // Until every caller has moved to request.AddHeader, a request with an empty list still
        // reads .NET's collections.
        var legacy = requestConfiguration.Headers.Length == 0;
        var entries = new List<HeaderEntry>(requestConfiguration.Headers);
        if (legacy)
        {
            AddOrReplace(entries, request.Headers.NonValidated);
        }

        byte[] body = [];
        var hasContent = request.Content is not null;
        if (request.Content is not null)
        {
            if (legacy)
            {
                AddOrReplace(entries, request.Content.Headers.NonValidated);
            }
            body = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            if (body.Length > maximumBodyBytes)
            {
                throw new HttpRequestException(
                    $"The request body exceeds the {maximumBodyBytes}-byte session limit.");
            }
        }

        return new BufferedRequest(
            method,
            url,
            entries.ToArray(),
            body,
            hasContent,
            versionPolicy)
        {
            Trailers = requestConfiguration.Trailers,
            ReplayPolicy = requestConfiguration.ReplayPolicy,
            HasProxyOverride = requestConfiguration.HasProxyOverride,
            Proxy = requestConfiguration.Proxy,
            EnableRetries = requestConfiguration.EnableRetries,
            FramesBeforeHeaders = requestConfiguration.FramesBeforeHeaders,
            FramesAfterHeaders = requestConfiguration.FramesAfterHeaders,
            HeaderOrder = requestConfiguration.HeaderOrder,
            PseudoHeaderOrder = requestConfiguration.PseudoHeaderOrder,
            HeaderPriority = requestConfiguration.HeaderPriority,
            PriorityUpdate = requestConfiguration.PriorityUpdate,
            HeadersPadding = requestConfiguration.HeadersPadding,
            DataPadding = requestConfiguration.DataPadding,
            Scheme = requestConfiguration.Scheme,
            Protocol = requestConfiguration.Protocol,
            PathOverride = requestConfiguration.PathOverride,
            AuthorityMode = requestConfiguration.AuthorityMode,
        };
    }

    public static BufferedRequest CreateStreaming(
        HttpRequestMessage request,
        int maximumBodyBytes,
        int streamingBufferSize,
        TlsHttpVersionPolicy sessionVersionPolicy)
    {
        var requestConfiguration = TlsRequestOptions.Snapshot(request);
        var legacy = requestConfiguration.Headers.Length == 0;
        var (method, url, entries, versionPolicy) = ReadMetadata(
            request,
            sessionVersionPolicy,
            requestConfiguration.Headers);
        var hasContent = request.Content is not null;
        if (request.Content is not null)
        {
            if (legacy)
            {
                AddOrReplace(entries, request.Content.Headers.NonValidated);
            }
            if (request.Content.Headers.ContentLength is { } declaredLength &&
                declaredLength > maximumBodyBytes)
            {
                throw new HttpRequestException(
                    $"The request body exceeds the {maximumBodyBytes}-byte session limit.");
            }
        }
        return new BufferedRequest(
            method,
            url,
            entries.ToArray(),
            [],
            hasContent,
            versionPolicy,
            request.Content,
            streamingBufferSize)
        {
            Trailers = requestConfiguration.Trailers,
            ReplayPolicy = requestConfiguration.ReplayPolicy,
            HasProxyOverride = requestConfiguration.HasProxyOverride,
            Proxy = requestConfiguration.Proxy,
            EnableRetries = requestConfiguration.EnableRetries,
            FramesBeforeHeaders = requestConfiguration.FramesBeforeHeaders,
            FramesAfterHeaders = requestConfiguration.FramesAfterHeaders,
            HeaderOrder = requestConfiguration.HeaderOrder,
            PseudoHeaderOrder = requestConfiguration.PseudoHeaderOrder,
            HeaderPriority = requestConfiguration.HeaderPriority,
            PriorityUpdate = requestConfiguration.PriorityUpdate,
            HeadersPadding = requestConfiguration.HeadersPadding,
            DataPadding = requestConfiguration.DataPadding,
            Scheme = requestConfiguration.Scheme,
            Protocol = requestConfiguration.Protocol,
            PathOverride = requestConfiguration.PathOverride,
            AuthorityMode = requestConfiguration.AuthorityMode,
        };
    }

    public Task<Stream> OpenStreamingContentAsync(CancellationToken cancellationToken) =>
        StreamingContent is null
            ? throw new InvalidOperationException("The request has no streaming content.")
            : StreamingContent.ReadAsStreamAsync(cancellationToken);

    /// <summary>
    /// Validates the requested HTTP version and turns it into the transport policy for
    /// this request.
    /// </summary>
    /// <remarks>
    /// <see cref="HttpVersionPolicy.RequestVersionExact"/> pins the transport: 3.0 pins
    /// QUIC, 2.0 pins HTTP/2, anything else pins HTTP/1.1. Every other
    /// <see cref="HttpRequestMessage.VersionPolicy"/> leaves the session policy in charge.
    /// TlsClient implements no Happy Eyeballs, so it never promotes a request onto QUIC
    /// nor retries a pinned HTTP/3 request over TCP — the request fails instead.
    /// </remarks>
    private static TlsHttpVersionPolicy ResolveVersionPolicy(
        HttpRequestMessage request,
        TlsHttpVersionPolicy sessionVersionPolicy)
    {
        if (request.Version.Major is < 1 or > 3)
        {
            throw new NotSupportedException(
                "TlsClient currently supports HTTP/1.1, HTTP/2 and HTTP/3 request versions.");
        }
        if (request.VersionPolicy !=
            global::System.Net.Http.HttpVersionPolicy.RequestVersionExact)
        {
            return sessionVersionPolicy;
        }
#pragma warning disable TLSCLIENT3 // HTTP/3 is experimental; an exact 3.0 request must still pin it.
        return request.Version.Major switch
        {
            3 => TlsHttpVersionPolicy.Http3Only,
            2 => TlsHttpVersionPolicy.Http2Only,
            _ => TlsHttpVersionPolicy.Http11Only,
        };
#pragma warning restore TLSCLIENT3
    }

    private static (string Method, Uri Url, List<HeaderEntry> Entries,
        TlsHttpVersionPolicy VersionPolicy) ReadMetadata(
        HttpRequestMessage request,
        TlsHttpVersionPolicy sessionVersionPolicy,
        HeaderEntry[] configuredHeaders)
    {
        ArgumentNullException.ThrowIfNull(request);
        var url = request.RequestUri ??
            throw new ArgumentException("The request must have a RequestUri.", nameof(request));
        if (!url.IsAbsoluteUri)
        {
            throw new ArgumentException("The request URI must be absolute.", nameof(request));
        }
        if (!string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException("TlsClient accepts only https:// request URLs.");
        }
        var versionPolicy = ResolveVersionPolicy(request, sessionVersionPolicy);
        var method = request.Method.Method;
        Http11RequestWriter.ValidateMethod(method);
        // ponytail: transitional fallback, deleted in Task 6 of the sealed-AddHeader plan.
        var entries = new List<HeaderEntry>(configuredHeaders);
        if (configuredHeaders.Length == 0)
        {
            AddOrReplace(entries, request.Headers.NonValidated);
        }
        return (method, url, entries, versionPolicy);
    }

    internal static void AddOrReplace(List<HeaderEntry> destination, HeaderEntry incoming)
    {
        var index = destination.FindIndex(entry =>
            string.Equals(entry.Name, incoming.Name, StringComparison.OrdinalIgnoreCase));
        var copy = new HeaderEntry(incoming.Name, (string[])incoming.Values.Clone());
        if (index < 0)
        {
            destination.Add(copy);
        }
        else
        {
            destination[index] = copy;
        }
    }

    private static void AddOrReplace(
        List<HeaderEntry> destination,
        HttpHeadersNonValidated headers)
    {
        foreach (var header in headers)
        {
            AddOrReplace(
                destination,
                new HeaderEntry(header.Key, header.Value.ToArray()));
        }
    }

    private static bool IsContentHeader(string name) => name.StartsWith(
        "Content-",
        StringComparison.OrdinalIgnoreCase);
}
