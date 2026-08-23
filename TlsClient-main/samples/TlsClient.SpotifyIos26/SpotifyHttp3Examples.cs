// HTTP/3-only requests through a SOCKS5 proxy, carrying the captured Spotify iOS fingerprint.
//
// Everything here is deliberate. The library sets no headers on your behalf and generates no
// ClientHello of its own: what you add to the request is exactly what reaches the wire.
//
//   await using var session = SpotifyHttp3Examples.CreateSession(
//       "socks5://proxy.example.net:1080", "user", "pass");
//   var response = await SpotifyHttp3Examples.GetProfileAsync(session, url, token, clientId);
//
// HEADER ORDER, in one paragraph. TlsPresets.Spotify declares NO header order, so fields reach
// the wire in the order you add them. That is enough for a GET. It is NOT enough for a request
// with a body: HttpRequestHeaders silently refuses content-type and content-length, so their
// real values arrive later from request.Content.Headers and land at the END of the block - where
// no captured client puts them. A request with a body therefore states its order explicitly.
// All of this is pinned by InsertionOrderHeaderTests.

#pragma warning disable TLSCLIENT3 // Http3Only is [Experimental]; these samples opt in on purpose.

using System.Net.Http.Headers;
using System.Text;

namespace TlsClient.Samples;

/// <summary>Worked GET / POST / PUT over HTTP/3 with a session-wide SOCKS5 proxy.</summary>
public static class SpotifyHttp3Examples
{
    private const string UserAgent = "Spotify/9.1.76 iOS/27.0 (iPhone17,2)";

    /// <summary>
    /// The captured header order of a Spotify iOS HTTP/3 GET to <c>spclient</c>, confirmed from
    /// two independent capture paths. You do not need to set this - adding the fields in this
    /// order achieves the same thing - and it is here so the target image is visible.
    /// </summary>
    private static readonly string[] SpclientGetOrder =
    [
        "accept",
        "x-client-id",
        "accept-encoding",
        "priority",
        "app-platform",
        "user-agent",
        "authorization",
        "accept-language",
        "spotify-app-version",
    ];

    /// <summary>
    /// The captured order of the <c>login5.spotify.com</c> <c>/v4/login</c> POST. Note where the
    /// content fields sit: <c>content-type</c> FIRST and <c>content-length</c> seventh of ten,
    /// between <c>cache-control</c> and <c>user-agent</c>. Neither position is reachable by
    /// insertion order, which is the whole reason a body request names its order.
    /// </summary>
    private static readonly string[] Login5PostOrder =
    [
        "content-type",
        "accept",
        "priority",
        "accept-encoding",
        "x-retry-count",
        "cache-control",
        "content-length",
        "user-agent",
        "accept-language",
        "client-token",
    ];

    /// <summary>
    /// One session, one proxy, for the whole of its life. <c>options.Proxy</c> is set once and
    /// every request the session makes goes through it - there is no per-session "enable proxy"
    /// call and no way to lose it midway.
    /// </summary>
    /// <remarks>
    /// It MUST be SOCKS5. QUIC is UDP, and RFC 1928 section 7 UDP ASSOCIATE is the only one of
    /// the proxy types that relays datagrams; an HTTP proxy throws <c>NotSupportedException</c>
    /// before any dial rather than silently falling back to TCP. Credentials travel as RFC 1929
    /// username/password.
    /// <para>The destination goes to the relay as a DOMAINNAME (ATYP 0x03), so the name resolves
    /// at the egress rather than here. Some relays reject raw-IP destinations outright, which is
    /// why this is not optional. The SOCKS5 per-datagram header also shrinks the QUIC payload
    /// ceiling; handled, but it leaves less room on a marginal path.</para>
    /// </remarks>
    public static TlsSession CreateSession(string proxyAddress, string username, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(proxyAddress);

        // TlsPresets.Spotify pins HttpVersionPolicy = Http3Only and carries the measured QUIC
        // and TLS shape. ONE preset covers every endpoint: across 41 QUIC captures spanning
        // seven hostnames, every cipher, extension, group, signature algorithm and transport
        // parameter was identical. Only the rotation offset and the GREASE values differ, and
        // both are redrawn per connection because the handset redraws them too.
        var options = TlsPresets.Spotify.CreateOptions();
        options.Proxy = TlsProxy.Socks5(proxyAddress, username, password);
        options.Timeout = TimeSpan.FromSeconds(30);

        return new TlsSession(options);
    }

    /// <summary>A GET. Insertion order is the wire order; nothing else is needed.</summary>
    public static Task<TlsResponse> GetProfileAsync(
        TlsSession session,
        string url,
        string bearerToken,
        string clientId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        // Added in SpclientGetOrder, so no HeaderOrder is set. Add them in a different order and
        // that different order is what ships - the library does not second-guess you.
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        request.Headers.TryAddWithoutValidation("x-client-id", clientId);
        request.Headers.TryAddWithoutValidation("accept-encoding", "gzip, deflate, br");
        request.Headers.TryAddWithoutValidation("priority", "u=3, i");
        request.Headers.TryAddWithoutValidation("app-platform", "iOS");
        request.Headers.TryAddWithoutValidation("user-agent", UserAgent);
        request.Headers.TryAddWithoutValidation("authorization", "Bearer " + bearerToken);
        request.Headers.TryAddWithoutValidation("accept-language", "en-US,en;q=0.9");
        request.Headers.TryAddWithoutValidation("spotify-app-version", "9.1.76.2050");

        return session.SendAsync(request, cancellationToken);
    }

    /// <summary>
    /// The same GET, ordered from the request itself. Use this when you are handed headers you
    /// did not add in order: it restates the order you built rather than a hard-coded array.
    /// </summary>
    /// <remarks>
    /// Over HTTP/3 this is equivalent to setting nothing. Over HTTP/1.1 or HTTP/2 it is NOT.
    /// <c>Host</c> is generated rather than added, so it is absent from <c>request.Headers</c>,
    /// and <c>Order</c> appends whatever the array does not name - which moves Host from first
    /// to last. It is harmless here only because HTTP/3 drops Host and emits <c>:authority</c>
    /// instead, and this preset is Http3Only. On any other transport, append <c>"host"</c>
    /// yourself at the position you want it.
    /// </remarks>
    public static Task<TlsResponse> GetOrderedFromRequestAsync(
        TlsSession session,
        string url,
        string bearerToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        request.Headers.TryAddWithoutValidation("user-agent", UserAgent);
        request.Headers.TryAddWithoutValidation("authorization", "Bearer " + bearerToken);

        TlsRequestOptions.For(request).HeaderOrder =
            request.Headers.Select(header => header.Key).ToArray();

        return session.SendAsync(request, cancellationToken);
    }

    /// <summary>A POST with a protobuf body, in the captured login-leg image.</summary>
    /// <remarks>
    /// The order is stated because it HAS to be. <c>content-type</c> is set on
    /// <c>request.Content.Headers</c>, the only collection that accepts it, and content headers
    /// are appended after the request headers - so insertion order can never put it first.
    /// <c>content-length</c> never appears in the code at all: it is recomputed from the body,
    /// and naming it in the order is what decides where the generated field lands.
    /// </remarks>
    public static Task<TlsResponse> PostLoginAsync(
        TlsSession session,
        string url,
        ReadOnlyMemory<byte> protobufBody,
        string clientToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new ReadOnlyMemoryContent(protobufBody),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-protobuf");

        request.Headers.TryAddWithoutValidation("accept", "*/*");
        request.Headers.TryAddWithoutValidation("priority", "u=3, i");
        request.Headers.TryAddWithoutValidation("accept-encoding", "gzip, deflate, br");
        request.Headers.TryAddWithoutValidation("x-retry-count", "0");
        request.Headers.TryAddWithoutValidation("cache-control", "no-cache, no-store, max-age=0");
        request.Headers.TryAddWithoutValidation("user-agent", UserAgent);
        request.Headers.TryAddWithoutValidation("accept-language", "en-US,en;q=0.9");
        request.Headers.TryAddWithoutValidation("client-token", clientToken);

        TlsRequestOptions.For(request).HeaderOrder = Login5PostOrder;

        return session.SendAsync(request, cancellationToken);
    }

    /// <summary>A PUT with a JSON body, ordered from the request plus the content fields.</summary>
    /// <remarks>
    /// The derive-from-request idiom, corrected for a body: <c>request.Headers</c> cannot report
    /// the content fields, so they are spliced in at the positions you want. Here
    /// <c>content-type</c> leads and <c>content-length</c> trails.
    /// <para>PUT is idempotent, so it is eligible for the retry policy where POST is not.
    /// <c>TlsRequestOptions.EnableRetries</c> forces either answer per request.</para>
    /// </remarks>
    public static Task<TlsResponse> PutSettingsAsync(
        TlsSession session,
        string url,
        string json,
        string bearerToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        var request = new HttpRequestMessage(HttpMethod.Put, url)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };

        request.Headers.TryAddWithoutValidation("accept", "*/*");
        request.Headers.TryAddWithoutValidation("priority", "u=3, i");
        request.Headers.TryAddWithoutValidation("user-agent", UserAgent);
        request.Headers.TryAddWithoutValidation("authorization", "Bearer " + bearerToken);
        request.Headers.TryAddWithoutValidation("accept-language", "en-US,en;q=0.9");

        TlsRequestOptions.For(request).HeaderOrder =
        [
            "content-type",
            .. request.Headers.Select(header => header.Key),
            "content-length",
        ];

        return session.SendAsync(request, cancellationToken);
    }
}

#pragma warning restore TLSCLIENT3
