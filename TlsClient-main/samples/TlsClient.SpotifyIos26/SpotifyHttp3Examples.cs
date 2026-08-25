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

        // The order you add them in is the order that ships. Nothing re-sorts it, and nothing
        // is added on your behalf — this preset is Http3Only, so the authority travels as
        // :authority and no host field is needed. On HTTP/1.1 or HTTP/2, add "host" yourself
        // at the position you want it: RFC 9112 section 3.2 makes an absent one malformed.
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.AddHeader("accept", "*/*");
        request.AddHeader("x-client-id", clientId);
        request.AddHeader("accept-encoding", "gzip, deflate, br");
        request.AddHeader("priority", "u=3, i");
        request.AddHeader("app-platform", "iOS");
        request.AddHeader("user-agent", UserAgent);
        request.AddHeader("authorization", "Bearer " + bearerToken);
        request.AddHeader("accept-language", "en-US,en;q=0.9");
        request.AddHeader("spotify-app-version", "9.1.76.2050");

        return session.SendAsync(request, cancellationToken);
    }

    /// <summary>A POST with a protobuf body, in the captured login-leg image.</summary>
    /// <remarks>
    /// The content fields are added like any other, and land where they were added:
    /// <c>content-type</c> FIRST and <c>content-length</c> seventh of ten, between
    /// <c>cache-control</c> and <c>user-agent</c>. The <c>content-length</c> VALUE is a
    /// placeholder — the real one is recomputed from the body — so only its position here
    /// matters. A body with no <c>content-length</c> or <c>transfer-encoding</c> added throws.
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

        request.AddHeader("content-type", "application/x-protobuf");
        request.AddHeader("accept", "*/*");
        request.AddHeader("priority", "u=3, i");
        request.AddHeader("accept-encoding", "gzip, deflate, br");
        request.AddHeader("x-retry-count", "0");
        request.AddHeader("cache-control", "no-cache, no-store, max-age=0");
        request.AddHeader("content-length", "-1");
        request.AddHeader("user-agent", UserAgent);
        request.AddHeader("accept-language", "en-US,en;q=0.9");
        request.AddHeader("client-token", clientToken);

        return session.SendAsync(request, cancellationToken);
    }

    /// <summary>A PUT with a JSON body, with the content fields at either end.</summary>
    /// <remarks>
    /// <c>content-type</c> leads and <c>content-length</c> trails, both by insertion. Note that
    /// the <c>StringContent</c> constructor's own <c>application/json; charset=utf-8</c> never
    /// reaches the wire: <c>Content.Headers</c> is not read, so the exact bytes added here are
    /// what ship.
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

        request.AddHeader("content-type", "application/json");
        request.AddHeader("accept", "*/*");
        request.AddHeader("priority", "u=3, i");
        request.AddHeader("user-agent", UserAgent);
        request.AddHeader("authorization", "Bearer " + bearerToken);
        request.AddHeader("accept-language", "en-US,en;q=0.9");
        request.AddHeader("content-length", "-1");

        return session.SendAsync(request, cancellationToken);
    }
}

#pragma warning restore TLSCLIENT3
