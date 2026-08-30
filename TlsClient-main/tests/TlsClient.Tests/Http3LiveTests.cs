using System.Net;
using System.Text;

namespace TlsClient.Tests;

/// <summary>
/// The end-to-end proof HTTP/3 can have in this assembly: real requests, with and without
/// content, over a real QUIC handshake, against endpoints that report back which protocol they
/// were reached over.
/// </summary>
/// <remarks>
/// <para>Requires network access and is skipped unless <c>TLSCLIENT_LIVE_TESTS=1</c>, matching
/// <see cref="Http2LiveParityTests"/>; the offline suite stays hermetic.</para>
/// <para>TWO INDEPENDENT GATES, BECAUSE A STATUS CODE IS NOT ONE. A silent downgrade to
/// HTTP/2 would also answer 200. The negotiated ALPN read off the QUIC handshake is the first
/// gate; the endpoint naming the protocol it was reached over in its own body is the second,
/// and it is the endpoint's word rather than ours.</para>
/// <para>WHAT LIVES HERE AND WHAT DOES NOT. A request's WIRE IMAGE is pinned offline in
/// <see cref="Http3RequestContentTests"/>, which drives the same
/// <c>Http3Connection.BuildRequestAsync</c> and the same <c>TryEncode</c> the wire gets. These
/// tests exist for the half that cannot be faked: that a real HTTP/3 server accepts the
/// result, and that the refusals a peer's flow control produces are the ones a caller is
/// actually told about.</para>
/// </remarks>
public sealed class Http3LiveTests
{
    private const string Host = "fp.impersonate.pro";
    private const string Path = "/api/http3";

    /// <summary>The second host, for the requests fp.impersonate.pro will not serve: it
    /// answers no POST on any path. tls3.peet.ws does, and reports the protocol, the method and
    /// the request headers it saw.</summary>
    private const string FingerprintHost = "tls3.peet.ws";
    private const string FingerprintPath = "/api/all";

    private static bool Enabled =>
        Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_TESTS") == "1";

    private static readonly Uri Origin = new($"https://{Host}/");

    private static BufferedRequest Get(params HeaderEntry[] headers) =>
        new("GET", new Uri($"https://{Host}{Path}"), headers, [], HasContent: false);

    private static async ValueTask<IHttpConnection> ConnectAsync(
        TlsSessionConfiguration configuration) =>
        await Http3Connection.CreateAsync(
            Origin,
            proxy: null,
            configuration,
            new SharpTls.Tls13SessionCache(),
            new DnsEndpointResolver(configuration),
            new Socks5AssociationGate(),
            CancellationToken.None);

    [Fact]
    public async Task AnHttp3GetReturnsAParsedResponseOverGenuinelyNegotiatedH3()
    {
        if (!Enabled)
        {
            return;
        }

        var configuration = new TlsSessionOptions().Snapshot();
        await using var connection = await ConnectAsync(configuration);

        Assert.Equal("h3", connection.TlsInfo.ApplicationProtocol);
        Assert.NotEmpty(connection.TlsInfo.PeerCertificateChain);
        // The peer's initial_max_streams_bidi has been read by the time this returns, so the
        // connection already knows how many request streams may be opened. IT IS THE PEER'S
        // NUMBER AND NOT ONE OF OURS, which is why this is a lower bound rather than an
        // equality: a server that allowed exactly one would be within its rights and would
        // still be reported honestly. What is pinned is that nothing here caps it at 1 — real
        // HTTP/3 servers allow far more, and the whole point of the read loop is that we no
        // longer throw that away.
        Assert.True(
            connection.MaximumConcurrentRequests >= 1,
            $"the peer allowed {connection.MaximumConcurrentRequests} request streams");

        var response = await connection.SendAsync(
            Get(new HeaderEntry("User-Agent", ["TlsClient-Http3-Live"])),
            null,
            configuration,
            CancellationToken.None);

        Assert.Equal(HttpVersion.Version30, response.Version);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // RFC 9114 section 4.3.2 carries no reason phrase, so there is nothing to report.
        Assert.Equal(string.Empty, response.ReasonPhrase);
        // Pseudo-headers are not HTTP fields (section 4.3), so none may have survived into the
        // header collection. Enumerated rather than asked by name, because TlsHeaders rejects
        // a name that is not a token and would throw on the question.
        Assert.DoesNotContain(
            response.Headers.Select(header => header.Key),
            name => name.StartsWith(':'));
        Assert.True(response.Headers.Count > 0);
        Assert.NotEmpty(response.Body);
        Assert.Contains(
            "http3",
            Encoding.UTF8.GetString(response.Body),
            StringComparison.Ordinal);

        Assert.True(connection.HasCompletedRequest);
        Assert.False(connection.HasActiveRequests);
    }

    [Fact]
    public async Task ASecondRequestReusesTheSameQuicConnection()
    {
        if (!Enabled)
        {
            return;
        }

        var configuration = new TlsSessionOptions().Snapshot();
        await using var connection = await ConnectAsync(configuration);

        var first = await connection.SendAsync(
            Get(), null, configuration, CancellationToken.None);
        Assert.True(connection.IsReusable);

        var second = await connection.SendAsync(
            Get(), null, configuration, CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
    }

    /// <summary>
    /// A POST that carries content, answered 200 by a real HTTP/3 server that names the
    /// protocol it was reached over and repeats the request line it read.
    /// </summary>
    /// <remarks>
    /// <para>A SECOND HOST, BECAUSE fp.impersonate.pro SERVES NO POST AT ALL — every path of it
    /// was tried and every one refused the method, so it can witness that a request with
    /// content completes but never that a server accepted one. tls3.peet.ws answers 200 to a
    /// POST and reports <c>"http_version"</c>, <c>"method"</c> and the request headers it
    /// received, all in its own words.</para>
    /// <para>WHAT THIS CANNOT WITNESS, STATED RATHER THAN IMPLIED: no HTTP/3 endpoint this
    /// client's ClientHello can reach echoes a request body back — the ones that do are behind
    /// CDNs that answer the narrow QUIC ClientHello with <c>illegal_parameter</c>. So the DATA
    /// frame's octets are pinned OFFLINE instead, in
    /// <see cref="Http3RequestContentTests"/>, by encoding the same request through the same
    /// <c>TryEncode</c> the wire gets and reading the frames back. This test's job is the half
    /// that cannot be faked offline: that a real server accepts the result.</para>
    /// </remarks>
    [Fact]
    public async Task AnHttp3PostWithContentIsAcceptedByARealHttp3Server()
    {
        if (!Enabled)
        {
            return;
        }

        var payload = Encoding.UTF8.GetBytes(
            "peaktls-h3-body-witness:" + Guid.NewGuid().ToString("n") + ":end");
        var configuration = new TlsSessionOptions().Snapshot();
        await using var connection = await Http3Connection.CreateAsync(
            new Uri($"https://{FingerprintHost}/"),
            proxy: null,
            configuration,
            new SharpTls.Tls13SessionCache(),
            new DnsEndpointResolver(configuration),
            new Socks5AssociationGate(),
            CancellationToken.None);

        Assert.Equal("h3", connection.TlsInfo.ApplicationProtocol);

        var response = await connection.SendAsync(
            new BufferedRequest(
                "POST",
                new Uri($"https://{FingerprintHost}{FingerprintPath}"),
                [new HeaderEntry("Content-Type", ["text/plain"])],
                payload,
                HasContent: true),
            null,
            configuration,
            CancellationToken.None);

        var seen = Encoding.UTF8.GetString(response.Body);
        Assert.Equal(HttpVersion.Version30, response.Version);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // The server's own three words: the protocol, the method, and the content-length it
        // read out of our HEADERS frame. A payload of a fresh length every run, so a hard-coded
        // or stale number cannot satisfy the last of them.
        Assert.Contains("\"http_version\": \"h3\"", seen, StringComparison.Ordinal);
        Assert.Contains("\"method\": \"POST\"", seen, StringComparison.Ordinal);
        Assert.Contains(
            $"content-length: {payload.Length}", seen, StringComparison.Ordinal);
        Assert.True(connection.IsReusable);
    }

    /// <summary>
    /// The project's own endpoint, asked whether a request CARRYING CONTENT still completes
    /// over HTTP/3 rather than failing. It serves no POST on any path, so the status is a
    /// refusal — and a status at all is the point: the request stream was written, read and
    /// answered.
    /// </summary>
    [Fact]
    public async Task AnHttp3PostCompletesAgainstTheProjectsOwnEndpoint()
    {
        if (!Enabled)
        {
            return;
        }

        var configuration = new TlsSessionOptions().Snapshot();
        await using var connection = await ConnectAsync(configuration);

        var response = await connection.SendAsync(
            new BufferedRequest(
                "POST",
                new Uri($"https://{Host}{Path}"),
                [],
                Encoding.UTF8.GetBytes("peaktls-h3-post"),
                HasContent: true),
            null,
            configuration,
            CancellationToken.None);

        Assert.Equal(HttpVersion.Version30, response.Version);
        // The exact code is the host's business — it has answered both 404 and 405 to this —
        // but it must be a served response and not a transport failure.
        Assert.InRange((int)response.StatusCode, 400, 499);
        Assert.True(connection.HasCompletedRequest);
    }

    /// <summary>
    /// A content-length that disagrees with the octets actually sent. This is the ONE shape
    /// that reaches it through TlsClient's own mapping: MergeHeaders derives the field from
    /// <c>BufferedRequest.ContentLength</c>, which for a streaming request is whatever the
    /// content DECLARED, while the DATA frame carries whatever the stream actually yielded.
    /// </summary>
    [Fact]
    public async Task AnHttp3RequestWhoseContentLengthLiesIsRefusedBeforeTheWire()
    {
        if (!Enabled)
        {
            return;
        }

        var configuration = new TlsSessionOptions().Snapshot();
        await using var connection = await ConnectAsync(configuration);

        // Declares 500 octets and yields 4.
        var content = new StreamContent(new MemoryStream("four"u8.ToArray()));
        content.Headers.ContentLength = 500;
        var request = new BufferedRequest(
            "POST",
            new Uri($"https://{Host}{Path}"),
            [],
            [],
            HasContent: true,
            // The policy selected this connection long before SendAsync; it is unread here.
            TlsHttpVersionPolicy.PreferHttp2,
            content);

        var exception = await Assert.ThrowsAsync<TlsHttpProtocolException>(async () =>
            await connection.SendAsync(
                request, null, configuration, CancellationToken.None));

        Assert.Contains("content-length", exception.Message, StringComparison.Ordinal);
        Assert.Contains("4.1.2", exception.Message, StringComparison.Ordinal);
        // Refused before a stream ordinal was spent, so the connection is still good.
        Assert.True(exception.IsStreamScoped);
        Assert.True(connection.IsReusable);
    }

    /// <summary>
    /// A body larger than the peer's initial per-stream credit. SharpTls processes no
    /// MAX_STREAM_DATA, so that credit is the whole allowance and the request is refused BY
    /// NAME rather than queued against credit that cannot arrive.
    /// </summary>
    [Fact]
    public async Task AnHttp3BodyPastThePeersStreamCreditIsRefusedByName()
    {
        if (!Enabled)
        {
            return;
        }

        var configuration = new TlsSessionOptions().Snapshot();
        await using var connection = await ConnectAsync(configuration);

        var request = new BufferedRequest(
            "POST",
            new Uri($"https://{Host}{Path}"),
            [],
            new byte[32 * 1024 * 1024],
            HasContent: true);

        var exception = await Assert.ThrowsAsync<TlsHttpProtocolException>(async () =>
            await connection.SendAsync(
                request, null, configuration, CancellationToken.None));

        Assert.Contains(
            "initial_max_stream_data_bidi_remote",
            exception.Message,
            StringComparison.Ordinal);
        Assert.Contains("MAX_STREAM_DATA", exception.Message, StringComparison.Ordinal);
        // Terminal, not "take another connection": every connection to this peer would refuse
        // the same body for the same reason.
        Assert.IsNotType<StaleHttpConnectionException>(exception);
        Assert.True(connection.IsReusable);
    }

    /// <summary>
    /// Trailers, which TlsClient expresses through <c>TlsRequestOptions.Trailers</c> and this
    /// path turns into RFC 9114 section 4.1's second HEADERS frame.
    /// </summary>
    /// <remarks>WHAT THE SERVER CAN AND CANNOT WITNESS. tls3.peet.ws reports the HEADER
    /// section it received and never the trailer section, so the 200 is an indirect witness —
    /// a trailing field section it could not decode would be a stream error rather than a
    /// response — and the announce field is a direct one. That the second HEADERS frame is
    /// emitted at all, and AFTER the DATA frame, is pinned offline instead by
    /// <c>Http3RequestContentTests.TrailersFollowTheBodyAsASecondHeadersFrame</c>.</remarks>
    [Fact]
    public async Task AnHttp3PostWithTrailersIsAcceptedByTheServer()
    {
        if (!Enabled)
        {
            return;
        }

        var payload = Encoding.UTF8.GetBytes(
            "peaktls-h3-trailers-" + Guid.NewGuid().ToString("n"));
        var configuration = new TlsSessionOptions().Snapshot();
        await using var connection = await Http3Connection.CreateAsync(
            new Uri($"https://{FingerprintHost}/"),
            proxy: null,
            configuration,
            new SharpTls.Tls13SessionCache(),
            new DnsEndpointResolver(configuration),
            new Socks5AssociationGate(),
            CancellationToken.None);

        var response = await connection.SendAsync(
            new BufferedRequest(
                "POST",
                new Uri($"https://{FingerprintHost}{FingerprintPath}"),
                [
                    new HeaderEntry("Content-Type", ["text/plain"]),
                    // Trailers force chunked framing, so the slot names Transfer-Encoding —
                    // dropped over HTTP/3 by RFC 9114 section 4.2. The Trailer field is added
                    // too, because nothing generates one from the trailer list.
                    new HeaderEntry("Transfer-Encoding", ["chunked"]),
                    new HeaderEntry("Trailer", ["Checksum"]),
                ],
                payload,
                HasContent: true)
            {
                Trailers = [new HeaderEntry("Checksum", ["abc123"])],
            },
            null,
            configuration,
            CancellationToken.None);

        var seen = Encoding.UTF8.GetString(response.Body);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"http_version\": \"h3\"", seen, StringComparison.Ordinal);
        Assert.Contains("\"method\": \"POST\"", seen, StringComparison.Ordinal);
        // RFC 9110 section 6.6.2's announce, which the session emits by default.
        Assert.Contains("trailer: Checksum", seen, StringComparison.Ordinal);
        // Trailers make MergeHeaders reach for Transfer-Encoding rather than Content-Length,
        // and section 4.2 forbids that over HTTP/3, so the field section carries neither —
        // which is what the server reports having seen.
        Assert.DoesNotContain("transfer-encoding", seen, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AStreamedHttp3ResponseReachesTheDestinationStream()
    {
        if (!Enabled)
        {
            return;
        }

        var configuration = new TlsSessionOptions().Snapshot();
        await using var connection = await ConnectAsync(configuration);

        await using var destination = new MemoryStream();
        using var streaming = new StreamingResponseContext(
            destination,
            new TlsStreamingConfiguration(4096, false),
            configuration.MaximumResponseBodyBytes);

        var response = await connection.SendAsync(
            Get(),
            streaming,
            configuration,
            CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // A streamed response hands the caller no buffered body; the octets went to the
        // destination instead.
        Assert.Empty(response.Body);
        Assert.Contains(
            "http3",
            Encoding.UTF8.GetString(destination.ToArray()),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConcurrentGetsShareOneConnectionRatherThanQueueingOnIt()
    {
        if (!Enabled)
        {
            return;
        }

        var configuration = new TlsSessionOptions().Snapshot();
        await using var connection = await ConnectAsync(configuration);

        // A real HTTP/3 server allows far more than one request stream, and before the read
        // loop existed this number was capped at 1 whatever the server said.
        Assert.True(
            connection.MaximumConcurrentRequests > 1,
            $"the peer allowed only {connection.MaximumConcurrentRequests} request streams, " +
            "so this test cannot tell multiplexing from serialisation");

        async Task<ParsedHttpResponse> OneAsync() => await connection.SendAsync(
            Get(new HeaderEntry("User-Agent", ["TlsClient-Http3-Live"])),
            null,
            configuration,
            CancellationToken.None);

        // One request first, to measure what a single round trip to THIS server costs today.
        // A fixed threshold would be a guess about someone else's network; a multiple of a
        // measurement taken seconds earlier is not.
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var warm = await OneAsync();
        var single = clock.Elapsed;
        Assert.Equal(HttpStatusCode.OK, warm.StatusCode);

        const int Count = 8;
        clock.Restart();
        var responses = await Task.WhenAll(
            Enumerable.Range(0, Count).Select(_ => OneAsync()));
        var together = clock.Elapsed;

        foreach (var response in responses)
        {
            Assert.Equal(HttpVersion.Version30, response.Version);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains(
                "http3",
                Encoding.UTF8.GetString(response.Body),
                StringComparison.Ordinal);
        }

        // THE WITNESS, AND IT IS THE TIMING RATHER THAN THE COUNT. Eight responses arriving is
        // exactly what serialisation produces too; eight responses arriving in less time than
        // four of them could take one after another is not. The bound is deliberately loose —
        // half the serialised cost rather than an eighth — so that a slow or jittery network
        // cannot fail it, while a connection that had gone back to one request at a time would
        // need each request to run four times faster than the one measured moments before.
        Assert.True(
            together < single * (Count / 2.0),
            $"{Count} concurrent HTTP/3 requests took {together.TotalMilliseconds:F0} ms " +
            $"against {single.TotalMilliseconds:F0} ms for one, which is the profile of a " +
            "connection that serialised them");
    }
}
