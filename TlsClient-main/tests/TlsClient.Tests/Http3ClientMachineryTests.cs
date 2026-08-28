using System.Collections.Concurrent;
using System.Net;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>
/// Whether an HTTP/3 connection PARTICIPATES in the client machinery that sits above it —
/// pooling, redirects, cookies and retries — rather than merely working on its own.
/// </summary>
/// <remarks>
/// <para>THE GAP THIS FILE CLOSES IS THAT EVERY EXISTING HTTP/3 TEST BYPASSES
/// <see cref="TlsSession"/>. <see cref="Http3LiveTests"/> calls
/// <c>Http3Connection.CreateAsync</c> and then <c>connection.SendAsync</c> directly, and
/// <see cref="Http3StreamMultiplexerTests"/> drives the read loop with a fake wire; neither ever
/// goes through the pool, so nothing witnessed that a second HTTP/3 request reuses the first
/// one's QUIC handshake, that a redirect stays on HTTP/3, that a Set-Cookie comes back on the
/// next request, or that a dead QUIC connection is tried again. <c>docs/HTTP3-EVALUATION.md</c>
/// condition 5 and <see cref="Http3EvaluationTests"/>'s own remarks both said as much: those
/// features "inherit the HTTP/2 code paths untested".</para>
/// <para>THE CONNECTION IS A FAKE AND THE MACHINERY IS REAL, which is the only division
/// available. QUIC has no loopback server — SharpTls ships a client and no server — so the
/// alternative to <see cref="HttpConnectAsync"/> is a live third-party origin, and a claim about
/// pooling that only a live origin can check is a claim nothing checks. Everything above
/// <see cref="IHttpConnection"/> here is production code: the real <see cref="TlsConnectionPool"/>
/// makes every reuse, eviction and lifetime decision, and the real <see cref="TlsSession"/> makes
/// every redirect, cookie and retry decision. <see cref="FakeHttp3Connection"/> reports the state
/// <c>Http3Connection</c> reports, mirrored member for member, and throws the exceptions
/// <c>Http3Connection.Describe</c> itself produces.</para>
/// <para>NO TEST HERE ASSERTS THAT A REQUEST COMPLETED, because a client that reconnected for
/// every request satisfies that too. Each one asserts a number the alternative could not
/// produce: how many QUIC handshakes were paid for, which version policy each of them was
/// dialled with, whether the connection that answered the second request was the same object,
/// or a concurrency a serialising pool would have to deadlock to reach. Every wait is bounded
/// by <see cref="Bound"/> and an expired bound is the failure, so a pool that deadlocked fails
/// the run rather than hanging it.</para>
/// </remarks>
public sealed class Http3ClientMachineryTests
{
    /// <summary>Every wait in this file. Long enough not to trip on a loaded CI machine, short
    /// enough that a genuine deadlock fails the run rather than hanging it.</summary>
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);

    private static readonly Uri First = new("https://first.example/start");
    private static readonly Uri Second = new("https://second.example/landing");

    // ------------------------------------------------------------------------------
    // Pooling.
    // ------------------------------------------------------------------------------

    /// <summary>
    /// The claim that matters most for HTTP/3, because the thing being saved is a whole QUIC
    /// handshake: two requests to one origin pay for one connection.
    /// </summary>
    [Fact]
    public async Task ASecondHttp3RequestReusesThePooledQuicConnection()
    {
        await using var fabric = new Http3Fabric();
        await using var session = Session(fabric);

        var first = await session.GetAsync(First).WaitAsync(Bound);
        var second = await session.GetAsync(First).WaitAsync(Bound);

        // One handshake, not two. A pool that did not reuse would still return two 200s.
        Assert.Single(fabric.Dials);
        // And the SAME object answered both, which "one dial" alone would not prove if the
        // pool had opened and immediately retired a connection between them.
        Assert.Equal(0, fabric.Exchanges[0].ConnectionOrdinal);
        Assert.Equal(0, fabric.Exchanges[1].ConnectionOrdinal);
        Assert.Equal(HttpVersion.Version30, first.HttpVersion);
        Assert.Equal(HttpVersion.Version30, second.HttpVersion);
        Assert.Equal("h3", second.Tls.ApplicationProtocol);
    }

    /// <summary>
    /// Four requests genuinely overlapping on one pooled connection, which is what
    /// <c>2ece2ae</c>'s background read loop bought and what
    /// <see cref="IHttpConnection.MaximumConcurrentRequests"/> is read for.
    /// </summary>
    /// <remarks>THE BARRIER IS THE ASSERTION AND THE BOUND IS THE FAILURE. No response is
    /// produced until all four requests are inside the connection at once, so a pool that
    /// leased them one at a time — because it had read <c>MaximumConcurrentRequests</c> as 1,
    /// or had opened four connections and spread them out — cannot reach the fourth and the
    /// bound expires. Four completions on their own prove nothing.</remarks>
    [Fact]
    public async Task ConcurrentHttp3RequestsOverlapOnOnePooledConnection()
    {
        const int Together = 4;
        using var arrived = new SemaphoreSlim(0, Together);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        // The default hundred-stream allowance, because the pool's ceiling is HALF the
        // remaining allowance rather than all of it — see
        // AnHttp3ConnectionsInFlightCeilingIsHalfItsRemainingAllowance — and an allowance of
        // four would therefore open a second connection rather than overlap four requests.
        await using var fabric = new Http3Fabric
        {
            Respond = async exchange =>
            {
                arrived.Release();
                await release.Task.ConfigureAwait(false);
                return Ok(exchange);
            },
        };
        await using var session = Session(fabric);

        // ISSUED ONE AT A TIME, EACH ONLY ONCE THE ONE BEFORE IT IS PARKED INSIDE THE
        // CONNECTION. That is stronger than firing four at once and stronger than counting
        // completions: request n+1 is not even started until request n is provably still in
        // flight, so every admission the pool makes is an admission on top of a live one. It
        // also removes the race that firing them together would leave, since the pool's
        // decision reads a counter the parked requests have already moved.
        var requests = new Task<TlsResponse>[Together];
        for (var index = 0; index < Together; index++)
        {
            requests[index] = session.GetAsync(First);
            Assert.True(
                await arrived.WaitAsync(Bound),
                $"HTTP/3 request {index + 1} of {Together} never reached the connection while " +
                "the ones before it were still in flight, which is the profile of a pool that " +
                "serialised them");
        }
        release.SetResult();
        var responses = await Task.WhenAll(requests).WaitAsync(Bound);

        Assert.Single(fabric.Dials);
        Assert.All(responses, response =>
            Assert.Equal(HttpVersion.Version30, response.HttpVersion));
        Assert.All(fabric.Exchanges, exchange => Assert.Equal(0, exchange.ConnectionOrdinal));
    }

    /// <summary>
    /// A pooled HTTP/3 connection carries at most HALF its remaining stream allowance at once,
    /// which is a wart this test pins rather than a design.
    /// </summary>
    /// <remarks>
    /// <para>THE TWO NUMBERS ARE IN DIFFERENT UNITS AND THE POOL COMPARES THEM ANYWAY.
    /// <c>TlsConnectionPool.CanAcceptRequest</c> asks <c>entry.Leases &lt;
    /// entry.Connection.MaximumConcurrentRequests</c>, which is exactly right for the other two
    /// transports — <c>Http11Connection</c> answers a constant 1 and <c>Http2Connection</c>
    /// answers the peer's fixed SETTINGS_MAX_CONCURRENT_STREAMS. <c>Http3Connection</c> answers
    /// the peer's REMAINING <c>initial_max_streams_bidi</c>, a lifetime allowance that the
    /// requests already in flight have themselves drawn down, so those requests are counted on
    /// both sides of the comparison and the ceiling settles at k &lt; A - k, or roughly half of
    /// A.</para>
    /// <para>WHAT A CALLER SEES IS A COST AND NOT A FAILURE: the pool opens another QUIC
    /// connection, up to <c>MaximumConnectionsPerOrigin</c>, so the request is served and the
    /// price is a handshake that a fuller connection would not have needed. Against a real
    /// server, whose allowance is typically a hundred or more, the ceiling is far above any
    /// concurrency a client reaches and never binds. Left alone because closing it means
    /// changing what <see cref="IHttpConnection.MaximumConcurrentRequests"/> MEANS, which is a
    /// contract all three transports implement.</para>
    /// </remarks>
    [Fact]
    public async Task AnHttp3ConnectionsInFlightCeilingIsHalfItsRemainingAllowance()
    {
        using var arrived = new SemaphoreSlim(0, 3);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var fabric = new Http3Fabric(streamAllowance: 4)
        {
            Respond = async exchange =>
            {
                arrived.Release();
                await release.Task.ConfigureAwait(false);
                return Ok(exchange);
            },
        };
        await using var session = Session(fabric);

        // One at a time, so the pool's arithmetic is read at a known point rather than raced:
        // request n is inside the connection, and has drawn the allowance down, before request
        // n+1 asks the pool for anything.
        var requests = new Task<TlsResponse>[3];
        for (var index = 0; index < 3; index++)
        {
            requests[index] = session.GetAsync(First);
            Assert.True(
                await arrived.WaitAsync(Bound),
                $"request {index + 1} of 3 never reached a connection");
        }
        release.SetResult();
        await Task.WhenAll(requests).WaitAsync(Bound);

        // An allowance of four admitted two, and the third bought a second handshake.
        Assert.Equal(2, fabric.Dials.Count);
        Assert.Equal([0, 0, 1], fabric.Exchanges.Select(exchange => exchange.ConnectionOrdinal));
    }

    /// <summary>
    /// The peer's <c>initial_max_streams_bidi</c> is a LIFETIME allowance rather than a
    /// concurrency limit — nothing in SharpTls processes MAX_STREAMS — so spending it retires
    /// the connection, and the pool must open another rather than fail the request.
    /// </summary>
    [Fact]
    public async Task AnExhaustedStreamAllowanceRetiresTheConnectionInsteadOfFailingTheRequest()
    {
        await using var fabric = new Http3Fabric(streamAllowance: 2);
        await using var session = Session(fabric);

        await session.GetAsync(First).WaitAsync(Bound);
        await session.GetAsync(First).WaitAsync(Bound);
        var third = await session.GetAsync(First).WaitAsync(Bound);

        Assert.Equal(2, fabric.Dials.Count);
        Assert.Equal([0, 0, 1], fabric.Exchanges.Select(exchange => exchange.ConnectionOrdinal));
        // Retired means disposed, not merely skipped: a QUIC connection left open would keep a
        // UDP socket and a read loop alive for nothing.
        Assert.True(fabric.Connections[0].IsDisposed);
        Assert.False(fabric.Connections[1].IsDisposed);
        Assert.Equal(HttpVersion.Version30, third.HttpVersion);
    }

    /// <summary>
    /// An HTTP/3 connection is never handed to an HTTP/2 request, nor the reverse — the pool
    /// key carries the version policy, so the two never meet.
    /// </summary>
    /// <remarks>This is the pooling half of the no-silent-downgrade rule. A pool keyed on host
    /// and port alone would answer an <c>Http3Only</c> request with whatever TCP connection to
    /// that origin happened to be idle.</remarks>
    [Fact]
    public async Task AnHttp3RequestIsNeverAnsweredByAPooledTcpConnection()
    {
        await using var fabric = new Http3Fabric();
        await using var session = Session(fabric, options =>
            options.HttpVersionPolicy = TlsHttpVersionPolicy.Http2Only);

        var overHttp2 = await session.GetAsync(First).WaitAsync(Bound);
        using var pinned = new HttpRequestMessage(HttpMethod.Get, First)
        {
            Version = HttpVersion.Version30,
            VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionExact,
        };
        var overHttp3 = await session.SendAsync(pinned).WaitAsync(Bound);

        Assert.Equal(HttpVersion.Version20, overHttp2.HttpVersion);
        Assert.Equal(HttpVersion.Version30, overHttp3.HttpVersion);
        // Two dials to ONE origin, because the version policy is part of the pool key.
        Assert.Equal(
            [TlsHttpVersionPolicy.Http2Only, Http3Only],
            fabric.Dials.Select(dial => dial.VersionPolicy));
        Assert.All(fabric.Dials, dial => Assert.Equal(First.IdnHost, dial.Origin.IdnHost));
    }

    /// <summary>
    /// A pooled HTTP/3 connection cannot outlive its QUIC deadline, and the mechanism that
    /// enforces that is <see cref="IHttpConnection.IsReusable"/> rather than the pool's own
    /// lifetime arithmetic.
    /// </summary>
    /// <remarks>
    /// <para>THE TWO CLOCKS DO NOT START TOGETHER, WHICH IS WHY THIS TEST EXISTS.
    /// <c>Http3Connection.CreateAsync</c> sets <c>TlsQuicConnectionOptions.HandshakeDeadline</c>
    /// from <see cref="TlsSessionOptions.PooledConnectionLifetime"/> and that deadline bounds
    /// every later receive, so it starts when the handshake starts. The pool's own expiry runs
    /// from the moment the connection ENTERED the pool, which is one handshake later. For the
    /// length of that handshake the pool's arithmetic still believes a connection whose QUIC
    /// deadline has already passed is fresh.</para>
    /// <para>What closes the window is that the read loop observes the deadline, stops, and
    /// <c>IsReusable</c> goes false — <c>Http3Connection.IsReusable</c> reads
    /// <c>!_multiplexer.IsStopped</c> for exactly this. So the test holds
    /// <c>PooledConnectionLifetime</c> at its ten-minute default, expires only the CONNECTION,
    /// and requires the pool to notice: a pool that trusted its own clock would hand the dead
    /// connection out again.</para>
    /// </remarks>
    [Fact]
    public async Task APooledHttp3ConnectionPastItsQuicDeadlineIsNotHandedOutAgain()
    {
        await using var fabric = new Http3Fabric();
        await using var session = Session(fabric);

        await session.GetAsync(First).WaitAsync(Bound);
        // The QUIC deadline passes while the pool's ten-minute lifetime has barely started.
        fabric.Connections[0].ExpireQuicDeadline();
        Assert.False(fabric.Connections[0].IsReusable);

        var second = await session.GetAsync(First).WaitAsync(Bound);

        Assert.Equal(2, fabric.Dials.Count);
        Assert.Equal(1, fabric.Exchanges[1].ConnectionOrdinal);
        Assert.True(fabric.Connections[0].IsDisposed);
        Assert.Equal(HttpVersion.Version30, second.HttpVersion);
    }

    /// <summary>
    /// The pool's own lifetime setting retires an HTTP/3 connection too, which is the half the
    /// test above deliberately holds still.
    /// </summary>
    [Fact]
    public async Task PooledConnectionLifetimeRetiresAnHttp3ConnectionAsWell()
    {
        await using var fabric = new Http3Fabric();
        await using var session = Session(
            fabric,
            options => options.PooledConnectionLifetime = TimeSpan.FromMilliseconds(1));

        await session.GetAsync(First).WaitAsync(Bound);
        // Bounded rather than slept on: the pool reads the wall clock when it next rents.
        await Task.Delay(20).WaitAsync(Bound);
        await session.GetAsync(First).WaitAsync(Bound);

        Assert.Equal(2, fabric.Dials.Count);
        Assert.All(fabric.Dials, dial => Assert.Equal(Http3Only, dial.VersionPolicy));
    }

    /// <summary>
    /// Pooling plus a background read loop plus disposal is the classic deadlock shape, so
    /// disposing a session with an HTTP/3 request still in flight must finish.
    /// </summary>
    /// <remarks>THE POOL'S HALF ONLY. Whether <c>Http3Connection</c> itself can be disposed
    /// while its read loop is pumping is pinned by
    /// <c>Http3StreamMultiplexerTests.DisposalEndsEveryInFlightRequestAndDoesNotHang</c>; what
    /// is unproven until here is that <c>TlsConnectionPool.DisposeAsync</c> does not block on a
    /// lease that is still outstanding.</remarks>
    [Fact]
    public async Task DisposingASessionWithAnInFlightHttp3RequestDoesNotHang()
    {
        var inside = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var fabric = new Http3Fabric
        {
            Respond = async exchange =>
            {
                inside.TrySetResult();
                await release.Task.ConfigureAwait(false);
                return Ok(exchange);
            },
        };
        var session = Session(fabric);

        var pending = session.GetAsync(First);
        await inside.Task.WaitAsync(Bound);

        // The bound is the assertion: a pool that waited for the outstanding lease never returns.
        await session.DisposeAsync().AsTask().WaitAsync(Bound);

        release.SetResult();
        // The request itself may succeed or fail; what it may not do is never finish.
        await pending.ContinueWith(_ => { }, TaskScheduler.Default).WaitAsync(Bound);
    }

    // ------------------------------------------------------------------------------
    // Redirects.
    // ------------------------------------------------------------------------------

    /// <summary>
    /// A redirect taken from HTTP/3 is followed over HTTP/3. Silently landing the second hop on
    /// TCP is the downgrade this project's central rule forbids, and a caller reading only the
    /// final response would never see it.
    /// </summary>
    [Fact]
    public async Task AnHttp3RedirectIsFollowedOverHttp3AndNeverDropsToTcp()
    {
        await using var fabric = new Http3Fabric
        {
            Respond = exchange => new ValueTask<ParsedHttpResponse>(
                exchange.Url == First
                    ? Redirect(exchange, HttpStatusCode.Found, Second)
                    : Ok(exchange)),
        };
        await using var session = Session(fabric);

        var response = await session.GetAsync(First).WaitAsync(Bound);

        // THE ASSERTION IS THE POLICY EACH HOP WAS DIALLED WITH, not the version of the final
        // response: a second hop dialled PreferHttp2 that happened to negotiate h3 would pass
        // the weaker check and still be the bug.
        Assert.Equal(2, fabric.Dials.Count);
        Assert.All(fabric.Dials, dial => Assert.Equal(Http3Only, dial.VersionPolicy));
        Assert.Equal([First.IdnHost, Second.IdnHost], fabric.Dials.Select(d => d.Origin.IdnHost));
        Assert.Equal(HttpVersion.Version30, response.HttpVersion);
        Assert.Equal(Second, response.Url);
        var hop = Assert.Single(response.History);
        Assert.Equal(HttpStatusCode.Found, hop.StatusCode);
        Assert.Equal(First, hop.From);
        Assert.Equal(Second, hop.To);
    }

    /// <summary>
    /// A same-origin redirect reuses the QUIC connection it arrived on rather than paying for a
    /// second handshake to the host it is already talking to.
    /// </summary>
    [Fact]
    public async Task ASameOriginHttp3RedirectReusesTheConnectionItArrivedOn()
    {
        var landing = new Uri(First, "/landing");
        await using var fabric = new Http3Fabric
        {
            Respond = exchange => new ValueTask<ParsedHttpResponse>(
                exchange.Url == First
                    ? Redirect(exchange, HttpStatusCode.MovedPermanently, landing)
                    : Ok(exchange)),
        };
        await using var session = Session(fabric);

        var response = await session.GetAsync(First).WaitAsync(Bound);

        Assert.Single(fabric.Dials);
        Assert.Equal([0, 0], fabric.Exchanges.Select(exchange => exchange.ConnectionOrdinal));
        Assert.Equal(landing, response.Url);
        Assert.Equal(HttpVersion.Version30, response.HttpVersion);
    }

    // ------------------------------------------------------------------------------
    // Cookies.
    // ------------------------------------------------------------------------------

    /// <summary>
    /// A Set-Cookie received over HTTP/3 is STORED, and is not replayed on the next request.
    /// The container is a record of what the server said, not a source of request fields: a
    /// field reaches the wire only when <c>AddHeader</c> put it there, so replaying the stored
    /// value is the caller's to do.
    /// </summary>
    [Fact]
    public async Task ASetCookieFromAnHttp3ResponseIsStoredButNotReplayedOnItsOwn()
    {
        await using var fabric = new Http3Fabric
        {
            Respond = exchange =>
            {
                var response = Ok(exchange);
                response.Headers.Add("set-cookie", "sid=abc; Path=/");
                return new ValueTask<ParsedHttpResponse>(response);
            },
        };
        await using var session = Session(fabric);

        await session.GetAsync(First).WaitAsync(Bound);
        await session.GetAsync(First).WaitAsync(Bound);

        Assert.True(string.IsNullOrEmpty(fabric.Exchanges[0].Cookie));
        Assert.True(string.IsNullOrEmpty(fabric.Exchanges[1].Cookie));
        var stored = Assert.Single(session.Cookies.GetCookies(First).Cast<Cookie>());
        Assert.Equal("sid", stored.Name);
        Assert.Equal("abc", stored.Value);
    }

    /// <summary>
    /// A cookie the request added does reach the wire, and reaches it as RFC 9114 section
    /// 4.2.1's <c>cookie</c> field.
    /// </summary>
    [Fact]
    public async Task AnAddedCookieReachesTheHttp3Request()
    {
        await using var fabric = new Http3Fabric();
        await using var session = Session(fabric);

        using var request = new HttpRequestMessage(HttpMethod.Get, First);
        request.AddHeader("cookie", "sid=abc");
        await session.SendAsync(request).WaitAsync(Bound);

        Assert.Equal("sid=abc", fabric.Exchanges[0].Cookie);
    }

    /// <summary>
    /// A cross-origin redirect does not carry the first origin's cookie to the second, over
    /// HTTP/3 as over anything else. The cookie under test is one the REQUEST added, because
    /// that is now the only kind there is — and it is exactly the kind the origin-bound filter
    /// exists to strip.
    /// </summary>
    [Fact]
    public async Task AnHttp3RedirectToAnotherOriginDoesNotCarryTheFirstOriginsCookies()
    {
        await using var fabric = new Http3Fabric
        {
            Respond = exchange =>
            {
                if (exchange.Url != First)
                {
                    return new ValueTask<ParsedHttpResponse>(Ok(exchange));
                }
                var response = Redirect(exchange, HttpStatusCode.Found, Second);
                response.Headers.Add("set-cookie", "sid=abc; Path=/");
                return new ValueTask<ParsedHttpResponse>(response);
            },
        };
        await using var session = Session(fabric);

        using var request = new HttpRequestMessage(HttpMethod.Get, First);
        request.AddHeader("cookie", "sid=abc");
        await session.SendAsync(request).WaitAsync(Bound);

        Assert.Equal(2, fabric.Exchanges.Count);
        Assert.Equal("sid=abc", fabric.Exchanges[0].Cookie);
        Assert.True(string.IsNullOrEmpty(fabric.Exchanges[1].Cookie));
        Assert.Empty(session.Cookies.GetCookies(Second).Cast<Cookie>());
        Assert.Single(session.Cookies.GetCookies(First).Cast<Cookie>());
    }

    // ------------------------------------------------------------------------------
    // Retries.
    // ------------------------------------------------------------------------------

    /// <summary>
    /// A refusal that a FRESH QUIC connection would not give is retried, on a fresh QUIC
    /// connection.
    /// </summary>
    /// <remarks>The exception is not invented here: it is what
    /// <c>Http3Connection.Describe</c> produces for a peer GOAWAY, so a change to that mapping
    /// changes what this test exercises.</remarks>
    [Fact]
    public async Task AStaleHttp3ConnectionIsRetriedOnAFreshQuicConnection()
    {
        var attempts = 0;
        await using var fabric = new Http3Fabric
        {
            Respond = exchange => Interlocked.Increment(ref attempts) == 1
                ? throw Http3Connection.Describe(
                    TlsQuicHttp3RequestRefusal.GoawayReceived,
                    TlsQuicHttp3RequestError.None,
                    streamCredit: 0,
                    initialMaxData: 0,
                    remainingConnectionData: 0,
                    connectionErrorCode: 0)
                : new ValueTask<ParsedHttpResponse>(Ok(exchange)),
        };
        await using var session = Session(fabric);

        var response = await session.GetAsync(First).WaitAsync(Bound);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // Two handshakes: the retry took a NEW connection rather than the refusing one.
        Assert.Equal(2, fabric.Dials.Count);
        Assert.Equal(1, fabric.Exchanges[1].ConnectionOrdinal);
        Assert.True(fabric.Connections[0].IsDisposed);
        // AND THE RETRY STAYED ON HTTP/3. A retry that fell back to TCP would be the same
        // silent downgrade a redirect must not make.
        Assert.All(fabric.Dials, dial => Assert.Equal(Http3Only, dial.VersionPolicy));
    }

    /// <summary>
    /// A QUIC connection that dies mid-response is retried, because a dead transport is not a
    /// protocol violation.
    /// </summary>
    /// <remarks>
    /// <para>THIS IS THE ONE THIS WORK HAD TO CLOSE. <c>Http3StreamMultiplexer</c>'s read loop
    /// meets two QUIC failure shapes — its deadline passing and the peer sending
    /// CONNECTION_CLOSE — and used to report both as a <c>TlsHttpProtocolException</c>, which is
    /// the single exception type <c>TlsSession.ShouldRetryException</c> refuses to retry. An
    /// idempotent HTTP/3 GET whose connection died therefore failed outright where the identical
    /// HTTP/2 GET was retried, because <c>Http2Connection</c>'s loop wraps a dead transport in a
    /// plain <see cref="IOException"/> instead. HTTP/3 now draws the same line.</para>
    /// <para>A POST IS STILL NOT REPLAYED, which is the other half of the safety and is asserted
    /// below rather than argued.</para>
    /// </remarks>
    [Fact]
    public async Task AQuicConnectionThatDiesMidResponseIsRetriedForAnIdempotentRequest()
    {
        var attempts = 0;
        await using var fabric = new Http3Fabric
        {
            Respond = exchange => Interlocked.Increment(ref attempts) == 1
                ? throw new IOException(
                    "The HTTP/3 (QUIC) connection failed before the response was complete.",
                    new TimeoutException())
                : new ValueTask<ParsedHttpResponse>(Ok(exchange)),
        };
        await using var session = Session(fabric);

        var response = await session.GetAsync(First).WaitAsync(Bound);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, fabric.Dials.Count);
        Assert.All(fabric.Dials, dial => Assert.Equal(Http3Only, dial.VersionPolicy));
        Assert.Equal(HttpVersion.Version30, response.HttpVersion);
    }

    /// <summary>
    /// The same dead connection does not replay a POST, because
    /// <c>TlsRetryOptions.RetryNonIdempotentMethods</c> defaults to false.
    /// </summary>
    [Fact]
    public async Task AQuicConnectionThatDiesMidResponseDoesNotReplayAPost()
    {
        await using var fabric = new Http3Fabric
        {
            Respond = _ => throw new IOException(
                "The HTTP/3 (QUIC) connection failed before the response was complete.",
                new TimeoutException()),
        };
        await using var session = Session(fabric);

        using var content = new StringContent("payload");
        using var request = new HttpRequestMessage(HttpMethod.Post, First) { Content = content };
        await Assert.ThrowsAsync<IOException>(
            async () => await session.SendAsync(request).WaitAsync(Bound));

        // ONE attempt and one handshake. Two would mean the payload reached the origin twice.
        Assert.Single(fabric.Exchanges);
        Assert.Single(fabric.Dials);
    }

    /// <summary>
    /// A refusal that every connection to this peer would repeat is NOT retried, so a large
    /// upload does not buy a second QUIC handshake to fail identically.
    /// </summary>
    [Fact]
    public async Task ATerminalHttp3RefusalIsNotRetried()
    {
        await using var fabric = new Http3Fabric
        {
            Respond = _ => throw Http3Connection.Describe(
                TlsQuicHttp3RequestRefusal.PeerStreamCreditTooSmall,
                TlsQuicHttp3RequestError.None,
                streamCredit: 6_291_456,
                initialMaxData: 15_728_640,
                remainingConnectionData: 15_720_000,
                connectionErrorCode: 0),
        };
        await using var session = Session(fabric);

        var exception = await Assert.ThrowsAsync<TlsHttpProtocolException>(
            async () => await session.GetAsync(First).WaitAsync(Bound));

        Assert.Contains(
            "initial_max_stream_data_bidi_remote",
            exception.Message,
            StringComparison.Ordinal);
        // ONE attempt, and the message a caller sees is the encoder's own rather than a
        // connect failure from a pointless second handshake.
        Assert.Single(fabric.Exchanges);
        Assert.Single(fabric.Dials);
    }

    /// <summary>
    /// A retry never escapes to another transport even when HTTP/3 keeps failing: the caller
    /// gets the HTTP/3 failure, not an HTTP/2 success.
    /// </summary>
    [Fact]
    public async Task AnHttp3RequestThatKeepsFailingIsNeverRetriedOverTcp()
    {
        await using var fabric = new Http3Fabric
        {
            Respond = _ => throw new IOException("the QUIC connection died"),
        };
        await using var session = Session(fabric);

        await Assert.ThrowsAsync<IOException>(
            async () => await session.GetAsync(First).WaitAsync(Bound));

        // MaximumAttempts defaults to 2, so exactly two HTTP/3 attempts and no third one over
        // anything else.
        Assert.Equal(2, fabric.Exchanges.Count);
        Assert.Equal(2, fabric.Dials.Count);
        Assert.All(fabric.Dials, dial => Assert.Equal(Http3Only, dial.VersionPolicy));
    }

    /// <summary>
    /// One fatal transport fault costs one connection and not the session: the requests riding
    /// the dead connection are told the real cause, the connection is evicted and disposed, and
    /// the next request is answered on a fresh one.
    /// </summary>
    /// <remarks>
    /// <para>THE FIELD REPORT THIS PINS SAID "NO RECOVERY". An HTTP/3 session took an
    /// <see cref="ArgumentException"/> out of QUIC packet construction and every later request
    /// then failed with a session timeout, so an onboarding run fetched nothing. The trigger is
    /// one bug; a client library surviving one bad connection is a separate property, and it is
    /// this one.</para>
    /// <para>AN <see cref="ArgumentException"/> IS THE FAULT DELIBERATELY, because it is the one
    /// shape that reaches the caller unrewritten and unretried.
    /// <c>TlsSession.ShouldRetryException</c> retries an <see cref="IOException"/> and an
    /// <see cref="HttpRequestException"/>, so either of those would let a silent retry supply
    /// the second connection and the test would prove nothing about eviction. Here the first
    /// caller gets the fault itself, and the SECOND request — a new call, the caller's own
    /// decision to reissue — is what must find a live connection.</para>
    /// <para>THE FOUR CONCURRENT REQUESTS ARE THE POINT AND NOT DECORATION. A connection dying
    /// under one request evicts on the path that request already walks; a connection dying under
    /// four has three more callers arriving at a corpse, which is the shape the report describes
    /// and the shape that leaves an entry pooled with outstanding leases. All four must be told,
    /// and the entry must still be gone afterwards.</para>
    /// </remarks>
    [Fact]
    public async Task AFatalTransportFaultEvictsTheHttp3ConnectionRatherThanPoisoningTheSession()
    {
        const int Together = 4;
        using var arrived = new SemaphoreSlim(0, Together);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var fabric = new Http3Fabric
        {
            Respond = async exchange =>
            {
                if (exchange.ConnectionOrdinal != 0)
                {
                    return Ok(exchange);
                }
                arrived.Release();
                await release.Task.ConfigureAwait(false);
                throw new ArgumentException("the QUIC packet could not be built");
            },
        };
        await using var session = Session(fabric);

        var requests = new Task<TlsResponse>[Together];
        for (var index = 0; index < Together; index++)
        {
            requests[index] = session.GetAsync(First);
            Assert.True(
                await arrived.WaitAsync(Bound),
                $"HTTP/3 request {index + 1} of {Together} never reached the connection that " +
                "was about to die");
        }
        release.SetResult();

        foreach (var request in requests)
        {
            // THE REAL CAUSE, NOT A TIMEOUT. A caller told only that its request expired cannot
            // tell a dead peer from a bug in this stack, and the report that started this said
            // "TaskCanceledException" for what was an ArgumentException all along.
            var fault = await Assert.ThrowsAsync<ArgumentException>(
                async () => await request.WaitAsync(Bound));
            Assert.Contains(
                "the QUIC packet could not be built",
                fault.Message,
                StringComparison.Ordinal);
        }

        // Evicted AND disposed, not merely marked. A pool that removed the entry and leaked the
        // QUIC connection would still leave the socket and the read loop alive.
        Assert.True(fabric.Connections[0].IsDisposed);

        // The whole claim: the session still works. Bounded, so a pool that parked this request
        // behind a corpse it would not replace fails the run rather than hanging it — which is
        // exactly how the reported failure presented.
        var recovered = await session.GetAsync(First).WaitAsync(Bound);

        Assert.Equal(HttpVersion.Version30, recovered.HttpVersion);
        Assert.Equal(2, fabric.Dials.Count);
        Assert.Equal(1, fabric.Exchanges[^1].ConnectionOrdinal);
        Assert.All(fabric.Dials, dial => Assert.Equal(Http3Only, dial.VersionPolicy));
    }

    // ------------------------------------------------------------------------------
    // The harness.
    // ------------------------------------------------------------------------------

#pragma warning disable TLSCLIENT3 // Exercising the experimental policy is the point of the file.
    private const TlsHttpVersionPolicy Http3Only = TlsHttpVersionPolicy.Http3Only;
#pragma warning restore TLSCLIENT3

    private static TlsSession Session(
        Http3Fabric fabric,
        Action<TlsSessionOptions>? configure = null)
    {
        var options = new TlsSessionOptions { HttpVersionPolicy = Http3Only };
        configure?.Invoke(options);
        return new TlsSession(options, fabric.Connect);
    }

    private static ParsedHttpResponse Ok(Exchange exchange)
    {
        var headers = new TlsHeaders();
        headers.Set("content-type", "text/plain");
        return new ParsedHttpResponse(
            exchange.Version,
            HttpStatusCode.OK,
            string.Empty,
            headers,
            new TlsHeaders(),
            "ok"u8.ToArray(),
            true,
            0);
    }

    private static ParsedHttpResponse Redirect(
        Exchange exchange,
        HttpStatusCode statusCode,
        Uri location)
    {
        var headers = new TlsHeaders();
        headers.Set("location", location.AbsoluteUri);
        return new ParsedHttpResponse(
            exchange.Version,
            statusCode,
            string.Empty,
            headers,
            new TlsHeaders(),
            [],
            true,
            0);
    }

    /// <summary>One dial the pool asked for.</summary>
    private readonly record struct Dial(Uri Origin, TlsHttpVersionPolicy VersionPolicy);

    /// <summary>Everything one request was handed on its way to the wire.</summary>
    /// <remarks>The cookie witness is the request's OWN field list, not an argument the pool
    /// computed: nothing injects a Cookie field any more, so a value that never reached the
    /// list never reaches the wire, and asserting on the argument would pass vacuously.
    /// </remarks>
    private sealed record Exchange(
        int ConnectionOrdinal,
        string Method,
        Uri Url,
        string? Cookie,
        Version Version);

    /// <summary>
    /// The connection factory the pool dials, plus the record of what it was asked for.
    /// </summary>
    private sealed class Http3Fabric(int streamAllowance = 100) : IAsyncDisposable
    {
        private readonly ConcurrentQueue<Dial> _dials = [];
        private readonly ConcurrentQueue<Exchange> _exchanges = [];
        private readonly List<FakeHttp3Connection> _connections = [];
        private readonly object _sync = new();

        /// <summary>What a request is answered with. The default is a plain 200.</summary>
        internal Func<Exchange, ValueTask<ParsedHttpResponse>> Respond { get; init; } =
            exchange => new ValueTask<ParsedHttpResponse>(Ok(exchange));

        internal IReadOnlyList<Dial> Dials => [.. _dials];

        internal IReadOnlyList<Exchange> Exchanges => [.. _exchanges];

        internal IReadOnlyList<FakeHttp3Connection> Connections
        {
            get
            {
                lock (_sync)
                {
                    return [.. _connections];
                }
            }
        }

        internal HttpConnectAsync Connect => (origin, versionPolicy, _, _) =>
        {
            _dials.Enqueue(new Dial(origin, versionPolicy));
            FakeHttp3Connection connection;
            lock (_sync)
            {
                connection = new FakeHttp3Connection(
                    this,
                    _connections.Count,
                    versionPolicy,
                    streamAllowance);
                _connections.Add(connection);
            }
            return new ValueTask<IHttpConnection>(connection);
        };

        internal ValueTask<ParsedHttpResponse> RespondAsync(Exchange exchange)
        {
            _exchanges.Enqueue(exchange);
            return Respond(exchange);
        }

        public async ValueTask DisposeAsync()
        {
            foreach (var connection in Connections)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// An <see cref="IHttpConnection"/> that reports what <c>Http3Connection</c> reports.
    /// </summary>
    /// <remarks>
    /// <para>EVERY MEMBER IS MIRRORED FROM <c>Http3Connection</c> RATHER THAN INVENTED, because
    /// the pool reads nothing else and a fake that reported something friendlier would prove
    /// only that the pool works with a friendlier connection.
    /// <see cref="MaximumConcurrentRequests"/> is the peer's remaining allowance measured
    /// against the number of streams EVER opened, not the number in flight, because
    /// <c>initial_max_streams_bidi</c> is a lifetime allowance and nothing in SharpTls processes
    /// MAX_STREAMS. <see cref="IsReusable"/> ends on disposal, on that allowance reaching zero,
    /// on a failure that left the connection in an unknown state, and on the connection's own
    /// deadline — the four clauses <c>Http3Connection.IsReusable</c> carries, with the read loop
    /// and the peer GOAWAY folded into <see cref="ExpireQuicDeadline"/> and the failure clause
    /// respectively.</para>
    /// <para>The failure clause is mirrored exactly too: an <see cref="HttpRequestException"/>
    /// and a stream-scoped <see cref="TlsHttpProtocolException"/> leave the connection intact
    /// because neither put an octet on the wire, and everything else retires it.</para>
    /// </remarks>
    private sealed class FakeHttp3Connection : IHttpConnection
    {
        private readonly Http3Fabric _fabric;
        private readonly int _allowance;
        private readonly Version _version;
        private int _opened;
        private int _active;
        private int _reusable = 1;
        private int _expired;
        private int _disposed;

        internal FakeHttp3Connection(
            Http3Fabric fabric,
            int ordinal,
            TlsHttpVersionPolicy versionPolicy,
            int allowance)
        {
            _fabric = fabric;
            Ordinal = ordinal;
            _allowance = allowance;
            _version = versionPolicy == Http3Only
                ? HttpVersion.Version30
                : versionPolicy == TlsHttpVersionPolicy.Http2Only
                    ? HttpVersion.Version20
                    : HttpVersion.Version11;
            TlsInfo = new TlsConnectionInfo(
                "fake",
                SharpTls.Protocol.TlsProtocolVersion.Tls13,
                default,
                default,
                _version == HttpVersion.Version30 ? "h3" : "h2",
                false,
                false,
                false,
                []);
            LastUsed = DateTimeOffset.UtcNow;
        }

        internal int Ordinal { get; }

        public TlsConnectionInfo TlsInfo { get; }

        public DateTimeOffset LastUsed { get; private set; }

        public bool HasCompletedRequest => Volatile.Read(ref _opened) != 0;

        public int MaximumConcurrentRequests =>
            Math.Max(0, _allowance - Volatile.Read(ref _opened));

        public bool IsReusable =>
            Volatile.Read(ref _reusable) != 0 &&
            !IsDisposed &&
            Volatile.Read(ref _expired) == 0 &&
            MaximumConcurrentRequests > 0;

        public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

        public bool HasActiveRequests => Volatile.Read(ref _active) != 0;

        /// <summary>Ends the connection the way its QUIC deadline passing ends it: the read
        /// loop stops and <see cref="IsReusable"/> goes false, while the pool's own lifetime
        /// arithmetic still believes the entry is fresh.</summary>
        internal void ExpireQuicDeadline() => Volatile.Write(ref _expired, 1);

        public async ValueTask<ParsedHttpResponse> SendAsync(
            BufferedRequest request,
            StreamingResponseContext? streamingResponse,
            TlsSessionConfiguration configuration,
            CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            if (!IsReusable)
            {
                throw new StaleHttpConnectionException(
                    "The HTTP/3 connection no longer accepts new request streams.");
            }
            Interlocked.Increment(ref _opened);
            Interlocked.Increment(ref _active);
            try
            {
                return await _fabric.RespondAsync(new Exchange(
                    Ordinal,
                    request.Method,
                    request.Url,
                    request.Headers
                        .FirstOrDefault(header => header.Name.Equals(
                            "Cookie", StringComparison.OrdinalIgnoreCase))
                        ?.Values.FirstOrDefault(),
                    _version)).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                if (exception is not HttpRequestException &&
                    exception is not TlsHttpProtocolException { IsStreamScoped: true })
                {
                    Volatile.Write(ref _reusable, 0);
                }
                throw;
            }
            finally
            {
                Interlocked.Decrement(ref _active);
                LastUsed = DateTimeOffset.UtcNow;
            }
        }

        public ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref _disposed, 1);
            return ValueTask.CompletedTask;
        }
    }
}
