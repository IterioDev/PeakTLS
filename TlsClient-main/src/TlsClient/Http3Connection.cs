using System.Diagnostics;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using SharpTls;
using SharpTls.Certificates;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace TlsClient;

/// <summary>
/// One HTTP/3 connection over one QUIC connection, as <see cref="IHttpConnection"/>.
/// </summary>
/// <remarks>
/// <para>THIS IS NOT A <c>SharpTlsTransport</c> CONSUMER. That type dials TCP and hands back a
/// TLS <see cref="Stream"/>; HTTP/3 has neither. The UDP socket, the QUIC handshake and the
/// HTTP/3 layer are all built here, in the order SharpTls's own live interop test establishes.
/// </para>
/// <para>MULTIPLEXED, AND THE PUMP IS WHAT MAKES THAT POSSIBLE RATHER THAN WHAT PREVENTED IT.
/// <c>TlsQuicHttp3Connection.PumpOnceAsync</c> receives ONE datagram per call on the calling
/// thread, so while the only thread that pumped was one already inside <see cref="SendAsync"/>,
/// a second concurrent request would have sat waiting for the first's pump and
/// <see cref="MaximumConcurrentRequests"/> was capped at 1 however many streams the peer
/// allowed. <see cref="Http3StreamMultiplexer"/> now owns that pump on a background loop and
/// hands each datagram's frames to the request stream they belong to, so the cap is gone and
/// the number this reports is the peer's <c>initial_max_streams_bidi</c> allowance and nothing
/// of ours.</para>
/// </remarks>
internal sealed class Http3Connection : IHttpConnection
{
    /// <summary>
    /// How long the QUIC connection may live at all, when the session declares no pooled
    /// lifetime. <c>TlsQuicConnectionOptions.HandshakeDeadline</c> is misleadingly named: it is
    /// set once at start and never moved, and every later receive is bounded by it too, so it
    /// is the connection's whole lifetime and not just its handshake.
    /// </summary>
    private static readonly TimeSpan DefaultConnectionLifetime = TimeSpan.FromMinutes(5);

    /// <summary>The idle timeout advertised when the session declares none. The effective one
    /// is the smaller of this and the peer's, per RFC 9000 section 10.1.</summary>
    private static readonly TimeSpan DefaultIdleTimeout = TimeSpan.FromSeconds(30);

    /// <summary>What the handshake itself gets, which the connection lifetime above cannot
    /// bound on its own once that lifetime is minutes long.</summary>
    private static readonly TimeSpan DefaultHandshakeTimeout = TimeSpan.FromSeconds(30);

    private readonly ITlsQuicDatagramTransport _transport;
    private readonly TlsQuicConnection _connection;
    private readonly TlsQuicHttp3Connection _http3;
    private readonly Http3StreamMultiplexer _multiplexer;
    private readonly int _requestStreamAllowance;
    private readonly TimeSpan? _idleBudget;
    private int _requestsOpened;
    private int _hasCompletedRequest;
    private int _isReusable = 1;
    private int _disposed;

    private Http3Connection(
        ITlsQuicDatagramTransport transport,
        TlsQuicConnection connection,
        TlsQuicHttp3Connection http3,
        TlsConnectionInfo tlsInfo,
        int requestStreamAllowance,
        TimeSpan? idleBudget)
    {
        _transport = transport;
        _connection = connection;
        _http3 = http3;
        _multiplexer = new Http3StreamMultiplexer(
            new SharpTlsHttp3Streams(connection, http3));
        _requestStreamAllowance = requestStreamAllowance;
        _idleBudget = idleBudget;
        TlsInfo = tlsInfo;
        LastUsed = DateTimeOffset.UtcNow;
    }

    public TlsConnectionInfo TlsInfo { get; }

    public DateTimeOffset LastUsed { get; private set; }

    public bool HasCompletedRequest => Volatile.Read(ref _hasCompletedRequest) != 0;

    /// <summary>
    /// Gets whether another request may be opened on this connection.
    /// </summary>
    /// <remarks>
    /// Four things end reuse, and only the first is this type's own bookkeeping.
    /// <list type="number">
    /// <item>Disposal, or a failure that left the connection in an unknown state.</item>
    /// <item>The peer's <c>initial_max_streams_bidi</c> is spent. It is a LIFETIME allowance
    /// rather than a concurrency limit — nothing here processes MAX_STREAMS — so the count of
    /// request streams ever opened is what is measured against it.</item>
    /// <item>A peer GOAWAY. RFC 9114 section 5.2 rejects "requests ... with the indicated
    /// identifier or greater", and every stream this connection opens from now on has a
    /// greater identifier, so any GOAWAY at all ends reuse.</item>
    /// <item>The read loop having stopped, for whatever reason ended it. That is the OBSERVED
    /// end of the connection rather than a predicted one, and it is what the two clauses below
    /// only estimate.</item>
    /// <item>The negotiated QUIC idle timeout. The read loop receives between requests but
    /// sends nothing ack-eliciting, so an idle connection is still not keeping itself alive
    /// (RFC 9000 section 10.1); past the negotiated timeout the peer has discarded its state
    /// and a second request would be sent into a hole. Half of the timeout, so a request that
    /// starts inside the budget can still finish inside it. Kept as well as the clause above
    /// because it retires an idle connection BEFORE the loop spends the full timeout finding
    /// out.</item>
    /// </list>
    /// </remarks>
    public bool IsReusable =>
        Volatile.Read(ref _isReusable) != 0 &&
        !IsDisposed &&
        !_multiplexer.IsStopped &&
        RemainingRequestStreams > 0 &&
        _http3.PeerGoawayStreamId is null &&
        (_idleBudget is not { } budget || DateTimeOffset.UtcNow - LastUsed < budget);

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    public bool HasActiveRequests => _multiplexer.HasActiveStreams;

    /// <summary>
    /// Gets how many requests may be in flight at once: the peer's remaining
    /// <c>initial_max_streams_bidi</c> allowance.
    /// </summary>
    /// <remarks>THE PEER'S NUMBER AND NOTHING OF OURS. It was capped at one while a request's
    /// own thread was the only thing that could pump the connection;
    /// <see cref="Http3StreamMultiplexer"/> pumps it on a background loop instead, so what is
    /// left to limit concurrency is the allowance itself. It is a LIFETIME allowance rather
    /// than a concurrency limit — nothing in SharpTls processes MAX_STREAMS — so the count of
    /// request streams ever opened is what is measured against it, and this reaching 0 ends
    /// reuse rather than merely pausing it.</remarks>
    public int MaximumConcurrentRequests => RemainingRequestStreams;

    private int RemainingRequestStreams =>
        Math.Max(0, _requestStreamAllowance - Volatile.Read(ref _requestsOpened));

    /// <summary>
    /// Dials UDP - directly, or through a SOCKS5 UDP association - completes a QUIC
    /// handshake with ALPN <c>h3</c>, and opens HTTP/3's unidirectional streams.
    /// </summary>
    /// <remarks>
    /// <para>A SOCKS5 <paramref name="proxy"/> RELAYS THE DATAGRAMS BUT NOT THE LOOKUP. The
    /// origin is resolved locally, below, because <c>ITlsQuicDatagramTransport.SendAsync</c>
    /// takes an <see cref="IPEndPoint"/>, so RFC 1928's domain-name address type never gets a
    /// chance to be used. The proxy carries the traffic while this host still makes the DNS
    /// query - visible to a local resolver, and answered from here rather than from the
    /// proxy's vantage point, which can select a different server. Anyone proxying to hide
    /// their network position wants <c>TlsSessionOptions.DnsResolver</c> pointed somewhere
    /// that does not defeat the purpose.</para>
    /// <para>ONE <c>TlsQuicConnectionSpec</c> OBJECT REACHES BOTH READERS, and that is
    /// load-bearing rather than tidy. The connection enforces the six flow-control limits from
    /// its spec while the ClientHello factory ADVERTISES them from its own; a second spec
    /// object with different values is not rejected anywhere and simply makes the client
    /// police a budget it never advertised. Two of the three divergences are silent — see
    /// <c>TlsQuicClientHelloProfileFactory</c>'s remarks for the third, which throws.</para>
    /// <para>THE PROFILE IS BUILT INSIDE THE CLIENT CALLBACK, per connection. Three of the
    /// transport parameters are drawn afresh on every composition, so a profile hoisted out of
    /// this method and reused would freeze three values a real client varies.</para>
    /// </remarks>
    /// <exception cref="HttpRequestException">The origin resolved to no address, the
    /// handshake did not complete, or the peer did not select <c>h3</c>.</exception>
    public static async ValueTask<IHttpConnection> CreateAsync(
        Uri origin,
        TlsProxy? proxy,
        TlsSessionConfiguration configuration,
        DnsEndpointResolver dnsResolver,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(dnsResolver);

        var connectionId = Guid.NewGuid();
        var addresses = await dnsResolver.ResolveAsync(
            origin.IdnHost,
            origin.Port,
            connectionId,
            cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0)
        {
            throw new HttpRequestException(
                $"No address was resolved for '{origin.IdnHost}'.");
        }
        // The first address only. Happy Eyeballs (RFC 8305) races TCP connects and has no
        // equivalent here: a QUIC handshake is the connect, so racing two would mean two
        // handshakes and two ClientHellos. Left undone rather than approximated.
        var endPoint = new IPEndPoint(addresses[0], origin.Port);

        // Every value here is the session's, not this file's. NOT configuration.Profile for the
        // TLS half: a TlsProfile describes a TCP ClientHello — TLS 1.2 suites, session tickets,
        // ALPS — and several of its extensions are ones RFC 9001 section 8.4 forbids over QUIC.
        // TlsSessionOptions.Quic is the QUIC-shaped surface that drives this instead.
        var spec = configuration.Quic.ConnectionSpec;
        var factory = new TlsQuicClientHelloProfileFactory
        {
            ConnectionSpec = spec,
            AlpnProtocols = configuration.Quic.AlpnProtocols,
            Tls = configuration.Quic.ConfigureClientHello,
        };

        // THE TRANSPORT IS THE ONLY THING A PROXY CHANGES HERE. Everything below - the
        // spec, the ClientHello, the deadline, the streams - is identical either way,
        // because ITlsQuicDatagramTransport is a real seam: the SOCKS5 relay encapsulates
        // each datagram with its destination and decapsulates the origin address on the way
        // back, so the connection above it never learns that it is relayed.
        //
        // The factory has already refused every proxy type but SOCKS5, so a non-null proxy
        // here is a SOCKS5 one. Asserting that rather than re-deciding it keeps the two
        // places from drifting into disagreeing about which types can carry QUIC.
        Debug.Assert(
            proxy is null || proxy.Type == TlsProxyType.Socks5,
            "HttpConnectionFactory must reject non-SOCKS5 proxies before reaching here.");
        var transport = proxy is null
            ? TlsQuicUdpDatagramTransport.Create(endPoint.AddressFamily)
            : await TlsQuicSocks5Transport.ConnectAsync(
                new TlsQuicSocks5Options
                {
                    ProxyEndPoint = new DnsEndPoint(proxy.Address.IdnHost, proxy.EffectivePort),
                    Username = proxy.GetCredentials()?.UserName,
                    Password = proxy.GetCredentials()?.Password,

                    // The origin travels as a NAME, so the proxy resolves it rather than this
                    // host. A literal-address datagram header is refused outright by proxies
                    // whose ruleset forbids IP destinations - they close the control connection
                    // on the first datagram, which surfaces as the association ending. Sending
                    // the name is the only form such a proxy accepts, and it moves DNS to the
                    // proxy's vantage point, which is usually what a caller proxying to hide
                    // their location wanted anyway.
                    DestinationHost = origin.IdnHost,
                },
                cancellationToken).ConfigureAwait(false);
        TlsQuicConnection? connection = null;
        CustomTlsQuicClient? tlsClient = null;
        try
        {
            connection = new TlsQuicConnection(
                new TlsQuicConnectionOptions(transport, endPoint, spec)
                {
                    HandshakeDeadline = Bounded(
                        configuration.PooledConnectionLifetime,
                        DefaultConnectionLifetime),
                    IdleTimeout = Bounded(
                        configuration.PooledConnectionIdleTimeout,
                        DefaultIdleTimeout),
                },
                source => tlsClient = CreateTlsClient(origin, configuration, factory, source));

            using var handshake = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            handshake.CancelAfter(HandshakeTimeout(configuration));
            try
            {
                await connection.ConnectAsync(handshake.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                handshake.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new HttpRequestException(
                    $"The HTTP/3 (QUIC) handshake with '{origin.IdnHost}' did not complete " +
                    $"within {HandshakeTimeout(configuration)}.");
            }
            catch (Exception exception) when (
                exception is TimeoutException or InvalidOperationException)
            {
                throw new HttpRequestException(
                    $"The HTTP/3 (QUIC) handshake with '{origin.IdnHost}' failed.",
                    exception);
            }

            if (tlsClient?.NegotiatedApplicationProtocol !=
                TlsQuicClientHelloProfileFactory.Http3AlpnToken)
            {
                throw new HttpRequestException(
                    "The peer did not select ALPN 'h3', so this connection cannot carry " +
                    $"HTTP/3 (it selected '{tlsClient?.NegotiatedApplicationProtocol}').");
            }

            // The spec's default settings carry SETTINGS_H3_DATAGRAM (0x33) = 1, which the
            // constructor refuses unless the ClientHello also advertised a non-zero
            // max_datagram_frame_size. The default transport parameter preset does, so the
            // pair agrees by construction — a narrowed preset that drops 0x20 would be told
            // here rather than by a peer's H3_SETTINGS_ERROR.
            var http3 = new TlsQuicHttp3Connection(connection, configuration.Quic.Http3Spec);
            http3.OpenLocalStreams();
            if (!await connection.SendPendingAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new HttpRequestException(
                    "The HTTP/3 control stream could not be opened: the QUIC connection had " +
                    "nothing to send.");
            }

            var allowance = (int)Math.Min(
                connection.PeerFlowControl.InitialMaxStreamsBidi,
                int.MaxValue);
            var idleBudget = connection.EffectiveIdleTimeout() is { } effective
                ? TimeSpan.FromTicks(effective.Ticks / 2)
                : (TimeSpan?)null;
            var result = new Http3Connection(
                transport,
                connection,
                http3,
                BuildTlsInfo(configuration, tlsClient),
                allowance,
                idleBudget);
            // Started here rather than in the constructor so that the loop cannot observe a
            // half-built connection, and only once everything above succeeded — a connection
            // that failed the handshake is disposed by the catch below, which has no loop to
            // stop.
            result._multiplexer.Start();
            return result;
        }
        catch
        {
            if (connection is not null)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }
            await transport.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask<ParsedHttpResponse> SendAsync(
        BufferedRequest request,
        string? cookieHeader,
        StreamingResponseContext? streamingResponse,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        // Built before the stream is opened because nothing in it touches the connection: a
        // field section this connection would refuse to encode, or a caller's own content
        // stream failing, should not have spent a stream ordinal first.
        var encodable = await BuildRequestAsync(
            request, cookieHeader, configuration, cancellationToken)
            .ConfigureAwait(false);

        Http3StreamState? state = null;
        try
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            if (!IsReusable)
            {
                throw new StaleHttpConnectionException(
                    "The HTTP/3 connection no longer accepts new request streams.");
            }

            // NO CONNECTION-WIDE GATE AROUND THE REST OF THIS METHOD, WHICH IS THE CHANGE.
            // OpenAsync takes SharpTls exclusively for as long as it takes to encode and send
            // one request and then releases it; everything after is a wait on THIS stream's
            // own state, which the background read loop fills in. Two callers therefore
            // overlap for the whole of the part that takes time.
            state = await _multiplexer.OpenAsync(
                encodable,
                streamingResponse is not null,
                configuration.MaximumResponseBodyBytes,
                cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _requestsOpened);

            var result = await ReadResponseAsync(
                state,
                request,
                streamingResponse,
                configuration,
                cancellationToken).ConfigureAwait(false);
            Interlocked.Exchange(ref _hasCompletedRequest, 1);
            LastUsed = DateTimeOffset.UtcNow;
            return result;
        }
        catch (Exception exception)
        {
            // A request the peer never saw leaves the connection intact: a field section it
            // refused to encode, or one too large for the peer's advertised limit, spent no
            // stream ordinal and put no byte on the wire. Everything else did — INCLUDING A
            // CANCELLED REQUEST, whose stream is abandoned mid-response because SharpTls
            // exposes no RESET_STREAM, so its octets keep arriving into a reader nothing
            // drains. Retiring the connection is what stops that; the requests already in
            // flight on it are unaffected, since IsReusable gates only NEW ones.
            if (exception is not HttpRequestException &&
                exception is not TlsHttpProtocolException { IsStreamScoped: true })
            {
                Volatile.Write(ref _isReusable, 0);
            }
            streamingResponse?.Abort(exception);
            throw;
        }
        finally
        {
            if (state is not null)
            {
                _multiplexer.Release(state.StreamId);
            }
        }
    }

    /// <summary>
    /// Turns one TlsClient request into the RFC 9114 section 4.1 message SharpTls encodes:
    /// its pseudo-headers, its field section, its content and its trailer section.
    /// </summary>
    /// <remarks>
    /// <para>SEPARATE FROM <see cref="SendAsync"/> SO THAT IT CAN BE WITNESSED. Everything here
    /// is a pure function of the request and the configuration — no socket, no QUIC handshake,
    /// no peer — and <c>TlsQuicHttp3Request.TryEncode</c> is reachable from the test assembly,
    /// so the WHOLE wire image of a request is checkable offline. Inlined in SendAsync it was
    /// not: the only thing that could have proved a body reached the DATA frame was a live run,
    /// and the mutation sweep found exactly that hole by reporting a deliberately broken
    /// <c>:scheme</c> as unwitnessed.</para>
    /// <para><see cref="TlsQuicHttp3Request.Body"/> and
    /// <see cref="TlsQuicHttp3Request.Trailers"/> both default to empty, and empty is what makes
    /// TryEncode emit NO DATA frame and NO trailing HEADERS frame — so a GET's wire image is
    /// byte for byte what it was before request content existed.</para>
    /// </remarks>
    internal static async ValueTask<TlsQuicHttp3Request> BuildRequestAsync(
        BufferedRequest request,
        string? cookieHeader,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var fields = Http3FieldMapper.BuildRequestFields(
            request, cookieHeader, configuration, out var authority);
        var trailers = Http3FieldMapper.BuildTrailerFields(request, configuration);
        var body = await ReadRequestBodyAsync(request, configuration, cancellationToken)
            .ConfigureAwait(false);

        var path = request.PathOverride ??
            request.Url.GetComponents(UriComponents.PathAndQuery, UriFormat.UriEscaped);
        if (path.Length == 0)
        {
            path = "/";
        }
        return new TlsQuicHttp3Request
        {
            Method = request.Method,
            Scheme = request.Scheme ?? "https",
            Authority = authority,
            Path = path,
            Fields = fields,
            Body = [.. body],
            Trailers = trailers,
        };
    }

    /// <summary>
    /// Gets the octets of RFC 9114 section 4.1's optional content, as one array.
    /// </summary>
    /// <remarks>
    /// <para>ONE ARRAY AND NOT A STREAM, WHICH IS SharpTls'S SHAPE RATHER THAN A CHOICE.
    /// <c>TlsQuicHttp3Request.TryEncode</c> appends the HEADERS frame, the DATA frame and the
    /// trailing HEADERS frame to one list and <c>TryOpenRequest</c> hands the lot to a single
    /// <c>Send</c> with FIN; there is no entry point that appends to a stream already open. A
    /// streaming request body is therefore BUFFERED here rather than streamed, which is a
    /// smaller lie than sending the request without it — and the session's request-body limit
    /// bounds what that buffering may cost, checked as the octets arrive rather than after.
    /// </para>
    /// <para><see cref="BufferedRequest.HasContent"/> is what is read, not
    /// <see cref="BufferedRequest.Body"/>'s length, so that the one request shape that carries
    /// octets it does not mean to send — a redirect that dropped its body — keeps agreeing with
    /// <see cref="Http11RequestWriter"/> about whether there is content at all.</para>
    /// </remarks>
    /// <exception cref="HttpRequestException">The streamed content passed the session's
    /// request-body limit.</exception>
    internal static async ValueTask<byte[]> ReadRequestBodyAsync(
        BufferedRequest request,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken)
    {
        if (!request.HasContent)
        {
            return [];
        }
        if (!request.IsStreaming)
        {
            return request.Body;
        }

        using var content = await request.OpenStreamingContentAsync(cancellationToken)
            .ConfigureAwait(false);
        using var buffered = new MemoryStream();
        // Math.Max because a zero-length read buffer makes EVERY read return 0, which this
        // loop would read as the end of the stream and send the request with an empty body —
        // silently, and only for the caller who configured a zero buffer size.
        var chunk = new byte[Math.Max(1, request.StreamingBufferSize)];
        while (true)
        {
            var read = await content.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            if (buffered.Length + read > configuration.MaximumRequestBodyBytes)
            {
                throw new HttpRequestException(
                    "The HTTP/3 request body exceeds the " +
                    $"{configuration.MaximumRequestBodyBytes}-byte session limit.");
            }
            buffered.Write(chunk, 0, read);
        }
        return buffered.ToArray();
    }

    /// <summary>
    /// Waits for one request stream to finish, delivering its octets to a streaming consumer as
    /// they arrive.
    /// </summary>
    /// <remarks>
    /// <para>THIS METHOD NO LONGER PUMPS ANYTHING, WHICH IS WHY IT NO LONGER BLOCKS ANYONE.
    /// <see cref="Http3StreamMultiplexer"/>'s loop owns the wire and copies each stream's
    /// octets into its own <see cref="Http3StreamState"/>; what happens here is a wait on that
    /// state. A stalled response therefore parks THIS call and no other, and the loop keeps
    /// delivering to every other request on the connection.</para>
    /// <para>THE SIGNAL IS CAPTURED BEFORE THE STATE IS READ, and reversing those two lines is
    /// a lost wake-up: a harvest landing between a read and a later capture would complete a
    /// task this call no longer holds, and the request would wait for a datagram that may
    /// never come.</para>
    /// <para>CANCELLATION IS PER REQUEST. The token is awaited on this stream's own signal and
    /// touches neither the read loop nor any other request; a cancelled request abandons its
    /// stream and its caller retires the connection, while everything else in flight runs
    /// on.</para>
    /// </remarks>
    private async ValueTask<ParsedHttpResponse> ReadResponseAsync(
        Http3StreamState state,
        BufferedRequest request,
        StreamingResponseContext? streamingResponse,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var headerBytes = 0;
        TlsHeaders? headers = null;
        HttpStatusCode? status = null;
        // Counted rather than measured off progress.Body, which a streaming request never gets:
        // its octets left in chunks and only their total survives for section 4.1.2's check.
        var streamedBytes = 0;
        Http3StreamProgress progress;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var pumped = _multiplexer.Pumped;
            progress = state.Take();
            if (progress.Fault is not null)
            {
                throw progress.Fault;
            }
            if (headers is null && progress.Status >= 0)
            {
                status = Http3FieldMapper.ReadStatus(progress.Status);
                headers = Http3FieldMapper.BuildHeaders(
                    progress.HeaderFields,
                    configuration.MaximumResponseHeaderBytes,
                    configuration.MaximumResponseHeaderCount,
                    ref headerBytes);
                streamingResponse?.Begin(status.Value, headers);
            }
            if (streamingResponse is not null && headers is not null &&
                progress.Chunks is { } chunks)
            {
                // Awaited on THIS thread and never on the read loop's. The consumer therefore
                // sees octets as they arrive, and one that never returns stalls only its own
                // request. SharpTls still retains every octet it delivered, so this is
                // incremental DELIVERY and not yet bounded memory.
                foreach (var chunk in chunks)
                {
                    streamedBytes += chunk.Length;
                    await streamingResponse.WriteAsync(chunk, cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            if (progress.Done)
            {
                break;
            }
            await pumped.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        if (headers is null || status is null)
        {
            throw new TlsHttpProtocolException(
                "The HTTP/3 response stream ended before its header section arrived.");
        }
        if (!progress.ResponseIsComplete)
        {
            throw new TlsHttpProtocolException(
                "The HTTP/3 response stream ended before the response was complete.");
        }

        var trailerBytes = headerBytes;
        var trailers = Http3FieldMapper.BuildHeaders(
            progress.TrailerFields,
            configuration.MaximumResponseHeaderBytes,
            configuration.MaximumResponseHeaderCount,
            ref trailerBytes);
        var hasBody = Http3FieldMapper.HasResponseBody(request.Method, status.Value);
        var received = progress.Body ?? [];
        var receivedLength = streamingResponse is not null ? streamedBytes : received.Length;
        Http3FieldMapper.ValidateContentLength(
            headers,
            request.Method,
            hasBody ? receivedLength : 0);
        byte[] body;
        if (streamingResponse is not null)
        {
            await streamingResponse.CompleteAsync(cancellationToken).ConfigureAwait(false);
            body = [];
        }
        else
        {
            body = hasBody ? received : [];
        }

        // string.Empty for the reason phrase, not a looked-up default: RFC 9114 section 4.3.2
        // gives HTTP/3 a :status and nothing else — "HTTP/3 does not define a way to carry the
        // version or reason phrase that is included in an HTTP/1.1 status line". Inventing one
        // would report as observed what was never sent. HTTP/2 does the same.
        return new ParsedHttpResponse(
            HttpVersion.Version30,
            status.Value,
            string.Empty,
            headers,
            trailers,
            body,
            true,
            headerBytes);
    }

    /// <summary>
    /// Stops the read loop, says goodbye, and closes the socket.
    /// </summary>
    /// <remarks>DISPOSAL CANNOT RACE THE LOOP BECAUSE THE LOOP IS AWAITED FIRST.
    /// <c>Http3StreamMultiplexer.DisposeAsync</c> cancels the lifetime every one of the loop's
    /// waits observes and then waits for the loop task to finish, so by the time the QUIC
    /// connection and the UDP socket below are torn down, nothing is inside a pump. Every
    /// request still in flight was failed as that loop stopped, so none of them is left waiting
    /// on a connection that no longer exists.</remarks>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Volatile.Write(ref _isReusable, 0);
        await _multiplexer.DisposeAsync().ConfigureAwait(false);
        await TryCloseAsync().ConfigureAwait(false);
        await _connection.DisposeAsync().ConfigureAwait(false);
        await _transport.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Sends RFC 9114 section 5.2's application CONNECTION_CLOSE, carrying whatever section
    /// 8.1 code this connection took.
    /// </summary>
    /// <remarks>Best effort by construction: this runs on teardown paths, where the peer may
    /// already be gone and where a throw would replace the failure being reported.</remarks>
    private async ValueTask TryCloseAsync()
    {
        try
        {
            await _http3.CloseWithCurrentErrorAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
            // A connection that cannot say goodbye is still a closed connection.
        }
    }

    /// <summary>
    /// Turns one <c>TryOpenRequest</c> refusal into the exception a TlsClient caller sees.
    /// </summary>
    /// <remarks>
    /// <para>THE EXCEPTION TYPE IS THE RETRY DECISION, so it is chosen per cause rather than
    /// per severity. <c>TlsSession.ShouldRetryException</c> retries an
    /// <see cref="IOException"/> and an <see cref="HttpRequestException"/> and never a
    /// <see cref="TlsHttpProtocolException"/>; <c>TlsConnectionPool</c> additionally evicts the
    /// connection on a <see cref="StaleHttpConnectionException"/>. So a refusal a FRESH
    /// CONNECTION WOULD ALSO GIVE must not be stale — retrying a 50 MB upload three times
    /// costs three QUIC handshakes and fails identically each time.</para>
    /// <para>All of them left the connection intact: every refusal here is decided before
    /// <c>OpenBidirectional</c>, so no stream ordinal was spent and no octet reached the wire.
    /// That is what lets the two terminal arms be stream-scoped.</para>
    /// </remarks>
    internal static Exception Describe(
        TlsQuicHttp3RequestRefusal refusal,
        TlsQuicHttp3RequestError malformed,
        ulong streamCredit,
        ulong initialMaxData,
        ulong remainingConnectionData,
        ulong connectionErrorCode) => refusal switch
        {
            TlsQuicHttp3RequestRefusal.Malformed => Malformed(malformed),
            // Nothing was written and no ordinal was spent, so the same request on a fresh
            // connection is not a replay. StaleHttpConnectionException is what the pool and
            // the retry policy already read as "take another connection".
            TlsQuicHttp3RequestRefusal.GoawayReceived => new StaleHttpConnectionException(
                "The peer sent an HTTP/3 GOAWAY, so this request would not be processed."),
            TlsQuicHttp3RequestRefusal.PeerBidirectionalStreamsExhausted =>
                new StaleHttpConnectionException(
                    "The peer's initial_max_streams_bidi allowance is exhausted, so no " +
                    "further HTTP/3 request stream may be opened on this connection."),
            // TERMINAL, NOT STALE. This is the peer's initial_max_stream_data_bidi_remote,
            // which every stream on every connection to this peer starts with, so the next
            // connection refuses the same request for the same reason. SharpTls cannot wait
            // for the credit to grow either: its receive dispatch parses MAX_STREAM_DATA and
            // drops it, and TlsQuicPeerFlowControlBudget's per-stream budget says in its own
            // message that it is static. Naming the number is the only actionable thing left.
            TlsQuicHttp3RequestRefusal.PeerStreamCreditTooSmall =>
                new TlsHttpProtocolException(
                    "The HTTP/3 request does not fit in the peer's per-stream flow-control " +
                    $"credit: initial_max_stream_data_bidi_remote is {streamCredit} bytes and " +
                    "the encoded request — its HEADERS frame, its body and its trailers " +
                    "together — must fit inside that. SharpTls does not process " +
                    "MAX_STREAM_DATA, so the credit never grows and no retry can help. Send a " +
                    "smaller body, or send this request over HTTP/2 or HTTP/1.1.")
                {
                    IsStreamScoped = true,
                },
            // STALE, AND THAT IS THE DIFFERENCE FROM THE ARM ABOVE. This is the connection's
            // shared pool, which OpenLocalStreams and every earlier request on THIS connection
            // have already drawn down; SharpTls processes no MAX_DATA either, so the pool never
            // refills — but a fresh connection starts with the whole of initial_max_data, so
            // taking another connection is the fix here and is not the fix above.
            TlsQuicHttp3RequestRefusal.PeerConnectionCreditTooSmall =>
                new StaleHttpConnectionException(
                    "The HTTP/3 request does not fit in what is left of the peer's " +
                    $"connection-level flow-control credit: {remainingConnectionData} of " +
                    $"initial_max_data's {initialMaxData} bytes remain on this connection, " +
                    "and SharpTls processes no MAX_DATA to refill them. A fresh connection " +
                    "starts with the whole allowance."),
            TlsQuicHttp3RequestRefusal.ConnectionErrored => new StaleHttpConnectionException(
                "The HTTP/3 connection took error code " +
                $"0x{connectionErrorCode:x} and accepts no further requests."),
            TlsQuicHttp3RequestRefusal.FieldSectionTooLargeForPeer => new HttpRequestException(
                "The HTTP/3 request field section exceeds the peer's advertised " +
                "SETTINGS_MAX_FIELD_SECTION_SIZE."),
            _ => new TlsHttpProtocolException(
                $"The HTTP/3 request was refused ({refusal})."),
        };

    /// <summary>
    /// Names the RFC 9114 rule a locally refused request broke.
    /// </summary>
    /// <remarks>Two of the members are not field-section faults at all and would be misreported
    /// by the general message: a content-length that disagrees with the body is section 4.1.2's
    /// rule about the MESSAGE, and a pseudo-header in a trailer section is section 4.3's rule
    /// about WHERE a field may appear. Every one of them is decided before a byte is
    /// encoded onto the wire.</remarks>
    private static TlsHttpProtocolException Malformed(
        TlsQuicHttp3RequestError error) => error switch
    {
        // UNCONDITIONAL FOR A REQUEST. Section 4.1.2's "a response defined as never having
        // content" escape that TlsQuicHttp3Response applies is a RESPONSE rule; nothing
        // exempts a request's content-length from agreeing with its body.
        TlsQuicHttp3RequestError.ContentLengthDisagreesWithBody =>
            new TlsHttpProtocolException(
                "The HTTP/3 request declares a content-length that disagrees with the number " +
                "of body octets it carries (RFC 9114 section 4.1.2). It was refused before " +
                "any of it reached the wire.")
            {
                IsStreamScoped = true,
            },
        TlsQuicHttp3RequestError.PseudoHeaderInTrailerSection =>
            new TlsHttpProtocolException(
                "An HTTP/3 request trailer names a pseudo-header, which RFC 9114 section 4.3 " +
                "permits only in a header section.")
            {
                IsStreamScoped = true,
            },
        _ => new TlsHttpProtocolException(
            "The HTTP/3 request field section is malformed " +
            $"(RFC 9114 section 4.2/4.3.1: {error}).")
        {
            IsStreamScoped = true,
        },
    };

    private static CustomTlsQuicClient CreateTlsClient(
        Uri origin,
        TlsSessionConfiguration configuration,
        TlsQuicClientHelloProfileFactory factory,
        ReadOnlyMemory<byte> sourceConnectionId)
    {
        var options = new CustomTlsQuicClientOptions
        {
            ServerName = origin.IdnHost,
            ServerPort = origin.Port,
            ClientHello = factory.Create(sourceConnectionId.Span),
        };
        options.CertificateValidation.DangerouslySkipServerCertificateValidation =
            configuration.DangerouslySkipServerCertificateValidation;
        // Revocation is off for the reason SharpTls's own live run records: an OCSP fetch
        // happens inside the pump loop, between two datagrams, and a several-second fetch
        // would spend the connection's deadline and be recorded as packet loss. Chain and
        // hostname validation stay on.
        options.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
        ApplyCertificatePins(options.CertificateValidation, configuration.CertificatePins);
        return new CustomTlsQuicClient(options);
    }

    /// <summary>
    /// Wires configured certificate pinning into the QUIC handshake.
    /// </summary>
    /// <remarks>Duplicated from <c>SharpTlsTransport</c> rather than shared because that
    /// method takes <c>CustomTlsClientOptions</c> and this path has
    /// <c>CustomTlsQuicClientOptions</c>; the validation options themselves are the same type.
    /// Not skipped: silently dropping a pin on one version is a downgrade the caller asked
    /// against.</remarks>
    private static void ApplyCertificatePins(
        CustomTlsCertificateValidationOptions validation,
        TlsCertificatePins pins)
    {
        if (!pins.HasPins)
        {
            return;
        }
        var existing = validation.EvidenceValidator;
        validation.EvidenceValidator = async (evidence, cancellationToken) =>
        {
            var result = existing is null
                ? new TlsServerCertificateEvidenceValidationResult(
                    TlsStapledOcspValidationStatus.NotChecked,
                    0)
                : await existing(evidence, cancellationToken).ConfigureAwait(false);
            pins.Validate(evidence);
            return result;
        };
    }

    private static TlsConnectionInfo BuildTlsInfo(
        TlsSessionConfiguration configuration,
        CustomTlsQuicClient client) =>
        new(
            configuration.Profile.Name,
            // QUIC is TLS 1.3 by definition — RFC 9001 section 4.2 forbids anything older —
            // and CustomTlsQuicClient exposes no negotiated version to read instead.
            TlsProtocolVersion.Tls13,
            client.NegotiatedCipherSuite ?? default,
            client.NegotiatedGroup ?? default,
            client.NegotiatedApplicationProtocol,
            client.SessionWasResumed,
            client.HandshakeUsedHelloRetryRequest,
            client.EncryptedClientHelloAccepted,
            client.PeerCertificateChain);

    private static TimeSpan HandshakeTimeout(TlsSessionConfiguration configuration) =>
        configuration.Timeout > TimeSpan.Zero && configuration.Timeout < DefaultHandshakeTimeout
            ? configuration.Timeout
            : DefaultHandshakeTimeout;

    /// <summary>Reads a configured duration that QUIC needs to be finite and positive.</summary>
    /// <remarks><c>Timeout.InfiniteTimeSpan</c> is a legal value for both pool settings and is
    /// not a legal QUIC deadline, so it falls back rather than throwing.</remarks>
    private static TimeSpan Bounded(TimeSpan configured, TimeSpan fallback) =>
        configured > TimeSpan.Zero && configured < TimeSpan.MaxValue ? configured : fallback;
}
