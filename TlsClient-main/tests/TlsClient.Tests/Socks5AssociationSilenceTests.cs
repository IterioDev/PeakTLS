using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>
/// Pins that an RFC 1928 section 7 UDP association which relays the QUIC handshake and then goes
/// silent is reported as exactly that, recovered from, and never confused with a slow origin.
/// </summary>
/// <remarks>
/// <para>A DIFFERENT FAILURE FROM THE ONE <see cref="Socks5AssociationRetryTests"/> COVERS, AND
/// THE PROOF IS THAT THE RE-ASSOCIATION THERE FIRES ZERO TIMES AGAINST IT. That fix re-dials
/// only an association whose <c>RelayedNothing</c> is true; the field stalls — about five per
/// hundred and nine dials, always the FIRST request to a new host — all took the
/// <c>!RelayedNothing</c> branch, so every failing association had already carried at least one
/// inbound datagram. The association sets up, relays the handshake, <c>ConnectAsync</c> returns,
/// the connection is pooled, and then the first request gets nothing at all and dies on the
/// connection's own receive deadline with every QUIC counter at zero.</para>
/// <para>THE CONNECTION IS ASSEMBLED RATHER THAN DIALLED, WHICH IS THE ONLY WAY THIS IS
/// CHECKABLE OFFLINE. The assembly has no QUIC server, so no dial in
/// <see cref="Socks5AssociationRetryTests"/> can ever reach a request — every claim in that file
/// is about what the client did BEFORE the handshake. What is under test here is what happens
/// AFTER one, so the QUIC and HTTP/3 halves come in through <c>IHttp3Streams</c>, the seam that
/// already exists for exactly this reason, while the RELAY is real: a genuine
/// <c>TlsQuicSocks5Transport</c> over a genuine RFC 1928 setup exchange, with genuine datagrams
/// moving its counters. The measurement under test is that transport's, so faking it would be
/// faking the answer.</para>
/// </remarks>
public sealed class Socks5AssociationSilenceTests
{
    /// <summary>Every wait in this file. Long enough that a loaded agent does not trip it, short
    /// enough that a genuine deadlock fails the run rather than hanging it.</summary>
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);

    /// <summary>The silence deadline every test here configures. Two orders of magnitude under
    /// the two-second default, because loopback needs no headroom and a file that spends the
    /// default on every case is a file nobody runs.</summary>
    private static readonly TimeSpan Silence = TimeSpan.FromMilliseconds(250);

    private static readonly Uri Origin = new("https://origin.example/first");

    private readonly ConcurrentQueue<TlsConnectEvent> _events = [];

#pragma warning disable TLSCLIENT3 // Exercising the experimental policy is the point of the file.
    private const TlsHttpVersionPolicy Http3Only = TlsHttpVersionPolicy.Http3Only;
#pragma warning restore TLSCLIENT3

    // ------------------------------------------------------------------------------
    // The named failure.
    // ------------------------------------------------------------------------------

    /// <summary>
    /// THE CENTRAL CLAIM. A relay that answers the handshake and then stops must produce a
    /// failure that says the association went silent, not a bare timeout.
    /// </summary>
    [Fact]
    public async Task ARelayThatAnswersTheHandshakeAndThenStops_IsNamedRatherThanTimedOut()
    {
        await using var server = Socks5SetupServer.Start(relayFromAssociate: 1);
        var relay = await AssociateAsync(server, "session-a");
        // The handshake burst, in the only form this assembly can produce one: a datagram out
        // and its echo back, which is what a working association looks like from this side. The
        // baseline the watch takes below is therefore NON-ZERO, exactly as it is in the field,
        // so nothing here can pass by way of the setup-phase "never relayed at all" case.
        await RelayOneAsync(relay);
        await using var connection = Connect(relay, new SilentHttp3Streams());

        var failure = await Assert
            .ThrowsAsync<StaleHttpConnectionException>(() => SendAsync(connection, null, default))
            .WaitAsync(Bound);

        Assert.Contains(
            "relayed the HTTP/3 (QUIC) handshake and then stopped",
            failure.Message,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(TlsQuicOptions.AssociationSilenceDeadline),
            failure.Message,
            StringComparison.Ordinal);
        // DropSummary's all-zero form is the positive statement that nothing reached the socket
        // at all, which is the finding rather than decoration.
        Assert.Contains("SOCKS5 relay drops: 0", failure.Message, StringComparison.Ordinal);

        // The event is what a tester counts a run off, and it must carry the whole silence and
        // not just this request's share of it.
        var silence = Assert.Single(Silences);
        Assert.Equal(Origin.IdnHost, silence.Host);
        Assert.Same(failure, silence.Exception);
        Assert.True(silence.Elapsed >= Silence);
    }

    /// <summary>
    /// THE GUARD THAT MATTERS MOST, because the reason the setup-phase fix could be trusted is
    /// that its trigger was too narrow to fire on anything else. A connection that has received
    /// ANYTHING since its handshake is never flagged, however long its request waits.
    /// </summary>
    [Fact]
    public async Task AConnectionThatHasReceivedAnythingSinceTheHandshake_IsNeverFlagged()
    {
        await using var server = Socks5SetupServer.Start(relayFromAssociate: 1);
        var relay = await AssociateAsync(server, "session-a");
        await RelayOneAsync(relay);
        await using var connection = Connect(relay, new SilentHttp3Streams());

        // ONE MORE DATAGRAM AFTER THE WATCH'S BASELINE WAS TAKEN, AND NOTHING ELSE. The request
        // below still gets no response and still waits many times the deadline. If the trigger
        // were "the request was slow" rather than "the association has relayed nothing since the
        // handshake", this is the case that would wrongly retire a live but unhurried origin.
        await RelayOneAsync(relay);

        using var caller = new CancellationTokenSource(Silence * 8);
        await Assert
            .ThrowsAnyAsync<OperationCanceledException>(() => SendAsync(connection, null, caller.Token))
            .WaitAsync(Bound);

        Assert.Empty(Silences);
    }

    /// <summary>
    /// A DIRECT DIAL HAS NO ASSOCIATION TO BE REAPED, so nothing about it is bounded by a knob
    /// that exists for proxies. Its request waits exactly as long as it always did.
    /// </summary>
    [Fact]
    public async Task ADirectConnection_IsEntirelyUnaffected()
    {
        await using var connection = Connect(
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork),
            new SilentHttp3Streams(),
            relay: null);

        using var caller = new CancellationTokenSource(Silence * 8);
        await Assert
            .ThrowsAnyAsync<OperationCanceledException>(() => SendAsync(connection, null, caller.Token))
            .WaitAsync(Bound);

        // Not one event of any kind: both of these are proxy-only measurements.
        Assert.Empty(_events);
    }

    // ------------------------------------------------------------------------------
    // Recovery.
    // ------------------------------------------------------------------------------

    /// <summary>
    /// THE DELIVERABLE. The failure's SHAPE is what makes the stall disappear: an
    /// <see cref="IOException"/> that <c>TlsSession.ShouldRetryException</c> retries, and a
    /// <c>StaleHttpConnectionException</c> that <c>TlsConnectionPool.SendCoreAsync</c> evicts
    /// on, so the retry cannot be handed the same dead association back.
    /// </summary>
    /// <remarks>THE SECOND ATTEMPT REACHING A FRESH ASSOCIATION IS THE ASSERTION, and it is
    /// counted at the proxy: two RFC 1928 ASSOCIATEs arrived, and the response came back over
    /// the connection built on the second. A retry that reused the first association would leave
    /// that count at one and stall exactly as the field does.</remarks>
    [Fact]
    public async Task TheFailureShape_MakesTheSessionRedialOntoAFreshAssociation()
    {
        await using var server = Socks5SetupServer.Start(relayFromAssociate: 1);
        var dials = 0;
        var options = new TlsSessionOptions
        {
            HttpVersionPolicy = Http3Only,
            ConnectObserver = _events.Enqueue,
        };
        options.Quic.AssociationSilenceDeadline = Silence;

        await using var session = new TlsSession(options, async (origin, _, _, _) =>
        {
            var relay = await AssociateAsync(server, "session-a");
            await RelayOneAsync(relay);
            // The first connection's relay goes silent after its handshake; the second's
            // answers. Which one a request lands on is decided by the pool and the retry
            // policy, which is the thing under test.
            var answers = Interlocked.Increment(ref dials) > 1;
            return Connect(
                relay,
                new SilentHttp3Streams { AnswersRequests = answers },
                relay,
                origin);
        });

        var response = await session.GetAsync(Origin).WaitAsync(Bound);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // TWO ASSOCIATIONS AT THE PROXY, not two requests over one. This is the whole claim.
        Assert.Equal(2, server.AssociateCount);
        Assert.Single(Silences);
        // One gap per connection and two connections, under two identities: neither event can
        // be a duplicate of the other's.
        Assert.Equal(2, FirstRequests.Length);
        Assert.Equal(2, FirstRequests.Select(gap => gap.ConnectionId).Distinct().Count());
    }

    // ------------------------------------------------------------------------------
    // The gap.
    // ------------------------------------------------------------------------------

    /// <summary>
    /// THE MEASUREMENT THAT MAY BE THE WHOLE ANSWER. An idle-reaping proxy explains "only the
    /// first request to a new host" exactly, and the window it would reap in — handshake done,
    /// connection pooled, nothing sent — was invisible until this event existed.
    /// </summary>
    [Fact]
    public async Task TheHandshakeToFirstRequestGap_IsReported()
    {
        await using var server = Socks5SetupServer.Start(relayFromAssociate: 1);
        var relay = await AssociateAsync(server, "session-a");
        await RelayOneAsync(relay);
        await using var connection = Connect(relay, new SilentHttp3Streams());

        // The dialled-then-pooled-then-used shape, compressed. The idle window is what the event
        // has to carry, and nothing else on the record shows it.
        var idle = Silence * 2;
        await Task.Delay(idle);
        using var caller = new CancellationTokenSource(Silence * 8);
        await Assert
            .ThrowsAnyAsync<Exception>(() => SendAsync(connection, null, caller.Token))
            .WaitAsync(Bound);

        var gap = Assert.Single(FirstRequests);
        Assert.True(
            gap.Elapsed >= idle,
            $"the reported gap was {gap.Elapsed}, under the {idle} the connection provably sat " +
            "idle, so it is measuring something other than the window");
        // Nothing arrived during the window, which is the ORDINARY state — the read loop sends
        // nothing ack-eliciting between requests (RFC 9000 section 10.1) — and is precisely the
        // state an idle-reaping proxy needs to discard the association.
        Assert.Equal(0, gap.AddressCount);
        Assert.Equal(Origin.IdnHost, gap.Host);
        Assert.Equal(Origin.Port, gap.Port);
    }

    /// <summary>
    /// ONCE PER CONNECTION, because the question is about the FIRST request. A later request on
    /// a pooled connection measures a different window and is not what the field failure selects
    /// for.
    /// </summary>
    [Fact]
    public async Task TheGap_IsReportedOncePerConnectionAndNotPerRequest()
    {
        await using var server = Socks5SetupServer.Start(relayFromAssociate: 1);
        var relay = await AssociateAsync(server, "session-a");
        await RelayOneAsync(relay);
        await using var connection = Connect(
            relay,
            new SilentHttp3Streams { AnswersRequests = true });

        await SendAsync(connection, null, default).WaitAsync(Bound);
        await SendAsync(connection, null, default).WaitAsync(Bound);

        Assert.Single(FirstRequests);
    }

    // ------------------------------------------------------------------------------
    // The knob.
    // ------------------------------------------------------------------------------

    [Fact]
    public void TheDefaultSilenceDeadline_IsTwoSeconds() => Assert.Equal(
        TimeSpan.FromSeconds(2),
        new TlsSessionOptions().Quic.AssociationSilenceDeadline);

    [Fact]
    public void ANonPositiveSilenceDeadline_IsRefused()
    {
        // Zero would fail every proxied request the instant it waited at all: a request that has
        // not yet been answered is by definition one whose association has relayed nothing since
        // the handshake.
        var options = new TlsSessionOptions();
        options.Quic.AssociationSilenceDeadline = TimeSpan.Zero;

        var error = Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
        Assert.Equal(nameof(TlsQuicOptions.AssociationSilenceDeadline), error.ParamName);
    }

    [Fact]
    public async Task AnInfiniteSilenceDeadline_LeavesASilentAssociationUndetected()
    {
        // The behaviour that predates the knob, spelled explicitly: "never judge an association
        // reaped". Accepted rather than refused, unlike zero.
        await using var server = Socks5SetupServer.Start(relayFromAssociate: 1);
        var relay = await AssociateAsync(server, "session-a");
        await RelayOneAsync(relay);
        await using var connection = Connect(relay, new SilentHttp3Streams());

        using var caller = new CancellationTokenSource(Silence * 8);
        await Assert
            .ThrowsAnyAsync<OperationCanceledException>(
                () => SendAsync(connection, Timeout.InfiniteTimeSpan, caller.Token))
            .WaitAsync(Bound);

        Assert.Empty(Silences);
    }

    // ------------------------------------------------------------------------------
    // Harness.
    // ------------------------------------------------------------------------------

    private TlsConnectEvent[] FirstRequests => [.. _events.Where(
        connectEvent =>
            connectEvent.Kind == TlsConnectEventKind.Socks5AssociationFirstRequest)];

    private TlsConnectEvent[] Silences => [.. _events.Where(
        connectEvent =>
            connectEvent.Kind == TlsConnectEventKind.Socks5AssociationWentSilent)];

    /// <summary>Opens one real RFC 1928 section 7 association against the double.</summary>
    private static async Task<Socks5LivenessTransport> AssociateAsync(
        Socks5SetupServer server,
        string session) => new(await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options
            {
                ProxyEndPoint = new DnsEndPoint(
                    server.ProxyEndPoint.Address.ToString(),
                    server.ProxyEndPoint.Port),
                Username = session,
                Password = "password",
                DestinationHost = Origin.IdnHost,
            },
            CancellationToken.None).WaitAsync(Bound));

    /// <summary>
    /// Moves one datagram through the association and back, which is what "the relay carried the
    /// handshake" looks like from this side.
    /// </summary>
    /// <remarks>The double's live relay echoes, so what comes back still carries the RFC 1928
    /// section 7 header this transport wrote and decapsulates cleanly. What it CONTAINS is
    /// irrelevant: the counters under test move on arrival, not on usefulness.</remarks>
    private static async Task RelayOneAsync(Socks5LivenessTransport relay)
    {
        await relay
            .SendAsync(new IPEndPoint(IPAddress.Loopback, 443), new byte[] { 1, 2, 3 }, default)
            .AsTask()
            .WaitAsync(Bound);
        var buffer = new byte[2048];
        await relay.ReceiveAsync(buffer, default).AsTask().WaitAsync(Bound);
    }

    /// <summary>Assembles one started connection over a real relay and a fake stream layer.
    /// </summary>
    private static Http3Connection Connect(
        ITlsQuicDatagramTransport transport,
        IHttp3Streams streams,
        Socks5LivenessTransport? relay = null,
        Uri? origin = null)
    {
        origin ??= Origin;
        relay ??= transport as Socks5LivenessTransport;
        var connection = new Http3Connection(
            transport,
            streams,
            relay is null
                ? null
                : new Socks5AssociationWatch(
                    relay,
                    Guid.NewGuid(),
                    origin.IdnHost,
                    origin.Port),
            new TlsConnectionInfo(
                "witness",
                TlsProtocolVersion.Tls13,
                default,
                default,
                "h3",
                false,
                false,
                false,
                []),
            requestStreamAllowance: 100,
            idleBudget: null);
        connection.Start();
        return connection;
    }

    private Task<ParsedHttpResponse> SendAsync(
        Http3Connection connection,
        TimeSpan? silence,
        CancellationToken cancellationToken)
    {
        var options = new TlsSessionOptions { ConnectObserver = _events.Enqueue };
        options.Quic.AssociationSilenceDeadline = silence ?? Silence;
        return connection.SendAsync(
            new BufferedRequest("GET", Origin, [], [], HasContent: false),
            null,
            options.Snapshot(),
            cancellationToken).AsTask();
    }

    /// <summary>
    /// An <see cref="IHttp3Streams"/> that either answers a request at once or never answers it
    /// at all, with a pump that parks the way a real one parks on a UDP receive.
    /// </summary>
    /// <remarks>PARKING IS THE POINT. A reaped association leaves the read loop inside a receive
    /// that never returns, so nothing ever signals <c>Http3StreamMultiplexer.Pumped</c> — which
    /// is precisely the state the silence guard has to tell apart from a slow response. A fake
    /// that RETURNED from its pump would signal it and the guard would never arm.</remarks>
    private sealed class SilentHttp3Streams : IHttp3Streams
    {
        private readonly Channel<ulong> _answers = Channel.CreateUnbounded<ulong>();
        private readonly Dictionary<ulong, bool> _finished = [];
        private readonly object _sync = new();
        private ulong _nextStreamId;

        /// <summary>Whether an opened stream is answered with a 200, or left forever silent.
        /// </summary>
        internal bool AnswersRequests { get; init; }

        public ulong ConnectionErrorCode => 0;

        public ulong? PeerGoawayStreamId => null;

        public ulong? TryOpenRequest(
            TlsQuicHttp3Request request,
            out TlsQuicHttp3RequestRefusal refusal,
            out TlsQuicHttp3RequestError malformed)
        {
            refusal = TlsQuicHttp3RequestRefusal.None;
            malformed = TlsQuicHttp3RequestError.None;
            lock (_sync)
            {
                var id = _nextStreamId;
                _nextStreamId += 4;
                _finished[id] = false;
                if (AnswersRequests)
                {
                    _answers.Writer.TryWrite(id);
                }
                return id;
            }
        }

        public ValueTask SendPendingAsync(CancellationToken cancellationToken) =>
            ValueTask.CompletedTask;

        public async ValueTask<bool> PumpOnceAsync(CancellationToken cancellationToken)
        {
            var id = await _answers.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            lock (_sync)
            {
                _finished[id] = true;
            }
            return true;
        }

        public Http3StreamSnapshot Peek(ulong streamId)
        {
            lock (_sync)
            {
                var done = _finished.TryGetValue(streamId, out var finished) && finished;
                return new Http3StreamSnapshot(
                    done ? 200 : -1,
                    done ? [new TlsQuicHttp3Field(":status", "200")] : [],
                    [],
                    0,
                    done,
                    done);
            }
        }

        public byte[] CopyBody(ulong streamId, int start, int end) => [];

        public Exception Describe(
            TlsQuicHttp3RequestRefusal refusal,
            TlsQuicHttp3RequestError malformed) =>
            new TlsHttpProtocolException($"refused: {refusal}");

        public ValueTask CloseWithCurrentErrorAsync() => ValueTask.CompletedTask;

        public ValueTask DisposeAsync()
        {
            _answers.Writer.TryComplete();
            return ValueTask.CompletedTask;
        }
    }
}
