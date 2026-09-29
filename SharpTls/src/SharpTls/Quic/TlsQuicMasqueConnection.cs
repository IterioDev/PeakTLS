using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Channels;

namespace SharpTls.Quic;

/// <summary>One outer HTTP/3 connection to a MASQUE proxy, carrying any number of RFC 9298
/// CONNECT-UDP tunnels at once: each tunnel is one request stream on it
/// (<see cref="TlsQuicMasqueTransport"/>), and RFC 9297 s2.1 routes the datagrams by quarter
/// stream id. Dial once per proxy session, then open a tunnel per inner connection, so a
/// session costs one outer handshake rather than one per inner dial. See
/// docs/MASQUE-DATAGRAM-TRANSPORT.md.</summary>
/// <remarks>ONE OWNER TASK DRIVES THE OUTER CONNECTION, and nothing else touches it after the
/// dial: an open or a tunnel close is posted to the owner as a command and the owner runs it
/// between pumps. A tunnel's send queues a payload and wakes the owner; the owner alone hands
/// payloads to the connection and unwraps what arrives.</remarks>
internal sealed class TlsQuicMasqueConnection : ITlsQuicMasqueConnection
{
    // RFC 9000 s14.1: "A client MUST expand the payload of all UDP datagrams carrying Initial
    // packets to at least the smallest allowed maximum datagram size of 1200 bytes". A tunnel
    // narrower than that cannot carry the inner connection's first flight at all.
    private const int InnerInitialSize = 1200;

    /// <summary>RFC 9114 s6.2: the unidirectional streams a peer must be allowed to open
    /// (control, QPACK encoder, QPACK decoder) before HTTP/3 can start.</summary>
    private const ulong Http3UnidirectionalStreams = 3;

    /// <summary>How far behind the outer connection's own handshake deadline the dial's backstop
    /// runs, so a stalled handshake is reported by the receiver (what it discarded and why)
    /// rather than by a bare cancellation.</summary>
    private static readonly TimeSpan DeadlineGrace = TimeSpan.FromSeconds(1);

    /// <summary>The length of the Context ID every tunnel writes: context 0 as a one-byte
    /// varint (RFC 9298 s4).</summary>
    internal const int ContextIdLength = 1;

    /// <summary>The outer QUIC connection; driven by the owner task only.</summary>
    private readonly TlsQuicConnection _connection;

    /// <summary>The HTTP/3 layer over <see cref="_connection"/>; driven by the owner task
    /// only.</summary>
    private readonly TlsQuicHttp3Connection _http3;

    /// <summary>The socket this connection opened, or <see langword="null"/> when the caller
    /// supplied <see cref="TlsQuicMasqueOptions.OuterTransport"/> and keeps ownership of
    /// it.</summary>
    private readonly ITlsQuicDatagramTransport? _ownedOuter;

    /// <summary>The outer transport as <see cref="_connection"/> reads it, so a writer can wake
    /// the owner's receive.</summary>
    private readonly WakeableTransport _wakeable;

    private readonly TlsQuicMasqueOptions _options;

    /// <summary>Live tunnels by request stream id. Owner task only.</summary>
    private readonly Dictionary<ulong, TlsQuicMasqueTransport> _tunnels = [];

    /// <summary>Opens whose CONNECT-UDP has left and whose response is awaited. Owner task
    /// only.</summary>
    private readonly List<PendingOpen> _opening = [];

    /// <summary>Work for the owner: an open, or a tunnel's close. Completed once the owner has
    /// exited; what was posted before that still runs, in the owner's last act.</summary>
    private readonly Channel<Action> _commands = Channel.CreateUnbounded<Action>(
        new UnboundedChannelOptions { SingleReader = true });

    /// <summary>Cancelled by <see cref="DisposeAsync"/>; ends the owner.</summary>
    private readonly CancellationTokenSource _lifetime = new();

    /// <summary>The owner task, which alone touches <see cref="_connection"/> and
    /// <see cref="_http3"/> between the dial and <see cref="DisposeAsync"/>.</summary>
    private Task? _owner;

    /// <summary>Why this connection ended, once it has: the outer's failure, or disposal.
    /// Every tunnel and every later open reports it.</summary>
    private TlsQuicProxyException? _ended;

    /// <summary>1 once <see cref="DisposeAsync"/> has started.</summary>
    private int _disposed;

    private int _tunnelCount;

    private int _tunnelsRequested;

    private TlsQuicMasqueConnection(
        TlsQuicConnection connection,
        TlsQuicHttp3Connection http3,
        WakeableTransport wakeable,
        ITlsQuicDatagramTransport? ownedOuter,
        TlsQuicMasqueOptions options)
    {
        _connection = connection;
        _http3 = http3;
        _wakeable = wakeable;
        _ownedOuter = ownedOuter;
        _options = options;
    }

    /// <summary>Whether the outer connection has ended, by failure or by disposal: every
    /// tunnel on it has failed and every later <see cref="OpenTunnelAsync"/> fails at once. A
    /// caller keeping one connection per proxy session dials a new one when it sees this.</summary>
    public bool IsClosed => Volatile.Read(ref _ended) is not null;

    /// <summary>Tunnels open right now.</summary>
    public int TunnelCount => Volatile.Read(ref _tunnelCount);

    /// <summary>Tunnels ever asked for, open or not: zero means a connection nothing has used
    /// yet.</summary>
    public int TunnelsRequested => Volatile.Read(ref _tunnelsRequested);

    /// <inheritdoc/>
    /// <remarks>Read off the owner's connection from another thread: a whole int, so the read
    /// is atomic, and a count one pump stale answers "did anything arrive" as well.</remarks>
    public int DatagramsReceived => _connection.DatagramsReceived;

    /// <summary>The outer connection's DATAGRAM frame payload, which every tunnel's ceiling is
    /// derived from.</summary>
    internal int MaximumDatagramFramePayload => _connection.MaximumDatagramFramePayload;

    /// <summary>Datagrams the HTTP/3 layer dropped for a stream nothing reads.</summary>
    internal ulong DroppedDatagramsWrongStream => _http3.DroppedDatagramsWrongStream;

    /// <summary>Dials the proxy and checks that it offers CONNECT-UDP; tunnels are opened on the
    /// result with <see cref="OpenTunnelAsync"/>.</summary>
    /// <remarks>
    /// <para>TWO STEPS UNDER ONE DEADLINE: the outer QUIC handshake, then the proxy's SETTINGS
    /// (RFC 8441 s3's SETTINGS_ENABLE_CONNECT_PROTOCOL as RFC 9220 carries it to HTTP/3, and
    /// RFC 9297 s2.1.1's SETTINGS_H3_DATAGRAM) plus RFC 9221 s3's max_datagram_frame_size.</para>
    /// <para>A REFUSED DIAL SAYS GOODBYE: an outer connection that got as far as HTTP/3 is
    /// closed with the RFC 9114 s8.1 code it recorded (H3_DATAGRAM_ERROR, say), or H3_NO_ERROR
    /// when it recorded none, before the exception leaves, so the proxy does not hold a
    /// half-open connection until its idle timeout.</para>
    /// </remarks>
    /// <param name="options">The proxy and the outer connection's shape.</param>
    /// <param name="cancellationToken">Cancels the dial.</param>
    /// <returns>The connected outer, ready for tunnels.</returns>
    /// <exception cref="TlsQuicProxyException">The proxy does not offer CONNECT-UDP, closed the
    /// outer connection, or no address of it completed the handshake within
    /// <see cref="TlsQuicMasqueOptions.HandshakeDeadline"/>.</exception>
    /// <exception cref="ArgumentException"><see cref="TlsQuicMasqueOptions.OuterSpec"/>
    /// advertises fewer than three unidirectional streams (initial_max_streams_uni), so the
    /// proxy could never open its control and QPACK streams (RFC 9114 s6.2).</exception>
    public static async Task<TlsQuicMasqueConnection> ConnectAsync(
        TlsQuicMasqueOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        // RFC 9114 s6.2: the proxy needs three unidirectional streams (control, QPACK encoder,
        // QPACK decoder) before it may send SETTINGS. An outer spec that advertises fewer - the
        // RFC-minimum parameter list advertises none - completes the handshake and then waits
        // out the deadline for a SETTINGS the proxy is not allowed to send. Refuse it by name.
        var advertised = options.OuterSpec.LocalFlowControl
            .AsAdvertisedBy(options.OuterSpec.TransportParameters);
        if (advertised.InitialMaxStreamsUni < Http3UnidirectionalStreams)
        {
            throw new ArgumentException(
                $"OuterSpec advertises initial_max_streams_uni = {advertised.InitialMaxStreamsUni}, "
                    + $"but HTTP/3 needs at least {Http3UnidirectionalStreams} (RFC 9114 s6.2) or the "
                    + "proxy can never open its control stream and send SETTINGS. Place the six "
                    + "flow-control parameters in OuterSpec.TransportParameters.",
                nameof(options));
        }

        // The outer connection's own HandshakeDeadline bounds step 1 and, when it fires, names
        // what the receiver discarded and why; this backstop runs a grace period behind it so
        // that report wins the race, and bounds DNS and step 2 on its own.
        var budget = options.HandshakeDeadline + DeadlineGrace;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(budget);
        var ct = deadline.Token;
        var stage = "resolving the proxy";

        ITlsQuicDatagramTransport? outer = null;
        TlsQuicConnection? connection = null;
        TlsQuicHttp3Connection? http3Owned = null;
        var unreachable = new List<string>();
        try
        {
            // Step 1: the outer QUIC connection, to the first address that answers. A proxy
            // name resolves to several addresses (a provider's front has five), and UDP has no
            // refusal to report: a dead one costs a whole HandshakeDeadline and says nothing.
            // So each address gets its own deadline, in resolver order, and the backstop is
            // re-armed to cover all of them. Step 2 runs once, against the address that
            // completed the handshake: what the proxy answers there is not an address problem.
            IReadOnlyList<IPEndPoint> candidates;
            if (options.OuterTransport is null)
            {
                candidates = await ResolveProxyAsync(options, ct).ConfigureAwait(false);
            }
            else
            {
                candidates = options.OuterRemoteEndPoints is { Count: > 0 } endPoints
                    ? endPoints
                    : throw new ArgumentException(
                        "OuterTransport needs at least one OuterRemoteEndPoints entry.",
                        nameof(options));
            }
            budget = options.HandshakeDeadline * candidates.Count + DeadlineGrace;
            deadline.CancelAfter(budget);

            var factory = new TlsQuicClientHelloProfileFactory
            {
                ConnectionSpec = options.OuterSpec,
                AlpnProtocols = [TlsQuicClientHelloProfileFactory.Http3AlpnToken],
                Tls = options.ConfigureOuterClientHello,
            };

            IPEndPoint proxy = candidates[0];
            WakeableTransport? wakeable = null;
            for (var index = 0; index < candidates.Count; index++)
            {
                proxy = candidates[index];
                outer = options.OuterTransport
                    ?? TlsQuicUdpDatagramTransport.Create(proxy.AddressFamily);

                // The connection reads through the wrapper for its whole life; nothing wakes
                // the dial's own pumps, so they read exactly as they would from the socket.
                wakeable = new WakeableTransport(outer, proxy);
                connection = new TlsQuicConnection(
                    new TlsQuicConnectionOptions(wakeable, proxy, options.OuterSpec)
                    {
                        HandshakeDeadline = options.HandshakeDeadline,
                    },
                    sourceConnectionId =>
                    {
                        // TlsClient's Http3Connection.CreateTlsClient, minus the session-level
                        // hooks a proxy dial has none of.
                        var client = new CustomTlsQuicClientOptions
                        {
                            ServerName = options.ProxyEndPoint.Host,
                            ServerPort = options.ProxyEndPoint.Port,
                            ClientHello = factory.Create(sourceConnectionId.Span),
                        };
                        client.CertificateValidation.DangerouslySkipServerCertificateValidation =
                            options.DangerouslySkipOuterCertificateValidation;

                        // An OCSP fetch inside the pump loop would spend the handshake deadline
                        // between two datagrams; chain and hostname validation stay on.
                        client.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                        return new CustomTlsQuicClient(client);
                    });
                stage = $"the outer QUIC handshake with {proxy}";
                try
                {
                    await connection.ConnectAsync(ct).ConfigureAwait(false);
                    break;
                }
                catch (Exception exception) when (
                    index < candidates.Count - 1
                        && !ct.IsCancellationRequested
                        && exception is TimeoutException or SocketException)
                {
                    // Silence or a socket error is what an unreachable address looks like; a
                    // proxy that answered and then refused is not, and is reported as is.
                    unreachable.Add($"{proxy} ({exception.GetType().Name})");
                    await connection.DisposeAsync().ConfigureAwait(false);
                    connection = null;
                    if (outer != options.OuterTransport)
                    {
                        await outer.DisposeAsync().ConfigureAwait(false);
                    }
                    outer = null;
                }
            }

            // The loop either broke out with a connected outer or let the last attempt's
            // exception through; the compiler cannot see that, so say it once.
            if (connection is null || wakeable is null || outer is null)
            {
                throw new UnreachableException("The address loop neither connected nor threw.");
            }

            // Step 2: the proxy must offer extended CONNECT and datagrams.
            stage = "waiting for the proxy's SETTINGS";
            var http3 = new TlsQuicHttp3Connection(connection, options.OuterHttp3Spec);
            http3Owned = http3;
            http3.OpenLocalStreams();
            await FlushAsync(connection, ct).ConfigureAwait(false);
            while (!http3.PeerSettingsReceived)
            {
                await PumpAndFlushAsync(connection, http3, ct).ConfigureAwait(false);
            }
            RequireSetting(
                http3,
                TlsQuicHttp3Spec.EnableConnectProtocolIdentifier,
                "SETTINGS_ENABLE_CONNECT_PROTOCOL");
            RequireSetting(http3, TlsQuicHttp3Spec.H3DatagramIdentifier, "SETTINGS_H3_DATAGRAM");
            if (connection.PeerMaxDatagramFrameSize is null)
            {
                throw new TlsQuicProxyException(
                    TlsQuicProxyError.MasqueNotOffered,
                    "The proxy's transport parameters carry no max_datagram_frame_size "
                        + "(RFC 9221 s3), so it accepts no DATAGRAM frames.");
            }

            // The floor, for the first tunnel: its stream id is 0, so the quarter stream id is
            // one byte. Later tunnels lose a byte more once the quarter stream id needs it.
            var capacity = connection.MaximumDatagramFramePayload - 1 - ContextIdLength;
            if (capacity < InnerInitialSize)
            {
                throw new TlsQuicProxyException(
                    TlsQuicProxyError.MasqueNotOffered,
                    $"A tunnel would carry at most {capacity} bytes per datagram, below the "
                        + $"{InnerInitialSize} an inner Initial needs (peer "
                        + $"max_datagram_frame_size {connection.PeerMaxDatagramFrameSize}).");
            }

            var result = new TlsQuicMasqueConnection(
                connection,
                http3,
                wakeable,
                outer == options.OuterTransport ? null : outer,
                options);
            result._owner = Task.Run(result.RunAsync);
            http3Owned = null;
            connection = null;
            outer = null;
            return result;
        }
        catch (Exception exception) when (
            (exception is OperationCanceledException
                && deadline.IsCancellationRequested
                && !cancellationToken.IsCancellationRequested)
            || exception is TimeoutException)
        {
            // The outer TlsQuicConnection's own HandshakeDeadline throws TimeoutException with
            // the receiver's discard report; the backstop throws OperationCanceledException.
            // TlsQuicProxyException has one constructor, (error, message); the cause rides in
            // the text.
            var earlier = unreachable.Count == 0
                ? string.Empty
                : $" Addresses tried before it and unreachable: {string.Join(", ", unreachable)}.";

            // No address of the remembered answer completed the dial, so the answer may be
            // what is stale: the next dial looks the name up again.
            ForgetProxyAddresses(options);
            throw new TlsQuicProxyException(
                TlsQuicProxyError.MasqueTunnelRefused,
                $"The MASQUE proxy connection did not come up within {budget} during {stage} "
                    + $"({exception.GetType().Name}: {exception.Message}).{earlier}");
        }
        catch (InvalidOperationException exception)
        {
            // The outer connection refusing to go on: a proxy that closed it mid-dial leaves it
            // draining, and the next send says so (RFC 9000 s10.2).
            throw Closed(exception);
        }
        finally
        {
            // A refused dial says goodbye: the proxy should not hold a half-open connection
            // until its idle timeout. The close carries the s8.1 code the HTTP/3 layer recorded,
            // or H3_NO_ERROR if it recorded none. Best effort, never a second exception.
            if (http3Owned is not null)
            {
                try
                {
                    await http3Owned.CloseWithCurrentErrorAsync(CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // The close is a courtesy; the dial's own failure is the one reported.
                }
            }
            if (connection is not null)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }
            if (outer is not null && outer != options.OuterTransport)
            {
                await outer.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>One lookup of a proxy name, shared by every dial in the process until it
    /// expires, and the counter that spreads those dials over its addresses.</summary>
    private sealed class ResolvedProxy(Task<IReadOnlyList<IPAddress>> lookup)
    {
        public Task<IReadOnlyList<IPAddress>> Lookup { get; } = lookup;

        public long StartedAt { get; } = Stopwatch.GetTimestamp();

        public int Dials;
    }

    /// <summary>Lookups by proxy name and resolver, for the whole process: a proxy session is a
    /// credential, not a name, so two hundred sessions dialling one provider resolve one name.
    /// </summary>
    private static readonly Dictionary<(string Host, Delegate? Resolver), ResolvedProxy> ResolvedProxies =
        [];

    /// <summary>The proxy's addresses for one dial: from the lookup every dial shares within
    /// <see cref="TlsQuicMasqueOptions.ProxyAddressLifetime"/>, rotated so that consecutive
    /// dials lead with different addresses and each still has all of them to fall through.
    /// </summary>
    /// <remarks>The lookup runs under no caller's token: a caller that gives up leaves a lookup
    /// the next caller finds finished. A lookup that fails, or answers with no address, is
    /// reported to everyone waiting on it and not kept.</remarks>
    /// <param name="options">The proxy, its resolver and the lifetime.</param>
    /// <param name="cancellationToken">Cancels this caller's wait.</param>
    /// <returns>The endpoints to try, in order.</returns>
    /// <exception cref="TlsQuicProxyException">The name resolved to no address.</exception>
    internal static async Task<IReadOnlyList<IPEndPoint>> ResolveProxyAsync(
        TlsQuicMasqueOptions options, CancellationToken cancellationToken)
    {
        var host = options.ProxyEndPoint.Host;
        var key = (host.ToUpperInvariant(), (Delegate?)options.ProxyResolver);
        ResolvedProxy resolved;
        lock (ResolvedProxies)
        {
            if (!ResolvedProxies.TryGetValue(key, out resolved!) || IsExpired(resolved, options))
            {
                resolved = new ResolvedProxy(LookUpAsync(options));
                ResolvedProxies[key] = resolved;
            }
        }

        IReadOnlyList<IPAddress> addresses;
        try
        {
            addresses = await resolved.Lookup.WaitAsync(cancellationToken).ConfigureAwait(false);
            if (addresses.Count == 0)
            {
                throw new TlsQuicProxyException(
                    TlsQuicProxyError.MasqueTunnelRefused, $"'{host}' resolved to no address.");
            }
        }
        catch (Exception) when (resolved.Lookup.IsCompleted)
        {
            Forget(key, resolved);
            throw;
        }

        var first = (Interlocked.Increment(ref resolved.Dials) - 1) % addresses.Count;
        var endPoints = new IPEndPoint[addresses.Count];
        for (var index = 0; index < endPoints.Length; index++)
        {
            endPoints[index] = new IPEndPoint(
                addresses[(first + index) % addresses.Count], options.ProxyEndPoint.Port);
        }
        return endPoints;
    }

    /// <summary>Drops the remembered lookup of the proxy name, so the next dial makes its own.
    /// </summary>
    /// <param name="options">The proxy and its resolver.</param>
    internal static void ForgetProxyAddresses(TlsQuicMasqueOptions options)
    {
        lock (ResolvedProxies)
        {
            ResolvedProxies.Remove(
                (options.ProxyEndPoint.Host.ToUpperInvariant(), options.ProxyResolver));
        }
    }

    private static void Forget((string Host, Delegate? Resolver) key, ResolvedProxy resolved)
    {
        lock (ResolvedProxies)
        {
            if (ResolvedProxies.TryGetValue(key, out var current) && ReferenceEquals(current, resolved))
            {
                ResolvedProxies.Remove(key);
            }
        }
    }

    private static bool IsExpired(ResolvedProxy resolved, TlsQuicMasqueOptions options) =>
        resolved.Lookup.IsFaulted
            || resolved.Lookup.IsCanceled
            || (options.ProxyAddressLifetime != Timeout.InfiniteTimeSpan
                && Stopwatch.GetElapsedTime(resolved.StartedAt) >= options.ProxyAddressLifetime);

    private static async Task<IReadOnlyList<IPAddress>> LookUpAsync(TlsQuicMasqueOptions options)
    {
        if (options.ProxyResolver is { } resolver)
        {
            return await resolver(options.ProxyEndPoint.Host, CancellationToken.None)
                .ConfigureAwait(false);
        }
        return await System.Net.Dns
            .GetHostAddressesAsync(options.ProxyEndPoint.Host, CancellationToken.None)
            .ConfigureAwait(false);
    }

    /// <summary>Opens one CONNECT-UDP tunnel to a target (RFC 9298 s3) and returns it once any
    /// 2xx answer arrives.</summary>
    /// <remarks>The request goes out on the owner's next turn and the answer is awaited under
    /// <see cref="TlsQuicMasqueOptions.HandshakeDeadline"/>. An open abandoned at the deadline
    /// has its request stream ended when the proxy answers, so the tunnel never stays open on
    /// the proxy's side for nobody.</remarks>
    /// <param name="targetHost">The target, written into the RFC 9298 s2 URI template.</param>
    /// <param name="targetPort">The target UDP port, written into the template.</param>
    /// <param name="targetEndPoint">Echoed in every receive result; the inner connection never
    /// compares it.</param>
    /// <param name="cancellationToken">Cancels the open.</param>
    /// <returns>The tunnel.</returns>
    /// <exception cref="TlsQuicProxyException">The proxy refused the request, reset it, ended
    /// the outer connection, the connection had already ended, or no answer came within the
    /// deadline.</exception>
    public async Task<TlsQuicMasqueTransport> OpenTunnelAsync(
        string targetHost, int targetPort, IPEndPoint targetEndPoint, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(targetHost);
        ArgumentNullException.ThrowIfNull(targetEndPoint);
        Interlocked.Increment(ref _tunnelsRequested);

        var open = new PendingOpen(targetHost, targetPort, targetEndPoint);
        if (Volatile.Read(ref _ended) is { } ended || !_commands.Writer.TryWrite(() => BeginOpen(open)))
        {
            throw Volatile.Read(ref _ended) ?? Disposed();
        }
        _wakeable.Wake();

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_options.HandshakeDeadline);
        try
        {
            return await open.Answer.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            // Whichever side wins: an answer that arrives after this is a tunnel nobody waits
            // for, which the owner ends on the proxy's side too (see TryFinishOpen).
            if (!open.Answer.TrySetCanceled() && open.Answer.Task.IsCompletedSuccessfully)
            {
                await open.Answer.Task.Result.DisposeAsync().ConfigureAwait(false);
            }
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            throw new TlsQuicProxyException(
                TlsQuicProxyError.MasqueTunnelRefused,
                $"The MASQUE tunnel to {targetHost}:{targetPort} did not come up within "
                    + $"{_options.HandshakeDeadline} waiting for the CONNECT-UDP response.");
        }
    }

    /// <summary>Wakes the owner: a tunnel queued a payload.</summary>
    internal void Wake() => _wakeable.Wake();

    /// <summary>A tunnel has been disposed: the owner ends its request stream (RFC 9298 s3.4)
    /// and forgets it. Nothing to do on a connection that has already ended.</summary>
    /// <param name="tunnel">The tunnel.</param>
    internal void CloseTunnel(TlsQuicMasqueTransport tunnel)
    {
        if (_commands.Writer.TryWrite(() => EndTunnel(tunnel)))
        {
            _wakeable.Wake();
        }
    }

    /// <summary>Ends the connection: fails every tunnel and pending open with
    /// <see cref="TlsQuicProxyError.MasqueTunnelClosed"/>, stops the owner, and closes the
    /// outer with the RFC 9114 s8.1 code the HTTP/3 layer recorded (H3_NO_ERROR if none).
    /// Idempotent.</summary>
    /// <remarks>An outer transport the caller supplied through
    /// <see cref="TlsQuicMasqueOptions.OuterTransport"/> stays the caller's to dispose.
    /// </remarks>
    /// <returns>A task that completes once the outer connection is closed.</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Interlocked.CompareExchange(ref _ended, Disposed(), null);
        _lifetime.Cancel();
        if (_owner is { } owner)
        {
            try
            {
                await owner.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // RunAsync catches everything; nothing reaches here.
            }
        }

        // Only now: the owner has exited, so nothing else is driving the connection or holding
        // its tunnel table. A connection that took an HTTP/3 connection error (H3_DATAGRAM_ERROR,
        // say) tells the proxy so; a healthy one closes with H3_NO_ERROR.
        FailAll(_ended!);
        try
        {
            await _http3.CloseWithCurrentErrorAsync(CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The close is a courtesy to the proxy; a connection that already failed or
            // drained has nothing left to say.
        }
        await _connection.DisposeAsync().ConfigureAwait(false);
        if (_ownedOuter is not null)
        {
            await _ownedOuter.DisposeAsync().ConfigureAwait(false);
        }
        _lifetime.Dispose();
    }

    /// <summary>The owner loop: the only code that drives the outer connection once it is up.
    /// Runs what was posted, sends everything every tunnel queued, pumps one datagram, answers
    /// pending opens, and hands each tunnel what arrived for it.</summary>
    /// <remarks>
    /// <para>OUTBOUND FIRST, AND ALL OF IT: SendPendingAsync builds one 1-RTT packet per call
    /// and the send path puts one DATAGRAM frame per packet, so one call per iteration would
    /// trickle an inner Initial flight at one datagram per proxy packet or timer. Refill the
    /// connection's queue from every tunnel, send, repeat until a send builds nothing (window
    /// shut or queues empty); a bounded loop, never a hot one. A payload the full queue refuses
    /// waits in its tunnel so that tunnel's order survives.</para>
    /// <para>THE PUMP BLOCKS UNTIL THE PROXY SENDS OR A TIMER FIRES, and a writer wakes the
    /// socket receive inside it through <see cref="WakeableTransport.Wake"/>, never the pump
    /// itself. The woken receive returns an empty datagram, TlsQuicConnection's own wake-up
    /// (ReceiveWithinDeadlineAsync returns one when a recovery, pacing or delayed-ACK deadline
    /// falls due): no packet is read, PumpOnceAsync still runs its send pass, and the HTTP/3
    /// pump still reaches TryProcess. A cancelled pump token would reach whatever the pump was
    /// doing when the writer ran, including an answer whose DATAGRAM was already dequeued and
    /// recorded as sent before the socket write threw: a payload lost, and a loss later
    /// declared for a packet that never left. So the pump's token is the lifetime's
    /// alone.</para>
    /// <para>ANY FAILURE OF THE OUTER ENDS EVERY TUNNEL: each one's channels complete with a
    /// <see cref="TlsQuicProxyError.MasqueTunnelClosed"/> naming the cause, which its next send
    /// or receive throws; a tunnel of its own ending (the proxy resetting or ending its stream,
    /// a TLS alert through it) ends that tunnel alone.</para>
    /// </remarks>
    /// <returns>A task that completes when the connection ends; it never faults.</returns>
    private async Task RunAsync()
    {
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                while (_commands.Reader.TryRead(out var command))
                {
                    command();
                }

                do
                {
                    foreach (var tunnel in _tunnels.Values)
                    {
                        if (!tunnel.DrainOutbound(_http3))
                        {
                            // The connection's DATAGRAM queue is full; the flush below makes
                            // room, and the refused payload waits in its tunnel.
                            break;
                        }
                    }
                }
                while (await _connection.SendPendingAsync(_lifetime.Token).ConfigureAwait(false));

                if (!await _http3.PumpOnceAsync(_lifetime.Token).ConfigureAwait(false))
                {
                    throw new TlsQuicProxyException(
                        TlsQuicProxyError.MasqueTunnelClosed,
                        "The outer HTTP/3 connection failed with error "
                            + $"0x{_http3.ConnectionErrorCode:x}.");
                }

                for (var index = _opening.Count - 1; index >= 0; index--)
                {
                    if (TryFinishOpen(_opening[index]))
                    {
                        _opening.RemoveAt(index);
                    }
                }

                // A copy: a tunnel that ends removes itself from the table.
                foreach (var tunnel in _tunnels.Values.ToArray())
                {
                    if (tunnel.Pump(_http3) is { } failure)
                    {
                        EndTunnel(tunnel);
                        tunnel.Fail(failure);
                    }
                }
            }
        }
        catch (Exception exception) when (!_lifetime.IsCancellationRequested)
        {
            var failure = exception as TlsQuicProxyException ?? Closed(exception);
            Interlocked.CompareExchange(ref _ended, failure, null);
            FailAll(_ended!);
        }
        catch (Exception)
        {
            // Disposed: DisposeAsync fails the tunnels once this task has returned.
        }
        finally
        {
            // Nothing posted from here on runs; what was posted before still does, and finds
            // the connection ended.
            _commands.Writer.TryComplete();
            while (_commands.Reader.TryRead(out var command))
            {
                command();
            }
        }
    }

    /// <summary>Owner: sends the CONNECT-UDP for an open (RFC 9298 s3.4's extended CONNECT with
    /// RFC 9297 s3.4's capsule-protocol and the s2 default template path) and waits for its
    /// answer in <see cref="TryFinishOpen"/>.</summary>
    private void BeginOpen(PendingOpen open)
    {
        if (Volatile.Read(ref _ended) is { } ended)
        {
            open.Answer.TrySetException(ended);
            return;
        }
        if (open.Answer.Task.IsCompleted)
        {
            // Abandoned before it started.
            return;
        }

        var credentials = Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{_options.Username}:{_options.Password}"));
        var request = new TlsQuicHttp3Request
        {
            Method = "CONNECT",
            Protocol = "connect-udp",
            Scheme = "https",
            Authority = $"{_options.ProxyEndPoint.Host}:{_options.ProxyEndPoint.Port}",
            Path = $"/.well-known/masque/udp/{Uri.EscapeDataString(open.Host)}/{open.Port}/",
            Fields =
            [
                new TlsQuicHttp3Field("proxy-authorization", $"Basic {credentials}"),
                new TlsQuicHttp3Field("capsule-protocol", "?1"),
            ],
        };
        var stream = _http3.TryOpenRequest(
            request, out var refusal, out var malformed, receivesDatagrams: true);
        if (stream is null)
        {
            open.Answer.TrySetException(new TlsQuicProxyException(
                TlsQuicProxyError.MasqueTunnelRefused,
                $"The CONNECT-UDP request could not be sent: {refusal}/{malformed}."));
            return;
        }
        open.Stream = stream;
        _opening.Add(open);
    }

    /// <summary>Owner: judges an open's answer. Any 2xx is a tunnel (RFC 9298 s3.5); a
    /// non-2xx or a reset is a named failure; no answer yet is a wait.</summary>
    /// <returns>Whether the open is finished, one way or the other.</returns>
    private bool TryFinishOpen(PendingOpen open)
    {
        var stream = open.Stream!;
        if (open.Answer.Task.IsCompleted)
        {
            // The caller gave up at its deadline: end the request stream so the proxy does not
            // keep a tunnel for nobody.
            TryFin(stream);
            return true;
        }

        var response = _http3.ResponseFor(stream.Id);
        if (response is null)
        {
            open.Answer.TrySetException(new TlsQuicProxyException(
                TlsQuicProxyError.MasqueTunnelClosed,
                "The tunnel exchange vanished before a response."));
            return true;
        }
        if (response.IsReset)
        {
            open.Answer.TrySetException(new TlsQuicProxyException(
                TlsQuicProxyError.MasqueTunnelClosed,
                "The proxy reset the CONNECT-UDP stream with error "
                    + $"0x{response.ResetErrorCode:x} before answering."));
            return true;
        }
        if (response.Status < 0)
        {
            return false;
        }

        TlsQuicProxyException? refusal = response.Status switch
        {
            >= 200 and <= 299 => null,
            407 => new TlsQuicProxyException(
                TlsQuicProxyError.MasqueAuthenticationRejected,
                "The MASQUE proxy answered 407: credentials refused or the account's traffic "
                    + "limit reached."),
            400 => new TlsQuicProxyException(
                TlsQuicProxyError.MasqueTargetRejected,
                $"The MASQUE proxy answered 400 for target {open.Host}:{open.Port}."),
            _ => new TlsQuicProxyException(
                TlsQuicProxyError.MasqueTunnelRefused,
                $"The MASQUE proxy answered {response.Status} to CONNECT-UDP."),
        };
        if (refusal is not null)
        {
            TryFin(stream);
            open.Answer.TrySetException(refusal);
            return true;
        }

        var tunnel = new TlsQuicMasqueTransport(
            this, stream, open.EndPoint, _connection.MaximumDatagramFramePayload, _options.InnerDatagramCeiling);
        if (!open.Answer.TrySetResult(tunnel))
        {
            // Answered a breath after the caller gave up.
            TryFin(stream);
            tunnel.Fail(Disposed());
            return true;
        }
        _tunnels[stream.Id] = tunnel;
        Interlocked.Increment(ref _tunnelCount);
        return true;
    }

    /// <summary>Owner: forgets a tunnel and ends its request stream with a FIN (RFC 9298 s3.4:
    /// closing the request stream ends the tunnel). Also after the proxy ended or reset its
    /// side: our side is still open until we close it, and RFC 9000 s4.6 credits a new stream
    /// only once both sides of an old one are done, so a session that saw many proxy-ended
    /// tunnels would otherwise run out of request streams.</summary>
    private void EndTunnel(TlsQuicMasqueTransport tunnel)
    {
        if (!_tunnels.Remove(tunnel.Stream.Id))
        {
            return;
        }
        Interlocked.Decrement(ref _tunnelCount);
        TryFin(tunnel.Stream);
    }

    /// <summary>Owner: the FIN that ends a request stream, unless one has gone already or the
    /// stream can no longer carry one.</summary>
    private void TryFin(TlsQuicStream stream)
    {
        if (Volatile.Read(ref _ended) is not null || stream.FinQueued)
        {
            return;
        }
        try
        {
            _connection.Streams.Send(stream, ReadOnlyMemory<byte>.Empty, fin: true);
        }
        catch (InvalidOperationException)
        {
            // The stream is past sending (a STOP_SENDING answered, or the connection is
            // closing); the proxy has nothing more to learn from us.
        }
    }

    /// <summary>Fails every tunnel and every pending open with the connection's end. Owner
    /// task, or <see cref="DisposeAsync"/> once the owner has exited.</summary>
    private void FailAll(TlsQuicProxyException ended)
    {
        foreach (var tunnel in _tunnels.Values)
        {
            tunnel.Fail(ended);
        }
        _tunnels.Clear();
        Volatile.Write(ref _tunnelCount, 0);
        foreach (var open in _opening)
        {
            open.Answer.TrySetException(ended);
        }
        _opening.Clear();
    }

    /// <summary>An open in flight: its target, its answer, and its request stream once the
    /// owner has sent the request.</summary>
    private sealed class PendingOpen(string host, int port, IPEndPoint endPoint)
    {
        public string Host { get; } = host;

        public int Port { get; } = port;

        public IPEndPoint EndPoint { get; } = endPoint;

        public TaskCompletionSource<TlsQuicMasqueTransport> Answer { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TlsQuicStream? Stream { get; set; }
    }

    /// <summary>The outer transport as the connection reads it: every member forwards, except
    /// that <see cref="Wake"/> ends the receive in progress, or the next one, with an empty
    /// datagram instead of an exception.</summary>
    /// <remarks>Disposing it disposes the inner transport; the connection never does, and
    /// disposes only an inner it opened itself.</remarks>
    /// <param name="inner">The socket, or the caller's
    /// <see cref="TlsQuicMasqueOptions.OuterTransport"/>.</param>
    /// <param name="proxy">What an empty datagram reports as its sender, as the connection's
    /// own wake-up does.</param>
    private sealed class WakeableTransport(ITlsQuicDatagramTransport inner, IPEndPoint proxy)
        : ITlsQuicDatagramTransport
    {
        /// <summary>The source that ends the receive in progress, or <see langword="null"/>
        /// between receives.</summary>
        private CancellationTokenSource? _receiving;

        /// <summary>1 from a <see cref="Wake"/> until the receive that answers it
        /// returns.</summary>
        private int _woken;

        /// <inheritdoc/>
        public int MaxDatagramPayloadSize => inner.MaxDatagramPayloadSize;

        /// <inheritdoc/>
        /// <remarks>Forwarded explicitly: the interface's default would report 0 whatever the
        /// inner transport encapsulates.</remarks>
        public int DatagramOverhead => inner.DatagramOverhead;

        /// <summary>Ends the receive in progress with an empty datagram, or the next one before
        /// it waits.</summary>
        /// <remarks>The flag covers the window before a receive has published its source: the
        /// receive reads it after publishing. Interlocked on both sides, so the store and the
        /// load on each side do not reorder, or a wake-up that ran between them sees no source
        /// while the receive sees no flag - a lost wake-up with nothing else to end the
        /// receive. Http3StreamMultiplexer.cs (TlsClient) explains the same pair.</remarks>
        public void Wake()
        {
            Interlocked.Exchange(ref _woken, 1);
            try
            {
                Volatile.Read(ref _receiving)?.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // That receive has returned; the refill after its pump takes the payload.
            }
        }

        /// <inheritdoc/>
        public ValueTask SendAsync(
            IPEndPoint destination, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken) =>
            inner.SendAsync(destination, payload, cancellationToken);

        /// <inheritdoc/>
        /// <remarks>
        /// <para>THE CALLER'S CANCELLATION OUTRANKS A WAKE-UP. The connection's token carries
        /// its deadlines, so an already-cancelled one leaves as the exception its
        /// ReceiveWithinDeadlineAsync turns into loss recovery or abandonment; a pending wake-up
        /// loses nothing by waiting, because its payload is already in the channel.</para>
        /// <para>THE FLAG CLEARS WHEN THE RECEIVE RETURNS, whether a wake-up or a datagram
        /// ended it. A wake-up cleared here belongs to a payload already in a tunnel's channel,
        /// and the owner's refill after this pump takes it.</para>
        /// </remarks>
        public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
            Memory<byte> buffer, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var receiving = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Interlocked.Exchange(ref _receiving, receiving);
            try
            {
                if (Volatile.Read(ref _woken) != 0)
                {
                    return new TlsQuicDatagramReceiveResult(0, proxy);
                }
                return await inner.ReceiveAsync(buffer, receiving.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                receiving.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                return new TlsQuicDatagramReceiveResult(0, proxy);
            }
            finally
            {
                Interlocked.Exchange(ref _receiving, null);
                Interlocked.Exchange(ref _woken, 0);
            }
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }

    /// <summary>A <see cref="TlsQuicProxyError.MasqueTunnelClosed"/> carrying its cause in
    /// the text, since <see cref="TlsQuicProxyException"/> takes no inner exception.</summary>
    /// <param name="cause">What ended the connection.</param>
    /// <returns>The exception to throw.</returns>
    private static TlsQuicProxyException Closed(Exception cause) => new(
        TlsQuicProxyError.MasqueTunnelClosed,
        $"The MASQUE proxy connection ended: {cause.GetType().Name}: {cause.Message}");

    private static TlsQuicProxyException Disposed() => new(
        TlsQuicProxyError.MasqueTunnelClosed, "The MASQUE proxy connection was disposed.");

    private static void RequireSetting(TlsQuicHttp3Connection http3, ulong identifier, string name)
    {
        if (TlsQuicHttp3Settings.Value(http3.PeerSettings, identifier) != 1)
        {
            throw new TlsQuicProxyException(
                TlsQuicProxyError.MasqueNotOffered,
                $"The proxy's SETTINGS carry no {name} = 1, so it does not offer CONNECT-UDP.");
        }
    }

    // TlsQuicConnection.PumpOnceAsync reads and processes; the ACKs and any stream bytes it
    // queued leave only through SendPendingAsync, so each pump is followed by a flush.
    private static async ValueTask PumpAndFlushAsync(
        TlsQuicConnection connection, TlsQuicHttp3Connection http3, CancellationToken ct)
    {
        if (!await http3.PumpOnceAsync(ct).ConfigureAwait(false))
        {
            throw new TlsQuicProxyException(
                TlsQuicProxyError.MasqueTunnelClosed,
                $"The outer HTTP/3 connection failed with error 0x{http3.ConnectionErrorCode:x}.");
        }
        await FlushAsync(connection, ct).ConfigureAwait(false);
    }

    private static async ValueTask FlushAsync(TlsQuicConnection connection, CancellationToken ct)
    {
        while (await connection.SendPendingAsync(ct).ConfigureAwait(false))
        {
        }
    }
}
