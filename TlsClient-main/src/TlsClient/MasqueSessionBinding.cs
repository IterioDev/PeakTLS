using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using SharpTls.Quic;

namespace TlsClient;

/// <summary>A session's MASQUE state, keyed by proxy session identity: the pool of outer
/// connections its h3 dials open tunnels on, the MASQUE-first binding of a sticky session the TCP
/// proxy shares with the MASQUE proxy, and the memory of an exit that proved unable to carry
/// UDP.</summary>
/// <remarks>
/// <para>A POOL OF OUTER CONNECTIONS PER PROXY SESSION. RFC 9298 lets one HTTP/3 connection
/// carry any number of CONNECT-UDP tunnels, and an outer whose tunnel has ended is reused by the
/// next dial, so sequential dials skip the outer handshake. Concurrent ones each get their own by
/// default (<see cref="TlsQuicOptions.MasqueTunnelsPerConnection"/>): measured 2026-09-29 with
/// every tunnel of a session on one outer, the downloads shared one congestion window at the
/// proxy and 200 tunnel opens a run went unanswered behind them. An outer that has ended is
/// dropped from the pool and disposed; a dial in flight counts as taken.</para>
/// <para>THE ORDER OF FIRST USE DECIDES THE EXIT. Measured 2026-09-28 against Oxylabs
/// residential proxies with one sticky session id shared by <see cref="TlsSessionOptions.Proxy"/>
/// (SOCKS5) and <see cref="TlsQuicOptions.Proxy"/> (MASQUE): a session whose first use was the
/// SOCKS5 front got an exit that answered every later MASQUE tunnel with a TCP TLS alert or a
/// closed stream, 10 sessions out of 10; a session whose first use was MASQUE carried h3 and
/// then h2 over SOCKS5 on the SAME exit IP, 8 out of 8, 74 dials out of 74. So when both slots
/// name the same session, the first TCP proxy connect of the session waits for one MASQUE tunnel
/// to the same origin to open and close first. That tunnel's outer connection is the one the
/// session's h3 dials then share, so the binding costs nothing extra.</para>
/// <para>ONCE MEANS ONCE, INCLUDING ON FAILURE. A binding that fails (the proxy down, the
/// tunnel refused) is recorded as done: the TCP connect goes ahead and the h3 dial reports its
/// own failure later by name. Priming on every TCP connect would turn a broken MASQUE hop into
/// a broken TCP hop too.</para>
/// <para>AN EXIT THAT PROVED UNABLE TO CARRY UDP IS REMEMBERED. Datagrams into a tunnel and
/// nothing back while the outer stayed alive, a TLS alert record answering the inner Initial,
/// or every tunnel of a dial ending with nothing back: each is a property of the session's
/// exit, not of the dial, so every later h3 dial on that session fails at once with the same
/// named error instead of spending another deadline. The TCP path is untouched; only a fresh
/// session id changes the exit.</para>
/// <para>SCOPED TO THE SESSION, keyed by the proxy username, which is where a provider encodes
/// its session id: two <see cref="TlsProxy"/> instances with the same username are one session
/// on the provider's side.</para>
/// </remarks>
internal sealed class MasqueSessionBinding : IAsyncDisposable
{
    /// <summary>One outer connection of a session's pool, or the dial producing it, and how
    /// many dials hold it while their tunnel opens.</summary>
    internal sealed class PooledOuter(Task<ITlsQuicMasqueConnection> dial)
    {
        public Task<ITlsQuicMasqueConnection> Dial { get; } = dial;

        /// <summary>Leases not yet released: dials between taking this outer and their open
        /// finishing. Under the binding's lock.</summary>
        public int Opening { get; set; }

        /// <summary>Whether this outer cannot take another tunnel: its leases and its open
        /// tunnels reach <paramref name="capacity"/>. A dial still in flight counts its leases
        /// only.</summary>
        public bool IsFull(int capacity) =>
            Opening + (Dial.IsCompletedSuccessfully ? Dial.Result.TunnelCount : 0) >= capacity;

        /// <summary>Whether this outer is past use: its dial failed, or it has ended.</summary>
        public bool IsDead =>
            Dial.IsFaulted || Dial.IsCanceled || (Dial.IsCompletedSuccessfully && Dial.Result.IsClosed);
    }

    /// <summary>One proxy session's state.</summary>
    private sealed class Session
    {
        /// <summary>The session's outer connections.</summary>
        public List<PooledOuter> Outers { get; } = [];

        /// <summary>The MASQUE-first binding; a completed task is a bound session.</summary>
        public Task? Binding { get; set; }

        /// <summary>The failure that convicted this session's exit, if one did.</summary>
        public TlsQuicProxyException? Failure { get; set; }

        public long FailedAt { get; set; }
    }

    /// <summary>An outer connection held for one tunnel open. Disposing it, once the open has
    /// finished either way, lets the pool count the tunnel through the connection instead.
    /// </summary>
    internal sealed class OuterLease : IDisposable
    {
        private readonly MasqueSessionBinding _owner;
        private readonly PooledOuter _pooled;
        private int _released;

        internal OuterLease(MasqueSessionBinding owner, PooledOuter pooled, ITlsQuicMasqueConnection connection)
        {
            _owner = owner;
            _pooled = pooled;
            Connection = connection;
        }

        /// <summary>The outer connection.</summary>
        public ITlsQuicMasqueConnection Connection { get; }

        /// <summary>Releases the hold. Idempotent.</summary>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                _owner.Release(_pooled);
            }
        }
    }

    private readonly Dictionary<string, Session> _sessions = new(StringComparer.Ordinal);

    private int _disposed;

    /// <summary>Dials the outer connection for a proxy. Tests replace it.</summary>
    internal Func<TlsProxy, TlsSessionConfiguration, CancellationToken, Task<ITlsQuicMasqueConnection>> Dialer
    {
        get;
        init;
    } = async (masque, configuration, cancellationToken) =>
        await TlsQuicMasqueConnection.ConnectAsync(
            Http3Connection.MasqueOptionsFor(masque, configuration), cancellationToken).ConfigureAwait(false);

    /// <summary>What binds a session: opens and closes one tunnel on the session's outer
    /// connection. Tests replace it; <see langword="null"/> is
    /// <see cref="Http3Connection.PrimeMasqueSessionAsync"/>.</summary>
    internal Func<Uri, TlsProxy, TlsSessionConfiguration, CancellationToken, Task>? Primer { get; init; }

    /// <summary>Whether a TCP proxy connect has to wait for a MASQUE binding: the option is on,
    /// <paramref name="configuration"/> names a MASQUE proxy, and <paramref name="tcpProxy"/>
    /// carries the same username.</summary>
    internal static bool ShouldBind(
        TlsProxy? tcpProxy,
        TlsSessionConfiguration configuration,
        [NotNullWhen(true)] out TlsProxy? masque)
    {
        masque = null;
        if (!configuration.Quic.BindSessionThroughMasque
            || configuration.Quic.Proxy is not { Type: TlsProxyType.Masque } candidate
            || tcpProxy is null
            || tcpProxy.Type == TlsProxyType.Masque)
        {
            return false;
        }
        var tcpUser = tcpProxy.GetCredentials()?.UserName;
        var masqueUser = candidate.GetCredentials()?.UserName;
        if (string.IsNullOrEmpty(tcpUser) || !string.Equals(tcpUser, masqueUser, StringComparison.Ordinal))
        {
            return false;
        }
        masque = candidate;
        return true;
    }

    /// <summary>The verdict on an inner dial that failed through a tunnel: datagrams went in,
    /// nothing came back, and the outer connection to the proxy stayed alive, so the exit behind
    /// the session does not carry UDP to the target. Anything else is not the exit's silence:
    /// a datagram back means the path works, nothing sent means the dial never reached it, an
    /// outer that ended is the proxy front's failure.</summary>
    /// <param name="failure">What the inner dial threw.</param>
    /// <param name="host">The origin.</param>
    /// <param name="sent">Datagrams the tunnel carried in.</param>
    /// <param name="received">Datagrams the tunnel carried back.</param>
    /// <param name="outerClosed">Whether the outer connection had ended.</param>
    /// <param name="backlog">Datagrams still queued in the tunnel behind the outer.</param>
    /// <returns>The named failure, or <see langword="null"/> when the exit is not convicted.</returns>
    internal static TlsQuicProxyException? JudgeSilence(
        Exception failure, string host, ulong sent, ulong received, bool outerClosed, int backlog)
    {
        // A BACKLOG IS OUR SIDE. Datagrams the inner connection handed the tunnel that never
        // reached the outer mean its retransmissions were stuck here, so the exit saw two
        // datagrams where a deadline's worth of probes should have gone: a live report of
        // 2026-09-29 convicted a session on exactly that, behind a jammed shared outer.
        if (sent == 0 || received > 0 || outerClosed || backlog > 0)
        {
            return null;
        }
        return new TlsQuicProxyException(
            TlsQuicProxyError.MasqueExitSilent,
            $"The inner QUIC handshake with '{host}' got nothing back through the MASQUE tunnel: "
                + $"{sent} datagram(s) went into it and none came out, while the outer connection "
                + "to the proxy stayed alive. The exit behind this proxy session does not carry UDP "
                + "to the target; later h3 dials on this session fail at once with this error, and "
                + $"a fresh proxy session reaches a different exit. ({failure.GetType().Name}: "
                + $"{failure.Message})");
    }

    /// <summary>Whether a tunnel open that failed on a reused outer connection says the outer
    /// itself is stale: the open went unanswered (refused at its deadline, or closed) and
    /// nothing at all arrived on the connection meanwhile. A proxy that answered anything, a
    /// 522 included, is there, and discarding its connection would end every other tunnel on
    /// it. An outer that has already ended is replaced by the next dial without this.</summary>
    /// <param name="failure">What the open threw.</param>
    /// <param name="reused">Whether the outer had carried an open before this one.</param>
    /// <param name="closed">Whether the outer has ended.</param>
    /// <param name="receivedBefore">The outer's received datagrams when the open began.</param>
    /// <param name="receivedAfter">The same count when it failed.</param>
    /// <returns>Whether to discard the outer and dial again.</returns>
    internal static bool IsStale(
        Exception failure, bool reused, bool closed, int receivedBefore, int receivedAfter) =>
        reused
            && !closed
            && receivedAfter == receivedBefore
            && failure is TlsQuicProxyException
            {
                Error: TlsQuicProxyError.MasqueTunnelClosed or TlsQuicProxyError.MasqueTunnelRefused,
            };

    /// <summary>Whether an inner dial that failed through a tunnel is dialled again on a fresh
    /// one: its handshake ran out of its deadline, something did come back through the tunnel
    /// (nothing back is <see cref="JudgeSilence"/>'s), and attempts remain. A failure that is
    /// not a deadline is the origin's or TLS's answer and is reported as it is.</summary>
    /// <param name="failure">What the inner dial threw.</param>
    /// <param name="received">Datagrams the tunnel carried back.</param>
    /// <param name="attempt">The attempt that failed, from one.</param>
    /// <param name="attempts">How many attempts a dial may make.</param>
    /// <returns>Whether to dial again.</returns>
    internal static bool ShouldDialAgain(Exception failure, ulong received, int attempt, int attempts)
    {
        if (received == 0 || attempt >= attempts)
        {
            return false;
        }
        for (var cursor = failure; cursor is not null; cursor = cursor.InnerException)
        {
            if (cursor is TimeoutException)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>An outer connection for one tunnel open: one of the session's with room for it
    /// (<see cref="TlsQuicOptions.MasqueTunnelsPerConnection"/>), or a new dial when none has.
    /// Dispose the lease once the open has finished.</summary>
    /// <remarks>
    /// <para>AN IDLE OUTER IS REUSED, a busy one is not. A dial whose tunnels have all ended leaves
    /// its outer to the next dial, so sequential dials pay one outer handshake between them;
    /// concurrent ones each get their own, so one download does not share a congestion window
    /// with, or queue ahead of, another dial's traffic.</para>
    /// <para>The dial runs under its own deadlines rather than a caller's token: a caller that
    /// gives up leaves a dial the next caller finds finished, not one it cancelled for everyone.
    /// Outers that have ended are dropped from the pool and disposed here.</para>
    /// </remarks>
    internal async ValueTask<OuterLease> GetOuterAsync(
        TlsProxy masque, TlsSessionConfiguration configuration, CancellationToken cancellationToken)
    {
        var capacity = Math.Max(1, configuration.Quic.MasqueTunnelsPerConnection);
        PooledOuter chosen;
        List<ITlsQuicMasqueConnection> retired = [];
        lock (_sessions)
        {
            var session = SessionFor(masque);
            for (var index = session.Outers.Count - 1; index >= 0; index--)
            {
                var pooled = session.Outers[index];
                if (pooled.IsDead && pooled.Opening == 0)
                {
                    session.Outers.RemoveAt(index);
                    if (pooled.Dial.IsCompletedSuccessfully)
                    {
                        retired.Add(pooled.Dial.Result);
                    }
                }
            }

            // Oldest first: an established outer before one still dialling, and before a new dial.
            chosen = session.Outers.FirstOrDefault(pooled => !pooled.IsDead && !pooled.IsFull(capacity))
                ?? AddOuter(session, masque, configuration);
            chosen.Opening++;
        }
        foreach (var outer in retired)
        {
            await outer.DisposeAsync().ConfigureAwait(false);
        }

        try
        {
            var connection = await chosen.Dial.WaitAsync(cancellationToken).ConfigureAwait(false);
            return new OuterLease(this, chosen, connection);
        }
        catch (Exception)
        {
            Release(chosen);
            throw;
        }
    }

    private PooledOuter AddOuter(Session session, TlsProxy masque, TlsSessionConfiguration configuration)
    {
        var pooled = new PooledOuter(DialAndReportAsync(masque, configuration));
        session.Outers.Add(pooled);
        return pooled;
    }

    private void Release(PooledOuter pooled)
    {
        lock (_sessions)
        {
            pooled.Opening--;
        }
    }

    /// <summary>Drops <paramref name="outer"/> from the session's pool and disposes it: for an
    /// outer that is not <see cref="ITlsQuicMasqueConnection.IsClosed"/> but let an open go
    /// unanswered with nothing arriving meanwhile, which is what a proxy that silently forgot the
    /// connection looks like (<see cref="IsStale"/>). The next dial gets a fresh one.</summary>
    internal async ValueTask DiscardAsync(TlsProxy masque, ITlsQuicMasqueConnection outer)
    {
        lock (_sessions)
        {
            SessionFor(masque).Outers.RemoveAll(pooled =>
                pooled.Dial.IsCompletedSuccessfully && ReferenceEquals(pooled.Dial.Result, outer));
        }
        await outer.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>Runs before a TCP proxy connect: binds the session through MASQUE once when
    /// <see cref="ShouldBind"/> says so, otherwise returns at once. A second caller during the
    /// binding waits for the same one.</summary>
    internal async ValueTask EnsureBoundAsync(
        Uri origin,
        TlsProxy? tcpProxy,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken)
    {
        if (!ShouldBind(tcpProxy, configuration, out var masque))
        {
            return;
        }
        Task binding;
        lock (_sessions)
        {
            var session = SessionFor(masque);
            session.Binding ??= BindAsync(origin, masque, configuration, cancellationToken);
            binding = session.Binding;
        }
        if (!binding.IsCompleted)
        {
            await binding.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Records that a session is bound, from a successful h3 dial through
    /// <paramref name="masque"/>.</summary>
    internal void MarkBound(TlsProxy masque)
    {
        lock (_sessions)
        {
            SessionFor(masque).Binding = Task.CompletedTask;
        }
    }

    /// <summary>Records the failure that convicted the session's exit.</summary>
    internal void Remember(TlsProxy masque, TlsQuicProxyException failure)
    {
        lock (_sessions)
        {
            var session = SessionFor(masque);
            session.Failure = failure;
            session.FailedAt = Stopwatch.GetTimestamp();
        }
    }

    /// <summary>The failure that convicted the session's exit, as the exception a later dial
    /// throws at once: the same error, the same message, and how long ago it was
    /// proved.</summary>
    internal TlsQuicProxyException? RememberedFailure(TlsProxy masque)
    {
        lock (_sessions)
        {
            if (SessionFor(masque) is not { Failure: { } failure } session)
            {
                return null;
            }
            var age = Stopwatch.GetElapsedTime(session.FailedAt);
            return new TlsQuicProxyException(
                failure.Error,
                $"{failure.Message} (remembered from a dial {age.TotalSeconds:F0} s ago on this "
                    + "proxy session: every h3 dial on it fails at once until the session id changes)");
        }
    }

    /// <summary>Disposes every session's outer connection. A dial still in flight disposes its
    /// result when it lands rather than being waited for.</summary>
    /// <returns>A task that completes once every finished outer is closed.</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        List<Task<ITlsQuicMasqueConnection>> outers;
        lock (_sessions)
        {
            outers = [.. _sessions.Values.SelectMany(session => session.Outers).Select(pooled => pooled.Dial)];
            _sessions.Clear();
        }
        foreach (var outer in outers)
        {
            if (outer.IsCompletedSuccessfully)
            {
                await outer.Result.DisposeAsync().ConfigureAwait(false);
            }
            else if (!outer.IsCompleted)
            {
                _ = outer.ContinueWith(
                    static landed => landed.Result.DisposeAsync().AsTask(),
                    CancellationToken.None,
                    TaskContinuationOptions.OnlyOnRanToCompletion,
                    TaskScheduler.Default);
            }
        }
    }

    /// <summary>The session's state under the lock, created on first sight.</summary>
    private Session SessionFor(TlsProxy masque)
    {
        var key = masque.GetCredentials()?.UserName is { Length: > 0 } user
            ? user
            : masque.Address.ToString();
        if (!_sessions.TryGetValue(key, out var session))
        {
            session = new Session();
            _sessions[key] = session;
        }
        return session;
    }

    /// <summary>One outer dial, reported as <see cref="TlsConnectEventKind.MasqueConnectionOpened"/>
    /// with what it cost or why it failed.</summary>
    private async Task<ITlsQuicMasqueConnection> DialAndReportAsync(
        TlsProxy masque, TlsSessionConfiguration configuration)
    {
        var connectionId = Guid.NewGuid();
        var startedAt = Stopwatch.GetTimestamp();
        try
        {
            var outer = await Dialer(masque, configuration, CancellationToken.None).ConfigureAwait(false);
            TlsConnectTelemetry.Emit(
                configuration.ConnectObserver,
                connectionId,
                TlsConnectEventKind.MasqueConnectionOpened,
                masque.Address.IdnHost,
                masque.EffectivePort,
                elapsed: Stopwatch.GetElapsedTime(startedAt));
            return outer;
        }
        catch (Exception exception)
        {
            TlsConnectTelemetry.Emit(
                configuration.ConnectObserver,
                connectionId,
                TlsConnectEventKind.MasqueConnectionOpened,
                masque.Address.IdnHost,
                masque.EffectivePort,
                elapsed: Stopwatch.GetElapsedTime(startedAt),
                exception: exception);
            throw;
        }
    }

    private async Task BindAsync(
        Uri origin,
        TlsProxy masque,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken)
    {
        try
        {
            var primer = Primer
                ?? ((o, m, c, ct) => Http3Connection.PrimeMasqueSessionAsync(o, m, c, this, ct));
            await primer(origin, masque, configuration, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Best effort: the primer already reported the failure to the connect observer, and
            // the TCP connect it was holding up is not the one that failed. The session counts
            // as attempted, so no later TCP connect pays for the same broken hop.
        }
    }
}
