using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using SharpTls.Quic;

namespace TlsClient;

/// <summary>A session's MASQUE state, keyed by proxy session identity: the one outer connection
/// every h3 dial on that session shares, the MASQUE-first binding of a sticky session the TCP
/// proxy shares with the MASQUE proxy, and the memory of an exit that proved unable to carry
/// UDP.</summary>
/// <remarks>
/// <para>ONE OUTER CONNECTION PER PROXY SESSION. RFC 9298 lets one HTTP/3 connection carry any
/// number of CONNECT-UDP tunnels, one request stream each, so every inner dial on a session
/// opens a tunnel on the session's outer connection instead of dialling the proxy front again:
/// one outer handshake per session rather than one per origin. Two hundred sessions in lockstep
/// were putting five or six bursts of two hundred outer handshakes onto one proxy front from
/// one address, and the front went silent under them. An outer that has ended (its idle
/// timeout, a proxy close, a failure) is replaced by the next dial; a dial in flight is shared
/// by every caller that arrives during it.</para>
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
    /// <summary>One proxy session's state.</summary>
    private sealed class Session
    {
        /// <summary>The outer connection, or the dial producing it; a faulted dial is replaced
        /// by the next caller.</summary>
        public Task<ITlsQuicMasqueConnection>? Outer { get; set; }

        /// <summary>The MASQUE-first binding; a completed task is a bound session.</summary>
        public Task? Binding { get; set; }

        /// <summary>The failure that convicted this session's exit, if one did.</summary>
        public TlsQuicProxyException? Failure { get; set; }

        public long FailedAt { get; set; }
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
    /// <returns>The named failure, or <see langword="null"/> when the exit is not convicted.</returns>
    internal static TlsQuicProxyException? JudgeSilence(
        Exception failure, string host, ulong sent, ulong received, bool outerClosed)
    {
        if (sent == 0 || received > 0 || outerClosed)
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

    /// <summary>The session's outer connection, dialled now if it has none or the one it had
    /// has ended. Callers arriving during a dial share it.</summary>
    /// <remarks>The dial runs under its own deadlines rather than a caller's token: a caller
    /// that gives up leaves a dial the next caller will find finished, not one it cancelled for
    /// everyone.</remarks>
    internal async ValueTask<ITlsQuicMasqueConnection> GetOuterAsync(
        TlsProxy masque, TlsSessionConfiguration configuration, CancellationToken cancellationToken)
    {
        Task<ITlsQuicMasqueConnection> dial;
        ITlsQuicMasqueConnection? retired = null;
        lock (_sessions)
        {
            var session = SessionFor(masque);
            if (session.Outer is { IsCompletedSuccessfully: true } ended && ended.Result.IsClosed)
            {
                retired = ended.Result;
                session.Outer = null;
            }
            if (session.Outer is null || session.Outer.IsFaulted || session.Outer.IsCanceled)
            {
                session.Outer = DialAndReportAsync(masque, configuration);
            }
            dial = session.Outer;
        }
        if (retired is not null)
        {
            await retired.DisposeAsync().ConfigureAwait(false);
        }
        return await dial.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Drops <paramref name="outer"/> as the session's connection, if it still is,
    /// and disposes it: for an outer that is not <see cref="ITlsQuicMasqueConnection.IsClosed"/>
    /// but refused or ended a tunnel open, which is what a proxy that silently forgot the
    /// connection looks like. The next dial gets a fresh one.</summary>
    internal async ValueTask DiscardAsync(TlsProxy masque, ITlsQuicMasqueConnection outer)
    {
        lock (_sessions)
        {
            var session = SessionFor(masque);
            if (session.Outer is { IsCompletedSuccessfully: true } current
                && ReferenceEquals(current.Result, outer))
            {
                session.Outer = null;
            }
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
            outers = [.. _sessions.Values.Select(s => s.Outer).OfType<Task<ITlsQuicMasqueConnection>>()];
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
