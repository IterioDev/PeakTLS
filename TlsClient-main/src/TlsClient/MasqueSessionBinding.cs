using System.Diagnostics.CodeAnalysis;

namespace TlsClient;

/// <summary>Binds a sticky proxy session through its MASQUE proxy before the session's first
/// TCP proxy use, once per session identity.</summary>
/// <remarks>
/// <para>THE ORDER OF FIRST USE DECIDES THE EXIT. Measured 2026-09-28 against Oxylabs
/// residential proxies with one sticky session id shared by <see cref="TlsSessionOptions.Proxy"/>
/// (SOCKS5) and <see cref="TlsQuicOptions.Proxy"/> (MASQUE): a session whose first use was the
/// SOCKS5 front got an exit that answered every later MASQUE tunnel with a TCP TLS alert or a
/// closed stream, 10 sessions out of 10; a session whose first use was MASQUE carried h3 and
/// then h2 over SOCKS5 on the SAME exit IP, 8 out of 8, 74 dials out of 74. So when both slots
/// name the same session, the first TCP proxy connect of the session waits for one MASQUE tunnel
/// to the same origin to open and close first. That costs one outer dial, about a second, once.
/// </para>
/// <para>ONCE MEANS ONCE, INCLUDING ON FAILURE. A binding that fails (the proxy down, the
/// tunnel refused) is recorded as done: the TCP connect goes ahead and the h3 dial reports its
/// own failure later by name. Priming on every TCP connect would turn a broken MASQUE hop into
/// a broken TCP hop too.</para>
/// <para>SCOPED TO THE SESSION, keyed by the proxy username, which is where a provider encodes
/// its session id: two <see cref="TlsProxy"/> instances with the same username are one session
/// on the provider's side. A successful h3 dial marks its session bound as well, so a session
/// whose first use is h3 never primes. Concurrent first connects share one binding task.</para>
/// </remarks>
internal sealed class MasqueSessionBinding
{
    /// <summary>One task per session identity; a completed task is a bound session.</summary>
    private readonly Dictionary<string, Task> _bindings = new(StringComparer.Ordinal);

    /// <summary>What binds a session: opens and closes one tunnel. Tests replace it.</summary>
    internal Func<Uri, TlsProxy, TlsSessionConfiguration, CancellationToken, Task> Primer { get; init; } =
        (origin, masque, configuration, cancellationToken) =>
            Http3Connection.PrimeMasqueSessionAsync(origin, masque, configuration, cancellationToken);

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
        var key = masque.GetCredentials()!.UserName;
        Task binding;
        lock (_bindings)
        {
            if (!_bindings.TryGetValue(key, out var existing))
            {
                existing = BindAsync(origin, masque, configuration, cancellationToken);
                _bindings[key] = existing;
            }
            binding = existing;
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
        if (masque.GetCredentials()?.UserName is not { Length: > 0 } key)
        {
            return;
        }
        lock (_bindings)
        {
            _bindings[key] = Task.CompletedTask;
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
            await Primer(origin, masque, configuration, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Best effort: the primer already reported the failure to the connect observer, and
            // the TCP connect it was holding up is not the one that failed. The session counts
            // as attempted, so no later TCP connect pays for the same broken hop.
        }
    }
}
