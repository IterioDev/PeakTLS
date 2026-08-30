using System.Collections.Concurrent;
using System.Diagnostics;

namespace TlsClient;

/// <summary>
/// Admits one RFC 1928 section 7 UDP ASSOCIATE at a time per proxy session, so that two
/// HTTP/3 dials sharing a proxy do not set their associations up concurrently.
/// </summary>
/// <remarks>
/// <para>WHY THIS EXISTS: FIELD EVIDENCE THAT NOTHING REACHES THE SOCKET. Over SOCKS5-UDP with
/// three concurrent sticky proxy sessions, a fraction of dials to a NEW host received zero
/// handshake response and timed out. Two independent observations placed the loss above the
/// socket rather than inside the QUIC layer: widening the relay's accepted source to
/// <c>Any</c> did not reduce the rate, so replies were not arriving from an unexpected address
/// — they were not arriving at all; and every receive-side counter (discarded, want-of-keys,
/// unprocessed, DCID mismatch, changed-SCID, retained, replayed) plus the transport drop
/// counters read zero. Only a fresh association ever stalled; established connections were
/// stable.</para>
/// <para>TWO CAUSES REMAINED AND THEY NEED DIFFERENT FIXES. (a) A setup race — the ASSOCIATE
/// reply racing the first relayed datagram, or several ASSOCIATEs opening near-simultaneously
/// and interfering. (b) A per-session cap on concurrent associations at the proxy provider,
/// where the excess ASSOCIATE succeeds at the TCP level and then never relays. Serialising
/// setup fixes (a) outright AND is the only available discriminator for (b): if stalls survive
/// one-at-a-time setup, the cause is a concurrency cap and not a race.</para>
/// <para>THE SCOPE IS THE PROXY SESSION, WHICH IS <see cref="TlsProxy.PoolKey"/>. That key is
/// the proxy type, the endpoint without user-info, and the credentials — which is exactly what
/// makes a sticky session sticky, since the provider distinguishes sessions by the username
/// handed to it. <see cref="ConnectionKey"/> already separates pooled connections by the same
/// key, so this reuses the boundary the pool had already drawn rather than inventing a second
/// one. Two dials through DIFFERENT sessions take different semaphores and never wait on each
/// other, which matters because the whole point of running three sessions is three times the
/// throughput.</para>
/// <para>ONLY THE ASSOCIATE IS HELD, NEVER THE HANDSHAKE. The caller releases as soon as
/// <c>TlsQuicSocks5Transport.ConnectAsync</c> returns, before the QUIC handshake starts.
/// Holding across the handshake would turn three concurrent dials into three sequential
/// handshake timeouts in exactly the failure case this was built to diagnose.</para>
/// <para>THE SEMAPHORES ARE NEVER EVICTED, one per distinct proxy identity per session. A
/// session that rotates through thousands of sticky credentials accumulates one small object
/// each. That is the deliberate ceiling: refcounted removal is racy for a saving of a few tens
/// of bytes, and the pool's own per-key dictionaries have the same shape.</para>
/// </remarks>
internal sealed class Socks5AssociationGate
{
    /// <summary>
    /// How long a dial may wait for another dial's ASSOCIATE before giving up, when the
    /// session names nothing: thirty seconds.
    /// </summary>
    /// <remarks>THE BOUND IS ON THE WAIT, NOT ON THE ASSOCIATE. Whoever holds the gate is
    /// bounded by its own caller's cancellation; this bounds everyone queued behind it, so a
    /// hung ASSOCIATE fails the dials behind it with a named error instead of converting into
    /// a hung session. Thirty seconds matches <c>Http3Connection</c>'s default handshake
    /// timeout, so in healthy operation — where an ASSOCIATE is a TCP connect, a greeting, an
    /// authentication exchange and one request/reply — the gate is never the shorter bound and
    /// firing it always means something upstream is genuinely stuck.</remarks>
    public static readonly TimeSpan DefaultWaitTimeout = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Waits for this proxy session's association slot and returns how long the wait took.
    /// </summary>
    /// <remarks>The returned duration is the observability the whole exercise depends on: a
    /// null result — "we serialised and the stalls did not go away" — is unattributable unless
    /// the tester can see that dials actually queued. <c>Http3Connection</c> reports it as
    /// <see cref="TlsConnectEventKind.Socks5AssociationGateEntered"/>.</remarks>
    /// <exception cref="HttpRequestException">The wait exceeded <paramref name="timeout"/>.
    /// </exception>
    /// <exception cref="OperationCanceledException">The caller cancelled while queued. Nothing
    /// was acquired, so there is nothing to release and no <see cref="Exit"/> is owed.
    /// </exception>
    public async ValueTask<TimeSpan> EnterAsync(
        TlsProxy proxy,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        var gate = _gates.GetOrAdd(proxy.PoolKey, static _ => new SemaphoreSlim(1, 1));
        var started = Stopwatch.GetTimestamp();

        // SemaphoreSlim.WaitAsync(TimeSpan, CancellationToken) is the whole implementation:
        // it is FIFO-ish, it observes the token WITHOUT taking the slot, and it reports a
        // timeout as false rather than an exception. A cancelled or timed-out waiter therefore
        // holds nothing, which is what makes the caller's try/finally correct.
        if (!await gate.WaitAsync(timeout, cancellationToken).ConfigureAwait(false))
        {
            throw new HttpRequestException(
                $"A SOCKS5 UDP ASSOCIATE for another connection through the same proxy " +
                $"session did not complete within {timeout}, so this connection to " +
                $"'{proxy.Address.IdnHost}' gave up waiting for its turn. Association setup " +
                $"is serialised per proxy session; raise " +
                $"{nameof(TlsQuicOptions)}.{nameof(TlsQuicOptions.AssociationWaitTimeout)} " +
                $"if the proxy is merely slow.");
        }
        return Stopwatch.GetElapsedTime(started);
    }

    /// <summary>Releases the slot taken by a successful <see cref="EnterAsync"/>.</summary>
    /// <remarks>CALL THIS FROM A <c>finally</c>. A dial that throws — a refused TCP connect to
    /// the proxy, a rejected authentication, a cancelled ASSOCIATE — must not leave the slot
    /// taken, or one failure wedges every later dial through that session for the lifetime of
    /// the pool.</remarks>
    public void Exit(TlsProxy proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        if (_gates.TryGetValue(proxy.PoolKey, out var gate))
        {
            gate.Release();
        }
    }
}
