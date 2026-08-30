using System.Net;
using SharpTls.Quic;

namespace TlsClient;

/// <summary>
/// Wraps a SOCKS5 UDP relay transport and answers one question about it: has the association
/// ever carried a datagram INBOUND?
/// </summary>
/// <remarks>
/// <para>WHY THIS EXISTS: A SUCCESSFUL ASSOCIATE IS NOT A WORKING ASSOCIATION. Roughly six to
/// eight per cent of fresh RFC 1928 section 7 UDP ASSOCIATEs complete perfectly — the TCP
/// control connection is up, the section 6 reply is well-formed and carries a REP of X'00' and
/// a routable BND — and then relay nothing, ever. The QUIC handshake behind such an association
/// times out with every receive-side counter at zero. Serialising setup per proxy session did
/// not move the rate (25 dials at a concurrency of 1 stalled twice, statistically identical to
/// 6% at three threads), so it is a fixed per-association failure probability rather than a
/// race or a per-session cap, and the only remedy is to notice and re-associate.</para>
/// <para>ZERO INBOUND DATAGRAMS IS THE ONLY HONEST TRIGGER, and this type exists to make that
/// precise rather than approximate. A working association answers within one round trip; a dead
/// one never answers at all. Retrying on "the handshake failed" instead would mask a genuine
/// defect — a rejected ClientHello, a peer that will not speak h3, a relay whose replies are
/// being filtered — behind a re-dial that papers over it. Every one of those cases has SOMETHING
/// arriving, so <see cref="RelayedNothing"/> is false and the caller reports the real failure.
/// </para>
/// <para>IT COUNTS THE DROPS TOO, NOT ONLY WHAT IT DELIVERED.
/// <c>TlsQuicSocks5Transport.ReceiveAsync</c> loops internally over datagrams its
/// <see cref="TlsQuicSocks5RelaySource"/> policy rejects and over unparseable section 7
/// headers, so those never reach this decorator — yet each one is proof that the relay is
/// alive and answering. Reading the inner transport's own drop counters is what keeps a
/// pooled relay answering from a sibling address (the case
/// <c>DatagramsFromUnexpectedSource</c> exists to reveal) from being misdiagnosed as a dead
/// association and re-dialled instead of reported.</para>
/// <para>ONLY THE PROXIED PATH IS WRAPPED. A direct <c>TlsQuicUdpDatagramTransport</c> has no
/// association to be dead, so <c>Http3Connection</c> hands it through unwrapped and this
/// type's cost — one <see cref="Interlocked"/> increment per received datagram — is never
/// paid there.</para>
/// </remarks>
internal sealed class Socks5LivenessTransport : ITlsQuicDatagramTransport
{
    private readonly TlsQuicSocks5Transport _relay;
    private int _inboundDatagrams;

    public Socks5LivenessTransport(TlsQuicSocks5Transport relay)
    {
        ArgumentNullException.ThrowIfNull(relay);
        _relay = relay;
    }

    /// <summary>
    /// Gets or sets what to run the first time a datagram is delivered to the QUIC layer.
    /// </summary>
    /// <remarks>THE POINT IS TO STOP CUTTING THE HANDSHAKE SHORT ONCE LIVENESS IS PROVEN.
    /// <c>Http3Connection</c> arms its handshake cancellation at the short liveness deadline
    /// and uses this to re-arm it to the full handshake budget, so a stall costs seconds rather
    /// than the whole deadline while a working connection keeps every bit of the time it always
    /// had. Invoked on the receive path, so it must not throw and must not block; the caller's
    /// handler swallows the <see cref="ObjectDisposedException"/> it can race with.</remarks>
    public Action? OnFirstInboundDatagram { get; set; }

    /// <summary>Gets how many datagrams this transport handed up to the QUIC layer.</summary>
    public int InboundDatagrams => Volatile.Read(ref _inboundDatagrams);

    /// <summary>
    /// Gets whether nothing whatsoever has come back through this association — neither a
    /// delivered datagram nor one the relay-source policy or the section 7 header parser threw
    /// away.
    /// </summary>
    /// <remarks>TRUE IS THE ONE CONDITION THAT JUSTIFIES A RE-ASSOCIATE. False means the relay
    /// is carrying traffic and whatever went wrong went wrong above this layer, where a fresh
    /// association would fix nothing and hide something.</remarks>
    public bool RelayedNothing =>
        InboundDatagrams == 0 &&
        _relay.DatagramsFromUnexpectedSource == 0 &&
        _relay.MalformedRelayHeaders == 0 &&
        _relay.OversizedRelayPayloads == 0;

    /// <summary>Gets the inner transport's account of every datagram it dropped, for splicing
    /// into a failure message.</summary>
    public string DropSummary => _relay.DropSummary;

    /// <inheritdoc />
    public int MaxDatagramPayloadSize => _relay.MaxDatagramPayloadSize;

    /// <inheritdoc />
    /// <remarks>FORWARDED RATHER THAN DEFAULTED. The interface's default is zero, which is
    /// right for a bare socket and wrong for a relay: RFC 1928 section 7 puts a header in front
    /// of every payload, and a QUIC datagram built to the path MTU without subtracting it
    /// leaves the interface oversized. Letting the default apply here would silently undo the
    /// relay's own accounting.</remarks>
    public int DatagramOverhead => _relay.DatagramOverhead;

    /// <inheritdoc />
    public ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken) =>
        _relay.SendAsync(destination, payload, cancellationToken);

    /// <inheritdoc />
    public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var result = await _relay.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);

        // THE 0 -> 1 TRANSITION IS THE EVENT, so the callback fires exactly once however many
        // datagrams follow. Interlocked because the connection's receive loop and the dialling
        // thread read this from different threads; the counter is only consulted once the
        // handshake has finished one way or the other, so a stale read cannot occur where it
        // would matter.
        if (Interlocked.Increment(ref _inboundDatagrams) == 1)
        {
            OnFirstInboundDatagram?.Invoke();
        }
        return result;
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync() => _relay.DisposeAsync();
}
