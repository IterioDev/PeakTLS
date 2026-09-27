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
    private readonly ITlsQuicDatagramTransport _relay;
    private readonly TlsQuicSocks5Transport? _socks;
    private int _inboundDatagrams;
    private bool _sawQuicDatagram;

    public Socks5LivenessTransport(TlsQuicSocks5Transport relay)
        : this((ITlsQuicDatagramTransport)relay)
    {
        _socks = relay;
    }

    /// <summary>For tests: any transport stands in for the relay, and the drop counters read as
    /// zero because only <see cref="TlsQuicSocks5Transport"/> keeps them.</summary>
    internal Socks5LivenessTransport(ITlsQuicDatagramTransport relay)
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
    /// Gets everything that has come back through this association since it was opened: what
    /// was delivered to the QUIC layer, plus everything the relay-source policy or the section
    /// 7 header parser threw away.
    /// </summary>
    /// <remarks>
    /// <para>A RUNNING TOTAL RATHER THAN A BOOLEAN, BECAUSE THE SECOND QUESTION IS ABOUT A
    /// WINDOW. Setup asks "has this association EVER relayed?", which
    /// <see cref="RelayedNothing"/> answers; the request path asks "has it relayed anything
    /// SINCE the handshake?", which only a number a caller can snapshot and compare against can
    /// answer. Both are the same measurement read at different instants, so they must be the
    /// same counter — two counters would be two things to keep in step, and this stack has
    /// already paid for that mistake once.</para>
    /// <para>MONOTONIC AND NEVER RESET. A caller that wants a window keeps its own baseline;
    /// nothing here decides what a window is.</para>
    /// </remarks>
    public long RelayedTotal =>
        InboundDatagrams +
        (_socks?.DatagramsFromUnexpectedSource ?? 0) +
        (_socks?.MalformedRelayHeaders ?? 0) +
        (_socks?.OversizedRelayPayloads ?? 0);

    /// <summary>
    /// Gets whether nothing whatsoever has come back through this association — neither a
    /// delivered datagram nor one the relay-source policy or the section 7 header parser threw
    /// away.
    /// </summary>
    /// <remarks>TRUE IS THE ONE CONDITION THAT JUSTIFIES A RE-ASSOCIATE. False means the relay
    /// is carrying traffic and whatever went wrong went wrong above this layer, where a fresh
    /// association would fix nothing and hide something.</remarks>
    public bool RelayedNothing => RelayedTotal == 0;

    /// <summary>Gets the inner transport's account of every datagram it dropped, for splicing
    /// into a failure message.</summary>
    public string DropSummary => _socks?.DropSummary ?? "no relay counters: not a SOCKS5 relay";

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

        // THE RELAY'S FIRST DATAGRAMS SAY WHETHER IT RELAYS UDP AT ALL. A QUIC datagram carries
        // RFC 9000 s17's fixed bit; a seven-byte TLS alert record is what a TCP TLS server
        // answers to bytes that are not a ClientHello, and a UDP relay cannot produce one. Its
        // arrival before any QUIC datagram means the proxy writes UDP ASSOCIATE payload into a
        // TCP connection to the destination port, and every attempt through it will sit out the
        // handshake deadline. SharpTls's receiver rightly only counts such a packet (RFC 9000
        // s12.2 forbids a throw on unauthenticated input); the association is where the verdict
        // belongs, and once one QUIC datagram has arrived the check is off for good.
        if (!_sawQuicDatagram)
        {
            _sawQuicDatagram = InspectFirstDatagram(buffer.Span[..result.Length]);
        }
        return result;
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync() => _relay.DisposeAsync();

    private static bool InspectFirstDatagram(ReadOnlySpan<byte> datagram)
    {
        if (IsTlsAlertRecord(datagram))
        {
            throw new TlsQuicProxyException(
                TlsQuicProxyError.RelayDeliveredTlsAlert,
                "The SOCKS5 relay answered a QUIC datagram with a TLS alert record "
                + $"({Convert.ToHexString(datagram)}: alert level {datagram[5]}, description "
                + $"{datagram[6]}). Only a TCP TLS server produces that record, so this proxy writes "
                + "UDP ASSOCIATE payload into a TCP connection to the destination port and cannot "
                + "carry QUIC. Use HTTP/2 over TCP through it, or a proxy whose UDP ASSOCIATE "
                + "relays datagrams.");
        }

        return datagram.Length > 0 && (datagram[0] & 0x40) != 0;
    }

    /// <summary>RFC 8446 s5.1's record header with ContentType alert (21), a legacy version of
    /// 0x0300 to 0x0304 and a length of 2, then an alert level of warning or fatal: OpenSSL and
    /// BoringSSL answer any first record that is not TLS with exactly <c>15 03 01 00 02 02 46</c>,
    /// fatal <c>protocol_version</c>.</summary>
    internal static bool IsTlsAlertRecord(ReadOnlySpan<byte> datagram) =>
        datagram.Length == 7
        && datagram[0] == 0x15
        && datagram[1] == 0x03
        && datagram[2] <= 0x04
        && datagram[3] == 0x00
        && datagram[4] == 0x02
        && datagram[5] is 1 or 2;
}
