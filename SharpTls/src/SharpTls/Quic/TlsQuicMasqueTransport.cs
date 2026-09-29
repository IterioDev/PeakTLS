using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading.Channels;

namespace SharpTls.Quic;

/// <summary>One RFC 9298 CONNECT-UDP tunnel on a <see cref="TlsQuicMasqueConnection"/>,
/// presented as the UDP-shaped <see cref="ITlsQuicDatagramTransport"/> an inner QUIC
/// connection dials through. One instance is one request stream on the outer connection;
/// disposing it ends that stream and nothing else. See docs/MASQUE-DATAGRAM-TRANSPORT.md.</summary>
internal sealed class TlsQuicMasqueTransport : ITlsQuicDatagramTransport
{
    /// <summary>RFC 9298 s4's Context ID for a UDP payload, the only one this tunnel
    /// registers.</summary>
    private const byte ContextIdUdpPayload = 0x00;

    /// <summary>How many framed payloads <see cref="SendAsync"/> queues ahead of the owner
    /// before it waits.</summary>
    /// <remarks>The third of three stages a blocked outer fills, after the connection's own
    /// DATAGRAM queue (TlsQuicConnection.DatagramQueueBound, 64) and the one payload the owner
    /// holds in <see cref="_stalled"/>.</remarks>
    private const int OutboundBound = 64;

    /// <summary>A received datagram too short to be a QUIC packet is a message from the proxy
    /// or its exit rather than from the target, so its bytes are kept for the tunnel-ended
    /// report. RFC 9000 s14.1's 1200-byte Initial floor is far above this; a 7-byte answer to
    /// an inner Initial was a proxy refusing the target.</summary>
    private const int ShortDatagramLength = 64;

    private const int RememberedSizes = 6;

    /// <summary>The outer connection this tunnel rides on; its owner task drives this tunnel's
    /// owner-side members.</summary>
    private readonly TlsQuicMasqueConnection _connection;

    /// <summary>The target every received datagram is reported as coming from.</summary>
    private readonly IPEndPoint _targetEndPoint;

    /// <summary>Framed payloads (Context ID, then the UDP payload) waiting for the owner.
    /// </summary>
    /// <remarks>Bounded and waiting, never dropping: backpressure from a blocked outer reaches
    /// the inner connection's send as an await, not as a loss.</remarks>
    private readonly Channel<byte[]> _outbound = Channel.CreateBounded<byte[]>(
        new BoundedChannelOptions(OutboundBound)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
        });

    /// <summary>UDP payloads the owner unwrapped, waiting for <see cref="ReceiveAsync"/>.
    /// </summary>
    private readonly Channel<byte[]> _inbound = Channel.CreateUnbounded<byte[]>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });

    /// <summary>The one payload the connection's full DATAGRAM queue refused, held so the
    /// channel's order survives the retry.</summary>
    private byte[]? _stalled;

    /// <summary>Inbound datagrams dropped for a Context ID other than 0.</summary>
    private ulong _droppedWrongContext;

    /// <summary>Inbound datagrams dropped for a payload above
    /// <see cref="MaxDatagramPayloadSize"/>.</summary>
    private ulong _droppedOversize;

    /// <summary>1 once <see cref="DisposeAsync"/> has started.</summary>
    private int _disposed;

    /// <summary>Payloads handed to the outer connection's DATAGRAM queue, and datagrams
    /// delivered to <see cref="ReceiveAsync"/>: the two numbers that say whether a tunnel the
    /// proxy ended ever carried anything back.</summary>
    private ulong _sentIntoTunnel;

    private ulong _receivedFromTunnel;

    /// <summary>When the proxy answered 2xx, for the age in a tunnel-ended message.</summary>
    private readonly long _openedAt = Stopwatch.GetTimestamp();

    /// <summary>The sizes of the last few datagrams each way, for a tunnel-ended message: a
    /// proxy or exit that ends a tunnel on one particular size shows it here.</summary>
    private readonly Queue<int> _sentSizes = new();

    private readonly Queue<int> _receivedSizes = new();

    private byte[]? _lastShortReceived;

    /// <param name="connection">The outer connection.</param>
    /// <param name="stream">The CONNECT-UDP request stream the proxy answered 2xx on.</param>
    /// <param name="targetEndPoint">What every receive reports as the sender.</param>
    /// <param name="maximumDatagramFramePayload">The outer connection's DATAGRAM frame
    /// payload.</param>
    /// <param name="innerCeiling">A caller's ceiling on the inner payload, or
    /// <see langword="null"/> for the arithmetic one.</param>
    internal TlsQuicMasqueTransport(
        TlsQuicMasqueConnection connection,
        TlsQuicStream stream,
        IPEndPoint targetEndPoint,
        int maximumDatagramFramePayload,
        int? innerCeiling)
    {
        _connection = connection;
        Stream = stream;
        _targetEndPoint = targetEndPoint;

        // RFC 9297 s2.1: an HTTP Datagram is the Quarter Stream ID varint then the payload;
        // RFC 9298 s4 puts the Context ID in front of the UDP payload inside that. A caller's
        // ceiling (a proxy guide's stated inner size) can only lower it.
        var arithmetic = maximumDatagramFramePayload
            - QuicVariableLengthInteger.GetEncodedLength(stream.Id / 4)
            - TlsQuicMasqueConnection.ContextIdLength;
        MaxDatagramPayloadSize = Math.Min(arithmetic, innerCeiling ?? int.MaxValue);
    }

    /// <summary>The CONNECT-UDP request stream. Owner task only.</summary>
    internal TlsQuicStream Stream { get; }

    /// <summary>The largest inner UDP payload one outer DATAGRAM frame carries: the outer
    /// connection's DATAGRAM frame payload minus the Quarter Stream ID and the Context ID.</summary>
    public int MaxDatagramPayloadSize { get; }

    /// <summary>Payloads handed to the outer connection so far.</summary>
    public ulong DatagramsSent => Volatile.Read(ref _sentIntoTunnel);

    /// <summary>Datagrams the proxy forwarded back so far. Zero after an inner handshake
    /// deadline, with <see cref="DatagramsSent"/> above zero and the outer connection alive, is
    /// an exit that does not carry UDP to the target.</summary>
    public ulong DatagramsReceived => Volatile.Read(ref _receivedFromTunnel);

    /// <summary>Payloads the inner connection handed this tunnel that have not reached the
    /// outer connection yet: queued in the channel, or the one the outer's full DATAGRAM queue
    /// refused. Above zero when a dial fails, the missing answers may be ours never having
    /// left, not the exit's silence.</summary>
    public int Backlog => _outbound.Reader.Count + (Volatile.Read(ref _stalled) is null ? 0 : 1);

    /// <summary>What was dropped on the way in, by reason, for a diagnostic.</summary>
    internal string DropSummary =>
        $"{_droppedWrongContext} datagram(s) dropped for a context id other than 0, "
        + $"{_droppedOversize} for exceeding {MaxDatagramPayloadSize} bytes inbound; "
        + $"{_connection.DroppedDatagramsWrongStream} for a stream nothing reads.";

    /// <summary>What crossed the tunnel each way, with the sizes of the last few datagrams:
    /// for the message of a dial that failed through it. Acknowledgements arriving while
    /// nothing above a thousand bytes does is a return path that loses the large datagrams a
    /// server's flight is made of.</summary>
    /// <returns>The counts and the sizes.</returns>
    public string DescribeTraffic()
    {
        lock (_sentSizes)
        {
            return $"{DatagramsSent} datagram(s) went in, {Backlog} still queued behind the outer, "
                + $"and {DatagramsReceived} came back "
                + $"(last sizes in: {string.Join(", ", _sentSizes)}; back: "
                + $"{string.Join(", ", _receivedSizes)}; ceiling {MaxDatagramPayloadSize})";
        }
    }

    /// <summary>Queues one inner UDP payload for the tunnel as a context-0 HTTP Datagram.
    /// </summary>
    /// <remarks>
    /// <para>DELAY, NEVER DROP. Completes once the owner task can take the payload; a
    /// congestion-blocked outer fills the connection's DATAGRAM queue, the one payload the
    /// owner holds, and <see cref="OutboundBound"/> more, and then this call waits. RFC 9221
    /// s5.2 does not retransmit a DATAGRAM frame once it is lost, so what this layer can
    /// promise is only that it never discards one itself.</para>
    /// <para>RFC 9298 s4 puts Context ID 0 in front of the payload and RFC 9297 s2.1 the
    /// Quarter Stream ID in front of that; the second is the HTTP/3 layer's.</para>
    /// </remarks>
    /// <param name="destination">Ignored: the tunnel's target was fixed by the CONNECT-UDP
    /// request (RFC 9298 s2).</param>
    /// <param name="payload">The inner UDP payload.</param>
    /// <param name="cancellationToken">Cancels the wait for room.</param>
    /// <returns>A task that completes once the owner has room for the payload.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The payload exceeds
    /// <see cref="MaxDatagramPayloadSize"/>.</exception>
    /// <exception cref="TlsQuicProxyException">The tunnel has ended
    /// (<see cref="TlsQuicProxyError.MasqueTunnelClosed"/>).</exception>
    public async ValueTask SendAsync(
        IPEndPoint destination, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (payload.Length > MaxDatagramPayloadSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(payload),
                payload.Length,
                $"This MASQUE tunnel carries at most {MaxDatagramPayloadSize} bytes per datagram.");
        }

        var framed = new byte[TlsQuicMasqueConnection.ContextIdLength + payload.Length];
        framed[0] = ContextIdUdpPayload;
        payload.Span.CopyTo(framed.AsSpan(TlsQuicMasqueConnection.ContextIdLength));
        try
        {
            await _outbound.Writer.WriteAsync(framed, cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException closed)
        {
            throw closed.InnerException as TlsQuicProxyException ?? Closed(closed);
        }
        _connection.Wake();
    }

    /// <summary>Receives one inner UDP payload the proxy forwarded, with its RFC 9297 s2.1
    /// and RFC 9298 s4 framing removed.</summary>
    /// <remarks>Only Context ID 0 is delivered; any other is dropped and counted (RFC 9298
    /// s4 lets a receiver drop a datagram whose context it does not know), as is a payload
    /// above <see cref="MaxDatagramPayloadSize"/>.</remarks>
    /// <param name="buffer">Receives the payload; at least
    /// <see cref="MaxDatagramPayloadSize"/> bytes.</param>
    /// <param name="cancellationToken">Cancels the receive.</param>
    /// <returns>The payload length, reported as coming from the tunnel's target.</returns>
    /// <exception cref="TlsQuicProxyException">The tunnel has ended
    /// (<see cref="TlsQuicProxyError.MasqueTunnelClosed"/>): the proxy reset or ended the
    /// tunnel stream, the outer connection failed or closed, or the tunnel was
    /// disposed.</exception>
    public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer, CancellationToken cancellationToken)
    {
        byte[] datagram;
        try
        {
            datagram = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException closed)
        {
            throw closed.InnerException as TlsQuicProxyException ?? Closed(closed);
        }

        datagram.CopyTo(buffer);
        return new TlsQuicDatagramReceiveResult(datagram.Length, _targetEndPoint);
    }

    /// <summary>Ends the tunnel: fails every pending and later send and receive with
    /// <see cref="TlsQuicProxyError.MasqueTunnelClosed"/>, and has the outer connection end
    /// the request stream (RFC 9298 s3.4). The outer connection itself stays up for its other
    /// tunnels. Idempotent.</summary>
    /// <returns>A completed task; the stream's FIN leaves on the owner's next turn.</returns>
    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return ValueTask.CompletedTask;
        }

        Fail(new TlsQuicProxyException(
            TlsQuicProxyError.MasqueTunnelClosed, "The MASQUE tunnel was disposed."));
        _connection.CloseTunnel(this);
        return ValueTask.CompletedTask;
    }

    /// <summary>Owner: hands every queued payload to the outer connection's DATAGRAM queue.
    /// </summary>
    /// <returns><see langword="false"/> when the queue refused one, which then waits in
    /// <see cref="_stalled"/> for the next turn.</returns>
    internal bool DrainOutbound(TlsQuicHttp3Connection http3)
    {
        while (true)
        {
            var next = _stalled;
            if (next is null && !_outbound.Reader.TryRead(out next))
            {
                return true;
            }
            if (!http3.TrySendDatagram(Stream.Id, next))
            {
                _stalled = next;
                return false;
            }
            _stalled = null;
            Interlocked.Increment(ref _sentIntoTunnel);
            Remember(_sentSizes, next.Length - TlsQuicMasqueConnection.ContextIdLength);
        }
    }

    /// <summary>Owner: unwraps what arrived for this tunnel and checks that its stream is
    /// still open.</summary>
    /// <returns>Why the tunnel ended, or <see langword="null"/> while it lives.</returns>
    internal TlsQuicProxyException? Pump(TlsQuicHttp3Connection http3)
    {
        foreach (var datagram in http3.DrainDatagrams(Stream.Id))
        {
            // A varint read, not a byte compare: RFC 9000 s16 lets 0 arrive in any of
            // its four encodings.
            var cursor = 0;
            if (!QuicVariableLengthInteger.TryRead(datagram, ref cursor, out var context)
                || context != ContextIdUdpPayload)
            {
                _droppedWrongContext++;
                continue;
            }
            if (datagram.Length - cursor > MaxDatagramPayloadSize)
            {
                _droppedOversize++;
                continue;
            }
            var payload = datagram[cursor..];
            if (TlsQuicRelayDiagnostics.IsTlsAlertRecord(payload))
            {
                // The verdict the SOCKS5 relay gives, given here: only a TCP TLS server
                // answers a QUIC Initial with a TLS alert record, so the exit behind this
                // proxy session wrote the inner datagram into a TCP connection. No inner
                // packet will ever cross it, and no second tunnel on the same session
                // reaches a different exit.
                return new TlsQuicProxyException(
                    TlsQuicProxyError.RelayDeliveredTlsAlert,
                    "The target answered the inner QUIC Initial with a TLS alert record "
                        + $"({Convert.ToHexString(payload)}: "
                        + $"{TlsQuicRelayDiagnostics.DescribeAlert(payload)}). Only a TCP TLS "
                        + "server produces that record, so the exit behind this proxy session "
                        + "writes UDP payloads into a TCP connection to the target port and "
                        + "cannot carry QUIC. Nothing on this side changes that; a different "
                        + "proxy session reaches a different exit.");
            }
            _inbound.Writer.TryWrite(payload);
            Interlocked.Increment(ref _receivedFromTunnel);
            Remember(_receivedSizes, payload.Length);
            if (payload.Length <= ShortDatagramLength)
            {
                _lastShortReceived = payload;
            }
        }

        var response = http3.ResponseFor(Stream.Id);
        if (response is null || response.IsReset || response.IsComplete)
        {
            return new TlsQuicProxyException(
                TlsQuicProxyError.MasqueTunnelClosed,
                TunnelEnded(
                    response is { IsReset: true }
                        ? $"The proxy reset the tunnel stream with error 0x{response.ResetErrorCode:x}"
                        : "The proxy ended the tunnel stream",
                    response));
        }
        return null;
    }

    /// <summary>Ends both channels with <paramref name="failure"/>, which the next send or
    /// receive throws. Outbound first: a caller that sees the receive fail must find the send
    /// failed too, not one more payload accepted into a tunnel that has ended.</summary>
    internal void Fail(TlsQuicProxyException failure)
    {
        _outbound.Writer.TryComplete(failure);
        _inbound.Writer.TryComplete(failure);
    }

    /// <summary>The message for a tunnel the proxy ended: how, how long after it opened, and
    /// what crossed it in each direction. A tunnel that carried datagrams in and none back is
    /// an exit that could not reach the target over UDP (a residential exit's UDP is the
    /// exit's, not the proxy front's), so the message says to change proxy session rather than
    /// retry the same one.</summary>
    private string TunnelEnded(string how, TlsQuicHttp3Response? response)
    {
        var age = Stopwatch.GetElapsedTime(_openedAt);
        var text = $"{how} {age.TotalSeconds:F1} s after it opened, with {_sentIntoTunnel} "
            + $"datagram(s) sent into it and {_receivedFromTunnel} received back"
            + $" (last sizes sent: {string.Join(", ", _sentSizes)}; received: "
            + $"{string.Join(", ", _receivedSizes)}; ceiling {MaxDatagramPayloadSize}).";
        if (_sentIntoTunnel > 0 && _receivedFromTunnel == 0)
        {
            text += " Nothing ever came back: the exit behind this proxy session could not carry"
                + " UDP to the target. That is a property of the session, so retry with a fresh"
                + " proxy session rather than the same one.";
        }
        if (_lastShortReceived is { } shortDatagram)
        {
            var printable = shortDatagram.All(b => b is >= 0x20 and < 0x7f);
            text += $" The last datagram received was {shortDatagram.Length} bytes, too short"
                + $" for a QUIC packet: {Convert.ToHexString(shortDatagram)}"
                + (printable ? $" (ASCII '{Encoding.ASCII.GetString(shortDatagram)}')" : string.Empty)
                + ". That is the proxy or its exit answering, not the target.";
        }
        if (response is { DiscardedBodyBytes: > 0 })
        {
            // RFC 9297 s3.2 capsules, which nothing here parses; a proxy that explains itself
            // does so there, so the bytes go into the message for a reader to decode.
            var tail = response.DiscardedBodyTail.Span;
            text += $" The proxy wrote {response.DiscardedBodyBytes} byte(s) on the tunnel"
                + $" stream before ending it, the last {tail.Length} being"
                + $" {Convert.ToHexString(tail)}.";
        }
        return text;
    }

    // Under one lock for both queues: the owner writes them and DescribeTraffic reads them from
    // the dialling thread.
    private void Remember(Queue<int> sizes, int size)
    {
        lock (_sentSizes)
        {
            sizes.Enqueue(size);
            while (sizes.Count > RememberedSizes)
            {
                sizes.Dequeue();
            }
        }
    }

    /// <summary>A <see cref="TlsQuicProxyError.MasqueTunnelClosed"/> carrying its cause in
    /// the text, since <see cref="TlsQuicProxyException"/> takes no inner exception.</summary>
    /// <param name="cause">What ended the tunnel.</param>
    /// <returns>The exception to throw.</returns>
    private static TlsQuicProxyException Closed(Exception cause) => new(
        TlsQuicProxyError.MasqueTunnelClosed,
        $"The MASQUE tunnel ended: {cause.GetType().Name}: {cause.Message}");
}
