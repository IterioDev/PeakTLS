using System.Diagnostics;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Channels;

namespace SharpTls.Quic;

/// <summary>An RFC 9298 CONNECT-UDP tunnel over HTTP/3, presented as the UDP-shaped
/// <see cref="ITlsQuicDatagramTransport"/> an inner QUIC connection dials through. One
/// instance is one tunnel on one outer connection. See docs/MASQUE-DATAGRAM-TRANSPORT.md.</summary>
internal sealed class TlsQuicMasqueTransport : ITlsQuicDatagramTransport
{
    // RFC 9000 s14.1: "A client MUST expand the payload of all UDP datagrams carrying Initial
    // packets to at least the smallest allowed maximum datagram size of 1200 bytes". A tunnel
    // narrower than that cannot carry the inner connection's first flight at all.
    private const int InnerInitialSize = 1200;

    /// <summary>The length of the Context ID this tunnel writes: context 0 as a one-byte
    /// varint.</summary>
    /// <remarks>RFC 9298 s4: every HTTP Datagram on a CONNECT-UDP stream starts with a Context
    /// ID varint, and context 0 carries a UDP payload.</remarks>
    private const int ContextIdLength = 1;

    /// <summary>RFC 9298 s4's Context ID for a UDP payload, the only one this tunnel
    /// registers.</summary>
    private const byte ContextIdUdpPayload = 0x00;

    /// <summary>How many framed payloads <see cref="SendAsync"/> queues ahead of the owner
    /// before it waits.</summary>
    /// <remarks>The second of three stages a blocked outer fills, after the connection's own
    /// DATAGRAM queue (TlsQuicConnection.DatagramQueueBound, 64) and the one payload the owner
    /// holds in <see cref="_stalled"/>.</remarks>
    private const int OutboundBound = 64;

    /// <summary>The outer QUIC connection; driven by the owner task only.</summary>
    private readonly TlsQuicConnection _connection;

    /// <summary>The HTTP/3 layer over <see cref="_connection"/>; driven by the owner task
    /// only.</summary>
    private readonly TlsQuicHttp3Connection _http3;

    /// <summary>The socket this tunnel opened, or <see langword="null"/> when the caller
    /// supplied <see cref="TlsQuicMasqueOptions.OuterTransport"/> and keeps ownership of
    /// it.</summary>
    private readonly ITlsQuicDatagramTransport? _ownedOuter;

    /// <summary>The CONNECT-UDP request stream.</summary>
    private readonly ulong _streamId;

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

    /// <summary>Cancelled by <see cref="DisposeAsync"/>; ends the owner.</summary>
    private readonly CancellationTokenSource _lifetime = new();

    /// <summary>The owner task, which alone touches <see cref="_connection"/> and
    /// <see cref="_http3"/> between the dial and <see cref="DisposeAsync"/>.</summary>
    private Task? _owner;

    /// <summary>The source that cancels the owner's current pump, or <see langword="null"/>
    /// between pumps.</summary>
    private CancellationTokenSource? _pumpInterrupt;

    /// <summary>Wake-ups requested since the owner last reset it; see
    /// <see cref="InterruptPump"/>.</summary>
    private int _interruptRequests;

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

    private TlsQuicMasqueTransport(
        TlsQuicConnection connection,
        TlsQuicHttp3Connection http3,
        ITlsQuicDatagramTransport? ownedOuter,
        ulong streamId,
        IPEndPoint targetEndPoint)
    {
        _connection = connection;
        _http3 = http3;
        _ownedOuter = ownedOuter;
        _streamId = streamId;
        _targetEndPoint = targetEndPoint;

        // RFC 9297 s2.1: an HTTP Datagram is the Quarter Stream ID varint then the payload;
        // RFC 9298 s4 puts the Context ID in front of the UDP payload inside that.
        MaxDatagramPayloadSize = connection.MaximumDatagramFramePayload
            - QuicVariableLengthInteger.GetEncodedLength(streamId / 4)
            - ContextIdLength;
    }

    /// <summary>The largest inner UDP payload one outer DATAGRAM frame carries: the outer
    /// connection's DATAGRAM frame payload minus the Quarter Stream ID and the Context ID.</summary>
    public int MaxDatagramPayloadSize { get; }

    /// <summary>What was dropped on the way in, by reason, for a diagnostic.</summary>
    internal string DropSummary =>
        $"{_droppedWrongContext} datagram(s) dropped for a context id other than 0, "
        + $"{_droppedOversize} for exceeding {MaxDatagramPayloadSize} bytes inbound; "
        + $"{_http3.DroppedDatagramsWrongStream} for a stream nothing reads.";

    /// <summary>Dials the proxy, checks that it offers CONNECT-UDP, sends the request and
    /// returns the tunnel once any 2xx answer arrives (RFC 9298 s3).</summary>
    /// <remarks>
    /// <para>FOUR STEPS UNDER ONE DEADLINE: the outer QUIC handshake, the proxy's SETTINGS
    /// (RFC 8441 s3's SETTINGS_ENABLE_CONNECT_PROTOCOL as RFC 9220 carries it to HTTP/3, and
    /// RFC 9297 s2.1.1's SETTINGS_H3_DATAGRAM) plus RFC 9221 s3's max_datagram_frame_size, the
    /// extended CONNECT itself, and its response.</para>
    /// <para>A REFUSED DIAL SAYS GOODBYE: an outer connection that got as far as HTTP/3 is
    /// closed with H3_NO_ERROR (RFC 9114 s8.1) before the exception leaves, so the proxy does
    /// not hold a half-open connection until its idle timeout.</para>
    /// </remarks>
    /// <param name="options">The tunnel to build.</param>
    /// <param name="cancellationToken">Cancels the dial.</param>
    /// <returns>The connected tunnel.</returns>
    /// <exception cref="TlsQuicProxyException">The proxy does not offer CONNECT-UDP, refused
    /// the request, reset it, closed the outer connection, or the tunnel did not come up
    /// within <see cref="TlsQuicMasqueOptions.HandshakeDeadline"/>.</exception>
    public static async Task<TlsQuicMasqueTransport> ConnectAsync(
        TlsQuicMasqueOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(options.HandshakeDeadline);
        var ct = deadline.Token;

        var outer = options.OuterTransport;
        TlsQuicConnection? connection = null;
        TlsQuicHttp3Connection? http3Owned = null;
        try
        {
            // Step 1: the outer QUIC connection.
            IPEndPoint proxy;
            if (outer is null)
            {
                var addresses = await System.Net.Dns.GetHostAddressesAsync(options.ProxyEndPoint.Host, ct)
                    .ConfigureAwait(false);
                if (addresses.Length == 0)
                {
                    throw new TlsQuicProxyException(
                        TlsQuicProxyError.MasqueTunnelRefused,
                        $"'{options.ProxyEndPoint.Host}' resolved to no address.");
                }
                proxy = new IPEndPoint(addresses[0], options.ProxyEndPoint.Port);
                outer = TlsQuicUdpDatagramTransport.Create(proxy.AddressFamily);
            }
            else
            {
                proxy = options.OuterRemoteEndPoint
                    ?? throw new ArgumentException(
                        "OuterTransport needs OuterRemoteEndPoint.", nameof(options));
            }

            var factory = new TlsQuicClientHelloProfileFactory
            {
                ConnectionSpec = options.OuterSpec,
                AlpnProtocols = [TlsQuicClientHelloProfileFactory.Http3AlpnToken],
                Tls = options.ConfigureOuterClientHello,
            };
            connection = new TlsQuicConnection(
                new TlsQuicConnectionOptions(outer, proxy, options.OuterSpec)
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
            await connection.ConnectAsync(ct).ConfigureAwait(false);

            // Step 2: the proxy must offer extended CONNECT and datagrams.
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

            // The floor: the tunnel is this connection's first request, so its stream id is 0
            // and the quarter stream id is one byte.
            var capacity = connection.MaximumDatagramFramePayload - 1 - ContextIdLength;
            if (capacity < InnerInitialSize)
            {
                throw new TlsQuicProxyException(
                    TlsQuicProxyError.MasqueNotOffered,
                    $"The tunnel would carry at most {capacity} bytes per datagram, below the "
                        + $"{InnerInitialSize} an inner Initial needs (peer "
                        + $"max_datagram_frame_size {connection.PeerMaxDatagramFrameSize}).");
            }

            // Step 3: CONNECT-UDP, RFC 9298 s3.4's extended CONNECT with RFC 9297 s3.4's
            // capsule-protocol and the s2 default template path.
            var credentials = Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{options.Username}:{options.Password}"));
            var request = new TlsQuicHttp3Request
            {
                Method = "CONNECT",
                Protocol = "connect-udp",
                Scheme = "https",
                Authority = $"{options.ProxyEndPoint.Host}:{options.ProxyEndPoint.Port}",
                Path = $"/.well-known/masque/udp/{Uri.EscapeDataString(options.TargetHost)}/"
                    + $"{options.TargetPort}/",
                Fields =
                [
                    new TlsQuicHttp3Field("proxy-authorization", $"Basic {credentials}"),
                    new TlsQuicHttp3Field("capsule-protocol", "?1"),
                ],
            };
            var stream = http3.TryOpenRequest(
                    request, out var refusal, out var malformed, receivesDatagrams: true)
                ?? throw new TlsQuicProxyException(
                    TlsQuicProxyError.MasqueTunnelRefused,
                    $"The CONNECT-UDP request could not be sent: {refusal}/{malformed}.");
            await FlushAsync(connection, ct).ConfigureAwait(false);

            // Step 4: the response. Any 2xx is a tunnel (RFC 9298 s3.5).
            TlsQuicHttp3Response response;
            while (true)
            {
                response = http3.ResponseFor(stream.Id)
                    ?? throw new TlsQuicProxyException(
                        TlsQuicProxyError.MasqueTunnelClosed,
                        "The tunnel exchange vanished before a response.");
                if (response.IsReset)
                {
                    throw new TlsQuicProxyException(
                        TlsQuicProxyError.MasqueTunnelClosed,
                        "The proxy reset the CONNECT-UDP stream with error "
                            + $"0x{response.ResetErrorCode:x} before answering.");
                }
                if (response.Status >= 0)
                {
                    break;
                }
                await PumpAndFlushAsync(connection, http3, ct).ConfigureAwait(false);
            }
            switch (response.Status)
            {
                case >= 200 and <= 299:
                    break;
                case 407:
                    throw new TlsQuicProxyException(
                        TlsQuicProxyError.MasqueAuthenticationRejected,
                        "The MASQUE proxy answered 407: credentials refused or the account's "
                            + "traffic limit reached.");
                case 400:
                    throw new TlsQuicProxyException(
                        TlsQuicProxyError.MasqueTargetRejected,
                        "The MASQUE proxy answered 400 for target "
                            + $"{options.TargetHost}:{options.TargetPort}.");
                default:
                    throw new TlsQuicProxyException(
                        TlsQuicProxyError.MasqueTunnelRefused,
                        $"The MASQUE proxy answered {response.Status} to CONNECT-UDP.");
            }

            Debug.Assert(stream.Id == 0, "the tunnel is the outer connection's first request");
            var transport = new TlsQuicMasqueTransport(
                connection,
                http3,
                outer == options.OuterTransport ? null : outer,
                stream.Id,
                options.TargetEndPoint);
            transport._owner = Task.Run(transport.RunAsync);
            http3Owned = null;
            connection = null;
            outer = null;
            return transport;
        }
        catch (Exception exception) when (
            (exception is OperationCanceledException
                && deadline.IsCancellationRequested
                && !cancellationToken.IsCancellationRequested)
            || exception is TimeoutException)
        {
            // Two clocks run to the same value: this method's linked deadline and the outer
            // TlsQuicConnection's own HandshakeDeadline, which throws TimeoutException.
            // TlsQuicProxyException has one constructor, (error, message); the cause rides in
            // the text.
            throw new TlsQuicProxyException(
                TlsQuicProxyError.MasqueTunnelRefused,
                $"The MASQUE tunnel did not come up within {options.HandshakeDeadline} "
                    + $"({exception.GetType().Name}: {exception.Message}).");
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
            // until its idle timeout. Best effort, never a second exception.
            if (http3Owned is not null)
            {
                try
                {
                    await http3Owned.CloseAsync(
                            TlsQuicHttp3ErrorCode.H3NoError, CancellationToken.None)
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

        var framed = new byte[ContextIdLength + payload.Length];
        framed[0] = ContextIdUdpPayload;
        payload.Span.CopyTo(framed.AsSpan(ContextIdLength));
        try
        {
            await _outbound.Writer.WriteAsync(framed, cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException closed)
        {
            throw closed.InnerException as TlsQuicProxyException ?? Closed(closed);
        }
        InterruptPump();
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

    /// <summary>Ends the tunnel: stops the owner, closes the outer connection with
    /// H3_NO_ERROR (RFC 9114 s8.1), and fails every pending and later send and receive with
    /// <see cref="TlsQuicProxyError.MasqueTunnelClosed"/>. Idempotent.</summary>
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

        var gone = new TlsQuicProxyException(
            TlsQuicProxyError.MasqueTunnelClosed, "The MASQUE tunnel was disposed.");
        _lifetime.Cancel();
        _outbound.Writer.TryComplete(gone);
        _inbound.Writer.TryComplete(gone);
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

        // Only now: the owner has exited, so nothing else is driving the connection.
        try
        {
            await _http3.CloseAsync(TlsQuicHttp3ErrorCode.H3NoError, CancellationToken.None)
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

    /// <summary>The owner loop: the only code that drives the outer connection once the
    /// tunnel is up. Sends everything queued, pumps one datagram, unwraps what arrived, and
    /// checks the tunnel stream is still open.</summary>
    /// <remarks>
    /// <para>OUTBOUND FIRST, AND ALL OF IT: SendPendingAsync builds one 1-RTT packet per call
    /// and the send path puts one DATAGRAM frame per packet, so one call per iteration would
    /// trickle an inner Initial flight at one datagram per proxy packet or timer. Refill the
    /// connection's queue, send, repeat until a send builds nothing (window shut or queue
    /// empty); a bounded loop, never a hot one. A payload the full queue refuses waits in
    /// <see cref="_stalled"/> so the channel keeps its order.</para>
    /// <para>THE PUMP BLOCKS UNTIL THE PROXY SENDS OR A TIMER FIRES, and a writer interrupts
    /// it through <see cref="InterruptPump"/>. That cancellation is safe to take mid-receive:
    /// TlsQuicConnection.ReceiveWithinDeadlineAsync lets a caller's cancellation leave as
    /// OperationCanceledException before any state changes (its catch filters on the
    /// deadline's source with the caller's token NOT cancelled), and the HTTP/3 pump never
    /// reaches TryProcess on that path; a datagram not yet read stays in the transport.</para>
    /// <para>ANY FAILURE ENDS THE TUNNEL: both channels complete with a
    /// <see cref="TlsQuicProxyError.MasqueTunnelClosed"/> naming the cause, which the next
    /// send or receive throws.</para>
    /// </remarks>
    /// <returns>A task that completes when the tunnel ends; it never faults.</returns>
    private async Task RunAsync()
    {
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                do
                {
                    while (true)
                    {
                        var next = _stalled;
                        if (next is null && !_outbound.Reader.TryRead(out next))
                        {
                            break;
                        }
                        if (!_http3.TrySendDatagram(_streamId, next))
                        {
                            _stalled = next;
                            break;
                        }
                        _stalled = null;
                    }
                }
                while (await _connection.SendPendingAsync(_lifetime.Token).ConfigureAwait(false));

                using (var interrupt = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token))
                {
                    // Interlocked.Exchange, not Volatile.Write: the store of the source and the
                    // load of the request counter below must not reorder, or a writer that ran
                    // between them sees null and this sees 0 - a lost wake-up with nothing else
                    // to end the receive. Http3StreamMultiplexer.cs (TlsClient) explains the
                    // same pair.
                    Interlocked.Exchange(ref _pumpInterrupt, interrupt);
                    try
                    {
                        if (Volatile.Read(ref _interruptRequests) > 0)
                        {
                            interrupt.Cancel();
                        }
                        if (!await _http3.PumpOnceAsync(interrupt.Token).ConfigureAwait(false))
                        {
                            throw new TlsQuicProxyException(
                                TlsQuicProxyError.MasqueTunnelClosed,
                                "The outer HTTP/3 connection failed with error "
                                    + $"0x{_http3.ConnectionErrorCode:x}.");
                        }
                    }
                    catch (OperationCanceledException) when (!_lifetime.IsCancellationRequested)
                    {
                        // Stepped aside for a writer; its payload is in the channel.
                    }
                    finally
                    {
                        // Reset BEFORE the refill at the top: a request cleared here belongs
                        // to a payload already in the channel, which that refill takes.
                        Interlocked.Exchange(ref _pumpInterrupt, null);
                        Interlocked.Exchange(ref _interruptRequests, 0);
                    }
                }

                foreach (var datagram in _http3.DrainDatagrams(_streamId))
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
                    _inbound.Writer.TryWrite(datagram[cursor..]);
                }

                var response = _http3.ResponseFor(_streamId);
                if (response is null || response.IsReset || response.IsComplete)
                {
                    throw new TlsQuicProxyException(
                        TlsQuicProxyError.MasqueTunnelClosed,
                        response is { IsReset: true }
                            ? $"The proxy reset the tunnel stream with error 0x{response.ResetErrorCode:x}."
                            : "The proxy ended the tunnel stream.");
                }
            }
        }
        catch (Exception exception) when (!_lifetime.IsCancellationRequested)
        {
            // Outbound first: a caller that sees the receive fail must find the send failed
            // too, not one more payload accepted into a tunnel that has ended.
            var failure = exception as TlsQuicProxyException ?? Closed(exception);
            _outbound.Writer.TryComplete(failure);
            _inbound.Writer.TryComplete(failure);
        }
        catch (Exception)
        {
            // Disposed: DisposeAsync completes the channels.
        }
    }

    /// <summary>Wakes the owner out of its pump so it takes a payload just queued.</summary>
    /// <remarks>The counter covers the window before the owner has published its source: it
    /// reads the counter after publishing and cancels its own pump if a request is waiting.
    /// </remarks>
    private void InterruptPump()
    {
        Interlocked.Increment(ref _interruptRequests);
        try
        {
            Volatile.Read(ref _pumpInterrupt)?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The owner finished that pump and disposed its source; it refills next anyway.
        }
    }

    /// <summary>A <see cref="TlsQuicProxyError.MasqueTunnelClosed"/> carrying its cause in
    /// the text, since <see cref="TlsQuicProxyException"/> takes no inner exception.</summary>
    /// <param name="cause">What ended the tunnel.</param>
    /// <returns>The exception to throw.</returns>
    private static TlsQuicProxyException Closed(Exception cause) => new(
        TlsQuicProxyError.MasqueTunnelClosed,
        $"The MASQUE tunnel ended: {cause.GetType().Name}: {cause.Message}");

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
