using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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

    /// <summary>RFC 9114 s6.2: the unidirectional streams a peer must be allowed to open
    /// (control, QPACK encoder, QPACK decoder) before HTTP/3 can start.</summary>
    private const ulong Http3UnidirectionalStreams = 3;

    /// <summary>How far behind the outer connection's own handshake deadline the dial's backstop
    /// runs, so a stalled handshake is reported by the receiver (what it discarded and why)
    /// rather than by a bare cancellation.</summary>
    private static readonly TimeSpan DeadlineGrace = TimeSpan.FromSeconds(1);

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
    /// <remarks>The third of three stages a blocked outer fills, after the connection's own
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

    /// <summary>The outer transport as <see cref="_connection"/> reads it, so a writer can wake
    /// the owner's receive.</summary>
    private readonly WakeableTransport _wakeable;

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

    private TlsQuicMasqueTransport(
        TlsQuicConnection connection,
        TlsQuicHttp3Connection http3,
        WakeableTransport wakeable,
        ITlsQuicDatagramTransport? ownedOuter,
        ulong streamId,
        IPEndPoint targetEndPoint,
        int? innerCeiling)
    {
        _connection = connection;
        _http3 = http3;
        _wakeable = wakeable;
        _ownedOuter = ownedOuter;
        _streamId = streamId;
        _targetEndPoint = targetEndPoint;

        // RFC 9297 s2.1: an HTTP Datagram is the Quarter Stream ID varint then the payload;
        // RFC 9298 s4 puts the Context ID in front of the UDP payload inside that. A caller's
        // ceiling (a proxy guide's stated inner size) can only lower it.
        var arithmetic = connection.MaximumDatagramFramePayload
            - QuicVariableLengthInteger.GetEncodedLength(streamId / 4)
            - ContextIdLength;
        MaxDatagramPayloadSize = Math.Min(arithmetic, innerCeiling ?? int.MaxValue);
    }

    /// <summary>The sizes of the last few datagrams each way, for a tunnel-ended message: a
    /// proxy or exit that ends a tunnel on one particular size shows it here.</summary>
    private readonly Queue<int> _sentSizes = new();

    private readonly Queue<int> _receivedSizes = new();

    private const int RememberedSizes = 6;

    private static void Remember(Queue<int> sizes, int size)
    {
        sizes.Enqueue(size);
        while (sizes.Count > RememberedSizes)
        {
            sizes.Dequeue();
        }
    }

    /// <summary>The largest inner UDP payload one outer DATAGRAM frame carries: the outer
    /// connection's DATAGRAM frame payload minus the Quarter Stream ID and the Context ID.</summary>
    public int MaxDatagramPayloadSize { get; }

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
    /// closed with the RFC 9114 s8.1 code it recorded (H3_DATAGRAM_ERROR, say), or H3_NO_ERROR
    /// when it recorded none, before the exception leaves, so the proxy does not hold a
    /// half-open connection until its idle timeout.</para>
    /// </remarks>
    /// <param name="options">The tunnel to build.</param>
    /// <param name="cancellationToken">Cancels the dial.</param>
    /// <returns>The connected tunnel.</returns>
    /// <exception cref="TlsQuicProxyException">The proxy does not offer CONNECT-UDP, refused
    /// the request, reset it, closed the outer connection, or the tunnel did not come up
    /// within <see cref="TlsQuicMasqueOptions.HandshakeDeadline"/>.</exception>
    /// <exception cref="ArgumentException"><see cref="TlsQuicMasqueOptions.OuterSpec"/>
    /// advertises fewer than three unidirectional streams (initial_max_streams_uni), so the
    /// proxy could never open its control and QPACK streams (RFC 9114 s6.2).</exception>
    public static async Task<TlsQuicMasqueTransport> ConnectAsync(
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
        // that report wins the race, and bounds DNS and steps 2 to 4 on its own.
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
            // re-armed to cover all of them. Steps 2 to 4 run once, against the address that
            // completed the handshake: what the proxy answers there is not an address problem.
            IReadOnlyList<IPEndPoint> candidates;
            if (options.OuterTransport is null)
            {
                var addresses = await System.Net.Dns.GetHostAddressesAsync(options.ProxyEndPoint.Host, ct)
                    .ConfigureAwait(false);
                if (addresses.Length == 0)
                {
                    throw new TlsQuicProxyException(
                        TlsQuicProxyError.MasqueTunnelRefused,
                        $"'{options.ProxyEndPoint.Host}' resolved to no address.");
                }
                candidates = [.. addresses.Select(a => new IPEndPoint(a, options.ProxyEndPoint.Port))];
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
            stage = "waiting for the CONNECT-UDP response";
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
                wakeable,
                outer == options.OuterTransport ? null : outer,
                stream.Id,
                options.TargetEndPoint,
                options.InnerDatagramCeiling);
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
            // The outer TlsQuicConnection's own HandshakeDeadline throws TimeoutException with
            // the receiver's discard report; the backstop throws OperationCanceledException.
            // TlsQuicProxyException has one constructor, (error, message); the cause rides in
            // the text.
            var earlier = unreachable.Count == 0
                ? string.Empty
                : $" Addresses tried before it and unreachable: {string.Join(", ", unreachable)}.";
            throw new TlsQuicProxyException(
                TlsQuicProxyError.MasqueTunnelRefused,
                $"The MASQUE tunnel did not come up within {budget} during {stage} "
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
        _wakeable.Wake();
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

    /// <summary>Ends the tunnel: stops the owner, closes the outer connection with the
    /// RFC 9114 s8.1 code the HTTP/3 layer recorded (H3_NO_ERROR if none), and fails every pending and later send and receive with
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

        // Only now: the owner has exited, so nothing else is driving the connection. A tunnel
        // that took an HTTP/3 connection error (H3_DATAGRAM_ERROR, say) tells the proxy so; a
        // healthy one closes with H3_NO_ERROR.
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
                        _sentIntoTunnel++;
                        Remember(_sentSizes, next.Length - ContextIdLength);
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
                    _receivedFromTunnel++;
                    Remember(_receivedSizes, datagram.Length - cursor);
                }

                var response = _http3.ResponseFor(_streamId);
                if (response is null || response.IsReset || response.IsComplete)
                {
                    throw new TlsQuicProxyException(
                        TlsQuicProxyError.MasqueTunnelClosed,
                        TunnelEnded(
                            response is { IsReset: true }
                                ? $"The proxy reset the tunnel stream with error 0x{response.ResetErrorCode:x}"
                                : "The proxy ended the tunnel stream",
                            response));
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

    /// <summary>The outer transport as the connection reads it: every member forwards, except
    /// that <see cref="Wake"/> ends the receive in progress, or the next one, with an empty
    /// datagram instead of an exception.</summary>
    /// <remarks>Disposing it disposes the inner transport; the tunnel never does, and disposes
    /// only an inner it opened itself.</remarks>
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
        /// ended it. A wake-up cleared here belongs to a payload already in the channel, and the
        /// owner's refill after this pump takes it.</para>
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
