using System.Diagnostics;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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

    // RFC 9298 s4: every HTTP Datagram on a CONNECT-UDP stream starts with a Context ID
    // varint, and context 0 (one byte) carries UDP payloads.
    private const int ContextIdLength = 1;

    private readonly TlsQuicConnection _connection;
    private readonly TlsQuicHttp3Connection _http3;
    private readonly ITlsQuicDatagramTransport _outer;
    private readonly ulong _streamId;
    private readonly IPEndPoint _targetEndPoint;
    private Task? _owner;

    private TlsQuicMasqueTransport(
        TlsQuicConnection connection,
        TlsQuicHttp3Connection http3,
        ITlsQuicDatagramTransport outer,
        ulong streamId,
        IPEndPoint targetEndPoint)
    {
        _connection = connection;
        _http3 = http3;
        _outer = outer;
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
    /// the request, reset it, or the tunnel did not come up within
    /// <see cref="TlsQuicMasqueOptions.HandshakeDeadline"/>.</exception>
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
                connection, http3, outer, stream.Id, options.TargetEndPoint);
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

    /// <summary>Not yet implemented: the data plane lands with the tunnel's owner loop.</summary>
    /// <param name="destination">Ignored; a tunnel has one target.</param>
    /// <param name="payload">The inner UDP payload.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>Never returns.</returns>
    /// <exception cref="NotImplementedException">Always.</exception>
    public ValueTask SendAsync(
        IPEndPoint destination, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken) =>
        throw new NotImplementedException();

    /// <summary>Not yet implemented: the data plane lands with the tunnel's owner loop.</summary>
    /// <param name="buffer">Receives the inner UDP payload.</param>
    /// <param name="cancellationToken">Cancels the receive.</param>
    /// <returns>Never returns.</returns>
    /// <exception cref="NotImplementedException">Always.</exception>
    public ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer, CancellationToken cancellationToken) =>
        throw new NotImplementedException();

    /// <summary>Not yet implemented: teardown lands with the tunnel's owner loop.</summary>
    /// <returns>Never returns.</returns>
    /// <exception cref="NotImplementedException">Always.</exception>
    public ValueTask DisposeAsync() => throw new NotImplementedException();

    // The tunnel's owner loop; the data plane fills it in.
    private Task RunAsync() => Task.CompletedTask;

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
