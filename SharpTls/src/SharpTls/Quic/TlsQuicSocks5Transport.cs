using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SharpTls.Quic;

/// <summary>Relays QUIC datagrams through a SOCKS5 UDP association (RFC 1928 section 4,
/// RFC 1929). Owns a TCP control connection and a UDP relay socket; the control
/// connection must stay open for the association's lifetime.</summary>
public sealed class TlsQuicSocks5Transport : ITlsQuicDatagramTransport
{
    private readonly Socket _control;
    private readonly Socket _udp;
    private readonly IPEndPoint _relayEndPoint;
    private readonly IPEndPoint _receiveTemplate;
    private readonly int _headerSize;
    private readonly string? _destinationHost;
    private readonly CancellationTokenSource _terminationCts = new();
    private readonly Task _controlWatcher;
    private volatile bool _disposed;

    private TlsQuicSocks5Transport(
        Socket control, Socket udp, IPEndPoint relayEndPoint, string? destinationHost)
    {
        _control = control;
        _udp = udp;
        _relayEndPoint = relayEndPoint;
        _destinationHost = destinationHost;

        // The domain form is the longer header, so sizing from it keeps MaxDatagramPayloadSize
        // honest: QUIC's path MTU accounting reads that number and a datagram built against a
        // smaller figure would not fit once the name is prepended.
        _headerSize = destinationHost is null
            ? TlsQuicSocks5Protocol.HeaderSizeFor(relayEndPoint.AddressFamily)
            : Math.Max(
                TlsQuicSocks5Protocol.HeaderSizeForDomain(destinationHost),
                TlsQuicSocks5Protocol.HeaderSizeFor(relayEndPoint.AddressFamily));
        _receiveTemplate = new IPEndPoint(
            udp.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

        // RFC 1928: the association ends when the control connection ends. This task
        // watches for that so a pending ReceiveAsync does not hang forever after the
        // proxy (or the peer) has already walked away.
        _controlWatcher = Task.Run(() => WatchControlConnectionAsync(_terminationCts.Token));
    }

    /// <inheritdoc />
    // The relay socket's own family decides the ceiling, and the SOCKS5 header eats into it:
    // every datagram this transport sends is header + payload on the wire, so a payload sized
    // against the bare maximum produces an oversized datagram and SocketError.MessageSize.
    public int MaxDatagramPayloadSize =>
        TlsQuicUdpDatagramTransport.MaximumFor(_udp.AddressFamily) - _headerSize;

    /// <summary>Connects to a SOCKS5 proxy and establishes a UDP association for relaying
    /// QUIC datagrams.</summary>
    /// <exception cref="ArgumentException"><see cref="TlsQuicSocks5Options.Username"/> and
    /// <see cref="TlsQuicSocks5Options.Password"/> were not both supplied or both
    /// omitted.</exception>
    /// <exception cref="TlsQuicProxyException">The proxy rejected the negotiation, the
    /// authentication, or the UDP ASSOCIATE request.</exception>
    public static async Task<ITlsQuicDatagramTransport> ConnectAsync(
        TlsQuicSocks5Options options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if ((options.Username is null) != (options.Password is null))
        {
            throw new ArgumentException(
                "Username and Password must both be supplied or both omitted.", nameof(options));
        }

        Socket? control = null;
        Socket? udp = null;
        try
        {
            control = await ConnectControlSocketAsync(options.ProxyEndPoint, cancellationToken)
                .ConfigureAwait(false);

            var proxy = (IPEndPoint)control.RemoteEndPoint!;

            udp = new Socket(proxy.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(
                proxy.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
            TlsQuicUdpDatagramTransport.SetDontFragment(udp, proxy.AddressFamily);

            await NegotiateAsync(control, options, cancellationToken).ConfigureAwait(false);
            var relayEndPoint = await AssociateAsync(control, proxy, cancellationToken).ConfigureAwait(false);

            var transport = new TlsQuicSocks5Transport(
                control, udp, relayEndPoint, options.DestinationHost);
            control = null;
            udp = null;
            return transport;
        }
        finally
        {
            udp?.Dispose();
            control?.Dispose();
        }
    }

    // Resolves a DnsEndPoint (TlsQuicSocks5Options documents that it is accepted) and
    // connects with a socket created for that exact address family. Deferring the family
    // to the OS (`new Socket(SocketType, ProtocolType)` + instance ConnectAsync) looks
    // equivalent but is not: on this platform it silently produces a dual-stack IPv6
    // socket even for a literal IPv4 target, so control.RemoteEndPoint reports
    // InterNetworkV6 — which then mismatches the IPv4 relay address a real SOCKS5
    // ASSOCIATE reply carries, and every UDP send fails with a family mismatch.
    private static async Task<Socket> ConnectControlSocketAsync(
        EndPoint proxyEndPoint, CancellationToken cancellationToken)
    {
        if (proxyEndPoint is DnsEndPoint dns)
        {
            var addresses = await System.Net.Dns
                .GetHostAddressesAsync(dns.Host, cancellationToken).ConfigureAwait(false);
            if (addresses.Length == 0)
            {
                throw new SocketException((int)SocketError.HostNotFound);
            }

            proxyEndPoint = new IPEndPoint(addresses[0], dns.Port);
        }

        var target = (IPEndPoint)proxyEndPoint;
        var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(target, cancellationToken).ConfigureAwait(false);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    // RFC 1928 s3 greeting/method-selection, then RFC 1929 s2 subnegotiation if selected.
    private static async Task NegotiateAsync(
        Socket control, TlsQuicSocks5Options options, CancellationToken cancellationToken)
    {
        var hasCredentials = options.Username is not null;

        // RFC 1928 s3: "The server selects from one of the methods given in METHODS" — the
        // server chooses, we don't get to hint. Offer MethodUsernamePassword only when we
        // actually hold credentials: offering it unconditionally would advertise a
        // capability we don't have, and a proxy configured to accept either method (a
        // common configuration) could then select username/password and fail a connection
        // that offering only MethodNoAuthentication would have let succeed.
        await WriteAsync(
            control, TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: hasCredentials), cancellationToken)
            .ConfigureAwait(false);

        var selection = await ReadExactAsync(control, 2, cancellationToken).ConfigureAwait(false);
        var method = TlsQuicSocks5Protocol.ParseMethodSelection(selection);

        switch (method)
        {
            case TlsQuicSocks5Protocol.MethodNoAuthentication:
                return;

            case TlsQuicSocks5Protocol.MethodUsernamePassword when hasCredentials:
                var request = TlsQuicSocks5Protocol.EncodeAuthenticationRequest(
                    options.Username!, options.Password!);
                try
                {
                    await WriteAsync(control, request, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    // The codec's comment is explicit: the returned buffer still holds the
                    // credentials, and the caller — us — must zero it once it has been
                    // written to the socket, even if the write itself failed.
                    CryptographicOperations.ZeroMemory(request);
                }

                var reply = await ReadExactAsync(control, 2, cancellationToken).ConfigureAwait(false);
                TlsQuicSocks5Protocol.ValidateAuthenticationReply(reply);
                return;

            // Unreachable against a compliant proxy: we never offer MethodUsernamePassword
            // without credentials (see the greeting above), and RFC 1928 s3 requires the
            // server to select only from what was offered. Kept as a defensive branch for
            // a non-compliant proxy that selects a method we didn't offer — not dead code.
            case TlsQuicSocks5Protocol.MethodUsernamePassword:
                throw new TlsQuicProxyException(
                    TlsQuicProxyError.CredentialsRequired,
                    "The SOCKS5 proxy requires username/password authentication but none were configured.");

            default:
                // RFC 1928 s3: METHOD 0xFF means none of the offered methods were
                // acceptable, and "the client MUST close the connection" — control.Dispose()
                // in ConnectAsync's finally handles that since this throw unwinds there.
                throw new TlsQuicProxyException(
                    TlsQuicProxyError.NoAcceptableAuthenticationMethod,
                    hasCredentials
                        ? $"The SOCKS5 proxy accepted none of the offered authentication methods " +
                          $"(selected 0x{method:X2})."
                        : "The SOCKS5 proxy accepted none of the offered authentication methods. No " +
                          "credentials were configured, so only 'no authentication' was offered; this proxy " +
                          "appears to require a username and password.");
        }
    }

    // RFC 1928 s4/s6: CMD is UDP ASSOCIATE; the reply carries the relay endpoint to send
    // encapsulated datagrams to.
    private static async Task<IPEndPoint> AssociateAsync(
        Socket control, IPEndPoint proxy, CancellationToken cancellationToken)
    {
        await WriteAsync(
            control, TlsQuicSocks5Protocol.EncodeAssociateRequest(proxy.AddressFamily), cancellationToken)
            .ConfigureAwait(false);

        byte[] header;
        try
        {
            header = await ReadExactAsync(control, 4, cancellationToken).ConfigureAwait(false);
        }
        catch (TlsQuicProxyException exception)
            when (exception.Error == TlsQuicProxyError.MalformedProxyResponse)
        {
            // Authentication already succeeded to get here, so the proxy speaks SOCKS5 and the
            // credentials are good — it closed on seeing CMD=UDP ASSOCIATE. That is the normal
            // behaviour of a TCP-only proxy, which most commercial residential pools are: they
            // implement CONNECT and nothing else. QUIC is UDP, so there is no client-side way
            // around it.
            throw new TlsQuicProxyException(
                TlsQuicProxyError.MalformedProxyResponse,
                "The SOCKS5 proxy closed the control connection without answering UDP ASSOCIATE. " +
                "Authentication had already succeeded, so this proxy almost certainly relays TCP " +
                "only and does not implement RFC 1928 section 7 UDP ASSOCIATE - which QUIC " +
                $"requires. Use a proxy that relays UDP, or a TCP version policy for this one. " +
                $"({exception.Message})");
        }

        var addressType = TlsQuicSocks5Protocol.ValidateAssociateReplyHeader(header);

        var addressLength = addressType == TlsQuicSocks5Protocol.AddressIPv6 ? 16 : 4;
        var tail = await ReadExactAsync(control, addressLength + 2, cancellationToken).ConfigureAwait(false);
        var port = BinaryPrimitives.ReadUInt16BigEndian(tail.AsSpan(addressLength, 2));

        return TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            addressType, tail.AsSpan(0, addressLength), port, proxy.Address);
    }

    private static ValueTask<int> WriteAsync(Socket control, byte[] buffer, CancellationToken cancellationToken) =>
        control.SendAsync(buffer, SocketFlags.None, cancellationToken);

    // Reads exactly `length` bytes or throws. A short read followed by a graceful close
    // is reported by name — how many of how many bytes arrived — rather than as a bare
    // IOException, since that is what a caller debugging a flaky proxy needs to see.
    private static async Task<byte[]> ReadExactAsync(Socket control, int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await control
                .ReceiveAsync(buffer.AsMemory(offset, length - offset), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw TlsQuicSocks5Protocol.Malformed(
                    $"SOCKS5 control connection closed after {offset} of {length} expected bytes.");
            }

            offset += read;
        }

        return buffer;
    }

    /// <inheritdoc />
    public async ValueTask SendAsync(
        IPEndPoint destination, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            payload.Length, MaxDatagramPayloadSize, nameof(payload));

        if (_terminationCts.IsCancellationRequested)
        {
            throw new TlsQuicProxyException(
                TlsQuicProxyError.AssociationTerminated,
                "The SOCKS5 UDP association has ended; the control connection closed.");
        }

        // Rented, not allocated: this is the per-datagram hot path.
        var rented = ArrayPool<byte>.Shared.Rent(_headerSize + payload.Length);
        try
        {
            // A proxy whose ruleset forbids literal-address destinations needs the name.
            var headerLength = _destinationHost is null
                ? TlsQuicSocks5Protocol.WriteUdpHeader(rented, destination)
                : TlsQuicSocks5Protocol.WriteUdpHeader(
                    rented, _destinationHost, destination.Port);
            payload.Span.CopyTo(rented.AsSpan(headerLength));

            await _udp
                .SendToAsync(
                    rented.AsMemory(0, headerLength + payload.Length),
                    SocketFlags.None,
                    _relayEndPoint,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <inheritdoc />
    public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer, CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, _terminationCts.Token);
        var scratchLength = _headerSize + buffer.Length;

        while (true)
        {
            var rented = ArrayPool<byte>.Shared.Rent(scratchLength);
            try
            {
                SocketReceiveFromResult result;
                try
                {
                    result = await _udp
                        .ReceiveFromAsync(
                            rented.AsMemory(0, scratchLength), SocketFlags.None, _receiveTemplate, linked.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (
                    !cancellationToken.IsCancellationRequested &&
                    _terminationCts.IsCancellationRequested &&
                    !_disposed)
                {
                    // The caller did not cancel and we are not mid-disposal, so the only
                    // remaining source of the internal token firing is the control watcher
                    // observing the control connection end.
                    throw new TlsQuicProxyException(
                        TlsQuicProxyError.AssociationTerminated,
                        "The SOCKS5 UDP association has ended; the control connection closed.");
                }

                // RFC 9000 s14: a datagram that fails validation is dropped and the receive
                // loop keeps waiting — never fatal, or any host reaching this UDP port could
                // kill the connection with one junk packet.
                if (!_relayEndPoint.Equals(result.RemoteEndPoint))
                {
                    continue;
                }

                if (!TlsQuicSocks5Protocol.TryReadUdpHeader(
                        rented.AsSpan(0, result.ReceivedBytes), out var origin, out var headerLength))
                {
                    continue;
                }

                var payloadLength = result.ReceivedBytes - headerLength;
                if (payloadLength > buffer.Length)
                {
                    continue;
                }

                rented.AsSpan(headerLength, payloadLength).CopyTo(buffer.Span);
                return new TlsQuicDatagramReceiveResult(payloadLength, origin);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    // RFC 1928: the association ends when the control connection ends. Any completion —
    // zero bytes, a byte, or a socket error — ends it; only the exceptions expected from
    // our own shutdown path are swallowed.
    private async Task WatchControlConnectionAsync(CancellationToken cancellationToken)
    {
        try
        {
            _ = await _control
                .ReceiveAsync(new byte[1], SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return; // Disposal already signalled termination.
        }
        catch (ObjectDisposedException)
        {
            return; // Disposal already signalled termination.
        }
        catch (SocketException)
        {
            // Disposal, or the peer resetting the connection, can surface this way instead
            // of a graceful zero-byte read — either way the association is over.
        }

        if (!cancellationToken.IsCancellationRequested)
        {
            await _terminationCts.CancelAsync().ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        await _terminationCts.CancelAsync().ConfigureAwait(false);

        // The UDP socket closes first: a pending ReceiveAsync then faults from that
        // disposal directly (see ITlsQuicDatagramTransport's remarks — the exact
        // exception is platform-dependent) rather than from the control connection
        // closing a moment later.
        _udp.Dispose();
        _control.Dispose();

        try
        {
            await _controlWatcher.ConfigureAwait(false);
        }
        catch
        {
            // WatchControlConnectionAsync already swallows the exceptions its own
            // shutdown path produces; this is a defensive backstop, not an expected path.
        }

        _terminationCts.Dispose();
    }
}
