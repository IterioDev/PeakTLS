using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

/// <summary>A deterministic, offline SOCKS5 relay for driving the codec over real sockets.
/// Speaks just enough of RFC 1928 / RFC 1929 to exercise a client end to end: one control
/// connection, one UDP ASSOCIATE, and an echoing UDP relay. Not a general-purpose proxy.</summary>
internal sealed class FakeSocks5Relay : IAsyncDisposable
{
    private readonly TcpListener _controlListener;
    private readonly Socket _udpSocket;
    private readonly string? _username;
    private readonly string? _password;
    private readonly bool _wildcardBoundAddress;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptTask;
    private readonly Task _udpTask;
    private volatile Socket? _controlSocket;
    private volatile EndPoint? _lastClientUdpEndPoint;
    private Exception? _backgroundException;
    private bool _disposed;

    private FakeSocks5Relay(
        TcpListener controlListener,
        Socket udpSocket,
        string? username,
        string? password,
        bool wildcardBoundAddress)
    {
        _controlListener = controlListener;
        _udpSocket = udpSocket;
        _username = username;
        _password = password;
        _wildcardBoundAddress = wildcardBoundAddress;
        ProxyEndPoint = (IPEndPoint)controlListener.LocalEndpoint;
        UdpEndPoint = (IPEndPoint)udpSocket.LocalEndPoint!;

        // ponytail: one connection, one relay socket, no pooling — this is a test double,
        // not a real proxy. Add multi-connection support if a future test needs it.
        _acceptTask = Task.Run(() => AcceptLoopAsync(_cts.Token));
        _udpTask = Task.Run(() => UdpLoopAsync(_cts.Token));
    }

    /// <summary>Starts a relay bound to loopback ephemeral ports.</summary>
    internal static FakeSocks5Relay Start(
        string? username = null,
        string? password = null,
        bool wildcardBoundAddress = false)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        return new FakeSocks5Relay(listener, udpSocket, username, password, wildcardBoundAddress);
    }

    /// <summary>Gets the TCP control listener's endpoint.</summary>
    internal IPEndPoint ProxyEndPoint { get; }

    /// <summary>Gets the UDP relay socket's endpoint.</summary>
    internal IPEndPoint UdpEndPoint { get; }

    /// <summary>Gets an exception captured from a background loop, if one occurred outside
    /// an expected shutdown path. Tests can assert this stays null. The first failure wins
    /// so a cascade doesn't overwrite the interesting one.</summary>
    internal Exception? BackgroundException => _backgroundException;

    /// <summary>Closes the control connection, simulating the proxy dropping the association.</summary>
    internal void DropControlConnection() => _controlSocket?.Dispose();

    /// <summary>Sends raw bytes from the relay's UDP socket to the last client that sent it
    /// a datagram. Requires a prior round trip so the relay has learned the client's address.</summary>
    internal void SendRaw(byte[] datagram)
    {
        var target = _lastClientUdpEndPoint
            ?? throw new InvalidOperationException(
                "SendRaw requires a prior datagram from the client so the relay knows where to send.");
        _udpSocket.SendTo(datagram, target);
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var socket = await _controlListener.AcceptSocketAsync(cancellationToken)
                .ConfigureAwait(false);
            _controlSocket = socket;
            await HandleControlConnectionAsync(socket, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (SocketException)
        {
            // Disposal can surface as a SocketException instead of ObjectDisposedException
            // on some platforms/timings — an expected shutdown either way.
        }
        catch (Exception ex)
        {
            Interlocked.CompareExchange(ref _backgroundException, ex, null);
        }
    }

    private async Task HandleControlConnectionAsync(Socket socket, CancellationToken cancellationToken)
    {
        // RFC 1928 s3: VER | NMETHODS | METHODS...
        var greetingHeader = await ReadExactAsync(socket, 2, cancellationToken).ConfigureAwait(false);
        var offeredMethods = await ReadExactAsync(socket, greetingHeader[1], cancellationToken).ConfigureAwait(false);

        var requiresCredentials = _username is not null;
        var desiredMethod = requiresCredentials
            ? TlsQuicSocks5Protocol.MethodUsernamePassword
            : TlsQuicSocks5Protocol.MethodNoAuthentication;

        // A real server validates the offer instead of trusting its own configuration —
        // a client that miscounts NMETHODS or omits a method must fail here too, not
        // pass against this double and only then fail against a real relay.
        if (!offeredMethods.Contains(desiredMethod))
        {
            await socket.SendAsync(
                new byte[] { TlsQuicSocks5Protocol.Version, TlsQuicSocks5Protocol.MethodNone },
                SocketFlags.None,
                cancellationToken).ConfigureAwait(false);
            return; // RFC 1928 s3: NO ACCEPTABLE METHODS closes the connection.
        }

        await socket.SendAsync(
            new byte[] { TlsQuicSocks5Protocol.Version, desiredMethod },
            SocketFlags.None,
            cancellationToken).ConfigureAwait(false);

        if (requiresCredentials)
        {
            var authenticated = await AuthenticateAsync(socket, cancellationToken).ConfigureAwait(false);
            if (!authenticated)
            {
                return; // RFC 1929 s2: close the connection after a failed attempt.
            }
        }

        await ReplyToAssociateAsync(socket, cancellationToken).ConfigureAwait(false);

        // Hold the control connection open so tests can observe DropControlConnection().
        try
        {
            _ = await socket.ReceiveAsync(new byte[1], SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SocketException)
        {
            // The client (or DropControlConnection) reset the connection — an expected
            // end of the control channel, not a relay bug.
        }
    }

    // RFC 1929 s2: VER | ULEN | UNAME | PLEN | PASSWD, replies VER | STATUS.
    private async Task<bool> AuthenticateAsync(Socket socket, CancellationToken cancellationToken)
    {
        var header = await ReadExactAsync(socket, 2, cancellationToken).ConfigureAwait(false);
        var username = Encoding.UTF8.GetString(
            await ReadExactAsync(socket, header[1], cancellationToken).ConfigureAwait(false));
        var passwordLength = (await ReadExactAsync(socket, 1, cancellationToken).ConfigureAwait(false))[0];
        var password = Encoding.UTF8.GetString(
            await ReadExactAsync(socket, passwordLength, cancellationToken).ConfigureAwait(false));

        var success = username == _username && password == _password;
        await socket.SendAsync(
            new byte[] { TlsQuicSocks5Protocol.AuthenticationVersion, success ? (byte)0x00 : (byte)0x01 },
            SocketFlags.None,
            cancellationToken).ConfigureAwait(false);
        return success;
    }

    // RFC 1928 s4/s6: reads VER|CMD|RSV|ATYP|DST.ADDR|DST.PORT, replies
    // VER|REP|RSV|ATYP|BND.ADDR|BND.PORT with the relay's own UDP endpoint.
    private async Task ReplyToAssociateAsync(Socket socket, CancellationToken cancellationToken)
    {
        var requestHeader = await ReadExactAsync(socket, 4, cancellationToken).ConfigureAwait(false);
        var addressLength = requestHeader[3] switch
        {
            TlsQuicSocks5Protocol.AddressIPv4 => 4,
            TlsQuicSocks5Protocol.AddressIPv6 => 16,
            var atyp => throw new InvalidOperationException(
                $"FakeSocks5Relay does not support ATYP 0x{atyp:X2} in the ASSOCIATE request."),
        };
        _ = await ReadExactAsync(socket, addressLength + 2, cancellationToken).ConfigureAwait(false);

        var boundAddress = _wildcardBoundAddress
            ? IPAddress.Any.GetAddressBytes()
            : UdpEndPoint.Address.GetAddressBytes();

        var reply = new byte[4 + boundAddress.Length + 2];
        reply[0] = TlsQuicSocks5Protocol.Version;
        reply[1] = 0x00; // REP: succeeded
        reply[2] = 0x00; // RSV
        reply[3] = TlsQuicSocks5Protocol.AddressIPv4;
        boundAddress.CopyTo(reply, 4);
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(4 + boundAddress.Length), (ushort)UdpEndPoint.Port);

        await socket.SendAsync(reply, SocketFlags.None, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReadExactAsync(Socket socket, int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await socket
                .ReceiveAsync(buffer.AsMemory(offset, length - offset), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException("Control connection closed while a reply was expected.");
            }

            offset += read;
        }

        return buffer;
    }

    private async Task UdpLoopAsync(CancellationToken cancellationToken)
    {
        // ponytail: fixed 64KiB scratch buffer, reused every iteration — this is a test
        // double handling one client at a time, not a pooled server.
        var buffer = new byte[ushort.MaxValue];
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var result = await _udpSocket
                    .ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), cancellationToken)
                    .ConfigureAwait(false);

                _lastClientUdpEndPoint = result.RemoteEndPoint;

                // Echo the datagram back verbatim, header included: the client can then
                // decapsulate it and see the destination it sent to, proving round trip.
                await _udpSocket
                    .SendToAsync(
                        buffer.AsMemory(0, result.ReceivedBytes),
                        SocketFlags.None,
                        result.RemoteEndPoint,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (SocketException)
        {
            // Same rationale as the accept loop: disposal can surface this way too.
        }
        catch (Exception ex)
        {
            Interlocked.CompareExchange(ref _backgroundException, ex, null);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        await _cts.CancelAsync().ConfigureAwait(false);
        _controlListener.Stop();
        _controlSocket?.Dispose();
        _udpSocket.Dispose();

        await Task.WhenAll(_acceptTask, _udpTask).ConfigureAwait(false);
        _cts.Dispose();
    }
}
