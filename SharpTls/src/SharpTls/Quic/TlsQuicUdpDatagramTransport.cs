using System.Net;
using System.Net.Sockets;

namespace SharpTls.Quic;

/// <summary>Sends and receives QUIC datagrams directly over a UDP socket.</summary>
public sealed class TlsQuicUdpDatagramTransport : ITlsQuicDatagramTransport
{
    // RFC 9000 s18.2: 65527 is the maximum permitted UDP payload, and it is reachable only
    // over IPv6. This is the protocol ceiling, NOT what every socket accepts - see
    // MaximumFor.
    internal const int MaximumUdpPayload = 65527;

    // 65535 - 20 (IPv4 header) - 8 (UDP header). An IPv4 socket refuses anything larger with
    // WSAEMSGSIZE / SocketError.MessageSize, so advertising the 65527 IPv6 figure on an IPv4
    // transport overstates the ceiling by 20 bytes and turns a caller's legal-looking datagram
    // into a socket exception. Measured, not assumed: an IPv4 SendTo of 65507 succeeds and
    // 65508 fails with MessageSize (10040).
    internal const int MaximumIPv4UdpPayload = 65507;

    /// <summary>The largest UDP payload the given family's sockets actually accept.</summary>
    internal static int MaximumFor(AddressFamily family) =>
        family == AddressFamily.InterNetworkV6 ? MaximumUdpPayload : MaximumIPv4UdpPayload;

    private readonly Socket _socket;
    private readonly IPEndPoint _receiveTemplate;
    private bool _disposed;

    private TlsQuicUdpDatagramTransport(Socket socket)
    {
        _socket = socket;
        _receiveTemplate = new IPEndPoint(
            socket.AddressFamily == AddressFamily.InterNetworkV6
                ? IPAddress.IPv6Any
                : IPAddress.Any,
            0);
    }

    /// <summary>Creates a transport bound to an ephemeral port of the given family.</summary>
    public static ITlsQuicDatagramTransport Create(AddressFamily family)
    {
        var socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.Bind(new IPEndPoint(
                family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
            SetDontFragment(socket, family);
            DisableUdpConnectionReset(socket);
            return new TlsQuicUdpDatagramTransport(socket);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public int MaxDatagramPayloadSize => MaximumFor(_socket.AddressFamily);

    /// <summary>Windows' SIO_UDP_CONNRESET, 0x9800000C.</summary>
    private const int SioUdpConnectionReset = unchecked((int)0x9800000C);

    /// <summary>
    /// Stops Windows turning an inbound ICMP Port Unreachable into a failure on the NEXT
    /// receive.
    /// </summary>
    /// <remarks>
    /// <para>WINDOWS ONLY, AND IT IS A RECEIVE-SIDE BUG WITH A SEND-SIDE CAUSE. When a UDP
    /// datagram this socket sent draws an ICMP Port Unreachable, Windows remembers it and
    /// fails the socket's next RECEIVE with WSAECONNRESET (10054) - for a datagram that has
    /// nothing to do with the one that bounced. Every other platform ignores the ICMP on an
    /// unconnected UDP socket, which is why the symptom is Windows-only.</para>
    /// <para>WHY IT LOOKS LIKE A BUFFER PROBLEM AND IS NOT. The failure surfaces as an
    /// exception out of a receive call, so a field report naturally describes it as a
    /// "receive-buffer exception" - and because the following receive succeeds, it also
    /// self-recovers, which makes it look transient rather than structural. Neither the buffer
    /// nor its size is involved: WSAEMSGSIZE (10040) is the size error and is a different
    /// code, fixed on the send side by bounding every datagram to the path MTU.</para>
    /// <para>WHY CONCURRENCY MAKES IT WORSE. One bounced datagram poisons one socket's next
    /// receive, so the rate scales with the number of sockets and with how often a peer or a
    /// SOCKS5 relay is unreachable for a moment. At one connection it is invisible; at a
    /// hundred it is a steady trickle of exceptions and retries.</para>
    /// <para>RFC 9000 s10.2.2 has the protocol half of the same rule: an endpoint MUST NOT
    /// treat an ICMP message as a connection error, because it is unauthenticated - anyone on
    /// the path can forge one. Letting one end a receive is exactly that treatment.</para>
    /// </remarks>
    /// <param name="socket">The datagram socket, before first use.</param>
    internal static void DisableUdpConnectionReset(Socket socket)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            socket.IOControl(SioUdpConnectionReset, [0, 0, 0, 0], null);
        }
        catch (SocketException)
        {
            // An older stack, or a socket type that refuses the control code. The caller is no
            // worse off than before this line existed.
        }
        catch (PlatformNotSupportedException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    // Sets the IPv4 Don't Fragment bit, which RFC 9000 s14 requires where the platform
    // supports it. IPv6 routers do not fragment, so the flag does not apply there.
    internal static void SetDontFragment(Socket socket, AddressFamily family)
    {
        if (family != AddressFamily.InterNetwork)
        {
            return;
        }

        try
        {
            socket.DontFragment = true;
        }
        catch (SocketException)
        {
            // The platform refused. QUIC still bounds datagrams to 1200 bytes until
            // path MTU discovery raises the limit, so this is not fatal.
        }
        catch (NotSupportedException)
        {
        }
    }

    /// <inheritdoc />
    public async ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            payload.Length, MaxDatagramPayloadSize, nameof(payload));

        _ = await _socket
            .SendToAsync(payload, SocketFlags.None, destination, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var result = await _socket
            .ReceiveFromAsync(buffer, SocketFlags.None, _receiveTemplate, cancellationToken)
            .ConfigureAwait(false);

        return new TlsQuicDatagramReceiveResult(
            result.ReceivedBytes, (IPEndPoint)result.RemoteEndPoint);
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;
            _socket.Dispose();
        }

        return ValueTask.CompletedTask;
    }
}
