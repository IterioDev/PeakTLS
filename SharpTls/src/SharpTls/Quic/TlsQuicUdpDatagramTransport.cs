using System.Net;
using System.Net.Sockets;

namespace SharpTls.Quic;

/// <summary>Sends and receives QUIC datagrams directly over a UDP socket.</summary>
public sealed class TlsQuicUdpDatagramTransport : ITlsQuicDatagramTransport
{
    // RFC 9000 s18.2: 65527 is the maximum permitted UDP payload.
    internal const int MaximumUdpPayload = 65527;

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
            return new TlsQuicUdpDatagramTransport(socket);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public int MaxDatagramPayloadSize => MaximumUdpPayload;

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
