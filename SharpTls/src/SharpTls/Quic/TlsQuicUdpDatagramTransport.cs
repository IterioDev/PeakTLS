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

    // Volatile because DisposeAsync and a pending SendAsync/ReceiveAsync are routinely on
    // different threads: the pump awaits the receive while whoever owns the connection's
    // lifetime disposes. The exception filters below read this flag to tell a teardown from a
    // network error, so a stale read would misclassify the very race it exists to classify.
    private volatile bool _disposed;

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

    /// <summary>
    /// True for the two shapes a socket teardown takes under a pending operation, and for no
    /// network condition at all.
    /// </summary>
    /// <remarks>
    /// <para>WSA_OPERATION_ABORTED (995) IS A LIFECYCLE EVENT WEARING A NETWORK ERROR'S
    /// CLOTHES. Winsock defines it as "The I/O operation has been aborted because of either a
    /// thread exit or an application request", and .NET surfaces it as
    /// <see cref="SocketError.OperationAborted"/>. On a UDP socket only two things in this
    /// process can produce it: closing the handle while an overlapped receive is posted, or
    /// CancelIoEx against that receive - which is exactly what .NET's own cancellation support
    /// for the ValueTask socket overloads calls. No peer, no router and no ICMP message can
    /// cause it, so nothing diagnostic is lost by translating it.</para>
    /// <para>WHY .NET DOES NOT ALREADY TRANSLATE IT ON THE PATH THAT MATTERS.
    /// SocketAsyncEventArgs turns OperationAborted into an
    /// <see cref="OperationCanceledException"/> only by calling ThrowIfCancellationRequested on
    /// the token the operation was started with. When the abort came from Dispose rather than
    /// from that token, the token is NOT cancelled, the call falls through, and the raw
    /// <see cref="SocketException"/> reaches the caller. That is the reported defect: a second
    /// connection's transport is disposed under a pending receive and the pump sees
    /// "SocketException: I/O operation aborted" instead of a shutdown.</para>
    /// <para>DELIBERATELY NARROW. <see cref="SocketError.ConnectionReset"/> (10054, which
    /// <see cref="DisableUdpConnectionReset"/> suppresses at its ICMP source) and
    /// <see cref="SocketError.MessageSize"/> (10040, which TlsQuicConnection catches by name to
    /// report a datagram the host refused) are real answers from the stack about real
    /// datagrams. Widening this predicate to "any SocketException during teardown" would eat
    /// both.</para>
    /// </remarks>
    /// <param name="exception">The exception a socket call produced.</param>
    internal static bool IsTeardownFault(Exception exception) =>
        exception is ObjectDisposedException
            || (exception is SocketException socket
                && socket.SocketErrorCode == SocketError.OperationAborted);

    // Which teardown happened decides the shape, and the two answers are not
    // interchangeable to a caller.
    //
    // A CALLER'S CANCELLATION IS ROUTINE, NOT EXCEPTIONAL. The pump loop cancels a pending
    // receive with an interrupt token on every ordinary shutdown, so it must arrive as the
    // cancellation shape the rest of this namespace uses. TlsQuicConnection's
    // ReceiveWithinDeadlineAsync catches OperationCanceledException and separates a deadline
    // cancel from a caller cancel by testing the two token sources rather than the exception,
    // so carrying `cancellationToken` here keeps that distinction intact: a caller cancel
    // fails its `!cancellationToken.IsCancellationRequested` guard and propagates, exactly as
    // it did before this translation existed.
    //
    // A DISPOSAL IS STILL A FAULT, JUST NOT A PLATFORM-SPECIFIC ONE.
    // ITlsQuicDatagramTransport.ReceiveAsync promises that disposing under a pending call
    // faults it, and ObjectDisposedException is what every .NET type raises for use after
    // dispose - the same exception a receive STARTED after DisposeAsync already gets, so the
    // two orderings of the same race now agree instead of differing by platform.
    private static Exception TranslateTeardown(
        Exception cause, CancellationToken cancellationToken) =>
        cancellationToken.IsCancellationRequested
            ? new OperationCanceledException(
                "The QUIC datagram socket operation was cancelled.", cause, cancellationToken)
            : new ObjectDisposedException(
                nameof(TlsQuicUdpDatagramTransport),
                "The QUIC datagram transport was disposed while a socket operation was "
                    + "pending.");

    /// <inheritdoc />
    public async ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            payload.Length, MaxDatagramPayloadSize, nameof(payload));

        try
        {
            _ = await _socket
                .SendToAsync(payload, SocketFlags.None, destination, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (IsTeardownFault(exception)
            && (cancellationToken.IsCancellationRequested || _disposed))
        {
            // THE SEND HAS THE SAME EXPOSURE AS THE RECEIVE, AND IT IS SMALLER ONLY BY LUCK. A
            // UDP send usually completes into the driver without pending, so the window is
            // narrow - but it is the same window, and the pump sends under the same interrupt
            // token it receives under. The filter's `IsTeardownFault` leaves SocketError
            // .MessageSize untouched, which is load-bearing: TlsQuicConnection catches that
            // one by name to report a datagram the host refused, and swallowing it here would
            // silently disable path MTU discovery's only feedback.
            throw TranslateTeardown(exception, cancellationToken);
        }
    }

    /// <inheritdoc />
    public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        SocketReceiveFromResult result;
        try
        {
            result = await _socket
                .ReceiveFromAsync(buffer, SocketFlags.None, _receiveTemplate, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (IsTeardownFault(exception)
            && (cancellationToken.IsCancellationRequested || _disposed))
        {
            // THE FILTER'S SECOND HALF IS WHAT KEEPS THIS HONEST. Without it a 995 arriving
            // with neither the caller cancelling nor this transport disposed - a thread exit,
            // which is the other cause Winsock names - would be relabelled as a disposal this
            // type never performed. Such a fault falls through unchanged instead.
            //
            // TlsQuicDatagramTransportTests.DisposingWhileAReceiveIsPendingSurfacesAsDisposal
            // and TlsQuicDatagramTransportTests.CancellingAPendingReceiveSurfacesAsCancellation
            // pin the two branches; without this catch the first sees SocketException 995.
            throw TranslateTeardown(exception, cancellationToken);
        }

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
