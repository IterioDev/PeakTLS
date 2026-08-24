using System.Net;
using System.Net.Sockets;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

/// <content>
/// Windows' SIO_UDP_CONNRESET, and the field report that named it wrongly.
///
/// THE REPORT SAID "SOCKS5-UDP recv-buffer exception fires and self-recovers" at a hundred
/// threads. Neither half of that names the cause. The buffer is not involved - WSAEMSGSIZE
/// (10040) is the size error and lives on the send side - and it self-recovers because the
/// poison is one-shot: Windows fails exactly ONE receive per ICMP Port Unreachable it saw, and
/// the next one succeeds. What scales with thread count is the number of sockets, not the size
/// of anything.
/// </content>
public sealed class TlsQuicUdpConnectionResetTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(5);

    /// <summary>A port on the loopback interface with nothing listening on it.</summary>
    private static int ClosedLoopbackPort()
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    [Fact]
    public async Task AnIcmpUnreachableDoesNotPoisonTheNextReceive()
    {
        // WINDOWS ONLY, AND SKIPPED RATHER THAN FAKED ELSEWHERE. Every other platform ignores
        // an ICMP error on an unconnected UDP socket, so on Linux and macOS this test would
        // pass without the fix and prove nothing.
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var receiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        receiver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        TlsQuicUdpDatagramTransport.DisableUdpConnectionReset(receiver);

        // STEP 1: draw the ICMP. A datagram to a closed loopback port comes back as Port
        // Unreachable, and it is that reply Windows would otherwise hold against the next
        // receive on this socket.
        var closed = new IPEndPoint(IPAddress.Loopback, ClosedLoopbackPort());
        await receiver.SendToAsync(new byte[] { 1, 2, 3 }, SocketFlags.None, closed);

        // Give the stack a moment to deliver the ICMP, so the test is about the fix rather
        // than about winning a race with it.
        await Task.Delay(100);

        // STEP 2: a real datagram from somebody else. Without the control code this receive
        // throws SocketException(ConnectionReset) instead of returning it.
        using var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        await sender.SendToAsync(
            new byte[] { 4, 5, 6, 7 }, SocketFlags.None, (IPEndPoint)receiver.LocalEndPoint!);

        using var cancellation = new CancellationTokenSource(Bound);
        var buffer = new byte[64];
        var result = await receiver.ReceiveFromAsync(
            buffer,
            SocketFlags.None,
            new IPEndPoint(IPAddress.Any, 0),
            cancellation.Token);

        Assert.Equal(4, result.ReceivedBytes);
        Assert.Equal(new byte[] { 4, 5, 6, 7 }, buffer[..result.ReceivedBytes]);
    }

    [Fact]
    public void TheControlCodeIsAppliedWithoutThrowingOnAnyPlatform()
    {
        // The call is best-effort by design - an older stack may refuse the code - so the one
        // thing every platform must agree on is that asking never throws.
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        TlsQuicUdpDatagramTransport.DisableUdpConnectionReset(socket);
        TlsQuicUdpDatagramTransport.DisableUdpConnectionReset(socket);
    }

    [Fact]
    public void ADisposedSocketIsNotAFailure()
    {
        // Create() applies this between Bind and first use, but a caller racing a dispose must
        // not turn a shutdown into an exception from a best-effort tuning call.
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Dispose();

        TlsQuicUdpDatagramTransport.DisableUdpConnectionReset(socket);
    }
}
