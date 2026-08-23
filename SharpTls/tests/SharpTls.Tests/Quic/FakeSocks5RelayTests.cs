using System.Net;
using System.Net.Sockets;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class FakeSocks5RelayTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    [Fact]
    public async Task NoAuthHandshakeThenAssociateSucceeds()
    {
        await using var relay = FakeSocks5Relay.Start();
        using var control = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await control.ConnectAsync(relay.ProxyEndPoint).WaitAsync(Timeout);

        await control.SendAsync(TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: false))
            .WaitAsync(Timeout);
        var methodSelection = await ReadExactAsync(control, 2);
        Assert.Equal(TlsQuicSocks5Protocol.MethodNoAuthentication,
            TlsQuicSocks5Protocol.ParseMethodSelection(methodSelection));

        var associateEndPoint = await AssociateAsync(control, relay.ProxyEndPoint);
        Assert.Equal(relay.UdpEndPoint, associateEndPoint);

        AssertNoBackgroundException(relay);
    }

    [Fact]
    public async Task CredentialledHandshakeThenAssociateSucceeds()
    {
        await using var relay = FakeSocks5Relay.Start(username: "alice", password: "hunter2");
        using var control = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await control.ConnectAsync(relay.ProxyEndPoint).WaitAsync(Timeout);

        await control.SendAsync(TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: true))
            .WaitAsync(Timeout);
        var methodSelection = await ReadExactAsync(control, 2);
        Assert.Equal(TlsQuicSocks5Protocol.MethodUsernamePassword,
            TlsQuicSocks5Protocol.ParseMethodSelection(methodSelection));

        await control.SendAsync(TlsQuicSocks5Protocol.EncodeAuthenticationRequest("alice", "hunter2"))
            .WaitAsync(Timeout);
        var authReply = await ReadExactAsync(control, 2);
        TlsQuicSocks5Protocol.ValidateAuthenticationReply(authReply);

        var associateEndPoint = await AssociateAsync(control, relay.ProxyEndPoint);
        Assert.Equal(relay.UdpEndPoint, associateEndPoint);

        AssertNoBackgroundException(relay);
    }

    [Fact]
    public async Task GreetingOmittingTheConfiguredMethodIsRejected()
    {
        await using var relay = FakeSocks5Relay.Start(username: "alice", password: "hunter2");
        using var control = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await control.ConnectAsync(relay.ProxyEndPoint).WaitAsync(Timeout);

        // Offer only no-auth, even though the relay is configured to require credentials.
        await control.SendAsync(TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: false))
            .WaitAsync(Timeout);

        var methodSelection = await ReadExactAsync(control, 2);
        Assert.Equal(
            TlsQuicSocks5Protocol.MethodNone,
            TlsQuicSocks5Protocol.ParseMethodSelection(methodSelection));

        AssertNoBackgroundException(relay);
    }

    [Fact]
    public async Task RejectedCredentialsThrowAndCloseTheControlConnection()
    {
        await using var relay = FakeSocks5Relay.Start(username: "alice", password: "hunter2");
        using var control = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await control.ConnectAsync(relay.ProxyEndPoint).WaitAsync(Timeout);

        await control.SendAsync(TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: true))
            .WaitAsync(Timeout);
        _ = await ReadExactAsync(control, 2);

        await control.SendAsync(TlsQuicSocks5Protocol.EncodeAuthenticationRequest("alice", "wrong"))
            .WaitAsync(Timeout);
        var authReply = await ReadExactAsync(control, 2);

        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ValidateAuthenticationReply(authReply));
        Assert.Equal(TlsQuicProxyError.CredentialsRejected, exception.Error);

        // RFC 1929 requires the server to close the connection after a failed
        // authentication attempt. A pending read must observe that, not hang. Either a
        // graceful close (0 bytes) or a reset (throws) is an acceptable outcome — both
        // close through the same path as DropControlConnection().
        var probe = new byte[1];
        try
        {
            var read = await control.ReceiveAsync(probe, SocketFlags.None).WaitAsync(Timeout);
            Assert.Equal(0, read);
        }
        catch (SocketException)
        {
            // Connection reset is an equally valid outcome of a closed connection.
        }

        AssertNoBackgroundException(relay);
    }

    [Fact]
    public async Task WildcardBoundAddressIsSubstitutedWithTheProxyAddress()
    {
        await using var relay = FakeSocks5Relay.Start(wildcardBoundAddress: true);
        using var control = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await control.ConnectAsync(relay.ProxyEndPoint).WaitAsync(Timeout);

        await control.SendAsync(TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: false))
            .WaitAsync(Timeout);
        _ = await ReadExactAsync(control, 2);

        var associateEndPoint = await AssociateAsync(control, relay.ProxyEndPoint);

        Assert.Equal(relay.ProxyEndPoint.Address, associateEndPoint.Address);
        Assert.NotEqual(IPAddress.Any, associateEndPoint.Address);
        Assert.Equal(relay.UdpEndPoint.Port, associateEndPoint.Port);

        AssertNoBackgroundException(relay);
    }

    [Fact]
    public async Task DatagramRoundTripsThroughTheRelay()
    {
        await using var relay = FakeSocks5Relay.Start();
        using var control = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await control.ConnectAsync(relay.ProxyEndPoint).WaitAsync(Timeout);
        await control.SendAsync(TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: false))
            .WaitAsync(Timeout);
        _ = await ReadExactAsync(control, 2);
        await AssociateAsync(control, relay.ProxyEndPoint);

        using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        var destination = new IPEndPoint(IPAddress.Loopback, 4242);
        var payload = new byte[] { 9, 8, 7, 6 };
        var headerSize = TlsQuicSocks5Protocol.HeaderSizeFor(AddressFamily.InterNetwork);
        var datagram = new byte[headerSize + payload.Length];
        TlsQuicSocks5Protocol.WriteUdpHeader(datagram, destination);
        payload.CopyTo(datagram, headerSize);

        await udp.SendToAsync(datagram, SocketFlags.None, relay.UdpEndPoint).WaitAsync(Timeout);

        var buffer = new byte[512];
        var result = await udp.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0))
            .WaitAsync(Timeout);

        Assert.True(TlsQuicSocks5Protocol.TryReadUdpHeader(
            buffer.AsSpan(0, result.ReceivedBytes), out var origin, out var headerLength));
        Assert.Equal(destination, origin);
        Assert.Equal(payload, buffer[headerLength..result.ReceivedBytes]);

        AssertNoBackgroundException(relay);
    }

    [Fact]
    public async Task InjectedMalformedDatagramIsRejectedByTheCodec()
    {
        await using var relay = FakeSocks5Relay.Start();
        using var control = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await control.ConnectAsync(relay.ProxyEndPoint).WaitAsync(Timeout);
        await control.SendAsync(TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: false))
            .WaitAsync(Timeout);
        _ = await ReadExactAsync(control, 2);
        await AssociateAsync(control, relay.ProxyEndPoint);

        using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        // Teach the relay this client's UDP address with a normal round trip first.
        var destination = new IPEndPoint(IPAddress.Loopback, 4242);
        var headerSize = TlsQuicSocks5Protocol.HeaderSizeFor(AddressFamily.InterNetwork);
        var datagram = new byte[headerSize + 1];
        TlsQuicSocks5Protocol.WriteUdpHeader(datagram, destination);
        datagram[^1] = 42;
        await udp.SendToAsync(datagram, SocketFlags.None, relay.UdpEndPoint).WaitAsync(Timeout);
        var warmup = new byte[512];
        _ = await udp.ReceiveFromAsync(warmup, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0))
            .WaitAsync(Timeout);

        // A non-zero FRAG byte must be rejected: RFC 1928 s7 permits an
        // implementation without fragmentation support to drop it.
        var malformed = (byte[])datagram.Clone();
        malformed[2] = 0x01;
        relay.SendRaw(malformed);

        var buffer = new byte[512];
        var result = await udp.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0))
            .WaitAsync(Timeout);

        Assert.False(TlsQuicSocks5Protocol.TryReadUdpHeader(
            buffer.AsSpan(0, result.ReceivedBytes), out _, out _));

        AssertNoBackgroundException(relay);
    }

    [Fact]
    public async Task DroppingTheControlConnectionEndsThePendingRead()
    {
        await using var relay = FakeSocks5Relay.Start();
        using var control = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await control.ConnectAsync(relay.ProxyEndPoint).WaitAsync(Timeout);
        await control.SendAsync(TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: false))
            .WaitAsync(Timeout);
        _ = await ReadExactAsync(control, 2);
        await AssociateAsync(control, relay.ProxyEndPoint);

        var probe = new byte[1];
        var pending = control.ReceiveAsync(probe, SocketFlags.None);

        relay.DropControlConnection();

        // Either a graceful close (0 bytes) or a reset (throws) is acceptable —
        // the only requirement is that the pending read does not hang.
        try
        {
            var read = await pending.WaitAsync(Timeout);
            Assert.Equal(0, read);
        }
        catch (SocketException)
        {
            // Connection reset is an equally valid outcome of a dropped connection.
        }

        AssertNoBackgroundException(relay);
    }

    // The background loops swallow expected shutdown exceptions but capture anything
    // else, so a loop that dies would otherwise just look like the client hanging —
    // this turns that into a clear assertion failure instead.
    private static void AssertNoBackgroundException(FakeSocks5Relay relay) =>
        Assert.Null(relay.BackgroundException);

    private static async Task<IPEndPoint> AssociateAsync(Socket control, IPEndPoint proxyEndPoint)
    {
        await control.SendAsync(TlsQuicSocks5Protocol.EncodeAssociateRequest(AddressFamily.InterNetwork))
            .WaitAsync(Timeout);

        var header = await ReadExactAsync(control, 4);
        var atyp = TlsQuicSocks5Protocol.ValidateAssociateReplyHeader(header);
        var addressLength = atyp == TlsQuicSocks5Protocol.AddressIPv6 ? 16 : 4;
        var addressAndPort = await ReadExactAsync(control, addressLength + 2);

        var port = (ushort)((addressAndPort[^2] << 8) | addressAndPort[^1]);
        return TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            atyp, addressAndPort.AsSpan(0, addressLength), port, proxyEndPoint.Address);
    }

    private static async Task<byte[]> ReadExactAsync(Socket socket, int length)
    {
        var buffer = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await socket.ReceiveAsync(buffer.AsMemory(offset, length - offset), SocketFlags.None)
                .AsTask().WaitAsync(Timeout);
            if (read == 0)
            {
                throw new IOException("Control connection closed before the expected reply arrived.");
            }

            offset += read;
        }

        return buffer;
    }
}
