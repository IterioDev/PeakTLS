using System.Net;
using System.Net.Sockets;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicDatagramTransportTests
{
    [Fact]
    public async Task DirectTransportRoundTripsADatagram()
    {
        using var peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        peer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var peerEndPoint = (IPEndPoint)peer.LocalEndPoint!;

        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        await transport.SendAsync(peerEndPoint, new byte[] { 1, 2, 3 }, CancellationToken.None);

        var received = new byte[16];
        var result = await peer
            .ReceiveFromAsync(received, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0))
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(3, result.ReceivedBytes);
        Assert.Equal(new byte[] { 1, 2, 3 }, received[..3]);
    }

    [Fact]
    public async Task DirectTransportReceivesAndReportsTheSender()
    {
        using var peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        peer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var peerEndPoint = (IPEndPoint)peer.LocalEndPoint!;

        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        // Provoke the transport into revealing its bound port by sending first.
        await transport.SendAsync(peerEndPoint, new byte[] { 7 }, CancellationToken.None);
        var probe = new byte[8];
        var probeResult = await peer
            .ReceiveFromAsync(probe, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0))
            .WaitAsync(TimeSpan.FromSeconds(5));

        peer.SendTo(new byte[] { 4, 5 }, probeResult.RemoteEndPoint);

        var buffer = new byte[16];
        var received = await transport.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(2, received.Length);
        Assert.Equal(new byte[] { 4, 5 }, buffer[..2]);
        Assert.Equal(peerEndPoint, received.RemoteEndPoint);
    }

    [Fact]
    public async Task DirectTransportRejectsAnOversizedPayload()
    {
        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await transport.SendAsync(
                new IPEndPoint(IPAddress.Loopback, 9),
                new byte[transport.MaxDatagramPayloadSize + 1],
                CancellationToken.None));
    }

    [Fact]
    public async Task DirectTransportCeilingIsTheMaximumUdpPayload()
    {
        // RFC 9000 s18.2 names 65527 as the maximum permitted UDP payload.
        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        Assert.Equal(65527, transport.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task DirectTransportSupportsIPv6()
    {
        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetworkV6);

        Assert.Equal(65527, transport.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task DisposingTwiceIsSafe()
    {
        var transport = TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        await transport.DisposeAsync();
        await transport.DisposeAsync();
    }

    [Fact]
    public async Task DisposingWhileReceivePendingFaultsTheReceive()
    {
        var transport = TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);
        var pending = transport.ReceiveAsync(new byte[64], CancellationToken.None).AsTask();

        await transport.DisposeAsync();

        // The exact type is platform-dependent, so assert only that it faults
        // and does not hang. Consumers must treat this as shutdown, not as a
        // protocol error.
        await Assert.ThrowsAnyAsync<Exception>(
            async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task ReceiveHonoursCancellation()
    {
        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        using var cts = new CancellationTokenSource();
        var pending = transport.ReceiveAsync(new byte[64], cts.Token).AsTask();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Theory]
    [InlineData("user", null)]
    [InlineData(null, "pass")]
    public async Task Socks5OptionsRejectHalfSuppliedCredentials(string? user, string? pass)
    {
        var options = new TlsQuicSocks5Options
        {
            ProxyEndPoint = new IPEndPoint(IPAddress.Loopback, 1080),
            Username = user,
            Password = pass,
        };

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await TlsQuicSocks5Transport.ConnectAsync(options, CancellationToken.None));
    }

    [Fact]
    public async Task RelayedTransportRoundTripsADatagram()
    {
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        var origin = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443);
        await transport.SendAsync(origin, new byte[] { 9, 8, 7 }, CancellationToken.None);

        var buffer = new byte[64];
        var result = await transport.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(3, result.Length);
        Assert.Equal(new byte[] { 9, 8, 7 }, buffer[..3]);
        Assert.Equal(origin, result.RemoteEndPoint);
        Assert.Null(relay.BackgroundException);
    }

    [Fact]
    public async Task RelayedTransportAuthenticatesWithCredentials()
    {
        await using var relay = FakeSocks5Relay.Start("alice", "s3cret");
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options
            {
                ProxyEndPoint = relay.ProxyEndPoint,
                Username = "alice",
                Password = "s3cret",
            },
            CancellationToken.None);

        var origin = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443);
        await transport.SendAsync(origin, new byte[] { 1 }, CancellationToken.None);
        var buffer = new byte[16];
        var result = await transport.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, result.Length);
        Assert.Null(relay.BackgroundException);
    }

    [Fact]
    public async Task RelayedTransportReportsRejectedCredentials()
    {
        await using var relay = FakeSocks5Relay.Start("alice", "s3cret");

        var exception = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await TlsQuicSocks5Transport.ConnectAsync(
                new TlsQuicSocks5Options
                {
                    ProxyEndPoint = relay.ProxyEndPoint,
                    Username = "alice",
                    Password = "wrong",
                },
                CancellationToken.None));

        Assert.Equal(TlsQuicProxyError.CredentialsRejected, exception.Error);
    }

    [Fact]
    public async Task RelayedTransportReportsNoAcceptableMethodWhenCredentialsAreMissing()
    {
        await using var relay = FakeSocks5Relay.Start("alice", "s3cret");

        // A credential-less client offers only MethodNoAuthentication (RFC 1928 s3: the
        // server selects only from what was offered), so a proxy that requires
        // credentials replies MethodNone (0xFF), not a MethodUsernamePassword selection.
        var exception = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await TlsQuicSocks5Transport.ConnectAsync(
                new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
                CancellationToken.None));

        Assert.Equal(TlsQuicProxyError.NoAcceptableAuthenticationMethod, exception.Error);
    }

    [Fact]
    public async Task RelayedTransportSubstitutesAWildcardBoundAddress()
    {
        await using var relay = FakeSocks5Relay.Start(wildcardBoundAddress: true);
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        // If substitution failed the datagram goes to 0.0.0.0 and never returns.
        var origin = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443);
        await transport.SendAsync(origin, new byte[] { 1 }, CancellationToken.None);

        var buffer = new byte[16];
        var result = await transport.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, result.Length);
        Assert.Null(relay.BackgroundException);
    }

    [Fact]
    public async Task DroppingTheControlConnectionEndsTheAssociation()
    {
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        relay.DropControlConnection();

        var exception = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await transport.ReceiveAsync(new byte[64], CancellationToken.None)
                .AsTask().WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Equal(TlsQuicProxyError.AssociationTerminated, exception.Error);
    }

    [Theory]
    // FRAG != 0 must be dropped.
    [InlineData(new byte[] { 0x00, 0x00, 0x01, 0x01, 203, 0, 113, 9, 0x01, 0xBB, 0xAA })]
    // RSV != 0 must be dropped.
    [InlineData(new byte[] { 0x00, 0x01, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xBB, 0xAA })]
    // Header overruns the datagram.
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x01, 203, 0, 113 })]
    public async Task MalformedRelayedDatagramsAreDroppedNotFatal(byte[] hostile)
    {
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        var origin = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443);

        // Prime the relay so it learns the client's UDP address, then inject.
        await transport.SendAsync(origin, new byte[] { 5 }, CancellationToken.None);
        var buffer = new byte[64];
        _ = await transport.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        relay.SendRaw(hostile);
        await transport.SendAsync(origin, new byte[] { 6 }, CancellationToken.None);

        var result = await transport.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        // The hostile datagram was skipped and the good one arrived.
        Assert.Equal(1, result.Length);
        Assert.Equal(6, buffer[0]);
        Assert.Null(relay.BackgroundException);
    }

    [Fact]
    public async Task RelayedCeilingSubtractsTheHeaderOverhead()
    {
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        // RFC 9000 s18.2 ceiling minus the 10-byte RFC 1928 s7 IPv4 header.
        Assert.Equal(65527 - 10, transport.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task RelayedTransportRejectsAnOversizedPayload()
    {
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await transport.SendAsync(
                new IPEndPoint(IPAddress.Loopback, 443),
                new byte[transport.MaxDatagramPayloadSize + 1],
                CancellationToken.None));
    }

    [Fact]
    public void MinimumInitialDatagramCostsTenBytesOverIPv4()
    {
        // RFC 9000 s14.1: a client MUST expand every datagram carrying an Initial
        // packet to at least 1200 bytes. Through a SOCKS5 relay that is 1210 on the
        // client-to-relay path. If this number drifts the handshake fails with no
        // diagnostic, so it is pinned rather than derived.
        var datagram = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv4 + 1200];
        var written = TlsQuicSocks5Protocol.WriteUdpHeader(
            datagram, new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443));

        Assert.Equal(10, written);
        // RFC 1928 s7: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(4) + DST.PORT(2).
        Assert.Equal(2 + 1 + 1 + 4 + 2, TlsQuicSocks5Protocol.UdpHeaderSizeIPv4);
    }

    [Fact]
    public void MinimumInitialDatagramCostsTwentyTwoBytesOverIPv6()
    {
        var datagram = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv6 + 1200];
        var written = TlsQuicSocks5Protocol.WriteUdpHeader(
            datagram, new IPEndPoint(IPAddress.Parse("2001:db8::1"), 443));

        Assert.Equal(22, written);
        // RFC 1928 s7 with a 16-byte address.
        Assert.Equal(2 + 1 + 1 + 16 + 2, TlsQuicSocks5Protocol.UdpHeaderSizeIPv6);
    }

    [Fact]
    public async Task RelayedCeilingLeavesRoomForAMinimumInitialDatagram()
    {
        // The ceiling must not be so tight that a conforming 1200-byte Initial
        // cannot be sent at all.
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        Assert.Equal(
            TlsQuicUdpDatagramTransport.MaximumUdpPayload
                - TlsQuicSocks5Protocol.HeaderSizeFor(relay.ProxyEndPoint.AddressFamily),
            transport.MaxDatagramPayloadSize);
        Assert.Null(relay.BackgroundException);
    }
}
