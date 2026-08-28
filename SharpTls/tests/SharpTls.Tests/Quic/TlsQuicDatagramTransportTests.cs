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
        // RFC 9000 s18.2 names 65527 as the maximum permitted UDP payload, but that figure is
        // only reachable over IPv6. An IPv4 datagram carries a 20-byte IP header and an 8-byte
        // UDP header inside the same 65535 total, so its ceiling is 65507 and the socket
        // refuses 65508 with SocketError.MessageSize. This assertion used to read 65527 for an
        // IPv4 transport, which encoded a 20-byte overstatement as the expected behaviour.
        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        Assert.Equal(65507, transport.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task DirectTransportSupportsIPv6()
    {
        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetworkV6);

        // IPv6 is where the RFC 9000 s18.2 figure is actually reachable.
        Assert.Equal(65527, transport.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task DisposingTwiceIsSafe()
    {
        var transport = TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        await transport.DisposeAsync();
        await transport.DisposeAsync();
    }

    /// <summary>
    /// A production report: two hosts in one run, the first connection fine and the second
    /// dying with "SocketException: I/O operation aborted". That is Winsock's
    /// WSA_OPERATION_ABORTED (995) - "The I/O operation has been aborted because of either a
    /// thread exit or an application request" - which on a UDP socket means the handle was
    /// closed while an overlapped receive was posted. It is a lifecycle event, and it used to
    /// reach the pump loop looking exactly like a network failure.
    /// </summary>
    /// <remarks>
    /// WHY .NET DOES NOT ALREADY COVER THIS. SocketAsyncEventArgs turns OperationAborted into
    /// an OperationCanceledException only by calling ThrowIfCancellationRequested on the token
    /// the operation started with. Here that token is CancellationToken.None - nobody
    /// cancelled, the transport was disposed - so the call is a no-op and the raw
    /// SocketException falls through. Before the fix this assertion reads:
    /// "Assert.Throws() Failure: Exception type was not an exact match
    ///  Expected: typeof(System.ObjectDisposedException)
    ///  Actual:   typeof(System.Net.Sockets.SocketException)".
    /// </remarks>
    [Fact]
    public async Task DisposingWhileAReceiveIsPendingSurfacesAsDisposal()
    {
        var transport = TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);
        var pending = transport.ReceiveAsync(new byte[64], CancellationToken.None).AsTask();

        // Give the receive a chance to actually post before the handle closes under it. The
        // assertion holds either way - a receive that has not started yet fails from the
        // disposed socket instead - but only the posted case reproduces the reported 995.
        await Task.Delay(50);
        await transport.DisposeAsync();

        var exception = await Assert.ThrowsAsync<ObjectDisposedException>(
            async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)));

        // Named after the transport, not after System.Net.Sockets.Socket: the caller disposed
        // this object and should be told about the object it holds.
        Assert.Equal(nameof(TlsQuicUdpDatagramTransport), exception.ObjectName);
    }

    /// <summary>
    /// The other half of the same guard, and the one TlsQuicConnection depends on. Its
    /// ReceiveWithinDeadlineAsync separates a deadline cancel from a caller cancel by testing
    /// the two token sources inside an OperationCanceledException filter, so a caller cancel
    /// that arrived as anything else would never reach that filter at all.
    /// </summary>
    [Fact]
    public async Task CancellingAPendingReceiveSurfacesAsCancellation()
    {
        await using var transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        using var cts = new CancellationTokenSource();
        var pending = transport.ReceiveAsync(new byte[64], cts.Token).AsTask();
        await Task.Delay(50);
        await cts.CancelAsync();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)));

        // The caller's own token, so a caller can tell its cancellation from anyone else's.
        Assert.Equal(cts.Token, exception.CancellationToken);
    }

    [Fact]
    public async Task SendingThroughADisposedTransportSurfacesAsDisposal()
    {
        // The send path had the same bare socket call as the receive. A UDP send usually
        // completes into the driver without pending, so the abort window is narrow - but a
        // send issued AFTER disposal is the deterministic end of the same range, and before
        // the fix it reported ObjectName "System.Net.Sockets.Socket": an internal handle the
        // caller never saw, from a type it did dispose.
        var transport = TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);
        await transport.DisposeAsync();

        var exception = await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await transport.SendAsync(
                new IPEndPoint(IPAddress.Loopback, 9), new byte[] { 1 }, CancellationToken.None));

        Assert.Equal(nameof(TlsQuicUdpDatagramTransport), exception.ObjectName);
    }

    /// <summary>
    /// The teardown translation must not eat a real answer from the stack. Two SocketErrors
    /// are named because both are load-bearing elsewhere in this stack.
    /// </summary>
    [Fact]
    public void TheTeardownPredicateAcceptsOnlyLifecycleFaults()
    {
        // WSA_OPERATION_ABORTED (995) and use-after-dispose: lifecycle, translated.
        Assert.True(TlsQuicUdpDatagramTransport.IsTeardownFault(
            new SocketException((int)SocketError.OperationAborted)));
        Assert.True(TlsQuicUdpDatagramTransport.IsTeardownFault(
            new ObjectDisposedException("socket")));

        // WSAEMSGSIZE (10040): TlsQuicConnection catches this one by name to report a datagram
        // the host refused, which is path MTU discovery's only feedback. Swallowing it here
        // would disable that silently.
        Assert.False(TlsQuicUdpDatagramTransport.IsTeardownFault(
            new SocketException((int)SocketError.MessageSize)));

        // WSAECONNRESET (10054): already suppressed at its ICMP source by
        // DisableUdpConnectionReset, and RFC 9000 s10.2.2 forbids treating an ICMP message as
        // a connection error - but where it does arrive it is about a real datagram, not about
        // this transport's lifetime.
        Assert.False(TlsQuicUdpDatagramTransport.IsTeardownFault(
            new SocketException((int)SocketError.ConnectionReset)));

        // Not a socket fault at all.
        Assert.False(TlsQuicUdpDatagramTransport.IsTeardownFault(new InvalidOperationException()));
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
    public async Task ARelayedTransportChargesForItsOwnHeader()
    {
        // RFC 9000 s14.2 measures the maximum datagram size as "the total UDP payload size of a
        // single UDP datagram", which for an encapsulating transport is header + QUIC datagram.
        // A path budget that ignored the header would build a datagram that fits the path and
        // put one 32 bytes over it on the wire - which is how "direct works, only the relay
        // fails" arises from a defect that is not in the relay at all.
        //
        // 32 IS THE DOMAIN FORM FOR A REAL HOST, derived rather than asserted as a bare
        // literal: RFC 1928 section 7 spends 2 bytes on RSV, 1 on FRAG and 1 on ATYP, then a
        // 1-byte name length, the name itself, and 2 for the port. "gew1-spclient.spotify.com"
        // is 25 characters, so 4 + 1 + 25 + 2 = 32.
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options
            {
                ProxyEndPoint = relay.ProxyEndPoint,
                DestinationHost = "gew1-spclient.spotify.com",
            },
            CancellationToken.None);

        Assert.Equal(4 + 1 + 25 + 2, ((ITlsQuicDatagramTransport)transport).DatagramOverhead);

        // AND THE CEILING ALREADY SUBTRACTED IT, which is the invariant that keeps the two
        // numbers from drifting apart: whatever this transport says it prepends is exactly what
        // its payload ceiling gives up against the bare socket maximum.
        Assert.Equal(
            TlsQuicUdpDatagramTransport.MaximumIPv4UdpPayload
                - ((ITlsQuicDatagramTransport)transport).DatagramOverhead,
            transport.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task APlainUdpTransportPrependsNothing()
    {
        // The other half, and the reason DatagramOverhead has a DEFAULT implementation at all:
        // a transport that does not encapsulate must report zero without being made to write a
        // member that says nothing about it. The plain UDP transport declares no override, so
        // this reads the interface default - which is exactly what an out-of-tree transport
        // written before the member existed will do.
        //
        // THROUGH THE INTERFACE, NOT THE CONCRETE TYPE, and that is not incidental: a C# default
        // interface member is reachable only through the interface, so this line is also the
        // evidence that every consumer of ITlsQuicDatagramTransport gets an answer.
        await using ITlsQuicDatagramTransport transport =
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork);

        Assert.Equal(0, transport.DatagramOverhead);
        Assert.Equal(
            TlsQuicUdpDatagramTransport.MaximumIPv4UdpPayload, transport.MaxDatagramPayloadSize);
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

    /// <summary>
    /// The relayed transport has TWO things to tear down under a pending receive - the UDP
    /// relay socket and the TCP control connection whose life RFC 1928 ties the association to
    /// - and disposal touches both. The caller cancelled nothing, so what it must not get is
    /// either a cancellation it never asked for or a Winsock error code.
    /// </summary>
    /// <remarks>
    /// Before the fix this assertion reads:
    /// "Assert.Throws() Failure: Exception type was not an exact match
    ///  Expected: typeof(System.ObjectDisposedException)
    ///  Actual:   typeof(System.OperationCanceledException)".
    /// The receive links the caller's token with an internal termination token, and DisposeAsync
    /// cancels that internal one first - so disposal used to be indistinguishable from the
    /// association simply ending, and both were indistinguishable from a caller's own cancel
    /// except by inspecting a token the caller does not hold.
    /// </remarks>
    [Fact]
    public async Task DisposingARelayedTransportWhileAReceiveIsPendingSurfacesAsDisposal()
    {
        await using var relay = FakeSocks5Relay.Start();
        var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        var pending = transport.ReceiveAsync(new byte[64], CancellationToken.None).AsTask();
        await Task.Delay(50);
        await transport.DisposeAsync();

        var exception = await Assert.ThrowsAsync<ObjectDisposedException>(
            async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Equal(nameof(TlsQuicSocks5Transport), exception.ObjectName);
    }

    /// <summary>
    /// And the distinction the pump loop actually runs on: a caller's own cancellation of a
    /// relayed receive stays a cancellation carrying the caller's own token, so
    /// TlsQuicConnection.ReceiveWithinDeadlineAsync can still tell it from a deadline.
    /// </summary>
    [Fact]
    public async Task CancellingAPendingRelayedReceiveSurfacesAsCancellation()
    {
        await using var relay = FakeSocks5Relay.Start();
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(
            new TlsQuicSocks5Options { ProxyEndPoint = relay.ProxyEndPoint },
            CancellationToken.None);

        using var cts = new CancellationTokenSource();
        var pending = transport.ReceiveAsync(new byte[64], cts.Token).AsTask();
        await Task.Delay(50);
        await cts.CancelAsync();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Equal(cts.Token, exception.CancellationToken);
        Assert.Null(relay.BackgroundException);
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

        // The relay socket's own family ceiling minus the 10-byte RFC 1928 s7 IPv4 header.
        // FakeSocks5Relay listens on IPv4, so the ceiling is 65507 rather than the RFC 9000
        // s18.2 figure of 65527 - the header comes off what the socket accepts, not off the
        // protocol maximum.
        Assert.Equal(65507 - 10, transport.MaxDatagramPayloadSize);
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
            TlsQuicUdpDatagramTransport.MaximumFor(relay.ProxyEndPoint.AddressFamily)
                - TlsQuicSocks5Protocol.HeaderSizeFor(relay.ProxyEndPoint.AddressFamily),
            transport.MaxDatagramPayloadSize);
        Assert.Null(relay.BackgroundException);
    }
}
