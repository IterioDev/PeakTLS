using System.Net;
using SharpTls;
using SharpTls.Quic;
using static SharpTls.Tests.Quic.TlsQuicConnectionTests;

namespace SharpTls.Tests.Quic;

/// <summary>One outer MASQUE connection carrying several CONNECT-UDP tunnels (RFC 9298 s3:
/// each tunnel is one request stream on the same HTTP/3 connection). Opening, routing
/// datagrams by quarter stream id, ending one tunnel without the others, and how the outer's
/// own end reaches every tunnel.</summary>
public sealed class TlsQuicMasqueConnectionTests
{
    private static readonly TlsQuicHttp3Setting[] FullOffer =
    [
        .. TestHttp3Settings.DatagramCapable,
        new(TlsQuicHttp3Spec.EnableConnectProtocolIdentifier, 1),
    ];

    private static readonly IPEndPoint AnyTarget = new(IPAddress.Loopback, 443);

    [Fact]
    public async Task ASecondTunnelOpensOnTheNextRequestStreamOfTheSameOuter()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        await using var second = await harness.OpenTunnelAsync(4, 200, ct, host: "second.test");

        Assert.Equal(2, harness.Connection.TunnelCount);
        var frame = harness.Peer.ReceivedStreamFrames.Single(f => f.StreamId == 4);
        Assert.False(frame.Fin);
        var fields = TlsQuicHttp3RequestTests.DecodeFieldSection(HeadersPayload(frame.Data));
        Assert.Contains((":path", "/.well-known/masque/udp/second.test/443/"), fields);

        // Quarter stream id 1 is still a one-byte varint, so the ceiling is the first tunnel's.
        Assert.Equal(harness.Transport.MaxDatagramPayloadSize, second.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task EachTunnelReceivesOnlyTheDatagramsOfItsOwnQuarterStreamId()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);
        await using var second = await harness.OpenTunnelAsync(4, 200, ct);

        await harness.Peer.SendOneRttRawFrameAsync(MasqueHarness.DatagramFrame(0x01, 0x00, 4, 4), ct);
        await harness.Peer.SendOneRttRawFrameAsync(MasqueHarness.DatagramFrame(0x00, 0x00, 0, 0), ct);

        var buffer = new byte[2048];
        var first = await harness.Transport.ReceiveAsync(buffer, ct);
        Assert.Equal(new byte[] { 0, 0 }, buffer[..first.Length]);
        var other = await second.ReceiveAsync(buffer, ct);
        Assert.Equal(new byte[] { 4, 4 }, buffer[..other.Length]);
    }

    [Fact]
    public async Task EachTunnelSendsUnderItsOwnQuarterStreamId()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);
        await using var second = await harness.OpenTunnelAsync(4, 200, ct);

        await second.SendAsync(AnyTarget, new byte[] { 2 }, ct);

        await harness.PumpPeerUntilAsync(() => harness.Peer.ReceivedDatagrams.Count > 0, ct);
        Assert.Equal(new byte[] { 0x01, 0x00, 2 }, harness.Peer.ReceivedDatagrams[^1]);
    }

    [Fact]
    public async Task DisposingOneTunnelEndsItsStreamAndLeavesTheOuterAndTheOtherTunnelUp()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);
        await using var second = await harness.OpenTunnelAsync(4, 200, ct);

        await harness.Transport.DisposeAsync();

        // RFC 9298 s3.4: the client ends a tunnel by closing its request stream; the outer
        // connection and its other tunnel are untouched.
        await harness.PumpPeerUntilAsync(
            () => harness.Peer.ReceivedStreamFrames.Any(f => f.StreamId == 0 && f.Fin), ct);
        Assert.Null(harness.Peer.LastConnectionClose);
        Assert.False(harness.Connection.IsClosed);
        Assert.Equal(1, harness.Connection.TunnelCount);

        await harness.Peer.SendOneRttRawFrameAsync(MasqueHarness.DatagramFrame(0x01, 0x00, 7), ct);
        var buffer = new byte[2048];
        var received = await second.ReceiveAsync(buffer, ct);
        Assert.Equal(new byte[] { 7 }, buffer[..received.Length]);
    }

    [Fact]
    public async Task DisposingTheOuterEndsEveryTunnelAndClosesWithNoError()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);
        await using var second = await harness.OpenTunnelAsync(4, 200, ct);

        await harness.Connection.DisposeAsync();
        await harness.Connection.DisposeAsync();

        foreach (var tunnel in new[] { harness.Transport, second })
        {
            var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
                await tunnel.ReceiveAsync(new byte[2048], ct));
            Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, error.Error);
        }
        Assert.True(harness.Connection.IsClosed);
        await harness.PumpPeerAsync(ct);
        var close = Assert.NotNull(harness.Peer.LastConnectionClose);
        Assert.Equal(0x1dUL, close.RawType);
        Assert.Equal(0x100UL, close.ErrorCode);

        var refused = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.Connection.OpenTunnelAsync("late.test", 443, AnyTarget, ct));
        Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, refused.Error);
    }

    [Fact]
    public async Task AnOuterCloseFailsEveryTunnelAndEveryLaterOpenByName()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);
        await using var second = await harness.OpenTunnelAsync(4, 200, ct);

        // RFC 9000 s19.19's application CONNECTION_CLOSE with H3_NO_ERROR (0x100).
        await harness.Peer.SendOneRttRawFrameAsync([0x1d, 0x41, 0x00, 0x00], ct);

        foreach (var tunnel in new[] { harness.Transport, second })
        {
            var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
                await tunnel.ReceiveAsync(new byte[2048], ct));
            Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, error.Error);
            Assert.Contains("draining", error.Message);
        }
        Assert.True(harness.Connection.IsClosed);
        Assert.Equal(0, harness.Connection.TunnelCount);

        var refused = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.Connection.OpenTunnelAsync("late.test", 443, AnyTarget, ct));
        Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, refused.Error);
        Assert.Contains("draining", refused.Message);
    }

    [Fact]
    public async Task AProxyEndingOneTunnelStreamLeavesTheOtherTunnelUp()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);
        await using var second = await harness.OpenTunnelAsync(4, 200, ct);

        var offset = (ulong)ResponseBytes(200, [], []).Length;
        await harness.Peer.SendStreamFramesAsync([Stream(0, offset, [], fin: true)], ct);

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.Transport.ReceiveAsync(new byte[2048], ct));
        Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, error.Error);
        Assert.Contains("ended the tunnel stream", error.Message);
        Assert.False(harness.Connection.IsClosed);
        Assert.Equal(1, harness.Connection.TunnelCount);

        await harness.Peer.SendOneRttRawFrameAsync(MasqueHarness.DatagramFrame(0x01, 0x00, 9), ct);
        var buffer = new byte[2048];
        var received = await second.ReceiveAsync(buffer, ct);
        Assert.Equal(new byte[] { 9 }, buffer[..received.Length]);
    }

    [Fact]
    public async Task AnOpenTheProxyNeverAnswersIsRefusedNamingTheStageAndTheOuterStaysUp()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(
            ct, peerSettings: FullOffer, handshakeDeadline: TimeSpan.FromSeconds(1));

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.Connection.OpenTunnelAsync("silent.test", 443, AnyTarget, ct));

        Assert.Equal(TlsQuicProxyError.MasqueTunnelRefused, error.Error);
        Assert.Contains("waiting for the CONNECT-UDP response", error.Message);
        Assert.False(harness.Connection.IsClosed);
        Assert.Equal(1, harness.Connection.TunnelCount);
    }

    // A live run of 2026-09-29, 200 sessions: a proxy's 522 carries a body and a content-length,
    // its DATA arrived a pump before its FIN, the tunnel exchange had already dropped the DATA
    // (a datagram exchange keeps no body), and RFC 9114 s4.1.2's content-length check at the
    // FIN compared the declared length with the emptied buffer. That is H3_MESSAGE_ERROR, which
    // this HTTP/3 layer treats as the connection's, so one refused tunnel closed the outer
    // connection under every other tunnel of the session.
    [Fact]
    public async Task ARefusalWhoseBodyArrivesBeforeItsFinLeavesTheOuterAndItsTunnelsUp()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        var open = harness.Connection.OpenTunnelAsync("second.test", 443, AnyTarget, ct);
        await harness.PumpPeerUntilAsync(
            () => harness.Peer.ReceivedStreamFrames.Any(f => f.StreamId == 4), ct);
        var response = ResponseBytes(522, [("content-length", "5")], "gone!"u8.ToArray());
        await harness.Peer.SendStreamFramesAsync([Stream(4, 0, response)], ct);
        var refused = await Assert.ThrowsAsync<TlsQuicProxyException>(async () => await open);
        Assert.Equal(TlsQuicProxyError.MasqueTunnelRefused, refused.Error);

        // The FIN in a packet of its own, after the body has been read and dropped.
        await harness.Peer.SendStreamFramesAsync(
            [Stream(4, (ulong)response.Length, [], fin: true)], ct);

        await harness.Peer.SendOneRttRawFrameAsync(MasqueHarness.DatagramFrame(0x00, 0x00, 7), ct);
        var buffer = new byte[2048];
        var received = await harness.Transport.ReceiveAsync(buffer, ct);
        Assert.Equal(new byte[] { 7 }, buffer[..received.Length]);
        Assert.False(harness.Connection.IsClosed);
    }

    [Fact]
    public async Task ARefusedSecondTunnelIsNamedAndTheOuterStaysUp()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.OpenTunnelAsync(4, 407, ct));

        Assert.Equal(TlsQuicProxyError.MasqueAuthenticationRejected, error.Error);
        Assert.False(harness.Connection.IsClosed);
        Assert.Equal(1, harness.Connection.TunnelCount);
    }
}
