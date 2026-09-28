using System.Net;
using System.Text;
using SharpTls;
using SharpTls.Quic;
using static SharpTls.Tests.Quic.TlsQuicConnectionTests;

namespace SharpTls.Tests.Quic;

/// <summary>The MASQUE tunnel. The dial: what the proxy must offer (RFC 9298 s3, RFC 9297
/// s2.1.1, RFC 9221 s3), what the CONNECT-UDP request carries, and how each answer is judged
/// by name. The data plane: context-0 framing both ways, backpressure that delays rather than
/// drops, and every way the tunnel ends surfacing as MasqueTunnelClosed.</summary>
public sealed class TlsQuicMasqueTransportTests
{
    private static readonly TlsQuicHttp3Setting ExtendedConnect =
        new(TlsQuicHttp3Spec.EnableConnectProtocolIdentifier, 1);

    // A proxy that offers everything: DatagramCapable already carries SETTINGS_H3_DATAGRAM.
    private static readonly TlsQuicHttp3Setting[] FullOffer =
        [.. TestHttp3Settings.DatagramCapable, ExtendedConnect];

    [Fact]
    public async Task AProxyWithoutExtendedConnectIsRefusedByName()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await MasqueHarness.CreateAsync(
                cancellation.Token, peerSettings: [.. TestHttp3Settings.DatagramCapable]));

        Assert.Equal(TlsQuicProxyError.MasqueNotOffered, error.Error);
        Assert.Contains("SETTINGS_ENABLE_CONNECT_PROTOCOL", error.Message);
    }

    [Fact]
    public async Task AProxyWithoutDatagramsIsRefusedByName()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var noSetting = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await MasqueHarness.CreateAsync(
                cancellation.Token,
                peerSettings: [.. TestHttp3Settings.QpackCapable, ExtendedConnect]));
        Assert.Equal(TlsQuicProxyError.MasqueNotOffered, noSetting.Error);
        Assert.Contains("SETTINGS_H3_DATAGRAM", noSetting.Message);

        var noParameter = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await MasqueHarness.CreateAsync(
                cancellation.Token, peerSettings: FullOffer, serverMaxDatagramFrameSize: null));
        Assert.Equal(TlsQuicProxyError.MasqueNotOffered, noParameter.Error);
        Assert.Contains("max_datagram_frame_size", noParameter.Message);
    }

    [Theory]
    [InlineData(200, null)]
    [InlineData(201, null)]
    [InlineData(407, TlsQuicProxyError.MasqueAuthenticationRejected)]
    [InlineData(400, TlsQuicProxyError.MasqueTargetRejected)]
    [InlineData(503, TlsQuicProxyError.MasqueTunnelRefused)]
    public async Task TheConnectUdpStatusDecidesTheOutcome(int status, TlsQuicProxyError? expected)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        if (expected is null)
        {
            await using var harness = await MasqueHarness.CreateAsync(
                cancellation.Token, peerSettings: FullOffer, answerStatus: status);
            Assert.True(harness.Transport.MaxDatagramPayloadSize >= 1200);
            return;
        }

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await MasqueHarness.CreateAsync(
                cancellation.Token, peerSettings: FullOffer, answerStatus: status));
        Assert.Equal(expected, error.Error);
        if (status == 503)
        {
            Assert.Contains("503", error.Message);
        }
    }

    [Fact]
    public async Task TheConnectUdpRequestIsExactlyWhatTheGuideAsksFor()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var harness = await MasqueHarness.CreateAsync(
            cancellation.Token, peerSettings: FullOffer);

        var frame = harness.Peer.ReceivedStreamFrames.Single(f => f.StreamId == 0);
        Assert.False(frame.Fin);   // RFC 9298 s3.4: the stream stays open for the tunnel

        var fields = TlsQuicHttp3RequestTests.DecodeFieldSection(HeadersPayload(frame.Data));
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:pass"));
        List<(string Name, string Value)> expected =
            [
                (":method", "CONNECT"),
                (":protocol", "connect-udp"),
                (":authority", "proxy.test:50000"),
                (":scheme", "https"),
                (":path", "/.well-known/masque/udp/target.test/443/"),
                ("proxy-authorization", "Basic " + basic),
                ("capsule-protocol", "?1"),
            ];
        Assert.Equal(expected, fields);
    }

    [Theory]
    [InlineData(65535UL, 1358)]
    [InlineData(1300UL, 1295)]
    public async Task TheCapacityIsTheOuterFramePayloadMinusFraming(ulong peerLimit, int expected)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var harness = await MasqueHarness.CreateAsync(
            cancellation.Token, peerSettings: FullOffer, serverMaxDatagramFrameSize: peerLimit);

        Assert.Equal(expected, harness.Transport.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task ACapacityBelowAnInitialIsRefusedByName()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await MasqueHarness.CreateAsync(
                cancellation.Token, peerSettings: FullOffer, serverMaxDatagramFrameSize: 1100));

        Assert.Equal(TlsQuicProxyError.MasqueNotOffered, error.Error);
        Assert.Contains("1200", error.Message);
    }

    [Fact]
    public async Task AResetBeforeTheResponseIsATunnelClosed()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await MasqueHarness.CreateAsync(
                cancellation.Token, peerSettings: FullOffer, answerWithReset: true));

        Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, error.Error);
        Assert.Contains("0x10c", error.Message);
    }

    [Fact]
    public async Task AnOuterCloseDuringTheDialIsATunnelClosed()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await MasqueHarness.CreateAsync(
                cancellation.Token, peerSettings: FullOffer, answerWithClose: true));

        // The cause rides in the text: TlsQuicConnection's draining refusal (RFC 9000 s10.2).
        Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, error.Error);
        Assert.Contains("draining", error.Message);
    }

    [Fact]
    public async Task ASentPayloadReachesThePeerAsAContextZeroHttpDatagram()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        // Any destination: RFC 9298 s2 fixed the target in the request.
        await harness.Transport.SendAsync(
            new IPEndPoint(IPAddress.Any, 1), new byte[] { 0xC0, 1, 2, 3 }, ct);

        // RFC 9297 s2.1's Quarter Stream ID (stream 0, so 0x00), then RFC 9298 s4's Context
        // ID 0, then the payload.
        await PumpPeerUntilAsync(harness, () => harness.Peer.ReceivedDatagrams.Count > 0, ct);
        Assert.Equal(new byte[] { 0x00, 0x00, 0xC0, 1, 2, 3 }, harness.Peer.ReceivedDatagrams[^1]);
    }

    [Fact]
    public async Task APeerDatagramReachesReceiveAsyncWithoutItsFraming()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        await harness.Peer.SendOneRttRawFrameAsync(DatagramFrame(0x00, 0x00, 9, 8, 7), ct);

        var buffer = new byte[2048];
        var received = await harness.Transport.ReceiveAsync(buffer, ct);
        Assert.Equal(3, received.Length);
        Assert.Equal(new byte[] { 9, 8, 7 }, buffer[..3]);
        Assert.Equal(new IPEndPoint(IPAddress.Loopback, 443), received.RemoteEndPoint);
    }

    [Fact]
    public async Task ANonZeroContextIdIsDroppedAndCounted()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        await harness.Peer.SendOneRttRawFrameAsync(DatagramFrame(0x00, 0x02, 1), ct);
        await harness.Peer.SendOneRttRawFrameAsync(DatagramFrame(0x00, 0x00, 5), ct);

        var buffer = new byte[2048];
        var received = await harness.Transport.ReceiveAsync(buffer, ct);
        Assert.Equal(new byte[] { 5 }, buffer[..received.Length]);
        Assert.StartsWith(
            "1 datagram(s) dropped for a context id other than 0", harness.Transport.DropSummary);
    }

    [Fact]
    public async Task AnOversizePayloadIsRefusedByNameNotDropped()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);
        var ceiling = harness.Transport.MaxDatagramPayloadSize;

        var error = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await harness.Transport.SendAsync(
                new IPEndPoint(IPAddress.Loopback, 443), new byte[ceiling + 1], ct));

        Assert.Contains($"at most {ceiling} bytes", error.Message);
    }

    [Fact]
    public async Task SendAwaitsWhenTheOuterIsCongestionBlocked()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;

        // OPEN FOR THE DIAL, which needs the window, and shut once the tunnel is up. The 5 s
        // initial RTT keeps an RFC 9002 s6.2 probe out of the 200 ms window.
        var gate = new ScriptedSendGate { Open = true };
        await using var harness = await MasqueHarness.CreateAsync(
            ct,
            peerSettings: FullOffer,
            outerSpec: MasqueHarness.OuterSpec(gate, initialRtt: TimeSpan.FromSeconds(5)));
        gate.Open = false;

        // What a shut outer absorbs before a send waits: TlsQuicConnection's DATAGRAM queue
        // (64), the one payload that queue refused and the owner holds, and the channel (64).
        const int absorbed = 64 + 1 + 64;
        var target = new IPEndPoint(IPAddress.Loopback, 443);
        var sends = Enumerable.Range(0, absorbed + 1)
            .Select(i => harness.Transport.SendAsync(target, new byte[] { (byte)i }, ct).AsTask())
            .ToList();

        await Task.WhenAll(sends.Take(absorbed)).WaitAsync(TimeSpan.FromSeconds(5), ct);
        await Task.Delay(TimeSpan.FromMilliseconds(200), ct);
        Assert.False(sends[absorbed].IsCompleted, "a send beyond the bound completed");

        // A PROPERTY FLIP WAKES NOTHING: the owner is parked in its pump, and the last send in
        // the channel write before it reaches InterruptPump. A PING from the proxy wakes it.
        gate.Open = true;
        await harness.Peer.SendOneRttRawFrameAsync([0x01], ct);
        await sends[absorbed].WaitAsync(TimeSpan.FromSeconds(5), ct);

        await PumpPeerUntilAsync(
            harness, () => harness.Peer.ReceivedDatagrams.Count >= absorbed + 1, ct);
        Assert.Equal(
            Enumerable.Range(0, absorbed + 1).Select(i => new byte[] { 0x00, 0x00, (byte)i }),
            harness.Peer.ReceivedDatagrams);
    }

    [Fact]
    public async Task AResetAfterTheResponseSurfacesAsTunnelClosedOnTheNextReceive()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        // RFC 9000 s19.4: the final size is every byte already sent, the 200's HEADERS frame.
        var finalSize = (ulong)ResponseBytes(200, [], []).Length;
        await harness.Peer.SendStreamFramesAsync([Reset(0, finalSize, 0x10c)], ct);

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.Transport.ReceiveAsync(new byte[2048], ct));
        Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, error.Error);
        Assert.Contains("0x10c", error.Message);

        var send = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.Transport.SendAsync(
                new IPEndPoint(IPAddress.Loopback, 443), new byte[] { 1 }, ct));
        Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, send.Error);
        Assert.Contains("0x10c", send.Message);
    }

    [Fact]
    public async Task AnOuterConnectionCloseSurfacesAsTunnelClosed()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        // RFC 9000 s19.19's application CONNECTION_CLOSE with H3_NO_ERROR (0x100).
        await harness.Peer.SendOneRttRawFrameAsync([0x1d, 0x41, 0x00, 0x00], ct);

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.Transport.ReceiveAsync(new byte[2048], ct));
        Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, error.Error);
        Assert.Contains("draining", error.Message);
    }

    [Fact]
    public async Task DisposeIsIdempotentAndClosesTheOuter()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        await harness.Transport.DisposeAsync();
        await harness.Transport.DisposeAsync();
        await harness.PumpPeerAsync(ct);

        // RFC 9114 s5.2's graceful close: H3_NO_ERROR in an application CONNECTION_CLOSE.
        var close = Assert.NotNull(harness.Peer.LastConnectionClose);
        Assert.Equal(0x1dUL, close.RawType);
        Assert.Equal(0x100UL, close.ErrorCode);
    }

    // RFC 9221 s4's DATAGRAM frame with a Length (type 0x31); every payload here is under 64
    // bytes, so the length is a one-byte varint.
    private static byte[] DatagramFrame(params byte[] payload) =>
        [0x31, (byte)payload.Length, .. payload];

    // The owner sends on its own schedule, so the peer is pumped until what the test waits
    // for has arrived; the test's token bounds the wait.
    private static async Task PumpPeerUntilAsync(
        MasqueHarness harness, Func<bool> arrived, CancellationToken cancellationToken)
    {
        while (true)
        {
            await harness.PumpPeerAsync(cancellationToken);
            if (arrived())
            {
                return;
            }
            await Task.Delay(TimeSpan.FromMilliseconds(5), cancellationToken);
        }
    }
}
