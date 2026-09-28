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
    public async Task AZeroContextIdInALongerEncodingIsStillContextZero()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        // RFC 9000 s16: 0x40 0x00 is 0 as a two-byte varint.
        await harness.Peer.SendOneRttRawFrameAsync(DatagramFrame(0x00, 0x40, 0x00, 9, 8), ct);

        var buffer = new byte[2048];
        var received = await harness.Transport.ReceiveAsync(buffer, ct);
        Assert.Equal(new byte[] { 9, 8 }, buffer[..received.Length]);
    }

    [Fact]
    public async Task AnOversizeInboundDatagramIsDroppedAndCounted()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);
        var ceiling = harness.Transport.MaxDatagramPayloadSize;

        // Quarter Stream ID 0, Context ID 0, then one byte past the ceiling; the frame's Length
        // needs a two-byte varint.
        var length = 2 + ceiling + 1;
        await harness.Peer.SendOneRttRawFrameAsync(
            [0x31, (byte)(0x40 | (length >> 8)), (byte)(length & 0xFF), 0x00, 0x00, .. new byte[ceiling + 1]],
            ct);
        await harness.Peer.SendOneRttRawFrameAsync(DatagramFrame(0x00, 0x00, 5), ct);

        var buffer = new byte[2048];
        var received = await harness.Transport.ReceiveAsync(buffer, ct);
        Assert.Equal(new byte[] { 5 }, buffer[..received.Length]);
        Assert.Contains($"1 for exceeding {ceiling} bytes inbound", harness.Transport.DropSummary);
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

        // OPEN FOR THE DIAL, which needs the window, and shut once the tunnel is up. An RFC 9002
        // s6.2 probe may leave inside the 200 ms window below, but a probe carries only PING and
        // a DATAGRAM frame is packed only past the gate, so no payload leaves the connection's
        // queue and no room opens for the last send.
        var gate = new ScriptedSendGate { Open = true };
        await using var harness = await MasqueHarness.CreateAsync(
            ct, peerSettings: FullOffer, outerSpec: MasqueHarness.OuterSpec(gate));
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
        // the channel write before it wakes the owner. A PING from the proxy wakes it.
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
    public async Task AWriterWakingTheOwnerMidAnswerLosesNoPayload()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        var gate = new ScriptedSendGate { Open = true };
        HoldingTransport? outer = null;
        await using var harness = await MasqueHarness.CreateAsync(
            ct,
            peerSettings: FullOffer,
            outerSpec: MasqueHarness.OuterSpec(gate),
            wrapOuter: inner => outer = new HoldingTransport(inner));
        gate.Open = false;
        var target = new IPEndPoint(IPAddress.Loopback, 443);

        // Payload 1 waits in the connection's DATAGRAM queue once the shut gate has refused it.
        var asked = gate.Asked.Count;
        await harness.Transport.SendAsync(target, new byte[] { 1 }, ct);
        while (gate.Asked.Count == asked)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(5), ct);
        }

        // The proxy's PING is answered inside the pump, and the answer carries payload 1,
        // already dequeued and recorded as sent. Held at the socket, a second writer wakes the
        // owner; the answer must still leave.
        var held = outer!.HoldNextSend();
        gate.Open = true;
        await harness.Peer.SendOneRttRawFrameAsync([0x01], ct);
        await held.WaitAsync(ct);
        await harness.Transport.SendAsync(target, new byte[] { 2 }, ct);
        outer.Release();

        await PumpPeerUntilAsync(harness, () => harness.Peer.ReceivedDatagrams.Count >= 2, ct);
        Assert.Equal(
            [new byte[] { 0x00, 0x00, 1 }, new byte[] { 0x00, 0x00, 2 }],
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

    /// <summary>An outer transport that forwards everything and can hold one send at the
    /// socket, where a writer's wake-up once cancelled it.</summary>
    /// <param name="inner">The harness's half of the pair.</param>
    private sealed class HoldingTransport(ITlsQuicDatagramTransport inner) : ITlsQuicDatagramTransport
    {
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private TaskCompletionSource? _held;

        /// <inheritdoc/>
        public int MaxDatagramPayloadSize => inner.MaxDatagramPayloadSize;

        /// <summary>Holds the next send until <see cref="Release"/>.</summary>
        /// <returns>A task that completes once that send is held.</returns>
        internal Task HoldNextSend()
        {
            var held = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Volatile.Write(ref _held, held);
            return held.Task;
        }

        /// <summary>Lets the held send go on.</summary>
        internal void Release() => _release.TrySetResult();

        /// <inheritdoc/>
        public async ValueTask SendAsync(
            IPEndPoint destination, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _held, null) is { } held)
            {
                held.SetResult();
                await _release.Task;
            }
            await inner.SendAsync(destination, payload, cancellationToken);
        }

        /// <inheritdoc/>
        public ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
            Memory<byte> buffer, CancellationToken cancellationToken) =>
            inner.ReceiveAsync(buffer, cancellationToken);

        /// <summary>Nothing: the pair is the harness's to dispose.</summary>
        /// <returns>A completed task.</returns>
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
