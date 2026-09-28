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
    public async Task AnOuterSpecAdvertisingNoUnidirectionalStreamsIsRefusedBeforeDialing()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        // The RFC-minimum list plus the datagram parameter: what a caller gets by forgetting
        // flow control. The first live dial did exactly this and idled out after a completed
        // handshake, waiting for a SETTINGS the proxy could not send.
        var outerSpec = new TlsQuicConnectionSpec
        {
            PathMtuDiscovery = false,
            BasePathMtu = 1392,
            MaximumPathMtu = 1392,
            DestinationConnectionIdLength = 8,
            TransportParameters = new TlsQuicTransportParameterSpec
            {
                Parameters =
                [
                    .. TlsQuicTransportParameterSpec.RfcMinimumParameters,
                    TlsQuicTransportParameterSlot.Literal(0x20, [0x80, 0x00, 0xFF, 0xFF]),
                ],
            },
        };

        var error = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await MasqueHarness.CreateAsync(
                cancellation.Token, peerSettings: FullOffer, outerSpec: outerSpec));

        Assert.Contains("initial_max_streams_uni = 0", error.Message);
        Assert.Contains("RFC 9114 s6.2", error.Message);
    }

    [Fact]
    public async Task AnUnreachableProxyAddressFallsThroughToTheNextOne()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        // The first address swallows every datagram, as a dead front does over UDP; the dial
        // spends one deadline on it, then dials the second and comes up.
        await using var harness = await MasqueHarness.CreateAsync(
            cancellation.Token,
            peerSettings: FullOffer,
            unreachableFirst: [new IPEndPoint(IPAddress.Loopback, 9)],
            handshakeDeadline: TimeSpan.FromSeconds(1));

        Assert.True(harness.Transport.MaxDatagramPayloadSize >= 1200);
        Assert.True(harness.ClientTransport.MisdirectedSends > 0, "the dead address was never tried");
    }

    [Fact]
    public async Task EveryProxyAddressUnreachableIsRefusedNamingEachOne()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await MasqueHarness.CreateAsync(
                cancellation.Token,
                peerSettings: FullOffer,
                unreachableFirst: [new IPEndPoint(IPAddress.Loopback, 9), new IPEndPoint(IPAddress.Loopback, 10)],
                reachable: false,
                handshakeDeadline: TimeSpan.FromSeconds(1)));

        Assert.Equal(TlsQuicProxyError.MasqueTunnelRefused, error.Error);
        Assert.Contains("the outer QUIC handshake with 127.0.0.1:10", error.Message);
        Assert.Contains("unreachable: 127.0.0.1:9 (TimeoutException)", error.Message);
    }

    [Theory]
    [InlineData(1300, 1300)]    // a guide's number below the arithmetic wins
    [InlineData(2000, 1358)]    // one above it changes nothing
    public async Task ACallersCeilingCanOnlyLowerTheArithmeticOne(int ceiling, int expected)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var harness = await MasqueHarness.CreateAsync(
            cancellation.Token, peerSettings: FullOffer, innerCeiling: ceiling);

        Assert.Equal(expected, harness.Transport.MaxDatagramPayloadSize);
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
        await harness.PumpPeerUntilAsync(() => harness.Peer.ReceivedDatagrams.Count > 0, ct);
        Assert.Equal(new byte[] { 0x00, 0x00, 0xC0, 1, 2, 3 }, harness.Peer.ReceivedDatagrams[^1]);
    }

    [Fact]
    public async Task APeerDatagramReachesReceiveAsyncWithoutItsFraming()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        await harness.Peer.SendOneRttRawFrameAsync(MasqueHarness.DatagramFrame(0x00, 0x00, 9, 8, 7), ct);

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

        await harness.Peer.SendOneRttRawFrameAsync(MasqueHarness.DatagramFrame(0x00, 0x02, 1), ct);
        await harness.Peer.SendOneRttRawFrameAsync(MasqueHarness.DatagramFrame(0x00, 0x00, 5), ct);

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
        await harness.Peer.SendOneRttRawFrameAsync(MasqueHarness.DatagramFrame(0x00, 0x40, 0x00, 9, 8), ct);

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
        await harness.Peer.SendOneRttRawFrameAsync(MasqueHarness.DatagramFrame(0x00, 0x00, 5), ct);

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

        await harness.PumpPeerUntilAsync(
            () => harness.Peer.ReceivedDatagrams.Count >= absorbed + 1, ct);
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

        await harness.PumpPeerUntilAsync(() => harness.Peer.ReceivedDatagrams.Count >= 2, ct);
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
    public async Task AProxyEndingTheTunnelStreamSaysWhatCrossedIt()
    {
        // A field log of 2026-09-28: the tunnel opened, the inner Initial went in, and the
        // proxy FINned the stream 0.7 s later with nothing coming back - a residential exit
        // that cannot carry UDP. The message must say so and point at the proxy session.
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        await harness.Transport.SendAsync(
            new IPEndPoint(IPAddress.Loopback, 443), new byte[] { 0xC0, 1, 2, 3 }, ct);
        while (harness.Peer.ReceivedDatagrams.Count == 0)
        {
            await harness.PumpPeerAsync(ct);
            await Task.Delay(TimeSpan.FromMilliseconds(5), ct);
        }

        // RFC 9000 s19.8: the FIN sits at the offset after every byte already sent, the 200.
        var offset = (ulong)ResponseBytes(200, [], []).Length;
        await harness.Peer.SendStreamFramesAsync([Stream(0, offset, [], fin: true)], ct);

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.Transport.ReceiveAsync(new byte[2048], ct));
        Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, error.Error);
        Assert.Contains("ended the tunnel stream", error.Message);
        Assert.Contains("1 datagram(s) sent into it and 0 received back", error.Message);
        Assert.Contains("fresh proxy session", error.Message);
    }

    [Fact]
    public async Task ATlsAlertRecordThroughTheTunnelIsARelayThatCannotCarryQuic()
    {
        // A field log of 2026-09-28: the answer to the inner Initial was 15 03 01 00 02 02 46,
        // TLS fatal protocol_version, which only a TCP TLS server produces. The exit behind
        // that MASQUE session wrote the datagram into a TCP connection, exactly as the SOCKS5
        // relays did, and the verdict is the same one, given before any tunnel retry.
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        await harness.Peer.SendOneRttRawFrameAsync(
            MasqueHarness.DatagramFrame(0x00, 0x00, 0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46), ct);

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.Transport.ReceiveAsync(new byte[2048], ct));
        Assert.Equal(TlsQuicProxyError.RelayDeliveredTlsAlert, error.Error);
        Assert.Contains("15030100020246", error.Message);
        Assert.Contains("protocol_version", error.Message);
        Assert.Contains("different proxy session", error.Message);
    }

    [Fact]
    public async Task AShortDatagramBeforeTheTunnelEndsIsShownAsTheProxysOwnAnswer()
    {
        // A field log of 2026-09-28: two 1200-byte Initials in, one 7-byte datagram back, FIN.
        // Seven bytes is no QUIC packet; it is the proxy or its exit speaking, and the report
        // has to show the bytes so a reader can tell what it said.
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        // Quarter stream id 0, context id 0, then ASCII "BLOCKED", as one DATAGRAM frame.
        byte[] answer = [0x00, 0x00, .. "BLOCKED"u8.ToArray()];
        await harness.Peer.SendOneRttRawFrameAsync([0x31, (byte)answer.Length, .. answer], ct);
        var received = await harness.Transport.ReceiveAsync(new byte[2048], ct);
        Assert.Equal(7, received.Length);

        var offset = (ulong)ResponseBytes(200, [], []).Length;
        await harness.Peer.SendStreamFramesAsync([Stream(0, offset, [], fin: true)], ct);

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.Transport.ReceiveAsync(new byte[2048], ct));
        Assert.Contains("7 bytes, too short for a QUIC packet: 424C4F434B4544 (ASCII 'BLOCKED')", error.Message);
    }

    [Fact]
    public async Task WhatTheProxyWroteBeforeEndingTheTunnelStreamIsInTheMessage()
    {
        // RFC 9297 s3.2 capsules are the one place a proxy can explain an ended tunnel.
        // Nothing parses them, so the bytes themselves go into the message.
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        var offset = (ulong)ResponseBytes(200, [], []).Length;
        byte[] capsule = [0x00, 0x03, 0xAA, 0xBB, 0xCC];   // a DATA frame's payload; type 0, length 3
        byte[] data = [0x00, (byte)capsule.Length, .. capsule];   // HTTP/3 DATA frame
        await harness.Peer.SendStreamFramesAsync([Stream(0, offset, data, fin: true)], ct);

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await harness.Transport.ReceiveAsync(new byte[2048], ct));
        Assert.Equal(TlsQuicProxyError.MasqueTunnelClosed, error.Error);
        Assert.Contains("wrote 5 byte(s) on the tunnel stream before ending it", error.Message);
        Assert.Contains("0003AABBCC", error.Message);
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
    public async Task DisposingTheTunnelEndsItsStreamAndDisposingTheOuterClosesTheConnection()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = cancellation.Token;
        await using var harness = await MasqueHarness.CreateAsync(ct, peerSettings: FullOffer);

        // Both idempotent. The tunnel's dispose is RFC 9298 s3.4's end of the request stream
        // (a FIN) and nothing more: the outer connection is another tunnel's to use.
        await harness.Transport.DisposeAsync();
        await harness.Transport.DisposeAsync();
        await harness.PumpPeerUntilAsync(
            () => harness.Peer.ReceivedStreamFrames.Any(f => f.StreamId == 0 && f.Fin), ct);
        Assert.Null(harness.Peer.LastConnectionClose);

        // RFC 9114 s5.2's graceful close: H3_NO_ERROR in an application CONNECTION_CLOSE.
        await harness.Connection.DisposeAsync();
        await harness.Connection.DisposeAsync();
        await harness.PumpPeerAsync(ct);
        var close = Assert.NotNull(harness.Peer.LastConnectionClose);
        Assert.Equal(0x1dUL, close.RawType);
        Assert.Equal(0x100UL, close.ErrorCode);
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
