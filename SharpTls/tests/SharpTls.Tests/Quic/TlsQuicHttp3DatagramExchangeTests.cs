using SharpTls.Quic;
using static SharpTls.Tests.Quic.TlsQuicConnectionTests;

namespace SharpTls.Tests.Quic;

// Task 5 of the MASQUE plan: an exchange opened with receivesDatagrams keeps its request stream
// open (RFC 9297 s2.1, RFC 9298 s3.1) and is the one place RFC 9297 s2.1's quarter stream id
// routes an HTTP datagram to or from. Every test here uses one arrangement, ArrangeAsync: both
// halves of the datagram claim advertised on each side, and the peer's SETTINGS enabling
// extended CONNECT so that a connect-udp request may open at all.
public sealed class TlsQuicHttp3DatagramExchangeTests
{
    private static TlsQuicHttp3Request ConnectUdp() => TlsQuicHttp3ExtendedConnectTests.ConnectUdp();

    private static TlsQuicHttp3Request Get() =>
        new() { Method = "GET", Scheme = "https", Authority = "a", Path = "/" };

    [Fact]
    public async Task ADatagramExchangeSendsItsHeadersWithoutFin()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);

        var tunnel = harness.Http3.TryOpenRequest(ConnectUdp(), out _, out _, receivesDatagrams: true);
        var get = harness.Http3.TryOpenRequest(Get(), out _, out _);
        await harness.FlushAsync(cancellation.Token);

        Assert.False(harness.Peer.ReceivedStreamFrames.Single(f => f.StreamId == tunnel!.Id).Fin);
        Assert.True(harness.Peer.ReceivedStreamFrames.Single(f => f.StreamId == get!.Id).Fin);
    }

    [Fact]
    public async Task ASentDatagramCarriesTheQuarterStreamIdAndNothingElse()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);
        var tunnel = harness.Http3.TryOpenRequest(ConnectUdp(), out _, out _, receivesDatagrams: true)!;
        await harness.FlushAsync(cancellation.Token);

        Assert.True(harness.Http3.TrySendDatagram(tunnel.Id, [0x00, 0xAA, 0xBB]));
        await harness.FlushAsync(cancellation.Token);

        byte[] expected = [.. QuicVariableLengthInteger.Encode(tunnel.Id / 4), 0x00, 0xAA, 0xBB];
        Assert.Equal(expected, harness.Peer.ReceivedDatagrams.Single());
    }

    [Fact]
    public async Task AReceivedDatagramForTheExchangeIsDrainedByItsStreamId()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);
        var tunnel = harness.Http3.TryOpenRequest(ConnectUdp(), out _, out _, receivesDatagrams: true)!;
        await harness.FlushAsync(cancellation.Token);

        await harness.Peer.SendOneRttRawFrameAsync(DatagramFrame(tunnel.Id / 4, [9, 8, 7]), cancellation.Token);
        Assert.True(await harness.Http3.PumpOnceAsync(cancellation.Token));

        Assert.Equal(new byte[] { 9, 8, 7 }, Assert.Single(harness.Http3.DrainDatagrams(tunnel.Id)));
        Assert.Empty(harness.Http3.DrainDatagrams(tunnel.Id));
    }

    [Fact]
    public async Task ADatagramForAnUnmarkedStreamIsCountedAndDropped()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);
        var get = harness.Http3.TryOpenRequest(Get(), out _, out _)!;
        await harness.FlushAsync(cancellation.Token);

        await harness.Peer.SendOneRttRawFrameAsync(DatagramFrame(get.Id / 4, [1]), cancellation.Token);
        Assert.True(await harness.Http3.PumpOnceAsync(cancellation.Token));

        Assert.Empty(harness.Http3.DrainDatagrams(get.Id));
        Assert.Equal(1UL, harness.Http3.DroppedDatagramsWrongStream);
    }

    // RFC 9297 s2.1: "If a datagram is received after the corresponding stream's receive side
    // is closed, the received datagrams MUST be silently dropped." The peer's FIN closes it,
    // and so does its RESET_STREAM (H3_REQUEST_CANCELLED, 0x010c).
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ADatagramAfterTheExchangeStreamEndsIsDropped(bool reset)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);
        var tunnel = harness.Http3.TryOpenRequest(ConnectUdp(), out _, out _, receivesDatagrams: true)!;
        await harness.FlushAsync(cancellation.Token);
        var response = ResponseBytes(200, [], []);
        TlsQuicFrame[] end = reset
            ? [Stream(tunnel.Id, 0, response), Reset(tunnel.Id, (ulong)response.Length, 0x010c)]
            : [Stream(tunnel.Id, 0, response, fin: true)];
        await harness.PeerSendsAsync(cancellation.Token, end);

        await harness.Peer.SendOneRttRawFrameAsync(DatagramFrame(tunnel.Id / 4, [1]), cancellation.Token);
        Assert.True(await harness.Http3.PumpOnceAsync(cancellation.Token));

        Assert.Empty(harness.Http3.DrainDatagrams(tunnel.Id));
        Assert.Equal(1UL, harness.Http3.DroppedDatagramsWrongStream);
    }

    [Fact]
    public async Task TheExchangeKeepsNoBodyBytes()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);
        var tunnel = harness.Http3.TryOpenRequest(ConnectUdp(), out _, out _, receivesDatagrams: true)!;
        await harness.FlushAsync(cancellation.Token);

        // A 200 followed by 100 body bytes on the tunnel's stream, no FIN.
        await harness.PeerSendsAsync(cancellation.Token, Stream(tunnel.Id, 0, ResponseBytes(200, [], new byte[100])));

        var response = harness.Http3.ResponseFor(tunnel.Id)!;
        Assert.Equal(200, response.Status);
        Assert.Equal(0, response.Body.Length);
        Assert.False(response.IsComplete);
    }

    [Fact]
    public async Task PeerSettingsAreForwarded()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);

        Assert.True(harness.Http3.PeerSettingsReceived);
        Assert.Equal(1UL, TlsQuicHttp3Settings.Value(harness.Http3.PeerSettings, 0x08));
    }

    private static async Task<Harness> ArrangeAsync(CancellationToken ct)
    {
        var harness = await Harness.CreateAsync(
            ct,
            spec: new TlsQuicHttp3Spec { Settings = TestHttp3Settings.DatagramCapable },
            flowControl:
            [
                .. FlowControlParameters(),
                TlsQuicTransportParameter.VariableInteger(TlsQuicTransportParameterId.MaxDatagramFrameSize, 65535),
            ]);
        await harness.PeerSendsAsync(ct, PeerControl(new TlsQuicHttp3Setting(0x08, 1), new TlsQuicHttp3Setting(0x33, 1)));
        return harness;
    }

    // RFC 9221 s4's DATAGRAM frame with Length (type 0x31) carrying RFC 9297 s2.1's HTTP
    // Datagram: the quarter stream id, then the payload.
    private static byte[] DatagramFrame(ulong quarterStreamId, byte[] payload)
    {
        var data = new List<byte>(QuicVariableLengthInteger.Encode(quarterStreamId));
        data.AddRange(payload);
        var frame = new List<byte> { 0x31 };
        frame.AddRange(QuicVariableLengthInteger.Encode((ulong)data.Count));
        frame.AddRange(data);
        return frame.ToArray();
    }
}
