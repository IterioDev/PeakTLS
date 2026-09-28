using System.Text;
using SharpTls;
using SharpTls.Quic;
using static SharpTls.Tests.Quic.TlsQuicConnectionTests;

namespace SharpTls.Tests.Quic;

/// <summary>The MASQUE dial: what the proxy must offer (RFC 9298 s3, RFC 9297 s2.1.1, RFC 9221
/// s3), what the CONNECT-UDP request carries, and how each answer is judged by name.</summary>
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
}
