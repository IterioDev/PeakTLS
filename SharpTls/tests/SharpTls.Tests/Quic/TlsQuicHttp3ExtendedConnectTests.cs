using System.Collections.Immutable;
using SharpTls.Quic;
using static SharpTls.Tests.Quic.TlsQuicConnectionTests;

namespace SharpTls.Tests.Quic;

// Task 4 of the MASQUE plan: RFC 9220 s3's :protocol pseudo-header, gated on RFC 8441 s3's
// SETTINGS_ENABLE_CONNECT_PROTOCOL. TlsQuicHttp3Request.Protocol is the encoder half;
// TlsQuicHttp3Connection.TryOpenRequest's ExtendedConnectNotEnabled refusal is the gate half.
public sealed class TlsQuicHttp3ExtendedConnectTests
{
    internal static TlsQuicHttp3Request ConnectUdp() => new()
    {
        Method = "CONNECT",
        Protocol = "connect-udp",
        Scheme = "https",
        Authority = "masque.example:50000",
        Path = "/.well-known/masque/udp/target.example/443/",
        Fields =
        [
            new TlsQuicHttp3Field("proxy-authorization", "Basic dXNlcjpwYXNz"),
            new TlsQuicHttp3Field("capsule-protocol", "?1"),
        ],
    };

    // TryEncode writes a HEADERS frame; its callers decode with
    // DecodeFieldSection(Assert.Single(ReadFrames(encoded)).Payload) (see
    // TlsQuicHttp3RequestTests.cs). Both helpers are internal static so this file can reuse
    // them rather than duplicating a QPACK-decoding helper a third time.
    private static List<(string Name, string Value)> Decode(List<byte> encoded) =>
        TlsQuicHttp3RequestTests.DecodeFieldSection(
            Assert.Single(TlsQuicHttp3RequestTests.ReadFrames(encoded)).Payload);

    [Fact]
    public void TheProtocolPseudoHeaderFollowsTheMethodWhateverTheOrder()
    {
        var encoded = new List<byte>();
        Assert.True(ConnectUdp().TryEncode(encoded, new TlsQuicHttp3Spec(), out _));
        var fields = Decode(encoded);

        Assert.Equal(
            [":method", ":protocol", ":authority", ":scheme", ":path", "proxy-authorization", "capsule-protocol"],
            fields.Select(f => f.Name).ToArray());
        Assert.Equal("connect-udp", fields[1].Value);
    }

    [Fact]
    public void ARequestWithoutProtocolStillHasNoProtocolLine()
    {
        var get = new TlsQuicHttp3Request { Method = "GET", Scheme = "https", Authority = "a", Path = "/" };
        var encoded = new List<byte>();
        Assert.True(get.TryEncode(encoded, new TlsQuicHttp3Spec(), out _));
        Assert.DoesNotContain(Decode(encoded), f => f.Name == ":protocol");
    }

    [Fact]
    public async Task TheConnectionRefusesExtendedConnectUntilThePeerEnablesIt()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await Harness.CreateAsync(cancellation.Token);
        // Harness.CreateAsync sends no peer SETTINGS at all; the peer's list is empty here.

        var stream = harness.Http3.TryOpenRequest(ConnectUdp(), out var refusal, out _);

        Assert.Null(stream);
        Assert.Equal(TlsQuicHttp3RequestRefusal.ExtendedConnectNotEnabled, refusal);
    }

    [Fact]
    public async Task ThePeerEnablingItLetsTheRequestOpen()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await Harness.CreateAsync(cancellation.Token);
        await harness.PeerSendsAsync(cancellation.Token, PeerControl(new TlsQuicHttp3Setting(0x08, 1)));
        Assert.True(harness.Http3.Streams.PeerSettingsReceived);

        var stream = harness.Http3.TryOpenRequest(ConnectUdp(), out var refusal, out _);

        Assert.NotNull(stream);
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
    }
}
