using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicConnectionDatagramTests
{
    [Fact]
    public async Task ThePeersMaxDatagramFrameSizeIsKeptAfterTheHandshake()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(
            cancellation.Token,
            flowControl:
            [
                .. TlsQuicConnectionTests.FlowControlParameters(),
                TlsQuicTransportParameter.VariableInteger(
                    TlsQuicTransportParameterId.MaxDatagramFrameSize, 65535),
            ]);

        Assert.Equal(65535UL, harness.Connection.PeerMaxDatagramFrameSize);
    }

    [Fact]
    public async Task APeerThatSendsNoMaxDatagramFrameSizeLeavesItNull()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(cancellation.Token);

        Assert.Null(harness.Connection.PeerMaxDatagramFrameSize);
    }

    [Fact]
    public async Task AnAdvertisedZeroMeansNoDatagramsAndReadsAsNull()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(
            cancellation.Token,
            flowControl:
            [
                .. TlsQuicConnectionTests.FlowControlParameters(),
                TlsQuicTransportParameter.VariableInteger(
                    TlsQuicTransportParameterId.MaxDatagramFrameSize, 0),
            ]);

        Assert.Null(harness.Connection.PeerMaxDatagramFrameSize);
    }
}
