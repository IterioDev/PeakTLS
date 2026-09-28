using SharpTls.Quic;
using static SharpTls.Tests.Quic.TlsQuicConnectionTests;

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

    [Fact]
    public async Task AQueuedDatagramLeavesAsOneLengthBearingDatagramFrameAndNothingElse()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await Harness.CreateAsync(
            cancellation.Token, flowControl: PeerAcceptingDatagrams());
        var payload = Enumerable.Range(0, 300).Select(i => (byte)i).ToArray();

        Assert.True(harness.Connection.TryQueueDatagram(payload));
        Assert.Equal(1, harness.Connection.QueuedDatagrams);
        await harness.FlushAsync(cancellation.Token);
        Assert.Equal(0, harness.Connection.QueuedDatagrams);

        var frames = harness.Peer.LastDatagramFrames;
        Assert.Contains(frames, f => f.Type == TlsQuicFrameType.Datagram);
        Assert.DoesNotContain(frames, f => f.Type == TlsQuicFrameType.Stream);
        Assert.Equal(payload, harness.Peer.ReceivedDatagrams.Single());
    }

    [Fact]
    public async Task TheQueueRefusesTheSixtyFifthDatagramAndNeverDrops()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await Harness.CreateAsync(
            cancellation.Token, flowControl: PeerAcceptingDatagrams());

        for (var i = 0; i < 64; i++)
        {
            Assert.True(harness.Connection.TryQueueDatagram(new byte[] { (byte)i }));
        }

        Assert.False(harness.Connection.TryQueueDatagram(new byte[] { 0xFF }));
        Assert.Equal(64, harness.Connection.QueuedDatagrams);
    }

    [Fact]
    public async Task QueueingIsRefusedByNameWhenThePeerAcceptsNoDatagrams()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await Harness.CreateAsync(cancellation.Token);

        var exception = Assert.Throws<InvalidOperationException>(
            () => harness.Connection.TryQueueDatagram(new byte[] { 1 }));
        Assert.Contains("max_datagram_frame_size", exception.Message);
    }

    [Fact]
    public async Task APayloadAboveTheFrameCeilingIsRefusedByName()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await Harness.CreateAsync(
            cancellation.Token, flowControl: PeerAcceptingDatagrams());
        var ceiling = harness.Connection.MaximumDatagramFramePayload;

        // Spec() leaves the base MTU at 1200, so the ceiling is 1200 - (1 + DCID + PN + 16) - 3.
        Assert.InRange(ceiling, 1100, 1199);
        Assert.True(harness.Connection.TryQueueDatagram(new byte[ceiling]));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => harness.Connection.TryQueueDatagram(new byte[ceiling + 1]));

        // AND A FRAME AT THE CEILING FITS THE PACKET IT WAS SIZED FOR.
        await harness.FlushAsync(cancellation.Token);
        Assert.Equal(ceiling, harness.Peer.ReceivedDatagrams.Single().Length);
    }

    [Fact]
    public async Task ACongestionBlockedWindowHoldsDatagramsAndReleasesThemInOrder()
    {
        // THE GATE STARTS OPEN: CreateAsync flushes the control streams through the gated path
        // and asserts that SendPendingAsync sent.
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var gate = new ScriptedSendGate { Open = true };
        using var harness = await Harness.CreateAsync(
            cancellation.Token,
            connectionSpec: RetransmittingProbeSpec(gate),
            flowControl: PeerAcceptingDatagrams());
        gate.Open = false;

        Assert.True(harness.Connection.TryQueueDatagram(new byte[] { 1 }));
        Assert.True(harness.Connection.TryQueueDatagram(new byte[] { 2 }));
        Assert.False(await harness.Connection.SendPendingAsync(cancellation.Token));
        Assert.Equal(2, harness.Connection.QueuedDatagrams);

        // ONE DATAGRAM FRAME PER PACKET, so two passes.
        gate.Open = true;
        await harness.FlushAsync(cancellation.Token);
        Assert.Equal(1, harness.Connection.QueuedDatagrams);
        await harness.FlushAsync(cancellation.Token);
        Assert.Equal(0, harness.Connection.QueuedDatagrams);
        Assert.Equal([new byte[] { 1 }, new byte[] { 2 }], harness.Peer.ReceivedDatagrams);
    }

    [Fact]
    public async Task AHeadTheShrunkenPathCannotCarryIsDroppedAndTheNextDatagramStillLeaves()
    {
        // RFC 9221 s5.4. The payload is sized against a raised path MTU, then RFC 8899 s4.3's
        // black-hole detection takes the MTU back to BASE_PLPMTU before it is sent. Kept, it
        // would fit no packet and block every datagram behind it.
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await Harness.CreateAsync(
            cancellation.Token, flowControl: PeerAcceptingDatagrams());

        // CreateAsync's opening flush left a PMTU probe at MaximumPathMtu unacknowledged.
        await harness.Peer.SendCumulativeAckAsync(cancellation.Token);
        await harness.Connection.PumpOnceAsync(cancellation.Token);
        var raised = harness.Connection.CurrentMaxDatagramSize;
        Assert.True(raised > Spec().BasePathMtu, $"the probe did not raise the path: {raised}");
        var unsendable = new byte[harness.Connection.MaximumDatagramFramePayload];
        Assert.True(harness.Connection.TryQueueDatagram(unsendable));

        // s4.3's third indicator: consecutive losses of packets larger than BASE_PLPMTU.
        for (ulong packet = 1000; packet < 1000 + TlsQuicPathMtu.MaximumProbes; packet++)
        {
            harness.Connection.PathMtu.OnPacketLost(packet, raised);
        }

        Assert.Equal(Spec().BasePathMtu, harness.Connection.CurrentMaxDatagramSize);
        Assert.True(unsendable.Length > harness.Connection.MaximumDatagramFramePayload);

        Assert.True(harness.Connection.TryQueueDatagram(new byte[] { 7 }));
        await harness.FlushAsync(cancellation.Token);

        Assert.Equal(1, harness.Connection.DroppedUnsendableDatagrams);
        Assert.Equal(0, harness.Connection.QueuedDatagrams);
        Assert.Equal([new byte[] { 7 }], harness.Peer.ReceivedDatagrams);
    }

    [Fact]
    public async Task APacketCarryingADatagramCarriesNoStreamFrameAndTheStreamDataTakesTheNext()
    {
        // The `!carriesDatagram` guard in TryBuildApplicationPacket. The datagram arm runs
        // first, so the first packet is the datagram's alone; the stream data waits one pass.
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var gate = new ScriptedSendGate { Open = true };
        using var harness = await Harness.CreateAsync(
            cancellation.Token,
            connectionSpec: RetransmittingProbeSpec(gate),
            flowControl: PeerAcceptingDatagrams());
        var stream = harness.Connection.Streams.OpenBidirectional();
        harness.Connection.Streams.Send(stream, new byte[] { 0x11, 0x22, 0x33 });
        Assert.True(harness.Connection.TryQueueDatagram(new byte[] { 1 }));

        var first = await FlushOneDatagramAsync(harness, cancellation.Token);
        Assert.Contains(first, f => f.Type == TlsQuicFrameType.Datagram);
        Assert.DoesNotContain(first, f => f.Type == TlsQuicFrameType.Stream);

        var second = await FlushOneDatagramAsync(harness, cancellation.Token);
        Assert.Contains(second, f => f.Type == TlsQuicFrameType.Stream);
        Assert.DoesNotContain(second, f => f.Type == TlsQuicFrameType.Datagram);
    }

    // LastDatagramFrames is the LAST datagram the peer opened, so each pass must send exactly
    // one for the snapshot to be that pass's packet.
    private static async Task<(TlsQuicEncryptionLevel Level, TlsQuicFrameType Type)[]>
        FlushOneDatagramAsync(Harness harness, CancellationToken cancellationToken)
    {
        var before = harness.ClientTransport.Sent.Count;
        await harness.FlushAsync(cancellationToken);
        Assert.Equal(before + 1, harness.ClientTransport.Sent.Count);
        return [.. harness.Peer.LastDatagramFrames];
    }

    [Fact]
    public void ALostDatagramFrameIsDroppedNotRepaired() =>
        // RFC 9221 s5.2: DATAGRAM frames are not retransmitted.
        Assert.Equal(
            TlsQuicRepairAction.Drop, TlsQuicRetransmission.ActionFor(TlsQuicFrameType.Datagram));

    private static List<TlsQuicTransportParameter> PeerAcceptingDatagrams() =>
    [
        .. FlowControlParameters(),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.MaxDatagramFrameSize, 65535),
    ];
}
