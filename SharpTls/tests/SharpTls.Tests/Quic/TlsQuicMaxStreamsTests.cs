using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

/// <content>
/// RFC 9000 section 4.6's MAX_STREAMS, which this endpoint did not send at all until now: the
/// stream-count limit was enforced at the advertised value and never rose, so a peer that
/// opened <c>initial_max_streams_uni</c> streams got no more for the life of the connection.
/// Bounded rather than wrong for plain HTTP/3 - RFC 9114 section 6.2 needs three - and real for
/// anything that opens and closes streams over time.
/// </content>
public sealed class TlsQuicMaxStreamsTests
{
    private static TlsQuicStreamSet Set(ulong streamsUni, ulong streamsBidi = 0) =>
        new(
            TlsQuicPeerFlowControlBudget.FromPeerParameters(new TlsQuicTransportParameters(
            [
                TlsQuicTransportParameter.VariableInteger(
                    TlsQuicTransportParameterId.InitialMaxData, 1_000_000),
                TlsQuicTransportParameter.VariableInteger(
                    TlsQuicTransportParameterId.InitialMaxStreamsUni, 100),
                TlsQuicTransportParameter.VariableInteger(
                    TlsQuicTransportParameterId.InitialMaxStreamsBidi, 100),
            ])),
            new TlsQuicLocalFlowControlSpec
            {
                InitialMaxStreamsUni = streamsUni,
                InitialMaxStreamsBidi = streamsBidi,
            });

    private static List<TlsQuicFrame> Drain(TlsQuicStreamSet set)
    {
        set.DatagramPayloadBudget = 1200;
        return [.. set.TakePendingFrames(1200)];
    }

    [Fact]
    public void FinishedPeerStreamsAreCreditedCumulativelyAndOnlyOnceTheThresholdIsCrossed()
    {
        // A limit of 4 puts the threshold at 4 / 2 = 2 finished streams, so the first finish
        // grants nothing and the second grants 4 + 2 = 6. THE GRANT IS CUMULATIVE, which is
        // s19.11's own word: "a count of the cumulative number of streams of the corresponding
        // type that can be opened over the lifetime of the connection". A live count would have
        // needed streams to be removed from the set, and nothing removes them.
        var set = Set(streamsUni: 4);

        set.CreditPeerStream(TlsQuicStreamDirection.Unidirectional);
        Assert.Empty(Drain(set));

        set.CreditPeerStream(TlsQuicStreamDirection.Unidirectional);
        var frame = Assert.Single(Drain(set));

        // 0x13 and not 0x12: s19.11 gives MAX_STREAMS two type values, and the low bit is the
        // direction. Asserting the RAW type rather than frame.Type is what makes that
        // observable - both derive to TlsQuicFrameType.MaxStreams.
        Assert.Equal(0x13UL, frame.RawType);
        Assert.Equal(6UL, frame.MaximumStreams);

        // Two more finishes cross the threshold again, from the grant rather than from zero.
        set.CreditPeerStream(TlsQuicStreamDirection.Unidirectional);
        Assert.Empty(Drain(set));
        set.CreditPeerStream(TlsQuicStreamDirection.Unidirectional);
        Assert.Equal(8UL, Assert.Single(Drain(set)).MaximumStreams);
    }

    [Fact]
    public void TheBidirectionalGrantCarriesTheOtherTypeValue()
    {
        var set = Set(streamsUni: 0, streamsBidi: 2);

        set.CreditPeerStream(TlsQuicStreamDirection.Bidirectional);
        var frame = Assert.Single(Drain(set));

        Assert.Equal(0x12UL, frame.RawType);
        Assert.Equal(3UL, frame.MaximumStreams);
    }

    [Fact]
    public void ALimitThatWasNeverAdvertisedIsNeverRaised()
    {
        // RFC 9000 s18.2 makes an absent initial_max_streams_uni zero, and
        // TlsQuicLocalFlowControlSpec.AsAdvertisedBy is what turns an unlisted transport
        // parameter into that zero. Granting from this side would hand the peer a budget the
        // ClientHello said it did not have - the same advertise/enforce divergence
        // TlsQuicStreams.cs's block comment forbids, arriving by the other door.
        var set = Set(streamsUni: 0);

        for (var i = 0; i < 16; i++)
        {
            set.CreditPeerStream(TlsQuicStreamDirection.Unidirectional);
        }

        Assert.Empty(Drain(set));
    }

    [Fact]
    public void OnlyPeerInitiatedStreamsAreCredited()
    {
        // MAX_STREAMS governs what the PEER may open. A stream this endpoint opened is not the
        // peer's to be credited for, and crediting it would raise the peer's budget every time
        // a request of our own finished.
        var set = Set(streamsUni: 2);
        var local = set.OpenUnidirectional();

        set.OnStreamReceiveComplete(local);
        set.OnStreamReceiveComplete(local);

        Assert.Empty(Drain(set));
    }
}
