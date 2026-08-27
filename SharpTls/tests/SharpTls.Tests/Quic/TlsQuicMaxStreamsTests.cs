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

    // THE AUDIT'S FINDING 8: the grant went out and the credit was then refused on use.
    //
    // CreditPeerStream raised _peerStreamGranted and queued s19.11's MAX_STREAMS; the
    // admission check in TryReceive read TlsQuicLocalFlowControlSpec.PeerStreamLimitFor, which
    // returns initial_max_streams_uni verbatim and never moves. So a peer that did exactly what
    // the frame told it to - "a count of the cumulative number of streams of the corresponding
    // type that can be opened over the lifetime of the connection" - was killed with
    // STREAM_LIMIT_ERROR, which is a protocol violation on OUR side and not the peer's.
    //
    // THIS IS ONE TEST AND NOT TWO BECAUSE THE TWO HALVES HAVE TO AGREE. Asserting only that
    // the third stream is accepted would pass against an implementation that had simply deleted
    // the check, so the fourth - one past the grant, at ordinal 3 against a limit of 3 - has to
    // still be refused. s19.11's own worked example is the same shape read at the initial
    // limit: "a server that receives a unidirectional stream limit of 3 is permitted to open
    // streams 3, 7, and 11, but not stream 15."
    //
    // ZERO-LENGTH FRAMES OPEN EVERY STREAM HERE, so no data limit has to be advertised and the
    // COUNT is the only thing under test. s19.8 makes one a frame with a meaning rather than a
    // no-op to optimise away: "When a Stream Data field has a length of 0, the offset in the
    // STREAM frame is the offset of the next byte that would be sent."
    [Fact]
    public void APeerStreamInsideAGrantWeSentIsAdmittedAndTheOneBeyondItIsNot()
    {
        // A limit of 2 puts the threshold at max(1, 2 / 2) = 1 finished stream, so one finish
        // is enough to raise the advertised limit to 2 + 1 = 3.
        var set = Set(streamsUni: 2);

        // s2.1's ordinal 0 of the server-initiated unidirectional type, opened and finished in
        // one frame.
        Assert.True(
            set.TryReceive(Opening(3, fin: true), out var opening),
            $"Refused stream 3 with {opening}.");
        Assert.Equal(3UL, Assert.Single(Drain(set)).MaximumStreams);

        // Ordinal 2, which is inside the 3 we just granted and outside the 2 we started from.
        // THIS IS THE FINDING: the frame above told the peer this stream was allowed.
        Assert.True(
            // NOT finished, only opened. A second FIN would credit the peer AGAIN - the
            // threshold is one stream - and raise the limit to 4 under the assertion below,
            // which would then be measuring the next grant rather than this one.
            set.TryReceive(Opening(11, fin: false), out var granted),
            $"Refused stream 11 with {granted} after advertising a limit of 3 - the peer spent "
                + "credit this endpoint sent it.");

        // Ordinal 3, which is past the grant. Still refused, or the fix above would be a
        // deletion of the limit rather than a correction of which limit it reads.
        Assert.False(set.TryReceive(Opening(15, fin: false), out var beyond));
        Assert.Equal(TlsQuicTransportError.StreamLimitError, beyond);
    }

    // s19.8's zero-length frame, hand-built the way TlsQuicStreamsTests builds every peer
    // frame: this file is about what is DONE with a frame and the encoding is
    // TlsQuicStreamFramesTests'. The OFF bit is absent because the offset is 0 - s19.8: "When
    // the Offset field is absent, the offset is 0" - and the FIN bit is the caller's, because
    // opening a stream and finishing it are two different events for the s4.6 credit.
    private static TlsQuicFrame Opening(ulong streamId, bool fin) => new()
    {
        RawType = (ulong)TlsQuicFrameType.Stream
            | TlsQuicStreamFrames.LengthBit
            | (fin ? TlsQuicStreamFrames.FinBit : 0),
        StreamId = streamId,
        Data = Array.Empty<byte>(),
    };

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
