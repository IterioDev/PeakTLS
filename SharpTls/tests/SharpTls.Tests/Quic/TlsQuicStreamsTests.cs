using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task 14e of A4-minimal: RFC 9000 s2.1's stream identifiers, s19.8's STREAM frames with
// offsets and FIN, and the peer-initiated unidirectional streams RFC 9204 s4.2 requires an
// endpoint to allow.
//
// ============================================================================
// A WITNESS PER s2.1 COMBINATION, NOT A WITNESS PER METHOD.
// ============================================================================
//
//   s2.1's four identifiers differ in TWO BITS. One test that walked all four would pass on an
//   implementation that got three right, and - worse - would pass for the WRONG REASON on the
//   fourth if the assertion were computed the same way the code is. Task 11 shipped a
//   comparison that could not fail by exactly that route.
//
//   So the four tests below each assert THREE HAND-WRITTEN INTEGERS for their own combination
//   and nothing about the other three. The numbers are not derived from TlsQuicStreamId: the
//   ids for ordinals 0, 1 and 7 are 4n, 4n+1, 4n+2 and 4n+3 by s2.1's construction, so they
//   are written out as 0/4/28, 1/5/29, 2/6/30 and 3/7/31 and a reader can check each against
//   the two bits without running anything.
//
//   THE FIFTH TEST IS THE CROSS-CHECK, and it is the one that would catch a derivation that
//   was self-consistently wrong: TlsQuicStreamId.FirstOfEachType is s2.1's table written down
//   as data, From computes the same four ids from the bits, and they must agree. Neither is
//   the other's source.
//
// ============================================================================
// ZERO IS NOT ABSENT, IN FOUR PLACES, AND EACH HAS ITS OWN TEST.
// ============================================================================
//
//   OFFSET 0 VERSUS AN ABSENT OFFSET FIELD. s19.8: "When the Offset field is absent, the
//   offset is 0." Two wire forms, one value. AStreamsFirstFrameOmitsTheOffsetFieldAndItsSecond
//   CarriesIt pins which one this send path emits and why.
//
//   A ZERO-LENGTH STREAM FRAME VERSUS NO FRAME AT ALL. s19.8: "When a Stream Data field has a
//   length of 0, the offset in the STREAM frame is the offset of the next byte that would be
//   sent." AZeroLengthStreamFrameIsQueuedRatherThanSkipped and
//   AZeroLengthStreamFrameIsAcceptedAndIsNotAGap.
//
//   A FIN WITH NO DATA VERSUS A FIN WITH DATA. AFinWithNoDataEndsAStreamWhoseBytesAlready
//   ArrivedAndIsNotTheSameAsNoFrame.
//
//   A STREAM OPENED WITH ZERO CREDIT VERSUS ONE NEVER OPENED. AStreamOpenedWithZeroCreditIs
//   NotTheSameAsAStreamThatWasNeverOpened - the first exists, has spent an ordinal and can
//   still carry a zero-length frame; the second is not there at all and a frame on it is
//   s19.8's STREAM_STATE_ERROR.
//
// ============================================================================
// WHAT THESE CANNOT PIN.
// ============================================================================
//
//   THESE ARE UNIT TESTS OVER TlsQuicFrame VALUES, NOT OVER BYTES. Nothing here encodes or
//   decodes a STREAM frame - TlsQuicStreamFramesTests does that against eight hand-derived
//   wire forms - so a defect in s19.8's field layout is invisible from this file. What is
//   pinned here is which frames are built and what is done with the ones that arrive.
//
//   THE LOOPBACK HALF IS IN TlsQuicConnectionStreamTests AND SHARES OUR BUGS. It proves the
//   frames cross a real AEAD and a real short header; it does not prove the bytes, for the
//   reason task 7's inverted nonce demonstrated by killing 0 of 11 loopback tests.
public sealed class TlsQuicStreamsTests
{
    // ---- RFC 9000 s2.1: one witness per combination ---------------------------------------

    [Fact]
    public void AClientInitiatedBidirectionalStreamIdHasBothTypeBitsClear()
    {
        // s2.1's 0x00 row. Both type bits clear, so the id is four times the ordinal.
        Assert.Equal(0UL, Id(TlsQuicStreamInitiator.Client, TlsQuicStreamDirection.Bidirectional, 0));
        Assert.Equal(4UL, Id(TlsQuicStreamInitiator.Client, TlsQuicStreamDirection.Bidirectional, 1));
        Assert.Equal(28UL, Id(TlsQuicStreamInitiator.Client, TlsQuicStreamDirection.Bidirectional, 7));

        Assert.Equal(TlsQuicStreamInitiator.Client, TlsQuicStreamId.InitiatorOf(28));
        Assert.Equal(TlsQuicStreamDirection.Bidirectional, TlsQuicStreamId.DirectionOf(28));
        Assert.Equal(7UL, TlsQuicStreamId.OrdinalOf(28));
    }

    [Fact]
    public void AServerInitiatedBidirectionalStreamIdHasOnlyTheInitiatorBitSet()
    {
        // s2.1's 0x01 row.
        Assert.Equal(1UL, Id(TlsQuicStreamInitiator.Server, TlsQuicStreamDirection.Bidirectional, 0));
        Assert.Equal(5UL, Id(TlsQuicStreamInitiator.Server, TlsQuicStreamDirection.Bidirectional, 1));
        Assert.Equal(29UL, Id(TlsQuicStreamInitiator.Server, TlsQuicStreamDirection.Bidirectional, 7));

        Assert.Equal(TlsQuicStreamInitiator.Server, TlsQuicStreamId.InitiatorOf(29));
        Assert.Equal(TlsQuicStreamDirection.Bidirectional, TlsQuicStreamId.DirectionOf(29));
        Assert.Equal(7UL, TlsQuicStreamId.OrdinalOf(29));
    }

    [Fact]
    public void AClientInitiatedUnidirectionalStreamIdHasOnlyTheDirectionBitSet()
    {
        // s2.1's 0x02 row - the streams subsystem C opens for its HTTP control stream and
        // QPACK's encoder and decoder.
        Assert.Equal(2UL, Id(TlsQuicStreamInitiator.Client, TlsQuicStreamDirection.Unidirectional, 0));
        Assert.Equal(6UL, Id(TlsQuicStreamInitiator.Client, TlsQuicStreamDirection.Unidirectional, 1));
        Assert.Equal(30UL, Id(TlsQuicStreamInitiator.Client, TlsQuicStreamDirection.Unidirectional, 7));

        Assert.Equal(TlsQuicStreamInitiator.Client, TlsQuicStreamId.InitiatorOf(30));
        Assert.Equal(TlsQuicStreamDirection.Unidirectional, TlsQuicStreamId.DirectionOf(30));
        Assert.Equal(7UL, TlsQuicStreamId.OrdinalOf(30));
    }

    [Fact]
    public void AServerInitiatedUnidirectionalStreamIdHasBothTypeBitsSet()
    {
        // s2.1's 0x03 row - the three streams RFC 9204 s4.2 requires this endpoint to allow
        // its peer to create, and the row A4 task 14's original text left out.
        Assert.Equal(3UL, Id(TlsQuicStreamInitiator.Server, TlsQuicStreamDirection.Unidirectional, 0));
        Assert.Equal(7UL, Id(TlsQuicStreamInitiator.Server, TlsQuicStreamDirection.Unidirectional, 1));
        Assert.Equal(31UL, Id(TlsQuicStreamInitiator.Server, TlsQuicStreamDirection.Unidirectional, 7));

        Assert.Equal(TlsQuicStreamInitiator.Server, TlsQuicStreamId.InitiatorOf(31));
        Assert.Equal(TlsQuicStreamDirection.Unidirectional, TlsQuicStreamId.DirectionOf(31));
        Assert.Equal(7UL, TlsQuicStreamId.OrdinalOf(31));
    }

    [Fact]
    public void TheFourStreamTypesAtOrdinalZeroAreTheTableAndTheDerivationAgreeing()
    {
        // s2.1's table, written as data, against s2.1's bits, computed. A derivation that was
        // self-consistently wrong - the two bits swapped, say - still agrees with itself in
        // the four tests above only if their constants were computed the same way, and they
        // are not; this is the second guard on that.
        Assert.Equal(
            TlsQuicStreamId.FirstOfEachType.ToArray(),
            new[]
            {
                Id(TlsQuicStreamInitiator.Client, TlsQuicStreamDirection.Bidirectional, 0),
                Id(TlsQuicStreamInitiator.Server, TlsQuicStreamDirection.Bidirectional, 0),
                Id(TlsQuicStreamInitiator.Client, TlsQuicStreamDirection.Unidirectional, 0),
                Id(TlsQuicStreamInitiator.Server, TlsQuicStreamDirection.Unidirectional, 0),
            });
    }

    [Fact]
    public void TheLargestStreamIdIsTheLargestVariableLengthInteger()
    {
        // s2.1 puts the ordinal above the two type bits of a variable-length integer, so the
        // largest id there is - both type bits set, ordinal at its ceiling - is exactly
        // QuicVariableLengthInteger.MaximumValue. The boundary is asserted from both sides so
        // the guard cannot be off by one in either direction.
        var largestOrdinal = QuicVariableLengthInteger.MaximumValue >> TlsQuicStreamId.OrdinalShift;

        Assert.Equal(
            QuicVariableLengthInteger.MaximumValue,
            Id(TlsQuicStreamInitiator.Server, TlsQuicStreamDirection.Unidirectional, largestOrdinal));

        Assert.Throws<ArgumentOutOfRangeException>(() => Id(
            TlsQuicStreamInitiator.Client,
            TlsQuicStreamDirection.Bidirectional,
            largestOrdinal + 1));
    }

    [Fact]
    public void AnUndefinedInitiatorOrDirectionIsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => TlsQuicStreamId.From(
            (TlsQuicStreamInitiator)7, TlsQuicStreamDirection.Bidirectional, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => TlsQuicStreamId.From(
            TlsQuicStreamInitiator.Client, (TlsQuicStreamDirection)7, 0));
    }

    // ---- Opening, and which s18.2 limit each kind takes ------------------------------------

    [Fact]
    public void OpenedStreamsTakeConsecutiveOrdinalsWithinTheirOwnType()
    {
        // s2.1 numbers each type separately, so the first unidirectional stream is 0x02 and
        // not 0x06 just because a bidirectional one was opened first. Interleaved on purpose:
        // a single ordinal counter shared by both types passes a test that opens one type.
        var streams = Set();

        Assert.Equal(0UL, streams.OpenBidirectional().Id);
        Assert.Equal(2UL, streams.OpenUnidirectional().Id);
        Assert.Equal(4UL, streams.OpenBidirectional().Id);
        Assert.Equal(6UL, streams.OpenUnidirectional().Id);
        Assert.Equal(10UL, streams.OpenUnidirectional().Id);
    }

    [Fact]
    public void OurOwnStreamsTakeTheirCreditFromTheParameterScopedToTheStreamsWeOpen()
    {
        // s18.2 again, and the 0x05/0x06 flip TlsQuicPeerFlowControlBudget.cs calls its most
        // likely defect, asked here from the STREAM side rather than the budget side.
        var streams = Set();

        Assert.Equal(6006UL, streams.OpenBidirectional().Budget!.Limit);
        Assert.Equal(7007UL, streams.OpenUnidirectional().Budget!.Limit);
    }

    // ---- The send side --------------------------------------------------------------------

    [Fact]
    public void AStreamsFirstFrameOmitsTheOffsetFieldAndItsSecondCarriesIt()
    {
        // s19.8's OFF bit: "When set to 0, the Offset field is absent and the Stream Data
        // starts at an offset of 0". Offset 0 is expressible BOTH ways, so which one this send
        // path chooses is a decision rather than a derivation, and this is where it is pinned.
        var streams = Set();
        var stream = streams.OpenUnidirectional();

        streams.Send(stream, new byte[] { 1, 2, 3 });
        streams.Send(stream, new byte[] { 4, 5 });
        var frames = streams.TakePendingFrames();

        Assert.False(TlsQuicStreamFrames.HasOffset(frames[0].RawType));
        Assert.Equal(0UL, frames[0].Offset);

        Assert.True(TlsQuicStreamFrames.HasOffset(frames[1].RawType));
        Assert.Equal(3UL, frames[1].Offset);

        // s19.8's LEN bit is set on both, always: the implicit form's "Stream Data field
        // extends to the end of the packet" would confine the frame to the end of its packet,
        // and TryBuildApplicationPacket may put an ACK after it.
        Assert.True(TlsQuicStreamFrames.HasLength(frames[0].RawType));
        Assert.True(TlsQuicStreamFrames.HasLength(frames[1].RawType));
        Assert.False(TlsQuicStreamFrames.IsFin(frames[0].RawType));
    }

    [Fact]
    public void AZeroLengthStreamFrameIsQueuedRatherThanSkipped()
    {
        // ZERO VERSUS ABSENT on the Stream Data field. s19.8: "When a Stream Data field has a
        // length of 0, the offset in the STREAM frame is the offset of the next byte that
        // would be sent" - so a zero-length frame is a legal frame with a meaning, not a
        // no-op to be optimised away. A send path that skipped it would leave a caller's FIN
        // unsent.
        var streams = Set();
        var stream = streams.OpenUnidirectional();

        Assert.False(streams.HasPendingFrames);
        streams.Send(stream, ReadOnlyMemory<byte>.Empty);

        Assert.True(streams.HasPendingFrames);
        var frames = streams.TakePendingFrames();
        Assert.Single(frames);
        Assert.Equal(0, frames[0].Data.Length);
        Assert.Equal(0UL, stream.SendOffset);
        Assert.False(stream.FinSent);
    }

    [Fact]
    public void AFinWithNoDataIsAFrameAndNotTheAbsenceOfOne()
    {
        // The FIN half of zero-versus-absent, on the send side. s19.8: "The FIN bit (0x01)
        // indicates that the frame marks the end of the stream. The final size of the stream
        // is the sum of the offset and the length of this frame" - so a FIN carrying nothing
        // at offset 3 declares a final size of 3, which is a statement no absent frame makes.
        var streams = Set();
        var stream = streams.OpenUnidirectional();

        streams.Send(stream, new byte[] { 1, 2, 3 });
        streams.Send(stream, ReadOnlyMemory<byte>.Empty, fin: true);
        var frames = streams.TakePendingFrames();

        Assert.Equal(2, frames.Count);
        Assert.True(TlsQuicStreamFrames.IsFin(frames[1].RawType));
        Assert.Equal(3UL, frames[1].Offset);
        Assert.Equal(0, frames[1].Data.Length);
        Assert.True(stream.FinSent);
        Assert.Equal(3UL, stream.SendOffset);
    }

    [Fact]
    public void SendingAfterTheFinIsRefusedBecauseTheFinalSizeIsFixed()
    {
        var streams = Set();
        var stream = streams.OpenUnidirectional();
        streams.Send(stream, new byte[] { 1 }, fin: true);

        var error = Assert.Throws<InvalidOperationException>(
            () => streams.Send(stream, new byte[] { 2 }));
        Assert.Contains("FIN", error.Message, StringComparison.Ordinal);
        Assert.Equal(1UL, stream.SendOffset);
    }

    [Fact]
    public void SendingOnAServerInitiatedUnidirectionalStreamIsRefusedBecauseItIsReceiveOnly()
    {
        // s2.1's 0x03 row is the peer's to send on. The stream exists here - it was created by
        // a frame arriving - so this is a refusal about DIRECTION and not about existence.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 0, [9]), out _));
        var stream = streams.PeerInitiated[0];

        Assert.False(stream.CanSend);
        Assert.Null(stream.Budget);
        var error = Assert.Throws<InvalidOperationException>(
            () => streams.Send(stream, new byte[] { 1 }));
        Assert.Contains("receive-only", error.Message, StringComparison.Ordinal);
    }

    // ---- Budget exhaustion ----------------------------------------------------------------

    [Fact]
    public void ExhaustingTheStreamsOwnCreditFailsCleanlyRatherThanSendingPastThePeersLimit()
    {
        // THE NAMED WITNESS FOR EXHAUSTION, AND IT NOW SPLITS RATHER THAN REFUSES. RFC 9000
        // s19.10's limit is the PEER's and exceeding it is the FLOW_CONTROL_ERROR the old
        // throw was avoiding - so what has not changed is that only the granted byte leaves.
        // What has changed is the OTHER byte's fate: MAX_STREAM_DATA is handled now, so there
        // IS a later moment in which it can be sent, and it waits for one instead of being
        // rejected along with the byte that fitted.
        var streams = Set(uni: 4);
        var stream = streams.OpenUnidirectional();
        streams.Send(stream, new byte[] { 1, 2, 3 });
        _ = streams.TakePendingFrames();

        streams.Send(stream, new byte[] { 4, 5 });

        // FOUR SENT, ONE HELD. A truncating send path would have dropped the 5 entirely and a
        // credit-blind one would have sent it.
        Assert.Equal(4UL, stream.SendOffset);
        Assert.Equal(0UL, stream.Budget!.Remaining);
        Assert.Equal(1UL, stream.BlockedBytes);

        var queued = streams.TakePendingFrames();
        Assert.Equal(
            new byte[] { 4 },
            Assert.Single(queued, each => each.Type == TlsQuicFrameType.Stream).Data.ToArray());

        // AND s19.13'S SIGNAL WENT WITH IT: "A sender SHOULD send a STREAM_DATA_BLOCKED frame
        // (type=0x15) when it wishes to send data but is unable to do so due to stream-level
        // flow control."
        var blocked = Assert.Single(
            queued, each => each.Type == TlsQuicFrameType.StreamDataBlocked);
        Assert.Equal(stream.Id, blocked.StreamId);

        // THE GRANT RELEASES EXACTLY THE HELD BYTE and no more.
        Assert.True(streams.TryReceiveMaxStreamData(MaxStreamData(stream.Id, 5), out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(5UL, stream.SendOffset);
        Assert.False(stream.HasBlockedData);
        Assert.Equal(
            new byte[] { 5 },
            Assert.Single(streams.TakePendingFrames()).Data.ToArray());
    }

    [Fact]
    public void AFinRidesOnlyTheFrameCarryingTheLastByteAndClosesTheStreamWhileItWaits()
    {
        // ============================================================================
        // THREE MUTATIONS SURVIVED THE FIRST SWEEP AND THIS TEST IS WHY THEY WILL NOT.
        // ============================================================================
        //
        // Splitting a write means the FIN outlives the call that supplied it, and every way
        // of getting that wrong leaves the whole 2,473-case gate green:
        //
        //   A4C-16  a PARTIAL take carries the FIN - so the peer sees the stream end at the
        //           first chunk and RFC 9000 s4.5 fixes a final size three bytes short of the
        //           body. Every other test sends a FIN that fits in one frame.
        //   A4C-18  a FULL take of a NON-LAST entry carries it - the same lie, one entry
        //           later, and invisible unless two writes are queued at once.
        //   A4C-21  Send's guard reads FinSent instead of FinQueued - so a caller may write
        //           AFTER a FIN that is merely waiting for credit, which puts bytes past the
        //           end of the stream.
        //
        // s19.8 is the sentence all three break: the FIN bit "indicates that the frame marks
        // the end of the stream", and "the final size of the stream is the sum of the offset
        // and the length of this frame".
        var streams = Set(uni: 2);

        // ---- A4C-16's shape: the FIN is pending from the FIRST write ----------------------
        //
        // AND THE ORDER IS THE WHOLE POINT. A first attempt at this test queued the FIN in a
        // SECOND Send, which meant the only partial take happened while _blockedFin was still
        // false - so the mutant that copies _blockedFin onto a partial take copied a false and
        // the row survived a second time. The FIN has to be in flight BEFORE the split for the
        // split to be able to steal it. This is the shape TlsQuicHttp3Connection actually
        // produces: one Send carrying HEADERS, body and FIN together.
        var early = streams.OpenUnidirectional();
        streams.Send(early, new byte[] { 1, 2, 3, 4 }, fin: true);

        var partial = Assert.Single(
            streams.TakePendingFrames(), each => each.Type == TlsQuicFrameType.Stream);
        Assert.Equal(new byte[] { 1, 2 }, partial.Data.ToArray());
        Assert.False(TlsQuicStreamFrames.IsFin(partial.RawType));
        Assert.False(early.FinSent);
        Assert.True(early.FinQueued);

        // ---- A4C-18's shape: a FULL take of a NON-LAST entry ------------------------------
        var stream = streams.OpenUnidirectional();

        streams.Send(stream, new byte[] { 1, 2, 3 });
        streams.Send(stream, new byte[] { 4 }, fin: true);

        // TWO BYTES OF CREDIT AGAINST A THREE-BYTE HEAD: a partial take, and it must not be
        // the end of anything.
        var first = Assert.Single(
            streams.TakePendingFrames(), each => each.Type == TlsQuicFrameType.Stream);
        Assert.Equal(new byte[] { 1, 2 }, first.Data.ToArray());
        Assert.False(TlsQuicStreamFrames.IsFin(first.RawType));

        // ONE MORE BYTE: this take EMPTIES the head entry, so it is a full take - and it is
        // still not the last entry, which is the distinction A4C-18 erases.
        Assert.True(streams.TryReceiveMaxStreamData(MaxStreamData(stream.Id, 3), out _));
        var second = Assert.Single(
            streams.TakePendingFrames(), each => each.Type == TlsQuicFrameType.Stream);
        Assert.Equal(new byte[] { 3 }, second.Data.ToArray());
        Assert.False(TlsQuicStreamFrames.IsFin(second.RawType));

        // THE FIN IS QUEUED AND NOT SENT, AND THE STREAM IS CLOSED TO WRITERS ANYWAY. Reading
        // FinSent here says "still open" and lets the byte below through, three bytes past a
        // final size the peer has not been told yet.
        Assert.False(stream.FinSent);
        Assert.True(stream.FinQueued);
        var error = Assert.Throws<InvalidOperationException>(
            () => streams.Send(stream, new byte[] { 9 }));
        Assert.Contains("FIN bit", error.Message, StringComparison.Ordinal);

        // THE LAST BYTE, AND ONLY NOW THE FIN.
        Assert.True(streams.TryReceiveMaxStreamData(MaxStreamData(stream.Id, 4), out _));
        var third = Assert.Single(
            streams.TakePendingFrames(), each => each.Type == TlsQuicFrameType.Stream);
        Assert.Equal(new byte[] { 4 }, third.Data.ToArray());
        Assert.True(TlsQuicStreamFrames.IsFin(third.RawType));
        Assert.True(stream.FinSent);
        Assert.Equal(4UL, stream.SendOffset);
        Assert.False(stream.HasBlockedData);
    }

    [Fact]
    public void AStreamDataBlockedFrameCarriesTheOffsetWhichIsAlsoTheLimit()
    {
        // ============================================================================
        // s19.12 AND s19.13 DISAGREE ABOUT WHAT THEIR IDENTICAL FIELD MEANS.
        // ============================================================================
        //
        // rfc9000-section19-frame-formats.txt, read past the wrap, gives DATA_BLOCKED's field
        // as "A variable-length integer indicating the connection-level LIMIT at which
        // blocking occurred" and STREAM_DATA_BLOCKED's - the same name, the same width, the
        // analogous frame - as "A variable-length integer indicating the OFFSET of the stream
        // at which the blocking occurred". Limit in one, offset in the other.
        //
        // FOLLOWED: each section's own word. DATA_BLOCKED carries the connection limit and
        // STREAM_DATA_BLOCKED carries the send offset. THE TWO CANDIDATES COINCIDE HERE and
        // this test asserts against both, which is the only honest way to pin a field whose
        // two readings cannot be told apart: TlsQuicStreamSet.Drain only emits the frame when
        // the per-stream credit is exhausted, and an exhausted per-stream credit means every
        // granted byte has been sent, so SendOffset IS Limit at that instant. A future
        // blocking condition that fires with credit to spare - a datagram-sized cap on the
        // frame, say - would separate them, and this test would fail rather than silently
        // pick one.
        //
        // WRITTEN BECAUSE THE MUTATION SURVIVED: sweep row A4C-13 replaced the field with a
        // literal 0 and the whole 2,473-case gate stayed green. Nothing anywhere read it.
        var streams = Set(connectionData: 1_000_000, uni: 6);
        var stream = streams.OpenUnidirectional();

        streams.Send(stream, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 });

        var blocked = Assert.Single(
            streams.TakePendingFrames(),
            each => each.Type == TlsQuicFrameType.StreamDataBlocked);

        // s19.13's own word - the offset at which the blocking occurred.
        Assert.Equal(stream.SendOffset, blocked.MaximumStreamData);

        // s19.12's word, applied to the same field by analogy - the limit at which it
        // occurred. Both are 6, and the literal 6 is here so that a build in which BOTH
        // properties moved together still fails.
        Assert.Equal(stream.Budget!.Limit, blocked.MaximumStreamData);
        Assert.Equal(6UL, blocked.MaximumStreamData);

        // AND IT IS NOT THE BLOCKED BYTE COUNT, which is the third number in play and the one
        // a reader guessing from the frame's name would reach for.
        Assert.Equal(3UL, stream.BlockedBytes);
        Assert.NotEqual(stream.BlockedBytes, blocked.MaximumStreamData);
    }

    [Fact]
    public void ASecondBlockOnOneStreamSignalsOnceUntilTheLimitMoves()
    {
        // s13.3: a blocked signal is re-sent "only while the endpoint is blocked on the
        // corresponding limit", which is about the CONDITION and not about every write made
        // while it holds. A caller writing a body in chunks against an exhausted limit would
        // otherwise queue one STREAM_DATA_BLOCKED per chunk.
        var streams = Set(uni: 1);
        var stream = streams.OpenUnidirectional();

        streams.Send(stream, new byte[] { 1, 2 });
        Assert.Single(
            streams.TakePendingFrames(),
            each => each.Type == TlsQuicFrameType.StreamDataBlocked);

        streams.Send(stream, new byte[] { 3 });
        Assert.DoesNotContain(
            streams.TakePendingFrames(),
            each => each.Type == TlsQuicFrameType.StreamDataBlocked);

        // THE LIMIT MOVES BUT NOT FAR ENOUGH, so the block is a NEW block and signals again.
        Assert.True(streams.TryReceiveMaxStreamData(MaxStreamData(stream.Id, 2), out _));
        Assert.Single(
            streams.TakePendingFrames(),
            each => each.Type == TlsQuicFrameType.StreamDataBlocked);
    }

    [Fact]
    public void ExhaustingTheConnectionCreditFailsEvenWhenEveryStreamFitsItsOwn()
    {
        // The other level. Two streams whose per-stream limits are ample and whose sum exceeds
        // initial_max_data (0x04). A send path that consulted only the per-stream limit would
        // let all six bytes through.
        var streams = Set(connectionData: 5, uni: 100);
        var first = streams.OpenUnidirectional();
        var second = streams.OpenUnidirectional();

        streams.Send(first, new byte[] { 1, 2, 3 });
        streams.Send(second, new byte[] { 4, 5, 6, 7, 8 });

        // TWO OF THE SECOND STREAM'S FIVE, which is the whole connection allowance and not
        // this stream's own - it has 98 of its 100 left and cannot spend one of them.
        Assert.Equal(2UL, second.SendOffset);
        Assert.Equal(98UL, second.Budget!.Remaining);
        Assert.Equal(3UL, second.BlockedBytes);

        // s19.12's signal, once, for the connection scope: "A sender SHOULD send a
        // DATA_BLOCKED frame (type=0x14) when it wishes to send data but is unable to do so
        // due to connection-level flow control", carrying "the connection-level limit at which
        // blocking occurred".
        var blocked = Assert.Single(
            streams.TakePendingFrames(), each => each.Type == TlsQuicFrameType.DataBlocked);
        Assert.Equal(5UL, blocked.MaximumData);

        // A GRANT THAT RAISES BUT DOES NOT UNBLOCK RE-SIGNALS, AND CARRIES THE NEW LIMIT.
        // s13.3: a blocked frame is re-sent "only while the endpoint is blocked on the
        // corresponding limit" and "always include[s] the limit that is causing blocking at
        // the time that they are transmitted". WRITTEN BECAUSE THE MUTATION SURVIVED: sweep
        // row A4C-27 left the connection's signal latched after a raise, so the second block
        // went unannounced and the peer had no reason to grant again - a stall the whole gate
        // called green, because every other MAX_DATA in the suite unblocked completely.
        streams.ReceiveMaxData(MaxData(6));
        Assert.Equal(3UL, second.SendOffset);
        Assert.Equal(2UL, second.BlockedBytes);
        var again = Assert.Single(
            streams.TakePendingFrames(), each => each.Type == TlsQuicFrameType.DataBlocked);
        Assert.Equal(6UL, again.MaximumData);

        // AND s19.9'S GRANT RELEASES IT. Not the stream's own limit, which was never the
        // binding one.
        streams.ReceiveMaxData(MaxData(8));
        Assert.Equal(5UL, second.SendOffset);
        Assert.False(second.HasBlockedData);
        Assert.DoesNotContain(
            streams.TakePendingFrames(), each => each.Type == TlsQuicFrameType.DataBlocked);
    }

    [Fact]
    public void AStreamOpenedWithZeroCreditIsNotTheSameAsAStreamThatWasNeverOpened()
    {
        // ZERO VERSUS ABSENT, on the budget. A peer advertising initial_max_stream_data_uni of
        // 0 has granted a stream and no bytes to put on it - s18.2's own reading, per
        // TlsQuicPeerFlowControlBudget.cs's header - which is a different state from a stream
        // nobody opened. The opened one exists, has spent an ordinal, and can still carry the
        // zero-length frame s19.8 defines; the never-opened one is not there at all.
        var streams = Set(uni: 0);
        var stream = streams.OpenUnidirectional();

        Assert.Same(stream, streams.Find(2));
        Assert.Equal(0UL, stream.Budget!.Limit);
        Assert.Null(streams.Find(6));

        streams.Send(stream, ReadOnlyMemory<byte>.Empty);
        Assert.True(streams.HasPendingFrames);
        _ = streams.TakePendingFrames();

        // A ZERO LIMIT IS A LIMIT AND NOT A SPECIAL CASE. The byte is held rather than sent,
        // exactly as it would be at any other exhausted limit, and a MAX_STREAM_DATA is what
        // releases it - which is the peer's own reading of s18.2: an initial limit of 0 is
        // "equivalent to sending a MAX_STREAM_DATA frame of 0", not a stream that can never
        // carry anything.
        streams.Send(stream, new byte[] { 1 });
        Assert.Equal(0UL, stream.SendOffset);
        Assert.Equal(1UL, stream.BlockedBytes);

        Assert.True(streams.TryReceiveMaxStreamData(MaxStreamData(stream.Id, 1), out _));
        Assert.Equal(1UL, stream.SendOffset);
        Assert.False(stream.HasBlockedData);
    }

    // ---- Receiving: peer-initiated streams, ordering, and FIN -----------------------------

    [Fact]
    public void APeerInitiatedUnidirectionalStreamIsAcceptedWithoutHavingBeenOpened()
    {
        // RFC 9204 s4.2, last clause: "An endpoint MUST allow its peer to create an encoder
        // stream and a decoder stream even if the connection's settings prevent their use."
        // s19.8 supplies the mechanism - "STREAM frames implicitly create a stream" - and this
        // is the half A4 task 14's original text left out and subsystem C cannot start
        // without: an HTTP/3 server opens three of these before it has heard anything from us.
        var streams = Set();

        Assert.True(streams.TryReceive(Frame(3, 0, [7, 8, 9]), out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);

        var stream = Assert.Single(streams.PeerInitiated);
        Assert.Equal(3UL, stream.Id);
        Assert.True(stream.CanReceive);
        Assert.False(stream.CanSend);
        Assert.Equal(new byte[] { 7, 8, 9 }, stream.Received);
    }

    [Fact]
    public void APeerInitiatedStreamSpendsNoneOfOurOwnStreamAllowance()
    {
        // s18.2 scopes initial_max_streams_uni to the streams WE open. A peer opening one
        // against our allowance would let three QPACK streams starve subsystem C of the three
        // s6.2 requires it to open.
        var streams = Set(streamsUni: 3);
        Assert.True(streams.TryReceive(Frame(3, 0, [1]), out _));
        Assert.True(streams.TryReceive(Frame(7, 0, [1]), out _));
        Assert.Equal(2, streams.PeerInitiated.Count);

        // ALL THREE THE PEER GRANTED ARE STILL THERE, and the FOURTH is the one refused. Had
        // the two peer-opened streams been charged to our allowance, the first of these would
        // have thrown.
        Assert.Equal(2UL, streams.OpenUnidirectional().Id);
        Assert.Equal(6UL, streams.OpenUnidirectional().Id);
        Assert.Equal(10UL, streams.OpenUnidirectional().Id);
        Assert.Throws<InvalidOperationException>(() => streams.OpenUnidirectional());
    }

    [Fact]
    public void BytesArrivingOutOfOrderAreDeliveredInStreamOrder()
    {
        // ORDERING IS THE THING STREAMS GET WRONG, and out-of-order arrival is witnessed
        // explicitly rather than assumed not to happen: RFC 9000 s2.2 makes a stream an
        // ordered byte sequence and the datagrams carrying it unordered.
        var streams = Set();

        Assert.True(streams.TryReceive(Frame(3, 4, [5, 6]), out _));
        var stream = streams.PeerInitiated[0];

        // NOTHING YET. The second frame's bytes are held, not delivered, because the first
        // four are missing - which is the whole difference between reassembly and appending.
        Assert.Empty(stream.Received);

        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2, 3, 4]), out _));
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6 }, stream.Received);
    }

    [Fact]
    public void AGapInTheMiddleHoldsEverythingAfterItUntilItIsFilled()
    {
        // Three pieces, the middle one last. A drain that stopped after moving one piece would
        // deliver 0-1 and leave 4-5 held forever.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2]), out _));
        Assert.True(streams.TryReceive(Frame(3, 4, [5, 6]), out _));
        var stream = streams.PeerInitiated[0];
        Assert.Equal(new byte[] { 1, 2 }, stream.Received);

        Assert.True(streams.TryReceive(Frame(3, 2, [3, 4]), out _));
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6 }, stream.Received);
    }

    [Fact]
    public void AnOverlappingRetransmissionDeliversOnlyTheBytesBeyondWhatWasAlreadyDelivered()
    {
        // A HOSTILE OR MERELY LOSSY PEER, and the case that separates "reject overlaps" from
        // "trim them": the second frame repeats two delivered bytes and carries two new ones.
        // Rejecting it strands the new bytes; appending it whole duplicates the old ones.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2, 3]), out _));
        Assert.True(streams.TryReceive(Frame(3, 1, [2, 3, 4, 5]), out var error));

        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, streams.PeerInitiated[0].Received);
    }

    [Fact]
    public void ARetransmissionBehindAGapThatCarriesMoreBytesReplacesTheShorterOne()
    {
        // BEHIND A GAP, WHICH IS THE ONLY PLACE THE CHOICE IS OBSERVABLE. Two pieces at the
        // same offset are both held rather than delivered while the bytes before them are
        // missing, and only then does "which of the two do we keep" have an answer that
        // matters: keeping the shorter one strands the bytes past it forever, because RFC 9000
        // s13.3's retransmission has already happened and nothing will send them again.
        //
        // WRITTEN BECAUSE THE MUTATION SURVIVED. Reversing the length comparison left the
        // whole 1262-case gate green - every other overlap in this file resolves at an offset
        // the drain reaches immediately, so the two pieces never coexist.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 4, [5, 6]), out _));
        Assert.True(streams.TryReceive(Frame(3, 4, [5, 6, 7, 8]), out _));
        Assert.Empty(streams.PeerInitiated[0].Received);

        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2, 3, 4]), out _));
        Assert.Equal(
            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, streams.PeerInitiated[0].Received);
    }

    [Fact]
    public void ADuplicateOfBytesAlreadyDeliveredIsAcceptedAndChangesNothing()
    {
        // RFC 9000 s2.2 makes the comparison OPTIONAL - "An endpoint MAY treat receipt of
        // different data at the same offset within a stream as a connection error of type
        // PROTOCOL_VIOLATION" - and this endpoint takes the other branch and ignores the
        // duplicate. Pinned so that the absence of a comparison is a recorded choice rather
        // than an oversight, and so that a duplicate cannot append.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2, 3]), out _));
        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2, 3]), out var error));

        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(new byte[] { 1, 2, 3 }, streams.PeerInitiated[0].Received);
    }

    [Fact]
    public void AZeroLengthStreamFrameIsAcceptedAndIsNotAGap()
    {
        // ZERO VERSUS ABSENT on the receive side. s19.8 gives a zero-length frame a meaning -
        // "the offset in the STREAM frame is the offset of the next byte that would be sent" -
        // and an implementation that buffered it as a piece would leave an entry at an offset
        // no drain could consume, stalling every later byte behind it.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 6, []), out var far));
        Assert.Equal(TlsQuicTransportError.NoError, far);

        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2]), out _));
        Assert.Equal(new byte[] { 1, 2 }, streams.PeerInitiated[0].Received);
    }

    [Fact]
    public void AFinWithNoDataEndsAStreamWhoseBytesAlreadyArrivedAndIsNotTheSameAsNoFrame()
    {
        // The receive half of zero-versus-absent for FIN. Two frames that differ ONLY in the
        // FIN bit, both carrying nothing: one ends the stream and one does not.
        var open = Set();
        Assert.True(open.TryReceive(Frame(3, 0, [1, 2]), out _));
        Assert.True(open.TryReceive(Frame(3, 2, []), out _));
        Assert.False(open.PeerInitiated[0].FinReceived);
        Assert.Null(open.PeerInitiated[0].FinalSize);

        var closed = Set();
        Assert.True(closed.TryReceive(Frame(3, 0, [1, 2]), out _));
        Assert.True(closed.TryReceive(Frame(3, 2, [], fin: true), out _));
        Assert.True(closed.PeerInitiated[0].FinReceived);
        Assert.Equal(2UL, closed.PeerInitiated[0].FinalSize);
        Assert.True(closed.PeerInitiated[0].ReceiveComplete);
        Assert.Equal(new byte[] { 1, 2 }, closed.PeerInitiated[0].Received);
    }

    [Fact]
    public void AFinThatOvertakesItsOwnStreamDataIsNotCompleteUntilTheGapIsFilled()
    {
        // s19.8's FIN rides on a frame like any other and may arrive first. FinReceived and
        // ReceiveComplete are separate properties for exactly this: knowing where the stream
        // ends is not the same as having everything before that point.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 2, [3, 4], fin: true), out _));
        var stream = streams.PeerInitiated[0];

        Assert.True(stream.FinReceived);
        Assert.Equal(4UL, stream.FinalSize);
        Assert.False(stream.ReceiveComplete);

        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2]), out _));
        Assert.True(stream.ReceiveComplete);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, stream.Received);
    }

    [Fact]
    public void ASecondFinAgreeingWithTheFirstIsALegalRetransmission()
    {
        // s20.1's FINAL_SIZE_ERROR case (3) is about a DIFFERENT final size. The same one
        // again is a retransmission, and refusing it would close a connection on a peer doing
        // exactly what RFC 9000 s13.3 has it do with a frame it thinks was lost.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2], fin: true), out _));
        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2], fin: true), out var error));

        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(new byte[] { 1, 2 }, streams.PeerInitiated[0].Received);
    }

    // ---- Receiving: every refusal, and none of them a throw -------------------------------

    [Fact]
    public void AStreamFrameOnAStreamThisEndpointNeverOpenedIsStreamStateError()
    {
        // s19.8: "An endpoint MUST terminate the connection with error STREAM_STATE_ERROR if
        // it receives a STREAM frame for a locally initiated stream that has not yet been
        // created". Stream 0 is client-initiated and bidirectional; this endpoint is the
        // client and has opened nothing.
        var streams = Set();

        Assert.False(streams.TryReceive(Frame(0, 0, [1]), out var error));
        Assert.Equal(TlsQuicTransportError.StreamStateError, error);
        Assert.Empty(streams.PeerInitiated);
        Assert.Null(streams.Find(0));
    }

    [Fact]
    public void AStreamFrameOnOurOwnUnidirectionalStreamIsStreamStateError()
    {
        // s19.8's second half, "or for a send-only stream". The stream EXISTS here - we opened
        // it - so this refusal and the one above are different checks reached by different
        // inputs, and neither test can stand in for the other.
        var streams = Set();
        var stream = streams.OpenUnidirectional();

        Assert.False(streams.TryReceive(Frame(stream.Id, 0, [1]), out var error));
        Assert.Equal(TlsQuicTransportError.StreamStateError, error);
        Assert.Empty(stream.Received);
    }

    [Fact]
    public void AServerInitiatedBidirectionalStreamIsAcceptedAndTakesTheBidiLocalLimit()
    {
        // s2.1's 0x01 row, and the reason TlsQuicPeerFlowControlBudget has an
        // AcceptBidirectionalStream distinct from its two Open methods: s18.2 scopes
        // initial_max_stream_data_bidi_local (0x05) to the streams the PEER opens.
        var streams = Set();

        Assert.True(streams.TryReceive(Frame(1, 0, [1]), out _));
        var stream = Assert.Single(streams.PeerInitiated);

        Assert.True(stream.CanSend);
        Assert.Equal(5005UL, stream.Budget!.Limit);
    }

    [Fact]
    public void DataPastAnEstablishedFinalSizeIsFinalSizeError()
    {
        // s20.1 FINAL_SIZE_ERROR case (1): "An endpoint received a STREAM frame containing
        // data that exceeded the previously established final size."
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2], fin: true), out _));

        Assert.False(streams.TryReceive(Frame(3, 2, [3]), out var error));
        Assert.Equal(TlsQuicTransportError.FinalSizeError, error);
        Assert.Equal(new byte[] { 1, 2 }, streams.PeerInitiated[0].Received);
    }

    [Fact]
    public void AFinBelowWhatWasAlreadyReceivedIsFinalSizeError()
    {
        // s20.1 FINAL_SIZE_ERROR case (2): "an endpoint received a STREAM frame ... containing
        // a final size that was lower than the size of stream data that was already received."
        // The one direction case (1) cannot catch, because on the FIRST FIN there is no
        // established size for anything to exceed.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2, 3, 4]), out _));

        Assert.False(streams.TryReceive(Frame(3, 0, [1, 2], fin: true), out var error));
        Assert.Equal(TlsQuicTransportError.FinalSizeError, error);
        Assert.False(streams.PeerInitiated[0].FinReceived);
    }

    [Fact]
    public void AFinBelowBytesHeldButNotYetDeliveredIsAlsoFinalSizeError()
    {
        // The same case (2) reached through the UNDELIVERED half. Bytes sitting behind a gap
        // are "already received" in s20.1's sense even though nothing has delivered them, and
        // a check that compared only against the delivered prefix would accept this and then
        // deliver past the final size later.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 6, [7, 8]), out _));
        Assert.Empty(streams.PeerInitiated[0].Received);

        Assert.False(streams.TryReceive(Frame(3, 0, [1, 2], fin: true), out var error));
        Assert.Equal(TlsQuicTransportError.FinalSizeError, error);
    }

    [Fact]
    public void ASecondFinWithADifferentFinalSizeIsFinalSizeError()
    {
        // s20.1 FINAL_SIZE_ERROR case (3): "a different final size to the one already
        // established." Below the first, so that case (1)'s "exceeded" cannot be what rejects
        // it and this test pins case (3) alone.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2, 3], fin: true), out _));

        Assert.False(streams.TryReceive(Frame(3, 0, [1, 2], fin: true), out var error));
        Assert.Equal(TlsQuicTransportError.FinalSizeError, error);
        Assert.Equal(3UL, streams.PeerInitiated[0].FinalSize);
    }

    [Fact]
    public void ASecondFinBelowTheFirstWhileTheStreamIsStillEmptyIsFinalSizeErrorToo()
    {
        // s20.1's case (3) AS THE SOLE CAUSE, which is the only input that reaches it. A
        // differing final size ABOVE the established one is caught by case (1)'s "exceeded the
        // previously established final size" first; a differing one BELOW is caught by case
        // (2)'s "lower than the size of stream data that was already received" - UNLESS
        // nothing has been received yet, which is exactly this: a FIN that overtakes its own
        // stream data declares a final size of 4 with zero bytes delivered and zero held, and
        // a second FIN at 2 is then below the first and above everything received.
        //
        // WRITTEN BECAUSE THE MUTATION SURVIVED. Deleting case (3) left the whole gate green,
        // ASecondFinWithADifferentFinalSizeIsFinalSizeError included: its stream has three
        // bytes delivered, so case (2) catches its second FIN and the check under test never
        // has to fire.
        var streams = Set();
        Assert.True(streams.TryReceive(Frame(3, 4, [], fin: true), out _));
        Assert.Equal(4UL, streams.PeerInitiated[0].FinalSize);
        Assert.Empty(streams.PeerInitiated[0].Received);

        Assert.False(streams.TryReceive(Frame(3, 2, [], fin: true), out var error));
        Assert.Equal(TlsQuicTransportError.FinalSizeError, error);
        Assert.Equal(4UL, streams.PeerInitiated[0].FinalSize);
    }

    [Fact]
    public void AnOffsetPastWhatThisEndpointWillHoldIsRefusedRatherThanAllocated()
    {
        // AN ABSURD OFFSET, which is a peer choosing the size of our allocation. The boundary
        // is asserted from both sides so the guard cannot be off by one: one byte ending
        // exactly at the limit is accepted, and the same byte one further along is refused
        // with s20.1's FLOW_CONTROL_ERROR.
        //
        // AND THE BOUNDARY IS NOW THE ADVERTISED NUMBER. Before C9 it was a 1 MiB constant
        // that nothing put on the wire; the limit named below is the initial_max_stream_data_
        // uni (0x07) this endpoint emits, so moving the parameter moves the guard, and a peer
        // conforming to what we told it can never be refused. Stream 3 is s2.1's server-
        // initiated unidirectional type, which is the one 0x07 governs.
        var local = new TlsQuicLocalFlowControlSpec { InitialMaxStreamDataUni = 4096 };
        var streams = Set(local: local);
        var last = local.InitialMaxStreamDataUni - 1;

        Assert.True(streams.TryReceive(Frame(3, last, [1]), out _));
        Assert.False(streams.TryReceive(Frame(3, last + 1, [1]), out var error));
        Assert.Equal(TlsQuicTransportError.FlowControlError, error);
    }

    [Fact]
    public void MorePeerInitiatedStreamsThanThisEndpointTracksIsStreamLimitError()
    {
        // s20.1 STREAM_LIMIT_ERROR (0x04). Without it a peer opens streams until the process
        // dies, which is the s19.8 "STREAM frames implicitly create a stream" clause read
        // without a bound.
        //
        // THE LIMIT IS THE ADVERTISED initial_max_streams_uni (0x09), and the shape is
        // s19.11's own worked example: "a server that receives a unidirectional stream limit
        // of 3 is permitted to open streams 3, 7, and 11, but not stream 15." Four here rather
        // than three so the loop and the refusal are separate numbers.
        var local = new TlsQuicLocalFlowControlSpec { InitialMaxStreamsUni = 4 };
        var streams = Set(local: local);
        for (var index = 0UL; index < local.InitialMaxStreamsUni; index++)
        {
            Assert.True(streams.TryReceive(Frame((index << 2) | 3, 0, [1]), out _));
        }

        var overflowing = (local.InitialMaxStreamsUni << 2) | 3;
        Assert.False(streams.TryReceive(Frame(overflowing, 0, [1]), out var error));
        Assert.Equal(TlsQuicTransportError.StreamLimitError, error);
        Assert.Null(streams.Find(overflowing));

        // AND A FRAME ON A STREAM ALREADY TRACKED STILL WORKS. The limit is on CREATION, so a
        // check placed after the lookup rather than inside it would break every open stream
        // the moment an id past the advertised limit arrived.
        Assert.True(streams.TryReceive(Frame(3, 1, [2]), out _));
    }

    [Theory]
    [InlineData(0UL, 0UL, 1, false)]
    [InlineData(2UL, 0UL, 1, false)]
    [InlineData(3UL, ulong.MaxValue, 1, false)]
    [InlineData(3UL, 0UL, 0, true)]
    [InlineData(3UL, QuicVariableLengthInteger.MaximumValue, 4, false)]
    [InlineData(ulong.MaxValue, 0UL, 1, false)]
    public void NoPeerControlledStreamFrameMakesTryReceiveThrow(
        ulong streamId, ulong offset, int length, bool expected)
    {
        // 9a-ii SHIPPED AN OFF-PATH REMOTE KILL SWITCH, and a peer-initiated stream is
        // peer-CONTROLLED even after the AEAD has authenticated it: the stream id, the offset
        // and the length are all the peer's to choose. Every row here is a value a hostile
        // server can put in a 1-RTT packet - a locally initiated id, one of our own send-only
        // ids, an offset one below 2^64 whose end wraps, a zero length, an offset at s19.8's
        // own 2^62-1 ceiling with data past it, and an id ABOVE the varint range that no
        // encoder could produce but a hand-built frame can.
        //
        // THAT LAST ROW CHANGED VERDICT AT C9 AND THE OLD REASONING WAS RIGHT WHEN IT WAS
        // WRITTEN. It read "ACCEPTED and not refused, which is deliberate: ... inventing a
        // rejection for an id TlsQuicStreamFrames.TryReadStream can never hand us would be a
        // guard with no reachable input." The guard was invented for a different reason -
        // s20.1's STREAM_LIMIT_ERROR is now measured against the initial_max_streams_uni we
        // advertise rather than against a 64-stream constant - and 2^64-1 shifted right two
        // bits is an ordinal enormously past any advertised limit, so it is refused as a side
        // effect of a rule that has plenty of reachable inputs. Still a verdict, still no
        // throw, which is what this test is about.
        //
        // The assertion is that a VERDICT comes back, whichever it is. The individual codes
        // are pinned by the named tests above; this one is about the absence of a throw.
        var streams = Set();
        var stream = streams.OpenUnidirectional();
        Assert.Equal(2UL, stream.Id);

        Assert.Equal(expected, streams.TryReceive(Frame(streamId, offset, new byte[length]), out _));
    }

    // ---- C9's receive side: the advertised limits, and the frames that raise them -----------

    // THE TEST THAT WOULD HAVE CAUGHT FINDING 2, and it is the only one here that fails against
    // the code as it stood: A4-minimal enforced a fixed window and sent no MAX_STREAM_DATA or
    // MAX_DATA, so a stream stopped dead at the initial window no matter how much the
    // application consumed. The HTTP/3 spike's response was 4,943 bytes and fit under both
    // numbers, which is the whole reason this survived to now.
    //
    // 1024 bytes through a 64-byte window is sixteen windows' worth. Every chunk that crosses
    // the threshold must produce a grant and every grant must be believed, or the transfer
    // stops - there is no partial-credit failure mode that still delivers the last byte.
    [Fact]
    public void ATransferManyTimesLargerThanTheInitialWindowCompletes()
    {
        var local = new TlsQuicLocalFlowControlSpec
        {
            InitialMaxData = 64,
            InitialMaxStreamDataUni = 64,
        };
        var streams = Set(local: local);

        // Content, not zeroes: a reassembler that dropped or duplicated a chunk would rebuild
        // the right LENGTH out of zeroes and the comparison would not notice.
        var body = new byte[1024];
        for (var index = 0; index < body.Length; index++)
        {
            body[index] = (byte)(index * 7);
        }

        var sawMaximumStreamData = false;
        var sawMaximumData = false;
        for (var offset = 0; offset < body.Length; offset += 32)
        {
            Assert.True(
                streams.TryReceive(Frame(3, (ulong)offset, body[offset..(offset + 32)]), out var error),
                $"Refused at offset {offset} with {error}.");

            // The grants leave in the next 1-RTT packet, which is what emptying the queue
            // stands in for here - TlsQuicApplicationSendPath does it for real.
            foreach (var frame in streams.TakePendingFrames())
            {
                sawMaximumStreamData |= frame.RawType == (ulong)TlsQuicFrameType.MaxStreamData;
                sawMaximumData |= frame.RawType == (ulong)TlsQuicFrameType.MaxData;
            }
        }

        Assert.Equal(body, streams.PeerInitiated[0].Received.ToArray());
        Assert.True(sawMaximumStreamData, "No MAX_STREAM_DATA was ever queued.");
        Assert.True(sawMaximumData, "No MAX_DATA was ever queued.");
    }

    // THE THRESHOLD, FROM BOTH SIDES. The first frame leaves more than half the window
    // outstanding and must produce nothing; the second crosses and must produce exactly one
    // frame of each type carrying the new limit. Asserting the VALUE and not just the presence
    // is what stops a grant that re-sends the old limit - s19.10 makes that frame a no-op:
    // "MAX_STREAM_DATA frames that do not increase the stream limit MUST be ignored."
    [Fact]
    public void CrossingTheUpdateThresholdQueuesOneMaxStreamDataAndOneMaxData()
    {
        var local = new TlsQuicLocalFlowControlSpec
        {
            InitialMaxData = 16,
            InitialMaxStreamDataUni = 16,
        };
        var streams = Set(local: local);

        Assert.True(streams.TryReceive(Frame(3, 0, new byte[7]), out _));
        Assert.Empty(streams.TakePendingFrames());

        Assert.True(streams.TryReceive(Frame(3, 7, new byte[2]), out _));
        var frames = streams.TakePendingFrames();
        Assert.Equal(2, frames.Count);

        // delivered (9) plus one whole window (16). Not 16 + 16: the window slides with what
        // has been consumed, so re-granting from the old limit would hand the peer credit for
        // bytes it has not sent yet.
        var maximumStreamData = Assert.Single(
            frames, f => f.RawType == (ulong)TlsQuicFrameType.MaxStreamData);
        Assert.Equal(3UL, maximumStreamData.StreamId);
        Assert.Equal(25UL, maximumStreamData.MaximumStreamData);

        var maximumData = Assert.Single(
            frames, f => f.RawType == (ulong)TlsQuicFrameType.MaxData);
        Assert.Equal(25UL, maximumData.MaximumData);
        Assert.Equal(25UL, streams.ConnectionReceiveLimit);
    }

    // THE ONE INPUT THAT SEPARATES >= FROM > IS EQUALITY, and without this row both thresholds
    // survived being weakened: no other test happens to land on exactly half a window. The
    // rule is "outstanding credit BELOW half the window", not "at or below" - at exactly half
    // there is still a whole half-window the peer may send, and granting there would put a
    // frame on the wire for a peer that is not waiting on one.
    //
    // Both levels sit on the boundary at once here, so this pins CreditReceiveWindow's
    // comparison and CreditConnectionWindow's together.
    [Fact]
    public void OutstandingCreditExactlyOnTheUpdateThresholdQueuesNothing()
    {
        var local = new TlsQuicLocalFlowControlSpec
        {
            InitialMaxData = 16,
            InitialMaxStreamDataUni = 16,
        };
        var streams = Set(local: local);

        Assert.True(streams.TryReceive(Frame(3, 0, new byte[8]), out _));
        Assert.Empty(streams.TakePendingFrames());
        Assert.Equal(16UL, streams.PeerInitiated[0].ReceiveLimit);
        Assert.Equal(16UL, streams.ConnectionReceiveLimit);
    }

    // s19.9's connection level, which did not exist before C9 at all: "All data sent in STREAM
    // frames counts toward this limit." Two streams that each sit exactly on their own
    // per-stream limit exceed initial_max_data between them, so a check written only per
    // stream lets this through.
    //
    // BOTH FRAMES LEAVE A GAP AT OFFSET 0 on purpose. Nothing is delivered, so nothing credits
    // the window back, and the refusal is about the limit rather than about the threshold.
    [Fact]
    public void TwoStreamsInsideTheirOwnLimitsCanStillExceedTheAdvertisedConnectionLimit()
    {
        var local = new TlsQuicLocalFlowControlSpec
        {
            InitialMaxData = 12,
            InitialMaxStreamDataUni = 8,
        };
        var streams = Set(local: local);

        Assert.True(streams.TryReceive(Frame(3, 4, new byte[4]), out _));
        Assert.False(streams.TryReceive(Frame(7, 4, new byte[4]), out var error));
        Assert.Equal(TlsQuicTransportError.FlowControlError, error);
    }

    // s19.10, past the wrap: "When counting data toward this limit, an endpoint accounts for
    // the largest received offset of data that is sent or received on the stream. Loss or
    // reordering can mean that the largest received offset on a stream can be greater than the
    // total size of data received on that stream." So a retransmission advances nothing and
    // must cost nothing - charge it and a peer that retransmits under a lossy path is refused
    // for conforming.
    [Fact]
    public void ARetransmissionSpendsNoConnectionLevelCredit()
    {
        var local = new TlsQuicLocalFlowControlSpec
        {
            InitialMaxData = 8,
            InitialMaxStreamDataUni = 8,
        };
        var streams = Set(local: local);

        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2, 3, 4]), out _));
        Assert.True(streams.TryReceive(Frame(3, 0, [1, 2, 3, 4]), out _));

        // Charging the duplicate would have spent all 8 and refused this.
        Assert.True(streams.TryReceive(Frame(3, 4, [5, 6, 7, 8]), out _));
        Assert.Equal(8UL, streams.PeerInitiated[0].LargestReceivedOffset);
        Assert.Equal(
            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
            streams.PeerInitiated[0].Received.ToArray());
    }

    // s18.2 gives the two directions separate parameters and s20.1 scopes STREAM_LIMIT_ERROR to
    // "its advertised stream limit for the CORRESPONDING stream type", so one shared counter is
    // wrong in both directions: it refuses a legal bidirectional stream once the
    // unidirectional allowance is spent, and vice versa.
    [Fact]
    public void TheStreamCountLimitIsPerDirectionAndNotOneSharedCounter()
    {
        var local = new TlsQuicLocalFlowControlSpec
        {
            InitialMaxStreamsUni = 1,
            InitialMaxStreamsBidi = 2,
        };
        var streams = Set(local: local);

        // s2.1's 0x03 type, ordinals 0 and 1.
        Assert.True(streams.TryReceive(Frame(3, 0, [1]), out _));
        Assert.False(streams.TryReceive(Frame(7, 0, [1]), out var uniError));
        Assert.Equal(TlsQuicTransportError.StreamLimitError, uniError);

        // s2.1's 0x01 type, ordinals 0, 1 and 2. The first of these is the one a shared
        // counter would already have refused.
        Assert.True(streams.TryReceive(Frame(1, 0, [1]), out _));
        Assert.True(streams.TryReceive(Frame(5, 0, [1]), out _));
        Assert.False(streams.TryReceive(Frame(9, 0, [1]), out var bidiError));
        Assert.Equal(TlsQuicTransportError.StreamLimitError, bidiError);
    }

    // The per-stream receive limit is chosen by s2.1 type, and the three types that can receive
    // take three different parameters. Equal defaults hide a swap, so the three are distinct
    // here and each is asserted through the boundary rather than through a getter: one byte
    // ending on the limit is taken, the next is not.
    [Theory]
    [InlineData(1UL, 6006UL)]
    [InlineData(3UL, 7007UL)]
    public void APeerInitiatedStreamIsBoundedByTheParameterSection182ScopesToItsType(
        ulong streamId, ulong expected)
    {
        var streams = Set(local: new TlsQuicLocalFlowControlSpec
        {
            InitialMaxData = QuicVariableLengthInteger.MaximumValue,
            InitialMaxStreamDataBidiLocal = 5005,
            InitialMaxStreamDataBidiRemote = 6006,
            InitialMaxStreamDataUni = 7007,
        });

        Assert.True(streams.TryReceive(Frame(streamId, expected - 1, [1]), out _));
        Assert.False(streams.TryReceive(Frame(streamId, expected, [1]), out var error));
        Assert.Equal(TlsQuicTransportError.FlowControlError, error);
    }

    // ---- Scaffolding ----------------------------------------------------------------------

    private static ulong Id(
        TlsQuicStreamInitiator initiator, TlsQuicStreamDirection direction, ulong ordinal) =>
        TlsQuicStreamId.From(initiator, direction, ordinal);

    // s19.8's frame, built by hand rather than encoded and read back: this file is about what
    // is DONE with a frame, and the encoding is TlsQuicStreamFramesTests'. The OFF bit follows
    // the offset the way the send path's does, so that a frame at offset 0 here is the same
    // wire form a peer would send.
    private static TlsQuicFrame Frame(
        ulong streamId, ulong offset, byte[] data, bool fin = false)
    {
        var rawType = (ulong)TlsQuicFrameType.Stream | TlsQuicStreamFrames.LengthBit;
        if (offset != 0)
        {
            rawType |= TlsQuicStreamFrames.OffsetBit;
        }

        if (fin)
        {
            rawType |= TlsQuicStreamFrames.FinBit;
        }

        return new TlsQuicFrame
        {
            RawType = rawType,
            StreamId = streamId,
            Offset = offset,
            Data = data,
        };
    }

    // THE SIX s18.2 VALUES ARE DISTINCT AND EACH ENDS IN ITS OWN PARAMETER'S ID, the
    // convention TlsQuicConnectionTests.FlowControlParameters set: a read that fetched 0x05
    // where it meant 0x06 produces a number that names the parameter it wrongly came from.
    private static TlsQuicStreamSet Set(
        ulong connectionData = 1_000_004,
        ulong bidiLocal = 5005,
        ulong bidiRemote = 6006,
        ulong uni = 7007,
        ulong streamsBidi = 108,
        ulong streamsUni = 109,
        TlsQuicLocalFlowControlSpec? local = null) =>
        new(TlsQuicPeerFlowControlBudget.FromPeerParameters(new TlsQuicTransportParameters(
        [
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxData, connectionData),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal, bidiLocal),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote, bidiRemote),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamDataUni, uni),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamsBidi, streamsBidi),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamsUni, streamsUni),
        ])),
        local);

    // s19.10's and s19.9's frames as the PEER would send them. Hand-built for the reason every
    // other peer frame in this file is - a helper that reused the send path's construction
    // would make the two directions one implementation.
    private static TlsQuicFrame MaxStreamData(ulong streamId, ulong maximumStreamData) => new()
    {
        RawType = (ulong)TlsQuicFrameType.MaxStreamData,
        StreamId = streamId,
        MaximumStreamData = maximumStreamData,
    };

    private static TlsQuicFrame MaxData(ulong maximumData) => new()
    {
        RawType = (ulong)TlsQuicFrameType.MaxData,
        MaximumData = maximumData,
    };
}
