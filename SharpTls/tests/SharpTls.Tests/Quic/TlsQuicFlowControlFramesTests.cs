using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// The six flow-control frames: RFC 9000 s19.9 MAX_DATA, s19.10 MAX_STREAM_DATA,
// s19.11 MAX_STREAMS, s19.12 DATA_BLOCKED, s19.13 STREAM_DATA_BLOCKED and s19.14
// STREAMS_BLOCKED. Split from TlsQuicFramesTests for the same reason ACK, STREAM
// and CRYPTO were.
//
// None of the six has a published test vector - RFC 9001 A.2's CRYPTO frame is
// the only one this whole phase gets - so every byte array below is hand-derived
// from the s19.9 to s19.14 field lists (Figures 33 to 38) and the s16
// variable-length integer rules, with the derivation written above the test and
// asserted against the encoder directly. A round-trip test alone would only prove
// this library's encoder and decoder agree with each other, which they can do
// while both being wrong about field order.
//
//   MAX_DATA {                      DATA_BLOCKED {
//     Type (i) = 0x10,                Type (i) = 0x14,
//     Maximum Data (i),               Maximum Data (i),
//   }                               }
//
//   MAX_STREAM_DATA {               STREAM_DATA_BLOCKED {
//     Type (i) = 0x11,                Type (i) = 0x15,
//     Stream ID (i),                  Stream ID (i),
//     Maximum Stream Data (i),        Maximum Stream Data (i),
//   }                               }
//
//   MAX_STREAMS {                   STREAMS_BLOCKED {
//     Type (i) = 0x12..0x13,          Type (i) = 0x16..0x17,
//     Maximum Streams (i),            Maximum Streams (i),
//   }                               }
//
// EIGHT TYPE VALUES, NOT SIX, and the tests are organised around that rather than
// around the six frame names: s19.11 gives MAX_STREAMS two values and s19.14 gives
// STREAMS_BLOCKED two, so every check inside
// TlsQuicFlowControlFrames.TryReadMaximumStreams and
// WriteMaximumStreamsFrameFields is reachable four ways and carries four rows. The
// cheap mutation that exposes a missing row is to wrap the check in
// `if (rawType == 0x12)` or similar and see whether anything fails; each of those
// four one-value mutations is recorded at the check it was applied to.
//
// Every field value in these vectors is 63 or below except where the derivation
// says otherwise, so it encodes as a single byte whose value is the value itself:
// s16 gives the first byte's two most significant bits as the log2 of the encoded
// length, so 0b00 means one byte with six value bits.
public sealed class TlsQuicFlowControlFramesTests
{
    // 2^62 - 1, the largest value a variable-length integer can carry (s16 spends
    // the first byte's two most significant bits on the length, leaving 62 value
    // bits in the 8-byte form). Not 2^64 - 1, and NOT the bound on a stream count.
    private const ulong VarintMaximum = (1UL << 62) - 1;

    // The three field values every vector below uses, deliberately three
    // *different* small numbers so that a writer or reader which emitted or
    // consumed MAX_STREAM_DATA's two fields in the wrong order would produce
    // visibly wrong bytes rather than two plausible ones.
    private const ulong MaximumData = 42;      // -> 0x2a
    private const ulong StreamId = 4;          // -> 0x04
    private const ulong MaximumStreams = 7;    // -> 0x07

    // A two-byte varint prefix (s16: first byte 0b01_xxxxxx means two bytes) with
    // its second byte missing - the shortest input that makes
    // QuicVariableLengthInteger.Read throw rather than return, which is what every
    // truncation row below appends to a frame type.
    private const byte TruncatedVarintPrefix = 0x40;

    // s19.11's bound, 2^60, and the first value above it. The 8-byte encoding:
    // s16's first byte is 0b11 for length 2^3 = 8 or'd with the top 6 of the 62
    // value bits. 2^60 is 0x1000_0000_0000_0000, whose value bits 61..56 are
    // 0b010000 = 0x10, so the first byte is 0xc0 | 0x10 = 0xd0 and the remaining
    // seven bytes are the low 56 bits, all zero. 2^60 + 1 differs in the last byte
    // alone. An 8-byte form is used rather than the shortest possible one because
    // 2^60 needs 61 bits and only the 8-byte form has room; that is the same
    // encoding QuicVariableLengthInteger.Write would pick.
    private const ulong StreamCountBound = 1UL << 60;
    private static readonly byte[] StreamCountBoundEncoded =
        [0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    private static readonly byte[] StreamCountBoundPlusOneEncoded =
        [0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

    // s19.9 Figure 33 and s19.12 Figure 36 have identical field lists, so one
    // theory covers both frames and its two rows are the two paths through
    // TlsQuicFlowControlFrames.WriteMaximumDataFrameFields:
    //
    //   type  bytes
    //   0x10  10 2a     MAX_DATA,     Maximum Data = 42
    //   0x14  14 2a     DATA_BLOCKED, Maximum Data = 42
    //
    // THIS IS THE DEMONSTRATION THAT THE SHARED WRITER IS GENUINELY SHARED, which
    // the A2 plan asks for explicitly: there is one implementation behind these two
    // rows, and a mutation inside it fails a row belonging to each of the two frame
    // types rather than only the one an author reached for first.
    //
    // Mutation checks (performed and reverted), neither failing anything else in
    // the Quic suite:
    //   * deleting the QuicVariableLengthInteger.Write of frame.MaximumData in
    //     WriteMaximumDataFrameFields - fails both rows.
    //   * swapping the two Write calls so the field precedes the type - fails both
    //     rows, which is the only thing that can catch it: both fields are varints
    //     and the reader would decode the swapped bytes back into a MAX_DATA-looking
    //     frame of type 0x2a, so a round-trip test would not notice.
    [Theory]
    [InlineData(0x10UL, new byte[] { 0x10, 0x2a })]
    [InlineData(0x14UL, new byte[] { 0x14, 0x2a })]
    public void MaximumDataFramesMatchTheirHandDerivedBytes(ulong rawType, byte[] expected)
    {
        var frame = new TlsQuicFrame { RawType = rawType, MaximumData = MaximumData };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal(expected, destination);
    }

    // s19.10 Figure 34 and s19.13 Figure 37, Stream ID = 4 then Maximum Stream
    // Data = 42:
    //
    //   type  bytes
    //   0x11  11 04 2a     MAX_STREAM_DATA
    //   0x15  15 04 2a     STREAM_DATA_BLOCKED
    //
    // The two field values differ so that these two rows are the only thing in the
    // suite that can catch a writer emitting the fields in the wrong order. s19.10
    // and s19.13 both put Stream ID first.
    //
    // Mutation checks (performed and reverted): swapping the two field Write calls
    // in WriteMaximumStreamDataFrameFields - fails both rows; deleting either -
    // fails both rows.
    [Theory]
    [InlineData(0x11UL, new byte[] { 0x11, 0x04, 0x2a })]
    [InlineData(0x15UL, new byte[] { 0x15, 0x04, 0x2a })]
    public void MaximumStreamDataFramesMatchTheirHandDerivedBytes(ulong rawType, byte[] expected)
    {
        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            StreamId = StreamId,
            MaximumStreamData = MaximumData,
        };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal(expected, destination);
    }

    // s19.11 Figure 35 and s19.14 Figure 38, Maximum Streams = 7, all four type
    // values:
    //
    //   type  bytes     meaning
    //   0x12  12 07     MAX_STREAMS,     bidirectional
    //   0x13  13 07     MAX_STREAMS,     unidirectional
    //   0x16  16 07     STREAMS_BLOCKED, bidirectional
    //   0x17  17 07     STREAMS_BLOCKED, unidirectional
    //
    // Four rows and not two: the 0x13 and 0x17 rows are the only thing in the suite
    // that can catch a writer emitting (ulong)frame.Type instead of frame.RawType,
    // because those are the two values that derive to a *different* number
    // (0x13 -> MaxStreams = 0x12, 0x17 -> StreamsBlocked = 0x16). This is the same
    // property TlsQuicStreamFramesTests pins for STREAM's eight forms, and it is
    // why TlsQuicFrame has no direction field: the direction survives a write only
    // because RawType is what gets emitted.
    //
    // Mutation checks (performed and reverted). Neither is witnessed by this test
    // alone - WritingAMaximumStreamsFrameAtTheStreamCountBoundSucceeds asserts the
    // type byte and the field too, over the same four type values - so both are
    // recorded with the other test's rows named, per the plan's rule about not
    // claiming sole coverage:
    //   * replacing frame.RawType with (ulong)frame.Type in
    //     WriteMaximumStreamsFrameFields - fails this test's 0x13 and 0x17 rows
    //     plus that test's 0x13 and 0x17 rows, four in all, and nothing else in the
    //     Quic suite. The 0x12 and 0x16 rows cannot fail: those are the range bases,
    //     where RawType and (ulong)Type are the same number.
    //   * deleting the Write of frame.MaximumStreams - fails all four rows here plus
    //     all four there, eight in all.
    [Theory]
    [InlineData(0x12UL, new byte[] { 0x12, 0x07 })]
    [InlineData(0x13UL, new byte[] { 0x13, 0x07 })]
    [InlineData(0x16UL, new byte[] { 0x16, 0x07 })]
    [InlineData(0x17UL, new byte[] { 0x17, 0x07 })]
    public void MaximumStreamsFramesMatchTheirHandDerivedBytes(ulong rawType, byte[] expected)
    {
        var frame = new TlsQuicFrame { RawType = rawType, MaximumStreams = MaximumStreams };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal(expected, destination);
    }

    // The read direction of the three vector theories above, asserting the fields
    // rather than the bytes: that the type reaches TlsQuicFrame.RawType intact,
    // that the derived Type is the Table 3 base, that the value lands in the field
    // s19.9 to s19.14 name, and that `offset` advanced past the whole frame and no
    // further.
    //
    // Reading is dispatched through TlsQuicFrames.TryReadFrame, not the family
    // readers directly, so these also pin the eight case labels added to that
    // switch - without them each of these inputs would fall through to the default
    // arm and be rejected as an unknown frame type. Only these three theories can:
    // the rejecting tests all expect false with FRAME_ENCODING_ERROR, which is
    // exactly what a dropped case label produces, so a suite of rejection tests
    // would pass with the whole dispatch deleted.
    //
    // Mutation checks (performed and reverted), on the two switches in
    // TlsQuicFrames rather than on the family readers:
    //   * dropping the `case DataBlocked` label from the read dispatch - fails one
    //     row, the 0x14 row of MaximumDataFramesParseBackToTheirFields.
    //   * dropping the `StreamsBlocked | UnidirectionalBit` label - fails two rows,
    //     the 0x17 rows of MaximumStreamsFramesParseBackToTheirFields and
    //     MaximumStreamsAtTheStreamCountBoundIsAccepted.
    //   * dropping the `case TlsQuicFrameType.DataBlocked` label from the WRITE
    //     dispatch - fails two rows; dropping `case StreamsBlocked` - fails four.
    //   * pointing the write dispatch's MaxData/DataBlocked arm at
    //     WriteMaximumStreamDataFrameFields instead - fails four rows, the two
    //     byte-vector rows and the two ParamName rows, which is what stops the three
    //     writers being interchangeable by accident.
    //
    // `expectedType` is passed as a ulong rather than as a TlsQuicFrameType: the
    // enum is internal, and a public xunit test method cannot take an internal
    // parameter type (CS0051). The assertion casts frame.Type back, so it still
    // pins the derived value and not merely the raw one.
    [Theory]
    [InlineData(new byte[] { 0x10, 0x2a }, 0x10UL, 0x10UL)]
    [InlineData(new byte[] { 0x14, 0x2a }, 0x14UL, 0x14UL)]
    public void MaximumDataFramesParseBackToTheirFields(
        byte[] encoded, ulong expectedRawType, ulong expectedType)
    {
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal(expectedRawType, frame.RawType);
        Assert.Equal(expectedType, (ulong)frame.Type);
        Assert.Equal(MaximumData, frame.MaximumData);
    }

    [Theory]
    [InlineData(new byte[] { 0x11, 0x04, 0x2a }, 0x11UL, 0x11UL)]
    [InlineData(new byte[] { 0x15, 0x04, 0x2a }, 0x15UL, 0x15UL)]
    public void MaximumStreamDataFramesParseBackToTheirFields(
        byte[] encoded, ulong expectedRawType, ulong expectedType)
    {
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal(expectedRawType, frame.RawType);
        Assert.Equal(expectedType, (ulong)frame.Type);

        // Asserted as two different numbers in the two fields s19.10 names, which
        // is what makes a reader that swapped them fail here as well as in the
        // byte-vector theory above.
        Assert.Equal(StreamId, frame.StreamId);
        Assert.Equal(MaximumData, frame.MaximumStreamData);
    }

    [Theory]
    [InlineData(new byte[] { 0x12, 0x07 }, 0x12UL, 0x12UL)]
    [InlineData(new byte[] { 0x13, 0x07 }, 0x13UL, 0x12UL)]
    [InlineData(new byte[] { 0x16, 0x07 }, 0x16UL, 0x16UL)]
    [InlineData(new byte[] { 0x17, 0x07 }, 0x17UL, 0x16UL)]
    public void MaximumStreamsFramesParseBackToTheirFields(
        byte[] encoded, ulong expectedRawType, ulong expectedType)
    {
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);

        // The 0x13 and 0x17 rows are where RawType and (ulong)Type differ - the two
        // columns above are deliberately unequal there - so these two assertions
        // together are what pin TlsQuicFrame.Type's s19.11 and s19.14 range arms on
        // the read path as well as the writer's use of RawType.
        Assert.Equal(expectedRawType, frame.RawType);
        Assert.Equal(expectedType, (ulong)frame.Type);
        Assert.Equal(MaximumStreams, frame.MaximumStreams);
    }

    // s12.4: "Frames always fit within a single QUIC packet and cannot span
    // multiple packets", so a field whose varint prefix promises more bytes than
    // the payload holds is badly formatted rather than incomplete, and s20.1's
    // FRAME_ENCODING_ERROR is "An endpoint received a frame that was badly
    // formatted". `offset` must be left at 0, since TryReadFrame only commits an
    // advance on success.
    //
    // Two rows, one per path through
    // TlsQuicFlowControlFrames.TryReadMaximumData's catch.
    //
    // Mutation checks (performed and reverted): deleting the catch - fails both
    // rows with an unhandled TlsQuicTransportException, which is the Try-shaped
    // contract broken rather than a wrong answer; dropping its `error` assignment -
    // fails both rows on the error code, since the exception is raised inside
    // QuicVariableLengthInteger.Read as TRANSPORT_PARAMETER_ERROR and this catch is
    // the only place the frame-level code is chosen; conditioning either on
    // rawType == 0x10 - fails the 0x14 row alone, and vice versa.
    [Theory]
    [InlineData(0x10)]
    [InlineData(0x14)]
    public void MaximumDataFrameTruncatedInItsFieldIsRejected(byte rawType)
    {
        byte[] encoded = [rawType, TruncatedVarintPrefix];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // FOUR rows for one catch, not two: TryReadMaximumStreamData reads two fields
    // inside one try block, so either can be the truncated one, for either of the
    // two frame types. A suite that only truncated the Stream ID would leave a
    // mutation that narrowed the try to the first Read alive.
    //
    //   type  bytes        truncated field
    //   0x11  11 40        Stream ID
    //   0x11  11 04 40     Maximum Stream Data (Stream ID = 4 read successfully)
    //   0x15  15 40        Stream ID
    //   0x15  15 04 40     Maximum Stream Data
    //
    // Mutation checks (performed and reverted): narrowing the try to cover only the
    // Stream ID read - fails the two Maximum Stream Data rows with an unhandled
    // TlsQuicTransportException; deleting the catch - fails all four; conditioning
    // it on rawType == 0x11 - fails the two 0x15 rows.
    [Theory]
    [InlineData(new byte[] { 0x11, TruncatedVarintPrefix })]
    [InlineData(new byte[] { 0x11, 0x04, TruncatedVarintPrefix })]
    [InlineData(new byte[] { 0x15, TruncatedVarintPrefix })]
    [InlineData(new byte[] { 0x15, 0x04, TruncatedVarintPrefix })]
    public void MaximumStreamDataFrameTruncatedInEitherFieldIsRejected(byte[] encoded)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // Four rows, one per type value TryReadMaximumStreams can be reached with.
    //
    // Mutation checks (performed and reverted): deleting the catch - fails all
    // four with an unhandled TlsQuicTransportException; dropping its `error`
    // assignment - fails all four on the error code; conditioning either on any one
    // of the four rawType values - fails the other three rows.
    [Theory]
    [InlineData(0x12)]
    [InlineData(0x13)]
    [InlineData(0x16)]
    [InlineData(0x17)]
    public void MaximumStreamsFrameTruncatedInItsFieldIsRejected(byte rawType)
    {
        byte[] encoded = [rawType, TruncatedVarintPrefix];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // s19.11's bound on the read path, the ONE validity rule in these six sections
    // this stateless layer can enforce. s19.11, of Maximum Streams: "This value
    // cannot exceed 2^60, as it is not possible to encode stream IDs larger than
    // 2^62-1. Receipt of a frame that permits opening of a stream larger than this
    // limit MUST be treated as a connection error of type FRAME_ENCODING_ERROR."
    // s19.14 carries the same bound for STREAMS_BLOCKED and allows
    // "STREAM_LIMIT_ERROR or FRAME_ENCODING_ERROR"; TlsQuicFlowControlFrames
    // records why FRAME_ENCODING_ERROR is used for both.
    //
    // WHY THIS READ-SIDE BOUND IS REACHABLE AT ALL, when the plan's standing rule
    // says a bound on a parser-produced value usually is not: the rule's example
    // (TlsQuicStreamFrames.TryReadData's largest-offset check) has the varint
    // maximum itself as its limit, so nothing a varint decodes to can exceed it.
    // 2^60 is a quarter of that, so every value from 2^60 + 1 to 2^62 - 1 decodes
    // fine and must be rejected here. The input below is a complete, well-formed
    // 8-byte varint, so the catch above it cannot fire and this is the only check
    // that can reject it.
    //
    // Four rows, one per type value - the plan's two-type-value rule applied twice,
    // once to s19.11's pair and once to s19.14's.
    //
    // Mutation checks (performed and reverted): deleting the comparison - fails all
    // four rows, which then parse successfully; conditioning it on any one of the
    // four rawType values - fails the other three rows; changing the constant to
    // QuicVariableLengthInteger.MaximumValue - fails all four.
    [Theory]
    [InlineData(0x12)]
    [InlineData(0x13)]
    [InlineData(0x16)]
    [InlineData(0x17)]
    public void MaximumStreamsAboveTheStreamCountBoundIsRejected(byte rawType)
    {
        byte[] encoded = [rawType, .. StreamCountBoundPlusOneEncoded];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // The other side of the same bound: s19.11 says the value "cannot exceed 2^60",
    // so 2^60 itself is legal and the comparison must be strict. Four rows again.
    //
    // These rows are also the only place a flow-control field is carried in
    // anything other than a single byte, so they are what would catch a reader that
    // assumed the one-byte form the vectors above all use.
    //
    // Mutation check (performed and reverted): weakening the comparison in
    // TryReadMaximumStreams to >= - fails all four rows, and nothing else in the
    // Quic suite.
    [Theory]
    [InlineData(0x12)]
    [InlineData(0x13)]
    [InlineData(0x16)]
    [InlineData(0x17)]
    public void MaximumStreamsAtTheStreamCountBoundIsAccepted(byte rawType)
    {
        byte[] encoded = [rawType, .. StreamCountBoundEncoded];
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal((ulong)rawType, frame.RawType);
        Assert.Equal(StreamCountBound, frame.MaximumStreams);
    }

    // s16 leaves a variable-length integer 62 value bits, so a Maximum Data of
    // 2^62 has no encoding. Checked in WriteMaximumDataFrameFields before the frame
    // type is written, so the rejection cannot leave a partial frame behind -
    // `destination` is seeded with a sentinel byte and asserted to be still alone,
    // which is the half of this test that catches a bound moved below the writes.
    // Asserting only the exception type would not: the encoder's own throw is also
    // an ArgumentException subclass.
    //
    // The ParamName is "maximumData", a string literal in
    // TlsQuicFlowControlFrames.RequireEncodableVarint rather than nameof()-derived -
    // there is no parameter of that name on the method that passes it - so renaming
    // TlsQuicFrame.MaximumData will not update it and this assertion will not fail
    // if it goes stale.
    //
    // Two rows, one per path through the single RequireEncodableVarint call.
    //
    // Mutation checks (performed and reverted), neither failing anything else in
    // the Quic suite:
    //   * deleting the RequireEncodableVarint call - fails both rows with
    //     ArgumentOutOfRangeException (a different exact type, from
    //     QuicVariableLengthInteger, naming a parameter "value" this namespace does
    //     not have) and with the type byte already in the destination, which is why
    //     Assert.Throws' exact-type match and the sentinel both matter.
    //   * conditioning the call on rawType == 0x10 - fails the 0x14 row alone, and
    //     vice versa. This is the mutation the second row exists for.
    [Theory]
    [InlineData(0x10UL)]
    [InlineData(0x14UL)]
    public void WritingAMaximumDataFrameAboveTheVarintMaximumThrows(ulong rawType)
    {
        var frame = new TlsQuicFrame { RawType = rawType, MaximumData = VarintMaximum + 1 };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("maximumData", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The Stream ID bound of the second shape. s19.10 makes the field "encoded as a
    // variable-length integer", so s16 caps it at 2^62 - 1; s19.11's 2^60 bound is
    // on a *count of streams* and does not apply to an identifier, which is the
    // asymmetry s19.11's own explanation of 2^60 turns on.
    //
    // MaximumStreamData is left at 0 so the second RequireEncodableVarint call in
    // WriteMaximumStreamDataFrameFields cannot also reject this frame. The two
    // calls throw the SAME exception type on the same kind of value, so without
    // that separation a mutation deleting one of them would be invisible; ParamName
    // is the only thing that distinguishes them, and both names are string literals
    // rather than nameof()-derived (see RequireEncodableVarint).
    //
    // Mutation checks (performed and reverted):
    //   * deleting the RequireEncodableVarint(frame.StreamId, ...) call - fails both
    //     rows with ArgumentOutOfRangeException and the type byte already written.
    //   * conditioning it on rawType == 0x11 - fails the 0x15 row alone.
    [Theory]
    [InlineData(0x11UL)]
    [InlineData(0x15UL)]
    public void WritingAMaximumStreamDataFrameWhoseStreamIdExceedsTheVarintMaximumThrows(ulong rawType)
    {
        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            StreamId = VarintMaximum + 1,
            MaximumStreamData = 0,
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("streamId", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The Maximum Stream Data bound of the same shape, and the reason it is a
    // separate test rather than a third row of the one above: StreamId is set to a
    // legal 4 here so the *first* RequireEncodableVarint cannot fire, which is what
    // makes this test the sole witness for the second call. Both calls raise
    // ArgumentException, so the ParamName assertion is load-bearing - with
    // "streamId" asserted instead, deleting the second call would still pass.
    //
    // Mutation checks (performed and reverted):
    //   * deleting the RequireEncodableVarint(frame.MaximumStreamData, ...) call -
    //     fails both rows with ArgumentOutOfRangeException, and with the type byte
    //     AND the Stream ID byte already in the destination.
    //   * conditioning it on rawType == 0x11 - fails the 0x15 row alone.
    [Theory]
    [InlineData(0x11UL)]
    [InlineData(0x15UL)]
    public void WritingAMaximumStreamDataFrameWhoseFieldExceedsTheVarintMaximumThrows(ulong rawType)
    {
        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            StreamId = StreamId,
            MaximumStreamData = VarintMaximum + 1,
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("maximumStreamData", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // s19.11's and s19.14's bound on the write path, where the field is
    // caller-supplied and bounded by nothing - the plan's rule that a write-side
    // bound on a caller-supplied value is always reachable.
    //
    // EIGHT rows: four type values crossed with two magnitudes, and the second
    // magnitude is not redundant. At 2^60 + 1 the value is a perfectly encodable
    // varint, so deleting the check makes the frame write successfully and nothing
    // throws at all. At 2^62 the value is unencodable, so deleting the check makes
    // QuicVariableLengthInteger.Write throw ArgumentOutOfRangeException *after* the
    // type byte is in the destination - a different failure that only the
    // exact-type match and the sentinel can catch. The two magnitudes therefore
    // pin two different consequences of the same missing check, and 2^60 + 1 alone
    // would not show that no encodability check stands behind this one.
    //
    // No RequireEncodableVarint call exists for this field, deliberately: 2^60 is
    // strictly below the varint maximum, so an encodability check behind this one
    // could never fire and its own mutation-pin would be unkillable. That is why
    // the 2^62 rows assert ParamName "frame" - the bound's own message - rather
    // than a "maximumStreams" literal.
    //
    // Mutation checks (performed and reverted), none failing anything else in the
    // Quic suite:
    //   * deleting the comparison - fails all eight rows: the four 2^60 + 1 rows
    //     because nothing throws, the four 2^62 rows on both exception type and
    //     sentinel.
    //   * conditioning it on any one of rawType == 0x12, == 0x13, == 0x16 or
    //     == 0x17 - fails the six rows belonging to the other three values, all four
    //     mutations tried separately. This is the four-path mutation the plan's
    //     standing rule asks for; a single MAX_STREAMS row would have let every one
    //     of the four survive.
    //   * changing the constant to QuicVariableLengthInteger.MaximumValue - fails
    //     the four 2^60 + 1 rows.
    [Theory]
    [InlineData(0x12UL, (1UL << 60) + 1)]
    [InlineData(0x13UL, (1UL << 60) + 1)]
    [InlineData(0x16UL, (1UL << 60) + 1)]
    [InlineData(0x17UL, (1UL << 60) + 1)]
    [InlineData(0x12UL, VarintMaximum + 1)]
    [InlineData(0x13UL, VarintMaximum + 1)]
    [InlineData(0x16UL, VarintMaximum + 1)]
    [InlineData(0x17UL, VarintMaximum + 1)]
    public void WritingAMaximumStreamsFrameAboveTheStreamCountBoundThrows(
        ulong rawType, ulong maximumStreams)
    {
        var frame = new TlsQuicFrame { RawType = rawType, MaximumStreams = maximumStreams };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("frame", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The accepting side of the write-path bound: 2^60 exactly, which s19.11's
    // "cannot exceed" makes legal. Asserted against hand-derived bytes rather than
    // just "did not throw", so the 8-byte encoding is checked too - the type byte
    // followed by StreamCountBoundEncoded, whose derivation is above.
    //
    // Because it asserts the type byte, this test is a second witness for two of
    // MaximumStreamsFramesMatchTheirHandDerivedBytes' mutations as well as for its
    // own; that is recorded there rather than duplicated here.
    //
    // Mutation check (performed and reverted): weakening the comparison in
    // WriteMaximumStreamsFrameFields to >= - fails all four rows, and nothing else
    // in the Quic suite.
    [Theory]
    [InlineData(0x12UL)]
    [InlineData(0x13UL)]
    [InlineData(0x16UL)]
    [InlineData(0x17UL)]
    public void WritingAMaximumStreamsFrameAtTheStreamCountBoundSucceeds(ulong rawType)
    {
        var frame = new TlsQuicFrame { RawType = rawType, MaximumStreams = StreamCountBound };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal<byte>([(byte)rawType, .. StreamCountBoundEncoded], destination);
    }

    // s19.11: "A MAX_STREAMS frame with a type of 0x12 applies to bidirectional
    // streams, and a MAX_STREAMS frame with a type of 0x13 applies to
    // unidirectional streams." s19.14 pairs 0x16 and 0x17 the same way.
    //
    // Nothing in TlsQuicFlowControlFrames branches on this - the two type values of
    // each pair are byte-for-byte the same shape - exactly as nothing in
    // TlsQuicStreamFrames branches on IsFin. Both exist so a later phase can ask
    // the question without masking RawType by hand, and both are pinned here rather
    // than left to a future caller. All four values, so a mutation that reads the
    // wrong bit or inverts the sense cannot pass on a subset.
    //
    // Mutation checks (performed and reverted), neither failing anything else in the
    // Quic suite:
    //   * replacing UnidirectionalBit with 0x02 in the mask - fails the 0x12 and
    //     0x16 rows, since both of those values already have bit 0x02 set (0x12 is
    //     0b10010, 0x16 is 0b10110) and would be read as unidirectional. The two
    //     odd rows cannot catch it.
    //   * inverting the comparison to == 0 - fails all four rows.
    //
    // A third mutation is worth recording because it CANNOT be run: changing the
    // UnidirectionalBit constant itself to 0x02 does not compile. 0x16 already has
    // that bit, so `StreamsBlocked | UnidirectionalBit` collapses onto the bare
    // StreamsBlocked label in TlsQuicFrames.TryReadFrame's switch and the compiler
    // rejects the duplicate case (CS0152). The constant's value is therefore pinned
    // by the read dispatch's spelling as well as by this theory - which is an
    // argument for spelling those labels `Base | UnidirectionalBit` rather than as
    // bare 0x13 and 0x17.
    [Theory]
    [InlineData(0x12UL, false)]
    [InlineData(0x13UL, true)]
    [InlineData(0x16UL, false)]
    [InlineData(0x17UL, true)]
    public void IsUnidirectionalReadsTheDirectionFromTheRawType(ulong rawType, bool expected)
    {
        Assert.Equal(expected, TlsQuicFlowControlFrames.IsUnidirectional(rawType));
    }

    // THE THREE READERS' OWN Try-SHAPED CONTRACT - "`offset` only advances on
    // success" - called directly rather than through TlsQuicFrames.TryReadFrame,
    // which is the only production caller. TryReadFrame publishes its `offset` only
    // on success, so a family reader that advanced its caller's cursor on the way
    // out would be invisible from outside; the promise has to be pinned by a second
    // caller, and a test is allowed to be one because these readers are already
    // `internal` for the dispatch switch. The pattern is A2 task 3b's, at
    // TlsQuicStreamFramesTests.TryReadStreamCommitsNothingWhenTheOffsetBoundRejects.
    //
    // `offset` starts at 1, past the frame type, because that is where TryReadFrame
    // leaves it - and a nonzero start is what makes "exactly as passed in"
    // distinguishable from "reset to zero".
    //
    // TWO TESTS FOR THREE READERS, and the missing one is a deliberate omission
    // rather than a gap. Every rejection has to walk some bytes before it fires for
    // an early commit to be observable at all, and TryReadMaximumData has none that
    // do: its only rejection is its single field's varint truncating, and
    // QuicVariableLengthInteger.Read advances the offset it is given as its last
    // statement, so on a throw nothing has moved and `walked` still equals the entry
    // offset. `offset = walked` there is a no-op for every input. The property holds
    // by construction, not merely unwitnessed, and it stops holding the moment that
    // reader gains a second field or a bound - which is what TryReadMaximumStreams
    // below is. Recorded rather than papered over with a test that could not fail.
    [Fact]
    public void TryReadMaximumStreamDataCommitsNothingWhenItsSecondFieldIsTruncated()
    {
        // Type 0x11, Stream ID 4, then a two-byte varint prefix with its second
        // byte missing. The Stream ID is read successfully, so `walked` is 2 when
        // the catch fires and an early commit would show as offset 2.
        //
        // Mutation check (performed and reverted): adding `offset = walked;` before
        // the `return false;` in TryReadMaximumStreamData's catch fails this test
        // and nothing else in the Quic suite.
        byte[] payload = [0x11, 0x04, TruncatedVarintPrefix];
        var offset = 1;

        Assert.False(TlsQuicFlowControlFrames.TryReadMaximumStreamData(
            payload, ref offset, 0x11, out var frame, out var error));
        Assert.Equal(1, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(default, frame.StreamId);
        Assert.Equal(default, frame.MaximumStreamData);
    }

    [Fact]
    public void TryReadMaximumStreamsCommitsNothingWhenTheStreamCountBoundRejects()
    {
        // Type 0x12 with a complete 8-byte 2^60 + 1, which the s19.11 bound
        // rejects. The field is read successfully first, so `walked` is 9 when the
        // bound fires - the most any rejection in this file walks, and so the most
        // for an early commit to expose. The catch above the bound is the no-op case
        // described in the note on the previous test, which is why the bound and not
        // a truncation is what this pins.
        //
        // Mutation check (performed and reverted): adding `offset = walked;` before
        // the `return false;` in TryReadMaximumStreams' stream-count bound fails
        // this test and nothing else in the Quic suite.
        byte[] payload = [0x12, .. StreamCountBoundPlusOneEncoded];
        var offset = 1;

        Assert.False(TlsQuicFlowControlFrames.TryReadMaximumStreams(
            payload, ref offset, 0x12, out var frame, out var error));
        Assert.Equal(1, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(default, frame.MaximumStreams);
    }
}
