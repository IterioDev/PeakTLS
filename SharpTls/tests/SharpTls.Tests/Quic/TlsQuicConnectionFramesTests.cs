using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// The eight connection-management frames: RFC 9000 s19.4 RESET_STREAM, s19.5
// STOP_SENDING, s19.7 NEW_TOKEN, s19.15 NEW_CONNECTION_ID, s19.16
// RETIRE_CONNECTION_ID, s19.17 PATH_CHALLENGE, s19.18 PATH_RESPONSE and s19.19
// CONNECTION_CLOSE. Split from TlsQuicFramesTests for the same reason ACK, STREAM
// and CRYPTO and the flow-control six were.
//
// None of the eight has a published test vector - RFC 9001 A.2's CRYPTO frame is
// the only one this whole phase gets - so every byte array below is hand-derived
// from the s19 field lists (Figures 28, 29, 31, 39, 40, 41, 42 and 43) and the s16
// variable-length integer rules, with the derivation written above the test and
// asserted against the encoder directly. A round-trip test alone would only prove
// this library's encoder and decoder agree with each other, which they can do
// while both being wrong about field order.
//
//   RESET_STREAM {                  STOP_SENDING {
//     Type (i) = 0x04,                Type (i) = 0x05,
//     Stream ID (i),                  Stream ID (i),
//     Application Protocol            Application Protocol
//       Error Code (i),                 Error Code (i),
//     Final Size (i),               }
//   }
//
//   NEW_TOKEN {                     NEW_CONNECTION_ID {
//     Type (i) = 0x07,                Type (i) = 0x18,
//     Token Length (i),               Sequence Number (i),
//     Token (..),                     Retire Prior To (i),
//   }                                 Length (8),
//                                     Connection ID (8..160),
//   RETIRE_CONNECTION_ID {            Stateless Reset Token (128),
//     Type (i) = 0x19,              }
//     Sequence Number (i),
//   }                               PATH_CHALLENGE / PATH_RESPONSE {
//                                     Type (i) = 0x1a / 0x1b,
//   CONNECTION_CLOSE {                Data (64),
//     Type (i) = 0x1c..0x1d,        }
//     Error Code (i),
//     [Frame Type (i)],
//     Reason Phrase Length (i),
//     Reason Phrase (..),
//   }
//
// THE FIELDS ARE NOT ALL VARINTS, which is what makes this family's vectors worth
// reading byte by byte rather than skimming. NEW_CONNECTION_ID's Length is one
// plain byte and its Stateless Reset Token is a bare 16, neither of them
// length-prefixed; PATH_CHALLENGE's and PATH_RESPONSE's Data is a bare 8. The
// widths in the RFC's figures are BITS - "(128)" and "(64)" - so the byte counts
// below are those figures divided by eight, and a vector that got the division
// wrong would still round-trip through this library and fail against any real
// peer.
//
// TEN TYPE VALUES, NOT EIGHT: s19.17 and s19.18 are two frame types sharing one
// format, and s19.19 is one frame type with two forms that differ in which fields
// exist. So the tests are organised around the type values rather than the frame
// names, and every check inside TlsQuicConnectionFrames.TryReadPathData,
// WritePathDataFrameFields, TryReadConnectionClose and
// WriteConnectionCloseFrameFields is reachable two ways and carries two rows. The
// cheap mutation that exposes a missing row is to wrap the check in
// `if (rawType == 0x1a)` or `if (IsApplicationError(rawType))` and see whether
// anything fails; each of those is recorded at the check it was applied to.
//
// Every field value in these vectors is 63 or below, so it encodes as a single
// byte whose value is the value itself: s16 gives the first byte's two most
// significant bits as the log2 of the encoded length, so 0b00 means one byte with
// six value bits.
public sealed class TlsQuicConnectionFramesTests
{
    // 2^62 - 1, the largest value a variable-length integer can carry (s16 spends
    // the first byte's two most significant bits on the length, leaving 62 value
    // bits in the 8-byte form).
    private const ulong VarintMaximum = (1UL << 62) - 1;

    // A two-byte varint prefix (s16: first byte 0b01_xxxxxx means two bytes) with
    // its second byte missing - the shortest input that makes
    // QuicVariableLengthInteger.Read throw rather than return, which is what every
    // truncation row below appends to a frame.
    private const byte TruncatedVarintPrefix = 0x40;

    // The varint field values every vector below uses, deliberately all
    // *different* small numbers so that a writer or reader which emitted or
    // consumed a frame's fields in the wrong order would produce visibly wrong
    // bytes rather than plausible ones. Field order is the one thing a round-trip
    // test cannot catch when every field is a varint.
    private const ulong StreamIdValue = 9;                       // -> 0x09
    private const ulong ApplicationProtocolErrorCodeValue = 11;  // -> 0x0b
    private const ulong FinalSizeValue = 42;                     // -> 0x2a
    private const ulong SequenceNumberValue = 7;                 // -> 0x07
    private const ulong RetirePriorToValue = 3;                  // -> 0x03
    private const ulong ErrorCodeValue = 0x07;                   // -> 0x07
    private const ulong TriggerFrameTypeValue = 0x08;            // -> 0x08

    private static readonly byte[] TokenBytes = [0xc0, 0xff, 0xee];
    private static readonly byte[] ConnectionIdBytes = [0xde, 0xad, 0xbe, 0xef];

    // 16 bytes - s19.15's "Stateless Reset Token (128)", 128 bits divided by 8.
    // Ascending so that a writer or reader which reversed or shifted it would be
    // visible in the vector rather than symmetric.
    private static readonly byte[] StatelessResetTokenBytes =
    [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];

    // 8 bytes - s19.17's "Data (64)", 64 bits divided by 8.
    private static readonly byte[] PathDataBytes =
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    // "bad" in ASCII. s19.19 makes the Reason Phrase a SHOULD-be-UTF-8 byte string;
    // three bytes keeps the length field a single byte.
    private static readonly byte[] ReasonPhraseBytes = [0x62, 0x61, 0x64];

    // s19.4 Figure 28, Stream ID = 9, Application Protocol Error Code = 11, Final
    // Size = 42:
    //
    //   04 09 0b 2a
    //   ^  ^  ^  ^-- Final Size
    //   |  |  +----- Application Protocol Error Code
    //   |  +-------- Stream ID
    //   +----------- Type
    //
    // Three different values in three fields, which is what makes this test the
    // only thing in the suite that can catch a writer emitting them in the wrong
    // order: all three are varints, so a permuted writer's output decodes back into
    // a plausible RESET_STREAM and a round-trip test would not notice.
    //
    // STREAM ID IS 9 AND NOT THE 4 THIS FILE FIRST USED, and the change was forced
    // by a surviving mutation rather than chosen. RESET_STREAM's type value is
    // 0x04, so with Stream ID 4 the first two bytes of this vector were the same
    // byte and "write the Stream ID before the frame type" produced byte-for-byte
    // identical output. That mutation survived the whole Quic suite. A field value
    // that collides with its own frame's type byte is a hole in every vector it
    // appears in, and this file's other seven types were checked for the same
    // collision after it was found - none had it.
    //
    // Mutation checks (performed and reverted), none failing anything else in the
    // Quic suite: deleting the Final Size Write call in
    // WriteResetStreamFrameFields - fails this test; permuting the Stream ID and
    // Application Protocol Error Code writes - fails this test; swapping the type
    // Write with the Stream ID - fails this test, which it did NOT before the value
    // changed from 4 to 9.
    [Fact]
    public void ResetStreamFrameMatchesItsHandDerivedBytes()
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x04,
            StreamId = StreamIdValue,
            ApplicationProtocolErrorCode = ApplicationProtocolErrorCodeValue,
            FinalSize = FinalSizeValue,
        };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal<byte>([0x04, 0x09, 0x0b, 0x2a], destination);
    }

    // s19.5 Figure 29, the same two field values without a Final Size:
    //
    //   05 09 0b
    //
    // The absence of a third byte is the assertion that matters: s19.5's figure has
    // two fields where s19.4's has three, and a shared reader or writer that
    // treated STOP_SENDING as a RESET_STREAM with a defaulted Final Size would
    // append a 0x00 here. That is why TlsQuicConnectionFrames implements the two
    // separately rather than sharing.
    [Fact]
    public void StopSendingFrameMatchesItsHandDerivedBytes()
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x05,
            StreamId = StreamIdValue,
            ApplicationProtocolErrorCode = ApplicationProtocolErrorCodeValue,
        };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal<byte>([0x05, 0x09, 0x0b], destination);
    }

    // s19.7 Figure 31, two token lengths:
    //
    //   07 03 c0 ff ee                Token Length = 3
    //   07 05 11 22 33 44 55          Token Length = 5
    //   ^  ^  ^------- Token
    //   |  +---------- Token Length
    //   +------------- Type
    //
    // The Token Length is a varint written from Token.Length, not a field of
    // TlsQuicFrame, so no separate value can disagree with the bytes that follow.
    //
    // TWO ROWS BECAUSE ONE CANNOT TELL THE FIELD FROM A CONSTANT. With only the
    // three-byte token this file first carried, replacing the Token Length write
    // with the literal 3 left the whole Quic suite green: it was the only non-empty
    // token in the suite on either side, so nothing could separate "write the
    // length" from "write a 3". This is the RESET_STREAM finding one field over -
    // a value that coincides with a fixed quantity makes the code that computes it
    // indistinguishable from the quantity - and the second row is chosen so its
    // length is neither the first row's 3 nor NEW_TOKEN's own type byte 0x07.
    //
    // The sibling guard is fine and the contrast is the point: the same mutation on
    // NEW_CONNECTION_ID's Length byte dies, because
    // NewConnectionIdAtBothEndsOfTheLengthRangeIsAccepted round-trips widths 1 and
    // 20. Two widths is what makes a length field observable.
    //
    // Mutation checks (performed and reverted), measured: replacing the Token
    // Length write with the literal 3UL - fails the five-byte row here and nothing
    // else; deleting the Token Length write - fails both rows; deleting the
    // WriteBytes of the token - fails both rows.
    [Theory]
    [InlineData(new byte[] { 0xc0, 0xff, 0xee }, new byte[] { 0x07, 0x03, 0xc0, 0xff, 0xee })]
    [InlineData(
        new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55 },
        new byte[] { 0x07, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55 })]
    public void NewTokenFramesMatchTheirHandDerivedBytes(byte[] token, byte[] expected)
    {
        var frame = new TlsQuicFrame { RawType = 0x07, Token = token };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal(expected, destination);
    }

    // s19.15 Figure 39, and the vector this file exists for - three fields that are
    // not varints:
    //
    //   18 07 03 04 de ad be ef 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
    //   ^  ^  ^  ^  ^----------- Connection ID, 4 bytes
    //   |  |  |  +-------------- Length = 4, an 8-BIT INTEGER, not a varint
    //   |  |  +----------------- Retire Prior To = 3
    //   |  +-------------------- Sequence Number = 7
    //   +----------------------- Type
    //                                    then 16 bytes of Stateless Reset Token
    //
    // 24 bytes in all: 1 + 1 + 1 + 1 + 4 + 16. The Length byte is 0x04 either way,
    // so this vector does not distinguish a one-byte read from a varint read; the
    // row that does is in NewConnectionIdWithAnOutOfRangeLengthIsRejected below.
    // What it does pin is the token's width and position: a reader or writer that
    // took the token as 8 or 32 bytes, or that put it before the connection ID,
    // fails here.
    //
    // Retire Prior To (3) is deliberately below Sequence Number (7) rather than
    // equal, so this vector satisfies s19.15's ordering constraint strictly and the
    // constraint's own boundary is tested separately.
    //
    // Mutation checks (performed and reverted), measured. Note the first two are
    // WRITER mutations, so the parse-back test is unaffected by them - the
    // round-tripping rows of NewConnectionIdAtBothEndsOfTheLengthRangeIsAccepted
    // are what join this test in failing:
    //   * permuting Sequence Number and Retire Prior To - fails three.
    //   * swapping the two WriteBytes calls - fails four; the connection ID and the
    //     token have different lengths, so the frame's shape changes.
    //   * writing the Length through QuicVariableLengthInteger.Write instead of as
    //     a byte - SURVIVES, and correctly: every legal length is below 64, so the
    //     one-byte varint form encodes it as itself and the two agree over the
    //     whole legal range. Recorded at that line in TlsQuicConnectionFrames,
    //     together with the read-side input that does separate them.
    [Fact]
    public void NewConnectionIdFrameMatchesItsHandDerivedBytes()
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x18,
            SequenceNumber = SequenceNumberValue,
            RetirePriorTo = RetirePriorToValue,
            ConnectionId = ConnectionIdBytes,
            StatelessResetToken = StatelessResetTokenBytes,
        };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal<byte>(
        [
            0x18,
            0x07,
            0x03,
            0x04,
            0xde, 0xad, 0xbe, 0xef,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ],
            destination);
    }

    // s19.16 Figure 40 - the shortest frame in this file:
    //
    //   19 07
    //
    // Sequence Number = 7, the same value NEW_CONNECTION_ID's vector uses, since
    // s19.15 and s19.16 name the field identically and TlsQuicFrame carries one
    // property for both.
    [Fact]
    public void RetireConnectionIdFrameMatchesItsHandDerivedBytes()
    {
        var frame = new TlsQuicFrame { RawType = 0x19, SequenceNumber = SequenceNumberValue };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal<byte>([0x19, 0x07], destination);
    }

    // s19.17 Figure 41 and s19.18 Figure 42, eight bytes with no length in front of
    // them:
    //
    //   type  bytes
    //   0x1a  1a 01 02 03 04 05 06 07 08   PATH_CHALLENGE
    //   0x1b  1b 01 02 03 04 05 06 07 08   PATH_RESPONSE
    //
    // Nine bytes total, not ten: there is no Length field. A writer that emitted
    // one would produce `1a 08 01 02 ...` and fail both rows.
    //
    // THIS IS THE DEMONSTRATION THAT THE SHARED WRITER IS GENUINELY SHARED, which
    // the A2 plan asks for: there is one implementation behind these two rows -
    // s19.18 says the formats are identical - so a mutation inside it fails a row
    // belonging to each of the two frame types rather than only the one an author
    // reached for first.
    //
    // Mutation checks (performed and reverted), measured: prefixing the data with
    // its length in WritePathDataFrameFields - fails these two rows and nothing
    // else; writing the data before the frame type - fails these two rows and
    // nothing else; changing PathDataLength to 7 - fails ten rows across this file,
    // which is what a width constant used by both directions costs.
    [Theory]
    [InlineData(0x1aUL)]
    [InlineData(0x1bUL)]
    public void PathFramesMatchTheirHandDerivedBytes(ulong rawType)
    {
        var frame = new TlsQuicFrame { RawType = rawType, Data = PathDataBytes };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal<byte>([(byte)rawType, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], destination);
    }

    // s19.19 Figure 43, BOTH FORMS, and the pair of rows that pins the bracketed
    // field:
    //
    //   type  bytes                    fields
    //   0x1c  1c 07 08 03 62 61 64     Error Code 0x07, Frame Type 0x08, "bad"
    //   0x1c  1c 07 00 03 62 61 64     Error Code 0x07, Frame Type 0,    "bad"
    //   0x1d  1d 07 03 62 61 64        Error Code 0x07, "bad"
    //
    // Seven bytes against six: s19.19's Frame Type field is present in the
    // transport form and absent in the application one - "The application-specific
    // variant of CONNECTION_CLOSE (type 0x1d) does not include this field" - so the
    // 0x1d row is one byte shorter and every byte after the Error Code has moved.
    // Those rows are what make that difference observable; either alone would pass
    // against a writer that always emitted the field or never did.
    //
    // THE MIDDLE ROW IS THE ZERO-VERSUS-ABSENT AXIS, and it is the plan's
    // "enumerate reachable paths, not reachable flag paths" rule landing on the
    // value a real peer sends most often. s19.19 gives Frame Type 0 a meaning - "A
    // value of 0 (equivalent to the mention of the PADDING frame) is used when the
    // frame type is unknown" - so a transport-form close carrying 0 is a legal,
    // ordinary frame that must still emit the field. Without this row, narrowing
    // the writer's presence guard to `!IsApplicationError(RawType) &&
    // frame.TriggerFrameType != 0` left the whole Quic suite green: every other
    // 0x1c vector in this file carries Frame Type 0x08, so the mutant's silent
    // omission was unobservable and a peer would have read the Reason Phrase Length
    // as the trigger type. The middle row's seven bytes against the mutant's six is
    // what kills it.
    //
    // The Error Code (0x07) and the Frame Type (0x08) are deliberately different
    // numbers in the first row, so a writer that swapped them fails it.
    //
    // Mutation checks (performed and reverted), measured. Each also takes the
    // corresponding row of ConnectionCloseWithAnEmptyReasonPhraseRoundTrips, which
    // writes the same two forms with a zero-length phrase:
    //   * narrowing that guard to `&& frame.TriggerFrameType != 0` - fails ONE,
    //     the middle row, and nothing else in the Quic suite. Before that row
    //     existed it failed nothing at all, which is why it is there.
    //   * deleting the guard entirely, so the Frame Type is always written - fails
    //     two, the 0x1d row here and there; that row grows to seven bytes.
    //   * inverting that guard - fails five, every row of the two theories.
    //   * replacing frame.RawType with (ulong)frame.Type in the type Write - fails
    //     two, the 0x1d rows, whose derived Type is ConnectionClose = 0x1c. The two
    //     0x1c rows cannot catch it: for them the two expressions are equal. This is
    //     the only place in this file where those two expressions differ, since
    //     0x1c is the family's one Table 3 range base; the same mutation applied to
    //     any of the other six writers SURVIVES, correctly, because none of their
    //     types is a range base.
    [Theory]
    [InlineData(0x1cUL, TriggerFrameTypeValue, new byte[] { 0x1c, 0x07, 0x08, 0x03, 0x62, 0x61, 0x64 })]
    [InlineData(0x1cUL, 0UL, new byte[] { 0x1c, 0x07, 0x00, 0x03, 0x62, 0x61, 0x64 })]
    [InlineData(0x1dUL, 0UL, new byte[] { 0x1d, 0x07, 0x03, 0x62, 0x61, 0x64 })]
    public void ConnectionCloseFramesMatchTheirHandDerivedBytes(
        ulong rawType, ulong triggerFrameType, byte[] expected)
    {
        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            ErrorCode = ErrorCodeValue,
            TriggerFrameType = triggerFrameType,
            ReasonPhrase = ReasonPhraseBytes,
        };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal(expected, destination);
    }

    // The read direction of the vectors above, asserting the fields rather than the
    // bytes: that the type reaches TlsQuicFrame.RawType intact, that the value
    // lands in the field s19.4 to s19.19 name, and that `offset` advanced past the
    // whole frame and no further.
    //
    // Reading is dispatched through TlsQuicFrames.TryReadFrame, not the family
    // readers directly, so these also pin the eight case labels added to that
    // switch - without them each of these inputs would fall through to the default
    // arm and be rejected as an unknown frame type. Only the accepting tests can:
    // the rejecting tests all expect false with FRAME_ENCODING_ERROR, which is
    // exactly what a dropped case label produces, so a suite of rejection tests
    // would pass with the whole dispatch deleted.
    //
    // Mutation checks (performed and reverted), on the two switches in
    // TlsQuicFrames rather than on the family readers:
    //   * dropping the `case TlsQuicFrameType.StopSending` label from the read
    //     dispatch - fails StopSendingFrameParsesBackToItsFields alone.
    //   * dropping the `case PathResponse` label - fails the 0x1b rows of
    //     PathFramesParseBackToTheirFields and
    //     PathFrameConsumesExactlyEightBytesAndNoMore.
    //   * dropping the `ConnectionClose | ApplicationErrorBit` label - fails the
    //     0x1d rows of ConnectionCloseFramesParseBackToTheirFields and
    //     ConnectionCloseWithAnEmptyReasonPhraseRoundTrips.
    //   * pointing the read dispatch's ResetStream arm at TryReadStopSending -
    //     fails two, ResetStreamFrameParsesBackToItsFields on the offset, since the
    //     frame's Final Size byte is left unread, and the Final-Size row of
    //     ResetStreamTruncatedInAnyFieldIsRejected, which such a reader accepts.
    [Fact]
    public void ResetStreamFrameParsesBackToItsFields()
    {
        byte[] encoded = [0x04, 0x09, 0x0b, 0x2a];
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal(0x04UL, frame.RawType);
        Assert.Equal(0x04UL, (ulong)frame.Type);

        // Three different numbers in the three fields s19.4 names, which is what
        // makes a reader that permuted them fail here as well as in the byte
        // vector above.
        Assert.Equal(StreamIdValue, frame.StreamId);
        Assert.Equal(ApplicationProtocolErrorCodeValue, frame.ApplicationProtocolErrorCode);
        Assert.Equal(FinalSizeValue, frame.FinalSize);
    }

    [Fact]
    public void StopSendingFrameParsesBackToItsFields()
    {
        byte[] encoded = [0x05, 0x09, 0x0b];
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal(0x05UL, frame.RawType);
        Assert.Equal(StreamIdValue, frame.StreamId);
        Assert.Equal(ApplicationProtocolErrorCodeValue, frame.ApplicationProtocolErrorCode);

        // s19.5's figure has no Final Size, so the property TlsQuicFrame shares
        // with RESET_STREAM must be left at its default rather than filled from the
        // next frame's bytes.
        Assert.Equal(0UL, frame.FinalSize);
    }

    // Both token lengths on the read side too. The write-side finding above has an
    // exact read-side twin - slicing a fixed 3 bytes instead of the decoded length
    // is invisible to a suite whose only token is 3 bytes long - and the review
    // that found the write half had already been caught once handing over a
    // write-only row for a two-sided defect. Sweeping one direction of the
    // zero-versus-absent and one-value-only axes is how a hole survives.
    //
    // Mutation check (performed and reverted), measured: slicing a literal 3 bytes
    // instead of (int)tokenLength in TryReadNewToken - fails the five-byte row here
    // and nothing else.
    [Theory]
    [InlineData(new byte[] { 0x07, 0x03, 0xc0, 0xff, 0xee }, new byte[] { 0xc0, 0xff, 0xee })]
    [InlineData(
        new byte[] { 0x07, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55 },
        new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55 })]
    public void NewTokenFramesParseBackToTheirFields(byte[] encoded, byte[] expectedToken)
    {
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal(0x07UL, frame.RawType);
        Assert.Equal(expectedToken, frame.Token.ToArray());
    }

    [Fact]
    public void NewConnectionIdFrameParsesBackToItsFields()
    {
        byte[] encoded =
        [
            0x18, 0x07, 0x03, 0x04,
            0xde, 0xad, 0xbe, 0xef,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal(0x18UL, frame.RawType);
        Assert.Equal(SequenceNumberValue, frame.SequenceNumber);
        Assert.Equal(RetirePriorToValue, frame.RetirePriorTo);

        // The two fixed-width fields, asserted separately: their contents do not
        // overlap, so a reader that took the token from one byte too early or one
        // too late fails one of these two rather than both.
        Assert.Equal<byte>(ConnectionIdBytes, frame.ConnectionId.ToArray());
        Assert.Equal<byte>(StatelessResetTokenBytes, frame.StatelessResetToken.ToArray());
    }

    [Fact]
    public void RetireConnectionIdFrameParsesBackToItsFields()
    {
        byte[] encoded = [0x19, 0x07];
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal(0x19UL, frame.RawType);
        Assert.Equal(SequenceNumberValue, frame.SequenceNumber);
    }

    [Theory]
    [InlineData(0x1aUL)]
    [InlineData(0x1bUL)]
    public void PathFramesParseBackToTheirFields(ulong rawType)
    {
        byte[] encoded = [(byte)rawType, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal(rawType, frame.RawType);
        Assert.Equal(rawType, (ulong)frame.Type);
        Assert.Equal<byte>(PathDataBytes, frame.Data.ToArray());
    }

    // THE READ-SIDE TWIN OF THE MIDDLE ROW ABOVE, and it was missing for a round:
    // the row that fixed the writer was write-only, so narrowing the READER's
    // presence guard to skip the Frame Type read when the next byte is zero still
    // left the whole Quic suite green. A transport-form close carrying s19.19's
    // "the frame type is unknown" value then decodes its Reason Phrase Length as
    // the trigger type - the same silent field shift, one direction over.
    //
    // Both halves of the axis, in both directions, is the rule this cost twice to
    // learn.
    //
    // Mutation check (performed and reverted), measured: narrowing the reader's
    // guard to `!IsApplicationError(rawType) && payload.Span[walked] != 0` - fails
    // the middle row here and nothing else.
    [Theory]
    [InlineData(new byte[] { 0x1c, 0x07, 0x08, 0x03, 0x62, 0x61, 0x64 }, 0x1cUL, TriggerFrameTypeValue)]
    [InlineData(new byte[] { 0x1c, 0x07, 0x00, 0x03, 0x62, 0x61, 0x64 }, 0x1cUL, 0UL)]
    [InlineData(new byte[] { 0x1d, 0x07, 0x03, 0x62, 0x61, 0x64 }, 0x1dUL, 0UL)]
    public void ConnectionCloseFramesParseBackToTheirFields(
        byte[] encoded, ulong expectedRawType, ulong expectedTriggerFrameType)
    {
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);

        // RawType and the derived Type differ on the 0x1d row - 0x1c..0x1d is a
        // Table 3 range - so these two assertions together pin TlsQuicFrame.Type's
        // s19.19 range arm as well as the form surviving the read.
        Assert.Equal(expectedRawType, frame.RawType);
        Assert.Equal(0x1cUL, (ulong)frame.Type);
        Assert.Equal(ErrorCodeValue, frame.ErrorCode);

        // 0 on the 0x1d row is not an untested default: s19.19 gives the absent
        // field's value the same meaning the transport form's 0 has, and a reader
        // that read the Frame Type unconditionally would put the Reason Phrase
        // Length (3) here instead.
        Assert.Equal(expectedTriggerFrameType, frame.TriggerFrameType);
        Assert.Equal<byte>(ReasonPhraseBytes, frame.ReasonPhrase.ToArray());
    }

    // s12.4: "Frames always fit within a single QUIC packet and cannot span
    // multiple packets", so a field whose varint prefix promises more bytes than
    // the payload holds is badly formatted rather than incomplete, and s20.1's
    // FRAME_ENCODING_ERROR is "An endpoint received a frame that was badly
    // formatted". `offset` must be left at 0, since TryReadFrame only commits an
    // advance on success.
    //
    // THREE ROWS FOR ONE CATCH, one per field of s19.4's figure: a frame truncated
    // in its Stream ID, in its Application Protocol Error Code and in its Final
    // Size fail at three different Read calls, so a mutation that narrowed the try
    // to cover only the first would survive a suite that tested one of them.
    //
    //   04 40           Stream ID truncated
    //   04 09 40        Application Protocol Error Code truncated
    //   04 09 0b 40     Final Size truncated
    //
    // Mutation checks (performed and reverted), measured. Each also takes
    // TryReadResetStreamCommitsNothingWhenItsLastFieldIsTruncated, which enters the
    // same catch: changing the caught type so the exception escapes - fails four;
    // dropping its `error` assignment - fails the same four on the error code;
    // narrowing the catch to failures that walked nothing, which is the try
    // covering only the first Read - fails three; narrowing it to the first two
    // reads - fails two.
    [Theory]
    [InlineData(new byte[] { 0x04, TruncatedVarintPrefix })]
    [InlineData(new byte[] { 0x04, 0x09, TruncatedVarintPrefix })]
    [InlineData(new byte[] { 0x04, 0x09, 0x0b, TruncatedVarintPrefix })]
    public void ResetStreamTruncatedInAnyFieldIsRejected(byte[] encoded)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // The same for s19.5's two fields. Mutation checks (performed and reverted),
    // measured: changing the caught type so the exception escapes - fails three,
    // both rows plus TryReadStopSendingCommitsNothingWhenItsSecondFieldIsTruncated;
    // narrowing the catch to failures that walked nothing - fails two, the second
    // row and that same test.
    [Theory]
    [InlineData(new byte[] { 0x05, TruncatedVarintPrefix })]
    [InlineData(new byte[] { 0x05, 0x09, TruncatedVarintPrefix })]
    public void StopSendingTruncatedInEitherFieldIsRejected(byte[] encoded)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    [Fact]
    public void NewTokenTruncatedInItsLengthIsRejected()
    {
        byte[] encoded = [0x07, TruncatedVarintPrefix];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // THE FIELD THAT CANNOT BE EMPTY. s19.7, Token: "The token MUST NOT be empty. A
    // client MUST treat receipt of a NEW_TOKEN frame with an empty Token field as a
    // connection error of type FRAME_ENCODING_ERROR." The error code is named
    // outright, so unlike this phase's other rejections there was no choice to
    // justify.
    //
    // The input is a complete, well-formed frame in every other respect - the
    // length varint is one whole byte and nothing follows it that should - so the
    // catch above and the extent check below cannot fire, and the zero-length check
    // is the only thing that can reject it.
    //
    // Mutation check (performed and reverted), measured: deleting the check - fails
    // two, this test with a successful parse into a frame whose Token is empty, and
    // TryReadNewTokenCommitsNothingWhenTheTokenIsEmpty, whose input is the same
    // frame read at a nonzero offset.
    [Fact]
    public void NewTokenWithAnEmptyTokenIsRejected()
    {
        byte[] encoded = [0x07, 0x00];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // A Token Length of 3 with two bytes behind it. Mutation check (performed and
    // reverted): deleting the extent check - this test fails with
    // ArgumentOutOfRangeException out of Memory.Slice, an exception escaping a
    // Try-shaped reader rather than a wrong answer.
    [Fact]
    public void NewTokenWhoseLengthOverrunsThePayloadIsRejected()
    {
        byte[] encoded = [0x07, 0x03, 0xc0, 0xff];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    [Theory]
    [InlineData(new byte[] { 0x18, TruncatedVarintPrefix })]
    [InlineData(new byte[] { 0x18, 0x07, TruncatedVarintPrefix })]
    public void NewConnectionIdTruncatedInItsVarintFieldsIsRejected(byte[] encoded)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // THE ORDERING CONSTRAINT. s19.15: "The value in the Retire Prior To field MUST
    // be less than or equal to the value in the Sequence Number field. Receiving a
    // value in the Retire Prior To field that is greater than that in the Sequence
    // Number field MUST be treated as a connection error of type
    // FRAME_ENCODING_ERROR."
    //
    // Sequence Number 3, Retire Prior To 4 - one apart, so it is the constraint and
    // not a large number that rejects this - followed by a complete and otherwise
    // valid body: a length byte of 1, one connection ID byte and a full 16-byte
    // token. Every other check in the reader therefore passes, and only the
    // ordering comparison can reject it.
    //
    // WHY THIS READ-SIDE CHECK IS REACHABLE AT ALL, when the plan's standing rule
    // says a bound on a parser-produced value usually is not: the bound here is not
    // a constant the varint range already enforces, it is the frame's other field.
    // Any pair of decodable varints in the wrong order reaches it.
    //
    // Mutation check (performed and reverted): deleting the comparison - this test
    // fails with a successful parse; nothing else in the Quic suite fails.
    [Fact]
    public void NewConnectionIdWhoseRetirePriorToExceedsItsSequenceNumberIsRejected()
    {
        byte[] encoded = [0x18, 0x03, 0x04, 0x01, 0x5a, .. StatelessResetTokenBytes];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // The other side of the same constraint: s19.15 says "less than or equal to",
    // so equality is legal and the comparison must be strict. The same body as the
    // rejecting test with Retire Prior To lowered to 3.
    //
    // Mutation check (performed and reverted): weakening the comparison in
    // TryReadNewConnectionId to >= - fails this test and nothing else in the Quic
    // suite.
    [Fact]
    public void NewConnectionIdWhoseRetirePriorToEqualsItsSequenceNumberIsAccepted()
    {
        byte[] encoded = [0x18, 0x03, 0x03, 0x01, 0x5a, .. StatelessResetTokenBytes];
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal(3UL, frame.SequenceNumber);
        Assert.Equal(3UL, frame.RetirePriorTo);
    }

    // The Length field is an 8-bit integer, so a frame that ends immediately after
    // Retire Prior To has no room for it. Mutation check (performed and reverted):
    // deleting the `walked >= payload.Length` check - this test fails with
    // IndexOutOfRangeException out of the span index, again an exception escaping a
    // Try-shaped reader.
    [Fact]
    public void NewConnectionIdWithNoLengthByteIsRejected()
    {
        byte[] encoded = [0x18, 0x07, 0x03];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // THE BOUNDED-LENGTH FIELD, rejecting side. s19.15: "An 8-bit unsigned integer
    // containing the length of the connection ID. Values less than 1 and greater
    // than 20 are invalid and MUST be treated as a connection error of type
    // FRAME_ENCODING_ERROR."
    //
    // Three rows, killing two different mutations - which is why they are one
    // theory rather than three tests, and why the third row's job is written down:
    //
    //   length byte  body                              kills
    //   0x00         16 token bytes                    deleting the range check
    //   0x15 (21)    21 cid bytes + 16 token bytes     deleting the range check
    //   0x40 (64)    05 + 5 cid bytes + 16 token       reading Length as a varint
    //
    // The first two rows carry a body that exactly fits the length they declare, so
    // the extent check below cannot fire for either and the range check is the only
    // thing that can reject them: with it deleted, both parse successfully - the
    // first into a frame with an empty connection ID, the second into one with a
    // 21-byte connection ID.
    //
    // The third row is the one that pins the field's WIDTH rather than its range,
    // and it is the only input that can. Every legal length is below 64, so a
    // mutation reading the Length through QuicVariableLengthInteger.Read agrees
    // with a one-byte read over the whole legal range and no accepting vector can
    // separate them. At 0x40 they diverge: s16 makes 0x40 a two-byte varint prefix,
    // so the mutant reads 0x40 0x05 as the value 5 and then finds exactly 5
    // connection ID bytes and 16 token bytes waiting - it accepts the frame. The
    // correct one-byte read sees 64 and rejects. Deleting the range check does NOT
    // fail this row (the extent check rejects it instead, with the same code), and
    // that is recorded rather than papered over.
    //
    // Mutation checks (performed and reverted), measured: deleting the range check
    // - fails three, rows one and two plus
    // TryReadNewConnectionIdCommitsNothingWhenTheLengthIsOutOfRange, whose input is
    // row one's; dropping the `< MinimumConnectionIdLength` half - fails two, row
    // one and that same test; dropping the `> MaximumConnectionIdLength` half -
    // fails row two alone; reading the Length as a varint - fails row three
    // alone.
    [Theory]
    [InlineData(new byte[]
    {
        0x18, 0x07, 0x03, 0x00,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    })]
    [InlineData(new byte[]
    {
        0x18, 0x07, 0x03, 0x15,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    })]
    [InlineData(new byte[]
    {
        0x18, 0x07, 0x03, 0x40,
        0x05, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    })]
    public void NewConnectionIdWithAnOutOfRangeLengthIsRejected(byte[] encoded)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // The accepting side of the same range, at both ends: s19.15's "less than 1 and
    // greater than 20 are invalid" makes 1 and 20 themselves legal, so both
    // comparisons must be strict at those values.
    //
    // Both directions in one test, because the write-side range check has exactly
    // the same two boundaries and the same two mutations: the frame is read from
    // hand-built bytes and then written back, and the bytes must match.
    //
    // Mutation checks (performed and reverted), measured: changing
    // MinimumConnectionIdLength to 2 - fails two, this test's 1 row and
    // NewConnectionIdWhoseRetirePriorToEqualsItsSequenceNumberIsAccepted, which
    // also carries a one-byte connection ID; changing MaximumConnectionIdLength to
    // 19 - fails this test's 20 row alone.
    [Theory]
    [InlineData(1)]
    [InlineData(20)]
    public void NewConnectionIdAtBothEndsOfTheLengthRangeIsAccepted(int connectionIdLength)
    {
        var connectionId = new byte[connectionIdLength];
        Array.Fill(connectionId, (byte)0x5a);
        byte[] encoded =
            [0x18, 0x07, 0x03, (byte)connectionIdLength, .. connectionId, .. StatelessResetTokenBytes];
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal<byte>(connectionId, frame.ConnectionId.ToArray());
        Assert.Equal<byte>(StatelessResetTokenBytes, frame.StatelessResetToken.ToArray());

        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, frame);
        Assert.Equal(encoded, destination);
    }

    // The two fixed-width fields, truncated. Three rows, and the third exists
    // because writing this test with the obvious two left a real hole:
    //
    //   18 07 03 04 de ad be                      declares 4 cid bytes, has 3
    //   18 07 03 04 de ad be ef <15 token bytes>  token one byte short
    //   18 07 03 14 <16 bytes>                    declares 20 cid bytes, has 16
    //
    // The second row pins the token's width on the read side: 15 bytes is a frame
    // that a reader expecting any smaller token would accept.
    //
    // THE THIRD ROW IS WHAT WITNESSES THE CONNECTION ID'S OWN REJECTION, and the
    // first row is not. TryTakeFixed reports rather than throwing and leaves
    // `walked` untouched on failure, so dropping the first call's `!` - accepting
    // an empty connection ID and continuing - still rejects the first row: only 3
    // bytes remain and the token needs 16. It does NOT reject the third, where 16
    // bytes remain and the mutant hands them to the token, producing a frame with
    // an EMPTY connection ID and a token made of what was meant to be the
    // connection ID. That is a frame this reader must not accept, and the
    // two-obvious-rows version of this test accepted it.
    //
    // Mutation checks (performed and reverted), measured: dropping TryTakeFixed's
    // own bounds check, so it always slices - fails seven, all three rows here with
    // ArgumentOutOfRangeException plus all four of
    // PathFrameWithFewerThanEightDataBytesIsRejected; dropping the first call's
    // rejection in TryReadNewConnectionId - fails row three and nothing else;
    // dropping the second call's - fails three; changing StatelessResetTokenLength
    // to 15 - fails eight, row two by accepting it and the byte vectors above by
    // shortening the frame.
    [Theory]
    [InlineData(new byte[] { 0x18, 0x07, 0x03, 0x04, 0xde, 0xad, 0xbe })]
    [InlineData(new byte[]
    {
        0x18, 0x07, 0x03, 0x04, 0xde, 0xad, 0xbe, 0xef,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    })]
    [InlineData(new byte[]
    {
        0x18, 0x07, 0x03, 0x14,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    })]
    public void NewConnectionIdTruncatedInItsConnectionIdOrTokenIsRejected(byte[] encoded)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    [Fact]
    public void RetireConnectionIdTruncatedInItsFieldIsRejected()
    {
        byte[] encoded = [0x19, TruncatedVarintPrefix];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // THE FIXED-WIDTH FIELD, rejecting side. s19.17: "This 8-byte field contains
    // arbitrary data", and Figure 41 spells it "Data (64)" - no Length in front of
    // it, so a frame with fewer than eight bytes left is malformed rather than
    // short.
    //
    // Four rows: two type values crossed with two magnitudes, empty and one byte
    // short. The empty row is not redundant - it is the degenerate case the plan's
    // "enumerate reachable paths, not reachable flag paths" rule is about, where a
    // check conditioned on there being any data at all would still pass.
    //
    // Mutation checks (performed and reverted): deleting the TryTakeFixed rejection
    // - fails all four rows with ArgumentOutOfRangeException out of Memory.Slice;
    // conditioning it on rawType == 0x1a - fails the two 0x1b rows, and vice versa;
    // changing PathDataLength to 7 - fails the two 7-byte rows by accepting them.
    [Theory]
    [InlineData(new byte[] { 0x1a })]
    [InlineData(new byte[] { 0x1a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 })]
    [InlineData(new byte[] { 0x1b })]
    [InlineData(new byte[] { 0x1b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 })]
    public void PathFrameWithFewerThanEightDataBytesIsRejected(byte[] encoded)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // The other half of "exactly eight": the check is "at least eight", so a
    // payload with more bytes behind the frame must leave them for the next frame
    // rather than swallowing them. s12.4 makes a payload "a sequence of complete
    // frames", and TlsQuicFrames' read loop runs until offset == payload.Length, so
    // a reader that ran to the end here would silently eat every following frame -
    // the trap TlsQuicStreamFrames documents for the LEN-less STREAM form, which
    // for a path frame would be a defect rather than a wire form.
    //
    // A PING (0x01) follows, chosen because it is one byte and unambiguous.
    //
    // Mutation check (performed and reverted), measured: taking
    // `payload.Length - walked` instead of PathDataLength in TryReadPathData -
    // fails six, these two rows on the offset and on the second frame never being
    // read, plus all four rows of PathFrameWithFewerThanEightDataBytesIsRejected,
    // which a length-of-whatever-remains reader accepts.
    [Theory]
    [InlineData(0x1aUL)]
    [InlineData(0x1bUL)]
    public void PathFrameConsumesExactlyEightBytesAndNoMore(ulong rawType)
    {
        byte[] payload = [(byte)rawType, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01];
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out _));
        Assert.Equal(9, offset);
        Assert.Equal<byte>(PathDataBytes, frame.Data.ToArray());

        Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var next, out _));
        Assert.Equal(payload.Length, offset);
        Assert.Equal((ulong)0x01, next.RawType);
    }

    // FIVE ROWS FOR ONE CATCH, not three: s19.19's transport form has three fields
    // to be truncated in and its application form has two, and the Frame Type read
    // exists on only one of the two forms. This is the plan's "a guard reachable by
    // more than one path needs a witness per path" applied to a form axis rather
    // than a flag axis.
    //
    //   1c 40              Error Code truncated, transport form
    //   1c 07 40           Frame Type truncated
    //   1c 07 08 40        Reason Phrase Length truncated
    //   1d 40              Error Code truncated, application form
    //   1d 07 40           Reason Phrase Length truncated (no Frame Type here)
    //
    // The fourth and fifth rows are what a suite written around the transport form
    // alone would omit, and they are the ones that fail if the `error` assignment
    // is conditioned on !IsApplicationError.
    //
    // Mutation checks (performed and reverted), measured: changing the caught type
    // so the exception escapes - fails all five; narrowing the catch to failures
    // that walked nothing, which is the try covering only the Error Code read -
    // fails the three rows truncated in a later field; conditioning the catch on
    // IsApplicationError - fails the three 0x1c rows, and on its negation the two
    // 0x1d rows.
    [Theory]
    [InlineData(new byte[] { 0x1c, TruncatedVarintPrefix })]
    [InlineData(new byte[] { 0x1c, 0x07, TruncatedVarintPrefix })]
    [InlineData(new byte[] { 0x1c, 0x07, 0x08, TruncatedVarintPrefix })]
    [InlineData(new byte[] { 0x1d, TruncatedVarintPrefix })]
    [InlineData(new byte[] { 0x1d, 0x07, TruncatedVarintPrefix })]
    public void ConnectionCloseTruncatedInAnyFieldIsRejected(byte[] encoded)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // A Reason Phrase Length of 5 with one byte behind it, in both forms - the
    // extent check is reachable from each, so it carries a row for each.
    //
    // Mutation checks (performed and reverted), measured: deleting the check -
    // fails three, both rows with ArgumentOutOfRangeException out of Memory.Slice
    // plus TryReadConnectionCloseCommitsNothingWhenItsReasonPhraseOverruns;
    // conditioning it on IsApplicationError - fails the 0x1c row and that same
    // test, and on its negation the 0x1d row alone.
    [Theory]
    [InlineData(new byte[] { 0x1c, 0x07, 0x08, 0x05, 0x62 })]
    [InlineData(new byte[] { 0x1d, 0x07, 0x05, 0x62 })]
    public void ConnectionCloseWhoseReasonPhraseLengthOverrunsThePayloadIsRejected(byte[] encoded)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // s19.19, Reason Phrase: "This can be zero length if the sender chooses not to
    // give details beyond the Error Code value." So unlike NEW_TOKEN's Token there
    // is no lower bound, and the zero-length case is a legal wire form in both
    // directions and both forms.
    //
    // Four assertions' worth in one test, deliberately: the bytes a zero-length
    // phrase writes, that they parse back, that the phrase is empty rather than
    // absent-and-null, and that `offset` lands on the length byte + 1 rather than
    // running to the end of the payload.
    //
    // Mutation checks (performed and reverted): deleting the
    // `if (!IsApplicationError(...))` guard around the Frame Type Write - fails the
    // 0x1d row; deleting it in the reader - fails the 0x1d row on the parse.
    [Theory]
    [InlineData(0x1cUL, TriggerFrameTypeValue, new byte[] { 0x1c, 0x07, 0x08, 0x00 })]
    [InlineData(0x1dUL, 0UL, new byte[] { 0x1d, 0x07, 0x00 })]
    public void ConnectionCloseWithAnEmptyReasonPhraseRoundTrips(
        ulong rawType, ulong triggerFrameType, byte[] expected)
    {
        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            ErrorCode = ErrorCodeValue,
            TriggerFrameType = triggerFrameType,
        };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);
        Assert.Equal(expected, destination);

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(expected, ref offset, out var read, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(expected.Length, offset);
        Assert.Equal(rawType, read.RawType);
        Assert.Equal(ErrorCodeValue, read.ErrorCode);
        Assert.Equal(triggerFrameType, read.TriggerFrameType);
        Assert.True(read.ReasonPhrase.IsEmpty);
    }

    // s16 leaves a variable-length integer 62 value bits, so a field of 2^62 has no
    // encoding. Checked in the writer before the frame type is written, so the
    // rejection cannot leave a partial frame behind - `destination` is seeded with a
    // sentinel byte and asserted to be still alone, which is the half of these
    // tests that catches a bound moved below the writes. Asserting only the
    // exception type would not: the encoder's own throw is also an ArgumentException
    // subclass.
    //
    // THREE ROWS, ONE PER FIELD, each with the other two left legal so that exactly
    // one RequireEncodableVarint call can fire. All three raise the same exception
    // type on the same kind of value, so the ParamName assertion is what
    // distinguishes them - with "streamId" asserted on every row, deleting the
    // second or third call would still pass. The names are string literals in
    // TlsQuicConnectionFrames.RequireEncodableVarint rather than nameof()-derived,
    // so renaming the TlsQuicFrame properties will not update them and these
    // assertions will not fail if they go stale.
    //
    // Mutation checks (performed and reverted), each failing exactly its own row:
    // deleting any one of the three calls - fails that field's row with
    // ArgumentOutOfRangeException (a different exact type, naming a parameter
    // "value" this namespace does not have) and with bytes already in the
    // destination.
    [Theory]
    [InlineData("streamId", VarintMaximum + 1, 0UL, 0UL)]
    [InlineData("applicationProtocolErrorCode", 0UL, VarintMaximum + 1, 0UL)]
    [InlineData("finalSize", 0UL, 0UL, VarintMaximum + 1)]
    public void WritingAResetStreamFrameWhoseFieldsExceedTheVarintMaximumThrows(
        string expectedParamName, ulong streamId, ulong applicationProtocolErrorCode, ulong finalSize)
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x04,
            StreamId = streamId,
            ApplicationProtocolErrorCode = applicationProtocolErrorCode,
            FinalSize = finalSize,
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal(expectedParamName, exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The same for s19.5's two fields, and a second witness that the two writers
    // are not interchangeable: a STOP_SENDING frame carrying an unencodable Final
    // Size is NOT rejected, because s19.5 has no such field - see
    // WritingAStopSendingFrameIgnoresTheFinalSizeItHasNoFieldFor below.
    [Theory]
    [InlineData("streamId", VarintMaximum + 1, 0UL)]
    [InlineData("applicationProtocolErrorCode", 0UL, VarintMaximum + 1)]
    public void WritingAStopSendingFrameWhoseFieldsExceedTheVarintMaximumThrows(
        string expectedParamName, ulong streamId, ulong applicationProtocolErrorCode)
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x05,
            StreamId = streamId,
            ApplicationProtocolErrorCode = applicationProtocolErrorCode,
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal(expectedParamName, exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The consequence of TlsQuicFrame being one struct for twenty frame types,
    // recorded rather than defended: a caller that sets FinalSize on a STOP_SENDING
    // frame has asked for something s19.5's figure cannot express, and this library
    // drops it silently. That is the same relationship STREAM already has to ACK -
    // nothing stops a caller setting AckDelay on a STREAM frame either - and
    // TlsQuicFrames' own comment explains why a struct in which every frame type
    // checked every other type's fields is not the trade this design makes.
    //
    // Pinned so the behaviour is a documented choice rather than an accident, and
    // so a future writer that started validating it fails here deliberately rather
    // than surprising a caller: this test would go red, and the right response
    // would be to change it.
    [Fact]
    public void WritingAStopSendingFrameIgnoresTheFinalSizeItHasNoFieldFor()
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x05,
            StreamId = StreamIdValue,
            ApplicationProtocolErrorCode = ApplicationProtocolErrorCodeValue,
            FinalSize = VarintMaximum + 1,
        };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal<byte>([0x05, 0x09, 0x0b], destination);
    }

    // The write-side half of s19.7's "The token MUST NOT be empty", which binds the
    // sender directly rather than by way of the receiver's connection error.
    //
    // Mutation check (performed and reverted): deleting the check - this test fails
    // because nothing throws at all; the writer emits a two-byte frame, `07 00`,
    // which is precisely the input NewTokenWithAnEmptyTokenIsRejected proves a peer
    // must close the connection over. The sentinel assertion is not what catches
    // this one; the missing exception is.
    [Fact]
    public void WritingANewTokenFrameWithAnEmptyTokenThrows()
    {
        var frame = new TlsQuicFrame { RawType = 0x07, Token = ReadOnlyMemory<byte>.Empty };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("frame", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    [Fact]
    public void WritingANewConnectionIdFrameWhoseSequenceNumberExceedsTheVarintMaximumThrows()
    {
        // Retire Prior To is left at 0 so the ordering check below it cannot also
        // fire: with both at 2^62 the ordering check would pass and this one would
        // still be the rejection, but with only one call able to fire the ParamName
        // assertion identifies which check ran.
        var frame = new TlsQuicFrame
        {
            RawType = 0x18,
            SequenceNumber = VarintMaximum + 1,
            RetirePriorTo = 0,
            ConnectionId = ConnectionIdBytes,
            StatelessResetToken = StatelessResetTokenBytes,
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("sequenceNumber", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The write-side half of s19.15's ordering constraint, where both fields are
    // caller-supplied and bounded by nothing - the plan's rule that a write-side
    // bound on a caller-supplied value is always reachable.
    //
    // TWO ROWS, TWO MAGNITUDES, and the second is not redundant. At Sequence Number
    // 7 and Retire Prior To 8 both values are perfectly encodable varints, so
    // deleting the check makes the frame write successfully and nothing throws at
    // all. At 2^62 - 1 and 2^62 the Retire Prior To is unencodable, so deleting the
    // check makes QuicVariableLengthInteger.Write throw
    // ArgumentOutOfRangeException *after* the type byte and the sequence number are
    // in the destination - a different failure that only the exact-type match and
    // the sentinel can catch.
    //
    // The second row is also what stands in for the RequireEncodableVarint call
    // this writer deliberately does not make for Retire Prior To: the sequence
    // number bound plus this check leave Retire Prior To <= 2^62 - 1 by
    // transitivity, so such a call would be dead code after this check and a pure
    // ParamName change before it - never a rejection this check does not already
    // make.
    //
    // Mutation checks (performed and reverted): deleting the check - fails both
    // rows, for the two different reasons above; adding a
    // RequireEncodableVarint(frame.RetirePriorTo, ...) call before it - fails this
    // test's second row on ParamName alone, which is what "shadowed rather than
    // needed" looks like from the outside.
    [Theory]
    [InlineData(7UL, 8UL)]
    [InlineData(VarintMaximum, VarintMaximum + 1)]
    public void WritingANewConnectionIdFrameWhoseRetirePriorToExceedsItsSequenceNumberThrows(
        ulong sequenceNumber, ulong retirePriorTo)
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x18,
            SequenceNumber = sequenceNumber,
            RetirePriorTo = retirePriorTo,
            ConnectionId = ConnectionIdBytes,
            StatelessResetToken = StatelessResetTokenBytes,
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("frame", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The accepting side: s19.15 says "less than or equal to", so equality is legal
    // and the write-side comparison must be strict. Asserted against hand-derived
    // bytes rather than just "did not throw", so the encoding is checked too.
    //
    // Mutation check (performed and reverted): weakening the comparison in
    // WriteNewConnectionIdFrameFields to >= - fails this test and nothing else in
    // the Quic suite.
    [Fact]
    public void WritingANewConnectionIdFrameWhoseRetirePriorToEqualsItsSequenceNumberSucceeds()
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x18,
            SequenceNumber = SequenceNumberValue,
            RetirePriorTo = SequenceNumberValue,
            ConnectionId = ConnectionIdBytes,
            StatelessResetToken = StatelessResetTokenBytes,
        };
        List<byte> destination = [];

        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal<byte>(
            [0x18, 0x07, 0x07, 0x04, 0xde, 0xad, 0xbe, 0xef, .. StatelessResetTokenBytes],
            destination);
    }

    // The write-side half of s19.15's connection ID length range, at both ends:
    // empty and 21 bytes. Two paths through one check, the same non-flag axis the
    // read-side twin has.
    //
    // Mutation checks (performed and reverted): deleting the check - fails both
    // rows, since nothing throws and the writer emits a length byte of 0x00 or 0x15;
    // dropping the `< MinimumConnectionIdLength` half - fails the empty row;
    // dropping the `> MaximumConnectionIdLength` half - fails the 21 row.
    [Theory]
    [InlineData(0)]
    [InlineData(21)]
    public void WritingANewConnectionIdFrameWithAnOutOfRangeConnectionIdLengthThrows(
        int connectionIdLength)
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x18,
            SequenceNumber = SequenceNumberValue,
            RetirePriorTo = RetirePriorToValue,
            ConnectionId = new byte[connectionIdLength],
            StatelessResetToken = StatelessResetTokenBytes,
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("frame", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The stateless reset token has no length field on the wire, so a token of the
    // wrong size cannot be encoded - it would silently shift every byte after it,
    // except that nothing follows it, so it would silently truncate or extend the
    // frame instead. Exact equality, not a range: s19.15 Figure 39 fixes the width
    // at 128 bits.
    //
    // Three rows - empty, one short, one long - because the check is an equality
    // and each side of it needs a witness, with the empty case separate for the
    // reason the plan's "enumerate reachable paths" rule gives.
    //
    // Mutation checks (performed and reverted): deleting the check - fails all
    // three; weakening it to `<` - fails the 17-byte row; to `>` - fails the empty
    // and 15-byte rows.
    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    public void WritingANewConnectionIdFrameWithAWrongLengthStatelessResetTokenThrows(int tokenLength)
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x18,
            SequenceNumber = SequenceNumberValue,
            RetirePriorTo = RetirePriorToValue,
            ConnectionId = ConnectionIdBytes,
            StatelessResetToken = new byte[tokenLength],
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("frame", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    [Fact]
    public void WritingARetireConnectionIdFrameAboveTheVarintMaximumThrows()
    {
        var frame = new TlsQuicFrame { RawType = 0x19, SequenceNumber = VarintMaximum + 1 };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("sequenceNumber", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The write-side half of the fixed-width field. Exact equality in both
    // directions: a short Data would be followed by whatever the caller appends
    // next, and a long one would leave trailing bytes the peer reads as another
    // frame, so neither is representable.
    //
    // SIX ROWS: two type values crossed with three lengths - empty, one short, one
    // long. The type axis is the plan's multi-path rule; the length axis carries
    // the two directions of the equality plus the degenerate empty case.
    //
    // Mutation checks (performed and reverted): deleting the check - fails all six,
    // since nothing throws; weakening it to `<` - fails the two 9-byte rows; to `>`
    // - fails the four shorter ones; conditioning it on frame.RawType == 0x1a -
    // fails the three 0x1b rows, and vice versa.
    [Theory]
    [InlineData(0x1aUL, 0)]
    [InlineData(0x1aUL, 7)]
    [InlineData(0x1aUL, 9)]
    [InlineData(0x1bUL, 0)]
    [InlineData(0x1bUL, 7)]
    [InlineData(0x1bUL, 9)]
    public void WritingAPathFrameWithoutExactlyEightDataBytesThrows(ulong rawType, int dataLength)
    {
        var frame = new TlsQuicFrame { RawType = rawType, Data = new byte[dataLength] };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("frame", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The Error Code bound, REACHABLE FROM BOTH FORMS - s19.19 gives 0x1c and 0x1d
    // an Error Code each, from different code spaces but with the same 62-bit
    // encoding - so two rows.
    //
    // Mutation checks (performed and reverted): deleting the
    // RequireEncodableVarint call - fails both rows with
    // ArgumentOutOfRangeException and the type byte already written; conditioning it
    // on IsApplicationError(frame.RawType) - fails the 0x1c row alone, and on its
    // negation the 0x1d row. That pair is the two-form mutation the plan's rule
    // asks for, and a single-row test would have let both survive.
    [Theory]
    [InlineData(0x1cUL)]
    [InlineData(0x1dUL)]
    public void WritingAConnectionCloseFrameWhoseErrorCodeExceedsTheVarintMaximumThrows(ulong rawType)
    {
        var frame = new TlsQuicFrame { RawType = rawType, ErrorCode = VarintMaximum + 1 };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("errorCode", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The Frame Type bound, and the one guard in this family that is CHECKED AND
    // SINGLE-PATH: only the transport form has the field, so only 0x1c can reach
    // the call. Recorded here rather than left implicit, so a reader can tell it
    // from the guards above that carry a row per form.
    //
    // Mutation check (performed and reverted): deleting the call - fails this test
    // with ArgumentOutOfRangeException and with the type byte and the error code
    // byte already in the destination, which the sentinel assertion catches.
    [Fact]
    public void WritingAConnectionCloseFrameWhoseTriggerFrameTypeExceedsTheVarintMaximumThrows()
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x1c,
            ErrorCode = ErrorCodeValue,
            TriggerFrameType = VarintMaximum + 1,
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("triggerFrameType", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // s19.19: "The application-specific variant of CONNECTION_CLOSE (type 0x1d)
    // does not include this field." There is nowhere to put a triggering frame type
    // in that form, so a caller that set one asked for something the frame cannot
    // express and writing anyway would drop it silently. Same defect class as
    // TlsQuicStreamFrames' rejection of a CRYPTO frame carrying a stream ID.
    //
    // The value used is 0x08 - a perfectly legal frame type - so it is the form and
    // not the magnitude that rejects this, which is what separates this test from
    // the varint-maximum one above.
    //
    // Not the converse: a 0x1c frame leaving TriggerFrameType at 0 is legal, since
    // s19.19 assigns 0 the meaning "the frame type is unknown", and that case is a
    // passing row of ConnectionCloseWithAnEmptyReasonPhraseRoundTrips rather than a
    // rejection here.
    //
    // Mutation check (performed and reverted): deleting the check - this test fails
    // because nothing throws; the writer emits a valid-looking 0x1d frame with the
    // field silently dropped.
    [Fact]
    public void WritingAnApplicationConnectionCloseCarryingATriggerFrameTypeThrows()
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x1d,
            ErrorCode = ErrorCodeValue,
            TriggerFrameType = TriggerFrameTypeValue,
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("frame", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // s19.19: "The CONNECTION_CLOSE frame with a type of 0x1c is used to signal
    // errors at only the QUIC layer, or the absence of errors (with the NO_ERROR
    // code). The CONNECTION_CLOSE frame with a type of 0x1d is used to signal an
    // error with the application that uses QUIC."
    //
    // Unlike this namespace's other two type-bit predicates, both directions of
    // TlsQuicConnectionFrames branch on this one, so it is pinned by every
    // CONNECTION_CLOSE test above as well as directly here. Both values, so a
    // mutation that read the wrong bit or inverted the sense cannot pass on a
    // subset.
    //
    // Mutation checks (performed and reverted), measured: masking with 0x04
    // instead of ApplicationErrorBit - fails five, this test's 0x1c row among them,
    // since 0x1c is 0b11100 and would be read as an application close while the
    // 0x1d row alone could not catch it; inverting the comparison to == 0 - fails
    // ten, both rows here and every CONNECTION_CLOSE test that depends on the form.
    //
    // A third mutation is worth recording because it CANNOT be run: changing the
    // ApplicationErrorBit constant itself to 0x04 does not compile. 0x1c already
    // has that bit, so `ConnectionClose | ApplicationErrorBit` collapses onto the
    // bare ConnectionClose label in TlsQuicFrames.TryReadFrame's switch and the
    // compiler rejects the duplicate case (CS0152) - the exact failure the A2
    // plan's task 5 note warns about, confirmed here rather than taken on trust.
    // The constant's value is therefore pinned by the read dispatch's spelling as
    // well as by this theory.
    [Theory]
    [InlineData(0x1cUL, false)]
    [InlineData(0x1dUL, true)]
    public void IsApplicationErrorReadsTheFormFromTheRawType(ulong rawType, bool expected)
    {
        Assert.Equal(expected, TlsQuicConnectionFrames.IsApplicationError(rawType));
    }

    // THE READERS' OWN Try-SHAPED CONTRACT - "`offset` only advances on success" -
    // called directly rather than through TlsQuicFrames.TryReadFrame, which is the
    // only production caller. TryReadFrame publishes its `offset` only on success,
    // so a family reader that advanced its caller's cursor on the way out would be
    // invisible from outside; the promise has to be pinned by a second caller, and
    // a test is allowed to be one because these readers are already `internal` for
    // the dispatch switch. The pattern is A2 task 3b's, at
    // TlsQuicStreamFramesTests.TryReadStreamCommitsNothingWhenTheOffsetBoundRejects.
    //
    // `offset` starts at 1, past the frame type, because that is where TryReadFrame
    // leaves it - and a nonzero start is what makes "exactly as passed in"
    // distinguishable from "reset to zero".
    //
    // FIVE TESTS FOR SEVEN READERS, and the two omissions are deliberate rather
    // than gaps. Every rejection has to walk some bytes before it fires for an early
    // commit to be observable at all, and two readers have none that do:
    //
    //   * TryReadRetireConnectionId's only rejection is its single varint field
    //     truncating, and QuicVariableLengthInteger.Read advances the offset it is
    //     given as its last statement after both bounds checks, so on a throw
    //     nothing has moved and `walked` still equals the entry offset.
    //   * TryReadPathData's only rejection is its first and only field being short,
    //     which fires before TryTakeFixed advances anything at all.
    //
    // In both, `offset = walked` in the failing branch would be a no-op for every
    // input, so a test written for that mutation would pass against the mutated code
    // - a false witness, which is worse than no test. Both hold by construction, and
    // both stop holding the moment their reader gains a second field.
    [Fact]
    public void TryReadResetStreamCommitsNothingWhenItsLastFieldIsTruncated()
    {
        // Type 0x04, Stream ID 4, Application Protocol Error Code 11, then a
        // two-byte varint prefix with its second byte missing. The first two fields
        // are read successfully, so `walked` is 3 when the catch fires and an early
        // commit would show as offset 3.
        //
        // Mutation check (performed and reverted): adding `offset = walked;` before
        // the `return false;` in TryReadResetStream's catch fails this test and
        // nothing else in the Quic suite.
        byte[] payload = [0x04, 0x09, 0x0b, TruncatedVarintPrefix];
        var offset = 1;

        Assert.False(TlsQuicConnectionFrames.TryReadResetStream(
            payload, ref offset, out var frame, out var error));
        Assert.Equal(1, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(default, frame.StreamId);
        Assert.Equal(default, frame.FinalSize);
    }

    [Fact]
    public void TryReadStopSendingCommitsNothingWhenItsSecondFieldIsTruncated()
    {
        // `walked` is 2 when the catch fires.
        //
        // Mutation check (performed and reverted): adding `offset = walked;` before
        // the `return false;` in TryReadStopSending's catch fails this test and
        // nothing else in the Quic suite.
        byte[] payload = [0x05, 0x09, TruncatedVarintPrefix];
        var offset = 1;

        Assert.False(TlsQuicConnectionFrames.TryReadStopSending(
            payload, ref offset, out var frame, out var error));
        Assert.Equal(1, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(default, frame.ApplicationProtocolErrorCode);
    }

    [Fact]
    public void TryReadNewTokenCommitsNothingWhenTheTokenIsEmpty()
    {
        // The Token Length is read successfully, so `walked` is 2 when the
        // zero-length rejection fires. The catch above it is one of the vacuous
        // cases described on the first of these tests, which is why the s19.7 rule
        // and not a truncation is what this pins.
        //
        // Mutation check (performed and reverted): adding `offset = walked;` before
        // the `return false;` in TryReadNewToken's zero-length branch fails this
        // test and nothing else in the Quic suite.
        byte[] payload = [0x07, 0x00];
        var offset = 1;

        Assert.False(TlsQuicConnectionFrames.TryReadNewToken(
            payload, ref offset, out var frame, out var error));
        Assert.Equal(1, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Equal(default, frame.RawType);
        Assert.True(frame.Token.IsEmpty);
    }

    [Fact]
    public void TryReadNewConnectionIdCommitsNothingWhenTheLengthIsOutOfRange()
    {
        // Sequence Number, Retire Prior To and the Length byte are all consumed, so
        // `walked` is 4 when the range check fires - the deepest rejection in this
        // file and so the most for an early commit to expose.
        //
        // Mutation check (performed and reverted): adding `offset = walked;` before
        // the `return false;` in TryReadNewConnectionId's range check fails this
        // test and nothing else in the Quic suite.
        byte[] payload = [0x18, 0x07, 0x03, 0x00, .. StatelessResetTokenBytes];
        var offset = 1;

        Assert.False(TlsQuicConnectionFrames.TryReadNewConnectionId(
            payload, ref offset, out var frame, out var error));
        Assert.Equal(1, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(default, frame.SequenceNumber);
        Assert.True(frame.ConnectionId.IsEmpty);
    }

    [Fact]
    public void TryReadConnectionCloseCommitsNothingWhenItsReasonPhraseOverruns()
    {
        // All three of the transport form's fields are read successfully, so
        // `walked` is 4 when the extent check fires.
        //
        // Mutation check (performed and reverted): adding `offset = walked;` before
        // the `return false;` in TryReadConnectionClose's extent check fails this
        // test and nothing else in the Quic suite.
        byte[] payload = [0x1c, 0x07, 0x08, 0x05, 0x62];
        var offset = 1;

        Assert.False(TlsQuicConnectionFrames.TryReadConnectionClose(
            payload, ref offset, 0x1c, out var frame, out var error));
        Assert.Equal(1, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(default, frame.ErrorCode);
        Assert.True(frame.ReasonPhrase.IsEmpty);
    }
}
