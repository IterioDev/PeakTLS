using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicFramesTests
{
    // Hand-derived from RFC 9000 s19.1 Figure 23: "a PADDING frame consists
    // of the single byte that identifies the frame as a PADDING frame."
    [Fact]
    public void PaddingFrameEncodesAsSingleZeroByte()
    {
        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Padding });

        Assert.Equal<byte>([0x00], destination);
    }

    // Hand-derived from RFC 9000 s19.2 Figure 24: PING has no content beyond
    // its type=0x01.
    [Fact]
    public void PingFrameEncodesAsSingleByteWithValueOne()
    {
        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping });

        Assert.Equal<byte>([0x01], destination);
    }

    // Hand-derived from RFC 9000 s19.20: HANDSHAKE_DONE has no content
    // beyond its type=0x1e (Table 3, s12.4).
    [Fact]
    public void HandshakeDoneFrameEncodesAsSingleByteWithValueOx1e()
    {
        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.HandshakeDone });

        Assert.Equal<byte>([0x1e], destination);
    }

    // A default-constructed TlsQuicFrame has RawType 0x00, and RFC 9000 s19.1
    // makes 0x00 a PADDING frame - so `default` is a valid frame, not a
    // sentinel, and the derived Type must say so. TryReadFrame relies on this:
    // it assigns `frame = default` before parsing.
    [Fact]
    public void DefaultConstructedFrameIsPadding()
    {
        var frame = default(TlsQuicFrame);

        Assert.Equal(0UL, frame.RawType);
        Assert.Equal(TlsQuicFrameType.Padding, frame.Type);
    }

    // Pins finding 4's single-source-of-truth invariant: Type is derived from
    // RawType, never set beside it, so the two cannot disagree. Expected
    // values are hand-derived from RFC 9000 s12.4 Table 3 and the ranges the
    // s12.4 sentence "The Frame Type in ACK, STREAM, MAX_STREAMS,
    // STREAMS_BLOCKED, and CONNECTION_CLOSE frames is used to carry other
    // frame-specific flags" creates:
    //   ACK              0x02-0x03 (s19.3, ECN bit)          -> 0x02
    //   STREAM           0x08-0x0f (s19.8, OFF/LEN/FIN bits) -> 0x08
    //   MAX_STREAMS      0x12-0x13 (s19.11, direction)       -> 0x12
    //   STREAMS_BLOCKED  0x16-0x17 (s19.14, direction)       -> 0x16
    //   CONNECTION_CLOSE 0x1c-0x1d (s19.19, transport/app)   -> 0x1c
    // Every other value is its own base - "For all other frames, the Frame
    // Type field simply identifies the frame."
    [Theory]
    [InlineData(0x00UL, (ulong)TlsQuicFrameType.Padding)]
    [InlineData(0x01UL, (ulong)TlsQuicFrameType.Ping)]
    [InlineData(0x02UL, (ulong)TlsQuicFrameType.Ack)]
    [InlineData(0x03UL, (ulong)TlsQuicFrameType.Ack)]
    [InlineData(0x04UL, (ulong)TlsQuicFrameType.ResetStream)]
    [InlineData(0x06UL, (ulong)TlsQuicFrameType.Crypto)]
    [InlineData(0x08UL, (ulong)TlsQuicFrameType.Stream)]
    [InlineData(0x0bUL, (ulong)TlsQuicFrameType.Stream)]
    [InlineData(0x0fUL, (ulong)TlsQuicFrameType.Stream)]
    [InlineData(0x10UL, (ulong)TlsQuicFrameType.MaxData)]
    [InlineData(0x11UL, (ulong)TlsQuicFrameType.MaxStreamData)]
    [InlineData(0x12UL, (ulong)TlsQuicFrameType.MaxStreams)]
    [InlineData(0x13UL, (ulong)TlsQuicFrameType.MaxStreams)]
    [InlineData(0x16UL, (ulong)TlsQuicFrameType.StreamsBlocked)]
    [InlineData(0x17UL, (ulong)TlsQuicFrameType.StreamsBlocked)]
    [InlineData(0x1cUL, (ulong)TlsQuicFrameType.ConnectionClose)]
    [InlineData(0x1dUL, (ulong)TlsQuicFrameType.ConnectionClose)]
    [InlineData(0x1eUL, (ulong)TlsQuicFrameType.HandshakeDone)]
    [InlineData(0x1fUL, 0x1fUL)]

    // Task C17's sixth range, and the only one not from Table 3:
    //   DATAGRAM         0x30-0x31 (RFC 9221 s4, LEN bit)     -> 0x30
    // 0x2f and 0x32 bracket it and must each be their own base. They are the rows
    // that fail a range slipped one value in either direction; without them an arm
    // written `>= 0x2f` or `<= 0x32` passes, since neither value is otherwise asked
    // about anywhere in this file.
    [InlineData(0x2fUL, 0x2fUL)]
    [InlineData(0x30UL, (ulong)TlsQuicFrameType.Datagram)]
    [InlineData(0x31UL, (ulong)TlsQuicFrameType.Datagram)]
    [InlineData(0x32UL, 0x32UL)]
    public void DerivedTypeAlwaysAgreesWithExactRawType(ulong rawType, ulong expectedBase)
    {
        var frame = new TlsQuicFrame { RawType = rawType };

        Assert.Equal((TlsQuicFrameType)expectedBase, frame.Type);

        // The exact value survives the derivation untouched - masking is
        // Type's business only.
        Assert.Equal(rawType, frame.RawType);

        // A base type is a fixed point of the derivation: feed a base back in
        // and it maps to itself. This is what makes "mask down to the base"
        // well defined for a caller that switches on Type and then wants the
        // canonical value.
        Assert.Equal(frame.Type, new TlsQuicFrame { RawType = expectedBase }.Type);
    }

    // InlineData carries the raw ulong value rather than TlsQuicFrameType
    // itself: that enum is internal, and a public [Theory] method may not
    // expose an internal type in its signature (CS0051), even within a
    // test assembly that can see internals via InternalsVisibleTo.
    [Theory]
    [InlineData((ulong)TlsQuicFrameType.Padding)]
    [InlineData((ulong)TlsQuicFrameType.Ping)]
    [InlineData((ulong)TlsQuicFrameType.HandshakeDone)]
    public void FieldLessFrameRoundTrips(ulong rawType)
    {
        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, new TlsQuicFrame { RawType = rawType });

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(destination.ToArray(), ref offset, out var frame, out var error));

        // The exact wire value round-trips, not just the base type.
        Assert.Equal(rawType, frame.RawType);
        Assert.Equal((TlsQuicFrameType)rawType, frame.Type);
        Assert.Equal(destination.Count, offset);
        Assert.Equal(TlsQuicTransportError.NoError, error);
    }

    // Proves the frame type field is read as a full variable-length integer
    // (RFC 9000 s16), not as a single byte, across every encoding width a
    // varint can take.
    //
    // The multi-byte rows are all over-long encodings, and s12.4 forbids
    // *sending* them: "a frame type MUST use the shortest possible encoding.
    // For frame types defined in this document, this means a single-byte
    // encoding, even though it is possible to encode these values as a two-,
    // four-, or eight-byte variable-length integer. For instance, though
    // 0x4001 is a legitimate two-byte encoding for a variable-length integer
    // with a value of 1, PING frames are always encoded as a single byte with
    // the value 0x01." That 0x4001 sentence is the RFC illustrating the
    // encoding a sender must NOT use - not an endorsement of it - and the row
    // below is here because of what the RFC says next, about receivers: "An
    // endpoint MAY treat the receipt of a frame type that uses a longer
    // encoding than necessary as a connection error of type
    // PROTOCOL_VIOLATION." MAY, not MUST. TryReadFrame declines that option
    // and resolves an over-long frame type by value (its comment gives the
    // reasoning), so these rows pin a deliberate choice, not a spec
    // requirement. A reader that only looked at byte 0 of row 3 would see
    // 0x40 and recognize nothing.
    //
    // The last two rows are both 8-byte varints of small values. The
    // all-zeros one only pins how many bytes were consumed; the 0x1e one also
    // pins that the value accumulated across the trailing bytes rather than
    // being read as zero.
    [Theory]
    [InlineData(new byte[] { 0x00 }, (ulong)TlsQuicFrameType.Padding, 1)]
    [InlineData(new byte[] { 0x01 }, (ulong)TlsQuicFrameType.Ping, 1)]
    [InlineData(new byte[] { 0x40, 0x01 }, (ulong)TlsQuicFrameType.Ping, 2)]
    [InlineData(new byte[] { 0x80, 0x00, 0x00, 0x1e }, (ulong)TlsQuicFrameType.HandshakeDone, 4)]
    [InlineData(new byte[] { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, (ulong)TlsQuicFrameType.Padding, 8)]
    [InlineData(new byte[] { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e }, (ulong)TlsQuicFrameType.HandshakeDone, 8)]
    public void FrameTypeIsReadAsVarintAtEveryEncodingWidth(byte[] encoded, ulong expectedRawType, int expectedConsumed)
    {
        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));

        Assert.Equal(expectedRawType, frame.RawType);
        Assert.Equal((TlsQuicFrameType)expectedRawType, frame.Type);
        Assert.Equal(expectedConsumed, offset);
        Assert.Equal(TlsQuicTransportError.NoError, error);
    }

    // The other half of the s12.4 shortest-encoding rule, the half that is a
    // MUST and binds this library: whatever width a frame type arrived in, the
    // writer emits it in the shortest one. RawType is the decoded *value*
    // (1, here), so the two-byte encoding it came from is not recoverable and
    // must not be - "PING frames are always encoded as a single byte with the
    // value 0x01".
    [Fact]
    public void FrameTypeReadFromAnOverLongEncodingIsWrittenBackInShortestForm()
    {
        byte[] overLongPing = [0x40, 0x01];
        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(overLongPing, ref offset, out var frame, out _));
        Assert.Equal(2, offset);
        Assert.Equal((ulong)TlsQuicFrameType.Ping, frame.RawType);

        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, frame);

        Assert.Equal<byte>([0x01], destination);
    }

    // RFC 9000 s12.4 Table 3 assigns every value from 0x00 to 0x1e; 0x1f is
    // the first value the table does not define anywhere, so it is a value
    // no future A2 task will ever legitimately claim. s12.4: "An endpoint
    // MUST treat the receipt of a frame of unknown type as a connection
    // error of type FRAME_ENCODING_ERROR" - this Try-shaped reader (no
    // connection to raise that error against) reports the code out-of-band
    // alongside a false return.
    [Fact]
    public void UnknownFrameTypeIsRejected()
    {
        byte[] encoded = [0x1f];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // The rejection the single-byte 0x1f case above cannot reach: a frame type
    // at or above 2^32 whose low 32 bits alias a type this reader accepts.
    //
    // Input and value both hand-derived from the RFC 9000 s16 varint rules -
    // the two most significant bits of the first byte are the log2 of the
    // encoded length in bytes, and the remaining 62 bits are the value:
    //
    //   0xc0 = 0b11_000000 -> 2MSB '11' = 3 -> 2^3 = 8 bytes total,
    //                         and the low 6 bits of byte 0 are value bits.
    //   value = (0x00 & 0x3f)                      -- byte 0's 6 value bits
    //           <<8 | 0x00 <<8 | 0x00 <<8 | 0x01    -- bytes 1..3
    //           <<8 | 0x00 <<8 | 0x00 <<8 | 0x00 <<8 | 0x1e   -- bytes 4..7
    //         = 0x00000001_0000001e
    //         = 1 * 2^32 + 0x1e
    //         = 4294967296 + 30
    //         = 4294967326
    //   value & 0xffffffff = 0x0000001e = 30 = HANDSHAKE_DONE (s12.4 Table 3)
    //
    // 4294967326 is a legal varint value (below the 2^62 - 1 maximum) and
    // Table 3 assigns nothing at or above 0x1f, so it is an unknown frame
    // type and s12.4's FRAME_ENCODING_ERROR MUST applies.
    //
    // Isolating one check: the input is a complete 8-byte varint, so the
    // truncation catch in TryReadFrame cannot fire; and 8 bytes is the
    // *shortest* encoding of 4294967326 (it exceeds the 4-byte ceiling of
    // 2^30 - 1 = 1073741823), so no shortest-encoding question arises either.
    // The switch's default arm is the only thing left that can reject it.
    //
    // Mutation check (performed and reverted): with the frame type read as
    // `QuicVariableLengthInteger.Read(payload, ref typeOffset) & 0xFFFFFFFF`,
    // this test fails - TryReadFrame returns true and reports HANDSHAKE_DONE -
    // while every other Quic test still passes. That is the surviving mutation
    // this test was added to kill.
    [Fact]
    public void FrameTypeAliasingAKnownTypeInItsLowThirtyTwoBitsIsRejected()
    {
        byte[] encoded = [0xc0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);

        // The value really is the aliasing one, read as a full varint: proving
        // the input is what the derivation above says keeps this test honest
        // about which mutation it kills.
        var typeOffset = 0;
        Assert.Equal(4294967326UL, QuicVariableLengthInteger.Read(encoded, ref typeOffset));
        Assert.Equal(8, typeOffset);
        Assert.Equal((ulong)TlsQuicFrameType.HandshakeDone, 4294967326UL & 0xFFFFFFFF);
    }

    // FrameTypeNotYetImplementedByThisTaskIsRejected stood here until A2 task 5,
    // and was deleted rather than re-pointed at another input. Its subject was "a
    // value s12.4 Table 3 assigns, reaching TryReadFrame's default arm because no
    // task had given it a case label yet" - the input moved from CRYPTO (0x06) to
    // RESET_STREAM (0x04) once task 3b landed, for exactly that reason. Task 5
    // implements every remaining Table 3 value, so there is no longer any such
    // input: the scenario is unrepresentable, not merely uncovered, which is the
    // A2 plan's "lost its subject" rather than "lost its coverage". The default
    // arm itself keeps both of its other witnesses, UnknownFrameTypeIsRejected
    // and FrameTypeAliasingAKnownTypeInItsLowThirtyTwoBitsIsRejected above.

    [Fact]
    public void EmptyBufferReturnsFalseRatherThanThrowing()
    {
        var offset = 0;
        Assert.False(TlsQuicFrames.TryReadFrame(ReadOnlyMemory<byte>.Empty, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // Mutation check target (see TlsQuicFrames.TryReadFrame's catch clause
    // for the full note). Input is exactly one byte, 0x40: the top two bits
    // ('01') declare a 2-byte varint, but the second byte never arrives.
    // Because the Read call throws before rawType is ever assigned, the
    // switch on rawType is unreachable for this input - only the catch
    // clause can be why TryReadFrame returns false here, so this input
    // isolates that one check the way the earlier-task bounds test in this
    // project's history failed to.
    //
    // Manually performed: deleted the `catch (TlsQuicTransportException)`
    // clause around the QuicVariableLengthInteger.Read call in
    // TlsQuicFrames.TryReadFrame (letting the exception propagate). Ran
    // this test: it failed with an unhandled TlsQuicTransportException
    // ("Truncated QUIC variable-length integer.") instead of the expected
    // false return - a real exception, not a quiet wrong answer. Reverted
    // the deletion; TlsQuicFrames.cs now matches the file committed here.
    //
    // The reported code is FRAME_ENCODING_ERROR and not the caught
    // exception's TRANSPORT_PARAMETER_ERROR: a truncated frame is not a
    // "need more bytes" condition, because s12.4 says frames "always fit
    // within a single QUIC packet and cannot span multiple packets", so
    // there is nothing to wait for and s20.1's "frame that was badly
    // formatted" is what happened.
    [Fact]
    public void TruncatedMultiByteFrameTypeReturnsFalseNotThrows()
    {
        byte[] encoded = [0x40];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // Design constraint from subsystem B: the writer must never merge or
    // reorder frames. Three WriteFrame calls - even two of the same type -
    // must read back as three distinct frames, not fewer.
    [Fact]
    public void WriterEmitsRequestedSequenceUnmergedAndReaderRecoversAllOfIt()
    {
        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Padding });
        TlsQuicFrames.WriteFrame(destination, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping });
        TlsQuicFrames.WriteFrame(destination, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Padding });

        Assert.Equal<byte>([0x00, 0x01, 0x00], destination);

        byte[] payload = [.. destination];
        var offset = 0;
        List<ulong> read = [];
        while (offset < payload.Length)
        {
            Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out _));
            read.Add(frame.RawType);
        }

        Assert.Equal<ulong>(
        [
            (ulong)TlsQuicFrameType.Padding,
            (ulong)TlsQuicFrameType.Ping,
            (ulong)TlsQuicFrameType.Padding,
        ],
            read);
        Assert.Equal(3, read.Count);
        Assert.Equal(payload.Length, offset);
    }

    // WritingAnUnimplementedFrameTypeThrows stood here until A2 task 5, the write
    // side of the deletion recorded above and the same argument: its subject was a
    // Table 3 type WriteFrame had no case for, its input moved from CRYPTO to
    // RESET_STREAM when task 3b landed, and task 5 leaves no such type. Unlike its
    // read-side twin this one would have gone RED rather than quietly stopped
    // testing - WriteFrame's new ResetStream case writes a four-byte frame for a
    // default-constructed RESET_STREAM instead of throwing - which is what makes
    // "the subject is gone" a conclusion rather than an excuse. The default arm's
    // surviving witness is the test immediately below, whose input is outside
    // Table 3 altogether and so stays reachable forever.

    // The writer dispatches on the derived Type, so a RawType whose base is
    // implemented but whose exact value is not - here the 2^32-aliasing value
    // from the rejection test above, whose base is itself - must not slip
    // through as an eight-byte HANDSHAKE_DONE.
    [Fact]
    public void WritingAFrameTypeAboveTableThreeThrows()
    {
        var frame = new TlsQuicFrame { RawType = 4294967326UL };
        Assert.Throws<ArgumentException>(() => TlsQuicFrames.WriteFrame([], frame));
    }

    // ---- Task C17: RFC 9221 DATAGRAM, parse and drop ------------------------
    //
    // WHAT THIS CLOSES IS AN ADVERTISEMENT, NOT A FEATURE. SharpTls accepts and
    // discards DATAGRAM frames; it does not implement QUIC or HTTP/3 datagrams.
    // The tests below are therefore all about the FRAMING and none of them about
    // the data, because the data has nowhere to go: what has to be right is the
    // extent, since a payload is "a sequence of complete frames" (RFC 9000 s12.4
    // Figure 11) and a DATAGRAM measured wrong corrupts every frame after it.
    //
    // Every input here is hand-built bytes rather than encoder output, and it has
    // to be: WriteFrame refuses to emit a DATAGRAM, which is the point of
    // WritingADatagramFrameThrowsBecauseThisLibraryNeverSendsOne below. Each is
    // derived from RFC 9221 s4's frame diagram - Type (i) = 0x30..0x31, then
    // [Length (i)], then Datagram Data (..) - and from its LEN bit sentence.

    // The LEN-clear form, 0x30. RFC 9221 s4: "if this bit is set to 0, the Length
    // field is absent and the Datagram Data field extends to the end of the
    // packet."
    //
    // THE TRAILING BYTES ARE THE WHOLE TEST and they are chosen so that the two
    // readings of the LEN bit disagree. 0x01 is a complete PING frame and 0xbb is
    // an unassigned type, so:
    //
    //   * read as LEN-clear (correct): both bytes are datagram data, the frame
    //     ends at the buffer's end, offset is 4 and the walk yields ONE frame.
    //   * read as LEN-present (the inverted bit): 0x01 becomes a Length of 1, one
    //     byte of data is consumed, offset lands on 3, and the walk then meets
    //     0xbb and rejects it - two visible differences, in offset and in count.
    //
    // A trailer whose first byte equalled its own remaining length would make the
    // two readings agree and the test vacuous. That is exactly the trap RFC 9221
    // sets, so the length here is 1 while two bytes remain.
    [Fact]
    public void DatagramWithTheLenBitClearRunsToTheEndOfThePayload()
    {
        byte[] payload = [0x30, 0x01, 0xbb];
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out var error));
        Assert.Equal((ulong)TlsQuicFrameType.Datagram, frame.RawType);
        Assert.Equal(TlsQuicFrameType.Datagram, frame.Type);
        Assert.Equal(TlsQuicTransportError.NoError, error);

        // The extent, which is the claim: the whole buffer, not one byte of it.
        Assert.Equal(payload.Length, offset);
    }

    // The LEN-present form, 0x31, and the sharper half of the same pair. RFC 9221
    // s4: "if this bit is set to 1, the Length field is present."
    //
    // A frame FOLLOWS the datagram here, which is what no single-frame test can
    // check: read as LEN-clear (the inverted bit), the DATAGRAM would swallow the
    // PING and the walk would yield one frame instead of two. Read correctly it
    // consumes type + Length + 2 bytes = 4, and the PING is reached.
    //
    // The declared Length is 2 while 3 bytes remain, so this also cannot be
    // satisfied by a reader that ignores Length and runs to the end.
    [Fact]
    public void DatagramWithTheLenBitSetConsumesOnlyItsDeclaredLength()
    {
        byte[] payload = [0x31, 0x02, 0xaa, 0xbb, (byte)TlsQuicFrameType.Ping];
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var datagram, out var error));
        Assert.Equal(0x31UL, datagram.RawType);
        Assert.Equal(TlsQuicFrameType.Datagram, datagram.Type);
        Assert.Equal(4, offset);
        Assert.Equal(TlsQuicTransportError.NoError, error);

        Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var ping, out error));
        Assert.Equal((ulong)TlsQuicFrameType.Ping, ping.RawType);
        Assert.Equal(payload.Length, offset);
        Assert.Equal(TlsQuicTransportError.NoError, error);
    }

    // THIS TEST USED TO ASSERT THE OPPOSITE AND IS INVERTED RATHER THAN DELETED. It read
    // `Assert.True(frame.Data.IsEmpty)` under the heading "the drop, asserted rather than
    // described", and its reason was that nothing above the reader could act on a datagram, so
    // a populated field was an invitation with no legitimate taker. Two receive-side rules
    // ended that: RFC 9221 s3 measures the frame against max_datagram_frame_size and RFC 9297
    // s2.1 reads a Quarter Stream ID out of the payload, and neither can run on bytes the
    // reader threw away. What was a deliberate omission is now a defect, so the assertion
    // turns over and keeps the row a reader can find the change at.
    //
    // Both forms, because they reach the payload by different routes: the LEN-present one
    // starts after a Length field and the LEN-clear one starts immediately and runs to the end.
    [Theory]
    [InlineData(new byte[] { 0x30, 0xaa, 0xbb, 0xcc }, 4)]
    [InlineData(new byte[] { 0x31, 0x03, 0xaa, 0xbb, 0xcc }, 5)]
    public void TheDatagramPayloadAndItsEncodedLengthAreCarried(byte[] payload, int encoded)
    {
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out _));
        Assert.Equal(payload.Length, offset);

        // THE SAME THREE BYTES OUT OF TWO DIFFERENT FRAMINGS. The LEN-clear row has no Length
        // field at all and the LEN-present row spends a byte on one, so a reader that returned
        // the whole frame instead of its Datagram Data field would pass one row and fail the
        // other.
        Assert.Equal(new byte[] { 0xaa, 0xbb, 0xcc }, frame.Data.ToArray());

        // AND THE SIZE IS THE WHOLE FRAME, NOT THE PAYLOAD. RFC 9221 s3 measures "including
        // the frame type, length, and payload", which is why the two rows expect 4 and 5
        // against the same 3 bytes of data.
        Assert.Equal(encoded, frame.EncodedLength);
    }

    // Every frame type but DATAGRAM leaves EncodedLength at zero, because no other frame has a
    // size rule to measure. Asserted on PING rather than described, so that a reader who added
    // the field to another reader would have to change a test to do it.
    [Fact]
    public void ANonDatagramFrameCarriesNoEncodedLength()
    {
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(
            new byte[] { 0x01 }, ref offset, out var frame, out _));
        Assert.Equal(TlsQuicFrameType.Ping, frame.Type);
        Assert.Equal(0, frame.EncodedLength);
    }

    // RFC 9221 s4: "Note that empty (i.e., zero-length) datagrams are allowed."
    // Both forms reach it - a 0x30 at the very end of a payload has no bytes left
    // to extend over, and a 0x31 can say so explicitly with Length 0.
    //
    // The second row is also the exact-fit boundary: Length 0 with 0 bytes
    // remaining is the case a `>=` written where the extent check needs `>` would
    // wrongly reject. The third row is the same boundary with data present -
    // Length 2 with exactly 2 bytes left.
    [Theory]
    [InlineData(new byte[] { 0x30 }, 1)]
    [InlineData(new byte[] { 0x31, 0x00 }, 2)]
    [InlineData(new byte[] { 0x31, 0x02, 0xaa, 0xbb }, 4)]
    public void EmptyAndExactlyFittingDatagramsAreAccepted(byte[] payload, int expectedOffset)
    {
        var offset = 0;

        Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out var error));
        Assert.Equal(TlsQuicFrameType.Datagram, frame.Type);
        Assert.Equal(expectedOffset, offset);
        Assert.Equal(TlsQuicTransportError.NoError, error);
    }

    // A Length field promising more bytes than the payload holds. RFC 9000 s12.4
    // makes this malformed rather than incomplete - frames "cannot span multiple
    // packets", so there is no continuation to wait for - and s20.1's
    // FRAME_ENCODING_ERROR is "a frame that was badly formatted".
    //
    // The rows walk the failure outward from the boundary:
    //
    //   * Length 3 with 2 bytes left: off by one, the row a bounds check written
    //     with the wrong comparison lands on.
    //   * Length 1 with 0 bytes left: the field runs out at EOF exactly.
    //   * Length 1073741823 (2^30 - 1, the largest a 4-byte varint holds) with 0
    //     bytes left: the row that matters if the extent check is deleted.
    //     `(int)length` would be positive and enormous, so offset would leap far
    //     past the buffer.
    //   * Length 4611686018427387903 (2^62 - 1, the varint maximum) with 0 bytes
    //     left: the same defect at its worst. `(int)` of that value is -1, so a
    //     reader that cast before comparing would move the offset BACKWARDS into
    //     bytes it had already parsed and loop.
    //
    // A truncated Length varint is the separate row at the end: 0x40 declares a
    // two-byte varint whose second byte never arrives, so QuicVariableLengthInteger
    // .TryRead reports false and the extent check is never reached at all.
    [Theory]
    [InlineData(new byte[] { 0x31, 0x03, 0xaa, 0xbb })]
    [InlineData(new byte[] { 0x31, 0x01 })]
    [InlineData(new byte[] { 0x31, 0xbf, 0xff, 0xff, 0xff })]
    [InlineData(new byte[] { 0x31, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff })]
    [InlineData(new byte[] { 0x31, 0x40 })]
    public void ADatagramLengthPastTheEndOfThePayloadIsRejected(byte[] payload)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out var error));

        // TryReadFrame's contract: a failure commits nothing.
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // The refusal, and it is the deliverable rather than a limitation of it. This
    // library parses DATAGRAM frames so that its own advertisement -
    // max_datagram_frame_size in TlsQuicTransportParameterSpec's default preset,
    // SETTINGS_H3_DATAGRAM = 1 in TlsQuicHttp3Spec's default settings - does not
    // kill connections. It implements no datagram semantics and must never claim
    // to by emitting one.
    //
    // Both wire values, because the refusal is on the derived Type and a reader of
    // WriteFrame's switch cannot tell from one row whether the other reaches the
    // same arm. RFC 9221 s3 independently forbids sending in this tree's situation:
    // "An endpoint MUST NOT send DATAGRAM frames until it has received the
    // max_datagram_frame_size transport parameter with a non-zero value during the
    // handshake", and nothing here reads a peer's value of that parameter.
    [Theory]
    [InlineData(0x30UL)]
    [InlineData(0x31UL)]
    public void WritingADatagramFrameThrowsBecauseThisLibraryNeverSendsOne(ulong rawType)
    {
        var frame = new TlsQuicFrame { RawType = rawType };

        var thrown = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame([], frame));

        // The message is asserted, not just the exception type, because falling
        // through to the default arm would throw the same type with a message
        // reading "is not implemented" - which is the opposite of what this is.
        Assert.Contains("never sent", thrown.Message, StringComparison.Ordinal);
    }
}
