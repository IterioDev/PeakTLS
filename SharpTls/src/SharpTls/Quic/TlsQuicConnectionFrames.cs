namespace SharpTls.Quic;

// The eight connection-management frames of RFC 9000 s19, both directions:
// s19.4 RESET_STREAM (type 0x04), s19.5 STOP_SENDING (0x05), s19.7 NEW_TOKEN
// (0x07), s19.15 NEW_CONNECTION_ID (0x18), s19.16 RETIRE_CONNECTION_ID (0x19),
// s19.17 PATH_CHALLENGE (0x1a), s19.18 PATH_RESPONSE (0x1b) and s19.19
// CONNECTION_CLOSE (0x1c..0x1d). With these twenty of twenty frame types have a
// reader and a writer.
//
// Pure functions. This file decides how the eight frames are written and read and
// nothing else - NO CONNECTION STATE, no path validation, no token validation, no
// connection ID issuance, rotation or retirement bookkeeping, no close handling.
// These sections carry more stateful MUSTs than any family so far, and what is
// deliberately absent is worth listing so that absence is not mistaken for an
// oversight:
//
//   * s19.4: "An endpoint that receives a RESET_STREAM frame for a send-only
//     stream MUST terminate the connection with error STREAM_STATE_ERROR." Needs
//     the stream state machine, which is phase A4's.
//   * s19.5: "Receiving a STOP_SENDING frame for a locally initiated stream that
//     has not yet been created MUST be treated as a connection error of type
//     STREAM_STATE_ERROR", and the same code again for a receive-only stream.
//     Stream state again.
//   * s19.7: "Clients MUST NOT send NEW_TOKEN frames. A server MUST treat receipt
//     of a NEW_TOKEN frame as a connection error of type PROTOCOL_VIOLATION."
//     Needs to know which endpoint this is; this file is used by both. Its
//     neighbouring paragraph - clients "are responsible for discarding duplicate
//     values" - needs the tokens already seen.
//   * s19.15, both halves of the zero-length-connection-ID rule: "An endpoint MUST
//     NOT send this frame if it currently requires that its peer send packets with
//     a zero-length Destination Connection ID", and "An endpoint that is sending
//     packets with a zero-length Destination Connection ID MUST treat receipt of a
//     NEW_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION".
//     The send half binds this file's writers and is listed with the receive half
//     because both need the same absent state - what this endpoint requires of its
//     peer's headers. Also the MAY for a frame that
//     "repeats a previously issued connection ID with a different Stateless Reset
//     Token field value"; "A receiver MUST ignore any Retire Prior To fields that
//     do not increase the largest received Retire Prior To value"; and the MUST to
//     send a corresponding RETIRE_CONNECTION_ID for a sequence number below a
//     previously received Retire Prior To. All four need the connection ID table.
//   * s19.16: "Receipt of a RETIRE_CONNECTION_ID frame containing a sequence
//     number greater than any previously sent to the peer MUST be treated as a
//     connection error of type PROTOCOL_VIOLATION", the MAY about the sequence
//     number naming the containing packet's own Destination Connection ID, and the
//     zero-length-connection-ID PROTOCOL_VIOLATION. State, and in the second case
//     the enclosing packet, neither of which reaches a frame reader.
//   * s19.18: "If the content of a PATH_RESPONSE frame does not match the content
//     of a PATH_CHALLENGE frame previously sent by the endpoint, the endpoint MAY
//     generate a connection error of type PROTOCOL_VIOLATION." Needs the
//     challenges outstanding on each path.
//   * s19.19: "The application-specific variant of CONNECTION_CLOSE (type 0x1d)
//     can only be sent using 0-RTT or 1-RTT packets; see Section 12.5." That is a
//     frame-type-to-packet-type rule, which is A2 task 6's table, not a property
//     of the bytes in front of this reader.
//
// Four rules in these eight sections ARE enforced here, and they are exactly the
// ones that are properties of the field in front of you:
//
//   * s19.7's "The token MUST NOT be empty" - see TryReadNewToken.
//   * s19.15's connection ID length range, 1 to 20 - see MinimumConnectionIdLength.
//   * s19.15's Retire Prior To <= Sequence Number ordering - see
//     TryReadNewConnectionId.
//   * s19.17's and s19.18's fixed 8-byte Data field - see TryReadPathData.
//
// THE FIELDS ARE NOT ALL VARINTS, which is what distinguishes this family from
// every earlier one. Three departures, each with its own failure mode:
//
//   * s19.15's Length is "An 8-bit unsigned integer", not a varint, and its
//     Stateless Reset Token is a bare 128 bits with no length in front of it.
//   * s19.17's and s19.18's Data is "(64)" in the figure - a fixed 8 bytes, again
//     with no length prefix. A reader that treated it as varint-prefixed would
//     consume the wrong bytes for every input, and one that did not check 8 bytes
//     remain would slice past the payload.
//   * s19.7's Token and s19.19's Reason Phrase are length-prefixed like STREAM's
//     data, but bounded differently at zero: an empty Reason Phrase is legal and
//     an empty Token is a connection error.
//
// TryTakeFixed is the one helper the fixed-width fields share; the three call
// sites differ only in the length they ask for.
//
// SEVEN READERS AND SEVEN WRITERS FOR EIGHT FRAME TYPES. The one pair that shares
// an implementation is PATH_CHALLENGE and PATH_RESPONSE, and the sharing is the
// RFC's own rather than this file's invention - s19.18: "The format of a
// PATH_RESPONSE frame is identical to that of the PATH_CHALLENGE frame; see
// Section 19.17." A mutation anywhere inside TryReadPathData or
// WritePathDataFrameFields therefore fails rows belonging to both frame types.
//
// What is deliberately NOT shared, and this is the closest call in the file:
// s19.5's two fields are named identically to the first two of s19.4's three, so
// STOP_SENDING looks like a RESET_STREAM without its Final Size. It is not
// implemented that way. The RFC never says the two formats are related - contrast
// the sentence it does spend on PATH_RESPONSE above - and a shared reader would
// need a `hasFinalSize` conditional over the frame type, which is the shape the
// A2 plan's file-layout amendment was written against. Two short readers that each
// match one figure beat one reader that matches neither.
internal static class TlsQuicConnectionFrames
{
    /// <summary>
    /// The low bit that separates CONNECTION_CLOSE's two type values. RFC 9000
    /// s19.19: "The CONNECTION_CLOSE frame with a type of 0x1c is used to signal
    /// errors at only the QUIC layer, or the absence of errors (with the NO_ERROR
    /// code). The CONNECTION_CLOSE frame with a type of 0x1d is used to signal an
    /// error with the application that uses QUIC."
    /// </summary>
    /// <remarks>
    /// s19.19 does not call this a bit; like s19.11 and s19.14 it simply lists two
    /// values. What licenses reading it as a flag is s12.4: "The Frame Type in ACK,
    /// STREAM, MAX_STREAMS, STREAMS_BLOCKED, and CONNECTION_CLOSE frames is used to
    /// carry other frame-specific flags." CONNECTION_CLOSE is in that list, and the
    /// application value is the odd one, exactly as the unidirectional value is in
    /// <see cref="TlsQuicFlowControlFrames.UnidirectionalBit"/>.
    /// </remarks>
    internal const ulong ApplicationErrorBit = 0x01;

    /// <summary>
    /// The shortest connection ID a NEW_CONNECTION_ID frame may carry. RFC 9000
    /// s19.15, of the Length field: "An 8-bit unsigned integer containing the
    /// length of the connection ID. Values less than 1 and greater than 20 are
    /// invalid and MUST be treated as a connection error of type
    /// FRAME_ENCODING_ERROR." So a zero-length connection ID, which QUIC allows in
    /// a packet header, cannot be issued through this frame.
    /// </summary>
    internal const int MinimumConnectionIdLength = 1;

    /// <summary>
    /// The longest connection ID a NEW_CONNECTION_ID frame may carry, from the
    /// s19.15 sentence quoted on <see cref="MinimumConnectionIdLength"/>. "Greater
    /// than 20 are invalid" makes 20 itself legal, so both comparisons against this
    /// pair of constants are inclusive at the ends and 21 is the smallest illegal
    /// value.
    /// </summary>
    internal const int MaximumConnectionIdLength = 20;

    /// <summary>
    /// The width of a NEW_CONNECTION_ID frame's Stateless Reset Token, in bytes.
    /// RFC 9000 s19.15 Figure 39 spells the field "Stateless Reset Token (128)" and
    /// its description says "A 128-bit value that will be used for a stateless reset
    /// when the associated connection ID is used"; 128 bits is 16 bytes. Not
    /// length-prefixed - the width is fixed by the figure.
    /// </summary>
    internal const int StatelessResetTokenLength = 16;

    /// <summary>
    /// The width of a PATH_CHALLENGE or PATH_RESPONSE frame's Data field, in bytes.
    /// RFC 9000 s19.17 Figure 41 spells it "Data (64)" and its description says
    /// "This 8-byte field contains arbitrary data"; s19.18 gives PATH_RESPONSE the
    /// identical format. Not length-prefixed, and not variable: a frame carrying
    /// seven bytes is malformed rather than short.
    /// </summary>
    internal const int PathDataLength = 8;

    /// <summary>
    /// Whether a CONNECTION_CLOSE frame with this exact wire type carries an
    /// application error code (0x1d) rather than a transport one (0x1c). Only
    /// meaningful for those two values, which RFC 9000 s12.4 Table 3 assigns to
    /// CONNECTION_CLOSE - the same documented, unenforced precondition
    /// <see cref="TlsQuicFlowControlFrames.IsUnidirectional"/> carries, and the same
    /// aliasing hazard: this takes a bare ulong, so IsApplicationError(0x01) returns
    /// true for what is really a PING. Nothing is wrong today because
    /// TlsQuicFrames.TryReadFrame's case labels mean the callers have already
    /// matched the type.
    /// </summary>
    /// <remarks>
    /// Unlike this namespace's other two type-bit predicates, this one is NOT a
    /// convenience for a later phase: both directions branch on it here, because
    /// s19.19's Frame Type field is present in one form and absent in the other.
    /// <see cref="TryReadConnectionClose"/> and
    /// <see cref="WriteConnectionCloseFrameFields"/> are its production callers, so
    /// it is the answer to the A2 plan's cap on unused predicates rather than a
    /// third instance of one. The form lives in
    /// <see cref="TlsQuicFrame.RawType"/> and nowhere else, so no field on the
    /// struct can fall out of step with the wire type.
    /// </remarks>
    internal static bool IsApplicationError(ulong rawConnectionCloseFrameType) =>
        (rawConnectionCloseFrameType & ApplicationErrorBit) != 0;

    // Reads everything after the frame type of a RESET_STREAM frame, in the order
    // RFC 9000 s19.4 Figure 28 lists it:
    //
    //   RESET_STREAM Frame {
    //     Type (i) = 0x04,
    //     Stream ID (i),
    //     Application Protocol Error Code (i),
    //     Final Size (i),
    //   }
    //
    // No rawType parameter: s12.4 Table 3 assigns RESET_STREAM the single value
    // 0x04, so there is nothing for the caller to pass and nothing to branch on.
    // Every check below is therefore reachable exactly one way, which is worth
    // saying explicitly - the A2 plan's multi-path rule applies to CONNECTION_CLOSE
    // and to the two path frames in this file, and to nothing else in it.
    //
    // The field order is the one thing a round-trip test cannot catch: all three
    // are varints, so a reader that permuted them would decode any frame into three
    // plausible numbers and re-encode them into the same bytes. It is pinned
    // instead by hand-derived vectors giving the three fields three different
    // values; see TlsQuicConnectionFramesTests.ResetStreamFrameMatchesItsHand
    // DerivedBytes.
    //
    // Same Try-shaped contract as TlsQuicFrames.TryReadFrame, its only production
    // caller: never throws for any input, and `offset` only advances on success.
    // The second half is observable - a frame truncated in its Final Size fails
    // with two fields already walked - and is pinned by a direct call at a nonzero
    // offset, TlsQuicConnectionFramesTests.TryReadResetStreamCommitsNothingWhenIts
    // LastFieldIsTruncated.
    internal static bool TryReadResetStream(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;
        var walked = offset;

        // s19.4, Stream ID: "A variable-length integer encoding of the stream
        // ID of the stream being terminated."
        //
        // s19.4, Application Protocol Error Code: "A variable-length integer
        // containing the application protocol error code (see Section 20.2)
        // that indicates why the stream is being closed." s20.2 leaves that
        // space entirely to the application, so there is no value to validate
        // against here - s20 bounds it only by making error codes "62-bit
        // unsigned integers", which the varint encoding already guarantees.
        //
        // s19.4, Final Size: "A variable-length integer indicating the final
        // size of the stream by the RESET_STREAM sender, in units of bytes; see
        // Section 4.5." s4.5's rules about a final size that contradicts one
        // already established are FINAL_SIZE_ERROR conditions needing the
        // stream's history, so they are not enforceable here; see this file's
        // own comment.
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var streamId) ||
            !QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var applicationProtocolErrorCode) ||
            !QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var finalSize))
        {
            // Same reasoning as TlsQuicFrames.TryReadFrame's own check: the
            // reported code is this namespace's FRAME_ENCODING_ERROR, chosen
            // directly rather than derived from a caught exception - TryRead
            // carries no code of its own. Per s12.4 "Frames always fit within a
            // single QUIC packet and cannot span multiple packets", so a field
            // running off the end of an already-decrypted payload is badly
            // formatted rather than incomplete, and s20.1 makes
            // FRAME_ENCODING_ERROR "An endpoint received a frame that was badly
            // formatted".
            //
            // THREE PATHS REACH THIS CHECK, one per field, and all three are rows
            // of TlsQuicConnectionFramesTests.ResetStreamTruncatedInAnyFieldIs
            // Rejected. The fourth casualty of each is
            // TlsQuicConnectionFramesTests.TryReadResetStreamCommitsNothingWhenIts
            // LastFieldIsTruncated, whose input truncates Final Size and so
            // reaches this check only through the third term. Mutation checks
            // (performed and reverted): dropping the whole condition, so nothing
            // is ever rejected, fails all four; dropping any one
            // `!QuicVariableLengthInteger.TryRead` term fails exactly the row
            // whose truncation only that term can catch (the commits-nothing
            // test needs the third).
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        frame = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.ResetStream,
            StreamId = streamId,
            ApplicationProtocolErrorCode = applicationProtocolErrorCode,
            FinalSize = finalSize,
        };
        offset = walked;
        return true;
    }

    // Reads everything after the frame type of a STOP_SENDING frame, in the order
    // RFC 9000 s19.5 Figure 29 lists it:
    //
    //   STOP_SENDING Frame {
    //     Type (i) = 0x05,
    //     Stream ID (i),
    //     Application Protocol Error Code (i),
    //   }
    //
    // Single type value 0x05, so no rawType parameter and one path through every
    // check, exactly as in TryReadResetStream. Why this is not TryReadResetStream
    // with the third read skipped is in this file's own comment.
    //
    // Same Try-shaped contract; the "advances only on success" half is observable
    // here too - the second field can fail with the first walked past - and is
    // pinned by TlsQuicConnectionFramesTests.TryReadStopSendingCommitsNothingWhen
    // ItsSecondFieldIsTruncated.
    internal static bool TryReadStopSending(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;
        var walked = offset;

        // s19.5, Stream ID: "A variable-length integer carrying the stream ID
        // of the stream being ignored."
        //
        // s19.5, Application Protocol Error Code: "A variable-length integer
        // containing the application-specified reason the sender is ignoring
        // the stream; see Section 20.2."
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var streamId) ||
            !QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var applicationProtocolErrorCode))
        {
            // Two paths, one per field, both rows of
            // TlsQuicConnectionFramesTests.StopSendingTruncatedInEitherFieldIs
            // Rejected, plus
            // TlsQuicConnectionFramesTests.TryReadStopSendingCommitsNothingWhenIts
            // SecondFieldIsTruncated, which enters here too through the second
            // term. Mutation checks (performed and reverted): dropping the whole
            // condition fails all three; dropping the second
            // `!QuicVariableLengthInteger.TryRead` term fails the second row and
            // the commits-nothing test.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        frame = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.StopSending,
            StreamId = streamId,
            ApplicationProtocolErrorCode = applicationProtocolErrorCode,
        };
        offset = walked;
        return true;
    }

    // Reads everything after the frame type of a NEW_TOKEN frame, in the order
    // RFC 9000 s19.7 Figure 31 lists it:
    //
    //   NEW_TOKEN Frame {
    //     Type (i) = 0x07,
    //     Token Length (i),
    //     Token (..),
    //   }
    //
    // Single type value 0x07, so one path through every check.
    //
    // Same Try-shaped contract; pinned at a nonzero offset by
    // TlsQuicConnectionFramesTests.TryReadNewTokenCommitsNothingWhenTheTokenIsEmpty,
    // which is a rejection that fires with the Token Length already walked past.
    internal static bool TryReadNewToken(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;
        var walked = offset;

        // s19.7, Token Length: "A variable-length integer specifying the length
        // of the token in bytes."
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var tokenLength))
        {
            // Mutation check (performed and reverted): see
            // TlsQuicConnectionFramesTests.NewTokenTruncatedInItsLengthIsRejected.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // THE FIELD THAT CANNOT BE EMPTY. s19.7, Token: "An opaque blob that the
        // client can use with a future Initial packet. The token MUST NOT be empty.
        // A client MUST treat receipt of a NEW_TOKEN frame with an empty Token
        // field as a connection error of type FRAME_ENCODING_ERROR." The error code
        // is named outright, so unlike this phase's other rejections there is no
        // choice to justify.
        //
        // Checked before the extent check below rather than after: a zero length
        // can never overrun the payload, so the order is not forced, but a property
        // of the field on its own reads first and keeps the two checks separately
        // killable.
        //
        // Mutation checks (performed and reverted): deleting this check makes
        // TlsQuicConnectionFramesTests.NewTokenWithAnEmptyTokenIsRejected parse
        // successfully into a frame with an empty Token, and also fails
        // TlsQuicConnectionFramesTests.TryReadNewTokenCommitsNothingWhenTheTokenIs
        // Empty; nothing else in the Quic suite depends on it. Weakening it to
        // `tokenLength < 0` does not
        // compile - the value is a ulong - which is itself the observation that
        // "empty" is the only degenerate case there is here.
        if (tokenLength == 0)
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // The extent check, in the form TlsQuicStreamFrames.TryReadData uses and
        // for the same reason: `tokenLength` is a variable-length integer, so a
        // peer can put nearly 2^62 in two bytes, and casting that to int before the
        // comparison would truncate it to whatever its low 32 bits happen to be -
        // possibly a small in-bounds number. Compared as a ulong against the
        // remaining byte count, and nothing is allocated from it: the slice below is
        // taken only after the bytes are proven to exist.
        //
        // s12.4 again: frames "cannot span multiple packets", so a Token Length
        // reaching past the end of the payload is badly formatted, not incomplete.
        //
        // Mutation check (performed and reverted): deleting this check makes
        // TlsQuicConnectionFramesTests.NewTokenWhoseLengthOverrunsThePayloadIs
        // Rejected throw ArgumentOutOfRangeException out of Memory.Slice - an
        // exception escaping a Try-shaped reader, which is the contract broken
        // rather than a wrong answer.
        var remaining = (ulong)(payload.Length - walked);
        if (tokenLength > remaining)
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        frame = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.NewToken,
            Token = payload.Slice(walked, (int)tokenLength),
        };
        offset = walked + (int)tokenLength;
        return true;
    }

    // Reads everything after the frame type of a NEW_CONNECTION_ID frame, in the
    // order RFC 9000 s19.15 Figure 39 lists it:
    //
    //   NEW_CONNECTION_ID Frame {
    //     Type (i) = 0x18,
    //     Sequence Number (i),
    //     Retire Prior To (i),
    //     Length (8),
    //     Connection ID (8..160),
    //     Stateless Reset Token (128),
    //   }
    //
    // Two varints, then three fields that are not varints at all: an 8-bit length,
    // a connection ID of that many bytes, and a bare 128-bit token. The widths in
    // the figure are bits, so "(8..160)" is 1 to 20 bytes and matches the Length
    // field's own stated range exactly.
    //
    // Single type value 0x18, so one path through every check below except where a
    // check has two ends or two truncation points, which is noted at each.
    //
    // Same Try-shaped contract; pinned at a nonzero offset by
    // TlsQuicConnectionFramesTests.TryReadNewConnectionIdCommitsNothingWhenThe
    // LengthIsOutOfRange, whose rejection fires with three fields already walked -
    // the deepest rejection in this file.
    internal static bool TryReadNewConnectionId(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;
        var walked = offset;

        // s19.15, Sequence Number: "The sequence number assigned to the
        // connection ID by the sender, encoded as a variable-length integer;
        // see Section 5.1.1."
        //
        // s19.15, Retire Prior To: "A variable-length integer indicating which
        // connection IDs should be retired; see Section 5.1.2."
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var sequenceNumber) ||
            !QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var retirePriorTo))
        {
            // Two paths, one per field, both rows of
            // TlsQuicConnectionFramesTests.NewConnectionIdTruncatedInItsVarint
            // FieldsIsRejected. Mutation checks (performed and reverted): dropping
            // the whole condition fails both; dropping the second
            // `!QuicVariableLengthInteger.TryRead` term fails the second row alone.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // THE ORDERING CONSTRAINT, and the only validity rule in this phase that
        // relates two fields of one frame to each other rather than to a constant.
        // s19.15: "The value in the Retire Prior To field MUST be less than or equal
        // to the value in the Sequence Number field. Receiving a value in the Retire
        // Prior To field that is greater than that in the Sequence Number field MUST
        // be treated as a connection error of type FRAME_ENCODING_ERROR."
        //
        // REACHABLE ON THE READ SIDE despite both operands coming out of
        // QuicVariableLengthInteger.TryRead, and for a different reason than the A2
        // plan's usual one: the bound here is not a constant the varint range
        // already enforces, it is the other field. Any pair of decodable varints
        // with retirePriorTo > sequenceNumber reaches it - the smallest being 1 and
        // 0 in two bytes.
        //
        // "Less than or equal" makes equality legal, so the comparison is strict and
        // the boundary needs its own accepting row.
        //
        // Mutation checks (performed and reverted): deleting this check makes
        // TlsQuicConnectionFramesTests.NewConnectionIdWhoseRetirePriorToExceedsIts
        // SequenceNumberIsRejected parse successfully; weakening it to >= fails
        // TlsQuicConnectionFramesTests.NewConnectionIdWhoseRetirePriorToEqualsIts
        // SequenceNumberIsAccepted, which is the sentence's "or equal to" and would
        // otherwise go unpinned.
        if (retirePriorTo > sequenceNumber)
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // s19.15, Length: "An 8-bit unsigned integer containing the length of the
        // connection ID." One byte, read directly rather than through
        // QuicVariableLengthInteger - a varint read would interpret the two most
        // significant bits as a width and consume up to eight bytes for a field the
        // figure fixes at one.
        //
        // Mutation check (performed and reverted): deleting this bounds check makes
        // TlsQuicConnectionFramesTests.NewConnectionIdWithNoLengthByteIsRejected
        // throw IndexOutOfRangeException out of the span index below - again an
        // exception escaping a Try-shaped reader.
        //
        // READING THE FIELD AS A VARINT IS THE OTHER MUTATION, and it is nearly
        // unkillable: every legal length is 20 or below, so s16's one-byte form
        // encodes it as itself and a varint read agrees with a byte read over the
        // whole legal range. No accepting vector can separate them. The one input
        // that can is a length byte of 0x40 or above, where s16 reads the top two
        // bits as a width and consumes further bytes - so a mutant decodes
        // `40 05` as the value 5 and accepts a frame this reader rejects at 64.
        // That is the third row of
        // TlsQuicConnectionFramesTests.NewConnectionIdWithAnOutOfRangeLengthIs
        // Rejected, which exists for this mutation alone.
        if (walked >= payload.Length)
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        int connectionIdLength = payload.Span[walked];
        walked++;

        // THE BOUNDED-LENGTH FIELD. s19.15, continuing the Length description:
        // "Values less than 1 and greater than 20 are invalid and MUST be treated as
        // a connection error of type FRAME_ENCODING_ERROR." Both ends are reachable
        // from a one-byte field that can hold 0 to 255, so both need a witness -
        // TWO PATHS THROUGH ONE CHECK, the low end and the high end, which is the
        // plan's multi-path rule on an axis that is not a flag.
        //
        // This is also the shape the plan's provenance rule calls out as the
        // counter-case: the bound is far tighter than the field's own range, so
        // unlike a varint-maximum check on a parser-produced value it fires for real
        // inputs on the read side as well as the write side.
        //
        // Both rejecting rows carry a body that exactly fits the length they
        // declare - the 0 row has a full 16-byte token and no connection ID, the 21
        // row has 21 connection ID bytes and a full token - so the extent check
        // below cannot fire for either and this is the only thing that can reject
        // them.
        //
        // Mutation checks (performed and reverted), measured: deleting the check
        // fails three - the first two rows of
        // TlsQuicConnectionFramesTests.NewConnectionIdWithAnOutOfRangeLengthIs
        // Rejected, which then parse successfully into a frame with an empty
        // connection ID and one with a 21-byte one, plus
        // TlsQuicConnectionFramesTests.TryReadNewConnectionIdCommitsNothingWhenThe
        // LengthIsOutOfRange, whose input is the zero-length one. Dropping the low
        // half fails two, the high half one. Raising
        // MinimumConnectionIdLength to 2 fails two rows and lowering
        // MaximumConnectionIdLength to 19 fails one, all in
        // TlsQuicConnectionFramesTests.NewConnectionIdAtBothEndsOfTheLengthRangeIs
        // Accepted and its neighbours.
        if (connectionIdLength < MinimumConnectionIdLength ||
            connectionIdLength > MaximumConnectionIdLength)
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // s19.15, Connection ID: "A connection ID of the specified length." Then the
        // Stateless Reset Token, whose length is not specified anywhere but the
        // figure - see StatelessResetTokenLength.
        //
        // Two calls, two rejections, and they need SEPARATE witnesses that are not
        // the obvious ones. TryTakeFixed reports rather than throwing and leaves
        // `walked` untouched on failure, so dropping the first call's `!` does not
        // simply make a short connection ID slice past the end - it makes the token
        // take the connection ID's bytes and the frame parse with an empty
        // connection ID. The input that exposes that is one where 16 or more bytes
        // remain but fewer than the declared length: see the third row of
        // TlsQuicConnectionFramesTests.NewConnectionIdTruncatedInItsConnectionIdOr
        // TokenIsRejected, which was added after the two obvious rows were found to
        // leave that mutation alive.
        //
        // Mutation checks (performed and reverted), measured: dropping the first
        // call's rejection - fails that third row and nothing else; dropping the
        // second call's - fails three; dropping TryTakeFixed's own bounds check -
        // fails seven, all three rows of that theory plus all four of
        // TlsQuicConnectionFramesTests.PathFrameWithFewerThanEightDataBytesIs
        // Rejected, with ArgumentOutOfRangeException out of Memory.Slice.
        if (!TryTakeFixed(payload, ref walked, connectionIdLength, out var connectionId) ||
            !TryTakeFixed(payload, ref walked, StatelessResetTokenLength, out var statelessResetToken))
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        frame = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.NewConnectionId,
            SequenceNumber = sequenceNumber,
            RetirePriorTo = retirePriorTo,
            ConnectionId = connectionId,
            StatelessResetToken = statelessResetToken,
        };
        offset = walked;
        return true;
    }

    // Reads everything after the frame type of a RETIRE_CONNECTION_ID frame, RFC
    // 9000 s19.16 Figure 40 - one variable-length integer:
    //
    //   RETIRE_CONNECTION_ID Frame {
    //     Type (i) = 0x19,
    //     Sequence Number (i),
    //   }
    //
    // Single type value 0x19, one field, one path through the one check.
    //
    // Same Try-shaped contract as TryReadResetStream, and the "advances only on
    // success" half is UNOBSERVABLE HERE BY CONSTRUCTION rather than for want of a
    // test - the same case TlsQuicFlowControlFrames.TryReadMaximumData records. The
    // only rejection is this reader's single field truncating, and
    // QuicVariableLengthInteger.TryRead advances the offset it is handed only on
    // success, so on a false return `walked` still equals the entry offset and
    // `offset = walked` in the rejecting branch is a no-op for every input. A
    // test would pass against the mutated code, making it a false witness rather
    // than coverage. The trigger that would end this: a second field or a bound.
    internal static bool TryReadRetireConnectionId(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;
        var walked = offset;

        // s19.16, Sequence Number: "The sequence number of the connection ID
        // being retired; see Section 5.1.2." The three MUSTs s19.16 attaches to
        // that number all compare it against what this endpoint previously sent
        // or against the enclosing packet's Destination Connection ID; see this
        // file's own comment for why none of them is enforceable here.
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var sequenceNumber))
        {
            // Mutation check (performed and reverted): see
            // TlsQuicConnectionFramesTests.RetireConnectionIdTruncatedInItsFieldIs
            // Rejected - dropping the `!` above starts accepting a frame TryRead
            // rejected; dropping this assignment fails it on the error code.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        frame = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.RetireConnectionId,
            SequenceNumber = sequenceNumber,
        };
        offset = walked;
        return true;
    }

    // Reads everything after the frame type of a PATH_CHALLENGE (RFC 9000 s19.17
    // Figure 41) or PATH_RESPONSE (s19.18 Figure 42) frame - eight bytes, with no
    // length in front of them:
    //
    //   PATH_CHALLENGE Frame {          PATH_RESPONSE Frame {
    //     Type (i) = 0x1a,                Type (i) = 0x1b,
    //     Data (64),                      Data (64),
    //   }                               }
    //
    // One reader for two frame types because s19.18 says so: "The format of a
    // PATH_RESPONSE frame is identical to that of the PATH_CHALLENGE frame; see
    // Section 19.17." rawType is passed through to TlsQuicFrame.RawType rather than
    // branched on - the two frames differ in that value and in nothing else. Its two
    // reachable values, 0x1a and 0x1b, are the two paths through the one check here,
    // so that check is witnessed twice.
    //
    // Same Try-shaped contract as TryReadResetStream, and the "advances only on
    // success" half is UNOBSERVABLE BY CONSTRUCTION here, for a different reason
    // than TryReadRetireConnectionId's: this reader's only rejection is its first
    // and only field being short, which fires before anything has been walked at
    // all, so `walked == offset` when it returns false. Vacuous to test, and the
    // trigger that would end it is a second field.
    internal static bool TryReadPathData(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        ulong rawType,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;
        var walked = offset;

        // THE FIXED-WIDTH FIELD. s19.17, Data: "This 8-byte field contains arbitrary
        // data", and Figure 41 spells it "Data (64)" - 64 bits with no Length in
        // front of it, unlike every other variable-looking field in this file. A
        // reader that treated it as varint-prefixed would consume the first byte as
        // a width and then the wrong bytes as data; one that did not check eight
        // remain would slice past the payload.
        //
        // Only "at least eight", not "exactly eight": s12.4 makes a packet payload
        // "a sequence of complete frames", so bytes after the eighth belong to the
        // next frame, and `offset` advances by exactly PathDataLength so the
        // caller's read loop finds them. Pinned by
        // TlsQuicConnectionFramesTests.PathFrameConsumesExactlyEightBytesAndNoMore.
        //
        // Mutation checks (performed and reverted): deleting this check makes both
        // rows of TlsQuicConnectionFramesTests.PathFrameWithFewerThanEightDataBytes
        // IsRejected throw ArgumentOutOfRangeException out of Memory.Slice;
        // conditioning it on rawType == 0x1a fails the 0x1b rows alone, and vice
        // versa; changing PathDataLength to 7 fails ten rows across this family's
        // tests, both directions and both type values, which is what a width
        // constant with no length field on the wire should cost.
        if (!TryTakeFixed(payload, ref walked, PathDataLength, out var data))
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        frame = new TlsQuicFrame
        {
            RawType = rawType,
            Data = data,
        };
        offset = walked;
        return true;
    }

    // Reads everything after the frame type of a CONNECTION_CLOSE frame, in the
    // order RFC 9000 s19.19 Figure 43 lists it:
    //
    //   CONNECTION_CLOSE Frame {
    //     Type (i) = 0x1c..0x1d,
    //     Error Code (i),
    //     [Frame Type (i)],
    //     Reason Phrase Length (i),
    //     Reason Phrase (..),
    //   }
    //
    // THE BRACKETED FIELD IS THE WHOLE DIFFICULTY. s19.19, Frame Type: "A
    // variable-length integer encoding the type of frame that triggered the error. A
    // value of 0 (equivalent to the mention of the PADDING frame) is used when the
    // frame type is unknown. The application-specific variant of CONNECTION_CLOSE
    // (type 0x1d) does not include this field." So the two forms differ in which
    // fields exist, not merely in what they mean - the same shape as STREAM's OFF
    // and LEN bits, with one bit instead of three. Every check below is reachable
    // from both forms unless its comment says otherwise, and carries a row for each.
    //
    // Same Try-shaped contract as TryReadResetStream; the "advances only on success"
    // half is observable - the reason-phrase extent check fires with two or three
    // varints already walked - and is pinned by
    // TlsQuicConnectionFramesTests.TryReadConnectionCloseCommitsNothingWhenIts
    // ReasonPhraseOverruns.
    internal static bool TryReadConnectionClose(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        ulong rawType,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;
        var walked = offset;

        // 0 is not a "missing value" placeholder for the absent form - s19.19 gives
        // 0 the meaning "the frame type is unknown", so an application-form frame
        // decodes to exactly the value the transport form would carry if its sender
        // did not know what triggered the error. TlsQuicFrame.RawType is what
        // separates the two, which is why there is no second field recording the
        // form.
        //
        // FIVE PATHS CAN REJECT THIS FRAME BELOW, not three: the transport form
        // can be truncated in any of its three fields and the application form in
        // either of its two, and the Frame Type read exists on only one of the two
        // forms. All five are rows of
        // TlsQuicConnectionFramesTests.ConnectionCloseTruncatedInAnyFieldIsRejected.
        // Each of the three checks below reports the same FRAME_ENCODING_ERROR,
        // chosen directly rather than derived from a caught exception - per s12.4
        // "cannot span multiple packets", so a field running off the end of an
        // already-decrypted payload is malformed rather than incomplete.
        //
        // s19.19, Error Code: "A variable-length integer that indicates the
        // reason for closing this connection. A CONNECTION_CLOSE frame of type
        // 0x1c uses codes from the space defined in Section 20.1. A
        // CONNECTION_CLOSE frame of type 0x1d uses codes defined by the
        // application protocol; see Section 20.2." Both spaces are open - s20.1
        // reserves 0x0100-0x01ff for CRYPTO_ERROR and s22.5 registers new codes -
        // so the value is not validated against TlsQuicTransportError here, which
        // lists only the codes this library raises.
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var errorCode))
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // The field presence rule quoted above. Mutation check (performed and
        // reverted): deleting the IsApplicationError condition, so the Frame Type
        // is read unconditionally, makes an application-form frame consume its
        // Reason Phrase Length as a Frame Type - it fails the 0x1d rows of
        // TlsQuicConnectionFramesTests.ConnectionCloseFramesParseBackToTheir
        // Fields and of
        // TlsQuicConnectionFramesTests.ConnectionCloseWithAnEmptyReasonPhrase
        // RoundTrips, and nothing else. Inverting it to
        // IsApplicationError(rawType) fails the 0x1c rows of the same two.
        ulong triggerFrameType = 0;
        if (!IsApplicationError(rawType) &&
            !QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out triggerFrameType))
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // s19.19, Reason Phrase Length: "A variable-length integer specifying
        // the length of the reason phrase in bytes."
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var reasonPhraseLength))
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // The extent check, same form and same reasoning as TryReadNewToken's -
        // compared as a ulong, nothing sized from it, s12.4's "cannot span multiple
        // packets" making an overrun malformed rather than incomplete.
        //
        // Reachable from both forms, so both are rows of
        // TlsQuicConnectionFramesTests.ConnectionCloseWhoseReasonPhraseLength
        // OverrunsThePayloadIsRejected. Mutation checks (performed and reverted):
        // deleting it fails three - both rows, which throw
        // ArgumentOutOfRangeException out of Memory.Slice, plus
        // TlsQuicConnectionFramesTests.TryReadConnectionCloseCommitsNothingWhenIts
        // ReasonPhraseOverruns; conditioning it on IsApplicationError(rawType) fails
        // the 0x1c row and that same commits-nothing test, and on its negation the
        // 0x1d row alone.
        var remaining = (ulong)(payload.Length - walked);
        if (reasonPhraseLength > remaining)
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // s19.19, Reason Phrase: "Additional diagnostic information for the closure.
        // This can be zero length if the sender chooses not to give details beyond
        // the Error Code value." So unlike NEW_TOKEN's Token there is no lower bound
        // here, and an empty phrase is represented as Empty rather than as a
        // zero-length slice, matching TlsQuicFrame.Data's convention.
        //
        // THE `length == 0 ? Empty :` TERNARY IS VACUOUS TO TEST - dropping it
        // leaves the suite green, and that survival is neither unwitnessed nor a
        // reachability argument. `payload.Slice(walked, 0)` and
        // ReadOnlyMemory<byte>.Empty are indistinguishable through every member a
        // caller can reach: same Length, same IsEmpty, same empty ToArray(). The
        // only difference is invisible to a test - a zero-length slice still holds
        // a reference to the datagram array, so it keeps that buffer alive for as
        // long as the frame is, while Empty roots nothing. That is a lifetime
        // property, and this is defence in depth for it rather than a pinnable
        // behaviour. A test written here would pass against the mutant, which is
        // the false witness the A2 plan's third survivor category is about.
        //
        // The SHOULD
        // that it "be a UTF-8 encoded string" is not enforced: it is a SHOULD, the
        // bytes are the peer's, and rejecting a close frame because its diagnostic
        // text is malformed would turn a clean shutdown into a parse failure.
        var length = (int)reasonPhraseLength;
        frame = new TlsQuicFrame
        {
            RawType = rawType,
            ErrorCode = errorCode,
            TriggerFrameType = triggerFrameType,
            ReasonPhrase = length == 0 ? ReadOnlyMemory<byte>.Empty : payload.Slice(walked, length),
        };
        offset = walked + length;
        return true;
    }

    // Appends one RESET_STREAM frame's wire bytes to destination (RFC 9000 s19.4
    // Figure 28). The low-level writer TlsQuicFrames.WriteFrame's ResetStream case
    // dispatches to, named after TlsQuicStreamFrames.WriteStreamFrameFields and
    // playing the same role.
    //
    // Caller-chosen input, so a rejection throws rather than returning false - same
    // split as WriteFrame versus TryReadFrame. Every check runs before the first
    // byte is written, so a rejection never leaves a partial frame in the caller's
    // buffer, and the tests seed `destination` with a sentinel byte and assert it is
    // still alone rather than only asserting the exception type.
    //
    // frame.RawType is not validated in any writer in this file. WriteFrame
    // dispatches on the derived TlsQuicFrame.Type, and of this file's eight types
    // only CONNECTION_CLOSE is the base of a Table 3 range, so for the other seven
    // exactly one RawType derives to the Type that reached the writer and a range
    // check would be dead code - the same argument
    // TlsQuicStreamFrames.WriteCryptoFrameFields makes for 0x06.
    internal static void WriteResetStreamFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        // Three separate bounds, not a loop, and each is reachable one way only -
        // 0x04 is this method's single type path - so one witness each, distinguished
        // by ParamName. They throw the same exception type on the same kind of value,
        // so ParamName is the only thing that tells them apart; all three names below
        // are string literals in RequireEncodableVarint's message and NOT
        // nameof()-derived, since there is no parameter of any of those names on this
        // method. Renaming the TlsQuicFrame properties will not update them and the
        // tests asserting on ParamName will not fail if they go stale.
        //
        // All three fields are caller-supplied and bounded by nothing but the varint
        // range - the plan's rule that a write-side bound on a caller-supplied field
        // is always reachable. Checked here rather than left to the encoder because
        // the frame type is written first: without these,
        // QuicVariableLengthInteger.Write would throw ArgumentOutOfRangeException
        // with the type byte already in the caller's buffer.
        //
        // Neither s19.4 nor s4.5 puts a tighter bound on any of the three. s20 caps
        // an application error code at 62 bits ("QUIC transport error codes and
        // application error codes are 62-bit unsigned integers"), which is the same
        // bound the varint encoding imposes, so there is no second check to add for
        // it - the one below is that sentence and s16's at once.
        //
        // Mutation checks (performed and reverted), each failing exactly its own row
        // of TlsQuicConnectionFramesTests.WritingAResetStreamFrameWhoseFieldsExceed
        // TheVarintMaximumThrows and nothing else: deleting any one call fails that
        // field's row with ArgumentOutOfRangeException (a different exact type,
        // naming a parameter "value" this namespace does not have) and with bytes
        // already in the destination.
        RequireEncodableVarint(frame.StreamId, "streamId");
        RequireEncodableVarint(frame.ApplicationProtocolErrorCode, "applicationProtocolErrorCode");
        RequireEncodableVarint(frame.FinalSize, "finalSize");

        // UNREACHABLE, NOT UNWITNESSED: replacing frame.RawType with
        // (ulong)frame.Type here leaves the whole Quic suite green, and that survival
        // is correct. Reaching this method requires frame.Type to be ResetStream, and
        // 0x04 is not the base of a Table 3 flag range, so TlsQuicFrame.Type's
        // fall-through arm maps it to itself and the two expressions are the same
        // number for every input. The same honest gap TlsQuicFrames.WriteFrame's
        // Padding/Ping/HandshakeDone arm records. It closes only if Table 3 ever
        // gives 0x04 a flag, which no QUIC v1 extension in scope does. RawType is
        // written anyway so that all seven writers here read alike, and because
        // WriteConnectionCloseFrameFields' identical line IS pinned.
        QuicVariableLengthInteger.Write(destination, frame.RawType);
        QuicVariableLengthInteger.Write(destination, frame.StreamId);
        QuicVariableLengthInteger.Write(destination, frame.ApplicationProtocolErrorCode);
        QuicVariableLengthInteger.Write(destination, frame.FinalSize);
    }

    // Appends one STOP_SENDING frame's wire bytes to destination (RFC 9000 s19.5
    // Figure 29). Same contract as WriteResetStreamFrameFields, and the same
    // dead-code argument against validating RawType: 0x05 is not a range base
    // either, so the (ulong)frame.Type mutation survives here too and correctly.
    internal static void WriteStopSendingFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        // Two bounds, one path each, one witness each - the rows of
        // TlsQuicConnectionFramesTests.WritingAStopSendingFrameWhoseFieldsExceedThe
        // VarintMaximumThrows, whose other field is left legal so that exactly one
        // call can fire and ParamName identifies which.
        RequireEncodableVarint(frame.StreamId, "streamId");
        RequireEncodableVarint(frame.ApplicationProtocolErrorCode, "applicationProtocolErrorCode");

        QuicVariableLengthInteger.Write(destination, frame.RawType);
        QuicVariableLengthInteger.Write(destination, frame.StreamId);
        QuicVariableLengthInteger.Write(destination, frame.ApplicationProtocolErrorCode);
    }

    // Appends one NEW_TOKEN frame's wire bytes to destination (RFC 9000 s19.7
    // Figure 31). Same contract as WriteResetStreamFrameFields.
    internal static void WriteNewTokenFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        // The write-side half of s19.7's "The token MUST NOT be empty", which binds
        // the sender directly rather than by way of the receiver's connection error.
        // The failure mode if it were written anyway is not silence but a peer that
        // MUST close the connection, since s19.7 makes an empty Token field a
        // FRAME_ENCODING_ERROR at the client.
        //
        // Mutation check (performed and reverted): deleting this check makes
        // TlsQuicConnectionFramesTests.WritingANewTokenFrameWithAnEmptyTokenThrows
        // write a two-byte frame (type and a zero length) instead of throwing, so
        // nothing throws at all - the sentinel assertion is not what catches it, the
        // missing exception is.
        if (frame.Token.Length == 0)
        {
            throw new ArgumentException(
                $"A NEW_TOKEN frame cannot carry an empty token (RFC 9000 s19.7: \"The token MUST " +
                $"NOT be empty. A client MUST treat receipt of a NEW_TOKEN frame with an empty " +
                $"Token field as a connection error of type FRAME_ENCODING_ERROR\"), but " +
                $"{nameof(frame)}.{nameof(TlsQuicFrame.Token)} is empty.",
                nameof(frame));
        }

        // NO RequireEncodableVarint FOR THE TOKEN LENGTH, deliberately: it is
        // frame.Token.Length, a non-negative int, so it is at most 2^31 - 1 and
        // cannot reach the 2^62 - 1 varint maximum. A check would be dead code and
        // its own mutation-pin unkillable - the shadowed-check trap the A2 plan
        // warns about. Same reasoning as TlsQuicStreamFrames' handling of
        // frame.Data.Length.
        QuicVariableLengthInteger.Write(destination, frame.RawType);
        QuicVariableLengthInteger.Write(destination, (ulong)frame.Token.Length);
        WriteBytes(destination, frame.Token);
    }

    // Appends one NEW_CONNECTION_ID frame's wire bytes to destination (RFC 9000
    // s19.15 Figure 39). Same contract as WriteResetStreamFrameFields.
    internal static void WriteNewConnectionIdFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        // Caller-supplied and bounded by nothing, so reachable; one path.
        RequireEncodableVarint(frame.SequenceNumber, "sequenceNumber");

        // The write-side half of s19.15's ordering constraint, quoted in full at
        // TryReadNewConnectionId. Caller-supplied on both sides here, so it is
        // reachable for the reason the read-side twin is also reachable and then
        // some: either field can be anything up to 2^64 - 1.
        //
        // NO SEPARATE RequireEncodableVarint FOR Retire Prior To, and this is a
        // transitivity argument rather than an oversight. The check above leaves
        // SequenceNumber <= 2^62 - 1, and this check leaves RetirePriorTo <=
        // SequenceNumber, so RetirePriorTo <= 2^62 - 1 follows. Placed AFTER this
        // check an encodability test on it could therefore never fire - dead code,
        // and its own mutation-pin unkillable. Placed BEFORE it, it would fire only
        // for inputs this check already rejects: it would change the reported
        // ParamName and nothing else, which is the shadowed check the plan's
        // standing rule warns about. Neither placement adds a rejection. That is
        // also why the rejecting theory below carries a second
        // magnitude: at seq = 2^62 - 1 and retire = 2^62 the value really is
        // unencodable, and deleting this check is what would let it reach the
        // encoder.
        //
        // Mutation checks (performed and reverted), against
        // TlsQuicConnectionFramesTests.WritingANewConnectionIdFrameWhoseRetirePrior
        // ToExceedsItsSequenceNumberThrows:
        //   * deleting the check - fails both rows: the encodable row because
        //     nothing throws at all and a frame violating a MUST goes on the wire,
        //     the unencodable row on both exception type and sentinel, since
        //     QuicVariableLengthInteger.Write then throws
        //     ArgumentOutOfRangeException with the type byte and the sequence number
        //     already in the destination.
        //   * weakening it to >= - fails
        //     TlsQuicConnectionFramesTests.WritingANewConnectionIdFrameWhoseRetire
        //     PriorToEqualsItsSequenceNumberSucceeds, which is s19.15's "less than
        //     or equal to".
        if (frame.RetirePriorTo > frame.SequenceNumber)
        {
            throw new ArgumentException(
                $"A NEW_CONNECTION_ID frame's Retire Prior To ({frame.RetirePriorTo}) exceeds its " +
                $"Sequence Number ({frame.SequenceNumber}) (RFC 9000 s19.15: \"The value in the " +
                $"Retire Prior To field MUST be less than or equal to the value in the Sequence " +
                "Number field\").",
                nameof(frame));
        }

        // The write-side half of s19.15's connection ID length range. Two paths
        // through one check - too short and too long - each with its own row, the
        // same non-flag axis the read-side twin has.
        //
        // Mutation checks (performed and reverted), against
        // TlsQuicConnectionFramesTests.WritingANewConnectionIdFrameWithAnOutOfRange
        // ConnectionIdLengthThrows: deleting the check fails both rows - the empty
        // row writes a frame with a zero length byte, the 21-byte row writes one
        // whose length byte is 0x15, and neither throws; dropping either half of the
        // comparison fails that half's row.
        if (frame.ConnectionId.Length < MinimumConnectionIdLength ||
            frame.ConnectionId.Length > MaximumConnectionIdLength)
        {
            throw new ArgumentException(
                $"A NEW_CONNECTION_ID frame's connection ID is {frame.ConnectionId.Length} bytes, " +
                $"outside the {MinimumConnectionIdLength} to {MaximumConnectionIdLength} RFC 9000 " +
                "s19.15 allows (\"Values less than 1 and greater than 20 are invalid and MUST be " +
                "treated as a connection error of type FRAME_ENCODING_ERROR\").",
                nameof(frame));
        }

        // The stateless reset token has no length field on the wire at all, so a
        // token of the wrong size cannot be encoded - it would silently shift every
        // byte after it. Exact equality, not a range: s19.15 Figure 39 fixes the
        // width at 128 bits.
        //
        // Mutation checks (performed and reverted), against
        // TlsQuicConnectionFramesTests.WritingANewConnectionIdFrameWithAWrongLength
        // StatelessResetTokenThrows, whose three rows are empty, one byte short and
        // one byte long: deleting the check fails all three, writing frames that are
        // 16, 15 and 17 bytes of token respectively; weakening it to `<` fails the
        // 17-byte row alone; to `>` fails the other two.
        if (frame.StatelessResetToken.Length != StatelessResetTokenLength)
        {
            throw new ArgumentException(
                $"A NEW_CONNECTION_ID frame's stateless reset token is " +
                $"{frame.StatelessResetToken.Length} bytes; RFC 9000 s19.15 makes it \"A 128-bit " +
                $"value\", so it must be exactly {StatelessResetTokenLength}.",
                nameof(frame));
        }

        QuicVariableLengthInteger.Write(destination, frame.RawType);
        QuicVariableLengthInteger.Write(destination, frame.SequenceNumber);
        QuicVariableLengthInteger.Write(destination, frame.RetirePriorTo);

        // The Length field is one byte, not a varint - s19.15: "An 8-bit unsigned
        // integer containing the length of the connection ID." The cast is safe
        // because the range check above leaves the value between 1 and 20.
        //
        // Mutation check (performed and reverted): writing this through
        // QuicVariableLengthInteger.Write instead emits the same single byte for
        // every legal length, since 20 is below the 63 the one-byte varint form
        // reaches - so that mutation survives, and it survives *correctly* only
        // because the range check makes the two encodings agree over the whole legal
        // range. Recorded rather than tested: no legal frame can separate them, and
        // a test would have to construct an illegal one.
        destination.Add((byte)frame.ConnectionId.Length);
        WriteBytes(destination, frame.ConnectionId);
        WriteBytes(destination, frame.StatelessResetToken);
    }

    // Appends one RETIRE_CONNECTION_ID frame's wire bytes to destination (RFC 9000
    // s19.16 Figure 40). Same contract as WriteResetStreamFrameFields.
    internal static void WriteRetireConnectionIdFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        // One field, one path, one witness -
        // TlsQuicConnectionFramesTests.WritingARetireConnectionIdFrameAboveThe
        // VarintMaximumThrows.
        RequireEncodableVarint(frame.SequenceNumber, "sequenceNumber");

        QuicVariableLengthInteger.Write(destination, frame.RawType);
        QuicVariableLengthInteger.Write(destination, frame.SequenceNumber);
    }

    // Appends one PATH_CHALLENGE (RFC 9000 s19.17 Figure 41) or PATH_RESPONSE
    // (s19.18 Figure 42) frame's wire bytes to destination. One writer for two frame
    // types for the reason TryReadPathData gives - s19.18 declares the formats
    // identical - so a mutation here fails rows belonging to both.
    //
    // Same contract as WriteResetStreamFrameFields. Neither 0x1a nor 0x1b is a range
    // base, so the (ulong)frame.Type mutation survives here as well, and correctly.
    internal static void WritePathDataFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        // The write-side half of the fixed-width field. Exact equality, and both
        // directions matter: a short Data would be padded by whatever frame follows
        // it and a long one would leave trailing bytes that the peer reads as
        // another frame, so neither is representable on the wire.
        //
        // Reachable from both type values, and the rejecting theory crosses the two
        // types with three lengths - empty, one short, one long. Mutation checks
        // (performed and reverted): deleting the check fails all six rows, since
        // nothing throws; weakening it to `<` fails the two 9-byte rows; to `>` the
        // four shorter ones; conditioning it on frame.RawType == 0x1a fails the
        // three 0x1b rows, and vice versa - the two-path mutation the plan's rule
        // asks for.
        if (frame.Data.Length != PathDataLength)
        {
            throw new ArgumentException(
                $"A PATH_CHALLENGE or PATH_RESPONSE frame carries {frame.Data.Length} bytes of " +
                $"data; RFC 9000 s19.17 makes it \"This 8-byte field contains arbitrary data\", so " +
                $"it must be exactly {PathDataLength}.",
                nameof(frame));
        }

        QuicVariableLengthInteger.Write(destination, frame.RawType);
        WriteBytes(destination, frame.Data);
    }

    // Appends one CONNECTION_CLOSE frame's wire bytes to destination (RFC 9000
    // s19.19 Figure 43), in whichever of the two forms frame.RawType selects. Same
    // contract as WriteResetStreamFrameFields.
    //
    // THE ONE WRITER IN THIS FILE WHERE frame.RawType IS LOAD-BEARING rather than
    // equal to (ulong)frame.Type by construction: 0x1c and 0x1d both derive to
    // TlsQuicFrameType.ConnectionClose, so a writer that emitted the derived value
    // would silently turn every application close into a transport one - and would
    // then emit a Frame Type field the peer does not expect, shifting the whole rest
    // of the frame. That is the same mutation
    // TlsQuicFlowControlFrames.WriteMaximumStreamsFrameFields records, and the reason
    // this file's CONNECTION_CLOSE vectors cover both type values.
    //
    // RawType is still not validated: TlsQuicFrame.Type derives ConnectionClose only
    // from 0x1c..0x1d, so by the time WriteFrame has dispatched here RawType is
    // already one of those two values and a range check could not fire.
    internal static void WriteConnectionCloseFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        // Caller-supplied, bounded only by s20's "62-bit unsigned integers", which is
        // the varint range. REACHABLE FROM BOTH FORMS, so both are rows of
        // TlsQuicConnectionFramesTests.WritingAConnectionCloseFrameWhoseErrorCode
        // ExceedsTheVarintMaximumThrows. Mutation checks (performed and reverted):
        // deleting the call fails both rows with ArgumentOutOfRangeException and the
        // type byte already written; conditioning it on IsApplicationError(RawType)
        // fails the 0x1c row alone, and on its negation the 0x1d row.
        RequireEncodableVarint(frame.ErrorCode, "errorCode");

        if (IsApplicationError(frame.RawType))
        {
            // s19.19: "The application-specific variant of CONNECTION_CLOSE (type
            // 0x1d) does not include this field." There is nowhere to put a
            // triggering frame type in this form, so a caller that set one asked for
            // something the frame cannot express and writing anyway would drop it
            // silently. Same defect class as
            // TlsQuicStreamFrames.WriteCryptoFrameFields' rejection of a CRYPTO
            // frame carrying a stream ID, and as its OFF-clear/Offset contradiction.
            //
            // SINGLE PATH, CHECKED AND SINGLE-PATH ON PURPOSE: only 0x1d can reach
            // it, because it is inside this branch. The converse - a 0x1c frame
            // leaving TriggerFrameType at 0 - is legal and needs no check, since
            // s19.19 assigns 0 the meaning "the frame type is unknown". That
            // legality is a claim, so it is pinned rather than asserted: the
            // Frame-Type-0 row of
            // TlsQuicConnectionFramesTests.ConnectionCloseFramesMatchTheirHand
            // DerivedBytes is a transport-form close carrying 0, and it is the only
            // thing in the suite that stops the presence guard below being narrowed
            // to skip exactly that frame.
            //
            // Mutation check (performed and reverted): deleting this check makes
            // TlsQuicConnectionFramesTests.WritingAnApplicationConnectionClose
            // CarryingATriggerFrameTypeThrows write a valid-looking 0x1d frame with
            // the field silently dropped, so nothing throws.
            if (frame.TriggerFrameType != 0)
            {
                throw new ArgumentException(
                    $"A CONNECTION_CLOSE frame of type 0x{frame.RawType:x2} carries no Frame Type " +
                    $"field (RFC 9000 s19.19: \"The application-specific variant of " +
                    $"CONNECTION_CLOSE (type 0x1d) does not include this field\"), but " +
                    $"{nameof(frame)}.{nameof(TlsQuicFrame.TriggerFrameType)} is " +
                    $"{frame.TriggerFrameType}. Use type 0x1c to report a triggering frame type.",
                    nameof(frame));
            }
        }
        else
        {
            // Caller-supplied and bounded by nothing, so reachable - but reachable
            // from the transport form ONLY, since the application form has no such
            // field. Recorded as checked-and-single-path so a later reader can tell
            // it from the guards above that carry a row per form; its one witness is
            // TlsQuicConnectionFramesTests.WritingAConnectionCloseFrameWhoseTrigger
            // FrameTypeExceedsTheVarintMaximumThrows.
            //
            // Mutation check (performed and reverted): deleting the call fails that
            // test with ArgumentOutOfRangeException and the type and error code bytes
            // already in the destination.
            RequireEncodableVarint(frame.TriggerFrameType, "triggerFrameType");
        }

        QuicVariableLengthInteger.Write(destination, frame.RawType);
        QuicVariableLengthInteger.Write(destination, frame.ErrorCode);

        // The bracketed field, on the form that has it - and the guard this file's
        // review found under-witnessed, which is worth recording at the line rather
        // than only in the test.
        //
        // NARROWING IT TO `&& frame.TriggerFrameType != 0` LEFT THE WHOLE SUITE
        // GREEN when this task first landed. Every 0x1c vector carried Frame Type
        // 0x08, and nothing wrote the transport form with 0 - which s19.19 makes
        // the value for "the frame type is unknown" and so the commonest
        // CONNECTION_CLOSE a real peer sends. Under that mutant the field vanishes
        // and the peer reads the Reason Phrase Length as the trigger type. The
        // zero-versus-absent axis of the A2 plan's standing rule, landing on the
        // one value most likely to appear in production.
        //
        // Mutation checks (performed and reverted), measured after the
        // Frame-Type-0 row was added:
        //   * narrowing it to `&& frame.TriggerFrameType != 0` - fails one, that
        //     new row, and nothing else. It failed nothing before the row existed.
        //   * deleting the condition, so the Frame Type is always written - fails
        //     two, the 0x1d rows of
        //     TlsQuicConnectionFramesTests.ConnectionCloseFramesMatchTheirHand
        //     DerivedBytes and of
        //     TlsQuicConnectionFramesTests.ConnectionCloseWithAnEmptyReasonPhrase
        //     RoundTrips.
        //   * inverting it - fails five, every row of those two theories.
        if (!IsApplicationError(frame.RawType))
        {
            QuicVariableLengthInteger.Write(destination, frame.TriggerFrameType);
        }

        // No RequireEncodableVarint for the Reason Phrase Length, for the reason
        // WriteNewTokenFrameFields gives about the Token Length: it is an int
        // length, so the check would be dead.
        QuicVariableLengthInteger.Write(destination, (ulong)frame.ReasonPhrase.Length);
        WriteBytes(destination, frame.ReasonPhrase);
    }

    // The fixed-width fields of s19.15 and s19.17 / s19.18: takes exactly `length`
    // bytes if they are there, and reports rather than throwing if they are not.
    // Three call sites - a connection ID, a stateless reset token and a path
    // challenge's data - differing only in the length they ask for, which is the
    // whole of what the three fields have in common and the whole of what this
    // shares.
    //
    // THE TRAP, FOR THE NEXT CALLER: this reports rather than throwing and leaves
    // `walked` untouched on failure, so CHAINING TWO CALLS WITH `||` makes the
    // first call's failure indistinguishable from the second's - the short field is
    // simply skipped and the next one consumes its bytes. Each call site therefore
    // needs its own witness, and the obvious truncation input does not provide one:
    // it has to be an input where the LATER field's bytes are all present and only
    // the earlier one is short. That cost a row to discover; see
    // TryReadNewConnectionId's two chained calls and the third row of
    // TlsQuicConnectionFramesTests.NewConnectionIdTruncatedInItsConnectionIdOr
    // TokenIsRejected.
    //
    // On success `walked` has advanced past the field; on failure it is exactly as
    // passed in. That failure-path guarantee is DEFENCE IN DEPTH rather than a
    // pinned contract, the same status TlsQuicStreamFrames.TryReadData records: every
    // caller passes its own local `walked` and none publishes it when this returns
    // false, so a version that advanced before failing would behave identically
    // through every reachable caller. Written this way anyway so that the callers'
    // guarantee - which IS pinned - holds by construction rather than by an
    // ordering argument a later edit could break. Making it observable would mean
    // widening it for a test, which is scaffolding, not coverage.
    //
    // `payload.Length - length` is not used as the comparison, deliberately:
    // `payload.Length - walked` cannot be negative (every caller's `walked` is at
    // most payload.Length) and `length` is a small non-negative int at all three
    // call sites, so neither side can wrap.
    private static bool TryTakeFixed(
        ReadOnlyMemory<byte> payload,
        ref int walked,
        int length,
        out ReadOnlyMemory<byte> taken)
    {
        if (payload.Length - walked < length)
        {
            taken = ReadOnlyMemory<byte>.Empty;
            return false;
        }

        taken = payload.Slice(walked, length);
        walked += length;
        return true;
    }

    // RFC 9000 s16 leaves a variable-length integer 62 value bits, so
    // QuicVariableLengthInteger.MaximumValue is 2^62 - 1 and a larger value has no
    // encoding. ArgumentException matching every other caller-input rejection in
    // this namespace, rather than the ArgumentOutOfRangeException the encoder would
    // raise on its own - and raised before any byte is written, which the encoder's
    // own throw would not be. The same helper TlsQuicStreamFrames,
    // TlsQuicAckFrames and TlsQuicFlowControlFrames each keep privately; not hoisted
    // into one shared home, because the four differ in the frame family their
    // message names and that prefix is what tells a reader which frame rejected them.
    //
    // parameterName is a string literal at every call site above; see
    // WriteResetStreamFrameFields for why that matters to the tests.
    private static void RequireEncodableVarint(ulong value, string parameterName)
    {
        if (value > QuicVariableLengthInteger.MaximumValue)
        {
            throw new ArgumentException(
                $"Connection frame {parameterName} ({value}) exceeds the largest " +
                $"variable-length integer value, {QuicVariableLengthInteger.MaximumValue} " +
                "(RFC 9000 s16).",
                parameterName);
        }
    }

    // A byte field copied verbatim - a token, a connection ID, a stateless reset
    // token, a path challenge's data or a reason phrase, all of which are already
    // exactly the bytes the frame carries. Same shape as
    // TlsQuicStreamFrames.WriteData and TlsQuicAckFrames.WriteFrameFields' AckRanges
    // copy.
    private static void WriteBytes(List<byte> destination, ReadOnlyMemory<byte> bytes)
    {
        foreach (var b in bytes.Span)
        {
            destination.Add(b);
        }
    }
}
