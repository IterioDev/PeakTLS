namespace SharpTls.Quic;

// The six flow-control frames of RFC 9000 s19, both directions: s19.9 MAX_DATA
// (type 0x10), s19.10 MAX_STREAM_DATA (0x11), s19.11 MAX_STREAMS (0x12..0x13),
// s19.12 DATA_BLOCKED (0x14), s19.13 STREAM_DATA_BLOCKED (0x15) and s19.14
// STREAMS_BLOCKED (0x16..0x17).
//
// Pure functions. This file decides how the six frames are written and read and
// nothing else - NO FLOW-CONTROL ACCOUNTING, no window tracking, no limit
// enforcement, no connection or stream state. Those sections are mostly *about*
// accounting, so a reviewer reading s19.9 to s19.14 against this file will find
// far more MUSTs there than checks here, and what is deliberately absent is worth
// listing so that absence is not mistaken for an oversight:
//
//   * s19.9: "An endpoint MUST terminate a connection with an error of type
//     FLOW_CONTROL_ERROR if it receives more data than the maximum data value
//     that it has sent." Needs the limit this endpoint last advertised and the
//     running total every STREAM frame contributed to it. Neither exists here.
//   * s19.10: "Receiving a MAX_STREAM_DATA frame for a locally initiated stream
//     that has not yet been created MUST be treated as a connection error of type
//     STREAM_STATE_ERROR", and the same code again for a receive-only stream.
//     Needs the stream state machine, which is phase A4's.
//   * s19.11: "MAX_STREAMS frames that do not increase the stream limit MUST be
//     ignored", and "An endpoint MUST terminate a connection with an error of
//     type STREAM_LIMIT_ERROR if a peer opens more streams than was permitted."
//     Both need the limit previously received; the second also needs to know
//     which streams the peer has opened.
//   * s19.13: "An endpoint that receives a STREAM_DATA_BLOCKED frame for a
//     send-only stream MUST terminate the connection with error
//     STREAM_STATE_ERROR." Stream state again.
//
// Exactly one rule in those six sections IS enforced here, and it is the only one
// that can be: s19.11's and s19.14's bound on the stream count, which is a
// property of the single field in front of you and needs no state at all. See
// <see cref="MaximumStreamCount"/>.
//
// THREE WIRE SHAPES, SIX FRAME TYPES - which is why this file has three readers
// and three writers rather than six of each. The shapes are the RFC's own field
// lists, Figures 33 to 38, side by side:
//
//   MAX_DATA Frame {                DATA_BLOCKED Frame {
//     Type (i) = 0x10,                Type (i) = 0x14,
//     Maximum Data (i),               Maximum Data (i),
//   }                               }
//
//   MAX_STREAM_DATA Frame {         STREAM_DATA_BLOCKED Frame {
//     Type (i) = 0x11,                Type (i) = 0x15,
//     Stream ID (i),                  Stream ID (i),
//     Maximum Stream Data (i),        Maximum Stream Data (i),
//   }                               }
//
//   MAX_STREAMS Frame {             STREAMS_BLOCKED Frame {
//     Type (i) = 0x12..0x13,          Type (i) = 0x16..0x17,
//     Maximum Streams (i),            Maximum Streams (i),
//   }                               }
//
// Each pair is field-for-field identical down to the field *names*, so the
// sharing is the RFC's rather than this file's invention: a helper per pair is one
// implementation of one figure, not one implementation smoothing over two. That is
// the bar A2's task 2 post-mortem set - shared code has to be demonstrably shared,
// and here a mutation anywhere inside one of these six methods fails tests for
// both of its frame types, which is recorded per method below.
//
// The pairing is by shape, not by meaning, and those are not the same thing: a
// MAX_DATA frame grants credit where a DATA_BLOCKED frame reports having run out
// of it, and s19.13's Maximum Stream Data is "the offset of the stream at which
// the blocking occurred" where s19.10's is a limit that may never be reached. All
// of that difference is in what a later phase does with the frame. The bytes and
// their validity are identical, and the bytes are all this layer has - so the six
// methods below are named after the RFC field they carry rather than after a
// semantic gloss, which would be wrong for one member of every pair.
//
// What is NOT shared across the three pairs, and why there is no single six-way
// helper: only the second shape carries a Stream ID, and only the third is bounded
// by s19.11's stream count. A six-way helper would carry both differences as
// conditionals over the frame type, which is exactly the "cuts horizontally
// through one frame type" shape the plan's file-layout amendment was written
// about.
internal static class TlsQuicFlowControlFrames
{
    /// <summary>
    /// The low bit that separates the two type values of each ranged frame in
    /// this file. RFC 9000 s19.11: "A MAX_STREAMS frame with a type of 0x12
    /// applies to bidirectional streams, and a MAX_STREAMS frame with a type of
    /// 0x13 applies to unidirectional streams." s19.14 pairs its own two values
    /// the same way: "A STREAMS_BLOCKED frame of type 0x16 is used to indicate
    /// reaching the bidirectional stream limit, and a STREAMS_BLOCKED frame of
    /// type 0x17 is used to indicate reaching the unidirectional stream limit."
    /// </summary>
    /// <remarks>
    /// Neither section calls this a bit - each simply lists two values, unlike
    /// s19.8, which names OFF, LEN and FIN and gives each a mask. What licenses
    /// reading it as a flag is s12.4: "The Frame Type in ACK, STREAM,
    /// MAX_STREAMS, STREAMS_BLOCKED, and CONNECTION_CLOSE frames is used to
    /// carry other frame-specific flags." Both of this file's ranged types are
    /// in that list, and in both the unidirectional value is the odd one.
    /// </remarks>
    internal const ulong UnidirectionalBit = 0x01;

    /// <summary>
    /// The largest stream count a MAX_STREAMS or a STREAMS_BLOCKED frame may
    /// carry: 2^60. RFC 9000 s19.11, of MAX_STREAMS' Maximum Streams field:
    /// "This value cannot exceed 2^60, as it is not possible to encode stream
    /// IDs larger than 2^62-1." s19.14 carries that sentence verbatim for
    /// STREAMS_BLOCKED's field of the same name; only the sentence naming the
    /// consequence differs between the two, for which see
    /// <see cref="TryReadMaximumStreams"/>. "Cannot exceed" makes 2^60 itself
    /// legal, so 2^60 + 1 is the smallest illegal value and both comparisons
    /// against this constant are strict.
    /// </summary>
    /// <remarks>
    /// Where the factor of four comes from, taken from s19.11's own worked
    /// example rather than reconstructed: "a server that receives a
    /// unidirectional stream limit of 3 is permitted to open streams 3, 7, and
    /// 11, but not stream 15." A limit of N therefore reaches stream ID 4N - 1
    /// at the most, and 4N - 1 &lt;= 2^62 - 1 gives N &lt;= 2^60. So this is one
    /// quarter of 2^62 - it is neither QuicVariableLengthInteger.MaximumValue
    /// (2^62 - 1) nor half of it, and being *below* the varint maximum is what
    /// makes it the one bound in this file that a decoded value can violate.
    /// </remarks>
    internal const ulong MaximumStreamCount = 1UL << 60;

    /// <summary>
    /// Whether a MAX_STREAMS or STREAMS_BLOCKED frame with this exact wire type
    /// concerns unidirectional streams rather than bidirectional ones. Only
    /// meaningful for the four values RFC 9000 s12.4 Table 3 assigns to those two
    /// frames - 0x12, 0x13, 0x16 and 0x17 - and unenforced, the same documented
    /// precondition <see cref="TlsQuicStreamFrames.IsFin"/> carries, with the same
    /// aliasing hazard: this takes a bare ulong, so IsUnidirectional(0x03) returns
    /// true for what is really an ECN-bearing ACK. Nothing is wrong today because
    /// TlsQuicFrames.TryReadFrame's case labels mean the callers have already
    /// matched the type.
    /// </summary>
    /// <remarks>
    /// This is the only way to ask the question, deliberately: the direction lives
    /// in <see cref="TlsQuicFrame.RawType"/> and nowhere else, so there is no
    /// direction field on the struct that could fall out of step with the wire
    /// type. Neither reader nor writer here branches on it - the two type values
    /// of each pair are byte-for-byte the same shape - exactly as nothing in
    /// TlsQuicStreamFrames branches on IsFin. It exists so that phase A3's or A4's
    /// stream-limit bookkeeping does not have to mask by hand, which is the
    /// masking TlsQuicFrameType's own comment says this design avoids.
    /// </remarks>
    internal static bool IsUnidirectional(ulong rawStreamLimitFrameType) =>
        (rawStreamLimitFrameType & UnidirectionalBit) != 0;

    // Reads everything after the frame type of the connection-level pair, s19.9
    // MAX_DATA (Figure 33) and s19.12 DATA_BLOCKED (Figure 36) - one
    // variable-length integer, which both sections call "Maximum Data".
    //
    // rawType is passed through to TlsQuicFrame.RawType rather than branched on:
    // the two frames differ only in that value. Its two reachable values, 0x10 and
    // 0x14, are the two paths through every check in this method, so each check is
    // witnessed twice below.
    //
    // Same Try-shaped contract as TlsQuicFrames.TryReadFrame, its only production
    // caller: never throws for any input, and `offset` only advances on success.
    //
    // The second half of that promise is UNOBSERVABLE HERE, and by construction
    // rather than for want of a test - the distinction the plan's rule turns on.
    // TryReadFrame discards this method's `offset` on failure, so the promise needs
    // a second caller to pin it, and a test can be one (this method is already
    // internal; nothing was widened). But there is nothing for such a test to
    // catch: the only rejection is this reader's single field truncating, and
    // QuicVariableLengthInteger.TryRead only advances the offset it is handed on
    // success, so on a false return `walked` still equals the entry offset and
    // `offset = walked` in the check below is a no-op for every input. A test
    // would pass against the mutated code, which makes it worse than no test.
    //
    // Its two siblings do have rejections that fire with bytes already walked, and
    // both are pinned - see TryReadMaximumStreamData and TryReadMaximumStreams. If
    // this reader ever gains a second field or a bound, it joins them.
    internal static bool TryReadMaximumData(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        ulong rawType,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;
        var walked = offset;

        // s19.9, Maximum Data: "A variable-length integer indicating the
        // maximum amount of data that can be sent on the entire connection,
        // in units of bytes." s19.12's field of the same name is "A
        // variable-length integer indicating the connection-level limit at
        // which blocking occurred" - a different meaning, the same single
        // varint on the wire.
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var maximumData))
        {
            // Same reasoning as TlsQuicFrames.TryReadFrame's own check: the
            // reported code is this namespace's FRAME_ENCODING_ERROR, chosen
            // directly rather than derived from a caught exception - TryRead
            // carries no code of its own. Per s12.4, "Frames always fit within a
            // single QUIC packet and cannot span multiple packets", so a field
            // running off the end of an already-decrypted payload is badly
            // formatted rather than incomplete - there is no continuation to wait
            // for - and s20.1 makes FRAME_ENCODING_ERROR "An endpoint received a
            // frame that was badly formatted".
            //
            // Mutation checks (performed and reverted): see
            // TlsQuicFlowControlFramesTests.MaximumDataFrameTruncatedInItsField
            // IsRejected, whose 0x10 and 0x14 rows are the two paths here -
            // inverting the `!` above fails both, accepting a frame TryRead
            // rejected, and dropping this assignment fails both on the error
            // code. Conditioning either on rawType == 0x10 fails the 0x14 row
            // alone, and vice versa.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        frame = new TlsQuicFrame
        {
            RawType = rawType,
            MaximumData = maximumData,
        };
        offset = walked;
        return true;
    }

    // Reads everything after the frame type of the stream-level pair, s19.10
    // MAX_STREAM_DATA (Figure 34) and s19.13 STREAM_DATA_BLOCKED (Figure 37) -
    // Stream ID then Maximum Stream Data, in that order.
    //
    // The order matters and is the one thing a round-trip test cannot catch: both
    // fields are varints, so a reader that swapped them would decode any frame
    // into two plausible numbers and re-encode them back into the same bytes. It is
    // pinned instead by hand-derived vectors that give the two fields different
    // values; see TlsQuicFlowControlFramesTests.
    //
    // rawType's two reachable values here are 0x11 and 0x15.
    //
    // Same Try-shaped contract as TryReadMaximumData, and unlike that one the
    // "`offset` only advances on success" half IS observable and IS pinned: a frame
    // truncated in its second field fails after the Stream ID has been walked past.
    // TlsQuicFlowControlFramesTests.TryReadMaximumStreamDataCommitsNothingWhenIts
    // SecondFieldIsTruncated calls this directly at a nonzero offset for that.
    internal static bool TryReadMaximumStreamData(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        ulong rawType,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;
        var walked = offset;

        // s19.10, Stream ID: "The stream ID of the affected stream, encoded
        // as a variable-length integer." s19.13's is "A variable-length
        // integer indicating the stream that is blocked due to flow control."
        //
        // s19.10, Maximum Stream Data: "A variable-length integer indicating
        // the maximum amount of data that can be sent on the identified
        // stream, in units of bytes." s19.13's field of the same name is "A
        // variable-length integer indicating the offset of the stream at
        // which the blocking occurred".
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var streamId) ||
            !QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var maximumStreamData))
        {
            // One check for both reads, same reasoning as TryReadMaximumData's.
            // Four paths reach it, not two: either field can be the truncated one,
            // for either frame type. All four are rows of
            // TlsQuicFlowControlFramesTests.MaximumStreamDataFrameTruncatedInEither
            // FieldIsRejected. A frame truncated in its Stream ID and one truncated
            // in its Maximum Stream Data fail at different TryRead calls, so a
            // mutation that dropped the second `!QuicVariableLengthInteger.TryRead`
            // term entirely - checking only the Stream ID - would survive a suite
            // that tested only the Stream-ID-truncated rows.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        frame = new TlsQuicFrame
        {
            RawType = rawType,
            StreamId = streamId,
            MaximumStreamData = maximumStreamData,
        };
        offset = walked;
        return true;
    }

    // Reads everything after the frame type of the stream-count pair, s19.11
    // MAX_STREAMS (Figure 35) and s19.14 STREAMS_BLOCKED (Figure 38) - one
    // variable-length integer, which both sections call "Maximum Streams".
    //
    // rawType has FOUR reachable values here, not two: 0x12 and 0x13 for
    // MAX_STREAMS, 0x16 and 0x17 for STREAMS_BLOCKED. Every check below is
    // therefore reachable four ways and carries four witnesses.
    //
    // Its "`offset` only advances on success" half is pinned at the stream-count
    // bound, which fires with the whole field already walked past, by
    // TlsQuicFlowControlFramesTests.TryReadMaximumStreamsCommitsNothingWhenThe
    // StreamCountBoundRejects - a direct call at a nonzero offset. The check below
    // is the no-op case TryReadMaximumData's comment sets out and is not pinned.
    internal static bool TryReadMaximumStreams(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        ulong rawType,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;
        var walked = offset;

        // s19.11, Maximum Streams: "A count of the cumulative number of
        // streams of the corresponding type that can be opened over the
        // lifetime of the connection." s19.14's is "A variable-length integer
        // indicating the maximum number of streams allowed at the time the
        // frame was sent."
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var maximumStreams))
        {
            // Same reasoning as TryReadMaximumData's own check. Four paths, all
            // four rows of TlsQuicFlowControlFramesTests.MaximumStreamsFrameTruncated
            // InItsFieldIsRejected.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // THE ONE READ-SIDE BOUND IN THIS FILE, and the only one of the six
        // sections' MUSTs this layer can enforce.
        //
        // s19.11, of Maximum Streams: "This value cannot exceed 2^60, as it is
        // not possible to encode stream IDs larger than 2^62-1. Receipt of a
        // frame that permits opening of a stream larger than this limit MUST be
        // treated as a connection error of type FRAME_ENCODING_ERROR." s19.14
        // repeats the bound for STREAMS_BLOCKED and words the consequence
        // slightly differently: "Receipt of a frame that encodes a larger stream
        // ID MUST be treated as a connection error of type STREAM_LIMIT_ERROR or
        // FRAME_ENCODING_ERROR."
        //
        // FRAME_ENCODING_ERROR for both. s19.11 mandates it outright; s19.14
        // offers a choice, and FRAME_ENCODING_ERROR is the member common to the
        // two sections as well as the only one this layer can justify - s20.1
        // makes STREAM_LIMIT_ERROR "An endpoint received a frame for a stream
        // identifier that exceeded its advertised stream limit for the
        // corresponding stream type", which is a statement about what this
        // endpoint advertised and this file has no such state, while a count no
        // stream ID could ever reach is badly formatted on its face. (It is also
        // the only one available: TlsQuicTransportError carries the codes this
        // library actually raises, and 0x04 is not among them.)
        //
        // PROVENANCE: this is a bound on a value QuicVariableLengthInteger.TryRead
        // produced, which the A2 plan's standing rule says is usually
        // unreachable - and it is reachable anyway, for one specific reason. The
        // rule's example, TlsQuicStreamFrames.TryReadData's largest-offset bound,
        // is unreachable because its limit *is* the varint maximum, so a decoded
        // value cannot exceed it. MaximumStreamCount is 2^60, a quarter of the
        // varint maximum, so 2^60 + 1 through 2^62 - 1 all decode fine and all
        // must be rejected here. The rule is about the limit's relation to the
        // varint maximum, not about the value having come from a parser.
        //
        // Mutation checks (performed and reverted), four rows each, one per
        // reachable rawType:
        //   * deleting this comparison - fails the four rejecting rows of
        //     TlsQuicFlowControlFramesTests.MaximumStreamsAboveTheStreamCount
        //     BoundIsRejected.
        //   * weakening it to >= - fails the four rows of
        //     MaximumStreamsAtTheStreamCountBoundIsAccepted, which carry exactly
        //     2^60 because s19.11 says "cannot exceed" rather than "must be less
        //     than".
        //   * conditioning it on any one of rawType == 0x12, == 0x13, == 0x16 or
        //     == 0x17 - fails the other three rejecting rows. This is the
        //     four-path mutation the plan's standing rule asks for, and it is why
        //     the rejecting theory has four rows rather than the one MAX_STREAMS
        //     row an author would naturally reach for.
        if (maximumStreams > MaximumStreamCount)
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        frame = new TlsQuicFrame
        {
            RawType = rawType,
            MaximumStreams = maximumStreams,
        };
        offset = walked;
        return true;
    }

    // Appends one MAX_DATA (s19.9 Figure 33) or DATA_BLOCKED (s19.12 Figure 36)
    // frame's wire bytes to destination. The low-level writer
    // TlsQuicFrames.WriteFrame's MaxData and DataBlocked cases both dispatch to,
    // named after TlsQuicStreamFrames.WriteStreamFrameFields and playing the same
    // role.
    //
    // Caller-chosen input, so a rejection throws rather than returning false -
    // same split as WriteFrame versus TryReadFrame. Every check runs before the
    // first byte is written, so a rejection never leaves a partial frame in the
    // caller's buffer, and the tests seed `destination` with a sentinel and assert
    // it is still alone rather than only asserting the exception type.
    //
    // frame.RawType is not validated. TlsQuicFrames.WriteFrame dispatches on the
    // derived TlsQuicFrame.Type, and neither 0x10 nor 0x14 is the base of a Table 3
    // flag range, so 0x10 is the only RawType that derives to MaxData and 0x14 the
    // only one that derives to DataBlocked - a range check here would be dead code,
    // the same argument TlsQuicStreamFrames.WriteCryptoFrameFields makes for 0x06.
    internal static void WriteMaximumDataFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        // Checked here rather than left to the encoder because the frame type is
        // written first: without this, QuicVariableLengthInteger.Write would throw
        // ArgumentOutOfRangeException with the type byte already in the caller's
        // buffer. Caller-supplied and bounded by nothing - the plan's rule that a
        // write-side bound on a caller-supplied field is always reachable, so both
        // of this method's two type paths need a witness.
        RequireEncodableVarint(frame.MaximumData, "maximumData");

        // UNREACHABLE, NOT UNWITNESSED: replacing frame.RawType here with
        // (ulong)frame.Type leaves the whole Quic suite green, and that survival is
        // correct. Reaching this method requires frame.Type to be MaxData or
        // DataBlocked, and neither 0x10 nor 0x14 is the base of a Table 3 flag
        // range, so TlsQuicFrame.Type's fall-through arm maps them to themselves
        // and the two expressions are the same number for every input. The same
        // honest gap TlsQuicFrames.WriteFrame's Padding/Ping/HandshakeDone arm
        // records, and it closes only if Table 3 ever gives one of these two types
        // a flag - which no QUIC v1 extension in scope does. RawType is written
        // anyway so that all six writers in this file read alike, and because
        // WriteMaximumStreamsFrameFields' identical line IS pinned; a reader
        // comparing them should know which is which.
        QuicVariableLengthInteger.Write(destination, frame.RawType);
        QuicVariableLengthInteger.Write(destination, frame.MaximumData);
    }

    // Appends one MAX_STREAM_DATA (s19.10 Figure 34) or STREAM_DATA_BLOCKED
    // (s19.13 Figure 37) frame's wire bytes to destination. Same contract as
    // WriteMaximumDataFrameFields, and the same dead-code argument against
    // validating RawType: 0x11 and 0x15 are not range bases either.
    internal static void WriteMaximumStreamDataFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        // Two separate bounds, not one loop, and each needs its own witness per
        // type path - four rows between them. They throw the same exception type
        // on the same kind of value, so the only thing that distinguishes them is
        // ParamName; both names below are string literals in
        // RequireEncodableVarint's message, NOT nameof()-derived, since there is no
        // parameter of either name on this method. Renaming TlsQuicFrame.StreamId
        // or MaximumStreamData will not update them and the tests asserting on
        // ParamName will not fail if they go stale.
        //
        // s19.10 makes the Stream ID "encoded as a variable-length integer", so
        // s16 caps it at QuicVariableLengthInteger.MaximumValue, 2^62 - 1;
        // neither s19.10 nor s19.13 puts a tighter bound on either field. Note
        // that this is NOT
        // MaximumStreamCount: 2^60 bounds a *count of streams*, while a stream
        // *identifier* runs to the full varint range, which is the asymmetry
        // s19.11's own explanation turns on.
        RequireEncodableVarint(frame.StreamId, "streamId");
        RequireEncodableVarint(frame.MaximumStreamData, "maximumStreamData");

        // Unreachable rather than unwitnessed for the same reason
        // WriteMaximumDataFrameFields records at its own first Write: 0x11 and 0x15
        // are not range bases either, so (ulong)frame.Type would emit the same byte
        // and that mutation survives correctly.
        QuicVariableLengthInteger.Write(destination, frame.RawType);
        QuicVariableLengthInteger.Write(destination, frame.StreamId);
        QuicVariableLengthInteger.Write(destination, frame.MaximumStreamData);
    }

    // Appends one MAX_STREAMS (s19.11 Figure 35) or STREAMS_BLOCKED (s19.14
    // Figure 38) frame's wire bytes to destination. Same contract as
    // WriteMaximumDataFrameFields.
    //
    // Unlike the other two writers this one emits a type from a *range*, so
    // frame.RawType rather than (ulong)frame.Type is load-bearing here: both 0x12
    // and 0x13 derive to TlsQuicFrameType.MaxStreams and both 0x16 and 0x17 to
    // StreamsBlocked, so a writer that emitted the derived value would silently
    // turn every unidirectional frame into a bidirectional one. That is the same
    // mutation TlsQuicStreamFrames.WriteStreamFrameFields records, and the reason
    // this file's hand-derived vectors cover all four type values rather than one
    // per frame type.
    //
    // RawType is still not validated, for a slightly longer version of the other
    // two writers' argument: TlsQuicFrame.Type derives MaxStreams only from
    // 0x12..0x13 and StreamsBlocked only from 0x16..0x17, so by the time
    // WriteFrame has dispatched here RawType is already one of those four values
    // and a range check could not fire.
    internal static void WriteMaximumStreamsFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        // The write-side half of the s19.11 / s19.14 stream-count bound quoted in
        // TryReadMaximumStreams, on a caller-supplied field this time, so it is
        // reachable for the reason the read-side twin is *also* reachable and then
        // some: frame.MaximumStreams can be anything up to 2^64 - 1.
        //
        // NO SEPARATE RequireEncodableVarint FOR THIS FIELD, deliberately.
        // MaximumStreamCount is 2^60 and QuicVariableLengthInteger.MaximumValue is
        // 2^62 - 1, so this check is strictly the tighter of the two and an
        // encodability check behind it could never fire. Adding one would be the
        // shadowed check the plan's standing rule warns about, with the twist that
        // the shadowed one would be dead rather than merely redundant - and its own
        // mutation-pin would then be unkillable. The other two writers need
        // RequireEncodableVarint precisely because their fields have no tighter
        // bound than the varint range.
        //
        // Mutation checks (performed and reverted), four rows each, one per
        // reachable rawType - the plan's two-type-value rule applies twice here,
        // once for each ranged frame:
        //   * deleting this check - fails the four rows of
        //     TlsQuicFlowControlFramesTests.WritingAMaximumStreamsFrameAboveThe
        //     StreamCountBoundThrows, all four with the wrong exception type
        //     (nothing throws at all: 2^60 + 1 is a perfectly encodable varint, so
        //     unlike the other two writers' bounds there is no
        //     ArgumentOutOfRangeException from the encoder to fall back on, and
        //     the frame is written happily) and, at values above the varint
        //     maximum, with the type byte already in the destination.
        //   * weakening it to >= - fails the four rows of
        //     WritingAMaximumStreamsFrameAtTheStreamCountBoundSucceeds.
        //   * conditioning it on any one of the four rawType values - fails the six
        //     rejecting rows belonging to the other three values, all four
        //     one-value mutations tried separately.
        //   * replacing MaximumStreamCount with
        //     QuicVariableLengthInteger.MaximumValue - fails the four 2^60 + 1 rows,
        //     which is the check that this bound is 2^60 and not the varint maximum.
        if (frame.MaximumStreams > MaximumStreamCount)
        {
            throw new ArgumentException(
                $"The stream count in this frame ({frame.MaximumStreams}) exceeds " +
                $"{MaximumStreamCount}, the largest a MAX_STREAMS or STREAMS_BLOCKED frame may " +
                "carry (RFC 9000 s19.11: \"This value cannot exceed 2^60, as it is not possible " +
                "to encode stream IDs larger than 2^62-1\").",
                nameof(frame));
        }

        QuicVariableLengthInteger.Write(destination, frame.RawType);
        QuicVariableLengthInteger.Write(destination, frame.MaximumStreams);
    }

    // RFC 9000 s16 leaves a variable-length integer 62 value bits, so
    // QuicVariableLengthInteger.MaximumValue is 2^62 - 1 and a larger value has no
    // encoding. ArgumentException matching every other caller-input rejection in
    // this namespace, rather than the ArgumentOutOfRangeException the encoder would
    // raise on its own - and raised before any byte is written, which the encoder's
    // own throw would not be. The same helper TlsQuicStreamFrames and
    // TlsQuicAckFrames each keep privately; not hoisted into one shared home,
    // because the three differ in the frame family their message names and that
    // prefix is what tells a reader which frame rejected them.
    //
    // parameterName is a string literal at every call site above; see
    // WriteMaximumStreamDataFrameFields for why that matters to the tests.
    private static void RequireEncodableVarint(ulong value, string parameterName)
    {
        if (value > QuicVariableLengthInteger.MaximumValue)
        {
            throw new ArgumentException(
                $"Flow control frame {parameterName} ({value}) exceeds the largest " +
                $"variable-length integer value, {QuicVariableLengthInteger.MaximumValue} " +
                "(RFC 9000 s16).",
                parameterName);
        }
    }
}
