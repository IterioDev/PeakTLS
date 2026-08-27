namespace SharpTls.Quic;

// STREAM frames (RFC 9000 s19.8) and CRYPTO frames (s19.6), both directions.
// Pure functions - no stream state machine, no flow control accounting, no
// reassembly, no CRYPTO buffering (TlsQuicCryptoStreamReassembler already does
// that and is untouched by this file). This decides only how the two frames are
// written and read, never when one is sent.
//
// One file for two frame types, which is the A2 plan's amended layout, and it
// is a family rather than a coincidence: s19.6 - "CRYPTO frames are
// functionally identical to STREAM frames, except that they do not bear a
// stream identifier; they are not flow controlled; and they do not carry
// markers for optional offset, optional length, and the end of the stream." The
// shared part is real and it is the dangerous part: both carry an Offset and a
// length-delimited data field, and both are bounded by the same sentence about
// the largest offset a stream may deliver, so that sentence's arithmetic is
// written once here (TryReadData, RequireLargestOffsetInRange) instead of twice.
//
// The differences are equally real and are not smoothed over. CRYPTO is not
// STREAM with a different type value:
//
//   * CRYPTO has no flags in its type at all - s12.4 Table 3 assigns it the
//     single value 0x06, so both its Offset and its Length are unconditionally
//     present, and there is no implicit-length CRYPTO form.
//   * CRYPTO has no FIN bit. s19.6: "The stream does not have an explicit end,
//     so CRYPTO frames do not have a FIN bit."
//   * CRYPTO has no Stream ID. s19.6: "Unlike STREAM frames, which include a
//     stream ID indicating to which stream the data belongs, the CRYPTO frame
//     carries data for a single stream per encryption level."
//
// STREAM's own type is a range for the opposite reason - s19.8: "The Type field
// in the STREAM frame takes the form 0b00001XXX (or the set of values from 0x08
// to 0x0f). The three low-order bits of the frame type determine the fields that
// are present in the frame." So every combination of the three flags is a STREAM
// frame, which is why TlsQuicFrames.TryReadFrame matches 0x08..0x0f with one
// relational pattern and hands the raw value here rather than to eight readers.
//
// THE ABSENT FIELDS. TlsQuicFrame has no Length field and no Fin field, and both
// omissions are load-bearing rather than tidiness:
//
//   * No Length. s19.8's LEN bit chooses between an explicit Length and one that
//     "extends to the end of the packet", but either way the length of the data
//     a frame carries is Data.Length, so a separate field could only ever
//     disagree with it. Which of the two forms a frame used lives in RawType's
//     LEN bit and nowhere else - that is precisely what RawType exists for,
//     since both forms end up with a length and only the raw type separates them.
//   * No Fin. s19.8's FIN bit is carried by RawType alone, so IsFin(RawType)
//     below is the only way to ask and there is no second copy to fall out of
//     step with the wire type.
//
// THE IMPLICIT-LENGTH FORM, and where such a frame may appear. s19.8's LEN bit:
// "If this bit is set to 0, the Length field is absent and the Stream Data field
// extends to the end of the packet." Combined with s12.4 - "The payload of QUIC
// packets, after removing packet protection, consists of a sequence of complete
// frames" and "Frames always fit within a single QUIC packet and cannot span
// multiple packets" - a LEN-less STREAM frame can only be the *last* frame in a
// packet payload, because it consumes every byte to the payload's end and
// leaves nothing for a following frame to occupy.
//
// This reader does not enforce that as a separate rule, and cannot: it enforces
// it structurally. TryReadStream on a LEN-less form advances `offset` to
// payload.Length exactly, so the caller's read loop ("call TryReadFrame until
// offset == payload.Length", see TlsQuicFrames) terminates immediately after it.
// There is no input for which "a LEN-less STREAM was not last" is observable and
// rejectable - any bytes that followed one were, by definition, its Stream Data.
// A check here would be dead code, and per the standing convention in
// TlsQuicAckFrames dead validation is worse than none.
//
// The writer's side of that is a caller obligation this file cannot check.
// WriteFrame appends one frame and knows nothing about what a caller appends
// next - deliberately, since subsystem B controls frame layout and a writer with
// lookahead would have to reorder or reject to use it. So a caller that writes a
// LEN-less STREAM frame and then writes anything else has produced a payload in
// which that second frame's bytes are stream data, silently. Pinned by
// TlsQuicStreamFramesTests.ALenLessStreamFrameSwallowsWhateverFollowsIt, which
// exists to document the trap rather than to assert a behaviour worth relying
// on. Callers with more than one frame to write must set the LEN bit on every
// STREAM frame but the last.
internal static class TlsQuicStreamFrames
{
    /// <summary>
    /// RFC 9000 s19.8: "The OFF bit (0x04) in the frame type is set to indicate
    /// that there is an Offset field present. When set to 1, the Offset field is
    /// present. When set to 0, the Offset field is absent and the Stream Data
    /// starts at an offset of 0."
    /// </summary>
    internal const ulong OffsetBit = 0x04;

    /// <summary>
    /// RFC 9000 s19.8: "The LEN bit (0x02) in the frame type is set to indicate
    /// that there is a Length field present. If this bit is set to 0, the Length
    /// field is absent and the Stream Data field extends to the end of the
    /// packet. If this bit is set to 1, the Length field is present."
    /// </summary>
    internal const ulong LengthBit = 0x02;

    /// <summary>
    /// RFC 9000 s19.8: "The FIN bit (0x01) indicates that the frame marks the
    /// end of the stream. The final size of the stream is the sum of the offset
    /// and the length of this frame."
    /// </summary>
    internal const ulong FinBit = 0x01;

    // THE 0x08..0x0f PRECONDITION ON THE THREE HELPERS BELOW IS DOCUMENTED AND
    // UNENFORCED, and the collision is not hypothetical: they take a bare ulong,
    // so IsFin(0x03) returns true - 0x03 is s12.4's ECN-bearing ACK, whose low bit
    // is s19.3.2's ECN flag and has nothing to do with FIN. HasLength(0x02) and
    // HasOffset(0x04) alias RESET_STREAM and plain ACK the same way. Nothing is
    // wrong today, because TlsQuicFrames.TryReadFrame's case labels mean these are
    // only ever reached with a type already matched to STREAM, and there is no
    // other caller - so a check here would be unreachable, and this is a note
    // rather than a fix on purpose.
    //
    // The first caller that is NOT the dispatch switch should get an
    // `in TlsQuicFrame` overload instead of a bare ulong, so the type and the
    // question travel together and TlsQuicFrame.Type can be asserted to be
    // TlsQuicFrameType.Stream. Widening the parameter is what removes the
    // collision; adding a range check to the ulong form only moves it, since the
    // caller would still have had to know which range to pass.

    /// <summary>
    /// Whether a STREAM frame with this exact wire type carries an Offset field.
    /// Only meaningful for the eight values RFC 9000 s12.4 Table 3 assigns to
    /// STREAM, 0x08 to 0x0f - the caller has already matched the type, and
    /// s19.8 defines the bits only within that range. Unenforced; see the note
    /// above.
    /// </summary>
    internal static bool HasOffset(ulong rawStreamFrameType) =>
        (rawStreamFrameType & OffsetBit) != 0;

    /// <summary>
    /// Whether a STREAM frame with this exact wire type carries an explicit
    /// Length field. False means the implicit form, whose Stream Data runs to
    /// the end of the packet - see this class's own comment for why that
    /// confines such a frame to the end of a payload. Same 0x08..0x0f
    /// precondition as <see cref="HasOffset"/>.
    /// </summary>
    internal static bool HasLength(ulong rawStreamFrameType) =>
        (rawStreamFrameType & LengthBit) != 0;

    /// <summary>
    /// Whether a STREAM frame with this exact wire type marks the end of its
    /// stream. The FIN bit is recorded in <see cref="TlsQuicFrame.RawType"/>, and
    /// this is the only place it is read - TlsQuicFrame has no Fin field, so there
    /// is no copy of it to disagree with the wire type. Same 0x08..0x0f
    /// precondition as <see cref="HasOffset"/>. CRYPTO frames never have this bit;
    /// s19.6: "The stream does not have an explicit end, so CRYPTO frames do not
    /// have a FIN bit."
    /// </summary>
    internal static bool IsFin(ulong rawStreamFrameType) =>
        (rawStreamFrameType & FinBit) != 0;

    // Reads everything after a STREAM frame's type, in the order RFC 9000 s19.8
    // Figure 32 lists it:
    //
    //   STREAM Frame {
    //     Type (i) = 0x08..0x0f,
    //     Stream ID (i),
    //     [Offset (i)],
    //     [Length (i)],
    //     Stream Data (..),
    //   }
    //
    // The two bracketed fields are present exactly when rawType's OFF and LEN
    // bits are set, which is what makes this one reader cover all eight wire
    // forms. Offset precedes Length; a reader that swapped them would still
    // decode the 0x0e/0x0f forms into two plausible-looking numbers.
    //
    // Same Try-shaped contract as TlsQuicFrames.TryReadFrame, which is the only
    // production caller: never throws for any input, and `offset` only advances on
    // success. The second half is pinned by a direct call at a nonzero offset -
    // TlsQuicStreamFramesTests.TryReadStreamCommitsNothingWhenTheOffsetBoundRejects,
    // and its CRYPTO counterpart for TryReadCrypto - because TryReadFrame discards
    // this method's `offset` on failure and so cannot observe it. The identical
    // promise on the private TryReadData genuinely cannot be observed; see its own
    // remark.
    //
    // Takes ReadOnlyMemory<byte>, not ReadOnlySpan<byte>, for the reason
    // TlsQuicAckFrames.TryReadAck documents: TlsQuicFrame.Data below is a
    // zero-copy ReadOnlyMemory<byte> slice of `payload`, and a span-derived
    // slice cannot become a ReadOnlyMemory<byte> without copying.
    internal static bool TryReadStream(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        ulong rawType,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        var walked = offset;

        // s19.8, Stream ID: "A variable-length integer indicating the stream
        // ID of the stream". Unconditional - it is outside the brackets in
        // Figure 32, so all eight forms carry it.
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var streamId))
        {
            // Truncated Stream ID. Same reasoning as TlsQuicFrames.TryReadFrame's
            // own check: the code is this namespace's FRAME_ENCODING_ERROR,
            // chosen directly rather than derived from a caught exception - per
            // s12.4 frames "cannot span multiple packets", so a field that runs
            // off the end of an already-decrypted payload is malformed and not
            // incomplete.
            //
            // Mutation check (performed and reverted): see
            // TlsQuicStreamFramesTests.StreamTruncatedInItsHeaderFieldsIsRejected.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // s19.8, Offset: "This field is present when the OFF bit is set to 1.
        // When the Offset field is absent, the offset is 0." So 0 here is not a
        // "missing value" placeholder - it is the value s19.8 assigns.
        //
        // Mutation check (performed and reverted): deleting the HasOffset
        // condition, so the Offset is read unconditionally, makes an OFF-clear
        // frame consume the first byte of its Stream Data as an Offset. It
        // fails the four OFF-clear rows of
        // TlsQuicStreamFramesTests.EachStreamFormMatchesItsHandDerivedBytes
        // plus AZeroLengthStreamFrameIsLegalInBothTheExplicitAndImplicitForms,
        // OffBitSetWithOffsetZeroIsLegalAndIsADistinctWireFormFromOffClear and
        // ALenLessStreamFrameSwallowsWhateverFollowsIt - ten rows in all, and
        // nothing else in the Quic suite.
        ulong frameOffset = 0;
        if (HasOffset(rawType) &&
            !QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out frameOffset))
        {
            // Truncated Offset - the same reasoning and the same test as the
            // Stream ID check above, whose truncated-Offset rows reach this
            // check instead.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        if (!TryReadData(payload, ref walked, HasLength(rawType), frameOffset, out var data, out error))
        {
            return false;
        }

        frame = new TlsQuicFrame
        {
            RawType = rawType,
            StreamId = streamId,
            Offset = frameOffset,
            Data = data,
        };
        offset = walked;
        return true;
    }

    // Reads everything after a CRYPTO frame's type, in the order RFC 9000 s19.6
    // Figure 30 lists it:
    //
    //   CRYPTO Frame {
    //     Type (i) = 0x06,
    //     Offset (i),
    //     Length (i),
    //     Crypto Data (..),
    //   }
    //
    // No rawType parameter, unlike TryReadStream and TryReadAck: s12.4 Table 3
    // assigns CRYPTO one value, so there is nothing for the caller to pass and
    // nothing this reader could branch on. Neither field is bracketed - both are
    // unconditionally present, which is s19.6's "they do not carry markers for
    // optional offset, optional length, and the end of the stream" - so the
    // Length is always explicit and CRYPTO has no implicit-length form.
    //
    // Same Try-shaped contract as TryReadStream.
    internal static bool TryReadCrypto(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        var walked = offset;

        // s19.6, Offset: "A variable-length integer specifying the byte
        // offset in the stream for the data in this CRYPTO frame."
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var frameOffset))
        {
            // Mutation check (performed and reverted): see
            // TlsQuicStreamFramesTests.CryptoTruncatedInItsOffsetIsRejected.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // hasLength is unconditionally true, which is the whole difference from
        // TryReadStream's call: a CRYPTO frame never runs to the end of the
        // packet. RFC 9001 A.2's published 245-byte frame is what pins this -
        // with hasLength false, its Length field (0x40f1) would be read as
        // Crypto Data and the frame would swallow the 917 PADDING bytes behind
        // it. See TlsQuicStreamFramesTests.Rfc9001AppendixA2ClientInitialCrypto
        // FrameParsesToItsPublishedOffsetAndLength.
        if (!TryReadData(payload, ref walked, hasLength: true, frameOffset, out var data, out error))
        {
            return false;
        }

        frame = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Crypto,
            Offset = frameOffset,
            Data = data,
        };
        offset = walked;
        return true;
    }

    // Appends one STREAM frame's wire bytes to destination (RFC 9000 s19.8
    // Figure 32), in whichever of the eight forms frame.RawType selects. The
    // low-level writer TlsQuicFrames.WriteFrame's Stream case dispatches to,
    // named after TlsQuicAckFrames.WriteFrameFields and playing the same role.
    //
    // There is no higher-level entry point beside this one, unlike ACK's
    // WriteAckFrame. ACK needed one because three of its fields are fully
    // determined by the range chain, so taking a TlsQuicFrame would have left
    // fields that get silently recomputed. STREAM has no such field: the Length
    // it writes is frame.Data.Length, which is not a separate field of the
    // struct at all and so cannot disagree with anything.
    //
    // Caller-chosen input, so every rejection throws rather than returning
    // false - same split as WriteFrame versus TryReadFrame. Every check runs
    // before the first byte is written, so a rejection never leaves a partial
    // frame in the caller's buffer.
    internal static void WriteStreamFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        // s19.8: "When the Offset field is absent, the offset is 0." So a frame
        // whose OFF bit is clear but whose Offset is not 0 is a contradiction,
        // and the failure mode if it were written anyway is silence: the Offset
        // is simply not emitted, the peer reads the data at offset 0, and
        // nothing on the wire records that the caller meant otherwise. Rejected
        // for the same reason TlsQuicAckFrames.WriteFrameFields rejects a type
        // 0x02 ACK carrying ECN counts.
        //
        // Not the converse, though: OFF set with Offset 0 is legal and is a
        // distinct wire form (0x0c versus 0x08), which the eight-form vectors
        // rely on - the two are different byte sequences that decode to the same
        // fields, and s12.4's shortest-encoding MUST applies to the frame type,
        // not to a sender's choice of which STREAM form to use.
        if (!HasOffset(frame.RawType) && frame.Offset != 0)
        {
            throw new ArgumentException(
                $"STREAM frame type 0x{frame.RawType:x2} has the OFF bit (0x{OffsetBit:x2}) clear, so " +
                $"RFC 9000 s19.8 gives it an offset of 0 (\"When the Offset field is absent, the " +
                $"offset is 0\"), but {nameof(frame)}.{nameof(TlsQuicFrame.Offset)} is " +
                $"{frame.Offset}. Set the OFF bit to carry an offset.",
                nameof(frame));
        }

        // s2.1 caps a stream ID at 2^62-1 by making it a variable-length
        // integer, which is QuicVariableLengthInteger.MaximumValue. Checked here
        // rather than left to the encoder because the frame type is written
        // first: without this, QuicVariableLengthInteger.Write would throw
        // ArgumentOutOfRangeException with the type byte already in the caller's
        // buffer.
        RequireEncodableVarint(frame.StreamId, "streamId");

        RequireLargestOffsetInRange(frame, "s19.8");

        QuicVariableLengthInteger.Write(destination, frame.RawType);
        QuicVariableLengthInteger.Write(destination, frame.StreamId);

        if (HasOffset(frame.RawType))
        {
            QuicVariableLengthInteger.Write(destination, frame.Offset);
        }

        // s19.8, Length: "When the LEN bit is set to 0, the Stream Data field
        // consumes all the remaining bytes in the packet." So the implicit form
        // writes no Length field at all, and it is the caller's job not to
        // append anything after this frame - see this class's own comment.
        if (HasLength(frame.RawType))
        {
            QuicVariableLengthInteger.Write(destination, (ulong)frame.Data.Length);
        }

        WriteData(destination, frame.Data);
    }

    // Appends one CRYPTO frame's wire bytes to destination (RFC 9000 s19.6
    // Figure 30). Both fields unconditional, no flags, no FIN, no stream ID -
    // see TryReadCrypto and this class's own comment.
    //
    // The frame type is not validated here: TlsQuicFrames.WriteFrame dispatches
    // on the derived TlsQuicFrame.Type, and 0x06 is the only RawType that
    // derives to TlsQuicFrameType.Crypto (it is not the base of a flag range),
    // so a RawType check would be dead code.
    //
    // THE TWO WIDTHS (A4 task 5). RFC 9000 s16: "Values do not need to be encoded on the
    // minimum number of bytes necessary, with the sole exception of the Frame Type
    // field", so a CRYPTO frame's Offset and Length are a sender choice at every width
    // that holds them - fingerprint field 7. Both default to Minimal, which is what
    // every pre-task-5 caller wrote and what RFC 9001 A.2 shows (offset 0x00, length
    // 0x40f1). The frame type itself is written through the Minimal overload and takes
    // no width, because s16's exemption makes a wide one illegal rather than merely
    // unusual. The width reaches here from a TlsQuicPacketPlan; nothing maps
    // TlsQuicConnectionSpec's two matching properties onto one yet, which is A4 task
    // 9a-ii's, and that half of field 7 is recorded on
    // TlsQuicConnectionSpec.HeaderLengthVarintWidth. Witnessed by
    // TlsQuicDatagramBuilderTests.CryptoOffsetAndLengthVarintsAreWrittenAtTheWidthsThePl
    // anAsksFor.
    internal static void WriteCryptoFrameFields(
        List<byte> destination,
        in TlsQuicFrame frame,
        TlsQuicVarintWidth offsetWidth = TlsQuicVarintWidth.Minimal,
        TlsQuicVarintWidth lengthWidth = TlsQuicVarintWidth.Minimal)
    {
        // s19.6: "Unlike STREAM frames, which include a stream ID indicating to
        // which stream the data belongs, the CRYPTO frame carries data for a
        // single stream per encryption level." There is no field to put a
        // stream ID in, so a caller that set one asked for something this frame
        // cannot express, and writing anyway would drop it silently. Same
        // defect class as the OFF/Offset contradiction above.
        if (frame.StreamId != 0)
        {
            throw new ArgumentException(
                $"A CRYPTO frame carries no stream ID (RFC 9000 s19.6: \"they do not bear a stream " +
                $"identifier\"), but {nameof(frame)}.{nameof(TlsQuicFrame.StreamId)} is " +
                $"{frame.StreamId}. Use a STREAM frame to address a stream.",
                nameof(frame));
        }

        RequireLargestOffsetInRange(frame, "s19.6");

        // A width narrower than its value is a caller error, and GetEncodedLength(value,
        // width) is the one place that reports it. Resolved HERE rather than at the two
        // Write calls below so a rejection never leaves a frame type byte and half an
        // Offset in the caller's buffer - the same all-checks-first guarantee
        // WriteStreamFrameFields gives, and the reason these two lines are not folded
        // into the writes.
        _ = QuicVariableLengthInteger.GetEncodedLength(frame.Offset, offsetWidth);
        _ = QuicVariableLengthInteger.GetEncodedLength((ulong)frame.Data.Length, lengthWidth);

        QuicVariableLengthInteger.Write(destination, (ulong)TlsQuicFrameType.Crypto);
        QuicVariableLengthInteger.Write(destination, frame.Offset, offsetWidth);
        QuicVariableLengthInteger.Write(destination, (ulong)frame.Data.Length, lengthWidth);
        WriteData(destination, frame.Data);
    }

    // The Length field and the data behind it, for both frame types: STREAM's
    // "[Length (i)], Stream Data (..)" and CRYPTO's "Length (i), Crypto Data
    // (..)". One implementation, because the bound that matters here - the
    // largest offset a stream may deliver - is worded identically in s19.8 and
    // s19.6 and a second copy of it could drift.
    //
    // `hasLength` is the s19.8 LEN bit for STREAM and unconditionally true for
    // CRYPTO. On success `offset` has advanced past the data; on failure it is
    // exactly as passed in, and `data` is empty.
    //
    // That failure-path guarantee is DEFENCE IN DEPTH, not a pinned contract, and
    // is recorded as such rather than asserted: no test can observe it. `offset`
    // here is a local of whichever sub-reader called this method (`walked`), and
    // neither TryReadStream nor TryReadCrypto publishes that local when this
    // returns false - each returns false immediately without assigning its own
    // `offset` parameter. So a version of this method that advanced `offset` and
    // filled `data` before failing would behave identically through every reachable
    // caller. It is written this way anyway because it makes the two callers'
    // guarantee - which IS pinned, by
    // TlsQuicStreamFramesTests.TryReadStreamCommitsNothingWhenTheOffsetBoundRejects
    // and its CRYPTO counterpart - true by construction rather than by a
    // side-effect-ordering argument a later edit could quietly break. Making it
    // observable would mean widening it to internal purely for a test, which is
    // scaffolding, not coverage.
    private static bool TryReadData(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        bool hasLength,
        ulong frameOffset,
        out ReadOnlyMemory<byte> data,
        out TlsQuicTransportError error)
    {
        data = ReadOnlyMemory<byte>.Empty;
        error = TlsQuicTransportError.NoError;
        var walked = offset;

        int length;
        if (hasLength)
        {
            // s19.8, Length: "A variable-length integer specifying the
            // length of the Stream Data field in this STREAM frame." s19.6
            // says the same of CRYPTO's Length and its Crypto Data field.
            if (!QuicVariableLengthInteger.TryRead(payload.Span, ref walked, out var declared))
            {
                // Mutation check (performed and reverted): see
                // TlsQuicStreamFramesTests.StreamTruncatedInItsLengthFieldIsRejected.
                error = TlsQuicTransportError.FrameEncodingError;
                return false;
            }

            // The bound on an explicit Length. s12.4: "Frames always fit within
            // a single QUIC packet and cannot span multiple packets", so a
            // Length that reaches past the end of the payload is malformed, not
            // incomplete - there is no continuation to wait for and
            // FRAME_ENCODING_ERROR is s20.1's "frame that was badly formatted".
            //
            // Compared as a ulong against the remaining byte count, never by
            // computing walked + (int)declared: `declared` is a variable-length
            // integer, so a peer can put nearly 2^62 in two bytes, and casting
            // that to int before the comparison would truncate it to whatever
            // the low 32 bits happen to be - possibly a small in-bounds number.
            // No allocation is sized from it either, for the reason
            // TlsQuicAckFrames.TryWalkRanges gives about ACK Range Count: the
            // slice below is taken only after the bytes are proven to exist.
            //
            // Mutation check (performed and reverted): see
            // TlsQuicStreamFramesTests.StreamWhoseExplicitLengthOverrunsThePayload
            // IsRejected and CryptoWhoseExplicitLengthOverrunsThePayloadIsRejected.
            var remaining = (ulong)(payload.Length - walked);
            if (declared > remaining)
            {
                error = TlsQuicTransportError.FrameEncodingError;
                return false;
            }

            length = (int)declared;
        }
        else
        {
            // s19.8: "If this bit is set to 0, the Length field is absent and
            // the Stream Data field extends to the end of the packet." This is
            // the line that makes such a frame necessarily the last in its
            // payload - see this class's own comment for the full argument and
            // for why nothing enforces it separately.
            length = payload.Length - walked;
        }

        // s19.8: "The first byte in the stream has an offset of 0. The largest
        // offset delivered on a stream -- the sum of the offset and data length
        // -- cannot exceed 2^62-1, as it is not possible to provide flow control
        // credit for that data. Receipt of a frame that exceeds this limit MUST
        // be treated as a connection error of type FRAME_ENCODING_ERROR or
        // FLOW_CONTROL_ERROR." s19.6 bounds CRYPTO with the same sentence,
        // offering FRAME_ENCODING_ERROR or CRYPTO_BUFFER_EXCEEDED.
        //
        // FRAME_ENCODING_ERROR is chosen for both, being the alternative common
        // to the two lists and the only one this layer can justify: s20.1 makes
        // FLOW_CONTROL_ERROR "An endpoint received more data than it permitted
        // in its advertised data limits", and CRYPTO_BUFFER_EXCEEDED "An
        // endpoint has received more data in CRYPTO frames than it can buffer" -
        // both are statements about connection state this file does not have,
        // while a frame naming an offset no stream can reach is badly formatted
        // on its face.
        //
        // Written as a subtraction on the limit rather than as
        // `frameOffset + (ulong)length > MaximumValue`, so that nothing is
        // combined before it is checked. On this read path both operands happen
        // to be small enough that the sum could not wrap - frameOffset came from
        // a varint so it is at most 2^62-1, and length is an int - but the
        // encode path shares the same formula through
        // RequireLargestOffsetInRange, where frame.Offset is a caller-supplied
        // ulong that can wrap the sum to a small passing value. One form, safe
        // on both paths. MaximumValue - length cannot underflow: length is a
        // non-negative int, far below 2^62-1.
        //
        // The boundary: frameOffset + length == 2^62-1 exactly is legal, since
        // s19.8 says "cannot exceed". So with length 1 the largest legal offset
        // is 2^62-2 and the smallest illegal one is 2^62-1.
        //
        // Mutation check (performed and reverted): see
        // TlsQuicStreamFramesTests.StreamLargestOffsetIsBoundedAtTheStreamMaximum
        // and CryptoLargestOffsetIsBoundedAtTheStreamMaximum, which pin both
        // directions - deleting this comparison fails their rejecting rows and
        // weakening it to `>=` fails their accepting ones. Both LEN states are
        // covered, since the length reaching here is the decoded Length field on
        // one path and the implicit remainder on the other.
        //
        // UNREACHABLE, NOT UNWITNESSED: guarding this as
        // `if (length > 0 && frameOffset > ...)` survives the whole suite, and
        // that survival is correct rather than a coverage hole. With length 0 the
        // guard reduces to `frameOffset > MaximumValue`, and on this path
        // frameOffset was decoded by QuicVariableLengthInteger.TryRead, so it is at
        // most MaximumValue by construction - no input can make the skipped
        // comparison fire. The same is true of `HasOffset`-conditioning on the
        // write side, where the OFF/Offset check forces Offset to 0 first. Neither
        // is worth a test, but both are worth recording: this reasoning is what
        // stands in for coverage, so a later change that lets an unvalidated
        // offset reach here - anything that stops decoding it with TryRead - makes
        // the path reachable and the argument void. The write-side twin of this
        // very check had exactly the shape above and WAS a real hole, because
        // frame.Offset there is caller-supplied and unbounded; see
        // RequireLargestOffsetInRange.
        if (frameOffset > QuicVariableLengthInteger.MaximumValue - (ulong)length)
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        // Empty rather than a zero-length slice for a frame that carries no
        // data, matching TlsQuicFrame.AckRanges' convention for an absent
        // variable-length section. s19.8 makes a zero-length Stream Data legal
        // and meaningful: "When a Stream Data field has a length of 0, the
        // offset in the STREAM frame is the offset of the next byte that would
        // be sent."
        data = length == 0 ? ReadOnlyMemory<byte>.Empty : payload.Slice(walked, length);
        offset = walked + length;
        return true;
    }

    // The write-side half of the s19.8 / s19.6 largest-offset bound quoted in
    // TryReadData, in the same pre-combination form and for a sharper reason:
    // frame.Offset here is whatever the caller put on the struct, so it can be
    // up to 2^64-1, and `frame.Offset + (ulong)frame.Data.Length` **wraps** for
    // a large enough Offset - producing a small number that a naive
    // `sum > MaximumValue` test waves through. The same class of defect as the
    // ACK range underflow this phase already had to fix: check before
    // combining, not after.
    //
    // This one check covers the encodability of the Offset field too, being
    // strictly tighter: Data.Length is non-negative, so anything it rejects at
    // length 0 is exactly what QuicVariableLengthInteger could not encode. That
    // claim is pinned by the emptyData rows of
    // TlsQuicStreamFramesTests.WritingAStreamFrameWhoseLargestOffsetExceedsThe
    // StreamMaximumThrows and its CRYPTO counterpart - `if (frame.Data.Length > 0
    // && ...)` here survived until they existed, and an unencodable Offset then
    // reached QuicVariableLengthInteger.Write, which throws the wrong exception
    // type with the frame type byte already in the caller's buffer. Unlike the
    // read-side twin, where the equivalent guard is unreachable because the offset
    // came from a varint, frame.Offset here is caller-supplied and unbounded, so
    // the zero-length path is genuinely reachable.
    //
    // `section` names which RFC section the caller is enforcing, so the message
    // cites s19.8 for STREAM and s19.6 for CRYPTO - the sentence is the same in
    // both but a reviewer checking one frame type should not be sent to the
    // other's section.
    private static void RequireLargestOffsetInRange(in TlsQuicFrame frame, string section)
    {
        if (frame.Offset > QuicVariableLengthInteger.MaximumValue - (ulong)frame.Data.Length)
        {
            throw new ArgumentException(
                $"The largest offset this frame delivers - offset {frame.Offset} plus " +
                $"{frame.Data.Length} bytes of data - exceeds " +
                $"{QuicVariableLengthInteger.MaximumValue}, the largest offset a QUIC stream can " +
                $"reach (RFC 9000 {section}: \"the sum of the offset and data length -- cannot " +
                "exceed 2^62-1\").",
                nameof(frame));
        }
    }

    // RFC 9000 s16 leaves a variable-length integer 62 value bits, so
    // QuicVariableLengthInteger.MaximumValue is 2^62 - 1 and a larger value has
    // no encoding. ArgumentException, matching every other caller-input
    // rejection in this namespace, rather than the ArgumentOutOfRangeException
    // the encoder would raise on its own - and raised before any byte is
    // written, which the encoder's own throw would not be.
    //
    // The parameter name is a string literal, not nameof()-derived: there is no
    // parameter called "streamId" on the method that passes it. A rename of
    // TlsQuicFrame.StreamId will not update it, and the tests that assert on
    // ParamName will not fail if it goes stale.
    private static void RequireEncodableVarint(ulong value, string parameterName)
    {
        if (value > QuicVariableLengthInteger.MaximumValue)
        {
            throw new ArgumentException(
                $"STREAM {parameterName} ({value}) exceeds the largest variable-length integer " +
                $"value, {QuicVariableLengthInteger.MaximumValue} (RFC 9000 s16).",
                parameterName);
        }
    }

    // The data field itself, copied verbatim - it is already exactly the bytes
    // the frame carries, whether from a reader's zero-copy slice of a received
    // datagram or from a caller's own buffer. Same shape as
    // TlsQuicAckFrames.WriteFrameFields' AckRanges copy.
    //
    // AddRange OVER A PER-BYTE Add LOOP, AND THE BYTES ARE THE SAME BYTES. This is
    // the frame's largest field - a STREAM frame carries whatever the datagram
    // budget allows, so the loop it replaces ran up to ~1200 times per frame and
    // again on every TlsQuicFrames.MeasureFrame of it. List<byte>.AddRange grows
    // the backing array once and memcpys, where Add re-checks capacity per byte;
    // the resulting list contents are identical, which is what
    // TlsQuicStreamFramesTests.EachStreamFormMatchesItsHandDerivedBytes pins
    // against hand-derived bytes.
    private static void WriteData(List<byte> destination, ReadOnlyMemory<byte> data)
    {
        destination.AddRange(data.Span);
    }
}
