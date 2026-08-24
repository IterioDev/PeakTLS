namespace SharpTls.Quic;

// A single QUIC frame (RFC 9000 s19). One Type-discriminated struct covers
// every frame type, the same shape TlsQuicPacketHeader uses for
// TlsQuicLongHeader/TlsQuicShortHeader: fields that only apply to some
// frame types are simply unset for the rest. PADDING, PING, and
// HANDSHAKE_DONE carry no fields beyond the frame type itself. Later A2 tasks
// add the fields STREAM, CRYPTO and the rest need (stream id, offset, data,
// ...) here, rather than a parallel struct per frame type.
//
// The fields live here but the code that reads and writes them lives one file
// per frame family - TlsQuicAckFrames for ACK, and so on - so each field gets a
// one-line summary here and its RFC quote beside the arithmetic that applies it.
// At twenty frame types the alternative is several hundred lines of quoted RFC
// between the struct's fields, with the code they explain in another file.
internal readonly struct TlsQuicFrame
{
    /// <summary>
    /// The Frame Type field exactly as decoded, flags included. This is the
    /// only settable part of the frame's identity: for the five types where
    /// s12.4 says "The Frame Type in ACK, STREAM, MAX_STREAMS,
    /// STREAMS_BLOCKED, and CONNECTION_CLOSE frames is used to carry other
    /// frame-specific flags", some of those flags are not recoverable from
    /// the decoded fields - a STREAM frame with no LEN bit runs to the end of
    /// the packet, so a length exists either way and the bit itself is gone
    /// unless it is kept here. Note this is the decoded *value*, not the
    /// encoding: a frame type read from an over-long varint keeps its value
    /// and loses its width, which is what s12.4's shortest-encoding MUST
    /// wants on the way back out.
    /// </summary>
    internal ulong RawType { get; init; }

    /// <summary>
    /// The Table 3 base type <see cref="RawType"/> belongs to, for switch
    /// dispatch. Derived, never settable, so it cannot disagree with
    /// <see cref="RawType"/>. A value outside every flag range - including
    /// one Table 3 never assigns - maps to itself; a default-constructed
    /// TlsQuicFrame therefore has RawType 0x00 and Type PADDING, which
    /// RFC 9000 s19.1 makes a valid frame.
    /// </summary>
    internal TlsQuicFrameType Type => RawType switch
    {
        // Ranges are from the RFC section cited on each TlsQuicFrameType
        // member. They are fixed by RFC 9000 s12.4 Table 3 for every QUIC v1
        // peer, so unlike connection ID or packet number lengths these are
        // not a per-client layout choice subsystem B can vary.
        //
        // Mutation check (performed and reverted): deleting the STREAM arm
        // fails TlsQuicFramesTests.DerivedTypeAlwaysAgreesWithExactRawType at
        // rawType 0x0b and 0x0f; deleting the CONNECTION_CLOSE arm fails it at
        // rawType 0x1d. Nothing else can decide those inputs - the theory
        // constructs the struct directly, so no reader or writer check runs at
        // all, and each arm is the only one whose range contains its value.
        // The interior rows (0x0b) matter separately from the endpoints: an arm
        // narrowed to a single value would still pass on 0x08 alone.
        >= 0x02 and <= 0x03 => TlsQuicFrameType.Ack,
        >= 0x08 and <= 0x0f => TlsQuicFrameType.Stream,
        >= 0x12 and <= 0x13 => TlsQuicFrameType.MaxStreams,
        >= 0x16 and <= 0x17 => TlsQuicFrameType.StreamsBlocked,
        >= 0x1c and <= 0x1d => TlsQuicFrameType.ConnectionClose,

        // The sixth range, and the only one not from s12.4 Table 3. RFC 9221
        // s4: "The Type field in the DATAGRAM frame takes the form 0b0011000X
        // (or the values 0x30 and 0x31)." Placed after the five above rather
        // than merged with them because its provenance is a different
        // document; see TlsQuicFrameType.Datagram.
        //
        // Mutation check (performed and reverted): deleting this arm fails
        // TlsQuicFramesTests.DerivedTypeAlwaysAgreesWithExactRawType at rawType
        // 0x31, which would otherwise map to itself instead of to Datagram.
        // Narrowing it to `== 0x30` fails the same row, and widening it to
        // `>= 0x30 and <= 0x32` fails that theory's 0x32 row.
        >= 0x30 and <= 0x31 => TlsQuicFrameType.Datagram,
        _ => (TlsQuicFrameType)RawType,
    };

    // ACK, RFC 9000 s19.3. Read and written by TlsQuicAckFrames, which quotes
    // s19.3 beside the arithmetic that applies each field; one line each here.
    // AckDelay is the raw wire value - s19.3's ack_delay_exponent scaling is a
    // later phase's, needing transport parameters this layer does not have.
    // LargestAcknowledged, AckRangeCount and FirstAckRange are determined by the
    // range chain, so WriteAckFrame derives them from the ranges it is given
    // rather than taking this struct.

    /// <summary>ACK: Largest Acknowledged, untruncated.</summary>
    internal ulong LargestAcknowledged { get; init; }

    /// <summary>ACK: ACK Delay, raw and unscaled.</summary>
    internal ulong AckDelay { get; init; }

    /// <summary>ACK: the number of ACK Range fields, one less than the number of ranges.</summary>
    internal ulong AckRangeCount { get; init; }

    /// <summary>ACK: how far below Largest Acknowledged the first range reaches.</summary>
    internal ulong FirstAckRange { get; init; }

    /// <summary>
    /// ACK: the wire bytes of the ACK Ranges section (RFC 9000 s19.3.1's Gap /
    /// ACK Range Length chain), unparsed - a zero-copy slice of the buffer
    /// this frame was read from, not a decoded value and not a copy. Pass the
    /// frame to <see cref="TlsQuicAckFrames.TryGetRanges"/> for the packet
    /// numbers it describes. Empty for a non-ACK frame and for an ACK with no
    /// ACK Range fields.
    /// </summary>
    /// <remarks>
    /// LIFETIME: as with <see cref="TlsQuicLongHeader"/>'s fields, this aliases
    /// the datagram the frame was parsed from and is only valid while that
    /// buffer is unmodified - see
    /// <see cref="ITlsQuicDatagramTransport.ReceiveAsync"/>.
    /// </remarks>
    internal ReadOnlyMemory<byte> AckRanges { get; init; }

    /// <summary>
    /// ACK type 0x03 only: the ECT(0), ECT(1) and ECN-CE counts of RFC 9000
    /// s19.3.2, one value because the RFC makes them all-present-or-all-absent.
    /// Null for type 0x02, which does not carry them; never null with a
    /// zero-count ambiguity for type 0x03, since 0 is a legitimate cumulative
    /// count there - unlike three separate <c>ulong</c> fields, null and
    /// "present but all zero" are distinguishable states.
    /// <see cref="RawType"/> is still what decides, via
    /// <see cref="TlsQuicAckFrames.HasEcnCounts"/>; this field does not decide
    /// anything on its own, and the two are kept in agreement by
    /// <see cref="TlsQuicAckFrames"/> whenever a frame is written.
    /// </summary>
    internal TlsQuicEcnCounts? EcnCounts { get; init; }

    // STREAM (RFC 9000 s19.8) and CRYPTO (s19.6). Read and written by
    // TlsQuicStreamFrames, which quotes both sections beside the arithmetic
    // that applies each field; one line each here. There is deliberately no
    // Length and no Fin field - see that file's "THE ABSENT FIELDS" note.

    /// <summary>STREAM: Stream ID. Absent from CRYPTO, which has no stream identifier (RFC 9000 s19.6).</summary>
    internal ulong StreamId { get; init; }

    /// <summary>
    /// STREAM and CRYPTO: the Offset field - the byte offset in the stream of
    /// the data this frame carries. 0 for a STREAM frame whose OFF bit is
    /// clear, which RFC 9000 s19.8 makes the same thing: "When the Offset field
    /// is absent, the offset is 0."
    /// </summary>
    internal ulong Offset { get; init; }

    /// <summary>
    /// STREAM's Stream Data (RFC 9000 s19.8), CRYPTO's Crypto Data (s19.6) or
    /// PATH_CHALLENGE's and PATH_RESPONSE's Data (s19.17, s19.18) - a zero-copy
    /// slice of the buffer this frame was read from, not a copy. Empty for a
    /// frame that carries no data, which s19.8 and s19.6 allow; s19.17 does not,
    /// making its Data exactly
    /// <see cref="TlsQuicConnectionFrames.PathDataLength"/> bytes.
    /// </summary>
    /// <remarks>
    /// LIFETIME: as with <see cref="AckRanges"/>, this aliases the datagram the
    /// frame was parsed from and is only valid while that buffer is unmodified -
    /// see <see cref="ITlsQuicDatagramTransport.ReceiveAsync"/>.
    /// </remarks>
    internal ReadOnlyMemory<byte> Data { get; init; }

    // The six flow-control frames - MAX_DATA (RFC 9000 s19.9), MAX_STREAM_DATA
    // (s19.10), MAX_STREAMS (s19.11), DATA_BLOCKED (s19.12),
    // STREAM_DATA_BLOCKED (s19.13) and STREAMS_BLOCKED (s19.14). Read and
    // written by TlsQuicFlowControlFrames, which quotes those sections beside
    // the code that applies each field; one line each here. StreamId above is
    // reused by MAX_STREAM_DATA and STREAM_DATA_BLOCKED, both of which name
    // their first field "Stream ID" exactly as s19.8 does.
    //
    // THREE FIELDS FOR SIX FRAME TYPES, one per distinct RFC field name. The
    // six sections use only three names between them: s19.9 and s19.12 both
    // call their only field "Maximum Data", s19.10 and s19.13 both call their
    // second field "Maximum Stream Data", and s19.11 and s19.14 both call their
    // only field "Maximum Streams". So each field below is exactly one RFC field
    // name, which is the granularity a reviewer can check against the section
    // text without a mapping argument in between.
    //
    // Not collapsed further into one `Maximum` field shared by all six, though
    // no two of the three are ever present at once. Two reasons, in order: the
    // connection-level budget of s19.9 and the per-stream budget of s19.10 are
    // different quantities that a later phase must not confuse, and one field
    // would make the confusion untypeable rather than merely unlikely; and a
    // single name could not be checked against any RFC field name, since the
    // RFC has three.
    //
    // The cost of three, recorded because it is real: a caller who means
    // MAX_DATA but sets MaximumStreamData writes a MAX_DATA frame carrying 0,
    // silently. Nothing here rejects that, and TlsQuicFlowControlFrames' writers
    // deliberately do not either - see the note there. The relationship is the
    // one STREAM already has to ACK: nothing stops a caller setting AckDelay on
    // a STREAM frame either, and a struct in which every frame type checked
    // every other type's fields would need twenty such checks per writer. What
    // the RFC does forbid outright - CRYPTO carrying a stream ID, s19.6's "they
    // do not bear a stream identifier" - is checked, in
    // TlsQuicStreamFrames.WriteCryptoFrameFields; no sentence in s19.9 to s19.14
    // says anything comparable about a field belonging to another frame type.

    /// <summary>MAX_DATA and DATA_BLOCKED: the Maximum Data field (RFC 9000 s19.9, s19.12).</summary>
    internal ulong MaximumData { get; init; }

    /// <summary>MAX_STREAM_DATA and STREAM_DATA_BLOCKED: the Maximum Stream Data field (RFC 9000 s19.10, s19.13).</summary>
    internal ulong MaximumStreamData { get; init; }

    /// <summary>MAX_STREAMS and STREAMS_BLOCKED: the Maximum Streams field, bounded at 2^60 (RFC 9000 s19.11, s19.14).</summary>
    internal ulong MaximumStreams { get; init; }

    // The eight connection-management frames - RESET_STREAM (RFC 9000 s19.4),
    // STOP_SENDING (s19.5), NEW_TOKEN (s19.7), NEW_CONNECTION_ID (s19.15),
    // RETIRE_CONNECTION_ID (s19.16), PATH_CHALLENGE (s19.17), PATH_RESPONSE
    // (s19.18) and CONNECTION_CLOSE (s19.19). Read and written by
    // TlsQuicConnectionFrames, which quotes those sections beside the code that
    // applies each field; one line each here.
    //
    // Two of the fields above are reused rather than duplicated, both because the
    // RFC uses the same field name: StreamId, which s19.4 and s19.5 name "Stream
    // ID" exactly as s19.8 does, and Data, which s19.17 and s19.18 name "Data".
    // Everything else these eight sections name is new below, one field per
    // distinct RFC field name - the same granularity the flow-control block above
    // uses, and the granularity a reviewer can check against the section text
    // without a mapping argument in between.
    //
    // ONE DEPARTURE FROM THAT RULE, and it is deliberate: s19.19's second field is
    // called "Frame Type", which would collide with this struct's own Type and
    // RawType - the frame's own identity - for a field that carries some *other*
    // frame's type. TriggerFrameType names what s19.19's own description says it
    // is: "the type of frame that triggered the error".
    //
    // The four byte-string fields carry the same LIFETIME caveat as AckRanges and
    // Data: each aliases the datagram the frame was parsed from and is valid only
    // while that buffer is unmodified - see
    // <see cref="ITlsQuicDatagramTransport.ReceiveAsync"/>.

    /// <summary>RESET_STREAM and STOP_SENDING: the Application Protocol Error Code field (RFC 9000 s19.4, s19.5).</summary>
    internal ulong ApplicationProtocolErrorCode { get; init; }

    /// <summary>RESET_STREAM: the Final Size field (RFC 9000 s19.4).</summary>
    internal ulong FinalSize { get; init; }

    /// <summary>
    /// NEW_TOKEN: the Token field (RFC 9000 s19.7), a zero-copy slice. Never empty
    /// on a frame this library reads or writes - s19.7: "The token MUST NOT be
    /// empty."
    /// </summary>
    internal ReadOnlyMemory<byte> Token { get; init; }

    /// <summary>NEW_CONNECTION_ID and RETIRE_CONNECTION_ID: the Sequence Number field (RFC 9000 s19.15, s19.16).</summary>
    internal ulong SequenceNumber { get; init; }

    /// <summary>NEW_CONNECTION_ID: the Retire Prior To field, never above <see cref="SequenceNumber"/> (RFC 9000 s19.15).</summary>
    internal ulong RetirePriorTo { get; init; }

    /// <summary>
    /// NEW_CONNECTION_ID: the Connection ID field (RFC 9000 s19.15), a zero-copy
    /// slice of 1 to 20 bytes. Its length is the frame's separate 8-bit Length
    /// field on the wire, which is not a field of this struct for the reason
    /// TlsQuicStreamFrames gives about STREAM's Length: a second copy could only
    /// ever disagree with the bytes themselves.
    /// </summary>
    internal ReadOnlyMemory<byte> ConnectionId { get; init; }

    /// <summary>NEW_CONNECTION_ID: the Stateless Reset Token field, exactly 16 bytes (RFC 9000 s19.15).</summary>
    internal ReadOnlyMemory<byte> StatelessResetToken { get; init; }

    /// <summary>
    /// The whole encoded size of an RFC 9221 s4 DATAGRAM frame in bytes -
    /// "including the frame type, length, and payload", which is s3's own
    /// parenthesis and the unit max_datagram_frame_size is measured in. Zero
    /// for every other frame type, none of which has a size rule.
    /// </summary>
    /// <remarks>CARRIED RATHER THAN RECOMPUTED, because it cannot be recovered
    /// from <see cref="Data"/>. The Length field is a variable-length integer
    /// and RFC 9000 s16 requires the minimal encoding only of frame TYPES, so a
    /// peer may spend four bytes on a length that fits in one and the frame is
    /// still legal and still larger than a derived figure would say. The reader
    /// knows the two offsets; nothing downstream does.</remarks>
    internal int EncodedLength { get; init; }

    /// <summary>CONNECTION_CLOSE: the Error Code field, in the transport space for 0x1c and the application space for 0x1d (RFC 9000 s19.19).</summary>
    internal ulong ErrorCode { get; init; }

    /// <summary>
    /// CONNECTION_CLOSE type 0x1c only: the Frame Type field of RFC 9000 s19.19 -
    /// "the type of frame that triggered the error", 0 when it is unknown. Always
    /// 0 for type 0x1d, which does not carry the field;
    /// <see cref="TlsQuicConnectionFrames.IsApplicationError"/> over
    /// <see cref="RawType"/> is what decides, and a 0x1d frame carrying a non-zero
    /// value here is rejected on the way out rather than silently truncated.
    /// </summary>
    internal ulong TriggerFrameType { get; init; }

    /// <summary>
    /// CONNECTION_CLOSE: the Reason Phrase field (RFC 9000 s19.19), a zero-copy
    /// slice. Empty is legal - "This can be zero length if the sender chooses not
    /// to give details beyond the Error Code value" - and is not validated as
    /// UTF-8, which s19.19 makes a SHOULD.
    /// </summary>
    internal ReadOnlyMemory<byte> ReasonPhrase { get; init; }
}

// Reads and writes individual QUIC frames (RFC 9000 s19). Pure functions:
// no sockets, no connection state.
//
// A packet payload is "a sequence of complete frames" (s12.4 Figure 11), so
// there is no plural TryReadFrames here - callers read a whole payload by
// calling TryReadFrame repeatedly, each call advancing offset past the
// frame it just read, until offset == payload.Length. That mirrors
// QuicVariableLengthInteger.TryRead's own ref-offset shape.
//
// The writer never merges, coalesces, or reorders: each WriteFrame call
// appends exactly the bytes for the one frame passed in, and nothing else.
// Subsystem B later controls frame layout inside the Initial packet - how a
// CRYPTO stream splits across frames, and where PADDING and PING sit, is
// one of six fields distinguishing a real client's fingerprint - so a
// writer that helpfully combined adjacent PADDING bytes into one write, or
// reordered frames for its own convenience, would make that impossible.
internal static class TlsQuicFrames
{
    /// <summary>
    /// RFC 9221 s4's LEN bit, the low bit of the DATAGRAM frame type: "The
    /// least significant bit of the Type field in the DATAGRAM frame is the LEN
    /// bit (0x01), which indicates whether there is a Length field present".
    /// </summary>
    /// <remarks>
    /// Lives here rather than in a TlsQuicDatagramFrames file because DATAGRAM
    /// has no family file: it has no writer to share one with, and its reader is
    /// the fifteen lines of <see cref="TryReadDatagram"/> below. The other five
    /// flag bits in this namespace - EcnCountsBit, OffsetBit/LengthBit/FinBit,
    /// UnidirectionalBit, ApplicationErrorBit - each sit beside the code that
    /// both reads and writes their frame family.
    /// </remarks>
    internal const ulong DatagramLengthBit = 0x01;

    // Try-shaped and never throws: frame payloads are attacker-controlled
    // and a later phase runs this in a receive loop, same contract as
    // TlsQuicPacketHeader.TryReadLongHeader. On failure, frame and offset
    // are left exactly as passed in - only a success commits the advance.
    //
    // `error` carries the RFC 9000 s20.1 connection error code the rejection
    // maps to, because a bool cannot: s12.4 assigns different codes to
    // different malformations and a later receive loop has to send the right
    // one. It is a second `out` rather than a returned result type to match
    // TlsQuicPacketHeader.TryReadLongHeader, which already reports two
    // out-values beside its bool. Every rejection is a connection error, never
    // a "need more bytes" - s12.4: "Frames always fit within a single QUIC
    // packet and cannot span multiple packets", so a frame that runs off the
    // end of an already-decrypted payload is malformed, not incomplete. On
    // success `error` is NO_ERROR (0x00).
    //
    // Over-long frame types are accepted, by choice. s12.4 says a sender
    // "MUST use the shortest possible encoding" and then, of the receiver:
    // "An endpoint MAY treat the receipt of a frame type that uses a longer
    // encoding than necessary as a connection error of type
    // PROTOCOL_VIOLATION." That is a MAY, so declining it is conformant, and
    // declining it is what this reader does: it resolves the frame type by
    // decoded value and never looks at how many bytes carried it. The reason
    // is asymmetric cost. Subsystem B's job is to be indistinguishable from a
    // real client talking to real servers, and killing a connection over a
    // peer's encoding quirk that changes nothing about the frame's meaning
    // buys no security and risks a server we cannot change; the half of the
    // rule that protects us is the sending MUST, and WriteFrame satisfies
    // that unconditionally. Enforcing the MAY later needs no new state -
    // `typeOffset - offset` is the width the peer used, and
    // QuicVariableLengthInteger.GetEncodedLength(rawType) is the shortest -
    // so this stays a one-line switch if that trade ever changes.
    //
    // Takes ReadOnlyMemory<byte>, not ReadOnlySpan<byte>, following
    // TlsQuicPacketHeader.TryReadLongHeader (see its comment for the full
    // reasoning): TlsQuicFrame.AckRanges is a ReadOnlyMemory<byte> slice of
    // `payload`, and a span-derived slice cannot become a
    // ReadOnlyMemory<byte> without copying. Taking Memory here, and passing it
    // straight through to TlsQuicAckFrames.TryReadAck, keeps the whole path
    // from ReceiveAsync's buffer to a parsed frame copy-free.
    internal static bool TryReadFrame(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;

        var typeOffset = offset;
        if (!QuicVariableLengthInteger.TryRead(payload.Span, ref typeOffset, out var rawType))
        {
            // The bounds check that stops this reader running past the end
            // of the payload: QuicVariableLengthInteger.TryRead reports false
            // when fewer bytes remain than its own length prefix declares (or
            // the payload is empty), never throwing, so this is TryReadFrame's
            // own Try-shaped contract holding by construction rather than by a
            // caught exception. Mutation check (performed and reverted):
            // inverting the `!` above makes
            // TlsQuicFramesTests.TruncatedMultiByteFrameTypeReturnsFalseNotThrows
            // fail - it starts accepting a frame type TryRead rejected. That
            // test's one-byte input (0x40, a two-byte-varint prefix with the
            // second byte missing) never reaches the switch below - TryRead
            // above reports false first - so only this check can be why the
            // call returns false; no other check in this method can reject it
            // first.
            //
            // The code reported is this file's own, not derived from the
            // failed read: unlike Read, TryRead carries no exception or code
            // of its own to inherit, so FRAME_ENCODING_ERROR below is this
            // file's direct choice rather than an override - s20.1's "An
            // endpoint received a frame that was badly formatted", and a frame
            // type whose varint prefix promises more bytes than the payload
            // holds is badly formatted, per s12.4's "cannot span multiple
            // packets" (no continuation to wait for).
            //
            // Mutation check (performed and reverted): dropping this
            // assignment, so the block returns false with `error` still
            // NO_ERROR, fails both
            // TlsQuicFramesTests.TruncatedMultiByteFrameTypeReturnsFalseNotThrows
            // (input 0x40) and EmptyBufferReturnsFalseRatherThanThrowing (input
            // empty). Both inputs make TryRead report false before rawType is
            // set, so the switch below never runs and no other check in this
            // method can set `error` for them.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        switch (rawType)
        {
            // One arm for all three: RawType carries the value, so these no
            // longer need a case each to name their Type.
            case (ulong)TlsQuicFrameType.Padding:
            case (ulong)TlsQuicFrameType.Ping:
            case (ulong)TlsQuicFrameType.HandshakeDone:
                frame = new TlsQuicFrame { RawType = rawType };
                break;

            // Both ACK types, s12.4 Table 3's 0x02..0x03. The second label is
            // spelled with the ECN bit rather than as a bare 0x03 because that
            // is what the value means - s19.3.2: "The ACK frame uses the least
            // significant bit of the type value (that is, type 0x03) to indicate
            // ECN feedback".
            case (ulong)TlsQuicFrameType.Ack:
            case (ulong)TlsQuicFrameType.Ack | TlsQuicAckFrames.EcnCountsBit:
                // TryReadAck builds the frame in one expression at the end, so
                // on failure it leaves `frame` at default and `typeOffset`
                // untouched - which is what TryReadFrame promises its own caller
                // for both of its out-values and for `offset`.
                if (!TlsQuicAckFrames.TryReadAck(payload, ref typeOffset, rawType, out frame, out error))
                {
                    return false;
                }
                break;

            // CRYPTO, s12.4 Table 3's single value 0x06 - one value, not a
            // range. Why it has no flags, and why it is not STREAM with a
            // different type value, is in TlsQuicStreamFrames.
            case (ulong)TlsQuicFrameType.Crypto:
                if (!TlsQuicStreamFrames.TryReadCrypto(payload, ref typeOffset, out frame, out error))
                {
                    return false;
                }
                break;

            // All eight STREAM forms, s12.4 Table 3's 0x08..0x0f - a relational
            // pattern over the base value or'd with every s19.8 flag, like
            // TlsQuicFrame.Type's own arm, rather than eight labels. rawType is
            // passed on whole; TryReadStream is where s19.8's field-presence
            // rules live and quotes them.
            case >= (ulong)TlsQuicFrameType.Stream and
                 <= ((ulong)TlsQuicFrameType.Stream |
                     TlsQuicStreamFrames.OffsetBit |
                     TlsQuicStreamFrames.LengthBit |
                     TlsQuicStreamFrames.FinBit):
                if (!TlsQuicStreamFrames.TryReadStream(payload, ref typeOffset, rawType, out frame, out error))
                {
                    return false;
                }
                break;

            // The six flow-control frames, s12.4 Table 3's 0x10..0x17 with 0x12
            // and 0x16 ranged. Three arms, not six: s19.9's and s19.12's field
            // lists are identical, as are s19.10's and s19.13's and s19.11's and
            // s19.14's, so TlsQuicFlowControlFrames has one reader per shape and
            // rawType is what carries the difference through to the frame. Its own
            // comment sets out the three figures side by side.
            case (ulong)TlsQuicFrameType.MaxData:
            case (ulong)TlsQuicFrameType.DataBlocked:
                if (!TlsQuicFlowControlFrames.TryReadMaximumData(payload, ref typeOffset, rawType, out frame, out error))
                {
                    return false;
                }
                break;

            case (ulong)TlsQuicFrameType.MaxStreamData:
            case (ulong)TlsQuicFrameType.StreamDataBlocked:
                if (!TlsQuicFlowControlFrames.TryReadMaximumStreamData(payload, ref typeOffset, rawType, out frame, out error))
                {
                    return false;
                }
                break;

            // Four labels for two frame types. Both are ranged - s19.11 "type=0x12
            // or 0x13", s19.14 "type=0x16 or 0x17" - and the second value of each
            // is spelled with the flag rather than as a bare 0x13 or 0x17 because
            // that is what the value means, the same way the ECN-bearing ACK label
            // above is spelled. Written as four labels rather than two relational
            // patterns because each range is two values wide, so a pattern would
            // be longer than the labels it replaced.
            case (ulong)TlsQuicFrameType.MaxStreams:
            case (ulong)TlsQuicFrameType.MaxStreams | TlsQuicFlowControlFrames.UnidirectionalBit:
            case (ulong)TlsQuicFrameType.StreamsBlocked:
            case (ulong)TlsQuicFrameType.StreamsBlocked | TlsQuicFlowControlFrames.UnidirectionalBit:
                if (!TlsQuicFlowControlFrames.TryReadMaximumStreams(payload, ref typeOffset, rawType, out frame, out error))
                {
                    return false;
                }
                break;

            // The eight connection-management frames, s12.4 Table 3's 0x04, 0x05,
            // 0x07, 0x18, 0x19, 0x1a, 0x1b and the ranged 0x1c..0x1d. Seven arms,
            // not eight: s19.18 makes PATH_RESPONSE's format "identical to that of
            // the PATH_CHALLENGE frame", so those two share a reader and rawType
            // carries the difference through to the frame, exactly as the
            // flow-control pairs above do. TlsQuicConnectionFrames' own comment
            // sets out all eight figures and says why STOP_SENDING does not share
            // RESET_STREAM's reader despite looking like a prefix of it.
            case (ulong)TlsQuicFrameType.ResetStream:
                if (!TlsQuicConnectionFrames.TryReadResetStream(payload, ref typeOffset, out frame, out error))
                {
                    return false;
                }
                break;

            case (ulong)TlsQuicFrameType.StopSending:
                if (!TlsQuicConnectionFrames.TryReadStopSending(payload, ref typeOffset, out frame, out error))
                {
                    return false;
                }
                break;

            case (ulong)TlsQuicFrameType.NewToken:
                if (!TlsQuicConnectionFrames.TryReadNewToken(payload, ref typeOffset, out frame, out error))
                {
                    return false;
                }
                break;

            case (ulong)TlsQuicFrameType.NewConnectionId:
                if (!TlsQuicConnectionFrames.TryReadNewConnectionId(payload, ref typeOffset, out frame, out error))
                {
                    return false;
                }
                break;

            case (ulong)TlsQuicFrameType.RetireConnectionId:
                if (!TlsQuicConnectionFrames.TryReadRetireConnectionId(payload, ref typeOffset, out frame, out error))
                {
                    return false;
                }
                break;

            case (ulong)TlsQuicFrameType.PathChallenge:
            case (ulong)TlsQuicFrameType.PathResponse:
                if (!TlsQuicConnectionFrames.TryReadPathData(payload, ref typeOffset, rawType, out frame, out error))
                {
                    return false;
                }
                break;

            // Both CONNECTION_CLOSE types, s12.4 Table 3's 0x1c..0x1d. The second
            // label is spelled with the application-error bit rather than as a bare
            // 0x1d for the reason the ECN-bearing ACK and the unidirectional
            // MAX_STREAMS labels above are: that is what the value means, per
            // s19.19's two paragraphs on the two types. 0x1c does not already carry
            // bit 0x01, so unlike the STREAMS_BLOCKED case that the A2 plan warns
            // about, `Base | Bit` here is a distinct label and compiles.
            case (ulong)TlsQuicFrameType.ConnectionClose:
            case (ulong)TlsQuicFrameType.ConnectionClose | TlsQuicConnectionFrames.ApplicationErrorBit:
                if (!TlsQuicConnectionFrames.TryReadConnectionClose(payload, ref typeOffset, rawType, out frame, out error))
                {
                    return false;
                }
                break;

            // Both DATAGRAM forms, RFC 9221 s4's 0x30..0x31 - the only arm here
            // whose frame type is not an s12.4 Table 3 row. Two labels rather
            // than a relational pattern, matching the MAX_STREAMS arm above:
            // the range is two values wide, so a pattern would be longer than
            // the labels it replaced, and the second is spelled with the LEN bit
            // rather than as a bare 0x31 because that is what the value means.
            case (ulong)TlsQuicFrameType.Datagram:
            case (ulong)TlsQuicFrameType.Datagram | DatagramLengthBit:
                if (!TryReadDatagram(payload, offset, ref typeOffset, rawType, out frame, out error))
                {
                    return false;
                }
                break;

            default:
                // RFC 9000 s12.4: "An endpoint MUST treat the receipt of a
                // frame of unknown type as a connection error of type
                // FRAME_ENCODING_ERROR." Raising the connection error is a
                // later, stateful phase's job (this file has none); this
                // Try-shaped reader reports the code and lets that phase act.
                //
                // This arm is the equality test that keeps the frame type
                // whole. Mutation check (performed and reverted): masking the
                // decoded value with `& 0xFFFFFFFF` at the TryRead call above
                // makes TlsQuicFramesTests.FrameTypeAliasingAKnownTypeInIts
                // LowThirtyTwoBitsIsRejected fail - its 8-byte varint decodes
                // to 4294967326, whose low 32 bits are 0x1e, so a masking
                // reader accepts it as HANDSHAKE_DONE. That input is a
                // complete 8-byte varint (the check above cannot fire) and
                // 4294967326 needs all 8 bytes (so the shortest-encoding
                // question below cannot arise either), leaving this arm the
                // only check that can reject it.
                //
                // ONE CASE ONLY SINCE A2 TASK 5: values no frame type this
                // library knows is assigned - 0x1f and up, MINUS the two RFC
                // 9221 DATAGRAM values 0x30 and 0x31 that task C17 gave labels
                // above. Until task 5 this arm also caught values Table 3 *does*
                // assign to frame types A2 had not implemented yet, for which
                // FRAME_ENCODING_ERROR was only approximately right; that second
                // set is now empty, because every value from 0x00 to 0x1e has a
                // case label above. So no Table 3 membership test is needed here
                // to tell the two apart - the distinction has stopped existing
                // rather than merely being ignored.
                //
                // C17 did NOT reopen it. An unimplemented *extension* frame type
                // is an unknown frame type to this endpoint in exactly s12.4's
                // sense, and RFC 9000 s12.4 says so for extensions specifically:
                // "An endpoint MUST treat the receipt of a frame of unknown type
                // as a connection error of type FRAME_ENCODING_ERROR." The
                // 0x1f-and-up description is kept as the arm's subject with the
                // two-value hole named, rather than being softened to something
                // unfalsifiable.
                //
                // The test that covered that second set,
                // FrameTypeNotYetImplementedByThisTaskIsRejected, was deleted by
                // task 5 rather than re-pointed: its subject was "a Table 3 type
                // with no case label", which is now unrepresentable. Its coverage
                // of this arm survives in the two tests named below, which reach
                // the same arm with the only inputs that still can.
                //
                // Mutation check (performed and reverted): dropping this
                // assignment, leaving `error` at NO_ERROR, fails
                // TlsQuicFramesTests.UnknownFrameTypeIsRejected (0x1f) and
                // TlsQuicFramesTests.FrameTypeAliasingAKnownTypeInItsLowThirty
                // TwoBitsIsRejected (the 8-byte 2^32 alias). Both inputs are
                // complete varints, so the check above cannot fire and this is the
                // only arm that sets `error` for them.
                error = TlsQuicTransportError.FrameEncodingError;
                return false;
        }

        offset = typeOffset;
        return true;
    }

    /// <summary>The encoded length of one frame in bytes, measured by encoding it.</summary>
    /// <remarks>
    /// <para>MEASURED RATHER THAN CALCULATED, and that is the whole point. A second
    /// implementation that added up field widths would be a duplicate of
    /// <see cref="WriteFrame"/> that no test compares against it, and every varint in a QUIC
    /// frame has four possible widths - so the two would agree on the common case and drift on
    /// the boundary, which is exactly where a datagram budget is decided.</para>
    /// <para>THE CALLER OWNS THE SCRATCH so the packing loop allocates once per datagram
    /// rather than once per frame. It is cleared on entry, so a caller may hand the same list
    /// to every call and read nothing into its contents afterwards.</para>
    /// </remarks>
    /// <param name="scratch">A working list the caller owns and reuses; cleared on entry.</param>
    /// <param name="frame">The frame to measure.</param>
    internal static int MeasureFrame(List<byte> scratch, in TlsQuicFrame frame)
    {
        ArgumentNullException.ThrowIfNull(scratch);
        scratch.Clear();
        WriteFrame(scratch, frame);
        return scratch.Count;
    }

    /// <summary>
    /// Reads RFC 9221 s4's DATAGRAM frame and DROPS ITS PAYLOAD, leaving
    /// <paramref name="frame"/> carrying nothing but its
    /// <see cref="TlsQuicFrame.RawType"/> and advancing
    /// <paramref name="offset"/> past the Datagram Data field.
    /// </summary>
    /// <remarks>
    /// <para>THIS CLOSES AN ADVERTISEMENT, NOT A FEATURE. SharpTls accepts and
    /// discards DATAGRAM frames; it does not implement QUIC or HTTP/3
    /// datagrams. The reason it exists at all is that this client's *defaults*
    /// claim it does: <see cref="TlsQuicTransportParameterSpec"/>'s a captured client
    /// preset emits <c>max_datagram_frame_size</c> = 65536 and
    /// <see cref="TlsQuicHttp3Spec"/>'s <c>CaptureSettings</c> emits
    /// <c>SETTINGS_H3_DATAGRAM</c> = 1, and RFC 9221 s3 makes the first of
    /// those a statement that "the endpoint is willing to receive QUIC
    /// DATAGRAM frames". Before this method a DATAGRAM arriving on the back of
    /// that invitation was an unknown frame type and closed the connection.</para>
    ///
    /// <para>DROPPING IS CONFORMANT AND IS NOT A SHORTCUT AROUND ONE. RFC 9221
    /// s5.3: "since DATAGRAM frames are inherently unreliable, they MAY be
    /// dropped by the receiver if the receiver cannot process them." The
    /// delivery obligation in s5 is a SHOULD conditioned on ability - "it
    /// SHOULD deliver the data to the application immediately, as long as it is
    /// able to process the frame" - and there is no application here to deliver
    /// to. What the framing still has to be got right for is the offset: a
    /// DATAGRAM sits in a payload that is "a sequence of complete frames"
    /// (RFC 9000 s12.4 Figure 11), so mis-measuring its extent corrupts every
    /// frame after it rather than only losing this one.</para>
    ///
    /// <para>Data AND EncodedLength ARE NOW SET, AND THIS PARAGRAPH USED TO SAY
    /// THE OPPOSITE. It read "no Data field is set, deliberately ... because a
    /// populated field is an invitation to use it, and there is nothing here
    /// that may", which held while nothing above this reader could act on a
    /// datagram. Two receive-side rules ended that. RFC 9221 s3 measures a
    /// DATAGRAM against max_datagram_frame_size "including the frame type,
    /// length, and payload", so the whole encoded extent has to leave this
    /// method; RFC 9297 s2.1 reads a Quarter Stream ID out of the payload's
    /// first varint, so the payload does too. Neither can be recovered once the
    /// span is gone, and the caller has neither offset.</para>
    ///
    /// <para>DROPPING IS STILL THE CONTRACT FOR THE PAYLOAD ITSELF. Nothing in
    /// this tree consumes datagram data; the two fields exist to let
    /// TlsQuicConnection and TlsQuicHttp3Connection REFUSE a datagram the RFCs
    /// say to refuse, after which the bytes go nowhere. <see cref="TlsQuicFrame.Data"/> is a
    /// slice of the receiver's decrypt scratch, so it stays valid only for the
    /// walk - the same contract STREAM's and PATH_CHALLENGE's Data carry - and
    /// the accepting path still allocates nothing, which
    /// QuicFuzzSeedsTests.ReadingAnyFrameInTheSeedCorpusAllocatesNothing keeps
    /// true over a corpus holding both DATAGRAM forms.</para>
    /// </remarks>
    /// <param name="payload">The packet's frame sequence, whose end bounds a
    /// LEN-clear DATAGRAM.</param>
    /// <param name="frameStart">The offset of this frame's type varint, which
    /// RFC 9221 s3's size includes and <paramref name="offset"/> is already
    /// past.</param>
    /// <param name="offset">On entry, the first byte after the frame type; on
    /// success, the first byte after the Datagram Data field. Unchanged on
    /// failure, as <see cref="TryReadFrame"/> promises for its own caller.</param>
    /// <param name="rawType">
    /// The exact wire value, 0x30 or 0x31. Its low bit is the only thing that
    /// decides this frame's shape, so it is taken rather than re-derived.
    /// </param>
    /// <param name="frame">The frame type and nothing else - see the remarks on
    /// dropping. Left at <see langword="default"/> on failure.</param>
    /// <param name="error">RFC 9000 s20.1's FRAME_ENCODING_ERROR on failure,
    /// NO_ERROR on success.</param>
    internal static bool TryReadDatagram(
        ReadOnlyMemory<byte> payload,
        int frameStart,
        ref int offset,
        ulong rawType,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        error = TlsQuicTransportError.NoError;

        var dataOffset = offset;

        // Where the Datagram Data field begins. It equals `offset` in the
        // LEN-clear form and moves past the Length field in the LEN-set one,
        // which is why it is tracked rather than assumed to be either.
        var dataStart = offset;

        // RFC 9221 s4, on the LEN bit, quoted whole because both halves are
        // load-bearing and the second is the one a reader guesses wrong: "if
        // this bit is set to 0, the Length field is absent and the Datagram Data
        // field extends to the end of the packet; if this bit is set to 1, the
        // Length field is present."
        //
        // So SET means present. That is read out of s4 and not inferred from
        // STREAM's LEN bit, which happens to agree - RFC 9000 s19.8's "LEN: The
        // third-least-significant bit (0x04) ... indicating that the Length
        // field is present" - but is a different bit of a different frame in a
        // different document, and agreement is not derivation.
        if ((rawType & DatagramLengthBit) != 0)
        {
            if (!QuicVariableLengthInteger.TryRead(payload.Span, ref dataOffset, out var length))
            {
                error = TlsQuicTransportError.FrameEncodingError;
                return false;
            }

            // s4: "A variable-length integer specifying the length of the
            // Datagram Data field in bytes." A Length past the end of the
            // payload is malformed and not incomplete, for s12.4's reason that
            // every other reader here cites: frames "cannot span multiple
            // packets", so there is no continuation to wait for.
            //
            // Compared in ulong, on the remaining count, so that neither side
            // can overflow: `payload.Length - dataOffset` is non-negative
            // because TryRead only advances within the span. Casting `length`
            // to int first is the defect this ordering forecloses - an unchecked
            // (int) of a 62-bit varint can land anywhere, including negative,
            // and `dataOffset + that` would then move the offset BACKWARDS into
            // bytes already parsed.
            if (length > (ulong)(payload.Length - dataOffset))
            {
                error = TlsQuicTransportError.FrameEncodingError;
                return false;
            }

            dataStart = dataOffset;
            dataOffset += (int)length;
        }
        else
        {
            // s4 again: "When the LEN bit is set to 0, the Datagram Data field
            // extends to the end of the QUIC packet." `payload` IS that packet's
            // frame sequence, so its end is the end of this frame - the same
            // implicit-length rule TlsQuicStreamFrames applies to a LEN-clear
            // STREAM frame, and with the same consequence for a caller's walk
            // loop: nothing can follow this frame, so `offset` lands on
            // payload.Length and the loop ends.
            //
            // s4 also notes what makes the empty case legal rather than
            // degenerate, for both forms: "Note that empty (i.e., zero-length)
            // datagrams are allowed." A 0x30 at the very end of a payload and a
            // 0x31 with Length 0 are both complete frames.
            dataOffset = payload.Length;
            dataStart = offset;
        }

        // THE DATA IS NOW CARRIED, AND THIS COMMENT USED TO SAY THE OPPOSITE.
        // It read "everything between `offset` and `dataOffset` was Datagram
        // Data and is not carried out of this method in any form", and the drop
        // was deliberate while nothing above this reader could act on a
        // datagram. Two rules made it untenable: RFC 9221 s3's size rule needs
        // the frame's whole encoded length, and RFC 9297 s2.1's two need the
        // first varint of the payload. Neither is recoverable once the span is
        // gone.
        //
        // IT IS A SLICE, NOT A COPY, and it aliases the receiver's decrypt
        // scratch exactly as STREAM's and PATH_CHALLENGE's Data do. Whoever
        // keeps it past the walk copies it, which is the contract those two
        // already carry - see TlsQuicStreams.ReceiveStreamFrame.
        //
        // EncodedLength MEASURES FROM `frameStart`, NOT FROM `offset`. s3 says
        // "including the frame type", and `offset` is already past the type
        // varint when this reader is called.
        frame = new TlsQuicFrame
        {
            RawType = rawType,
            Data = payload[dataStart..dataOffset],
            EncodedLength = dataOffset - frameStart,
        };
        offset = dataOffset;
        return true;
    }

    // Appends exactly one frame's wire bytes to destination. The frame type
    // is caller-chosen, not attacker-controlled, so an unimplemented type
    // throws instead of failing quietly - same split as
    // TlsQuicPacketHeader.WriteLongHeader vs TryReadLongHeader.
    //
    // Dispatches on the derived base Type but emits the exact RawType, so a
    // later task's STREAM frame keeps its OFF/LEN/FIN bits on the way out.
    // QuicVariableLengthInteger.Write picks the width from
    // GetEncodedLength(value), always the shortest, which is what s12.4
    // demands: "a frame type MUST use the shortest possible encoding". A frame
    // this reader took from an over-long encoding is therefore rewritten in
    // one byte. That is the rule, not a round-trip bug - RawType is the
    // decoded value and s12.4 leaves exactly one legal encoding of it.
    // cryptoOffsetWidth and cryptoLengthWidth (A4 task 5) reach exactly one arm below,
    // the CRYPTO one, and are named for it so they cannot be read as a general varint
    // policy. STREAM's Offset and Length are the same kind of sender choice under RFC
    // 9000 s16 and deliberately get no knob here: TlsQuicConnectionSpec declares widths
    // for CRYPTO only, because the Initial flight is what subsystem B fingerprints, and
    // a parameter with no spec field behind it would be the same accepted-and-ignored
    // defect these two exist to remove. Task 14 is where STREAM sending arrives.
    internal static void WriteFrame(
        List<byte> destination,
        in TlsQuicFrame frame,
        TlsQuicVarintWidth cryptoOffsetWidth = TlsQuicVarintWidth.Minimal,
        TlsQuicVarintWidth cryptoLengthWidth = TlsQuicVarintWidth.Minimal)
    {
        ArgumentNullException.ThrowIfNull(destination);

        switch (frame.Type)
        {
            case TlsQuicFrameType.Padding:
            case TlsQuicFrameType.Ping:
            case TlsQuicFrameType.HandshakeDone:
                // Mutation check (performed and reverted): replacing
                // frame.RawType with (ulong)frame.Type here changes nothing -
                // the Quic suite is still fully green. This is an honest gap,
                // not an untested claim: none of PADDING, PING or
                // HANDSHAKE_DONE is the base of a Table 3 flag range, so for
                // every type this switch admits today RawType and
                // (ulong)Type are the same number, and no input can separate
                // them: reaching this arm requires Type to be Padding, Ping or
                // HandshakeDone, none of which is a range base, so RawType is
                // 0x00, 0x01 or 0x1e and the two expressions are equal by
                // construction. A2 task 3b did NOT close this, contrary to what
                // this comment claimed before that task - STREAM dispatches to
                // its own case below, so the frame whose RawType 0x0b must
                // survive as 0x0b never reaches here. Only a future
                // flag-carrying type routed through this arm would close it, and
                // no A2 task adds one. Kept rather than dropped because the
                // equivalent line in
                // TlsQuicStreamFrames.WriteStreamFrameFields *is* pinned, so a
                // reader comparing the two files should know which is which.
                QuicVariableLengthInteger.Write(destination, frame.RawType);
                return;
            case TlsQuicFrameType.Ack:
                // Writable through this overload since A2 task 3a. Before
                // then, a decoded ACK frame held its ACK Ranges as an offset
                // and length into the payload it was read from, which
                // WriteFrame had no access to; TlsQuicAckFrames.WriteAckFrame
                // needed its own entry point for that reason alone.
                // TlsQuicFrame.AckRanges is now a self-contained
                // ReadOnlyMemory<byte> slice - it carries its own buffer
                // reference - so the frame has everything WriteFrame needs.
                // TlsQuicAckFrames.WriteFrameFields does the actual writing;
                // it is shared with TlsQuicAckFrames.WriteAckFrame, which
                // builds a frame from absolute ranges and calls back into
                // this method, so "write an ACK" has exactly one
                // implementation regardless of which entry point a caller
                // used to reach it.
                TlsQuicAckFrames.WriteFrameFields(destination, frame);
                return;
            case TlsQuicFrameType.Stream:
                // Dispatched on the derived base Type, so all eight s19.8 wire
                // forms arrive here and frame.RawType decides which fields
                // WriteStreamFrameFields emits. This is the case that makes
                // "emit RawType, not (ulong)Type" observable.
                TlsQuicStreamFrames.WriteStreamFrameFields(destination, frame);
                return;
            case TlsQuicFrameType.Crypto:
                TlsQuicStreamFrames.WriteCryptoFrameFields(
                    destination, frame, cryptoOffsetWidth, cryptoLengthWidth);
                return;

            // The six flow-control frames, paired by wire shape exactly as the
            // read dispatch above pairs them. Six labels, three writers.
            //
            // MaxStreams and StreamsBlocked are the second and third ranged types
            // to reach a writer, after Stream: each covers two RawTypes that derive
            // to the same Type, so "emit RawType, not (ulong)Type" is observable
            // here too - see WriteMaximumStreamsFrameFields. The other four types
            // are not range bases, so for them the two are equal by construction,
            // the same honest gap the Padding/Ping/HandshakeDone arm above records.
            case TlsQuicFrameType.MaxData:
            case TlsQuicFrameType.DataBlocked:
                TlsQuicFlowControlFrames.WriteMaximumDataFrameFields(destination, frame);
                return;
            case TlsQuicFrameType.MaxStreamData:
            case TlsQuicFrameType.StreamDataBlocked:
                TlsQuicFlowControlFrames.WriteMaximumStreamDataFrameFields(destination, frame);
                return;
            case TlsQuicFrameType.MaxStreams:
            case TlsQuicFrameType.StreamsBlocked:
                TlsQuicFlowControlFrames.WriteMaximumStreamsFrameFields(destination, frame);
                return;

            // The eight connection-management frames, paired by wire shape exactly
            // as the read dispatch above pairs them: seven arms, with
            // PATH_CHALLENGE and PATH_RESPONSE sharing one because s19.18 makes
            // their formats identical.
            //
            // ConnectionClose is the fourth ranged type to reach a writer, after
            // Stream, MaxStreams and StreamsBlocked, and the only one in this
            // family: 0x1c and 0x1d both derive to it, so "emit RawType, not
            // (ulong)Type" is observable here - and more sharply than for the
            // others, since the two forms differ in which fields follow. The other
            // seven types are not range bases, so for them the two are equal by
            // construction, the same honest gap the Padding/Ping/HandshakeDone arm
            // above records.
            case TlsQuicFrameType.ResetStream:
                TlsQuicConnectionFrames.WriteResetStreamFrameFields(destination, frame);
                return;
            case TlsQuicFrameType.StopSending:
                TlsQuicConnectionFrames.WriteStopSendingFrameFields(destination, frame);
                return;
            case TlsQuicFrameType.NewToken:
                TlsQuicConnectionFrames.WriteNewTokenFrameFields(destination, frame);
                return;
            case TlsQuicFrameType.NewConnectionId:
                TlsQuicConnectionFrames.WriteNewConnectionIdFrameFields(destination, frame);
                return;
            case TlsQuicFrameType.RetireConnectionId:
                TlsQuicConnectionFrames.WriteRetireConnectionIdFrameFields(destination, frame);
                return;
            case TlsQuicFrameType.PathChallenge:
            case TlsQuicFrameType.PathResponse:
                TlsQuicConnectionFrames.WritePathDataFrameFields(destination, frame);
                return;
            case TlsQuicFrameType.ConnectionClose:
                TlsQuicConnectionFrames.WriteConnectionCloseFrameFields(destination, frame);
                return;

            // THE ONE FRAME TYPE THIS LIBRARY READS AND REFUSES TO WRITE, and
            // the refusal is the feature. Task C17 closed an advertisement, not
            // a feature: this client advertises max_datagram_frame_size and
            // SETTINGS_H3_DATAGRAM by default, so it must not kill a connection
            // over an arriving DATAGRAM - but it implements no datagram
            // semantics and must never claim to by emitting one.
            //
            // An explicit arm rather than a fall-through to `default` below.
            // Falling through would throw the same exception with a message
            // reading like an oversight, and would leave the refusal resting on
            // the absence of a case label - which the next person to add a frame
            // type could undo without ever reading a word about why it was
            // absent. Pinned by
            // TlsQuicFramesTests.WritingADatagramFrameThrowsBecauseThisLibrary
            // NeverSendsOne.
            //
            // RFC 9221 s3 makes sending a separate permission this endpoint has
            // not got anyway: "An endpoint MUST NOT send DATAGRAM frames until
            // it has received the max_datagram_frame_size transport parameter
            // with a non-zero value during the handshake." Nothing in this tree
            // reads a peer's value of that parameter, so even the conformant
            // path to a first DATAGRAM does not exist here.
            case TlsQuicFrameType.Datagram:
                throw new ArgumentException(
                    "RFC 9221 DATAGRAM frames are parsed and dropped, never sent: SharpTls " +
                    "advertises max_datagram_frame_size and SETTINGS_H3_DATAGRAM but implements " +
                    "no datagram semantics.",
                    nameof(frame));

            default:
                // Reachable only for a RawType neither s12.4 Table 3 nor RFC 9221
                // assigns, since A2 task 5 gave every value from 0x00 to 0x1e a
                // case label above and task C17 gave 0x30-0x31 the refusing arm
                // immediately above - the same narrowing the read dispatch's
                // default arm records. A DATAGRAM therefore never reaches here,
                // which is why its refusal carries its own message rather than
                // this one's "not implemented".
                // TlsQuicFramesTests.WritingAFrameTypeAboveTableThreeThrows is the
                // surviving witness; WritingAnUnimplementedFrameTypeThrows was
                // deleted by that task because its subject, a Table 3 type with no
                // writer, stopped existing.
                throw new ArgumentException(
                    $"Frame type {frame.Type} is not implemented.", nameof(frame));
        }
    }
}
