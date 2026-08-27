namespace SharpTls.Quic;

// One acknowledged range of packet numbers, both ends inclusive - RFC 9000
// s19.3.1: "An ACK Range acknowledges all packets between the smallest packet
// number and the largest, inclusive." A range that acknowledges exactly one
// packet has Largest == Smallest, and s19.3.1 makes that legal explicitly: "A
// value of 0 indicates that only the largest packet number is acknowledged."
//
// Absolute packet numbers, not the wire's relative Gap / ACK Range Length
// pair. s19.3.1: "Gap and ACK Range Length values use a relative integer
// encoding for efficiency. Though each encoded value is positive, the values
// are subtracted, so that each ACK Range describes progressively lower-
// numbered packets." Relative values are meaningless outside their position in
// the chain, and that relative arithmetic is exactly where this frame's traps
// live, so it is done once - here, with both directions of each s19.3.1
// formula in one file for review - rather than in every caller.
internal readonly record struct TlsQuicAckRange(ulong Largest, ulong Smallest);

// RFC 9000 s19.3.2's three ECN counts, one struct because the RFC makes them
// all-present-or-all-absent: "ECN counts are only present when the ACK frame
// type is 0x03." Held on TlsQuicFrame as TlsQuicEcnCounts? rather than as
// three separate ulong fields for four reasons, all delivered by the type
// actually being used, not by named-argument discipline at any call site.
//
// First, all-or-nothing presence is the only state the type can represent:
// there is no way to hold "two of three counts" the way three independent
// ulong fields could. Second, absent is distinguishable from a legitimate
// all-zero reading: 0 is a legitimate cumulative count (s19.3.2 - "the total
// number of packets received"), so a plain ulong can never tell "type 0x03,
// legitimately reporting zero ECN packets so far" apart from "these fields
// were never populated at all," while null now carries that second meaning on
// its own. Third, it collapses three TlsQuicFrame fields into one. Fourth, it
// makes the "type says no ECN but counts are non-zero" contradiction
// unrepresentable rather than merely checked - see
// TlsQuicAckFrames.WriteFrameFields' hasEcnCounts comparison, which reduces to
// one nullability test instead of a bitwise OR across three fields.
//
// This does not, on its own, stop a positional TlsQuicEcnCounts(a, b, c) call
// from transposing two arguments - it is exactly as transposable as the old
// three-ulong parameter list, since C# does not require named arguments.
// Genuine immunity to that would need three distinct wrapper types (one per
// count), which is not worth it for A2.
internal readonly record struct TlsQuicEcnCounts(ulong Ect0, ulong Ect1, ulong EcnCe);

// ACK frames (RFC 9000 s19.3), both directions: the reader TlsQuicFrames
// dispatches to, the writer callers use, the s19.3.1 range arithmetic both
// share, and the s19.3.2 ECN bit rule. Pure functions - no connection state, no
// ACK generation policy, no loss detection.
//
// One file per frame family, both directions in it, is the A2 plan's amended
// layout, and ACK is why it was amended: the first split put the range
// arithmetic here and the frame's own fields in TlsQuicFrames, which cut
// horizontally through a single frame type and leaked both ways - the decoder
// reached into six TlsQuicFrame fields, TlsQuicFrames reached back for four
// members of this class, and the writer needed 33 lines of comment to explain
// where the cut fell. TlsQuicFrames now keeps the struct, the two dispatch
// switches and the field-less frames; everything ACK-shaped is here. Most
// helpers below are private; WriteFrameFields is internal because
// TlsQuicFrames.WriteFrame's Ack case is the other place "write an ACK" has
// to happen, and the two share this one implementation rather than diverging.
//
// Nothing here applies the ack_delay_exponent transport parameter to the ACK
// Delay field. s19.3 says the field "is decoded by multiplying the value in
// the field by 2 to the power of the ack_delay_exponent transport parameter
// sent by the sender of the ACK frame; see Section 18.2" - that needs the
// peer's transport parameters, which is a later phase's state.
// TlsQuicFrame.AckDelay is the raw field, undecoded, in both directions.
internal static class TlsQuicAckFrames
{
    /// <summary>
    /// RFC 9000 s19.3.2: "The ACK frame uses the least significant bit of the
    /// type value (that is, type 0x03) to indicate ECN feedback [...] ECN
    /// counts are only present when the ACK frame type is 0x03."
    /// </summary>
    internal const ulong EcnCountsBit = 0x01;

    /// <summary>
    /// Whether an ACK frame with this exact wire type carries the three ECN
    /// counts of RFC 9000 s19.3.2. Only meaningful for the two values s12.4
    /// Table 3 assigns to ACK, 0x02 and 0x03 - the caller has already matched
    /// the type, and s19.3.2 defines the bit only within that range.
    /// </summary>
    internal static bool HasEcnCounts(ulong rawAckFrameType) =>
        (rawAckFrameType & EcnCountsBit) != 0;

    // Reads everything after an ACK frame's type, in the order RFC 9000 s19.3
    // Figure 25 lists it:
    //
    //   ACK Frame {
    //     Type (i) = 0x02..0x03,
    //     Largest Acknowledged (i),
    //     ACK Delay (i),
    //     ACK Range Count (i),
    //     First ACK Range (i),
    //     ACK Range (..) ...,
    //     [ECN Counts (..)],
    //   }
    //
    // Note ACK Range Count precedes First ACK Range on the wire, which is not
    // the order the field descriptions below the figure use.
    //
    // Same Try-shaped contract as TlsQuicFrames.TryReadFrame, which is the only
    // production caller: never throws for any input, and `offset` only advances on
    // success. That second half needs a second caller to be observable at all -
    // TryReadFrame discards this method's `offset` on failure - and it has one:
    // TlsQuicAckFramesTests.TryReadAckCommitsNothingWhenItsRangeChainRejects calls
    // this directly at a nonzero offset, on a frame whose four fixed fields all
    // parse and whose range chain then underflows, so the most bytes possible have
    // been walked when the rejection fires. Nothing was widened for it; this method
    // is internal for the dispatch switch already.
    //
    // Takes ReadOnlyMemory<byte>, not ReadOnlySpan<byte>, following
    // TlsQuicPacketHeader.TryReadLongHeader (see its comment): AckRanges below
    // is stored on the returned frame as a ReadOnlyMemory<byte> slice of
    // `payload`, and a span-derived slice cannot become a ReadOnlyMemory<byte>
    // without copying. Taking Memory here lets it be a zero-copy slice instead.
    internal static bool TryReadAck(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        ulong rawType,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error)
    {
        frame = default;
        var span = payload.Span;
        var walked = offset;

        // s19.3, Largest Acknowledged: "A variable-length integer
        // representing the largest packet number the peer is acknowledging
        // [...] Unlike the packet number in the QUIC long or short header,
        // the value in an ACK frame is not truncated." So it is read whole,
        // with none of s17.1's packet number reconstruction.
        //
        // s19.3, ACK Range Count: "A variable-length integer specifying the
        // number of ACK Range fields in the frame." Read, never used to size
        // anything - see TryWalkRanges.
        //
        // s19.3, First ACK Range: "A variable-length integer indicating the
        // number of contiguous packets preceding the Largest Acknowledged
        // that are being acknowledged."
        if (!QuicVariableLengthInteger.TryRead(span, ref walked, out var largestAcknowledged) ||
            !QuicVariableLengthInteger.TryRead(span, ref walked, out var ackDelay) ||
            !QuicVariableLengthInteger.TryRead(span, ref walked, out var ackRangeCount) ||
            !QuicVariableLengthInteger.TryRead(span, ref walked, out var firstAckRange))
        {
            // Truncated fixed part. Same reasoning as TryReadFrame's own check:
            // the code is this namespace's FRAME_ENCODING_ERROR, chosen
            // directly rather than derived from a caught exception, and per
            // s12.4 frames "cannot span multiple packets" so there is nothing
            // to wait for.
            //
            // Mutation check (performed and reverted): see
            // TlsQuicAckFramesTests.AckTruncatedInItsFixedFieldsIsRejected.
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        var ackRangesOffset = walked;
        if (!TryWalkRanges(
            span, ref walked, largestAcknowledged, firstAckRange, ackRangeCount, null, out error))
        {
            return false;
        }

        var ackRangesLength = walked - ackRangesOffset;

        // Zero-copy slice of the ACK Ranges section, following A1's
        // TlsQuicLongHeader.PacketNumber pattern: the wire bytes themselves,
        // not a decoded value, and a slice of the caller's buffer rather than
        // a copy. Empty rather than a zero-length slice for AckRangeCount 0,
        // matching TlsQuicPacketHeader.TryReadConnectionId's convention for an
        // absent variable-length section. Pass the frame to TryGetRanges for
        // the packet numbers this section describes.
        var ackRanges = ackRangesLength == 0
            ? ReadOnlyMemory<byte>.Empty
            : payload.Slice(ackRangesOffset, ackRangesLength);

        // s19.3.2: "ECN counts are only present when the ACK frame type is
        // 0x03." Reading them unconditionally would silently swallow up to
        // three varints of whatever frame followed this one in the payload,
        // which is why this is a condition on the frame type and not on whether
        // three more varints happen to parse.
        //
        // Mutation check (performed and reverted): see
        // TlsQuicAckFramesTests.AckWithoutTheEcnBitDoesNotConsumeTheFollowingFrames.
        TlsQuicEcnCounts? ecnCounts = null;
        if (HasEcnCounts(rawType))
        {
            // s19.3.2 Figure 27 order: ECT0 Count, ECT1 Count, ECN-CE
            // Count. Each is "a variable-length integer representing the
            // total number of packets received with the [...] codepoint in
            // the packet number space of the ACK frame", so these are
            // cumulative connection totals, not per-frame deltas.
            if (!QuicVariableLengthInteger.TryRead(span, ref walked, out var ect0Count) ||
                !QuicVariableLengthInteger.TryRead(span, ref walked, out var ect1Count) ||
                !QuicVariableLengthInteger.TryRead(span, ref walked, out var ecnCeCount))
            {
                // Mutation check (performed and reverted): see
                // TlsQuicAckFramesTests.AckWithTheEcnBitButTruncatedEcnCountsIsRejected.
                error = TlsQuicTransportError.FrameEncodingError;
                return false;
            }
            ecnCounts = new TlsQuicEcnCounts(ect0Count, ect1Count, ecnCeCount);
        }

        frame = new TlsQuicFrame
        {
            RawType = rawType,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = ackDelay,
            AckRangeCount = ackRangeCount,
            FirstAckRange = firstAckRange,
            AckRanges = ackRanges,
            EcnCounts = ecnCounts,
        };
        offset = walked;
        return true;
    }

    // Appends one ACK frame's wire bytes to destination (RFC 9000 s19.3
    // Figure 25), acknowledging exactly the ranges given, in the order given.
    //
    // The ranges arrive here as absolute packet numbers, not as a
    // TlsQuicFrame, because a decoded TlsQuicFrame is a decode result: three
    // of its ACK fields (Largest Acknowledged, ACK Range Count, First ACK
    // Range) are fully determined by the range chain, so taking the struct
    // instead would leave fields that are silently recomputed. Passing only
    // what cannot be derived leaves nothing to disagree with: Largest
    // Acknowledged is ranges[0].Largest by definition, since s19.3's First ACK
    // Range is measured down from it, and ACK Range Count is ranges.Length - 1.
    //
    // This builds the frame's remaining field, AckRanges, by running the
    // ranges through WriteRangeChain into a scratch buffer, then hands the
    // whole frame to TlsQuicFrames.WriteFrame to put on the wire - the same entry
    // point every other frame type in this namespace uses. Before A2 task 3a
    // this method wrote its own bytes directly, because a decoded frame held
    // only the ACK Ranges section's *extent* (an offset and length into the
    // payload it was read from), which WriteFrame had no access to. Now
    // AckRanges is a self-contained ReadOnlyMemory<byte> slice - it carries its
    // own buffer reference - so WriteFrame can write an ACK frame from nothing
    // but the frame's own fields, and the reason this method needed its own
    // entry point is gone.
    //
    // Nothing is normalized, merged, or reordered: one wire ACK Range per range
    // given, in that order, even where two adjacent ranges could be expressed
    // as one. How a client splits its ACK ranges is observable and is part of
    // what subsystem B later imitates.
    //
    // Caller-chosen input, so every rejection throws rather than returning
    // false - same split as WriteFrame versus TryReadFrame.
    internal static void WriteAckFrame(
        List<byte> destination,
        ulong rawType,
        ulong ackDelay,
        ReadOnlySpan<TlsQuicAckRange> ranges,
        TlsQuicEcnCounts? ecnCounts = null)
    {
        ArgumentNullException.ThrowIfNull(destination);

        // s12.4 Table 3 assigns ACK exactly two values, 0x02 and 0x03, so the
        // ECN bit is only meaningful inside that pair - which is what
        // HasEcnCounts documents and what makes this check its precondition
        // rather than a courtesy. Without it, any odd frame type would be
        // written out with ACK's fields behind it.
        if (rawType != (ulong)TlsQuicFrameType.Ack &&
            rawType != ((ulong)TlsQuicFrameType.Ack | EcnCountsBit))
        {
            throw new ArgumentException(
                $"Frame type 0x{rawType:x} is not an ACK frame; RFC 9000 s12.4 Table 3 assigns ACK " +
                "0x02 and 0x03.",
                nameof(rawType));
        }

        // s19.3 Figure 25 makes First ACK Range a mandatory field, so an ACK
        // frame always acknowledges at least one range - there is no way to
        // encode an ACK that acknowledges nothing, and a zero-length `ranges`
        // is a caller bug rather than an empty-but-valid frame.
        if (ranges.IsEmpty)
        {
            throw new ArgumentException(
                "An ACK frame acknowledges at least one range: RFC 9000 s19.3's First ACK Range " +
                "field is mandatory.",
                nameof(ranges));
        }

        // ackDelay and ecnCounts are not bounded here: WriteFrameFields bounds
        // every field it writes, including these two, and every path through
        // this method ends at that call - so a check here would be a second
        // copy of the same test on the same value, invisible to a mutation
        // that deletes either one. See WriteFrameFields' own comment for the
        // fields that still need to be checked here (none - LargestAcknowledged
        // and FirstAckRange are ranges[0]-derived and already bounded below by
        // ValidateRanges, and AckRangeCount can never exceed ranges.Length - 1,
        // an int, so it is always encodable from this entry point).
        //
        // The one validation pass, and it happens before the first byte is
        // written: an unencodable range set must not leave a half-built ACK in
        // the caller's buffer. WriteRangeChain below does not re-check, and
        // does not need to - this is its only caller.
        ValidateRanges(ranges);

        // Encoded into a scratch buffer, not `destination` directly: this
        // becomes the frame's AckRanges field, which TlsQuicFrames.WriteFrame
        // copies verbatim. `destination` itself is not touched until that
        // call, so a rejection above never leaves partial output in it.
        List<byte> ackRangeBytes = [];
        WriteRangeChain(ackRangeBytes, ranges);

        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            LargestAcknowledged = ranges[0].Largest,
            AckDelay = ackDelay,
            AckRangeCount = (ulong)(ranges.Length - 1),
            FirstAckRange = ranges[0].Largest - ranges[0].Smallest,
            AckRanges = ackRangeBytes.ToArray(),
            EcnCounts = ecnCounts,
        };
        TlsQuicFrames.WriteFrame(destination, frame);
    }

    // Reads back the ACK Ranges of a frame TryReadAck already accepted, as
    // absolute packet-number ranges: the first from Largest Acknowledged and
    // First ACK Range, then one per ACK Range field. This is the caller-facing
    // entry point - the walker it delegates to is private and advances a cursor;
    // this one takes a frame and hands back a list.
    //
    // Takes only `frame`, not a separate payload: frame.AckRanges is already a
    // self-contained ReadOnlyMemory<byte> slice of the buffer the frame was
    // read from (see TlsQuicFrame.AckRanges), so there is no second buffer a
    // caller could mismatch it against, and no extent to bounds-check here -
    // Memory.Slice already proved AckRanges in-bounds when TryReadAck built it.
    // Before A2 task 3a, this took the payload back too and bounds-checked an
    // offset/length pair against it, because that was the only way a caller
    // could hand back the bytes the frame's extent pointed at; that check is
    // deleted, not weakened, because the state it guarded against - an extent
    // that outruns the buffer it is sliced from - is no longer constructible
    // through this API.
    //
    // `decoded` is appended to, not cleared, so ranges from several ACK frames
    // in one payload can accumulate in one list. A rejection removes only what
    // this call added - see RollBack.
    //
    // NULL MEANS VALIDATE ONLY, and it is not a new code path - TryWalkRanges
    // below has always taken a nullable list, because TryReadAck must walk the
    // whole chain to find where the frame ends while having nowhere to put the
    // ranges. This entry point now exposes the same choice, so that a caller
    // which only needs the s19.3.1 well-formedness verdict does not have to
    // allocate a list it never reads. TlsQuicAckTracker.ProcessAckFrame is that
    // caller, and it is on the receive path, where the size of what gets
    // allocated is the peer's choice.
    internal static bool TryGetRanges(
        in TlsQuicFrame frame,
        List<TlsQuicAckRange>? decoded,
        out TlsQuicTransportError error)
    {
        error = TlsQuicTransportError.NoError;

        if (frame.Type != TlsQuicFrameType.Ack)
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        var offset = 0;
        return TryWalkRanges(
            frame.AckRanges.Span,
            ref offset,
            frame.LargestAcknowledged,
            frame.FirstAckRange,
            frame.AckRangeCount,
            decoded,
            out error);
    }

    // Appends one ACK frame's wire bytes to destination from an already-built
    // frame (RawType, the four fixed fields, AckRanges, and EcnCounts all
    // populated) - the low-level half of what used to be WriteAckFrame's own
    // direct writing, now shared with TlsQuicFrames.WriteFrame's Ack case so
    // that "write an ACK" has exactly one implementation regardless of which
    // public entry point a caller used to reach it.
    //
    // RawType is still the single source of truth for whether this ACK
    // carries ECN counts (s19.3.2: "ECN counts are only present when the ACK
    // frame type is 0x03"), and frame.EcnCounts must agree with it - a type
    // 0x02 frame with EcnCounts set, or a type 0x03 frame with EcnCounts null,
    // is a contradiction and throws. Unlike the old three-ulong-parameter
    // check this replaces, this test is exact - EcnCounts null versus
    // non-null - rather than nonzero versus zero, so it also catches a type
    // 0x03 frame nobody ever populated EcnCounts on, which three ulongs
    // defaulting to 0 could never distinguish from a legitimate all-zero
    // report.
    //
    // Every field written below is bounded first, all of it before the first
    // byte is written - a caller reaching this method directly through
    // TlsQuicFrames.WriteFrame (not through WriteAckFrame, which no longer
    // bounds these itself; see its own comment) supplies these fields on a
    // TlsQuicFrame with no ValidateRanges pass to have gone through, so this
    // is the only bound they get. Seven separate calls, not one shared
    // pre-check, for the same reason WriteAckFrame's own bounds were seven
    // separate calls before this task: one shared helper invites one shared
    // test that pins only the first call site.
    internal static void WriteFrameFields(List<byte> destination, in TlsQuicFrame frame)
    {
        var hasEcnCounts = HasEcnCounts(frame.RawType);
        if (hasEcnCounts != (frame.EcnCounts is not null))
        {
            throw new ArgumentException(
                hasEcnCounts
                    ? $"ACK frame type 0x{frame.RawType:x2} carries ECN counts (RFC 9000 s19.3.2), " +
                      $"but {nameof(frame)}.{nameof(TlsQuicFrame.EcnCounts)} is null."
                    : $"ACK frame type 0x{frame.RawType:x2} does not carry ECN counts (RFC 9000 " +
                      "s19.3.2: \"ECN counts are only present when the ACK frame type is 0x03\"), " +
                      $"but {nameof(frame)}.{nameof(TlsQuicFrame.EcnCounts)} is set. Use type 0x03 " +
                      "to report them.",
                nameof(frame));
        }

        // LargestAcknowledged and FirstAckRange overlap ValidateRanges' own
        // bound on ranges[0] when reached through WriteAckFrame - that is
        // unavoidable duplication, not accidental: ValidateRanges must still
        // bound every range (including the ones that never become these two
        // fields, only Gap/Length differences in the chain WriteRangeChain
        // already encoded by the time this method runs), while these two
        // checks are what protect a frame built and passed straight to
        // TlsQuicFrames.WriteFrame, which never runs ValidateRanges at all.
        // See TlsQuicAckFramesTests.WritingAnAckRangeWhoseSmallestExceedsIts
        // LargestThrows for how its input was reshaped so ValidateRanges'
        // own guard stays independently visible despite the overlap.
        RequireEncodableVarint(frame.LargestAcknowledged, "largestAcknowledged");
        RequireEncodableVarint(frame.AckDelay, "ackDelay");
        RequireEncodableVarint(frame.AckRangeCount, "ackRangeCount");
        RequireEncodableVarint(frame.FirstAckRange, "firstAckRange");
        if (frame.EcnCounts is { } bounds)
        {
            RequireEncodableVarint(bounds.Ect0, "ect0");
            RequireEncodableVarint(bounds.Ect1, "ect1");
            RequireEncodableVarint(bounds.EcnCe, "ecnCe");
        }

        QuicVariableLengthInteger.Write(destination, frame.RawType);
        QuicVariableLengthInteger.Write(destination, frame.LargestAcknowledged);
        QuicVariableLengthInteger.Write(destination, frame.AckDelay);
        QuicVariableLengthInteger.Write(destination, frame.AckRangeCount);
        QuicVariableLengthInteger.Write(destination, frame.FirstAckRange);

        // The ACK Ranges section is copied verbatim rather than re-derived
        // from the fixed fields above: it is already exactly the wire bytes
        // this frame carries, whether they came from TryReadAck's zero-copy
        // slice of a received datagram or from WriteAckFrame's freshly encoded
        // scratch buffer.
        //
        // AddRange RATHER THAN A PER-BYTE Add LOOP: one bulk copy into the same
        // list, so the bytes and their order are unchanged and only the number of
        // capacity checks differs. The section grows with the number of ranges the
        // tracker has to report, and every TlsQuicFrames.MeasureFrame of this frame
        // re-encodes it. Pinned byte-for-byte by
        // TlsQuicAckFramesTests.AckReadFromTheWireIsWrittenBackByteForByte, which
        // reads a multi-range ACK off the wire and asserts the re-encoding is the
        // identical byte sequence.
        destination.AddRange(frame.AckRanges.Span);

        if (frame.EcnCounts is { } counts)
        {
            QuicVariableLengthInteger.Write(destination, counts.Ect0);
            QuicVariableLengthInteger.Write(destination, counts.Ect1);
            QuicVariableLengthInteger.Write(destination, counts.EcnCe);
        }
    }

    // Walks the ACK Range chain of RFC 9000 s19.3.1 from `offset`, validating
    // every computed packet number, and optionally collecting the ranges it
    // describes. The internal cursor-advancing walker: on success `offset` has
    // moved past the chain, on failure it is exactly as passed in.
    //
    // That failure-path half is DEFENCE IN DEPTH, not a pinned contract, and is
    // recorded as such rather than asserted - the same status
    // TlsQuicStreamFrames.TryReadData's identical promise carries, and for the same
    // reason. This method is private, and `offset` here is a local of whichever
    // caller invoked it: TryReadAck's `walked` and TryGetRanges' own `offset`,
    // neither of which is published when this returns false. So a version that
    // advanced `offset` before failing would behave identically through every
    // reachable caller and no test could observe the difference. Widening this to
    // internal purely so a test could call it would be scaffolding, not coverage -
    // it would make an unobservable property merely look pinned. The two callers'
    // own promises ARE pinned, by
    // TlsQuicAckFramesTests.TryReadAckCommitsNothingWhenItsRangeChainRejects and by
    // TryGetRanges taking no cursor from its caller at all.
    //
    // Try-shaped and never throws: an ACK frame's fields are attacker-
    // controlled (a peer holding the keys can put any bytes here) and a later
    // phase runs this in a receive loop. Every rejection reports
    // FRAME_ENCODING_ERROR, per s19.3.1's closing MUST and s20.1's own ACK
    // example, both quoted at the checks below.
    //
    // `decoded` is where the two callers differ, and it is nullable so that the
    // arithmetic below exists exactly once. TryReadAck passes null: it must
    // validate the whole chain to know where the frame ends, but it stores only
    // the section's extent, so it has nowhere to put ranges and must not
    // allocate for them. TryGetRanges passes the caller's list. Two copies of
    // these formulas - one validating, one decoding - is the single most
    // dangerous refactor available in this file: they could drift, and the drift
    // would surface as acknowledging packets that were never sent, not as a test
    // failure.
    //
    // No allocation is ever sized from `ackRangeCount`. That field is a
    // variable-length integer, so a peer can set it to nearly 2^62 in three
    // bytes; anything shaped like "allocate count entries, then parse" is a
    // remote memory-exhaustion defect that every functional test would pass.
    // Instead the loop below proves the bytes exist as it walks: each iteration
    // reads two varints, each varint either consumes at least one byte or its
    // TryRead call fails and returns out of the loop, so the loop cannot run
    // more times than there are bytes remaining, and a
    // `decoded` list only ever grows one entry per two-or-more bytes actually
    // consumed. Callers of TryGetRanges must not pre-size their list from
    // AckRangeCount either, for the same reason.
    private static bool TryWalkRanges(
        ReadOnlySpan<byte> payload,
        ref int offset,
        ulong largestAcknowledged,
        ulong firstAckRange,
        ulong ackRangeCount,
        List<TlsQuicAckRange>? decoded,
        out TlsQuicTransportError error)
    {
        error = TlsQuicTransportError.NoError;

        // Where this call's own additions start. Not 0: `decoded` is the
        // caller's list and may already hold ranges from an earlier ACK frame in
        // the same payload, which a rollback must not touch. See RollBack.
        var added = decoded?.Count ?? 0;

        // s19.3, First ACK Range: "A variable-length integer indicating the
        // number of contiguous packets preceding the Largest Acknowledged that
        // are being acknowledged. That is, the smallest packet acknowledged in
        // the range is determined by subtracting the First ACK Range value from
        // the Largest Acknowledged field."
        //
        // The check is before the subtraction, not after, because after is too
        // late: every packet number here is a ulong, and a ulong does not go
        // negative - 0 - 1 wraps to 18446744073709551615, a colossal packet
        // number that no endpoint ever sent. s19.3.1: "If any computed packet
        // number is negative, an endpoint MUST generate a connection error of
        // type FRAME_ENCODING_ERROR." Rejected, not wrapped.
        //
        // firstAckRange == largestAcknowledged is legal and is the largest
        // legal value: it makes smallest 0, acknowledging everything from
        // packet 0 up. The smallest illegal value is largestAcknowledged + 1,
        // so for largestAcknowledged == 0 the boundary is firstAckRange == 1.
        //
        // Mutation check (performed and reverted): see
        // TlsQuicAckFramesTests.AckWhoseFirstRangeUnderflowsPastZeroIsRejected.
        if (firstAckRange > largestAcknowledged)
        {
            error = TlsQuicTransportError.FrameEncodingError;
            return false;
        }

        var smallest = largestAcknowledged - firstAckRange;
        decoded?.Add(new TlsQuicAckRange(largestAcknowledged, smallest));

        var walked = offset;
        for (ulong index = 0; index < ackRangeCount; index++)
        {
            // s19.3.1 Figure 26: each ACK Range is Gap (i) then ACK Range
            // Length (i), and s19.3.1: "The number of Gap and ACK Range
            // Length values is determined by the ACK Range Count field; one
            // of each value is present for each value in the ACK Range
            // Count field."
            if (!QuicVariableLengthInteger.TryRead(payload, ref walked, out var gap) ||
                !QuicVariableLengthInteger.TryRead(payload, ref walked, out var ackRangeLength))
            {
                // This is the bound on ACK Range Count, and it is the exact
                // case s20.1 names when it defines the code: "FRAME_ENCODING_
                // ERROR (0x07): An endpoint received a frame that was badly
                // formatted -- for instance, a frame of an unknown type or an
                // ACK frame that has more acknowledgment ranges than the
                // remainder of the packet could carry." There is no separate
                // count-versus-length comparison to make, because an ACK frame
                // carries no length field: per s12.4 frames "cannot span
                // multiple packets", so the payload's end is the frame's only
                // outer bound, and running past it is malformed rather than
                // incomplete.
                //
                // The code reported is this namespace's own, chosen directly
                // rather than derived from a caught exception - TryRead
                // carries no code of its own to override.
                //
                // Mutation check (performed and reverted): see
                // TlsQuicAckFramesTests.AckRangeCountThatOverrunsTheBufferIsRejected
                // and AckRangeCountNearTheVarintMaximumIsRejectedWithoutAllocating.
                error = TlsQuicTransportError.FrameEncodingError;
                RollBack(decoded, added);
                return false;
            }

            // s19.3.1: "The value of the Gap field establishes the largest
            // packet number value for the subsequent ACK Range using the
            // following formula:
            //
            //    largest = previous_smallest - gap - 2"
            //
            // Guarded before the subtraction, for the ulong reason above.
            // `gap + 2` cannot itself overflow: gap came from a variable-length
            // integer, so gap <= 2^62 - 1 (s16 gives 62 value bits), hence
            // gap + 2 <= 2^62 + 1, far below 2^64. Writing the test this way
            // rather than as `smallest - 2 < gap` keeps it a single comparison
            // with no intermediate subtraction to underflow on its own.
            //
            // The boundary: gap == previous_smallest - 2 is the largest legal
            // gap, and it makes the next range's largest 0. So the smallest
            // illegal input is previous_smallest == 1 with gap == 0 - the
            // encoded gap cannot be smaller and the ACK cannot be tighter.
            // s19.3.1 explains why 2 and not 1: "Each Gap indicates a range of
            // packets that are not being acknowledged. The number of packets in
            // the gap is one higher than the encoded value of the Gap field." A
            // gap of 0 still skips one packet, so two consecutive ACK Ranges
            // can never be contiguous.
            //
            // Mutation check (performed and reverted): see
            // TlsQuicAckFramesTests.AckWhoseGapUnderflowsPastZeroIsRejected.
            if (gap + 2 > smallest)
            {
                error = TlsQuicTransportError.FrameEncodingError;
                RollBack(decoded, added);
                return false;
            }

            var largest = smallest - gap - 2;

            // s19.3.1: "Thus, given a largest packet number for the range, the
            // smallest value is determined by the following formula:
            //
            //    smallest = largest - ack_range"
            //
            // A separate subtraction from the Gap one above, so a separate
            // guard: ackRangeLength == largest is legal (the range reaches down
            // to packet 0) and ackRangeLength == largest + 1 is the smallest
            // illegal value, so with largest == 0 the boundary is
            // ackRangeLength == 1. Both halves of that boundary are pinned - a
            // `>=` here would reject the legal one.
            //
            // Mutation check (performed and reverted): see
            // TlsQuicAckFramesTests.AckWhoseRangeLengthUnderflowsPastZeroIsRejected.
            if (ackRangeLength > largest)
            {
                error = TlsQuicTransportError.FrameEncodingError;
                RollBack(decoded, added);
                return false;
            }

            smallest = largest - ackRangeLength;
            decoded?.Add(new TlsQuicAckRange(largest, smallest));

            // No ordering or overlap check is needed, and none is written: the
            // s19.3.1 formula makes both structural. largest is at most
            // previous_smallest - 2, so each range is strictly below the last
            // with at least one unacknowledged packet between them, which is
            // s19.3.1's "each ACK Range describes progressively lower-numbered
            // packets" and "descending packet number order". A check here would
            // be dead code, and dead validation is worse than none - it reads
            // like the invariant is enforced here rather than by the formula.
        }

        offset = walked;
        return true;
    }

    // Appends the ACK Range fields of RFC 9000 s19.3.1 Figure 26 - the Gap /
    // ACK Range Length pairs, one pair per range after the first. This is
    // exactly the bytes TlsQuicFrame.AckRanges holds and TryGetRanges walks;
    // WriteAckFrame runs it into a scratch buffer to build that field, rather
    // than appending straight to the caller's `destination`, so that the
    // resulting frame can go through TlsQuicFrames.WriteFrame like any other.
    //
    // ACK Range Count and First ACK Range are not written here, unlike the
    // pre-task-3a version of this method: they are separate TlsQuicFrame
    // fields (AckRangeCount, FirstAckRange) since AckRanges narrowed to match
    // exactly what TryReadAck's ackRangesLength covers, and
    // TlsQuicAckFrames.WriteFrameFields writes them directly from the frame
    // alongside the rest of the fixed fields - the same split TryReadAck
    // already uses on the read side. Requires a non-empty, already-validated
    // `ranges`; WriteAckFrame is the only caller and does both.
    private static void WriteRangeChain(List<byte> destination, ReadOnlySpan<TlsQuicAckRange> ranges)
    {
        for (var index = 1; index < ranges.Length; index++)
        {
            // Gap, the inverse of s19.3.1's "largest = previous_smallest - gap
            // - 2" solved for gap. Then ACK Range Length, the inverse of
            // "smallest = largest - ack_range" - s19.3.1 gives First ACK Range
            // and ACK Range Length the same meaning, which is why both are one
            // subtraction of the same shape.
            QuicVariableLengthInteger.Write(
                destination, ranges[index - 1].Smallest - ranges[index].Largest - 2);
            QuicVariableLengthInteger.Write(
                destination, ranges[index].Largest - ranges[index].Smallest);
        }
    }

    // Every rule the encode direction has to enforce, in the order the
    // arithmetic needs them, so that WriteRangeChain above can subtract
    // without rechecking anything.
    private static void ValidateRanges(ReadOnlySpan<TlsQuicAckRange> ranges)
    {
        for (var index = 0; index < ranges.Length; index++)
        {
            var range = ranges[index];

            // s12.3: "The packet number is an integer in the range 0 to 2^62-1.
            // [...] Packet numbers are limited to this range because they need
            // to be representable in whole in the Largest Acknowledged field of
            // an ACK frame (Section 19.3)."
            // QuicVariableLengthInteger.MaximumValue is that same 2^62-1,
            // derived there from the s16 encoding's 62 value bits.
            //
            // Checked for every range, not just the first, even though only the
            // first range's Largest is written as a field of its own: a later
            // range's Largest is written only as a gap, so without this bound an
            // out-of-range packet number would reach the `range.Largest + 2`
            // comparison below, where it could wrap past 2^64 and pass a check
            // it should fail.
            if (range.Largest > QuicVariableLengthInteger.MaximumValue)
            {
                throw new ArgumentException(
                    $"ACK range {index} largest ({range.Largest}) exceeds the largest QUIC packet " +
                    $"number, {QuicVariableLengthInteger.MaximumValue} (RFC 9000 s12.3).",
                    nameof(ranges));
            }

            if (range.Smallest > range.Largest)
            {
                throw new ArgumentException(
                    $"ACK range {index} smallest ({range.Smallest}) exceeds its largest " +
                    $"({range.Largest}).",
                    nameof(ranges));
            }

            // A gap below zero means the caller asked for two ranges that touch
            // or overlap, and the wire format cannot express that - s19.3.1's
            // "The number of packets in the gap is one higher than the encoded
            // value of the Gap field" means even an encoded gap of 0 skips a
            // packet, so consecutive ACK Ranges are never contiguous. Rejected
            // rather than wrapped: a wrapped gap near 2^64 would put an
            // acknowledgement for packets that were never sent on the wire.
            if (index > 0 && range.Largest + 2 > ranges[index - 1].Smallest)
            {
                throw new ArgumentException(
                    $"ACK range {index} (largest {range.Largest}) must be at least 2 below the " +
                    $"previous range's smallest ({ranges[index - 1].Smallest}): RFC 9000 s19.3.1 " +
                    "encodes it as largest = previous_smallest - gap - 2, so ranges must descend " +
                    "and cannot be contiguous.",
                    nameof(ranges));
            }
        }
    }

    // RFC 9000 s16 leaves a variable-length integer 62 value bits, so
    // QuicVariableLengthInteger.MaximumValue is 2^62 - 1 and a larger value has
    // no encoding. ArgumentException, matching every other caller-input
    // rejection in this file, rather than the ArgumentOutOfRangeException the
    // encoder would raise on its own.
    private static void RequireEncodableVarint(ulong value, string parameterName)
    {
        if (value > QuicVariableLengthInteger.MaximumValue)
        {
            throw new ArgumentException(
                $"ACK {parameterName} ({value}) exceeds the largest variable-length integer value, " +
                $"{QuicVariableLengthInteger.MaximumValue} (RFC 9000 s16).",
                parameterName);
        }
    }

    // Discards the ranges *this call* added before it failed, and only those -
    // `decoded` is the caller's list, and a caller decoding several ACK frames
    // from one payload into one list must not lose the ranges it already
    // accepted because a later frame was malformed. Hence the `added` baseline
    // rather than 0. A caller that heeds the false return would not look at the
    // partial ranges either way, but the failure mode if one does is the exact
    // thing this file exists to prevent: acting on packet numbers from a chain
    // that was rejected.
    //
    // Called from all three places TryWalkRanges can bail out after adding a
    // range, and each call is pinned separately by a row of
    // TlsQuicAckFramesTests.RangesDecodedBeforeARejectionDoNotSurviveIt: the
    // truncated-range check by (7, 0x40), the Gap guard by (7, 0x05), the ACK Range Length guard
    // by (8, 0x03). Deleting any one of the three fails exactly its own row -
    // verified, because "one shared helper, one shared test" would have pinned
    // only whichever call site happened to be reached first. The `added`
    // baseline has its own pin: that test seeds the list with a sentinel range
    // and asserts it is the sole survivor, which is what catches
    // `added = 0` - a mutation that left the rest of the Quic suite fully
    // green when every row started from an empty list.
    private static void RollBack(List<TlsQuicAckRange>? decoded, int added)
    {
        decoded?.RemoveRange(added, decoded.Count - added);
    }
}
