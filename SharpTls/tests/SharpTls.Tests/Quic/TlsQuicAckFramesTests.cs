using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// ACK frames (RFC 9000 s19.3, s19.3.1 ACK Ranges, s19.3.2 ECN Counts). Split
// from TlsQuicFramesTests because ACK carries more validity rules than every
// other frame type in this phase put together.
//
// There is no published test vector for an ACK frame, so a round-trip test here
// would only prove this library's encoder and decoder agree with each other -
// and they could agree while both being wrong. Every expected byte array below
// is therefore hand-derived from the s19.3 Figure 25 field list and the s16
// variable-length integer rules, with the derivation written out above the
// test, and asserted against the encoder directly. The wire order is the
// figure's, which is *not* the order the prose descriptions below the figure
// use - ACK Range Count comes before First ACK Range:
//
//   ACK Frame {
//     Type (i) = 0x02..0x03,
//     Largest Acknowledged (i),
//     ACK Delay (i),
//     ACK Range Count (i),
//     First ACK Range (i),
//     ACK Range (..) ...,       <- Gap (i), ACK Range Length (i), repeated
//     [ECN Counts (..)],        <- ECT0 (i), ECT1 (i), ECN-CE (i)
//   }
//
// Every value in these vectors is 63 or below except where noted, so it encodes
// as a single byte whose value is the value itself: s16 gives the first byte's
// two most significant bits as the log2 of the encoded length, so 0b00 means one
// byte with six value bits.
public sealed class TlsQuicAckFramesTests
{
    // 2^62 - 1, the largest value a variable-length integer can carry: s16
    // spends the first byte's two most significant bits on the length, leaving
    // 62 value bits in the 8-byte form. Not 2^64 - 1. RFC 9000 s12.3 makes it
    // the largest packet number for exactly this reason: "Packet numbers are
    // limited to this range because they need to be representable in whole in
    // the Largest Acknowledged field of an ACK frame (Section 19.3)."
    private const ulong VarintMaximum = (1UL << 62) - 1;

    // The 8-byte encoding of VarintMaximum: first byte 0b11_000000 for length
    // 2^3 = 8, or'd with the top 6 value bits (all ones) = 0xff, then seven more
    // 0xff bytes of value.
    private static readonly byte[] VarintMaximumEncoded =
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

    // Acknowledges packets 8, 9 and 10 - one range, no ECN.
    //
    //   Type                = 0x02  (ACK without ECN counts, s12.4 Table 3)
    //   Largest Acknowledged= 10    -> 0x0a
    //   ACK Delay           = 25    -> 0x19
    //   ACK Range Count     = 0     -> 0x00   (no ACK Range fields follow)
    //   First ACK Range     = 2     -> 0x02   (smallest = 10 - 2 = 8)
    [Fact]
    public void AckWithOneRangeMatchesItsHandDerivedBytesAndDecodesBackToThatRange()
    {
        byte[] expected = [0x02, 0x0a, 0x19, 0x00, 0x02];

        List<byte> destination = [];
        TlsQuicAckFrames.WriteAckFrame(
            destination, (ulong)TlsQuicFrameType.Ack, 25, [new TlsQuicAckRange(10, 8)]);

        Assert.Equal(expected, destination);

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(expected, ref offset, out var read, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(expected.Length, offset);
        Assert.Equal((ulong)TlsQuicFrameType.Ack, read.RawType);
        Assert.Equal(10UL, read.LargestAcknowledged);

        // The ACK Delay field is stored raw. s19.3 says it "is decoded by
        // multiplying the value in the field by 2 to the power of the
        // ack_delay_exponent transport parameter sent by the sender of the ACK
        // frame", which needs the peer's transport parameters - a later phase's
        // state. 25 in, 25 out, unscaled.
        Assert.Equal(25UL, read.AckDelay);
        Assert.Equal(0UL, read.AckRangeCount);
        Assert.Equal(2UL, read.FirstAckRange);

        // With ACK Range Count 0 the ACK Ranges section is empty.
        Assert.Equal(0, read.AckRanges.Length);

        Assert.Equal<TlsQuicAckRange>([new TlsQuicAckRange(10, 8)], Decode(read));
    }

    // Acknowledges 10-12, 6-7, and 2 - three ranges, no ECN. Derived from the
    // two s19.3.1 formulas, not from any example:
    //
    //   Type                 = 0x02
    //   Largest Acknowledged = 12    -> 0x0c
    //   ACK Delay            = 0     -> 0x00
    //   ACK Range Count      = 2     -> 0x02   (two ACK Range fields follow)
    //   First ACK Range      = 2     -> 0x02   smallest = 12 - 2 = 10
    //   ACK Range 1: Gap     = 1     -> 0x01   largest = previous_smallest - gap - 2
    //                                                 = 10 - 1 - 2 = 7
    //               Length   = 1     -> 0x01   smallest = largest - ack_range = 7 - 1 = 6
    //   ACK Range 2: Gap     = 2     -> 0x02   largest = 6 - 2 - 2 = 2
    //               Length   = 0     -> 0x00   smallest = 2 - 0 = 2
    //
    // Cross-check on the gaps, from s19.3.1's "The number of packets in the gap
    // is one higher than the encoded value of the Gap field": gap 1 means 2
    // unacknowledged packets, which are 8 and 9, between the range ending at 10
    // and the range starting at 7. Gap 2 means 3 packets - 3, 4 and 5 - between
    // 6 and 2. Both hold.
    [Fact]
    public void AckWithSeveralRangesMatchesItsHandDerivedBytesAndDecodesBackToThoseRanges()
    {
        byte[] expected = [0x02, 0x0c, 0x00, 0x02, 0x02, 0x01, 0x01, 0x02, 0x00];

        TlsQuicAckRange[] ranges =
        [
            new TlsQuicAckRange(12, 10),
            new TlsQuicAckRange(7, 6),
            new TlsQuicAckRange(2, 2),
        ];

        List<byte> destination = [];
        TlsQuicAckFrames.WriteAckFrame(destination, (ulong)TlsQuicFrameType.Ack, 0, ranges);
        Assert.Equal(expected, destination);

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(expected, ref offset, out var read, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(expected.Length, offset);
        Assert.Equal(12UL, read.LargestAcknowledged);
        Assert.Equal(2UL, read.AckRangeCount);
        Assert.Equal(2UL, read.FirstAckRange);

        // The ACK Ranges section is four bytes.
        Assert.Equal(4, read.AckRanges.Length);

        Assert.Equal<TlsQuicAckRange>(ranges, Decode(read));
    }

    // The ECN variant. s19.3.2: "ECN counts are only present when the ACK frame
    // type is 0x03."
    //
    //   Type                 = 0x03  (ACK with ECN counts)
    //   Largest Acknowledged = 5     -> 0x05
    //   ACK Delay            = 0     -> 0x00
    //   ACK Range Count      = 0     -> 0x00
    //   First ACK Range      = 0     -> 0x00   smallest = 5 - 0 = 5, so this
    //                                         acknowledges packet 5 alone -
    //                                         s19.3.1: "A value of 0 indicates
    //                                         that only the largest packet
    //                                         number is acknowledged."
    //   ECT0 Count           = 1     -> 0x01   s19.3.2 Figure 27 order
    //   ECT1 Count           = 2     -> 0x02
    //   ECN-CE Count         = 3     -> 0x03
    [Fact]
    public void AckWithEcnCountsMatchesItsHandDerivedBytes()
    {
        byte[] expected = [0x03, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03];

        List<byte> destination = [];
        TlsQuicAckFrames.WriteAckFrame(
            destination,
            (ulong)TlsQuicFrameType.Ack | TlsQuicAckFrames.EcnCountsBit,
            0,
            [new TlsQuicAckRange(5, 5)],
            new TlsQuicEcnCounts(Ect0: 1, Ect1: 2, EcnCe: 3));

        Assert.Equal(expected, destination);

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(expected, ref offset, out var read, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(expected.Length, offset);
        Assert.Equal(0x03UL, read.RawType);
        Assert.Equal(TlsQuicFrameType.Ack, read.Type);
        Assert.Equal(new TlsQuicEcnCounts(1, 2, 3), read.EcnCounts);
        Assert.Equal<TlsQuicAckRange>([new TlsQuicAckRange(5, 5)], Decode(read));
    }

    // A type 0x03 ACK reporting three zero counts is legal and still carries
    // all three fields: 0 is a legitimate cumulative count, so s19.3.2's
    // presence rule cannot be "present when nonzero". `ecnCounts` must still be
    // supplied explicitly, though - unlike the pre-task-3a three-ulong-default
    // signature, omitting it for a type 0x03 ACK is now a caller error (see
    // WritingAnAckWithMismatchedEcnCountPresenceThrows), not a silent all-zero
    // report, since TlsQuicEcnCounts? can finally tell "zero" from "absent"
    // apart.
    [Fact]
    public void AckWithEcnBitAndAllZeroCountsStillWritesThreeCountFields()
    {
        byte[] expected = [0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        List<byte> destination = [];
        TlsQuicAckFrames.WriteAckFrame(
            destination, 0x03, 0, [new TlsQuicAckRange(5, 5)], new TlsQuicEcnCounts(0, 0, 0));

        Assert.Equal(expected, destination);
    }

    // Largest Acknowledged at the variable-length integer maximum, 2^62 - 1.
    // This is the boundary the plan asks for, and it is also why the reader has
    // no upper-bound check on the field: 2^62 has no varint encoding at all
    // (s16 leaves 62 value bits), so a larger packet number cannot appear on the
    // wire to be rejected. The reader's job at this boundary is only to not
    // mangle the value - a reader that lost the top bits would report a
    // different packet number and acknowledge packets that were never sent.
    //
    //   Type                 = 0x02
    //   Largest Acknowledged = 2^62 - 1 -> 0xff * 8   (see VarintMaximumEncoded)
    //   ACK Delay            = 0        -> 0x00
    //   ACK Range Count      = 0        -> 0x00
    //   First ACK Range      = 0        -> 0x00       smallest = largest
    [Fact]
    public void AckWithLargestAcknowledgedAtTheVarintMaximumMatchesItsHandDerivedBytes()
    {
        byte[] expected = [0x02, .. VarintMaximumEncoded, 0x00, 0x00, 0x00];
        Assert.Equal(12, expected.Length);

        List<byte> destination = [];
        TlsQuicAckFrames.WriteAckFrame(
            destination,
            (ulong)TlsQuicFrameType.Ack,
            0,
            [new TlsQuicAckRange(VarintMaximum, VarintMaximum)]);

        Assert.Equal(expected, destination);

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(expected, ref offset, out var read, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(expected.Length, offset);
        Assert.Equal(4611686018427387903UL, read.LargestAcknowledged);
        Assert.Equal(VarintMaximum, read.LargestAcknowledged);
        Assert.Equal<TlsQuicAckRange>(
            [new TlsQuicAckRange(VarintMaximum, VarintMaximum)], Decode(read));
    }

    // The other end of the same boundary: First ACK Range at its largest legal
    // value, which s19.3 fixes at Largest Acknowledged itself ("the smallest
    // packet acknowledged in the range is determined by subtracting the First
    // ACK Range value from the Largest Acknowledged field"), so the range
    // reaches down to packet 0 and acknowledges every packet number there is.
    // One more would compute a negative packet number; see
    // AckWhoseFirstRangeUnderflowsPastZeroIsRejected.
    [Fact]
    public void AckWithFirstRangeReachingPacketZeroFromTheVarintMaximumIsAccepted()
    {
        byte[] encoded = [0x02, .. VarintMaximumEncoded, 0x00, 0x00, .. VarintMaximumEncoded];
        Assert.Equal(19, encoded.Length);

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var read, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(encoded.Length, offset);
        Assert.Equal(VarintMaximum, read.FirstAckRange);
        Assert.Equal<TlsQuicAckRange>(
            [new TlsQuicAckRange(VarintMaximum, 0)], Decode(read));
    }

    // s19.3.1: "If any computed packet number is negative, an endpoint MUST
    // generate a connection error of type FRAME_ENCODING_ERROR." This is the
    // smallest input in existence that violates it: Largest Acknowledged 0 with
    // First ACK Range 1 computes smallest = 0 - 1.
    //
    // The trap this pins is that in ulong the result does not go negative - it
    // wraps to 18446744073709551615 - so a reader that subtracts and then looks
    // at the result accepts an acknowledgement for a packet number no endpoint
    // has ever reached. TlsQuicAckFrames.TryWalkRanges compares before
    // subtracting for that reason.
    //
    // Isolating one check: ACK Range Count is 0, so the Gap and ACK Range Length
    // guards and the range-section bound never execute at all; the type is a
    // known one-byte value; all four fixed fields are present, so no truncation
    // catch can fire; and this is ACK type 0x02, so no ECN counts are read. The
    // First ACK Range comparison is the only check in the whole path that can
    // reject this input.
    //
    // Mutation check (performed and reverted): deleting the
    // `if (firstAckRange > largestAcknowledged)` guard in
    // TlsQuicAckFrames.TryWalkRanges makes this test fail - TryReadFrame returns
    // true and reports a range of (0, 18446744073709551615). 1 failure of 366 -
    // no other test's input reaches this guard.
    [Fact]
    public void AckWhoseFirstRangeUnderflowsPastZeroIsRejected()
    {
        // Type 0x02, Largest Acknowledged 0, ACK Delay 0, ACK Range Count 0,
        // First ACK Range 1.
        byte[] encoded = [0x02, 0x00, 0x00, 0x00, 0x01];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);

        // The legal twin, one byte different: First ACK Range 0 acknowledges
        // packet 0 alone. Proves the rejection above is about the arithmetic and
        // not about the frame's shape.
        byte[] legal = [0x02, 0x00, 0x00, 0x00, 0x00];
        offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(legal, ref offset, out var read, out error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal<TlsQuicAckRange>([new TlsQuicAckRange(0, 0)], Decode(read));
    }

    // The Gap subtraction of s19.3.1: "largest = previous_smallest - gap - 2".
    // Derived from the formula rather than from an example, so both halves of
    // the boundary are here:
    //
    //   previous_smallest = 2, gap = 0 -> largest = 0. Legal, and the tightest
    //     legal ACK Range there is: s19.3.1's "The number of packets in the gap
    //     is one higher than the encoded value of the Gap field" means gap 0
    //     still skips a packet, so two ranges can never be contiguous and the
    //     -2 is not an off-by-one.
    //   previous_smallest = 1, gap = 0 -> largest = -1. The smallest illegal
    //     input that exists: the gap cannot encode smaller than 0, and no
    //     tighter previous_smallest can carry a second range at all.
    //
    // Isolating one check on the rejected input: the type is known and
    // one-byte; every field is present, so no truncation catch fires; First ACK
    // Range 0 with Largest Acknowledged 1 cannot underflow, so the first-range
    // guard passes; ACK Range Length is 0, the smallest value there is, so the
    // range-length guard cannot be what rejects it; and type 0x02 reads no ECN
    // counts. Only the Gap guard is left.
    //
    // Mutation check (performed and reverted): deleting the
    // `if (gap + 2 > smallest)` guard in TlsQuicAckFrames.TryWalkRanges makes
    // this test fail - TryReadFrame returns true, having computed largest =
    // 18446744073709551615. 2 failures of 366: this one and the (7, 0x05) row of
    // RangesDecodedBeforeARejectionDoNotSurviveIt, which reaches the same guard
    // on purpose to pin its rollback.
    [Fact]
    public void AckWhoseGapUnderflowsPastZeroIsRejected()
    {
        // Type 0x02, Largest Acknowledged 1, ACK Delay 0, ACK Range Count 1,
        // First ACK Range 0 (smallest = 1), Gap 0, ACK Range Length 0.
        byte[] encoded = [0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);

        // The legal twin, one byte different (Largest Acknowledged 2 instead of
        // 1): acknowledges packet 2 and packet 0, skipping packet 1.
        byte[] legal = [0x02, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00];
        offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(legal, ref offset, out var read, out error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(legal.Length, offset);
        Assert.Equal<TlsQuicAckRange>(
            [new TlsQuicAckRange(2, 2), new TlsQuicAckRange(0, 0)], Decode(read));
    }

    // The other subtraction in the chain, s19.3.1's "smallest = largest -
    // ack_range", at its own boundary. This input is the legal twin from
    // AckWhoseGapUnderflowsPastZeroIsRejected with only its last byte changed
    // from 0 to 1: the Gap arithmetic still lands on largest = 0, and then ACK
    // Range Length 1 asks for smallest = -1.
    //
    // Isolating one check: every field is present (no truncation), First ACK
    // Range 0 cannot underflow, and the Gap guard demonstrably passes on this
    // input because its legal twin above - identical up to the final byte -
    // parses successfully. Only the ACK Range Length guard can reject it.
    //
    // Mutation checks (performed and reverted), both on the
    // `if (ackRangeLength > largest)` guard in TlsQuicAckFrames.TryWalkRanges.
    // Disabling it makes this test fail - TryReadFrame returns true with a second
    // range of (0, 18446744073709551615) - along with the (8, 0x03) row of
    // RangesDecodedBeforeARejectionDoNotSurviveIt, which reaches the same guard
    // deliberately to pin its rollback. Widening it to `>=` fails this test on the
    // nonzero legal twin below, and AckWhoseGapUnderflowsPastZeroIsRejected as
    // well - that second failure is the reason the twin was added: before it
    // existed, `>=` was caught *only* by the Gap test, whose own legal twin
    // happens to pass through this guard with ackRangeLength == largest == 0. A
    // guard pinned solely by another guard's test is this project's recurring
    // trap, and it survives every rename and refactor unnoticed.
    // Note the two subtraction guards must be mutated separately either way: the
    // Gap guard cannot cover for this one, because they check different
    // subtractions.
    [Fact]
    public void AckWhoseRangeLengthUnderflowsPastZeroIsRejected()
    {
        // Type 0x02, Largest Acknowledged 2, ACK Delay 0, ACK Range Count 1,
        // First ACK Range 0 (smallest = 2), Gap 0 (largest = 0),
        // ACK Range Length 1.
        byte[] encoded = [0x02, 0x02, 0x00, 0x01, 0x00, 0x00, 0x01];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);

        // The legal twin this guard needs of its own, at a boundary where both
        // sides are nonzero - the two sibling tests each have one and this one
        // did not, so `>` could be widened to `>=` here and only the *Gap* test
        // would notice, which is the same "pinned by the wrong test" problem in
        // miniature:
        //
        //   Largest Acknowledged 5, First ACK Range 0 -> smallest = 5
        //   Gap 1                                     -> largest  = 5 - 1 - 2 = 2
        //   ACK Range Length 2                        -> smallest = 2 - 2 = 0
        //
        // ackRangeLength == largest exactly, which s19.3.1 permits: the range
        // simply reaches down to packet 0. One more is the smallest illegal
        // value, and differs in a single byte.
        byte[] legal = [0x02, 0x05, 0x00, 0x01, 0x00, 0x01, 0x02];
        offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(legal, ref offset, out var read, out error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(legal.Length, offset);
        Assert.Equal<TlsQuicAckRange>(
            [new TlsQuicAckRange(5, 5), new TlsQuicAckRange(2, 0)], Decode(read));

        byte[] oneMore = [0x02, 0x05, 0x00, 0x01, 0x00, 0x01, 0x03];
        offset = 0;
        Assert.False(TlsQuicFrames.TryReadFrame(oneMore, ref offset, out _, out error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // s20.1 names this exact case when it defines the code: "FRAME_ENCODING_
    // ERROR (0x07): An endpoint received a frame that was badly formatted --
    // for instance, a frame of an unknown type or an ACK frame that has more
    // acknowledgment ranges than the remainder of the packet could carry."
    //
    // Two inputs, because an ACK Range is two varints and each read needs its
    // own bound: the first stops before the Gap, the second after it and before
    // the ACK Range Length.
    //
    // Isolating one check: in both inputs the four fixed fields are complete and
    // First ACK Range 4 is well below Largest Acknowledged 8, so no
    // packet-number guard can fire; in the second input Gap 0 against
    // previous_smallest 4 passes the Gap guard too. What is missing is bytes,
    // which only the bound on the range reads can catch.
    //
    // Mutation check (performed and reverted): making the
    // `catch (TlsQuicTransportException)` around the two range reads in
    // TlsQuicAckFrames.TryWalkRanges catch an unrelated type instead, so the
    // exception propagates, makes this test and
    // AckRangeCountNearTheVarintMaximumIsRejectedWithoutAllocating fail with an
    // unhandled TlsQuicTransportException escaping a Try-shaped method, rather
    // than a false return. 3 failures of 366 - the third is the (7, 0x40) row of
    // RangesDecodedBeforeARejectionDoNotSurviveIt, which truncates a range read
    // inside a valid extent to pin this path's rollback.
    [Fact]
    public void AckRangeCountThatOverrunsTheBufferIsRejected()
    {
        // Type 0x02, Largest Acknowledged 8, ACK Delay 0, ACK Range Count 1,
        // First ACK Range 4 - then the promised ACK Range never arrives.
        byte[] noGap = [0x02, 0x08, 0x00, 0x01, 0x04];
        var offset = 0;
        Assert.False(TlsQuicFrames.TryReadFrame(noGap, ref offset, out var frame, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);

        // Same frame with the Gap present but its ACK Range Length missing.
        byte[] gapButNoLength = [0x02, 0x08, 0x00, 0x01, 0x04, 0x00];
        offset = 0;
        Assert.False(
            TlsQuicFrames.TryReadFrame(gapButNoLength, ref offset, out frame, out error));
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // ACK Range Count is a variable-length integer, so a peer can promise
    // 4611686018427387903 ranges in eight bytes and supply two. Nothing may be
    // sized from it: an implementation shaped like "allocate ACK Range Count
    // entries, then parse" is a remote memory-exhaustion defect that no
    // functional test would notice.
    //
    // This test notices, because TryReadFrame is Try-shaped and must never
    // throw: an allocation of 2^62 - 1 entries throws OutOfMemoryException or
    // OverflowException out of a method whose contract is a false return, so the
    // Assert.False below fails rather than passing. The first ACK Range is valid
    // and complete so that an allocating implementation has to reach the
    // allocation at all, and the walk is proven to make real progress before it
    // runs out of bytes.
    [Fact]
    public void AckRangeCountNearTheVarintMaximumIsRejectedWithoutAllocating()
    {
        // Type 0x02, Largest Acknowledged 8, ACK Delay 0,
        // ACK Range Count 2^62 - 1 (eight bytes), First ACK Range 0
        // (smallest = 8), then one complete ACK Range: Gap 0 (largest = 6),
        // ACK Range Length 0 (smallest = 6). The second promised range's bytes
        // do not exist.
        byte[] encoded =
            [0x02, 0x08, 0x00, .. VarintMaximumEncoded, 0x00, 0x00, 0x00];
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // The fixed part of an ACK is four varints, and any of them can be
    // truncated. s12.4 makes this malformed rather than incomplete: frames
    // "always fit within a single QUIC packet and cannot span multiple packets",
    // so there is no continuation to wait for.
    //
    // Isolating one check: each input stops inside the fixed fields, before the
    // ACK Ranges section exists, so no packet-number guard and no range bound
    // can run - the first row does not even have a Largest Acknowledged to
    // compare against.
    //
    // Mutation check (performed and reverted): making the
    // `catch (TlsQuicTransportException)` around the four fixed-field reads in
    // TlsQuicAckFrames.TryReadAck catch an unrelated type instead makes all 6 rows
    // fail with an unhandled TlsQuicTransportException instead of a false
    // return, and nothing else in the Quic suite.
    [Theory]
    [InlineData(new byte[] { 0x02 })]                          // no Largest Acknowledged
    [InlineData(new byte[] { 0x02, 0x0a })]                    // no ACK Delay
    [InlineData(new byte[] { 0x02, 0x0a, 0x00 })]              // no ACK Range Count
    [InlineData(new byte[] { 0x02, 0x0a, 0x00, 0x00 })]        // no First ACK Range
    [InlineData(new byte[] { 0x03, 0x0a, 0x00, 0x00 })]        // same, ECN variant
    [InlineData(new byte[] { 0x02, 0x0a, 0x00, 0x00, 0x40 })]  // First ACK Range varint truncated
    public void AckTruncatedInItsFixedFieldsIsRejected(byte[] encoded)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // s19.3.2: "ECN counts are only present when the ACK frame type is 0x03."
    // The consequence for a reader is that ECN counts must be read on the type
    // bit, never on whether three more varints happen to be there - a payload
    // is "a sequence of complete frames" (s12.4 Figure 11), so the bytes after a
    // type 0x02 ACK belong to the next frame.
    //
    // Isolating one check: the ACK itself is complete and valid, and the three
    // PING frames after it are the shortest possible following frames, so the
    // only way to read fewer than four frames from this payload is to consume
    // bytes that are not part of the ACK.
    //
    // Mutation check (performed and reverted): changing the
    // `if (TlsQuicAckFrames.HasEcnCounts(rawType))` guard in
    // TlsQuicAckFrames.TryReadAck to an unconditional read makes this test fail -
    // one frame is read instead of four, with the three PING bytes swallowed as
    // ECT0/ECT1/ECN-CE counts of 1. It is the widest mutation in this file -
    // every type 0x02 vector here then over-reads - and this test is the one
    // that says *why* in terms of the following frame rather than in terms of
    // a byte count.
    [Fact]
    public void AckWithoutTheEcnBitDoesNotConsumeTheFollowingFrames()
    {
        // Type 0x02, Largest Acknowledged 5, ACK Delay 0, ACK Range Count 0,
        // First ACK Range 0 - then PING, PING, PING (s19.2, type 0x01).
        byte[] encoded = [0x02, 0x05, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01];

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var ack, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(5, offset);
        Assert.Equal(TlsQuicFrameType.Ack, ack.Type);
        Assert.Null(ack.EcnCounts);

        List<ulong> rest = [];
        while (offset < encoded.Length)
        {
            Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out _));
            rest.Add(frame.RawType);
        }

        Assert.Equal<ulong>(
            [
                (ulong)TlsQuicFrameType.Ping,
                (ulong)TlsQuicFrameType.Ping,
                (ulong)TlsQuicFrameType.Ping,
            ],
            rest);
    }

    // The converse: a type 0x03 ACK must consume exactly its three ECN counts
    // and stop, leaving the following frame readable. A reader that skipped the
    // counts would report the first count as the next frame.
    [Fact]
    public void AckWithTheEcnBitConsumesExactlyThreeCountsAndNoMore()
    {
        // The ECN vector from above, followed by a PING.
        byte[] encoded = [0x03, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x01];

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var ack, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(8, offset);
        Assert.Equal(new TlsQuicEcnCounts(1, 2, 3), ack.EcnCounts);

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var ping, out error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal((ulong)TlsQuicFrameType.Ping, ping.RawType);
        Assert.Equal(encoded.Length, offset);
    }

    // A type 0x03 ACK whose ECN counts run off the end of the payload is
    // malformed, for the same s12.4 reason as any other truncated frame.
    //
    // Isolating one check: the four fixed fields are complete, ACK Range Count 0
    // means the range section is empty and its guards never run, and First ACK
    // Range 0 cannot underflow. Only the bound on the ECN count reads is left.
    //
    // Mutation check (performed and reverted): making the
    // `catch (TlsQuicTransportException)` around the three ECN reads in
    // TlsQuicAckFrames.TryReadAck catch an unrelated type instead makes all 3 rows
    // fail with an unhandled TlsQuicTransportException instead of a false
    // return, and nothing else in the Quic suite.
    [Theory]
    [InlineData(new byte[] { 0x03, 0x05, 0x00, 0x00, 0x00 })]              // no counts at all
    [InlineData(new byte[] { 0x03, 0x05, 0x00, 0x00, 0x00, 0x01 })]        // only ECT0
    [InlineData(new byte[] { 0x03, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02 })]  // no ECN-CE
    public void AckWithTheEcnBitButTruncatedEcnCountsIsRejected(byte[] encoded)
    {
        var offset = 0;

        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // An ACK sits in a payload beside other frames, at a nonzero offset. Its
    // ACK Ranges slice must be the bytes at that ACK's own position in the
    // shared buffer, not (for instance) the bytes at the start of the
    // payload, so decoding it must produce this ACK's own ranges. A PING
    // before and after also pins that the reader leaves the following frame
    // where it found it.
    [Fact]
    public void AckAtANonzeroOffsetInAPayloadDecodesItsOwnRangesAndLeavesNeighboringFramesIntact()
    {
        // PING, then the several-ranges ACK vector, then PING.
        byte[] encoded = [0x01, 0x02, 0x0c, 0x00, 0x02, 0x02, 0x01, 0x01, 0x02, 0x00, 0x01];

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var ping, out _));
        Assert.Equal((ulong)TlsQuicFrameType.Ping, ping.RawType);
        Assert.Equal(1, offset);

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var ack, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(10, offset);

        // The ACK starts at byte 1, so its four fixed fields end - and its ACK
        // Ranges section starts - at byte 6, four bytes long.
        Assert.Equal(4, ack.AckRanges.Length);
        Assert.Equal<TlsQuicAckRange>(
            [
                new TlsQuicAckRange(12, 10),
                new TlsQuicAckRange(7, 6),
                new TlsQuicAckRange(2, 2),
            ],
            Decode(ack));

        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var trailing, out _));
        Assert.Equal((ulong)TlsQuicFrameType.Ping, trailing.RawType);
        Assert.Equal(encoded.Length, offset);
    }

    // Before A2 task 3a, TryGetRanges took the payload back as a second
    // argument, because the frame stored only the *extent* of its ACK Ranges -
    // an offset and length into whatever buffer the caller supplied - and a
    // caller that supplied a different or too-short buffer got false rather
    // than an exception or ranges read from unrelated bytes. That whole
    // scenario is deleted along with the parameter it depended on, not
    // weakened: TlsQuicFrame.AckRanges is now a self-contained
    // ReadOnlyMemory<byte> slice with no second buffer to mismatch it
    // against, and the extent it used to describe was already proven
    // in-bounds by Memory.Slice when TryReadAck built it - there is no longer
    // an input that can reach a would-be bounds failure through this API.
    //
    // What remains meaningful, and still needs its own test, is that a frame
    // which is not an ACK at all has no ranges to decode - a PING frame's
    // AckRanges is `default`, and without this check a caller could
    // misinterpret that empty slice as "zero ACK Ranges" and get back a
    // spurious range decoded from the frame's zeroed ACK fields.
    //
    // Mutation check (performed and reverted): disabling the
    // `frame.Type != TlsQuicFrameType.Ack` check in
    // TlsQuicAckFrames.TryGetRanges makes this test fail - it returns true
    // with a spurious range of (0, 0) - and nothing else in the Quic suite.
    [Fact]
    public void TryGetRangesOnANonAckFrameReturnsFalse()
    {
        List<TlsQuicAckRange> decoded = [];
        Assert.False(TlsQuicAckFrames.TryGetRanges(
            new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }, decoded, out var error));
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Empty(decoded);
    }

    // A rejected chain leaves no ranges behind. The list is the caller's, and a
    // caller that ignored the false return and acted on a partial decode would
    // be acknowledging packets from a frame this library rejected - the exact
    // failure the whole file guards against.
    //
    // TryWalkRanges can bail out at three places once it has already added
    // ranges - the Gap guard, the ACK Range Length guard, and the catch around
    // the two range reads - and each has its own RollBack call, so each needs its
    // own input. All three rows below start from the same valid several-ranges
    // vector, whose extent is bytes 5..8, and change one byte of it so that the
    // first two ranges (12-10 and 7-6) decode and the third fails:
    //
    //   byte 8 = 0x03: ACK Range Length 3 against largest 2 -> smallest = 2 - 3.
    //     Pins the RollBack in the ACK Range Length guard.
    //   byte 7 = 0x05: Gap 5 against previous smallest 6 -> largest = 6 - 5 - 2.
    //     Pins the RollBack in the Gap guard. The length byte is untouched and
    //     the length guard is never reached.
    //   byte 7 = 0x40: s16 makes 0x40 a two-byte varint prefix, so Gap consumes
    //     bytes 7 and 8 (value 0, legal), and the ACK Range Length read then has
    //     no bytes left inside the four-byte extent. Pins the RollBack in the
    //     catch - no arithmetic guard fires, because Gap 0 against previous
    //     smallest 6 is perfectly legal.
    //
    // The list is seeded with a sentinel range before every row, and asserted to
    // be the sole survivor. That is what pins the *baseline* the rollback
    // measures from, which is a separate thing from pinning the three call
    // sites: `decoded` is the caller's list, and TryGetRanges appends rather than
    // clearing, so ranges accumulated from an earlier ACK frame in the same
    // payload are already in it. A rollback that removed everything instead of
    // only this call's additions would silently discard already-accepted
    // acknowledgements - and with every row starting from an empty list that bug
    // is invisible, which is exactly what a review mutation demonstrated by
    // changing `var added = decoded?.Count ?? 0` to `var added = 0` and leaving
    // the rest of the Quic suite fully green. 999 is a packet number no row's
    // frame can produce, so its survival cannot be an accident of the
    // arithmetic.
    //
    // Corrupts a copy of the frame's own AckRanges bytes rather than passing a
    // second, differently-corrupted buffer to TryGetRanges: since A2 task 3a
    // TryGetRanges reads only frame.AckRanges, so this builds a frame `with`
    // AckRanges replaced by the corrupted slice while every other field -
    // LargestAcknowledged, FirstAckRange, AckRangeCount - stays exactly what
    // TryReadAck decoded from the valid bytes. Those fixed fields sit before
    // byte 5 and the corruption never touches them, so this reaches the same
    // "trusted fixed fields, corrupted range chain" case the pre-task-3a
    // two-buffer version did.
    //
    // Mutation checks (performed and reverted), all in
    // TlsQuicAckFrames.TryWalkRanges: emptying each of the three RollBack calls
    // separately fails exactly the corresponding row of this test and nothing
    // else in the Quic suite - TryGetRanges still returns false, but the caller's
    // list is left holding the two ranges decoded from a chain this library
    // rejected. Replacing the `added` baseline with 0 fails all three rows and
    // nothing else, because that is the only place the sentinel matters.
    [Theory]
    [InlineData(8, 0x03)]
    [InlineData(7, 0x05)]
    [InlineData(7, 0x40)]
    public void RangesDecodedBeforeARejectionDoNotSurviveIt(int index, byte value)
    {
        byte[] valid = [0x02, 0x0c, 0x00, 0x02, 0x02, 0x01, 0x01, 0x02, 0x00];
        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(valid, ref offset, out var ack, out _));

        byte[] corrupted = [.. valid];
        corrupted[index] = value;

        // The frame itself is now unreadable, which is the primary defence.
        offset = 0;
        Assert.False(TlsQuicFrames.TryReadFrame(corrupted, ref offset, out _, out var error));
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);

        // Decoding the valid frame's fixed fields against the corrupted range
        // chain (bytes 5..8, both `index` values fall inside it) reaches the
        // rejection with two ranges already collected, and discards those two
        // without touching what the caller had before the call.
        var corruptedFrame = ack with { AckRanges = corrupted.AsMemory(5, 4) };
        var sentinel = new TlsQuicAckRange(999, 999);
        List<TlsQuicAckRange> decoded = [sentinel];
        Assert.False(TlsQuicAckFrames.TryGetRanges(corruptedFrame, decoded, out var rangeError));
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, rangeError);
        Assert.Equal<TlsQuicAckRange>([sentinel], decoded);
    }

    // The other half of the appending contract: a *successful* decode appends to
    // whatever the caller's list already holds rather than replacing it, so
    // ranges from several ACK frames in one payload accumulate. Pinned here
    // because the rollback test above can only prove what a rejection leaves
    // behind.
    [Fact]
    public void DecodingRangesAppendsToTheCallersListRatherThanReplacingIt()
    {
        byte[] encoded = [0x02, 0x0c, 0x00, 0x02, 0x02, 0x01, 0x01, 0x02, 0x00];
        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var ack, out _));

        var sentinel = new TlsQuicAckRange(999, 999);
        List<TlsQuicAckRange> decoded = [sentinel];
        Assert.True(TlsQuicAckFrames.TryGetRanges(ack, decoded, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal<TlsQuicAckRange>(
            [
                sentinel,
                new TlsQuicAckRange(12, 10),
                new TlsQuicAckRange(7, 6),
                new TlsQuicAckRange(2, 2),
            ],
            decoded);
    }

    // Read, decode, write, and the bytes must be identical - including the ACK
    // Delay field, which is neither scaled nor recomputed, and the ranges, which
    // are neither merged nor reordered.
    //
    // Also writes the same frame straight through TlsQuicFrames.WriteFrame,
    // with no WriteAckFrame call at all - the A2 task 3a capability
    // ("ACK writes through WriteFrame again", now that AckRanges is a
    // self-contained slice rather than an offset into a payload WriteFrame
    // does not have) has to reproduce the same bytes as the WriteAckFrame path
    // above, decoded straight from the wire with no re-derivation.
    [Fact]
    public void AckReadFromTheWireIsWrittenBackByteForByte()
    {
        byte[] encoded = [0x03, 0x0c, 0x19, 0x02, 0x02, 0x01, 0x01, 0x02, 0x00, 0x07, 0x08, 0x09];

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out _));
        Assert.Equal(encoded.Length, offset);

        var ranges = Decode(frame);
        List<byte> destination = [];
        TlsQuicAckFrames.WriteAckFrame(
            destination,
            frame.RawType,
            frame.AckDelay,
            [.. ranges],
            frame.EcnCounts);

        Assert.Equal(encoded, destination);

        List<byte> viaWriteFrame = [];
        TlsQuicFrames.WriteFrame(viaWriteFrame, frame);
        Assert.Equal(encoded, viaWriteFrame);

        // The three derived fields the writer does not take are the ones it
        // reproduces from `ranges` alone, so the byte-for-byte match above is
        // also what pins that derivation.
        Assert.Equal(12UL, frame.LargestAcknowledged);
        Assert.Equal(2UL, frame.AckRangeCount);
        Assert.Equal(2UL, frame.FirstAckRange);
    }

    // The writer emits one wire ACK Range per range given, in the order given,
    // even when two adjacent ranges could have been expressed as one. Which
    // ranges a client sends and how it splits them is observable, and subsystem
    // B later imitates it, so this is the caller's decision.
    //
    // Ranges 12-10 and 8-6 could be sent as one range 12-6 only if packet 9 were
    // acknowledged, which it is not - so the pair below is the tightest split the
    // format allows, Gap 0. Emitting it as one range would acknowledge a packet
    // the caller never named.
    [Fact]
    public void WriterEmitsAdjacentRangesSeparatelyWithoutMergingThem()
    {
        //   Largest Acknowledged = 12 -> 0x0c
        //   ACK Delay            = 0  -> 0x00
        //   ACK Range Count      = 1  -> 0x01
        //   First ACK Range      = 2  -> 0x02  smallest = 10
        //   Gap                  = 0  -> 0x00  largest = 10 - 0 - 2 = 8
        //   ACK Range Length     = 2  -> 0x02  smallest = 8 - 2 = 6
        byte[] expected = [0x02, 0x0c, 0x00, 0x01, 0x02, 0x00, 0x02];

        List<byte> destination = [];
        TlsQuicAckFrames.WriteAckFrame(
            destination, 0x02, 0, [new TlsQuicAckRange(12, 10), new TlsQuicAckRange(8, 6)]);

        Assert.Equal(expected, destination);
    }

    // RawType is the single source of truth for whether an ACK carries ECN
    // counts (s19.3.2: "ECN counts are only present when the ACK frame type is
    // 0x03"), and TlsQuicFrame.EcnCounts must agree with it or writing throws -
    // both directions. This is the A2 task 3a replacement for the pre-task-3a
    // three-ulong-parameter version of this check (WriteAckFrame's
    // `(ect0Count | ect1Count | ecnCeCount) != 0`, tested with one InlineData
    // row per field to catch a check written against only one of the three):
    // that shape of mistake is no longer representable, because ecnCounts is
    // one nullable record now, not three interchangeable ulongs, so there is
    // exactly one way to "set" it rather than three. What is new here, and
    // what a three-ulong check could never test, is the other direction: type
    // 0x03 with EcnCounts left null, which the old defaulted-to-zero ulongs
    // could never distinguish from a legitimate all-zero report (see
    // AckWithEcnBitAndAllZeroCountsStillWritesThreeCountFields's comment).
    //
    // Reached through TlsQuicFrames.WriteFrame directly rather than through
    // WriteAckFrame: since A2 task 3a, WriteFrame is where "write an ACK" is
    // actually implemented (TlsQuicAckFrames.WriteFrameFields), so this is
    // also the test that proves the frame's internal consistency is still
    // enforced now that WriteFrame no longer refuses every ACK outright.
    //
    // Mutation check (performed and reverted): disabling the
    // `hasEcnCounts != (frame.EcnCounts is not null)` check in
    // TlsQuicAckFrames.WriteFrameFields fails both rows and nothing else in
    // the Quic suite. Also checked: moving the check to after the writes
    // (so it still throws, but only once part of the frame is already in
    // `destination`) fails both rows too, because the destination assertion
    // below - not just the exception type - is what that mutation breaks; a
    // version of this test without it would not have caught it.
    [Theory]
    [InlineData(0x02UL, true)]
    [InlineData(0x03UL, false)]
    public void WritingAnAckWithMismatchedEcnCountPresenceThrows(ulong rawType, bool setEcnCounts)
    {
        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            LargestAcknowledged = 5,
            EcnCounts = setEcnCounts ? new TlsQuicEcnCounts(1, 2, 3) : null,
        };
        List<byte> destination = [0xaa];

        Assert.Throws<ArgumentException>(() => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal<byte>([0xaa], destination);
    }

    // TlsQuicAckFrames.WriteFrameFields bounds every field it writes, reached
    // through TlsQuicFrames.WriteFrame directly rather than through
    // WriteAckFrame - the defect this pins was found by spec review of the
    // first version of this task: WriteFrameFields wrote LargestAcknowledged,
    // AckDelay, AckRangeCount, FirstAckRange and the ECN counts with no bound
    // at all, so a hand-built TlsQuicFrame passed straight to WriteFrame could
    // reach QuicVariableLengthInteger.Write with an unencodable value and get
    // back ArgumentOutOfRangeException naming a parameter ("value") this
    // namespace does not have, with part of the frame already in the caller's
    // buffer - the exact failure mode RequireEncodableVarint exists to
    // prevent elsewhere in this file. WriteAckFrame's own callers never hit
    // this: ValidateRanges bounds LargestAcknowledged/FirstAckRange (both
    // ranges[0]-derived) before WriteFrameFields is reached, and
    // AckRangeCount is ranges.Length - 1, an int, always encodable. Only a
    // frame built directly - as this test does - can carry an unencodable
    // value into WriteFrameFields, which is why this test goes through
    // WriteFrame and not WriteAckFrame.
    //
    // One row per field, each frame otherwise entirely valid (RawType 0x03 so
    // EcnCounts is required and the ECN rows reach their bound rather than the
    // presence check), so each row can only be rejected by its own field's
    // bound.
    //
    // Every row seeds `destination` with a sentinel and asserts it stays
    // alone, not just that something threw - a standing rule after this same
    // defect class survived two rounds in this file: RawType,
    // LargestAcknowledged, AckDelay, AckRangeCount and FirstAckRange are all
    // written by TlsQuicAckFrames.WriteFrameFields before the field-specific
    // rows above them in the frame (LargestAcknowledged before AckDelay,
    // AckDelay before AckRangeCount, and so on), so a bound moved below an
    // earlier field's write would still throw ArgumentException - the
    // exception-type assertion alone cannot tell "rejected before the first
    // byte" from "rejected after five of seven fields are already in the
    // buffer".
    //
    // Mutation checks (performed and reverted), each against its own
    // RequireEncodableVarint call in TlsQuicAckFrames.WriteFrameFields and
    // each failing only its own row and nothing else in the Quic suite:
    // deleting the LargestAcknowledged call, the AckDelay call, the
    // AckRangeCount call, the FirstAckRange call, and each of the three ECN
    // calls, seven mutations total. Also checked: moving the AckDelay bound
    // below the RawType and LargestAcknowledged writes (leaving the check
    // itself intact) makes the "ackDelay" row fail on the destination
    // assertion - [0xaa, 3, 5] instead of [0xaa] - which the exception-type
    // assertion alone did not catch.
    [Theory]
    [InlineData("largestAcknowledged")]
    [InlineData("ackDelay")]
    [InlineData("ackRangeCount")]
    [InlineData("firstAckRange")]
    [InlineData("ect0")]
    [InlineData("ect1")]
    [InlineData("ecnCe")]
    public void WritingAnAckFrameDirectlyThroughWriteFrameWithAFieldAboveTheVarintMaximumThrows(string field)
    {
        const ulong TooLarge = VarintMaximum + 1;
        var frame = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Ack | TlsQuicAckFrames.EcnCountsBit,
            LargestAcknowledged = field == "largestAcknowledged" ? TooLarge : 5,
            AckDelay = field == "ackDelay" ? TooLarge : 0,
            AckRangeCount = field == "ackRangeCount" ? TooLarge : 0,
            FirstAckRange = field == "firstAckRange" ? TooLarge : 0,
            EcnCounts = new TlsQuicEcnCounts(
                field == "ect0" ? TooLarge : 0,
                field == "ect1" ? TooLarge : 0,
                field == "ecnCe" ? TooLarge : 0),
        };
        List<byte> destination = [0xaa];

        Assert.Throws<ArgumentException>(() => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal<byte>([0xaa], destination);
    }

    // The WriteAckFrame-facing half of the same bound: ackDelay and the ECN
    // counts are no longer checked inside WriteAckFrame itself (see its own
    // comment) - they are checked once, in WriteFrameFields, which every
    // WriteAckFrame call reaches through TlsQuicFrames.WriteFrame. This test
    // proves that collapse did not lose the bound for WriteAckFrame's own
    // callers, only moved where it lives.
    //
    // Mutation check (performed and reverted): deleting the AckDelay,
    // Ect0, Ect1 or EcnCe RequireEncodableVarint call in
    // TlsQuicAckFrames.WriteFrameFields fails exactly its own row here (and
    // the corresponding row of
    // WritingAnAckFrameDirectlyThroughWriteFrameWithAFieldAboveTheVarintMaximumThrows
    // above) and nothing else in the Quic suite - so the bound is visible
    // from both entry points, not just the direct one. The failure without it
    // is not silent: QuicVariableLengthInteger.Write raises
    // ArgumentOutOfRangeException, a different type from a different file
    // naming a parameter ("value") this namespace does not have, after part
    // of the frame is already in the caller's buffer - which is why
    // Assert.Throws' exact-type match is load-bearing here.
    [Theory]
    [InlineData("delay")]
    [InlineData("ect0")]
    [InlineData("ect1")]
    [InlineData("ecnCe")]
    public void WritingAnAckFieldAboveTheVarintMaximumThrows(string field)
    {
        const ulong TooLarge = VarintMaximum + 1;
        var delay = field == "delay" ? TooLarge : 0;
        var ect0 = field == "ect0" ? TooLarge : 0;
        var ect1 = field == "ect1" ? TooLarge : 0;
        var ecnCe = field == "ecnCe" ? TooLarge : 0;

        // Type 0x03 throughout, so the ECN rows reach the bound check rather than
        // being rejected by the ECN-mismatch check first, and so the delay row is
        // not accidentally the only one that can fail.
        Assert.Throws<ArgumentException>(() => TlsQuicAckFrames.WriteAckFrame(
            [], 0x03, delay, [new TlsQuicAckRange(5, 5)], new TlsQuicEcnCounts(ect0, ect1, ecnCe)));
    }

    // The reverse of the above: WriteAckFrame writes its rawType argument as the
    // frame type and then ACK's fields after it, so a type that is not ACK would
    // emit a well-formed frame type followed by fields that type does not have -
    // a PING frame with four varints of debris behind it. The type is
    // caller-chosen, so this throws.
    //
    // s12.4 Table 3 assigns ACK exactly 0x02 and 0x03, so the last two rows
    // matter as much as the first three: 0x01 and 0x04 bracket the pair, and a
    // check written as "not 0x02" or as a mask would let one of them through.
    // TlsQuicAckFrames.HasEcnCounts reads the low bit and is only defined inside
    // the pair, so this guard is its precondition - without it, every odd frame
    // type would be written as an ACK carrying ECN counts.
    //
    // The ParamName assertion is load-bearing for three of the five rows, not
    // decorative: since ACK writes through TlsQuicFrames.WriteFrame (A2 task
    // 3a), disabling WriteAckFrame's own rawType guard does not let
    // ResetStream(0x04), Crypto(0x06) or 0x42 through silently - the frame
    // still reaches WriteFrame with a non-Ack Type, and WriteFrame's own
    // "frame type is not implemented" default arm rejects it with an
    // unrelated ArgumentException. An Assert.Throws<ArgumentException> alone
    // cannot tell that rejection from this guard's, so those three rows would
    // "pass" whether or not WriteAckFrame's guard exists - only Padding(0x00)
    // and Ping(0x01) are cases WriteFrame would otherwise happily write with
    // no exception at all (see WriteFrame's Padding/Ping/HandshakeDone arm),
    // so only those two rows genuinely pinned the guard before this
    // assertion was added. WriteAckFrame's guard throws with nameof(rawType);
    // WriteFrame's default arm throws with nameof(frame) - different
    // ParamName strings - so asserting ParamName == "rawType" makes all five
    // rows pin the same guard again.
    //
    // Mutation check (performed and reverted): disabling the rawType guard in
    // TlsQuicAckFrames.WriteAckFrame fails all 5 rows and nothing else in the
    // Quic suite. Before the ParamName assertion existed, the same mutation
    // also "failed all 5 rows" for the wrong reason - Padding/Ping failed
    // because no exception was thrown at all, ResetStream/Crypto/0x42 failed
    // only in the sense that some other check's ArgumentException happened to
    // still fire, which the assertion could not distinguish from this one.
    [Theory]
    [InlineData((ulong)TlsQuicFrameType.Padding)]
    [InlineData((ulong)TlsQuicFrameType.Ping)]
    [InlineData((ulong)TlsQuicFrameType.ResetStream)]
    [InlineData((ulong)TlsQuicFrameType.Crypto)]
    [InlineData(0x42UL)]
    public void WritingANonAckTypeThroughWriteAckFrameThrows(ulong rawType)
    {
        var exception = Assert.Throws<ArgumentException>(() => TlsQuicAckFrames.WriteAckFrame(
            [], rawType, 0, [new TlsQuicAckRange(0, 0)]));
        Assert.Equal("rawType", exception.ParamName);
    }

    // s19.3 Figure 25 makes First ACK Range mandatory, so every ACK
    // acknowledges at least one range and there is no encoding for an ACK that
    // acknowledges nothing.
    //
    // Mutation check (performed and reverted): disabling the `ranges.IsEmpty`
    // guard in TlsQuicAckFrames.WriteAckFrame makes this test fail and nothing else,
    // with IndexOutOfRangeException from the ranges[0] access behind it - so the
    // guard is what turns a caller bug into a diagnosable one.
    [Fact]
    public void WritingAnAckWithNoRangesThrows()
    {
        Assert.Throws<ArgumentException>(() => TlsQuicAckFrames.WriteAckFrame([], 0x02, 0, []));
    }

    // The encode direction of s19.3.1's "largest = previous_smallest - gap - 2",
    // solved for gap. A gap below zero is not encodable, and must not be wrapped
    // into a gap near 2^64: that would acknowledge packets that were never sent.
    //
    // The rows walk the boundary out from the tightest legal split rather than
    // from an example. Against a previous range of 12-10:
    //   largest 8  -> gap 0. Legal, and covered by
    //                 WriterEmitsAdjacentRangesSeparatelyWithoutMergingThem.
    //   largest 9  -> gap -1. Contiguous with 12-10; the smallest illegal case.
    //   largest 10 -> gap -2. Overlaps the previous range at its smallest.
    //   largest 12 -> overlaps it entirely.
    //   largest 13 -> ascending, which s19.3.1's "descending packet number
    //                 order" forbids outright.
    //
    // Mutation check (performed and reverted): disabling the
    // `range.Largest + 2 > ranges[index - 1].Smallest` guard in
    // TlsQuicAckFrames.ValidateRanges fails all 4 rows here plus
    // WritingAnUnencodableAckLeavesTheDestinationUntouched, which uses the same
    // violation to test a different property, and nothing else in the Quic
    // suite.
    [Theory]
    [InlineData(9UL, 9UL)]
    [InlineData(10UL, 10UL)]
    [InlineData(12UL, 12UL)]
    [InlineData(13UL, 13UL)]
    public void WritingAnAckWhoseRangesAreNotStrictlyDescendingWithAGapThrows(
        ulong largest, ulong smallest)
    {
        Assert.Throws<ArgumentException>(() => TlsQuicAckFrames.WriteAckFrame(
            [], 0x02, 0, [new TlsQuicAckRange(12, 10), new TlsQuicAckRange(largest, smallest)]));
    }

    // A range whose smallest exceeds its largest is not a range; s19.3.1's
    // "smallest = largest - ack_range" has no solution for it.
    //
    // Two rows, not one: this test originally put the violation at index 0
    // (`[new TlsQuicAckRange(10, 11)]`), then moved it to index 1 when
    // TlsQuicAckFrames.WriteFrameFields grew its own LargestAcknowledged/
    // FirstAckRange bounds, because index 0's Largest/Smallest become those
    // two fields verbatim and WriteFrameFields' new FirstAckRange bound would
    // otherwise also reject the wrapped 10 - 11 with the same
    // ArgumentException type ValidateRanges itself throws, making a deleted
    // ValidateRanges guard invisible. That move fixed the shadow but cost the
    // suite its only index-0 coverage of ValidateRanges' loop - proven by a
    // mutation changing the loop's `index = 0` start to `index = 1`, which
    // then passed 370/370, since every remaining ValidateRanges test puts its
    // violation at index 1 or later. Moving the only witness for a check
    // un-pins it; this row adds index 0 back instead, alongside index 1
    // rather than instead of it.
    //
    // The ParamName assertion is what makes the index-0 row (`offendingIndex:
    // 0`) mean anything: ranges[0].Largest/Smallest always become
    // LargestAcknowledged/FirstAckRange, so a violation there is caught by
    // ValidateRanges *or* by WriteFrameFields' FirstAckRange bound - both
    // ArgumentException, so the type alone cannot tell them apart. The two
    // checks throw with different ParamName values (nameof(ranges) in
    // ValidateRanges; the literal field name in WriteFrameFields'
    // RequireEncodableVarint), so asserting ParamName == "ranges" pins
    // ValidateRanges specifically. Index 1's Largest/Smallest are never
    // copied into a WriteFrameFields field - they only ever appear as a
    // difference inside the ACK Range Length varint WriteRangeChain writes
    // before WriteFrameFields is ever reached - so that row's violation
    // cannot reach WriteFrameFields at all; it needs no ParamName check to
    // stay isolated, but gets one anyway for a uniform assertion across both
    // rows.
    //
    // Contract note: "firstAckRange" in the second mutation check below is a
    // string literal in TlsQuicAckFrames.WriteFrameFields'
    // RequireEncodableVarint(frame.FirstAckRange, "firstAckRange") call, not
    // a compiler-checked nameof(TlsQuicFrame.FirstAckRange) - renaming that
    // property will not update the literal, and nothing will fail to compile
    // if it drifts. The index-0 row's isolation only needs that literal to
    // stay different from "ranges", which a drifted rename would not break,
    // but a future reader relying on the exact string in the comment below
    // should know it is not enforced by the compiler.
    //
    // Mutation checks (performed and reverted), both against the
    // `range.Smallest > range.Largest` guard in TlsQuicAckFrames.ValidateRanges
    // and both failing only their own row and nothing else in the Quic suite:
    // disabling the guard outright fails the index-1 row with
    // ArgumentOutOfRangeException (the second range's ACK Range Length is
    // written as 10 - 11, which wraps to 18446744073709551615 and does not
    // even fit a variable-length integer, so the write dies further on
    // instead of naming the caller's mistake) and fails the index-0 row on
    // the ParamName assertion (WriteFrameFields' FirstAckRange bound catches
    // the same wrapped value instead, with ParamName "firstAckRange" rather
    // than "ranges"). Also checked: reverting ValidateRanges' loop from
    // `index = 0` back to `index = 1` fails only the index-0 row, on the same
    // ParamName assertion, and nothing else in the Quic suite - which is the
    // coverage this row exists to restore.
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void WritingAnAckRangeWhoseSmallestExceedsItsLargestThrows(int offendingIndex)
    {
        TlsQuicAckRange[] ranges = offendingIndex == 0
            ? [new TlsQuicAckRange(10, 11)]
            : [new TlsQuicAckRange(20, 15), new TlsQuicAckRange(10, 11)];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicAckFrames.WriteAckFrame([], 0x02, 0, ranges));
        Assert.Equal("ranges", exception.ParamName);
    }

    // s12.3 bounds every packet number at 2^62 - 1, "because they need to be
    // representable in whole in the Largest Acknowledged field of an ACK frame
    // (Section 19.3)".
    //
    // Two rows, same reason as WritingAnAckRangeWhoseSmallestExceedsItsLargest
    // Throws: ranges[0].Largest always becomes LargestAcknowledged, which
    // TlsQuicAckFrames.WriteFrameFields bounds before any byte is written, so
    // a violation at index 0 is fully shadowed there - `ValidateRanges` could
    // stop checking index 0's Largest bound entirely and every *wire* test
    // would still pass, because WriteFrameFields rejects the same value with
    // the same exception type. What is lost without ValidateRanges' own check
    // is diagnosis, not safety: the caller gets ParamName "largestAcknowledged"
    // and a raw s16 varint-range message instead of "ranges", the offending
    // range's index, and the s12.3 citation. This was found by a reviewer
    // explicitly asked to assume a fourth shadow existed after the third one
    // (see WritingAnAckRangeWhoseSmallestExceedsItsLargestThrows) and look for
    // it - adding `index > 0 &&` to this exact guard, mirroring the
    // descending-order check's own `index > 0 &&`, survived the full suite.
    //
    // The index-1 row (`offendingIndex: 1`) is unaffected by any of this:
    // ranges[1].Largest is never copied into a WriteFrameFields field, only
    // ever appearing as a Gap difference WriteRangeChain writes before
    // WriteFrameFields is reached, so its input is built so that only the
    // bound can reject it, and so that without the bound the failure is
    // silent rather than an exception. Its second range's largest is
    // ulong.MaxValue, so the descending-order check computes largest + 2 = 1
    // in ulong - which is *below* the previous range's smallest of 5 and
    // therefore passes. An implementation missing the bound then encodes
    // gap = 5 - ulong.MaxValue - 2 = 4, a perfectly well-formed varint, and
    // emits an ACK acknowledging packets 12-5 and 0 - a range the caller
    // never asked for, on a connection that may never have sent packet 0.
    //
    // Contract note: "largestAcknowledged" in the mutation checks below is a
    // string literal in TlsQuicAckFrames.WriteFrameFields'
    // RequireEncodableVarint(frame.LargestAcknowledged, "largestAcknowledged")
    // call, not a compiler-checked nameof(TlsQuicFrame.LargestAcknowledged) -
    // renaming that property will not update the literal, and nothing will
    // fail to compile if it drifts. The index-0 row's isolation only needs
    // that literal to stay different from "ranges", which a drifted rename
    // would not break, but the exact string is not enforced by the compiler.
    //
    // Mutation checks (performed and reverted), both against the
    // `range.Largest > QuicVariableLengthInteger.MaximumValue` guard in
    // TlsQuicAckFrames.ValidateRanges and both failing only their own row and
    // nothing else in the Quic suite: disabling the guard outright fails the
    // index-1 row - WriteAckFrame returns normally, with no exception of any
    // kind, having written [0x02, 0x0c, 0x00, 0x01, 0x07, 0x04, 0x00]; that
    // frame is not merely wrong, it is malformed, since decoding its Gap of 4
    // against a previous smallest of 5 computes 5 - 4 - 2, a negative packet
    // number, which s19.3.1 says the peer MUST treat as a
    // FRAME_ENCODING_ERROR connection error - and fails the index-0 row on
    // the ParamName assertion, since WriteFrameFields' LargestAcknowledged
    // bound catches the same out-of-range value instead, with ParamName
    // "largestAcknowledged" rather than "ranges". Adding `index > 0 &&` to
    // this guard (the exact mutation the reviewer found) fails only the
    // index-0 row, on the same ParamName assertion, and nothing else - the
    // coverage this row exists to restore.
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void WritingAnAckRangeAboveTheLargestPacketNumberThrows(int offendingIndex)
    {
        TlsQuicAckRange[] ranges = offendingIndex == 0
            ? [new TlsQuicAckRange(VarintMaximum + 1, VarintMaximum + 1)]
            : [new TlsQuicAckRange(12, 5), new TlsQuicAckRange(ulong.MaxValue, ulong.MaxValue)];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicAckFrames.WriteAckFrame([], 0x02, 0, ranges));
        Assert.Equal("ranges", exception.ParamName);
    }

    // An unencodable range set must not leave a partial frame in the caller's
    // buffer: the type, Largest Acknowledged and ACK Delay are written before
    // the range chain, so validation has to happen before any of them.
    //
    // Mutation check (performed and reverted): deleting the
    // `TlsQuicAckFrames.ValidateRanges(ranges);` call from the top of
    // TlsQuicAckFrames.WriteAckFrame fails this test and six others (every
    // WriteAckFrame test whose ranges violate a ValidateRanges rule) and
    // nothing else in the Quic suite. Since A2 task 3a, WriteAckFrame encodes
    // the range chain into a scratch buffer before ever touching `destination`
    // (see the comment above WriteRangeChain's call site), so `destination`
    // stays untouched either way here - what this specific test actually pins
    // is Assert.Throws' exact-type match: without ValidateRanges, the
    // unchecked subtraction inside WriteRangeChain produces a value with no
    // varint encoding, which QuicVariableLengthInteger.Write rejects with
    // ArgumentOutOfRangeException, not the plain ArgumentException a caller
    // gets from ValidateRanges naming the actual mistake.
    [Fact]
    public void WritingAnUnencodableAckLeavesTheDestinationUntouched()
    {
        List<byte> destination = [0xaa];

        Assert.Throws<ArgumentException>(() => TlsQuicAckFrames.WriteAckFrame(
            destination, 0x02, 0, [new TlsQuicAckRange(12, 10), new TlsQuicAckRange(10, 10)]));

        Assert.Equal<byte>([0xaa], destination);
    }

    // s19.3.2 puts the ECN indicator in the type's least significant bit, so the
    // bit and the two Table 3 values must agree. Both ACK types derive to the
    // same base Type (s12.4 Table 3, range 0x02-0x03), which is what makes
    // RawType the only place the distinction lives.
    [Fact]
    public void EcnCountsBitDistinguishesTheTwoAckTypes()
    {
        Assert.False(TlsQuicAckFrames.HasEcnCounts((ulong)TlsQuicFrameType.Ack));
        Assert.True(TlsQuicAckFrames.HasEcnCounts((ulong)TlsQuicFrameType.Ack | TlsQuicAckFrames.EcnCountsBit));
        Assert.Equal(0x03UL, (ulong)TlsQuicFrameType.Ack | TlsQuicAckFrames.EcnCountsBit);
        Assert.Equal(
            TlsQuicFrameType.Ack,
            new TlsQuicFrame { RawType = 0x02 }.Type);
        Assert.Equal(
            TlsQuicFrameType.Ack,
            new TlsQuicFrame { RawType = 0x03 }.Type);
    }

    // TryReadAck's own Try-shaped contract, called directly rather than through
    // TlsQuicFrames.TryReadFrame, which is the only production caller. The same
    // pin TlsQuicStreamFramesTests added for TryReadStream and TryReadCrypto in
    // A2 task 3b, and it exists for the same reason: TryReadFrame publishes its
    // `offset` only on success and leaves `frame` at default on failure, so a
    // sub-reader that advanced its caller's cursor on the way out would be
    // invisible from outside. The comment on TryReadAck claimed that promise with
    // nothing pinning it; this is the pin.
    //
    // The input is AckWhoseFirstRangeUnderflowsPastZeroIsRejected's - type 0x02,
    // Largest Acknowledged 0, ACK Delay 0, ACK Range Count 0, First ACK Range 1 -
    // chosen because it fails inside TryWalkRanges, after all four fixed fields
    // have been walked past. That is the failure with the most already consumed
    // and so the most for an early commit to expose. Adding a row rather than
    // moving that test's input, per the plan's rule about not relocating the only
    // coverage of a check.
    //
    // `offset` starts at 1, past the frame type, because that is where TryReadFrame
    // leaves it - and a nonzero start is what makes "exactly as passed in"
    // distinguishable from "reset to zero".
    //
    // Mutation check (performed and reverted): adding `offset = walked;` before the
    // `return false;` on TryReadAck's TryWalkRanges failure path fails this test and
    // nothing else in the Quic suite.
    //
    // Note what this does NOT reach: TryWalkRanges' own identical promise. It is
    // private, and both of its callers - TryReadAck here and TryGetRanges - pass a
    // local neither publishes on failure, so no test can observe whether it left
    // that local alone. Its comment says defence-in-depth for that reason.
    [Fact]
    public void TryReadAckCommitsNothingWhenItsRangeChainRejects()
    {
        byte[] payload = [0x02, 0x00, 0x00, 0x00, 0x01];
        var offset = 1;

        Assert.False(TlsQuicAckFrames.TryReadAck(
            payload, ref offset, 0x02, out var frame, out var error));
        Assert.Equal(1, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(default, frame.LargestAcknowledged);
        Assert.Equal(default, frame.FirstAckRange);
        Assert.Equal(0, frame.AckRanges.Length);
    }

    // Decodes a frame's ACK Ranges or fails the test. Wrapped because every
    // decode in this file is of a frame TryReadFrame already accepted, where a
    // false return would mean the reader and the decoder disagree about bytes
    // the reader had already validated. Took the source payload as a separate
    // parameter before A2 task 3a; frame.AckRanges is self-contained now, so
    // there is nothing left for a second parameter to do.
    private static List<TlsQuicAckRange> Decode(in TlsQuicFrame frame)
    {
        List<TlsQuicAckRange> decoded = [];
        Assert.True(TlsQuicAckFrames.TryGetRanges(frame, decoded, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        return decoded;
    }
}
