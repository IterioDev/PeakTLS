using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// ACK generation (RFC 9000 s13.1 packet processing, s13.2 generating
// acknowledgements, s13.2.5 host delay), against the frame layout of s19.3.
//
// WHY THE EXPECTED BYTES ARE HAND-DERIVED AND NOT ROUND-TRIPPED. A2 wrote both
// halves of the ACK codec - TlsQuicAckFrames.WriteAckFrame and TryGetRanges -
// so feeding this tracker's ranges through the encoder and back through the
// decoder proves only that A2 agrees with itself. It would agree just as well
// if the s19.3.1 chain ran in the wrong direction. Every expected array below
// is therefore derived from Figure 25's field list and Figure 26's Gap /
// ACK Range Length pair by hand, with the arithmetic written above the test,
// and asserted against the bytes WriteAckFrame actually emits.
//
//   ACK Frame {
//     Type (i) = 0x02..0x03,
//     Largest Acknowledged (i),
//     ACK Delay (i),
//     ACK Range Count (i),        <- pairs that FOLLOW, so one less than ranges
//     First ACK Range (i),
//     ACK Range (..) ...,         <- Gap (i), ACK Range Length (i), repeated
//   }
//
// s19.3.1 gives both formulas in the decode direction - "smallest = largest -
// ack_range" and "largest = previous_smallest - gap - 2" - so each derivation
// below inverts them: length = largest - smallest, gap = previous_smallest -
// largest - 2. Every value in these vectors is 63 or below, so s16's two-bit
// length prefix is 0b00 and each field is one byte holding its own value.
public sealed class TlsQuicAckTrackerTests
{
    // s12.4 Table 3 marks PADDING, ACK and CONNECTION_CLOSE with N - "Packets
    // containing only frames with this marking are not ack-eliciting" - and
    // marks nothing else, so CRYPTO stands for "an ordinary ack-eliciting
    // packet" throughout.
    private static readonly TlsQuicFrame[] Crypto =
        [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Crypto }];

    private static readonly TlsQuicFrame[] AckOnly =
        [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ack }];

    private static readonly TlsQuicFrame[] PaddingOnly =
        [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Padding }];

    private static readonly DateTimeOffset Epoch =
        new(2026, 8, 18, 0, 0, 0, TimeSpan.Zero);

    // Receives every number given, in the order given, all ack-eliciting and all
    // at the same instant - so ack_delay is zero and the vectors below isolate
    // the range chain. Order matters and is never sorted here: the insertion
    // path is what these tests exercise.
    private static TlsQuicAckTracker Receive(
        params ulong[] packetNumbers) =>
        Receive(new TlsQuicAckTracker(), TlsQuicEncryptionLevel.Initial, packetNumbers);

    private static TlsQuicAckTracker Receive(
        TlsQuicAckTracker tracker,
        TlsQuicEncryptionLevel level,
        params ulong[] packetNumbers)
    {
        foreach (var packetNumber in packetNumbers)
        {
            tracker.OnPacketReceived(level, packetNumber, Crypto, Epoch);
        }
        return tracker;
    }

    // The whole path under test: tracker state out, s19.3 bytes back. Goes
    // through WriteAckFrame rather than asserting on the TlsQuicAckRange list,
    // because a range list can be read two ways and a byte array cannot.
    private static byte[] Encode(
        TlsQuicAckTracker tracker,
        TlsQuicEncryptionLevel level = TlsQuicEncryptionLevel.Initial,
        DateTimeOffset? now = null,
        bool force = false)
    {
        Assert.True(tracker.TryBuildAck(level, now ?? Epoch, force, out var ackDelay, out var ranges));
        List<byte> encoded = [];
        TlsQuicAckFrames.WriteAckFrame(encoded, (ulong)TlsQuicFrameType.Ack, ackDelay, ranges);
        return [.. encoded];
    }

    // ---- The three range shapes the task names ------------------------------

    // A CONTIGUOUS RECEIVE SET, and packet number 0 with it.
    //
    // Received 0, 1, 2, 3 - one run, so one range (3, 0). s19.3.1: "An ACK
    // Range acknowledges all packets between the smallest packet number and the
    // largest, inclusive."
    //
    //   Type                 0x02
    //   Largest Acknowledged 3          the largest received
    //   ACK Delay            0          received and acknowledged at Epoch
    //   ACK Range Count      0          one range, and the first is not a pair
    //   First ACK Range      3 - 0 = 3  s19.3: "the smallest packet acknowledged
    //                                   in the range is determined by subtracting
    //                                   the First ACK Range value from the
    //                                   Largest Acknowledged field"
    //
    // PACKET NUMBER 0 IS THE POINT OF STARTING AT 0 rather than 1. s17.1 puts no
    // lower exclusion on a packet number, so 0 is an ordinary receivable packet;
    // an off-by-one that treated it as "no packet" would make First ACK Range 2
    // and silently stop acknowledging the first packet of every connection.
    [Fact]
    public void AContiguousReceiveSetFromPacketNumberZeroIsOneRange()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x03, 0x00, 0x00, 0x03 },
            Encode(Receive(0, 1, 2, 3)));
    }

    // The same four packets arriving in reverse, to show the range is a property
    // of the set and not of the arrival order - the merge path runs downward
    // here and upward above.
    [Fact]
    public void AContiguousReceiveSetArrivingInReverseIsTheSameOneRange()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x03, 0x00, 0x00, 0x03 },
            Encode(Receive(3, 2, 1, 0)));
    }

    // A SCATTERED RECEIVE SET.
    //
    // Received 10, 8, 6, 5, 4, 1. Runs, descending: [10], [8], [6..4], [1].
    // Four ranges: (10,10), (8,8), (6,4), (1,1).
    //
    //   Type                 0x02
    //   Largest Acknowledged 10
    //   ACK Delay            0
    //   ACK Range Count      4 - 1 = 3      three Gap/Length pairs follow
    //   First ACK Range      10 - 10 = 0    s19.3.1: "A value of 0 indicates that
    //                                       only the largest packet number is
    //                                       acknowledged."
    //   pair 1  Gap    10 - 8 - 2 = 0       only packet 9 is missing, and s19.3.1
    //                                       says "The number of packets in the gap
    //                                       is one higher than the encoded value",
    //                                       so one missing packet encodes as 0
    //           Length  8 - 8 = 0
    //   pair 2  Gap     8 - 6 - 2 = 0       only packet 7 missing
    //           Length  6 - 4 = 2           three packets, 6 5 4
    //   pair 3  Gap     4 - 1 - 2 = 1       two missing, 3 and 2
    //           Length  1 - 1 = 0
    //
    // Checked back through the decode formulas s19.3.1 actually prints:
    //   largest 10, smallest = 10 - 0 = 10
    //   largest = 10 - 0 - 2 = 8,  smallest = 8 - 0 = 8
    //   largest =  8 - 0 - 2 = 6,  smallest = 6 - 2 = 4
    //   largest =  4 - 1 - 2 = 1,  smallest = 1 - 0 = 1
    [Fact]
    public void AScatteredReceiveSetBecomesTheDescendingGapAndLengthChain()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x0a, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00 },
            Encode(Receive(10, 8, 6, 5, 4, 1)));
    }

    // A GAP AT THE LOW END.
    //
    // Received 5, 4, 3 and 0; packets 2 and 1 never arrived. Two ranges,
    // (5,3) and (0,0), with the gap below the last run rather than between two
    // interior ones.
    //
    //   Type                 0x02
    //   Largest Acknowledged 5
    //   ACK Delay            0
    //   ACK Range Count      2 - 1 = 1
    //   First ACK Range      5 - 3 = 2
    //   pair 1  Gap     3 - 0 - 2 = 1      two missing, 2 and 1
    //           Length  0 - 0 = 0          packet 0 alone
    //
    // THE LOWEST RANGE ENDS AT PACKET NUMBER 0, which is the zero-versus-absent
    // case for the chain's tail: an ACK Range Length of 0 here means "one packet,
    // number 0" and not "no range". Decode check: largest = 3 - 1 - 2 = 0, and
    // smallest = 0 - 0 = 0, which is exactly s19.3.1's floor - one lower and it
    // would be the negative that section makes a FRAME_ENCODING_ERROR.
    [Fact]
    public void AGapAtTheLowEndKeepsPacketNumberZeroAsItsOwnRange()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x05, 0x00, 0x01, 0x02, 0x01, 0x00 },
            Encode(Receive(5, 4, 3, 0)));
    }

    // ---- The subtraction that can acknowledge a packet never sent -----------

    // THE HIGHEST-VALUE WITNESS IN THIS FILE. Two packets with exactly one
    // number missing between them are NOT one range, and the wire says so in a
    // way no round-trip could: received 5 and 3, packet 4 never arrived.
    //
    //   Largest Acknowledged 5
    //   ACK Range Count      2 - 1 = 1
    //   First ACK Range      5 - 5 = 0
    //   pair 1  Gap     5 - 3 - 2 = 0      one missing packet, number 4
    //           Length  3 - 3 = 0
    //
    // If the tracker's merge condition is one too loose in the downward
    // direction - `packetNumber + 2 == range.Smallest` instead of `+ 1`, or the
    // algebraically tempting `packetNumber >= range.Smallest - 2` - the two
    // collapse into a single range (5,3) and the frame becomes
    // { 0x02, 0x05, 0x00, 0x00, 0x02 }: an acknowledgement of packet 4, which
    // was never received. s19.3 makes that permanent - "QUIC acknowledgments are
    // irrevocable. Once acknowledged, a packet remains acknowledged, even if it
    // does not appear in a future ACK frame" - so the peer retires a packet that
    // never arrived and the data in it is never retransmitted.
    //
    // The two directions are separate tests because a single one pins only
    // whichever branch of Insert its arrival order happens to reach.
    [Fact]
    public void APacketTwoBelowARangeStaysASeparateRangeAndNeverAcknowledgesTheSkippedNumber()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00 },
            Encode(Receive(5, 3)));
    }

    [Fact]
    public void APacketTwoAboveARangeStaysASeparateRangeAndNeverAcknowledgesTheSkippedNumber()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00 },
            Encode(Receive(3, 5)));
    }

    // The other side of the same condition: exactly adjacent packets DO merge,
    // so the tests above are pinning a boundary and not just "never merge".
    // Received 5 and 4 - one range (5,4), First ACK Range 5 - 4 = 1, no pairs.
    // A merge condition one too TIGHT leaves two ranges here, which s19.3.1
    // cannot even encode: "The number of packets in the gap is one higher than
    // the encoded value of the Gap field", so adjacent ranges have no Gap value,
    // and TlsQuicAckFrames.ValidateRanges throws rather than emitting bytes.
    [Fact]
    public void AdjacentPacketsMergeIntoOneRange()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x05, 0x00, 0x00, 0x01 },
            Encode(Receive(5, 4)));
    }

    // Filling a one-packet hole from the middle must merge BOTH ways at once.
    // Received 5, 3, then 4: the range (5,5) extends down and (3,3) extends up
    // and the two become one (5,3). Without the second coalesce step the list
    // holds two ranges that touch, which s19.3.1 cannot encode at all.
    //
    //   Largest Acknowledged 5, ACK Range Count 0, First ACK Range 5 - 3 = 2
    [Fact]
    public void FillingAOnePacketHoleCoalescesTheRangesOnBothSidesOfIt()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x05, 0x00, 0x00, 0x02 },
            Encode(Receive(5, 3, 4)));
    }

    // The gap-versus-length subtraction direction, stated as its own assertion
    // rather than left implicit in a whole-frame vector.
    //
    // s19.3.1 prints the decode direction: "largest = previous_smallest - gap -
    // 2". Inverted, gap = previous_smallest - largest - 2. Four numbers appear in
    // that one expression - the previous range's Smallest and Largest, this
    // range's Smallest and Largest - and the test has to make all four DIFFERENT
    // or it cannot tell the readings apart.
    //
    // EVERY RANGE HERE IS THREE PACKETS WIDE, AND THAT IS THE POINT. This test
    // used to receive 20 and 10 - two ranges one packet wide, so Largest ==
    // Smallest in both, so `ranges[index].Largest` and `ranges[index].Smallest`
    // are the same number and the formula the test is NAMED for was not pinned by
    // it. Mutating that operand left the whole Quic suite showing only three
    // tracker failures and this test green. That is mutation 16's pattern
    // recurring - the implementer had already caught their own hand-derivation
    // error in this exact arithmetic and written this test to prevent it, and the
    // test could not distinguish the cases either.
    //
    // Received 22, 21, 20 and 12, 11, 10. Two ranges, (22,20) and (12,10):
    //
    //   Largest Acknowledged 22
    //   ACK Range Count      2 - 1 = 1
    //   First ACK Range      22 - 20 = 2
    //   pair 1  Gap     20 - 12 - 2 = 6      seven missing packets, 19 down to 13
    //           Length  12 - 10 = 2          three packets, 12 11 10
    //
    // The four wrong readings and what each emits as the gap:
    //
    //   previous SMALLEST - this LARGEST - 2  = 20 - 12 - 2 = 6   correct
    //   previous SMALLEST - this SMALLEST - 2 = 20 - 10 - 2 = 8   the operand
    //                                                             this test
    //                                                             exists for
    //   previous LARGEST  - this LARGEST - 2  = 22 - 12 - 2 = 8
    //   this LARGEST - previous SMALLEST - 2  = 12 - 20 - 2 wraps to 2^64 - 10,
    //                                                       not varint-encodable
    //
    // And gap 6 is no longer equal to length 2, so a chain that emitted the two
    // in the wrong order is caught by the same vector.
    //
    // Decode check, through the formulas s19.3.1 actually prints: largest 22,
    // smallest = 22 - 2 = 20; largest = 20 - 6 - 2 = 12, smallest = 12 - 2 = 10.
    [Fact]
    public void TheGapIsPreviousSmallestMinusLargestMinusTwoAndNotTheReverse()
    {
        var encoded = Encode(Receive(22, 21, 20, 12, 11, 10));

        Assert.Equal(
            new byte[] { 0x02, 0x16, 0x00, 0x01, 0x02, 0x06, 0x02 },
            encoded);
        Assert.Equal(0x06, encoded[5]);
        Assert.Equal(0x02, encoded[6]);
    }

    // THE OVER-MERGE, PINNED FROM ABOVE. Every merge test above catches a
    // condition that is too TIGHT by its symptom - two adjacent ranges, which
    // s19.3.1 cannot encode and ValidateRanges throws on. Loosening the downward
    // coalesce instead has no such symptom: it produces a perfectly well-formed
    // frame that acknowledges a packet nobody received.
    //
    // Received 6, then 3, then 5. Packet 5 is adjacent below (6,6) so that range
    // extends down to (6,5) - and then the coalesce asks whether the range
    // beneath now touches it. (3,3).Largest + 1 is 4, and 4 != 5, so it does not:
    // packet 4 never arrived and the two must stay separate.
    //
    //   Largest Acknowledged 6
    //   ACK Range Count      2 - 1 = 1
    //   First ACK Range      6 - 5 = 1
    //   pair 1  Gap     5 - 3 - 2 = 0        one missing packet, number 4
    //           Length  3 - 3 = 0
    //
    // Under `ranges[index + 1].Largest + 2 == packetNumber` the two coalesce into
    // (6,3) and the frame becomes { 0x02, 0x06, 0x00, 0x00, 0x03 } - an
    // acknowledgement of packet 4. s19.3 makes it permanent: "QUIC
    // acknowledgments are irrevocable. Once acknowledged, a packet remains
    // acknowledged, even if it does not appear in a future ACK frame."
    //
    // FillingAOnePacketHoleCoalescesTheRangesOnBothSidesOfIt does die under that
    // same mutant, but on the adjacency symptom - it stops merging a hole that
    // WAS filled. Nothing before this test asked whether the merge could swallow
    // a hole that was not.
    [Fact]
    public void TheDownwardCoalesceDoesNotOverMergeAndAcknowledgeAnUnreceivedPacket()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x06, 0x00, 0x01, 0x01, 0x00, 0x00 },
            Encode(Receive(6, 3, 5)));
    }

    // ---- s13.2's ack-eliciting gate ----------------------------------------

    // s13.2: "Endpoints acknowledge all packets they receive and process.
    // However, only ack-eliciting packets cause an ACK frame to be sent within
    // the maximum ack delay. Packets that are not ack-eliciting are only
    // acknowledged when an ACK frame is sent for other reasons."
    //
    // So a space holding nothing but ACK-only packets owes no ACK. This is the
    // zero-versus-absent case for the pending flag: the range set is NOT empty -
    // packet 7 was received and would be acknowledged if an ACK went out for
    // another reason - and a tracker that decided on "are there ranges" would
    // send one and, per s13.2.1, risk exactly the loop that section forbids:
    // "An endpoint MUST NOT send a non-ack-eliciting packet in response to a
    // non-ack-eliciting packet, even if there are packet gaps that precede the
    // received packet. This avoids an infinite feedback loop of
    // acknowledgments."
    [Fact]
    public void APacketOfOnlyNonAckElicitingFramesGeneratesNoAck()
    {
        var tracker = new TlsQuicAckTracker();
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 7, AckOnly, Epoch);

        Assert.False(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));
    }

    // PADDING carries the same N marking, and is a separate row of Table 3 - a
    // gate that named only ACK would leave this green while the one above fails.
    [Fact]
    public void APacketOfOnlyPaddingGeneratesNoAck()
    {
        var tracker = new TlsQuicAckTracker();
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 7, PaddingOnly, Epoch);

        Assert.False(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));
    }

    // The other half of the same sentence: those packets ARE still acknowledged
    // "when an ACK frame is sent for other reasons", so the range survived and
    // the force overload reaches it. Without this, "generates no ACK" above
    // would be satisfied just as well by discarding the packet entirely.
    //
    //   Largest Acknowledged 7, ACK Range Count 0, First ACK Range 7 - 7 = 0
    [Fact]
    public void ANonAckElicitingPacketIsStillAcknowledgedWhenAnAckIsSentForOtherReasons()
    {
        var tracker = new TlsQuicAckTracker();
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 7, AckOnly, Epoch);

        Assert.True(tracker.TryBuildAck(
            TlsQuicEncryptionLevel.Initial, Epoch, force: true, out var ackDelay, out var ranges));
        List<byte> encoded = [];
        TlsQuicAckFrames.WriteAckFrame(encoded, (ulong)TlsQuicFrameType.Ack, ackDelay, ranges);

        Assert.Equal(new byte[] { 0x02, 0x07, 0x00, 0x00, 0x00 }, encoded);
    }

    // s19.3's First ACK Range is mandatory, so an ACK naming no packets has no
    // encoding - force must not manufacture one out of an empty space. The
    // separate guard from the flag above, reached by a different path.
    [Fact]
    public void ForcingAnAckOnASpaceThatHasReceivedNothingStillBuildsNothing()
    {
        var tracker = new TlsQuicAckTracker();

        Assert.False(tracker.TryBuildAck(
            TlsQuicEncryptionLevel.Initial, Epoch, force: true, out _, out _));
    }

    // A mixed packet is ack-eliciting: s12.4's N legend is "Packets containing
    // ONLY frames with this marking are not ack-eliciting", so one CRYPTO frame
    // beside an ACK frame is enough.
    [Fact]
    public void APacketMixingAnAckFrameWithACryptoFrameIsAckEliciting()
    {
        var tracker = new TlsQuicAckTracker();
        tracker.OnPacketReceived(
            TlsQuicEncryptionLevel.Initial,
            7,
            [
                new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ack },
                new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Crypto },
            ],
            Epoch);

        Assert.True(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));
    }

    // The flag is a debt, not a latch that the next packet overwrites. An
    // ack-eliciting packet followed by an ACK-only one still owes an ACK - an
    // assignment rather than an OR in OnPacketReceived would let the second
    // packet cancel the first packet's obligation, which s13.2.1's "MUST
    // acknowledge all ack-eliciting Initial and Handshake packets immediately"
    // forbids.
    [Fact]
    public void ANonAckElicitingPacketDoesNotCancelAnEarlierPacketsObligation()
    {
        var tracker = new TlsQuicAckTracker();
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 1, Crypto, Epoch);
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 2, AckOnly, Epoch);

        Assert.True(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));
    }

    // s13.2.1: "Since packets containing only ACK frames are not congestion
    // controlled, an endpoint MUST NOT send more than one such packet in
    // response to receiving an ack-eliciting packet." One ack-eliciting packet
    // buys one ACK; the ranges stay, the obligation does not.
    [Fact]
    public void OneAckElicitingPacketOwesExactlyOneAck()
    {
        var tracker = Receive(1);

        Assert.True(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));
        Assert.False(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));
        Assert.True(tracker.TryBuildAck(
            TlsQuicEncryptionLevel.Initial, Epoch, force: true, out _, out _));
    }

    // ---- s13.2.5 / s19.3's ACK Delay ---------------------------------------

    // ACK DELAY THROUGH A NON-DEFAULT EXPONENT.
    //
    // s18.2: "If this value is absent, a default value of 3 is assumed
    // (indicating a multiplier of 8)." This tracker advertises 5, so the
    // multiplier is 32.
    //
    // s19.3, ACK Delay: "A variable-length integer encoding the acknowledgment
    // delay in microseconds [...] It is decoded by multiplying the value in the
    // field by 2 to the power of the ack_delay_exponent transport parameter sent
    // by the sender of the ACK frame."
    //
    // The packet arrives at Epoch and the ACK is built 992 microseconds later.
    //   encoded = 992 / 2^5 = 992 / 32 = 31 = 0x1f
    //   decoded = 31 * 32 = 992 microseconds, exactly what was measured
    //
    // At the DEFAULT exponent of 3 the same delay encodes as 992 / 8 = 124,
    // which is above 63 and so takes s16's two-byte form, { 0x40, 0x7c } - a
    // different value AND a different field width, so this vector cannot pass
    // against a tracker that ignored its exponent.
    //
    //   Type 0x02, Largest Acknowledged 0, ACK Delay 0x1f,
    //   ACK Range Count 0, First ACK Range 0 - 0 = 0
    //
    // Largest Acknowledged is packet number 0 deliberately: a zero there is a
    // real acknowledgement of a real packet, and sits next to a NON-zero ACK
    // Delay so the two zeros in this frame cannot be swapped unnoticed.
    [Fact]
    public void AckDelayIsScaledByThisEndpointsNonDefaultAckDelayExponent()
    {
        var tracker = new TlsQuicAckTracker(ackDelayExponent: 5);
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 0, Crypto, Epoch);

        Assert.Equal(
            new byte[] { 0x02, 0x00, 0x1f, 0x00, 0x00 },
            Encode(tracker, now: Epoch + TimeSpan.FromMicroseconds(992)));
    }

    // The same 992 microseconds at the default exponent, to show the previous
    // vector is measuring the exponent and not the delay.
    [Fact]
    public void TheSameDelayAtTheDefaultExponentEncodesDifferently()
    {
        var tracker = new TlsQuicAckTracker();
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 0, Crypto, Epoch);

        Assert.Equal(
            new byte[] { 0x02, 0x00, 0x40, 0x7c, 0x00, 0x00 },
            Encode(tracker, now: Epoch + TimeSpan.FromMicroseconds(992)));
    }

    // s19.3 prices the encoding: "at the cost of lower resolution". 1008
    // microseconds at exponent 5 is 31.5 units, and the field carries 31 - it
    // TRUNCATES. Rounding to nearest would emit 32 and report 1024 microseconds,
    // a delay longer than the one actually taken, which s13.2.5's "An endpoint
    // MUST NOT include delays that it does not control" rules out from the other
    // direction. 1008 is chosen because it is the exact half-unit, the only
    // input that separates truncation from round-half-up.
    [Fact]
    public void AckDelayTruncatesRatherThanRoundingToNearest()
    {
        var tracker = new TlsQuicAckTracker(ackDelayExponent: 5);
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 0, Crypto, Epoch);

        Assert.Equal(
            new byte[] { 0x02, 0x00, 0x1f, 0x00, 0x00 },
            Encode(tracker, now: Epoch + TimeSpan.FromMicroseconds(1008)));
    }

    // s13.2.5: "the time the packet with the largest packet number is received"
    // - the LARGEST, not the latest to arrive. Packet 9 arrives at Epoch, then
    // the reordered packet 4 arrives 500 microseconds later, and the ACK is
    // built at Epoch + 992. The delay is measured from packet 9's arrival, so
    // it is still 992 microseconds and encodes as 31 at exponent 5. A tracker
    // that stamped every arrival would measure 492 and emit 15.
    //
    //   Largest Acknowledged 9, ACK Delay 0x1f, ACK Range Count 1,
    //   First ACK Range 9 - 9 = 0, Gap 9 - 4 - 2 = 3, Length 4 - 4 = 0
    [Fact]
    public void AckDelayIsMeasuredFromTheLargestPacketNumberNotTheLatestArrival()
    {
        var tracker = new TlsQuicAckTracker(ackDelayExponent: 5);
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 9, Crypto, Epoch);
        tracker.OnPacketReceived(
            TlsQuicEncryptionLevel.Initial, 4, Crypto, Epoch + TimeSpan.FromMicroseconds(500));

        Assert.Equal(
            new byte[] { 0x02, 0x09, 0x1f, 0x01, 0x00, 0x03, 0x00 },
            Encode(tracker, now: Epoch + TimeSpan.FromMicroseconds(992)));
    }

    // A DUPLICATE of the current largest does not restart the delay clock
    // either. s13.2.5 measures "the delays intentionally introduced between the
    // time the packet with the largest packet number is received and the time an
    // acknowledgment is sent" - the delay this endpoint introduced is counted
    // from when it first held that packet, and a retransmission arriving later
    // adds no new measurement point. Restarting on it would UNDERSTATE the delay
    // we actually introduced, which is the direction that corrupts the peer's
    // RTT estimate rather than merely coarsening it.
    //
    // ADDED AFTER A MUTATION SURVIVED. The comparison is `>`, and its comment
    // said in so many words that a duplicate does not restart the clock, but
    // nothing tested it: weakening it to `>=` left the whole suite green. The
    // reordering test above only moves the clock DOWN in packet number, never
    // level with it.
    //
    // Packet 9 at Epoch, packet 9 again 500 microseconds later, ACK at Epoch +
    // 992. At exponent 5 the delay is 992 / 32 = 31 = 0x1f; measured from the
    // duplicate it would be 492 / 32 = 15 = 0x0f.
    [Fact]
    public void ADuplicateOfTheLargestPacketDoesNotRestartTheDelayClock()
    {
        var tracker = new TlsQuicAckTracker(ackDelayExponent: 5);
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 9, Crypto, Epoch);
        tracker.OnPacketReceived(
            TlsQuicEncryptionLevel.Initial, 9, Crypto, Epoch + TimeSpan.FromMicroseconds(500));

        Assert.Equal(
            new byte[] { 0x02, 0x09, 0x1f, 0x00, 0x00 },
            Encode(tracker, now: Epoch + TimeSpan.FromMicroseconds(992)));
    }

    // A clock that goes backwards across an adjustment would make `now -
    // receivedAt` negative, and TimeSpan.Ticks is signed while ACK Delay is not
    // - the cast would wrap to a delay of some thousands of years, which the
    // peer folds straight into its RTT estimate. Clamped to zero instead.
    [Fact]
    public void AnAckBuiltBeforeThePacketArrivedReportsZeroDelayRatherThanWrapping()
    {
        var tracker = new TlsQuicAckTracker(ackDelayExponent: 5);
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 0, Crypto, Epoch);

        Assert.Equal(
            new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00 },
            Encode(tracker, now: Epoch - TimeSpan.FromSeconds(1)));
    }

    // ---- s12.3's three spaces ----------------------------------------------

    // s12.3 gives Initial, Handshake and one application data space. Packet
    // number 3 in Initial and packet number 3 in Handshake are different
    // packets - s19.3: "Packets from different packet number spaces can be
    // identified using the same numeric value" - so acknowledging one must not
    // acknowledge the other, and building an ACK for one must not consume the
    // other's obligation.
    [Fact]
    public void EachPacketNumberSpaceTracksItsOwnRangesAndItsOwnObligation()
    {
        var tracker = new TlsQuicAckTracker();
        Receive(tracker, TlsQuicEncryptionLevel.Initial, 3);
        Receive(tracker, TlsQuicEncryptionLevel.Handshake, 7);

        Assert.Equal(
            new byte[] { 0x02, 0x03, 0x00, 0x00, 0x00 },
            Encode(tracker, TlsQuicEncryptionLevel.Initial));
        Assert.Equal(
            new byte[] { 0x02, 0x07, 0x00, 0x00, 0x00 },
            Encode(tracker, TlsQuicEncryptionLevel.Handshake));
    }

    // s13.2.6: "Packets that a client sends with 0-RTT packet protection MUST be
    // acknowledged by the server in packets protected by 1-RTT keys." The two
    // levels are ONE space, so a 0-RTT packet and a 1-RTT packet land in the same
    // range set - and the encryption-level enum lists them non-adjacently
    // (Initial, EarlyData, Handshake, Application), so a mapping taken from the
    // enum's ordinal would put EarlyData where Handshake belongs.
    //
    //   Received 0-RTT 4 and 1-RTT 5: one merged range (5,4).
    //   Largest Acknowledged 5, ACK Range Count 0, First ACK Range 5 - 4 = 1
    [Fact]
    public void ZeroRttAndOneRttShareTheOneApplicationDataSpace()
    {
        var tracker = new TlsQuicAckTracker();
        Receive(tracker, TlsQuicEncryptionLevel.EarlyData, 4);
        Receive(tracker, TlsQuicEncryptionLevel.Application, 5);

        Assert.Equal(
            new byte[] { 0x02, 0x05, 0x00, 0x00, 0x01 },
            Encode(tracker, TlsQuicEncryptionLevel.Application));

        // Forced, because the ACK just built CONSUMED the one obligation the two
        // packets created between them - which is itself the point: had these
        // been two spaces, a second obligation would still be outstanding here.
        Assert.Equal(
            new byte[] { 0x02, 0x05, 0x00, 0x00, 0x01 },
            Encode(tracker, TlsQuicEncryptionLevel.EarlyData, force: true));
    }

    // ---- s13.2.3's range limit ---------------------------------------------

    // s13.2.3: "A receiver limits the number of ACK Ranges (Section 19.3.1) it
    // remembers and sends in ACK frames" - the count is this endpoint's choice,
    // but WHICH end is dropped is not: "If it does not [fit within a single QUIC
    // packet], then older ranges (those with the smallest packet numbers) are
    // omitted", and "A receiver SHOULD include an ACK Range containing the
    // largest received packet number in every ACK frame."
    //
    // Received 1, 3, 5, 7 - four separate ranges, all one packet wide, with a
    // limit of 2. The two kept are the HIGHEST two, (7,7) and (5,5).
    //
    //   Largest Acknowledged 7, ACK Range Count 1, First ACK Range 7 - 7 = 0,
    //   Gap 7 - 5 - 2 = 0, Length 5 - 5 = 0
    //
    // Dropping from the wrong end would give Largest Acknowledged 3, which
    // s13.2.3 warns about by name: "including a lower value than what was
    // included in a previous ACK frame could cause ECN to be unnecessarily
    // disabled".
    [Fact]
    public void OverTheRangeLimitTheOldestRangesAreOmittedAndTheLargestIsKept()
    {
        var tracker = new TlsQuicAckTracker(maximumAckRanges: 2);
        Receive(tracker, TlsQuicEncryptionLevel.Initial, 1, 3, 5, 7);

        Assert.Equal(
            new byte[] { 0x02, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00 },
            Encode(tracker));
    }

    // s13.2.3: "A receiver MUST retain an ACK Range unless it can ensure that it
    // will not subsequently accept packets with numbers in that range.
    // Maintaining a minimum packet number that increases as ranges are discarded
    // is one way to achieve this with minimal state."
    //
    // After the prune above, the smallest number still retained is 5. Packet 1,
    // arriving again, is below that floor and must not come back into the range
    // set - if it did, the discarded range would be re-created and the sentence
    // above violated. The frame is unchanged from the previous test.
    //
    // The re-arriving packet also creates NO new obligation - it is dropped
    // whole, not half-recorded - so the second ACK has to be forced. That is
    // asserted first, because otherwise the forced build below would hide it.
    [Fact]
    public void APacketBelowTheFloorLeftByAPruneIsNotReadmitted()
    {
        var tracker = new TlsQuicAckTracker(maximumAckRanges: 2);
        Receive(tracker, TlsQuicEncryptionLevel.Initial, 1, 3, 5, 7);
        Assert.True(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));

        Receive(tracker, TlsQuicEncryptionLevel.Initial, 1);

        Assert.False(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));
        Assert.Equal(
            new byte[] { 0x02, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00 },
            Encode(tracker, now: Epoch, force: true));
    }

    // The floor is the SMALLEST number of the lowest retained range, not its
    // largest - s13.2.3 permits refusing only what was actually discarded, and
    // the lowest surviving range is retained in full.
    //
    // ADDED AFTER A MUTATION SURVIVED. Setting the floor from `ranges[^1].Largest`
    // instead of `.Smallest` left the whole suite green, because every other
    // range-limit test here prunes down to ONE-PACKET ranges, where the two
    // fields hold the same number. The bug needs a wide range at the bottom to
    // show at all - and then it refuses packets inside a range this endpoint is
    // still acknowledging, so a retransmission of one of them is dropped and
    // never acknowledged, and the peer retransmits it forever.
    //
    // Received 1, then 5, 6, 7, then 9 - three ranges, (9,9), (7,5) and (1,1),
    // with a limit of 2. The first build prunes (1,1) away and puts the floor at
    // 5. Packet 6 then arrives again: inside (7,5), so above the true floor and
    // below the mutant's floor of 7.
    //
    //   Largest Acknowledged 9
    //   ACK Range Count      2 - 1 = 1
    //   First ACK Range      9 - 9 = 0
    //   pair 1  Gap    9 - 7 - 2 = 0    previous_smallest is 9, and the operand
    //                                   beside it is the next range's LARGEST,
    //                                   7 - not its smallest. Only packet 8 is
    //                                   missing, and s19.3.1 encodes one missing
    //                                   packet as 0.
    //           Length 7 - 5 = 2        three packets, 7 6 5
    //
    // Decode check: largest 9, smallest = 9 - 0 = 9; largest = 9 - 0 - 2 = 7,
    // smallest = 7 - 2 = 5.
    [Fact]
    public void TheFloorIsTheSmallestOfTheLowestRetainedRangeNotItsLargest()
    {
        var tracker = new TlsQuicAckTracker(maximumAckRanges: 2);
        Receive(tracker, TlsQuicEncryptionLevel.Initial, 1, 5, 6, 7, 9);

        Assert.Equal(
            new byte[] { 0x02, 0x09, 0x00, 0x01, 0x00, 0x00, 0x02 },
            Encode(tracker));

        Receive(tracker, TlsQuicEncryptionLevel.Initial, 6);

        // Not forced: packet 6 was accepted, so it carries its own obligation.
        // Under the mutant it is refused, the obligation never exists, and this
        // build returns false before the bytes are ever compared.
        Assert.Equal(
            new byte[] { 0x02, 0x09, 0x00, 0x01, 0x00, 0x00, 0x02 },
            Encode(tracker));
    }

    // The floor is the smallest RETAINED number, and that number is still
    // acceptable - a `<=` where the code has `<` would refuse a duplicate of
    // packet 5 and, worse, refuse the packet that would extend the lowest kept
    // range downward. Receiving 5 again is a no-op, and the frame is unchanged.
    [Fact]
    public void ThePacketNumberAtTheFloorItselfIsStillAccepted()
    {
        var tracker = new TlsQuicAckTracker(maximumAckRanges: 2);
        Receive(tracker, TlsQuicEncryptionLevel.Initial, 1, 3, 5, 7);
        Assert.True(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));

        Receive(tracker, TlsQuicEncryptionLevel.Initial, 5);

        Assert.Equal(
            new byte[] { 0x02, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00 },
            Encode(tracker, now: Epoch));
    }

    // A range set exactly AT the limit is not over it, so nothing is dropped and
    // - the part that actually bites - s13.2.3's minimum packet number is not
    // raised. That floor is a one-way ratchet: "A receiver MUST retain an ACK
    // Range unless it can ensure that it will not subsequently accept packets
    // with numbers in that range." Raising it when nothing was discarded refuses
    // packets the receiver never stopped being willing to acknowledge.
    //
    // ADDED AFTER A MUTATION SURVIVED. Turning the prune guard's `<=` into `<`
    // left the whole suite green, because at Count == limit the RemoveRange it
    // then reaches is a no-op (it removes Count - limit == 0 entries) - so the
    // ONLY effect is the floor being set, and no test asked a question the floor
    // could answer at that exact count. Every other range-limit test above sits
    // strictly OVER the limit, where both readings prune identically.
    //
    // Limit 3, received 5, 3 and 1: three one-packet ranges, exactly at the
    // limit. Build an ACK (which is where Prune runs), then receive packet 0.
    // Packet 0 is below the floor the mutant just raised to 1 and is dropped -
    // taking its ack-eliciting obligation with it, so the second build does not
    // even happen. Correctly, 0 is accepted and merges with (1,1) into (1,0).
    //
    //   Largest Acknowledged 5
    //   ACK Range Count      3 - 1 = 2
    //   First ACK Range      5 - 5 = 0
    //   pair 1  Gap 5 - 3 - 2 = 0, Length 3 - 3 = 0
    //   pair 2  Gap 3 - 1 - 2 = 0, Length 1 - 0 = 1
    //
    // Decode check: largest 5, smallest 5 - 0 = 5; largest = 5 - 0 - 2 = 3,
    // smallest = 3 - 0 = 3; largest = 3 - 0 - 2 = 1, smallest = 1 - 1 = 0.
    [Fact]
    public void ARangeSetExactlyAtTheLimitIsNotPrunedAndRaisesNoFloor()
    {
        var tracker = new TlsQuicAckTracker(maximumAckRanges: 3);
        Receive(tracker, TlsQuicEncryptionLevel.Initial, 5, 3, 1);
        Assert.True(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));

        Receive(tracker, TlsQuicEncryptionLevel.Initial, 0);

        Assert.Equal(
            new byte[] { 0x02, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
            Encode(tracker));
    }

    // A limit of 1 is legal and means "the newest contiguous run only" - s19.3's
    // First ACK Range is mandatory, so one range is the floor and a tracker
    // permitted zero could only build frames WriteAckFrame rejects.
    [Fact]
    public void ARangeLimitOfOneKeepsOnlyTheNewestRun()
    {
        var tracker = new TlsQuicAckTracker(maximumAckRanges: 1);
        Receive(tracker, TlsQuicEncryptionLevel.Initial, 1, 3, 4);

        Assert.Equal(
            new byte[] { 0x02, 0x04, 0x00, 0x00, 0x01 },
            Encode(tracker));
    }

    [Fact]
    public void ARangeLimitBelowOneIsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicAckTracker(maximumAckRanges: 0));
    }

    // s13.2.3'S BOUND IS ON TWO VERBS AND THIS IS THE FIRST ONE: "A receiver
    // limits the number of ACK Ranges (Section 19.3.1) it REMEMBERS and sends in
    // ACK frames, both to limit the size of ACK frames and to avoid RESOURCE
    // EXHAUSTION."
    //
    // Every range-limit test above builds an ACK, and the prune used to run
    // inside that build - so all of them witnessed only the "sends" half. Nothing
    // asked what the tracker holds while no ACK is being built, which is the
    // state an attacker can hold it in indefinitely: TryBuildAck returns early
    // when nothing ack-eliciting is outstanding, so a stream of non-ack-eliciting
    // packets on scattered numbers never reached the prune at all.
    //
    // Limit 2, and packets 5, 3, 1 arrive with NO build in between. The prune now
    // runs on arrival, so packet 1 is recorded, immediately discarded as the
    // third range, and the floor goes to 3 - the smallest number still retained.
    // Packet 2 then arrives and is BELOW that floor, which is the only check in
    // OnPacketReceived that can refuse it: it is under s12.3's ceiling, it is not
    // contained in any range, and it is adjacent to (3,3) from below, so if the
    // floor does not stop it the merge does the opposite of stopping it.
    //
    //   Largest Acknowledged 5
    //   ACK Range Count      2 - 1 = 1
    //   First ACK Range      5 - 5 = 0
    //   pair 1  Gap    5 - 3 - 2 = 0     only packet 4 missing
    //           Length 3 - 3 = 0
    //
    // With the prune back at build time, packet 1 is still held when packet 2
    // arrives: 2 extends (3,3) down and then coalesces with (1,1), giving (5,5)
    // and (3,1), and the frame's last byte is 2 rather than 0. So this is the
    // witness for WHERE the bound is enforced, not merely that it exists -
    // OverTheRangeLimitTheOldestRangesAreOmittedAndTheLargestIsKept already dies
    // if nothing prunes anywhere.
    [Fact]
    public void TheRangeLimitIsAppliedOnArrivalNotOnlyWhenAnAckIsBuilt()
    {
        var tracker = new TlsQuicAckTracker(maximumAckRanges: 2);
        Receive(tracker, TlsQuicEncryptionLevel.Initial, 5, 3, 1, 2);

        Assert.Equal(
            new byte[] { 0x02, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00 },
            Encode(tracker));
    }

    // The same bound, reached down the path that had no bound at all: packets
    // that are NOT ack-eliciting. s13.2 keeps them out of the build - "Packets
    // that are not ack-eliciting are only acknowledged when an ACK frame is sent
    // for other reasons" - so every TryBuildAck below the forced one returns
    // false, and while the prune lived inside TryBuildAck that meant the range
    // list grew with nothing ever trimming it. PADDING is the cheapest frame
    // there is and Initial keys are derivable from an observed Destination
    // Connection ID, so this is an off-path injector's shape, not a peer's.
    //
    // Four PADDING-only packets on scattered numbers at a limit of 2, no ACK
    // built until the forced one at the end. The two highest ranges survive.
    [Fact]
    public void NonAckElicitingPacketsAreStillBoundedByTheRangeLimit()
    {
        var tracker = new TlsQuicAckTracker(maximumAckRanges: 2);
        foreach (var packetNumber in (ulong[])[1, 3, 5, 7])
        {
            tracker.OnPacketReceived(
                TlsQuicEncryptionLevel.Initial, packetNumber, PaddingOnly, Epoch);
            Assert.False(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));
        }

        Assert.Equal(
            new byte[] { 0x02, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00 },
            Encode(tracker, force: true));
    }

    // ---- s12.3's packet number ceiling -------------------------------------

    // s12.3: "The packet number is an integer in the range 0 to 2^62-1. [...]
    // Packet numbers are limited to this range because they need to be
    // representable in whole in the Largest Acknowledged field of an ACK frame
    // (Section 19.3)."
    //
    // DROPPED, NOT THROWN, and this test used to assert the throw and to call the
    // input REACHABLE. Both were changed together, because they have to agree.
    // The reachability claim rested on TlsQuicPacketNumber.Decode having no 2^62
    // ceiling on its plain return path, which is true - but Decode reconstructs
    // around the largest packet number received so far, so a value this large
    // needs a largest-received already up near 2^62 and no sequence of packets a
    // peer can send walks it there. It is effectively unreachable.
    //
    // "Effectively" is why the check stays. That it now RETURNS is why the label
    // mattered: OnPacketReceived is the receive path, a peer picks this number,
    // and a genuinely reachable throw here is a one-datagram remote kill of task
    // 9a-ii's loop. The two answers - a throw for a reachable input, a drop for
    // an unreachable one - are not interchangeable, and the code, the doc and
    // this test had drifted onto different ones.
    //
    // Asserted as "nothing was recorded and nothing is owed", which only the
    // ceiling check can produce: 2^62 is above every floor Prune can raise, so
    // the below-floor return cannot be what refuses it.
    [Fact]
    public void APacketNumberAboveTheSection123CeilingIsDroppedRatherThanThrowing()
    {
        var tracker = new TlsQuicAckTracker();

        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 1UL << 62, Crypto, Epoch);

        Assert.False(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));
        Assert.False(tracker.TryBuildAck(
            TlsQuicEncryptionLevel.Initial, Epoch, force: true, out _, out _));
    }

    // The ceiling itself is a legal packet number, so the bound is exclusive
    // above and not off by one.
    [Fact]
    public void ThePacketNumberCeilingItselfIsAccepted()
    {
        var tracker = new TlsQuicAckTracker();
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, (1UL << 62) - 1, Crypto, Epoch);

        Assert.True(tracker.TryBuildAck(TlsQuicEncryptionLevel.Initial, Epoch, out _, out _));
    }

    // s18.2, ack_delay_exponent: "Values above 20 are invalid." Twenty is not.
    //
    // SPLIT ACROSS TWO TESTS, ONE PER CHECK. These were one method until a
    // mutation sweep showed both the upper bound and the negative guard failing
    // under the same name - which is true but useless, because the name then
    // says nothing about which of the two broke. Each input below can only be
    // rejected by one of them.
    [Fact]
    public void AnAckDelayExponentAboveTwentyIsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicAckTracker(ackDelayExponent: 21));
    }

    [Fact]
    public void ANegativeAckDelayExponentIsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicAckTracker(ackDelayExponent: -1));
    }

    // Twenty is the largest legal value, so the bound is exclusive above and not
    // off by one. A shift by 20 is also the widest s18.2 permits, which this
    // exercises end to end rather than only at construction: 2^20 microseconds
    // of delay encodes as exactly 1.
    [Fact]
    public void TheAckDelayExponentOfTwentyIsAcceptedAndScalesByTwoToTheTwenty()
    {
        var tracker = new TlsQuicAckTracker(ackDelayExponent: 20);
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Initial, 0, Crypto, Epoch);

        Assert.Equal(
            new byte[] { 0x02, 0x00, 0x01, 0x00, 0x00 },
            Encode(tracker, now: Epoch + TimeSpan.FromMicroseconds(1 << 20)));
    }

    // ---- Duplicates --------------------------------------------------------

    // s19.3: "QUIC acknowledgments are irrevocable. Once acknowledged, a packet
    // remains acknowledged." A duplicate is neither an error nor a new range -
    // it changes nothing. Received 5, 4, 5: still the one range (5,4).
    [Fact]
    public void ADuplicatePacketNumberChangesNothing()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x05, 0x00, 0x00, 0x01 },
            Encode(Receive(5, 4, 5)));
    }

    // A duplicate landing in the interior of a wide range takes a different
    // branch from one landing on its edge - the containment test rather than
    // either adjacency test. Received 9..5 then 7.
    //
    //   Largest Acknowledged 9, ACK Range Count 0, First ACK Range 9 - 5 = 4
    [Fact]
    public void ADuplicateInsideAWideRangeChangesNothing()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x09, 0x00, 0x00, 0x04 },
            Encode(Receive(9, 8, 7, 6, 5, 7)));
    }

    // A duplicate landing exactly on the SMALLEST end of a wide range - the
    // containment test's lower bound, which the two duplicates above both miss.
    // Received 9..5, so the range is (9,5), then packet 5 again.
    //
    // ADDED AFTER A MUTATION SURVIVED. Weakening that bound from `>=
    // range.Smallest` to `> range.Smallest` left the whole suite green: the
    // duplicate above lands at Largest and the one before it lands strictly
    // inside, so nothing asked about the low edge. Under the mutant packet 5 is
    // not recognised as already held, falls past every adjacency test, and is
    // appended at the TAIL - leaving (9,5) followed by (5,5), which overlap.
    // s19.3.1 has no encoding for overlapping ranges and
    // TlsQuicAckFrames.ValidateRanges throws, so the symptom is an exception
    // while building an ACK after an ordinary retransmission.
    //
    //   Largest Acknowledged 9, ACK Range Count 0, First ACK Range 9 - 5 = 4
    [Fact]
    public void ADuplicateOfTheSmallestPacketInAWideRangeChangesNothing()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x09, 0x00, 0x00, 0x04 },
            Encode(Receive(9, 8, 7, 6, 5, 5)));
    }

    // ---- ProcessAckFrame ---------------------------------------------------

    // Builds a real ACK frame the way a peer would and reads it back, so
    // ProcessAckFrame sees exactly what TlsQuicFrames.TryReadFrame produces.
    private static TlsQuicFrame AckFrame(params TlsQuicAckRange[] ranges)
    {
        List<byte> encoded = [];
        TlsQuicAckFrames.WriteAckFrame(encoded, (ulong)TlsQuicFrameType.Ack, 0, ranges);
        var offset = 0;
        ReadOnlyMemory<byte> wire = encoded.ToArray();
        Assert.True(TlsQuicFrames.TryReadFrame(wire, ref offset, out var frame, out _));
        return frame;
    }

    // Task 4b's input. s17.1 makes largest-acked the figure that decides how few
    // bytes a truncated packet number can use.
    [Fact]
    public void ProcessAckFrameAdvancesLargestAcked()
    {
        var tracker = new TlsQuicAckTracker();

        Assert.True(tracker.ProcessAckFrame(
            TlsQuicEncryptionLevel.Initial, AckFrame(new TlsQuicAckRange(9, 7)), Epoch, out _));

        Assert.Equal(9UL, tracker.LargestAcked(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(Epoch, tracker.LargestAckedAt(TlsQuicEncryptionLevel.Initial));
    }

    // NULL IS NOT ZERO. Packet number 0 is acknowledgeable, so "no ACK has
    // arrived" and "an ACK acknowledged packet 0" are different states and a
    // ulong defaulting to 0 could not tell them apart. Task 4b reads this to
    // choose an encoded length, and reading absent as zero would have it size
    // the very first packet number against a peer that has acknowledged
    // nothing.
    [Fact]
    public void LargestAckedIsNullBeforeAnyAckAndZeroAfterAnAckForPacketZero()
    {
        var tracker = new TlsQuicAckTracker();
        Assert.Null(tracker.LargestAcked(TlsQuicEncryptionLevel.Initial));

        Assert.True(tracker.ProcessAckFrame(
            TlsQuicEncryptionLevel.Initial, AckFrame(new TlsQuicAckRange(0, 0)), Epoch, out _));

        Assert.Equal(0UL, tracker.LargestAcked(TlsQuicEncryptionLevel.Initial));
    }

    // s19.3's irrevocability again, from the read side: a reordered ACK naming a
    // lower Largest Acknowledged is not new information. Lowering it would be
    // actively harmful - task 4b's encoded length SHRINKS as largest-acked
    // grows, so a value that fell back would size a packet number in too few
    // bytes for the peer to reconstruct.
    [Fact]
    public void AReorderedAckNamingALowerLargestDoesNotLowerLargestAcked()
    {
        var tracker = new TlsQuicAckTracker();
        Assert.True(tracker.ProcessAckFrame(
            TlsQuicEncryptionLevel.Initial, AckFrame(new TlsQuicAckRange(9, 9)), Epoch, out _));

        Assert.True(tracker.ProcessAckFrame(
            TlsQuicEncryptionLevel.Initial,
            AckFrame(new TlsQuicAckRange(4, 4)),
            Epoch + TimeSpan.FromSeconds(1),
            out _));

        Assert.Equal(9UL, tracker.LargestAcked(TlsQuicEncryptionLevel.Initial));

        // The timestamp did not move either - A3's RTT sample must belong to the
        // ACK that actually advanced the figure.
        Assert.Equal(Epoch, tracker.LargestAckedAt(TlsQuicEncryptionLevel.Initial));
    }

    // A REPEATED ACK naming the SAME Largest Acknowledged is not new information
    // either, and the thing it must not move is the timestamp. s19.3: "QUIC
    // acknowledgments are irrevocable. Once acknowledged, a packet remains
    // acknowledged, even if it does not appear in a future ACK frame" - so a
    // peer bundling the same Largest Acknowledged into every packet it sends,
    // which s13.2 actively encourages ("When sending a packet for any reason, an
    // endpoint SHOULD attempt to include an ACK frame if one has not been sent
    // recently"), says nothing new each time.
    //
    // ADDED AFTER A MUTATION SURVIVED. Weakening the comparison to `>=` leaves
    // LargestAcked itself unchanged - it reassigns the same number - so the only
    // casualty is LargestAckedAt, which starts tracking the LATEST repeat rather
    // than the ACK that actually advanced the figure. A3 subtracts that
    // timestamp from the acknowledged packet's send time, so the sample would
    // grow by the whole interval between repeats and the RTT estimate would
    // climb for as long as the peer keeps repeating itself. The reordering test
    // above only goes strictly DOWN in Largest Acknowledged and never level.
    [Fact]
    public void ARepeatedAckAtTheSameLargestDoesNotMoveTheRttTimestamp()
    {
        var tracker = new TlsQuicAckTracker();
        Assert.True(tracker.ProcessAckFrame(
            TlsQuicEncryptionLevel.Initial, AckFrame(new TlsQuicAckRange(9, 9)), Epoch, out _));

        Assert.True(tracker.ProcessAckFrame(
            TlsQuicEncryptionLevel.Initial,
            AckFrame(new TlsQuicAckRange(9, 9)),
            Epoch + TimeSpan.FromSeconds(1),
            out _));

        Assert.Equal(9UL, tracker.LargestAcked(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(Epoch, tracker.LargestAckedAt(TlsQuicEncryptionLevel.Initial));
    }

    // s13.2.6: "ACK frames MUST only be carried in a packet that has the same
    // packet number space as the packet being acknowledged." A Handshake ACK
    // says nothing about Initial packet numbers. The task text's proposed
    // signature had no space parameter, which would have merged these two into
    // one counter and let a Handshake ACK raise the figure task 4b uses to
    // encode Initial packet numbers.
    [Fact]
    public void LargestAckedIsPerPacketNumberSpace()
    {
        var tracker = new TlsQuicAckTracker();
        Assert.True(tracker.ProcessAckFrame(
            TlsQuicEncryptionLevel.Handshake, AckFrame(new TlsQuicAckRange(40, 40)), Epoch, out _));

        Assert.Null(tracker.LargestAcked(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(40UL, tracker.LargestAcked(TlsQuicEncryptionLevel.Handshake));
    }

    // s19.3.1: "If any computed packet number is negative, an endpoint MUST
    // generate a connection error of type FRAME_ENCODING_ERROR." The chain is
    // validated through TlsQuicAckFrames.TryGetRanges rather than re-walked
    // here, and a rejection must leave largest-acked untouched - otherwise a
    // malformed frame sets the figure task 4b encodes against.
    //
    // The frame below claims Largest Acknowledged 3 with a First ACK Range of 5,
    // so the smallest is 3 - 5, which is negative.
    [Fact]
    public void AMalformedRangeChainIsRejectedAndLeavesLargestAckedUntouched()
    {
        var tracker = new TlsQuicAckTracker();
        var frame = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Ack,
            LargestAcknowledged = 3,
            AckDelay = 0,
            AckRangeCount = 0,
            FirstAckRange = 5,
            AckRanges = ReadOnlyMemory<byte>.Empty,
        };

        Assert.False(tracker.ProcessAckFrame(
            TlsQuicEncryptionLevel.Initial, frame, Epoch, out var error));

        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Null(tracker.LargestAcked(TlsQuicEncryptionLevel.Initial));
    }

    // A frame that is not an ACK at all has no ranges - the guard
    // TlsQuicAckFrames.TryGetRanges already owns, reached through this method's
    // own path.
    [Fact]
    public void ProcessAckFrameOnANonAckFrameIsRejected()
    {
        var tracker = new TlsQuicAckTracker();

        Assert.False(tracker.ProcessAckFrame(
            TlsQuicEncryptionLevel.Initial,
            new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping },
            Epoch,
            out _));

        Assert.Null(tracker.LargestAcked(TlsQuicEncryptionLevel.Initial));
    }

    // ---- RFC 9002 s5, RTT estimation (task A3-4) ----------------------------
    //
    // NOTHING BELOW COMPARES AGAINST A TABLE OF EXPECTED NUMBERS, and that is not a
    // stylistic preference. RFC 9002 s5 publishes no test vectors - its worked
    // behaviour is prose and pseudocode - so a table would be a table of numbers
    // this file computed once and then froze, which proves that the code has not
    // changed rather than that it is right. Every expectation below is either
    // recomputed from s5.3's formulas in exact decimal arithmetic (see
    // SmoothedFrom and VariationFrom, which deliberately do NOT share the
    // implementation's increment form) or derived by hand with the arithmetic
    // written above the test.
    //
    // THE INPUTS STRADDLE RATHER THAN SIT INSIDE. Three tasks in a row here lost
    // mutants to inputs that could not tell two readings apart, so each test below
    // names the two answers its input separates and asserts against both: the
    // initial RTT is an order of magnitude from the first sample so the
    // initialising and smoothing branches cannot round into each other; the peer's
    // ack_delay_exponent differs from ours by four bits; the ack_delay that must be
    // refused exceeds the whole distance between latest_rtt and min_rtt; and the
    // two orderings of s5.3's last two lines are asserted to be 137.5 ms and
    // 125 ms rather than merely "not equal".

    // Handshake, not Initial, for every test that involves an acknowledgement
    // delay: s5.3's first bullet lets an endpoint ignore the delay for Initial
    // packets and DecodeAckDelay takes that MAY, so an Initial-level delay test
    // would exercise the branch that discards its own input.
    // AnInitialPacketsAcknowledgementDelayIsIgnored is the test of that branch.
    private const TlsQuicEncryptionLevel RttLevel = TlsQuicEncryptionLevel.Handshake;

    // The same real-peer round trip AckFrame builds, with the ACK Delay field set.
    private static TlsQuicFrame AckFrame(ulong ackDelay, params TlsQuicAckRange[] ranges)
    {
        List<byte> encoded = [];
        TlsQuicAckFrames.WriteAckFrame(encoded, (ulong)TlsQuicFrameType.Ack, ackDelay, ranges);
        var offset = 0;
        ReadOnlyMemory<byte> wire = encoded.ToArray();
        Assert.True(TlsQuicFrames.TryReadFrame(wire, ref offset, out var frame, out _));
        return frame;
    }

    private static TlsQuicSentPacket Sent(
        ulong packetNumber, DateTimeOffset sentAt, bool ackEliciting = true) =>
        new(RttLevel, packetNumber, 1200, ackEliciting, true, sentAt);

    // s19.3's ACK Delay is in microseconds and is encoded by dividing by
    // 2^ack_delay_exponent, so a test that wants the peer to REPORT a given delay
    // has to encode it the way the peer would. Written as a helper rather than as
    // a constant per test because the exponent varies between these tests, which is
    // the whole point of two of them.
    private static ulong EncodeAckDelay(TimeSpan delay, int exponent) =>
        (ulong)(delay.Ticks / 10) >> exponent;

    // s5.3's two averages in exact decimal arithmetic, from the RFC's own weighted
    // form. NOT the increment form the implementation uses - it works in whole
    // ticks and writes `s + (a - s)/8` for the overflow reason UpdateRtt's
    // DEPARTURE 2 gives - so these are an independent derivation that can differ
    // from the implementation by the one tick integer truncation costs, which is
    // what AssertWithinOneTick allows and no more.
    private static decimal SmoothedFrom(TimeSpan smoothed, TimeSpan adjusted) =>
        ((7m * smoothed.Ticks) + adjusted.Ticks) / 8m;

    private static decimal VariationFrom(
        TimeSpan variation, TimeSpan smoothedBefore, TimeSpan adjusted) =>
        ((3m * variation.Ticks) + Math.Abs(smoothedBefore.Ticks - adjusted.Ticks)) / 4m;

    private static void AssertWithinOneTick(decimal expectedTicks, TimeSpan actual) =>
        Assert.True(
            Math.Abs(expectedTicks - actual.Ticks) <= 1m,
            $"expected {expectedTicks} ticks, got {actual.Ticks}");

    // One round trip: a packet sent at sentAt, acknowledged rtt later, with the
    // peer reporting encodedAckDelay in the frame's ACK Delay field.
    //
    // EVERY CALL MUST USE A HIGHER packetNumber THAN THE LAST, because s5.1's first
    // condition is that the largest acknowledged is newly acknowledged - a repeat
    // is exactly what ADuplicatedAcknowledgementProducesNoSecondRttSample tests and
    // would silently turn any other test into a no-op.
    private static void Sample(
        TlsQuicAckTracker tracker,
        ulong packetNumber,
        TimeSpan rtt,
        ulong encodedAckDelay = 0,
        bool ackEliciting = true,
        TlsQuicEncryptionLevel? level = null,
        DateTimeOffset? sentAt = null)
    {
        var sent = sentAt ?? Epoch;
        Assert.True(tracker.ProcessAckFrame(
            level ?? RttLevel,
            AckFrame(encodedAckDelay, new TlsQuicAckRange(packetNumber, packetNumber)),
            sent + rtt,
            [Sent(packetNumber, sent, ackEliciting)],
            out _));
    }

    // A.4: "smoothed_rtt = kInitialRtt", "rttvar = kInitialRtt / 2", and min_rtt
    // and latest_rtt at zero.
    //
    // WHICH kInitialRtt, ASSERTED RATHER THAN ASSUMED. There are two initial-RTT
    // numbers in this codebase and they disagree: TlsQuicRecoverySpec.KInitialRtt
    // is 333 ms, and TlsQuicTransportParameterSpec.Brave151InitialRttRange - the
    // fallback of the transport-parameter entry that ADVERTISES an initial RTT to
    // the peer - tops out at 300 ms. The tracker's default reads the recovery side,
    // and this pins that, so a later edit that quietly switches the source fails
    // here instead of shipping. Resolving the disagreement is task A3-7's; this
    // test only refuses to let it be resolved by accident.
    [Fact]
    public void BeforeAnySampleTheEstimatorHoldsAppendixA4sInitialisation()
    {
        var tracker = new TlsQuicAckTracker();

        Assert.Equal(TlsQuicRecoverySpec.KInitialRtt, tracker.SmoothedRtt);
        Assert.Equal(
            new TimeSpan(TlsQuicRecoverySpec.KInitialRtt.Ticks / 2), tracker.RttVariation);
        Assert.Equal(TimeSpan.Zero, tracker.MinimumRtt);
        Assert.Equal(TimeSpan.Zero, tracker.LatestRtt);
        Assert.Null(tracker.FirstRttSampleAt);

        // The divergence itself, named so the two numbers are visible together.
        Assert.True(
            TlsQuicRecoverySpec.KInitialRtt
                > TlsQuicTransportParameterSpec.Brave151InitialRttRange.Maximum);
    }

    // A.7's first branch: "if (first_rtt_sample == 0): min_rtt = latest_rtt;
    // smoothed_rtt = latest_rtt; rttvar = latest_rtt / 2". s5.3: "On the first RTT
    // sample after initialization, the estimator is reset using that sample. This
    // ensures that the estimator retains no history of past samples."
    //
    // THE STRADDLE: the seed is 1000 ms and the sample is 100 ms. A.7's branch
    // gives exactly 100 ms; the smoothing branch would give
    // 1000 + (100 - 1000)/8 = 887.5 ms, and rttvar 500 + (|1000-100| - 500)/4 =
    // 600 ms. A seed near the sample would put those two answers within rounding of
    // each other and witness nothing at all.
    [Fact]
    public void TheFirstSampleInitialisesTheEstimatorRatherThanSmoothingTheSeed()
    {
        var tracker = new TlsQuicAckTracker(initialRtt: TimeSpan.FromMilliseconds(1000));

        Sample(tracker, 0, TimeSpan.FromMilliseconds(100));

        Assert.Equal(TimeSpan.FromMilliseconds(100), tracker.LatestRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(100), tracker.MinimumRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(100), tracker.SmoothedRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(50), tracker.RttVariation);
        Assert.Equal(Epoch + TimeSpan.FromMilliseconds(100), tracker.FirstRttSampleAt);

        // The two values the smoothing branch would have produced, stated so the
        // assertions above are readable as a choice between two numbers.
        Assert.NotEqual(TimeSpan.FromMilliseconds(887.5), tracker.SmoothedRtt);
        Assert.NotEqual(TimeSpan.FromMilliseconds(600), tracker.RttVariation);
    }

    // A.7's second branch, recomputed rather than tabulated. No ACK Delay, so
    // adjusted_rtt == latest_rtt and this isolates the two averages.
    [Fact]
    public void ASubsequentSampleSmoothsUsingSection53sFormulas()
    {
        var tracker = new TlsQuicAckTracker();
        Sample(tracker, 0, TimeSpan.FromMilliseconds(100));

        var smoothedBefore = tracker.SmoothedRtt;
        var variationBefore = tracker.RttVariation;
        var second = TimeSpan.FromMilliseconds(180);

        Sample(tracker, 1, second);

        AssertWithinOneTick(
            VariationFrom(variationBefore, smoothedBefore, second), tracker.RttVariation);
        AssertWithinOneTick(SmoothedFrom(smoothedBefore, second), tracker.SmoothedRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(180), tracker.LatestRtt);

        // s5.2: min_rtt "will not adapt" upward. 180 is above 100, so it stays.
        Assert.Equal(TimeSpan.FromMilliseconds(100), tracker.MinimumRtt);
    }

    // THE ONE PLACE RFC 9002 CONTRADICTS ITSELF, and the test that makes the choice
    // visible. s5.3's prose updates smoothed_rtt first and then measures the
    // variation against the UPDATED value; A.7's pseudocode measures the variation
    // first, against the smoothed_rtt from before this sample. See UpdateRtt's
    // DEPARTURE 4 for why A.7 wins.
    //
    // The arithmetic, with min_rtt 100 ms, smoothed_rtt 100 ms, rttvar 50 ms and a
    // second sample of 500 ms:
    //   A.7:   rttvar = 3/4 * 50 + 1/4 * |100 - 500| = 37.5 + 100   = 137.5 ms
    //   s5.3:  smoothed_rtt = (7 * 100 + 500)/8 = 150 ms, so the variation sample
    //          is |150 - 500| = 350 - exactly 7/8 of 400 - and
    //          rttvar = 37.5 + 87.5 = 125 ms
    // The 7/8 is not a rounding artefact but the identity
    // |(7s + a)/8 - a| = 7/8 * |s - a|, which is why s5.3's prose order
    // underestimates rttvar by 12.5% forever rather than transiently.
    [Fact]
    public void RttVariationIsMeasuredAgainstTheSmoothedRttFromBeforeThisSample()
    {
        var tracker = new TlsQuicAckTracker();
        Sample(tracker, 0, TimeSpan.FromMilliseconds(100));

        var variationBefore = tracker.RttVariation;
        var smoothedBefore = tracker.SmoothedRtt;
        var second = TimeSpan.FromMilliseconds(500);

        Sample(tracker, 1, second);

        var appendixA7 = VariationFrom(variationBefore, smoothedBefore, second);
        var section53Prose = VariationFrom(
            variationBefore, TimeSpan.FromMilliseconds(150), second);

        Assert.Equal(137.5m * TimeSpan.TicksPerMillisecond, appendixA7);
        Assert.Equal(125m * TimeSpan.TicksPerMillisecond, section53Prose);

        AssertWithinOneTick(appendixA7, tracker.RttVariation);
        Assert.NotEqual(section53Prose, tracker.RttVariation.Ticks);

        // smoothed_rtt itself is the same under both orderings, which is why only
        // rttvar can witness the difference.
        AssertWithinOneTick(SmoothedFrom(smoothedBefore, second), tracker.SmoothedRtt);
    }

    // s19.3: the ACK Delay field "is decoded by multiplying the value in the field
    // by 2 to the power of the ack_delay_exponent transport parameter sent by the
    // SENDER OF THE ACK FRAME" - the peer, for a frame we received. This class
    // scales the ACKs it SENDS by its own exponent, and the two are deliberately
    // not the same field; the class header's second numbered note says a mismatch
    // "is silent in both directions: both values are legal, every frame still
    // parses", which is exactly why no other test in this file can see it.
    //
    // Ours 3, theirs 7, so one encoded field means two delays 2^4 = 16 apart:
    //   min_rtt 200 ms from the first sample; second sample latest_rtt 400 ms.
    //   encoded = 128 ms / 2^7 microseconds, so theirs decodes 128 ms and ours 8 ms.
    //   400 - 200 = 200 >= 128, so adjusted_rtt = 272 ms and
    //     smoothed_rtt = (7 * 200 + 272)/8 = 209 ms.
    //   Using OUR exponent would give adjusted_rtt 392 ms and
    //     smoothed_rtt = (7 * 200 + 392)/8 = 224 ms.
    //
    // The handshake is deliberately NOT confirmed, because max_ack_delay's 25 ms
    // default would cap both readings to the same number and hide the whole point.
    [Fact]
    public void TheAcknowledgementDelayIsDecodedWithThePeersExponentAndNotOurs()
    {
        var tracker = new TlsQuicAckTracker(ackDelayExponent: 3);
        tracker.OnPeerAckParameters(7, TlsQuicAckTracker.DefaultMaxAckDelay);

        Sample(tracker, 0, TimeSpan.FromMilliseconds(200));
        Sample(
            tracker,
            1,
            TimeSpan.FromMilliseconds(400),
            EncodeAckDelay(TimeSpan.FromMilliseconds(128), 7));

        Assert.Equal(TimeSpan.FromMilliseconds(209), tracker.SmoothedRtt);
        Assert.NotEqual(TimeSpan.FromMilliseconds(224), tracker.SmoothedRtt);
    }

    // s5.3's last bullet: "MUST NOT subtract the acknowledgment delay from the RTT
    // sample if the resulting value is smaller than the min_rtt. This limits the
    // underestimation of the smoothed_rtt due to a misreporting peer."
    //
    // Driven by a peer reporting an implausibly large delay, which is the case the
    // sentence exists for. min_rtt 200 ms, latest_rtt 210 ms, reported delay
    // 1000 ms: 210 - 200 = 10 ms is far below 1000 ms, so nothing is subtracted and
    // smoothed_rtt = (7 * 200 + 210)/8 = 201.25 ms. Without the guard the adjusted
    // sample would be 210 - 1000 = -790 ms and smoothed_rtt would be
    // (1400 - 790)/8 = 76.25 ms - below min_rtt, which is the state the guard names.
    [Fact]
    public void AnAcknowledgementDelayIsNotSubtractedWhenTheResultWouldFallBelowMinRtt()
    {
        var tracker = new TlsQuicAckTracker();

        Sample(tracker, 0, TimeSpan.FromMilliseconds(200));
        Sample(
            tracker,
            1,
            TimeSpan.FromMilliseconds(210),
            EncodeAckDelay(TimeSpan.FromMilliseconds(1000), 3));

        Assert.Equal(TimeSpan.FromMilliseconds(201.25), tracker.SmoothedRtt);
        Assert.NotEqual(TimeSpan.FromMilliseconds(76.25), tracker.SmoothedRtt);
        Assert.True(tracker.SmoothedRtt >= tracker.MinimumRtt);
    }

    // THE BOUNDARY OF THE SAME GUARD, which the test above cannot reach and which
    // no published example straddles. s5.3 forbids subtracting only when the result
    // is "SMALLER THAN the min_rtt" - equal is not smaller - and A.7 spells the
    // comparison `if (latest_rtt >= min_rtt + ack_delay)`. So an ack_delay landing
    // exactly on min_rtt IS subtracted, and `>=` versus `>` is a real difference on
    // exactly this one input.
    //
    // min_rtt 200 ms, latest_rtt 500 ms, reported delay exactly 300 ms:
    //   >=  subtracts, adjusted_rtt = 200 ms = min_rtt,
    //       smoothed_rtt = (7 * 200 + 200)/8 = 200 ms
    //   >   refuses,   adjusted_rtt = 500 ms,
    //       smoothed_rtt = (7 * 200 + 500)/8 = 237.5 ms
    [Fact]
    public void AnAcknowledgementDelayThatLandsExactlyOnMinRttIsStillSubtracted()
    {
        var tracker = new TlsQuicAckTracker();

        Sample(tracker, 0, TimeSpan.FromMilliseconds(200));
        Sample(
            tracker,
            1,
            TimeSpan.FromMilliseconds(500),
            EncodeAckDelay(TimeSpan.FromMilliseconds(300), 3));

        Assert.Equal(TimeSpan.FromMilliseconds(200), tracker.SmoothedRtt);
        Assert.NotEqual(TimeSpan.FromMilliseconds(237.5), tracker.SmoothedRtt);
    }

    // s5.1's "at least one of the NEWLY ACKNOWLEDGED packets was ack-eliciting" -
    // newly acknowledged BY THIS FRAME, not merely still retained. A retained
    // packet the ACK does not name contributes nothing, and this is the input that
    // separates a real range test from an implementation that answers "is anything
    // in the sent list ack-eliciting", which almost always says yes.
    //
    // Packet 7 is the largest acknowledged and is an ACK-only packet; packet 1 is
    // ack-eliciting, still retained, and outside the frame's single range. The
    // correct answer is no sample.
    [Fact]
    public void ARetainedPacketOutsideTheAcknowledgedRangesDoesNotMakeTheSampleEligible()
    {
        var tracker = new TlsQuicAckTracker();
        TlsQuicSentPacket[] sentPackets = [Sent(1, Epoch), Sent(7, Epoch, ackEliciting: false)];

        Assert.True(tracker.ProcessAckFrame(
            RttLevel,
            AckFrame(0, new TlsQuicAckRange(7, 7)),
            Epoch + TimeSpan.FromMilliseconds(120),
            sentPackets,
            out _));

        Assert.Equal(7ul, tracker.LargestAcked(RttLevel));
        Assert.Null(tracker.FirstRttSampleAt);
        Assert.Equal(TlsQuicRecoverySpec.KInitialRtt, tracker.SmoothedRtt);
    }

    // The sent-packet list is documented as not required to be sorted, and this is
    // what makes that claim load-bearing rather than a hopeful sentence. Handed in
    // reverse of send order, the walk meets the ack-eliciting packet BEFORE it meets
    // the largest acknowledged - so an implementation that assigns the
    // ack-eliciting flag instead of accumulating it discards the answer it already
    // had and reports no sample. In send order the two mutations are
    // indistinguishable, which is why every other test here would pass against it.
    //
    // Packet 9 is the largest and ACK-only, sent 10 ms after packet 8, which is
    // ack-eliciting. The frame arrives 130 ms after Epoch, so the sample is
    // 120 ms measured from packet 9.
    [Fact]
    public void AnUnsortedSentPacketListStillAnswersBothOfSection51sQuestions()
    {
        var tracker = new TlsQuicAckTracker();
        TlsQuicSentPacket[] reversed =
        [
            Sent(9, Epoch + TimeSpan.FromMilliseconds(10), ackEliciting: false),
            Sent(8, Epoch),
        ];

        Assert.True(tracker.ProcessAckFrame(
            RttLevel,
            AckFrame(0, new TlsQuicAckRange(9, 8)),
            Epoch + TimeSpan.FromMilliseconds(130),
            reversed,
            out _));

        Assert.Equal(TimeSpan.FromMilliseconds(120), tracker.LatestRtt);
        Assert.NotNull(tracker.FirstRttSampleAt);
    }

    // s5.3, and the word is CONDITIONS rather than a rule: "SHOULD ignore the
    // peer's max_ack_delay until the handshake is confirmed" and "MUST use the
    // lesser of the acknowledgment delay and the peer's max_ack_delay AFTER the
    // handshake is confirmed". Applying the cap unconditionally is the mutation
    // this test exists for, and it is invisible without a confirmed/unconfirmed
    // pair because either arm alone looks self-consistent.
    //
    // Identical input to both trackers: min_rtt 200 ms, latest_rtt 400 ms, reported
    // delay 100 ms, peer max_ack_delay at s18.2's 25 ms default.
    //   unconfirmed: delay 100 ms used whole, adjusted 300 ms,
    //                smoothed_rtt = (7 * 200 + 300)/8 = 212.5 ms
    //   confirmed:   delay min(100, 25) = 25 ms, adjusted 375 ms,
    //                smoothed_rtt = (7 * 200 + 375)/8 = 221.875 ms
    [Fact]
    public void MaxAckDelayCapsTheReportedDelayOnlyAfterTheHandshakeIsConfirmed()
    {
        var unconfirmed = new TlsQuicAckTracker();
        var confirmed = new TlsQuicAckTracker();
        confirmed.OnHandshakeConfirmed();

        foreach (var tracker in new[] { unconfirmed, confirmed })
        {
            Sample(tracker, 0, TimeSpan.FromMilliseconds(200));
            Sample(
                tracker,
                1,
                TimeSpan.FromMilliseconds(400),
                EncodeAckDelay(TimeSpan.FromMilliseconds(100), 3));
        }

        Assert.Equal(TimeSpan.FromMilliseconds(212.5), unconfirmed.SmoothedRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(221.875), confirmed.SmoothedRtt);
    }

    // s5.2: "min_rtt MUST be set to the lesser of min_rtt and latest_rtt on all
    // other samples", and "If a path's actual RTT decreases, the min_rtt will adapt
    // immediately on the first low sample. If the path's actual RTT increases,
    // however, the min_rtt will not adapt to it."
    //
    // Both directions in one sequence, because a test of only the rising half
    // passes against a min_rtt that never moves at all and a test of only the
    // falling half passes against one that tracks latest_rtt.
    [Fact]
    public void MinRttFallsOnALowerSampleAndDoesNotRiseOnAHigherOne()
    {
        var tracker = new TlsQuicAckTracker();

        Sample(tracker, 0, TimeSpan.FromMilliseconds(200));
        Assert.Equal(TimeSpan.FromMilliseconds(200), tracker.MinimumRtt);

        Sample(tracker, 1, TimeSpan.FromMilliseconds(900));
        Assert.Equal(TimeSpan.FromMilliseconds(200), tracker.MinimumRtt);

        Sample(tracker, 2, TimeSpan.FromMilliseconds(120));
        Assert.Equal(TimeSpan.FromMilliseconds(120), tracker.MinimumRtt);

        Sample(tracker, 3, TimeSpan.FromMilliseconds(1500));
        Assert.Equal(TimeSpan.FromMilliseconds(120), tracker.MinimumRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(1500), tracker.LatestRtt);
    }

    // s5.1's FIRST condition - "the largest acknowledged packet number is newly
    // acknowledged" - and the reason it is not decoration.
    //
    // Nothing in this codebase deduplicates a received packet number, so a
    // duplicated datagram is opened twice and the ACK inside it is processed twice.
    // The second arrival is 900 ms after the first; a second sample would record
    // 1020 ms for a path whose round trip is 120 ms, and would keep doing so on
    // every duplicate. THIS IS INVISIBLE TO EVERY OTHER TEST IN THIS FILE, because
    // a clean path produces no duplicates - which is the shape of defect that
    // reaches production as unexplained RTT variance.
    [Fact]
    public void ADuplicatedAcknowledgementProducesNoSecondRttSample()
    {
        var tracker = new TlsQuicAckTracker();
        var frame = AckFrame(0, new TlsQuicAckRange(4, 4));
        TlsQuicSentPacket[] sentPackets = [Sent(4, Epoch)];

        Assert.True(tracker.ProcessAckFrame(
            RttLevel, frame, Epoch + TimeSpan.FromMilliseconds(120), sentPackets, out _));

        var after = (
            tracker.LatestRtt, tracker.MinimumRtt, tracker.SmoothedRtt,
            tracker.RttVariation, tracker.FirstRttSampleAt);
        Assert.Equal(TimeSpan.FromMilliseconds(120), tracker.LatestRtt);

        Assert.True(tracker.ProcessAckFrame(
            RttLevel, frame, Epoch + TimeSpan.FromMilliseconds(1020), sentPackets, out _));

        Assert.Equal(
            after,
            (tracker.LatestRtt, tracker.MinimumRtt, tracker.SmoothedRtt,
             tracker.RttVariation, tracker.FirstRttSampleAt));
    }

    // s5.1's SECOND condition, and it is a MUST NOT rather than a SHOULD NOT: "An
    // RTT sample MUST NOT be generated on receiving an ACK frame that does not
    // newly acknowledge at least one ack-eliciting packet. [...] an ACK frame that
    // contains acknowledgments for only non-ack-eliciting packets could include an
    // arbitrarily large ACK Delay value."
    //
    // So the reported delay here is arbitrarily large on purpose - 5 seconds
    // against a 120 ms round trip - because that is the value the sentence is
    // protecting the estimator from.
    [Fact]
    public void AnAcknowledgementOfOnlyNonAckElicitingPacketsProducesNoSample()
    {
        var tracker = new TlsQuicAckTracker();

        Sample(
            tracker,
            4,
            TimeSpan.FromMilliseconds(120),
            EncodeAckDelay(TimeSpan.FromSeconds(5), 3),
            ackEliciting: false);

        Assert.Null(tracker.FirstRttSampleAt);
        Assert.Equal(TimeSpan.Zero, tracker.LatestRtt);
        Assert.Equal(TimeSpan.Zero, tracker.MinimumRtt);
        Assert.Equal(TlsQuicRecoverySpec.KInitialRtt, tracker.SmoothedRtt);

        // The frame is still well formed and largest-acked still advances - s5.1
        // withholds a SAMPLE, not the acknowledgement.
        Assert.Equal(4ul, tracker.LargestAcked(RttLevel));
    }

    // The two halves of s5.1 that pull in different directions, in one input:
    // "at least ONE of the newly acknowledged packets was ack-eliciting" decides
    // WHETHER to sample, and "An RTT sample is generated using ONLY THE LARGEST
    // acknowledged packet in the received ACK frame" decides WHAT to measure.
    //
    // Packet 3 is ack-eliciting and sent at Epoch; packet 4 is an ACK-only packet
    // sent 10 ms later; both are newly acknowledged by one frame arriving 130 ms
    // after Epoch. The sample must be taken (packet 3 satisfies the condition) and
    // must be 120 ms, measured from packet 4 (the largest) - not 130 ms from packet
    // 3, which is what an implementation that measures from the ack-eliciting
    // packet it found would report.
    [Fact]
    public void TheSampleComesFromTheLargestAckedEvenWhenAnotherPacketMadeItEligible()
    {
        var tracker = new TlsQuicAckTracker();
        TlsQuicSentPacket[] sentPackets =
        [
            Sent(3, Epoch),
            Sent(4, Epoch + TimeSpan.FromMilliseconds(10), ackEliciting: false),
        ];

        Assert.True(tracker.ProcessAckFrame(
            RttLevel,
            AckFrame(0, new TlsQuicAckRange(4, 3)),
            Epoch + TimeSpan.FromMilliseconds(130),
            sentPackets,
            out _));

        Assert.Equal(TimeSpan.FromMilliseconds(120), tracker.LatestRtt);
        Assert.NotEqual(TimeSpan.FromMilliseconds(130), tracker.LatestRtt);
    }

    // s13.1: "An endpoint SHOULD treat receipt of an acknowledgment for a packet it
    // did not send as a connection error of type PROTOCOL_VIOLATION, IF IT IS ABLE
    // TO DETECT THE CONDITION." This pins the stated decision not to raise it - see
    // TryFindLargestNewlyAcked for the argument - as behaviour rather than as a
    // comment, because "we chose not to" and "we forgot" look identical from
    // outside.
    //
    // Largest-acked still advances to 9: s17.1's encoder input is about what the
    // peer claims to have seen, and refusing to move it would make us encode packet
    // numbers in more bytes than the peer needs, on the peer's say-so either way.
    [Fact]
    public void AnAcknowledgementNamingAPacketWeDidNotSendSamplesNothingAndRaisesNothing()
    {
        var tracker = new TlsQuicAckTracker();
        TlsQuicSentPacket[] sentPackets = [Sent(1, Epoch)];

        Assert.True(tracker.ProcessAckFrame(
            RttLevel,
            AckFrame(0, new TlsQuicAckRange(9, 9)),
            Epoch + TimeSpan.FromMilliseconds(50),
            sentPackets,
            out var error));

        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(9ul, tracker.LargestAcked(RttLevel));
        Assert.Null(tracker.FirstRttSampleAt);
        Assert.Equal(TlsQuicRecoverySpec.KInitialRtt, tracker.SmoothedRtt);
    }

    // "no existing TlsQuicAckTrackerTests case changes behaviour, since this task
    // adds and does not alter" - the four-argument overload is what every existing
    // caller uses, and it must sample nothing at all rather than sample from a list
    // it does not have.
    [Fact]
    public void TheOverloadWithoutASentPacketListSamplesNothing()
    {
        var tracker = new TlsQuicAckTracker();

        Assert.True(tracker.ProcessAckFrame(
            RttLevel,
            AckFrame(0, new TlsQuicAckRange(4, 4)),
            Epoch + TimeSpan.FromMilliseconds(120),
            out _));

        Assert.Equal(4ul, tracker.LargestAcked(RttLevel));
        Assert.Null(tracker.FirstRttSampleAt);
        Assert.Equal(TimeSpan.Zero, tracker.LatestRtt);
        Assert.Equal(TlsQuicRecoverySpec.KInitialRtt, tracker.SmoothedRtt);
    }

    // THE ONE MUTATION IN THIS TASK'S SWEEP THAT SURVIVED, and the test written
    // for it. Recorded as a survivor first because that is the honest order: the
    // property was asserted in a comment and by nothing else.
    //
    // ProcessAckFrame's own remark says why the decoded ranges used to be thrown
    // away - passing "a fresh List sized, one entry at a time, by however many
    // Gap / ACK Range Length pairs the peer chose to send" is "an allocation on
    // the receive path whose size is the attacker's to pick". A3-4 needs the
    // ranges, so the four-argument overload still passes null and the sampling
    // overload reuses one cleared list. The mutation that makes the validate-only
    // path pass a real list instead CHANGES NO OUTPUT AT ALL - every assertion in
    // this file still passes - it merely allocates on every received ACK and
    // never releases, which is why only a measurement can see it.
    //
    // Warmed first so tiered JIT and xUnit's own first-call work are not counted,
    // then measured over a thousand iterations: the threshold is under two bytes
    // per call, while the mutant grows a list by three ranges per call and
    // reallocates its backing array all the way to three thousand entries.
    [Fact]
    public void TheValidateOnlyPathWalksTheRangeChainWithoutAllocating()
    {
        var tracker = new TlsQuicAckTracker();
        var frame = AckFrame(
            0,
            new TlsQuicAckRange(40, 38),
            new TlsQuicAckRange(30, 20),
            new TlsQuicAckRange(10, 0));

        for (var warmup = 0; warmup < 64; warmup++)
        {
            Assert.True(tracker.ProcessAckFrame(RttLevel, frame, Epoch, out _));
        }

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var iteration = 0; iteration < 1000; iteration++)
        {
            Assert.True(tracker.ProcessAckFrame(RttLevel, frame, Epoch, out _));
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(allocated < 1024, $"validate-only path allocated {allocated} bytes over 1000 calls");
    }

    // s5.3's first bullet, a MAY this implementation takes: "MAY ignore the
    // acknowledgment delay for Initial packets, since these acknowledgments are not
    // delayed by the peer". Two levels, one input, so the branch is visible rather
    // than assumed.
    //
    // min_rtt 200 ms, latest_rtt 400 ms, reported delay 100 ms:
    //   Handshake: adjusted 300 ms, smoothed_rtt = (7 * 200 + 300)/8 = 212.5 ms
    //   Initial:   delay ignored, adjusted 400 ms,
    //              smoothed_rtt = (7 * 200 + 400)/8 = 225 ms
    [Fact]
    public void AnInitialPacketsAcknowledgementDelayIsIgnored()
    {
        var initial = new TlsQuicAckTracker();
        var handshake = new TlsQuicAckTracker();

        foreach (var (tracker, level) in new[]
        {
            (initial, TlsQuicEncryptionLevel.Initial),
            (handshake, TlsQuicEncryptionLevel.Handshake),
        })
        {
            Sample(tracker, 0, TimeSpan.FromMilliseconds(200), level: level);
            Sample(
                tracker,
                1,
                TimeSpan.FromMilliseconds(400),
                EncodeAckDelay(TimeSpan.FromMilliseconds(100), 3),
                level: level);
        }

        Assert.Equal(TimeSpan.FromMilliseconds(225), initial.SmoothedRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(212.5), handshake.SmoothedRtt);
    }

    // s5 computes its values "for each PATH", and A.3 lists latest_rtt,
    // smoothed_rtt, rttvar, min_rtt and first_rtt_sample as plain variables while
    // giving largest_acked_packet, loss_time and sent_packets a
    // [kPacketNumberSpace] subscript. One estimator, three spaces.
    //
    // A per-space estimator would take the second sample here as ITS first and
    // report smoothed_rtt 300 ms; one shared estimator smooths it against the first
    // and reports (7 * 100 + 300)/8 = 125 ms.
    [Fact]
    public void TheRttEstimatorIsOneForTheConnectionAndNotOnePerPacketNumberSpace()
    {
        var tracker = new TlsQuicAckTracker();

        Sample(tracker, 0, TimeSpan.FromMilliseconds(100), level: TlsQuicEncryptionLevel.Initial);
        Sample(tracker, 0, TimeSpan.FromMilliseconds(300), level: TlsQuicEncryptionLevel.Handshake);

        Assert.Equal(TimeSpan.FromMilliseconds(125), tracker.SmoothedRtt);
        Assert.NotEqual(TimeSpan.FromMilliseconds(300), tracker.SmoothedRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(100), tracker.MinimumRtt);

        // Largest-acked is per space and unaffected by the shared estimator: both
        // spaces saw packet number 0, and neither shadowed the other.
        Assert.Equal(0ul, tracker.LargestAcked(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(0ul, tracker.LargestAcked(TlsQuicEncryptionLevel.Handshake));
    }

    // An acknowledgement whose arrival timestamp precedes the send timestamp is not
    // a short round trip, it is a clock that moved - the same hazard TryBuildAck
    // clamps for. Discarded rather than clamped to zero: a zero sample would pin
    // min_rtt at zero for the rest of the connection, and s5.3's below-min_rtt guard
    // would then never fire again, so the "safe" clamp is the one that disarms the
    // protection.
    [Fact]
    public void AnAcknowledgementArrivingBeforeItsPacketWasSentProducesNoSample()
    {
        var tracker = new TlsQuicAckTracker();
        Sample(tracker, 0, TimeSpan.FromMilliseconds(200));

        Assert.True(tracker.ProcessAckFrame(
            RttLevel,
            AckFrame(0, new TlsQuicAckRange(1, 1)),
            Epoch,
            [Sent(1, Epoch + TimeSpan.FromSeconds(1))],
            out _));

        Assert.Equal(TimeSpan.FromMilliseconds(200), tracker.LatestRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(200), tracker.MinimumRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(200), tracker.SmoothedRtt);
    }

    // The receive path must not throw for anything a peer can put in the field, and
    // ACK Delay is a varint the peer fills - so 2^62-1 microseconds, then shifted
    // left by an ack_delay_exponent of 20. Decoded naively that is 2^82
    // microseconds, which wraps a ulong silently into a small positive number and
    // then multiplies by ten into a second wrap.
    //
    // Saturating instead means the delay reaches the min_rtt guard as an enormous
    // value, is refused there, and the sample survives intact - so the assertion is
    // that the estimator reports exactly what it would have with no delay at all.
    [Fact]
    public void AnAcknowledgementDelayAtTheVarintMaximumNeitherThrowsNorWraps()
    {
        var tracker = new TlsQuicAckTracker();
        tracker.OnPeerAckParameters(TlsQuicAckTracker.MaximumAckDelayExponent,
            TlsQuicAckTracker.DefaultMaxAckDelay);

        Sample(tracker, 0, TimeSpan.FromMilliseconds(200));
        Sample(tracker, 1, TimeSpan.FromMilliseconds(400),
            QuicVariableLengthInteger.MaximumValue);

        // (7 * 200 + 400)/8 = 225 ms - the no-subtraction answer.
        Assert.Equal(TimeSpan.FromMilliseconds(225), tracker.SmoothedRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(400), tracker.LatestRtt);
    }

    // OnPeerAckParameters clamps and does not throw, because both values are the
    // peer's and TlsQuicTransportParameters.ValidatePeer already raises s7.4's
    // TRANSPORT_PARAMETER_ERROR for either one out of range.
    //
    // The exponent clamp is the load-bearing half. C# evaluates `x << 64` as
    // `x << (64 & 63)`, which is `x << 0` - so an unclamped 64 would decode every
    // ACK Delay as its raw microsecond count rather than saturating, and would be
    // silently, exactly wrong rather than obviously wrong. With the clamp to 20 a
    // reported 1000-unit delay decodes to 1000 * 2^20 microseconds, about 1049
    // seconds, which the min_rtt guard refuses; without it the same field would
    // decode to 1 ms and be subtracted. min_rtt 200 ms, latest_rtt 400 ms:
    //   clamped:   adjusted 400 ms, smoothed_rtt = (7 * 200 + 400)/8 = 225 ms
    //   unclamped: adjusted 399 ms, smoothed_rtt = (7 * 200 + 399)/8 = 224.875 ms
    [Fact]
    public void OnPeerAckParametersClampsOutOfRangeValuesRatherThanThrowing()
    {
        var tracker = new TlsQuicAckTracker();
        tracker.OnPeerAckParameters(64, TimeSpan.FromDays(1));

        Sample(tracker, 0, TimeSpan.FromMilliseconds(200));
        Sample(tracker, 1, TimeSpan.FromMilliseconds(400), 1000);

        Assert.Equal(TimeSpan.FromMilliseconds(225), tracker.SmoothedRtt);
        Assert.NotEqual(TimeSpan.FromMilliseconds(224.875), tracker.SmoothedRtt);

        // The other end of both ranges, and the negative one s18.2 has no word for
        // because a varint cannot express it - a caller can.
        var negative = new TlsQuicAckTracker();
        negative.OnPeerAckParameters(-1, TimeSpan.FromSeconds(-5));
        negative.OnHandshakeConfirmed();

        Sample(negative, 0, TimeSpan.FromMilliseconds(200));
        Sample(negative, 1, TimeSpan.FromMilliseconds(400),
            EncodeAckDelay(TimeSpan.FromMilliseconds(100), 0));

        // max_ack_delay clamped to zero and the handshake confirmed, so the cap
        // removes the delay entirely: adjusted 400 ms, smoothed_rtt 225 ms.
        Assert.Equal(TimeSpan.FromMilliseconds(225), negative.SmoothedRtt);

        // s18.2: "Values of 2^14 or greater are invalid", so a day is clamped to
        // 16383 ms and the cap still bites. min_rtt 200 ms, latest_rtt 30000 ms,
        // reported delay 20000 ms, handshake confirmed:
        //   clamped:   min(20000, 16383) = 16383, adjusted 13617 ms,
        //              smoothed_rtt = (7 * 200 + 13617)/8 = 1877.125 ms
        //   unclamped: min(20000, 86400000) = 20000, adjusted 10000 ms,
        //              smoothed_rtt = (7 * 200 + 10000)/8 = 1425 ms
        var enormous = new TlsQuicAckTracker();
        enormous.OnPeerAckParameters(3, TimeSpan.FromDays(1));
        enormous.OnHandshakeConfirmed();

        Sample(enormous, 0, TimeSpan.FromMilliseconds(200));
        Sample(enormous, 1, TimeSpan.FromMilliseconds(30000),
            EncodeAckDelay(TimeSpan.FromMilliseconds(20000), 3));

        Assert.Equal(TimeSpan.FromMilliseconds(1877.125), enormous.SmoothedRtt);
        Assert.NotEqual(TimeSpan.FromMilliseconds(1425), enormous.SmoothedRtt);
        Assert.Equal(
            TimeSpan.FromMilliseconds((1 << 14) - 1), TlsQuicAckTracker.MaximumMaxAckDelay);
    }

    // A negative seed is a CALLER's value rather than a peer's, so this throws
    // where OnPacketReceived's rejections drop - the same split the class remarks
    // draw. A negative smoothed_rtt would make s6.2.1's PTO negative before a
    // single sample existed.
    [Fact]
    public void ANegativeInitialRttIsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicAckTracker(initialRtt: TimeSpan.FromMilliseconds(-1)));

        // Zero is legal and is not the same as absent: it seeds both values at zero
        // rather than falling back to kInitialRtt.
        var zero = new TlsQuicAckTracker(initialRtt: TimeSpan.Zero);
        Assert.Equal(TimeSpan.Zero, zero.SmoothedRtt);
        Assert.Equal(TimeSpan.Zero, zero.RttVariation);
    }

    // THE INVARIANT A CONSTANT-RETURNING MUTANT FAILS, over a long random sequence
    // rather than a chosen one - so it is the property being tested and not a
    // vector. s5.3's estimator is a convex combination of values that are
    // themselves bounded below by min_rtt (the guard guarantees adjusted_rtt >=
    // min_rtt) and above by the largest raw sample, so smoothed_rtt can never leave
    // that interval however the samples move.
    //
    // The delays are drawn too, up to twice the round trip, so roughly half of them
    // trip s5.3's below-min_rtt guard and the other half are subtracted - which is
    // the mix that makes the lower bound a real constraint rather than a
    // consequence of never adjusting anything.
    //
    // The distinct-values assertion is what a constant-returning mutant actually
    // dies on: a constant inside [min_rtt, max sample] satisfies the interval and
    // nothing else here would notice it.
    [Fact]
    public void SmoothedRttStaysBetweenMinRttAndTheLargestSampleAcrossALongSequence()
    {
        var random = new Random(20260821);
        var tracker = new TlsQuicAckTracker();
        HashSet<TimeSpan> distinct = [];
        var largestSample = TimeSpan.Zero;

        for (var packetNumber = 0ul; packetNumber < 400; packetNumber++)
        {
            var rtt = TimeSpan.FromMilliseconds(random.Next(5, 400));
            largestSample = rtt > largestSample ? rtt : largestSample;

            Sample(
                tracker,
                packetNumber,
                rtt,
                EncodeAckDelay(TimeSpan.FromMilliseconds(random.Next(0, 2 * 400)), 3));

            Assert.True(
                tracker.SmoothedRtt >= tracker.MinimumRtt,
                $"smoothed {tracker.SmoothedRtt} below min {tracker.MinimumRtt} at {packetNumber}");
            Assert.True(
                tracker.SmoothedRtt <= largestSample,
                $"smoothed {tracker.SmoothedRtt} above largest {largestSample} at {packetNumber}");
            Assert.True(tracker.RttVariation >= TimeSpan.Zero);

            distinct.Add(tracker.SmoothedRtt);
        }

        Assert.Equal(TimeSpan.FromMilliseconds(5), tracker.MinimumRtt);
        Assert.True(distinct.Count > 100, $"smoothed_rtt took only {distinct.Count} values");
    }

    // ---- knob 12: TlsQuicRecoverySpec.AckPolicy - A3-13 --------------------
    //
    // RFC 9000 s13.2.1, THE SENTENCE THE WHOLE KNOB LIVES INSIDE, quoted once here
    // and cited by line below rather than re-quoted in each test:
    //
    //   "An endpoint MUST acknowledge all ack-eliciting Initial and Handshake
    //    packets immediately and all ack-eliciting 0-RTT and 1-RTT packets within
    //    its advertised max_ack_delay, with the following exception."
    //
    // TWO SPACES, OPPOSITE TREATMENT, ONE SENTENCE - which is why every test below
    // that moves the knob also names a level. A suite that only ever probed one
    // space could pass against an implementation that delayed everything, and that
    // implementation would be violating a MUST.
    //
    // THE BOUND IS 25 ms AND IT IS THIS CLIENT'S ADVERTISED VALUE, NOT A STAND-IN.
    // s18.2: "If this value is absent, a default of 25 milliseconds is assumed", and
    // max_ack_delay (0x0B) is absent from TlsQuicTransportParameterSpec's entries -
    // so 25 ms is what this client told the peer it would honour.

    private static readonly TlsQuicFrame[] Ping =
        [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }];

    private static TlsQuicAckTracker Delayed() =>
        new(ackPolicy: TlsQuicAckPolicy.DelayedToMaxAckDelay);

    // THE SHIPPED DEFAULT'S BYTES, PINNED. perk_hash parity depends on defaults not
    // moving, so this is asserted as an ARRAY and not as "TryBuildAck returned true":
    // a delay leaking into the shipped path would change the ACK Delay field and
    // leave a boolean assertion green.
    //
    // Received packet 0, ack-eliciting, built in the same instant.
    //   Type 0x02, Largest Acknowledged 0, ACK Delay 0, ACK Range Count 0,
    //   First ACK Range 0 - every field one byte under s16's 0b00 prefix.
    //
    // ALL THREE SPACES, because the default must be untouched in the one space the
    // knob can reach as well as in the two it cannot.
    [Fact]
    public void TheShippedDefaultAcknowledgesInTheArrivalInstantAtEveryLevel()
    {
        foreach (var level in new[]
        {
            TlsQuicEncryptionLevel.Initial,
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicEncryptionLevel.Application,
        })
        {
            Assert.Equal(
                new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00 },
                Encode(Receive(new TlsQuicAckTracker(), level, 0), level));

            // AND THE EXPLICIT SETTING IS THE SAME BYTES AS THE UNSET ONE. Without
            // this, "Immediate is the default" would rest on the enum's member order
            // alone, and reordering the members would move the shipped behaviour
            // without moving a single expectation.
            Assert.Equal(
                new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00 },
                Encode(
                    Receive(
                        new TlsQuicAckTracker(ackPolicy: TlsQuicAckPolicy.Immediate),
                        level,
                        0),
                    level));
        }
    }

    // s13.2.1's OTHER half: 0-RTT and 1-RTT get max_ack_delay, so nothing is
    // available in the arrival instant and everything is available at the bound.
    //
    // THE ACK THAT FINALLY COMES OUT IS A DIFFERENT FRAME, NOT A LATE COPY OF THE
    // SAME ONE, and that is what makes this knob a fingerprint rather than a
    // schedule. s13.2.5 measures "the delays intentionally introduced between the
    // time the packet with the largest packet number is received and the time an
    // acknowledgment is sent", so the ACK Delay field carries the 25 ms:
    //   25 ms = 25000 us, and s19.3 encodes it shifted right by this endpoint's
    //   ack_delay_exponent of 3 - 25000 >> 3 = 3125.
    //   3125 needs s16's two-byte form: 0x4000 | 3125 = 0x4C35.
    //   Type 0x02, Largest 0x00, ACK Delay 0x4C 0x35, Range Count 0x00,
    //   First ACK Range 0x00.
    [Fact]
    public void DelayedToMaxAckDelayWithholdsAnApplicationAckUntilTheBoundThenEmitsIt()
    {
        var tracker = Receive(Delayed(), TlsQuicEncryptionLevel.Application, 0);
        var bound = Epoch + TlsQuicAckTracker.DefaultMaxAckDelay;

        Assert.False(tracker.TryBuildAck(
            TlsQuicEncryptionLevel.Application, Epoch, out _, out _));

        // ONE TICK SHORT, WHICH IS THE COMPARISON ITSELF UNDER TEST. Without this
        // row a `<=` that released a tick early would pass every other assertion
        // here, and so would an implementation that delayed by any amount at all.
        Assert.False(tracker.TryBuildAck(
            TlsQuicEncryptionLevel.Application,
            bound - TimeSpan.FromTicks(1),
            out _,
            out _));

        // AT the bound, not after it: "within the maximum delay" includes the
        // maximum. The mirror of the row above, and the pair pins the boundary from
        // both sides so neither a `<` nor a `<=` can be swapped for the other.
        Assert.Equal(
            new byte[] { 0x02, 0x00, 0x4C, 0x35, 0x00, 0x00 },
            Encode(tracker, TlsQuicEncryptionLevel.Application, bound));
    }

    // s13.2.1's Initial and Handshake MUST, asserted against BOTH policies - which
    // is the assertion A3-12's readout probe was missing. The knob is not entitled
    // to waive this, so the two levels answer identically no matter how it is set.
    [Fact]
    public void EveryPolicyAcknowledgesInitialAndHandshakeInTheArrivalInstant()
    {
        foreach (var level in new[]
        {
            TlsQuicEncryptionLevel.Initial,
            TlsQuicEncryptionLevel.Handshake,
        })
        {
            Assert.Equal(
                Encode(Receive(new TlsQuicAckTracker(), level, 0), level),
                Encode(Receive(Delayed(), level, 0), level));

            // And no wake is armed for a space that was never held back.
            Assert.Null(Receive(Delayed(), level, 0).DelayedAckDeadline);
        }
    }

    // s12.3 collapses 0-RTT and 1-RTT onto one space and s13.2.1 gives them one
    // rule, so EarlyData is delayed exactly as Application is. Asserted because the
    // implementation compares against a single space index: a version that tested
    // `level == Application` instead would leave 0-RTT immediate and no other test
    // here would notice.
    [Fact]
    public void EarlyDataIsHeldBackWithTheApplicationSpaceItShares()
    {
        var tracker = Receive(Delayed(), TlsQuicEncryptionLevel.EarlyData, 0);

        Assert.False(tracker.TryBuildAck(
            TlsQuicEncryptionLevel.EarlyData, Epoch, out _, out _));
        Assert.Equal(
            Epoch + TlsQuicAckTracker.DefaultMaxAckDelay,
            tracker.DelayedAckDeadline);
    }

    // s13.2's "When sending a packet for any reason, an endpoint SHOULD attempt to
    // include an ACK frame if one has not been sent recently" - the force overload -
    // is never withheld. Acknowledging EARLY cannot break a promise not to
    // acknowledge LATE.
    [Fact]
    public void AForcedBuildIsNeverWithheld()
    {
        Assert.Equal(
            new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00 },
            Encode(
                Receive(Delayed(), TlsQuicEncryptionLevel.Application, 0),
                TlsQuicEncryptionLevel.Application,
                Epoch,
                force: true));
    }

    // THE DEADLINE IS ANCHORED ON THE OLDEST UNACKNOWLEDGED PACKET AND NOT THE
    // NEWEST, AND THIS IS THE TEST THE WHOLE MUST TURNS ON.
    //
    // _largestReceivedAt already exists on this class and moves forward on every
    // higher-numbered arrival, so reusing it would have been the smaller diff. Under
    // that version a peer sending an ack-eliciting packet every 10 ms would push the
    // deadline back by 10 ms every 10 ms and this endpoint would acknowledge NEVER,
    // while every other test in this section stayed green - each of them receives a
    // single packet. s13.2.1's promise is per packet, so the bound belongs to the
    // first one waiting.
    [Fact]
    public void TheDelayedDeadlineIsAnchoredOnTheOldestUnacknowledgedPacketNotTheNewest()
    {
        var tracker = Delayed();
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Application, 0, Crypto, Epoch);

        var later = Epoch + TimeSpan.FromMilliseconds(10);
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Application, 1, Crypto, later);

        Assert.Equal(
            Epoch + TlsQuicAckTracker.DefaultMaxAckDelay,
            tracker.DelayedAckDeadline);

        // And the ACK really is available there, 15 ms after the second packet
        // arrived rather than 25 - both packets in the one frame, which is the
        // batching the policy exists to produce.
        //   Largest Acknowledged 1, ACK Range Count 0, First ACK Range 1 - 0 = 1.
        //   ACK Delay is measured from the LARGEST packet's arrival (s13.2.5), so it
        //   is 25 - 10 = 15 ms: 15000 >> 3 = 1875 = 0x0753, two-byte form 0x4753.
        Assert.Equal(
            new byte[] { 0x02, 0x01, 0x47, 0x53, 0x00, 0x01 },
            Encode(
                tracker,
                TlsQuicEncryptionLevel.Application,
                Epoch + TlsQuicAckTracker.DefaultMaxAckDelay));
    }

    // Nothing to flush, nothing to wake for - under either policy, and after the
    // debt is discharged. The last of the three is what keeps a wake from re-arming
    // on an instant already past once the ACK has gone out.
    [Fact]
    public void NoDeadlineIsOwedWithoutADebtToDischarge()
    {
        Assert.Null(new TlsQuicAckTracker().DelayedAckDeadline);
        Assert.Null(Delayed().DelayedAckDeadline);
        Assert.Null(
            Receive(new TlsQuicAckTracker(), TlsQuicEncryptionLevel.Application, 0)
                .DelayedAckDeadline);

        var tracker = Receive(Delayed(), TlsQuicEncryptionLevel.Application, 0);
        Assert.NotNull(tracker.DelayedAckDeadline);
        Assert.True(tracker.TryBuildAck(
            TlsQuicEncryptionLevel.Application,
            Epoch + TlsQuicAckTracker.DefaultMaxAckDelay,
            out _,
            out _));
        Assert.Null(tracker.DelayedAckDeadline);

        // AND IT RE-ARMS FROM THE NEXT DEBT'S OWN INSTANT, not from the first one's.
        var next = Epoch + TimeSpan.FromMilliseconds(100);
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Application, 1, Crypto, next);
        Assert.Equal(next + TlsQuicAckTracker.DefaultMaxAckDelay, tracker.DelayedAckDeadline);
    }

    // s12.4 Table 3's N marking survives the knob: a packet carrying only an ACK
    // incurs no debt, so it arms nothing. Without this a delayed tracker would wake
    // the connection for an acknowledgement s13.2.1 forbids it to send - "An
    // endpoint MUST NOT send a non-ack-eliciting packet in response to a
    // non-ack-eliciting packet ... This avoids an infinite feedback loop".
    [Fact]
    public void ANonAckElicitingPacketArmsNoDelayedWake()
    {
        var tracker = Delayed();
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Application, 0, AckOnly, Epoch);
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Application, 1, PaddingOnly, Epoch);

        Assert.Null(tracker.DelayedAckDeadline);
        Assert.False(tracker.TryBuildAck(
            TlsQuicEncryptionLevel.Application,
            Epoch + TimeSpan.FromDays(1),
            out _,
            out _));
    }

    // NOTHING THROWS FOR ANY INPUT, INCLUDING ONE NO SEAM SHOULD LET THROUGH. An
    // enum is an integer in a hat; TlsQuicRecoverySpec.AckPolicy's init rejects an
    // undeclared cast, but this class defends itself independently by testing for
    // DelayedToMaxAckDelay by equality rather than switching with a throwing
    // default. An undeclared value therefore acknowledges immediately - the shipped
    // behaviour - instead of killing a connection from the receive path.
    [Fact]
    public void AnUndeclaredAckPolicyAcknowledgesImmediatelyAndThrowsNothing()
    {
        var undeclared = (TlsQuicAckPolicy)(-1);
        Assert.False(Enum.IsDefined(undeclared));

        var tracker = Receive(
            new TlsQuicAckTracker(ackPolicy: undeclared),
            TlsQuicEncryptionLevel.Application,
            0);

        Assert.Null(tracker.DelayedAckDeadline);
        Assert.Equal(
            new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00 },
            Encode(tracker, TlsQuicEncryptionLevel.Application));
    }

    // s13.2.1's exception, which is the one legal way to exceed the bound: "Prior to
    // handshake confirmation, an endpoint might not have packet protection keys for
    // decrypting Handshake, 0-RTT, or 1-RTT packets when they are received. It might
    // therefore buffer them and acknowledge them when the requisite keys become
    // available." A packet not yet processed has not been handed to OnPacketReceived
    // at all - see its own contract, "CALL THIS AFTER PROCESSING, NOT ON RECEIPT" -
    // so the clock this class starts is the PROCESSING instant and the exception
    // costs it no code. Asserted so the absence is a measured fact and not a gap:
    // a debt arising at t starts its bound at t, whatever the packet's arrival was.
    [Fact]
    public void TheBoundRunsFromProcessingAndNotFromAnEarlierArrival()
    {
        var processed = Epoch + TimeSpan.FromSeconds(5);
        var tracker = Delayed();
        tracker.OnPacketReceived(TlsQuicEncryptionLevel.Application, 0, Crypto, processed);

        Assert.Equal(
            processed + TlsQuicAckTracker.DefaultMaxAckDelay,
            tracker.DelayedAckDeadline);
        Assert.False(tracker.TryBuildAck(
            TlsQuicEncryptionLevel.Application, processed, out _, out _));
    }

    // TWO POLICIES, ONE PACKET, ONE INSTANT - the shape A3-12's readout row 17
    // measures, kept here as well so the knob's observable difference is pinned by a
    // test that does not depend on the readout being rendered at all.
    [Fact]
    public void TheTwoPoliciesDisagreeAboutTheSameApplicationPacketAtTheSameInstant()
    {
        Assert.True(
            Receive(new TlsQuicAckTracker(), TlsQuicEncryptionLevel.Application, 0)
                .TryBuildAck(TlsQuicEncryptionLevel.Application, Epoch, out _, out _));
        Assert.False(
            Receive(Delayed(), TlsQuicEncryptionLevel.Application, 0)
                .TryBuildAck(TlsQuicEncryptionLevel.Application, Epoch, out _, out _));
    }
}
