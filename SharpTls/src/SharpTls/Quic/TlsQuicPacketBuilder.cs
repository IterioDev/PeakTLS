using System.Runtime.InteropServices;

namespace SharpTls.Quic;

/// <summary>What the send path knows about one packet the moment it hands it to a
/// transport. A4-minimal builds one of these per packet and discards it.</summary>
/// <remarks>
/// <para>THIS TYPE EXISTS FOR A3, WHICH IS NOT IN THIS PHASE. A3 (RFC 9002 loss
/// detection) needs a record of every packet still outstanding, and nothing in this
/// codebase retains one: <see cref="CustomTlsQuicClient"/> advances its CRYPTO write
/// offset and hands over the only copy of the bytes. Emitting this record now is what
/// makes A3 an insertion - it stores the values in a list - instead of a rewrite of
/// this builder. Each field is here because A3 needs it and none of it can be
/// recovered later:</para>
/// <list type="bullet">
/// <item><description><see cref="Level"/> and <see cref="PacketNumber"/> identify the
/// packet inside its number space. RFC 9000 s12.3 gives Initial, Handshake and
/// application data separate spaces, so a packet number alone does not name a packet;
/// an ACK frame is interpreted against the space its own packet arrived in.</description></item>
/// <item><description><see cref="Size"/> is the byte count A3 subtracts from bytes in
/// flight on acknowledgement or loss.</description></item>
/// <item><description><see cref="IsAckEliciting"/> decides whether losing this packet
/// must be repaired at all, and whether a peer owes an acknowledgement for it - RFC
/// 9000 s13.2.</description></item>
/// <item><description><see cref="IsInFlight"/> decides whether the packet counts
/// toward a congestion window. Distinct from <see cref="IsAckEliciting"/>: RFC 9000
/// s13.2.7 says "Packets containing PADDING frames are considered to be in flight for
/// congestion control purposes", and a PADDING-only packet elicits nothing.</description></item>
/// <item><description><see cref="SentAt"/> is the RTT sample's start. A3 subtracts it
/// from the acknowledgement's arrival time.</description></item>
/// </list>
/// <para>WHAT IT DELIBERATELY DOES NOT CARRY, because the fields above are each
/// justified and an unexplained absence reads as an oversight: the CRYPTO stream byte
/// range this packet carried. The field list matches RFC 9002's own <c>SentPacket</c>
/// pseudocode, which is everything RTT, the congestion window and PTO need - none of
/// those asks what was inside. RETRANSMISSION DOES, and the answer is that it comes
/// off the send side by offset rather than by replaying this record: RFC 9000 s13.3
/// says lost CRYPTO <i>data</i> is retransmitted, not that the packet is, and A4's
/// plan already records that <see cref="CustomTlsQuicClient"/> hands over the only
/// copy of its CRYPTO bytes as it advances the write offset. So whatever retains
/// those bytes - A3 - owns the offset bookkeeping with them, and a range here would
/// be a second place to keep in step with the first. Named rather than left silent,
/// because "which bytes were lost" is the first thing a reader of this type looks for
/// and does not find.</para>
/// <para>THE CLOCK IS NOT HERE, AND THAT IS DELIBERATE. <see cref="SentAt"/> is a
/// parameter of <see cref="TlsQuicPacketBuilder.Build"/>, not something this file
/// reads. A4's clock seam is <c>TimeProvider</c> on
/// <see cref="TlsQuicConnectionOptions"/>, owned by the connection loop; a builder
/// that reached for a clock of its own would be a second, untestable one. The name is
/// "sent at" rather than "built at" because the connection loop builds and sends in
/// one synchronous step and passes the timestamp it is about to send with - if that
/// ever stops being true, the caller is where the difference is visible, not
/// here.</para>
/// </remarks>
internal readonly record struct TlsQuicSentPacket(
    TlsQuicEncryptionLevel Level,
    ulong PacketNumber,
    int Size,
    bool IsAckEliciting,
    bool IsInFlight,
    DateTimeOffset SentAt);

/// <summary>The header fields of one packet to build: everything RFC 9000 s17.2's long
/// header or s17.3.1's short header carries that is not derived from the frames. Which
/// form is built is decided by <see cref="Type"/> alone - see its remarks - and the
/// fields belonging to the other form are rejected rather than ignored.</summary>
/// <remarks>
/// <para>This is NOT <see cref="TlsQuicConnectionSpec"/> and does not hold one. The
/// spec carries connection ID <i>lengths</i>; a packet carries connection ID
/// <i>bytes</i>, which are connection state - the destination connection ID changes
/// after a Retry, and the source connection ID is drawn once per connection. The
/// connection layer is what turns spec knobs plus connection state into one of these.
/// The spec's <see cref="TlsQuicConnectionSpec.InitialCryptoFrameByteCounts"/> and
/// <see cref="TlsQuicConnectionSpec.InitialCryptoFramesPerDatagram"/> never reach this
/// type at all: a flight plan is task 5's, and this builder is given one already
/// ordered frame list.</para>
/// <para>LIFETIME: every <c>ReadOnlyMemory&lt;byte&gt;</c> here is borrowed, matching
/// how <see cref="TlsQuicLongHeader"/> and <see cref="TlsQuicFrame"/> treat theirs.
/// Build copies what it needs into the destination span before returning.</para>
/// </remarks>
internal readonly struct TlsQuicPacketPlan
{
    /// <summary>RFC 9000 s17.2 Table 5, or null for the short header of s17.3.1. Retry is
    /// not buildable here; see <see cref="TlsQuicPacketBuilder.Build"/>.</summary>
    /// <remarks>
    /// <para>NULL RATHER THAN A FIFTH ENUM MEMBER, because s17.2's "Long Packet Type (2)"
    /// field is the thing this property carries and a short header HAS NO SUCH FIELD -
    /// s17.3.1's byte 0 spends those two bit positions on the Spin Bit and a Reserved bit.
    /// A fifth member of <see cref="TlsQuicLongPacketType"/> would be a value Table 5 does
    /// not print, and the enum is a transcription of Table 5.</para>
    /// <para>An absence rather than a flag also keeps the three places that already ask
    /// "is this an Initial?" correct with no edit: <c>Type == Initial</c> is false when
    /// Type is null, whereas a <c>bool IsShortHeader</c> beside a Type that defaults to
    /// <see cref="TlsQuicLongPacketType.Initial"/> - it is 0x00 in Table 5 - would have
    /// made every short-header plan claim to be an Initial one until each site was found
    /// and fixed.</para>
    /// </remarks>
    internal TlsQuicLongPacketType? Type { get; init; }

    /// <summary>RFC 9000 s17.3.1's Spin Bit, short header only. s17.4 makes it a sender
    /// choice - "endpoints MAY disable the spin bit" - so it is a knob and never derived.
    /// </summary>
    internal bool SpinBit { get; init; }

    /// <summary>RFC 9000 s17.3.1's Key Phase bit, short header only: which of the two
    /// 1-RTT key phases <see cref="TlsQuicPacketBuilder.Build"/> was handed keys for. The
    /// caller states it because the builder is given key bytes and no key schedule; RFC
    /// 9001 s6 key update is out of this phase's scope, and the receive side's
    /// <c>TlsQuicPacketReceiver.InstallReadKeys</c> takes the same bit for the same
    /// reason.</summary>
    internal bool KeyPhase { get; init; }

    /// <summary>RFC 9000 s17.2's Version field.</summary>
    internal uint Version { get; init; }

    /// <summary>RFC 9000 s17.2's Destination Connection ID, bytes and all.</summary>
    internal ReadOnlyMemory<byte> DestinationConnectionId { get; init; }

    /// <summary>RFC 9000 s17.2's Source Connection ID. Empty is legal and is what
    /// Chromium sends - see <see cref="TlsQuicConnectionSpec.SourceConnectionIdLength"/>.</summary>
    internal ReadOnlyMemory<byte> SourceConnectionId { get; init; }

    /// <summary>RFC 9000 s17.2.2's Token, for an Initial packet only. Empty on a first
    /// flight, which is the only case RFC 9001 A.2 shows.</summary>
    internal ReadOnlyMemory<byte> Token { get; init; }

    /// <summary>The full, untruncated packet number. RFC 9001 s5.3 uses this value -
    /// not the truncated wire form - to build the AEAD nonce.</summary>
    internal ulong PacketNumber { get; init; }

    /// <summary>How many bytes the truncated packet number occupies on the wire, 1 to
    /// 4. A sender knob, not a derived value; see
    /// <see cref="TlsQuicConnectionSpec.PacketNumberEncodedLength"/>.</summary>
    internal int PacketNumberEncodedLength { get; init; }

    /// <summary>The largest packet number this endpoint has had acknowledged in this
    /// packet's number space, or null if none has been. Read only to bound
    /// <see cref="PacketNumberEncodedLength"/> from below, by RFC 9000 Appendix
    /// A.2's rule; task 8's ACK processing is what advances it.</summary>
    internal ulong? LargestAcknowledged { get; init; }

    /// <summary>The width RFC 9000 s17.2's Length field is written at. Minimal is the
    /// default and the only encoding RFC 9001 A.2 shows; s16 permits any wider one,
    /// which makes this observable - A4's plan Finding 5.</summary>
    internal TlsQuicVarintWidth LengthVarintWidth { get; init; }

    /// <summary>The width every CRYPTO frame in this packet writes its RFC 9000 s19.6
    /// Offset field at; see <see cref="TlsQuicConnectionSpec.CryptoOffsetVarintWidth"/>.
    /// </summary>
    /// <remarks>PER PACKET, NOT PER FRAME, because the spec declares one width for the
    /// connection and a per-frame override would be a knob subsystem B has no field to
    /// populate. A packet whose CRYPTO frames wanted different widths is expressible only
    /// by building two packets, which is a flight-plan decision and therefore task 5's.
    /// </remarks>
    internal TlsQuicVarintWidth CryptoOffsetVarintWidth { get; init; }

    /// <summary>The width every CRYPTO frame in this packet writes its RFC 9000 s19.6
    /// Length field at; see <see cref="TlsQuicConnectionSpec.CryptoLengthVarintWidth"/>.
    /// Per packet, for the reason given on <see cref="CryptoOffsetVarintWidth"/>.</summary>
    internal TlsQuicVarintWidth CryptoLengthVarintWidth { get; init; }
}

/// <summary>RFC 9001 s5.3 and s5.4: assembles one protected QUIC packet - RFC 9000
/// s17.2's long header or s17.3.1's short header - from a header plan and an ordered
/// frame list.</summary>
/// <remarks>
/// <para>ORDER IS THE CALLER'S, ALWAYS. Frames are written in exactly the order given,
/// with no merging, no reordering and no padding added - the same contract
/// <see cref="TlsQuicFrames.WriteFrame"/> already keeps. Frame order inside a packet
/// is one of the layout fields subsystem B varies, so "helpfully" normalising it here
/// would destroy the thing the spec exists to express.</para>
/// <para>NO TLS ENGINE AND NO TRANSPORT. The payload arrives as frames and the keys
/// arrive as bytes. That is what lets RFC 9001 A.2's published ClientHello - which
/// this library will never generate - be sealed by this exact code path, and it is the
/// same seam subsystem B needs.</para>
/// <para>THE ORDER OF THE THREE STEPS IS NORMATIVE, not a preference. RFC 9001 s5.3:
/// "When constructing packets, the AEAD function is applied prior to applying header
/// protection; see Section 5.4." So: write the unprotected header, seal the payload
/// with that header as associated data, then mask the header. Header protection's
/// sample is taken from ciphertext that does not exist until the seal has run.</para>
/// </remarks>
internal static class TlsQuicPacketBuilder
{
    // MUTATION RECORD. Each mutation was applied in a git worktree, the gate
    // (dotnet test --filter "FullyQualifiedName~Quic") run, and the mutation reverted.
    // NO SURVIVORS. What follows is the observed failure set per mutation, not a summary:
    // where it says ONLY, that test was the entire failure set for that run.
    //
    // HOW TO RECOUNT THIS, because the "how many are blind to the published vectors"
    // figure was wrong twice before anyone counted the bullets. Every mutation sits in
    // exactly one of the two sections below, each section states the count of its own
    // bullets, and the total is the sum - so both halves are recomputable from the list
    // immediately above them. Do not carry the total anywhere it cannot be rederived;
    // that is how it moved.
    //
    // Two named groups, so the wide kill sets are itemised once rather than restated:
    //
    //   THE BYTE-EXACT PAIR =
    //     TlsQuicPacketBuilderTests.AppendixA2ClientInitialIsProducedByteForByte
    //     TlsQuicPacketBuilderTests.AppendixA3ServerInitialIsProducedByteForByte
    //
    //   THE HAND-DERIVED HEADER SET =
    //     TlsQuicPacketBuilderTests.ANonZeroTokenIsWrittenWithItsLengthPrefixAndMovesEve
    //       rythingAfterIt
    //     TlsQuicPacketBuilderTests.PacketNumberEncodedLengthIsWrittenAsTheSpecAsksAtEve
    //       ryLegalWidth (all four rows)
    //     TlsQuicPacketBuilderTests.TheHeaderLengthVarintIsWrittenAtTheWidthTheSpecAsksF
    //       or (all four rows)
    //     TlsQuicPacketBuilderTests.CryptoFramesAreWrittenAtTheOffsetsAndInTheOrderGiven
    //       WithNoMerging
    //     TlsQuicPacketBuilderTests.TheAeadNonceUsesTheFullPacketNumberNotTheTruncatedWi
    //       reForm
    //
    // SECTION 1 - AT LEAST ONE PUBLISHED VECTOR SEES IT. Eleven bullets.
    //
    //   1. AAD ends at the packet number offset instead of after it -> the byte-exact
    //      pair, CryptoFramesAreWrittenAtTheOffsetsAndInTheOrderGivenWithNoMerging and
    //      TheAeadNonceUsesTheFullPacketNumberNotTheTruncatedWireForm, and nothing else:
    //      the header-only assertions cannot see an AAD change.
    //   2. AAD one byte short -> the same four.
    //   3. Length field omits the 16-byte tag -> the byte-exact pair and the whole
    //      hand-derived header set.
    //   4. Length field omits the packet number length -> the same.
    //   5. Header protection applied at pn_offset + 1 -> the byte-exact pair and the
    //      whole hand-derived header set.
    //   6. ...at pn_offset - 1 -> those, plus
    //      TlsQuicPacketBuilderTests.APayloadTooShortForTheSectionFiveFourTwoSampleIsRej
    //      ected.
    //   7. ...applied to the header slice only, so the sample is missing -> those, plus
    //      the Table 3 Spec-column tests, which then fail on the throw.
    //   8. Packet size omits the tag -> the byte-exact pair, the hand-derived header set,
    //      the Spec-column tests, and
    //      TlsQuicPacketBuilderTests.ADestinationTooSmallForThePayloadAndTagIsRejected.
    //   9. TryApply's false return ignored -> kills broadly, because skipping it also
    //      skips the masking every byte-exact assertion checks.
    //  10. IsAckEliciting excluding CRYPTO -> the byte-exact pair, and since this review
    //      also TlsQuicPacketBuilderTests.CryptoOnlyPacketsAreAckElicitingAndInFlight.
    //  11. IsInFlight excluding CRYPTO -> A.3 ALONE before that test existed, and A.3
    //      plus it now. THE OLD WITNESS WAS AN ACCIDENT: A.2 stayed green because its
    //      payload is CRYPTO plus PADDING and PADDING keeps this flag true by itself, so
    //      the flag was held only by what A.3's payload happens to contain, and would
    //      have stopped being held - silently - if that composition ever changed. A flag
    //      now has a witness that is about the flag.
    //
    // SECTION 2 - NEITHER PUBLISHED VECTOR SEES IT. Thirteen bullets. Every one left RFC
    // 9001 A.2 AND A.3 GREEN, which is the whole finding of this task and the reason the
    // plan demands a hand-derived case per knob rather than trusting leg 1:
    //
    //   1. AEAD nonce built from the truncated wire packet number instead of the full one
    //      -> ONLY TlsQuicPacketBuilderTests.TheAeadNonceUsesTheFullPacketNumberNotTheTr
    //      uncatedWireForm. A.2 writes packet number 2 in four bytes and A.3 writes 1 in
    //      two, so in both the truncated and the full value are the same number.
    //   2. IsInFlight also excluding PADDING -> ONLY
    //      TlsQuicPacketBuilderTests.PaddingOnlyPacketsAreNotAckElicitingButAreStillInFl
    //      ight.
    //   3. IsAckEliciting no longer excluding CONNECTION_CLOSE -> ONLY
    //      TlsQuicPacketBuilderTests.ConnectionCloseOnlyPacketsAreNotAckElicitingButAreI
    //      nFlight.
    //   4. IsAckEliciting also excluding PING -> ONLY
    //      TlsQuicPacketBuilderTests.PingOnlyPacketsAreAckElicitingAndInFlight. A live
    //      survivor found by spec review, not by the first sweep, which covered the three
    //      rows Table 3 marks N and missed the empty-Spec row beside them.
    //   5. IsInFlight also excluding PING -> ONLY the same test.
    //   6. Frames sorted by offset before writing -> ONLY
    //      TlsQuicPacketBuilderTests.CryptoFramesAreWrittenAtTheOffsetsAndInTheOrderGive
    //      nWithNoMerging. A.2 carries one CRYPTO frame and A.3's two are already in the
    //      order a sort would put them.
    //   7. The empty-frame-list guard disabled -> ONLY
    //      TlsQuicPacketBuilderTests.BuildingAPacketWithNoFramesIsRejected.
    //   8. The send-path legality guard disabled -> ONLY
    //      TlsQuicPacketBuilderTests.AFrameTable3ForbidsInThisPacketTypeIsRejected.
    //   9. The 1-to-4 packet number length guard widened -> ONLY
    //      TlsQuicPacketBuilderTests.APacketNumberEncodedLengthOutsideOneToFourIsRejected
    //      , both rows.
    //  10. The Appendix A.2 packet number floor guard disabled -> ONLY
    //      TlsQuicPacketBuilderTests.APacketNumberEncodedLengthBelowTheAppendixATwoFloorI
    //      sRejected.
    //  11. The non-Initial token guard disabled -> ONLY
    //      TlsQuicPacketBuilderTests.ATokenOnANonInitialPacketIsRejected.
    //  12. The destination bound disabled -> ONLY
    //      TlsQuicPacketBuilderTests.ADestinationTooSmallForThePayloadAndTagIsRejected.
    //  13. The Token Length varint widened along with the Length varint, in
    //      TlsQuicPacketHeader -> the three non-minimal rows of
    //      TlsQuicPacketBuilderTests.TheHeaderLengthVarintIsWrittenAtTheWidthTheSpecAsks
    //      For and of TlsQuicPacketHeaderTests.WriteLongHeaderWidensOnlyTheLengthFieldWh
    //      enAsked. A.2's token length is 0 and its Length varint minimal, so it never
    //      sees a widened field at all.
    //
    // Eleven plus thirteen is twenty-four mutations, no survivors.

    // ================================================================================
    // A4 TASK 14b - THE SHORT-HEADER SWEEP. Same method as above: applied in a git
    // worktree off f8c0fbe, gate run, reverted. NINETEEN mutations, EIGHTEEN killed, ONE
    // SURVIVOR, and the survivor is named and classified rather than left implicit.
    //
    // HOW TO RECOUNT THIS. Three groups by the file mutated, each stating the count of
    // its own bullets: 8 + 5 + 6 = 19. Killed is 19 less the one survivor in group A,
    // which is 18. Do not carry either number anywhere it cannot be rederived from the
    // bullets immediately above it - that is how the count above this block moved twice.
    //
    // AND HOW GOOD THIS EVIDENCE IS, BECAUSE IT IS NOT AS GOOD AS THE SWEEP ABOVE. Every
    // mutation above had RFC 9001 A.2 or A.3 available to it as a possible killer. THIS
    // SWEEP HAS NO PUBLISHED VECTOR AT ALL - Appendix A has no 1-RTT packet, A.5 is a
    // header-protection sample and is spent in TlsQuicHeaderProtectionTests - so every
    // kill below is by a hand-derived case, a loopback, or a spec-derived differential.
    // A kill count is therefore not comparable with the one above it.
    //
    // Two named groups, so the wide kill sets are itemised once:
    //
    //   THE LAYOUT SET = all four rows of
    //     TlsQuicPacketBuilderTests.AShortHeaderMatchesTheSection1731FieldLayout
    //
    //   THE LOOPBACK SET =
    //     TlsQuicPacketBuilderTests.AShortHeaderPacketIsOpenedByThePacketReceiverAtTheIn
    //       stalledKeyPhase (both rows)
    //     TlsQuicPacketBuilderTests.AShortHeaderPacketBuiltAtTheOtherKeyPhaseIsAKeyUpdat
    //       eError (both rows)
    //
    // GROUP A - THIS FILE. Eight bullets.
    //
    //   1. LevelOf's null arm returns Handshake instead of Application -> 13 tests: the
    //      layout set, the loopback set, ShortHeaderProtectionReachesTheFifthBitOfByteZe
    //      roWhichALongHeaderMaskCannot, AShortHeaderPacketIsBuiltAtTheApplicationLevelA
    //      ndCarriesHandshakeDone, and in TlsQuicDatagramBuilderTests both rows of
    //      NothingMayBeCoalescedAfterAShortHeaderPacket and AnInitialCoalescedWithAShort
    //      HeaderPacketIsPaddedInTheShortHeaderOne. HANDSHAKE_DONE is what does it: RFC
    //      9000 s12.4 Table 3 marks it "___1", so the legality gate rejects the whole
    //      frame list the moment the level is anything but Application.
    //   2. ValidateShortHeaderPlan's Version check disabled -> ONLY
    //      TlsQuicPacketBuilderTests.ALongHeaderOnlyFieldOnAShortHeaderPlanIsRejected,
    //      the "version" row.
    //   3. ...its Source Connection ID check disabled -> ONLY that test's "source
    //      connection id" row.
    //   4. ...its Token check disabled -> ONLY that test's "token" row.
    //   5. ...its Length varint width check disabled -> ONLY that test's "length varint
    //      width" row.
    //   6. The whole ValidateShortHeaderPlan call replaced by ValidateToken -> three of
    //      that test's four rows, NOT the token one. That is the intended reading and not
    //      a gap: ValidateToken's condition is `Type != Initial`, which a null Type
    //      satisfies, so the token half survives the swap and the other three do not.
    //      Recorded because it is the mutation that shows the four conditions are pinned
    //      separately rather than as a block.
    //   7. THE ONE SURVIVOR. The builder fills TlsQuicShortHeader.PacketNumberOffset with
    //      999 instead of leaving it default -> NOTHING FAILS. VACUOUS, and deliberately
    //      so: that field is the READ side's, filled by TryReadShortHeader from the bytes
    //      it walked, and WriteShortHeader never reads it - it returns the offset through
    //      its out parameter instead. No test is written for this. A test that pinned the
    //      field to 0 on a struct the writer ignores would pass against every mutant that
    //      matters and would be a false witness for the offset, which is exactly the
    //      transcription task 14a exists to prevent.
    //   8. Header protection applied at a locally recomputed `1 + len(dcid) + 1` instead
    //      of at the out parameter -> 10 tests: the layout set, the loopback set,
    //      ShortHeaderProtectionReachesTheFifthBitOfByteZeroWhichALongHeaderMaskCannot,
    //      and TlsQuicDatagramBuilderTests.AnInitialCoalescedWithAShortHeaderPacketIsPad
    //      dedInTheShortHeaderOne. This is the mutation that makes bullet 7's survival
    //      safe to accept: the offset that is actually used is pinned, at the one byte of
    //      slack a recomputation would most plausibly get wrong.
    //
    // GROUP B - THE SHORT-HEADER WRITER AND THE PROTECTION MASK, in TlsQuicPacketHeader
    // and TlsQuicHeaderProtection. Five bullets. These are task 14a's and task 4's code,
    // mutated here because 14b's done-when is about the bits they write.
    //
    //   9. WriteShortHeader ignores header.KeyPhase (always clear) -> 15 tests: the two
    //      key-phase-true rows of the layout set, the two rows of the loopback set that
    //      involve a set phase, and eleven in TlsQuicPacketHeaderTests.
    //  10. WriteShortHeader hardcodes the Key Phase bit SET -> 28 tests, the complementary
    //      halves of the same sets plus TlsQuicConnectionTests and
    //      TlsQuicFingerprintReadoutTests, which run whole handshakes. BOTH DIRECTIONS
    //      RUN, because a bit witnessed in one direction only is held by a mutant that
    //      hardcodes that direction - which is what bullet 9 and this one are between
    //      them.
    //  11. WriteShortHeader ignores header.SpinBit -> 4 tests: the two spin-true rows of
    //      the layout set and both spin-true rows of
    //      TlsQuicPacketHeaderTests.SpinBitAndKeyPhaseRoundTripIndependently.
    //  12. TlsQuicHeaderProtection.ShortHeaderProtectionMask narrowed from 0x1f to the
    //      long header's 0x0f -> 2 tests:
    //      TlsQuicHeaderProtectionTests.LongHeaderMasksLowFourBitsShortHeaderMasksLowFive
    //      Bits and ShortHeaderProtectionReachesTheFifthBitOfByteZeroWhichALongHeaderMask
    //      Cannot. THE FIRST OF THOSE ALREADY EXISTED, so this builder's five-bit witness
    //      is a second one and not the only one - said plainly because the whole layout
    //      set stays GREEN under this mutation, apply and remove cancelling exactly, and
    //      a reader could otherwise take the layout set for evidence about the mask.
    //  13. WriteShortHeader sets the Header Form bit -> 45 tests. Recorded because it is
    //      the builder's entire obligation towards bullet 12: the mask width is selected
    //      from that bit by TlsQuicHeaderProtection.ProtectionMaskFor, so a short header
    //      that set it would silently take the long header's four-bit mask.
    //
    // GROUP C - TlsQuicDatagramBuilder. Six bullets.
    //
    //  14. The s12.2 predecessor guard disabled -> ONLY both rows of
    //      TlsQuicDatagramBuilderTests.NothingMayBeCoalescedAfterAShortHeaderPacket.
    //  15. The same guard testing packets[index] instead of packets[index - 1] -> 4
    //      tests: both rows of that test, plus AShortHeaderHasNoSourceConnectionIdToCompa
    //      re and AnInitialCoalescedWithAShortHeaderPacketIsPaddedInTheShortHeaderOne,
    //      which are the two that build a LEGAL datagram ending in a short header and are
    //      therefore what separates "followed by" from "present at all".
    //  16. The Source Connection ID comparison applied to short headers too -> ONLY
    //      TlsQuicDatagramBuilderTests.AShortHeaderHasNoSourceConnectionIdToCompare and
    //      AnInitialCoalescedWithAShortHeaderPacketIsPaddedInTheShortHeaderOne.
    //  17. ...never applied at all -> ONLY
    //      TlsQuicDatagramBuilderTests.CoalescingPacketsWithDifferentConnectionIdsIsRejec
    //      ted, its source row. So the narrowing in that comparison is pinned from both
    //      sides: too wide by bullet 16, too narrow by this one.
    //  18. SolvePaddingFrameCount's short-header branch omits the connection ID length ->
    //      ONLY TlsQuicDatagramBuilderTests.AnInitialCoalescedWithAShortHeaderPacketIsPad
    //      dedInTheShortHeaderOne.
    //  19. ...omits the authentication tag -> ONLY the same test.
    //
    // Eight plus five plus six is nineteen mutations; one survivor, in group A, classified
    // vacuous with no test written for it.


    // RFC 9001 s5.3: "These cipher suites have a 16-byte authentication tag."
    // TlsQuicPacketProtection.Seal owns the same number for its own bounds check;
    // this copy is the one the Length field and the destination bound are computed
    // from, and the two are cross-checked by Seal throwing if they ever disagree.
    //
    // Internal, not private, for A4 task 5: TlsQuicDatagramBuilder solves for a PADDING
    // frame count from a datagram size, and the tag is a term in that arithmetic. A third
    // copy of the number is exactly the transcription this phase bans.
    internal const int AuthenticationTagLength = 16;

    /// <summary>Builds one protected packet into <paramref name="destination"/> and
    /// reports what was sent.</summary>
    /// <remarks>
    /// Every argument is caller-supplied and most of them come, directly or through
    /// the connection layer, from <see cref="TlsQuicConnectionSpec"/> - which
    /// subsystem B populates. So every guard below is reachable by construction and
    /// each carries its own witness.
    /// </remarks>
    /// <returns>The record A3 will retain; see <see cref="TlsQuicSentPacket"/>.</returns>
    internal static TlsQuicSentPacket Build(
        in TlsQuicPacketPlan plan,
        IReadOnlyList<TlsQuicFrame> frames,
        TlsQuicPacketProtectionCipher packetProtectionCipher,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        TlsQuicHeaderProtectionCipher headerProtectionCipher,
        ReadOnlySpan<byte> headerProtectionKey,
        DateTimeOffset sentAt,
        Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(frames);

        var level = LevelOf(plan);

        // RFC 9000 s12.4: "An endpoint MUST treat receipt of a packet containing no
        // frames as a connection error of type PROTOCOL_VIOLATION." Sending one is
        // therefore never right, and an empty list is also what would make
        // IsAckEliciting and IsInFlight below vacuously false rather than meaningful.
        // Witnessed by TlsQuicPacketBuilderTests.BuildingAPacketWithNoFramesIsRejected.
        if (frames.Count == 0)
        {
            throw new ArgumentException(
                "A QUIC packet must carry at least one frame (RFC 9000 s12.4).", nameof(frames));
        }

        ValidatePacketNumberEncoding(plan);
        if (plan.Type is null)
        {
            ValidateShortHeaderPlan(plan);
        }
        else
        {
            ValidateToken(plan);
        }

        var payload = new List<byte>();
        foreach (var frame in frames)
        {
            // RFC 9000 s12.4 Table 3's "Pkts" column, applied on the SEND path and not
            // only on the receive path. It is one call, and it turns a spec that names
            // a frame the packet type cannot carry into a test failure here rather than
            // into a PROTOCOL_VIOLATION from the peer at handshake time.
            // Witnessed by TlsQuicPacketBuilderTests.AFrameTable3ForbidsInThisPacketTyp
            // eIsRejected.
            if (!TlsQuicFrameLegality.Permits(frame, level))
            {
                throw new ArgumentException(
                    $"RFC 9000 s12.4 Table 3 does not permit a {frame.Type} frame in a {level} packet.",
                    nameof(frames));
            }

            TlsQuicFrames.WriteFrame(
                payload, frame, plan.CryptoOffsetVarintWidth, plan.CryptoLengthVarintWidth);
        }

        var packetNumberLength = plan.PacketNumberEncodedLength;
        var encodedPacketNumber = EncodePacketNumber(plan.PacketNumber, packetNumberLength);

        int headerLength;
        int packetNumberOffset;
        if (plan.Type is null)
        {
            // RFC 9000 s17.3.1's field list, in order: byte 0, Destination Connection ID,
            // Packet Number, Packet Payload. NO LENGTH FIELD, which is why the arithmetic
            // above it is absent rather than merely unused - s12.2 makes the short-header
            // packet the last one in its datagram and its payload runs to the end, so
            // there is nothing for a Length to delimit. TlsQuicPacketHeader.cs:418-421
            // already says exactly this on the read side; the send side agreeing is the
            // point of A4 task 14b, and TlsQuicDatagramBuilder.BuildDatagram enforces the
            // "last one" half.
            var shortHeader = new TlsQuicShortHeader
            {
                SpinBit = plan.SpinBit,
                KeyPhase = plan.KeyPhase,
                DestinationConnectionId = plan.DestinationConnectionId,
                PacketNumberLength = packetNumberLength,
                PacketNumber = encodedPacketNumber,
            };

            // PacketNumberOffset is deliberately NOT set on the struct above and is taken
            // from the out parameter instead (A4 task 14a). The field is the read side's,
            // filled by the parser from the bytes it walked; recomputing it here to feed
            // the writer that is about to lay the same bytes out would be the second
            // transcription 4a's text bans.
            headerLength = TlsQuicPacketHeader.WriteShortHeader(
                destination, shortHeader, out packetNumberOffset);
        }
        else
        {
            // RFC 9000 s17.2, Length: "The length of the remainder of the packet (that is,
            // the Packet Number and Payload fields) in bytes". The payload on the wire is
            // the AEAD output, which RFC 9001 s5.3 makes the plaintext plus the tag - so
            // the tag is inside Length, and RFC 9001 A.2 says so arithmetically: "a length
            // of 1182 bytes: the 4-byte packet number, 1162 bytes of frames, and the
            // 16-byte authentication tag."
            var length = (ulong)(packetNumberLength + payload.Count + AuthenticationTagLength);

            var header = new TlsQuicLongHeader
            {
                Type = plan.Type.Value,
                Version = plan.Version,
                DestinationConnectionId = plan.DestinationConnectionId,
                SourceConnectionId = plan.SourceConnectionId,
                Token = plan.Token,
                Length = length,
                PacketNumberLength = packetNumberLength,
                PacketNumber = encodedPacketNumber,
            };

            headerLength = TlsQuicPacketHeader.WriteLongHeader(
                destination, header, out packetNumberOffset, plan.LengthVarintWidth);
        }

        var size = headerLength + payload.Count + AuthenticationTagLength;
        if (destination.Length < size)
        {
            // WriteLongHeader has already bounded the header portion and thrown for
            // that case; this is the payload and tag it knows nothing about. The
            // header bytes it wrote are left in place - the caller is discarding the
            // buffer either way, and copying them somewhere first to keep the failure
            // atomic would cost an allocation on the success path too.
            // Witnessed by TlsQuicPacketBuilderTests.ADestinationTooSmallForThePayloadA
            // ndTagIsRejected.
            throw new ArgumentException(
                $"Packet needs {size} bytes, destination has {destination.Length}.", nameof(destination));
        }

        // RFC 9001 s5.3: "The associated data, A, for the AEAD is the contents of the
        // QUIC header, starting from the first byte of either the short or long header,
        // up to and including the unprotected packet number." EITHER FORM - the sentence
        // names both, and that is why one slice serves both branches above. It is exactly
        // the bytes the header writer just wrote - unprotected, because header protection
        // has not run yet - so the slice is [0, headerLength) and no arithmetic re-derives
        // it.
        //
        // The nonce takes plan.PacketNumber, the FULL number, not the truncated wire
        // form: s5.3 says "The 62 bits of the reconstructed QUIC packet number in
        // network byte order are left-padded with zeros to the size of the IV."
        TlsQuicPacketProtection.Seal(
            packetProtectionCipher,
            key,
            iv,
            plan.PacketNumber,
            destination[..headerLength],
            CollectionsMarshal.AsSpan(payload),
            destination.Slice(headerLength, payload.Count + AuthenticationTagLength));

        // RFC 9001 s5.4.2: "sample_offset = pn_offset + 4", and the sample is 16 bytes
        // of the protected packet. packetNumberOffset is pn_offset, returned by the
        // writer that laid the header out rather than recomputed from the field widths
        // a second time (A4 task 4a, and 14a for the short header's own writer).
        //
        // THE NUMBER OF PROTECTED BITS IN BYTE 0 IS NOT DECIDED HERE, AND MUST NOT BE.
        // RFC 9001 s5.4's preamble: "The four least significant bits of the first byte
        // are protected for packets with long headers; the five least significant bits of
        // the first byte are protected for packets with short headers." That difference -
        // 0x0f against 0x1f, one bit, the high Reserved bit - lives in
        // TlsQuicHeaderProtection.ProtectionMaskFor, which selects on the Header Form bit
        // that s17.2/s17.3.1 both leave outside the mask. So this call is byte-identical
        // for the two forms and the builder's whole obligation is to have left byte 0's
        // Header Form bit clear, which WriteShortHeader does. A copy of the two mask
        // values here would be the transcription this phase bans, and the removal side
        // that has to agree with it is pinned against RFC 9001 A.5's published
        // ChaCha20 SHORT-HEADER sample in TlsQuicHeaderProtectionTests - evidence about
        // the mask width that owes nothing to this builder.
        // Witnessed here by TlsQuicPacketBuilderTests.ShortHeaderProtectionReachesTheFift
        // hBitOfByteZeroWhichALongHeaderMaskCannot.
        //
        // TryApply returns false when the packet is too short for that sample, which
        // s5.4.2 makes a real caller case rather than an internal error: it "results in
        // needing at least 3 bytes of frames in the unprotected payload if the packet
        // number is encoded on a single byte, or 2 bytes of frames for a 2-byte packet
        // number encoding". A short frame list is a spec author's choice, so this is
        // reachable and must not be swallowed - an unmasked packet number would
        // otherwise go out looking perfectly well-formed.
        // Witnessed by TlsQuicPacketBuilderTests.APayloadTooShortForTheSectionFiveFourT
        // woSampleIsRejected.
        if (!TlsQuicHeaderProtection.TryApply(
                headerProtectionCipher, headerProtectionKey, destination[..size], packetNumberOffset))
        {
            throw new ArgumentException(
                $"Payload of {payload.Count} bytes is too short for RFC 9001 s5.4.2's 16-byte header " +
                $"protection sample at a {packetNumberLength}-byte packet number.",
                nameof(frames));
        }

        return new TlsQuicSentPacket(
            level,
            plan.PacketNumber,
            size,
            IsAckEliciting(frames),
            IsInFlight(frames),
            sentAt);
    }

    // RFC 9000 s12.4, first paragraph: "Version Negotiation, Stateless Reset, and Retry
    // packets do not contain frames." Retry is the only one of the three that
    // TlsQuicLongPacketType can even name, and TlsQuicRetry already builds it - it has
    // no packet number and no packet protection, so nothing this builder does applies.
    // Witnessed by TlsQuicPacketBuilderTests.BuildingARetryPacketIsRejected and
    // TlsQuicPacketBuilderTests.ALongPacketTypeOutsideTable5IsRejected, which are two
    // reachable paths through one mapping and throw different exception types so
    // neither hides the other.
    private static TlsQuicEncryptionLevel LevelOf(in TlsQuicPacketPlan plan) => plan.Type switch
    {
        // RFC 9001 s4.1.1's table pairs "1-RTT" with the "1-RTT" keys, and s17.3.1 titles
        // the short header "1-RTT Packet" - the two are the same thing under two names, so
        // a plan with no long packet type is an Application-level packet. This arm decides
        // BOTH which column of RFC 9000 s12.4 Table 3 the frame loop above is checked
        // against AND the Level on the returned TlsQuicSentPacket, which s12.3 makes the
        // packet number space. Witnessed by TlsQuicPacketBuilderTests.AShortHeaderPacketIs
        // BuiltAtTheApplicationLevelAndCarriesHandshakeDone, whose HANDSHAKE_DONE frame
        // Table 3 permits in a 1-RTT packet and in no other, so naming any other level
        // here turns the legality gate into a rejection.
        null => TlsQuicEncryptionLevel.Application,

        // RFC 9001 s4.1.1 pairs the packet types with the encryption levels
        // TlsQuicFrameLegality keys on; 0-RTT is the level named EarlyData here.
        TlsQuicLongPacketType.Initial => TlsQuicEncryptionLevel.Initial,
        TlsQuicLongPacketType.ZeroRtt => TlsQuicEncryptionLevel.EarlyData,
        TlsQuicLongPacketType.Handshake => TlsQuicEncryptionLevel.Handshake,
        TlsQuicLongPacketType.Retry => throw new ArgumentException(
            "RFC 9000 s12.4: Retry packets do not contain frames, and RFC 9000 s17.2.5 gives them "
            + "no packet number to protect. Use TlsQuicRetry.",
            nameof(plan)),
        _ => throw new ArgumentOutOfRangeException(nameof(plan), plan.Type, "Unknown long packet type."),
    };

    private static void ValidatePacketNumberEncoding(in TlsQuicPacketPlan plan)
    {
        // RFC 9000 s17.1: "Packet Number: This field is 1 to 4 bytes long." Checked
        // here as well as inside WriteLongHeader because the two arrive at it from
        // different arguments - this one reports the plan field a spec author set, and
        // the one downstream reports a TlsQuicLongHeader this method built. Different
        // ParamName, so neither check masks a mutation in the other.
        // Witnessed by TlsQuicPacketBuilderTests.APacketNumberEncodedLengthOutsideOneTo
        // FourIsRejected.
        if (plan.PacketNumberEncodedLength is < 1 or > 4)
        {
            throw new ArgumentOutOfRangeException(
                nameof(plan),
                plan.PacketNumberEncodedLength,
                "RFC 9000 s17.1: the Packet Number field is 1 to 4 bytes long.");
        }

        // RFC 9000 Appendix A.2: a sender must send enough of the packet number that
        // the peer can recover it - "at least twice as large as the difference between
        // the packet number and the largest acknowledged". TlsQuicPacketNumber.Encoded
        // Length is that computation and is not repeated here; it is the FLOOR, and a
        // sender is free to go wider, which is the whole point of the knob (RFC 9001
        // A.2 encodes packet number 2 in four bytes). Going narrower produces a packet
        // the peer decodes as a different number, silently.
        //
        // EncodedLength also throws when the packet number is below the largest
        // acknowledged, which is a caller error this method deliberately does not
        // restate - one transcription of that rule, in the type that owns it.
        // Witnessed by TlsQuicPacketBuilderTests.APacketNumberEncodedLengthBelowTheAppe
        // ndixATwoFloorIsRejected and TlsQuicPacketBuilderTests.APacketNumberBelowTheLa
        // rgestAcknowledgedIsRejected.
        var floor = TlsQuicPacketNumber.EncodedLength(plan.PacketNumber, plan.LargestAcknowledged);
        if (plan.PacketNumberEncodedLength < floor)
        {
            throw new ArgumentOutOfRangeException(
                nameof(plan),
                plan.PacketNumberEncodedLength,
                $"Packet number {plan.PacketNumber} needs at least {floor} bytes against a largest "
                + $"acknowledged of {plan.LargestAcknowledged?.ToString() ?? "none"} (RFC 9000 Appendix A.2).");
        }
    }

    // RFC 9000 s17.2: only the Initial packet has Token Length and Token fields; s17.2.3
    // and s17.2.4 give 0-RTT and Handshake neither. WriteLongHeader writes a token for
    // an Initial packet and silently ignores one otherwise, so without this a spec
    // carrying a token would lose it with no signal - the same defect class
    // TlsQuicStreamFrames.WriteCryptoFrameFields guards with its stream ID check.
    // Witnessed by TlsQuicPacketBuilderTests.ATokenOnANonInitialPacketIsRejected.
    private static void ValidateToken(in TlsQuicPacketPlan plan)
    {
        if (!plan.Token.IsEmpty && plan.Type != TlsQuicLongPacketType.Initial)
        {
            throw new ArgumentException(
                $"RFC 9000 s17.2 gives only Initial packets a Token field; this plan is {plan.Type}.",
                nameof(plan));
        }
    }

    // RFC 9000 s17.3.1's field list gives the short header exactly four fields - byte 0,
    // Destination Connection ID, Packet Number, Packet Payload - so every long-header-only
    // field of the plan has nowhere to go in one. WriteShortHeader does not take them and
    // would not complain, so without this a plan carrying one would lose it with no signal:
    // the same defect class ValidateToken guards one level up, and the reason that method
    // is reached only on the long-header branch rather than being widened to cover both.
    //
    // FOUR SEPARATE CONDITIONS, NOT ONE COMBINED TEST, because a test can only pin the
    // check that fires first and each field needs its own row. Witnessed one row each by
    // TlsQuicPacketBuilderTests.ALongHeaderOnlyFieldOnAShortHeaderPlanIsRejected.
    private static void ValidateShortHeaderPlan(in TlsQuicPacketPlan plan)
    {
        if (plan.Version != 0)
        {
            throw new ArgumentException(
                "RFC 9000 s17.3.1 gives the short header no Version field; this plan sets "
                + $"0x{plan.Version:x8}.",
                nameof(plan));
        }

        if (!plan.SourceConnectionId.IsEmpty)
        {
            throw new ArgumentException(
                "RFC 9000 s17.3.1 gives the short header no Source Connection ID field; this plan "
                + $"sets {plan.SourceConnectionId.Length} bytes of one.",
                nameof(plan));
        }

        if (!plan.Token.IsEmpty)
        {
            throw new ArgumentException(
                "RFC 9000 s17.3.1 gives the short header no Token field; only s17.2.2's Initial "
                + $"packet has one, and this plan sets {plan.Token.Length} bytes.",
                nameof(plan));
        }

        // s17.3.1 has no Length field either - s12.2 makes the short-header packet the last
        // in its datagram, so its payload runs to the end and nothing needs delimiting. A
        // non-Minimal width is a request for a field that is not written at all.
        if (plan.LengthVarintWidth != TlsQuicVarintWidth.Minimal)
        {
            throw new ArgumentException(
                "RFC 9000 s17.3.1 gives the short header no Length field; this plan asks for a "
                + $"{plan.LengthVarintWidth} one.",
                nameof(plan));
        }
    }

    // RFC 9000 Appendix A.2's EncodePacketNumber, truncation and serialisation: the
    // least significant `length` bytes of the full packet number, in network byte
    // order. Truncate is TlsQuicPacketNumber's, so the masking rule has one home.
    private static byte[] EncodePacketNumber(ulong fullPacketNumber, int length)
    {
        var truncated = TlsQuicPacketNumber.Truncate(fullPacketNumber, length * 8);
        var encoded = new byte[length];
        for (var index = length - 1; index >= 0; index--)
        {
            encoded[index] = (byte)truncated;
            truncated >>= 8;
        }
        return encoded;
    }

    // RFC 9000 s12.4's "Spec" column legend, verbatim: "N: Packets containing only
    // frames with this marking are not ack-eliciting; see Section 13.2." Table 3 prints
    // N against PADDING (0x00), ACK (0x02-0x03) and CONNECTION_CLOSE (0x1c-0x1d) and
    // against nothing else, so any other frame makes the packet ack-eliciting.
    //
    // THE ROW THAT IS EASIEST TO ADD BY MISTAKE IS PING (0x01), whose Spec cell is
    // EMPTY. It is not marked N, so a PING-only packet IS ack-eliciting - s19.2: "The
    // receiver of a PING frame simply needs to acknowledge the packet containing this
    // frame." That matters past this phase, because a PING-only packet is what a PTO
    // probe is: marking it non-ack-eliciting would make A3's probes elicit nothing and
    // repair nothing, and the symptom would appear two phases from this line. Pinned by
    // TlsQuicPacketBuilderTests.PingOnlyPacketsAreAckElicitingAndInFlight, which a
    // spec-review sweep found to be the only thing standing between this set and that
    // mistake.
    //
    // TlsQuicFrameLegality transcribes Table 3's "Pkts" column and says in its header
    // that the "Spec" column is out of scope there - correctly, because Spec describes
    // the packet a frame is bundled into rather than which packet types may carry it.
    // A packet is exactly what this file assembles, so the two markings this phase
    // needs live here, with the same one-transcription rule: the rows are named above
    // and nowhere else.
    //
    // The empty-frame-list case is rejected in Build, so "containing only frames with
    // this marking" is never satisfied vacuously ON THE SEND SIDE. The receive side has
    // no such guarantee and does not need one: an empty list here returns false, and a
    // received packet carrying no frames is already a s12.4 PROTOCOL_VIOLATION the
    // caller rejects before it would ever ask this question.
    //
    // INTERNAL, NOT PRIVATE, SINCE A4 TASK 8. TlsQuicAckTracker.OnPacketReceived asks
    // the same question about a RECEIVED packet - s13.2's "only ack-eliciting packets
    // cause an ACK frame to be sent" - and the promise three paragraphs up, that "the
    // rows are named above and nowhere else", is only true if it calls this rather than
    // transcribing Table 3's N column a second time. The rows and their mutation record
    // stay here, where the send side's four tests already pin them; widening the
    // accessibility was the whole change.
    internal static bool IsAckEliciting(IReadOnlyList<TlsQuicFrame> frames)
    {
        foreach (var frame in frames)
        {
            if (frame.Type is not (TlsQuicFrameType.Padding
                or TlsQuicFrameType.Ack
                or TlsQuicFrameType.ConnectionClose))
            {
                return true;
            }
        }
        return false;
    }

    // RFC 9000 s12.4's legend again: "C: Packets containing only frames with this
    // marking do not count toward bytes in flight for congestion control purposes".
    // Table 3 prints C against ACK alone - not against PADDING, which carries N and P
    // but not C. s13.2.7 states the consequence in words rather than table markings:
    // "Packets containing PADDING frames are considered to be in flight for congestion
    // control purposes", which is the independent reading that confirms the row.
    private static bool IsInFlight(IReadOnlyList<TlsQuicFrame> frames)
    {
        foreach (var frame in frames)
        {
            if (frame.Type != TlsQuicFrameType.Ack)
            {
                return true;
            }
        }
        return false;
    }
}
