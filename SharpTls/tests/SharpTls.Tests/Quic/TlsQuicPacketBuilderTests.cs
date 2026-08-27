using SharpTls.Fuzzing;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task 4b of A4-minimal. Two kinds of test live here and they answer different
// questions, which is the whole point of the split:
//
// 1. RFC 9001 Appendix A.2 and A.3 - the only IETF-published packet-level bytes this
//    phase has. They pin the builder at one particular layout and nothing else. Read
//    the table in the A4 plan ("What leg 1 does and does not anchor") before treating
//    a green A.2 as evidence about anything configurable: A.2's token length is 0, its
//    varints are all minimal, and it is a single datagram, so three of subsystem B's
//    eight fields are anchored only at their degenerate default and two not at all.
//
// 2. Hand-derived vectors at NON-DEFAULT values of every knob this builder reads.
//    Their expected bytes are written out from the RFC 9000 s17.2 field diagram and
//    s16 Table 4 by hand, in the comment above each one - never captured from a run of
//    this builder. Task 4a demonstrated why: dropping the token-length term from the
//    packet-number offset passed the A.2 test and was caught only by a non-empty-token
//    case.
//
// WHAT IS AND IS NOT DECODED. A long header's header protection masks only byte 0's
// low four bits and the Packet Number field (RFC 9001 s5.4). Every other header byte
// travels in the clear, so the hand-derived tests assert the connection IDs, the token
// and the Length varint straight off the wire with no decoding at all. Only byte 0 and
// the packet number need TlsQuicHeaderProtection.TryRemove, and only the payload needs
// TlsQuicPacketProtection.TryOpen. Those two are the inverse crypto, pinned
// independently against A.2, A.3 and A.5 in their own test classes - not this
// builder's own arithmetic reflected back.
public sealed class TlsQuicPacketBuilderTests
{
    // RFC 9001 Appendix A: "These packets use an 8-byte client-chosen Destination
    // Connection ID of 0x8394c8f03e515708." Both A.2's client keys and A.3's server
    // keys derive from it (A.1), which is why A.3 uses it even though its own
    // Destination Connection ID field is empty.
    private const string AppendixAConnectionIdHex = "8394C8F03E515708";

    // A fixed instant, because TlsQuicSentPacket.SentAt is a parameter and this class
    // has no clock of its own - see the remark on TlsQuicSentPacket.
    private static readonly DateTimeOffset SentAt = new(2026, 8, 18, 12, 0, 0, TimeSpan.Zero);

    // The hand-derived vector every non-default test below shares, so one field varies
    // at a time. Chosen against the standing rule that a field value must not collide
    // with a structural byte: no byte here is 0x00 (PADDING and the frame-type of a
    // CRYPTO frame's offset), 0x01 (PING), 0x06 (CRYPTO), or equal to any length or
    // Length-varint byte the packets below carry, so an ordering or off-by-one
    // mutation cannot land on a byte that happens to match its neighbour.
    private const string VectorDestinationConnectionIdHex = "B1B2B3B4B5B6B7B8";
    private const string VectorSourceConnectionIdHex = "C1C2C3";
    private const string VectorTokenHex = "9C5F3E7AB6";
    private const ulong VectorPacketNumber = 42;

    // RFC 9000 s17.2: "Long Packet Type (2)" is the third and fourth most significant
    // bits of byte 0, after the Header Form and Fixed bits - so Table 5's value sits at
    // 0x30 shifted left by 4. Spelled out here rather than imported from
    // TlsQuicPacketHeader so the expected side of the assertion shares nothing with the
    // code under test.
    private const int LongPacketTypeMask = 0x30;

    // byte0 is excluded (header protection masks its low bits) and so is the Length
    // varint and the packet number, which the per-test comments derive. This is
    // everything between them, straight from RFC 9000 s17.2's field order: Version(4),
    // DCID Length(1) + DCID(8), SCID Length(1) + SCID(3), Token Length(1) + Token(5).
    // 23 bytes, so the Length varint starts at offset 24.
    private const string VectorHeaderMiddleHex =
        "0000000108B1B2B3B4B5B6B7B803C1C2C3059C5F3E7AB6";

    // PING then CRYPTO, in that order and never merged or sorted. RFC 9000 s19.2 makes
    // PING the single byte 0x01; s19.6's CRYPTO is type 0x06, an Offset varint, a
    // Length varint and the data. Offset 64 is deliberately the first value s16
    // Table 4 pushes out of the 1-byte form, so it encodes as 0x4040 and a reader that
    // assumed one byte would desynchronise. 8 bytes total.
    private const string VectorPayloadHex = "01064040037E8D9A";

    [Fact]
    public void AppendixA2ClientInitialIsProducedByteForByte()
    {
        // The CRYPTO frame's own bytes are published; its DATA is bytes 4 onward,
        // after the type (0x06), the Offset varint (0x00) and the Length varint
        // (0x40f1) that RFC 9001 A.2 prints and that s19.6 defines the order of.
        var publishedCryptoFrame = QuicRfcVectors.BuildA2CryptoFrame();
        var frames = new List<TlsQuicFrame>(1 + QuicRfcVectors.A2PaddingFrameCount)
        {
            new() { RawType = 0x06, Offset = 0, Data = publishedCryptoFrame.AsMemory(4) },
        };

        // A.2'S PADDING BYTES ARE NOT PUBLISHED. The extract gives the CRYPTO frame and
        // says the payload is that frame "plus enough PADDING frames to make a
        // 1162-byte payload". So this list is RECONSTRUCTED from that sentence plus RFC
        // 9000 s19.1 (PADDING is frame type 0x00, one byte, no body) and is not a
        // transcription. It is validated only THROUGH the protected output: if the
        // count or the byte were wrong, the AEAD tag and every ciphertext byte below
        // would differ. Nothing here asserts the plaintext literally, because there is
        // no published plaintext to assert it against.
        for (var i = 0; i < QuicRfcVectors.A2PaddingFrameCount; i++)
        {
            frames.Add(new TlsQuicFrame { RawType = 0x00 });
        }

        var plan = new TlsQuicPacketPlan
        {
            Type = TlsQuicLongPacketType.Initial,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = Convert.FromHexString(AppendixAConnectionIdHex),
            SourceConnectionId = ReadOnlyMemory<byte>.Empty,
            Token = ReadOnlyMemory<byte>.Empty,
            PacketNumber = 2,
            PacketNumberEncodedLength = 4,
            LargestAcknowledged = null,
            LengthVarintWidth = TlsQuicVarintWidth.Minimal,
        };

        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, Convert.FromHexString(AppendixAConnectionIdHex));
        using var keys = secrets.DeriveClientPacketProtectionKeys(TlsQuicVersion.Version1);

        var packet = Build(keys, plan, frames, out var sent);

        Assert.Equal(
            TlsQuicPacketProtectionTests.A2FullProtectedPacketHex,
            Convert.ToHexString(packet),
            ignoreCase: true);

        // 1200 = the 22-byte header + 1162 bytes of frames + the 16-byte tag, which is
        // also the datagram size A.2 describes. Task 5 owns reaching it by padding; the
        // builder only reports what it wrote.
        Assert.Equal(1200, sent.Size);
        Assert.Equal(TlsQuicEncryptionLevel.Initial, sent.Level);
        Assert.Equal(2UL, sent.PacketNumber);
        Assert.True(sent.IsAckEliciting);
        Assert.True(sent.IsInFlight);
        Assert.Equal(SentAt, sent.SentAt);
    }

    [Fact]
    public void AppendixA3ServerInitialIsProducedByteForByte()
    {
        // A.3's plaintext IS published in full ("including an ACK frame, a CRYPTO frame,
        // and no PADDING frames"), so unlike A.2 the frames are read back out of it
        // rather than reconstructed. The two split points are the s19.3 and s19.6 field
        // layouts, not this builder's: an ACK of type 0x02 is five one-byte varints
        // (type, Largest Acknowledged 0, ACK Delay 0, ACK Range Count 0, First ACK
        // Range 0) = bytes 0-4, and the CRYPTO frame's header is type 0x06, Offset
        // varint 0x00 and Length varint 0x405a = bytes 5-8, so its data starts at 9.
        var publishedPlaintext = Convert.FromHexString(TlsQuicPacketProtectionTests.A3PlaintextHex);
        var frames = new List<TlsQuicFrame>
        {
            new() { RawType = 0x02, LargestAcknowledged = 0, AckDelay = 0, AckRangeCount = 0, FirstAckRange = 0 },
            new() { RawType = 0x06, Offset = 0, Data = publishedPlaintext.AsMemory(9) },
        };

        var plan = new TlsQuicPacketPlan
        {
            Type = TlsQuicLongPacketType.Initial,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = ReadOnlyMemory<byte>.Empty,
            SourceConnectionId = Convert.FromHexString("F067A5502A4262B5"),
            Token = ReadOnlyMemory<byte>.Empty,
            PacketNumber = 1,
            PacketNumberEncodedLength = 2,
            LargestAcknowledged = null,
            LengthVarintWidth = TlsQuicVarintWidth.Minimal,
        };

        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, Convert.FromHexString(AppendixAConnectionIdHex));
        using var keys = secrets.DeriveServerPacketProtectionKeys(TlsQuicVersion.Version1);

        var packet = Build(keys, plan, frames, out var sent);

        Assert.Equal(
            TlsQuicPacketProtectionTests.A3FullProtectedPacketHex,
            Convert.ToHexString(packet),
            ignoreCase: true);

        // 135 = the 20-byte header + 99 bytes of frames + the 16-byte tag. A.3's own
        // Length field is 0x4075 = 117 = the 2-byte packet number plus those two.
        Assert.Equal(135, sent.Size);
        Assert.Equal(1UL, sent.PacketNumber);
        Assert.True(sent.IsAckEliciting);
        Assert.True(sent.IsInFlight);
    }

    // KNOB: packet-number encoded length, at 1 and 3 - the two A.2 never shows. It
    // publishes 4 (for the value 2, a deliberately non-minimal choice); 2 is A.3's.
    //
    // Hand-derived from RFC 9000 s17.2. Byte 0 is 0xC0 (Header Form 1, Fixed Bit 1,
    // Long Packet Type 00 = Initial, Reserved 00) OR'd with the Packet Number Length
    // bits, which s17.2 defines as "one less than the length of the Packet Number
    // field in bytes" - so 0xC0, 0xC1, 0xC2, 0xC3 for 1, 2, 3, 4. The Length field is
    // the packet number length plus the 8-byte payload plus the 16-byte tag, i.e.
    // 25, 26, 27, 28 - each inside s16 Table 4's 1-byte range, so 0x19, 0x1A, 0x1B,
    // 0x1C. The packet number 42 truncates to its low bytes, big-endian, per RFC 9000
    // Appendix A.2: 2A, 002A, 00002A, 0000002A.
    //
    // pn_offset is 25 on every row and does NOT move with the packet number length:
    // 1 + 4 + 1 + 8 + 1 + 3 + 1 + 5 + 1, straight down the s17.2 field list. That is
    // the invariant a packet-number-length mutation in the offset arithmetic breaks.
    [Theory]
    [InlineData(1, "C0", "19", "2A")]
    [InlineData(2, "C1", "1A", "002A")]
    [InlineData(3, "C2", "1B", "00002A")]
    [InlineData(4, "C3", "1C", "0000002A")]
    public void PacketNumberEncodedLengthIsWrittenAsTheSpecAsksAtEveryLegalWidth(
        int encodedLength, string firstByteHex, string lengthVarintHex, string packetNumberHex)
    {
        var plan = VectorPlan() with { PacketNumberEncodedLength = encodedLength };
        using var keys = VectorKeys();

        var packet = Build(keys, plan, VectorFrames(), out var sent);

        const int packetNumberOffset = 25;

        // The clear-text window: everything between byte 0 and the packet number is
        // outside RFC 9001 s5.4's mask, so this is asserted with no decoding at all.
        Assert.Equal(
            VectorHeaderMiddleHex + lengthVarintHex,
            Convert.ToHexString(packet[1..packetNumberOffset]));

        Assert.Equal(
            firstByteHex + VectorHeaderMiddleHex + lengthVarintHex + packetNumberHex,
            Convert.ToHexString(Unprotect(keys, packet, packetNumberOffset, encodedLength)));

        Assert.Equal(packetNumberOffset + encodedLength + 8 + 16, sent.Size);
        Assert.Equal(VectorPacketNumber, sent.PacketNumber);
    }

    // KNOB: the header Length field's varint width (A4 plan, Finding 5). RFC 9000 s16:
    // "Values do not need to be encoded on the minimum number of bytes necessary, with
    // the sole exception of the Frame Type field." A.2 gives this zero coverage - its
    // three varints 00, 40f1 and 449e are all minimal.
    //
    // Hand-derived: the VALUE is 28 on every row (4-byte packet number + 8-byte payload
    // + 16-byte tag) and only its encoding widens, per s16 Table 4's 2MSB prefix -
    // 0x1C, 0x401C, 0x8000001C, 0xC00000000000001C. pn_offset therefore moves by
    // exactly the extra bytes: 25, 26, 28, 32.
    //
    // The Token Length varint stays "05" on every row, which is what shows the width
    // reached one field rather than every varint in the header.
    [Theory]
    // The int rows are TlsQuicVarintWidth's member values - 0 Minimal, then the byte
    // counts 2, 4 and 8 - because xunit needs a public signature and the enum is
    // internal.
    [InlineData(0, "1C", 25)]
    [InlineData(2, "401C", 26)]
    [InlineData(4, "8000001C", 28)]
    [InlineData(8, "C00000000000001C", 32)]
    public void TheHeaderLengthVarintIsWrittenAtTheWidthTheSpecAsksFor(
        int width, string lengthVarintHex, int packetNumberOffset)
    {
        var plan = VectorPlan() with { LengthVarintWidth = (TlsQuicVarintWidth)width };
        using var keys = VectorKeys();

        var packet = Build(keys, plan, VectorFrames(), out var sent);

        Assert.Equal(
            VectorHeaderMiddleHex + lengthVarintHex,
            Convert.ToHexString(packet[1..packetNumberOffset]));

        Assert.Equal(
            "C3" + VectorHeaderMiddleHex + lengthVarintHex + "0000002A",
            Convert.ToHexString(Unprotect(keys, packet, packetNumberOffset, 4)));

        Assert.Equal(packetNumberOffset + 4 + 8 + 16, sent.Size);
    }

    // KNOB: a non-zero token with a distinctive prefix. A.2's token length is 0x00, so
    // the prefix path is never entered there - and task 4a's own mutation record shows
    // dropping the token-length term from the packet-number offset passing A.2.
    //
    // Hand-derived: RFC 9000 s17.2.2 puts Token Length then Token immediately after the
    // Source Connection ID. The Token Length varint is present either way - "05" here,
    // "00" for an empty token, both the 1-byte form of s16 Table 4 - so what shifts
    // everything after it is the five token BYTES, not six. That distinction is exactly
    // the off-by-one a packet-number offset can carry: pn_offset is 25 with this token
    // and 20 without it.
    [Fact]
    public void ANonZeroTokenIsWrittenWithItsLengthPrefixAndMovesEverythingAfterIt()
    {
        using var keys = VectorKeys();

        var withToken = Build(keys, VectorPlan(), VectorFrames(), out var sentWithToken);
        var withoutToken = Build(
            keys, VectorPlan() with { Token = ReadOnlyMemory<byte>.Empty }, VectorFrames(), out var sentWithout);

        // The token and its length prefix, at the offset s17.2.2 puts them: byte 0(1) +
        // Version(4) + DCID Length(1) + DCID(8) + SCID Length(1) + SCID(3) = 18.
        Assert.Equal("05" + VectorTokenHex, Convert.ToHexString(withToken[18..24]));

        // With no token the Token Length varint is "00" and the Length varint follows
        // it directly, so the six bytes above collapse to one.
        Assert.Equal("001C", Convert.ToHexString(withoutToken[18..20]));
        Assert.Equal(sentWithToken.Size - 5, sentWithout.Size);

        // And the packet number moved with them, which is the thing A.2 cannot show.
        Assert.Equal(
            "C3" + VectorHeaderMiddleHex + "1C0000002A",
            Convert.ToHexString(Unprotect(keys, withToken, 25, 4)));
        Assert.Equal(
            "C300000001" + "08B1B2B3B4B5B6B7B803C1C2C300" + "1C0000002A",
            Convert.ToHexString(Unprotect(keys, withoutToken, 20, 4)));
    }

    // KNOB: CRYPTO splitting and frame order within a packet. A.2 carries one CRYPTO
    // frame at offset 0, so it pins order trivially and split not at all.
    //
    // Hand-derived from RFC 9000 s19.6: type 0x06, Offset varint, Length varint, data.
    // The two frames are given DELIBERATELY OUT OF STREAM ORDER - offset 3 before
    // offset 0 - because a builder that sorted or merged them would produce a payload
    // that is still perfectly legal QUIC, and only the byte order distinguishes it.
    // 06 03 02 AABB is the offset-3 frame; 06 00 03 F1F2F3 is the offset-0 one.
    [Fact]
    public void CryptoFramesAreWrittenAtTheOffsetsAndInTheOrderGivenWithNoMerging()
    {
        var frames = new[]
        {
            new TlsQuicFrame { RawType = 0x06, Offset = 3, Data = Convert.FromHexString("AABB") },
            new TlsQuicFrame { RawType = 0x06, Offset = 0, Data = Convert.FromHexString("F1F2F3") },
        };
        using var keys = VectorKeys();

        var packet = Build(keys, VectorPlan(), frames, out var sent);

        // Length = 4 (packet number) + 11 (payload) + 16 (tag) = 31 = 0x1F.
        Assert.Equal(VectorHeaderMiddleHex + "1F", Convert.ToHexString(packet[1..25]));
        Assert.Equal(
            "060302AABB060003F1F2F3",
            Convert.ToHexString(Open(keys, packet, 25, 4, VectorPacketNumber)!));
        Assert.Equal(25 + 4 + 11 + 16, sent.Size);
    }

    // RFC 9000 s12.4 Table 3's "Spec" column, exercised at the three shapes that
    // separate its two markings. A.2 and A.3 above cover the ordinary case - a packet
    // carrying CRYPTO, which is marked neither N nor C.
    [Fact]
    public void PaddingOnlyPacketsAreNotAckElicitingButAreStillInFlight()
    {
        // s13.2.7, verbatim: "Packets containing PADDING frames are considered to be in
        // flight for congestion control purposes". PADDING carries N and P in Table 3,
        // never C, which is the same fact in table form.
        var frames = new TlsQuicFrame[8];
        using var keys = VectorKeys();

        Build(keys, VectorPlan(), frames, out var sent);

        Assert.False(sent.IsAckEliciting);
        Assert.True(sent.IsInFlight);
    }

    [Fact]
    public void AckOnlyPacketsAreNeitherAckElicitingNorInFlight()
    {
        // ACK is the one row Table 3 marks NC, so it is the only frame that can make a
        // packet both.
        var frames = new[]
        {
            new TlsQuicFrame { RawType = 0x02, LargestAcknowledged = 7, AckDelay = 0, AckRangeCount = 0, FirstAckRange = 0 },
        };
        using var keys = VectorKeys();

        Build(keys, VectorPlan(), frames, out var sent);

        Assert.False(sent.IsAckEliciting);
        Assert.False(sent.IsInFlight);
    }

    [Fact]
    public void ConnectionCloseOnlyPacketsAreNeitherAckElicitingNorInFlight()
    {
        // RFC 9002 s2, "In-flight", verbatim: "Packets are considered in flight when they
        // are ack-eliciting or contain a PADDING frame, and they have been sent but are
        // not acknowledged, declared lost, or discarded along with old keys." A packet of
        // nothing but CONNECTION_CLOSE is neither of those two things, so it is NOT in
        // flight. Type 0x1c is the one s12.4 permits in an Initial packet.
        //
        // THIS ASSERTION USED TO READ True, AND IT ENCODED A BUG. The reasoning it carried
        // was that RFC 9000 s12.4 Table 3 prints C - "do not count toward bytes in flight"
        // - against ACK alone, so anything without C must be in flight. That inverts the
        // table: C marks frames that CANNOT put a packet in flight, it does not promise
        // that every unmarked frame CAN. RFC 9002 s2 is the positive definition, and it
        // names exactly two ways in - ack-eliciting, or PADDING. CONNECTION_CLOSE is
        // neither; Table 3's own N against it is what rules out the first.
        var frames = new[]
        {
            new TlsQuicFrame { RawType = 0x1c, ErrorCode = 0, TriggerFrameType = 0, ReasonPhrase = ReadOnlyMemory<byte>.Empty },
        };
        using var keys = VectorKeys();

        Build(keys, VectorPlan(), frames, out var sent);

        Assert.False(sent.IsAckEliciting);
        Assert.False(sent.IsInFlight);
    }

    [Fact]
    public void AnAckPaddedOutIsInFlightBecauseOfThePaddingAlone()
    {
        // The trap in RFC 9002 s2's "ack-eliciting OR contains PADDING": neither frame in
        // this packet is ack-eliciting - ACK and PADDING are both on IsAckEliciting's
        // exclusion list - yet the packet IS in flight, because s13.2.7 says so in words:
        // "Packets containing PADDING frames are considered to be in flight for congestion
        // control purposes".
        //
        // Without this case, writing IsInFlight as a bare alias for IsAckEliciting leaves
        // the whole suite green: PaddingOnlyPacketsAreNotAckElicitingButAreStillInFlight
        // is the only other test that separates the two, and it would fail on the PADDING
        // half while this one is the pair that pins the disjunction itself.
        var frames = new TlsQuicFrame[4];
        frames[0] = new TlsQuicFrame { RawType = 0x02, LargestAcknowledged = 7, AckDelay = 0, AckRangeCount = 0, FirstAckRange = 0 };
        using var keys = VectorKeys();

        Build(keys, VectorPlan(), frames, out var sent);

        Assert.False(sent.IsAckEliciting);
        Assert.True(sent.IsInFlight);
    }

    [Fact]
    public void PingOnlyPacketsAreAckElicitingAndInFlight()
    {
        // PING's Spec cell in Table 3 is EMPTY - neither N nor C - so a packet of
        // nothing but PING is both ack-eliciting and in flight. THIS IS THE ROW THE
        // THREE TESTS ABOVE CANNOT REACH: between them they cover exactly the frames
        // marked N, and every other packet in this class carries CRYPTO, which sets both
        // flags for its own reasons. Without this case, adding PING to IsAckEliciting's
        // exclusion set leaves the whole suite green.
        //
        // RFC 9000 s19.2 says the same thing in words: "The receiver of a PING frame
        // simply needs to acknowledge the packet containing this frame." A PING-only
        // packet is also the shape A3 will send as a PTO probe, so a probe wrongly
        // marked non-ack-eliciting would be a probe that never elicits the
        // acknowledgement it exists to provoke.
        var frames = new[] { new TlsQuicFrame { RawType = 0x01 } };
        using var keys = VectorKeys();

        Build(keys, VectorPlan(), frames, out var sent);

        Assert.True(sent.IsAckEliciting);
        Assert.True(sent.IsInFlight);
    }

    [Fact]
    public void CryptoOnlyPacketsAreAckElicitingAndInFlight()
    {
        // The second empty-Spec row, and the one that was relying on an accident. Before
        // this test existed, excluding CRYPTO from IsAckEliciting was caught by A.2 and
        // A.3 - and excluding it from IsInFlight was caught by A.3 ALONE, because A.2's
        // packet is CRYPTO plus PADDING and PADDING keeps the flag true on its own. A
        // byte-exactness test is a fragile witness for a flag: it catches this only
        // because of what A.3's payload happens to contain, and it would stop catching it
        // the moment that composition changed, silently.
        //
        // So the flag now has a witness that is about the flag. Table 3 leaves CRYPTO's
        // Spec cell empty exactly as it leaves PING's, which is why the two sit together.
        var frames = new[]
        {
            new TlsQuicFrame { RawType = 0x06, Offset = 0, Data = Convert.FromHexString("7E8D9A") },
        };
        using var keys = VectorKeys();

        Build(keys, VectorPlan(), frames, out var sent);

        Assert.True(sent.IsAckEliciting);
        Assert.True(sent.IsInFlight);
    }

    [Fact]
    public void ANullFrameListIsRejected()
    {
        using var keys = VectorKeys();
        var plan = VectorPlan();
        var buffer = new byte[512];

        Assert.Throws<ArgumentNullException>(() => TlsQuicPacketBuilder.Build(
            plan,
            null!,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            SentAt,
            buffer));
    }

    [Fact]
    public void BuildingAPacketWithNoFramesIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(() => BuildOrThrow(VectorPlan(), []));

        Assert.Equal("frames", error.ParamName);
        Assert.Contains("at least one frame", error.Message);
    }

    [Fact]
    public void BuildingARetryPacketIsRejected()
    {
        var plan = VectorPlan() with { Type = TlsQuicLongPacketType.Retry };

        var error = Assert.Throws<ArgumentException>(() => BuildOrThrow(plan, VectorFrames()));

        Assert.Equal("plan", error.ParamName);
        Assert.Contains("Retry", error.Message);
    }

    [Fact]
    public void ALongPacketTypeOutsideTable5IsRejected()
    {
        // The second reachable path through the same mapping, and a different exception
        // type so it cannot stand in for the Retry case above or vice versa. Subsystem B
        // populates these values, so a cast-in number is a caller input like any other.
        var plan = VectorPlan() with { Type = (TlsQuicLongPacketType)7 };

        var error = Assert.Throws<ArgumentOutOfRangeException>(() => BuildOrThrow(plan, VectorFrames()));

        Assert.Equal("plan", error.ParamName);
    }

    [Fact]
    public void EachLongHeaderTypeIsStampedIntoByteZeroWithTable5sValue()
    {
        // RFC 9000 s17.2, Table 5: Long Header Packet Types, quoted from
        // docs/superpowers/specs/reference-captures/
        // rfc9000-packet-formats-and-pn-pseudocode.txt:
        //
        //     +======+===========+================+
        //     | Type | Name      | Section        |
        //     +======+===========+================+
        //     | 0x00 | Initial   | Section 17.2.2 |
        //     | 0x01 | 0-RTT     | Section 17.2.3 |
        //     | 0x02 | Handshake | Section 17.2.4 |
        //     | 0x03 | Retry     | Section 17.2.5 |
        //     +------+-----------+----------------+
        //
        // WHY THIS ASSERTS A BYTE AND NOT AN ENUM, AND WHY IT IS HERE AND NOT IN A
        // ROUND-TRIP TEST. TlsQuicLongPacketType's four numbers are the only place
        // these values live, and every other use of them is one half of an INVERSE
        // PAIR: TlsQuicPacketBuilder.LevelOf maps type -> encryption level and
        // TlsQuicPacketReceiver.LevelOf maps it back through the same table, and
        // TlsQuicPacketHeaderTests.RoundTripsEachLongHeaderType writes byte 0 and reads
        // it back with the same shift. Swapping ZeroRtt = 0x01 and Handshake = 0x02 in
        // the enum therefore cancels EXACTLY and leaves the whole suite green - and RFC
        // 9001 Appendix A publishes no Handshake packet, so leg 1's byte-for-byte
        // vectors cannot reach it either. On the wire the swap is fatal: every
        // Handshake packet would go out stamped 0-RTT. So the value has to be pinned
        // against the table, on a packet that was actually built, by a test that never
        // mentions the enum on the expected side.
        //
        // The type bits survive header protection unmasked. RFC 9001 s5.4.1 masks only
        // "packet[0] ^= mask[0] & 0x0f" for a long header, and 0x30 sits above that
        // nibble - so reading them straight off the protected packet is correct, and
        // this assertion pins that too.
        using var keys = VectorKeys();

        // Initial is the only one of the three the builder can produce that has a Token
        // field (s17.2.2), so the other two drop it - ATokenOnANonInitialPacketIsRejected
        // is the guard that makes that necessary. 0-RTT takes PING rather than the
        // shared vector frames because s12.4 Table 3 forbids CRYPTO in a 0-RTT packet.
        TlsQuicFrame[] pingOnly = [new() { RawType = 0x01 }];
        var initial = Build(keys, VectorPlan(), VectorFrames(), out _);
        var zeroRtt = Build(
            keys, VectorPlan() with { Type = TlsQuicLongPacketType.ZeroRtt, Token = default }, pingOnly, out _);
        var handshake = Build(
            keys,
            VectorPlan() with { Type = TlsQuicLongPacketType.Handshake, Token = default },
            VectorFrames(),
            out _);

        Assert.Equal(0x00, initial[0] & LongPacketTypeMask);
        Assert.Equal(0x01 << 4, zeroRtt[0] & LongPacketTypeMask);
        Assert.Equal(0x02 << 4, handshake[0] & LongPacketTypeMask);

        // Retry has no builder path at all - s17.2.5 gives it no packet number and no
        // packet protection, so BuildingARetryPacketIsRejected above turns it away - and
        // TlsQuicPacketHeader.WriteLongHeader is the only encoder in the tree that ever
        // writes its byte 0. Same table, same mask, and nothing to unprotect.
        var retry = new byte[128];
        TlsQuicPacketHeader.WriteLongHeader(
            retry,
            new TlsQuicLongHeader
            {
                Type = TlsQuicLongPacketType.Retry,
                Version = (uint)TlsQuicVersion.Version1,
                DestinationConnectionId = Convert.FromHexString(VectorDestinationConnectionIdHex),
                SourceConnectionId = Convert.FromHexString(VectorSourceConnectionIdHex),
                Token = Convert.FromHexString(VectorTokenHex),

                // s17.2.5: "Retry Integrity Tag: ... a 128-bit field". Its value is task
                // 9b's; only its length is load-bearing here, because WriteLongHeader
                // refuses to write a Retry packet without one.
                RetryIntegrityTag = new byte[16],
            },
            out _);

        Assert.Equal(0x03 << 4, retry[0] & LongPacketTypeMask);
    }

    [Fact]
    public void AFrameTable3ForbidsInThisPacketTypeIsRejected()
    {
        // RFC 9000 s12.4 Table 3 gives STREAM the Pkts cell "__01", so it may appear in
        // 0-RTT and 1-RTT packets and never in an Initial one.
        var frames = new[]
        {
            new TlsQuicFrame { RawType = 0x08, StreamId = 4, Offset = 0, Data = ReadOnlyMemory<byte>.Empty },
        };

        var error = Assert.Throws<ArgumentException>(() => BuildOrThrow(VectorPlan(), frames));

        Assert.Equal("frames", error.ParamName);
        Assert.Contains("Table 3", error.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    public void APacketNumberEncodedLengthOutsideOneToFourIsRejected(int encodedLength)
    {
        var plan = VectorPlan() with { PacketNumberEncodedLength = encodedLength };

        var error = Assert.Throws<ArgumentOutOfRangeException>(() => BuildOrThrow(plan, VectorFrames()));

        Assert.Equal("plan", error.ParamName);
        Assert.Contains("1 to 4 bytes", error.Message);
    }

    [Fact]
    public void APacketNumberEncodedLengthBelowTheAppendixATwoFloorIsRejected()
    {
        // RFC 9000 Appendix A.2's rule, via TlsQuicPacketNumber.EncodedLength: with no
        // acknowledgement yet, packet number 1000 leaves 1001 numbers unacknowledged
        // and needs two bytes. One byte would be decoded by the peer as some other
        // packet number entirely, with nothing on the wire to signal it.
        var plan = VectorPlan() with { PacketNumber = 1000, PacketNumberEncodedLength = 1 };

        var error = Assert.Throws<ArgumentOutOfRangeException>(() => BuildOrThrow(plan, VectorFrames()));

        Assert.Equal("plan", error.ParamName);
        Assert.Contains("needs at least 2 bytes", error.Message);
    }

    [Fact]
    public void APacketNumberBelowTheLargestAcknowledgedIsRejected()
    {
        // The guard is TlsQuicPacketNumber.EncodedLength's own and is deliberately not
        // restated in the builder, so the ParamName is that method's. Witnessed here
        // because the values reaching it are the plan's, which makes it reachable.
        var plan = VectorPlan() with { PacketNumber = 5, LargestAcknowledged = 9 };

        var error = Assert.Throws<ArgumentOutOfRangeException>(() => BuildOrThrow(plan, VectorFrames()));

        Assert.Equal("fullPn", error.ParamName);
    }

    [Fact]
    public void ATokenOnANonInitialPacketIsRejected()
    {
        // RFC 9000 s17.2.4 gives a Handshake packet no Token field, and WriteLongHeader
        // writes one only for an Initial packet - so without this guard the token would
        // vanish with no signal at all.
        var plan = VectorPlan() with { Type = TlsQuicLongPacketType.Handshake };

        var error = Assert.Throws<ArgumentException>(() => BuildOrThrow(plan, VectorFrames()));

        Assert.Equal("plan", error.ParamName);
        Assert.Contains("Token field", error.Message);
    }

    [Fact]
    public void ADestinationTooSmallForThePayloadAndTagIsRejected()
    {
        // 29 bytes is exactly the header this vector writes, so WriteLongHeader's own
        // bound passes and only the builder's payload-and-tag bound can catch it. That
        // separation is the point: a destination one byte short of the header throws
        // from the writer with ParamName "destination" too, and this case proves the
        // builder's own check is doing work rather than shadowing that one.
        using var keys = VectorKeys();
        var plan = VectorPlan();
        var frames = VectorFrames();
        var buffer = new byte[29];

        var error = Assert.Throws<ArgumentException>(() => TlsQuicPacketBuilder.Build(
            plan,
            frames,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            SentAt,
            buffer));

        Assert.Equal("destination", error.ParamName);
        Assert.Contains("Packet needs 53 bytes", error.Message);
    }

    [Fact]
    public void APayloadTooShortForTheSectionFiveFourTwoSampleIsRejected()
    {
        // RFC 9001 s5.4.2: a 16-byte sample taken from pn_offset + 4 "results in needing
        // at least 3 bytes of frames in the unprotected payload if the packet number is
        // encoded on a single byte". Two PING frames is two bytes, one short of that,
        // and a builder that ignored TryApply's false would emit a packet whose packet
        // number was never masked.
        var frames = new[]
        {
            new TlsQuicFrame { RawType = 0x01 },
            new TlsQuicFrame { RawType = 0x01 },
        };
        var plan = VectorPlan() with { PacketNumber = 0, PacketNumberEncodedLength = 1 };

        var error = Assert.Throws<ArgumentException>(() => BuildOrThrow(plan, frames));

        Assert.Equal("frames", error.ParamName);
        Assert.Contains("s5.4.2", error.Message);
    }

    // RFC 9001 s5.3 builds the AEAD nonce from "the reconstructed QUIC packet number",
    // the full 62-bit value - not the truncated form that travels on the wire. EVERY
    // PUBLISHED VECTOR HIDES THE DIFFERENCE: A.2's packet number is 2 written in four
    // bytes and A.3's is 1 written in two, so truncated and full are the same number in
    // both, and so is 42 in the vector above. This is the case that separates them.
    //
    // Hand-derived: 300 truncated to one byte is 300 - 256 = 0x2C, and RFC 9000 Appendix
    // A.2 allows one byte here because only one packet number is unacknowledged. The
    // Length field is 1 + 8 + 16 = 25 = 0x19 and byte 0 is 0xC0 for a 1-byte packet
    // number.
    // THE OTHER SIDE OF THE BOUND, AND THE NUMBER THE PROBE BUILDERS PAD TO. s5.4.2's sample
    // starts at pn_offset + 4, so the frames have to make up whatever the packet number does
    // not: "at least 3 bytes of frames ... if the packet number is encoded on a single byte, or
    // 2 bytes of frames for a 2-byte packet number encoding". The row above proves 2 bytes is
    // refused at a 1-byte packet number; this proves 3 is enough, which is what
    // TlsQuicConnection.PadForHeaderProtectionSample computes as 4 - packetNumberLength.
    //
    // WHY IT MATTERS THAT THIS IS PINNED. Both probe builders send a lone PING and both MEASURE
    // the datagram by building it once before padding it. An off-by-one in that pad would put
    // the throw back exactly where it was, and only for profiles with a short packet number.
    [Theory]
    [InlineData(1, 3)]
    [InlineData(2, 2)]
    [InlineData(3, 1)]
    [InlineData(4, 1)]
    public void TheSectionFiveFourTwoMinimumIsFourLessThePacketNumberLength(
        int packetNumberLength, int frameCount)
    {
        var frames = Enumerable
            .Range(0, frameCount)
            .Select(_ => new TlsQuicFrame { RawType = 0x01 })
            .ToArray();
        var plan = VectorPlan() with
        {
            PacketNumber = 0,
            PacketNumberEncodedLength = packetNumberLength,
        };

        BuildOrThrow(plan, frames);
    }

    [Fact]
    public void TheAeadNonceUsesTheFullPacketNumberNotTheTruncatedWireForm()
    {
        var plan = VectorPlan() with
        {
            PacketNumber = 300,
            LargestAcknowledged = 299,
            PacketNumberEncodedLength = 1,
        };
        using var keys = VectorKeys();

        var packet = Build(keys, plan, VectorFrames(), out _);

        Assert.Equal(
            "C0" + VectorHeaderMiddleHex + "19" + "2C",
            Convert.ToHexString(Unprotect(keys, packet, 25, 1)));

        // The discriminator, and the reason this is not a round trip: the packet opens
        // under 300 and does NOT open under 44. A builder that seeded the nonce from the
        // wire bytes would give exactly the opposite pair of answers.
        Assert.Equal(VectorPayloadHex, Convert.ToHexString(Open(keys, packet, 25, 1, 300)!));
        Assert.Null(Open(keys, packet, 25, 1, 44));
    }

    // ================================================================================
    // A4 TASK 14b - THE SHORT HEADER (RFC 9000 s17.3.1, the "1-RTT Packet").
    //
    // HOW STRONG THIS SECTION'S EVIDENCE IS, STATED BEFORE ANY OF IT. There is NO
    // published 1-RTT packet anywhere in RFC 9001 Appendix A. A.2 and A.3 are Initial
    // packets; A.5 is a ChaCha20_Poly1305 HEADER-PROTECTION sample - it publishes a
    // masked byte 0 and a masked packet number and no payload, and it is already spent
    // in TlsQuicHeaderProtectionTests. So the long-header path's leg 1, two byte-exact
    // IETF vectors, HAS NO COUNTERPART HERE and nothing below should be read as if it
    // did. What this section has instead is three weaker legs, and they are weaker in
    // the specific way the plan warns about:
    //
    //   1. A hand-derived header, written out from s17.3.1's field list in the comment
    //      on AShortHeaderMatchesTheSection1731FieldLayout - the same discipline the
    //      long-header hand-derived set uses, and the only leg here that is about
    //      EXPECTED BYTES rather than about a round trip.
    //   2. TlsQuicPacketReceiver opening the packet. A round trip, and seal/open and
    //      encode/decode CANCEL: a shared error in offset or nonce arithmetic makes both
    //      halves wrong identically and leaves this green. What it does buy is stated at
    //      OneRttKeys, and it is narrower than it looks.
    //   3. The nonce discriminator - the packet opens under the full packet number and
    //      does NOT open under the truncated one - which does not cancel, because the two
    //      answers are different from each other rather than merely consistent.
    //
    // THE KEY MATERIAL IS NOT ARBITRARY EITHER, for the same reason: see OneRttKeys.
    // ================================================================================

    // Five bytes, so the Destination Connection ID length is neither the long-header
    // vector's eight nor zero; RFC 9000 s17.3.1 allows 0 to 20 and pn_offset is
    // 1 + this length, so a wrong length moves every field after byte 0. No byte here is
    // 0x00 (PADDING), 0x01 (PING), 0x1e (HANDSHAKE_DONE) or 0x05 (its own length), by the
    // same rule the long-header vector above states.
    private const string ShortVectorDestinationConnectionIdHex = "A7B8C9DAEB";

    // 0x01A1B2C3. Chosen so the full number and the three-byte truncation differ - the
    // low three bytes are A1B2C3 and the fourth is 0x01 - which is what makes the nonce
    // discriminator below a real discriminator rather than a tautology. RFC 9001 A.2's
    // packet number 2 in four bytes cannot separate the two at all.
    private const ulong ShortVectorPacketNumber = 0x01A1B2C3;

    // RFC 9000 Appendix A.2's floor is "at least twice as large as the difference between
    // the packet number and the largest acknowledged". A difference of 5 needs 3 bits and
    // therefore one byte, so a three-byte encoding is a legal sender choice above the
    // floor - which is the whole point of the knob.
    private const ulong ShortVectorLargestAcknowledged = ShortVectorPacketNumber - 5;

    // THE LOOPBACK TESTS BELOW USE A DIFFERENT PACKET NUMBER, AND THAT IS A REAL
    // CONSTRAINT RATHER THAN A CONVENIENCE. RFC 9000 Appendix A.2's floor is stated
    // against "the largest acknowledged", which is a sender's model of what its PEER has
    // seen; a fresh TlsQuicPacketReceiver has seen nothing, so its A.3 DecodePacketNumber
    // resolves a truncated number against a largest-received of 0. 0x01A1B2C3 truncated to
    // three bytes decodes to 0x00A1B2C3 there - a different number, a different RFC 9001
    // s5.3 nonce, and an authentication failure. So the loopback rows use a number whose
    // three-byte form IS its full form, and the full-versus-truncated discriminator stays
    // where it can be asserted directly, in the hand-derived test above.
    private const ulong ShortLoopbackPacketNumber = 0x0A1B2C;
    private const ulong ShortLoopbackLargestAcknowledged = ShortLoopbackPacketNumber - 5;

    // HANDSHAKE_DONE (0x1e) then PING (0x01), in that order. RFC 9000 s12.4 Table 3 marks
    // HANDSHAKE_DONE's Pkts column "___1" - a 1-RTT packet and nothing else - which is
    // what makes it the discriminator for the encryption level this path builds at.
    private const string ShortVectorPayloadHex = "1E01";

    [Theory]
    // Spin Bit and Key Phase, both directions of each, with the other three rows'
    // expected byte 0 derived the same way. Four rows rather than one because a bit
    // asserted in one direction only is held by a mutant that hardcodes that direction.
    [InlineData(false, false, 0x42)]
    [InlineData(false, true, 0x46)]
    [InlineData(true, false, 0x62)]
    [InlineData(true, true, 0x66)]
    public void AShortHeaderMatchesTheSection1731FieldLayout(bool spinBit, bool keyPhase, int expectedFirstByte)
    {
        // RFC 9000 s17.3.1, Figure 19, verbatim from
        // rfc9000-packet-formats-and-pn-pseudocode.txt lines 589-599:
        //
        //   1-RTT Packet {
        //     Header Form (1) = 0,
        //     Fixed Bit (1) = 1,
        //     Spin Bit (1),
        //     Reserved Bits (2),
        //     Key Phase (1),
        //     Packet Number Length (2),
        //     Destination Connection ID (0..160),
        //     Packet Number (8..32),
        //     Packet Payload (8..),
        //   }
        //
        // and the field descriptions that follow it give each mask in words: Header Form
        // "the most significant bit (0x80) ... set to 0 for the short header", Fixed Bit
        // "the next bit (0x40) ... set to 1", Spin Bit "the third most significant bit
        // (0x20)", Reserved Bits "those with a mask of 0x18 ... The value included prior
        // to protection MUST be set to 0", Key Phase "the next bit (0x04)", Packet Number
        // Length "the least significant two bits (those with a mask of 0x03) ... encoded
        // as an unsigned two-bit integer that is one less than the length of the Packet
        // Number field in bytes".
        //
        // BYTE 0, THEREFORE, AT A THREE-BYTE PACKET NUMBER - which is NOT the default;
        // TlsQuicConnectionSpec.PacketNumberEncodedLength defaults to 4 and RFC 9001 A.2
        // writes 4:
        //
        //   0x00 (Header Form) | 0x40 (Fixed) | spin 0x20 | 0x00 (Reserved)
        //     | keyPhase 0x04 | (3 - 1) = 0x02
        //
        //   spin 0, phase 0 -> 0x40 | 0x02                      = 0x42
        //   spin 0, phase 1 -> 0x40 | 0x04 | 0x02               = 0x46
        //   spin 1, phase 0 -> 0x40 | 0x20 | 0x02               = 0x62
        //   spin 1, phase 1 -> 0x40 | 0x20 | 0x04 | 0x02        = 0x66
        //
        // THE REST OF THE PACKET, at a five-byte Destination Connection ID:
        //
        //   offset 0       byte 0, above
        //   offset 1..5    Destination Connection ID, 5 bytes, A7B8C9DAEB
        //   offset 6..8    Packet Number, 3 bytes. pn_offset = 1 + 5 = 6, and RFC 9001
        //                  s5.4.2's pseudocode says the same thing in as many words:
        //                  "pn_offset = 1 + len(connection_id)". The bytes are the least
        //                  significant three of 0x01A1B2C3 in network order: A1 B2 C3.
        //   offset 9..10   the sealed payload, two plaintext bytes long
        //   offset 11..26  RFC 9001 s5.3's 16-byte authentication tag
        //
        // 1 + 5 + 3 + 2 + 16 = 27 bytes, and NO Length field appears anywhere: s17.3.1's
        // field list does not have one, which is the difference from s17.2 that s12.2
        // turns into "cannot be followed by other packets in the same UDP datagram".
        //
        // NOT ONE OF THESE NUMBERS CAME OFF A RUN OF THE BUILDER. They are the field list
        // above, added up.
        var plan = ShortVectorPlan() with { SpinBit = spinBit, KeyPhase = keyPhase };
        using var keys = OneRttKeys();

        var packet = Build(keys, plan, ShortVectorFrames(), out var sent);

        Assert.Equal(27, sent.Size);
        Assert.Equal(27, packet.Length);
        Assert.Equal(TlsQuicEncryptionLevel.Application, sent.Level);
        Assert.Equal(ShortVectorPacketNumber, sent.PacketNumber);

        // Offsets 1..5 travel IN THE CLEAR. RFC 9001 s5.4 protects byte 0 and the Packet
        // Number field and nothing else, so the Destination Connection ID is asserted
        // straight off the wire with no decoding at all - the same treatment the
        // long-header hand-derived tests give the connection IDs and the token.
        Assert.Equal(ShortVectorDestinationConnectionIdHex, Convert.ToHexString(packet[1..6]));

        // Byte 0 and the packet number need s5.4's inverse. Unprotect returns the header
        // through the packet number, which s5.3 makes the AEAD's associated data.
        var header = Unprotect(keys, packet, 6, 3);
        Assert.Equal(9, header.Length);
        Assert.Equal(expectedFirstByte, header[0]);
        Assert.Equal("A1B2C3", Convert.ToHexString(header[6..9]));

        // THE DISCRIMINATOR, and the one leg of this task that does not cancel: the packet
        // opens under the FULL number 0x01A1B2C3 and does not open under the truncated
        // 0x00A1B2C3 the wire carries. RFC 9001 s5.3 builds the nonce from "the 62 bits of
        // the reconstructed QUIC packet number", not from the wire bytes.
        Assert.Equal(
            ShortVectorPayloadHex,
            Convert.ToHexString(Open(keys, packet, 6, 3, ShortVectorPacketNumber)!));
        Assert.Null(Open(keys, packet, 6, 3, 0xA1B2C3));
    }

    [Fact]
    public void AShortHeaderPacketIsBuiltAtTheApplicationLevelAndCarriesHandshakeDone()
    {
        // RFC 9001 s4.1.1 names the 1-RTT keys against "1-RTT" packets and RFC 9000
        // s17.3.1 titles the short header "1-RTT Packet", so a plan with no long packet
        // type is an Application-level packet. That mapping is not cosmetic: it selects
        // which column of RFC 9000 s12.4 Table 3 the send-path legality gate checks every
        // frame against, and it becomes TlsQuicSentPacket.Level, which s12.3 makes the
        // packet number space an ACK is interpreted in.
        //
        // HANDSHAKE_DONE IS THE DISCRIMINATOR. Table 3's Pkts column reads "___1" for it -
        // 1-RTT and nothing else - so this frame list is legal at exactly one level and is
        // rejected at every other. The second half of this test is the same list under a
        // Handshake plan, which is what makes the first half evidence about the LEVEL
        // rather than merely evidence that Build returned.
        var plan = ShortVectorPlan();
        using var keys = OneRttKeys();

        Build(keys, plan, ShortVectorFrames(), out var sent);

        Assert.Equal(TlsQuicEncryptionLevel.Application, sent.Level);
        Assert.True(sent.IsAckEliciting);
        Assert.True(sent.IsInFlight);

        var handshakePlan = VectorPlan() with { Type = TlsQuicLongPacketType.Handshake, Token = default };
        var rejected = Assert.Throws<ArgumentException>(
            () => BuildOrThrow(handshakePlan, ShortVectorFrames()));
        Assert.Equal("frames", rejected.ParamName);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AShortHeaderPacketIsOpenedByThePacketReceiverAtTheInstalledKeyPhase(bool keyPhase)
    {
        // THE DONE-WHEN OF TASK 14b, and what it is worth is set out at OneRttKeys: the
        // receiver is handed the key bytes and NOTHING ELSE the builder computed. It
        // re-derives pn_offset from the connection ID length it was constructed with,
        // reads the packet number length out of byte 0 after removing header protection
        // itself, and reconstructs the packet number with its own decoder.
        //
        // BOTH PHASES, because RFC 9000 s17.3.1's Key Phase bit is written from the plan
        // and a builder that hardcoded either value would be held by a single-row test.
        // TlsQuicPacketReceiver discards a packet whose Key Phase bit disagrees with the
        // phase its keys were installed at, so "the bit written matches the installed
        // phase" is exactly the question this asks.
        var connectionId = Convert.FromHexString(ShortVectorDestinationConnectionIdHex);
        using var keys = OneRttKeys();
        var packet = Build(keys, ShortLoopbackPlan() with { KeyPhase = keyPhase }, ShortVectorFrames(), out var sent);

        using var receiver = new TlsQuicPacketReceiver((uint)TlsQuicVersion.Version1, connectionId.Length);
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.Application,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            keyPhase);

        var seen = new List<TlsQuicFrameType>();
        var levels = new List<TlsQuicEncryptionLevel>();
        var numbers = new List<ulong>();
        var result = receiver.Receive(
            packet,
            (in TlsQuicFrame frame, in TlsQuicReceivedPacket received) =>
            {
                seen.Add(frame.Type);
                levels.Add(received.Level);
                numbers.Add(received.PacketNumber);
            });

        Assert.Equal(1, result.Processed);
        Assert.Equal(0, result.Discarded);
        Assert.Null(result.CloseError);
        Assert.Equal([TlsQuicFrameType.HandshakeDone, TlsQuicFrameType.Ping], seen);
        Assert.All(levels, level => Assert.Equal(TlsQuicEncryptionLevel.Application, level));
        Assert.All(numbers, number => Assert.Equal(ShortLoopbackPacketNumber, number));
        Assert.Equal(ShortLoopbackPacketNumber, sent.PacketNumber);
    }

    [Theory]
    // Both directions, because the comparison is reachable by two paths and one witness
    // pins only whichever the test happened to take.
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void AShortHeaderPacketBuiltAtTheOtherKeyPhaseIsDiscarded(bool built, bool installed)
    {
        // The negative half of the pair above, and the reason that one is about the KEY
        // PHASE BIT rather than merely about decryption succeeding. A builder that wrote a
        // constant Key Phase bit would still pass the positive test on one of its two
        // rows; it fails here on the row where the constant disagrees with the install.
        //
        // THIS TEST ASSERTED KEY_UPDATE_ERROR UNTIL RFC 9001 s6 WAS IMPLEMENTED. A flipped
        // Key Phase bit used to be a connection error because this library could not follow
        // a key update at all; it is now the announcement of one, and the receiver answers
        // it by trying the NEXT generation of read keys. No next generation is armed here -
        // this receiver was handed one set of keys directly - so s5.5 applies instead: "a
        // packet that appears to trigger a key update but cannot be unprotected successfully
        // MUST be discarded".
        //
        // THE BIT IS STILL WHAT THIS TEST IS ABOUT. The packet authenticates under the
        // installed keys, so a builder writing a constant phase would be indistinguishable
        // from one writing the right phase on the matching row and would still land in the
        // discard on the other.
        var connectionId = Convert.FromHexString(ShortVectorDestinationConnectionIdHex);
        using var keys = OneRttKeys();
        var packet = Build(keys, ShortLoopbackPlan() with { KeyPhase = built }, ShortVectorFrames(), out _);

        using var receiver = new TlsQuicPacketReceiver((uint)TlsQuicVersion.Version1, connectionId.Length);
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.Application,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            installed);

        var seen = 0;
        var result = receiver.Receive(packet, (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => seen++);

        Assert.Equal(0, result.Processed);
        Assert.Equal(0, seen);
        Assert.Equal(1, result.Discarded);

        // NOT A CLOSE, and that is the change. s5.5's discard leaves the connection alive so
        // that a forged Key Phase bit cannot kill it - the same reasoning s17.3.1 gives for
        // judging the reserved bits after the AEAD rather than before it.
        Assert.Null(result.CloseError);
    }

    [Fact]
    public void ShortHeaderProtectionReachesTheFifthBitOfByteZeroWhichALongHeaderMaskCannot()
    {
        // RFC 9001 s5.4, the preamble before s5.4.1's pseudocode: "The four least
        // significant bits of the first byte are protected for packets with long headers;
        // the five least significant bits of the first byte are protected for packets with
        // short headers."
        //
        // FOUR VERSUS FIVE IS EXACTLY ONE BIT, 0x10 - the high half of RFC 9000 s17.3.1's
        // Reserved Bits (0x18). A long header's 0x0f covers its own Reserved Bits (0x0c)
        // and Packet Number Length (0x03) and stops; a short header's 0x1f reaches one bit
        // further up because s17.3.1 spends byte 0 differently: the Spin Bit takes 0x20,
        // the Reserved Bits slide down to 0x18 and the Key Phase takes 0x04.
        //
        // WHY THIS TEST IS SHAPED THE WAY IT IS, AND NOT AS A ROUND TRIP. Applying and
        // removing protection both select the mask through the same
        // TlsQuicHeaderProtection.ProtectionMaskFor, so a 0x1f narrowed to 0x0f is
        // INVISIBLE to any build-then-unprotect assertion - the two halves cancel exactly.
        // The observable difference is on the wire: the Reserved Bits are written as 0
        // ("The value included prior to protection MUST be set to 0"), so under a four-bit
        // mask bit 0x10 of the PROTECTED byte 0 can never be anything but 0, whatever the
        // sample. Under the five-bit mask it is 1 whenever the mask byte's own bit 0x10 is,
        // which is half of all samples.
        //
        // THIS IS A SECOND WITNESS, NOT THE ONLY ONE, and saying so is the point.
        // TlsQuicHeaderProtectionTests.LongHeaderMasksLowFourBitsShortHeaderMasksLowFiveBits
        // already pins the two mask values directly and also fails when 0x1f is narrowed to
        // 0x0f. What this adds is that a packet THIS BUILDER produced gets the short-header
        // mask - which it only does because WriteShortHeader leaves the Header Form bit
        // clear, and which the whole hand-derived layout set above cannot see, staying green
        // under the narrowed mask because apply and remove cancel.
        //
        // Eight packet numbers, therefore, and eight independent AES samples: the claim is
        // that at least one protected byte 0 has 0x10 set, which is derivable from the mask
        // width alone and is false for every possible sample under 0x0f. The unprotected
        // side is asserted too, because the claim only means anything if the bit really was
        // written as 0.
        using var keys = OneRttKeys();
        var reachedTheFifthBit = false;

        for (var index = 0; index < 8; index++)
        {
            var plan = ShortVectorPlan() with
            {
                PacketNumber = ShortVectorPacketNumber + (ulong)index,
                LargestAcknowledged = ShortVectorLargestAcknowledged,
            };
            var packet = Build(keys, plan, ShortVectorFrames(), out _);

            Assert.Equal(0, Unprotect(keys, packet, 6, 3)[0] & 0x18);
            reachedTheFifthBit |= (packet[0] & 0x10) != 0;
        }

        Assert.True(
            reachedTheFifthBit,
            "RFC 9001 s5.4 protects five bits of byte 0 for a short header, so bit 0x10 must be "
            + "maskable; a four-bit long-header mask leaves it 0 for every sample.");
    }

    [Theory]
    // One row per field RFC 9000 s17.3.1 does not have, because a test can only pin the
    // check that fires first.
    [InlineData("version")]
    [InlineData("source connection id")]
    [InlineData("token")]
    [InlineData("length varint width")]
    public void ALongHeaderOnlyFieldOnAShortHeaderPlanIsRejected(string field)
    {
        // s17.3.1's field list is byte 0, Destination Connection ID, Packet Number,
        // Packet Payload. Every other field TlsQuicPacketPlan carries belongs to s17.2's
        // long header, and TlsQuicPacketHeader.WriteShortHeader neither writes nor
        // complains about one - so a plan carrying it would lose it silently. That is the
        // defect class ValidateToken already guards for a non-Initial long header.
        var plan = ShortVectorPlan();
        plan = field switch
        {
            "version" => plan with { Version = (uint)TlsQuicVersion.Version1 },
            "source connection id" => plan with
            {
                SourceConnectionId = Convert.FromHexString(VectorSourceConnectionIdHex),
            },
            "token" => plan with { Token = Convert.FromHexString(VectorTokenHex) },
            "length varint width" => plan with { LengthVarintWidth = TlsQuicVarintWidth.FourBytes },
            _ => throw new ArgumentOutOfRangeException(nameof(field), field, null),
        };

        var thrown = Assert.Throws<ArgumentException>(() => BuildOrThrow(plan, ShortVectorFrames()));
        Assert.Equal("plan", thrown.ParamName);
    }

    // RFC 9000 s17.3.1's short header, at a THREE-byte packet number - not the default
    // four - and a FIVE-byte connection ID, so no field of this vector sits at the value
    // the long-header vector above uses.
    private static TlsQuicPacketPlan ShortVectorPlan() => new()
    {
        Type = null,
        DestinationConnectionId = Convert.FromHexString(ShortVectorDestinationConnectionIdHex),
        PacketNumber = ShortVectorPacketNumber,
        PacketNumberEncodedLength = 3,
        LargestAcknowledged = ShortVectorLargestAcknowledged,
        SpinBit = true,
        KeyPhase = true,
    };

    // The same header, at a packet number a receiver holding no history decodes back to
    // the value it was built from; see ShortLoopbackPacketNumber.
    private static TlsQuicPacketPlan ShortLoopbackPlan() => ShortVectorPlan() with
    {
        PacketNumber = ShortLoopbackPacketNumber,
        LargestAcknowledged = ShortLoopbackLargestAcknowledged,
    };

    private static TlsQuicFrame[] ShortVectorFrames() =>
    [
        new() { RawType = 0x1e },
        new() { RawType = 0x01 },
    ];

    // THE 1-RTT KEY MATERIAL, AND THE INDEPENDENCE CLAIM THAT RESTS ON IT.
    //
    // RFC 9001 publishes no 1-RTT keys, so there is no vector to take these from. The next
    // best thing is bytes that ARE anchored to a published vector somewhere: these are
    // A.1's server Initial keys, derived from Appendix A's published connection ID, and
    // TlsQuicKeySetTests pins that derivation against A.1's printed output. Installing
    // them at the Application level is the same device
    // TlsQuicPacketReceiverTests.InstallHandshake uses and for the same reason - these
    // tests are about packet layout, not about key derivation, and inventing key bytes
    // here would put a made-up constant where a pinned one fits.
    //
    // WHAT "KEYS DERIVED INDEPENDENTLY OF THE BUILDER" DOES AND DOES NOT BUY, stated
    // plainly because the difference is where this task's evidence is weakest. The
    // receiver gets the same key BYTES - different bytes would only produce an
    // authentication failure, which proves nothing about layout. What it does not get is
    // anything the builder COMPUTED: not headerLength, not pn_offset, not the packet
    // number length, not the packet number. TlsQuicPacketReceiver re-derives pn_offset
    // from the connection ID length it was constructed with, removes header protection
    // with its own code, reads the packet number length from the now-unmasked byte 0, and
    // reconstructs the full number with TlsQuicPacketNumber.Decode.
    //
    // AND IT STILL CANCELS IN ONE PLACE. Both sides compute pn_offset as 1 + len(cid) -
    // the receiver from its own parse, the builder from WriteShortHeader - so a shared
    // misreading of s17.3.1's field ORDER would be invisible to this leg. That is what the
    // hand-derived byte assertions are for, and why they are not optional here.
    private static TlsQuicPacketProtectionKeys OneRttKeys()
    {
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, Convert.FromHexString(AppendixAConnectionIdHex));
        return secrets.DeriveServerPacketProtectionKeys(TlsQuicVersion.Version1);
    }

    private static TlsQuicPacketPlan VectorPlan() => new()
    {
        Type = TlsQuicLongPacketType.Initial,
        Version = (uint)TlsQuicVersion.Version1,
        DestinationConnectionId = Convert.FromHexString(VectorDestinationConnectionIdHex),
        SourceConnectionId = Convert.FromHexString(VectorSourceConnectionIdHex),
        Token = Convert.FromHexString(VectorTokenHex),
        PacketNumber = VectorPacketNumber,
        PacketNumberEncodedLength = 4,
        LargestAcknowledged = null,
        LengthVarintWidth = TlsQuicVarintWidth.Minimal,
    };

    private static TlsQuicFrame[] VectorFrames() =>
    [
        new() { RawType = 0x01 },
        new() { RawType = 0x06, Offset = 64, Data = Convert.FromHexString("7E8D9A") },
    ];

    private static TlsQuicPacketProtectionKeys VectorKeys()
    {
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, Convert.FromHexString(VectorDestinationConnectionIdHex));
        return secrets.DeriveClientPacketProtectionKeys(TlsQuicVersion.Version1);
    }

    private static byte[] Build(
        TlsQuicPacketProtectionKeys keys,
        in TlsQuicPacketPlan plan,
        IReadOnlyList<TlsQuicFrame> frames,
        out TlsQuicSentPacket sent)
    {
        var buffer = new byte[4096];
        sent = TlsQuicPacketBuilder.Build(
            plan,
            frames,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            SentAt,
            buffer);
        return buffer[..sent.Size];
    }

    private static void BuildOrThrow(in TlsQuicPacketPlan plan, IReadOnlyList<TlsQuicFrame> frames)
    {
        using var keys = VectorKeys();
        Build(keys, plan, frames, out _);
    }

    // RFC 9001 s5.4's inverse, pinned against A.2 and A.5 in
    // TlsQuicHeaderProtectionTests, used here only to see byte 0 and the packet number.
    // Returns the header, which s5.3 makes the AEAD's associated data.
    private static byte[] Unprotect(
        TlsQuicPacketProtectionKeys keys, byte[] packet, int packetNumberOffset, int expectedPacketNumberLength)
    {
        var copy = (byte[])packet.Clone();
        Assert.True(TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            copy,
            packetNumberOffset,
            out var packetNumberLength));
        Assert.Equal(expectedPacketNumberLength, packetNumberLength);
        return copy[..(packetNumberOffset + packetNumberLength)];
    }

    // Null on an authentication failure rather than an assertion, because one test
    // below needs the failing case as its discriminator.
    private static byte[]? Open(
        TlsQuicPacketProtectionKeys keys,
        byte[] packet,
        int packetNumberOffset,
        int packetNumberLength,
        ulong packetNumber)
    {
        var copy = (byte[])packet.Clone();
        Assert.True(TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            copy,
            packetNumberOffset,
            out _));

        var headerLength = packetNumberOffset + packetNumberLength;
        var plaintext = new byte[copy.Length - headerLength - 16];
        return TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            packetNumber,
            copy.AsSpan(0, headerLength),
            copy.AsSpan(headerLength),
            plaintext)
            ? plaintext
            : null;
    }
}
