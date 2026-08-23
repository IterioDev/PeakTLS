using SharpTls.Fuzzing;
using System.Collections.Immutable;
using System.Globalization;
using System.Text.RegularExpressions;
using SharpTls.Cryptography;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task 5 of A4-minimal: coalescing, padding and the multi-datagram Initial flight.
//
// WHY ALMOST EVERY VECTOR HERE IS HAND-DERIVED. Task 4b measured it: of its 24 mutations,
// 13 leave RFC 9001 A.2 and A.3 both green. A.2 is also a SINGLE DATAGRAM, so it says
// nothing at all about flights, per-datagram padding or coalescing - the three things this
// file is about. It appears once below, as the check that the datagram builder still
// reproduces it byte for byte, and it anchors nothing else.
//
// THE ARITHMETIC EVERY PADDING TEST BELOW SHARES, written out once from RFC 9000 s17.2's
// field diagram so no individual test restates it:
//
//   fixedHeader = byte0(1) + Version(4) + DCID Len(1) + DCID + SCID Len(1) + SCID
//                 [+ Token Len varint + Token, Initial only] + Packet Number
//   packetSize  = fixedHeader + LengthVarint + payload + paddingFrames + 16-byte tag
//   Length      = packetNumberLength + payload + paddingFrames + 16
//
// For the shared vector below: 1 + 4 + 1 + 8 + 1 + 3 + 1 + 5 = 24 before the Length
// varint, plus a 4-byte packet number, so fixedHeader = 28 and the Length varint begins at
// offset 24. For a Handshake packet, which s17.2.4 gives no Token fields, the same sum is
// 1 + 4 + 1 + 8 + 1 + 3 = 18 before the Length varint and fixedHeader = 22.
//
// WHAT IS AND IS NOT DECODED, same as the packet builder's tests: header protection masks
// only byte 0's low bits and the Packet Number field, so every other header byte - the
// Length varint above all - is asserted straight off the wire. Only the payload needs
// TlsQuicPacketProtection.TryOpen.
public sealed class TlsQuicDatagramBuilderTests
{
    private static readonly DateTimeOffset SentAt = new(2026, 8, 18, 12, 0, 0, TimeSpan.Zero);

    // The same shape task 4b's hand-derived tests use, and chosen against the same rule: no
    // byte here is 0x00 (PADDING, and a CRYPTO offset of 0), 0x01 (PING), 0x06 (CRYPTO), or
    // equal to a length or Length-varint byte any packet below carries.
    private const string VectorDestinationConnectionIdHex = "B1B2B3B4B5B6B7B8";
    private const string VectorSourceConnectionIdHex = "C1C2C3";
    private const string VectorTokenHex = "9C5F3E7AB6";
    private const ulong VectorPacketNumber = 42;

    // RFC 9001 Appendix A's 8-byte client-chosen Destination Connection ID, for the one
    // published vector below.
    private const string AppendixAConnectionIdHex = "8394C8F03E515708";

    // The Length varint's offset in a packet built from VectorPlan: the 24 bytes derived in
    // this class's own header comment.
    private const int VectorLengthVarintOffset = 24;

    [Fact]
    public void ASingleInitialDatagramIsExpandedToTheSectionFourteenOneTargetWithPaddingFrames()
    {
        // HAND-DERIVED, PaddingTarget 1250 - deliberately not 1200, so the target is a knob
        // and not the RFC's floor doubling as a default.
        //
        // payload = PING(0x01) + CRYPTO(0x06, offset 64 -> 0x4040, length 3 -> 0x03, data)
        //         = 1 + 1 + 2 + 1 + 3 = 8 bytes.
        // At a Minimal Length varint, s16 Table 4's widths give one self-consistent answer:
        //   w=1: Length = 4 + 1250 - 28 - 1 = 1225, which needs 2 bytes. Inconsistent.
        //   w=2: Length = 4 + 1250 - 28 - 2 = 1224, which needs 2 bytes. Consistent.
        // So paddingFrames = 1250 - 28 - 2 - 8 - 16 = 1196, the payload is 1204 bytes and
        // Length is 4 + 1204 + 16 = 1224. s16's 2-byte form is 0x4000 | 1224 = 0x44C8.
        const int target = 1250;
        const int paddingFrames = 1196;

        using var keys = VectorKeys();
        var datagram = BuildOne(keys, Spec(target), VectorPlan(), VectorFrames(), out var sent);

        Assert.Equal(target, datagram.Length);
        Assert.Equal(target, sent.Size);
        Assert.Equal(
            "44C8",
            Convert.ToHexString(datagram, VectorLengthVarintOffset, 2),
            ignoreCase: true);
        Assert.Equal(
            VectorPayloadHex + new string('0', 2 * paddingFrames),
            Convert.ToHexString(OpenVector(keys, datagram)),
            ignoreCase: true);
    }

    [Fact]
    public void ThePaddingSolverHonoursANonMinimalHeaderLengthVarintWidth()
    {
        // HAND-DERIVED at LengthVarintWidth.FourBytes, where GetLongHeaderLength's
        // circularity does not exist at all - the width is fixed, so there is one candidate:
        //   paddingFrames = 1200 - 28 - 4 - 8 - 16 = 1144
        //   Length        = 4 + 8 + 1144 + 16 = 1172
        // s16 Table 4's 4-byte form is 0x80000000 | 1172 = 0x80000494, and the packet is
        // 24 + 4 + 4 + 1152 + 16 = 1200 bytes.
        const int paddingFrames = 1144;

        using var keys = VectorKeys();
        var plan = VectorPlan() with { LengthVarintWidth = TlsQuicVarintWidth.FourBytes };
        var datagram = BuildOne(keys, Spec(1200), plan, VectorFrames(), out _);

        Assert.Equal(1200, datagram.Length);
        Assert.Equal(
            "80000494",
            Convert.ToHexString(datagram, VectorLengthVarintOffset, 4),
            ignoreCase: true);
        Assert.Equal(
            VectorPayloadHex + new string('0', 2 * paddingFrames),
            Convert.ToHexString(Open(keys, datagram, VectorLengthVarintOffset + 4, VectorPacketNumber)),
            ignoreCase: true);
    }

    [Fact]
    public void CryptoOffsetAndLengthVarintsAreWrittenAtTheWidthsThePlanAsksFor()
    {
        // THE PLAN, NOT THE SPEC, and the name says so because the widths below are set on
        // VectorPlan(). Task 5 opened the CRYPTO writer so a width can reach the wire at all;
        // what it did NOT add is a TlsQuicConnectionSpec-to-TlsQuicPacketPlan mapping, so
        // setting TlsQuicConnectionSpec.CryptoOffsetVarintWidth still changes no byte. A4
        // task 9a-ii owns that mapping. This test was previously named for the spec, which
        // asserted a path no code has.
        //
        // HAND-DERIVED, and the witness the two knobs owed since task 4b. RFC 9000 s16
        // Table 4's "2MSB" column: the 4-byte form prefixes 0x80, the 2-byte form 0x40. So
        // a CRYPTO frame at offset 0, 3 bytes of data, with a 4-byte Offset and a 2-byte
        // Length is 06 80000000 4003 7E8D9A - ten bytes, against the six the minimal form
        // writes (06 00 03 7E8D9A). Neither RFC 9001 A.2 nor A.3 encodes either field
        // non-minimally, so nothing but this case can see the widths at all.
        //
        //   paddingFrames = 1200 - 28 - 2 - 10 - 16 = 1144
        //   Length        = 4 + 10 + 1144 + 16 = 1174, 2 bytes, consistent.
        const string widened = "06800000004003" + "7E8D9A";
        const int paddingFrames = 1144;

        using var keys = VectorKeys();
        var plan = VectorPlan() with
        {
            CryptoOffsetVarintWidth = TlsQuicVarintWidth.FourBytes,
            CryptoLengthVarintWidth = TlsQuicVarintWidth.TwoBytes,
        };
        var frames = new[] { CryptoFrame(0, "7E8D9A") };
        var datagram = BuildOne(keys, Spec(1200), plan, frames, out _);

        Assert.Equal(1200, datagram.Length);
        Assert.Equal(
            widened + new string('0', 2 * paddingFrames),
            Convert.ToHexString(OpenVector(keys, datagram)),
            ignoreCase: true);

        // The same frame at the default widths, so the comparison is against this builder's
        // own minimal form and not only against the hand-derived hex above: six bytes, and
        // four more PADDING frames take up the difference.
        var minimal = BuildOne(keys, Spec(1200), VectorPlan(), frames, out _);
        Assert.Equal(
            "060003" + "7E8D9A" + new string('0', 2 * (paddingFrames + 4)),
            Convert.ToHexString(OpenVector(keys, minimal)),
            ignoreCase: true);
    }

    [Fact]
    public void ACryptoVarintWidthTooNarrowForItsValueIsRejected()
    {
        // s16's widths are a floor as well as a choice: GetEncodedLength(value, width)
        // refuses a width the value does not fit, rather than truncating it silently. 300
        // needs two bytes, so a one-byte Offset is a caller error.
        using var keys = VectorKeys();
        var plan = VectorPlan() with { CryptoOffsetVarintWidth = TlsQuicVarintWidth.OneByte };

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            BuildOne(keys, Spec(1200), plan, [CryptoFrame(300, "7E8D9A")], out _));
    }

    [Fact]
    public void TheTwoDatagramInitialFlightSplitsWhereTheSpecSaysAndPadsEveryDatagram()
    {
        // HAND-DERIVED, and the case the whole task exists for: three CRYPTO frames over
        // two datagrams, so the two flat arrays are exercised at values neither of which is
        // derivable from the other - two frames in the first datagram and one in the
        // second, from a split of 100/60/3.
        //
        // Datagram 0's payload, from s19.6's field order and s16 Table 4:
        //   06 00   4064   <100 bytes>   -> 1 + 1 + 2 + 100 = 104
        //   06 4064 3C     <60 bytes>    -> 1 + 2 + 1 +  60 =  64
        //   168 bytes, so paddingFrames = 1200 - 28 - 2 - 168 - 16 = 986 and
        //   Length = 4 + 1154 + 16 = 1174 -> 0x4000 | 1174 = 0x4496.
        //
        // Datagram 1's payload:
        //   06 40A0 03     <3 bytes>     -> 1 + 2 + 1 +   3 =   7
        //   paddingFrames = 1200 - 28 - 2 - 7 - 16 = 1147, and the payload is 1154 bytes
        //   again, so Length is 1174 and the varint 0x4496 in this datagram too.
        //
        // The stream byte at index i is i+1, so a split at the wrong boundary changes the
        // first data byte of a frame as well as its Offset: frame 1 must start at 0x65 and
        // frame 2 at 0xA1. A test asserting only the declared counts passes against a
        // builder that splits in the wrong place.
        var stream = CryptoStream(163);
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            InitialCryptoFrameByteCounts = [100, 60, 3],
            InitialCryptoFramesPerDatagram = [2, 1],
        };

        using var keys = VectorKeys();
        var sent = new List<TlsQuicSentPacket>();
        var flight = TlsQuicDatagramBuilder.BuildInitialFlight(
            spec, Template(keys, VectorPlan()), stream, SentAt, sent);

        Assert.Equal(2, flight.Count);

        // RFC 9000 s14.1 asserted PER DATAGRAM, which is what "all UDP datagrams carrying
        // Initial packets" says. A flight-total assertion would pass against a builder that
        // padded one datagram to 2400.
        Assert.All(flight, datagram => Assert.Equal(1200, datagram.Length));
        Assert.All(
            flight,
            datagram => Assert.Equal(
                "4496",
                Convert.ToHexString(datagram, VectorLengthVarintOffset, 2),
                ignoreCase: true));

        Assert.Equal(
            "06004064" + Hex(stream, 0, 100) + "0640643C" + Hex(stream, 100, 60)
                + new string('0', 2 * 986),
            Convert.ToHexString(OpenVector(keys, flight[0])),
            ignoreCase: true);
        Assert.Equal(
            "0640A003" + Hex(stream, 160, 3) + new string('0', 2 * 1147),
            Convert.ToHexString(OpenVector(keys, flight[1], VectorPacketNumber + 1)),
            ignoreCase: true);

        // s12.3 gives the Initial space one packet number sequence; the flight advances by
        // one per datagram and reports both, which is what A3 will retain.
        Assert.Equal(new[] { VectorPacketNumber, VectorPacketNumber + 1 }, sent.Select(p => p.PacketNumber).ToArray());
        Assert.All(sent, packet => Assert.Equal(1200, packet.Size));
    }

    [Fact]
    public void AnInitialCoalescedWithAHandshakePacketIsPaddedInTheLastPacket()
    {
        // HAND-DERIVED, and the case where s14.1's SECOND route - "or by coalescing the
        // Initial packet" - arrives on its own: the PADDING lands in the Handshake packet,
        // because that is the last one, and the datagram still reaches the floor.
        //
        // Initial packet: payload 06 00 03 7E8D9A = 6 bytes, Length = 4 + 6 + 16 = 26,
        //   which s16 encodes in one byte as 0x1A, so the packet is 24 + 1 + 4 + 6 + 16 =
        //   51 bytes and the second packet begins at offset 51.
        // Handshake packet: s17.2.4 gives it no Token fields, so its Length varint sits 18
        //   bytes into it - absolute offset 69 - and fixedHeader is 22. The budget is
        //   1200 - 51 = 1149 and the payload is one PING:
        //     w=1: Length = 4 + 1149 - 22 - 1 = 1130, needs 2. Inconsistent.
        //     w=2: Length = 4 + 1149 - 22 - 2 = 1129, needs 2. Consistent.
        //   paddingFrames = 1149 - 22 - 2 - 1 - 16 = 1108, and 0x4000 | 1129 = 0x4469.
        //
        // Both packets are sealed under the same Initial keys. RFC 9001 s5.3 keys a packet
        // from the arguments it is given, not from its type, and A4 task 9a-i owns which
        // keys a level actually uses; using one set here keeps this test about layout.
        using var keys = VectorKeys();
        var initial = new TlsQuicPacketToSend
        {
            Plan = VectorPlan(),
            Frames = [CryptoFrame(0, "7E8D9A")],
            PacketProtectionCipher = TlsQuicPacketProtectionCipher.AesGcm,
            Key = keys.CopyKey(),
            Iv = keys.CopyIv(),
            HeaderProtectionCipher = TlsQuicHeaderProtectionCipher.Aes,
            HeaderProtectionKey = keys.CopyHeaderProtectionKey(),
        };
        var handshake = initial with
        {
            Plan = VectorPlan() with
            {
                Type = TlsQuicLongPacketType.Handshake,
                Token = ReadOnlyMemory<byte>.Empty,
            },
            Frames = [new TlsQuicFrame { RawType = 0x01 }],
        };

        var buffer = new byte[1200];
        var sent = new List<TlsQuicSentPacket>();
        var written = TlsQuicDatagramBuilder.BuildDatagram(
            Spec(1200), [initial, handshake], SentAt, buffer, sent);

        Assert.Equal(1200, written);
        Assert.Equal(new[] { 51, 1149 }, sent.Select(p => p.Size).ToArray());
        Assert.Equal(
            new[] { TlsQuicEncryptionLevel.Initial, TlsQuicEncryptionLevel.Handshake },
            sent.Select(p => p.Level).ToArray());
        Assert.Equal("1A", Convert.ToHexString(buffer, VectorLengthVarintOffset, 1), ignoreCase: true);
        Assert.Equal("4469", Convert.ToHexString(buffer, 69, 2), ignoreCase: true);

        // The Handshake packet's own header, in the clear: s17.2's Version, then both
        // connection IDs with their length bytes, and no Token Length at all.
        Assert.Equal(
            "0000000108" + VectorDestinationConnectionIdHex + "03" + VectorSourceConnectionIdHex,
            Convert.ToHexString(buffer, 52, 17),
            ignoreCase: true);
        Assert.Equal(
            "01" + new string('0', 2 * 1108),
            Convert.ToHexString(Open(keys, buffer[51..], 20, VectorPacketNumber)),
            ignoreCase: true);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void CoalescingPacketsWithDifferentConnectionIdsIsRejected(bool differByDestination)
    {
        // RFC 9000 s12.2: "Senders MUST NOT coalesce QUIC packets with different connection
        // IDs into a single UDP datagram." The MUST NOT is unqualified and s17.2 gives a long
        // header two connection IDs, so both rows here are violations - it is the RECEIVER's
        // SHOULD in the next sentence that narrows to the Destination Connection ID, and a
        // sender does not get to be judged by the receiver's leniency.
        //
        // THE SUBSTITUTED ID IS THE SAME LENGTH AS THE ONE IT REPLACES, deliberately. Every
        // packet size below is byte-for-byte what
        // AnInitialCoalescedWithAHandshakePacketIsPaddedInTheLastPacket builds and asserts,
        // so nothing about the length, the budget or the padding solver can reject this
        // datagram: remove the s12.2 guard and it builds to 1200 bytes and succeeds. That is
        // what makes this a witness for the guard rather than for whichever check fires
        // first.
        using var keys = VectorKeys();
        var initial = Template(keys, VectorPlan()) with { Frames = [CryptoFrame(0, "7E8D9A")] };
        var handshake = initial with
        {
            Plan = VectorPlan() with
            {
                Type = TlsQuicLongPacketType.Handshake,
                Token = ReadOnlyMemory<byte>.Empty,
                DestinationConnectionId = Convert.FromHexString(
                    differByDestination ? "D1D2D3D4D5D6D7D8" : VectorDestinationConnectionIdHex),
                SourceConnectionId = Convert.FromHexString(
                    differByDestination ? VectorSourceConnectionIdHex : "E1E2E3"),
            },
            Frames = [new TlsQuicFrame { RawType = 0x01 }],
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            TlsQuicDatagramBuilder.BuildDatagram(
                Spec(1200), [initial, handshake], SentAt, new byte[1200], null));

        Assert.Equal("packets", exception.ParamName);
        Assert.Contains(
            "MUST NOT coalesce QUIC packets with different connection IDs",
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void AHandshakeOnlyDatagramIsNotExpanded()
    {
        // s14.1 binds "UDP datagrams carrying Initial packets" and nothing else, so this
        // datagram is whatever its one packet is: fixedHeader 22, payload PING + CRYPTO =
        // 1 + 7 = 8, Length = 4 + 8 + 16 = 28 which s16 writes as the single byte 0x1C, and
        // the packet is 18 + 1 + 4 + 8 + 16 = 47 bytes. The number is hand-derived rather
        // than "less than 1200", because a builder that padded to some other target would
        // also be less than 1200.
        using var keys = VectorKeys();
        var plan = VectorPlan() with
        {
            Type = TlsQuicLongPacketType.Handshake,
            Token = ReadOnlyMemory<byte>.Empty,
        };
        var datagram = BuildOne(keys, Spec(1200), plan, VectorFrames(), out _);

        Assert.Equal(47, datagram.Length);
        Assert.Equal("1C", Convert.ToHexString(datagram, 18, 1), ignoreCase: true);
        Assert.Equal(VectorPayloadHex, Convert.ToHexString(Open(keys, datagram, 19, VectorPacketNumber)), ignoreCase: true);
    }

    [Fact]
    public void PaddingLeadsWhenTheSpecOrdersItBeforeCrypto()
    {
        // TlsQuicConnectionSpec.InitialFrameOrder is a layout knob, and where the PADDING
        // this builder adds sits relative to the caller's frames is the one ordering
        // decision the builder itself makes. Reversed from the default here, so the same
        // 1148 PADDING bytes appear before 06 00 03 7E8D9A instead of after it - the same
        // packet size, a different wire image.
        //   paddingFrames = 1200 - 28 - 2 - 6 - 16 = 1148, Length = 4 + 1154 + 16 = 1174.
        const int paddingFrames = 1148;

        using var keys = VectorKeys();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            InitialFrameOrder = [TlsQuicFrameType.Padding, TlsQuicFrameType.Crypto],
        };
        var datagram = BuildOne(keys, spec, VectorPlan(), [CryptoFrame(0, "7E8D9A")], out _);

        Assert.Equal(1200, datagram.Length);
        Assert.Equal(
            new string('0', 2 * paddingFrames) + "060003" + "7E8D9A",
            Convert.ToHexString(OpenVector(keys, datagram)),
            ignoreCase: true);
    }

    [Fact]
    public void APacketThatAlreadyFillsTheTargetIsNotPadded()
    {
        // s14.1: "Datagrams containing Initial packets MAY exceed 1200 bytes if the sender
        // believes that the network path and peer both support the size that it chooses."
        // So overshooting the target is legal and is not an error - the MUST is a floor.
        // A CRYPTO frame with 1200 bytes of data is 1 + 1 + 2 + 1200 = 1204 bytes of
        // payload, Length = 4 + 1204 + 16 = 1224 (0x44C8) and the packet is
        // 24 + 2 + 4 + 1204 + 16 = 1250 bytes, with no PADDING added at all.
        using var keys = VectorKeys();
        var buffer = new byte[4096];
        var packet = Template(keys, VectorPlan()) with
        {
            Frames = [new TlsQuicFrame { RawType = 0x06, Offset = 0, Data = CryptoStream(1200) }],
        };

        var written = TlsQuicDatagramBuilder.BuildDatagram(Spec(1200), [packet], SentAt, buffer, null);

        Assert.Equal(1250, written);
        Assert.True(written >= 1200);
        Assert.Equal("44C8", Convert.ToHexString(buffer, VectorLengthVarintOffset, 2), ignoreCase: true);
    }

    [Theory]
    [InlineData(16409)]
    [InlineData(16412)]
    public void APaddingTargetEitherSideOfTheTableFourStepIsReached(int target)
    {
        // The pair that shows the step is real and is not a builder limitation. With
        // fixedHeader 28, a Minimal Length varint reaches a datagram of T bytes only when
        // the width it needs is the width the size assumed:
        //   2 bytes: Length = T - 26 must be at most 16383, so T <= 16409.
        //   4 bytes: Length = T - 28 must be at least 16384, so T >= 16412.
        // Both ends are reachable; the two sizes between them are not.
        using var keys = VectorKeys();
        var datagram = BuildOne(keys, Spec(target), VectorPlan(), VectorFrames(), out _);

        Assert.Equal(target, datagram.Length);
        Assert.Equal(
            target == 16409 ? "7FFF" : "80004000",
            Convert.ToHexString(datagram, VectorLengthVarintOffset, target == 16409 ? 2 : 4),
            ignoreCase: true);
    }

    [Theory]
    [InlineData(16410)]
    [InlineData(16411)]
    public void APaddingTargetOnTheTableFourStepIsRejected(int target)
    {
        // The gap the theory above brackets. At 16410 the 2-byte width would need a Length
        // of 16384, which needs 4 bytes, and the 4-byte width would need a Length of 16382,
        // which needs 2 - neither is self-consistent, so no PADDING frame count produces a
        // datagram of exactly this size. Rejected rather than rounded: rounding would
        // silently miss the target a fingerprint spec asked for.
        //
        // TWO ROWS, AND THAT IS THE GENERAL RULE RATHER THAN AN ACCIDENT: at the boundary
        // between a w_prev-byte and a w_next-byte Length, exactly w_next - w_prev datagram
        // sizes are unreachable, because Length = budget - H - w moves by one per budget and
        // the two candidate widths disagree over that whole span. Here w_prev = 2 and
        // w_next = 4, so the gap is two values wide. The 1/2 boundary's single value is
        // witnessed below; the 4/8 boundary's four need a budget past a billion and
        // PaddingTarget stops at 65527, so they are unreachable by construction.
        using var keys = VectorKeys();

        var exception = Assert.Throws<ArgumentException>(() =>
            BuildOne(keys, Spec(target), VectorPlan(), VectorFrames(), out _));

        // The knob the caller actually set. Naming the solver's own private `plan` sent a
        // reader looking for an argument no caller of this builder ever passes.
        Assert.Equal("spec", exception.ParamName);
    }

    [Fact]
    public void ACoalescedBudgetOnTheOneByteTableFourStepIsRejected()
    {
        // THE 1/2 BOUNDARY, which the theory above cannot reach: its dead value is
        // H + 65 = 83, and PaddingTarget's own floor is 1200. A COALESCED budget has no such
        // floor - it is whatever the target leaves after the earlier packets - so this is
        // where the narrowest step is reachable at all.
        //
        // The Initial packet, HAND-DERIVED: a CRYPTO frame of 1067 bytes at offset 0 is
        //   06 00 442B <1067 bytes> = 1 + 1 + 2 + 1067 = 1071 bytes of payload, so
        //   Length = 4 + 1071 + 16 = 1091 (two bytes) and the packet is
        //   28 + 2 + 1071 + 16 = 1117 bytes. It is not the last packet, so nothing pads it.
        // That leaves the Handshake packet a budget of 1200 - 1117 = 83, and s17.2.4 gives a
        // Handshake no Token fields, so its H - fixedHeader less the packet number - is 18:
        //   w=1: Length = 83 - 18 - 1 = 64, which needs 2 bytes. Inconsistent.
        //   w=2: Length = 83 - 18 - 2 = 63, which needs 1 byte.  Inconsistent.
        // Neither wider width can be consistent either, so the budget is rejected. 83 is the
        // ONLY value with this property at this H: 82 is reachable at one byte and 84 at two.
        using var keys = VectorKeys();
        var initial = Template(keys, VectorPlan()) with
        {
            Frames = [new TlsQuicFrame { RawType = 0x06, Offset = 0, Data = CryptoStream(1067) }],
        };
        var handshake = initial with
        {
            Plan = VectorPlan() with
            {
                Type = TlsQuicLongPacketType.Handshake,
                Token = ReadOnlyMemory<byte>.Empty,
            },
            Frames = [new TlsQuicFrame { RawType = 0x01 }],
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            TlsQuicDatagramBuilder.BuildDatagram(
                Spec(1200), [initial, handshake], SentAt, new byte[1200], null));

        Assert.Equal("spec", exception.ParamName);
        Assert.Contains("Handshake packet exactly 83 bytes", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1066, 1116, 84, "4040")]
    [InlineData(1068, 1118, 82, "3F")]
    public void ACoalescedBudgetEitherSideOfTheOneByteTableFourStepIsReached(
        int cryptoBytes, int initialSize, int budget, string lengthVarintHex)
    {
        // The bracket that shows 83 is a step and not a builder limitation, and the reason
        // the test above can claim "only 83". A CRYPTO frame one byte shorter leaves a budget
        // of 84, one byte longer leaves 82, and both are reached exactly.
        //   84: w=2 gives Length = 84 - 18 - 2 = 64, two bytes. Consistent, 0x4000|64 =
        //       0x4040, and paddingFrames = 84 - 22 - 2 - 1 - 16 = 43.
        //   82: w=1 gives Length = 82 - 18 - 1 = 63, one byte.  Consistent, 0x3F, and
        //       paddingFrames = 82 - 22 - 1 - 1 - 16 = 42.
        // The Handshake's own Length varint sits 18 bytes into it - byte 0, the version and
        // both connection IDs with their length bytes, and no Token fields.
        using var keys = VectorKeys();
        var initial = Template(keys, VectorPlan()) with
        {
            Frames = [new TlsQuicFrame { RawType = 0x06, Offset = 0, Data = CryptoStream(cryptoBytes) }],
        };
        var handshake = initial with
        {
            Plan = VectorPlan() with
            {
                Type = TlsQuicLongPacketType.Handshake,
                Token = ReadOnlyMemory<byte>.Empty,
            },
            Frames = [new TlsQuicFrame { RawType = 0x01 }],
        };

        var buffer = new byte[1200];
        var sent = new List<TlsQuicSentPacket>();
        var written = TlsQuicDatagramBuilder.BuildDatagram(
            Spec(1200), [initial, handshake], SentAt, buffer, sent);

        Assert.Equal(1200, written);
        Assert.Equal(new[] { initialSize, budget }, sent.Select(p => p.Size).ToArray());
        Assert.Equal(
            lengthVarintHex,
            Convert.ToHexString(buffer, initialSize + 18, lengthVarintHex.Length / 2),
            ignoreCase: true);
    }

    [Fact]
    public void AppendixA2IsStillProducedByteForByteThroughTheDatagramBuilder()
    {
        // The one published vector, and the only test here that is not hand-derived. It
        // checks two things nothing else can: that the padding solver lands on RFC 9001
        // A.2's own numbers - 1200 = 16 + 2 + 4 + 1162 + 16, so 1162 - 245 = 917 PADDING
        // frames after the 245-byte CRYPTO frame - and that a datagram built here is the
        // same bytes task 4b's packet builder produces. Note the padding count is NOT
        // passed in: A.2's payload is reached by solving, which is the whole difference
        // from the packet-builder test that hands the frames over ready-made.
        var cryptoFrame = QuicRfcVectors.BuildA2CryptoFrame();
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

        var datagram = BuildOne(
            keys,
            Spec(1200),
            plan,
            [new TlsQuicFrame { RawType = 0x06, Offset = 0, Data = cryptoFrame.AsMemory(4) }],
            out var sent);

        Assert.Equal(
            TlsQuicPacketProtectionTests.A2FullProtectedPacketHex,
            Convert.ToHexString(datagram),
            ignoreCase: true);
        Assert.Equal(1200, sent.Size);
    }

    [Fact]
    public void AFlightDatagramMayExceedThePaddingTarget()
    {
        // HAND-DERIVED, and the input TlsQuicDatagramBuilder's own header comment names as
        // the reason the multi-datagram flight exists: the Brave 151 capture's
        // X25519MLKEM768 key share is 1216 bytes, which does not fit a 1200-byte datagram.
        // Declared as ONE CRYPTO frame in ONE datagram, so the flight has to overshoot rather
        // than split - and s14.1 permits exactly that, because PaddingTarget is a floor:
        // "Datagrams containing Initial packets MAY exceed 1200 bytes if the sender believes
        // that the network path and peer both support the size that it chooses."
        //
        //   payload = 06 00 44C0 <1216 bytes> = 1 + 1 + 2 + 1216 = 1220
        //   the narrowest candidate already needs 1200 - 28 - 1 - 1220 - 16 = -65 PADDING
        //   frames, so none is added at all,
        //   Length  = 4 + 1220 + 16 = 1240 -> 0x4000 | 1240 = 0x44D8, two bytes,
        //   and the datagram is 24 + 2 + 4 + 1220 + 16 = 1266 bytes.
        //
        // 1266 is asserted rather than "more than 1200": a builder that overshot to some
        // other size would also be more than 1200. Sizing the flight's buffer from
        // PaddingTarget made this input throw from TlsQuicPacketBuilder.Build, naming a
        // `destination` BuildInitialFlight has no parameter for.
        var stream = CryptoStream(1216);
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            InitialCryptoFrameByteCounts = [1216],
            InitialCryptoFramesPerDatagram = [1],
        };

        using var keys = VectorKeys();
        var sent = new List<TlsQuicSentPacket>();
        var flight = TlsQuicDatagramBuilder.BuildInitialFlight(
            spec, Template(keys, VectorPlan()), stream, SentAt, sent);

        var datagram = Assert.Single(flight);
        Assert.Equal(1266, datagram.Length);
        Assert.Equal(1266, Assert.Single(sent).Size);
        Assert.Equal(
            "44D8", Convert.ToHexString(datagram, VectorLengthVarintOffset, 2), ignoreCase: true);
        Assert.Equal(
            "060044C0" + Hex(stream, 0, 1216),
            Convert.ToHexString(OpenVector(keys, datagram)),
            ignoreCase: true);
    }

    [Fact]
    public void AFlightDatagramLargerThanAUdpPayloadIsRejected()
    {
        // The other side of the overshoot contract, and where it stops. s14.1 lets a datagram
        // exceed the target; s18.2 caps what a UDP datagram can be at all - "the maximum
        // permitted UDP payload of 65527" - and a flight plan that puts more CRYPTO stream
        // than that into one datagram is describing something no socket can send. Rejected
        // naming `spec`, the parameter that carries both knobs, rather than surfacing as a
        // bound on the buffer BuildInitialFlight allocates for itself: a caller cannot set
        // that buffer and would be reading a diagnostic about a parameter it never passed.
        //
        // 65527 bytes of stream is the boundary itself: the data alone exactly fills a UDP
        // payload, leaving nothing for the header, the frame fields or the 16-byte tag.
        var spec = new TlsQuicConnectionSpec { PaddingTarget = 1200 };
        using var keys = VectorKeys();

        var exception = Assert.Throws<ArgumentException>(() =>
            TlsQuicDatagramBuilder.BuildInitialFlight(
                spec, Template(keys, VectorPlan()), CryptoStream(65527), SentAt));

        Assert.Equal("spec", exception.ParamName);
        Assert.Contains("65527-byte UDP payload", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnsplitFlightIsOneCryptoFrameInOneDatagram()
    {
        // Both flight-plan arrays empty. The spec's own words: an empty byte-count list
        // "means one frame carrying everything", and an empty datagram plan means one
        // datagram. 163 bytes of stream is one frame at offset 0:
        //   06 00 40A3 <163 bytes> = 1 + 1 + 2 + 163 = 167 bytes of payload, so
        //   paddingFrames = 1200 - 28 - 2 - 167 - 16 = 987.
        var stream = CryptoStream(163);
        using var keys = VectorKeys();

        var flight = TlsQuicDatagramBuilder.BuildInitialFlight(
            Spec(1200), Template(keys, VectorPlan()), stream, SentAt);

        var datagram = Assert.Single(flight);
        Assert.Equal(1200, datagram.Length);
        Assert.Equal(
            "060040A3" + Hex(stream, 0, 163) + new string('0', 2 * 987),
            Convert.ToHexString(OpenVector(keys, datagram)),
            ignoreCase: true);
    }

    [Fact]
    public void ASplitWithNoDatagramPlanPutsEveryFrameInOneDatagram()
    {
        // The other single-empty case, and the one that separates the two arrays: the same
        // 163 bytes, split into two frames, still one datagram. A builder that derived the
        // datagram grouping from the split would produce two.
        //   06 00   4064 <100 bytes> = 104
        //   06 4064 3F   <63 bytes>  =  67
        //   171 bytes, so paddingFrames = 1200 - 28 - 2 - 171 - 16 = 983.
        var stream = CryptoStream(163);
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            InitialCryptoFrameByteCounts = [100, 63],
        };
        using var keys = VectorKeys();

        var flight = TlsQuicDatagramBuilder.BuildInitialFlight(
            spec, Template(keys, VectorPlan()), stream, SentAt);

        var datagram = Assert.Single(flight);
        Assert.Equal(
            "06004064" + Hex(stream, 0, 100) + "0640643F" + Hex(stream, 100, 63)
                + new string('0', 2 * 983),
            Convert.ToHexString(OpenVector(keys, datagram)),
            ignoreCase: true);
    }

    [Fact]
    public void TheFinalCryptoFrameMayBeShorterThanTheSplitDeclares()
    {
        // TlsQuicConnectionSpec.InitialCryptoFrameByteCounts: "The final element may be
        // short if the stream runs out." 130 bytes against a 100/60 split gives a second
        // frame of 30, not 60 - and its Length varint is 0x1E, one byte, where a 60-byte
        // frame would write 0x3C.
        var frames = TlsQuicDatagramBuilder.PlanInitialCryptoFrames(
            new TlsQuicConnectionSpec { InitialCryptoFrameByteCounts = [100, 60] },
            CryptoStream(130));

        var datagram = Assert.Single(frames);
        Assert.Equal(new[] { 0UL, 100UL }, datagram.Select(f => f.Offset).ToArray());
        Assert.Equal(new[] { 100, 30 }, datagram.Select(f => f.Data.Length).ToArray());
    }

    [Fact]
    public void ASplitWhoseNonFinalFrameOutrunsTheStreamIsRejected()
    {
        // Only the FINAL element may be short, so a 90-byte stream against a 100/60 split
        // is a spec that describes a longer stream than it was handed. Distinct from the
        // case below and reported distinctly: this one fails at frame 0.
        var exception = Assert.Throws<ArgumentException>(() =>
            TlsQuicDatagramBuilder.PlanInitialCryptoFrames(
                new TlsQuicConnectionSpec { InitialCryptoFrameByteCounts = [100, 60] },
                CryptoStream(90)));

        Assert.Contains("only the final frame may be short", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ASplitThatDoesNotCoverTheWholeStreamIsRejected()
    {
        // The opposite direction: the split is satisfiable but leaves bytes behind, so the
        // flight would send a truncated ClientHello and the peer would wait forever for the
        // rest. Silently dropping the tail is the failure this rejects.
        var exception = Assert.Throws<ArgumentException>(() =>
            TlsQuicDatagramBuilder.PlanInitialCryptoFrames(
                new TlsQuicConnectionSpec { InitialCryptoFrameByteCounts = [50] },
                CryptoStream(163)));

        Assert.Contains("covers 50 bytes", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ASplitWhoseFinalFrameHasNothingLeftToCarryIsRejected()
    {
        // The third reachable path through the same walk, and the only one that reaches the
        // final element with nothing remaining: 163/5 against a 163-byte stream fills frame
        // 0 exactly and leaves frame 1 with zero bytes. A zero-length CRYPTO frame is what
        // the spec's own "every element must be at least 1" bound exists to prevent one
        // step earlier, and this is where the stream, rather than the spec, produces one.
        var exception = Assert.Throws<ArgumentException>(() =>
            TlsQuicDatagramBuilder.PlanInitialCryptoFrames(
                new TlsQuicConnectionSpec { InitialCryptoFrameByteCounts = [163, 5] },
                CryptoStream(163)));

        Assert.Contains("no stream left to carry", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyCryptoStreamIsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            TlsQuicDatagramBuilder.PlanInitialCryptoFrames(
                new TlsQuicConnectionSpec(), ReadOnlyMemory<byte>.Empty));
    }

    [Fact]
    public void ADatagramWithNoPacketsIsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            TlsQuicDatagramBuilder.BuildDatagram(
                Spec(1200), [], SentAt, new byte[1200], null));
    }

    [Fact]
    public void ADestinationTooSmallForTheExpandedDatagramIsRejected()
    {
        // The bound lives in TlsQuicPacketBuilder.Build, where the bytes are written; this
        // pins that expanding to a target the buffer cannot hold reaches it rather than
        // being clamped or silently truncated to a short Initial datagram.
        using var keys = VectorKeys();
        var packet = Template(keys, VectorPlan()) with { Frames = VectorFrames() };

        var exception = Assert.Throws<ArgumentException>(() =>
            TlsQuicDatagramBuilder.BuildDatagram(
                Spec(1250), [packet], SentAt, new byte[1200], null));

        Assert.Equal("destination", exception.ParamName);
    }

    [Fact]
    public void ATargetThatIsReachedOnlyWithZeroPaddingAtAnInconsistentWidthIsRejected()
    {
        // The other side of the already-full pre-check, and the case that separates
        // "no PADDING is needed" from "no PADDING count works". A CRYPTO frame carrying
        // 1151 bytes is 1 + 1 + 2 + 1151 = 1155 bytes of payload, so at the narrowest
        // width the count comes out at exactly 0 - the pre-check's boundary, not below it.
        // But a Length of 4 + 1155 + 0 + 16 = 1175 needs two bytes, not one, and every
        // wider candidate needs a negative count. So the target is unreachable and must be
        // rejected: returning 0 here would emit a 1201-byte datagram against a 1200-byte
        // target, one byte wrong and completely silent.
        using var keys = VectorKeys();
        var frames = new[]
        {
            new TlsQuicFrame { RawType = 0x06, Offset = 0, Data = CryptoStream(1151) },
        };

        Assert.Throws<ArgumentException>(() => BuildOne(keys, Spec(1200), VectorPlan(), frames, out _));
    }

    [Fact]
    public void ARejectedCryptoVarintWidthLeavesNoPartialFrameBehind()
    {
        // TlsQuicStreamFrames' own contract, which the two new width parameters could have
        // broken quietly: "Every check runs before the first byte is written, so a
        // rejection never leaves a partial frame in the caller's buffer." Resolving the
        // widths at the Write calls instead of ahead of them would leave the 0x06 frame
        // type - and, for a bad Length width, an Offset too - in the caller's list.
        var destination = new List<byte> { 0x9C };
        var frame = new TlsQuicFrame { RawType = 0x06, Offset = 300, Data = Convert.FromHexString("7E8D9A") };

        Assert.Throws<ArgumentOutOfRangeException>(() => TlsQuicStreamFrames.WriteCryptoFrameFields(
            destination, frame, TlsQuicVarintWidth.OneByte));

        Assert.Equal(new byte[] { 0x9C }, destination.ToArray());
    }

    [Fact]
    public void ARetryPacketCannotBeCoalescedIntoADatagram()
    {
        // RFC 9000 s12.2 makes Retry unfollowable in a datagram because s17.2.5 gives it no
        // Length field. Nothing in this builder guards it: TlsQuicPacketBuilder.Build
        // rejects Retry outright - it has no packet number and no packet protection - so
        // the rule is enforced one layer down and a second guard here would be a branch no
        // input can reach. This pins the delegation, so a future builder that started
        // swallowing a packet-level failure would be visible.
        using var keys = VectorKeys();
        var packet = Template(keys, VectorPlan() with { Type = TlsQuicLongPacketType.Retry }) with
        {
            Frames = VectorFrames(),
        };

        Assert.Throws<ArgumentException>(() =>
            TlsQuicDatagramBuilder.BuildDatagram(
                Spec(1200), [packet], SentAt, new byte[1200], null));
    }

    [Fact]
    public void AFlightTemplateCarryingItsOwnFramesIsRejected()
    {
        using var keys = VectorKeys();
        var template = Template(keys, VectorPlan()) with { Frames = VectorFrames() };

        var exception = Assert.Throws<ArgumentException>(() =>
            TlsQuicDatagramBuilder.BuildInitialFlight(
                Spec(1200), template, CryptoStream(163), SentAt));

        Assert.Equal("template", exception.ParamName);
    }

    // PING then CRYPTO, in that order and never merged or sorted - the same eight bytes
    // task 4b's tests use, so the two files' hand-derived arithmetic starts from one shape.
    // s19.2 makes PING the single byte 0x01; s19.6's CRYPTO is type 0x06, an Offset varint,
    // a Length varint and the data. Offset 64 is the first value s16 Table 4 pushes out of
    // the 1-byte form, so it encodes as 0x4040.
    private const string VectorPayloadHex = "01064040037E8D9A";

    private static TlsQuicFrame[] VectorFrames() =>
    [
        new() { RawType = 0x01 },
        CryptoFrame(64, "7E8D9A"),
    ];

    private static TlsQuicFrame CryptoFrame(ulong offset, string dataHex) => new()
    {
        RawType = 0x06,
        Offset = offset,
        Data = Convert.FromHexString(dataHex),
    };

    [Theory]
    // Two shapes of "followed by", because the guard walks predecessors and one row would
    // pin only the arrangement it happened to use: a short header followed by a long one,
    // and a short header followed by another short one.
    [InlineData(false)]
    [InlineData(true)]
    public void NothingMayBeCoalescedAfterAShortHeaderPacket(bool followerIsShort)
    {
        // RFC 9000 s12.2, verbatim from rfc9000-section12-packets-and-frames.txt lines
        // 100-103: "Retry packets (Section 17.2.5), Version Negotiation packets
        // (Section 17.2.1), and packets with a short header (Section 17.3) do not contain
        // a Length field and so cannot be followed by other packets in the same UDP
        // datagram." The same section says it again at lines 79-80: "A packet with a short
        // header does not include a length, so it can only be the last packet included in
        // a UDP datagram."
        //
        // The read side of this already exists and is what makes the rule concrete rather
        // than stylistic: TlsQuicPacketHeader.TryReadShortHeader sets `consumed` to the
        // whole remaining datagram, so any follower's bytes are read as part of the
        // payload above them. A sender that emitted one would be feeding its own parser
        // bytes it cannot recover.
        using var keys = VectorKeys();
        var shortPacket = Template(keys, ShortVectorPlan()) with
        {
            Frames = new[] { new TlsQuicFrame { RawType = 0x01 } },
        };
        var follower = followerIsShort
            ? shortPacket with { Plan = ShortVectorPlan() with { PacketNumber = 43 } }
            : shortPacket with
            {
                Plan = VectorPlan() with
                {
                    Type = TlsQuicLongPacketType.Handshake,
                    Token = ReadOnlyMemory<byte>.Empty,
                    SourceConnectionId = ReadOnlyMemory<byte>.Empty,
                },
            };

        var thrown = Assert.Throws<ArgumentException>(() => TlsQuicDatagramBuilder.BuildDatagram(
            Spec(1200), [shortPacket, follower], SentAt, new byte[1200]));
        Assert.Equal("packets", thrown.ParamName);

        // AND THE ARRANGEMENT s12.2 CALLS TYPICAL IS STILL BUILDABLE, which is what makes
        // the rejection above about "followed by" rather than about short headers at all:
        // "A sender can coalesce multiple QUIC packets (typically a Handshake packet and a
        // 1-RTT packet) into one UDP datagram." Neither packet is an Initial one, so
        // s14.1's expansion does not apply and the datagram is exactly the two packets.
        var handshake = shortPacket with
        {
            Plan = VectorPlan() with
            {
                Type = TlsQuicLongPacketType.Handshake,
                Token = ReadOnlyMemory<byte>.Empty,
                SourceConnectionId = ReadOnlyMemory<byte>.Empty,
            },
        };
        var sent = new List<TlsQuicSentPacket>();
        TlsQuicDatagramBuilder.BuildDatagram(
            Spec(1200), [handshake, shortPacket], SentAt, new byte[1200], sent);
        Assert.Equal(
            new[] { TlsQuicEncryptionLevel.Handshake, TlsQuicEncryptionLevel.Application },
            sent.Select(p => p.Level).ToArray());
    }

    [Fact]
    public void AShortHeaderHasNoSourceConnectionIdToCompare()
    {
        // s12.2's "Senders MUST NOT coalesce QUIC packets with different connection IDs
        // into a single UDP datagram" is compared on both IDs for a long header, because
        // s17.2 gives it both. s17.3.1 gives the short header only a Destination
        // Connection ID, so the source half has nothing to compare and is skipped: a
        // Handshake packet with a non-empty Source Connection ID - which is what every
        // client but Chromium sends - coalesced with a 1-RTT packet is exactly s12.2's own
        // typical example, and comparing an absent field against a present one would
        // reject it.
        //
        // The destination half is NOT skipped, and the second half of this test is that
        // row: a short header whose Destination Connection ID differs is still rejected,
        // so this is a narrowing of the comparison and not a hole in it.
        using var keys = VectorKeys();
        var handshake = Template(keys, VectorPlan() with
        {
            Type = TlsQuicLongPacketType.Handshake,
            Token = ReadOnlyMemory<byte>.Empty,
        }) with
        {
            Frames = new[] { new TlsQuicFrame { RawType = 0x01 } },
        };
        Assert.False(handshake.Plan.SourceConnectionId.IsEmpty);

        var oneRtt = handshake with { Plan = ShortVectorPlan() };
        Assert.True(oneRtt.Plan.SourceConnectionId.IsEmpty);

        var sent = new List<TlsQuicSentPacket>();
        TlsQuicDatagramBuilder.BuildDatagram(
            Spec(1200), [handshake, oneRtt], SentAt, new byte[1200], sent);
        Assert.Equal(2, sent.Count);

        var elsewhere = oneRtt with
        {
            Plan = ShortVectorPlan() with
            {
                DestinationConnectionId = Convert.FromHexString("B1B2B3B4B5B6B7B9"),
            },
        };
        var thrown = Assert.Throws<ArgumentException>(() => TlsQuicDatagramBuilder.BuildDatagram(
            Spec(1200), [handshake, elsewhere], SentAt, new byte[1200]));
        Assert.Equal("packets", thrown.ParamName);
    }

    [Fact]
    public void AnInitialCoalescedWithAShortHeaderPacketIsPaddedInTheShortHeaderOne()
    {
        // HAND-DERIVED, and the case that makes SolvePaddingFrameCount's short-header
        // branch reachable: s14.1 expands the datagram inside its LAST packet, s12.2 makes
        // a short-header packet the last one, so the two meet.
        //
        // Initial packet: identical to AnInitialCoalescedWithAHandshakePacketIsPaddedInThe
        //   LastPacket's first packet - payload 06 00 03 7E8D9A = 6 bytes, Length =
        //   4 + 6 + 16 = 26 encoded in one byte as 0x1A, so 24 + 1 + 4 + 6 + 16 = 51 bytes.
        // Short-header packet: RFC 9000 s17.3.1 gives it byte 0, the 8-byte Destination
        //   Connection ID and a 4-byte Packet Number and NOTHING ELSE - no Version, no
        //   Source Connection ID, no Token, no Length - so its header is 1 + 8 + 4 = 13
        //   bytes flat. THERE IS NO s16 TABLE 4 SEARCH HERE, because there is no Length
        //   varint whose own width could depend on the count it helps determine; the
        //   circularity GetLongHeaderLength documents simply does not arise.
        //   budget = 1200 - 51 = 1149, payload = one PING = 1 byte, tag = 16, so
        //   paddingFrames = 1149 - 13 - 1 - 16 = 1119 and the packet is
        //   13 + 1 + 1119 + 16 = 1149 bytes. 51 + 1149 = 1200.
        using var keys = VectorKeys();
        var initial = Template(keys, VectorPlan()) with { Frames = [CryptoFrame(0, "7E8D9A")] };
        var oneRtt = initial with
        {
            Plan = ShortVectorPlan() with
            {
                DestinationConnectionId = Convert.FromHexString(VectorDestinationConnectionIdHex),
                PacketNumberEncodedLength = 4,
            },
            Frames = [new TlsQuicFrame { RawType = 0x01 }],
        };

        var buffer = new byte[1200];
        var sent = new List<TlsQuicSentPacket>();
        var written = TlsQuicDatagramBuilder.BuildDatagram(
            Spec(1200), [initial, oneRtt], SentAt, buffer, sent);

        Assert.Equal(1200, written);
        Assert.Equal(new[] { 51, 1149 }, sent.Select(p => p.Size).ToArray());
        Assert.Equal(
            new[] { TlsQuicEncryptionLevel.Initial, TlsQuicEncryptionLevel.Application },
            sent.Select(p => p.Level).ToArray());

        // The short header's Destination Connection ID, in the clear at offsets 52..59:
        // RFC 9001 s5.4 masks byte 0 and the packet number and nothing else.
        Assert.Equal(
            VectorDestinationConnectionIdHex,
            Convert.ToHexString(buffer, 52, 8),
            ignoreCase: true);

        // PADDING TRAILS, as it does in the long-header sibling: the default
        // InitialFrameOrder never names PING, so PaddingLeads is false.
        Assert.Equal(
            "01" + new string('0', 2 * 1119),
            Convert.ToHexString(Open(keys, buffer[51..], 9, ShortVectorPacketNumber)),
            ignoreCase: true);
    }

    // ==============================================================================
    // THE MUTATION LEDGER - TASK B9 (TlsQuicDatagramBuilder's flight plan, and this section)
    // ==============================================================================
    //
    //   ROWS BELOW                   15  = B9-1 to B9-15 with no gaps
    //   KILLED                       15  = 15 rows, less 0 survivors
    //   SURVIVED                      0
    //                                     15 + 0 = 15
    //
    //   HOW. mutate-b9.py in a private git worktree detached at f83331f; every run rebuilt
    //   with `dotnet build --no-incremental` and then ran `dotnet test --filter
    //   FullyQualifiedName~Quic --no-build`. Each run's TOTAL case count was checked against
    //   a floor of 1937 and a run below it would have been REJECTED rather than read - an
    //   aborted run prints an ordinary "Failed: 0, Passed: <m>" line that is
    //   indistinguishable from a survivor. All seventeen runs reported 1937 cases.
    //
    //   THE HARNESS WAS PROVED IN BOTH DIRECTIONS BEFORE THE ROWS, and neither control is
    //   counted among them. A known-bad edit - MlKem768.EncapsulationKeySize wrong by one,
    //   which breaks the 1216 = 1184 + 32 cross-check - was KILLED at 9 failures. An inert
    //   edit - one added comment line in TlsQuicDatagramBuilder.cs - SURVIVED.
    //
    //   1  the split budget moves up past the advertised ceiling            KILLED  6
    //   2  the split budget moves down but stays inside the legal band      KILLED  8
    //   3  the split budget outgrows the ClientHello, one datagram again    KILLED  6
    //   4  the datagram count rounds up one too eagerly                     KILLED  3
    //   5  the datagram count loses its final partial datagram              KILLED  8
    //   6  the last frame declares the whole budget, not the remainder      KILLED  7
    //   7  the frames-per-datagram half of the plan is dropped              KILLED 10
    //   8  the zero-budget guard is removed                                 KILLED  2
    //   9  the empty-stream guard is removed                                KILLED  2
    //   10 the short final frame is planned first instead of last           KILLED  6
    //   11 CRYPTO stream offsets restart at 0 in every frame                KILLED  6
    //   12 the datagram grouping re-reads the frame list from the start     KILLED  6
    //   13 every datagram of the flight reuses the template's packet number KILLED  4
    //   14 the planner ignores its budget argument and uses the preset      KILLED  2
    //   15 the final short frame is padded out to a full budget's worth     KILLED  5
    //
    //   ROWS 1, 2 AND 3 ARE THE SIZE-BOUNDARY ONES AND THEY ARE THE VACUITY HAZARD THIS
    //   SECTION WAS BUILT AROUND. The input straddles the boundary in all three: the
    //   ClientHello is 1512 bytes against a 1400-byte budget, so it is longer than the
    //   budget but shorter than twice it, and every one of the three moves lands somewhere
    //   different.
    //     Row 3 raises the budget to 1600, ABOVE the stream, so the flight collapses to one
    //       datagram and the "more than one" clause catches it. 1512 < 1600 is the straddle.
    //     Row 1 raises it to 1500, still BELOW the stream, so the flight is still two
    //       datagrams - the count says nothing - but the first becomes
    //       50 + 1500 = 1550 bytes, which is 78 over the capture's 1472 ceiling. Only the
    //       per-datagram ceiling check catches it. 1512 > 1500 is the straddle.
    //     Row 2 lowers it to 1300: still two datagrams, and BOTH still land inside
    //       [1200, 1472] at 1350 and 1200. Neither the count clause nor the band clause sees
    //       it at all. Only the exact [1450, 1200] and exact [1400, 112] assertions catch it
    //       - which is why the exact sizes are asserted as well as the band, and why row 2 is
    //       in this ledger rather than left out as "obviously covered".
    // ==============================================================================

    // ------------------------------------------------------------------------------
    // Task B9: the Initial flight plan the post-quantum key share forces.
    //
    // EVERY NUMBER THESE TESTS COMPARE AGAINST IS READ OUT OF A CHECKED-IN SOURCE, never
    // typed here: 1216 and 32 out of the Brave capture's key-share sentence, 1472 out of its
    // transport-parameter table, and s14.1's 1200-byte floor out of the RFC extract - past
    // its line wrap, which is where the "of 1200 bytes" half of the sentence lives. A test
    // that typed those four would compare this file against itself.
    //
    // THE SIZES ARE ASSERTED EXACTLY AND NOT AS A RANGE. "More than one datagram, each
    // between 1200 and 1472" is satisfied by a wide band of wrong split points - 1300 gives
    // [1350, 1200] and passes it too - so the band is asserted AS WELL AS, never INSTEAD OF,
    // the exact [1450, 1200] the shipped preset produces.
    // ------------------------------------------------------------------------------

    [Fact]
    public void TheCapturesPostQuantumKeyShareIsTheSumOfTheTwoNamedConstantsInTheTree()
    {
        // Step 1 of B9, and a genuine cross-check rather than a restatement of either side:
        // the capture states one number, 1216, and the tree states it as a SUM of two named
        // constants (X25519MlKem768KeyShare.cs:9). The capture happens to state the second
        // addend too - "plus X25519 at 32 bytes" - so all three relations are checkable and
        // a test that only compared 1216 to 1216 would miss an ML-KEM constant that was
        // wrong by the same amount X25519's was.
        var capture = File.ReadAllText(Path.Combine(RepositoryRoot(), Brave151CapturePath));
        var hybrid = Regex.Match(capture, @"X25519MLKEM768 at (\d+) bytes");
        var classical = Regex.Match(capture, @"plus X25519 at (\d+) bytes");
        Assert.True(hybrid.Success, "The capture's X25519MLKEM768 key-share size was not found.");
        Assert.True(classical.Success, "The capture's X25519 key-share size was not found.");

        var hybridSize = int.Parse(hybrid.Groups[1].Value, CultureInfo.InvariantCulture);
        var classicalSize = int.Parse(classical.Groups[1].Value, CultureInfo.InvariantCulture);

        // The constants are the 'expected' side only because xUnit2000 insists a constant
        // goes there; the direction of the comparison is the capture's either way.
        Assert.Equal(X25519MlKem768KeyShare.ClientShareSize, hybridSize);
        Assert.Equal(X25519.KeyLength, classicalSize);
        Assert.Equal(MlKem768.EncapsulationKeySize, hybridSize - classicalSize);
    }

    [Fact]
    public void TheCapturesKeyShareForcesAMultiDatagramInitialAndEveryDatagramFitsThePath()
    {
        // Steps 2 and 3 of B9, and the capture's own conclusion 5: "The post-quantum key
        // share forces a multi-datagram Initial, so that path is required, not optional."
        //
        // s14.1's expansion rule is PER DATAGRAM - "all UDP datagrams carrying Initial
        // packets" - so the floor is checked on each entry of the returned list and never on
        // the flight's total, which is the mistake the builder's own summary warns against.
        // The ceiling is the capture's advertised max_udp_payload_size and is checked the
        // same way.
        //
        // THE ARITHMETIC, from this class's header comment plus s19.6's CRYPTO fields:
        //   the ClientHello encodes to 1512 bytes, so the preset's 1400-byte budget cuts it
        //   at [1400, 112] - it STRADDLES the budget, which is what makes the split point
        //   observable at all;
        //   datagram 0 = 28 header + 2 Length + (1 Type + 1 Offset + 2 Length + 1400) + 16
        //              = 1450, already over the 1200 target so no PADDING is added;
        //   datagram 1 = 28 + 2 + (1 + 2 Offset + 2 Length + 112) + 16 = 163 raw, which
        //              s14.1 expands to the 1200-byte target.
        var floor = SectionFourteenOneFloor();
        var ceiling = AdvertisedMaximumUdpPayload();
        var clientHello = Brave151ClientHello();
        var (byteCounts, framesPerDatagram) = TlsQuicDatagramBuilder.PlanInitialFlightSplit(
            clientHello.Length,
            TlsQuicDatagramBuilder.Brave151InitialCryptoStreamBytesPerDatagram);
        using var keys = VectorKeys();

        var flight = TlsQuicDatagramBuilder.BuildInitialFlight(
            SplitSpec(byteCounts, framesPerDatagram),
            Template(keys, VectorPlan()),
            clientHello,
            SentAt);

        Assert.Equal(1512, clientHello.Length);
        Assert.Equal(new[] { 1400, 112 }, byteCounts);
        Assert.Equal(new[] { 1, 1 }, framesPerDatagram);
        Assert.True(flight.Count > 1, $"The flight is {flight.Count} datagram(s), not more than one.");
        Assert.Equal(new[] { 1450, 1200 }, flight.Select(datagram => datagram.Length).ToArray());

        // Per datagram, and named in the failure message so a regression says WHICH one.
        for (var index = 0; index < flight.Count; index++)
        {
            Assert.True(
                flight[index].Length >= floor,
                $"Datagram {index} is {flight[index].Length} bytes, below s14.1's {floor}.");
            Assert.True(
                flight[index].Length <= ceiling,
                $"Datagram {index} is {flight[index].Length} bytes, above the advertised {ceiling}.");
        }

        Assert.Equal(1200, floor);
        Assert.Equal(1472, ceiling);
    }

    [Fact]
    public void TheSameClientHelloWithTheSplitRemovedIsOneDatagramOverTheAdvertisedCeiling()
    {
        // FINDING 5, PINNED RATHER THAN FIXED-AND-FORGOTTEN. The default spec's two flight
        // arrays are empty, which means one CRYPTO frame in one datagram, and this input is
        // the one the capture says Chromium answers with two. Nothing throws, no gate goes
        // red, and the capture's lines 30-33 put per-datagram Initial flight plans among
        // what neither verification endpoint inspects - so this test is the only thing in
        // the repository that can report the silent failure at all.
        //
        // 1562 = 28 + 2 + (1 Type + 1 Offset + 2 Length + 1512) + 16, and it is asserted
        // exactly because "over 1472" is also true of a flight that went wrong some other
        // way. It is 90 bytes over the ceiling the capture advertises.
        var ceiling = AdvertisedMaximumUdpPayload();
        var clientHello = Brave151ClientHello();
        using var keys = VectorKeys();

        var flight = TlsQuicDatagramBuilder.BuildInitialFlight(
            Spec(1200), Template(keys, VectorPlan()), clientHello, SentAt);

        var datagram = Assert.Single(flight);
        Assert.Equal(1562, datagram.Length);
        Assert.True(datagram.Length > ceiling, "The unsplit flight no longer overshoots.");
        Assert.Equal(90, datagram.Length - ceiling);
    }

    [Fact]
    public void TheSplitsCryptoOffsetsRunContiguouslyFromZeroAndReassembleTheClientHello()
    {
        // Read back through the real frame parser, not through the plan the builder was
        // handed: TlsQuicFrames.TryReadFrame over each datagram's decrypted payload, which
        // is the same reader a server runs. A split that duplicated a byte, dropped one, or
        // numbered the second frame's offset from its own datagram rather than from the
        // stream would still produce two datagrams of legal size and would still satisfy
        // every other test in this section.
        var clientHello = Brave151ClientHello();
        var (byteCounts, framesPerDatagram) = TlsQuicDatagramBuilder.PlanInitialFlightSplit(
            clientHello.Length,
            TlsQuicDatagramBuilder.Brave151InitialCryptoStreamBytesPerDatagram);
        using var keys = VectorKeys();

        var flight = TlsQuicDatagramBuilder.BuildInitialFlight(
            SplitSpec(byteCounts, framesPerDatagram),
            Template(keys, VectorPlan()),
            clientHello,
            SentAt);

        var crypto = CryptoFramesOf(keys, flight);

        Assert.Equal(new[] { 0UL, 1400UL }, crypto.Select(frame => frame.Offset).ToArray());
        Assert.Equal(new[] { 1400, 112 }, crypto.Select(frame => frame.Data.Length).ToArray());

        // Contiguous from 0, stated as the running sum rather than as the two offsets above
        // so that a longer flight would be checked the same way.
        var expected = 0UL;
        foreach (var frame in crypto)
        {
            Assert.Equal(expected, frame.Offset);
            expected += (ulong)frame.Data.Length;
        }
        Assert.Equal((ulong)clientHello.Length, expected);

        var reassembled = crypto.SelectMany(frame => frame.Data.ToArray()).ToArray();
        Assert.Equal(clientHello, reassembled);
    }

    [Fact]
    public void ACallerSuppliedSplitIsHonouredExactlyAndThePresetIsNotConsulted()
    {
        // THE USER'S DIRECTIVE, WITNESSED: "everything must be configurable if different
        // clients/browsers/apps/systems could send a different value". A different client
        // splits its Initial flight differently, so a caller states its own frame byte
        // counts and its own frames-per-datagram and gets exactly those - three frames of
        // 500/500/512 grouped two-then-one, which is a shape PlanInitialFlightSplit can
        // never produce (its budget is uniform and it puts one frame in each datagram).
        // Deliberately NOT the preset's shape, so a builder that ignored the spec and used
        // the preset would produce two frames of 1400/112 in two datagrams and fail here.
        var clientHello = Brave151ClientHello();
        using var keys = VectorKeys();

        var flight = TlsQuicDatagramBuilder.BuildInitialFlight(
            SplitSpec([500, 500, 512], [2, 1]),
            Template(keys, VectorPlan()),
            clientHello,
            SentAt);

        Assert.Equal(2, flight.Count);

        // Per datagram, because the grouping is half of what was asked for: the first
        // datagram carries two CRYPTO frames and the second carries one.
        var first = CryptoFramesOf(keys, [flight[0]]);
        var second = CryptoFramesOf(keys, [flight[1]], firstPacketNumber: VectorPacketNumber + 1);
        Assert.Equal(new[] { 0UL, 500UL }, first.Select(frame => frame.Offset).ToArray());
        Assert.Equal(new[] { 500, 500 }, first.Select(frame => frame.Data.Length).ToArray());
        Assert.Equal(new[] { 1000UL }, second.Select(frame => frame.Offset).ToArray());
        Assert.Equal(new[] { 512 }, second.Select(frame => frame.Data.Length).ToArray());
        Assert.Equal(
            clientHello,
            first.Concat(second).SelectMany(frame => frame.Data.ToArray()).ToArray());
    }

    [Theory]
    // The budget itself and the two lengths either side of it - the only place the frame
    // count can change - then the same three around twice the budget.
    [InlineData(1399, new[] { 1399 })]
    [InlineData(1400, new[] { 1400 })]
    [InlineData(1401, new[] { 1400, 1 })]
    [InlineData(2799, new[] { 1400, 1399 })]
    [InlineData(2800, new[] { 1400, 1400 })]
    [InlineData(2801, new[] { 1400, 1400, 1 })]
    [InlineData(1, new[] { 1 })]
    public void ThePlannedSplitStraddlesItsBudgetExactly(int streamLength, int[] expected)
    {
        var (byteCounts, framesPerDatagram) = TlsQuicDatagramBuilder.PlanInitialFlightSplit(
            streamLength, TlsQuicDatagramBuilder.Brave151InitialCryptoStreamBytesPerDatagram);

        Assert.Equal(expected, byteCounts);
        Assert.Equal(Enumerable.Repeat(1, expected.Length), framesPerDatagram);
        Assert.Equal(streamLength, byteCounts.Sum());
    }

    [Fact]
    public void TheBudgetIsAKnobAndNotThePresetsNumber()
    {
        // A different client, a different budget: the same stream cut at 600 rather than at
        // the capture's 1400. A planner that ignored its argument and used the preset would
        // return [1400, 112] here.
        var (byteCounts, framesPerDatagram) =
            TlsQuicDatagramBuilder.PlanInitialFlightSplit(1512, 600);

        Assert.Equal(new[] { 600, 600, 312 }, byteCounts);
        Assert.Equal(new[] { 1, 1, 1 }, framesPerDatagram);
    }

    [Fact]
    public void EveryPlannedSplitIsOneTheSpecAndTheBuilderBothAccept()
    {
        // "Nothing on these paths throws for any input", checked rather than asserted in
        // prose. The spec's cross-check between the two arrays, its per-element lower bound,
        // and SplitIntoFrames' two rejections - a non-final frame that outruns the stream,
        // and a split that does not cover it - are all reachable from a hand-written plan,
        // and none of them may be reachable from a planned one. Every length from 1 to twice
        // the budget, at three budgets including 1.
        foreach (var budget in new[] { 1, 97, TlsQuicDatagramBuilder.Brave151InitialCryptoStreamBytesPerDatagram })
        {
            for (var length = 1; length <= 2 * TlsQuicDatagramBuilder.Brave151InitialCryptoStreamBytesPerDatagram; length++)
            {
                var (byteCounts, framesPerDatagram) =
                    TlsQuicDatagramBuilder.PlanInitialFlightSplit(length, budget);
                var frames = TlsQuicDatagramBuilder.PlanInitialCryptoFrames(
                    SplitSpec(byteCounts, framesPerDatagram), CryptoStream(length));

                Assert.Equal(byteCounts.Length, frames.Count);
                Assert.Equal(length, frames.Sum(datagram => datagram.Sum(f => f.Data.Length)));
            }
        }
    }

    [Theory]
    [InlineData(0, 1400, "cryptoStreamLength")]
    [InlineData(-1, 1400, "cryptoStreamLength")]
    [InlineData(1512, 0, "cryptoStreamBytesPerDatagram")]
    [InlineData(1512, -1, "cryptoStreamBytesPerDatagram")]
    public void APlanWithNoStreamOrNoBudgetIsRejectedNamingTheArgument(
        int streamLength, int budget, string parameterName)
    {
        // A zero budget is the one that matters: unchecked it is a division by zero, and
        // clamped it would describe a flight of infinitely many empty datagrams.
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            TlsQuicDatagramBuilder.PlanInitialFlightSplit(streamLength, budget));

        Assert.Equal(parameterName, exception.ParamName);
    }

    // ------------------------------------------------------------------------------
    // Task B9 helpers.
    // ------------------------------------------------------------------------------

    private const string Brave151CapturePath =
        "docs/superpowers/specs/reference-captures/" +
        "2026-08-16-brave-151-http3-impersonate-pro.md";

    private const string Rfc9000Section14Path =
        "docs/superpowers/specs/reference-captures/" +
        "rfc9000-section14-datagram-size-and-pmtu.txt";

    /// <summary>s14.1's floor, read out of the extract past the line wrap that splits
    /// "maximum datagram" from "size of 1200 bytes".</summary>
    private static int SectionFourteenOneFloor()
    {
        var extract = File.ReadAllText(Path.Combine(RepositoryRoot(), Rfc9000Section14Path));
        var quoted = Regex.Match(
            Regex.Replace(extract.ReplaceLineEndings(" "), @"\s+", " "),
            @"expand the payload of all UDP datagrams carrying Initial packets to at least "
            + @"the smallest allowed maximum datagram size of (\d+) bytes");
        Assert.True(quoted.Success, "RFC 9000 s14.1's expansion sentence was not found in the extract.");
        return int.Parse(quoted.Groups[1].Value, CultureInfo.InvariantCulture);
    }

    /// <summary>The capture's own max_udp_payload_size row, which is what this client tells a
    /// server it is willing to receive and therefore the ceiling its own Initial respects.
    /// </summary>
    private static int AdvertisedMaximumUdpPayload()
    {
        var capture = File.ReadAllText(Path.Combine(RepositoryRoot(), Brave151CapturePath));
        var row = Regex.Match(capture, @"\|\s*`max_udp_payload_size`\s*\|\s*(\d+)\s*\|");
        Assert.True(row.Success, "The capture's max_udp_payload_size row was not found.");
        return int.Parse(row.Groups[1].Value, CultureInfo.InvariantCulture);
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !Directory.Exists(Path.Combine(directory.FullName, "src", "SharpTls", "Quic")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory.FullName;
    }

    private static TlsQuicConnectionSpec SplitSpec(
        ImmutableArray<int> byteCounts, ImmutableArray<int> framesPerDatagram) => new()
        {
            PaddingTarget = 1200,
            InitialCryptoFrameByteCounts = byteCounts,
            InitialCryptoFramesPerDatagram = framesPerDatagram,
        };

    /// <summary>Every CRYPTO frame of a flight, in order, parsed back out of the decrypted
    /// payloads by the library's own frame reader.</summary>
    private static List<TlsQuicFrame> CryptoFramesOf(
        TlsQuicPacketProtectionKeys keys,
        IReadOnlyList<byte[]> flight,
        ulong firstPacketNumber = VectorPacketNumber)
    {
        var crypto = new List<TlsQuicFrame>();
        for (var index = 0; index < flight.Count; index++)
        {
            var payload = (ReadOnlyMemory<byte>)OpenVector(
                keys, flight[index], firstPacketNumber + (ulong)index);
            var offset = 0;
            while (offset < payload.Length)
            {
                Assert.True(
                    TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out var error),
                    $"Datagram {index} did not parse at offset {offset}: {error}.");
                if (frame.RawType == (ulong)TlsQuicFrameType.Crypto)
                {
                    crypto.Add(frame);
                }
                else
                {
                    // The only other thing s14.1's expansion puts in an Initial packet.
                    Assert.Equal((ulong)TlsQuicFrameType.Padding, frame.RawType);
                }
            }
        }
        return crypto;
    }

    /// <summary>One connection's ClientHello from the B8 factory, offering the capture's two
    /// key shares - X25519MLKEM768 and X25519 - in the capture's supported-groups order.
    /// </summary>
    private static byte[] Brave151ClientHello() =>
        new TlsQuicClientHelloProfileFactory
        {
            Tls = builder => builder
                .WithSupportedGroups(
                    NamedGroup.X25519MlKem768,
                    NamedGroup.X25519,
                    NamedGroup.Secp256r1,
                    NamedGroup.Secp384r1)
                .WithKeyShares(NamedGroup.X25519MlKem768, NamedGroup.X25519),
        }.Create(default).BuildDeterministicForTesting("example.test", [0x2b]);

    // RFC 9000 s17.3.1's short header, sharing the long-header vector's packet number so
    // that only the header form varies between the two.
    private static TlsQuicPacketPlan ShortVectorPlan() => new()
    {
        Type = null,
        DestinationConnectionId = Convert.FromHexString(VectorDestinationConnectionIdHex),
        PacketNumber = ShortVectorPacketNumber,
        PacketNumberEncodedLength = 4,
        SpinBit = true,
        KeyPhase = true,
    };

    private const ulong ShortVectorPacketNumber = VectorPacketNumber;

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

    private static TlsQuicConnectionSpec Spec(int paddingTarget) =>
        new() { PaddingTarget = paddingTarget };

    // The stream byte at index i is i+1, so every frame's first data byte names the offset
    // it was cut at. 1..255 never produces 0x00, which would be indistinguishable from a
    // PADDING frame in an asserted payload.
    private static byte[] CryptoStream(int length)
    {
        var stream = new byte[length];
        for (var index = 0; index < length; index++)
        {
            stream[index] = (byte)((index % 255) + 1);
        }
        return stream;
    }

    private static string Hex(byte[] source, int start, int length) =>
        Convert.ToHexString(source, start, length);

    private static TlsQuicPacketToSend Template(
        TlsQuicPacketProtectionKeys keys, in TlsQuicPacketPlan plan) => new()
        {
            Plan = plan,
            PacketProtectionCipher = TlsQuicPacketProtectionCipher.AesGcm,
            Key = keys.CopyKey(),
            Iv = keys.CopyIv(),
            HeaderProtectionCipher = TlsQuicHeaderProtectionCipher.Aes,
            HeaderProtectionKey = keys.CopyHeaderProtectionKey(),
        };

    private static byte[] BuildOne(
        TlsQuicPacketProtectionKeys keys,
        TlsQuicConnectionSpec spec,
        in TlsQuicPacketPlan plan,
        IReadOnlyList<TlsQuicFrame> frames,
        out TlsQuicSentPacket sent)
    {
        var buffer = new byte[Math.Max(spec.PaddingTarget, 4096)];
        var packets = new List<TlsQuicPacketToSend> { Template(keys, plan) with { Frames = frames } };
        var reported = new List<TlsQuicSentPacket>();
        var written = TlsQuicDatagramBuilder.BuildDatagram(spec, packets, SentAt, buffer, reported);
        sent = reported[0];
        return buffer[..written];
    }

    private static TlsQuicPacketProtectionKeys VectorKeys()
    {
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, Convert.FromHexString(VectorDestinationConnectionIdHex));
        return secrets.DeriveClientPacketProtectionKeys(TlsQuicVersion.Version1);
    }

    // The Length varint of a VectorPlan packet is two bytes at offset 24, so the packet
    // number starts at 26 - the offset this class's header comment derives.
    private static byte[] OpenVector(
        TlsQuicPacketProtectionKeys keys, byte[] datagram, ulong packetNumber = VectorPacketNumber) =>
        Open(keys, datagram, VectorLengthVarintOffset + 2, packetNumber);

    // RFC 9001 s5.4's inverse then s5.3's, both pinned against A.2 and A.5 in their own test
    // classes - not this builder's arithmetic reflected back.
    private static byte[] Open(
        TlsQuicPacketProtectionKeys keys, byte[] packet, int packetNumberOffset, ulong packetNumber)
    {
        var copy = (byte[])packet.Clone();
        Assert.True(TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            copy,
            packetNumberOffset,
            out var packetNumberLength));

        var headerLength = packetNumberOffset + packetNumberLength;
        var plaintext = new byte[copy.Length - headerLength - 16];
        Assert.True(TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            packetNumber,
            copy.AsSpan(0, headerLength),
            copy.AsSpan(headerLength),
            plaintext));
        return plaintext;
    }
}
