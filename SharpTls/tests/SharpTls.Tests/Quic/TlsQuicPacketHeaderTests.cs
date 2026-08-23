using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicPacketHeaderTests
{
    // RFC 9001 Appendix A.2: the client Initial header BEFORE protection.
    // Appendix A.2 shows both forms - "header = c000000001088394c8f03e51570
    // 80000449e7b9aec34" is the *protected* header (byte 0 masked to 0xC0,
    // packet number bytes masked to 7b9aec34) produced by XORing the
    // unprotected header with the AES-ECB sample mask. The unprotected form,
    // used here because header protection is out of scope until Task 4, is
    // given a few lines earlier: "The header includes the connection ID and
    // a packet number of 2: c300000001088394c8f03e5157080000449e00000002".
    private const string AppendixA2UnprotectedHeaderHex =
        "c300000001088394c8f03e5157080000449e00000002";

    // RFC 9001 Appendix A.5: a *protected* ChaCha20-Poly1305 short header
    // packet with an empty Destination Connection ID - "packet =
    // 4cfe4189655e5cd55c41f69080575d7999c25a5bfb". Unlike Appendix A.2,
    // A.5 shows no unprotected-header form to fall back to; this is the
    // only version of this packet the RFC gives.
    private const string AppendixA5ProtectedPacketHex =
        "4cfe4189655e5cd55c41f69080575d7999c25a5bfb";

    [Fact]
    public void ParsesAppendixA2ClientInitialHeader()
    {
        var headerBytes = Convert.FromHexString(AppendixA2UnprotectedHeaderHex);

        // The unprotected header declares Length = 1182 (4-byte packet
        // number + 1162-byte frames + 16-byte tag). headerBytes already
        // includes the 4-byte packet number, so pad with dummy payload bytes
        // out to that declared length so the parser's overrun check passes.
        var datagram = new byte[18 + 1182];
        headerBytes.CopyTo(datagram, 0);

        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(datagram, out var header, out var consumed));

        Assert.Equal(TlsQuicLongPacketType.Initial, header.Type);
        Assert.Equal((uint)TlsQuicVersion.Version1, header.Version);
        Assert.Equal("8394C8F03E515708", Convert.ToHexString(header.DestinationConnectionId.Span));
        Assert.Equal(0, header.SourceConnectionId.Length);
        Assert.Equal(0, header.Token.Length);
        Assert.Equal(1182UL, header.Length);
        Assert.Equal(18, header.PacketNumberOffset);
        Assert.Equal(4, header.PacketNumberLength);
        Assert.Equal("00000002", Convert.ToHexString(header.PacketNumber.Span));
        Assert.Equal(datagram.Length, consumed);
    }

    // xunit theory methods must be public, but TlsQuicLongPacketType is
    // internal - a public method cannot take a less-accessible parameter
    // type, so the packet type travels as its raw Table 5 value instead.
    [Theory]
    [InlineData(0)] // Initial
    [InlineData(1)] // ZeroRtt
    [InlineData(2)] // Handshake
    [InlineData(3)] // Retry
    public void RoundTripsEachLongHeaderType(int typeValue)
    {
        var type = (TlsQuicLongPacketType)typeValue;
        var hasToken = type is TlsQuicLongPacketType.Initial or TlsQuicLongPacketType.Retry;
        var header = BuildHeader(
            type,
            destinationConnectionIdLength: 8,
            sourceConnectionIdLength: 4,
            tokenLength: hasToken ? 5 : 0,
            packetNumberLength: 3);

        var buffer = new byte[64];
        var written = TlsQuicPacketHeader.WriteLongHeader(buffer, header, out var packetNumberOffset);

        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(buffer.AsMemory(0, written), out var parsed, out var consumed));

        Assert.Equal(written, consumed);
        Assert.Equal(header.Type, parsed.Type);
        Assert.Equal(header.Version, parsed.Version);
        Assert.Equal(header.DestinationConnectionId.ToArray(), parsed.DestinationConnectionId.ToArray());
        Assert.Equal(header.SourceConnectionId.ToArray(), parsed.SourceConnectionId.ToArray());
        Assert.Equal(header.Token.ToArray(), parsed.Token.ToArray());

        if (type == TlsQuicLongPacketType.Retry)
        {
            Assert.Equal(header.RetryIntegrityTag.ToArray(), parsed.RetryIntegrityTag.ToArray());

            // Retry has no Packet Number field (RFC 9000 s17.2.5) - WriteLongHeader
            // reports 0 rather than a stale offset into what it just wrote.
            Assert.Equal(0, packetNumberOffset);
        }
        else
        {
            Assert.Equal(header.Length, parsed.Length);
            Assert.Equal(header.PacketNumberLength, parsed.PacketNumberLength);
            Assert.Equal(header.PacketNumber.ToArray(), parsed.PacketNumber.ToArray());
            Assert.Equal(written, parsed.PacketNumberOffset + parsed.PacketNumberLength);

            // The write side's own reported offset must agree with what an
            // independent re-parse of those same bytes computes - a path this
            // covers across all three non-Retry types (Initial, 0-RTT,
            // Handshake) at once, each with a 5-byte token when the type
            // carries one and a 4-byte source connection ID.
            Assert.Equal(parsed.PacketNumberOffset, packetNumberOffset);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    public void ConnectionIdLengthZeroAndMaximumRoundTripBothDirections(int length)
    {
        var header = BuildHeader(
            TlsQuicLongPacketType.Handshake,
            destinationConnectionIdLength: length,
            sourceConnectionIdLength: length,
            tokenLength: 0,
            packetNumberLength: 1);

        var buffer = new byte[64];
        var written = TlsQuicPacketHeader.WriteLongHeader(buffer, header, out var packetNumberOffset);

        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(buffer.AsMemory(0, written), out var parsed, out _));
        Assert.Equal(length, parsed.DestinationConnectionId.Length);
        Assert.Equal(length, parsed.SourceConnectionId.Length);

        // Witnesses the offset at the connection-ID-length knob's other extreme
        // from RoundTripsEachLongHeaderType's fixed 8/4 - both 0 (A.2's SCID) and
        // 20 (the s17.2 maximum) move the offset, and the write side must agree
        // with an independent re-parse at both.
        Assert.Equal(parsed.PacketNumberOffset, packetNumberOffset);
    }

    [Fact]
    public void EmptyDatagramIsRejectedWithoutThrowing()
    {
        Assert.False(TlsQuicPacketHeader.TryReadLongHeader(ReadOnlyMemory<byte>.Empty, out _, out _));
    }

    [Fact]
    public void DatagramShorterThanFixedPrefixIsRejectedWithoutThrowing()
    {
        // Header form + Fixed Bit + Initial type, but truncated inside Version.
        var datagram = Convert.FromHexString("C30000");
        Assert.False(TlsQuicPacketHeader.TryReadLongHeader(datagram, out _, out _));
    }

    [Fact]
    public void OversizedDestinationConnectionIdLengthIsRejectedWithoutThrowing()
    {
        // Initial, version 1, Destination Connection ID Length = 21 (RFC 9000
        // s17.2's version-1 bound is 20).
        var datagram = Convert.FromHexString("C30000000115");
        Assert.False(TlsQuicPacketHeader.TryReadLongHeader(datagram, out _, out _));
    }

    [Fact]
    public void OversizedSourceConnectionIdLengthIsRejectedWithoutThrowing()
    {
        // Initial, version 1, zero-length DCID, Source Connection ID Length = 21.
        var datagram = Convert.FromHexString("C3000000010015");
        Assert.False(TlsQuicPacketHeader.TryReadLongHeader(datagram, out _, out _));
    }

    // The two tests above declare a 21-byte connection ID but never supply the
    // bytes, so the "not enough bytes remain" check rejects first and the
    // > MaximumConnectionIdLength comparison in TryReadConnectionId is never
    // reached. These three datagrams carry every byte they claim - DCID/SCID
    // length, a valid Length varint, and a present Packet Number - so that if
    // the bound comparison were deleted, parsing would run to completion and
    // return true. Only the bound comparison can make them fail.

    [Fact]
    public void OversizedDestinationConnectionIdWithAllBytesPresentIsRejectedWithoutThrowing()
    {
        var datagram = new List<byte> { 0xE0, 0x00, 0x00, 0x00, 0x01, 21 }; // Handshake, version 1, DCID len 21
        datagram.AddRange(SequentialBytes(21, seed: 0x60)); // all 21 DCID bytes present
        datagram.Add(0); // SCID len 0
        datagram.Add(1); // Length varint = 1 (covers exactly the 1-byte packet number)
        datagram.Add(0xAA); // Packet Number

        Assert.False(TlsQuicPacketHeader.TryReadLongHeader(datagram.ToArray(), out _, out _));
    }

    [Fact]
    public void OversizedSourceConnectionIdWithAllBytesPresentIsRejectedWithoutThrowing()
    {
        var datagram = new List<byte> { 0xE0, 0x00, 0x00, 0x00, 0x01, 0, 21 }; // Handshake, DCID len 0, SCID len 21
        datagram.AddRange(SequentialBytes(21, seed: 0x70)); // all 21 SCID bytes present
        datagram.Add(1); // Length varint = 1
        datagram.Add(0xBB); // Packet Number

        Assert.False(TlsQuicPacketHeader.TryReadLongHeader(datagram.ToArray(), out _, out _));
    }

    [Fact]
    public void ConnectionIdLengthOfExactlyTwentyBytesWithAllBytesPresentIsAccepted()
    {
        // RFC 9000 s17.2: the bound is "MUST NOT exceed 20 bytes" - 20 itself
        // is legal. Pins the accept side of the same boundary the two tests
        // above pin from the reject side.
        var datagram = new List<byte> { 0xE0, 0x00, 0x00, 0x00, 0x01, 20 }; // Handshake, version 1, DCID len 20
        datagram.AddRange(SequentialBytes(20, seed: 0x60));
        datagram.Add(0); // SCID len 0
        datagram.Add(1); // Length varint = 1
        datagram.Add(0xAA); // Packet Number

        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(datagram.ToArray(), out var header, out var consumed));
        Assert.Equal(20, header.DestinationConnectionId.Length);
        Assert.Equal(datagram.Count, consumed);
    }

    // The combined check `length < packetNumberLength || length > remaining` has two
    // clauses. Every overrun test above declares a huge Length, which always fails the
    // second clause first, so the first clause is never exercised on its own. Here Length
    // (2) is fully backed by real bytes - `length > remaining` is false - but is still
    // shorter than the declared 4-byte packet number, so only the first clause can reject
    // this datagram.
    [Fact]
    public void DeclaredLengthShorterThanPacketNumberLengthWithAllBytesPresentIsRejectedWithoutThrowing()
    {
        // Handshake, version 1, DCID/SCID len 0, packet number length 4 (low 2 bits = 3),
        // Length varint = 2.
        var datagram = new List<byte> { 0xE3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02 };
        datagram.AddRange(SequentialBytes(2, seed: 0x90)); // exactly the 2 bytes Length declares

        Assert.False(TlsQuicPacketHeader.TryReadLongHeader(datagram.ToArray(), out _, out _));
    }

    [Fact]
    public void TokenLengthOverrunIsRejectedWithoutThrowing()
    {
        // Initial, zero-length DCID/SCID, Token Length varint declares 63
        // bytes but none follow.
        var datagram = Convert.FromHexString("C3000000010000" + "3F");
        Assert.False(TlsQuicPacketHeader.TryReadLongHeader(datagram, out _, out _));
    }

    [Fact]
    public void LengthVarintOverrunIsRejectedWithoutThrowing()
    {
        // Initial, zero-length DCID/SCID, empty Token, Length varint declares
        // 16383 bytes (2-byte encoding 0x7FFF) but nothing follows.
        var datagram = Convert.FromHexString("C3000000010000" + "00" + "7FFF");
        Assert.False(TlsQuicPacketHeader.TryReadLongHeader(datagram, out _, out _));
    }

    [Fact]
    public void FixedBitClearIsRejectedWithoutThrowing()
    {
        // Header Form set, Fixed Bit (0x40) clear: RFC 9000 s17.2 requires
        // discarding such packets.
        var datagram = Convert.FromHexString("8300000001000000");
        Assert.False(TlsQuicPacketHeader.TryReadLongHeader(datagram, out _, out _));
    }

    // RFC 9001 A.2 (TlsQuicPacketHeaderTests.WriteLongHeaderPacketNumberOffsetMatchesAppendixA2
    // below) is the phase's only externally-published vector, and its token is
    // zero-length - it proves the offset arithmetic at Token = 0 and nothing
    // about the term a non-zero token adds. A.2 also fixes the Length varint at
    // its own 2-byte encoding (449e for 1182) and PacketNumberLength at 4, so it
    // cannot separate "token shifts the offset" from "token happens not to
    // matter here". This test is the second, independently hand-derived case
    // Task 4a's plan asks for: a real non-zero token (7 bytes, distinct from
    // A.2's 0) at different connection ID and packet-number lengths, pinned
    // directly against WriteLongHeader's own out parameter - not only through a
    // round trip, which would let the read and write sides share a transposed
    // term and still agree with each other.
    [Fact]
    public void PacketNumberOffsetAccountsForNonEmptyToken()
    {
        var header = BuildHeader(
            TlsQuicLongPacketType.Initial,
            destinationConnectionIdLength: 8,
            sourceConnectionIdLength: 0,
            tokenLength: 7,
            packetNumberLength: 2);

        var buffer = new byte[64];
        var written = TlsQuicPacketHeader.WriteLongHeader(buffer, header, out var packetNumberOffset);

        // byte0(1) + version(4) + dcidLen(1) + dcid(8) + scidLen(1) + scid(0)
        // + tokenLen-varint(1, 7 fits a 1-byte varint) + token(7) +
        // length-varint(1, packetNumberLength=2 fits a 1-byte varint) = 24.
        Assert.Equal(24, packetNumberOffset);
        Assert.Equal(written, packetNumberOffset + header.PacketNumberLength);

        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(buffer.AsMemory(0, written), out var parsed, out _));
        Assert.Equal(24, parsed.PacketNumberOffset);
        Assert.Equal(written, parsed.PacketNumberOffset + parsed.PacketNumberLength);
    }

    // Task 4a of A4-minimal: WriteLongHeader gained an `out int
    // packetNumberOffset` parameter so header protection (RFC 9001 s5.4, task
    // 4b) can find the Packet Number field without recomputing the header
    // layout a second time. This is the vector task 4a's plan requires: RFC
    // 9001 A.2's own unprotected header, built from its stated field values -
    // not from anything this file's helpers already agree with themselves
    // about. Header protection has not been applied here (that is task 4b's
    // job), so the written bytes are checked against A.2's *unprotected* form,
    // the same one ParsesAppendixA2ClientInitialHeader parses.
    //
    // 18 is derived directly from the RFC 9000 s17.2 field layout, not from
    // this file's or GetLongHeaderLength's own arithmetic: byte0(1) +
    // version(4) + dcidLen(1) + dcid(8) + scidLen(1) + scid(0) +
    // tokenLen-varint(1, 0 fits a 1-byte varint) + token(0) +
    // length-varint(2, "449e" is the RFC's own 2-byte encoding of 1182) = 18 -
    // matching the published header's own byte count up to where "00000002"
    // (the packet number) begins.
    [Fact]
    public void WriteLongHeaderPacketNumberOffsetMatchesAppendixA2()
    {
        var header = new TlsQuicLongHeader
        {
            Type = TlsQuicLongPacketType.Initial,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = Convert.FromHexString("8394C8F03E515708"),
            SourceConnectionId = ReadOnlyMemory<byte>.Empty,
            Token = ReadOnlyMemory<byte>.Empty,
            Length = 1182,
            PacketNumberLength = 4,
            PacketNumber = Convert.FromHexString("00000002"),
        };

        var buffer = new byte[64];
        var written = TlsQuicPacketHeader.WriteLongHeader(buffer, header, out var packetNumberOffset);

        Assert.Equal(18, packetNumberOffset);
        Assert.Equal(written, packetNumberOffset + header.PacketNumberLength);
        Assert.Equal(Convert.FromHexString(AppendixA2UnprotectedHeaderHex), buffer[..written]);
    }

    // The packet is still header-protection-protected: RFC 9001 s5.4.1
    // masks only the low 5 bits of byte 0 (Reserved Bits 0x18, Key Phase
    // 0x04, Packet Number Length 0x03) plus the Packet Number bytes
    // themselves. Header Form (0x80), Fixed Bit (0x40), and Spin Bit
    // (0x20) sit outside that mask, so they are the sender's true values
    // even here. KeyPhase, PacketNumberLength, and PacketNumber are NOT
    // asserted below - reading this protected packet's low 2 bits (0x4c &
    // 0x03 = 0) yields a packet number length of 1, not the sender's real
    // 3, which is exactly the masking this layer is not responsible for
    // undoing (that is Task 4's job).
    [Fact]
    public void ParsesAppendixA5ShortHeaderPacket()
    {
        var datagram = Convert.FromHexString(AppendixA5ProtectedPacketHex);

        Assert.True(TlsQuicPacketHeader.TryReadShortHeader(
            datagram, destinationConnectionIdLength: 0, out var header, out var consumed));

        Assert.Equal(0, header.DestinationConnectionId.Length);
        Assert.False(header.SpinBit);
        Assert.Equal(1, header.PacketNumberOffset);
        Assert.Equal(datagram.Length, consumed);
    }

    [Theory]
    [InlineData(0, 1, false)]
    [InlineData(0, 1, true)]
    [InlineData(0, 2, false)]
    [InlineData(0, 2, true)]
    [InlineData(0, 3, false)]
    [InlineData(0, 3, true)]
    [InlineData(0, 4, false)]
    [InlineData(0, 4, true)]
    [InlineData(20, 1, false)]
    [InlineData(20, 1, true)]
    [InlineData(20, 2, false)]
    [InlineData(20, 2, true)]
    [InlineData(20, 3, false)]
    [InlineData(20, 3, true)]
    [InlineData(20, 4, false)]
    [InlineData(20, 4, true)]
    public void RoundTripsShortHeaderAcrossConnectionIdAndPacketNumberLengths(
        int destinationConnectionIdLength, int packetNumberLength, bool keyPhase)
    {
        var header = BuildShortHeader(destinationConnectionIdLength, packetNumberLength, spinBit: false, keyPhase);

        var buffer = new byte[32];
        var written = TlsQuicPacketHeader.WriteShortHeader(buffer, header, out _);

        Assert.True(TlsQuicPacketHeader.TryReadShortHeader(
            buffer.AsMemory(0, written), destinationConnectionIdLength, out var parsed, out var consumed));

        Assert.Equal(written, consumed);
        Assert.Equal(header.SpinBit, parsed.SpinBit);
        Assert.Equal(header.KeyPhase, parsed.KeyPhase);
        Assert.Equal(header.DestinationConnectionId.ToArray(), parsed.DestinationConnectionId.ToArray());
        Assert.Equal(header.PacketNumberLength, parsed.PacketNumberLength);
        Assert.Equal(header.PacketNumber.ToArray(), parsed.PacketNumber.ToArray());
        Assert.Equal(written, parsed.PacketNumberOffset + parsed.PacketNumberLength);
    }

    // Task 14a of A4-minimal: WriteShortHeader gained an `out int
    // packetNumberOffset` so the 1-RTT send path (task 14b) can find the
    // Packet Number field - and the RFC 9001 s5.4.2 sample that starts four
    // bytes past it - without recomputing the header layout a second time,
    // exactly as task 4a did for WriteLongHeader.
    //
    // Both expected offsets below are read off RFC 9000 s17.3.1's own field
    // list rather than off this tree's arithmetic. That list gives a 1-RTT
    // packet exactly two fields ahead of the Packet Number: byte 0 (Header
    // Form, Fixed Bit, Spin Bit, Reserved Bits, Key Phase and Packet Number
    // Length all pack into that single byte), then "Destination Connection ID
    // (0..160)" - 0 to 20 bytes, carried with no length prefix because a short
    // header has none. There is no Version, no Token and no Length field
    // between them. So the offset is 1 + DCID length: 1 with an empty
    // connection ID, 9 with an 8-byte one.
    //
    // Vector 1 is published: RFC 9001 A.5's "unprotected header = 4200bff4" -
    // an empty-DCID 1-RTT header whose 3-byte packet number encodes as
    // 0x00bff4. It pins byte 0's bit layout against the RFC's own byte, but it
    // cannot tell an offset of 1 from an offset of 1 + DCID length, because
    // its DCID is empty. Vector 2 is hand-derived to close exactly that gap:
    // the same packet number behind A.2's 8-byte connection ID
    // (8394c8f03e515708), with Key Phase set so the bit is witnessed too.
    // Its byte 0 is 0x40 (Fixed Bit) | 0x04 (Key Phase) | 0x02 (Packet Number
    // Length 3, encoded as one less) = 0x46, with Header Form, Spin Bit and
    // both Reserved Bits clear.
    [Fact]
    public void WriteShortHeaderPacketNumberOffsetMatchesSection1731Layout()
    {
        var buffer = new byte[32];

        var appendixA5 = new TlsQuicShortHeader
        {
            SpinBit = false,
            KeyPhase = false,
            DestinationConnectionId = ReadOnlyMemory<byte>.Empty,
            PacketNumberLength = 3,
            PacketNumber = Convert.FromHexString("00bff4"),
        };

        var written = TlsQuicPacketHeader.WriteShortHeader(
            buffer, appendixA5, out var packetNumberOffset);

        Assert.Equal(1, packetNumberOffset);
        Assert.Equal(written, packetNumberOffset + appendixA5.PacketNumberLength);
        Assert.Equal(Convert.FromHexString("4200bff4"), buffer[..written]);

        var withConnectionId = new TlsQuicShortHeader
        {
            SpinBit = false,
            KeyPhase = true,
            DestinationConnectionId = Convert.FromHexString("8394c8f03e515708"),
            PacketNumberLength = 3,
            PacketNumber = Convert.FromHexString("00bff4"),
        };

        written = TlsQuicPacketHeader.WriteShortHeader(
            buffer, withConnectionId, out packetNumberOffset);

        Assert.Equal(9, packetNumberOffset);
        Assert.Equal(written, packetNumberOffset + withConnectionId.PacketNumberLength);
        Assert.Equal(Convert.FromHexString("468394c8f03e51570800bff4"), buffer[..written]);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void SpinBitAndKeyPhaseRoundTripIndependently(bool spinBit, bool keyPhase)
    {
        var header = BuildShortHeader(
            destinationConnectionIdLength: 8, packetNumberLength: 2, spinBit, keyPhase);

        var buffer = new byte[32];
        var written = TlsQuicPacketHeader.WriteShortHeader(buffer, header, out _);

        Assert.True(TlsQuicPacketHeader.TryReadShortHeader(
            buffer.AsMemory(0, written), destinationConnectionIdLength: 8, out var parsed, out _));

        Assert.Equal(spinBit, parsed.SpinBit);
        Assert.Equal(keyPhase, parsed.KeyPhase);
    }

    [Fact]
    public void ShortHeaderDatagramShorterThanFixedPrefixPlusDeclaredConnectionIdLengthIsRejectedWithoutThrowing()
    {
        // Header Form clear + Fixed Bit set (0x40): a structurally valid
        // short header first byte, so neither the Header Form nor Fixed
        // Bit check rejects it, and destinationConnectionIdLength (8) is
        // within the valid range so that check doesn't fire either. Only
        // 1 byte is present against a required 1 + 8 = 9, so only the
        // length bound check can reject this datagram.
        var datagram = new byte[] { 0x40 };
        Assert.False(TlsQuicPacketHeader.TryReadShortHeader(
            datagram, destinationConnectionIdLength: 8, out _, out _));
    }

    [Fact]
    public void ShortHeaderRejectsFirstByteWithHeaderFormBitSet()
    {
        // Header Form bit (0x80) set marks a long header packet. Mirrors
        // TryReadLongHeader's FixedBitClearIsRejectedWithoutThrowing test,
        // which rejects a *clear* Header Form bit as "not a long header."
        // TryReadShortHeader rejects here rather than dispatching to
        // TryReadLongHeader itself, keeping each parser single-purpose;
        // wire-form dispatch is left to the caller, same as the existing
        // split between the two Try* functions.
        var datagram = Convert.FromHexString("C300000001000000");
        Assert.False(TlsQuicPacketHeader.TryReadShortHeader(
            datagram, destinationConnectionIdLength: 0, out _, out _));
    }

    private static TlsQuicShortHeader BuildShortHeader(
        int destinationConnectionIdLength, int packetNumberLength, bool spinBit, bool keyPhase)
    {
        return new TlsQuicShortHeader
        {
            SpinBit = spinBit,
            KeyPhase = keyPhase,
            DestinationConnectionId = SequentialBytes(destinationConnectionIdLength, seed: 0x60),
            PacketNumberLength = packetNumberLength,
            PacketNumber = SequentialBytes(packetNumberLength, seed: 0x70),
        };
    }

    private static TlsQuicLongHeader BuildHeader(
        TlsQuicLongPacketType type,
        int destinationConnectionIdLength,
        int sourceConnectionIdLength,
        int tokenLength,
        int packetNumberLength)
    {
        var destinationConnectionId = SequentialBytes(destinationConnectionIdLength, seed: 0x10);
        var sourceConnectionId = SequentialBytes(sourceConnectionIdLength, seed: 0x20);
        var token = SequentialBytes(tokenLength, seed: 0x30);

        if (type == TlsQuicLongPacketType.Retry)
        {
            return new TlsQuicLongHeader
            {
                Type = type,
                Version = (uint)TlsQuicVersion.Version1,
                DestinationConnectionId = destinationConnectionId,
                SourceConnectionId = sourceConnectionId,
                Token = token,
                RetryIntegrityTag = SequentialBytes(16, seed: 0x50),
            };
        }

        return new TlsQuicLongHeader
        {
            Type = type,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = destinationConnectionId,
            SourceConnectionId = sourceConnectionId,
            Token = type == TlsQuicLongPacketType.Initial ? token : ReadOnlyMemory<byte>.Empty,
            // Zero-length payload keeps round-trip tests self-contained: Length
            // covers only the Packet Number field, so WriteLongHeader's output
            // is itself a complete, parseable packet with no frame bytes needed.
            Length = (ulong)packetNumberLength,
            PacketNumberLength = packetNumberLength,
            PacketNumber = SequentialBytes(packetNumberLength, seed: 0x40),
        };
    }


    // Task 4b of A4-minimal: RFC 9000 s16 permits a non-minimal encoding for every
    // field except the frame type, so the Length field's width is a sender choice and
    // therefore observable (A4's plan, Finding 5). A.2's own Length is minimal - "449e"
    // is the 2-byte form of 1182 - so this vector is hand-derived from s16 Table 4
    // rather than published: the same 1182 in the 4-byte form is prefix 0x80 over
    // 00 00 04 9E, and in the 8-byte form prefix 0xC0 over six zero bytes then 04 9E.
    //
    // The Token Length varint deliberately does NOT widen with it: A.2's token length
    // is 0 and stays the single byte "00" on every row, which is what pins that the
    // width reaches one field and not both. The packet number offset moves by exactly
    // the extra Length bytes, which is what task 4a's out parameter is for.
    [Theory]
    // The int rows are TlsQuicVarintWidth's member values - 0 Minimal, then the byte
    // counts 2, 4 and 8 - because xunit needs a public signature and the enum is
    // internal.
    [InlineData(0, 18, "C300000001088394C8F03E5157080000449E00000002")]
    [InlineData(2, 18, "C300000001088394C8F03E5157080000449E00000002")]
    [InlineData(4, 20, "C300000001088394C8F03E51570800008000049E00000002")]
    [InlineData(8, 24, "C300000001088394C8F03E5157080000C00000000000049E00000002")]
    public void WriteLongHeaderWidensOnlyTheLengthFieldWhenAsked(
        int width, int expectedPacketNumberOffset, string expectedHeaderHex)
    {
        var header = new TlsQuicLongHeader
        {
            Type = TlsQuicLongPacketType.Initial,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = Convert.FromHexString("8394C8F03E515708"),
            SourceConnectionId = ReadOnlyMemory<byte>.Empty,
            Token = ReadOnlyMemory<byte>.Empty,
            Length = 1182,
            PacketNumberLength = 4,
            PacketNumber = Convert.FromHexString("00000002"),
        };

        var buffer = new byte[64];
        var written = TlsQuicPacketHeader.WriteLongHeader(buffer, header, out var packetNumberOffset, (TlsQuicVarintWidth)width);

        Assert.Equal(expectedPacketNumberOffset, packetNumberOffset);
        Assert.Equal(expectedHeaderHex, Convert.ToHexString(buffer[..written]));

        // A wider Length is legal, not merely different: the reader that has always
        // existed must recover 1182 from every row above. That is the independent
        // check - a second implementation of s16's decode, written before this knob.
        var datagram = new byte[written + 1182];
        buffer.AsSpan(0, written).CopyTo(datagram);
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(datagram, out var parsed, out _));
        Assert.Equal(1182UL, parsed.Length);
        Assert.Equal(expectedPacketNumberOffset, parsed.PacketNumberOffset);
    }

    private static byte[] SequentialBytes(int length, byte seed)
    {
        var bytes = new byte[length];
        for (var i = 0; i < length; i++)
        {
            bytes[i] = (byte)(seed + i);
        }
        return bytes;
    }
}
