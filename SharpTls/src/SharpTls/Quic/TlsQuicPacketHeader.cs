using System.Buffers.Binary;

namespace SharpTls.Quic;

// RFC 9000 s17.2, Table 5.
internal enum TlsQuicLongPacketType
{
    Initial = 0x00,
    ZeroRtt = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
}

// A parsed long header (RFC 9000 s17.2). Connection ID lengths, packet number
// length, and token contents are carried by the packet itself, never assumed:
// subsystem B varies all of them per imitated client (Chromium sends a
// zero-length source connection ID and an 8-byte destination connection ID;
// Firefox varies its destination connection ID length across 8, 9, and 15
// bytes), so nothing here may become a hardcoded layout constant.
//
// LIFETIME: every ReadOnlyMemory field below is a zero-copy slice of the
// datagram passed to the parser, not an independent copy. The parsed header is
// only valid while that buffer is unmodified. A caller that rents its datagram
// from a pool must not return it, and must not reuse it for the next receive,
// until it has finished with every header parsed out of it. This matters most
// for a coalesced datagram, where several packets alias one buffer.
internal readonly struct TlsQuicLongHeader
{
    /// <summary>RFC 9287 s3: write the QUIC Bit as 0 rather than 1.</summary>
    /// <remarks>
    /// <para>SAME INVERTED SENSE AS <see cref="TlsQuicShortHeader.GreaseFixedBit"/>, for the
    /// same reason: a default-constructed header must still write RFC 9000 s17.2's mandatory
    /// 1.</para>
    /// <para>THIS CLIENT NEVER SETS IT ON A LONG HEADER, and cannot legally. s3 permits
    /// clearing the bit only once the PEER has advertised grease_quic_bit, and the peer's
    /// transport parameters do not arrive until its EncryptedExtensions - by which point every
    /// packet this endpoint sends carries a short header. It exists here because the writer and
    /// the reader are one codec and a codec that can read a shape it cannot write is a codec
    /// with an untestable half.</para>
    /// </remarks>
    internal bool GreaseFixedBit { get; init; }

    internal TlsQuicLongPacketType Type { get; init; }
    internal uint Version { get; init; }
    internal ReadOnlyMemory<byte> DestinationConnectionId { get; init; }
    internal ReadOnlyMemory<byte> SourceConnectionId { get; init; }

    // Initial (s17.2.2): the address-validation Token. Retry (s17.2.5): the
    // Retry Token. Empty for 0-RTT and Handshake, which carry neither.
    internal ReadOnlyMemory<byte> Token { get; init; }

    // The Length field (s17.2): byte count of the Packet Number plus Payload
    // fields combined. Retry has no Length field; 0 there, which is never a
    // value a real Initial/0-RTT/Handshake packet can carry (Length is always
    // >= PacketNumberLength, which is at least 1).
    internal ulong Length { get; init; }

    // Byte offset from the start of the datagram to the first byte of the
    // Packet Number field. Header protection (Task 4) samples ciphertext at
    // PacketNumberOffset + 4, so it is computed once here instead of being
    // recomputed - and possibly miscomputed - a second time later. 0 for
    // Retry, which has no packet number.
    internal int PacketNumberOffset { get; init; }

    // Length of the Packet Number field in bytes (1-4), read from the low 2
    // bits of byte 0. Those bits - and the raw PacketNumber bytes below - are
    // still masked by header protection until a later stage removes it, so
    // RFC 9000 s17.2 is treated as opaque data here, not validated. 0 for
    // Retry, which has no packet number.
    internal int PacketNumberLength { get; init; }

    // Raw (possibly still header-protected) bytes of the truncated packet
    // number, length == PacketNumberLength. Empty for Retry.
    internal ReadOnlyMemory<byte> PacketNumber { get; init; }

    // Retry only (s17.2.5): the 128-bit Retry Integrity Tag. Empty otherwise.
    // Task 6 verifies the tag; this type only delimits it.
    internal ReadOnlyMemory<byte> RetryIntegrityTag { get; init; }
}

// A parsed short header (RFC 9000 s17.3.1), the single "1-RTT Packet"
// format used once 1-RTT keys are negotiated. Unlike the long header, the
// Destination Connection ID carries no length prefix on the wire - the
// receiver already knows its own connection ID length from connection
// state - so callers supply it rather than the parser inferring it.
// Subsystem B varies connection ID length, packet number length, spin bit,
// and key phase per imitated client, so none of those may become a
// hardcoded layout constant.
//
// LIFETIME: as with TlsQuicLongHeader, every ReadOnlyMemory field is a
// zero-copy slice of the caller's datagram and is only valid while that buffer
// is unmodified.
internal readonly struct TlsQuicShortHeader
{
    // RFC 9000 s17.4: not covered by header protection (the s5.4 preamble of
    // [QUIC-TLS] says its mask only ever touches the low 4 or 5 bits of byte
    // 0), so this is the true value even on a still-protected packet.
    internal bool SpinBit { get; init; }

    /// <summary>RFC 9287 s3: write the QUIC Bit as 0 rather than 1.</summary>
    /// <remarks>THE SENSE IS INVERTED ON PURPOSE - "grease it" rather than "set it" - so that
    /// a default-constructed header still writes s17.2's mandatory 1. A `FixedBit` property
    /// defaulting to true would read better and would be wrong for every `default` struct in
    /// this tree.</remarks>
    internal bool GreaseFixedBit { get; init; }

    // RFC 9000 s17.3.1: covered by header protection. The value read here
    // is only meaningful once a later stage removes protection; treated as
    // opaque data until then, same as PacketNumberLength below.
    internal bool KeyPhase { get; init; }

    internal ReadOnlyMemory<byte> DestinationConnectionId { get; init; }

    // Byte offset from the start of the datagram to the first byte of the
    // Packet Number field. Header protection (Task 4) samples ciphertext at
    // PacketNumberOffset + 4 regardless of the packet's actual (still-
    // protected) packet number length, so it is computed once here instead
    // of being recomputed - and possibly miscomputed - a second time later.
    internal int PacketNumberOffset { get; init; }

    // Length of the Packet Number field in bytes (1-4), read from the low 2
    // bits of byte 0. Those bits - and the raw PacketNumber bytes below -
    // are still masked by header protection until a later stage removes it,
    // so (like TlsQuicLongHeader.PacketNumberLength) this is opaque data
    // here, not validated. Short headers have no Length field to cross-
    // check it against, unlike the long header.
    internal int PacketNumberLength { get; init; }

    internal ReadOnlyMemory<byte> PacketNumber { get; init; }
}

internal static class TlsQuicPacketHeader
{
    // RFC 9000 s17.2, Destination/Source Connection ID Length: "In QUIC
    // version 1, this value MUST NOT exceed 20 bytes. Endpoints that receive
    // a version 1 long header with a value larger than 20 MUST drop the
    // packet."
    internal const int MaximumConnectionIdLength = 20;

    // RFC 9000 s17.2.5: Retry Integrity Tag is 128 bits.
    private const int RetryIntegrityTagLength = 16;

    /// <summary>RFC 9369 section 5's long-header type values, indexed by
    /// <see cref="TlsQuicLongPacketType"/>'s RFC 9000 value.</summary>
    /// <remarks>
    /// <para>s5: "Initial: 0b01, 0-RTT: 0b10, Handshake: 0b11, Retry: 0b00." RFC 9000 s17.2
    /// numbers the same four 0b00, 0b01, 0b10, 0b11 in that order, so v2 is v1 + 1 modulo 4 -
    /// but it is written out as a table rather than as arithmetic, because the arithmetic is a
    /// coincidence of the two lists and not a rule either RFC states.</para>
    /// <para>WHY VERSION 2 IS REMAPPED AT ALL, and it is worth knowing before touching this:
    /// s5's own reason is that the remap makes a v2 packet unusable by a middlebox that hard
    /// codes v1's numbering, which is the ossification the version exists to break.</para>
    /// </remarks>
    private static ReadOnlySpan<byte> Version2LongPacketTypes => [0b01, 0b10, 0b11, 0b00];

    /// <summary>Maps a first byte's two type bits to a packet type, in this version's
    /// numbering.</summary>
    /// <remarks>ANY VERSION THAT IS NOT 2 IS READ AS VERSION 1's NUMBERING, including 0. That
    /// is right for both cases it covers: an unknown version cannot be decoded further than
    /// this anyway, and version 0 is a Version Negotiation packet, whose s17.2.1 "Unused" field
    /// occupies these bits and carries no meaning at all.</remarks>
    private static TlsQuicLongPacketType DecodeLongPacketType(byte typeBits, uint version) =>
        version == (uint)TlsQuicVersion.Version2
            ? (TlsQuicLongPacketType)Version2LongPacketTypes.IndexOf(typeBits)
            : (TlsQuicLongPacketType)typeBits;

    /// <summary>The inverse: the two type bits this version writes for a packet type.</summary>
    private static byte EncodeLongPacketType(TlsQuicLongPacketType type, uint version) =>
        version == (uint)TlsQuicVersion.Version2
            ? Version2LongPacketTypes[(int)type]
            : (byte)type;

    private const byte HeaderFormBit = 0x80;
    private const byte FixedBitMask = 0x40;
    private const byte LongPacketTypeMask = 0x30;
    private const int LongPacketTypeShift = 4;
    private const byte PacketNumberLengthMask = 0x03;

    // RFC 9000 s17.3.1, short header only: Spin Bit (0x20) and Key Phase
    // (0x04). HeaderFormBit, FixedBitMask, and PacketNumberLengthMask above
    // sit at the same bit positions in byte 0 for both header forms, so
    // short header parsing reuses them instead of redefining equivalents.
    private const byte SpinBitMask = 0x20;
    private const byte KeyPhaseMask = 0x04;

    // Try-shaped and never throws: a packet off the network is
    // attacker-controlled, and once a connection loop exists a throw here
    // would let one malformed datagram kill the connection. Same contract as
    // TlsQuicSocks5Protocol.TryReadUdpHeader.
    //
    // Takes ReadOnlyMemory<byte>, not ReadOnlySpan<byte>: DestinationConnectionId,
    // SourceConnectionId, Token, and PacketNumber are stored as ReadOnlyMemory<byte>
    // fields on the returned header, and a span-derived slice cannot become a
    // ReadOnlyMemory<byte> without copying. Taking Memory here lets every stored field be
    // a zero-copy slice of the caller's buffer instead - ReceiveAsync already hands
    // callers a Memory<byte>, so the path from socket to parsed header stays copy-free.
    // acceptGreasedQuicBit - RFC 9287 s3: true only when this endpoint advertised
    // grease_quic_bit, which obliges it to "accept packets with the QUIC Bit set to 0".
    // Default false keeps RFC 9000 s17.2's "packets containing a zero value for this bit are
    // not valid packets in this version and MUST be discarded", which is the right answer for
    // an endpoint that granted no such permission - and for every caller that is inspecting
    // bytes rather than receiving them.
    internal static bool TryReadLongHeader(
        ReadOnlyMemory<byte> datagram,
        out TlsQuicLongHeader header,
        out int consumed,
        bool acceptGreasedQuicBit = false)
    {
        header = default;
        consumed = 0;

        if (datagram.Length < 1)
        {
            return false;
        }

        var span = datagram.Span;
        var firstByte = span[0];

        // RFC 9000 s17.2, Fixed Bit: "Packets containing a zero value for
        // this bit are not valid packets in this version and MUST be
        // discarded." The Header Form bit (0x80) must also be set: a clear
        // bit means this is a short header, which this function does not
        // parse.
        if ((firstByte & HeaderFormBit) == 0
            || ((firstByte & FixedBitMask) == 0 && !acceptGreasedQuicBit))
        {
            return false;
        }

        // THE TYPE BITS ARE READ HERE AND DECODED BELOW, once the version is known. They used
        // to be cast straight to TlsQuicLongPacketType, unconditionally in RFC 9000's
        // numbering - which mistypes every RFC 9369 long header, because s5 remaps all four.
        var typeBits = (byte)((firstByte & LongPacketTypeMask) >> LongPacketTypeShift);

        var offset = 1;
        if (datagram.Length < offset + 4)
        {
            return false;
        }
        var version = BinaryPrimitives.ReadUInt32BigEndian(span[offset..]);
        offset += 4;

        var type = DecodeLongPacketType(typeBits, version);

        if (!TryReadConnectionId(datagram, ref offset, MaximumConnectionIdLength, out var destinationConnectionId))
        {
            return false;
        }
        if (!TryReadConnectionId(datagram, ref offset, MaximumConnectionIdLength, out var sourceConnectionId))
        {
            return false;
        }

        if (type == TlsQuicLongPacketType.Retry)
        {
            return TryFinishRetry(
                datagram, offset, type, version, destinationConnectionId, sourceConnectionId,
                out header, out consumed);
        }

        var token = ReadOnlyMemory<byte>.Empty;
        if (type == TlsQuicLongPacketType.Initial
            && !TryReadLengthPrefixed(datagram, ref offset, out token))
        {
            return false;
        }

        // VACUOUS TO TEST, not unwitnessed - a mutation sweep (A4 task 2, run in a
        // worktree) found this check's own failure path unobservable through
        // TryReadLongHeader's return value. Ignoring TryRead's bool here and
        // falling through with `length` at its TryRead-assigned default of 0 does
        // not let a truncated Length field through: `packetNumberLength` below is
        // always 1 to 4 (PacketNumberLengthMask's low two bits plus one), and the
        // very next check rejects whenever `length < packetNumberLength` - which 0
        // always satisfies. So a failed TryRead and a successful one that
        // legitimately decoded 0 are rejected by the identical downstream
        // comparison, for the identical reason, and no input can separate them.
        if (!QuicVariableLengthInteger.TryRead(span, ref offset, out var length))
        {
            return false;
        }

        var packetNumberLength = (firstByte & PacketNumberLengthMask) + 1;
        var packetNumberOffset = offset;

        // Two independent failure modes share this one check: a declared Length too small
        // to even hold the packet number field (first clause) and a declared Length larger
        // than what remains in the datagram (second clause). Both are pinned separately -
        // see TlsQuicPacketHeaderTests.DeclaredLengthShorterThanPacketNumberLengthWithAll
        // BytesPresentIsRejectedWithoutThrowing for the first clause, since every overrun
        // test that predates it uses a huge declared Length that always fails the second
        // clause first.
        if (length < (ulong)packetNumberLength || length > (ulong)(datagram.Length - offset))
        {
            return false;
        }

        header = new TlsQuicLongHeader
        {
            Type = type,
            Version = version,
            DestinationConnectionId = destinationConnectionId,
            SourceConnectionId = sourceConnectionId,
            Token = token,
            Length = length,
            PacketNumberOffset = packetNumberOffset,
            PacketNumberLength = packetNumberLength,
            PacketNumber = datagram.Slice(packetNumberOffset, packetNumberLength),
        };
        consumed = packetNumberOffset + (int)length;
        return true;
    }

    // packetNumberOffset (A4 task 4a): byte offset from the start of `destination`
    // to the first byte of the Packet Number field - the write-side mirror of
    // TlsQuicLongHeader.PacketNumberOffset above, computed the same way (the
    // running offset immediately after the Length varint, before the packet
    // number bytes are copied in). RFC 9001 s5.4.2 samples header-protection
    // ciphertext starting 4 bytes after this offset, and without it the caller
    // would have to re-derive the header layout a second time to find where
    // that sample begins - a second transcription with no independent source.
    // 0 for Retry, which RFC 9000 s17.2.5 gives no Packet Number field to
    // protect. Pinned against RFC 9001 A.2's own header bytes by
    // TlsQuicPacketHeaderTests.WriteLongHeaderPacketNumberOffsetMatchesAppendixA2.
    //
    // lengthVarintWidth (A4 task 4b): the width the Length field is written at.
    // RFC 9000 s16 permits a non-minimal encoding for every field except the
    // frame type, so this width is a sender choice and therefore observable -
    // A4's plan Finding 5. It is a parameter rather than a field on
    // TlsQuicLongHeader deliberately: the struct is shared with the read path,
    // and a write-only width field would read back as Minimal on a header
    // parsed from a wire form that was not minimal - a field that lies rather
    // than one that is absent. The Token Length varint is NOT covered; nothing
    // in the target capture or in RFC 9001 A.2 distinguishes its width, so no
    // knob is offered for it. Witnessed by
    // TlsQuicPacketHeaderTests.WriteLongHeaderWidensOnlyTheLengthFieldWhenAsked.
    internal static int WriteLongHeader(
        Span<byte> destination,
        in TlsQuicLongHeader header,
        out int packetNumberOffset,
        TlsQuicVarintWidth lengthVarintWidth = TlsQuicVarintWidth.Minimal)
    {
        ValidateConnectionIdLength(header.DestinationConnectionId, "Destination", nameof(header));
        ValidateConnectionIdLength(header.SourceConnectionId, "Source", nameof(header));

        if (header.Type != TlsQuicLongPacketType.Retry)
        {
            ValidatePacketNumberLength(header.PacketNumber.Length, header.PacketNumberLength, nameof(header));
        }
        else if (header.RetryIntegrityTag.Length != RetryIntegrityTagLength)
        {
            throw new ArgumentException(
                $"Retry Integrity Tag must be exactly {RetryIntegrityTagLength} bytes.", nameof(header));
        }

        var required = GetLongHeaderLength(header, lengthVarintWidth);
        if (destination.Length < required)
        {
            throw new ArgumentException(
                $"Long header needs {required} bytes, destination has {destination.Length}.",
                nameof(destination));
        }

        var offset = 0;

        // Reserved bits (Initial/0-RTT/Handshake) and Unused bits (Retry) are
        // always written as 0. RFC 9000 s17.2: "The value included prior to
        // protection MUST be set to 0." For Retry's Unused bits the RFC only
        // requires "an arbitrary value"; 0 is a legal choice and keeps output
        // deterministic.
        var lowBits = header.Type == TlsQuicLongPacketType.Retry ? 0 : header.PacketNumberLength - 1;
        destination[offset++] = (byte)(
            HeaderFormBit
            | (header.GreaseFixedBit ? 0 : FixedBitMask)
            | (EncodeLongPacketType(header.Type, header.Version) << LongPacketTypeShift)
            | lowBits);

        BinaryPrimitives.WriteUInt32BigEndian(destination[offset..], header.Version);
        offset += 4;

        offset = WriteConnectionId(destination, offset, header.DestinationConnectionId.Span);
        offset = WriteConnectionId(destination, offset, header.SourceConnectionId.Span);

        if (header.Type == TlsQuicLongPacketType.Retry)
        {
            header.Token.Span.CopyTo(destination[offset..]);
            offset += header.Token.Length;
            header.RetryIntegrityTag.Span.CopyTo(destination[offset..]);
            offset += header.RetryIntegrityTag.Length;
            packetNumberOffset = 0;
            return offset;
        }

        if (header.Type == TlsQuicLongPacketType.Initial)
        {
            offset = WriteVariableLength(
                destination, offset, (ulong)header.Token.Length, TlsQuicVarintWidth.Minimal);
            header.Token.Span.CopyTo(destination[offset..]);
            offset += header.Token.Length;
        }

        offset = WriteVariableLength(destination, offset, header.Length, lengthVarintWidth);
        packetNumberOffset = offset;
        header.PacketNumber.Span.CopyTo(destination[offset..]);
        offset += header.PacketNumber.Length;
        return offset;
    }

    // Try-shaped and never throws, same contract as TryReadLongHeader.
    // destinationConnectionIdLength is a parameter, not read from the wire:
    // RFC 9000 s17.3.1's short header carries no length field for it, so
    // the receiver must already know it from connection state.
    internal static bool TryReadShortHeader(
        ReadOnlyMemory<byte> datagram,
        int destinationConnectionIdLength,
        out TlsQuicShortHeader header,
        out int consumed,
        bool acceptGreasedQuicBit = false)
    {
        header = default;
        consumed = 0;

        if (datagram.Length < 1)
        {
            return false;
        }

        var span = datagram.Span;
        var firstByte = span[0];

        // RFC 9000 s17.3.1, Header Form: "set to 0 for the short header." A
        // set bit here is a long header packet, which this function does
        // not parse - the mirror image of TryReadLongHeader rejecting a
        // clear Header Form bit. Callers dispatching on wire form route to
        // TryReadLongHeader instead; this function does not attempt that
        // dispatch itself, matching the existing single-responsibility split.
        if ((firstByte & HeaderFormBit) != 0)
        {
            return false;
        }

        // Fixed Bit (0x40): "Packets containing a zero value for this bit
        // are not valid packets in this version and MUST be discarded."
        // Unlike the Reserved Bits, Key Phase, and Packet Number Length
        // below, the Header Form and Fixed Bit are outside the header
        // protection mask (RFC 9001 s5.4 preamble), so this check is
        // meaningful even on a still-protected packet.
        if ((firstByte & FixedBitMask) == 0 && !acceptGreasedQuicBit)
        {
            return false;
        }

        if (destinationConnectionIdLength < 0 || destinationConnectionIdLength > MaximumConnectionIdLength)
        {
            return false;
        }

        // Packet Number Length bits (0x03): still covered by header
        // protection until a later stage removes it, so - like the long
        // header parse - this is read as opaque data, not validated.
        var packetNumberLength = (firstByte & PacketNumberLengthMask) + 1;
        var packetNumberOffset = 1 + destinationConnectionIdLength;

        if (datagram.Length < packetNumberOffset + packetNumberLength)
        {
            return false;
        }

        var destinationConnectionId = destinationConnectionIdLength == 0
            ? ReadOnlyMemory<byte>.Empty
            : datagram.Slice(1, destinationConnectionIdLength);

        header = new TlsQuicShortHeader
        {
            SpinBit = (firstByte & SpinBitMask) != 0,
            KeyPhase = (firstByte & KeyPhaseMask) != 0,
            DestinationConnectionId = destinationConnectionId,
            PacketNumberOffset = packetNumberOffset,
            PacketNumberLength = packetNumberLength,
            PacketNumber = datagram.Slice(packetNumberOffset, packetNumberLength),
        };

        // RFC 9000 s12.2: only long header packets can precede others in a
        // datagram; a short header packet is always the last one and its
        // payload runs to the end of the datagram (there is no Length field
        // to delimit it otherwise).
        consumed = datagram.Length;
        return true;
    }

    // packetNumberOffset (A4 task 14a): byte offset from the start of
    // `destination` to the first byte of the Packet Number field - the
    // write-side mirror of TlsQuicShortHeader.PacketNumberOffset, and the exact
    // counterpart of WriteLongHeader's out parameter above, for the same
    // reason: RFC 9001 s5.4.2 samples header-protection ciphertext starting 4
    // bytes after this offset, and without it the send path would have to
    // re-derive the header layout a second time to find where that sample
    // begins - a second transcription with no independent source.
    //
    // RFC 9000 s17.3.1's field list gives a short header exactly two fields
    // ahead of the Packet Number - byte 0 and the Destination Connection ID -
    // so the offset is 1 + DCID length, with no Version, no Token and no
    // Length field to account for. s5.4.2's own pseudocode agrees in as many
    // words - "pn_offset = 1 + len(connection_id)" - which is a second,
    // independent statement of the same layout, not this file's arithmetic.
    // Pinned by
    // TlsQuicPacketHeaderTests.WriteShortHeaderPacketNumberOffsetMatchesSection1731Layout.
    internal static int WriteShortHeader(
        Span<byte> destination, in TlsQuicShortHeader header, out int packetNumberOffset)
    {
        ValidateConnectionIdLength(header.DestinationConnectionId, "Destination", nameof(header));
        ValidatePacketNumberLength(header.PacketNumber.Length, header.PacketNumberLength, nameof(header));

        var required = 1 + header.DestinationConnectionId.Length + header.PacketNumberLength;
        if (destination.Length < required)
        {
            throw new ArgumentException(
                $"Short header needs {required} bytes, destination has {destination.Length}.",
                nameof(destination));
        }

        var offset = 0;

        // Header Form bit left clear (short header). Reserved bits (0x18)
        // left at 0 per RFC 9000 s17.3.1: "The value included prior to
        // protection MUST be set to 0."
        destination[offset++] = (byte)(
            (header.GreaseFixedBit ? 0 : FixedBitMask)
            | (header.SpinBit ? SpinBitMask : 0)
            | (header.KeyPhase ? KeyPhaseMask : 0)
            | (header.PacketNumberLength - 1));

        header.DestinationConnectionId.Span.CopyTo(destination[offset..]);
        offset += header.DestinationConnectionId.Length;

        packetNumberOffset = offset;
        header.PacketNumber.Span.CopyTo(destination[offset..]);
        offset += header.PacketNumber.Length;

        return offset;
    }

    // Shared bounds-check parser for the Connection ID Length + Connection ID pair that both
    // the long header (RFC 9000 s17.2) and the Version Negotiation packet (s17.2.1) use -
    // this is attacker-controlled input, so the check belongs in exactly one place. Internal
    // rather than private: TlsQuicVersionNegotiation calls it too. maximumLength is the one
    // thing that genuinely differs between the two callers - 20 bytes for a version-1 long
    // header, 255 bytes for Version Negotiation - and is deliberately left as a parameter
    // rather than unified.
    //
    // Takes ReadOnlyMemory<byte>, not ReadOnlySpan<byte>, so connectionId can be a
    // zero-copy slice of the caller's buffer instead of a defensive .ToArray() copy.
    internal static bool TryReadConnectionId(
        ReadOnlyMemory<byte> datagram, ref int offset, int maximumLength, out ReadOnlyMemory<byte> connectionId)
    {
        connectionId = ReadOnlyMemory<byte>.Empty;

        if (datagram.Length < offset + 1)
        {
            return false;
        }
        var length = datagram.Span[offset];
        offset += 1;

        if (length > maximumLength || datagram.Length < offset + length)
        {
            return false;
        }
        if (length > 0)
        {
            connectionId = datagram.Slice(offset, length);
        }
        offset += length;
        return true;
    }

    private static bool TryReadLengthPrefixed(
        ReadOnlyMemory<byte> datagram, ref int offset, out ReadOnlyMemory<byte> value)
    {
        value = ReadOnlyMemory<byte>.Empty;

        // VACUOUS TO TEST, not unwitnessed - a mutation sweep (A4 task 2, run in a
        // worktree) found this check's own failure path unobservable through
        // TryReadLongHeader, the only caller: ignoring TryRead's bool here and
        // falling through with length 0 leaves `offset` exactly where it was
        // (TryRead never advances it on failure), and the very next thing
        // TryReadLongHeader does is another QuicVariableLengthInteger.TryRead call,
        // for the packet's own Length field, at that identical unmoved offset
        // against the identical span. TryRead is a pure function of (source,
        // offset), so that second call reproduces the exact same failure the first
        // one had and TryReadLongHeader still returns false - no input can make the
        // two implementations disagree on accept/reject. Same status as
        // TryReadRetireConnectionId's no-op offset restore in
        // TlsQuicConnectionFrames.cs. The trigger that would end this: a caller
        // that does something other than immediately re-reading at the same
        // position on this method's failure.
        if (!QuicVariableLengthInteger.TryRead(datagram.Span, ref offset, out var length))
        {
            return false;
        }

        if (length > (ulong)(datagram.Length - offset))
        {
            return false;
        }
        if (length > 0)
        {
            value = datagram.Slice(offset, (int)length);
        }
        offset += (int)length;
        return true;
    }

    private static bool TryFinishRetry(
        ReadOnlyMemory<byte> datagram,
        int offset,
        TlsQuicLongPacketType type,
        uint version,
        ReadOnlyMemory<byte> destinationConnectionId,
        ReadOnlyMemory<byte> sourceConnectionId,
        out TlsQuicLongHeader header,
        out int consumed)
    {
        header = default;
        consumed = 0;

        // RFC 9000 s12.2: "Retry packets (Section 17.2.5), ... do not
        // contain a Length field and so cannot be followed by other packets
        // in the same UDP datagram." So - unlike the other three long
        // header types - Retry cannot be coalesced with a following packet.
        // It always runs to the end of the datagram, ending in the
        // fixed-size Retry Integrity Tag.
        var retryTokenLength = datagram.Length - offset - RetryIntegrityTagLength;
        if (retryTokenLength < 0)
        {
            return false;
        }

        header = new TlsQuicLongHeader
        {
            Type = type,
            Version = version,
            DestinationConnectionId = destinationConnectionId,
            SourceConnectionId = sourceConnectionId,
            Token = retryTokenLength == 0
                ? ReadOnlyMemory<byte>.Empty
                : datagram.Slice(offset, retryTokenLength),
            RetryIntegrityTag = datagram.Slice(offset + retryTokenLength, RetryIntegrityTagLength),
        };
        consumed = datagram.Length;
        return true;
    }

    // Shared with TlsQuicVersionNegotiation.Write: byte-for-byte identical Connection ID
    // Length + Connection ID encoding in both wire formats. Internal rather than private
    // for the same reason as TryReadConnectionId above.
    internal static int WriteConnectionId(Span<byte> destination, int offset, ReadOnlySpan<byte> connectionId)
    {
        destination[offset++] = (byte)connectionId.Length;
        connectionId.CopyTo(destination[offset..]);
        return offset + connectionId.Length;
    }

    // Shared by WriteLongHeader and WriteShortHeader so the bound and its message cannot
    // drift apart between the two (previously duplicated three times near-identically).
    private static void ValidateConnectionIdLength(ReadOnlyMemory<byte> connectionId, string label, string paramName)
    {
        if (connectionId.Length > MaximumConnectionIdLength)
        {
            throw new ArgumentException(
                $"{label} connection ID must be at most {MaximumConnectionIdLength} bytes.", paramName);
        }
    }

    // Shared by WriteLongHeader (non-Retry) and WriteShortHeader. The 1-4 byte range check
    // and the "PacketNumber bytes match PacketNumberLength" check always travel together at
    // every call site (previously duplicated twice each), so one helper covers both.
    private static void ValidatePacketNumberLength(int packetNumberByteLength, int packetNumberLength, string paramName)
    {
        if (packetNumberLength is < 1 or > 4)
        {
            throw new ArgumentOutOfRangeException(
                paramName, packetNumberLength, "Packet number length must be 1-4 bytes.");
        }
        if (packetNumberByteLength != packetNumberLength)
        {
            throw new ArgumentException("PacketNumber length must match PacketNumberLength.", paramName);
        }
    }

    private static int WriteVariableLength(
        Span<byte> destination, int offset, ulong value, TlsQuicVarintWidth width)
    {
        var encoded = QuicVariableLengthInteger.Encode(
            value, QuicVariableLengthInteger.GetEncodedLength(value, width));
        encoded.CopyTo(destination[offset..]);
        return offset + encoded.Length;
    }

    // Internal, not private, for task 5. Padding a flight's last packet to
    // TlsQuicConnectionSpec.PaddingTarget means knowing the header's byte length BEFORE
    // the frame list exists, because the PADDING frame count is the target minus the
    // header, the packet number, the payload so far and the 16-byte tag. That is this
    // arithmetic, and there must not be a second copy of it - the same rule task 4a's
    // `out int packetNumberOffset` exists to keep. Calling WriteLongHeader as a throwaway
    // just to read its return would work and is worse: it needs a scratch buffer, a Length
    // value and a packet number the caller does not have yet.
    //
    // ONE CIRCULARITY TO KNOW ABOUT, because it is not obvious and it is task 5's to
    // resolve: at TlsQuicVarintWidth.Minimal the Length field's own width depends on
    // header.Length, which depends on the payload, which depends on how much PADDING fits,
    // which depends on this result. The widths are RFC 9000 s16 Table 4's four steps, so
    // the dependency is a step function and settles immediately - compute against a
    // provisional Length and recompute if the width changed. A fixed
    // TlsQuicVarintWidth does not have the problem at all.
    internal static int GetLongHeaderLength(in TlsQuicLongHeader header, TlsQuicVarintWidth lengthVarintWidth)
    {
        var length = 1 + 4 + 1 + header.DestinationConnectionId.Length + 1 + header.SourceConnectionId.Length;

        if (header.Type == TlsQuicLongPacketType.Retry)
        {
            return length + header.Token.Length + header.RetryIntegrityTag.Length;
        }

        if (header.Type == TlsQuicLongPacketType.Initial)
        {
            length += QuicVariableLengthInteger.GetEncodedLength((ulong)header.Token.Length) + header.Token.Length;
        }

        length += QuicVariableLengthInteger.GetEncodedLength(header.Length, lengthVarintWidth)
            + header.PacketNumberLength;
        return length;
    }
}
