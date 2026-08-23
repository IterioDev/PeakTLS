using System.Buffers.Binary;

namespace SharpTls.Quic;

/// <summary>RFC 9000 §17.2.1 Version Negotiation packet: sent only by servers, in reply to a
/// client packet whose version the server does not support.</summary>
/// <remarks>
/// RFC 9001 §5 gives Version Negotiation packets no cryptographic protection whatsoever, so a
/// parsed packet is unauthenticated network input end to end: it may be used only to pick a
/// version for a fresh connection attempt, and MUST be ignored once a packet for the
/// connection has been successfully processed. That selection policy is connection state
/// (subsystem A4) and lives above this layer - this type only delimits and validates the wire
/// format.
/// </remarks>
internal readonly struct TlsQuicVersionNegotiationPacket
{
    internal ReadOnlyMemory<byte> DestinationConnectionId { get; init; }
    internal ReadOnlyMemory<byte> SourceConnectionId { get; init; }
    internal IReadOnlyList<uint> SupportedVersions { get; init; }
}

internal static class TlsQuicVersionNegotiation
{
    // RFC 9000 s17.2.1's own packet diagram gives Destination/Source
    // Connection ID a range of (0..2040) bits = 0..255 bytes - not the
    // 20-byte cap RFC 9000 s17.2 places on version-1 Initial/0-RTT/Handshake
    // packets (TlsQuicPacketHeader.MaximumConnectionIdLength). That 20-byte
    // cap is scoped to "a version 1 long header"; a Version Negotiation
    // packet's Version field is always 0, not 1, so the cap does not apply.
    // s17.2.1 says so explicitly: "Version-specific rules for the
    // connection ID therefore MUST NOT influence a decision about whether to
    // send a Version Negotiation packet." The general s17.2 prose backs
    // this up: servers "SHOULD be able to read longer connection IDs from
    // other QUIC versions" in order to properly form one. 255 is also
    // exactly what an 8-bit length field can express, so - unlike the
    // 20-byte case - no length byte value can ever exceed this bound; the
    // only way a connection ID declaration can be invalid here is if fewer
    // bytes remain in the datagram than it declares.
    internal const int MaximumConnectionIdLength = byte.MaxValue;

    private const byte HeaderFormBit = 0x80;

    // RFC 9000 s17.2.1: "servers SHOULD set the most significant bit of this
    // field (0x40) to 1 so that Version Negotiation packets appear to have
    // the Fixed Bit field." Used only when writing; readers never test it,
    // see TryRead.
    private const byte RecommendedUnusedBits = 0x40;

    private const int SupportedVersionSize = 4;

    /// <summary>Parses an RFC 9000 §17.2.1 Version Negotiation packet. Try-shaped and never
    /// throws for any input - same contract as TlsQuicSocks5Protocol.TryReadUdpHeader and
    /// TlsQuicPacketHeader.TryReadLongHeader.</summary>
    /// <remarks>
    /// RFC 9001 §5 gives Version Negotiation packets no cryptographic protection at all,
    /// making this the single least trustworthy packet type on the wire: anyone able to send
    /// the client a UDP datagram can forge one. A successful parse is advisory only - use it
    /// to pick a version for a fresh connection attempt, and MUST ignore it once a packet for
    /// the connection has been successfully processed.
    /// </remarks>
    internal static bool TryRead(ReadOnlyMemory<byte> datagram, out TlsQuicVersionNegotiationPacket packet)
    {
        packet = default;

        // Header Form byte + Version(4) + DCID length byte + SCID length byte, minimum.
        if (datagram.Length < 1 + 4 + 1 + 1)
        {
            return false;
        }

        var span = datagram.Span;

        // RFC 9000 s17.2.1's layout is "Header Form (1) = 1, Unused (7)" -
        // unlike every other long header packet (s17.2: Fixed Bit, Long
        // Packet Type, Type-Specific Bits), the seven bits after Header Form
        // are one undifferentiated Unused field, not a Fixed Bit that MUST
        // be 1. "The value in the Unused field is set to an arbitrary value
        // by the server. Clients MUST ignore the value of this field." so
        // only the top bit is ever inspected here.
        if ((span[0] & HeaderFormBit) == 0)
        {
            return false;
        }

        var offset = 1;

        var version = BinaryPrimitives.ReadUInt32BigEndian(span[offset..]);
        offset += 4;

        // RFC 9000 s17.2.1: "The Version field of a Version Negotiation
        // packet MUST be set to 0x00000000." This is also the field a real
        // client uses to recognise a Version Negotiation packet in the first
        // place, so - unlike the Unused bits - it is validated, not ignored.
        if (version != 0)
        {
            return false;
        }

        // MaximumConnectionIdLength (255) is exactly what an 8-bit length byte can express
        // (see its own doc comment above), so the shared helper's length > maximumLength
        // branch can never fire for either call below - the only real bound violation here
        // is the datagram running out before supplying the declared number of bytes.
        if (!TlsQuicPacketHeader.TryReadConnectionId(datagram, ref offset, MaximumConnectionIdLength, out var destinationConnectionId))
        {
            return false;
        }
        if (!TlsQuicPacketHeader.TryReadConnectionId(datagram, ref offset, MaximumConnectionIdLength, out var sourceConnectionId))
        {
            return false;
        }

        // RFC 9000 s17.2.1: "The remainder of the Version Negotiation packet
        // is a list of 32-bit versions that the server supports," and
        // separately: the packet "does not include the Packet Number and
        // Length fields present in other packets that use the long header
        // form. Consequently, a Version Negotiation packet consumes an
        // entire UDP datagram." So there is no length prefix for this list -
        // everything left in the buffer is the list, and a remainder that is
        // not an exact multiple of 4 bytes cannot be one.
        var remaining = datagram.Length - offset;
        if (remaining % SupportedVersionSize != 0)
        {
            return false;
        }

        var versions = new uint[remaining / SupportedVersionSize];
        for (var index = 0; index < versions.Length; index++)
        {
            versions[index] = BinaryPrimitives.ReadUInt32BigEndian(span[offset..]);
            offset += SupportedVersionSize;
        }

        packet = new TlsQuicVersionNegotiationPacket
        {
            DestinationConnectionId = destinationConnectionId,
            SourceConnectionId = sourceConnectionId,
            SupportedVersions = versions,
        };
        return true;
    }

    internal static int Write(Span<byte> destination, in TlsQuicVersionNegotiationPacket packet)
    {
        if ((uint)packet.DestinationConnectionId.Length > MaximumConnectionIdLength)
        {
            throw new ArgumentException(
                $"Destination connection ID must be at most {MaximumConnectionIdLength} bytes.",
                nameof(packet));
        }
        if ((uint)packet.SourceConnectionId.Length > MaximumConnectionIdLength)
        {
            throw new ArgumentException(
                $"Source connection ID must be at most {MaximumConnectionIdLength} bytes.",
                nameof(packet));
        }

        var supportedVersions = packet.SupportedVersions ?? [];
        var required = GetWrittenLength(packet.DestinationConnectionId.Length, packet.SourceConnectionId.Length, supportedVersions.Count);
        if (destination.Length < required)
        {
            throw new ArgumentException(
                $"Version Negotiation packet needs {required} bytes, destination has {destination.Length}.",
                nameof(destination));
        }

        var offset = 0;

        // Header Form = 1; the Unused bits are set to the RFC's recommended
        // 0x40 rather than 0, so a produced packet also satisfies s17.2.1's
        // guidance about coexisting with other protocols multiplexed on the
        // same port (RFC 7983) - this is what TryRead's "unusual bits" test
        // deliberately does NOT rely on, since clients MUST ignore this byte.
        destination[offset++] = (byte)(HeaderFormBit | RecommendedUnusedBits);

        BinaryPrimitives.WriteUInt32BigEndian(destination[offset..], 0);
        offset += 4;

        offset = TlsQuicPacketHeader.WriteConnectionId(destination, offset, packet.DestinationConnectionId.Span);
        offset = TlsQuicPacketHeader.WriteConnectionId(destination, offset, packet.SourceConnectionId.Span);

        foreach (var supportedVersion in supportedVersions)
        {
            BinaryPrimitives.WriteUInt32BigEndian(destination[offset..], supportedVersion);
            offset += SupportedVersionSize;
        }

        return offset;
    }

    private static int GetWrittenLength(int destinationConnectionIdLength, int sourceConnectionIdLength, int supportedVersionCount) =>
        1 + 4 + 1 + destinationConnectionIdLength + 1 + sourceConnectionIdLength + (supportedVersionCount * SupportedVersionSize);
}
