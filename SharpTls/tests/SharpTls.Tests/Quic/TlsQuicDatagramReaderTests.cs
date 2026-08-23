using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicDatagramReaderTests
{
    [Fact]
    public void CoalescedInitialAndHandshakeAreBothFoundWithCorrectBoundaries()
    {
        var initial = BuildLongHeaderBytes(TlsQuicLongPacketType.Initial, destinationConnectionIdLength: 8, sourceConnectionIdLength: 4, packetNumberLength: 2);
        var handshake = BuildLongHeaderBytes(TlsQuicLongPacketType.Handshake, destinationConnectionIdLength: 8, sourceConnectionIdLength: 4, packetNumberLength: 3);
        var datagram = Concat(initial, handshake);

        var packets = TlsQuicDatagramReader.Read(datagram).ToList();

        Assert.Equal(2, packets.Count);
        Assert.Equal(TlsQuicCoalescedPacketKind.Long, packets[0].Kind);
        Assert.Equal(initial, packets[0].Packet.ToArray());
        Assert.Equal(TlsQuicCoalescedPacketKind.Long, packets[1].Kind);
        Assert.Equal(handshake, packets[1].Packet.ToArray());
    }

    [Fact]
    public void YieldedPacketsAliasTheSourceBufferRatherThanCopyingIt()
    {
        // Every other test asserts through Packet.ToArray(), which would pass just as well
        // against a defensive copy - it proves the bytes match, not that they're the same
        // bytes. The LIFETIME contract documented on Read is the entire reason this reader
        // returns slices rather than copies, so pin it directly: mutate the source datagram
        // after materialising the walk, and confirm a yielded packet's span sees the change.
        var initial = BuildLongHeaderBytes(TlsQuicLongPacketType.Initial, destinationConnectionIdLength: 8, sourceConnectionIdLength: 4, packetNumberLength: 2);
        var handshake = BuildLongHeaderBytes(TlsQuicLongPacketType.Handshake, destinationConnectionIdLength: 8, sourceConnectionIdLength: 4, packetNumberLength: 3);
        var datagram = Concat(initial, handshake);

        var packets = TlsQuicDatagramReader.Read(datagram).ToList();

        datagram[0] ^= 0xFF;
        datagram[initial.Length] ^= 0xFF;

        Assert.Equal(datagram[0], packets[0].Packet.Span[0]);
        Assert.Equal(datagram[initial.Length], packets[1].Packet.Span[0]);
    }

    [Fact]
    public void InitialFollowedByShortHeaderBothFoundAndShortHeaderTakesRemainder()
    {
        var initial = BuildLongHeaderBytes(TlsQuicLongPacketType.Initial, destinationConnectionIdLength: 8, sourceConnectionIdLength: 4, packetNumberLength: 2);
        var shortHeader = BuildShortHeaderBytes(destinationConnectionIdLength: 8, packetNumberLength: 1);
        var datagram = Concat(initial, shortHeader);

        var packets = TlsQuicDatagramReader.Read(datagram).ToList();

        Assert.Equal(2, packets.Count);
        Assert.Equal(TlsQuicCoalescedPacketKind.Long, packets[0].Kind);
        Assert.Equal(initial, packets[0].Packet.ToArray());
        Assert.Equal(TlsQuicCoalescedPacketKind.Short, packets[1].Kind);
        Assert.Equal(shortHeader, packets[1].Packet.ToArray());
    }

    [Fact]
    public void ShortHeaderFollowedByTrailingBytesYieldsExactlyOnePacketCoveringAllOfIt()
    {
        var shortHeader = BuildShortHeaderBytes(destinationConnectionIdLength: 0, packetNumberLength: 1);
        var trailingBytes = SequentialBytes(6, seed: 0x99);
        var datagram = Concat(shortHeader, trailingBytes);

        var packets = TlsQuicDatagramReader.Read(datagram).ToList();

        // RFC 9000 s12.2: a short header packet has no Length field and so can only be the
        // last packet in the datagram - the trailing bytes are part of this one packet, not a
        // second one.
        var packet = Assert.Single(packets);
        Assert.Equal(TlsQuicCoalescedPacketKind.Short, packet.Kind);
        Assert.Equal(datagram, packet.Packet.ToArray());
    }

    [Fact]
    public void TruncatedTrailingPacketIsDroppedButEarlierPacketsAreStillYielded()
    {
        var initial = BuildLongHeaderBytes(TlsQuicLongPacketType.Initial, destinationConnectionIdLength: 8, sourceConnectionIdLength: 4, packetNumberLength: 2);
        var datagram = Concat(initial, TruncatedHandshakePrefix());

        var packets = TlsQuicDatagramReader.Read(datagram).ToList();

        var packet = Assert.Single(packets);
        Assert.Equal(TlsQuicCoalescedPacketKind.Long, packet.Kind);
        Assert.Equal(initial, packet.Packet.ToArray());
    }

    [Fact]
    public void UnparseableFirstPacketYieldsNoPackets()
    {
        var datagram = TruncatedHandshakePrefix();

        Assert.Empty(TlsQuicDatagramReader.Read(datagram));
    }

    [Fact]
    public void EmptyDatagramYieldsNoPackets()
    {
        Assert.Empty(TlsQuicDatagramReader.Read(ReadOnlyMemory<byte>.Empty));
    }

    [Fact]
    public void VersionNegotiationDatagramYieldsOneItemCoveringTheWholeDatagram()
    {
        var datagram = BuildVersionNegotiationBytes();

        var packets = TlsQuicDatagramReader.Read(datagram).ToList();

        var packet = Assert.Single(packets);
        Assert.Equal(TlsQuicCoalescedPacketKind.VersionNegotiation, packet.Kind);
        Assert.Equal(datagram, packet.Packet.ToArray());
    }

    [Fact]
    public void ThreeCoalescedPacketsAreAllFound()
    {
        var initial = BuildLongHeaderBytes(TlsQuicLongPacketType.Initial, destinationConnectionIdLength: 8, sourceConnectionIdLength: 4, packetNumberLength: 1);
        var zeroRtt = BuildLongHeaderBytes(TlsQuicLongPacketType.ZeroRtt, destinationConnectionIdLength: 8, sourceConnectionIdLength: 0, packetNumberLength: 2);
        var handshake = BuildLongHeaderBytes(TlsQuicLongPacketType.Handshake, destinationConnectionIdLength: 8, sourceConnectionIdLength: 4, packetNumberLength: 4);
        var datagram = Concat(initial, zeroRtt, handshake);

        var packets = TlsQuicDatagramReader.Read(datagram).ToList();

        Assert.Equal(3, packets.Count);
        Assert.Equal(initial, packets[0].Packet.ToArray());
        Assert.Equal(zeroRtt, packets[1].Packet.ToArray());
        Assert.Equal(handshake, packets[2].Packet.ToArray());
        Assert.All(packets, p => Assert.Equal(TlsQuicCoalescedPacketKind.Long, p.Kind));
    }

    // Handshake, version 1, zero-length DCID/SCID, Length varint declares 63 bytes but none
    // follow - TryReadLongHeader's declared-length-exceeds-remaining check rejects it. Mirrors
    // TlsQuicPacketHeaderTests.LengthVarintOverrunIsRejectedWithoutThrowing.
    private static byte[] TruncatedHandshakePrefix() =>
        Convert.FromHexString("E0000000010000" + "3F");

    private static byte[] BuildLongHeaderBytes(
        TlsQuicLongPacketType type, int destinationConnectionIdLength, int sourceConnectionIdLength, int packetNumberLength)
    {
        var header = new TlsQuicLongHeader
        {
            Type = type,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = SequentialBytes(destinationConnectionIdLength, seed: 0x10),
            SourceConnectionId = SequentialBytes(sourceConnectionIdLength, seed: 0x20),
            Token = ReadOnlyMemory<byte>.Empty,
            // Zero-length payload: Length covers only the Packet Number field, so the written
            // bytes are themselves a complete packet with nothing left over - concatenating two
            // of these back to back produces a datagram with no gap or overlap between them.
            Length = (ulong)packetNumberLength,
            PacketNumberLength = packetNumberLength,
            PacketNumber = SequentialBytes(packetNumberLength, seed: 0x40),
        };

        var buffer = new byte[64];
        var written = TlsQuicPacketHeader.WriteLongHeader(buffer, header, out _);
        return buffer[..written];
    }

    private static byte[] BuildShortHeaderBytes(int destinationConnectionIdLength, int packetNumberLength)
    {
        var header = new TlsQuicShortHeader
        {
            DestinationConnectionId = SequentialBytes(destinationConnectionIdLength, seed: 0x60),
            PacketNumberLength = packetNumberLength,
            PacketNumber = SequentialBytes(packetNumberLength, seed: 0x70),
        };

        var buffer = new byte[32];
        var written = TlsQuicPacketHeader.WriteShortHeader(buffer, header, out _);
        return buffer[..written];
    }

    private static byte[] BuildVersionNegotiationBytes()
    {
        var packet = new TlsQuicVersionNegotiationPacket
        {
            DestinationConnectionId = SequentialBytes(8, seed: 0x10),
            SourceConnectionId = SequentialBytes(4, seed: 0x20),
            SupportedVersions = new uint[] { (uint)TlsQuicVersion.Version1 },
        };

        var buffer = new byte[64];
        var written = TlsQuicVersionNegotiation.Write(buffer, packet);
        return buffer[..written];
    }

    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    private static byte[] SequentialBytes(int length, byte seed)
    {
        var bytes = new byte[length];
        for (var index = 0; index < length; index++)
        {
            bytes[index] = (byte)(seed + index);
        }
        return bytes;
    }
}
