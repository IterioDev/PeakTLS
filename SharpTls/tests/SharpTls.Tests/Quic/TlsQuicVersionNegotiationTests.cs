using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicVersionNegotiationTests
{
    [Fact]
    public void RoundTripsKnownConnectionIdsAndVersionList()
    {
        var destinationConnectionId = SequentialBytes(8, seed: 0x10);
        var sourceConnectionId = SequentialBytes(4, seed: 0x20);
        uint[] versions = [(uint)TlsQuicVersion.Version1, (uint)TlsQuicVersion.Version2, 0xFACADE0D];

        var packet = new TlsQuicVersionNegotiationPacket
        {
            DestinationConnectionId = destinationConnectionId,
            SourceConnectionId = sourceConnectionId,
            SupportedVersions = versions,
        };

        var buffer = new byte[64];
        var written = TlsQuicVersionNegotiation.Write(buffer, packet);

        Assert.True(TlsQuicVersionNegotiation.TryRead(buffer.AsMemory(0, written), out var parsed));
        Assert.Equal(destinationConnectionId, parsed.DestinationConnectionId.ToArray());
        Assert.Equal(sourceConnectionId, parsed.SourceConnectionId.ToArray());
        Assert.Equal(versions, parsed.SupportedVersions);
    }

    [Fact]
    public void ConnectionIdLengthOfExactly255BytesRoundTrips()
    {
        // RFC 9000 s17.2.1's own diagram bounds Destination/Source Connection
        // ID at (0..2040) bits = 255 bytes - the single behaviour that
        // distinguishes this wire format from TlsQuicPacketHeader's 20-byte
        // version-1 cap. Pins the accept side of that boundary; the sibling
        // TlsQuicPacketHeaderTests.ConnectionIdLengthOfExactlyTwentyBytesWith
        // AllBytesPresentIsAccepted pins the same edge for its own 20-byte cap.
        var destinationConnectionId = SequentialBytes(255, seed: 0x00);
        var sourceConnectionId = SequentialBytes(255, seed: 0x01);
        var packet = new TlsQuicVersionNegotiationPacket
        {
            DestinationConnectionId = destinationConnectionId,
            SourceConnectionId = sourceConnectionId,
            SupportedVersions = new uint[] { (uint)TlsQuicVersion.Version1 },
        };

        var buffer = new byte[1 + 4 + 1 + 255 + 1 + 255 + 4];
        var written = TlsQuicVersionNegotiation.Write(buffer, packet);

        Assert.True(TlsQuicVersionNegotiation.TryRead(buffer.AsMemory(0, written), out var parsed));
        Assert.Equal(destinationConnectionId, parsed.DestinationConnectionId.ToArray());
        Assert.Equal(sourceConnectionId, parsed.SourceConnectionId.ToArray());
    }

    [Fact]
    public void WriteRejectsDestinationConnectionIdLongerThan255Bytes()
    {
        var packet = new TlsQuicVersionNegotiationPacket
        {
            DestinationConnectionId = SequentialBytes(256, seed: 0x00),
            SourceConnectionId = ReadOnlyMemory<byte>.Empty,
            SupportedVersions = [],
        };

        var buffer = new byte[600];
        Assert.Throws<ArgumentException>(() => TlsQuicVersionNegotiation.Write(buffer, packet));
    }

    [Fact]
    public void WriteRejectsSourceConnectionIdLongerThan255Bytes()
    {
        var packet = new TlsQuicVersionNegotiationPacket
        {
            DestinationConnectionId = ReadOnlyMemory<byte>.Empty,
            SourceConnectionId = SequentialBytes(256, seed: 0x00),
            SupportedVersions = [],
        };

        var buffer = new byte[600];
        Assert.Throws<ArgumentException>(() => TlsQuicVersionNegotiation.Write(buffer, packet));
    }

    [Fact]
    public void VersionListIsParsedInOrderAndCompletely()
    {
        uint[] versions = [0x00000001, 0x6B3343CF, 0xAABBCCDD, 0x00000002];
        var packet = new TlsQuicVersionNegotiationPacket
        {
            DestinationConnectionId = ReadOnlyMemory<byte>.Empty,
            SourceConnectionId = ReadOnlyMemory<byte>.Empty,
            SupportedVersions = versions,
        };

        var buffer = new byte[32];
        var written = TlsQuicVersionNegotiation.Write(buffer, packet);

        Assert.True(TlsQuicVersionNegotiation.TryRead(buffer.AsMemory(0, written), out var parsed));
        Assert.Equal(versions.Length, parsed.SupportedVersions.Count);
        for (var index = 0; index < versions.Length; index++)
        {
            Assert.Equal(versions[index], parsed.SupportedVersions[index]);
        }
    }

    [Fact]
    public void EmptyVersionListIsLegalAndRoundTrips()
    {
        // RFC 9000 s17.2.1's diagram writes the list as "Supported Version
        // (32) ...", the same "field, then ellipsis" notation s17.2.1 also
        // uses for the Destination/Source Connection ID bytes preceding it -
        // zero-or-more repetition with no stated minimum count. So a Version
        // Negotiation packet listing zero supported versions is
        // syntactically legal at this layer, even though a real server has
        // no reason to send one it did not need to negotiate.
        var packet = new TlsQuicVersionNegotiationPacket
        {
            DestinationConnectionId = SequentialBytes(4, seed: 0x10),
            SourceConnectionId = ReadOnlyMemory<byte>.Empty,
            SupportedVersions = [],
        };

        var buffer = new byte[16];
        var written = TlsQuicVersionNegotiation.Write(buffer, packet);

        Assert.True(TlsQuicVersionNegotiation.TryRead(buffer.AsMemory(0, written), out var parsed));
        Assert.Empty(parsed.SupportedVersions);
    }

    [Fact]
    public void BodyLengthNotAMultipleOfFourIsRejectedWithoutThrowing()
    {
        // Header Form byte, Version = 0, zero-length DCID and SCID, then 3
        // trailing bytes - not a whole number of 32-bit supported versions.
        var datagram = Convert.FromHexString("80" + "00000000" + "00" + "00" + "AABBCC");
        Assert.False(TlsQuicVersionNegotiation.TryRead(datagram, out _));
    }

    [Fact]
    public void ConnectionIdLengthDeclaringMoreThanRemainsIsRejectedWithoutThrowing()
    {
        // Destination Connection ID Length = 0xFA (250) - legal per RFC 9000
        // s17.2.1, which lifts the 20-byte version-1 cap for Version
        // Negotiation packets - but only 4 bytes actually follow.
        var datagram = Convert.FromHexString("80" + "00000000" + "FA" + "AABBCCDD");
        Assert.False(TlsQuicVersionNegotiation.TryRead(datagram, out _));
    }

    [Theory]
    [InlineData(0)]  // nothing at all
    [InlineData(1)]  // header byte only, Version missing
    [InlineData(3)]  // Version truncated (2 of 4 bytes)
    [InlineData(5)]  // Version complete, DCID length byte missing
    [InlineData(6)]  // DCID length says 4, 0 DCID bytes present
    [InlineData(8)]  // DCID length says 4, 2 of 4 DCID bytes present
    [InlineData(10)] // DCID complete, SCID length byte missing
    [InlineData(11)] // SCID length says 2, 0 SCID bytes present
    [InlineData(12)] // SCID length says 2, 1 of 2 SCID bytes present
    [InlineData(15)] // SCID complete, supported version truncated (2 of 4 bytes)
    public void TruncationAtEveryFieldBoundaryIsRejectedWithoutThrowing(int cutLength)
    {
        var full = BuildValidPacketBytes();
        Assert.False(TlsQuicVersionNegotiation.TryRead(full.AsMemory(0, cutLength), out _));
    }

    [Fact]
    public void CuttingExactlyAfterConnectionIdsYieldsALegalEmptyVersionList()
    {
        // Offset 13 in BuildValidPacketBytes is precisely "DCID and SCID
        // complete, zero supported-version bytes" - not a truncation at all,
        // since an empty version list is legal (see
        // EmptyVersionListIsLegalAndRoundTrips). Pinned here so the boundary
        // list above is not mistaken for treating this offset as a failure.
        var full = BuildValidPacketBytes();
        Assert.True(TlsQuicVersionNegotiation.TryRead(full.AsMemory(0, 13), out var parsed));
        Assert.Empty(parsed.SupportedVersions);
    }

    [Fact]
    public void HeaderFormBitClearIsRejectedWithoutThrowing()
    {
        // RFC 9000 s17.2.1's "Header Form (1) = 1" is the one bit in byte 0
        // that IS checked (see UnusualUnusedBitsAfterHeaderFormAreIgnored
        // for the other seven, which are not).
        var full = BuildValidPacketBytes();
        full[0] = (byte)(full[0] & 0x7F);
        Assert.False(TlsQuicVersionNegotiation.TryRead(full, out _));
    }

    [Fact]
    public void UnusualUnusedBitsAfterHeaderFormAreIgnored()
    {
        // RFC 9000 s17.2.1: the seven bits after Header Form are "Unused...
        // set to an arbitrary value by the server. Clients MUST ignore the
        // value of this field." - unlike every other long header packet
        // (s17.2), where those bits are a Fixed Bit + Long Packet Type +
        // Type-Specific Bits and getting one wrong is a reason to discard
        // the packet. Set every one of them, rather than the 0x40 Write()
        // produces, and confirm the packet still parses.
        var full = BuildValidPacketBytes();
        full[0] = 0xFF; // Header Form (0x80) still set; all seven Unused bits now set too.

        Assert.True(TlsQuicVersionNegotiation.TryRead(full, out var parsed));
        Assert.Equal(4, parsed.DestinationConnectionId.Length);
        Assert.Equal(2, parsed.SourceConnectionId.Length);
        Assert.Equal((uint)TlsQuicVersion.Version1, Assert.Single(parsed.SupportedVersions));
    }

    [Fact]
    public void VersionFieldNonZeroIsRejectedWithoutThrowing()
    {
        // RFC 9000 s17.2.1: "The Version field of a Version Negotiation
        // packet MUST be set to 0x00000000" - and is how a client recognises
        // the packet as Version Negotiation at all.
        var full = BuildValidPacketBytes();
        full[4] = 0x01; // low byte of the big-endian Version field.
        Assert.False(TlsQuicVersionNegotiation.TryRead(full, out _));
    }

    // Header(0x80) Version(00000000) DCIDLen(04) DCID(4 bytes) SCIDLen(02)
    // SCID(2 bytes) one supported version (4 bytes) = 17 bytes total.
    // Field boundary offsets: 0, 1, 5, 6, 10, 11, 13, 17.
    private static byte[] BuildValidPacketBytes()
    {
        var destinationConnectionId = SequentialBytes(4, seed: 0x10);
        var sourceConnectionId = SequentialBytes(2, seed: 0x20);
        var packet = new TlsQuicVersionNegotiationPacket
        {
            DestinationConnectionId = destinationConnectionId,
            SourceConnectionId = sourceConnectionId,
            SupportedVersions = new uint[] { (uint)TlsQuicVersion.Version1 },
        };

        var buffer = new byte[17];
        var written = TlsQuicVersionNegotiation.Write(buffer, packet);
        if (written != buffer.Length)
        {
            throw new InvalidOperationException("Test fixture size drifted from Write()'s output.");
        }
        return buffer;
    }

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
