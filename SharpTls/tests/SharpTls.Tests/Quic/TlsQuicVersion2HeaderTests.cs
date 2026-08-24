using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

/// <content>
/// RFC 9369 section 5's long-header type remap. TlsQuicSecrets was already version-aware -
/// section 3.2's salt and the "quicv2 " label prefix - while TlsQuicPacketHeader read and wrote
/// the type field in RFC 9000's numbering unconditionally, so every version 2 long header this
/// library produced or parsed was mistyped. A half-implemented version is worse than none: the
/// keys would have derived correctly and the packet would still have been the wrong kind.
/// </content>
public sealed class TlsQuicVersion2HeaderTests
{
    private static TlsQuicLongHeader Header(TlsQuicLongPacketType type, TlsQuicVersion version) =>
        new()
        {
            Type = type,
            Version = (uint)version,
            DestinationConnectionId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
            SourceConnectionId = new byte[] { 9, 10, 11, 12 },
            Token = type == TlsQuicLongPacketType.Initial ? new byte[] { 0xAA } : [],
            PacketNumber = new byte[] { 0x42 },
            PacketNumberLength = 1,
            Length = 20,
        };

    private static byte TypeBitsOf(TlsQuicLongPacketType type, TlsQuicVersion version)
    {
        var buffer = new byte[128];
        TlsQuicPacketHeader.WriteLongHeader(buffer, Header(type, version), out _);
        return (byte)((buffer[0] & 0x30) >> 4);
    }

    // THE PARAMETER IS AN int AND NOT THE ENUM because TlsQuicLongPacketType is internal and
    // xUnit requires a public test method - the same reason the neighbouring header tests keep
    // the enum inside a private helper. The int IS RFC 9000 s17.2's value for the type, which
    // makes the theory rows read as "v1 value -> v2 value".
    [Theory]
    [InlineData(0b00, 0b01)]
    [InlineData(0b01, 0b10)]
    [InlineData(0b10, 0b11)]
    public void Version2WritesSectionFivesTypeValues(int version1Value, byte expected)
    {
        var type = (TlsQuicLongPacketType)version1Value;
        // rfc9369 s5, transcribed: "Initial: 0b01, 0-RTT: 0b10, Handshake: 0b11, Retry: 0b00."
        // The four are asserted as HAND-WRITTEN NUMBERS and not as (v1 + 1) % 4, because that
        // arithmetic is a coincidence of how the two RFCs happen to order their lists and is
        // exactly the shortcut a wrong implementation would also take.
        Assert.Equal(expected, TypeBitsOf(type, TlsQuicVersion.Version2));

        // ...and version 1 is untouched, which is the other half: a remap applied to both
        // versions would satisfy the line above and break every connection this library makes.
        Assert.Equal((byte)type, TypeBitsOf(type, TlsQuicVersion.Version1));
    }

    [Fact]
    public void RetryIsZeroInVersionTwoAndThreeInVersionOne()
    {
        // Retry is the pair that crosses: 0b11 in v1 and 0b00 in v2. It is separated from the
        // theory above because a Retry header carries an integrity tag instead of a packet
        // number, so it is a different shape rather than a fourth row.
        var retry = new TlsQuicLongHeader
        {
            Type = TlsQuicLongPacketType.Retry,
            Version = (uint)TlsQuicVersion.Version2,
            DestinationConnectionId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
            SourceConnectionId = new byte[] { 9, 10, 11, 12 },
            Token = new byte[] { 0xAA, 0xBB },
            RetryIntegrityTag = new byte[16],
        };

        var buffer = new byte[128];
        TlsQuicPacketHeader.WriteLongHeader(buffer, retry, out _);
        Assert.Equal(0b00, (buffer[0] & 0x30) >> 4);

        TlsQuicPacketHeader.WriteLongHeader(
            buffer, retry with { Version = (uint)TlsQuicVersion.Version1 }, out _);
        Assert.Equal(0b11, (buffer[0] & 0x30) >> 4);
    }

    [Theory]
    [InlineData(0b00)]
    [InlineData(0b01)]
    [InlineData(0b10)]
    public void AVersionTwoHeaderRoundTripsToTheSameType(int version1Value)
    {
        var type = (TlsQuicLongPacketType)version1Value;
        var buffer = new byte[128];
        var written = TlsQuicPacketHeader.WriteLongHeader(
            buffer, Header(type, TlsQuicVersion.Version2), out _);

        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(
            buffer.AsMemory(0, written + 20), out var parsed, out _));

        Assert.Equal(type, parsed.Type);
        Assert.Equal((uint)TlsQuicVersion.Version2, parsed.Version);
    }

    [Fact]
    public void AVersionOneReaderWouldHaveMistypedEveryVersionTwoHeader()
    {
        // THE BUG, PINNED AS A DIFFERENCE. Reading a v2 Initial with v1's numbering yields
        // 0-RTT, which is the failure the old unconditional cast produced: the keys derived
        // correctly - TlsQuicSecrets was already version-aware - and the packet was still the
        // wrong kind. If this ever stops differing, the remap has been removed.
        var buffer = new byte[128];
        var written = TlsQuicPacketHeader.WriteLongHeader(
            buffer, Header(TlsQuicLongPacketType.Initial, TlsQuicVersion.Version2), out _);

        var rawBits = (TlsQuicLongPacketType)((buffer[0] & 0x30) >> 4);
        Assert.NotEqual(TlsQuicLongPacketType.Initial, rawBits);
        Assert.Equal(TlsQuicLongPacketType.ZeroRtt, rawBits);

        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(
            buffer.AsMemory(0, written + 20), out var parsed, out _));
        Assert.Equal(TlsQuicLongPacketType.Initial, parsed.Type);
    }
}
