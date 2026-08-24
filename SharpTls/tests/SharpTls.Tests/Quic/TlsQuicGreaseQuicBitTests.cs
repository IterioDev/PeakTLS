using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

/// <content>
/// RFC 9287's <c>grease_quic_bit</c> (0x2ab2), which was length-validated on arrival and then
/// ignored on both edges. Two independent halves, and the receive one was a latent hole rather
/// than a missing feature: a profile could advertise the parameter - the transport-parameter
/// list accepts any identifier by design - and then discard every packet the peer greased in
/// reply, because RFC 9000 s17.2's "MUST be discarded" was applied unconditionally.
/// </content>
public sealed class TlsQuicGreaseQuicBitTests
{
    private const byte QuicBit = 0x40;

    private static TlsQuicLongHeader Header(bool grease) =>
        new()
        {
            Type = TlsQuicLongPacketType.Handshake,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
            SourceConnectionId = new byte[] { 9, 10, 11, 12 },
            PacketNumber = new byte[] { 0x42 },
            PacketNumberLength = 1,
            Length = 20,
            GreaseFixedBit = grease,
        };

    [Fact]
    public void TheQuicBitIsSetUnlessTheHeaderAsksForItToBeGreased()
    {
        var buffer = new byte[128];

        TlsQuicPacketHeader.WriteLongHeader(buffer, Header(grease: false), out _);
        Assert.Equal(QuicBit, buffer[0] & QuicBit);

        TlsQuicPacketHeader.WriteLongHeader(buffer, Header(grease: true), out _);
        Assert.Equal(0, buffer[0] & QuicBit);
    }

    [Fact]
    public void ADefaultConstructedHeaderStillWritesTheMandatoryOne()
    {
        // THE REASON THE FIELD'S SENSE IS INVERTED. `GreaseFixedBit` defaults to false, so a
        // default-constructed header writes s17.2's mandatory 1. A `FixedBit` property
        // defaulting to true would read better and would be silently wrong for every `default`
        // struct in this tree - the bug would be a packet every peer discards.
        var buffer = new byte[128];
        var header = Header(grease: false);
        Assert.False(default(TlsQuicLongHeader).GreaseFixedBit);
        Assert.False(header.GreaseFixedBit);

        TlsQuicPacketHeader.WriteLongHeader(buffer, header, out _);
        Assert.Equal(QuicBit, buffer[0] & QuicBit);
    }

    [Fact]
    public void AGreasedHeaderIsDiscardedByDefaultAndReadWhenTheParameterWasAdvertised()
    {
        var buffer = new byte[128];
        var written = TlsQuicPacketHeader.WriteLongHeader(buffer, Header(grease: true), out _);
        var datagram = buffer.AsMemory(0, written + 20);

        // s17.2 for an endpoint that granted no permission: "Packets containing a zero value
        // for this bit are not valid packets in this version and MUST be discarded."
        Assert.False(TlsQuicPacketHeader.TryReadLongHeader(datagram, out _, out _));

        // RFC 9287 s3 for one that did: "An endpoint that advertises the grease_quic_bit
        // transport parameter MUST accept packets with the QUIC Bit set to 0."
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(
            datagram, out var parsed, out _, acceptGreasedQuicBit: true));
        Assert.Equal(TlsQuicLongPacketType.Handshake, parsed.Type);
    }

    [Fact]
    public void AGreasedShortHeaderFollowsTheSameRule()
    {
        var buffer = new byte[128];
        var header = new TlsQuicShortHeader
        {
            DestinationConnectionId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
            PacketNumber = new byte[] { 0x07 },
            PacketNumberLength = 1,
            GreaseFixedBit = true,
        };

        TlsQuicPacketHeader.WriteShortHeader(buffer, header, out _);
        Assert.Equal(0, buffer[0] & QuicBit);

        var datagram = buffer.AsMemory(0, 32);
        Assert.False(TlsQuicPacketHeader.TryReadShortHeader(datagram, 8, out _, out _));
        Assert.True(TlsQuicPacketHeader.TryReadShortHeader(
            datagram, 8, out _, out _, acceptGreasedQuicBit: true));
    }

    [Fact]
    public void AGreasedPacketDoesNotSwallowTheOnesCoalescedBehindIt()
    {
        // THE HALF THAT IS EASY TO MISS. TlsQuicDatagramReader uses TryReadLongHeader to find
        // each coalesced packet's BOUNDARY, so a greased header there does not merely fail to
        // parse - it ends the walk, and every packet behind it in the datagram is lost with it.
        var buffer = new byte[256];
        var first = TlsQuicPacketHeader.WriteLongHeader(buffer, Header(grease: true), out _);
        var payload = first + 20;
        var second = TlsQuicPacketHeader.WriteLongHeader(
            buffer.AsSpan(payload), Header(grease: true), out _);
        var total = payload + second + 20;

        Assert.Empty(TlsQuicDatagramReader.Read(buffer.AsMemory(0, total)));
        Assert.Equal(
            2,
            TlsQuicDatagramReader.Read(buffer.AsMemory(0, total), acceptGreasedQuicBit: true)
                .Count());
    }
}
