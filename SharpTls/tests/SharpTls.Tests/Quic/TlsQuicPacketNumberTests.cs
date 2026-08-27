using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicPacketNumberTests
{
    [Fact]
    public void DecodesTheRfcWorkedExample()
    {
        // RFC 9000 A.3: "if the highest successfully authenticated packet had a
        // packet number of 0xa82f30ea, then a packet containing a 16-bit value
        // of 0x9b32 will be decoded as 0xa82f9b32."
        Assert.Equal(
            0xa82f9b32UL,
            TlsQuicPacketNumber.Decode(largestPn: 0xa82f30eaUL, truncated: 0x9b32, bits: 16));
    }

    [Fact]
    public void DecodeAdjustsUpwardWhenTheCandidateIsBelowTheWindow()
    {
        // expected_pn = 500, candidate = (500 & ~255) | 3 = 259, which is at or
        // below expected_pn - pn_hwin (372), so RFC 9000 A.3 adds pn_win.
        // Without that branch this returns 259.
        Assert.Equal(515UL, TlsQuicPacketNumber.Decode(largestPn: 499, truncated: 3, bits: 8));
    }

    [Fact]
    public void DecodeAdjustsDownwardWhenTheCandidateIsAboveTheWindow()
    {
        // expected_pn = 300, candidate = (300 & ~255) | 0xFC = 508, which is above
        // expected_pn + pn_hwin (428), so RFC 9000 A.3 subtracts pn_win.
        // Without that branch this returns 508.
        Assert.Equal(252UL, TlsQuicPacketNumber.Decode(largestPn: 299, truncated: 0xFC, bits: 8));
    }

    [Fact]
    public void EncodedLengthIsTwoBytesForTheRfcWorkedExample()
    {
        // RFC 9000 A.2: acked 0xabe8b3, sending 0xac5c02 leaves 29,519 (0x734f)
        // outstanding; representing at least twice that range needs 16 bits.
        Assert.Equal(2, TlsQuicPacketNumber.EncodedLength(fullPn: 0xac5c02, largestAcked: 0xabe8b3));
    }

    [Fact]
    public void EncodedLengthIsThreeBytesForTheRfcWorkedExample()
    {
        // RFC 9000 A.2: same state, sending 0xace8fe needs 24 bits.
        Assert.Equal(3, TlsQuicPacketNumber.EncodedLength(fullPn: 0xace8fe, largestAcked: 0xabe8b3));
    }

    [Fact]
    public void EncodedLengthWithNothingAckedUsesFullPnPlusOne()
    {
        // RFC 9000 A.2: "if largest_acked is None: num_unacked = full_pn + 1".
        Assert.Equal(1, TlsQuicPacketNumber.EncodedLength(fullPn: 0, largestAcked: null));
    }

    // RFC 9000 A.2's min_bits comes from a real-valued log2, and ceil(min_bits / 8)
    // is taken on that real value. A floor-based log2 loses the fractional part
    // that pushes the byte count up whenever floor(log2(num_unacked)) + 1 lands
    // exactly on an 8-bit boundary and num_unacked is not itself a power of two
    // (i.e. num_unacked in (128,255], (32768,65535], ...). Do not "simplify"
    // this bump away - it is exactly what the failing test at 255 was for.
    [Theory]
    [InlineData(128UL, 1)]
    [InlineData(129UL, 2)]
    [InlineData(255UL, 2)]
    [InlineData(256UL, 2)]
    [InlineData(32768UL, 2)]
    [InlineData(32769UL, 3)]
    [InlineData(65535UL, 3)]
    [InlineData(65536UL, 3)]
    public void EncodedLengthRoundsUpAtEightBitBoundaries(ulong numUnacked, int expectedBytes)
    {
        // largestAcked = null and fullPn = numUnacked - 1 gives num_unacked ==
        // fullPn + 1 == numUnacked, per RFC 9000 A.2's "largest_acked is None" case.
        Assert.Equal(expectedBytes, TlsQuicPacketNumber.EncodedLength(fullPn: numUnacked - 1, largestAcked: null));
    }

    [Theory]
    [InlineData(128UL)]
    [InlineData(255UL)]
    [InlineData(32768UL)]
    [InlineData(65536UL)]
    public void EncodedLengthIsAlwaysBetweenOneAndFourBytes(ulong numUnacked)
    {
        var length = TlsQuicPacketNumber.EncodedLength(fullPn: numUnacked - 1, largestAcked: null);
        Assert.InRange(length, 1, 4);
    }

    [Theory]
    [InlineData((1UL << 31) + 1)]
    [InlineData(1UL << 32)]
    [InlineData(1UL << 40)]
    public void EncodedLengthRejectsAnAckGapWiderThanFourBytesCanDisambiguate(ulong numUnacked)
    {
        // RFC 9000 s17.1 gives the Packet Number field 1 to 4 bytes, so 32 bits is the
        // widest truncation that exists, and RFC 9000 A.3's DecodePacketNumber resolves a
        // 32-bit truncation only to within pn_hwin = 2^31 of expected_pn. A.2's arithmetic
        // therefore asks for 5 bytes once num_unacked passes 2^31 - a length the wire
        // format has no room for.
        //
        // Before the fix this returned 5, and the only place that saw it - TlsQuicPacket
        // Builder.ValidatePacketNumberEncoding - reported it as a FLOOR ("needs at least 5
        // bytes") that its own 1-to-4 guard makes unsatisfiable. Name the condition that
        // actually happened instead. numUnacked - 1 with largestAcked = null gives
        // num_unacked == fullPn + 1 == numUnacked, per A.2's "largest_acked is None" case.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => TlsQuicPacketNumber.EncodedLength(fullPn: numUnacked - 1, largestAcked: null));
    }

    [Fact]
    public void EncodedLengthStillAcceptsTheWidestEncodableAckGap()
    {
        // The boundary the throw above must not swallow: num_unacked == 2^31 exactly is
        // min_bits = 32, which is four bytes and legal. One past it is not.
        Assert.Equal(
            4,
            TlsQuicPacketNumber.EncodedLength(fullPn: (1UL << 31) - 1, largestAcked: null));
    }

    [Fact]
    public void EncodedLengthRejectsFullPnBelowLargestAcked()
    {
        // A caller passing fullPn < largestAcked is a programmer error: the ulong
        // subtraction would otherwise wrap to a huge value instead of going
        // negative. Fail loudly instead of returning nonsense.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => TlsQuicPacketNumber.EncodedLength(fullPn: 10, largestAcked: 11));
    }

    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void EncodeThenDecodeRoundTrips(int bits)
    {
        const ulong largestPn = 1000;
        var full = largestPn + 1;
        var truncated = TlsQuicPacketNumber.Truncate(full, bits);

        Assert.Equal(full, TlsQuicPacketNumber.Decode(largestPn, truncated, bits));
    }

    [Fact]
    public void DecodeDoesNotOverflowNearTheSixtyTwoBitCeiling()
    {
        // The guard "candidate_pn < (1 << 62) - pn_win" exists to stop the
        // upward adjustment wrapping past the 62-bit packet number ceiling.
        var largest = (1UL << 62) - 2;
        var result = TlsQuicPacketNumber.Decode(largest, truncated: 0x00, bits: 8);

        Assert.True(result < (1UL << 62), $"decoded {result} exceeded the 62-bit ceiling");
    }

    [Fact]
    public void DecodeDoesNotUnderflowNearZero()
    {
        // The guard "candidate_pn >= pn_win" exists to stop the downward
        // adjustment wrapping below zero.
        var result = TlsQuicPacketNumber.Decode(largestPn: 0, truncated: 0xFF, bits: 8);

        Assert.True(result < (1UL << 62), $"decoded {result} exceeded the 62-bit ceiling");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(33)]
    [InlineData(64)]
    public void DecodeRejectsIllegalBitWidths(int bits)
    {
        // RFC 9000 A.3: pn_nbits is 8, 16, 24 or 32.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => TlsQuicPacketNumber.Decode(largestPn: 100, truncated: 1, bits: bits));
    }
}
