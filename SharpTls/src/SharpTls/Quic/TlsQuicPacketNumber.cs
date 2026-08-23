using System.Numerics;

namespace SharpTls.Quic;

// RFC 9000 Appendix A.2 / A.3: truncated packet number encoding and decoding.
internal static class TlsQuicPacketNumber
{
    // RFC 9000 A.2: EncodePacketNumber. Returns the number of least-significant
    // bytes of full_pn that must be sent so the peer can recover it unambiguously.
    // The result is a byte count; multiply by 8 before passing it as the `bits`
    // argument to Truncate or Decode, which both operate in bits.
    internal static int EncodedLength(ulong fullPn, ulong? largestAcked)
    {
        if (largestAcked is { } acked && fullPn < acked)
        {
            throw new ArgumentOutOfRangeException(
                nameof(fullPn),
                fullPn,
                $"Packet number {fullPn} is below the largest acknowledged {acked}.");
        }

        var numUnacked = largestAcked is null ? fullPn + 1 : fullPn - largestAcked.Value;

        // min_bits = log(num_unacked, 2) + 1, using a real-valued log2. BitOperations.Log2
        // only gives floor(log2(value)) via a leading-zero-count, not Math.Log, so it's exact
        // integer arithmetic with no floating-point rounding - but it also discards the
        // fractional part of the real log2 that the RFC's ceil(min_bits / 8) depends on.
        // That fraction only changes the byte count when floor(log2(x)) + 1 lands exactly on
        // an 8-bit boundary and x itself is not a power of two (e.g. x = 255: real min_bits
        // ~8.994 needs 2 bytes, but floor-based min_bits = 8 rounds to 1). Bump the byte count
        // by one in exactly that case instead of switching to floating point.
        var k = BitOperations.Log2(numUnacked);
        var minBits = k + 1;
        var numBytes = (minBits + 7) / 8;
        // Do not remove: pinned by EncodedLengthRoundsUpAtEightBitBoundaries.
        if ((numUnacked & (numUnacked - 1)) != 0 && minBits % 8 == 0)
        {
            numBytes++;
        }
        return numBytes;
    }

    // RFC 9000 A.2: EncodePacketNumber, truncation step.
    // Truncates a full packet number to the least significant `bits` bits, as
    // sent on the wire in a packet's Packet Number field.
    internal static ulong Truncate(ulong fullPn, int bits)
    {
        ValidateBits(bits);
        return fullPn & ((1UL << bits) - 1);
    }

    // RFC 9000 A.3: DecodePacketNumber.
    internal static ulong Decode(ulong largestPn, ulong truncated, int bits)
    {
        ValidateBits(bits);

        var expectedPn = largestPn + 1;
        var pnWin = 1UL << bits;
        var pnHwin = pnWin / 2;
        var pnMask = pnWin - 1;
        var candidatePn = (expectedPn & ~pnMask) | truncated;

        // The RFC compares candidate_pn against expected_pn - pn_hwin using
        // unbounded integers, where that difference can be negative. ulong
        // subtraction would instead wrap around to a huge value (mod 2^64),
        // which would corrupt the "<=" comparison below. Since candidate_pn is
        // always non-negative, it can never be <= a mathematically negative
        // bound, so the branch simply cannot fire in that case - guard it
        // explicitly instead of computing the wrapped subtraction.
        if (expectedPn >= pnHwin)
        {
            var lowerBound = expectedPn - pnHwin;

            // Guards the overflow past the 62-bit packet number ceiling: do not
            // adjust upward if doing so would push candidate_pn to or past 2^62.
            if (candidatePn <= lowerBound && candidatePn < (1UL << 62) - pnWin)
            {
                return candidatePn + pnWin;
            }
        }

        // Guards the underflow below zero: do not adjust downward unless
        // candidate_pn - pn_win stays non-negative.
        if (candidatePn > expectedPn + pnHwin && candidatePn >= pnWin)
        {
            return candidatePn - pnWin;
        }

        return candidatePn;
    }

    private static void ValidateBits(int bits)
    {
        if (bits is not (8 or 16 or 24 or 32))
        {
            throw new ArgumentOutOfRangeException(
                nameof(bits),
                bits,
                "Packet number field width must be 8, 16, 24, or 32 bits.");
        }
    }
}
