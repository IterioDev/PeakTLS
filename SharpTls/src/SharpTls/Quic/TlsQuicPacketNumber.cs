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
        // <=, NOT <. RFC 9000 s12.3: "A QUIC endpoint MUST NOT reuse a packet number within
        // the same packet number space", so a packet number EQUAL to one already acknowledged
        // is as impossible as one below it - and it is the equal case that fails quietly.
        // num_unacked becomes 0, BitOperations.Log2(0) returns 0 by documented convention
        // ("by convention, input value 0 returns 0 since Log(0) is undefined") rather than by
        // computing anything, and the result is a confident 1-byte encoding of a packet number
        // the peer has already seen. The guard stopped exactly one short of the case that
        // needed it.
        if (largestAcked is { } acked && fullPn <= acked)
        {
            throw new ArgumentOutOfRangeException(
                nameof(fullPn),
                fullPn,
                $"Packet number {fullPn} is not above the largest acknowledged {acked}.");
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

        // RFC 9000 s17.1: "Packet Number: This field is 1 to 4 bytes long." Four is
        // therefore the widest truncation the wire format has, and the arithmetic above
        // asks for five as soon as num_unacked passes 2^31 - min_bits = log2(2^31) + 1 =
        // 32 is the last value that still fits. Past that point A.2 has no answer, because
        // A.3's DecodePacketNumber resolves a 32-bit truncation only to within pn_hwin =
        // 2^31 of expected_pn: a wider gap decodes to a DIFFERENT packet number at the
        // peer, and nothing on either side notices.
        //
        // DO NOT CLAMP TO 4 HERE, which is the tempting one-line alternative. Clamping
        // returns a floor the caller can satisfy while destroying the only property the
        // floor exists to guarantee - it would hand back "4 is enough" for a gap where no
        // length is enough, and the silent misdecode above is precisely what the caller
        // consults this method to avoid. There is also no honest floor to report: the
        // pre-existing behaviour of returning 5 fed TlsQuicPacketBuilder.ValidatePacket
        // NumberEncoding, whose own s17.1 guard rejects anything above 4 first, so the
        // caller was told it needed a width that same caller forbids - a demand no plan
        // can ever meet, phrased as if the plan were at fault.
        //
        // Throw instead, naming the condition that actually happened: an acknowledgement
        // gap too wide for any legal packet number encoding. Reaching it needs 2^31
        // packets outstanding in one space, so this is an unreachable-in-practice contract
        // statement on a shared helper rather than a live failure mode - but it is now a
        // stated one. ArgumentOutOfRangeException on fullPn matches the largestAcked guard
        // at the top: both say "the pair of numbers you passed cannot be encoded".
        // Witnessed by TlsQuicPacketNumberTests.EncodedLengthRejectsAnAckGapWiderThanFour
        // BytesCanDisambiguate and TlsQuicPacketNumberTests.EncodedLengthStillAcceptsThe
        // WidestEncodableAckGap.
        if (numBytes > 4)
        {
            throw new ArgumentOutOfRangeException(
                nameof(fullPn),
                fullPn,
                $"RFC 9000 A.2 needs {numBytes} bytes to encode packet number {fullPn} against a "
                + $"largest acknowledged of {largestAcked?.ToString() ?? "none"}, but RFC 9000 s17.1 "
                + "gives the Packet Number field 1 to 4 bytes. The acknowledgement gap is "
                + $"{numUnacked} packets, wider than the 2^31 a 4-byte truncation can be decoded "
                + "back across by RFC 9000 A.3.");
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
