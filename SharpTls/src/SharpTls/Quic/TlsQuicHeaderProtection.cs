using System.Buffers.Binary;
using System.Security.Cryptography;
using SharpTls.Cryptography;

namespace SharpTls.Quic;

// RFC 9001 s5.4: which AEAD family determines how the header protection
// mask is computed. AES-128 vs AES-256 (s5.4.3) is not a separate case -
// System.Security.Cryptography.Aes self-selects the variant from the
// caller-supplied 16- or 32-byte key - but ChaCha20 (s5.4.4) needs its own
// raw block function, so the two families are distinguished explicitly.
internal enum TlsQuicHeaderProtectionCipher
{
    /// AEAD_AES_128_GCM, AEAD_AES_128_CCM, AEAD_AES_256_GCM: mask = AES-ECB(hp_key, sample).
    Aes,

    /// AEAD_CHACHA20_POLY1305: mask = ChaCha20(hp_key, counter, nonce) encrypting 5 zero bytes.
    ChaCha20,
}

// RFC 9001 s5.4: QUIC header protection. Masks (Apply) or unmasks (Remove)
// the low bits of byte 0 and the Packet Number field using a mask derived
// by sampling 16 bytes of already-AEAD-protected ciphertext - this runs
// independently of, and does not perform, AEAD packet protection itself.
//
// The packet number offset is always a caller-supplied parameter (as
// TlsQuicLongHeader.PacketNumberOffset / TlsQuicShortHeader.PacketNumberOffset
// already report it) rather than recomputed here, so the wire layout is
// only ever derived in one place.
internal static class TlsQuicHeaderProtection
{
    // RFC 9000 s17.2/s17.3.1: the Header Form bit sits outside the
    // protection mask in both header forms, so it is trustworthy even on a
    // still-protected packet and is what selects between the two masks below.
    private const byte HeaderFormBit = 0x80;

    // RFC 9001 s5.4 (preamble, before s5.4.1's application pseudocode): "The
    // four least significant bits of the first byte are protected for
    // packets with long headers; the five least significant bits of the
    // first byte are protected for packets with short headers."
    private const byte LongHeaderProtectionMask = 0x0f;
    private const byte ShortHeaderProtectionMask = 0x1f;

    private const byte PacketNumberLengthMask = 0x03;

    // RFC 9001 s5.4.2: the sample is 16 bytes of protected payload.
    private const int SampleLength = 16;

    // mask[0] protects byte 0; mask[1..5] protect up to a 4-byte packet number.
    private const int MaskLength = 5;

    // RFC 9001 s5.4.1: applying protection to an as-yet-unprotected header.
    // Byte 0 is still in the clear on entry, so pn_length is read from it
    // BEFORE masking - the opposite order from TryRemove. Getting this
    // backwards here does not corrupt anything (byte 0 is already correct),
    // but doing it backwards in TryRemove does; see TryRemove's comment.
    internal static bool TryApply(
        TlsQuicHeaderProtectionCipher cipher,
        ReadOnlySpan<byte> headerProtectionKey,
        Span<byte> packet,
        int packetNumberOffset)
    {
        if (!TryComputeMask(cipher, headerProtectionKey, packet, packetNumberOffset, out var mask))
        {
            return false;
        }

        var pnLength = (packet[0] & PacketNumberLengthMask) + 1;
        if (packetNumberOffset + pnLength > packet.Length)
        {
            return false;
        }

        packet[0] ^= (byte)(mask[0] & ProtectionMaskFor(packet[0]));
        for (var i = 0; i < pnLength; i++)
        {
            packet[packetNumberOffset + i] ^= mask[1 + i];
        }
        return true;
    }

    // RFC 9001 s5.4.1: removing protection differs from applying it only in
    // the order pn_length is determined. Byte 0 is STILL MASKED on entry, so
    // reading pn_length from it now would read protected bits, not the real
    // packet number length. Byte 0 must be unmasked first; only the
    // now-correct byte 0 gives the real pn_length used below to unmask the
    // right number of packet number bytes. See
    // TlsQuicHeaderProtectionTests.RemovalReadsPacketNumberLengthAfterUnmaskingByte0Not
    // Before, whose RFC 9001 Appendix A.5 vector fails outright if this order
    // is reversed - and the mutation check recorded in that test's comment.
    internal static bool TryRemove(
        TlsQuicHeaderProtectionCipher cipher,
        ReadOnlySpan<byte> headerProtectionKey,
        Span<byte> packet,
        int packetNumberOffset,
        out int packetNumberLength)
    {
        packetNumberLength = 0;

        if (!TryComputeMask(cipher, headerProtectionKey, packet, packetNumberOffset, out var mask))
        {
            return false;
        }

        packet[0] ^= (byte)(mask[0] & ProtectionMaskFor(packet[0]));

        var pnLength = (packet[0] & PacketNumberLengthMask) + 1;
        if (packetNumberOffset + pnLength > packet.Length)
        {
            return false;
        }

        for (var i = 0; i < pnLength; i++)
        {
            packet[packetNumberOffset + i] ^= mask[1 + i];
        }

        packetNumberLength = pnLength;
        return true;
    }

    // RFC 9000 s17.2/s17.3.1: Header Form bit (0x80) selects the packet's
    // header form and is never covered by the protection mask itself, so it
    // is safe to read regardless of whether byte 0 is currently masked.
    private static byte ProtectionMaskFor(byte firstByte) =>
        (firstByte & HeaderFormBit) != 0 ? LongHeaderProtectionMask : ShortHeaderProtectionMask;

    // RFC 9001 s5.4.2: the sample is the 16 bytes of protected payload
    // starting at packet_number_offset + 4, regardless of the packet's
    // actual (possibly still-protected) packet number length - see
    // TlsQuicLongHeader.PacketNumberOffset's own doc comment. Try-shaped:
    // a sample that would run past the end of the packet is rejected here
    // without throwing, matching every other network-input parser in this
    // namespace (TlsQuicPacketHeader.TryReadLongHeader and friends).
    private static bool TryComputeMask(
        TlsQuicHeaderProtectionCipher cipher,
        ReadOnlySpan<byte> headerProtectionKey,
        ReadOnlySpan<byte> packet,
        int packetNumberOffset,
        out byte[] mask)
    {
        mask = [];

        // packet.Length is bounded (a real array length), so subtracting
        // from it cannot overflow - unlike the equivalent addition-based
        // check (packetNumberOffset + 4 + SampleLength > packet.Length),
        // which wraps for packetNumberOffset near int.MaxValue and would
        // let an out-of-bounds Slice below throw instead of returning false.
        if (packetNumberOffset < 0 ||
            packet.Length < 1 ||
            packetNumberOffset > packet.Length - 4 - SampleLength)
        {
            return false;
        }

        var sampleOffset = packetNumberOffset + 4;
        var sample = packet.Slice(sampleOffset, SampleLength);
        mask = cipher switch
        {
            TlsQuicHeaderProtectionCipher.Aes => AesMask(headerProtectionKey, sample),
            TlsQuicHeaderProtectionCipher.ChaCha20 => ChaCha20Mask(headerProtectionKey, sample),
            _ => throw new ArgumentOutOfRangeException(nameof(cipher), cipher, "Unknown header protection cipher."),
        };
        return true;
    }

    // RFC 9001 s5.4.3: mask = AES-ECB(hp_key, sample). The key is copied
    // into the Aes instance and then zeroed - the instance itself is
    // disposed via `using`, which clears its internal key material.
    private static byte[] AesMask(ReadOnlySpan<byte> headerProtectionKey, ReadOnlySpan<byte> sample)
    {
        using var aes = Aes.Create();
        var keyBytes = headerProtectionKey.ToArray();
        try
        {
            aes.Key = keyBytes;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        Span<byte> block = stackalloc byte[SampleLength];
        aes.EncryptEcb(sample, block, PaddingMode.None);

        var mask = new byte[MaskLength];
        block[..MaskLength].CopyTo(mask);
        return mask;
    }

    // RFC 9001 s5.4.4: the sample's first 4 bytes are a little-endian block
    // counter, the remaining 12 are the nonce; the mask is ChaCha20
    // encrypting 5 zero bytes, which - since XOR with zero is a no-op - is
    // just the first 5 bytes of the raw keystream block.
    private static byte[] ChaCha20Mask(ReadOnlySpan<byte> headerProtectionKey, ReadOnlySpan<byte> sample)
    {
        var counter = BinaryPrimitives.ReadUInt32LittleEndian(sample);
        var nonce = sample[4..];

        Span<byte> block = stackalloc byte[64];
        ChaCha20.Block(headerProtectionKey, counter, nonce, block);

        var mask = new byte[MaskLength];
        block[..MaskLength].CopyTo(mask);
        return mask;
    }
}
