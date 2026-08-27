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
        if (!TryTakeSample(packet, packetNumberOffset, out var sample))
        {
            return false;
        }

        Span<byte> mask = stackalloc byte[MaskLength];
        KeyMask(cipher, headerProtectionKey, sample, mask);
        return ApplyMask(mask, packet, packetNumberOffset);
    }

    /// <summary>The same as the key-taking overload, over a key schedule its owner prepared
    /// once; see <see cref="TlsQuicHeaderProtectionKeySchedule"/>. The mask is the same mask -
    /// the schedule IS the key with s5.4's block cipher already derived - which is what
    /// TlsQuicHeaderProtectionTests.APreparedKeyScheduleProducesTheSameMaskAsTheRawKeyForBothCi
    /// phers pins on RFC 9001's own vectors, in both directions.</summary>
    internal static bool TryApply(
        TlsQuicHeaderProtectionKeySchedule schedule,
        Span<byte> packet,
        int packetNumberOffset)
    {
        ArgumentNullException.ThrowIfNull(schedule);

        if (!TryTakeSample(packet, packetNumberOffset, out var sample))
        {
            return false;
        }

        Span<byte> mask = stackalloc byte[MaskLength];
        schedule.Mask(sample, mask);
        return ApplyMask(mask, packet, packetNumberOffset);
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
    //
    // NO src CALLER, AND THAT IS THE POINT - DO NOT DELETE IT. The receiver takes the
    // schedule overload below, so a caller search finds this one unreferenced outside
    // tests and it reads as dead code. It is not: it is the REFERENCE the schedule is
    // checked against. TlsQuicHeaderProtectionTests.APreparedKeyScheduleProducesTheSame
    // MaskAsTheRawKeyForBothCiphers removes the same packet both ways and compares the
    // bytes, and that comparison is the only thing standing between a prepared cipher
    // and a silent divergence - it is what caught an AES arm that masked with CBC and a
    // random IV, which produces a well-formed packet no peer can open. Delete this
    // overload and the schedule is left being compared with itself.
    internal static bool TryRemove(
        TlsQuicHeaderProtectionCipher cipher,
        ReadOnlySpan<byte> headerProtectionKey,
        Span<byte> packet,
        int packetNumberOffset,
        out int packetNumberLength)
    {
        packetNumberLength = 0;

        if (!TryTakeSample(packet, packetNumberOffset, out var sample))
        {
            return false;
        }

        Span<byte> mask = stackalloc byte[MaskLength];
        KeyMask(cipher, headerProtectionKey, sample, mask);
        return RemoveMask(mask, packet, packetNumberOffset, out packetNumberLength);
    }

    /// <summary>The same as the key-taking overload, over a key schedule its owner prepared
    /// once; see <see cref="TlsQuicHeaderProtectionKeySchedule"/>.</summary>
    internal static bool TryRemove(
        TlsQuicHeaderProtectionKeySchedule schedule,
        Span<byte> packet,
        int packetNumberOffset,
        out int packetNumberLength)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        packetNumberLength = 0;

        if (!TryTakeSample(packet, packetNumberOffset, out var sample))
        {
            return false;
        }

        Span<byte> mask = stackalloc byte[MaskLength];
        schedule.Mask(sample, mask);
        return RemoveMask(mask, packet, packetNumberOffset, out packetNumberLength);
    }

    // The masking half of s5.4.1, shared by the four entries above so the two ways of DERIVING
    // a mask cannot drift in what they then DO with it. Reading the sample from a slice of the
    // packet these write to is safe by s5.4.2's own arithmetic: the sample begins at
    // packet_number_offset + 4 and the bytes written end there.
    private static bool ApplyMask(
        ReadOnlySpan<byte> mask, Span<byte> packet, int packetNumberOffset)
    {
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

    private static bool RemoveMask(
        ReadOnlySpan<byte> mask,
        Span<byte> packet,
        int packetNumberOffset,
        out int packetNumberLength)
    {
        packetNumberLength = 0;

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
    private static bool TryTakeSample(
        ReadOnlySpan<byte> packet, int packetNumberOffset, out ReadOnlySpan<byte> sample)
    {
        sample = default;

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

        sample = packet.Slice(packetNumberOffset + 4, SampleLength);
        return true;
    }

    // The mask from a raw key, deriving the block cipher per call and keeping nothing.
    //
    // THE SEND PATH IS THIS OVERLOAD'S CALLER AND THE REASON IS NOT SPEED. TlsQuicKeySet hands
    // out OWNED COPIES of the key bytes - TlsQuicWriteKeyMaterial copies in its constructor -
    // precisely so nothing survives a key update still pointing at material the set has since
    // zeroed. A prepared cipher cannot be copied, so handing one out would put that borrowed
    // lifetime straight back, one level up: a caller holding a schedule across an update holds
    // a destroyed key. See TlsQuicHeaderProtectionKeySchedule's remarks for who may hold one.
    private static void KeyMask(
        TlsQuicHeaderProtectionCipher cipher,
        ReadOnlySpan<byte> headerProtectionKey,
        ReadOnlySpan<byte> sample,
        Span<byte> mask)
    {
        switch (cipher)
        {
            // RFC 9001 s5.4.3: mask = AES-ECB(hp_key, sample). The key is copied
            // into the Aes instance and then zeroed - the instance itself is
            // disposed via `using`, which clears its internal key material.
            case TlsQuicHeaderProtectionCipher.Aes:
                using (var aes = Aes.Create())
                {
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
                    block[..MaskLength].CopyTo(mask);
                }

                return;

            // RFC 9001 s5.4.4: the sample's first 4 bytes are a little-endian block
            // counter, the remaining 12 are the nonce; the mask is ChaCha20
            // encrypting 5 zero bytes, which - since XOR with zero is a no-op - is
            // just the first 5 bytes of the raw keystream block.
            case TlsQuicHeaderProtectionCipher.ChaCha20:
                var counter = BinaryPrimitives.ReadUInt32LittleEndian(sample);
                Span<byte> keystream = stackalloc byte[64];
                ChaCha20.Block(headerProtectionKey, counter, sample[4..], keystream);
                keystream[..MaskLength].CopyTo(mask);
                return;

            default:
                throw new ArgumentOutOfRangeException(
                    nameof(cipher), cipher, "Unknown header protection cipher.");
        }
    }
}

/// <summary>
/// One header-protection key, prepared once for the packets it will mask.
/// </summary>
/// <remarks>
/// <para>RFC 9001 s5.4 runs a block cipher over a sample of EVERY packet, sent and received,
/// under a key that does not change while that key is installed. Deriving the cipher per packet
/// is what this removes: AES-ECB through a fresh <c>Aes.Create()</c> measured 836ns and 440
/// bytes of allocation per packet, and through an encryptor prepared once, 80ns and none. The
/// bytes are identical - same AES, same key, same sample; what is saved is the provider handle
/// round-trip and the object graph behind it.</para>
/// <para>WHO MAY HOLD ONE, AND WHY THAT IS NOT EVERY CALLER. A schedule cannot be copied, so it
/// can only ever be BORROWED - and a borrowed handle to key material is the exact shape of the
/// audit's finding 1, where a caller fetched key spans, a key update zeroed the arrays under
/// them, and 1-RTT packets went out sealed with zeros. <see cref="TlsQuicKeySet"/> closed that
/// by handing out owned copies; a schedule handed out beside them would reopen it one level up,
/// because the schedule is disposed when the level is re-keyed or discarded and a caller holding
/// one across an update holds a destroyed key. So the rule is that a schedule NEVER LEAVES ITS
/// OWNER: TlsQuicPacketReceiver keeps one per level inside its own read keys, masks with it in
/// place, and disposes it on the line that zeroes those keys. The send path fetches owned key
/// copies and derives per packet from them - see TlsQuicHeaderProtection's KeyMask - which is
/// slower and is the arrangement that cannot go stale.</para>
/// <para>NOT THREAD-SAFE, and it inherits that from its owner rather than adding it:
/// <see cref="System.Security.Cryptography.ICryptoTransform"/> keeps per-call state and
/// TlsQuicPacketReceiver already requires one thread of control, "one loop and no parallel
/// send/receive pumps".</para>
/// <para>ChaCha20 (s5.4.4) has no schedule to prepare - its block function takes the raw key -
/// so that arm keeps a copy of the key and zeroes it on disposal, and the two ciphers are one
/// type so that the owner has one thing to hold and one thing to dispose.</para>
/// </remarks>
internal sealed class TlsQuicHeaderProtectionKeySchedule : IDisposable
{
    private const int SampleLength = 16;
    private const int MaskLength = 5;

    private readonly TlsQuicHeaderProtectionCipher _cipher;

    // AES: the prepared encryptor, and a 16-byte block for it to write into. ECB has no
    // chaining state, so RFC 9001 s5.4.3's single-block encryption is the same transform used
    // over and over rather than a stream that has to be reset between packets.
    private readonly ICryptoTransform? _aes;
    private readonly byte[]? _aesSample;
    private readonly byte[]? _aesBlock;

    // ChaCha20: the key itself, because ChaCha20.Block takes it per call.
    private readonly byte[]? _chachaKey;

    private bool _disposed;

    internal TlsQuicHeaderProtectionKeySchedule(
        TlsQuicHeaderProtectionCipher cipher, ReadOnlySpan<byte> headerProtectionKey)
    {
        _cipher = cipher;
        switch (cipher)
        {
            case TlsQuicHeaderProtectionCipher.Aes:
                // s5.4.3 is silent on AES-128 versus AES-256 because it does not need to
                // choose: Aes self-selects from the key length the caller supplies, exactly as
                // the per-packet form did.
                var aes = Aes.Create();
                try
                {
                    // ECB AND NO PADDING, SET BEFORE THE ENCRYPTOR IS TAKEN. Aes.Create()
                    // hands back CBC with a RANDOMLY GENERATED IV, so an encryptor made from
                    // the defaults masks with AES-CBC under a nonce nobody else has - every
                    // packet unopenable, and the first version of this type did exactly that.
                    // s5.4.3 asks for AES-ECB over one block: no chaining, no padding, which
                    // is also what makes one transform reusable for every packet.
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.None;

                    var keyBytes = headerProtectionKey.ToArray();
                    try
                    {
                        aes.Key = keyBytes;
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(keyBytes);
                    }

                    _aes = aes.CreateEncryptor();
                }
                finally
                {
                    // The encryptor holds its own copy of the schedule, so the algorithm object
                    // has nothing left to contribute and its key material goes now rather than
                    // at some later collection.
                    aes.Dispose();
                }

                _aesSample = new byte[SampleLength];
                _aesBlock = new byte[SampleLength];
                break;

            case TlsQuicHeaderProtectionCipher.ChaCha20:
                _chachaKey = headerProtectionKey.ToArray();
                break;

            default:
                throw new ArgumentOutOfRangeException(
                    nameof(cipher), cipher, "Unknown header protection cipher.");
        }
    }

    /// <summary>RFC 9001 s5.4.2's mask for one 16-byte sample: five bytes, the first for byte 0
    /// and the rest for the packet number.</summary>
    internal void Mask(ReadOnlySpan<byte> sample, Span<byte> mask)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_cipher == TlsQuicHeaderProtectionCipher.Aes)
        {
            // RFC 9001 s5.4.3: mask = AES-ECB(hp_key, sample). TransformBlock rather than
            // EncryptEcb because the latter builds a fresh cipher per call - which is the cost
            // this type exists to remove - and rather than TransformFinalBlock, which returns a
            // freshly allocated array. ECB treats each block independently, so repeated
            // TransformBlock calls carry nothing between packets.
            sample.CopyTo(_aesSample!);
            _aes!.TransformBlock(_aesSample!, 0, SampleLength, _aesBlock!, 0);
            _aesBlock.AsSpan(0, MaskLength).CopyTo(mask);
            return;
        }

        // RFC 9001 s5.4.4: the sample's first 4 bytes are a little-endian block
        // counter, the remaining 12 are the nonce; the mask is ChaCha20
        // encrypting 5 zero bytes, which - since XOR with zero is a no-op - is
        // just the first 5 bytes of the raw keystream block.
        var counter = BinaryPrimitives.ReadUInt32LittleEndian(sample);
        var nonce = sample[4..];

        Span<byte> block = stackalloc byte[64];
        ChaCha20.Block(_chachaKey, counter, nonce, block);
        block[..MaskLength].CopyTo(mask);
    }

    /// <summary>Destroys the prepared key. Called by whoever zeroes the key bytes this was
    /// built from, in the same breath; see the type's remarks.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _aes?.Dispose();
        if (_chachaKey is not null)
        {
            CryptographicOperations.ZeroMemory(_chachaKey);
        }
    }
}
