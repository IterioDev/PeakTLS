using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SharpTls.Quic;

// RFC 9001 s5.3: which AEAD family. AES-128-GCM vs AES-256-GCM is not a
// separate case here either - System.Security.Cryptography.AesGcm
// self-selects the variant from the caller-supplied 16- or 32-byte key,
// same reasoning as TlsQuicHeaderProtectionCipher.Aes - but
// ChaCha20-Poly1305 is a distinct .NET type with its own key/nonce/tag
// handling, so the two families are distinguished explicitly.
internal enum TlsQuicPacketProtectionCipher
{
    /// AEAD_AES_128_GCM or AEAD_AES_256_GCM, selected by key length (16 or 32 bytes).
    AesGcm,

    /// AEAD_CHACHA20_POLY1305.
    ChaCha20Poly1305,
}

/// <summary>
/// RFC 9001 s5.3: AEAD packet protection. Seals (encrypts+authenticates) or
/// opens (verifies+decrypts) a QUIC packet's payload - independent of header
/// protection (Task 4's <see cref="TlsQuicHeaderProtection"/>), which masks a
/// different part of the packet using a different key.
/// </summary>
/// <remarks>
/// Ordering (s5.3): "When constructing packets, the AEAD function is applied
/// prior to applying header protection... When processing packets, an
/// endpoint first removes the header protection." So a sender always calls
/// <see cref="Seal"/> before <see cref="TlsQuicHeaderProtection.TryApply"/>;
/// a receiver always calls <see cref="TlsQuicHeaderProtection.TryRemove"/>
/// before <see cref="TryOpen"/>. This type implements only the two AEAD ends
/// of that pipeline - callers own the ordering.
/// </remarks>
//
// The associated data is always a caller-supplied span, never recomputed
// here from packet layout: TlsQuicLongHeader.PacketNumberOffset and
// TlsQuicShortHeader.PacketNumberOffset (plus PacketNumberLength) already
// report exactly where s5.3's "up to and including the unprotected packet
// number" boundary falls - on the header in its unprotected state, i.e.
// after TlsQuicHeaderProtection.TryRemove on receive, or before
// TlsQuicHeaderProtection.TryApply on send. Callers slice from there
// instead of this type re-deriving the same boundary a second time.
internal static class TlsQuicPacketProtection
{
    // RFC 9001 s5.3: "These cipher suites have a 16-byte authentication tag."
    private const int TagLength = 16;

    // RFC 9001 s5.1: "The Length provided with 'quic iv' is the minimum
    // length of the AEAD nonce or 8 bytes if that is larger" - 12 bytes for
    // every AEAD QUIC uses here. Matches every IV this codebase derives
    // (TlsQuicPacketProtectionKeys.CopyIv via Tls13Hkdf.ExpandLabel(..., 12)).
    private const int NonceLength = 12;

    // RFC 9001 s5.3: seals `plaintext` into `ciphertext` (which must be
    // exactly plaintext.Length + 16 bytes for the AEAD tag) under
    // `key`/`iv` at `packetNumber`, authenticating `associatedData`
    // alongside it. Unlike TryOpen, sealing your own plaintext under your
    // own key has no routine failure mode worth a bool return - a
    // mis-sized destination is a caller bug, and AesGcm/ChaCha20Poly1305
    // already throw ArgumentException for that, consistent with
    // WriteLongHeader/WriteShortHeader elsewhere in this namespace.
    internal static void Seal(
        TlsQuicPacketProtectionCipher cipher,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ulong packetNumber,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext)
    {
        if (ciphertext.Length != plaintext.Length + TagLength)
        {
            throw new ArgumentException(
                $"Ciphertext must be exactly {TagLength} bytes longer than the plaintext.",
                nameof(ciphertext));
        }

        Span<byte> nonce = stackalloc byte[NonceLength];
        try
        {
            ComputeNonce(iv, packetNumber, nonce);

            var body = ciphertext[..plaintext.Length];
            var tag = ciphertext[plaintext.Length..];

            switch (cipher)
            {
                case TlsQuicPacketProtectionCipher.AesGcm:
                    using (var aesGcm = new AesGcm(key, TagLength))
                    {
                        aesGcm.Encrypt(nonce, plaintext, body, tag, associatedData);
                    }
                    break;
                case TlsQuicPacketProtectionCipher.ChaCha20Poly1305:
                    using (var chaCha20Poly1305 = new ChaCha20Poly1305(key))
                    {
                        chaCha20Poly1305.Encrypt(nonce, plaintext, body, tag, associatedData);
                    }
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(cipher), cipher, "Unknown packet protection cipher.");
            }
        }
        finally
        {
            // nonce = IV XOR packetNumber, and packetNumber is public (it
            // travels in clear on the wire once header protection is
            // removed) - so a leaked nonce plus the known packet number
            // recovers the secret IV directly (IV = nonce XOR pn). Zeroed on
            // every exit path, matching TlsQuicSecrets.Dispose and
            // ChaCha20.Block's zeroing of their own stack-held key material.
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    // RFC 9001 s5.3 combined with RFC 9000 s14 (malformed/forged packets
    // "MUST be discarded" rather than tearing down the connection): failure
    // to authenticate is routine - it happens on every stray or forged
    // datagram - so it is reported as a false return, never an exception.
    // `plaintext` must be exactly ciphertext.Length - 16 bytes.
    internal static bool TryOpen(
        TlsQuicPacketProtectionCipher cipher,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ulong packetNumber,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> plaintext)
    {
        if (ciphertext.Length < TagLength || plaintext.Length != ciphertext.Length - TagLength)
        {
            return false;
        }

        Span<byte> nonce = stackalloc byte[NonceLength];
        try
        {
            ComputeNonce(iv, packetNumber, nonce);

            var body = ciphertext[..^TagLength];
            var tag = ciphertext[^TagLength..];

            try
            {
                switch (cipher)
                {
                    case TlsQuicPacketProtectionCipher.AesGcm:
                        using (var aesGcm = new AesGcm(key, TagLength))
                        {
                            aesGcm.Decrypt(nonce, body, tag, plaintext, associatedData);
                        }
                        break;
                    case TlsQuicPacketProtectionCipher.ChaCha20Poly1305:
                        using (var chaCha20Poly1305 = new ChaCha20Poly1305(key))
                        {
                            chaCha20Poly1305.Decrypt(nonce, body, tag, plaintext, associatedData);
                        }
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(cipher), cipher, "Unknown packet protection cipher.");
                }
                return true;
            }
            catch (AuthenticationTagMismatchException)
            {
                // RFC 9000 s14: routine on every stray or forged datagram, not
                // an exceptional condition. Defensively clear whatever the
                // failed decrypt may have written rather than trust that both
                // underlying AEAD implementations already do so.
                CryptographicOperations.ZeroMemory(plaintext);
                return false;
            }
        }
        finally
        {
            // Same reasoning as Seal's finally: nonce = IV XOR packetNumber
            // and packetNumber is public, so the nonce must never outlive
            // this call - including on the authentication-failure path above.
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    // RFC 9001 s5.3: "The nonce, N, is formed by combining the packet
    // protection IV with the packet number. The 62 bits of the
    // reconstructed QUIC packet number in network byte order are
    // left-padded with zeros to the size of the IV. The exclusive OR of the
    // padded packet number and the IV forms the AEAD nonce." `packetNumber`
    // here is that reconstructed (full, untruncated) value - producing it
    // from the wire's truncated encoding (TlsQuicPacketNumber.Decode against
    // largest_acked on receive; the sender's own counter on send) is the
    // caller's job, not this method's.
    private static void ComputeNonce(ReadOnlySpan<byte> iv, ulong packetNumber, Span<byte> nonce)
    {
        if (iv.Length != NonceLength)
        {
            throw new ArgumentException($"IV must be exactly {NonceLength} bytes.", nameof(iv));
        }

        iv.CopyTo(nonce);

        Span<byte> packetNumberBytes = stackalloc byte[8];
        try
        {
            BinaryPrimitives.WriteUInt64BigEndian(packetNumberBytes, packetNumber);

            // "Left-padded with zeros to the size of the IV": an 8-byte
            // packetNumber XORed against the low-order (rightmost) bytes of
            // the 12-byte IV, high IV bytes untouched - equivalent to XORing
            // against a zero-prefixed 12-byte buffer without allocating one.
            var offset = nonce.Length - packetNumberBytes.Length;
            for (var i = 0; i < packetNumberBytes.Length; i++)
            {
                nonce[offset + i] ^= packetNumberBytes[i];
            }
        }
        finally
        {
            // Intermediate only (the packet number itself is public, unlike
            // nonce/IV), but zeroed anyway to match this file's blanket rule:
            // nothing nonce-shaped survives on the stack past its use.
            CryptographicOperations.ZeroMemory(packetNumberBytes);
        }
    }
}
