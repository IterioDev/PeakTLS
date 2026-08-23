using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SharpTls.Cryptography;

// RFC 8439 s2.3: the raw ChaCha20 block function. QUIC header protection
// (RFC 9001 s5.4.4) needs this directly, keyed by a 32-byte hp key and an
// explicit block counter recovered from the packet sample - not the
// combined AEAD construction .NET exposes as ChaCha20Poly1305. Pinned
// against RFC 8439's own published block-function test vector (s2.3.2)
// before any caller uses it; do not trust this from memory.
internal static class ChaCha20
{
    private const int BlockSize = 64;
    private const int KeyLength = 32;
    private const int NonceLength = 12;

    // RFC 8439 s2.3: constant words are the ASCII string "expand 32-byte k"
    // split into four little-endian 32-bit words.
    private const uint Constant0 = 0x61707865;
    private const uint Constant1 = 0x3320646e;
    private const uint Constant2 = 0x79622d32;
    private const uint Constant3 = 0x6b206574;

    // RFC 8439 s2.3/2.3.1: state = constants | key | counter | nonce; run 10
    // iterations of the 8 quarter rounds (= 20 rounds); add the original
    // state back in; serialize word-by-word in little-endian order.
    internal static void Block(
        ReadOnlySpan<byte> key, uint counter, ReadOnlySpan<byte> nonce, Span<byte> destination)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException($"ChaCha20 key must be {KeyLength} bytes.", nameof(key));
        }
        if (nonce.Length != NonceLength)
        {
            throw new ArgumentException($"ChaCha20 nonce must be {NonceLength} bytes.", nameof(nonce));
        }
        if (destination.Length != BlockSize)
        {
            throw new ArgumentException($"Destination must be exactly {BlockSize} bytes.", nameof(destination));
        }

        Span<uint> state = stackalloc uint[16];
        Span<uint> working = stackalloc uint[16];
        try
        {
            state[0] = Constant0;
            state[1] = Constant1;
            state[2] = Constant2;
            state[3] = Constant3;
            for (var i = 0; i < 8; i++)
            {
                state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(i * 4)..]);
            }
            state[12] = counter;
            for (var i = 0; i < 3; i++)
            {
                state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[(i * 4)..]);
            }

            state.CopyTo(working);

            for (var round = 0; round < 10; round++)
            {
                // RFC 8439 s2.3: quarter rounds 1-4 form a "column round" over
                // (0,4,8,12)/(1,5,9,13)/(2,6,10,14)/(3,7,11,15); 5-8 form a
                // "diagonal round" over (0,5,10,15)/(1,6,11,12)/(2,7,8,13)/(3,4,9,14).
                QuarterRound(working, 0, 4, 8, 12);
                QuarterRound(working, 1, 5, 9, 13);
                QuarterRound(working, 2, 6, 10, 14);
                QuarterRound(working, 3, 7, 11, 15);
                QuarterRound(working, 0, 5, 10, 15);
                QuarterRound(working, 1, 6, 11, 12);
                QuarterRound(working, 2, 7, 8, 13);
                QuarterRound(working, 3, 4, 9, 14);
            }

            for (var i = 0; i < 16; i++)
            {
                // RFC 8439 s2.3: "addition" here is modulo 2^32 - unchecked wraps
                // uint addition the same way, which is the intended behaviour.
                unchecked
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(destination[(i * 4)..], working[i] + state[i]);
                }
            }
        }
        finally
        {
            // state holds the raw 32-byte key (words 4-11); working holds
            // key-derived intermediate round state. Both are zeroed here -
            // not just on the success path - so a key never lingers on the
            // stack past this call, matching the zeroing discipline the AES
            // header-protection path already follows (TlsQuicHeaderProtection.AesMask).
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(state));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(working));
        }
    }

    // RFC 8439 s2.1: the ChaCha quarter round.
    private static void QuarterRound(Span<uint> state, int a, int b, int c, int d)
    {
        unchecked
        {
            state[a] += state[b]; state[d] ^= state[a]; state[d] = BitOperations.RotateLeft(state[d], 16);
            state[c] += state[d]; state[b] ^= state[c]; state[b] = BitOperations.RotateLeft(state[b], 12);
            state[a] += state[b]; state[d] ^= state[a]; state[d] = BitOperations.RotateLeft(state[d], 8);
            state[c] += state[d]; state[b] ^= state[c]; state[b] = BitOperations.RotateLeft(state[b], 7);
        }
    }
}
