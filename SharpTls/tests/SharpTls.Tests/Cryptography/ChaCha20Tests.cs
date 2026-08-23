using SharpTls.Cryptography;

namespace SharpTls.Tests.Cryptography;

public sealed class ChaCha20Tests
{
    // RFC 8439 s2.3.2: the RFC's own published test vector for the raw
    // block function, fetched from https://www.rfc-editor.org/rfc/rfc8439.txt
    // rather than transcribed from memory. Key = 00:01:...:1f, Nonce =
    // (00:00:00:09:00:00:00:4a:00:00:00:00), Block Count = 1. Each row below
    // is one 16-byte line of the RFC's own "Serialized Block:" hex dump, kept
    // separate rather than fused into one blob to make it checkable against
    // the source line by line.
    [Fact]
    public void MatchesRfc8439BlockFunctionTestVector()
    {
        var key = Convert.FromHexString(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var nonce = Convert.FromHexString("000000090000004a00000000");
        Span<byte> block = stackalloc byte[64];

        ChaCha20.Block(key, counter: 1, nonce, block);

        const string row0 = "10f1e7e4d13b5915500fdd1fa32071c4"; // 000  10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
        const string row1 = "c7d1f4c733c068030422aa9ac3d46c4e"; // 016  c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
        const string row2 = "d2826446079faa0914c2d705d98b02a2"; // 032  d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
        const string row3 = "b5129cd1de164eb9cbd083e8a2503c4e"; // 048  b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e

        Assert.Equal(row0 + row1 + row2 + row3, Convert.ToHexString(block), ignoreCase: true);
    }

    // RFC 8439 s2.6.2: the Poly1305 key-generation worked example, which
    // exercises Block Count = 0 (the vector above only covers Block Count =
    // 1) using the same block function. Only the first 32 of the 64 output
    // bytes are published for this example.
    [Fact]
    public void MatchesRfc8439Poly1305KeyGenerationTestVector()
    {
        var key = Convert.FromHexString(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        var nonce = Convert.FromHexString("000000000001020304050607");
        Span<byte> block = stackalloc byte[64];

        ChaCha20.Block(key, counter: 0, nonce, block);

        const string row0 = "8ad5a08b905f81cc815040274ab29471"; // 000  8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71
        const string row1 = "a833b637e3fd0da508dbb8e2fdd1a646"; // 016  a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46

        Assert.Equal(row0 + row1, Convert.ToHexString(block[..32]), ignoreCase: true);
    }

    // The single internal caller (TlsQuicHeaderProtection) always passes
    // correctly sized arguments, so these guards have no other coverage.
    [Fact]
    public void ThrowsForWrongKeyLength()
    {
        Assert.Throws<ArgumentException>(() => ChaCha20.Block(new byte[31], 0, new byte[12], new byte[64]));
    }

    [Fact]
    public void ThrowsForWrongNonceLength()
    {
        Assert.Throws<ArgumentException>(() => ChaCha20.Block(new byte[32], 0, new byte[11], new byte[64]));
    }

    [Fact]
    public void ThrowsForWrongDestinationLength()
    {
        Assert.Throws<ArgumentException>(() => ChaCha20.Block(new byte[32], 0, new byte[12], new byte[63]));
    }
}
