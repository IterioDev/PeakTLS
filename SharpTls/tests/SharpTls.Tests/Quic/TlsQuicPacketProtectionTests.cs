using System.Buffers.Binary;
using System.Security.Cryptography;
using SharpTls.Fuzzing;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicPacketProtectionTests
{
    // RFC 9001 Appendix A.1: Initial secrets' derived key/IV (both directions
    // use AEAD_AES_128_GCM - see s5 "Initial packets use AEAD_AES_128_GCM").
    private const string ClientKeyHex = "1f369613dd76d5467730efcbe3b1a22d";
    private const string ClientIvHex = "fa044b2f42a3fd3b46fb255c";
    private const string ServerKeyHex = "cf3a5331653c364c88f0f379b6067e37";
    private const string ServerIvHex = "0ac1493ca1905853b0bba03e";

    // RFC 9001 Appendix A.2: client Initial. AssociatedData is the
    // UNPROTECTED header (s5.3: AEAD runs before header protection is
    // applied), i.e. header[0]=0xc3 and a plaintext packet number of 2 -
    // not the 0xc0/masked form header protection later produces on the wire.
    // WIDENED FROM private TO internal BY A4 TASK 4B, for the reason task 3b
    // widened A2CryptoFrameHex: TlsQuicPacketBuilderTests needs the same published
    // bytes to check a whole assembled packet against, and a second transcription of
    // a 1200-byte vector is the copy that goes wrong silently. Same assembly, so
    // internal is enough; QuicRfcVectors exists only for the cross-assembly case.
    internal const string A2AssociatedDataHex =
        "c300000001088394c8f03e5157080000449e00000002";

    // The CRYPTO frame the RFC prints explicitly (245 bytes), plus the payload
    // length and the plaintext builder that go with it.
    //
    // The transcription moved to SharpTls.Fuzzing.QuicRfcVectors in A2 task 7
    // and these three are now forwarders. Task 3b widened them from private to
    // internal because TlsQuicStreamFramesTests wanted the same 245 bytes and a
    // second transcription is the copy that goes wrong silently; task 7 wanted
    // them from tools/SharpTls.Fuzz too, where `internal` on a test class means
    // nothing because that is a different assembly. QuicRfcVectors is
    // source-linked into both, so there is still exactly one transcription -
    // see its header for why it may only ever expose bytes, never a type.
    //
    // Forwarders rather than call-site rewrites: the existing callers - this
    // class's own vectors and
    // TlsQuicStreamFramesTests.Rfc9001AppendixA2ClientInitialCryptoFrameParses
    // ToItsPublishedOffsetAndLength - are untouched, so nothing in committed
    // test code churns to move one transcription.
    internal const string A2CryptoFrameHex = QuicRfcVectors.A2CryptoFrameHex;

    internal const int A2PayloadLength = QuicRfcVectors.A2PayloadLength;

    // Full wire packet (protected header + AEAD output), extracted verbatim
    // from the RFC (mechanically, via a script over the reference-capture
    // file, not retyped). The AEAD ciphertext+tag is the tail of this array
    // starting at AssociatedData.Length: header protection only XORs the
    // header bytes (same length in/out) and never touches payload bytes, so
    // that tail is byte-for-byte the AEAD's raw output regardless of the
    // header's protection state either side of it.
    internal const string A2FullProtectedPacketHex =
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8ba" +
        "b936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a12" +
        "82a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6" +
        "005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" +
        "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde5" +
        "35d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e" +
        "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e3" +
        "0c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" +
        "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63" +
        "ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d874" +
        "3eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf8" +
        "2a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" +
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc29" +
        "62e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f0" +
        "5796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c" +
        "1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" +
        "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a" +
        "0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd" +
        "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de3" +
        "54270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" +
        "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a" +
        "4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e5" +
        "66d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef" +
        "023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" +
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbb" +
        "e2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd8" +
        "04a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc852" +
        "44259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" +
        "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5" +
        "e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";

    // RFC 9001 Appendix A.3: server Initial. AssociatedData is again the
    // unprotected header (byte0=0xc1, plaintext 2-byte packet number 1).
    internal const string A3AssociatedDataHex =
        "c1000000010008f067a5502a4262b50040750001";

    // Full 99-byte plaintext (ACK + CRYPTO frames, "no PADDING frames" per
    // the RFC text, so nothing to append here unlike A.2).
    internal const string A3PlaintextHex =
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566" +
        "dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684" +
        "d1081287c834d5311bcf32bb9da1a002b00020304";

    internal const string A3FullProtectedPacketHex =
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f3" +
        "7a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7d" +
        "deb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850ab" +
        "bdca3d20398c276456cbc42158407dd074ee";

    // RFC 9001 Appendix A.5: a ChaCha20-Poly1305 short-header packet, so the
    // test suite exercises both AEAD families end to end, not just AES-GCM.
    // packetNumber = 654360564 is ~2^29.3 - its big-endian encoding is
    // 00 00 00 00 27 00 bf f4, so this vector alone does NOT exercise nonce
    // bytes above the low 4; NonceIncorporatesPacketNumberBitsAboveTheLow32Bits
    // below covers that range explicitly.
    private const string ChaCha20KeyHex =
        "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8";
    private const string ChaCha20IvHex = "e0459b3474bdd0e44a41c144";
    private const ulong ChaCha20PacketNumber = 654360564;

    // Unprotected header IS the full associated data here: short header,
    // empty destination connection ID, so pn_offset = 1 and the header ends
    // at pn_offset + pn_length(3) = 4, consuming the whole thing.
    private const string A5AssociatedDataHex = "4200bff4";
    private const string A5PlaintextHex = "01";
    private const string A5FullProtectedPacketHex = "4cfe4189655e5cd55c41f69080575d7999c25a5bfb";

    [Fact]
    public void AppendixA2ClientInitialSealProducesPublishedCiphertext()
    {
        var key = Convert.FromHexString(ClientKeyHex);
        var iv = Convert.FromHexString(ClientIvHex);
        var associatedData = Convert.FromHexString(A2AssociatedDataHex);
        var plaintext = BuildA2Plaintext();
        var expectedCiphertext = Convert.FromHexString(A2FullProtectedPacketHex)[associatedData.Length..];

        var ciphertext = new byte[plaintext.Length + 16];
        TlsQuicPacketProtection.Seal(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber: 2, associatedData, plaintext, ciphertext);

        Assert.Equal(Convert.ToHexString(expectedCiphertext), Convert.ToHexString(ciphertext), ignoreCase: true);
    }

    [Fact]
    public void AppendixA2ClientInitialOpenRecoversPublishedPlaintext()
    {
        var key = Convert.FromHexString(ClientKeyHex);
        var iv = Convert.FromHexString(ClientIvHex);
        var associatedData = Convert.FromHexString(A2AssociatedDataHex);
        var ciphertext = Convert.FromHexString(A2FullProtectedPacketHex)[associatedData.Length..];
        var expectedPlaintext = BuildA2Plaintext();

        var plaintext = new byte[ciphertext.Length - 16];
        Assert.True(TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber: 2, associatedData, ciphertext, plaintext));

        Assert.Equal(Convert.ToHexString(expectedPlaintext), Convert.ToHexString(plaintext), ignoreCase: true);
    }

    [Fact]
    public void AppendixA3ServerInitialSealProducesPublishedCiphertext()
    {
        var key = Convert.FromHexString(ServerKeyHex);
        var iv = Convert.FromHexString(ServerIvHex);
        var associatedData = Convert.FromHexString(A3AssociatedDataHex);
        var plaintext = Convert.FromHexString(A3PlaintextHex);
        var expectedCiphertext = Convert.FromHexString(A3FullProtectedPacketHex)[associatedData.Length..];

        var ciphertext = new byte[plaintext.Length + 16];
        TlsQuicPacketProtection.Seal(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber: 1, associatedData, plaintext, ciphertext);

        Assert.Equal(Convert.ToHexString(expectedCiphertext), Convert.ToHexString(ciphertext), ignoreCase: true);
    }

    [Fact]
    public void AppendixA3ServerInitialOpenRecoversPublishedPlaintext()
    {
        var key = Convert.FromHexString(ServerKeyHex);
        var iv = Convert.FromHexString(ServerIvHex);
        var associatedData = Convert.FromHexString(A3AssociatedDataHex);
        var ciphertext = Convert.FromHexString(A3FullProtectedPacketHex)[associatedData.Length..];
        var expectedPlaintext = Convert.FromHexString(A3PlaintextHex);

        var plaintext = new byte[ciphertext.Length - 16];
        Assert.True(TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber: 1, associatedData, ciphertext, plaintext));

        Assert.Equal(Convert.ToHexString(expectedPlaintext), Convert.ToHexString(plaintext), ignoreCase: true);
    }

    [Fact]
    public void AppendixA5ChaCha20SealProducesPublishedCiphertext()
    {
        var key = Convert.FromHexString(ChaCha20KeyHex);
        var iv = Convert.FromHexString(ChaCha20IvHex);
        var associatedData = Convert.FromHexString(A5AssociatedDataHex);
        var plaintext = Convert.FromHexString(A5PlaintextHex);
        var expectedCiphertext = Convert.FromHexString(A5FullProtectedPacketHex)[associatedData.Length..];

        var ciphertext = new byte[plaintext.Length + 16];
        TlsQuicPacketProtection.Seal(
            TlsQuicPacketProtectionCipher.ChaCha20Poly1305, key, iv, ChaCha20PacketNumber, associatedData, plaintext, ciphertext);

        Assert.Equal(Convert.ToHexString(expectedCiphertext), Convert.ToHexString(ciphertext), ignoreCase: true);
    }

    [Fact]
    public void AppendixA5ChaCha20OpenRecoversPublishedPlaintext()
    {
        var key = Convert.FromHexString(ChaCha20KeyHex);
        var iv = Convert.FromHexString(ChaCha20IvHex);
        var associatedData = Convert.FromHexString(A5AssociatedDataHex);
        var ciphertext = Convert.FromHexString(A5FullProtectedPacketHex)[associatedData.Length..];
        var expectedPlaintext = Convert.FromHexString(A5PlaintextHex);

        var plaintext = new byte[ciphertext.Length - 16];
        Assert.True(TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.ChaCha20Poly1305, key, iv, ChaCha20PacketNumber, associatedData, ciphertext, plaintext));

        Assert.Equal(Convert.ToHexString(expectedPlaintext), Convert.ToHexString(plaintext), ignoreCase: true);
    }

    [Fact]
    public void TamperedCiphertextByteFailsAuthenticationWithoutThrowing()
    {
        var (key, iv, associatedData, plaintext) = BuildSyntheticInputs();
        var ciphertext = new byte[plaintext.Length + 16];
        TlsQuicPacketProtection.Seal(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber: 42, associatedData, plaintext, ciphertext);

        ciphertext[0] ^= 0x01; // Flip one ciphertext bit - anywhere in body or tag invalidates the tag.

        var recovered = new byte[plaintext.Length];
        var exception = Record.Exception(() => TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber: 42, associatedData, ciphertext, recovered));
        Assert.Null(exception);
        Assert.False(TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber: 42, associatedData, ciphertext, recovered));
    }

    // Proves associatedData actually reaches the AEAD: a bug that silently
    // passed an empty (or otherwise wrong) associated data span would make
    // Seal and Open agree with each other and this test would not catch it
    // by itself - it is the RFC vector tests above (A.2/A.3/A.5, which pin
    // an externally published ciphertext bound to the real header bytes)
    // that would fail in that scenario. This test's job is narrower: prove
    // TryOpen is sensitive to associatedData at all.
    [Fact]
    public void TamperedAssociatedDataByteFailsAuthenticationWithoutThrowing()
    {
        var (key, iv, associatedData, plaintext) = BuildSyntheticInputs();
        var ciphertext = new byte[plaintext.Length + 16];
        TlsQuicPacketProtection.Seal(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber: 42, associatedData, plaintext, ciphertext);

        var tamperedAssociatedData = (byte[])associatedData.Clone();
        tamperedAssociatedData[0] ^= 0x01;

        var recovered = new byte[plaintext.Length];
        var exception = Record.Exception(() => TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber: 42, tamperedAssociatedData, ciphertext, recovered));
        Assert.Null(exception);
        Assert.False(TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber: 42, tamperedAssociatedData, ciphertext, recovered));
    }

    // RFC 9001 s5.3: the nonce is IV XOR (packet number, left-padded with
    // zeros). A construction that ignores the packet number - or drops it
    // silently - would seal identical plaintext under identical key/IV to
    // identical ciphertext no matter what packetNumber is passed; sealing
    // the same plaintext across several packet numbers and requiring all
    // outputs to differ is otherwise invisible from Seal/Open agreeing with
    // themselves. Includes 0, 1, 2, and 2^62-1 (the largest 62-bit packet
    // number, occupying the nonce's full width per s5.3's "62 bits").
    [Fact]
    public void SealProducesDistinctCiphertextsAcrossPacketNumbers()
    {
        var (key, iv, associatedData, plaintext) = BuildSyntheticInputs();
        ulong[] packetNumbers = [0, 1, 2, 4_611_686_018_427_387_903UL];

        var ciphertexts = new HashSet<string>();
        foreach (var packetNumber in packetNumbers)
        {
            var ciphertext = new byte[plaintext.Length + 16];
            TlsQuicPacketProtection.Seal(
                TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber, associatedData, plaintext, ciphertext);
            Assert.True(ciphertexts.Add(Convert.ToHexString(ciphertext)));
        }
    }

    // RFC 9001 s5.3: pins an actual nonce value rather than just "differs
    // from other nonces" (SealProducesDistinctCiphertextsAcrossPacketNumbers
    // above already checks that, and would keep passing even if the packet
    // number were silently truncated to its low 32 bits before folding into
    // the nonce - none of the RFC vectors' packet numbers set any bit above
    // 2^32, so nothing here so far would notice that bug either).
    //
    // packetNumberA/B share identical low 32 bits (both end 0x00000000) and
    // differ only in byte 3 of their 8-byte big-endian encoding (0x01 vs
    // 0x02) - a byte strictly above the low 4 that a truncating bug would
    // drop. That byte lands at nonce[iv.Length - 8 + 3] = nonce[7] for a
    // 12-byte IV.
    //
    // ComputeExpectedNonce below reimplements the RFC's XOR independently of
    // TlsQuicPacketProtection (plain byte math, no shared code, so this test
    // cannot pass merely by calling the same buggy logic twice), and the
    // resulting nonce is fed to .NET's own AesGcm as an external oracle on
    // both sides: Seal's ciphertext must match sealing under that
    // independently-computed nonce directly, and TryOpen must be able to
    // recover the plaintext from ciphertext sealed under it. The open side
    // matters separately from the seal side: today both paths share one
    // ComputeNonce, so Seal-then-TryOpen round trips would stay
    // self-consistent even if that shared method were wrong - and would
    // stop proving anything at all if TryOpen ever inlined its own nonce
    // computation instead of sharing it.
    [Fact]
    public void NonceIncorporatesPacketNumberBitsAboveTheLow32Bits()
    {
        var key = new byte[16];
        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)((i * 5) + 2);
        }
        var iv = new byte[12];
        for (var i = 0; i < iv.Length; i++)
        {
            iv[i] = (byte)((i * 7) + 3);
        }
        var associatedData = new byte[] { 0x01, 0x02, 0x03 };
        var plaintext = new byte[] { 0xaa, 0xbb, 0xcc, 0xdd };

        const ulong packetNumberA = 0x00000001_00000000UL;
        const ulong packetNumberB = 0x00000002_00000000UL;

        var expectedNonceA = ComputeExpectedNonce(iv, packetNumberA);
        var expectedNonceB = ComputeExpectedNonce(iv, packetNumberB);

        Assert.NotEqual(expectedNonceA[7], expectedNonceB[7]);
        for (var i = 0; i < iv.Length; i++)
        {
            if (i == 7)
            {
                continue;
            }
            Assert.Equal(expectedNonceA[i], expectedNonceB[i]);
        }

        Assert.Equal(
            Convert.ToHexString(SealWithReferenceNonce(key, expectedNonceA, associatedData, plaintext)),
            Convert.ToHexString(SealWithProductionCode(key, iv, packetNumberA, associatedData, plaintext)));
        Assert.Equal(
            Convert.ToHexString(SealWithReferenceNonce(key, expectedNonceB, associatedData, plaintext)),
            Convert.ToHexString(SealWithProductionCode(key, iv, packetNumberB, associatedData, plaintext)));

        // Mirror on the open side: ciphertext sealed under the
        // independently computed nonce must be recoverable by production
        // TryOpen given the same packet number.
        Assert.True(OpenWithProductionCode(
            key, iv, packetNumberA, associatedData,
            SealWithReferenceNonce(key, expectedNonceA, associatedData, plaintext), out var recoveredA));
        Assert.Equal(Convert.ToHexString(plaintext), Convert.ToHexString(recoveredA), ignoreCase: true);

        Assert.True(OpenWithProductionCode(
            key, iv, packetNumberB, associatedData,
            SealWithReferenceNonce(key, expectedNonceB, associatedData, plaintext), out var recoveredB));
        Assert.Equal(Convert.ToHexString(plaintext), Convert.ToHexString(recoveredB), ignoreCase: true);
    }

    private static byte[] ComputeExpectedNonce(byte[] iv, ulong packetNumber)
    {
        var nonce = (byte[])iv.Clone();
        var packetNumberBytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(packetNumberBytes, packetNumber);
        var offset = nonce.Length - packetNumberBytes.Length;
        for (var i = 0; i < packetNumberBytes.Length; i++)
        {
            nonce[offset + i] ^= packetNumberBytes[i];
        }
        return nonce;
    }

    private static byte[] SealWithReferenceNonce(byte[] key, byte[] nonce, byte[] associatedData, byte[] plaintext)
    {
        var ciphertext = new byte[plaintext.Length + 16];
        using var aesGcm = new AesGcm(key, 16);
        aesGcm.Encrypt(
            nonce, plaintext, ciphertext.AsSpan(0, plaintext.Length), ciphertext.AsSpan(plaintext.Length), associatedData);
        return ciphertext;
    }

    private static byte[] SealWithProductionCode(
        byte[] key, byte[] iv, ulong packetNumber, byte[] associatedData, byte[] plaintext)
    {
        var ciphertext = new byte[plaintext.Length + 16];
        TlsQuicPacketProtection.Seal(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber, associatedData, plaintext, ciphertext);
        return ciphertext;
    }

    private static bool OpenWithProductionCode(
        byte[] key, byte[] iv, ulong packetNumber, byte[] associatedData, byte[] ciphertext, out byte[] plaintext)
    {
        plaintext = new byte[ciphertext.Length - 16];
        return TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.AesGcm, key, iv, packetNumber, associatedData, ciphertext, plaintext);
    }

    // [Theory]/[InlineData] can't carry TlsQuicPacketProtectionCipher directly -
    // xunit requires [Theory] methods to be public, and CS0051 then rejects an
    // internal enum parameter on a public method. Two [Fact] wrappers around
    // one private helper sidestep that without making the cipher enum public.
    [Fact]
    public void SealThenOpenRoundTripsAesGcm() => AssertSealThenOpenRoundTrips(TlsQuicPacketProtectionCipher.AesGcm);

    [Fact]
    public void SealThenOpenRoundTripsChaCha20Poly1305() =>
        AssertSealThenOpenRoundTrips(TlsQuicPacketProtectionCipher.ChaCha20Poly1305);

    private static void AssertSealThenOpenRoundTrips(TlsQuicPacketProtectionCipher cipher)
    {
        var keyLength = cipher == TlsQuicPacketProtectionCipher.AesGcm ? 16 : 32;
        var key = new byte[keyLength];
        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)((i * 29) + 3);
        }
        var iv = new byte[12];
        for (var i = 0; i < iv.Length; i++)
        {
            iv[i] = (byte)((i * 11) + 7);
        }
        var associatedData = new byte[] { 0x42, 0x00, 0xbf, 0xf4 };
        var plaintext = new byte[64];
        for (var i = 0; i < plaintext.Length; i++)
        {
            plaintext[i] = (byte)i;
        }

        var ciphertext = new byte[plaintext.Length + 16];
        TlsQuicPacketProtection.Seal(cipher, key, iv, packetNumber: 12345, associatedData, plaintext, ciphertext);

        var recovered = new byte[plaintext.Length];
        Assert.True(TlsQuicPacketProtection.TryOpen(cipher, key, iv, packetNumber: 12345, associatedData, ciphertext, recovered));
        Assert.Equal(Convert.ToHexString(plaintext), Convert.ToHexString(recovered), ignoreCase: true);
    }

    internal static byte[] BuildA2Plaintext() => QuicRfcVectors.BuildA2Plaintext();

    private static (byte[] Key, byte[] Iv, byte[] AssociatedData, byte[] Plaintext) BuildSyntheticInputs()
    {
        var key = new byte[16];
        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)((i * 17) + 5);
        }
        var iv = new byte[12];
        for (var i = 0; i < iv.Length; i++)
        {
            iv[i] = (byte)((i * 23) + 1);
        }
        var associatedData = new byte[] { 0xc3, 0x00, 0x00, 0x00, 0x01 };
        var plaintext = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        return (key, iv, associatedData, plaintext);
    }
}
