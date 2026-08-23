using System.Security.Cryptography;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicHeaderProtectionTests
{
    // RFC 9001 Appendix A.1: client Initial header protection key.
    private const string ClientHpKeyHex = "9f50449e04a0e810283a1e9933adedd2";

    // RFC 9001 Appendix A.2: client Initial header, unprotected and
    // protected forms, plus the 16-byte ciphertext sample used to derive
    // the mask between them. header[18..22) is the packet number field
    // (pnOffset = 18), and the sample starts immediately after the header
    // at pnOffset + 4 = 22, which is also where these 22-byte headers end -
    // so header + sample below reproduces the real packet layout with the
    // minimum bytes needed to exercise it.
    private const string AppendixA2UnprotectedHeaderHex =
        "c300000001088394c8f03e5157080000449e00000002";
    private const string AppendixA2ProtectedHeaderHex =
        "c000000001088394c8f03e5157080000449e7b9aec34";
    private const string AppendixA2SampleHex =
        "d1b1c98dd7689fb8ec11d242b123dc9b";

    // RFC 9001 Appendix A.5: header protection key and full 21-byte packet
    // (short header, empty DCID, so pnOffset = 1) for a ChaCha20-Poly1305
    // packet, unprotected and protected. Unlike A.2, the full packet is
    // used directly rather than header+sample, because A.5's sample is not
    // a clean 16-byte suffix of just the header region - it is the last 16
    // of the packet's 21 bytes, verified to equal RFC 9001's own published
    // "sample = 5e5cd55c..." value before this file was written.
    private const string ChaCha20HpKeyHex =
        "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4";
    private const string AppendixA5UnprotectedPacketHex =
        "4200bff4655e5cd55c41f69080575d7999c25a5bfb";
    private const string AppendixA5ProtectedPacketHex =
        "4cfe4189655e5cd55c41f69080575d7999c25a5bfb";

    [Fact]
    public void AppendixA2RemovesProtection()
    {
        var packet = BuildPacket(AppendixA2ProtectedHeaderHex, AppendixA2SampleHex);
        var hpKey = Convert.FromHexString(ClientHpKeyHex);

        Assert.True(TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset: 18, out var pnLength));

        Assert.Equal(4, pnLength);
        Assert.Equal(AppendixA2UnprotectedHeaderHex, Convert.ToHexString(packet[..22]), ignoreCase: true);
    }

    [Fact]
    public void AppendixA2AppliesProtection()
    {
        var packet = BuildPacket(AppendixA2UnprotectedHeaderHex, AppendixA2SampleHex);
        var hpKey = Convert.FromHexString(ClientHpKeyHex);

        Assert.True(TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset: 18));

        Assert.Equal(AppendixA2ProtectedHeaderHex, Convert.ToHexString(packet[..22]), ignoreCase: true);
    }

    // THE trap (RFC 9001 s5.4.1): removing protection must read pn_length
    // from byte 0 AFTER unmasking it, not before. The A.5 packet is the
    // RFC's own demonstration of why: its protected byte 0 is 0x4c, and
    // 0x4c & 0x03 = 0 implies a 1-byte packet number - but the real,
    // unmasked byte 0 is 0x42, giving 0x42 & 0x03 = 2, i.e. a 3-byte packet
    // number. An implementation that reads pn_length before unmasking would
    // compute pnLength = 1 here, unmask only 1 of the 3 protected packet
    // number bytes, and return the wrong value below - this test pins both.
    //
    // Mutation check performed manually: temporarily reordering
    // TlsQuicHeaderProtection.TryRemove to read pn_length before the
    // `packet[0] ^= ...` unmasking line makes this test fail (pnLength
    // comes back as 1, not 3, and the recovered header does not match
    // AppendixA5UnprotectedPacketHex). Reverted after confirming the failure.
    [Fact]
    public void RemovalReadsPacketNumberLengthAfterUnmaskingByte0NotBefore()
    {
        var packet = Convert.FromHexString(AppendixA5ProtectedPacketHex);
        var hpKey = Convert.FromHexString(ChaCha20HpKeyHex);

        Assert.True(TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.ChaCha20, hpKey, packet, packetNumberOffset: 1, out var pnLength));

        Assert.Equal(3, pnLength);
        Assert.Equal(AppendixA5UnprotectedPacketHex, Convert.ToHexString(packet), ignoreCase: true);
    }

    [Fact]
    public void AppendixA5AppliesProtection()
    {
        var packet = Convert.FromHexString(AppendixA5UnprotectedPacketHex);
        var hpKey = Convert.FromHexString(ChaCha20HpKeyHex);

        Assert.True(TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.ChaCha20, hpKey, packet, packetNumberOffset: 1));

        Assert.Equal(AppendixA5ProtectedPacketHex, Convert.ToHexString(packet), ignoreCase: true);
    }

    // RFC 9001 s5.4.1: long header masks the low 4 bits of byte 0 (0x0f),
    // short header masks the low 5 (0x1f). A real AES-ECB mask is computed
    // independently of the class under test (its own Aes call, not a
    // hardcoded constant), searching for a sample whose mask byte 0 has bit
    // 0x10 set - only then can the two mask widths provably disagree. If
    // the implementation had the two masks swapped, the "long header"
    // result below would come back with bit 0x10 flipped too, failing the
    // final assertions.
    [Fact]
    public void LongHeaderMasksLowFourBitsShortHeaderMasksLowFiveBits()
    {
        var hpKey = new byte[16];
        for (var i = 0; i < hpKey.Length; i++)
        {
            hpKey[i] = (byte)((i * 13) + 7);
        }

        byte[]? sample = null;
        byte mask0 = 0;
        for (var candidate = 0; candidate < 256; candidate++)
        {
            var candidateSample = new byte[16];
            candidateSample[0] = (byte)candidate;
            for (var i = 1; i < candidateSample.Length; i++)
            {
                candidateSample[i] = (byte)((i * 3) + 1);
            }

            using var aes = Aes.Create();
            aes.Key = hpKey;
            var block = aes.EncryptEcb(candidateSample, PaddingMode.None);
            if ((block[0] & 0x10) != 0)
            {
                sample = candidateSample;
                mask0 = block[0];
                break;
            }
        }

        Assert.NotNull(sample); // Premise of the test: AES-ECB must exhibit bit 0x10 for some sample here.

        // packetNumberOffset = 1, and the sample always starts at
        // packetNumberOffset + 4 = 5 (RFC 9001 s5.4.2) regardless of the
        // 1-byte packet number this minimal packet actually carries.
        const int packetNumberOffset = 1;
        const int sampleOffset = packetNumberOffset + 4;

        var longPacket = new byte[sampleOffset + 16];
        longPacket[0] = 0x80; // Header Form bit set: long header.
        sample.CopyTo(longPacket, sampleOffset);
        Assert.True(TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, longPacket, packetNumberOffset));

        var shortPacket = new byte[sampleOffset + 16];
        shortPacket[0] = 0x00; // Header Form bit clear: short header.
        sample.CopyTo(shortPacket, sampleOffset);
        Assert.True(TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, shortPacket, packetNumberOffset));

        Assert.Equal((byte)(0x80 ^ (mask0 & 0x0f)), longPacket[0]);
        Assert.Equal((byte)(mask0 & 0x1f), shortPacket[0]);
        Assert.Equal(0, longPacket[0] & 0x10); // Long header: bit 0x10 never touched.
        Assert.NotEqual(0, shortPacket[0] & 0x10); // Short header: bit 0x10 was masked.
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void RoundTripsApplyThenRemoveForEachPacketNumberLength(int packetNumberLength)
    {
        var hpKey = new byte[16];
        for (var i = 0; i < hpKey.Length; i++)
        {
            hpKey[i] = (byte)((i * 19) + 3);
        }

        const int packetNumberOffset = 5;
        var original = new byte[packetNumberOffset + 4 + 16]; // header prefix + max pn + sample region.
        original[0] = (byte)(0x80 | (packetNumberLength - 1)); // long header, low 2 bits encode pn length.
        for (var i = 1; i < original.Length; i++)
        {
            original[i] = (byte)((i * 7) + 11);
        }

        var packet = (byte[])original.Clone();
        Assert.True(TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset));
        Assert.NotEqual(Convert.ToHexString(original), Convert.ToHexString(packet)); // sanity: protection actually changed something.

        Assert.True(TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset, out var recoveredLength));

        Assert.Equal(packetNumberLength, recoveredLength);
        Assert.Equal(Convert.ToHexString(original), Convert.ToHexString(packet));
    }

    // RFC 9001 s5.4.3: AEAD_AES_256_GCM uses AES-256, selected implicitly by
    // System.Security.Cryptography.Aes from a 32-byte key - every other AES
    // test here uses a 16-byte key, so this is the only coverage of that
    // path. Round-trips like RoundTripsApplyThenRemoveForEachPacketNumberLength,
    // then additionally checks the masked bytes actually differ from a
    // 16-byte-key run on the same original packet - without that check, a
    // bug that silently ignored key length (e.g. always running AES-128 off
    // the first 16 bytes) would still pass the round trip.
    [Fact]
    public void RoundTripsWithAes256KeyAndProducesADifferentMaskThanAes128()
    {
        const int packetNumberOffset = 5;
        var original = new byte[packetNumberOffset + 4 + 16];
        original[0] = 0x80 | 3; // long header, pn length 4
        for (var i = 1; i < original.Length; i++)
        {
            original[i] = (byte)((i * 7) + 11);
        }

        var hpKey128 = new byte[16];
        for (var i = 0; i < hpKey128.Length; i++)
        {
            hpKey128[i] = (byte)((i * 19) + 3);
        }

        var hpKey256 = new byte[32];
        for (var i = 0; i < hpKey256.Length; i++)
        {
            hpKey256[i] = (byte)((i * 29) + 5);
        }

        var roundTrip = (byte[])original.Clone();
        Assert.True(TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes, hpKey256, roundTrip, packetNumberOffset));
        Assert.NotEqual(Convert.ToHexString(original), Convert.ToHexString(roundTrip));
        Assert.True(TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes, hpKey256, roundTrip, packetNumberOffset, out var recoveredLength));
        Assert.Equal(4, recoveredLength);
        Assert.Equal(Convert.ToHexString(original), Convert.ToHexString(roundTrip));

        var protected128 = (byte[])original.Clone();
        Assert.True(TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes, hpKey128, protected128, packetNumberOffset));
        var protected256 = (byte[])original.Clone();
        Assert.True(TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes, hpKey256, protected256, packetNumberOffset));

        Assert.NotEqual(Convert.ToHexString(protected128), Convert.ToHexString(protected256));
    }

    [Fact]
    public void SampleThatWouldRunPastPacketEndIsRejectedWithoutThrowing()
    {
        var hpKey = new byte[16];
        var packet = new byte[10]; // packetNumberOffset(1) + 4 + 16 sample bytes needs 21; only 10 available.
        packet[0] = 0x80;

        var applyException = Record.Exception(() => TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset: 1));
        Assert.Null(applyException);
        Assert.False(TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset: 1));

        var removeException = Record.Exception(() => TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset: 1, out _));
        Assert.Null(removeException);
        Assert.False(TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset: 1, out var pnLength));
        Assert.Equal(0, pnLength);
    }

    // packetNumberOffset near int.MaxValue: sampleOffset = offset + 4 does
    // not overflow, but the old guard's `sampleOffset + SampleLength >
    // packet.Length` did - wrapping to a large negative number, passing the
    // bounds check, and letting the subsequent Slice throw. Guarding via
    // subtraction from the (always-bounded) packet.Length instead cannot
    // overflow, so this must return false, never throw.
    [Fact]
    public void OffsetNearIntMaxDoesNotOverflowTheSampleBoundsGuard()
    {
        var hpKey = new byte[16];
        var packet = new byte[32];
        const int packetNumberOffset = int.MaxValue - 10;

        var applyException = Record.Exception(() => TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset));
        Assert.Null(applyException);
        Assert.False(TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset));

        var removeException = Record.Exception(() => TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset, out _));
        Assert.Null(removeException);
        Assert.False(TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes, hpKey, packet, packetNumberOffset, out var pnLength));
        Assert.Equal(0, pnLength);
    }

    private static byte[] BuildPacket(string headerHex, string sampleHex)
    {
        var header = Convert.FromHexString(headerHex);
        var sample = Convert.FromHexString(sampleHex);
        var packet = new byte[header.Length + sample.Length];
        header.CopyTo(packet, 0);
        sample.CopyTo(packet, header.Length);
        return packet;
    }
}
