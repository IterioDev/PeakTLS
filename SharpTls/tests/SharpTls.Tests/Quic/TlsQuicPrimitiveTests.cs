using SharpTls.Quic;
using SharpTls.Protocol;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicPrimitiveTests
{
    [Theory]
    [InlineData(0UL, "00")]
    [InlineData(63UL, "3F")]
    [InlineData(64UL, "4040")]
    [InlineData(16383UL, "7FFF")]
    [InlineData(16384UL, "80004000")]
    [InlineData(1073741823UL, "BFFFFFFF")]
    [InlineData(1073741824UL, "C000000040000000")]
    [InlineData(4611686018427387903UL, "FFFFFFFFFFFFFFFF")]
    public void VariableLengthIntegerBoundariesAreCanonical(ulong value, string expectedHex)
    {
        var encoded = QuicVariableLengthInteger.Encode(value);
        var offset = 0;

        Assert.Equal(expectedHex, Convert.ToHexString(encoded));
        Assert.Equal(value, QuicVariableLengthInteger.Read(encoded, ref offset));
        Assert.Equal(encoded.Length, offset);

        // TryRead is Read's never-throwing twin (A4 task 2, handoff s8 item 5) and
        // must decode every accepting input identically to Read - including at
        // each of the four encoded widths this theory's eight rows already cover,
        // reused rather than duplicated in a second theory.
        var tryOffset = 0;
        Assert.True(QuicVariableLengthInteger.TryRead(encoded, ref tryOffset, out var tryValue));
        Assert.Equal(value, tryValue);
        Assert.Equal(encoded.Length, tryOffset);
    }

    // The standing rule for a varint reader: a witness per reachable path, not
    // just per flag - four encoded widths (above), the empty-buffer case, the
    // truncated-prefix case, and a declared width that overruns the bytes
    // remaining. All four are attacker-controlled by construction (TryRead's
    // production callers all read attacker-supplied packet and frame bytes), so
    // per the plan's provenance rule every one of them is reachable and needs a
    // witness.
    [Theory]
    [InlineData(new byte[] { }, 0)]
    [InlineData(new byte[] { 0x00 }, 1)]
    public void TryReadOnAnEmptyOrExhaustedBufferReturnsFalseAndLeavesOffsetUnchanged(byte[] source, int offset)
    {
        // The first bounds check inside TryRead, (uint)offset >= (uint)source.Length,
        // covers both a genuinely empty buffer (a zero-length datagram) and an
        // offset already at the end of a non-empty one (the state a caller's own
        // "call TryReadFrame until offset == payload.Length" loop reaches after
        // consuming every byte, per TlsQuicFrames' own comment).
        var walked = offset;
        Assert.False(QuicVariableLengthInteger.TryRead(source, ref walked, out var value));
        Assert.Equal(offset, walked);
        Assert.Equal(0UL, value);
    }

    [Theory]
    [InlineData(new byte[] { 0x40 })] // 2-byte form (RFC 9000 s16, 2MSB 01), second byte missing.
    [InlineData(new byte[] { 0x80, 0x00, 0x00 })] // 4-byte form (2MSB 10), one byte short.
    [InlineData(new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })] // 8-byte form (2MSB 11), one byte short.
    public void TryReadOnATruncatedMultiByteWidthPrefixReturnsFalseAndLeavesOffsetUnchanged(byte[] source)
    {
        // The second bounds check inside TryRead, source.Length - offset < length:
        // each row supplies the width-declaring first byte but one byte fewer than
        // RFC 9000 s16's Table 4 says that width needs, the same shape as a peer's
        // datagram simply ending mid-varint. The 1-byte form has no continuation
        // byte to truncate, so it is not a row here - VariableLengthIntegerBoundaries
        // AreCanonical's 0/63 rows are that width's only reachable shape.
        var offset = 0;
        Assert.False(QuicVariableLengthInteger.TryRead(source, ref offset, out var value));
        Assert.Equal(0, offset);
        Assert.Equal(0UL, value);
    }

    [Fact]
    public void TryReadWhoseDeclaredWidthOverrunsTheBytesRemainingAtANonzeroOffsetReturnsFalseAndLeavesOffsetUnchanged()
    {
        // Same bounds check as the truncated-prefix theory above, proven instead at
        // a nonzero starting offset inside a longer buffer - the shape every
        // production caller actually uses, walking a `ref offset` forward through
        // one shared payload (TlsQuicFrames.TryReadFrame and the rest). An
        // implementation that compared the declared width against source.Length
        // rather than against the bytes remaining after offset would pass the
        // truncated-prefix theory above (offset 0 there) and still be wrong here.
        byte[] source = [0x00, 0xC0, 0x01, 0x02, 0x03];
        var offset = 1;
        Assert.False(QuicVariableLengthInteger.TryRead(source, ref offset, out var value));
        Assert.Equal(1, offset);
        Assert.Equal(0UL, value);
    }

    [Fact]
    public void OrderedTransportParametersRoundTripAndPreserveUnknownIds()
    {
        var parameters = new TlsQuicTransportParameters(
        [
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.MaxUdpPayloadSize,
                65_527),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxData,
                1_000_000),
            new TlsQuicTransportParameter(0x173E, [1, 2, 3]),
            TlsQuicTransportParameter.Empty(
                TlsQuicTransportParameterId.DisableActiveMigration),
        ]);

        var encoded = parameters.Encode();
        var parsed = TlsQuicTransportParameters.Parse(encoded);
        parsed.ValidatePeer(TlsQuicEndpointRole.Client);

        Assert.Equal(encoded, parsed.Encode());
        Assert.Equal([1, 2, 3], parsed.Get(0x173E)!.Value);
        Assert.Equal(
            1_000_000UL,
            parsed.Get((ulong)TlsQuicTransportParameterId.InitialMaxData)!
                .GetVariableInteger());
        var defensive = parsed.Get(0x173E)!.Value;
        defensive[0] = 9;
        Assert.Equal([1, 2, 3], parsed.Get(0x173E)!.Value);
    }

    [Fact]
    public void DuplicateTruncatedAndInvalidPeerParametersFailClosed()
    {
        Assert.Equal(
            TlsQuicTransportError.TransportParameterError,
            Assert.Throws<TlsQuicTransportException>(() =>
                TlsQuicTransportParameters.Parse([0x01, 0x01, 0x00, 0x01, 0x00]))
                .Error);
        Assert.Equal(
            TlsQuicTransportError.TransportParameterError,
            Assert.Throws<TlsQuicTransportException>(() =>
                TlsQuicTransportParameters.Parse([0x40])).Error);

        var clientWithServerOnlyParameter = new TlsQuicTransportParameters(
        [
            new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.StatelessResetToken,
                new byte[16]),
        ]);
        Assert.Equal(
            TlsQuicTransportError.TransportParameterError,
            Assert.Throws<TlsQuicTransportException>(() =>
                clientWithServerOnlyParameter.ValidatePeer(TlsQuicEndpointRole.Client)).Error);

        var invalidUdp = new TlsQuicTransportParameters(
        [
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.MaxUdpPayloadSize,
                1199),
        ]);
        Assert.Throws<TlsQuicTransportException>(() =>
            invalidUdp.ValidatePeer(TlsQuicEndpointRole.Server));

        var invalidVersionInfo = new TlsQuicTransportParameters(
        [
            new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.VersionInformation,
                [0, 0, 0, 2, 0, 0, 0, 1]),
        ]);
        Assert.Throws<TlsQuicTransportException>(() =>
            invalidVersionInfo.ValidatePeer(TlsQuicEndpointRole.Server));
    }

    [Fact]
    public void CryptoStreamReassemblesGapsRetransmissionsAndRejectsConflicts()
    {
        var stream = new TlsQuicCryptoStreamReassembler(4096);

        Assert.Empty(stream.Add(5, "world"u8));
        Assert.Equal("helloworld"u8.ToArray(), stream.Add(0, "hello"u8));
        Assert.Empty(stream.Add(0, "helloworld"u8));
        Assert.Equal(10, stream.DeliveredLength);
        Assert.Equal(
            TlsQuicTransportError.ProtocolViolation,
            Assert.Throws<TlsQuicTransportException>(() =>
                stream.Add(3, "X"u8)).Error);

        stream.Discard();
        Assert.Empty(stream.Add(0, "hello"u8));
        Assert.Equal(
            TlsQuicTransportError.ProtocolViolation,
            Assert.Throws<TlsQuicTransportException>(() =>
                stream.Add(10, "!"u8)).Error);
    }

    [Fact]
    public void CryptoStreamEnforcesBufferLimitAndCannotDiscardAGap()
    {
        var stream = new TlsQuicCryptoStreamReassembler(1024);
        Assert.Empty(stream.Add(100, [1]));
        Assert.Equal(
            TlsQuicTransportError.ProtocolViolation,
            Assert.Throws<TlsQuicTransportException>(stream.Discard).Error);
        Assert.Equal(
            TlsQuicTransportError.CryptoBufferExceeded,
            Assert.Throws<TlsQuicTransportException>(() =>
                stream.Add(1024, [1])).Error);
    }

    [Fact]
    public void Rfc9001InitialSecretsAndKeysMatchAppendixA()
    {
        var connectionId = Convert.FromHexString("8394C8F03E515708");
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1,
            connectionId);
        using var clientKeys = secrets.DeriveClientPacketProtectionKeys(
            TlsQuicVersion.Version1);
        using var serverKeys = secrets.DeriveServerPacketProtectionKeys(
            TlsQuicVersion.Version1);

        Assert.Equal(
            "C00CF151CA5BE075ED0EBFB5C80323C42D6B7DB67881289AF4008F1F6C357AEA",
            Convert.ToHexString(secrets.CopyClientSecret()));
        Assert.Equal(
            "3C199828FD139EFD216C155AD844CC81FB82FA8D7446FA7D78BE803ACDDA951B",
            Convert.ToHexString(secrets.CopyServerSecret()));
        AssertKeys(
            clientKeys,
            "1F369613DD76D5467730EFCBE3B1A22D",
            "FA044B2F42A3FD3B46FB255C",
            "9F50449E04A0E810283A1E9933ADEDD2");
        AssertKeys(
            serverKeys,
            "CF3A5331653C364C88F0F379B6067E37",
            "0AC1493CA1905853B0BBA03E",
            "C206B8D9B9F0F37644430B490EEAA314");
    }

    [Fact]
    public void Rfc9369InitialSecretsAndKeysMatchAppendixA()
    {
        var connectionId = Convert.FromHexString("8394C8F03E515708");
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version2,
            connectionId);
        using var clientKeys = secrets.DeriveClientPacketProtectionKeys(
            TlsQuicVersion.Version2);
        using var serverKeys = secrets.DeriveServerPacketProtectionKeys(
            TlsQuicVersion.Version2);

        Assert.Equal(
            "14EC9D6EB9FD7AF83BF5A668BC17A7E283766AADE7ECD0891F70F9FF7F4BF47B",
            Convert.ToHexString(secrets.CopyClientSecret()));
        Assert.Equal(
            "0263DB1782731BF4588E7E4D93B7463907CB8CD8200B5DA55A8BD488EAFC37C1",
            Convert.ToHexString(secrets.CopyServerSecret()));
        AssertKeys(
            clientKeys,
            "8B1A0BC121284290A29E0971B5CD045D",
            "91F73E2351D8FA91660E909F",
            "45B95E15235D6F45A6B19CB CB0294BA9".Replace(" ", string.Empty));
        AssertKeys(
            serverKeys,
            "82DB637861D55E1D011F19EA71D5D2A7",
            "DD13C276499C0249D3310652",
            "EDF6D05C83121201B436E16877593C3A");
    }

    [Fact]
    public void TlsTrafficSecretUsesVersionSpecificKeySeparationLabels()
    {
        using var secret = new TlsQuicTrafficSecret(
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicSecretDirection.Write,
            TlsCipherSuite.TlsAes128GcmSha256,
            Enumerable.Range(0, 32).Select(value => (byte)value).ToArray());
        using var v1 = secret.DerivePacketProtectionKeys(TlsQuicVersion.Version1);
        using var v2 = secret.DerivePacketProtectionKeys(TlsQuicVersion.Version2);

        Assert.False(v1.CopyKey().AsSpan().SequenceEqual(v2.CopyKey()));
        Assert.False(v1.CopyIv().AsSpan().SequenceEqual(v2.CopyIv()));
        Assert.False(v1.CopyHeaderProtectionKey().AsSpan().SequenceEqual(
            v2.CopyHeaderProtectionKey()));
        Assert.Equal(TlsQuicEncryptionLevel.Handshake, secret.Level);
        Assert.Equal(TlsQuicSecretDirection.Write, secret.Direction);

        secret.Dispose();
        Assert.Throws<ObjectDisposedException>(secret.CopySecret);
    }


    // RFC 9000 s16, Table 4's four rows, encoding one value at every width that can
    // hold it. 64 needs two bytes minimally, so the 1-byte row is the rejection test
    // below rather than a row here. The expected bytes are Table 4's "2MSB" prefix
    // over a big-endian value, written out by hand: 0x40|0x00,0x40 for two bytes,
    // 0x80 over three zero bytes then 0x40 for four, 0xC0 over seven then 0x40 for
    // eight - the value itself is unchanged, only its width.
    [Theory]
    // The int rows are TlsQuicVarintWidth's own member values - 0 Minimal, then the
    // byte counts 2, 4 and 8 - passed as int because xunit needs public signatures and
    // that enum is internal like everything else in this namespace.
    [InlineData(0, "4040")]
    [InlineData(2, "4040")]
    [InlineData(4, "80000040")]
    [InlineData(8, "C000000000000040")]
    public void WidenedEncodingUsesTheRequestedWidth(int width, string expected)
    {
        var length = QuicVariableLengthInteger.GetEncodedLength(64UL, (TlsQuicVarintWidth)width);
        var encoded = QuicVariableLengthInteger.Encode(64UL, length);

        Assert.Equal(expected, Convert.ToHexString(encoded));

        // s16 makes the wider forms legal, not merely different, so the decoder that
        // has always existed must read them all back as the same value.
        var offset = 0;
        Assert.Equal(64UL, QuicVariableLengthInteger.Read(encoded, ref offset));
        Assert.Equal(encoded.Length, offset);
    }

    // A width narrower than the value needs is a silent truncation if it is honoured,
    // so it is a caller error. 64 does not fit RFC 9000 s16 Table 4's 1-byte row,
    // whose range stops at 63.
    [Fact]
    public void AWidthTooNarrowForTheValueIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicVariableLengthInteger.GetEncodedLength(64UL, TlsQuicVarintWidth.OneByte));

        Assert.Equal("width", error.ParamName);
    }

    // RFC 9000 s20.1's code points, as data, transcribed from
    // docs/superpowers/specs/reference-captures/rfc9000-section20-transport-error-codes.txt:
    //   "NO_ERROR (0x00)", "FLOW_CONTROL_ERROR (0x03)", "STREAM_LIMIT_ERROR (0x04)",
    //   "STREAM_STATE_ERROR (0x05)", "FINAL_SIZE_ERROR (0x06)",
    //   "FRAME_ENCODING_ERROR (0x07)",
    //   "TRANSPORT_PARAMETER_ERROR (0x08)", "PROTOCOL_VIOLATION (0x0a)",
    //   "CRYPTO_BUFFER_EXCEEDED (0x0d)", "KEY_UPDATE_ERROR (0x0e)".
    //
    // TlsQuicTransportError is a WIRE enum - declared ": ulong", and task 9b writes
    // (ulong)CloseError straight into a CONNECTION_CLOSE frame's Error Code field - so
    // every one of these numbers reaches the peer. The public API baseline pins the
    // SYMBOL and never the number ("F: public const SharpTls.Quic.TlsQuicTransportError
    // KeyUpdateError = SharpTls.Quic.TlsQuicTransportError.KeyUpdateError"), and no
    // other test reads a member as a number, so without this every code point could be
    // wrong with the whole suite green. Pinned as a set, not one special case, because
    // the gap was the enum's and not one member's.
    [Theory]
    [InlineData(TlsQuicTransportError.NoError, 0x00UL)]
    [InlineData(TlsQuicTransportError.FlowControlError, 0x03UL)]
    [InlineData(TlsQuicTransportError.StreamLimitError, 0x04UL)]
    [InlineData(TlsQuicTransportError.StreamStateError, 0x05UL)]
    [InlineData(TlsQuicTransportError.FinalSizeError, 0x06UL)]
    [InlineData(TlsQuicTransportError.FrameEncodingError, 0x07UL)]
    [InlineData(TlsQuicTransportError.TransportParameterError, 0x08UL)]
    [InlineData(TlsQuicTransportError.ProtocolViolation, 0x0AUL)]
    [InlineData(TlsQuicTransportError.ApplicationError, 0x0CUL)]
    [InlineData(TlsQuicTransportError.CryptoBufferExceeded, 0x0DUL)]
    [InlineData(TlsQuicTransportError.KeyUpdateError, 0x0EUL)]
    [InlineData(TlsQuicTransportError.AeadLimitReached, 0x0FUL)]
    public void EveryTransportErrorCarriesItsSection201CodePoint(TlsQuicTransportError error, ulong code) =>
        Assert.Equal(code, (ulong)error);

    [Fact]
    public void TheTransportErrorCodePointsAreExactlyTheTwelvePinnedAbove() =>
        // The count is not asserted as a number: it is the list, so a member added
        // without a row above fails here rather than passing unnoticed. Sorted because
        // the enum's declaration order is not its numeric order.
        //
        // APPLICATION_ERROR (0x0c) IS TASK 14d's, AND THIS TEST IS WHY IT IS TRANSCRIBED
        // RATHER THAN REMEMBERED. The extract reads "APPLICATION_ERROR (0x0c):  The
        // application or application protocol caused the connection to be closed." - the
        // seventh member, and the guard did its job: adding it turned this red before any
        // 14d test existed.
        //
        // AND IT DID IT AGAIN FOR TASK 14e's FOUR, which is worth recording because the four
        // are consecutive and the transcription that would go wrong is an off-by-one across
        // the run. Each is quoted at its declaration in TlsQuicProtocol.cs, and the extract
        // reads them in this order: "FLOW_CONTROL_ERROR (0x03)", "STREAM_LIMIT_ERROR (0x04)",
        // "STREAM_STATE_ERROR (0x05)", "FINAL_SIZE_ERROR (0x06)" - immediately before
        // FRAME_ENCODING_ERROR (0x07), which was already here and is the anchor that makes a
        // shifted run visible.
        //
        // AND AGAIN FOR AEAD_LIMIT_REACHED (0x0f), which RFC 9001 s6.6 names twice - once for
        // the integrity limit and once for a confidentiality limit reached with no key update
        // available - and which s20.1 puts immediately after KEY_UPDATE_ERROR. The two are
        // adjacent AND related, which is exactly the pair a transcription is most likely to
        // collapse onto one number.
        Assert.Equal(
            new ulong[] { 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F },
            Enum.GetValues<TlsQuicTransportError>().Select(e => (ulong)e).Order());

    private static void AssertKeys(
        TlsQuicPacketProtectionKeys keys,
        string key,
        string iv,
        string headerProtectionKey)
    {
        Assert.Equal(key, Convert.ToHexString(keys.CopyKey()));
        Assert.Equal(iv, Convert.ToHexString(keys.CopyIv()));
        Assert.Equal(
            headerProtectionKey,
            Convert.ToHexString(keys.CopyHeaderProtectionKey()));
    }
}
