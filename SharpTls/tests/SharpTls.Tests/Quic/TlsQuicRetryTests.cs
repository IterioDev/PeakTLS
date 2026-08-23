using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicRetryTests
{
    // RFC 9001 Appendix A.2: the client's original chosen Destination
    // Connection ID - the ODCID this Retry's tag is computed against.
    private const string OriginalDestinationConnectionIdHex = "8394c8f03e515708";

    // RFC 9001 Appendix A.4: the full wire Retry packet (header through
    // tag), extracted verbatim - not retyped by hand. The pseudo-packet's
    // tail and the published tag are sliced from this in code below,
    // mirroring TlsQuicPacketProtectionTests' house style (see
    // A2FullProtectedPacketHex there), so there is exactly one
    // hand-transcribed copy of this vector.
    private const string A4FullRetryPacketHex =
        "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";

    [Fact]
    public void AppendixA4ComputeTagProducesPublishedTag()
    {
        var odcid = Convert.FromHexString(OriginalDestinationConnectionIdHex);
        var fullPacket = Convert.FromHexString(A4FullRetryPacketHex);
        var retryPacketWithoutTag = fullPacket[..^16];
        var expectedTag = fullPacket[^16..];

        var tag = new byte[16];
        TlsQuicRetry.ComputeTag(TlsQuicVersion.Version1, odcid, retryPacketWithoutTag, tag);

        Assert.Equal(Convert.ToHexString(expectedTag), Convert.ToHexString(tag), ignoreCase: true);
    }

    [Fact]
    public void AppendixA4PublishedRetryPacketVerifiesSuccessfully()
    {
        var odcid = Convert.FromHexString(OriginalDestinationConnectionIdHex);
        var fullPacket = Convert.FromHexString(A4FullRetryPacketHex);
        var retryPacketWithoutTag = fullPacket[..^16];
        var tag = fullPacket[^16..];

        Assert.True(TlsQuicRetry.TryVerify(TlsQuicVersion.Version1, odcid, retryPacketWithoutTag, tag));
    }

    [Fact]
    public void FlippedBitInOriginalDestinationConnectionIdFailsVerification()
    {
        var odcid = Convert.FromHexString(OriginalDestinationConnectionIdHex);
        var fullPacket = Convert.FromHexString(A4FullRetryPacketHex);
        var retryPacketWithoutTag = fullPacket[..^16];
        var tag = fullPacket[^16..];

        odcid[0] ^= 0x01;

        var exception = Record.Exception(() =>
            TlsQuicRetry.TryVerify(TlsQuicVersion.Version1, odcid, retryPacketWithoutTag, tag));
        Assert.Null(exception);
        Assert.False(TlsQuicRetry.TryVerify(TlsQuicVersion.Version1, odcid, retryPacketWithoutTag, tag));
    }

    [Fact]
    public void FlippedBitInRetryTokenFailsVerification()
    {
        var odcid = Convert.FromHexString(OriginalDestinationConnectionIdHex);
        var fullPacket = Convert.FromHexString(A4FullRetryPacketHex);
        var retryPacketWithoutTag = fullPacket[..^16];
        var tag = fullPacket[^16..];

        // retryPacketWithoutTag is 20 bytes: a 15-byte header (byte0=1,
        // version=4, DCID len+DCID(0)=1, SCID len+SCID(8)=9) followed by the
        // 5-byte Retry Token, which RFC 9001 A.4 states is the ASCII "token"
        // - so the last byte is inside the token, not the header.
        retryPacketWithoutTag[^1] ^= 0x01;

        var exception = Record.Exception(() =>
            TlsQuicRetry.TryVerify(TlsQuicVersion.Version1, odcid, retryPacketWithoutTag, tag));
        Assert.Null(exception);
        Assert.False(TlsQuicRetry.TryVerify(TlsQuicVersion.Version1, odcid, retryPacketWithoutTag, tag));
    }

    [Fact]
    public void FlippedBitInTagFailsVerification()
    {
        var odcid = Convert.FromHexString(OriginalDestinationConnectionIdHex);
        var fullPacket = Convert.FromHexString(A4FullRetryPacketHex);
        var retryPacketWithoutTag = fullPacket[..^16];
        var tag = fullPacket[^16..];

        tag[0] ^= 0x01;

        var exception = Record.Exception(() =>
            TlsQuicRetry.TryVerify(TlsQuicVersion.Version1, odcid, retryPacketWithoutTag, tag));
        Assert.Null(exception);
        Assert.False(TlsQuicRetry.TryVerify(TlsQuicVersion.Version1, odcid, retryPacketWithoutTag, tag));
    }

    // RFC 9001 s5.8: "only an entity that observes an Initial packet can
    // send a valid Retry packet" - the ODCID is exactly what encodes that
    // property, so a wrong-but-plausible ODCID (as opposed to a corrupted
    // byte within the right one) gets its own test rather than being folded
    // into the bit-flip cases above.
    //
    // Deliberately self-consistent (ComputeTag then TryVerify against the
    // *same* retryPacketWithoutTag, not the published tag): a version that
    // silently dropped the ODCID from the pseudo-packet would make
    // ComputeTag ignore correctOdcid, so comparing against the fixed A.4 tag
    // would fail for both a correct and a wrong ODCID alike and this test
    // would not distinguish the two. Round-tripping through this class's own
    // ComputeTag first is what makes the wrong-ODCID case fail *only* when
    // the ODCID genuinely participates in the tag.
    [Fact]
    public void WrongOriginalDestinationConnectionIdFailsVerification()
    {
        var correctOdcid = Convert.FromHexString(OriginalDestinationConnectionIdHex);
        var wrongOdcid = Convert.FromHexString("0011223344556677");
        var fullPacket = Convert.FromHexString(A4FullRetryPacketHex);
        var retryPacketWithoutTag = fullPacket[..^16];

        var tag = new byte[16];
        TlsQuicRetry.ComputeTag(TlsQuicVersion.Version1, correctOdcid, retryPacketWithoutTag, tag);

        Assert.False(TlsQuicRetry.TryVerify(TlsQuicVersion.Version1, wrongOdcid, retryPacketWithoutTag, tag));
    }

    [Fact]
    public void TruncatedRetryPacketIsRejectedWithoutThrowing()
    {
        var odcid = Convert.FromHexString(OriginalDestinationConnectionIdHex);
        var fullPacket = Convert.FromHexString(A4FullRetryPacketHex);
        var retryPacketWithoutTag = fullPacket[..^16];
        var truncatedTag = fullPacket[^16..][..10]; // as if the datagram were cut mid-tag.

        var exception = Record.Exception(() =>
            TlsQuicRetry.TryVerify(TlsQuicVersion.Version1, odcid, retryPacketWithoutTag, truncatedTag));
        Assert.Null(exception);
        Assert.False(TlsQuicRetry.TryVerify(TlsQuicVersion.Version1, odcid, retryPacketWithoutTag, truncatedTag));
    }

    // RFC 9001 s5.8's tag lets a receiver discard a corrupted Retry; it must
    // equally discard one whose Version field names a QUIC version we have
    // no Retry constants for. `version` is the peer-controlled Version field
    // - an off-path attacker forging a Retry chooses it - so TryVerify must
    // swallow the resulting NotSupportedException from GetKey/GetNonce
    // rather than let it escape and, in a receive loop that does not wrap
    // every call individually, halt processing of every other packet too.
    [Fact]
    public void UnsupportedVersion2FailsVerificationWithoutThrowing()
    {
        var odcid = Convert.FromHexString(OriginalDestinationConnectionIdHex);
        var fullPacket = Convert.FromHexString(A4FullRetryPacketHex);
        var retryPacketWithoutTag = fullPacket[..^16];
        var tag = fullPacket[^16..];

        var exception = Record.Exception(() =>
            TlsQuicRetry.TryVerify(TlsQuicVersion.Version2, odcid, retryPacketWithoutTag, tag));
        Assert.Null(exception);
        Assert.False(TlsQuicRetry.TryVerify(TlsQuicVersion.Version2, odcid, retryPacketWithoutTag, tag));
    }

    // Same reasoning as above, for a version value entirely outside the
    // enum (GetKey/GetNonce's ArgumentOutOfRangeException path) rather than
    // a defined-but-unimplemented one.
    [Fact]
    public void VersionOutsideEnumFailsVerificationWithoutThrowing()
    {
        var odcid = Convert.FromHexString(OriginalDestinationConnectionIdHex);
        var fullPacket = Convert.FromHexString(A4FullRetryPacketHex);
        var retryPacketWithoutTag = fullPacket[..^16];
        var tag = fullPacket[^16..];
        var unknownVersion = (TlsQuicVersion)0xdeadbeef;

        var exception = Record.Exception(() =>
            TlsQuicRetry.TryVerify(unknownVersion, odcid, retryPacketWithoutTag, tag));
        Assert.Null(exception);
        Assert.False(TlsQuicRetry.TryVerify(unknownVersion, odcid, retryPacketWithoutTag, tag));
    }

    // Builds a Retry packet through the real wire-serialization path
    // (TlsQuicPacketHeader.WriteLongHeader), computes its tag, patches the
    // tag into place, then verifies - exercising ComputeTag and TryVerify
    // together against something other than the fixed A.4 vector.
    [Fact]
    public void ConstructRetryComputeTagThenVerifyRoundTrips()
    {
        var originalDestinationConnectionId = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        var header = new TlsQuicLongHeader
        {
            Type = TlsQuicLongPacketType.Retry,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = new byte[] { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 },
            SourceConnectionId = new byte[] { 0x99, 0x98, 0x97 },
            Token = "token"u8.ToArray(),
            RetryIntegrityTag = new byte[16], // placeholder; overwritten below once the real tag is known.
        };

        var buffer = new byte[128];
        var written = TlsQuicPacketHeader.WriteLongHeader(buffer, header, out _);
        var packet = buffer[..written];
        var retryPacketWithoutTag = packet[..^16];

        var tag = new byte[16];
        TlsQuicRetry.ComputeTag(TlsQuicVersion.Version1, originalDestinationConnectionId, retryPacketWithoutTag, tag);
        tag.CopyTo(packet.AsSpan(packet.Length - 16));

        Assert.True(TlsQuicRetry.TryVerify(
            TlsQuicVersion.Version1, originalDestinationConnectionId, packet[..^16], packet[^16..]));
    }

    // RFC 9000 s7.2: a zero-length source connection ID is legal, and is
    // exactly what Chromium sends (subsystem B's imitation target) - which
    // makes the client's ODCID zero-length too. Exercises
    // BuildPseudoPacket's pseudoPacket[0] = 0 path with no ID bytes
    // following it; A.4 alone never does, since its ODCID is 8 bytes.
    [Fact]
    public void ConstructRetryWithEmptyOriginalDestinationConnectionIdRoundTrips()
    {
        var originalDestinationConnectionId = ReadOnlySpan<byte>.Empty;
        var header = new TlsQuicLongHeader
        {
            Type = TlsQuicLongPacketType.Retry,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = new byte[] { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 },
            SourceConnectionId = new byte[] { 0x99, 0x98, 0x97 },
            Token = "token"u8.ToArray(),
            RetryIntegrityTag = new byte[16], // placeholder; overwritten below once the real tag is known.
        };

        var buffer = new byte[128];
        var written = TlsQuicPacketHeader.WriteLongHeader(buffer, header, out _);
        var packet = buffer[..written];
        var retryPacketWithoutTag = packet[..^16];

        var tag = new byte[16];
        TlsQuicRetry.ComputeTag(TlsQuicVersion.Version1, originalDestinationConnectionId, retryPacketWithoutTag, tag);
        tag.CopyTo(packet.AsSpan(packet.Length - 16));

        Assert.True(TlsQuicRetry.TryVerify(
            TlsQuicVersion.Version1, originalDestinationConnectionId, packet[..^16], packet[^16..]));
    }
}
