using System.Security.Cryptography;

namespace SharpTls.Quic;

// RFC 9001 s5.8: Retry Packet Integrity. Retry packets carry a 128-bit tag
// computed with AEAD_AES_128_GCM under a fixed key and nonce (not derived
// per-connection, unlike every other QUIC key in this namespace) over a
// "Retry Pseudo-Packet" (Figure 8) that is never sent on the wire: the
// transmitted Retry packet with its tag removed, prefixed by a length-
// prefixed copy of the client's original Destination Connection ID (ODCID) -
// the DCID from the client's first Initial packet, which the Retry packet
// itself does not carry.
//
// This buys two properties (s5.8): a receiver can discard packets corrupted
// in transit, and only an entity that observed the client's Initial packet -
// and therefore knows the ODCID - can produce a tag that verifies. It is not
// confidentiality: Retry packets are visible to anyone on path. That shapes
// the API below the same way TlsQuicPacketProtection.TryOpen is shaped:
// verification is the routine operation (every stray or forged Retry that
// arrives is rejected by a false return, matching RFC 9000 s14/s17.2.5.2's
// "MUST discard"), while construction (ComputeTag) has no routine failure
// mode and throws on caller error instead.
//
// `retryPacketWithoutTag` in both methods below is the on-wire Retry packet
// - Header Form byte through Retry Token, i.e. every field in RFC 9000
// Figure 18 except the trailing Retry Integrity Tag - not re-serialized
// here. A verifier already has these bytes as everything but the last 16
// bytes of a received Retry datagram (TlsQuicPacketHeader.TryReadLongHeader
// never returns a Retry packet coalesced with anything else - see
// TlsQuicPacketHeader.TryFinishRetry's comment - so the datagram minus its
// tag suffices). A sender gets the same bytes from
// TlsQuicPacketHeader.WriteLongHeader called with a 16-byte placeholder tag,
// sliced to length-minus-16; see TlsQuicRetryTests for the pattern. Keeping
// wire serialization in one place (TlsQuicPacketHeader) avoids a second,
// possibly drifting copy of the Figure 18 layout here.
internal static class TlsQuicRetry
{
    private const int TagLength = 16;

    // RFC 9001 s5.8: "The secret key and the nonce are values derived by
    // calling HKDF-Expand-Label using [a fixed secret] as the secret, with
    // labels being 'quic key' and 'quic iv'." That derivation has no
    // per-connection input, so its output is a compile-time constant rather
    // than something recomputed on every call - the RFC publishes the
    // already-derived result directly. Kept as a version-keyed table
    // (GetKey/GetNonce below) rather than inlined into ComputeTag/TryVerify
    // so a future QUIC v2 (RFC 9369, which defines different constants for
    // this same construction) is another table entry, not a second code
    // path through this class.
    private static ReadOnlySpan<byte> Version1Key =>
    [0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
     0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e];

    private static ReadOnlySpan<byte> Version1Nonce =>
    [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
     0x23, 0x98, 0x25, 0xbb];

    // RFC 9001 s5.8: construction has no routine failure mode - sealing an
    // empty plaintext under a fixed, public key is not something that fails
    // because the network corrupted a byte, unlike TryVerify below - so
    // invalid input here is a caller bug and throws, matching
    // TlsQuicPacketProtection.Seal's contract. `version` here is chosen by
    // the caller (this endpoint's own negotiated/attempted version), not by
    // a peer, so throwing on one we do not have constants for is correct -
    // deliberately asymmetric with TryVerify below, which takes `version`
    // off the wire and must never throw on it. Do not "fix" these two into
    // matching behavior.
    internal static void ComputeTag(
        TlsQuicVersion version,
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> retryPacketWithoutTag,
        Span<byte> tag)
    {
        if (tag.Length != TagLength)
        {
            throw new ArgumentException($"Tag must be exactly {TagLength} bytes.", nameof(tag));
        }
        if (originalDestinationConnectionId.Length > TlsQuicPacketHeader.MaximumConnectionIdLength)
        {
            throw new ArgumentOutOfRangeException(nameof(originalDestinationConnectionId));
        }

        var key = GetKey(version);
        var nonce = GetNonce(version);
        var pseudoPacket = BuildPseudoPacket(originalDestinationConnectionId, retryPacketWithoutTag);

        using var aesGcm = new AesGcm(key, TagLength);
        aesGcm.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, pseudoPacket);
    }

    // RFC 9000 s14 / s17.2.5.2: "Clients MUST discard Retry packets that
    // have a Retry Integrity Tag that cannot be validated" - routine on
    // every corrupted or forged Retry, so failure is a false return, never
    // an exception. Same contract as TlsQuicPacketProtection.TryOpen.
    //
    // Unlike ComputeTag, `version` here is not trustworthy: it is the
    // Version field off a packet the peer sent, and an off-path attacker
    // forging a Retry controls it directly. GetKey/GetNonce therefore run
    // inside the try, and both NotSupportedException (a well-formed version
    // we have no constants for, e.g. v2 today) and ArgumentOutOfRangeException
    // (a version outside the enum entirely) are discarded the same as a
    // failed tag - a receive loop must be able to drop one bad Retry without
    // its exception escaping and halting packet processing for everyone else.
    internal static bool TryVerify(
        TlsQuicVersion version,
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> retryPacketWithoutTag,
        ReadOnlySpan<byte> tag)
    {
        if (tag.Length != TagLength ||
            originalDestinationConnectionId.Length > TlsQuicPacketHeader.MaximumConnectionIdLength)
        {
            return false;
        }

        try
        {
            var key = GetKey(version);
            var nonce = GetNonce(version);
            var pseudoPacket = BuildPseudoPacket(originalDestinationConnectionId, retryPacketWithoutTag);

            using var aesGcm = new AesGcm(key, TagLength);
            aesGcm.Decrypt(nonce, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty, pseudoPacket);
            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            // RFC 9000 s14: routine on every corrupted or forged Retry, not
            // an exceptional condition - see TlsQuicPacketProtection.TryOpen
            // for the same reasoning applied to ordinary packet protection.
            return false;
        }
        catch (NotSupportedException)
        {
            // A peer offering a QUIC version whose Retry constants we do not have
            // is discarded, not fatal: version arrives on the wire and an off-path
            // attacker forging a Retry controls it.
            return false;
        }
        catch (ArgumentOutOfRangeException)
        {
            // Same reasoning for a version value outside the enum entirely.
            return false;
        }
    }

    // RFC 9001 s5.8 Figure 8: ODCID Length (1 byte) + Original Destination
    // Connection ID, prepended to the transmitted Retry packet with its tag
    // removed. Never sent on the wire - only ever fed to the AEAD as
    // associated data. Mutation check: skipping the ODCID prefix here still
    // produces *a* valid-looking tag, just not one any real receiver (who
    // independently reconstructs this same pseudo-packet from their own copy
    // of the ODCID) would ever compute - see TlsQuicRetryTests' mutation
    // check note for how the test suite pins this.
    private static byte[] BuildPseudoPacket(
        ReadOnlySpan<byte> originalDestinationConnectionId, ReadOnlySpan<byte> retryPacketWithoutTag)
    {
        var pseudoPacket = new byte[1 + originalDestinationConnectionId.Length + retryPacketWithoutTag.Length];
        pseudoPacket[0] = (byte)originalDestinationConnectionId.Length;
        originalDestinationConnectionId.CopyTo(pseudoPacket.AsSpan(1));
        retryPacketWithoutTag.CopyTo(pseudoPacket.AsSpan(1 + originalDestinationConnectionId.Length));
        return pseudoPacket;
    }

    private static ReadOnlySpan<byte> GetKey(TlsQuicVersion version) => version switch
    {
        TlsQuicVersion.Version1 => Version1Key,
        TlsQuicVersion.Version2 => throw new NotSupportedException(
            "QUIC v2 (RFC 9369) Retry integrity constants are not yet implemented."),
        _ => throw new ArgumentOutOfRangeException(nameof(version), version, "Unknown QUIC version."),
    };

    private static ReadOnlySpan<byte> GetNonce(TlsQuicVersion version) => version switch
    {
        TlsQuicVersion.Version1 => Version1Nonce,
        TlsQuicVersion.Version2 => throw new NotSupportedException(
            "QUIC v2 (RFC 9369) Retry integrity constants are not yet implemented."),
        _ => throw new ArgumentOutOfRangeException(nameof(version), version, "Unknown QUIC version."),
    };
}
