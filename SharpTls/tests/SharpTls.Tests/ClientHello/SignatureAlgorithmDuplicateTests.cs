using System.Security.Cryptography;
using System.Text;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.ClientHello;

/// <summary>
/// Pins the one signature_algorithms invariant no RFC supplies: a repeated codepoint is data,
/// not an error. RFC 9846 §4.3.3 (RFC 8446 §4.2.3) constrains only the ORDER of the list —
/// "The values are indicated in descending order of preference" — and never forbids a repeat.
/// Real devices repeat one: the shipped Apple capture carries 0x0805 twice, and the reported
/// handset sends a ten-entry list with the same repeat. <see cref="ClientHelloBuilder"/> keeps a
/// caller-typo guard on by default and <c>AllowDuplicateSignatureAlgorithms</c> turns it off.
/// </summary>
public sealed class SignatureAlgorithmDuplicateTests
{
    /// <summary>
    /// The reported handset's list, exactly as seen in 80/80 pcapng connections and in the
    /// reporter's own hellos.json `sig_hash_algs`: ten entries, 0x0805 twice, at index 4 and 5.
    /// </summary>
    private static readonly ushort[] ReportedHandsetCodepoints =
    [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
    ];

    private static readonly SignatureScheme[] ReportedHandsetList =
    [
        SignatureScheme.EcdsaSecp256r1Sha256, // 0403
        SignatureScheme.RsaPssRsaeSha256,     // 0804
        SignatureScheme.RsaPkcs1Sha256,       // 0401
        SignatureScheme.EcdsaSecp384r1Sha384, // 0503
        SignatureScheme.RsaPssRsaeSha384,     // 0805  <-- first
        SignatureScheme.RsaPssRsaeSha384,     // 0805  <-- repeat
        SignatureScheme.RsaPkcs1Sha384,       // 0501
        SignatureScheme.RsaPssRsaeSha512,     // 0806
        SignatureScheme.RsaPkcs1Sha512,       // 0601
        SignatureScheme.RsaPkcs1Sha1,         // 0201
    ];

    /// <summary>The same list with the repeat dropped: nine entries, otherwise identical.</summary>
    private static readonly SignatureScheme[] DeduplicatedList =
        [.. ReportedHandsetList.Where((_, index) => index != 5)];

    // ---- the witness: ten entries with a repeat reach the wire, in order ------------

    [Fact]
    public void TenEntryListWithARepeatIsAcceptedAndEmittedVerbatim()
    {
        // Decoded out of the ENCODED ClientHello, as raw codepoints, so this cannot pass by
        // reading the builder's input back, and cannot pass for a mutant that re-maps enums.
        var onTheWire = ReadSigalgCodepoints(BuildHello(ReportedHandsetList));

        Assert.Equal(ReportedHandsetCodepoints, onTheWire);
        Assert.Equal(10, onTheWire.Length);
        // Order and position, not just multiset membership: a mutant that sorts, that appends
        // the repeat at the end, or that hoists it to the front all fail here.
        Assert.Equal(0x0805, onTheWire[4]);
        Assert.Equal(0x0805, onTheWire[5]);
        Assert.Equal(9, onTheWire.Distinct().Count());
        Assert.Equal(1, onTheWire.Count(value => value == 0x0403));
    }

    [Fact]
    public void TheRepeatIsExactlyTwoBytesOfWireAndMovesNothingElse()
    {
        var ten = BuildHello(ReportedHandsetList);
        var nine = BuildHello(DeduplicatedList);

        // The reporter's stated symptom, both halves of it.
        Assert.Equal(nine.Length + 2, ten.Length);
        Assert.Equal(ReadSigalgCodepoints(nine).Length + 1, ReadSigalgCodepoints(ten).Length);

        // The two bytes land inside signature_algorithms and nowhere else: every other
        // extension is byte-identical and the extension order is untouched. A mutant that
        // paid for the repeat out of padding, or that grew some other list, fails here.
        var tenExtensions = ReadExtensions(ten);
        var nineExtensions = ReadExtensions(nine);
        Assert.Equal(nineExtensions.Select(x => x.Type), tenExtensions.Select(x => x.Type));
        for (var index = 0; index < tenExtensions.Count; index++)
        {
            if (tenExtensions[index].Type == (ushort)TlsExtensionType.SignatureAlgorithms)
            {
                Assert.Equal(nineExtensions[index].Data.Length + 2, tenExtensions[index].Data.Length);
                continue;
            }

            Assert.Equal(nineExtensions[index].Data, tenExtensions[index].Data);
        }
    }

    [Fact]
    public void TheRepeatChangesTheJa4SignatureAlgorithmComponent()
    {
        // JA4's `c` part hashes the signature_algorithms codepoints in wire order, repeats
        // included — which is exactly why JA4 moves here while JA3, which does not hash this
        // list at all, does not. The joined segment is pinned literally so the expectation is
        // checkable by hand against the capture.
        Assert.Equal(
            "0403,0804,0401,0503,0805,0805,0501,0806,0601,0201",
            Ja4SignatureAlgorithmSegment(BuildHello(ReportedHandsetList)));
        Assert.Equal(
            "0403,0804,0401,0503,0805,0501,0806,0601,0201",
            Ja4SignatureAlgorithmSegment(BuildHello(DeduplicatedList)));
        Assert.NotEqual(
            Ja4SignatureAlgorithmDigest(BuildHello(ReportedHandsetList)),
            Ja4SignatureAlgorithmDigest(BuildHello(DeduplicatedList)));
    }

    // ---- the knob works in both directions -----------------------------------------

    [Fact]
    public void DuplicatesStayRejectedUntilTheKnobIsTurnedOn()
    {
        // Default-off, so no shipped profile silently gains a typo net it did not ask for.
        var byDefault = Assert.Throws<ArgumentException>(
            () => ClientHelloProfiles.Custom(builder =>
                builder.WithSignatureAlgorithms(ReportedHandsetList)));
        Assert.Equal("_signatureAlgorithms", byDefault.ParamName);

        // Explicit false is honoured too, so the knob is a real parameter and not a
        // write-only flag a mutant could ignore.
        var explicitlyOff = Assert.Throws<ArgumentException>(
            () => ClientHelloProfiles.Custom(builder => builder
                .AllowDuplicateSignatureAlgorithms(enabled: false)
                .WithSignatureAlgorithms(ReportedHandsetList)));
        Assert.Equal("_signatureAlgorithms", explicitlyOff.ParamName);
    }

    [Fact]
    public void TheKnobIsOrderIndependentAndUnique_ListsAreUnaffectedByIt()
    {
        // Turning it on before or after the list must behave identically, and turning it on
        // must not perturb the bytes of a list that has no duplicate at all.
        var before = BuildHello(builder => builder
            .AllowDuplicateSignatureAlgorithms()
            .WithSignatureAlgorithms(ReportedHandsetList));
        var after = BuildHello(builder => builder
            .WithSignatureAlgorithms(ReportedHandsetList)
            .AllowDuplicateSignatureAlgorithms());
        Assert.Equal(before, after);

        Assert.Equal(
            BuildHello(builder => builder.WithSignatureAlgorithms(DeduplicatedList)),
            BuildHello(builder => builder
                .AllowDuplicateSignatureAlgorithms()
                .WithSignatureAlgorithms(DeduplicatedList)));
    }

    [Fact]
    public void TheKnobDoesNotLeakIntoTheRfcBackedGuards()
    {
        // key_share: RFC 9846 §4.3.8 / RFC 8446 §4.2.8 — "Clients MUST NOT offer multiple
        // KeyShareEntry values for the same group." Still rejected with the knob on. The
        // parameter name is asserted so deleting this guard cannot be masked by some other
        // guard happening to throw an ArgumentException of its own.
        var keyShare = Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .AllowDuplicateSignatureAlgorithms()
            .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.X25519, NamedGroup.X25519)));
        Assert.Equal("_keyShareGroups", keyShare.ParamName);
        // The message, not just the parameter: the same-order-subset rule further down also
        // rejects this input and also blames _keyShareGroups, so without this the dedicated
        // RFC-backed guard could be deleted outright and nothing would notice.
        Assert.Contains("Duplicate values are not allowed", keyShare.Message, StringComparison.Ordinal);

        // supported_groups: RFC 9846 §4.3.7 — "The "named_group_list" MUST NOT contain any
        // duplicate entries." Still rejected with the knob on. Same reason for pinning the
        // parameter: with this guard gone the key_share guard would otherwise catch it,
        // because key shares default to the supported-group list.
        var groups = Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .AllowDuplicateSignatureAlgorithms()
            .WithSupportedGroups(NamedGroup.X25519, NamedGroup.X25519)));
        Assert.Equal("_supportedGroups", groups.ParamName);

        // signature_algorithms_cert is a separate list with its own guard; the knob is
        // scoped to signature_algorithms and must not unlock it.
        var cert = Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .AllowDuplicateSignatureAlgorithms()
            .WithSignatureAlgorithms(ReportedHandsetList)
            .WithCertificateSignatureAlgorithms(
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.EcdsaSecp256r1Sha256)));
        Assert.Equal("_certificateSignatureAlgorithms", cert.ParamName);
    }

    [Fact]
    public void TheAssumptionOnlyGuardsKeepTheirCurrentBehaviourUntilEvidenceMovesThem()
    {
        // cipher_suites and supported_versions are rejected on OUR authority, not the RFC's:
        // RFC 9846 §4.2.2 and §4.3.1 fix only the order of those lists. That makes them the
        // next candidates if a capture ever shows a real client repeating an entry, so pin
        // today's behaviour — including which parameter is blamed — so that any change is a
        // decision someone made rather than a refactor nobody noticed.
        var versions = Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithSupportedVersions(TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls13)));
        Assert.Equal("_supportedVersions", versions.ParamName);
        Assert.Contains("Duplicate values are not allowed", versions.Message, StringComparison.Ordinal);

        var suites = Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256, TlsCipherSuite.TlsAes128GcmSha256)));
        Assert.Equal("_cipherSuites", suites.ParamName);
        Assert.Contains("Duplicate values are not allowed", suites.Message, StringComparison.Ordinal);
    }

    // ---- the capability is live in shipped evidence, not just in a test ------------

    [Fact]
    public void TheShippedCaptureAlreadyCarriesARepeatedCodepoint()
    {
        // Non-vacuous: if the repeat ever stopped reaching the wire for a real profile, the
        // tests above could still pass on a hand-built builder while the shipped one regressed.
        // The Spotify iOS QUIC capture carries ten entries with 0x0805 twice.
        var codepoints = ReadSigalgCodepoints(
            ClientHelloProfiles.Spotify917602050IOS270Quic
                .BuildDeterministicForTesting("example.com", [7, 7, 4, 2]));

        Assert.Equal(10, codepoints.Length);
        Assert.Equal(9, codepoints.Distinct().Count());
        Assert.Equal(2, codepoints.Count(value => value == 0x0805));
    }

    // Deliberately NOT re-pinned here: "no shipped profile's bytes moved" is the job of
    // SpotifyIosQuicProfileWireTests. This comment used to name LegacyUTlsProfileTests,
    // UTlsProfileTests, AdditionalUTlsProfileTests and SpotifyIos16CaptureTests, all of which
    // were deleted with the 52 uTLS profiles — leaving the claim true-sounding and the coverage
    // gone, until a cipher-order edit sailed through a green suite and exposed it.

    // ---- helpers -------------------------------------------------------------------

    private static byte[] BuildHello(SignatureScheme[] algorithms)
        => BuildHello(builder => builder
            .AllowDuplicateSignatureAlgorithms()
            .WithSignatureAlgorithms(algorithms));

    private static byte[] BuildHello(Action<ClientHelloBuilder> configure)
        => ClientHelloProfiles.Custom(configure)
            .BuildDeterministicForTesting("example.com", [7, 7, 4, 2]);

    private static string Ja4SignatureAlgorithmSegment(byte[] handshake)
        => string.Join(',', ReadSigalgCodepoints(handshake).Select(value => value.ToString("x4")));

    private static string Ja4SignatureAlgorithmDigest(byte[] handshake)
        => Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(Ja4SignatureAlgorithmSegment(handshake))))[..12];

    private static ushort[] ReadSigalgCodepoints(byte[] handshake)
    {
        var body = ReadExtensions(handshake)
            .Single(extension => extension.Type == (ushort)TlsExtensionType.SignatureAlgorithms)
            .Data;
        var reader = new TlsBinaryReader(new TlsBinaryReader(body).ReadVector16());
        var result = new List<ushort>();
        while (!reader.End)
        {
            result.Add(reader.ReadUInt16());
        }
        return [.. result];
    }

    private static List<(ushort Type, byte[] Data)> ReadExtensions(byte[] handshake)
    {
        var reader = new TlsBinaryReader(handshake);
        Assert.Equal((byte)HandshakeType.ClientHello, reader.ReadUInt8());
        var body = new TlsBinaryReader(reader.ReadBytes(reader.ReadUInt24()));
        _ = body.ReadUInt16();
        _ = body.ReadBytes(32);
        _ = body.ReadVector8();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        var result = new List<(ushort Type, byte[] Data)>();
        while (!extensions.End)
        {
            result.Add((extensions.ReadUInt16(), extensions.ReadVector16().ToArray()));
        }
        return result;
    }
}
