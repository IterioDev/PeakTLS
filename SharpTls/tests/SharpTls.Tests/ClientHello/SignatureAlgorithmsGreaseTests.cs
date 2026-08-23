using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.ClientHello;

/// <summary>
/// Covers the two 2026 Chromium client codepoint gaps: the ML-DSA signature algorithms
/// (BoringSSL `include/openssl/ssl.h` @ main L1174-L1176, sent by Chromium's `kVerifyPrefs`
/// at `net/socket/ssl_client_socket_impl.cc` @ main L797-L809) and GREASE in
/// signature_algorithms (`net/base/features.cc` @ main L1004
/// <c>BASE_FEATURE(kTlsGreaseSigalgs, base::FEATURE_ENABLED_BY_DEFAULT)</c>, spliced at
/// `ssl/extensions.cc` @ main L1031-L1036).
/// </summary>
public sealed class SignatureAlgorithmsGreaseTests
{
    private static readonly SignatureScheme[] ChromiumVerifyPrefs =
    [
        SignatureScheme.MlDsa44,
        SignatureScheme.MlDsa65,
        SignatureScheme.MlDsa87,
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPkcs1Sha256,
        SignatureScheme.EcdsaSecp384r1Sha384,
        SignatureScheme.RsaPssRsaeSha384,
        SignatureScheme.RsaPkcs1Sha384,
        SignatureScheme.RsaPssRsaeSha512,
        SignatureScheme.RsaPkcs1Sha512,
    ];

    private static readonly SignatureScheme[] ClassicPrefs =
    [
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPkcs1Sha256,
    ];

    // ---- Gap 1: ML-DSA codepoints ------------------------------------------------

    [Theory]
    [InlineData(SignatureScheme.MlDsa44, 0x0904)]
    [InlineData(SignatureScheme.MlDsa65, 0x0905)]
    [InlineData(SignatureScheme.MlDsa87, 0x0906)]
    public void MlDsaCodepointsMatchBoringSslSslHeader(SignatureScheme scheme, int codepoint)
        => Assert.Equal(codepoint, (ushort)scheme);

    [Fact]
    public void MlDsaSchemesAreAdvertisedInExactCallerOrder()
    {
        // The whole kVerifyPrefs order must survive, not just membership: JA4 and peetprint
        // hash the sigalg sequence.
        Assert.Equal(
            ChromiumVerifyPrefs,
            BuildSigalgs(builder => builder.WithSignatureAlgorithms(ChromiumVerifyPrefs)));
    }

    [Fact]
    public void MlDsaSchemesAreOmittableAndTheWireBytesDiffer()
    {
        var with = BuildHello(builder => builder.WithSignatureAlgorithms(ChromiumVerifyPrefs));
        var without = BuildHello(builder => builder.WithSignatureAlgorithms(ClassicPrefs));

        Assert.Equal(ChromiumVerifyPrefs, ReadSigalgs(with));
        Assert.Equal(ClassicPrefs, ReadSigalgs(without));
        Assert.NotEqual(with, without);
        Assert.DoesNotContain(SignatureScheme.MlDsa44, ReadSigalgs(without));
    }

    [Fact]
    public void MlDsaOrderIsCallerControlledNotCanonicalised()
    {
        // A mutant that sorted, deduplicated, or hard-coded the Chromium order would pass a
        // membership assertion. Reversing the list must reverse the wire bytes exactly.
        SignatureScheme[] reversed = [.. ChromiumVerifyPrefs.Reverse()];
        Assert.Equal(
            reversed,
            BuildSigalgs(builder => builder.WithSignatureAlgorithms(reversed)));
    }

    [Fact]
    public void MlDsaIsNotAddedToCertificateOrDelegatedCredentialLists()
    {
        // BoringSSL greases and ML-DSA-leads only signature_algorithms; the sibling
        // extensions carry exactly what the caller set.
        var hello = BuildHello(builder => builder
            .WithSignatureAlgorithms(ChromiumVerifyPrefs)
            .WithCertificateSignatureAlgorithms(ClassicPrefs)
            .WithGrease()
            .WithGreaseSignatureAlgorithms());

        Assert.Equal(
            ClassicPrefs,
            ReadSchemes(ReadExtension(hello, TlsExtensionType.SignatureAlgorithmsCert)));
    }

    // ---- Gap 2: GREASE in signature_algorithms ------------------------------------

    [Fact]
    public void GreaseSigalgIsAbsentByDefault()
    {
        var sigalgs = BuildSigalgs(builder => builder
            .WithGrease()
            .WithSignatureAlgorithms(ClassicPrefs));

        Assert.Equal(ClassicPrefs, sigalgs);
        Assert.DoesNotContain(sigalgs, scheme => IsGrease((ushort)scheme));
    }

    [Fact]
    public void GreaseSigalgIsPrependedWhenEnabled()
    {
        var sigalgs = BuildSigalgs(builder => builder
            .WithGrease()
            .WithSignatureAlgorithms(ClassicPrefs)
            .WithGreaseSignatureAlgorithms());

        // BoringSSL writes the fake value before tls12_add_verify_sigalgs.
        Assert.Equal(ClassicPrefs.Length + 1, sigalgs.Count);
        Assert.True(IsGrease((ushort)sigalgs[0]));
        Assert.Equal(ClassicPrefs, sigalgs.Skip(1));
    }

    [Fact]
    public void DisablingGreaseSigalgRestoresTheExactUngreasedBytes()
    {
        // Guards the knob in both directions and proves the disabled path consumes no
        // randomness: every other byte of the hello, GREASE values included, is unchanged.
        var off = BuildHello(builder => builder
            .WithGrease()
            .WithSignatureAlgorithms(ClassicPrefs));
        var explicitlyOff = BuildHello(builder => builder
            .WithGrease()
            .WithSignatureAlgorithms(ClassicPrefs)
            .WithGreaseSignatureAlgorithms(enabled: false));
        var on = BuildHello(builder => builder
            .WithGrease()
            .WithSignatureAlgorithms(ClassicPrefs)
            .WithGreaseSignatureAlgorithms());

        Assert.Equal(off, explicitlyOff);
        Assert.NotEqual(off, on);
        Assert.Equal(off.Length + 2, on.Length);
        AssertOnlySignatureAlgorithmsDiffer(off, on);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void GreaseSigalgLandsAtTheRequestedIndex(int index)
    {
        var sigalgs = BuildSigalgs(builder => builder
            .WithGrease()
            .WithSignatureAlgorithms(ClassicPrefs)
            .WithGreaseSignatureAlgorithms(enabled: true, index));

        Assert.True(IsGrease((ushort)sigalgs[index]));
        // The caller's list must be intact and in order around the splice, so a mutant that
        // always prepends, or that overwrites an entry, fails for index > 0.
        Assert.Equal(ClassicPrefs, sigalgs.Where((_, i) => i != index));
    }

    [Theory]
    [InlineData(int.MinValue)]
    [InlineData(-1)]
    [InlineData(4)]
    [InlineData(int.MaxValue)]
    public void OutOfRangeGreaseSigalgIndexClampsAndNeverThrows(int index)
    {
        var sigalgs = BuildSigalgs(builder => builder
            .WithGrease()
            .WithSignatureAlgorithms(ClassicPrefs)
            .WithGreaseSignatureAlgorithms(enabled: true, index));

        var expected = index < 0 ? 0 : ClassicPrefs.Length;
        Assert.Equal(ClassicPrefs.Length + 1, sigalgs.Count);
        Assert.True(IsGrease((ushort)sigalgs[expected]));
        Assert.Equal(ClassicPrefs, sigalgs.Where((_, i) => i != expected));
    }

    [Fact]
    public void GreaseSigalgWithoutGreaseEnabledEmitsNothingAndDoesNotThrow()
    {
        var sigalgs = BuildSigalgs(builder => builder
            .WithSignatureAlgorithms(ClassicPrefs)
            .WithGreaseSignatureAlgorithms());

        Assert.Equal(ClassicPrefs, sigalgs);
    }

    // ---- Gap 2: the seventh slot inside the equality-class model -------------------

    [Fact]
    public void SlotCountIsDerivedFromTheSlotEnum()
    {
        // Every declared slot must round-trip through the factory. If a slot is ever added
        // without extending the factory this fails rather than silently defaulting to 0.
        var policy = ClientHelloGreasePolicy.CreateWithSignatureAlgorithm(0, 1, 2, 3, 4, 5, 6);

        Assert.Equal(7, Enum.GetValues<ClientHelloGreaseSlot>().Length);
        Assert.Equal(
            Enum.GetValues<ClientHelloGreaseSlot>().Length,
            policy.DistinctValueCount);
        Assert.Equal(
            Enumerable.Range(0, 7),
            Enum.GetValues<ClientHelloGreaseSlot>().Select(policy.GetValueClass));
    }

    [Fact]
    public void SignatureAlgorithmSlotFollowsTheDocumentedFactoryDefaults()
    {
        Assert.Equal(
            0,
            ClientHelloGreasePolicy.Consistent.SignatureAlgorithmValueClass);
        Assert.Equal(
            6,
            ClientHelloGreasePolicy.PerSlot.SignatureAlgorithmValueClass);
        // The six-argument overload shares the primary extension class.
        var shared = ClientHelloGreasePolicy.CreateWithSecondaryExtension(0, 1, 2, 3, 4, 5);
        Assert.Equal(
            shared.GetValueClass(ClientHelloGreaseSlot.Extension),
            shared.SignatureAlgorithmValueClass);
        Assert.Equal(6, shared.DistinctValueCount);
    }

    [Fact]
    public void ConsistentPolicyReusesTheOneGreaseValueInSignatureAlgorithms()
    {
        var hello = BuildHello(builder => builder
            .WithGrease(ClientHelloGreasePolicy.Consistent)
            .WithSignatureAlgorithms(ClassicPrefs)
            .WithGreaseSignatureAlgorithms());

        Assert.Equal(ReadGreaseCipherSuite(hello), (ushort)ReadSigalgs(hello)[0]);
    }

    [Fact]
    public void DistinctClassGivesSignatureAlgorithmsItsOwnGreaseValue()
    {
        var policy = ClientHelloGreasePolicy.CreateWithSignatureAlgorithm(0, 0, 0, 0, 0, 0, 1);
        var hello = BuildHello(builder => builder
            .WithGrease(policy)
            .WithSignatureAlgorithms(ClassicPrefs)
            .WithGreaseSignatureAlgorithms());
        var greaseSigalg = (ushort)ReadSigalgs(hello)[0];

        Assert.Equal(2, policy.DistinctValueCount);
        Assert.True(IsGrease(greaseSigalg));
        Assert.NotEqual(ReadGreaseCipherSuite(hello), greaseSigalg);
    }

    [Fact]
    public void GreaseSigalgSurvivesHelloRetryRequestUnchanged()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithGrease(ClientHelloGreasePolicy.PerSlot)
            .WithSignatureAlgorithms(ClassicPrefs)
            .WithGreaseSignatureAlgorithms()
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1));
        using var first = profile.BuildSecure("example.com");
        using var retry = ClientHelloEncoder.BuildRetry(first, NamedGroup.Secp384r1, cookie: null);

        var value = first.GreaseValues!.Value.SignatureAlgorithm;
        Assert.True(IsGrease(value));
        Assert.Equal(value, retry.GreaseValues!.Value.SignatureAlgorithm);
        Assert.Equal(value, (ushort)ReadSigalgs(retry.EncodedHandshake)[0]);
        Assert.Equal(
            value,
            first.GreaseValues.Value.Get(ClientHelloGreaseSlot.SignatureAlgorithm));
    }

    [Fact]
    public void DisabledGreaseSigalgLeavesNoValueOnTheHandshakeResult()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithGrease(ClientHelloGreasePolicy.Consistent)
            .WithSignatureAlgorithms(ClassicPrefs));
        using var hello = profile.BuildSecure("example.com");

        // Zero is the documented "no value" marker; a real GREASE value here would mean the
        // disabled path still drew and carried one.
        Assert.Equal(0, hello.GreaseValues!.Value.SignatureAlgorithm);
        Assert.True(IsGrease(hello.GreaseValues.Value.CipherSuite));
    }

    [Fact]
    public void PerSlotKeepsTheSignatureAlgorithmValueDistinctFromEveryOtherSlot()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithGrease(ClientHelloGreasePolicy.PerSlot)
            .WithSignatureAlgorithms(ClassicPrefs)
            .WithGreaseSignatureAlgorithms());
        using var hello = profile.BuildSecure("example.com");
        var values = hello.GreaseValues!.Value;

        ushort[] others =
        [
            values.CipherSuite,
            values.SupportedVersion,
            values.SupportedGroup,
            values.KeyShare,
            values.Extension,
        ];
        Assert.DoesNotContain(values.SignatureAlgorithm, others);
        Assert.All(others, value => Assert.True(IsGrease(value)));
    }

    // ---- helpers ------------------------------------------------------------------

    private static byte[] BuildHello(Action<ClientHelloBuilder> configure)
        => ClientHelloProfiles.Custom(configure)
            .BuildDeterministicForTesting("example.com", [7, 7, 4, 2]);

    private static IReadOnlyList<SignatureScheme> BuildSigalgs(Action<ClientHelloBuilder> configure)
        => ReadSigalgs(BuildHello(configure));

    private static IReadOnlyList<SignatureScheme> ReadSigalgs(byte[] handshake)
        => ReadSchemes(ReadExtension(handshake, TlsExtensionType.SignatureAlgorithms));

    private static IReadOnlyList<SignatureScheme> ReadSchemes(byte[] body)
    {
        var reader = new TlsBinaryReader(new TlsBinaryReader(body).ReadVector16());
        var result = new List<SignatureScheme>();
        while (!reader.End)
        {
            result.Add((SignatureScheme)reader.ReadUInt16());
        }
        return result;
    }

    private static ushort ReadGreaseCipherSuite(byte[] handshake)
    {
        var reader = new TlsBinaryReader(handshake);
        Assert.Equal((byte)HandshakeType.ClientHello, reader.ReadUInt8());
        var body = new TlsBinaryReader(reader.ReadBytes(reader.ReadUInt24()));
        _ = body.ReadUInt16();
        _ = body.ReadBytes(32);
        _ = body.ReadVector8();
        var suites = new TlsBinaryReader(body.ReadVector16());
        var first = suites.ReadUInt16();
        Assert.True(IsGrease(first));
        return first;
    }

    private static byte[] ReadExtension(byte[] handshake, TlsExtensionType type)
        => ReadExtensions(handshake).Single(extension => extension.Type == (ushort)type).Data;

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

    private static void AssertOnlySignatureAlgorithmsDiffer(byte[] left, byte[] right)
    {
        var a = ReadExtensions(left);
        var b = ReadExtensions(right);
        Assert.Equal(a.Select(x => x.Type), b.Select(x => x.Type));
        for (var index = 0; index < a.Count; index++)
        {
            if (a[index].Type == (ushort)TlsExtensionType.SignatureAlgorithms)
            {
                Assert.NotEqual(a[index].Data, b[index].Data);
                continue;
            }
            Assert.Equal(a[index].Data, b[index].Data);
        }
    }

    private static bool IsGrease(ushort value)
        => (value & 0x0F0F) == 0x0A0A && (byte)(value >> 8) == (byte)value;
}
