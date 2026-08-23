using System.IO.Compression;
using SharpTls.Certificates;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Certificates;

public sealed class CompressedCertificateTests
{
    [Theory]
    [InlineData((ushort)1)]
    [InlineData((ushort)2)]
    [InlineData((ushort)3)]
    public void ManagedAlgorithmsRoundTripExactly(ushort algorithm)
    {
        var certificateBody = Enumerable.Range(0, 8_193)
            .Select(index => (byte)((index * 31) & 0xFF))
            .ToArray();
        var compressed = Compress(certificateBody, algorithm);
        var message = Encode(algorithm, certificateBody.Length, compressed);

        var decompressed = CompressedCertificateParser.Decompress(
            message,
            CreateOffer(algorithm),
            TlsLimits.Default);

        Assert.Equal(certificateBody, decompressed);
    }

    [Theory]
    [InlineData((ushort)1, -1)]
    [InlineData((ushort)1, 1)]
    [InlineData((ushort)2, -1)]
    [InlineData((ushort)2, 1)]
    [InlineData((ushort)3, -1)]
    [InlineData((ushort)3, 1)]
    public void DeclaredLengthMismatchIsRejected(ushort algorithm, int adjustment)
    {
        var certificateBody = Enumerable.Repeat((byte)0xA5, 4_096).ToArray();
        var compressed = Compress(certificateBody, algorithm);
        var message = Encode(algorithm, certificateBody.Length + adjustment, compressed);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(
                message,
                CreateOffer(algorithm),
                TlsLimits.Default));

        Assert.Equal(TlsAlertDescription.BadCertificate, exception.Alert);
    }

    [Fact]
    public void UnoferredAndCorruptAlgorithmsAreRejected()
    {
        var body = Enumerable.Repeat((byte)7, 256).ToArray();
        var zlib = Encode(1, body.Length, Compress(body, 1));
        var corrupt = Encode(2, body.Length, [1, 2, 3, 4, 5]);

        var unoffered = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(zlib, CreateOffer(2), TlsLimits.Default));
        var invalid = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(corrupt, CreateOffer(2), TlsLimits.Default));

        Assert.Equal(TlsAlertDescription.BadCertificate, unoffered.Alert);
        Assert.Equal(TlsAlertDescription.BadCertificate, invalid.Alert);
    }

    [Fact]
    public void DeclaredOutputIsBoundedBeforeDecompression()
    {
        var writer = new TlsBinaryWriter();
        writer.WriteUInt16(2);
        writer.WriteUInt24(TlsLimits.Default.MaxHandshakeMessageSize + 1);
        writer.WriteVector24([1]);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(
                writer.WrittenSpan,
                CreateOffer(2),
                TlsLimits.Default));

        Assert.Equal(TlsAlertDescription.BadCertificate, exception.Alert);
    }

    [Theory]
    [InlineData(TlsCertificateCompressionAlgorithm.Zlib)]
    [InlineData(TlsCertificateCompressionAlgorithm.Brotli)]
    public void ServerEncoderProducesAnExactlyRecoverableCertificateBody(
        TlsCertificateCompressionAlgorithm algorithm)
    {
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (System.Security.Cryptography.RSA)pki.LeafKey,
            [pki.Root]);
        var uncompressed = Tls13ServerHandshakeMessages.BuildCertificate(
            credential,
            TlsLimits.Default);
        var compressed = Tls13ServerHandshakeMessages.BuildCompressedCertificate(
            credential,
            TlsLimits.Default,
            algorithm);

        Assert.Equal((byte)HandshakeType.CompressedCertificate, compressed[0]);
        var recovered = CompressedCertificateParser.Decompress(
            compressed.AsSpan(TlsConstants.HandshakeHeaderLength),
            CreateOffer((ushort)algorithm),
            TlsLimits.Default);
        Assert.Equal(uncompressed.AsSpan(TlsConstants.HandshakeHeaderLength).ToArray(), recovered);
    }

    [Theory]
    [InlineData(new byte[] { 0 })]
    [InlineData(new byte[] { 1, 0 })]
    [InlineData(new byte[] { 4, 0, 2, 0, 2 })]
    public void ServerParserRejectsMalformedOrDuplicateCompressionOffers(byte[] extensionBody)
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.CompressCertificate,
                    extensionBody)));
        var encoded = profile.BuildDeterministicForTesting("example.com", [4, 3, 2, 1]);

        Assert.Throws<TlsProtocolException>(() => Tls13ClientHelloParser.Parse(
            encoded.AsSpan(TlsConstants.HandshakeHeaderLength)));
    }

    [Fact]
    public void ZstdCertificateChainDecompressesIntoTheHandshakeCertificateMessage()
    {
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (System.Security.Cryptography.RSA)pki.LeafKey,
            [pki.Root]);
        var certificateBody = Tls13ServerHandshakeMessages
            .BuildCertificate(credential, TlsLimits.Default)
            .AsSpan(TlsConstants.HandshakeHeaderLength)
            .ToArray();
        var message = Encode(3, certificateBody.Length, Compress(certificateBody, 3));

        var recovered = CompressedCertificateParser.Decompress(
            message,
            CreateOffer(3),
            TlsLimits.Default);

        Assert.Equal(certificateBody, recovered);
        using var parsed = CertificateMessageParser.Parse(
            recovered,
            TlsLimits.Default,
            CreateOffer(3));
        Assert.Equal(2, parsed.Certificates.Count);
        Assert.Equal(pki.Leaf.RawData, parsed.Leaf.RawData);
    }

    [Fact]
    public void ZstdBombIsBoundedByTheDeclaredUncompressedLength()
    {
        const int declared = 1024;
        const int expansion = 64 * 1024 * 1024;
        var message = Encode(3, declared, CompressZeros(expansion));
        Assert.True(
            message.Length < 64 * 1024,
            $"Bomb seed must stay small to be a bomb; was {message.Length} bytes.");

        // Run once to warm the JIT and the cached offer, then measure only the second run so
        // the delta is the decompression path itself: a 64 MiB expansion hiding behind a
        // 1 KiB declaration must never materialise.
        var offer = CreateOffer(3);
        _ = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(message, offer, TlsLimits.Default));
        var before = GC.GetAllocatedBytesForCurrentThread();
        var exception = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(message, offer, TlsLimits.Default));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(TlsAlertDescription.BadCertificate, exception.Alert);
        // Anti-vacuity: proves the bomb reached the zstd decompressor and was stopped by it,
        // rather than being turned away by one of the structural pre-checks ahead of it.
        Assert.IsType<ZstdSharp.ZstdException>(exception.InnerException);
        Assert.True(
            allocated < 1024 * 1024,
            $"zstd decompression allocated {allocated} bytes for a {declared}-byte declaration.");
    }

    [Fact]
    public void ZstdBombWithAnHonestHeaderStillCannotExceedTheHandshakeLimit()
    {
        // uncompressed_length is range-checked against MaxHandshakeMessageSize before any
        // decompressor is constructed, so an honest 64 MiB frame is rejected structurally.
        var limits = TlsLimits.Default;
        var writer = new TlsBinaryWriter();
        writer.WriteUInt16(3);
        writer.WriteUInt24(limits.MaxHandshakeMessageSize + 1);
        writer.WriteVector24(CompressZeros(64 * 1024 * 1024));

        var exception = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(writer.WrittenSpan, CreateOffer(3), limits));

        Assert.Equal(TlsAlertDescription.BadCertificate, exception.Alert);
        Assert.Contains("invalid uncompressed length", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(new byte[] { 0x28, 0xB5, 0x2F, 0xFD })]
    [InlineData(new byte[] { 0x28, 0xB5, 0x2F, 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF })]
    [InlineData(new byte[] { 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF })]
    [InlineData(new byte[] { 0x50, 0x2A, 0x4D, 0x18, 0x04, 0x00, 0x00, 0x00, 1, 2, 3, 4 })]
    public void MalformedZstdFailsAsBadCertificateAndNeverEscapes(byte[] payload)
    {
        var exception = Record.Exception(() => CompressedCertificateParser.Decompress(
            Encode(3, 256, payload),
            CreateOffer(3),
            TlsLimits.Default));

        var protocolException = Assert.IsType<TlsProtocolException>(exception);
        Assert.Equal(TlsAlertDescription.BadCertificate, protocolException.Alert);
    }

    [Fact]
    public void TruncatedZstdFrameFailsAsBadCertificateAndNeverEscapes()
    {
        var body = Enumerable.Range(0, 4_096).Select(index => (byte)index).ToArray();
        var frame = Compress(body, 3);
        for (var length = 1; length < frame.Length; length++)
        {
            var exception = Record.Exception(() => CompressedCertificateParser.Decompress(
                Encode(3, body.Length, frame[..length]),
                CreateOffer(3),
                TlsLimits.Default));

            var protocolException = Assert.IsType<TlsProtocolException>(exception);
            Assert.Equal(TlsAlertDescription.BadCertificate, protocolException.Alert);
        }
    }

    [Fact]
    public void BitFlippedZstdFramesNeverEscapeAsAnUnmappedException()
    {
        var body = Enumerable.Range(0, 2_048).Select(index => (byte)(index * 7)).ToArray();
        var frame = Compress(body, 3);
        var rejected = 0;
        for (var index = 0; index < frame.Length; index++)
        {
            var mutated = (byte[])frame.Clone();
            mutated[index] ^= 0xFF;
            var exception = Record.Exception(() => CompressedCertificateParser.Decompress(
                Encode(3, body.Length, mutated),
                CreateOffer(3),
                TlsLimits.Default));

            if (exception is null)
            {
                continue; // A flip that still decodes to the exact same body is legitimate.
            }
            var protocolException = Assert.IsType<TlsProtocolException>(exception);
            Assert.Equal(TlsAlertDescription.BadCertificate, protocolException.Alert);
            rejected++;
        }

        // Most flips land in zstd's raw-literal section and simply yield different bytes of the
        // same declared length, which is not a protocol error. The property under test is that
        // no flip escapes as an unmapped exception; the count guards against vacuity by proving
        // the rejection path is reached at all.
        Assert.True(rejected > 0, "No bit flip reached a rejection path.");
    }

    [Fact]
    public void OfferedButUnimplementedAlgorithmIsRejectedRatherThanDecompressed()
    {
        var body = Enumerable.Repeat((byte)9, 512).ToArray();
        var message = Encode(4, body.Length, Compress(body, 3));

        var exception = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(
                message,
                CreateOffer(4),
                TlsLimits.Default));

        Assert.Equal(TlsAlertDescription.BadCertificate, exception.Alert);
        Assert.Contains("no managed decompressor", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ZstdIsRejectedWhenTheProfileDidNotOfferIt()
    {
        var body = Enumerable.Repeat((byte)3, 512).ToArray();
        var message = Encode(3, body.Length, Compress(body, 3));

        var exception = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(
                message,
                CreateOffer(2),
                TlsLimits.Default));

        Assert.Equal(TlsAlertDescription.BadCertificate, exception.Alert);
        Assert.Contains("unoffered", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryShippedProfileOnlyAdvertisesAlgorithmsThisClientCanDecompress()
    {
        var profiles = typeof(ClientHelloProfiles)
            .GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(property => property.PropertyType == typeof(ClientHelloProfile))
            .ToArray();
        Assert.NotEmpty(profiles);

        var advertised = new SortedSet<ushort>();
        var offenders = new List<string>();
        foreach (var property in profiles)
        {
            var profile = (ClientHelloProfile)property.GetValue(null)!;
            foreach (var extension in profile.Spec.SnapshotConfiguration().ExtensionLayout)
            {
                if (extension.RawExtensionType != 27)
                {
                    continue;
                }
                var encoded = new TlsBinaryReader(
                    new TlsBinaryReader(extension.RawData).ReadVector8());
                while (!encoded.End)
                {
                    var algorithm = encoded.ReadUInt16();
                    advertised.Add(algorithm);
                    var body = Enumerable.Repeat((byte)0x5A, 512).ToArray();
                    var message = Encode(
                        algorithm,
                        body.Length,
                        Compress(body, algorithm switch { 1 => 1, 2 => 2, _ => 3 }));
                    var exception = Record.Exception(() =>
                        CompressedCertificateParser.Decompress(
                            message,
                            profile.Spec.SnapshotConfiguration(),
                            TlsLimits.Default));
                    if (exception is not null)
                    {
                        offenders.Add($"{property.Name} advertises {algorithm}: {exception.Message}");
                    }
                }
            }
        }

        Assert.Empty(offenders);

        // Guards the test itself against a vacuous pass. The shipped catalogue is one profile
        // advertising zlib alone, so zstd is no longer reachable through it — exercise all
        // three algorithms explicitly instead, which is what this assertion always meant.
        Assert.NotEmpty(advertised);
        var everyAlgorithm = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.X25519)
            .WithAlpn("h2", "http/1.1")
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PskKeyExchangeModes),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.Raw(27, [0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03])));
        foreach (ushort algorithm in (ushort[])[1, 2, 3])
        {
            var body = Enumerable.Repeat((byte)0x5A, 512).ToArray();
            var message = Encode(algorithm, body.Length, Compress(body, algorithm));
            CompressedCertificateParser.Decompress(
                message,
                everyAlgorithm.Spec.SnapshotConfiguration(),
                TlsLimits.Default);
        }
    }

    /// <summary>
    /// Regression for a brotli escape found by the certificates fuzz target once its offer was
    /// widened past zlib: <see cref="BrotliStream"/> reports corrupt input as a bare
    /// <see cref="InvalidOperationException"/> ("Decoder ran into invalid data."), which the
    /// original <c>InvalidDataException or IOException</c> filter did not catch, so a hostile
    /// server could drive an unhandled exception out of the client's certificate path.
    /// </summary>
    [Fact]
    public void CorruptBrotliDecoderStateFailsAsBadCertificateAndNeverEscapes()
    {
        var message = Convert.FromBase64String(
            "AAIAAY8AAVIbjgGAZhAPrSY4E+hLeOP8GhhuHnzQ8Rrx/MluHdBs5xFFtMdr3NRBEFwIwTkgA87A" +
            "qUAbisAIQp2s+1xM+1ma9lg/YcbNpdf3RneuoIAQF18wR+9EGUMRQCdOA6hwUWsMJSb2iU5IEPUP" +
            "8a4ArHQkEjJAVlxOKi0lLeNAkETp4CLZlxnvviDwo1cojIdqQBhJSkpNdB4SUvCinsCY8IVTyL+H" +
            "cM/3/itQA479tRYOAye5029fCg/d0y4ajcXYG99IaLuGMCVnTVRcez6U1xt+2mkJzAELLmrNQorR" +
            "YtT3SSN+Etu839j0jP+cmP/xvPWOrTpgaydwYfSANi2AzFDB8H8MB6DJuTGF6kJAC2Gn2Rej+bVN" +
            "3iPq0K/pLrhvWb5BRRfGg6cA/kkt+e7JPrGA02/RsjtJ801tJqzrrOWA1qdqSutX3AN2Vl+ftEaR" +
            "zmUIAg==");
        Assert.Equal(2, (message[0] << 8) | message[1]);

        var exception = Record.Exception(() => CompressedCertificateParser.Decompress(
            message,
            CreateOffer(2),
            TlsLimits.Default));

        var protocolException = Assert.IsType<TlsProtocolException>(exception);
        Assert.Equal(TlsAlertDescription.BadCertificate, protocolException.Alert);
        Assert.IsType<InvalidOperationException>(protocolException.InnerException);
    }

    /// <summary>
    /// docs/THREAT-MODEL.md TM-15 was amended to say the runtime package carries exactly one
    /// third-party dependency, exact-version pinned. Neither half of that claim is observable
    /// from runtime behaviour, so it is asserted against the project file directly: without
    /// this, a floated version range or a second dependency would silently make the threat
    /// model false again.
    /// </summary>
    [Fact]
    public void RuntimeProjectDeclaresOnlyTheExactPinnedZstdDependency()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "SharpTls.slnx")))
        {
            directory = directory.Parent;
        }
        Assert.NotNull(directory);
        var project = Path.Combine(directory!.FullName, "src", "SharpTls", "SharpTls.csproj");
        Assert.True(File.Exists(project), $"Runtime project not found at {project}.");

        var references = System.Text.RegularExpressions.Regex
            .Matches(
                File.ReadAllText(project),
                "<PackageReference\\s+Include=\"(?<id>[^\"]+)\"\\s+Version=\"(?<version>[^\"]+)\"")
            .Select(match => (Id: match.Groups["id"].Value, Version: match.Groups["version"].Value))
            .ToArray();

        var single = Assert.Single(references);
        Assert.Equal("ZstdSharp.Port", single.Id);
        Assert.StartsWith("[", single.Version, StringComparison.Ordinal);
        Assert.EndsWith("]", single.Version, StringComparison.Ordinal);
    }

    private static ClientHelloConfiguration CreateOffer(ushort algorithm) =>
        ClientHelloProfiles.Custom(builder => builder.WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.Raw(27, [2, (byte)(algorithm >> 8), (byte)algorithm])))
        .Spec
        .SnapshotConfiguration();

    private static byte[] Encode(ushort algorithm, int uncompressedLength, byte[] compressed)
    {
        var writer = new TlsBinaryWriter();
        writer.WriteUInt16(algorithm);
        writer.WriteUInt24(uncompressedLength);
        writer.WriteVector24(compressed);
        return writer.ToArray();
    }

    private static byte[] CompressZeros(int length)
    {
        var chunk = new byte[64 * 1024];
        using var output = new MemoryStream();
        using (var compressor = new ZstdSharp.CompressionStream(output, level: 1, leaveOpen: true))
        {
            for (var written = 0; written < length; written += chunk.Length)
            {
                compressor.Write(chunk, 0, Math.Min(chunk.Length, length - written));
            }
        }
        return output.ToArray();
    }

    private static byte[] Compress(byte[] value, ushort algorithm)
    {
        using var output = new MemoryStream();
        using (Stream compressor = algorithm switch
        {
            1 => new ZLibStream(output, CompressionLevel.SmallestSize, leaveOpen: true),
            2 => new BrotliStream(output, CompressionLevel.SmallestSize, leaveOpen: true),
            3 => new ZstdSharp.CompressionStream(output, level: 19, leaveOpen: true),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        })
        {
            compressor.Write(value);
        }
        return output.ToArray();
    }
}
