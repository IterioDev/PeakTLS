using SharpTls;
using SharpTls.Protocol;

namespace SharpTls.Tests;

/// <summary>
/// Profiles that exist only to give a test a ClientHello to send. The shipped catalogue is one
/// captured profile, so a test that needs a broad TLS 1.2-capable offer has to build its own
/// rather than borrow an impersonation profile that no longer exists.
/// </summary>
/// <remarks>Nothing here claims to look like any real client. If a test asserts a fingerprint,
/// it must pin its own bytes rather than reach for these.</remarks>
internal static class TestClientHelloProfiles
{
    /// <summary>
    /// A deliberately broad TLS 1.3 offer: the common suites and curves, ALPN for the TCP
    /// versions. Used by interop and parser tests that need a peer to have something to
    /// negotiate, not by anything that checks a fingerprint. TLS 1.2 is deliberately not
    /// offered.
    /// </summary>
    internal static ClientHelloProfile Interop { get; } = ClientHelloProfiles.Custom(builder =>
        builder
            .WithTls13()
            .WithCipherSuites(
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsAes256GcmSha384,
                TlsCipherSuite.TlsChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256,
                TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384,
                TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
                TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384,
                TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsEcdheEcdsaWithAes128CbcSha,
                TlsCipherSuite.TlsEcdheEcdsaWithAes256CbcSha,
                TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha,
                TlsCipherSuite.TlsEcdheRsaWithAes256CbcSha)
            .WithSupportedGroups(
                NamedGroup.X25519,
                NamedGroup.Secp256r1,
                NamedGroup.Secp384r1,
                NamedGroup.Secp521r1)
            .WithKeyShares(NamedGroup.X25519)
            .WithSignatureAlgorithms(
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.RsaPssRsaeSha256,
                SignatureScheme.RsaPkcs1Sha256,
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.RsaPssRsaeSha384,
                SignatureScheme.RsaPkcs1Sha384,
                SignatureScheme.RsaPssRsaeSha512,
                SignatureScheme.RsaPkcs1Sha512,
                SignatureScheme.RsaPkcs1Sha1)
            .WithAlpn("h2", "http/1.1")

            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(23, []),                            // EMS
                ClientHelloExtensionSpec.Raw(65281, [0x00]),                     // renegotiation
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.Raw(11, [0x01, 0x00]),                  // ec_point_formats
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
                ClientHelloExtensionSpec.Raw(5, [0x01, 0x00, 0x00, 0x00, 0x00]), // status_request
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.Raw(18, []),                            // SCT
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PskKeyExchangeModes),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions)));

    /// <summary>
    /// Carries a profile-bound GREASE Encrypted ClientHello. The removed uTLS transcriptions
    /// used to be the only profiles that did, so the snapshot path needs its own now.
    /// </summary>
    internal static ClientHelloProfile GreaseEch { get; } = ClientHelloProfiles.Custom(builder =>
        builder
            .WithTls13()
            .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.X25519)
            .WithGreaseEncryptedClientHello(223));
}
