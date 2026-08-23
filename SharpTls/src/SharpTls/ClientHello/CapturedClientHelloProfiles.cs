using SharpTls.Protocol;

namespace SharpTls;

/// <summary>
/// The shipped ClientHello catalogue: profiles taken from a first-party passive capture of a
/// real device. The uTLS transcriptions this library used to carry were removed — author your
/// own with <see cref="ClientHelloProfiles.Custom"/> and pin them against your own capture.
/// </summary>
public static partial class ClientHelloProfiles
{
    /// <summary>
    /// Gets the QUIC ClientHello of Spotify 9.1.76.2050 on iOS 27.0, iPhone17,2, as recorded
    /// on the wire. Decoded from the Initial CRYPTO frames of 80 client connections to
    /// <c>*.spotify.com</c> across two hotspot captures — no proxy, no keylog, because RFC 9001
    /// s5.2 derives Initial keys from the clear-text Destination Connection ID. JA4
    /// <c>q13d0311h3_55b375c5d22e_f2a83c8e78ae</c>, reproduced live.
    /// <para>
    /// JA3 is <c>48d08f334704479db85d91df80039756</c>, the PROXY-path image. The 80 direct
    /// connections above hash to <c>2f9431e877b01e163774ae4ae0df9ded</c> instead: same phone,
    /// same build, different cipher order and no vendor transport parameter. This profile ships
    /// the proxy values; see the cipher-suite note below. JA4 is identical either way because it
    /// sorts the cipher list.
    /// </para>
    /// <para>
    /// This is the QUIC half and differs from the same app's TCP hello in more than ALPN: three
    /// cipher suites instead of thirteen, a post-quantum group, an empty legacy_session_id, no
    /// TLS 1.2 in supported_versions, and none of the extensions RFC 9001 s8.4 forbids over
    /// QUIC. Do not derive one from the other.
    /// </para>
    /// </summary>
    public static ClientHelloProfile Spotify917602050IOS270Quic { get; } =
        Custom(ApplySpotify917602050IOS270QuicClientHello);

    /// <summary>
    /// Applies the Spotify 9.1.76.2050 iOS QUIC ClientHello shape to a builder.
    /// </summary>
    /// <param name="builder">The builder to configure.</param>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
    /// <remarks>Public because a QUIC session configures its ClientHello through a builder
    /// callback rather than through a <see cref="ClientHelloProfile"/> — the profile above and
    /// that callback have to be the same shape, so they are the same method.</remarks>
    public static void ApplySpotify917602050IOS270QuicClientHello(ClientHelloBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder
            .WithTls13()

            // The seven known parameters plus the vendor 0xff080808, exactly as captured and
            // encoded exactly as captured — note the
            // two-byte 0x4040 for active_connection_id_limit and the EMPTY
            // initial_source_connection_id, which follows from a zero-length source id.
            // A live QUIC connection replaces these with its own per-connection set; they are
            // here so this profile is complete on its own and so the extension is enabled,
            // which is what lets it appear in the layout below.
            .WithQuicTransportParameters(new Quic.TlsQuicTransportParameters(
            [
                new Quic.TlsQuicTransportParameter(0x04, [0x81, 0x00, 0x00, 0x00]),
                new Quic.TlsQuicTransportParameter(0x05, [0x80, 0x20, 0x00, 0x00]),
                new Quic.TlsQuicTransportParameter(0x06, [0x80, 0x20, 0x00, 0x00]),
                new Quic.TlsQuicTransportParameter(0x07, [0x80, 0x20, 0x00, 0x00]),
                new Quic.TlsQuicTransportParameter(0x09, [0x08]),
                new Quic.TlsQuicTransportParameter(0x0E, [0x40, 0x40]),
                new Quic.TlsQuicTransportParameter(0x0F, []),

                // Vendor parameter, last in 4 of 4 proxy captures and absent from all 80 direct
                // connections. Declared here as well as in the TlsClient preset: a live dial
                // takes the preset's rotated list, but anything building this profile standalone
                // reads THIS list, and the two disagreeing is how one path silently ships a
                // different fingerprint from the other.
                new Quic.TlsQuicTransportParameter(0xFF08_0808, [0x09]),
            ]))

            // GREASE value classes over all 80 hellos: supported_groups and key_share always
            // carry the same value; cipher_suites, supported_versions and the two GREASE
            // extension slots each draw their own, agreeing only at the 1-in-16 chance rate.
            .WithGrease(ClientHelloGreasePolicy.CreateWithSecondaryExtension(0, 1, 2, 2, 3, 4))
            .WithSecondaryGreaseExtension([0x00])
            .WithGreaseKeyShareBody([0x00])
            // Empty, as the capture shows. [] and not null: null means UNSPECIFIED, which the
            // encoder fills with 32 random bytes. TlsQuicClientHelloProfileFactory forces this
            // for every QUIC hello anyway; stated here so the profile matches the capture on
            // its own terms rather than relying on that.
            .WithSessionId([])
            // 0x1302, 0x1303, 0x1301 — the order in 4 of 4 proxy captures. The 80 pcapng
            // connections decrypted from Initials show 0x1302, 0x1301, 0x1303 instead, from the
            // same phone on the same build. The split is real and unexplained; the proxy path is
            // taken as authoritative because it is the path this library actually dials through.
            // Only JA3 moves: JA4 sorts the cipher list, so both orders hash alike there.
            .WithCipherSuites(
                TlsCipherSuite.TlsAes256GcmSha384,
                TlsCipherSuite.TlsChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(
                NamedGroup.X25519MlKem768,
                NamedGroup.X25519,
                NamedGroup.Secp256r1,
                NamedGroup.Secp384r1,
                NamedGroup.Secp521r1)

            // Two real shares, not one per group: X25519MLKEM768 at 1216 bytes and X25519 at
            // 32, behind the GREASE entry.
            .WithKeyShares(NamedGroup.X25519MlKem768, NamedGroup.X25519)

            // Ten entries, with 0x0805 (rsa_pss_rsae_sha384) twice. Byte-identical in all 80
            // captures and independently in the proxy captures' sig_hash_algs. This is the
            // Apple list MINUS ecdsa_sha1, which the TCP hello does carry.
            .AllowDuplicateSignatureAlgorithms()
            .WithSignatureAlgorithms(
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.RsaPssRsaeSha256,
                SignatureScheme.RsaPkcs1Sha256,
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.RsaPssRsaeSha384,
                SignatureScheme.RsaPssRsaeSha384,
                SignatureScheme.RsaPkcs1Sha384,
                SignatureScheme.RsaPssRsaeSha512,
                SignatureScheme.RsaPkcs1Sha512,
                SignatureScheme.RsaPkcs1Sha1)
            .WithAlpn("h3")

            // No padding extension: the hello is 1488 bytes and the client adds none.
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
                ClientHelloExtensionSpec.Raw(5, [0x01, 0x00, 0x00, 0x00, 0x00]), // status_request
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.Raw(18, []),                            // SCT
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PskKeyExchangeModes),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.QuicTransportParameters),
                ClientHelloExtensionSpec.Raw(27, [0x02, 0x00, 0x01]),            // zlib
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SecondaryGrease));
    }
}
