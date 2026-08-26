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
    /// JA3 is <c>48d08f334704479db85d91df80039756</c>. A second image,
    /// <c>2f9431e877b01e163774ae4ae0df9ded</c>, differs in cipher order and carries no vendor
    /// transport parameter; the 80 connections above are all of that second kind. This profile
    /// ships the first; see the cipher-suite note below. JA4 is identical either way because it
    /// sorts the cipher list.
    /// </para>
    /// <para>
    /// NOT A PROXY ARTEFACT, WHICH THIS TEXT USED TO SAY. A later proxy capture of
    /// <c>login5.spotify.com</c> from the same app on iOS 26 carries the SECOND image - the
    /// "direct" cipher order and no vendor parameter - on the same path that produced the first.
    /// The two differences co-occur and the capture path does not predict them, so the profile
    /// is an iOS 27 shape and an iOS 26 client is a DIFFERENT profile, not this one seen through
    /// a different lens. The 80 connections' OS build was not recorded, so which side they
    /// belong to is inference, not measurement.
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
    /// Applies the Spotify 9.1.76.2050 iOS 27.0 QUIC ClientHello shape to a builder.
    /// </summary>
    /// <param name="builder">The builder to configure.</param>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
    /// <remarks>Public because a QUIC session configures its ClientHello through a builder
    /// callback rather than through a <see cref="ClientHelloProfile"/> — the profile above and
    /// that callback have to be the same shape, so they are the same method.</remarks>
    public static void ApplySpotify917602050IOS270QuicClientHello(ClientHelloBuilder builder) =>
        ApplySpotifyIosQuicClientHello(
            builder,
            [
                TlsCipherSuite.TlsAes256GcmSha384,
                TlsCipherSuite.TlsChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsAes128GcmSha256,
            ],
            vendorTransportParameter: true);

    /// <summary>
    /// Gets the QUIC ClientHello of the same Spotify 9.1.76.2050 build on iOS 26, iPhone17,2.
    /// Decoded from the Initial CRYPTO frames of a first-party capture to
    /// <c>login5.spotify.com</c>. JA3 <c>2f9431e877b01e163774ae4ae0df9ded</c>, JA4
    /// <c>q13d0311h3_55b375c5d22e_f2a83c8e78ae</c> — the same JA4 as
    /// <see cref="Spotify917602050IOS270Quic"/>, which sorts the cipher list and cannot see the
    /// difference.
    /// <para>
    /// TWO DIFFERENCES FROM THE iOS 27 PROFILE, AND NOTHING ELSE. The cipher order is 0x1302,
    /// 0x1301, 0x1303, and the vendor transport parameter <c>0xff080808</c> is absent — which is
    /// exactly ten bytes, so this hello is 1481 where that one is 1491 for the same server name.
    /// Extension order, the ten signature algorithms, groups, key-share sizes, status_request,
    /// compress_certificate, psk_key_exchange_modes, supported_versions and the empty
    /// legacy_session_id are byte-identical between the two.
    /// </para>
    /// <para>
    /// ONE CAPTURE, AND THE THIN PARTS ARE NAMED RATHER THAN GUESSED. The GREASE class pattern
    /// and the transport-parameter rotation are carried over from the iOS 27 measurement: a
    /// single hello cannot separate a class pattern from coincidence, and it lands on one of
    /// seven rotation offsets whatever the client does. This capture happens to show
    /// cipher_suites and supported_versions drawing the same GREASE value and the second GREASE
    /// extension drawing supported_groups', which independent draws produce about once in 256 —
    /// suspicious, not decisive. Pin it against more captures before trusting those two axes.
    /// </para>
    /// </summary>
    public static ClientHelloProfile Spotify917602050IOS260Quic { get; } =
        Custom(ApplySpotify917602050IOS260QuicClientHello);

    /// <summary>
    /// Applies the Spotify 9.1.76.2050 iOS 26 QUIC ClientHello shape to a builder.
    /// </summary>
    /// <param name="builder">The builder to configure.</param>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
    /// <remarks>Public for the same reason as the iOS 27 one: a QUIC session configures its
    /// ClientHello through a builder callback, not through a
    /// <see cref="ClientHelloProfile"/>.</remarks>
    public static void ApplySpotify917602050IOS260QuicClientHello(ClientHelloBuilder builder) =>
        ApplySpotifyIosQuicClientHello(
            builder,
            [
                TlsCipherSuite.TlsAes256GcmSha384,
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsChaCha20Poly1305Sha256,
            ],
            vendorTransportParameter: false);

    /// <summary>
    /// The shape both Spotify QUIC profiles share. ONE METHOD RATHER THAN TWO COPIES: the two
    /// captures differ in the cipher order and in whether the vendor transport parameter is
    /// present, and in nothing else — so those are the parameters, and every other field cannot
    /// drift between the profiles without drifting in both.
    /// </summary>
    private static void ApplySpotifyIosQuicClientHello(
        ClientHelloBuilder builder,
        TlsCipherSuite[] cipherSuites,
        bool vendorTransportParameter)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder
            .WithTls13()

            .WithQuicTransportParameters(new Quic.TlsQuicTransportParameters(
                SpotifyIosQuicTransportParameters(vendorTransportParameter)))

            // GREASE value classes over all 80 iOS 27 hellos: supported_groups and key_share
            // always carry the same value; cipher_suites, supported_versions and the two GREASE
            // extension slots each draw their own, agreeing only at the 1-in-16 chance rate.
            // The iOS 26 profile INHERITS this rather than measuring it — see that profile's
            // remarks for the one capture that does not fit and why one capture cannot settle it.
            .WithGrease(ClientHelloGreasePolicy.CreateWithSecondaryExtension(0, 1, 2, 2, 3, 4))
            .WithSecondaryGreaseExtension([0x00])
            .WithGreaseKeyShareBody([0x00])
            // Empty, as the capture shows. [] and not null: null means UNSPECIFIED, which the
            // encoder fills with 32 random bytes. TlsQuicClientHelloProfileFactory forces this
            // for every QUIC hello anyway; stated here so the profile matches the capture on
            // its own terms rather than relying on that.
            .WithSessionId([])
            // 0x1302, 0x1303, 0x1301 on iOS 27; 0x1302, 0x1301, 0x1303 on iOS 26 and in the 80
            // pcapng connections decrypted from Initials. The capture path does not predict which
            // one appears and the OS build does, which is why this is a parameter and not a
            // constant. The second order always travels with the vendor transport parameter being
            // ABSENT; the two never split apart, so they are one difference wearing two faces.
            // Only JA3 moves: JA4 sorts the cipher list, so both orders hash alike there.
            .WithCipherSuites(cipherSuites)
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

            // No padding extension: the client adds none, whatever the hello weighs. The length
            // is not a constant to check against — it moves with the server name and with the
            // vendor transport parameter, so the same shape is 1491 bytes to
            // login5.spotify.com on iOS 27, 1481 on iOS 26, and 1488 to the 25-character
            // gew1-spclient.spotify.com.
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

    /// <summary>
    /// The seven known transport parameters, each encoded exactly as captured — note the
    /// two-byte 0x4040 for active_connection_id_limit and the EMPTY
    /// initial_source_connection_id, which follows from a zero-length source id — optionally
    /// followed by the vendor <c>0xff080808</c> that only iOS 27 sends.
    /// <para>
    /// THE ORDER IS THE ROTATION BASE, NOT ANY ONE CAPTURE'S ORDER. The real client ships a
    /// cyclic rotation of these seven, redrawn per connection, with the vendor entry pinned
    /// last: an iOS 27 capture to login5.spotify.com reads 0x0e, 0x0f, 0x04, 0x05, 0x06, 0x07,
    /// 0x09 — offset 5 of this list, not this list. A live QUIC connection replaces these with
    /// its own per-connection set and TlsQuicTransportParameterSpec draws the offset there, so a
    /// standalone build of either profile emits offset 0 and matches one connection in seven.
    /// That is the price of a profile being complete on its own; the extension being present is
    /// also what lets it appear in the layout above.
    /// </para>
    /// <para>
    /// The vendor parameter is last in 4 of 4 iOS 27 captures, absent from all 80 of the others
    /// and absent from the iOS 26 capture — the observation that ties it to the OS build rather
    /// than to the capture path. Declared here as well as in the TlsClient preset: a live dial
    /// takes the preset's rotated list, but anything building a profile standalone reads THIS
    /// one, and the two disagreeing is how one path silently ships a different fingerprint from
    /// the other.
    /// </para>
    /// </summary>
    private static Quic.TlsQuicTransportParameter[] SpotifyIosQuicTransportParameters(
        bool vendorTransportParameter)
    {
        Quic.TlsQuicTransportParameter[] known =
        [
            new(0x04, [0x81, 0x00, 0x00, 0x00]),
            new(0x05, [0x80, 0x20, 0x00, 0x00]),
            new(0x06, [0x80, 0x20, 0x00, 0x00]),
            new(0x07, [0x80, 0x20, 0x00, 0x00]),
            new(0x09, [0x08]),
            new(0x0E, [0x40, 0x40]),
            new(0x0F, []),
        ];

        return vendorTransportParameter
            ? [.. known, new Quic.TlsQuicTransportParameter(0xFF08_0808, [0x09])]
            : known;
    }

    /// <summary>
    /// Gets the TCP ClientHello of Spotify 9.1.76.2050 on iOS 27.0, iPhone17,2 — the hello its
    /// HTTP/2 legs dial with, where <see cref="Spotify917602050IOS270Quic"/> is the QUIC one.
    /// </summary>
    /// <remarks>
    /// <para>TRANSCRIBED, NOT CAPTURED HERE, and that distinction is what this catalogue is
    /// organised around. The QUIC profile above is decoded from first-party pcapng; this one is
    /// read from a fingerprint record supplied in bogdanfinn/tls-client's JSON format, whose
    /// collection method is not recorded. Everything below is derivable from that record except
    /// where a comment says otherwise. Pin it against your own capture before trusting it.</para>
    /// <para>THIRTEEN CIPHER SUITES TO THE QUIC HELLO'S THREE, a 32-byte legacy_session_id where
    /// QUIC sends an empty one, TLS 1.2 in supported_versions, and the 1.2-era extensions RFC
    /// 9001 s8.4 forbids over QUIC — extended_master_secret, renegotiation_info and
    /// ec_point_formats. The two share a post-quantum group and the same ten signature
    /// algorithms, and little else. Do not derive one from the other.</para>
    /// <para>THE TEN 1.2 CIPHER SUITES ARE A SHAPE, NOT A CAPABILITY. SharpTls negotiates TLS
    /// 1.3 only and refuses a ServerHello selecting 1.2, so this hello offers suites it will not
    /// complete on. That is what the real client's bytes say, and the app negotiates 1.3 in
    /// practice; an endpoint answering 1.2 fails closed rather than downgrading.</para>
    /// </remarks>
    public static ClientHelloProfile Spotify917602050IOS270Tcp { get; } =
        Custom(ApplySpotify917602050IOS270TcpClientHello);

    /// <summary>Applies the Spotify 9.1.76.2050 iOS TCP ClientHello shape to a builder.</summary>
    /// <param name="builder">The builder to configure.</param>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
    public static void ApplySpotify917602050IOS270TcpClientHello(ClientHelloBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        _ = builder
            // INFERRED FROM THE QUIC CAPTURE OF THE SAME APP, NOT FROM THE RECORD. A JA3 string
            // records that a GREASE slot is present, never whether two slots drew the SAME
            // value, so the equality pattern is unmeasurable from this source. The 80-connection
            // QUIC capture of this build showed supported_groups and key_share sharing a value
            // while every other slot drew its own; one BoringSSL generator produces both hellos,
            // so that pattern is carried over. Recapture if it matters to you.
            .WithGrease(ClientHelloGreasePolicy.CreateWithSecondaryExtension(0, 1, 2, 2, 3, 4))
            .WithSecondaryGreaseExtension([0x00])
            .WithGreaseKeyShareBody([0x00])

            // NULL, NOT EMPTY: an unspecified session id is filled with 32 random bytes, which
            // is what a TCP hello carries. The QUIC hello sends [] instead, and the difference
            // is one of the things that keeps the two JA3s apart.
            .WithSessionId(null)

            // The three 1.3 suites lead, then the ten 1.2 suites in the record's order.
            .WithCipherSuites(
                TlsCipherSuite.TlsAes256GcmSha384,
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384,
                TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384,
                TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256,
                TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
                TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsEcdheEcdsaWithAes256CbcSha,
                TlsCipherSuite.TlsEcdheEcdsaWithAes128CbcSha,
                TlsCipherSuite.TlsEcdheRsaWithAes256CbcSha,
                TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha)

            .WithSupportedGroups(
                NamedGroup.X25519MlKem768,
                NamedGroup.X25519,
                NamedGroup.Secp256r1,
                NamedGroup.Secp384r1,
                NamedGroup.Secp521r1)

            // Two real shares, matching the record's keyShareCurves: the hybrid and X25519.
            .WithKeyShares(NamedGroup.X25519MlKem768, NamedGroup.X25519)

            // GREASE, 1.3, 1.2 — the 1.2 entry is why the JA3 version field reads 771.
            .WithSupportedVersions(TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls12)

            // Ten entries with 0x0805 (rsa_pss_rsae_sha384) TWICE, exactly as the QUIC hello
            // carries them. The duplicate is load-bearing: without the opt-in the encoder
            // collapses it, JA3 still matches because it does not read this list, and JA4
            // silently diverges because it does.
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

            .WithAlpn("h2", "http/1.1")

            // The record's extension order, all fifteen slots. Six have no built-in kind and go
            // out as raw bodies; the three the QUIC hello also carries use the same bytes.
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(23, []),                            // ext_master_secret
                ClientHelloExtensionSpec.Raw(65281, [0x00]),                     // renegotiation_info
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.Raw(11, [0x01, 0x00]),                  // ec_point_formats
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
                ClientHelloExtensionSpec.Raw(5, [0x01, 0x00, 0x00, 0x00, 0x00]), // status_request
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.Raw(18, []),                            // SCT
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PskKeyExchangeModes),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.Raw(27, [0x02, 0x00, 0x01]),            // zlib
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SecondaryGrease));
    }
}
