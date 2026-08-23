using SharpTls;

namespace TlsClient;

internal static class ClientHelloProfileRewriter
{
    public static ClientHelloProfile WithAlpn(
        ClientHelloProfile profile,
        bool includeSni,
        params string[] protocols)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(protocols);
        var spec = profile.Spec;
        var applicationSettingsProtocols = spec.ApplicationSettingsProtocols
            .Where(protocol => protocols.Contains(protocol, StringComparer.Ordinal))
            .ToArray();
        var layout = spec.Extensions
            .Where(extension => applicationSettingsProtocols.Length != 0 ||
                extension.BuiltInKind != ClientHelloExtensionKind.ApplicationSettings)
            .Where(extension => includeSni ||
                extension.BuiltInKind != ClientHelloExtensionKind.ServerName)
            .ToList();

        if (!layout.Any(extension =>
                extension.BuiltInKind == ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation))
        {
            var insertionIndex = layout.FindIndex(extension => extension.BuiltInKind is
                ClientHelloExtensionKind.Padding or ClientHelloExtensionKind.PreSharedKey);
            if (insertionIndex < 0)
            {
                insertionIndex = layout.Count;
            }

            layout.Insert(
                insertionIndex,
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation));
        }

        return ClientHelloProfiles.Custom(builder =>
        {
            builder.WithCipherSuites(spec.CipherSuites.ToArray());
            if (spec.Extensions.Any(extension =>
                    extension.BuiltInKind == ClientHelloExtensionKind.SupportedVersions))
            {
                builder.WithSupportedVersions(spec.SupportedVersions.ToArray());
            }
            else
            {
                // A spec with no supported_versions extension IS a legacy-shaped ClientHello -
                // that extension is how 1.3 is asked for. REWRITING IT IS STILL CORRECT even
                // though this client cannot negotiate 1.2, because rewriting is not connecting:
                // importing a captured legacy hello to read its JA3, diff its extension order or
                // export it again are all things a fingerprinting library exists to do, and none
                // of them opens a socket. SharpTls keeps WithLegacyTls12ClientHello for the same
                // reason - it is a shape, not a capability.
                //
                // The refusal belongs one layer out, where a socket IS opened, and lives there:
                // SharpTlsTransport.RequireTls13Only rejects this hello at connect time rather
                // than letting it advertise a fallback the handshake cannot finish.
                builder.WithLegacyTls12ClientHello();
            }

            if (spec.GreasePolicy is not null)
            {
                builder.WithGrease(spec.GreasePolicy);
            }
            if (spec.SecondaryGreaseExtensionBody is not null)
            {
                builder.WithSecondaryGreaseExtension(spec.SecondaryGreaseExtensionBody);
            }
            if (spec.FixedGreaseKeyShareBody is not null)
            {
                builder.WithGreaseKeyShareBody(spec.FixedGreaseKeyShareBody);
            }

            builder
                .WithSupportedGroups(spec.SupportedGroups.ToArray())
                .WithKeyShares(spec.KeyShareGroups.ToArray())
                .AllowDuplicateSignatureAlgorithms(spec.AllowsDuplicateSignatureAlgorithms)
                .WithSignatureAlgorithms(spec.SignatureAlgorithms.ToArray())
                .WithCertificateSignatureAlgorithms(
                    spec.CertificateSignatureAlgorithms?.ToArray())
                .WithAlpn(protocols)
                .WithSessionResumption(spec.SupportsSessionResumption)
                .WithPostHandshakeAuthentication(spec.SupportsPostHandshakeAuthentication)
                .WithRecordSizeLimit(spec.RecordSizeLimit)
                .WithDelegatedCredentials(spec.DelegatedCredentialSignatureAlgorithms?.ToArray())
                .AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity(
                    spec.AllowsUnsupportedDelegatedCredentialAlgorithmsForWireFidelity)
                .WithQuicTransportParameters(spec.QuicTransportParameters)
                .WithSni(includeSni && spec.IncludeSni)
                .WithSessionId(spec.SessionId)
                .WithExtensionShuffling(spec.ShuffleExtensions);

            if (applicationSettingsProtocols.Length != 0 &&
                spec.ApplicationSettingsCodePoint.HasValue)
            {
                builder.WithApplicationSettings(
                    spec.ApplicationSettingsCodePoint.Value,
                    applicationSettingsProtocols);
            }

            if (spec.UseBoringPadding)
            {
                builder.WithBoringPadding();
            }
            else if (spec.PaddingLength.HasValue)
            {
                builder.WithPadding(spec.PaddingLength);
            }

            if (spec.GreaseEncryptedClientHello)
            {
                builder.WithGreaseEncryptedClientHello(
                    spec.GreaseEchCipherSuites,
                    spec.GreaseEchPayloadLengths.ToArray());
            }

            builder.WithExtensionLayout(layout.ToArray());
        });
    }
}
