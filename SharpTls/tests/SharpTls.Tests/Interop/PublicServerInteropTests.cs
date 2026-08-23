using System.Text;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Protocol;
using SharpTls.Tests.ClientHello;

namespace SharpTls.Tests.Interop;

[Collection(nameof(PublicInteropCollection))]
public sealed class PublicServerInteropTests
{
    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task Aes128P256HandshakeAndHttp11()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)));
        await using (client)
        {
            Assert.Equal(TlsCipherSuite.TlsAes128GcmSha256, client.NegotiatedCipherSuite);
            Assert.Equal(NamedGroup.Secp256r1, client.NegotiatedGroup);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task Aes256P384HandshakeAndHttp11()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes256GcmSha384)
            .WithSupportedGroups(NamedGroup.Secp384r1)));
        await using (client)
        {
            Assert.Equal(TlsCipherSuite.TlsAes256GcmSha384, client.NegotiatedCipherSuite);
            Assert.Equal(NamedGroup.Secp384r1, client.NegotiatedGroup);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task Aes128X25519HandshakeAndHttp11()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.X25519)));
        await using (client)
        {
            Assert.Equal(TlsCipherSuite.TlsAes128GcmSha256, client.NegotiatedCipherSuite);
            Assert.Equal(NamedGroup.X25519, client.NegotiatedGroup);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task Aes128P521HandshakeAndHttp11()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp521r1)));
        await using (client)
        {
            Assert.Equal(TlsCipherSuite.TlsAes128GcmSha256, client.NegotiatedCipherSuite);
            Assert.Equal(NamedGroup.Secp521r1, client.NegotiatedGroup);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact(requiresChaCha: true)]
    [Trait("Category", "Interop")]
    public async Task ChaCha20P256HandshakeAndHttp11()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsChaCha20Poly1305Sha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)));
        await using (client)
        {
            Assert.Equal(TlsCipherSuite.TlsChaCha20Poly1305Sha256, client.NegotiatedCipherSuite);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task EmptyKeyShareForcesHelloRetryRequest()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares()));
        await using (client)
        {
            Assert.True(client.HandshakeUsedHelloRetryRequest);
            Assert.Equal(NamedGroup.Secp256r1, client.NegotiatedGroup);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task IndependentGoogleEndpointCompletesHttp11()
    {
        const string host = "www.google.com";
        var client = await ConnectAsync(
            ClientHelloProfiles.Custom(builder => builder.WithAlpn("http/1.1")),
            host);
        await using (client)
        {
            Assert.Equal("http/1.1", client.NegotiatedApplicationProtocol);
            await AssertHttpResponseAsync(client, host);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task PrivateUseRawExtensionIsIgnoredByPublicServer()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(0xFDE8, [1, 3, 3, 7]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare))));
        await using (client)
        {
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task CallerOwnedTransportAndStreamCompleteHttp11()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync("example.com", 443, timeout.Token);
        await using var transport = new NetworkStream(socket, ownsSocket: false);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.Custom(builder => builder.WithAlpn("http/1.1")),
        });

        await client.AuthenticateAsync(
            transport,
            "example.com",
            leaveOpen: true,
            timeout.Token);
        await using var stream = client.OpenApplicationStream(leaveClientOpen: true);
        await stream.WriteAsync(
            "HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"u8.ToArray(),
            timeout.Token);
        var response = new byte[128];
        var read = await stream.ReadAsync(response, timeout.Token);

        Assert.True(read > 0);
        Assert.StartsWith(
            "HTTP/1.1 ",
            Encoding.ASCII.GetString(response, 0, read),
            StringComparison.Ordinal);
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task ClientAndRequestedServerKeyUpdatePreserveHttp11Traffic()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder =>
            builder.WithAlpn("http/1.1")));
        await using (client)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var beforeUpdate = client.ExportKeyingMaterial(
                "EXPORTER-SharpTls-interop",
                "example.com"u8,
                32);
            await client.RequestKeyUpdateAsync(requestPeerUpdate: true, timeout.Token);
            await AssertHttpResponseAsync(client);

            Assert.Equal(1UL, client.ClientKeyUpdateCount);
            Assert.True(client.ServerKeyUpdateCount >= 1UL);
            Assert.Equal(
                beforeUpdate,
                client.ExportKeyingMaterial(
                    "EXPORTER-SharpTls-interop",
                    "example.com"u8,
                    32));
            CryptographicOperations.ZeroMemory(beforeUpdate);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task SessionTicketResumesASecondAuthenticatedConnection()
    {
        using var cache = new Tls13SessionCache();
        await using (var first = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            sessionCache: cache))
        {
            Assert.False(first.SessionWasResumed);
            await AssertHttpResponseAsync(first);
            Assert.True(cache.Count > 0);
        }

        await using var second = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            sessionCache: cache);
        Assert.True(second.SessionWasResumed);
        await AssertHttpResponseAsync(second);
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task SessionTicketResumptionSurvivesHelloRetryRequest()
    {
        using var cache = new Tls13SessionCache();
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares()
            .WithSessionResumption());

        await using (var first = await ConnectAsync(profile, sessionCache: cache))
        {
            Assert.True(first.HandshakeUsedHelloRetryRequest);
            await AssertHttpResponseAsync(first);
            Assert.True(cache.Count > 0);
        }

        await using var second = await ConnectAsync(profile, sessionCache: cache);
        Assert.True(second.HandshakeUsedHelloRetryRequest);
        Assert.True(second.SessionWasResumed);
        await AssertHttpResponseAsync(second);
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task SessionTicketResumesAtIndependentGoogleEndpoint()
    {
        const string host = "www.google.com";
        using var cache = new Tls13SessionCache();
        await using (var first = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            host,
            sessionCache: cache))
        {
            await AssertHttpResponseAsync(first, host);
            Assert.True(cache.Count > 0);
        }

        await using var second = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            host,
            sessionCache: cache);
        Assert.True(second.SessionWasResumed);
        await AssertHttpResponseAsync(second, host);
    }

    [InteropFact(requiresEarlyDataEndpoint: true)]
    [Trait("Category", "Interop")]
    public async Task ReplayAcknowledgedEarlyHttpRequestIsAccepted()
    {
        var host = Environment.GetEnvironmentVariable("SHARPTLS_EARLY_DATA_HOST")!;
        using var cache = new Tls13SessionCache();
        await using (var first = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            host,
            sessionCache: cache,
            disableRevocationForEndpoint: true))
        {
            await AssertHttpResponseAsync(first, host);
            Assert.True(cache.Count > 0);
        }

        var request = Encoding.ASCII.GetBytes(
            $"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        var earlyData = new Tls13EarlyDataOptions(
            request,
            acknowledgeReplayRisk: true,
            Tls13EarlyDataRejectionPolicy.RetransmitAfterHandshake);
        await using var second = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            host,
            sessionCache: cache,
            earlyData: earlyData,
            disableRevocationForEndpoint: true);

        Assert.Equal(Tls13EarlyDataStatus.Accepted, second.EarlyDataStatus);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var response = await second.ReadApplicationDataAsync(timeout.Token);
        Assert.NotNull(response);
        Assert.StartsWith(
            "HTTP/1.1 ",
            Encoding.ASCII.GetString(response),
            StringComparison.Ordinal);
    }

    private static async Task<CustomTlsClient> ConnectAsync(
        ClientHelloProfile profile,
        string host = "example.com",
        int port = 443,
        Tls13SessionCache? sessionCache = null,
        Tls13EarlyDataOptions? earlyData = null,
        bool disableRevocationForEndpoint = false)
    {
        var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = host,
            ClientHello = profile,
            SessionCache = sessionCache,
            EarlyData = earlyData,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                // Cloudflare's test endpoint does not always expose a reachable
                // revocation responder. Keep this exception local to the smoke test.
                RevocationMode = disableRevocationForEndpoint
                    ? X509RevocationMode.NoCheck
                    : X509RevocationMode.Online,
            },
        });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await client.ConnectAsync(host, port, timeout.Token);
        return client;
    }

    private static async Task AssertHttpResponseAsync(
        CustomTlsClient client,
        string host = "example.com")
    {
        var request = Encoding.ASCII.GetBytes(
            $"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await client.WriteApplicationDataAsync(request, timeout.Token);
        var first = await client.ReadApplicationDataAsync(timeout.Token);
        Assert.NotNull(first);
        Assert.StartsWith("HTTP/1.1 ", Encoding.ASCII.GetString(first), StringComparison.Ordinal);
    }
}

[CollectionDefinition(nameof(PublicInteropCollection), DisableParallelization = true)]
public sealed class PublicInteropCollection;

public sealed class InteropFactAttribute : FactAttribute
{
    public InteropFactAttribute(
        bool requiresChaCha = false,
        bool requiresEarlyDataEndpoint = false)
    {
        if (!string.Equals(
            Environment.GetEnvironmentVariable("SHARPTLS_RUN_INTEROP"),
            "1",
            StringComparison.Ordinal))
        {
            Skip = "Set SHARPTLS_RUN_INTEROP=1 to enable public-network interoperability tests.";
        }
        else if (requiresChaCha && !System.Security.Cryptography.ChaCha20Poly1305.IsSupported)
        {
            Skip = "ChaCha20-Poly1305 is unavailable on this runtime.";
        }
        else if (requiresEarlyDataEndpoint && string.IsNullOrWhiteSpace(
            Environment.GetEnvironmentVariable("SHARPTLS_EARLY_DATA_HOST")))
        {
            Skip = "Set SHARPTLS_EARLY_DATA_HOST to an endpoint that advertises TLS 1.3 early data.";
        }
    }
}
