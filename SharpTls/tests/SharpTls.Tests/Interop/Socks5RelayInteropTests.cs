using System.Net;
using System.Net.Sockets;
using SharpTls.Quic;

namespace SharpTls.Tests.Interop;

// Opt-in, real-relay interoperability tests for TlsQuicSocks5Transport. Unlike
// PublicServerInteropTests, which reaches live public TLS servers, this harness is
// intended to run against a locally operated SOCKS5 UDP ASSOCIATE relay — 3proxy,
// Dante or gost are all known-good reference implementations. Point
// SHARPTLS_SOCKS5_PROXY_HOST/SHARPTLS_SOCKS5_PROXY_PORT at that relay to enable the
// no-credentials test; also set SHARPTLS_SOCKS5_USERNAME/SHARPTLS_SOCKS5_PASSWORD,
// matching a relay configured to require RFC 1929 authentication, to enable the
// credentialled test. Every test here carries [Trait("Category", "Interop")] and must
// never run in the offline suite.
[Collection(nameof(Socks5InteropCollection))]
public sealed class Socks5RelayInteropTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    [Socks5InteropFact]
    [Trait("Category", "Interop")]
    public async Task AssociationAndDatagramRoundTripSucceedWithoutCredentials()
    {
        await RunRoundTripAsync(useCredentials: false);
    }

    [Socks5InteropFact(requiresCredentials: true)]
    [Trait("Category", "Interop")]
    public async Task AssociationAndDatagramRoundTripSucceedWithCredentials()
    {
        await RunRoundTripAsync(useCredentials: true);
    }

    private static async Task RunRoundTripAsync(bool useCredentials)
    {
        var options = new TlsQuicSocks5Options
        {
            ProxyEndPoint = new DnsEndPoint(Socks5InteropFactAttribute.ProxyHost!, Socks5InteropFactAttribute.ProxyPort),
            Username = useCredentials ? Socks5InteropFactAttribute.Username : null,
            Password = useCredentials ? Socks5InteropFactAttribute.Password : null,
        };

        using var timeout = new CancellationTokenSource(Timeout);

        // Association: a completed UDP ASSOCIATE against the real relay, including the
        // RFC 1929 subnegotiation when credentials are supplied.
        await using var transport = await TlsQuicSocks5Transport.ConnectAsync(options, timeout.Token);

        // Datagram round trip: an ordinary local UDP peer stands in for the QUIC origin.
        // The relay must decapsulate the outbound datagram to reach it and re-encapsulate
        // its reply, which only succeeds end-to-end against a conforming relay.
        using var origin = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        origin.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var originEndPoint = (IPEndPoint)origin.LocalEndPoint!;

        var payload = new byte[] { 1, 2, 3, 4, 5 };
        await transport.SendAsync(originEndPoint, payload, timeout.Token);

        var originBuffer = new byte[64];
        var fromRelay = await origin
            .ReceiveFromAsync(originBuffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0))
            .WaitAsync(Timeout);
        Assert.Equal(payload, originBuffer[..fromRelay.ReceivedBytes]);

        origin.SendTo(payload, fromRelay.RemoteEndPoint);

        var clientBuffer = new byte[64];
        var received = await transport.ReceiveAsync(clientBuffer, timeout.Token);
        Assert.Equal(payload, clientBuffer[..received.Length]);
    }
}

[CollectionDefinition(nameof(Socks5InteropCollection), DisableParallelization = true)]
public sealed class Socks5InteropCollection;

public sealed class Socks5InteropFactAttribute : FactAttribute
{
    public static string? ProxyHost => Environment.GetEnvironmentVariable("SHARPTLS_SOCKS5_PROXY_HOST");

    public static int ProxyPort => int.Parse(
        Environment.GetEnvironmentVariable("SHARPTLS_SOCKS5_PROXY_PORT") ?? "0");

    public static string? Username => Environment.GetEnvironmentVariable("SHARPTLS_SOCKS5_USERNAME");

    public static string? Password => Environment.GetEnvironmentVariable("SHARPTLS_SOCKS5_PASSWORD");

    public Socks5InteropFactAttribute(bool requiresCredentials = false)
    {
        if (string.IsNullOrWhiteSpace(ProxyHost) ||
            string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SHARPTLS_SOCKS5_PROXY_PORT")))
        {
            Skip = "Set SHARPTLS_SOCKS5_PROXY_HOST and SHARPTLS_SOCKS5_PROXY_PORT to enable SOCKS5 " +
                "relay interoperability tests (run against 3proxy, Dante or gost).";
        }
        else if (requiresCredentials &&
            (string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Password)))
        {
            Skip = "Set SHARPTLS_SOCKS5_USERNAME and SHARPTLS_SOCKS5_PASSWORD to enable the " +
                "credentialled SOCKS5 relay interoperability test.";
        }
    }
}
