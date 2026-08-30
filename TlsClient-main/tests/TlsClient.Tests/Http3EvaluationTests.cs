using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Reflection;
using SharpTls;

namespace TlsClient.Tests;

/// <summary>
/// Guards the HTTP/3 wiring decisions. HTTP/3 is no longer rejected outright, but it is
/// reachable only through an explicit, caller-driven policy: there is no Happy Eyeballs,
/// no racing and no automatic fallback between the TCP transports and QUIC.
/// </summary>
/// <remarks>
/// <para>
/// <c>docs/HTTP3-EVALUATION.md</c> defines a seven-condition entry gate. These tests cover
/// the <em>selection and dispatch</em> half only. Conditions still unmet at the time this
/// file was written, and therefore deliberately NOT asserted green here:
/// </para>
/// <list type="bullet">
///   <item>Condition 2 — QUIC loss recovery is incomplete upstream in SharpTls; ACK/loss/PTO
///     work is in progress and retransmission is not finished.</item>
///   <item>Condition 3 — no interoperability evidence against two established QUIC stacks
///     under reordering, duplication, loss and malformed input.</item>
///   <item>Condition 5 — pooling, redirects, cookies and retries now have HTTP/3 witnesses in
///     <see cref="Http3ClientMachineryTests"/>; DNS/ECH bootstrapping, proxy policy, response
///     streaming semantics, telemetry, resumption and the 0-RTT replay policy do not.</item>
///   <item>Condition 6 — no Linux/macOS/Windows CI coverage for the HTTP/3 path.</item>
///   <item>Condition 7 — no independent security review of packet parsing, loss recovery,
///     stream state, QPACK, amplification or 0-RTT replay.</item>
/// </list>
/// <para>
/// <see cref="TlsHttpVersionPolicy.Http3Only"/> is therefore marked
/// <see cref="ExperimentalAttribute"/>, and <see cref="Http3Only_IsMarkedExperimental"/>
/// fails if that opt-in gate is ever removed while the conditions above remain open.
/// </para>
/// </remarks>
#pragma warning disable TLSCLIENT3 // These tests exist precisely to pin the experimental policy.
public sealed class Http3EvaluationTests
{
    private const string Host = "example.com";

    [Fact]
    public async Task Http3ExactRequest_PinsHttp3_InsteadOfBeingRejected()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/")
        {
            Version = HttpVersion.Version30,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };

        var buffered = await BufferedRequest.CreateAsync(
            request,
            maximumBodyBytes: 1024,
            TlsHttpVersionPolicy.PreferHttp2,
            CancellationToken.None);

        Assert.Equal(TlsHttpVersionPolicy.Http3Only, buffered.HttpVersionPolicy);
    }

    [Theory]
    [InlineData(1, 1, TlsHttpVersionPolicy.Http11Only)]
    [InlineData(2, 0, TlsHttpVersionPolicy.Http2Only)]
    [InlineData(3, 0, TlsHttpVersionPolicy.Http3Only)]
    public async Task RequestVersionExact_PinsExactlyTheRequestedTransport(
        int major,
        int minor,
        TlsHttpVersionPolicy expected)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/")
        {
            Version = new Version(major, minor),
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };

        var buffered = await BufferedRequest.CreateAsync(
            request,
            maximumBodyBytes: 1024,
            // A session policy that differs from every expectation, so a pass can only come
            // from the request pin and never from the session default leaking through.
            TlsHttpVersionPolicy.PreferHttp2,
            CancellationToken.None);

        Assert.Equal(expected, buffered.HttpVersionPolicy);
    }

    [Theory]
    [InlineData(HttpVersionPolicy.RequestVersionOrLower)]
    [InlineData(HttpVersionPolicy.RequestVersionOrHigher)]
    public async Task Http3Request_WithoutAnExactPin_LeavesTheSessionPolicyInCharge(
        HttpVersionPolicy versionPolicy)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/")
        {
            Version = HttpVersion.Version30,
            VersionPolicy = versionPolicy,
        };

        var buffered = await BufferedRequest.CreateAsync(
            request,
            maximumBodyBytes: 1024,
            TlsHttpVersionPolicy.Http2Only,
            CancellationToken.None);

        // No Happy Eyeballs: a non-exact 3.0 request is never promoted onto QUIC behind the
        // caller's back. It runs on whatever the session selected.
        Assert.Equal(TlsHttpVersionPolicy.Http2Only, buffered.HttpVersionPolicy);
    }

    [Fact]
    public async Task VersionsAboveHttp3_AreStillRejected()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/")
        {
            Version = new Version(4, 0),
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };

        var exception = await Assert.ThrowsAsync<NotSupportedException>(
            () => BufferedRequest.CreateAsync(
                request,
                maximumBodyBytes: 1024,
                TlsHttpVersionPolicy.PreferHttp2,
                CancellationToken.None).AsTask());

        Assert.Contains("HTTP/1.1, HTTP/2 and HTTP/3", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(AlpnMatrix))]
    public void Alpn_OffersH3_WhenAndOnlyWhenThePolicySelectsIt(
        TlsHttpVersionPolicy policy,
        string[] expectedAlpn)
    {
        var alpn = TlsProfiles.Modern.GetClientHello(Host, policy).Spec.AlpnProtocols;

        Assert.Equal(expectedAlpn, alpn);
        Assert.Equal(policy == TlsHttpVersionPolicy.Http3Only, alpn.Contains("h3"));
    }

    [Fact]
    public void Http3Alpn_IsNeverMixedWithTheTcpProtocols()
    {
        // A list like ["h3", "h2"] would only make sense as a fallback ladder, and TlsClient
        // does not implement one. h3 must stand alone.
        var alpn = TlsProfiles.Modern.GetClientHello(Host, TlsHttpVersionPolicy.Http3Only)
            .Spec.AlpnProtocols;

        Assert.Equal(["h3"], alpn);
    }

    [Fact]
    public void TcpTransport_RefusesAPinnedHttp3Policy_RatherThanDowngrading()
    {
        // Defence in depth for the fork in HttpConnectionFactory: even if an Http3Only policy
        // reached the TCP validation path with a perfectly good h2 connection in hand, it must
        // fail loudly instead of quietly serving HTTP/2.
        foreach (var negotiated in new string?[] { "h2", "http/1.1", null })
        {
            var exception = Assert.Throws<TlsHttpProtocolException>(
                () => SharpTlsTransport.ValidateApplicationProtocol(
                    negotiated,
                    TlsHttpVersionPolicy.Http3Only));

            Assert.Contains("does not downgrade", exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Http3_ForksBeforeTheTcpConnect_AndRefusesAProxiedRequest()
    {
        // TlsClient proxies are TCP CONNECT tunnels; QUIC dials UDP itself. The refusal must
        // arrive before any dial: the origin and proxy below are both closed ports, so a
        // NotSupportedException can only come from the pre-connect fork. A NotSupportedException
        // raised after SharpTlsTransport.ConnectAsync would surface as a socket failure instead.
        var configuration = new TlsSessionOptions().Snapshot();

        var exception = await Assert.ThrowsAsync<NotSupportedException>(
            () => HttpConnectionFactory.ConnectAsync(
                new Uri("https://127.0.0.1:1/"),
                TlsHttpVersionPolicy.Http3Only,
                TlsProxy.Http("http://127.0.0.1:1"),
                configuration,
                new Tls13SessionCache(),
                new DnsEndpointResolver(configuration),
                new Socks5AssociationGate(),
                CancellationToken.None).AsTask());

        Assert.Contains("HTTP/3 cannot be tunnelled", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Http3Only_IsMarkedExperimental()
    {
        // The entry gate in docs/HTTP3-EVALUATION.md is not fully met (see the class remarks).
        // Until it is, selecting HTTP/3 must require an explicit acknowledgement.
        var member = typeof(TlsHttpVersionPolicy)
            .GetField(nameof(TlsHttpVersionPolicy.Http3Only), BindingFlags.Public | BindingFlags.Static);

        Assert.NotNull(member);
        var experimental = member.GetCustomAttribute<ExperimentalAttribute>();
        Assert.NotNull(experimental);
        Assert.Equal("TLSCLIENT3", experimental.DiagnosticId);
    }

    [Fact]
    public void NoPreferringHttp3Policy_Exists()
    {
        // "Prefer HTTP/3" could only mean "try QUIC, then silently retry over TCP", which is
        // the automatic fallback this design rules out. If somebody adds such a member, this
        // test should fail and force the fallback semantics to be spelled out first.
        var names = Enum.GetNames<TlsHttpVersionPolicy>();

        Assert.Equal(
            ["PreferHttp2", "Http11Only", "Http2Only", "Http3Only"],
            names);
    }

    public static TheoryData<TlsHttpVersionPolicy, string[]> AlpnMatrix => new()
    {
        { TlsHttpVersionPolicy.PreferHttp2, ["h2", "http/1.1"] },
        { TlsHttpVersionPolicy.Http11Only, ["http/1.1"] },
        { TlsHttpVersionPolicy.Http2Only, ["h2"] },
        { TlsHttpVersionPolicy.Http3Only, ["h3"] },
    };
}
#pragma warning restore TLSCLIENT3
