using System.Net;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

/// <summary>How an outer MASQUE dial finds the proxy's addresses. Measured 2026-09-29: the
/// proxy name's A records live ten seconds, a lookup on a host with a VPN adapter's resolver
/// in the way took two to four seconds, and every outer dial made one, so a burst of two
/// hundred sessions spent most of each dial's deadline resolving a name it had resolved
/// seconds before. One lookup now serves every dial in the process for a lifetime the caller
/// sets, and the dials spread over the addresses rather than all taking the first.</summary>
public sealed class TlsQuicMasqueProxyAddressTests
{
    private static TlsQuicMasqueOptions Options(
        string host,
        Func<string, CancellationToken, ValueTask<IReadOnlyList<IPAddress>>> resolver,
        TimeSpan? lifetime = null) => new()
    {
        ProxyEndPoint = new DnsEndPoint(host, 50000),
        Username = "user",
        Password = "pass",
        OuterSpec = MasqueHarness.OuterSpec(),
        OuterHttp3Spec = new TlsQuicHttp3Spec { Settings = TestHttp3Settings.DatagramCapable },
        ConfigureOuterClientHello = _ => { },
        ProxyResolver = resolver,
        ProxyAddressLifetime = lifetime ?? TimeSpan.FromMinutes(1),
    };

    private static readonly IPAddress[] Five =
    [
        IPAddress.Parse("192.0.2.1"),
        IPAddress.Parse("192.0.2.2"),
        IPAddress.Parse("192.0.2.3"),
        IPAddress.Parse("192.0.2.4"),
        IPAddress.Parse("192.0.2.5"),
    ];

    [Fact]
    public async Task OneLookupServesEveryDialWithinItsLifetime()
    {
        var lookups = 0;
        var release = new TaskCompletionSource<IReadOnlyList<IPAddress>>();
        ValueTask<IReadOnlyList<IPAddress>> Resolve(string host, CancellationToken ct)
        {
            Interlocked.Increment(ref lookups);
            return new ValueTask<IReadOnlyList<IPAddress>>(release.Task);
        }
        var options = Options("shared.proxy.test", Resolve);

        // Two hundred at once, all before the answer: one lookup in flight, shared.
        var dials = Enumerable.Range(0, 200)
            .Select(_ => TlsQuicMasqueConnection.ResolveProxyAsync(options, CancellationToken.None))
            .ToArray();
        release.SetResult(Five);
        await Task.WhenAll(dials);
        await TlsQuicMasqueConnection.ResolveProxyAsync(options, CancellationToken.None);

        Assert.Equal(1, lookups);
    }

    [Fact]
    public async Task DialsSpreadOverTheAddressesAndEachStillTriesThemAll()
    {
        var options = Options(
            "spread.proxy.test",
            (_, _) => new ValueTask<IReadOnlyList<IPAddress>>(Five));

        var firsts = new List<IPAddress>();
        for (var dial = 0; dial < 10; dial++)
        {
            var candidates = await TlsQuicMasqueConnection.ResolveProxyAsync(options, CancellationToken.None);
            Assert.Equal(Five.Order(Comparer<IPAddress>.Create((a, b) =>
                string.CompareOrdinal(a.ToString(), b.ToString()))),
                candidates.Select(c => c.Address).Order(Comparer<IPAddress>.Create((a, b) =>
                    string.CompareOrdinal(a.ToString(), b.ToString()))));
            Assert.All(candidates, candidate => Assert.Equal(50000, candidate.Port));
            firsts.Add(candidates[0].Address);
        }

        // Ten dials over five addresses: every address led twice.
        Assert.All(Five, address => Assert.Equal(2, firsts.Count(first => first.Equals(address))));
    }

    [Fact]
    public async Task ALookupPastItsLifetimeIsMadeAgain()
    {
        var lookups = 0;
        var options = Options(
            "expiring.proxy.test",
            (_, _) =>
            {
                lookups++;
                return new ValueTask<IReadOnlyList<IPAddress>>(Five);
            },
            lifetime: TimeSpan.Zero);

        await TlsQuicMasqueConnection.ResolveProxyAsync(options, CancellationToken.None);
        await TlsQuicMasqueConnection.ResolveProxyAsync(options, CancellationToken.None);

        Assert.Equal(2, lookups);
    }

    [Fact]
    public async Task AFailedLookupIsReportedAndNotKept()
    {
        var lookups = 0;
        var options = Options(
            "failing.proxy.test",
            (_, _) => ++lookups == 1
                ? ValueTask.FromException<IReadOnlyList<IPAddress>>(new IOException("resolver down"))
                : new ValueTask<IReadOnlyList<IPAddress>>(Five));

        await Assert.ThrowsAsync<IOException>(async () =>
            await TlsQuicMasqueConnection.ResolveProxyAsync(options, CancellationToken.None));
        var candidates = await TlsQuicMasqueConnection.ResolveProxyAsync(options, CancellationToken.None);

        Assert.Equal(5, candidates.Count);
        Assert.Equal(2, lookups);
    }

    [Fact]
    public async Task ANameThatResolvesToNothingIsRefusedByName()
    {
        var options = Options(
            "empty.proxy.test",
            (_, _) => new ValueTask<IReadOnlyList<IPAddress>>(Array.Empty<IPAddress>()));

        var error = await Assert.ThrowsAsync<TlsQuicProxyException>(async () =>
            await TlsQuicMasqueConnection.ResolveProxyAsync(options, CancellationToken.None));

        Assert.Equal(TlsQuicProxyError.MasqueTunnelRefused, error.Error);
        Assert.Contains("resolved to no address", error.Message);
    }

    [Fact]
    public async Task ForgettingANameMakesTheNextDialLookItUpAgain()
    {
        var lookups = 0;
        var options = Options(
            "forgotten.proxy.test",
            (_, _) =>
            {
                lookups++;
                return new ValueTask<IReadOnlyList<IPAddress>>(Five);
            });

        await TlsQuicMasqueConnection.ResolveProxyAsync(options, CancellationToken.None);
        TlsQuicMasqueConnection.ForgetProxyAddresses(options);
        await TlsQuicMasqueConnection.ResolveProxyAsync(options, CancellationToken.None);

        Assert.Equal(2, lookups);
    }
}
