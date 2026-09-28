namespace TlsClient.Tests;

/// <summary>The MASQUE-first binding of a sticky session shared by a TCP proxy and a MASQUE
/// proxy: when it applies, that it runs once, and that a failed binding never blocks TCP.</summary>
public sealed class MasqueSessionBindingTests
{
    private const string User = "customer-acct-cc-us-sessid-123456-sesstime-10";

    private static TlsSessionConfiguration Configuration(
        string? masqueUser = User, bool bind = true)
    {
        var options = new TlsSessionOptions();
        if (masqueUser is not null)
        {
            options.Quic.Proxy = TlsProxy.Masque("https://masque.example:50000", masqueUser, "p");
        }
        options.Quic.BindSessionThroughMasque = bind;
        return options.Snapshot();
    }

    private static TlsProxy Socks5(string user = User) =>
        TlsProxy.Socks5("socks5://socks.example:7777", user, "p");

    [Fact]
    public void ItAppliesOnlyWhenBothProxiesCarryTheSameUsername()
    {
        Assert.True(MasqueSessionBinding.ShouldBind(Socks5(), Configuration(), out var masque));
        Assert.Equal(TlsProxyType.Masque, masque!.Type);

        Assert.False(MasqueSessionBinding.ShouldBind(Socks5("other-session"), Configuration(), out _));
        Assert.False(MasqueSessionBinding.ShouldBind(Socks5(), Configuration(masqueUser: null), out _));
        Assert.False(MasqueSessionBinding.ShouldBind(null, Configuration(), out _));
        Assert.False(MasqueSessionBinding.ShouldBind(Socks5(), Configuration(bind: false), out _));
        Assert.False(MasqueSessionBinding.ShouldBind(
            TlsProxy.Http("http://proxy.example:8080"), Configuration(), out _));
    }

    [Fact]
    public async Task ItPrimesOncePerSessionAndNotAgainAfterAnH3Dial()
    {
        var primed = 0;
        var binding = new MasqueSessionBinding
        {
            Primer = (_, _, _, _) => { primed++; return Task.CompletedTask; },
        };
        var configuration = Configuration();
        var origin = new Uri("https://spclient.example/");

        await binding.EnsureBoundAsync(origin, Socks5(), configuration, CancellationToken.None);
        await binding.EnsureBoundAsync(origin, Socks5(), configuration, CancellationToken.None);
        Assert.Equal(1, primed);

        // Another session on the same TlsSession primes on its own.
        var other = Configuration(masqueUser: "customer-acct-cc-us-sessid-999-sesstime-10");
        await binding.EnsureBoundAsync(
            origin, Socks5("customer-acct-cc-us-sessid-999-sesstime-10"), other, CancellationToken.None);
        Assert.Equal(2, primed);

        // A session whose h3 dial already came up is bound without priming.
        var fresh = new MasqueSessionBinding { Primer = (_, _, _, _) => { primed++; return Task.CompletedTask; } };
        fresh.MarkBound(configuration.Quic.Proxy!);
        await fresh.EnsureBoundAsync(origin, Socks5(), configuration, CancellationToken.None);
        Assert.Equal(2, primed);
    }

    [Fact]
    public async Task AFailedPrimingIsRecordedAsDoneAndNeverThrown()
    {
        var primed = 0;
        var binding = new MasqueSessionBinding
        {
            Primer = (_, _, _, _) => { primed++; throw new IOException("proxy down"); },
        };
        var configuration = Configuration();
        var origin = new Uri("https://spclient.example/");

        await binding.EnsureBoundAsync(origin, Socks5(), configuration, CancellationToken.None);
        await binding.EnsureBoundAsync(origin, Socks5(), configuration, CancellationToken.None);
        Assert.Equal(1, primed);
    }

    [Fact]
    public async Task ConcurrentFirstConnectsShareOnePriming()
    {
        var primed = 0;
        var release = new TaskCompletionSource();
        var binding = new MasqueSessionBinding
        {
            Primer = async (_, _, _, _) => { Interlocked.Increment(ref primed); await release.Task; },
        };
        var configuration = Configuration();
        var origin = new Uri("https://spclient.example/");

        var first = binding.EnsureBoundAsync(origin, Socks5(), configuration, CancellationToken.None).AsTask();
        var second = binding.EnsureBoundAsync(origin, Socks5(), configuration, CancellationToken.None).AsTask();
        release.SetResult();
        await Task.WhenAll(first, second);
        Assert.Equal(1, primed);
    }
}
