using System.Net;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>The MASQUE-first binding of a sticky session shared by a TCP proxy and a MASQUE
/// proxy: when it applies, that it runs once, and that a failed binding never blocks TCP. And
/// the session's one outer MASQUE connection: shared by every dial, replaced once it has ended,
/// disposed with the binding; and the memory of an exit that proved unable to carry UDP.</summary>
public sealed class MasqueSessionBindingTests
{
    private const string User = "customer-acct-cc-us-sessid-123456-sesstime-10";

    /// <summary>An outer connection that does nothing but report whether it has ended.</summary>
    private sealed class FakeOuter : ITlsQuicMasqueConnection
    {
        public bool IsClosed { get; set; }

        public int TunnelsRequested => 0;

        public bool Disposed { get; private set; }

        public Task<TlsQuicMasqueTransport> OpenTunnelAsync(
            string targetHost, int targetPort, IPEndPoint targetEndPoint, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }

    [Fact]
    public async Task EveryDialOnOneSessionSharesOneOuterConnection()
    {
        var dialled = 0;
        var binding = new MasqueSessionBinding
        {
            Dialer = (_, _, _) => { dialled++; return Task.FromResult<ITlsQuicMasqueConnection>(new FakeOuter()); },
        };
        var configuration = Configuration();
        var masque = configuration.Quic.Proxy!;

        var first = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);
        var second = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);

        Assert.Same(first, second);
        Assert.Equal(1, dialled);
    }

    [Fact]
    public async Task AnOuterThatHasEndedIsReplacedByTheNextDial()
    {
        var dialled = 0;
        var binding = new MasqueSessionBinding
        {
            Dialer = (_, _, _) => { dialled++; return Task.FromResult<ITlsQuicMasqueConnection>(new FakeOuter()); },
        };
        var configuration = Configuration();
        var masque = configuration.Quic.Proxy!;

        var first = (FakeOuter)await binding.GetOuterAsync(masque, configuration, CancellationToken.None);
        first.IsClosed = true;
        var second = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);

        Assert.NotSame(first, second);
        Assert.Equal(2, dialled);
        Assert.True(first.Disposed);
    }

    [Fact]
    public async Task AFailedOuterDialIsReportedAndNotKept()
    {
        var dialled = 0;
        var binding = new MasqueSessionBinding
        {
            Dialer = (_, _, _) =>
            {
                dialled++;
                return dialled == 1
                    ? Task.FromException<ITlsQuicMasqueConnection>(new IOException("front silent"))
                    : Task.FromResult<ITlsQuicMasqueConnection>(new FakeOuter());
            },
        };
        var configuration = Configuration();
        var masque = configuration.Quic.Proxy!;

        await Assert.ThrowsAsync<IOException>(async () =>
            await binding.GetOuterAsync(masque, configuration, CancellationToken.None));
        var outer = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);

        Assert.IsType<FakeOuter>(outer);
        Assert.Equal(2, dialled);
    }

    [Fact]
    public async Task ConcurrentDialsShareOneOuterDialInFlight()
    {
        var dialled = 0;
        var release = new TaskCompletionSource<ITlsQuicMasqueConnection>();
        var binding = new MasqueSessionBinding
        {
            Dialer = (_, _, _) => { Interlocked.Increment(ref dialled); return release.Task; },
        };
        var configuration = Configuration();
        var masque = configuration.Quic.Proxy!;

        var first = binding.GetOuterAsync(masque, configuration, CancellationToken.None).AsTask();
        var second = binding.GetOuterAsync(masque, configuration, CancellationToken.None).AsTask();
        release.SetResult(new FakeOuter());
        var outers = await Task.WhenAll(first, second);

        Assert.Same(outers[0], outers[1]);
        Assert.Equal(1, dialled);
    }

    [Fact]
    public async Task DisposingTheBindingDisposesEveryOuter()
    {
        var binding = new MasqueSessionBinding
        {
            Dialer = (_, _, _) => Task.FromResult<ITlsQuicMasqueConnection>(new FakeOuter()),
        };
        var one = Configuration();
        var other = Configuration(masqueUser: "customer-acct-cc-us-sessid-999-sesstime-10");
        var first = (FakeOuter)await binding.GetOuterAsync(one.Quic.Proxy!, one, CancellationToken.None);
        var second = (FakeOuter)await binding.GetOuterAsync(other.Quic.Proxy!, other, CancellationToken.None);

        await binding.DisposeAsync();

        Assert.True(first.Disposed);
        Assert.True(second.Disposed);
    }

    [Fact]
    public async Task AnExitThatProvedUnableToCarryUdpIsRememberedPerSession()
    {
        var binding = new MasqueSessionBinding
        {
            Dialer = (_, _, _) => Task.FromResult<ITlsQuicMasqueConnection>(new FakeOuter()),
        };
        var configuration = Configuration();
        var masque = configuration.Quic.Proxy!;
        var proof = new TlsQuicProxyException(
            TlsQuicProxyError.MasqueExitSilent, "2 datagram(s) went in and nothing came back.");

        Assert.Null(binding.RememberedFailure(masque));
        binding.Remember(masque, proof);

        var remembered = binding.RememberedFailure(masque);
        Assert.NotNull(remembered);
        Assert.Equal(TlsQuicProxyError.MasqueExitSilent, remembered.Error);
        Assert.Contains("nothing came back", remembered.Message);
        Assert.Contains("remembered", remembered.Message);

        // Another session on the same TlsSession is judged on its own.
        var other = Configuration(masqueUser: "customer-acct-cc-us-sessid-999-sesstime-10");
        Assert.Null(binding.RememberedFailure(other.Quic.Proxy!));

        // The outer connection is not the problem and stays.
        var outer = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);
        Assert.False(outer.IsClosed);
    }

    [Theory]
    [InlineData(3UL, 0UL, false, true)]     // datagrams in, nothing back, outer alive: the exit
    [InlineData(3UL, 1UL, false, false)]    // something came back: the path works
    [InlineData(0UL, 0UL, false, false)]    // nothing went in: not the exit's silence
    [InlineData(3UL, 0UL, true, false)]     // the outer itself ended: not the exit
    public void OnlyDatagramsInWithNothingBackOnALiveOuterConvictsTheExit(
        ulong sent, ulong received, bool outerClosed, bool convicted)
    {
        var verdict = MasqueSessionBinding.JudgeSilence(
            new HttpRequestException("The HTTP/3 (QUIC) handshake with 'spclient.example' did not complete within 00:00:05."),
            "spclient.example",
            sent,
            received,
            outerClosed);

        if (!convicted)
        {
            Assert.Null(verdict);
            return;
        }
        Assert.NotNull(verdict);
        Assert.Equal(TlsQuicProxyError.MasqueExitSilent, verdict.Error);
        Assert.Contains("3 datagram(s)", verdict.Message);
        Assert.Contains("fresh proxy session", verdict.Message);
    }

    // A live run of 2026-09-29, 200 sessions in lockstep: an inner handshake that ran out of
    // its deadline with the server's acknowledgements arriving and its flight not, and the same
    // dial succeeding on a fresh tunnel seconds later. Nothing of the request has been sent
    // when a handshake fails, so a fresh tunnel is safe for every method; a session-level
    // retry only covers idempotent ones.
    [Theory]
    [InlineData(true, 2UL, 1, 3, true)]     // a deadline, something came back, attempts left
    [InlineData(true, 2UL, 3, 3, false)]    // the last attempt reports
    [InlineData(true, 0UL, 1, 3, false)]    // nothing back is the exit's silence, not a retry
    [InlineData(false, 2UL, 1, 3, false)]   // not a deadline: a refusal the origin gave
    public void AHandshakeDeadlineWithTrafficBackIsDialledAgainOnAFreshTunnel(
        bool deadline, ulong received, int attempt, int attempts, bool again)
    {
        Exception failure = deadline
            ? new HttpRequestException(
                "The HTTP/3 (QUIC) handshake with 'login5.example' failed.",
                new TimeoutException("The QUIC handshake did not confirm within 00:00:05."))
            : new HttpRequestException("The peer did not select ALPN 'h3'.");

        Assert.Equal(again, MasqueSessionBinding.ShouldDialAgain(failure, received, attempt, attempts));
    }

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
