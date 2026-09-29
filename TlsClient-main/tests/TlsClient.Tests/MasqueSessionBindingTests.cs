using System.Net;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>The MASQUE-first binding of a sticky session shared by a TCP proxy and a MASQUE
/// proxy: when it applies, that it runs once, and that a failed binding never blocks TCP. And
/// the session's pool of outer MASQUE connections: one live tunnel per outer by default, an idle
/// outer reused, an ended one replaced, all disposed with the binding; and the memory of an exit
/// that proved unable to carry UDP.</summary>
public sealed class MasqueSessionBindingTests
{
    private const string User = "customer-acct-cc-us-sessid-123456-sesstime-10";

    /// <summary>An outer connection that reports what a test sets.</summary>
    private sealed class FakeOuter : ITlsQuicMasqueConnection
    {
        public bool IsClosed { get; set; }

        public int TunnelsRequested => 0;

        public int TunnelCount { get; set; }

        public int DatagramsReceived => 0;

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

    private static MasqueSessionBinding Counting(Func<int> onDial) => new()
    {
        Dialer = (_, _, _) =>
        {
            onDial();
            return Task.FromResult<ITlsQuicMasqueConnection>(new FakeOuter());
        },
    };

    [Fact]
    public async Task ASequentialDialReusesAnIdleOuter()
    {
        var dialled = 0;
        var binding = Counting(() => ++dialled);
        var configuration = Configuration();
        var masque = configuration.Quic.Proxy!;

        ITlsQuicMasqueConnection first;
        using (var lease = await binding.GetOuterAsync(masque, configuration, CancellationToken.None))
        {
            first = lease.Connection;
        }
        using var second = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);

        Assert.Same(first, second.Connection);
        Assert.Equal(1, dialled);
    }

    // A live run of 2026-09-29, 100 sessions each sending 18 h3 requests at once: with every
    // tunnel of a session on one outer connection, the downloads shared one congestion window
    // at the proxy, and the outer send path, which puts datagrams before stream frames,
    // starved the next tunnel's CONNECT-UDP request behind them - 200 opens a run never
    // answered. One live tunnel per outer keeps concurrent dials apart and still reuses an
    // outer a finished dial left idle.
    [Fact]
    public async Task ConcurrentDialsEachGetAnOuterOfTheirOwn()
    {
        var dialled = 0;
        var binding = Counting(() => Interlocked.Increment(ref dialled));
        var configuration = Configuration();
        var masque = configuration.Quic.Proxy!;

        using var first = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);
        using var second = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);

        Assert.NotSame(first.Connection, second.Connection);
        Assert.Equal(2, dialled);
    }

    [Fact]
    public async Task AnOuterCarryingALiveTunnelIsNotHandedOut()
    {
        var dialled = 0;
        var binding = Counting(() => ++dialled);
        var configuration = Configuration();
        var masque = configuration.Quic.Proxy!;

        FakeOuter first;
        using (var lease = await binding.GetOuterAsync(masque, configuration, CancellationToken.None))
        {
            first = (FakeOuter)lease.Connection;
            first.TunnelCount = 1;
        }
        using var second = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);

        Assert.NotSame(first, second.Connection);
        Assert.Equal(2, dialled);
    }

    [Fact]
    public async Task ACapacityAboveOneLetsConcurrentDialsShareAnOuter()
    {
        var dialled = 0;
        var binding = Counting(() => ++dialled);
        var configuration = Configuration(tunnelsPerConnection: 2);
        var masque = configuration.Quic.Proxy!;

        using var first = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);
        using var second = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);
        using var third = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);

        Assert.Same(first.Connection, second.Connection);
        Assert.NotSame(first.Connection, third.Connection);
        Assert.Equal(2, dialled);
    }

    [Fact]
    public async Task AnOuterThatHasEndedIsReplacedAndDisposed()
    {
        var dialled = 0;
        var binding = Counting(() => ++dialled);
        var configuration = Configuration();
        var masque = configuration.Quic.Proxy!;

        FakeOuter first;
        using (var lease = await binding.GetOuterAsync(masque, configuration, CancellationToken.None))
        {
            first = (FakeOuter)lease.Connection;
        }
        first.IsClosed = true;
        using var second = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);

        Assert.NotSame(first, second.Connection);
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
        using var lease = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);

        Assert.IsType<FakeOuter>(lease.Connection);
        Assert.Equal(2, dialled);
    }

    [Fact]
    public async Task ADiscardedOuterIsDisposedAndNotHandedOutAgain()
    {
        var dialled = 0;
        var binding = Counting(() => ++dialled);
        var configuration = Configuration();
        var masque = configuration.Quic.Proxy!;

        FakeOuter first;
        using (var lease = await binding.GetOuterAsync(masque, configuration, CancellationToken.None))
        {
            first = (FakeOuter)lease.Connection;
            await binding.DiscardAsync(masque, first);
        }
        using var second = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);

        Assert.True(first.Disposed);
        Assert.NotSame(first, second.Connection);
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
        using var a = await binding.GetOuterAsync(one.Quic.Proxy!, one, CancellationToken.None);
        using var b = await binding.GetOuterAsync(one.Quic.Proxy!, one, CancellationToken.None);
        using var c = await binding.GetOuterAsync(other.Quic.Proxy!, other, CancellationToken.None);

        await binding.DisposeAsync();

        Assert.All(new[] { a, b, c }, lease => Assert.True(((FakeOuter)lease.Connection).Disposed));
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
        using var outer = await binding.GetOuterAsync(masque, configuration, CancellationToken.None);
        Assert.False(outer.Connection.IsClosed);
    }

    [Theory]
    [InlineData(3UL, 0UL, false, 0, true)]     // datagrams in, nothing back, outer alive: the exit
    [InlineData(3UL, 1UL, false, 0, false)]    // something came back: the path works
    [InlineData(0UL, 0UL, false, 0, false)]    // nothing went in: not the exit's silence
    [InlineData(3UL, 0UL, true, 0, false)]     // the outer itself ended: not the exit
    [InlineData(2UL, 0UL, false, 4, false)]    // sends stuck in the tunnel: our side, not the exit
    public void OnlyDatagramsInWithNothingBackOnALiveOuterConvictsTheExit(
        ulong sent, ulong received, bool outerClosed, int backlog, bool convicted)
    {
        var verdict = MasqueSessionBinding.JudgeSilence(
            new HttpRequestException("The HTTP/3 (QUIC) handshake with 'spclient.example' did not complete within 00:00:05."),
            "spclient.example",
            sent,
            received,
            outerClosed,
            backlog);

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

    // A live run of 2026-09-29, sessions sending their h3 requests concurrently: a 522 on one
    // tunnel open discarded the outer connection, and every other tunnel on it died with "The
    // MASQUE proxy connection was disposed". A proxy that answers - any status - is a proxy
    // that is there. Only one that let the open go unanswered, with nothing at all arriving on
    // the connection meanwhile, has forgotten it.
    [Theory]
    [InlineData(TlsQuicProxyError.MasqueTunnelRefused, true, false, 10, 10, true)]   // unanswered, silent: stale
    [InlineData(TlsQuicProxyError.MasqueTunnelRefused, true, false, 10, 14, false)]  // a 522: the proxy answered
    [InlineData(TlsQuicProxyError.MasqueTunnelClosed, true, false, 10, 12, false)]   // a reset: the proxy answered
    [InlineData(TlsQuicProxyError.MasqueTunnelRefused, false, false, 10, 10, false)] // a fresh outer is not stale
    [InlineData(TlsQuicProxyError.MasqueTunnelClosed, true, true, 10, 10, false)]    // ended: replaced anyway
    [InlineData(TlsQuicProxyError.MasqueAuthenticationRejected, true, false, 10, 10, false)]
    public void OnlyAnOuterThatWentSilentOnAnOpenIsDiscarded(
        TlsQuicProxyError error, bool reused, bool closed, int before, int after, bool discard)
    {
        Assert.Equal(
            discard,
            MasqueSessionBinding.IsStale(new TlsQuicProxyException(error, "x"), reused, closed, before, after));
    }

    private static TlsSessionConfiguration Configuration(
        string? masqueUser = User, bool bind = true, int tunnelsPerConnection = 1)
    {
        var options = new TlsSessionOptions();
        if (masqueUser is not null)
        {
            options.Quic.Proxy = TlsProxy.Masque("https://masque.example:50000", masqueUser, "p");
        }
        options.Quic.BindSessionThroughMasque = bind;
        options.Quic.MasqueTunnelsPerConnection = tunnelsPerConnection;
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
