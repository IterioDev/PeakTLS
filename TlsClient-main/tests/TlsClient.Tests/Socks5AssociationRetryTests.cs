using System.Collections.Concurrent;
using System.Diagnostics;

namespace TlsClient.Tests;

/// <summary>
/// Pins that an RFC 1928 section 7 UDP association which is established and then relays nothing
/// is re-established, and that one which relays ANYTHING never is.
/// </summary>
/// <remarks>
/// <para>THE FAILURE THIS ANSWERS. Six to eight per cent of fresh UDP ASSOCIATEs succeed
/// completely — RFC 1928 section 6 reply well-formed, REP X'00', a routable BND — and then
/// relay not one datagram, ever. The QUIC handshake behind such an association times out with
/// every receive-side counter at zero. It is not contention: pinning concurrency to 1 gave
/// 2 stalls in 25 dials, statistically identical to the ~6% seen at three threads, so it is a
/// fixed per-association probability and the only remedy is to notice and re-associate.</para>
/// <para>THE TRIGGER IS PRECISE ON PURPOSE, AND THAT PRECISION IS WHAT MOST OF THIS FILE
/// DEFENDS. Only ZERO inbound datagrams justifies a re-dial. A working association answers
/// within a round trip; a dead one never answers at all, and that is the whole discriminator.
/// Retrying on "the handshake failed" instead would silently paper over a rejected ClientHello,
/// a peer that will not speak h3, or replies being discarded by the relay-source policy — every
/// one a real defect, and hiding real defects behind re-dials is how three previous rounds of
/// this investigation lost time.</para>
/// <para>NO DIAL IN THIS FILE ENDS IN A CONNECTION, and none can: the assembly has no offline
/// QUIC server, so even a perfectly live relay leads to a handshake that times out. What is
/// measured instead is what the client DID — how many ASSOCIATEs it opened, which it abandoned,
/// and what it finally reported — which is where every claim about re-association actually
/// lives.</para>
/// </remarks>
public sealed class Socks5AssociationRetryTests
{
    /// <summary>Short enough that a dead association is abandoned in a few hundred
    /// milliseconds, long enough that a loopback echo comfortably beats it even on a busy
    /// build agent.</summary>
    private static readonly TimeSpan Liveness = TimeSpan.FromMilliseconds(400);

    /// <summary>The handshake bound once liveness is proven. Every dial here spends it in full
    /// on its last attempt, so it is the dominant cost of the file.</summary>
    private static readonly TimeSpan Handshake = TimeSpan.FromMilliseconds(900);

    /// <summary>Which attempts a dial at the default bound of three abandons: the first two.
    /// The third is not retried, so it emits nothing.</summary>
    private static readonly int[] AbandonedAttempts = [1, 2];

    [Fact]
    public async Task AnAssociationThatRelaysNothing_IsAbandonedAndTheNextOneCarriesTheDial()
    {
        // THE CENTRAL CLAIM. The first association is a black hole and the second is live, which
        // is the exact shape of the field failure. The client must notice the first is dead,
        // open a second, and then STOP — the second relays, so there is nothing left to
        // re-establish however the handshake behind it ends.
        await using var server = Socks5SetupServer.Start(relayFromAssociate: 2);
        var events = new ConcurrentQueue<TlsConnectEvent>();

        var error = await Assert.ThrowsAnyAsync<Exception>(
            () => DialAsync(server.Proxy("session-a"), events.Enqueue));

        Assert.Equal(2, server.AssociateCount);
        Assert.Single(Retries(events));

        // The second association DID relay, so the dial must not report the dead-association
        // failure. If it does, liveness is being read off something other than arriving
        // datagrams and the whole discriminator is fiction.
        Assert.DoesNotContain("relayed no inbound datagram", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAssociationThatRelaysAnything_IsNeverRetried()
    {
        // THE GUARD AGAINST MASKING REAL DEFECTS. This relay is alive from the first ASSOCIATE
        // and the handshake still fails — an echo is not a QUIC server. That failure is a real
        // one and must be reported, not retried: exactly one association, no retry events.
        await using var server = Socks5SetupServer.Start(relayFromAssociate: 1);
        var events = new ConcurrentQueue<TlsConnectEvent>();

        var error = await Assert.ThrowsAnyAsync<Exception>(
            () => DialAsync(server.Proxy("session-a"), events.Enqueue));

        Assert.Equal(1, server.AssociateCount);
        Assert.Empty(Retries(events));
        Assert.DoesNotContain("relayed no inbound datagram", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExhaustingTheAttempts_NamesTheDeadAssociationRatherThanTimingOut()
    {
        // BOUNDED, AND THE MESSAGE IS THE DELIVERABLE. "The handshake timed out" is what this
        // looked like for three rounds of investigation, and it pointed at the QUIC layer, which
        // was innocent every time. The report has to say which layer died and which knobs move
        // it, or the next person starts where the last one did.
        await using var server = Socks5SetupServer.Start();
        var events = new ConcurrentQueue<TlsConnectEvent>();

        var error = await Assert.ThrowsAsync<HttpRequestException>(
            () => DialAsync(server.Proxy("session-a"), events.Enqueue));

        Assert.Equal(3, server.AssociateCount);
        Assert.Equal(2, Retries(events).Length);
        Assert.Contains("relayed no inbound datagram at all", error.Message, StringComparison.Ordinal);
        Assert.Contains(
            nameof(TlsQuicOptions.MaximumAssociationAttempts),
            error.Message,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(TlsQuicOptions.AssociationLivenessDeadline),
            error.Message,
            StringComparison.Ordinal);

        // DropSummary's all-zero form is the positive statement that nothing reached the
        // socket, which is the finding rather than decoration.
        Assert.Contains("SOCKS5 relay drops: 0 from an unexpected source", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheRetriesAreNumbered_SoARunCanBeCountedOffTheObserver()
    {
        // A FIX WHOSE EFFECT CANNOT BE MEASURED LEAVES US WHERE THE LAST THREE ROUNDS STARTED.
        // The three outcomes a tester has to separate are "never retried" (no events),
        // "retried and succeeded" and "retried and still failed" — and separating the last two
        // needs the attempt number, not just a count.
        await using var server = Socks5SetupServer.Start();
        var events = new ConcurrentQueue<TlsConnectEvent>();

        await Assert.ThrowsAnyAsync<Exception>(
            () => DialAsync(server.Proxy("session-a"), events.Enqueue));

        var retries = Retries(events);
        Assert.Equal(AbandonedAttempts, retries.Select(retry => retry.AddressCount).ToArray());

        // One connection, so one identity across every event it emitted.
        Assert.Single(retries.Select(retry => retry.ConnectionId).Distinct());

        // The reason travels with the event. Without it a re-association is a number with no
        // account of what ended the association it abandoned.
        Assert.All(retries, retry => Assert.NotNull(retry.Exception));
        Assert.All(retries, retry => Assert.True(retry.Elapsed > TimeSpan.Zero));
    }

    [Fact]
    public async Task ADirectDial_IsNeitherProbedNorRetried()
    {
        // THERE IS NO ASSOCIATION TO BE DEAD WITHOUT A PROXY. A direct dial must take the
        // liveness deadline nowhere near its handshake — if it did, a session whose proxy
        // settings say nothing would have its direct dials cut short by a SOCKS5 feature. The
        // reported bound is the assertion: the handshake timeout, never the liveness deadline.
        var events = new ConcurrentQueue<TlsConnectEvent>();
        var options = new TlsSessionOptions
        {
            Timeout = Handshake,
            ConnectObserver = events.Enqueue,
        };
        options.Quic.AssociationLivenessDeadline = Liveness;
        var configuration = options.Snapshot();

        var started = Stopwatch.GetTimestamp();
        var error = await Assert.ThrowsAnyAsync<Exception>(() => Http3Connection.CreateAsync(
            new Uri("https://127.0.0.1:1/"),
            proxy: null,
            configuration,
            new SharpTls.Tls13SessionCache(),
            new DnsEndpointResolver(configuration),
            new Socks5AssociationGate(),
            CancellationToken.None).AsTask());
        var elapsed = Stopwatch.GetElapsedTime(started);

        Assert.Empty(Retries(events));

        // NOT RE-DIALLED, which is the claim a count of retry events cannot make on its own —
        // there is no relay wrapper on this path to emit one, so a direct dial that WERE looping
        // would report nothing and still cost three handshakes. The clock is the witness.
        Assert.True(
            elapsed < Handshake * 2,
            $"A direct dial took {elapsed} against a {Handshake} handshake bound, so it is " +
            "being re-dialled or probed like a proxied one.");

        // AND NOT PROBED: the bound it reports must be the handshake timeout, never the SOCKS5
        // liveness deadline.
        Assert.DoesNotContain(Liveness.ToString(), error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARetriedDial_DoesNotDeadlockAgainstTheAssociationGate()
    {
        // THE ONE WAY THIS FEATURE COULD WEDGE A WHOLE SESSION. Re-association takes a FRESH
        // ASSOCIATE, and setup is serialised per proxy session, so a retry that still held the
        // slot from its previous attempt would queue behind itself and never come back — taking
        // every other dial through that session with it. Two concurrent dials through ONE
        // session, each retrying to exhaustion, is the shape that catches it.
        await using var server = Socks5SetupServer.Start();
        var proxy = server.Proxy("session-a");
        var gate = new Socks5AssociationGate();

        var dials = Task.WhenAll(
            Assert.ThrowsAnyAsync<Exception>(() => DialAsync(proxy, gate: gate)),
            Assert.ThrowsAnyAsync<Exception>(() => DialAsync(proxy, gate: gate)));

        // Generous against the six liveness windows and two full handshakes below, and still far
        // short of forever: a deadlock fails here instead of hanging the suite.
        await dials.WaitAsync(TimeSpan.FromSeconds(30));

        // Two dials at three attempts each. Anything less means a retry was swallowed.
        Assert.Equal(6, server.AssociateCount);

        // AND STILL SERIALISED. A retry is an ordinary ASSOCIATE and must queue like one; if it
        // bypassed the gate to avoid the deadlock, this reads 2.
        Assert.Equal(1, server.MaximumConcurrentAssociates);
    }

    [Fact]
    public async Task ARefusedAssociate_IsReportedRatherThanRetried()
    {
        // AN ASSOCIATION THAT WAS NEVER ESTABLISHED IS NOT A DEAD ONE. RFC 1928 section 6's
        // non-zero REP is a refusal with a name, and re-dialling it would convert a clear
        // rejection into three of them and a misleading report.
        await using var server = Socks5SetupServer.Start(refuseFirstAssociate: true);
        var events = new ConcurrentQueue<TlsConnectEvent>();

        await Assert.ThrowsAnyAsync<Exception>(
            () => DialAsync(server.Proxy("session-a"), events.Enqueue));

        Assert.Equal(1, server.AssociateCount);
        Assert.Empty(Retries(events));
    }

    [Fact]
    public void TheDefaults_AreTwoSecondsAndThreeAttempts()
    {
        var quic = new TlsSessionOptions().Quic;

        Assert.Equal(TimeSpan.FromSeconds(2), quic.AssociationLivenessDeadline);
        Assert.Equal(3, quic.MaximumAssociationAttempts);
    }

    [Fact]
    public void ANonPositiveLivenessDeadline_IsRefused()
    {
        // Zero would declare every association dead before a datagram could physically arrive
        // and burn the whole attempt budget doing it, so it is refused where the caller can
        // still see which property they set.
        var options = new TlsSessionOptions();
        options.Quic.AssociationLivenessDeadline = TimeSpan.Zero;

        var error = Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
        Assert.Equal(nameof(TlsQuicOptions.AssociationLivenessDeadline), error.ParamName);
    }

    [Fact]
    public void AnAttemptBoundBelowOne_IsRefused()
    {
        // One is the meaningful floor: associate once, never retry, which is the behaviour that
        // predates the knob. Zero would dial nothing at all.
        var options = new TlsSessionOptions();
        options.Quic.MaximumAssociationAttempts = 0;

        var error = Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
        Assert.Equal(nameof(TlsQuicOptions.MaximumAssociationAttempts), error.ParamName);

        options.Quic.MaximumAssociationAttempts = 1;
        Assert.Equal(1, options.Snapshot().Quic.MaximumAssociationAttempts);
    }

    private static TlsConnectEvent[] Retries(ConcurrentQueue<TlsConnectEvent> events) =>
        [.. events
            .Where(e => e.Kind == TlsConnectEventKind.Socks5AssociationRetried)
            .OrderBy(e => e.Timestamp)];

    /// <summary>Dials HTTP/3 through the double. Always throws: this assembly has no offline
    /// QUIC server, so the handshake behind even a live relay times out. What the dial DID on
    /// the way there is the subject.</summary>
    private static async Task DialAsync(
        TlsProxy proxy,
        Action<TlsConnectEvent>? observer = null,
        Socks5AssociationGate? gate = null)
    {
        var options = new TlsSessionOptions
        {
            Timeout = Handshake,
            ConnectObserver = observer,
        };
        options.Quic.AssociationLivenessDeadline = Liveness;
        var configuration = options.Snapshot();

        await Http3Connection.CreateAsync(
            // A NAME RATHER THAN A LITERAL, because the ClientHello refuses an IP address in
            // SNI. Nothing listens on it either way: the datagrams go to the proxy.
            new Uri("https://localhost/"),
            proxy,
            configuration,
            new SharpTls.Tls13SessionCache(),
            new DnsEndpointResolver(configuration),
            gate ?? new Socks5AssociationGate(),
            CancellationToken.None);
    }
}
