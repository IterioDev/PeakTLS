using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using SharpTls;

namespace TlsClient.Tests;

/// <summary>
/// Pins that RFC 1928 section 7 UDP ASSOCIATE setup is serialised per proxy session, and only
/// the setup.
/// </summary>
/// <remarks>
/// <para>WHY SERIALISE AT ALL. Field testing over SOCKS5-UDP with three concurrent sticky
/// proxy sessions lost a fraction of dials to NEW hosts entirely: zero handshake response, a
/// ten-second timeout, and nothing to show for it. Widening the relay's accepted reply source
/// to <c>Any</c> changed nothing, so the replies were not merely arriving from an unexpected
/// address; every receive-side and transport-level drop counter read zero, so nothing was
/// arriving at all. Only fresh associations ever stalled. That leaves a setup race and a
/// provider-side cap on concurrent associations, and one-at-a-time setup fixes the first while
/// being the only available discriminator for the second.</para>
/// <para>THE DOUBLE BELOW SPEAKS ONLY THE SETUP HALF OF RFC 1928, deliberately. Every test
/// here is about what happens BEFORE the first relayed datagram, so the UDP socket it
/// advertises as BND is a black hole and every dial that gets past ASSOCIATE dies in the QUIC
/// handshake a few hundred milliseconds later. That failure is expected and is not what is
/// being measured — what is measured is how many ASSOCIATEs the server had open at once.</para>
/// </remarks>
public sealed class Socks5AssociationGateTests
{
    // Long enough that a starved thread pool cannot make a queued dial look like a serialised
    // one, short enough that the whole file stays under a couple of seconds.
    private static readonly TimeSpan Grace = TimeSpan.FromMilliseconds(400);

    private static readonly string[] Sessions = ["session-a", "session-b", "session-c"];

    [Fact]
    public async Task ConcurrentDialsThroughOneProxySession_AssociateOneAtATime()
    {
        // The server holds every ASSOCIATE open until released, so "one at a time" is
        // observable as a fact about the server rather than inferred from timing: if the three
        // dials were concurrent, three ASSOCIATEs would sit in the hold together.
        await using var server = Socks5SetupServer.Start(holdAssociates: true);
        var gate = new Socks5AssociationGate();
        var proxy = server.Proxy("session-a");

        var dials = Enumerable.Range(0, 3)
            .Select(_ => ExpectFailureAsync(Task.Run(() => DialAsync(proxy, gate))))
            .ToArray();

        await server.WaitForPendingAsync(1);
        await Task.Delay(Grace);

        // The other two are queued at the gate, not at the proxy. Without serialisation this
        // reads 3.
        Assert.Equal(1, server.PendingAssociates);

        server.ReleaseAssociates();
        await Task.WhenAll(dials);

        Assert.Equal(3, server.AssociateCount);
        Assert.Equal(1, server.MaximumConcurrentAssociates);
    }

    [Fact]
    public async Task ConcurrentDialsThroughDifferentProxySessions_DoNotWaitOnEachOther()
    {
        // THE OTHER HALF OF THE REQUIREMENT, AND THE MORE EXPENSIVE ONE TO GET WRONG. A gate
        // scoped to "the client" rather than to the proxy session would pass the test above
        // and silently throttle three sticky sessions down to one, which is the opposite of
        // why anyone runs three. Same proxy endpoint, three different credentials — which is
        // exactly how a provider distinguishes sticky sessions, and exactly what
        // TlsProxy.PoolKey keys on.
        await using var server = Socks5SetupServer.Start(holdAssociates: true);
        var gate = new Socks5AssociationGate();

        var dials = Sessions
            .Select(session =>
                ExpectFailureAsync(Task.Run(() => DialAsync(server.Proxy(session), gate))))
            .ToArray();

        await server.WaitForPendingAsync(3);
        Assert.Equal(3, server.PendingAssociates);

        server.ReleaseAssociates();
        await Task.WhenAll(dials);
    }

    [Fact]
    public async Task AFailedAssociate_ReleasesTheGateForTheNextDial()
    {
        // RFC 1928 section 6: a reply whose REP is not X'00' is a refusal, and the transport
        // throws from inside the gate. If the release were not in a finally, one refusal would
        // cost every later dial through that session its whole wait bound — a single bad
        // ASSOCIATE would take the session down rather than one request.
        await using var server = Socks5SetupServer.Start(refuseFirstAssociate: true);
        var gate = new Socks5AssociationGate();
        var proxy = server.Proxy("session-a");

        await Assert.ThrowsAnyAsync<Exception>(() => DialAsync(proxy, gate));
        var second = await Assert.ThrowsAnyAsync<Exception>(
            () => DialAsync(proxy, gate));

        // The second dial must have died in the QUIC handshake, having reached the proxy —
        // not at the gate, never having been let out of the queue.
        Assert.DoesNotContain("gave up waiting for its turn", second.Message, StringComparison.Ordinal);
        Assert.Equal(2, server.AssociateCount);
    }

    [Fact]
    public async Task ADirectDial_NeverEntersTheGate()
    {
        // A dial with no proxy takes no slot, waits on nothing, and shares no state. The
        // absence of the event is the assertion: the gate is entered on exactly one branch of
        // Http3Connection's transport choice, and this is what pins it to that branch.
        var events = new ConcurrentQueue<TlsConnectEvent>();
        var options = new TlsSessionOptions
        {
            Timeout = TimeSpan.FromMilliseconds(500),
            ConnectObserver = events.Enqueue,
        };
        var configuration = options.Snapshot();

        await Assert.ThrowsAnyAsync<Exception>(() => Http3Connection.CreateAsync(
            new Uri("https://127.0.0.1:1/"),
            proxy: null,
            configuration,
            new Tls13SessionCache(),
            new DnsEndpointResolver(configuration),
            new Socks5AssociationGate(),
            CancellationToken.None).AsTask());

        Assert.DoesNotContain(
            events,
            connectEvent =>
                connectEvent.Kind == TlsConnectEventKind.Socks5AssociationGateEntered);
    }

    [Fact]
    public async Task AProxiedDial_ReportsHowLongItQueuedForTheGate()
    {
        // WITHOUT THIS THE WHOLE EXERCISE IS UNATTRIBUTABLE. If stalls survive serialised
        // setup the cause is a provider-side concurrency cap rather than a race — but that
        // reading is only available if the tester can see that dials actually queued. The
        // second dial's Elapsed is that evidence.
        await using var server = Socks5SetupServer.Start(holdAssociates: true);
        var gate = new Socks5AssociationGate();
        var proxy = server.Proxy("session-a");
        var events = new ConcurrentQueue<TlsConnectEvent>();

        var first = Task.Run(() => DialAsync(proxy, gate, events.Enqueue));
        await server.WaitForPendingAsync(1);
        var second = Task.Run(() => DialAsync(proxy, gate, events.Enqueue));
        await Task.Delay(Grace);
        server.ReleaseAssociates();
        await Task.WhenAll(
            Assert.ThrowsAnyAsync<Exception>(() => first),
            Assert.ThrowsAnyAsync<Exception>(() => second));

        var waits = events
            .Where(e => e.Kind == TlsConnectEventKind.Socks5AssociationGateEntered)
            .Select(e => e.Elapsed)
            .OrderBy(elapsed => elapsed)
            .ToArray();

        // The held dial reports about nothing, the queued one reports about the hold. The
        // floor is half the hold rather than the whole of it because the second dial starts a
        // beat after the delay does; the gap between the two is the claim, not the exact
        // figure.
        Assert.Equal(2, waits.Length);
        Assert.True(
            waits[1] >= TimeSpan.FromMilliseconds(Grace.TotalMilliseconds / 2),
            $"The queued dial reported a {waits[1]} wait after being held for {Grace}, so the " +
            "reported wait is not the real one.");
    }

    [Fact]
    public async Task CancellationWhileQueued_IsPromptAndLeavesTheGateUsable()
    {
        // Two claims in one, because they fail differently. PROMPT: a caller that gives up
        // must not first serve out someone else's slow ASSOCIATE. USABLE: the abandoned wait
        // must not have consumed the slot on its way out, or the cancelling caller takes the
        // session down with it.
        var gate = new Socks5AssociationGate();
        var proxy = TlsProxy.Socks5("socks5://127.0.0.1:1", "session-a", "password");
        var infinite = Timeout.InfiniteTimeSpan;

        _ = await gate.EnterAsync(proxy, infinite, CancellationToken.None);

        // A generous but FINITE bound for the queued waiter, so that an implementation which
        // only checked the token after acquiring would fail here rather than hang.
        using var cancellation = new CancellationTokenSource();
        var queued = Task.Run(
            () => gate.EnterAsync(proxy, Grace * 10, cancellation.Token).AsTask());
        await Task.Delay(50);
        cancellation.Cancel();

        var started = Stopwatch.GetTimestamp();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued);
        Assert.True(
            Stopwatch.GetElapsedTime(started) < Grace,
            "The cancelled wait did not return promptly.");

        gate.Exit(proxy);

        // The holder's release is the ONLY one owed. If the cancelled waiter had taken the
        // slot, this would block forever instead of returning at once.
        Assert.True(await gate.EnterAsync(proxy, Grace, CancellationToken.None) < Grace);
    }

    [Fact]
    public async Task AWaitPastTheConfiguredBound_FailsAndNamesTheKnob()
    {
        // A gate with no bound converts a hung ASSOCIATE into a hung session, so the wait is
        // bounded and the refusal points at the property that widens it.
        var gate = new Socks5AssociationGate();
        var proxy = TlsProxy.Socks5("socks5://127.0.0.1:1", "session-a", "password");

        _ = await gate.EnterAsync(proxy, Timeout.InfiniteTimeSpan, CancellationToken.None);

        var error = await Assert.ThrowsAsync<HttpRequestException>(
            () => gate.EnterAsync(
                proxy,
                TimeSpan.FromMilliseconds(50),
                CancellationToken.None).AsTask());

        Assert.Contains(nameof(TlsQuicOptions.AssociationWaitTimeout), error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ANonPositiveAssociationWaitTimeout_IsRefused()
    {
        // Zero would fail every proxied dial the instant a second one overlapped, with a
        // message about a wait that never happened. Infinite is a legitimate answer and stays
        // legal.
        var options = new TlsSessionOptions();
        options.Quic.AssociationWaitTimeout = TimeSpan.Zero;

        var error = Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
        Assert.Equal(nameof(TlsQuicOptions.AssociationWaitTimeout), error.ParamName);

        options.Quic.AssociationWaitTimeout = Timeout.InfiniteTimeSpan;
        Assert.Equal(Timeout.InfiniteTimeSpan, options.Snapshot().Quic.AssociationWaitTimeout);
    }

    [Fact]
    public void TheDefaultWaitBound_IsThirtySeconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(30), new TlsSessionOptions().Quic.AssociationWaitTimeout);
    }

    /// <summary>Awaits a dial that is expected to fail. EVERY dial in this file does: the
    /// association it opens is real, but what the proxy advertises as BND is a black hole, so
    /// the QUIC handshake behind it always times out. The failure is scenery — the assertions
    /// are about what the proxy saw.</summary>
    private static async Task ExpectFailureAsync(Task dial) =>
        await Assert.ThrowsAnyAsync<Exception>(() => dial);

    /// <summary>Dials HTTP/3 through the double. Always throws: the association is real, the
    /// relay behind it is a black hole, so the QUIC handshake times out.</summary>
    private static async Task DialAsync(
        TlsProxy proxy,
        Socks5AssociationGate gate,
        Action<TlsConnectEvent>? observer = null)
    {
        var options = new TlsSessionOptions
        {
            // Bounds the handshake that follows the association, so a test costs its hold and
            // not thirty seconds. Http3Connection takes the session timeout when it is the
            // smaller of the two.
            Timeout = TimeSpan.FromMilliseconds(500),
            ConnectObserver = observer,
        };
        options.Quic.AssociationWaitTimeout = TimeSpan.FromSeconds(5);
        var configuration = options.Snapshot();

        await Http3Connection.CreateAsync(
            // A NAME RATHER THAN A LITERAL, because the ClientHello refuses an IP address in
            // SNI. Nothing listens on it: the handshake datagrams go to the proxy, and the
            // proxy's BND endpoint is a black hole.
            new Uri("https://localhost/"),
            proxy,
            configuration,
            new Tls13SessionCache(),
            new DnsEndpointResolver(configuration),
            gate,
            CancellationToken.None);
    }
}

/// <summary>
/// A SOCKS5 server that speaks only RFC 1928's setup exchange, across as many concurrent
/// control connections as it is given.
/// </summary>
/// <remarks>
/// <para>NOT <c>FakeSocks5Relay</c>, WHICH LIVES IN SharpTls's SUITE AND ACCEPTS ONE
/// CONNECTION. Concurrency is the entire subject here, so a single-connection double cannot
/// express the question — and the thing being counted is ASSOCIATEs in flight, which that one
/// does not track.</para>
/// <para>An ASSOCIATE is "in flight" from the moment its request is read to the moment its
/// reply is written, which is precisely the window the client is inside
/// <c>TlsQuicSocks5Transport.ConnectAsync</c> and therefore holding the gate.</para>
/// </remarks>
internal sealed class Socks5SetupServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly Socket _blackHole;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly ConcurrentBag<Socket> _controlConnections = [];
    private readonly TaskCompletionSource _release =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly bool _holdAssociates;
    private readonly Task _accept;
    private int _refusalsRemaining;
    private int _pending;
    private int _maximumPending;
    private int _associates;

    private Socks5SetupServer(TcpListener listener, Socket blackHole, bool hold, int refusals)
    {
        _listener = listener;
        _blackHole = blackHole;
        _holdAssociates = hold;
        _refusalsRemaining = refusals;
        ProxyEndPoint = (IPEndPoint)listener.LocalEndpoint;
        _accept = Task.Run(() => AcceptLoopAsync(_lifetime.Token));
    }

    public IPEndPoint ProxyEndPoint { get; }

    public int PendingAssociates => Volatile.Read(ref _pending);

    public int MaximumConcurrentAssociates => Volatile.Read(ref _maximumPending);

    public int AssociateCount => Volatile.Read(ref _associates);

    public static Socks5SetupServer Start(
        bool holdAssociates = false,
        bool refuseFirstAssociate = false)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        // RFC 1928 section 7's BND.ADDR/BND.PORT must be somewhere the client can send to, or
        // the send path fails before the handshake can time out. Nothing reads it.
        var blackHole = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        blackHole.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        return new Socks5SetupServer(listener, blackHole, holdAssociates, refuseFirstAssociate ? 1 : 0);
    }

    /// <summary>The proxy for one sticky session. The username is what makes it one: it is
    /// what a provider keys the session on, and what <c>TlsProxy.PoolKey</c> keys on.</summary>
    public TlsProxy Proxy(string session) => TlsProxy.Socks5(
        $"socks5://{ProxyEndPoint.Address}:{ProxyEndPoint.Port}",
        session,
        "password");

    public void ReleaseAssociates() => _release.TrySetResult();

    /// <summary>Waits until at least <paramref name="count"/> ASSOCIATEs are in flight at
    /// once, and fails the test rather than hanging if they never are.</summary>
    public async Task WaitForPendingAsync(int count)
    {
        var deadline = Stopwatch.StartNew();
        while (MaximumConcurrentAssociates < count)
        {
            Assert.True(
                deadline.Elapsed < TimeSpan.FromSeconds(10),
                $"Only {MaximumConcurrentAssociates} concurrent ASSOCIATE(s) ever reached the " +
                $"proxy; {count} were expected.");
            await Task.Delay(10);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _release.TrySetResult();
        await _lifetime.CancelAsync();
        _listener.Stop();
        _blackHole.Dispose();
        foreach (var socket in _controlConnections)
        {
            socket.Dispose();
        }
        try
        {
            await _accept;
        }
        catch (Exception)
        {
            // Shutdown races are not findings.
        }
        _lifetime.Dispose();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var socket = await _listener.AcceptSocketAsync(cancellationToken);
                _controlConnections.Add(socket);
                _ = Task.Run(() => HandleAsync(socket, cancellationToken), CancellationToken.None);
            }
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private async Task HandleAsync(Socket socket, CancellationToken cancellationToken)
    {
        try
        {
            // RFC 1928 section 3: VER | NMETHODS | METHODS. Username/password (X'02') when it
            // is offered, so that a per-session credential reaches the server and the client
            // exercises RFC 1929 rather than skipping it.
            var greeting = await ReadExactAsync(socket, 2, cancellationToken);
            var methods = await ReadExactAsync(socket, greeting[1], cancellationToken);
            var method = Array.IndexOf(methods, (byte)0x02) >= 0 ? (byte)0x02 : (byte)0x00;
            await socket.SendAsync(new byte[] { 0x05, method }, cancellationToken);

            if (method == 0x02)
            {
                // RFC 1929 section 2: VER | ULEN | UNAME | PLEN | PASSWD. Every credential is
                // accepted — the credential's job here is to separate sessions, not to be
                // checked.
                var authentication = await ReadExactAsync(socket, 2, cancellationToken);
                _ = await ReadExactAsync(socket, authentication[1], cancellationToken);
                var passwordLength = (await ReadExactAsync(socket, 1, cancellationToken))[0];
                _ = await ReadExactAsync(socket, passwordLength, cancellationToken);
                await socket.SendAsync(new byte[] { 0x01, 0x00 }, cancellationToken);
            }

            // RFC 1928 section 4: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT.
            var request = await ReadExactAsync(socket, 4, cancellationToken);
            var addressLength = request[3] switch
            {
                0x01 => 4,
                0x03 => (await ReadExactAsync(socket, 1, cancellationToken))[0],
                0x04 => 16,
                var atyp => throw new InvalidOperationException($"Unsupported ATYP 0x{atyp:X2}."),
            };
            _ = await ReadExactAsync(socket, addressLength + 2, cancellationToken);

            Interlocked.Increment(ref _associates);
            var pending = Interlocked.Increment(ref _pending);
            InterlockedMaximum(ref _maximumPending, pending);
            try
            {
                if (_holdAssociates)
                {
                    await _release.Task.WaitAsync(cancellationToken);
                }

                // RFC 1928 section 6: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT.
                var refuse = Interlocked.Decrement(ref _refusalsRemaining) >= 0;
                var address = ((IPEndPoint)_blackHole.LocalEndPoint!).Address.GetAddressBytes();
                var reply = new byte[4 + address.Length + 2];
                reply[0] = 0x05;
                reply[1] = refuse ? (byte)0x01 : (byte)0x00; // X'01' general SOCKS server failure.
                reply[3] = 0x01;
                address.CopyTo(reply, 4);
                BinaryPrimitives.WriteUInt16BigEndian(
                    reply.AsSpan(4 + address.Length),
                    (ushort)((IPEndPoint)_blackHole.LocalEndPoint!).Port);
                await socket.SendAsync(reply, cancellationToken);
            }
            finally
            {
                Interlocked.Decrement(ref _pending);
            }

            // RFC 1928 section 7: the association lives as long as the control connection, so
            // this is held open until the test disposes the server.
            _ = await socket.ReceiveAsync(new byte[1], cancellationToken);
        }
        catch (Exception)
        {
            // Every end of a control connection here is a test tearing down.
        }
    }

    private static void InterlockedMaximum(ref int target, int value)
    {
        var seen = Volatile.Read(ref target);
        while (value > seen)
        {
            var previous = Interlocked.CompareExchange(ref target, value, seen);
            if (previous == seen)
            {
                return;
            }
            seen = previous;
        }
    }

    private static async Task<byte[]> ReadExactAsync(
        Socket socket,
        int length,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var read = 0;
        while (read < length)
        {
            var received = await socket.ReceiveAsync(
                buffer.AsMemory(read),
                SocketFlags.None,
                cancellationToken);
            if (received == 0)
            {
                throw new IOException("The control connection closed mid-message.");
            }
            read += received;
        }
        return buffer;
    }
}
