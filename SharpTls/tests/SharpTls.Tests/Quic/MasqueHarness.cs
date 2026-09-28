using System.Net;
using SharpTls;
using SharpTls.Certificates;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;
using static SharpTls.Tests.Quic.TlsQuicConnectionTests;

namespace SharpTls.Tests.Quic;

/// <summary>An outer "proxy" for <see cref="TlsQuicMasqueConnection"/>'s dial and the first
/// tunnel on it: a <see cref="LoopbackQuicPeer"/> server on an in-memory pair, driven by one
/// scripted task while the client pumps itself inside
/// <see cref="TlsQuicMasqueConnection.ConnectAsync"/> and
/// <see cref="TlsQuicMasqueConnection.OpenTunnelAsync"/>.</summary>
/// <remarks>
/// <para>THE SERVER IS BUILT AFTER THE DIAL STARTS, because <see cref="Server"/> needs the
/// client's original Destination Connection ID for s7.3's
/// original_destination_connection_id, and that id exists only once the first Initial is on
/// the wire.</para>
/// <para>THE PEER IS NOT THREAD-SAFE. Nothing touches it while the script runs; after
/// <see cref="CreateAsync"/> returns, the test drives it from its own thread through
/// <see cref="PumpPeerAsync"/>.</para>
/// </remarks>
internal sealed class MasqueHarness : IAsyncDisposable
{
    private readonly TestPki _pki;
    private readonly TlsServerCertificate _credential;
    private readonly CustomTlsQuicServer _server;

    // How many of the client's datagrams the peer has opened; Peer.PumpOnceAsync blocks on an
    // empty inbox, so PumpPeerAsync pumps exactly the backlog and no more.
    private int _peerConsumed;

    private MasqueHarness(
        TestPki pki,
        TlsServerCertificate credential,
        CustomTlsQuicServer server,
        InMemoryDatagramTransport clientTransport,
        LoopbackQuicPeer peer,
        TlsQuicMasqueConnection connection,
        TlsQuicMasqueTransport transport,
        int peerConsumed)
    {
        _pki = pki;
        _credential = credential;
        _server = server;
        ClientTransport = clientTransport;
        Peer = peer;
        Connection = connection;
        Transport = transport;
        _peerConsumed = peerConsumed;
    }

    /// <summary>The outer connection the tunnel was opened on.</summary>
    internal TlsQuicMasqueConnection Connection { get; }

    /// <summary>The dialled tunnel: the outer's first request, stream 0.</summary>
    internal TlsQuicMasqueTransport Transport { get; }

    /// <summary>The proxy's side of the outer connection.</summary>
    internal LoopbackQuicPeer Peer { get; }

    /// <summary>The client half of the transport pair, for the datagram count.</summary>
    internal InMemoryDatagramTransport ClientTransport { get; }

    /// <summary>The outer spec every test dials with unless it passes its own.</summary>
    /// <remarks>The flow-control pair is the loopback's, not a persona's: a client that
    /// advertises RFC 9000 s18.2's absent-parameter zero cannot receive the proxy's control
    /// stream or its response. The 0x20 literal is 65535 as a four-byte varint.</remarks>
    /// <param name="congestionController">Replaces NewReno, for a test that shuts the
    /// window.</param>
    internal static TlsQuicConnectionSpec OuterSpec(
        ITlsQuicCongestionController? congestionController = null) => new()
    {
        PathMtuDiscovery = false,
        BasePathMtu = 1392,
        MaximumPathMtu = 1392,
        DestinationConnectionIdLength = 8,
        Recovery = new TlsQuicRecoverySpec
        {
            CongestionController =
                congestionController is null ? null : () => congestionController,
        },
        LocalFlowControl = TestQuicSpecValues.HarnessFlowControl,
        TransportParameters = new TlsQuicTransportParameterSpec
        {
            Parameters =
            [
                .. TestQuicSpecValues.HarnessParameters.Parameters,
                TlsQuicTransportParameterSlot.Literal(0x20, [0x80, 0x00, 0xFF, 0xFF]),
            ],
        },
    };

    /// <summary>Starts the dial, answers it as a proxy would, and returns once the dial has
    /// finished and the script with it.</summary>
    /// <param name="cancellationToken">Bounds the dial and the script.</param>
    /// <param name="peerSettings">The proxy's SETTINGS.</param>
    /// <param name="serverMaxDatagramFrameSize">The proxy's max_datagram_frame_size;
    /// <see langword="null"/> omits the parameter.</param>
    /// <param name="answerStatus">The CONNECT-UDP response status.</param>
    /// <param name="answerWithReset">Answer with RESET_STREAM 0x10c instead of a
    /// response.</param>
    /// <param name="answerWithClose">Answer by closing the outer connection with
    /// H3_NO_ERROR instead of a response.</param>
    /// <param name="outerSpec">Replaces <see cref="OuterSpec"/>.</param>
    /// <param name="wrapOuter">Wraps the client half of the pair before the dial uses it, for a
    /// test that has to see or hold the outer connection's sends; it stays the harness's to
    /// dispose.</param>
    /// <param name="unreachableFirst">Endpoints the dial tries before the live one; the pair
    /// drops every datagram to them, so each costs one <paramref name="handshakeDeadline"/>.
    /// </param>
    /// <param name="reachable">When <see langword="false"/>, the live endpoint is left out and
    /// the dial has only <paramref name="unreachableFirst"/> to try.</param>
    /// <param name="handshakeDeadline">Replaces the options' 10 s default, per address.</param>
    /// <param name="innerCeiling">A caller's inner datagram ceiling, below the arithmetic one.
    /// </param>
    /// <exception cref="Exception">Whatever the dial threw, after the peer is torn down; or
    /// the script's own failure, when it failed.</exception>
    internal static async ValueTask<MasqueHarness> CreateAsync(
        CancellationToken cancellationToken,
        TlsQuicHttp3Setting[] peerSettings,
        ulong? serverMaxDatagramFrameSize = 65535,
        int answerStatus = 200,
        bool answerWithReset = false,
        TlsQuicConnectionSpec? outerSpec = null,
        bool answerWithClose = false,
        Func<ITlsQuicDatagramTransport, ITlsQuicDatagramTransport>? wrapOuter = null,
        IPEndPoint[]? unreachableFirst = null,
        bool reachable = true,
        TimeSpan? handshakeDeadline = null,
        int? innerCeiling = null)
    {
        var pki = TestPki.Create();
        var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        var options = new TlsQuicMasqueOptions
        {
            HandshakeDeadline = handshakeDeadline ?? TimeSpan.FromSeconds(10),
            InnerDatagramCeiling = innerCeiling,
            ProxyEndPoint = new DnsEndPoint("proxy.test", 50000),
            Username = "user",
            Password = "pass",
            OuterSpec = outerSpec ?? OuterSpec(),
            OuterHttp3Spec = new TlsQuicHttp3Spec { Settings = TestHttp3Settings.DatagramCapable },
            ConfigureOuterClientHello = _ => { },
            OuterTransport = wrapOuter is null ? clientTransport : wrapOuter(clientTransport),
            // The pair drops anything not addressed to the server half, so an endpoint listed
            // before it is an address that never answers.
            OuterRemoteEndPoints = reachable
                ? [.. unreachableFirst ?? [], serverTransport.LocalEndPoint]
                : unreachableFirst ?? throw new ArgumentException(
                    "An unreachable proxy needs at least one endpoint.", nameof(unreachableFirst)),

            // TestPki's root is not machine-trusted and the leaf does not name proxy.test.
            DangerouslySkipOuterCertificateValidation = true,
        };

        // The two steps a caller takes: the outer connection, then the first tunnel on it. A
        // tunnel that fails to open takes the outer down with it here, as a caller's would.
        var dial = Task.Run(
            async () =>
            {
                var connection = await TlsQuicMasqueConnection.ConnectAsync(options, cancellationToken);
                try
                {
                    var tunnel = await connection.OpenTunnelAsync(
                        "target.test", 443, new IPEndPoint(IPAddress.Loopback, 443), cancellationToken);
                    return (connection, tunnel);
                }
                catch (Exception)
                {
                    await connection.DisposeAsync();
                    throw;
                }
            },
            cancellationToken);
        while (clientTransport.Sent.Count == 0 && !dial.IsCompleted)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(5), cancellationToken);
        }
        if (clientTransport.Sent.Count == 0)
        {
            // The dial failed before its first Initial; there is no peer to build.
            await clientTransport.DisposeAsync();
            await serverTransport.DisposeAsync();
            credential.Dispose();
            pki.Dispose();
            await dial;
            throw new InvalidOperationException("The dial completed without sending anything.");
        }

        // RFC 9000 s17.2: byte 5 of a long header is the Destination Connection ID length.
        var first = clientTransport.Sent[0];
        var originalDestination = first.AsMemory(6, first[5]);
        var server = Server(
            credential,
            originalDestination,
            flowControl: serverMaxDatagramFrameSize is { } size
                ?
                [
                    .. FlowControlParameters(),
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.MaxDatagramFrameSize, size),
                ]
                : null);
        var peer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        using var scriptCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var script = RunScriptAsync(
            peer,
            peerSettings,
            answerStatus,
            answerWithReset,
            answerWithClose,
            scriptCancellation.Token);

        TlsQuicMasqueConnection connection;
        TlsQuicMasqueTransport transport;
        try
        {
            (connection, transport) = await dial;
        }
        catch (Exception)
        {
            // The peer's own failure first, if it had one; otherwise stop it and rethrow the
            // dial's. A dial that failed mid-handshake sends no close, so the script may be
            // blocked on an empty inbox.
            if (!script.IsCompleted)
            {
                scriptCancellation.Cancel();
            }
            try
            {
                await script;
            }
            catch (OperationCanceledException) when (scriptCancellation.IsCancellationRequested)
            {
            }
            finally
            {
                await peer.DisposeAsync();
                await server.DisposeAsync();
                await clientTransport.DisposeAsync();
                credential.Dispose();
                pki.Dispose();
            }
            throw;
        }

        var pumped = await script;
        return new MasqueHarness(
            pki, credential, server, clientTransport, peer, connection, transport, pumped);
    }

    /// <summary>Opens a further tunnel on <see cref="Connection"/> and answers its CONNECT-UDP
    /// as the proxy: pumps the peer until the request's HEADERS arrive on
    /// <paramref name="streamId"/>, then sends a <paramref name="status"/> response.</summary>
    /// <param name="streamId">The request stream the client will open next: 4 for the second
    /// tunnel, 8 for the third.</param>
    /// <param name="status">The response status.</param>
    /// <param name="cancellationToken">Bounds the open.</param>
    /// <param name="host">The target host in the request's path.</param>
    /// <returns>The tunnel.</returns>
    /// <exception cref="TlsQuicProxyException">The open failed, by name.</exception>
    internal async ValueTask<TlsQuicMasqueTransport> OpenTunnelAsync(
        ulong streamId, int status, CancellationToken cancellationToken, string host = "second.test")
    {
        var open = Connection.OpenTunnelAsync(
            host, 443, new IPEndPoint(IPAddress.Loopback, 443), cancellationToken);
        while (!Peer.ReceivedStreamFrames.Any(frame => frame.StreamId == streamId))
        {
            if (open.IsCompleted)
            {
                // Failed before the request left; the await rethrows it.
                return await open;
            }
            await PumpPeerAsync(cancellationToken);
            await Task.Delay(TimeSpan.FromMilliseconds(5), cancellationToken);
        }
        await Peer.SendStreamFramesAsync(
            [Stream(streamId, 0, ResponseBytes(status, [], []))], cancellationToken);
        return await open;
    }

    /// <summary>Pumps the peer once per datagram the client has sent since the last call, and
    /// never on an empty inbox.</summary>
    /// <param name="cancellationToken">Cancels a pump.</param>
    internal async ValueTask PumpPeerAsync(CancellationToken cancellationToken)
    {
        while (_peerConsumed < ClientTransport.Sent.Count)
        {
            await Peer.PumpOnceAsync(SentAt, cancellationToken);
            _peerConsumed++;
        }
    }

    /// <summary>Pumps the peer until <paramref name="arrived"/> holds; the owner sends on its
    /// own schedule, so a test waits for what it expects rather than pumping a fixed count. The
    /// token bounds the wait.</summary>
    /// <param name="arrived">What the test waits for.</param>
    /// <param name="cancellationToken">Bounds the wait.</param>
    internal async Task PumpPeerUntilAsync(Func<bool> arrived, CancellationToken cancellationToken)
    {
        while (true)
        {
            await PumpPeerAsync(cancellationToken);
            if (arrived())
            {
                return;
            }
            await Task.Delay(TimeSpan.FromMilliseconds(5), cancellationToken);
        }
    }

    /// <summary>RFC 9221 s4's DATAGRAM frame with a Length (type 0x31); every payload here is
    /// under 64 bytes, so the length is a one-byte varint.</summary>
    /// <param name="payload">The frame's payload: quarter stream id, context id, bytes.</param>
    /// <returns>The frame.</returns>
    internal static byte[] DatagramFrame(params byte[] payload) =>
        [0x31, (byte)payload.Length, .. payload];

    /// <summary>Disposes the tunnel and the outer connection, then tears down the peer side and
    /// the transport pair.</summary>
    /// <remarks>No null guard: a dial that failed returned no harness.</remarks>
    public async ValueTask DisposeAsync()
    {
        await Transport.DisposeAsync();
        await Connection.DisposeAsync();
        await Peer.DisposeAsync();
        await _server.DisposeAsync();
        await ClientTransport.DisposeAsync();
        _credential.Dispose();
        _pki.Dispose();
    }

    // The proxy's half, one sequential task: finish the handshake, confirm it, send SETTINGS,
    // wait for the request's HEADERS on stream 0 and answer it. Returns how many datagrams it
    // opened. A dial that refuses the proxy closes the connection instead of sending HEADERS,
    // and the script stops there.
    private static async Task<int> RunScriptAsync(
        LoopbackQuicPeer peer,
        TlsQuicHttp3Setting[] peerSettings,
        int answerStatus,
        bool answerWithReset,
        bool answerWithClose,
        CancellationToken cancellationToken)
    {
        var pumped = 0;
        while (!peer.IsHandshakeComplete)
        {
            await peer.PumpOnceAsync(SentAt, cancellationToken);
            pumped++;
        }
        await peer.SendHandshakeDoneAsync(SentAt, cancellationToken);
        await peer.SendStreamFramesAsync([PeerControl(peerSettings)], cancellationToken);

        while (!peer.ReceivedStreamFrames.Any(frame => frame.StreamId == 0))
        {
            if (peer.LastConnectionClose is not null)
            {
                return pumped;
            }
            await peer.PumpOnceAsync(SentAt, cancellationToken);
            pumped++;
        }

        if (answerWithClose)
        {
            // RFC 9000 s19.19's application CONNECTION_CLOSE: type 0x1d, error code 0x100
            // (H3_NO_ERROR) as a two-byte varint, an empty reason phrase.
            await peer.SendOneRttRawFrameAsync([0x1d, 0x41, 0x00, 0x00], cancellationToken);
            return pumped;
        }

        await peer.SendStreamFramesAsync(
            [
                answerWithReset
                    ? Reset(0, 0, 0x10c)
                    : Stream(0, 0, ResponseBytes(answerStatus, [], [])),
            ],
            cancellationToken);
        return pumped;
    }
}
