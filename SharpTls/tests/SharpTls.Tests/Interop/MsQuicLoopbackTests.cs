using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using SharpTls.Protocol;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;

// System.Net.Security has its own TlsCipherSuite - the platform's enumeration of negotiated
// suites - and pulling that namespace in for SslServerAuthenticationOptions makes the bare name
// ambiguous. Ours is the one this file means.
using TlsCipherSuite = SharpTls.Protocol.TlsCipherSuite;

namespace SharpTls.Tests.Interop;

// A4-minimal task 10: THE MSQUIC LOOPBACK GATE.
//
// The first evidence this repo has from a QUIC implementation we did not write. Everything
// before it proved our client agrees with our own peer (LoopbackQuicPeer) or with bytes we
// hand-wrote ourselves (ScriptedDatagramTransport), and agreeing with yourself is not
// evidence. MsQuic is offline, deterministic and costs a few hundred milliseconds, so unlike
// task 13's live run it belongs in the gate rather than behind SHARPTLS_RUN_INTEROP=1.
//
// A GREEN RUN HERE IS EVIDENCE OF CONFORMANCE, NOT OF FINGERPRINT FIDELITY. MsQuic accepts
// many packet layouts that are nothing like Chromium's - it does not care how we split CRYPTO
// frames, which varint widths we chose, how we coalesced packets into datagrams or how we
// ordered transport parameters. Passing this test says our datagrams are legal QUIC. It says
// nothing whatsoever about whether they look like the target. Task 11's readout is the only
// place fidelity is measured, and this file cannot substitute for it.
//
// TWO THINGS THIS GATE CANNOT DO, both because of what MsQuic is rather than what we wrote:
//
//   1. IT WILL NOT PRODUCE A RETRY ON DEMAND. MsQuic sends Retry only when its own address
//      validation heuristics ask for it - under load, or when configured as a server that
//      always retries, which System.Net.Quic exposes no knob for. A loopback listener with no
//      load never retries.
//   2. IT WILL NOT PRODUCE A VERSION NEGOTIATION PACKET ON DEMAND. We offer exactly the
//      version it speaks, so there is nothing to negotiate, and System.Net.Quic exposes no way
//      to make a listener refuse a version.
//
// Both are why task 9b drives Retry and Version Negotiation from ScriptedDatagramTransport
// with hand-built Initial-level bytes instead of from a real peer. Neither is a gap in this
// test; they are the reason the scripted transport exists.

/// <summary>
/// A <see cref="QuicListener"/> on loopback, set up so our QUIC client can complete a
/// handshake against it, and shaped to be reused - C11 drives a whole HTTP/3 request and
/// response over this same fixture, so the listener setup is callable rather than welded
/// into one test.
/// </summary>
/// <remarks>
/// <para>THE THREE SETUP REQUIREMENTS, each of which fails in a way that does not name
/// itself:</para>
/// <para>1. THE SERVER CERTIFICATE NEEDS A USABLE PRIVATE KEY.
/// <c>CreateSelfSigned</c> alone is not enough on Windows: the handle it produces is not one
/// Schannel will sign with. <see cref="TestPki.CreateLeafWithPrivateKeyForPlatformTls"/>
/// already solves exactly this for the managed TLS servers in this folder - it exports a PFX
/// and re-imports through <c>X509CertificateLoader</c> - so this fixture reuses it rather than
/// growing a second copy. It re-imports with <c>UserKeySet | Exportable</c>, NOT
/// <c>EphemeralKeySet</c>: an ephemeral key is not persisted and Schannel, which is what
/// MsQuic uses on Windows, cannot sign with one.</para>
/// <para>2. ALPN MUST BE EXPLICIT ON BOTH SIDES. MsQuic FAILS the handshake on an ALPN
/// mismatch rather than negotiating nothing, so a missing <c>h3</c> on either side reads as a
/// generic handshake failure. Nothing under src/ offers h3 in a profile - the builder method
/// is the only route - so the client below calls <c>.WithAlpn("h3")</c> and the listener lists
/// the same protocol. The test asserts the SERVER's negotiated protocol, because that is the
/// only proof that MsQuic parsed our ALPN extension rather than ignoring it.</para>
/// <para>3. OUR CLIENT MUST ACCEPT A SELF-SIGNED CERTIFICATE. That is
/// <c>DangerouslySkipServerCertificateValidation</c>, and it is set here and nowhere outside
/// tests: no file under src/, samples/, benchmarks/ or tools/ assigns it, its default is
/// false, and <see cref="CustomTlsServerOptions"/> throws if a server is handed it.</para>
/// <para>A FOURTH REQUIREMENT THE PLAN DID NOT NAME, AND IT IS MEASURED RATHER THAN ASSERTED:
/// <c>MaxInboundUnidirectionalStreams</c> below is what MsQuic advertises as
/// <c>initial_max_streams_uni</c>, System.Net.Quic DEFAULTS IT TO 0, and
/// TlsQuicConnectionOptions.RequiredPeerUnidirectionalStreams defaults to 3 - RFC 9114 s6.2's
/// control, encoder and decoder streams. Setting it to 0 was run, and the handshake fails at
/// OUR end after TLS has already succeeded, with
/// <c>InvalidOperationException: "... the peer advertised initial_max_streams_uni (0x09) of 0
/// against the 3 this connection needs"</c>. So a QuicServerConnectionOptions written the
/// obvious way is rejected by us, correctly, and the failure names transport parameters rather
/// than a stream limit. That is the trap this fixture exists to have sprung once.</para>
/// <para>The three platform attributes are what CA1416 wants and are not a second gate:
/// System.Net.Quic is annotated as Windows/Linux/macOS-only, and the runtime gate is
/// <see cref="MsQuicLoopbackFactAttribute"/>'s <c>QuicListener.IsSupported</c> check, which
/// catches the far more common case of a supported OS with msquic absent.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("osx")]
internal sealed class MsQuicLoopbackServer : IAsyncDisposable
{
    private const string Alpn = "h3";

    /// <summary>Generous for loopback on purpose: a deadline this test hits is a hang, not a
    /// slow network, and A4-minimal has no retransmission to wait for.</summary>
    internal static readonly TimeSpan HandshakeDeadline = TimeSpan.FromSeconds(10);

    private readonly TestPki _pki;
    private readonly X509Certificate2 _certificate;
    private readonly QuicListener _listener;
    private readonly CancellationTokenSource _stopping = new();
    private readonly Channel<QuicConnection> _accepted =
        Channel.CreateUnbounded<QuicConnection>();
    private readonly Task _acceptLoop;

    private MsQuicLoopbackServer(TestPki pki, X509Certificate2 certificate, QuicListener listener)
    {
        _pki = pki;
        _certificate = certificate;
        _listener = listener;
        _acceptLoop = AcceptLoopAsync();
    }

    /// <summary>Where the listener actually bound. Port 0 above means the OS picks, so
    /// concurrent test classes cannot collide on a port.</summary>
    internal IPEndPoint EndPoint => _listener.LocalEndPoint;

    internal static async Task<MsQuicLoopbackServer> StartAsync()
    {
        var pki = TestPki.Create(dnsName: "localhost");
        X509Certificate2? certificate = null;
        try
        {
            certificate = pki.CreateLeafWithPrivateKeyForPlatformTls();
            var serverOptions = new QuicServerConnectionOptions
            {
                // H3_NO_ERROR / H3_REQUEST_CANCELLED. System.Net.Quic requires both to be set
                // explicitly; it throws rather than defaulting them.
                DefaultCloseErrorCode = 0x100,
                DefaultStreamErrorCode = 0x10c,
                // See the remarks: these two become initial_max_streams_uni and
                // initial_max_streams_bidi. Uni must be at least 3 or our own client rejects
                // the peer; bidi is what lets C11's request stream be opened.
                MaxInboundUnidirectionalStreams = 16,
                MaxInboundBidirectionalStreams = 16,
                ServerAuthenticationOptions = new SslServerAuthenticationOptions
                {
                    ApplicationProtocols = [new SslApplicationProtocol(Alpn)],
                    ServerCertificate = certificate,
                },
            };
            var listener = await QuicListener.ListenAsync(new QuicListenerOptions
            {
                ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
                ApplicationProtocols = [new SslApplicationProtocol(Alpn)],
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
            });
            return new MsQuicLoopbackServer(pki, certificate, listener);
        }
        catch
        {
            certificate?.Dispose();
            pki.Dispose();
            throw;
        }
    }

    /// <summary>The next connection MsQuic finished a handshake for. The caller owns and
    /// disposes it.</summary>
    /// <remarks>The accept loop runs continuously rather than being started per call, because
    /// MsQuic drives the handshake itself and a listener nobody is accepting from stops
    /// admitting connections once its backlog fills.</remarks>
    internal ValueTask<QuicConnection> AcceptAsync(CancellationToken cancellationToken) =>
        _accepted.Reader.ReadAsync(cancellationToken);

    /// <summary>Runs one whole client connection to this listener and returns it connected.
    /// The transport is the CALLER's to dispose - TlsQuicConnection documents its transport as
    /// not owned - which is why it is a parameter rather than created here.</summary>
    internal async Task<TlsQuicConnection> ConnectAsync(
        ITlsQuicDatagramTransport transport,
        CancellationToken cancellationToken = default)
    {
        // PaddingTarget is RFC 9000 s14.1's 1200-byte floor; MsQuic drops a smaller Initial
        // without answering. Every other knob is the spec's default.
        var spec = new TlsQuicConnectionSpec { PaddingTarget = 1200 };
        var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(transport, EndPoint, spec)
            {
                HandshakeDeadline = HandshakeDeadline,
                IdleTimeout = HandshakeDeadline,
            },
            CreateClient);
        try
        {
            await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>A fresh client per connection, carrying THIS connection's source connection ID
    /// as initial_source_connection_id (RFC 9000 s7.3 makes it mandatory and MsQuic checks
    /// it).</summary>
    private static CustomTlsQuicClient CreateClient(ReadOnlyMemory<byte> sourceConnectionId) =>
        new(new CustomTlsQuicClientOptions
        {
            // The certificate says CN=localhost, but validation is off below, so this name is
            // only what goes in SNI.
            ServerName = "localhost",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(
                    TlsCipherSuite.TlsAes128GcmSha256,
                    TlsCipherSuite.TlsAes256GcmSha384)
                .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1)
                // KEY SHARES FOR BOTH GROUPS, not just the preferred one. A4-minimal sends one
                // ClientHello and has no HelloRetryRequest path, so a group MsQuic's platform
                // provider does not implement - Schannel's x25519 support is version-dependent
                // - would end the attempt with an error that looks like loss.
                .WithKeyShares(NamedGroup.X25519, NamedGroup.Secp256r1)
                .WithAlpn(Alpn)
                .WithQuicTransportParameters(new TlsQuicTransportParameters(
                [
                    new TlsQuicTransportParameter(
                        (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
                        sourceConnectionId.ToArray()),
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.ActiveConnectionIdLimit, 2),

                    // RFC 9221 s3's 0x20 IS HERE FOR THE SAME REASON THE FLOW-CONTROL LIMITS
                    // BELOW ARE, and it was missed for the same reason. Every HTTP/3 caller of
                    // this fixture sends SharpTls.Tests.Quic.TestHttp3Settings.DatagramCapable, whose 51:1 claims
                    // willingness to receive HTTP/3 datagrams; 0x20 is the transport half of
                    // that claim and TlsQuicHttp3Connection now refuses one half without the
                    // other. MsQuic tolerates the inconsistent pair - which is precisely why
                    // this fixture never noticed, and why fp.impersonate.pro's 0x109 was the
                    // first thing that did. 65536 is a client capture's value, cited by
                    // TlsQuicTransportParameterSpec.RfcMinimumParameters row 3.
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.MaxDatagramFrameSize, 65536),

                    // THE FLOW-CONTROL LIMITS ARE HERE FOR C11, NOT FOR THE HANDSHAKE. Without
                    // them every peer limit defaults to 0, the server may open no stream and
                    // send no byte, and HTTP/3 cannot start at all - the finding the throwaway
                    // Http3GetSpike produced. A handshake-only test never notices, which is
                    // exactly why they are set in the shared fixture rather than in C11.
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.InitialMaxData, 1 << 20),
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal, 1 << 20),
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote, 1 << 20),
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.InitialMaxStreamDataUni, 1 << 20),
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.InitialMaxStreamsUni, 16),
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.InitialMaxStreamsBidi, 0),
                ]))),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                // Setup requirement 3. The certificate is self-signed and generated at test
                // start, so there is no chain to build and no responder to ask. This is the
                // only kind of path this option appears on.
                DangerouslySkipServerCertificateValidation = true,
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (true)
            {
                var connection = await _listener
                    .AcceptConnectionAsync(_stopping.Token)
                    .ConfigureAwait(false);
                await _accepted.Writer.WriteAsync(connection, _stopping.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Disposal.
        }
        catch (ObjectDisposedException)
        {
            // Disposal raced the pending accept.
        }
        finally
        {
            _accepted.Writer.TryComplete();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        await _listener.DisposeAsync().ConfigureAwait(false);
        await _acceptLoop.ConfigureAwait(false);
        while (_accepted.Reader.TryRead(out var connection))
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
        _stopping.Dispose();
        _certificate.Dispose();
        _pki.Dispose();
    }
}

[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("osx")]
public sealed class MsQuicLoopbackTests
{
    /// <summary>
    /// Two connections rather than one, against the same listener: "repeatable" is part of
    /// what this gate is for, and a fixture C11 reuses has to survive being used twice.
    /// </summary>
    [MsQuicLoopbackFact]
    public async Task OurQuicClientCompletesAHandshakeAgainstMsQuicOnLoopback()
    {
        await using var server = await MsQuicLoopbackServer.StartAsync();

        for (var attempt = 1; attempt <= 2; attempt++)
        {
            using var timeout = new CancellationTokenSource(
                MsQuicLoopbackServer.HandshakeDeadline + TimeSpan.FromSeconds(10));
            await using var transport =
                TlsQuicUdpDatagramTransport.Create(server.EndPoint.AddressFamily);

            // A FAILURE HERE IS A FINDING ABOUT OUR CLIENT, NOT A REASON TO LOOSEN THE TEST.
            // MsQuic is the reference; if it refuses what we sent, we sent something illegal.
            await using var connection = await server.ConnectAsync(transport, timeout.Token);
            await using var accepted = await server.AcceptAsync(timeout.Token);

            Assert.True(connection.IsHandshakeComplete, $"attempt {attempt}: TLS did not finish.");
            // Confirmed, not merely complete: RFC 9001 s4.1.2 confirms a client's handshake on
            // a received HANDSHAKE_DONE, and only a real peer sends one unprompted.
            Assert.True(
                connection.IsHandshakeConfirmed,
                $"attempt {attempt}: no HANDSHAKE_DONE was received from MsQuic.");
            // The server's view, which is the half we cannot fake: MsQuic parsed our ALPN
            // extension and picked h3 out of it.
            Assert.Equal(new SslApplicationProtocol("h3"), accepted.NegotiatedApplicationProtocol);
            // Not a style assertion. DiscardedForMissingKeys counts packets that met no keys -
            // the coalescing stall - and on a lossless loopback link a non-zero value is a bug
            // report about our key schedule, not about the peer.
            Assert.Equal(0, connection.DiscardedForMissingKeys);
        }
    }
}

/// <summary>Skips, and never fails, where System.Net.Quic cannot run - msquic is absent, the
/// platform TLS provider is too old, or the OS is unsupported.</summary>
public sealed class MsQuicLoopbackFactAttribute : FactAttribute
{
    public MsQuicLoopbackFactAttribute()
    {
        if (!QuicListener.IsSupported)
        {
            Skip = "System.Net.Quic's QuicListener is unsupported on this runtime "
                + "(msquic missing, or the platform TLS provider lacks TLS 1.3), so there is "
                + "no foreign QUIC implementation to test against here.";
        }
    }
}
