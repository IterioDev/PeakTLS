using System.Net.Sockets;
using System.Diagnostics;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient;

internal sealed class SharpTlsTransport : IAsyncDisposable
{
    private readonly TcpClient? _tcpClient;
    private readonly CustomTlsClient _tlsClient;
    private int _disposed;

    private SharpTlsTransport(
        TcpClient? tcpClient,
        CustomTlsClient tlsClient,
        CustomTlsStream stream,
        TlsConnectionInfo tlsInfo)
    {
        _tcpClient = tcpClient;
        _tlsClient = tlsClient;
        Stream = stream;
        TlsInfo = tlsInfo;
    }

    public CustomTlsStream Stream { get; }

    public TlsConnectionInfo TlsInfo { get; }

    public string? ApplicationProtocol => _tlsClient.NegotiatedApplicationProtocol;

    public static async ValueTask<SharpTlsTransport> ConnectAsync(
        Uri origin,
        TlsHttpVersionPolicy versionPolicy,
        TlsProxy? proxy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        DnsEndpointResolver dnsResolver,
        CancellationToken cancellationToken)
    {
        var connectionId = Guid.NewGuid();
        using var activity = TlsDiagnostics.StartConnection(
            origin,
            connectionId,
            configuration.Profile.Name);
        try
        {
            var transport = await ConnectCoreAsync(
                origin,
                versionPolicy,
                proxy,
                configuration,
                tls13SessionCache,
                    dnsResolver,
                connectionId,
                activity,
                cancellationToken).ConfigureAwait(false);
            TlsDiagnostics.CompleteConnection(activity, transport.TlsInfo);
            return transport;
        }
        catch (Exception exception)
        {
            TlsDiagnostics.RecordFailure(activity, exception);
            throw;
        }
    }

    private static async ValueTask<SharpTlsTransport> ConnectCoreAsync(
        Uri origin,
        TlsHttpVersionPolicy versionPolicy,
        TlsProxy? proxy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        DnsEndpointResolver dnsResolver,
        Guid connectionId,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        if (configuration.EchDnsResolver is not null)
        {
            return await ConnectWithEchDnsAsync(
                origin,
                versionPolicy,
                proxy,
                configuration,
                tls13SessionCache,
                    dnsResolver,
                activity,
                cancellationToken).ConfigureAwait(false);
        }

        TcpClient? tcpClient = null;
        CustomTlsClient? tlsClient = null;
        try
        {
            var connectHost = proxy?.Address.IdnHost ?? origin.IdnHost;
            var connectPort = proxy?.EffectivePort ?? origin.Port;
            var addresses = await dnsResolver.ResolveAsync(
                connectHost,
                connectPort,
                connectionId,
                cancellationToken).ConfigureAwait(false);
            tcpClient = await HappyEyeballsConnector.ConnectAsync(
                addresses,
                connectHost,
                connectPort,
                configuration.HappyEyeballsDelay,
                connectionId,
                configuration.ConnectObserver,
                cancellationToken).ConfigureAwait(false);
            var networkStream = tcpClient.GetStream();

            if (proxy is not null)
            {
                TlsConnectTelemetry.Emit(
                    configuration.ConnectObserver,
                    connectionId,
                    TlsConnectEventKind.ProxyTunnelStarted,
                    connectHost,
                    connectPort);
                var proxyStopwatch = Stopwatch.StartNew();
                try
                {
                    await ProxyTunnel.EstablishAsync(
                        networkStream,
                        origin,
                        proxy,
                        configuration.MaximumResponseHeaderBytes,
                        cancellationToken).ConfigureAwait(false);
                    TlsConnectTelemetry.Emit(
                        configuration.ConnectObserver,
                        connectionId,
                        TlsConnectEventKind.ProxyTunnelCompleted,
                        connectHost,
                        connectPort,
                        elapsed: proxyStopwatch.Elapsed);
                }
                catch (Exception exception)
                {
                    TlsConnectTelemetry.Emit(
                        configuration.ConnectObserver,
                        connectionId,
                        TlsConnectEventKind.ProxyTunnelFailed,
                        connectHost,
                        connectPort,
                        elapsed: proxyStopwatch.Elapsed,
                        exception: exception);
                    throw;
                }
            }

            var tlsOptions = new CustomTlsClientOptions
            {
                ServerName = origin.IdnHost,
                ClientHello = configuration.Profile.GetClientHello(origin.IdnHost, versionPolicy),
                TcpNoDelay = true,
            };
            tlsOptions.CertificateValidation.DangerouslySkipServerCertificateValidation =
                configuration.DangerouslySkipServerCertificateValidation;
            configuration.ConfigureTls?.Invoke(tlsOptions);
            configuration.ClientCertificates.Apply(tlsOptions);
            RequireTls13Only(tlsOptions);
            if (tlsOptions.SessionCache is null && tlsOptions.ClientHello.Spec.SupportsSessionResumption)
            {
                tlsOptions.SessionCache = tls13SessionCache;
            }
            ApplyCertificatePins(tlsOptions, configuration.CertificatePins);
            TlsDiagnostics.AttachHandshakeObserver(
                tlsOptions,
                configuration.HandshakeObserver,
                connectionId,
                origin.IdnHost,
                origin.Port,
                activity);

            tlsClient = new CustomTlsClient(tlsOptions);
            TlsConnectTelemetry.Emit(
                configuration.ConnectObserver,
                connectionId,
                TlsConnectEventKind.TlsHandshakeStarted,
                origin.IdnHost,
                origin.Port);
            var handshakeStopwatch = Stopwatch.StartNew();
            try
            {
                await tlsClient.AuthenticateAsync(
                    networkStream,
                    origin.IdnHost,
                    leaveOpen: false,
                    cancellationToken).ConfigureAwait(false);
                TlsConnectTelemetry.Emit(
                    configuration.ConnectObserver,
                    connectionId,
                    TlsConnectEventKind.TlsHandshakeCompleted,
                    origin.IdnHost,
                    origin.Port,
                    elapsed: handshakeStopwatch.Elapsed,
                    applicationProtocol: tlsClient.NegotiatedApplicationProtocol);
            }
            catch (Exception exception)
            {
                TlsConnectTelemetry.Emit(
                    configuration.ConnectObserver,
                    connectionId,
                    TlsConnectEventKind.TlsHandshakeFailed,
                    origin.IdnHost,
                    origin.Port,
                    elapsed: handshakeStopwatch.Elapsed,
                    exception: exception);
                throw;
            }
            ValidateApplicationProtocol(tlsClient.NegotiatedApplicationProtocol, versionPolicy);

            var state = tlsClient.GetConnectionState();
            var tlsInfo = new TlsConnectionInfo(
                configuration.Profile.Name,
                state.ProtocolVersion,
                state.CipherSuite,
                state.Group,
                state.ApplicationProtocol,
                state.SessionWasResumed,
                state.UsedHelloRetryRequest,
                state.EncryptedClientHelloAccepted,
                state.PeerCertificateChain);
            var stream = tlsClient.OpenApplicationStream(leaveClientOpen: true);
            return new SharpTlsTransport(tcpClient, tlsClient, stream, tlsInfo);
        }
        catch
        {
            if (tlsClient is not null)
            {
                await tlsClient.DisposeAsync().ConfigureAwait(false);
            }
            tcpClient?.Dispose();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            await _tlsClient.CloseAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Closing is best-effort after a response or transport failure.
        }
        await Stream.DisposeAsync().ConfigureAwait(false);
        await _tlsClient.DisposeAsync().ConfigureAwait(false);
        _tcpClient?.Dispose();
    }

    private static async ValueTask<SharpTlsTransport> ConnectWithEchDnsAsync(
        Uri origin,
        TlsHttpVersionPolicy versionPolicy,
        TlsProxy? proxy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        DnsEndpointResolver dnsResolver,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        if (proxy is not null)
        {
            throw new InvalidOperationException(
                "EchDnsResolver cannot route an alternative service through a proxy.");
        }
        if (System.Net.IPAddress.TryParse(origin.IdnHost, out _))
        {
            throw new InvalidOperationException("ECH DNS discovery requires a DNS origin.");
        }

        var resolution = await configuration.EchDnsResolver!
            .ResolveAsync(origin.IdnHost, origin.Port, cancellationToken)
            .ConfigureAwait(false);
        var failures = new List<Exception>();
        foreach (var endpoint in resolution.Endpoints)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await ConnectEchEndpointAsync(
                    origin,
                    endpoint,
                    versionPolicy,
                    configuration,
                    tls13SessionCache,
                            dnsResolver,
                    activity,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        throw new AggregateException(
            $"Every ECH DNS endpoint for '{origin.IdnHost}:{origin.Port}' failed.",
            failures);
    }

    private static async ValueTask<SharpTlsTransport> ConnectEchEndpointAsync(
        Uri origin,
        TlsEchDnsEndpoint endpoint,
        TlsHttpVersionPolicy versionPolicy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        DnsEndpointResolver dnsResolver,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        var failures = new List<Exception>();
        var hints = endpoint.Ipv6Hints
            .Concat(endpoint.Ipv4Hints)
            .Distinct()
            .ToArray();
        if (hints.Length != 0)
        {
            try
            {
                return await ConnectEchAddressSetAsync(
                    origin,
                    endpoint,
                    hints,
                    versionPolicy,
                    configuration,
                    tls13SessionCache,
                            activity,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        try
        {
            var connectionId = Guid.NewGuid();
            var addresses = await dnsResolver.ResolveAsync(
                endpoint.TargetName,
                endpoint.Port,
                connectionId,
                cancellationToken).ConfigureAwait(false);
            return await ConnectEchAddressSetAsync(
                origin,
                endpoint,
                addresses,
                versionPolicy,
                configuration,
                tls13SessionCache,
                    activity,
                cancellationToken,
                connectionId).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        throw new AggregateException(
            $"ECH endpoint '{endpoint.TargetName}:{endpoint.Port}' failed.",
            failures);
    }

    private static async ValueTask<SharpTlsTransport> ConnectEchAddressSetAsync(
        Uri origin,
        TlsEchDnsEndpoint endpoint,
        IReadOnlyList<System.Net.IPAddress> addresses,
        TlsHttpVersionPolicy versionPolicy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        Activity? activity,
        CancellationToken cancellationToken,
        Guid? existingConnectionId = null)
    {
        var connectionId = existingConnectionId ?? Guid.NewGuid();
        TcpClient? tcpClient = null;
        CustomTlsClient? tlsClient = null;
        try
        {
            tcpClient = await HappyEyeballsConnector.ConnectAsync(
                addresses,
                endpoint.TargetName,
                endpoint.Port,
                configuration.HappyEyeballsDelay,
                connectionId,
                configuration.ConnectObserver,
                cancellationToken).ConfigureAwait(false);

            var tlsOptions = new CustomTlsClientOptions
            {
                ServerName = origin.IdnHost,
                ClientHello = configuration.Profile.GetClientHello(
                    origin.IdnHost,
                    versionPolicy),
                TcpNoDelay = true,
            };
            tlsOptions.CertificateValidation.DangerouslySkipServerCertificateValidation =
                configuration.DangerouslySkipServerCertificateValidation;
            configuration.ConfigureTls?.Invoke(tlsOptions);
            configuration.ClientCertificates.Apply(tlsOptions);
            RequireTls13Only(tlsOptions);
            if (tlsOptions.SessionCache is null && tlsOptions.ClientHello.Spec.SupportsSessionResumption)
            {
                tlsOptions.SessionCache = tls13SessionCache;
            }
            ApplyCertificatePins(tlsOptions, configuration.CertificatePins);
            endpoint.ConfigureClient(tlsOptions);
            TlsDiagnostics.AttachHandshakeObserver(
                tlsOptions,
                configuration.HandshakeObserver,
                connectionId,
                origin.IdnHost,
                origin.Port,
                activity);

            tlsClient = new CustomTlsClient(tlsOptions);
            TlsConnectTelemetry.Emit(
                configuration.ConnectObserver,
                connectionId,
                TlsConnectEventKind.TlsHandshakeStarted,
                origin.IdnHost,
                origin.Port);
            var handshakeStopwatch = Stopwatch.StartNew();
            try
            {
                await tlsClient.AuthenticateAsync(
                    tcpClient.GetStream(),
                    origin.IdnHost,
                    leaveOpen: false,
                    cancellationToken).ConfigureAwait(false);
                TlsConnectTelemetry.Emit(
                    configuration.ConnectObserver,
                    connectionId,
                    TlsConnectEventKind.TlsHandshakeCompleted,
                    origin.IdnHost,
                    origin.Port,
                    elapsed: handshakeStopwatch.Elapsed,
                    applicationProtocol: tlsClient.NegotiatedApplicationProtocol);
            }
            catch (Exception exception)
            {
                TlsConnectTelemetry.Emit(
                    configuration.ConnectObserver,
                    connectionId,
                    TlsConnectEventKind.TlsHandshakeFailed,
                    origin.IdnHost,
                    origin.Port,
                    elapsed: handshakeStopwatch.Elapsed,
                    exception: exception);
                throw;
            }
            ValidateApplicationProtocol(tlsClient.NegotiatedApplicationProtocol, versionPolicy);

            var state = tlsClient.GetConnectionState();
            var tlsInfo = new TlsConnectionInfo(
                configuration.Profile.Name,
                state.ProtocolVersion,
                state.CipherSuite,
                state.Group,
                state.ApplicationProtocol,
                state.SessionWasResumed,
                state.UsedHelloRetryRequest,
                state.EncryptedClientHelloAccepted,
                state.PeerCertificateChain);
            var stream = tlsClient.OpenApplicationStream(leaveClientOpen: true);
            return new SharpTlsTransport(tcpClient, tlsClient, stream, tlsInfo);
        }
        catch
        {
            if (tlsClient is not null)
            {
                await tlsClient.DisposeAsync().ConfigureAwait(false);
            }
            tcpClient?.Dispose();
            throw;
        }
    }

    internal static void ValidateApplicationProtocol(
        string? applicationProtocol,
        TlsHttpVersionPolicy versionPolicy)
    {
        // Http3Only never reaches this method: HttpConnectionFactory forks to the QUIC dial
        // before the TCP transport is opened. If it ever does, the connection in hand is a
        // TCP one that can only have negotiated h2 or http/1.1, so fail loudly rather than
        // hand back a downgraded transport.
#pragma warning disable TLSCLIENT3 // HTTP/3 is experimental; the TCP path must still reject it.
        if (versionPolicy == TlsHttpVersionPolicy.Http3Only)
        {
            throw new TlsHttpProtocolException(
                "HTTP/3 was requested but this connection is the TCP transport, which can " +
                "only negotiate 'h2' or 'http/1.1'. TlsClient does not downgrade a pinned " +
                "HTTP/3 request onto TCP.");
        }
#pragma warning restore TLSCLIENT3
        var valid = versionPolicy switch
        {
            TlsHttpVersionPolicy.Http11Only => applicationProtocol is null or "http/1.1",
            TlsHttpVersionPolicy.Http2Only => applicationProtocol == "h2",
            _ => applicationProtocol is null or "http/1.1" or "h2",
        };
        if (!valid)
        {
            throw new TlsHttpProtocolException(
                $"The server selected unsupported ALPN '{applicationProtocol ?? "(none)"}'.");
        }
    }

    /// <summary>Refuses a ClientHello that does not offer TLS 1.3, wherever it came from.</summary>
    /// <remarks>THE CHECK IS HERE BECAUSE THIS IS WHERE EVERY PATH CONVERGES. A profile can be
    /// chosen from TlsProfiles, built with ClientHelloProfiles.Custom, or rewritten in place by
    /// TlsSessionOptions.ConfigureTls, which runs immediately above both call sites - validating
    /// at snapshot time would miss that last one entirely.
    /// <para>Offering 1.2 ALONGSIDE 1.3 is allowed: captured browser and app hellos do exactly
    /// that (the Spotify iOS h2 hello lists 1.3 and 1.2), and refusing them made every such
    /// preset undialable. A server that answers with a 1.2 ServerHello is refused by SharpTls
    /// at the handshake (CustomTlsClient), so no downgrade path exists. What stays refused here
    /// is a hello with no 1.3 at all - that one could never complete.</para></remarks>
    private static void RequireTls13Only(CustomTlsClientOptions tlsOptions)
    {
        if (!tlsOptions.ClientHello.Spec.SupportedVersions.Contains(
                SharpTls.Protocol.TlsProtocolVersion.Tls13))
        {
            throw new InvalidOperationException(
                "This client speaks TLS 1.3 only, and the ClientHello does not offer it. " +
                "Add TLS 1.3 to the profile, or to what ConfigureTls writes onto it.");
        }
    }

    private static void ApplyCertificatePins(
        CustomTlsClientOptions options,
        TlsCertificatePins pins)
    {
        if (!pins.HasPins)
        {
            return;
        }

        var validation = options.CertificateValidation ??
            throw new InvalidOperationException("ConfigureTls set CertificateValidation to null.");
        var existing = validation.EvidenceValidator;
        validation.EvidenceValidator = async (evidence, cancellationToken) =>
        {
            var result = existing is null
                ? new TlsServerCertificateEvidenceValidationResult(
                    TlsStapledOcspValidationStatus.NotChecked,
                    0)
                : await existing(evidence, cancellationToken).ConfigureAwait(false);
            pins.Validate(evidence);
            return result;
        };
    }

}
