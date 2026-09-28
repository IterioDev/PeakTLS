using System.Net;

namespace SharpTls.Quic;

/// <summary>Everything one MASQUE tunnel needs (RFC 9298 CONNECT-UDP over HTTP/3). Internal,
/// like the spec types it carries; TlsClient reaches it through InternalsVisibleTo.</summary>
internal sealed class TlsQuicMasqueOptions
{
    /// <summary>The proxy's QUIC listener, for example a provider's masque host on UDP 50000.
    /// Its host and port are also the CONNECT-UDP request's <c>:authority</c> and the outer
    /// ClientHello's server name.</summary>
    public required DnsEndPoint ProxyEndPoint { get; init; }

    /// <summary>The tunnel's target, written into the RFC 9298 s2 URI template.</summary>
    public required string TargetHost { get; init; }

    /// <summary>The tunnel's target UDP port, written into the RFC 9298 s2 URI template.</summary>
    public required int TargetPort { get; init; }

    /// <summary>Echoed in every receive result; the inner connection never compares it.</summary>
    public required IPEndPoint TargetEndPoint { get; init; }

    /// <summary>The proxy account's user name, sent as HTTP Basic credentials (RFC 7617) in
    /// <c>proxy-authorization</c> (RFC 9110 s11.7.2).</summary>
    public required string Username { get; init; }

    /// <summary>The proxy account's password, sent beside <see cref="Username"/>.</summary>
    public required string Password { get; init; }

    /// <summary>The outer connection's spec: PMTUD off, BasePathMtu = MaximumPathMtu = 1392,
    /// TransportParameters carrying an explicit 0x20 entry.</summary>
    public required TlsQuicConnectionSpec OuterSpec { get; init; }

    /// <summary>The outer HTTP/3 spec; its Settings carry SETTINGS_H3_DATAGRAM = 1.</summary>
    public required TlsQuicHttp3Spec OuterHttp3Spec { get; init; }

    /// <summary>Shapes the outer ClientHello; TlsClient passes its default.</summary>
    public required Action<ClientHelloBuilder> ConfigureOuterClientHello { get; init; }

    /// <summary>Bounds steps 1 to 4 of the dial as one deadline.</summary>
    public TimeSpan HandshakeDeadline { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Tests only: an already-connected outer transport, so no socket is opened and no
    /// name is resolved. The caller keeps ownership and disposes it.</summary>
    internal ITlsQuicDatagramTransport? OuterTransport { get; init; }

    /// <summary>Tests only: the endpoints the dial tries in order through
    /// <see cref="OuterTransport"/>, standing in for the proxy name's resolved addresses (an
    /// in-memory pair drops anything not addressed to its other half, which is how a test makes
    /// an address unreachable). Required when <see cref="OuterTransport"/> is set.</summary>
    internal IReadOnlyList<IPEndPoint>? OuterRemoteEndPoints { get; init; }

    /// <summary>Tests only: skips certificate validation on the outer connection.</summary>
    internal bool DangerouslySkipOuterCertificateValidation { get; init; }
}
