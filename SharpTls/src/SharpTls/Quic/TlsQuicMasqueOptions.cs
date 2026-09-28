using System.Net;

namespace SharpTls.Quic;

/// <summary>TEMPORARY STUB for parallel TlsClient work; the real type lands on another branch
/// and replaces this file before merge. Options for one RFC 9298 CONNECT-UDP tunnel.</summary>
internal sealed class TlsQuicMasqueOptions
{
    /// <summary>Gets the MASQUE proxy's host and UDP port.</summary>
    public required DnsEndPoint ProxyEndPoint { get; init; }

    /// <summary>Gets the target host named in the CONNECT-UDP request.</summary>
    public required string TargetHost { get; init; }

    /// <summary>Gets the target port named in the CONNECT-UDP request.</summary>
    public required int TargetPort { get; init; }

    /// <summary>Gets the endpoint reported as the source of every decapsulated datagram.</summary>
    public required IPEndPoint TargetEndPoint { get; init; }

    /// <summary>Gets the proxy username.</summary>
    public required string Username { get; init; }

    /// <summary>Gets the proxy password.</summary>
    public required string Password { get; init; }

    /// <summary>Gets the outer QUIC connection's spec.</summary>
    public required TlsQuicConnectionSpec OuterSpec { get; init; }

    /// <summary>Gets the outer HTTP/3 connection's spec.</summary>
    public required TlsQuicHttp3Spec OuterHttp3Spec { get; init; }

    /// <summary>Gets the outer ClientHello's configuration.</summary>
    public required Action<ClientHelloBuilder> ConfigureOuterClientHello { get; init; }

    /// <summary>Gets how long the tunnel has to come up.</summary>
    public TimeSpan HandshakeDeadline { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Gets a test-only replacement for the outer UDP transport.</summary>
    internal ITlsQuicDatagramTransport? OuterTransport { get; init; }

    /// <summary>Gets a test-only replacement for the proxy's resolved address.</summary>
    internal IPEndPoint? OuterRemoteEndPoint { get; init; }

    /// <summary>Gets whether the outer certificate check is skipped, for tests only.</summary>
    internal bool DangerouslySkipOuterCertificateValidation { get; init; }
}
