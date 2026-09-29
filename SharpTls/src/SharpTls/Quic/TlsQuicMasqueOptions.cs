using System.Net;

namespace SharpTls.Quic;

/// <summary>Everything one outer MASQUE connection needs (RFC 9298 CONNECT-UDP over HTTP/3):
/// the proxy, the credentials every tunnel on it sends, and the outer connection's shape. A
/// tunnel's target is given to <see cref="TlsQuicMasqueConnection.OpenTunnelAsync"/>. Internal,
/// like the spec types it carries; TlsClient reaches it through InternalsVisibleTo.</summary>
internal sealed class TlsQuicMasqueOptions
{
    /// <summary>The proxy's QUIC listener, for example a provider's masque host on UDP 50000.
    /// Its host and port are also the CONNECT-UDP request's <c>:authority</c> and the outer
    /// ClientHello's server name.</summary>
    public required DnsEndPoint ProxyEndPoint { get; init; }

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

    /// <summary>Bounds the outer dial per proxy address (the QUIC handshake, then the proxy's
    /// SETTINGS), and each tunnel's open on its own (the CONNECT-UDP response).</summary>
    public TimeSpan HandshakeDeadline { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>A ceiling on the inner UDP payload below the one the outer connection's frame
    /// budget gives, for a proxy whose guide states a smaller number than the arithmetic
    /// allows; <see langword="null"/> keeps the arithmetic. Never below RFC 9000 s14.1's 1200,
    /// which an inner Initial needs.</summary>
    public int? InnerDatagramCeiling { get; init; }

    /// <summary>Resolves the proxy name, or <see langword="null"/> for the system resolver.
    /// TlsClient passes the session's own, so the proxy hop follows the same resolution policy
    /// as everything else the session dials.</summary>
    public Func<string, CancellationToken, ValueTask<IReadOnlyList<IPAddress>>>? ProxyResolver { get; init; }

    /// <summary>How long one lookup of the proxy name serves every outer dial in the process.
    /// Zero looks the name up for every dial; <see cref="Timeout.InfiniteTimeSpan"/> keeps the
    /// first answer.</summary>
    /// <remarks>Longer than the records' own lifetime on purpose. A provider's front publishes
    /// its addresses for seconds (ten, measured), so a resolver cache is empty again for the
    /// next wave of dials, and a lookup that takes seconds on a host with a slow resolver in
    /// its list is then paid inside every dial's deadline. An address that stops answering
    /// costs one deadline and the dial moves to the next; when none answers, the name is
    /// forgotten and looked up afresh.</remarks>
    public TimeSpan ProxyAddressLifetime { get; init; } = TimeSpan.FromMinutes(1);

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
