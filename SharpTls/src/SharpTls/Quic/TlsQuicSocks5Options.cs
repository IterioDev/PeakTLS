using System.Net;

namespace SharpTls.Quic;

/// <summary>Configuration for a SOCKS5 UDP relay.</summary>
public sealed class TlsQuicSocks5Options
{
    /// <summary>Gets the SOCKS5 server. A <see cref="DnsEndPoint"/> is resolved for the
    /// TCP control connection.</summary>
    public required EndPoint ProxyEndPoint { get; init; }

    /// <summary>Gets the RFC 1929 username, 1 to 255 bytes when encoded as UTF-8.</summary>
    public string? Username { get; init; }

    /// <summary>
    /// Gets the destination host name to put in every relayed datagram header, or null to send
    /// the resolved literal address.
    /// </summary>
    /// <remarks>
    /// RFC 1928 section 7 allows ATYP=DOMAINNAME in the UDP request header, and some proxies
    /// REQUIRE it: a commercial pool whose ruleset forbids literal-address destinations closes
    /// the control connection the moment an IPv4 header arrives, which surfaces as the
    /// association ending rather than as a refusal. Setting this makes the PROXY resolve the
    /// name, so DNS moves off this host - deliberately, and it is the only way such a proxy
    /// will carry the traffic.
    /// </remarks>
    public string? DestinationHost { get; init; }

    /// <summary>Gets the RFC 1929 password, 1 to 255 bytes when encoded as UTF-8.</summary>
    public string? Password { get; init; }
}
