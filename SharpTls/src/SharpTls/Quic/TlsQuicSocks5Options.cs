using System.Net;

namespace SharpTls.Quic;

/// <summary>Which source addresses a relayed reply datagram may arrive from.</summary>
/// <remarks>
/// <para>RFC 1928 SAYS NOTHING ABOUT THE REPLY'S SOURCE, AND THAT IS THE WHOLE REASON THIS
/// KNOB EXISTS. Every sentence in section 7 that names BND is about the direction this client
/// SENDS: "In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR fields indicate
/// the port number/address where the client MUST send UDP request messages to be relayed",
/// and "A UDP-based client MUST send its datagrams to the UDP relay server at the UDP port
/// indicated by BND.PORT in the reply to the UDP ASSOCIATE request." For the return direction
/// the section says only "When a UDP relay server receives a reply datagram from a remote
/// host, it MUST encapsulate that datagram using the above UDP request header" - what it must
/// put IN the datagram, never what source it must come FROM.</para>
/// <para>THE ONE SOURCE-CHECKING MUST IN SECTION 7 POINTS THE OTHER WAY AND IS ADDRESS-ONLY:
/// "The UDP relay server MUST acquire from the SOCKS server the expected IP address of the
/// client that will send datagrams to the BND.PORT given in the reply to UDP ASSOCIATE. It
/// MUST drop any datagrams arriving from any source IP address other than the one recorded
/// for the particular association." That is an obligation on the SERVER, about the CLIENT's
/// address, and even there it is stated as an IP address with no mention of a port.
/// <see cref="AddressOnly"/> is that same rule turned around to face the relay.</para>
/// <para>AND SECTION 6 ALREADY WARNS THAT BND NEED NOT BE WHAT YOU SEE: "The supplied
/// BND.ADDR is often different from the IP address that the client uses to reach the SOCKS
/// server, since such servers are often multi-homed." A pooled or load-balanced relay extends
/// that to the port, and commonly to a sibling address in the same pool - so a strict equality
/// test on BND drops legitimate traffic from a conforming-enough proxy, and drops it silently.
/// </para>
/// </remarks>
public enum TlsQuicSocks5RelaySource
{
    /// <summary>Accept only a source equal to BND.ADDR and BND.PORT.</summary>
    /// <remarks>The strictest reading, and stricter than RFC 1928 requires - see the type's
    /// remarks. Correct against a single-homed relay that replies from the socket it
    /// advertised; against a pooled one it discards every reply and the connection stalls with
    /// no error, which is exactly what
    /// <see cref="TlsQuicSocks5Transport.DatagramsFromUnexpectedSource"/> exists to reveal.
    /// </remarks>
    Exact,

    /// <summary>Accept any source whose address equals BND.ADDR, whatever its port. The
    /// default.</summary>
    /// <remarks>Mirrors section 7's own address-only rule for the opposite direction, and
    /// covers the common pooled-relay case of a reply sent from a different ephemeral port on
    /// the advertised host. A forged datagram must still originate from the relay's own
    /// address to reach the QUIC layer.</remarks>
    AddressOnly,

    /// <summary>Accept a datagram from any source whatsoever.</summary>
    /// <remarks>FOR A RELAY POOL THAT ANSWERS FROM A SIBLING ADDRESS, and nothing else. This
    /// socket is bound to a wildcard address and is therefore reachable by any host that can
    /// route to it, so this setting lets an off-path attacker hand arbitrary bytes to the QUIC
    /// packet layer; RFC 9001's AEAD is then the only thing rejecting them, counting each one
    /// into <c>TlsQuicConnection.DiscardedPackets</c>. Reach for this only after
    /// <see cref="TlsQuicSocks5Transport.LastUnexpectedSource"/> has shown which address the
    /// pool actually replies from.</remarks>
    Any,
}

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

    /// <summary>Gets which source addresses a relayed reply may arrive from. Defaults to
    /// <see cref="TlsQuicSocks5RelaySource.AddressOnly"/>.</summary>
    /// <remarks>The default is the loosest policy that still requires the datagram to come
    /// from the host the proxy named; <see cref="TlsQuicSocks5RelaySource"/> has the RFC 1928
    /// sentences the three settings are read from. Whichever is set, a datagram this policy
    /// rejects is counted into
    /// <see cref="TlsQuicSocks5Transport.DatagramsFromUnexpectedSource"/> rather than
    /// vanishing.</remarks>
    public TlsQuicSocks5RelaySource RelaySource { get; init; } = TlsQuicSocks5RelaySource.AddressOnly;
}
