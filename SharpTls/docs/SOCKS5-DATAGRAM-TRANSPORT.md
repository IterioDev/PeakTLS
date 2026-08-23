# QUIC datagram transport and SOCKS5 UDP relay

`ITlsQuicDatagramTransport` is the datagram seam the QUIC transport is written against, so
it never references `System.Net.Sockets.Socket` directly. Two implementations ship in
`SharpTls.Quic`: `TlsQuicUdpDatagramTransport` sends and receives directly over a UDP
socket, and `TlsQuicSocks5Transport` relays the same traffic through a SOCKS5 UDP
association (RFC 1928 §4, RFC 1929). Both are interchangeable behind the interface; the
proxy is invisible above it.

## `ITlsQuicDatagramTransport`

```csharp
public interface ITlsQuicDatagramTransport : IAsyncDisposable
{
    int MaxDatagramPayloadSize { get; }

    ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken);

    ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken);
}
```

`MaxDatagramPayloadSize` is an endpoint ceiling, not a path MTU — QUIC path MTU discovery
operates below this value. `SendAsync` throws `ArgumentOutOfRangeException` when the
payload exceeds it.

`TlsQuicDatagramReceiveResult.RemoteEndPoint` reports the decapsulated origin address so
that everything above this seam — path validation, `preferred_address` handling,
connection migration — compares against the address QUIC actually negotiated, never the
relay.

**Threading rule.** One concurrent send and one concurrent receive are permitted; the
shipped implementations perform no internal locking. A second concurrent call to the same
method is a caller error, not a guarded condition.

**Disposal behaviour.** Disposing the transport while a `SendAsync` or `ReceiveAsync` call
is pending causes that call to fault rather than complete. The exact exception type is
platform-dependent: it comes from the underlying socket's own reaction to being disposed
out from under a pending operation, which .NET does not normalize across platforms. Do not
match on a specific exception type to detect this condition.

## `TlsQuicSocks5Options`

```csharp
public sealed class TlsQuicSocks5Options
{
    public required EndPoint ProxyEndPoint { get; init; }
    public string? Username { get; init; }
    public string? Password { get; init; }
}
```

`ProxyEndPoint` accepts a `DnsEndPoint`, which is resolved for the TCP control connection.
`Username` and `Password` must both be supplied or both omitted — `TlsQuicSocks5Transport.
ConnectAsync` throws `ArgumentException` otherwise. RFC 1929 §2 gives `ULEN` and `PLEN` a
range of 1 to 255 encoded UTF-8 bytes, so an empty username or password is also rejected;
there is no representable zero-length field.

## Association sequence

Every field value below is taken from RFC 1928 §3, §4 and RFC 1929 §2:

```
   TCP connect to ProxyEndPoint
-> 05 | NMETHODS | METHODS...        00 always offered; 02 also offered iff credentials set
<- 05 | METHOD                       X'FF' means no acceptable method
   [when METHOD = 02]
-> 01 | ULEN | UNAME | PLEN | PASSWD  VER is X'01', the subnegotiation version, not X'05'
<- 01 | STATUS                       X'00' success; any other value, the server closes
-> 05 | 03 | 00 | ATYP | DST.ADDR | DST.PORT      CMD X'03' is UDP ASSOCIATE
<- 05 | REP | 00 | ATYP | BND.ADDR | BND.PORT     REP X'00' is success
```

The RFC 1929 subnegotiation, when the proxy selects username/password authentication,
carries its own version octet — `VER = 0x01` — distinct from the `0x05` SOCKS version used
everywhere else in the exchange. Confusing the two is the most common way to misread a
capture of this handshake.

`CMD = 0x03` requests UDP ASSOCIATE. `DST.ADDR`/`DST.PORT` in that request encode the
address and port the client already knows it will send from; SharpTls always sends zeros
here (see below). The reply's `BND.ADDR`/`BND.PORT` is the endpoint the client must send
encapsulated UDP datagrams to.

## Behaviours deployed relays require that RFC 1928 does not state

RFC 1928 is not a complete specification of deployed relay behaviour. Three additional
rules are load-bearing and are exactly the kind of thing a future reader, working only
from the RFC text, would be tempted to "fix" back into breakage.

1. **A wildcard `BND.ADDR` means "the host you are already talking to."** Relays commonly
   answer the ASSOCIATE reply with `0.0.0.0` or `::` rather than restating their own
   address. When `BND.ADDR` is the unspecified address, SharpTls substitutes the IP address
   of the TCP control connection's remote endpoint. This includes the IPv4-mapped form
   `::ffff:0.0.0.0`: `IPAddress.Equals` compares family and bytes exactly and does not
   normalize that form to `0.0.0.0`, so the mapped address is unwrapped with `MapToIPv4()`
   before the wildcard check runs. Skipping this step sends every datagram to a null route
   and the association appears to succeed while nothing ever arrives.

2. **`DST.ADDR`/`DST.PORT` in the ASSOCIATE request are always all-zero.** RFC 1928 states:
   "If the client is not in possession of the information at the time of the UDP ASSOCIATE,
   the client MUST use a port number and address of all zeros." SharpTls treats this as
   unconditional rather than a policy flag — a bound local port is usually rewritten by NAT
   before the relay observes it, so reporting it causes more association failures than it
   would prevent. If a relay is ever found that rejects all-zero fields, a flag is the right
   fix at that point, not a default change.

3. **The IPv4 Don't Fragment bit is set where the platform allows it**, per RFC 9000 §14:
   "In IPv4, the Don't Fragment (DF) bit MUST be set if possible." `TlsQuicUdpDatagramTransport`
   and `TlsQuicSocks5Transport` both set `Socket.DontFragment = true` for
   `AddressFamily.InterNetwork` and tolerate a `SocketException` where the platform refuses
   to honor it. This does not apply to IPv6: IPv6 routers do not fragment in transit, so
   there is no DF-equivalent bit to set.

## The size budget

This is the one interaction where SOCKS5 can silently break QUIC. RFC 9000 §14.1 requires
a client to expand the payload of every UDP datagram carrying an Initial packet to at least
1200 bytes. The RFC 1928 §7 UDP request header adds 10 bytes for IPv4 or 22 bytes for IPv6
on top of that.

| Hop | Bytes, IPv4 | Bytes, IPv6 | Derivation |
| --- | --- | --- | --- |
| QUIC Initial datagram payload | 1200 | 1200 | RFC 9000 §14.1 minimum |
| client to relay, UDP payload | 1210 | 1222 | plus 10-byte (IPv4) / 22-byte (IPv6) SOCKS5 header |
| client to relay, IP packet with DF set | 1238 | 1270 | plus 20-byte IPv4/8-byte UDP or 40-byte IPv6/8-byte UDP headers |
| relay to origin, UDP payload | 1200 | 1200 | relay strips the SOCKS5 header |

The origin always observes a conforming 1200-byte-minimum datagram; the relay strips the
encapsulation before forwarding. The client-to-relay path is where the budget is tight: it
must carry 1210 (IPv4) or 1222 (IPv6) UDP payload bytes without fragmentation. If that path
is itself tunnelled below this size, the QUIC handshake cannot complete — this is a
documented deployment limit, not something the transport can work around. Shrinking the
Initial datagram to fit would violate RFC 9000 §14.1, and the server is required to discard
an underweight Initial rather than process it.

`MaxDatagramPayloadSize` already accounts for this: it is the socket receive ceiling minus
the 10- or 22-byte header for the transport's address family, so QUIC's PMTU logic and its
`max_udp_payload_size` transport parameter both see the correct number without needing to
know a proxy is involved.

## Inbound validation

A received datagram is **discarded, and the receive continues waiting**, when any of the
following holds. None of these fail the connection:

1. The source is not the relay's `BND` endpoint.
2. `RSV != 0x0000`.
3. `FRAG != 0x00`. RFC 1928 §7 permits this: "an implementation that does not support
   fragmentation MUST drop any datagram whose FRAG field is other than X'00'."
4. `ATYP` is neither `0x01` nor `0x04`. SharpTls never sends `ATYP = 0x03` (DOMAINNAME), so
   one appearing in a reply header is already anomalous.
5. The declared header extends past the end of the datagram.

Discarding rather than failing is what RFC 9000 §14 prescribes for datagrams that do not
meet expectations: "an endpoint MUST NOT close a connection when it receives a datagram
that does not meet size constraints; the endpoint MAY discard such datagrams." QUIC packet
protection is the real authenticator; this filtering is defence in depth against off-path
injection and against a malfunctioning relay, not a security boundary on its own.

## Association lifetime

RFC 1928 is explicit about when an association ends: "A UDP association terminates when
the TCP connection that the UDP ASSOCIATE request arrived on terminates." `TlsQuicSocks5Transport`
holds the TCP control connection open for the association's entire life and runs a
background watch on it whose only purpose is to observe the connection ending. Once it
does, any pending or subsequent `ReceiveAsync`/`SendAsync` call throws
`TlsQuicProxyException(TlsQuicProxyError.AssociationTerminated)`. `DisposeAsync` closes the
UDP socket first, then the control connection.

## Error model

```csharp
public enum TlsQuicProxyError
{
    NoAcceptableAuthenticationMethod,
    CredentialsRequired,
    CredentialsRejected,
    AssociateRejected,
    MalformedProxyResponse,
    AssociationTerminated,
}

public sealed class TlsQuicProxyException : IOException
{
    public TlsQuicProxyError Error { get; }
}
```

`TlsQuicProxyException` is deliberately distinct from `TlsQuicTransportException`, which
carries a `TlsQuicTransportError` — the RFC 9000 transport error-code space
(`PROTOCOL_VIOLATION`, `TRANSPORT_PARAMETER_ERROR`, `CRYPTO_BUFFER_EXCEEDED`). A proxy
negotiation failure is not a QUIC transport error and must not be reported as one: the QUIC
transport layer maps `TlsQuicTransportError` values onto CONNECTION_CLOSE frames, and a
SOCKS5 handshake failure has no such mapping.

A TCP connect failure to the proxy is not wrapped; `SocketException` already carries the OS
error code. A malformed or unparseable reply, including a wrong subnegotiation `VER` octet,
is reported as `MalformedProxyResponse`. `CredentialsRequired` is kept distinct from
`CredentialsRejected` so a caller can tell a configuration mistake (no credentials
supplied) from a wrong password.

## Non-goals

- SOCKS5 CONNECT and SOCKS5 BIND. The TlsClient package already implements TCP proxying
  through its own internal `ProxyTunnel`; this transport implements only the RFC 1928
  subset needed to reach `CMD = UDP ASSOCIATE`.
- SOCKS4 and SOCKS4a.
- GSS-API authentication (RFC 1928 method `X'01'`).
- SOCKS5 datagram fragmentation. `FRAG` is always sent as `0x00`, and any inbound datagram
  with `FRAG != 0x00` is dropped per the inbound validation rules above.

## Privacy

A configured SOCKS5 relay observes every datagram's destination address, and the timing
and size of all traffic passing through it. Name resolution for the destination happens on
the client before the datagram is encapsulated — the UDP request header always carries a
resolved IP address (`ATYP = 0x01`/`0x04`), never a domain name — so the client's own
resolver, not the relay, is what observes the origin hostname. Callers who need that lookup
itself protected should combine this transport with SharpTls's protected DNS
(`docs/PROTECTED-DNS.md`) or the RFC 9849 ECH DNS bootstrap.
