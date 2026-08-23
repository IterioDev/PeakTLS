# QUIC datagram transport and SOCKS5 UDP relay

Date: 2026-08-16
Status: design, approved for planning
Package: SharpTls
Namespace: `SharpTls.Quic`
Target framework: `net9.0`, `LangVersion 13.0`, `Nullable enable`

## Position in the HTTP/3 roadmap

HTTP/3 support in this codebase decomposes into five subsystems. Each gets its own
spec, plan and implementation cycle.

| ID | Subsystem | Primary standards |
| --- | --- | --- |
| A | QUIC transport: packets, header/payload protection, packet-number recovery, ACK, loss detection, PTO, congestion control, Retry, connection IDs, flow control, stream state, key update, connection close | RFC 9000, RFC 9001, RFC 9002, RFC 9369 |
| B | QUIC fingerprint specification layer: Initial packet spec, CRYPTO frame layout, transport-parameter order/GREASE/suppression, datagram padding, profile catalog | RFC 9000 §18, RFC 8701 |
| C | HTTP/3 and QPACK: control streams, SETTINGS, request streams, GOAWAY, priorities | RFC 9114, RFC 9204, RFC 9218, RFC 9297 |
| D | **Datagram transport abstraction and SOCKS5 UDP relay — this document** | RFC 1928, RFC 1929, RFC 9000 §14 |
| E | Client integration: pooling, Alt-Svc / HTTPS RR discovery, version policy, retries, presets | RFC 7838, RFC 9460 |

D is specified and built first. It is small, fully independent of A, testable today
against a real SOCKS5 relay, and it is a hard prerequisite for running QUIC through a
proxy. Building A directly on a `Socket` and retrofitting proxy support later would
require revisiting path validation, PMTU accounting, connection migration and
anti-amplification assumptions after they are already implemented.

## Relationship to existing code

`SharpTls.Quic` already contains the recordless QUIC-TLS adapter: `CustomTlsQuicClient`,
`CustomTlsQuicServer`, `TlsQuicInitialSecrets`, `TlsQuicTransportParameters`,
`TlsQuicCryptoStreamReassembler` and the `TlsQuicEvent` family. That adapter deliberately
owns no UDP, no packets and no streams. Subsystem D supplies the bottom of the stack that
adapter was written to sit above; subsystem A will supply the middle.

Two repository documents currently declare QUIC transport and HTTP/3 to be out of scope:

- `docs/ROADMAP.md`, "Deliberate core boundaries"
- `docs/QUIC-TLS.md`, "HTTP/3 and QPACK are not part of this library"

Both are rewritten as part of this work, together with the package threat model, because
the decision has been taken to host the transport inside SharpTls rather than in a
separate package.

SOCKS5 CONNECT and SOCKS4 are **out of scope**. The TlsClient package already implements
TCP proxying in its own internal `ProxyTunnel`. SharpTls needs only the subset of RFC 1928
required to reach `CMD = UDP ASSOCIATE`: greeting, method selection, and the RFC 1929
username/password subnegotiation.

## Goals

1. A public datagram seam that the QUIC transport is written against, so the transport
   never references `System.Net.Sockets.Socket` directly.
2. A conforming SOCKS5 UDP ASSOCIATE client with RFC 1929 username/password
   authentication.
3. Explicit, documented accounting of the encapsulation overhead against QUIC's
   1200-byte minimum initial datagram, so the size interaction is a designed property
   rather than a field failure.
4. A test seam that lets subsystem A be tested under loss, reordering and duplication
   without a network, satisfying item 3 of the entry gate in the TlsClient
   `docs/HTTP3-EVALUATION.md`.

## Non-goals

- SOCKS5 CONNECT, SOCKS5 BIND, SOCKS4, SOCKS4a.
- GSS-API authentication (RFC 1928 method `X'01'`).
- SOCKS5 datagram fragmentation. `FRAG` is always sent as `X'00'`, and any datagram
  received with `FRAG != X'00'` is dropped, which RFC 1928 explicitly permits: "an
  implementation that does not support fragmentation MUST drop any datagram whose FRAG
  field is other than X'00'."
- Path MTU discovery. The transport reports its own encapsulation ceiling; DPLPMTUD
  (RFC 8899) belongs to subsystem A.
- Any QUIC packet, frame or stream behaviour.

## File layout

All files directly under `src/SharpTls/Quic/`, alongside the existing QUIC-TLS adapter.

A `Transport/` subfolder was tried and reverted: it would have been the only source path
at that nesting depth in a tree where every other feature area is a single flat folder, and
the namespace stays `SharpTls.Quic` either way, so the extra level carried no signal.

| File | Contents |
| --- | --- |
| `ITlsQuicDatagramTransport.cs` | interface, `TlsQuicDatagramReceiveResult` |
| `TlsQuicUdpDatagramTransport.cs` | direct `Socket` implementation |
| `TlsQuicSocks5Transport.cs` | SOCKS5 UDP ASSOCIATE implementation, owns both sockets |
| `TlsQuicSocks5Options.cs` | proxy endpoint, credentials, timeouts, policy flags |
| `TlsQuicSocks5Protocol.cs` | pure encode/decode over spans, performs no I/O; also holds `TlsQuicProxyError` and `TlsQuicProxyException` |

Separating `TlsQuicSocks5Protocol` from `TlsQuicSocks5Transport` is what makes the wire
format directly unit-testable and fuzzable without sockets. SOCKS5 uses fixed-width
big-endian fields only, so the codec uses `System.Buffers.Binary.BinaryPrimitives` directly.
`TlsBinaryWriter` is built around TLS length-prefixed vectors and is not a fit;
`QuicVariableLengthInteger` is not involved either.

The error enum and exception live beside the protocol rather than in their own file,
matching `Quic/TlsQuicProtocol.cs`, which already groups its enums with
`TlsQuicTransportException`.

## Public API

```csharp
namespace SharpTls.Quic;

/// <summary>
/// Sends and receives UDP datagrams on behalf of a QUIC connection.
/// One concurrent send and one concurrent receive are permitted; the
/// implementation performs no internal locking.
/// </summary>
public interface ITlsQuicDatagramTransport : IAsyncDisposable
{
    /// <summary>
    /// Largest payload this transport can carry after its own encapsulation.
    /// This is an endpoint ceiling, not a path MTU: QUIC path MTU discovery
    /// operates below this value.
    /// </summary>
    int MaxDatagramPayloadSize { get; }

    /// <summary>
    /// Sends one datagram. Throws <see cref="ArgumentOutOfRangeException"/> when
    /// <paramref name="payload"/> exceeds <see cref="MaxDatagramPayloadSize"/>.
    /// </summary>
    ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken);

    /// <summary>
    /// Receives one datagram. Malformed or unauthorised datagrams are discarded
    /// and the call continues waiting; it does not fail the connection.
    /// </summary>
    ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken);
}

public readonly struct TlsQuicDatagramReceiveResult
{
    public int Length { get; }

    /// <summary>
    /// Address of the peer that originated the datagram. For a relayed
    /// transport this is the decapsulated origin address, never the relay.
    /// </summary>
    public IPEndPoint RemoteEndPoint { get; }
}
```

`RemoteEndPoint` reports the decapsulated origin address so that everything above this
seam — path validation, `preferred_address` handling, connection migration — compares
against the address QUIC actually negotiated. The proxy is invisible above the interface.

```csharp
public sealed class TlsQuicSocks5Options
{
    /// <summary>SOCKS5 server. DNS names are resolved for the TCP control connection.</summary>
    public required EndPoint ProxyEndPoint { get; init; }

    /// <summary>RFC 1929 username, 1 to 255 bytes when encoded as UTF-8.</summary>
    public string? Username { get; init; }

    /// <summary>RFC 1929 password, 1 to 255 bytes when encoded as UTF-8.</summary>
    public string? Password { get; init; }
}

public sealed class TlsQuicSocks5Transport : ITlsQuicDatagramTransport
{
    public static ValueTask<ITlsQuicDatagramTransport> ConnectAsync(
        TlsQuicSocks5Options options,
        CancellationToken cancellationToken);
}

public sealed class TlsQuicUdpDatagramTransport : ITlsQuicDatagramTransport
{
    public static ITlsQuicDatagramTransport Create(AddressFamily family);
}
```

`Username` and `Password` must both be null or both be non-null. Either one empty is an
`ArgumentException`: RFC 1929 gives `ULEN` and `PLEN` a range of 1 to 255, so a zero-length
field is not representable.

`ConnectAsync` takes no `AddressFamily`. The local UDP socket's family is fixed by the
family of `ProxyEndPoint` — the client talks only to the relay — so passing it separately
would allow a caller to state something the transport must then contradict.
`TlsQuicUdpDatagramTransport.Create` does take one, because there the local family follows
the resolved origin.

There is no handshake-timeout option. `ConnectAsync` already takes a `CancellationToken`;
callers bound the handshake with `CancelAfter`. A second timeout mechanism would force
every caller to handle both `TimeoutException` and `OperationCanceledException` for the
same condition.

## Destination address policy

The UDP request header always carries a resolved IP address: `ATYP = X'01'` for IPv4 or
`ATYP = X'04'` for IPv6. `ATYP = X'03'` (DOMAINNAME) is never sent.

Rationale: QUIC requires a concrete peer address for path validation (RFC 9000 §8.2),
`preferred_address` migration (§9.6.2) and PMTU accounting (§14). A domain name in the
header would leave the transport without one. A fixed IP address also keeps the
per-datagram header a constant size, and a meaningful share of deployed relays reject or
mishandle `ATYP = X'03'` on UDP.

The consequence is that name resolution happens on the client, so the client's resolver
observes the origin hostname. SharpTls already offers protected DNS (`docs/PROTECTED-DNS.md`)
and the ECH DNS bootstrap for callers who need that lookup itself protected.

## Association establishment

Wire exchange, with every field value taken from RFC 1928 §3, §4 and RFC 1929 §2.

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

RFC 1928 defines `BND.ADDR`/`BND.PORT` in the ASSOCIATE reply as "the port
number/address where the client MUST send UDP request messages to be relayed", and requires
the relay to "drop any datagrams arriving from any source IP address other than the one
recorded for the particular association".

Three behaviours are required by deployed relays but not stated in the RFC:

1. **Wildcard `BND.ADDR`.** Relays commonly answer with `0.0.0.0` or `::`, meaning "the
   host you are already talking to". When `BND.ADDR` is the unspecified address, substitute
   the IP address of the TCP control connection's remote endpoint. Without this the client
   sends datagrams to a null route and the handshake times out with no diagnostic.
2. **All-zero ASSOCIATE address.** `DST.ADDR` and `DST.PORT` in the ASSOCIATE request are
   always sent as zeros, which RFC 1928 permits when the client cannot know the address it
   will send from. A bound local port is usually rewritten by NAT before the relay sees it,
   so reporting it causes more association failures than it prevents. This is unconditional
   rather than a policy flag; if a relay is found that rejects zeros, a flag is added then.
3. **Don't Fragment.** RFC 9000 §14 requires that "UDP datagrams MUST NOT be fragmented at
   the IP layer. In IPv4, the Don't Fragment (DF) bit MUST be set if possible". Set
   `Socket.DontFragment = true` for `AddressFamily.InterNetwork` and tolerate a
   `SocketException` where the platform refuses. IPv6 routers do not fragment, so the flag
   is not set for `InterNetworkV6`.

`REP` values `X'01'` through `X'08'` each map to a distinct exception message. RFC 1928
requires the server to close the TCP connection within 10 seconds of a failure reply, so
no cleanup handshake is attempted after a failure.

## Datagram encapsulation

Every relayed datagram carries the RFC 1928 §7 header:

```
+-----+------+------+----------+----------+----------+
| RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+-----+------+------+----------+----------+----------+
|  2  |  1   |  1   | Variable |    2     | Variable |
+-----+------+------+----------+----------+----------+
```

`RSV` is `X'0000'`. `FRAG` is always `X'00'` on send. Header size is 10 bytes for IPv4 and
22 bytes for IPv6.

### Size budget

This is the one interaction where SOCKS5 can silently break QUIC, so it is stated
explicitly. RFC 9000 §14.1: "A client MUST expand the payload of all UDP datagrams
carrying Initial packets to at least the smallest allowed maximum datagram size of 1200
bytes."

| Hop | Bytes, IPv4 | Derivation |
| --- | --- | --- |
| QUIC Initial datagram payload | 1200 | RFC 9000 §14.1 minimum |
| client to relay, UDP payload | 1210 | plus 10-byte SOCKS5 header |
| client to relay, IP packet with DF set | 1238 | plus 20-byte IPv4 and 8-byte UDP headers |
| relay to origin, UDP payload | 1200 | relay strips the SOCKS5 header |

The origin therefore observes a conforming datagram. The client-to-relay path must carry
1238 bytes without fragmentation for IPv4. For IPv6 the equivalent chain is 1200 payload
plus a 22-byte header giving 1222 UDP payload bytes, plus 40-byte IPv6 and 8-byte UDP
headers, giving 1270 bytes. Where that path is itself tunnelled below this size the QUIC
handshake cannot complete. This is a
documented deployment limit, not something the transport works around: silently shrinking
the Initial datagram would violate RFC 9000 §14.1 and the server would discard it.

`MaxDatagramPayloadSize` is the socket receive ceiling minus the header size, so subsystem
A's PMTU logic and its `max_udp_payload_size` transport parameter both account for the
encapsulation automatically.

### Inbound validation

A received datagram is **discarded, and the receive continues**, when any of the following
holds. None of these fail the connection.

1. The source is not the relay's `BND` endpoint.
2. `RSV != X'0000'`.
3. `FRAG != X'00'`. RFC 1928: an implementation that does not support fragmentation MUST
   drop these.
4. `ATYP` is neither `X'01'` nor `X'04'`. The transport never sends `X'03'`, so a domain
   name in a reply header is anomalous.
5. The declared header extends past the end of the datagram.

Discarding rather than failing is what RFC 9000 §14 prescribes for unexpected datagrams:
"an endpoint MUST NOT close a connection when it receives a datagram that does not meet
size constraints; the endpoint MAY discard such datagrams." QUIC packet protection is the
real authenticator here; this filtering is defence in depth against off-path injection and
against a malfunctioning relay, not a security boundary on its own.

## Association lifetime

RFC 1928: "A UDP association terminates when the TCP connection that the UDP ASSOCIATE
request arrived on terminates."

The transport therefore holds the TCP control connection open for its whole life and runs
a background read on it whose only purpose is to observe FIN or RST. Any payload bytes
received on the control connection after the ASSOCIATE reply are treated as a protocol
violation and fault the transport.

On fault or on EOF, pending and subsequent `ReceiveAsync` calls throw. Subsystem A
surfaces that as connection loss. `DisposeAsync` closes the UDP socket first, then the
control connection.

## Error model

The existing `TlsQuicTransportException` is **not** reused. It carries a
`TlsQuicTransportError`, which is the RFC 9000 transport error-code space
(`PROTOCOL_VIOLATION`, `TRANSPORT_PARAMETER_ERROR`, `CRYPTO_BUFFER_EXCEEDED`). A proxy
negotiation failure is not a QUIC transport error and must not be reported as one, since
subsystem A will map `TlsQuicTransportError` values onto CONNECTION_CLOSE frames.

A new type follows the established sibling pattern of `TlsEchDnsException : IOException`:

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
    public TlsQuicProxyException(TlsQuicProxyError error, string message);
    public TlsQuicProxyError Error { get; }
}
```

| Condition | Result |
| --- | --- |
| TCP connect to the proxy failed | `SocketException` propagates unwrapped |
| `METHOD = X'FF'` | `TlsQuicProxyException(NoAcceptableAuthenticationMethod)` |
| Proxy selected `X'02'` but no credentials configured | `TlsQuicProxyException(CredentialsRequired)` |
| RFC 1929 `STATUS != X'00'` | `TlsQuicProxyException(CredentialsRejected)` |
| ASSOCIATE `REP` `X'01'`–`X'08'` | `TlsQuicProxyException(AssociateRejected)`, message distinct per value |
| `VER` mismatch, truncated or otherwise unparseable reply | `TlsQuicProxyException(MalformedProxyResponse)` |
| Control connection closed after association | transport faults; pending and later receives throw `TlsQuicProxyException(AssociationTerminated)` |
| Handshake cancelled or its `CancellationToken` deadline elapsed | `OperationCanceledException` |
| Malformed inbound datagram | discarded, receive continues |
| Payload larger than `MaxDatagramPayloadSize` | `ArgumentOutOfRangeException` |

Three deliberate omissions:

- A TCP connect failure is not wrapped. `SocketException` already carries the OS error
  code, which is strictly more information than a wrapper would add.
- A wrong `VER` octet is one way for a reply to be unparseable, so it shares
  `MalformedProxyResponse`. The message names the field and the value.
- The exception exposes no `REP` byte. Nothing in this subsystem or in the QUIC transport
  branches on the reply code; retry policy lives in subsystem E, in a different package.
  The value appears in the message, and a typed accessor is added if a caller needs to
  branch on it.

`CredentialsRequired` is kept distinct from `CredentialsRejected` so a caller can tell a
configuration mistake from a wrong password.

Credentials are never included in exception messages or diagnostics. `TlsQuicSocks5Options`
holds them as `string`; they are encoded once into the request buffer, which is cleared
after the auth exchange.

## Testing

The existing repository already provides `tests/SharpTls.Tests`, `tools/SharpTls.Fuzz`,
`tools/SharpTls.CoverageFuzz` and a three-OS CI workflow. This work adds to them; it
introduces no new test infrastructure.

### Wire vectors, no I/O

`TlsQuicSocks5Protocol` encode and decode are checked against byte arrays constructed
directly from the RFC field diagrams: greeting, method selection, RFC 1929 request and
reply, ASSOCIATE request, ASSOCIATE reply with IPv4, IPv6 and domain `BND.ADDR`, and UDP
header encapsulation and decapsulation for both address families.

### Negative cases

Each of `REP` `X'01'` through `X'08'` produces its own message. `VER` mismatch on every
message. `METHOD = X'FF'`. `STATUS != X'00'`. Truncation at each field boundary of each
message. `ULEN = 0` and `PLEN = 0`. `RSV != 0`. `FRAG != 0`. Unknown `ATYP`. Declared
header longer than the buffer. A username or password longer than 255 UTF-8 bytes is
rejected at the options boundary rather than truncated.

### In-process relay

A test-only SOCKS5 server: a TCP listener plus a UDP relay, deterministic and offline, so
it runs in CI on Linux, macOS and Windows. Cases: successful association with no
authentication; successful association with username and password; authentication
rejection; wildcard `BND.ADDR` substitution; control connection dropped mid-association
and after association; a datagram injected from a source other than the relay is dropped;
a datagram with `FRAG != 0` is dropped; a datagram whose header overruns the buffer is
dropped; round-trip of a full-size payload.

### Size

A 1200-byte payload produces exactly 1210 wire bytes over IPv4 and 1222 over IPv6.
`MaxDatagramPayloadSize` equals the socket ceiling minus 10 or 22 for the respective
families. A send one byte over the limit throws.

### Fuzz

A new decode target is added to `tools/SharpTls.Fuzz` covering the ASSOCIATE reply parser
and the UDP header parser. The invariants are that arbitrary input never throws an
exception type outside the declared set, never allocates in proportion to an
attacker-declared length field before that length is validated against the buffer, and
never fails to terminate.

### Interoperability

Opt-in, isolated from the offline suite, matching the existing interop pattern in this
repository: association and datagram round-trip against a real relay, with and without
credentials. Reference implementations for the harness are 3proxy, Dante and gost.

## Open items deferred to subsystem A

- Whether connection migration is offered at all when a relayed transport is in use.
  Migration is cheap through SOCKS5 because the destination is per-datagram, but the
  client's own address as observed by the origin is the relay's, so local migration is
  invisible to the peer and `preferred_address` migration changes only the header contents.
- DPLPMTUD (RFC 8899) probe ceiling, which must start from `MaxDatagramPayloadSize`.
