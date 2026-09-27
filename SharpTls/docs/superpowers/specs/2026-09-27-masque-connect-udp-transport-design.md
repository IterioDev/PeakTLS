# MASQUE CONNECT-UDP datagram transport — design

Date: 2026-09-27. Status: approved in conversation, awaiting review.

## Goal

Carry an unchanged Spotify iOS 27 HTTP/3 connection through Oxylabs' MASQUE proxy
(`masque.oxylabs.io:50000`, RFC 9298 CONNECT-UDP over HTTP/3), so that the target sees the
handset's QUIC fingerprint from a residential exit while the client keeps every knob it has
today. Field evidence (see `SharpTls/docs/SOCKS5-DATAGRAM-TRANSPORT.md`, "TLS alert") shows the
same provider's SOCKS5 UDP ASSOCIATE writes datagrams into TCP; MASQUE is its only native UDP
path.

## Non-goals

Shared outer connections across inner connections; MASQUE for TCP (`CONNECT`, RFC 9298 s5 is
UDP only); IPv6 targets; Oxylabs' legacy `/masque?h=` URI form; capsules beyond tolerating
them; 0-RTT or resumption on the outer connection; any change to the inner Spotify preset.

## Provider facts this design binds to

| Fact | Value | Source |
| --- | --- | --- |
| Endpoint | `masque.oxylabs.io` UDP 50000 | Oxylabs guide |
| Outer ALPN | `h3` | guide |
| Outer TLS | public CA, no override | guide |
| Datagram support | must advertise `max_datagram_frame_size` and `SETTINGS_H3_DATAGRAM = 1` | guide, RFC 9221 s3, RFC 9297 s2.1.1 |
| Proxy datagram ceiling | 1500 bytes, larger dropped silently | guide |
| URI template | `https://masque.oxylabs.io:50000/.well-known/masque/udp/{host}/{port}/` | guide, RFC 9298 s2 |
| Auth | `proxy-authorization: Basic base64(customer-USER[-key-value]:PASS)` on the CONNECT-UDP request | guide |
| Response | 200 tunnel up; 407 auth failed or traffic limit; 400 bad target | guide |
| Packet sizes | outer 1392, inner 1352, PMTUD off on both | guide |

The Spotify presets already run PMTUD off with every inner datagram at 1200 bytes
(`TlsPreset.cs`, `quic.PathMtuDiscovery = false`, `BasePathMtu` 1200), under the 1352 ceiling.
Nothing in the inner preset changes.

## Architecture

Two QUIC connections. The outer one, client to proxy, is ours but fingerprint-irrelevant: only
Oxylabs sees it. The inner one, client to target, is the existing Spotify connection, unchanged,
and reaches the wire only as the payload of outer DATAGRAM frames. The exit node emits inner
datagrams byte for byte.

The seam is `ITlsQuicDatagramTransport`, the interface the inner `TlsQuicConnection` already
sends and receives through, and which `TlsQuicSocks5Transport` and `TlsQuicUdpDatagramTransport`
implement. A new `TlsQuicMasqueTransport` implements it. Everything above the seam, the inner
connection, `TlsQuicHttp3Connection`, TlsClient's `Http3Connection`, the fingerprint knobs and
their tests, works identically.

One outer connection per inner connection, one CONNECT-UDP stream per outer connection. The
outer dies with the inner. No pool, no sharing, no shared state.

## Components

### 1. `TlsQuicConnection`: DATAGRAM frame send path (SharpTls, existing file)

Receive already exists: RFC 9221 s3's rules are enforced and payloads land in
`DrainReceivedDatagrams()`. Missing is send.

- `internal void QueueDatagram(ReadOnlyMemory<byte> payload)`: appends to a bounded FIFO (64
  entries; a full queue throws `InvalidOperationException` naming the bound, never drops).
  Throws `InvalidOperationException` if the peer advertised no `max_datagram_frame_size`, or
  `ArgumentOutOfRangeException` if the frame would exceed it or `MaximumDatagramFramePayload`.
- `internal int MaximumDatagramFramePayload`: the largest DATAGRAM frame payload one 1-RTT packet
  at the current path MTU can carry: MTU minus short header (1), Destination Connection ID
  length, largest packet number (4), AEAD tag (16), frame type (1) and length varint (2). At
  1392 with an 8-byte DCID that is 1360. Also bounded by the peer's `max_datagram_frame_size`
  minus frame type and length.
- The 1-RTT packet builder in `TlsQuicApplicationSendPath` drains the queue: one DATAGRAM frame
  (type 0x31, length present, RFC 9221 s4) per packet, plus an ACK frame when one is due and
  fits. A packet carrying a DATAGRAM frame carries no STREAM frame. Datagram frames are
  ack-eliciting and never retransmitted (s5.2); loss is the inner connection's business.
- `SendPendingAsync` returns true when a datagram was sent, as it does for any frame.

### 2. `TlsQuicHttp3Request`: extended CONNECT (SharpTls, existing file)

- `internal string? Protocol { get; init; }` emits `:protocol` (RFC 9220 s3) after `:method`.
  Pseudo-header order with it set: `:method`, `:protocol`, `:scheme`, `:authority`, `:path`.
  RFC 9220 s3 requires `:scheme` and `:path` alongside `:protocol`; encoding without them is a
  `TlsQuicHttp3RequestError.ExtendedConnectMissingPseudoHeader`.
- `TlsQuicHttp3Connection.TryOpenRequest` refuses a request with `Protocol` set unless the
  peer's SETTINGS carried `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08) = 1 (RFC 9220 s3 MUST):
  `TlsQuicHttp3RequestRefusal.ExtendedConnectNotEnabled`.
- Header values are ordinary fields: `proxy-authorization`, `capsule-protocol: ?1` (RFC 9297
  s3.1 requires it on a CONNECT-UDP request, RFC 9298 s3.1). QPACK handles them like any other.

### 3. `TlsQuicHttp3Connection`: HTTP datagrams per stream (SharpTls, existing file)

Today received HTTP datagrams are validated (quarter stream id, RFC 9297 s2.1) and discarded.

- `TryOpenRequest(..., receivesDatagrams: true)` marks the exchange; datagrams whose quarter
  stream id (stream id / 4) names a marked stream are queued on that exchange after the RFC 9298
  s5 context id is read: context id 0 is a UDP payload and is delivered; any other context id is
  counted and dropped (no other context is ever registered). Datagrams for unmarked streams are
  counted and dropped, as now.
- `internal List<byte[]> DrainDatagrams(ulong streamId)`.
- `internal void SendDatagram(ulong streamId, ReadOnlySpan<byte> payload)`: writes
  `varint(streamId / 4)`, `varint(0)`, payload, then `connection.QueueDatagram`.
- `internal ulong DroppedDatagramsWrongStream`, `DroppedDatagramsWrongContext`: for
  `DropSummary`.
- The tunnel stream's response body (capsules, RFC 9297 s3.2) is read and discarded; nothing
  parses capsules. The stream stays open for the tunnel's life; a FIN or RESET_STREAM from the
  proxy ends the tunnel (component 4).

### 4. `TlsQuicMasqueTransport` (SharpTls, new file `Quic/TlsQuicMasqueTransport.cs`)

Implements `ITlsQuicDatagramTransport`. One instance is one tunnel.

Options (`TlsQuicMasqueOptions`, new file next to it): `ProxyEndPoint` (DnsEndPoint, host and
port), `TargetHost`, `TargetPort`, `Username`, `Password`, `TargetEndPoint` (the IPEndPoint echoed
in every receive result; the inner connection compares it, the proxy resolves the real address),
`OuterSpec` (`TlsQuicConnectionSpec`), `OuterHelloConfiguration` (whatever the caller uses today
to shape a ClientHello; TlsClient passes its default), `HandshakeDeadline`.

`static Task<TlsQuicMasqueTransport> ConnectAsync(options, cancellationToken)`, in order:

1. Resolve the proxy host, open a UDP socket, dial the outer `TlsQuicConnection` with ALPN `h3`,
   SNI the proxy host, standard certificate validation. `OuterSpec` has PMTUD off and
   `BasePathMtu = MaximumPathMtu = 1392`, `max_datagram_frame_size = 65535`, and its
   `TlsQuicHttp3Spec` sends `SETTINGS_H3_DATAGRAM = 1`. Failure: the connection's own exception.
2. Open local streams, pump until the proxy's SETTINGS arrive. `SETTINGS_ENABLE_CONNECT_PROTOCOL`
   must be 1 and `SETTINGS_H3_DATAGRAM` must be 1, and the outer transport parameters must carry
   a `max_datagram_frame_size` of at least 1360 + 3; otherwise `TlsQuicProxyException`
   (`MasqueNotOffered`) naming the missing item.
3. Send the CONNECT-UDP request: `:method CONNECT`, `:protocol connect-udp`, `:scheme https`,
   `:authority {proxy host}:{port}`, `:path /.well-known/masque/udp/{TargetHost}/{TargetPort}/`,
   `proxy-authorization: Basic ...`, `capsule-protocol: ?1`. Target host percent-encoded per
   RFC 9298 s2 (a hostname needs no encoding).
4. Pump until the response header section arrives. 200: tunnel up. 407:
   `MasqueAuthenticationRejected` ("credentials refused or account traffic limit reached").
   400: `MasqueTargetRejected`. Anything else: `MasqueTunnelRefused` carrying the status. A
   RESET_STREAM or connection close before headers: `MasqueTunnelClosed` carrying the code.
5. Start the owner task and return.

Ownership. The outer `TlsQuicConnection` is not thread-safe, so exactly one task touches it
after `ConnectAsync`: the owner task. It loops: drain outbound channel and send each payload
through `http3.SendDatagram`, `connection.SendPendingAsync`; `connection.PumpOnceAsync`; drain
`http3.DrainDatagrams(streamId)` into the inbound channel. It wakes on either channel or on the
socket. The two channels are the whole concurrency story:

- `SendAsync(destination, payload)`: `destination` is ignored (the tunnel target was fixed at
  step 3). Payload longer than `MaxDatagramPayloadSize` throws `ArgumentOutOfRangeException`
  naming the ceiling; that is a caller's misconfiguration, never a silent drop. Otherwise writes
  to the outbound channel.
- `ReceiveAsync(buffer)`: reads the inbound channel, copies, returns
  `TlsQuicDatagramReceiveResult(length, TargetEndPoint)`.
- `MaxDatagramPayloadSize` = min(outer `MaximumDatagramFramePayload`, proxy ceiling 1500) minus
  quarter stream id varint length minus 1 (context id). For stream 0 at 1392 that is 1358, above
  the guide's 1352 and above the preset's 1200. `DatagramOverhead` stays 0: the capacity is
  reported directly.
- `DropSummary`: dropped for wrong stream, wrong context, oversize inbound.

Failure after the tunnel is up. Owner task exceptions (outer connection closed by the proxy,
tunnel stream reset or finished, outer idle timeout, socket error) complete both channels with
`TlsQuicProxyException(MasqueTunnelClosed)` whose message carries the proxy's error code or the
underlying exception. Every later `SendAsync` and `ReceiveAsync` throws it. The inner
connection reports it through the path SOCKS5 `AssociationTerminated` takes today.

`DisposeAsync`: cancel the owner task, RESET_STREAM the tunnel with H3_NO_ERROR, CONNECTION_CLOSE
the outer with H3_NO_ERROR, dispose the socket. Idempotent.

### 5. TlsClient wiring (existing files)

- `TlsProxyType.Masque`; `TlsProxy.Masque(string address, string username, string password,
  Action<TlsQuicOptions>? configureOuter = null)`. `address` is `https://host:port`.
- `TlsQuicOptions.Proxy` (`TlsProxy?`, default null) and its `Snapshot` field. When set, it must
  be `Masque`; any other type throws `ArgumentException` at `Snapshot`.
- `Http3Connection.DialAsync`: when `configuration.Quic.Proxy` is set, the transport is
  `TlsQuicMasqueTransport.ConnectAsync(...)`, `relay` is null (no SOCKS5 liveness wrapper), the
  target is not resolved locally (`TargetEndPoint` is `IPAddress.Any:443`, an echo value), and
  `options.Proxy` is ignored for this dial. Otherwise the SOCKS5 and direct paths run unchanged.
- `options.Proxy` of type `Masque` on any dial throws `NotSupportedException`: "MASQUE carries
  UDP; set `options.Quic.Proxy`".
- Outer options: `TlsQuicOptions` defaults (the library's default QUIC ClientHello) with PMTUD
  off, both MTUs 1392, datagram transport parameter and setting on; `configureOuter` runs last.
- Telemetry: `TlsConnectEventKind.MasqueTunnelOpened` (elapsed to 200) and `MasqueTunnelClosed`
  (reason), through the existing `ConnectObserver`.

## Error model

Five new `TlsQuicProxyError` values, all raised as `TlsQuicProxyException`:

| Value | When | Message names |
| --- | --- | --- |
| `MasqueNotOffered` | proxy SETTINGS or transport parameters lack extended CONNECT or datagrams | the missing setting or parameter |
| `MasqueAuthenticationRejected` | 407 | credentials refused or traffic limit |
| `MasqueTargetRejected` | 400 | target host and port as sent |
| `MasqueTunnelRefused` | any other non-200 status | the status |
| `MasqueTunnelClosed` | tunnel or outer connection ended after 200 | proxy's error code or underlying exception |

Local misconfiguration (oversize send, wrong proxy type) is an argument exception, not a proxy
error. No silent downgrade anywhere: an h3 dial that cannot go through MASQUE fails by name.

## MTU arithmetic

Outer packet 1392 (guide). Short header 1 + DCID 8 + packet number up to 4 + AEAD tag 16 = 29.
DATAGRAM frame type 1 + length varint 2 = 3. Frame payload capacity 1360. HTTP datagram framing
for stream 0: quarter stream id 1 + context id 1 = 2. Inner capacity 1358. Guide asks 1352,
preset sends 1200. An inner Initial always fits one outer packet, so the guide's "silently
dropped, hangs indefinitely" case cannot occur; the transport asserts `MaxDatagramPayloadSize
>= 1200` at `ConnectAsync` and fails with `MasqueNotOffered` if the proxy's
`max_datagram_frame_size` makes it smaller.

## Testing

Offline, no network:

- DATAGRAM frame send: queued payload leaves as one 0x31 frame with length, ack-eliciting, not
  retransmitted after loss; queue bound; refused without peer `max_datagram_frame_size`.
- Extended CONNECT: exact header bytes of the CONNECT-UDP request; refusal without
  `SETTINGS_ENABLE_CONNECT_PROTOCOL`; error without `:scheme`/`:path`.
- HTTP datagram framing: send prefixes quarter stream id and context id 0; receive delivers
  context 0 to the marked stream, counts and drops other contexts and unmarked streams.
- Transport: `MaxDatagramPayloadSize` arithmetic at 1392 and at a smaller peer limit; oversize
  send refused by name; 200/407/400/other mapping; peer without settings; stream reset after
  200 surfaces `MasqueTunnelClosed` on the next receive; dispose is idempotent. These use the
  in-memory datagram transports already in `SharpTls.Tests/Quic` with a scripted outer peer.
- TlsClient: `TlsProxy.Masque` parsing; `Quic.Proxy` of a non-MASQUE type refused; `options.Proxy`
  of MASQUE type refused on TCP; dial picks the MASQUE transport when `Quic.Proxy` is set.

Live, gated by `TLSCLIENT_LIVE_MASQUE=https://user:pass@masque.oxylabs.io:50000`, credential
never in the repository:

- `SpotifyPresetLiveParityTests` assertions (JA3, transport parameter rotation, SETTINGS, header
  order) against fp.impersonate.pro through the tunnel.
- Three requests on one inner connection through the tunnel.
- One GET to `https://spclient.wg.spotify.com/` through the tunnel expecting 404: Google-hosted
  target reached with the account's authorization.
- A wrong password expecting `MasqueAuthenticationRejected`.

## Documentation

`TlsClient-main/docs/USAGE.md` section 2a gains the `Quic.Proxy` MASQUE paragraph and the
h3 limitations table row. `SharpTls/docs/SOCKS5-DATAGRAM-TRANSPORT.md` gains a pointer to the new
`SharpTls/docs/MASQUE-DATAGRAM-TRANSPORT.md`, which holds the wire details above (dial sequence,
framing, error model, MTU arithmetic) for readers who never see this spec.

## Files

Create: `SharpTls/src/SharpTls/Quic/TlsQuicMasqueTransport.cs`, `TlsQuicMasqueOptions.cs`,
`SharpTls/docs/MASQUE-DATAGRAM-TRANSPORT.md`, tests beside the existing SOCKS5 ones.
Modify: `TlsQuicConnection.cs`, `TlsQuicApplicationSendPath.cs`, `TlsQuicHttp3Request.cs`,
`TlsQuicHttp3Connection.cs`, `TlsQuicSocks5Protocol.cs` (enum), `TlsProxy.cs`,
`TlsQuicOptions.cs`, `Http3Connection.cs`, `TlsConnectEvent.cs`, `PublicAPI.Unshipped.txt`,
`PublicApi.Shipped.txt`, `USAGE.md`, `SOCKS5-DATAGRAM-TRANSPORT.md`.
