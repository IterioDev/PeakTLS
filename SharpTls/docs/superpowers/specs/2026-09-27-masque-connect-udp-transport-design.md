# MASQUE CONNECT-UDP datagram transport — design

Date: 2026-09-27. Status: design approved in conversation; five reviewer rounds applied;
awaiting the user's read before planning.

## Goal

Carry an unchanged Spotify iOS 27 HTTP/3 connection through Oxylabs' MASQUE proxy
(`masque.oxylabs.io:50000`, RFC 9298 CONNECT-UDP over HTTP/3), so that the target sees the
handset's QUIC fingerprint from a residential exit while the client keeps every knob it has
today. Field evidence (see `SharpTls/docs/SOCKS5-DATAGRAM-TRANSPORT.md`, "TLS alert") shows the
same provider's SOCKS5 UDP ASSOCIATE writes datagrams into TCP; MASQUE is its only native UDP
path.

## Non-goals

Shared outer connections across inner connections; MASQUE for TCP (RFC 9298 proxies UDP only;
the provider's TCP path stays SOCKS5 or HTTP CONNECT); IPv6 targets; Oxylabs' legacy `/masque?h=` URI form; capsules beyond tolerating
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
(`TlsPreset.cs` sets `quic.PathMtuDiscovery = false`; `BasePathMtu` stays at its 1200 default),
under the 1352 ceiling.
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
`DrainReceivedDatagrams()`. Missing is send, and the peer's limit.

- The peer's `max_datagram_frame_size` is kept. `TlsQuicConnection.AdvertisedMaxDatagramFrameSize`
  is our own ClientHello's value, not the peer's; the peer's parameters already reach
  `ApplyPeerTransportParametersAsync`, which reads 0x20 through the existing `Get(id)` into a new
  `internal ulong? PeerMaxDatagramFrameSize`, null when the peer sent none.
- `internal bool TryQueueDatagram(ReadOnlyMemory<byte> payload)`: appends to a bounded FIFO of
  64 entries and returns false when full, so the caller delays (RFC 9221 s5.4 allows delay or
  drop; this library delays and never drops). Throws `InvalidOperationException` if
  `PeerMaxDatagramFrameSize` is null, or `ArgumentOutOfRangeException` if the frame would exceed
  it or `MaximumDatagramFramePayload`.
- `internal int QueuedDatagrams`: what the FIFO holds; the owner task in component 4 reads it.
- `internal int MaximumDatagramFramePayload`: the largest DATAGRAM frame payload one 1-RTT packet
  at the current path MTU can carry: MTU minus short header (1), Destination Connection ID
  length, largest packet number (4), AEAD tag (16), frame type (1) and length varint (2). At
  1392 with an 8-byte DCID that is 1360. Also bounded by the peer's `max_datagram_frame_size`
  minus frame type and length.
- The 1-RTT packet builder in `TlsQuicApplicationSendPath` drains the queue: one DATAGRAM frame
  (type 0x31, length present, RFC 9221 s4) per packet, plus an ACK frame when one is due and
  fits. A packet carrying a DATAGRAM frame carries no STREAM frame. Datagram frames are
  ack-eliciting and never retransmitted (s5.2); loss is the inner connection's business. The
  builder's congestion-window gate applies unchanged: a cwnd-blocked outer leaves datagrams in
  the FIFO until acknowledgements open the window.
- `SendPendingAsync` returns true when a datagram was sent, as it does for any frame.

### 2. `TlsQuicHttp3Request`: extended CONNECT (SharpTls, existing file)

- `internal string? Protocol { get; init; }` emits `:protocol` (RFC 9220 s3). No new
  `TlsQuicHttp3PseudoHeader` member: the emit loop writes `:protocol` right after its `Method`
  arm whenever `Protocol` is set, in whatever `PseudoHeaderOrder` the spec carries, so no spec
  lists it and the existing order validation is untouched. RFC 8441 s4, which RFC 9220 s3 adopts for HTTP/3, requires
  `:scheme` and `:path` alongside `:protocol`; the existing validator already refuses an order
  that omits them (`MandatoryPseudoHeaderOmitted`), so no new error value. The "CONNECT
  LIMITATION" remark in `TlsQuicHttp3Request.cs` (around line 342) is rewritten, since this
  design is the extended CONNECT it said was not meant to be.
- `TlsQuicHttp3Connection.TryOpenRequest` refuses a request with `Protocol` set unless the
  peer's SETTINGS carried `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08) = 1: RFC 8441 s3 grants the
  extended form only "upon receipt" of that setting, and RFC 9220 s3 carries the rule to HTTP/3
  unchanged. Refusal: `TlsQuicHttp3RequestRefusal.ExtendedConnectNotEnabled`.
- The tunnel exchange never buffers a body: `TlsQuicHttp3Response.TryRead` accumulates DATA
  today, and a stream that never FINs would grow without bound, so an exchange opened with
  `receivesDatagrams` drops its body chunks (capsules, RFC 9297 s3.2) as they arrive.
- Header values are ordinary fields: `proxy-authorization`, `capsule-protocol: ?1` (RFC 9297
  s3.4 SHOULD; RFC 9298 s3.4 shows it and the guide's proxy expects it). QPACK handles them
  like any other.

### 3. `TlsQuicHttp3Connection`: HTTP datagrams per stream (SharpTls, existing file)

Today received HTTP datagrams are validated (quarter stream id, RFC 9297 s2.1) and discarded.

- `TryOpenRequest(..., receivesDatagrams: true)` marks the exchange and sends the HEADERS frame
  WITHOUT FIN. Today every request goes out with `fin: true`; RFC 9297 s2.1 forbids HTTP
  datagrams unless the stream's send side is open, and RFC 9298 s3.1 ties the tunnel's life to
  the request stream, so the send side stays open until the transport closes the connection.
  A test pins the flag. Datagrams whose quarter stream id (stream id / 4) names a marked stream
  are queued on that exchange as RFC 9297 HTTP Datagram Payloads, untouched; this layer knows
  nothing of RFC 9298's context id. Datagrams for unmarked streams are counted and dropped, as
  now.
- `internal List<byte[]> DrainDatagrams(ulong streamId)`.
- `internal bool TrySendDatagram(ulong streamId, ReadOnlySpan<byte> payload)`: writes
  `varint(streamId / 4)`, payload, then `connection.TryQueueDatagram`, returning its answer.
- `internal ulong DroppedDatagramsWrongStream` for `DropSummary`; `internal bool
  PeerSettingsReceived` and `internal ImmutableArray<TlsQuicHttp3Setting> PeerSettings`
  forwarding `TlsQuicHttp3Streams`' flag and list, so the transport can wait for SETTINGS and
  read the two values step 2 needs with `TlsQuicHttp3Settings.Value`.
- `PumpOnceAsync` is this type's (QUIC pump, then `TryProcess`, which is where received
  datagrams are drained); a `false` return means an HTTP/3 connection error, whose code is read
  from `ConnectionErrorCode` and turned into `MasqueTunnelClosed` by the transport.
- The tunnel stream's response body (capsules, RFC 9297 s3.2) is never parsed and never kept;
  the stream stays open for the tunnel's life, and a FIN or RESET_STREAM from the proxy ends the
  tunnel (component 4).
### 4. `TlsQuicMasqueTransport` (SharpTls, new file `Quic/TlsQuicMasqueTransport.cs`)

Implements `ITlsQuicDatagramTransport`. One instance is one tunnel. Both the transport and its
options are `internal`, like `TlsQuicConnectionSpec` and `TlsQuicHttp3Spec` they carry; TlsClient
reaches them through the existing `InternalsVisibleTo`, exactly as it reaches the HTTP/3 types
(see `Properties/AssemblyInfo.cs` for why that is deliberate). The only public change in SharpTls
is the five `TlsQuicProxyError` members.

Options (`TlsQuicMasqueOptions`, new file next to it): `ProxyEndPoint` (DnsEndPoint, host and
port), `TargetHost`, `TargetPort`, `Username`, `Password`, `TargetEndPoint` (a pure echo value
returned in every receive result; the inner connection never compares it, and the proxy resolves
the real address), `OuterSpec` (`TlsQuicConnectionSpec`), `OuterHttp3Spec` (`TlsQuicHttp3Spec`,
with `SETTINGS_H3_DATAGRAM = 1`), `ConfigureOuterClientHello` (`Action<ClientHelloBuilder>`, the
type `TlsQuicOptions.ConfigureClientHello` already uses; TlsClient passes
`TlsQuicOptions.ApplyDefaultClientHello`; TlsClient passes the outer `TlsQuicOptions`'
`ConfigureClientHello`, null meaning that default, as `Http3Connection.CreateTlsClient` does, so
`configureOuter` can set it), `HandshakeDeadline` (bounds steps 1 to 4 below as one deadline).
ALPN is fixed to `h3`. No idle timeout option: like the inner Spotify connection, the outer
advertises no `max_idle_timeout`, so the proxy's value governs and the failure path below
handles its expiry.

`static Task<TlsQuicMasqueTransport> ConnectAsync(options, cancellationToken)`, in order:

1. Resolve the proxy host, open a UDP socket, dial the outer `TlsQuicConnection` with ALPN `h3`,
   SNI the proxy host, standard certificate validation. The ClientHello is built the way
   `Http3Connection.CreateTlsClient` builds one: `TlsQuicClientHelloProfileFactory` composes
   `OuterSpec.TransportParameters` with the source connection id, applies
   `ConfigureOuterClientHello`, and the result goes into
   `CustomTlsQuicClientOptions { ServerName, ServerPort, ClientHello }`. No default parameter set
   carries `max_datagram_frame_size` (`RfcMinimumParameters` holds only
   `initial_source_connection_id`), so the outer options add an explicit
   `TlsQuicTransportParameterSlot.Literal(0x20, [0x80, 0x00, 0xFF, 0xFF])` entry (65535 as a
   varint; `Literal` takes bytes); `TlsQuicHttp3Connection`'s init check refuses
   `SETTINGS_H3_DATAGRAM = 1` without it. `OuterSpec` has PMTUD off and
   `BasePathMtu = MaximumPathMtu = 1392`; `OuterHttp3Spec` sends `SETTINGS_H3_DATAGRAM = 1`.
   Failure: the connection's own exception.
2. Open local streams, pump until the proxy's SETTINGS arrive. `SETTINGS_ENABLE_CONNECT_PROTOCOL`
   must be 1, `SETTINGS_H3_DATAGRAM` must be 1, the proxy's transport parameters must carry a
   `max_datagram_frame_size`, and the resulting `MaxDatagramPayloadSize` must be at least 1200
   (an inner Initial); otherwise `TlsQuicProxyException` (`MasqueNotOffered`) naming the missing
   item or the capacity. This is the one floor; nothing else checks a size.
3. Send the CONNECT-UDP request: `:method CONNECT`, `:protocol connect-udp`, `:scheme https`,
   `:authority {proxy host}:{port}`, `:path /.well-known/masque/udp/{TargetHost}/{TargetPort}/`,
   `proxy-authorization: Basic ...`, `capsule-protocol: ?1`. Target host percent-encoded per
   RFC 9298 s2 (a hostname needs no encoding).
4. Pump until the response header section arrives. Any 2xx (RFC 9298 s3.5): tunnel up. 407:
   `MasqueAuthenticationRejected` ("credentials refused or account traffic limit reached").
   400: `MasqueTargetRejected`. Anything else: `MasqueTunnelRefused` carrying the status. A
   RESET_STREAM or connection close before headers: `MasqueTunnelClosed` carrying the code.
5. Start the owner task and return.

Ownership. The outer `TlsQuicConnection` is not thread-safe, so exactly one task touches it
after `ConnectAsync`: the owner task. It loops: while `connection.QueuedDatagrams` is below the
FIFO bound, move one payload from the outbound channel with `Reader.TryRead` (never an awaiting
read, which would starve the pump) through `http3.TrySendDatagram` (the transport prefixes
RFC 9298 s4's context id 0 first); then `connection.SendPendingAsync`; `http3.PumpOnceAsync` (a
`false` return is an HTTP/3 connection error: `MasqueTunnelClosed` carrying
`ConnectionErrorCode`); drain `http3.DrainDatagrams(streamId)` into the inbound channel, stripping
the context id and counting a non-zero one as dropped. The pump blocks inside
the connection's receive until the proxy sends or a timer fires, so a writer must be able to
interrupt it: the same mechanism `Http3StreamMultiplexer` already uses (`_pumpInterrupt`), a
cancellation source the outbound writer cancels and the owner task replaces, which the
connection's receive path honours as caller cancellation. Backpressure is delay,
never drop and never a throw: the outbound channel is bounded (64, `BoundedChannelFullMode.Wait`)
so an inner burst while the outer is congestion-window-blocked makes the inner's `SendAsync`
await, which is what RFC 9221 s5.4 asks for. A test blocks the outer's window and shows the
datagrams leave in order once it opens. The two channels are the whole concurrency story:

- `SendAsync(destination, payload)`: `destination` is ignored (the tunnel target was fixed at
  step 3). Payload longer than `MaxDatagramPayloadSize` throws `ArgumentOutOfRangeException`
  naming the ceiling; that is a caller's misconfiguration, never a silent drop. Otherwise writes
  to the outbound channel, awaiting when it is full.
- `ReceiveAsync(buffer)`: reads the inbound channel, copies, returns
  `TlsQuicDatagramReceiveResult(length, TargetEndPoint)`.
- `MaxDatagramPayloadSize` = outer `MaximumDatagramFramePayload` minus quarter stream id varint
  length minus 1 (context id). For stream 0 at 1392 that is 1358, above the guide's 1352 and
  above the preset's 1200. The guide's 1500 is a UDP packet ceiling that the 1392 outer packet
  already respects, so it never binds. `DatagramOverhead` stays 0: the capacity is reported
  directly.
- `DropSummary`: dropped for wrong stream (from the HTTP/3 layer), wrong context id and oversize
  inbound (counted here).

Failure after the tunnel is up. Owner task exceptions (outer connection closed by the proxy,
including RFC 9298 s3.1's inactivity close, tunnel stream reset or finished, outer idle timeout,
socket error) complete both channels with `TlsQuicProxyException(MasqueTunnelClosed)` whose
message carries the proxy's error code or the underlying exception. Every later `SendAsync` and
`ReceiveAsync` throws it. The inner connection reports it through the path SOCKS5
`AssociationTerminated` takes today; TlsClient's pool retires the connection and redials subject
to the session's retry policy (`TlsSession.ShouldRetryException`), as for that error. The
outer's effective idle time is the smaller of ours and the proxy's `max_idle_timeout`; if the
proxy's is shorter than the inner's, the outer ends first during a long idle and the next use
takes this path.

`DisposeAsync`: cancel the owner task, CONNECTION_CLOSE the outer with H3_NO_ERROR, which ends
the tunnel stream with it (the library has no caller-initiated RESET_STREAM path, only the one
that answers STOP_SENDING, and this design adds none), dispose the socket. Idempotent.

### 5. TlsClient wiring (existing files)

- `TlsProxyType.Masque = 3` (`Http = 0`, `Socks5 = 2`; 1 is unused on purpose and stays so);
  `TlsProxy.Masque(string address, string username, string password,
  Action<TlsQuicOptions>? configureOuter = null)`. `address` is `https://host:port` and the port
  is required: `EffectivePort` must not fall back to 1080 for this type.
- `TlsQuicOptions.Proxy` (`TlsProxy?`, default null) and its `Snapshot` field. When set, it must
  be `Masque`; any other type throws `ArgumentException` at `Snapshot`.
- `HttpConnectionFactory`, h3 branch: today it throws `NotSupportedException` for any
  `options.Proxy` that is not SOCKS5 before `Http3Connection.CreateAsync`, with a remark that
  says this client does not speak MASQUE. When `Quic.Proxy` is set that check is skipped and
  `options.Proxy` is not consulted at all for h3, so an HTTP proxy for TCP beside MASQUE for h3
  is a legal session. When `Quic.Proxy` is null the check stays as it is; the remark is
  rewritten.
- `Http3Connection.CreateAsync`: when `configuration.Quic.Proxy` is set, the transport is
  `TlsQuicMasqueTransport.ConnectAsync(...)`, `relay` is null (no SOCKS5 liveness wrapper), and
  the target is not resolved locally (`TargetEndPoint` is `IPAddress.Any` with the origin's
  port). Otherwise the SOCKS5 and direct paths run unchanged.
- TCP path: `ProxyTunnel`'s switch on `TlsProxyType` gains a `Masque` arm that throws
  `NotSupportedException`: "MASQUE carries UDP; set `options.Quic.Proxy` and give `options.Proxy`
  a SOCKS5 or HTTP proxy for TCP".
- Outer options: a fresh `TlsQuicOptions` (the library's default QUIC ClientHello) with PMTUD
  off, both MTUs 1392, an explicit `max_datagram_frame_size = 65535` transport parameter entry,
  and a fresh `TlsHttp3Options` whose `Settings` carry `SETTINGS_H3_DATAGRAM = 1` (that is where
  the setting lives, and `TlsQuicOptions.Snapshot` takes one); `configureOuter` runs last on the
  `TlsQuicOptions`.
- Telemetry: `TlsConnectEventKind.MasqueTunnelOpened` (elapsed to the 2xx) and
  `MasqueTunnelClosed` (reason), through the existing `ConnectObserver`.

## Error model

Five new `TlsQuicProxyError` values, all raised as `TlsQuicProxyException`:

| Value | When | Message names |
| --- | --- | --- |
| `MasqueNotOffered` | proxy SETTINGS or transport parameters lack extended CONNECT or datagrams | the missing setting or parameter |
| `MasqueAuthenticationRejected` | 407 | credentials refused or traffic limit |
| `MasqueTargetRejected` | 400 | target host and port as sent |
| `MasqueTunnelRefused` | any other non-2xx status | the status |
| `MasqueTunnelClosed` | tunnel stream or outer connection ended, before or after the response | proxy's error code or underlying exception |

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
  retransmitted after loss; `TryQueueDatagram` returns false at the bound; refused without peer
  `max_datagram_frame_size`; a cwnd-blocked outer holds datagrams and releases them in order.
- Extended CONNECT: exact header bytes of the CONNECT-UDP request; refusal without
  `SETTINGS_ENABLE_CONNECT_PROTOCOL`; a `receivesDatagrams` request's HEADERS carries no FIN and
  an ordinary request's still does.
- HTTP datagram framing: the HTTP/3 layer prefixes and strips the quarter stream id and delivers
  payloads to the marked stream, counting and dropping unmarked streams; the transport prefixes
  and strips context id 0 and counts and drops any other.
- Transport: `MaxDatagramPayloadSize` arithmetic at 1392 with an 8-byte DCID (1358), at a peer limit of 1300
  (accepted, 1295) and of 1100 (refused, `MasqueNotOffered`); oversize send refused by name;
  2xx/407/400/other mapping; peer without settings; stream reset after the response surfaces
  `MasqueTunnelClosed` on the next receive; dispose is idempotent. These use the in-memory
  datagram transports already in `SharpTls.Tests/Quic` with a scripted outer peer.
- TlsClient: `TlsProxy.Masque` parsing, port required; `Quic.Proxy` of a non-MASQUE type refused;
  `options.Proxy` of MASQUE type refused on TCP by name; an HTTP `options.Proxy` beside a MASQUE
  `Quic.Proxy` accepted on h3; dial picks the MASQUE transport when `Quic.Proxy` is set.

Live, gated by `TLSCLIENT_LIVE_MASQUE=https://user:pass@masque.oxylabs.io:50000`, credential
never in the repository:

- `SpotifyPresetLiveParityTests` assertions (JA3, transport parameter rotation, SETTINGS, header
  order) against fp.impersonate.pro through the tunnel.
- Three requests on one inner connection through the tunnel.
- One GET to `https://spclient.wg.spotify.com/` through the tunnel: asserts HTTP/3, status 404
  and a `server: envoy` response header, which is that Google-hosted edge answering. The same
  dial through the provider's SOCKS5 fails with `RelayDeliveredTlsAlert`.
- A wrong password expecting `MasqueAuthenticationRejected`.

## Documentation

`TlsClient-main/docs/USAGE.md`: the proxy-type table in section 2a gains a `TlsProxy.Masque` row
and a `Quic.Proxy` paragraph, its heading "With HTTP/3 it must be SOCKS5" is reworded, and the
"h3 through an HTTP proxy ... Neither relays UDP" row of the h3 table is rewritten. `SharpTls/docs/SOCKS5-DATAGRAM-TRANSPORT.md` gains a pointer to the new
`SharpTls/docs/MASQUE-DATAGRAM-TRANSPORT.md`, which holds the wire details above (dial sequence,
framing, error model, MTU arithmetic) for readers who never see this spec.

## Files

Create: `SharpTls/src/SharpTls/Quic/TlsQuicMasqueTransport.cs`, `TlsQuicMasqueOptions.cs`,
`SharpTls/docs/MASQUE-DATAGRAM-TRANSPORT.md`, tests beside the existing SOCKS5 ones.
Modify: `TlsQuicConnection.cs`, `TlsQuicApplicationSendPath.cs`, `TlsQuicHttp3Request.cs`,
`TlsQuicHttp3Connection.cs`,
`TlsQuicSocks5Protocol.cs` (enum), `TlsProxy.cs`, `TlsQuicOptions.cs`, `Http3Connection.cs`,
`HttpConnectionFactory.cs`, `ProxyTunnel.cs`, `TlsConnectEvent.cs`,
`TlsClient-main/src/TlsClient/PublicAPI.Unshipped.txt`,
`SharpTls/tests/SharpTls.Tests/Api/PublicApi.Shipped.txt` (enum members only), `USAGE.md`,
`SOCKS5-DATAGRAM-TRANSPORT.md`.
