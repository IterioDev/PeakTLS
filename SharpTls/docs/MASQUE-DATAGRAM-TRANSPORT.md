# MASQUE CONNECT-UDP datagram transport

`TlsQuicMasqueTransport` is the third `ITlsQuicDatagramTransport` implementation, alongside
`TlsQuicUdpDatagramTransport` and `TlsQuicSocks5Transport` (see
`SOCKS5-DATAGRAM-TRANSPORT.md`). It carries an unchanged inner QUIC connection through an
RFC 9298 CONNECT-UDP proxy running over HTTP/3, instead of over a raw socket or a SOCKS5 UDP
association. Everything above the `ITlsQuicDatagramTransport` seam — the inner connection,
`TlsQuicHttp3Connection`, TlsClient's `Http3Connection`, the fingerprint knobs and their tests —
is unaware which transport it is talking to.

Two types share the work. `TlsQuicMasqueConnection` is the outer HTTP/3 connection to the proxy,
dialled once per proxy session; `TlsQuicMasqueTransport` is one CONNECT-UDP tunnel on it, one
request stream, opened per inner connection with `OpenTunnelAsync`. RFC 9298 lets one HTTP/3
connection carry any number of tunnels, and RFC 9297 §2.1's quarter stream id routes each
datagram to its tunnel, so a session that reaches several origins pays one outer handshake rather
than one per origin (two hundred sessions in lockstep were putting five or six bursts of two
hundred handshakes onto one proxy front, which went silent under them). The outer connection's
only job is to move the inner connections' datagrams to and from the proxy; its own TLS
fingerprint is irrelevant, since only the proxy ever terminates it. The exit node re-emits the
inner connection's datagrams byte for byte, so the inner connection's QUIC fingerprint —
transport parameter rotation, packet sizes, everything — reaches the target exactly as the client
built it.

## The dial

`TlsQuicMasqueConnection.ConnectAsync` runs steps 1 and 2; `OpenTunnelAsync` runs steps 3 and 4
for each tunnel. Step 1 tries every address the proxy name resolves to, in resolver order, each
under the outer connection's own `HandshakeDeadline`: UDP has no refusal to report, so a dead
address costs one deadline and says nothing, and the next one is tried. A backstop 1 s behind the
sum of those deadlines bounds DNS and step 2, and the grace lets a stalled outer handshake be
reported by the receiver (what it discarded and why) rather than by a bare cancellation. A missed
deadline is `MasqueTunnelRefused`; its message names the stage the dial was in and lists the
addresses that never answered. Step 2 runs once, against the address that completed the handshake:
what the proxy answers there is not an address problem. An outer spec advertising fewer than three
unidirectional streams (RFC 9114 §6.2) is refused with `ArgumentException` before any packet
leaves, since the proxy could never open its control stream and send SETTINGS. Each tunnel's open
(steps 3 and 4) runs under one `HandshakeDeadline` of its own; an open the proxy never answers is
`MasqueTunnelRefused` naming the stage, and its request stream is ended when the answer does
arrive, so the proxy keeps no tunnel for nobody. The outer connection survives a refused open.

The proxy name is looked up once for the whole process and the answer serves every dial for
`ProxyAddressLifetime` (one minute by default; TlsClient passes the session's
`DnsRefreshInterval`), through `ProxyResolver` when the caller has one. That is longer than the
records' own lifetime on purpose: the provider measured publishes its five addresses for ten
seconds, so a resolver cache is empty again for the next wave of dials, and on a host with a slow
resolver in its list each lookup took two to four seconds of the dial's deadline. Consecutive
dials lead with different addresses of the answer, and each still has all of them to fall
through. A lookup that fails is reported and not kept; a dial that no address completed forgets
the answer, so the next one looks the name up afresh.

1. **Outer QUIC handshake.** ALPN `h3`, SNI the proxy host, chain and hostname validation on,
   revocation checking off (`X509RevocationMode.NoCheck`: an OCSP fetch inside the pump loop
   would spend the handshake deadline between two datagrams), PMTUD off, both path MTUs fixed at 1392. The default transport
   parameter list is `initial_source_connection_id` alone, which advertises no flow control at
   all: the proxy could open zero unidirectional streams, would never send its SETTINGS, and the
   dial would idle out after a completed handshake. The outer ClientHello therefore places the
   six flow-control parameters at RFC 9114 §6.2's floor (three unidirectional streams with 1,024
   bytes of credit each, the same credit on the tunnel's own stream, no server-initiated
   bidirectional streams per §6.1) and adds `max_datagram_frame_size` explicitly as a literal
   transport parameter (id `0x20`); without it the proxy has no basis to accept HTTP/3
   datagrams (RFC 9221 §3). The outer HTTP/3 settings send `SETTINGS_H3_DATAGRAM = 1`
   (RFC 9297 §2.1.1).
2. **Wait for the proxy's SETTINGS.** The proxy must advertise
   `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (RFC 8441 §3, carried into HTTP/3 by RFC 9220 §3) and
   `SETTINGS_H3_DATAGRAM = 1` (RFC 9297 §2.1.1), and its transport parameters must carry a
   `max_datagram_frame_size` large enough that the resulting datagram capacity is at least 1200
   bytes — an inner QUIC Initial (RFC 9000 §14.1). Any of these missing, or the capacity short,
   fails the dial with `MasqueNotOffered`, naming what was missing. This is the transport's only
   size floor; nothing else checks a size at dial time.
3. **The CONNECT-UDP request**, sent as an extended CONNECT (RFC 8441 §4, RFC 9220 §3) with the
   HEADERS frame **not** carrying FIN — RFC 9297 §2.1 forbids HTTP datagrams unless the stream's
   send side stays open, and RFC 9298 §3.1 ties the tunnel's lifetime to the request stream:

   ```
   :method               CONNECT
   :protocol             connect-udp
   :authority            {proxy host}:{proxy port}
   :scheme               https
   :path                 /.well-known/masque/udp/{target host}/{target port}/
   proxy-authorization   Basic {base64(user:pass)}
   capsule-protocol      ?1
   ```

   The fields go out in exactly this order, pinned by
   `TlsQuicMasqueTransportTests.TheConnectUdpRequestIsExactlyWhatTheGuideAsksFor`. The path is the RFC 9298 §2 URI template; the target host is percent-encoded per that
   section (a plain hostname needs no encoding). `capsule-protocol: ?1` is an RFC 9297 §3.4
   SHOULD that this proxy expects. Response capsules are never parsed — a tunnel that never
   FINs would otherwise buffer without bound — so any body chunks the proxy sends are dropped as
   they arrive.
4. **The response.** Any 2xx status means the tunnel is up (RFC 9298 §3.5). 407 is
   `MasqueAuthenticationRejected` (credentials refused, or the account's traffic limit was
   reached). 400 is `MasqueTargetRejected`, naming the target host and port as sent. Any other
   status is `MasqueTunnelRefused`, carrying the status. A RESET_STREAM or connection close
   before the header section arrives is `MasqueTunnelClosed`, carrying the proxy's error code.

With a 2xx in hand the owner registers the tunnel under its stream id and `OpenTunnelAsync`
returns a live `TlsQuicMasqueTransport`. The owner task itself starts when `ConnectAsync`
returns, before any tunnel exists, and runs until the connection ends.

## One connection, many tunnels

The first tunnel is stream 0, the second stream 4, the third stream 8: the client's bidirectional
streams in order, one CONNECT-UDP each, all on one outer connection. Nothing about a tunnel
depends on the others except the shared send path: a congestion-blocked outer holds every
tunnel's payloads, in each tunnel's own order.

A tunnel ends in one of three ways, and only the last touches the others:

- **Disposed by its owner.** `TlsQuicMasqueTransport.DisposeAsync` fails the tunnel's own sends
  and receives, then asks the owner to end its request stream with a FIN (RFC 9298 §3.4: closing
  the request stream ends the tunnel) and forget it. The outer connection and every other tunnel
  are untouched. TlsClient's `Http3Connection` disposes its tunnel with the inner connection, so a
  pooled h3 connection going away costs one FIN, not an outer close.
- **Ended by the proxy or the exit.** A RESET_STREAM or FIN on the tunnel's stream, or a TLS
  alert record through it, fails that tunnel alone with the message described under the error
  model; the rest go on.
- **The outer connection ends.** Its idle timeout, a CONNECTION_CLOSE from the proxy, a failure
  in the pump, or `TlsQuicMasqueConnection.DisposeAsync`: every tunnel fails with the same
  `MasqueTunnelClosed` naming the cause, every open still waiting for its answer fails the same
  way, `IsClosed` turns true, and every later `OpenTunnelAsync` fails at once. A caller keeping
  one connection per proxy session (TlsClient's `MasqueSessionBinding`) sees `IsClosed` and
  dials a new one; `TunnelsRequested` tells it whether a connection was ever used, which decides
  whether a refused open means a stale connection or a real refusal.

## Framing on the wire

Every inner datagram travels inside one outer HTTP/3 DATAGRAM frame (frame type `0x31`,
RFC 9221 §4):

```
0x31 frame:  [ length varint ][ quarter stream id varint ][ context id: 0x00 ][ inner payload ]
                                \_______________ HTTP Datagram Payload ______________/
```

The quarter stream id is the CONNECT-UDP request stream id divided by four (RFC 9297 §2.1) — it
is how the HTTP/3 layer routes a datagram to the exchange that opened the tunnel; that layer
knows nothing about the byte after it. The context id is always `0x00`, meaning "UDP payload,
no extra encoding" (RFC 9298 §4); this transport is the only layer that reads or writes it.
Sending strips neither byte from the inner payload — both are prefixed on the way out and
stripped on the way back in — so the inner connection's own datagram is passed through
unmodified.

DATAGRAM frames are ack-eliciting but never retransmitted after loss (RFC 9221 §5.2): a lost
inner datagram is the inner connection's problem to notice and recover from, exactly as it would
be on a direct UDP path.

## Ownership and backpressure

The outer `TlsQuicConnection` is not thread-safe, so exactly one owner task touches it after
`ConnectAsync` returns. Anything else that has to reach it — an open, a tunnel's close — is
posted to the owner as a command and runs at the top of its next iteration. Each iteration then
drains every tunnel's queued payloads: the tunnel's held one first, then non-blocking reads from
its outbound channel (an awaiting read would starve the pump), each handed to the HTTP/3 layer,
which prefixes the quarter stream id (`SendAsync` already wrote the context id) and queues it on
the outer connection, until that queue refuses one or every channel is empty. A refused payload
is held in its tunnel's `_stalled` and goes first next time, so each tunnel's order holds. The
owner drives the outer connection's send path, refilling between sends until a send builds
nothing, then pumps the HTTP/3 connection once, answers any open whose response has arrived, and
hands each tunnel what arrived for it.

Per tunnel, two queues and one held payload sit around that loop, plus the outer connection's
own queue:

- **Outbound**: a bounded channel, capacity 64, `BoundedChannelFullMode.Wait`. `SendAsync`
  writes to it and awaits when it is full.
- **The held payload**: `_stalled`, the one payload the outer connection's FIFO last refused.
- **The outer connection's own FIFO**: a 64-entry bound inside `TlsQuicConnection` itself
  (`DatagramQueueBound`), ahead of the wire, shared by every tunnel.
- **Inbound**: an unbounded channel that `ReceiveAsync` reads from.

A blocked outer connection therefore absorbs 64 (its FIFO) + 1 (held) + 64 (the outbound
channel) = 129 payloads from one tunnel before that tunnel's `SendAsync` waits.

Backpressure is delay, never drop, at both bounds — RFC 9221 §5.4 permits either, and this
transport always chooses delay. A congestion-window-blocked outer connection simply leaves
datagrams queued until the window opens; an inner burst that fills the outbound channel makes
the inner connection's own `SendAsync` await, rather than silently losing datagrams.

Because the owner task otherwise blocks inside the outer connection's receive until the proxy
sends something or a timer fires, a writer that shows up mid-block needs to wake it. `SendAsync`
calls `WakeableTransport.Wake`, and the wake cancels only the socket receive inside that
decorator, which returns an empty datagram — the same shape as the connection's own timer
wake-up — so no packet is read and the pump's send pass and HTTP/3 processing still run. The
pump's own token is the connection lifetime's alone: a wake never reaches the pump itself, so a
send in progress is never cancelled and no payload already dequeued and recorded as sent is lost.

## Error model

The errors are `TlsQuicProxyError` members raised as `TlsQuicProxyException`:

| Value | Fires when |
| --- | --- |
| `MasqueNotOffered` | the proxy's SETTINGS or transport parameters lack extended CONNECT, HTTP/3 datagrams, or enough datagram capacity for a 1200-byte inner Initial |
| `MasqueAuthenticationRejected` | the CONNECT-UDP response is 407 |
| `MasqueTargetRejected` | the CONNECT-UDP response is 400 |
| `RelayDeliveredTlsAlert` | the answer to the inner Initial through the tunnel is a TLS alert record (`15 03 01 00 02 02 46`, fatal protocol_version): the exit behind this proxy session wrote the datagram into a TCP TLS connection, so no inner packet will cross it and no second tunnel on the same session reaches a different exit. Named at once, without the tunnel retries |
| `MasqueTunnelRefused` | the CONNECT-UDP response is any other non-2xx status, or the outer dial or the tunnel's open missed its deadline (the message names the stage) |
| `MasqueTunnelClosed` | the tunnel stream or the outer connection ends, before or after the response — a proxy-initiated close, a stream reset, the outer connection's own idle timeout, or the connection's disposal. The message says how long the tunnel lived and how many datagrams crossed it each way; datagrams in and none back is an exit that cannot carry UDP to the target, cured by a fresh proxy session rather than a retry of the same one |
| `MasqueExitSilent` | raised by TlsClient, not here: an inner handshake through a tunnel that carried datagrams in and none back while the outer stayed alive. TlsClient remembers it for the proxy session; see its `MasqueSessionBinding` |

Once a tunnel has failed, every subsequent `SendAsync` and `ReceiveAsync` call on it throws the
same exception immediately; there is no partial-failure state. `DatagramsSent` and
`DatagramsReceived` stay readable afterwards, which is how TlsClient tells an exit's silence from
a proxy's.

Local misconfiguration is not a proxy error: sending a payload larger than
`MaxDatagramPayloadSize` throws `ArgumentOutOfRangeException` naming the ceiling, since that is a
caller mistake, not something the network refused.

## MTU arithmetic

Outer packets are fixed at 1392 bytes. Working down from there to the inner connection's usable
datagram capacity:

| Deduction | Bytes | Running total |
| --- | --- | --- |
| Outer packet size | — | 1392 |
| Short header (1) + 8-byte DCID + packet number (up to 4) + AEAD tag (16) | 29 | 1363 |
| DATAGRAM frame type (1) + length varint (2) | 3 | 1360 |
| Quarter stream id (1) + context id (1) | 2 | **1358** |

1358 is the inner connection's usable datagram payload for an 8-byte server connection ID; a
longer connection ID lowers it by exactly the difference. The transport asserts this capacity is

A caller may cap the inner payload below that arithmetic through
`TlsQuicMasqueOptions.InnerDatagramCeiling`. TlsClient passes `TlsProxy.Masque`'s
`maxInnerDatagramPayload`, default 1352, the Oxylabs guide's inner size, so a tunnel to that proxy
carries the guide's number rather than the few bytes more the arithmetic allows. The ceiling is
never below RFC 9000 s14.1's 1200.
at least 1200 bytes — an inner Initial (RFC 9000 §14.1) — at dial time (step 2 above) and fails
with `MasqueNotOffered` rather than let a handshake hang. The proxy's own 1500-byte UDP datagram
ceiling never binds here: the 1392-byte outer packet already sits well under it.

## `DropSummary` and test-only options

`DropSummary` counts datagrams that were discarded without failing the connection:

- **Wrong context id** — an inbound HTTP datagram whose context id is not `0x00` (RFC 9298 §4).
- **Oversize inbound** — a decapsulated payload larger than `MaxDatagramPayloadSize`.
- **Wrong stream** — an HTTP datagram whose quarter stream id names a stream nothing reads
  (counted by the HTTP/3 layer for the whole outer connection, surfaced on every tunnel).

None of these end the tunnel; they are defence in depth against a malfunctioning or hostile
proxy, the same posture `SOCKS5-DATAGRAM-TRANSPORT.md`'s inbound validation takes.

`TlsQuicMasqueOptions` also carries a small set of options that exist only for tests, never for
production dials: `OuterTransport` substitutes a scripted outer datagram transport in place of a
real UDP socket, `OuterRemoteEndPoints` lists the outer connection's peer addresses without a DNS
resolution, and `DangerouslySkipOuterCertificateValidation` turns off the outer connection's
certificate validation. All three exist so the offline test suite can script a fake MASQUE proxy
without a network; none of them is reachable from `TlsProxy.Masque(...)`.

## See also

- `SOCKS5-DATAGRAM-TRANSPORT.md` — the other `ITlsQuicDatagramTransport` proxy path, and why a
  provider that only tunnels UDP into TCP cannot carry QUIC at all.
- RFC 9221 (QUIC Datagram), §3, §4, §5.2, §5.4.
- RFC 9297 (HTTP Datagrams and the Capsule Protocol), §2.1, §3.4.
- RFC 9298 (CONNECT-UDP), §2, §3.1, §3.5, §4.
- RFC 8441 (Bootstrapping WebSockets with HTTP/2, extended CONNECT), §3, §4.
- RFC 9220 (Bootstrapping WebSockets with HTTP/3), §3.
