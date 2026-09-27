# Built-in presets

A `TlsPreset` is a coherent starting point, not just a TLS alias. It selects the pinned
SharpTls ClientHello profile and configures ALPN policy, ordered HTTP/2 SETTINGS, the
connection WINDOW_UPDATE increment, pseudo-header order, HEADERS priority data, and regular
header order.

**A preset sends no headers of its own, and neither does a session.** Every field on the wire
is one the caller put on the request. A preset's declared header order only decides *where* a
field lands when it is present; it never causes one to be sent. Nothing — not even a
`User-Agent` — is added on the caller's behalf.

```csharp
await using var session = new TlsSession(TlsPresets.SpotifyH2);

var options = TlsPresets.SpotifyH2.CreateOptions();
await using var customized = new TlsSession(options);

var request = new HttpRequestMessage(HttpMethod.Get, url);
request.AddHeader("accept-language", "tr-TR,tr;q=0.9");
var response = await customized.SendAsync(request);

// The order you add them in is the order on the wire. There is nothing else to set.
```

`CreateOptions()` always returns an independent mutable object. The short aliases
`Spotify` and `SpotifyH2` point to the current built-in versioned presets; choose the
versioned property when reproducibility matters.

## Profile matrix

| TlsClient preset | SharpTls TLS profile | Transport | Ordered HTTP/2 SETTINGS | WINDOW_UPDATE increment | Pseudo-header order |
|---|---|---|---|---:|---|
| `Spotify918602428IOS270Http2` | `Spotify918602428IOS270Tcp` | TCP, PreferHttp2 | `2:0; 4:2097152; 3:100; 9:1` | `10485760` | `m,s,p,a` |
| `Spotify918602428IOS270Http3` | `Spotify918602428IOS270Quic` | QUIC, Http3Only | HTTP/3, not HTTP/2 — see below | n/a | `m,s,a,p` |
| `Spotify917602050IOS260Http3` | `Spotify917602050IOS260Quic` | QUIC, Http3Only | HTTP/3, not HTTP/2 — see below | n/a | `m,s,a,p` |

**THREE PRESETS, ONE CLIENT.** The same app dials HTTP/2 over TCP and
HTTP/3 over QUIC with genuinely different hellos — thirteen cipher suites against three, a
different extension set, and even a different pseudo-header order. Neither is derivable from
the other; pick the one matching the transport you are dialling.

The setting identifiers are the HTTP/2 registry values. The pseudo-header abbreviation
uses `m` = method, `a` = authority, `s` = scheme, and `p` = path. WINDOW_UPDATE values
are increments, not final receive-window sizes.

The Spotify h2 preset's four settings are deliberately not in ascending identifier order:
`SETTINGS_INITIAL_WINDOW_SIZE` (`0x4`) precedes `SETTINGS_MAX_CONCURRENT_STREAMS`
(`0x3`) exactly as the capture records them, and no other identifier is sent at all —
no `HEADER_TABLE_SIZE`, no `MAX_FRAME_SIZE`, no `MAX_HEADER_LIST_SIZE`, no
`SETTINGS_ENABLE_CONNECT_PROTOCOL`. `0x9` is RFC 9218 `SETTINGS_NO_RFC7540_PRIORITIES`,
sent as `1`; consistent with it, no PRIORITY frames and no priority flag on any HEADERS.
SETTINGS, WINDOW_UPDATE and the first HEADERS travel in one TLS record; the SETTINGS
acknowledgement goes out on its own once the server's SETTINGS arrive.

## Provenance

The two presets do not have the same kind of evidence behind them, and the difference
matters when judging how far to trust each.

`Spotify918602428IOS270Http3` is a **first-party passive capture of a real device**.

`Spotify917602050IOS260Http3` is the same app on **iOS 26**, from one first-party
capture. THE OS VERSION IN THESE NAMES IS LOAD-BEARING: the two builds send genuinely
different hellos — cipher order `0x1302, 0x1301, 0x1303` and no vendor `0xff080808`
transport parameter on iOS 26, against `0x1302, 0x1303, 0x1301` and the vendor parameter
present on iOS 27. Exactly ten bytes and one swap; every other TLS field, every QUIC
packet dimension and the whole HTTP/3 layer are byte-identical between them. JA3 splits,
JA4 does not — it sorts the cipher list and cannot see either difference.

This was once documented as a proxy-versus-direct capture artefact. It is not: the iOS 26
capture came down the same proxy path that produced the iOS 27 image and still carries the
other shape, and the 2026-09-26 capture below — passive, no proxy, iOS 27 — carries the
iOS 27 shape in 33 of 33 QUIC hellos. Two of the iOS 26 preset's axes are INHERITED from
the iOS 27 measurement rather than measured — the transport-parameter rotation and the
GREASE equality pattern — because one hello lands on one of seven rotation offsets whatever
the client does, and cannot tell a GREASE class pattern from a coincidence. Pin those
against your own captures.

`Spotify918602428IOS270Http2` was a **transcription of a supplied fingerprint record** in
bogdanfinn/tls-client's JSON format, whose collection method is not recorded, and is now
**first-party captured**: the 2026-09-26 pcapng, decrypted with the device's key log, holds
10 h2 connections of this hello. The record was wrong on two things and right on the rest.
The TLS 1.3 trio is `0x1302, 0x1303, 0x1301` (17 of 17 hellos of this shape), not the
`0x1302, 0x1301, 0x1303` it said. The HTTP/2 preface is four settings in the order
`2, 4, 3, 9` with a `10485760` window increment (10 of 10 connections), not the seven
settings and `15663105` it said. Both are corrected. The pseudo-header order `m,s,p,a` it
had right. The GREASE equality pattern, once carried over from the QUIC capture, is now
measured on the TCP path: 14 of 14 exactly-listed hellos show supported_groups and key_share
sharing a value and every other slot drawing its own. The app's in-app web view
(`challenge.spotify.com`, `encore.scdn.co` and friends) dials with WebKit's own, different
hello; that stack is out of scope here.

The presets are named for the 9.1.86.2428 build because that is the capture every value was
last verified against; the QUIC shape is unchanged from 9.1.76.2050, so the older build sends
the same bytes. `Spotify917602050IOS260Http3` keeps its name: iOS 26 was only ever measured on
9.1.76.

Both presets are dialled for real by `tests/TlsClient.Tests/SpotifyPresetLiveParityTests.cs`
(run with `TLSCLIENT_LIVE_TESTS=1`): the h3 one against `fp.impersonate.pro/api/http3`, which
reads back the hello, the transport parameters in wire order, the SETTINGS and the header
order; the h2 one against `tls3.peet.ws/api/all`, which reads back the TCP hello's JA3 and the
Akamai-style frame image `2:0;4:2097152;3:100;9:1|10485760|0|m,s,p,a`. Neither endpoint
reports QPACK encoder behaviour; the dynamic-table encoder is verified offline against the
capture's bytes and against the loopback peer instead.

| | |
|---|---|
| Device | iPhone17,2 |
| OS | iOS 27.0 |
| App | Spotify 9.1.76.2050 (numeric UA `917602050`) |
| Method | Windows mobile hotspot + Wireshark — **no proxy, no MITM, no keylog**. QUIC Initial packets derive their keys from the clear-text Destination Connection ID (RFC 9001 §5.2), so the opening flight decrypts from a plain capture. HTTP/3 SETTINGS came from mitmproxy WireGuard captures of the same handset, which terminate QUIC and so reach the 1-RTT layer a pcapng cannot. |
| Analysis | `scripts/quic_initial_analyze.py` |
| Date | 2026-08-22 |
| Sample size | 80 client connections to `*.spotify.com` across two captures |
| Captured JA3 | `48d08f334704479db85d91df80039756` on iOS 27; `2f9431e877b01e163774ae4ae0df9ded` on iOS 26 |
| Captured JA4 | `q13d0311h3_55b375c5d22e_f2a83c8e78ae` |

Nothing in the preset is inferred from a similar client or copied from another
fingerprint database. Both hashes are reproduced live against `fp.impersonate.pro`.

A second first-party capture, one app version later, confirmed the QUIC and HTTP/3 shape
byte for byte and is the source for every TCP-side correction above:

| | |
|---|---|
| Device / OS | iPhone17,2, iOS 27.0 (24A437), CFNetwork 3896.100.1.2.1 |
| App | Spotify 9.1.86.2428 |
| Method | Passive pcapng plus the device's TLS key log, so both the Initial flight and the 1-RTT HTTP/3 layer decrypt |
| Date | 2026-09-26 |
| Sample size | 53 TCP hellos across 33 hosts; 33 QUIC hellos, 86 QUIC connections, 3 with decrypted HTTP/3 |
| Agrees with the preset | QUIC ClientHello, all seven transport parameters and the vendor `0xff080808` last, the cyclic rotation (5 of 7 offsets seen), HTTP/3 SETTINGS `16383 / 100 / reserved`, `m,s,a,p` |
| Adds | QPACK encoder dynamic table — see below; the h2 frames, not yet decoded |

The preset's name still says `9.1.76.2050` because that is the capture it was decoded from;
the app version does not move the wire shape, the OS version does.

**This preset is `Http3Only`.** The shape it carries is QUIC's, and RFC 9001 §8.4 forbids
several extensions a TCP hello carries, so applying it to a TCP dial would impersonate
nothing. The same app's HTTP/2 legs are a *different* ClientHello — thirteen cipher suites
instead of three, a 32-byte `legacy_session_id` where this one is empty, TLS 1.2 in
`supported_versions`, and the 1.2-era extensions §8.4 forbids over QUIC. Both hellos carry
the `X25519MLKEM768` hybrid group; that is one of the few things they share. Use
`Spotify918602428IOS270Http2` for the TCP half — do not derive one from the other.

### What is measured

Every value below was identical across all 80 connections unless noted:

| | |
|---|---|
| Connection id lengths | source `0`, destination `8` |
| Padding target | `1200` |
| Packet number encoded length | `1` |
| Token | empty |
| Initial CRYPTO split | first frame exactly `999` bytes, second the remainder (`464 + len(SNI)`), one frame per datagram |
| Coalescing | none — one packet per datagram |
| Varint widths | header `2`, crypto length `2`, crypto offset minimal (`1` then `2`) |
| Flow control | `initial_max_data` 16777216, three stream limits 2097152, `initial_max_streams_uni` 8, `active_connection_id_limit` 64 |
| Transport parameters | seven; `initial_max_streams_bidi` (`0x08`) is **not** sent |
| HTTP/3 SETTINGS | `QPACK_MAX_TABLE_CAPACITY 16383`, `QPACK_BLOCKED_STREAMS 100`, one reserved identifier — no `MAX_FIELD_SECTION_SIZE` |

**The transport-parameter order rotates.** 91 captured connections produced exactly seven
orders, and every one was a *cyclic rotation* of a single sequence — never a shuffle, which
would have drawn from 7! = 5040. A fixed order would therefore match one connection in
seven. `CreateOptions()` redraws the rotation each time.

### Measured since, and now in the preset

- **The HTTP/3 pseudo-header order** is `m,s,a,p` — 41 of 41 proxy captures, and every
  decrypted request stream of the 2026-09-26 capture.
- **The unidirectional stream open order** is control, qpack_encoder, qpack_decoder — 4 of
  4 proxy captures carrying 1-RTT.
- **The reserved SETTINGS entry is redrawn per connection**, through
  `TlsHttp3Setting.Drawn`; an earlier revision drew it once per options object.
- **The QPACK encoder uses its dynamic table**, and the preset reproduces how. Three
  decrypted connections of the 2026-09-26 capture, 36 inserts: capacity `4096`, announced on
  the encoder stream once the server's SETTINGS are in (`02 3f e1 1f`, one frame); a
  (name, value) pair inserted the first time it is encoded after having appeared in an
  earlier request that was itself encoded with the table active — so the first request
  after capacity is static-only and a pair seen once is never inserted; inserts with a
  static name reference where the name is in the static table, a literal name otherwise;
  Huffman only when strictly shorter; the encoder and decoder streams opened lazily with
  their first instruction. Three `options.Http3` knobs carry it —
  `QpackEncoderDynamicTableCapacity = 4096`, `QpackInsertPolicy = OnSecondUse`,
  `UnidirectionalStreamOpening = Lazy` — and the library defaults leave every other caller
  on the static-only encoder it had before. No fingerprint endpoint reports QPACK, so the
  capture and `TlsQuicQpackEncoderPolicyTests`' replay of it are the only witnesses.

### What is not measured

- **Everything under `Quic.Recovery`** — the congestion controller, pacing, PTO, ACK
  policy. An opening-flight capture cannot see loss behaviour. This is the largest
  remaining behavioural difference and no ClientHello fidelity closes it.
- **The QPACK Huffman and name-reference policies** beyond what the dynamic-table finding
  above implies; the instruction bytes are in the capture and have not been decoded.
- **Whether the client probes its path MTU at all.** Both HTTP/3 presets set
  `Quic.PathMtuDiscovery = false`, against a library default of `true`. That is a fingerprint
  decision first: a probe is a PING-and-PADDING datagram at a size nothing else in the flight
  uses, on a schedule this library invented, and **no capture here records whether the real
  client sends one**, at what size, or how often. RFC 9000 §14.2 makes discovery a SHOULD and
  offers the same sentence's other half — *"In the absence of these mechanisms, QUIC endpoints
  SHOULD NOT send datagrams larger than the smallest allowed maximum datagram size"* — so both
  answers conform, and these presets pick the one that puts nothing extra on the wire.

  The path argument agrees rather than drives. Every datagram stays at `BasePathMtu`'s 1200,
  which is under every tunnel MTU worth naming (WireGuard 1420, Tailscale 1280, PPPoE 1492)
  with room for a SOCKS5 relay's RFC 1928 §7 header on top. A ceiling above what the local
  interface carries is refused by a DF-set socket with `WSAEMSGSIZE` — RFC 9000 §14 requires
  that DF bit — and 1200 is the only ceiling no route can undercut, because §14.1 already
  requires every path to carry it. The cost is throughput on a genuine 1500-byte path.

  `Quic.MaximumPathMtu` stays pinned at 1392 and is **inert** while discovery is off. It is
  kept so a caller who turns discovery back on gets a tunnel-safe ceiling rather than the
  library's 1472, which is the UDP payload of a 1500-byte Ethernet MTU exactly and therefore
  too large for the tunnelled paths this preset is usually dialled through. Neither value is
  captured; both describe the local path rather than the client.

### Two header images, one QUIC shape

The app speaks HTTP/3 on more than one host, and the header block differs per leg while the
QUIC and TLS halves do not — and the QUIC/TLS half is identical across every endpoint measured
(41 QUIC captures, seven hostnames, one value for every cipher, extension, group, signature
algorithm and transport-parameter set). So there is ONE preset, and it declares no header order
at all: fields reach the wire in the order the caller added them.

The measured header images are recorded in USAGE.md section 7. Two of them:

| Captured leg | App | Header order |
|---|---|---|
| `spclient.wg.spotify.com` GET | 9.1.86.2428 | `spotify-app-version, accept, authorization, time-zone, app-platform, priority, accept-language, accept-encoding, user-agent, x-client-id, client-token` |
| `spclient.wg.spotify.com` GET | 9.1.76.2050 | `accept, x-client-id, accept-encoding, priority, app-platform, user-agent, authorization, accept-language, spotify-app-version` |
| `login5.spotify.com` POST `/v4/login` | 9.1.76.2050 | `content-type, accept, priority, accept-encoding, x-retry-count, cache-control, content-length, user-agent, accept-language, client-token` |

The 9.1.86 image is a different sequence from the 9.1.76 one, not a reordering: it adds
`time-zone` on every request and `client-token` on plain GETs. The login5 POST is not the
GET reordered either — each carries names the other does not. `Content-Type` and
`Content-Length` come from the request body, and the captured order interleaves them among
session headers — `Http3FieldMapperTests` pins that offline, because `tls3.peet.ws` reports
HTTP/3 field lines in an order that varies between runs and so cannot settle it. The full
set of 9.1.86 images, including the pairs whose order moves between requests, is in
USAGE.md section 7.

Two more honest limits:

- The **User-Agent** is `Spotify/9.1.76 iOS/27.0 (iPhone17,2)` on both 9.1.76 HTTP/3 legs.
  The 9.1.86 capture's header VALUES have not been decoded yet; by the same pattern the
  string is `Spotify/9.1.86 iOS/27.0 (iPhone17,2)`, and that is what the sample sends. Over
  **HTTP/2** the same app's `login5` leg uses
  `Spotify/917602050 CFNetwork/3892.100.1 Darwin/27.0.0` instead — that string belongs to
  the TCP path and is not what either h3 preset sends; the 9.1.86 device reports CFNetwork
  `3896.100.1.2.1`, so its h2 string is `Spotify/918602428 CFNetwork/3896.100.1.2.1
  Darwin/27.0.0` by the same pattern.
- The **header order** is a sequence to feed to `AddHeader` rather than an array to assign
  — the preset carries none. `Authorization`, `X-Client-Id` and `Client-Token` are
  per-account credentials; add them at the captured positions shown, because insertion order
  IS the wire order. `Accept-Language` and `Time-Zone` are the captured device's locale and
  zone, not fingerprint axes: change them freely.

## The preface is a script, not a fixed set of settings

`TlsHttp2Options.Preface` is an ordered list of frames written verbatim, and a SETTINGS
frame holds `(identifier, value)` pairs of raw 16-bit identifiers. Nothing is normalized:
an identifier the registry does not define, a GREASE value, and the same identifier
declared twice all reach the wire exactly as written, in the order written. Where a
duplicate identifier appears, the last value governs TlsClient's own receive state, which
is what a peer would apply.

The preface also carries `TlsHttp2WindowUpdateFrame`, `TlsHttp2PrefacePriorityFrame`, and
`TlsHttp2RawFrame` for a frame type TlsClient has no model for. Local receive bounds —
maximum frame size, initial window, header table size, push, connection window — are
derived from these declared frames rather than configured separately, because a client is
bound by what it advertised.

Two limits worth knowing. The preface must begin with a SETTINGS frame, which may be empty
but must be present and first, per RFC 9113 section 3.4 — a server reading anything else
answers `GOAWAY(PROTOCOL_ERROR)`, so no real client emits one. The rule is applied to the
type octet a frame actually emits, so a `TlsHttp2RawFrame` of type `0x4` satisfies it. And
known identifiers are still range-checked against RFC 9113 section 6.5.2, so
`SETTINGS_MAX_FRAME_SIZE` outside `[16384, 16777215]` is rejected at configuration time
rather than sent; unknown identifiers carry any value.

The browser presets these paragraphs used to describe — `Chrome133`, `Firefox148` and
`Android11`, transcribed from bogdanfinn/tls-client and uTLS — were removed along with the
uTLS profiles they were built on. The two presets above are what ships. See Provenance
above for how each was obtained.

TlsClient's loopback capture tests establish a real SharpTls connection and assert the
serialized settings order and values, connection window increment, HEADERS priority
bytes, decoded pseudo-header order, and that a caller-supplied User-Agent lands where the
preset's declared order puts it. Android's omitted
`SETTINGS_ENABLE_PUSH` is intentional: HTTP/2 defaults push to enabled, so TlsClient
keeps the HPACK state synchronized and immediately rejects promised streams with
`RST_STREAM`, carrying `CANCEL` unless `TlsHttp2Options.Shutdown.PushRejectionResetCode`
declares another code.

Regular request headers are application context, not part of the upstream HTTP/2
profile. The built-ins provide an order and nothing else: they do not invent a complete
browser navigation request (`sec-ch-*`, Fetch Metadata, and similar values depend on runtime
context), and they do not supply a `User-Agent` either. Every field is the caller's.

### Reserving a slot for Content-Length

`Content-Length` is always recomputed from the body, so a caller cannot set its value — but
it can set its POSITION. Declare it with any placeholder and the generated field lands in
that slot instead of at the end:

```csharp
request.AddHeader("content-length", "-1");   // slot, not value
```

This matters because captured clients interleave it: Spotify's HTTP/3 login POST puts it
seventh of ten, between `cache-control` and `user-agent`. `Transfer-Encoding` reserves the
same slot for a chunked body.

## The request image is a script too

The preface declares the connection; `TlsRequestOptions` declares one request. Attach it to
an `HttpRequestMessage` with `TlsRequestOptions.For(request)` and send with
`TlsSession.SendAsync`.

```csharp
using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.test/");
var requestOptions = TlsRequestOptions.For(request);
requestOptions.FramesBeforeHeaders =
[
    new TlsHttp2StreamPriorityFrame
    {
        Priority = new TlsHttp2Priority { StreamDependency = 0, Weight = 220 },
    },
];
requestOptions.FramesAfterHeaders = [new TlsHttp2PriorityUpdateFrame { Value = "u=0, i" }];
var response = await session.SendAsync(request);
```

`FramesBeforeHeaders` and `FramesAfterHeaders` are ordered lists written immediately either
side of the request's header block. Both are empty by default, which is what keeps the
emitted request image unchanged. Four frame types are declarable:

| Type | Writes |
|---|---|
| `TlsHttp2StreamPriorityFrame` | A PRIORITY frame on the request's stream — the deprecated RFC 7540 dependency and weight RFC 9113 section 5.3.2 keeps on the wire |
| `TlsHttp2PriorityUpdateFrame` | An RFC 9218 PRIORITY_UPDATE naming the request's stream |
| `TlsHttp2PingFrame` | A client-initiated PING with an 8-octet payload |
| `TlsHttp2RequestRawFrame` | Any type, flags, stream identifier and payload, verbatim |

Three details decide what actually lands:

- **"After the header block" means after the last CONTINUATION frame**, not after HEADERS.
  RFC 9113 section 4.3 requires a field block to be a contiguous sequence with no
  interleaved frames of any other type or from any other stream, so a declared frame lands
  outside the complete block and never inside it.
- **Stream identifier `0` is a sentinel meaning "this request's stream"**, resolved when the
  frame is written, because the identifier is not allocated until then. A frame that
  genuinely targets stream 0 — a connection-level PING, SETTINGS or WINDOW_UPDATE — is
  declared as `TlsHttp2RequestRawFrame`, whose stream identifier is written verbatim and
  never substituted.
- **`FlushAfter` ends the write batch after that frame.** Left alone, the frame stays in the
  request's batch and shares a transport record with what follows.

Session-level `PriorityUpdate` remains a fallback: it is emitted after HEADERS only when the
request declares no `TlsHttp2PriorityUpdateFrame` of its own.

These are per-*request* knobs, and a `TlsHttpBehaviorProfile` deliberately does not carry
them — a profile describes a session, and two requests on one connection may each declare
their own script. Capture them alongside the profile if a persona needs them.

`PseudoHeaderOrder`, `HeaderPriority`, `PriorityUpdate`, `HeadersPadding`, `DataPadding`,
`Scheme`, `Protocol`, `PathOverride` and `AuthorityMode` are nullable per-request overrides on
the same object; null falls back to the session value. There is no header-order override,
because there is no header order: `AddHeader` decides both membership and position.

## Pseudo-headers

`TlsHttp2Options.PseudoHeaders` declares *which* request pseudo-headers are emitted, in what
order, and how the authority is conveyed. The order is not a permutation of a fixed set: a
name absent from it is never written, which is what makes a plain CONNECT header block —
`:method` and `:authority` alone, RFC 9113 section 8.5 requiring `:scheme` and `:path` be
omitted — expressible at all. Order itself is unconstrained by the RFC; only "all
pseudo-header fields MUST appear in a field block before all regular field lines" (section
8.3) is normative, so any permutation is legal and is pure fingerprint. A repeated name is
rejected, as section 8.3 makes it malformed.

Composition is validated per request, at send time, because legality depends on the method.
A request whose declared order is illegal for its method throws before a byte is written.

### `AuthorityMode` — and which one departs from the RFC

The three modes are **not** equally conformant. RFC 9113 section 8.3.1: "Clients that
generate HTTP/2 requests directly MUST use the ':authority' pseudo-header field to convey
authority information, unless there is no authority information to convey (in which case it
MUST NOT generate ':authority')."

| Mode | Emits | Conformance |
|---|---|---|
| `AuthorityOnly` (default) | `:authority`, `host` dropped | Satisfies the MUST |
| `Both` | `:authority` and `host` | Conformant while the two agree, which TlsClient guarantees |
| `HostHeaderOnly` | `host` only | **Deliberately violates that MUST** |

`Both` stays conformant by construction. Section 8.3.1 also says "Clients MUST NOT generate
a request with a Host header field that differs from the ':authority' pseudo-header field",
and a server "SHOULD treat a request as malformed" when the two identify different entities;
TlsClient derives both from one value — the request's `Host` field when it carries one,
otherwise the authority of the request URI — so they cannot disagree.

`HostHeaderOnly` is the odd one out and is offered only because TlsClient reproduces clients
that exist, including non-conformant ones: some intermediaries and hand-rolled HTTP/2 stacks
forward the `host` field they received and never synthesise `:authority`, and a capture of
one cannot be replayed without this mode. Section 8.3.1 defines no server fallback to `host`
when `:authority` is absent, so whether a peer routes such a request at all is
server-dependent. Choose it to reproduce such a client, never for a client of your own
design.

### `:protocol` is emitted, but this is not WebSocket support

`TlsRequestOptions.Protocol` supplies the RFC 8441 section 4 `:protocol` value, and it is
emitted when it is set *and* `:protocol` appears in the declared order. It is validated as
an RFC 9110 section 5.6.2 token, and the pseudo-header set is checked against the method:
an extended CONNECT — CONNECT with `:protocol` — requires `:method`, `:scheme`, `:path`,
`:authority` and `:protocol`, where a plain CONNECT permits only `:method` and `:authority`.

**No bidirectional CONNECT stream exists.** Nothing keeps the stream open in both
directions, no 2xx CONNECT response semantics are implemented, and no tunnel is handed back
to a caller. What is reproducible is the *request image* of a client that speaks extended
CONNECT — the header block it puts on the wire. Do not read `:protocol` support as WebSocket
over HTTP/2 support; it is not, and it is not planned.

The genuinely useful wins here are the non-WebSocket ones:

- **`OPTIONS *`.** `TlsRequestOptions.PathOverride` reaches `:path` verbatim, so the
  asterisk-form request target RFC 9113 section 8.3.1 defines for a server-wide OPTIONS is
  expressible. The value must be non-empty visible ASCII — section 8.2.1 makes a field value
  containing NUL, CR or LF malformed, and a space would split the request target.
- **`host` versus `:authority`.** The `AuthorityMode` axis above is what lets a capture of a
  stack that emits one, the other, or both be replayed as it was captured.
- **A non-`https` `:scheme`.** `PseudoHeaders.Scheme` is not restricted to `http` and
  `https`. Section 8.3.1: "':scheme' is not restricted to 'http' and 'https' schemed URIs. A
  proxy or gateway can translate requests for non-HTTP schemes." The value is checked against
  the RFC 3986 section 3.1 scheme grammar and nothing more.
