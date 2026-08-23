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
await using var session = new TlsSession(TlsPresets.Chrome133);

var options = TlsPresets.Firefox148.CreateOptions();
await using var customized = new TlsSession(options);

var request = new HttpRequestMessage(HttpMethod.Get, url);
request.Headers.TryAddWithoutValidation("accept-language", "tr-TR,tr;q=0.9");
var response = await customized.SendAsync(request);

// Set options.HeaderOrder = null and the order you added them in is the order on the wire.
```

`CreateOptions()` always returns an independent mutable object. The short aliases
`Chrome`, `Firefox`, `Android`, and `Spotify` point to the current built-in versioned
presets; choose the versioned property when reproducibility matters.

## Profile matrix

| TlsClient preset | SharpTls TLS profile | Ordered HTTP/2 SETTINGS | WINDOW_UPDATE increment | HEADERS priority | Pseudo-header order |
|---|---|---|---:|---|---|
| `Chrome133` | `UTlsChrome133` | `1:65536; 2:0; 4:6291456; 6:262144` | `15663105` | none | `m,a,s,p` |
| `Firefox148` | `UTlsFirefox148` | `1:65536; 2:0; 4:131072; 5:16384` | `12517377` | dep `0`, non-exclusive, weight `41` | `m,p,a,s` |
| `Android11` | `UTlsAndroid11OkHttp` | `4:16777216` | `16711681` | dep `0`, non-exclusive, weight `1` | `m,p,a,s` |
| `Spotify917602050IOS270Http3` | `Spotify917602050IOS270Quic` | HTTP/3, not HTTP/2 — see below | n/a | n/a | `m,a,s,p` (unmeasured) |

The setting identifiers are the HTTP/2 registry values. The pseudo-header abbreviation
uses `m` = method, `a` = authority, `s` = scheme, and `p` = path. WINDOW_UPDATE values
are increments, not final receive-window sizes.

The Spotify preset's two settings are deliberately not in ascending identifier order:
`SETTINGS_INITIAL_WINDOW_SIZE` (`0x4`) precedes `SETTINGS_MAX_CONCURRENT_STREAMS`
(`0x3`) exactly as the capture records them, and no other identifier is sent at all —
no `HEADER_TABLE_SIZE`, no `ENABLE_PUSH`, no `MAX_FRAME_SIZE`, no `MAX_HEADER_LIST_SIZE`,
no `SETTINGS_ENABLE_CONNECT_PROTOCOL` — and no PRIORITY frames.

## Provenance

The first three presets and the Spotify preset do not have the same kind of evidence
behind them, and the difference matters when judging how far to trust each.

`Chrome133`, `Firefox148`, and `Android11` are **transcriptions of a third-party
project**: their HTTP/2 values come from bogdanfinn/tls-client at the commit linked
below, and their ClientHellos from uTLS at its pinned commit. Their accuracy is
inherited from those upstreams.

`Spotify917602050IOS270Http3` is a **first-party passive capture of a real device**.

| | |
|---|---|
| Device | iPhone17,2 |
| OS | iOS 27.0 |
| App | Spotify 9.1.76.2050 (numeric UA `917602050`) |
| Method | Windows mobile hotspot + Wireshark — **no proxy, no MITM, no keylog**. QUIC Initial packets derive their keys from the clear-text Destination Connection ID (RFC 9001 §5.2), so the opening flight decrypts from a plain capture. HTTP/3 SETTINGS came from mitmproxy WireGuard captures of the same handset, which terminate QUIC and so reach the 1-RTT layer a pcapng cannot. |
| Analysis | `scripts/quic_initial_analyze.py` |
| Date | 2026-08-22 |
| Sample size | 80 client connections to `*.spotify.com` across two captures |
| Captured JA3 | `48d08f334704479db85d91df80039756` (proxy path; direct path is `2f9431e877b01e163774ae4ae0df9ded`) |
| Captured JA4 | `q13d0311h3_55b375c5d22e_f2a83c8e78ae` |

Nothing in the preset is inferred from a similar client or copied from another
fingerprint database. Both hashes are reproduced live against `fp.impersonate.pro`.

**This preset is `Http3Only`.** The shape it carries is QUIC's, and RFC 9001 §8.4 forbids
several extensions a TCP hello carries, so applying it to a TCP dial would impersonate
nothing. The same app's HTTP/2 legs are a *different* ClientHello — thirteen cipher suites
instead of three, no post-quantum group, a 32-byte `legacy_session_id`, TLS 1.2 in
`supported_versions` — and are not reproduced here.

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

### What is not measured

- **Everything under `Quic.Recovery`** — the congestion controller, pacing, PTO, ACK
  policy. An opening-flight capture cannot see loss behaviour. This is the largest
  remaining behavioural difference and no ClientHello fidelity closes it.
- **The HTTP/3 pseudo-header order.** The preset sends the library default `m,a,s,p`,
  which is plausible for a Chromium stack but is not confirmed for this client.
- **The unidirectional stream open order and the QPACK encoding choices.**
- **The reserved SETTINGS redraw cadence.** `TlsHttp3Options.Settings` is a list of literal
  pairs with no drawn slot, so it is redrawn per options object; the real client redraws
  per connection.

### Two header images, one QUIC shape

The app speaks HTTP/3 on more than one host, and the header block differs per leg while the
QUIC and TLS halves do not — and the QUIC/TLS half is identical across every endpoint measured
(41 QUIC captures, seven hostnames, one value for every cipher, extension, group, signature
algorithm and transport-parameter set). So there is ONE preset, and it declares no header order
at all: fields reach the wire in the order the caller added them.

The measured header images are recorded in USAGE.md section 7. Two of them:

| Captured leg | Header order |
|---|---|
| `spclient.wg.spotify.com` GET | `accept, x-client-id, accept-encoding, priority, app-platform, user-agent, authorization, accept-language, spotify-app-version` |
| `login5.spotify.com` POST `/v4/login` | `content-type, accept, priority, accept-encoding, x-retry-count, cache-control, content-length, user-agent, accept-language, client-token` |

The second is not the first reordered: each carries names the other does not.
`Content-Type` and `Content-Length` come from the request body, and the captured order
interleaves them among session headers — `Http3FieldMapperTests` pins that offline, because
`tls3.peet.ws` reports HTTP/3 field lines in an order that varies between runs and so cannot
settle it.

Two more honest limits:

- The **User-Agent** is `Spotify/9.1.76 iOS/27.0 (iPhone17,2)` on both HTTP/3 legs. Over
  **HTTP/2** the same app's `login5` leg uses
  `Spotify/917602050 CFNetwork/3892.100.1 Darwin/27.0.0` instead — that string belongs to
  the TCP path and is not what either h3 preset sends.
- The **header order** is the captured h3 `GET` order. `Authorization` and `X-Client-Id`
  are per-account credentials the preset leaves empty; set them on the session and they
  take their captured positions, because `HeaderOrder` places headers rather than
  insertion order. `Accept-Language: en-US,en;q=0.9` is the captured device's UI language,
  not a fingerprint axis: change it freely.

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

The HTTP/2 values for `Chrome133`, `Firefox148`, and `Android11` — and only those three;
see Provenance above for `Spotify917602050IOS270Http3` — were transcribed from
bogdanfinn/tls-client commit
[`b790a311273f26051935641120de169e497e5943`](https://github.com/bogdanfinn/tls-client/commit/b790a311273f26051935641120de169e497e5943):

- [Chrome 133 profile](https://github.com/bogdanfinn/tls-client/blob/b790a311273f26051935641120de169e497e5943/profiles/internal_browser_profiles.go#L820-L935)
- [Firefox 148 profile](https://github.com/bogdanfinn/tls-client/blob/b790a311273f26051935641120de169e497e5943/profiles/contributed_browser_profiles.go#L10-L151)
- [OkHttp Android 11 profile](https://github.com/bogdanfinn/tls-client/blob/b790a311273f26051935641120de169e497e5943/profiles/contributed_custom_profiles.go#L1250-L1274)

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
request.Headers.TryAddWithoutValidation("content-length", "-1");   // slot, not value
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

`HeaderOrder`, `PseudoHeaderOrder`, `HeaderPriority`, `PriorityUpdate`, `HeadersPadding`,
`DataPadding`, `Scheme`, `Protocol`, `PathOverride` and `AuthorityMode` are nullable
per-request overrides on the same object; null falls back to the session value.

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
