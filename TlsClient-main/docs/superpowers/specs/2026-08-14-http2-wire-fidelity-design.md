# HTTP/2 wire fidelity design

Date: 2026-08-14
Status: approved for implementation planning
Applies to: a private fork of TlsClient `0.6.0-preview.1`
Revision: 2 — absorbs a protocol review that found six critical defects and sixteen
uncovered wire axes in revision 1.

## Purpose

Make every byte TlsClient writes on an HTTP/2 connection a declared value rather than a
compiled-in constant, so that a captured client can be replayed exactly. The current
implementation expresses the four components of the widely used Akamai HTTP/2
fingerprint, but a large number of observable behaviors below that level are hardcoded
and cannot be configured at all.

The working standard is a specific one: reproduce an arbitrary observed client — a mobile
application on a bespoke HTTP stack, not only a desktop browser — byte for byte on the
wire. Configurability that covers an axis real clients vary on is the product. A knob is
only unnecessary when the protocol itself fixes the value.

This document covers HTTP/2 only. HTTP/3 and QUIC are deliberately out of scope and are
expected to follow as separate work.

## Goals

- Any HTTP/2 connection preface a real client can produce is expressible as data,
  including unknown SETTINGS identifiers, duplicate identifiers, and unknown frame types.
- Every HPACK representation defined by RFC 7541 is reachable, and both the choice
  between them and the table index used are policies the caller controls.
- The request lifecycle is declarative: header ordering, pseudo-header composition,
  priority signalling, and any additional frames sent around a request are per-request
  values, not session constants.
- The data path is declarative: DATA frame sizing, end-of-body framing, and flow-control
  replenishment are declared rather than derived from internal code paths.
- Connection shutdown and stream reset codes are declared.
- The complete HTTP/2 persona remains serializable through `TlsHttpBehaviorProfile`, and
  can be derived from a captured connection rather than written by hand.

## Non-goals

- Changing HTTP/1.1 behavior, except where a request-scoped option is explicitly defined
  to apply to both protocols.
- Preserving the shipped public API. This is a private fork; `PublicAPI.Shipped.txt` is
  rewritten rather than extended, and no compatibility shims are kept.
- Weakening the receive path's hostile-input posture. The HPACK decoder, frame reader,
  and parser bounds remain strict.

Note that "send-side only" is *not* a non-goal, because it is not achievable. Several
SETTINGS values a client declares govern what it must then accept — see
[Deriving local receive state](#deriving-local-receive-state-from-the-script). Declaring
`(2, 1)` obliges the connection to accept PUSH_PROMISE; declaring `(6, N)` binds its own
header-list limit. That is the honest consequence of a client being bound by what it
advertises, and it is stated rather than papered over.

## Gaps this closes

Each item was confirmed by reading the current implementation.

### Connection and encoding

| Gap | Where it lives today |
|---|---|
| SETTINGS identifiers restricted to eight known values | `TlsHttp2Setting` enum; `GetSettingValue` at `Http2Connection.cs:1496` |
| `ENABLE_PUSH` value hardcoded to `0` | `Http2Connection.cs:1501` |
| Preface frame order fixed as SETTINGS, WINDOW_UPDATE, PRIORITY | `SendClientPrefaceAsync` at `Http2Connection.cs:241` |
| No way to emit an unknown or GREASE frame | same |
| Initial stream identifier always 1, step always 2 | `_nextStreamId` at `Http2Connection.cs:30`, incremented at `:121` |
| Literal without indexing (`0x00`) never emitted | `HpackEncoder.Encode` at `HpackCodec.cs:95` |
| Never-indexed representation fixed to `cookie` and `authorization` | `Http2Connection.cs:644` |
| Huffman coding always "when strictly shorter" | `WriteString` at `HpackCodec.cs:238,247` |
| Dynamic table always used; no static-only mode | `HpackEncoder.Add` at `HpackCodec.cs:175` |
| Dynamic table size update timing not controllable; only one update per block | `_pendingDynamicTableSizeUpdate` at `HpackCodec.cs:81` |
| Static name index always the lowest match | `FindName` at `HpackCodec.cs:156-173` |
| Cookie crumbling not implemented | `BuildRequestHeaders` at `Http2Connection.cs:601` |
| Multi-value headers always emitted as separate fields, never joined | `Http2Connection.cs:645-648` |
| Write batching fixed: one write per frame, flush points hardcoded | `Http2Connection.cs:246-289`, `:334`, `:377` |

### Request lifecycle

| Gap | Where it lives today |
|---|---|
| Header order and pseudo-header order are session-scoped only | `TlsSessionOptions.HeaderOrder`, `TlsHttp2Options.PseudoHeaderOrder` |
| HEADERS priority is one session-wide value for every stream | `TlsHttpVersionPolicy.cs:91`, applied at `Http2Connection.cs:1332` |
| PRIORITY_UPDATE is one session-wide value, always emitted after HEADERS | `TlsHttpVersionPolicy.cs:100`, `Http2Connection.cs:321-333` |
| No mid-connection PRIORITY frames, no client-initiated PING | script is preface-only; `HandlePingAsync:985` only echoes |
| Pseudo-header set fixed to four; `:protocol` (RFC 8441) unreachable | `TlsHttpVersionPolicy.cs:137-144`, `Http2Connection.cs:617-628` |
| `host` unconditionally dropped; `:scheme` hardcoded to `https` | `Http2Connection.cs:633`, `:621` |
| `:path` always derived from the URI; `OPTIONS *` inexpressible | `Http2Connection.cs:611-615` |
| HEADERS/DATA padding never emitted | decode-only at `RemovePadding:1408` |
| `Trailer` request header emitted on HTTP/2 whenever trailers exist | `Http11RequestWriter.cs:88-91` |
| CONTINUATION splits at the peer's `MAX_FRAME_SIZE` only | `WriteHeaderBlockLockedAsync` at `Http2Connection.cs:1320` |

### Data path and shutdown

| Gap | Where it lives today |
|---|---|
| DATA frames sized at whatever the peer permits, up to 16 MiB | `ReserveSendWindowAsync` at `Http2Connection.cs:1106-1110` |
| End-of-body framing chosen by internal code path, not by persona | `:318` (empty), `:370-373` (buffered), `:450-454` (streaming) |
| WINDOW_UPDATE increment always equals bytes consumed | `RestoreReceiveWindowAsync` at `Http2Connection.cs:1230,:1239` |
| WINDOW_UPDATE triggered on application consumption, never on receipt | `PumpBodyAsync` at `Http2Connection.cs:1886` |
| Connection and stream updates never coalesced; order fixed | `SendWindowUpdateAsync` at `Http2Connection.cs:1204-1210` |
| Stream update silently suppressed on end-of-stream | `Http2Connection.cs:1235-1238` |
| No GOAWAY on normal shutdown | `DisposeAsync` at `Http2Connection.cs:213-239` |
| RST_STREAM codes hardcoded per situation | `:161`, `:174`, `:194`, `:906` |

### Tooling

| Gap | Where it lives today |
|---|---|
| No way to derive an HTTP/2 persona from a capture, while the TLS half already has one | `TlsHttpBehaviorProfile.Capture` reads configuration, not wire bytes |

## Architecture

The existing two-stage shape is preserved: a mutable options object is validated and
frozen into an immutable configuration record at session construction, which the
connection then reads.

```
TlsHttp2Options
├── Preface        : IReadOnlyList<TlsHttp2PrefaceFrame>
├── Hpack          : TlsHpackOptions
├── FlowControl    : TlsHttp2FlowControlOptions
├── Data           : TlsHttp2DataOptions
├── Shutdown       : TlsHttp2ShutdownOptions
├── PseudoHeaders  : TlsHttp2PseudoHeaderOptions
├── InitialStreamId, StreamIdStep
├── HeaderBlockFragmentSize, SettingsAckPlacement
├── EmitTrailerHeader
└── HeaderPriority, PriorityUpdate          (session defaults; overridable per request)

TlsRequestOptions  (per request, null means fall back to session)
├── HeaderOrder, PseudoHeaderOrder
├── HeaderPriority, PriorityUpdate
├── FramesBeforeHeaders, FramesAfterHeaders : IReadOnlyList<TlsHttp2RequestFrame>
├── Scheme, Protocol, PathOverride, AuthorityMode
└── HeadersPadding, DataPadding
```

`TlsHttp2Options` moves out of `TlsHttpVersionPolicy.cs` into its own `TlsHttp2Options.cs`.

### Removed members

`SettingsOrder`, `HeaderTableSize`, `InitialWindowSize`, `MaxFrameSize`,
`MaxHeaderListSize`, `MaxConcurrentStreams`, `EnableConnectProtocol`,
`DisableRfc7540Priorities`, `ConnectionWindowIncrement`, and `InitialPriorityFrames` are
all removed. Every one is expressible through the preface script, and keeping both forms
would create two ways to describe one wire behavior.

The `TlsHttp2Setting` enum is removed. Settings are identified by raw `ushort`.

`Http2ErrorCode` becomes public, because shutdown and reset codes are now declared.

## Preface script

```csharp
public abstract class TlsHttp2PrefaceFrame
{
    public bool FlushAfter { get; set; }
}

public readonly record struct TlsHttp2SettingValue(ushort Id, uint Value);

public sealed class TlsHttp2SettingsFrame : TlsHttp2PrefaceFrame
{
    public IReadOnlyList<TlsHttp2SettingValue> Settings { get; set; } = [];
}

public sealed class TlsHttp2WindowUpdateFrame : TlsHttp2PrefaceFrame
{
    public uint Increment { get; set; }
}

public sealed class TlsHttp2PriorityFrame : TlsHttp2PrefaceFrame
{
    public int StreamId { get; set; }
    public TlsHttp2Priority Priority { get; set; } = new();
}

public sealed class TlsHttp2RawFrame : TlsHttp2PrefaceFrame
{
    public byte Type { get; set; }
    public byte Flags { get; set; }
    public int StreamId { get; set; }
    public byte[] Payload { get; set; } = [];
}
```

`TlsHttp2Options.Preface` is an ordered list. After the connection preface magic each
entry is serialized in the order given. An empty list sends the magic alone, which is
legal and was previously inexpressible. A settings frame with an empty `Settings` list
writes a zero-length SETTINGS frame, which some clients do send.

`FlushAfter` controls write batching — see [Write batching](#write-batching). The default
is `false` on every entry with a single flush after the last, reproducing today's
behavior.

`TlsHttp2WindowUpdateFrame` carries no stream identifier because it is always written on
stream 0. No stream has been opened at preface time, and RFC 9113 section 5.1 makes any
frame other than HEADERS or PRIORITY on an idle stream a connection error, so no
conforming client emits one here. A target that does so anyway is reproducible through
`TlsHttp2RawFrame` with type `0x8`.

`TlsHttp2PriorityFrame` replaces the existing public type of the same name. The old one
was an element of `InitialPriorityFrames`; the new one is a preface script entry. Since
`InitialPriorityFrames` is removed the two never coexist, so the name is reused rather
than versioned. `TlsHttp2Priority` itself is unchanged and is shared with `HeaderPriority`
and the per-request frame script.

### SETTINGS acknowledgement placement

Where the acknowledgement lands in the outbound frame sequence is observable, so it is a
declared position rather than a timing policy.

```csharp
public enum TlsHttp2SettingsAckPlacement
{
    Standalone,      // own write and flush, on receipt
    BeforeNextBatch, // coalesced ahead of the next write batch this connection emits
    AfterNextBatch,  // coalesced behind the next write batch this connection emits
}
```

`Standalone` is the default and preserves current behavior.

The unit of coalescing is a **write batch**, not a frame. A header block is HEADERS
followed by zero or more CONTINUATION frames, and RFC 9113 sections 6.2 and 6.10 require
CONTINUATION to follow immediately with no interleaved frames of any type. An
acknowledgement is therefore never inserted inside a header block: `AfterNextBatch`
places it after the final CONTINUATION, and `BeforeNextBatch` places it before the
HEADERS frame. The same rule applies to any other multi-frame batch the connection emits.

Deferral is bounded by the connection's own writes, not by inbound traffic. A pending
acknowledgement is flushed standalone when either of these occurs first: the connection
has written nothing by the time it must process a frame whose handling depends on the new
settings taking effect, or the connection goes idle with no queued work. Binding the
bound to inbound frames instead would make both coalescing values unreachable in
practice, because servers routinely send SETTINGS and WINDOW_UPDATE in one flight and the
read loop processes them back to back before the client writes anything.

### Deriving local receive state from the script

The removed properties were not only wire values; the connection reads several of them to
configure its own receive behavior. Once SETTINGS is an opaque list, local state must be
derived from the script, because a client is bound by what it advertises.

Identifiers that feed local state, and what they bind:

| Id | Local effect | Current source |
|---|---|---|
| `0x1` HEADER_TABLE_SIZE | HPACK decoder dynamic table bound | `Http2Connection.cs:56-58` |
| `0x2` ENABLE_PUSH | whether an inbound PUSH_PROMISE is a connection error | `HandlePushPromiseAsync:853` |
| `0x4` INITIAL_WINDOW_SIZE | initial per-stream receive window | stream state seed |
| `0x5` MAX_FRAME_SIZE | maximum inbound frame the reader accepts | `_localMaximumFrameSize:49-50` |
| `0x6` MAX_HEADER_LIST_SIZE | inbound header-list decode bound | `HandleHeadersAsync:823-825` |

Rules:

1. Scan every `TlsHttp2SettingsFrame` in the script, and every `TlsHttp2RawFrame` of type
   `0x4`, in script order.
2. Known identifiers configure local receive state and are range-validated.
3. Unknown identifiers are written to the wire and otherwise ignored.
4. On duplicate identifiers, every occurrence is written; the last determines local state,
   matching how a conforming peer processes the frame.
5. Identifiers absent from the script leave local state at the RFC 9113 default.
6. The connection receive window is seeded as `65535 + Σ increments` over every
   `TlsHttp2WindowUpdateFrame` and every `TlsHttp2RawFrame` of type `0x8` on stream 0.
   This replaces the removed `ConnectionWindowIncrement`, which
   `Http2Connection.cs:59-60` uses today and enforces hard at `HandleDataAsync:757-762`.

Rules 1 and 6 deliberately parse raw frames of types `0x4` and `0x8`, because the raw
escape hatch is otherwise a foot-gun: a persona could advertise credit or limits on the
wire that local state never records, and then abort the connection the moment the peer
relies on them.

Declaring these values changes what the connection accepts. That is intended, and is the
reason the "send-side only" framing was dropped from the non-goals.

## HPACK policy

```csharp
public enum TlsHpackRepresentation
{
    Indexed,
    LiteralIncrementalIndexing,
    LiteralWithoutIndexing,
    LiteralNeverIndexed,
}

public enum TlsHpackHuffman { WhenShorter, WhenNotLonger, Always, Never }

public enum TlsHpackTableSizeUpdate { Never, OnPeerSettingsChange, BeforeFirstRequest }

public enum TlsHpackNameIndex { LowestStatic, HighestStatic, MostRecentDynamic }

public enum TlsHpackMultiValue { SeparateFields, Join }

public sealed class TlsHpackOptions
{
    public TlsHpackRepresentation DefaultRepresentation { get; set; }
        = TlsHpackRepresentation.Indexed;

    public TlsHpackRepresentation IndexedFallback { get; set; }
        = TlsHpackRepresentation.LiteralIncrementalIndexing;

    public bool UseDynamicTable { get; set; } = true;

    public IDictionary<string, TlsHpackRepresentation> PerHeader { get; }
    public TlsHpackHuffman Huffman { get; set; } = TlsHpackHuffman.WhenShorter;
    public IDictionary<string, TlsHpackHuffman> PerHeaderHuffman { get; }

    public TlsHpackNameIndex NameIndex { get; set; } = TlsHpackNameIndex.LowestStatic;
    public IDictionary<string, int> PerHeaderNameIndex { get; }

    public TlsHpackMultiValue MultiValue { get; set; } = TlsHpackMultiValue.SeparateFields;
    public IDictionary<string, TlsHpackMultiValue> PerHeaderMultiValue { get; }
    public string MultiValueJoinSeparator { get; set; } = ", ";

    public TlsHpackTableSizeUpdate TableSizeUpdate { get; set; }
        = TlsHpackTableSizeUpdate.OnPeerSettingsChange;
    public IReadOnlyList<uint> TableSizeUpdateValues { get; set; } = [];

    public bool CrumbleCookies { get; set; }
    public string CookieCrumbSeparator { get; set; } = "; ";
}
```

### Encoder rules

For each header field, in order:

1. Resolve one representation: `PerHeader[name]` if present, else
   `DefaultRepresentation`.
2. If the resolved representation is `Indexed`, emit `0x80` when an exact name/value
   match exists in the static or dynamic table, and otherwise emit `IndexedFallback`.
3. If the resolved representation is a literal form, emit that form and never an indexed
   reference, even when an exact match exists — `0x40` incremental indexing, `0x00`
   literal without indexing, `0x10` never indexed — using a name index when the name
   alone is found.
4. Select the name index per `PerHeaderNameIndex[name]` if present, else `NameIndex`.
   `LowestStatic` reproduces today's `FindName`. This matters wherever a name has more
   than one static entry: `:method` is index 2 or 3, `:path` 4 or 5, `:scheme` 6 or 7.
   An explicit `PerHeaderNameIndex` entry is used verbatim and is validated to name an
   entry whose name matches the field.
5. Insert into the dynamic table only for `LiteralIncrementalIndexing`, and only when
   `UseDynamicTable` is true. This is required by RFC 7541: the other two literal forms
   explicitly do not update the table.
6. Apply Huffman coding per `PerHeaderHuffman[name]` if present, else `Huffman`.
   `WhenShorter` encodes only when the Huffman form is strictly shorter, matching
   `HpackCodec.cs:247`; `WhenNotLonger` also encodes on a tie. The two differ on real
   short values, so the distinction is observable.

`IndexedFallback` exists because `Indexed` alone cannot express the canonical shape of a
client that reads the static table but does not populate its own dynamic table:
`0x82` for `:method: GET`, `0x00`-prefixed literals for everything else. Without it,
`UseDynamicTable = false` emits `0x40` literals that announce incremental indexing while
suppressing the local insert — a byte no real static-only client emits, and one that
obliges the peer to insert an entry the client will never reference.

`UseDynamicTable = false` yields a static-table-only encoder that never inserts and
therefore never evicts.

### Dynamic table size updates

`TableSizeUpdate` controls emission: `Never` suppresses it entirely;
`OnPeerSettingsChange` reproduces today's behavior of emitting when the peer's
`SETTINGS_HEADER_TABLE_SIZE` differs from the current value; `BeforeFirstRequest` emits
once ahead of the first header block.

`TableSizeUpdateValues` is a list because RFC 7541 section 4.2 permits consecutive
updates, and the "size 0 then size N" pair — evict everything, then resize — is a real
encoder signature that a single value cannot express. An empty list means use the peer's
advertised value. Every value is applied to the encoder's own table as it is emitted, so
the declared size and the encoder's eviction behavior stay consistent.

### Multi-value headers

A `HeaderEntry` holding several values is emitted as one HPACK field per value today
(`Http2Connection.cs:645-648`). `MultiValue`/`PerHeaderMultiValue` selects that or a
single field with the values joined by `MultiValueJoinSeparator`. This is the mirror of
cookie crumbling: both directions of the same axis, and stacks differ on both.

### Cookie crumbling

When `CrumbleCookies` is true, a single `cookie` header whose value contains the
separator is split into one field per crumb, in order, each encoded independently under
the same policy. Permitted by RFC 9113 section 8.2.3 and observable on the wire. Applies
to HTTP/2 only; the HTTP/1.1 writer is untouched.

Clients that crumble generally do so in order to index individual crumbs, so a crumbling
persona will usually also want `PerHeader["cookie"]` changed away from its
`LiteralNeverIndexed` default.

### Default equivalence

Defaults reproduce the current encoder's output byte for byte, with one deliberate
exception documented below. `DefaultRepresentation` is `Indexed` with `IndexedFallback`
at `LiteralIncrementalIndexing`, which is exactly what the current encoder does. The
hardcoded never-index behavior for `cookie` and `authorization` is relocated into the
default `PerHeader` contents rather than removed.

**The exception.** Rule 3 forbids an indexed reference for a literal representation, and
for empty-valued `cookie` or `authorization` that changes the bytes. The static table
entries are `("authorization", "")` at index 23 and `("cookie", "")` at index 32
(`HpackCodec.cs:34,43`) — the values are empty strings, not absent — and `FindExact`
compares `header.Value == value` (`HpackCodec.cs:140`). So `Cookie: ""` reaches
`FindExact`, matches index 32, and today emits the single byte `0xA0`. Under rule 3 it
becomes a never-indexed literal with name index 32, three bytes. The same holds for
`authorization: ""`.

This is reachable through the public API — `TlsHeaders.ValidateValue`
(`TlsHeaders.cs:214-222`) rejects only CR and LF, so an empty value is accepted — but no
preset and no realistic request sends one. The divergence is accepted rather than
patched, because emitting a literal is the more faithful behavior for a persona that
declares those fields never-indexed: a client that never indexes its credentials does not
suddenly emit an indexed reference for an empty one. A test pins the exception so it
stays deliberate.

## Request lifecycle

The preface script makes connection setup declarative. The same treatment applies to each
request, because per-request variation is the norm in real clients: Firefox assigns
different HEADERS weights and dependency parents by resource class, and Chrome varies its
RFC 9218 priority field by resource type.

### Per-request frame script

```csharp
public abstract class TlsHttp2RequestFrame
{
    public bool FlushAfter { get; set; }
}

public sealed class TlsHttp2StreamPriorityFrame : TlsHttp2RequestFrame
{
    public TlsHttp2Priority Priority { get; set; } = new();
}

public sealed class TlsHttp2PriorityUpdateFrame : TlsHttp2RequestFrame
{
    public string Value { get; set; } = "";
}

public sealed class TlsHttp2PingFrame : TlsHttp2RequestFrame
{
    public byte[] Payload { get; set; } = new byte[8];
}

public sealed class TlsHttp2RequestRawFrame : TlsHttp2RequestFrame
{
    public byte Type { get; set; }
    public byte Flags { get; set; }
    public int StreamId { get; set; }
    public byte[] Payload { get; set; } = [];
}
```

`TlsRequestOptions.FramesBeforeHeaders` and `FramesAfterHeaders` are ordered lists written
immediately before and after the request's header block. Two lists rather than one list
with a position marker, because the header block's position is then unambiguous and no
sentinel entry is needed.

This one mechanism subsumes four separate axes: PRIORITY frames on the stream before
HEADERS, PRIORITY_UPDATE placement either side of HEADERS (today it is unconditionally
after, at `Http2Connection.cs:321-333`), mid-connection PRIORITY updates, and
client-initiated PING. Frames targeting stream 0 are permitted in both lists; frames
targeting the request's own stream use `StreamId = 0` as a sentinel meaning "this
request's stream", resolved at send time since the identifier is not known when the
options are built.

Session-level `PriorityUpdate` remains as a default: when set and the request declares no
`TlsHttp2PriorityUpdateFrame`, one is emitted after HEADERS as today.

### Per-request priority and ordering

```csharp
// TlsRequestOptions, all nullable, null falls back to the session value
public IReadOnlyList<string>? HeaderOrder { get; set; }
public IReadOnlyList<string>? PseudoHeaderOrder { get; set; }
public TlsHttp2Priority? HeaderPriority { get; set; }
public string? PriorityUpdate { get; set; }
public int? HeadersPadding { get; set; }
public int? DataPadding { get; set; }
```

`HeaderOrder` applies to both HTTP/1.1 and HTTP/2, because `Http11RequestWriter.Order`
(`Http11RequestWriter.cs:23`) is already shared between the HTTP/1.1 writer and the
HTTP/2 header builder (`Http2Connection.cs:607`) and splitting the semantics by protocol
would be surprising. Every other option in this section is HTTP/2 only and is ignored on
an HTTP/1.1 connection rather than throwing, so a persona can be applied to a session
whose version policy permits fallback.

`HeadersPadding` and `DataPadding` set the PADDED flag and pad length. The decode path
already handles padding (`RemovePadding:1408`, `ExtractHeaderFragment:1421`); only the
send side is new. No mainstream browser pads, but it is a legal per-frame axis a bespoke
application can use.

### Pseudo-headers

The current builder hardcodes four pseudo-headers with `:scheme` fixed to `https`
(`Http2Connection.cs:617-628`) and validation requires a permutation of exactly those four
(`TlsHttpVersionPolicy.cs:137-144`). That makes RFC 8441 extended CONNECT unreachable —
and extended CONNECT is how `URLSessionWebSocketTask` negotiates WebSocket over HTTP/2, so
any iOS application with a WebSocket is currently unreproducible. It is also internally
inconsistent, since the preface script can now advertise
`SETTINGS_ENABLE_CONNECT_PROTOCOL`.

```csharp
public enum TlsHttp2AuthorityMode { AuthorityOnly, HostHeaderOnly, Both }

public sealed class TlsHttp2PseudoHeaderOptions
{
    public IReadOnlyList<string> Order { get; set; }
        = [":method", ":authority", ":scheme", ":path"];
    public TlsHttp2AuthorityMode AuthorityMode { get; set; }
        = TlsHttp2AuthorityMode.AuthorityOnly;
    public string Scheme { get; set; } = "https";
}

// TlsRequestOptions
public string? Scheme { get; set; }
public string? Protocol { get; set; }      // RFC 8441 :protocol
public string? PathOverride { get; set; }  // e.g. "*" for OPTIONS *
public TlsHttp2AuthorityMode? AuthorityMode { get; set; }
```

`Order` declares which pseudo-headers are emitted and in what sequence, rather than
permuting a fixed set. `:protocol` is emitted when `Protocol` is set and appears in the
order. `PathOverride` supplies `:path` verbatim, making `OPTIONS *` expressible.

`AuthorityMode` selects `:authority` alone (today's behavior and the default — `host` is
unconditionally dropped at `Http2Connection.cs:633`), a `host` regular header alone, or
both. **An earlier revision of this section said RFC 9113 section 8.3.1 permits all three.
It does not, and the code does not claim it does.** Section 8.3.1: "Clients that generate
HTTP/2 requests directly MUST use the ':authority' pseudo-header field to convey authority
information, unless there is no authority information to convey (in which case it MUST NOT
generate ':authority')." A normal origin request has authority information to convey, so
the excuse does not apply and this is a MUST on the two conformant modes:

- `AuthorityOnly` satisfies it directly.
- `Both` satisfies it as well, and stays conformant only while the two fields agree.
  Section 8.3.1: "Clients MUST NOT generate a request with a Host header field that differs
  from the ':authority' pseudo-header field", and a server "SHOULD treat a request as
  malformed" when they identify different entities. TlsClient derives both from one value —
  the request's `Host` field when it carries one, otherwise the authority of the request
  URI — so they agree by construction.
- `HostHeaderOnly` **deliberately violates that MUST**, and is the only mode that does.
  Section 8.3.1 defines no server fallback to `host` when `:authority` is absent, so whether
  a peer routes such a request at all is server-dependent. It exists because TlsClient
  reproduces the wire image of clients that exist, including non-conformant ones — some
  intermediaries and hand-rolled stacks forward the `host` field they received and never
  synthesise `:authority`, and a capture of one cannot be replayed without it. Choose it to
  reproduce such a client, never for a client of your own design.

What stacks genuinely differ on is which of the three they picked, not whether the RFC
leaves the choice open. The axis is a fidelity axis, not a conformance one.

Validation is per request at send time, because legality depends on the method: `:method`
is always required; a CONNECT request without `:protocol` may carry only `:method` and
`:authority`; a CONNECT request with `:protocol` requires `:method`, `:authority`,
`:scheme`, `:path`, `:protocol`; any other method requires `:method`, `:scheme`, `:path`
and permits `:authority`. A request whose declared order is illegal for its method throws
before any byte is written.

### Header block framing

`TlsHttp2Options.HeaderBlockFragmentSize` is a nullable `int`. When set, the CONTINUATION
split size is `min(HeaderBlockFragmentSize, peerMaxFrameSize)` — it can only produce
fragments smaller than the peer permits, never larger.

Two details the previous revision left broken:

- The clamp uses 16384 until the peer's SETTINGS has been applied. `_peerMaximumFrameSize`
  is seeded at 16384 (`Http2Connection.cs:31`) and rises only when the peer's SETTINGS is
  processed, which races the first request because the preface is written before the read
  loop starts (`CreateAsync:87-88`). Without a stated rule, a persona declaring a fragment
  size above 16384 would fragment differently depending on scheduling. Replay must be
  deterministic, so the pre-SETTINGS value is fixed at the RFC default.
- `HeaderBlockFragmentSize` must be at least 6 whenever a priority payload may be present.
  `WriteHeaderBlockLockedAsync` computes `Math.Min(maximumFrameSize - priorityLength, …)`
  with `priorityLength` of 5, so a fragment size of 1 to 5 produces a negative length and
  throws at request time. Since per-request priority means the session cannot know whether
  any request will carry one, the minimum is enforced unconditionally at 6.

  **The floor of 6 is necessary but not sufficient, and this bullet predates the reason.**
  It was written before padding existed, and padding was then put into the same budget: a
  padded HEADERS frame spends `1 + padLength` — up to 256 octets — out of the fragment's
  own share, because RFC 9113 section 6.2 puts the Pad Length octet and the padding inside
  the frame payload and section 4.2 measures the whole payload. A declared size of 6 with a
  255-octet pad therefore still computes a negative length, and padding is per-request too,
  so raising the floor could not fix it either — the session cannot see the pad any more
  than it can see the priority. The writer instead guarantees at least one octet of field
  block per frame, `Math.Max(maximumFrameSize - priorityLength - padOverhead, 1)`. That
  overruns the client's own declared size and nothing else: pad plus priority plus one is at
  most 262 octets, and section 4.2 floors the peer's own advertised limit at 16384. It is
  also what keeps the split loop advancing rather than looping on a zero-length fragment.
  Recorded in commit `bb688de`.

`EmitTrailerHeader` (default `true`, preserving current behavior) controls the `Trailer`
request header that `Http11RequestWriter.cs:88-91` adds whenever trailers are present.
Real HTTP/2 clients generally do not send it.

## Data path

```csharp
public enum TlsHttp2EndStreamPlacement { OnLastDataFrame, SeparateEmptyDataFrame }

public sealed class TlsHttp2DataOptions
{
    public int? MaxDataFrameSize { get; set; }

    public TlsHttp2EndStreamPlacement NonEmptyBody { get; set; }
        = TlsHttp2EndStreamPlacement.OnLastDataFrame;

    public bool EmptyBodyEndsOnHeaders { get; set; } = true;
}
```

`MaxDataFrameSize` caps the client's own DATA frames. Today `ReserveSendWindowAsync`
(`Http2Connection.cs:1106-1110`) sizes each frame at
`min(remaining, peerMaxFrameSize, connectionWindow, streamWindow)`, i.e. as large as the
peer permits — up to 16 MiB. Real clients self-cap well below that; 16384 is the common
value. The effective size is `min(MaxDataFrameSize, peerMaxFrameSize, windows)`, with the
same pre-SETTINGS determinism rule as header fragments. For a POST-heavy application the
DATA size histogram is among the most visible properties of the connection.

End-of-stream framing is currently chosen by internal code path rather than by persona:
END_STREAM on HEADERS for a zero-length body (`:318`), on the last DATA frame for a
buffered body (`:370-373`), and a *separate empty DATA frame* for a streaming body
(`:450-454`). Those two switches make the choice explicit and independent of how the
caller happened to supply the body.

## Flow control

```csharp
public enum TlsHttp2WindowUpdateTrigger { OnConsume, OnReceive }
public enum TlsHttp2WindowUpdateIncrement { BytesAccounted, RefillToInitial, Fixed }
public enum TlsHttp2WindowUpdateOrder { ConnectionFirst, StreamFirst }

public sealed class TlsHttp2FlowControlOptions
{
    public uint StreamWindowUpdateThreshold { get; set; }
    public uint ConnectionWindowUpdateThreshold { get; set; }

    public TlsHttp2WindowUpdateTrigger Trigger { get; set; }
        = TlsHttp2WindowUpdateTrigger.OnConsume;
    public TlsHttp2WindowUpdateIncrement Increment { get; set; }
        = TlsHttp2WindowUpdateIncrement.BytesAccounted;
    public uint FixedIncrement { get; set; }

    public TlsHttp2WindowUpdateOrder Order { get; set; }
        = TlsHttp2WindowUpdateOrder.ConnectionFirst;
    public bool CoalesceConnectionAndStream { get; set; }
    public bool SuppressStreamUpdateOnEndStream { get; set; } = true;
}
```

Five independent axes, all fixed today:

- **Threshold.** `0` restores credit as bytes are accounted, preserving current behavior.
  Any other value accumulates and emits only once that many bytes are outstanding.
- **Trigger.** `OnConsume` credits when the application accepts data
  (`PumpBodyAsync:1886`); `OnReceive` credits on frame receipt. The two produce visibly
  different traces for a slow reader.
- **Increment.** `BytesAccounted` sends an increment equal to the bytes credited, which is
  what `RestoreReceiveWindowAsync:1230,:1239` does. `RefillToInitial` sends whatever
  restores the declared initial window. `Fixed` sends `FixedIncrement`.
- **Order and coalescing.** Today the connection-level update is written and flushed, then
  the stream-level one (`SendWindowUpdateAsync:1204-1210`). `Order` swaps them;
  `CoalesceConnectionAndStream` puts both in one write batch, which is what most clients
  do.
- **End-stream suppression.** The stream-level update is silently skipped when the stream
  is ending (`:1235-1238`). Some clients send it anyway.

Thresholds are validated against the declared windows: `StreamWindowUpdateThreshold` must
not exceed the declared `SETTINGS_INITIAL_WINDOW_SIZE`, and
`ConnectionWindowUpdateThreshold` must not exceed `65535 + Σ preface increments`.
Otherwise the window is exhausted before the threshold is reached, no WINDOW_UPDATE is
ever emitted, and the transfer stalls permanently. Both sides of that comparison now live
in the same options object, so the check is a cross-field rule in `Snapshot()`.

## Connection shutdown and reset codes

```csharp
public sealed class TlsHttp2ShutdownOptions
{
    public bool SendGoAwayOnDispose { get; set; }
    public Http2ErrorCode GoAwayErrorCode { get; set; } = Http2ErrorCode.NoError;
    public byte[]? GoAwayDebugData { get; set; }

    public Http2ErrorCode CancellationResetCode { get; set; } = Http2ErrorCode.Cancel;
    public Http2ErrorCode LocalFailureResetCode { get; set; } = Http2ErrorCode.InternalError;
    public Http2ErrorCode PushRejectionResetCode { get; set; } = Http2ErrorCode.Cancel;
}
```

`DisposeAsync` (`Http2Connection.cs:213-239`) closes the transport with no GOAWAY at all;
GOAWAY is sent only on an inbound protocol error (`ReadLoopAsync:683`). Whether a client
announces shutdown, with which code and last-stream-id, is observable. The three reset
codes are hardcoded today at `:161`, `:174`, `:194` and `:906`; which code a stack uses to
cancel a stream is a known discriminator.

Defaults preserve current behavior exactly: `SendGoAwayOnDispose` is `false`, and the
three reset codes match what the connection emits today.

## Write batching

Whether the magic, SETTINGS, and WINDOW_UPDATE land in one TLS record or several is
visible to any passive observer, and it is a layer above the TCP behavior the fidelity
ceiling excludes. Today the preface writes one frame at a time and flushes once
(`Http2Connection.cs:246-289`), the request path flushes after HEADERS and PRIORITY_UPDATE
(`:334`), and again after every DATA frame (`:377`).

`FlushAfter` on each preface and request frame declares a batch boundary. Two session
scalars cover the rest:

```csharp
public bool FlushAfterHeaderBlock { get; set; } = true;   // current behavior
public bool FlushAfterEveryDataFrame { get; set; } = true; // current behavior
```

A batch is written with a single underlying write where the transport permits it, so
batch boundaries and record boundaries correspond. This does not promise control over TLS
record splitting itself, which belongs to SharpTls.

## Validation

All validation happens in `TlsHttp2Options.Snapshot()` and throws at session
construction, except the per-request pseudo-header legality check, which necessarily runs
at send time.

- Known SETTINGS identifiers are range-checked per RFC 9113 section 6.5.2: `ENABLE_PUSH`
  0 or 1; `INITIAL_WINDOW_SIZE` at most 2^31 − 1; `MAX_FRAME_SIZE` within
  [16384, 16777215]. Unknown identifiers accept any value.
- A `TlsHttp2SettingsFrame` holds at most 2730 entries, so its encoded payload cannot
  exceed the 16384-octet default maximum frame size that applies before the peer's
  SETTINGS has been seen (RFC 9113 section 4.2).
- `TlsHttp2RawFrame.Type` may not be DATA (`0x0`), HEADERS (`0x1`), RST_STREAM (`0x3`),
  PUSH_PROMISE (`0x5`), GOAWAY (`0x7`), or CONTINUATION (`0x9`). The first, second, third,
  fifth and sixth are frames the connection owns or that only a server may send;
  PUSH_PROMISE from a client is a protocol error. SETTINGS (`0x4`) and WINDOW_UPDATE
  (`0x8`) *are* permitted precisely because rules 1 and 6 of the derivation parse them.
  PING (`0x6`), PRIORITY (`0x2`), PRIORITY_UPDATE (`0x10`), and unknown types are
  permitted.
- The preface script holds at most 32 frames; each raw payload is at most 16384 bytes.
- A priority frame's stream identifier may not equal its dependency.
- `InitialStreamId` must be odd and within [1, 2^31 − 1]. `StreamIdStep` must be even and
  within [2, 2^16].
- `HeaderBlockFragmentSize`, when set, must be within [6, 16777215]. The lower bound is
  the priority-payload rule above.
- `MaxDataFrameSize`, when set, must be within [1, 16777215].
- `TableSizeUpdateValues` entries must not exceed the peer's `SETTINGS_HEADER_TABLE_SIZE`
  when it is known, and must not exceed the encoder's configured maximum otherwise. RFC
  7541 section 6.3 makes a larger value a COMPRESSION_ERROR at the peer.
- Window thresholds must not exceed their declared windows, per the flow-control section.
- `PerHeaderNameIndex` values must reference a table entry whose name matches the key.
- `CookieCrumbSeparator` and `MultiValueJoinSeparator` must be non-empty.
- `PerHeader`, `PerHeaderHuffman`, `PerHeaderNameIndex`, and `PerHeaderMultiValue` keys
  must be lowercase HTTP tokens, consistent with the encoder's existing rejection of
  uppercase names.
- `IndexedFallback` must not be `Indexed`.
- Padding values, when set, must be within [0, 255] for a single pad-length octet.
- Every enum-typed option must be a defined value, matching how `HttpVersionPolicy` is
  already checked.

## Behavior profile portability

`TlsHttpBehaviorProfile` is extended to capture and restore the preface script, HPACK
policy, flow control, data options, shutdown options, pseudo-header options, stream
identifier settings, header block fragment size, and write-batching scalars, alongside the
header order and pseudo-header order it already carries. Raw frame payloads are base64.

The import path keeps its existing character: strict, case-sensitive, bounded to 256 KiB
by default, rejecting unknown and duplicate properties, and running the result through the
same validation used at session construction. It continues to exclude header values,
credentials, bodies, proxy data, and TLS configuration.

Per-request values are not part of the profile, since they belong to a request rather than
a persona.

## Deriving a persona from a capture

Every section above specifies a knob. None says how you learn what to set it to. For a
target that ships no preset the parameters must come from observation, so the inverse of
`TlsHttpBehaviorProfile` is part of this work rather than a follow-up.

The asymmetry is worth naming: the TLS half of a persona can already be imported from a
capture through `TlsClientHello.ImportCapture` (`TlsClientHello.cs:41`), which turns bytes
into an executable profile. The HTTP/2 half has no equivalent —
`TlsHttpBehaviorProfile.Capture` takes a `TlsSessionOptions` (`TlsHttpBehaviorProfile.cs:48`)
and so can only snapshot configuration that was already written by hand.

### Input

```csharp
public static TlsHttp2CaptureResult TlsHttp2Capture.Import(
    ReadOnlySpan<byte> clientToServerBytes,
    ReadOnlySpan<byte> serverToClientBytes,
    TlsHttp2CaptureOptions? options = null);
```

Both directions, because several inferences are about how the client *reacted* to the
server. A policy such as `OnPeerSettingsChange` cannot be distinguished from `Never`
without knowing whether the peer ever changed its table size, and that frame is in the
server-to-client stream. The server side may be empty, in which case every peer-dependent
inference is marked indeterminate rather than guessed.

Obtaining the streams is out of scope — they come from a proxy under the operator's
control or a TLS key log — but the importer accepts exactly those byte streams so any
acquisition method works.

### What is read directly

Everything in the preface script, because it is literally the bytes: frame types, flags,
stream identifiers, payloads, SETTINGS identifiers with their values, order and
duplicates, WINDOW_UPDATE increments, PRIORITY frames, and any unknown or GREASE frame.
Also read directly:

- `InitialStreamId` and `StreamIdStep`, from the first and subsequent HEADERS streams.
- `HeaderOrder` and `PseudoHeaderOrder`, from the decoded header block — the two
  highest-value outputs of any capture.
- The pseudo-header set, `AuthorityMode`, `Scheme`, and any `:protocol`.
- `HeaderPriority` and PRIORITY_UPDATE values and their placement relative to HEADERS.
- `SettingsAckPlacement`, from where the client's ACK sits in its own outbound sequence.
- Flow-control `Trigger`, `Increment`, `Order`, coalescing, and end-stream suppression,
  from WINDOW_UPDATE increments and their spacing against DATA received. Thresholds
  follow from the same series.
- `MaxDataFrameSize` and end-of-stream placement, from the DATA frame series.
- Shutdown behavior and reset codes, when the capture contains them.
- Padding, from the PADDED flag and pad length.

`HeaderBlockFragmentSize` is inferred **only** when a HEADERS frame lacked END_HEADERS,
i.e. an actual CONTINUATION was observed. When the block fit in one frame the first
fragment's length is simply the block size, and treating it as the fragment size would
pin every replayed request to that length and manufacture CONTINUATION frames the original
never sent. Absent a CONTINUATION the field is reported unobserved.

### What is inferred from header blocks

HPACK policy is recovered by decoding each header block while recording, per field, the
representation prefix used, the name index chosen, whether the value was Huffman coded,
whether one or more dynamic table size updates preceded the block, and how many `cookie`
fields appeared.

Two facts constrain the inference, and the earlier revision's promotion rule got both
wrong:

**Only fields where the encoder had a choice are evidence.** A field with an exact table
match tells you nothing about representation preference, because `Indexed` and a
literal-preferring policy are distinguished precisely by what they do on such a field.
Pseudo-headers almost always hit an exact static match, so counting them would let
`:method`, `:scheme` and `:path` alone promote `DefaultRepresentation = Indexed` in every
capture ever taken. Fields with an exact match are excluded from the representation
count, and a field observed as `0x40` on the first request and `0x80` on a later one is
the *signature* of an `Indexed` policy, not an inconsistency.

**Huffman needs a discriminating case.** Nearly every real header value is shorter Huffman
coded, so `WhenShorter`, `WhenNotLonger` and `Always` agree on almost every observation.
The deriver computes both lengths for each observed string and only counts fields where
they disagree — a value whose Huffman form is longer, or exactly equal. Absent such a
field, Huffman policy is reported unobserved rather than promoted to `Always`.

**Promotion.** A representation observed for one header name becomes a `PerHeader` entry.
It is promoted to `DefaultRepresentation` when at least three distinct *discriminating*
header names agree and no discriminating name disagrees; a split verdict leaves every
entry in `PerHeader` and reports the ambiguity. Contributing `PerHeader` entries are
removed on promotion, so the profile has one statement per behavior; entries that
disagree with the promoted default are retained.

**One request is not a policy.** For a field with no exact match, `Indexed` and
`LiteralIncrementalIndexing` emit the same `0x40` on first use and diverge only on the
second occurrence. An observation therefore records "saw prefix `0x40` once" distinctly
from "determined a policy", and the latter requires a repeat.

### Output

```csharp
public sealed class TlsHttp2CaptureResult
{
    public TlsHttpBehaviorProfile Profile { get; }
    public IReadOnlyList<TlsHttp2CaptureObservation> Observations { get; }
    public int RequestsSeen { get; }
}

public enum TlsHttp2ObservationState { Measured, Indeterminate, Defaulted }

public sealed class TlsHttp2CaptureObservation
{
    public string Field { get; }
    public TlsHttp2ObservationState State { get; }
    public int EvidenceCount { get; }
    public string? Reason { get; }
}
```

The result is an audit trail, not just a profile. An operator must be able to see that
`TableSizeUpdate` is `Indeterminate` because the peer never changed its table size on that
connection, or that `Huffman` is `Indeterminate` because no discriminating value appeared.
Guessing silently would defeat the purpose.

Two fields are unrecoverable in principle and are always `Defaulted`:
`CookieCrumbSeparator`, because crumbs do not carry their separator; and the distinction
between a crumbling client and an application that legitimately set several cookie
headers, which no capture can settle.

### Bounds and limits

The importer follows the same hostile-input discipline as the rest of the codebase:
bounded total input, bounded frame count, bounded header list, and rejection of malformed
framing rather than best-effort recovery. It derives the send-side persona only and does
not attempt to model the server.

## Preset migration

The three built-in presets are rewritten against the new shape and must produce
byte-identical wire output to today:

- Chrome 133: settings `(1, 65536), (2, 0), (4, 6291456), (6, 262144)`, then
  WINDOW_UPDATE increment 15663105. No priority frames, no header priority.
- Firefox 148: settings `(1, 65536), (2, 0), (4, 131072), (5, 16384)`, then
  WINDOW_UPDATE increment 12517377, header priority weight 41 on dependency 0,
  non-exclusive.
- OkHttp Android 11: settings `(4, 16777216)`, then WINDOW_UPDATE increment 16711681,
  header priority weight 1 on dependency 0, non-exclusive.

## Test plan

`TlsPresetWireTests` today establishes a real loopback connection and asserts the derived
Akamai fingerprint *string* — `"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"`
(`TlsPresetWireTests.cs:12-26`). That string pins none of the axes this work makes
configurable: not frame ordering, not flags, not HPACK representation choices, not whether
a zero-length SETTINGS frame was sent. Byte-level assertions are therefore new work, built
on the same loopback harness.

- Preface bytes asserted exactly for all three presets, proving migration changed nothing.
- An unknown SETTINGS identifier and a duplicated identifier both appear on the wire in
  declared order, and the duplicate's last value governs local state.
- A raw frame appears at its declared position. A raw SETTINGS frame and a raw
  WINDOW_UPDATE both feed local receive state, proven by the connection accepting traffic
  it would otherwise reject.
- One test per HPACK representation asserting the emitted prefix byte, including `0x00`.
- `IndexedFallback` produces `0x82` for `:method: GET` and `0x00`-prefixed literals
  elsewhere under `UseDynamicTable = false`, with no dynamic insertions across a
  multi-request connection.
- The empty-`cookie` divergence is pinned deliberately: `Cookie: ""` emits a never-indexed
  literal, not `0xA0`.
- `WhenShorter` and `WhenNotLonger` differ on a value whose Huffman form is exactly the
  same length.
- Name index selection: `:method: PUT` emits index 2 under `LowestStatic` and 3 under
  `HighestStatic`.
- Multi-value join and cookie crumbling each produce the expected field count.
- Consecutive table size updates emit in order, including the zero-then-N pair.
- CONTINUATION splits at the configured fragment size, clamps to 16384 before the peer's
  SETTINGS arrives, and a fragment size below 6 is rejected at construction.
- Per-request header order, pseudo-header order, priority, and PRIORITY_UPDATE override
  session values; null falls back.
- A per-request frame script emits PRIORITY before HEADERS and PRIORITY_UPDATE before
  HEADERS, inverting today's fixed placement.
- Extended CONNECT: a request with `:protocol` emits five pseudo-headers in declared
  order and is accepted by a loopback server advertising
  `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
- `AuthorityMode` emits `:authority` alone, `host` alone, and both.
- `MaxDataFrameSize` caps DATA frames below the peer's maximum; each end-of-stream
  placement produces its declared framing for empty, buffered, and streaming bodies.
- Each flow-control axis independently: threshold, trigger, increment mode, order,
  coalescing, end-stream suppression. A threshold exceeding its declared window is
  rejected at construction rather than deadlocking.
- `SendGoAwayOnDispose` emits GOAWAY with the declared code and last-stream-id; each reset
  code appears in its situation.
- `FlushAfter` boundaries produce the declared write batching.
- Each `TlsHttp2SettingsAckPlacement` value puts the ACK where it claims, and never inside
  a header block: a header block requiring CONTINUATION under `AfterNextBatch` places the
  ACK after the final CONTINUATION.
- Validation tests for the non-obvious rules: settings range and count, raw frame type
  rejection, non-odd `InitialStreamId`, fragment size below 6, threshold above window,
  `IndexedFallback = Indexed`, and a pseudo-header order illegal for its method.
- Round-trip: capture a preset's own connection bytes in both directions, import through
  `TlsHttp2Capture.Import`, apply the derived profile to a fresh session, assert the second
  connection's bytes equal the first. Run once with a header block large enough to require
  CONTINUATION, so the fragment-size inference is actually exercised rather than
  vacuously satisfied.
- The deriver marks peer-dependent fields `Indeterminate` when the server stream is empty,
  and `Measured` when it is supplied.
- Promotion: three discriminating names agree and promote; a split verdict does not; a
  field with an exact table match contributes no evidence; pseudo-headers alone never
  promote `Indexed`.
- The HPACK fuzz target — decoder-only today (`tools/TlsClient.Fuzz/Program.cs:91-92`) —
  gains an encode-policy round-trip and a capture-import target, since the importer parses
  untrusted bytes.

## Fidelity ceiling

This work does not achieve indistinguishability. The following remain outside its scope
and are recorded so the result is not overclaimed.

- Wall-clock timing of any frame. Placement and batching options control *where* bytes sit
  in the sequence, never *when* they are sent.
- TCP segmentation, Nagle behavior, and packet pacing. Write batching controls the
  boundaries handed to the TLS layer, not what the transport does with them.
- TLS record splitting, which belongs to SharpTls.
- Request concurrency patterns, connection reuse timing, and idle behavior.
- HPACK dynamic table contents over a long-lived connection are only as reproducible as
  the capture is long. The deriver recovers what the captured connection exercised;
  behavior the client never exhibited is reported as indeterminate rather than guessed.
- The HTTP/2 frame header's reserved bit, which `WriteFrameLockedAsync:1383` always clears
  and RFC 9113 section 4.1 requires to stay unset. Protocol-fixed, not a gap.
- HTTP/1.1 wire behavior beyond the shared `HeaderOrder`.

## Diff surface

New files:

- `src/TlsClient/TlsHttp2Options.cs` — moved out of `TlsHttpVersionPolicy.cs`; holds the
  flow-control, data, shutdown, and pseudo-header option types
- `src/TlsClient/TlsHttp2Preface.cs` — preface and per-request frame hierarchies
- `src/TlsClient/TlsHpackOptions.cs`
- `src/TlsClient/TlsHttp2Capture.cs` — capture import, observations, inference

Modified:

- `src/TlsClient/HpackCodec.cs` — encoder rewritten around the policy; decoder untouched
- `src/TlsClient/Http2Connection.cs` — preface writer, local-state derivation, header
  construction, pseudo-headers, CONTINUATION splitting, per-request frame scripts, DATA
  sizing and end-stream framing, flow-control cadence, shutdown, write batching, stream
  identifiers
- `src/TlsClient/Http11RequestWriter.cs` — shared `Order` takes a per-request override;
  `Trailer` header becomes conditional
- `src/TlsClient/BufferedRequest.cs` — carries per-request HTTP/2 options to the connection
- `src/TlsClient/TlsSession.cs` — constructs `BufferedRequest` with those options
- `src/TlsClient/TlsHttpVersionPolicy.cs` — `TlsHttp2Options` removed
- `src/TlsClient/TlsRequestOptions.cs` — per-request ordering, priority, frame scripts,
  pseudo-header overrides, padding
- `src/TlsClient/TlsHttpBehaviorProfile.cs` — capture, export, import, apply
- `src/TlsClient/TlsPreset.cs` — three presets rewritten
- `src/TlsClient/PublicAPI.Shipped.txt` — rewritten baseline
- `tests/TlsClient.Tests/` — `TlsPresetWireTests`, `TlsHttp2OptionsTests`, `HpackTests`,
  `TlsHttpBehaviorProfileTests`, and new `TlsHttp2CaptureTests`
- `tools/TlsClient.Fuzz/Program.cs` — encode-policy and capture-import targets
- `docs/PRESETS.md` — preset definitions restated in the new shape
