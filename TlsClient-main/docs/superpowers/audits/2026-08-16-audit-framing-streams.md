# RFC 9113 §4–§5 conformance audit — framing, stream state machine, error classification

**Date:** 2026-08-16
**Scope:** RFC 9113 sections 4.1, 4.2, 4.3, 5.1, 5.1.1, 5.1.2, 5.4, 5.5 — RECEIVE side.
**Code audited:** `src/TlsClient/Http2Connection.cs` (2956 lines, contains `Http2Connection`,
`Http2StreamState`, `Http2FrameParser`, `Http2FrameType`, `Http2FrameFlags`),
`src/TlsClient/TlsHttp2Options.cs`, `src/TlsClient/TlsHttp2ShutdownOptions.cs`.
**RFC source:** `https://www.rfc-editor.org/rfc/rfc9113.txt`, fetched and quoted verbatim.
**Divergence check:** `docs/superpowers/HANDOFF.md`,
`docs/superpowers/plans/2026-08-16-rfc-reference.md`, and the XML/inline docs in
`Http2Connection.cs` were read before any finding was called a defect.

**Headline:** the frame layer and stream-identifier logic are in good shape. The *error
classification* layer is not. Every protocol error the read loop detects — including
per-response validation errors that RFC 9113 §8.1.1 makes stream errors — is funnelled
through one `catch` that sends GOAWAY and fails every stream on the connection. Two
CRITICAL findings and four IMPORTANT ones follow from that single structural choice.

---

## 1. Section 4.1 — frame layout

### 1.1 Length vs. SETTINGS_MAX_FRAME_SIZE — enforced, against the right value

> "Length: The length of the frame payload expressed as an unsigned 24-bit integer in units
> of octets. Values greater than 2^14 (16,384) MUST NOT be sent unless the receiver has set
> a larger value for SETTINGS_MAX_FRAME_SIZE." (RFC 9113 §4.1)

`Http2FrameParser.ParseHeader` checks the length before the payload is read, against
`_localMaximumFrameSize` — the value the *client* advertised, not the peer's:

- `src/TlsClient/Http2Connection.cs:2920-2924` — length decode and the `> maximumFrameSize` check.
- `src/TlsClient/Http2Connection.cs:1091` — `ParseHeader(header, _localMaximumFrameSize)`.
- `src/TlsClient/Http2Connection.cs:62` — `_localMaximumFrameSize = http2.LocalMaxFrameSize;`,
  sourced from the declared preface script (see the comment at lines 59-60), so the bound the
  receiver enforces is exactly the bound it advertised.

**CONFORMS.** The direction that matters is right: a receiver must police its own advertised
maximum, and it does.

### 1.2 The error code is wrong — FINDING F1 (IMPORTANT)

> "An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds the size
> defined in SETTINGS_MAX_FRAME_SIZE, exceeds any limit defined for the frame type, or is too
> small to contain mandatory frame data." (RFC 9113 §4.2)

`src/TlsClient/Http2Connection.cs:2923` throws a bare `TlsHttpProtocolException`. That type
carries no error code. It surfaces at the read loop's catch:

- `src/TlsClient/Http2Connection.cs:1074-1077`:
  `if (exception is TlsHttpProtocolException) { await TrySendGoAwayAsync(Http2ErrorCode.ProtocolError); }`

So the GOAWAY on the wire always carries `PROTOCOL_ERROR` (0x01), never `FRAME_SIZE_ERROR`
(0x06). `Http2ErrorCode.FrameSizeError` exists in `src/TlsClient/TlsHttp2ShutdownOptions.cs`
but no receive-path code ever selects it — `grep` for `FrameSizeError` in
`Http2Connection.cs` returns nothing; line 1076 is the only `ProtocolError` reference.

**Mitigating text**, already collected by this project at
`docs/superpowers/plans/2026-08-16-rfc-reference.md:582`:

> "Additionally, an endpoint MAY use any applicable error code when it detects an error
> condition; a generic error code (such as PROTOCOL_ERROR or INTERNAL_ERROR) can always be
> used in place of more specific error codes." (RFC 9113 §5.4)

**VIOLATES, softened.** §5.4's blanket permission is real and the project has already
recorded it, so this is not a protocol break. It is still a finding for two reasons: §4.2
states a specific `MUST` that §5.4 only generically overrides, and — decisive for *this*
project — the GOAWAY error code is a byte on the wire. Chrome, Firefox and curl all emit
`FRAME_SIZE_ERROR` here; a client claiming byte-for-byte fidelity that emits
`PROTOCOL_ERROR` instead is distinguishable. Nothing in `HANDOFF.md` or the XML docs claims
this as a deliberate divergence, so it is undocumented.

**Severity: IMPORTANT** (wrong on the wire, fingerprint-visible; not connection-corrupting).

**Fix:** give `TlsHttpProtocolException` an `Http2ErrorCode` property defaulting to
`ProtocolError`, set it to `FrameSizeError` at the size-check throw sites (`:2923`, plus the
per-type sites in §2.2 below), and have `:1076` read
`exception is TlsHttpProtocolException p ? p.ErrorCode : Http2ErrorCode.ProtocolError`.
That one change also resolves F2, F5 and F6's error-code half.

### 1.3 Reserved bit — correct in both directions

> "Reserved: A reserved 1-bit field. The semantics of this bit are undefined, and the bit
> MUST remain unset (0x00) when sending and MUST be ignored when receiving." (RFC 9113 §4.1)

- Receive: `src/TlsClient/Http2Connection.cs:2925` —
  `BinaryPrimitives.ReadInt32BigEndian(header[5..]) & 0x7fff_ffff` masks the reserved bit off.
  A frame arriving with R set is parsed identically to one without.
- Send: `src/TlsClient/Http2Connection.cs:2311` —
  `WriteInt32BigEndian(header.AsSpan(5), streamId & 0x7fff_ffff)` forces the bit to 0.
- The same masking is applied to the two other 31-bit identifier fields:
  PUSH_PROMISE Promised Stream ID at `:2403-2404`, GOAWAY Last-Stream-ID at `:1461`,
  and WINDOW_UPDATE's reserved bit at `:1481`.

**CONFORMS.** No finding.

### 1.4 Unused flags

> "Unused flags are those that have no defined semantics for a particular frame type. Unused
> flags MUST be ignored on receipt and MUST be left unset (0x00) when sending." (RFC 9113 §4.1)

No receive path validates unused flags — `HandleFrameAsync` (`:1101-1135`) and each handler
test only the flags they care about with `&`. Ignoring is precisely what the RFC requires.

**CONFORMS.** No finding.

---

## 2. Section 4.2 — which oversize frames must be connection errors

### 2.1 The connection-error requirement is satisfied (as a superset)

> "A frame size error in a frame that could alter the state of the entire connection MUST be
> treated as a connection error (Section 5.4.1); this includes any frame carrying a field
> block (Section 4.3) (that is, HEADERS, PUSH_PROMISE, and CONTINUATION), a SETTINGS frame,
> and any frame with a stream identifier of 0." (RFC 9113 §4.2)

Because `ParseHeader` throws *before* the payload is read
(`src/TlsClient/Http2Connection.cs:1091-1093` — check, then `ReadExactlyAsync(payload)`), the
framing layer cannot resynchronise, and every oversize frame of every type becomes a
connection error at `:1071-1082`. That is a superset of the mandated set, and §5.4.1
explicitly permits it:

> "An endpoint can end a connection at any time. In particular, an endpoint MAY choose to
> treat a stream error as a connection error." (RFC 9113 §5.4.1)

**CONFORMS.** No finding. (This matches nghttp2 and Go's `net/http2`.)

### 2.2 Per-frame-type size limits — FINDING F2 (MINOR)

§4.2's "exceeds any limit defined for the frame type, or is too small to contain mandatory
frame data" clause is enforced for every frame type, but again with the wrong code:

| Frame | Code site | RFC requirement | Code raises |
|---|---|---|---|
| SETTINGS `len % 6 != 0` | `:1315-1318` | "A SETTINGS frame with a length other than a multiple of 6 octets MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR." (§6.5) | conn err, PROTOCOL_ERROR |
| SETTINGS ACK with payload | `:1321-1324` | §6.5 FRAME_SIZE_ERROR | conn err, PROTOCOL_ERROR |
| PING `len != 8` | `:1415` via `ValidateFrame` `:2415-2422` | "Receipt of a PING frame with a length field value other than 8 MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR." (§6.7) | conn err, PROTOCOL_ERROR |
| RST_STREAM `len != 4` | `:1439` via `ValidateFrame` | "A RST_STREAM frame with a length other than 4 octets MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR." (§6.4) | conn err, PROTOCOL_ERROR |
| WINDOW_UPDATE `len != 4` | `:1477-1480` | "A WINDOW_UPDATE frame with a length other than 4 octets MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR." (§6.9) | conn err, PROTOCOL_ERROR |
| GOAWAY `len < 8` | `:1456-1459` | §6.8 (too small for mandatory data → §4.2 FRAME_SIZE_ERROR) | conn err, PROTOCOL_ERROR |

The connection-vs-stream classification is right in every row. Only the code differs, under
the same §5.4 mitigation as F1.

**Severity: MINOR** (fingerprint-visible but low-frequency paths; same fix as F1).

### 2.3 PRIORITY size error is escalated to a connection error — FINDING F3 (IMPORTANT)

> "A PRIORITY frame with a length other than 5 octets MUST be treated as a **stream error**
> (Section 5.4.2) of type FRAME_SIZE_ERROR." (RFC 9113 §6.3)

`src/TlsClient/Http2Connection.cs:1109-1111`:

```csharp
case Http2FrameType.Priority:
    ValidateFrame(frame, streamMustBeZero: false, length: 5);
    break;
```

`ValidateFrame` (`:2415-2422`) folds two distinct rules into one `throw`:

```csharp
if ((streamMustBeZero ? frame.StreamId != 0 : frame.StreamId == 0) ||
    frame.Payload.Length != length)
{
    throw new TlsHttpProtocolException($"A {frame.Type} frame is malformed.");
}
```

The stream-id-0 half is correct (§6.3: "If a PRIORITY frame is received with a stream
identifier of 0x00, the recipient MUST respond with a connection error … of type
PROTOCOL_ERROR"). The length half is not: a 4- or 6-octet PRIORITY frame kills the whole
connection and every in-flight request on it, where the RFC mandates a RST_STREAM on that
stream alone. PRIORITY is deprecated but still emitted by real servers and intermediaries,
so this is reachable.

**VIOLATES. Severity: IMPORTANT** (a single stray deprecated frame drops unrelated requests).

**Fix:** split `ValidateFrame` into a stream-id check (connection error) and a length check
whose disposition the caller chooses. For `Priority`, on a length mismatch call
`TryResetStreamAsync(frame.StreamId, Http2ErrorCode.FrameSizeError)` and `break` instead of
throwing. Note `ValidateFrame` is also used by PING (`:1415`) and RST_STREAM (`:1439`), where
a connection error *is* correct — so the split must be per-caller, not global.

---

## 3. Section 4.3 — field-block contiguity on the receive side

> "Each field block is processed as a discrete unit. Field blocks MUST be transmitted as a
> contiguous sequence of frames, with no interleaved frames of any other type or from any
> other stream." (RFC 9113 §4.3)

> "If the END_HEADERS flag is not set, this frame MUST be followed by another CONTINUATION
> frame. A receiver MUST treat the receipt of any other type of frame or a frame on a
> different stream as a connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.10)

Both inbound field-block assemblers bypass `HandleFrameAsync` and read raw frames, so nothing
can be interleaved by construction:

- HEADERS: `src/TlsClient/Http2Connection.cs:1213-1223`. The loop calls `ReadFrameAsync`
  directly and rejects `frame.Type != Continuation || frame.StreamId != streamId` with a
  `TlsHttpProtocolException` → connection error, PROTOCOL_ERROR at `:1076`. Both the
  wrong-type and wrong-stream halves are covered.
- PUSH_PROMISE: `src/TlsClient/Http2Connection.cs:1291-1301`, same shape, checked against
  `associatedStreamId` (the correct stream — a PUSH_PROMISE's CONTINUATIONs continue on the
  associated stream, not the promised one).
- A CONTINUATION arriving *outside* any block reaches the dispatch switch and is rejected:
  `src/TlsClient/Http2Connection.cs:1130-1131`.

**CONFORMS.** This also satisfies §5.5's extension clause —

> "However, extension frames that appear in the middle of a field block (Section 4.3) are not
> permitted; these MUST be treated as a connection error (Section 5.4.1) of type
> PROTOCOL_ERROR." (RFC 9113 §5.5)

— because the loops reject *any* type that is not CONTINUATION, unknown types included.
No finding.

**Supporting observation (no finding):** the reassembled block is bounded by
`AppendHeaderFragment` at `:2372-2380` against `MaximumResponseHeaderBytes`, so a CONTINUATION
flood is memory-bounded. It becomes a connection error, which is the correct disposition for
an unbounded field block.

---

## 4. Section 5.1 — the stream state machine, inbound

The client's model is implicit: a stream exists in `_streams` (`:29`) from `TryAdd` at
`:156` until `TryRemove` at `:216`, and `IsIdleStream` (`:2382-2384`) distinguishes
never-opened from already-closed:

```csharp
private bool IsIdleStream(int streamId) => (streamId & 1) != 0
    ? streamId > Volatile.Read(ref _nextStreamId)
    : streamId > _highestPromisedStreamId;
```

Odd (client-initiated) ids above the high-water mark are idle; even (server-initiated) ids
above the highest promise are idle. Anything at or below, and not in `_streams`, is closed.
That is the right two-way split, and it is what makes the per-state analysis below possible.

Verified against `state.Completion` (`:2562`), which is only ever completed by `CompleteAsync`
on END_STREAM (`:2753`) or `TryFail` (`:2778`): `SendAsync` blocks at `:201` for the full
lifetime of the response including streaming bodies, so the `TryRemove` at `:216` cannot
retire a stream that is still receiving. No early-removal defect.

### 4.1 idle — CONFORMS

> "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be
> treated as a connection error (Section 5.4.1) of type PROTOCOL_ERROR. If this stream is
> initiated by the server, as described in Section 5.1.1, then receiving a HEADERS frame MUST
> also be treated as a connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §5.1)

| Inbound frame on an idle stream | Site | Behaviour |
|---|---|---|
| DATA | `:1168-1171` | connection error PROTOCOL_ERROR ✔ |
| HEADERS | `:1241-1244` | connection error PROTOCOL_ERROR ✔ (covers the server-initiated case: an even id above `_highestPromisedStreamId` is idle) |
| RST_STREAM | `:1446-1449` | connection error PROTOCOL_ERROR ✔ (also §6.4: "If a RST_STREAM frame identifying an idle stream is received, the recipient MUST treat this as a connection error … of type PROTOCOL_ERROR") |
| WINDOW_UPDATE | `:1496-1500` | connection error PROTOCOL_ERROR ✔ |
| PRIORITY | `:1109-1111` | accepted, no state change ✔ (§6.3: "can be sent on a stream in any state, including 'idle' or 'closed'") |
| PUSH_PROMISE on idle associated stream | `:1272-1276` | connection error PROTOCOL_ERROR ✔ |

**CONFORMS** across the board. This is the strongest part of the receive path.

### 4.2 reserved (remote) — CONFORMS

The client sets `LocalEnablePush` and rejects PUSH_PROMISE outright when it is off
(`:1255-1259`). When push is enabled, a promised stream is immediately reset
(`:1306-1308`) and remembered in `_rejectedPushStreams` (`:30`). Late frames on it are then
handled by the closed-stream path below — and crucially, DATA on it is still charged and
credited against the *connection* window at `:1150` / `:1172-1177`, which is exactly what
the RFC demands:

> "An endpoint MUST minimally process and then discard any frames it receives in this state.
> This means updating header compression state for HEADERS and PUSH_PROMISE frames. …
> Additionally, the content of DATA frames counts toward the connection flow-control window."
> (RFC 9113 §5.1, "closed")

**CONFORMS.** No finding.

### 4.3 open / half-closed (local) — CONFORMS

> "An endpoint can receive any type of frame in this state." (RFC 9113 §5.1, half-closed (local))

Any frame type is accepted while the stream is in `_streams`. No spurious rejection found.

### 4.4 half-closed (remote) — FINDING F4 (CRITICAL)

> "If an endpoint receives additional frames, other than WINDOW_UPDATE, PRIORITY, or
> RST_STREAM, for a stream that is in this state, it MUST respond with a **stream error**
> (Section 5.4.2) of type STREAM_CLOSED." (RFC 9113 §5.1)

The client enters half-closed (remote) the moment END_STREAM is received —
`Http2StreamState._endReceived` is set at `:2699` (DATA with END_STREAM) or `:2712`
(HEADERS with END_STREAM). Further inbound frames on that stream are detected:

- `src/TlsClient/Http2Connection.cs:2682-2685` —
  `if (Volatile.Read(ref _endReceived) != 0) throw new TlsHttpProtocolException("HTTP/2 DATA arrived after END_STREAM.");`
- `src/TlsClient/Http2Connection.cs:2712-2715` —
  `if (Interlocked.Exchange(ref _endReceived, 1) != 0) throw new TlsHttpProtocolException("HTTP/2 END_STREAM was received twice.");`

Both are called synchronously from the read loop — `EnqueueBody` at `:1186`, `EnqueueEnd` at
`:1238` — so both `TlsHttpProtocolException`s propagate straight to `ReadLoopAsync`'s catch at
`:1071-1084`, which sends GOAWAY and calls `FailAll`. The RFC's mandated STREAM_CLOSED stream
error becomes a connection teardown.

Concretely: one server that emits a stray DATA frame after END_STREAM on stream 7 destroys
streams 1, 3, 5, 9 and 11 as well, and marks the connection non-reusable (`:1073`), forcing
the pool to rebuild it. `FailAll(preserveEndedStreams: true)` at `:1078-1082` spares only
streams that have *already* received END_STREAM; every genuinely in-flight request dies.

**VIOLATES. Severity: CRITICAL** (kills unrelated in-flight requests; exactly the production
failure mode this audit was asked to hunt for).

**Fix:** have the read loop distinguish stream-scoped from connection-scoped failures. The
minimal shape: catch `TlsHttpProtocolException` around the `state.EnqueueBody` /
`state.EnqueueEnd` / `state.ApplyHeaders` calls inside `HandleDataAsync` / `HandleHeadersAsync`
(`:1186`, `:1230-1239`), call `state.TryFail(exception)` plus
`await TryResetStreamAsync(frame.StreamId, Http2ErrorCode.StreamClosed)`, and `return` —
letting the connection live. The connection receive window is already debited and credited
independently at `:1150` and via `RestoreReceiveWindowAsync`, so discarding the frame does not
desynchronise flow control. See F6 for the general form of this fix.

### 4.5 closed — CONFORMS (and the permissive choice is the right one)

> "An endpoint MUST NOT send frames other than PRIORITY on a closed stream. An endpoint **MAY**
> treat receipt of any other type of frame on a closed stream as a connection error
> (Section 5.4.1) of type STREAM_CLOSED, except as noted below." (RFC 9113 §5.1)

> "An endpoint that sends a frame with the END_STREAM flag set or a RST_STREAM frame might
> receive a WINDOW_UPDATE or RST_STREAM frame from its peer in the time before the peer
> receives and processes the frame that closes the stream." (RFC 9113 §5.1)

The client ignores all of them, which is the safe reading of a `MAY`:

| Frame on a closed stream | Site | Behaviour |
|---|---|---|
| DATA | `:1166-1183` | connection window credited back via `SendWindowUpdateAsync(0, …)` and `_connectionReceiveWindow += payloadLength`, then discarded ✔ |
| HEADERS | `:1225-1227`, then `:1245-1248` | **HPACK decode runs first**, so compression state stays synchronised, then discarded ✔ |
| RST_STREAM | `:1440-1451` | `TryGetValue` misses, not idle → discarded ✔ |
| WINDOW_UPDATE | `:1492-1501` | discarded ✔ — required: "A receiver could receive a WINDOW_UPDATE frame on a stream in a 'half-closed (remote)' or 'closed' state. A receiver MUST NOT treat this as an error (see Section 5.1)." (§6.9) |
| PUSH_PROMISE | `:1272-1276` | rejected as an idle/closed associated stream — see F5 note below |

**CONFORMS.** The HPACK-decode-before-lookup ordering at `:1225` is the detail most
implementations get wrong; this one has it right. No finding.

The one asymmetry worth recording, not a defect: PUSH_PROMISE on a *closed* associated
stream is a connection error at `:1272-1276`, where §5.1 says "Receiving a PUSH_PROMISE frame
also causes the promised stream to become 'reserved (remote)', even when the PUSH_PROMISE
frame is received on a closed stream." Since the client rejects every push anyway
(`:1306-1308`), the observable difference is confined to a server that pushes on a
just-completed stream. Under §5.1's `MAY` for closed streams this is permitted, so it is
**CONFORMS (permitted strictness)** rather than a violation — but it is undocumented, and
worth a comment at `:1272` so a future reader does not "fix" it in the wrong direction.

---

## 5. Section 5.1.1 — stream identifiers

> "The identifier of a newly established stream MUST be numerically greater than all streams
> that the initiating endpoint has opened or reserved. This governs streams that are opened
> using a HEADERS frame and streams that are reserved using PUSH_PROMISE. An endpoint that
> receives an unexpected stream identifier MUST respond with a connection error
> (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §5.1.1)

### 5.1 Inbound PUSH_PROMISE identifiers — CONFORMS

`src/TlsClient/Http2Connection.cs:1265-1288`:

- `:1267-1271` — zero and odd promised ids rejected (§5.1.1: "those initiated by the server
  MUST use even-numbered stream identifiers"; "the stream identifier of zero cannot be used
  to establish a new stream"). Connection error PROTOCOL_ERROR ✔
- `:1277-1281` — `if (promisedStreamId <= _highestPromisedStreamId) throw …
  "A PUSH_PROMISE reused or reordered a promised stream identifier."` This is the exact
  monotonic rule: `<=` rejects **reuse** (equal) and **lower-than-seen** (less) in one test.
  Connection error PROTOCOL_ERROR ✔
- `:1288` — `Volatile.Write(ref _highestPromisedStreamId, promisedStreamId)` updates the
  high-water mark *before* the CONTINUATION loop and before the RST, so `IsIdleStream` treats
  the promised stream as reserved from that instant. No window where a frame on the freshly
  promised stream is misclassified as idle ✔
- `_highestPromisedStreamId` starts at 0 (`:41`) and promised id 0 is already rejected, so the
  first legitimate promise (id 2) passes `2 > 0`. No off-by-one ✔

**CONFORMS.** No finding.

### 5.2 Outbound identifiers — CONFORMS

- `:136` — `Interlocked.Add(ref _nextStreamId, _streamIdStep)`, strictly monotonic under
  concurrency.
- `:75` — `_nextStreamId = http2.InitialStreamId - http2.StreamIdStep;` so the first allocated
  id is `InitialStreamId`.
- `src/TlsClient/TlsHttp2Options.cs:180-190` validates `InitialStreamId` odd and `≥ 1`, and
  `StreamIdStep` even and in `[2, 65536]`. The declarative-options surface therefore cannot
  configure a client into emitting even (server-reserved) identifiers.
- `:137-141` — exhaustion (`streamId <= 0` after 31-bit overflow) marks the connection
  non-reusable and refuses rather than wrapping. ✔

**CONFORMS.** No finding.

### 5.3 Rejected-push backlog cap — FINDING F5 (MINOR)

`src/TlsClient/Http2Connection.cs:1282-1286`:

```csharp
if (_rejectedPushStreams.Count >= 1024)
{
    throw new TlsHttpProtocolException(
        "Too many rejected HTTP/2 push streams remain outstanding.");
}
```

A local resource guard with no RFC basis. §5.4.1's "An endpoint can end a connection at any
time" permits it, and `ENHANCE_YOUR_CALM` exists for precisely this. But the magic number is
undocumented (no XML doc, no `HANDOFF.md` entry, not in the options surface), it emits
PROTOCOL_ERROR rather than ENHANCE_YOUR_CALM, and a server pushing aggressively on a
long-lived connection can trip it legitimately, taking live requests with it.

**Severity: MINOR.** **Fix:** name the constant, document it in XML, emit
`Http2ErrorCode.EnhanceYourCalm`, and — since this is a declarative-options codebase —
consider surfacing it on `TlsHttp2Options` alongside `LocalEnablePush`.

---

## 6. Section 5.1.2 — stream concurrency

> "Endpoints MUST NOT exceed the limit set by their peer." (RFC 9113 §5.1.2)

> "Streams that are in the 'open' state or in either of the 'half-closed' states count toward
> the maximum … Streams in either of the 'reserved' states do not count toward the stream
> limit." (RFC 9113 §5.1.2)

**Honoured on the send side. CONFORMS.**

- `:40` — `_peerMaximumConcurrentStreams = int.MaxValue`, matching §6.5.2's "initially there is
  no limit to this value".
- `:1357-1364` — SETTINGS 0x3 updates it under `_flowSync` and signals waiters.
- `:1603-1645` — `AcquireStreamSlotAsync` blocks before a stream id is even allocated
  (`:128`, before `:136`), so the client cannot open the (N+1)th stream. The wake-one-more
  handoff at `:1621`/`:1628` avoids the lost-wakeup that a naive semaphore release has here.
- `:1647-1654` — `ReleaseStreamSlot` runs in `SendAsync`'s outermost `finally` (`:228-231`),
  after `_streams.TryRemove` (`:216`), so the slot cannot be reused before the stream is gone.
- Reserved streams are never added to `_streams` and never take a slot (`HandlePushPromiseAsync`
  resets and returns without touching `_activeStreams`) — matching "Streams in either of the
  'reserved' states do not count toward the stream limit."

**Mid-connection reduction — CONFORMS.**

> "An endpoint that wishes to reduce the value of SETTINGS_MAX_CONCURRENT_STREAMS to a value
> that is below the current number of open streams can either close streams that exceed the
> new value or allow streams to complete." (RFC 9113 §5.1.2)

When the peer lowers the limit, `:1360-1361` overwrites `_peerMaximumConcurrentStreams` and
`:1617` (`if (_activeStreams < _peerMaximumConcurrentStreams)`) simply stops granting slots
until enough streams retire. Existing streams are never torn down. That is the second of the
two behaviours the RFC explicitly permits, and it is the safer one. A raise is handled too:
`SignalStreamSlot()` at `:1363` wakes blocked callers immediately.

Value clamping at `:1361` (`value > int.MaxValue ? int.MaxValue : (int)value`) is correct —
§6.5.2 defines no upper bound on this setting, so saturating rather than throwing is right.

**No findings in this section.**

---

## 7. Section 5.4 — error classification

This is the weakest area, and F6 is the single most consequential finding in this audit.

### 7.1 One catch-all makes every error a connection error — FINDING F6 (CRITICAL)

> "A stream error is an error related to a specific stream that does not affect processing of
> other streams. An endpoint that detects a stream error sends a RST_STREAM frame
> (Section 6.4) that contains the stream identifier of the stream where the error occurred."
> (RFC 9113 §5.4.2)

> "A connection error is any error that prevents further processing of the frame layer or
> corrupts any connection state." (RFC 9113 §5.4.1)

> "Malformed requests or responses that are detected MUST be treated as a **stream error**
> (Section 5.4.2) of type PROTOCOL_ERROR." (RFC 9113 §8.1.1)

> "A malformed request or response is one that is an otherwise valid sequence of HTTP/2 frames
> but is invalid due to the presence of extraneous frames, prohibited fields or pseudo-header
> fields, the absence of mandatory pseudo-header fields, the inclusion of uppercase field
> names, or invalid field names and/or values." (RFC 9113 §8.1.1)

`Http2StreamState.ApplyHeaders` is called from the read loop at
`src/TlsClient/Http2Connection.cs:1230`. Every validation failure inside it is a
`TlsHttpProtocolException`, and every one therefore reaches `:1071-1084` and takes the
connection down. Each of these is, by §8.1.1's own enumeration, a **malformed response** —
a stream error:

| Site | Condition | §8.1.1 category | Current disposition |
|---|---|---|---|
| `:2580-2583` | uppercase field name | "the inclusion of uppercase field names" | connection error ✘ |
| `:2586-2590` | pseudo-header after regular field / non-`:status` / duplicate `:status` | "prohibited fields or pseudo-header fields" | connection error ✘ |
| `:2596-2600` | `connection`/`proxy-connection`/`keep-alive`/`upgrade`/`transfer-encoding` present | §8.2.2: "Any message containing connection-specific header fields MUST be treated as malformed (Section 8.1.1)" | connection error ✘ |
| `:2604-2607` | `te` with a value other than `trailers` | §8.2.2 → malformed | connection error ✘ |
| `:2616-2619` | missing or non-3-digit `:status` | "the absence of mandatory pseudo-header fields" | connection error ✘ |
| `:2622-2626` | `101 Switching Protocols` | §8.1.1 (extraneous) | connection error ✘ |
| `:2641-2644` | `:status` present in trailers | "prohibited … pseudo-header fields" | connection error ✘ |
| `:1231-1235` | trailers without END_STREAM | §8.1 | connection error ✘ |
| `:2655-2658`, `:2686-2689` | DATA before response headers | "extraneous frames" | connection error ✘ |
| `:2682-2685`, `:2712-2715` | DATA / END_STREAM after END_STREAM | §5.1 STREAM_CLOSED (see F4) | connection error ✘ |
| `:2691-2695` | response body exceeds `MaximumResponseBodyBytes` | local policy, stream-scoped | connection error ✘ |
| `:2842-2845`, `:2850-2853` | too many response headers / header bytes | local policy, stream-scoped | connection error ✘ |

None of these "prevents further processing of the frame layer" or "corrupts any connection
state" — the §5.4.1 test. The frame layer is fine; HPACK state is already updated (decode
happens at `:1225`, before `ApplyHeaders`); flow control is already accounted (`:1150`).
Every one of them is recoverable by resetting one stream.

The blast radius is `FailAll` at `:1078-1082` plus `Volatile.Write(ref _isReusable, 0)` at
`:1073`: **one malformed response destroys every concurrent request on the connection and
retires the connection from the pool.** On a multiplexed client this is the difference between
one failed request and a hundred. A single misbehaving origin — an uppercase header name from
a legacy backend behind a CDN is the classic case — becomes a connection-wide outage that
repeats on every reconnect.

By contrast, the same class of error detected on the *body pump* thread is handled correctly
and stream-locally: `PumpBodyAsync` at `:2822-2825` catches and calls `TryFail(exception)`,
so `ValidateContentLength` (`:2860-2874`) and `AppendBodyAsync`'s limit check (`:2660-2664`)
fail only their own stream. The correct behaviour already exists in the file — it simply is
not applied on the read-loop path.

**VIOLATES. Severity: CRITICAL.**

**Fix (one change, covers F4 and most of F6):** classify at the throw site rather than at the
catch. Add `Http2ErrorCode ErrorCode` and `bool IsConnectionScoped` to
`TlsHttpProtocolException` (`src/TlsClient/TlsResponse.cs:154`); default
`IsConnectionScoped = false` for the response-validation throws in `Http2StreamState` and
`true` for the framing throws in `Http2Connection`/`Http2FrameParser`. Then wrap the three
read-loop call sites that touch stream state — `state.ApplyHeaders` (`:1230`),
`state.EnqueueEnd` (`:1238`), `state.EnqueueBody` (`:1186`) — as:

```csharp
catch (TlsHttpProtocolException ex) when (!ex.IsConnectionScoped)
{
    state.TryFail(ex);
    await TryResetStreamAsync(frame.StreamId, ex.ErrorCode).ConfigureAwait(false);
    return;
}
```

The connection survives, the offending request fails with the same exception the caller sees
today, and the peer gets the RST_STREAM §5.4.2 requires. Frame-layer errors (§4.1, §4.2, §4.3,
idle-stream errors) keep the existing GOAWAY path unchanged.

### 7.2 Detected stream errors emit no RST_STREAM — FINDING F7 (IMPORTANT)

> "An endpoint that detects a stream error **sends a RST_STREAM frame** (Section 6.4) that
> contains the stream identifier of the stream where the error occurred." (RFC 9113 §5.4.2)

The one place the client already treats a protocol error as stream-scoped — `PumpBodyAsync`'s
catch at `:2822-2825` — calls `TryFail` and nothing else. `TryFail` (`:2771-2780`) is purely
local: it completes the channel, aborts the streaming response, cancels tokens and sets the
exception on `Completion`. No frame is written.

The failed `Completion` then surfaces at `:201` (`await state.Completion.Task`). The only
`catch` between there and the `finally` is `catch (OperationCanceledException) when
(cancellationToken.IsCancellationRequested)` at `:207`, which does not match — so control goes
straight to `:214-226`, which removes and disposes the stream. `TryResetStreamAsync` is never
reached. (Its call sites are `:177`, `:190`, `:210`, `:1307` — all on the *send* path or the
push path; none on the response-validation path.)

For a mid-stream failure — `AppendBodyAsync`'s `MaximumResponseBodyBytes` check at
`:2660-2664` is the reachable case, since the stream is still open — the client silently stops
consuming while the server keeps sending. The octets are only recovered by
`ReturnStrandedConnectionCreditAsync` in the pump's `finally` (`:2826-2837`), which restores
the connection window but never tells the peer to stop. The server continues transmitting a
body nobody will read until it finishes or the connection dies.

**VIOLATES. Severity: IMPORTANT.** (Not CRITICAL: the connection stays usable and flow control
is not corrupted. But it wastes the peer's bandwidth and leaves the stream open on the server
until it completes.)

**Fix:** in `Http2Connection`, wrap the `await state.Completion.Task` at `:201` with a catch
for `TlsHttpProtocolException` that calls
`await TryResetStreamAsync(streamId, Http2ErrorCode.Cancel)` before rethrowing — but *only*
when the stream is not already fully closed (`!state.HasReceivedEndStream`), because §5.1
forbids sending anything but PRIORITY on a closed stream, and the content-length mismatch
case at `:2860-2874` is detected exactly at END_STREAM. Guarding on
`HasReceivedEndStream` (`:2556`) gives the right split for free.

### 7.3 GOAWAY-then-close on a genuine connection error — CONFORMS

> "An endpoint that encounters a connection error SHOULD first send a GOAWAY frame
> (Section 6.8) with the stream identifier of the last stream that it successfully received
> from its peer. … After sending the GOAWAY frame for an error condition, the endpoint MUST
> close the TCP connection." (RFC 9113 §5.4.1)

`:1074-1083` sends GOAWAY first, then `FailAll`, then `_isReusable = 0` — so the pool retires
the connection and it is closed. `TrySendGoAwayAsync` (`:1951-2003`) swallows write failures
("The protocol error may have arrived with an already-failed transport"), matching §5.4.1's
"GOAWAY only provides a best-effort attempt". Last-Stream-ID uses
`_highestPromisedStreamId` — correct per §6.8, and the reasoning is already documented in
detail at `:1963-1970` with a "Do not 'fix' this back to `_nextStreamId`" warning.
Cross-checked against `HANDOFF.md:156`, which records the same conclusion.

**CONFORMS.** No finding.

### 7.4 Correctly-classified connection errors — CONFORMS

For completeness, these read-loop throws *are* genuine connection errors and are classified
right: DATA/HEADERS/PUSH_PROMISE on stream 0 (`:1142-1145`, `:1204-1207`, `:1260-1263`),
SETTINGS on a non-zero stream (`:1315-1318`), padding ≥ payload length
(`:2342-2345`, `:2355-2358`, `:2365-2368`, `:2393-2396`, `:2406-2409` — §6.1/§6.2 both
mandate a connection error of type PROTOCOL_ERROR here), all idle-stream frames (§4.1 above),
field-block interruption (§3 above), receive-window overrun (`:1151-1155`), server-sent
`SETTINGS_ENABLE_PUSH` (`:1354-1356`, §6.5.2), invalid `SETTINGS_INITIAL_WINDOW_SIZE`
(`:1366-1370`) and `SETTINGS_MAX_FRAME_SIZE` (`:1373-1377`), and zero WINDOW_UPDATE increment
(`:1482-1485`).

One nuance worth noting, not a finding: `:1159-1163` makes a *stream*-window overrun a
connection error, where §6.9.1 says "errors on the flow-control window of a stream MUST be
treated as a stream error … of type FLOW_CONTROL_ERROR". Flow control is another agent's
area; flagged here only so it is not lost between scopes.

---

## 8. Section 5.5 — extensibility

> "Implementations MUST ignore unknown or unsupported values in all extensible protocol
> elements. Implementations MUST discard frames that have unknown or unsupported types."
> (RFC 9113 §5.5)

> "Type: … Implementations MUST ignore and discard frames of unknown types." (RFC 9113 §4.1)

`src/TlsClient/Http2Connection.cs:1132-1134`:

```csharp
default:
    // Unknown extension frames are ignored as required by RFC 9113.
    break;
```

Three things make this actually correct rather than merely present:

1. The payload is fully consumed before dispatch (`:1092-1093`), so discarding an unknown
   frame cannot desynchronise the framing layer.
2. The length is still bounded by `_localMaximumFrameSize` (`:2921-2924`), so an unknown type
   cannot be used to force an unbounded allocation.
3. Unknown types inside a field block are *not* ignored — the CONTINUATION loops
   (`:1216-1221`, `:1294-1299`) reject any non-CONTINUATION type, satisfying §5.5's
   "extension frames that appear in the middle of a field block … MUST be treated as a
   connection error … of type PROTOCOL_ERROR".

`Http2FrameType.PriorityUpdate = 0x10` (`:2946`) is declared for the send path and has no
`case` in the receive switch, so an inbound PRIORITY_UPDATE falls to `default` and is
discarded — correct for a client.

**CONFORMS.** No findings.

---

## Summary

| # | Finding | Severity | Site | RFC | Verdict |
|---|---|---|---|---|---|
| F1 | Oversize frame emits GOAWAY `PROTOCOL_ERROR`, not `FRAME_SIZE_ERROR` | IMPORTANT | `Http2Connection.cs:2923`, `:1076` | §4.2 | VIOLATES (softened by §5.4) |
| F2 | Per-type size errors (SETTINGS/PING/RST_STREAM/WINDOW_UPDATE/GOAWAY) all emit `PROTOCOL_ERROR` | MINOR | `:1315`, `:1415`, `:1439`, `:1477`, `:1456` | §6.4–§6.9 | VIOLATES (softened by §5.4) |
| F3 | PRIORITY with length ≠ 5 is a connection error; must be a stream error | IMPORTANT | `:1109-1111`, `:2415-2422` | §6.3 | VIOLATES |
| F4 | Frames after END_STREAM tear down the connection; must be a STREAM_CLOSED stream error | **CRITICAL** | `:2682-2685`, `:2712-2715` → `:1071-1084` | §5.1 | VIOLATES |
| F5 | Undocumented 1024-entry rejected-push cap raises a connection error | MINOR | `:1282-1286` | §5.4.1 (permitted) | CONFORMS but undocumented |
| F6 | All response-validation errors are connection errors; §8.1.1 makes them stream errors | **CRITICAL** | `:1230` → `ApplyHeaders` `:2573-2649`; `:1186`, `:1238` | §5.4.1/§5.4.2/§8.1.1 | VIOLATES |
| F7 | Stream errors detected on the body pump never emit RST_STREAM | IMPORTANT | `:2822-2825`, `:2771-2780`, `:201-213` | §5.4.2 | VIOLATES |

**Counts:** 2 CRITICAL, 3 IMPORTANT, 2 MINOR.

### Clean areas — verified conformant, no action needed

- **§4.1 frame layout**: length bound enforced against the advertised value; reserved bit
  masked on receive and zeroed on send; unused flags ignored.
- **§4.2 connection-vs-stream classification for oversize frames**: correct (a permitted
  superset). Only the error code is wrong (F1/F2).
- **§4.3 field-block contiguity**: fully correct on both HEADERS and PUSH_PROMISE, including
  the wrong-stream case and mid-block extension frames.
- **§5.1 idle, reserved(remote), open, half-closed(local), closed**: all correct. The
  closed-stream handling is notably well done — HPACK decode before the stream lookup,
  connection-window credit for discarded DATA, WINDOW_UPDATE and RST_STREAM ignored rather
  than erroring. Only half-closed(remote) is wrong (F4).
- **§5.1.1 stream identifiers**: monotonic enforcement, reuse rejection and the
  lower-than-seen rule are all present and correctly ordered against `IsIdleStream`.
  Outbound allocation is validated at the options boundary.
- **§5.1.2 concurrency**: honoured on the send side, correct default, correct handling of a
  mid-connection reduction, reserved streams correctly excluded from the count.
- **§5.5 extensibility**: unknown frame types discarded without desynchronising the framing
  layer, and correctly *not* discarded inside a field block.

### Recommended order of work

1. **F6 + F4 together.** They share one fix: classification at the throw site plus a
   stream-scoped catch at the three read-loop call sites (`:1186`, `:1230`, `:1238`). This is
   the change that stops one bad response from killing a connection's worth of requests.
2. **F7.** Small, and it stops the client from silently ignoring a body the server keeps
   sending.
3. **F3.** Isolated to `ValidateFrame`'s caller for PRIORITY.
4. **F1 + F2.** Mechanical once `TlsHttpProtocolException` carries an error code, which
   step 1 already introduces. Fingerprint-relevant for this project specifically.
5. **F5.** Documentation and an error-code change.

### Note on deliberate divergences

`docs/superpowers/HANDOFF.md` and the XML/inline docs were checked for every finding above.
The documented divergences in this file — the GOAWAY Last-Stream-ID choice (`:1963-1970`,
`HANDOFF.md:156`), the read loop taking `_writeGate` (`HANDOFF.md:275-296`), the flow-control
padding accounting (`:1519-1530`, `:1187-1191`) — are all correct as written and are **not**
findings. None of F1–F7 is claimed anywhere as an intentional fidelity divergence; all seven
are unintentional or undocumented. F1 and F2 are the only two with a fingerprint dimension,
and in both cases conformance and fidelity point the same way: real clients emit
`FRAME_SIZE_ERROR`.
