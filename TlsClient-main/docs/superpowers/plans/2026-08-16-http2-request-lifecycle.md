# HTTP/2 Request Lifecycle and Data Path Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make everything a client puts on the wire *per request* declarative — the frames around the header block, the pseudo-headers, header and DATA framing, flow-control credit, shutdown codes, and where write batches end — so an arbitrary real client's request image can be reproduced byte for byte.

**Architecture:** `TlsRequestOptions` gains ordered frame lists and nullable overrides that fall back to the session. `TlsHttp2Options` gains pseudo-header, data, flow-control, and shutdown option objects. `Http2Connection` gets a real write-batch buffer so a declared batch becomes one `WriteAsync`, which is what makes every `FlushAfter` knob observable.

**Tech Stack:** .NET 9, xUnit 2.9.3, SharpTls (ProjectReference to the sibling checkout).

**Spec:** `docs/superpowers/specs/2026-08-14-http2-wire-fidelity-design.md` — read "Request lifecycle", "Data path", "Flow control", "Connection shutdown and reset codes", and "Write batching" before starting. This plan implements all five.

**Predecessor:** `docs/superpowers/plans/2026-08-15-http2-connection-layer.md`, complete through Task 13; Task 14 (public API baseline rebase) was dropped by the owner because the API is still changing. Read `docs/superpowers/HANDOFF.md` first.

---

## Design principles

Carried forward unchanged, and they outrank everything here:

1. **Fidelity of reproduction.** Prove byte equality, never approximate. A test that cannot fail is worse than no test.
2. **Ease of use from a manual capture.** A human reading a Wireshark dump or a `tls.peet.ws/api/all` response is the primary user.
3. **Flexibility.** No helper may assume the three built-in presets.

**Do not apply YAGNI to configurability.** The test is not "will someone use this knob?" but "can this vary between real clients on the wire?"

## Global constraints

- Every default must preserve today's bytes. `tests/TlsClient.Tests/Http2WireGoldenTests.cs` passes **unmodified** at every commit. If a golden fixture moves, the change is wrong.
- Suite is **215 passed, 0 failed** at the start and must never regress. Run from the repository root:
  `cd "c:/Users/Admin/Desktop/PROJECTS/PeakTLS/TlsClient-main" && dotnet test TlsClient.slnx -c Release`
- `TreatWarningsAsErrors` with `AnalysisLevel=latest-recommended`. `CA1859` (private method returning an interface) and `CA1305` (culture) both bit implementers on the last plan.
- `PublicAPI.Unshipped.txt` must carry every new public member or the build fails `RS0016`. The baseline is **not** being rebased; add to Unshipped only.
- Private fork: no compatibility shims, no obsolete members, no migration helpers.
- SharpTls is a `ProjectReference` now. A change there rebuilds here; keep SharpTls green too.

## Carry-notes

Facts a fresh session will not otherwise know:

- **`CapturedFrame` compares `Payload` by reference.** Never assert two frames wholesale with `Assert.Equal`; use `Http2WireAssert.EqualFrames`.
- **`Http2WireServer.ReadOnceAsync(max, ct)`** issues exactly one read and returns what one TLS record delivered. It is the only way to observe a client flush boundary — the `ReadFrameAsync` path uses `ReadExactly` and reports the reader's shape.
- **The transport does not coalesce today.** Every `WriteAsync` becomes its own TLS record, which is why `FlushAfter` is currently inert. Task 1 is what changes that; until it lands, no batching assertion can fail.
- **`EnterWriteBatchAsync` / the batch-close helper already exist** in `Http2Connection`, added for SETTINGS ACK placement. Task 1 hooks the buffer into those seams rather than inventing new ones.
- **A deferred SETTINGS ACK rides a write batch.** Anything that changes batch boundaries changes where the ACK can land; `Http2SettingsAckPlacementTests` is the check.
- **`Http2WireCapture.RunAsync` takes a request delegate**, so a test that needs three requests issues them inside the delegate and returns the last response.
- **Test the encoder, not the round trip.** HPACK decoding is lossy about representation; assert emitted octets.
- **Never read a fixed number of frames after the header block.** The SETTINGS ACK is written by the read loop on its own clock, so a counted read races it — a test written that way passes in isolation and fails under the full suite with `Expected: Data, Actual: Settings`. Read to a frame that is guaranteed to arrive (`ReadUntilAsync(Data)` on a POST) so anything written in between is drained without a count. `ExchangeReadingFramesAfterHeaders(n)` is only safe when exactly n frames are certain.
- **`Http2WireResult.ClientFrames` holds only what the server script actually read.** `MinimalExchange` stops at END_HEADERS and cannot see frames after the header block.
- **A request rejected before HEADERS is retried by the session**, which hangs the single-accept harness for its full 15-second timeout. Set `EnableRetries = false` in any rejection test.

## Scope boundary

**In scope:** per-request frame scripts, per-request priority and ordering overrides, padding, pseudo-header composition including `:protocol` emission, `host` versus `:authority`, header block fragmentation, trailer header suppression, DATA framing and END_STREAM placement, flow-control policy, GOAWAY and reset codes, write batching.

**Explicitly out of scope:** bidirectional extended-CONNECT stream lifetime. The owner does not need WebSocket support. `:protocol` is emitted when declared and validated per method, but no stream stays open bidirectionally and no 2xx CONNECT semantics are implemented.

**Deferred to plan 4:** `TlsHttp2Capture.Import` and the inference rules.

## File structure

| File | Change | Responsibility |
|---|---|---|
| `src/TlsClient/Http2WriteBatch.cs` | create | Buffered batch writer: accumulate frames, emit one `WriteAsync` per batch |
| `src/TlsClient/TlsHttp2RequestFrame.cs` | create | `TlsHttp2RequestFrame` hierarchy and its frozen configuration |
| `src/TlsClient/TlsHttp2PseudoHeaderOptions.cs` | create | Pseudo-header order, scheme, authority mode |
| `src/TlsClient/TlsHttp2DataOptions.cs` | create | DATA framing and END_STREAM placement |
| `src/TlsClient/TlsHttp2FlowControlOptions.cs` | create | WINDOW_UPDATE policy |
| `src/TlsClient/TlsHttp2ShutdownOptions.cs` | create | GOAWAY and reset codes |
| `src/TlsClient/TlsHttp2Options.cs` | modify | Hosts the four new option objects plus `HeaderBlockFragmentSize`, `EmitTrailerHeader`, the two flush scalars |
| `src/TlsClient/TlsRequestOptions.cs` | modify | Frame lists and nullable per-request overrides |
| `src/TlsClient/Http2Connection.cs` | modify | Consumes all of the above |
| `src/TlsClient/TlsHttpBehaviorProfile.cs` | modify | Carries the new shape |
| `tests/TlsClient.Tests/Http2WriteBatchTests.cs` | create | Batch boundary assertions |
| `tests/TlsClient.Tests/Http2RequestLifecycleTests.cs` | create | Request-image wire assertions |
| `tests/TlsClient.Tests/Http2FlowControlTests.cs` | create | Credit-policy wire assertions |

---

## Chunk 1: Write batching

### Task 1: Buffer a write batch into one write

The foundation. Until this lands every `FlushAfter` in the codebase is decorative.

**Files:**
- Create: `src/TlsClient/Http2WriteBatch.cs`
- Modify: `src/TlsClient/Http2Connection.cs` — `WriteFrameLockedAsync`, `EnterWriteBatchAsync`, the batch-close helper, `SendClientPrefaceAsync`
- Test: `tests/TlsClient.Tests/Http2WriteBatchTests.cs`

- [x] **Step 1: Write the failing test**

Two preface frames, a flush declared after the first. Assert one read delivers magic + SETTINGS only.

```csharp
[Fact]
public async Task FlushAfter_EndsTheRecordAtTheDeclaredBoundary()
{
    var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
    options.Http2.Preface =
    [
        new TlsHttp2SettingsFrame { Settings = [new(0x1, 4_096)], FlushAfter = true },
        new TlsHttp2WindowUpdateFrame { Increment = 1_000 },
    ];

    var delivered = 0;
    var result = await Http2WireCapture.RunAsync(
        options,
        (session, url, ct) => session.GetAsync(url, ct),
        async (server, ct) =>
        {
            // 24 magic + 15 SETTINGS = 39; the WINDOW_UPDATE's 13 must not join it.
            delivered = await server.ReadOnceAsync(52, ct);
            var headers = await server.ReadUntilAsync(Http2FrameType.Headers, ct);
            await server.WriteFrameAsync(
                Http2FrameType.Headers,
                Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                headers.StreamId,
                [0x88],
                ct);
            await server.FlushAsync(ct);
        });

    Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
    Assert.Equal(39, delivered);
}
```

- [x] **Step 2: Run to verify it fails**

`dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj -c Release --filter "FullyQualifiedName~Http2WriteBatchTests"`

Expected: FAIL, actual 24 — the magic arrives alone because nothing coalesces.

- [x] **Step 3: Implement the buffer**

`Http2WriteBatch` accumulates into an `ArrayBufferWriter<byte>` and writes once on close. Rules:

- A frame written outside a batch is written and flushed immediately, exactly as today.
- Inside a batch, frames append to the buffer. Closing the batch issues one `WriteAsync` of the whole buffer, then one `FlushAsync`.
- A declared `FlushAfter` closes the current batch and opens a new one, so the boundary lands between frames.
- The buffer is bounded: if it exceeds 1 MiB, flush early rather than grow. A persona cannot use batching to force unbounded buffering.
- `SendClientPrefaceAsync` wraps its whole loop in one batch, honoring each frame's `FlushAfter`.

- [x] **Step 4: Run to verify it passes**

Same filter. Expected: PASS.

- [x] **Step 5: Run the full suite**

`dotnet test TlsClient.slnx -c Release` — expected 216 passed. `Http2WireGoldenTests` must be untouched: batching changes record boundaries, never frame bytes. `Http2SettingsAckPlacementTests` must also stay green; if it does not, the ACK is riding the wrong batch.

- [x] **Step 6: Commit**

```bash
git add src/TlsClient/Http2WriteBatch.cs src/TlsClient/Http2Connection.cs tests/TlsClient.Tests/Http2WriteBatchTests.cs
git commit -m "feat: write an HTTP/2 batch as a single transport write"
```

### Task 2: Session flush scalars

**Files:**
- Modify: `src/TlsClient/TlsHttp2Options.cs`, `src/TlsClient/Http2Connection.cs` — the flush after the header block and after each DATA frame
- Test: `tests/TlsClient.Tests/Http2WriteBatchTests.cs`

- [x] **Step 1: Add the options**

```csharp
public bool FlushAfterHeaderBlock { get; set; } = true;
public bool FlushAfterEveryDataFrame { get; set; } = true;
```

Both default to today's behavior. Carry them through `Snapshot()` into `TlsHttp2Configuration`.

- [x] **Step 2: Consume them**

The header block's trailing flush and the per-DATA flush become conditional. When false, the frames accumulate in the batch and go out when the batch closes.

Three boundaries close the batch whatever the scalars say, because withholding them strands
the request: a frame carrying END_STREAM (nothing follows it to coalesce with), a header
block whose request declares `Expect: 100-continue` (RFC 9110 section 10.1.1 has the client
wait for an interim response the peer cannot send for octets it never received), and the
moment before the client waits for flow-control credit (RFC 9113 section 6.9.1 has the peer
credit only what it has received, so waiting while holding the octets that earn the credit
deadlocks). The last is enforced inside `ReserveSendWindowAsync`, which is the only place
the send path blocks on the peer.

- [x] **Step 3: Test**

`FlushAfterEveryDataFrame = false` with a body large enough for three DATA frames: assert one read delivers more than one frame's worth. With it true, assert each read stops at one frame.

Peer `SETTINGS_MAX_FRAME_SIZE` cannot be advertised below 16384 (RFC 9113 section 6.5.2) and
a TLS record carries at most 16384 plaintext octets, so a buffered body cannot put two DATA
frames in one record. The tests use a streaming body read 4096 octets at a time instead —
one DATA frame per read — which is client-side and needs no peer SETTINGS at all.

- [x] **Step 4: Commit**

```bash
git commit -am "feat: make the header-block and DATA flushes declared"
```

### Task 3: Reinstate the preface batching assertion

**Files:**
- Modify: `tests/TlsClient.Tests/Http2ConnectionLayerTests.cs` — `PrefaceFrames_ArriveOneRecordPerWriteWhicheverWayFlushAfterIsSet`

- [x] **Step 1: Replace the placeholder**

That test exists only because the transport could not coalesce. Rewrite it as the assertion plan 2's Task 11 actually wanted: 52 octets delivered when nothing flushes between the preface frames, 39 when the SETTINGS frame flushes. Rename to `FlushAfter_SplitsThePrefaceIntoTheDeclaredWriteBatches`.

- [ ] **Step 2: Commit**

```bash
git commit -am "test: assert the declared preface write batching"
```

---

## Chunk 2: Request frame script and overrides

### Task 4: Request frame types

**Files:**
- Create: `src/TlsClient/TlsHttp2RequestFrame.cs`
- Modify: `src/TlsClient/PublicAPI.Unshipped.txt`

- [x] **Step 1: Write the types**

`TlsHttp2RequestFrame` (abstract, `FlushAfter`), and sealed `TlsHttp2StreamPriorityFrame`, `TlsHttp2PriorityUpdateFrame`, `TlsHttp2PingFrame`, `TlsHttp2RequestRawFrame` exactly as the spec's "Per-request frame script" section defines them.

- [x] **Step 2: Freeze and validate**

An internal `TlsHttp2RequestFrameConfiguration(byte Type, byte Flags, int StreamId, byte[] Payload, bool FlushAfter, bool TargetsRequestStream)` mirrors the preface's frozen shape. Validation, mirroring `TlsHttp2Options`:

- A raw frame may not use DATA, HEADERS, RST_STREAM, PUSH_PROMISE, GOAWAY, or CONTINUATION — those belong to the request machinery.
- A PING payload is exactly 8 octets; RFC 9113 section 6.7 makes any other length a **FRAME_SIZE_ERROR**.
- A PING must target stream 0; section 6.7 makes any other stream identifier a **PROTOCOL_ERROR**. Two failure modes, two different codes — do not collapse them into one message.
- `PriorityUpdateFrame.Value` is 1–256 visible ASCII, matching the session-level rule.
- At most 16 frames per list.

- [x] **Step 3: Declare the API and commit**

Build, copy the exact strings `RS0016` demands into `PublicAPI.Unshipped.txt`, rebuild clean.

```bash
git commit -am "feat: add HTTP/2 per-request frame types"
```

### Task 5: Frame lists on the request

**Files:**
- Modify: `src/TlsClient/TlsRequestOptions.cs`, `src/TlsClient/Http2Connection.cs` — `SendRequestAsync`
- Test: `tests/TlsClient.Tests/Http2RequestLifecycleTests.cs`

- [x] **Step 1: Add the lists**

`FramesBeforeHeaders` and `FramesAfterHeaders`, both defaulting to empty. Two lists, not one with a marker, so the header block's position needs no sentinel.

- [x] **Step 2: Resolve the stream sentinel at send time**

`StreamId = 0` on a request frame means "this request's stream" and is replaced with the allocated identifier when written. A frame that genuinely targets stream 0 declares `TlsHttp2RequestRawFrame` with the connection-level type it wants; the sentinel only applies to the frame classes whose natural target is the request stream. Document that in the XML docs — it is the one surprising rule in this task.

- [x] **Step 3: Write both lists inside the request's batch**

Before-frames precede HEADERS, after-frames follow the final CONTINUATION. Nothing may land between HEADERS and its CONTINUATION frames (RFC 9113 sections 6.2 and 6.10).

- [x] **Step 4: Test**

A PING in `FramesBeforeHeaders` and a PRIORITY in `FramesAfterHeaders`: assert `ClientFrames` order is PING, HEADERS, PRIORITY, and that the PRIORITY carries the request's stream identifier while the PING carries 0.

- [x] **Step 5: Commit**

```bash
git commit -am "feat: script the frames around a request's header block"
```

### Task 6: Session PRIORITY_UPDATE stays a fallback

**Files:**
- Modify: `src/TlsClient/Http2Connection.cs` — the unconditional PRIORITY_UPDATE emission after HEADERS

- [x] **Step 1: Make it conditional**

Emit the session-level `PriorityUpdate` after HEADERS only when the request declares no `TlsHttp2PriorityUpdateFrame` of its own. A request that declares one owns the placement.

- [x] **Step 2: Test and commit**

Assert a request declaring a `TlsHttp2PriorityUpdateFrame` in `FramesBeforeHeaders` emits exactly one PRIORITY_UPDATE, before HEADERS.

```bash
git commit -am "feat: let a request override the session PRIORITY_UPDATE"
```

### Task 7: Per-request overrides

**Files:**
- Modify: `src/TlsClient/TlsRequestOptions.cs`, `src/TlsClient/Http2Connection.cs` — `BuildRequestHeaders`

- [x] **Step 1: Add the nullable properties**

`HeaderOrder`, `PseudoHeaderOrder`, `HeaderPriority`, `PriorityUpdate`. Null falls back to the session value.

- [x] **Step 2: Resolve at send time**

`HeaderOrder` applies to HTTP/1.1 as well, because `Http11RequestWriter.Order` is already shared. Every other override is HTTP/2 only and is **ignored** on an HTTP/1.1 connection rather than throwing, so a persona survives version fallback.

- [x] **Step 3: Test and commit**

Two requests on one connection with different `PseudoHeaderOrder`: decode both header blocks and assert each followed its own order.

```bash
git commit -am "feat: allow per-request ordering and priority overrides"
```

### Task 8: Padding

**Files:**
- Modify: `src/TlsClient/TlsRequestOptions.cs`, `src/TlsClient/Http2Connection.cs` — header block writer and DATA writer

- [x] **Step 1: Add `HeadersPadding` and `DataPadding`**

Nullable ints. When set, the frame carries PADDED, a pad-length octet, and that many zero octets. Range 0–255; the pad length field is one octet (RFC 9113 sections 6.1 and 6.2).

**Nullable is load-bearing, not stylistic.** PADDED set with `Pad Length = 0` is a different wire image from PADDED unset — one octet longer — and RFC 9113 section 6.1 calls that out. `null` means no PADDED flag; `0` means PADDED with an empty pad. A plain `int` cannot express the difference.

- [x] **Step 2: Account for padding in the fragment budget**

Padding consumes frame payload. The HEADERS budget is `maxFrameSize − 1 (pad-length octet) − 5 (priority payload, when present) − padLength`. Overrunning it on HEADERS is a **connection** error, not a stream error, because HEADERS carries a field block (RFC 9113 section 4.2).

CONTINUATION has no PADDED flag, so only the first frame of a split block pays the pad cost.

- [x] **Step 3: Padded DATA is flow-controlled on the whole payload**

RFC 9113 section 6.1: "The entire DATA frame payload is included in flow control, including the Pad Length and Padding fields." The send-window reservation must therefore charge `dataBytes + 1 + padLength`, not `dataBytes`. Getting this wrong over-sends the window and the peer answers FLOW_CONTROL_ERROR. Task 13 sizes DATA frames; this rule binds both tasks.

- [x] **Step 4: Test and commit**

Assert the PADDED flag, the pad-length octet, and total frame length for a padded HEADERS and a padded DATA.

Tests live in `tests/TlsClient.Tests/Http2PaddingTests.cs`; the lifecycle file was already 575
lines. Two notes for later tasks:

- The loopback authority carries the listener's ephemeral port, so two captures of the "same"
  request do not encode to the same field block. Any test comparing one wire image against
  another across two `Http2WireCapture.RunAsync` calls must pin `Host`, which pins `:authority`.
- The connection send window is fixed at 65535 and **cannot** be changed by SETTINGS (RFC 9113
  section 6.9.2), so a send-side flow-control test needs no peer SETTINGS and therefore has no
  race against the client's read loop. Driving one through `SETTINGS_INITIAL_WINDOW_SIZE` would
  race the first request.

```bash
git commit -am "feat: emit declared HEADERS and DATA padding"
```

---

## Chunk 3: Pseudo-headers and header framing

### Task 9: Pseudo-header composition

**Files:**
- Create: `src/TlsClient/TlsHttp2PseudoHeaderOptions.cs`
- Modify: `src/TlsClient/TlsHttp2Options.cs`, `src/TlsClient/Http2Connection.cs` — `BuildRequestHeaders`

- [x] **Step 1: Write the options**

`Order`, `AuthorityMode` (`AuthorityOnly` / `HostHeaderOnly` / `Both`), `Scheme`. `TlsRequestOptions` gains `Scheme`, `Protocol`, `PathOverride`, `AuthorityMode`.

`TlsHttp2Options.PseudoHeaderOrder` is **shipped** public API and the baseline is not being
rebased, so it could not be deleted in favour of `PseudoHeaders.Order`. It is now a
forwarding property over that same storage — one source of truth, and `TlsPreset`,
`TlsHttpBehaviorProfile.ApplyTo` and `README.md` needed no edit. The internal
`TlsHttp2Configuration` carries `PseudoHeaders` in its place, which is what Task 21 extends.

`Order` **declares which pseudo-headers are emitted**, replacing today's permutation-of-exactly-four validation. `:protocol` is emitted when `Protocol` is set and appears in the order.

- [x] **Step 2: Replace the hardcoded builder**

Today `:scheme` is fixed to `https` and `host` is unconditionally dropped. `AuthorityMode` selects `:authority` alone, a `host` regular header alone, or both. `PathOverride` supplies `:path` verbatim so `OPTIONS *` becomes expressible.

**Correcting the spec here.** The spec claims RFC 9113 section 8.3.1 "permits all three". It does not. A client generating HTTP/2 requests directly **MUST** use `:authority` rather than `Host`, so `HostHeaderOnly` deliberately violates a MUST, and `Both` is legal only when the two carry the same value. Keep all three modes — this project reproduces real clients including non-conformant ones — but the XML docs must say which mode departs from the RFC and why anyone would want it. Do not repeat the "permits all three" claim.

- [x] **Step 3: Test and commit**

Assert each `AuthorityMode` produces the expected fields, and that `PathOverride = "*"` emits `:path: *`.

Tests live in `tests/TlsClient.Tests/Http2PseudoHeaderTests.cs`; the lifecycle file was already
575 lines. Note for Task 10: `AuthorityMode.Both` cannot emit divergent values as the builder
stands, because `:authority` and the `host` field are both read from the request's `Host` field
when it carries one and from the request URI otherwise. The cross-check that task owes is
therefore a guard against a future divergence, not against one reachable today.

```bash
git commit -am "feat: make HTTP/2 pseudo-header composition declarative"
```

### Task 10: Per-method pseudo-header validation

**Files:**
- Modify: `src/TlsClient/Http2Connection.cs` — `BuildRequestHeaders`

- [x] **Step 1: Validate before writing a byte**

Legality depends on the method, so this is per request at send time, not at `Snapshot()`:

- `:method` is always required.
- CONNECT without `:protocol`: only `:method` and `:authority` are permitted (RFC 9113 section 8.5).
- CONNECT with `:protocol`: `:method`, `:authority`, `:scheme`, `:path`, `:protocol` all required (RFC 8441 section 4).
- Any other method: `:method`, `:scheme`, `:path` required, `:authority` permitted.
- Under `AuthorityMode.Both`, the `host` header and `:authority` must carry the same value. Divergent values are rejected — a server that trusts one over the other becomes a request-smuggling seam, and no real client emits them differently.

Throw `HttpRequestException` before any frame is written, so a rejected request cannot leave a half-open stream.

- [x] **Step 2: Test and commit**

One case per rule, asserting the message names the offending method.

`Http2Connection.ValidatePseudoHeaders` runs at the end of the pseudo-header loop in
`BuildRequestHeaders`, which `SendRequestAsync` calls before it enters the write batch.

**No forbidden set for a non-CONNECT method.** The RFC reference's legality matrix (section 6)
prints `Forbidden: —` for normal methods, and RFC 9113 section 8.3.1 names no pseudo-header a
normal request may not carry, so only the required set is enforced there. In particular a
`:protocol` on a GET is *not* rejected: RFC 8441 section 4 scopes the field to CONNECT but
states no prohibition, and inventing one would have made
`Http2PseudoHeaderTests.Protocol_IsEmittedInItsDeclaredPositionOnlyWhenSet` — a Task 9 test —
illegal for no cited reason.

One Task 9 test did have to move: `RequestOrder_OverridesTheSessionOrder` declared
`[":scheme", ":authority", ":method"]` on a GET, which this task makes malformed for want of
`:path`. It now permutes the full four, which is the axis it was testing anyway.

The `AuthorityMode.Both` cross-check turned out to be reachable after all, though only through
a multi-valued `host` field: `:authority` is read from the *first* value, so a second one
diverges. Task 9's note holds for the single-valued case.

```bash
git commit -am "fix: validate pseudo-headers against the request method"
```

### Task 11: Header block fragmentation

**Files:**
- Modify: `src/TlsClient/TlsHttp2Options.cs`, `src/TlsClient/Http2Connection.cs` — the header block writer

- [x] **Step 1: Add `HeaderBlockFragmentSize`**

Nullable int. Effective split is `min(HeaderBlockFragmentSize, peerMaxFrameSize)` — it can only fragment smaller than the peer permits, never larger.

- [x] **Step 2: The two rules the spec calls out**

- **Pre-SETTINGS determinism.** The peer's maximum frame size is seeded at 16384 and rises only when the peer's SETTINGS is processed, which races the first request. Replay must be deterministic, so the pre-SETTINGS clamp is fixed at the RFC default of 16384 rather than whatever arrived first.
- **Minimum of 6, unconditionally.** The writer computes `maximumFrameSize - priorityLength` with a priority length of 5, so 1–5 yields a negative length. Per-request priority means the session cannot know whether a request will carry one, so the floor is enforced at `Snapshot()` regardless.

- [x] **Step 3: Test and commit**

A header list forcing CONTINUATION at a declared fragment size: assert every fragment's length. Assert `Snapshot()` rejects 5.

```bash
git commit -am "feat: declare the header block fragment size"
```

### Task 12: Trailer header suppression

**Files:**
- Modify: `src/TlsClient/TlsHttp2Options.cs`, `src/TlsClient/Http11RequestWriter.cs`

- [x] **Step 1: Add `EmitTrailerHeader`**

Default `true`, preserving current behavior. When false, the `Trailer` request header is not added even though trailers are present. Real HTTP/2 clients generally do not send it.

- [x] **Step 2: Test and commit**

```bash
git commit -am "feat: allow suppressing the Trailer request header"
```

---

## Chunk 4: Data path, flow control, shutdown

### Task 13: DATA framing

**Files:**
- Create: `src/TlsClient/TlsHttp2DataOptions.cs`
- Modify: `src/TlsClient/Http2Connection.cs` — the send-window reservation

- [x] **Step 1: Add `MaxDataFrameSize`**

Effective size is `min(MaxDataFrameSize, peerMaxFrameSize, connectionWindow, streamWindow)`, with the same pre-SETTINGS determinism rule as header fragments. Today the client frames as large as the peer permits — up to 16 MiB — while real clients self-cap, commonly at 16384. For a POST-heavy persona the DATA size histogram is among the most visible properties of the connection.

- [x] **Step 2: Test and commit**

Post a body of 40000 octets with `MaxDataFrameSize = 16384`; assert DATA frame lengths are 16384, 16384, 7232.

**Correction found while implementing.** That assertion cannot fail on its own: `_peerMaximumFrameSize` is seeded at the RFC 9113 section 6.5.2 default of 16384, so a client that ignored `MaxDataFrameSize` entirely would still emit 16384, 16384, 7232. The test therefore has the harness advertise `SETTINGS_MAX_FRAME_SIZE = 65536` first, and issues a warm-up request so the peer's SETTINGS is applied before the POST is framed — otherwise the two race.

```bash
git commit -am "feat: cap the client's own DATA frame size"
```

### Task 14: END_STREAM placement

**Files:**
- Modify: `src/TlsClient/TlsHttp2DataOptions.cs`, `src/TlsClient/Http2Connection.cs`

- [x] **Step 1: Add the switches**

`NonEmptyBody` (`OnLastDataFrame` / `SeparateEmptyDataFrame`) and `EmptyBodyEndsOnHeaders` (default true). Today the choice falls out of which internal code path supplied the body — END_STREAM on HEADERS for an empty body, on the last DATA frame for a buffered body, and a separate empty DATA frame for a streaming body. Make it a persona decision independent of how the caller supplied the body.

- [x] **Step 2: Test and commit**

Assert a buffered body under `SeparateEmptyDataFrame` emits a trailing zero-length DATA carrying END_STREAM, and that a streaming body under `OnLastDataFrame` does not.

**Conflict resolved while implementing, recorded here.** This step and the "every default must preserve today's bytes" constraint cannot both hold for the streaming path: today that path *always* closes with a separate empty DATA frame, so making the default `OnLastDataFrame` apply to it is by definition a change of default bytes. The step wins, because a `NonEmptyBody` that the streaming path ignores by default would leave exactly the "the code path decides, not the persona" defect this task exists to remove. The golden fixtures — the constraint's operational test, and the only place a stated byte image lives — are untouched and green; the two `Http2WriteBatchTests` record-boundary expectations that counted the trailing 9-octet frame were adjusted, and they assert batching, not placement.

**Constraint discovered while implementing.** `OnLastDataFrame` needs to know which frame is last *before* writing it. A streamed body only knows that from a declared `Content-Length`; finding out by reading one chunk ahead would hold written octets across a blocking read of the caller's producer, which is the deadlock 892f951 removed. A streamed body of undeclared length therefore keeps the separate empty frame, and the XML docs say so.

```bash
git commit -am "feat: declare where END_STREAM lands"
```

### Task 15: Flow-control credit policy

**Files:**
- Create: `src/TlsClient/TlsHttp2FlowControlOptions.cs`
- Modify: `src/TlsClient/Http2Connection.cs` — receive-window restoration
- Test: `tests/TlsClient.Tests/Http2FlowControlTests.cs`

- [x] **Step 1: Threshold, trigger, increment**

- **Threshold.** `0` credits as bytes are accounted, preserving current behavior. Any other value accumulates and emits only once that many bytes are outstanding.
- **Trigger.** `OnConsume` credits when the application accepts data; `OnReceive` credits on frame receipt. The two produce visibly different traces for a slow reader.
- **Increment.** `BytesAccounted` matches today. `RefillToInitial` restores the declared initial window. `Fixed` sends `FixedIncrement`, which must validate to `[1, 2^31 − 1]`: RFC 9113 section 6.9 makes a zero increment a PROTOCOL_ERROR, and the field is 31 bits.

A stream-level WINDOW_UPDATE on a half-closed or closed stream is explicitly **not** an error (section 6.9), which is what makes `SuppressStreamUpdateOnEndStream` a real axis rather than a conformance question.

- [x] **Step 2: Test and commit**

Assert the WINDOW_UPDATE increments a server sees for each combination, against a body large enough to cross the threshold twice.

```bash
git commit -am "feat: declare when and how much flow-control credit is returned"
```

### Task 16: Update order, coalescing, end-stream suppression

**Files:**
- Modify: `src/TlsClient/TlsHttp2FlowControlOptions.cs`, `src/TlsClient/Http2Connection.cs`

- [x] **Step 1: The remaining three axes**

`Order` swaps connection-first for stream-first. `CoalesceConnectionAndStream` puts both in one write batch — which is what most clients do, and is only observable because Task 1 exists. `SuppressStreamUpdateOnEndStream` defaults true, matching today; some clients send it anyway.

- [x] **Step 2: Test and commit**

Use `ReadOnceAsync` to prove the coalesced pair arrives in one record.

```bash
git commit -am "feat: declare WINDOW_UPDATE ordering and coalescing"
```

### Task 17: Cross-field threshold validation

**Files:**
- Modify: `src/TlsClient/TlsHttp2Options.cs` — `Snapshot()`

- [x] **Step 1: Reject a self-deadlocking persona**

`StreamWindowUpdateThreshold` must not exceed the declared `SETTINGS_INITIAL_WINDOW_SIZE`, and `ConnectionWindowUpdateThreshold` must not exceed `65535 + Σ preface WINDOW_UPDATE increments`. Otherwise the window is exhausted before the threshold is reached, no WINDOW_UPDATE is ever emitted, and the transfer stalls permanently. Both sides now live in the same options object, so this is a cross-field rule.

- [x] **Step 2: Test and commit**

```bash
git commit -am "fix: reject flow-control thresholds that can never be reached"
```

### Task 18: GOAWAY on shutdown

**Files:**
- Create: `src/TlsClient/TlsHttp2ShutdownOptions.cs`
- Modify: `src/TlsClient/Http2Connection.cs` — `DisposeAsync`

- [x] **Step 1: Add the options**

`SendGoAwayOnDispose` (default false, today's behavior), `GoAwayErrorCode` (default `NoError`), `GoAwayDebugData`. Whether a client announces shutdown, with which code and last-stream-id, is observable.

- [x] **Step 2: Test and commit**

**Last-Stream-ID is the last _peer_-initiated stream, not the client's own.** RFC 9113 section 6.8 defines it against streams the *sender's peer* opened, so in a client's GOAWAY it names the highest **even** identifier — a pushed stream — and is **0** whenever the server pushed nothing, which is the normal case. Assert 0 for a connection with no push, and assert the highest promised even identifier for one that received PUSH_PROMISE. Do not assert the client's own highest stream; that was wrong in an earlier draft of this plan.

```bash
git commit -am "feat: allow announcing shutdown with GOAWAY"
```

### Task 19: Reset codes

**Files:**
- Modify: `src/TlsClient/TlsHttp2ShutdownOptions.cs`, `src/TlsClient/Http2Connection.cs` — the four hardcoded reset sites

- [x] **Step 1: Replace the hardcodes**

`CancellationResetCode` (default `Cancel`), `LocalFailureResetCode` (default `InternalError`), `PushRejectionResetCode` (default `Cancel`). Which code a stack uses to cancel a stream is a known discriminator.

- [x] **Step 2: Test and commit**

Cancel a request mid-flight and assert the RST_STREAM error code matches the declared value.

```bash
git commit -am "feat: declare RST_STREAM error codes"
```

---

## Chunk 5: Net, portability, docs

### Task 20: Request-lifecycle wire assertions

**Files:**
- Create/extend: `tests/TlsClient.Tests/Http2RequestLifecycleTests.cs`

- [x] **Step 1: Close the net**

One assertion per axis this plan added that is not already covered by its own task: frame-list ordering across two requests on one connection, padding interaction with CONTINUATION, `AuthorityMode.Both` field ordering, `MaxDataFrameSize` against a peer that advertises less, and each reset code.

Survey first: two of the five were already pinned and were left alone rather than duplicated.

- Padding × CONTINUATION — **already covered** by `Http2PaddingTests.PaddingWithContinuation_IsPaidOnceOutOfTheFirstFramesBudget`, which asserts PADDED on the HEADERS frame only, its absence on every CONTINUATION, and that no fragment exceeds the peer's maximum.
- Three reset codes — **already covered**, each on its own trigger path: `CancelledStream_IsResetWithoutClosingMultiplexedConnection` (theory, default `Cancel` and a declared `RefusedStream`), `FailedUpload_ResetsTheStreamWithTheDeclaredLocalFailureCode` (theory, default `InternalError` and a declared `ConnectError`), and `Dispose_AnnouncesGoAwayNamingTheLastPeerInitiatedStream` (declared `PushRejectionResetCode` of `RefusedStream` on the declined PUSH_PROMISE).

Three were genuinely missing and were added:

- `Http2RequestLifecycleTests.FrameLists_AreResolvedPerRequestOnOneConnection` — two requests, one connection, different before-lists and only the first with an after-list. `DeclaredPriorityUpdate_NamesEachStreamItIsSentOn` looks adjacent but redirects a *single* request, so it shares one frame list and cannot see a leak between two.
- `Http2PseudoHeaderTests.Both_PutsTheHostFieldAfterEveryPseudoHeader` — `EveryPseudoHeaderPrecedesEveryRegularField` captures under the default `AuthorityOnly`, which drops `host`, so it is structurally blind to the one regular field `Both` adds.
- `Http2DataFramingTests.PeerMaximumFrameSize_BelowTheDeclaredCap_BindsInsteadOfIt` — the peer advertises 20000 against a declared cap of 40000. A non-default advertisement, so a client falling back on the fixed 16384 pre-SETTINGS floor fails it too.

- [x] **Step 2: Falsify every one of them**

Mutate the production code for each assertion and confirm it goes red. Three tests in the last plan passed on first run and only mutation showed they were real. Record what you mutated in the commit body.

All three passed on first run. Each was then falsified against the full suite:

| Mutation in `Http2Connection.cs` | Red |
|---|---|
| `ReserveSendWindowAsync`: `frameBudget = Math.Min(peerMax, declared)` → `= declared` | 2 (`PeerMaximumFrameSize_BelowTheDeclaredCap_BindsInsteadOfIt`, `FlushAfterEveryDataFrame_False_CoalescesTheFramesOfOneRead`) |
| `BuildRequestHeaders`: seed `output` with the `host` field before the pseudo-header loop under `Both` | 1 (`Both_PutsTheHostFieldAfterEveryPseudoHeader`) |
| `SendRequestAsync`: cache the first request's `FramesBeforeHeaders`/`FramesAfterHeaders` in connection fields and write those for every later request | 1 (`FrameLists_AreResolvedPerRequestOnOneConnection`) |

Mutations 2 and 3 turned exactly one test red each — the new one — which is the proof the axis was uncovered before rather than merely under-asserted.

- [x] **Step 3: Commit**

```bash
git commit -am "test: pin the declared request wire image"
```

### Task 21: Behavior profile carries the new shape

**Files:**
- Modify: `src/TlsClient/TlsHttpBehaviorProfile.cs`

- [x] **Step 1: Extend capture, export, import, apply**

Carry the pseudo-header, data, flow-control, and shutdown options and the two flush scalars. Per-request frame lists are **not** carried: the profile describes a session, not a request. Say so in the XML docs.

Bump `DocumentVersion` to 3 and reject 2, as this fork does. Keep the import path strict, case-sensitive, bounded, rejecting unknown and duplicate properties, and running the result through session-construction validation.

Done. `HeaderBlockFragmentSize` and `EmitTrailerHeader` are carried alongside the two flush scalars: both are session-level `TlsHttp2Options` fields that change the emitted bytes, so leaving them out would reintroduce exactly the silent round-trip drift e4388e7 was written to close. `Http2Document.pseudoHeaderOrder` is replaced by a `pseudoHeaders` object rather than kept beside it — the version bump is what pays for that.

Two strictness gaps closed while the import path was open. `JsonStringEnumConverter` accepts integers as well as names, so a document could carry an enum value no member defines; `TlsHttp2Behavior.Defined` now rejects each new enum as a `JsonException` rather than letting it surface later as an `ArgumentOutOfRangeException` from validation. `GoAwayDebugData` travels base64, as a preface payload does, because RFC 9113 section 6.8 makes it opaque octets.

`ApplyTo` writes through `options.PseudoHeaders`, not through the `TlsHttp2Options.PseudoHeaderOrder` forwarding property, which reaches neither `AuthorityMode` nor `Scheme`.

- [x] **Step 2: Test and commit**

Round-trip each preset and assert identical emitted bytes, extending the existing preset round-trip theory.

`CaptureImportApply_ReproducesEachPresetsPrefaceOctets` became `…PrefaceAndRequestBytes`: after the frozen-configuration assertions it now runs the preset and the restored profile against the same scripted server and compares the preface octets literally plus every client frame with the SETTINGS ACK filtered out. Two additions were needed to make it mean anything: the restored session is handed the preset's default header *values* by hand (a profile carries none), and `Host` is pinned on both, because the harness binds an ephemeral port and `:authority` would otherwise differ by the port alone — which is how the assertion first went red.

`CaptureImportApply_RoundTripsTheRequestLifecycleOptions` sets a non-default value in every one of the four option objects and in all four scalars, then asserts them off the restored `Snapshot()`. `Import_RejectsTheSupersededDocumentVersion` and `Import_RejectsAnUndefinedEnumCarriedAsANumber` cover the two new rejections.

| Mutation in `TlsHttpBehaviorProfile.cs` | Red |
|---|---|
| `ApplyTo`: drop `pseudoHeaders.Order` | 4 (`…PrefaceAndRequestBytes` firefox + android, `RoundTripsTheRequestLifecycleOptions`, `CaptureJsonImportApply_RoundTrips…`) |
| `ApplyTo`: drop `data.MaxDataFrameSize` | 1 (`RoundTripsTheRequestLifecycleOptions`) |
| `ApplyTo`: drop `shutdown.GoAwayDebugData` | 1 (`RoundTripsTheRequestLifecycleOptions`) |
| `ImportJson`: `document.Version != DocumentVersion` → `< 2` | 1 (`Import_RejectsTheSupersededDocumentVersion`) |
| `Defined<TEnum>`: return the value unchecked | 1 (`Import_RejectsAnUndefinedEnumCarriedAsANumber`) |

The first mutation is the one that proves the wire half earns its place: the theory's frozen-configuration assertions cover the preface and the derived receive bounds and never look at pseudo-header order, so those two reds came from the frame comparison alone. Chrome stayed green there because its declared order is the default one.

```bash
git commit -am "feat: carry the request-lifecycle options in the behavior profile"
```

### Task 22: Documentation

**Files:**
- Modify: `docs/PRESETS.md`, `docs/superpowers/HANDOFF.md`, `docs/superpowers/specs/2026-08-14-http2-wire-fidelity-design.md`

- [x] **Step 1: Document the request-level axes**

A section on the per-request frame script and the pseudo-header model, including that `:protocol` is emitted but no bidirectional CONNECT stream exists. Note `OPTIONS *` and `host` versus `:authority` as the non-WebSocket wins.

`docs/PRESETS.md` gains "The request image is a script too" and "Pseudo-headers". Both `AuthorityMode` and `:protocol` are stated against the RFC rather than around it: a table naming `HostHeaderOnly` as the one mode that violates a MUST, and a paragraph saying plainly that no bidirectional CONNECT stream exists, so `:protocol` emission is not WebSocket support and is not planned to become it. The non-WebSocket wins listed are `OPTIONS *` via `PathOverride`, `host` versus `:authority`, and a non-`https` `:scheme`.

- [x] **Step 2: Correct the spec, update the handoff, and commit**

The spec is the binding authority and was wrong in two places. Both are fixed in place with the correction called out, so a later reader does not "restore" them:

- **"which RFC 9113 section 8.3.1 permits"** applied to all three authority modes. It does not. Section 8.3.1 puts a MUST on `:authority` for a client generating requests directly, excused only when there is no authority information to convey; `Both` is conformant only while the two fields agree, and `HostHeaderOnly` deliberately violates the MUST. The code and this plan already carried the correction; the spec did not.
- **The `HeaderBlockFragmentSize` floor-of-6 rationale predated padding.** Task 8 charged padding to the same fragment budget, so 6 with a 255-octet pad still computes a negative length, and raising the floor cannot fix it because padding is per-request too. The writer's one-octet guarantee is what actually holds. Recorded per `bb688de`.

`HANDOFF.md`'s "Where things stand" was stale in every row — 150 tests, no production changes, OneDrive paths, SharpTls as a pinned binary NuGet reference. Rewritten against reality, plus four carry-forward facts: Task 14's deliberate default-byte change on the streaming path and why the alternative was worse, the `Content-Length` requirement `OnLastDataFrame` has on a streaming body, the `FixedIncrement` stall nothing rejects, and the shipped GOAWAY Last-Stream-ID bug now carrying a "do not fix this back" comment. The stale "`FlushAfter` has no observable effect" and "plan 2 is through Task 12" notes above it, and the reading-order list, were corrected in the same pass.

```bash
git commit -am "docs: describe the per-request wire image and correct the spec"
```

---

## Self-review checklist

Before declaring this plan complete:

- `Http2WireGoldenTests` passes **unmodified**. If it was touched, a default changed bytes and the change is wrong.
- Every new test has been falsified by mutating production code.
- `dotnet build TlsClient.slnx -c Release` is clean — no `RS0016`, no analyzer warnings.
- Both suites green: TlsClient and SharpTls.
- No knob is declared but inert. Task 1 exists precisely so the batching knobs are not.
- Every `Snapshot()` rule that can deadlock or overrun has a test proving the rejection.
