# HTTP/2 Connection Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the HTTP/2 connection preface and HPACK header encoding fully declarative, so any real client's connection-level wire image can be reproduced byte for byte.

**Architecture:** `TlsHttp2Options` loses its eight fixed setting properties and gains an ordered list of typed preface frames plus an HPACK policy object. `Http2Connection` writes that list verbatim and derives its own receive-side state from it. `HpackCodec`'s encoder is rewritten around a resolved-representation model that can emit all four RFC 7541 forms.

**Tech Stack:** .NET 9, xUnit 2.9.3, SharpTls 0.9.0-preview.5.

**Spec:** `docs/superpowers/specs/2026-08-14-http2-wire-fidelity-design.md` — read the Purpose, Goals, Non-goals, Preface script, and HPACK policy sections before starting. This plan implements the connection-layer half; request lifecycle and data path are plan 3, capture import is plan 4.

**Predecessor:** `docs/superpowers/plans/2026-08-15-http2-byte-level-wire-harness.md`, complete. It built the byte-level test harness under `tests/TlsClient.Tests/Wire/` that this plan's regression net depends on.

## Design principles

Carried from the harness plan, unchanged, and they outrank everything else here:

1. **Fidelity of reproduction.** Prove byte equality, never approximate. A test that cannot fail is worse than no test.
2. **Ease of use from a manual capture.** A human reading a Wireshark dump or a `tls.peet.ws/api/all` response is the primary user.
3. **Flexibility.** No helper may assume the three built-in presets.

## Global Constraints

- **This plan changes production code.** Unlike its predecessor, `src/` is in scope. The public API is deliberately broken; see below.
- **`PublicAPI.Shipped.txt` is enforced by a Roslyn analyzer and fails the build on any undeclared change.** Every task that alters public surface must update it in the same commit, or the build breaks for every later task.
- Target `net9.0`. Nullable reference types and `TreatWarningsAsErrors` are on, with `AnalysisLevel=latest-recommended`. Analyzer warnings fail the build. Note `CA1859` in particular: a private method returning an interface where a concrete type is used will fail.
- **The three presets must emit byte-identical wire output at the end of this plan.** `tests/TlsClient.Tests/Http2WireGoldenTests.cs` pins their preface bytes exactly and must pass unmodified. If a preset's bytes change, the migration is wrong — do not adjust the fixture.
- The suite is at **150 passed, 0 failed** at the start. It must never regress. Run `dotnet test TlsClient.slnx -c Release` from the repository root.
- This is a private fork. No compatibility shims, no obsolete-marked members, no migration helpers.

## Carry-notes from the harness plan

Facts a fresh session will not otherwise know, each of which cost a review round to establish:

- **`CapturedFrame` compares `Payload` by reference.** It is a `readonly record struct` holding a `byte[]`. Never assert two frames or two frame lists wholesale with `Assert.Equal`. Use `Http2WireAssert.EqualFrames`. This is documented in `tests/TlsClient.Tests/Wire/README.md`.
- **The byte-accounting equality in `Http2WireCaptureTests` is exact for structural reasons.** `RecordingStream` records only the bytes actually transferred, and `Http2WireServer.ReadFrameAsync` reads exactly 9 header bytes then exactly the declared payload, appending to `ClientFrames` only after both complete. Any buffered or speculative read introduced into those two files makes it flaky.
- **The client's SETTINGS ACK races the request writer.** It is emitted from the read loop (`Http2Connection.cs:971`) concurrently with request writes, so its position relative to HEADERS is nondeterministic today. Existing frame-sequence assertions filter it out. Task 7 changes this — see its note.
- **`Http2Connection.cs:1501` hardcodes `EnablePush => 0`.** The golden fixtures pin the resulting `(2, 0)` bytes, so the migration must keep emitting that byte while making the value expressible.
- **A known open finding:** `Http2WireCapture.RunAsync` correctly guarantees `responseReceived.TrySetResult()` in a `finally`, but no test detects a regression of it. The leak is in an unawaited background task, invisible to xUnit at that seam. Closing it needs the harness to expose the server task. Out of scope here; do not let it block you, and do not assume the test named `PropagatesClientRequestFailureInsteadOfHanging` proves anything about it.
- **`okhttp4-android-11` cannot complete a live TLS 1.2 handshake with tls.peet.ws** — the client offers `extended_master_secret`, the server does not reciprocate, and SharpTls aborts by policy. This is a SharpTls strictness divergence from real OkHttp, not a preset gap. It affects only `Http2LiveParityTests`, which is opt-in. Out of scope.

## Scope boundary

**In scope:** connection preface, SETTINGS, local receive-state derivation, SETTINGS ACK placement, stream identifier allocation, the entire HPACK send-side policy, preset migration, and the behavior-profile fields covering those.

**Not in scope, deferred to plan 3:** per-request frame scripts, per-request priority and ordering, pseudo-header composition and RFC 8441, `host` versus `:authority`, DATA framing, flow-control policy, shutdown and reset codes, padding. Where a spec section covers both halves, implement only the connection half and leave the request half at its current behavior.

**Not in scope, deferred to plan 4:** `TlsHttp2Capture.Import` and the inference rules.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `src/TlsClient/TlsHttp2Options.cs` | create | `TlsHttp2Options`, moved out of `TlsHttpVersionPolicy.cs`, in its new shape |
| `src/TlsClient/TlsHttp2Preface.cs` | create | `TlsHttp2PrefaceFrame` hierarchy and `TlsHttp2SettingValue` |
| `src/TlsClient/TlsHpackOptions.cs` | create | HPACK policy types |
| `src/TlsClient/TlsHttpVersionPolicy.cs` | modify | keeps only `TlsHttpVersionPolicy`, `TlsHttp2Priority`, `TlsHttp2PriorityFrame` |
| `src/TlsClient/HpackCodec.cs` | modify | encoder rewritten; decoder untouched |
| `src/TlsClient/Http2Connection.cs` | modify | preface writer, local-state derivation, stream ids, ACK placement, encoder wiring |
| `src/TlsClient/TlsPreset.cs` | modify | three presets rewritten against the new shape |
| `src/TlsClient/TlsHttpBehaviorProfile.cs` | modify | carries the new preface script and HPACK policy |
| `src/TlsClient/PublicAPI.Shipped.txt` | modify | rewritten baseline |
| `tests/TlsClient.Tests/Wire/RecordingStream.cs` | modify | records read segment lengths |
| `tests/TlsClient.Tests/Http2ConnectionLayerTests.cs` | create | new-axis wire assertions |

---

### Task 1: Record read segment lengths in the harness

`FlushAfter` on preface frames is only observable if the harness preserves write boundaries. `RecordingStream` currently concatenates into one `MemoryStream`, discarding them. Without this, the spec's own test line "`FlushAfter` boundaries produce the declared write batching" cannot be written.

**Files:**
- Modify: `tests/TlsClient.Tests/Wire/RecordingStream.cs`
- Test: `tests/TlsClient.Tests/Wire/RecordingStreamTests.cs`

**Interfaces:**
- Produces: `IReadOnlyList<int> ReadSegmentLengths { get; }` on `RecordingStream` — the length returned by each successful `ReadAsync` call, in order.

- [ ] **Step 1: Write the failing test**

Add to `RecordingStreamTests.cs`:

```csharp
    [Fact]
    public async Task RecordsTheLengthOfEachSuccessfulRead()
    {
        var source = new MemoryStream([1, 2, 3, 4, 5, 6]);
        await using var recording = new RecordingStream(source);

        var first = new byte[2];
        var second = new byte[4];
        await recording.ReadExactlyAsync(first);
        await recording.ReadExactlyAsync(second);

        Assert.Equal([2, 4], recording.ReadSegmentLengths);
    }

    [Fact]
    public async Task DoesNotRecordASegmentForAnEndOfStreamRead()
    {
        var source = new MemoryStream([1]);
        await using var recording = new RecordingStream(source);

        var buffer = new byte[4];
        await recording.ReadAsync(buffer);
        await recording.ReadAsync(buffer);

        Assert.Equal([1], recording.ReadSegmentLengths);
    }
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj -c Release --filter "FullyQualifiedName~RecordingStreamTests"
```

Expected: build failure, `'RecordingStream' does not contain a definition for 'ReadSegmentLengths'`.

- [ ] **Step 3: Implement**

Add a `List<int> _readSegments = []` field guarded by the existing `_sync` lock. In `ReadAsync`, inside the existing `if (read > 0)` block, append `read`. Expose:

```csharp
    public IReadOnlyList<int> ReadSegmentLengths
    {
        get
        {
            lock (_sync)
            {
                return _readSegments.ToArray();
            }
        }
    }
```

Return a copy, not the live list — `ClientFrames` returning a live list was flagged in the predecessor plan's review and this is the same hazard.

**Do not add speculative or buffered reads.** The byte-accounting equality in `Http2WireCaptureTests` depends on this class never reading more than requested.

- [ ] **Step 4: Run to verify it passes**

Same command. Expected: `Passed: 6` for that class.

- [ ] **Step 5: Run the full suite and commit**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet test TlsClient.slnx -c Release
git add tests/TlsClient.Tests/Wire/RecordingStream.cs tests/TlsClient.Tests/Wire/RecordingStreamTests.cs
git commit -m "test: record read segment lengths for write-batching assertions"
```

Expected: 152 passed.

---

### Task 2: Preface frame types and HPACK policy types

The typed data both halves of this plan are built from. Pure data, no behavior — nothing consumes it until Task 4.

**Both** the preface types and the HPACK policy types land here, even though the encoder is not rewritten until Task 8. Task 3 gives `TlsHttp2Options` an `Hpack` property, so `TlsHpackOptions` must already exist or Task 6 cannot restore the build.

**Files:**
- Create: `src/TlsClient/TlsHttp2Preface.cs`
- Create: `src/TlsClient/TlsHpackOptions.cs` — the types exactly as listed in Task 8 Step 1, which is the authoritative definition. Create them here; Task 8 changes only `HpackCodec.cs`.
- Modify: `src/TlsClient/PublicAPI.Unshipped.txt`

**Interfaces:**
- Produces: `TlsHttp2SettingValue`, `TlsHttp2PrefaceFrame`, `TlsHttp2SettingsFrame`, `TlsHttp2WindowUpdateFrame`, `TlsHttp2PrefacePriorityFrame`, `TlsHttp2RawFrame`, `TlsHttp2SettingsAckPlacement`, and all of `TlsHpackOptions` with its five enums.

- [ ] **Step 1: Write the file**

```csharp
namespace TlsClient;

/// <summary>One HTTP/2 SETTINGS entry, written verbatim in the order supplied.</summary>
/// <param name="Id">The setting identifier. Unknown and duplicate identifiers are permitted.</param>
/// <param name="Value">The setting value.</param>
public readonly record struct TlsHttp2SettingValue(ushort Id, uint Value);

/// <summary>A frame written as part of the HTTP/2 connection preface.</summary>
public abstract class TlsHttp2PrefaceFrame
{
    /// <summary>
    /// Gets or sets whether the transport is flushed after this frame. The default
    /// batches every preface frame into a single flush at the end.
    /// </summary>
    public bool FlushAfter { get; set; }
}

/// <summary>A SETTINGS frame. An empty list writes a zero-length payload.</summary>
public sealed class TlsHttp2SettingsFrame : TlsHttp2PrefaceFrame
{
    /// <summary>Gets or sets the settings, in exact wire order.</summary>
    public IReadOnlyList<TlsHttp2SettingValue> Settings { get; set; } = [];
}

/// <summary>
/// A connection-level WINDOW_UPDATE. It carries no stream identifier because no stream
/// exists at preface time; RFC 9113 section 5.1 makes any frame other than HEADERS or
/// PRIORITY on an idle stream a connection error.
/// </summary>
public sealed class TlsHttp2WindowUpdateFrame : TlsHttp2PrefaceFrame
{
    /// <summary>Gets or sets the window increment.</summary>
    public uint Increment { get; set; }
}

/// <summary>A PRIORITY frame emitted during the preface.</summary>
public sealed class TlsHttp2PrefacePriorityFrame : TlsHttp2PrefaceFrame
{
    /// <summary>Gets or sets the stream this priority applies to.</summary>
    public int StreamId { get; set; }

    /// <summary>Gets or sets the priority data.</summary>
    public TlsHttp2Priority Priority { get; set; } = new();
}

/// <summary>
/// An arbitrary frame, for reproducing GREASE and unknown frame types. Frame types the
/// connection owns are rejected at session construction.
/// </summary>
public sealed class TlsHttp2RawFrame : TlsHttp2PrefaceFrame
{
    /// <summary>Gets or sets the frame type octet.</summary>
    public byte Type { get; set; }

    /// <summary>Gets or sets the frame flags octet.</summary>
    public byte Flags { get; set; }

    /// <summary>Gets or sets the stream identifier.</summary>
    public int StreamId { get; set; }

    /// <summary>Gets or sets the frame payload.</summary>
    public byte[] Payload { get; set; } = [];
}

/// <summary>Where a SETTINGS acknowledgement is placed in the outbound frame sequence.</summary>
public enum TlsHttp2SettingsAckPlacement
{
    /// <summary>Its own write and flush, on receipt. The default.</summary>
    Standalone,

    /// <summary>Coalesced ahead of the next write batch this connection emits.</summary>
    BeforeNextBatch,

    /// <summary>Coalesced behind the next write batch this connection emits.</summary>
    AfterNextBatch,
}
```

**Naming note:** the preface priority frame is `TlsHttp2PrefacePriorityFrame`, not `TlsHttp2PriorityFrame`. The existing public `TlsHttp2PriorityFrame` in `TlsHttpVersionPolicy.cs` stays where it is and keeps its meaning for now — plan 3 revisits it. Reusing the name here would collide.

- [ ] **Step 2: Declare the new public API**

Add every new public member to `src/TlsClient/PublicAPI.Unshipped.txt`, one per line, in the analyzer's format. Build to discover the exact strings it wants:

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet build src/TlsClient/TlsClient.csproj -c Release
```

The `RS0016` errors name each missing entry verbatim. Copy them in.

- [ ] **Step 3: Verify the build is clean and commit**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet build TlsClient.slnx -c Release && dotnet test TlsClient.slnx -c Release
git add src/TlsClient/TlsHttp2Preface.cs src/TlsClient/PublicAPI.Unshipped.txt
git commit -m "feat: add HTTP/2 preface frame types"
```

Expected: build clean, 152 passed.

---

### Task 3: Reshape `TlsHttp2Options`

Move the class to its own file and replace the eight fixed setting properties with the preface script. Nothing consumes the new shape yet; `Http2Connection` is updated in Task 4. **This task will not compile on its own** — it deliberately breaks `Http2Connection`, `TlsPreset`, and `TlsHttpBehaviorProfile`. Tasks 3 through 6 form one compiling unit, so this task's commit is expected to leave the tree red.

If you are uncomfortable committing a non-building tree, do Tasks 3–6 as one task and one commit. That is an acceptable deviation; say so in your report.

**Files:**
- Create: `src/TlsClient/TlsHttp2Options.cs`
- Modify: `src/TlsClient/TlsHttpVersionPolicy.cs` — delete `TlsHttp2Setting` and `TlsHttp2Options`, keep `TlsHttpVersionPolicy`, `TlsHttp2Priority`, `TlsHttp2PriorityFrame`, and the existing `TlsHttp2Configuration` record adapted to the new fields.

**Interfaces:**
- Consumes: Task 2's types.
- Produces: the new `TlsHttp2Options` surface and `TlsHttp2Configuration` snapshot record.

- [ ] **Step 1: Write the new options class**

```csharp
namespace TlsClient;

/// <summary>Configures the HTTP/2 connection preface, header encoding, and stream identifiers.</summary>
public sealed class TlsHttp2Options
{
    /// <summary>
    /// Gets or sets the frames written after the connection preface magic, in exact order.
    /// An empty list sends the magic alone.
    /// </summary>
    public IReadOnlyList<TlsHttp2PrefaceFrame> Preface { get; set; } = [];

    /// <summary>Gets the HPACK send-side encoding policy.</summary>
    public TlsHpackOptions Hpack { get; } = new();

    /// <summary>Gets or sets the first client stream identifier. Must be odd.</summary>
    public int InitialStreamId { get; set; } = 1;

    /// <summary>Gets or sets the increment between client stream identifiers. Must be even.</summary>
    public int StreamIdStep { get; set; } = 2;

    /// <summary>Gets or sets where a SETTINGS acknowledgement sits in the outbound sequence.</summary>
    public TlsHttp2SettingsAckPlacement SettingsAckPlacement { get; set; }
        = TlsHttp2SettingsAckPlacement.Standalone;

    /// <summary>Gets or sets pseudo-headers in exact request wire order.</summary>
    public IReadOnlyList<string> PseudoHeaderOrder { get; set; } =
        [":method", ":authority", ":scheme", ":path"];

    /// <summary>Gets or sets optional RFC 7540 priority data embedded in HEADERS.</summary>
    public TlsHttp2Priority? HeaderPriority { get; set; }

    /// <summary>Gets or sets an optional RFC 9218 Priority Field Value for every request stream.</summary>
    public string? PriorityUpdate { get; set; }

    internal TlsHttp2Configuration Snapshot() { /* see Step 2 */ }
}
```

`HeaderTableSize`, `MaxConcurrentStreams`, `InitialWindowSize`, `MaxFrameSize`, `MaxHeaderListSize`, `ConnectionWindowIncrement`, `EnableConnectProtocol`, `DisableRfc7540Priorities`, `SettingsOrder`, and `InitialPriorityFrames` are all removed. So is the `TlsHttp2Setting` enum.

- [ ] **Step 2: Write `Snapshot()` validation**

Every rule below throws at session construction. Cite RFC 9113 section 6.5.2 in the message where it applies.

- Known setting identifiers are range-checked: `0x2` (ENABLE_PUSH) must be 0 or 1; `0x4` (INITIAL_WINDOW_SIZE) at most `2^31 - 1`; `0x5` (MAX_FRAME_SIZE) within `[16384, 16777215]`. Unknown identifiers accept any value.
- A `TlsHttp2SettingsFrame` holds at most **2730** entries, so its encoded payload cannot exceed the 16384-octet default maximum frame size that applies before the peer's SETTINGS is seen.
- `TlsHttp2RawFrame.Type` may not be `0x0` DATA, `0x1` HEADERS, `0x3` RST_STREAM, `0x5` PUSH_PROMISE, `0x7` GOAWAY, or `0x9` CONTINUATION. **`0x4` SETTINGS and `0x8` WINDOW_UPDATE are permitted** — Task 5 parses them for local state, which is why they are safe. `0x2` PRIORITY, `0x6` PING, `0x10` PRIORITY_UPDATE, and unknown types are permitted.
- The preface list holds at most 32 frames; each raw payload at most 16384 bytes.
- A preface priority frame's `StreamId` may not equal its `Priority.StreamDependency`.
- `InitialStreamId` odd, within `[1, 2^31 - 1]`. `StreamIdStep` even, within `[2, 65536]`.
- Every enum-typed option must be a defined value.

- [ ] **Step 3: Adapt `TlsHttp2Configuration`**

The internal snapshot record swaps its setting fields for the frozen preface list, the HPACK configuration, the stream identifier fields, and the ACK placement. Add the derived local-state fields Task 5 populates: `LocalHeaderTableSize`, `LocalInitialWindowSize`, `LocalMaxFrameSize`, `LocalMaxHeaderListSize`, `LocalEnablePush`, and `ConnectionReceiveWindow`.

Deriving them is Task 5's job; declare them here.

- [ ] **Step 4: Commit**

```bash
git add src/TlsClient/TlsHttp2Options.cs src/TlsClient/TlsHttpVersionPolicy.cs
git commit -m "feat!: replace fixed HTTP/2 settings with a declarative preface script"
```

The tree does not build after this commit. That is expected; Task 6 restores it.

---

### Task 4: Write the preface script

**Files:**
- Modify: `src/TlsClient/Http2Connection.cs` — `SendClientPrefaceAsync` at `:241-295`, `GetSettingValue` at `:1496-1510` deleted.

- [ ] **Step 1: Replace `SendClientPrefaceAsync`**

Write the magic, then each entry in order. Serialize per type:

- `TlsHttp2SettingsFrame` → type `0x4`, flags `0`, stream `0`, payload of 6 bytes per setting: 2-byte big-endian id, 4-byte big-endian value.
- `TlsHttp2WindowUpdateFrame` → type `0x8`, flags `0`, stream `0`, 4-byte big-endian increment.
- `TlsHttp2PrefacePriorityFrame` → type `0x2`, flags `0`, its stream, the 5-byte priority payload from the existing `BuildPriorityPayload`.
- `TlsHttp2RawFrame` → its own type, flags, stream, payload.

Flush after any frame whose `FlushAfter` is true, and once at the end regardless. Delete `GetSettingValue` entirely.

- [ ] **Step 2: Verify against the golden fixtures**

This is the checkpoint that matters. After Task 6 restores the build, `Http2WireGoldenTests` must pass unmodified. Until then you cannot run it — proceed to Task 5.

---

### Task 5: Derive local receive state from the script

The removed properties were not only wire values; the connection reads several to configure what it accepts. A client is bound by what it advertises, so local state must now come from the script.

**Files:**
- Modify: `src/TlsClient/Http2Connection.cs` — constructor around `:49-60`, `HandlePushPromiseAsync` at `:853`, `HandleHeadersAsync` at `:823-825`.

- [ ] **Step 1: Implement the derivation**

Scan every `TlsHttp2SettingsFrame` and every `TlsHttp2RawFrame` of type `0x4`, in script order, decoding raw payloads as 6-byte entries. For each known identifier, set the corresponding local field. Rules:

1. Known identifiers configure local receive state and are range-validated.
2. Unknown identifiers are written to the wire and otherwise ignored.
3. On duplicates, every occurrence is written; the **last** determines local state.
4. Identifiers absent from the script leave local state at the RFC 9113 default — `HEADER_TABLE_SIZE` 4096, `ENABLE_PUSH` 1, `INITIAL_WINDOW_SIZE` 65535, `MAX_FRAME_SIZE` 16384, `MAX_HEADER_LIST_SIZE` unbounded.
5. The connection receive window is seeded as `65535 + Σ increments` over every `TlsHttp2WindowUpdateFrame` and every `TlsHttp2RawFrame` of type `0x8` on stream 0. This replaces the removed `ConnectionWindowIncrement` that `:59-60` uses today.

Rule 4's `ENABLE_PUSH` default of 1 is a behavior change worth understanding: today `HandlePushPromiseAsync:853` checks `SettingsOrder.Contains(EnablePush)`. Under the new rules, a script that omits the setting means push is *enabled* by RFC default, so an inbound PUSH_PROMISE is legal and must be handled rather than treated as an error. All three presets emit `(2, 0)` except Android, which omits it — and the existing `TlsPresetWireTests` asserts Android rejects a push promise with `RST_STREAM(CANCEL)`. **Preserve that behavior:** the current code decodes the promised header block to keep HPACK state synchronized and then cancels the stream. Keep doing exactly that when push is enabled.

- [ ] **Step 2: Wire the derived values**

`_decoder` capacity from `LocalHeaderTableSize`, `_localMaximumFrameSize` from `LocalMaxFrameSize`, header-list bound from `LocalMaxHeaderListSize`, `_connectionReceiveWindow` from `ConnectionReceiveWindow`.

---

### Task 6: Stream identifiers, ACK placement, and restore the build

**Files:**
- Modify: `src/TlsClient/Http2Connection.cs` — `_nextStreamId` at `:30`, allocation at `:121`, SETTINGS ACK send at `:971`.
- Modify: `src/TlsClient/TlsPreset.cs`, `src/TlsClient/TlsHttpBehaviorProfile.cs` as needed to compile.

- [ ] **Step 1: Stream identifiers**

`_nextStreamId` seeds at `InitialStreamId - StreamIdStep` and `Interlocked.Add` uses `StreamIdStep`. Confirm `TrySendGoAwayAsync:1292` still reports a sensible last-stream-id before any stream opens; clamping at 0 as it does today is fine.

- [ ] **Step 2: ACK placement**

`Standalone` keeps current behavior — write and flush on receipt.

For the two coalescing values the unit is a **write batch**, not a frame. A header block is HEADERS plus zero or more CONTINUATION frames, and RFC 9113 sections 6.2 and 6.10 forbid interleaving anything between them. An acknowledgement is therefore never inserted inside a header block: `AfterNextBatch` places it after the final CONTINUATION, `BeforeNextBatch` before the HEADERS.

Deferral is bounded by the connection's own writes: a pending acknowledgement is flushed standalone when the connection must process a frame whose handling depends on the new settings taking effect, or when it goes idle with no queued work. **Do not bound it on inbound frames** — servers routinely send SETTINGS and WINDOW_UPDATE in one flight and the read loop processes them back to back before the client writes anything, which would make both coalescing values unreachable in practice.

Note this changes the ACK race described in the carry-notes. Under `Standalone` the race remains; under the coalescing values the position becomes deterministic. Existing frame-sequence assertions filter ACKs and stay valid either way.

- [ ] **Step 3: Restore the build**

`TlsPreset.cs` and `TlsHttpBehaviorProfile.cs` reference removed members. Get them compiling with the minimum change — Task 7 rewrites the presets properly and Task 13 does the behavior profile. A temporary empty preface in the presets is acceptable here **only if Task 7 immediately follows**.

- [ ] **Step 4: Build and commit**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet build TlsClient.slnx -c Release
```

Expected: clean. Tests will fail until Task 7 restores the presets — that is expected and is the only point in this plan where a red suite is acceptable. Report the failing count.

---

### Task 7: Migrate the three presets

The checkpoint for the whole connection-layer change. When this lands, `Http2WireGoldenTests` must pass **unmodified**.

**Files:**
- Modify: `src/TlsClient/TlsPreset.cs` — `ConfigureChrome`, `ConfigureFirefox`, `ConfigureAndroid` at `:142-189`.

- [ ] **Step 1: Rewrite the three preset configurations**

```csharp
    private static void ConfigureChrome(TlsHttp2Options http2)
    {
        http2.Preface =
        [
            new TlsHttp2SettingsFrame
            {
                Settings =
                [
                    new(0x1, 65_536),
                    new(0x2, 0),
                    new(0x4, 6_291_456),
                    new(0x6, 262_144),
                ],
            },
            new TlsHttp2WindowUpdateFrame { Increment = 15_663_105 },
        ];
        http2.PseudoHeaderOrder = [":method", ":authority", ":scheme", ":path"];
        http2.HeaderPriority = null;
        http2.PriorityUpdate = null;
    }
```

Firefox: settings `(0x1, 65536)`, `(0x2, 0)`, `(0x4, 131072)`, `(0x5, 16384)`; increment `12_517_377`; pseudo order `:method, :path, :authority, :scheme`; `HeaderPriority` weight 41 on dependency 0, non-exclusive.

Android: settings `(0x4, 16_777_216)`; increment `16_711_681`; pseudo order `:method, :path, :authority, :scheme`; `HeaderPriority` weight 1 on dependency 0, non-exclusive.

- [ ] **Step 2: Run the golden fixtures**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj -c Release --filter "FullyQualifiedName~Http2WireGoldenTests"
```

Expected: 6 passed — 3 preface-byte cases and 3 frame-sequence cases.

**If a preface byte differs, the migration is wrong.** Read the hex dump. Do not touch the fixture. The expected bytes were derived from arithmetic and independently verified; they are the specification here, not a record of past behavior.

- [ ] **Step 3: Run the full suite and commit**

Expected: 152 passed. `TlsPresetWireTests` must also pass unmodified, including its Android push-rejection assertion, which exercises Task 5's `ENABLE_PUSH` default rule.

```bash
git add src/TlsClient/TlsPreset.cs
git commit -m "feat: migrate presets to the declarative preface script"
```

---

### Task 8: HPACK representation policy

The encoder rewrite. This is where the missing `0x00` representation lands.

**Files:**
- Modify: `src/TlsClient/HpackCodec.cs` — `HpackEncoder` at `:76-236`. **The decoder at `:284` onward is untouched.**

**Interfaces:**
- Consumes: `TlsHpackOptions` and its enums, created in Task 2 from the definition below.

- [ ] **Step 1: The policy types (created in Task 2 — this is their authoritative definition)**

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
        = new Dictionary<string, TlsHpackRepresentation>(StringComparer.Ordinal)
        {
            ["cookie"] = TlsHpackRepresentation.LiteralNeverIndexed,
            ["authorization"] = TlsHpackRepresentation.LiteralNeverIndexed,
        };

    public TlsHpackHuffman Huffman { get; set; } = TlsHpackHuffman.WhenShorter;
    public IDictionary<string, TlsHpackHuffman> PerHeaderHuffman { get; }
        = new Dictionary<string, TlsHpackHuffman>(StringComparer.Ordinal);

    public TlsHpackNameIndex NameIndex { get; set; } = TlsHpackNameIndex.LowestStatic;
    public IDictionary<string, int> PerHeaderNameIndex { get; }
        = new Dictionary<string, int>(StringComparer.Ordinal);

    public TlsHpackMultiValue MultiValue { get; set; } = TlsHpackMultiValue.SeparateFields;
    public IDictionary<string, TlsHpackMultiValue> PerHeaderMultiValue { get; }
        = new Dictionary<string, TlsHpackMultiValue>(StringComparer.Ordinal);
    public string MultiValueJoinSeparator { get; set; } = ", ";

    public TlsHpackTableSizeUpdate TableSizeUpdate { get; set; }
        = TlsHpackTableSizeUpdate.OnPeerSettingsChange;
    public IReadOnlyList<uint> TableSizeUpdateValues { get; set; } = [];

    public bool CrumbleCookies { get; set; }
    public string CookieCrumbSeparator { get; set; } = "; ";
}
```

The `PerHeader` defaults for `cookie` and `authorization` relocate the hardcode at `Http2Connection.cs:644` — delete the `sensitive` computation there and let the policy carry it.

- [ ] **Step 2: Rewrite `HpackEncoder.Encode`**

Per field, in order:

1. Resolve one representation: `PerHeader[name]` if present, else `DefaultRepresentation`.
2. If it resolves to `Indexed`, emit `0x80` with the index when an exact name/value match exists in the static or dynamic table; otherwise emit `IndexedFallback`.
3. If it resolves to a literal form, emit that form and **never** an indexed reference, even when an exact match exists — `0x40` incremental indexing, `0x00` literal without indexing, `0x10` never indexed — using a name index when the name alone is found.
4. Select the name index per `PerHeaderNameIndex[name]` if present, else `NameIndex`. `LowestStatic` reproduces today's `FindName`.
5. Insert into the dynamic table **only** for `LiteralIncrementalIndexing`, and only when `UseDynamicTable` is true. RFC 7541 requires the other two literal forms not to update the table.
6. Apply Huffman per `PerHeaderHuffman[name]` if present, else `Huffman`. `WhenShorter` encodes only when strictly shorter, matching `:247`; `WhenNotLonger` also encodes on a tie.

- [ ] **Step 3: The one documented byte-level divergence**

Defaults reproduce today's output byte for byte, **except** for empty-valued `cookie` and `authorization`. The static table stores `("authorization", "")` at index 23 and `("cookie", "")` at index 32 (`HpackCodec.cs:34,43`) — empty string values, not absent — and `FindExact` compares values, so `Cookie: ""` matches index 32 and today emits the single byte `0xA0`. Under rule 3 it becomes a three-byte never-indexed literal.

This is accepted, not a bug: a persona that declares those fields never-indexed should not emit an indexed reference for an empty one. **Write a test pinning it** so it stays deliberate.

- [ ] **Step 4: Tests, then commit**

One test per representation asserting the emitted prefix byte, including `0x00`, which no current test can produce. Plus the empty-cookie divergence, both Huffman tie modes, and `LowestStatic` versus `HighestStatic` on `:method: PUT` — index 2 versus 3.

Full suite must stay green, and the golden preface fixtures must be untouched by this task since it changes only header encoding.

---

### Task 9: Dynamic table modes and size updates

**Files:**
- Modify: `src/TlsClient/HpackCodec.cs`

- [ ] **Step 1: Static-table-only mode**

`UseDynamicTable = false` yields an encoder that never inserts and therefore never evicts. Combined with `DefaultRepresentation = Indexed` and `IndexedFallback = LiteralWithoutIndexing`, this produces the canonical shape of a client that reads the static table but does not populate its own: `0x82` for `:method: GET`, `0x00`-prefixed literals elsewhere.

- [ ] **Step 2: Table size updates as a list**

`TableSizeUpdateValues` is a list because RFC 7541 section 4.2 permits consecutive updates, and the "size 0 then size N" pair — evict everything, then resize — is a real encoder signature a single value cannot express. An empty list means use the peer's advertised value. Every value is applied to the encoder's own table as it is emitted, so the declared size and eviction behavior stay consistent.

Validate that no value exceeds the peer's `SETTINGS_HEADER_TABLE_SIZE` when known, or the encoder's configured maximum otherwise. RFC 7541 section 6.3 makes a larger value a COMPRESSION_ERROR at the peer.

- [ ] **Step 3: Tests and commit**

`UseDynamicTable = false` produces no insertions across a multi-request connection. Consecutive updates emit in order, including the zero-then-N pair. Each `TableSizeUpdate` policy value emits and suppresses correctly.

---

### Task 10: Multi-value headers and cookie crumbling

**Files:**
- Modify: `src/TlsClient/Http2Connection.cs` — `BuildRequestHeaders` at `:601-663`, specifically the value loop at `:645-648`.

- [ ] **Step 1: Multi-value policy**

A `HeaderEntry` holding several values is emitted as one field per value today. `MultiValue` and `PerHeaderMultiValue` select that or a single field with values joined by `MultiValueJoinSeparator`. This is the mirror of cookie crumbling — both directions of one axis, and stacks differ on both.

- [ ] **Step 2: Cookie crumbling**

When `CrumbleCookies` is true, a single `cookie` header whose value contains the separator is split into one field per crumb, in order, each encoded independently under the same policy. Permitted by RFC 9113 section 8.2.3. HTTP/2 only — the HTTP/1.1 writer is untouched.

Clients that crumble generally do so in order to index individual crumbs, so a crumbling persona will usually also change `PerHeader["cookie"]` away from its never-indexed default. Note that in the XML docs.

- [ ] **Step 3: Tests and commit**

Crumbling produces the expected field count and the server reassembles an equivalent cookie value. Joining produces one field with the expected separator.

---

### Task 11: Connection-layer wire assertions

The regression net for everything this plan added. Without it, plan 3 inherits the same unfalsifiable position this plan started from.

**Files:**
- Create: `tests/TlsClient.Tests/Http2ConnectionLayerTests.cs`

- [ ] **Step 1: Write the tests**

Using `Http2WireCapture` and `Http2WireAssert` from the harness:

- An unknown SETTINGS identifier and a duplicated identifier both appear on the wire in declared order, and the duplicate's **last** value governs local state.
- A GREASE `TlsHttp2RawFrame` appears at its declared position in the preface.
- A raw SETTINGS frame and a raw WINDOW_UPDATE both feed local receive state, proven by the connection accepting traffic it would otherwise reject.
- An empty `Settings` list writes a zero-length SETTINGS frame.
- An empty `Preface` sends the magic alone.
- `InitialStreamId` and `StreamIdStep` produce the declared identifier sequence across three requests.
- `FlushAfter` boundaries produce the declared write batching, asserted through `RecordingStream.ReadSegmentLengths`.
- Each `TlsHttp2SettingsAckPlacement` value puts the ACK where it claims, and never inside a header block — construct a header block large enough to require CONTINUATION and assert the ACK lands after the final one under `AfterNextBatch`.
- Validation: settings range and count rejection, raw frame type rejection, non-odd `InitialStreamId`, even-step rejection, `IndexedFallback = Indexed` rejection.

- [ ] **Step 2: Commit**

---

### Task 12: HPACK fuzz target

**Files:**
- Modify: `tools/TlsClient.Fuzz/Program.cs` — the `"hpack"` target at `:91-92` is decoder-only today.

- [ ] **Step 1: Add an encode-policy round-trip**

Encode a header list under a randomized policy, decode it, assert the header list is recovered. The policy space is large enough that a fixed set of cases would miss combinations; randomize representation, Huffman mode, name index, and dynamic-table use.

- [ ] **Step 2: Commit**

---

### Task 13: Behavior profile carries the new shape

**Files:**
- Modify: `src/TlsClient/TlsHttpBehaviorProfile.cs`

- [ ] **Step 1: Extend capture, export, import, apply**

Carry the preface script, HPACK policy, stream identifier fields, and ACK placement alongside the header order and pseudo-header order it already holds. Raw frame payloads as base64.

Keep the import path's existing character: strict, case-sensitive, bounded to 256 KiB by default, rejecting unknown and duplicate properties, and running the result through the same validation used at session construction.

Plan 3 extends this again for request-lifecycle fields. Do not build for that now.

- [ ] **Step 2: Tests and commit**

Round-trip each preset's options through export and import and assert the resulting session emits identical preface bytes.

---

### Task 14: Rebase the public API baseline

**Files:**
- Modify: `src/TlsClient/PublicAPI.Shipped.txt`, `src/TlsClient/PublicAPI.Unshipped.txt`

- [ ] **Step 1: Fold unshipped into shipped**

This is a private fork with no compatibility obligation, so the baseline is rewritten rather than versioned. Move every entry from `Unshipped` into `Shipped` in sorted order, and delete the entries for every removed member.

- [ ] **Step 2: Verify and commit**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet build TlsClient.slnx -c Release && dotnet test TlsClient.slnx -c Release
```

Expected: clean build, no `RS0016` or `RS0017`, full suite green.

---

### Task 15: Update the preset documentation

**Files:**
- Modify: `docs/PRESETS.md`

- [ ] **Step 1: Restate the three presets in the new shape**

The profile matrix table's SETTINGS column now describes an ordered list of `(id, value)` pairs rather than an enum sequence. Keep the bogdanfinn commit citations — they are the provenance for these values.

Add a short section explaining that settings are now raw identifiers, so unknown and GREASE values are expressible.

- [ ] **Step 2: Commit**

---

## Self-review checklist for the executor

Before declaring the plan complete:

- `Http2WireGoldenTests` passes **unmodified**. If it was touched, the migration is wrong.
- `TlsPresetWireTests` passes unmodified, including the Android push-rejection assertion.
- No `TODO`, no commented-out code, no obsolete-marked members.
- `dotnet build` produces no `RS0016`/`RS0017` and no analyzer warnings.
- The empty-cookie divergence has a test pinning it deliberately.

## What this plan does not close

Recorded so the result is not overclaimed:

- Request lifecycle and data path — plan 3.
- Capture import — plan 4.
- The harness cannot detect a regression of the `RunAsync` server-task leak; see the carry-notes.
- HPACK dynamic table behavior over a long-lived connection is still only as pinned as the tests exercise.
