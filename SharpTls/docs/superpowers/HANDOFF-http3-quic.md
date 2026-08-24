# Handoff: HTTP/3 and QUIC in SharpTls

---

# START HERE — session handoff, 2026-08-20 (second session of the day)

**Branch `feat/quic-socks5-datagram-transport`. 323 commits. Nothing pushed.**
**Gate: `dotnet test --filter "FullyQualifiedName~Quic"` → 2236 passed, 0 failed, 5 skipped.** (at `1a17be7`)

Use that filter, never the full suite — see §8 for what it masks.

**THE GATE IS GREEN AND THE LIVE ENDPOINT REJECTS US.** Read *"OPEN AND URGENT"* below before
anything else. All five skips are `[InteropFact]`s, so a green gate says nothing about the wire.

**MEASURE THE GATE YOURSELF AT PRISTINE HEAD.** **Thirteen agents in a row** inherited a figure from
a brief and every one was wrong: concurrent commits move it, and another agent's uncommitted work in
a shared tree inflates it. HEAD moved mid-task under three of them. The number above is true at
`bea2654` and nowhere else. **Measure in a private worktree** - the shared tree frequently does not
compile while another agent is mid-edit.

**The field is `perk_text`, not `perk`.** Only the hashes carry the documented names; querying `perk`
returns nothing. A client capture is half-wrong about its own subject — its heading says `perk`,
its line 98 says `perk_text`. Every use of the bare word `perk` below means `perk_text`.

## Subsystem C is complete through C12. The instrument now exists.

`TlsQuicHttp3FingerprintReadout` renders the `perk` string's first two segments from bytes we
actually emitted, one row per field. **25 rows: 15 `match`, 2 `MISMATCH`, 8
`not-yet-known-from-the-capture`.** Both MISMATCHes are the rows the plan reserves for subsystem B
(transport-parameter wire order, CID length pair) and are labelled `[subsystem B]` rather than
scored as C's failures. That row list is what B works from.

## The live measurement, and the thing it got wrong at first

A real GET through `TlsQuicHttp3Connection` against `fp.impersonate.pro/api/http3` at `eb7d668`
returned HTTP/200 and this fingerprint:

    ours   1:0;6:262144;7:0 | m,a,s,p | 15:AUTO;14:2;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103 | 0,8
    client  1:65536;6:262144;7:100;51:1;GREASE | m,a,s,p | 12584:0x4f524947;GREASE;32:65536;9:103;8:100;7:6291456;5:6291456;15:AUTO;17:1@GREASE,1;1:30000;6:6291456;4:15728640;12583:AUTO;3:1472 | 0,8

**Segment 1 read as 1-of-5 and that was a misreading.** `TlsQuicHttp3Spec._settings` defaults to
`CaptureSettings` — all five of that client's pairs, `51:1` and the GREASE identifier included — so the
DEFAULT spec emits an exact segment 1. The live run deliberately narrowed it to QPACK `0`/`0`,
because capacity 0 is what makes the static-only C5–C8 decoder correct rather than lucky. **A test's
chosen spec is not the library's capability.** Reading one as the other is the trap here, and the
readout exists so nobody has to infer it from a live run again.

- **Segment 2, pseudo-header order `m,a,s,p`: exact match**, confirmed live against a server we do
  not control. C9's fingerprint argument holds.
- **Segment 4, CID pair `0,8`: exact match live.** The readout's own row shows `5,8` because its
  harness uses a 5-byte source CID deliberately, per task 11's reason — a harness artifact, not a
  mismatch.
- **Segment 3 is subsystem B's.** Every shared value already matches (4, 5, 6, 7, 8, 9, 15). What is
  missing is seven parameters — `google_connection_options`, a GREASE parameter,
  `max_datagram_frame_size`, `version_information`, `max_idle_timeout`, `initial_rtt`,
  `max_udp_payload_size` — plus one we send that that client does not, `active_connection_id_limit`, and
  the wire order itself. `initial_rtt` **must be randomised per connection**; a pinned value is
  itself a fingerprint.

C13 did record it: `reference-captures/2026-08-20-sharptls-c13-live-http3.md`, and the live wire
settled segment 4 as `0,8` — matching that client exactly, confirming the readout row was a harness
artifact.

## What landed this session

| Work | Commit |
| --- | --- |
| C13 — the live run, 0 failures in 20 attempts | `44e4e1e` |
| B — the fingerprint spec layer, SCOPED (12 tasks) | `3b1f7cc` |
| Both "small and owed" items in C | `cf96c89` |
| A4 task 10 — MsQuic loopback gate | `776bc07` |
| Flow control, both spike findings | `7ee8536`, `21b025b`, `38c9580` |
| C9 — HEADERS and the request, four dead knobs wired | `9fbfcdc` |
| C10 — DATA and the response | `239ea25` |
| C10b — H3_MESSAGE_ERROR, §4.2 field ban, §4.1.2 | `ac3a2e5` |
| C10c — zero-DATA Content-Length, the fifth escaping response | `15a9b0b` |
| C11 — the HTTP/3 connection; **the spike is deleted** | `eb7d668` |
| C12 — the fingerprint readout | `ac43deb` |
| A4 — 1-RTT CONNECTION_CLOSE, both forms | `9410755` |
| Captures: RFC 9110 §7.6.1, §6.4.1, §8.6; RFC 9114 §4.4 | `8cb320f`, `b3bbd24` |

Gate 1510 → 1954.

## Two defects that were real, and how they were found

**Flow control could not have worked, and no handshake test could see it.** Advertising no limits
left every peer limit at 0. `TlsQuicStreamSet`'s independent 1 MiB / 64-stream constants are now
**deleted**, the enforced bound is the advertised bound, a connection-level bound against
`initial_max_data` exists at all, and MAX_DATA / MAX_STREAM_DATA ride the 1-RTT packet 14c builds.
A client capture bounds all six values; the spike's hard-coded `initial_max_streams_bidi = 0` was
wrong — that client sends 100.

**No CONNECTION_CLOSE of either form could leave after handshake confirmation.** `BuildCloseDatagram`
walked `[Handshake, Initial]`, both discarded by RFC 9001 §4.9 by then, so it wrote nothing.
Fixed in `9410755`. **A4's Finding 1 is now fully closed** — the close path was never on that list,
it was a consequence nobody re-checked after 14b.

## Method notes earned this session — these cost real hours

- **The doc lost to the code seven consecutive times.** C11's comment claimed a 1-RTT close needed a
  short header the packet builder could not write; tasks 14b/14c had already added it and the real
  gap was one line. **When a comment says a later task owns something, go read the code.**
- **Every agent that inherited a gate figure was wrong — five in a row.** Concurrent commits move it,
  and uncommitted work in a shared tree inflates it. **Measure your own baseline at pristine HEAD.**
- **`taskkill /F /IM testhost.exe` is actively harmful under concurrency.** It matches every agent's
  test host. Runs were aborted at 178 and 171 cases in both directions. **Sweep in an isolated copy
  of the tree instead**, and keep only the case-count floor check.
- **An aborted sweep run prints an ordinary `Failed: 0, Passed: <m>` line** — it reads as a survivor
  that never ran. A `Total` floor (~1700 here) caught 12 of them in one task. Orphaned test hosts
  also make `dotnet test` silently run a **stale binary**; C11 discarded two entire sweeps to this.
- **`Copy-Item` preserves timestamps, so MSBuild skips the compile.** And a C# optional-parameter
  default is baked into the *calling* assembly, so a default-value mutation is invisible without
  `--no-incremental`.
- **Tests pass by coincidence more often than they look.** One witness truncated the only DATA frame
  so both orderings agreed; one parsed `" 17"` and `"+17"` to the same number because the fixture
  body was 17 bytes; one all-four-null totality test was satisfied by whichever check fired first,
  leaving three dereferences unmeasured. All three were found only by mutation.
- **A done-when clause is a floor, not a ceiling.** A mutant that hard-coded the capture's
  pseudo-header order *passed* C9's stated done-when; only an all-permutations test killed it.
- **A witness is sometimes impossible, and saying so beats writing a fake one.** C10c's 1xx row is
  unreachable because interim responses never become the final status. It says so at the row.

## SUBSYSTEM A3 IS UNDER WAY - loss recovery and congestion control, 8 of 15 tasks

**Why it exists now:** TlsClient's own HTTP/3 entry gate
(`TlsClient-main/docs/HTTP3-EVALUATION.md`, condition 2) requires ACK/loss/PTO and congestion
control. Everything else in that condition was built; A3 is what failed it. The user decided on
2026-08-21 to build A3 before HTTP/3 ships in TlsClient, rather than amend the gate.

| Task | State | Commit |
| --- | --- | --- |
| A3-0 RFC 9002 extracts (6 files, all byte-exact) | done | `2304698` |
| A3-1 the impairing datagram transport | done | `8497f60` |
| A3-2 the recovery spec seam, 14 knobs | done | `0e4d07c` |
| A3-3 retain sent packets, bytes in flight | done | `744b0ce` |
| A3-4 RTT estimation | done | `83895b6` |
| A3-5 the timer weave | done | `1a17be7` |
| A3-6 loss detection - A3-9 NewReno | in flight | - |
| A3-7 PTO - A3-8 retransmission - A3-10 - A3-11 - A3-12 - A3-13 - A3-14 | not started | - |

### THE HEADLINE: RFC 9002's pseudocode is NOT line-by-line transcribable

A3-0 verified that it was. **Four independent counter-examples have since been found, and every one
would have shipped a defect.** Treat "transcribable" as disproved and read prose against pseudocode
every time.

1. **§5.3's prose contradicts Appendix A.7 in the same document** (found by A3-4). §5.3 updates
   `smoothed_rtt` first and measures variation against the *updated* value; A.7 measures variation
   first, against the value from *before* the sample. They differ by exactly 7/8, via
   `|(7s+a)/8 - a| = 7/8 * |s-a|`. **Following the prose converges `rttvar` 12.5% low forever**, so
   §6.2.1's PTO arms early and the client retransmits spuriously on every connection - measurably
   distinct traffic, on a stack whose whole purpose is not standing out. **A.7 followed**; the test
   asserts both candidate numbers (137.5 ms vs 125 ms), so nobody can "fix" it back silently.
2. **A.8 arms `infinite`** where §6.2.1's prose is a MUST NOT (found by A3-5). In C# the pseudocode
   also throws - `MaxValue - now` is no valid delay. **Prose followed**, pinned against both `null`
   and `DateTimeOffset.MaxValue`.
3. **§6.2.1's `kGranularity` floor is absent from A.8** - redundant in the RFC, **not** redundant
   here, because A3-2 added a `PtoBackoff.Maximum` ceiling the RFC lacks.
4. **`2 ^ pto_count` is unbounded in A.9.** At 2^31 it wraps negative and **the backoff inverts into
   a speed-up** - a stack that answers sustained loss by transmitting faster. Capped; all period
   arithmetic saturates.

**A3-0 also found seven functions called and never defined**, of which two are load-bearing:
`InPersistentCongestion` (B.8) and `IsAppOrFlowControlLimited` (B.5). **§7.7 pacing and §7.6.1's
persistent-congestion duration have no pseudocode at all.**

### Findings that outrank their tasks

- **Retention was a parameter nobody passed.** `TlsQuicDatagramBuilder` had taken
  `ICollection<TlsQuicSentPacket>?` all along; the connection omitted it. And the plan named **two**
  call sites when there are **three** - it missed `BuildInitialFlight:1948`, *the opening flight*,
  the one most exposed to loss. Wiring only the named two would have left it untracked while every
  Initial-space assertion passed against an empty list.
- **The timer weave is an addition, not a split** - measured, not argued. Routing both existing
  deadlines through one earliest-of table cost **+11/-6 lines, zero tests touched**.
  `ReceiveWithinDeadlineAsync` has raced the receive against a `CancellationTokenSource` on the
  injected `TimeProvider` since A4-minimal; A3-5 adds an *entry*, not a timer.
- **Zero of six transports could impair.** The parent scoping claimed A3 needed no network because a
  test transport could simulate loss. `ScriptedDatagramTransport` could not fabricate Handshake or
  1-RTT packets at all. That is why A3-1 came first.
- **Nothing deduplicates a received packet number.** A duplicated 1-RTT packet is opened and its ACK
  processed twice. Pinned by A3-1, handled by A3-4's §5.1 "newly acknowledged" gate.

### STILL OPEN: two answers to one question about `initial_rtt`

`TlsQuicConnectionSpec.InitialRttRange` **defaults to `null`**. `DeclaredInitialRttRange` (100-300 ms)
lives on `TlsQuicTransportParameterSpec` as the *transport parameter entry's* fallback. So an
unconfigured client **advertises 100-300 ms** and would **start from `kInitialRtt`'s 333 ms**.
`DeclaredInitialRttRange`'s maximum sits *below* 333 ms, which is what makes the divergence
observable. **Task A3-7 owns resolving it**; A3-4 deliberately refused to deepen it by drawing a
third value.

### Method notes A3 paid for - all six are real failures from one day

- **A correct new feature can silently destroy an existing test's witness.** A3-5's PTO fires at ~1s;
  `APeerThatGoesSilentIsBoundedByTheIdleTimeoutToo` asserts only "under ten seconds", so the new
  timer **masked** the entry ledger row 69 witnessed. Behaviour was never wrong; the witness was gone.
  Found only because the sweep's known-bad control survived. **Check your calibration control.**
- **A harness's self-check can be the unchecked part.** One calibration unpacked mismatched tuples,
  mutated **nothing**, and reported SURVIVED against pristine source - certifying a broken harness as
  proven.
- **Assign `KILLED-BY-COMPILER` structurally from the build exit code**, never by parsing a log:
  `(KILLED|SURVIVED|KILLED-BY-COMPILER)` lets `KILLED` shadow the longer token and publishes
  compiler-kills as genuine kills.
- **A pipeline's exit code is the last command's.** One case floor aborted and returned 0 because
  `sed` was last. Read the output, not the status.
- **Do not pipe a sweep through `tail`** - one lost the per-row witness names. A verdict with no named
  witness is half a ledger row.
- **A detached harness outlives the agent turn that launched it**, and **absence of a running process
  is not completion**. Two sweeps mutating one file produced 14 rows of `KILLED-BY-COMPILER`; a later
  message claiming a sweep had finished would have produced 46 invented witnesses. Match processes by
  **command line**, capture the script name, and never `taskkill /F /IM testhost.exe` - three agents'
  hosts have been live at once.

### Debt recorded, not fixed

- **A4's 1000-code-line cap on `TlsQuicConnection.cs` is breached** - 962 at A4, 1133 at A3-3 (passed
  silently), 1306 now. A4's plan says the split is its own task.
- `TlsQuicPacketReceiver.cs` still holds a private `SpaceOf` copy; the tracker's is now `internal` and
  `TlsQuicConnection.cs`'s copy is collapsed.

---

## OPEN AND URGENT: the shipped defaults are rejected by the live endpoint

**C14 (`e8b4976`), C15 (`bd1ed29`) and C16 (`bea2654`) all landed. Subsystem C's QPACK arm is
complete offline.** The gate reads 2081 / 0 / 5 and every one of those 5 skips is an
`[InteropFact]` - which is exactly how this stayed invisible.

Run with `SHARPTLS_RUN_INTEROP=1` at `bea2654`:

- `AnHttp3RequestReturnsTheLiveFingerprintFromBothEndpoints` - **FAILS 5/5.** The peer closes with
  **`0x109`, H3_SETTINGS_ERROR**. `discarded=0`, `idle_timed_out=False`, `initial_datagrams=1`, so
  it is **not** loss and **not** a flake.
- `AFingerprintChangeIsVisibleEndToEndThroughTheProfileFactory` - **PASSES.**

**What changed:** C16 removed that test's hand-narrowing of QPACK SETTINGS, so it now sends
`CaptureSettings` (`1:65536;6:262144;7:100;51:1;GREASE`) instead of `1:0;6:262144;7:0`.

**The discriminating difference between the two tests is their QUIC TRANSPORT PARAMETERS**, not
their SETTINGS. The passing one drives `TlsQuicClientHelloProfileFactory`, defaulting to
`RfcMinimumParameters`, which **includes `max_datagram_frame_size` (32)**. The failing one uses a
hand-typed `BaselineParameters` (`QuicPublicEndpointInteropTests.cs` ~`:895-905`) carrying only
`initial_source_connection_id`, `active_connection_id_limit` and the six flow-control values -
**no `max_datagram_frame_size`**. So the failing arm advertises `SETTINGS_H3_DATAGRAM = 1` while
advertising no QUIC datagram support.

**THAT IS A LEAD, NOT A DIAGNOSIS.** `rfc9297-section2.1-http3-datagrams.txt` §2.1.1 says only that
the value MUST be 0 or 1 and that a value which is neither earns H3_SETTINGS_ERROR - and we send 1,
which is legal. **The linkage rule was asserted and could not be found in the captured text.** Other
candidates not yet ruled out: the GREASE setting identifier `126585778853`, `1:65536` itself,
`7:100`, a duplicate identifier, or SETTINGS frame encoding.

**Two lessons this cost, both already paid for elsewhere in this file:**

1. **C16 reported "the shipped defaults are honest" and it was verified OFFLINE.** Offline tests fix
   both sides of an interaction, so an inconsistency BETWEEN the halves cannot surface. **A claim
   about the wire needs the wire.**
2. **This is the third time a test's configuration hid the library's real behaviour.** Segment 1
   "matched" because tests narrowed SETTINGS; "we send 8 transport parameters" described a fixture;
   and now removing one narrowing exposed that the same test's *other* half had never been
   consistent with the defaults. See [A test's config is not the library's capability].

**The fix level matters more than the fix.** Adding one parameter to one test makes it green and
leaves every caller free to compose the same inconsistency. Per the user's standing directive the
library should say so **locally and loudly** rather than as a remote `0x109`, while still permitting
a deliberately inconsistent fingerprint if a real client sends one.

**Also broken, smaller:** the live recording prints `QPACK arm in force: DEFAULT (...)` and then
`the DEFAULT arm is ... and it is NOT what ran here.` Those contradict.

## The QPACK arm - C14, C15 and C16, all landed

Segment 1 is the only `perk` segment that does not match, and **it already emits an exact match** -
`TlsQuicHttp3Spec.CaptureSettings` carries all five of that client's pairs by default. It is not *usable*
live because the capture's `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 65536` lets the peer's encoder use
the dynamic table, and the C5-C8 decoder is static-only. Every live run so far narrowed SETTINGS to
QPACK `0`/`0` for exactly that reason.

- **C14 (`e8b4976`)** - the dynamic table the peer's encoder drives, decoder side only. Appendix
  B.2-B.5 all reproduce including table sizes and eviction points. RFC 9204 **§4.3 and §4.4 extracted**
  (neither was captured; only cross-referenced).
- **C15** - wire it into the decoder, plus §4.4's decoder-stream instructions.
- **C16** - blocked decoding, then the SETTINGS default stops being narrowed.

**C14's finding is the one to carry forward: the RFC's own examples cannot witness their own blind
spot.** Three prefix-width mutants survived the *entire* Appendix B-anchored walk, because every
literal the RFC publishes sits below the narrower mask - `10 & 0x1F == 10 & 0x0F`,
`15 & 0x7F == 15 & 0x3F`, `2 & 0x1F == 2 & 0x3F`. **Anchoring tests to published vectors is necessary
and not sufficient.** Straddling vectors killed all three. Two more from the same round: the
case-count floor genuinely fired, on a worktree missing `tools/` that compiled nothing - the exact
aborted run that reads as a clean sweep - and one mutation was *itself* equivalent (it reassigned a
field rather than the bytes) and had to be restated before it died.

**A correction that stuck:** the permanent rule is zero allocation on the **REJECTING** path, not the
accepting one. Accepting must allocate; an entry has to be stored.

## B12 needs the packet capture for all THREE values - the shortcut was tried and failed

`docs/superpowers/specs/2026-08-20-b12-capture-request.md` has the procedure. It once said uQUIC's
`ChromeRandomInitialRTT()` would settle `initial_rtt` without a capture. **Tried at `5c0039c`; it does
not.**

uQUIC draws uniformly over **[1000, 20000) microseconds**; a client capture's **192859 is outside
that by 9.6x**. Three independent readings: 192859 > 20000 outright; the function emits a **2-byte
varint** whose maximum is 16383, so **that client's wire encoding is not this encoding** whatever the
values; and uQUIC's own `maxRTT` exceeds 2-byte varint capacity, so its draws above 16383 silently
lose their overflow bits - it is not an authority even on its own terms.

**Two real draws now exist, 25x apart** - uQUIC's doc records 7740 us, a client capture 192859 us,
both plausible *measured* RTTs. The simplest reading consistent with both is that **Chromium reports
a path-derived estimate rather than a random draw**, in which case a range is the wrong model and the
knob's shape changes. Inference from two points, flagged as such.

**So the capture must record the RTT to the origin per connection**, or that correlation stays
uncheckable.

## What is next

- **C13 is DONE** (`44e4e1e`), and its number is the one that matters: **0 failures in 20 attempts**,
  across two runs of 5 attempts × 2 hosts, every one HTTP 200 with a complete body and
  `discarded=0`. Those attempts span three unidirectional stream headers, SETTINGS, HEADERS and a
  4,955-byte response — far more packets than A4 task 13's handshake. **With A4's 0/10 that is 30
  attempts and zero loss-induced failures.** One path on one day, and the capture says so, but it is
  the evidence for keeping A3 deferred. Capture:
  `reference-captures/2026-08-20-sharptls-c13-live-http3.md`.
  C12's readout survived contact with the wire: **no row disagrees in a defect-shaped way.**
  One open disagreement, deliberately not averaged: `tls3.peet.ws` reports HTTP/3 `settings: null`
  for a connection whose SETTINGS `impersonate.pro` read in full. The discriminating experiment is
  named in the capture.
- **C14–C16**, the QPACK dynamic-table arm. This is what unblocks running live with the capture's
  own `1:65536` / `7:100` instead of the narrowed `0`/`0`. Segment 1 already *emits* a match; it is
  not yet *usable* live.
- **C17**, RFC 9221 DATAGRAM, forced by the capture's own `max_datagram_frame_size` and `51:1`.
- **Subsystem B is now SCOPED** (`3b1f7cc`,
  `plans/2026-08-20-quic-b-fingerprint-spec-scoping.md`): **12 tasks B0–B11, 14 with the
  packet-capture arm**, 11 findings. Three of those findings change decisions:
  **(a)** *nothing in `src/` composes a client transport-parameter list at all* — every composing
  call site is under `tests/`, so "we send 8" was a statement about a fixture, not about SharpTls;
  **(b)** *an exact `perk_hash` is reachable without ever bounding `initial_rtt`*, because every
  value the capture does not publish is a value the hash does not take — only position is hashed,
  and the two sets coincide exactly; **(c)** *dropping `active_connection_id_limit` is inert both
  ways* — §18.2 defaults it to 2, we send 2, and nothing reads it.

## SUBSYSTEM B IS COMPLETE, B0-B11. THREE OF FOUR PERK SEGMENTS MATCH BRAVE 151.

**Task B11 (`2247128`) is the demonstration this phase existed to reach.** Change one field on a
`src/` spec, and the live endpoint's verdict moves as predicted:

| arm | `perk_hash` | `perk_hash_normalized` |
| --- | --- | --- |
| that client151 preset as shipped | `04736da3818104056c4fda492c21bd05` | `058578261cc56e6f6a02cbd3349dd51a` |
| same 14, sorted ascending | `8a1b68ab063c11af9a015c4553661f52` | `058578261cc56e6f6a02cbd3349dd51a` |
| preset again | `04736da3818104056c4fda492c21bd05` | `058578261cc56e6f6a02cbd3349dd51a` |

12/12 attempts, one distinct reading per arm.

| segment | verdict | owner |
| --- | --- | --- |
| 1 - h3 SETTINGS | differs ONLY because C13's narrowed QPACK arm is held in force | C14-C16 |
| 2 - pseudo-header order `m,a,s,p` | **MATCH** | C |
| 3 - transport parameters, wire order | **MATCH, character for character** | B |
| 4 - CID length pair `0,8` | **MATCH** | B |

**Full-perk parity is one QPACK arm away.** B10's readout scores the shipped preset
**16 match / 0 MISMATCH / 2 not-yet-known** across 18 rows.

**A prediction failed, and it is the most useful thing the run produced.** The sorted arm's RAW hash
is not the preset's NORMALIZED hash: normalization **also sorts the available-versions list inside
`version_information`**, raw `17:1@GREASE,1` becoming normalized `17:1@1,GREASE`. Nothing in the repo
said so and a client capture claims only "sorts transport parameters by ID". It does not affect B7,
which targets the raw form, and the raw form is that client's.

**Per-connection draws are inert to the hash, confirmed under the real composition path:** 8
connections drew 8 fresh `initial_rtt` values, 8 fresh reserved identifiers and 8 fresh GREASE
versions - one hash throughout.

## What landed in subsystem B

| Task | State | Commit |
| --- | --- | --- |
| B0 — RFC 9368 and RFC 9221's parameter extracted | done | `7e89e6b` |
| B1 — the transport-parameter seam, as an arbitrary list | done | `865fbc8` |
| B2-B5 — the capture's values, and the three per-connection draws | done | `865fbc8`, `63976b2` |
| B6 — stop sending `active_connection_id_limit` | **already shipped** by B1's preset | `865fbc8` |
| B7 — wire order | **absorbed into B1's preset**; only its traps remained | `865fbc8` |
| C17 — RFC 9221 DATAGRAM, parse and drop | done | `e95fa3c` |
| B8 — the h3 profile factory | done | `f83331f` |
| B9 — the Initial flight split | done | `3a7852f` |
| B10 — the readout, segment 3 | done | `020c7b2` |
| B11 — the live run through the factory | done | `2247128` |

**THE USER'S STANDING DIRECTIVE, given 2026-08-20 and binding on everything below:**

> *"no placeholder values, everything must be configurable if different clients/browsers/apps/systems
> could send a different value. the final goal of this library is to reproduce pretty much any
> fingerprint given, if the stack allows it."*

The reconciliation with this project's standing rule, recorded in the B plan as an amendment with the
original text struck but visible: **the rule "a constant nobody can check is not allowed" forbids
INVENTING a value and presenting it as known. It never forbade EXPOSING a knob.** The project had
been conflating those, which is why `InitialRttRange` sat as a permanent `null` with no consumer.
So: the knob always exists and is settable; observed values live in **cited presets**, not in a
type's defaults block; where the capture cannot bound a value the preset's choice is marked
UNVERIFIED, names the task that would settle it, and lands in the readout's third column. Refusing to
emit, or silently picking a number with no comment, are both out.

`TlsQuicTransportParameterSpec` is the shape that follows from it: an **ordered list of
identifier/value slots** taking arbitrary identifiers — unknown, GREASE, Google-private 12583/12584 —
arbitrary bytes, arbitrary order, duplicates, omission. `Literal(id, bytes)`, `Placed(id)` for values
the connection derives, and `Drawn(Func<spec, parameter?>)` for anything redrawn per connection, where
returning `null` omits it. a captured client is a preset of 7 literal + 7 placed slots, each citing a capture
line. Its acceptance test writes the expected bytes **by hand** rather than round-tripping the
encoder, so it checks against an independent computation instead of a tautology.

**Only two values remain UNVERIFIED, both settled by B12:** `initial_rtt`'s range width (only
checkable property today is that it contains the capture's 192859 µs; uQUIC's
`ChromeRandomInitialRTT()` settles it) and the capture's reserved-identifier N. The GREASE version's
marker is **gone** — RFC 9368 §3 bounds the form exactly, so nothing is invented.

## What the live endpoint actually hashes — MEASURED, not read off prose (`4ed90bf`)

12/12 attempts, one distinct reading per arm, nothing averaged:

- **Wire order IS hashed.** Reversing the list moved `perk_hash` and left `perk_hash_normalized`
  byte-identical. The normalized *string* matched too, so the sort is real.
- **Value is NOT hashed for `AUTO`-rendered parameters.** `initial_rtt` at 100000 vs 900000 moved
  **neither** hash. Position is hashed; value is not.
- **The service strips neither an unknown identifier nor a zero-length value.** That closed both
  halves of the scoping doc's uncertainty item 2, which it listed as "not stated anywhere".

**Consequence: B12's packet capture is not a prerequisite for wire order.** `initial_rtt`'s range
being unsettled blocks nothing downstream. That is measured.

**The capture's prose won this one.** Its sorting claim and the position-not-value reading both
measured true. The only thing still wrong in it is the field name: it is **`perk_text`**, not `perk`.

## The trap waiting for B8

`ClientHelloProfileRoller` **caches successful profiles per origin** (`CacheCapacity = 256`, the uTLS
Roller equivalent). A cached profile is an immutable `ClientHelloProfile` with its transport
parameters already baked in — so a cached QUIC profile **freezes all three per-connection draws**,
reintroducing the pinned-`initial_rtt` defect the capture warns about, silently, on the path a caller
is most likely to use. B8 must resolve it and witness the resolution, not discover it later.

**Both "small and owed" items are CLOSED by `cf96c89`.** `TlsQuicHttp3Connection.CloseAsync` now
calls `CloseWithApplicationErrorAsync`, so §8.1's code rides the Error Code field of a 0x1d frame
rather than travelling as prose — witnessed off a datagram the loopback peer decrypted, not off a
property. And the connection passes `request.Method` to the response reader, so a HEAD response is
read against §6.4.1's escaping set rather than strictly.

**Still open, pre-existing and unrelated:** §10.2.1's "respond to any incoming packet while closing".

**Still open in subsystem B's territory, and now the largest single unknown:** `SplitIntoFrames` and
`GroupIntoDatagrams` default to one frame in one datagram. Overshoot past the padding target is
deliberate and §14.1-justified (`TlsQuicDatagramBuilder.cs:355`, witnessed by
`AFlightDatagramMayExceedThePaddingTarget`), and it names a client capture's 1216-byte
X25519MLKEM768 key share as the motivating case. But the capture's own opening flight is **two**
datagrams, and swapping the key share in without splitting ships **one oversized Initial**. A wrong
split throws nothing, fails no test, and `fp.impersonate.pro` cannot see it — only a packet capture
of Chromium's opening flight measures it. That is task B12's whole reason for existing.

## Decisions still owed by the user

- **Nothing has been pushed.** 323 commits, local only.
- **Three foreign commits remain** — `1a66f05`, `8f5b2c9`, `7bcb36e`. §8 says do not rebase them out
  without asking, and nobody has asked.
- **A3 stays deferred**, on evidence rather than assumption.

---

Written 2026-08-17, at the end of a session that ran out of context.
Branch: `feat/quic-socks5-datagram-transport`. Nothing has been pushed.

Read this file, then `docs/superpowers/specs/2026-08-16-quic-transport-scoping.md`. Those two
give you the whole picture.

---

## 1. Where things stand

**118+ commits on `feat/quic-socks5-datagram-transport`. 682 tests match `~Quic`, zero failures.**

**Phase A2 is complete** — all seven tasks, both review gates each. All twenty frame types parse and
serialise, the §12.4 legality table is encoded as data with all 80 cells independently verified, and
a `quic-frames` fuzz target reaches every parser across two axes without a throw.

| Subsystem | State |
| --- | --- |
| **D** — datagram transport + SOCKS5 UDP relay | **complete**, 13 tasks, both review gates each |
| **A1** — QUIC packet layer | **complete**, 10 tasks, both gates each |
| **A2** — QUIC frame layer | **complete**, 7 tasks, both review gates each |
| A3 — loss detection, congestion control | not started |
| A4 — connection, streams, key update | not started |
| B — fingerprint spec layer | not started |
| C — HTTP/3 and QPACK | not started |
| E — client integration | not started |

### The two agents left mid-task were resolved at the start of the next session

1. **A2 Task 1 quality review** — its findings were lost, so it was re-run against `1137fcd`. It
   found a **surviving mutation**: masking the decoded frame type's high 32 bits changed nothing,
   because every test input was ≤ `0x1e`. A frame type at or above 2³² whose low 32 bits alias a
   known type was being accepted. Fixed in `d047306`, along with a comment that had quoted §12.4
   accurately but labelled it backwards, `TryReadFrame` gaining an `out TlsQuicTransportError` so
   a rejection reports which RFC code applies, and `RawType` preserving the exact wire type value
   (`Type` is now derived from it — Task 3's STREAM LEN flag is not recoverable from decoded
   fields). RFC 9000 §20.1 was extracted in `c0d6dbc` first, so those codes are checkable.
2. **A2 Task 2, ACK frames** — never committed, left nothing in the tree. Restarted from scratch.

---

## 2. What exists, concretely

### Subsystem D — `src/SharpTls/Quic/`

| File | Contents |
| --- | --- |
| `TlsQuicSocks5Protocol.cs` | complete SOCKS5 wire codec, no I/O — greeting, RFC 1929 auth, UDP ASSOCIATE, relay resolution, datagram header |
| `ITlsQuicDatagramTransport.cs` | the datagram seam, plus `TlsQuicDatagramReceiveResult` |
| `TlsQuicUdpDatagramTransport.cs` | direct UDP |
| `TlsQuicSocks5Options.cs`, `TlsQuicSocks5Transport.cs` | SOCKS5 relay transport |
| `tests/.../FakeSocks5Relay.cs` | in-process SOCKS5 server for offline tests |

Plus `docs/SOCKS5-DATAGRAM-TRANSPORT.md` and an opt-in interop harness.

### Phase A1 — the QUIC packet layer

| File | Contents |
| --- | --- |
| `TlsQuicPacketNumber.cs` | RFC 9000 A.2/A.3 encode, truncate, decode |
| `TlsQuicPacketHeader.cs` | long and short headers, all four long types |
| `TlsQuicVersionNegotiation.cs` | RFC 9000 §17.2.1 |
| `TlsQuicHeaderProtection.cs` | RFC 9001 §5.4, AES-ECB and ChaCha20 |
| `TlsQuicPacketProtection.cs` | RFC 9001 §5.3 AEAD seal/open |
| `TlsQuicRetry.cs` | RFC 9001 §5.8 integrity tag |
| `TlsQuicDatagramReader.cs` | RFC 9000 §12.2 coalesced splitting |
| `Cryptography/ChaCha20.cs` | RFC 8439 §2.3 block function, written from scratch — .NET exposes no raw ChaCha20 |

Every RFC 9001 Appendix A vector reproduces in both directions (A.2, A.3, A.4, A.5). Both
RFC 9000 packet-number worked examples reproduce.

### Phase A2 — the frame layer, complete

| File | Contents |
| --- | --- |
| `TlsQuicFrameType.cs` | RFC 9000 §12.4 Table 3, the twenty frame types; five occupy ranges whose low bits are flags |
| `TlsQuicFrames.cs` | the `TlsQuicFrame` struct, both dispatch switches, PADDING/PING/HANDSHAKE_DONE |
| `TlsQuicAckFrames.cs` | ACK, §19.3 — the gap-and-length chain, ECN counts, both directions |
| `TlsQuicStreamFrames.cs` | STREAM's eight wire forms and CRYPTO, §19.8 and §19.6 |
| `TlsQuicFlowControlFrames.cs` | the six flow-control frames, §19.9–§19.14 |
| `TlsQuicConnectionFrames.cs` | the eight connection-management frames, §19.4/5/7/15–19 |
| `TlsQuicFrameLegality.cs` | §12.4's frame-type-to-packet-type table as data, all 80 cells |
| `tools/SharpTls.Fuzz/` | the `quic-frames` target, two axes, per-parser/per-type/per-axis reachability |
| `tools/SharpTls.Fuzz/QuicRfcVectors.cs` | the shared RFC-vector home — bytes, not types, source-linked |

`RawType` is the single source of truth and `Type` is derived from it by range-bounded comparison —
STREAM's LEN flag is **not** recoverable from the decoded fields, which is why that field exists.
The read path takes `ReadOnlyMemory<byte>` and parsed payloads are slices of the caller's buffer;
`TryReadFrame` allocates **0 bytes** on the accepting path, and that is now a permanent test rather
than a figure three tasks measured and deleted.

Plan, with eighteen standing rules: `docs/superpowers/plans/2026-08-17-quic-a2-frame-layer.md`.

---

## 3. Ground truth already extracted — use it, never retype

`docs/superpowers/specs/reference-captures/`:

| File | Covers |
| --- | --- |
| `rfc9000-packet-formats-and-pn-pseudocode.txt` | RFC 9000 §17, Appendix A.1–A.3 |
| `rfc9000-section12-packets-and-frames.txt` | §12.1–12.5, coalescing and the frame type table |
| `rfc9000-section19-frame-formats.txt` | §19 complete, all 20 frame types |
| `rfc9001-section5-packet-protection.txt` | §5.1–5.8, keys, AEAD, header protection, Retry |
| `rfc9001-appendix-a-test-vectors.txt` | A.1 keys, A.2 client Initial, A.3 server Initial, A.4 Retry, A.5 ChaCha20 |
| `rfc9000-section16-variable-length-integers.txt` | §16 complete, Table 4, the non-minimal-encoding rule |
| `rfc9000-section18-transport-parameters.txt` | §18, §18.1, §18.2 complete, Figures 20–22 |
| `rfc9000-section20-transport-error-codes.txt` | §20.1, the transport error code space |
| `the preset that measured it` | a real a captured client HTTP/3 fingerprint, subsystem B's target |

A4's task 0 added eight more, same practice, all verified byte-verbatim by independent re-fetch and
line diff: RFC 9000 §7.2–7.3 (connection ID negotiation), §8.1 (address validation and the
amplification limit), §10.1–10.2 (idle timeout, immediate close), §13.1–13.2 (packetization and ACK
generation), §14 (datagram size and PMTU), RFC 9001 §4 (the TLS/QUIC interface), and RFC 9369 §3 and
§5 (QUIC v2).

**All fourteen extracts are verified byte-verbatim** against `rfc-editor.org` — diffed line by line,
not eyeballed. The two gaps flagged after A2 are now closed: §14 and RFC 9369 are both extracted.

**Extract any further RFC section the same way** — fetch, `sed` the line range, commit verbatim
with a header. Two implementers in this session cited sections that were not in the repo; both
happened to be right, but neither claim was checkable. That is the whole point of the practice.

---

## 4. What SharpTls already gives you for free

Do not reimplement these:

- `CustomTlsQuicClient` (1159 lines) — the entire TLS 1.3 handshake as an encryption-level state machine, with HRR, resumption, 0-RTT, ECH
- `TlsQuicTrafficSecret.DerivePacketProtectionKeys(version)` → key, IV, header protection key
- `TlsQuicInitialSecrets.Derive(...)` — QUIC v1 and v2 Initial secrets from a destination connection ID
- `QuicVariableLengthInteger` — the varint codec every frame and header needs
- `TlsQuicTransportParameters` (369 lines) — RFC 9000 §18 with order preservation
- `TlsQuicCryptoStreamReassembler`

---

## 5. The working method — this is what produced the results

Each task ran: **implement → spec review → quality review**, with fix rounds until clean. Every
task in this session found something. The method matters more than any individual finding.

### Non-negotiables for task prompts

1. **Point at the in-repo RFC extract; do not restate field layouts or constants in the prompt.**
   A transcription error in a prompt propagates into every packet and surfaces as a crypto
   failure, not a layout one.
2. **Require hand-derived expected bytes**, not only round-trips. A round trip proves the encoder
   and decoder agree; they can agree while both being wrong.
3. **Require a mutation check on every bounds check and every edge-case branch.** Delete the
   check, confirm a test fails, restore. Construct the input so *only* that check can reject it.
4. **`Try`-shaped parsers must never throw.** Frame and packet payloads are attacker-controlled;
   a later phase runs them in a receive loop, where a throw is a denial of service.
5. **State that a real defect found is worth more than a clean run**, and that the implementer
   should report rather than silently fix or work around.

### Reviewer prompts

- Give the reviewer the RFC file path and tell it to verify against the text, **never against the
  code's comments**.
- Ask it to reproduce the implementer's mutation, and to run one the implementer did not.
- Name the specific defect you suspect, with your arithmetic, and ask to be corrected if wrong.
  A reviewer corrected me twice this session — once on a proposed fix that was itself wrong.
- Separate the two passes. Spec review answers "does it implement the RFC"; quality review
  answers "is it well built". The Retry defect below sat exactly in that seam.

---

## 6. Traps this session hit — do not rediscover these

### Testing

- **Published RFC vectors are not adversarial.** Three different packet-number-length formulas
  all pass both RFC 9000 A.2 examples. Truncating the AEAD nonce to 32 bits passes all three
  RFC 9001 vectors. Derive boundary cases from the formula, not from the examples.
- **A test that exercises two checks pins only whichever fires first.** A connection ID bound
  test passed because a length check rejected first; deleting the bound left 15 tests green.
- **A fuzz run's headline number means nothing without reachability.** An earlier SOCKS5 target
  ran 200,000 inputs and never reached the two branches that mattered. The `quic-packets` target
  now prints a per-parser reachability breakdown — copy that pattern.
- **Seal/open, encode/decode pairs cancel out.** A bug in shared nonce or offset arithmetic makes
  both halves wrong identically. Only an external vector or an independently computed oracle
  catches it.

### Concurrency

- **`git commit -m` commits the entire index**, not just what you staged. With two agents in one
  tree, another agent's staged files get swept in. This cost a lost commit. **Chain `git add` and
  `git commit` in a single shell invocation**, then `git show --stat HEAD` to verify.
- **Run one implementer at a time.** Reviewers are read-only and can run alongside. Two
  implementers in disjoint files mostly works but produced a lost commit and a stalled agent
  that waited on a build error belonging to someone else.
- **Use `--filter "FullyQualifiedName~Quic"` as the regression gate, not the full suite.** See
  section 8.

### Design

- **No layout decision may be a constant.** Connection ID lengths, packet number length, token
  contents, frame order — subsystem B varies all of them per imitated client. A hardcoded
  `DestConnIDLength = 8` turns B into a rewrite instead of populating a struct.
- **Parsing is zero-copy.** Parsed header fields are slices of the caller's buffer. The contract
  is documented on `ITlsQuicDatagramTransport.ReceiveAsync` and both header structs. A caller
  must not reuse or pool the buffer while parsed results are alive.
- **`TlsQuicDatagramReader.Read` is a lazy iterator.** Because `yield return` defers all body
  execution, storing the `IEnumerable` across an `await` means the *walk itself* runs later,
  against whatever the buffer then holds. Documented on the method; preserve that warning.

---

## 6b. What phase A2 produced besides code — read this before A4

The plan at `docs/superpowers/plans/2026-08-17-quic-a2-frame-layer.md` carries **eighteen standing
rules**, each earned from a defect that survived a green test suite. Nine real defects were found in
A2, **every one by a mutation surviving an otherwise green run**, and two of those were in an earlier
task's already-reviewed code. The rules are not style advice and they transfer directly to A4:

- A surviving mutation is **unwitnessed**, **unreachable by construction**, or **vacuous** — identical
  symptom, opposite meanings. Say which. For a vacuous one write no test: it would pass against the
  mutant and become a false witness.
- **Provenance decides reachability.** A guard on a parser's output is often unreachable; the same
  guard on a caller's input always reachable. Unless the bound is *tighter* than the parser's own
  range, in which case both are.
- A guard reachable by more than one path needs a witness **per path** — and enumerate reachable
  paths, not just flag paths. Zero-versus-absent produced findings in four consecutive tasks.
- Two checks throwing the same exception type on the same value make a mutation **invisible** rather
  than merely unpinned; `ParamName` becomes load-bearing.
- **Independence needs external ground truth.** Two transcriptions work against an RFC table. Against
  the code's own behaviour, hand-derivation is just running it slowly — label that a snapshot and
  lean on invariants instead.
- Run mutation sweeps in a **`git worktree`**. An in-place sweep made a concurrent gate run show a
  fabricated defect that was escalated as real.
- **Commit working state before running anything long.** Three agents were lost mid-task; the work
  survived only because the tree happened to be readable.

## 6c. RFC conformance audit — what is checkable and what is not

`docs/superpowers/specs/2026-08-17-a2-rfc-conformance-audit.md` audited all 29 files under
`src/SharpTls/Quic/` against the extracts, and the extracts against the published RFCs.

**All six extracts are byte-verbatim** — diffed line by line against `rfc-editor.org`. **No behavioural
or cryptographic defect was found**: nonce construction, mask selection, packet-number decode window,
ACK arithmetic, error-code pairing and Retry integrity layout all verified exactly correct.

The finding is citation debt, and it matters because a constant nobody can check is not allowed here:

- **RFC 9000 §16** (varints) was the most-cited section in the codebase and in no extract, while
  `QuicVariableLengthInteger.cs` carried **zero citations** — twenty frame types rest on it.
- **§18/§18.2** (transport parameters) likewise absent, and subsystem B depends on their **wire order**
  being reproducible.
- **RFC 9369 (QUIC v2) has zero coverage** despite the code deriving v2 Initial secrets. Still open —
  rank it before A4 touches version negotiation.

§16, §18 and four miscitations were remediated immediately after the audit; check `git log` for what
landed. **The audit's method is the transferable part: it asked what the repo could *not* check,
which no review had done — every review until then verified constants against the extracts and none
asked what was missing from them.**

## 6d. A correction to "A2 is complete" — ACK *generation* was never built

A2 is complete **against its plan**, both review gates on all seven tasks. But the plan itself had a
hole: the original scoping listed ACK generation as item 11, and the A2 plan omitted it. A2 encodes
and decodes ACK frames perfectly and decides nothing about *when* to send one — which was its stated
architecture, so no review would have caught the omission.

The consequence is concrete: without ACK generation a server stalls under §8.1's amplification limit.
It is now A4 task 8. Worth noting as a class of miss — every review verified the work against the
plan, and none asked whether the plan matched the scoping it came from.

## 7. Next steps, in order

**Reordered 2026-08-17 — A3 is deferred until after the first fingerprint readout.** The goal that
pays for this work is a fingerprint measured against a live endpoint, and A3 is loss detection and
congestion control, which one handshake and one GET against a cooperative server on a good link does
not need. So the order below is now A2 → A4-minimal → C-minimal → **measure** → A3 → B.

The cost is explicit and must not be forgotten: **with A3 deferred there is no retransmission, so any
packet loss kills that attempt.** Fine for a measurement you can retry; not fine for anything that
ships or that anyone depends on. A3 lands before either.

**Do not re-run the HTTP/1.1 and h2 fingerprint check — it is already done.** A prior session
confirmed h2 fingerprinting matches what the profiles set. Section 9 used to describe it as never
run, which is how this session came to propose it; that line is corrected below. **This session's
scope is HTTP/3 and QUIC only.**

1. **Finish A2** — 3 tasks left: connection management frames (in flight), the §12.4 legality table,
   a `quic-frames` fuzz target. Tasks 1-4 are complete, both review gates each: frame types and the
   field-less frames, ACK, the `ReadOnlyMemory` migration, STREAM and CRYPTO, flow control. Plan,
   with eleven standing rules earned defect-by-defect:
   `docs/superpowers/plans/2026-08-17-quic-a2-frame-layer.md`.
2. **A3** — RTT estimation, loss detection, NewReno. RFC 9002 gives all of it as pseudocode, so
   this is transcription plus conformance tests. Constants confirmed: `kPacketThreshold = 3`,
   `kTimeThreshold = 9/8`, `kGranularity = 1ms`, `kInitialRtt = 333ms`, initial window
   `10 × max_datagram_size`, `kLossReductionFactor = 0.5`, `kPersistentCongestionThreshold = 3`.
   The deterministic loss/reorder harness is an implementation of `ITlsQuicDatagramTransport`.
3. **A4** — connection state machine driving `CustomTlsQuicClient`, key update, connection IDs,
   flow control, streams, close, path validation. First phase needing a network.
4. **C minimal** — HTTP/3 control stream, SETTINGS, one request stream, QPACK static-table-only.
   Enough to make one GET.
5. **Then test against the two endpoints** — see section 9.
6. **B** — the fingerprint layer, once A works.

---

## 8. Open items and known issues

### A pre-existing bug in someone else's area — not ours, worth fixing

`CertificateValidationTests.UntrustedRootIsRejected` fails on this machine.
`CertificateChainBuilder.Build` lets `X509Chain.Build`'s `CryptographicException` escape, so a
transient Windows CryptoAPI failure reaches library users as a raw crypto exception instead of
`TlsProtocolException`. No commit on this branch touches `Certificates/`; the file last changed
in `b9ff6e9`, before the branch.

**Consequence for you: use `--filter "FullyQualifiedName~Quic"` as the gate.** The full suite has
this failure regardless of your work, and using it as a gate will mask a real regression.

`Interop.ClientCertificateInteropTests.Tls12MutualAuthenticationInteroperatesWithPlatformServer`
fails the same way, also pre-existing — confirmed by stashing and re-running on a clean tree.
Full suite is therefore 2 failed / 972 passed / 30 skipped before you change anything.

### A second pre-existing defect, found during task 6's review — recorded, deliberately not fixed

`TlsQuicHeaderProtection.TryRemove`'s `out packetNumberLength` overload has a **failure path that is
not idempotent**. It XORs `packet[0]` with the mask *before* the bound check:

```
packet[0] ^= (byte)(mask[0] & ProtectionMaskFor(packet[0]));
var pnLength = (packet[0] & PacketNumberLengthMask) + 1;
if (packetNumberOffset + pnLength > packet.Length) { return false; }   // byte 0 already mutated
```

The ordering itself is forced — the Packet Number Length lives in byte 0 and is only readable once
byte 0 is unmasked, so the bound cannot be checked first. What is missing is restoring byte 0 on the
`false` return.

**Harmless today**, and task 6 does not paper over it: `TlsQuicPacketReceiver.ProcessPacket` discards
the packet on `false` and never looks at the buffer again. It becomes a real bug the moment a caller
retries, re-parses, or logs the datagram after a `false` — it gets one corrupted byte with no
indication. This is subsystem A1's file, outside task 6's scope, and the fix (`packet[0] ^= …` again
before `return false`, plus a witness that a rejected packet leaves the buffer byte-identical) is
left for the user to schedule.

### The Quic gate has one blind spot: public API

`PublicApiBaselineTests.ExportedApiMatchesTheReviewedBaseline` does **not** match `~Quic`, so the
gate cannot see it. Any change to a *public* type breaks it — `TlsQuicTransportError` is public,
and adding two enum members to it did. Regenerate with `tools/SharpTls.ApiCompat`, then **diff
`PublicApi.Shipped.txt` and confirm only your own lines moved**: regenerating absorbs any other
public API drift already sitting on the branch, which is the exact thing the baseline exists to
catch. Run that test by name alongside the gate whenever you touch a public type.

### A foreign commit on this branch

`1a66f05`, authored by IterioDev — TLS 1.2 extended-master-secret work, `CustomTlsClient.cs`
plus a 308-line managed TLS 1.2 test server. Also `8f5b2c9` and `7bcb36e`, a captured iOS 16.7.16
Spotify ClientHello shipped as a built-in profile.

None of these are QUIC work. They landed because this branch was shared. **The user paused to
decide session ownership and never returned to it.** Do not rebase them out without asking — if
their session has them checked out, rewriting history breaks their work.

### Three performance items deferred to A4

Recorded in the scoping doc, deliberately together because they live in different files and
fixing one while missing the others is the likely failure:

- `TlsQuicHeaderProtection.AesMask` calls `Aes.Create()` per packet
- `TryComputeMask` returns `out byte[] mask`, allocating per packet
- `TlsQuicPacketProtection` constructs `AesGcm`/`ChaCha20Poly1305` per packet
- **added in A2 task 3a:** `TlsQuicAckFrames.WriteAckFrame` allocates twice per call — a `List<byte>`
  scratch buffer plus a `ToArray` — to encode the range chain before writing the frame. The *receive*
  path is verified at 0 bytes per call and must stay that way; this is write-side only. The fix is
  either pooling or a `WriteFrameFields` overload taking the ranges directly, and either one is this
  same hoisting work, so it belongs here rather than in A2.

- **added in A2 task 5, and the only attacker-triggerable one:** `QuicVariableLengthInteger` exposes
  no `TryRead`, only a throwing `Read`, so **every malformed frame allocates a
  `TlsQuicTransportException` plus its message.** The success path allocates nothing — that is
  measured and, from A2 task 7, permanently tested — but a peer sending a flood of malformed frames
  gets a flood of exception allocations for free. Adding `TryRead` touches every A1 packet-layer
  caller as well as A2, which is why it belongs here rather than mid-phase.

The first four want an epoch-scoped instance or buffer owned by the connection layer A4 builds. The
fifth is a signature change, and it is the one with a security argument rather than only a
throughput one.

---

## 9. Verification targets

Two independent services, queried together. They fail differently, which is the point.

**`https://tls3.peet.ws/api/all`** — named comparable hashes: `ja3`, `ja3_hash`, `peetprint`,
`peetprint_hash`, ordered ciphers, per-extension detail.

**`https://fp.impersonate.pro/api/http3`** — protocol-segregated; refuses to answer unless the
requested protocol was actually negotiated. Catches a silent fallback that peet.ws cannot.

**The HTTP/1.1 and h2 comparison is already done — a prior session confirmed h2 fingerprinting
matches what the profiles set. Do not re-run it.** This paragraph used to propose it as unrun work,
which cost a later session a wasted agent before the user caught it. What remains unverified is h3,
and only h3.

Endpoint paths, from a probe of `fp.impersonate.pro`: `/api/http1` and `/api/http2` both answer, and
the protocol-segregation guard genuinely works — `/api/http3` refuses unless h3 was actually
negotiated. That refusal is exactly what makes it subsystem B's acceptance gate: it cannot be
satisfied by a silent fallback.

Usable **after A4 + minimal C**: reaching them over `h3` is subsystem B's acceptance gate.

A client capture in `reference-captures/` is the target readout. Key facts from it:

- client connection ID length **0**, server connection ID length **8**
- QUIC transport parameter **wire order is fingerprinted** — the `perk` format publishes both
  raw and normalised hashes, so sorting them changes one and not the other
- `initial_rtt` (12583) is **randomised per connection** — pinning it is itself a fingerprint
- `max_udp_payload_size` is **1472**, an advertised value independent of the transport's real
  ceiling. Do not wire them together.
- the X25519MLKEM768 key share is **1216 bytes**, which is why Chromium's Initial spans two
  datagrams — the multi-datagram Initial path is required, not optional

### Capturing an iOS app

`docs/superpowers/specs/2026-08-17-ios-http3-capture-methodology.md` has the full Windows setup.
Summary: mitmproxy 11 in WireGuard mode carries TCP and UDP for every host without DNS tricks.
The untested risk is whether iOS trusts user-added CAs for QUIC — Chrome does not, and if iOS
matches, the HTTP/3 layer is unreachable by interception. **Do the passive capture first**
(Windows Mobile Hotspot + Wireshark); Initial packets decrypt from the published salt with no CA
at all, giving the entire QUIC layer regardless.

---

## 10. What subsystem B actually needs — narrower than it looks

Comparison against `bogdanfinn/tls-client` is in the scoping doc. Its 23-field `customTlsClient`
surface covers TLS, HTTP/2 and HTTP/3 SETTINGS, and **nothing at the QUIC transport layer**. Its
`quic-go-utls` fork carries none of uquic's spec files.

QUIC transport parameters ride inside the ClientHello, so SharpTls **already expresses that half**
through `TlsQuicTransportParameters` and `ClientHelloBuilder.WithQuicTransportParameters`.

What is genuinely missing is the **packet layer only** — six fields, and A4's scoping found a
**seventh**:

1. source and destination connection ID lengths
2. initial packet number and its encoded length
3. token length and prefix
4. per-datagram Initial flight plans, so a two-datagram Initial is reproducible
5. CRYPTO frame splitting and frame ordering within the Initial
6. datagram padding target
**One of these is bounded by an RFC MUST, which was invisible until §7.2 was extracted:** the
client's self-chosen Destination Connection ID on its **very first Initial packet must be at least 8
bytes** (§7.2). that client's DCID length of 8 sits exactly at that floor, so the constraint is invisible
in the capture and only appears if someone tries to go lower. Field 1 below is therefore a knob with
a normative minimum, not a free parameter.

8. **how the 1200-byte minimum is reached** — a candidate, not yet confirmed observable. §14.1
   permits two ways: PADDING frames, or coalescing, explicitly including *"coalesced with invalid
   packets, which a receiver will discard."* That is a layout choice a real client makes. Chromium
   uses PADDING. Documented in A4's plan, deliberately not built.

7. **varint width for non-minimal encodings.** RFC 9000 §16 permits a varint to use a longer form
   than necessary — it exempts *only* the frame type, which must be shortest-form. So the encoded
   width of a CRYPTO offset or a Length field is a sender choice, not a derived value, and therefore
   observable. Found while scoping A4, from the §16 extract added hours earlier; it was invisible
   while that section was uncheckable.

**Those six fields are the struct.** A1 was built so they are parameters rather than constants;
keep that true through A2 and A4 and B becomes populating a spec object rather than a rewrite.
