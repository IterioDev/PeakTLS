# Handoff

Written 2026-08-15, updated 2026-08-16. Read this first if you are picking this work up
cold.

## Update, 2026-08-16

**The repository moved.** Every path below that reads
`c:\Users\mario\OneDrive\Desktop\...` is now
`c:\Users\Admin\Desktop\PROJECTS\PeakTLS\...`, with SharpTls a sibling of TlsClient-main
under `PeakTLS`. The plans carry the old paths too.

**~~Plan 2 is through Task 12.~~ Superseded — plan 2 finished and plan 3 finished after it.
See "Where things stand" below for the current position; it is the section to trust.** Plan
2's checkboxes were never ticked, so read git log rather than the boxes there.

**~~`FlushAfter` has no observable effect on the wire.~~ Superseded by plan 3, Task 1.** It
was true while the transport was unbuffered: every `WriteAsync` became its own TLS record
and there was no batch for a flush to end. `Http2WriteBatch` now accumulates a batch and
emits it as one `WriteAsync`, which is what makes every `FlushAfter` knob observable. The
measurement note still stands and still matters: the server reads with `ReadExactly` and so
reports the *reader's* shape, so a flush boundary is only visible through
`Http2WireServer.ReadOnceAsync` or `RecordingStream.ReadSegmentLengths`, never through
`ReadFrameAsync`.

**`graphify update .` on the merged graph silently shrinks it** — it does not block, contrary
to what the working conventions below say. It rewrote the 5552-node merged graph down to
2174 TlsClient-only nodes. Recover by refreshing each repo and merging:

```bash
graphify update .            # TlsClient, writes a TlsClient-only graph.json
graphify update ../SharpTls  # SharpTls' own graph
graphify merge-graphs <tlsclient>/graph.json ../SharpTls/graphify-out/graph.json --out <tmp>
```

then copy the result over `graphify-out/graph.json`. The current graph is 6366 nodes and
13541 edges, AST-only. The pre-existing semantic (LLM-inferred) edges are kept at
`graphify-out/graph.semantic-backup.json`; a merge of AST-only graphs does not reproduce
them, and regenerating them costs an API-backed `graphify extract`.

**One behavioral divergence was accepted in Task 8.** An empty-valued `cookie` or
`authorization` used to match the static table and emit one byte; under the never-indexed
default it is now a three-byte literal. `HpackEncoderPolicyTests` pins it.

**SharpTls is no longer a pinned binary.** `TlsClient.csproj` now carries a
`ProjectReference` to `../../../SharpTls/src/SharpTls/SharpTls.csproj`, because this fork
changes SharpTls itself and a package reference would keep resolving the unpatched
0.9.0-preview.5. Both repositories build and test together; SharpTls' `global.json` was
relaxed to `rollForward: latestMajor` for the same reason TlsClient's was. Everything below
that calls the clone read-only is out of date.

**`extended_master_secret` is no longer required on a TLS 1.2 full handshake.**
`CustomTlsClientOptions.RequireExtendedMasterSecret` defaults to false, which is what
OkHttp on Conscrypt does and what RFC 7627 section 5.3 permits — and which gives up the
triple-handshake protection the extension exists for. That default is a deliberate fidelity
choice, not an oversight. It governs the full handshake only: `Tls12Session` now records
whether the establishing handshake negotiated the extension and resumption aborts on a
mismatch in either direction, which section 5.3 requires unconditionally. This should
unblock the Android preset's live parity run, which has not been verified against the
network from here.

**The preface must begin with a SETTINGS frame** (RFC 9113 section 3.4), judged on the type
octet a frame emits, so a raw `0x4` qualifies. The former empty-preface escape hatch is
gone.

**Dependency policy, set by the owner 2026-08-16.** Fingerprint parity outranks everything,
including dependency count and security-review surface. A pure-managed third-party library
is acceptable wherever it buys parity — `BouncyCastle.Cryptography` for the EdDSA
primitives .NET 9 lacks is the live example. What is *not* acceptable is P/Invoke into
native or Go libraries. Do not weigh "extra dependency" or "expands the audit surface" as a
cost in this project; weigh only whether it is managed code and whether it buys parity.

**Execution style this session:** `superpowers:executing-plans`, inline rather than by
subagent. Every new test was falsified by mutating the production code and confirming reds
before being trusted — three of them passed on first run and only the mutation showed they
were real.

## What this project is

TlsClient is a pure-managed C# HTTP/1.1 and HTTP/2 client built on SharpTls, used for
browser and application fingerprint emulation. This is a **private fork** — it will not be
published, so the public API can be broken freely and no compatibility shims are wanted.

**The owner's goal, in their words:** replicate an arbitrary real client's fingerprint 1:1
— for example an iPhone 16 Pro Max running iOS 26 on a custom app — by hand-analysing a
Wireshark capture. Validation is against `tls.peet.ws/api/all`.

Three design principles outrank everything else, in order:

1. **Fidelity of reproduction.** Prove byte equality, never approximate. A test that
   cannot fail is worse than no test.
2. **Ease of use from a manual capture.** A human reading a Wireshark dump or a peet.ws
   response is the primary user.
3. **Flexibility.** No helper may assume the three built-in presets.

A consequence worth internalising: **do not apply YAGNI to configurability here.** The
right test is not "will someone use this knob?" but "can this vary between real clients on
the wire?" If it can, the knob is coverage, not speculation. An earlier over-engineering
audit in this project applied the wrong test and had to be partly reversed.

## Where things stand

Rewritten 2026-08-16 at the end of plan 3. The table this replaced was stale in every row —
it claimed 150 tests, no production changes, the old OneDrive paths, and a pinned binary
SharpTls. Trust this section and `git log`; the plans' checkboxes lag reality.

| | |
|---|---|
| Branch | `master`, working tree clean |
| Suite | **360 passing, 0 failed** (`dotnet test TlsClient.slnx -c Release`) |
| Production code | heavily changed — `Http2Connection`, `TlsHttp2Options` and most of the HTTP/2 surface |
| Repo | `c:\Users\Admin\Desktop\PROJECTS\PeakTLS\TlsClient-main` |
| SharpTls source | `c:\Users\Admin\Desktop\PROJECTS\PeakTLS\SharpTls`, a **`ProjectReference`** — this fork patches SharpTls, so it is built from source, not consumed as a package |
| Plan 1 (harness) | complete |
| Plan 2 (connection layer) | complete. Task 14, the public API baseline rebase, was **dropped by the owner** because the API is still moving; do not rebase `PublicAPI.Shipped.txt` |
| Plan 3 (request lifecycle) | complete through Task 22 — this section is Task 22's own output |
| Plan 4 | not written. `TlsHttp2Capture.Import` and the inference rules were deferred to it |

`Http2WireGoldenTests.cs` has never been modified, across all three plans. It is the
operational test of "every default preserves today's bytes"; if a change moves it, the
change is wrong.

### Four things a fresh session must know

**1. Task 14 moved default bytes on the streaming path, on purpose.** It is the only place
in plan 3 where a default knowingly changed what goes on the wire. A streamed body used to
close with a separate empty DATA frame while a buffered body closed on its last DATA frame —
the placement fell out of which internal code path supplied the body, which is not a persona
decision at all. `TlsHttp2DataOptions.NonEmptyBody` now decides, and its default
`OnLastDataFrame` applies to both paths. The alternative was worse: a `NonEmptyBody` the
default silently ignores wherever the caller happened to pass a stream would have left
exactly the defect the task existed to remove. The golden fixtures were untouched and green;
two `Http2WriteBatchTests` record-boundary expectations that counted the trailing 9-octet
frame were adjusted, and what they assert — batch coalescing and per-frame flushing — is
unchanged. Commit `e88abbf`.

**2. `OnLastDataFrame` on a streaming body needs a declared `Content-Length`.** Without one
the separate empty DATA frame is kept whatever `NonEmptyBody` says. The placement has to
know which frame is last *before* writing it, and a stream only knows that from a declared
length; finding out by reading one chunk ahead would hold written octets across a blocking
read of the caller's producer, which is precisely the deadlock `892f951` removed. This is
not a gap to close later — closing it reintroduces the deadlock.

**3. A `FixedIncrement` below average consumption can still stall a transfer, and nothing
rejects it.** `TlsHttp2FlowControlOptions` validates that a fixed increment is within
[1, 2^31 - 1] and that neither threshold exceeds the window it draws on, but
`TlsHttp2WindowUpdateIncrement.Fixed` is the one mode that can return *less* than was
consumed. RFC 9113 section 6.9.1 has the peer send only what the advertised window permits,
so a fixed increment below the average consumed amount shrinks the window on every update
until the transfer stops. It is left unrejected deliberately — a real client that does it is
still a real client, and the check would have to compare against a consumption rate nothing
knows at configuration time — but it is the remaining self-deadlock hole in the flow-control
options, and it is not the default.

**4. The GOAWAY Last-Stream-ID bug had shipped.** The error-path GOAWAY wrote the client's
own `_nextStreamId`. RFC 9113 section 6.8 defines that field against streams the sender's
*peer* initiated: "if the server sends a GOAWAY frame, the identified stream is the
highest-numbered stream initiated by the client." For a client it is therefore the highest
*promised* stream — even, per section 5.1.1 — and `0` whenever the server pushed nothing,
which is the normal case. Present since the `fdee6ed` baseline, fixed in `9a1ca7e`, and the
code now carries a "Do not 'fix' this back to `_nextStreamId`" comment, because writing the
client's own next identifier there looks like the obvious reading and is wrong.

## Documents, in reading order

1. `docs/superpowers/specs/2026-08-14-http2-wire-fidelity-design.md` — the binding
   authority. Revised twice after a protocol review found six critical defects, and again
   in plan 3 Task 22, which corrected two things it had wrong: it claimed RFC 9113 section
   8.3.1 permits all three authority modes (it does not — `HostHeaderOnly` violates a MUST),
   and its `HeaderBlockFragmentSize` floor-of-6 rationale predated padding being charged to
   the same budget. Being the binding authority does not make it right; check it against the
   code and the RFC before relying on a claim.
2. `docs/superpowers/plans/2026-08-15-http2-byte-level-wire-harness.md` — **complete**.
   Built the byte-level test harness.
3. `docs/superpowers/plans/2026-08-15-http2-connection-layer.md` — **complete**, bar Task 14
   which the owner dropped. Preface script, HPACK policy, local-state derivation, preset
   migration.
4. `docs/superpowers/plans/2026-08-16-http2-request-lifecycle.md` — **complete**. 22 tasks:
   write batching, per-request frame scripts, pseudo-headers, header and DATA framing, flow
   control, shutdown codes. Its "Carry-notes" section is the shortest list of harness traps
   in the repository — read it before writing a test.
5. `docs/superpowers/plans/2026-08-16-rfc-reference.md` — the RFC quotations the plans were
   checked against, so a claim can be verified without refetching.
6. Plan 4 is not written. `TlsHttp2Capture.Import` and the inference rules were deferred to
   it; the spec's "Deriving a persona from a capture" section is its scope.

## Running things

`global.json` was relaxed to `rollForward: latestMajor` so an installed SDK can build the
repo. Everything runs from the repository root:

```bash
cd "c:/Users/Admin/Desktop/PROJECTS/PeakTLS/TlsClient-main"
dotnet build TlsClient.slnx -c Release
dotnet test TlsClient.slnx -c Release
```

`TreatWarningsAsErrors` is on with `AnalysisLevel=latest-recommended`. Analyzer warnings
fail the build — `CA1859` and `CA1305` both bit implementers during the last plan.

`PublicAPI.Shipped.txt` is enforced by a Roslyn analyzer. Any undeclared public change
fails the build with `RS0016`. Build first, then copy the exact strings it demands.

The opt-in live test needs `TLSCLIENT_LIVE_TESTS=1` and reaches a third-party service.
It is not part of the offline suite.

## The test harness you inherited

Under `tests/TlsClient.Tests/Wire/`, with a `README.md` naming its hazards:

| File | What it does |
|---|---|
| `RecordingStream.cs` | Tees bytes per direction; records only what actually transferred |
| `Http2WireServer.cs` | Server framing primitives, `CapturedFrame` |
| `Http2WireCapture.cs` | Drives a real TLS loopback connection against a scripted server |
| `Http2WireAssert.cs` | Byte and frame equality with offset-annotated hex dumps |
| `Http2WireHex.cs` | Wireshark "Copy as Hex Stream" paste → `CapturedFrame` list |
| `Http2WirePeet.cs` | Renders frames in tls.peet.ws vocabulary, computes the Akamai fingerprint |

`Http2WireGoldenTests.cs` pins all three presets' preface bytes and the frame sequence
around HEADERS. **These are the regression net for every later plan.** If they fail after
a refactor, the refactor is wrong — the expected bytes were derived from arithmetic and
independently verified, not recorded from observed output.

## Things that will bite you

Each of these cost a review round to establish. They are not in the code.

**`CapturedFrame` compares `Payload` by reference.** It is a `readonly record struct`
holding a `byte[]`. `Assert.Equal(frameA, frameB)` silently does not prove byte equality.
Use `Http2WireAssert.EqualFrames`.

**The byte-accounting equality in `Http2WireCaptureTests` is exact for structural
reasons** — `RecordingStream` records only bytes actually transferred, and
`Http2WireServer.ReadFrameAsync` reads exactly 9 header bytes then exactly the declared
payload. Introducing any buffered or speculative read into those two files makes it flaky.

**The client's SETTINGS ACK races the request writer.** It is emitted from the read loop
concurrently with request writes, so its position relative to HEADERS is nondeterministic.
Frame-sequence assertions filter it out. The connection-layer plan's ACK placement task
changes this.

**`Http2Connection.cs:1501` hardcodes `EnablePush => 0`.** The golden fixtures pin the
resulting bytes, so any migration must keep emitting them while making the value
expressible.

**Only one HPACK byte is currently pinned** — `block[0]`, `0x82`, indexed `:method: GET`.
Decoding is lossy, so the entire HPACK policy layer could change every emitted byte with
the suite green. The connection-layer plan adds its own assertions as it goes; do not
assume you inherit a net there.

**Write batching is unobservable until the connection-layer plan's Task 1** adds read
segment lengths to `RecordingStream`.

## Audit findings deliberately not fixed, 2026-08-16

The triage of the four RFC audits is `docs/superpowers/audits/2026-08-16-audit-triage.md`:
31 IMPORTANT and MINOR findings, 16 already closed, 15 open, none falsified. Eleven of the
fifteen were fixed in the commits that follow it. These four were not, each for a reason
rather than an omission. All four are MINOR and none is exploitable.

**hpack 2a — strict UTF-8 rejection of legal field values.** `src/TlsClient/HpackCodec.cs:582`
decodes every HPACK string with `new UTF8Encoding(false, true)` and turns the fallback into a
connection-killing COMPRESSION_ERROR at `:586`. HPACK strings are opaque octets and RFC 9110
section 5.5 permits `obs-text` (0x80-0xFF) in values, so a legacy ISO-8859-1 header value tears
down the connection — a real interop gap, and a divergence from the HTTP/1.1 reader, which
decodes Latin-1. **Why not fixed:** decoding values as Latin-1 or with a replacement fallback
breaks the size arithmetic, not just the string. `HeaderSize` and the header-list accounting
(`HpackCodec.cs:492-494`, `:628-629`) both use `Encoding.UTF8.GetByteCount` on the decoded
string, which equals the wire octet count *only* while the decode is UTF-8. Latin-1 makes each
0x80-0xFF octet count 2, and U+FFFD counts 3, so the dynamic table size would no longer mirror
the peer's encoder — eviction diverges, indices drift, and the whole field block decodes to
garbage. The honest fix carries the wire octet count out of `ReadString` and onto `HpackHeader`,
through `Get`, the static table and both accounting sites. That is a change to the cross-block
state machine, which is where HPACK decoders historically break, for a MINOR. Do it as its own
piece of work with its own tests, not as an audit cleanup.

**hpack 8d — validation is not applied uniformly across field blocks.**
`src/TlsClient/Http2Connection.cs:1342` runs `ApplyHeaders` — and therefore
`ValidateReceivedField` — only when the stream is known, and `:1422` decodes a PUSH_PROMISE
field block with `_ = _decoder.Decode(...)` and discards it unvalidated. **Why not fixed:** the
audit itself records that "Neither is exploitable today because both results are dropped", and
that is still true — nothing consumes either list. Section 8.2.1's validation exists to stop
delimiter injection into what gets forwarded, and neither of these is forwarded anywhere. The
part that RFC 9113 section 4.3 does make mandatory — decompressing "even if the frames are to
be discarded", so the dynamic table stays in step — already happens unconditionally at both
sites. Validating a block this client throws away would add two error paths that can only fire
on responses it already ignores.

**http-semantics 4.5 — HTTP/2 send-side field-name validation is narrower than section
8.2.1.** `src/TlsClient/HpackCodec.cs:333-343` rejects only `A`-`Z`, NUL, CR and LF in a name,
where section 8.2.1 names the ranges 0x00-0x20, 0x41-0x5a and 0x7f-0xff plus a misplaced colon.
**Why not fixed:** the split is deliberate and already documented at
`Http2Connection.cs:2876-2879` — the receive validator exists to decide what this client will
*accept* from an untrusted peer, and widening the encoder changes what it is permitted to
*emit*, which is a separate decision in a library whose contract is putting declared bytes on
the wire. It is also unreachable: every name that reaches the encoder has already passed
`TlsHeaders.ValidateName`, which is RFC 9110 section 5.1's `token` production and strictly
narrower than section 8.2.1. A naive widening would break pseudo-headers, whose names start
with the colon the rule forbids. Defence in depth against a path that does not exist, at the
cost of the one rule the encoder must not get wrong.

**frame-types F-8.2 — Last-Stream-ID is not retained across multiple GOAWAYs.**
`src/TlsClient/Http2Connection.cs:1615` reads it into a method local, so a second GOAWAY
raising the identifier is honoured where RFC 9113 section 6.8 says "An endpoint MUST NOT
increase the value they send in the last stream identifier". **Why not fixed:** clamping alone
changes nothing observable. The failure condition at `:1628` is `pair.Key > lastStreamId ||
error != NoError`; a raise only makes it fire *less*, streams the first GOAWAY already failed
stay failed, `TryFail` is idempotent, and `_isReusable` is 0 by `:1614` so the pool hands out no
new stream on this connection. A clamp was written and then reverted rather than shipped
untestable — the guard would be code no test could turn red. The finding's real content is the
sentence after the MUST: "the peers might already have retried unprocessed requests on another
connection". That means streams above the retained value are provably unprocessed and should be
retryable regardless of method idempotency, which needs the retained value plus a distinguishable
exception plus `TlsRetryOptions` reading it. That is a retry-semantics feature, not a one-line
clamp, and it is where this should be picked up.

## Open findings, carried out of the harness plan

**The Android preset cannot complete a live TLS 1.2 handshake with tls.peet.ws.** The
client offers `extended_master_secret` (verified: `Raw(23, [])` is in
`UTlsAndroid11OkHttp.Spec.Extensions`), the server does not reciprocate, and SharpTls
aborts by policy at `Tls12ServerHelloParser.cs:183-187`. Real OkHttp/Conscrypt would
proceed. This is a **client-strictness divergence from the stack being emulated**, not a
missing extension — an earlier report diagnosed it backwards. It blocks live validation
for that preset only. Chrome 133 and Firefox 148 both pass live parity.

**No test detects a regression of the `Http2WireCapture.RunAsync` server-task leak.** The
production fix is correct and in place — a `try/finally` guarantees
`responseReceived.TrySetResult()`. But the leak is in an unawaited background task,
invisible to xUnit at that seam, so the test named
`PropagatesClientRequestFailureInsteadOfHanging` does not prove what its name claims.
Closing it needs the harness to expose the server task. Do not trust that test.

**Two rendering issues in `Http2WirePeet` deliberately deferred** to the plans that make
them matter: `DescribeFlags` was fixed to name `0x1` as `Ack` on SETTINGS and PING, but
the pseudo-header abbreviation still collides `:path` and `:protocol` into `"p"` — which
becomes ambiguous when plan 3 adds RFC 8441 extended CONNECT.

**The read loop blocks on `_writeGate`, and that is structural, not a flow-control bug.**
A reviewer flagged `Http2Connection.HandleDataAsync` (`src/TlsClient/Http2Connection.cs`,
the `TlsHttp2WindowUpdateTrigger.OnReceive` branch at the end of the method) as newly
stalling the reader behind a writer, on the reading that only the rejected-push credit
above it had that shape. **That reading is wrong about the baseline.** The read loop has
taken `_writeGate` since the connection-layer plan, on the *default* configuration, in two
places RFC 9113 makes mandatory:

- `HandleSettingsAsync` — `_writeGate.WaitAsync` for the SETTINGS ACK (section 6.5.3).
- `HandlePingAsync` — `EnterWriteBatchAsync` for the PING ACK (section 6.7).

So `OnReceive` crediting adds one more instance of an existing shape rather than a new
hazard class, and it is not even on by default. **Deliberately not fixed.** The conditions
under which any of the three bite are the same: a writer holding `_writeGate` blocked on a
transport whose send buffer is full, while the peer is itself blocked writing to us and
will not drain. Removing the coupling means the reader queueing frames for a writer to
drain — a second write path, which is exactly the restructuring that produced the two
deadlocks this file has already shipped. Do not attempt it for the credit path alone;
either all three move together, behind a test that can actually observe a stalled writer,
or none do.

**`RestoreReceiveWindowAsync`'s ceiling clamp is race-free but untested at the race.** The
decision and the window mutation now share one `_flowSync` acquisition, so two streams'
body pumps can no longer both size a `Fixed` or `RefillToInitial` increment against the
same headroom and both send it. The interleaving that broke it needed one pump to be
between its decision and its write while another decided — a window the wire harness
cannot force, since it is bounded by a `SemaphoreSlim` wait and a loopback TLS write. No
test covers it, and a timing-dependent one would be worse than none. If a seam ever exists
to hold `_writeGate` from a test, this is the first thing to point it at.

## Working conventions the owner set

**Query the graphify knowledge graph before reading files.** A merged cross-repo graph
covering both TlsClient and SharpTls lives at `graphify-out/graph.json` — 5552 nodes,
16265 edges. Use `graphify query "<question>"`, `graphify path`, `graphify explain`, or
`graphify affected`. Fall back to Read and Grep only when the graph does not answer or
byte-level detail is needed. Refresh with `graphify extract <path> --code-only` per repo
then `graphify merge-graphs` — a plain `update` on the merged graph would shrink it and
the guard blocks that.

The graph indexes **code only**. The ~84 markdown files, including the spec and plans, are
not in it; adding them needs a semantic pass.

**Execution style.** The last plan ran via `superpowers:subagent-driven-development` —
fresh implementer per task, task review after each, one final whole-branch review. It
found six real defects across ten tasks, and **every one traced back to the plan's own
code rather than implementer error**. Two were tests that could not fail. Budget for that:
the reviews are what make this work, not overhead on top of it.

The owner consented to working directly on `master` for the harness plan. That consent was
for that plan; ask again rather than assuming it carries.

## After HTTP/2

HTTP/3 and QUIC, which the owner already knows is tedious. The realistic shape:

SharpTls hands you the TLS half — `SharpTls.Quic` has 26 exported types including
`CustomTlsQuicClient`, per-level packet protection keys, and **ordered, arbitrary-ID QUIC
transport parameters**, which is precisely the axis bogdanfinn's `quic-go-utls` fork
cannot control because its `Marshal` order is hardcoded.

What is missing is the QUIC transport itself: 8–15k lines, plus 3–5k for HTTP/3 and QPACK.
SharpTls's own roadmap permanently scopes QUIC transport and HTTP/3 out, so it will never
arrive from upstream.

Milestone 1 is the place to stop and reassess: UDP, Initial and Handshake packet
protection, CRYPTO exchange to the first 1-RTT packet. No streams, no recovery, no HTTP/3.
That alone emits a Chrome-shaped QUIC Initial with correct connection-ID lengths and
de-risks everything after it.
