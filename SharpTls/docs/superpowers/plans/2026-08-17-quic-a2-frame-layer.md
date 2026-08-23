# QUIC Frame Layer (Phase A2) Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse and serialise every QUIC frame type, and enforce which frames may appear in which packet type.

**Architecture:** Pure functions over spans, same as phase A1. No sockets, no timers, no connection state. A frame codec that a later phase drives; this phase decides nothing about when to send what.

**Tech Stack:** C# 13, .NET 9, xunit 2.9.3.

**Standards:** RFC 9000 §19 (all frame formats), §12.4 (frame types and the packet-type legality table), §12.5 (frames and number spaces).

---

## Ground truth in the repo

Do not retype values from these. Copy them.

| File | Contents |
| --- | --- |
| `reference-captures/rfc9000-section19-frame-formats.txt` | §19 complete — all 20 frame types plus extension frames |
| `reference-captures/rfc9000-section12-packets-and-frames.txt` | §12.4 frame type table and legality rules, §12.5 number spaces |
| `reference-captures/rfc9001-appendix-a-test-vectors.txt` | A.2's client Initial plaintext is a real CRYPTO frame followed by PADDING |

**Every constant carries its RFC section. Reviewers verify against the RFC text, never against the code's comments.** That produced zero wire-format defects across A1's ten tasks and is not optional here.

## What already exists and must be reused

In `src/SharpTls/Quic/`:

- `QuicVariableLengthInteger` — `GetEncodedLength`, `Write`, `Read`, `Encode`, `ReadExact`. **Nearly every frame field is a varint.** Do not reimplement.
- `TlsQuicPacketHeader` — parses packets; A2 parses their payloads.
- `TlsQuicDatagramReader` — splits datagrams into packets.
- `TlsQuicTransportError` and `TlsQuicTransportException` — the RFC 9000 error code space, for frame-level protocol violations.

## The one real frame-level test vector

RFC 9001 A.2's client Initial plaintext is a 245-byte CRYPTO frame followed by 917 bytes of PADDING. That is the only IETF-published frame encoding available to this phase, and it is already extracted. Use it as the anchor for CRYPTO and PADDING.

**Every other frame type has no published vector.** That is the defining risk of this phase, and it is worse than A1's. A1 could check itself against IETF bytes; here, a round-trip test only proves the encoder and decoder agree with each other, and they can agree while both being wrong.

Two consequences, both mandatory:

1. **Hand-construct expected bytes from the §19 field diagrams for at least one instance of every frame type.** Write the expected byte array literal in the test, derived from the diagram, and assert the encoder produces it. Never assert only that encode-then-decode round-trips.
2. **Mutation-check every bounds and validity check**, as A1 did. Delete the check, confirm a test fails, restore. Construct the input so only the check under test can reject it.

## Design constraint carried from A1 and B

Subsystem B must be able to control **frame layout inside the Initial packet** — how a CRYPTO stream is split across frames, and where PADDING and PING sit. uQUIC models this as a pluggable frame builder, and it is one of the six fields that distinguish a real client's fingerprint.

Therefore: **the encoder must accept an arbitrary ordered sequence of frames and emit them in that order.** No reordering, no coalescing of adjacent frames, no automatic padding. If the caller asks for three CRYPTO frames with a PING between them, that is what goes on the wire. A frame writer that "helpfully" merges or reorders makes subsystem B impossible.

## File layout

All directly under `src/SharpTls/Quic/`. No subfolders.

**Amended after task 2 — split by frame family, one file per family, both directions in it.**
As written this table gave `TlsQuicFrames.cs` every frame type, and that reached 619 lines after only
two of the five frame-implementing tasks, heading past 1500. Worse, the `TlsQuicAckRanges.cs` split
task 2 actually shipped cuts *horizontally through one frame type*: `TryDecodeRanges` reaches into
six `TlsQuicFrame` fields, `TlsQuicFrames.cs` reaches back for `EcnCountsBit`, `HasEcnCounts`,
`ValidateRanges` and `WriteRanges`, `ValidateRanges` is `internal` only because the boundary crosses
files, and `WriteAckFrame` needs 33 lines of comment to explain where the cut falls. So the one-file
rule is already dead in practice; what remains is choosing the seam deliberately rather than by
accretion. No subfolders are involved either way.

| File | Responsibility | Task |
| --- | --- | --- |
| `TlsQuicFrameType.cs` | the frame type enum and §12.4 metadata | 1 |
| `TlsQuicFrames.cs` | the `TlsQuicFrame` struct, both dispatch switches, the field-less frames | 1 |
| `TlsQuicAckFrames.cs` | ACK, both directions — was `TlsQuicAckRanges.cs` | 2 |
| `TlsQuicStreamFrames.cs` | STREAM and CRYPTO, both directions | 3 |
| `TlsQuicFlowControlFrames.cs` | the six flow-control frames | 4 |
| `TlsQuicConnectionFrames.cs` | the eight connection-management frames | 5 |
| `TlsQuicFrameLegality.cs` | §12.4's frame-type-to-packet-type table | 6 |

`TlsQuicFrames.cs` then grows ~10 lines per frame type instead of ~180, landing near 400 for all
twenty — which is also exactly the surface task 6's legality table needs.

**Judged on complete evidence after task 5, when all twenty types existed: the struct held up — but
on task 7's argument, not task 6's.** Measured at 256 bytes, 23 init-settable properties. Task 7
vindicates it decisively: an allocation test and a fuzz campaign parsing millions of frames are only
possible because a parse allocates nothing, and a class hierarchy would allocate one object per frame
and make the phase's only permanent allocation test unwritable. **Task 6 does not vindicate it at
all** — §12.4's table is keyed by the `TlsQuicFrameType` enum and by packet type, and never touches
`TlsQuicFrame`. So half of the original justification below never materialized; keep the conclusion,
retire that half. The real cost is a 256-byte copy per `in`/`out` — measurable, nowhere near an
allocation — plus field crosstalk, which is documented and deliberately pinned.

**Keep the single `Type`-discriminated `TlsQuicFrame` struct.** Not deference to this plan: a class
hierarchy allocates per frame and destroys the no-allocation receive contract, explicit overlapping
layout is unreviewable, and tasks 6 and 7 both want one uniform type to hold and switch on. The real
cost at twenty types is stack copy size — `in` parameters are already used throughout, so measure it
in A4, do not redesign it now. The struct's growth driver is not field count but RFC-quoting field
docs: keep one-line `<summary>` per field and put the quote beside the code that applies it.

**The rule task 3b earned, and the most productive one so far — a guard reachable by more than one
flag path needs a witness per path.** STREAM's three low bits change which fields are present, so
several guards are reachable two ways: the largest-offset §19.8 MUST takes its length from the
`Length` field when LEN is set and from the remaining payload when it is clear. Every test row used
`0x0e`, so adding `if (hasLength && …)` to that guard — skipping it entirely for the four LEN-clear
forms — **survived a green suite**. Going one guard over found the same hole twice more, in
`RequireEncodableVarint(StreamId)` and the STREAM-site largest-offset call, both exposed by the same
cheap mutation: wrap the guard in a flag condition and see if anything fails.

This applies directly to what is left. **Task 4:** MAX_STREAMS and STREAMS_BLOCKED each have two type
values. **Task 5:** CONNECTION_CLOSE has two forms and the application form drops a field entirely.
**Task 6:** the legality table is indexed by both frame type and packet type.

The method that works, in order: for each guard, enumerate its reachable paths; add a row per path
rather than trusting the one the author happened to pick; then mutate the guard behind a flag
condition per path and confirm each row dies. And **say which guards do *not* have multiple paths and
why** — task 3b listed the ones reachable only when a flag is set, so a later reader can tell
"checked and single-path" from "not checked".

**Flag bits are not the only axis — enumerate reachable paths, not reachable flag paths.** Task 3b's
own quality review then found the same hole one axis over: every row exercising the write-side
largest-offset guard used a one-byte `Data`, so nothing covered `Data.Length == 0`, where the guard
degenerates to the offset-encodability check its comment claims it performs. Conditioning it on
`Data.Length > 0` survived a green suite. Field *lengths*, empty collections, and zero-versus-absent
all branch a guard as effectively as a type bit does.

**An `internal` helper's contract is observable — test it directly; only a caller's local is not.**
Three times now a helper has documented "never throws, and `offset` only advances on success" while
nothing could observe the second half, because the sole caller discards the helper's offset on
failure. The resolution is not to downgrade the comment by reflex. Task 3b got the split right and it
is the pattern to copy: `TryReadStream` and `TryReadCrypto` are `internal`, so a test *can* be a
second caller — they were pinned with direct calls entering at a **nonzero** offset, chosen so
"unchanged" is distinguishable from "reset to zero". `TryReadData`'s identical promise genuinely
cannot be observed, because its offset is the caller's local that no caller publishes, so that
comment says defence-in-depth and explains why no test reaches it.

So per helper: if it is `internal`, pin it with a direct call at a nonzero offset. If its offset is
only ever a caller's local, say so and say why. **Do not widen visibility to make a test possible** —
that is scaffolding, not coverage, and it makes an unobservable property merely look pinned.

**A cross-reference is a claim too — enforce it.** Task 4 put 36 `TlsQuic*Tests.Name` citations into
the sources and every one resolved, but nothing stops a rename or deletion turning them into stale
comments that now *look* authoritative. A ~10-line test regex-scans `src/SharpTls/Quic/*.cs` for
`TlsQuic\w*Tests\.(\w+)` and asserts each resolves to a `[Fact]` or `[Theory]`. Land it before the
citation count grows; an unenforced name rots exactly like the seven comments this phase has caught.
Shipped in `tests/SharpTls.Tests/Quic/QuicCommentReferencesTests.cs`.

**Write every test citation qualified — `ClassTests.MethodName`, never a bare method name.** This is
now enforceable only in that form, and the reason is worth understanding rather than obeying: at the
moment of a rename, a bare cited name stops being a known test and becomes an ordinary CamelCase
word, so nothing remains to resolve it against. A checker that matched only bare names which *do*
resolve would find exactly the citations that are already correct — a test that cannot fail, which is
the same false witness as a test written for a vacuous mutation. Twelve bare citations predate the
rule and are documented in place; do not churn committed comment blocks to retrofit them.

**And when you pin a claim, say next to the claim which test pins it.** The ACK line survived two
reviews because nothing in the source distinguished a pinned claim from an unpinned one — a reader,
human or agent, had to re-derive it every time. Task 4's reviewer then reported all three families as
unpinned when one of them had been pinned by task 3b all along. A one-line cross-reference at the
claim is what stops that.

**A third category of survivor: the mutation is vacuous — and here a test would be actively
harmful.** Task 4 found one. `TryReadMaximumData`'s only rejection is its single varint field
truncating, and `QuicVariableLengthInteger.Read` does `offset += length` as its *last* statement
after both bounds checks — so on a throw the cursor has not moved, `walked == offset` in the catch,
and the early-commit mutation is literally `offset = offset`. Not a behaviour change for any input.
**A test written for it would pass against the mutated code**, which is worse than no test: a false
witness that makes the next reviewer stop looking. Record the argument and the trigger that would end
it (here: the reader gaining a second field or a bound), and write no test.

So a surviving mutation is one of three things — **unwitnessed** (add the row), **unreachable by
construction** (record the argument and what would make it reachable), or **vacuous** (record why,
and deliberately write no test). Say which. They look identical from the test output.

**Run mutation sweeps in a `git worktree`, never in the shared tree.** Task 6 ran an in-place sweep
while the coordinator happened to gate the tree, which showed a **fabricated defect** — a flipped
CRYPTO cell — that got escalated as real, adjudicated against the RFC, and sent back for a fix that
was never needed. The whole round-trip was wasted, and the reasoning about it was correct while the
premise was not, which is the expensive kind of wrong.

Two consequences. A sweep is a long sequence of deliberate corruptions; anything else reading the
tree during it reads garbage that *looks* like a finding. And stopping one is not reliable — task 6
reported that `TaskStop` returned success while the sweep kept advancing, so it had to be killed at
the process level. An isolated worktree removes both problems, and this project already uses them.

**Paste mutation-record counts from the run; never summarise them by category.** All three defects
in task 6 were counts derived by reasoning instead of observation — "the six 0-RTT cells and the two
lowercase cells" (the lowercase ones kill nothing extra: six, not eight), "fourteen of the twenty
rows are `__01`" (twelve, and 14 + 2 + 6 = 22 > 20 on its own arithmetic), and "thirty cells
including CONNECTION_CLOSE" (28, none on CONNECTION_CLOSE, plus two rows from a test the record never
names). Every one was plausible, and none was measured.

This matters more than ordinary comment rot: the standing rule is that a mutation record **names the
killing test**, so a record naming kills that provably do not happen is a false witness in the one
place this phase trusts most. Copy the observed failing test names out of the run output. If a
category summary is wanted, write it *after* the pasted list and let the two disagree loudly.

**Qualify the names as you paste them.** Run output prints bare method names, and the citation
checker can only enforce `ClassTests.MethodName` — so pasting raw output mechanically grows the
unenforceable set. Task 6 added three bare citations that way while obeying the paste rule. Prefix
the class as you paste; it is the same keystroke and it keeps the record enforceable.

Related, from the same task: **check the checker.** Two of its own comparison scripts were silently
broken — a regex of `0x[0-9a-f-]+` cannot match `0x02-0x03`, and `tr -d '_'` ate the underscores out
of the very `Pkts` values being compared — each producing a false mismatch. A verification script is
code, and it fails the same ways.

**A reachability report needs its own witness — the numbers are the deliverable, so they are a claim.**
Task 7's review mutated the harness's own counting: a cap counter incremented on every input, printing
`inputs hitting the 512-frame cap=41` out of `inputs=40` — arithmetically impossible — and a parser
loop set `reached = true` unconditionally, printing a uniform `40/40 (100.00% true)` for all thirteen
readers whose real rates span 1% to 93%. **Both survived the full gate.** Nothing asserted on the
printed breakdown or the counters behind it, so the only thing between a broken counter and a
confidently clean run was a human reading text.

The seed corpus is deterministic, so its reachability is *knowable in advance*. Pin it the way task 6
pinned its table: hand-derive which parsers each seed should and should **not** reach, and assert
both. A PING seed must not reach the ACK reader. Asserting only upper bounds is not enough — it would
not have killed either mutation above.

**Independence needs external ground truth — where there is none, say "snapshot" and lean on
invariants.** Task 6's two-transcription rule works because §12.4's table exists outside the code: two
people can read the RFC and disagree. Task 7's reachability counts have no such source. There is no
external answer to "does `TryReadAck` accept seed #17 at offset 1" — hand-deriving it means tracing
the parser's own byte consumption, which is epistemically **the same operation as running it**, done
with a human calculator. A number obtained that way is a regression snapshot, not a witness, and
calling it hand-derived is the overclaiming this phase keeps catching.

So: pin such numbers if you like, but **label them a snapshot**, and put the real weight on properties
that hold without running the code — a PING seed cannot reach the ACK reader; no parser can be
simultaneously 0/N and N/N. Those are what killed the two mutations in task 7; the thirteen exact
percentages rode along behind them. Where a count *is* genuinely derivable from a structural argument
— task 7 found two of thirteen, one from a fixed 16-byte trailing field and an offset-alignment
argument — promote it to a direct check and say what the argument is.

**Choose vector values that cannot collide with a structural byte.** Task 5's RESET_STREAM vector
used Stream ID `4`, and RESET_STREAM's type byte is `0x04` — so the mutation "write the Stream ID
before the frame type" produced **byte-identical output** and survived a green suite. The vector was
hand-derived and correct; it simply could not distinguish two orderings. Field values that coincide
with a type byte, a length, or any other structural byte make ordering mutations invisible. Pick
values that are distinct from every structural byte in the frame — task 5 changed it to `9` and then
swept the other seven writers for the same collision, which is the right follow-through.

**Provenance decides reachability, and it is the most predictive rule here.** Task 3b's read-side
largest-offset bound has an unreachable path: the offset came out of
`QuicVariableLengthInteger.Read`, so it is ≤ 2⁶²−1 by construction and a bound on it cannot fire. The
**write-side twin of that same guard, on the same conceptual field, was a real hole** — there
`frame.Offset` is caller-supplied and bounded by nothing.

So: a guard on a value a parser produced is often unreachable; the identical-looking guard on a value
a caller handed you is always reachable. **Every write-side bound on a caller-supplied field needs a
witness. Its read-side twin may legitimately need none.** That single distinction predicts where the
holes are in tasks 4 and 5, which are almost entirely write-side bounds on caller-supplied varints.

**A surviving mutation means one of two things, and they look identical — say which.** Conditioning
the same guard on `HasOffset` also survived, but that one is *correct*: OFF-clear implies `Offset ==
0` because an earlier check throws otherwise, and `0 > (2^62-1 − int)` is false for every `int`, so
the path is unreachable by construction. Conditioning it on `HasLength` surviving was a real hole.
Identical symptom, opposite meaning. When a mutation survives, decide whether the path is
**unreachable** (leave it, and record the argument) or **unwitnessed** (add the row), and write down
which — an unreachable-by-construction claim is exactly as load-bearing as a test, and nothing
enforces it if a later change makes the path reachable.

Two more standing rules, both from task 3a, where three consecutive fix rounds each opened a fresh
coverage hole while closing the previous one:

- **When you fix a shadow, add a row — never move the only coverage of a check.** Task 3a added a
  bound that shadowed an existing mutation-pin, and moved the shadowed test's input to restore
  isolation. That input was the suite's *only* index-0 coverage of `ValidateRanges`, so a mutation
  that used to kill a test now kills none. Moving a test to un-shadow one check silently un-pins
  whatever else that input was the only witness for. Add the new case and keep the old one.
- **A test written for a partial-write defect must assert the destination is untouched, not just
  that something threw.** Asserting the exception type alone is what let the original mutation
  survive: the check can be moved *below* the writes and the type is unchanged. This applies to
  every write-side bound, and it is cheap — seed the destination with a sentinel byte and assert it
  is still alone.

Two standing rules from task 2's reviews:

- **The 500-line file limit is measured on code lines, not raw lines.** `TlsQuicAckFrames.cs` is 685
  raw but 262 code, 379 comment, and every comment in it was checked and found load-bearing. A rule
  applied to raw lines here would delete the mutation records and RFC citations that are the main
  reason this phase has found real defects. STREAM's eight wire forms will exceed 500 raw too.
- **Never write an absolute test count into a comment.** They go stale every task — this file
  already carries "313" and "365" from earlier tasks. Name the commit, or state the count relative
  to the check under discussion ("deleting this fails exactly one test"), which is the part that
  actually matters and does not rot.

Tests mirror these in `tests/SharpTls.Tests/Quic/`.

---

## Task 1: Frame types and the trivial frames

**Files:** create `TlsQuicFrameType.cs`, `TlsQuicFrames.cs`, and tests.

RFC 9000 §12.4 gives the frame type table; §19.1, §19.2 and §19.20 give PADDING, PING and HANDSHAKE_DONE.

- The frame type is itself a varint, not a byte. Several types occupy a **range** of values, notably STREAM, whose low bits are flags. Read §12.4 before assuming a type is a single value.
- PADDING has no fields. A run of consecutive PADDING bytes is one logical frame or many; §19.1 says which. Read it and say in your report what you chose and why.
- Reading is `Try`-shaped and never throws for any input.

Tests: hand-built expected bytes for each of the three; a frame type varint at each encoding width; an unknown frame type rejected per §12.4.

## Task 2: ACK frames

**Files:** create `TlsQuicAckRanges.cs`, extend `TlsQuicFrames.cs`, and tests.

RFC 9000 §19.3, §19.3.1 ACK Ranges, §19.3.2 ECN Counts. This is the most intricate frame in QUIC and deserves its own task.

- The range encoding is a gap-and-length chain, expressed relative to the previous range, descending. Getting the relative arithmetic wrong produces acknowledgements for packets that were never sent — which a peer treats as a protocol violation.
- ACK type `0x03` carries ECN counts; `0x02` does not.
- §19.3.1 states validity rules on the ranges. Enforce them; an ACK whose ranges underflow past zero is malformed and must be rejected, not wrapped.

Tests: hand-built bytes for a single range, several ranges, and the ECN variant; ranges that underflow rejected; a range count that overruns the buffer rejected; largest-acknowledged at the varint maximum.

## Task 3a: migrate the read path, behaviour-preserving

**Files:** `TlsQuicFrames.cs`, `TlsQuicAckFrames.cs`, their callers, and tests.

Split out of task 3 after task 2's reviews. Land the two mechanical changes described in the
amendments below — the `ReadOnlyMemory<byte>` read path, and the ECN counts record struct — on their
own, with **no new frame type and no change in behaviour**.

The reason is verifiability: a behaviour-preserving refactor is provable by an unchanged test count
and an unchanged set of test names. Bundled with STREAM's eight new wire forms, a failure could be
either the migration or the new code, and this phase has already shown that when two things can
explain one result, the wrong one gets believed.

**Done when** `TlsQuicFrame` holds a `Memory` slice instead of `AckRangesOffset`/`AckRangesLength`,
ACK writes through `WriteFrame` again rather than its own entry point, and the three ECN counts are
one nullable value.

**Correction — the original wording of this criterion was self-contradictory.** It also demanded an
unchanged gate count with no test deleted or renamed, which cannot hold at the same time as ACK
rejoining `WriteFrame`: two tests existed solely to assert that `WriteFrame` *always throws* for ACK,
and that is exactly the behaviour this task removes. The implementer spotted the contradiction rather
than quietly picking a side, which is the right outcome.

The honest bar for a behaviour-preserving refactor is not an untouched test list but this: **every
removed test must have lost its subject, not its coverage.** A test whose scenario the new design
makes *unrepresentable* is a design improvement — the bug became impossible instead of merely
watched. A test whose scenario is still reachable but no longer asserted is lost coverage and a
defect. State which of the two each removal is, and where the surviving coverage went.

## Task 3b: STREAM and CRYPTO frames

**Files:** create `TlsQuicStreamFrames.cs` per the amended file layout, and tests.

RFC 9000 §19.8 STREAM, §19.6 CRYPTO.

- **STREAM has eight wire forms**, selected by the three low bits of its type: OFF, LEN and FIN. Each combination changes which fields are present. All eight must round-trip and all eight need hand-built expected bytes.
- A STREAM frame without LEN extends to the end of the packet — the same "implicit length" rule that made short headers subtle in A1.
- CRYPTO is the anchor for RFC 9001 A.2. Assert the published 245-byte frame parses to the expected offset and length.

**Amendment after task 2 — switch the read path to `ReadOnlyMemory<byte>` in task 3a.** Task 1 gave
`TryReadFrame` a `ReadOnlySpan<byte>` payload, which means a frame cannot hold a slice of it, so
task 2 had to store its ACK range chain as a pair of `int` offsets into the payload instead. A1
already solved this: `TlsQuicLongHeader` is a plain `readonly struct` holding `ReadOnlyMemory<byte>`
slices, and `TryReadLongHeader` takes `ReadOnlyMemory<byte>` for exactly that reason — its own
comment says so. **Follow A1, not task 1.** No `ref struct` is needed.

**Fold the ECN counts into a record struct — task 3a.** §19.3.2 makes ECT0/ECT1/ECN-CE
all-present-or-all-absent, so they are one value, not three. `TlsQuicEcnCounts(ulong Ect0, ulong
Ect1, ulong EcnCe)` passed as `TlsQuicEcnCounts?` — the same shape as `TlsQuicAckRange`, already in
the file — makes all-or-nothing presence per §19.3.2 the only representable state, distinguishes
absent from a legitimate all-zero reading, collapses three `TlsQuicFrame` fields into one, and makes
the "type says no ECN but counts are non-zero" contradiction check unrepresentable and therefore
deletable. Net deletion.

**Correction — an earlier version of this paragraph claimed the record struct removes the
transposition hazard "structurally". It does not.** `new TlsQuicEcnCounts(a, c, b)` is exactly as
swappable as the old three-argument call; the hazard moved from the method call to the constructor
call, and both real construction sites are positional. Genuine structural immunity would need three
distinct wrapper types, which is not worth it here. Claim only the four things above — and do not let
a comment in the code claim more, which one did until task 3a's quality review caught it. It waits for this task
because the record struct survives ACK rejoining `WriteFrame` and a plain parameter object would not.

Task 3 is where this stops being optional: CRYPTO and STREAM carry payload bytes, and tasks 4-5 add
NEW_TOKEN, NEW_CONNECTION_ID, PATH_CHALLENGE/PATH_RESPONSE and CONNECTION_CLOSE's reason phrase.
Doing it here converts task 2's two `int` fields into one `Memory` field mechanically, and lets ACK
rejoin `WriteFrame` instead of needing its own entry point. Preserve the zero-copy contract
documented on `ITlsQuicDatagramTransport.ReceiveAsync` and both header structs: parsed fields are
slices of the caller's buffer, and a caller must not reuse or pool it while parsed results are alive.

## Task 4: Flow control frames

**Files:** create `TlsQuicFlowControlFrames.cs` per the amended file layout, and tests. (This line
said "extend `TlsQuicFrames.cs`" until task 4 pointed out the layout table had superseded it.)

RFC 9000 §19.9 MAX_DATA, §19.10 MAX_STREAM_DATA, §19.11 MAX_STREAMS, §19.12 DATA_BLOCKED, §19.13 STREAM_DATA_BLOCKED, §19.14 STREAMS_BLOCKED.

MAX_STREAMS and STREAMS_BLOCKED each have two type values, for bidirectional and unidirectional. §19.11 bounds the stream count; a value above that bound is a protocol violation, not a large number.

## Task 5: Connection management frames

**Files:** create `TlsQuicConnectionFrames.cs` per the amended file layout, and tests.

One mechanical note from task 4, which hit it: naming a flag bit and writing
`case StreamsBlocked | UnidirectionalBit:` **fails to compile** with CS0152 if the base label is also
present, because `0x16` already carries that bit. Spell ranged case labels as `Base | Bit`
consistently, or spell them as literals — but do not mix the two and expect distinct labels.
CONNECTION_CLOSE's `0x1c`/`0x1d` pair has the same shape.

RFC 9000 §19.4 RESET_STREAM, §19.5 STOP_SENDING, §19.7 NEW_TOKEN, §19.15 NEW_CONNECTION_ID, §19.16 RETIRE_CONNECTION_ID, §19.17 PATH_CHALLENGE, §19.18 PATH_RESPONSE, §19.19 CONNECTION_CLOSE.

- CONNECTION_CLOSE has **two forms**, `0x1c` for transport errors and `0x1d` for application errors. The application form has no Frame Type field. §19.19 says which fields each carries.
- NEW_CONNECTION_ID carries a 128-bit stateless reset token and a connection ID whose length §19.15 bounds. Enforce the bound.
- PATH_CHALLENGE and PATH_RESPONSE carry exactly 8 bytes of opaque data. Not a varint-prefixed field — a fixed 8 bytes.

## Task 6: Frame legality by packet type

**Files:** create `TlsQuicFrameLegality.cs`, and tests.

RFC 9000 §12.4 gives a table of which frames may appear in Initial, 0-RTT, Handshake and 1-RTT packets. Encode it as data, not as a switch — it is a table in the RFC and should be a table here, so it can be checked against the source line by line.

§12.5 additionally constrains which frames may appear in which packet number space. Read it and state in your report whether it adds anything §12.4 does not already cover.

Tests: every frame type against every packet type, asserted against the §12.4 table. This is 20 × 4 assertions.

**Clarification, because the original wording here was dangerous.** It said the test "should be a
theory driven by the table itself", which reads two ways — and one of them is a test that cannot
fail. **A test whose expectations are read from the same table it is testing is tautological**: it
asserts the table equals itself and would pass against any transcription error, including a
systematically inverted one. That is this phase's oldest lesson one level up — a round trip proves
the encoder and decoder agree while both are wrong.

The expectations must be an **independent transcription of the RFC's own Table 3 `Pkts` column**,
written into the test by hand from the extract, and the implementation's table must be a separate
transcription. Two independent readings of the same RFC text, compared. If they disagree, one is
wrong and the test says so — which is the entire point.

The extract is `rfc9000-section12-packets-and-frames.txt`. Both transcriptions are checkable against
it line by line, and a reviewer must do exactly that rather than compare the two transcriptions to
each other.

## Task 7: Fuzz target

**Files:** modify `tools/SharpTls.Fuzz/ProtocolFuzzTargets.cs`.

Add a `quic-frames` target following the `quic-packets` pattern established in A1 — which includes, mandatorily:

- **Call every parser unguarded.** No boundary helper. These are `Try`-shaped and must never throw.
- **Print a per-parser reachability breakdown**, as `quic-packets` does. A clean run without reachability numbers cannot distinguish "every branch anchored" from "nothing reached".
- **Seed from real structural inputs** — the A.2 CRYPTO frame, one instance of every frame type built by the encoder, a packet payload containing several frames in sequence.
- **Add a `VerifyQuicFrameSeeds()` self-check**, as A1 did, so a future refactor cannot silently invalidate a seed.

**Amendment after task 2 — payload fuzzing alone cannot reach the range-decode bounds check.** A
reviewer proved this: it deleted half of `TlsQuicAckRanges`' two-comparison extent check and all 358
tests passed, because the reader always hands the decoder the very buffer it just parsed, so the
length comparison is unreachable from `TryReadFrame` no matter how many payloads you throw at it. An
`ArgumentOutOfRangeException` escaped a `Try` method through that hole.

So this target needs a **second axis**: for each frame the reader accepts, re-decode it against
*re-sliced* views of the payload — every prefix, and an unrelated buffer — not only against the
buffer it came from. Report reachability per axis. A frame-payload-only run that reports a clean
sweep is measuring the axis that was already covered.

**Also add the one permanent allocation test — it belongs here, not in A4.** Task 3b's review
established that `GC.GetAllocatedBytesForCurrentThread` appears in **no file** under `src/` or
`tests/`. Three separate tasks have each written a temporary allocation test, confirmed 0 bytes per
call on the receive path, and deleted it — so the property has been measured three times and is
guarded zero times, and each task's claim rested on a measurement nobody could re-run.

This is not the deferred A4 performance work. Nothing being sized from the attacker-controlled ACK
Range Count is a **denial-of-service defence**, and it was the driver of task 2's whole extent-based
design. A defence with no regression test is one refactor away from being gone, and the receive path
is exactly where a future task would not notice.

One test, on `TryReadFrame` over a payload containing several frame types including a multi-range
ACK: warm up, then assert 0 bytes allocated per call.

**Scope it to accepting inputs, and say so in the test.** Task 5's review established why this is a
decision rather than an oversight: `QuicVariableLengthInteger` exposes no `TryRead`, only a throwing
`Read`, so **every malformed frame allocates a `TlsQuicTransportException` and its message.** The
success path allocates nothing; the rejection path allocates once per rejected frame.

Do **not** add `TryRead` in this task. It touches every A1 packet-layer caller as well as A2, and it
is the same hoisting work as the other per-packet allocation items already deferred — it is recorded
in the handoff's A4 list as item 5, flagged as attacker-triggerable rather than merely wasteful,
since a flood of malformed frames is a flood of exception allocations.

**Correction before you start: Tests does not project-reference the fuzz tool.** A note here assumed
it did. `tests/SharpTls.Tests/SharpTls.Tests.csproj` **source-links** `ProtocolFuzzTargets.cs` via
`<Compile Include=… Link=…>`, so that file compiles into *both* assemblies and the same source becomes
two distinct CLR types. Source-linking a shared vectors file is therefore an established working
pattern here — but **anything passing a vector type across the assembly boundary will not compile**,
because each side sees its own type. Share the bytes, not the type. Both assemblies carry
`InternalsVisibleTo`, so internals access itself is fine.

**And create the shared home for RFC vectors — this task is where the current arrangement breaks.**
Task 3b needed RFC 9001 A.2's 245-byte CRYPTO frame, which `TlsQuicPacketProtectionTests` already
had, and reused it by widening that constant to `internal` rather than transcribing 245 bytes a
second time. That was the right call — a typo in a re-transcription yields a test passing against a
wrong expectation — but it does not survive contact with this task: **`tools/SharpTls.Fuzz/` is a
different assembly, where `internal` on a test class does nothing.** This target needs A.2 as a seed,
so discover it now rather than mid-task. Somewhere both the test project and the fuzz tool can reach,
holding the vectors verbatim with their RFC citation.

## Done when

- Every frame type in §19 encodes to hand-derived bytes and parses back.
- RFC 9001 A.2's CRYPTO frame and PADDING run parse correctly.
- The §12.4 legality table is encoded as data and tested exhaustively.
- No parser throws for any input, proven by a fuzz target that reports its reachability.
- The encoder emits frames in exactly the order given, with no merging or reordering.
- `dotnet test --filter "FullyQualifiedName~Quic"` green.

## Not in this phase

Loss detection, congestion control and ACK *generation* policy (A3). Connection and stream state machines (A4). This phase decides nothing about when a frame is sent — only how it is written and read.
