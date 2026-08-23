# Subsystem A3 scoping: QUIC loss recovery and congestion control

Date: 2026-08-21
Status: scoping plan. Not a spec, not an implementation.
Parent: `docs/superpowers/specs/2026-08-16-quic-transport-scoping.md` lines 63-80 (the A3 sketch)
Models for structure and rigour: `docs/superpowers/plans/2026-08-19-quic-c-http3-scoping.md`,
`docs/superpowers/plans/2026-08-20-quic-b-fingerprint-spec-scoping.md`
Gate this closes: `../../../TlsClient-main/docs/HTTP3-EVALUATION.md` condition 2

**Purpose:** answer *"what has to exist before HTTP/3 can ship in TlsClient"* with a dependency
chain rather than a date, cost it, and — the thing this document adds over reading RFC 9002 —
say which of A3's values are **fingerprint knobs** and which are **pure algorithm**.

**Read-only note:** this document was produced without touching `src/` or `tests/`, the index, or
history. Every claim about the tree was checked with a read or a grep, and the grep is named.

---

## Why A3 is now required, and why it was deferred

`TlsClient-main/docs/HTTP3-EVALUATION.md` is TlsClient's own HTTP/3 entry gate, dated 2026-07-21.
Its condition 2 (extract lines 34-37) requires *"QUIC v1 packet parsing/protection, packet-number
recovery, ACK/loss/PTO, congestion control, Retry, connection IDs, flow control, stream state, key
discard/update, connection close, and transport-parameter validation… implemented with strict
bounds."* **ACK/loss/PTO and congestion control are A3, and they do not exist.** Today a single
lost packet ends an attempt, because nothing retransmits — `TlsQuicConnectionOptions.cs:73-82`
states it in the source's own words: *"A4-minimal has no loss detection and no PTO, so a single
lost packet stalls the handshake forever with no diagnosable error… IT IS A TIMEOUT, NOT A
RETRANSMISSION."*

A3 was deferred by the user on measured evidence, and the reasoning was sound at the time.
`HANDOFF-http3-quic.md:643-650` records the reorder: *"the goal that pays for this work is a
fingerprint measured against a live endpoint, and A3 is loss detection and congestion control,
which one handshake and one GET against a cooperative server on a good link does not need."* It
also records the cost, in the same paragraph: *"Fine for a measurement you can retry; not fine for
anything that ships or that anyone depends on. A3 lands before either."*

**That evidence is one path on good days to two cooperative endpoints.** The user has now decided
it is not sufficient for a shipped client. This document states that reasoning and does not
re-litigate it. What it does do is record the evidence accurately, because the brief that
commissioned it did not — see Finding 0.

---

## The short answer

| Milestone | Tasks | Derived from |
| --- | --- | --- |
| A3, enough that a lost packet is **repaired** (retention, RTT, loss, PTO, retransmission) | **9** | tasks A3-0 … A3-8 below |
| plus congestion control, which condition 2 names as a separate clause | **+3** | tasks A3-9, A3-10, A3-11 below |
| plus the evidence: a readout, and a live run **under induced loss** | **+2** | tasks A3-12, A3-13 below |
| the timing-capture arm — the knobs no fingerprint endpoint can see | **+1** | task A3-14 below |

9 + 3 = **12 tasks to make a lost packet survivable and the window bounded.**
12 + 2 = **14 with the evidence that says it works.** 14 + 1 = **15 with the unverifiable arm.**
Every figure is the length of a list in this file.

**The range is 12 to 15 and the four things that drive it are named in *The estimate and its
uncertainty*.** One of them — whether a timer can be woven into `TlsQuicConnection`'s single loop
without splitting it — is not bounded by any RFC and is the only term that can move the number a
lot. The source has already predicted it: `TlsQuicApplicationSendPath.cs:57-61` says a delayed ACK
*"has to fire without a datagram to trigger it, which means either a second thread of control or a
timeout woven into the receive await — the first breaks that invariant, and the second is
loss-recovery scheduling, which is A3's."*

**And one thing that is not an uncertainty, though the sketch makes it look like the biggest one.**
The sketch's parenthesis reads *"no network, deterministic simulation"*, and the tree has no
implementation of `ITlsQuicDatagramTransport` that can drop, reorder or duplicate anything —
see Finding 4. That is a task, not a risk. It is A3-1, it is the first task after the extract, and
it is small because the decorator shape already exists in the tree.

---

## Findings from planning — read these before the tasks

Eleven. Each changes a task, and six of them contradict something a prior document asserts — three
of those contradict this document's own brief. A4's plan found eight during planning, C's found ten
and B's found eleven; all three said that section was worth more than the tasks. This follows the
same practice.

### Finding 0 — the deferral evidence is 54 attempts with zero loss events, not ninety with one

This document's brief says *"roughly 90 live attempts with one loss event."* Both halves are wrong,
and the direction matters: the sample is **smaller** than the brief believes and the outcome is
**cleaner**.

The running total is stated in the tree, not inferred here.
`reference-captures/2026-08-20-sharptls-b11-live-run-through-the-factory.md:73`: **"Running total
for the A3-deferral evidence: 0 failures in 54 attempts"**. It reconciles from four runs, and the
list is what produces the figure:

| Run | Attempts | Loss-induced failures | Recorded in |
| --- | --- | --- | --- |
| A4 task 13, handshake only | 10 | 0 | `HANDOFF-http3-quic.md:219` |
| C13, full GET + 4,955-byte response | 20 | 0 | `reference-captures/2026-08-20-sharptls-c13-live-http3.md:36-37` |
| B11 order probe | 12 | 0 | `reference-captures/2026-08-20-sharptls-b11-perk-order-probe.md:54` |
| B11 through the factory | 12 | 0 | `…-b11-live-run-through-the-factory.md:51` |

10 + 20 + 12 + 12 = **54**, and the failure column sums to **0**.
`QuicPublicEndpointInteropTests.cs:1394-1396` carries the same list as the test's own printed
readout — *"Prior totals, for the running A3 evidence: A4 task 13 0/10, C13 0/20, the order probe
0/12"* — which is 42 plus that run's own 12.

**There is one recent live failure and it is emphatically not loss.** `HANDOFF-http3-quic.md`'s
"OPEN AND URGENT" section records that at `bea2654`
`AnHttp3RequestReturnsTheLiveFingerprintFromBothEndpoints` **fails 5/5** with H3_SETTINGS_ERROR
(`0x109`) — and states the disqualification in the tree's own words: *"`discarded=0`,
`idle_timed_out=False`, `initial_datagrams=1`, so it is **not** loss and **not** a flake."* It is a
`max_datagram_frame_size` advertisement mismatch, which is B's and C17's, not A3's.

**Why this changes a task rather than merely correcting a number.** A3-13's done-when cannot be
"the live run stops failing", because the live run's current failure is not A3's to fix and would
credit A3 with someone else's repair. And a deferral resting on 54 clean attempts is resting on a
number small enough that **one** loss event would have moved it — which is the honest argument for
building A3 now, and it is stronger than the brief's version. *A zero out of 54 is not evidence that
loss is rare; it is evidence that nobody has yet run this on a bad path.* -> tasks A3-13, A3-1.

### Finding 1 — retention is a parameter nobody passes, not a mechanism nobody built

The brief asks whether anything retains sent packets today. The answer is more favourable than
"no", and it changes A3-3 from a build into a wiring.

`grep -rn "List<TlsQuicSentPacket>\|_sentPackets\|sentPackets\|inFlight\|BytesInFlight" src/ --include=*.cs`
returns **4** lines, all in `TlsQuicDatagramBuilder.cs`:

- `:121` — `BuildDatagram(…, ICollection<TlsQuicSentPacket>? sentPackets = null)`
- `:267` — `sentPackets?.Add(sent);`
- `:301` — the same optional parameter on the second overload
- `:372` — the second overload forwarding it

So the collection seam **already exists and is already populated when supplied**. And nobody
supplies it: `grep -rn "sentPackets\|BuildDatagram\|BuildInitialFlight" src/SharpTls/Quic/TlsQuicConnection.cs src/SharpTls/Quic/TlsQuicApplicationSendPath.cs`
finds the connection calling `BuildDatagram(_options.Spec, packets, now, _sendBuffer)` at `:2249`
and `:2496` — **four arguments, the optional fifth omitted at both call sites.**

`TlsQuicPacketBuilder.cs:6-14` says this was deliberate: *"A4-minimal builds one of these per
packet and discards it… Emitting this record now is what makes A3 an insertion — it stores the
values in a list — instead of a rewrite of this builder."* The prediction holds. A3-3 passes a list.

**One thing that record deliberately does not carry, and it is the half of retransmission that is
real work.** `TlsQuicPacketBuilder.cs:33-46`: *"WHAT IT DELIBERATELY DOES NOT CARRY… the CRYPTO
stream byte range this packet carried… RETRANSMISSION DOES, and the answer is that it comes off the
send side by offset rather than by replaying this record: RFC 9000 s13.3 says lost CRYPTO data is
retransmitted, not that the packet is."*

So the split is: **A3-3 retains what RFC 9002's `SentPacket` needs** (level, packet number, size,
ack-eliciting, in-flight, sent-at — the six fields of `TlsQuicSentPacket`, counted from its
constructor at `TlsQuicPacketBuilder.cs:55-61`), and **A3-8 owns the byte bookkeeping separately**.
Merging them would put a second copy of the CRYPTO offset next to `CustomTlsQuicClient`'s
`_initialWriteOffset` and `_handshakeWriteOffset` (`CustomTlsQuicClient.cs:43-44`), which is the
divergence the builder's remark refuses. -> tasks A3-3, A3-8.

### Finding 2 — `TlsQuicAckTracker` is a receive-side tracker and A3 extends it at a point it names

The brief asks what the tracker does and does not do, so that A3-4 extends rather than duplicates.
Established from `sed -n '640,760p' src/SharpTls/Quic/TlsQuicAckTracker.cs` and its file header
(`sed -n '1,120p'`).

**What it does.** It answers *when* to send an ACK and *which numbers* it names: `OnPacketReceived`,
`TryBuildAck`, per-space received ranges, the ack-eliciting-pending flag, `ack_delay` scaled by
**our own** advertised exponent. Its header states its own scope: *"WHEN to send an ACK frame, and
which packet numbers it names — RFC 9000 s13.1, s13.2 and s13.2.5. The complement of
TlsQuicAckFrames."* All three packet-number spaces are indexed (`SpaceOf(level)`), which is
§12.3's split, and `AckRangeLimit` is wired.

**What it does not do, in its own words at `:668-686`, labelled `A3'S INSERTION POINT`:**

- **RTT sampling.** *"Nothing here does that, because a sample also needs the send time of the
  acknowledged packet, which lives in the sent-packet list A3 owns."* And it names the exact trap:
  §13.2.5's ACK Delay is decoded with the **peer's** `ack_delay_exponent`, *"the mirror of the value
  `TlsQuicAckTracker(int, int)` takes."*
- **Loss detection**, and §13.1's *"treat receipt of an acknowledgment for a packet it did not send
  as a connection error of type PROTOCOL_VIOLATION, if it is able to detect the condition"* —
  deferred because *"detecting it needs the set of packets actually sent, which this class does not
  have."*

`ProcessAckFrame` today does exactly two things: it validates the range chain via
`TlsQuicAckFrames.TryGetRanges(frame, decoded: null, …)` and advances `LargestAcked` /
`LargestAckedAt`. The `decoded: null` is deliberate and is A3's hook: *"When A3 does need the ranges
it passes a list here and nothing else changes"* (`:729`).

**So A3-4 is an insertion at a documented seam, not a new class**, and the three things it must add
— the peer's exponent, the ranges list, and the sent-packet lookup — are each already named at the
line that will change. **Item 11 of the parent scoping ("ACK generation state") is not A3's; it
shipped.** The sketch's list does not claim it, and this finding exists so nobody re-scopes it.

Packet-number spaces likewise: `TlsQuicPacketNumber.cs` (**102** lines, `wc -l`) is complete for
Appendix A.2/A.3 truncation and decoding and needs nothing from A3. The gate's phrase
*"packet-number recovery"* is satisfied by that file plus the tracker's per-space
`LargestAcked`; what condition 2 is missing is the clause after it. -> task A3-4.

### Finding 3 — item 18 is mislabelled: §8.1's limit is a *server's*, and the client MUST it hides is a PTO probe

This is the single largest correction in this document, and the brief asks the wrong question about
it. The brief says *"check whether A4 already implements it before scoping it again."* The answer is
that A4 implements the half a client owes, and A3 owes a different half that the sketch's one-line
item does not name.

`rfc9000-section8-address-validation-and-amplification.txt` **is** in the tree — the brief's
confirmation is correct. Reading it past the wrap (extract lines 33-59) gives three sentences and
they assign three different owners:

1. *"Prior to validating the client address, **servers** MUST NOT send more than three times as
   many bytes as the number of bytes they have received."* — **Not ours.** The section closes the
   point at extract lines 68-71: *"In addition to sending limits imposed prior to address
   validation, servers are also constrained in what they can send by the limits set by the
   congestion controller. **Clients are only constrained by the congestion controller.**"*
2. *"**Clients** MUST ensure that UDP datagrams containing Initial packets have UDP payloads of at
   least 1200 bytes, adding PADDING frames as necessary."* — **Already shipped.**
   `TlsQuicConnectionSpec.PaddingTarget` (`:324`) rejects anything below `MinimumInitialDatagramSize`
   with *"Below 1200 or above 65527"*, and the extract's own provenance header names this: *"Ground
   truth for phase A4 task 5's padding decision — pad every Initial-carrying datagram to the target,
   not just the first, or a real server can stall mid-flight waiting for more from us."*
3. *"To prevent this deadlock, **clients MUST send a packet on a Probe Timeout (PTO)**; see Section
   6.2 of [QUIC-RECOVERY]. Specifically, the client MUST send an Initial packet in a UDP datagram
   that contains at least 1200 bytes if it does not have Handshake keys, and otherwise send a
   Handshake packet."* — **This is A3's, it is a MUST, and it is a sub-clause of the PTO task.**

So sketch item 18 ("Anti-amplification limit (RFC 9000 §8.1)") should not produce a task that
implements a limit. It produces a **done-when clause on A3-7**: a client with no Handshake keys
whose PTO fires must emit an Initial packet in a ≥1200-byte datagram, and one with Handshake keys
must emit a Handshake packet. The reason it is worth this much text: implementing a three-times
byte counter on a client would be **unreachable by construction**, and A2's standing rule is that a
surviving mutation is unwitnessed, unreachable, or vacuous — this one would be all three, and it
would look like conformance. -> task A3-7.

### Finding 4 — nothing in the tree can drop, reorder or duplicate a datagram, and the sketch's central claim is false past the first flight

The parent scoping's A3 gate (lines 72-74) reads: *"Loss, reordering and duplication are simulated
by a test implementation of `ITlsQuicDatagramTransport` — the interface subsystem D already shipped.
No network needed."* The interface did ship. The implementation does not exist, and the double the
brief points at cannot be it.

`grep -rn ": ITlsQuicDatagramTransport" src/ tests/ --include=*.cs` returns **6** implementations.
Against what A3 needs:

| Implementation | Can drop? | Can reorder? | Can duplicate? |
| --- | --- | --- | --- |
| `TlsQuicUdpDatagramTransport` | only by real network luck | — | — |
| `TlsQuicSocks5Transport` | same | — | — |
| `InMemoryDatagramTransport` (`tests/…:44`) | **no** | **no** | **no** |
| `ScriptedDatagramTransport` (`tests/…:81`) | by omission only | Initial level only | Initial level only |
| `RecordingTransport` (`QuicPublicEndpointInteropTests.cs:816`) | no — it observes | — | — |
| `NullTransport` (`TlsQuicConnectionOptionsTests.cs:216`) | n/a | n/a | n/a |

**`InMemoryDatagramTransport` is a lossless pair by construction.** `CreatePair()` (`:61`) wires two
endpoints to each other's channel; the only drop it has is `MisdirectedSends` (`:84`), which counts
datagrams *addressed elsewhere*. There is no impairment hook of any kind.

**`ScriptedDatagramTransport` has a hard ceiling the sketch's claim runs straight into**, and it
says so itself (`:41-52`): *"It **cannot** fabricate a Handshake or 1-RTT packet: those keys descend
from the client ephemeral share, which differs on every run, so a fabricated one never decrypts…
**Record-and-replay is dead past the first flight, and no amount of scripting rescues it.**"* Its own
list of what does live there ends the argument: *"reordering and duplication **at Initial level**…
all live here because each is pre-key-agreement or purely temporal."*

**A3 is overwhelmingly about Handshake and 1-RTT packets.** So the vehicle is not a script; it is a
**decorator between two real endpoints that agree keys** — `LoopbackQuicPeer` over
`InMemoryDatagramTransport`, with an impairing wrapper in the middle. And the decorator shape is
already in the tree: `RecordingTransport` (`QuicPublicEndpointInteropTests.cs:815-856`) is exactly
that shape, wrapping an inner transport and forwarding both directions. A3-1 writes a second one.
It is small because the pattern exists, not because impairment is easy.

**A second half of the same gap, and it is a trap with a note already on it.** `ManualTimeProvider`
(`ScriptedDatagramTransport.cs:23`) overrides `GetUtcNow` **only**, and its remarks (`:16-21`) name
the consequence for exactly this phase: *"FOR THE PHASE THAT ADDS TIMERS: this overrides `GetUtcNow`
only, so `CreateTimer` falls through to the base implementation and schedules against the real
clock. A test that awaits a timer built from this waits in wall-clock time and flakes… **Whoever
adds a timer overrides `CreateTimer` too, or the determinism this seam exists for is gone.**"* A3 is
that phase. -> tasks A3-1, A3-5.

### Finding 5 — the single loop is the architectural risk, and A4 has already written the prediction down

`TlsQuicApplicationSendPath.cs:29-72` re-decides A4's delayed-ACK row and closes it for A4 — *"the
timer is not missing work, it is work this shape does not need"* — on four lettered points. Point
(c) is the one that binds A3:

> *"A TIMER IS AN ARCHITECTURE CHANGE, NOT A TUNING KNOB. `TlsQuicConnection`'s remarks open with
> 'ONE LOOP, ONE THREAD OF CONTROL' and name it as what satisfies `CustomTlsQuicClient`'s and
> `TlsQuicPacketReceiver`'s shared-state requirements. A delayed ACK has to fire without a datagram
> to trigger it, which means either a second thread of control or a timeout woven into the receive
> await — the first breaks that invariant, and the second is loss-recovery scheduling, which is
> A3's."*

Every A3 timer has the same shape: a loss-detection timer and a PTO both fire **with no datagram to
trigger them**. `TlsQuicConnection.cs` is **2853** lines (`wc -l`) and C's Finding 10 already found
that reshaping `PumpOnceAsync` for a send-first entry point was a task of its own (14c), for
attributability. A3 reshapes it again, for a *wake-on-deadline* entry point.

**So A3-5 is sequenced as its own task, before any timer has a customer.** This is the same call C
made for 14c and A4 made for task 4a, and it exists so that a failure is attributable to the weave
or to the algorithm and not to both.

It also reopens something A4 closed. Point (c)'s conclusion holds *"only if it adds a send path that
runs between received datagrams often enough for batching to remove packets rather than add delay."*
A3 adds exactly that. **The delayed-ACK decision must therefore be re-decided a third time**, and
whether it stays immediate is a fingerprint choice — see the knob table. -> tasks A3-5, A3-12.

### Finding 6 — `kInitialRtt` is not 333ms here, because the value is already a knob and already advertised

RFC 9002 §6.2.2 gives `kInitialRtt = 333ms` as the PTO base before any RTT sample exists. Copying it
would be the mistake this project has already refused twice.

`TlsQuicConnectionSpec.InitialRttRange` (`:575`) is `(TimeSpan Minimum, TimeSpan Maximum)?` and B5
gave it a consumer:
`TlsQuicTransportParameterSpec.Brave151InitialRttRange` (`:421-422`) ships
`(100000µs, 300000µs)` as the range the preset draws `initial_rtt` (parameter 12583) from, marked
UNVERIFIED. The Brave capture (line 91) records one observed draw of **192859µs ≈ 193ms**.

**333ms and 193ms are different numbers, and a client that advertises one while retransmitting on
the other is self-contradictory on the wire.** RFC 9002's constant is the interoperable default;
Chromium's is what it puts in parameter 12583. So A3's PTO base reads
`TlsQuicConnectionSpec.InitialRttRange`, and RFC 9002's 333ms is the value the knob falls back to
when the range is null — which is its shipped default (`_initialRttRange` at `:180`, no
initialiser).

**And there is a live inference in the tree that may invert this dependency entirely.**
`uquic-u_parrot-chrome-random-initial-rtt.txt` — the only capture whose name matches any recovery
term — records uQUIC's `ChromeRandomInitialRTT()` as uniform over `[1000, 20000)` microseconds, and
then refuses to adopt it, in a banner: *"THE OBSERVED 192859 IS OUTSIDE THIS RANGE. THIS FUNCTION
DOES NOT SETTLE `Brave151InitialRttRange`."* Its reading of the two data points is the interesting
part: *"there are now two single draws from the real world — 7740 us (uQUIC's Chrome 146 pcap) and
192859 us (this repo's Brave 151 capture) — a factor of 25 apart, and BOTH inside the range of a
plausible measured network RTT. **The simplest reading consistent with both is that Chromium reports
a path-derived RTT estimate rather than drawing a random number**, in which case there is no fixed
distribution to copy."*

**If that reading is right, `initial_rtt` is A3's *output*, not A3's input** — it is what an RTT
estimator seeded from a cached prior connection to that host would produce, and `InitialRttRange` is
a stand-in for a cache A3 could actually build. The capture is explicit that this is *"an inference
from two data points; it is NOT established here"*, so nothing is decided on it. But it is why
A3-2's knob must be shaped as *a source of an initial RTT* rather than *a constant*, and why A3-14's
capture request must ask for two connections to the same host in sequence — which is the one
experiment that distinguishes a draw from an estimate. -> tasks A3-2, A3-7, A3-14.

### Finding 7 — `max_ack_delay` is absent from Chromium's fourteen parameters, and its absence is the binding value

The capture's transport-parameter table (`2026-08-16-brave-151-http3-impersonate-pro.md`, the table
headed *"QUIC transport parameters, in wire order"*) lists **14** entries and
`max_ack_delay` (0x0B) is not among them — the identifiers present are 12584, GREASE, 32, 9, 8, 7,
5, 15, 17, 1, 6, 4, 12583, 3. The identifier exists in our codec
(`TlsQuicProtocol.cs:172`, `MaxAckDelay = 0x0B`) and in nothing else:
`grep -rn "MaxAckDelay" src/SharpTls/Quic/*.cs` finds that one line.

So Chromium takes RFC 9000 §18.2's default. That default is the ceiling **our peer** is entitled to
assume for us, and it is the `max_ack_delay` term in §6.2.1's PTO formula. Two consequences:

- **A3's PTO arithmetic has a term whose value comes from a parameter nobody sends.** Reading it as
  "absent, therefore zero" would compute a PTO shorter than the peer's, which is the failure mode
  §6.2.1's term exists to prevent. The extract, not a memory of the default, is what A3-0 must
  make checkable.
- **Whether we honour the delay or beat it is a fingerprint choice.** `TlsQuicApplicationSendPath`'s
  point (a) records the current decision — *"max_ack_delay is honoured by being beaten rather than
  by being scheduled against"* — and Finding 5 says A3 reopens it. Chromium does not acknowledge
  every 1-RTT packet immediately. -> tasks A3-0, A3-5, A3-12.

### Finding 8 — the knob seam is already decided, and it is not where A3's instinct would put it

`TlsQuicConnectionOptions.cs`'s remarks state the rule in one sentence: *"Neither timeout below is a
fingerprint knob: they gate when this client gives up and change no byte a peer or an observer sees.
**Layout knobs live on `TlsQuicConnectionSpec` and nowhere else.**"*

That sentence sorts every A3 value for free, and it sorts them the opposite way from where a
recovery implementer would reach:

- A value that changes **what an observer sees** — a timer that decides when a retransmission leaves,
  a window that decides how many packets go out before the first ACK, an algorithm that shapes the
  send rate — belongs on **`TlsQuicConnectionSpec`**, beside `PaddingTarget` and `InitialRttRange`,
  even though none of it is "layout" in the ordinary sense.
- A value that only decides **when this client gives up** — the handshake deadline, the idle timeout,
  a maximum probe count before abandoning — belongs on **`TlsQuicConnectionOptions`**.

`grep -cE '^    public ' src/SharpTls/Quic/TlsQuicConnectionSpec.cs` returns **18** today (B's
Finding 8 counted 17; B1 added `TransportParameters` at `:746`, and 17 + 1 = 18 reconciles). A3 adds
a nested spec rather than eighteen more properties, following `LocalFlowControl` (`:714`) and
`TransportParameters` (`:746`), which are the two precedents for a sub-spec on this type.

**One knob already moved out of the "inert" column and the B plan has not caught up.** B's standing
rules say *"`InitialRttRange` and `AckRangeLimit` are both present-but-inert."* For `AckRangeLimit`
that is now stale: `TlsQuicConnection.cs:555-557` records it in the past tense — *"so
`TlsQuicConnectionSpec.AckRangeLimit` **was** a present-but-inert knob"* — immediately above
`_acks = new TlsQuicAckTracker(options.AckDelayExponent, options.Spec.AckRangeLimit);`, and
`TlsQuicConnection.cs:102` carries the mutation row *"17. AckRangeLimit not wired to the tracker
[WAS-SURVIVOR] -> now ONLY TheSpecsAckRangeLimitBoundsTheRangesThatReachTheWire."* A3 inherits a
wired knob, not an inert one. -> task A3-2.

### Finding 9 — three frame types already record a lost-frame debt aimed here, and one is a stall rather than a slowdown

`grep -rnw "A3" src/ tests/ --include=*.cs` returns **62** lines across **14** files
(`grep -rlw "A3" src/ tests/ --include=*.cs | wc -l`). Most are
"A3 will do this"; three are specific debts A3-8 must discharge, and they are not the same shape:

- **CRYPTO.** `TlsQuicPacketBuilder.cs:33-46`, quoted in Finding 1: lost CRYPTO *data* is resent by
  offset, and `CustomTlsQuicClient` holds the only copy as it advances `_initialWriteOffset` /
  `_handshakeWriteOffset` (`:43-44`). **A lost CRYPTO frame today ends the handshake.**
- **STREAM.** `TlsQuicStreams.cs` handles *receiving* a retransmission — `:632`, `:664`, `:747`,
  `:759`, `:795` all reason about overlapping offsets — and retains nothing of its own sends. So
  the receive half of retransmission exists and the send half does not.
- **MAX_STREAM_DATA, and this one is the trap.** `TlsQuicStreams.cs:120-126`: *"AND A LOST GRANT IS
  A STALLED TRANSFER, WHICH IS A3's AND NOT THIS TASK'S. A grant is computed once per threshold
  crossing, so if the datagram carrying it is lost the peer stops at the old limit, sends nothing
  more, and nothing on this side crosses a threshold again — the two ends wait on each other."* And
  it names the wrong fix: *"a receiver that re-sent grants on a timer would be duplicating A3's loss
  detection in one frame type's private schedule."*

**A lost grant is a deadlock, not a delay**, and it will present as a hung response body rather than
a slow one. That distinction has to be in A3-8's done-when, because a test that only measures
throughput under loss would pass a build that never repairs a grant. RFC 9000 §13.3 is the authority
on which frames are resent and **it is not in this repo** — `TlsQuicApplicationSendPath.cs:287-292`
says so at the one place it is cited: *"NOT QUOTED, BECAUSE s13.3 IS NOT IN THIS REPO'S REFERENCE
CAPTURES: `rfc9000-section13-packetization-and-ack-generation.txt` stops inside s13.2, so this
citation is weaker than the ones around it."* -> tasks A3-0, A3-8.

### Finding 10 — RFC 9002 is not captured, and the one file whose name matches is not it

The brief's task zero, verified.
`ls docs/superpowers/specs/reference-captures/ | grep -i "9002\|recovery\|congestion"` returns
**nothing**. Widening it to `"9002\|recovery\|congestion\|rtt\|loss\|pto"` returns exactly **one**
line — `uquic-u_parrot-chrome-random-initial-rtt.txt` — which matches on `rtt` alone, is Go source
code rather than RFC text, and is Finding 6's subject. **No RFC 9002 text is in this repository.**

`ls docs/superpowers/specs/reference-captures/` returns **55** entries, **51** of them `.txt`
extracts (`ls …/*.txt | wc -l`). Every one of the 51 was produced by the same method, and A3-0
follows it. Against what A3 cites:

| Source | Needed for | Present? |
| --- | --- | --- |
| RFC 9002 §5, §5.1-§5.3 (RTT: `latest_rtt`, `min_rtt`, `smoothed_rtt`, `rttvar`) | sketch item 13, task A3-4 | **no** |
| RFC 9002 §6, §6.1 (loss detection, both thresholds), §6.1.1, §6.1.2 | sketch item 14, task A3-6 | **no** |
| RFC 9002 §6.2, §6.2.1-§6.2.4 (PTO, backoff, **§6.2.2.1 before address validation**, probe contents) | sketch item 15 + Finding 3, task A3-7 | **no** |
| RFC 9002 §7, §7.1-§7.8 and Appendix B (NewReno, the three states, pacing at §7.7, persistent congestion at §7.6) | sketch items 16-17, tasks A3-9 … A3-11 | **no** |
| RFC 9002 Appendix A (the variables and the pseudocode) and Appendix B (the constants) | every task's recomputation base | **no** |
| RFC 9000 §13.3 Retransmission of Information | Finding 9, task A3-8 | **no** — and the tree says so at `TlsQuicApplicationSendPath.cs:288` |
| RFC 9000 §8.1 | Finding 3, task A3-7 | **yes** — `rfc9000-section8-address-validation-and-amplification.txt`, §8.1 complete through §8.1.4 |
| RFC 9000 §13.2 (ACK generation), §12.3 (spaces) | already consumed by the tracker | **yes** — `rfc9000-section13-packetization-and-ack-generation.txt`, `…-section12-packets-and-frames.txt` |

**Six extracts needed, one already present.** Note the last row's shape: §13.2 is captured and §13.3
is not, in the *same* RFC, because the existing extract's range stops mid-section. That is a range
to extend, not a new topic, and A3-0's done-when has to treat it as a distinct artefact anyway.

### Finding 11 — RFC 9002's pseudocode is a trap this project has already named twice

The sketch's gate says *"RFC 9002 gives all of this as pseudocode, so conformance tests can follow
it line by line."* The handoff repeats it (`:662-664`): *"RFC 9002 gives all of it as pseudocode, so
this is transcription plus conformance tests."*

**Transcription plus a round trip is exactly the evidence shape this project has twice ruled
insufficient.** C's Finding on Huffman states the general form: *"A transcription error in a 257-row
table is invisible to a round trip — the encoder and decoder would share it."* The same holds here
and is worse, because **RFC 9002 publishes no test vectors at all.** There is no
`rfc9001-appendix-a-test-vectors.txt` equivalent for recovery: no published `(sequence of ACKs,
expected congestion window)` pair anywhere in the document.

So A3's evidence has to come from somewhere other than agreement with itself, and there are exactly
three sources available, in descending strength:

1. **An independent implementation.** `System.Net.Quic.QuicListener` over MsQuic is already A4 task
   10's fixture and is genuinely foreign code. Under induced loss, an MsQuic peer that completes a
   transfer is evidence our recovery is *interoperable*; it is not evidence our window is
   *Chromium's*.
2. **Invariants recomputed rather than compared.** `smoothed_rtt` must lie between `min_rtt` and the
   largest sample; the window must never fall below the minimum; bytes-in-flight must return to zero
   when everything is acknowledged. These kill real bugs and are checkable without a vector.
3. **A packet capture** — A3-14, and the only thing that settles the knobs.

**And the standing rule bites hardest here.** *A done-when clause is a floor, not a ceiling*: a
mutant that hard-coded the capture's pseudo-header order passed C9's stated done-when. The recovery
analogue is a controller that returns a constant window — it satisfies "the window never falls below
the minimum" and every arithmetic invariant, and it fails only a test that drives loss and asserts
the window *moved in the right direction at a named event*. Every congestion task's done-when below
names that event. -> tasks A3-9, A3-10, A3-13.

---

## The fingerprint dimension — which A3 values are knobs, and which are pure algorithm

This is the section this document exists for, and it is the one thing reading RFC 9002 does not
give you.

**The user's standing directive, carried from the B1 amendment:** *"no placeholder values,
everything must be configurable if different clients/browsers/apps/systems could send a different
value. don't forget the final goal of this library is to reproduce pretty much any fingerprint
given, if the stack allows it."*

**The discriminator, stated once and applied below.** A value is a **knob** if two conforming clients
could differ on it in a way an observer can distinguish — as bytes on the wire, or as timing between
datagrams. A value is **pure algorithm** if changing it is a defect rather than a difference.
RFC 9002 itself draws this line: §7 makes congestion control explicitly replaceable, and Appendix B's
constants are RECOMMENDED, not MUST. **Recovery is the layer where the RFC most loudly says "this is
one choice among several", and it is therefore the layer with the highest knob density in the whole
QUIC stack.**

### The knobs

Every row is a settable value on `TlsQuicConnectionSpec`'s A3 sub-spec (Finding 8), shipping a cited
preset value where the capture bounds one and an **UNVERIFIED** preset value where it does not —
never refused, never silently invented.

| # | Knob | Why an observer can see it | Source for the preset |
| --- | --- | --- | --- |
| 1 | **Initial RTT** (`kInitialRtt`) | decides *when* the first retransmission leaves, before any sample exists. Directly timeable off two datagrams | **already a knob**: `InitialRttRange` (`:575`), preset `Brave151InitialRttRange` = 100-300ms, UNVERIFIED. Finding 6 |
| 2 | **Initial congestion window** (`10 * max_datagram_size`) | how many datagrams go out before the first ACK. B9's two-datagram Initial already sits at this boundary | RFC 9002 App. B default; Chromium's is **UNVERIFIED** — A3-14 |
| 3 | **Minimum congestion window** (`2 * max_datagram_size`) | the floor a heavily-lossy path settles at; changes steady-state pacing | same |
| 4 | **The congestion controller itself** — NewReno / CUBIC / BBR | the send-rate curve under loss. **The largest single fingerprint in A3.** Chromium ships BBR; RFC 9002 §7 ships NewReno | §7's own replaceability clause. Which one Chromium runs is **UNVERIFIED** here |
| 5 | `kLossReductionFactor` (0.5) | NewReno halves on loss; BBR does not. Visible in one recovery episode | RFC 9002 App. B |
| 6 | `kPacketThreshold` (3) | reordering tolerance — decides whether a reordered packet triggers a retransmission at all | RFC 9002 §6.1.1 |
| 7 | `kTimeThreshold` (9/8) | the same, on the time axis | RFC 9002 §6.1.2 |
| 8 | `kPersistentCongestionThreshold` (3) | how long a blackout must last before the window collapses to the minimum | RFC 9002 §7.6 |
| 9 | **PTO backoff base and cap** | the exponential's shape, and whether it is capped. Two clients diverge by the third probe | RFC 9002 §6.2.1; the cap is implementation choice |
| 10 | **Probes per PTO** (1 or 2) | §6.2.4 permits either. Byte-countable | RFC 9002 §6.2.4 |
| 11 | **What a probe packet contains** — PING, PING+PADDING, or retransmitted data | byte-observable in the clear-ish (size) and after decryption | §6.2.4 leaves it open |
| 12 | **ACK policy: immediate vs delayed to `max_ack_delay`** | ACK packet counts and their spacing. Currently "immediate at every level" by A4's decision, which A3 reopens | Finding 5, Finding 7. Chromium's is **UNVERIFIED** |
| 13 | `AckRangeLimit` | how many ranges an ACK frame carries under reordering | **already a knob and already wired** (`:640`, `TlsQuicConnection.cs:557`) |
| 14 | **Pacing on/off, and the pacer's burst size** (§7.7) | whether a window's worth leaves as a burst or spread over an RTT. Very visible | RFC 9002 §7.7 (a SHOULD, not a MUST). Chromium paces |
| 15 | **The pacing rate scale** — §7.7's `N` | the *gap* between the datagrams row 14 sizes. Row 14 decides how many leave together; this decides how fast the next allowance arrives, and a pcap measures the gap directly | RFC 9002 §7.7's `rate = N * congestion_window / smoothed_rtt`, whose only stated bound is "small, but at least 1 (for example, 1.25)". **UNVERIFIED** — A3-14 |

**Fifteen knobs**, counted from the rows of that table.

**Row 15 was added by task A3-11 and the arithmetic below moves with it.** The table shipped
with fourteen rows because §7.7 was read as one choice; building the pacer showed it is two
independent settings, since the burst and the refill rate are separately observable and a caller
who can set only the burst cannot change the spacing at all — neither `congestion_window` nor
`smoothed_rtt` is settable. Folding it into row 14 would have been the cheaper edit and a false
one. **Task A3-12's readout is therefore 15 + 2 = 17 rows**, not 16: one per knob, plus the
controller's identity, plus the ACK policy. Its `not-yet-known-from-the-capture` count moves
from four to **five** — the initial congestion window, the controller identity, the ACK policy,
the pacing burst size, and now the pacing rate scale.

### The pure algorithm

Changing any of these is a bug, not a fingerprint, and none becomes a knob.

| # | Fixed | Why it is not a knob |
| --- | --- | --- |
| 1 | The `smoothed_rtt` and `rttvar` update weights (§5.3) | the estimator's arithmetic. Not separably observable across one connection; RFC 9002 states them as the algorithm |
| 2 | `min_rtt` tracking, and §5.3's rule not to subtract `ack_delay` below `min_rtt` | a correctness guard against a lying peer |
| 3 | §5.1's rule that a sample comes only from a newly-acknowledged, ack-eliciting, largest-acknowledged packet | conformance |
| 4 | The per-space separation of loss timers and PTO (§6.2.1, §12.3) | structure. `TlsQuicAckTracker` already indexes by space |
| 5 | `kGranularity` (1ms) | a **platform** timer-resolution floor, not a browser property. A knob here would express what clock the machine has |
| 6 | The PTO formula `smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay` | the shape is fixed; the terms inside it are rows 1, 5 and 9 above |
| 7 | The persistent-congestion duration formula (§7.6) | the shape is fixed; only its threshold (knob 8) varies |
| 8 | Slow start / recovery / congestion avoidance state transitions | the state machine, distinct from its constants |
| 9 | RFC 9000 §13.3's frame-by-frame table of what is retransmitted | correctness. *Whether a retransmission is bundled with new data* is observable, but the table is not |
| 10 | §19.3's irrevocability of acknowledgement, and ACK-range validation | already shipped in `TlsQuicAckTracker.ProcessAckFrame` |

**Ten fixed items**, counted from the rows of that table.

### The honest caveat, and it is the whole of A3-14's reason

**No fingerprint endpoint this project can reach sees any of the fourteen knobs.** The `perk` string
has four segments — h3 SETTINGS, pseudo-header order, transport parameters in wire order, CID
lengths — and **not one of them is a timing field.** The capture's own list of what the service does
not inspect (lines 30-33) names six things; timing is not on it, because timing is not in the
format at all.

Two consequences, and they pull opposite ways exactly as B's Finding 3 did.

- **For any hash-based gate this collapses to nothing.** A3 can ship with all fourteen knobs at
  RFC 9002's defaults and no published hash moves. There is no measurement that fails.
- **For a packet-capture diff it is the largest remaining surface in the project.** B12 owed six
  values; A3 owes fourteen, and unlike B's they are *behavioural* — they show up on every
  connection that loses a packet rather than only in the opening flight. **A wrong answer here looks
  exactly like a right one**, which is B's Finding 5 restated for a different layer.

So every knob above ships **settable**, with its preset marked UNVERIFIED where nothing bounds it,
named in A3-12's readout third column, and named by A3-14 as something a capture must settle.
Refusing to emit is not an option and neither is a silent default: the B1 amendment's exact words
are *"the knob still exists, is settable, and is emitted; the preset's choice for it is marked
unverified… What is forbidden is refusing to emit the parameter, or picking a number with no
comment."*

---

## What A3 inherits, concretely

Verified against the source, not assumed.

| Concern | Where | State |
| --- | --- | --- |
| A per-packet record with RFC 9002's `SentPacket` fields | `TlsQuicSentPacket` (`TlsQuicPacketBuilder.cs:55`) | complete — 6 fields, built per packet |
| A retention seam on the builder | `TlsQuicDatagramBuilder.cs:121`, `:267`, `:301` | **complete and never supplied** — Finding 1 |
| Per-space received-packet tracking and ACK generation | `TlsQuicAckTracker` | complete; **receive side only** — Finding 2 |
| ACK-frame range validation, `LargestAcked`, `LargestAckedAt` | `ProcessAckFrame` (`:711`) | complete; RTT and loss are the declared gap at `:668` |
| Truncated packet-number encode/decode | `TlsQuicPacketNumber.cs` (102 lines) | complete (A4 task 4b) |
| A clock seam every deadline already reads | `TlsQuicConnectionOptions.TimeProvider` | complete — *"The QUIC sources contain no other clock today"* |
| §8.1's client padding MUST | `TlsQuicConnectionSpec.PaddingTarget` (`:324`), floor 1200 | complete — Finding 3 |
| An independent peer for interop evidence | `System.Net.Quic.QuicListener` (A4 task 10) | complete |
| An in-process peer that genuinely agrees keys | `LoopbackQuicPeer` over `InMemoryDatagramTransport` | complete, **and lossless** — Finding 4 |
| A transport-decorator pattern to copy | `RecordingTransport` (`QuicPublicEndpointInteropTests.cs:816`) | complete |
| `AckRangeLimit` wired to the tracker | `TlsQuicConnection.cs:557` | complete — Finding 8; B's "inert" note is stale |
| `InitialRttRange` with a consumer | `TlsQuicConnectionSpec.cs:575` + B5's preset | **advertised, not yet consumed by any timer** — Finding 6 |
| A datagram transport that can drop, reorder or duplicate | — | **absent** — Finding 4 |
| A `TimeProvider` that drives `CreateTimer` deterministically | — | **absent** — Finding 4 |
| A sent-packet list, bytes in flight, any congestion window | — | **absent** |
| Retransmission of any frame, at any level | — | **absent** — Finding 9 |
| RFC 9002 text, in any form | — | **absent** — Finding 10 |

---

## Task A3-0: extract the RFC sections A3 needs

**Files:** new files under `docs/superpowers/specs/reference-captures/`, matching the convention of
the 51 `.txt` extracts already there (`ls docs/superpowers/specs/reference-captures/*.txt | wc -l`).

**Method, unchanged from A4 task 0, C0 and B0:** fetch from `https://www.rfc-editor.org/rfc/rfcNNNN.txt`
inside the sandbox, locate the heading in the document *body* past the table of contents, `sed` the
range, prepend a provenance header in the established shape (see
`rfc9000-section6-version-negotiation.txt`'s first twelve lines: title with the exact subsections
covered, source URL and date, *why* it was captured, and `Copy these values; do not retype them.`),
then **diff the committed body line by line against an independent re-fetch of the same range**,
trimming only trailing whitespace.

Six extracts, and the count is the length of this list:

1. **RFC 9002 §5, §5.1-§5.3** — `latest_rtt`, `min_rtt`, `smoothed_rtt`, `rttvar`, and §5.3's
   `ack_delay` rules. Sketch item 13.
2. **RFC 9002 §6, §6.1, §6.1.1, §6.1.2** — packet threshold and time threshold. Sketch item 14.
3. **RFC 9002 §6.2, §6.2.1-§6.2.4** — PTO, backoff, probe contents, **and §6.2.2.1 "Before Address
   Validation", which is the other end of Finding 3's client MUST.** Sketch item 15.
4. **RFC 9002 §7, §7.1-§7.8** — congestion control including §7.6 persistent congestion and §7.7
   pacing. Sketch items 16-17, and knobs 2-5, 8 and 14.
5. **RFC 9002 Appendix A and Appendix B** — the pseudocode variables and the constants. **Appendix B
   is what makes every constant in the knob table recomputable rather than recalled**, which the
   handoff's list at `:662-665` currently is.
6. **RFC 9000 §13.3 Retransmission of Information** — Finding 9. This is an **extension** of an
   existing extract: `rfc9000-section13-packetization-and-ack-generation.txt` stops inside §13.2,
   which `TlsQuicApplicationSendPath.cs:288` already records as a weakness in its own citation.

**RFC 9000 §8.1 is already present** and needs nothing: `rfc9000-section8-address-validation-and-amplification.txt`
covers §8.1 complete through §8.1.4 (`grep -n "^8\." on the extract returns §8.1, §8.1.1, §8.1.2,
§8.1.3, §8.1.4`). Finding 3 turns on two sentences inside it, both past their line wrap.

**Say what has no vector, at the top of extract 5.** RFC 9002 publishes **no test vectors** —
nothing corresponding to RFC 9001 Appendix A or RFC 9204 Appendix B. Finding 11 is why that sentence
belongs in the extract's provenance header rather than only in this plan: a later implementer
reaching for "the published vector" must find the statement that there is none before they invent
one from a round trip.

**Done when** every new extract diffs at zero mismatches against an independent re-fetch of the same
range; each carries a provenance header naming the exact subsections it covers; extract 6 is
verified not to overlap or contradict the existing §13.2 extract at the seam; and extract 5's header
states plainly that RFC 9002 publishes no test vectors, naming Finding 11's three substitute
evidence sources.

---

## Task A3-1: the impairing transport, and a clock that drives timers

**Files:** a new file under `tests/SharpTls.Tests/Quic/`, and tests.
**Model:** `RecordingTransport` (`QuicPublicEndpointInteropTests.cs:815-856`) for the decorator
shape; `ManualTimeProvider` (`ScriptedDatagramTransport.cs:23-30`) for the clock.

Finding 4: no implementation of `ITlsQuicDatagramTransport` in the tree can drop, reorder or
duplicate, and the double the sketch points at cannot fabricate a Handshake or 1-RTT packet at all.
**First, because every later task's done-when is unwritable without it.**

Two things, together because a loss harness whose timers run on the wall clock is not deterministic
and would flake exactly where A3 needs precision:

1. **An impairing decorator** over any inner `ITlsQuicDatagramTransport`, driven by a *script* of
   verdicts rather than a probability — deterministic means reproducible, and a seeded RNG is a
   second thing to keep in step with a failure report. Drop the *n*th datagram; hold the *n*th and
   release it after the *m*th; deliver the *n*th twice. Placed between two `LoopbackQuicPeer`
   endpoints, which do agree keys, so it reaches Handshake and 1-RTT where the script cannot.
2. **A `TimeProvider` that overrides `CreateTimer`** as well as `GetUtcNow`, so a PTO fires at a
   known fake instant with zero wall-clock elapsed. `ManualTimeProvider`'s own remarks demand this
   of *"the phase that adds timers"* and A3 is it. Whether this extends `ManualTimeProvider` or
   replaces it is an implementation call; what is not optional is that one clock drives both the
   script and the connection.

**Done when** a `LoopbackQuicPeer` handshake completes with the decorator in the path and no
impairment scripted, byte-identically to one without it — so the decorator is proved inert before
anything relies on it being active; each of drop, reorder and duplicate is witnessed **at
Handshake and at 1-RTT level**, not only at Initial, which is the level `ScriptedDatagramTransport`
cannot reach and the reason this task exists; a timer created from the clock fires at a fake instant
with the test's wall-clock duration bounded well below it, with a witness; the same script run twice
produces the same sequence of deliveries, asserted from the recorded order; and a test drops a
datagram and asserts the connection **fails** — pinning today's behaviour before A3-8 changes it,
so that the improvement is attributable rather than assumed.

---

## Task A3-2: the recovery spec seam

**Files:** a new `TlsQuicRecoverySpec.cs` (or equivalent) reached from `TlsQuicConnectionSpec`, and
tests. No behaviour.
**Model:** `TlsQuicLocalFlowControlSpec` (`TlsQuicConnectionSpec.cs:714`) and
`TlsQuicTransportParameterSpec` (`:746`) — the two existing sub-specs on this type.

The same seam A4 task 1, C1 and B1 created for their layers. **Every one of the fourteen knobs in
the table above exists here and is settable**; the ten pure-algorithm items do not appear.

Shape, and each clause is forced by a finding rather than chosen:

- **The initial RTT is not a constant.** It reads `TlsQuicConnectionSpec.InitialRttRange` (`:575`),
  which B5 already populates and advertises as parameter 12583, falling back to RFC 9002's
  `kInitialRtt` only when the range is null — which is its shipped default. Finding 6. **A second
  number here would be a second place to keep in step with an advertisement, which is the exact
  defect `TlsQuicConnectionSpec.cs:690-700` records from the flow-control values.**
- **`max_ack_delay` comes from the transport parameters**, ours and the peer's, not from a constant
  in this file. Finding 7: Chromium sends no such parameter, so the §18.2 default applies and must
  be read from the extract.
- **The congestion controller is a seam, not an enum.** Knob 4 is a *choice of algorithm*; an enum
  with one member is the unrequested abstraction this repo's rules forbid, and an enum with three
  members two of which throw is worse. One interface, one shipped implementation (A3-9), and the
  seam's own doc comment naming BBR as what a caller would supply.
- **`AckRangeLimit` is not re-declared.** It exists at `:640` and is wired. Finding 8.

**Every varying field is a knob, per the B1 amendment.** Where RFC 9002 Appendix B bounds a default,
take it and cite the extract line. Where nothing bounds Chromium's — knobs 2, 4, 12 and 14 — **the
knob still exists and is settable**, its preset carries a doc comment marking it UNVERIFIED and
naming A3-14 as the task that would settle it, and it goes in A3-12's third column. The struck
"declared placeholder" remedy from B1 does not return.

**Done when** every one of the knob table's fourteen rows is a settable member reachable from
`TlsQuicConnectionSpec`, and a test derives that count from the rendered member list rather than
asserting fourteen beside it; validation rejects out-of-range values with a **reachability witness
per rejecting branch**; a spec whose `InitialRttRange` is non-null produces a PTO base drawn from it
and not from `kInitialRtt`, with a witness per branch — **and a mutant that reads `kInitialRtt`
unconditionally is killed by that test, because it would otherwise pass every arithmetic invariant
in A3-7**; each UNVERIFIED preset's doc comment names A3-14 and a test asserts that task reference
resolves to a task in this document; and a grep of the task's own diff finds no numeric recovery
constant outside the preset block.

---

## Task A3-3: retain sent packets, and count bytes in flight

**Files:** `TlsQuicConnection.cs`, and tests. **No change to `TlsQuicDatagramBuilder.cs`** —
Finding 1 shows the parameter is already there.
**RFC:** 9002 Appendix A (the `SentPacket` fields and `bytes_in_flight`); 9000 §12.3 (the three
spaces); §13.2.7 (a PADDING-only packet is in flight and elicits nothing).

Pass an `ICollection<TlsQuicSentPacket>` at `TlsQuicConnection.cs:2249` and `:2496`, retain it per
packet-number space, and remove entries on acknowledgement.

Three things the retention must get right, each because the record already encodes the distinction
and a list that flattens it would discard information the builder deliberately kept:

1. **Per space, never merged.** `TlsQuicSentPacket.Level` plus `PacketNumber` identify a packet;
   the number alone does not. `TlsQuicAckTracker.SpaceOf` already does this mapping and is the one
   that must be reused rather than re-derived.
2. **`IsInFlight` and `IsAckEliciting` are different questions.** §13.2.7 makes a PADDING-only
   packet in flight for congestion purposes and ack-eliciting for none.
3. **Discard on key discard.** RFC 9002 §6.4: when a packet-number space's keys are discarded, its
   sent packets go with them. A retained Initial packet that outlives its keys is an unbounded leak
   on a connection that never completes.

**Done when** a packet sent and then acknowledged leaves the list, and bytes in flight returns to
**exactly** zero, asserted after a complete `LoopbackQuicPeer` handshake — this is the invariant
Finding 11 names and it kills an off-by-one no round trip would; an ACK in one space does not remove
a packet from another, with a witness per space pair; a PADDING-only packet is retained as in-flight
and not as ack-eliciting, with a witness per flag; discarding a level's keys empties that space's
list, with a witness; and a mutant that retains packets and never removes them is killed by the
returns-to-zero test rather than by inspection — **a test that only asserts "the list is non-empty
after sending" would pass it.**

---

## Task A3-4: RTT estimation

**Files:** `TlsQuicAckTracker.cs`, and tests.
**RFC:** 9002 §5, §5.1-§5.3 (extracted at A3-0); 9000 §13.2.5 and §19.3 for the ACK Delay field's
scaling.

The insertion at the point `TlsQuicAckTracker.cs:668` labels `A3'S INSERTION POINT`. Finding 2: it
needs three things it names itself, and A3-3 supplied the third.

- **Pass the ranges.** `TryGetRanges(frame, decoded: null, …)` becomes a real list. `:729` promises
  *"nothing else changes"*; this task is where that promise is tested.
- **Decode `ack_delay` with the PEER'S exponent**, not ours. This is the trap
  `TlsQuicConnectionOptions.cs:168-177` and the tracker's header both spell out at length: our
  exponent scales ACKs we **send**, the peer's decodes ACKs we **receive**, and *"a mismatch is
  silent in both directions: both values are legal, every frame still parses."* The peer's value
  arrives on `TlsQuicPeerTransportParametersEvent` and today only `MaxIdleTimeout` is retained off
  it — C's Finding 6, closed for the six flow-control values by task 14d; `ack_delay_exponent` is
  a seventh and must be checked rather than assumed retained.
- **Sample only from the largest newly-acknowledged ack-eliciting packet** (§5.1), and apply §5.3's
  guard that `ack_delay` is not subtracted when the result would fall below `min_rtt`.

**Done when** a scripted RTT sequence produces `latest_rtt`, `min_rtt`, `smoothed_rtt` and `rttvar`
whose values are recomputed from §5.3's formulas in the test rather than compared against a table of
expected numbers — **there is no published vector (Finding 11), so recomputation is the only honest
form**; `smoothed_rtt` provably lies between `min_rtt` and the largest sample for a long random
sequence, which is an invariant a constant-returning mutant fails; a peer advertising an exponent
different from ours is decoded by **theirs**, with a witness that using ours produces a different
and wrong sample — the mismatch is otherwise silent and no other test can see it; §5.3's
below-`min_rtt` guard fires with a witness, driven by a peer reporting an implausibly large
`ack_delay`; an ACK naming a packet we never sent is detectable now that A3-3 retains the set, and
§13.1's PROTOCOL_VIOLATION is either raised or its non-raising is a stated decision; and no
existing `TlsQuicAckTrackerTests` case changes behaviour, since this task adds and does not alter.

---

## Task A3-5: the timer weave — one loop, and a deadline that fires without a datagram

**Files:** `TlsQuicConnection.cs`, and tests.
**RFC:** none directly — this is architecture, and it is sequenced alone for exactly that reason.

Finding 5. `TlsQuicConnection.cs` is 2853 lines and its remarks open with *"ONE LOOP, ONE THREAD OF
CONTROL"*, which `TlsQuicApplicationSendPath.cs:57-61` names as what satisfies
`CustomTlsQuicClient`'s and `TlsQuicPacketReceiver`'s shared-state requirements. Every A3 timer
fires with no datagram to trigger it.

Add a **wake-on-deadline** entry to the pump: the receive await races an earliest-deadline timer, and
when the timer wins the loop runs a send pass with no datagram received. The single thread of control
is preserved — this is the second of the two options point (c) names, and the one it assigns to A3.

**Split out from every algorithm task deliberately**, exactly as C split 14c from 14b and A4 split
task 4a from 4b: a failure after a bundled change is unattributable between the weave and the
recovery logic, and this file has an 85-row mutation ledger whose header arithmetic a reviewer must
be able to rebuild.

**One thing this task must not do:** decide the ACK policy. It merely makes a delayed ACK *possible*
and thereby reopens the row `TlsQuicApplicationSendPath.cs:29-72` closed for A4. Whether A3 keeps
acknowledging immediately is knob 12 and is A3-2's and A3-12's, not this task's. The source's own
condition for reopening — *"a send path that runs between received datagrams often enough for
batching to remove packets rather than add delay"* — is satisfied by this task, and that sentence
must be updated at `TlsQuicApplicationSendPath.cs` rather than left standing on a premise this task
removes.

**Done when** a test drives the connection to send with **no datagram received and no datagram
pending**, purely on a deadline, with the fake clock advanced by A3-1's provider and wall-clock time
bounded well below the deadline; the existing handshake-deadline and idle-timeout tests are green
with no behaviour change, since both already ride this loop; a timer that fires while a datagram is
being processed does not produce two concurrent send passes, with a witness — **this is the
invariant "one thread of control" names and the only way to lose it is a race no arithmetic test
sees**; the mutation ledger's header arithmetic still reconciles after the rows this task adds; and
`TlsQuicApplicationSendPath.cs`'s point (c) is amended rather than left contradicted.

---

## Task A3-6: loss detection

**Files:** a new recovery file, `TlsQuicAckTracker.cs`, and tests.
**RFC:** 9002 §6, §6.1, §6.1.1 (packet threshold), §6.1.2 (time threshold) — extracted at A3-0.
**Knobs:** 6 (`kPacketThreshold`), 7 (`kTimeThreshold`), 5 (`kGranularity`, which is *fixed* — see
the pure-algorithm table row 5).

Declare a packet lost when it is more than `kPacketThreshold` behind the largest acknowledged in its
space, or older than `kTimeThreshold * max(smoothed_rtt, latest_rtt)`. Arm the loss-detection timer
for the earliest un-declared packet.

**Point at the extract; quote no pseudocode.** RFC 9002 §6.1 gives this as an algorithm and the
temptation is to paste it. The rule this project earned is that a transcription checked only against
itself is unchecked; §6.1's two thresholds are knobs 6 and 7 and are read from A3-2's spec, so the
test recomputes the boundary from the spec object rather than from a literal.

**Done when** a packet dropped by A3-1's decorator and then skipped by `kPacketThreshold` later
acknowledgements is declared lost at the boundary and **not one packet earlier**, with a witness on
each side of the threshold — a one-sided test passes an off-by-one; the time threshold fires at
`kTimeThreshold * max(smoothed_rtt, latest_rtt)` recomputed from A3-2's spec and A3-4's estimator
rather than from a literal, with a witness at the boundary; a **reordered but not lost** packet that
arrives late is **not** declared lost, which is the case the whole threshold exists to protect and
which A3-1's reorder script is the only thing in the tree that can produce; loss in one space does
not declare loss in another, with a witness per space pair; and a mutant that declares every
unacknowledged packet lost immediately is killed by the reordering test — **it passes every "loss is
detected" test and fails only this one.**

---

## Task A3-7: probe timeout, and §8.1's anti-deadlock probe

**Files:** the recovery file, `TlsQuicConnection.cs`, and tests.
**RFC:** 9002 §6.2, §6.2.1 (the formula), §6.2.2 and **§6.2.2.1 (before address validation)**,
§6.2.3, §6.2.4 (probe contents); **RFC 9000 §8.1, extract lines 48-59, read past the wrap** —
Finding 3.
**Knobs:** 1 (initial RTT, from `InitialRttRange`), 9 (backoff base and cap), 10 (probes per PTO),
11 (probe contents).

PTO = `smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay`, per space, with exponential
backoff on each expiry and a reset on a new acknowledgement.

**Three things this task must get right that the sketch's one line does not name.**

1. **The base before any sample is `InitialRttRange`, not `kInitialRtt`.** Finding 6. A client that
   advertises parameter 12583 at ~193ms and retransmits on 333ms is contradicting its own
   advertisement, and both numbers are on the wire.
2. **`max_ack_delay` is the peer's advertised value, and Chromium advertises none.** Finding 7:
   the §18.2 default applies, read from A3-0's extract. Treating an absent parameter as zero
   computes a PTO shorter than the peer's own budget, which is what the term exists to prevent.
3. **§8.1's client MUST is this task's, and it is the whole of sketch item 18.** Extract lines
   48-59: *"To prevent this deadlock, clients MUST send a packet on a Probe Timeout (PTO)…
   Specifically, the client MUST send an Initial packet in a UDP datagram that contains at least
   1200 bytes if it does not have Handshake keys, and otherwise send a Handshake packet."*
   **Do not implement a three-times byte counter.** Finding 3: that limit binds servers, the
   section closes *"Clients are only constrained by the congestion controller"*, and a counter here
   would be unreachable by construction while reading as conformance.

**Done when** the PTO is recomputed from A3-4's live estimator and A3-2's knobs in the test rather
than compared against a literal; a connection with **no RTT sample at all** arms its first PTO from
`InitialRttRange` and not from `kInitialRtt`, with a witness per branch — Finding 6, and this is the
clause a straight RFC transcription fails; backoff doubles across consecutive expiries and **resets**
on a new acknowledgement, with a witness per direction; a PTO firing with **no Handshake keys**
emits an Initial packet in a datagram of at least 1200 bytes, and one firing **with** Handshake keys
emits a Handshake packet, each with its own witness, and each citing §8.1's sentence at the emitting
line; the probe's frame contents follow knob 11 rather than a constant, with the same PTO producing
two different probes under two specs; a PTO does not fire while nothing is in flight **unless** the
§8.1 anti-deadlock case applies, with a witness for the distinction — **the two are easy to conflate
and conflating them either spams probes or reintroduces the deadlock §8.1 exists to break**; and a
mutant that arms the PTO but never re-arms it after the first expiry is killed by the backoff test.

---

## Task A3-8: retransmission — what is actually re-sent

**Files:** `TlsQuicConnection.cs`, `CustomTlsQuicClient.cs`, `TlsQuicStreams.cs`, and tests.
**RFC:** 9000 **§13.3**, extracted at A3-0 — Finding 9 and `TlsQuicApplicationSendPath.cs:288`
record that it is absent today; §12.4 Table 3 for level legality, already encoded as data.

**The task the sketch does not have.** Items 13-18 are RTT, loss, PTO, congestion, persistent
congestion and amplification — **none of them re-sends anything.** Detecting loss and repairing it
are different tasks, and a phase that shipped 13-18 exactly as written would detect a loss it could
not repair.

§13.3's rule is that lost **information** is retransmitted, not lost **packets**. Three carriers,
each with a different owner, from Finding 9:

- **CRYPTO** — resent by offset. `CustomTlsQuicClient` advances `_initialWriteOffset` and
  `_handshakeWriteOffset` (`:43-44`) and hands over the only copy, so this task is where the send
  side starts retaining. `TlsQuicPacketBuilder.cs:37-46` already states the design: the byte range
  is deliberately **not** on `TlsQuicSentPacket`, because *"a range here would be a second place to
  keep in step with the first."*
- **STREAM** — resent by offset. `TlsQuicStreams` already handles *receiving* a retransmission
  (`:632`, `:664`, `:747`, `:759`, `:795` all reason about overlapping offsets); the send half is
  new.
- **MAX_STREAM_DATA and the other flow-control grants** — and **this one is a deadlock, not a
  slowdown.** `TlsQuicStreams.cs:120-126`: *"A grant is computed once per threshold crossing, so if
  the datagram carrying it is lost the peer stops at the old limit, sends nothing more, and nothing
  on this side crosses a threshold again — the two ends wait on each other."* It also rules out the
  wrong fix: *"a receiver that re-sent grants on a timer would be duplicating A3's loss detection in
  one frame type's private schedule."*

And the frames that are **not** resent: `TlsQuicApplicationSendPath.cs:287-292` already records
PATH_RESPONSE as one, with the §13.3 citation marked weak precisely because the extract is missing.
A3-0 lands it; this task upgrades that comment.

**Done when** a CRYPTO frame dropped by A3-1's decorator is retransmitted and the handshake
**completes**, against `LoopbackQuicPeer` and against `System.Net.Quic.QuicListener` — the foreign
peer is Finding 11's strongest available evidence and a loopback alone would share our bugs; a
dropped STREAM frame is retransmitted and the response body arrives **byte-identical** to the
unimpaired run, compared against that run rather than against a fixture; **a dropped
MAX_STREAM_DATA grant is repaired and the transfer completes rather than stalling**, with the test
asserting completion under a bounded fake-clock deadline — a throughput-shaped test cannot see this
and Finding 9 says so; every frame type §13.3 excludes is **not** retransmitted, with a witness per
excluded type read from the extract and not retyped; the same information is never sent twice
concurrently at two offsets, with a witness; and a mutant that re-sends the whole lost *packet*
rather than its information is killed — **it repairs the transfer and passes every completion test,
and fails only a test that reads the retransmitted frame's offsets back off the wire.**

---

## Task A3-9: NewReno congestion control

**Files:** a new congestion file behind A3-2's seam, and tests.
**RFC:** 9002 §7, §7.1-§7.5, §7.8, and **Appendix B** — extracted at A3-0. Sketch item 16.
**Knobs:** 2 (initial window), 3 (minimum window), 4 (the controller seam), 5
(`kLossReductionFactor`).

Three states — slow start, recovery, congestion avoidance — behind the seam A3-2 declares, with
`bytes_in_flight` from A3-3 as the input and the send path gated on the window.

**Why NewReno and not BBR, stated rather than assumed.** RFC 9002 §7 publishes NewReno and makes
the controller replaceable; **Chromium ships BBR** (knob 4). Building NewReno first is not a
judgement that Chromium runs it — it is that NewReno is the one RFC 9002 specifies, so it is the
one whose correctness is checkable against a document rather than against a guess. The seam is what
makes the eventual answer cheap, and A3-14 is what would tell us which answer is right. **Say so at
the seam**, so nobody later reads the shipped default as a measurement.

**Done when** the initial window, the minimum window and the reduction factor all come from A3-2's
spec and a test drives **two different specs to two different send behaviours**, so the values are
proved to be knobs rather than constants with getters; each of the three state transitions is
witnessed **at the event that causes it** — an ACK in slow start growing the window, a loss entering
recovery, an ACK after the recovery period entering congestion avoidance — because Finding 11's
constant-window mutant satisfies every arithmetic invariant and fails only a test that names the
event; the window never falls below the minimum across a long scripted loss sequence, checked
against the spec object; bytes in flight never exceeds the window on the send path, with a witness
at the boundary; **a transfer completes through the MsQuic listener under a scripted loss pattern**,
which is the only foreign-code evidence available; and the seam's doc comment states that NewReno is
RFC 9002's controller and not a measurement of Chromium's, naming A3-14.

---

## Task A3-10: persistent congestion

**Files:** the congestion file, and tests.
**RFC:** 9002 §7.6 — extracted at A3-0. Sketch item 17.
**Knob:** 8 (`kPersistentCongestionThreshold`).

Detect the blackout §7.6 defines and collapse the window to the minimum. The duration is
`(smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay) * kPersistentCongestionThreshold`
— the **shape** is fixed (pure-algorithm row 7) and the **threshold** is knob 8.

Split from A3-9 because its trigger is a *time* condition over a *sequence* of losses, where §7.5's
is a single loss event, and because it is the one congestion path that only A3-1's scripted
blackout can reach.

**Done when** a scripted blackout spanning the computed duration collapses the window to exactly the
minimum, with the duration recomputed in the test from A3-4's live estimator and A3-2's threshold
rather than from a literal; a blackout **one interval shorter** does **not** collapse it, with a
witness — the one-sided test is what an off-by-one survives; §7.6's requirement that the period be
bounded by two ack-eliciting packets sent at different times is enforced, with a witness, because a
naive implementation collapses on a single loss and every "collapse happens" test would pass it; and
recovery from persistent congestion re-enters slow start, witnessed at that transition.

---

## Task A3-11: pacing

**Files:** the congestion file, `TlsQuicConnection.cs`, and tests.
**RFC:** 9002 §7.7 — extracted at A3-0.
**Knob:** 14 (pacing on/off, and the burst size).

§7.7 is a SHOULD, not a MUST, and **it is the knob with the highest observability-per-line in this
whole document**: whether a window's worth of packets leaves as a burst or spread across an RTT is
visible to anyone holding a pcap and invisible to every hash-based endpoint. Chromium paces.

Sequenced last of the congestion arm because it needs a window to pace *against*, and it rides
A3-5's deadline weave rather than adding a scheduler of its own.

**Done when** pacing on and pacing off produce measurably different send *timings* for the same
window and the same data, measured on A3-1's fake clock so the assertion is exact rather than
statistical; the burst size is read from A3-2's spec with two specs producing two behaviours; pacing
**never** delays a PTO probe, with a witness — §8.1's anti-deadlock probe exists to break a stall and
a pacer that held it would reintroduce exactly the deadlock A3-7 closes; disabling pacing changes no
byte of any packet, only its departure time, asserted by comparing the recorded payloads; and the
knob's doc comment marks Chromium's burst size UNVERIFIED and names A3-14.

---

## Task A3-12: the recovery fingerprint readout

**Files:** `TlsQuicFingerprintReadout.cs` and its snapshot, and tests.
**Model:** the existing readouts and
`tests/SharpTls.Tests/Quic/quic-fingerprint-readout.snapshot.txt`.

Task 11 established that the third column — `not-yet-known-from-the-capture` — was the most valuable
thing a readout produced, because it told subsystem B what to go capture. **A3's readout is almost
entirely that column**, and saying so plainly is the point.

The rows, and the count is the length of the knob table: **14**, one per knob, plus one row
recording **which controller is in force** as a named string rather than a boolean, plus one row
recording the **ACK policy** — immediate or delayed — since Finding 5 makes it a live decision
rather than a constant. **16.**

The rows whose verdict is `not-yet-known-from-the-capture`, counted from this sentence's list: the
initial congestion window; the controller identity; the ACK policy; and the pacing burst size.
**Four.** Every other knob has a value from RFC 9002 Appendix B, which makes it *cited* — but
**cited to the RFC is not the same as matching Chromium**, and the readout must render that
distinction rather than showing a green `match` against a document Chromium is not obliged to
follow. A fourth verdict value, or an explicit "source: RFC 9002 default, not the capture" column,
is this task's design call.

**One thing this readout must not do.** It must not report a `match` for any timing knob, because
**nothing has measured one.** B's Finding 10 rule applies verbatim: growing the table must keep the
arithmetic line reconciling, and scoring a row green because a fixture chose a value is *scoring the
fixture* — which `TlsQuicHttp3FingerprintReadout.cs:96-98` already refuses to do for ALPN.

**Done when** every rendered value is derived from the **connection's live recovery state** and not
from the spec object, with a test in the shape of task 11's
`TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith` proving it cannot be a restatement; the row count
and the verdict counts are derived from the rendered list and their arithmetic line reconciles, per
B's Finding 10; no timing row renders `match` against the capture, with a test that asserts the
absence rather than a reader checking; every UNVERIFIED knob's row names A3-14; and the readout is
rendered after a run **with loss induced**, so the rows describe a controller that actually did
something rather than one that was never exercised.

---

## Task A3-13: the live run, under induced loss

**Files:** extend `tests/SharpTls.Tests/Interop/QuicPublicEndpointInteropTests.cs`.
`SHARPTLS_RUN_INTEROP=1`-gated, never in the gate.

`https://fp.impersonate.pro/api/http3` and `https://tls3.peet.ws/api/all`, through A3-1's impairing
decorator wrapped around the **real** UDP transport, alongside `RecordingTransport`.

**What this task is for, and it is not "the live run passes".** Finding 0: the endpoint currently
fails 5/5 with H3_SETTINGS_ERROR for a reason that is B's and C17's, not A3's, and the handoff says
plainly *"it is **not** loss and **not** a flake."* **A3 must not be credited with repairing someone
else's defect, and must not be blocked by it.** The comparison this task makes is A3-against-A3: the
same endpoint, the same request, with loss induced and with the retransmission path enabled and
disabled.

**Two numbers this run produces that nothing else can.**

1. **The completion rate under a *known* loss rate**, which converts Finding 0's zero-out-of-54 from
   an absence of evidence into a measured curve. Drop 1 datagram in 20, in 10, in 5; record where
   completion falls off.
2. **The real path's *own* loss rate**, measured at last by running long enough for one to happen.
   54 attempts on good days is a sample that has never seen the event it is used to argue about.

**Done when** the completion rate is recorded at no fewer than three induced loss rates plus an
unimpaired control, each with its attempt count, into a new file under `reference-captures/`
alongside the existing four live captures; the **same** scripted loss pattern is run with
retransmission disabled and enabled and both numbers recorded, so the improvement is attributable
rather than asserted; the running A3-deferral total in
`QuicPublicEndpointInteropTests.cs:1394-1396` is extended rather than replaced, and its arithmetic
still reconciles from its list; any failure is classified as loss-induced or not **using the
`discarded` / `idle_timed_out` / `initial_datagrams` counters the existing report already prints**,
which is the classification the handoff used to disqualify the current 5/5; and the report states
plainly that a completion rate against two cooperative endpoints on one path is not a claim about
the internet.

---

## The packet-capture arm — only a real capture settles the knobs

### Task A3-14: acquire the timing capture

**Files:** new files under `docs/superpowers/specs/reference-captures/`; an addendum to
`docs/superpowers/specs/2026-08-20-b12-capture-request.md` rather than a competing request.

**This is B12's capture with four more questions on it, not a second expedition.** B12 already asks
for a packet capture of Chromium's opening flight; A3 needs the same capture to run *longer* and to
lose something. Filing it separately would send someone out twice.

What A3 needs that B12 does not already ask for, and the count is the length of this list:

1. **The initial congestion window** — how many datagrams leave before the first ACK returns
   (knob 2).
2. **The controller's identity** — inferable from the send-rate curve after a loss: a halving is
   NewReno or CUBIC, a probe-and-drain cycle is BBR (knob 4).
3. **The PTO base and backoff** — the interval before the first retransmission on a path where a
   packet was dropped, and the interval before the second (knobs 1, 9, 10, 11).
4. **The ACK policy and pacing** — inter-ACK spacing against `max_ack_delay`'s §18.2 default, and
   whether a window's worth departs as a burst (knobs 12, 14).

**And one experiment that settles Finding 6, which no amount of single-connection capture can.**
Capture **two connections to the same host in sequence**, and compare their `initial_rtt` (12583)
values against the *measured* RTT of the first. If the second connection's advertised value tracks
the first's measured RTT, `initial_rtt` is a path-derived estimate and **A3 produces it rather than
consuming it** — which inverts B5's dependency and makes `Brave151InitialRttRange` a stand-in for a
cache rather than a distribution. If the two are uncorrelated, it is a draw and the range is real.
**Neither the Brave capture nor the uQUIC source can distinguish these**, and
`uquic-u_parrot-chrome-random-initial-rtt.txt` says so in its own conclusion.

**Done when** each recorded artefact carries a provenance header naming what produced it, when, and
what it does and does not settle, in the shape the uQUIC capture established for non-RFC sources;
each of the four items above is either recorded with a value or **explicitly recorded as still
unsettled**, and no value appears without one of those two labels; the two-connection experiment is
recorded with both advertised values and the first connection's measured RTT, whichever way it
comes out; and the report states plainly that an inference from a send-rate curve is weaker evidence
than a byte read off a header, and marks the controller identity accordingly.

---

## Ordering constraint

Each arrow is a hard prerequisite, and the reason is stated.

```
A3-0  extracts                    RFC 9002 is absent entirely and RFC 9000 s13.3 is absent
                                  from an extract that stops mid-section; a citation with no
                                  in-repo extract is not checkable
  -> A3-1  the impairing harness  FIRST after the extracts, because every later done-when
                                  needs to induce a loss, and no transport in the tree can.
                                  ScriptedDatagramTransport cannot reach Handshake or 1-RTT
                                  at all - Finding 4
  -> A3-2  the recovery spec      every later task reads a knob from it, and a knob added
                                  late is a knob whose guard is unwitnessed (C1's rule)
  -> A3-3  sent-packet retention  RTT needs a send time and loss needs a sent set; the
                                  tracker says so itself at TlsQuicAckTracker.cs:668
  -> A3-4  RTT estimation         needs A3-3's send times. Loss and PTO both read its output
  -> A3-5  the timer weave        BEFORE any timer has a customer, so a failure is
                                  attributable to the weave or to the algorithm, not both.
                                  Same reason C split 14c and A4 split task 4a
  -> A3-6  loss detection         needs A3-4's smoothed_rtt for the time threshold and
                                  A3-5's timer to arm
  -> A3-7  PTO + s8.1's probe     needs A3-4's estimator for the formula and A3-5's timer to
                                  fire; s8.1's client MUST is a clause on this task, not a
                                  task of its own - Finding 3
  -> A3-8  retransmission         LAST of the repair arm: it can only re-send what A3-6 and
                                  A3-7 declare lost. Detecting and repairing are different
                                  tasks and the sketch has only the first
  -> A3-9  NewReno                after A3-8, because a controller with nothing to
                                  retransmit has no loss episode to react to
  -> A3-10 persistent congestion  after A3-9: it collapses a window A3-9 defines
  -> A3-11 pacing                 after A3-9: it paces against a window
  -> A3-12 the readout            after A3-11, because a readout of a controller that never
                                  ran is a restatement of the spec - the failure task 11's
                                  TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith prevents
  -> A3-13 the live run           last; the only task needing a network
```

`A3-14` is filed with B12 and can be acquired at any time; it retro-settles four of A3-12's rows and
Finding 6's inversion, which is why those ship as UNVERIFIED knobs rather than as gaps that block.

**The single riskiest ordering assumption**, stated as A4's, C's and B's plans state their own:
**that A3-5's timer weave is an addition to `TlsQuicConnection`'s loop rather than a split of it.**
The whole chain from A3-6 onward assumes a deadline can fire inside the existing single thread of
control. `TlsQuicApplicationSendPath.cs:57-61` names the two options and assigns the second to A3,
but nobody has tried it in a 2853-line file carrying an 85-row ledger. **If the loop must split, the
number is 13 rather than 12 and every task after A3-5 rebases on a shape nobody has reviewed.**
The mitigation is cheap and belongs inside A3-5: **build the deadline entry and drive it with the
existing idle timeout before any recovery code exists.** The idle timeout is already a deadline, it
already rides this loop, and it already has tests. If a deadline cannot be woven for a timer that
already exists, it will not be woven for one that does not.

---

## The estimate and its uncertainty

**12 tasks to make a lost packet survivable and the window bounded. 14 with the evidence. 15 with
the capture arm.** Each figure is the length of a list in this document: A3-0 … A3-8 is 9,
A3-9 … A3-11 is 3, A3-12 … A3-13 is 2, A3-14 is 1. 9 + 3 = 12; 12 + 2 = 14; 14 + 1 = 15.

Four things drive the range, and only the first can move it a lot.

1. **Whether A3-5's timer weave is a refactor or a split — the widest term.** `TlsQuicConnection.cs`
   is 2853 lines with an 85-row mutation ledger whose header arithmetic a reviewer must rebuild, and
   its remarks make "ONE LOOP, ONE THREAD OF CONTROL" load-bearing for two other types'
   shared-state requirements. A4's own history says the honest expectation is a fix round: every
   task in that phase found something, and C's 14c — the last reshaping of this same pump — was
   itself a task carved out of one that did not mention it. **What would measure it: drive the
   existing idle timeout through a new deadline entry before writing any recovery code.** It costs
   a fraction of a session and it is inside A3-5's done-when. If it splits, 12 becomes 13.
2. **Whether retransmission is one task or three.** A3-8 covers CRYPTO, STREAM and the flow-control
   grants, and Finding 9 shows the three have different owners in different files, with the grant
   being a *deadlock* rather than a slowdown. A4's task 14 was one task that turned out to be five
   (C's Finding 1), for exactly this shape of reason: a task named after one file that landed in
   three. If A3-8 splits, 12 becomes 14 or 15.
3. **Whether the endpoint is reachable at all when A3-13 runs.** The live test fails 5/5 today for
   a reason that is B's and C17's (Finding 0). A3-13 does not depend on that being fixed — its
   comparison is A3-against-A3 — but a run that cannot complete even unimpaired measures nothing,
   and then A3's evidence is the MsQuic listener alone. That is weaker but not absent, which is why
   this term is bounded.
4. **Whether NewReno is the right controller to build first.** Knob 4 says Chromium ships BBR. If
   A3-14 comes back saying so unambiguously and a BBR implementation becomes the *actual* target
   rather than a seam nobody fills, that is not one more task — BBR is a phase. It sits outside this
   range deliberately, in *Not in this phase*, because scoping it from a send-rate curve nobody has
   captured would be inventing a number, which is the thing this project refuses.

**What would narrow the range fastest, in order:** drive the idle timeout through a deadline entry
(settles 1, needs no recovery code, and it is the riskiest ordering assumption); then A3-1's
harness, which converts every later done-when from unwritable to writable and is the single largest
unblocking step in the document; then A3-14, which settles four readout rows and Finding 6's
inversion, and which someone is going out for anyway on B12's behalf.

No date is offered. The parent scoping estimated A3 as items 13-18 — six items — and this is 15
over an enumerated list; the difference is not scope creep but the three things items 13-18 do not
mention: **the harness that induces loss, the timer that fires without a datagram, and the
retransmission that repairs what the other five detect.** Every figure in this project that was
asserted rather than derived has moved at least once.

---

## What A3 does not own, and must not be blamed for

| Not A3's | Whose | Why it will look like A3's |
| --- | --- | --- |
| The current 5/5 live failure at `bea2654` | **B / C17** | it is a `max_datagram_frame_size` advertisement mismatch closing with H3_SETTINGS_ERROR; `discarded=0` and `initial_datagrams=1` disqualify loss. Finding 0 |
| **Key update** — condition 2 names it in the same clause | **A4-complete** | the gate's condition 2 lists "key discard/update", and C's ownership table already assigns key update to A4-complete. **A3 is not the only thing failing condition 2** — see Finding 0's note on the brief |
| Path MTU discovery | **A4-complete or never** | a wrong MTU presents as loss on large packets and will be diagnosed as A3 |
| `MAX_STREAMS` never rising | **A4-complete** | `TlsQuicStreams.cs:115-118` records it; a peer that exhausts the stream limit stalls exactly as a lost grant does, and A3-8 does not fix it |
| ECN | **never, or A-complete** | RFC 9002 §7 has ECN paths this document does not scope; nothing in the capture asks for it |
| Connection migration and path validation under loss | **A4-complete** | PATH_RESPONSE is explicitly not retransmitted (§13.3), so a lost one is the peer's to repeat |
| `initial_rtt`'s advertised *range* | **B5 / B12** | A3 consumes it (Finding 6). If A3-14's two-connection experiment inverts the dependency, that is a finding for B, not a defect in A3 |
| Which controller Chromium actually runs | **A3-14, then a later phase** | knob 4 is a seam A3 ships one implementation behind; filling it with BBR is not in this range |

---

## Not in this phase

Each cut names where it lands, per A4's practice.

| Cut | Lands in | What the cut costs |
| --- | --- | --- |
| **A BBR implementation** | **later A3, or never** | knob 4 is the largest fingerprint in this document and A3 ships NewReno behind a seam. The cost is that a packet-capture diff of the send-rate curve will not match Chromium, and A3-12's readout must say so rather than showing green |
| ECN (RFC 9002 §7's ECN paths, RFC 9000 §13.4) | **A-complete** | an ECN-marking path degrades us to loss-based recovery, which is correct but not Chromium's |
| Path MTU discovery (RFC 9000 §14.2-§14.3) | **A4-complete** | a wrong MTU produces loss A3 will faithfully repair, forever, instead of reducing the packet size |
| Retransmission of 0-RTT data | **never, in this client** | A4-minimal never sends 0-RTT and C never asks for it |
| A prior-RTT cache keyed by host | **later, and only if A3-14 inverts Finding 6** | if `initial_rtt` is path-derived, this is what would produce it honestly. Scoping it now would be building for an inference the capture explicitly does not establish |
| Congestion control across multiple connections to one host | **never** | outside RFC 9002 and outside the fingerprint |
| A delayed-ACK *timer* as opposed to the *decision* | **A3-5 makes it possible; knob 12 decides it** | keeping immediate ACKs is legal and is a fingerprint difference from Chromium. Recognising that this is a cut with a cost is the point |
| Making the fourteen knobs public API | **E** | B's ownership table already records that all three type declarations in `TlsQuicConnectionSpec.cs` are `internal`. A3's are too |

---

## Standing rules carried in

The eighteen from `2026-08-17-quic-a2-frame-layer.md`, plus A4's amendments, C's additions and B's
three, transfer whole. The seven that bite hardest here:

- **Never write a count you cannot recompute from a list.** Every figure here names the grep or the
  list that produces it: 54 live attempts as 10 + 20 + 12 + 12 with 0 failures, 55 capture files of
  which 51 are `.txt`, 6 implementations of `ITlsQuicDatagramTransport` of which 0 can impair, 4
  lines matching the sent-packet grep all in one file, 62 word-boundary `A3` hits across 14 files,
  18 public members on `TlsQuicConnectionSpec`, 6 fields on `TlsQuicSentPacket`, 14 knobs, 10 fixed
  items, 16 readout rows of which 4 are not-yet-known, 6 extracts, 12 / 14 / 15 tasks.
- **A constant nobody can check is not allowed** — as amended by B1 and not as originally written.
  The "declared placeholder" remedy does not survive. **Every one of the fourteen knobs exists, is
  settable and is emitted**; where nothing bounds Chromium's value the preset is marked UNVERIFIED
  in its own doc comment, names A3-14, and goes in A3-12's third column. What is forbidden is
  refusing to emit, or picking a number with no comment.
- **Point at the extract; never restate a field layout or a constant.** This document quotes **no
  RFC 9002 pseudocode**, which is the specific temptation this phase carries — the sketch's own gate
  says *"conformance tests can follow it line by line"*, and Finding 11 is why that is not enough on
  its own.
- **The extracts are hard-wrapped at ~72 columns.** Finding 3 turns entirely on two sentences of
  §8.1 read past their wrap — one assigning the limit to servers, one closing with *"Clients are
  only constrained by the congestion controller."* Four separate misreads in this project came from
  stopping at one wrap.
- **A done-when clause is a floor, not a ceiling.** A mutant that hard-coded the capture's
  pseudo-header order passed C9's stated done-when. The recovery analogue is a **constant-returning
  congestion controller**, which satisfies every arithmetic invariant in A3-9 and fails only a test
  that names the event that must move the window. Every congestion done-when above names its event.
- **A knob that exists is not a knob that is wired.** Before scoping a knob as done, grep for its
  consumer. `AckRangeLimit` graduated (Finding 8) and `InitialRttRange` has not (Finding 6).
- **When a plan says a later task "owns" something, go read what that task's text actually lists.**
  Sketch item 18 says "anti-amplification limit"; §8.1 says the limit is a server's and the client's
  obligation is a PTO probe. Sketch items 13-18 name six algorithms and no retransmission. **The
  doc has lost to the code twelve consecutive times in this project, and this document adds three
  more: item 18's owner, the sketch's deterministic-simulation claim, and the brief's own attempt
  count.**

And two this phase adds:

- **A double's stated limits are part of the plan, not part of the test.** The sketch said loss
  could be simulated by a test transport; `ScriptedDatagramTransport` had said in its own remarks,
  for weeks, that *"record-and-replay is dead past the first flight."* Both sentences were in the
  repository at the same time. **Read the double before scoping the harness that uses it.**
- **A layer with no published vectors needs its evidence named before its first task, not after.**
  RFC 9001 gave A4 Appendix A and RFC 9204 gave C Appendix B. RFC 9002 gives A3 nothing, and
  "transcription plus conformance tests" (the sketch's gate, and the handoff's repetition of it) is
  the shape of a claim that cannot fail. Finding 11 names the three substitutes; A3-0 writes them
  into the extract's own header so the next reader meets them before the pseudocode.
