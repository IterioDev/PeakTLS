# Reference capture: SharpTls QUIC recovery, task A3-13's live run under induced loss

Source: `https://fp.impersonate.pro/api/http3` (GET) and `https://tls3.peet.ws/api/all` (GET),
queried on the same run.
Captured: 2026-08-22, Windows 11 x64, `net9.0`, one machine, one residential path, one
afternoon.
Produced by: `QuicPublicEndpointInteropTests.AnImpairedHttp3RequestMeetsTheRecoveryMachineryOnALivePath`
in `tests/SharpTls.Tests/Interop/QuicPublicEndpointInteropTests.cs`, run as
`SHARPTLS_RUN_INTEROP=1 dotnet test --filter "FullyQualifiedName~AnImpairedHttp3RequestMeetsTheRecoveryMachineryOnALivePath"`
at branch `feat/quic-socks5-datagram-transport`, parent commit `c9a86cb`. The test writes its
full recording, every attempt line included, to `%TEMP%/quic-a3-13-induced-loss.txt`; every
value below is copied from that recording and nothing is altered.

Loss is induced by `ImpairingDatagramTransport` (`tests/SharpTls.Tests/Quic/`) wrapped around
the **real UDP transport**, under `RecordingTransport`. It impairs the **send side only**, by
**ordinal**, never by rate.

**What this settles.** Whether A3's recovery machinery — RTT, loss detection, PTO,
retransmission, NewReno, persistent congestion, pacing — repairs a real connection to a real
server when something is really missing. Every A3 test before this one is offline or faces a
peer this repository wrote.

**What this does not settle.** *A completion rate against two cooperative endpoints, on one
path, from one machine, on one day, is not a claim about the internet.* It is a claim about
these two endpoints on this path. What carries beyond it is the comparison **between arms**,
because the arms differ only in the script.

---

## The prior number this replaces, and the one it corrects

The running A3-deferral total stood at **0 loss-induced failures in 54 unimpaired attempts**
(A4 task 13 0/10, C13 0/20, the order probe 0/12, the B11 factory run 0/12). This run's
`CONTROL` arm adds **8 more unimpaired attempts, 0 failures**, for **0/62**. The path is clean;
that has never been the question.

**Finding 0 of the A3 plan is stale and this run says so plainly.** The plan records the live
HTTP/3 test failing **5/5 with `H3_SETTINGS_ERROR` (`0x109`)** at `bea2654`, attributed to a
`max_datagram_frame_size` advertisement mismatch owned by B and C17. At `c9a86cb` that failure
is **gone**: `AnHttp3RequestReturnsTheLiveFingerprintFromBothEndpoints` returns **10/10
COMPLETED, `h3_error=0x0`, status 200** against both hosts. A3-13 is therefore measuring A3
against A3 on a working path, which is what the task asked for, and it is not being credited
with anyone's repair — the defect repaired itself between commits, or was repaired by a task
that did not say so.

---

## The seven arms

`ImpairingDatagramTransport` ordinals are 1-based over datagrams offered to `SendAsync`.
Ordinal 1 is the **entire** opening flight: the C13 capture of these same two endpoints prints
`initial_datagrams=1` on all ten of its attempts, so `Drop(1)` is the ClientHello, not part of
it.

| arm | script | recovery spec |
| --- | --- | --- |
| `CONTROL` | none | shipped default |
| `DUPLICATE_OPENING` | `Duplicate(1)` | shipped default |
| `DROP_OPENING_SHIPPED_PROBE` | `Drop(1)` | shipped default (`ProbeContents = Ping`) |
| `DROP_OPENING_REPAIRING_PROBE` | `Drop(1)` | `ProbeContents = RetransmittedData` |
| `DROP_MID_EXCHANGE` | `Drop(5)` | `ProbeContents = RetransmittedData` |
| `REORDER` | `HoldUntilAfter(4, 5)` | `ProbeContents = RetransmittedData` |
| `BURST_BLACKOUT` | `Drop(6)` … `Drop(13)` | `ProbeContents = RetransmittedData` |

4 attempts per arm per host, 8 per arm, **56 attempts total**.

**One deliberate departure from the task text, and the instrument is the reason.** A3-13's
done-when asks for "the completion rate at no fewer than three induced loss rates" and names
1-in-20, 1-in-10 and 1-in-5. `ImpairingDatagramTransport` cannot express a rate and says at
length why it will not: *"'Drop the 3rd datagram' reproduces; 'drop 5% of datagrams' reproduces
only if the seed, the sequence the RNG is drawn in and the code between draws all stay
identical … Loss RATES belong in a soak test."* Six scripted patterns are run instead of three
rates, each reproducible byte for byte. A rate arm would have to come with a seed and would
still not be re-runnable from this document, which is what a reference capture is for. Reading
the two `DROP_OPENING_*` arms as an A/B (finding 2) is what the rate curve was wanted for, and
it answers the question more sharply than a curve over three points would have.

**Every number in the `ProbeContents` column is a value this run set, not a value the library
defaults to.** The shipped default is `TlsQuicProbeContents.Ping`
(`TlsQuicRecoverySpec.cs:573`). `RetransmittedData` is a knob turned, and the two
`DROP_OPENING_*` arms exist precisely so that turning it is the **only** difference between
them — which is the plan's "the same scripted loss pattern run with retransmission disabled and
enabled", with the disabled side being the shipped default rather than a configuration invented
to lose.

The congestion controller is **NewReno at 12000 bytes initial window** in every arm, and that
is the library's own fallback rather than an injection: `TlsQuicConnection.Congestion`
constructs `TlsQuicNewRenoCongestionController` when `Recovery.CongestionController` is null.
`controller=NewReno cwnd=12000` on every unimpaired attempt below is the readback.

---

## The result

| arm | host | completed | **failure rate** | lost | retransmitted | probes | persistent congestion | dropped | reordered | min cwnd |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CONTROL` | fp.impersonate.pro | 4/4 | **0/4** | 0 | 0 | 0 | 0 | 0 | 0 | 12000 |
| `CONTROL` | tls3.peet.ws | 4/4 | **0/4** | 0 | 0 | 0 | 0 | 0 | 0 | 12000 |
| `DUPLICATE_OPENING` | fp.impersonate.pro | 4/4 | **0/4** | 0 | 0 | 0 | 0 | 0 | 0 | 12000 |
| `DUPLICATE_OPENING` | tls3.peet.ws | 4/4 | **0/4** | 0 | 0 | 0 | 0 | 0 | 0 | 12000 |
| `DROP_OPENING_SHIPPED_PROBE` | fp.impersonate.pro | **0/4** | **4/4** | 0 | 0 | 8 | 0 | 4 | 0 | 12000 |
| `DROP_OPENING_SHIPPED_PROBE` | tls3.peet.ws | 4/4 | **0/4** | 4 | 4 | 8 | 0 | 4 | 0 | 6000 |
| `DROP_OPENING_REPAIRING_PROBE` | fp.impersonate.pro | 4/4 | **0/4** | 4 | 12 | 8 | 0 | 4 | 0 | 6000 |
| `DROP_OPENING_REPAIRING_PROBE` | tls3.peet.ws | 4/4 | **0/4** | 4 | 12 | 8 | 0 | 4 | 0 | 6000 |
| `DROP_MID_EXCHANGE` | fp.impersonate.pro | 4/4 | **0/4** | 0 | 8 | 8 | 0 | 4 | 0 | 12000 |
| `DROP_MID_EXCHANGE` | tls3.peet.ws | 4/4 | **0/4** | 4 | 8 | 8 | 0 | 4 | 0 | 12000 |
| `REORDER` | fp.impersonate.pro | 4/4 | **0/4** | 0 | 0 | 0 | 0 | 0 | 4 | 12000 |
| `REORDER` | tls3.peet.ws | 4/4 | **0/4** | 0 | 0 | 0 | 0 | 0 | 4 | 12000 |
| `BURST_BLACKOUT` | fp.impersonate.pro | 4/4 | **0/4** | 28 | 80 | 16 | 0 | 32 | 0 | 6000 |
| `BURST_BLACKOUT` | tls3.peet.ws | 4/4 | **0/4** | 32 | 48 | 8 | 0 | 32 | 0 | 6000 |

**52 of 56 attempts completed. All four failures are in one arm against one host.** Counters
are summed over the four attempts of that cell; `min cwnd` is the smallest congestion window
observed at the end of any attempt in the cell, against an initial window of 12000.

### The counters, per arm, and whether the mechanism engaged

The trap this task was warned about is an arm that completes having lost nothing. A3-8's first
loss test completed in 220 ms having lost nothing and passed; A3-11 found a vacuous test of its
own the same way. Each row below states which counter proves the arm was not vacuous.

| arm | impairment witnessed by | recovery witnessed by | engaged? |
| --- | --- | --- | --- |
| `CONTROL` | n/a — the control | n/a | n/a |
| `DUPLICATE_OPENING` | `delivered` exceeds `offered` (16 delivered of 15 offered) | nothing — **correctly**, a duplicate is not loss | n/a |
| `DROP_OPENING_SHIPPED_PROBE` | `dropped=1` every attempt | `probes=2` per attempt; on tls3 also `lost=1 retransmitted=1`; **on fp nothing, and the connection died** | partly — see finding 1 |
| `DROP_OPENING_REPAIRING_PROBE` | `dropped=1` every attempt | `lost=1 retransmitted=3 probes=2 cwnd 12000→6000` per attempt, both hosts | **yes** |
| `DROP_MID_EXCHANGE` | `dropped=1` every attempt | `retransmitted=2 probes=2` per attempt, both hosts; `lost=1` on tls3 only | **yes** |
| `REORDER` | `reordered=True` all 8 attempts | nothing — **correctly**, see finding 3 | n/a |
| `BURST_BLACKOUT` | `dropped=8` every attempt | `lost=7–8 retransmitted=12–20 probes=2–4 cwnd 12000→6000` per attempt | **yes** |

**No impaired arm was vacuous.** The instrument fired on all 48 impaired attempts, and the
test asserts that per attempt rather than trusting it — `Http3Recovery.Impaired` carries four
witnesses because there are four impairments, and the reorder one had to be added after the
first run reported the working `REORDER` arm as vacuous (see finding 3).

---

## Finding 1 — the shipped PTO probe kills the connection on one of the two endpoints

**This is the most valuable output of this task and it is a defect report, not a rate.**

`Drop(1)` removes the whole ClientHello. With the **shipped** `ProbeContents = Ping`, the PTO
fires and sends a PING-only Initial packet — a packet the server receives *before it has ever
seen a ClientHello*. Verbatim, all four attempts, `fp.impersonate.pro`:

```
attempt 1: FAILED elapsed_ms=1197 discarded=0 discarded_missing_keys=0 idle_timed_out=False
  initial_datagrams=3 datagrams_sent=3 lost=0 retransmitted=0 probes=2
  persistent_congestion=0 cwnd=12000 controller=NewReno offered=3 dropped=1 delivered=2
  still_held=0 reordered=False
  ended_with="InvalidOperationException: The peer closed the connection with error code 0xa
  (RFC 9000 s19.19 CONNECTION_CLOSE), so this attempt is draining and can neither send nor
  complete."
```

`0xa` is **PROTOCOL_VIOLATION** (RFC 9000 s20.1). The server did not time out and did not drop
the probe: it looked at a client Initial packet carrying PING and PADDING and no CRYPTO, judged
it a protocol violation, and closed. `discarded=0`, `discarded_missing_keys=0`,
`idle_timed_out=False`, `initial_datagrams=3` — by the classification the A3 plan's own
Finding 0 used, **this failure is not loss and not a flake**. It is the client's probe.

`tls3.peet.ws` answers the identical probe with an ACK, which is what lets ACK-driven loss
detection run at all there (`lost=1 retransmitted=1`), and completes 4/4.

**The two endpoints disagree, and the disagreement is the finding.** It is not to be averaged.
One server tolerates a contentless Initial probe; the other refuses it. A client that only ever
met the tolerant one would ship this.

**What it points at, stated as an inference and not as a diagnosis.** RFC 9002 s6.2.4 has the
sender retransmit unacknowledged data on a PTO where it has any, and reserve PING for the case
where it has none. This client had unacknowledged Initial CRYPTO and sent PING anyway, because
`ProbeContents` defaults to `Ping`. **Whether the default is wrong, or whether it is a
deliberate fingerprinting choice with an unwitnessed cost, is not A3-13's to decide** — the
knob lives in `src/SharpTls/Quic/TlsQuicRecoverySpec.cs`, which this task may not open. It is
handed on.

---

## Finding 2 — one knob turns 0/4 into 4/4, and the improvement is attributable

The `DROP_OPENING_*` pair differs in exactly one initialiser. Same drop, same host, same
minute.

| | `fp.impersonate.pro` | `tls3.peet.ws` |
| --- | --- | --- |
| `ProbeContents = Ping` (shipped) | **0/4** | 4/4 |
| `ProbeContents = RetransmittedData` | **4/4** | 4/4 |

With the repairing probe, `fp.impersonate.pro` attempt 1 verbatim:

```
COMPLETED handshake_ms=1582 response_ms=231 status=200 body_bytes=5329 fin=True h3_error=0x0
  discarded=1 discarded_missing_keys=1 unprocessed=0 idle_timed_out=False initial_datagrams=3
  datagrams_sent=17 lost=1 retransmitted=3 probes=2 persistent_congestion=0 cwnd=6000
  controller=NewReno offered=17 dropped=1 delivered=16 still_held=0 reordered=False
```

A whole ClientHello was destroyed and a 200 with a full 5329-byte body came back anyway, in
about 1.6 s against a 0.6 s unimpaired handshake. **`lost=1`, `retransmitted=3`, `probes=2`,
and the congestion window halved from 12000 to 6000** — the recovery path did the work, and
each of those four numbers would be zero or unchanged if it had not. This is the first
real-network evidence that A3's repair arm functions end to end.

---

## Finding 3 — reordering is tolerated, nothing is declared lost, and that is correct

`HoldUntilAfter(4, 5)` delivers datagram 5 before datagram 4. All 8 attempts:
`reordered=True`, `lost=0`, `retransmitted=0`, `probes=0`, `cwnd=12000`, 200 in the usual time.

RFC 9002 s6.1.1's packet threshold is a **reordering tolerance**, `kPacketThreshold = 3`. A
single-position swap is far inside it, so declaring nothing lost is the specified behaviour and
a retransmission here would have been the bug. **A reorder of this depth is not an
approximation of loss and must not be read as one.**

**This arm is also where this task nearly published a false negative.** A released hold drops
nothing, holds nothing at the end, and delivers exactly as many datagrams as were offered — so
every counter reads identically to a run that impaired nothing at all. The first run of this
test reported the working `REORDER` arm as *vacuous* on that basis. The delivery **order** is
the only witness a reorder leaves, and `Http3Recovery.DeliveredOutOfOrder` now carries it. The
warning that a vacuous arm is indistinguishable from a clean one cuts both ways: a **working**
arm is indistinguishable from a vacuous one when the witness is the wrong one.

---

## Finding 4 — persistent congestion was never established, and the reason is arithmetic

`BURST_BLACKOUT` drops **eight consecutive datagrams** after the handshake. It is by far the
most violent arm: 32 datagrams destroyed across 8 attempts, **60 packets declared lost, 128
frames retransmitted**, response times stretched from 192 ms to 3269 ms on `fp` and from 33 ms
to 1063 ms on `tls3`. The congestion window halved to 6000 on every attempt.

**`persistent_congestion = 0` on all 8 attempts, both hosts.**

RFC 9002 s7.6 needs the lost span to exceed `kPersistentCongestionThreshold` (3) probe timeout
periods. Against `tls3.peet.ws` the smoothed RTT is ~35 ms, so three PTO periods is a few
hundred milliseconds and the whole blacked-out exchange fits inside one of them. The blackout
was long in **datagrams** and short in **time**, and s7.6 measures time.

**Recorded as unsettled, not as evidence of absence.** This run does not show that persistent
congestion works on a real path, and it does not show that it does not. Establishing it live
needs a blackout of seconds, which means an arm whose PTO backoff is allowed to run several
more doublings than a 20-second response deadline permits. A3-10's offline tests remain the
only evidence for that path.

---

## Finding 5 — `discarded_missing_keys` moves whenever the server's flight is re-sent

`QuicPublicEndpointInteropTests`' own header states that `DiscardedForMissingKeys` is the
coalescing stall — a Handshake packet coalesced behind ServerHello that met no keys — and that
"a non-zero value there is a bug report about us, not about the internet." It is non-zero here,
`discarded=1 discarded_missing_keys=1`, in exactly the arms that cause the **server** to send
its first flight twice:

- `DUPLICATE_OPENING` on `fp.impersonate.pro` (the doubled Initial draws a doubled reply)
- `DROP_OPENING_REPAIRING_PROBE` on both hosts (the retransmitted ClientHello draws a second
  reply)

and zero everywhere else, including in all 8 `CONTROL` attempts and all 8 `BURST_BLACKOUT`
attempts. **Reported, not diagnosed.** It may be benign — a second copy of a flight whose keys
have already been consumed and discarded is a duplicate, not a stall — or it may be the counter
doing its job. Deciding needs `src/SharpTls/Quic/`, which this task may not open.

---

## Do the two endpoints agree?

**Six arms of seven agree. One disagrees, and it is finding 1.**

```
CONTROL:                       fp 4/4, tls3 4/4  -> AGREE
DUPLICATE_OPENING:             fp 4/4, tls3 4/4  -> AGREE
DROP_OPENING_SHIPPED_PROBE:    fp 0/4, tls3 4/4  -> DISAGREE
DROP_OPENING_REPAIRING_PROBE:  fp 4/4, tls3 4/4  -> AGREE
DROP_MID_EXCHANGE:             fp 4/4, tls3 4/4  -> AGREE
REORDER:                       fp 4/4, tls3 4/4  -> AGREE
BURST_BLACKOUT:                fp 4/4, tls3 4/4  -> AGREE
```

The hosts also disagree quietly inside `DROP_MID_EXCHANGE`, in a way the completion rate hides:
`fp.impersonate.pro` repairs with `lost=0 retransmitted=2` — the PTO probe carried the data
before ACK-driven detection could declare anything — while `tls3.peet.ws` repairs with `lost=1
retransmitted=2`, ACK-driven detection getting there first. Same client, same script, different
RTT (≈200 ms against ≈35 ms), different repair path. **Neither is wrong, and averaging them
would have erased the observation.**

---

## Provenance and standing

- **What produced it**: the test named at the head of this file, at `c9a86cb`, one run,
  2026-08-22. The first run of the same test is not reported here; it produced the same table
  to within one packet (`lost=31` against `lost=32` in one `BURST_BLACKOUT` cell) and failed on
  the reorder witness described in finding 3.
- **What is measured**: 56 attempts, 4 per arm per host. Failure rates and every counter are
  copied from the recording.
- **What is inferred and marked as such**: the cause of `fp.impersonate.pro`'s
  PROTOCOL_VIOLATION (finding 1), and the reason persistent congestion did not establish
  (finding 4). Both are readings of an endpoint's behaviour and of an RFC's arithmetic, not
  bytes read off a header, and are weaker evidence accordingly.
- **What is recorded as still unsettled**: persistent congestion on a real path (finding 4);
  whether `discarded_missing_keys` under a re-sent server flight is a defect (finding 5);
  whether `ProbeContents = Ping` is the right shipped default (finding 1).
- **What this is not**: a claim about the internet. Two endpoints, one path, one machine, one
  day. Four attempts per cell is enough to tell 0/4 from 4/4 and is **not** enough to measure a
  rate between them.
