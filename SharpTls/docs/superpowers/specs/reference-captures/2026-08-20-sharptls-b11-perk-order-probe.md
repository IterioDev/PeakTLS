# Reference capture: the B11 order-and-value probe — what `fp.impersonate.pro` actually hashes

Source: `https://fp.impersonate.pro/api/http3`.
Captured: 2026-08-20, Windows 11 x64, `net9.0`.
Produced by:
`QuicPublicEndpointInteropTests.TheLiveServiceIsAskedWhetherItHashesParameterOrderAndParameterValue`
in `tests/SharpTls.Tests/Interop/QuicPublicEndpointInteropTests.cs`, run as
`SHARPTLS_RUN_INTEROP=1 dotnet test --filter "FullyQualifiedName~TheLiveServiceIsAskedWhetherItHashesParameterOrderAndParameterValue"`
at branch `feat/quic-socks5-datagram-transport`, parent commit `639d3c4`. The test writes its full
recording to `%TEMP%/quic-b11-order-probe.txt`; every value below is copied from that recording.

**This is a new file rather than an appendix to
`2026-08-20-sharptls-c13-live-http3.md`, on purpose.** That file records *a run*: one client
configuration, observed. This one records *an experiment*: four configurations, deliberately
differing in one thing each, compared against each other. Its control happens to reproduce C13's
numbers byte for byte, which is what makes it a control rather than a second run.

**Why it exists.** `docs/superpowers/plans/2026-08-20-quic-b-fingerprint-spec-scoping.md` names one
riskiest ordering assumption — *that B7 (wire order) can be reached with B5's `initial_rtt` range
still a placeholder* — and rests it entirely on prose: a client capture's *"sorting the parameters
would change `perk_hash` while leaving `perk_hash_normalized` intact"*, and Finding 3's *"the perk
renders `12583:AUTO`, so the hash sees position and not value."* Neither sentence was a measurement
before this file. The plan itself puts the mitigation in B11 and says to run it as soon as anything
can reach the endpoint. This is that run, pulled forward.

## The experiment

Four arms, three whole connections each, **12 attempts, all against `172.236.250.207:443`**. Every
arm ran the same NARROWED QPACK arm C13 ran (`1:0;6:262144;7:0`), so perk segments 1, 2 and 4 are
held constant and only segment 3 can move.

| arm | transport parameter ids, in the order sent | differs from the control by |
| --- | --- | --- |
| `BASELINE` | `15,14,4,5,6,7,8,9` | nothing — this is C13's exact list |
| `REVERSED` | `9,8,7,6,5,4,14,15` | **position only.** Same eight parameters, same eight values, emitted back to front |
| `RTT_100000` | `15,14,4,5,6,7,8,9,12583` | `initial_rtt` appended, value **100000** |
| `RTT_900000` | `15,14,4,5,6,7,8,9,12583` | `initial_rtt` appended, value **900000** |

Three choices in that table are load-bearing.

- **`REVERSED` is neither the baseline order nor ascending order.** `9,8,7,6,5,4,14,15` is the
  baseline reversed; the normalized form sorts to `4,5,6,7,8,9,14,15`. A service that sorts
  internally and a service that preserves wire order therefore cannot produce the same pair of
  answers, which is the whole point.
- **`RTT_100000` and `RTT_900000` differ in a value and in nothing else** — same set, same order —
  and 100000 and 900000 both encode to a **four-byte** QUIC varint (RFC 9000 §16 covers
  16384..2³⁰−1 in four bytes), so not even the encoded blob length differs. "The blob got longer" is
  removed as an explanation and the value itself is the only variable.
- **The probe uses 12583, not 15.** `initial_source_connection_id` also renders `AUTO`, but its
  value *is* the source connection ID, so changing it also moves perk segment 4 — the CID length
  pair — and that is a confound. 12583 is inert: RFC 9000 §18.1 makes a receiver ignore a transport
  parameter it does not understand.

## The result: 12 of 12 attempts completed, and every arm answered once

Every attempt returned status 200 over genuinely negotiated h3, with `discarded=0` and
`discarded_missing_keys=0` throughout. **Each arm produced exactly ONE distinct reading across its
three attempts** — no arm answered two different ways, so nothing below is a single sample and
nothing had to be averaged.

Handshakes ran 554–688 ms and responses 183–251 ms, in line with C13's 564–655 / 186–236.

### Question 1 — does wire order move the hashes?

| | `BASELINE` | `REVERSED` |
| --- | --- | --- |
| segment 3 | `15:AUTO;14:2;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103` | `9:103;8:100;7:6291456;6:6291456;5:6291456;4:15728640;14:2;15:AUTO` |
| `perk_hash` | `6d94f63e5db7fe12fa493e5b23c2443f` | `8fb1d356cd2fe67b07d6b71db466c8d0` |
| `perk_hash_normalized` | `ff76216a19258be0123a5ee76da4fa7a` | `ff76216a19258be0123a5ee76da4fa7a` |

**Measured: `perk_hash` MOVED. `perk_hash_normalized` DID NOT MOVE.** The normalized *string* was
byte-identical between the two arms as well —
`…|4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103;14:2;15:AUTO|0,8` — so the normalization is
a real ascending-by-identifier sort and not a coincidence of hashing.

**Segment 3 reproduced the order we sent, exactly, in both arms.** The raw form is a transcript of
the wire, not a re-derivation.

The `BASELINE` arm's two hashes are **byte-identical to C13's**, which were recorded under a
different parent commit (`3f642da`) on a separate run. The control reproduces.

### Question 2 — does a value the perk renders `AUTO` move either hash?

| | `RTT_100000` | `RTT_900000` |
| --- | --- | --- |
| segment 3 | `15:AUTO;14:2;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103;12583:AUTO` | *identical* |
| `perk_hash` | `142065d4d75344ff30bc02238c250f0e` | `142065d4d75344ff30bc02238c250f0e` |
| `perk_hash_normalized` | `748f61709948cfe6bdedda8673c39e48` | `748f61709948cfe6bdedda8673c39e48` |

**Measured: NEITHER hash moved.** A nine-fold change in `initial_rtt` produced a byte-identical
`perk_text`, a byte-identical `perk_text_normalized` and two byte-identical hashes, three times
each. The service tokenises the parameter as `12583:AUTO` and the number never reaches the hash.

**Read the scope of that carefully.** It is a statement about *`AUTO`-rendered* parameters, not
about parameters in general. In the same segment-3 string, `4:15728640` and `8:100` render their
values verbatim, so for those the value plainly *is* hashed. Two identifiers were observed rendering
`AUTO` here — `15` and `12583` — and this probe measured value-insensitivity for `12583` only.

## Two things this settles that the plan listed as open

1. **The service does not strip an unknown or private identifier.** 12583 is in no RFC 9000 §18
   registry, and it appeared in both perk strings and moved both hashes when it was added. The
   scoping doc's uncertainty item 2 — *"whether the renderer strips a zero-length value or an
   unknown identifier is not stated anywhere"* — is half-answered here.
2. **Nor does it strip a zero-length value.** Parameter 15 was sent empty on all 12 attempts and
   renders as `15:AUTO` rather than being dropped. That is the other half.

Both halves came free with the arms that were already running.

## The decision this experiment exists to inform

> **B7 can proceed with `initial_rtt`'s range unsettled. Yes.**

The evidence is Question 2: `initial_rtt`'s *value* is not an input to either hash, so B7's
segment-3 target — a character-for-character match of the capture's segment 3 — is reachable while
B5's range is still `InitialRttRange = null`, and B12's packet capture is not a prerequisite of B7.
B5 remains a real task, because a **pinned** `initial_rtt` is a fingerprint against anyone who
correlates connections rather than hashing one — but that is a defect B5 fixes on its own schedule,
not a blocker on B7.

The plan's 12-task estimate holds on this axis. Uncertainty item 2 does not add its extra task.

## Where the documents stood up and where they did not

**A client capture's prose was right, and this is the first time in this project a document has
beaten a measurement rather than losing to one.** Its line 53–55 claim — that both hashes are
published, that the normalized form sorts by identifier, that the raw form preserves wire order, and
that *"sorting the parameters would change `perk_hash` while leaving `perk_hash_normalized`
intact"* — is now measured, in both directions, 3 times per arm. Finding 3's *"position, not value"*
reading is likewise measured, for `12583`. **Neither claim needed rewriting.**

**What was still wrong, and it is the same thing C13 already filed:** the field is `perk_text`, not
`perk`. A client capture's own section heading says `perk`; a reader querying `perk` gets nothing
back. C13 recorded this and it remains true — this probe reads `perk_text`, `perk_hash`,
`perk_text_normalized` and `perk_hash_normalized` and only the latter three carry the names the plan
and the capture use.

## Reproducing it

```
SHARPTLS_RUN_INTEROP=1 dotnet test --filter "FullyQualifiedName~TheLiveServiceIsAskedWhetherItHashesParameterOrderAndParameterValue"
```

The test is `[InteropFact]`-gated exactly as its neighbours are and skips out of the ordinary gate.
Its single assertion is deliberately **not** on either prediction — both answers were findings
before the run, and a test that asserted one of them would be a test that could be made to lie by
editing it. It asserts only that all four arms reached the service and were handed a perk back,
because an arm that never connected measures nothing.
