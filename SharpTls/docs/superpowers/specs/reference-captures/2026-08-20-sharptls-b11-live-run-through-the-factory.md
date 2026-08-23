# Reference capture: the B11 live run — subsystem B's own composition, read back by `fp.impersonate.pro`

Source: `https://fp.impersonate.pro/api/http3`, resolved to `172.236.250.207:443`.
Captured: 2026-08-20, Windows 11 x64, `net9.0`.
Produced by:
`QuicPublicEndpointInteropTests.AFingerprintChangeIsVisibleEndToEndThroughTheProfileFactory`
in `tests/SharpTls.Tests/Interop/QuicPublicEndpointInteropTests.cs`, run as
`SHARPTLS_RUN_INTEROP=1 dotnet test --filter "FullyQualifiedName~AFingerprintChangeIsVisibleEndToEndThroughTheProfileFactory"`
at branch `feat/quic-socks5-datagram-transport`, parent commit `f83331f`. The test writes its full
recording to `%TEMP%/quic-b11-live-run.txt`; every value below is copied from that recording.

**What makes this run different from the two beside it.** `2026-08-20-sharptls-c13-live-http3.md`
recorded a run whose transport parameters were a list typed into the test file.
`2026-08-20-sharptls-b11-perk-order-probe.md` recorded an experiment over deliberate edits to that
same typed list. **This run is the first where the bytes on the wire came from `src/` rather than
from `tests/`:** the ClientHello is built by `TlsQuicClientHelloProfileFactory` (task B8) driving
`TlsQuicTransportParameterSpec.Brave151Parameters` (tasks B1–B7), with the test supplying only
subsystem E's half — two cipher suites, two groups, one key share.

---

## The three arms, and the predictions written before the run

The predictions are in the test's own header comment, above the code that ran them, so they cannot
have been written after the answers arrived.

| arm | what it sends | prediction |
| --- | --- | --- |
| `PRESET` | the shipped default `TransportParameters`, fourteen entries in the capture's order | P1: segment 3 reproduces the capture's fourteen identifiers **in the capture's order** |
| `SORTED` | the same fourteen entries, **ascending by emitted identifier** | P2: `perk_hash` **moves**, `perk_hash_normalized` **does not**. P2b (sharper): `SORTED`'s `perk_text` equals `PRESET`'s `perk_text_normalized`, and therefore `SORTED`'s `perk_hash` equals `PRESET`'s `perk_hash_normalized` |
| `PRESET_REPEAT` | `PRESET` again, on fresh connections | P3: **both hashes byte-identical** to `PRESET`'s, because the three per-connection draws all render as `AUTO` or `GREASE` |

`SORTED`'s sort key is **read back from a composition, not retyped**: three of the fourteen entries
are drawn, and a drawn slot's `Id` is zero until its function has run, so sorting the slots by their
own `Id` would file `version_information` and `initial_rtt` at the front instead of at 17 and 12583.

The identifiers each arm actually sent, printed from the composed list rather than beside it:

```
PRESET         12584,3307251970621932607,32,9,8,7,5,15,17,1,6,4,12583,3
SORTED         1,3,4,5,6,7,8,9,15,17,32,12583,12584,255623186645396665
PRESET_REPEAT  12584,1260693278099998973,32,9,8,7,5,15,17,1,6,4,12583,3
```

The second entry of `PRESET` and of `PRESET_REPEAT` is the reserved (GREASE) parameter, and the two
numbers differ because it is redrawn per composition. Both satisfy RFC 9000 §18.1's `31 * N + 27`.
That difference is what P3 is a test of.

---

## The result: 12 of 12 attempts completed, and every arm answered exactly once

Every attempt returned HTTP 200 over genuinely negotiated h3 (`"protocol": "http3"` in the body),
with `discarded=0`, `discarded_missing_keys=0`, `unprocessed=0` and `idle_timed_out=False`
throughout. **Each arm produced exactly ONE distinct reading across its four attempts** — no arm
answered two ways, so nothing below is a single sample and nothing was averaged.

| | attempts | complete | failure rate | Initial-flight datagrams | handshake ms | response ms |
| --- | --- | --- | --- | --- | --- | --- |
| `PRESET` | 4 | 4 | 0/4 | **1 on every attempt** | 557–669 | 198–392 |
| `SORTED` | 4 | 4 | 0/4 | **1 on every attempt** | 559–600 | 198–223 |
| `PRESET_REPEAT` | 4 | 4 | 0/4 | **1 on every attempt** | 550–603 | 199–226 |
| **total** | **12** | **12** | **0/12** | | | |

**The Initial flight was ONE datagram on all twelve attempts.** The plan's B11 text warned to
"expect loss" because "B9 doubles the Initial datagrams that must survive" — that did not happen on
this run, and the reason is that this run's TLS half offers a single X25519 key share. B9's split is
provoked by a ~1216-byte key share arriving with a full browser profile (X25519MLKEM768), which
subsystem E has not wired in here. **So this run does not measure the two-datagram case at all**, and
the 0/12 below must not be read as evidence about it. Per whole attempt, 13 datagrams were sent on
eleven of the twelve and 16 on the remaining one — handshake plus the whole request and response.

**Running total for the A3-deferral evidence: 0 failures in 54 attempts** — A4 task 13's 0/10,
C13's 0/20, the order probe's 0/12, and this run's 0/12.

---

## Arm 1 — `PRESET`, the Brave 151 preset as shipped

`perk_text`, verbatim:

```
1:0;6:262144;7:0|m,a,s,p|12584:0x4f524947;GREASE;32:65536;9:103;8:100;7:6291456;5:6291456;15:AUTO;17:1@GREASE,1;1:30000;6:6291456;4:15728640;12583:AUTO;3:1472|0,8
```

- `perk_hash` = `04736da3818104056c4fda492c21bd05`
- `perk_hash_normalized` = `058578261cc56e6f6a02cbd3349dd51a`
- `perk_text_normalized` =
  `1:0;6:262144;7:0|m,a,s,p|1:30000;3:1472;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103;15:AUTO;17:1@1,GREASE;32:65536;12583:AUTO;12584:0x4f524947;GREASE|0,8`

The endpoint's own QUIC block, unchanged across all twelve attempts:

```json
"quic": {
  "client_connection_id_length": 0,
  "server_connection_id_length": 8
}
```

**P1: MET.** See the segment table below — segment 3 is character-for-character the capture's.

## Arm 2 — `SORTED`, the same fourteen ascending by identifier

`perk_text`, verbatim:

```
1:0;6:262144;7:0|m,a,s,p|1:30000;3:1472;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103;15:AUTO;17:1@GREASE,1;32:65536;12583:AUTO;12584:0x4f524947;GREASE|0,8
```

- `perk_hash` = `8a1b68ab063c11af9a015c4553661f52`
- `perk_hash_normalized` = `058578261cc56e6f6a02cbd3349dd51a`
- `perk_text_normalized` = byte-identical to `PRESET`'s.

**P2: MET.** `perk_hash` moved (`04736da3…` → `8a1b68ab…`); `perk_hash_normalized` did not move
(`058578261cc56e6f6a02cbd3349dd51a` on both). Changing nothing but the order of the fourteen
parameters moved the fingerprint the endpoint reports, and left the order-insensitive one alone.
**This is the end-to-end demonstration the phase existed to reach:** one field on a spec object in
`src/`, and a public service's verdict moves in the predicted direction.

**P2b: NOT MET, and the reason is a new finding.** `SORTED`'s raw form is *not* `PRESET`'s
normalized form. The two strings differ in exactly one substring:

| | segment 3, `version_information` entry |
| --- | --- |
| `SORTED`'s `perk_text` | `17:1@GREASE,1` |
| `PRESET`'s `perk_text_normalized` | `17:1@1,GREASE` |

**The normalization does not only sort the outer parameter list — it also sorts the
available-versions list *inside* parameter 17's value.** No document in this repo states that: the
Brave capture's line 53 says only "the normalized form sorts transport parameters by ID". Because
that inner sort is not something a client can produce by reordering its parameter list, no wire
order at all can make `perk_text` equal `perk_text_normalized` while a GREASE version is present,
and so the two hashes necessarily differ (`8a1b68ab…` vs `058578261c…`).

**This does not weaken P2 and does not affect B7.** The raw form is what B7 must match, and it
preserves the available-versions order we sent — `17:1@GREASE,1`, which is exactly Brave's. The
failed prediction was about the *normalized* form, which nothing in subsystem B targets.

## Arm 3 — `PRESET_REPEAT`, the same configuration on fresh connections

`perk_text` byte-identical to `PRESET`'s.

- `perk_hash` = `04736da3818104056c4fda492c21bd05` — identical
- `perk_hash_normalized` = `058578261cc56e6f6a02cbd3349dd51a` — identical

**P3: MET.** Across eight connections in two arms the factory drew eight fresh `initial_rtt`
microsecond values, eight fresh reserved identifiers (two of them recorded above, differing in every
digit), and eight fresh GREASE versions — and the endpoint returned one hash. The three redrawn
fields render as `12583:AUTO`, a bare `GREASE`, and `GREASE` inside `17:1@GREASE,1`; none reaches
either hash. This is the order-probe's "position, not value" result holding for all three drawn
parameters at once, and it is what makes B8's per-connection redraw free of fingerprint cost.

---

## Diffed field by field against the Brave 151 capture

`docs/superpowers/specs/reference-captures/2026-08-16-brave-151-http3-impersonate-pro.md`, its
line 47.

| # | segment | owner | ours (`PRESET`) | Brave 151 | verdict |
| --- | --- | --- | --- | --- | --- |
| 1 | h3 SETTINGS | **C** | `1:0;6:262144;7:0` | `1:65536;6:262144;7:100;51:1;GREASE` | DIFFER — the narrowed QPACK arm, C's, see below |
| 2 | pseudo-header order | **C** | `m,a,s,p` | `m,a,s,p` | **MATCH** |
| 3 | transport parameters, wire order | **B** | `12584:0x4f524947;GREASE;32:65536;9:103;8:100;7:6291456;5:6291456;15:AUTO;17:1@GREASE,1;1:30000;6:6291456;4:15728640;12583:AUTO;3:1472` | *identical* | **MATCH, character for character** |
| 4 | connection ID length pair | **B** | `0,8` | `0,8` | **MATCH** |

**Both segments subsystem B owns now match Brave 151 exactly.** Segment 3 is the fourteen
parameters, their values, their rendering and their wire order; segment 4 is the CID length pair,
which already matched at C13 and still does. Neither is re-filed from another subsystem's ledger:
B is what composes them now, and this is B reporting its own result.

**Neither of the two that do not match is B's.** Segment 1 is the HTTP/3 SETTINGS frame and segment
2 the pseudo-header order, both subsystem C's, and this file does not re-file them as B's — exactly
as C13 was told not to re-file B's. Segment 2 already matches. Segment 1 differs only because this
run held C13's **narrowed** QPACK arm (`QPACK_MAX_TABLE_CAPACITY 0`, `QPACK_BLOCKED_STREAMS 0`) in
force so that segments 1, 2 and 4 were constant across the three arms and only segment 3 could move.
C13 recorded that `TlsQuicHttp3Spec`'s default arm already emits an exact segment 1 and that what it
cannot yet do is *survive* a peer encoder taking up the offer — C14–C16's work.

**So the whole-perk consequence, stated plainly and not measured here:** with segments 2, 3 and 4
matching, the only thing between this client and Brave 151's `perk_hash`
(`7d726b1554d23ae0ffb3e8c533f20a2f`) is segment 1, and segment 1 is one QPACK arm away. Whether the
default arm survives a live run end to end is C's measurement to take, not this one.

### The hashes, three ways

| | `perk_hash` | `perk_hash_normalized` |
| --- | --- | --- |
| C13, the typed list | `6d94f63e5db7fe12fa493e5b23c2443f` | `ff76216a19258be0123a5ee76da4fa7a` |
| **B11, through the factory** | **`04736da3818104056c4fda492c21bd05`** | **`058578261cc56e6f6a02cbd3349dd51a`** |
| Brave 151 | `7d726b1554d23ae0ffb3e8c533f20a2f` | `733abf232de1c065c494640332f04555` |

The B11 hashes still differ from Brave's because segment 1 differs; they differ from C13's because
segment 3 does. Both differences are accounted for, and neither is unexplained.

## Diffed against C13's earlier run — the delta wiring the factory in made

Segment 3, C13 versus this run:

```
C13   15:AUTO;14:2;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103
B11   12584:0x4f524947;GREASE;32:65536;9:103;8:100;7:6291456;5:6291456;15:AUTO;17:1@GREASE,1;1:30000;6:6291456;4:15728640;12583:AUTO;3:1472
```

C13's own list of what was missing relative to Brave was: `google_connection_options` (12584), the
GREASE transport parameter, `max_datagram_frame_size` (32), `version_information` (17),
`max_idle_timeout` (1), `initial_rtt` (12583), `max_udp_payload_size` (3) — and one parameter sent
that Brave does not send, `active_connection_id_limit` (14) — and the wire order itself.

**All nine of those are settled by this run.** Seven parameters arrived, `14` is gone, and the order
is the capture's. The six values C13 already shared with Brave (4, 5, 6, 7, 8, 9) are unchanged and
still match, and `15` is still empty. Every identifier is emitted by `Brave151Parameters` and
`TlsQuicClientHelloProfileFactory`; nothing on the wire came from the test file.

---

## The same-spec constraint, verified rather than assumed

`TlsQuicClientHelloProfileFactory.ConnectionSpec` must be **the same object** passed to
`TlsQuicConnectionOptions`. The test satisfies it by construction — one `TlsQuicConnectionSpec` is
built per attempt and handed to both. Reading `TlsQuicTransportParameterSpec.Compose` and
`TlsQuicConnection` for what a *second* spec would actually do gives three answers, and only the
first is loud:

1. **A different `SourceConnectionIdLength` throws.** `Compose` compares the span it is handed
   against its own spec's declared length and raises `ArgumentException`; the connection generates
   the ID from *its* spec, so the attempt ends at `ConnectAsync`.
2. **A different `LocalFlowControl` is silent, and is the dangerous one.** `Compose` places the six
   advertised flow-control values from the factory's spec while `TlsQuicStreamSet` enforces the six
   from the connection's. The client would advertise one budget and police another with nothing
   throwing — which is the exact gap `Compose` placing them (rather than letting them be typed
   twice) exists to close, re-opened from outside.
3. **A different `InitialRttRange` is also silent:** the drawn entry reads the spec it is composed
   against, so the connection's range is simply ignored.

---

## What this settles, and what it does not

**Settles.** Subsystem B's composed transport parameters and CID lengths reproduce Brave 151's perk
segments 3 and 4 exactly, live. A change to the parameter list moves `perk_hash` in the predicted
direction and leaves `perk_hash_normalized` alone. The per-connection redraws cost nothing in
fingerprint terms. The task-B11 done-when's sorted-order probe is answered here as well as at
`4ed90bf`, this time over the shipped fourteen rather than over a typed eight.

**Does not settle.** Everything the Brave capture's lines 30–33 already name as not inspected by
this service — the Initial packet number and its encoded length, the token, frame order inside the
Initial, the padding target, CRYPTO frame splitting, the per-datagram flight plan. Those still need
task B12's packet capture, and no number in this file bears on them. **Nor does it settle the
multi-datagram Initial:** every attempt here sent a one-datagram Initial flight, so B9's split is
untested against a live peer and this run's 0/12 says nothing about it.

## What in the surrounding documents was wrong

- **`perk` is still not a field.** The wire calls it `perk_text`, and the normalized string
  `perk_text_normalized`; only the two hashes carry the names the plan and the Brave capture use.
  C13 filed this, the order probe re-filed it, and it is still true.
- **"The normalized form sorts transport parameters by ID"** (Brave capture, line 53) is
  incomplete. It also sorts the available-versions list inside `version_information`'s value:
  `17:1@GREASE,1` raw becomes `17:1@1,GREASE` normalized. Measured here on twelve attempts.
- **B11's "expect loss … B9 doubles the Initial datagrams that must survive"** did not apply to this
  run. The Initial flight was one datagram every time, because the TLS half in force offers a single
  X25519 key share rather than a browser's post-quantum share.

## Reproducing it

```
SHARPTLS_RUN_INTEROP=1 dotnet test --filter "FullyQualifiedName~AFingerprintChangeIsVisibleEndToEndThroughTheProfileFactory"
```

`[InteropFact]`-gated exactly as its neighbours are, and skipped out of the ordinary gate — the gate
at `f83331f` was 1915 passed / 0 failed / 4 skipped (1919 total) and is 1915 / 0 / 5 (1920 total)
with this test added, the one extra case being this test skipping.

Its two assertions are deliberately **not** on any prediction: that all three arms reached the
service and were handed a `perk_hash`, and that `PRESET`'s body reports `"protocol": "http3"`. Both
answers to every prediction were findings before the run, and a test that asserted one of them would
be a test that could be made to lie by editing it.
