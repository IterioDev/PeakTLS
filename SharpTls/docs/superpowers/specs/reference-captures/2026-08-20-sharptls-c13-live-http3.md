# Reference capture: SharpTls over HTTP/3, task C13's live run

Source: `https://fp.impersonate.pro/api/http3` and `https://tls3.peet.ws/api/all`, queried on
the same run.
Captured: 2026-08-20, Windows 11 x64, `net9.0`.
Produced by: `QuicPublicEndpointInteropTests.AnHttp3RequestReturnsTheLiveFingerprintFromBothEndpoints`
in `tests/SharpTls.Tests/Interop/QuicPublicEndpointInteropTests.cs`, run as
`SHARPTLS_RUN_INTEROP=1 dotnet test --filter "FullyQualifiedName~AnHttp3RequestReturnsTheLiveFingerprintFromBothEndpoints"`
at branch `feat/quic-socks5-datagram-transport`, parent commit `3f642da`. The test writes its
full recording, including both response bodies verbatim, to
`%TEMP%/quic-http3-live-run.txt`; every value below is copied from that recording.

**This is the opposite kind of document from the Brave capture beside it.** That file records
what a real browser puts on the wire and is the target. This file records what *we* put on the
wire, as read back by two servers nobody here configured. Where the two disagree, the Brave
file is right by definition.

Nothing below is altered. No cookie or token was returned by either endpoint, so nothing is
redacted.

## The run

| | fp.impersonate.pro | tls3.peet.ws |
| --- | --- | --- |
| path | `/api/http3` | `/api/all` |
| resolved | 172.236.250.207:443 | 134.209.246.126:443 |
| attempts | 5 | 5 |
| complete responses | 5 | 5 |
| **failure rate** | **0/5** | **0/5** |
| status | 200 on every attempt | 200 on every attempt |
| handshake | 564–655 ms | 102–137 ms |
| response after handshake | 186–236 ms | 31–42 ms |
| `discarded` / `discarded_missing_keys` | 0 / 0 on every attempt | 0 / 0 on every attempt |
| peer SETTINGS | `1:4096;7:16;8:1;GREASE` | `8:1` |

**0 of 10 attempts lost a packet.** A second, independent run of the same test minutes earlier
returned 5/5 and 5/5 as well, for **0 failures in 20 attempts**, and produced a byte-identical
`perk_hash`. This is the number task C13 exists to produce.

**What that measures, and what it does not.** A3 is deferred, so nothing retransmits: a single
lost packet ends an attempt outright. C's traffic spans far more packets than A4 task 13's
handshake — three unidirectional stream headers, a SETTINGS frame, a HEADERS frame and every
DATA frame of a 4955-byte response — so this is a materially larger exposure than the 0/10 A4
task 13 measured, and it still cost nothing. It is a measurement of **one host's path to two
endpoints on one day**, not of the internet; `discarded=0` throughout says the sockets met no
off-path noise either, which is itself a statement about this path rather than about QUIC.
Taken with A4 task 13's 0/10, the case for keeping A3 deferred rests on 30 attempts across two
tasks with zero loss-induced failures.

## The QPACK arm in force — read this before reading segment 1

**The NARROWED arm ran: `1:0;6:262144;7:0`.** QPACK_MAX_TABLE_CAPACITY 0 and
QPACK_BLOCKED_STREAMS 0 are load-bearing rather than cosmetic — RFC 9204 §3.2.3 leaves the
peer's encoder unable to use the dynamic table at capacity 0, which is what makes the
static-only decoder C5–C8 ships a *correct* decoder here rather than a lucky one.

**The DEFAULT arm is `TlsQuicHttp3Spec.CaptureSettings`, `1:65536;6:262144;7:100;51:1;GREASE`
— all five of the capture's pairs — and it is NOT what ran here.** A test's chosen spec is not
the library's capability. The default emits an exact segment 1 already; what it cannot yet do
is *survive* a peer encoder that takes up the offer, which is C14–C16's job. Reading segment 1
below as a statement about what this library can emit is the specific misreading that produced
a wrong reading once already, which is why this section sits above the fingerprint rather than
below it.

## QUIC layer

```json
"quic": {
  "client_connection_id_length": 0,
  "server_connection_id_length": 8
}
```

**Both match the Brave capture exactly**, live, against a server we do not control. The spec's
default `SourceConnectionIdLength` is 0 and `DestinationConnectionIdLength` is 8, and this run
used those defaults.

## The `perk` fingerprint, verbatim

```
1:0;6:262144;7:0|m,a,s,p|15:AUTO;14:2;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103|0,8
```

- `perk_hash` = `6d94f63e5db7fe12fa493e5b23c2443f`
- `perk_hash_normalized` = `ff76216a19258be0123a5ee76da4fa7a`
- normalized string = `1:0;6:262144;7:0|m,a,s,p|4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103;14:2;15:AUTO|0,8`

For the Brave target beside it: `7d726b1554d23ae0ffb3e8c533f20a2f` and
`733abf232de1c065c494640332f04555`.

**THE FIELD IS CALLED `perk_text` ON THE WIRE, NOT `perk`.** The JSON keys the endpoint
actually returns are `perk_text`, `perk_hash`, `perk_text_normalized`, `perk_hash_normalized`.
Only the two hashes carry the names the plan and the handoff use; a reader looking up `perk`
finds nothing. The Brave capture beside this one is half-right about it — its section heading
says "The `perk` fingerprint format" while its own prose at line 98 says `perk_text`. The test
looks up both spellings so a recording is never empty because a document used the other one.

Segment by segment against Brave:

| # | segment | ours, live | Brave | owner |
| --- | --- | --- | --- | --- |
| 1 | h3 SETTINGS | `1:0;6:262144;7:0` | `1:65536;6:262144;7:100;51:1;GREASE` | C — **narrowed arm, see above; the default arm matches exactly** |
| 2 | pseudo-header order | `m,a,s,p` | `m,a,s,p` | C — **exact match, live** |
| 3 | transport parameters, wire order | `15:AUTO;14:2;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103` | `12584:0x4f524947;GREASE;32:65536;9:103;8:100;7:6291456;5:6291456;15:AUTO;17:1@GREASE,1;1:30000;6:6291456;4:15728640;12583:AUTO;3:1472` | **subsystem B** |
| 4 | CID length pair | `0,8` | `0,8` | **subsystem B — and it already matches** |

## HTTP/3 SETTINGS, as the endpoint read them back

| ID | Name | Value |
| --- | --- | --- |
| 1 | `SETTINGS_QPACK_MAX_TABLE_CAPACITY` | 0 |
| 6 | `SETTINGS_MAX_FIELD_SECTION_SIZE` | 262144 |
| 7 | `SETTINGS_QPACK_BLOCKED_STREAMS` | 0 |

Pseudo-header order, as `header_order`: `:method`, `:authority`, `:scheme`, `:path` — `m,a,s,p`,
and the endpoint echoed all four header lines with their values intact.

## QUIC transport parameters, in wire order — subsystem B's, not C's

| # | ID | Name | Value |
| --- | --- | --- | --- |
| 1 | 15 | `initial_source_connection_id` | empty (`0x`), consistent with a zero-length source CID |
| 2 | 14 | `active_connection_id_limit` | 2 |
| 3 | 4 | `initial_max_data` | 15728640 |
| 4 | 5 | `initial_max_stream_data_bidi_local` | 6291456 |
| 5 | 6 | `initial_max_stream_data_bidi_remote` | 6291456 |
| 6 | 7 | `initial_max_stream_data_uni` | 6291456 |
| 7 | 8 | `initial_max_streams_bidi` | 100 |
| 8 | 9 | `initial_max_streams_uni` | 103 |

This ordering is **recomputed, not copied**: tls3.peet.ws returns the raw extension blob
`0f000e0102040480f000000504806000000604806000000704806000000802406409024067`, and decoding it
as RFC 9000 §18 varint triples yields exactly `15,14,4,5,6,7,8,9` with the same eight values.
Two independent endpoints therefore agree on segment 3 even though only one of them publishes a
perk.

**Every value we share with Brave matches** (4, 5, 6, 7, 8, 9, and 15's emptiness). What
differs is the *set* and the *order*, and both are subsystem B's:

- **Missing, relative to Brave:** `google_connection_options` (12584),
  the GREASE transport parameter, `max_datagram_frame_size` (32), `version_information` (17),
  `max_idle_timeout` (1), `initial_rtt` (12583), `max_udp_payload_size` (3).
- **Sent, that Brave does not:** `active_connection_id_limit` (14).
- **Wire order itself.** Task 11 already recorded this as a MISMATCH and **task C13 does not
  re-file it.** It appears here so that a perk readout is not silently missing a perk segment,
  and for no other reason.
- `initial_rtt` **must be randomised per connection** when it is added. A pinned value is
  itself a fingerprint. The Brave capture's finding 3 is the authority.

## TLS layer, carried inside the QUIC handshake

Both endpoints derived the same JA3 from the same run, which is the cleanest agreement in this
document.

- JA3: `771,4865-4866,0-10-13-43-51-16-57,29-23,` — hash `e1466f3b01a9815ee008aae28abcca8f`
  (fp.impersonate.pro and tls3.peet.ws, independently, identical).
- JA3N hash: `6ab48a27f50016ceeb8eb349e9c890b6`.
- JA4 (tls3.peet.ws only): `q13d27_62ed6f6ca7ad_8552ec156356`.
- peetprint: `772||29-23|1027-1283-1539-2052-2053-2054-2057-2058-2059|0||4865-4866|0-10-13-16-43-51-57`,
  hash `f1b2548d143dc8592b50174603cc4a7c`.
- Cipher suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`.
- Extensions in wire order: 0 `server_name`, 10 `supported_groups`, 13 `signature_algorithms`,
  43 `supported_versions`, 51 `key_share`, 16 `alpn` (`h3`), 57 `quic_transport_parameters`.
- Supported groups: X25519 (29), P-256 (23). Key share: X25519 only, 32 bytes.

This is the interop test's own ClientHello, not a browser profile, and it is nowhere near
Brave's — no ChaCha, no X25519MLKEM768, no `compress_certificate`, no ALPS, no ECH. That gap is
subsystem B's and E's and is out of C13's scope; it is recorded so nobody mistakes this file's
TLS section for a target.

## The second endpoint, and the one disagreement it produced

tls3.peet.ws confirmed `"http_version": "h3"` on all five attempts and publishes **no perk of
any spelling**. What it publishes instead:

```json
"http3": {
  "settings": null,
  "akamai_fingerprint": "|m,a,s,p",
  "akamai_fingerprint_hash": "c089f6a90da27dee08ed98c1af5c44d7",
  "used_0rtt": false, "supports_datagrams": false, "version": 1
}
```

**Where the two endpoints agree:** the protocol was h3, the pseudo-header order was `m,a,s,p`
(peet.ws's `akamai_fingerprint` carries it after the pipe), the four header lines, the
transport-parameter wire order and values, and the whole TLS layer including the JA3 hash.

**Where they disagree, and it is a finding rather than something to average:** peet.ws reports
`"settings": null` and an **empty settings segment** in `akamai_fingerprint` (`"|m,a,s,p"`) for
a connection whose SETTINGS fp.impersonate.pro read back in full as `1:0;6:262144;7:0`.

What the evidence already rules out and what it does not:

- **Not "we sent no SETTINGS".** fp.impersonate.pro read all three pairs off the same client
  configuration on the same run, and it enumerated them individually rather than echoing our
  spec.
- **Not "one request fell back off h3".** Both endpoints affirm h3, which is the whole reason
  `/api/http3` is C13's gate.
- **Still open:** whether peet.ws never observed our control stream, observed it after
  snapshotting the request, or simply does not populate that field for any client. Its own
  SETTINGS is a bare `8:1` where fp.impersonate.pro sends `1:4096;7:16;8:1;GREASE`, so the two
  deployments run different HTTP/3 stacks and a difference in derivation is at least as likely
  as a difference in what reached them.
- **What would settle it**, and what C13 deliberately did not build: the same client sending
  its control stream and SETTINGS, pumping one round trip, and only then opening the request
  stream. If peet.ws then reports settings, the difference is a same-flight ordering race on
  their side; if it still reports null, the field is not populated for any client and there is
  no finding here at all. Building a second connection shape to answer it belongs to whoever
  needs the answer, not to the run that recorded the question.

## Task C12's readout, diffed against this capture, field by field

The left column is `tests/SharpTls.Tests/Quic/quic-http3-fingerprint-readout.snapshot.txt`,
which was produced offline by `TlsQuicHttp3FingerprintReadout` under the **default** arm. The
right column is this live run under the **narrowed** arm. Rows that differ because of the arm
are marked as such and are not defects.

| # | field | C12 readout (offline, default arm) | live (narrowed arm) | verdict |
| --- | --- | --- | --- | --- |
| 1 | settings 0x01 QPACK_MAX_TABLE_CAPACITY | 65536 | 0 | differs-by-arm |
| 2 | settings 0x06 MAX_FIELD_SECTION_SIZE | 262144 | 262144 | agree |
| 3 | settings 0x07 QPACK_BLOCKED_STREAMS | 100 | 0 | differs-by-arm |
| 4 | settings 0x33 H3_DATAGRAM | 1 | absent | differs-by-arm |
| 5 | settings reserved (GREASE) pair | present | absent | differs-by-arm |
| 6 | settings wire order | 1,6,7,51,GREASE | 1,6,7 | agree (same relative order, arm's subset) |
| 7 | perk segment 1, whole | `1:65536;6:262144;7:100;51:1;GREASE` | `1:0;6:262144;7:0` | differs-by-arm |
| 8 | pseudo-header order (segment 2) | m,a,s,p | m,a,s,p, confirmed by **both** endpoints | agree |
| 9 | §4.2.2 receive half - the limit we advertise | 262144 | 262144, echoed by the endpoint | agree |
| 10 | §4.2.2 send half - emitted field section against that limit | 4 field lines, within | 4 header lines echoed, within | agree |
| 11 | unidirectional stream open order | control,qpack-encoder,qpack-decoder | not published by either endpoint | still-not-published |
| 12 | QPACK Huffman flag policy | H set on 2 of 2 string literals | not published by either endpoint | still-not-published |
| 13 | QPACK name-match policy, §4.5.2 vs §4.5.4 | 4.5.2,4.5.4,4.5.2,4.5.4 | not published; both endpoints decoded all four fields correctly | still-not-published |
| 14 | reserved (GREASE) request-stream frame - N | none emitted | not published by either endpoint | still-not-published |
| 15 | reserved (GREASE) request-stream frame - payload | none emitted | not published by either endpoint | still-not-published |
| 16 | reserved (GREASE) request-stream frame - position | none emitted | not published by either endpoint | still-not-published |
| 17 | ALPN token (RFC 9114 §3.2) | no-profile-under-src-offers-h3 | `h3`, reported by both endpoints | resolved-live for the test's own profile; unchanged for `src/` |
| 18 | transport parameter 0x04 `initial_max_data` [B] | 15728640 | 15728640 | agree |
| 19 | transport parameter 0x05 `initial_max_stream_data_bidi_local` [B] | 6291456 | 6291456 | agree |
| 20 | transport parameter 0x06 `initial_max_stream_data_bidi_remote` [B] | 6291456 | 6291456 | agree |
| 21 | transport parameter 0x07 `initial_max_stream_data_uni` [B] | 6291456 | 6291456 | agree |
| 22 | transport parameter 0x08 `initial_max_streams_bidi` [B] | 100 | 100 | agree |
| 23 | transport parameter 0x09 `initial_max_streams_uni` [B] | 103 | 103 | agree |
| 24 | transport parameter wire order (segment 3) [B] | 15,14,4,5,6,7,8,9 | 15,14,4,5,6,7,8,9, confirmed by **both** endpoints | agree (still a MISMATCH against Brave — task 11's, not re-filed) |
| 25 | connection ID length pair (segment 4) [B] | 5,8 | **0,8** | harness-artifact confirmed |

Verdict counts, derived from the rows above:

```
rows                     25
agree                    12   (2, 6, 8, 9, 10, 18, 19, 20, 21, 22, 23, 24)
differs-by-arm            5   (1, 3, 4, 5, 7)
still-not-published       6   (11, 12, 13, 14, 15, 16)
resolved-live             1   (17)
harness-artifact          1   (25)
12 + 5 + 6 + 1 + 1 = 25
```

**No row disagrees in a way that is a defect.** Every difference is one of three things: the
arm this run deliberately chose, a field neither endpoint publishes, or a harness artifact.

Three rows need comment.

**Row 25 is the one the live run corrects.** The readout's `5,8` reads as a MISMATCH against
Brave's `0,8`, and it is not one — its harness uses a five-byte source connection ID
deliberately, per task 11's reason, so that `initial_source_connection_id` has a header field to
agree with. This run uses the spec's default zero-length source CID and the endpoint read back
**`0,8`, matching Brave exactly.** The readout row is a harness artifact and this capture is the
external evidence that says so.

**Row 24 agrees with the readout and still mismatches Brave.** That is not a contradiction: the
readout's "ours" column is right about us and the MISMATCH is against the target. It is task
11's finding and subsystem B's work, re-rendered here for completeness and not re-filed.

**Row 17's grep recipe is now stale, though its conclusion is not.**
`grep -rn '"h3"' src/ --include=*.cs` no longer "returns nothing" — it returns four hits, three
of them the comments that assert it returns nothing, plus
`TlsQuicHttp3FingerprintReadout.cs:753`, which is the readout printing the Brave column's own
literal. `grep -rn "WithAlpn" src/ --include=*.cs` still shows every profile under `src/`
offering `h2`/`http/1.1` and none offering `h3`, so the claim holds and only its recipe has
rotted.

## What this capture settles

1. **0 failures in 20 attempts across two hosts**, over traffic spanning a whole request and a
   4955-byte response, with `discarded=0` and `discarded_missing_keys=0` throughout. Together
   with A4 task 13's 0/10 this is the evidence for keeping A3 deferred, and it is evidence about
   one path on one day, not a guarantee.
2. **`/api/http3` returned a body over genuinely negotiated h3**, five times out of five. The
   endpoint reports the protocol it was reached over, so no fallback can produce that answer.
3. **Segment 2, `m,a,s,p`, matches Brave exactly, live, confirmed independently by both
   endpoints.** C9's fingerprint argument holds against servers we do not control.
4. **Segment 4, `0,8`, matches Brave exactly, live**, and the C12 readout's `5,8` is a harness
   artifact rather than a defect.
5. **Segment 1 under the narrowed arm is `1:0;6:262144;7:0`** and says nothing about the default
   arm, which already emits the capture's five pairs. C14–C16 is what makes the default arm
   usable live.
6. **Segment 3 is subsystem B's entirely** — every shared value matches, the missing seven
   parameters and the wire order are B's, and task 11 already filed the wire order.
7. **The two endpoints disagree about our HTTP/3 SETTINGS**, and that disagreement is recorded
   open, with the discriminating experiment named, rather than averaged away.
