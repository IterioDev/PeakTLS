# Subsystem C scoping: HTTP/3 and QPACK

Date: 2026-08-19
Status: scoping plan. Not a spec, not an implementation.
Parent: `docs/superpowers/specs/2026-08-16-quic-transport-scoping.md`
Model for structure and rigour: `docs/superpowers/plans/2026-08-17-quic-a4-minimal-connection.md`

**Purpose:** answer *"when can we start testing against `fp.impersonate.pro/api/http3`"* with a
dependency chain rather than a date, and cost the work that closes it.

This exists because subsystem C had never been scoped. The parent scoping document mentions HTTP/3
exactly once, in passing (`h3Settings` under bogdanfinn's surface, RFC 9114 s7.2.4.1), and nothing
else. Every number below is derived from a list in this document or from a grep named beside it.

**Read-only note:** this document was produced without touching `src/` or `tests/`, the index, or
history. Every claim about the tree was checked with a read or a grep, and the grep is named.

---

## The short answer

| Milestone | Tasks | Derived from |
| --- | --- | --- |
| A4 task 14, correctly sized (1-RTT sending - a transport prerequisite, not HTTP) | **5** | tasks 14a-14e below |
| C, enough to make `/api/http3` **answer** | **14** | tasks C0-C13 below |
| C, enough to make its `perk` settings segment **match a captured client** | **+3** | tasks C14-C16 below |
| RFC 9221 DATAGRAM parse-and-drop, forced by the capture's own advertisement | **+1** | task C17 below |

5 + 14 = **19 tasks to ask the endpoint**. 19 + 3 = **22 to satisfy its QPACK half**.
22 + 1 = **23 with the DATAGRAM debt closed.** Every figure is the length of a list in this file.

**The range is 19 to 23 and the four things that drive it are named in *The estimate and its
uncertainty*.** One of them - the live loss rate with A3 deferred - is not bounded by anything in
this repo, and it is the only term that could move the number a lot. It is measurable today, by
running A4's task 13, which has not been run.

---

## Findings from planning - read these before the tasks

Ten. Each changes a task, and four of them contradict something a prior document asserts. A4's plan
found eight during planning and that section was worth more than its tasks; this follows the same
practice.

### Finding 1 - A4's task 14 is five tasks, and `TlsQuicConnection.cs` already says so

Task 14 reads: *"Files: create `TlsQuicStreams.cs`, and tests. Minimal means: open a unidirectional
stream (C's control stream) and one bidirectional stream; send and receive STREAM frames with
offsets; handle FIN."* One file, stream plumbing.

That is not what stands between here and one 1-RTT byte. The source comments written during tasks
9a-ii and 9b are more honest than the plan text:

- `src/SharpTls/Quic/TlsQuicConnection.cs:2286-2287` - *"Application means a short header, which
  `TlsQuicPacketBuilder` does not build, and EarlyData means 0-RTT, which A4-minimal never sends.
  Task 14 owns 1-RTT sending."*
- `TlsQuicConnection.cs:1966-1967` - *"Application is absent because no short header can be built."*
- `TlsQuicConnection.cs:1925` - PATH_RESPONSE is *"unreachable here for the same reason the
  Application-level ACK is - task 14 owns 1-RTT."*

Checked against the tree, the list of things that do not exist is:

1. **`TlsQuicPacketHeader.WriteShortHeader` returns `int` and no packet-number offset**
   (`:424`, `WriteShortHeader(Span<byte> destination, in TlsQuicShortHeader header)`). Task 4a added
   `out int packetNumberOffset` to `WriteLongHeader` only, and 4a's own reasoning - *"a second
   computation of the same layout in our own code is a second transcription with no independent
   source"* - applies verbatim to the short header.
2. **`TlsQuicPacketBuilder` builds long headers only.** Its `Build` (`:281`) constructs a
   `TlsQuicLongHeader` and calls `WriteLongHeader`; a grep for `ShortHeader` in that file returns
   nothing.
3. **The connection's send loop skips the Application level by construction**
   (`TlsQuicConnection.cs:1792`), and its own mutation ledger carries the row *"20. The Application
   skip removed - 2 tests"*.
4. **No 1-RTT ACK can be generated**, because generating one requires sending a 1-RTT packet.
5. **PATH_RESPONSE cannot be sent**, per the task-9b amendment: RFC 9000 §12.4 Table 3 gives
   PATH_RESPONSE the row `___1`, so the answer may go only in a 1-RTT packet.
6. **The peer's flow-control limits are discarded** - see Finding 6.

**So task 14 is a phase-sized item wearing a task-sized label.** It is split into 14a-14e in
*The A4 prerequisite* below. This is the single largest correction in this document, and it is
recorded because A4's own standing rules say a cut must name where it lands: task 14 named
`TlsQuicStreams.cs` and landed six things there.

### Finding 2 - the knowingly violated 1-RTT ACK MUST costs A4 one retransmission and costs C the feature

The task-9a-ii amendment records it, past its line wrap, from
`rfc9000-section13-packetization-and-ack-generation.txt` lines 59-61: *"An endpoint MUST acknowledge
all ack-eliciting Initial and Handshake packets immediately **and all ack-eliciting 0-RTT and 1-RTT
packets within its advertised max_ack_delay**, with the following exception."*

For A4-minimal the blast radius is one packet: HANDSHAKE_DONE, retransmitted until the server gives
up. Task 13 was told to measure it.

**For C the blast radius is the whole transfer.** Every HTTP/3 byte - our control stream, our
SETTINGS, our request, and the entire response - rides 1-RTT. A response of any size spans several
packets. A server that receives no acknowledgement for any of them treats them all as lost,
retransmits them all, collapses its congestion window, and eventually closes. **There is no version
of subsystem C that works without 1-RTT ACK generation**, and no version in which it is a deviation
to be reported rather than a task to be done.

Note what this does *not* require: it does not require A3. Generating an ACK is A4 task 8's
machinery, which already tracks the Application packet-number space (`TlsQuicAckTracker`, indexed by
RFC 9000 §12.3's three spaces). What is missing is only the ability to *send* at that level, which
is 14a-14c. **Receiving and processing the peer's ACKs of our data still does nothing** - that is
A3, and it stays deferred. -> task 14c.

### Finding 3 - `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 65536` is the fingerprint, and it is the sentence that authorises the dynamic table

This is the minimal-versus-complete decision, and it is forced rather than chosen.

RFC 9204 §3.2.3, verbatim: *"For clients not using 0-RTT data (whether 0-RTT is not attempted or is
rejected) and for all HTTP/3 servers, the maximum table capacity is 0 until the encoder processes a
SETTINGS frame with a non-zero value of SETTINGS_QPACK_MAX_TABLE_CAPACITY. When the maximum table
capacity is zero, the encoder MUST NOT insert entries into the dynamic table and MUST NOT send any
encoder instructions on the encoder stream."*

A client capture's h3 SETTINGS carry `1: 65536`. So:

- **Advertise 0** and the server's encoder is *forbidden* by the RFC from using the dynamic table or
  sending a single encoder instruction. A static-table-only decoder is then complete, not a gamble.
  The `perk` settings segment becomes `1:0;6:262144;7:0;51:1;GREASE` and **both** published hashes
  change.
- **Advertise 65536** and the server's encoder is *permitted* to insert entries, send encoder
  instructions, and reference the dynamic table from a response field section. Whether any given
  server takes that permission is a behavioural question no RFC and no capture answers. A
  static-only decoder becomes a coin flip on the acceptance gate.

There is no third value that is both conforming and fingerprint-accurate. **This is the split**, and
it is why tasks C14-C16 exist as a separate arm rather than as later polish.

The same pattern governs `7: 100` (`SETTINGS_QPACK_BLOCKED_STREAMS`, RFC 9204 §5, default zero):
advertising 100 tells the peer we tolerate up to 100 streams blocked on the dynamic table, which is
§2.1.2's permission and §2.2.1's obligation on us.

### Finding 4 - QPACK has published byte vectors, and they cover exactly the minimal encoder and nothing else

RFC 9204 Appendix B.1, as published:

```
   Stream: 0
   0000                | Required Insert Count = 0, Base = 0
   510b 2f69 6e64 6578 | Literal Field Line with Name Reference
   2e68 746d 6c        |  Static Table, Index=1
                       |  (:path=/index.html)
```

That is a complete, published, byte-exact field section for a static-name-reference literal with
`H = 0`, at `Required Insert Count = 0` and `Base = 0` - **precisely what the minimal encoder
emits**. It is the same role RFC 9001 Appendix A.2 played for A4, and it means C's byte-level claims
are anchored externally rather than by round-trip.

And it carries A4's leg-1 caveat verbatim. B.1 exercises the field section prefix at 0/0, §4.5.4's
literal-with-static-name-reference, and a non-Huffman string. It exercises **nothing** of: Huffman,
a non-zero Required Insert Count, a non-zero Base, §4.5.2's indexed field line, §4.5.6's
literal-literal name, or any encoder or decoder instruction. B.2 through B.5 all exercise the
dynamic table and are the C14-C16 arm's vectors.

**Huffman has no vector in RFC 9204 at all** and must borrow RFC 7541 Appendix C.4 and C.6 - three
request examples and three response examples with Huffman coding, each published as hex.

### Finding 5 - the Huffman decoder is mandatory, the encoder is optional, and the fingerprint decides neither

Derivation, because the question was asked directly.

- RFC 9204 §4.1.2 makes `H` a **per-string sender choice**: *"This string format includes optional
  Huffman encoding."* The server's choice is not ours. A decoder that cannot read `H = 1` fails on
  the first response header a real server sends with it, and whether a given server sets it is not
  offline-checkable. **So the decoder is mandatory in both arms.**
- The published fingerprint does not contain it. The `perk` format is
  `<h3 settings> | <pseudo-header order> | <quic transport parameters, wire order> | <cid lengths>`.
  Huffman appears in none of the four segments, so `perk_hash` cannot move on it.
- **Therefore Chromium's choice does not force the encoder for this endpoint.** It forces it for a
  packet-capture diff, which is stronger evidence and is subsystem B's, not C's gate.

The conclusion taken anyway: build both directions in one task. The cost of a Huffman codec is
dominated by transcribing RFC 7541 Appendix B, which the decoder needs regardless. That table is
**257 rows** - counted, not recalled, by `grep -cE "\[ *[0-9]+\] *$"` over the Appendix B range of
`rfc7541.txt`, which is 256 octet symbols plus EOS. A canonical-code encoder over an
already-transcribed table is small. Building the decoder and then arguing about the encoder costs
more than building both. -> task C6.

**Say what is not known:** whether the endpoint, or any CDN in front of it, inspects the `H` flag or
the resulting byte lengths. Nothing in the capture says. It goes in the readout's not-yet-known
column.

### Finding 6 - the connection parses the peer's flow-control limits and throws them away

`TlsQuicConnection.ApplyPeerTransportParametersAsync` (`:1448`) reads exactly one parameter off the
`TlsQuicPeerTransportParametersEvent` - `MaxIdleTimeout` (0x01) - and then calls
`ValidateConnectionIdsUnderSection73`. Nothing retains `initial_max_data` (0x04),
`initial_max_stream_data_bidi_local` (0x05), `initial_max_stream_data_bidi_remote` (0x06),
`initial_max_stream_data_uni` (0x07), `initial_max_streams_bidi` (0x08) or
`initial_max_streams_uni` (0x09). All six are parsed and addressable -
`TlsQuicTransportParameters.Get(ulong)` (`:96`) and `TlsQuicProtocol.cs:114-124` define the ids -
and none is stored.

Task 14's *"flow control is a static budget taken from the peer's advertised initial limits"* has
nothing to read. -> task 14d.

There is a second half. RFC 9114 §6.2: *"Each endpoint needs to create at least one unidirectional
stream for the HTTP control stream. QPACK requires two additional unidirectional streams, and other
extensions might require further streams. Therefore, the transport parameters sent by both clients
and servers MUST allow the peer to create at least three unidirectional streams. These transport
parameters SHOULD also provide at least 1,024 bytes of flow-control credit to each unidirectional
stream."* Whether a given server honours that MUST is not knowable offline. A client that opens
control plus encoder plus decoder against a server advertising `initial_max_streams_uni` below 3
must fail with a named error rather than hang on a budget it silently exceeded. -> task 14d's
done-when.

### Finding 7 - SETTINGS wire order is a knob and this capture cannot prove it is one

The capture's settings, in the order the `perk` string renders them:
`1:65536;6:262144;7:100;51:1;GREASE`.

The identifiers are 1, 6, 7, 51, 126585778853 - **strictly ascending**. So Chromium's emission order
and a sort by identifier are indistinguishable from this capture alone. Contrast the transport
parameter segment, where the capture's own line 74 can say *"It is not sorted, and it is not the
RFC's presentation order"* because that list demonstrably is not sorted.

Two things say the order is nevertheless a knob: bogdanfinn's surface exposes `h3SettingsOrder` as a
field **separate from** `h3Settings` (parent scoping, the HTTP/3 row of the customisation table),
which is somebody's judgement that it varies; and RFC 9114 §7.2.4 imposes no ordering at all - its
only ordering rule is *"The same setting identifier MUST NOT occur more than once in the SETTINGS
frame."*

**So SETTINGS order goes in the not-yet-known-from-the-capture column, and C's readout must report
it there rather than claim a match.** A packet capture settles it. -> tasks C1, C3, C12.

While recomputing this: the GREASE identifier conforms to §7.2.4.1's reserved form
*"0x1f * N + 0x21"*. Check: (126585778853 - 33) / 31 = 126585778820 / 31 = 4083412220, an integer.
Its value is free - §7.2.4.1: *"Because the setting has no defined meaning, the value of the setting
can be any value the implementation selects."* The `perk` string renders it as the literal token
`GREASE`, so neither the identifier nor the value is hashed. **Its position is.** It is last, which
is also what ascending order would produce, so Finding 7's ambiguity covers it too.

### Finding 8 - the capture advertises two datagram capabilities this tree does not have

`SETTINGS_H3_DATAGRAM` is RFC 9297 §2.1.1: *"An endpoint can indicate to its peer that it is willing
to receive HTTP/3 Datagrams by sending the SETTINGS_H3_DATAGRAM (0x33) setting with a value of 1."*
0x33 is 51. The capture sends `51: 1`. It also sends transport parameter 32
(`max_datagram_frame_size`) at 65536.

`src/SharpTls/Quic/TlsQuicFrameType.cs` defines exactly **20** frame types -
`grep -cE "^\s+[A-Z][A-Za-z]+ = 0x" src/SharpTls/Quic/TlsQuicFrameType.cs` returns 20, which is RFC
9000 §12.4 Table 3's set - and `grep -n "0x30\|0x31\|Datagram"` on the same file returns nothing.
RFC 9221's DATAGRAM frame is not in the codec. An arriving DATAGRAM frame is an unknown frame type
and closes the connection.

So copying the capture's SETTINGS and transport parameters advertises a capability we cannot honour.
**In practice no server sends an unsolicited DATAGRAM frame** - one only flows inside a context the
client established - so this is a latent defect rather than an immediate one. It is recorded rather
than discovered, and the close is cheap: parse and drop. -> task C17, optional, and the reason it is
optional is stated rather than assumed.

### Finding 9 - there is no HTTP layer of any kind in this repository to build on

Three greps, all returning nothing under `src/`:

- `grep -rni --include=*.cs -e "hpack" -e "huffman" src/ tools/ samples/` - no matches.
- `grep -rln "SocketsHttpHandler\|HttpClient" src/ tests/ samples/ tools/ --include=*.cs` - no
  matches.
- `ls src/SharpTls` shows no `Http` directory. The only HTTP artefact in the tree is
  `samples/SharpTls.Http11/Program.cs`.

Two consequences.

**C cannot mirror an existing implementation.** A2 could lean on A1's shape; C has no h2 or HPACK
sibling. Every primitive - prefixed integers, string literals, the static table, field sections - is
new code.

**C cannot delegate HTTP semantics.** .NET's HTTP/3 is reached through `System.Net.Quic`, which
performs its own TLS handshake through msquic and cannot be handed SharpTls's ClientHello. That is
the same property that makes `QuicListener` a genuinely independent test peer in A4's leg 3, and
here it works against us. Request construction, response parsing and body reading are all C's,
where the h1 and h2 fingerprint checks got them from somewhere outside this tree.

**And note what this makes uncheckable:** the handoff's *"a prior session confirmed h2
fingerprinting matches what the profiles set"* rests on machinery that is not in this repository.
That is not a claim it was wrong - it is a statement that C inherits nothing from it.

### Finding 10 - the connection pump is receive-driven, and HTTP/3 requires the client to speak first

`TlsQuicConnection.PumpOnceAsync` (`:657`) allocates a receive buffer and awaits a datagram before
doing anything else. The only unsolicited send in the type is `StartAsync`'s Initial flight.

RFC 9114 §6.2.1: *"Each side MUST initiate a single control stream at the beginning of the
connection and send its SETTINGS frame as the first frame on this stream."* RFC 9114 §3.2: *"After
the QUIC connection is established, a SETTINGS frame MUST be sent by each endpoint as the initial
frame of their respective HTTP control stream."* Then the request. None of that is a reply to
anything.

So the loop needs a send-when-there-is-something-to-send entry point, and that reshapes a 2320-line
file carrying an 85-row mutation ledger whose header arithmetic (85 - 16 - 11 = 58) a reviewer must
be able to rebuild. **Sequence it as its own task**, for exactly the attributability reason task 4a
was split from task 4b. -> task 14c.

---

## What C inherits, concretely

Verified against the source, not assumed.

| Concern | Where | State |
| --- | --- | --- |
| Varint codec, both directions, with `TryRead` | `QuicVariableLengthInteger` | complete (A4 task 2). **HTTP/3 frames and QPACK prefixed integers are different encodings** - §7.1's Type and Length are QUIC varints and reuse this; RFC 9204 §4.1.1's prefixed integers are HPACK's and do not |
| STREAM frame codec, all eight wire forms | `TlsQuicStreamFrames.TryReadStream` `:182`, `WriteStreamFrameFields` `:325` | complete (A2 task 4) |
| Frame legality per level | `TlsQuicFrameLegality.Permits` `:266` | complete, and A4 gates the send path on it |
| Received-packet tracking for the Application space | `TlsQuicAckTracker` | complete and space-indexed; only the ability to *send* at Application is missing |
| Short header **read** path, 1-RTT read keys, post-AEAD key-phase check | `TlsQuicPacketReceiver` `:449`, `:692` | complete (A4 task 6) |
| Application-level key install | `TlsQuicKeySet.InstallFromTrafficSecret` `:246` | complete; the *use* is what is skipped |
| Transport parameter access by id | `TlsQuicTransportParameters.Get` `:96` | complete; retention is not - Finding 6 |
| An in-process peer and an independent one | `LoopbackQuicPeer`, `System.Net.Quic.QuicListener` | task 7 done; task 10 not started |
| Short header **write** path | `TlsQuicPacketHeader.WriteShortHeader` `:424` | exists, **no packet-number offset** - Finding 1 |
| Short header **packet** build | - | absent - Finding 1 |
| Anything HTTP | - | absent - Finding 9 |

---

## Task C0: extract the RFC sections C needs

**Files:** new files under `docs/superpowers/specs/reference-captures/`, one per topic, matching the
convention of those already there (`ls docs/superpowers/specs/reference-captures/`).

**Method, unchanged from A4 task 0:** fetch from `https://www.rfc-editor.org/rfc/rfcNNNN.txt` inside
the sandbox, locate the heading in the document *body* past the table of contents, `sed` the range,
prepend a provenance header in the established shape (see
`rfc9000-section6-version-negotiation.txt`'s first twelve lines: title with the exact subsections
covered, source URL and date, *why* it was captured, and `Copy these values; do not retype them.`),
then **diff the committed body line by line against the fetched range**, trimming only trailing
whitespace. Extraction is a task, not an assumption.

**The extracts are hard-wrapped at ~72 columns.** Four separate misreads in this project came from
quoting a sentence truncated at the wrap - three in A4's session and one that inverted §13.2.1's
scope and cost a knowingly violated MUST its correct label. Read past the wrap, every time.

### RFC 9114 - HTTP/3

| Section | Needed for one GET? | Why |
| --- | --- | --- |
| §3.2 Connection Establishment | **minimal** | the ALPN token `h3`, and SETTINGS as the initial control-stream frame |
| §4.1 HTTP Message Framing, §4.1.2 Malformed Requests and Responses | **minimal** | the HEADERS-then-DATA-then-trailers shape and the invalid-sequence connection error |
| §4.2, §4.2.1 Field Compression, §4.2.2 Header Size Constraints | **minimal** | `SETTINGS_MAX_FIELD_SECTION_SIZE`'s meaning; the capture sets it to 262144 |
| §4.3 HTTP Control Data, §4.3.1 Request Pseudo-Header Fields, §4.3.2 Response Pseudo-Header Fields | **minimal** | §4.3 is the section that proves pseudo-header **order is unconstrained** and therefore fingerprintable |
| §5 Connection Closure, §5.1-§5.4 | **minimal** | a server GOAWAY mid-request must be handled, not thrown on |
| §6, §6.1 Bidirectional Streams, §6.2 Unidirectional Streams, §6.2.1 Control Streams, §6.2.3 Reserved Stream Types | **minimal** | stream types, the at-least-three-uni-streams MUST, and the unknown-stream-type rule |
| §7.1 Frame Layout, §7.2, §7.2.1 DATA, §7.2.2 HEADERS, §7.2.4 SETTINGS with §7.2.4.1 and §7.2.4.2, §7.2.6 GOAWAY, §7.2.8 Reserved Frame Types | **minimal** | the whole wire format C emits, plus §7.2.4.1's `0x1f * N + 0x21` GREASE form |
| §8, §8.1 HTTP/3 Error Codes | **minimal** | the code that goes in an application CONNECTION_CLOSE. `grep -cE "^   H3_[A-Z_]+ \(0x"` over the §8.1 range returns 17 definitions |
| §10.8 Frame Parsing | **minimal** | C's parsers are attacker-facing; this repo's rule is that `Try`-shaped parsers never throw |
| §11.2.1 Frame Types, §11.2.2 Settings Parameters, §11.2.4 Stream Types | **minimal** | §7.2.8 and §7.2.4.1 both *point at* these registries for the reserved-from-HTTP/2 rule, and that rule is a MUST-NOT-send plus a MUST-error-on-receipt |
| §4.1.1 Request Cancellation, §4.4 CONNECT, §4.5 Upgrade, §4.6 Server Push | later | one GET, no push, no CONNECT |
| §6.2.2 Push Streams, §7.2.3 CANCEL_PUSH, §7.2.5 PUSH_PROMISE, §7.2.7 MAX_PUSH_ID | later | push is refused by never raising `MAX_PUSH_ID`; the frames still need recognising, which §11.2.1 covers |
| §9 Extensions, §10.5.1, §10.6, Appendix A | later | A.2.5 / A.3 / A.4.1 are transition guidance, useful to B and not to C |

### RFC 9204 - QPACK

| Section | Needed for one GET? | Why |
| --- | --- | --- |
| §3.1 Static Table, Appendix A | **minimal** | the table itself: **99 entries, indices 0-98** - counted by `grep -cE '^ +\| +[0-9]+ +\|'` over the Appendix A range (99 rows), first index 0, last 98, and 98 - 0 + 1 = 99 reconciles |
| §3.2.3 Maximum Dynamic Table Capacity | **minimal** | Finding 3. This one section decides the whole split and must be in the repo before anyone picks a value for setting 0x01 |
| §3.2.4 Absolute, §3.2.5 Relative, §3.2.6 Post-Base Indexing | **minimal** | a static-only decoder must *recognise* a dynamic reference to reject it correctly, and these define what it is recognising |
| §4.1, §4.1.1 Prefixed Integers, §4.1.2 String Literals | **minimal** | the two primitives, and §4.1.2 is where the Huffman flag and the N-bit-prefix extension live |
| §4.2 Encoder and Decoder Streams | **minimal** | stream types 0x02 and 0x03, and the two MAY-omit clauses that are the answer to "which streams must exist even if unused" |
| §4.5, §4.5.1-§4.5.6 Field Line Representations | **minimal** | all six. The encoder uses two or three; the decoder must recognise all six |
| §5 Configuration, §6 Error Handling | **minimal** | the two settings' identifiers and defaults; the QPACK error codes |
| Appendix B, B.1-B.5 | **minimal** | B.1 is the minimal encoder's external vector (Finding 4). B.2-B.5 are the dynamic arm's |
| §2.2 Decoder, §2.2.3 Invalid References | **minimal** | §2.2.3 is what a static-only decoder does when it meets a dynamic reference |
| §7.2 Static Huffman Encoding, §7.3, §7.4 | **minimal** | short, and §7.2 is the RFC's own statement of what the Huffman choice leaks |
| §2.1, §2.1.1, §2.1.3, §2.1.4, §4.3.1-§4.3.4 Encoder Instructions | dynamic arm | our encoder never inserts; in the 0-capacity arm the server MUST NOT send these at all |
| §2.1.2 Blocked Streams, §2.2.1 Blocked Decoding, §2.2.2 State Synchronization, §4.4.1-§4.4.3 Decoder Instructions | dynamic arm | required the moment setting 0x07 and setting 0x01 are both non-zero |
| Appendix C Sample Single-Pass Encoding Algorithm | later | an encoder-side optimisation for the dynamic table |

### RFC 7541 - HPACK, referenced by QPACK for two primitives only

| Section | Needed for one GET? | Why |
| --- | --- | --- |
| §5.1 Integer Representation, §5.2 String Literal Representation | **minimal** | RFC 9204 §4.1.2 defers to §5.2 by name and extends it; §4.1.1 defers to §5.1 |
| Appendix B Huffman Code | **minimal** | **257 rows** - `grep -cE "\[ *[0-9]+\] *$"` over the Appendix B range. §4.1.2: *"the Huffman table from Appendix B of [RFC7541] is used without modification"* |
| Appendix C.1 (integer examples), C.4 and C.6 (the Huffman-coded request and response examples) | **minimal** | the only published Huffman vectors in either RFC |
| §2, §3, §4, §6, Appendix A | **not needed** | HPACK's dynamic table, index address space and binary format are *replaced* by QPACK, not reused. Extracting them would invite someone to implement the wrong thing |

### RFC 9297 and RFC 9221 - because the capture advertises them

| Section | Needed? | Why |
| --- | --- | --- |
| RFC 9297 §2.1 HTTP/3 Datagrams, §2.1.1 SETTINGS_H3_DATAGRAM | **minimal** | the capture sends `51: 1`, and §2.1.1 says what that asserts |
| RFC 9221 §3 Datagram Frame Types, §4 Behavior and Usage, and its `max_datagram_frame_size` transport parameter | conditional | Finding 8. Needed only if task C17 is taken; extract it with C17 rather than speculatively |

**Done when** every extract diffs at zero mismatches against an independent re-fetch of the same
range, and each carries a provenance header naming the exact subsections it covers.

---

## The A4 prerequisite - task 14, split

These are transport tasks in A4's files, not HTTP tasks. They are listed here because C cannot start
without them and because A4's task 14 does not describe them.

### Task 14a: `WriteShortHeader` returns the packet-number offset

**Files:** `TlsQuicPacketHeader.cs`, and tests.
**RFC:** 9000 §17.3.1 (short header); 9001 §5.4.2 (the sample offset).

Behaviour-preserving signature change, split out for the reason task 4a was: a signature change to
A1 bundled with new send-path code makes a failure unattributable between them. Do not recompute the
offset in the builder - 4a's own text explains why that is a second transcription with no
independent source.

**Done when** every existing A1 short-header test is green with no behaviour change, and one new
test pins the returned offset against a hand-derived short header whose layout is read off §17.3.1
rather than off our own arithmetic.

### Task 14b: short-header packet assembly

**Files:** `TlsQuicPacketBuilder.cs`, and tests.
**RFC:** 9001 §5.3 (AEAD, and the associated data being the header through the unprotected packet
number), §5.4 (header protection, and the five protected bits for a short header); 9000 §17.3.1,
§12.2 (a short-header packet is always last in a datagram - `TlsQuicPacketHeader.cs:418-421` already
documents this on the read side).

Build one protected short-header packet from a header spec and an **ordered** frame list, the same
shape as the long-header path, gated through `TlsQuicFrameLegality.Permits` and emitting a
`TlsQuicSentPacket`.

**Done when** a 1-RTT packet built by this path is opened by `TlsQuicPacketReceiver` with keys
derived independently of the builder; the key-phase bit written matches the installed phase; the
datagram builder rejects anything coalesced after it; and one hand-derived expected-bytes test
exists at a non-default packet-number encoded length. **There is no published vector for a 1-RTT
packet in RFC 9001 Appendix A** - A.2 and A.3 are Initial. Say so; this task's evidence is weaker
than task 4b's and the report must not claim otherwise.

### Task 14c: the Application send path - the ACK, the pump, and PATH_RESPONSE

**Files:** `TlsQuicConnection.cs`, and tests.
**RFC:** 9000 §13.2 and **§13.2.1 read past its line wrap** (Finding 2), §12.4 Table 3
(PATH_RESPONSE is `___1`), §12.3 (the Application packet-number space).

Three things, together because all three are the single change "the connection may now send at
Application level", and separating them would leave the skip half-removed:

1. Remove the Application skip at `TlsQuicConnection.cs:1792` and let `TlsQuicAckTracker` build
   Application-space ACKs. **This closes the phase's one knowingly violated MUST.** The EarlyData
   skip at `:1757` stays - 0-RTT shares the Application space and §12.4 forbids an ACK in a 0-RTT
   packet, which is a different reason and is not fixed by this task.
2. Add a send-when-there-is-something-to-send path to the pump (Finding 10), so the client can speak
   first. The receive-driven loop stays; this is an additional entry, not a replacement.
3. Send the PATH_RESPONSE that task 9b recorded and could not emit.

**Done when** a 1-RTT packet the connection sent is acknowledged by the loopback peer and by the
MsQuic listener; the mutation ledger's row 20 ("the Application skip removed") is re-run and now
kills; a test drives the pump to send with no datagram received first; the recorded PATH_CHALLENGE
data leaves in a PATH_RESPONSE and the test that currently asserts *no datagram follows* is inverted
with its reason updated; and A4's *Not in this phase* row for the delayed-ACK timer is revisited -
`max_ack_delay` now has a customer, and whether it is honoured or deliberately left at immediate
must be a stated decision rather than a silence.

### Task 14d: peer flow-control limits and the static budget

**Files:** `TlsQuicConnection.cs`, `TlsQuicConnectionOptions.cs`, and tests.
**RFC:** 9000 §4.1 (data flow), §18.2 (the six limit parameters); 9114 §6.2 (the at-least-three
uni-streams MUST and the 1,024-byte SHOULD).

Retain the six parameters Finding 6 shows are discarded. Expose a static budget: connection-level and
per-stream, per direction and per stream type. **No `MAX_DATA` or `MAX_STREAM_DATA` is ever sent and
no `*_BLOCKED` frame is ever handled** - that is A4-complete's, and this task must say so at the
point where the budget is consumed so nobody assumes it grows.

**Done when** each of the six parameters is read from a scripted peer and reaches the budget with a
named witness per parameter; a server advertising `initial_max_streams_uni` below 3 fails with a
named error rather than hanging; and exhausting the budget fails cleanly rather than silently
exceeding the peer's limit.

### Task 14e: minimal streams

**Files:** create `TlsQuicStreams.cs`, and tests.
**RFC:** 9000 §2.1 (stream ids and the two type bits), §19.8 (STREAM - codec already exists), §4.1.

This is A4 task 14's original text, and it is correct as far as it goes: open a client-initiated
unidirectional stream and a client-initiated bidirectional stream, send and receive STREAM frames
with offsets, handle FIN. No stream state machine beyond open/data/fin, no `RESET_STREAM`, no
`STOP_SENDING` semantics. It also needs the receive half C depends on: **accept peer-initiated
unidirectional streams**, because RFC 9204 §4.2's last clause is *"An endpoint MUST allow its peer
to create an encoder stream and a decoder stream even if the connection's settings prevent their
use."*

**Done when** A4 task 14's original done-when holds, plus: a peer-initiated unidirectional stream is
accepted and its bytes delivered in order; and stream ids for all four §2.1 combinations are derived
from the type bits with a named witness per combination.

---

## Subsystem C

### Task C1: the HTTP/3 layout spec

**Files:** create `TlsQuicHttp3Spec.cs`, and tests. No behaviour.

The same seam A4 task 1 created, for the layer above. Every fingerprint dimension C can vary, so
subsystem B populates a struct rather than rewriting C:

- the SETTINGS list **as an ordered sequence of identifier/value pairs**, not a set of named
  properties - Finding 7 makes order a knob, and a named-property design cannot express order
- whether a reserved (GREASE) setting is emitted, and where in the sequence
- pseudo-header order, as an ordered list, defaulting to the capture's `:method, :authority,
  :scheme, :path`
- which unidirectional streams to open, and **in what order** - RFC 9114 §6.2's *"Endpoints SHOULD
  create the HTTP control stream as well as the unidirectional streams required by mandatory
  extensions (such as the QPACK encoder and decoder streams) first"* leaves the order among the
  three free
- QPACK encoder policy: Huffman on or off per string, and whether a header with a static name match
  prefers §4.5.4 (name reference) or §4.5.6 (literal name)
- whether reserved (GREASE) frames are sent on a request stream, per §7.2.8 - bogdanfinn exposes
  this as `h3SendGreaseFrames`

**A constant nobody can check is not allowed.** Where the capture bounds a default, take it and cite
the capture line. Where it does not - SETTINGS order, GREASE frame policy, stream-open order - the
default is a **declared placeholder**, and it goes in task C12's not-yet-known column, exactly as A4
task 1 refused to invent a range for `initial_rtt` and task 8 labelled `AckRangeLimit` a placeholder.
Do not manufacture a plausible value.

**Done when** every field above exists; validation rejects out-of-range values with a reachability
witness per field; each placeholder default carries a doc comment naming it as one and naming the
task that would settle it; and a grep of the task's own diff finds no numeric layout literal outside
the defaults block.

### Task C2: the HTTP/3 frame codec

**Files:** create `TlsQuicHttp3Frames.cs`, and tests.
**RFC:** 9114 §7.1 (Type, Length, Payload - all QUIC varints, reuse
`QuicVariableLengthInteger.TryRead`), §7.2 (the defined types), §7.2.8 and §11.2.1 (reserved types:
the `0x1f * N + 0x21` form which MAY be sent, and the HTTP/2-inherited types which MUST NOT be sent
and whose receipt MUST be a connection error of type H3_FRAME_UNEXPECTED), §10.8 (frame parsing).

Type-and-length framing only; payloads are the following tasks'. This is the widest attack surface
after the QUIC receive loop, so A2's rule binds: **`Try`-shaped parsers must never throw**, and the
rejecting path allocates zero bytes.

**Done when** every defined and reserved type round-trips; the reserved-identifier generator's output
satisfies `(id - 0x21) mod 0x1f == 0` for a range of N, checked by recomputation and not against a
table; an HTTP/2-inherited type is rejected with H3_FRAME_UNEXPECTED named; a frame whose Length
overruns the available bytes is rejected without a throw; a frame with trailing bytes after its
identified fields is rejected per §7.1; and a mutation on the length bound is killed by a named test.

### Task C3: the SETTINGS frame

**Files:** `TlsQuicHttp3Frames.cs` or a sibling, and tests.
**RFC:** 9114 §7.2.4, §7.2.4.1, §7.2.4.2, §11.2.2; 9204 §5; 9297 §2.1.1.

Encode from task C1's **ordered** list. Decode preserving order, because the peer's order is as much
a fingerprint as ours and B will want to read it. Enforce the duplicate-identifier rule and the
HTTP/2-reserved-identifier rule.

**Done when** the capture's five settings encode to bytes that re-parse to the same five pairs **in
the same order**; the rendered settings segment equals `1:65536;6:262144;7:100;51:1;GREASE`
character for character, with the GREASE token substituted by the same rule the `perk` format uses;
a duplicate identifier is rejected with H3_SETTINGS_ERROR named; an HTTP/2-inherited identifier is
rejected; `SETTINGS_H3_DATAGRAM` with a value other than 0 or 1 is rejected per RFC 9297 §2.1.1; and
a test asserts the encoder does **not** sort - pass the list in a non-ascending order and confirm the
bytes follow the list. Finding 7 makes that the one property the capture cannot settle, so it must at
least be expressible.

### Task C4: unidirectional streams and the control stream

**Files:** create `TlsQuicHttp3Streams.cs`, and tests.
**RFC:** 9114 §6.2 (the stream-type varint header, the unknown-type rule, the at-least-three MUST),
§6.2.1 (control stream type 0x00, SETTINGS first, H3_MISSING_SETTINGS, H3_STREAM_CREATION_ERROR,
H3_CLOSED_CRITICAL_STREAM), §6.2.3 (reserved stream types), §11.2.4; 9204 §4.2 (encoder 0x02,
decoder 0x03).

Open our streams per the C1 spec, in the spec's order. Read the peer's, dispatching by type.
**§6.2's unknown-type rule is a MUST with two legal answers** - abort reading or discard - and
*"The recipient MUST NOT consider unknown stream types to be a connection error of any kind."* A peer
opening a GREASE stream must not kill the connection.

**Done when** the control stream's first frame being anything but SETTINGS is rejected with
H3_MISSING_SETTINGS named; a second control stream is rejected with H3_STREAM_CREATION_ERROR; a
closed control stream is rejected with H3_CLOSED_CRITICAL_STREAM; an unknown stream type is tolerated
with a witness that the connection survives; a unidirectional stream reset before its type byte
arrives is tolerated (§6.2's *"A receiver MUST tolerate unidirectional streams being closed or reset
prior to the reception of the unidirectional stream header"*); and the order the three streams are
opened in matches the spec, asserted from the recorded STREAM frames rather than from the spec object.

### Task C5: QPACK primitives - prefixed integers and non-Huffman string literals

**Files:** create `TlsQuicQpackPrimitives.cs`, and tests.
**RFC:** 9204 §4.1.1, §4.1.2; 7541 §5.1, §5.2.

These are **not** QUIC varints and must not be routed through `QuicVariableLengthInteger` - different
encoding, different section, different RFC. Note also §4.1.2's extension: *"An 'N-bit prefix string
literal' begins mid-byte... The prefix size, N, can have a value between 2 and 8, inclusive."*

**Done when** RFC 7541 C.1.1, C.1.2 and C.1.3 reproduce byte-exactly in both directions (10 at a
5-bit prefix, 1337 at a 5-bit prefix, 42 starting at an octet boundary); every prefix size from 2 to
8 round-trips; a continuation chain that overflows is rejected without a throw; and a mutation on the
prefix-fill boundary is killed by a named test. Hand-derived bytes, not round-trips - a round trip
proves the encoder and decoder agree while both are wrong.

### Task C6: the Huffman codec, both directions

**Files:** create `TlsQuicQpackHuffman.cs`, and tests.
**RFC:** 7541 Appendix B (the table, **257 rows**), §5.2, Appendix C.4 and C.6; 9204 §4.1.2, §7.2.

Transcribe the table from the extract, never from memory. Both directions in one task per Finding 5.

**Done when** RFC 7541 C.4.1, C.4.2, C.4.3, C.6.1, C.6.2 and C.6.3 all decode to their published
header lists and re-encode to their published bytes; the EOS symbol and an over-long padding run are
both rejected without a throw per §5.2; the table's row count is derived by the task's own self-check
rather than asserted; and a mutation on the padding-length bound is killed by a named test. **A
transcription error in a 257-row table is invisible to a round trip** - the encoder and decoder would
share it - so the published vectors are the only evidence that counts, and the report must say which
rows they actually exercise.

### Task C7: the static table and the encoder's field line representations

**Files:** create `TlsQuicQpackStaticTable.cs` and `TlsQuicQpackEncoder.cs`, and tests.
**RFC:** 9204 §3.1, Appendix A (99 entries, 0-98), §4.5.1 (the encoded field section prefix), §4.5.2
(indexed field line), §4.5.4 (literal with name reference), §4.5.6 (literal with literal name);
Appendix B.1.

Static references only. `Required Insert Count = 0` and `Base = 0` always, which is what makes the
prefix constant and the encoder stateless in this arm.

**Done when** RFC 9204 B.1 reproduces byte-exactly - `0000 510b 2f69 6e64 6578 2e68 746d 6c` for
`:path=/index.html` - with the plaintext taken from the extract and not from this plan; the static
table's entry count is derived by a self-check over the transcribed list; a full match on name and
value emits §4.5.2 while a name-only match emits §4.5.4, each with a hand-derived expected byte
string; the Huffman flag follows the C1 spec rather than a constant, with the same header encoded
both ways in one test; and a mutation on the static-versus-dynamic table bit is killed by a named
test - that bit is the difference between a valid reference and a reference into a table that does
not exist.

### Task C8: the decoder, static-only

**Files:** create `TlsQuicQpackDecoder.cs`, and tests.
**RFC:** 9204 §4.5.1-§4.5.6 (all six representations), §2.2, §2.2.3, §3.2.4-§3.2.6, §6; 9114 §4.2.2.

Decode a field section whose prefix declares `Required Insert Count = 0`. Recognise all six
representations; resolve the three static ones; **reject the three dynamic ones with
QPACK_DECOMPRESSION_FAILED** rather than misreading them. Enforce `SETTINGS_MAX_FIELD_SECTION_SIZE`
per §4.2.2 on the way in.

**Done when** B.1's bytes decode to `:path=/index.html`; each of the three dynamic representations is
rejected with the error code named and a witness per representation; a non-zero Required Insert Count
is rejected in this arm with the reason recorded in the source (it becomes legal in C14); a truncated
section, an out-of-range static index and an over-long string are each rejected without a throw; a
field section exceeding the advertised maximum is rejected; and the decoder allocates zero bytes on
the rejecting path.

### Task C9: HEADERS and the request

**Files:** create `TlsQuicHttp3Request.cs`, and tests.
**RFC:** 9114 §4.1, §4.2, §4.2.2, §4.3, §4.3.1, §7.2.2.

Emit pseudo-headers in the C1 spec's order, then regular fields. **§4.3's only ordering rule is that
all pseudo-header fields precede regular fields** - it imposes no order among the pseudo-headers
themselves, which is exactly why `m,a,s,p` is a fingerprint and not a conformance requirement. Say
that in the source, with the citation, so nobody later "fixes" the order to something canonical.

**Done when** a GET for `https://fp.impersonate.pro/api/http3` produces a HEADERS frame whose decoded
pseudo-header order is `:method, :authority, :scheme, :path`, read back by task C8's decoder rather
than asserted against the encoder's input; changing the spec's order changes the bytes, with a
witness; §4.3.1's mandatory-field rules are enforced (exactly one each of `:method`, `:scheme`,
`:path`; `:path` non-empty for an https URI); and a reserved GREASE frame is emitted on the request
stream when the spec asks for one and is absent when it does not.

### Task C10: DATA and the response

**Files:** `TlsQuicHttp3Request.cs`, and tests.
**RFC:** 9114 §4.1 (the message shape and the invalid-sequence connection error), §4.1.2, §7.2.1,
§4.3.2.

Read HEADERS, then zero or more DATA frames, then optionally trailing HEADERS, then FIN. Enforce
§4.1's invalid sequences - a DATA before any HEADERS, or a HEADERS or DATA after the trailers - as
H3_FRAME_UNEXPECTED. Tolerate interim responses and unknown frame types interleaved, per §4.1 and §9.

**Done when** a scripted response of HEADERS plus two DATA frames plus FIN yields the concatenated
body byte-exactly; each of §4.1's three named invalid sequences is rejected with H3_FRAME_UNEXPECTED
and a witness per sequence; an unknown frame type between HEADERS and DATA is skipped without error;
a DATA frame split across two STREAM frames reassembles; and nothing on this path throws for any
input.

### Task C11: the HTTP/3 connection

**Files:** create `TlsQuicHttp3Connection.cs`, and tests.
**RFC:** 9114 §3.2, §5.1-§5.4, §6.2.1, §7.2.4, §7.2.6, §8.1.

Wire it together: on a confirmed QUIC connection, open the spec's unidirectional streams, send
SETTINGS as the control stream's first frame, open a request stream, send HEADERS with FIN, read the
response. Handle a server GOAWAY (§5.2) and map an HTTP/3 error to an application CONNECTION_CLOSE
(§8.1).

**One thing this task must state rather than discover:** the ALPN token is `h3` (§3.2), it lives in
the `ClientHelloProfile`, and A4's Finding 1 requires a **fresh profile per connection**.
`grep -rn '"h3"' src/ --include=*.cs` returns nothing today - no profile in the tree offers it. That
is subsystem B's and E's to supply, and C's done-when must not silently assume it.

**Done when** a full request and response complete against `LoopbackQuicPeer` and against
`System.Net.Quic.QuicListener` (A4 task 10's fixture), both offline; SETTINGS not being the peer's
control-stream first frame closes with H3_MISSING_SETTINGS; a GOAWAY mid-request is handled without a
throw; and the connection's own SETTINGS are read back off the recorded STREAM frames, not off the
spec object.

### Task C12: the HTTP/3 fingerprint readout

**Files:** create `TlsQuicHttp3FingerprintReadout.cs`, and tests.
**Model:** `src/SharpTls/Quic/TlsQuicFingerprintReadout.cs` and its snapshot
`tests/SharpTls.Tests/Quic/quic-fingerprint-readout.snapshot.txt`.

Render the `perk` string's **first two segments** - the h3 SETTINGS and the pseudo-header order -
from what we actually emitted, one row per field, with a verdict column of exactly three values:
`match`, `MISMATCH`, `not-yet-known-from-the-capture`. Task 11 established that the third column was
the most valuable, because it told subsystem B what to go capture. Do the same.

The rows whose verdict is `not-yet-known` before this task is written, taken from the findings above:
SETTINGS wire order (Finding 7); GREASE frame emission on the request stream; the order in which the
three unidirectional streams are opened; the Huffman flag policy (Finding 5); and the QPACK
representation choice between §4.5.2 and §4.5.4 for a full static match. That is five, and the count
is the length of that sentence's list.

The rows this task **must not** report as not-yet-known, because they are settled: the five SETTINGS
identifier and value pairs, and the pseudo-header order. The capture publishes both affirmatively.

**Done when** the readout is derived from the recorded stream bytes rather than from the spec object,
with a test in the shape of task 11's `TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith` proving it
cannot be a restatement; every row's verdict is one of the three values; the row count is derived
from the rendered list rather than asserted beside it; and the rendered settings segment is diffed
character for character against the capture's.

### Task C13: the live run

**Files:** extend `tests/SharpTls.Tests/Interop/QuicPublicEndpointInteropTests.cs` (A4 task 13's
file). `SHARPTLS_RUN_INTEROP=1`-gated, never in the gate.

`https://fp.impersonate.pro/api/http3` and `https://tls3.peet.ws/api/all`, on the same run, per the
parent scoping's *How to use them together*. **Disagreement between them is a finding to investigate,
not a result to average.**

**Expect loss to kill attempts.** A3 is deferred; a single lost packet ends the attempt. Retry at the
process level and **record the failure rate** - with C's traffic spanning many more packets than a
handshake, this is a materially larger exposure than A4 task 13's, and it is A3's strongest evidence.

**Done when** `/api/http3` returns a body rather than its protocol-segregation refusal - which is the
gate, because it cannot be satisfied by a fallback; the returned `perk`, `perk_hash` and
`perk_hash_normalized` are recorded verbatim into a new file under `reference-captures/` alongside
a client capture; the task C12 readout is diffed against it field by field; the attempt count and
the QPACK arm in force are recorded; and **the two `perk` segments C does not own - transport
parameter wire order and the CID length pair - are reported as subsystem B's, not as C's failures.**
Task 11 already recorded transport parameter wire order as a MISMATCH; C must not re-file it.

---

## The dynamic-table arm - only if setting 0x01 carries the capture's 65536

Finding 3 is the whole justification. These three exist because of one number in the capture.

### Task C14: the QPACK dynamic table and the encoder-stream reader

**Files:** create `TlsQuicQpackDynamicTable.cs`, and tests.
**RFC:** 9204 §3.2, §3.2.1 (size), §3.2.2 (capacity and eviction), §3.2.3, §3.2.4 (absolute), §3.2.5
(relative), §3.2.6 (post-base), §4.3.1 (set capacity), §4.3.2 (insert with name reference), §4.3.3
(insert with literal name), §4.3.4 (duplicate); Appendix B.2-B.5.

**Decoder side only.** Our encoder never inserts and never sends an encoder instruction, in either
arm - that is a free choice §4.2 grants and it costs nothing in the `perk` string. What this task
builds is the table the *peer's* encoder drives.

**Done when** B.2, B.3, B.4 and B.5 reproduce as published in the decoding direction, including their
stated table sizes and eviction points; a capacity above the advertised maximum is rejected with
QPACK_ENCODER_STREAM_ERROR named (§3.2.3's MUST NOT); an insertion that would evict an entry with
outstanding references is rejected; all three indexing modes resolve with a witness per mode; and
nothing on this path throws for any input.

### Task C15: decoder-stream instructions

**Files:** `TlsQuicQpackDecoder.cs`, `TlsQuicHttp3Streams.cs`, and tests.
**RFC:** 9204 §4.4.1 (section acknowledgment), §4.4.2 (stream cancellation), §4.4.3 (insert count
increment), §2.2.2 (state synchronization).

Required by §4.2: the decoder stream may be omitted **only** *"if its decoder sets the maximum
capacity of the dynamic table to zero"*, and this arm does not.

**Done when** a decoded field section that referenced the dynamic table produces a Section
Acknowledgment; a cancelled request stream produces a Stream Cancellation; insertions decoded without
an accompanying field section produce an Insert Count Increment; and each instruction's bytes are
hand-derived rather than round-tripped.

### Task C16: blocked decoding

**Files:** `TlsQuicQpackDecoder.cs`, and tests.
**RFC:** 9204 §2.1.2, §2.2.1, §2.2.3.

A field section whose Required Insert Count exceeds the entries received so far must be **held** until
the encoder stream catches up - the two arrive on different streams with no ordering guarantee. This
is what `SETTINGS_QPACK_BLOCKED_STREAMS = 100` promises the peer.

**Done when** a field section delivered before its encoder instructions decodes correctly once they
arrive; the number of simultaneously blocked streams is bounded by the advertised value with a
witness at the boundary; and a section that never unblocks fails on the connection's deadline rather
than hanging - the same deadline-not-retransmission distinction A4 task 9a-ii draws.

### Task C17: RFC 9221 DATAGRAM, parse and drop - optional, and Finding 8 says why

**Files:** `TlsQuicFrameType.cs`, `TlsQuicFrames.cs`, `TlsQuicFrameLegality.cs`, and tests.
**RFC:** 9221 §3, §4; extract them with this task, not before.

Only needed because the capture advertises `max_datagram_frame_size` and `SETTINGS_H3_DATAGRAM = 1`.
Parse the two frame forms and drop the payload; never send one.

**Done when** both forms parse without a throw; `TlsQuicFrameLegality`'s table gains their rows with
each cell verified against RFC 9221 rather than inferred; and the report states plainly that this
closes an advertisement, not a feature.

---

## Ordering constraint

**Nothing in C can be attempted before 1-RTT sending works:**
`14a -> 14b -> 14c -> 14d -> 14e`, in that order.

The reasons, one per edge. 14a before 14b because the builder needs the packet-number offset and must
not recompute it. 14b before 14c because the send path cannot skip-remove a level it cannot build a
packet for. 14c before 14d because a budget with no send path has no consumer and its guards would be
unreachable by construction - A2's rule that provenance decides reachability. 14d before 14e because
a stream that cannot ask how much credit it has will invent a number.

**Then C, and the order is mostly forced by what anchors what:**

`C0 -> C1 -> C2 -> C3 -> C4`, and independently `C0 -> C5 -> C6 -> C7 -> C8`, joining at
`C9 -> C10 -> C11 -> C12 -> C13`.

- **C0 first, absolutely.** Every later task cites a section, and this project's rule is that a
  citation with no in-repo extract is not checkable. Two implementers in a prior session cited
  sections that were not in the repo and both happened to be right, which is exactly the problem.
- **C1 before C2, C3, C4, C7 and C9**, because all five read the spec, and a knob added late is a
  knob whose guard is unwitnessed.
- **C5 before C6 and C7.** The prefixed integer is the substrate of both; the Huffman flag is one bit
  of a string literal C5 defines.
- **C6 before C8**, not because the decoder needs an encoder but because a decoder that cannot read
  `H = 1` cannot be tested against RFC 7541 C.4 and C.6, which are the only Huffman vectors there
  are.
- **C7 before C8**, so B.1 is reproduced by the encoder first and read back by the decoder second -
  the same direction task 4b took with RFC 9001 A.2, and for the same reason: get the external byte
  match before the general form.
- **C11 before C12**, because a readout of bytes that were never emitted is a restatement of the
  spec, which is the failure task 11's `TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith` exists to
  prevent.
- **C13 last of the minimal arm**, and it is the only task in that arm needing a network.
- **C14 -> C15 -> C16** after C13, and only if the arm is taken: the table before the instructions
  that acknowledge it, and the instructions before the blocking that depends on their counts.

**The single riskiest ordering assumption**, stated as A4's plan states its own: **that task 14b can
produce a 1-RTT packet an implementation we did not write will open, with no published vector to
anchor it.** RFC 9001 Appendix A has no 1-RTT example - A.2 and A.3 are Initial packets. So 14b's
evidence would otherwise be our own read path, which A2's trap list warns about by name: *"Seal/open,
encode/decode pairs cancel out."* The mitigation is leg 3: **attempt the MsQuic loopback exchange of
a 1-RTT packet as the first thing in 14b, before writing the general form.** If a 1-RTT packet we
build cannot be opened by MsQuic, stop and report - every later task's evidence rests on it.

A second note that is a recommendation rather than a constraint: **A4 task 13 should run before 14a.**
It costs one session, it is the only thing that converts the live loss rate from an unknown into a
number, and that unknown is the widest term in the estimate below.

---

## The estimate and its uncertainty

**19 tasks to ask the endpoint. 22 to satisfy its QPACK half. 23 with the DATAGRAM debt closed.**
Each figure is the length of a list in this document: 14a-14e is 5, C0-C13 is 14, C14-C16 is 3, C17
is 1. 5 + 14 = 19; 19 + 3 = 22; 22 + 1 = 23.

Four things drive the range, and only the fourth can move it outside it.

1. **Which value goes in setting 0x01.** 0 costs 19; the capture's 65536 costs 22. This is a
   fingerprint decision, not an engineering one, and it belongs to the user or to subsystem B. It is
   the only term in the range settled by a choice rather than by evidence.
2. **Whether the server actually exercises the dynamic table.** Not offline-knowable and not stated
   by any RFC - §3.2.3 grants permission, it does not predict use. One live probe against
   `fp.impersonate.pro` with 65536 advertised collapses this either way, and it can be run the day
   C13 first works. If the server never inserts, C14-C16 remain owed for correctness but stop
   blocking the gate.
3. **Whether 14c's reshaping of `PumpOnceAsync` is a refactor or a rewrite.** It is 2320 lines
   carrying an 85-row mutation ledger whose header arithmetic a reviewer must be able to rebuild.
   A4's own history says the honest expectation is a fix round: every task in that phase found
   something. If 14c splits, the number is 20 rather than 19.
4. **Whether A3 stays deferred - the only term that can move the number a lot.** C's traffic is many
   more packets than a handshake, and with no retransmission a single loss ends the attempt. The real
   loss rate on a real path to this endpoint is **unmeasured**: A4 task 13 exists to measure it and
   has not been run. If a multi-packet response cannot complete often enough to be useful, A3 enters
   the chain - items 13 to 18 in the parent scoping, so roughly six further tasks at that document's
   granularity - and the answer becomes 25 to 29 rather than 19 to 23.

**What would narrow the range fastest, in order:** run A4 task 13 (settles 4, adds no new code); then
take the 65536 arm and probe once (settles 2); then attempt 14b against MsQuic (settles the riskiest
ordering assumption and most of 3).

No date is offered. The parent scoping's estimate for subsystem A moved from "35 to 45" to a 25-task
minimal milestone once the cuts were named, and every figure in this project that was asserted rather
than derived has moved at least once.

---

## The minimal-versus-complete split, stated plainly

One row per decision, with the clause that decides it.

| Decision | Minimal (`/api/http3` answers) | Complete (matches a captured client) | The clause |
| --- | --- | --- | --- |
| `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (0x01) | **0** | **65536** | RFC 9204 §3.2.3. At 0 the peer's encoder MUST NOT use the dynamic table or send encoder instructions. At 65536 it may |
| `SETTINGS_QPACK_BLOCKED_STREAMS` (0x07) | **0** | **100** | RFC 9204 §5, §2.1.2 |
| QPACK dynamic table, decode side | **not built** | **built** (C14) | entailed by 0x01 |
| QPACK dynamic table, encode side | **never**, in both arms | **never** | RFC 9204 §4.2's first MAY - our encoder simply does not wish to use it, and nothing in the `perk` string can see that |
| Huffman **decoding** | **mandatory** | mandatory | RFC 9204 §4.1.2 - `H` is the sender's per-string choice, so the server's choice is not ours |
| Huffman **encoding** | optional for the gate | build it anyway | absent from all four `perk` segments. Required only for a packet-capture diff, which is subsystem B's evidence. Built because the 257-row table is transcribed for the decoder regardless |
| Control stream (type 0x00) | **MUST exist** | MUST exist | RFC 9114 §6.2.1 - *"Each side MUST initiate a single control stream at the beginning of the connection and send its SETTINGS frame as the first frame on this stream"* |
| Our QPACK **encoder** stream (0x02) | **MAY be omitted** | **open it, leave it empty** | RFC 9204 §4.2 - *"An endpoint MAY avoid creating an encoder stream if it will not be used"*. Omitting it is legal and is a difference from Chromium, which opens one |
| Our QPACK **decoder** stream (0x03) | **MAY be omitted** | **MUST exist and carry instructions** | RFC 9204 §4.2 - the omission is permitted *"if its decoder sets the maximum capacity of the dynamic table to zero"*, which is false in the complete arm |
| The peer's encoder and decoder streams | **MUST be accepted** in both arms | MUST be accepted | RFC 9204 §4.2 - *"An endpoint MUST allow its peer to create an encoder stream and a decoder stream even if the connection's settings prevent their use"* |
| Blocked decoding | not needed at 0x07 = 0 | **needed** (C16) | RFC 9204 §2.2.1 |
| Field line representations, encode | §4.5.1 prefix at 0/0, plus §4.5.2, §4.5.4, §4.5.6 | same | our encoder is static-only in both arms |
| Field line representations, decode | recognise all six, resolve three, reject three | resolve all six | RFC 9204 §2.2.3 |
| RFC 9221 DATAGRAM | not parsed - and that is a **latent defect**, not a clean cut | parse and drop (C17) | Finding 8 |

**The one-sentence version:** the smallest thing that makes `/api/http3` answer is a static-table-only
QPACK with a Huffman decoder, one control stream, and no encoder or decoder stream at all - and it
gets a different `perk_hash` than that client, because the two QPACK settings that make it legal are
themselves part of the hash.

---

## What C does not own, and must not be blamed for

| Not C's | Whose | Why it will look like C's |
| --- | --- | --- |
| Transport parameter wire order - task 11's standing MISMATCH | **B** | it is `perk` segment 3, so it appears in the same string C13 records. The capture's own item 2 says SharpTls can already express it |
| The CID length pair `0,8` | **A4 / B** | `perk` segment 4. Task 11 reports it as a match at the default and notes the witness is erased at zero length |
| `initial_rtt` being absent from our transport parameters | **B** | task 9a-ii's amendment records it as a known deviation; it is in segment 3 |
| The ALPN `h3` profile | **B / E** | `grep -rn '"h3"' src/ --include=*.cs` returns nothing; no profile in the tree offers it |
| Retransmission of a lost response packet | **A3** | it will present as C hanging or as a truncated body |
| Key update over a long-lived h3 connection | **A4-complete** | one GET never triggers it |

---

## When can we start testing against `fp.impersonate.pro/api/http3`?

As a dependency chain, not a date. Each arrow is a hard prerequisite, and the reason is stated.

```
A4 9b  [DONE, a0537ea]
  -> A4 10   MsQuic loopback gate       [DONE, 776bc07]  C11 needs an independent peer
  -> A4 13   the live run               [DONE]           0/10 attempts lost a packet
  -> 14a -> 14b -> 14c -> 14d -> 14e    [DONE]           1-RTT sending; C is all 1-RTT
  -> C0 -> {C1..C4} and {C5..C8} -> C9 -> C10 -> C11 -> C12   [ALL DONE, through ac43deb]
  -> C13    the endpoint ANSWERS        [ANSWERED already, eb7d668]  HTTP/200, protocol: http3
            C13 remains owed for the RETRY/FAILURE RATE and for recording perk into a capture
  -> C14 -> C15 -> C16   the endpoint's QPACK settings MATCH   22 tasks from here
  -> B      transport parameter wire order             the perk hash still differs without it
```

**Three statements, each with its own truth value:**

1. **The endpoint can be *asked* after 19 tasks.** That is the point at which `/api/http3` returns a
   body instead of its protocol-segregation refusal, which is itself the proof that h3 was genuinely
   negotiated. Nineteen is 5 plus 14, both list lengths in this document.
2. **Its QPACK half can be *satisfied* after 22**, if the capture's `1: 65536` is honoured. At 19 the
   answer arrives but `perk_hash` and `perk_hash_normalized` both differ, because settings 0x01 and
   0x07 are inside the hash and the minimal arm sets them to 0.
3. **The whole `perk` string cannot be matched by subsystem C at all.** Two of its four segments are
   transport-layer: parameter wire order, which task 11 already recorded as a MISMATCH, and the CID
   length pair. Those are subsystem B's. C can be complete and the hash still differ.

**The first thing to do is not a C task.** Run A4 task 13. It needs no new code, and it is the only
thing that turns the loss-rate unknown - the widest term in the estimate - into a number. If a
handshake cannot complete reliably against a live server today, a multi-packet HTTP/3 response
certainly cannot, and the chain above gains A3 before it gains anything else.

---

## Not in this phase

Each cut names where it lands, per A4's practice. Silently omitting any of these is the failure mode
this section exists to prevent.

| Cut | Lands in | What the cut costs |
| --- | --- | --- |
| Server push: PUSH_PROMISE, push streams, CANCEL_PUSH, MAX_PUSH_ID | **C-complete** | nothing for a GET. `MAX_PUSH_ID` is never sent, so RFC 9114 §7.2.7 means the server may not push at all. The frames must still be *recognised* - that is C2's |
| The CONNECT method, HTTP Upgrade | **never, or E** | not a fingerprinting path |
| Request cancellation and rejection (§4.1.1), `RESET_STREAM` and `STOP_SENDING` semantics | **C-complete** | a cancelled request leaks a stream until the connection closes |
| Trailing header sections | **C-complete** | recognised and skipped, not decoded |
| Priority (RFC 9218), `h3PriorityParam` | **B** | bogdanfinn exposes it; a client capture's `perk` does not carry it, so there is nothing to match against yet |
| More than one request per connection, connection reuse (§3.3) | **E** | the acceptance gate is one GET |
| Alt-Svc discovery (§3.1.1) and the h1-or-h2 upgrade path | **E** | the parent scoping notes the service advertises h3 via Alt-Svc, so reaching it may take a retry. C connects to a known h3 endpoint directly |
| A response body decompressor (gzip, br, zstd) | **E** | if we advertise `accept-encoding` we must decode. C's minimal request may omit it - **and omitting it is itself a fingerprint difference from Chromium**, so this is a cut with a cost, not a free one |
| 0-RTT and early data for h3 | **C-complete** | RFC 9204 §3.2.3 has 0-RTT-specific dynamic table rules this arm does not implement |
| QPACK encoder-side dynamic table use | **never, deliberately** | RFC 9204 §4.2's first MAY grants it; nothing in the `perk` string observes it |
| Sending QUIC DATAGRAM frames | **never** | RFC 9297 §2.1.1 forbids it until the setting is sent *and* received as 1; we only advertise |

---

## Standing rules carried in

The eighteen from `2026-08-17-quic-a2-frame-layer.md` and the additions from A4's amendments transfer
whole. The six that bite hardest here:

- **Point at the extract; never restate a field layout or a constant in a plan or a prompt.** A
  transcription error propagates into every field section and surfaces as a decompression failure,
  not a layout one. This document deliberately quotes no QPACK or HTTP/3 field diagram.
- **The extracts are hard-wrapped at ~72 columns.** Four misreads in this project came from a sentence
  truncated at the wrap, including the one that inverted §13.2.1's scope. Read past the wrap.
- **Never write a count you cannot recompute from a list.** Every figure here names the grep or the
  list that produces it: 99 static table entries, 257 Huffman rows, 20 QUIC frame types, 17 HTTP/3
  error codes, 19 / 22 / 23 tasks.
- **A constant nobody can check is not allowed.** Where the capture does not bound something -
  SETTINGS order, stream-open order, GREASE frame policy - the default is a declared placeholder and
  it goes in the readout's third column. Task 1 refused to invent a range for `initial_rtt`; that
  refusal was correct and it applies here.
- **A surviving mutation is unwitnessed, unreachable by construction, or vacuous - say which.** For a
  vacuous one write no test; it would pass against the mutant and become a false witness.
- **A mutation ledger is an itemised list whose entries are counted, and the header figure is derived
  from that count.** One row per mutation, contiguously numbered, `[RE-LISTED]` marked, every section
  stating "N rows", and the header showing its arithmetic.

And one this phase adds, from Findings 1 and 6:

- **When a plan says a later task "owns" something, go read what that task's text actually lists.**
  A4's source comments named five things task 14 owns; A4's task 14 text named one. The comment was
  right and the plan was wrong, which is one more instance of the pattern the handoff already
  records: *"Doc-versus-code mutations found a real defect in six consecutive tasks... and every time
  the doc lost."*
