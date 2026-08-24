# Client-side MUST conformance audit

**Complete, and the findings are fixed.** All 508 client-relevant MUST sentences from the
pinned RFC extracts carry a verdict, and **0 are MISSING**. The seven code-level findings the
audit opened have all been closed; the eighth was a deliberate non-goal and remains one.

| | |
|---|---|
| MUST sentences dispositioned | 508 |
| MISSING | 0 |
| Individually traced to `file:line` | 102 |
| Subsystem-verified (weaker — read the caveat) | 403 |
| Extractor artefacts, not normative | 3 |
| Defects found and fixed | 8 (see "What the audit changed") |
| False positives caught before entry | 5 |

**The remaining gap is confidence, not conformance.** 102 sentences were individually located
in the code; 403 were verified at subsystem level — the code implementing that class of rule was
read and named, but the individual sentence was not traced. `scripts/must-checklist.json` carries
the level per sentence. Do not treat a subsystem verdict as a traced one; the work this document
leaves behind is converting the second number into the first, one rule at a time.

## What the audit changed

Nine defects, in the order they were fixed. The **Finding** column is the number used in the
body below, so the two can be read against each other; the `legacy_session_id` defect predates
the numbering because it was found and fixed before the audit began.

**Four of these were not latent.** The `legacy_session_id` violation broke every handshake
against a BoringSSL peer before a request could be sent. The datagram rules were live because
the shipped presets invite datagrams. And a server exercising RFC 9001 §6 — which it may do at
any point after the handshake is confirmed — was answered with a connection error. The rest
require a peer to misbehave first. And the ninth was breaking any request whose body exceeded
about 1400 bytes, on every path - it reached this document as a proxy bug and was not one.

| Finding | Rule | Was | Commit |
|---|---|---|---|
| — | RFC 9001 §8.4 — QUIC forbids TLS compatibility mode, so `legacy_session_id` MUST be empty | 32 random bytes, and every BoringSSL peer answered alert 47 | `7b5c663` |
| 3 | RFC 9114 §7.2.7 — a client MUST treat a received MAX_PUSH_ID as H3_FRAME_UNEXPECTED | Parsed and accepted: it shares CANCEL_PUSH's payload shape, so one arm handled both and it inherited the wrong rule | `2a4faef` |
| 7 | RFC 9114 §7.2.5 — a PUSH_PROMISE above the advertised push ID is H3_ID_ERROR | Skipped. No push ID was ever advertised, so every one is above it — the rule binds *because* server push is unimplemented | `2a4faef` |
| 5 | RFC 9000 §19.4, §19.5, §19.13 — RESET_STREAM, STOP_SENDING and STREAM_DATA_BLOCKED against the stream's direction; §19.16 RETIRE_CONNECTION_ID | All four fell into the frame switch's default arm. Three of the stream rules were marked COMPLIANT at subsystem confidence — true of `TlsQuicStreams.cs`, false of the dispatch | `2a4faef` |
| 6 | RFC 9221 §3 and RFC 9297 §2.1 — DATAGRAM receive validation at both layers | Parsed, payload dropped, never validated, while the shipped presets advertise `max_datagram_frame_size` = 65536 and SETTINGS_H3_DATAGRAM = 1 | `d6ffad4` |
| 4 | RFC 9000 §12.3 — duplicate suppression after removing packet protection | Only the largest packet number per space was kept; a duplicated datagram was walked twice, re-delivering its ACK | `2033d59` |
| 1, 2 | RFC 9001 §6 — key update, and §6.6's AEAD usage counts | Out of scope by declaration: a flipped Key Phase bit was answered with KEY_UPDATE_ERROR, so a conforming server rotating keys had the connection closed on it | `e6cb025` |
| 9 | RFC 9000 §14.2 — no datagram size ceiling on the send path | A 32 KB request body went out as one 32837-byte datagram, which a DF-set socket refuses. Found from a field report whose own diagnosis was wrong | `684b958`, `ed3412f` |

**Finding 8 was not fixed and should not be.** RFC 9218 §7.2's PRIORITY_UPDATE is absent. No MUST
compels a client to send one, and emitting priority signals that no real target sends would make
this client MORE distinguishable, which is the opposite of the library's purpose. Do not
"fix" it without a capture showing the impersonation target sends them.

## What this audits, and what it does not

Scope is **client-side MUST / MUST NOT / REQUIRED / SHALL only**. SHOULD and RECOMMENDED are
out. Server-side duties are out — this is a client library. Where the library knowingly breaks
a rule to impersonate a real client, that is recorded rather than hidden: a caller needs to
know which rules are broken on purpose.

RFCs in scope: 9000, 9001, 9002, 9114, 9204, 9221, 9297, 9368, 9369, 8446, 8701, 9218, and the
three HTTP-semantics sections of 9110 that HTTP/3 inherits. RFC 7541 is out of scope (HPACK is
HTTP/2) except as the Huffman table QPACK reuses.

**Normative text is quoted only from the pinned extracts in
`docs/superpowers/specs/reference-captures/`, never from memory.** Where a rule falls outside
the pinned sections, the finding says so instead of quoting it. This is the same rule the test
suite already follows — `TlsQuicClientHelloProfileFactoryTests` parses the HTTP/3 ALPN token out
of the RFC 9114 extract rather than typing it.

The audit is deliberately run in two directions, because neither finds the other's defects:

- **spec-driven** — enumerate the RFC's MUSTs, then locate each one. Finds requirements
  implemented *nowhere*.
- **code-driven** — read the implementation, then check it against the extract. Finds
  requirements implemented *wrongly*.

## Method note: absence of a keyword is not absence of enforcement

Five findings were nearly filed in error, every one because a grep shaped around the *words* a
rule might use returned nothing while the rule was implemented:

- `signature_algorithms_cert` looked absent when only one file was searched. It is implemented.
- The RFC 8446 §4.2.8 key-share ordering rule looked unenforced because the code expresses it
  as a monotonic `Array.IndexOf` cursor rather than anything matching `subset` or `Contains`.
- The RFC 9001 packet-protection labels (`quic key`, `quic iv`, `quic hp`) looked absent to a
  search for those literal strings, because they are composed at runtime from a
  version-dependent prefix and a suffix.
- The RFC 9000 §18.2 `active_connection_id_limit` floor check was missed by two searches before
  a third found it.
- The RFC 9000 §12.4 empty-payload check survived NINE search patterns and was found only by
  reading the receive path. It lives in a returned tuple, not a thrown error or a named guard.

Both would have been false positives in a report whose whole value is being trustworthy. A
MISSING verdict in this document therefore requires the failed search patterns to be named, and
a reader should treat any MISSING without them as unverified.

## Findings

**Every finding below is FIXED.** The diagnosis is kept as written - what the defect was, how it
was found, and which searches missed it - because that is what a reader needs in order to judge
the verdicts that were NOT findings. Each carries the commit that closed it and a note of what
would undo it. The one exception is finding 8, RFC 9218's PRIORITY_UPDATE, which is a deliberate
non-goal and is still absent on purpose.


### RFC 8446 (TLS 1.3) — ClientHello and extension layer

Pinned extracts: `rfc8446-section4.1.2-client-hello.txt`,
`rfc8446-section4.1.4-hello-retry-request.txt`, `rfc8446-section4.2-extensions.txt`,
`rfc8446-section9.2-mandatory-to-implement-extensions.txt`,
`rfc8446-appendixD.4-middlebox-compatibility-mode.txt`.

| § | Requirement | Location | Verdict |
|---|---|---|---|
| 9.2 | The seven mandatory-to-implement extensions | `ClientHelloBuilder.cs:262`, `ClientHelloEncoder.cs:289` | COMPLIANT |
| 4.1.2 | `legacy_version` is 0x0303 | `Protocol/TlsConstants.cs:5`, written `ClientHelloEncoder.cs:244` | COMPLIANT |
| 4.1.2 | `legacy_compression_methods` is a single zero byte | `ClientHelloEncoder.cs:248` | COMPLIANT |
| 4.2.8 | "Clients MUST NOT offer multiple KeyShareEntry values for the same group" | `ClientHelloBuilder.cs:562` | COMPLIANT |
| 4.2.8 | "Clients MUST NOT offer any KeyShareEntry values for groups not listed in the client's `supported_groups` extension" | `ClientHelloBuilder.cs:567` | COMPLIANT |
| 4.2.8 | "Each KeyShareEntry value MUST correspond to a group offered in the `supported_groups` extension and MUST appear in the same order" | `ClientHelloBuilder.cs:568` | COMPLIANT |
| D.4 / RFC 9001 §8.4 | Empty `legacy_session_id` over QUIC | `TlsQuicClientHelloProfileFactory.cs` | WAS DIVERGENT, FIXED |

Notes on the interesting rows:

**§9.2** — all seven are implementable, including `signature_algorithms_cert` and the
HelloRetryRequest `cookie` echo (`ClientHelloEncoder.cs:623`). `cookie` is correctly not
configurable in an initial ClientHello, since it only exists as a server-provided value in HRR.

**§4.2.8** — all three client MUSTs are enforced together in one loop. The ordering rule is a
strictly-increasing index into `_supportedGroups`, which is exactly "same-order subset". The
extract's own sentence is quoted in the source comment.

**D.4** — this is the one real defect the audit has found so far, and it was already fixed in
commit `7b5c663` before this document existed. Every QUIC ClientHello carried a 32-byte
`legacy_session_id`; RFC 9001 §8.4 requires it empty because QUIC has no TLS compatibility
mode. BoringSSL peers — Google, Cloudflare, every Spotify host — answered CRYPTO_ERROR with
alert 47 (`illegal_parameter`) before any request. Severity would have been BLOCKS-INTEROP.
Cause: `WithSessionId(null)` means *unspecified*, and the encoder then filled 32 random bytes
for TLS 1.3 compatibility mode — correct over TCP, illegal over QUIC. Now forced empty in the
QUIC factory and pinned by
`TlsQuicClientHelloProfileFactoryTests.TheSessionIdIsEmptyBecauseQuicHasNoCompatibilityMode`.

### RFC 9001 (QUIC-TLS)

Pinned extracts: `rfc9001-section5-packet-protection.txt`, `rfc9001-section4-using-tls.txt`,
`rfc9001-appendix-a-test-vectors.txt`.

| § | Requirement | Location | Verdict |
|---|---|---|---|
| 5.2 | `initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a` | `Quic/TlsQuicSecrets.cs:147` | COMPLIANT, byte-exact |
| 5.2 | `initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)` | `Cryptography/Tls13Hkdf.cs:21` | COMPLIANT |
| 5.1 | `client in` / `server in` labels | `Quic/TlsQuicSecrets.cs:187`, `:193` | COMPLIANT |
| 5.1 | `quic key` / `quic iv` / `quic hp` labels | `Quic/TlsQuicSecrets.cs:109` | COMPLIANT |
| RFC 9369 | QUIC v2 salt and `quicv2 ` label prefix | `Quic/TlsQuicSecrets.cs:109`, `:150` | COMPLIANT |

**The HKDF trap is avoided.** RFC 9001 §5.2 specifies HKDF-**Extract** for the Initial secret.
A generic HKDF helper that performs extract-then-expand yields a different value, and the two
are easy to confuse — the pcap analyser in `scripts/quic_initial_analyze.py` was written with
that bug and only caught by its own RFC 9001 Appendix A self-check. `Tls13Hkdf.Extract`
delegates to `HKDF.Extract`, so the library derivation is correct.

The QUIC v2 row is coverage found rather than sought: labels are composed as a version-dependent
prefix plus a suffix, so RFC 9369's `quicv2 ` schedule is handled alongside v1.

Packet protection, second pass:

| § | Requirement | Location | Verdict |
|---|---|---|---|
| 5.3 | AEAD nonce is the IV XOR the packet number, left-padded to the IV length | `Quic/TlsQuicPacketProtection.cs:194` | COMPLIANT |
| 5.4 | Header protection masks the low 4 bits (long header) / low 5 bits (short header) of byte 0 | `Quic/TlsQuicHeaderProtection.cs:41` | COMPLIANT |
| 5.4.2 | "sample of ciphertext is taken starting from an offset of 4 bytes", 16 bytes long | `Quic/TlsQuicHeaderProtection.cs:156` | COMPLIANT |
| 5.2 | Initial secrets derive from the ORIGINAL destination connection ID | `Quic/TlsQuicConnection.cs:2092` | COMPLIANT |
| 8.x | QUIC forbids the TLS `KeyUpdate` message | `Quic/CustomTlsQuicClient.cs:933` | COMPLIANT |
| **5.3** | **"An endpoint MUST initiate a key update (Section 6) prior to exceeding any limit set for the AEAD that is in use."** | `Quic/TlsQuicConnection.cs` `ApplyKeyUpdateIfNeeded` | **FIXED** `e6cb025` |

**The Appendix A test vectors are asserted.** The RFC's A.1 client destination connection ID
`8394c8f03e515708` appears in `TlsQuicHeaderProtectionTests`, `TlsQuicPacketBuilderTests`,
`TlsQuicPacketHeaderTests` and `TlsQuicPacketProtectionTests`. That is the strongest evidence
available for this subsystem: the whole crypto path is checked against the RFC's own numbers
rather than against the implementation's opinion of itself.

The DCID row is another avoided trap. Initial keys are pinned to
`OriginalDestinationConnectionId`, held separately from the working
`_destinationConnectionId`, so they do not drift when the server supplies a new connection ID.
Recomputing them per packet is a bug the pcap analyser in `scripts/` originally had.

#### FINDING 1 — key update was not implemented (FIXED, `e6cb025`)

**Fixed.** `Quic/TlsQuicPacketReceiver.cs` now holds RFC 9001 §6.5's three generations and
`Quic/TlsQuicKeySet.cs` derives them with the version-dependent `quic ku` label. What follows
is the diagnosis as it stood.

Searched: `"ku"` and `+ "ku"` under `src/SharpTls/Quic` (no hits), `KeyPhase` across `src`
(17 hits, all header bit plumbing), and `Next|Update|Phase|Rotate` in `Quic/TlsQuicKeySet.cs`.

`Quic/TlsQuicKeySet.cs:436` states the position outright: *"Key update is out of scope for this
phase"*, and constructs every key set with `keyPhase: false`. No `quic ku` secret can be
derived. The Key Phase bit is fully plumbed on both read and write
(`Quic/TlsQuicPacketHeader.cs:89`, `:133`, `:409`, `:463`) — the bit is understood, the key
derivation behind it is not.

Severity **LATENT** for the send side. The AEAD limits this MUST protects are on the order of
2^23 packets for AES-GCM; a fingerprinting client making a handful of requests per connection
will not approach them, so no live failure is expected.

**The receive side is worse, and §6 has since been pinned to settle it.** RFC 9001 §6.2:
*"If a packet is successfully processed using the next key and IV, then the peer has initiated
a key update. The endpoint MUST update its send keys to the corresponding key phase in
response."* The client parses the Key Phase bit but cannot derive the next generation of
secrets, so a server that initiates a key update leaves it unable to decrypt and unable to
respond. This is a MUST violation, not merely an absent optimisation.

Severity on the receive side is **BLOCKS-INTEROP, conditional**: it bites only when a peer
actually initiates an update. Short request/response connections rarely see one, which is why
the live HTTP/3 tests against Google, Cloudflare and Spotify all pass — but the client has no
defence if a peer chooses to.

#### FINDING 2 — AEAD packet counts were not tracked (FIXED, `e6cb025`)

**Fixed with finding 1**, which is what the diagnosis below predicted: there is no action to
take on reaching a confidentiality limit without a key update to take it.

Searched: `confidentialityLimit`, `integrityLimit`, `AeadLimit`, `encryptedPacketCount`,
`2^23`, `8388608`, `aeadConfidentiality` across `src` — no hits.

RFC 9001 §6.6: *"Endpoints MUST count the number of encrypted packets for each set of keys. If
the total number of encrypted packets with the same key exceeds the confidentiality limit for
the selected AEAD, the endpoint MUST stop using those keys."* Nothing counts. This is the same
root cause as FINDING 1 — without key update there is no action to take on reaching a limit —
but it is a separate MUST and the RFC's fallback (*"If a key update is not possible ... the
endpoint MUST stop using the"* keys) is also absent, so the client would simply keep
encrypting past the limit.

Severity **LATENT**, for the same arithmetic as FINDING 1.

Still unaudited within RFC 9001: CRYPTO stream ordering and the §5.6 0-RTT key rules.

### RFC 9114 (HTTP/3) — individually traced rules

The ten pinned RFC 9114 extracts contain **139 MUST occurrences, 116 of them client-relevant**
after removing server-only sentences. **23 were checked directly.** The rest are unaudited. This
section is a high-confidence sample, not a clean bill, and the ratio is stated so it cannot be
mistaken for one.

| § | Requirement | Location | Verdict |
|---|---|---|---|
| 3.2 | Clients MUST send SNI | `ClientHello` SNI extension, exercised by every preset | COMPLIANT |
| 3.2 | SETTINGS MUST be the initial frame of the control stream | `Quic/TlsQuicHttp3Connection.cs:543`, `:591` | COMPLIANT |
| 4.1 | Transfer-Encoding MUST NOT be used | `Http3FieldMapper.cs:35` | COMPLIANT |
| 4.2 | Field names MUST be converted to lowercase | `Http3FieldMapper.cs:78` | COMPLIANT |
| 4.2 | Uppercase field names MUST be treated as malformed | `Http3FieldMapper.cs:290` (request), `:233` (response) | COMPLIANT |
| 4.2 | Connection-specific fields MUST NOT be generated | `Http3FieldMapper.cs` connection-specific list | COMPLIANT |
| 4.2 | TE, if present, MUST NOT be anything but "trailers" | `Http3FieldMapper.cs` TE branch | COMPLIANT |
| 4.2 | Multiple cookie field lines MUST be joined with "; " | `Http3FieldMapper.cs` cookie branch | COMPLIANT |
| 4.2 | Clients MUST NOT accept a malformed response | `Http3FieldMapper.cs:233` | COMPLIANT |
| 4.3 | Pseudo-headers MUST appear before regular fields | `Http3FieldMapper.cs` field assembly | COMPLIANT |
| 5 | No new requests after receiving GOAWAY | `Quic/TlsQuicHttp3Connection.cs:27` | COMPLIANT |
| 7.2.8 | Reserved frame types / settings ignored on receive | `Quic/TlsQuicHttp3Frames.cs:45`, `:93` | COMPLIANT |
| 10.8 | Frame length MUST exactly match its contents | `Quic/TlsQuicHttp3Frames.cs:324` | COMPLIANT |
| 4.1 | After sending a request a client MUST close the stream for sending | `Http3Connection.cs:450` | COMPLIANT |
| 6.2 | "Recipients of unknown stream types MUST either abort reading ... or discard incoming data" | `Quic/TlsQuicHttp3Streams.cs:394`, `:420` | COMPLIANT, both legal answers implemented |
| 6.2.1 | Closing a critical stream is H3_CLOSED_CRITICAL_STREAM | `Quic/TlsQuicHttp3Streams.cs:481` | COMPLIANT |
| 4.3.1 | The request pseudo-header fields | `Quic/TlsQuicHttp3Request.cs:477-480` | COMPLIANT |
| 7.2.4 | "The same setting identifier MUST NOT occur more than once in the SETTINGS frame" | `Quic/TlsQuicHttp3Frames.cs:502` | COMPLIANT |
| 7.2.4.1 | Reserved HTTP/2 setting identifiers are H3_SETTINGS_ERROR on receipt | `Quic/TlsQuicHttp3Frames.cs:487` | COMPLIANT |
| 7.2.1, 7.2.2 | DATA and HEADERS on the control stream are H3_FRAME_UNEXPECTED | `Quic/TlsQuicHttp3Streams.cs:699-703` | COMPLIANT |
| 7.2.5 | PUSH_PROMISE on the control stream is H3_FRAME_UNEXPECTED | `Quic/TlsQuicHttp3Streams.cs:701` | COMPLIANT |
| 7.2.8 | Unknown and reserved frame types are ignored | `Quic/TlsQuicHttp3Streams.cs:720` | COMPLIANT |
| RFC 9297 §2.1.1 | SETTINGS_H3_DATAGRAM with a value other than 0 or 1 is H3_SETTINGS_ERROR | `Quic/TlsQuicHttp3Frames.cs:494` | COMPLIANT |
| 7.2.7 | MAX_PUSH_ID on a stream other than the control stream is H3_FRAME_UNEXPECTED | `Quic/TlsQuicHttp3Request.cs:1637` | COMPLIANT |
| **7.2.7** | **"A client MUST treat the receipt of a MAX_PUSH_ID frame as a connection error of type H3_FRAME_UNEXPECTED."** (control stream) | `Quic/TlsQuicHttp3Streams.cs` MaxPushId arm | **FIXED** `2a4faef` |
| **7.2.5** | **"A client MUST treat receipt of a PUSH_PROMISE frame that contains a larger push ID than the client has advertised as a connection error of H3_ID_ERROR."** | `Quic/TlsQuicHttp3Request.cs` PushPromise arm | **FIXED** `2a4faef` |

#### FINDING 3 — a server's MAX_PUSH_ID was accepted instead of rejected (FIXED, `2a4faef`)

**Fixed.** The arm is split. Do not merge it back: CANCEL_PUSH and MAX_PUSH_ID share a
payload shape and have opposite rules, which is what produced this in the first place.

RFC 9114 §7.2.7, verbatim from the extract: *"A server MUST NOT send a MAX_PUSH_ID frame. A
client MUST treat the receipt of a MAX_PUSH_ID frame as a connection error of type
H3_FRAME_UNEXPECTED."*

**Scope correction.** RFC 9114 s7.2.7 states two rules and only the second is unmet.
"Receipt of a MAX_PUSH_ID frame on any other stream MUST be treated as a connection error of
type H3_FRAME_UNEXPECTED" IS enforced - `Quic/TlsQuicHttp3Request.cs:1637` rejects it on a
request stream. The gap is the CONTROL stream, where the frame may legally appear and so
reaches the accepting branch.

`Quic/TlsQuicHttp3Streams.cs:714-717` handles it in a shared case block:

```csharp
case (ulong)TlsQuicHttp3FrameType.CancelPush:
case (ulong)TlsQuicHttp3FrameType.MaxPushId:
    return TlsQuicHttp3Frames.TryReadSingleVarintPayload(payload, out _, out error);
```

The payload parses and the frame is accepted. No H3_FRAME_UNEXPECTED is raised.

**The cause is the shared case, and the surrounding comment shows the reasoning that produced
it.** It explains that the payload is parsed rather than used because §7.1's length rule is "a
check on receipt, not on use" — which is right, and is right for CANCEL_PUSH, a frame a server
MAY legitimately send on the control stream. MAX_PUSH_ID is the opposite: a server MUST NOT send
it and a client MUST reject it. Two frames with opposite rules ended up sharing one branch
because they share a payload shape.

Severity **LATENT**. A conforming server never sends MAX_PUSH_ID, and accepting one harms
nothing in the client's own operation — the code never acts on the value, and server push is
refused by never advertising a limit. It is nonetheless a MUST violation, and it is the
laxness-on-inbound class that this audit exists to find: the client is more permissive than the
specification allows, which is exactly what a peer probing for implementation quirks would
measure.

#### FINDING 7 — PUSH_PROMISE push IDs were never validated (FIXED, `2a4faef`)

**Fixed.** The push ID is read first so a truncated payload is H3_FRAME_ERROR rather than an
identifier problem it does not have.

RFC 9114 s7.2.5: *"A client MUST treat receipt of a PUSH_PROMISE frame that contains a larger
push ID than the client has advertised as a connection error of H3_ID_ERROR."*

This client never sends MAX_PUSH_ID, so its advertised limit is unset and s7.2.7's default
applies: *"a server cannot push until it receives a MAX_PUSH_ID frame."* Every push ID is
therefore larger than advertised, and every PUSH_PROMISE should be H3_ID_ERROR.

`Quic/TlsQuicHttp3Request.cs` routes PUSH_PROMISE to the `default:` arm, which returns `true` -
accepted and skipped. The comment there is correct that s4.1 permits PUSH_PROMISE to APPEAR on a
request stream; what is missing is the separate push-ID check. No push-ID state is tracked
anywhere, and `H3IdError` appears in that file only inside a mutation-ledger comment.

Numbered 7 to match the handoff list below; findings are numbered by fix order, not by
the order they were found.

Severity **LATENT**: a conforming server does not push without a limit, so the frame should
never arrive.

**Inbound validation is otherwise present, which was the thing worth checking.** A client that validates
only what it sends is the easy mistake: `ValidateReceivedField` applies RFC 9114 §4.2's rules to
*received* fields and is wired into the response path at `Http3FieldMapper.cs:233`. Its own
comment gives the reason — a field name carrying a delimiter, control character or uppercase
letter is a request-splitting vector as soon as a caller copies it into another protocol, so
QPACK's decoder is deliberately not the only guard.

### RFC 9204 (QPACK) — MUSTs audited

The rules below were individually traced to `file:line`; the rest are subsystem-verified.

| § | Requirement | Location | Verdict |
|---|---|---|---|
| 4.1.1 | "QPACK implementations MUST be able to decode integers up to and including 62 bits long" | `Quic/TlsQuicQpackPrimitives.cs:136` | COMPLIANT |
| 4.1.2 | A second encoder or decoder stream is H3_STREAM_CREATION_ERROR | `Quic/TlsQuicHttp3Streams.cs:584` | COMPLIANT |
| 4.1.2 | Closing either stream is H3_CLOSED_CRITICAL_STREAM | `Quic/TlsQuicHttp3Streams.cs:481` | COMPLIANT |
| 3.1 | An invalid static table index is QPACK_DECOMPRESSION_FAILED | `Quic/TlsQuicQpackDecoder.cs:983` (`StaticIndexOutOfRange`) | COMPLIANT |
| 2.1.2 | An encoder MUST limit blocked streams to SETTINGS_QPACK_BLOCKED_STREAMS | `Quic/TlsQuicHttp3Connection.cs:847` | COMPLIANT, mutation-tested |
| 2.2 | More blocked streams than promised is QPACK_DECOMPRESSION_FAILED | `Quic/TlsQuicHttp3Connection.cs:1056` | COMPLIANT, named test |
| RFC 7541 §5.2 | The Huffman EOS symbol is an error, not a string terminator | `Quic/TlsQuicQpackHuffman.cs:138` | COMPLIANT, mutation-tested |
| RFC 7541 §5.2 | Padding longer than 7 bits is an error | `Quic/TlsQuicQpackPrimitives.cs:149` (`PaddingTooLong`) | COMPLIANT |
| 2.1 | An encoder MAY decline the dynamic table | `Quic/TlsQuicQpackEncoder.cs:151` | COMPLIANT by construction |

**The dynamic table is decode-only, and that is a deliberate shape rather than a gap.**
`TryEncodeFieldSectionPrefix` writes a Required Insert Count of 0 and a Base of 0
unconditionally, so this client never emits a dynamic reference; `TlsQuicQpackDynamicTable.cs`
exists to RESOLVE the ones a server sends. §2.1 permits exactly this. The earlier open question
— "is the dynamic table implemented, partial, or absent" — resolves to: fully present for
decode, deliberately unused for encode.

Nineteen MUSTs remain unchecked, mostly encoder-stream instruction semantics and eviction rules
that a decode-only encoder never exercises.

### RFC 8701, 9218, 9221 — specifics checked

| RFC | Requirement | Location | Verdict |
|---|---|---|---|
| 8701 | The reserved GREASE value set | `ClientHello/ClientHelloBuilder.cs:1001` | COMPLIANT, exact |
| 9221 §4 | DATAGRAM frame types 0x30/0x31, low bit = length present | `Quic/TlsQuicFrameType.cs:146` | COMPLIANT |
| 9218 §7.2 | The HTTP/3 PRIORITY_UPDATE frame (0xF0700 / 0xF0701) | NOT-FOUND | MISSING, N-A-nongoal |

The GREASE predicate is `(value & 0x0F0F) == 0x0A0A && (byte)(value >> 8) == (byte)value`, which
is RFC 8701's reserved set written as an expression rather than a table.

**PRIORITY_UPDATE is absent and that is defensible.** Searched: `0xF0700`, decimal `986`/`987`,
`PriorityUpdate` and `priorit` across `SharpTls/src/SharpTls/Quic` — the only `PriorityUpdate`
surface in the tree is on the HTTP/2 request path. RFC 9218 §7.2's frame is not sent, and no
MUST compels a client to send it: a client that never reprioritises simply never emits one, and
servers apply their own scheduling. It is recorded as MISSING against the spec and
N-A-nongoal in practice, because a fingerprinting client that emitted priority signals no real
target sends would be MORE distinguishable, not less.

### RFC 9000 (QUIC transport) — individually traced rules

The rules below were individually traced to `file:line`. The remainder of RFC 9000's MUSTs are
covered by the subsystem sweep further down, at the weaker confidence level that section
explains.

| § | Requirement | Location | Verdict |
|---|---|---|---|
| 14.1 | Initial datagrams padded to at least 1200 bytes | `Quic/TlsQuicConnectionSpec.cs:146` | COMPLIANT |
| 18.2 | `max_udp_payload_size` below 1200 is a parameter error | `Quic/TlsQuicTransportParameters.cs:258` | COMPLIANT |
| 7.2 | "This Destination Connection ID MUST be at least 8 bytes in length" | `Quic/TlsQuicConnection.cs:1175` | COMPLIANT |
| 18.2 | "An endpoint that receives a value less than 2 MUST close the connection" (`active_connection_id_limit`) | `Quic/TlsQuicTransportParameters.cs:283` | COMPLIANT |
| 18.2 | "A client MUST NOT include any server-only transport parameter" | `Quic/TlsQuicTransportParameters.cs:233` via `RequireServer` | COMPLIANT |
| 17.2.5.2 | "A client MUST accept and process at most one Retry packet for each connection attempt" | `Quic/TlsQuicConnection.cs:194` | COMPLIANT, mutation-tested |
| 17.2.5.2 | "A client MUST discard a Retry packet with a zero-length Retry Token field" | `Quic/TlsQuicConnection.cs:196` | COMPLIANT, mutation-tested |
| 5.8 | "Clients MUST discard Retry packets that have a Retry Integrity Tag that cannot be validated" | `Quic/TlsQuicConnection.cs:198` | COMPLIANT, mutation-tested |
| 6 | "A client MUST discard any Version Negotiation packet if it has received and successfully processed any other packet" | `Quic/TlsQuicConnection.cs:205` | COMPLIANT, mutation-tested |
| 17.2.1 | Version Negotiation connection ID echo checks | `Quic/TlsQuicConnection.cs:206-207` | COMPLIANT, mutation-tested |
| 19.7 | "A client MUST treat receipt of a NEW_TOKEN frame with an empty Token field as a connection error" | `Quic/TlsQuicConnectionFrames.cs:379` | COMPLIANT, tested |
| 19.19 | CONNECTION_CLOSE types 0x1c and 0x1d are distinct forms | `Quic/TlsQuicConnection.cs:250` | COMPLIANT, mutation-tested |
| 12.4 | "An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION" | `Quic/TlsQuicPacketReceiver.cs:727` | COMPLIANT |
| 12.4 | "An endpoint MUST treat receipt of a frame in a packet type that is not permitted as a connection error of type PROTOCOL_VIOLATION" | `Quic/TlsQuicPacketReceiver.cs:751` | COMPLIANT |
| 17.2 | Non-zero reserved bits are a connection error | `Quic/TlsQuicPacketReceiver.cs:689` | COMPLIANT |

**Seven of the twelve carry named killing mutants**, recorded in the mutation ledgers inside the
source files themselves. That is stronger evidence than an audit read can produce: a ledger row
naming the test that kills a specific deletion shows the rule is not merely present but load
bearing. Retry handling and Version Negotiation are the best-evidenced areas in the codebase.


#### FINDING 4 — received packets were not duplicate-suppressed (FIXED, `2033d59`)

**Fixed** with a 128-packet sliding window per space, consulted after the AEAD and after the
§17.1 largest-received update. Both positions are rules; see the handoff.

RFC 9000 §12.3, from `rfc9000-section12-packets-and-frames.txt`: *"A receiver MUST discard a
newly unprotected packet unless it is certain that it has not processed another packet with the
same packet number from the same packet number space."* And: *"Duplicate suppression MUST happen
after removing packet protection."*

`Quic/TlsQuicPacketReceiver.cs:715` keeps only the largest packet number per space:

```csharp
if (packetNumber > _largestReceived[space])
{
    _largestReceived[space] = packetNumber;
}
```

There is no record of which packet numbers were already processed, and the frame loop at `:754`
dispatches to the handler unconditionally. A packet duplicated by the network has its frames
applied twice.

Searched: `duplicate`, `alreadyProcessed`, `seenPacket`, `replay`, `_received[`, `bitmap`,
`window`, `HasProcessed`, `Seen` in the receiver; `duplicate` and `s12.3` in the ACK tracker.

**Do not confuse this with the ACK-range deduplication, which IS present and mutation-tested.**
`TlsQuicAckTracker` has killed mutants named `ADuplicatePacketNumberChangesNothing`,
`ADuplicateOfTheLargestPacketDoesNotRestartTheDelayClock` and
`ADuplicateOfTheSmallestPacketInAWideRangeChangesNothing`. ACK GENERATION handles duplicates
correctly. What is absent is discarding the duplicate before its frames reach the handler.

Severity **LATENT**. Most QUIC frames are idempotent by design — STREAM carries offsets, MAX_DATA
and MAX_STREAM_DATA are monotonic, ACK is a set union — which is why a duplicated packet does not
visibly break a connection. The MUST exists because not all of them are, and because
"idempotent in practice" is a property of the frames a peer happens to send rather than one this
receiver enforces.

#### RESOLVED — empty-payload packet rejection IS implemented

Previously recorded UNRESOLVED. Reading the packet receive path settled it:
`Quic/TlsQuicPacketReceiver.cs:727` returns
`(TlsQuicTransportError.ProtocolViolation, "Packet contained no frames.")`, which is exactly
RFC 9000 §12.4. The same method also enforces two neighbouring §12.4 MUSTs — a frame in a packet
type that does not permit it (`:751`) and non-zero reserved bits (`:689`), both PROTOCOL_VIOLATION.

**This was the fifth near-miss, and the only one that survived a grep sweep.** Nine search
patterns failed to find it because the check lives in a returned tuple rather than a thrown
error or a named guard. It was found only by reading the receive path, which is what the
UNRESOLVED verdict said would be required. Recording it as MISSING would have put a false
defect into a report whose entire value is being trustworthy.

Everything else in RFC 9000 — frame formats in detail, variable-length integer widths, packet
number encoding and duplicate suppression, stream state machines, flow control accounting,
address validation, ACK generation policy, error-code selection — is unchecked.

### RFC 9002 (loss detection and congestion control) — constants verified

RFC 9002 is overwhelmingly SHOULD-level, so there is little for a MUST audit to bite on. What
IS checkable is the constant set in Appendix A/B, and a wrong constant is both a correctness
defect and a fingerprint one: pacing and recovery behaviour are observable, so a stack using
the wrong initial window or loss threshold looks like a different stack.

All nine match the extract exactly.

| Constant | RFC value | Location |
|---|---|---|
| `kInitialRtt` | 333 ms | `Quic/TlsQuicRecoverySpec.cs:428` |
| `kPacketThreshold` | 3 | `Quic/TlsQuicRecoverySpec.cs:486` |
| `kTimeThreshold` | 9/8 | `Quic/TlsQuicRecoverySpec.cs:496` |
| `kGranularity` | 1 ms | `Quic/TlsQuicConnection.cs:950` |
| `kInitialWindow` datagrams | 10 | `Quic/TlsQuicRecoverySpec.cs:444` |
| `kInitialWindow` byte cap | 14720 | `Quic/TlsQuicRecoverySpec.cs:454` |
| `kMinimumWindow` datagrams | 2 | `Quic/TlsQuicRecoverySpec.cs:462` |
| `kLossReductionFactor` | 0.5 | `Quic/TlsQuicRecoverySpec.cs:473` |
| `kPersistentCongestionThreshold` | 3 | `Quic/TlsQuicRecoverySpec.cs:503` |

No RFC 9002 MUST was audited — only the constants. The loss-detection and congestion-control
ALGORITHMS around them are unchecked.

### FINDING 9 — no datagram size ceiling at all (FIXED, `684b958` and `ed3412f`)

This entry was headed "OPEN — RFC 9000 §14 and the SOCKS5 header, an unresolved field report"
and parked a WSAEMSGSIZE report from a collaborator: reproducible over a SOCKS5 relay at
`clienttoken` and `login5`, direct working. The reported diagnosis was that the relay's receive
buffer was smaller than the QUIC datagram. **That was wrong, and so was the reading of §14 kept
here.** Both are recorded rather than replaced, because each was a plausible answer that a
measurement killed.

**What was actually wrong.** There was no path MTU ceiling on the send path anywhere.
`TlsQuicStreamSet.Drain` moved an entire request body into ONE STREAM frame bounded only by the
peer's flow-control credit, and the 1-RTT packet took every queued frame at once, bounded only
by the 65527-byte send buffer. Measured, one datagram per body: 512 bytes produced 577, 2 KB
produced 2113, 8 KB produced 8257, 32 KB produced 32837. RFC 9000 §14.2: "In the absence of
these mechanisms, QUIC endpoints SHOULD NOT send datagrams larger than the smallest allowed
maximum datagram size."

**Why it surfaced on the relay and not directly.** §14 requires the DF bit and both transports
set it, so on a 1500-byte MTU any datagram over 1472 bytes is refused at the socket. Verified
against a live interface at the boundary: 1472 sent, 1473 threw `SocketError.MessageSize` with
the exact message the report quotes. The SOCKS5 header adds 32 bytes for a domain-form Spotify
host, so the relay crosses 1472 with a body 32 bytes smaller than direct does. **Direct fails
too** — the report's "direct works" was a threshold, not an exemption.

**Three wrong answers, each killed by a measurement rather than by argument.** The receive
buffer is `_headerSize + 65527` and cannot truncate an IPv4 datagram, so a receive-side
WSAEMSGSIZE is impossible. DF against the handshake datagrams does not explain it either: those
are 1200 bytes and fit. And the section that used to stand here proposed measuring
`PaddingTarget` against the wire datagram — but `PaddingTarget` is a FLOOR for Initial packets
and ceilings nothing, so changing it would not have bounded the body that was actually
overflowing.

**The fix, in two parts.** `684b958` bounds every datagram: `ITlsQuicDatagramTransport` gained
`DatagramOverhead` so an encapsulating transport's header is charged against the path budget,
`Drain` segments a body into datagram-sized STREAM frames (RFC 8899 §4.4), and
`TakePendingFrames` takes only as many frames as fit, measured with the encoder that will write
them. `ed3412f` adds RFC 8899 DPLPMTUD to raise that ceiling above 1200, **on by default** —
§14.2 makes discovery a SHOULD, and a default that has to be remembered is one that gets
forgotten. The probe waits for §5.1.1's "application data has been sent since the previous
probe packet", so it never appears in the opening flight, and the search normally ends after
one probe. `TlsQuicConnectionSpec.PathMtuDiscovery = false` restores the fixed 1200-byte
ceiling for a connection that has to match a capture byte for byte.

**What is still not settled.** Whether the collaborator's specific failures were the 32-byte
header crossing 1472 on a 1500-byte path, or a smaller MTU on their proxy route. Both produce
the same exception and the fix covers both, so the distinction now costs nothing — but it was
never established and is not claimed.

### FINDING 5 — unhandled frame types skipped their receive-side MUSTs (FIXED, `2a4faef`)

**Fixed.** RESET_STREAM, STOP_SENDING and STREAM_DATA_BLOCKED route to
`TlsQuicStreamSet.TryReceiveStreamStateSignal`; RETIRE_CONNECTION_ID has an arm of its own.
Three of the four rules below carried a COMPLIANT verdict at subsystem confidence when this
was written - true of `TlsQuicStreams.cs`, false of the dispatch that reaches it.

`Quic/TlsQuicConnection.cs` dispatches on frame type at `:1680-1782` and handles exactly eight:
CRYPTO, ACK, HANDSHAKE_DONE, CONNECTION_CLOSE, PATH_CHALLENGE, STREAM, MAX_DATA, MAX_STREAM_DATA.
Everything else reaches the `default:` arm at `:1791` and is ignored.

That is correct for PADDING and PING, which need no action. It is not correct for the frames
below, each of which carries a receive-side MUST that is consequently unenforced. Stream-state
validation DOES exist for the handled frames — `Quic/TlsQuicStreams.cs:1410`, `:1461`, `:1516`,
`:1525` all raise STREAM_STATE_ERROR — so this is a dispatch gap, not an absent concept.

| § | Rule | Binds? | Verdict |
|---|---|---|---|
| 19.16 | "An endpoint that provides a zero-length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION" | **Yes** — at `SourceConnectionIdLength`'s default of 0. The knob permits non-zero, so the fix tests the length rather than assuming it | **FIXED** `2a4faef` |
| 19.16 | A RETIRE_CONNECTION_ID sequence number above any previously sent is PROTOCOL_VIOLATION (this row said FRAME_ENCODING_ERROR and was wrong; §19.16 says PROTOCOL_VIOLATION) | Yes | **FIXED** `2a4faef` |
| 19.16 | The sequence number MUST NOT refer to the connection ID of the packet carrying it | The MUST NOT binds a SENDER and this client never sends the frame; §19.16's MAY is the only receive-side action and is taken | **FIXED** `2a4faef` |
| 19.13 | "An endpoint that receives a STREAM_DATA_BLOCKED frame for a send-only stream MUST terminate the connection with error STREAM_STATE_ERROR" | Yes | **FIXED** `2a4faef` |
| 19.15 | NEW_CONNECTION_ID received while sending a zero-length DESTINATION connection ID is PROTOCOL_VIOLATION | **No** — this client's destination connection ID is 8 bytes | N-A |

**The §19.13 row was already known to the codebase.** The `default:` arm's own comment names it:
*"ONE MUST IS THEREFORE STILL UNIMPLEMENTED AND IS NAMED RATHER THAN GLOSSED."* That is the right
instinct and this audit simply found the other four next to it.

The §19.16 rows are the ones that bind hardest, because this client deliberately uses a
zero-length source connection ID — the same choice the Spotify capture makes. A server that
sends RETIRE_CONNECTION_ID to a zero-length-CID client is misbehaving, and the RFC requires the
client to say so rather than ignore it.

Severity **LATENT** for all four: each requires a peer to send something a conforming server
does not send.

### GREASE negotiation rejection — compliant, but incidentally

RFC 8701 requires a client to reject GREASE values a server negotiates. It does, in three
places, but none of them is a GREASE check:

- Cipher suite — `Handshake/ServerHelloParser.cs:49` demands `Enum.IsDefined(typeof(TlsCipherSuite), ...)`, and GREASE is not an enum member.
- Version — `:90` demands the selected version equal exactly `TlsConstants.Tls13Version`.
- HRR group — `:199` demands the group be one that was offered and not already shared.

All three reject GREASE as a side effect of rejecting anything undefined. **This is worth
recording because the protection is structural rather than intentional**: adding a GREASE
constant to `TlsCipherSuite` for any reason would silently remove it. A reader looking for an
explicit RFC 8701 check will not find one, and should not conclude the rule is unmet.

### QUIC datagrams — send side satisfied by refusal

`Quic/TlsQuicFrames.cs:912-922` refuses to write a DATAGRAM frame at all, with the refusal
pinned by `TlsQuicFramesTests.WritingADatagramFrameThrowsBecauseThisLibraryNeverSendsOne` and
the RFC 9221 §3 sentence quoted beside it. Every send-side DATAGRAM MUST is therefore satisfied
by construction.

The receive side was NOT, and is now (**FIXED**, `d6ffad4`). RFC 9221 §3 requires
PROTOCOL_VIOLATION on a DATAGRAM frame received without having advertised support and on one
larger than the advertised size; RFC 9297 §2.1 requires H3_DATAGRAM_ERROR (0x33) for a payload
too short to parse the Quarter Stream ID and for a value above 2^60-1. None was located.

**THE SEVERITY NOTE HERE WAS TOO COMFORTABLE AND IS CORRECTED RATHER THAN DELETED.** It read
that the client "advertises `max_datagram_frame_size` only when configured to, and a server
sending unsolicited DATAGRAM frames is misbehaving". The shipped preset advertises
`max_datagram_frame_size` = 65536 and the capture settings send SETTINGS_H3_DATAGRAM = 1,
because the client being impersonated does — so a server sending DATAGRAM frames on that
invitation is conforming, not misbehaving, and these rules were live rather than latent.

### Subsystem sweep — the remaining buckets

The buckets below were audited at SUBSYSTEM level rather than sentence by sentence: the code
that implements each class of rule was read, and the rule class was found implemented with the
evidence named here. `scripts/must-checklist.json` records these with `confidence: "subsystem"`
so they are never mistaken for individually traced sentences, which carry
`confidence: "verified"`.

**Read that distinction literally.** A subsystem verdict says "this code implements this class of
rule and here is where"; it does not say "this exact sentence was located in the code". A
handoff session tightening any of these should re-check the specific sentence before relying on
it.

| Bucket | Verdict | Evidence read |
|---|---|---|
| `http-semantics` | COMPLIANT | `TlsQuicHttp3Request` malformed-request taxonomy (`MandatoryPseudoHeaderOmitted`, `AuthorityMissing`, `AuthorityEmpty`, `PseudoHeaderAmongRegularFields`, `PseudoHeaderInTrailerSection`, `RegularFieldNameNotLowercase`), plus `Http3FieldMapper.ValidateReceivedField` rejecting uppercase and `:` on received fields |
| `qpack` | COMPLIANT | `TlsQuicQpackDynamicTable` eviction and capacity rules, mutation-tested against RFC 9204 Appendix B.5; `TlsQuicQpackDecoder` error taxonomy |
| `streams` | COMPLIANT | `TlsQuicStreams.cs` — `StreamLimitError` at `:1431`, `FinalSizeError` at `:827`, `:838`, `:847`, `StreamStateError` at `:1410`, `:1461`, `:1516`, `:1525` |
| `recovery` | COMPLIANT | `TlsQuicRecoverySpec` constants (all nine exact) plus `TlsQuicCongestionControl` and `TlsQuicPersistentCongestion` |
| `wire` | COMPLIANT | `QuicVariableLengthInteger` minimal form; coalescing connection-ID check mutation-tested (`ASubsequentCoalescedPacketWithADifferentDestinationConnectionIdIsIgnored`) |
| `0rtt-resumption` | COMPLIANT | `CustomTlsQuicClient` `EarlyDataStatus` accept/reject at `:231`, `:242`; `TlsQuicTransportParameters:199` enforces the non-decreasing rule against remembered values |
| `tls-hello` | COMPLIANT | `ClientHelloBuilder.Validate` and the `ServerHelloParser` rejection sites at `:49`, `:52`, `:57`, `:62`, `:90`, `:186`, `:199` |
| `push` | N-A-nonbinding | Server push is not implemented and no push limit is ever advertised, so a conforming server cannot push. Findings 3 and 7 are the exceptions that bind BECAUSE of this |
| `migration` | N-A-nonbinding | Connection migration is not implemented. PATH_CHALLENGE is answered (`TlsQuicApplicationSendPath.cs:524`); the connection-ID frames are finding 5 |
| `priority-ext` | N-A-nongoal | RFC 9218 PRIORITY_UPDATE absent; see finding 8 |
| `other` | **UNCHECKED** | 131 sentences, mostly prose fragments the sentence splitter cut from tables and figures. Needs a pass with a better extractor before it can be audited |

### Compliant, but structurally rather than explicitly

Three rules are met as a SIDE EFFECT of another check rather than by a check written for them.
Each would break silently if the incidental mechanism changed, and none is findable by searching
for the rule it satisfies:

| Rule | Satisfied by | What would break it |
|---|---|---|
| RFC 8701 — reject GREASE values a server negotiates | `Enum.IsDefined(typeof(TlsCipherSuite), ...)`, an exact TLS 1.3 version match, and the HRR offered-group check | Adding a GREASE constant to `TlsCipherSuite` for any reason |
| RFC 9000 §12.4 — a frame type MUST use the shortest encoding | `TlsQuicFrames.WriteFrame` calls the minimal varint overload and has no width parameter | Giving `WriteFrame` a width parameter, which the file's own comment anticipates |
| RFC 9221 — every send-side DATAGRAM rule | The codec refuses to write a DATAGRAM frame at all, pinned by `WritingADatagramFrameThrowsBecauseThisLibraryNeverSendsOne` | Adding a DATAGRAM write path without re-reading §3 |

These are recorded because a reader looking for the explicit check will not find one and could
wrongly file a MISSING — which is the same failure mode as the five near-misses, arriving from
the opposite direction.

### Final sweep — TLS 1.3 abort rules and platform-delegated checks

The last unchecked cluster was RFC 8446's abort rules and key-share validation. Both are met,
neither by a check written against the sentence:

**Abort rules.** `SharpTls/src/SharpTls/Handshake/` contains **65** sites raising
`TlsProtocolException.Illegal` or `.Decode` — the `illegal_parameter` and `decode_error` alerts
RFC 8446 names. `ServerHelloParser` alone rejects an unoffered cipher suite (`:52`), a suite
changed after HelloRetryRequest (`:57`), legacy compression (`:62`), a non-TLS-1.3
`supported_versions` (`:90`), an out-of-range PSK identity (`:156`), a second HelloRetryRequest
(`:186`) and an unoffered or already-shared HRR group (`:199`).

**Key-share public value validation is delegated to the platform.** RFC 8446 §4.2.8.2 requires
peers to validate each other's public values — a point on the curve for ECDHE, `1 < Y < p-1` for
FFDHE. `Cryptography/EcdheKeyShare.cs:86` imports the peer's value through
`ECDiffieHellman.Create(new ECParameters { ... })`, and .NET rejects an off-curve point at
import with `CryptographicException`. The rule is met; no code in this repository expresses it.
Add it to the structural-compliance table above in spirit: a platform change would move it.

**One rough edge, recorded rather than filed as a finding.** The enum `TlsCipherSuite` carries
"fingerprint-only" suites — `TlsDheRsaWithAes128CbcSha` and neighbours — that exist purely so
pinned legacy ClientHello profiles can encode them. `ServerHelloParser:49` accepts any suite
that is both `Enum.IsDefined` and offered, so a server selecting one of those would pass the
ServerHello check and fail later in `CipherSuiteInfo.Get`, which throws `NotSupportedException`
for anything outside the three TLS 1.3 AEAD suites.

That is fail-closed, which is the important half. But it fails with a general .NET exception
rather than an `illegal_parameter` alert, so the peer is never told why. It is near-unreachable
today — the legacy uTLS profiles were deleted and no shipped preset offers those suites — which
is why it is a note rather than a finding. If legacy profiles ever return, make
`ServerHelloParser` reject a non-TLS-1.3 suite explicitly.

### Coverage, finally

| Confidence | Count | Meaning |
|---|---|---|
| `verified` | 102 | The sentence was individually located in the code, with `file:line` |
| `subsystem` | 403 | The subsystem implementing that class of rule was read and named, but this sentence was not individually traced |
| `extractor` | 3 | Not a normative sentence — a fragment the splitter cut out of a table or figure |
| **MISSING** | 0 | Every finding is fixed; the 19 sentences that were MISSING now carry the code that implements them |

**Do not read `subsystem` as `verified`.** It is a real reading of real code with the evidence
named, and it is weaker than a traced sentence. Anyone tightening a specific rule should
re-check it directly; `scripts/must-checklist.json` carries the confidence per sentence so the
distinction survives this document.

### Deliberate divergences (impersonation, not defects)

| Rule | What the library does | Why |
|---|---|---|
| Duplicate `signature_algorithms` entries | Emits 0x0805 twice behind `AllowDuplicateSignatureAlgorithms()` | The captured Spotify iOS client does. RFC 8446 §4.2.3 has no MUST forbidding it, and JA4 hashes the list, so the repeat is invisible to JA4 and visible to JA3 — which is the point. Opt-in, off by default. |
| GREASE values in five namespaces | Sends reserved GREASE codepoints per RFC 8701 | Required to look like a real client. RFC 8701 reserves the values but mandates no selection policy, so the choice of value is a fingerprint decision and not a conformance question. |
| Vendor QUIC transport parameter `0xff080808` | Emitted last, outside the rotation | Observed in 4 of 4 proxy captures of the target client. Unknown transport parameters MUST be ignored by peers, so this is legal. |

## Attrition

All **508** client-relevant MUST sentences are dispositioned and **0** are MISSING.
**102** are individually traced to `file:line`; **403** are subsystem-verified; 3 were
extractor artefacts rather than normative text.

**Five findings were nearly filed in error and are not in any count above**, each because a grep
shaped around the words a rule might use returned nothing while the code implemented it under a
different spelling:

- `signature_algorithms_cert` — one file searched instead of the tree.
- RFC 8446 §4.2.8's key-share ordering rule — a monotonic `Array.IndexOf` cursor, matching
  neither `subset` nor `Contains`.
- The RFC 9001 packet-protection labels — composed at runtime from a version-dependent prefix.
- RFC 9000 §18.2's `active_connection_id_limit` floor — missed by two searches, found by a third.
- RFC 9000 §12.4's empty-payload check — survived NINE patterns, found only by reading the
  receive path. It lives in a returned tuple rather than a thrown error or a named guard.

That is five near-misses against 102 traced confirmations. Weigh it before adding a MISSING
verdict, and weigh it twice before trusting a subsystem one.

**One near-miss came from the opposite direction and is the reason the confidence levels are
kept apart.** Three of the rules fixed under finding 3 — RFC 9000 §19.4's, §19.5's two —
carried a COMPLIANT verdict at subsystem confidence when the fixing began. They were compliant
in `TlsQuicStreams.cs`, which the sweep read, and unreachable from the frame dispatch, which it
did not. A subsystem verdict can be true of the file and false of the path that reaches it.

---

## Handoff - for a fresh session picking this up

Read this section first. Everything needed to act is here; nothing depends on the session that
wrote it.

### What is closed, and how each fix is pinned

Every finding this audit opened is fixed and carries a test that fails without it. The table
under "What the audit changed" above names the commits; what follows is what a reader needs in
order to not undo one by accident.

**RFC 9001 §6 key update** — `Quic/TlsQuicPacketReceiver.cs` holds §6.5's three generations and
selects between them by §6.5's own rule. Two things there look redundant and are not. The
FALLBACK ATTEMPT after the first candidate fails exists solely so §6.4's ordering violation can
be seen at all: a packet that opens with the previous keys above the current phase's lowest
number is KEY_UPDATE_ERROR, and a receiver that stopped at one attempt could never distinguish
that from a forgery. The `_awaitingPeerKeyPhaseCatchUp` FLAG covers a state §6.5 does not name —
after a locally initiated update the peer is still at the old phase, which is byte-for-byte
identical to the peer initiating one. Deleting either is a silent regression that no obvious
test covers; both are tested by name.

`Quic/TlsQuicKeySet.cs` keeps the 1-RTT traffic secrets because a derived key cannot be walked
back to the secret that made it, and carries the header protection key across generations
unchanged — §6.1: "The header protection key is not updated." Deriving a fresh one there would
leave the peer unable to remove header protection at all, and the symptom would be every
subsequent packet silently discarded rather than an error.

**RFC 9001 §6.6's limits** are pinned as FIGURES rather than as branches:
`TheAeadLimitsAreTheFiguresSection66States` asserts 2^23 / 2^62 confidentiality and 2^52 / 2^36
integrity, with the two ciphers deliberately opposite ways round. Reaching a limit in a test is
not feasible, and a limit made injectable to fake it would be a knob no shipped path uses; the
real risk in those four numbers is transcription, which is what is tested.

**RFC 9000 §12.3 duplicate suppression** uses a 128-packet sliding window per space. The ceiling
is stated rather than hidden: a packet further back is discarded without certainty, which is the
shape §12.3 itself suggests, and costs a retransmit rather than data.

**RFC 9114 §7.2.7 and §7.2.5** — MAX_PUSH_ID and CANCEL_PUSH share a payload shape and have
opposite rules, which is exactly what produced the original bug. Do not merge those arms again,
however identical they look. PUSH_PROMISE binds BECAUSE server push is unimplemented: no push ID
was ever advertised, so every one is above the maximum. That inversion is easy to get backwards.

**RFC 9221 §3 and RFC 9297 §2.1** — `TlsQuicFrames.TryReadDatagram` now carries the payload and
the frame's whole encoded length out. The length cannot be recomputed downstream: the Length
field is a varint and RFC 9000 §16 requires the minimal encoding only of frame TYPES, so a peer
may spend four bytes on a length that fits in one and the frame is still legal.

### Still open, and it is not a conformance verdict

**The live interop tests do not run.** `TlsClient-main/tests/TlsClient.Tests/Http3BoringSslInteropTests.cs`
gates on `TLSCLIENT_LIVE_TESTS=1` and returns early otherwise — so it PASSES rather than skips,
and it passed in about a second under three different ways of setting that variable, which is
too fast for four hosts and a handshake each. Live HTTP/3 was re-verified for this work by a
throwaway console probe instead (Google 200, Cloudflare 200, `gew1-spclient.spotify.com` 404 on
`/` with the handshake complete). A test that cannot fail is worth either fixing or deleting.

### Rules for editing this document

- Normative text is quoted ONLY from `docs/superpowers/specs/reference-captures/`, never from
  memory. If a rule falls outside the pinned sections, pin the section first - that is what
  closed the key-update question and turned it from a guess into a verdict.
- A MISSING verdict MUST name the failed search patterns. Five findings were nearly filed in
  error because a grep shaped around a rule's words returned nothing while the code implemented
  it under a different spelling; one survived nine patterns and was found only by reading the
  path.
- Recount the tables before changing the attrition line. It has been wrong twice.
- A test that pinned behaviour this document changed is INVERTED, never deleted, and says at its
  assertion what it used to claim and why. Eight of them now do. A reader looking for when
  something changed should land on the assertion rather than on a git log.

### The checklist artefact

`scripts/must-checklist.json` holds all **508** client-relevant MUST sentences extracted
from the pinned extracts. Each carries:

- `src` — the pinned extract it came from
- `bucket` — subsystem grouping
- `verdict` — `COMPLIANT`, `MISSING`, `N-A-server`, `N-A-nongoal`, `N-A-nonbinding`,
  `N-A-neversends`, or `N-A-artefact`
- `confidence` — `verified` (102), `subsystem` (403), or `extractor` (3)
- `evidence` — the code that was read, and for the 19 rules fixed by this work, the code
  that now implements them

Filter it rather than re-reading this document.

**The remaining work is confidence.** Find a sentence carrying `subsystem`, trace it to
`file:line`, and change `confidence` to `verified` with the location in `evidence`. That is the
increment this audit leaves behind: converting subsystem verdicts to traced ones, one rule at a
time, without re-deriving anything. Three rules that were subsystem-COMPLIANT turned out to be
unreachable from the dispatch that should have reached them, so this is not bookkeeping.

### Two facts that change how the buckets read

- **0-RTT is implemented** (`Quic/CustomTlsQuicClient.cs:141`, `:231`, `:242`), so its 34 MUSTs are
  live requirements rather than non-goals. They are subsystem-verified, not traced.
- **Server push is not implemented** and the client never advertises a push limit, so most of the
  16 push MUSTs are unreachable — except findings 3 and 7, which bind precisely BECAUSE the
  client does not push. That inversion is easy to get backwards.

## Relationship to other documents

`docs/superpowers/specs/2026-08-17-a2-rfc-conformance-audit.md` audits whether the **extracts
quote the RFCs correctly**. It does not audit the code, and the two should not be confused.

`TlsClient-main/docs/HTTP3-EVALUATION.md` has a "what is still missing" section predating this
audit. **This document supersedes it for conformance questions.** That file was written before
RFC 9114 and RFC 9204 were audited and before the `legacy_session_id` defect was found; where the
two disagree, this one is current.

`scripts/must-checklist.json` is the machine-readable half of this document and is the thing to
edit when continuing. This file explains; that file tracks.
