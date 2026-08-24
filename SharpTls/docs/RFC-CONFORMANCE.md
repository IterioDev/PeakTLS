# Client-side MUST conformance audit

Status: **IN PROGRESS.** RFC 8446 (ClientHello and extension layer) and RFC 9001 §5-§6
(packet protection, key update) are done. Every other
RFC in scope is not yet audited and is listed as such below. Do not read this document as a
clean bill for anything it does not name.

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

Three findings were nearly filed in error across the first two passes, every one because a grep
shaped around the *words* a rule might use returned nothing while the rule was implemented:

- `signature_algorithms_cert` looked absent when only one file was searched. It is implemented.
- The RFC 8446 §4.2.8 key-share ordering rule looked unenforced because the code expresses it
  as a monotonic `Array.IndexOf` cursor rather than anything matching `subset` or `Contains`.
- The RFC 9001 packet-protection labels (`quic key`, `quic iv`, `quic hp`) looked absent to a
  search for those literal strings, because they are composed at runtime from a
  version-dependent prefix and a suffix.

Both would have been false positives in a report whose whole value is being trustworthy. A
MISSING verdict in this document therefore requires the failed search patterns to be named, and
a reader should treat any MISSING without them as unverified.

## Findings

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
| **5.3** | **"An endpoint MUST initiate a key update (Section 6) prior to exceeding any limit set for the AEAD that is in use."** | **NOT-FOUND** | **MISSING** |

**The Appendix A test vectors are asserted.** The RFC's A.1 client destination connection ID
`8394c8f03e515708` appears in `TlsQuicHeaderProtectionTests`, `TlsQuicPacketBuilderTests`,
`TlsQuicPacketHeaderTests` and `TlsQuicPacketProtectionTests`. That is the strongest evidence
available for this subsystem: the whole crypto path is checked against the RFC's own numbers
rather than against the implementation's opinion of itself.

The DCID row is another avoided trap. Initial keys are pinned to
`OriginalDestinationConnectionId`, held separately from the working
`_destinationConnectionId`, so they do not drift when the server supplies a new connection ID.
Recomputing them per packet is a bug the pcap analyser in `scripts/` originally had.

#### FINDING 1 — key update is not implemented (MISSING)

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

#### FINDING 2 — AEAD packet counts are not tracked (MISSING)

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

### Deliberate divergences (impersonation, not defects)

| Rule | What the library does | Why |
|---|---|---|
| Duplicate `signature_algorithms` entries | Emits 0x0805 twice behind `AllowDuplicateSignatureAlgorithms()` | The captured Spotify iOS client does. RFC 8446 §4.2.3 has no MUST forbidding it, and JA4 hashes the list, so the repeat is invisible to JA4 and visible to JA3 — which is the point. Opt-in, off by default. |
| GREASE values in five namespaces | Sends reserved GREASE codepoints per RFC 8701 | Required to look like a real client. RFC 8701 reserves the values but mandates no selection policy, so the choice of value is a fingerprint decision and not a conformance question. |
| Vendor QUIC transport parameter `0xff080808` | Emitted last, outside the rotation | Observed in 4 of 4 proxy captures of the target client. Unknown transport parameters MUST be ignored by peers, so this is legal. |

## Not yet audited

Nothing below has been examined. Each is a gap in this document, not a clean result.

- RFC 9000 — transport. Wire encoding (§12, §14, §16, §18, §19, packet formats) and lifecycle
  (§2.1, §4.5, §6, §7, §8, §10, §13, §13.3, §20).
- RFC 9001 — §5 and §6 are audited above. Still open: CRYPTO stream ordering and §5.6 0-RTT
  keys.
- RFC 9002 — loss detection and congestion control, and whether the Appendix A/B constants
  match exactly (a wrong constant is both a correctness and a fingerprint issue).
- RFC 9114 — HTTP/3 framing, stream mapping, SETTINGS, pseudo-headers, error handling.
- RFC 9204 — QPACK. Open question: is the dynamic table implemented, partial, or absent, and
  if absent does the client advertise a capacity consistent with that.
- RFC 8446 — everything outside the five pinned sections. The pinned set covers the ClientHello
  and extension layer only; the record layer, key schedule, and certificate handling are not
  pinned and so were not audited.
- RFC 8701, 9218, 9221, 9297, 9368, 9369 — GREASE value sets, priorities, QUIC and HTTP
  datagrams, version negotiation and QUIC v2.

## Attrition

Findings raised: 21. Confirmed: 17 compliant, 1 defect (already fixed), 2 MISSING (key update,
AEAD packet counting). The one question previously left UNVERIFIED was closed by pinning
RFC 9001 §6, which turned it from an open question into a confirmed MUST violation. Dropped as false
positives before entry: 3 — `signature_algorithms_cert`, the §4.2.8 ordering rule, and the QUIC
packet-protection labels, all three of which a keyword-shaped grep reported as absent while the
code implemented them. Three near-misses in two passes is why the method note above exists.

## Relationship to other documents

`docs/superpowers/specs/2026-08-17-a2-rfc-conformance-audit.md` audits whether the **extracts
quote the RFCs correctly**. It does not audit the code, and the two should not be confused.

`TlsClient-main/docs/HTTP3-EVALUATION.md` has a "what is still missing" section predating this
audit. Where the two disagree, neither is authoritative yet — this document has not reached
HTTP/3 .
