# Subsystem A scoping: the QUIC transport

Date: 2026-08-16
Status: scoping estimate, not a spec
Purpose: turn "is this worth doing" into a costed answer

This document sizes the QUIC transport before committing to it. It is deliberately not a
design. Every claim about what already exists was checked against the source tree, and
every claim about what is required was checked against RFC 9000, RFC 9001 or RFC 9002.

## The short answer

Subsystem A is roughly three to four times the size of subsystem D, which is 13 tasks. Call
it **35 to 45 tasks** at the same granularity, in four phases, of which the first two are
pure functions with published test vectors and no network.

It is large but not open-ended. Nothing in it requires invention: every algorithm is
specified in pseudocode in the RFCs, the hardest cryptographic component is already built
and shipped in this repository, and a reference implementation exists to check behaviour
against.

## What SharpTls already provides

Verified in `src/SharpTls/Quic/`. This is the part that does not need building.

| Component | Where | What it removes from subsystem A |
| --- | --- | --- |
| Full TLS 1.3 handshake as an encryption-level state machine | `CustomTlsQuicClient` (1159 lines) | the entire handshake, HRR, resumption, 0-RTT, ECH, client auth |
| Packet protection key derivation | `TlsQuicTrafficSecret.DerivePacketProtectionKeys(version)` | HKDF key/IV/hp-key derivation per level and direction |
| QUIC v1 and v2 Initial secrets from a destination connection ID | `TlsQuicInitialSecrets.Derive(...)` | the Initial key schedule, both versions |
| Variable-length integer codec | `QuicVariableLengthInteger` | the varint primitive every frame and header depends on |
| CRYPTO stream reassembly with overlap, gap and bound checks | `TlsQuicCryptoStreamReassembler` | out-of-order handshake reassembly |
| Transport parameter parse/encode with role rules | `TlsQuicTransportParameters` (369 lines) | RFC 9000 §18 in full |
| Encryption-level secret and key-discard events | `TlsQuicEvents` | knowing when to install and drop each key set |

That is the security-critical half. What remains is mechanical protocol work.

## What subsystem A must build

### Phase A1 — packet layer (no network, published test vectors)

1. Long header codec: Initial, 0-RTT, Handshake, Retry. Connection ID handling, token field, length field.
2. Short header codec, including the key phase bit.
3. Version Negotiation packet handling.
4. Packet number encoding and the truncated-to-full recovery algorithm (RFC 9000 §17.1, appendices A.2/A.3).
5. Header protection. RFC 9001 §5.4: sample 16 bytes at `pn_offset + 4`; AES-ECB mask for the AES suites, raw ChaCha20 over 5 zero bytes for AEAD_CHACHA20_POLY1305; protect the low 4 bits of byte 0 for long headers and low 5 for short headers. Keys come from `TlsQuicPacketProtectionKeys`, the algorithm does not.
6. AEAD packet protection. RFC 9001 §5.3: nonce is the packet protection IV XORed with the left-zero-padded 62-bit packet number; associated data is the header through the unprotected packet number.
7. Retry integrity tag. RFC 9001 §5.8: AEAD_AES_128_GCM under the fixed key `0xbe0c690b9f66575a1d766b54e368c84e` over a pseudo-packet that prepends the original destination connection ID.
8. Coalesced packet splitting inside one datagram.

**Gate:** RFC 9001 Appendix A ships worked test vectors for a real protected Initial packet.
That is ground truth, not self-consistency. Plus round-trip fuzz on every parser.

### Phase A2 — frame layer (no network)

9. Frame codec for all ~20 types: PADDING, PING, ACK and ACK-with-ECN, RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN, STREAM in its 8 flag variants, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, both CONNECTION_CLOSE forms, HANDSHAKE_DONE.
10. ACK range encoding and decoding.
11. ACK generation state: what to acknowledge, when, and the ack delay.
12. Frame-type-to-packet-type legality table (RFC 9000 §12.4).

**Gate:** a fuzz target per parser, full frame-type coverage, varint boundary cases.

### Phase A3 — recovery and congestion (no network, deterministic simulation)

13. RTT estimation: `latest_rtt`, `min_rtt`, `smoothed_rtt`, `rttvar` (RFC 9002 §5).
14. Loss detection: packet threshold `kPacketThreshold = 3`, time threshold `kTimeThreshold = 9/8`, `kGranularity = 1ms`, `kInitialRtt = 333ms` (§6.1).
15. Probe timeout with exponential backoff across packet number spaces (§6.2).
16. NewReno congestion control (§7, appendix B): initial window `10 * max_datagram_size`, minimum `2 * max_datagram_size`, `kLossReductionFactor = 0.5`, `kPersistentCongestionThreshold = 3`, three states — slow start, recovery, congestion avoidance.
17. Persistent congestion detection: `(smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay) * 3`.
18. Anti-amplification limit (RFC 9000 §8.1).

**Gate:** RFC 9002 gives all of this as pseudocode, so conformance tests can follow it line
by line. Loss, reordering and duplication are simulated by a test implementation of
`ITlsQuicDatagramTransport` — the interface subsystem D already shipped. No network needed.

### Deferred from A1 into A4

Found during phase A1 review, correct but not fixable at the time because the fix belongs to
a caller that does not yet exist:

- **Hoist the AES header protection instance out of the per-packet path.**
  `TlsQuicHeaderProtection.AesMask` calls `Aes.Create()`, builds a key schedule and heap-copies
  the key on every packet in both directions, for a key that RFC 9001 §5.4 keeps stable for an
  entire encryption epoch. The ChaCha20 path alongside it is stack-only with no per-call setup,
  and that asymmetry is what shows the cost is not inherent. The connection layer built in this
  phase is the natural owner of a keyed `Aes` per epoch; pass it in rather than raw key bytes.
- **Stop allocating the 5-byte mask per packet.** `TryComputeMask` returns `out byte[] mask`,
  allocating in both cipher paths. Take a caller-supplied `Span<byte>` instead. Same change,
  same caller.
- **Hoist the AEAD ciphers too.** `TlsQuicPacketProtection.Seal` and `TryOpen` construct
  `new AesGcm(key, TagLength)` or `new ChaCha20Poly1305(key)` on every packet in both
  directions, for the same epoch-stable key. This is the same defect as the header-protection
  `Aes.Create()` above and must be fixed in the same pass — otherwise A4 hoists one keyed
  cipher into the connection layer and leaves the other allocating per packet, which is the
  easy half to miss because the two live in different files.

### Phase A4 — connection (network, interop)

19. Connection state machine driving `CustomTlsQuicClient`'s event stream.
20. Key update (RFC 9001 §6), including the timing-side-channel requirements in §6.3.
21. Connection ID management: NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, active limits.
22. Connection-level and stream-level flow control.
23. Stream state machines: sending and receiving halves, bidirectional and unidirectional.
24. Connection close, draining period, idle timeout.
25. Path validation (§8.2), stateless reset detection, `preferred_address`.
26. Datagram assembly: what to pack, in what order, respecting congestion window and anti-amplification.

**Gate:** interoperability against at least two independent QUIC implementations under
loss, reordering and malformed input. This is the phase that cannot be faked offline.

## Why the estimate is credible rather than optimistic

- **Phases A1 through A3 need no network at all.** That is more than half the work, and all
  of it is testable with the same pure-function discipline that made subsystem D's codec
  cheap: 328 lines of code against 460 lines of test, one real bug found.
- **RFC 9002 is written as pseudocode.** Loss detection and congestion control are
  transcription plus tests, not design.
- **RFC 9001 Appendix A gives real packet vectors.** Phase A1 can be proven correct against
  bytes published by the IETF rather than against its own assumptions.
- **`ITlsQuicDatagramTransport` already exists.** The deterministic loss/reorder/duplicate
  harness that phase A3 needs is one implementation of an interface subsystem D shipped.
  That seam was chosen for exactly this reason.

### A known allocation ceiling, and the escape hatch

Subsystem D's transport allocates one `IPEndPoint` per received datagram, because
`ITlsQuicDatagramTransport.ReceiveAsync` returns the sender as an `IPEndPoint`. At QUIC
packet rates that is real garbage, and it was accepted deliberately rather than overlooked.

The escape hatch is confirmed to exist: .NET 9 ships
`Socket.ReceiveFromAsync(Memory<byte>, SocketFlags, SocketAddress, CancellationToken)`,
which reuses a caller-owned `SocketAddress` and allocates nothing per receive. Verified
against the installed SDK, not assumed.

Taking it is subsystem A's decision, not subsystem D's, because it changes what the receive
result can be: a reused `SocketAddress` cannot be handed back as a plain `IPEndPoint`
without either copying it or making the caller responsible for reading it before the next
receive. That is a real API consequence and should be decided when there is a packet loop
to measure, not before.
- **uQUIC and quic-go are a behavioural reference.** Not to copy, but to check against when
  the RFC is ambiguous.

## Scope reductions available, and what each costs

The estimate above is for a client that talks to real servers. It can be cut further:

| Cut | Saves | Costs |
| --- | --- | --- |
| Client only, no server | large | nothing; a server was never in scope |
| Single path, no active migration | 2-3 tasks | cannot survive a network change mid-connection; `preferred_address` still needs handling |
| No 0-RTT at first | 1-2 tasks | slower reconnects; the TLS side already supports it, so this is deferral not deletion |
| NewReno only, no CUBIC or BBR | 0 | none; RFC 9002 specifies NewReno and explicitly permits other controllers later |
| No ECN | 1 task | slightly worse congestion response; ECN is optional in RFC 9002 §7.1 |
| No QUIC v2 | 1 task | v2 exists mainly for greasing; `TlsQuicInitialSecrets` already derives both |

A deliberately minimal first milestone — client only, single path, no 0-RTT, no ECN, v1
only — lands closer to **25 tasks** and still produces a real HTTP/3-capable connection.

## Verification targets

Two independent services, queried together on every check. They are complementary rather
than redundant, and a disagreement between them is itself a finding: it means either our
implementation is doing something inconsistent, or one service's methodology differs from
the other's. Either way it is worth knowing, and neither service alone would surface it.

### `https://tls3.peet.ws/api/all`

One endpoint whose sections vary by the protocol used to reach it. The `tls3` host is the
HTTP/3 endpoint.

Confirmed present in the TLS block, checked directly rather than assumed:

- `tls.ja3` and `tls.ja3_hash`
- `tls.peetprint` and `tls.peetprint_hash`
- the full ordered `ciphers` list
- the full `extensions` array with per-extension detail, current enough to report
  `X25519MLKEM768 (4588)` under `supported_groups`
- `tls_version_negotiated` and `tls_version_record`

Its strength is **named, comparable fingerprint hashes**. A JA3 or peetprint hash can be
diffed directly against the value a real browser produces, which makes a mismatch immediately
actionable.

### `https://fp.impersonate.pro/api/http3`

Protocol-segregated: a separate endpoint per protocol, each of which **refuses to answer
unless that protocol was actually negotiated**. Verified directly — requesting `/api/http3`
or `/api/http2` over HTTP/1.1 returns an explanatory refusal, not a misleading reading:

```json
{ "info": "/api/http3 requires a matching protocol request, but this request negotiated HTTP/1.1.",
  "expected_protocol": "http3", "actual_protocol": "http/1.1" }
```

`/api/http1` does answer over HTTP/1.1, and its shape is `{ info, protocol, http1: { headers: [ordered] } }`,
so `/api/http3` can be expected to carry an equivalent `http3` object. The exact QUIC-layer
field set is **not yet known and must not be assumed** — it cannot be observed until an h3
client exists to ask. There is no `/api/all`, `/api/tls`, `/api/ja3` or `/api/ja4`; all four
return 404. The service advertises HTTP/3 via Alt-Svc, so reaching it may take a retry.

Its strength is **refusing to lie**. It is impossible to believe you have verified an HTTP/3
fingerprint when you were actually served over HTTP/2 — a mistake that is very easy to make
while a fallback path exists, and one that peet.ws's single-endpoint design will not catch
for you.

### How to use them together

Query both on every verification run, over the same protocol, and record both readouts.

- **Agreement** raises confidence, because two independent implementations inspected the
  same connection and drew the same conclusion.
- **Disagreement** is a finding to investigate before anything else, not a result to average.
  The likely causes, in rough order: our client behaving non-deterministically between the
  two connections; a fallback silently serving one request over a different protocol, which
  impersonate.pro will catch and peet.ws will not; or genuinely different methodology, which
  is worth understanding once and writing down.

### When each becomes usable

1. **Now, with no QUIC work at all.** SharpTls already ships 40 ClientHello profiles. Each
   can be pointed at peet.ws over HTTP/1.1 or HTTP/2 and its reported JA3 and peetprint
   compared against the browser it claims to imitate, with `fp.impersonate.pro/api/http1`
   or `/api/http2` cross-checking header order on the same run. That is an independent
   check on the existing corpus, dependent on nothing in subsystems A through E.
2. **After phase A4, as subsystem B's acceptance gate.** Reaching both over `h3` and diffing
   the QUIC-layer readouts against a real Chrome or Firefox is the test that says whether
   the fingerprint work succeeded. Neither request can be made before a QUIC transport
   exists, which is why B's gate cannot be pulled earlier.

Treat agreement between both as necessary, not sufficient. Together they confirm the fields
these two services happen to inspect. A packet capture diffed against a real browser remains
the stronger evidence, which is why the existing profile corpus is capture-backed rather
than hash-backed.

## Prior art: what bogdanfinn/tls-client already covers, and what it does not

`bogdanfinn/tls-client` does ship HTTP/3, via `bogdanfinn/quic-go-utls` — a quic-go fork
with uTLS substituted for the TLS handshake. Its test suite includes a Chrome-against-
Cloudflare HTTP/3 case. So HTTP/3 with an accurate ClientHello is demonstrably sufficient
against at least one major CDN today.

Its complete documented customisation surface is the 23-field `customTlsClient` object:

| Layer | Fields | Count |
| --- | --- | --- |
| TLS | `ja3String`, `keyShareCurves`, `supportedVersions`, `supportedSignatureAlgorithms`, `supportedDelegatedCredentialsAlgorithms`, `certCompressionAlgos`, `alpnProtocols`, `alpsProtocols`, `ECHCandidatePayloads`, `ECHCandidateCipherSuites`, `recordSizeLimit` | 11 |
| HTTP/2 | `h2Settings`, `h2SettingsOrder`, `connectionFlow`, `headerPriority`, `priorityFrames`, `pseudoHeaderOrder`, `streamId`, `allowHttp` | 8 |
| HTTP/3 | `h3Settings`, `h3SettingsOrder`, `h3PseudoHeaderOrder`, `h3PriorityParam`, `h3SendGreaseFrames` | 5 |
| QUIC transport | none | 0 |

### The distinction that matters

`h3Settings` accepts `QPACK_MAX_TABLE_CAPACITY`, `MAX_FIELD_SECTION_SIZE`,
`QPACK_BLOCKED_STREAMS` and `H3_DATAGRAM`. Those are HTTP/3 SETTINGS frame values
(RFC 9114 §7.2.4.1), sent on the HTTP/3 control stream.

They are **not** QUIC transport parameters (RFC 9000 §18) — `initial_max_data`,
`max_udp_payload_size`, `max_idle_timeout`, `initial_max_streams_bidi` and the rest — which
travel in the `quic_transport_parameters` TLS extension inside the ClientHello. Different
layer, different wire location, different fingerprint. Conflating the two makes the gap look
smaller than it is in one direction and larger in the other.

Confirmed at source level, not inferred: `bogdanfinn/quic-go-utls` contains 552 files and
no `u_*.go`, spec or parrot files, unlike `refraction-networking/uquic`. Its `Config` is
stock quic-go — timeouts, versions, token store. Its transport parameters marshal in fixed
order with a single greased value quic-go inserts itself and does not expose.

### Where SharpTls already stands

The transport-parameter half of the QUIC fingerprint is **already expressible today**,
because those parameters ride inside the ClientHello this library already controls:

- `TlsQuicTransportParameters` — 369 lines, strict parsing, unknown-parameter preservation,
  role-specific validation
- `ClientHelloBuilder.WithQuicTransportParameters(...)` — already in the shipped API

That covers uQUIC's `RandomizeTransportParameters`, `SuppressTransportParameters` and GREASE
transport parameters without any new transport code.

### The actual remaining gap

Subsystem B's target is therefore narrower than "reproduce uQUIC". What is genuinely
missing is the **packet layer only**:

- source and destination connection ID lengths
- initial packet number, and its encoded length
- token length and prefix
- per-datagram Initial flight plans, so a two-datagram Initial is reproducible
- CRYPTO frame splitting and frame ordering within the Initial
- datagram padding target

All six live in phase A1's packet codec and the spec struct that drives it. That is the
concrete argument for the sequencing warning above: A1 must take its layout decisions from a
struct rather than from constants, because these six fields are the struct.

## What this does not include

Subsystem B, the fingerprint spec layer, is separate and comes after A works. It is
comparatively small — roughly 8 to 10 tasks — because it parameterises code A already
wrote rather than adding new protocol behaviour. The uQUIC surface is the checklist:
connection ID lengths, initial packet number and its encoded length, token length and
prefix, per-datagram Initial plans, CRYPTO frame splitting, transport parameter order,
GREASE parameters, datagram padding target.

The critical sequencing point: **A must be built with B's knobs in mind.** If the packet
builder hardcodes connection ID lengths or frame ordering, B becomes a rewrite instead of a
parameterisation. That does not mean building B early — it means A's packet construction
takes its layout decisions from a struct rather than from constants.

## Recommendation

Build it, in phase order, with a decision point after A1.

Phase A1 is self-contained, provable against IETF-published vectors, and is the honest test
of whether this pace works for protocol code of this density. If A1 goes the way subsystem
D's codec went, the rest is the same work repeated. If it does not, stopping after A1 costs
one phase rather than the whole subsystem.
