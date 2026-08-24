# QUIC Connection Layer, Minimal (Phase A4-minimal) Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete one QUIC handshake against a real server, and produce a packet-layer fingerprint readout comparable against `reference-captures/the preset that measured it`.

That sentence is the whole scope test. If a feature is not needed to complete one handshake, or is not one of the layout fields the readout reports, it is out — see **Not in this phase**, which names where each cut lands.

**Architecture:** A single-threaded connection object that owns packet numbers, keys, and the send/receive loop, and drives `CustomTlsQuicClient` — which is already a pure, clock-free, I/O-free, resumable byte pump. A4 supplies everything below the TLS boundary: packet assembly, datagram assembly, the receive pipeline, ACK generation, and the state machine that sequences them. Every layout decision comes from a spec struct, never a constant.

**Tech Stack:** C# 13, .NET 9, xunit 2.9.3. All new production types `internal`, inside `SharpTls.dll` — see *Assembly and visibility* below.

**Standards:** RFC 9000 §7.2–7.3 (connection ID negotiation), §8.1 (anti-amplification), §10.1–10.2 (idle timeout, immediate close), §12.2 (coalescing), §13.1–13.2 (packet handling and ACK generation), §14 (datagram size and PMTU), §17 (packet formats), §19.3 (ACK); RFC 9001 §4 (using TLS), §5 (packet protection); RFC 9369 §3, §5 (QUIC v2 — for citation coverage only, not implemented).

---

## What is different about this phase, and what follows from it

Phases D, A1 and A2 were codecs: bytes in, bytes out, checkable against published vectors. A4 is the first phase with a network, a clock, and state that outlives a function call. Four consequences drive every decision below.

1. **There is no published vector for a *connection*.** There is, however, more external ground truth than "none" — see *The testing strategy* — and pretending otherwise is how a phase quietly becomes self-referential.
2. **Time enters.** Anything reading a clock directly is untestable. The seam is decided in task 1 and is `TimeProvider`, because that is already this repo's house style in five files.
3. **A multi-datagram Initial is mandatory.** The X25519MLKEM768 key share alone is 1216 bytes. Any design where "an Initial" and "a datagram" are the same object is wrong before it compiles.
4. **Every layout decision is subsystem B's to vary.** A1 and A2 kept these as parameters. A4 must too, or B is a rewrite.

---

## Ground truth in the repo

Do not retype values from these. Copy them.

| File under `docs/superpowers/specs/reference-captures/` | What A4 uses it for |
| --- | --- |
| `rfc9001-appendix-a-test-vectors.txt` | **The phase's anchor.** A.1 keys, A.2 the complete client Initial *datagram* (1200 bytes, padded), A.3 the complete server Initial, A.4 Retry, A.5 ChaCha20 |
| `rfc9001-section5-packet-protection.txt` | §5.1–5.8 — keys, AEAD, header protection, Retry |
| `rfc9000-packet-formats-and-pn-pseudocode.txt` | §17 packet formats, Appendix A.1–A.3 packet-number pseudocode |
| `rfc9000-section12-packets-and-frames.txt` | §12.2 coalescing (what may share a datagram, and that Retry may not), §12.4 legality |
| `rfc9000-section19-frame-formats.txt` | §19.3 ACK, §19.6 CRYPTO, §19.17/18 PATH_CHALLENGE/RESPONSE, §19.19 CONNECTION_CLOSE |
| `rfc9000-section16-variable-length-integers.txt` | §16 — **including the rule that non-minimal varint encodings are permitted everywhere except the Frame Type field.** See *Finding 5* |
| `rfc9000-section18-transport-parameters.txt` | §18/§18.2 — the bounds the peer's parameters are validated against |
| `rfc9000-section20-transport-error-codes.txt` | §20.1 — the code to put in CONNECTION_CLOSE |
| `the preset that measured it` | The readout target: client CID length 0, server CID length 8, `max_udp_payload_size` 1472, transport parameter wire order |

**Every constant carries its RFC section. Reviewers verify against the RFC text, never against the code's comments.** That produced zero wire-format defects across A1's ten tasks and A2's seven, and is not optional here.

### The sections task 0 added — landed in `1d142ef`, all byte-verbatim

| File | What A4 uses it for |
| --- | --- |
| `rfc9000-section7-connection-id-negotiation.txt` | §7.2 the client's first DCID (**MUST be at least 8 bytes**) and the server's SCID becoming ours; §7.3 CID authentication |
| `rfc9000-section8-address-validation-and-amplification.txt` | §8.1 the 3× limit — which **counts all bytes received, including discarded and malformed datagrams** |
| `rfc9000-section10-idle-timeout-and-immediate-close.txt` | §10.1 idle timeout, §10.2 immediate close |
| `rfc9000-section13-packetization-and-ack-generation.txt` | §13.1 ack-eliciting, §13.2 ACK generation, **§13.2.1 Initial and Handshake ACKs sent immediately** |
| `rfc9000-section14-datagram-size-and-pmtu.txt` | §14.1's MUST, verbatim: *"A client MUST expand the payload of all UDP datagrams carrying Initial packets to at least the smallest allowed maximum datagram size of 1200 bytes"* |
| `rfc9001-section4-using-tls.txt` | §4.1 the interface, §4.1.1 levels, **§4.1.2 complete vs confirmed**, §4.9.x key discard |
| `rfc9369-section3-version2-differences.txt`, `rfc9369-section5-tls-resumption-and-new-token.txt` | QUIC v2 — citation coverage only, retiring the A2 audit's last open finding |

**Eight files, one per topic**, matching the convention the six prior extracts use. An earlier draft of this plan said "nine"; there is no ninth range with a textual basis, and the implementer was right to decline to manufacture one.

**Four requirements these extracts surfaced that no earlier draft of this plan stated.** Three independently confirm a review finding from the RFC text rather than from code reading:

1. **§7.2: the client's self-chosen DCID on its first Initial MUST be at least 8 bytes.** This is a hard validation rule on `TlsQuicConnectionSpec`, not a Chromium-shaped default, and **it bounds one of subsystem B's knobs**. that client's DCID length of 8 sits exactly at the floor, so the constraint is invisible until someone tries to go below it. → task 1.
2. **§7.3: both endpoints MUST validate** the peer's `original_destination_connection_id` and `retry_source_connection_id` against the CIDs observed on the wire, treating a mismatch as `TRANSPORT_PARAMETER_ERROR` or `PROTOCOL_VIOLATION`. → task 9b, and it confirms this was a gap in the task list, not merely a missing citation.
3. **§4.1.2, verbatim: *"At the client, the handshake is considered confirmed when a HANDSHAKE_DONE frame is received."*** A client *MAY* also confirm on an acknowledgment for a 1-RTT packet. → task 9a-ii, and it is Finding 8 confirmed from the RFC.
4. **§13.2.1: ACKs for Initial and Handshake packets MUST be sent immediately**, with no `max_ack_delay`, unlike 1-RTT. → task 8, as a simplification.

**Any further section is extracted the same way:** fetch from `rfc-editor.org` inside the sandbox, `sed` the line range, commit verbatim with a provenance header, diff line by line. **Extraction is a task, not an assumption** — two implementers in a prior session cited sections that were not in the repo, and both happened to be right, which is exactly the problem.

---

## What already exists and must be reused

Verified against the source, not assumed. Signatures are copied from the files.

### The TLS engine is already the right shape — it will not fight this plan

`CustomTlsQuicClient` (`src/SharpTls/Quic/CustomTlsQuicClient.cs:15`) documents itself: *"The caller owns QUIC packets, CRYPTO frames, loss recovery and packet protection; this type owns only TLS Handshake bytes."* That is exactly true.

- **Zero I/O.** No `Socket`, no `ITlsQuicDatagramTransport`, no `Dns` — zero hits in the file.
- **Zero timers.** No `Stopwatch`, no `Task.Delay`, no `Timer` anywhere in `src/SharpTls/Quic/`.
- **Fully resumable across an RTT.** HRR, 0-RTT and ECH are internal state transitions inside `ProcessCryptoDataAsync`; none needs caller involvement beyond feeding bytes and shipping the returned events. A second ClientHello after HRR arrives as another `TlsQuicCryptoDataEvent` at `Initial` level with the write offset already advanced.

The surface A4 drives:

```
:112  public TlsQuicProcessResult StartHandshake()
:237  public async ValueTask<TlsQuicProcessResult> ProcessCryptoDataAsync(
          TlsQuicEncryptionLevel level, ulong offset, ReadOnlyMemory<byte> data, CancellationToken ct = default)
:312  public TlsQuicProcessResult NotifyHandshakePacketSent()   // emits TlsQuicDiscardKeysEvent(Initial)
:333  public TlsQuicProcessResult ConfirmHandshake()            // emits TlsQuicDiscardKeysEvent(Handshake)
:77   public bool IsHandshakeComplete { get; }
```

Output is push-only: every call returns `TlsQuicProcessResult` whose `Events` list (`TlsQuicEvents.cs:134`, *"in the exact order in which TLS produced them"*) carries `TlsQuicCryptoDataEvent { Level, Offset, Data }`, `TlsQuicTrafficSecretEvent`, `TlsQuicPeerTransportParametersEvent`, `TlsQuicDiscardKeysEvent`, `TlsQuicHandshakeCompletedEvent`.

Keys: `TlsQuicTrafficSecret.DerivePacketProtectionKeys(TlsQuicVersion)` → `TlsQuicPacketProtectionKeys` with `CopyKey()/CopyIv()/CopyHeaderProtectionKey()`. Initial keys come separately from `TlsQuicInitialSecrets.Derive(version, destinationConnectionId)`. `TlsQuicTrafficSecret` **rejects `Level == Initial`** by design.

### The packet and frame layers

| Concern | Read | Write |
| --- | --- | --- |
| Long header | `TlsQuicPacketHeader.TryReadLongHeader` `:146` | `WriteLongHeader(Span<byte>, in TlsQuicLongHeader)` `:252` |
| Short header | `TryReadShortHeader` `:318` | `WriteShortHeader` `:395` |
| Packet number | `TlsQuicPacketNumber.Decode` `:53` | `EncodedLength` `:12`, `Truncate` `:46` |
| AEAD | `TlsQuicPacketProtection.TryOpen` `:123` | `Seal` `:64` |
| Header protection | `TlsQuicHeaderProtection.TryRemove` `:91` | `TryApply` `:57` |
| Coalesced datagram | `TlsQuicDatagramReader.Read` `:77` (lazy iterator) | **absent** |
| Frames | `TlsQuicFrames.TryReadFrame(ReadOnlyMemory<byte>, ref int, out TlsQuicFrame, out TlsQuicTransportError)` `:327` | `WriteFrame(List<byte>, in TlsQuicFrame)` `:601` |
| Legality | `TlsQuicFrameLegality.Permits(in TlsQuicFrame, TlsQuicEncryptionLevel)` `:266` | — |
| Retry | `TlsQuicRetry.TryVerify` `:104` | `ComputeTag` `:68` |
| Version Negotiation | `TlsQuicVersionNegotiation.TryRead` `:61` | `Write` `:142` |

Also reuse: `QuicVariableLengthInteger`, `TlsQuicTransportParameters` (order-preserving), `TlsQuicCryptoStreamReassembler`, `TlsQuicProtocol`'s enums and `TlsQuicTransportException`.

### What does **not** exist, confirmed by grep

- **No function assembles a complete packet.** `WriteLongHeader` emits header bytes and returns the count; it does not seal, does not apply header protection, and **does not return the packet-number offset** that `TryApply` needs.
- **No datagram writer.** `TlsQuicDatagramReader` splits; nothing coalesces.
- **No padding target.** There is no `1200`, `1252`, `1472` or `1350` anywhere in `src/`. Only `65527` (RFC max UDP payload) and `MaximumConnectionIdLength = 20`.
- **No per-number-space packet number state.** `TlsQuicPacketNumber` is stateless pure math; `largestAcked` is a caller argument.
- **No ACK generation.** `TlsQuicAckFrames` encodes ranges it is handed. Nothing tracks received packet numbers. **See Finding 2 — this fell through a gap between documents.**
- **No in-memory `ITlsQuicDatagramTransport`.** Both implementations use real sockets. `FakeSocks5Relay` is a fake SOCKS5 *server*, not a transport double.
- **No client↔server loopback test.** `CustomTlsQuicClientTests.cs` hand-builds server handshake messages (`BuildServerHello` `:411`, `BuildHelloRetryRequest` `:437`, `BuildEncryptedExtensions` `:468`, `BuildCertificate` `:491`, `BuildCertificateVerify` `:506`); `CustomTlsQuicServerTests.cs` never constructs a client. Wiring the two together is new — and cheap.

---

## Findings from planning — read these before task 1

These were found while writing this plan, not while executing it. Each changes a task.

### Finding 1 — a `ClientHelloProfile` is **never** reusable across QUIC connections for the actual target

QUIC transport parameters are **not** on `CustomTlsQuicClientOptions`. They are baked into the immutable `ClientHelloProfile` via `ClientHelloBuilder.WithQuicTransportParameters(...)` (`src/SharpTls/ClientHello/ClientHelloBuilder.cs:340`), and `CustomTlsQuicClientOptions.Snapshot()` (`:78-88`) hard-rejects a profile without them.

**Two parameters are per-connection, and the second one has no escape clause:**

- `initial_source_connection_id` (0x0F) is per-connection whenever the source CID is non-empty. Chromium's is zero-length, so for *that* fingerprint this one parameter is constant.
- **`initial_rtt` (12583) is randomised per connection.** The capture is explicit: 192859 "is not a constant to copy — uQUIC models this as `ChromeRandomInitialRTT()`. A fixed value here would itself be a fingerprint." It is a transport parameter, so it lives in the same immutable profile.

**Therefore: build a fresh `ClientHelloProfile` per connection, unconditionally.** An earlier draft of this plan conditioned it on `SourceConnectionIdLength != 0`, which is wrong for the exact fingerprint this phase exists to reproduce. Budget for it in task 9a-ii, and pin it: two consecutive connections must produce two different `initial_rtt` values.

### Finding 2 — ACK generation is orphaned between two documents

The scoping document (`2026-08-16-quic-transport-scoping.md`) lists ACK generation as **A2 item 11**. The A2 plan's seven tasks do not include it, and A2 is marked complete. Nothing tracks received packet numbers anywhere in `src/`.

A4 must own it (task 8). It is not optional for minimal: a server that never sees an ACK keeps its flight in flight, re-arms its PTO, and with the anti-amplification limit in play may stop sending entirely.

### Finding 3 — the zero-copy contract fights a receive loop, and this is where it bites

`ITlsQuicDatagramTransport.ReceiveAsync` (`:48-58`), both header structs and `TlsQuicFrame` all document that parsed fields are **slices of the caller's buffer**. `TlsQuicDatagramReader.Read` is additionally a **lazy iterator** — storing the `IEnumerable` across an `await` means the walk itself runs later, against whatever the buffer then holds.

A4 is the first code that both owns the buffer and wants to hold parsed results. Task 6 must state the rule and pin it: **a datagram's buffer is owned by one synchronous pass; anything that must outlive that pass is copied, not aliased.** In practice the only thing that outlives it is CRYPTO payload, which `ProcessCryptoDataAsync` is `async` for — so CRYPTO bytes are copied into the reassembler's call, and everything else is consumed before the pass returns. For minimal, allocate a fresh receive buffer per datagram; do not pool. Pooling is an A3-era optimisation and it is exactly the change that would silently break this.

### Finding 4 — the send path is `List<byte>`-based end to end

`TlsQuicFrames.WriteFrame` takes a `List<byte>`. So does every per-family writer. There is no span-based frame writer and no "write this ordered sequence" entry point — A4 loops `WriteFrame` itself, which is fine and preserves order by construction (`TlsQuicFrames.cs:278` documents that the writer never merges or reorders).

The consequence for the deferred allocation work: **hoisting the per-packet cipher instances does not make the send path allocation-free**, because the frame writer allocates a `List<byte>` per packet regardless. The receive path is the one that is measured at 0 bytes and is attacker-facing. That reorders the deferred items — see *The four deferred allocation fixes*.

### Finding 5 — there is a seventh and eighth fingerprint field, and the RFC extract already proves it

RFC 9000 §16, extract line 44: *"Values do not need to be encoded on the minimum number of bytes necessary, with the sole exception of the Frame Type field; see Section 12.4."*

So the encoded **width** of the long header's `Length` varint, and of a CRYPTO frame's `Offset` and `Length` varints, are free choices an implementation makes — and therefore fingerprintable, exactly like packet-number length already is. `QuicVariableLengthInteger.Write` always writes minimal, so today we can only produce one of the possible encodings.

This is not in the handoff's six-field list. It costs one optional parameter to keep open and a rewrite to add later. **Put the knob in the spec struct in task 1, default it to minimal, and add "is Chromium's Length field minimally encoded?" to task 11's readout questions.** We do not yet know the answer; a packet capture does.

Note that RFC 9001 A.2 cannot help here: its varints are `00` (token length), `40f1` (CRYPTO length) and `449e` (header Length), **all minimal**. Leg 1 gives this field zero coverage — see *What leg 1 does and does not anchor*.

### Finding 7 — the scoping assigns A4 a receive-path decision, and task 6 is where it comes due

The scoping's *"A known allocation ceiling, and the escape hatch"*: `ITlsQuicDatagramTransport.ReceiveAsync` allocates one `IPEndPoint` per datagram; .NET 9's `Socket.ReceiveFromAsync(Memory<byte>, SocketFlags, SocketAddress, CancellationToken)` reuses a caller-owned `SocketAddress` and allocates nothing. The scoping is explicit that this is **subsystem A's decision, not D's**, and that it "should be decided when there is a packet loop to measure, not before."

**Task 6 is that loop, and task 3 adds two new implementations of the interface whose shape the decision changes.** So it is decided in this phase whether or not it is taken. The decision, and its reasoning, is in the cut table: **deferred, with the interface left unchanged.** A handshake is ten datagrams; the allocation is invisible at that volume, and changing the receive result's shape now would land on `TlsQuicUdpDatagramTransport`, `TlsQuicSocks5Transport` and both new doubles before there is anything to measure. Task 6 records it in one comment at the receive site so the next reader finds the decision rather than the silence.

### Finding 8 — nothing in the handshake path receives HANDSHAKE_DONE, and "complete" is not "confirmed"

`CustomTlsQuicClient.ConfirmHandshake()` (`:331`) documents itself as *"Marks receipt of QUIC HANDSHAKE_DONE. Only a client calls this; it releases Handshake keys."* It **throws** `InvalidOperationException` if `!IsHandshakeComplete`.

RFC 9001 §4.1.2 separates two states this plan's first draft used interchangeably:

- **Handshake complete** — TLS finished. Client-side, this is `IsHandshakeComplete`.
- **Handshake confirmed** — for a client, *on receipt of HANDSHAKE_DONE*, and only then may Handshake keys be discarded.

HANDSHAKE_DONE (`0x1e`) arrives in a **1-RTT packet**, which has a **short header**. An earlier draft's task 6 was long-header only and no task read a short header or installed 1-RTT read keys — which made task 9a's done-condition ("Handshake keys discarded when the handshake is confirmed") unsatisfiable, and invited an implementer to call `ConfirmHandshake` on TLS-complete and discard Handshake keys the server may still be using. Task 14's streams are 1-RTT traffic over the same missing path.

**So task 6 reads short headers and installs 1-RTT read keys, and task 9a-ii names HANDSHAKE_DONE as the trigger.** Key update is out of scope, so the short header's key phase bit is read and a value other than the installed phase closes the connection — **but only on a packet the AEAD has already authenticated.** RFC 9001 §5.5: *"Similarly, a packet that appears to trigger a key update but cannot be unprotected successfully MUST be discarded."* Checking the bit where it first becomes readable — after header-protection removal, before the AEAD — closes on exactly the packet that clause says must be discarded. §5.4 gives the `quic hp` key confidentiality only and no authentication, so a pre-AEAD close is a one-datagram remote kill for any off-path observer; §17.3.1 names the same hazard for the reserved bits by name. Post-AEAD is not the prudent ordering here, it is the only conforming one.

### Finding 6 — three methods on the TLS client skip its own lock

`StartHandshake` (`:112`), `NotifyHandshakePacketSent` (`:312`) and `ConfirmHandshake` (`:333`) mutate state and call `_initialReassembler.Discard()` without taking the `SemaphoreSlim` that guards `ProcessCryptoDataAsync`. This is not a defect — it is a documented single-connection type — but it makes the connection loop's threading model a **requirement**, not a preference: one loop, one thread of control, no concurrent send and receive pumps touching the TLS engine.

Also: `TlsQuicProcessResult.Dispose()` zeroes unconsumed secrets (`TlsQuicEvents.cs:137-148`). **Install keys before disposing the result.** And the client is one-shot: any exception latches `_failed` and poisons the instance permanently. New connection = new client *and* (per Finding 1) possibly a new profile.

---

## The testing strategy — the decision

This is the most important call in the plan, so it is stated as a decision with its reasoning, not as a list of test types.

**"We tested it against a real endpoint once" is not a regression test.** Neither is a loopback against ourselves, on its own — A2's own trap list says it: *"Seal/open, encode/decode pairs cancel out. A bug in shared nonce or offset arithmetic makes both halves wrong identically."* A client and a server we both wrote share every such bug.

So: **four legs, each answering a question the others cannot, and two of them in the regression gate.**

### Leg 1 — RFC 9001 Appendix A, as a *connection* vector (in the gate, always)

The claim that A4 has no published vector is not quite true, and the difference is worth a whole task. **RFC 9001 A.2 is a complete, real, protected client Initial datagram — 1200 bytes, padded — and A.3 is the server's Initial reply on the same connection.** They are two datagrams of a real connection with published keys, and they are the only externally-sourced bytes this phase will ever have.

#### What leg 1 does and does not anchor

An earlier draft claimed "five of the six fields, anchored externally." Checked field by field against the extract, that was overstated, and the overstatement matters because it is the handoff's own trap: *"Published RFC vectors are not adversarial."*

| Field | Anchored by A.2? |
| --- | --- |
| Destination / source CID length | **Fully** — 8 and 0, and 0 is a genuinely awkward value |
| Initial packet number and encoded length | **Fully** — PN 2 at encoded length 4, a non-minimal choice and therefore a real test |
| Datagram padding target | **Fully** — 1200 |
| Token length and prefix | **Degenerate only** — token length is `00`. The prefix path is never entered |
| CRYPTO splitting and frame order | **Order yes, split no** — one CRYPTO frame at offset 0, then PADDING |
| Varint encoding widths (Finding 5) | **Not at all** — `00`, `40f1`, `449e` are all minimal |
| Per-datagram flight plan | **Not at all** — A.2 is one datagram |

So A.2 proves the builder correct **at Chromium-ish defaults** and proves nothing about the spec struct's **knobs** — which are exactly what subsystem B is. Leg 1 is still the strongest evidence in the phase; it is just not sufficient on its own.

**The consequence is a companion done-condition on tasks 4b and 5: for every knob, one hand-derived expected-bytes test at a non-default value** — a non-zero token, a real multi-frame CRYPTO split, a non-minimal `Length` varint, packet-number encoded lengths 1 and 3. Hand-derived bytes, not round-trips; a round trip proves the encoder and decoder agree while both are wrong.

One more caveat for task 4b: **A.2's PADDING bytes are not published.** The extract gives the CRYPTO frame and says "plus enough PADDING frames to make a 1162-byte payload." So the plaintext is *reconstructed* and then checked through the protected output — say that in the test, and do not describe the plaintext as literal published bytes.

**The design constraint leg 1 imposes, and it is the same one subsystem B needs:** the packet builder takes an ordered frame list and a spec, **not** a TLS engine. A.2's CRYPTO payload is a specific ClientHello ours will never reproduce, so the payload must be injectable. B needs exactly the same seam. This is the good kind of constraint — the test and the fingerprint layer want the identical shape.

### Leg 2 — the scripted transport double (in the gate, always)

An `ITlsQuicDatagramTransport` implementation over a script: no socket, no clock, deterministic. It records what the connection sends and replays a scripted server response.

**State its limit explicitly, because a plan that does not will assume something unbuildable.** A scripted transport can fabricate any packet the *Initial* keys protect, because Initial keys derive from the destination connection ID and a published salt — no key agreement involved. It **cannot** fabricate a Handshake or 1-RTT packet, because those keys depend on the client's ephemeral share, which differs every run. Recording a real server's response once and replaying it fails for the same reason.

So leg 2 owns exactly: Retry, Version Negotiation, malformed and truncated datagrams, unknown versions, coalesced Initial packets, packet reordering and duplication at Initial level, idle timeout, and the handshake deadline. All are pre-key-agreement or purely temporal, and all are deterministic. That is a real and useful set, and it is where the fake `TimeProvider` lives.

### Leg 3 — MsQuic loopback (in the gate when supported)

**`System.Net.Quic.QuicListener` is a real, independent QUIC implementation shipped with the runtime, and it works on this machine — verified, not assumed:**

```
QuicListener.IsSupported   = True
QuicConnection.IsSupported = True
RuntimeVersion             = 9.0.17
```

An in-process `QuicListener` on loopback with a self-signed certificate gives a **full handshake against an implementation we did not write**, offline, with no new dependency and no network. It kills the shared-bug objection outright, and it enforces real conformance — padding, ACKs, transport parameter validity — failing us for real reasons.

Gate it on `QuicListener.IsSupported` and **skip, never fail**, when false. That is why legs 1 and 2 must stand alone: on a machine without msquic the gate must still mean something.

**Leg 3 validates conformance, not fingerprint fidelity.** MsQuic will happily accept a great many layouts that are nothing like Chromium's — a one-byte packet number, a different CID length, a single-datagram Initial. So task 10 passing is evidence that we speak QUIC, and **is not evidence about any spec knob.** Fidelity evidence comes from leg 1's byte-exact match, the non-default knob tests, and task 11's readout diff. Do not let a green task 10 be reported as fingerprint progress.

This also justifies task 7 (our own loopback peer wrapping `CustomTlsQuicServer`) being *smaller* than it looks: leg 3 covers "does an independent implementation accept us", so task 7's peer exists only to exercise paths MsQuic will not produce on demand, and to give a fast in-process fixture. If task 7 turns out to cost more than a day, cut it and lean on legs 1–3 — it is the one task in this plan with a cheap fallback.

### Leg 4 — the live endpoints (never in the gate)

`SHARPTLS_RUN_INTEROP=1`-gated, following `tests/SharpTls.Tests/Interop/PublicServerInteropTests.cs:579`. Non-deterministic by nature, and with A3 deferred, loss-fragile by construction. It answers one question no other leg can — *does a production server on a real path accept us* — and it is the run that produces the readout for comparison.

### What the gate is

`dotnet test --filter "FullyQualifiedName~Quic"`, which runs legs 1 and 2 always and leg 3 when supported. Plus `PublicApiBaselineTests.ExportedApiMatchesTheReviewedBaseline` **by name**, because the `~Quic` filter cannot see it — see *Assembly and visibility*.

Note the two pre-existing failures in the full suite (`CertificateValidationTests.UntrustedRootIsRejected`, `Interop.ClientCertificateInteropTests.Tls12MutualAuthentication...`). They are not ours; the `~Quic` filter is the gate precisely because of them.

### What this strategy deliberately does **not** do

No mutation-testing of the network loop's timing. No loss/reorder simulation harness — that is A3's, and building it now would test retransmission code that does not exist. No property-based state machine exploration. Each is defensible later and none is needed to complete one handshake.

---

## Where A3's absence is load-bearing

A3 is deferred by the user's decision, recorded in the handoff. **No loss detection, no congestion control, no retransmission.** Five places in this plan depend on that, and A3 needs to know what it is inserting into.

1. **Nothing retains a sent packet.** There is no retransmit buffer, and `CustomTlsQuicClient` does not have one either — `CreateCryptoEvent` advances the write offset and hands over the only copy. **Mitigation that makes A3 an insertion instead of a rewrite:** the send path returns a `TlsQuicSentPacket` record — `{ Level, PacketNumber, Size, IsAckEliciting, IsInFlight, SentAt }` — for every packet it emits. A4-minimal discards it. A3 stores it. The record costs nothing now and is the difference between A3 adding a list and A3 rewriting task 4b. **Task 4b's done-condition includes emitting this record.**
2. **ACK processing computes no RTT sample.** Task 8 processes incoming ACK frames only far enough to advance largest-acked (which task 4b needs for packet-number encoding). The entry point must exist and be named `ProcessAckFrame`, taking the frame and the receive time, so A3 fills in the body rather than finding a place for one.
3. **The handshake has no PTO.** If any packet is lost, the connection hangs. The only mitigation in minimal is a **handshake deadline** on the injected `TimeProvider` that fails the attempt cleanly (task 9a-ii). That is a timeout, not a retransmission, and the plan must not let anyone mistake it for one. A lost packet means: retry the whole attempt at the process level.
4. **Anti-amplification shrinks the server's budget, and with no PTO we cannot recover from the stall it can cause.** RFC 9000 §8.1 limits a server to 3× the bytes it has received from an unvalidated address — and per the extract, that count includes **all** bytes received, discarded and malformed datagrams among them, which makes the budget slightly larger than a naive reading suggests. If the server exhausts that budget mid-flight it stops sending and waits for more from us — and with no PTO we never send more, so the connection hangs until the handshake deadline with no diagnosable error. That is the A3-dependent part, and it is real.

   **It is not, however, the reason to pad every Initial datagram — see the correction in task 5.** An earlier draft argued from an arithmetic error (it compared 7200 against "~3600", which assumes the second datagram contributes nothing, when the second datagram exists precisely *because* the ClientHello overflows the first: ~1216 for the key share plus ~600–700 more means it carries roughly 700–800 bytes, so the unpadded total is ~2000 and the budget ~6000, not 3600). A 17% difference that still fits an RSA chain does not demonstrate a stall. The padding rule stands on RFC 9000 §14.1, which is normative; amplification is secondary colour with corrected numbers.
5. **No congestion window is needed for exactly this case, and the arithmetic is why.** RFC 9002's initial window is `10 × max_datagram_size` ≈ 12000 bytes. Our entire Initial flight is ~2400. So the handshake is conformant on send without any congestion controller. This is true for a handshake and false for anything that sends data — state it so nobody generalises it.

---

## Design constraints carried from A1, A2 and B

- **No layout decision may be a constant.** Task 1 creates the spec struct and nothing afterwards may read a literal for: source/destination connection ID length, initial packet number, packet-number encoded length, token bytes, per-datagram flight plan, CRYPTO splitting, frame order, padding target, and (Finding 5) varint encoding widths.
- **The encoder emits frames in exactly the order given.** No merging, no reordering, no automatic padding. Already true of `WriteFrame`; task 5 must not "helpfully" fix anything up.
- **The packet builder takes frames and a spec, not a TLS engine.** Required by both leg 1 and subsystem B.
- **Buffers are owned by one synchronous pass** (Finding 3).
- **One thread of control** (Finding 6).
- **`TlsQuicFrameLegality.Permits` gates every frame on the send path**, not only the receive path. It is one call and it turns a class of B-authored spec error into a test failure instead of a peer's CONNECTION_CLOSE.

## Assembly and visibility

**Everything A4 adds is `internal`, inside `SharpTls.dll`.** The entire packet and frame layer is `internal` and `AssemblyInfo.cs:3-6` already grants `SharpTls.Tests`, `SharpTls.Fuzz`, `SharpTls.Benchmarks` and `SharpTls.CoverageFuzz`. Nothing outside the assembly needs a connection object until subsystem E.

This deliberately sidesteps the handoff's known blind spot: `PublicApiBaselineTests` does not match `~Quic`, so a public-type change breaks a test the gate cannot see. If a task does end up needing a public type, run that test by name, regenerate with `tools/SharpTls.ApiCompat`, and **diff `PublicApi.Shipped.txt` to confirm only your own lines moved** — regenerating absorbs unrelated drift already on the branch.

## The four deferred allocation fixes — the decision and its reasoning

Recorded in handoff §8. Finding 4 reorders them.

| Item | Lands | Why |
| --- | --- | --- |
| **(e)** `QuicVariableLengthInteger` has no `TryRead`; every malformed frame allocates an exception + message. the throwing `Read` is called across 7 files | **Task 2, before anything else** | It is the only one with a security argument, and **A4's receive loop is what creates the exposure** — before task 6 there is no code path from a socket to a parser. The fix must land no later than the loop it protects, and its cost only grows as A4 adds callers. Mechanical and provable: suite stays green, plus a new allocation test on the *rejecting* path |
| **(a)** `Aes.Create()` per packet, **(b)** `out byte[] mask` per packet, **(c)** `new AesGcm`/`ChaCha20Poly1305` per packet | **Task 12, after the first successful handshake** | The scoping argues A4 is the natural epoch owner, and it is right — but doing it *before* the handshake works puts a signature change to A1's crypto on the critical path, so a handshake failure could be attributed to either the new connection layer or the changed crypto API. That is precisely the bundling A2's task 3/3a split exists to prevent. Afterwards it is a behaviour-preserving refactor with the A.1/A.2/A.3/A.5 vectors and a working handshake as the net. The epoch type gets written once and re-typed once — a ~40-line cost, paid to keep the critical path attributable |
| **(d)** `TlsQuicAckFrames.WriteAckFrame` allocates a `List<byte>` + `ToArray` per call | **A3** | Write-side only; the receive path is already 0 bytes and permanently tested. A handshake sends about three ACKs. A3 is the phase that generates them per RTT and therefore the phase where the cost is real |

**And note what none of these buy:** per Finding 4, the send path allocates a `List<byte>` per packet in the frame writer regardless. Do not let task 12's report claim an allocation-free send path.

## File layout

All production files directly under `src/SharpTls/Quic/`. No subfolders. The 500-line limit is measured on **code** lines, not raw lines — RFC citations and mutation records are the reason this project finds defects.

**`TlsQuicConnection.cs` is exempted at a stated number, not silently.** *Amended by task 9b's fix round, which measured it rather than arguing about it.* Measure with `grep -vcE '^\s*(//|$)'`; after 9b it is **962 code lines** (2392 raw, 1430 comment and blank) against a 500 cap — 92% over, and it was 92% over before this round too. The rule was being ignored rather than judged, which is the failure the rule exists to prevent, so it is judged here:

- **The cap for this file is 1000 code lines through task 14.** That is the measured 962 plus room for the corrections a review round produces, and it is a number a reviewer can check in one command.
  - *Task 14c measured it again and it went DOWN: 964 before, **960** after, because the pump's three preconditions moved out with the send path. Task 14c's new code is `TlsQuicApplicationSendPath.cs` (81 code lines), a **partial class** — the sibling file this list asks for, taken as a partial so the shared private state stays private, which is the trade the bullet below refuses to make.*
- **Task 14's new concerns do not go in this file.** Short headers, 1-RTT sending, PATH_RESPONSE and streams are a different packet type and a different lifecycle from the handshake this file drives; they land in a sibling file. If task 14 finds it cannot separate them, the number above is what it has to renegotiate explicitly, in writing, before it exceeds it.
- **The existing content is NOT to be split, and this was tested rather than asserted.** 9b's spec reviewer put the "one concern" defence under pressure and it held for Retry, close and idle timeout: the three mutate a dozen shared private fields (`_destinationConnectionId`, `_retryToken`, `_adoptedFromRetry`, `_idleSince`, `_sentAckElicitingSinceReceive`, `_processedServerPacket`, `_draining`, …), and driving them into separate types would force every one of them `internal` — trading a long file for a wide mutable surface, which is the worse of the two.
- **Two pieces ARE extractable and neither was extracted.** `HandleVersionNegotiation` (~30 code lines, a pure predicate) and the §7.3 validator trio (~70 code lines, whose four inputs are already `internal` properties). Together they are ~100 lines, which takes 962 to ~862 — **so extraction does not solve the size problem and must not be done for that reason.** The §7.3 trio has a second, independent argument — as a pure function its five arms become direct unit tests instead of needing the doctored-`LoopbackQuicPeer` route through a complete TLS handshake — and the fix round still declined it: rows 78-85 already witness all five arms through that route, so the extraction buys cheaper FUTURE tests rather than missing coverage, `CloseUnderSection73Async` is not pure (it puts a CONNECTION_CLOSE on the wire) so the split is a real refactor rather than a move, and a fix round is the wrong place to restructure working, witnessed code. **Whoever wants it should take it as its own task with its own sweep**, not as a side effect of a size complaint.

| File | Responsibility | Task |
| --- | --- | --- |
| `TlsQuicConnectionSpec.cs` | every layout knob subsystem B varies, plus Chromium-shaped defaults | 1 |
| `TlsQuicPacketBuilder.cs` | one protected packet: header + ordered frames + PN + AEAD + HP | 4b |
| `TlsQuicDatagramBuilder.cs` | coalescing, padding to target, the Initial flight plan | 5 |
| `TlsQuicPacketReceiver.cs` | datagram → packets (long **and short** header) → HP removal → AEAD open → frames | 6 |
| `TlsQuicAckTracker.cs` | received-PN tracking per space, ACK range construction, `ProcessAckFrame` | 8 |
| `TlsQuicConnection.cs` | the state machine and the send/receive loop | 9a-ii, 9b |
| `TlsQuicConnectionOptions.cs` | transport, endpoint, spec, `TimeProvider`, deadlines | 1, 9a-ii |
| `TlsQuicKeySet.cs` | per-level per-direction key ownership, install and discard | 9a-i (re-typed in 12) |
| `TlsQuicFingerprintReadout.cs` | the six-plus fields, extracted from what we emitted | 11 |
| `TlsQuicStreams.cs` | minimal send/receive stream plumbing for subsystem C | 14 |

Tests mirror these in `tests/SharpTls.Tests/Quic/`, plus `InMemoryDatagramTransport.cs`, `ScriptedDatagramTransport.cs`, `LoopbackQuicPeer.cs`; interop tests in `tests/SharpTls.Tests/Interop/`.

## Standing rules inherited from A2

The eighteen rules in `2026-08-17-quic-a2-frame-layer.md` transfer whole. The six that bite hardest here:

- **A surviving mutation is unwitnessed, unreachable by construction, or vacuous — say which.** For a vacuous one write no test; it would pass against the mutant and become a false witness.
- **Provenance decides reachability.** A guard on a parser's output is often unreachable; the same guard on a caller's input always is. In A4 the caller is frequently the spec struct, which is B's to populate — so **every guard on a spec field is reachable and needs a witness.**
- **Independence needs external ground truth.** Leg 1 has it. Legs 2 and 3 do not, for state-machine behaviour — label those numbers *snapshots* and lean on invariants (a Retry script cannot reach the 1-RTT reader; the handshake cannot complete before Handshake keys install).
- **Run mutation sweeps in a `git worktree`**, never the shared tree.
- **Commit working state before running anything long.** Three agents were lost mid-task in a prior session.
- **Chain `git add <paths>` and `git commit` in one invocation**, then `git show --stat HEAD`. `git commit -m` commits the whole index and this branch is shared.
- **Never write an absolute count into a comment or a plan** — they rot every task. State the count relative to the check under discussion, or name the grep that produces it.
- **A mutation ledger is an itemised list whose entries are counted, and the header figure is derived from that count rather than asserted beside it.** *Amended after task 8; this is the third strike.* The existing rule — never write a count you cannot recompute — was not enough, because the authors of tasks 6 and 8 both believed they had complied and both shipped a header nobody could rebuild from the list underneath. So the rule is now mechanical rather than aspirational: **one row per mutation, contiguously numbered with no gaps; an entry that appears in two sections marked `[RE-LISTED]` in the one that does not count it; every section stating "N rows"; and the header showing its arithmetic** (`35 + 5 + 3 = 43`, `40 rows less 5 re-listed = 35`). A reviewer must be able to check the header by counting, without reading a single verdict. **A re-run row names itself** — "six came back BUILD-FAIL and were re-run" is not traceable unless the six are named.
- **Adding a property to `TlsQuicConnectionSpec` owes a guard witness and a `grep -rn "spec\.<Property>" src/`.** *Amended after task 8; second occurrence.* If nothing reads it, the doc-comment must say so and name the task that will wire it — see the task-4b amendment on present-but-inert knobs. The rule is now stated at the top of `TlsQuicConnectionSpec.cs` as well as here, because the plan is not what the author of the next knob has open.
- **This branch carries foreign commits.** `1a66f05` (IterioDev, TLS 1.2 extended-master-secret), plus `8f5b2c9` and `7bcb36e` (a captured iOS Spotify ClientHello). None is QUIC work; they landed because the branch is shared. **Do not rebase them out without asking** — if that session has them checked out, rewriting history breaks it.

---

## Task 0: Extract the RFC sections A4 needs — **COMPLETE, `1d142ef`**

**Files:** eight files under `docs/superpowers/specs/reference-captures/`, listed in *The sections task 0 added* above.

RFC 9000 §7.2–7.3, §8.1, §10.1–10.2, §13.1–13.2, §14 (incl. §14.1); RFC 9001 §4; RFC 9369 §3 and §5.

Method as established: fetch from `rfc-editor.org` inside the sandbox (`curl`/`wget`/`WebFetch` are blocked by this repo's `CLAUDE.md`), locate the heading in the document *body* past the table of contents, `sed` the range, prepend a provenance header, and **diff the committed body line by line against the fetched range**, trimming only trailing whitespace.

RFC 9369 is extraction only. QUIC v2 is not implemented in this phase; the extract exists so `TlsQuicSecrets.cs:100,109,144,150-152,235` and `TlsQuicProtocol.cs:10-11` become checkable, which is the A2 audit's one open finding.

**Done when** every extract diffs at zero mismatches against the published RFC and each carries its provenance header. *(Verified: 8 files, independent re-fetch and line diff, 0 mismatches. `HANDOFF-http3-quic.md` §3's "still absent" list was in an earlier draft of this criterion; that file is outside this task's write scope and the coordinator owns it.)*

## Task 1: The two seams — the layout spec and the clock

**Files:** create `TlsQuicConnectionSpec.cs`, `TlsQuicConnectionOptions.cs`, and tests.

No behaviour. Two declarations, bundled because neither has behaviour to attribute a failure to — a mistake in either is a compile error or a defaulting error, not a protocol failure.

`TlsQuicConnectionSpec` carries, at minimum: `SourceConnectionIdLength`, `DestinationConnectionIdLength`, `InitialPacketNumber`, `PacketNumberEncodedLength`, `Token`, the per-datagram Initial flight plan, the CRYPTO split plan, frame order within each packet, `PaddingTarget`, and (Finding 5) the varint width overrides for the header `Length` field and CRYPTO `Offset`/`Length`. Defaults are Chromium-shaped where a client capture states them: source CID length **0**, destination CID length **8**.

**One field has a normative floor, and it is the one that looks most like a free choice.** RFC 9000 §7.2, verbatim: *"the client populates the Destination Connection ID field with an unpredictable value. This Destination Connection ID MUST be at least 8 bytes in length."* So `DestinationConnectionIdLength` is a subsystem B knob **bounded below at 8** — and that client's value of 8 sits exactly on the floor, which is why the constraint is invisible until someone tries 4. Validate it here, document the floor as normative with the citation, and give it a witness. Note the asymmetry: `SourceConnectionIdLength` has no such floor and 0 is legal, which is what Chromium uses.

Two capture facts must also be written into this file as comments, because both are traps that look like ordinary configuration:

- **`max_udp_payload_size` (1472) is an advertised transport parameter and is *not* `PaddingTarget`, and is *not* the transport's real ceiling.** The capture is explicit: "Advertised parameter and actual ceiling are separate concerns and must not be wired together." Subsystem D reports a ceiling of 65527 − 10; Chromium advertises a path-derived 1472; §14.1 sets the Initial padding floor at 1200. Three different numbers, three different meanings, and nothing in this codebase should derive any of them from another.
- **`initial_rtt` (12583) is randomised per connection** (Finding 1). It is not a spec constant — it is a per-connection draw, and pinning it is itself a fingerprint. The spec holds the *policy* (randomise, and within what range), not the value.

`TlsQuicConnectionOptions` takes the transport, the remote endpoint, the spec, a `TimeProvider`, an idle timeout and a handshake deadline. **`TimeProvider` is the clock seam** — it is .NET's own type, it needs no package, and it is already this repo's house style (`Dns/TlsEchDnsResolver.cs:36,50,58`, `Sessions/Tls12SessionCache.cs:15,27,34`, three more). Follow the established pattern exactly: public/default constructor uses `TimeProvider.System`, an internal overload takes one. A test double is a ~10-line subclass; do **not** add `Microsoft.Extensions.TimeProvider.Testing`.

**Done when** the spec expresses every field in the table above; validation rejects out-of-range values with the reachability witness per field required by the standing rules; the connection options default to `TimeProvider.System` and accept an injected one; and a grep of the task's own diff finds no numeric layout literal outside the defaults block.

## Task 2: `QuicVariableLengthInteger.TryRead` and its call sites

**Files:** `QuicVariableLengthInteger.cs`, and its callers in `TlsQuicConnectionFrames.cs`, `TlsQuicAckFrames.cs`, `TlsQuicFlowControlFrames.cs`, `TlsQuicStreamFrames.cs`, `TlsQuicPacketHeader.cs`, `TlsQuicTransportParameters.cs`, `TlsQuicFrames.cs`, and tests.

Seven files. **Do not trust a call-site count from this plan** — an earlier draft carried "34", while `grep -rn "QuicVariableLengthInteger\.Read" src/` returns 47 matching lines including doc comments and `ReadExact`. Run the grep, enumerate what it finds, and report the number you actually migrated against the number the grep returns, with the difference explained. A count in a plan rots; the grep does not.

Behaviour-preserving. Add `TryRead`, migrate every caller off the throwing `Read` on parse paths, delete the `try`/`catch` wrappers that exist only to convert the throw.

Handoff §8 item 5: today **every malformed frame allocates a `TlsQuicTransportException` plus its message**, and a peer sending a flood of malformed frames gets a flood of allocations. The exposure does not exist yet because nothing reads from a socket — task 6 creates it. This lands first so it is never true in a shipped state.

Per A2 task 3a's rule: **every removed test must have lost its subject, not its coverage** — say which, for each.

**Done when** no parse path calls the throwing `Read`; the existing suite is green with no behaviour change; and a new allocation test asserts **0 bytes allocated on the *rejecting* path** of `TryReadFrame` over a malformed payload, alongside the existing accepting-path test from A2 task 7.

## Task 3: The in-memory and scripted datagram transports

**Files:** create `tests/SharpTls.Tests/Quic/InMemoryDatagramTransport.cs` and `ScriptedDatagramTransport.cs`, and tests for both.

Two `ITlsQuicDatagramTransport` implementations — the first ones in the repo. Neither touches a socket.

`InMemoryDatagramTransport`: a paired channel, so two connection objects can be wired together. `ScriptedDatagramTransport`: records everything sent, and returns a scripted sequence of received datagrams, driven by the injected `TimeProvider` so a "delay" advances fake time rather than real time.

Honour the interface's documented contract: one concurrent send and one concurrent receive, no internal locking, `SendAsync` throws `ArgumentOutOfRangeException` above `MaxDatagramPayloadSize`, and disposal **faults** a pending call rather than completing it.

**The doubles are themselves code and fail the same ways** — A2 task 6 lost a round trip to a broken verification script, and task 7 found two mutations in a reachability harness that survived the full gate. So: test the doubles. A scripted script that runs out must be distinguishable from one that returns empty; a recorded send must be byte-compared, not length-compared.

**Done when** both types pass the interface contract tests that `TlsQuicDatagramTransportTests.cs` already applies to the socket implementations, and the scripted one advances only fake time — asserted by a test whose wall-clock duration is unbounded but whose fake clock advances a known amount.

## Task 4a: `WriteLongHeader` returns the packet-number offset

**Files:** `TlsQuicPacketHeader.cs`, and tests.

Behaviour-preserving signature change, split out of the original task 4 for exactly the reason task 12 is scheduled late: **a signature change to A1 bundled with new connection-layer code makes a failure unattributable between them.** That argument is used to defer the crypto hoist; it applies verbatim here, and this is the riskiest step in the plan.

`WriteLongHeader` emits header bytes and returns the count. Header protection needs the packet-number offset within those bytes, and `TryApply` has no way to learn it. Add an `out int packetNumberOffset`.

Do **not** recompute the offset in the builder instead: a second computation of the same layout in our own code is a second transcription with no independent source — the hazard of two transcriptions without the benefit of two independent readings.

**Done when** every existing A1 test is green with no behaviour change, and one new test pins the returned offset against RFC 9001 A.2's unprotected header (`c000000001088394c8f03e5157080000449e` + a 4-byte packet number), where the offset is independently derivable from the published field layout rather than from our own arithmetic.

## Task 4b: Packet assembly, anchored on RFC 9001 A.2 and A.3

**Files:** create `TlsQuicPacketBuilder.cs`, and tests.

RFC 9001 §5.3 (AEAD), §5.4 (header protection), §5.4.2 (sample offset); RFC 9000 §17.2 (long header), Appendix A.2 (packet number encoding).

Build one protected long-header packet from a header spec and an **ordered** frame list: pick the packet number, `EncodedLength`/`Truncate` it, compute the `Length` varint (pn length + payload + 16-byte tag, at the width the spec requests), `WriteLongHeader`, `Seal` with the written header slice as AAD, then `TryApply` at the offset task 4a returns.

Gate every frame through `TlsQuicFrameLegality.Permits(in frame, level)` before writing it.

Emit a `TlsQuicSentPacket { Level, PacketNumber, Size, IsAckEliciting, IsInFlight, SentAt }` per packet. A4-minimal discards it; it is A3's insertion point (*Where A3's absence is load-bearing*, item 1).

**Attempt the A.2 byte match first, before writing the builder's general form.** If it cannot be reached, stop and report — leg 1 is the phase's only external ground truth and every later task's evidence rests on it.

**Done when:**

- Given A.2's destination connection ID `0x8394c8f03e515708`, packet number 2 at encoded length 4, A.2's CRYPTO frame bytes and PADDING to a 1162-byte payload, the builder emits **A.2's exact protected bytes**. Note that **A.2's PADDING bytes are not published** — the extract says "plus enough PADDING frames to make a 1162-byte payload" — so the plaintext is reconstructed and validated *through* the protected output. Say so in the test; do not describe the plaintext as published.
- A.3's server Initial reproduces on the server keys.
- **Per Finding 5 and *What leg 1 does and does not anchor*: one hand-derived expected-bytes test per knob at a non-default value** — a non-zero token with a distinctive prefix, packet-number encoded lengths 1 and 3, and a non-minimal `Length` varint. A.2 exercises none of these; without them the spec struct's knobs are untested and subsystem B inherits an unproven parameterisation.
- A mutation sweep on the AAD slice bounds, the `Length` computation and the packet-number offset, with the killing test named per A2's rules. **A mutation that leaves the byte-exact A.2 comparison passing is a finding about the vector's coverage, not a pass** — record which of the three categories it falls into.

## Task 5: Datagram assembly — coalescing, padding, and the multi-datagram Initial flight

**Files:** create `TlsQuicDatagramBuilder.cs`, and tests.

RFC 9000 §12.2 (coalescing; Retry has no Length field and cannot be followed in the same datagram), §14.1 (the 1200-byte minimum), §8.1 (why item 4 below matters).

Split deliberately from task 4b for attributability: 4b's failure is "wrong bytes in one packet", task 5's is "wrong split across datagrams". Bundled, an A.2 mismatch cannot be attributed between them, and A2's task 3/3a split exists because that exact bundling cost a round trip.

- Coalesce multiple packets into one datagram per §12.2, in the order the flight plan gives. Retry has no Length field and cannot be followed in the same datagram.
- Pad to `Spec.PaddingTarget` with PADDING frames inside the last packet's payload — not with trailing zero bytes outside a packet.
- Plan a CRYPTO flight across N datagrams from the spec's split plan. **A multi-datagram Initial is mandatory:** the X25519MLKEM768 key share is 1216 bytes and Chromium's Initial spans two datagrams because of it. A design where one Initial is one datagram is wrong.
- **Pad every UDP datagram carrying an Initial packet, not just the first — because RFC 9000 §14.1 requires it.** Verbatim from `rfc9000-section14-datagram-size-and-pmtu.txt`: *"A client MUST expand the payload of all UDP datagrams carrying Initial packets to at least the smallest allowed maximum datagram size of 1200 bytes by adding PADDING frames to the Initial packet or by coalescing the Initial packet; see Section 12.2."* **All** UDP datagrams — per datagram, not per flight. Cite that; do not paraphrase this line. Amplification (§8.1) is secondary colour, and an earlier draft justified the rule with an arithmetic error — see *Where A3's absence is load-bearing*, item 4. **Do not quote that arithmetic into a source comment.** "Chromium does it too" is a behavioural observation, not a justification, and this project verifies against the RFC rather than against behaviour.
- §14.1 names **two** legal ways to reach the floor — PADDING frames, or coalescing (and *"Initial packets can even be coalesced with invalid packets, which a receiver will discard"*). That is another layout choice a real client makes and therefore another candidate fingerprint bit. Chromium pads with PADDING frames; implement that, and note the alternative in the spec's documentation without building it.

**Done when** a spec producing a 1216-byte key share yields exactly the datagram count and the per-datagram byte counts its flight plan declares; every Initial-carrying datagram reaches the §14.1 floor, asserted per datagram rather than for the flight; frame order within each packet matches the plan with no merging; **hand-derived expected bytes for a real multi-frame CRYPTO split at non-default offsets** (declared counts are not enough — a count assertion passes against a builder that splits at the wrong boundaries); and A.2's single-datagram case still reproduces byte-exactly through the datagram builder, not only through the packet builder.

## Task 6: The receive pipeline

**Files:** create `TlsQuicPacketReceiver.cs`, and tests.

RFC 9000 §12.2, §17.2, Appendix A.3 (packet number decoding); RFC 9001 §5.3, §5.4.

Datagram → `TlsQuicDatagramReader.Read` → per packet: remove header protection, decode the truncated packet number against the largest received **in that number space**, open the AEAD, then `TryReadFrame` in a loop until the payload is consumed, dispatching each frame.

**Long *and* short headers.** Per Finding 8, HANDSHAKE_DONE arrives in a 1-RTT packet, so this pipeline must read short headers via `TryReadShortHeader` and the connection must install 1-RTT *read* keys as soon as the TLS engine emits them — otherwise task 9a-ii has no trigger for `ConfirmHandshake` and task 14's streams have no receive path. An earlier draft of this task was long-header only, which made task 9a's done-condition unsatisfiable. Key update is out of scope, so a short header whose key phase bit differs from the installed phase closes the connection — **after the AEAD has authenticated the packet, never before.** RFC 9001 §5.5: *"Similarly, a packet that appears to trigger a key update but cannot be unprotected successfully MUST be discarded."* The bit is readable as soon as header protection is removed, and closing there closes on precisely the packet §5.5 says to discard; §5.4's `quic hp` key authenticates nothing, so that ordering hands an off-path attacker a one-datagram connection kill. Every check that can close — reserved bits and key phase alike — runs after `TryOpen` succeeds.

**Record the `IPEndPoint`-per-datagram decision here** (Finding 7). One comment at the receive site: the scoping assigns this decision to subsystem A, this loop is where it comes due, and A4-minimal **defers it** — a handshake is ten datagrams, and reshaping `ITlsQuicDatagramTransport.ReceiveAsync` around a reusable `SocketAddress` would land on four implementations before there is anything to measure. The next reader must find the decision, not the silence.

Three contracts this task must honour and pin, all from Finding 3:

- `TlsQuicDatagramReader.Read` is a **lazy iterator**. Enumerate it synchronously, inside the pass. Never store the `IEnumerable` across an `await`.
- Parsed frames alias the receive buffer. Anything outliving the pass is **copied**. Allocate a fresh buffer per datagram; do not pool.
- Nothing here may throw for any input. Frames and headers are attacker-controlled and this is the loop that reads them.

Handle, without throwing: an unknown version, a Version Negotiation packet, a Retry packet, a packet that fails AEAD (discard silently per §12.2 — a failed decrypt is not an error), a truncated datagram, and a datagram whose trailing bytes are not a packet.

**Done when** RFC 9001 A.3's server Initial datagram decrypts and its CRYPTO frame reaches `TlsQuicCryptoStreamReassembler` with the correct offset and length; a short-header 1-RTT packet carrying HANDSHAKE_DONE is read and dispatched, and an unexpected key phase closes rather than being ignored; each of the six malformed cases above is handled without a throw, with a mutation witness per case; and a test asserts the buffer-lifetime rule by mutating the receive buffer after the pass and confirming nothing retained aliases it.

## Task 7: The loopback peer

**Files:** create `tests/SharpTls.Tests/Quic/LoopbackQuicPeer.cs`, and tests.

Wrap `CustomTlsQuicServer` in the packet layer built by tasks 4–6, over `InMemoryDatagramTransport`, so a full client↔server handshake runs in-process with no socket and no clock.

**No client↔server loopback test exists today.** `CustomTlsQuicClientTests.cs` hand-builds server messages; `CustomTlsQuicServerTests.cs` never constructs a client. Note the server's asymmetric surface: no `StartHandshake` (it is reactive), no `NotifyHandshakePacketSent`/`ConfirmHandshake` (client-only), plus `IssueSessionTicketAsync`.

Building this is mostly wiring **if and only if** tasks 4b–6 are role-neutral — packet protection is directional but symmetric, and the builder takes keys, not a role. Make that explicit in tasks 4b and 6 so this task does not become a second implementation.

**This task has a cheap fallback.** Leg 3 (MsQuic, task 10) already answers "does an independent implementation accept us", and answers it better, because a loopback against ourselves shares our bugs. If this task exceeds a day, cut it and note the cut — it is the only task here with that property.

**Done when** a client and a server complete a handshake over `InMemoryDatagramTransport` with `IsHandshakeComplete` true on both, and the test's report states explicitly which of its assertions would survive a bug shared by both halves (the honest answer is: the ones about *sequencing*, not the ones about *bytes* — those are leg 1's).

## Task 8: ACK generation

**Files:** create `TlsQuicAckTracker.cs`, and tests.

RFC 9000 §13.1 (packet processing), §13.2 (generating acknowledgements, ack delay, limiting ranges), §19.3 (the frame). **Extracted in `1d142ef`.**

Finding 2: the scoping listed this as A2 item 11, the A2 plan omitted it, and A2 shipped without it. A4 owns it now. It is not optional — a server that never sees an ACK re-arms its PTO and, under §8.1, may stop sending altogether.

Track received packet numbers per number space; build the descending gap-and-length range chain `TlsQuicAckFrames.WriteAckFrame` consumes; detect ack-eliciting packets per §13.1; encode `ack_delay` with the exponent from the peer's transport parameters.

**A simplification §13.2.1 hands this task: ACKs for Initial and Handshake packets MUST be sent immediately, with no `max_ack_delay`** — the delay budget applies only to 1-RTT. A4-minimal never sends 1-RTT application data, so **no delayed-ACK timer is needed on the happy path.** Build the immediate path and say in the source why the timer is absent, so a later implementer does not add one speculatively or assume it was forgotten.

Also add `ProcessAckFrame(in TlsQuicFrame, DateTimeOffset receivedAt)`, which in minimal only advances largest-acked (task 4b needs it for packet-number encoding) and validates the ranges. It is A3's insertion point for RTT sampling and loss detection (*Where A3's absence is load-bearing*, item 2).

**Done when** hand-derived ACK frames match for a contiguous receive set, a scattered one, and one with a gap at the low end; an ACK is not generated for a packet set containing only non-ack-eliciting frames; `ack_delay` round-trips through a non-default `ack_delay_exponent`; and a mutation on the gap-versus-length subtraction direction is killed by a named test — this is the arithmetic that acknowledges packets that were never sent.

## Task 9a-i: Key ownership, install and discard ordering

**Files:** create `TlsQuicKeySet.cs`, and tests.

RFC 9001 §4.1.1 (encryption levels), §4.9/§4.9.1/§4.9.2 (discarding keys). **Extracted in `1d142ef`.**

Split out of task 9a because bundled it puts six independently-failing things behind one symptom — "the handshake does not complete" — which is the least attributable symptom in this plan. This half needs **no handshake at all**: it is driven from synthetic `TlsQuicProcessResult` event sequences and `ScriptedDatagramTransport`.

`TlsQuicKeySet` owns keys per encryption level and direction: install from `TlsQuicTrafficSecretEvent` (via `DerivePacketProtectionKeys`), install Initial keys from `TlsQuicInitialSecrets.Derive`, discard on `TlsQuicDiscardKeysEvent`, and refuse use of a discarded or uninstalled level.

The trap: **`TlsQuicProcessResult.Dispose()` zeroes unconsumed secrets** (`TlsQuicEvents.cs:137-148`). Install before disposing.

**Done when** an event sequence installs each level in order; a discarded level is unusable with a named witness; installing after disposal yields zeros, pinned by a test that reads a secret after disposal; and Initial keys re-derive correctly when the destination connection ID changes (the Retry path task 9b needs).

## Task 9a-ii: The connection loop — to handshake complete and confirmed

**Files:** create `TlsQuicConnection.cs`; extend `TlsQuicConnectionOptions.cs`; and tests.

RFC 9001 §4.1 (the handshake interface), §4.1.2 (**complete versus confirmed**); RFC 9000 §7.2 (connection ID negotiation). **Extracted in `1d142ef`.**

One loop, one thread of control (Finding 6). Per iteration: drain `TlsQuicProcessResult.Events` in order, hand secrets to the task 9a-i key set **before disposing the result**, map each `TlsQuicCryptoDataEvent` to CRYPTO frames per the spec's split plan, assemble and send, then receive and feed `ProcessCryptoDataAsync`.

Specifics that will bite:

- The server's Source Connection ID on its first packet **becomes our Destination Connection ID** (§7.2). Get this wrong and the handshake fails with no useful error.
- **Complete is not confirmed** (Finding 8). RFC 9001 §4.1.2, verbatim: *"At the client, the handshake is considered confirmed when a HANDSHAKE_DONE frame is received."* (§4.1.2 also allows a client to *MAY* confirm on an acknowledgment for a 1-RTT packet — not implemented in minimal; say so rather than omitting it.) `IsHandshakeComplete` means TLS finished; `ConfirmHandshake()` is documented as *"Marks receipt of QUIC HANDSHAKE_DONE"* and **throws if TLS is not yet complete**. So: call `NotifyHandshakePacketSent` when the first Handshake packet goes out (it emits `TlsQuicDiscardKeysEvent(Initial)`), and call `ConfirmHandshake` **only on receipt of a HANDSHAKE_DONE frame** from task 6's 1-RTT path. Discarding Handshake keys on TLS-complete instead would drop keys the server may still be using. Both calls are idempotent afterwards.
- Per Finding 1, **build a fresh `ClientHelloProfile` per connection, unconditionally** — `initial_rtt` is randomised per connection and lives in the immutable profile, so this is required for the actual target regardless of source CID length.
- A **handshake deadline** on the injected `TimeProvider` fails the attempt cleanly. It is a timeout, not a retransmission — say so in the source, at the deadline.

**Done when** the client reaches handshake complete against the task 7 peer and then confirmed on a received HANDSHAKE_DONE; Initial keys are discarded when the first Handshake packet is sent and Handshake keys only on HANDSHAKE_DONE, each with a named witness; two consecutive connections produce two different `initial_rtt` values; and the handshake deadline fires deterministically on a fake clock with **zero wall-clock time elapsed**.

## Task 9b: Retry, Version Negotiation, and close

**Files:** `TlsQuicConnection.cs`, and tests.

RFC 9000 §17.2.5 and RFC 9001 §5.8 (Retry), RFC 9000 §17.2.1 (Version Negotiation), **§7.3 (authenticating connection IDs)**, §10.1 (idle timeout), §10.2 (immediate close).

Split from 9a because these are unreachable until the happy path works, and because a 9a failure means "the handshake does not complete" while a 9b failure means "an unusual server response is mishandled" — different symptoms, different fixes.

- **Retry:** verify the integrity tag with `TlsQuicRetry.TryVerify`, adopt the new destination connection ID and token, **re-derive Initial keys from the new DCID** (task 9a-i's path), and retain the *original* DCID. A second Retry must be ignored, not honoured.
- **§7.3 connection ID authentication — assigned here, not dropped.** §7.3 requires **both endpoints MUST validate** the server's `original_destination_connection_id` against the DCID we actually sent, its `initial_source_connection_id` against the CID it is using, and `retry_source_connection_id` when a Retry occurred — a mismatch being `TRANSPORT_PARAMETER_ERROR` or `PROTOCOL_VIOLATION`. An earlier draft consumed only the Retry half of §7.3. A cooperative server always passes, which is exactly why this gets silently skipped — and it is the check that stops an off-path attacker substituting connection IDs. It is a handful of comparisons against values we already hold. Build it, with a witness per parameter, driven from `ScriptedDatagramTransport` with a deliberately mismatched value.
- **Version Negotiation:** per §17.2.1, and per the rule at `TlsQuicVersionNegotiation.cs:8-13` that a VN packet MUST be ignored once a packet has been successfully processed. Minimal does not negotiate to v2 — it reports and fails.
- **Close:** send CONNECTION_CLOSE with a §20.1 code; enter a draining period only as far as "stop sending, stop delivering"; idle timeout on the injected `TimeProvider` per §10.1.
- **PATH_CHALLENGE:** respond with PATH_RESPONSE. The frame codec exists; it is three lines, and it is cheaper than reasoning about what a server does when we ignore one. This is *not* path validation (out of scope) — it is answering a question.

**Done when** each of the five is driven from `ScriptedDatagramTransport` with hand-built Initial-level bytes; a Retry with a corrupt integrity tag is ignored; a second Retry is ignored; a VN packet after a successfully processed packet is ignored; each §7.3 mismatch closes the connection with the right §20.1 code, one witness per parameter; and idle timeout fires on fake time with a named witness.


**Carried in from task 1 — do not re-run §7.2's 8-byte floor on the adopted CID.** §7.2 binds "a
client that has not previously received an Initial or Retry packet from the server". After a Retry
the Destination Connection ID is the server's Source Connection ID and is **no longer self-chosen**,
so the floor stops applying. Re-running that guard here would reject legal server behaviour.

## Task 10: The MsQuic loopback gate

**Files:** create `tests/SharpTls.Tests/Interop/MsQuicLoopbackTests.cs`.

`System.Net.Quic.QuicListener` on loopback. Verified available on this machine: `QuicListener.IsSupported = True` on .NET 9.0.17.

Three setup requirements that will each cost an hour if discovered mid-task:

- **A server certificate with a usable private key.** `QuicServerConnectionOptions.ServerAuthenticationOptions.ServerCertificate` needs the private key attached — generate with `CertificateRequest` and `CreateSelfSigned`, and on Windows re-import via `X509CertificateLoader` with `Exportable | EphemeralKeySet` if the key handle is not usable directly.
- **Explicit ALPN on both sides.** `QuicServerConnectionOptions.ServerAuthenticationOptions.ApplicationProtocols` must list `h3`, and our client's profile must offer it. MsQuic fails the handshake on ALPN mismatch rather than negotiating nothing.
- **Our client must accept the self-signed certificate**, via the existing validation-skip option, and that option must not leak into any non-test path.

This is the first evidence from an implementation we did not write, and it is offline and repeatable, so it belongs in the gate — **gated on `QuicListener.IsSupported`, skipping and never failing when false.**

**Done when** a full handshake completes against `QuicListener`; the test skips cleanly with an explanatory message when unsupported; and the report states both limits — that MsQuic will not produce Retry or Version Negotiation on demand (which is why task 9b uses the scripted transport), and that **a green run is evidence of conformance, not of fingerprint fidelity**, because MsQuic accepts many layouts that are nothing like Chromium's.

## Task 11: The fingerprint readout

**Files:** create `TlsQuicFingerprintReadout.cs`, and tests.

Extract, from the datagrams **we emitted**, the fields subsystem B needs: source and destination connection ID lengths; initial packet number and its encoded length; token length and prefix; the per-datagram Initial flight plan; the CRYPTO frame splits and the frame order within each Initial packet; the datagram padding target; and (Finding 5) the varint widths actually used for the header `Length` field and CRYPTO `Offset`/`Length`.

**This is the phase's payoff, and it needs no network at all.** Every one of those fields is something *we* emit, so all of them are observable from a recording transport. Only "does a real server accept it" needs the network. That is why this task sits before the live run and not after it.

Emit it as a diffable text block matching the shape of `the preset that measured it`'s QUIC section, and check in the readout produced against the task 10 loopback as a snapshot — **labelled a snapshot**, per A2's rule about numbers with no external source.

**Done when** the readout is produced from recorded datagrams alone; it reports every field above; the snapshot is checked in and asserted; and the report contains a **hand-written comparison against a client capture**, naming for each field: match, mismatch, or not-yet-known-from-the-capture. The last category is the useful output — it tells subsystem B what still needs a packet capture.


**Carried in from task 1 — report the missing `initial_rtt` as a known deviation.** The spec's
`InitialRttRange` is `null`, because a client capture contains exactly one draw and nothing in the
repo bounds Chromium's range. So this connection sends **no** `initial_rtt` transport parameter at
all. That is a real difference from the target and **must appear in the readout as a named deviation**
— not omitted, and not silently passed. If it is ever bounded (by capturing enough connections, or
by reading uQUIC's `ChromeRandomInitialRTT()`), this line changes.

**Carried in from task 9a-ii's fix round — four more things this readout owes.**

1. **A KNOWINGLY VIOLATED MUST, reported as one.** A4-minimal never acknowledges a 1-RTT packet,
   including the one carrying HANDSHAKE_DONE, and RFC 9000 §13.2.1's MUST covers 1-RTT explicitly
   — see the amendment above for the whole sentence past its line wrap, and for why §13.2.1's
   exception does not apply. This is not a soft deviation and must not be reported as one.
2. **Two new layout fields**, both fingerprint dimensions and both now knobs rather than
   literals: the **coalescing order** of packets within one datagram
   (`TlsQuicConnectionSpec.CoalesceAscendingByLevel`) and the **ACK's position** inside a packet
   (`AckLeadsInPacket`). Both are readable from recorded datagrams only by decrypting them, so the
   readout takes them from the spec the connection was built with, and **says that is where they
   came from**. Neither has ground truth in a client capture: both belong in the
   not-yet-known-from-the-capture column.
3. **`AckDelayExponent` is still not observable**, for the reason the amendment gives — the loop
   reads the clock once per pump, so every `ack_delay` is structurally zero. Report it as *wired
   and validated but not observable*, which is the weaker of the two claims, and note that the
   connection now **fails loudly** if the scaled and advertised values disagree.
4. **`initial_source_connection_id` freshness is unobservable at the target's own zero-length
   source CID**, which is why the tests advertise a five-byte one. Say so rather than claiming a
   witness the target's shape erases.

## Task 12: Hoist the per-packet cipher instances

**Files:** `TlsQuicHeaderProtection.cs`, `TlsQuicPacketProtection.cs`, `TlsQuicKeySet.cs`, and tests.

Handoff §8 items (a), (b), (c), and the scoping's "Deferred from A1 into A4" list. Confirmed: `TlsQuicHeaderProtection.cs:172` `Aes.Create()` plus `:173` `headerProtectionKey.ToArray()` per packet; `:140` `out byte[] mask` with `new byte[5]` at `:186` and in `ChaCha20Mask`; `TlsQuicPacketProtection.cs:91,97,150,156` constructing `AesGcm`/`ChaCha20Poly1305` per packet.

Behaviour-preserving. `TlsQuicKeySet` owns a keyed `Aes` and a keyed AEAD per encryption level and direction, for a key RFC 9001 §5.4 keeps stable for the epoch; `TryComputeMask` takes a caller-supplied `Span<byte>`.

Scheduled *after* the first successful handshake deliberately — see *The four deferred allocation fixes* for why putting a crypto signature change on the critical path costs attributability.

**Do the three together.** They live in two files and fixing one while missing the others is the named likely failure — A4 would hoist one keyed cipher and leave the other allocating per packet.

**Done when** RFC 9001 A.1, A.2, A.3 and A.5 all still reproduce byte-exactly; `Aes.Create()`, `new AesGcm` and `new ChaCha20Poly1305` appear zero times on the per-packet path (grep in the report); an allocation test pins seal-plus-open at 0 bytes per packet; the task 10 loopback handshake still completes; and **the report does not claim an allocation-free send path** — Finding 4 says the frame writer's `List<byte>` is still there, and (d) is A3's.

## Task 13: The live run

**Files:** create `tests/SharpTls.Tests/Interop/QuicPublicEndpointInteropTests.cs`.

Gated on `SHARPTLS_RUN_INTEROP=1`, following `PublicServerInteropTests.cs:579`. Never in the gate.

Complete a handshake against a live server and produce the task 11 readout from it. `fp.impersonate.pro/api/http3` cannot be satisfied yet — it refuses to answer unless h3 was genuinely negotiated, which needs subsystem C — so this task's target is a handshake and a readout, not a fingerprint response.

**Expect loss to kill attempts.** With A3 deferred there is no retransmission; a single lost packet ends that attempt. Retry at the process level and record the failure rate — it is A3's first piece of evidence.

**Carried in from task 9a-ii's fix round — two things this run owes.**

1. **A stray datagram must no longer end an attempt, and this is the run that proves it on the
   real internet.** Before the fix round, a single undecryptable packet — a replayed datagram, a
   scan, an old connection's stray — threw and killed the connection; it would have hit that on
   the first one. The loop now counts discards and carries on (RFC 9000 §12.2). **Record
   `DiscardedPackets` and `DiscardedForMissingKeys` per attempt**: they are the first real-world
   evidence of how much unrelated traffic a live socket meets, and a non-zero
   `DiscardedForMissingKeys` is the coalescing stall rather than noise.
2. **The unacknowledged HANDSHAKE_DONE is observable here and nowhere else.** A real server
   retransmits it until it gives up, because A4-minimal cannot acknowledge a 1-RTT packet. Record
   how many retransmissions arrive and whether the server eventually closes — that is the cost of
   the knowingly violated MUST, measured rather than predicted, and it is what tells task 14 how
   urgent it is.

**Done when** a handshake completes against at least one live endpoint, the readout is captured and compared against a client capture, and the report records how many attempts it took.

## Task 14: Minimal streams for subsystem C

**Files:** create `TlsQuicStreams.cs`, and tests.

RFC 9000 §19.8 (STREAM — codec already exists), §2.1 (stream IDs and types), §4.1 (data flow, for the static-budget rule below).

**After the first readout.** Nothing in A4-minimal's success condition needs a stream; subsystem C does, and blocking C on a full stream implementation is what turns "minimal" into "complete".

Minimal means: open a unidirectional stream (C's control stream) and one bidirectional stream; send and receive STREAM frames with offsets; handle FIN. Flow control is a **static budget** taken from the peer's advertised initial limits — no `MAX_DATA`/`MAX_STREAM_DATA` updates sent, no `STREAM_DATA_BLOCKED` handling, no stream state machine beyond open/data/fin. Enough for one GET.

**Done when** a stream carries bytes both ways over the task 7 peer and the task 10 loopback, offsets and FIN round-trip, and the static budget is respected — with a named test for the case where the budget is exhausted, which must fail cleanly rather than silently violate the peer's limit.

**NAMED DEFERRAL TASK 14 INHERITS: `CustomTlsQuicServer` does not send §7.3's two mandatory connection ID parameters, and this library's own client now rejects it for that.** *Recorded by task 9b's fix round, which found it and decided not to fix it.* Task 9b made the CLIENT strict — §7.3's *"An endpoint MUST treat the absence of the initial_source_connection_id transport parameter from either endpoint or the absence of the original_destination_connection_id transport parameter from the server as a connection error of type TRANSPORT_PARAMETER_ERROR."* — and commit `7ccfbd2` touched `TlsQuicConnection.cs` and two test files only. So the conforming server is `LoopbackQuicPeer`'s test helper, and the **public** `CustomTlsQuicServer` still sends `_configuration.TransportParameters` verbatim (`:490`, `:873`) and adds nothing.

- **Why it was not fixed.** `original_destination_connection_id` is the Destination Connection ID off the client's first Initial packet — a runtime, per-connection value living in the packet layer that this type's own summary already assigns to the caller. A static configuration structurally cannot carry it. The real fix is a **server-side QUIC connection driver** that owns the connection IDs and merges them in; A4 builds no such thing, A4 is a client, and inventing one inside a fix round is not a fix round.
- **What WAS done.** The gap is now stated on the public type itself, in `CustomTlsQuicServer`'s `<remarks>`: the two parameters, the §7.3 sentence that makes them mandatory, why this type cannot supply them, and `LoopbackQuicPeer`'s helper as the worked example. **The defect that actually bites is "with nothing telling them to"** — a caller who reads the type now knows. No signature changed.
- **Why nothing downstream will find it.** Task 10's MsQuic gate and task 13's live run both talk to FOREIGN servers. Neither ever constructs a `CustomTlsQuicServer`, so neither can notice. **Task 14 is A4's last task and therefore A4's last chance not to exit with a public server type its own client refuses.** Task 14 either supplies the driver or restates the deferral against a named successor phase — what it must not do is let it go quiet again.

---

## Ordering constraint

**Before a handshake can be attempted at all:** tasks 0 → 1 → 2 → 3 → 4a → 4b → 5 → 6 → 8 → 9a-i → 9a-ii, with 7 anywhere after 6.

That order is not arbitrary. Task 0 unblocks 5, 9a-i and 9a-ii. Task 1's spec is read by 4b, 5 and 11. Task 2 must precede 6 because 6 creates the exposure it closes. 4a must precede 4b, and 4b must precede 5, both for attributability. Task 6 must build the short-header path before 9a-ii, because HANDSHAKE_DONE is what triggers `ConfirmHandshake` (Finding 8). Task 8 must precede 9a-ii because a handshake whose ACKs never arrive leaves the server's flight in flight.

**After the first successful handshake:** 9b, 10, 11, 12, 13, 14. Task 11 is the payoff and needs no network. Task 12 is deliberately here rather than earlier. Task 14 exists to unblock subsystem C.

**The single riskiest ordering assumption:** that task 4b's A.2 byte-exact match is achievable. If it is not — if some field in `WriteLongHeader` or `Seal` cannot be driven to A.2's exact bytes — then leg 1 collapses and the phase loses its only external ground truth. **Attempt the A.2 byte match as the very first thing in task 4b, before writing the builder's general form.** If it fails, stop and report; every later task's evidence depends on it.

## Done when

- RFC 9001 A.2's client Initial datagram and A.3's server Initial reproduce byte-exactly through the datagram builder.
- **Every spec knob has a hand-derived expected-bytes test at a non-default value** — non-zero token, a real CRYPTO split, a non-minimal `Length` varint, packet-number encoded lengths 1 and 3. A.2 exercises none of these, and they are what subsystem B inherits.
- A two-datagram Initial flight is produced from a spec and matches the declared plan, with every Initial-carrying datagram at the §14.1 floor.
- No parser or receive-loop path throws for any input, and the rejecting path allocates 0 bytes.
- The handshake reaches **confirmed** — HANDSHAKE_DONE received over a 1-RTT short-header packet — not merely complete.
- A handshake completes against `System.Net.Quic.QuicListener` on loopback, in the gate.
- A handshake completes against a live server, and a fingerprint readout is produced and compared against a client capture field by field.
- Every layout field is read from `TlsQuicConnectionSpec`; no numeric layout literal exists outside its defaults block.
- `dotnet test --filter "FullyQualifiedName~Quic"` green, plus `PublicApiBaselineTests.ExportedApiMatchesTheReviewedBaseline` by name.

**The phase gate is deliberately downgraded from the scoping's.** The scoping sets A4's gate at *"interoperability against at least two independent QUIC implementations under loss, reordering and malformed input."* A4-minimal meets the malformed-input half (task 6's six cases plus A2's fuzz target), meets roughly **one and a half implementations** (MsQuic is genuinely independent; task 7's peer is ours), and **does not meet loss and reordering at all** — that harness is A3's, and building it now would test retransmission code that does not exist. This is a cut, not an oversight; it is listed as one below, and A3 restores it.

## Not in this phase

Each cut names where it lands. Silently omitting any of these is the failure mode this section exists to prevent.

| Cut | Lands in | What the cut costs |
| --- | --- | --- |
| Loss detection, RTT, PTO, retransmission, congestion control | **A3** | Any lost packet kills that attempt. Five load-bearing dependencies, enumerated above |
| ACK write-side allocations (handoff §8 item d) | **A3** | Nothing at handshake volume (~3 ACKs) |
| Loss/reorder/duplicate simulation harness | **A3** | It would test retransmission code that does not exist |
| Key update (RFC 9001 §6, incl. §6.3's timing requirements) | **A4-complete** | Cannot survive a long-lived connection. One handshake and one GET never trigger it |
| Connection migration, path validation (§8.2, §9), `preferred_address` | **A4-complete** | Cannot survive a network change. PATH_CHALLENGE is *answered* in 9b; the path is never validated or changed |
| NEW_CONNECTION_ID / RETIRE_CONNECTION_ID management, `active_connection_id_limit` | **A4-complete** | Parsed and ignored. With a zero-length source CID the peer cannot route by ours anyway. Must not error on receipt |
| Stateless reset detection (§10.3) | **A4-complete** | A stateless reset looks like a garbage datagram and is discarded; the connection then idles out |
| Dynamic flow control (`MAX_DATA`, `MAX_STREAM_DATA`, `*_BLOCKED`), stream limits | **A4-complete** | Task 14's static budget covers one GET and nothing larger |
| Full stream state machines, `RESET_STREAM`/`STOP_SENDING` semantics | **A4-complete** | Task 14 does open/data/fin only |
| Graceful close and full draining semantics (§10.2.2) | **A4-complete** | 9b sends CONNECTION_CLOSE and stops. No draining timer |
| 0-RTT | **A4-complete** | The TLS side already supports it; this is deferral, not deletion |
| ECN | **A4-complete** | The ACK codec already handles ECN counts; nothing sets or reads them |
| QUIC v2 (RFC 9369) | **A4-complete or B** | Extracted in task 0 for citation coverage only. that client's `version_information` lists GREASE and v1, not v2, so B may never need it |
| A shipped QUIC server | **never** | Task 7's peer is a test fixture. `CustomTlsQuicServer` remains the TLS half only |
| Pooled receive buffers, span-based frame writing | **A3 or later** | Finding 3: pooling is the change that would silently break the aliasing contract. Do not do it while the contract is only documented |
| **The `IPEndPoint`-per-datagram allocation** (Finding 7): reshaping `ITlsQuicDatagramTransport.ReceiveAsync` around a reusable `SocketAddress`, per `Socket.ReceiveFromAsync(Memory<byte>, SocketFlags, SocketAddress, CancellationToken)` | **A3** | The scoping assigns this decision to subsystem A and says to take it "when there is a packet loop to measure". Task 6 is that loop, so this is a **decision, deferred** — not an omission. A handshake is ten datagrams; the change would land on four implementations of the interface before there is anything to measure. A3 is the phase that runs the loop at rate. Recorded at the receive site in task 6 |
| Confirming the handshake on a 1-RTT ACK (RFC 9001 §4.1.2's optional shortcut) | **A4-complete** | HANDSHAKE_DONE is the required trigger and is sufficient. The shortcut only matters if HANDSHAKE_DONE is lost, which is A3's problem |
| Delayed-ACK timer and `max_ack_delay` honouring for 1-RTT | **Decided in task 14c: not deferred, DECLINED** | *Amended by task 14c, which removed this row's premise.* The original reason was "minimal sends no 1-RTT data, so the timer has no customer yet"; it does now. The decision is to acknowledge **immediately at every level**, and it is a choice rather than an omission: §13.2.1 makes `max_ack_delay` a **ceiling** ("an endpoint promises to never intentionally delay acknowledgments ... by more than the indicated value"), so a delay of zero meets the MUST for 1-RTT by construction; this connection sends at most one datagram per datagram received, so the ACK rides in an answer that was being built anyway and delaying it removes no packet from the wire — which is the only cost §13.2.1's balance argument names; and a timer must fire with no datagram to trigger it, which needs either a second thread of control (against `TlsQuicConnection`'s **one loop, one thread of control**) or timeout-driven scheduling, which is A3's. The full argument is in `TlsQuicApplicationSendPath.cs`'s header. **A4-complete owns it again only if it adds a send path frequent enough between received datagrams for batching to remove packets rather than add latency.** |
| HTTP/3, QPACK, SETTINGS | **C** | Task 14 exists to unblock it |
| The fingerprint spec layer itself | **B** | A4 builds the struct and populates it with Chromium-shaped defaults. B varies it |

---

## Amendments after task 1

**The `initial_rtt` requirement cannot be met with what is in the repo, and task 9a-ii's pin is
unsatisfiable as written.** The plan asks the spec to hold "the policy — randomise, and within what
range". **No ground truth for Chromium's range exists here**: a client capture contains a single
draw (parameter 12583, observed value 192859), which fixes neither bounds nor distribution. Task 1
refused to invent bounds and defaulted the field to `null`, which was correct — a fabricated range is
a fingerprint that is confidently wrong, and the standing rule is that a constant nobody can check is
not allowed.

So 9a-ii's "two consecutive connections yield two different `initial_rtt` values" cannot be pinned
until someone either captures enough connections to bound the range, or reads uQUIC's
`ChromeRandomInitialRTT()`. **Treat that as a prerequisite task, not an assumption.** Until then the
field stays `null` and the connection sends no `initial_rtt` at all — which is itself a deviation from
the target and must be recorded in task 11's readout as a known difference rather than silently
passing.

**§7.2's floor is narrower in scope than the plan implies — do not re-run it after Retry.** The RFC
binds "a client that has not previously received an Initial or Retry packet from the server", not
literally the first packet sent. After a Retry the Destination Connection ID is the server's Source
Connection ID and is **no longer self-chosen**, so the 8-byte floor stops applying. Task 9b must not
re-run that guard on the adopted CID — doing so would reject legal server behaviour.

**SETTLED after task 1's quality review — the flight plan stays two flat arrays.** Decided from what
the consumers actually take, and the "three consumers" framing was wrong by one: **task 4b is not a
consumer** — it builds one packet from a header spec and an ordered frame list, and the flight plan
never reaches it. Task 5 is the only consumer needing grouping, and that is a five-line walk taking
`counts[i]` chunks per datagram. **Task 11 wants them flat**: it reports the per-datagram flight plan
and the CRYPTO splits as *separate* lines, diffed against a client capture's own two separate
fields, so a nested form would have to be flattened back out.

Nesting's real advantage — the sum invariant becomes structurally true — costs the affordance both
the capture format and task 11 depend on: **stating one half without the other.** A nested
per-datagram record cannot express "I know the split, not the grouping" without an optional wrapper
that reintroduces the same partial-state problem. Flat, with the cross-check, is right.

**Superseded — the original open-decision note:** Task 1
implemented the CRYPTO split plan and the per-datagram frame counts as **two flat arrays with an
equality cross-check** (their sum must match the chunk count). The plan named them as separate
concepts without fixing a representation. Tasks 4b, 5 and 11 are the three consumers. **Decide before
the second consumer exists** — a nested representation is a mechanical change today and a
three-site refactor once 4b, 5 and 11 all depend on the flat shape.

**Mutate the code to match its own documentation — if that survives, the documentation is probably
the wrong one.** Task 3 produced two unwitnessed claims of the same shape, both prose the author
wrote about their own code's *timing* without ever executing the ordering it described. A remark said
a reply factory "runs when the receive that serves it is issued"; the code ran it at the later of
receive-issued and reply-enqueued. Changing the code to match the comment **survived the whole
suite** — nothing could tell doc from behaviour in either direction, and the existing test passed
only because its inputs happened to avoid the distinguishing order.

That ordering was not hypothetical: it is exactly what a blocked receive pump produces, which is what
task 9a-ii's connection loop does. The claim would have been relied on and been false.

So for any comment of the form "this runs when X" or "this sees Y as of Z", write the mutation that
makes the code literally do what the comment says and run it. A kill means they agree. **A survivor
means you have a doc and an implementation that disagree with nothing to arbitrate** — and the doc
usually loses, because behaviour is what later tasks actually hit.

---

## Amendments after task 4b

**Two of the spec's varint-width knobs currently have no implementation path — task 5 must close this
or field 7 is only half-deliverable.** `CryptoOffsetVarintWidth` and `CryptoLengthVarintWidth` are
dead: `TlsQuicStreamFrames.WriteCryptoFrameFields` always writes minimal varints, the A2 frame layer
is frozen and both-gates reviewed, and the builder takes **finished frames**, so it cannot honour a
width the frame writer never emitted.

This matters beyond tidiness. RFC 9000 §16 permits non-minimal encodings everywhere except the frame
type, which is *why* varint width is fingerprint field 7 — a sender choice, not a derived value. With
these two knobs dead, the builder can vary the header's `Length` width but not a CRYPTO frame's
offset or length width. **Task 5 needs a widened CRYPTO writer, or the plan must record field 7 as
partially deliverable and say which halves.** Do not quietly leave the knobs present-but-inert: a knob
that accepts a value and ignores it is worse than an absent one.

**Task 4a's `out pn_offset` covers the long header only.** `WriteShortHeader` never got it, so 1-RTT
sending — task 14 — needs the same one-line change first. Cheap now, and it is the identical
signature change 4a already validated against §5.4.2 and cross-checked over 2016 header shapes.

**The strongest evidence yet that published vectors are not adversarial.** Task 4b ran 22 mutations
with zero survivors — and **13 of them leave RFC 9001 A.2 *and* A.3 green**, caught only by the
hand-derived non-default cases. Final tally, recomputable from the record's two sections:
**11 seen by a published vector + 13 seen by neither = 24.**
**Well over half the defect space is invisible to both IETF vectors this phase has.**

**This figure moved three times — 9, then 15, then 13 — and that is the more useful lesson.** Nine
came from a category summary. Fifteen came from itemising, and was still wrong; the coordinator
repeated it into this plan without recounting. Thirteen came from a reviewer counting the record's
own bullets and checking the total closed against 22. **A count nobody can recompute from a list
keeps moving, no matter how many careful people repeat it** — so state the list, show the arithmetic
that closes, and let the number be derived rather than asserted.

The total then moved a fourth time, from 22 to 24 — but **legitimately**, and the difference is the
point. The first three moves were the same population counted differently. The fourth was the
population itself growing: a reviewer added two CRYPTO mutations, and an odd single-item bucket was
folded into the section it belonged in. **13 blind never moved once it was derived from a list.**
That is what a recomputable figure looks like: it changes when the world changes, not when someone
recounts. Every later task that leans on A.2/A.3 must carry its own non-default witnesses; the
vectors anchor defaults, and defaults are not what subsystem B varies.

---

## Amendments after task 5

**Fingerprint field 7 is HALF deliverable today, and this is the "say which halves" the task-4b
amendment demanded.** Task 5 did widen the CRYPTO writer — `TlsQuicStreamFrames.WriteCryptoFrameFields`
now takes an Offset width and a Length width, and `TlsQuicPacketHeader` already took a Length-field
width — so **every varint width in field 7 is reachable from a `TlsQuicPacketPlan`.** What task 5 did
**not** add is a `TlsQuicConnectionSpec` → `TlsQuicPacketPlan` mapping, so **none of the three spec
properties is read by anything under `src/`**: `HeaderLengthVarintWidth`, `CryptoOffsetVarintWidth`
and `CryptoLengthVarintWidth` are validated, stored, and reach no writer. Task 9a-ii owns that
mapping.

The interim report that this "ships whole" was wrong, and it was repeated into the handoff and into
three doc-comments before anyone re-ran the grep. **The check is one grep — `spec\.` against those
three names — and it takes a second.** A claim that a knob is honoured is exactly the kind that
survives on repetition, because the knob still validates, still stores, and still has a test that
looks like it covers it. The test in question was named `...AtTheWidthsTheSpecAsksFor` and set every
width on a **plan**; it is now named `...ThePlanAsksFor`.

**So the standing rule gains a corollary: a knob is honoured only if a caller setting it on the type
the caller holds changes a byte.** "The writer accepts a width" is a different claim, and both halves
must be stated separately or the pair reads as the stronger one.

**§14.1's padding target is a FLOOR and the code must be able to express an overshoot.**
`BuildInitialFlight` sized its scratch buffer from `spec.PaddingTarget`, which made every datagram
that legally exceeds the target throw — on the very input the builder exists for, a 1216-byte
X25519MLKEM768 key share declared as one CRYPTO frame against a 1200-byte target. The buffer is now
§18.2's 65527-byte UDP payload, and the ceiling that *is* real — a flight plan putting more CRYPTO
stream into one datagram than a UDP payload can hold — is rejected at the top of the method, naming
`spec`, the parameter the caller passed.

**A private method's parameter name is not a diagnostic.** Two separate guards threw
`ArgumentException` naming `plan` or `destination`, neither of which any caller of the public entry
point supplies. `ParamName` is load-bearing in this phase — A2's rules make it the only thing telling
two same-type throws apart — so it must name something the caller can set. Pass the caller's
`nameof` down rather than naming the local.

**The §16 Table 4 dead band is `w_next − w_prev` values wide, and the 1/2 boundary is reachable
through coalescing.** The solver's own comment said "a one-byte range" while its witness carried two
`InlineData` rows. The general statement: at the boundary between a `w_prev`-byte and a `w_next`-byte
Length, the budgets in `[H + w_prev + max(w_prev) + 1, H + w_next + max(w_prev)]` are reachable at
neither width — 1 value at 1/2, 2 at 2/4, 4 at 4/8. **`PaddingTarget` has a 1200 floor but a
coalesced budget does not**, which is the only way the 1/2 band (`budget = H + 65`) can be reached at
all; it is now witnessed at 83 and bracketed at 82 and 84. The 4/8 band needs a budget past a billion
and §18.2 caps `PaddingTarget` at 65527 — **unreachable by construction, and deliberately
unwitnessed.**

## Amendments after task 6

**The key-phase check's ORDERING is normative, and the task text as written asked for the
non-conforming one.** RFC 9001 §5.5, verbatim from the §5 capture: *"Similarly, a packet that appears
to trigger a key update but cannot be unprotected successfully MUST be discarded."* The task said
only that a differing key phase "closes the connection cleanly", with no ordering — and the key phase
bit becomes readable the moment header protection is removed, one step before the AEAD. A reader
implementing the sentence where the bit first appears closes on **exactly the packet §5.5 says must
be discarded**. §5.4 makes the reason concrete: the `quic hp` key provides confidentiality only and
authenticates nothing, so a pre-AEAD close is an off-path attacker's one-datagram remote kill, which
is the hazard §17.3.1 already names for the reserved bits — *"Discarding such a packet after only
removing header protection can expose the endpoint to attacks."* Post-AEAD is not the prudent
ordering, it is the only conforming one, and both Task 6 and Finding 8 now say so. The implementation
was already right; only the plan was wrong, which is the dangerous direction.

**§12.2's receiver half was missing and is now implemented, not deferred.** Task 5 closed the sender
half — *"Senders MUST NOT coalesce QUIC packets with different connection IDs into a single UDP
datagram"* — and the receiver half of the same paragraph, *"Receivers SHOULD ignore any subsequent
packets with a different Destination Connection ID than the first packet in the datagram"*, had no
code and no witness. SHOULD-level and the AEAD gates it in practice, but it costs eight lines and one
theory, which is less than the amendment justifying its absence would have cost.

**A buffer that outlives its documented lifetime is a security bug twice over.** `_scratch` is an
instance field; its comment claimed it was reused *"only within a single pass"*. Both halves of that
gap were real. The comment misled the task 9a-ii and task 14 handler authors about contract 3, whose
whole argument is that a pooled buffer turns a retained alias into a read of the next datagram — the
scratch **is** that pool, one layer down, for exactly the CRYPTO payload the contract is about. And
the growth path abandoned the previous datagram's decrypted TLS plaintext on the GC heap un-zeroed,
peer-triggerably, with no keys required: the resize happens at the top of `Receive`, before a byte is
parsed. `Dispose` already zeroed and already stated the intent; the resize just did not honour it,
and **deleting `Dispose`'s zeroing was a surviving mutation** — the stated intent had zero coverage
in either place.

**A wire enum needs its numbers pinned, and the public API baseline does not do it.**
`TlsQuicTransportError : ulong` is written into CONNECTION_CLOSE's Error Code field by task 9b, so
every member reaches the peer. `PublicApi.Shipped.txt` records
`F: public const … KeyUpdateError = SharpTls.Quic.TlsQuicTransportError.KeyUpdateError` — the symbol,
never the value — and no other test read a member as a number, so mutating `0x0E` to `0x0F` survived
the entire Quic gate *and* `PublicApiBaselineTests`. All six members are now pinned against the §20.1
capture as a set rather than one special case, because the gap belonged to the enum and not to the
member that exposed it. **General rule: the API baseline pins shape, never values. Anything whose
number is the contract needs its own witness.**

**"One synchronous pass" is a buffer rule and was being read as a concurrency one.** The word
"thread" appeared nowhere in `TlsQuicPacketReceiver`, whose `_keys`, `_largestReceived` and
`_scratch` are unsynchronised mutable state. Finding 6 already makes "one loop, one thread of
control" a **requirement** at the `CustomTlsQuicClient` layer; it is now stated on the receiver type
too, because task 9a-ii's author reads this file and the two requirements are satisfied by the same
single loop.

**A count you cannot recompute is not a record.** Task 6's mutation record asserted 44 mutations as
eight bucket sizes, of which only four were named anywhere — the same figure-that-moved failure mode
the A2 rules already forbid — and it silently classified a second unreachable-by-construction branch
(the long-header re-parse) as killed. The question was settled by **running** the mutation rather
than reasoning about it: deleting that guard leaves 925/925 green, so the record now reads **two**
survivors, both unreachable by construction and both deliberately unwitnessed. The 44 is kept but
marked approximate. **Corollary to the standing rule: survivors are the part of a mutation record
that must be itemised, because they are the part a later reader has to act on; a total nobody can
reconstruct is decoration.**

**The prescribed public-API regeneration was skipped and has now been run.** This task added a
`public` enum member, and the *Assembly and visibility* section's procedure for that case is to
regenerate with `tools/SharpTls.ApiCompat` and diff. It was hand-added instead. The outcome was
correct — 1050 lines generated, 1050 in the baseline, zero differences, and mutations deleting or
mis-sorting the line both died — but "it happened to be right" is not the same evidence as "the
tool agrees", and only one of the two survives a reviewer asking.

## Amendments after task 8

**Three places the task text disagreed with the RFC, all recorded in `TlsQuicAckTracker.cs` rather
than implemented.** Both review passes sustained all three, so they are settled and task 11 should
report them as known differences rather than re-derive them:

1. The task said *"ACKs for Initial and Handshake packets MUST be sent immediately."* §13.2.1 scopes
   that MUST to **ack-eliciting** packets — *"An endpoint MUST acknowledge all ack-eliciting Initial
   and Handshake packets immediately"* — so a packet carrying only PADDING, ACK and CONNECTION_CLOSE
   obliges nothing however Initial it is, and the paraphrase also drops the sentence's *"with the
   following exception"* clause.
2. The task said to encode `ack_delay` *"with the exponent from the peer's transport parameters."*
   §19.3 says the field *"is decoded by multiplying the value in the field by 2 to the power of the
   `ack_delay_exponent` transport parameter **sent by the sender of the ACK frame**"* — which for
   ACKs we generate is **our own** advertised value. The peer's exponent decodes ACKs we *receive*
   and belongs to A3's RTT sampling. Using the wrong one mis-scales every reported delay by
   `2^(theirs − ours)`, silently, because both values are legal and the frame still parses.
3. The task's `ProcessAckFrame(in TlsQuicFrame, DateTimeOffset)` signature had **no packet number
   space**. Largest-acked is per space (§12.3), and §13.2.6 — *"ACK frames MUST only be carried in a
   packet that has the same packet number space as the packet being acknowledged"* — so a space-less
   counter would let a Handshake ACK raise the figure task 4b uses to size Initial packet numbers,
   and a too-large largest-acked makes the encoder pick **fewer** bytes than the peer needs.

**§13.2.3's bound is on two verbs and only one of them was implemented.** *"A receiver limits the
number of ACK Ranges (Section 19.3.1) it **remembers and sends** in ACK frames, both to limit the
size of ACK frames and to avoid **resource exhaustion**."* `Prune` was called from `TryBuildAck` and
nowhere else, and `TryBuildAck` returns before it whenever nothing ack-eliciting is outstanding — so
non-ack-eliciting traffic on scattered packet numbers grew `_ranges` without any limit at all
(20,000 PADDING-only packets, 20,000 ranges retained, `TryBuildAck` returning false throughout, and
the first forced build then pruning to 32). It also made `Insert`'s "linear, because the list is
bounded" comment **false at its only call site**: descending arrival walked the whole list, quadratic
in an attacker-controlled count, ~287 ms for 5000 packets in Debug. `Prune` now runs after every
insert on the receive path, which fixes the bound and the complexity together and makes both
doc-comments true.

**The floor moved with it, and that is a real behaviour change.** `_minimumPacketNumber` now ratchets
on **arrival** rather than on send, so a packet below a range just discarded is refused immediately
instead of at the next build: holding (5,5) and (3,3) at a limit of 2, packet 1 is recorded, pruned,
and the floor put at 3, so a later packet 2 is refused where it once merged. §13.2.3 prices exactly
that — *"A receiver can discard unacknowledged ACK Ranges to limit ACK frame size, at the cost of
increased retransmissions from the sender"* — and its MUST is untouched, because the floor is still
set from the smallest number **still retained**. The set of received packets that can be acknowledged
is smaller, sooner; the set of **un**received packets that can be acknowledged is still empty.

**Where this hid is worth more than the fix.** Neither review pass was wrong on its own terms: spec
review stopped at "no MUST violated" and this violates none, quality review stopped at "the limit is
implemented" and it is. The defect lives in the seam the two-pass method creates — **a requirement
one pass reads as satisfied by an implementation the other pass reads as present**. The question that
finds it is neither pass's: *for each half of a compound requirement, which line enforces that half,
and on which path?*

**`AckRangeLimit`'s default of 32 is a placeholder and task 11 must report it as one.** The that client
capture says nothing about ACK ranges and there is no published vector, so it sits in the same
not-yet-known-from-the-capture category as `InitialPacketNumber` and the `initial_rtt` range task 1
refused to invent. It is honestly labelled in the source XML doc, which task 11 will not read — hence
this line. **It is also not yet wired**: nothing under `src/` constructs a tracker from a spec, so
setting the property changes no byte. Task 9a-ii owns that wiring, alongside the
`HeaderLengthVarintWidth` / `CryptoOffsetVarintWidth` / `CryptoLengthVarintWidth` mapping the task-5
amendment already assigned it. This is the second present-but-inert knob in two tasks, which is why
the standing rules above now carry it and `TlsQuicConnectionSpec.cs` carries it at the top of the
file.

**A test named for a formula did not pin the formula.** `TheGapIsPreviousSmallestMinusLargestMinus
TwoAndNotTheReverse` received packets 20 and 10 — two ranges one packet wide, so `Largest ==
Smallest` in both — and therefore survived mutating the gap's `ranges[index].Largest` to
`.Smallest`. That is mutation 16's pattern recurring inside the test written to prevent it: the
implementer had already caught their own hand-derivation error in this arithmetic. **General rule:
a witness for a formula over a record's fields must give every field a different value**, or it pins
the expression's shape and not its operands. The vector is now 22/21/20 and 12/11/10, where all four
candidate readings of the gap produce different bytes.

**The receive path throws for nothing a peer can send.** `OnPacketReceived` threw
`ArgumentOutOfRangeException` for a packet number above §12.3's 2^62−1 while merely returning for one
below the floor — a throw-versus-drop split on the same class of input — and both the doc and the
test labelled the throwing case REACHABLE from `TlsQuicPacketNumber.Decode`. `Decode`'s plain return
path has no 2^62 ceiling, but it reconstructs *around* the largest received so far, so reaching that
value needs a largest-received already near 2^62: **effectively unreachable, and the label was
overstated**. It is now a drop, because the label mattered — a genuinely reachable throw there is a
one-datagram remote kill of task 9a-ii's loop, the hazard §17.3.1 names for the reserved bits. Code,
doc and test now agree.

**`ProcessAckFrame` allocated on the receive path, outside the four deferred fixes.** It passed a
fresh `List<TlsQuicAckRange>` to `TryGetRanges` and never read it — an allocation whose size is the
peer's choice, on the path *The four deferred allocation fixes* describes as "already 0 bytes and
permanently tested". `TryGetRanges`' list is now nullable, which is not a new code path: the private
`TryWalkRanges` beneath it has always taken a nullable list so that `TryReadAck` can validate a chain
it has nowhere to store. A4-minimal wants the verdict only; A3 passes a list when it wants the
ranges.

---

## Amendments after task 9a-i

**The done-when describes a behaviour the type does not have.** It asks that "installing after
disposal yields zeros, pinned by a test that reads a secret after disposal". Reading a disposed
secret does not yield zeros — it **throws**. `TlsQuicProcessResult.Dispose()` disposes the event,
which disposes the `TlsQuicTrafficSecret`, and `CopySecret` then raises `ObjectDisposedException`.
That check already existed and is the real defence against the disposal trap.

This matters beyond wording. `TlsQuicKeySet` grew an all-zero rejection *believing* it guarded the
trap, and the type's own remarks said so. It cannot: `CopySecret` throws before the guard is
reached. The guard survives as defence in depth against a hand-constructed all-zero secret — no
disposal path produces one — and it is now documented at that narrower reach. **A guard justified by
a scenario it cannot see is the same defect class as a dead knob**, and it took driving the real
`TlsQuicProcessResult` to expose it; the hand-zeroed `byte[32]` stand-in the task originally used
pins the guard while simulating the trap, which is exactly how the two stayed confused.

**PRESENCE IS NOT IDENTITY — the lesson task 9a-i cost the most to learn.** Inverting the Initial
*read* derivation, so a client reads with the client secret and decrypts nothing, **passed all 1004
tests**. Every read assertion went through `TlsQuicPacketReceiver.HasReadKeys`, which reports that a
slot is non-null and nothing about what is in it. The write half had RFC 9001 A.1 as an external
oracle; the read half had none. **Both review gates found it independently**, which is the strongest
signal this method has produced. The fix is A.3's published server Initial — protected with the
server secret by someone else, so it is an oracle we cannot fake.

Generalised: **a direction, a level, or a slot asserted only by a boolean is unpinned.** Task 9a-ii
installs 1-RTT read keys and task 14 reads over them; both need an identity oracle, not `Has*`.

**`StateOf` became `WriteStateOf`.** It reports the write direction only — read state lives on the
receiver — and a read-only install leaves it saying `NeverInstalled`, which is true of the writes and
false of the level. The unqualified name invited the wrong reading.

**§4.9.1's "MUST NOT send Initial packets after this point" is enforced by refusing re-derivation.**
`InstallInitialKeys` throws once Initial has been discarded. Retry cannot legitimately land there —
it answers the first Initial, long before any Handshake packet is sent — so a re-derivation after
the discard is a sequencing bug. **Task 9b must not rely on re-deriving Initial keys post-discard.**

**§5.3 permits four cipher suites, not three,** and `CipherSuiteInfo` supports three. §5.3: *"QUIC
can use any of the cipher suites defined in [TLS13] with the exception of TLS_AES_128_CCM_8_SHA256."*
The omitted one, TLS_AES_128_CCM_SHA256, **is** permitted and §5.4.1 names its AEAD. So
`TlsQuicKeySet.CiphersFor`'s rejection arm is not a safety net awaiting an unsupported suite —
adding that suite to `CipherSuiteInfo` makes the arm **wrongly reject a legal one**. Whoever adds it
owes a fourth case, not a witness.

**Citation correction:** *"Prior to TLS selecting a cipher suite, AES header protection is used"* is
§5.4.1, not §5.3. Two files cited it wrongly.

**Rows 14–21 of that file's ledger are the review gates', and every one was a survivor** — seven
real defects and one dead guard, against one defect found by the implementer's own sweep. The
self-run sweep and the adversarial pass are not substitutes for each other, and the ratio here is
the clearest evidence this phase has produced.

---

## Amendments after task 7

**Splitting coalesced datagrams is a permanent caller responsibility. Task 9a-ii inherits it.**
`TlsQuicPacketReceiver.Receive` *does* walk coalesced packets itself — §12.2's *"Receivers MUST be
able to process coalesced packets"* is satisfied. But it is **synchronous**, and installing Handshake
keys requires an `await` into TLS, so it cannot install keys mid-walk **by construction**. A server
that coalesces ServerHello (Initial) with its Handshake flight — which is what real servers do, and
what task 7's own server did — therefore has its Handshake packet discarded on the first pass.

§12.2 says increasing-level ordering *"makes it more likely that the receiver will be able to process
all the packets in a single pass"*; ours never can for Initial+Handshake. **A caller whose keys arrive
between coalesced packets must split with `TlsQuicDatagramReader.Read` and call `Receive` per
packet.** The full contract is on `Receive`'s own remarks — read it there, it is longer than this.

**A3 makes this load-bearing rather than cosmetic.** Loss detection and retransmission are deferred by
the user's decision, so a discarded Handshake packet is never recovered: the handshake simply stalls
with every packet accounted for. That failure has **no symptom of its own**, which is why
`DiscardedForMissingKeys` was added to `TlsQuicReceiveResult` — so a caller can detect the stall
instead of inferring it.

**And splitting silently forfeits §12.2's connection-ID clause** — *"Receivers SHOULD ignore any
subsequent packets with a different Destination Connection ID than the first packet in the
datagram."* Each per-packet call re-nulls the first-DCID, so the clause task 6's fix round added stops
applying. Measured, not assumed: neutering that check kills **exactly one** test, task 6's own, and
**zero** of task 7's. A splitting caller that wants the clause back must compare DCIDs itself.

**A wire constant can be wrong with encode and decode agreeing, and leg 1 will not see it.** Swapping
`ZeroRtt = 0x01` and `Handshake = 0x02` (RFC 9000 Table 5) **survived all 1024 tests**. The two sides
are inverses over the same enum so they cancel exactly, and **Appendix A has no Handshake vector**.
Every Handshake packet would have gone out stamped 0-RTT and MsQuic would have rejected it.

Now pinned by `TlsQuicPacketBuilderTests.EachLongHeaderTypeIsStampedIntoByteZeroWithTable5sValue`,
which asserts `byte0 & 0x30` on **built** packets against Table 5. Two details make it a real wire
assertion rather than an enum tautology: the type bits sit above §5.4.1's
`packet[0] ^= mask[0] & 0x0f`, so they read clean off the *protected* packet; and Retry has to be
taken from `WriteLongHeader`, its only encoder, because the builder rejects it.

**Generalise it:** any constant that reaches the wire, is written and read by our own pair, and has no
external vector is invisible to every test we can write from the inside. Enumerate those and pin them
against the RFC table, not against each other. This is the same shape as task 9a-i's *presence is not
identity*.

**A self-checking harness will over-claim about itself.** Task 7's honesty section — which assertions
survive a bug shared by both halves — listed *"which encryption level each flight arrives at"* under
SURVIVES. It does not: the level is a byte the harness's own pair writes and reads. The row was
split, with *order* staying (anchored by a flight being unopenable before the flight that yields its
keys) and *level* moving.

The rest of the section held under audit, and one measurement is worth carrying forward: a reviewer
inverted the AEAD nonce's packet-number byte order — a textbook cancelling defect — and **0 of task
7's 11 tests died, while 18 died elsewhere in the suite.** That is the honesty claim being true rather
than merely stated, and it is the reason leg 1 stays the byte authority.

---

## Amendments after task 9a-ii

**Two of the done-when conditions were settled before the task started, and one of them is
dead.** The `initial_rtt` pin — "two consecutive connections produce two different
`initial_rtt` values" — was already overturned by the amendments after task 1, and task 9a-ii
did not implement it. The field stays `null`, the connection sends no `initial_rtt` at all, and
**task 11 reports that as a known deviation.** What survives of Finding 1 is the structural
half: the connection takes a **client factory** rather than a client, and calls it once per
attempt with the Source Connection ID that attempt drew. That is the ordering in which
`initial_source_connection_id` (0x0F) and the header field cannot disagree — and it is worth
saying that with the target's zero-length source CID the freshness is currently
**unobservable from outside**, so the tests advertise a 5-byte one to make it witnessable at
all.

**The three-disjunct guard is equivalent to `Processed == 0` at a splitting caller, and the
task text's reasoning for it does not apply there.** The text said the naive form "cannot fire
on the real stall shape (`Processed=1, Discarded=1`)" — true, but that shape belongs to a
caller that hands a **whole datagram** to one `Receive` call, which is precisely what task
9a-ii does not do. One packet per call makes `Processed + Discarded <= 1`, so all three
disjuncts fire together or not at all: deleting each in turn leaves 1043/1043 green.

**And the guard should not have existed at all — see "the discard kill switch" below. This
paragraph is kept because it is the reasoning the fix round overturned, not because it stands.**

**`DiscardedForMissingKeys` distinguishes two failures a connection loop meets, and both are
now witnessed apart.** A packet sealed with the wrong secret is §12.2's "or for any other
reason": `Discarded=1, DiscardedForMissingKeys=0`. A packet at a level whose keys have not
arrived is §12.2's "because the keys are not available": `Discarded=1,
DiscardedForMissingKeys=1`. The first draft of task 9a-ii's guard test asserted the
missing-keys count on the wrong one of the two and would have passed with the field unread.

**`ApplyDiscards` over `ProcessCryptoDataAsync` results is dead code for a CLIENT, and the
comment justifying it described the SERVER.** `CustomTlsQuicClient` raises
`TlsQuicDiscardKeysEvent` from exactly two places, `NotifyHandshakePacketSent` (`:327`) and
`ConfirmHandshake` (`:347`); `CustomTlsQuicServer` raises one from `ProcessCryptoDataAsync`
(`:154`). The install/send/discard remark task 9a-ii inherited from `LoopbackQuicPeer` — where
it is true, because that peer drives both roles — claimed the client's completion result
carries a Handshake discard whose ordering matters. It does not. **Applying those discards
before the send survives the whole gate**, and the apply is now a *check* that the assumption
still holds. What actually makes the order load-bearing is §4.9.1's trigger being a **send**,
which is a different sentence.

**Two levels must be skipped on the send path, for two different reasons, and both were found
by running the loop rather than by reading it.**

1. **EarlyData.** `TlsQuicAckTracker` is indexed by RFC 9000 §12.3's packet number *spaces*,
   and 0-RTT shares 1-RTT's — so a tracker with Application ranges offers them at the EarlyData
   level too, and a level-indexed send loop tries to build a 0-RTT packet carrying an ACK,
   which §12.4 Table 3 forbids.
2. **Application.** A4-minimal cannot send a 1-RTT packet at all, so it **cannot acknowledge
   one** — including the very packet that carries HANDSHAKE_DONE. **This is a KNOWINGLY
   VIOLATED MUST, and the first draft of this paragraph said "§13.2.1's MUST is scoped to
   Initial and Handshake" because it quoted a sentence truncated at a line wrap.** The whole
   sentence, from `rfc9000-section13-packetization-and-ack-generation.txt` lines 59–61: *"An
   endpoint MUST acknowledge all ack-eliciting Initial and Handshake packets immediately **and
   all ack-eliciting 0-RTT and 1-RTT packets within its advertised max_ack_delay**, with the
   following exception."* One MUST, two conjuncts — 1-RTT is named, and only its *deadline* is
   relaxed. §13.2.1's exception cannot rescue it either: it covers an endpoint that "might not
   have packet protection keys for decrypting Handshake, 0-RTT, or 1-RTT packets when they are
   received", and we decrypted the packet. A server will retransmit its HANDSHAKE_DONE
   unacknowledged. **Task 11's readout owes it as a knowingly violated MUST rather than as a
   soft deviation; task 13's live run owes reporting what a real server does about the
   unacknowledged retransmissions; task 14 closes it.** Throwing instead would be a
   one-datagram kill of the connection on a peer's entirely conforming frame.

**The handshake deadline needs two mechanisms, and only one of them can be witnessed on a fake
clock.** A peer that answers LATE is caught by a `GetUtcNow` comparison after the receive
returns, which is what fires deterministically with zero wall-clock time elapsed. A peer that
goes SILENT never produces a clock reading at all, so only a token source bounding the await
can end it — and a `TimeProvider` subclass that overrides `GetUtcNow` and nothing else inherits
the **real** timer, so that half cannot be driven off a fake clock without building a fake
timer that would then be the thing under test. Both are implemented; the silent half is
witnessed in 250 ms of real time and labelled as such. **A plan that asks only for the
fake-clock condition leaves the case A3's absence actually produces untested.**

**The connection reads the clock ONCE per pump, so every `ack_delay` it reports is
structurally zero.** §13.2.5's reader subtracts the reported delay from its RTT sample, so
under-reporting makes the peer's estimate larger and therefore more conservative;
over-reporting would shrink it. The safe direction is taken deliberately. **The consequence for
task 11: `TlsQuicConnectionOptions.AckDelayExponent` is wired and validated but scales a zero,
so it moves no wire byte yet** — the weaker of the two claims the task-5 amendment separates,
and it must be reported as the weaker one.

**`AckRangeLimit` and the three varint widths are now honoured in the strong sense** — a caller
setting them on the type the caller holds changes a byte, witnessed by
`TheSpecsAckRangeLimitBoundsTheRangesThatReachTheWire` and `TheSpecsVarintWidthsReachTheWire`,
the latter by *opening* the connection's own Initial packet with keys derived from the
Destination Connection ID it chose. One correction to the obvious expectation: **"minimal" is
the shortest width that HOLDS THE VALUE, not one byte.** The first draft of that witness
expected a one-byte encoding for all three fields and was wrong for two of them, because a
ClientHello's size and a padded datagram's size both sit past §16 Table 4's 63-value ceiling.

**§7.2's adoption is unwitnessable against `LoopbackQuicPeer`, and that is a property of the
peer rather than of the clause.** That peer echoes the client's own Destination Connection ID
back as its Source Connection ID, so adopting it is a no-op and a connection that never adopted
would pass every loopback test. The witness has to be scripted, with a server Source Connection
ID that exists nowhere else, read back off the *next datagram the connection emitted*.
**Whoever writes task 9b's Retry witness inherits exactly this trap**, because Retry moves the
same field.

**Splitting forfeits §12.2's connection ID clause, and task 9a-ii RE-APPLIES it** rather than
recording its loss. It costs eight lines across the per-packet calls and it is witnessable, for
a reason worth writing down: the AEAD key does **not** depend on the Destination Connection ID
*field*, only on the one §5.2 derived from, so a second coalesced packet naming a different
Destination Connection ID **opens perfectly well** and only this clause can reject it. A test
can therefore tell the clause apart from the AEAD, which the "the AEAD gates it in practice"
argument for dropping it had assumed it could not.

### The fix round after task 9a-ii's two review gates

**A throw on `TlsQuicReceiveResult.Discarded` was an off-path remote kill switch, and it is
gone.** `Discarded` is incremented on header-protection-removal failure and on **AEAD
failure** — both of which run on *unauthenticated* input — so `RequireOneCleanlyProcessed
Packet`'s `Discarded > 0` disjunct ended the connection on input nobody had to authenticate. A
reviewer reproduced the kill with **zero key material**: a client reads with §5.2's *server*
secret, so the client's **own Initial datagram replayed back at it** cannot open, giving `0
processed, 1 discarded` and a dead attempt. RFC 9000 §12.2 requires the opposite — *"if
decryption fails (because the keys are not available or for any other reason), the receiver MAY
either discard or buffer the packet for later processing and **MUST attempt to process the
remaining packets**"* — `TlsQuicPacketReceiver`'s own contract said the same ("a failed decrypt
is NOT an error and never sets `CloseError`"), and `BuildAnswerDatagram` argued the same rule
280 lines further down the same file while this guard did the reverse. **The mutation sweep did
not find it; a reviewer reading what `Discarded` means did.** Discards are now counted
(`DiscardedPackets`, `DiscardedForMissingKeys`, `UnprocessedPackets`) and reported by
`DeadlineExceeded`, which is the only failure a stall can now produce and therefore the only
place diagnosability can live. The one thing that still throws is `CloseError`, which is set
only on an **AEAD-authenticated** packet.

**Two hardcoded layout choices are now knobs, because the design constraints already said they
had to be.** Reversing the coalescing loop to descending encryption levels, and moving the ACK
from first to last inside a packet, both left 1043/1043 green — and both are named by *"nothing
afterwards may read a literal for: … frame order, per-datagram flight plan."* They are now
`TlsQuicConnectionSpec.CoalesceAscendingByLevel` and `TlsQuicConnectionSpec.AckLeadsInPacket`,
witnessed from the **receiving** side (`LoopbackQuicPeer.LastDatagramFrames`), because both sit
under the AEAD and the sender cannot read its own packets back. The ACK-leads choice had been
*declared* ungrounded in a comment and hardcoded anyway; **declared is not knobbed, and task 11
cannot report a field the connection fixes.**

**Row 23 was A4-minimal's debt, not A3's.** The ledger reasoned that reaching
`LargestAcknowledged`'s effect needed "a peer acknowledging a packet number far behind, which
no test here builds". The distance is `full_pn - largest_acked`, and **`InitialPacketNumber` —
a knob task 9a-ii itself wired — sets `full_pn` directly**: `{ InitialPacketNumber = 127,
PacketNumberEncodedLength = 1 }` plus a scripted ACK of 127 makes the real code want one byte
and the mutant want two. **Evidence beat argument**, and the general rule this is the proof of
is that a reachability argument is worth less than the forty lines of test that would settle
it.

**§7.2 had two gaps, one unwitnessed and one unimplemented.** *"A client MUST change the
Destination Connection ID it uses for sending packets in response to only the first received
Initial or Retry packet"* was implemented and never measured — deleting the guard left
1043/1043 green. And *"Once a client has received a **valid** Initial packet from the server,
it MUST discard any subsequent packet it receives on that connection with a different Source
Connection ID"* appeared nowhere in `src/SharpTls/Quic/` or in this plan. Both are now
implemented and witnessed, and **`valid` is the load-bearing word**: the compared-against value
is recorded only after the AEAD opens a packet, because a Source Connection ID taken off
unauthenticated input would let an off-path sender choose it — the influence §7.3's last
paragraph exists to deny. **Adoption itself necessarily reads unauthenticated input** and
cannot not: the Initial keys cannot be derived from a value the packet supplies. §7.3 is the
closure, and it says so.

**`ack_delay_exponent` had two sources and nothing reconciled them.** The value we *scale* by
is `TlsQuicConnectionOptions.AckDelayExponent`; the value we *advertise* is transport parameter
`0x0A` inside the `ClientHelloProfile` the factory builds. §19.3 makes the ACK's **sender** the
one that scales, so the peer divides by the advertised value. The mismatch is masked today
because every `ack_delay` this loop reports is structurally zero — **which is exactly why it
now fails at construction**: the moment task 14 or A3 reads the clock twice, a mismatched pair
is a 2^n error in the peer's RTT estimate with no symptom on either side.

**Smaller.** `_confirmed` is set *after* `ConfirmHandshake` (the old order could report
§4.1.2's confirmed state with Handshake keys still installed, had `ConfirmHandshake` thrown).
The install/send/discard remark now separates the ordering that is load-bearing **against the
build** — witnessed — from the one **against the send**, which is vacuous: moving
`NotifyHandshakePacketSent` between `BuildAnswerDatagram` and `SendAsync` changes no byte,
because the datagram is already assembled and `TryGetWriteKeys` is never consulted again. The
lazy-iterator argument is now a one-line **check** that the reader's slice and the loop's
window are the same bytes.

**The ledger is 46 rows: 24 killed on first run, 12 was-survivors, 10 surviving.** Rows 33–46
are the fix round's, run against the 1054-test gate; rows the fix round touched (4, 5, 6, 22,
23) were re-run against it. **The lesson rows 33, 34 and 36 carry: mutate the CHOICES, not only
the CHECKS.** All three were hardcoded behaviour rather than guards, which is why a sweep aimed
at guards missed all three.

**Task 9b inherits three things from this loop.** `OriginalDestinationConnectionId` is exposed
separately from `DestinationConnectionId` precisely because Retry moves one and not the other,
and because §5.2 keys Initial from the first. `TlsQuicKeySet.InstallInitialKeys` throws once
Initial is discarded, so Retry must land before the first Handshake packet — which it does. And
the two throws this loop makes on peer input (a malformed ACK chain, and a
`TlsQuicReceiveResult.CloseError`) are placeholders for §10.2's immediate close: they end a
one-shot attempt, which is what a close achieves minus the frame on the wire, and 9b replaces
both.

---

## Amendments after task 11

**The task text says to snapshot against "the task 10 loopback". Task 10 is not started, and
task 7's `LoopbackQuicPeer` is the right substitute** — it completes a full handshake in-process
with no socket and no clock, which is all the readout needs. Whoever writes task 10 should note
that the snapshot is already pinned against the in-process peer and that an MsQuic run would be a
*second* recording, not a replacement: leg 3 validates conformance and is explicitly not evidence
about any spec knob.

**THE READOUT'S KEYS COME OUT OF THE RECORDING, and that is what makes the whole task a
measurement rather than a restatement.** RFC 9001 §5.2 derives the Initial secrets from "the
Destination Connection ID field from the client's first Initial packet" — a value the recording
carries in the clear — so `TlsQuicFingerprintReadout` opens our own Initial packets without being
handed anything. The consequence worth carrying forward is not about our code: **every field in
the `"quic"` block is equally readable by any on-path observer**, which is precisely why they are
fingerprint fields at all. The anti-tautology witness is
`TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith` — one recording rendered against two specs that
disagree on every knob, identical block. Without it the readout could have been a restatement and
every other assertion in the file would still have passed.

**Two of the five owed items turned out to be MEASURABLE, and were measured rather than
restated.** The absent `initial_rtt` is now read out of the reassembled ClientHello's RFC 9001
§8.2 extension — `transport_parameters_wire_order` reports `[15, 14]` and 12583 is absent from a
list that was actually parsed, which is a different claim from "the spec field is null". So is
`initial_source_connection_id` agreeing with the header. **The general rule this is the proof of:
when a plan says "report X as a known deviation", ask first whether the bytes carry X.** Two of
five did.

**The order knobs are less unobservable than the 9a-ii amendment claimed, and the readout says
which half is which.** `CoalesceAscendingByLevel`'s *consequence* is cleartext — RFC 9000 §17.2's
long header type is not under the AEAD, so the per-datagram sequence `Initial + Handshake` is
printed from bytes and does corroborate ascending order. `AckLeadsInPacket`'s consequence is
readable too, but only inside a packet we can open, and no recording this phase produces holds an
Initial packet carrying an ACK beside another frame. The readout therefore prints both knobs as
spec-sourced **and** prints two corroboration counts, with the rule that **a zero means the
recording is silent, not that it agrees.** Neither has capture ground truth either way.

**A partial recording must not be allowed to report an absence.** If the CRYPTO stream cannot be
reassembled — a gap or a truncation — `initial_rtt_parameter_present` prints
`"not-recoverable-from-this-recording"` rather than `false`. Reporting `false` there would be a
deviation claimed on no evidence, which is the same failure mode as an invented constant.

**MOST packet-layer fields land in not-yet-known-from-the-capture — but not all, and the earlier
claim that no mismatch was found was wrong.** The comparison table has one row per rendered
field: the readout's twenty `"quic"` fields plus the two spec-sourced order knobs, **22 rows**.
They come out **3 match, 2 mismatch, 17 not-yet-known** (3 + 2 + 17 = 22).

**The mismatch is `transport_parameters_wire_order`, and it is a real difference, not a gap.**
Line 30's not-inspected list is exhaustive — "initial packet number and its encoded length, token
length and prefix, per-datagram Initial flight plans, CRYPTO frame splitting, frame ordering,
datagram padding target" — and **wire order is absent from it**. The capture publishes the order
affirmatively (line 54: "Both are published, so wire order is fingerprinted and must be reproduced
exactly"; line 74: "This ordering is the fingerprint"). Ours is `[15, 14]`. Chromium's is the
**14-entry** `[12584, GREASE, 32, 9, 8, 7, 5, 15, 17, 1, 6, 4, 12583, 3]` — count it off the table
at lines 79–92, and off the `perk` string at line 47. They differ in **membership and order**, and
`14` (`active_connection_id_limit`) is not in Chromium's list at all.
`initial_rtt_parameter_present` is the second mismatch and is entailed by the first: 12583 is
entry 13 of that list and we send no such parameter. **Whose job it is to fix belongs in a note,
never in a verdict cell** — filing a known difference as not-yet-known sends subsystem B to
capture something it already holds.

**Two of the three matches carry a caveat that must travel inside the verdict cell.**
`client_connection_id_length` is **match — default only; the snapshot advertises 5**: the tests
behind the snapshot use a five-byte source connection ID on purpose, because at the target's own
zero length the `initial_source_connection_id` witness is erased. What equals the capture's 0 is
`TlsQuicConnectionSpec`'s default, exercised by
`AZeroLengthSourceConnectionIdIsReportedAsErasingItsOwnWitness`.
`initial_source_connection_id_equals_header_source` is **match — vacuous at the capture's zero
length**: an empty parameter equals an empty header field for a client that never copied it.
Only `server_connection_id_length` (8 in both) is a plain match.

**And one not-yet-known is soft rather than blank.** `initial_flight_datagram_count` reads 1 in
our snapshot, which is fair — our recording carries a 236-byte CRYPTO frame, not a 1216-byte key
share. But the capture settles the target's side of it: line 126, "That 1216-byte post-quantum
share is why Chromium's Initial does not fit one datagram", and line 141, "The post-quantum key
share forces a multi-datagram Initial, so that path is required, not optional." The honest row is
**not-yet-known (split plan); capture settles Chromium's is ≥2 datagrams**.

**`datagram_padding_target`'s verdict is right and its stated reason was not.** RFC 9000 §14.1:
"Datagrams containing Initial packets MAY exceed 1200 bytes if the sender believes that the
network path and peer both support the size that it chooses." 1200 is a **floor**, and the target
is a client choice above it — which this plan already stated in the amendments after task 5
("§14.1's padding target is a FLOOR and the code must be able to express an overshoot"), and
task 11's note regressed. The verdict is not-yet-known because **line 30 names datagram padding
target as not inspected**; that, and not §14.1, is the reason.

**The mutation sweep changed two verdicts, and both were the same defect shape.** A guard with two
disjuncts had only one of them witnessed — a first datagram that fails to *parse* fires before the
"is it Initial" check ever runs, so replacing the type check with a constant left 1069/1069 green.
And the CRYPTO reassembly has two failure shapes reaching two different checks; only the gap was
witnessed, and the truncation — the one that would otherwise index past the end of a ClientHello
that never arrived — was not. **For any guard that is a disjunction, ask which input reaches each
disjunct, and check that some test produces it.**

**Three checks in the reassembly shadow each other and no in-contract input separates them.**
Contiguity, the ClientHello handshake-type byte, and the declared-length coverage all reject an
incomplete stream, and which one fires depends on what the missing bytes happened to hold. They
are kept — contiguity is the one that is right *by reason* rather than by happenstance — and the
ledger records two of them as unwitnessed rather than pretending otherwise.

## Amendments after the review gates on task 11

**THE ANTI-TAUTOLOGY WITNESS LEAKED ON THE FIELDS IT WAS THE ONLY GUARD FOR, and one of them was
the field the amendments above single out as measured rather than restated.** Both gates found it
independently. The witness rendered one recording against two specs, but those specs left `Token`,
`InitialCryptoFrameByteCounts`, `InitialCryptoFramesPerDatagram`, `InitialFrameOrder`,
`InitialRttRange` and `AckRangeLimit` unset on **both** sides, so rendering `token_length`,
`token_prefix`, `initial_crypto_frame_byte_counts`, `initial_flight_crypto_frames_per_datagram`
or `initial_rtt_parameter_present` off the spec produced an identical block and survived
1069/1069 — re-run against the pre-fix commit to confirm, four times. The two specs now disagree
on **every property `TlsQuicConnectionSpec` declares**, and the same four mutants die, three of
them failing the witness *and nothing else*. **A guard that leaks on part of its own scope is
worse than no guard, because it is cited as if it covered that part.** The general rule: a test
that renders a recording against a spec constrains exactly the properties the two specs disagree
on, so "disagree on every knob" has to be checked against the type's property list, not asserted.

**Two tests asserted a value against the source of that same value.** The token test set
`spec.Token = [de ad be ef 01]` and passed *that same spec object* to `Describe`; the CRYPTO split
test asserted `[64, …]` against a spec saying `[64, 65000]`. Both now hand `Describe` a default
spec, which agrees with the connection's spec on the only two fields `Describe` reads from it.
This is the same shape that let task 8's formula-named test survive an inverted range chain and
task 9a-i's read direction survive 1004 tests.

**A verdict field compared lengths under a name that said value.**
`initial_source_connection_id_equals_header_source` tested
`parameter.Value.Length == header source length`, so five entirely different bytes reported
agreement — and replacing the whole ternary with a constant survived 1069/1069, which is the
"witness that cannot fail" the readout's own `RenderSpecSourced` comment forbids. It now compares
bytes (RFC 9000 §7.3 requires the value to agree), the verdict words are `same-value` /
`different-value`, and a recording advertising the bitwise complement of its own five-byte source
CID witnesses the failing branch.

**The snapshot was a ratchet with no pawl.** Its failure named no field, no line and no diff, and
pointed at a temp file CI discards — strictly worse than a plain `Assert.Equal`. Since
`initial_frame_order`, `initial_padding_bytes`, `initial_crypto_frame_byte_counts` and the
per-datagram rows are pinned by that snapshot *alone*, the cheapest response to it was a
re-baseline, which would silently delete the fingerprint. It now names the first differing field
and line and says re-baseline only if that field was meant to move.

**Two paths reported a wrong number instead of throwing, and `Describe`'s contract is a comment
rather than a type.** It is `internal` and takes any `IReadOnlyList<ReadOnlyMemory<byte>>`, so
"datagrams this connection emitted" binds nobody. The CRYPTO frame type width is now measured
rather than assumed to be one byte — `TlsQuicFrames`' reader declines §12.4's receiver MAY on
purpose, so an over-long type is admissible input and the old arithmetic would have sampled an
interior Offset byte — and every index in the ClientHello walk is bounds-checked, so such input
raises the `InvalidOperationException` the type's remarks promise rather than
`IndexOutOfRangeException`. **Handling the input the signature accepts was chosen over narrowing
the signature.**

**`header_length_varint_widths` is renamed `header_length_varint_widths_whole_recording`**, because
it scopes over every datagram while the two `crypto_*_varint_widths` rows scope over the Initial
flight — which is why the default profile reads `[2, 1]`, the `1` coming from datagram 1, outside
the flight. A reader of the snapshot cannot see the code comment that used to be the only
explanation.

**The ledger is 33 rows, 25 killed, 8 survived** — self-checks re-run literally against the file.
The eight survivors are 3 unreachable-by-construction, 1 vacuous, 4 unwitnessed **by this corpus**.
Two survivor classifications were independently re-confirmed and left alone: M12 (padding counted
per byte) is genuinely vacuous — `padding += 2` KILLS, so the field has a witness and the `+= 1`
expressions are identical — and `Distinct`'s first-seen order is real, not incidental (`.OrderBy`
kills two tests). M22's wording is narrowed from *unwitnessed* to *unwitnessed by this corpus*: a
recording with a padded ACK-only Initial would separate it, so it is not unwitnessable.

---

## Amendments after task 9b

**THE TASK'S "§7.3, DRIVEN FROM `ScriptedDatagramTransport`" IS IMPOSSIBLE, AND THE DERIVATION IS
in that type's own remarks.** Transport parameters arrive inside EncryptedExtensions, which is
Handshake-level CRYPTO, and the scripted double says what it cannot do: *"It cannot fabricate a
Handshake or 1-RTT packet: those keys descend from the client ephemeral share, which differs on
every run, so a fabricated one never decrypts and neither does a real server response recorded
once and replayed."* §7.3 is therefore driven from `LoopbackQuicPeer` with a server whose
connection ID parameters are **doctored in the test** — which keeps the property the instruction
was really asking for, a mismatched value that exists only in the test file and cannot be a
restatement of anything the connection computed. The other four of the five are scripted, with
hand-built Initial-level bytes, exactly as asked.

**THE LOOPBACK SERVER WAS NOT §7.3-CONFORMING, AND EIGHTEEN TESTS SAID SO THE MOMENT THE CLIENT
CHECKED.** `CustomTlsQuicServer` sends `_configuration.TransportParameters` verbatim and adds
nothing, and the test configuration carried only `active_connection_id_limit` — so every
loopback-driven handshake in this phase ran against a server that omitted both parameters §7.3
makes mandatory: *"An endpoint MUST treat the absence of the initial_source_connection_id
transport parameter from either endpoint or the absence of the original_destination_connection_id
transport parameter from the server as a connection error of type TRANSPORT_PARAMETER_ERROR."*
The fix is test-side (the server now advertises both), and the shape is worth naming: **the
cooperative peer this plan keeps warning about was not merely cooperative, it was
non-conforming**, and only a client that enforced the MUST could tell.

**The connection IDs now move to the constructor.** A conforming server has to know the client's
first Destination Connection ID to advertise `original_destination_connection_id`, and drawing
both IDs in `StartAsync` made that unknowable until after the first packet had already been sent.
Finding 1's ordering is untouched: the Source Connection ID still exists before the factory that
must advertise it is called, which is the only sequencing that constraint fixes.

**§7.3's `initial_source_connection_id` is compared against the connection ID we ADDRESS, not the
one we OBSERVED, and the first draft had it the other way round.** The mutation sweep reported the
two as inseparable — no test could tell them apart, because against any peer that behaves they are
the same bytes. §7.3's own sentences separate them: *"The values provided by a peer for these
transport parameters MUST match the values that an endpoint used in the Destination and Source
Connection ID fields of Initial packets that it sent"*, and after §7.2's adoption the Destination
Connection ID field we USE is the adopted one. The purpose clause settles which reading is meant:
*"Including connection ID values in transport parameters and verifying them ensures that an
attacker cannot influence the choice of connection ID for a successful connection by injecting
packets carrying attacker-chosen connection IDs during the handshake."* Under the observed-value
reading an injected first Initial moves the adoption, the parameter still agrees with the honest
server's Source Connection ID, and **the connection SUCCEEDS while addressing the attacker's
value** — the exact outcome that sentence exists to deny. It is now witnessed with **zero key
material**: a datagram sealed with §5.2's *client* secret cannot open at a client, but §7.2's
adoption necessarily runs before the AEAD, so the forgery moves the Destination Connection ID and
§7.3 is what catches it two flights later. **A survivor that turns out to be a defect rather than
a missing test is the most valuable thing a sweep produces, and this is the second one this phase
has had.**

**Every §7.3 arm closes with TRANSPORT_PARAMETER_ERROR, and three of the five had a choice.** §7.3
names TRANSPORT_PARAMETER_ERROR alone for the two absences, and offers *"a connection error of type
TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION"* for the retry_source absence, the retry_source
presence, and any mismatch. §20.1 settles the choice, because the two definitions are not
symmetrical: TRANSPORT_PARAMETER_ERROR (0x08) is *"An endpoint received transport parameters that
were badly formatted, included an invalid value, omitted a mandatory transport parameter, included
a forbidden transport parameter, or were otherwise in error"* — a mismatch is an invalid value, an
absence after a Retry is an omitted mandatory parameter, and a presence without one is a forbidden
parameter, so all three are **named clauses of 0x08** — while PROTOCOL_VIOLATION (0x0a) is *"An
endpoint detected an error with protocol compliance that was not covered by more specific error
codes"*, which defers by its own words wherever 0x08 applies.

**PATH_RESPONSE CANNOT BE SENT BY A4-MINIMAL, AND THE TASK'S "IT IS THREE LINES" ASSUMED A LEVEL
THIS PHASE CANNOT BUILD.** RFC 9000 §12.4 Table 3 gives PATH_CHALLENGE the row `__01` and
PATH_RESPONSE the row `___1`: a peer can only send us a challenge in a 0-RTT or 1-RTT packet, and
the answer may go **only** in a 1-RTT packet — which needs a short header, which
`TlsQuicPacketBuilder` does not build. This is the same shape as the Application-level ACK the
connection already skips, with the same owner (task 14). What is implemented is the half that can
be: the eight bytes are recorded off the frame, witnessed by a real PATH_CHALLENGE riding beside
HANDSHAKE_DONE in the only 1-RTT packet this tree builds, and the test asserts that **no datagram
follows**, so the gap is pinned rather than merely stated.

**The Retry re-derivation ordering holds against task 9a-i's throw, and the reason is a guard
rather than an assumption.** `TlsQuicKeySet.InstallInitialKeys` throws once Initial has been
discarded; §4.9.1 discards Initial when this client first **sends** a Handshake packet; sending one
requires Handshake write keys, which come out of a server Initial packet the AEAD opened, which
sets the flag §17.2.5.2's *"After the client has received and processed an Initial or Retry packet
from the server, it MUST discard any subsequent Retry packets that it receives"* is enforced by.
So every state in which the discard has happened is a state in which the once-only guard has
already returned, and the dependency is one-way. It is recorded at the call site as what the guard
costs if anyone widens it, not as a comment claiming the throw is unreachable in general.

**A THROW ON A VERSION NEGOTIATION PACKET IS A THROW ON UNAUTHENTICATED INPUT, AND IT NEEDED THE
RFC'S OWN TWO GUARDS BEFORE IT WAS SAFE TO WRITE.** RFC 9001 §5 gives that packet type no
protection whatsoever, and A4-minimal *reports and fails* on one — which is a remote kill switch
unless something stands in front of it. Two things do, and both are the RFC's: the rule
`TlsQuicVersionNegotiation`'s contract already states, that a VN packet MUST be ignored once a
packet for the connection has been successfully processed (and *processed* here means the AEAD
opened it, not that a parser liked it); and §17.2.1's echo requirement, whose point the RFC states
outright — *"Echoing both connection IDs gives clients some assurance that the server received the
packet and that the Version Negotiation packet was not generated by an entity that did not observe
the Initial packet."* An on-path attacker still wins, and that is the RFC's position rather than a
gap here: §10.2.3, *"QUIC does not include defensive measures for on-path attacks during the
handshake."* **The first draft of this task's VN handling had no echo check at all, which would
have shipped the third off-path kill switch of the phase.**

**§10.1's idle timeout needed a second deadline in the receive, and the attribution rule is a
COMPARISON rather than a test for expiry.** A peer that answers LATE is caught by the `GetUtcNow`
check after the receive; a peer that goes SILENT never produces a clock reading and is ended by the
token source, which runs on `TimeProvider`'s own timer while a fake `GetUtcNow` has not moved at
all — so on a fake clock both remainings are still positive and only their ORDER says which bound
armed the token. `RemainingBeforeIdleTimeout() <= RemainingBeforeDeadline()` is the rule, and it
is the same rule in the LATE case, where both are negative and the more negative one expired first.

**Two of §10.1's clauses are load-bearing in opposite directions and both are witnessed.** The
timeout is *silent* at the effective value — *"the connection is silently closed and its state is
discarded"* — so no CONNECTION_CLOSE goes out; but *"By announcing a max_idle_timeout, an endpoint
commits to initiating an immediate close (Section 10.2) if it abandons the connection prior to the
effective value"*, and the handshake deadline is exactly such an abandonment, so **it now sends a
NO_ERROR close** when this endpoint advertised one. The mutation ledger's rows for both are in
`TlsQuicConnection.cs`.

**§10.1's three-times-PTO floor is NOT implemented, and it is A3's to close.** *"To avoid
excessively small idle timeout periods, endpoints MUST increase the idle timeout period to be at
least three times the current Probe Timeout (PTO)."* There is no current PTO because loss recovery
is deferred; the consequence is one-directional — this connection can give up EARLIER than the
floor, never later — and it is recorded as a knowingly unimplemented MUST rather than left to be
discovered.

**`max_idle_timeout` is a peer-chosen 62-bit millisecond count, and converting it naively is a
remote kill switch.** §16's largest varint is about 146 million years and overflows both `TimeSpan`
and every `DateTimeOffset` sum built from one. The conversion saturates at a year, witnessed by a
server advertising 2^62-1.

**A NULLABLE THAT COULD NEVER BE NULL, FOUND BY A FAILING TEST RATHER THAN BY REVIEW.**
`ReadOnlyMemory<T>` declares an implicit conversion from `T[]?`, so in
`x is { } v ? new ReadOnlyMemory<byte>(v) : null` the conditional's natural type is
`ReadOnlyMemory<byte>` and **not** the nullable: the null literal converts through that operator
into an EMPTY memory, which is then lifted into a nullable that HAS a value. Both that form and
the plainer `=> _field` report "a Retry happened, carrying a zero-length connection ID" for every
connection that never saw one — and §7.3 turns on exactly that distinction, since *"If a
zero-length connection ID is selected, the corresponding transport parameter is included with a
zero-length value."* **Absent and empty are different states, and the C# that looks like it says so
does not.** The cast on the null branch is load-bearing; anything returning
`ReadOnlyMemory<byte>?` from a nullable array in this codebase should be read again.

**Two deadline tests had to move their idle timeout out of the way**, because the 30-second default
is nearer than the hour those tests use, and the receive is bounded by the nearer of the two. That
is not a workaround: it is the first evidence that the two deadlines are ordered at all, and the
tests say which one they mean.

**The ledger is 89 rows: 61 killed on first run, 17 was-survivors, 11 surviving.** Rows 47-85 are
task 9b's, run against the 1104-test gate; rows 86-89 are its review fix round's, run against
1108. The three self-checks in `TlsQuicConnection.cs` were re-run literally and return
89 / 17 / 11, which reconciles as 89 − 17 − 11 = 61.

**The row that survived 9b was reclassified by the fix round, and its recorded reason was false.**
Row 71 — §10.1's *"if no other ack-eliciting packets have been sent since last receiving and
processing a packet"* condition — was filed *unreachable by construction* because *"this loop
makes at most one ack-eliciting send per received packet"*. **That is not true.** `StartAsync`'s
opening flight and `HandleRetryAsync`'s answer are two ack-eliciting sends with no processed
packet between them: a Retry reaches no AEAD, so it sets neither `_processedServerPacket` nor
`_idleSince`. What actually made the guard unfireable was that `StartAsync` wrote `_idleSince`
directly and **never set `_sentAckElicitingSinceReceive`** — and that omission was itself a §10.1
divergence, measured as one: a Retry answered nine minutes into a ten-minute idle bound moved the
deadline out to nineteen. **Two contradictory readings of the same sentence each passed the whole
1104-test gate.** The fix round set the flag, added the witness that separates them, and row 71 is
now a kill. **A survivor whose recorded justification is false is worse than an unrecorded one**,
because the next reader trusts it — and A3's retransmission is a second ack-eliciting send in
exactly this silence.

**Two mutants measured something other than what they named, and the correction is the lesson.**
The first form of the peer-close row INVERTED the branch instead of deleting it, so every packet
entered draining and 37 tests died — a number that says nothing about the check. And the first
form of the Retry re-derivation row anchored on a line that appears TWICE in the file, so it
neutered `StartAsync`'s Initial key installation rather than the Retry's and killed 72. **A
mutation is evidence only when its anchor is unique and its edit is a deletion**; a large kill
count is a signal to re-read the mutant, not a stronger result.

**A neutered branch has to be written against a non-constant.** This repo builds CS0162
(unreachable code) as an error, so `if (false)` does not compile and a sweep that writes it
measures nothing — fourteen of the first run's rows came back BUILD-ERROR before the helper was
introduced. Whoever runs the next sweep starts from that.

**And a pure DELETION has a second way to fail to compile: CS0414.** *Found by the fix round.*
Row 71's mutant deletes `RestartIdleTimerOnAckElicitingSend`'s guard — which is
`_sentAckElicitingSinceReceive`'s only **read**. Deleting it makes the field write-only and
warnings-as-errors fails the build, so the mutant measured nothing on its first attempt. It was
re-run as `_ = _sentAckElicitingSinceReceive;` in place of the guard: the early return gone, which
is the deletion's whole behaviour, with the read kept so the build stands. **When a guard is a
field's only reader, deleting it is a build failure, not a mutation** — keep the read, drop the
effect.

---

## What task 9b's review fix round changed

*Appended after both review gates returned "ship" with findings. Gate throughout:
`dotnet test --filter "FullyQualifiedName~Quic"` — never the full suite, which masks two
pre-existing failures. **1104 passed / 0 failed before, 1108 / 0 after**, the four being the round's
own witnesses.*

**§6.2 carries THREE normative rules and only two were implemented — this is the security finding.**
Read past the extract's line wrap, which is where the third one hides: *"A client that supports only
this version of QUIC MUST abandon the current connection attempt if it receives a Version
Negotiation packet, with the following two exceptions. A client MUST discard any Version
Negotiation packet if it has received and successfully processed any other packet, including an
earlier Version Negotiation packet. **A client MUST discard a Version Negotiation packet that lists
the QUIC version selected by the client.**"* The third was missing, and the spec reviewer's mutant
for it survived 1104/0 — nothing pinned it either way. **The consequence was a live hole:** §17.2.1's
echo check proves only that the sender *observed* our Initial, and it says exactly that much —
*"Echoing both connection IDs gives clients some assurance that the server received the packet and
that the Version Negotiation packet was not generated by an entity that did not observe the Initial
packet"* — so an off-path attacker who did observe it ended the attempt with a VN offering only
`0x00000001`. The echo check stops the **unobserved** attacker; §6.2's third rule stops the
**observed** one, and the source now says which does which. Two witnesses, because §6.2 says
*"lists"* and not *"lists only*": a membership test, not an equality test on a one-element list.

**§17.2.5.1's identical-SCID check compared the wrong operand.** The RFC names *"the Destination
Connection ID field of **its Initial packet**"* — the client's own first Initial, which is
`OriginalDestinationConnectionId` and never moves. The operand was `_destinationConnectionId`,
which §7.2's adoption moves off **unauthenticated** input: an injected Initial that never opens
still takes the once-only adoption with it and leaves `_processedServerPacket` false, so control
reaches the check with the operand replaced by a value the attacker chose — and a Retry echoing our
true original Destination Connection ID, precisely what §17.2.5.1 forbids, compared unequal and was
accepted. Spec review's mutant for this survived; it is row 87 now and it kills.

**Two justifications were false while their conclusions were right, and both were rewritten.**
(a) The §7.3 remark argued that reading unauthenticated input is unavoidable because *"the Initial
keys cannot be derived from a value this packet supplies, so the adoption necessarily precedes the
AEAD"*. **That does not follow.** The Initial keys come from `OriginalDestinationConnectionId`,
which never moves, so the AEAD opens the packet either way; and `_validatedServerSourceConnectionId`
— recorded only after `outcome.Processed > 0` — is standing proof that a post-AEAD hook exists.
Pre-AEAD adoption is a **choice** (§7.2 phrases the rule on *"upon first receiving an Initial or
**Retry** packet"*, and a Retry reaches no AEAD, so one placement covers both triggers), and §7.3
is what makes the choice safe. The same false sentence had been copied into two test files and was
corrected in all three. (b) The Retry dispatch still said *"the order of the FOUR checks"* after
`a08a76d` restored the version check as a fifth — corrected, along with "the once-only rule comes
first", which the restored check had also made untrue.

**Row 89 survives, and the reviewer's reason for it covers only half of it.** The mutant drops
§10.1's ack-eliciting condition on the answer datagram (`crypto.Count > 0` → `>= 0`), making an
ACK-only datagram restart the timer. The reviewer called it **vacuous** because the call receives
the same `now` already assigned to `_idleSince` — and for `_idleSince` that is airtight rather than
merely likely: `written > 0` with no CRYPTO means the datagram carries an ACK, an ACK means
something was processed in this pump, and processing is what performs that assignment. **But the
call also flips `_sentAckElicitingSinceReceive` from false to true**, which is a real state
difference. It is unobservable only because A4-minimal has no second ack-eliciting send in that
window — the Retry answer is the sole candidate and a Retry after a processed packet is discarded,
and CONNECTION_CLOSE is not ack-eliciting (§2). So the honest classification is **vacuous on the
timer, unreachable by construction on the flag**, and **A3's retransmission makes it reachable**.
No test, per the rule for survivors of this kind.

**Three numbers the round was briefed with were wrong and are corrected here**, since a wrong
figure in a handoff propagates: the file is **962 code lines / 1430 comment-and-blank / 2392 raw**
(`grep -vcE '^\s*(//|$)'`) and was 956 before this round — not "~1230 code / ~1090 comment"; there
are **five** Retry discard rules, not four; and row 71 was **not** unreachable by construction for
the reason recorded, as above.
