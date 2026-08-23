# QUIC Packet Layer (Phase A1) Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse and serialise every QUIC packet form, apply and remove header and payload protection, and prove it against IETF-published test vectors.

**Architecture:** Pure functions over spans. No sockets, no timers, no connection state. Everything in this phase is verifiable offline against RFC 9001 Appendix A, which publishes a complete worked Initial packet in both directions plus a Retry and a ChaCha20 short-header packet.

**Tech Stack:** C# 13, .NET 9, xunit 2.9.3, `System.Security.Cryptography` (AES-ECB, ChaCha20, AES-GCM).

**Standards:** RFC 9000 §17 and Appendix A.1–A.3; RFC 9001 §5.1–5.4, §5.8 and Appendix A; RFC 9369 for QUIC v2.

---

## Ground truth already in the repo

Do not retype any value from these. Copy them.

| File | Contents |
| --- | --- |
| `docs/superpowers/specs/reference-captures/rfc9001-appendix-a-test-vectors.txt` | Initial keys, client Initial, server Initial, Retry, ChaCha20 short header — all against DCID `0x8394c8f03e515708` |
| `docs/superpowers/specs/reference-captures/rfc9000-packet-formats-and-pn-pseudocode.txt` | RFC 9000 §17 in full, plus Appendix A.1 varint decoding, A.2 packet number encoding, A.3 packet number decoding |

**Every constant in this plan carries its RFC section. Reviewers verify values against the
RFC text, never against the code's comments.** That discipline produced zero wire-format
defects across subsystem D's thirteen tasks and is not optional here.

## What already exists and must be reused

In `src/SharpTls/Quic/`:

- `TlsQuicInitialSecrets.Derive(...)` — Initial secrets from a destination connection ID, QUIC v1 and v2
- `TlsQuicTrafficSecret.DerivePacketProtectionKeys(version)` → `TlsQuicPacketProtectionKeys` with `CopyKey()`, `CopyIv()`, `CopyHeaderProtectionKey()`
- `QuicVariableLengthInteger` — `GetEncodedLength`, `Write`, `Read`, `Encode`, `ReadExact`
- `TlsQuicVersion`, `TlsQuicEncryptionLevel`, `TlsQuicTransportError`, `TlsQuicTransportException`

**Do not reimplement key derivation or varints.** A1 consumes them.

## File layout

All directly under `src/SharpTls/Quic/`. No subfolders — that was tried in subsystem D and
reverted, since every other feature area in this tree is a single flat folder.

| File | Responsibility | Task |
| --- | --- | --- |
| `TlsQuicPacketNumber.cs` | encode/decode truncated packet numbers | 1 |
| `TlsQuicPacketHeader.cs` | long and short header parse/serialise, header types | 2, 3 |
| `TlsQuicHeaderProtection.cs` | AES-ECB and ChaCha20 mask, apply/remove | 4 |
| `TlsQuicPacketProtection.cs` | AEAD seal/open, nonce construction | 5 |
| `TlsQuicRetry.cs` | Retry integrity tag | 6 |
| `TlsQuicVersionNegotiation.cs` | version negotiation packet | 7 |
| `TlsQuicDatagramReader.cs` | coalesced packet splitting | 8 |

Tests mirror these in `tests/SharpTls.Tests/Quic/`.

## Design constraint that governs every task

Subsystem B must be able to control connection ID lengths, initial packet number and its
encoded length, token contents, and frame layout **without rewriting this code**.

Therefore: **no packet-construction function reads a layout decision from a constant.**
Connection ID lengths, packet number length, and token bytes are parameters or come from an
options object. A hardcoded `DestConnIDLength = 8` here turns subsystem B into a rewrite.

---

## Chunk 1: numbers and headers

### Task 1: Packet number encoding and decoding

**Files:** create `src/SharpTls/Quic/TlsQuicPacketNumber.cs`, `tests/SharpTls.Tests/Quic/TlsQuicPacketNumberTests.cs`

RFC 9000 Appendix A.2 and A.3 give both algorithms as pseudocode. It is in the repo file
named above. Transcribe it — do not improvise, and preserve the overflow and underflow
guards exactly; they are the parts that break under adversarial packet numbers.

- [ ] **Step 1: failing tests**

Use the RFC's own worked examples as the primary cases. RFC 9000 §17.1 and Appendix A.2/A.3:

```csharp
    [Fact]
    public void DecodesTheRfcWorkedExample()
    {
        // RFC 9000 A.3: with largest_pn 0xa82f30ea, a 16-bit truncated value
        // of 0x9b32 decodes to 0xa82f9b32.
        Assert.Equal(
            0xa82f9b32UL,
            TlsQuicPacketNumber.Decode(largestPn: 0xa82f30eaUL, truncated: 0x9b32, bits: 16));
    }

    [Fact]
    public void EncodingPicksSixteenBitsForTheRfcWorkedExample()
    {
        // RFC 9000 A.2: acked 0xabe8b3, sending 0xac5c02 leaves 29,519
        // outstanding, so representing twice that range needs 16 bits.
        Assert.Equal(2, TlsQuicPacketNumber.EncodedLength(fullPn: 0xac5c02, largestAcked: 0xabe8b3));
    }

    [Fact]
    public void EncodingPicksTwentyFourBitsForTheRfcWorkedExample()
    {
        // RFC 9000 A.2: same state, sending 0xace8fe needs 24 bits.
        Assert.Equal(3, TlsQuicPacketNumber.EncodedLength(fullPn: 0xace8fe, largestAcked: 0xabe8b3));
    }
```

Add negative and boundary cases: no packets acked yet (`largestAcked` null, so
`num_unacked = full_pn + 1`); a decode near the `1 << 62` ceiling that must not overflow;
a decode near zero that must not underflow; all four legal `bits` values (8, 16, 24, 32).

- [ ] **Step 2:** run, watch fail
- [ ] **Step 3:** implement, transcribing A.2 and A.3 verbatim
- [ ] **Step 4:** run, watch pass
- [ ] **Step 5:** commit `feat(quic): encode and decode truncated packet numbers`

### Task 2: Long header packets

**Files:** create `TlsQuicPacketHeader.cs`, `TlsQuicPacketHeaderTests.cs`

RFC 9000 §17.2. Covers Initial, 0-RTT, Handshake and Retry.

Field order, from the extracted §17.2 text — verify against it, do not trust this table:
Header Form (1) = 1, Fixed Bit (1) = 1, Long Packet Type (2), Type-Specific Bits (4),
Version (32), DCID Len (8), Destination Connection ID (0..160), SCID Len (8), Source
Connection ID (0..160), then type-specific fields. Initial adds Token Length (varint) and
Token; Initial, 0-RTT and Handshake add Length (varint) and Packet Number (8..32).

Requirements:

- Connection ID lengths are **parameters**, not constants. Legal range is 0 to 20 bytes
  (RFC 9000 §17.2 — confirm). A zero-length source connection ID is legal and is what
  Chromium sends.
- Reserved bits and packet number length live in the protected part of byte 0, so the
  parser must accept them still masked and the serialiser must write them before protection
  is applied.
- Parsing is `Try`-shaped and never throws on malformed input. A packet off the network is
  attacker-controlled; a throw here becomes a denial of service once a connection loop exists.
- Retry has no Length or Packet Number and ends with a 128-bit integrity tag (RFC 9001 §5.8).

Tests: round-trip each type; the RFC 9001 Appendix A client Initial header bytes
`c000000001088394c8f03e5157080000449e7b9aec34` parse to the expected fields; CID lengths 0
and 20 both work; a declared length overrunning the buffer is rejected without throwing;
a wrong Fixed Bit is rejected.

- [ ] Steps 1–5 as above, commit `feat(quic): parse and serialise long header packets`

### Task 3: Short header packets

**Files:** modify `TlsQuicPacketHeader.cs` and its tests

RFC 9000 §17.3. Header Form (1) = 0, Fixed Bit (1) = 1, Spin Bit (1), Reserved (2),
Key Phase (1), Packet Number Length (2), Destination Connection ID, Packet Number, Payload.

The destination connection ID has **no length field** — the receiver knows its own CID
length from the connection state. So the parser takes that length as a parameter. This is
the single most common short-header parsing mistake.

Tests: round-trip; the RFC 9001 A.5 ChaCha20 short-header packet parses; spin and key-phase
bits survive; a zero-length CID works.

- [ ] Steps 1–5, commit `feat(quic): parse and serialise short header packets`

---

## Chunk 2: protection

### Task 4: Header protection

**Files:** create `TlsQuicHeaderProtection.cs` and tests

RFC 9001 §5.4. The pseudocode is in §5.4.1 and is reproduced here because it is short and
exact — but check it against the RFC text anyway:

```
mask = header_protection(hp_key, sample)

pn_length = (packet[0] & 0x03) + 1
if (packet[0] & 0x80) == 0x80:
   # Long header: 4 bits masked
   packet[0] ^= mask[0] & 0x0f
else:
   # Short header: 5 bits masked
   packet[0] ^= mask[0] & 0x1f

packet[pn_offset:pn_offset+pn_length] ^= mask[1:1+pn_length]
```

- Sample is **16 bytes at `pn_offset + 4`** (RFC 9001 §5.4.2).
- AES suites: `mask = AES-ECB(hp_key, sample)`, 128-bit key for AEAD_AES_128_GCM and
  AEAD_AES_128_CCM, 256-bit for AEAD_AES_256_GCM (§5.4.3).
- ChaCha20: first 4 bytes of the sample are the block counter as a **little-endian** 32-bit
  integer, the remaining 12 are the nonce, and the mask is ChaCha20 encrypting **5 zero
  bytes** (§5.4.4).
- Removing protection differs from applying it only in when `pn_length` is read — after
  unmasking byte 0 on removal, before masking on application. Getting this backwards
  produces a packet that decrypts correctly exactly half the time, which is a miserable bug
  to find. Write a test that would catch it.

Tests: the Appendix A client Initial, whose unprotected and protected header bytes are both
published; the A.5 ChaCha20 packet; apply-then-remove round-trips for all four packet number
lengths.

- [ ] Steps 1–5, commit `feat(quic): apply and remove QUIC header protection`

### Task 5: AEAD packet protection

**Files:** create `TlsQuicPacketProtection.cs` and tests

RFC 9001 §5.3. The nonce is the packet protection IV XORed with the packet number, where
the 62-bit packet number is written in network byte order and **left-padded with zeros to
the length of the IV**. The associated data is the packet header from the first byte
through the end of the unprotected packet number. The plaintext is the packet payload.

Order matters and is stated in §5.3: **AEAD first, then header protection** on the way out;
header protection removed first, then AEAD, on the way in.

Tests: the Appendix A client Initial and server Initial both decrypt to their published
plaintexts and re-encrypt to the published ciphertexts. A tampered AAD byte must fail
authentication. A tampered ciphertext byte must fail authentication.

- [ ] Steps 1–5, commit `feat(quic): seal and open QUIC packet payloads`

### Task 6: Retry integrity

**Files:** create `TlsQuicRetry.cs` and tests

RFC 9001 §5.8. AEAD_AES_128_GCM with the fixed key `0xbe0c690b9f66575a1d766b54e368c84e`,
over a Retry pseudo-packet that prepends the original destination connection ID and its
length to the Retry packet with the tag removed. Take the nonce from the RFC text; do not
guess it.

QUIC v2 uses different constants (RFC 9369) — implement v1 now, and structure the code so
v2 is a table lookup rather than a second code path.

Tests: the Appendix A.4 Retry vector verifies; a single flipped byte anywhere in the pseudo
packet fails verification.

- [ ] Steps 1–5, commit `feat(quic): compute and verify the Retry integrity tag`

---

## Chunk 3: framing edges

### Task 7: Version Negotiation

**Files:** create `TlsQuicVersionNegotiation.cs` and tests

RFC 9000 §17.2.1. Version field is `0x00000000`; the body is a list of 32-bit versions. It
has **no cryptographic protection at all** (RFC 9001 §5), so it must be treated as
unauthenticated: a client uses it only to select a version for a fresh connection attempt
and must ignore it once a packet has been successfully processed.

Tests: parse and serialise; an empty version list; a truncated list rejected without throwing;
a body length not a multiple of 4 rejected.

- [ ] Steps 1–5, commit `feat(quic): parse version negotiation packets`

### Task 8: Coalesced packets

**Files:** create `TlsQuicDatagramReader.cs` and tests

RFC 9000 §12.2. One UDP datagram may carry several QUIC packets. Long header packets carry
a Length field, so a reader walks them; a short header packet has no length and therefore
**must be the last packet in the datagram**.

RFC 9000 §12.2 also requires that a packet which cannot be processed is discarded while the
rest of the datagram is still processed — so a decryption failure on packet 1 must not
discard packet 2.

Tests: a datagram with Initial + Handshake coalesced; Initial + 1-RTT where the short header
is last; a short header followed by trailing bytes must not be treated as another packet;
a truncated trailing packet is dropped while earlier packets survive.

- [ ] Steps 1–5, commit `feat(quic): split coalesced packets from one datagram`

---

## Task 9: consolidation pass — added after task 3's review

Runs after task 4 lands and before tasks 5 and 8, because both would otherwise copy the
patterns being fixed here. Pure refactor plus two tests; no new behaviour.

**Files:** `TlsQuicPacketHeader.cs`, `TlsQuicVersionNegotiation.cs`, and both test files.

1. **Extract the shared connection ID codec.** `WriteConnectionId` is byte-for-byte identical
   in both files, and `TryReadConnectionId` differs only by a bound check that is always false
   at 255. Extract one helper parameterised by maximum length:
   `TryReadConnectionId(ReadOnlySpan<byte> datagram, ref int offset, int maxLength, out ...)`.
   Task 3's commit introduced the second copy; tasks 5 and 8 would add a third and fourth.
   This is bounds-check parsing on attacker-controlled input and must not exist twice.

2. **Stop copying on every parse.** `.ToArray()` runs up to five times per packet — destination
   and source connection IDs, token, packet number, Retry integrity tag — forced by taking
   `ReadOnlySpan<byte>`, since a span-derived slice cannot be stored in a `ReadOnlyMemory<byte>`
   field. Change the parse input to `ReadOnlyMemory<byte>`, deriving `.Span` internally for
   `BinaryPrimitives` and slicing for stored fields.

   This fits the stack: `ITlsQuicDatagramTransport.ReceiveAsync` already hands the caller a
   `Memory<byte>`, so socket to parsed header becomes copy-free end to end. Task 8's coalesced
   datagram walk is the hot path that makes it matter, and changing the signature after that
   loop exists is far more expensive.

   If any copy turns out to be genuinely required — a caller reusing a pooled buffer beyond the
   packet's lifetime — keep it and mark it with a comment saying why, rather than leaving it
   unexplained.

3. **Collapse the repeated validation blocks.** The connection ID length bound appears three
   times near-identically, the packet number length range twice, the packet number length match
   twice. Two small private helpers remove the drift risk.

4. **Pin the untested half of a combined check.** The long header's
   `length < packetNumberLength || length > remaining` has only its second clause isolated by a
   test. Deleting the first clause survives all 41 cases. Add one case pinning
   `length < packetNumberLength` alone, with the rest of the datagram complete, following the
   existing "all bytes present" pattern.

## Status: COMPLETE, 2026-08-17

All ten tasks implemented and through both review gates. 1,754 lines of production code
against 3,168 lines of test; 272 tests matching the `~Quic` filter, zero failures.

Six defects were found by review that a passing suite did not surface:

1. A `floor(log2)` off-by-one in packet number length. Both RFC 9000 A.2 worked examples sit
   at bit widths where the correct formula and two plausible wrong ones agree.
2. `Decode`'s two wraparound branches were never entered by any test — every case hit the
   guard rather than the adjustment. Deleting either `return` left the suite green.
3. An integer overflow in the header protection sample bounds guard, breaking the documented
   never-throws contract for packet number offsets near `int.MaxValue`.
4. The AEAD nonce was not zeroed. Since `nonce = IV XOR packet_number` and the packet number
   is public, a leaked nonce recovers the secret IV directly.
5. `TlsQuicRetry.TryVerify` threw on a peer-controlled version field, on the one packet type
   whose entire threat model is off-path forgery.
6. A connection ID bound test that passed only because an unrelated length check fired first.
   Deleting the bound left all 15 tests green.

Plus a gap no defect list captures: truncating the packet number to 32 bits in the AEAD nonce
passes **all three** RFC 9001 vectors and a ciphertext-distinctness check. It is caught only by
a test added after a reviewer corrected a claim about what those vectors cover. That bug would
work correctly until packet number 2^32, then cause nonce reuse under AES-GCM.

The general lesson, since it recurred in nearly every task: **published RFC vectors demonstrate
an algorithm on representative input. They are not adversarial, and they cannot distinguish a
correct implementation from a plausible misreading.** Where a branch exists to handle an edge
case, delete it and confirm a test fails. Where a bounds check exists, construct input that
only that check can reject.

## Done when

- Every RFC 9001 Appendix A vector reproduces exactly: client Initial, server Initial,
  Retry, ChaCha20 short header.
- Every RFC 9000 Appendix A.2/A.3 worked example reproduces.
- `dotnet test --filter "Category!=Interop"` is green.
- A fuzz target exists for every parser that touches network bytes, and none of them throws.
- No layout decision — connection ID length, packet number length, token — is hardcoded.

## Not in this phase

Frames (A2), loss detection and congestion control (A3), connection and stream state (A4),
the fingerprint spec layer (B), HTTP/3 (C). This phase produces no network traffic.
