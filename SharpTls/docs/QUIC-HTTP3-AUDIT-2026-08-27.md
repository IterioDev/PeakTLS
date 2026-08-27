# QUIC / HTTP-3 codepath audit — 2026-08-27

Scope agreed with the requester: **wire correctness** and **concurrency / object lifetime**.
Fingerprint fidelity (transport-parameter ordering, ClientHello profile, datagram shaping,
SETTINGS composition) was explicitly deferred to a later sweep and is **not** covered here.

Surface: `SharpTls/src/SharpTls/Quic/` — 59 files, 44,646 lines. Navigation and clustering came
from the graphify knowledge graph (`graphify-out/graph.json`, built 2026-08-27 14:22, after
`27f528f`); the graph's community partition supplied the nine audit clusters below and its hub
ranking picked the read order. Findings are from reading the source those clusters named.

Nothing has been changed. This is the pre-fix report.

| Cluster (graphify community) | Files |
|---|---|
| c96 / c119 keys | `TlsQuicSecrets`, `TlsQuicKeySet`, `TlsQuicPacketProtection`, `TlsQuicHeaderProtection`, `TlsQuicRetry` |
| c167 packet plane | `TlsQuicPacketHeader`, `TlsQuicPacketNumber`, `TlsQuicPacketBuilder`, `TlsQuicPacketReceiver`, `TlsQuicDatagramReader/Builder`, `QuicVariableLengthInteger` |
| c36 frames | `TlsQuicFrames`, `TlsQuicStreamFrames`, `TlsQuicAckFrames`, `TlsQuicConnectionFrames`, `TlsQuicFlowControlFrames`, `TlsQuicFrameLegality` |
| c129 / c173 recovery | `TlsQuicAckTracker`, `TlsQuicLossDetection`, `TlsQuicCongestionControl`, `TlsQuicRecoverySpec`, `TlsQuicPathMtu` |
| c44 streams | `TlsQuicStreams`, `TlsQuicPeerFlowControlBudget`, `TlsQuicApplicationSendPath` |
| c46 / c244 / c94 connection | `TlsQuicConnection`, `CustomTlsQuicClient/Server`, `TlsQuicCryptoStreamReassembler`, `TlsQuicEvents` |
| c38 / c192 HTTP/3 | `TlsQuicHttp3Connection/Frames/Request/Streams/Spec` |
| c98 / c130 QPACK | `TlsQuicQpackDecoder`, `…DynamicTable`, `…Huffman`, `…Primitives`, `…StaticTable` |

---

## Severity summary

| # | Severity | Title | Location |
|---|---|---|---|
| 1 | **Critical** | 1-RTT packets sealed with an all-zero key after a local key update | `TlsQuicApplicationSendPath.cs:660-669` (+3 sites) |
| 2 | **Critical** | Quadratic memory amplification in stream reassembly | `TlsQuicStreams.cs:961-1022` |
| 3 | **High** | RESET_STREAM is parsed, validated, then discarded — response never completes | `TlsQuicConnection.cs:2330`, `TlsQuicStreams.cs:1782` |
| 4 | **High** | CRYPTO data silently dropped when a level's write keys are discarded | `TlsQuicConnection.cs:5086-5154` |
| 5 | **High** | Packet-number counter not advanced when the Initial flight fails to send | `TlsQuicConnection.cs:4669-4682` |
| 6 | **High** | Unbounded buffering on HTTP/3 control, QPACK-encoder and request streams | `TlsQuicHttp3Streams.cs:426-431`, `TlsQuicHttp3Request.cs:1508-1511` |
| 7 | **Medium-High** | Destination Connection ID adopted from an unauthenticated packet | `TlsQuicConnection.cs:2774-2778` |
| 8 | **Medium-High** | MAX_STREAMS credit is granted but refused on use | `TlsQuicStreams.cs:1394-1427` vs `:1639-1644` |
| 9 | **Medium** | Peer protocol violations throw locally instead of sending CONNECTION_CLOSE | `TlsQuicConnection.cs:2450-2474`, `:3065-3074` |
| 10 | **Medium** | CONNECTION_CLOSE sent at one level only during the handshake | `TlsQuicConnection.cs:5421-5527` |
| 11 | **Medium** | Inbound MAX_STREAMS ignored — connection dies at the initial stream limit | `TlsQuicConnection.cs:2426` (default arm) |
| 12 | **Medium** | Oversized first frame can overrun the datagram budget | `TlsQuicStreams.cs:1544-1573` |
| 13 | **Low-Medium** | `EncodedLength` can return 5 for a packet-number field capped at 4 | `TlsQuicPacketNumber.cs:12-49` |
| 14 | **Low-Medium** | CONNECTION_CLOSE-only packets counted as in-flight | `TlsQuicPacketBuilder.cs:847-857` |
| 15 | **Low** | Idle timeout does not apply RFC 9000 s10.1's `max(3×PTO, …)` floor | `TlsQuicConnection.cs:5716` |
| 16 | ~~Low~~ **WITHDRAWN** | ~~GOAWAY recorded but never enforced~~ — false positive, see below | `TlsQuicHttp3Streams.cs:841-863` |
| 17 | **Low** | CRYPTO reassembler allocates its whole ceiling on one far-offset frame | `TlsQuicCryptoStreamReassembler.cs:100-111` |
| P1–P7 | Perf | See the performance section | various |

The whole QUIC layer contains **no synchronisation primitives** (one `SemaphoreSlim` each in
`CustomTlsQuicClient`/`Server`, one `volatile` in the SOCKS5 transport, nothing in
`TlsQuicConnection`, `TlsQuicStreamSet`, `TlsQuicPacketReceiver` or `TlsQuicKeySet`). Single-thread
affinity is therefore a hard, unstated precondition. Finding 1 is the sharpest consequence of that
model, but the precondition itself should be documented and asserted.

---

## 1. Critical — 1-RTT packets sealed with an all-zero key after a local key update

`TlsQuicKeySet.TryGetWriteKeys` hands back a `TlsQuicWriteKeyMaterial`, a `ref struct` whose `Key`,
`Iv` and `HeaderProtectionKey` are `ReadOnlySpan<byte>` **over the live internal arrays**
(`TlsQuicKeySet.cs:558-579`, `:779-800`). `WriteKeys.Dispose()` zeroes those arrays in place
(`TlsQuicKeySet.cs:749-754`), and `ApplyKeyUpdate` disposes the outgoing `WriteKeys` after
installing the replacement (`TlsQuicKeySet.cs:265-266`).

Every 1-RTT send path captures that span **before** calling `ShortHeaderPlan()`, and copies the key
**after**:

```csharp
// TlsQuicApplicationSendPath.cs:528
if (!_keys.TryGetWriteKeys(TlsQuicEncryptionLevel.Application, out var keys, out _)) …

// TlsQuicApplicationSendPath.cs:660
packet = new TlsQuicPacketToSend
{
    Plan = ShortHeaderPlan(),          // 662 — may run a key update
    Frames = frames,
    PacketProtectionCipher = keys.PacketCipher,
    Key = keys.Key.ToArray(),          // 665 — copies the array ShortHeaderPlan just zeroed
    Iv = keys.Iv.ToArray(),
    HeaderProtectionCipher = keys.HeaderCipher,
    HeaderProtectionKey = keys.HeaderProtectionKey.ToArray(),
};
```

`ShortHeaderPlan()` sets `KeyPhase = ProtectOneMoreApplicationPacket()`
(`TlsQuicApplicationSendPath.cs:711`), which calls `ApplyKeyUpdateIfNeeded()` (`:746-762`). When the
confidentiality limit is reached (`TlsQuicConnection.cs:1595-1620`, 2^23 packets for AES-GCM) that
runs `_keys.ApplyKeyUpdate(locallyInitiated: true)` — and `keys.Key` / `keys.Iv` /
`keys.HeaderProtectionKey` now span zeroed memory. C# object initialisers assign in source order, so
the copies at lines 665-670 capture zeros while `KeyPhase` already reports the *new* phase.

Result: the packet is AEAD-sealed and header-protected under all-zero keys with the new phase bit
set. The peer cannot decrypt it, cannot distinguish it from forgery, and the connection dies
silently. `_lowestApplicationPacketNumberInWritePhase` is additionally off by one, because
`PacketNumber = _nextPacketNumber[Application]++` (`:689`) runs before the update records the
"lowest packet number in the new phase" as the *next* number.

Same shape at three more sites, all `keys` captured then `ShortHeaderPlan()` then `keys.Key.ToArray()`:

- `TlsQuicConnection.cs:4248` / `:4258` / `:4267` — `TryBuildPathMtuProbeDatagram`
- `TlsQuicConnection.cs:4419` / `:4430` / `:4439` — `TryBuildProbeDatagram`
- `TlsQuicConnection.cs:5427` / `:5495` / `:5499` — `BuildCloseDatagram`

**Reachability.** The confidentiality-limit path needs ~8.4 M 1-RTT packets (≈10 GB at 1200 B) on
one connection — rare but not hypothetical for a long-lived HTTP/3 session. The peer-initiated
branch of `ApplyKeyUpdateIfNeeded` is consumed earlier in `PumpOnceAsync` (`:2548`), before
`SendAnswerAsync` (`:2552`), so it does not currently reach this ordering; that is a scheduling
accident, not a guarantee, and it breaks the moment a send path runs between a receive and the pump's
`ApplyKeyUpdateIfNeeded`.

**Fix direction.** The root cause is the `ref struct`-of-spans API, not the four call sites. Either
make `TryGetWriteKeys` return owned copies, or re-fetch the key material *after* the plan is built.
The one-line variant — moving `Plan =` to last in each initialiser — fixes the symptom at all four
sites but leaves the trap armed for the next caller.

## 2. Critical — quadratic memory amplification in stream reassembly

`TlsQuicStream.Buffer` stores every distinct STREAM-frame offset verbatim
(`TlsQuicStreams.cs:961-982`), while connection-level flow control only charges the *advance* past
the highest offset seen so far (`:871-876`, `TryAdmitConnectionData`).

A peer with a window of W bytes sends, in this order:

```
(offset=1, len=W-1)   -> advance = W, charged once
(offset=2, len=W-2)   -> advance = 0, free
(offset=3, len=W-3)   -> advance = 0, free
...
(offset=0, len=W)     -> last, so nothing drains until here
```

Nothing drains until the final frame (each `offset > _delivered.Count`), so `_undelivered` holds
roughly W²/2 bytes against W bytes of flow-control credit. A 256 KB window yields ~32 GB; a 1 MB
window ~500 GB. `Buffer`'s only dedup is an exact-offset key lookup (`:977-980`), which these frames
all miss.

`Drain` compounds it (`:992-1022`): `do { foreach (var offset in _undelivered.Keys.ToList()) … } while (moved)`
allocates a fresh key list per pass and can need one pass per buffered chunk — O(k²) time plus k
allocations for k out-of-order chunks.

**Fix direction.** Account buffered bytes, not just the advance: charge `_undelivered`'s retained
size against the stream/connection window, or coalesce on insert into a gap list keyed by
non-overlapping ranges (which also collapses `Drain` to O(k log k)).

## 3. High — RESET_STREAM is parsed, validated, then discarded

`TlsQuicConnection.cs:2330` routes RESET_STREAM (and STOP_SENDING, STREAM_DATA_BLOCKED) to
`ReceiveStreamStateSignal`, which calls `TlsQuicStreamSet.TryReceiveStreamStateSignal`
(`TlsQuicStreams.cs:1782-1815`). That method checks only the stream's *direction* and returns. The
frame's `FinalSize` and `ApplicationProtocolErrorCode` are decoded by
`TlsQuicConnectionFrames.TryReadResetStream` and never read.

Consequences:

- `_finalSize` is never set, so `ReceiveComplete` (`TlsQuicStreams.cs:689`) never becomes true.
- `TlsQuicHttp3Request` never sees `endOfStream`, so `IsComplete` stays false
  (`TlsQuicHttp3Request.cs:1564-1585`) and the awaiting caller hangs until the idle timeout.
- The application error code the server sent is lost.
- RFC 9000 s4.5's final-size accounting is skipped, so a RESET_STREAM whose final size contradicts
  data already received is not caught as `FINAL_SIZE_ERROR`.

STOP_SENDING is likewise ignored: this endpoint keeps queueing STREAM frames on a stream the peer has
asked it to stop writing.

## 4. High — CRYPTO data silently dropped when a level's write keys are discarded

In `BuildAnswerDatagram` the pending-CRYPTO loop *consumes* entries out of the `crypto` list into
`frames` (`TlsQuicConnection.cs:5086-5122`, note `crypto.RemoveAt(c--)` at `:5114`). Only afterwards
does the method look for write keys:

```csharp
// TlsQuicConnection.cs:5134
if (!_keys.TryGetWriteKeys(level, out var keys, out var state))
{
    if (state == TlsQuicKeyLevelState.Discarded)
    {
        continue;        // 5153 — `frames` (and the CRYPTO bytes in it) are thrown away
    }
    throw …;
}
```

`RecordRepairable` has not run yet (`:5161`), so the bytes are not retransmittable either. Reachable
whenever Initial CRYPTO is still queued at the moment Initial keys are discarded — the normal
sequence once Handshake keys install. `SendAnswerAsync`'s loop then breaks on `written <= 0`
(`:4787-4790`) with `crypto` shorter than it should be and no error raised, so the handshake stalls
until the abandonment deadline.

**Fix direction.** Hoist the `TryGetWriteKeys` probe above the crypto-consuming loop.

## 5. High — packet-number counter not advanced when the Initial flight fails to send

```csharp
// TlsQuicConnection.cs:4669
var datagrams = BuildInitialFlight(cryptoStream);   // assigns PNs, records them as sent
foreach (var datagram in datagrams)
{
    await SendDatagramAsync(datagram, cancellationToken).ConfigureAwait(false);
}
_nextPacketNumber[(int)TlsQuicEncryptionLevel.Initial] += (ulong)datagrams.Count;   // 4681
```

`BuildInitialFlight` already sealed each packet under its packet number and called
`RetainSentPackets()` (`:4746`). If any `SendDatagramAsync` throws — `SocketError.MessageSize` is a
documented, reachable case, handled explicitly at `:1363` — the counter is never advanced. The retry
path (`HandleRetryAsync` → `SendInitialFlightAsync`, `:3010`) then re-uses the same packet numbers.
Under the Initial keys that is **AEAD nonce reuse for AES-GCM**, since the nonce is
`IV XOR packet_number` (`TlsQuicPacketProtection.cs:187-215`).

The retry path is doubly exposed: it re-derives Initial keys from the new DCID first (`:2999`), so a
partial send *before* the Retry followed by a full send *after* would use different keys — but a
partial send after the Retry, or any local refusal on the first flight, repeats a nonce under one key.

**Fix direction.** Advance the counter where the numbers are assigned, in `BuildInitialFlight`, not
after the awaits.

## 6. High — unbounded buffering on HTTP/3 control, QPACK-encoder and request streams

Three buffers grow only from peer input, with no cap:

- `PeerStreamState.Unparsed` (`TlsQuicHttp3Streams.cs:37`), filled byte-by-byte from
  `stream.Received` at `:427-430`. `TlsQuicHttp3Frames.TryRead` returns `Incomplete` for any frame
  whose declared length exceeds what has arrived (`TlsQuicHttp3Frames.cs:315-318`), and the only
  length rejection is `> int.MaxValue` (`:309`). A control frame declaring 2 GB is buffered whole.
- The same buffer on a QPACK encoder stream: `TlsQuicQpackPrimitives.TryDecodeStringLiteral` returns
  `Truncated` (`:523-527`) which maps to `NeedMoreData` (`TlsQuicQpackDynamicTable.cs:740-743`), so
  the instruction is held indefinitely. A string literal declaring 2^40 bytes parks the stream and
  buffers forever.
- `TlsQuicHttp3Request._pending` and `._body` (`TlsQuicHttp3Request.cs:1508-1511`, `:1613-1616`),
  both `List<byte>` filled one byte at a time.

`TlsQuicStream._delivered` is never trimmed — `Received` (`TlsQuicStreams.cs:682`) exposes the whole
stream and `CreditReceiveWindow` (`:912-948`) keeps raising `_receiveLimit` to
`delivered + _receiveWindow`. So a response body is resident **three times**: `_delivered`,
`_pending`, `_body`.

**Fix direction.** Cap control-stream and encoder-stream frame length at a configured maximum
(H3_EXCESSIVE_LOAD / QPACK_ENCODER_STREAM_ERROR on breach), and consume `_delivered` as it is read
rather than retaining it.

## 7. Medium-High — Destination Connection ID adopted from an unauthenticated packet

`AcceptedUnderSection122` runs **before** `_receiver.Receive` and therefore before any AEAD check:

```csharp
// TlsQuicConnection.cs:2774
if (!_adoptedServerConnectionId)
{
    _destinationConnectionId = longHeader.SourceConnectionId.ToArray();
    _adoptedServerConnectionId = true;
}
```

`_validatedServerSourceConnectionId` — the guard that pins the server's SCID — is only set after
`outcome.Processed > 0` (`:2503-2511`). The client's Initial DCID travels in the clear, so an
off-path attacker who observes or guesses it can inject one long-header packet before the server's
reply and permanently redirect this endpoint's DCID. `_adoptedServerConnectionId` latches, so the
genuine server packet never corrects it.

RFC 9000 s7.2 conditions the switch on a *valid* Initial packet. Confidentiality is not at risk; a
cheap, reliable off-path connection kill is.

**Fix direction.** Defer the adoption to the point where `outcome.Processed > 0`, alongside
`_validatedServerSourceConnectionId`.

## 8. Medium-High — MAX_STREAMS credit granted but refused on use

`CreditPeerStream` (`TlsQuicStreams.cs:1394-1427`) tracks `_peerStreamGranted` and emits MAX_STREAMS
frames raising the peer's limit to `initial + finished`. The receive-side admission check still gates
on the **static** initial value:

```csharp
// TlsQuicStreams.cs:1639
if (TlsQuicStreamId.OrdinalOf(id)
    >= LocalFlowControl.PeerStreamLimitFor(TlsQuicStreamId.DirectionOf(id)))
{
    error = TlsQuicTransportError.StreamLimitError;
    return false;
}
```

and `PeerStreamLimitFor` returns `InitialMaxStreamsUni` / `InitialMaxStreamsBidi` verbatim
(`TlsQuicConnectionSpec.cs:1357-1360`). A peer that uses the credit we advertised is killed with
`STREAM_LIMIT_ERROR` — a protocol violation on our side.

## 9. Medium — peer protocol violations throw locally instead of closing the connection

`PumpOnceAsync` raises `InvalidOperationException` for a malformed ACK (`:2456`), a rejected STREAM
frame (`:2464`), a protocol failure (`:2473`) and any receiver-signalled close
(`AccountForPacket`, `:3071`) — carrying the right error code in the message text but never sending
CONNECTION_CLOSE. `ProtocolFailureCode` is assigned (`:2376`) and unused. The peer is left to time
out. Only the s7.3 transport-parameter checks (`:5655-5668`) and the s6.2 flow-control check
(`:3227-3234`) route through `CloseAsync`.

## 10. Medium — CONNECTION_CLOSE sent at one encryption level only

```csharp
// TlsQuicConnection.cs:5421
ReadOnlySpan<TlsQuicEncryptionLevel> candidates = _confirmed
    ? [TlsQuicEncryptionLevel.Application]
    : [TlsQuicEncryptionLevel.Handshake, TlsQuicEncryptionLevel.Initial];

foreach (var candidate in candidates)
{
    …
    return written;      // 5526 — first level with keys wins, the rest never sent
}
```

RFC 9000 s10.2.3 wants the close in every packet number space the peer may still be reading, because
a server that has not yet processed our Handshake keys sees only the Initial packet. The `foreach`
returns on the first hit, so the Initial copy is never coalesced.

## 11. Medium — inbound MAX_STREAMS ignored

The frame switch's `default:` arm is a no-op (`TlsQuicConnection.cs:2426-2445`). MAX_STREAMS is
parsed by `TlsQuicFlowControlFrames.TryReadMaximumStreams` and dropped, so
`TlsQuicPeerFlowControlBudget._remainingBidirectionalStreams` is never raised.
`OpenBidirectionalStream` throws `InvalidOperationException` once the initial allowance runs out
(`TlsQuicPeerFlowControlBudget.cs:429-443`) — the code comments acknowledge this as an
"A4-minimal" limitation, but the HTTP/3 layer ships on top of it, so request N+1 on a reused
connection dies with an exception rather than waiting for credit.

## 12. Medium — oversized first frame can overrun the datagram budget

```csharp
// TlsQuicStreams.cs:1557
if (taken.Count > 0 && spent + size > payloadBudget)
{
    return taken;
}
```

The first frame is admitted unmeasured. `Drain` chunks STREAM payloads to
`DatagramPayloadBudget - OneRttStreamFrameOverheadBound` *at queue time* (`:1276`), so a frame queued
under a larger PMTU, or a queued repair / flow-control frame, can exceed the budget the caller passes
in `TryBuildApplicationPacket` (`TlsQuicApplicationSendPath.cs:636-637`, where `budget - spent` is
already reduced by an ACK frame). Downstream that surfaces as `TlsQuicPacketBuilder.Build`'s
`"Packet needs N bytes, destination has M"` (`TlsQuicPacketBuilder.cs:566`) or an over-MTU datagram.

## 13. Low-Medium — `EncodedLength` can return 5

`TlsQuicPacketNumber.EncodedLength` (`:12-49`) reproduces RFC 9000 Appendix A.2 correctly, including
the ceiling correction at `:44-47`, but never clamps its result. For `numUnacked > 2^31` it returns
5, which every caller then feeds to `ValidatePacketNumberEncoding`'s `is < 1 or > 4` check
(`TlsQuicPacketBuilder.cs:680`) as a *floor* it can never satisfy — the exception says the plan needs
5 bytes, which is not a length the wire format has. Unreachable at realistic ack gaps; still an
unstated contract on a shared helper.

## 14. Low-Medium — CONNECTION_CLOSE-only packets counted as in-flight

`IsInFlight` returns true for any frame that is not ACK (`TlsQuicPacketBuilder.cs:847-857`). RFC 9002
s2 defines in-flight as *ack-eliciting or containing PADDING*; CONNECTION_CLOSE is neither. A
close-only packet therefore inflates `_bytesInFlight` and consumes congestion window. Harmless in
practice (the connection is closing) but it diverges from the recovery model and from
`IsAckEliciting`'s own exclusion list one method above.

## 15. Low — idle timeout missing the `3×PTO` floor

`IdleDeadline()` (`TlsQuicConnection.cs:5716`) is `_idleSince + EffectiveIdleTimeout()`. RFC 9000
s10.1 requires the effective period to be `max(idle_timeout, 3 × PTO)`, so a connection with a small
advertised `max_idle_timeout` and a high RTT closes earlier than the peer expects.

## 16. WITHDRAWN — GOAWAY *is* enforced

**This finding was wrong.** It is kept here rather than deleted, because the way it was reached is
worth not repeating.

`TryAcceptGoaway` validates the identifier and stores `PeerGoawayStreamId`
(`TlsQuicHttp3Streams.cs:841-863`), including RFC 9114 s5.2's rule that a later GOAWAY may not name a
larger identifier. The audit then searched for consumers of `PeerGoawayStreamId` **within the file it
was reading**, found none, and concluded nothing enforced it.

`TlsQuicHttp3Connection.TryOpenRequest` enforces it, at `:620-624`, and says so in a comment written
against exactly this misreading:

> s5.2: "Endpoints MUST NOT initiate new requests or promise new pushes on the connection after
> receipt of a GOAWAY frame from the peer." NO COMPARISON AGAINST THE IDENTIFIER HERE — the MUST NOT
> is unconditional, and the identifier bounds which ALREADY-SENT requests were processed (see
> `IsRejectedByGoaway`), not which new ones may be opened.

`IsRejectedByGoaway` (`:724`) separately carries the `>=` rule for requests already in flight. Two
tests pin both halves: `AGoawayForbidsANewRequest` and `AGoawayOfZeroStillForbidsANewRequest`, the
second of which exists specifically to kill the mutant this finding proposed.

The fix this report originally recommended — refusing stream IDs at or above the identifier — would
have been a **regression**, weakening an unconditional MUST NOT into a comparison. The implementer
assigned to it declined to make the change and was right to.

Lesson for the next sweep: a stored value with no consumer *in the file that stores it* is not an
unenforced value. Grep the whole namespace before calling something dead.

## 17. Low — CRYPTO reassembler allocates its ceiling on one far-offset frame

`EnsureCapacity` grows to `max(required, …)` capped at `_maximumLength`
(`TlsQuicCryptoStreamReassembler.cs:100-111`), and `_received` is a parallel `byte[]` of the same
size. A single CRYPTO frame at offset `_maximumLength - 1` allocates both arrays at full size — up to
2 × 32 MB at the constructor's ceiling (`:18`). Requires valid handshake keys, so it is a malicious
*server*, not an off-path attacker.

---

## Performance (no correctness impact, all on the hot path)

- **P1** — `TlsQuicHeaderProtection.AesMask` calls `Aes.Create()` and allocates a 5-byte `byte[]`
  **per packet** (`:180-198`). One cached, keyed instance per key set would remove an object
  allocation and a CSP handle round-trip from every send and receive.
- **P2** — `TlsQuicConnection.PumpOnceAsync` allocates `new byte[65527]` on every call (`:2084`).
- **P3** — Frame bodies are copied into `List<byte>` one byte at a time:
  `TlsQuicStreamFrames.WriteData` (`:665-671`), `TlsQuicAckFrames.WriteFrameFields` (`:452-455`),
  `TlsQuicHttp3Frames.Write` (`:258-261`), `TlsQuicHttp3Request` (`:1508-1511`, `:1613-1616`),
  `TlsQuicHttp3Streams` (`:427-430`). `CollectionsMarshal` / `AddRange` is a drop-in.
- **P4** — `TlsQuicFrames.MeasureFrame` fully re-encodes a frame to measure it
  (`TlsQuicFrames.cs:663-669`) and is called repeatedly inside budget loops
  (`TlsQuicConnection.cs:5058-5060`, `:5081-5084`, `:5171-5174`, `TlsQuicStreams.cs:1556`) — the
  same frames are encoded several times per datagram.
- **P5** — `_lastDatagramFrames` builds a `string.Join` over every frame, each measured, on **every**
  datagram (`TlsQuicConnection.cs:5163-5167`) — a diagnostic string produced whether or not it is
  ever read.
- **P6** — `TakePendingFrames` and `TryTakeSendable` use `List.RemoveAt(0)`
  (`TlsQuicStreams.cs:1564`, `:775`), O(n) per frame, O(n²) per flush.
- **P7** — `TlsQuicConnection.Acknowledges` linear-scans `_ackedRanges` for each of up to 1024
  retained packets (`:3401-3403`, `:3517-3530`), and `ReceiveMaxData` sorts and copies every stream
  on each MAX_DATA (`TlsQuicStreams.cs:1839`).

---

## Verified correct (checked, no finding)

Recorded so a later pass does not re-tread them.

- HKDF label composition and the v1/v2 prefix switch, including the `quic ku` version dependence
  (`TlsQuicSecrets.cs:127-176`); Initial salts and the 16/12/16 Initial key lengths (`:266-283`).
- AEAD nonce construction — right-aligned XOR of the 62-bit packet number into the 12-byte IV, with
  zeroing on every exit path including the authentication-failure path
  (`TlsQuicPacketProtection.cs:187-215`, `:150-171`).
- Header-protection ordering: `pn_length` read *before* masking on apply and *after* unmasking on
  remove (`TlsQuicHeaderProtection.cs:66-119`); the subtraction-based sample bound that avoids the
  `packetNumberOffset + 4 + 16` overflow (`:151-158`).
- Packet-number decode against RFC 9000 A.3, including the `expectedPn >= pnHwin` underflow guard
  (`TlsQuicPacketNumber.cs:61-98`).
- RFC 9369 v2 long-header type permutation, in both directions (`TlsQuicPacketHeader.cs:154-171`).
- Varint read/write bounds, including the `source.Length - offset < length` check
  (`QuicVariableLengthInteger.cs:144-173`).
- ACK range walking: `firstAckRange > largestAcknowledged`, `gap + 2 > smallest` and
  `ackRangeLength > largest` all rejected, with rollback of partially decoded ranges
  (`TlsQuicAckFrames.cs:511-661`). The `ackRangeCount` loop is bounded by payload length, not by the
  peer-supplied count.
- AEAD confidentiality and integrity limits are enforced, with the integrity check run both before
  and after each `Receive` (`TlsQuicConnection.cs:1567-1663`, `:2198`, `:2448`).
- Key-phase handling: previous/next key selection, the `KEY_UPDATE_ERROR` check for a previous-phase
  packet numbered above the current phase's low-water mark, and the 128-bit duplicate window
  (`TlsQuicPacketReceiver.cs:894-1035`, `:1141-1180`).
- Reserved-bit checks run *after* AEAD open, as RFC 9001 s5.4 requires
  (`TlsQuicPacketReceiver.cs:972-979`).
- Frame payloads that outlive the receiver's shared `_scratch` buffer are copied, not aliased:
  CRYPTO (`TlsQuicConnection.cs:2225`), PATH_CHALLENGE (`:2310`), DATAGRAM (`:1733`), STREAM
  (`TlsQuicStreams.cs:982`).
- Huffman: complete-code validation at static-init, EOS symbol rejected, padding length and pattern
  both checked (`TlsQuicQpackHuffman.cs:213-277`, `:368-443`).
- QPACK Required Insert Count reconstruction and `Base` sign handling against RFC 9204 s4.5.1
  (`TlsQuicQpackDecoder.cs:457-642`); Known Received Count bookkeeping across Section
  Acknowledgment and Insert Count Increment (`:1139-1233`).
- QPACK encoder-stream instructions mutate table state only after every parse step succeeds
  (`TlsQuicQpackDynamicTable.cs:499-640`), so a truncated instruction leaves no partial effect.
- RTT estimation: ack-delay decode bounded by the peer's exponent, clamped to `max_ack_delay` only
  after handshake confirmation, and applied only when `latestRtt - minRtt >= ackDelay`
  (`TlsQuicAckTracker.cs:1708-1808`).
- Loss detection matches RFC 9002 s6.1: packet threshold, time threshold, and `loss_time` set only
  for packets at or below `largest_acked` (`TlsQuicLossDetection.cs:402-553`).
- CRYPTO reassembly rejects mismatched overlapping bytes and post-discard gap fills
  (`TlsQuicCryptoStreamReassembler.cs:27-98`).

---

## Suggested fix order

1. **#1** — silent, breaks the connection, and the API shape that causes it invites recurrence.
2. **#2**, **#6** — remotely triggerable resource exhaustion.
3. **#5**, **#4** — nonce reuse and handshake stall; both are small, local reorderings.
4. **#3**, **#8**, **#11** — HTTP/3 correctness on reused connections.
5. **#7**, **#9**, **#10** — protocol conformance and off-path robustness.
6. Remainder, then the performance set (**P1**–**P7**) as one pass.

Findings 4, 5 and 12 each have a one-or-two-line fix at the point identified. Findings 1, 2, 3 and 6
need a small design decision first (key-material ownership; buffered-byte accounting; stream reset
state; a buffering cap), so they are worth agreeing before the edit.
