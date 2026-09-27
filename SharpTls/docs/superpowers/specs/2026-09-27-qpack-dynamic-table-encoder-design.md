# QPACK dynamic-table encoder — design

Status: approved 2026-09-27 (user), implementation pending.
Evidence: `reference-captures/2026-09-26-spotify-9.1.86-ios27-pcapng.md` §6 — three decrypted
HTTP/3 connections of Spotify 9.1.86.2428 on iOS 27.0, 46 request sections, 36 encoder inserts,
decoded with `scripts/qpack_decode.py`.

## 1. Problem

SharpTls's HTTP/3 client encodes every request field section against the QPACK static table
only: constant `00 00` prefix, never an encoder-stream instruction. The imitated client sets a
dynamic table capacity of 4096, inserts most of its request headers, and references them from
the second use on. That is visible on the encoder stream (client uni stream 6), in every
request's Required Insert Count, and in the size of every HEADERS frame after the first. No
public fingerprint endpoint reports it, so the gap is invisible to `fp.impersonate.pro` and
`tls3.peet.ws` and visible to anyone terminating QUIC.

## 2. Observed behaviour to reproduce (all measured, 3 of 3 connections)

1. **Capacity.** The client sends `Set Dynamic Table Capacity = min(4096, peer's
   SETTINGS_QPACK_MAX_TABLE_CAPACITY)` as the first bytes after the encoder stream's type
   byte, in the packet after the server's SETTINGS arrive. Nothing dynamic happens before
   the peer's SETTINGS. (4096 equalled the server's maximum in every capture; the client's
   own ceiling above that is unknown and is taken as 4096.)
2. **Insert gate.** A (name, value) pair is inserted when a request is encoded and all of:
   capacity has been sent; the pair is not an exact static-table match; the pair is not
   already in the dynamic table; the pair appeared in at least one earlier request that was
   encoded while the table was active. Requests encoded before the capacity instruction do
   not count, which is why the first request after capacity is always static-only and why a
   pair that appeared only before capacity is not inserted on its next use (conn 61's
   `content-type: application/protobuf`, seen on streams 0 and 8, never inserted; the nine
   pairs seen on stream 4 all inserted on stream 8). Pairs seen once are never inserted.
3. **Insert form.** Insert With Name Reference to the STATIC table when the name is in it,
   Insert With Literal Name otherwise. Never a dynamic name reference, never Duplicate.
   Inserts go out in request-header order, all of one request's inserts in one encoder-stream
   write, before that request's HEADERS.
4. **Section encoding.** Base = dynamic insert count before this request's inserts. Entries
   inserted for this request: Indexed Field Line With Post-Base Index. Entries already in
   the table: Indexed Field Line (relative to Base). Exact static match: Indexed Field Line,
   static. Name in static table, value not in any table: Literal Field Line With Name
   Reference, static. Otherwise Literal Field Line With Literal Name. Required Insert Count =
   1 + largest absolute index referenced, 0 if none. Never-indexed bit never set.
5. **Strings.** Huffman when strictly shorter than raw (`ShorterOfTheTwo`, the existing
   default) for names and values, in inserts and in sections.
6. **Uni-stream timing.** Control stream opens and carries SETTINGS at connection start, in
   its own packet. Encoder stream opens when the capacity instruction is first sent. Decoder
   stream opens when the first decoder instruction (Section Ack, Insert Count Increment,
   Stream Cancellation) is due. Order when all three exist is still control, encoder, decoder.
7. **Eviction.** Capacity 4096 with ~700-byte bearer/token entries evicts within a session.
   Oldest entries evicted first; an entry with outstanding section references is never
   evicted and an insert that would need to evict one is skipped for that request (the
   header goes out as the literal it would have been). RFC 9204 §2.1.1.
8. **Blocked streams.** Decided once per section, per stream. A section may reference entries
   above the Known Received Count only if its stream is already counted as blocked or the
   number of blocked streams is below the peer's `SETTINGS_QPACK_BLOCKED_STREAMS`. Otherwise
   the section references only known-received entries: lines whose entry is above the count
   go out as the literal they would otherwise be, and no inserts are made for that request
   (an insert only ever pays off through a reference the budget forbids). RFC 9204 §2.1.2.
   Unobservable in the capture; required for correctness.
9. **MaxEntries.** The Required Insert Count wraps modulo `2 * MaxEntries` where
   `MaxEntries = floor(peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY / 32)` — the DECODER's
   advertised maximum, not the capacity this encoder chose (RFC 9204 §4.5.1.1). With a peer
   maximum of 16383 and a chosen 4096 the two differ (511 vs 128 entries), and using the
   wrong one desynchronises after 256 inserts. Invisible in the capture, where they were equal.
   `MaxEntries` is never 0 while a table exists: a capacity below 32 admits no entry, and the
   prefix writer asserts `maxEntries > 0` whenever RIC > 0 rather than dividing by it.

Not reproduced (unmeasured, no knob): what the client does when the peer advertises more
than 4096; draining behaviour near eviction; behaviour after a Stream Cancellation from the
peer beyond releasing references.

## 3. Units

### 3.1 `TlsQuicQpackEncoderTable` (new, `SharpTls/Quic`)

Encoder-side dynamic table. Owns entries, absolute indices, size, capacity, Known Received
Count, and per-section reference tracking.

```
internal sealed class TlsQuicQpackEncoderTable
{
    TlsQuicQpackEncoderTable(int capacity, ulong peerMaximumCapacity);   // capacity <= peer maximum
    int  Capacity { get; }   int Size { get; }   ulong InsertCount { get; }   ulong DroppedCount { get; }
    ulong KnownReceivedCount { get; }
    ulong MaxEntries { get; }                          // floor(peerMaximumCapacity / 32), §4.5.1.1
    bool TryFind(name, value, out ulong absoluteIndex);
    bool IsKnownReceived(ulong absoluteIndex) => absoluteIndex < KnownReceivedCount;
    bool CanInsert(name, value);                      // fits after evicting only unreferenced entries
    ulong Insert(name, value);                        // evicts as needed; caller checked CanInsert
    void  RecordSection(ulong streamId, ulong requiredInsertCount, IReadOnlyList<ulong> referenced);
                                                      // RIC 0 sections are NOT recorded: the peer never acks them (§4.4.1)
    bool  TryAcknowledgeSection(ulong streamId);      // oldest unacked section on the stream; false = unknown stream (peer error)
    bool  TryCancelStream(ulong streamId);            // releases every section on the stream; false = none (still legal, §4.4.2)
    bool  TryIncrementKnownReceived(ulong increment); // false = zero or past InsertCount (peer error, §4.4.3)
    int   BlockedStreamCount { get; }                 // streams with a recorded section whose RIC > KnownReceivedCount
}
```

Entry size is `32 + name.Length + value.Length` (§3.2.1). Evict from the lowest absolute
index while `Size + entrySize > Capacity`, stopping (and refusing the insert) at the first
entry with an outstanding reference. Index conversions live here, not in the callers:
`relative = Base - absolute - 1`, `postBase = absolute - Base`. Testable without any stream.

### 3.2 `TlsQuicQpackEncoder` (existing static class, extended)

Adds encoder-stream instruction writers and the dynamic representations, all
`TryEncode…(…, Span<byte> destination, out int written)` in the file's existing style:

- `TryEncodeSetDynamicTableCapacity(ulong capacity, …)` — `001xxxxx`, 5-bit prefix.
- `TryEncodeInsertWithStaticNameReference(int staticIndex, value, huffman, …)` — `11xxxxxx`, 6-bit.
- `TryEncodeInsertWithLiteralName(name, value, huffman, …)` — `01Hxxxxx`, 5-bit name length.
- `TryEncodeFieldSectionPrefix(ulong requiredInsertCount, ulong base, ulong maxEntries, …)` —
  §4.5.1: `EncodedInsertCount = RIC == 0 ? 0 : (RIC mod (2 * MaxEntries)) + 1`;
  `S = Base < RIC`, `Delta = S ? RIC - Base - 1 : Base - RIC`. `maxEntries` is the peer-derived
  value from §2.9. The existing zero-argument overload stays as the static-only prefix.
- `TryEncodeIndexedDynamic(ulong relativeIndex, …)` — `10xxxxxx`, 6-bit prefix;
  `TryEncodeIndexedPostBase(ulong postBaseIndex, …)` — `0001xxxx`, 4-bit prefix. Both take the
  already-converted index (§3.1).

Byte-exact against the capture: `3f e1 1f` for capacity 4096;
`c0 91 45 64 a0 c5 a9 2b f8 99 74 56 74 9a 5f 4b 90 f4 ff` for
`:authority: spclient.wg.spotify.com`; `6e 45 67 49 a5 f4 b0 eb ad 6e e5 b1 06 3d 5f 88 7d 70 ae f3 8b 89 a1 3d`
for `spotify-app-version: 9.1.86.2428`; `69 1d 75 ad 5d 03 4c a7 b2 9f 03 69 4f 53` for
`app-platform: iOS` (raw value); prefixes `0a 88` (RIC 9, Base 0) and `0a 00` (RIC 9, Base 9).

### 3.3 `TlsQuicQpackEncoderPolicy` (new, `SharpTls/Quic`, one per connection)

The decision layer between a request's header list and the two encoders above. Holds the
table, the use counter, and the connection-phase flags.

```
internal sealed class TlsQuicQpackEncoderPolicy
{
    TlsQuicQpackEncoderPolicy(TlsQuicHttp3Spec spec);
    bool CapacitySent { get; }
    // Called when the peer's SETTINGS arrive. Returns the capacity instruction bytes to write
    // on the encoder stream, or empty when the configured capacity or the peer's maximum is 0.
    ReadOnlyMemory<byte> OnPeerSettings(ulong peerMaximumCapacity, ulong peerBlockedStreams);

    // TWO PHASES, BECAUSE THE CONNECTION CAN STILL REFUSE THE REQUEST AFTER ENCODING IT.
    // Plan mutates nothing: it reads the table and the use counter and produces the bytes plus
    // a description of what Commit would do. Commit applies the inserts, records the section's
    // references under the stream id the connection opened, bumps the use counter and the
    // requests-since-capacity count. A refused request is simply never committed.
    TlsQuicQpackEncoderPlan Plan(List<(byte[] Name, byte[] Value)> lines);
    void Commit(TlsQuicQpackEncoderPlan plan, ulong streamId);

    // The peer's decoder-stream instructions. false = protocol error, caller closes with
    // QPACK_DECODER_STREAM_ERROR.
    bool TryAcknowledgeSection(ulong streamId);  bool TryCancelStream(ulong streamId);  bool TryIncrementKnownReceived(ulong n);
}

internal sealed record TlsQuicQpackEncoderPlan(
    ReadOnlyMemory<byte> EncoderStreamBytes,   // empty when nothing is inserted
    ReadOnlyMemory<byte> FieldSection,         // prefix + representations
    ulong RequiredInsertCount,
    IReadOnlyList<(byte[] Name, byte[] Value)> Inserts,
    IReadOnlyList<ulong> ReferencedAbsoluteIndices,
    IReadOnlyList<(byte[] Name, byte[] Value)> Seen);   // every non-exact-static line, for the use counter
```

Plan never fails: header validation happened in `TlsQuicHttp3Request` before it, and the
byte buffers grow until the encoders fit. With capacity 0 (the library default) every plan
carries empty `EncoderStreamBytes`, RIC 0 and today's static-only section, byte for byte.
`TlsQuicHttp3Request.TryEncode` gains an overload taking the policy; its literal lines are
produced by the same `TlsQuicQpackEncoder.TryEncodeFieldLine` the static path uses, so the
two cannot drift.

### 3.4 `TlsQuicHttp3Streams` (existing, extended)

- Tracks `LocalEncoderStream` beside the existing control and decoder streams.
- `OpenLocalStreams()` honours `UnidirectionalStreamOpening`: `AtConnectionStart` opens all
  three as today; `Lazy` opens only the control stream, and `EnsureEncoderStream()` /
  `EnsureDecoderStream()` open the others on first use. `EnsureDecoderStream()` first opens
  the encoder stream (type byte alone) if it is still closed, so the stream ids are always
  control 2, encoder 6, decoder 10 as on the phone, even if the peer's encoder instructions
  are processed before its SETTINGS.
- Reads the peer's decoder stream (type `0x03`, today accepted and ignored): §4.4
  instructions Section Acknowledgment `1xxxxxxx` (7-bit stream id), Stream Cancellation
  `01xxxxxx` (6-bit), Insert Count Increment `00xxxxxx` (6-bit), forwarded to the policy. A
  Section Acknowledgment for a stream with no recorded section, or an Insert Count Increment
  of zero or past `InsertCount`, closes the connection with `QPACK_DECODER_STREAM_ERROR`
  (0x0202), §4.4.1, §4.4.3, §6. A Stream Cancellation for a stream with nothing recorded is
  legal and a no-op (§4.4.2). References are released ONLY by these peer instructions; the
  connection never releases them locally, because a late acknowledgment after a local release
  would read as the peer's error.
- `SendEncoderInstructions(ReadOnlyMemory<byte>)` writes on the encoder stream, opening it
  first under `Lazy`.

### 3.5 `TlsQuicHttp3Connection` (existing, extended)

- After the peer's SETTINGS are processed: `policy.OnPeerSettings(...)`; if non-empty, write
  the capacity bytes on the encoder stream.
- `TryOpenRequest`, reordered so nothing is committed before the request is certain to go:
  validate and `Plan` → `FitsPeerFieldSectionLimit(plan.FieldSection)` → the existing
  stream/credit refusals → `OpenBidirectional()` → `Commit(plan, stream.Id)` → write
  `plan.EncoderStreamBytes` on the encoder stream (own send) → send HEADERS on the request
  stream. A refusal at any step leaves the table, the counters and the encoder stream
  untouched. Whether the encoder bytes land in their own packet (as on the phone) is verified
  on the loopback capture; if the packetiser coalesces them with the HEADERS packet, that is
  recorded as a remaining difference, not fixed in this task.

### 3.6 Knobs

`TlsQuicHttp3Spec` (internal) and `TlsHttp3Options` (public, mapped in `Snapshot()`):

| Knob | Type | Default | Preset |
|---|---|---|---|
| `QpackEncoderDynamicTableCapacity` | `int`, 0..2^30-1 | `0` (static-only, today's bytes) | `4096` |
| `QpackInsertPolicy` | `enum { Never, OnSecondUse }` | `Never` | `OnSecondUse` |
| `UnidirectionalStreamOpening` | `enum { AtConnectionStart, Lazy }` | `AtConnectionStart` | `Lazy` |

Public enums `TlsHttp3QpackInsertPolicy`, `TlsHttp3UnidirectionalStreamOpening` in TlsClient;
`PublicAPI.Unshipped.txt` updated. Capacity > 0 with `Never` is legal (capacity sent, nothing
inserted); `OnSecondUse` with capacity 0 inserts nothing. Huffman and name-match policies are
the existing knobs at their existing defaults.

## 4. Data flow, one request

1. Caller adds headers → `TlsQuicHttp3Request` validates as today → ordered `lines`.
2. `policy.Plan(lines)`, in this order:
   a. Classify every line: exact static match → indexed static, not counted; else counted
      as "seen", and either already in the dynamic table (absolute index), or a candidate.
   b. Insert gate (§2.2) for every candidate, in header order, subject to `CanInsert`.
   c. Blocked-streams check, once. The stream is not open at plan time, so it is never already
      blocked; the rule is `BlockedStreamCount < peerBlockedStreams`. If false: drop every
      planned insert and every reference to an entry that is not known-received; those lines
      go literal.
   d. Base = `InsertCount` before this plan's inserts; references to planned inserts are
      post-base, to existing entries relative; RIC = 1 + max referenced absolute, or 0.
   e. Emit encoder bytes (inserts in header order) and the section.
3. Connection: refusal checks, open stream, `Commit`, write encoder bytes, write HEADERS.
4. Peer decoder stream: Section Ack raises Known Received Count and releases the stream's
   oldest section; Insert Count Increment raises the count; Stream Cancellation releases the
   stream's sections.

## 5. Errors

- Peer maximum capacity 0, or configured capacity 0 → no capacity instruction, static-only
  for the connection.
- Peer decoder instruction invalid (§3.4) → `QPACK_DECODER_STREAM_ERROR`, connection closed
  through the existing `Fail` path.
- Insert refused by eviction (referenced entry in the way) → that line is a literal, other
  inserts proceed. Blocked-streams budget exhausted → no inserts and no unacknowledged
  references for that whole section (§4.2c). Neither is an error.
- Section larger than the peer's `MAX_FIELD_SECTION_SIZE` → existing refusal path, measured
  on the planned section, before Commit.

## 6. Tests

- `TlsQuicQpackEncoderTableTests`: sizing, eviction order, refusal on referenced entries,
  Known Received Count from acks and increments, blocked-stream count.
- `TlsQuicQpackEncoderTests`: the byte-exact vectors in §3.2, prefix cases, every
  representation.
- `TlsQuicQpackEncoderPolicyTests`: replay the capture — feed connection 61's 11 request
  header lists in order and assert the insert sequence (#0–#13 in the reference doc), the
  static-only first two sections, `EncRIC/S/Delta` per section, and the encoder-stream
  frame boundaries. Capacity-0 path byte-identical to today. A refused (never committed)
  plan leaves the next plan identical to one made without it. Peer maximum 16383 with
  capacity 4096: 300 inserts, every prefix decodes back to its RIC with MaxEntries 511 —
  the test that catches §2.9. Budget exhausted: section carries only known-received
  references and no encoder bytes.
- `TlsQuicHttp3StreamsTests`: peer decoder stream parsing, lazy opening order.
- Loopback (`TlsQuicHttp3MsQuicLoopbackTests`): System.Net.Quic decodes a dynamic section
  and answers; a second request on the same connection uses indexed dynamic lines.
- Live: `SpotifyPresetLiveParityTests` still 200 (the server must decode us); nothing more
  is observable there.
- `TlsPresetTests` / `SpotifyHttp2PresetTests` unaffected; `TlsPresetTests` gains the three
  preset values.

## 7. Out of scope

Duplicate instruction, dynamic name references, never-indexed lines, server-side encoder,
HTTP/2 HPACK (already policy-complete), the WebKit stack.
