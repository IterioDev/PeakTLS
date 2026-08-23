# Audit — RFC 9113 section 6 frame types, RECEIVE side

Date: 2026-08-16
Scope: every frame type as `Http2Connection` receives it — the read loop, the `Handle*Async`
methods, the fragment/padding extractors, and `Http2FrameParser`.
Source under audit: `src/TlsClient/Http2Connection.cs` (all line references are to that file
unless stated otherwise).
RFC text: fetched verbatim from `https://www.rfc-editor.org/rfc/rfc9113.txt`. Every quotation
below is from that fetch, not from memory.

Divergence policy applied: `docs/superpowers/HANDOFF.md` and
`docs/superpowers/plans/2026-08-16-rfc-reference.md` were checked first. Neither documents any
of the divergences recorded below; the reference plan covers the send-side request lifecycle
only (its section 5.3 discusses `SETTINGS_ENABLE_CONNECT_PROTOCOL`, not `SETTINGS_ENABLE_PUSH`,
and nothing in it addresses inbound validation). XML docs on the receive path were checked:
the only RFC commentary present is on `HandleDataAsync` (1189-1191) and `ReserveSendWindowAsync`
(1524-1529), both send/flow-control notes. So none of the findings below are documented
fidelity choices.

---

## 0. Cross-cutting: every connection error is emitted as PROTOCOL_ERROR

**Finding F-0 — IMPORTANT.** `ReadLoopAsync` (1071-1084) catches any exception from the frame
handlers and, when it is a `TlsHttpProtocolException`, sends `GOAWAY(PROTOCOL_ERROR)`
unconditionally:

```
1074:            if (exception is TlsHttpProtocolException)
1076:                await TrySendGoAwayAsync(Http2ErrorCode.ProtocolError)
```

There is no way for a handler to request a different code. RFC 9113 mandates specific codes per
condition — section 4.2: *"An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame
exceeds the size defined in SETTINGS_MAX_FRAME_SIZE, exceeds any limit defined for the frame
type, or is too small to contain mandatory frame data."* Section 6.5: *"A SETTINGS frame with a
length other than a multiple of 6 octets MUST be treated as a connection error (Section 5.4.1)
of type FRAME_SIZE_ERROR."* Section 6.9.1: window overruns are FLOW_CONTROL_ERROR. All of these
go out as PROTOCOL_ERROR.

**Status: VIOLATES.** Wrong on the wire in every one of the frame-size and flow-control cases
below. It is also a fingerprint issue in its own right: a real client emits the RFC code.

**Fix.** Give `TlsHttpProtocolException` an `Http2ErrorCode` property (defaulting to
`ProtocolError`), set it at each throw site, and have line 1076 read it.

**Finding F-0b — IMPORTANT.** The `checked(...)` arithmetic on the receive path (1490, 1494,
1512) throws `OverflowException`, which is *not* a `TlsHttpProtocolException`. Line 1074 is
therefore false, **no GOAWAY is sent at all**, and line 1078 wraps it as
`IOException("The HTTP/2 connection failed.")`. The peer sees a bare transport close where the
RFC requires `GOAWAY(FLOW_CONTROL_ERROR)`. See F-9.2 and F-5.5.

---

## 1. DATA — RFC 9113 section 6.1

Handler: `HandleDataAsync` (1138-1198). Padding stripped by `RemovePadding` (2336-2347).

### 1.1 Pad Length exceeding the payload — CONFORMS (with a hole, see 1.2)

> "The total number of padding octets is determined by the value of the Pad Length field. If
> the length of the padding is the length of the frame payload or greater, the recipient MUST
> treat this as a connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.1)

```
2342:        if (frame.Payload.Length == 0 || frame.Payload[0] >= frame.Payload.Length)
2344:            throw new TlsHttpProtocolException("An HTTP/2 padding length is invalid.");
```

`Payload[0] >= Payload.Length` is exactly the RFC's "the length of the frame payload or
greater" test (the Pad Length octet is itself part of the payload). The empty-payload case
(PADDED set with a zero-length payload, i.e. no Pad Length field at all) is caught too.
**Status: CONFORMS.**

### 1.2 Padding not validated when the stream is gone

**Finding F-1.1 — MINOR.** `RemovePadding` is only reached at 1184, inside the branch where a
`Http2StreamState` was found. When the stream is closed or unknown but not idle, the handler
returns at 1182 without ever inspecting the Pad Length:

```
1166:        if (state is null)
1172:            await SendWindowUpdateAsync(0, payloadLength, cancellationToken)
1182:            return;
1184:        var data = RemovePadding(frame);   // unreachable for the state is null path
```

The §6.1 rule is unconditional on stream state. A malformed padded DATA frame arriving after
the client reset the stream is silently accepted.

**Fix.** Call `RemovePadding(frame)` (discarding the result) before the `state is null` early
return, or hoist it above the `lock` at 1148.

### 1.3 Padding counted toward flow control — CONFORMS

> "The entire DATA frame payload is included in flow control, including the Pad Length and
> Padding fields if present." (RFC 9113 §6.1)

Receive accounting at 1146-1164 uses `frame.Payload.Length` (the whole payload) for both the
connection and stream windows; the credit returned at 1186 and 1194 is also
`frame.Payload.Length`, not the de-padded `data.Length`. The comment at 1189-1191 states the
rule correctly. **Status: CONFORMS.**

### 1.4 DATA on stream 0 — CONFORMS

```
1142:        if (frame.StreamId == 0)
1144:            throw new TlsHttpProtocolException("A DATA frame used stream zero.");
```

Matches §6.1: *"If a DATA frame is received whose Stream Identifier field is 0x00, the recipient
MUST respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR."*
**Status: CONFORMS** (modulo F-0, the code is right).

### 1.5 DATA on a half-closed(remote)/closed stream — CONFORMS

> "If a DATA frame is received whose stream is not in the 'open' or 'half-closed (local)' state,
> the recipient MUST respond with a stream error (Section 5.4.2) of type STREAM_CLOSED."
> (RFC 9113 §6.1)

`Http2StreamState.EnqueueBody` rejects DATA after END_STREAM (2682-2685) and before the
response headers (2686-2689); DATA for an idle stream is rejected at 1168-1171. DATA for a
stream the client already finished with is absorbed and re-credited (1172-1182), which the RFC
tolerates. **Status: CONFORMS.** (The STREAM_CLOSED case is escalated to a connection error —
covered by F-0.)

---

## 2. HEADERS — RFC 9113 section 6.2

Handler: `HandleHeadersAsync` (1200-1249). Fragment extraction: `ExtractHeaderFragment`
(2349-2370).

### 2.1 HEADERS on stream 0 — CONFORMS

> "HEADERS frames MUST be associated with a stream. If a HEADERS frame is received whose Stream
> Identifier field is 0x00, the recipient MUST respond with a connection error (Section 5.4.1)
> of type PROTOCOL_ERROR." (RFC 9113 §6.2)

Line 1204-1207. **Status: CONFORMS.**

### 2.2 Pad / priority interaction — CONFORMS

> "The total number of padding octets is determined by the value of the Pad Length field. If the
> length of the padding is the length of the frame payload or greater, the recipient MUST treat
> this as a connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.2)

```
2353:        if ((frame.Flags & Http2FrameFlags.Padded) != 0)
2355:            if (frame.Payload.Length == 0) throw ...
2359:            padding = frame.Payload[offset++];
2361:        if ((frame.Flags & Http2FrameFlags.Priority) != 0)
2363:            offset += 5;
2365:        if (offset > frame.Payload.Length || padding > frame.Payload.Length - offset)
2367:            throw new TlsHttpProtocolException("A HEADERS frame has invalid padding or priority.");
```

Both orderings are handled: Pad Length is read first, the 5 priority octets are skipped second,
and the residual check `padding > Length - offset` is *stricter* than the RFC sentence (it also
rejects padding that would push the fragment length negative once the priority block is
accounted for, which the RFC sentence alone does not literally cover but which is required for
a well-formed frame). A PRIORITY-flagged frame shorter than 5 octets is caught by
`offset > frame.Payload.Length`. **Status: CONFORMS.**

### 2.3 Exclusive-dependency and self-dependency — CONFORMS (nothing to do)

The 5 priority octets are skipped at 2363 and never parsed, so neither the Exclusive bit nor a
self-dependency is examined. This is correct for RFC 9113:

> "This update to HTTP/2 deprecates the priority signaling defined in RFC 7540 [RFC7540]. The
> bulk of the text related to priority signals is not included in this document." (RFC 9113
> §5.3.2)

> "Endpoints that receive priority signals in HEADERS or PRIORITY frames can benefit from
> applying that information." (RFC 9113 §5.3.2 — a benefit, not a MUST)

The RFC 7540 rule "a stream cannot depend on itself" is not carried into RFC 9113 §6.2 or §6.3;
the retrieved §6.3 text lists only Exclusive/Stream Dependency/Weight field definitions and the
stream-0 rule. **Status: CONFORMS.** (Note for the send-side auditor: `BuildPriorityPayload`
at 2428-2431 still enforces the withdrawn 7540 self-dependency rule outbound. Harmless, but it
is a 7540 leftover.)

### 2.4 END_HEADERS handling — see F-2.1 (CONTINUATION flood)

```
1213:        while ((frame.Flags & Http2FrameFlags.EndHeaders) == 0)
1215:            frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
1216:            if (frame.Type != Http2FrameType.Continuation || frame.StreamId != streamId)
1219:                throw new TlsHttpProtocolException("A header block was interrupted before END_HEADERS.");
```

The type and stream checks are correct (§6.2: *"A HEADERS frame without the END_HEADERS flag set
MUST be followed by a CONTINUATION frame for the same stream. A receiver MUST treat the receipt
of any other type of frame or a frame on a different stream as a connection error (Section
5.4.1) of type PROTOCOL_ERROR."*). The termination hazard is F-2.1 below.

### 2.5 Trailers — CONFORMS

1231-1235 requires END_STREAM on a trailer section, matching §8.1 ("*Trailer sections … MUST
carry the END_STREAM flag*" is enforced as written).

### Finding F-2.1 — CRITICAL: unbounded CONTINUATION loop (zero-length frames never terminate)

`AppendHeaderFragment` is the only bound on the loop:

```
2374:        if (block.Length + fragment.Length > _configuration.MaximumResponseHeaderBytes)
2376:            throw new TlsHttpProtocolException(
2377:                "The compressed HTTP/2 header block exceeded the configured limit.");
```

The guard is on **accumulated bytes**. A peer that sends `HEADERS` without END_HEADERS followed
by an endless stream of *zero-length* CONTINUATION frames never advances `block.Length`, so the
loop at 1213-1223 (and the identical loop at 1291-1301 in `HandlePushPromiseAsync`) spins
forever. Each iteration reads 9 header octets and 0 payload octets, so it is not even
rate-limited by payload size. The read loop is the only reader on the connection, so every
other stream on it stalls with it, and there is no timeout on `ReadFrameAsync`
(2319-2334 blocks on `_transport.Stream.ReadAsync` with only `_lifetime.Token`).

This is the CONTINUATION-flood shape (CVE-2024-27316 and the related 2024 HTTP/2 advisories).
RFC 9113 §10.5 covers it:

> "An endpoint that receives field blocks that are longer than it is willing to handle can send
> an HTTP 431 (Request Header Fields Too Large) status code [RFC6585]. … An endpoint can also
> close a connection using the ENHANCE_YOUR_CALM error code if the peer sends field blocks that
> are excessively large." (RFC 9113 §10.5)

**Fix.** Count CONTINUATION frames as well as bytes: add a frame counter to both loops
(a cap in the low hundreds is what mainline stacks use) and throw once it is exceeded. One
shared counter passed into `AppendHeaderFragment` covers both call sites with a single guard.

---

## 3. PRIORITY — RFC 9113 section 6.3

Handled inline in `HandleFrameAsync`:

```
1109:            case Http2FrameType.Priority:
1110:                ValidateFrame(frame, streamMustBeZero: false, length: 5);
1111:                break;
```

with

```
2415:    private static void ValidateFrame(Http2Frame frame, bool streamMustBeZero, int length)
2417:        if ((streamMustBeZero ? frame.StreamId != 0 : frame.StreamId == 0) ||
2418:            frame.Payload.Length != length)
2420:            throw new TlsHttpProtocolException($"A {frame.Type} frame is malformed.");
```

### 3.1 Stream 0 is a PROTOCOL_ERROR — CONFORMS

> "The PRIORITY frame always identifies a stream. If a PRIORITY frame is received with a stream
> identifier of 0x00, the recipient MUST respond with a connection error (Section 5.4.1) of
> type PROTOCOL_ERROR." (RFC 9113 §6.3)

Line 2417 (`streamMustBeZero: false` → error when `StreamId == 0`) throws
`TlsHttpProtocolException`, which becomes `GOAWAY(PROTOCOL_ERROR)`. **Status: CONFORMS.**

### Finding F-3.1 — IMPORTANT: length != 5 kills the connection; it is a *stream* error

> "A PRIORITY frame with a length other than 5 octets MUST be treated as a stream error
> (Section 5.4.2) of type FRAME_SIZE_ERROR." (RFC 9113 §6.3)

Line 2418 throws the same connection-fatal `TlsHttpProtocolException` for a wrong length as for
stream 0. Every in-flight request on the connection is destroyed over a frame the RFC says must
cost only one stream — and PRIORITY frames can legally arrive on *closed* streams, so a single
stray frame from a buggy intermediary tears down a multiplexed connection.

**Status: VIOLATES** (both the error scope and, via F-0, the error code).

**Fix.** Split the two conditions. Keep the stream-0 case connection-fatal; for a wrong length,
call `TryResetStreamAsync(frame.StreamId, Http2ErrorCode.FrameSizeError)` and continue the read
loop. `TryResetStreamAsync` already exists (used at 1307).

### 3.2 Priority payload ignored — CONFORMS

The 5 payload octets are discarded. §5.3.2 deprecates the scheme and phrases consumption as a
benefit, never a MUST. **Status: CONFORMS.**

---

## 4. RST_STREAM — RFC 9113 section 6.4

Handler: `HandleReset` (1437-1452).

### 4.1 Length exactly 4, stream != 0 — CONFORMS

> "A RST_STREAM frame with a length other than 4 octets MUST be treated as a connection error
> (Section 5.4.1) of type FRAME_SIZE_ERROR." (RFC 9113 §6.4)

> "RST_STREAM frames MUST be associated with a stream. If a RST_STREAM frame is received with a
> stream identifier of 0x00, the recipient MUST treat this as a connection error (Section
> 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.4)

`1439: ValidateFrame(frame, streamMustBeZero: false, length: 4);` covers both, and here a
connection error *is* the required scope. **Status: CONFORMS** (error code subject to F-0 —
the length case goes out as PROTOCOL_ERROR where FRAME_SIZE_ERROR is mandated).

### 4.2 RST_STREAM on an idle stream — CONFORMS

> "RST_STREAM frames MUST NOT be sent for a stream in the 'idle' state. If a RST_STREAM frame
> identifying an idle stream is received, the recipient MUST treat this as a connection error
> (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.4)

```
1446:        else if (IsIdleStream(frame.StreamId))
1448:            throw new TlsHttpProtocolException("RST_STREAM was received for an idle stream.");
```

`IsIdleStream` (2382-2384) defines idle correctly per direction: odd (client-initiated) ids
above `_nextStreamId` and even (server-promised) ids above `_highestPromisedStreamId`.
**Status: CONFORMS.**

### 4.3 Behaviour after receipt — CONFORMS

> "After receiving a RST_STREAM on a stream, the receiver MUST NOT send additional frames for
> that stream, except for PRIORITY." (RFC 9113 §6.4)

1440-1445 fails the stream locally (`state.TryFail`) and sends nothing. 1450 drops the id from
`_rejectedPushStreams`, 1451 wakes the flow-control waiters. `SendAsync`'s `finally` (216)
removes the stream from `_streams`, so no later frame can target it. **Status: CONFORMS.**

---

## 5. SETTINGS — RFC 9113 section 6.5

Handler: `HandleSettingsAsync` (1311-1409).

### 5.1 Length a multiple of 6, and stream 0 — CONFORMS

> "The stream identifier for a SETTINGS frame MUST be zero (0x00). If an endpoint receives a
> SETTINGS frame whose Stream Identifier field is anything other than 0x00, the endpoint MUST
> respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.5)

> "A SETTINGS frame with a length other than a multiple of 6 octets MUST be treated as a
> connection error (Section 5.4.1) of type FRAME_SIZE_ERROR." (RFC 9113 §6.5)

`1315: if (frame.StreamId != 0 || frame.Payload.Length % 6 != 0)`. **Status: CONFORMS**
(length case emits the wrong code — F-0).

### 5.2 ACK with a non-empty payload — CONFORMS

> "Receipt of a SETTINGS frame with the ACK flag set and a length field value other than 0 MUST
> be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR." (RFC 9113 §6.5)

1319-1326. Note the `% 6` test at 1315 runs first, so a 6-octet ACK reaches 1321 and a 5-octet
ACK is rejected one line earlier — both are errors either way. **Status: CONFORMS** (code —
F-0).

### Finding F-5.1 — CRITICAL: `SETTINGS_ENABLE_PUSH = 0` from the server kills the connection

```
1354:                    case 0x2: // SETTINGS_ENABLE_PUSH
1355:                        throw new TlsHttpProtocolException(
1356:                            "A server must not send SETTINGS_ENABLE_PUSH.");
```

The value is never read. The RFC says the opposite of what the message claims:

> "SETTINGS_ENABLE_PUSH (0x02): … The initial value of SETTINGS_ENABLE_PUSH is 1. For a client,
> this value indicates that it is willing to receive PUSH_PROMISE frames. For a server, this
> initial value has no effect, and is equivalent to the value 0. **Any value other than 0 or 1
> MUST be treated as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.**"
> (RFC 9113 §6.5.2)

> "A server cannot set the SETTINGS_ENABLE_PUSH setting to a value other than 0 (see Section
> 6.5.2)." (RFC 9113 §8.4)

A server sending `ENABLE_PUSH = 0` is doing precisely the one thing §8.4 permits it to do — it
is the standard way a server announces it will never push. The client tears the connection down
with GOAWAY on the peer's *first* SETTINGS frame, before any request completes. Only
`ENABLE_PUSH = 1` (and any value > 1) is an error from a server.

**Status: VIOLATES. Severity CRITICAL** — kills connections against a conformant peer, at the
handshake, deterministically.

**Fix.**

```csharp
case 0x2: // SETTINGS_ENABLE_PUSH — a server may only ever send 0 (RFC 9113 sections 6.5.2, 8.4).
    if (value != 0)
    {
        throw new TlsHttpProtocolException("A server sent an invalid SETTINGS_ENABLE_PUSH.");
    }
    break;
```

### 5.3 SETTINGS_INITIAL_WINDOW_SIZE range — CONFORMS

> "Values above the maximum flow-control window size of 2^31-1 MUST be treated as a connection
> error (Section 5.4.1) of type FLOW_CONTROL_ERROR." (RFC 9113 §6.5.2)

`1366: if (value > int.MaxValue)` — `int.MaxValue` is exactly 2^31-1, and `value` is a `uint`
read at 1347, so the comparison is unsigned and correct. **Status: CONFORMS** (code — F-0).

### 5.4 SETTINGS_MAX_FRAME_SIZE range — CONFORMS

> "The initial value is 2^14 (16,384) octets. The value advertised by an endpoint MUST be
> between this initial value and the maximum allowed frame size (2^24-1 or 16,777,215 octets),
> inclusive. Values outside this range MUST be treated as a connection error (Section 5.4.1) of
> type PROTOCOL_ERROR." (RFC 9113 §6.5.2)

`1374: if (value is < 16 * 1024 or > 16_777_215)`. Boundaries inclusive on both ends.
**Status: CONFORMS** (and here PROTOCOL_ERROR is the right code).

### 5.5 Mid-connection SETTINGS_INITIAL_WINDOW_SIZE change — CONFORMS (the classic bug is absent)

> "In addition to changing the flow-control window for streams that are not yet active, a
> SETTINGS frame can alter the initial flow-control window size for streams with active
> flow-control windows (that is, streams in the 'open' or 'half-closed (remote)' state). When
> the value of SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver MUST adjust the size of all
> stream flow-control windows that it maintains by the difference between the new value and the
> old value." (RFC 9113 §6.9.2)

```
1505:    private void ApplyInitialWindowSize(int value)
1507:        lock (_flowSync)
1509:            var delta = value - _peerInitialWindowSize;
1510:            foreach (var state in _streams.Values)
1512:                state.SendWindow = checked(state.SendWindow + delta);
1514:            Volatile.Write(ref _peerInitialWindowSize, value);
1516:        SignalWindow();
```

The delta is applied to every live stream's **send** window (correct — it is the peer's
setting), the new value is stored for streams created later (`SendAsync` seeds new state from
`_peerInitialWindowSize` at 145), and the whole thing is under `_flowSync`, the same lock
`ReserveSendWindowAsync` uses. A shrinking setting drives windows negative, which §6.9.2
explicitly requires (*"A change to SETTINGS_INITIAL_WINDOW_SIZE can cause the available space in
a flow-control window to become negative. A sender MUST track the negative flow-control
window"*), and `checked` does not interfere with that direction. **Status: CONFORMS.** This is
the bug the audit brief flagged as classic; it is not present.

**Finding F-5.2 — IMPORTANT (sub-case of F-0b).** The one defect is the failure mode at 1512.

> "An endpoint MUST treat a change to SETTINGS_INITIAL_WINDOW_SIZE that causes any flow-control
> window to exceed the maximum size as a connection error (Section 5.4.1) of type
> FLOW_CONTROL_ERROR." (RFC 9113 §6.9.2)

`checked` throws `OverflowException`, not `TlsHttpProtocolException`, so `ReadLoopAsync`
(1074) sends **no GOAWAY at all** and reports an `IOException`. The detection is right; the
signalling is missing.

**Fix.** Replace `checked` with an explicit bound and a typed throw:

```csharp
var updated = (long)state.SendWindow + delta;
if (updated > int.MaxValue)
{
    throw new TlsHttpProtocolException(
        "SETTINGS_INITIAL_WINDOW_SIZE overflowed a stream flow-control window.");
}
state.SendWindow = (int)updated;
```

### 5.6 Unknown settings ignored — CONFORMS

> "An endpoint that receives a SETTINGS frame with any unknown or unsupported identifier MUST
> ignore that setting." (RFC 9113 §6.5.2)

The `switch` at 1349-1383 has no `default`, so unknown identifiers fall through silently.
0x6 (`SETTINGS_MAX_HEADER_LIST_SIZE`) is advisory and ignored; 0x8/0x9 are range-checked at
1380-1382. **Status: CONFORMS.**

### 5.7 SETTINGS_HEADER_TABLE_SIZE — CONFORMS, no allocation hazard

1352 forwards the raw `uint` to `HpackCodec.SetMaximumDynamicTableSize`, which clamps at
`src/TlsClient/HpackCodec.cs:93` (`Math.Min(value, 16U * 1024 * 1024)`). A hostile
`0xFFFFFFFF` cannot drive an allocation. **Status: CONFORMS.**

---

## 6. PUSH_PROMISE — RFC 9113 section 6.6

Handler: `HandlePushPromiseAsync` (1251-1309). Fragment extraction:
`ExtractPushPromiseFragment` (2386-2413).

### 6.1 Received after advertising ENABLE_PUSH=0 — CONFORMS, with one caveat

> "A client that has both set this parameter to 0 **and had it acknowledged** MUST treat the
> receipt of a PUSH_PROMISE frame as a connection error (Section 5.4.1) of type
> PROTOCOL_ERROR." (RFC 9113 §6.5.2)

`1255: if (!_configuration.Http2.LocalEnablePush) throw ...` — correct in substance.

**Finding F-6.1 — MINOR.** The RFC conditions the error on the setting having been
*acknowledged*. The client does not track whether its own SETTINGS has been ACKed, so a
PUSH_PROMISE that the server put on the wire before it processed the client's SETTINGS — a
legal race the RFC's "and had it acknowledged" wording exists to cover — is treated as fatal.
Narrow window (the server's ACK normally precedes any push), but it is a real over-strictness.

**Fix.** Set a flag when a SETTINGS ACK is received (the ACK is already recognised at 1319) and
require it before throwing at 1255; before the ACK, fall through to the RST_STREAM rejection
path at 1307.

### 6.2 PUSH_PROMISE on stream 0 — CONFORMS

> "If the Stream Identifier field specifies the value 0x00, a recipient MUST respond with a
> connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.6)

Line 1260-1263. **Status: CONFORMS.**

### 6.3 Promised stream identifier validity — CONFORMS

> "The Promised Stream ID field … MUST be a valid choice for the next stream sent by the sender
> (see 'new stream identifier' in Section 5.1.1)." (RFC 9113 §6.6)

> "Streams initiated by a client MUST use odd-numbered stream identifiers; those initiated by
> the server MUST use even-numbered stream identifiers." (RFC 9113 §5.1.1)

```
1267:        if (promisedStreamId == 0 || (promisedStreamId & 1) != 0)
1272:        if (!_streams.ContainsKey(associatedStreamId))
1277:        if (promisedStreamId <= _highestPromisedStreamId)
```

Non-zero, even, monotonically increasing, and only on an open associated stream — all four
required properties. The reserved bit is masked at 2404. Truncated frames are caught at
2399-2402 and padding at 2406-2409. **Status: CONFORMS.**

### 6.4 Rejection path — CONFORMS

1289-1305 decodes the promised field block into the HPACK decoder even though the result is
discarded (`_ = _decoder.Decode(...)`), which §4.3 requires — *"A decoding error in a field
block MUST be treated as a connection error (Section 5.4.1) of type COMPRESSION_ERROR"* and the
decoder's dynamic table must stay in sync or every later block is garbage. The stream is then
recorded in `_rejectedPushStreams` and reset (1306-1308), and its later DATA/HEADERS are
absorbed at 1180 / 1247. The 1024-entry cap at 1282-1286 bounds the bookkeeping.
**Status: CONFORMS.**

### 6.5 CONTINUATION loop — same flood hazard as F-2.1

The loop at 1291-1301 has the identical zero-length-CONTINUATION non-termination. See F-2.1.

---

## 7. PING — RFC 9113 section 6.7

Handler: `HandlePingAsync` (1411-1435). `1415: ValidateFrame(frame, streamMustBeZero: true,
length: 8);`

### 7.1 Length exactly 8 — CONFORMS

> "Receipt of a PING frame with a length field value other than 8 MUST be treated as a
> connection error (Section 5.4.1) of type FRAME_SIZE_ERROR." (RFC 9113 §6.7)

**Status: CONFORMS** (code — F-0).

### 7.2 Stream 0 required — CONFORMS

> "PING frames are not associated with any individual stream. If a PING frame is received with a
> Stream Identifier field value other than 0x00, the recipient MUST respond with a connection
> error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.7)

**Status: CONFORMS.**

### 7.3 ACK behaviour and verbatim echo — CONFORMS

> "Receivers of a PING frame that does not include an ACK flag MUST send a PING frame with the
> ACK flag set in response, with an identical frame payload." (RFC 9113 §6.7)

> "An endpoint MUST NOT respond to PING frames containing this flag." (RFC 9113 §6.7)

```
1416:        if ((frame.Flags & Http2FrameFlags.Ack) != 0) return;      // no response to an ACK
1423:            await WriteFrameLockedAsync(
1424:                Http2FrameType.Ping,
1425:                Http2FrameFlags.Ack,
1426:                0,
1427:                frame.Payload,          // verbatim, unmodified
```

The received payload array is passed straight through — byte-for-byte echo, stream 0, ACK flag
set, and flushed immediately at 1429. **Status: CONFORMS.** This is the cleanest handler in the
file.

---

## 8. GOAWAY — RFC 9113 section 6.8

Handler: `HandleGoAway` (1454-1473).

### 8.1 Stream 0 and minimum length — CONFORMS

> "An endpoint MUST treat a GOAWAY frame with a stream identifier other than 0x00 as a
> connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.8)

`1456: if (frame.StreamId != 0 || frame.Payload.Length < 8)` — 8 is the mandatory
Last-Stream-ID + Error Code; the trailing Additional Debug Data is variable and correctly not
length-constrained. **Status: CONFORMS.**

### 8.2 "MUST NOT open additional streams" — CONFORMS

> "Receivers of a GOAWAY frame MUST NOT open additional streams on the connection, although a
> new connection can be established for new streams." (RFC 9113 §6.8)

`1460: Volatile.Write(ref _isReusable, 0);` and `SendAsync` refuses at both 122-126 and (after
acquiring the stream slot) 131-135, so no stream can be opened after a GOAWAY is parsed.
The re-check at 131 closes the window where a caller was already blocked on
`AcquireStreamSlotAsync`. **Status: CONFORMS.**

### Finding F-8.1 — IMPORTANT: a non-NO_ERROR GOAWAY destroys already-completed streams

```
1463:        foreach (var pair in _streams)
1465:            if (pair.Key > lastStreamId || error != Http2ErrorCode.NoError)
1467:                pair.Value.TryFail(new HttpRequestException(
1468:                    $"The peer closed the HTTP/2 connection with {error}."));
```

The `|| error != NoError` disjunction fails **every** live stream, including streams at or below
Last-Stream-ID whose END_STREAM has already been received and whose body is merely awaiting
consumption. `TryFail` (2771-2780) calls `_streamingResponse?.Abort(exception)` and cancels
`_responseCancellation` — for a streaming response that has been fully received but not yet
read out, that is a truncated body handed to the caller as an error.

The RFC's Last-Stream-ID semantics are the opposite:

> "The last stream identifier in the GOAWAY frame contains the highest-numbered stream
> identifier for which the sender of the GOAWAY frame might have taken some action on or might
> yet take action on. All streams up to and including the identified stream might have been
> processed in some way." (RFC 9113 §6.8)

> "Activity on streams numbered lower than or equal to the last stream identifier might still
> complete successfully." (RFC 9113 §6.8)

> "If the receiver of the GOAWAY has sent data on streams with a higher stream identifier than
> what is indicated in the GOAWAY frame, those streams are not or will not be processed."
> (RFC 9113 §6.8)

The codebase already knows the right shape: `ReadLoopAsync` calls
`FailAll(exception, preserveEndedStreams: true)` at 1078-1082, and `FailAll` (2435-2445) skips
streams where `HasReceivedEndStream` is set. `HandleGoAway` is the one path that omits that
guard. Given the deliberate care taken at 1082, this reads as an oversight rather than a
fidelity choice — and nothing in HANDOFF.md documents it.

**Status: VIOLATES.**

**Fix.**

```csharp
foreach (var pair in _streams)
{
    if (pair.Value.HasReceivedEndStream)
    {
        continue;   // section 6.8: activity at or below Last-Stream-ID may still complete
    }
    if (pair.Key > lastStreamId || error != Http2ErrorCode.NoError)
    {
        pair.Value.TryFail(...);
    }
}
```

`HasReceivedEndStream` is already exposed at 2556.

### Finding F-8.2 — MINOR: Last-Stream-ID is not retained across multiple GOAWAYs

`lastStreamId` is a local (1461) and is discarded when the method returns.

> "An endpoint MAY send multiple GOAWAY frames if circumstances change. … The last stream
> identifier from the last GOAWAY frame received indicates which streams could have been acted
> upon. Endpoints MUST NOT increase the value they send in the last stream identifier."
> (RFC 9113 §6.8)

The receive side is under no MUST to police an increasing value, and since `_isReusable` is
already 0 no new stream can appear, so the practical impact is confined to retry classification:
a stream failed by the first GOAWAY (id > lastStreamId, therefore provably unprocessed and
safely retryable on a new connection) is reported with the same generic
`HttpRequestException` as a stream that may have been processed. The retry layer cannot
distinguish them.

**Fix (optional).** Store the received Last-Stream-ID in a field and tag the exception for
streams above it as definitely-unprocessed, so `TlsRetryOptions` can retry them regardless of
idempotency.

---

## 9. WINDOW_UPDATE — RFC 9113 section 6.9

Handler: `HandleWindowUpdate` (1475-1503).

### 9.1 Length exactly 4 — CONFORMS

> "A WINDOW_UPDATE frame with a length other than 4 octets MUST be treated as a connection
> error (Section 5.4.1) of type FRAME_SIZE_ERROR." (RFC 9113 §6.9)

`1477: if (frame.Payload.Length != 4)`. The reserved bit is masked at 1481 (`& 0x7fff_ffff`),
as §6.9 requires (*"one reserved bit plus an unsigned 31-bit integer"*). **Status: CONFORMS**
(code — F-0).

### Finding F-9.1 — IMPORTANT: a zero increment on a *stream* must be a stream error

> "A receiver MUST treat the receipt of a WINDOW_UPDATE frame with a flow-control window
> increment of 0 as a stream error (Section 5.4.2) of type PROTOCOL_ERROR; errors on the
> connection flow-control window MUST be treated as a connection error (Section 5.4.1)."
> (RFC 9113 §6.9)

```
1482:        if (increment == 0)
1484:            throw new TlsHttpProtocolException("A WINDOW_UPDATE increment was zero.");
```

The check runs before the stream id is even examined (the `frame.StreamId == 0` branch is at
1488), so a zero increment on any stream destroys the whole connection. Correct only for stream
0. **Status: VIOLATES.**

**Fix.** Move the test below the stream-id dispatch: connection-fatal when `StreamId == 0`,
otherwise `TryResetStreamAsync(frame.StreamId, Http2ErrorCode.ProtocolError)` and carry on.

### Finding F-9.2 — IMPORTANT: window overflow past 2^31-1 is untyped and mis-scoped

> "A sender MUST NOT allow a flow-control window to exceed 2^31-1 octets. If a sender receives a
> WINDOW_UPDATE that causes a flow-control window to exceed this maximum, it MUST terminate
> either the stream or the connection, as appropriate. For streams, the sender sends a
> RST_STREAM with an error code of FLOW_CONTROL_ERROR; for the connection, a GOAWAY frame with
> an error code of FLOW_CONTROL_ERROR is sent." (RFC 9113 §6.9.1)

```
1490:                _connectionSendWindow = checked(_connectionSendWindow + increment);
1494:                state.SendWindow = checked(state.SendWindow + increment);
```

Two defects:

1. **Wrong scope at 1494.** A stream-window overflow must produce `RST_STREAM(FLOW_CONTROL_ERROR)`
   on that stream; here it kills the connection.
2. **Wrong signal in both cases.** `checked` raises `OverflowException`, which is not a
   `TlsHttpProtocolException`, so 1074-1077 sends **no GOAWAY** — the peer gets a bare
   transport close instead of the mandated `GOAWAY(FLOW_CONTROL_ERROR)` / `RST_STREAM`.

The boundary itself is right: `int.MaxValue == 2^31-1` is exactly the RFC maximum, so `checked`
trips at precisely the correct value. Only the reaction is wrong.

**Status: VIOLATES.**

**Fix.** Compute in `long`, compare against `int.MaxValue`, and branch on scope:

```csharp
if (frame.StreamId == 0)
{
    var updated = (long)_connectionSendWindow + increment;
    if (updated > int.MaxValue)
    {
        throw new TlsHttpProtocolException(   // carries Http2ErrorCode.FlowControlError once F-0 lands
            "A WINDOW_UPDATE overflowed the connection flow-control window.");
    }
    _connectionSendWindow = (int)updated;
}
```

and for the stream case, record the id and reset it after leaving the `lock` (the reset is
async and cannot be awaited inside `lock (_flowSync)`).

### 9.3 WINDOW_UPDATE on an idle stream — CONFORMS

`1496-1500` rejects it. §5.1, "idle": *"Receiving any frame other than HEADERS or PRIORITY on a
stream in this state MUST be treated as a connection error (Section 5.4.1) of type
PROTOCOL_ERROR."* **Status: CONFORMS.**

### 9.4 WINDOW_UPDATE on a closed stream — CONFORMS

Falls through all three branches at 1488-1500 and is ignored. §5.1, "half-closed (local)":
*"In this state, a receiver can ignore WINDOW_UPDATE frames, which might arrive for a short
period after a frame with the END_STREAM flag set is sent."* **Status: CONFORMS.**

---

## 10. CONTINUATION — RFC 9113 section 6.10

### 10.1 CONTINUATION without a preceding HEADERS/PUSH_PROMISE — CONFORMS

> "A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE or CONTINUATION frame
> without the END_HEADERS flag set. A recipient that observes violation of this rule MUST
> respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.10)

Header blocks are consumed by an inline loop inside `HandleHeadersAsync` /
`HandlePushPromiseAsync`, so the *only* way a CONTINUATION reaches the top-level dispatcher is
if nothing preceded it:

```
1130:            case Http2FrameType.Continuation:
1131:                throw new TlsHttpProtocolException("An unexpected CONTINUATION frame was received.");
```

This also covers CONTINUATION with a stream identifier of 0 (§6.10: *"If a CONTINUATION frame
is received with a Stream Identifier field of 0x00, the recipient MUST respond with a
connection error (Section 5.4.1) of type PROTOCOL_ERROR"*) and CONTINUATION after END_HEADERS
— once the loop exits, the next CONTINUATION lands here. **Status: CONFORMS.**

### 10.2 CONTINUATION on a different stream, or another frame type mid-block — CONFORMS

> "If the END_HEADERS flag is not set, this frame MUST be followed by another CONTINUATION
> frame. A receiver MUST treat the receipt of any other type of frame or a frame on a different
> stream as a connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.10)

1216-1221 (HEADERS) and 1294-1299 (PUSH_PROMISE) check both the type and the stream id on every
iteration. Because the loops read directly from the transport rather than re-entering the
dispatcher, no interleaved SETTINGS/PING/WINDOW_UPDATE can slip in unnoticed — they hit the
same check and are rejected, which is what §6.10 and §4.3 require. **Status: CONFORMS.**

### 10.3 Termination — see F-2.1 (CRITICAL)

The one gap is that neither loop bounds the *number* of CONTINUATION frames, only their
cumulative size, so a zero-length flood never terminates.

---

## 11. Frame header parsing — RFC 9113 section 4.2 (context for all of the above)

`Http2FrameParser.ParseHeader` (2905-2931):

```
2920:        var length = header[0] << 16 | header[1] << 8 | header[2];
2921:        if (length > maximumFrameSize)
2923:            throw new TlsHttpProtocolException("An HTTP/2 frame exceeded SETTINGS_MAX_FRAME_SIZE.");
2925:        var streamId = BinaryPrimitives.ReadInt32BigEndian(header[5..]) & 0x7fff_ffff;
```

The oversize check uses `_localMaximumFrameSize` (the value *this* client advertised), which is
the correct direction, and the reserved bit of the stream id is masked as §4.1 requires
(*"Reserved: A reserved 1-bit field. The semantics of this bit are undefined, and the bit MUST
remain unset (0x00) when sending and MUST be ignored when receiving."*). Unknown frame types
reach `default:` at 1132-1134 and are ignored, per §4.1 (*"Implementations MUST ignore and
discard frames of unknown types"*). **Status: CONFORMS.**

**Finding F-11.1 — MINOR.** An oversize frame is always a connection error. §4.2:

> "A frame size error in a frame that could alter the state of the entire connection MUST be
> treated as a connection error (Section 5.4.1); this includes any frame carrying a field block
> (Section 4.3) (that is, HEADERS, PUSH_PROMISE, and CONTINUATION), a SETTINGS frame, and any
> frame with a stream identifier of 0." (RFC 9113 §4.2)

By enumerating the connection-fatal cases, §4.2 implies an oversize DATA frame on a non-zero
stream is a *stream* error. The current behaviour is over-strict, not unsafe — but it is a
divergence, and because the payload has not been read off the wire at that point the connection
genuinely cannot be resynchronised without draining `length` octets first. Low priority.

**Fix (if pursued).** For DATA on a non-zero stream, drain `length` octets, then
`RST_STREAM(FRAME_SIZE_ERROR)` and continue.

---

## Summary table

| # | Frame / area | Rule (RFC 9113) | Status | Severity | Location |
|---|---|---|---|---|---|
| F-0 | all | Per-condition error codes (§4.2, §6.5, §6.9.1) | VIOLATES | IMPORTANT | 1071-1077 |
| F-0b | all | Typed connection error must produce a GOAWAY | VIOLATES | IMPORTANT | 1074, 1490, 1494, 1512 |
| — | DATA §6.1 | Pad Length >= payload → PROTOCOL_ERROR | CONFORMS | — | 2342-2345 |
| F-1.1 | DATA §6.1 | …unconditionally, whatever the stream state | VIOLATES | MINOR | 1166-1184 |
| — | DATA §6.1 | Whole payload (pad included) charged to flow control | CONFORMS | — | 1146-1164, 1186, 1194 |
| — | DATA §6.1 | Stream 0 → PROTOCOL_ERROR | CONFORMS | — | 1142-1145 |
| — | DATA §6.1 | Not open/half-closed(local) → STREAM_CLOSED | CONFORMS | — | 2682-2689, 1168-1171 |
| — | HEADERS §6.2 | Stream 0 → PROTOCOL_ERROR | CONFORMS | — | 1204-1207 |
| — | HEADERS §6.2 | Pad + priority residual check | CONFORMS | — | 2353-2368 |
| — | HEADERS §6.2 | Exclusive / self-dependency (withdrawn in 9113 §5.3.2) | CONFORMS | — | 2361-2364 |
| — | HEADERS §6.2 | Trailers must carry END_STREAM | CONFORMS | — | 1231-1235 |
| **F-2.1** | **HEADERS/PUSH_PROMISE §6.2, §6.10, §10.5** | **Bound the field block; zero-length CONTINUATION flood never terminates** | **VIOLATES** | **CRITICAL** | **1213-1223, 1291-1301, 2374** |
| — | PRIORITY §6.3 | Stream 0 → connection PROTOCOL_ERROR | CONFORMS | — | 1110, 2417 |
| F-3.1 | PRIORITY §6.3 | Length != 5 → **stream** error FRAME_SIZE_ERROR | VIOLATES | IMPORTANT | 1110, 2418 |
| — | PRIORITY §6.3 | Payload may be ignored (deprecated) | CONFORMS | — | 1110-1111 |
| — | RST_STREAM §6.4 | Length exactly 4; stream 0 → PROTOCOL_ERROR | CONFORMS | — | 1439, 2415-2422 |
| — | RST_STREAM §6.4 | Idle stream → connection PROTOCOL_ERROR | CONFORMS | — | 1446-1449, 2382-2384 |
| — | RST_STREAM §6.4 | Send no further frames on that stream | CONFORMS | — | 1440-1451, 216 |
| — | SETTINGS §6.5 | Stream 0; length a multiple of 6 | CONFORMS | — | 1315-1318 |
| — | SETTINGS §6.5 | ACK with a payload → FRAME_SIZE_ERROR | CONFORMS | — | 1319-1326 |
| **F-5.1** | **SETTINGS §6.5.2, §8.4** | **ENABLE_PUSH: only a value other than 0 or 1 is an error; a server legally sends 0** | **VIOLATES** | **CRITICAL** | **1354-1356** |
| — | SETTINGS §6.5.2 | INITIAL_WINDOW_SIZE > 2^31-1 → FLOW_CONTROL_ERROR | CONFORMS | — | 1366-1370 |
| — | SETTINGS §6.5.2 | MAX_FRAME_SIZE outside [16384, 16777215] → PROTOCOL_ERROR | CONFORMS | — | 1374-1377 |
| — | **SETTINGS §6.9.2** | **Mid-connection INITIAL_WINDOW_SIZE change adjusts all send windows by the delta** | **CONFORMS** | — | 1505-1517 |
| F-5.2 | SETTINGS §6.9.2 | …overflow → GOAWAY(FLOW_CONTROL_ERROR) | VIOLATES | IMPORTANT | 1512 |
| — | SETTINGS §6.5.2 | Unknown identifiers ignored | CONFORMS | — | 1349-1383 |
| — | SETTINGS §6.5.2 | HEADER_TABLE_SIZE bounded | CONFORMS | — | 1352, HpackCodec.cs:93 |
| — | PUSH_PROMISE §6.5.2 | ENABLE_PUSH=0 → PROTOCOL_ERROR on receipt | CONFORMS | — | 1255-1259 |
| F-6.1 | PUSH_PROMISE §6.5.2 | …only once the setting was acknowledged | VIOLATES | MINOR | 1255 |
| — | PUSH_PROMISE §6.6 | Stream 0 → PROTOCOL_ERROR | CONFORMS | — | 1260-1263 |
| — | PUSH_PROMISE §6.6, §5.1.1 | Promised id non-zero, even, increasing, live parent | CONFORMS | — | 1267-1281 |
| — | PUSH_PROMISE §4.3 | Decode the block even when rejecting | CONFORMS | — | 1303-1308 |
| — | PING §6.7 | Length exactly 8 → FRAME_SIZE_ERROR | CONFORMS | — | 1415 |
| — | PING §6.7 | Stream 0 → PROTOCOL_ERROR | CONFORMS | — | 1415, 2417 |
| — | PING §6.7 | ACK not answered; payload echoed verbatim | CONFORMS | — | 1416-1429 |
| — | GOAWAY §6.8 | Stream 0; >= 8 octets | CONFORMS | — | 1456-1459 |
| — | GOAWAY §6.8 | Open no further streams | CONFORMS | — | 1460, 122-135 |
| F-8.1 | GOAWAY §6.8 | Streams <= Last-Stream-ID may still complete | VIOLATES | IMPORTANT | 1463-1470 |
| F-8.2 | GOAWAY §6.8 | Last-Stream-ID retained for retry classification | NOT IMPLEMENTED | MINOR | 1461 |
| — | WINDOW_UPDATE §6.9 | Length exactly 4; reserved bit masked | CONFORMS | — | 1477-1481 |
| F-9.1 | WINDOW_UPDATE §6.9 | Increment 0 → **stream** error off stream 0 | VIOLATES | IMPORTANT | 1482-1485 |
| F-9.2 | WINDOW_UPDATE §6.9.1 | Overflow past 2^31-1 → RST_STREAM / GOAWAY FLOW_CONTROL_ERROR | VIOLATES | IMPORTANT | 1490, 1494 |
| — | WINDOW_UPDATE §5.1 | Idle stream rejected; closed stream ignored | CONFORMS | — | 1488-1500 |
| — | CONTINUATION §6.10 | Unsolicited / stream 0 / after END_HEADERS → PROTOCOL_ERROR | CONFORMS | — | 1130-1131 |
| — | CONTINUATION §6.10 | Wrong type or wrong stream mid-block → PROTOCOL_ERROR | CONFORMS | — | 1216-1221, 1294-1299 |
| — | header §4.1, §4.2 | Oversize rejected; reserved bit ignored; unknown types discarded | CONFORMS | — | 2920-2930, 1132-1134 |
| F-11.1 | header §4.2 | Oversize DATA on a stream may be a stream error | VIOLATES | MINOR | 2921-2924 |

**Counts:** 2 CRITICAL, 6 IMPORTANT, 4 MINOR, 1 NOT IMPLEMENTED (counted within MINOR),
33 rules CONFORMS.

## Suggested order of work

1. **F-5.1** — one-line fix, removes a deterministic connection kill against conformant servers.
2. **F-2.1** — CONTINUATION frame counter in both loops; unbounded remote-controlled loop.
3. **F-0 / F-0b** — typed error codes on `TlsHttpProtocolException`; unblocks the correct
   signalling in F-3.1, F-5.2, F-9.1 and F-9.2, and is itself a wire-fidelity issue.
4. **F-8.1** — one `continue` on `HasReceivedEndStream`, mirroring the guard already at 1082.
5. **F-3.1 / F-9.1 / F-9.2** — demote three over-broad connection errors to stream errors.
6. **F-1.1, F-6.1, F-8.2, F-11.1** — cleanup.
