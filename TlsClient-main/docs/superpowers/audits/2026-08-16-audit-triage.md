# Audit triage — IMPORTANT and MINOR findings at HEAD

Four RFC conformance audits were filed on 2026-08-16 against the HTTP/2 and HTTP/1.1 stacks.
Their CRITICAL findings were closed by the commits listed below. This document re-checks every
**IMPORTANT** and **MINOR** finding against the code as it stands today, because the audits'
`file:line` references are stale — most real code sits 130–350 lines below where the reports
cite it.

Baseline at triage time: `dotnet test TlsClient.slnx -c Release` → **402 passed, 0 failed**.
HEAD: `9760fab`.

## Counts

| | IMPORTANT | MINOR | Total |
|---|---|---|---|
| Already fixed | 13 | 3 | **16** |
| Still open | 0 | 15 | **15** |
| Falsified | 0 | 0 | **0** |
| **Total** | **13** | **18** | **31** |

**Every IMPORTANT finding is closed.** Everything still open is MINOR.

The commits that did the closing, and what each actually reached:

| Commit | Closed |
|---|---|
| `115b45b` | `SETTINGS_ENABLE_PUSH=0` (F-5.1) |
| `8732fa5` | unbounded CONTINUATION loop (F-2.1) |
| `c31c863` | HPACK integer shift overflow (1b) **and** the over-long-encoding ceiling (1c) |
| `1802553` + `b31ba5b` | the entire error-code/scope rework — F1, F2, F3, F4, F6, F7, F-3.1, F-8.1, F-9.1, F-9.2, hpack 6 and 8c |
| `520f8ca` | RFC 9113 §8.2.1 receive-side field validation — 8a, 8b |
| `e01fd41` | idle stream outranks the zero-increment rule (F-9.1 refinement) |
| `134d052`, `9c33e7c`, `0728afd`, `e859bb7`, `4343809` | HTTP/1.1 and proxy — 1.3, 2.2, 5.3, 5.4, 7.2 |

`b31ba5b` alone closes ten findings; it was clearly written against these audits.

---

## 1. Framing and streams (`2026-08-16-audit-framing-streams.md`)

| Finding | Sev | Verdict | Evidence |
|---|---|---|---|
| F1 oversize frame sends the wrong GOAWAY code | IMPORTANT | **ALREADY FIXED** | `1802553` added `TlsHttpProtocolException.Http2ErrorCode` (`TlsResponse.cs:175`); `b31ba5b` stamps `FrameSizeError` at `Http2Connection.cs:3275-3278`, and the read loop sends the declared code at `Http2Connection.cs:1102`. Test `Http2ErrorScopeTests.OversizeFrame_ReportsFrameSizeError`. |
| F2 per-frame-type size limits | MINOR | **ALREADY FIXED** | `b31ba5b`. PRIORITY=5 `Http2Connection.cs:1204-1211`; RST_STREAM=4 `:1584`→`:2677-2682`; PING=8 `:1560`; WINDOW_UPDATE=4 `:1668-1673`; SETTINGS %6 `:1441-1448` plus ACK-with-payload `:1450-1459`; GOAWAY <8 `:1606-1613`. Tests at `Http2ErrorScopeTests.cs:155/293/314/336`. |
| F3 PRIORITY size error escalated to a connection error | IMPORTANT | **ALREADY FIXED** | `b31ba5b`. PRIORITY no longer routes through `ValidateFrame`; `Http2Connection.cs:1204-1211` throws `{ FrameSizeError, IsStreamScoped = true }`. Test `PriorityWithAWrongLength_ResetsOneStreamAndSparesTheOthers`. |
| F5 rejected-push backlog cap | MINOR | **STILL OPEN** | `Http2Connection.cs:1400-1404`. Bare `>= 1024`, default (PROTOCOL_ERROR, connection-scoped) exception, no named constant, no XML doc. |
| F7 detected stream errors emit no RST_STREAM | IMPORTANT | **ALREADY FIXED** | `TryResetStreamAsync` (`Http2Connection.cs:2150-2179`) writes a real RST_STREAM and is reached from `FailStreamAsync:1178`. The body-limit case the audit named now throws `Malformed` from `EnqueueBody` (`:3034-3038`), called synchronously inside `HandleFrameAsync`'s try. Loopback tests read an actual RST_STREAM frame off the wire (`Http2ErrorScopeTests.cs:658`). |

**F5 — what a fix needs.** Name the constant, XML-document it citing RFC 9113 §5.4.1 ("An
endpoint can end a connection at any time"), and carry `Http2ErrorCode.EnhanceYourCalm`, which
§7 defines for exactly this ("the endpoint detected that its peer is exhibiting a behavior that
might be generating excessive load").

---

## 2. Frame types (`2026-08-16-audit-frame-types.md`)

| Finding | Sev | Verdict | Evidence |
|---|---|---|---|
| F-3.1 PRIORITY length != 5 kills the connection | IMPORTANT | **ALREADY FIXED** | `b31ba5b`, same site as F3 above. |
| F-8.1 non-NO_ERROR GOAWAY destroys completed streams | IMPORTANT | **ALREADY FIXED** | `b31ba5b` hoists the `HasReceivedEndStream` → `continue` guard (`Http2Connection.cs:1619-1627`) *above* the `pair.Key > lastStreamId \|\| error != NoError` test at `:1628`. Test `GoAway_LeavesAnAlreadyCompleteResponseIntact`, whose server writes `InternalError` explicitly. |
| F-8.2 Last-Stream-ID not retained across GOAWAYs | MINOR | **STILL OPEN** | `Http2Connection.cs:1615` — `lastStreamId` is still a method local. No field, no clamp. |
| F-9.1 zero increment on a stream must be a stream error | IMPORTANT | **ALREADY FIXED** | `b31ba5b` `Http2Connection.cs:1674` `IsStreamScoped = frame.StreamId != 0`; `e01fd41` hoists the idle check above it (`:1650-1664`). Tests `ZeroWindowUpdateOnAStream_...` and `ZeroWindowUpdateOnAnIdleStream_...`. |
| F-9.2 window overflow past 2^31-1 untyped and mis-scoped | IMPORTANT | **ALREADY FIXED** | `b31ba5b`. Connection `Http2Connection.cs:1685-1691` → `FlowControlError` + GOAWAY; stream `:1700-1707` → `FlowControlError` + RST_STREAM. Both are explicit `long` comparisons, so the audit's `checked`/`OverflowException` complaint no longer applies. Tests at `Http2ErrorScopeTests.cs:197` and `:379`. |

**F-8.2 — what a fix needs.** RFC 9113 §6.8: "An endpoint MUST NOT increase the value they send
in the last stream identifier, since the peers might already have retried unprocessed requests
on another connection." Promote `lastStreamId` to a field and `Math.Min`-clamp each subsequent
GOAWAY against it. Impact is confined to which streams get failed; `_isReusable` is already 0
by `:1614`, so no new stream can appear either way.

---

## 3. HPACK (`2026-08-16-audit-hpack.md`)

| Finding | Sev | Verdict | Evidence |
|---|---|---|---|
| 1c shift ceiling permits over-long encodings | MINOR | **ALREADY FIXED** | `c31c863`. Ceiling lowered 28→21 at `HpackCodec.cs:536`, value bound at `:540`. |
| 2a strict UTF-8 rejection of legal field values | MINOR | **STILL OPEN** | `HpackCodec.cs:582` still `new UTF8Encoding(false, true)`; `:586` turns the fallback into a connection-killing COMPRESSION_ERROR. |
| 3a no negative Huffman tests | MINOR | **STILL OPEN** | `HpackTests.HuffmanDecoder_DecodesRfc7541Vector` is the only Huffman test and is positive-only. The four throw sites `HpackHuffman.cs:733,776,792,800` have no regression coverage. |
| 4a table insertion precedes the header-list-size rejection | MINOR | **STILL OPEN** | `HpackCodec.cs:462` `Add(header)` runs before the size accounting at `:492-498`. |
| 5a limit applied before our SETTINGS is acknowledged | MINOR | **STILL OPEN** | `HpackCodec.cs:471-476`; no comment recording the deliberate leniency. |
| 6 decoding errors must be a connection COMPRESSION_ERROR | IMPORTANT | **ALREADY FIXED** | `b31ba5b`. `HpackDecodingError.Create` (`HpackCodec.cs:644-648`) stamps `CompressionError` and leaves `IsStreamScoped` false, so the stream-scoped catch filter at `Http2Connection.cs:1131` cannot intercept it. Test `HpackDecodingFailure_ReportsCompressionError`. |
| 8a field-name validation covers only the uppercase range | IMPORTANT | **ALREADY FIXED** | `520f8ca`. `ValidateReceivedField` (`Http2Connection.cs:2885-2910`) rejects empty names, `<= 0x20`, `>= 0x7f`, `A`–`Z`, and a colon at any index but 0 — exactly §8.2.1's mandatory ranges. Tests at `Http2ErrorScopeTests.cs:24/76/104`. |
| 8b field-value validation is absent on receive | IMPORTANT | **ALREADY FIXED** | `520f8ca`. `Http2Connection.cs:2903-2909` rejects NUL/CR/LF. Test `ResponseFieldValueWithCrLf_...`. The leading/trailing SP/HTAB half is a documented carve-out at `Http2Connection.cs:2880-2883` — see finding 4.3 below, which is where it is now tracked. |
| 8c malformed messages escalated to connection errors | MINOR | **ALREADY FIXED** | `b31ba5b`. `Malformed()` (`Http2Connection.cs:2851`) sets `IsStreamScoped = true`; `HandleFrameAsync:1131-1134` routes it to `FailStreamAsync`. |
| 8d validation not applied uniformly across field blocks | MINOR | **STILL OPEN** | `Http2Connection.cs:1342` gates `ApplyHeaders` behind a stream lookup; `:1422` discards the PUSH_PROMISE field block with `_ = _decoder.Decode(...)` and no validation. |

---

## 4. HTTP semantics (`2026-08-16-audit-http-semantics.md`)

| Finding | Sev | Verdict | Evidence |
|---|---|---|---|
| 1.3 authority-form for a caller-issued CONNECT | IMPORTANT | **ALREADY FIXED** | `0728afd`. `Http11RequestWriter.cs:30-33`. Tests `PlainConnect_UsesTheAuthorityFormRequestTarget` and `ExtendedConnect_KeepsTheOriginFormRequestTarget`. |
| 1.5 asterisk-form (`OPTIONS *`) on HTTP/1.1 | MINOR | **STILL OPEN** | `Http11RequestWriter.cs:30-37` never consults `PathOverride`; only `Http2Connection.cs:809` honours it. An empty target degrades to `"/"` at `:36`. |
| 2.2 both Content-Length and Transfer-Encoding on a response | IMPORTANT | **ALREADY FIXED** | `e859bb7`. `Http11ResponseReader.cs:116-121` marks the connection non-reusable. Test `ReadAsync_ContentLengthAlongsideTransferEncodingIsNotReusable`. |
| 3.2 whitespace tolerated around chunk-size | MINOR | **STILL OPEN** | `Http11ResponseReader.cs:340`/`:383` still `.Trim()`, `:341`/`:386` still `NumberStyles.HexNumber` (which implies `AllowLeadingWhite \| AllowTrailingWhite`). |
| 3.6 negative header budget throws the wrong exception type | MINOR | **STILL OPEN** | `BufferedHttpReader.cs:27` `new MemoryStream(Math.Min(maximumBytes, 256))` throws `ArgumentOutOfRangeException` for a negative budget, escaping the `TlsHttpProtocolException` contract `ShouldRetryException` classifies on. |
| 4.3 leading/trailing whitespace in caller-supplied values | MINOR | **STILL OPEN** | `TlsHeaders.cs:214-222` rejects only CR/LF; `Http11RequestWriter.cs:225-233` rejects only control characters. |
| 4.5 HTTP/2 send-side field-name validation is narrower than §8.2.1 | MINOR | **STILL OPEN** | `HpackCodec.cs:333-343`. Already recorded as a deliberate split at `Http2Connection.cs:2876-2879`. |
| 5.4 ProxyTunnel discards buffered post-header octets | IMPORTANT | **ALREADY FIXED** | `4343809`. `BufferedHttpReader.HasBufferedBytes` (`:21`) plus the fail-loud guard at `ProxyTunnel.cs:97-101`. Test `Http_RejectsOctetsReadPastTheConnectResponseHead`. |
| 5.5 ProxyTunnel does not skip a 1xx before the CONNECT response | MINOR | **STILL OPEN** | `ProxyTunnel.cs:66` parses the first status line as final; `:83` then reports a `100`/`103` interim as a proxy rejection. |
| 6.4 duplicate `Location` fields resolve silently to the first | MINOR | **STILL OPEN** | `TlsSession.cs:664` and `:706` both `GetFirstOrDefault("Location")`. |
| 7.3 abandoned delay timer | MINOR | **STILL OPEN** | `Http11Connection.cs:287` `Task.Delay(expectTimeout, cancellationToken)` with no linked CTS; the losing timer is never cancelled. |

---

## Disposition

Eleven fixed in the commits that follow this document:

F5, hpack 3a / 4a / 5a, and http-semantics 1.5, 3.2, 3.6, 4.3, 5.5, 6.4, 7.3.

Four deliberately not fixed — each recorded with its file:line and reason under "Audit findings
deliberately not fixed" in `docs/superpowers/HANDOFF.md`:

hpack 2a (UTF-8 strictness — the fix needs the wire octet count threaded through the decoder
before the dynamic-table accounting can survive it), hpack 8d (validation uniformity — the
unvalidated blocks are the ones nothing consumes), http-semantics 4.5 (send-side field-name
validation — a deliberate, already-documented split, on an unreachable path), frame-types F-8.2
(Last-Stream-ID retention — the clamp alone changes nothing observable, so it would be code no
test could turn red; the finding's real content is retry semantics).
