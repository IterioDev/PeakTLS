# RFC conformance audit — HPACK (RFC 7541) and field validity (RFC 9113 §8.2)

Date: 2026-08-16
Scope: `src/TlsClient/HpackCodec.cs` (encoder + decoder), `src/TlsClient/HpackHuffman.cs`,
receive-side field validation in `src/TlsClient/Http2Connection.cs`,
fuzz target `tools/TlsClient.Fuzz/Program.cs`.
Emphasis: the DECODER, which parses attacker-controlled bytes off the network.

RFC text quoted from `https://www.rfc-editor.org/rfc/rfc7541.txt` and
`https://www.rfc-editor.org/rfc/rfc9113.txt`, fetched during this audit.

Severity key:
**CRITICAL** — memory/hang/crash from network input, or connection-state corruption.
**IMPORTANT** — wrong on the wire.
**MINOR** — interop wart, missing test, over-strictness.

---

## 1. Integer decoding (RFC 7541 §5.1)

RFC 7541 §5.1 pseudocode:

> ```
> decode I from the next N bits
> if I < 2^N - 1, return I
> else
>     M = 0
>     repeat
>         B = next octet
>         I = I + (B & 127) * 2^M
>         M = M + 7
>     while B & 128 == 128
>     return I
> ```

RFC 7541 §7.4 (Implementation Limits):

> An implementation of HPACK needs to ensure that large values for
> integers, long encoding for integers, or long string literals do not
> create security weaknesses.
>
> An implementation has to set a limit for the values it accepts for
> integers, as well as for the encoded length (see Section 5.1).

### 1a. Continuation loop is bounded — CONFORMS

`HpackCodec.cs:524-544`. The loop terminates on three conditions: end of block
(`offset >= source.Length`, line 526), a shift ceiling (`shift > 28`, line 526), and the
cleared continuation bit (line 539). An attacker cannot hang the reader with an
arbitrarily long continuation run — it is cut off after five octets. No unbounded shift,
no hang.

### 1b. Signed shift truncation yields a NEGATIVE integer — **CRITICAL**

`src/TlsClient/HpackCodec.cs:533`

```csharp
value = checked(value + ((next & 0x7f) << shift));
```

`checked` in C# governs `+ - * /`, `++`, `--`, unary `-`, and explicit numeric
conversions. It does **not** govern the shift operators. At the last permitted iteration
`shift == 28`, `(next & 0x7f)` is an `int` of up to 127, and `127 << 28` overflows the
32-bit result silently: bits 32-34 are discarded, leaving `0xF0000000`, i.e.
`-268435456`. The subsequent `checked(+)` then adds a negative number, which does not
overflow, so no `OverflowException` is raised and the guard at line 535-538 never fires.

Verified arithmetic (int32 semantics, identical in C# and JS):

| input bytes (7-bit prefix) | `ReadInteger` returns |
|---|---|
| `FF 80 80 80 80 7F` | `-268435329` |
| `FF 80 80 80 80 08` | `-2147483521` |

Two of the four `ReadInteger` call sites consume the result without a lower-bound check:

* **Indexed field**, `HpackCodec.cs:450-455`. The only guard is `index == 0`; a negative
  index passes and reaches `Get(index)`.
* **Literal name index**, `HpackCodec.cs:504-508` (`ReadName`), same path into `Get`.

`Get` then does, at `HpackCodec.cs:583-595`:

```csharp
if (index <= HpackStaticTable.Entries.Length)
{
    return HpackStaticTable.Entries[index - 1];
}
```

A negative `index` satisfies `index <= 61`, so control flows into the static-table branch
and indexes `Entries[-268435330]`. The bounds check at line 590 (`(uint)dynamicIndex >=
(uint)_dynamicTable.Count`) is on the *other* branch and is never reached. Result:
**`IndexOutOfRangeException`**, a type the decoder never intends to raise.

Consequences at the connection layer, `Http2Connection.cs:1071-1084`:

```csharp
catch (Exception exception)
{
    Volatile.Write(ref _isReusable, 0);
    if (exception is TlsHttpProtocolException)
    {
        await TrySendGoAwayAsync(Http2ErrorCode.ProtocolError).ConfigureAwait(false);
    }
    FailAll(
        exception is TlsHttpProtocolException
            ? exception
            : new IOException("The HTTP/2 connection failed.", exception),
        ...);
}
```

`IndexOutOfRangeException` is not a `TlsHttpProtocolException`, so:

1. **No GOAWAY is sent at all** — the connection is dropped silently, which RFC 9113
   §4.3 requires to be a connection error of type COMPRESSION_ERROR (see item 6).
2. Every in-flight stream is failed with a generic
   `IOException("The HTTP/2 connection failed.")` instead of the protocol exception,
   so callers cannot distinguish a malicious peer from a socket fault, and retry logic
   keyed on transport errors may replay requests against the same hostile server.

Six bytes from the network reach this. It is trivially reachable from a
`HEADERS` frame payload.

**Fix.** Accumulate in a wider type and bound the result explicitly, replacing
`HpackCodec.cs:523-544`:

```csharp
var shift = 0;
long accumulated = value;
while (true)
{
    if ((uint)offset >= (uint)source.Length || shift > 21)
    {
        throw new TlsHttpProtocolException("The HPACK integer is truncated or too large.");
    }
    var next = source[offset++];
    accumulated += (long)(next & 0x7f) << shift;
    if (accumulated > int.MaxValue)
    {
        throw new TlsHttpProtocolException("The HPACK integer is too large.");
    }
    if ((next & 0x80) == 0)
    {
        return (int)accumulated;
    }
    shift += 7;
}
```

A `shift` ceiling of 21 (four continuation octets) already covers every value up to
`int.MaxValue` with the shortest legal encoding; the `> int.MaxValue` test then catches
the long-encoding case that §7.4 warns about. Defence in depth: also make `Get` reject
`index <= 0` at `HpackCodec.cs:585` rather than assuming callers screened it, since both
call sites route through it.

### 1c. Shift ceiling permits over-long encodings — MINOR

`HpackCodec.cs:526` allows `shift` up to 28, i.e. five continuation octets carrying 35
payload bits. RFC 7541 §7.4 asks for "a limit ... as well as for the encoded length".
Folded into the fix above.

---

## 2. String literal decoding (RFC 7541 §5.2) — CONFORMS

* End-of-block before the length prefix: `HpackCodec.cs:549-552`.
* Declared length exceeding the remaining block: `HpackCodec.cs:555-558`,
  `if (length < 0 || length > block.Length - offset)`. This also absorbs the negative
  value from item 1b on this path — the string-length call site is the one that *is*
  guarded.
* Huffman buffer sizing: `HpackCodec.cs:566`, `new byte[Math.Max(32, checked(length * 2))]`,
  with `HpackHuffman.Decode` growing it by doubling (`HpackHuffman.cs:712-716`,
  `779-783`). `length` is already bounded by the remaining block, so the allocation is
  bounded by twice the compressed block, itself capped at `MaximumResponseHeaderBytes`
  (see item 7). No unbounded allocation.

### 2a. Strict UTF-8 rejection of legal field values — MINOR

`HpackCodec.cs:571-581` decodes every string with `new UTF8Encoding(false, true)` and
converts a `DecoderFallbackException` into a connection-killing
`TlsHttpProtocolException`. HPACK strings are opaque octet sequences, and RFC 9110 §5.5
permits `obs-text` (0x80-0xFF) in field values, recommending they be treated as opaque
data. A peer emitting a legacy ISO-8859-1 header value therefore tears down the whole
connection. Consider decoding with Latin-1 for values, or with a replacement fallback,
rather than failing the connection.

---

## 3. Huffman decoding (RFC 7541 §5.2, Appendix B) — CONFORMS (all three MUSTs)

RFC 7541 §5.2:

> Upon decoding, an incomplete code at the end of the encoded data is
> to be considered as padding and discarded.  A padding strictly longer
> than 7 bits MUST be treated as a decoding error.  A padding not
> corresponding to the most significant bits of the code for the EOS
> symbol MUST be treated as a decoding error.  A Huffman-encoded string
> literal containing the EOS symbol MUST be treated as a decoding
> error.

All three are enforced in `src/TlsClient/HpackHuffman.cs`:

| MUST | Enforced at | Mechanism |
|---|---|---|
| EOS symbol inside the encoding | `HpackHuffman.cs:729-734` | EOS is absent from the decoding tree, so traversal lands on next-table index 0 and throws `TlsHttpProtocolException`. |
| Padding strictly longer than 7 bits | `HpackHuffman.cs:796-801` | A trailing all-ones octet consumes a full 8 bits in the main loop and leaves `lookupTableIndex != 0` at the end, which throws. |
| Padding not matching the EOS prefix | `HpackHuffman.cs:749-757`, `765-793` | The tail loop breaks only when *every* remaining bit is 1 (line 752-757). Otherwise it attempts a symbol lookup; a code longer than the bits available (`bitsInAcc < 0`, line 773-777) or an incomplete traversal (line 789-793) throws. |

The implementation is the table-driven design also used by the .NET runtime, and its
error paths line up with the RFC sentence-for-sentence.

### 3a. No negative Huffman tests — MINOR

`tests/TlsClient.Tests/HpackTests.cs:8` (`HuffmanDecoder_DecodesRfc7541Vector`) is the
only Huffman test and it is positive-only. None of the three MUST-error cases above has
a regression test, so a future optimisation of the tail loop could silently reintroduce
a classic HPACK vulnerability. Add three one-line cases: an EOS-bearing encoding, a
trailing `0xFF` padding octet, and a trailing partial pad containing a zero bit.

---

## 4. Dynamic table (RFC 7541 §4.1-4.4)

RFC 7541 §4.1:

> The size of an entry is the sum of its name's length in octets (as
> defined in Section 5.2), its value's length in octets, and 32.

RFC 7541 §4.4:

> It is not an error to
> attempt to add an entry that is larger than the maximum size; an
> attempt to add an entry larger than the maximum size causes the table
> to be emptied of all existing entries and results in an empty table.

RFC 7541 §6.1:

> The index value of 0 is not used.  It MUST be treated as a decoding
> error if found in an indexed header field representation.

| Rule | Verdict | Evidence |
|---|---|---|
| Entry size = name + value + 32 | CONFORMS | `HpackCodec.cs:621-622`. Uses `Encoding.UTF8.GetByteCount`, which round-trips to the original octet count because `DecodeUtf8` (line 571-581) has already rejected anything that is not valid UTF-8. |
| Eviction on insert | CONFORMS | `HpackCodec.cs:606-608` inserts then calls `Evict()` (line 611-619). Evicting after insertion rather than before is behaviourally identical here because the oversize case is screened first at line 600. |
| Eviction when the maximum shrinks (§4.3) | CONFORMS | `HpackCodec.cs:478` calls `Evict()` immediately after lowering `_maximumDynamicTableSize`. |
| Oversize entry clears the table, is not an error | CONFORMS | `HpackCodec.cs:600-605`. Clears and returns; no throw. |
| Index 0 in an indexed field is a decoding error | CONFORMS | `HpackCodec.cs:451-454`. |
| Index beyond static+dynamic must error, not throw | **VIOLATES** | `HpackCodec.cs:590-593` handles the positive out-of-range case correctly with `(uint)dynamicIndex >= (uint)_dynamicTable.Count`. But the *negative* index from item 1b never reaches it — line 585 routes negatives into the static-table branch and raises `IndexOutOfRangeException`. See item 1b; same root cause, same fix. **CRITICAL** (counted once, under item 1b). |

### 4a. Table insertion precedes the header-list-size rejection — MINOR

`HpackCodec.cs:462` calls `Add(header)` for a literal-with-incremental-indexing field
*before* the header-list-size check at line 492-498 can reject the block. If that check
throws, the dynamic table has already been mutated. Today this is inert because the
exception kills the connection and the decoder is discarded, but it is a state-mutation
ordering wart that becomes a real desync the moment anyone makes that error recoverable.
Move the size accounting above the representation dispatch, or compute the size before
`Add`.

---

## 5. Dynamic table size update (RFC 7541 §6.3) — CONFORMS

RFC 7541 §6.3:

> The new maximum size MUST be lower than or equal to the limit
> determined by the protocol using HPACK.  A value that exceeds this
> limit MUST be treated as a decoding error.  In HTTP/2, this limit is
> the last value of the SETTINGS_HEADER_TABLE_SIZE parameter (see
> Section 6.5.2 of [HTTP2]) received from the decoder and acknowledged
> by the encoder (see Section 6.5.3 of [HTTP2]).

RFC 7541 §4.2:

> This dynamic table size
> update MUST occur at the beginning of the first header block
> following the change to the dynamic table size.

* **Bound against the advertised maximum — CONFORMS.** `HpackCodec.cs:471-477` compares
  against `_configuredMaximumDynamicTableSize`, the value passed to the decoder
  constructor (`Http2Connection.cs:65`, `new HpackDecoder(http2.LocalHeaderTableSize)`),
  which is the same `state.HeaderTableSize` this client advertises in SETTINGS
  (`TlsHttp2Options.cs:264`, `439`, default 4096 at `TlsHttp2Options.cs:496`, capped at
  16 MiB at `TlsHttp2Options.cs:11`). The comparison is `(uint)size >`, so the negative
  value from item 1b becomes a huge `uint` and is correctly rejected — this call site is
  safe.
* **Initial maximum — CONFORMS.** `HpackCodec.cs:435`,
  `Math.Min(maximumDynamicTableSize, 4096)`, matching the RFC 9113 §6.5.2 initial value
  of SETTINGS_HEADER_TABLE_SIZE regardless of what this client intends to advertise.
* **Position rule — CONFORMS.** `mayResize` is initialised true (`HpackCodec.cs:443`),
  checked before accepting an update (line 466-470), and cleared once a header field has
  been emitted (line 491). The `continue` at line 479 skips the clearing, which correctly
  permits the consecutive updates §4.2 describes. Covered by
  `tests/TlsClient.Tests/HpackTests.cs:63` (`Decoder_RejectsTableResizeAfterHeaderField`).

### 5a. Limit applied before our SETTINGS is acknowledged — MINOR

§6.3 pins the limit to the last SETTINGS_HEADER_TABLE_SIZE "received from the decoder
**and acknowledged by the encoder**". `HpackCodec.cs:472` applies the configured value
from the very first field block, before any SETTINGS exchange. This errs lenient (it
accepts an update a strict reading would reject during the pre-ACK window) and is bounded
by the configured cap, so it is not exploitable. Worth a comment so it is not mistaken
for an oversight.

---

## 6. Decoding errors must be a connection error of type COMPRESSION_ERROR — **VIOLATES (IMPORTANT)**

RFC 9113 §4.3:

> A receiver
> MUST terminate the connection with a connection error (Section 5.4.1)
> of type COMPRESSION_ERROR if it does not decompress a field block.
>
> A decoding error in a field block MUST be treated as a connection
> error (Section 5.4.1) of type COMPRESSION_ERROR.

**Connection-scoped: CONFORMS.** `Http2Connection.cs:1071-1084` treats any
`TlsHttpProtocolException` out of the read loop as terminal — it clears `_isReusable`,
sends GOAWAY, and fails every stream. HPACK state is never resynchronised on a live
connection. Correct.

**Error code: VIOLATES.** `Http2Connection.cs:1076` sends
`Http2ErrorCode.ProtocolError` (0x1) for *every* protocol exception, HPACK failures
included. `Http2ErrorCode.CompressionError = 0x9` is declared at
`src/TlsClient/TlsHttp2ShutdownOptions.cs:62` and is **never referenced anywhere in
`src/`** — the only occurrence of the string "COMPRESSION_ERROR" in the source tree is a
comment in the encoder at `HpackCodec.cs:127`. A conforming peer receiving GOAWAY(0x1)
for a compression fault is told the wrong thing about why the connection died.

**Worse: the item 1b path sends no GOAWAY at all**, because
`IndexOutOfRangeException` fails the `is TlsHttpProtocolException` test at line 1074.

**Fix.** Give HPACK failures a distinguishable identity and map it to the right code:

```csharp
// TlsResponse.cs — carry the code on the exception
public sealed class TlsHttpProtocolException : IOException
{
    internal Http2ErrorCode Http2ErrorCode { get; init; } = Http2ErrorCode.ProtocolError;
    ...
}

// Http2Connection.cs:1074-1077
if (exception is TlsHttpProtocolException protocolException)
{
    await TrySendGoAwayAsync(protocolException.Http2ErrorCode).ConfigureAwait(false);
}
```

and set `Http2ErrorCode = Http2ErrorCode.CompressionError` on the eleven throw sites in
`HpackCodec.cs` (lines 453, 468, 474, 497, 514, 528, 537, 551, 557, 579, 592) and the
four in `HpackHuffman.cs` (lines 733, 776, 792, 800). Fixing item 1b removes the
no-GOAWAY case.

---

## 7. Header list size bounds — CONFORMS (clean)

RFC 9113 §6.5.2 defines SETTINGS_MAX_HEADER_LIST_SIZE over the uncompressed size,
"the sum of the length of the field name, the length of the field value, and 32".

* **Bound is applied.** `Http2Connection.cs:70-72`:
  `_headerListDecodeBound = min(LocalMaxHeaderListSize, MaximumResponseHeaderBytes)`,
  falling back to `MaximumResponseHeaderBytes` when no setting is declared.
  `MaximumResponseHeaderBytes` defaults to 64 KiB (`TlsSessionOptions.cs:79`) and is
  validated into 1 KiB..1 MiB (`TlsSessionOptions.cs:230`). There is no unbounded path.
* **Uses the RFC formula.** `HpackCodec.cs:492-498` accumulates
  `32 + UTF8.GetByteCount(name) + UTF8.GetByteCount(value)` per field, in a `long`, under
  `checked`, and throws once the running total exceeds the bound. Correct formula,
  correct accumulator width.
* **The compressed side is bounded too.** `Http2Connection.cs:2374` caps the accumulated
  HEADERS + CONTINUATION fragment buffer at `MaximumResponseHeaderBytes` before
  decompression begins, so the input to `Decode` is bounded independently of the output.
* **Dynamic table memory is bounded** by `_maximumDynamicTableSize`, itself bounded by the
  configured value (default 4096, hard cap 16 MiB at `TlsHttp2Options.cs:11`).

A compression bomb — a small block that indexes a large entry thousands of times — is
therefore capped at roughly 64 KiB of decoded headers plus a 4 KiB table per connection.
This item is clean.

---

## 8. RFC 9113 §8.2 field validity on RECEIVE — PARTIAL

Receive-side validation lives in `Http2StreamState.ApplyHeaders`,
`src/TlsClient/Http2Connection.cs:2573-2649`, called from `Http2Connection.cs:1230`.

RFC 9113 §8.2.1:

> Failure to validate fields can be exploited for request smuggling attacks. In
> particular, unvalidated fields might enable attacks when messages are forwarded using
> HTTP/1.1, where characters such as carriage return (CR), line feed (LF), and COLON
> are used as delimiters. Implementations MUST perform the following minimal validation
> of field names and values:
>
> *  A field name MUST NOT contain characters in the ranges 0x00-0x20,
>    0x41-0x5a, or 0x7f-0xff (all ranges inclusive). ...
> *  With the exception of pseudo-header fields (Section 8.3), which
>    have a name that starts with a single colon, field names MUST NOT
>    include a colon (ASCII COLON, 0x3a).
> *  A field value MUST NOT contain the zero value (ASCII NUL, 0x00),
>    line feed (ASCII LF, 0x0a), or carriage return (ASCII CR, 0x0d) at
>    any position.
> *  A field value MUST NOT start or end with an ASCII whitespace
>    character (ASCII SP or HTAB, 0x20 or 0x09).

RFC 9113 §8.2.2:

> An endpoint MUST NOT generate an HTTP/2 message containing
> connection-specific header fields.  This includes the Connection
> header field and those listed as having connection-specific semantics
> in Section 7.6.1 of [HTTP] (that is, Proxy-Connection, Keep-Alive,
> Transfer-Encoding, and Upgrade).  Any message containing connection-
> specific header fields MUST be treated as malformed (Section 8.1.1).
>
> The only exception to this is the TE header field, which MAY be
> present in an HTTP/2 request; when it is, it MUST NOT contain any
> value other than "trailers".

| Rule | Verdict | Evidence |
|---|---|---|
| Uppercase field names | CONFORMS | `Http2Connection.cs:2580`, rejects any `>= 'A' and <= 'Z'`. |
| Connection-specific fields | CONFORMS | `Http2Connection.cs:2595-2600` rejects `connection`, `proxy-connection`, `keep-alive`, `upgrade`, `transfer-encoding` — all five named by §8.2.2. |
| TE other than "trailers" | CONFORMS | `Http2Connection.cs:2601-2607`. |
| Other invalid characters in NAMES | **NOT IMPLEMENTED** | see 8a |
| Invalid characters in VALUES | **NOT IMPLEMENTED** | see 8b |

### 8a. Field-name validation covers only the uppercase range — **IMPORTANT**

`Http2Connection.cs:2580` is the entire name check. Of the ranges §8.2.1 makes
mandatory, only 0x41-0x5a is enforced. Accepted today:

* 0x00-0x20 — including NUL, CR (0x0d), LF (0x0a), HTAB, and SP inside a field name.
* 0x7f-0xff — DEL and all high-bit octets.
* An embedded colon at a non-leading position (`x:y`), which §8.2.1 prohibits outside
  pseudo-headers.
* An **empty** field name. `"".StartsWith(':')` is false at line 2584, so an empty name
  falls straight into the regular-field branch at line 2608 and is accepted.

The RFC names request smuggling as the specific risk, and the risk is live here: these
names flow into `BuildHeaders` (line 2634) and out to callers as ordinary `TlsHeaders`,
where anything that re-serialises them over HTTP/1.1 — a logging sink, a proxy, a
downstream client — inherits the injection.

### 8b. Field-value validation is absent on receive — **IMPORTANT**

There is no check anywhere in `ApplyHeaders` for NUL / LF / CR in a field value, nor for
leading or trailing SP/HTAB. A response header value containing a raw `\r\n` is decoded,
accepted, and handed to the caller.

The asymmetry is stark and is worth naming: the **encoder** validates exactly this on the
send path, `HpackCodec.cs:333-344`:

```csharp
if (header.Value.Any(character => character is '\0' or '\r' or '\n'))
{
    throw new HttpRequestException("HTTP/2 header values cannot contain NUL, CR, or LF.");
}
```

The rule the client refuses to *emit* it will happily *accept*. Since the peer is the
untrusted party and the client is not, the check belongs on the receive path at least as
much as on the send path.

**Fix for 8a + 8b.** One helper, applied in the `ApplyHeaders` loop before the existing
checks, replacing the uppercase test at `Http2Connection.cs:2580`:

```csharp
private static void ValidateReceivedField(HpackHeader field)
{
    var name = field.Name;
    if (name.Length == 0)
    {
        throw new TlsHttpProtocolException("An HTTP/2 field name is empty.");
    }
    for (var index = 0; index < name.Length; index++)
    {
        var character = name[index];
        if (character <= 0x20 || character >= 0x7f ||
            character is >= 'A' and <= 'Z' ||
            (character == ':' && index != 0))
        {
            throw new TlsHttpProtocolException("An HTTP/2 field name contains a prohibited character.");
        }
    }
    var value = field.Value;
    if (value.Any(character => character is '\0' or '\n' or '\r'))
    {
        throw new TlsHttpProtocolException("An HTTP/2 field value contains NUL, CR, or LF.");
    }
    if (value.Length != 0 &&
        (value[0] is ' ' or '\t' || value[^1] is ' ' or '\t'))
    {
        throw new TlsHttpProtocolException("An HTTP/2 field value has leading or trailing whitespace.");
    }
}
```

Note the `character >= 0x7f` test also subsumes the strictness discussion in item 2a for
*names*; values keep their own, laxer rule as the RFC intends.

### 8c. Malformed messages are escalated to connection errors — MINOR

RFC 9113 §8.1.1:

> Malformed requests or responses that are detected MUST be treated as a stream error
> (Section 5.4.2) of type PROTOCOL_ERROR.

Every `ApplyHeaders` rejection (`Http2Connection.cs:2582`, `2588`, `2599`, `2606`,
`2618`, `2625`, `2643`) throws `TlsHttpProtocolException` out of the read loop, where
`Http2Connection.cs:1071-1084` converts it into a GOAWAY and fails *every* stream on the
connection. One malformed response therefore destroys unrelated concurrent requests. This
is over-strict rather than unsafe, but it is a real availability difference from the
spec — and it is a different rule from item 6, where connection scope *is* correct
because HPACK state cannot be resynchronised. Malformed-message detection has no such
excuse: the decoder state is already consistent by the time `ApplyHeaders` runs, so a
RST_STREAM(PROTOCOL_ERROR) is sufficient and correct.

### 8d. Validation is not applied uniformly across field blocks — MINOR

* `Http2Connection.cs:1228` only calls `ApplyHeaders` when the stream is known
  (`_streams.TryGetValue`); a HEADERS block for an unknown stream is decoded but never
  validated.
* `Http2Connection.cs:1303` decodes PUSH_PROMISE field blocks with `_ = _decoder.Decode(...)`
  and discards the result without validation.

Neither is exploitable today because both results are dropped. Both are, however, correct
on the point that matters for compression state — RFC 9113 §4.3 requires decompression to
happen "even if the frames are to be discarded", and `Http2Connection.cs:1225` and `1303`
both decode unconditionally before any stream lookup. That part **CONFORMS**.

---

## 9. Fuzz target coverage (`tools/TlsClient.Fuzz`)

**What the "hpack" target actually does**, `tools/TlsClient.Fuzz/Program.cs:92-94`:

```csharp
case "hpack":
    _ = new HpackDecoder(4096).Decode(data, 16 * 1024);
    break;
```

**Correctly configured.** `IsExpectedRejection` (`Program.cs:231-240`) swallows
`IOException`, and `TlsHttpProtocolException` derives from `IOException`
(`src/TlsClient/TlsResponse.cs:154`), so every legitimate decoder rejection is absorbed
as expected. `IndexOutOfRangeException` is **not** in that list, so the harness *would*
surface the item 1b crash if an input ever reached it. The harness is not the problem.

**What it does not cover.**

1. **No coverage-guided engine.** The only driver is `--smoke`
   (`Program.cs:22-28`, `45-59`), a `Random`-seeded byte mutator (`Program.cs:273-288`)
   over a one-byte seed, `"hpack" => [0x88]` (`Program.cs:246`). The probability of a
   blind mutator emitting the six-byte sequence `FF 80 80 80 80 7F` is negligible. This
   is precisely why item 1b survived: the target exists, the oracle is right, and the
   input generator cannot get there.
2. **Single-block, fresh-decoder only.** A new `HpackDecoder` per input means the
   cross-block dynamic-table state machine — eviction, index drift, size updates spanning
   blocks — is never exercised. That state machine is where HPACK decoders historically
   break.
3. **No RFC 7541 Appendix C corpus.** The published request/response vectors (C.3, C.4,
   C.5, C.6) with and without Huffman are the natural seed corpus and are absent.
4. **RFC 9113 §8.2 validation is out of scope entirely.** `ApplyHeaders` is never
   invoked by any target, so items 8a and 8b have no fuzz coverage at all.

**Recommended target shape** (replacing `Program.cs:92-94`), which costs three lines and
covers the state machine:

```csharp
case "hpack":
{
    var decoder = new HpackDecoder(4096);
    // Split the input into length-prefixed blocks so one decoder sees a sequence.
    var cursor = 0;
    while (cursor < data.Length)
    {
        var blockLength = Math.Min(data[cursor++], data.Length - cursor);
        _ = decoder.Decode(data.AsSpan(cursor, blockLength), 16 * 1024);
        cursor += blockLength;
    }
    break;
}
```

Then seed the corpus with the Appendix C vectors plus the item 1b crash input.

---

## Summary

| # | Area | Rule | Verdict | Severity | Location |
|---|---|---|---|---|---|
| 1a | Integer decoding | Continuation loop bounded (§5.1, §7.4) | CONFORMS | — | `HpackCodec.cs:524-544` |
| 1b | Integer decoding | Value must stay in range; index errors must not crash | **VIOLATES** | **CRITICAL** | `HpackCodec.cs:533`, `585-587`; `Http2Connection.cs:1074-1082` |
| 1c | Integer decoding | Limit the encoded length (§7.4) | PARTIAL | MINOR | `HpackCodec.cs:526` |
| 2 | String literals | Length bounds, Huffman sizing (§5.2) | CONFORMS | — | `HpackCodec.cs:549-568` |
| 2a | String literals | Opaque octets vs strict UTF-8 | over-strict | MINOR | `HpackCodec.cs:571-581` |
| 3 | Huffman | EOS symbol MUST error (§5.2) | CONFORMS | — | `HpackHuffman.cs:729-734` |
| 3 | Huffman | Padding > 7 bits MUST error (§5.2) | CONFORMS | — | `HpackHuffman.cs:796-801` |
| 3 | Huffman | Non-EOS padding MUST error (§5.2) | CONFORMS | — | `HpackHuffman.cs:749-793` |
| 3a | Huffman | Regression coverage for the three MUSTs | missing | MINOR | `tests/TlsClient.Tests/HpackTests.cs:8` |
| 4 | Dynamic table | Size = name + value + 32 (§4.1) | CONFORMS | — | `HpackCodec.cs:621-622` |
| 4 | Dynamic table | Eviction on insert and on shrink (§4.3, §4.4) | CONFORMS | — | `HpackCodec.cs:478`, `606-619` |
| 4 | Dynamic table | Oversize entry clears table, not an error (§4.4) | CONFORMS | — | `HpackCodec.cs:600-605` |
| 4 | Dynamic table | Index 0 is a decoding error (§6.1) | CONFORMS | — | `HpackCodec.cs:451-454` |
| 4 | Dynamic table | Out-of-range index must error, not throw | **VIOLATES** | **CRITICAL** (= 1b) | `HpackCodec.cs:585-593` |
| 4a | Dynamic table | Insert ordering vs list-size rejection | wart | MINOR | `HpackCodec.cs:462`, `492-498` |
| 5 | Size update | MUST NOT exceed advertised maximum (§6.3) | CONFORMS | — | `HpackCodec.cs:471-477` |
| 5 | Size update | MUST appear at block start (§4.2) | CONFORMS | — | `HpackCodec.cs:443`, `466-491` |
| 5a | Size update | Limit pinned to the *acknowledged* setting | lenient | MINOR | `HpackCodec.cs:472` |
| 6 | Error handling | Decoding error = connection error (§4.3) | CONFORMS | — | `Http2Connection.cs:1071-1084` |
| 6 | Error handling | ...of type COMPRESSION_ERROR (§4.3) | **VIOLATES** | **IMPORTANT** | `Http2Connection.cs:1076`; `TlsHttp2ShutdownOptions.cs:62` unused |
| 7 | Header list size | Bounded, RFC size formula | CONFORMS | — | `Http2Connection.cs:70-72`, `2374`; `HpackCodec.cs:492-498` |
| 8 | Field validity | Uppercase names malformed (§8.2.1) | CONFORMS | — | `Http2Connection.cs:2580` |
| 8 | Field validity | Connection-specific fields malformed (§8.2.2) | CONFORMS | — | `Http2Connection.cs:2595-2600` |
| 8 | Field validity | TE only "trailers" (§8.2.2) | CONFORMS | — | `Http2Connection.cs:2601-2607` |
| 8a | Field validity | Prohibited characters in names (§8.2.1) | **NOT IMPLEMENTED** | **IMPORTANT** | `Http2Connection.cs:2580-2584` |
| 8b | Field validity | Prohibited characters in values (§8.2.1) | **NOT IMPLEMENTED** | **IMPORTANT** | `Http2Connection.cs:2573-2610` |
| 8c | Field validity | Malformed = stream error (§8.1.1) | over-strict | MINOR | `Http2Connection.cs:1071-1084` |
| 8d | Field validity | Applied uniformly across blocks | partial | MINOR | `Http2Connection.cs:1228`, `1303` |
| 9 | Fuzzing | "hpack" target reach | inadequate | MINOR | `tools/TlsClient.Fuzz/Program.cs:92-94`, `246`, `273-288` |

**Totals: 1 CRITICAL, 3 IMPORTANT, 9 MINOR.**

The brief's premise is confirmed. The encoder is in good shape and the parts of the
decoder that were designed against the RFC text — Huffman error handling, table
accounting, size-update position, header-list bounds — are genuinely correct. The
failures cluster in exactly the two places nobody re-derived from the spec: one line of
integer arithmetic whose `checked` keyword does not do what it appears to, and the
receive-side field validation that was written on the send path and never mirrored.
