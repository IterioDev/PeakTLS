# RFC conformance audit — HTTP semantics (RFC 9110) and HTTP/1.1 message syntax (RFC 9112)

Date: 2026-08-16
Scope: RFC 9110, RFC 9112, and RFC 9113 section 8 where HTTP/2 maps onto them.
Files read: `src/TlsClient/Http11RequestWriter.cs`, `Http11ResponseReader.cs`,
`Http11Connection.cs`, `BufferedHttpReader.cs`, `ResponseDecompressor.cs`, `TlsHeaders.cs`,
`ProxyTunnel.cs`, `TlsSession.cs`, plus `BufferedRequest.cs`, `StreamingResponseBody.cs`,
`SharpTlsTransport.cs`, `HpackCodec.cs`, `TlsSessionOptions.cs`, `TlsConnectionPool.cs`, and
`Http2Connection.cs` (header-build region only) as corroborating evidence.

RFC text quoted below was fetched from `rfc-editor.org` during this audit
(`rfc9110.txt`, `rfc9112.txt`, `rfc9113.txt`); nothing is quoted from memory.

Documented-divergence check: `docs/superpowers/HANDOFF.md` was searched for accepted
divergences covering this area. It documents four HTTP/2 items (empty-valued cookie/HPACK
handling, END_STREAM placement, `FixedIncrement` flow control, the GOAWAY Last-Stream-ID
history) and four open findings, none of which cover any HTTP/1.1 finding below.
`docs/PROTOCOL-REVIEW.md` line 63 claims "HTTP CONNECT bounds and validates the response and
never forwards proxy credentials" — true of `ProxyTunnel`, and not a waiver for §1/§5 below.

---

## 1. RFC 9112 section 3 — request-line and request-target forms

### 1.1 origin-form — CONFORMS

`Http11RequestWriter.SerializeHeaders` builds the request-line at
`src/TlsClient/Http11RequestWriter.cs:24-33`:

```
var target = request.Url.GetComponents(UriComponents.PathAndQuery, UriFormat.UriEscaped);
if (target.Length == 0) { target = "/"; }
builder.Append(request.Method).Append(' ').Append(target).Append(" HTTP/1.1\r\n");
```

RFC 9112 section 3.2.1: the origin-form is `absolute-path [ "?" query ]`, and a client
"MUST send a '/' as the path" when the target URI's path is empty. `UriFormat.UriEscaped`
supplies the percent-encoded form, and the `Length == 0` guard supplies the `/`. The
`Host` field is seeded at `Http11RequestWriter.cs:72-89` with the default port elided
(`FormatAuthority`, `Http11RequestWriter.cs:172-176`), which is what section 3.2 requires
alongside origin-form. Correct.

### 1.2 authority-form via a configured HTTP proxy — CONFORMS

`ProxyTunnel.EstablishHttpAsync` at `src/TlsClient/ProxyTunnel.cs:45-48`:

```
var authority = Http11RequestWriter.FormatAuthority(origin, includeDefaultPort: true);
... .Append("CONNECT ").Append(authority).Append(" HTTP/1.1\r\n")
    .Append("Host: ").Append(authority).Append("\r\n")
```

RFC 9112 section 3.2.3:

> The "authority-form" of request-target is only used for CONNECT requests (Section 9.3.6
> of [HTTP]). It consists of only the uri-host and port number of the tunnel destination,
> separated by a colon (":").
>
>     authority-form = uri-host ":" port
>
> When making a CONNECT request to establish a tunnel through one or more proxies, a client
> MUST send only the host and port of the tunnel destination as the request-target. The
> client obtains the host and port from the target URI's authority component, except that it
> sends the scheme's default port if the target URI elides the port.

`includeDefaultPort: true` satisfies the "sends the scheme's default port" clause. This is
the portless-CONNECT bug found yesterday, and it is fixed on this path.

### 1.3 authority-form for a caller-issued CONNECT — VIOLATES — IMPORTANT

**Finding 1.3.** A `CONNECT` request submitted through the public API is written in
**origin-form**, not authority-form.

`src/TlsClient/Http11RequestWriter.cs:24-33` derives the request-target from
`UriComponents.PathAndQuery` unconditionally — there is no branch on `request.Method`. So
`session.SendAsync(new HttpRequestMessage(new HttpMethod("CONNECT"), "https://host/"))`
routed to HTTP/1.1 puts this on the wire:

```
CONNECT / HTTP/1.1
Host: host:443
```

This is not a hypothetical path. Three pieces of code prove `CONNECT` is a supported input
that reaches this writer:

- `Http11RequestWriter.ValidateMethod` (`Http11RequestWriter.cs:156-164`) accepts `CONNECT`;
  it rejects only the delimiter set.
- `Http11RequestWriter.MergeHeaders` (`Http11RequestWriter.cs:83-88`) **explicitly
  special-cases `CONNECT`** to seed the `Host` field with the default port — the exact
  authority-form string — and its own comment cites RFC 9112 section 3.2.3.
- `tests/TlsClient.Tests/Http11RequestWriterTests.cs:103-119` asserts that seeding.

The CONNECT-aware `Host` logic exists for `Http2Connection.BuildRequestHeaders`, which reads
`:authority` out of that field (`Http2Connection.cs:780-782`). `MergeHeaders` is shared by
both writers, so the HTTP/1.1 writer inherits CONNECT-aware `Host` seeding while its
request-line stays origin-form. The two halves disagree.

Quotation: RFC 9112 section 3.2.3, as quoted in 1.2 above — "a client MUST send only the
host and port of the tunnel destination as the request-target."

**Fix.** In `SerializeHeaders`, branch on the method before line 24:

```csharp
var target = string.Equals(request.Method, "CONNECT", StringComparison.Ordinal) &&
        request.Protocol is null
    ? FormatAuthority(request.Url, includeDefaultPort: true)
    : request.Url.GetComponents(UriComponents.PathAndQuery, UriFormat.UriEscaped);
```

The `request.Protocol is null` guard mirrors `MergeHeaders:83-85` so an RFC 8441 extended
CONNECT (which has no HTTP/1.1 expression at all) is not silently mangled. Alternatively —
and more in keeping with the fact that HTTP/1.1 has no way to *use* a caller-issued tunnel —
reject `CONNECT` in `Http11Connection.SendAsync` with a clear exception. Either is acceptable;
silently emitting origin-form is not. See finding 5.3, which is the same request seen from
the response side and is the more severe half.

### 1.4 absolute-form — NOT IMPLEMENTED (correct, no finding)

RFC 9112 section 3.2.2 reserves absolute-form for requests to a proxy. It is unreachable and
unnecessary here: `BufferedRequest.CreateAsync` rejects any non-`https` URL
(`src/TlsClient/BufferedRequest.cs:140-143`), and every proxy type is tunneled before TLS
begins (`src/TlsClient/SharpTlsTransport.cs:131-167` calls `ProxyTunnel.EstablishAsync`,
never a forwarding proxy). A client that never speaks cleartext HTTP to a proxy never needs
absolute-form.

### 1.5 asterisk-form (`OPTIONS *`) — NOT IMPLEMENTED on HTTP/1.1 — MINOR

The verbatim-path escape hatch exists only for HTTP/2. `BufferedRequest.PathOverride` is
documented "Ignored on HTTP/1.1" (`src/TlsClient/BufferedRequest.cs:70-73`) and is honoured
only at `Http2Connection.cs:786`, whose comment states it is "the only way to express the
asterisk form". `Http11RequestWriter.SerializeHeaders:24-30` never consults it, so an
`OPTIONS` request configured for asterisk-form silently degrades to `OPTIONS / HTTP/1.1`
after a version fallback.

RFC 9112 section 3.2.4:

> The "asterisk-form" of request-target is only used for a server-wide OPTIONS request
> (Section 9.3.7 of [HTTP]).
>
>     asterisk-form  = "*"

`Http11Connection.cs:48-51` documents the general rule that "the pseudo-header, priority and
PRIORITY_UPDATE overrides have no HTTP/1.1 meaning and are ignored rather than rejected, so a
persona survives a version fallback." `PathOverride` is a `:path` override, so it is arguably
inside that documented divergence — hence MINOR rather than a plain violation. It is worth an
explicit sentence in that comment naming `PathOverride`, because the difference between
`OPTIONS *` and `OPTIONS /` is semantic, not cosmetic: they address different resources.

**Fix.** Either honour `PathOverride` in `SerializeHeaders` (it is already validated by
`TlsHttp2PseudoHeaderOptions.ValidatePathOverride`), or name `PathOverride` explicitly in the
`Http11Connection.cs:48-51` comment so the silent degradation is documented rather than
inferred.

---

## 2. RFC 9112 section 6 — message body framing

### 2.1 Request side: Content-Length versus Transfer-Encoding — CONFORMS

`Http11RequestWriter.MergeHeaders` at `src/TlsClient/Http11RequestWriter.cs:68-69` removes
any caller-supplied `Content-Length` and `Transfer-Encoding`, then lines 94-105 install
exactly one framing:

```
Remove(headers, "Content-Length");
Remove(headers, "Transfer-Encoding");
...
if (request.HasPayload) {
    if (!request.HasTrailers && request.ContentLength is { } contentLength) { ... Content-Length ... }
    else { headers.Add(new HeaderEntry("Transfer-Encoding", ["chunked"])); }
}
```

RFC 9112 section 6.2:

> A sender MUST NOT send a Content-Length header field in any message that contains a
> Transfer-Encoding header field.

The removal-then-single-install shape makes both-present structurally impossible on the
request, whatever the caller sets. This is the right design and closes the request-smuggling
direction that matters most for a client. The body writer agrees with the declared framing:
`Http11Connection.WriteRequestBodyAsync:146-182` and
`WriteStreamingRequestBodyAsync:184-252` chunk exactly when `ContentLength is null ||
HasTrailers`, the same condition that chose `Transfer-Encoding: chunked`, and
`Http11Connection.cs:234-239` rejects a streaming body whose actual length disagrees with the
declared `Content-Length`.

### 2.2 Response side: both Content-Length and Transfer-Encoding present — IMPORTANT

**Finding 2.2.** When a response carries both fields, the client silently prefers
`Transfer-Encoding`, does not treat the message as an error, and — the part that matters —
**leaves the connection marked reusable**.

`Http11ResponseReader.ReadCoreAsync` at `src/TlsClient/Http11ResponseReader.cs:161-181`
(buffered) and `108-140` (streaming):

```
var transferEncodings = GetTokens(headers, "Transfer-Encoding");
if (transferEncodings.Count != 0) { ... ReadChunkedAsync ... }
else if (TryGetContentLength(headers, out var contentLength)) { ... }
```

`Content-Length` is never consulted once `Transfer-Encoding` is present, so the override
half is correct. `reusable` was computed at `Http11ResponseReader.cs:100` from
`IsPersistent(version, headers)` and is not reduced on this path; `TlsConnectionPool.cs:405`
and `:482` return the connection to the pool on `IsReusable`.

RFC 9112 section 6.1, item 3:

> If a message is received with both a Transfer-Encoding and a Content-Length header field,
> the Transfer-Encoding overrides the Content-Length. Such a message might indicate an
> attempt to perform request smuggling (Section 11.2) or response splitting (Section 11.1)
> and ought to be handled as an error.

and, from the same section:

> The message sender might have retained a portion of the message, in buffer, that could be
> misinterpreted by further use of the connection.

The MUST-strength override behaviour conforms. The "ought to be handled as an error" and the
buffer-retention warning do not: reusing a connection whose framing two upstream hops may
have read differently is precisely how a client becomes the downstream half of a smuggling
chain.

**Fix.** In both branches, detect the overlap and refuse to reuse:

```csharp
if (transferEncodings.Count != 0)
{
    if (headers.Contains("Content-Length")) { reusable = false; }   // RFC 9112 §6.1 item 3
    ...
}
```

Marking non-reusable is the minimum. Throwing `TlsHttpProtocolException` is defensible and
matches "ought to be handled as an error"; if fingerprint fidelity argues against throwing,
the non-reuse alone removes the exploitable half and should carry a comment saying so.

### 2.3 Multiple / malformed Content-Length values — CONFORMS

`Http11ResponseReader.TryGetContentLength` at `src/TlsClient/Http11ResponseReader.cs:475-500`
flattens every field line and every comma-separated member, requires every member to parse
under `NumberStyles.None` (no sign, no whitespace, no thousands separators), rejects negative
values and values above `int.MaxValue`, requires all members to be equal, and rejects an
empty field:

```
if (!long.TryParse(item.Trim(), NumberStyles.None, ...) || current < 0 ||
    current > int.MaxValue || parsed.HasValue && parsed.Value != current)
{ throw new TlsHttpProtocolException("Conflicting or invalid Content-Length headers were received."); }
```

RFC 9112 section 6.3 item 5 requires a recipient that receives multiple `Content-Length`
fields, or a field with an invalid value, to treat the message as unrecoverable. Both are
handled. The `.Trim()` before parsing correctly strips the OWS that RFC 9110 section 5.6.1
permits around list members while `NumberStyles.None` still rejects internal whitespace and
signs. This is one of the strongest parsers in the file.

---

## 3. RFC 9112 section 7 — chunked transfer coding

The relevant code is `ReadChunkedAsync` (`src/TlsClient/Http11ResponseReader.cs:306-345`) and
its streaming twin `CopyChunkedAsync` (`:347-403`). They are line-for-line equivalent in
their parsing, so findings apply to both.

### 3.1 chunk-size overflow and unbounded allocation — CONFORMS

`src/TlsClient/Http11ResponseReader.cs:321-325`:

```
if (!ulong.TryParse(sizeText, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var size) ||
    size > (ulong)(maximumBodyBytes - body.Length))
{ throw new TlsHttpProtocolException("A chunk size is invalid or exceeds the body limit."); }
```

- **Overflow**: `ulong.TryParse` returns `false` on a value exceeding 64 bits, so a
  `ffffffffffffffffff` chunk size is rejected rather than wrapping.
- **Sign**: `NumberStyles.HexNumber` does not include `AllowLeadingSign`, so `-1` is rejected.
- **Empty**: `TryParse("")` is `false`, so a bare CRLF where a chunk size belongs is rejected.
- **Allocation**: the cumulative bound `size > (ulong)(maximumBodyBytes - body.Length)` runs
  *before* `new byte[(int)size]` at line 336, and `maximumBodyBytes` is an `int` capped at
  `int.MaxValue` (`TlsSessionOptions.cs:218-221`), so the cast at 336 cannot truncate and the
  total body cannot exceed the configured limit. Default 64 MiB (`TlsSessionOptions.cs:70`).
- **Hang**: every read is `BufferedHttpReader.ReadLineAsync` / `ReadExactlyAsync` under the
  caller's `CancellationToken`, which `TlsSession.SendAsync:101-105` links to the session
  timeout. A stalled peer produces a `TimeoutException`, not a hang.

RFC 9112 section 7.1:

>     chunk          = chunk-size [ chunk-ext ] CRLF
>                      chunk-data CRLF
>     chunk-size     = 1*HEXDIG

### 3.2 Whitespace tolerated around chunk-size — MINOR

`src/TlsClient/Http11ResponseReader.cs:320` and `:363` apply `.Trim()`, and
`NumberStyles.HexNumber` additionally sets `AllowLeadingWhite | AllowTrailingWhite`. So
`"\t1a "` parses as chunk size `0x1a`. The grammar quoted above is `1*HEXDIG` with no OWS
production. Lenient chunk-size parsing is the classic differential that makes two hops
disagree on message boundaries.

For a client parsing responses this is low-risk — there is no downstream to forward to — hence
MINOR rather than IMPORTANT. **Fix:** drop the `.Trim()` and use
`NumberStyles.AllowHexSpecifier` instead of `NumberStyles.HexNumber`, which removes both
whitespace allowances.

### 3.3 chunk extensions — CONFORMS

`src/TlsClient/Http11ResponseReader.cs:319` / `:362` take everything before the first `;` as
the size. RFC 9112 section 7.1.1 allows a `chunk-ext-val` to be a `quoted-string` that may
itself contain `;`, but since the size always precedes the *first* `;`, no quoted-string
content can affect framing. Extensions are otherwise ignored, which section 7.1.1 permits
("A recipient MUST ignore unrecognized chunk extensions").

### 3.4 Chunk-data CRLF — CONFORMS

`src/TlsClient/Http11ResponseReader.cs:339-343` and `:397-401` read a line with a 2-byte
budget and require it to be empty, so `chunk-data CRLF` is enforced exactly; anything else
throws `"Chunk data was not followed by CRLF."`

### 3.5 Trailer section — CONFORMS

`src/TlsClient/Http11ResponseReader.cs:328-333` and `:376-381` parse the trailer section with
the same `ReadHeadersAsync` used for the header section, so it inherits the byte cap, the
field-count cap, the obs-fold rejection and the control-character rejection
(`Http11ResponseReader.cs:259-303`). Crucially, trailers are returned in a **separate**
`TlsHeaders` and are never merged into the header section: `ParsedHttpResponse` keeps
`Headers` and `Trailers` distinct (`Http11ResponseReader.cs:526-534`) and `TlsSession` passes
them into distinct `TlsResponse` slots (`TlsSession.cs:300-301`, `:412-413`).

RFC 9110 section 6.5.2:

> Unless the recipient understands the corresponding field's definition, a recipient MUST NOT
> merge a trailer field into the header section.

Not merging is the safe answer and closes the trailer-injection variant of response
splitting. No finding.

### 3.6 Negative header budget throws the wrong exception type — MINOR

`Http11ResponseReader.cs:75-79` passes `maximumHeaderBytes - statusLine.WireLength` as the
header budget. `ReadLineAsync` caps a line at `maximumBytes` bytes of content
(`BufferedHttpReader.cs:53-56`) but reports `WireLength = line.Length + 2`
(`BufferedHttpReader.cs:41`), so a maximal status line yields a budget of `-2`. That reaches
`BufferedHttpReader.cs:21`:

```
using var line = new MemoryStream(Math.Min(maximumBytes, 256));
```

`new MemoryStream(-2)` throws `ArgumentOutOfRangeException`, an unhandled non-protocol
exception driven purely by attacker-chosen input length. Not a hang and not a memory issue —
but it escapes the `TlsHttpProtocolException` contract that `ShouldRetryException`
(`TlsSession.cs:576-583`) uses to decide retryability, so a malformed peer response is
classified differently from every other malformed peer response.

**Fix.** `Math.Clamp(maximumBytes, 0, 256)` at `BufferedHttpReader.cs:21`, or clamp the
subtraction at `Http11ResponseReader.cs:77` to zero.

---

## 4. RFC 9110 section 5 — field syntax

### 4.1 Field name validity — CONFORMS

`TlsHeaders.ValidateName` at `src/TlsClient/TlsHeaders.cs:204-212` requires every character
in `0x21`–`0x7E` and excludes the delimiter set `()<>@,;:\"/[]?={} \t\r\n`
(`TlsHeaders.cs:12-13`). That is exactly RFC 9110 section 5.1's `token` / `tchar` production.
`Http11RequestWriter.ValidateHeaderName` (`Http11RequestWriter.cs:212-216`) routes through it
for every emitted field name (`Http11RequestWriter.cs:36`) and every emitted trailer name
(`:145`).

Minor implementation note, not an RFC finding: `ValidateHeaderName` allocates a whole
`TlsHeaders` per call just to reuse the private validator, once per header per request. A
`internal static void TlsHeaders.ValidateHeaderName(string)` would be the same check without
the allocation.

### 4.2 CR / LF / NUL injection through caller-supplied values — CONFORMS, with a weak
boundary — MINOR

RFC 9110 section 5.5:

> Field values containing CR, LF, or NUL characters are invalid and dangerous, due to the
> varying ways that implementations might parse and interpret those characters; a recipient
> of CR, LF, or NUL within a field value MUST either reject the message or replace each of
> those characters with SP before further processing or forwarding of that message.

The wire is safe on both versions:

- HTTP/1.1: `Http11RequestWriter.ValidateHeaderValue`
  (`src/TlsClient/Http11RequestWriter.cs:218-227`) rejects any character `> 0x00FF`, any
  character `< 0x0020` other than HTAB, and `0x007F`. CR, LF and NUL are all in that set. It
  runs on every value written (`:39`) and every trailer value (`:148`).
- HTTP/2: `HpackCodec.ValidateHeader` (`src/TlsClient/HpackCodec.cs:333-344`) rejects `'\0'`,
  `'\r'`, `'\n'` in values, and `HpackCodec.cs:135` calls it on every header encoded.
  Request trailers additionally reuse the HTTP/1.1 validator (`Http2Connection.cs:604`).

**Finding 4.2 (MINOR, defence in depth).** The *boundary* check is weaker than either
serializer. `TlsHeaders.ValidateValue` (`src/TlsClient/TlsHeaders.cs:214-222`) rejects only
CR and LF:

```csharp
if (value.Contains('\r', StringComparison.Ordinal) || value.Contains('\n', StringComparison.Ordinal))
{ throw new ArgumentException("HTTP header values cannot contain CR or LF.", nameof(value)); }
```

So `session.DefaultHeaders.Set("X-Trace", "a\0b")` is accepted at the API boundary and only
rejected later, at serialization. `TlsHeaders` is public API; a value that survives the
setter reads as accepted. The section-5.5 sentence names NUL alongside CR and LF, and the
serializer-side guards are one refactor away from being the only ones.

**Fix.** Add `'\0'` to `TlsHeaders.ValidateValue:217-218` and update the message. One-line
change; no behaviour change for any value that currently reaches the wire.

### 4.3 Leading/trailing whitespace in caller-supplied values — VIOLATES — MINOR

`Http11RequestWriter.ValidateHeaderValue` (`Http11RequestWriter.cs:220-221`) explicitly
permits HTAB and, by only rejecting `< 0x0020`, permits SP anywhere including the ends. Then
`Http11RequestWriter.cs:40` writes the value verbatim:

```
builder.Append(header.Name).Append(": ").Append(value).Append("\r\n");
```

So `Set("X-Foo", " bar ")` reaches the wire as `X-Foo:  bar \r\n`.

RFC 9110 section 5.5:

> A field value does not include leading or trailing whitespace. When a specific version of
> HTTP allows such whitespace to appear in a message, a field parsing implementation MUST
> exclude such whitespace prior to evaluating the field value.

Harmless to most servers, but it is also a fingerprint divergence: no mainstream client emits
padded field values, so a padded value is a distinguisher on a client whose stated purpose is
byte-for-byte reproduction.

**Fix.** Trim SP/HTAB from both ends in `ValidateHeaderValue`'s caller, or reject a value with
leading/trailing whitespace outright at `TlsHeaders.ValidateValue`. Rejecting is preferable
for a library — silent trimming changes a caller's value without telling them.

### 4.4 obs-fold — CONFORMS

`Http11ResponseReader.ReadHeadersAsync` at `src/TlsClient/Http11ResponseReader.cs:277-280`:

```
if (line.Text[0] is ' ' or '\t')
{ throw new TlsHttpProtocolException("Obsolete folded HTTP headers are rejected."); }
```

RFC 9112 section 5.2:

> A user agent that receives an obs-fold in a response message that is not within a message/
> http container MUST replace each received obs-fold with one or more SP octets prior to
> interpreting the field value.

Rejecting is stricter than the SP-replacement the RFC names. Section 5.2 also states that
obs-fold "is deprecated" and that a sender "MUST NOT generate a message that includes
line folding"; a client that refuses to interpret one cannot be split by it. The stricter
choice is deliberate-looking and safe. The request direction cannot emit obs-fold at all,
since CR and LF are rejected in values (4.2). No finding.

Adjacent, also conformant: bare-LF line endings are rejected (`BufferedHttpReader.cs:49-52`),
response field values are re-checked for control characters after trimming
(`Http11ResponseReader.cs:289-293`), the reason phrase is checked
(`Http11ResponseReader.cs:243-246`), and a field line with `:` at position 0 or absent is
rejected (`Http11ResponseReader.cs:282-286`).

### 4.5 HTTP/2 field-name validation is narrower than RFC 9113 section 8.2.1 — MINOR

`HpackCodec.ValidateHeader` (`src/TlsClient/HpackCodec.cs:333-338`) rejects an empty name,
uppercase `A`–`Z`, NUL, CR and LF — but not the rest of `0x00`–`0x20`, not `0x7f`–`0xff`, and
not a stray `:` inside a non-pseudo name.

RFC 9113 section 8.2.1:

> A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a, or 0x7f-0xff
> (all ranges inclusive). ... With the exception of pseudo-header fields ..., field names
> MUST NOT include a colon (ASCII COLON, 0x3a).

Not currently reachable: every name arriving at `BuildRequestHeaders` has already passed
either `TlsHeaders.ValidateName` (4.1) or `System.Net.Http.HttpHeaders`' own token check, and
both enforce `token`. Listed for completeness as defence in depth, since the HPACK validator
is the last line before the wire.

---

## 5. RFC 9110 sections 9 and 15 — responses without content

### 5.1 HEAD, 1xx, 204, 304 — CONFORMS

`Http11ResponseReader.ReadCoreAsync` at `src/TlsClient/Http11ResponseReader.cs:96-97`:

```
var noBody = string.Equals(requestMethod, "HEAD", StringComparison.Ordinal) ||
    statusCode is >= 100 and < 200 or 204 or 304;
```

RFC 9110 section 6.4.1:

> Responses to the HEAD request method (Section 9.3.2) never include content ...
> All 1xx (Informational), 204 (No Content), and 304 (Not Modified) responses do not include
> content.

`noBody` short-circuits before any framing header is consulted (`:155-158` buffered, `:107`
streaming), so a `204` carrying a bogus `Content-Length: 100` does not cause a read. Correct
on both the buffered and streaming paths.

Interim responses are handled separately and correctly: `Http11ResponseReader.cs:69` bounds
the loop at 9 iterations, `:81-88` consumes and discards any 1xx other than 101 (releasing the
`Expect: 100-continue` gate on a 100), `:89-92` rejects 101, and `:211` throws if the peer
never sends a final status. No hang, no unbounded interim loop.

### 5.2 Proxy CONNECT response — CONFORMS

`ProxyTunnel.EstablishHttpAsync` (`src/TlsClient/ProxyTunnel.cs:62-88`) reads the status line
and then loops field lines until the empty line, and **never attempts to read a body**. It
also never consults `Content-Length` or `Transfer-Encoding`, which is exactly what RFC 9112
section 6.3 item 2 demands:

> Any 2xx (Successful) response to a CONNECT request implies that the connection will become
> a tunnel immediately after the empty line that concludes the header fields. A client MUST
> ignore any Content-Length or Transfer-Encoding header fields received in such a message.

The header block is bounded (`ProxyTunnel.cs:73-77`) and a non-200 is turned into an
`HttpRequestException` after the block is drained (`:83-87`), so the failure path does not
hang either.

### 5.3 Caller-issued CONNECT: 2xx response is read as if it had content — CRITICAL (hang)

**Finding 5.3.** `noBody` at `src/TlsClient/Http11ResponseReader.cs:96-97` does not include
the successful-CONNECT case. A `CONNECT` issued through `TlsSession.SendAsync` (reachable —
see the three proofs in finding 1.3) that receives the canonical

```
HTTP/1.1 200 Connection Established
```

with no `Content-Length` and no `Transfer-Encoding` falls through both framing branches to the
read-until-close fallback — `ReadUntilCloseAsync` at `Http11ResponseReader.cs:193-194`
(buffered) or `CopyUntilCloseAsync` at `:143-147` (streaming). Both loop on
`reader.ReadAsync` until it returns `0`. After a successful CONNECT the peer will never close;
it is waiting for tunnel traffic. **The client blocks until the session timeout fires**
(`TlsSession.cs:101-105`), which is the whole request budget, and only then surfaces a
`TimeoutException`. On an unbounded `Timeout` it blocks indefinitely.

RFC 9110 section 6.4.1:

> 2xx (Successful) responses to a CONNECT request method (Section 9.3.6) switch the connection
> to tunnel mode instead of having content.

RFC 9110 section 9.3.6:

> Any 2xx (Successful) response indicates that the sender (and all inbound proxies) will
> switch to tunnel mode immediately after the response header section; data received after
> that header section is from the server identified by the request target.

This is the same request as finding 1.3 seen from the response side, and it is the worse half:
1.3 is a wrong byte sequence, 5.3 is a stall.

**Fix.** Extend the predicate at `Http11ResponseReader.cs:96-97`:

```csharp
var noBody = string.Equals(requestMethod, "HEAD", StringComparison.Ordinal) ||
    string.Equals(requestMethod, "CONNECT", StringComparison.Ordinal) && statusCode is >= 200 and < 300 ||
    statusCode is >= 100 and < 200 or 204 or 304;
```

and set `reusable = false` in that branch — the connection is now a tunnel, not a pooled HTTP
connection, and must not be handed to the next request. If instead the decision is to reject
caller-issued CONNECT outright (the option raised in 1.3), that closes 5.3 as well and is the
smaller change; do one or the other, not neither.

### 5.4 ProxyTunnel discards buffered post-header octets — IMPORTANT

**Finding 5.4.** `ProxyTunnel.cs:62` wraps the raw socket in a `BufferedHttpReader`, which
reads ahead into an 8192-byte internal buffer (`BufferedHttpReader.cs:8`, `:96-109`). At
`ProxyTunnel.cs:88` the method returns and that reader — with whatever it read past the blank
line still sitting in `_buffer` — is dropped. `SharpTlsTransport.cs:142-155` then begins the
TLS handshake directly on `networkStream`, which no longer contains those octets.

RFC 9110 section 9.3.6, quoted in 5.3: "data received after that header section is from the
server identified by the request target." Those bytes are tunnel payload; silently discarding
them is a data-loss defect.

Today this fails closed rather than open — for an `https` origin the discarded bytes could
only be unsolicited proxy output, and losing them makes the subsequent TLS handshake fail
rather than succeed with corrupted state. That is why this is IMPORTANT and not CRITICAL. It
is still a latent trap for any future non-TLS tunnel use, and the discard is invisible.

**Fix.** Have `ProxyTunnel.EstablishAsync` return the reader's unconsumed remainder (or accept
and return the `BufferedHttpReader`), and have `SharpTlsTransport` either prepend it to the
stream handed to TLS or fail loudly if it is non-empty. Failing loudly is the smaller change
and is correct for an HTTPS-only client:

```csharp
// A conforming proxy sends nothing between the blank line and our ClientHello.
if (reader.HasBufferedBytes) { throw new HttpRequestException("The proxy sent unsolicited data after the CONNECT response."); }
```

### 5.5 ProxyTunnel does not skip a 1xx before the CONNECT response — MINOR

`ProxyTunnel.cs:66` parses the first status line as final. A proxy that emits an interim `1xx`
before `200 Connection Established` is reported as a rejection
(`ProxyTunnel.cs:83-87`). RFC 9110 section 15.2 requires a client to be able to parse one or
more 1xx responses before the final response. Rare in practice for CONNECT; low severity.
**Fix:** loop past `1xx` status lines and their header blocks, as
`Http11ResponseReader.cs:69-88` already does.

---

## 6. RFC 9110 section 15.4 — redirect handling

### 6.1 Status codes and method/body preservation — CONFORMS

`TlsSession.TryCreateRedirect` at `src/TlsClient/TlsSession.cs:696-704` follows exactly
301, 302, 303, 307, 308. 300 (which requires a user choice) and 305/306 (deprecated) are not
followed — correct.

The method decision is at `src/TlsClient/TlsSession.cs:717-720`:

```
var switchToGet = response.StatusCode == HttpStatusCode.SeeOther && request.Method != "HEAD" ||
    response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Found &&
    request.Method == "POST";
var method = switchToGet ? "GET" : request.Method;
```

Against RFC 9110:

- **307 / 308** — never rewritten, body preserved. Section 15.4.8: "the user agent MUST NOT
  change the request method if it performs an automatic redirection to that URI." Section
  15.4.9 carries the same constraint for 308. **CONFORMS.**
- **303** — rewritten to GET except for HEAD, which is preserved. Section 15.4.4 defines 303
  as "a redirection that changed its method to GET"; preserving HEAD is the standard
  refinement (a HEAD need not become a GET to satisfy the semantics). **CONFORMS.**
- **301 / 302** — rewritten to GET only for POST. Section 15.4:
  "status codes 301 and 302 have been adjusted to allow a POST request to be redirected as
  GET." A PUT or DELETE keeps its method and body, which is correct: the adjustment is
  scoped to POST. **CONFORMS.**

Body and content headers are dropped exactly when the method changes —
`BufferedRequest.Redirect` at `src/TlsClient/BufferedRequest.cs:109` filters `Content-*` when
`dropBody`, and `:118-121` clears `Body`, `HasContent`, `StreamingContent` and `Trailers`.
`:98-103` refuses rather than silently truncating when a method-preserving redirect would
require replaying an unbuffered streaming body. Both correct.

### 6.2 Authorization and cookies on a cross-origin redirect — CONFORMS

Two layers, both required, both present:

1. **Per-request headers.** `BufferedRequest.Redirect` at
   `src/TlsClient/BufferedRequest.cs:104-108` drops `Authorization`, `Cookie` and `Host` when
   `originChanged`.
2. **Session-wide headers.** `:122` sets `SuppressSensitiveSessionHeaders`, which
   `Http11RequestWriter.MergeHeaders:58-62` honours by filtering
   `IsOriginBoundHeader` — `Authorization`, `Cookie`, `Host`
   (`Http11RequestWriter.cs:207-210`). This is the layer that is easy to miss: without it, a
   credential set once on `session.DefaultHeaders` would follow every redirect forever.

Origin comparison is scheme + IdnHost + port (`TlsSession.cs:726-729`) — the full origin
triple, not just the host. `Proxy-Authorization` is stripped unconditionally on every request
(`Http11RequestWriter.cs:70`) and on the HTTP/2 path (`Http2Connection.cs:833-834`), so proxy
credentials never leak to an origin at all. Cookies for the new hop are re-derived from the
`CookieContainer`, which scopes by URL (`TlsSession.cs:668-688`).

RFC 9110 section 15.4 lists, among the modifications a user agent makes when automatically
following a redirect, removing header fields specific to the original target, and section
11.6.2 warns against forwarding credentials across origins. The implementation matches. No
finding.

**Note, not a finding.** Only `Authorization`, `Cookie` and `Host` are stripped. A
caller-supplied bearer credential in a bespoke field (`X-Api-Key`, `Api-Key`) survives a
cross-origin redirect. The RFC does not enumerate such fields and mainstream user agents
behave identically, so this is defensible — but it is worth an XML doc sentence on
`FollowRedirects` so callers know the boundary of the guarantee.

### 6.3 Redirect limit — CONFORMS

`TlsSession.cs:278-282` (buffered) and `:394-398` (streaming) throw once
`redirects.Count >= MaximumRedirects`. Default 10, validated to `[0, 100]`
(`TlsSessionOptions.cs:67`, `:214-217`). RFC 9110 section 15.4: "A client SHOULD detect and
intervene in cyclical redirections." A hop cap terminates every cycle. The traversed hops are
also surfaced on `TlsResponse.Redirects` (`TlsSession.cs:306`), which is good for diagnosis.

### 6.4 Duplicate `Location` fields resolve silently to the first — MINOR

`TlsSession.cs:706` uses `headers.GetFirstOrDefault("Location")`, and `TlsHeaders`
accumulates repeated field lines into a value array (`TlsHeaders.cs:74-93`). A response with
two `Location` fields therefore follows the first without complaint.

RFC 9110 section 5.5 defines the category:

> Fields that only anticipate a single member as the field value are referred to as
> "singleton fields".

`Location` is such a field (section 10.2.2). The RFC does not state a MUST-level recipient
rule for duplicate singletons, so this is advisory rather than a violation — but section 8.3
warns of exactly this shape for `Content-Type`: "Recipients often attempt to handle this error
by using the last syntactically valid member of the list, leading to potential
interoperability and security issues if different implementations have different error
handling behaviors." Two `Location` fields from a partially-controlled upstream is an open
redirect waiting for a disagreement between hops.

**Fix.** In `TryCreateRedirect`, treat a `Location` with more than one value as
non-redirectable (return `false`) or throw. Three lines via `TryGetValues`.

---

## 7. RFC 9110 section 10.1.1 — Expect: 100-continue

### 7.1 Detection and timeout behaviour — CONFORMS

`Http11RequestWriter.Has100Continue` (`src/TlsClient/Http11RequestWriter.cs:122-133`)
correctly splits the `Expect` field on commas and compares case-insensitively after trimming,
so `Expect: 100-Continue` and `Expect: foo, 100-continue` are both detected.

`Http11Connection.SendAsync:76-103` flushes the header block, starts the response read, and
gates the body on `ShouldSendExpectedBodyAsync` (`Http11Connection.cs:270-301`), which races
four tasks: the 100 gate, the final-response gate, the response task, and a
`Task.Delay(expectTimeout)`. Default timeout 1 second (`TlsSessionOptions.cs:61`), validated
to at most 1 minute (`:209-212`).

**Server never sends the interim response** → the delay wins → `Http11Connection.cs:299-300`
returns `true` and the body is written. RFC 9110 section 10.1.1, requirements for clients:

> A client that sends a 100-continue expectation is not required to wait for any specific
> length of time; such a client MAY proceed to send the content even if it has not yet
> received a response. Furthermore, since 100 (Continue) responses cannot be sent through an
> HTTP/1.0 intermediary, such a client SHOULD NOT wait for an indefinite period before
> sending the content.

A bounded 1-second wait followed by sending anyway satisfies both sentences. **No hang.**
`expectTimeout == TimeSpan.Zero` short-circuits to "send immediately"
(`Http11Connection.cs:276-279`), which is also within the MAY.

### 7.2 Connection reused after a final response suppressed the body — CRITICAL (desync)

**Finding 7.2.** When the server answers a `100-continue` request with a **final** status
before the body is sent, the client correctly suppresses the body — and then returns the
connection to the pool as reusable, having declared a body length it never wrote.

The path, in order:

1. `Http11Connection.cs:69` writes the header block, which contains
   `Content-Length: N` (or `Transfer-Encoding: chunked`) — installed by
   `Http11RequestWriter.MergeHeaders:94-105`, since `expectContinue` is only true when
   `request.HasContent` (`Http11Connection.cs:72`).
2. The server replies with a final status (417, 413, 401, anything non-1xx).
   `Http11ResponseReader.cs:94` fires `expectContinue.FinalResponse`.
3. `ShouldSendExpectedBodyAsync` returns `false` at `Http11Connection.cs:290-293`.
4. `Http11Connection.cs:95-101` is skipped — **zero body octets are written.**
5. `Http11Connection.cs:129-131` runs unconditionally:
   `HasCompletedRequest = true; IsReusable = response.Reusable;`
   and `response.Reusable` came from `IsPersistent` (`Http11ResponseReader.cs:100`,
   `:502-511`), which returns `true` for any HTTP/1.1 response without `Connection: close`.
6. `TlsConnectionPool.cs:405` / `:482` return the connection to the pool on `IsReusable`.

The server is still waiting for `N` body octets on that connection. The next request written
on it is consumed as this request's body. That is a client-side request desync — the same
primitive as request smuggling, with the client supplying the confusion.

RFC 9112 section 9.5:

> A client sending a message body SHOULD monitor the network connection for an error response
> while it is transmitting the request. If the client sees a response that indicates the
> server does not wish to receive the message body and is closing the connection, the client
> SHOULD immediately cease transmitting the body and close its side of the connection.

The client does the first half — ceasing transmission — and omits the second. Note the code
already knows the situation is special: it has a dedicated `FinalResponse` gate whose entire
purpose is to detect it.

Partially mitigated in practice, because a server sending an early final status usually also
sends `Connection: close`, in which case `IsPersistent` returns `false` and the connection is
discarded. But that depends on the *server's* choice, not the client's, and 417 in particular
is frequently sent on a kept-alive connection.

**Fix.** Make the suppression decision reduce reusability. In `Http11Connection.SendAsync`,
capture the gate result and apply it at line 130:

```csharp
var bodySent = await ShouldSendExpectedBodyAsync(...);
if (bodySent) { await WriteRequestBodyAsync(...); await _transport.Stream.FlushAsync(...); }
response = await responseTask.ConfigureAwait(false);
...
// RFC 9112 §9.5: we declared a body and did not send it; the peer's parser is mid-message.
IsReusable = response.Reusable && bodySent;
```

Three lines. `bodySent` is already computed; it is simply discarded today.

### 7.3 Abandoned delay timer — MINOR

`Http11Connection.cs:280` creates `Task.Delay(expectTimeout, cancellationToken)` and, when
any other task wins the race at `:286-297`, never awaits or cancels it. The timer stays in the
runtime timer queue for the full `expectTimeout`. Not an RFC issue and bounded at 1 minute by
validation, but under high concurrency with `Expect: 100-continue` it is avoidable garbage.
**Fix:** a `using var delayCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken)`
and cancel it before returning.

---

## 8. RFC 9113 section 8.2.2 / 8.1 — connection-specific fields on HTTP/2

### 8.1 Stripping on the HTTP/2 path — CONFORMS

`Http2Connection.BuildRequestHeaders` at `src/TlsClient/Http2Connection.cs:832-837`:

```
var name = header.Name.ToLowerInvariant();
if (name is "connection" or "proxy-connection" or "keep-alive" or
    "upgrade" or "transfer-encoding" or "proxy-authorization")
{ continue; }
```

RFC 9113 section 8.2.2:

> An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header
> fields. This includes the Connection header field and those listed as having
> connection-specific semantics in Section 7.6.1 of [HTTP] (that is, Proxy-Connection,
> Keep-Alive, Transfer-Encoding, and Upgrade). Any message containing connection-specific
> header fields MUST be treated as malformed (Section 8.1.1).

The full enumerated list — `Connection`, `Proxy-Connection`, `Keep-Alive`,
`Transfer-Encoding`, `Upgrade` — is covered, plus `Proxy-Authorization` as a bonus. The strip
is load-bearing rather than defensive: `TlsSession.cs:44` seeds
`DefaultHeaders["Connection"] = "keep-alive"` for every session, and
`Http11RequestWriter.MergeHeaders:104` re-adds `Transfer-Encoding: chunked` for any
trailered or unknown-length payload. Both would otherwise reach HPACK. `ToLowerInvariant()`
is culture-invariant, so no Turkish-I hazard.

### 8.2 TE restricted to "trailers" — CONFORMS

`src/TlsClient/Http2Connection.cs:847-852`:

```
if (name == "te" && header.Values.Any(value =>
        !string.Equals(value.Trim(), "trailers", StringComparison.OrdinalIgnoreCase)))
{ throw new HttpRequestException("HTTP/2 permits TE only with the value 'trailers'."); }
```

RFC 9113 section 8.2.2:

> The only exception to this is the TE header field, which MAY be present in an HTTP/2
> request; when it is, it MUST NOT contain any value other than "trailers".

Rejecting rather than stripping is the stricter and correct reading of "MUST NOT contain any
value other than". Because the comparison is against the whole trimmed field-line value,
`TE: trailers, gzip` on one line is rejected as well as `TE: gzip` — which is right: RFC 9110
section 10.1.4's `t-codings` grammar gives `"trailers"` with no weight, so `trailers;q=0.5` is
also correctly rejected.

### 8.3 HTTP/1.1 path unaffected — CONFORMS

`Http11RequestWriter.SerializeHeaders:18-21` adds `Connection: keep-alive` when absent and
performs no stripping; the connection-specific filter lives only in
`Http2Connection.BuildRequestHeaders`. `MergeHeaders` — the routine both writers share —
contains no version-dependent stripping of these fields, so the HTTP/1.1 wire image is
untouched by the HTTP/2 rule. Confirmed by reading `Http11RequestWriter.cs:52-120` in full.

---

## 9. Decompression bounds

### 9.1 Buffered path — CONFORMS

`ResponseDecompressor.DecodeWithFactoryAsync` at
`src/TlsClient/ResponseDecompressor.cs:85-98` checks before every write:

```
var read = await decoder.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
if (read == 0) { return output.ToArray(); }
if (output.Length + read > maximumBytes)
{ throw new TlsHttpProtocolException("The decompressed response body exceeded the configured limit."); }
```

The bound is checked *before* the write, on every 8 KiB block, so peak output is at most
`maximumBytes + 8192`. `maximumBytes` is `MaximumResponseBodyBytes` — default 64 MiB, capped
at `int.MaxValue` (`TlsSessionOptions.cs:70`, `:218-221`) — threaded from
`TlsSession.cs:288-293`. A gzip/deflate/brotli bomb is stopped. **Not a memory-exhaustion
vector.**

### 9.2 Streaming path — CONFORMS

`StreamingResponseBody.cs:114-117` bounds the *encoded* octets and `:265-268` bounds the
*decoded* octets, both against the same `_maximumBytes` (`:12`, `:30`, `:99`). Both directions
are covered, which is the correct pair — bounding only the decoded side still lets an attacker
buffer an unbounded compressed stream.

### 9.3 Chained encodings — CONFORMS

`ResponseDecompressor.cs:29-36` walks `Content-Encoding` right-to-left, which is the correct
order (RFC 9110 section 8.4.1: the codings are "listed in the order in which they were
applied"), and passes the same `maximumBytes` into every layer. `decoded` is reassigned each
iteration, so peak live memory is roughly two layers, not N. The layer count is itself bounded
by the header-size cap. No unbounded amplification.

### 9.4 Unknown encodings pass through undecoded — no finding

`ResponseDecompressor.cs:23-26` returns the body untouched if any coding is not
`gzip`/`deflate`/`br`, reporting `WasDecompressed: false`. That is a documented convenience
boundary rather than an RFC rule; the caller can see both the body and the
`Content-Encoding` field and decide. Noted so a reader does not mistake it for a silent
failure.

---

## Summary

| # | Area | Rule | Verdict | Severity | Location |
|---|------|------|---------|----------|----------|
| 1.1 | RFC 9112 §3.2.1 | origin-form request-target | CONFORMS | — | `Http11RequestWriter.cs:24-33` |
| 1.2 | RFC 9112 §3.2.3 | authority-form for proxy CONNECT | CONFORMS | — | `ProxyTunnel.cs:45-48` |
| 1.3 | RFC 9112 §3.2.3 | authority-form for caller CONNECT | **VIOLATES** | **IMPORTANT** | `Http11RequestWriter.cs:24-33` |
| 1.4 | RFC 9112 §3.2.2 | absolute-form | NOT IMPLEMENTED | — (correct) | `BufferedRequest.cs:140-143` |
| 1.5 | RFC 9112 §3.2.4 | asterisk-form `OPTIONS *` | NOT IMPLEMENTED | MINOR | `Http11RequestWriter.cs:24-30` |
| 2.1 | RFC 9112 §6.2 | request: no CL with TE | CONFORMS | — | `Http11RequestWriter.cs:68-105` |
| 2.2 | RFC 9112 §6.1 item 3 | response: CL + TE both present | PARTIAL | **IMPORTANT** | `Http11ResponseReader.cs:100,161-181` |
| 2.3 | RFC 9112 §6.3 item 5 | multiple / invalid Content-Length | CONFORMS | — | `Http11ResponseReader.cs:475-500` |
| 3.1 | RFC 9112 §7.1 | chunk-size overflow / allocation / hang | CONFORMS | — | `Http11ResponseReader.cs:321-336` |
| 3.2 | RFC 9112 §7.1 | `chunk-size = 1*HEXDIG`, no OWS | VIOLATES | MINOR | `Http11ResponseReader.cs:320,363` |
| 3.3 | RFC 9112 §7.1.1 | chunk extensions | CONFORMS | — | `Http11ResponseReader.cs:319,362` |
| 3.4 | RFC 9112 §7.1 | chunk-data CRLF | CONFORMS | — | `Http11ResponseReader.cs:339-343` |
| 3.5 | RFC 9110 §6.5.2 | trailers not merged into headers | CONFORMS | — | `Http11ResponseReader.cs:328-333,526-534` |
| 3.6 | — | negative header budget throws wrong type | defect | MINOR | `BufferedHttpReader.cs:21` |
| 4.1 | RFC 9110 §5.1 | field-name token validity | CONFORMS | — | `TlsHeaders.cs:204-212` |
| 4.2 | RFC 9110 §5.5 | CR/LF/NUL injection | CONFORMS (weak boundary) | MINOR | `TlsHeaders.cs:214-222` |
| 4.3 | RFC 9110 §5.5 | no leading/trailing whitespace | **VIOLATES** | MINOR | `Http11RequestWriter.cs:220-221` |
| 4.4 | RFC 9112 §5.2 | obs-fold rejected | CONFORMS | — | `Http11ResponseReader.cs:277-280` |
| 4.5 | RFC 9113 §8.2.1 | HTTP/2 field-name ranges | PARTIAL | MINOR | `HpackCodec.cs:333-338` |
| 5.1 | RFC 9110 §6.4.1 | HEAD / 1xx / 204 / 304 no body | CONFORMS | — | `Http11ResponseReader.cs:96-97` |
| 5.2 | RFC 9112 §6.3 item 2 | proxy CONNECT response no body | CONFORMS | — | `ProxyTunnel.cs:62-88` |
| 5.3 | RFC 9110 §6.4.1, §9.3.6 | 2xx to caller CONNECT has no content | **VIOLATES** | **CRITICAL (hang)** | `Http11ResponseReader.cs:96-97,143,193` |
| 5.4 | RFC 9110 §9.3.6 | post-header octets are tunnel data | **VIOLATES** | **IMPORTANT** | `ProxyTunnel.cs:62,88` |
| 5.5 | RFC 9110 §15.2 | 1xx before CONNECT response | VIOLATES | MINOR | `ProxyTunnel.cs:66` |
| 6.1 | RFC 9110 §15.4.4/.8/.9 | 307/308 preserve, 303/301/302 rewrite | CONFORMS | — | `TlsSession.cs:696-720` |
| 6.2 | RFC 9110 §15.4, §11.6.2 | strip Authorization/Cookie cross-origin | CONFORMS | — | `BufferedRequest.cs:104-122`, `Http11RequestWriter.cs:58-62,207-210` |
| 6.3 | RFC 9110 §15.4 | redirect limit / cycle intervention | CONFORMS | — | `TlsSession.cs:278-282,394-398` |
| 6.4 | RFC 9110 §5.5, §8.3 | duplicate singleton `Location` | advisory | MINOR | `TlsSession.cs:706` |
| 7.1 | RFC 9110 §10.1.1 | 100-continue timeout, no indefinite wait | CONFORMS | — | `Http11Connection.cs:270-301` |
| 7.2 | RFC 9112 §9.5 | close after suppressing a declared body | **VIOLATES** | **CRITICAL (desync)** | `Http11Connection.cs:89-101,129-131` |
| 7.3 | — | abandoned delay timer | defect | MINOR | `Http11Connection.cs:280` |
| 8.1 | RFC 9113 §8.2.2 | strip connection-specific fields on h2 | CONFORMS | — | `Http2Connection.cs:832-837` |
| 8.2 | RFC 9113 §8.2.2 | TE only "trailers" | CONFORMS | — | `Http2Connection.cs:847-852` |
| 8.3 | RFC 9113 §8.2.2 | HTTP/1.1 path unaffected | CONFORMS | — | `Http11RequestWriter.cs:18-21` |
| 9.1 | — | buffered decompression bounded | CONFORMS | — | `ResponseDecompressor.cs:92-96` |
| 9.2 | — | streaming decompression bounded | CONFORMS | — | `StreamingResponseBody.cs:114-117,265-268` |
| 9.3 | RFC 9110 §8.4.1 | chained encodings order and bound | CONFORMS | — | `ResponseDecompressor.cs:29-36` |

**Counts:** 2 CRITICAL, 3 IMPORTANT, 8 MINOR, 24 rules conforming.

### Recommended order of work

1. **7.2** — three lines (`IsReusable = response.Reusable && bodySent`), removes a pooled
   connection desync, no wire-image change.
2. **5.3** — extend `noBody` for 2xx-to-CONNECT and set `reusable = false`; removes a hang.
3. **1.3** — emit authority-form for CONNECT (or reject CONNECT on HTTP/1.1); if CONNECT is
   rejected, 5.3 closes with it.
4. **2.2** — mark non-reusable when a response carries both `Content-Length` and
   `Transfer-Encoding`.
5. **5.4** — surface or reject `ProxyTunnel`'s unconsumed buffered octets.
6. The MINOR set: 3.2, 3.6, 4.2, 4.3, 6.4, 1.5, 5.5, 7.3, 4.5.

Findings 1.3, 5.3 and 5.4 all sit on the CONNECT path, and 7.2 sits on the
`Expect: 100-continue` path — both are HTTP/1.1-only code with no HTTP/2 counterpart, which
matches the brief's expectation that the older path would carry the residue. The chunked
parser, the `Content-Length` parser, the redirect logic and every decompression bound are
clean.
