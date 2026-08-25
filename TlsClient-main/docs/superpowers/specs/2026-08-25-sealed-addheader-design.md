# Sealed per-request header list

Date: 2026-08-25
Status: approved, not yet implemented

## Problem

A caller builds an `HttpRequestMessage` and adds fields with
`request.Headers.TryAddWithoutValidation(name, value)`. For content-related names —
`content-type`, `content-length`, `transfer-encoding`, and the rest of the `Content-*`
family — `HttpRequestHeaders` rejects the add. It does not throw; it returns `false`,
silently. The real values arrive later from `Content.Headers`, which `BufferedRequest`
appends after `request.Headers`, so every content field lands at the end of the block
regardless of where the caller wrote it.

Captured clients do not look like that. The captured Spotify iOS POST puts
`content-type` first and `content-length` mid-block. Reaching that shape today requires
naming every field a second time in `TlsSessionOptions.HeaderOrder` or
`TlsRequestOptions.HeaderOrder`, which is a second source of truth that can silently
disagree with the first.

Two further defects share the same root:

- `HttpRequestHeaders` reflows values on the way in. `accept-encoding: gzip, deflate, br`
  is stored as three values and emits three field lines; `user-agent` splits on spaces;
  `accept-language: en-US,en;q=0.9` gains a space inside the second value. This cannot be
  undone afterwards, because the separators differ per field.
- The pipeline injects fields the caller never asked for: `Host`, `Cookie`, `Trailer`,
  and whatever `Content.Headers` happens to hold — `StringContent` sets its own
  `Content-Type`.

## The rule

**A field reaches the wire if and only if `AddHeader` added it, in the order it was
added.** One exception, and it covers the value only, never the position:
`Content-Length` and `Transfer-Encoding` receive computed values, written into the slot
`AddHeader` named for them.

Nothing is synthesised. Nothing is appended. There is no session-level or request-level
order that competes, because both are deleted.

## API

`TlsHeaders` already provides exactly the required store: case-insensitive,
insertion-ordered, `Add(name, value)` appends a value while keeping the name's existing
position, `Snapshot()` returns `HeaderEntry[]`. No new collection type.

```csharp
// TlsRequestOptions
public TlsHeaders Headers { get; } = new();

/// <summary>Adds a header. This is the only way a field reaches the wire.</summary>
public void AddHeader(string name, string value) => Headers.Add(name, value);
```

The method takes no `HttpRequestMessage`. Once nothing round-trips through
`HttpRequestHeaders`, the request has no part in header composition, and an unused
parameter would only imply otherwise.

Name validation is `TlsHeaders`' own (`InvalidNameCharacters`), so a malformed name
throws at the call site rather than at send.

## Data flow

`BufferedRequest` builds its `HeaderEntry[]` from `options.Headers.Snapshot()` verbatim.
`request.Headers` and `request.Content.Headers` are never read — those are the only two
places that read them today, `BufferedRequest.cs:153` and `BufferedRequest.cs:307`, plus
the content merges at `:159` and `:209`. `request.Content` continues to supply body bytes
and the computed length.

`Http11RequestWriter.MergeHeaders` reduces to four steps:

1. Copy the entries.
2. Drop origin-bound fields (`Authorization`, `Cookie`) when
   `SuppressSensitiveSessionHeaders` is set — a cross-origin redirect must not carry
   credentials to a new host. This survives unchanged.
3. Strip `Proxy-Authorization`.
4. Substitute the framing value in place: overwrite the caller's placeholder at the
   `Content-Length` or `Transfer-Encoding` slot with the computed value.

HTTP/2 `:authority` and HTTP/3's `host` → `:authority` mapping are unchanged. Those are
pseudo-headers, governed by `PseudoHeaderOrder`, and are outside this contract.

Because no value passes through `HttpRequestHeaders`, reflow is gone.
`AddHeader("accept-encoding", "gzip, deflate, br")` emits one field line carrying those
exact bytes.

## Deletions

76 references across 24 files.

| Removed | Note |
| --- | --- |
| `TlsSessionOptions.HeaderOrder` | shipped API, breaking change (`!`) |
| `TlsRequestOptions.HeaderOrder` | unshipped |
| `TlsRequestOptions.HeaderNamesOf` | unshipped; loses its only consumer |
| `TlsSessionOptions.ValidateHeaderOrder` | |
| `TlsHttpBehaviorProfile.HeaderOrder` | and the required `headerOrder` profile-JSON field |
| `TlsPreset` header-order array | `TlsPreset.cs:52` |
| `Http11RequestWriter.Order` | no order array left to apply |
| `FramingAnchor` / `InsertFraming` | replaced by in-place value substitution |
| `Host` synthesis | `MergeHeaders` |
| `Cookie` injection | `MergeHeaders`; `cookieHeader` parameter threaded through 27 sites |
| `Trailer` emission | `MergeHeaders`, and the `emitTrailerHeader` flag with it |

No profile JSON documents exist on disk; profiles are declared in code. The schema change
affects externally authored documents only.

## Errors

- Body present, and the header list names neither `content-length` nor
  `transfer-encoding` → `InvalidOperationException` at build time. On HTTP/1.1 the
  alternative is a body the server cannot delimit, which is a hang, not a clean failure.
- `AddHeader` with a name that is not a valid token → `ArgumentException`, from
  `TlsHeaders`.

## Consequences accepted

- **Automatic cookies stop.** The container still records `Set-Cookie`; sending one means
  `AddHeader("cookie", ...)`.
- **Unnamed `Host` means no `Host` field.** RFC 9112 section 3.2 mandates it on
  HTTP/1.1, so most servers answer 400. On HTTP/2 and HTTP/3 it costs nothing, because
  `host` is dropped there anyway and `:authority` carries the value.
- **Presets and behavior profiles no longer carry a captured order.** Callers take the
  order from captures or from the samples and feed it to `AddHeader`.

## Known ceiling

Duplicate names collapse positionally. `AddHeader("a", ...)`, `AddHeader("b", ...)`,
`AddHeader("a", ...)` sends `a` with two values followed by `b`, not `a, b, a`, because
`TlsHeaders.Add` keeps a name's first position. No capture under study interleaves
duplicates. Upgrade path if one ever does: give the store a flat `List<HeaderEntry>` that
permits repeated names.

## Verification

`tests/TlsClient.Tests/InsertionOrderHeaderTests.cs` is rewritten as the proof of this
contract. Its existing `WireOrderAsync` helper stays.

1. GET — wire order equals the `AddHeader` sequence exactly.
2. POST with `content-type` first and `content-length` mid-block — wire matches, and the
   computed length lands at the named slot.
3. POST with a body and no framing name → throws.
4. A field set via `request.Headers.TryAddWithoutValidation`, and a `Content-Type` set by
   `StringContent`, never reach the wire.
5. `AddHeader("accept-encoding", "gzip, deflate, br")` emits one field line with those
   bytes — the reflow regression guard.
6. Cross-origin redirect still drops `authorization` and `cookie`.
