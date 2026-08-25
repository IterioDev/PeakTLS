# Sealed Per-Request Header List Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A field reaches the wire if and only if `request.AddHeader(name, value)` added it, in the order it was added.

**Architecture:** `TlsRequestOptions` gains a `TlsHeaders Headers` collection, mirroring the existing `Trailers` property exactly. A two-argument extension method `request.AddHeader(name, value)` reaches it through `TlsRequestOptions.For(request)`. `BufferedRequest` sources its `HeaderEntry[]` from that collection instead of `request.Headers.NonValidated` and `request.Content.Headers.NonValidated`. `Http11RequestWriter.MergeHeaders` stops synthesising `Host`, injecting `Cookie`, emitting `Trailer`, and adding `Connection: keep-alive`; `Order()` is deleted along with both `HeaderOrder` properties, the preset arrays, and the profile-document field.

**Tech Stack:** C# / .NET 9, xUnit, `dotnet build` and `dotnet test`. The public API surface is tracked in `src/TlsClient/PublicAPI.Shipped.txt` and `PublicAPI.Unshipped.txt`; the analyzer fails the build if these do not match the built surface.

**Spec:** `docs/superpowers/specs/2026-08-25-sealed-addheader-design.md`

---

## Background an engineer new to this codebase needs

`HttpRequestHeaders.TryAddWithoutValidation` returns `false` — it does not throw — for the
`Content-*` family. Those values arrive separately from `HttpContent.Headers`, which today is
appended after `request.Headers`, so content fields always land last no matter where the caller
wrote them. Separately, `HttpRequestHeaders` reflows values on the way in: `gzip, deflate, br`
becomes three stored values and emits three field lines. Both defects vanish once nothing
round-trips through .NET's header collections, which is what this plan does.

`TlsHeaders` (`src/TlsClient/TlsHeaders.cs`) is the existing insertion-ordered, case-insensitive
collection. `Add(name, value)` appends a value while keeping the name's first position.
`Snapshot()` returns `HeaderEntry[]`. `TlsRequestOptions.Trailers` already uses it exactly the
way this plan uses `Headers` — copy that pattern rather than inventing one.

`TlsRequestOptions.For(request)` gets-or-creates the options object stored in `request.Options`.
`TlsRequestOptions.Snapshot(request)` freezes it into the internal `TlsRequestConfiguration`
record that `BufferedRequest` consumes.

**Migration size, so nobody is surprised:** 74 `TryAddWithoutValidation` call sites (40 in
`tests/`, 34 in `samples/` and `tools/`) across 10 test files, plus 76 `HeaderOrder` references
in 24 files. Tasks 12 and 13 are large and mechanical.

**Transitional scaffolding:** Task 2 adds a fallback so `BufferedRequest` still reads
`request.Headers` when the `AddHeader` list is empty. This keeps the suite green while the
refactor lands. **Task 6 deletes it.** Do not ship it.

---

## File Structure

| File | Responsibility after this plan |
| --- | --- |
| `src/TlsClient/TlsRequestHeaderExtensions.cs` (new) | The `request.AddHeader` entry point. Nothing else. |
| `src/TlsClient/TlsRequestOptions.cs` | Gains `Headers`; loses `HeaderOrder` and `HeaderNamesOf`. |
| `src/TlsClient/BufferedRequest.cs` | Sources entries from the options collection; loses `HeaderOrder` and the `NonValidated` merges. |
| `src/TlsClient/Http11RequestWriter.cs` | `MergeHeaders` shrinks to four steps; `Order`, `FramingAnchor`, `InsertFraming` deleted. |
| `src/TlsClient/TlsSessionOptions.cs` | Loses `HeaderOrder` and `ValidateHeaderOrder`. |
| `src/TlsClient/TlsPreset.cs`, `TlsHttpBehaviorProfile.cs` | Lose the captured order and the profile-document field. |
| `src/TlsClient/Http11Connection.cs`, `Http2Connection.cs`, `Http3FieldMapper.cs` | Lose the `HeaderOrder` argument and the `cookieHeader` parameter. |
| `tests/TlsClient.Tests/InsertionOrderHeaderTests.cs` | The contract's proof. |

---

## Chunk 1: The AddHeader entry point

### Task 1: `TlsRequestOptions.Headers` and the `AddHeader` extension

**Files:**
- Create: `src/TlsClient/TlsRequestHeaderExtensions.cs`
- Modify: `src/TlsClient/TlsRequestOptions.cs` (add the property beside `Trailers`, line 12)
- Modify: `src/TlsClient/PublicAPI.Unshipped.txt`
- Test: `tests/TlsClient.Tests/AddHeaderTests.cs` (new)

- [ ] **Step 1: Write the failing test**

```csharp
namespace TlsClient.Tests;

public sealed class AddHeaderTests
{
    [Fact]
    public void AddHeaderRecordsNamesInInsertionOrderOnTheRequestsOptions()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeader("accept", "*/*");
        request.AddHeader("user-agent", "agent");

        var headers = TlsRequestOptions.For(request).Headers;
        Assert.Equal(["accept", "user-agent"], headers.Select(header => header.Key));
    }

    [Fact]
    public void AddHeaderKeepsAValueVerbatimRatherThanReflowingIt()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeader("accept-encoding", "gzip, deflate, br");

        Assert.True(
            TlsRequestOptions.For(request).Headers.TryGetValues("accept-encoding", out var values));
        Assert.Equal(["gzip, deflate, br"], values);
    }

    [Fact]
    public void AddingTheSameNameTwiceAppendsAValueAtTheNamesFirstPosition()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeader("a", "1");
        request.AddHeader("b", "2");
        request.AddHeader("a", "3");

        var headers = TlsRequestOptions.For(request).Headers;
        Assert.Equal(["a", "b"], headers.Select(header => header.Key));
        Assert.True(headers.TryGetValues("a", out var values));
        Assert.Equal(["1", "3"], values);
    }

    [Fact]
    public void AddHeaderRejectsANameThatIsNotAToken() =>
        Assert.Throws<ArgumentException>(() =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
            request.AddHeader("bad name", "value");
        });
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj --filter "FullyQualifiedName~AddHeaderTests"`

Expected: compile failure — `AddHeader` and `TlsRequestOptions.Headers` do not exist.

- [ ] **Step 3: Add the property**

In `src/TlsClient/TlsRequestOptions.cs`, immediately after the `Trailers` property:

```csharp
    /// <summary>
    /// Gets the request's header fields. This collection is the sole source of the wire's field
    /// section: a field reaches the wire if and only if it appears here, in the order it was
    /// added. Nothing is synthesised — an absent <c>Host</c> means no <c>Host</c> field, and an
    /// absent <c>Cookie</c> means the session container contributes nothing.
    /// </summary>
    /// <remarks>
    /// Values are stored verbatim. Nothing passes through <c>HttpRequestHeaders</c>, which is
    /// what keeps <c>accept-encoding: gzip, deflate, br</c> a single field line carrying those
    /// exact bytes rather than three lines.
    /// </remarks>
    public TlsHeaders Headers { get; } = new();
```

- [ ] **Step 4: Create the extension**

Create `src/TlsClient/TlsRequestHeaderExtensions.cs`:

```csharp
namespace TlsClient;

/// <summary>Adds header fields to an <see cref="HttpRequestMessage"/>.</summary>
public static class TlsRequestHeaderExtensions
{
    /// <summary>
    /// Adds a header field to <paramref name="request"/>. This is the only way a field reaches
    /// the wire: <c>request.Headers</c> and <c>request.Content.Headers</c> are not read.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="name">The field name. Must be a valid token.</param>
    /// <param name="value">The field value, sent verbatim.</param>
    /// <exception cref="ArgumentNullException">Any argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a valid token.</exception>
    public static void AddHeader(this HttpRequestMessage request, string name, string value)
    {
        ArgumentNullException.ThrowIfNull(request);
        TlsRequestOptions.For(request).Headers.Add(name, value);
    }
}
```

- [ ] **Step 5: Record the new public API**

Append to `src/TlsClient/PublicAPI.Unshipped.txt`, keeping the file's ordering:

```
TlsClient.TlsRequestHeaderExtensions
static TlsClient.TlsRequestHeaderExtensions.AddHeader(this System.Net.Http.HttpRequestMessage! request, string! name, string! value) -> void
TlsClient.TlsRequestOptions.Headers.get -> TlsClient.TlsHeaders!
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj --filter "FullyQualifiedName~AddHeaderTests"`

Expected: 4 passed.

- [ ] **Step 7: Commit**

```bash
git add src/TlsClient/TlsRequestHeaderExtensions.cs src/TlsClient/TlsRequestOptions.cs src/TlsClient/PublicAPI.Unshipped.txt tests/TlsClient.Tests/AddHeaderTests.cs
git commit -m "feat(headers): add request.AddHeader and the per-request header list"
```

---

### Task 2: Carry the list into `BufferedRequest`

**Files:**
- Modify: `src/TlsClient/TlsRequestOptions.cs` (`Snapshot`, and the `TlsRequestConfiguration` record at line 468)
- Modify: `src/TlsClient/BufferedRequest.cs:152-160`, `:196-212`, `:287-310`
- Test: `tests/TlsClient.Tests/AddHeaderTests.cs`

- [ ] **Step 1: Write the failing test**

Append to `AddHeaderTests`:

```csharp
    [Fact]
    public async Task TheBufferedFieldSectionIsTheAddHeaderSequence()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeader("host", "example.com");
        request.AddHeader("accept", "*/*");
        request.AddHeader("user-agent", "agent");

        var buffered = await BufferedRequest.CreateAsync(
            request,
            maximumBodyBytes: 4096,
            TlsHttpVersionPolicy.PreferHttp2,
            CancellationToken.None);

        Assert.Equal(
            ["host", "accept", "user-agent"],
            buffered.Headers.Select(header => header.Name.ToLowerInvariant()));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj --filter "FullyQualifiedName~TheBufferedFieldSectionIsTheAddHeaderSequence"`

Expected: FAIL — `buffered.Headers` is empty, because nothing reads the new collection yet.

- [ ] **Step 3: Add `Headers` to the configuration record**

In `src/TlsClient/TlsRequestOptions.cs`, add `HeaderEntry[] Headers` as the second component of
the `TlsRequestConfiguration` record, immediately after `Trailers`. In `Snapshot`, pass
`options.Headers.Snapshot()`. In the no-options early return at the top of `Snapshot`, pass `[]`
in the same position.

- [ ] **Step 4: Source the entries from it**

In `BufferedRequest.CreateAsync`, replace:

```csharp
        var entries = new List<HeaderEntry>();
        AddOrReplace(entries, request.Headers.NonValidated);
```

with:

```csharp
        // ponytail: transitional fallback, deleted in Task 6. Until every caller has moved to
        // request.AddHeader, a request with an empty list still reads .NET's collections.
        var entries = requestConfiguration.Headers.Length > 0
            ? new List<HeaderEntry>(requestConfiguration.Headers)
            : ReadLegacyHeaders(request);
```

Move the existing `request.Headers.NonValidated` merge into a new
`private static List<HeaderEntry> ReadLegacyHeaders(HttpRequestMessage request)` helper, and
guard the `AddOrReplace(entries, request.Content.Headers.NonValidated)` calls at `:159` and
`:209` so they run only when the fallback was taken. Apply the same change in `CreateStreaming`
and in `ReadMetadata`.

`BufferedRequest.Headers` is a positional record component already fed by `entries.ToArray()`,
so no new property is needed.

- [ ] **Step 5: Run the full suite**

Run: `dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj`

Expected: all pass. The fallback keeps every existing test on its old path.

- [ ] **Step 6: Commit**

```bash
git add src/TlsClient/TlsRequestOptions.cs src/TlsClient/BufferedRequest.cs tests/TlsClient.Tests/AddHeaderTests.cs
git commit -m "feat(headers): source BufferedRequest entries from the AddHeader list"
```

---

## Chunk 2: Seal the writer

### Task 3: Framing goes in the slot the caller named

**Files:**
- Modify: `src/TlsClient/Http11RequestWriter.cs` — the body-framing block of `MergeHeaders`, plus `FramingAnchor` and `InsertFraming`
- Test: `tests/TlsClient.Tests/InsertionOrderHeaderTests.cs`

The caller's chosen framing **name** is honoured, not just its position:

- named `content-length` → the computed length is written at that index.
- named `transfer-encoding` → `Transfer-Encoding: chunked` is written at that index and the body
  is chunked, whatever its length.
- named `content-length` but trailers or a streaming body make a length impossible → throw.
- named neither, with a body → throw.

- [ ] **Step 1: Write the failing tests**

Replace the file's `WireOrderAsync` helper with one that returns the merged entries:

```csharp
    private static async Task<List<HeaderEntry>> WireAsync(HttpRequestMessage request)
    {
        var buffered = await BufferedRequest.CreateAsync(
            request,
            maximumBodyBytes: 4096,
            TlsHttpVersionPolicy.PreferHttp2,
            CancellationToken.None);
        return Http11RequestWriter.MergeHeaders(buffered);
    }
```

```csharp
    [Fact]
    public async Task TheComputedLengthLandsInTheSlotTheCallerNamed()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/")
        {
            Content = new ReadOnlyMemoryContent(Encoding.UTF8.GetBytes("body")),
        };
        request.AddHeader("content-type", "application/x-protobuf");
        request.AddHeader("accept", "*/*");
        request.AddHeader("content-length", "-1");
        request.AddHeader("user-agent", "agent");

        var wire = await WireAsync(request);
        Assert.Equal(
            ["content-type", "accept", "content-length", "user-agent"],
            wire.Select(header => header.Name.ToLowerInvariant()));
        Assert.Equal(
            ["4"],
            wire.Single(header =>
                header.Name.Equals("content-length", StringComparison.OrdinalIgnoreCase)).Values);
    }

    [Fact]
    public async Task ABodyWithNoFramingNameThrows()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/")
        {
            Content = new ReadOnlyMemoryContent(Encoding.UTF8.GetBytes("body")),
        };
        request.AddHeader("accept", "*/*");

        await Assert.ThrowsAsync<InvalidOperationException>(() => WireAsync(request));
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj --filter "FullyQualifiedName~InsertionOrderHeaderTests"`

Expected: compile failure — `MergeHeaders` still takes a `cookieHeader` argument.

- [ ] **Step 3: Rewrite the framing block**

Replace `FramingAnchor` and `InsertFraming` with:

```csharp
    /// <summary>
    /// Reports the index of the framing slot the caller named, or -1. The name chosen there
    /// decides the framing: Transfer-Encoding forces chunked, Content-Length takes the computed
    /// length.
    /// </summary>
    private static int IndexOfFraming(List<HeaderEntry> headers) =>
        headers.FindIndex(header =>
            header.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
            header.Name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase));
```

and replace the `if (request.HasPayload)` block with:

```csharp
        if (request.HasPayload)
        {
            var index = IndexOfFraming(headers);
            if (index < 0)
            {
                throw new InvalidOperationException(
                    "The request has a body, but its header list names neither Content-Length " +
                    "nor Transfer-Encoding. Call request.AddHeader with one of them to place " +
                    "the body-framing field.");
            }
            var chunked = headers[index].Name.Equals(
                "Transfer-Encoding", StringComparison.OrdinalIgnoreCase);
            if (!chunked && (request.HasTrailers || request.ContentLength is null))
            {
                throw new InvalidOperationException(
                    "The request names Content-Length, but its body length is not known in " +
                    "advance. Name Transfer-Encoding instead.");
            }
            headers[index] = chunked
                ? new HeaderEntry("Transfer-Encoding", ["chunked"])
                : new HeaderEntry(
                    "Content-Length",
                    [request.ContentLength!.Value.ToString(
                        System.Globalization.CultureInfo.InvariantCulture)]);
        }
```

Delete the `Remove(headers, "Content-Length")` and `Remove(headers, "Transfer-Encoding")` calls
that preceded the old anchor logic.

- [ ] **Step 4: Run to verify they pass**

Run: `dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj --filter "FullyQualifiedName~InsertionOrderHeaderTests"`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/TlsClient/Http11RequestWriter.cs tests/TlsClient.Tests/InsertionOrderHeaderTests.cs
git commit -m "feat(headers): write body framing into the slot the caller named"
```

---

### Task 4: Stop synthesising Host, Cookie, Trailer and Connection

**Files:**
- Modify: `src/TlsClient/Http11RequestWriter.cs:16-20` (`Connection`), `:96-118` (`Host`, `Cookie`), `:138-149` (`Trailer`)
- Modify: `src/TlsClient/Http11Connection.cs:44`, `Http2Connection.cs:811`, `Http3FieldMapper.cs:62`, `TlsSession.cs`
- Test: `tests/TlsClient.Tests/InsertionOrderHeaderTests.cs`

- [ ] **Step 1: Write the failing test**

```csharp
    [Fact]
    public async Task NothingTheCallerDidNotAddReachesTheWire()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/")
        {
            Content = new StringContent("body", Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation("x-ignored", "1");
        request.AddHeader("content-type", "application/json");
        request.AddHeader("content-length", "-1");

        // No Host, no Connection, no Cookie, no x-ignored, and StringContent's own
        // "application/json; charset=utf-8" never appears — only the caller's exact bytes.
        var wire = await WireAsync(request);
        Assert.Equal(
            ["content-type", "content-length"],
            wire.Select(header => header.Name.ToLowerInvariant()));
        Assert.Equal(["application/json"], wire[0].Values);
    }
```

- [ ] **Step 2: Run to verify it fails**

Expected: FAIL — `host` leads the list.

- [ ] **Step 3: Delete the four injections**

In `SerializeHeaders`, delete:

```csharp
        if (!Contains(headers, "Connection"))
        {
            headers.Add(new HeaderEntry("Connection", ["keep-alive"]));
        }
```

RFC 9112 section 9.3 makes HTTP/1.1 persistent by default, so omitting the field is legal and
matches captures that do not send it.

In `MergeHeaders`, delete the `if (!Contains(headers, "Host"))` block including its CONNECT
authority comment, the `if (!Contains(headers, "Cookie") && ...)` block, and the
`if (request.HasTrailers) { Remove(headers, "Trailer"); ... }` block. Remove the now-unused
`cookieHeader` and `emitTrailerHeader` parameters from `MergeHeaders` and `Has100Continue`, and
the `cookieHeader` parameter from `SerializeHeaders`.

Keep `FormatAuthority` — `Http2Connection` and `Http3FieldMapper` still call it as the
`:authority` fallback when no `host` field was added.

- [ ] **Step 4: Fix the call sites the compiler names**

Drop the `cookieHeader` and `EmitTrailerHeader` arguments at `Http11Connection.cs:44`,
`Http2Connection.cs:811` and `Http3FieldMapper.cs:62`, then follow the compiler up the chain
through `TlsSession` until `cookieHeader` is gone from all 27 sites. `TlsSession.Cookies` stays
public and keeps recording `Set-Cookie`; it simply no longer contributes a request field.

- [ ] **Step 5: Run the full suite**

Run: `dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj`

Expected: many failures in tests that assumed a synthesised `Host` or `Connection`. That is the
point of the change; Task 12 migrates them. Confirm `InsertionOrderHeaderTests` and
`AddHeaderTests` pass.

- [ ] **Step 6: Commit**

```bash
git add src/TlsClient/ tests/TlsClient.Tests/InsertionOrderHeaderTests.cs
git commit -m "feat(headers)!: stop synthesising Host, Cookie, Trailer and Connection"
```

---

### Task 5: Delete `Order()`

**Files:**
- Modify: `src/TlsClient/Http11RequestWriter.cs:209-230`, `Http2Connection.cs:815-817`, `Http3FieldMapper.cs:66-68`, `Http11Connection.cs:50`

- [ ] **Step 1: Delete the method and its three call sites**

The merged list is already in the caller's order, so `Order` has nothing left to do. Delete the
method; at each call site drop the `regular = Http11RequestWriter.Order(...)` and
`merged = Http11RequestWriter.Order(...)` lines, and drop the `preferredOrder` parameter of
`SerializeHeaders`.

- [ ] **Step 2: Build**

Run: `dotnet build src/TlsClient/TlsClient.csproj`

Expected: succeeds. `request.HeaderOrder` and `configuration.HeaderOrder` are now unreferenced.

- [ ] **Step 3: Commit**

```bash
git add src/TlsClient/
git commit -m "refactor(headers): delete Order, the merged list is already the caller's"
```

---

### Task 6: Delete the transitional fallback

**Files:**
- Modify: `src/TlsClient/BufferedRequest.cs`

- [ ] **Step 1: Delete `ReadLegacyHeaders` and both `NonValidated` merges**

`CreateAsync`, `CreateStreaming` and `ReadMetadata` take their entries only from
`requestConfiguration.Headers`. `CreateStreaming` keeps its
`request.Content.Headers.ContentLength` read — that is the body-size limit check, not a header
merge. Delete the now-dead `AddOrReplace(List<HeaderEntry>, HttpHeadersNonValidated)` overload
and `IsContentHeader`.

- [ ] **Step 2: Run the two contract suites**

Run: `dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj --filter "FullyQualifiedName~AddHeaderTests|FullyQualifiedName~InsertionOrderHeaderTests"`

Expected: PASS. The rest of the suite stays red until Task 12.

- [ ] **Step 3: Commit**

```bash
git add src/TlsClient/BufferedRequest.cs
git commit -m "refactor(headers)!: stop reading request.Headers and Content.Headers"
```

---

## Chunk 3: Delete the order surface

Tasks 7, 8 and 9 leave the tree unbuildable individually — `TlsPreset` and
`TlsHttpBehaviorProfile` reference the property Task 7 removes. Do all three, then build, then
make one commit. This is the one place in the plan where a task does not end in a commit.

### Task 7: `TlsSessionOptions.HeaderOrder`

**Files:**
- Modify: `src/TlsClient/TlsSessionOptions.cs:147`, `:261`, `:301-312`, `:348`
- Modify: `src/TlsClient/PublicAPI.Shipped.txt:306-307`

- [ ] **Step 1:** Delete the property, the `ValidateHeaderOrder` method, its call in the
  snapshot, and the `HeaderOrder` component of `TlsSessionConfiguration`.
- [ ] **Step 2:** Delete lines 306-307 from `PublicAPI.Shipped.txt`. This is a deliberate
  breaking change; the commit subject carries `!`.

### Task 8: `TlsRequestOptions.HeaderOrder` and `HeaderNamesOf`

**Files:**
- Modify: `src/TlsClient/TlsRequestOptions.cs:80-87`, `:230-301`, `:359-363`, `:468`
- Modify: `src/TlsClient/PublicAPI.Unshipped.txt:389-390`, `:416`
- Modify: `src/TlsClient/BufferedRequest.cs:38`, `:183`, `:234`
- Delete: `tests/TlsClient.Tests/TlsRequestOptionsHeaderNamesTests.cs`

- [ ] **Step 1:** Delete `HeaderOrder`, `HeaderNamesOf` and its remarks block, the `HeaderOrder`
  validation inside `Snapshot`, the record component, and `BufferedRequest.HeaderOrder` with its
  two initialisers.
- [ ] **Step 2:** Delete the corresponding `PublicAPI.Unshipped.txt` lines, and delete
  `TlsRequestOptionsHeaderNamesTests.cs` — its subject no longer exists.

### Task 9: Presets and behavior profiles

**Files:**
- Modify: `src/TlsClient/TlsPreset.cs:52`, `:89`, the `_headerOrder` field, and every constructor
  call that supplies it
- Modify: `src/TlsClient/TlsHttpBehaviorProfile.cs:52`, `:63`, `:84-85`, `:138`, `:143`, `:147`,
  `:166`, `:175`, `:187-200`, `:226`
- Modify: `src/TlsClient/PublicAPI.Shipped.txt:129`

- [ ] **Step 1:** Before deleting `TlsPreset._headerOrder`, copy each preset's captured array
  into a scratch note. Task 13 needs those sequences for the samples, and after this commit they
  exist only in git history.
- [ ] **Step 2:** Delete `TlsHttpBehaviorProfile.HeaderOrder`, its `ValidateHeaderOrder`, the
  `HeaderOrder` field of the profile-document record, and the `document.HeaderOrder is null`
  guard at `:138`. The field leaves the schema, so a manifest that still carries it is ignored by
  `System.Text.Json` rather than rejected.
- [ ] **Step 3:** Delete `_headerOrder` from `TlsPreset` and its assignment in `ApplyTo`.
- [ ] **Step 4:** Delete line 129 from `PublicAPI.Shipped.txt`.
- [ ] **Step 5: Build, then commit Tasks 7-9 together**

Run: `dotnet build src/TlsClient/TlsClient.csproj`

Expected: succeeds.

```bash
git add src/TlsClient/ tests/TlsClient.Tests/TlsRequestOptionsHeaderNamesTests.cs
git commit -m "refactor(headers)!: delete HeaderOrder from session, request, preset and profile"
```

### Task 10: Profile-manifest round-trip

**Files:**
- Modify: `tests/TlsClient.Tests/TlsHttpBehaviorProfileTests.cs`
- Modify: `docs/PROFILE-MANIFEST.md`

- [ ] **Step 1:** Update the round-trip tests and the documented manifest schema to drop
  `headerOrder`. Note in the doc that a manifest still carrying the field is accepted and ignored.
- [ ] **Step 2:** Run `dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj --filter "FullyQualifiedName~TlsHttpBehaviorProfileTests"`
- [ ] **Step 3:** Commit.

---

## Chunk 4: Callers, tests and docs

### Task 11: Rewrite `InsertionOrderHeaderTests` as the contract

**Files:**
- Modify: `tests/TlsClient.Tests/InsertionOrderHeaderTests.cs`

Its four original tests documented what `TryAddWithoutValidation` does to header order. Three of
those behaviours no longer exist. The file becomes the proof of the new contract; update its
class-level summary comment to say so.

- [ ] **Step 1:** GET — the wire equals the `AddHeader` sequence.
- [ ] **Step 2:** POST — `content-type` first, computed `content-length` mid-block (from Task 3).
- [ ] **Step 3:** POST with a body and no framing name → throws (from Task 3).
- [ ] **Step 4:** `request.Headers` and `StringContent`'s own `Content-Type` never reach the wire
  (from Task 4).
- [ ] **Step 5:** `accept-encoding: gzip, deflate, br` is one field line carrying those bytes.
- [ ] **Step 6:** A cross-origin redirect still drops `authorization` and `cookie`. Build the
  redirected request through `BufferedRequest`'s redirect path with
  `SuppressSensitiveSessionHeaders` set, and assert both are absent while other fields survive.
- [ ] **Step 7:** Run the file, then commit.

### Task 12: Migrate the test suite

**Files:** the 10 test files holding the 40 `TryAddWithoutValidation` call sites.

- [ ] **Step 1:** Find them: `grep -rn "TryAddWithoutValidation" --include=*.cs tests/`
- [ ] **Step 2:** Replace `request.Headers.TryAddWithoutValidation(name, value)` with
  `request.AddHeader(name, value)`.
- [ ] **Step 3:** Leave the deliberate negative uses. `Http2PseudoHeaderTests` and
  `Http2HeaderBlockFramingTests` add a `Host` or `Trailer` specifically to prove it is rejected or
  suppressed. Those now prove it is *ignored* — update the assertions and the comments to say so
  rather than deleting the tests.
- [ ] **Step 4:** Every test that expected a synthesised `Host`, a `Connection: keep-alive`, a
  container `Cookie`, or a generated `Trailer` now needs an explicit `request.AddHeader` for it,
  or an assertion that it is absent. Decide per test which the test was actually about.
- [ ] **Step 5:** Every POST/PUT test now needs `request.AddHeader("content-length", "-1")` or
  `request.AddHeader("transfer-encoding", "chunked")` or it will throw. This is the largest single
  source of churn.
- [ ] **Step 6:** Run `dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj` — expect green.
- [ ] **Step 7:** Commit in file-sized batches, not one commit for all ten.

### Task 13: Migrate samples and tools

**Files:** `samples/TlsClient.SpotifyIos26/Program.cs`, `samples/TlsClient.SpotifyIos26/SpotifyHttp3Examples.cs`, `samples/TlsClient.QuickStart/`, `tools/` — 34 call sites.

- [ ] **Step 1:** Same mechanical replacement as Task 12.
- [ ] **Step 2:** The Spotify samples must now add `host` explicitly, at the position the
  preset's deleted `_headerOrder` array put it. Use the sequences copied in Task 9 Step 1.
- [ ] **Step 3:** The POST examples need a `content-length` slot added at the captured position.
- [ ] **Step 4:** Run `dotnet build` across the solution.
- [ ] **Step 5:** Commit.

### Task 14: Documentation

**Files:** `docs/USAGE.md`, `docs/PRESETS.md`

- [ ] **Step 1:** `docs/USAGE.md` — replace the `HeaderOrder` section with the one rule and an
  `AddHeader` example, covering the `Host` and framing-slot requirements explicitly, since both
  are new obligations on the caller.
- [ ] **Step 2:** `docs/PRESETS.md` — presets no longer carry a header order. Say where callers
  get the captured sequence instead.
- [ ] **Step 3:** Commit.

---

## Definition of done

- [ ] `dotnet build` succeeds for every project in the solution.
- [ ] `dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj` is green with no skips added.
- [ ] `grep -rn "HeaderOrder" --include=*.cs src/ tests/ samples/ tools/` returns only
      `PseudoHeaderOrder` matches.
- [ ] `grep -rn "TryAddWithoutValidation" --include=*.cs src/ samples/ tools/` returns nothing.
- [ ] `PublicAPI.Shipped.txt` and `PublicAPI.Unshipped.txt` match the built surface.
