# QPACK Dynamic-Table Encoder Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** SharpTls's HTTP/3 client encodes request headers through a QPACK dynamic table the way the captured Spotify iOS client does, behind three knobs whose defaults leave today's static-only bytes untouched.

**Architecture:** A new encoder-side table (`TlsQuicQpackEncoderTable`) and a per-connection policy (`TlsQuicQpackEncoderPolicy`) sit beside the existing static encoder. The policy plans a request without mutating anything; `TlsQuicHttp3Connection.TryOpenRequest` commits the plan only after every refusal check has passed. `TlsQuicHttp3Streams` grows the encoder stream, lazy uni-stream opening, and a reader for the peer's decoder stream. TlsClient exposes the knobs and the Spotify preset turns them on.

**Tech Stack:** C# / .NET 9, xunit, SharpTls `Quic` namespace, RFC 9204. Spec: `SharpTls/docs/superpowers/specs/2026-09-27-qpack-dynamic-table-encoder-design.md`. Evidence: `SharpTls/docs/superpowers/specs/reference-captures/2026-09-26-spotify-9.1.86-ios27-pcapng.md` §6.

**Conventions every task follows:**
- Build/test from `C:\Users\Admin\Desktop\PROJECTS\PeakTLS`. SharpTls tests: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~<Class>"`. TlsClient tests: `dotnet test TlsClient-main/tests/TlsClient.Tests --filter ...`. Pipe through `grep -E "Failed |Passed!|Failed!| error "` to keep output short.
- Test files live in `SharpTls/tests/SharpTls.Tests/Quic/`, namespace `SharpTls.Tests.Quic`, `using SharpTls.Quic;`, `public sealed class XTests`, xunit `[Fact]`/`[Theory]`. Expected bytes are written out literally (hex), never produced by the code under test.
- Source files carry a leading comment block explaining the RFC sections they implement, in the existing voice (see `TlsQuicQpackEncoder.cs`). No mutation ledger is required for new files.
- Every public TlsClient member goes into `TlsClient-main/src/TlsClient/PublicAPI.Unshipped.txt` (analyzer RS0016 fails the build otherwise).
- No commits until the whole plan is done (user decision); run the listed tests after every task instead.
- Byte vectors from the capture (all from `spclient.wg.spotify.com`, conn 61, decoded in the reference doc §6):
  - Set Dynamic Table Capacity 4096: `3f e1 1f`
  - Insert `:authority` (static 0) = `spclient.wg.spotify.com`, Huffman: `c0 91 45 64 a0 c5 a9 2b f8 99 74 56 74 9a 5f 4b 90 f4 ff`
  - Insert literal name `spotify-app-version` = `9.1.86.2428`, both Huffman: `6e 45 67 49 a5 f4 b0 eb ad 6e e5 b1 06 3d 5f 88 7d 70 ae f3 8b 89 a1 3d`
  - Insert literal name `app-platform` = `iOS`, name Huffman, value raw: `69 1d 75 ad 5d 03 4c a7 b2 9f 03 69 4f 53`
  - Prefix RIC 9 / Base 0 (peer max 4096 → MaxEntries 128): `0a 88`; prefix RIC 9 / Base 9: `0a 00`; static-only prefix: `00 00`
  - Indexed post-base index 0: `10`; indexed dynamic relative 0: `80`

---

## Chunk 1: encoders and table

### Task 1: Encoder instruction writers and dynamic representations

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicQpackEncoder.cs`
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicQpackEncoderInstructionTests.cs` (new)

- [ ] **Step 1: Write the failing tests** — one per writer, literal expected bytes:

```csharp
using System.Text;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// RFC 9204 s4.3 encoder instructions and the s4.5 dynamic representations, encoding side.
// Every expected byte string below is from the 2026-09-26 capture (reference doc s6) or
// derived by hand from s4.3/s4.5; none is produced by the code under test.
public sealed class TlsQuicQpackEncoderInstructionTests
{
    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    [Fact]
    public void SetDynamicTableCapacity4096IsThreeOctets()
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(TlsQuicQpackEncoder.TryEncodeSetDynamicTableCapacity(4096, buffer, out int written));
        Assert.Equal("3FE11F", Convert.ToHexString(buffer[..written]));
    }

    [Fact]
    public void InsertWithStaticNameReferenceMatchesTheCapturedAuthorityInsert()
    {
        Span<byte> buffer = stackalloc byte[64];
        Assert.True(TlsQuicQpackEncoder.TryEncodeInsertWithStaticNameReference(
            0, Ascii("spclient.wg.spotify.com"), TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo, buffer, out int written));
        Assert.Equal("C0914564A0C5A92BF8997456749A5F4B90F4FF", Convert.ToHexString(buffer[..written]));
    }

    [Fact]
    public void InsertWithLiteralNameMatchesTheCapturedAppVersionInsert()
    {
        Span<byte> buffer = stackalloc byte[64];
        Assert.True(TlsQuicQpackEncoder.TryEncodeInsertWithLiteralName(
            Ascii("spotify-app-version"), Ascii("9.1.86.2428"), TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo, buffer, out int written));
        Assert.Equal("6E456749A5F4B0EBAD6EE5B1063D5F887D70AEF38B89A13D", Convert.ToHexString(buffer[..written]));
    }

    [Fact]
    public void ARawValueUnderShorterOfTheTwoMatchesTheCapturedAppPlatformInsert()
    {
        Span<byte> buffer = stackalloc byte[64];
        Assert.True(TlsQuicQpackEncoder.TryEncodeInsertWithLiteralName(
            Ascii("app-platform"), Ascii("iOS"), TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo, buffer, out int written));
        Assert.Equal("691D75AD5D034CA7B29F03694F53", Convert.ToHexString(buffer[..written]));
    }

    [Theory]
    [InlineData(0UL, 0UL, 128UL, "0000")]   // static-only section
    [InlineData(9UL, 0UL, 128UL, "0A88")]   // capture: RIC 9, Base 0 -> S=1, Delta 8
    [InlineData(9UL, 9UL, 128UL, "0A00")]   // capture: RIC 9, Base 9 -> S=0, Delta 0
    [InlineData(10UL, 12UL, 128UL, "0B02")] // Base past RIC -> S=0, Delta 2
    [InlineData(300UL, 300UL, 128UL, "2D00")] // 300 mod 256 = 44, +1 = 45 = 0x2D
    public void TheFieldSectionPrefixEncodesRicAndBasePerSection451(ulong ric, ulong @base, ulong maxEntries, string hex)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(ric, @base, maxEntries, buffer, out int written));
        Assert.Equal(hex, Convert.ToHexString(buffer[..written]));
    }

    [Fact]
    public void IndexedDynamicAndPostBaseLinesCarryTheirPatterns()
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(TlsQuicQpackEncoder.TryEncodeIndexedDynamic(0, buffer, out int a));
        Assert.Equal("80", Convert.ToHexString(buffer[..a]));
        Assert.True(TlsQuicQpackEncoder.TryEncodeIndexedDynamic(63, buffer, out a));
        Assert.Equal("BF00", Convert.ToHexString(buffer[..a]));          // 6-bit fill boundary
        Assert.True(TlsQuicQpackEncoder.TryEncodeIndexedPostBase(0, buffer, out int b));
        Assert.Equal("10", Convert.ToHexString(buffer[..b]));
        Assert.True(TlsQuicQpackEncoder.TryEncodeIndexedPostBase(15, buffer, out b));
        Assert.Equal("1F00", Convert.ToHexString(buffer[..b]));          // 4-bit fill boundary
    }

    [Fact]
    public void ADestinationOneOctetShortFailsWithoutWriting()
    {
        Span<byte> buffer = stackalloc byte[2];
        Assert.False(TlsQuicQpackEncoder.TryEncodeSetDynamicTableCapacity(4096, buffer, out int written));
        Assert.Equal(0, written);
    }
}
```

- [ ] **Step 2: Run it, expect compile failure** (`TryEncodeSetDynamicTableCapacity` undefined):
`dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~TlsQuicQpackEncoderInstructionTests"`

- [ ] **Step 3: Implement** in `TlsQuicQpackEncoder.cs`. Add constants and writers next to the existing ones; reuse the private `TryEncodeString`:

```csharp
    // RFC 9204 s4.3 encoder instructions. The static-only header comment above this class
    // is now historical for the instructions: they exist because the dynamic arm exists.
    private const byte SetDynamicTableCapacityPattern = 0b0010_0000;     // s4.3.1, 5-bit prefix
    private const byte InsertWithNameReferenceStaticPattern = 0b1100_0000; // s4.3.2, T = 1, 6-bit
    private const byte InsertWithLiteralNamePattern = 0b0100_0000;       // s4.3.3, H + 5-bit name length
    private const byte IndexedFieldLineDynamicPattern = 0b1000_0000;     // s4.5.2, T = 0, 6-bit
    private const byte IndexedFieldLinePostBasePattern = 0b0001_0000;    // s4.5.3, 4-bit
    private const int SetDynamicTableCapacityPrefixBits = 5;
    private const int InsertNameLiteralPrefixBits = 6;                   // H bit + 5-bit length
    private const int PostBaseIndexPrefixBits = 4;
    private const int RequiredInsertCountPrefixBits = 8;
    private const int DeltaBasePrefixBits = 7;
    private const byte DeltaBaseSignBit = 0b1000_0000;

    internal static bool TryEncodeSetDynamicTableCapacity(ulong capacity, Span<byte> destination, out int written) =>
        TlsQuicQpackPrimitives.TryEncodeInteger(capacity, SetDynamicTableCapacityPrefixBits, SetDynamicTableCapacityPattern, destination, out written);

    internal static bool TryEncodeInsertWithStaticNameReference(
        int staticIndex, ReadOnlySpan<byte> value, TlsQuicQpackHuffmanPolicy huffman, Span<byte> destination, out int written)
    {
        written = 0;
        if (!TlsQuicQpackPrimitives.TryEncodeInteger((ulong)staticIndex, IndexedFieldLinePrefixBits, InsertWithNameReferenceStaticPattern, destination, out int head)) return false;
        if (!TryEncodeString(value, ValueLiteralPrefixBits, 0, huffman, destination[head..], out int tail)) return false;
        written = head + tail;
        return true;
    }

    internal static bool TryEncodeInsertWithLiteralName(
        ReadOnlySpan<byte> name, ReadOnlySpan<byte> value, TlsQuicQpackHuffmanPolicy huffman, Span<byte> destination, out int written)
    {
        written = 0;
        if (!TryEncodeString(name, InsertNameLiteralPrefixBits, InsertWithLiteralNamePattern, huffman, destination, out int head)) return false;
        if (!TryEncodeString(value, ValueLiteralPrefixBits, 0, huffman, destination[head..], out int tail)) return false;
        written = head + tail;
        return true;
    }

    // s4.5.1. maxEntries is floor(peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY / 32), NOT ours.
    internal static bool TryEncodeFieldSectionPrefix(
        ulong requiredInsertCount, ulong @base, ulong maxEntries, Span<byte> destination, out int written)
    {
        written = 0;
        if (requiredInsertCount != 0 && maxEntries == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxEntries), "A non-zero Required Insert Count needs a non-zero MaxEntries (RFC 9204 s4.5.1.1).");
        }
        ulong encoded = requiredInsertCount == 0 ? 0 : (requiredInsertCount % (2 * maxEntries)) + 1;
        if (!TlsQuicQpackPrimitives.TryEncodeInteger(encoded, RequiredInsertCountPrefixBits, 0, destination, out int head)) return false;
        bool negative = @base < requiredInsertCount;
        ulong delta = negative ? requiredInsertCount - @base - 1 : @base - requiredInsertCount;
        if (!TlsQuicQpackPrimitives.TryEncodeInteger(delta, DeltaBasePrefixBits, negative ? DeltaBaseSignBit : (byte)0, destination[head..], out int tail)) return false;
        written = head + tail;
        return true;
    }

    internal static bool TryEncodeIndexedDynamic(ulong relativeIndex, Span<byte> destination, out int written) =>
        TlsQuicQpackPrimitives.TryEncodeInteger(relativeIndex, IndexedFieldLinePrefixBits, IndexedFieldLineDynamicPattern, destination, out written);

    internal static bool TryEncodeIndexedPostBase(ulong postBaseIndex, Span<byte> destination, out int written) =>
        TlsQuicQpackPrimitives.TryEncodeInteger(postBaseIndex, PostBaseIndexPrefixBits, IndexedFieldLinePostBasePattern, destination, out written);
```

Check `TryEncodeString`'s `precedingBits` contract: it ORs the H bit at `1 << (prefixBits - 1)`; with `prefixBits = 6` and pattern `0b0100_0000` the H bit lands at bit 5, which is s4.3.3's layout. Also check `TlsQuicQpackPrimitives.TryEncodeInteger` throws if `precedingBits` overlaps the prefix mask — `0b0100_0000` with a 6-bit prefix is clear.

Update the class header comment: the "STATIC REFERENCES ONLY" paragraph now describes `TryEncodeFieldLine` alone; add two sentences saying the dynamic representations and instructions below are driven by `TlsQuicQpackEncoderPolicy` and are never reached with capacity 0.

- [ ] **Step 4: Run the tests, expect PASS.** Then run the existing `FullyQualifiedName~Qpack` filter, expect no change.

### Task 2: `TlsQuicQpackEncoderTable`

**Files:**
- Create: `SharpTls/src/SharpTls/Quic/TlsQuicQpackEncoderTable.cs`
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicQpackEncoderTableTests.cs`

- [ ] **Step 1: Write the failing tests.** Cover, with hand-computed numbers:
  - `EntrySizeIs32PlusNamePlusValue`: insert `("a","bc")` → `Size == 35`, `InsertCount == 1`, `TryFind` returns absolute 0.
  - `MaxEntriesComesFromThePeerMaximumNotTheCapacity`: `new(4096, 16383)` → `MaxEntries == 511`; `new(4096, 4096)` → 128.
  - `EvictionDropsTheOldestUntilItFits`: capacity 100; insert three 35-byte entries (`"a"/"bc"` ×3 with distinct values) — third insert evicts abs 0: `DroppedCount == 1`, `Size == 70`, `TryFind` of the first value false.
  - `AReferencedEntryIsNeverEvictedAndBlocksTheInsert`: capacity 100; insert abs 0, 1; `RecordSection(4, requiredInsertCount: 1, referenced: [0])`; `CanInsert("a","zz")` (35 bytes, needs eviction of abs 0) → false; after `TryAcknowledgeSection(4)` → true.
  - `SectionAcknowledgmentRaisesKnownReceivedToThatSectionsRic`: record section on stream 4 with RIC 3 and stream 8 with RIC 2; ack 8 → KRC 2; ack 4 → KRC 3; ack 4 again (no section) → false.
  - `InsertCountIncrementOfZeroOrPastInsertCountIsRefused`: `TryIncrementKnownReceived(0)` false; `(InsertCount + 1)` false; `(1)` true when one entry exists.
  - `BlockedStreamCountCountsStreamsWithASectionAboveKnownReceived`: two sections on stream 4 (RIC 1, RIC 2) and one on stream 8 (RIC 1); KRC 0 → count 2; increment KRC to 1 → count 1 (stream 4's RIC 2 still above); `TryCancelStream(4)` → 0.
  - `RecordSectionWithRicZeroIsNotRecorded`: `RecordSection(4, 0, [])` then `TryAcknowledgeSection(4)` → false.

- [ ] **Step 2: Run, expect compile failure.**

- [ ] **Step 3: Implement.** Shape (fill in bodies; keep it ~200 lines):

```csharp
namespace SharpTls.Quic;

// RFC 9204 s3.2 dynamic table, ENCODER side. ... (header comment: why a second table class:
// the decoder-side TlsQuicQpackDynamicTable is driven by the peer's instructions and resolves
// indices; this one is driven by our policy and tracks what the peer has acknowledged.)
internal sealed class TlsQuicQpackEncoderTable
{
    internal const int EntrySizeOverhead = 32;                 // s3.2.1
    private sealed class Entry(ulong absoluteIndex, byte[] name, byte[] value)
    {
        public ulong AbsoluteIndex { get; } = absoluteIndex;
        public byte[] Name { get; } = name; public byte[] Value { get; } = value;
        public int Size => EntrySizeOverhead + Name.Length + Value.Length;
        public int References;                                  // outstanding section references
    }
    private sealed record Section(ulong StreamId, ulong RequiredInsertCount, ulong[] Referenced);

    private readonly List<Entry> _entries = [];                 // oldest first; _entries[0].AbsoluteIndex == DroppedCount
    private readonly List<Section> _sections = [];              // unacknowledged, in record order

    internal TlsQuicQpackEncoderTable(int capacity, ulong peerMaximumCapacity)
    { /* capacity >= 0, capacity <= peerMaximumCapacity, else ArgumentOutOfRangeException */ }

    internal int Capacity { get; }   internal int Size { get; private set; }
    internal ulong InsertCount { get; private set; }   internal ulong DroppedCount { get; private set; }
    internal ulong KnownReceivedCount { get; private set; }
    internal ulong MaxEntries { get; }                          // peerMaximumCapacity / 32
    internal int BlockedStreamCount => _sections.Where(s => s.RequiredInsertCount > KnownReceivedCount).Select(s => s.StreamId).Distinct().Count();

    internal bool TryFind(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value, out ulong absoluteIndex) { /* newest first */ }
    internal bool IsKnownReceived(ulong absoluteIndex) => absoluteIndex < KnownReceivedCount;

    // Bytes freeable by evicting the contiguous oldest run of unreferenced entries whose
    // absolute index is below `protectBelow` (the caller passes the smallest index the
    // section being planned references, or ulong.MaxValue). s2.1.1.
    internal int EvictableBytes(ulong protectBelow) { ... }
    internal bool CanInsert(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value, ulong protectBelow = ulong.MaxValue) =>
        EntrySizeOverhead + name.Length + value.Length <= Capacity - Size + EvictableBytes(protectBelow);

    internal ulong Insert(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    { /* evict from oldest while Size + size > Capacity; throw InvalidOperationException if a referenced entry is reached (caller must have checked CanInsert); append; InsertCount++ */ }

    internal void RecordSection(ulong streamId, ulong requiredInsertCount, IReadOnlyList<ulong> referenced)
    { if (requiredInsertCount == 0) return; /* ++References on each referenced entry; add Section */ }
    internal bool TryAcknowledgeSection(ulong streamId) { /* oldest section with StreamId; release refs; KRC = max(KRC, RIC); remove */ }
    internal bool TryCancelStream(ulong streamId) { /* release every section on stream; return whether any */ }
    internal bool TryIncrementKnownReceived(ulong increment)
    { if (increment == 0 || KnownReceivedCount + increment > InsertCount) return false; KnownReceivedCount += increment; return true; }
}
```

Eviction needs `_entries[i].References == 0` — entries whose sections were acknowledged keep no reference. Note `TryAcknowledgeSection` must raise `KnownReceivedCount` only upward.

- [ ] **Step 4: Run the tests, expect PASS.**

### Task 3: `TlsQuicQpackEncoderPolicy` — plan/commit, static path identical to today

**Files:**
- Create: `SharpTls/src/SharpTls/Quic/TlsQuicQpackEncoderPolicy.cs` (policy + `TlsQuicQpackEncoderPlan` record + enum `TlsQuicQpackInsertPolicy`)
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Spec.cs` — add `QpackEncoderDynamicTableCapacity` (int, default 0, range 0..2^30-1, `ArgumentOutOfRangeException` otherwise), `QpackInsertPolicy` (default `Never`, `Enum.IsDefined` guard), `UnidirectionalStreamOpening` (default `AtConnectionStart`, guard) and enum `TlsQuicHttp3UnidirectionalStreamOpening` — put the two enums in `TlsQuicProtocol.cs` beside `TlsQuicQpackHuffmanPolicy`, **public**, so TlsClient can expose them without a mirror.
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicQpackEncoderPolicyTests.cs`

- [ ] **Step 1: Write the failing tests** (first batch — the static path and the gate):

```csharp
// helpers
private static List<(byte[] Name, byte[] Value)> Lines(params (string, string)[] pairs) =>
    pairs.Select(p => (Encoding.ASCII.GetBytes(p.Item1), Encoding.ASCII.GetBytes(p.Item2))).ToList();
private static TlsQuicQpackEncoderPolicy Spotify() => new(new TlsQuicHttp3Spec
{
    QpackEncoderDynamicTableCapacity = 4096, QpackInsertPolicy = TlsQuicQpackInsertPolicy.OnSecondUse,
});
// The capture's conn 61 stream 0 header list (reference doc s5/s6), credentials shortened.
private static List<(byte[], byte[])> Request0() => Lines(
    (":method","POST"), (":scheme","https"), (":authority","spclient.wg.spotify.com"),
    (":path","/remote-config-resolver/v3/unauth/configuration"), ("content-type","application/protobuf"),
    ("spotify-app-version","9.1.86.2428"), ("accept","application/protobuf"), ("time-zone","Europe/Athens"),
    ("app-platform","iOS"), ("priority","u=3, i"), ("accept-language","en-GB,en;q=0.9"),
    ("accept-encoding","gzip, deflate, br"), ("content-length","378"),
    ("user-agent","Spotify/9.1.86 iOS/27.0 (iPhone17,2)"), ("x-client-id","58bd3c95768941ea9eb4350aaa033eb3"),
    ("client-token","AAGxl8UElUaNDsgAvOJvyJ8k71PiW3qme"));
```

Tests:
  - `WithCapacityZeroEveryPlanIsTodaysStaticSection`: default spec policy; `Plan(Request0())` → `EncoderStreamBytes.IsEmpty`, `RequiredInsertCount == 0`, and `FieldSection` byte-equal to what `TlsQuicHttp3Request`'s existing static `EncodeFieldSection` produces for the same lines (call the existing private static through the request type: encode a `TlsQuicHttp3Request` with these fields via `TryEncode(List<byte>, spec, out _)` and compare the HEADERS payload using the `ReadFrames` helper pattern from `TlsQuicHttp3RequestTests`).
  - `NothingIsDynamicBeforeThePeersSettingsArrive`: Spotify policy; plan/commit two requests → both RIC 0, no encoder bytes, `CapacitySent == false`.
  - `OnPeerSettingsEmitsCapacityBoundedByThePeer`: `OnPeerSettings(4096, 16)` → bytes `3FE11F`; `OnPeerSettings(1000, 16)` → `Set Capacity 1000` (`3F C9 07`: 31 + 969; 969 = 0x3C9 → `C9 07`); `OnPeerSettings(0, 16)` → empty and `CapacitySent` stays false.
  - `TheFirstRequestAfterCapacityIsStillStaticAndTheSecondInserts`: replay conn 61: commit stream 0 (static, before settings); `OnPeerSettings(4096,16)`; plan+commit stream 4 → RIC 0, empty encoder bytes; plan stream 8 (same list as stream 0 with `content-length: 380`) → `EncoderStreamBytes` starts `C0914564A0C5A92BF8997456749A5F4B90F4FF` and contains 9 inserts (`:authority`, `spotify-app-version`, `time-zone`, `app-platform`, `priority`, `accept-language`, `user-agent`, `x-client-id`, `client-token`) in that order; `RequiredInsertCount == 9`; prefix bytes `0A88`; the `:authority` line is `10` (post-base 0); `content-length` is a literal with static name reference; `:path` (first time seen at this value) literal.
  - `APairSeenOnceIsNeverInserted`: after the above, a request with a fresh `:path` → no insert of it.
  - `AnUncommittedPlanChangesNothing`: plan a request twice without committing; both plans byte-identical; commit the second; a third plan differs (uses the table).
  - `BaseAndRelativeIndicesAfterInserts`: commit the stream-8 plan; plan a GET reusing the nine pairs → prefix `0A00` (RIC 9, Base 9), `:authority` line `88` (relative 8 = Base − 0 − 1), `client-token` line `80` (relative 0).
  - `TheWrapUsesThePeersMaxEntries`: `OnPeerSettings(16383, 100)`, then insert 300 distinct pairs (commit each with a second use so they insert); decode every prefix with `TlsQuicQpackDecoder`'s Required Insert Count reconstruction against a decoder table built with capacity 16383 (`new TlsQuicQpackDynamicTable(16383)` fed our encoder bytes via `TryReadEncoderInstructions`) and assert `TryDecodeFieldSectionAgainstTable` succeeds for each section. This is the test the spec's §2.9 exists for.
  - `AnExhaustedBlockedStreamBudgetKeepsTheSectionKnownReceivedOnly`: `OnPeerSettings(4096, 1)`; get one stream blocked (commit an inserting plan on stream 8, no acks); next plan → `EncoderStreamBytes.IsEmpty`, RIC 0, every line literal/static; after `TryAcknowledgeSection(8)` the next plan references normally.
  - `EvictionRefusalTurnsTheInsertIntoALiteral`: capacity 100 (`OnPeerSettings(100, 16)` with spec capacity 100); fill with referenced entries; a new second-use pair plans as literal with no encoder bytes.

- [ ] **Step 2: Run, expect compile failure.**

- [ ] **Step 3: Implement the policy.** Core of `Plan`:

```csharp
internal TlsQuicQpackEncoderPlan Plan(List<(byte[] Name, byte[] Value)> lines)
{
    var seen = new List<(byte[], byte[])>();
    var classified = new Classified[lines.Count];            // Kind: StaticExact | Dynamic(abs) | Insert(k) | StaticName(idx) | Literal
    // pass 1: classify, count, decide inserts
    bool inserting = _table is not null && CapacitySent && _requestsSinceCapacity >= 1 && _spec.QpackInsertPolicy == TlsQuicQpackInsertPolicy.OnSecondUse;
    ulong protectBelow = ulong.MaxValue; var inserts = new List<(byte[], byte[])>(); int plannedBytes = 0;
    for i in lines:
        if (TlsQuicQpackStaticTable.TryFindNameAndValue(name, value, out int idx)) { classified[i] = StaticExact(idx); continue; }
        seen.Add(line);
        if (_table is not null && _table.TryFind(name, value, out ulong abs)) { classified[i] = Dynamic(abs); protectBelow = Math.Min(protectBelow, abs); continue; }
        classified[i] = StaticNameOrLiteral(name);            // decided by the existing TryEncodeFieldLine rules
    if (inserting)
        for i in lines where classified is StaticNameOrLiteral and Uses(line) >= 1 and not already planned:
            int size = 32 + name.Length + value.Length;
            if (size <= _table.Capacity - _table.Size + _table.EvictableBytes(protectBelow) - plannedBytes) { inserts.Add(line); plannedBytes += size; classified[i] = Insert(inserts.Count - 1); }
    // blocked-streams budget, once
    ulong krc = _table?.KnownReceivedCount ?? 0;
    bool wouldBlock = inserts.Count > 0 || classified.Any(c => c is Dynamic d && d.Abs >= krc);
    if (wouldBlock && _table!.BlockedStreamCount >= (int)Math.Min(_peerBlockedStreams, int.MaxValue))
    {   // drop inserts, downgrade refs above krc to their literal form
        foreach c in classified: if Insert -> StaticNameOrLiteral; if Dynamic && Abs >= krc -> StaticNameOrLiteral
        inserts.Clear();
    }
    // prefix numbers
    ulong @base = _table?.InsertCount ?? 0;
    ulong ric = 0; var referenced = new List<ulong>();
    foreach c: Dynamic(abs) -> referenced.Add(abs), ric = max(ric, abs + 1); Insert(k) -> referenced.Add(@base + k), ric = max(ric, @base + k + 1);
    // bytes: encoder stream (inserts in order), then section (prefix + lines); grow buffers on false
    ...
    return new TlsQuicQpackEncoderPlan(encoderBytes, section, ric, inserts, referenced, seen);
}

internal void Commit(TlsQuicQpackEncoderPlan plan, ulong streamId)
{
    foreach seen in plan.Seen: _uses[Key(seen)]++;
    foreach insert in plan.Inserts: _table!.Insert(...);
    _table?.RecordSection(streamId, plan.RequiredInsertCount, plan.ReferencedAbsoluteIndices);
    if (CapacitySent) _requestsSinceCapacity++;
}
```

`Uses(line)` reads `_uses` — a `Dictionary<string,int>` keyed by `Encoding.Latin1.GetString(name) + "\0" + Encoding.Latin1.GetString(value)`. Insert candidates must also not duplicate a pair already planned for insert in this request (a header repeated twice in one request inserts once, references twice — second occurrence is post-base to the same k).

Section line emission per classification: `StaticExact` → `TryEncodeFieldLine` (it takes the s4.5.2 branch); `Dynamic(abs)` → `TryEncodeIndexedDynamic(@base - abs - 1)`; `Insert(k)` → `TryEncodeIndexedPostBase(k)`; `StaticNameOrLiteral` → `TryEncodeFieldLine` with the spec's Huffman and name-match policies (exactly today's path). Prefix: `TryEncodeFieldSectionPrefix(ric, @base, _table.MaxEntries)` when a table exists, else the zero-argument overload. Buffers: start at 256 bytes, double while any writer returns false (mirror `TlsQuicHttp3Request.EncodeFieldSection`'s doubling loop).

`OnPeerSettings(peerMax, peerBlocked)`: `int cap = (int)Math.Min((ulong)_spec.QpackEncoderDynamicTableCapacity, peerMax)`; if `cap == 0` return empty; `_table = new(cap, peerMax)`; `_peerBlockedStreams = peerBlocked`; `CapacitySent = true`; `_requestsSinceCapacity = 0`; return capacity bytes. Second call (peer sends SETTINGS once; guard anyway) → empty.

- [ ] **Step 4: Run the tests, expect PASS.** Also `FullyQualifiedName~TlsQuicHttp3SpecTests` for the new knob guards — add three theory rows there: capacity −1 and 2^30 throw `ArgumentOutOfRangeException`; undefined enum values throw.

## Chunk 2: streams, connection, request wiring

### Task 4: `TlsQuicHttp3Request` plans through the policy

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Request.cs` (`TryEncode` ~582, `EncodeFieldSection`/`TryEncodeFieldSection` ~1015-1060)
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3RequestTests.cs`

- [ ] **Step 1: Failing test** `WithAPolicyTheHeaderSectionIsThePlansAndTheTrailerSectionStaysStatic`: build a request with headers and one trailer; a Spotify policy that has capacity and one committed prior request; call the new overload `TryEncode(destination, spec, policy, out plan, out error)`; assert the first HEADERS payload equals `plan!.FieldSection` and the trailing HEADERS payload starts `00 00`. Also `WithoutAPolicyTheBytesAreUnchanged`: both overloads agree byte for byte when `policy` is null.

- [ ] **Step 2: Run, expect compile failure.**

- [ ] **Step 3: Implement.** Add `internal bool TryEncode(List<byte> destination, TlsQuicHttp3Spec spec, TlsQuicQpackEncoderPolicy? policy, out TlsQuicQpackEncoderPlan? plan, out TlsQuicHttp3RequestError error)`; the existing three-argument `TryEncode` calls it with `null`. Inside, after validation: `if (policy is null) { (buffer, length) = EncodeFieldSection(spec, lines); } else { plan = policy.Plan(lines); write plan.FieldSection }`. Trailer section keeps `EncodeFieldSection` (static). Update the remarks: the policy applies to the header section only; trailers are not in the capture.

- [ ] **Step 4: Run `FullyQualifiedName~TlsQuicHttp3RequestTests`, expect PASS.**

### Task 5: `TlsQuicHttp3Streams` — encoder stream, lazy opening, peer decoder stream

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Streams.cs`
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3StreamsTests.cs` (append)

- [ ] **Step 1: Failing tests** (use the file's existing `Set()` / `HarnessSpec()` helpers and `set.TakePendingFrames()`; look at how existing tests feed peer bytes — the tests around `TryReadEncoderStream` deliver a peer unidirectional stream through the set's receive path; copy that pattern):
  - `LazyOpeningSendsOnlyTheControlStreamAtStart`: spec `UnidirectionalStreamOpening = Lazy` → `OpenLocalStreams()` yields one frame, type byte `00`; `LocalEncoderStream` and `LocalDecoderStream` null.
  - `TheEncoderStreamOpensWithItsFirstInstruction`: lazy; `SendEncoderInstructions(new byte[]{0x3F,0xE1,0x1F})` → one new frame whose data is `02 3F E1 1F` (type byte and instruction in one send, like the phone's `023fe11f`).
  - `TheDecoderStreamOpensWithItsFirstInstruction`: lazy; deliver a peer encoder stream that inserts one entry (existing tests have such bytes) so `SendInsertCountIncrement` fires → frame `03 01`.
  - `AtConnectionStartStillOpensAllThreeUpFront`: the existing `TheThreeStreamsAreOpenedInTheSpecsOrder` keeps passing; add `EncoderStream` type byte assertion: with `AtConnectionStart` the encoder stream frame is exactly `02` and a later `SendEncoderInstructions` sends the instruction bytes alone.
  - `ThePeersDecoderStreamDrivesTheEncoderPolicy`: streams with Spotify spec; policy has capacity and a recorded section on stream 4 with RIC 2; deliver a peer uni stream `03 84` (type 3, Section Ack stream 4) → `EncoderPolicy.Table.KnownReceivedCount == 2`. Deliver `03 00` (Insert Count Increment 0) on a fresh streams object → `TryProcessPeerStreams` returns false with error `0x0202`. Deliver `03 44` (Stream Cancellation stream 4) with nothing recorded → still true.
  - `PeerSettingsTriggerTheCapacityInstruction`: Spotify spec, lazy; deliver a peer control stream carrying SETTINGS `01=4096, 07=16` (existing tests build control-stream bytes; reuse) → pending frames include `02 3F E1 1F`.

- [ ] **Step 2: Run, expect failures.**

- [ ] **Step 3: Implement:**
  - Field `internal TlsQuicQpackEncoderPolicy EncoderPolicy { get; }` constructed in the ctor from `spec`.
  - `internal TlsQuicStream? LocalEncoderStream { get; private set; }`.
  - `OpenLocalStreams()`: if `_spec.UnidirectionalStreamOpening == Lazy`, open only `Control` (with SETTINGS), record it, set `_opened = true`; else today's loop, but also assign `LocalEncoderStream` for `QpackEncoder`.
  - `private TlsQuicStream EnsureEncoderStream(ReadOnlySpan<byte> firstInstruction)` / `EnsureDecoderStream(...)`: open, send `[type varint] + first bytes` in one send, assign. `EnsureDecoderStream` first calls `EnsureEncoderStream(empty)` if the encoder stream is closed, so ids stay control 2 / encoder 6 / decoder 10. `SendEncoderInstructions(ReadOnlyMemory<byte> bytes)`: if `bytes.IsEmpty` return; if `LocalEncoderStream is null` → `EnsureEncoderStream(bytes)`, else `_streams.Send(LocalEncoderStream, bytes)`. `Emit` (decoder instructions): replace the null-throw with lazy opening when the spec is `Lazy` and the open order contains `QpackDecoder`; keep the throw when the open order omits it.
  - Peer SETTINGS acceptance (~line 815): after `PeerSettingsReceived = true`, call `var capacity = EncoderPolicy.OnPeerSettings(TlsQuicHttp3Settings.Value(settings, QpackMaxTableCapacityIdentifier) ?? 0, TlsQuicHttp3Settings.Value(settings, QpackBlockedStreamsIdentifier) ?? 0); SendEncoderInstructions(capacity);`.
  - `TryTakeStreamType`: add `else if (streamType == QpackDecoder) { /* keep bytes */ }` before the ignore arm; update the comment that said the decoder stream is discarded.
  - `TryReadPeerStream`: branch for `QpackDecoder` → `TryReadPeerDecoderStream(state, out error)`: loop over `state.Unparsed`; first byte `b`: `b & 0x80` → Section Ack, `TlsQuicQpackPrimitives.TryDecodeInteger(span, 7, ...)`; `b & 0x40` → Stream Cancellation, 6-bit; else Insert Count Increment, 6-bit. Incomplete integer → stop, keep bytes (bound leftover at `TlsQuicQpackPrimitives.MaximumIntegerEncodedLength`, else `QPACK_DECODER_STREAM_ERROR`). Dispatch to `EncoderPolicy.TryAcknowledgeSection / TryCancelStream / TryIncrementKnownReceived`; a false from ack or increment → `error = 0x0202; return false`. Define `internal const ulong QpackDecoderStreamError = 0x0202` on `TlsQuicQpackEncoderTable` (mirror of `TlsQuicQpackDynamicTable.QpackEncoderStreamError`).
  - `IsCriticalStreamType` already lists the decoder stream; nothing to change.

- [ ] **Step 4: Run `FullyQualifiedName~TlsQuicHttp3StreamsTests`, expect PASS.**

### Task 6: `TlsQuicHttp3Connection.TryOpenRequest` — plan, refuse, commit, send

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Connection.cs` (~593-690)
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ConnectionTests.cs` (append, using the file's `Harness`)

- [ ] **Step 1: Failing tests:**
  - `ARefusedRequestCommitsNothingToTheEncoderTable`: harness with Spotify spec and a peer whose `initial_max_streams_bidi` is exhausted after one request; second request refused → `Streams.EncoderPolicy` use counts unchanged (expose `internal int UseCount(name, value)` on the policy for tests) and no encoder-stream frame pending.
  - `TheSecondUseRequestSendsInsertsBeforeItsHeaders`: harness against `LoopbackQuicPeer` with Spotify spec: send request A, pump until the peer's SETTINGS are read, send A again (static), send A a third time → `LoopbackQuicPeer.ReceivedStreamFrames` contains, in order, a frame on the encoder stream (id 6 under lazy: control 2, then encoder 6) whose data starts `02 3F E1 1F` (or the instruction bytes if already open) and then the request stream's HEADERS whose payload prefix is not `00 00`.
  - `ThePeersSectionAcknowledgmentReleasesTheReferences`: continue: the loopback peer answers a Section Ack on its decoder stream (extend `LoopbackQuicPeer` with a helper to write `03 8x`, or drive the bytes through the peer's uni stream the way existing tests inject peer encoder instructions) → `BlockedStreamCount` drops to 0.

- [ ] **Step 2: Run, expect failures.**

- [ ] **Step 3: Implement.** In `TryOpenRequest`: `var frame = new List<byte>(); if (!request.TryEncode(frame, _spec, _streams.EncoderPolicy, out var plan, out malformed)) {...}` — keep every refusal check as is (they measure `frame`) — after `OpenBidirectional()`: `if (plan is not null) { _streams.EncoderPolicy.Commit(plan, stream.Id); _streams.SendEncoderInstructions(plan.EncoderStreamBytes); }` then the existing `Send(stream, frame, fin: true)`. Update the remarks paragraph "THE ORDER IS DELIBERATE" to add the commit rule from the spec §3.5.

- [ ] **Step 4: Run `FullyQualifiedName~TlsQuicHttp3ConnectionTests`, then the whole `FullyQualifiedName~Quic` filter; expect PASS and no change elsewhere.**

### Task 7: MsQuic loopback interop

**Files:**
- Modify: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3MsQuicLoopbackTests.cs` (append)

- [ ] **Step 1: Test** `ThreeRequestsOnOneConnectionAreDecodedBySystemNetQuicWithTheDynamicTableInUse`: Spotify spec (capacity 4096, OnSecondUse, Lazy); three identical GETs on one connection against the `System.Net.Quic` server the file already hosts; all three answered 200; the third request's HEADERS payload (read from the client's own sent frames as the file's existing tests do) has a non-zero first prefix octet. Skip-gate exactly like the file's other tests (MsQuic availability).
- [ ] **Step 2: Run** `FullyQualifiedName~TlsQuicHttp3MsQuicLoopbackTests`. The pre-existing `AFullRequestAndResponseCompleteAgainstSystemNetQuic` fails on this machine today (StreamLimitError) — note whether the new test passes or fails for the same environmental reason and report; do not chase the old failure.

## Chunk 3: TlsClient knobs, preset, docs, live check

### Task 8: `TlsHttp3Options` knobs and PublicAPI

**Files:**
- Modify: `TlsClient-main/src/TlsClient/TlsHttp3Options.cs`, `TlsClient-main/src/TlsClient/PublicAPI.Unshipped.txt`
- Test: `TlsClient-main/tests/TlsClient.Tests/TlsHttp3OptionsTests.cs` (exists? if not, add the three assertions to `TlsPresetTests.cs`)

- [ ] **Step 1: Failing test** `TheThreeQpackEncoderKnobsRoundTripIntoTheSpec`: set capacity 4096, `OnSecondUse`, `Lazy` on a `TlsHttp3Options`; `Snapshot()` → the spec's three properties equal (spec properties are internal; the test project has `InternalsVisibleTo` for SharpTls? check `SharpTls.csproj`; if not, assert through behaviour: build a `TlsQuicHttp3Streams` from the snapshot and check `OpenLocalStreams` sends one frame).
- [ ] **Step 2: Run, expect compile failure.**
- [ ] **Step 3: Implement:** three properties defaulting from `SpecDefaults`, mapped in `Snapshot()`; PublicAPI lines:
```
TlsClient.TlsHttp3Options.QpackEncoderDynamicTableCapacity.get -> int
TlsClient.TlsHttp3Options.QpackEncoderDynamicTableCapacity.set -> void
TlsClient.TlsHttp3Options.QpackInsertPolicy.get -> SharpTls.Quic.TlsQuicQpackInsertPolicy
TlsClient.TlsHttp3Options.QpackInsertPolicy.set -> void
TlsClient.TlsHttp3Options.UnidirectionalStreamOpening.get -> SharpTls.Quic.TlsQuicHttp3UnidirectionalStreamOpening
TlsClient.TlsHttp3Options.UnidirectionalStreamOpening.set -> void
```
- [ ] **Step 4: Run** `dotnet build TlsClient-main/src/TlsClient` then the test.

### Task 9: Preset

**Files:**
- Modify: `TlsClient-main/src/TlsClient/TlsPreset.cs` (`ConfigureSpotifyIosQuic`, after the `PseudoHeaderOrder` block)
- Test: `TlsClient-main/tests/TlsClient.Tests/TlsPresetTests.cs`

- [ ] **Step 1: Failing test** `TheSpotifyPresetTurnsOnTheMeasuredQpackEncoder`: `TlsPresets.Spotify.CreateOptions().Http3` → capacity 4096, `OnSecondUse`, `Lazy`; `Spotify917602050IOS260Http3` identical (shared method).
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** with a comment block in the file's voice citing the reference doc §6: capacity equal to the server's maximum in every capture; the second-use gate; lazy streams. Replace the "QPACK encoding choices ... left at their defaults" sentence in the method summary.
- [ ] **Step 4: Run** `FullyQualifiedName~TlsPresetTests|FullyQualifiedName~SpotifyHttp2PresetTests`, expect PASS.

### Task 10: Docs

**Files:**
- Modify: `TlsClient-main/docs/PRESETS.md` — move the "Measured, and NOT reproduced" QPACK bullet into "Measured since, and now in the preset", describing the gate, capacity and lazy streams; keep the sentence that no fingerprint endpoint sees it.
- Modify: `SharpTls/docs/superpowers/specs/reference-captures/2026-09-26-spotify-9.1.86-ios27-pcapng.md` — §6 last paragraph: "SharpTls's encoder is static-only …" → now reproduced by the preset; what remains unmeasured (peer max above 4096, draining).
- Modify: `SharpTls/docs/FINGERPRINT-KNOBS.md` — add three rows to the HTTP/3 knob table for the new spec properties, default and preset value, source column "2026-09-26 capture §6".
- Modify: `TlsClient-main/docs/USAGE.md` §3a — one paragraph naming the three `options.Http3` knobs.

- [ ] **Step 1: Make the edits.** No test; re-read each changed paragraph once.

### Task 11: Full verification

- [ ] **Step 1:** `dotnet test SharpTls/tests/SharpTls.Tests` — expect only the three pre-existing environmental failures (platform SslStream chain, MsQuic loopback StreamLimitError, UntrustedRootIsRejected) plus whatever Task 7 reported.
- [ ] **Step 2:** `dotnet test TlsClient-main/tests/TlsClient.Tests` — expect only the pre-existing multiplexer failure.
- [ ] **Step 3:** `TLSCLIENT_LIVE_TESTS=1 dotnet test TlsClient-main/tests/TlsClient.Tests --filter "FullyQualifiedName~SpotifyPresetLiveParityTests|FullyQualifiedName~Http3LiveTests" --logger "console;verbosity=normal"` — both parity tests pass with real durations; `fp.impersonate.pro` still answers 200 to a preset whose second request on a pooled connection uses the dynamic table (add a second `SendAsync` on the same session inside the h3 parity test and assert 200; the server's decoding of a dynamic section is the interop proof).
- [ ] **Step 4:** `dotnet run --project TlsClient-main/tools/TlsClient.ProfileCatalog > TlsClient-main/docs/PROFILE-MANIFEST.md` (unchanged expected; confirms build).
- [ ] **Step 5:** Report: what passed, what is environmental, and whether the encoder-stream bytes landed in their own packet on the loopback capture (Task 6's frame order) — the spec leaves coalescing as a recorded difference.
