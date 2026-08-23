# HTTP/2 Byte-Level Wire Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reusable test harness that records the exact decrypted client-to-server HTTP/2 byte stream from a real loopback connection, and pin the three built-in presets' connection prefaces as byte-level golden fixtures.

**Architecture:** A `Stream` decorator tees every byte the loopback server reads into a buffer. A reusable capture harness runs a real `TlsSession` against a scripted `CustomTlsServer` over TCP loopback, returning both the raw byte stream and a parsed frame list. Assertion helpers render mismatches as offset-annotated hex dumps. Existing tests are then refactored onto the harness without losing their current coverage.

**Tech Stack:** .NET 9, xUnit 2.9.3, SharpTls 0.9.0-preview.5, `System.Net.Sockets.TcpListener`, TlsClient internals via `InternalsVisibleTo`.

**Spec:** `docs/superpowers/specs/2026-08-14-http2-wire-fidelity-design.md`

## Why this plan exists before any encoder change

The spec's preset-migration section requires byte-identical output after a large refactor. The only existing wire test, `TlsPresetWireTests.Preset_EmitsCapturedHttp2Fingerprint`, asserts a derived Akamai fingerprint *string* — `"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"`. That string pins neither frame ordering, nor frame flags, nor HPACK representation choices, nor whether a zero-length SETTINGS frame was sent. Every axis the spec makes configurable is invisible to it. Until byte-level assertions exist, "byte-identical migration" is an unfalsifiable claim.

This plan builds nothing in `src/`. It is pure test infrastructure, and it must land first.

## Design principles

These outrank every other consideration in this plan and the two that follow. When a
choice trades one against something else, these win.

1. **Fidelity of reproduction.** The harness must be able to prove byte equality, not
   approximate equality. A helper that makes a test read nicely but hides a byte is worse
   than no helper.
2. **Ease of use from a manual capture.** The primary workflow is a human reading a
   Wireshark dump or a `tls.peet.ws/api/all` response and turning it into a persona.
   Every type here must be constructible from a pasted hex stream or a decoded frame
   listing, without a live connection.
3. **Flexibility.** No helper may assume the three built-in presets. Anything that works
   for Chrome must work for an arbitrary observed client, including one that sends frames
   the built-ins never send.

## Global Constraints

- **Do not modify anything under `src/`,** except `global.json` in Task 0. This plan is
  test infrastructure. If a test cannot be written without a production change, stop and
  report it rather than editing `src/`.
- **SDK:** installed SDKs are 6.0.420, 8.0.302, 8.0.413, 9.0.101, 9.0.314,
  10.0.100-rc.1, 10.0.302, and 10.0.400. `global.json` pins `9.0.200` with
  `"rollForward": "disable"`, which matches none of them, so `dotnet` fails from the
  repository root with `A compatible .NET SDK was not found`. Task 0 fixes this. Until
  Task 0 is committed, run `dotnet` from a directory outside the repository with an
  absolute project path.
- Target framework is `net9.0`. Nullable reference types and `TreatWarningsAsErrors` are on — a warning fails the build.
- Test assembly is `TlsClient.Tests`, which has `InternalsVisibleTo` access to TlsClient internals (`src/TlsClient/Properties/AssemblyInfo.cs:16`). `Http2FrameType`, `Http2FrameFlags`, `Http2ErrorCode`, `HpackDecoder`, `HpackHeader`, and `TlsHttp2Setting` are all internal and directly usable from tests.
- Loopback TLS uses `TlsSessionLoopbackTests.TestCertificates.Create()`, a nested helper in the existing test file. Reuse it; do not create a second PKI helper.
- Every test uses a 15-second `CancellationTokenSource` timeout, matching the existing pattern. A hung loopback test must fail, not block the suite.
- Commit after every task using the message given in that task's final step.

---

## File Structure

| File | Responsibility |
|---|---|
| `tests/TlsClient.Tests/Wire/RecordingStream.cs` (create) | `Stream` decorator that tees bytes into a buffer as they are read and written |
| `tests/TlsClient.Tests/Wire/Http2WireServer.cs` (create) | Scriptable server-side frame reader/writer over the recorded stream |
| `tests/TlsClient.Tests/Wire/Http2WireCapture.cs` (create) | Runs a real session against a scripted server; returns raw bytes plus parsed frames |
| `tests/TlsClient.Tests/Wire/Http2WireAssert.cs` (create) | Byte-equality assertions with offset-annotated hex dump output |
| `tests/TlsClient.Tests/Http2WireGoldenTests.cs` (create) | Golden preface byte fixtures for the three presets |
| `tests/TlsClient.Tests/TlsPresetWireTests.cs` (modify) | Refactored onto the shared harness, keeping its fingerprint assertion |

Files live under a `Wire/` subdirectory because they are shared infrastructure rather than tests. The existing test project has no subdirectories; this is the first, and it is justified because four files serve one purpose and would otherwise clutter a flat directory of test classes.

---

### Task 0: Unblock the SDK pin

Every later task runs `dotnet`. Fixing the pin once removes the working-directory dance
from all of them.

**Files:**
- Modify: `global.json`

**Interfaces:**
- Consumes: nothing. Produces: nothing.

- [ ] **Step 1: Confirm the failure**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet --version
```

Expected: `A compatible .NET SDK was not found. Requested SDK version: 9.0.200`.

- [ ] **Step 2: Relax the pin**

Replace the contents of `global.json` with:

```json
{
  "sdk": {
    "version": "9.0.101",
    "rollForward": "latestMajor",
    "allowPrerelease": false
  }
}
```

`9.0.101` is installed, and `latestMajor` lets the newest stable SDK (10.0.400) build the
`net9.0` target. `allowPrerelease` stays `false` so the 10.0.100-rc.1 SDK is never chosen.

- [ ] **Step 3: Verify from the repository root**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet --version && dotnet test TlsClient.slnx -c Release
```

Expected: a version prints, and the full suite passes. Record the pass count — every
later task must not regress it.

- [ ] **Step 4: Commit**

```bash
git add global.json
git commit -m "build: allow roll-forward so an installed SDK can build the repo"
```

From here on, run `dotnet` from the repository root. The `cd /tmp` prefix in later tasks
is no longer required; use it only if Task 0 was skipped.

---

### Task 1: RecordingStream

A `Stream` decorator that forwards every operation to an inner stream while appending the bytes to separate read and write buffers. The loopback server wraps its TLS application stream in one of these, so `ReadBytes` ends up holding exactly what the client sent.

**Files:**
- Create: `tests/TlsClient.Tests/Wire/RecordingStream.cs`
- Test: `tests/TlsClient.Tests/Wire/RecordingStreamTests.cs`

**Interfaces:**
- Consumes: nothing.
- Produces: `sealed class RecordingStream : Stream`, constructor `RecordingStream(Stream inner, bool leaveOpen = true)`, properties `byte[] ReadBytes { get; }` and `byte[] WrittenBytes { get; }`.

- [ ] **Step 1: Write the failing test**

Create `tests/TlsClient.Tests/Wire/RecordingStreamTests.cs`:

```csharp
namespace TlsClient.Tests.Wire;

public sealed class RecordingStreamTests
{
    [Fact]
    public async Task RecordsBytesReadAcrossMultipleCalls()
    {
        var source = new MemoryStream([1, 2, 3, 4, 5, 6]);
        await using var recording = new RecordingStream(source);

        var first = new byte[2];
        var second = new byte[4];
        await recording.ReadExactlyAsync(first);
        await recording.ReadExactlyAsync(second);

        Assert.Equal(new byte[] { 1, 2 }, first);
        Assert.Equal(new byte[] { 3, 4, 5, 6 }, second);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6 }, recording.ReadBytes);
        Assert.Empty(recording.WrittenBytes);
    }

    [Fact]
    public async Task RecordsBytesWrittenSeparatelyFromBytesRead()
    {
        var inner = new MemoryStream();
        await using var recording = new RecordingStream(inner);

        await recording.WriteAsync(new byte[] { 9, 8 });
        await recording.WriteAsync(new byte[] { 7 });

        Assert.Equal(new byte[] { 9, 8, 7 }, recording.WrittenBytes);
        Assert.Empty(recording.ReadBytes);
        Assert.Equal(new byte[] { 9, 8, 7 }, inner.ToArray());
    }

    [Fact]
    public async Task LeaveOpenFalseDisposesInnerStream()
    {
        var inner = new MemoryStream();
        var recording = new RecordingStream(inner, leaveOpen: false);

        await recording.DisposeAsync();

        Assert.Throws<ObjectDisposedException>(() => inner.Position);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run from a directory outside the repository:

```bash
cd /tmp && dotnet test "c:/Users/mario/OneDrive/Desktop/TlsClient-main/tests/TlsClient.Tests/TlsClient.Tests.csproj" -c Release --filter "FullyQualifiedName~RecordingStreamTests"
```

Expected: build failure, `The type or namespace name 'RecordingStream' could not be found`.

- [ ] **Step 3: Write the implementation**

Create `tests/TlsClient.Tests/Wire/RecordingStream.cs`:

```csharp
namespace TlsClient.Tests.Wire;

/// <summary>
/// Forwards every operation to an inner stream while recording the bytes that pass
/// through in each direction. Used to capture the exact decrypted HTTP/2 byte stream
/// a client sent.
/// </summary>
internal sealed class RecordingStream : Stream
{
    private readonly Stream _inner;
    private readonly bool _leaveOpen;
    private readonly MemoryStream _read = new();
    private readonly MemoryStream _written = new();
    private readonly Lock _sync = new();

    public RecordingStream(Stream inner, bool leaveOpen = true)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;
        _leaveOpen = leaveOpen;
    }

    public byte[] ReadBytes
    {
        get
        {
            lock (_sync)
            {
                return _read.ToArray();
            }
        }
    }

    public byte[] WrittenBytes
    {
        get
        {
            lock (_sync)
            {
                return _written.ToArray();
            }
        }
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        var read = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (read > 0)
        {
            lock (_sync)
            {
                _read.Write(buffer.Span[..read]);
            }
        }
        return read;
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        // Record only after the write is confirmed, mirroring ReadAsync. Recording
        // first would let a cancelled or failed write leave bytes in WrittenBytes that
        // never reached the wire, which breaks the byte-equality guarantee the whole
        // harness exists to provide.
        await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        lock (_sync)
        {
            _written.Write(buffer.Span);
        }
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) =>
        _inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_leaveOpen)
        {
            _inner.Dispose();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (!_leaveOpen)
        {
            await _inner.DisposeAsync().ConfigureAwait(false);
        }
        await base.DisposeAsync().ConfigureAwait(false);
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /tmp && dotnet test "c:/Users/mario/OneDrive/Desktop/TlsClient-main/tests/TlsClient.Tests/TlsClient.Tests.csproj" -c Release --filter "FullyQualifiedName~RecordingStreamTests"
```

Expected: `Passed! - Failed: 0, Passed: 3`.

- [ ] **Step 5: Commit**

```bash
git add tests/TlsClient.Tests/Wire/RecordingStream.cs tests/TlsClient.Tests/Wire/RecordingStreamTests.cs
git commit -m "test: add RecordingStream for byte-level wire capture"
```

---

### Task 2: Http2WireServer

The frame-level server primitives, extracted from the private helpers currently inlined in `TlsPresetWireTests.cs:239-289` so that every future wire test shares one implementation.

**Files:**
- Create: `tests/TlsClient.Tests/Wire/Http2WireServer.cs`
- Test: covered indirectly by Task 3's harness test; no standalone test file, because every method is a thin framing primitive whose behavior is only meaningful against a real connection.

**Interfaces:**
- Consumes: `RecordingStream` from Task 1.
- Produces:
  - `readonly record struct CapturedFrame(Http2FrameType Type, byte Flags, int StreamId, byte[] Payload)`
  - `sealed class Http2WireServer` with `Task<byte[]> ReadPrefaceAsync(CancellationToken)`, `Task<CapturedFrame> ReadFrameAsync(CancellationToken)`, `Task<CapturedFrame> ReadUntilAsync(Http2FrameType, CancellationToken)`, `Task WriteFrameAsync(Http2FrameType, byte, int, byte[], CancellationToken)`, `Task FlushAsync(CancellationToken)`, and `IReadOnlyList<CapturedFrame> ClientFrames { get; }`.

- [ ] **Step 1: Write the implementation**

This task has no standalone test — it is exercised end to end by Task 3, whose test fails until this compiles and behaves. Create `tests/TlsClient.Tests/Wire/Http2WireServer.cs`:

```csharp
using System.Buffers.Binary;

namespace TlsClient.Tests.Wire;

internal readonly record struct CapturedFrame(
    Http2FrameType Type,
    byte Flags,
    int StreamId,
    byte[] Payload);

/// <summary>
/// Server-side HTTP/2 framing primitives for loopback wire tests. Every frame read from
/// the client is retained in <see cref="ClientFrames"/> in arrival order.
/// </summary>
internal sealed class Http2WireServer(Stream stream)
{
    private readonly List<CapturedFrame> _clientFrames = [];

    public IReadOnlyList<CapturedFrame> ClientFrames => _clientFrames;

    public async Task<byte[]> ReadPrefaceAsync(CancellationToken cancellationToken)
    {
        var preface = new byte[24];
        await stream.ReadExactlyAsync(preface, cancellationToken).ConfigureAwait(false);
        return preface;
    }

    public async Task<CapturedFrame> ReadFrameAsync(CancellationToken cancellationToken)
    {
        var header = new byte[9];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        var length = header[0] << 16 | header[1] << 8 | header[2];
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        var frame = new CapturedFrame(
            (Http2FrameType)header[3],
            header[4],
            BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(5)) & 0x7fff_ffff,
            payload);
        _clientFrames.Add(frame);
        return frame;
    }

    /// <summary>Reads frames until one of <paramref name="type"/> arrives and returns it.</summary>
    public async Task<CapturedFrame> ReadUntilAsync(
        Http2FrameType type,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
            if (frame.Type == type)
            {
                return frame;
            }
        }
    }

    public async Task WriteFrameAsync(
        Http2FrameType type,
        byte flags,
        int streamId,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        header[0] = (byte)(payload.Length >> 16);
        header[1] = (byte)(payload.Length >> 8);
        header[2] = (byte)payload.Length;
        header[3] = (byte)type;
        header[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(5), streamId);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    public Task FlushAsync(CancellationToken cancellationToken) =>
        stream.FlushAsync(cancellationToken);
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd /tmp && dotnet build "c:/Users/mario/OneDrive/Desktop/TlsClient-main/tests/TlsClient.Tests/TlsClient.Tests.csproj" -c Release
```

Expected: `Build succeeded. 0 Error(s)`. Warnings from SourceLink about a missing remote are pre-existing and expected.

- [ ] **Step 3: Commit**

```bash
git add tests/TlsClient.Tests/Wire/Http2WireServer.cs
git commit -m "test: extract HTTP/2 server framing primitives for wire tests"
```

---

### Task 3: Http2WireCapture harness

Runs a real `TlsSession` against a scripted loopback server and returns the exact bytes the client sent.

**Files:**
- Create: `tests/TlsClient.Tests/Wire/Http2WireCapture.cs`
- Test: `tests/TlsClient.Tests/Wire/Http2WireCaptureTests.cs`

**Interfaces:**
- Consumes: `RecordingStream` (Task 1), `Http2WireServer` and `CapturedFrame` (Task 2), `TlsSessionLoopbackTests.TestCertificates`.
- Produces:
  - `sealed record Http2WireResult(byte[] ClientBytes, IReadOnlyList<CapturedFrame> ClientFrames, TlsResponse Response)`
  - `delegate Task Http2ServerScript(Http2WireServer server, CancellationToken cancellationToken)`
  - `static Task<Http2WireResult> Http2WireCapture.RunAsync(TlsSessionOptions options, Func<TlsSession, string, CancellationToken, Task<TlsResponse>> request, Http2ServerScript? script = null, CancellationToken cancellationToken = default)`
  - `static Http2ServerScript Http2WireCapture.MinimalExchange` — the default script: read preface, send empty SETTINGS, read the request header block, reply `200` with END_STREAM.

- [ ] **Step 1: Write the failing test**

Create `tests/TlsClient.Tests/Wire/Http2WireCaptureTests.cs`:

```csharp
using System.Net;

namespace TlsClient.Tests.Wire;

public sealed class Http2WireCaptureTests
{
    [Fact]
    public async Task CapturesConnectionPrefaceMagicExactly()
    {
        var options = TlsPresets.Chrome133.CreateOptions();

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, ct) => session.GetAsync(url, ct));

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal(
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray(),
            result.ClientBytes[..24]);
    }

    [Fact]
    public async Task CapturesClientFramesInArrivalOrder()
    {
        var options = TlsPresets.Chrome133.CreateOptions();

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, ct) => session.GetAsync(url, ct));

        Assert.Equal(Http2FrameType.Settings, result.ClientFrames[0].Type);
        Assert.Equal(Http2FrameType.WindowUpdate, result.ClientFrames[1].Type);
        Assert.Contains(result.ClientFrames, frame => frame.Type == Http2FrameType.Headers);
    }

    [Fact]
    public async Task CapturedBytesContainEveryCapturedFrame()
    {
        var options = TlsPresets.Chrome133.CreateOptions();

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, ct) => session.GetAsync(url, ct));

        // Magic plus each frame's 9-byte header and payload must account for the
        // recorded stream exactly. Every byte the server reads is recorded, and every
        // frame it parses comes from those same reads, so the two totals move together.
        // An inequality here would be silent on a recorder that duplicated bytes, which
        // is precisely the failure this harness exists to catch.
        var expected = 24 + result.ClientFrames.Sum(frame => 9 + frame.Payload.Length);
        Assert.Equal(expected, result.ClientBytes.Length);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /tmp && dotnet test "c:/Users/mario/OneDrive/Desktop/TlsClient-main/tests/TlsClient.Tests/TlsClient.Tests.csproj" -c Release --filter "FullyQualifiedName~Http2WireCaptureTests"
```

Expected: build failure, `The name 'Http2WireCapture' does not exist in the current context`.

- [ ] **Step 3: Write the implementation**

Create `tests/TlsClient.Tests/Wire/Http2WireCapture.cs`:

```csharp
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests.Wire;

internal sealed record Http2WireResult(
    byte[] ClientBytes,
    IReadOnlyList<CapturedFrame> ClientFrames,
    TlsResponse Response);

internal delegate Task Http2ServerScript(
    Http2WireServer server,
    CancellationToken cancellationToken);

/// <summary>
/// Runs a real TlsSession against a scripted loopback HTTP/2 server and returns the
/// exact decrypted bytes the client wrote.
/// </summary>
internal static class Http2WireCapture
{
    /// <summary>
    /// Reads the preface, acknowledges with an empty SETTINGS frame, waits for the
    /// request header block, and replies 200 with END_STREAM.
    /// </summary>
    public static Http2ServerScript MinimalExchange { get; } = async (server, cancellationToken) =>
    {
        var preface = await server.ReadPrefaceAsync(cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray(), preface);

        await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
        await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
        await server.FlushAsync(cancellationToken);

        var headers = await server.ReadUntilAsync(Http2FrameType.Headers, cancellationToken);
        var frame = headers;
        while ((frame.Flags & Http2FrameFlags.EndHeaders) == 0)
        {
            frame = await server.ReadFrameAsync(cancellationToken);
        }

        // 0x88 is the static-table entry for ":status: 200".
        await server.WriteFrameAsync(
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
            headers.StreamId,
            [0x88],
            cancellationToken);
        await server.FlushAsync(cancellationToken);
    };

    public static async Task<Http2WireResult> RunAsync(
        TlsSessionOptions options,
        Func<TlsSession, string, CancellationToken, Task<TlsResponse>> request,
        Http2ServerScript? script = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(request);
        script ??= MinimalExchange;

        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));

        var responseReceived = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = RunServerAsync(
            listener,
            serverCredential,
            script,
            responseReceived.Task,
            timeout.Token);

        options.HttpVersionPolicy = TlsHttpVersionPolicy.Http2Only;
        var existingConfigure = options.ConfigureTls;
        options.ConfigureTls = tls =>
        {
            existingConfigure?.Invoke(tls);
            tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
            tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
            tls.CertificateValidation.DisableCertificateDownloads = true;
        };

        await using var session = new TlsSession(options);
        var requestTask = request(
            session,
            $"https://127.0.0.1:{port}/capture",
            timeout.Token);

        // The server script only finishes after the client's response arrives, so it
        // cannot win this race unless it faulted. Observing it here surfaces the real
        // assertion failure immediately, instead of letting the client block until the
        // 15-second timeout and report a misleading cancellation.
        if (await Task.WhenAny(requestTask, serverTask).ConfigureAwait(false) == serverTask)
        {
            await serverTask.ConfigureAwait(false);
        }

        var response = await requestTask.ConfigureAwait(false);
        responseReceived.TrySetResult();

        var capture = await serverTask.ConfigureAwait(false);
        return new Http2WireResult(capture.ClientBytes, capture.Frames, response);
    }

    private static async Task<(byte[] ClientBytes, IReadOnlyList<CapturedFrame> Frames)>
        RunServerAsync(
            TcpListener listener,
            TlsServerCertificate credential,
            Http2ServerScript script,
            Task responseReceived,
            CancellationToken cancellationToken)
    {
        using var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["h2"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(
            tcpClient.GetStream(),
            leaveOpen: false,
            cancellationToken);

        await using var tlsStream = server.AsStream(leaveServerOpen: true);
        await using var recording = new RecordingStream(tlsStream);
        var wire = new Http2WireServer(recording);

        await script(wire, cancellationToken);
        await responseReceived.WaitAsync(cancellationToken);

        return (recording.ReadBytes, wire.ClientFrames);
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /tmp && dotnet test "c:/Users/mario/OneDrive/Desktop/TlsClient-main/tests/TlsClient.Tests/TlsClient.Tests.csproj" -c Release --filter "FullyQualifiedName~Http2WireCaptureTests"
```

Expected: `Passed! - Failed: 0, Passed: 3`.

If `CapturesConnectionPrefaceMagicExactly` fails with a timeout rather than an assertion, the server script and the client have deadlocked — check that `MinimalExchange` sends its SETTINGS frame before waiting for HEADERS, since the client will not proceed until the server's SETTINGS arrives.

- [ ] **Step 5: Commit**

```bash
git add tests/TlsClient.Tests/Wire/Http2WireCapture.cs tests/TlsClient.Tests/Wire/Http2WireCaptureTests.cs
git commit -m "test: add loopback HTTP/2 wire capture harness"
```

---

### Task 4: Byte assertion helper

`Assert.Equal(byte[], byte[])` on a 60-byte preface produces an unreadable failure message. This renders the mismatch as an offset-annotated hex dump so a one-byte regression is diagnosable at a glance.

**Files:**
- Create: `tests/TlsClient.Tests/Wire/Http2WireAssert.cs`
- Test: `tests/TlsClient.Tests/Wire/Http2WireAssertTests.cs`

**Interfaces:**
- Consumes: nothing.
- Produces: `static void Http2WireAssert.EqualBytes(byte[] expected, ReadOnlySpan<byte> actual, string what)` and `static string Http2WireAssert.ToHex(ReadOnlySpan<byte> bytes)`.

- [ ] **Step 1: Write the failing test**

Create `tests/TlsClient.Tests/Wire/Http2WireAssertTests.cs`:

```csharp
namespace TlsClient.Tests.Wire;

public sealed class Http2WireAssertTests
{
    [Fact]
    public void EqualBytesPassesOnIdenticalInput()
    {
        Http2WireAssert.EqualBytes([0x00, 0xff], new byte[] { 0x00, 0xff }, "preface");
    }

    [Fact]
    public void EqualBytesReportsFirstDifferingOffsetAndBothValues()
    {
        var failure = Assert.Throws<Xunit.Sdk.XunitException>(() =>
            Http2WireAssert.EqualBytes(
                [0x00, 0x01, 0x02],
                new byte[] { 0x00, 0x99, 0x02 },
                "preface"));

        Assert.Contains("preface", failure.Message);
        Assert.Contains("offset 1", failure.Message);
        Assert.Contains("01", failure.Message);
        Assert.Contains("99", failure.Message);
    }

    [Fact]
    public void EqualBytesReportsLengthMismatch()
    {
        var failure = Assert.Throws<Xunit.Sdk.XunitException>(() =>
            Http2WireAssert.EqualBytes([0x00, 0x01], new byte[] { 0x00 }, "preface"));

        Assert.Contains("length", failure.Message);
    }

    [Fact]
    public void ToHexGroupsBytesInSpaceSeparatedPairs()
    {
        Assert.Equal("00 0f ff", Http2WireAssert.ToHex(new byte[] { 0x00, 0x0f, 0xff }));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /tmp && dotnet test "c:/Users/mario/OneDrive/Desktop/TlsClient-main/tests/TlsClient.Tests/TlsClient.Tests.csproj" -c Release --filter "FullyQualifiedName~Http2WireAssertTests"
```

Expected: build failure, `The name 'Http2WireAssert' does not exist in the current context`.

- [ ] **Step 3: Write the implementation**

Create `tests/TlsClient.Tests/Wire/Http2WireAssert.cs`:

```csharp
using System.Text;
using Xunit.Sdk;

namespace TlsClient.Tests.Wire;

internal static class Http2WireAssert
{
    public static string ToHex(ReadOnlySpan<byte> bytes)
    {
        var builder = new StringBuilder(bytes.Length * 3);
        foreach (var value in bytes)
        {
            if (builder.Length != 0)
            {
                builder.Append(' ');
            }
            builder.Append(value.ToString("x2"));
        }
        return builder.ToString();
    }

    public static void EqualBytes(byte[] expected, ReadOnlySpan<byte> actual, string what)
    {
        ArgumentNullException.ThrowIfNull(expected);

        if (expected.Length != actual.Length)
        {
            throw new XunitException(
                $"{what}: length mismatch — expected {expected.Length} bytes, got {actual.Length}.{Environment.NewLine}" +
                $"  expected: {ToHex(expected)}{Environment.NewLine}" +
                $"  actual:   {ToHex(actual)}");
        }

        for (var offset = 0; offset < expected.Length; offset++)
        {
            if (expected[offset] == actual[offset])
            {
                continue;
            }

            var start = Math.Max(0, offset - 4);
            var length = Math.Min(12, expected.Length - start);
            throw new XunitException(
                $"{what}: differs at offset {offset} — expected {expected[offset]:x2}, got {actual[offset]:x2}.{Environment.NewLine}" +
                $"  expected[{start}..]: {ToHex(expected.AsSpan(start, length))}{Environment.NewLine}" +
                $"  actual  [{start}..]: {ToHex(actual.Slice(start, length))}");
        }
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /tmp && dotnet test "c:/Users/mario/OneDrive/Desktop/TlsClient-main/tests/TlsClient.Tests/TlsClient.Tests.csproj" -c Release --filter "FullyQualifiedName~Http2WireAssertTests"
```

Expected: `Passed! - Failed: 0, Passed: 4`.

- [ ] **Step 5: Commit**

```bash
git add tests/TlsClient.Tests/Wire/Http2WireAssert.cs tests/TlsClient.Tests/Wire/Http2WireAssertTests.cs
git commit -m "test: add hex-dump byte assertion helper for wire tests"
```

---

### Task 5: Golden preface fixtures

The deliverable. Pins each preset's connection preface — magic, SETTINGS frame, WINDOW_UPDATE frame — as exact bytes.

The expected values are derived from the preset definitions in `src/TlsClient/TlsPreset.cs:142-189`, not from observed output. If a test fails, either the arithmetic below is wrong or the implementation changed; both are worth knowing, and neither is discoverable from the current fingerprint-string test.

Chrome 133 emits four settings, so the SETTINGS payload is 24 bytes (`0x18`):

| Field | Bytes |
|---|---|
| Frame header, len 24, type `0x04`, flags `0x00`, stream 0 | `00 00 18 04 00 00 00 00 00` |
| `(1, 65536)` — `65536 = 0x00010000` | `00 01 00 01 00 00` |
| `(2, 0)` | `00 02 00 00 00 00` |
| `(4, 6291456)` — `6291456 = 0x00600000` | `00 04 00 60 00 00` |
| `(6, 262144)` — `262144 = 0x00040000` | `00 06 00 04 00 00` |
| WINDOW_UPDATE header, len 4, type `0x08`, stream 0 | `00 00 04 08 00 00 00 00 00` |
| Increment `15663105 = 0x00ef0001` | `00 ef 00 01` |

Firefox 148 also emits four settings: `(1, 65536)`, `(2, 0)`, `(4, 131072 = 0x00020000)`, `(5, 16384 = 0x00004000)`, then increment `12517377 = 0x00bf0001`.

OkHttp Android 11 emits one setting, so its payload is 6 bytes (`0x06`): `(4, 16777216 = 0x01000000)`, then increment `16711681 = 0x00ff0001`.

**Files:**
- Create: `tests/TlsClient.Tests/Http2WireGoldenTests.cs`

**Interfaces:**
- Consumes: `Http2WireCapture.RunAsync` (Task 3), `Http2WireAssert.EqualBytes` (Task 4).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the failing test**

Create `tests/TlsClient.Tests/Http2WireGoldenTests.cs`:

```csharp
using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

public sealed class Http2WireGoldenTests
{
    private static readonly byte[] Magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    public static TheoryData<string> PresetNames =>
        ["chrome-133", "firefox-148", "okhttp4-android-11"];

    [Theory]
    [MemberData(nameof(PresetNames))]
    public async Task Preset_EmitsExactPrefaceBytes(string presetName)
    {
        var expected = ExpectedPreface(presetName);

        var result = await Http2WireCapture.RunAsync(
            GetPreset(presetName).CreateOptions(),
            (session, url, ct) => session.GetAsync(url, ct));

        Http2WireAssert.EqualBytes(
            expected,
            result.ClientBytes.AsSpan(0, expected.Length),
            $"{presetName} preface");
    }

    private static TlsPreset GetPreset(string name) => name switch
    {
        "chrome-133" => TlsPresets.Chrome133,
        "firefox-148" => TlsPresets.Firefox148,
        "okhttp4-android-11" => TlsPresets.Android11,
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private static byte[] ExpectedPreface(string name)
    {
        var settings = name switch
        {
            "chrome-133" => new byte[]
            {
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // (1, 65536)
                0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // (2, 0)
                0x00, 0x04, 0x00, 0x60, 0x00, 0x00, // (4, 6291456)
                0x00, 0x06, 0x00, 0x04, 0x00, 0x00, // (6, 262144)
            },
            "firefox-148" => new byte[]
            {
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // (1, 65536)
                0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // (2, 0)
                0x00, 0x04, 0x00, 0x02, 0x00, 0x00, // (4, 131072)
                0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // (5, 16384)
            },
            "okhttp4-android-11" => new byte[]
            {
                0x00, 0x04, 0x01, 0x00, 0x00, 0x00, // (4, 16777216)
            },
            _ => throw new ArgumentOutOfRangeException(nameof(name)),
        };

        var increment = name switch
        {
            "chrome-133" => new byte[] { 0x00, 0xef, 0x00, 0x01 },        // 15663105
            "firefox-148" => new byte[] { 0x00, 0xbf, 0x00, 0x01 },       // 12517377
            "okhttp4-android-11" => new byte[] { 0x00, 0xff, 0x00, 0x01 },// 16711681
            _ => throw new ArgumentOutOfRangeException(nameof(name)),
        };

        var preface = new List<byte>(Magic);
        preface.AddRange([0x00, 0x00, (byte)settings.Length, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        preface.AddRange(settings);
        preface.AddRange([0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
        preface.AddRange(increment);
        return [.. preface];
    }
}
```

- [ ] **Step 2: Run the test**

```bash
cd /tmp && dotnet test "c:/Users/mario/OneDrive/Desktop/TlsClient-main/tests/TlsClient.Tests/TlsClient.Tests.csproj" -c Release --filter "FullyQualifiedName~Http2WireGoldenTests"
```

Expected: `Passed! - Failed: 0, Passed: 3`.

These tests are expected to pass immediately — they pin behavior that already exists. That is the point: they are a regression net for the refactor in plans 2 and 3, not a specification of new behavior.

If one fails, read the hex dump before changing anything. A mismatch means either the arithmetic in `ExpectedPreface` is wrong or `TlsPreset.cs` does not hold the values `docs/PRESETS.md` documents. Do not adjust the expected bytes to match observed output without first confirming which of those two it is — silently rewriting the expectation destroys the value of the fixture.

- [ ] **Step 3: Commit**

```bash
git add tests/TlsClient.Tests/Http2WireGoldenTests.cs
git commit -m "test: pin exact preface bytes for all three presets"
```

---

### Task 6: Refactor TlsPresetWireTests onto the harness

The existing test keeps its fingerprint assertion but stops carrying its own copy of the framing primitives. Its PUSH_PROMISE rejection check and User-Agent check must survive.

**Files:**
- Modify: `tests/TlsClient.Tests/TlsPresetWireTests.cs` (whole file rewritten)

**Interfaces:**
- Consumes: `Http2WireCapture.RunAsync`, `Http2WireServer`, `CapturedFrame`.
- Produces: nothing.

- [ ] **Step 1: Record the current baseline**

```bash
cd /tmp && dotnet test "c:/Users/mario/OneDrive/Desktop/TlsClient-main/tests/TlsClient.Tests/TlsClient.Tests.csproj" -c Release --filter "FullyQualifiedName~TlsPresetWireTests"
```

Expected: `Passed! - Failed: 0, Passed: 3`. Note the count — the refactor must end with the same three tests passing and the same three assertions intact.

- [ ] **Step 2: Rewrite the file**

Replace the whole of `tests/TlsClient.Tests/TlsPresetWireTests.cs` with:

```csharp
using System.Buffers.Binary;
using System.Net;
using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

public sealed class TlsPresetWireTests
{
    public static TheoryData<string, string> PresetFingerprints => new()
    {
        {
            "chrome-133",
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
        },
        {
            "firefox-148",
            "1:65536;2:0;4:131072;5:16384|12517377|0:0:41|m,p,a,s"
        },
        {
            "okhttp4-android-11",
            "4:16777216|16711681|0:0:1|m,p,a,s"
        },
    };

    [Theory]
    [MemberData(nameof(PresetFingerprints))]
    public async Task Preset_EmitsCapturedHttp2Fingerprint(
        string presetName,
        string expectedFingerprint)
    {
        var options = GetPreset(presetName).CreateOptions();
        var expectedUserAgent = options.DefaultHeaders["User-Agent"];
        var rejectedServerPush = false;
        IReadOnlyList<HpackHeader> requestHeaders = [];

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, ct) => session.GetAsync(url, ct),
            async (server, ct) =>
            {
                var preface = await server.ReadPrefaceAsync(ct);
                Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray(), preface);

                var settingsFrame = await server.ReadUntilAsync(Http2FrameType.Settings, ct);
                Assert.Equal(0, settingsFrame.StreamId);
                var settings = ReadSettings(settingsFrame.Payload);

                await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], ct);
                await server.FlushAsync(ct);

                var headersFrame = await server.ReadUntilAsync(Http2FrameType.Headers, ct);
                var block = new List<byte>(ReadFirstHeaderFragment(headersFrame));
                var continuation = headersFrame;
                while ((continuation.Flags & Http2FrameFlags.EndHeaders) == 0)
                {
                    continuation = await server.ReadFrameAsync(ct);
                    Assert.Equal(Http2FrameType.Continuation, continuation.Type);
                    Assert.Equal(headersFrame.StreamId, continuation.StreamId);
                    block.AddRange(continuation.Payload);
                }

                requestHeaders = new HpackDecoder(65_536).Decode([.. block], 262_144);

                if (settings.All(s => s.Identifier != (ushort)TlsHttp2Setting.EnablePush))
                {
                    var pushPromise = new byte[5];
                    BinaryPrimitives.WriteInt32BigEndian(pushPromise, 2);
                    pushPromise[4] = 0x82; // :method: GET, enough to exercise the HPACK context.
                    await server.WriteFrameAsync(
                        Http2FrameType.PushPromise,
                        Http2FrameFlags.EndHeaders,
                        headersFrame.StreamId,
                        pushPromise,
                        ct);
                    await server.FlushAsync(ct);

                    var reset = await server.ReadUntilAsync(Http2FrameType.RstStream, ct);
                    Assert.Equal(2, reset.StreamId);
                    Assert.Equal(
                        Http2ErrorCode.Cancel,
                        (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(reset.Payload));
                    rejectedServerPush = true;
                }

                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    headersFrame.StreamId,
                    [0x88],
                    ct);
                await server.FlushAsync(ct);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal(expectedFingerprint, BuildFingerprint(result.ClientFrames, requestHeaders));
        Assert.Equal(presetName == "okhttp4-android-11", rejectedServerPush);
        Assert.Equal(
            expectedUserAgent,
            requestHeaders.Single(header => header.Name == "user-agent").Value);
    }

    private static string BuildFingerprint(
        IReadOnlyList<CapturedFrame> frames,
        IReadOnlyList<HpackHeader> headers)
    {
        var settingsFrame = frames.First(frame => frame.Type == Http2FrameType.Settings);
        var settingsText = string.Join(
            ';',
            ReadSettings(settingsFrame.Payload)
                .Select(setting => $"{setting.Identifier}:{setting.Value}"));

        uint increment = 0;
        var windowUpdate = frames.FirstOrDefault(
            frame => frame.Type == Http2FrameType.WindowUpdate && frame.StreamId == 0);
        if (windowUpdate.Payload is { Length: 4 })
        {
            increment = BinaryPrimitives.ReadUInt32BigEndian(windowUpdate.Payload) & 0x7fff_ffffU;
        }

        var headersFrame = frames.First(frame => frame.Type == Http2FrameType.Headers);
        var priority = ReadPriority(headersFrame);
        var priorityText = priority is null
            ? "0"
            : $"{priority.Value.Dependency}:{(priority.Value.Exclusive ? 1 : 0)}:{priority.Value.Weight}";

        var pseudoOrder = string.Join(",", headers
            .TakeWhile(header => header.Name.StartsWith(':'))
            .Select(header => header.Name[1].ToString()));

        return $"{settingsText}|{increment}|{priorityText}|{pseudoOrder}";
    }

    private static TlsPreset GetPreset(string name) => name switch
    {
        "chrome-133" => TlsPresets.Chrome133,
        "firefox-148" => TlsPresets.Firefox148,
        "okhttp4-android-11" => TlsPresets.Android11,
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private static (ushort Identifier, uint Value)[] ReadSettings(byte[] payload)
    {
        Assert.Equal(0, payload.Length % 6);
        var settings = new (ushort Identifier, uint Value)[payload.Length / 6];
        for (var index = 0; index < settings.Length; index++)
        {
            var offset = index * 6;
            settings[index] = (
                BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(offset, 2)),
                BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset + 2, 4)));
        }
        return settings;
    }

    private static CapturedPriority? ReadPriority(CapturedFrame frame)
    {
        if ((frame.Flags & Http2FrameFlags.Priority) == 0)
        {
            return null;
        }
        Assert.True(frame.Payload.Length >= 5);
        var rawDependency = BinaryPrimitives.ReadUInt32BigEndian(frame.Payload);
        return new CapturedPriority(
            (int)(rawDependency & 0x7fff_ffffU),
            (rawDependency & 0x8000_0000U) != 0,
            frame.Payload[4] + 1);
    }

    private static byte[] ReadFirstHeaderFragment(CapturedFrame frame)
    {
        var offset = (frame.Flags & Http2FrameFlags.Priority) == 0 ? 0 : 5;
        return frame.Payload[offset..];
    }

    private readonly record struct CapturedPriority(int Dependency, bool Exclusive, int Weight);
}
```

- [ ] **Step 3: Run the full suite**

```bash
cd /tmp && dotnet test "c:/Users/mario/OneDrive/Desktop/TlsClient-main/tests/TlsClient.Tests/TlsClient.Tests.csproj" -c Release
```

Expected: every test passes. The suite was 98 test methods plus 6 inline data cases before this plan; it gains 13 (3 + 3 + 4 + 3). No pre-existing test may regress.

- [ ] **Step 4: Commit**

```bash
git add tests/TlsClient.Tests/TlsPresetWireTests.cs
git commit -m "test: refactor preset wire tests onto shared capture harness"
```

---

### Task 7: Wireshark hex-stream ingestion

The primary authoring workflow. In Wireshark, right-click the reassembled HTTP/2 payload
and choose *Copy → …as a Hex Stream*; the clipboard then holds one long lowercase hex
string. This turns that string into the same `CapturedFrame` list a live capture produces,
so a manually analysed dump and a live connection are directly comparable.

**Files:**
- Create: `tests/TlsClient.Tests/Wire/Http2WireHex.cs`
- Test: `tests/TlsClient.Tests/Wire/Http2WireHexTests.cs`

**Interfaces:**
- Consumes: `CapturedFrame` (Task 2).
- Produces: `static byte[] Http2WireHex.Parse(string hex)`, `static IReadOnlyList<CapturedFrame> Http2WireHex.ParseFrames(string hex, bool expectPreface = true)`.

- [ ] **Step 1: Write the failing test**

Create `tests/TlsClient.Tests/Wire/Http2WireHexTests.cs`:

```csharp
namespace TlsClient.Tests.Wire;

public sealed class Http2WireHexTests
{
    // Magic, then SETTINGS(4, 16777216), then WINDOW_UPDATE(16711681) — the
    // okhttp4-android-11 preface.
    private const string AndroidPreface =
        "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a" +
        "000006040000000000" + "000401000000" +
        "000004080000000000" + "00ff0001";

    [Fact]
    public void ParseAcceptsWhitespaceAndColonSeparators()
    {
        Assert.Equal(new byte[] { 0x00, 0xef, 0x00, 0x01 }, Http2WireHex.Parse("00 ef 00 01"));
        Assert.Equal(new byte[] { 0x00, 0xef, 0x00, 0x01 }, Http2WireHex.Parse("00:ef:00:01"));
        Assert.Equal(new byte[] { 0x00, 0xef, 0x00, 0x01 }, Http2WireHex.Parse("00ef0001"));
    }

    [Fact]
    public void ParseRejectsOddLength()
    {
        var failure = Assert.Throws<FormatException>(() => Http2WireHex.Parse("00e"));
        Assert.Contains("even", failure.Message);
    }

    [Fact]
    public void ParseFramesSplitsPrefaceIntoFrames()
    {
        var frames = Http2WireHex.ParseFrames(AndroidPreface);

        Assert.Equal(2, frames.Count);
        Assert.Equal(Http2FrameType.Settings, frames[0].Type);
        Assert.Equal(6, frames[0].Payload.Length);
        Assert.Equal(Http2FrameType.WindowUpdate, frames[1].Type);
        Assert.Equal(new byte[] { 0x00, 0xff, 0x00, 0x01 }, frames[1].Payload);
    }

    [Fact]
    public void ParseFramesRejectsAMissingPrefaceWhenExpected()
    {
        var failure = Assert.Throws<FormatException>(
            () => Http2WireHex.ParseFrames("000006040000000000000401000000"));
        Assert.Contains("preface", failure.Message);
    }

    [Fact]
    public void ParseFramesWithoutPrefaceReadsFramesDirectly()
    {
        var frames = Http2WireHex.ParseFrames(
            "000004080000000000" + "00ff0001",
            expectPreface: false);

        Assert.Single(frames);
        Assert.Equal(Http2FrameType.WindowUpdate, frames[0].Type);
    }

    [Fact]
    public void ParseFramesRejectsATruncatedPayload()
    {
        var failure = Assert.Throws<FormatException>(
            () => Http2WireHex.ParseFrames("000004080000000000" + "00ff", expectPreface: false));
        Assert.Contains("truncated", failure.Message);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj -c Release --filter "FullyQualifiedName~Http2WireHexTests"
```

Expected: build failure, `The name 'Http2WireHex' does not exist in the current context`.

- [ ] **Step 3: Write the implementation**

Create `tests/TlsClient.Tests/Wire/Http2WireHex.cs`:

```csharp
using System.Buffers.Binary;
using System.Text;

namespace TlsClient.Tests.Wire;

/// <summary>
/// Turns a hex dump — as produced by Wireshark's "Copy as Hex Stream" — into the same
/// frame list a live capture produces, so a manually analysed dump and a recorded
/// connection are directly comparable.
/// </summary>
internal static class Http2WireHex
{
    private static readonly byte[] Magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    public static byte[] Parse(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        var builder = new StringBuilder(hex.Length);
        for (var index = 0; index < hex.Length; index++)
        {
            var character = hex[index];
            if (char.IsWhiteSpace(character) || character is ':' or '-' or ',')
            {
                continue;
            }
            if (!char.IsAsciiHexDigit(character))
            {
                // Every other error path in this file names a position, and a stray
                // non-hex character is the likeliest mistake when pasting by hand.
                // Convert.FromHexString's own exception carries no index and no hint.
                throw new FormatException(
                    $"Not a hex stream: unexpected '{character}' at index {index}. " +
                    "Wireshark's \"Copy as Hex Stream\" produces the expected form. " +
                    "A hex dump pane, which prefixes each line with an offset column " +
                    "and appends an ASCII column, is not accepted — its offset digits " +
                    "would be read as payload.");
            }
            builder.Append(character);
        }

        var cleaned = builder.ToString();
        if (cleaned.Length % 2 != 0)
        {
            throw new FormatException(
                $"A hex stream must have an even number of digits; got {cleaned.Length}.");
        }
        return Convert.FromHexString(cleaned);
    }

    public static IReadOnlyList<CapturedFrame> ParseFrames(string hex, bool expectPreface = true)
    {
        var bytes = Parse(hex);
        var offset = 0;

        if (expectPreface)
        {
            if (bytes.Length < Magic.Length ||
                !bytes.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            {
                throw new FormatException(
                    "The stream does not begin with the HTTP/2 connection preface magic. " +
                    "Pass expectPreface: false to read a mid-connection capture.");
            }
            offset = Magic.Length;
        }

        var frames = new List<CapturedFrame>();
        while (offset < bytes.Length)
        {
            if (bytes.Length - offset < 9)
            {
                throw new FormatException(
                    $"Frame header truncated at offset {offset}: " +
                    $"{bytes.Length - offset} bytes remain, 9 required.");
            }

            var length = bytes[offset] << 16 | bytes[offset + 1] << 8 | bytes[offset + 2];
            if (bytes.Length - offset - 9 < length)
            {
                throw new FormatException(
                    $"Frame payload truncated at offset {offset}: declared {length} bytes, " +
                    $"{bytes.Length - offset - 9} available.");
            }

            frames.Add(new CapturedFrame(
                (Http2FrameType)bytes[offset + 3],
                bytes[offset + 4],
                BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(offset + 5)) & 0x7fff_ffff,
                bytes.AsSpan(offset + 9, length).ToArray()));
            offset += 9 + length;
        }

        return frames;
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj -c Release --filter "FullyQualifiedName~Http2WireHexTests"
```

Expected: `Passed! - Failed: 0, Passed: 6`.

- [ ] **Step 5: Commit**

```bash
git add tests/TlsClient.Tests/Wire/Http2WireHex.cs tests/TlsClient.Tests/Wire/Http2WireHexTests.cs
git commit -m "test: parse Wireshark hex streams into HTTP/2 frames"
```

---

### Task 8: peet.ws-shaped rendering

`tls.peet.ws/api/all` is the reference oracle this work is validated against. Rendering
captured frames into its exact vocabulary means an observed response and an emitted
connection can be diffed by eye or by assertion, with no manual translation step.

The live response shape, captured from a real HTTP/2 request on 2026-08-15:

```json
"http2": {
  "akamai_fingerprint": "2:0;4:65535|67043329|0|m,s,a,p",
  "akamai_fingerprint_hash": "4d43b19a4dbd222c13769dcdf6b97a2e",
  "sent_frames": [
    {"frame_type":"SETTINGS","length":12,
     "settings":["ENABLE_PUSH = 0","INITIAL_WINDOW_SIZE = 65535"]},
    {"frame_type":"WINDOW_UPDATE","length":4,"increment":67043329},
    {"frame_type":"HEADERS","stream_id":1,"length":25,
     "headers":[":method: GET",":scheme: https",":authority: tls.peet.ws",":path: /api/all"],
     "flags":["EndStream (0x1)","EndHeaders (0x4)"]}
  ]
}
```

**One divergence to preserve, not fix.** The Akamai priority segment — the third field —
is built from PRIORITY *frames*, and is `0` when none were sent. `TlsPresetWireTests`
uses a different internal string that encodes the HEADERS frame's priority flag as
`dependency:exclusive:weight`, which is why its Firefox expectation reads `0:0:41`. Under
the Akamai convention that same connection renders `0`, because Firefox 148 as configured
sends no PRIORITY frames. These are two different measurements of two different things.
Do not make one match the other; a test asserts both.

**Files:**
- Create: `tests/TlsClient.Tests/Wire/Http2WirePeet.cs`
- Test: `tests/TlsClient.Tests/Wire/Http2WirePeetTests.cs`

**Interfaces:**
- Consumes: `CapturedFrame` (Task 2), `Http2WireHex` (Task 7).
- Produces: `sealed record PeetFrame(string FrameType, int Length, int? StreamId, IReadOnlyList<string>? Settings, uint? Increment, IReadOnlyList<string>? Flags)`, `static IReadOnlyList<PeetFrame> Http2WirePeet.Describe(IReadOnlyList<CapturedFrame> frames)`, `static string Http2WirePeet.AkamaiFingerprint(IReadOnlyList<CapturedFrame> frames, IReadOnlyList<string> pseudoHeaderOrder)`.

- [ ] **Step 1: Write the failing test**

Create `tests/TlsClient.Tests/Wire/Http2WirePeetTests.cs`:

```csharp
namespace TlsClient.Tests.Wire;

public sealed class Http2WirePeetTests
{
    private const string ChromePreface =
        "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a" +
        "000018040000000000" +
        "000100010000" + "000200000000" + "000400600000" + "000600040000" +
        "000004080000000000" + "00ef0001";

    [Fact]
    public void DescribesSettingsWithRegistryNames()
    {
        var frames = Http2WireHex.ParseFrames(ChromePreface);

        var described = Http2WirePeet.Describe(frames);

        Assert.Equal("SETTINGS", described[0].FrameType);
        Assert.Equal(24, described[0].Length);
        Assert.Equal(
            [
                "HEADER_TABLE_SIZE = 65536",
                "ENABLE_PUSH = 0",
                "INITIAL_WINDOW_SIZE = 6291456",
                "MAX_HEADER_LIST_SIZE = 262144",
            ],
            described[0].Settings);
    }

    [Fact]
    public void DescribesWindowUpdateIncrement()
    {
        var described = Http2WirePeet.Describe(Http2WireHex.ParseFrames(ChromePreface));

        Assert.Equal("WINDOW_UPDATE", described[1].FrameType);
        Assert.Equal(15_663_105u, described[1].Increment);
    }

    [Fact]
    public void DescribesUnknownSettingIdentifierWithoutLosingIt()
    {
        // A single GREASE setting, id 0x4a4a, value 0.
        var frames = Http2WireHex.ParseFrames(
            "000006040000000000" + "4a4a00000000",
            expectPreface: false);

        var described = Http2WirePeet.Describe(frames);

        Assert.Equal(["UNKNOWN(0x4a4a) = 0"], described[0].Settings);
    }

    [Fact]
    public void AkamaiFingerprintMatchesTheDocumentedChromeValue()
    {
        var frames = Http2WireHex.ParseFrames(ChromePreface);

        var fingerprint = Http2WirePeet.AkamaiFingerprint(
            frames,
            [":method", ":authority", ":scheme", ":path"]);

        Assert.Equal("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", fingerprint);
    }

    [Fact]
    public void AkamaiPrioritySegmentUsesPriorityFramesNotHeadersFlags()
    {
        // HEADERS on stream 1 carrying a priority payload, but no PRIORITY frame.
        var frames = Http2WireHex.ParseFrames(
            "000005012000000001" + "0000000028",
            expectPreface: false);

        var fingerprint = Http2WirePeet.AkamaiFingerprint(frames, [":method"]);

        // Assert the whole string, not a substring. This fixture has no SETTINGS and no
        // WINDOW_UPDATE, so it renders a leading "|0|" whatever the priority segment
        // contains — a Contains check would be satisfied by that prefix alone and would
        // pass even if the priority logic read the HEADERS flag instead of PRIORITY
        // frames, which is the one thing this test exists to rule out.
        Assert.Equal("|0|0|m", fingerprint);
    }

    [Fact]
    public void DescribesFrameFlagsByName()
    {
        var frames = Http2WireHex.ParseFrames(
            "000001010500000001" + "88",
            expectPreface: false);

        var described = Http2WirePeet.Describe(frames);

        Assert.Equal(["EndStream (0x1)", "EndHeaders (0x4)"], described[0].Flags);
        Assert.Equal(1, described[0].StreamId);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj -c Release --filter "FullyQualifiedName~Http2WirePeetTests"
```

Expected: build failure, `The name 'Http2WirePeet' does not exist in the current context`.

- [ ] **Step 3: Write the implementation**

Create `tests/TlsClient.Tests/Wire/Http2WirePeet.cs`:

```csharp
using System.Buffers.Binary;

namespace TlsClient.Tests.Wire;

internal sealed record PeetFrame(
    string FrameType,
    int Length,
    int? StreamId,
    IReadOnlyList<string>? Settings,
    uint? Increment,
    IReadOnlyList<string>? Flags);

/// <summary>
/// Renders captured frames in the vocabulary that tls.peet.ws/api/all reports, so an
/// observed response and an emitted connection can be compared without translation.
/// </summary>
internal static class Http2WirePeet
{
    public static IReadOnlyList<PeetFrame> Describe(IReadOnlyList<CapturedFrame> frames)
    {
        ArgumentNullException.ThrowIfNull(frames);
        var described = new List<PeetFrame>(frames.Count);
        foreach (var frame in frames)
        {
            described.Add(new PeetFrame(
                FrameTypeName(frame.Type),
                frame.Payload.Length,
                frame.StreamId == 0 ? null : frame.StreamId,
                frame.Type == Http2FrameType.Settings ? DescribeSettings(frame.Payload) : null,
                frame.Type == Http2FrameType.WindowUpdate && frame.Payload.Length == 4
                    ? BinaryPrimitives.ReadUInt32BigEndian(frame.Payload) & 0x7fff_ffffU
                    : null,
                DescribeFlags(frame.Flags)));
        }
        return described;
    }

    public static string AkamaiFingerprint(
        IReadOnlyList<CapturedFrame> frames,
        IReadOnlyList<string> pseudoHeaderOrder)
    {
        ArgumentNullException.ThrowIfNull(frames);
        ArgumentNullException.ThrowIfNull(pseudoHeaderOrder);

        var settingsFrame = frames.FirstOrDefault(
            frame => frame.Type == Http2FrameType.Settings);
        var settingsText = settingsFrame.Payload is null
            ? string.Empty
            : string.Join(';', ReadSettings(settingsFrame.Payload)
                .Select(setting => $"{setting.Identifier}:{setting.Value}"));

        var windowUpdate = frames.FirstOrDefault(
            frame => frame.Type == Http2FrameType.WindowUpdate && frame.StreamId == 0);
        var increment = windowUpdate.Payload is { Length: 4 }
            ? BinaryPrimitives.ReadUInt32BigEndian(windowUpdate.Payload) & 0x7fff_ffffU
            : 0u;

        // The Akamai priority segment is built from PRIORITY frames only. A HEADERS
        // frame carrying a priority payload does not contribute; that is a different
        // measurement, and TlsPresetWireTests asserts it separately.
        var priorities = frames
            .Where(frame => frame.Type == Http2FrameType.Priority && frame.Payload.Length == 5)
            .Select(frame =>
            {
                var raw = BinaryPrimitives.ReadUInt32BigEndian(frame.Payload);
                var exclusive = (raw & 0x8000_0000U) != 0 ? 1 : 0;
                var dependency = raw & 0x7fff_ffffU;
                return $"{frame.StreamId}:{exclusive}:{dependency}:{frame.Payload[4] + 1}";
            })
            .ToArray();
        var priorityText = priorities.Length == 0 ? "0" : string.Join(',', priorities);

        var pseudoText = string.Join(
            ',',
            pseudoHeaderOrder.Select(name => name.TrimStart(':')[..1]));

        return $"{settingsText}|{increment}|{priorityText}|{pseudoText}";
    }

    private static string FrameTypeName(Http2FrameType type) => type switch
    {
        Http2FrameType.Data => "DATA",
        Http2FrameType.Headers => "HEADERS",
        Http2FrameType.Priority => "PRIORITY",
        Http2FrameType.RstStream => "RST_STREAM",
        Http2FrameType.Settings => "SETTINGS",
        Http2FrameType.PushPromise => "PUSH_PROMISE",
        Http2FrameType.Ping => "PING",
        Http2FrameType.GoAway => "GOAWAY",
        Http2FrameType.WindowUpdate => "WINDOW_UPDATE",
        Http2FrameType.Continuation => "CONTINUATION",
        _ => $"UNKNOWN(0x{(byte)type:x2})",
    };

    private static string SettingName(ushort identifier) => identifier switch
    {
        0x1 => "HEADER_TABLE_SIZE",
        0x2 => "ENABLE_PUSH",
        0x3 => "MAX_CONCURRENT_STREAMS",
        0x4 => "INITIAL_WINDOW_SIZE",
        0x5 => "MAX_FRAME_SIZE",
        0x6 => "MAX_HEADER_LIST_SIZE",
        0x8 => "ENABLE_CONNECT_PROTOCOL",
        0x9 => "NO_RFC7540_PRIORITIES",
        _ => $"UNKNOWN(0x{identifier:x4})",
    };

    private static IReadOnlyList<string> DescribeSettings(byte[] payload) =>
        [.. ReadSettings(payload)
            .Select(setting => $"{SettingName(setting.Identifier)} = {setting.Value}")];

    private static (ushort Identifier, uint Value)[] ReadSettings(byte[] payload)
    {
        var count = payload.Length / 6;
        var settings = new (ushort, uint)[count];
        for (var index = 0; index < count; index++)
        {
            var offset = index * 6;
            settings[index] = (
                BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(offset, 2)),
                BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset + 2, 4)));
        }
        return settings;
    }

    private static IReadOnlyList<string>? DescribeFlags(byte flags)
    {
        if (flags == 0)
        {
            return null;
        }
        var names = new List<string>();
        if ((flags & 0x1) != 0) names.Add("EndStream (0x1)");
        if ((flags & 0x4) != 0) names.Add("EndHeaders (0x4)");
        if ((flags & 0x8) != 0) names.Add("Padded (0x8)");
        if ((flags & 0x20) != 0) names.Add("Priority (0x20)");
        return names;
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj -c Release --filter "FullyQualifiedName~Http2WirePeetTests"
```

Expected: `Passed! - Failed: 0, Passed: 6`.

Note that `DescribeFlags` returns `EndStream` before `EndHeaders`, matching the observed
peet.ws ordering, which lists flags by ascending bit value rather than by name.

- [ ] **Step 5: Commit**

```bash
git add tests/TlsClient.Tests/Wire/Http2WirePeet.cs tests/TlsClient.Tests/Wire/Http2WirePeetTests.cs
git commit -m "test: render captured frames in tls.peet.ws vocabulary"
```

---

### Task 9: Opt-in live parity test against tls.peet.ws

The oracle test. Disabled by default so the offline suite stays hermetic, matching the
repository's stated position that public HTTPS smoke tests are optional and never required
for an offline run.

**Files:**
- Create: `tests/TlsClient.Tests/Http2LiveParityTests.cs`

**Interfaces:**
- Consumes: `Http2WirePeet.AkamaiFingerprint` (Task 8).
- Produces: nothing.

- [ ] **Step 1: Write the test**

Create `tests/TlsClient.Tests/Http2LiveParityTests.cs`:

```csharp
using System.Text.Json;
using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

/// <summary>
/// Compares what a preset actually emits against what tls.peet.ws observes. Requires
/// network access and is skipped unless TLSCLIENT_LIVE_TESTS=1, so the offline suite
/// stays hermetic.
/// </summary>
public sealed class Http2LiveParityTests
{
    private static bool Enabled =>
        Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_TESTS") == "1";

    public static TheoryData<string> PresetNames =>
        ["chrome-133", "firefox-148", "okhttp4-android-11"];

    [Theory]
    [MemberData(nameof(PresetNames))]
    public async Task Preset_AkamaiFingerprintMatchesPeetObservation(string presetName)
    {
        Assert.SkipUnless(Enabled, "Set TLSCLIENT_LIVE_TESTS=1 to run live network tests.");

        var preset = presetName switch
        {
            "chrome-133" => TlsPresets.Chrome133,
            "firefox-148" => TlsPresets.Firefox148,
            "okhttp4-android-11" => TlsPresets.Android11,
            _ => throw new ArgumentOutOfRangeException(nameof(presetName)),
        };

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var session = new TlsSession(preset);

        var response = await session.GetAsync("https://tls.peet.ws/api/all", timeout.Token);
        response.EnsureSuccessStatusCode();

        using var document = JsonDocument.Parse(response.Text);

        // GetProperty throws KeyNotFoundException without naming the missing key or
        // showing the body. This test runs rarely and unattended against a service
        // outside this repository's control, so an unlabelled failure years from now
        // would be undiagnosable. Name what was missing and show what arrived.
        Assert.True(
            document.RootElement.TryGetProperty("http2", out var http2),
            $"tls.peet.ws returned no http2 object — the connection may not have "
                + $"negotiated HTTP/2. Body: {Truncate(response.Text)}");
        Assert.True(
            http2.TryGetProperty("akamai_fingerprint", out var fingerprint),
            $"tls.peet.ws returned an http2 object with no akamai_fingerprint — its "
                + $"schema may have changed. Body: {Truncate(response.Text)}");
        var observed = fingerprint.GetString();

        // Record what the service saw. When this fails, the message is the whole point:
        // it names the exact axis that diverged from a real browser.
        Assert.False(
            string.IsNullOrWhiteSpace(observed),
            "tls.peet.ws returned no akamai_fingerprint");

        var expectedSettingsAndWindow = presetName switch
        {
            "chrome-133" => "1:65536;2:0;4:6291456;6:262144|15663105",
            "firefox-148" => "1:65536;2:0;4:131072;5:16384|12517377",
            "okhttp4-android-11" => "4:16777216|16711681",
            _ => throw new ArgumentOutOfRangeException(nameof(presetName)),
        };

        Assert.StartsWith(expectedSettingsAndWindow, observed);
    }
}
```

- [ ] **Step 2: Verify it skips by default**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj -c Release --filter "FullyQualifiedName~Http2LiveParityTests"
```

Expected: 3 skipped, 0 failed. If `Assert.SkipUnless` is unavailable in xUnit 2.9.3,
replace it with an early `return` guarded by `if (!Enabled)` and note the change; the
suite must not fail offline.

- [ ] **Step 3: Verify it runs and passes with network access**

```bash
cd "c:/Users/mario/OneDrive/Desktop/TlsClient-main" && TLSCLIENT_LIVE_TESTS=1 dotnet test tests/TlsClient.Tests/TlsClient.Tests.csproj -c Release --filter "FullyQualifiedName~Http2LiveParityTests"
```

Expected: 3 passed.

If a preset fails here, **do not change the expectation to match**. A mismatch is a real
finding about that preset's fidelity and belongs in a report, not in a rewritten
assertion. Record the observed string and stop.

- [ ] **Step 4: Commit**

```bash
git add tests/TlsClient.Tests/Http2LiveParityTests.cs
git commit -m "test: add opt-in tls.peet.ws akamai fingerprint parity check"
```

---

## What this plan deliberately does not do

- It does not assert HEADERS frame bytes. The header block depends on the request URL, which embeds an ephemeral loopback port, so those bytes are not stable across runs. Plans 2 and 3 assert decoded HPACK representation choices instead, which are stable.
- It does not capture the server-to-client direction. `RecordingStream.WrittenBytes` exists and works, but nothing needs it until the capture importer in the final plan, which requires both directions.
- It changes no production code, so it cannot fix any spec finding on its own. Its whole value is making the next two plans' "byte-identical" claims falsifiable.
