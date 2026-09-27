# MASQUE CONNECT-UDP Transport Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carry an unchanged Spotify HTTP/3 connection through Oxylabs' MASQUE proxy (`masque.oxylabs.io:50000`, RFC 9298 CONNECT-UDP over HTTP/3) behind the existing `ITlsQuicDatagramTransport` seam.

**Architecture:** An outer `TlsQuicConnection` + `TlsQuicHttp3Connection` to the proxy holds one extended-CONNECT stream; inner QUIC datagrams travel as RFC 9297 HTTP datagrams (quarter stream id) with RFC 9298 context id 0 inside RFC 9221 DATAGRAM frames. `TlsQuicMasqueTransport` owns the outer connection from a single owner task fed by two channels. TlsClient selects it when `options.Quic.Proxy` is a `TlsProxy.Masque`. Spec: `SharpTls/docs/superpowers/specs/2026-09-27-masque-connect-udp-transport-design.md` (read it first; it is the contract).

**Tech Stack:** C# / .NET 9, xunit, SharpTls (own QUIC + TLS stack), TlsClient. Tests: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~<Class>"` and the same for `TlsClient-main/tests/TlsClient.Tests`. Both test projects can see internals (`InternalsVisibleTo`).

---

## Conventions for every task

- Read the file region named before editing. Line numbers are as of commit `41e2ad4`; grep the anchor text if they drifted.
- Commit after each task with the message given. Never push. Never commit credentials; live tests read `TLSCLIENT_LIVE_MASQUE`.
- Public surface changes in SharpTls need `dotnet run --project SharpTls/tools/SharpTls.ApiCompat > SharpTls/tests/SharpTls.Tests/Api/PublicApi.Shipped.txt` (LF file); in TlsClient, add lines to `TlsClient-main/src/TlsClient/PublicAPI.Unshipped.txt` (RS0016/RS0017 analyzers fail the build otherwise).
- `TlsQuicApplicationSendPath.cs`, `TlsQuicConnectionFrames.cs` and friends are `partial class TlsQuicConnection` / static helpers; confirm with `grep -n "partial class" <file>` before adding members.
- Test helpers that already exist and must be reused: `InMemoryDatagramTransport.CreatePair()`, `LoopbackQuicPeer.ForServer(...)` (a scripted QUIC server peer with `SendOneRttRawFrameAsync`, `SendStreamFramesAsync`, `ReceivedStreamFrames`, `PumpOnceAsync`), the `Harness` nested class in `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ConnectionTests.cs:2026` (client connection + HTTP/3 + server peer with a completed handshake; `Harness.CreateAsync(ct, spec:, flowControl:, maxDatagramFrameSize:)`), `TestHttp3Settings.QpackCapable`, `ImpairingDatagramTransport` (loss injection).

## File map

| File | Responsibility after this plan |
| --- | --- |
| `SharpTls/src/SharpTls/Quic/TlsQuicConnection.cs` | keeps the peer's `max_datagram_frame_size`; bounded outbound datagram FIFO |
| `SharpTls/src/SharpTls/Quic/TlsQuicApplicationSendPath.cs` | packs one DATAGRAM frame per 1-RTT packet, congestion-gated |
| `SharpTls/src/SharpTls/Quic/TlsQuicFrames.cs`, `TlsQuicConnectionFrames.cs` | DATAGRAM frame writer (0x31 form) |
| `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Request.cs` | `Protocol` → `:protocol` after `:method` |
| `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Spec.cs` | `EnableConnectProtocolIdentifier = 0x08` |
| `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Connection.cs` | datagram-carrying exchanges: no FIN, per-stream datagram queues, send, forwarders |
| `SharpTls/src/SharpTls/Quic/TlsQuicSocks5Protocol.cs` | five `Masque*` members on `TlsQuicProxyError` |
| `SharpTls/src/SharpTls/Quic/TlsQuicMasqueOptions.cs` (new) | dial inputs |
| `SharpTls/src/SharpTls/Quic/TlsQuicMasqueTransport.cs` (new) | the tunnel: dial, owner task, channels, `ITlsQuicDatagramTransport` |
| `SharpTls/docs/MASQUE-DATAGRAM-TRANSPORT.md` (new) | wire-level reference |
| `TlsClient-main/src/TlsClient/TlsProxy.cs` | `TlsProxyType.Masque = 3`, `TlsProxy.Masque(...)` |
| `TlsClient-main/src/TlsClient/TlsQuicOptions.cs` | `Proxy` knob, snapshot, outer options builder |
| `TlsClient-main/src/TlsClient/Http3Connection.cs` | MASQUE dial branch, telemetry |
| `TlsClient-main/src/TlsClient/HttpConnectionFactory.cs`, `ProxyTunnel.cs` | proxy-type routing and refusals |
| `TlsClient-main/src/TlsClient/TlsConnectEvent.cs` | `MasqueTunnelOpened`, `MasqueTunnelClosed` |
| `TlsClient-main/tests/TlsClient.Tests/MasqueLiveTests.cs` (new) | live gate against Oxylabs |

---

## Chunk 1: SharpTls QUIC and HTTP/3 groundwork

### Task 1: Keep the peer's `max_datagram_frame_size`

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicConnection.cs:3622-3660` (`ApplyPeerTransportParametersAsync`) and the property block near line 1303 (`AdvertisedMaxDatagramFrameSize`)
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicConnectionDatagramTests.cs` (new)

- [ ] **Step 1: Write the failing test**

The harness's `flowControl` argument is the SERVER's transport parameter list. Find how existing tests build a `TlsQuicTransportParameter` (grep `new TlsQuicTransportParameter(` in `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ConnectionTests.cs`) and copy that shape.

```csharp
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicConnectionDatagramTests
{
    [Fact]
    public async Task ThePeersMaxDatagramFrameSizeIsKeptAfterTheHandshake()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(
            cancellation.Token,
            flowControl: [.. TlsQuicConnectionTests.FlowControlParameters(), TlsQuicTransportParameter.VariableInteger(0x20, 65535)]);

        Assert.Equal(65535UL, harness.Connection.PeerMaxDatagramFrameSize);
    }

    [Fact]
    public async Task APeerThatSendsNoMaxDatagramFrameSizeLeavesItNull()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(cancellation.Token);

        Assert.Null(harness.Connection.PeerMaxDatagramFrameSize);
    }
}
```

`TlsQuicTransportParameter.VariableInteger(id, value)` already exists (`TlsQuicConnectionTests.cs:1212`); `FlowControlParameters` is already `internal static` (`:1340`).

`Harness` is nested in `public sealed partial class TlsQuicConnectionTests` (the partial's other half is `TlsQuicHttp3ConnectionTests.cs`, where the harness sits at line 2026) and is `private sealed class` today; make it `internal sealed class`, and make `Server`, `Credential`, `Spec` and `SentAt` on that partial `internal static` too (Chunk 2 needs them). `flowControl` REPLACES the server's parameter list (`Server` does `parameters.AddRange(flowControl ?? FlowControlParameters())`, `TlsQuicConnectionTests.cs:~1322`), which is why the test spreads `FlowControlParameters()` first: without it the peer grants no streams and the harness cannot open its control streams.

- [ ] **Step 2: Run the test, expect a compile failure**

Run: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~TlsQuicConnectionDatagramTests"`
Expected: `error CS1061: 'TlsQuicConnection' does not contain a definition for 'PeerMaxDatagramFrameSize'`

- [ ] **Step 3: Implement**

Next to `AdvertisedMaxDatagramFrameSize` (line 1303):

```csharp
/// <summary>Gets the peer's RFC 9221 s3 <c>max_datagram_frame_size</c>, or
/// <see langword="null"/> when its transport parameters carried none, in which case it
/// accepts no DATAGRAM frames. <see cref="AdvertisedMaxDatagramFrameSize"/> is OUR value;
/// this is theirs, and it is what the send side must honour.</summary>
internal ulong? PeerMaxDatagramFrameSize { get; private set; }
```

In `ApplyPeerTransportParametersAsync`, after `_peerMaxAckDelay = ...`:

```csharp
// RFC 9221 s3: absent or 0 both mean "no DATAGRAM frames accepted".
var advertisedDatagramLimit = peer.Parameters
    .Get((ulong)TlsQuicTransportParameterId.MaxDatagramFrameSize)
    ?.GetVariableInteger();
PeerMaxDatagramFrameSize = advertisedDatagramLimit is 0 ? null : advertisedDatagramLimit;
``` `TlsQuicTransportParameterId.MaxDatagramFrameSize` exists (the parser's `case MaxDatagramFrameSize:` in `TlsQuicTransportParameters.cs:300` names it). The default `Server(...)` in the tests advertises no 0x20, so the second test's `Null` holds.

- [ ] **Step 4: Run the test, expect pass**

Run the same command. Expected: `Passed! - Failed: 0, Passed: 2`.

- [ ] **Step 5: Commit**

```bash
git add SharpTls/src/SharpTls/Quic/TlsQuicConnection.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicConnectionDatagramTests.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ConnectionTests.cs
git commit -m "feat(quic): keep the peer's max_datagram_frame_size" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 2: DATAGRAM frame writer

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicFrames.cs:1000-1012` (the `case TlsQuicFrameType.Datagram: throw ...` arm in the frame writer) and `MeasureFrame` if it switches on type
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicConnectionFrames.cs` (add `WriteDatagramFrameFields` beside `WritePathDataFrameFields`, line 1130)
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicFramesTests.cs` (existing file; add a fact)

- [ ] **Step 1: Write the failing test**

`TlsQuicFramesTests.cs:583` has `WritingADatagramFrameThrowsBecauseThisLibraryNeverSendsOne(ulong rawType)` with rows 0x30 and 0x31: delete it (its premise ends with this task) and replace it with:

```csharp
[Fact]
public void ADatagramFrameRoundTripsInItsLengthBearingForm()
{
    var frame = new TlsQuicFrame
    {
        RawType = (ulong)TlsQuicFrameType.Datagram | TlsQuicFrames.DatagramLengthBit,
        Data = new byte[] { 0x00, 0x00, 0xAA, 0xBB, 0xCC },
    };

    var written = new List<byte>();
    TlsQuicFrames.WriteFrame(written, frame);                      // TlsQuicFrames.cs:128
    Assert.Equal(0x31, written[0]);
    Assert.Equal(5, written[1]);
    Assert.Equal(frame.Data.ToArray(), written.Skip(2).ToArray());

    var offset = 0;
    Assert.True(TlsQuicFrames.TryReadFrame(written.ToArray(), ref offset, out var read, out var error)); // :369
    Assert.Equal(TlsQuicFrameType.Datagram, read.Type);
    Assert.Equal(frame.Data.ToArray(), read.Data.ToArray());
    Assert.Equal(written.Count, offset);
    Assert.Equal(written.Count, TlsQuicFrames.MeasureFrame([], frame));
}

[Fact]
public void TheLengthLessDatagramFormIsNeverWritten()
{
    var frame = new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Datagram, Data = new byte[] { 1 } };
    Assert.Throws<ArgumentException>(() => TlsQuicFrames.WriteFrame([], frame));
}
```

Also update the comment at `TlsQuicFramesTests.cs:393-394`, which names the deleted theory.

- [ ] **Step 2: Run, expect the ArgumentException**

Run: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~ADatagramFrameRoundTrips"`
Expected: FAIL, `ArgumentException: RFC 9221 DATAGRAM frames are parsed and dropped, never sent`.

- [ ] **Step 3: Implement**

In `TlsQuicConnectionFrames.cs`:

Every `Write*FrameFields` writes its own type from `frame.RawType` first (`TlsQuicConnectionFrames.cs:940, 959, 995, 1090` do exactly that), and the writer switch at `TlsQuicFrames.WriteFrame` (`:861`) keys on `frame.Type`:

```csharp
/// <summary>RFC 9221 s4's DATAGRAM frame in its 0x31 form: Type (i), Length (i), Datagram
/// Data. Only that form is ever sent, because a length-less 0x30 frame must be the last
/// frame in its packet and TryBuildApplicationPacket may append an ACK after it.</summary>
internal static void WriteDatagramFrameFields(List<byte> destination, in TlsQuicFrame frame)
{
    if ((frame.RawType & TlsQuicFrames.DatagramLengthBit) == 0)
    {
        throw new ArgumentException(
            "Only the length-bearing DATAGRAM form (0x31) is sent.", nameof(frame));
    }
    QuicVariableLengthInteger.Write(destination, frame.RawType);          // QuicVariableLengthInteger.cs:70
    QuicVariableLengthInteger.Write(destination, (ulong)frame.Data.Length);
    WriteBytes(destination, frame.Data);                                  // as TlsQuicConnectionFrames.cs:1154 does
}
``` Replace the throw arm in `TlsQuicFrames.cs:1000-1012` with:

```csharp
case TlsQuicFrameType.Datagram:
    TlsQuicConnectionFrames.WriteDatagramFrameFields(destination, frame);
    return;
```

and delete the stale remark above it at `:995` ("parsed and dropped, never sent"). `MeasureFrame` (`:663`) goes through `WriteFrame` into a scratch list, so it needs no change; the test pins that.

- [ ] **Step 4: Run, expect pass**

Same command. Expected: `Passed!`.

- [ ] **Step 5: Commit**

```bash
git add SharpTls/src/SharpTls/Quic/TlsQuicFrames.cs SharpTls/src/SharpTls/Quic/TlsQuicConnectionFrames.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicFramesTests.cs
git commit -m "feat(quic): write RFC 9221 DATAGRAM frames in their length-bearing form" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 3: Outbound datagram FIFO and the packet arm

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicConnection.cs` (fields near `_receivedDatagrams` at line 1059; `OneRttPacketOverhead` at line 1606)
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicApplicationSendPath.cs:600-660` (`TryBuildApplicationPacket`, between the PATH_RESPONSE arm and the stream block)
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicConnectionDatagramTests.cs`

- [ ] **Step 1: Write the failing tests**

```csharp
[Fact]
public async Task AQueuedDatagramLeavesAsOneLengthBearingDatagramFrameAndNothingElse()
{
    using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(
        cancellation.Token, flowControl: [.. TlsQuicConnectionTests.FlowControlParameters(), TlsQuicTransportParameter.VariableInteger(0x20, 65535)]);
    var payload = Enumerable.Range(0, 300).Select(i => (byte)i).ToArray();

    Assert.True(harness.Connection.TryQueueDatagram(payload));
    Assert.Equal(1, harness.Connection.QueuedDatagrams);
    Assert.True(await harness.Connection.SendPendingAsync(cancellation.Token));
    Assert.Equal(0, harness.Connection.QueuedDatagrams);

    await harness.Peer.PumpOnceAsync(SentAt, cancellation.Token); // see Harness for SentAt
    var frames = harness.Peer.LastDatagramFrames; // the (Level, Type) list, LoopbackQuicPeer.cs:510
    Assert.Contains(frames, f => f.Type == TlsQuicFrameType.Datagram);
    Assert.DoesNotContain(frames, f => f.Type == TlsQuicFrameType.Stream);
    Assert.Equal(payload, harness.Peer.ReceivedDatagrams.Single());
}
```

`LoopbackQuicPeer` records only `(Level, Type)` per frame today (`LoopbackQuicPeer.cs:515-519`). This task adds `internal List<byte[]> ReceivedDatagrams { get; } = [];` beside `ReceivedStreamFrames` (`:493`) and appends `frame.Data.ToArray()` where the peer's frame loop meets `TlsQuicFrameType.Datagram`. Tasks 5 and 8 rely on it.

```csharp

[Fact]
public async Task TheQueueRefusesTheSixtyFifthDatagramAndNeverDrops()
{
    using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(
        cancellation.Token, flowControl: [.. TlsQuicConnectionTests.FlowControlParameters(), TlsQuicTransportParameter.VariableInteger(0x20, 65535)]);

    for (var i = 0; i < 64; i++)
    {
        Assert.True(harness.Connection.TryQueueDatagram(new byte[] { (byte)i }));
    }
    Assert.False(harness.Connection.TryQueueDatagram(new byte[] { 0xFF }));
    Assert.Equal(64, harness.Connection.QueuedDatagrams);
}

[Fact]
public async Task QueueingIsRefusedByNameWhenThePeerAcceptsNoDatagrams()
{
    using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(cancellation.Token);

    var exception = Assert.Throws<InvalidOperationException>(
        () => harness.Connection.TryQueueDatagram(new byte[] { 1 }));
    Assert.Contains("max_datagram_frame_size", exception.Message);
}

[Fact]
public async Task APayloadAboveTheFrameCeilingIsRefusedByName()
{
    using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(
        cancellation.Token, flowControl: [.. TlsQuicConnectionTests.FlowControlParameters(), TlsQuicTransportParameter.VariableInteger(0x20, 65535)]);
    var ceiling = harness.Connection.MaximumDatagramFramePayload;

    Assert.True(ceiling >= 1200, $"ceiling {ceiling}");
    Assert.Throws<ArgumentOutOfRangeException>(
        () => harness.Connection.TryQueueDatagram(new byte[ceiling + 1]));
}

[Fact]
public async Task ACongestionBlockedWindowHoldsDatagramsAndReleasesThemInOrder()
{
    // The blocked-window tests (TlsQuicConnectionRetransmissionTests.cs:1479, :1573) close the
    // window with ScriptedSendGate { Open = false } (private at :2076; make it internal) plugged
    // in through RetransmittingProbeSpec -> Recovery.CongestionController. Harness.CreateAsync
    // gains `TlsQuicConnectionSpec? connectionSpec = null`, passed to the Connection(...)
    // overload it already calls (TlsQuicConnectionTests.cs:1115).
    using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    var gate = new ScriptedSendGate { Open = false };
    using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(
        cancellation.Token,
        connectionSpec: RetransmittingProbeSpec(gate),   // the retransmission tests' builder; make it internal
        flowControl: [.. TlsQuicConnectionTests.FlowControlParameters(), TlsQuicTransportParameter.VariableInteger(0x20, 65535)]);

    Assert.True(harness.Connection.TryQueueDatagram(new byte[] { 1 }));
    Assert.True(harness.Connection.TryQueueDatagram(new byte[] { 2 }));
    Assert.False(await harness.Connection.SendPendingAsync(cancellation.Token)); // window shut
    Assert.Equal(2, harness.Connection.QueuedDatagrams);

    gate.Open = true;
    Assert.True(await harness.Connection.SendPendingAsync(cancellation.Token));
    Assert.True(await harness.Connection.SendPendingAsync(cancellation.Token));
    Assert.Equal(0, harness.Connection.QueuedDatagrams);

    await harness.Peer.PumpOnceAsync(SentAt, cancellation.Token);
    await harness.Peer.PumpOnceAsync(SentAt, cancellation.Token);
    Assert.Equal([new byte[] { 1 }, new byte[] { 2 }], harness.Peer.ReceivedDatagrams);
}

[Fact]
public void ALostDatagramFrameIsDroppedNotRepaired() =>
    // RFC 9221 s5.2; TlsQuicLossDetection.ActionFor at :1248 already answers Drop and no test pins it.
    Assert.Equal(TlsQuicLossAction.Drop, TlsQuicLossDetection.ActionFor(TlsQuicFrameType.Datagram)); // check the enum's and method's exact names at :1248
```

`SentAt` is `private static` per test class in this suite (`LoopbackQuicPeerTests.cs:26`); declare the same member in this class. If the handshake itself needs the gate open (the Initial and Handshake packets go through the same controller), create the gate with `Open = true`, run `CreateAsync`, then set `Open = false` before queueing.

- [ ] **Step 2: Run, expect compile failure on `TryQueueDatagram`**

- [ ] **Step 3: Implement the FIFO on `TlsQuicConnection`**

Beside `_receivedDatagrams` (line 1059):

```csharp
// RFC 9221 s5.4 lets a sender delay or drop when it cannot send; this library delays. The
// bound is small on purpose: an inner QUIC stack behind a MASQUE tunnel keeps its own send
// pacing, so a queue that fills means the OUTER path is congested and the right answer is
// backpressure, not memory.
private const int DatagramQueueBound = 64;
private readonly Queue<byte[]> _datagramsToSend = new();

internal int QueuedDatagrams => _datagramsToSend.Count;

/// <summary>The largest DATAGRAM frame payload one 1-RTT packet at the current path MTU
/// carries: the packet budget minus the short header, DCID, largest packet number, AEAD tag,
/// frame type and a two-byte length, further bounded by the peer's
/// <c>max_datagram_frame_size</c> (which counts type and length, RFC 9221 s3).</summary>
internal int MaximumDatagramFramePayload
{
    get
    {
        const int typeAndLength = 3;
        var packet = DatagramPayloadBudget - OneRttPacketOverhead - typeAndLength;
        if (PeerMaxDatagramFrameSize is not { } peer)
        {
            return 0;
        }
        var byPeer = (int)Math.Min(peer, int.MaxValue) - typeAndLength;
        return Math.Max(0, Math.Min(packet, byPeer));
    }
}

/// <summary>Queues one DATAGRAM frame payload; <see langword="false"/> means the queue is
/// full and the caller must wait for <see cref="SendPendingAsync"/> to drain it.</summary>
internal bool TryQueueDatagram(ReadOnlyMemory<byte> payload)
{
    if (PeerMaxDatagramFrameSize is null)
    {
        throw new InvalidOperationException(
            "The peer advertised no max_datagram_frame_size (RFC 9221 s3), so it accepts no "
            + "DATAGRAM frames on this connection.");
    }
    var ceiling = MaximumDatagramFramePayload;
    if (payload.Length > ceiling)
    {
        throw new ArgumentOutOfRangeException(
            nameof(payload), payload.Length,
            $"A DATAGRAM frame payload on this connection is at most {ceiling} bytes.");
    }
    if (_datagramsToSend.Count >= DatagramQueueBound)
    {
        return false;
    }
    _datagramsToSend.Enqueue(payload.ToArray());
    return true;
}
```

`DatagramPayloadBudget` is at `TlsQuicConnection.cs:1337` and `OneRttPacketOverhead` at `:1605`; both are members of the same class the send-path partial extends.

- [ ] **Step 4: Implement the packet arm**

In `TryBuildApplicationPacket`, after the PATH_RESPONSE arm and BEFORE `if (_streams is { } streams && streams.HasPendingFrames && SendGateAdmits(now))`:

```csharp
// ONE DATAGRAM FRAME PER PACKET, AND NO STREAM FRAME BESIDE IT (spec component 1). The
// frame is ack-eliciting (RFC 9221 s5.2) and never retransmitted: it is not registered
// with the stream retransmission bookkeeping, and a lost one is the inner connection's
// loss to recover, not ours.
var carriesDatagram = false;
if (_datagramsToSend.Count > 0 && SendGateAdmits(now))
{
    var budget = DatagramPayloadBudget - reservedBytes - OneRttPacketOverhead;
    foreach (var already in frames)
    {
        budget -= TlsQuicFrames.MeasureFrame(_frameMeasureScratch, already);
    }
    if (hasAck && !_options.Spec.AckLeadsInPacket)
    {
        budget -= TlsQuicFrames.MeasureFrame(_frameMeasureScratch, ack);   // the ACK appended below
    }
    var next = _datagramsToSend.Peek();
    if (next.Length + 3 <= budget)
    {
        frames.Add(new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Datagram | TlsQuicFrames.DatagramLengthBit,
            Data = _datagramsToSend.Dequeue(),
        });
        PathMtu.OnApplicationDataSent();
        carriesDatagram = true;
    }
}

if (!carriesDatagram && _streams is { } streams && streams.HasPendingFrames && SendGateAdmits(now))
```

(that is: the existing stream block gains the `!carriesDatagram &&` guard). `SendGateAdmits` counts a refusal per call; calling it twice in one build when both a datagram and stream data are pending double-counts `SendsRefusedByCongestionWindow` only in the refused case; if a test in `TlsQuicApplicationSendPathTests` pins that counter, evaluate the gate once into a local and reuse it.

Two RFC 9221 s5.2 rules are already satisfied by existing code; verify, do not re-implement: `TlsQuicPacketBuilder.IsAckEliciting` (`:862`) excludes only PADDING, ACK and CONNECTION_CLOSE, so a DATAGRAM frame is ack-eliciting; `TlsQuicLossDetection.ActionFor` maps `Datagram => Drop` (`:1248`) and `RecordRepairable` skips `Drop` (`:735`), so a lost DATAGRAM frame is never retransmitted. `SendPendingAsync` reports whether a packet went out, so a datagram-only packet returns true.

- [ ] **Step 5: Run the datagram tests and the send-path suite**

Run: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~TlsQuicConnectionDatagramTests|FullyQualifiedName~TlsQuicApplicationSendPath|FullyQualifiedName~TlsQuicConnectionTests|FullyQualifiedName~TlsQuicFramesTests"`
Expected: all pass, including the `ALostDatagramFrameIsDroppedNotRepaired` unit fact. An empty `[Fact]` passes vacuously and is forbidden in this plan.

- [ ] **Step 6: Commit**

```bash
git add SharpTls/src/SharpTls/Quic/TlsQuicConnection.cs SharpTls/src/SharpTls/Quic/TlsQuicApplicationSendPath.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicConnectionDatagramTests.cs SharpTls/tests/SharpTls.Tests/Quic/LoopbackQuicPeer.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ConnectionTests.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicConnectionRetransmissionTests.cs
git commit -m "feat(quic): send DATAGRAM frames from a bounded, congestion-gated queue" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 4: Extended CONNECT

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Request.cs:342` (CONNECT LIMITATION remark), `:508-530` (init properties), `:856-870` (emit loop)
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Spec.cs:215` (add `EnableConnectProtocolIdentifier`)
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Connection.cs:17-30` (`TlsQuicHttp3RequestRefusal`), `:595-640` (`TryOpenRequest`)
- Modify: `TlsClient-main/src/TlsClient/Http3Connection.cs:1065-1110` (`Describe` switch on the refusal)
- Modify: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ConnectionTests.cs:2418` (`PeerControl` → `internal static`), `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3RequestTests.cs:1335,1355` (`ReadFrames`, `DecodeFieldSection` → `internal static`)
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ExtendedConnectTests.cs` (new)

- [ ] **Step 1: Write the failing tests**

```csharp
using System.Collections.Immutable;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicHttp3ExtendedConnectTests
{
    private static TlsQuicHttp3Request ConnectUdp() => new()
    {
        Method = "CONNECT",
        Protocol = "connect-udp",
        Scheme = "https",
        Authority = "masque.example:50000",
        Path = "/.well-known/masque/udp/target.example/443/",
        Fields =
        [
            new TlsQuicHttp3Field("proxy-authorization", "Basic dXNlcjpwYXNz"),
            new TlsQuicHttp3Field("capsule-protocol", "?1"),
        ],
    };

    // TryEncode writes a HEADERS frame; its callers decode with
    // DecodeFieldSection(Assert.Single(ReadFrames(encoded)).Payload) (TlsQuicHttp3RequestTests.cs:184,
    // :365; ReadFrames at :1335, DecodeFieldSection at :1355). Make both helpers internal static.
    private static ImmutableArray<TlsQuicHttp3Field> Decode(List<byte> encoded) =>
        TlsQuicHttp3RequestTests.DecodeFieldSection(
            Assert.Single(TlsQuicHttp3RequestTests.ReadFrames(encoded)).Payload);

    [Fact]
    public void TheProtocolPseudoHeaderFollowsTheMethodWhateverTheOrder()
    {
        var encoded = new List<byte>();
        Assert.True(ConnectUdp().TryEncode(encoded, new TlsQuicHttp3Spec(), out _)); // same call the request tests make at :184
        var fields = Decode(encoded);

        Assert.Equal(
            [":method", ":protocol", ":scheme", ":authority", ":path", "proxy-authorization", "capsule-protocol"],
            fields.Select(f => f.Name).ToArray());
        Assert.Equal("connect-udp", fields[1].Value);
    }

    [Fact]
    public void ARequestWithoutProtocolStillHasNoProtocolLine()
    {
        var get = new TlsQuicHttp3Request { Method = "GET", Scheme = "https", Authority = "a", Path = "/" };
        var encoded = new List<byte>();
        Assert.True(get.TryEncode(encoded, new TlsQuicHttp3Spec(), out _));
        Assert.DoesNotContain(Decode(encoded), f => f.Name == ":protocol");
    }

    [Fact]
    public async Task TheConnectionRefusesExtendedConnectUntilThePeerEnablesIt()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(cancellation.Token);
        // Harness.CreateAsync sends no peer SETTINGS at all; the peer's list is empty here.

        var stream = harness.Http3.TryOpenRequest(ConnectUdp(), out var refusal, out _);

        Assert.Null(stream);
        Assert.Equal(TlsQuicHttp3RequestRefusal.ExtendedConnectNotEnabled, refusal);
    }

    [Fact]
    public async Task ThePeerEnablingItLetsTheRequestOpen()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await TlsQuicConnectionTests.Harness.CreateAsync(cancellation.Token);
        await harness.PeerSendsAsync(cancellation.Token, PeerControl(new TlsQuicHttp3Setting(0x08, 1)));
        Assert.True(harness.Http3.Streams.PeerSettingsReceived);   // TlsQuicHttp3Connection.cs:502, used at TlsQuicHttp3ConnectionTests.cs:216

        var stream = harness.Http3.TryOpenRequest(ConnectUdp(), out var refusal, out _);

        Assert.NotNull(stream);
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
    }
}
```

Peer SETTINGS reach the client through `harness.PeerSendsAsync(ct, PeerControl(...))` (`TlsQuicHttp3ConnectionTests.cs:279`). `PeerControl(params TlsQuicHttp3Setting[] settings)` already exists (`:2418`) and builds the server's control-stream bytes (stream type `0x00`, SETTINGS frame `0x04`, length, id/value pairs); do NOT add an overload (a second `params` overload makes every existing call ambiguous). Make it `internal static` so this class and Chunk 2's harness can call it. `PeerSendsAsync` pumps the client connection and runs `Http3.TryProcess` itself (`:2337-2342`), so no extra `PumpOnceAsync` follows it.

- [ ] **Step 2: Run, expect compile failures (`Protocol`, `ExtendedConnectNotEnabled`)**

- [ ] **Step 3: Implement**

`TlsQuicHttp3Request.cs`, after `Path`:

```csharp
/// <summary>RFC 9220 s3's <c>:protocol</c> for an extended CONNECT (RFC 8441 s4), for
/// example <c>connect-udp</c> (RFC 9298 s3). <see langword="null"/> for every other
/// request. When set, <c>:scheme</c> and <c>:path</c> are mandatory (the existing
/// validator's MandatoryPseudoHeaderOmitted covers that) and the line is emitted right
/// after <c>:method</c>, whatever <see cref="TlsQuicHttp3Spec.PseudoHeaderOrder"/> says,
/// because no spec lists it.</summary>
internal string? Protocol { get; init; }
```

Emit loop (line 856): the `lines.Add(order[i] switch { ... })` expression cannot add two lines from one arm, so restructure:

```csharp
for (var i = 0; i < order.Length; i++)
{
    switch (order[i])
    {
        case TlsQuicHttp3PseudoHeader.Method:
            lines.Add((MethodName, Encoding.UTF8.GetBytes(method)));
            if (Protocol is { } protocol)
            {
                lines.Add((ProtocolName, Encoding.UTF8.GetBytes(protocol)));
            }
            break;
        case TlsQuicHttp3PseudoHeader.Authority:
            lines.Add((AuthorityName, Encoding.UTF8.GetBytes(authority)));
            break;
        case TlsQuicHttp3PseudoHeader.Scheme:
            lines.Add((SchemeName, Encoding.UTF8.GetBytes(scheme)));
            break;
        default:
            lines.Add((PathName, Encoding.UTF8.GetBytes(path)));
            break;
    }
}
```

with `private static readonly byte[] ProtocolName = Encoding.UTF8.GetBytes(":protocol");` beside `PathName` (line 480). Keep the existing comment about the default arm. Rewrite the CONNECT LIMITATION remark at line 342: plain CONNECT (no `:scheme`/`:path`, RFC 9114 s4.4) is still refused by the validator; extended CONNECT carries both and is the one form this library sends.

`TlsQuicHttp3Spec.cs:215`, beside `H3DatagramIdentifier`:

```csharp
/// <summary>RFC 9220 s3's SETTINGS_ENABLE_CONNECT_PROTOCOL.</summary>
internal const ulong EnableConnectProtocolIdentifier = 0x08;
```

`TlsQuicHttp3RequestRefusal`: add `ExtendedConnectNotEnabled` with a summary citing RFC 8441 s3 ("upon receipt of SETTINGS_ENABLE_CONNECT_PROTOCOL ... a client MAY use") via RFC 9220 s3. In `TryOpenRequest`, after the `_opened` check and before encoding:

```csharp
if (request.Protocol is not null
    && TlsQuicHttp3Settings.Value(_streams.PeerSettings, TlsQuicHttp3Spec.EnableConnectProtocolIdentifier) != 1)
{
    refusal = TlsQuicHttp3RequestRefusal.ExtendedConnectNotEnabled;
    return null;
}
```

The refusal-to-exception switch lives in `Http3Connection.Describe` (`TlsClient-main/src/TlsClient/Http3Connection.cs:1065-1110`; `SharpTlsHttp3Streams.Describe` only delegates to it). Add the arm `TlsQuicHttp3RequestRefusal.ExtendedConnectNotEnabled => new TlsHttpProtocolException("The peer did not send SETTINGS_ENABLE_CONNECT_PROTOCOL, so an extended CONNECT cannot be sent on this connection (RFC 8441 section 3).")` before its `_ =>` arm.

- [ ] **Step 4: Run, expect pass**

Run: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~TlsQuicHttp3ExtendedConnectTests|FullyQualifiedName~TlsQuicHttp3RequestTests"`.

- [ ] **Step 5: Commit**

```bash
git add SharpTls/src/SharpTls/Quic/TlsQuicHttp3Request.cs SharpTls/src/SharpTls/Quic/TlsQuicHttp3Spec.cs SharpTls/src/SharpTls/Quic/TlsQuicHttp3Connection.cs TlsClient-main/src/TlsClient/Http3Connection.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ExtendedConnectTests.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ConnectionTests.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3RequestTests.cs
git commit -m "feat(http3): extended CONNECT with :protocol, gated on the peer's setting" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 5: Datagram-carrying exchanges on `TlsQuicHttp3Connection`

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Connection.cs:415-424` (`Exchange`), `:595-720` (`TryOpenRequest`, the `fin: true` at 699), `:795-831` (datagram receive), `:925-945` (`Response.TryRead` site), plus new members
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Request.cs` (`TlsQuicHttp3Response.DiscardBody()` near `_body` at line 1418)
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3DatagramExchangeTests.cs` (new)

- [ ] **Step 1: Write the failing tests**

All six use one arrangement: `Harness.CreateAsync(ct, spec: new TlsQuicHttp3Spec { Settings = TestHttp3Settings.DatagramCapable }, flowControl: [.. FlowControlParameters(), TlsQuicTransportParameter.VariableInteger(0x20, 65535)])` (`DatagramCapable` at `TestHttp3Settings.cs:40` is QpackCapable plus 0x33 = 1; the harness's `maxDatagramFrameSize` default already puts 0x20 in the client hello), then `await harness.PeerSendsAsync(ct, PeerControl(new TlsQuicHttp3Setting(0x08, 1), new TlsQuicHttp3Setting(0x33, 1)))`. Put that in a private `static Task<Harness> ArrangeAsync(ct)`. Sending on a request stream from the peer uses `harness.PeerSendsAsync(ct, Stream(streamId, offset, bytes))`, where `Stream(ulong, ulong, byte[], bool fin = false)` builds the STREAM frame (private in `TlsQuicConnectionStreamTests.cs:786`; make it `internal static` and add that file to this task's commit), and `ResponseBytes(int status, (string, string)[] fields, byte[] body)` (`TlsQuicHttp3ConnectionTests.cs:2456`) builds HEADERS plus DATA for a response.

```csharp
public sealed class TlsQuicHttp3DatagramExchangeTests
{
    private static TlsQuicHttp3Request ConnectUdp() => TlsQuicHttp3ExtendedConnectTests.ConnectUdp(); // make it internal there

    [Fact]
    public async Task ADatagramExchangeSendsItsHeadersWithoutFin()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);

        var tunnel = harness.Http3.TryOpenRequest(ConnectUdp(), out _, out _, receivesDatagrams: true);
        var get = harness.Http3.TryOpenRequest(new TlsQuicHttp3Request { Method = "GET", Scheme = "https", Authority = "a", Path = "/" }, out _, out _);
        Assert.True(await harness.Connection.SendPendingAsync(cancellation.Token));
        await harness.Peer.PumpOnceAsync(SentAt, cancellation.Token);

        Assert.False(harness.Peer.ReceivedStreamFrames.Single(f => f.StreamId == tunnel!.Id).Fin);
        Assert.True(harness.Peer.ReceivedStreamFrames.Single(f => f.StreamId == get!.Id).Fin);
    }

    [Fact]
    public async Task ASentDatagramCarriesTheQuarterStreamIdAndNothingElse()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);
        var tunnel = harness.Http3.TryOpenRequest(ConnectUdp(), out _, out _, receivesDatagrams: true)!;
        await harness.FlushAsync(cancellation.Token); // the harness helper that sends and pumps the peer

        Assert.True(harness.Http3.TrySendDatagram(tunnel.Id, [0x00, 0xAA, 0xBB]));
        Assert.True(await harness.Connection.SendPendingAsync(cancellation.Token));
        await harness.Peer.PumpOnceAsync(SentAt, cancellation.Token);

        Assert.Equal([.. QuicVariableLengthInteger.Encode(tunnel.Id / 4), 0x00, 0xAA, 0xBB], harness.Peer.ReceivedDatagrams.Single());
    }

    [Fact]
    public async Task AReceivedDatagramForTheExchangeIsDrainedByItsStreamId()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);
        var tunnel = harness.Http3.TryOpenRequest(ConnectUdp(), out _, out _, receivesDatagrams: true)!;
        await harness.FlushAsync(cancellation.Token);

        await harness.Peer.SendOneRttRawFrameAsync(DatagramFrame(tunnel.Id / 4, [9, 8, 7]), cancellation.Token);
        Assert.True(await harness.Http3.PumpOnceAsync(cancellation.Token));

        Assert.Equal([new byte[] { 9, 8, 7 }], harness.Http3.DrainDatagrams(tunnel.Id));
        Assert.Empty(harness.Http3.DrainDatagrams(tunnel.Id));
    }

    [Fact]
    public async Task ADatagramForAnUnmarkedStreamIsCountedAndDropped()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);
        var get = harness.Http3.TryOpenRequest(new TlsQuicHttp3Request { Method = "GET", Scheme = "https", Authority = "a", Path = "/" }, out _, out _)!;
        await harness.FlushAsync(cancellation.Token);

        await harness.Peer.SendOneRttRawFrameAsync(DatagramFrame(get.Id / 4, [1]), cancellation.Token);
        Assert.True(await harness.Http3.PumpOnceAsync(cancellation.Token));

        Assert.Empty(harness.Http3.DrainDatagrams(get.Id));
        Assert.Equal(1UL, harness.Http3.DroppedDatagramsWrongStream);
    }

    [Fact]
    public async Task TheExchangeKeepsNoBodyBytes()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);
        var tunnel = harness.Http3.TryOpenRequest(ConnectUdp(), out _, out _, receivesDatagrams: true)!;
        await harness.FlushAsync(cancellation.Token);

        // A 200 followed by 100 body bytes on the tunnel's stream, no FIN. PeerSendsAsync pumps
        // and processes; do not pump again afterwards (an empty inbox blocks until the token).
        await harness.PeerSendsAsync(cancellation.Token, Stream(tunnel.Id, 0, ResponseBytes(200, [], new byte[100])));

        var response = harness.Http3.ResponseFor(tunnel.Id)!;
        Assert.Equal(200, response.Status);
        Assert.Equal(0, response.Body.Length);
        Assert.False(response.IsComplete);
    }

    [Fact]
    public async Task PeerSettingsAreForwarded()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await ArrangeAsync(cancellation.Token);

        Assert.True(harness.Http3.Streams.PeerSettingsReceived);
        Assert.Equal(1UL, TlsQuicHttp3Settings.Value(harness.Http3.PeerSettings, 0x08));
    }

    private static byte[] DatagramFrame(ulong quarterStreamId, byte[] payload)
    {
        var data = new List<byte>(QuicVariableLengthInteger.Encode(quarterStreamId));
        data.AddRange(payload);
        var frame = new List<byte> { 0x31 };
        frame.AddRange(QuicVariableLengthInteger.Encode((ulong)data.Count));
        frame.AddRange(data);
        return frame.ToArray();
    }
}
```

Every helper named here exists already or is made `internal static` in this task (`Stream`, `ResponseBytes`, `PeerControl`, `FlushAsync`); `DatagramFrame` is the one new one and is written above.

- [ ] **Step 2: Run, expect compile failures**

- [ ] **Step 3: Implement**

`Exchange`:

```csharp
private sealed class Exchange(TlsQuicStream stream, TlsQuicHttp3Response response, bool receivesDatagrams)
{
    internal TlsQuicStream Stream { get; } = stream;
    internal TlsQuicHttp3Response Response { get; } = response;
    internal bool ReceivesDatagrams { get; } = receivesDatagrams;
    internal List<byte[]> Datagrams { get; } = [];
    internal int Consumed;
    internal int Acknowledged;
}
```

`TryOpenRequest`: add a trailing parameter `bool receivesDatagrams = false`; pass it to `new Exchange(...)` at line 720; change line 699 to `_connection.Streams.Send(stream, frame.ToArray(), fin: !receivesDatagrams);` with a remark citing RFC 9297 s2.1 (no datagrams unless the send side is open) and RFC 9298 s3.1 (tunnel lifetime = request stream).

New members:

```csharp
internal bool PeerSettingsReceived => _streams.PeerSettingsReceived;
internal ImmutableArray<TlsQuicHttp3Setting> PeerSettings => _streams.PeerSettings;
internal ulong DroppedDatagramsWrongStream { get; private set; }

/// <summary>Takes every HTTP Datagram Payload (RFC 9297 s2.1) received for the exchange on
/// <paramref name="streamId"/> since the last call. Quarter stream id already stripped; any
/// RFC 9298 context id is still in front, because this layer does not know that RFC.</summary>
internal List<byte[]> DrainDatagrams(ulong streamId)
{
    foreach (var exchange in _exchanges)
    {
        if (exchange.Stream.Id == streamId && exchange.Datagrams.Count > 0)
        {
            var drained = new List<byte[]>(exchange.Datagrams);
            exchange.Datagrams.Clear();
            return drained;
        }
    }
    return [];
}

/// <summary>Queues an HTTP datagram on the exchange's stream: RFC 9297 s2.1's quarter
/// stream id then <paramref name="payload"/>. <see langword="false"/> when the connection's
/// DATAGRAM queue is full; the caller waits and retries after a send.</summary>
internal bool TrySendDatagram(ulong streamId, ReadOnlySpan<byte> payload)
{
    var quarter = QuicVariableLengthInteger.Encode(streamId / 4); // byte[] helper at QuicVariableLengthInteger.cs:175
    var datagram = new byte[quarter.Length + payload.Length];
    quarter.CopyTo(datagram, 0);
    payload.CopyTo(datagram.AsSpan(quarter.Length));
    return _connection.TryQueueDatagram(datagram);
}
```

Datagram receive (after the `quarterStreamId > MaximumQuarterStreamId` check, replacing the "payload goes nowhere" tail):

```csharp
var streamId = quarterStreamId * 4;
Exchange? target = null;
foreach (var exchange in _exchanges)
{
    if (exchange.Stream.Id == streamId && exchange.ReceivesDatagrams)
    {
        target = exchange;
        break;
    }
}
if (target is null)
{
    DroppedDatagramsWrongStream++;   // s2.1: silently dropped for a stream nothing reads
    continue;
}
target.Datagrams.Add(datagram[cursor..].ToArray());
```

Body drop, after the `Response.TryRead` call at line 936 succeeds:

```csharp
if (exchange.ReceivesDatagrams)
{
    exchange.Response.DiscardBody();
}
```

`TlsQuicHttp3Response.DiscardBody()` (`_body` is at `TlsQuicHttp3Request.cs:1422`): `internal void DiscardBody() => _body.Clear();` with a remark: a tunnel stream never FINs and its DATA frames are capsules nobody parses.

- [ ] **Step 4: Run, expect pass**

Run: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~TlsQuicHttp3DatagramExchangeTests|FullyQualifiedName~TlsQuicConnectionTests"`.

- [ ] **Step 5: Commit**

```bash
git add SharpTls/src/SharpTls/Quic/TlsQuicHttp3Connection.cs SharpTls/src/SharpTls/Quic/TlsQuicHttp3Request.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3DatagramExchangeTests.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ConnectionTests.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicConnectionStreamTests.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ExtendedConnectTests.cs
git commit -m "feat(http3): exchanges that send and receive HTTP datagrams on an open request stream" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 6: Proxy error values

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicSocks5Protocol.cs:11-32` (`TlsQuicProxyError`)
- Regenerate: `SharpTls/tests/SharpTls.Tests/Api/PublicApi.Shipped.txt`

- [ ] **Step 1: Add the members** after `RelayDeliveredTlsAlert`, each with a one-line summary from the spec's error table: `MasqueNotOffered`, `MasqueAuthenticationRejected`, `MasqueTargetRejected`, `MasqueTunnelRefused`, `MasqueTunnelClosed`. Widen the enum's summary at `TlsQuicSocks5Protocol.cs:10` ("Reasons a SOCKS5 proxy association failed") to cover MASQUE tunnels. The file mixes CRLF and LF; match the neighbouring lines.

- [ ] **Step 2: Regenerate the baseline and run its test**

```bash
dotnet run --project SharpTls/tools/SharpTls.ApiCompat > SharpTls/tests/SharpTls.Tests/Api/PublicApi.Shipped.txt
dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~PublicApiBaselineTests"
```
Expected: the diff of the baseline is exactly five `F:` lines; test passes.

- [ ] **Step 3: Commit**

```bash
git add SharpTls/src/SharpTls/Quic/TlsQuicSocks5Protocol.cs SharpTls/tests/SharpTls.Tests/Api/PublicApi.Shipped.txt
git commit -m "feat(quic): name the five MASQUE failure modes on TlsQuicProxyError" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Chunk 2: The transport

### Task 7: `TlsQuicMasqueOptions` and the dial

**Files:**
- Create: `SharpTls/src/SharpTls/Quic/TlsQuicMasqueOptions.cs`
- Create: `SharpTls/src/SharpTls/Quic/TlsQuicMasqueTransport.cs` (dial half)
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicMasqueTransportTests.cs` (new) with a `MasqueHarness` helper

The tests need an outer "proxy" peer: `MasqueHarness`, a new `internal sealed class` in `SharpTls/tests/SharpTls.Tests/Quic/MasqueHarness.cs`, built from the parts `TlsQuicConnectionTests.Harness` uses. Four facts shape it:

1. **Test seams on the options.** The transport must accept an already-built transport pair instead of opening a UDP socket: `TlsQuicMasqueOptions.OuterTransport` (the client half of `InMemoryDatagramTransport.CreatePair()`) and `OuterRemoteEndPoint` (the SERVER half's `LocalEndPoint`; `CreatePair` labels the server 127.0.0.1:443 and `SendAsync` silently drops anything addressed elsewhere, `InMemoryDatagramTransport.cs:63-64,111-115`). When `OuterTransport` is set, `ConnectAsync` uses `OuterRemoteEndPoint` as the remote endpoint and touches no DNS.
2. **The server needs the client's ODCID, which only exists once the dial started.** `Server(credential, odcid, ...)` (`TlsQuicConnectionTests.cs:1292`) puts it in `original_destination_connection_id` and the client validates it. So the harness starts `TlsQuicMasqueTransport.ConnectAsync(...)` as a task, waits until `clientTransport.Sent.Count > 0`, parses the long-header Destination Connection ID out of `Sent[0]` (byte 5 is the DCID length, the DCID follows; or use `TlsQuicPacketHeader.TryReadLongHeader`), then builds `Server(...)` and `LoopbackQuicPeer.ForServer(serverTransport, clientTransport.LocalEndPoint, server, Spec())`; the peer adopts connection ids from the first Initial (`LoopbackQuicPeer.cs:425-427`).
3. **The peer script is one sequential task and nothing else touches the peer while it runs.** Unlike `ConfirmedHandshake`, which drives client and peer alternately from one thread, here the client pumps itself inside `ConnectAsync`. The script: pump the peer until its handshake is complete, `SendHandshakeDoneAsync`, send `PeerControl(peerSettings)` with `SendStreamFramesAsync`, then pump until `ReceivedStreamFrames` holds a HEADERS frame on stream 0 (keep its bytes: Task 7's request test decodes them with `HeadersPayload` and `DecodeFieldSection`), and answer with `Stream(0, 0, ResponseBytes(answerStatus, [], []))`, or `Reset(0, 0, 0x10c)` when `answerWithReset` is set. `LoopbackQuicPeer` is not thread-safe: tests that later send raw frames (Task 8) do so only after `ConnectAsync` returned and the script task completed, and they pump the peer through `PumpPeerAsync` from the test thread.
4. **Visibility.** These `private static` helpers on the `TlsQuicConnectionTests` partial become `internal static` (word changes): `Server`, `Credential`, `Spec`, `SentAt` (`TlsQuicConnectionTests.cs`), `PeerControl(params TlsQuicHttp3Setting[])` (`TlsQuicHttp3ConnectionTests.cs:2418`, returns the stream-3 control frame carrying SETTINGS; Task 4 already made it internal), `HeadersPayload(byte[])` (`:2016`, strips the HEADERS frame out of stream bytes), `ResponseBytes(int status, (string, string)[] fields, byte[] body)` (`:2456`, builds response HEADERS plus DATA), `Reset(streamId, finalSize, code)` (`:898`, a RESET_STREAM frame), `Stream(id, offset, data, fin)` (`TlsQuicConnectionStreamTests.cs:786`), and `TlsQuicHttp3RequestTests.DecodeFieldSection` (`:1355`, internal after Task 4). `FlowControlParameters` is already internal (`:1340`).

`MasqueHarness.CreateAsync(ct, peerSettings: TlsQuicHttp3Setting[], serverMaxDatagramFrameSize: 65535, answerStatus: 200, answerWithReset: false, outerSpec: null)` returns a `MasqueHarness` object, not a bare transport: `Transport` (the `TlsQuicMasqueTransport`, or the exception `ConnectAsync` threw is rethrown after the peer task was awaited so its own failure is visible), `Peer` (the `LoopbackQuicPeer`, for `ReceivedStreamFrames`, `ReceivedDatagrams`, `SendOneRttRawFrameAsync`, `LastConnectionClose`), `ClientTransport` (the in-memory client half, for `Sent`), and `PumpPeerAsync(ct)`, which pumps the peer once per datagram the client has sent since the last call and never on an empty inbox (the `_peerConsumed` pattern of `Harness`, `TlsQuicHttp3ConnectionTests.cs:2055-2058, 2144-2158`; `Peer.PumpOnceAsync` blocks otherwise). `answerWithReset: true` makes the script send `Reset(0, 0, 0x10c)` instead of the HEADERS answer. `outerSpec` replaces the default outer spec (the congestion test passes one whose `Recovery = new TlsQuicRecoverySpec { CongestionController = () => gate }`, Task 3's technique, with the gate `Open = true` for the handshake and closed only after `CreateAsync` returned). The harness polls `ClientTransport.Sent.Count` from its own task with a short `Task.Delay` while the client's `ConnectAsync` task appends to that plain list (`InMemoryDatagramTransport.cs:52,124`); reading `Count` and `[0]` of a list that only grows is benign, and the harness reads nothing else from it. `PumpPeerAsync` passes `SentAt` to `Peer.PumpOnceAsync(sentAt, ct)` (`LoopbackQuicPeer.cs:578`). `serverMaxDatagramFrameSize` is `ulong?`: null omits the 0x20 entry from `Server(flowControl:)`, which the "no 0x20" half of `AProxyWithoutDatagramsIsRefusedByName` needs. Both new source files and the harness need `using SharpTls;` (`ClientHelloBuilder` and `TlsQuicClientHelloProfileFactory` live in that namespace).

The outer specs the tests use:

```csharp
OuterSpec = new TlsQuicConnectionSpec
{
    PathMtuDiscovery = false,
    BasePathMtu = 1392,
    MaximumPathMtu = 1392,
    DestinationConnectionIdLength = 8,
    TransportParameters = new TlsQuicTransportParameterSpec
    {
        Parameters =
        [
            .. TlsQuicTransportParameterSpec.RfcMinimumParameters,                      // :343
            TlsQuicTransportParameterSlot.Literal(0x20, [0x80, 0x00, 0xFF, 0xFF]),     // :81; 65535
        ],
    },
},
OuterHttp3Spec = new TlsQuicHttp3Spec { Settings = TestHttp3Settings.DatagramCapable },
ConfigureOuterClientHello = _ => { },   // the factory applies its own defaults when the hook adds nothing
DangerouslySkipOuterCertificateValidation = true,   // TestPki's root is not machine-trusted; copy what Harness does
```

`TlsQuicConnectionSpec.TransportParameters` is a `TlsQuicTransportParameterSpec` (`TlsQuicConnectionSpec.cs:1062`); the factory composes it with the source connection id (`TlsQuicClientHelloProfileFactory.cs:205-219`). Without the 0x20 entry the `TlsQuicHttp3Connection` constructor throws (`:474-491`).

- [ ] **Step 1: Write the options file**

```csharp
using System.Net;

namespace SharpTls.Quic;

/// <summary>Everything one MASQUE tunnel needs (RFC 9298 CONNECT-UDP over HTTP/3). Internal,
/// like the spec types it carries; TlsClient reaches it through InternalsVisibleTo.</summary>
internal sealed class TlsQuicMasqueOptions
{
    /// <summary>The proxy's QUIC listener, for example masque.oxylabs.io:50000.</summary>
    public required DnsEndPoint ProxyEndPoint { get; init; }

    /// <summary>The tunnel's target, written into the RFC 9298 s2 URI template.</summary>
    public required string TargetHost { get; init; }

    public required int TargetPort { get; init; }

    /// <summary>Echoed in every receive result; the inner connection never compares it.</summary>
    public required IPEndPoint TargetEndPoint { get; init; }

    public required string Username { get; init; }

    public required string Password { get; init; }

    /// <summary>The outer connection's spec: PMTUD off, BasePathMtu = MaximumPathMtu = 1392,
    /// TransportParameters carrying an explicit 0x20 entry.</summary>
    public required TlsQuicConnectionSpec OuterSpec { get; init; }

    /// <summary>The outer HTTP/3 spec; its Settings carry SETTINGS_H3_DATAGRAM = 1.</summary>
    public required TlsQuicHttp3Spec OuterHttp3Spec { get; init; }

    /// <summary>Shapes the outer ClientHello; TlsClient passes its default.</summary>
    public required Action<ClientHelloBuilder> ConfigureOuterClientHello { get; init; }

    /// <summary>Bounds steps 1 to 4 of the dial as one deadline.</summary>
    public TimeSpan HandshakeDeadline { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Tests only: an already-connected outer transport, so no socket is opened,
    /// and the endpoint it must address (an in-memory pair drops anything else).</summary>
    internal ITlsQuicDatagramTransport? OuterTransport { get; init; }

    internal IPEndPoint? OuterRemoteEndPoint { get; init; }

    /// <summary>Tests only: skips certificate validation on the outer connection.</summary>
    internal bool DangerouslySkipOuterCertificateValidation { get; init; }
}
```

- [ ] **Step 2: Write the failing dial tests**

```csharp
public sealed class TlsQuicMasqueTransportTests
{
    [Fact] public async Task AProxyWithoutExtendedConnectIsRefusedByName()
    // peer SETTINGS = QpackCapable + (0x33,1) only → TlsQuicProxyException.Error == MasqueNotOffered,
    // message contains "SETTINGS_ENABLE_CONNECT_PROTOCOL".

    [Fact] public async Task AProxyWithoutDatagramsIsRefusedByName()
    // SETTINGS with (0x08,1) but no (0x33,1) → MasqueNotOffered naming SETTINGS_H3_DATAGRAM;
    // and a server with no 0x20 transport parameter → MasqueNotOffered naming max_datagram_frame_size.

    [Theory]
    [InlineData(200, null)] [InlineData(201, null)]
    [InlineData(407, TlsQuicProxyError.MasqueAuthenticationRejected)]
    [InlineData(400, TlsQuicProxyError.MasqueTargetRejected)]
    [InlineData(503, TlsQuicProxyError.MasqueTunnelRefused)]
    public async Task TheConnectUdpStatusDecidesTheOutcome(int status, TlsQuicProxyError? expected)
    // AnswerConnectAsync(status); null expected → ConnectAsync returns a transport whose
    // MaxDatagramPayloadSize >= 1200; otherwise the named error, and for 503 the message contains "503".

    [Fact] public async Task TheConnectUdpRequestIsExactlyWhatTheGuideAsksFor()
    // harness.Peer.ReceivedStreamFrames.Single(f => f.StreamId == 0): Fin == false; decode with
    // DecodeFieldSection(HeadersPayload(frame.Data)): :method CONNECT, :protocol connect-udp,
    // :scheme https, :authority "proxy.test:50000", :path "/.well-known/masque/udp/target.test/443/",
    // proxy-authorization "Basic " + base64("user:pass"), capsule-protocol "?1", in that order.

    [Theory] [InlineData(65535, 1358)] [InlineData(1300, 1295)]
    public async Task TheCapacityIsTheOuterFramePayloadMinusFraming(ulong peerLimit, int expected)
    // Server 0x20 = peerLimit, OuterSpec with BasePathMtu = MaximumPathMtu = 1392 and an 8-byte
    // DestinationConnectionIdLength; assert MaxDatagramPayloadSize == expected (stream 0 → 1-byte
    // quarter stream id, 1-byte context id).

    [Fact] public async Task ACapacityBelowAnInitialIsRefusedByName()
    // peerLimit 1100 → MasqueNotOffered, message contains "1200".

    [Fact] public async Task AResetBeforeTheResponseIsATunnelClosed()
    // CreateAsync(ct, answerWithReset: true) → MasqueTunnelClosed with "0x10c" in the message.
}
```

Every test that reads the peer after `CreateAsync` (request bytes, datagrams, the close) calls `harness.PumpPeerAsync(ct)` first; a bare `Peer.PumpOnceAsync` on an empty inbox blocks until the token.

- [ ] **Step 3: Write the transport's dial half**

```csharp
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Channels;

namespace SharpTls.Quic;

/// <summary>An RFC 9298 CONNECT-UDP tunnel over HTTP/3, presented as the UDP-shaped
/// <see cref="ITlsQuicDatagramTransport"/> an inner QUIC connection dials through. One
/// instance is one tunnel on one outer connection. See docs/MASQUE-DATAGRAM-TRANSPORT.md.</summary>
internal sealed class TlsQuicMasqueTransport : ITlsQuicDatagramTransport
{
    private const int InnerInitialSize = 1200;          // RFC 9000 s14.1
    private const byte ContextIdUdpPayload = 0x00;      // RFC 9298 s4
    private const int ContextIdLength = 1;
    private const int OutboundBound = 64;

    private readonly TlsQuicConnection _connection;
    private readonly TlsQuicHttp3Connection _http3;
    private readonly ITlsQuicDatagramTransport _outer;
    private readonly ulong _streamId;
    private readonly IPEndPoint _targetEndPoint;
    private readonly Channel<byte[]> _outbound = Channel.CreateBounded<byte[]>(
        new BoundedChannelOptions(OutboundBound) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
    private readonly Channel<byte[]> _inbound = Channel.CreateUnbounded<byte[]>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private readonly CancellationTokenSource _lifetime = new();
    private Task? _owner;
    private CancellationTokenSource? _pumpInterrupt;
    private int _interruptRequests;
    private byte[]? _stalled;               // an outbound payload the FIFO refused; retried first
    private long _droppedWrongContext;
    private long _droppedOversize;
    private int _disposed;

    private TlsQuicMasqueTransport(
        TlsQuicConnection connection, TlsQuicHttp3Connection http3,
        ITlsQuicDatagramTransport outer, ulong streamId, IPEndPoint targetEndPoint)
    {
        _connection = connection;
        _http3 = http3;
        _outer = outer;
        _streamId = streamId;
        _targetEndPoint = targetEndPoint;
        MaxDatagramPayloadSize = connection.MaximumDatagramFramePayload
            - QuicVariableLengthInteger.Encode(streamId / 4).Length
            - ContextIdLength;
    }

    public int MaxDatagramPayloadSize { get; }

    internal string DropSummary =>
        $"{_droppedWrongContext} datagram(s) dropped for a context id other than 0, "
        + $"{_droppedOversize} for exceeding {MaxDatagramPayloadSize} bytes inbound; "
        + $"{_http3.DroppedDatagramsWrongStream} for a stream nothing reads.";

    public static async Task<TlsQuicMasqueTransport> ConnectAsync(
        TlsQuicMasqueOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(options.HandshakeDeadline);
        var ct = deadline.Token;

        ITlsQuicDatagramTransport? outer = options.OuterTransport;
        TlsQuicConnection? connection = null;
        TlsQuicHttp3Connection? http3Owned = null;
        try
        {
            // Step 1: outer QUIC connection.
            IPEndPoint proxy;
            if (outer is null)
            {
                var addresses = await Dns.GetHostAddressesAsync(options.ProxyEndPoint.Host, ct).ConfigureAwait(false);
                if (addresses.Length == 0)
                {
                    throw new TlsQuicProxyException(TlsQuicProxyError.MasqueTunnelRefused,
                        $"'{options.ProxyEndPoint.Host}' resolved to no address.");
                }
                proxy = new IPEndPoint(addresses[0], options.ProxyEndPoint.Port);
                outer = TlsQuicUdpDatagramTransport.Create(proxy.AddressFamily);
            }
            else
            {
                proxy = options.OuterRemoteEndPoint
                    ?? throw new ArgumentException("OuterTransport needs OuterRemoteEndPoint.", nameof(options));
            }

            var factory = new TlsQuicClientHelloProfileFactory
            {
                ConnectionSpec = options.OuterSpec,
                AlpnProtocols = ["h3"],
                Tls = options.ConfigureOuterClientHello,
            };
            connection = new TlsQuicConnection(
                new TlsQuicConnectionOptions(outer, proxy, options.OuterSpec)
                {
                    HandshakeDeadline = options.HandshakeDeadline,
                },
                sourceConnectionId =>
                {
                    var client = new CustomTlsQuicClientOptions
                    {
                        ServerName = options.ProxyEndPoint.Host,
                        ServerPort = options.ProxyEndPoint.Port,
                        ClientHello = factory.Create(sourceConnectionId.Span),
                    };
                    client.CertificateValidation.DangerouslySkipServerCertificateValidation =
                        options.DangerouslySkipOuterCertificateValidation;
                    return new CustomTlsQuicClient(client);   // mirror Http3Connection.CreateTlsClient exactly
                });
            await connection.ConnectAsync(ct).ConfigureAwait(false);

            // Step 2: the proxy must offer extended CONNECT and datagrams.
            var http3 = new TlsQuicHttp3Connection(connection, options.OuterHttp3Spec);
            http3Owned = http3;
            http3.OpenLocalStreams();
            await connection.SendPendingAsync(ct).ConfigureAwait(false);
            while (!http3.PeerSettingsReceived)
            {
                await PumpOrThrowAsync(http3, ct).ConfigureAwait(false);
            }
            RequireSetting(http3, TlsQuicHttp3Spec.EnableConnectProtocolIdentifier, "SETTINGS_ENABLE_CONNECT_PROTOCOL");
            RequireSetting(http3, TlsQuicHttp3Spec.H3DatagramIdentifier, "SETTINGS_H3_DATAGRAM");
            if (connection.PeerMaxDatagramFrameSize is null)
            {
                throw new TlsQuicProxyException(TlsQuicProxyError.MasqueNotOffered,
                    "The proxy's transport parameters carry no max_datagram_frame_size (RFC 9221 s3), so it accepts no DATAGRAM frames.");
            }

            // Step 3: CONNECT-UDP.
            var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{options.Username}:{options.Password}"));
            var request = new TlsQuicHttp3Request
            {
                Method = "CONNECT",
                Protocol = "connect-udp",
                Scheme = "https",
                Authority = $"{options.ProxyEndPoint.Host}:{options.ProxyEndPoint.Port}",
                Path = $"/.well-known/masque/udp/{Uri.EscapeDataString(options.TargetHost)}/{options.TargetPort}/",
                Fields =
                [
                    new TlsQuicHttp3Field("proxy-authorization", $"Basic {credentials}"),
                    new TlsQuicHttp3Field("capsule-protocol", "?1"),
                ],
            };
            var stream = http3.TryOpenRequest(request, out var refusal, out var malformed, receivesDatagrams: true)
                ?? throw new TlsQuicProxyException(TlsQuicProxyError.MasqueTunnelRefused,
                    $"The CONNECT-UDP request could not be sent: {refusal}/{malformed}.");
            await connection.SendPendingAsync(ct).ConfigureAwait(false);

            // Step 4: the response.
            TlsQuicHttp3Response response;
            while (true)
            {
                response = http3.ResponseFor(stream.Id)
                    ?? throw new TlsQuicProxyException(TlsQuicProxyError.MasqueTunnelClosed, "The tunnel exchange vanished before a response.");
                if (response.IsReset)
                {
                    throw new TlsQuicProxyException(TlsQuicProxyError.MasqueTunnelClosed,
                        $"The proxy reset the CONNECT-UDP stream with error 0x{response.ResetErrorCode:x} before answering.");
                }
                if (response.Status >= 0)
                {
                    break;
                }
                await PumpOrThrowAsync(http3, ct).ConfigureAwait(false);
            }
            switch (response.Status)
            {
                case >= 200 and <= 299:
                    break;
                case 407:
                    throw new TlsQuicProxyException(TlsQuicProxyError.MasqueAuthenticationRejected,
                        "The MASQUE proxy answered 407: credentials refused or the account's traffic limit reached.");
                case 400:
                    throw new TlsQuicProxyException(TlsQuicProxyError.MasqueTargetRejected,
                        $"The MASQUE proxy answered 400 for target {options.TargetHost}:{options.TargetPort}.");
                default:
                    throw new TlsQuicProxyException(TlsQuicProxyError.MasqueTunnelRefused,
                        $"The MASQUE proxy answered {response.Status} to CONNECT-UDP.");
            }

            // The floor is checked before anything owning channels or a CTS is built.
            var capacity = connection.MaximumDatagramFramePayload
                - QuicVariableLengthInteger.Encode(stream.Id / 4).Length
                - ContextIdLength;
            if (capacity < InnerInitialSize)
            {
                throw new TlsQuicProxyException(TlsQuicProxyError.MasqueNotOffered,
                    $"The tunnel carries at most {capacity} bytes per datagram, below the {InnerInitialSize} an inner Initial needs (peer max_datagram_frame_size {connection.PeerMaxDatagramFrameSize}).");
            }
            var transport = new TlsQuicMasqueTransport(connection, http3, outer, stream.Id, options.TargetEndPoint);
            transport._owner = Task.Run(transport.RunAsync);   // Task 8
            http3Owned = null;
            connection = null;
            outer = null;
            return transport;
        }
        catch (Exception exception) when (
            (exception is OperationCanceledException && deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            || exception is TimeoutException)
        {
            // Two clocks run to the same value: this method's linked deadline and the outer
            // TlsQuicConnection's own HandshakeDeadline, which throws TimeoutException
            // (TlsQuicConnection.cs:5181). Whichever fires first is the same fact.
            // TlsQuicProxyException has one constructor, (error, message); the cause rides in
            // the text, the shape Closed(...) below uses too.
            throw new TlsQuicProxyException(TlsQuicProxyError.MasqueTunnelRefused,
                $"The MASQUE tunnel did not come up within {options.HandshakeDeadline} ({exception.GetType().Name}: {exception.Message}).");
        }
        finally
        {
            // A refused dial says goodbye: the proxy should not hold a half-open connection
            // until its idle timeout. Best effort, never a second exception.
            if (http3Owned is not null)
            {
                try { await http3Owned.CloseAsync(TlsQuicHttp3ErrorCode.H3NoError, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception) { }
            }
            if (connection is not null)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }
            if (outer is not null && outer != options.OuterTransport)
            {
                await outer.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static void RequireSetting(TlsQuicHttp3Connection http3, ulong identifier, string name)
    {
        if (TlsQuicHttp3Settings.Value(http3.PeerSettings, identifier) != 1)
        {
            throw new TlsQuicProxyException(TlsQuicProxyError.MasqueNotOffered,
                $"The proxy's SETTINGS carry no {name} = 1, so it does not offer CONNECT-UDP.");
        }
    }

    private static async ValueTask PumpOrThrowAsync(TlsQuicHttp3Connection http3, CancellationToken ct)
    {
        if (!await http3.PumpOnceAsync(ct).ConfigureAwait(false))
        {
            throw new TlsQuicProxyException(TlsQuicProxyError.MasqueTunnelClosed,
                $"The outer HTTP/3 connection failed with error 0x{http3.ConnectionErrorCode:x}.");
        }
    }
}
```

Check against the code, not this listing: `CustomTlsQuicClient`'s constructor (see `Http3Connection.CreateTlsClient` at `Http3Connection.cs:1161`), `TlsQuicUdpDatagramTransport.Create(AddressFamily)` (`:45`), `TlsQuicConnectionOptions.HandshakeDeadline` is `init` (`TlsQuicConnectionOptions.cs:157-166`), `TlsQuicHttp3Response.ResetErrorCode` (`TlsQuicHttp3Request.cs:1586`), `TlsQuicHttp3ErrorCode.H3NoError = 0x100` (`TlsQuicHttp3Frames.cs:47`; `None` is 0 and is not H3_NO_ERROR). `QuicVariableLengthInteger.Encode` is at `QuicVariableLengthInteger.cs:175`. `ResponseFor` never returns null for an exchange this connection opened (`_exchanges` is never trimmed), so the "vanished" arm is defensive only. The `ReceiveAsync`/`SendAsync`/`DisposeAsync` members come in Task 8; until then stub them to throw `NotImplementedException` so this task compiles.

- [ ] **Step 3b: Run, expect compile failures** (`TlsQuicMasqueOptions`, `TlsQuicMasqueTransport` unknown) before Step 3's code lands; after it, the tests compile and the dial tests run.

- [ ] **Step 4: Run the dial tests, expect pass**

Run: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~TlsQuicMasqueTransportTests"`.

- [ ] **Step 5: Commit**

```bash
git add SharpTls/src/SharpTls/Quic/TlsQuicMasqueOptions.cs SharpTls/src/SharpTls/Quic/TlsQuicMasqueTransport.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicMasqueTransportTests.cs
git commit -m "feat(quic): dial a MASQUE CONNECT-UDP tunnel and judge the proxy's answer by name" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 8: Owner task, channels, and the transport surface

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicMasqueTransport.cs`
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicMasqueTransportTests.cs`

- [ ] **Step 1: Write the failing tests**

```csharp
[Fact] public async Task ASentPayloadReachesThePeerAsAContextZeroHttpDatagram()
// After a 200: SendAsync(any endpoint, [0xC0, 1, 2, 3]); pump the peer from the test thread;
// peer.ReceivedDatagrams (the payload list Task 3 added to LoopbackQuicPeer; a hard
// prerequisite here) ends with [varint(streamId/4), 0x00, 0xC0, 1, 2, 3].

[Fact] public async Task APeerDatagramReachesReceiveAsyncWithoutItsFraming()
// Peer sends raw DATAGRAM frame [varint(streamId/4), 0x00, 9, 8, 7]; ReceiveAsync returns
// Length 3, buffer [9,8,7], RemoteEndPoint == TargetEndPoint.

[Fact] public async Task ANonZeroContextIdIsDroppedAndCounted()
// Peer sends [varint(qsid), 0x02, 1]; a following context-0 datagram is what ReceiveAsync
// returns, and DropSummary starts with "1 datagram(s) dropped for a context id other than 0".

[Fact] public async Task AnOversizePayloadIsRefusedByNameNotDropped()
// SendAsync with MaxDatagramPayloadSize + 1 bytes → ArgumentOutOfRangeException naming the ceiling.

[Fact] public async Task SendAwaitsWhenTheOuterIsCongestionBlocked()
// Block the outer window (outerSpec with a closed ScriptedSendGate, as in Task 3's test). A
// blocked outer absorbs 64 (connection FIFO) + 1 (_stalled) + 64 (outbound channel) = 129
// payloads before SendAsync awaits, so issue 130 SendAsync calls without awaiting; await the
// first 129 with a 5 s timeout (the owner drains them concurrently, so they complete
// eventually, not instantly), then assert the 130th's task is still pending after 200 ms;
// open the gate, await the 130th, PumpPeerAsync, and assert all 130 arrive at the peer in
// order (peer.ReceivedDatagrams from Task 3).

[Fact] public async Task AResetAfterTheResponseSurfacesAsTunnelClosedOnTheNextReceive()
// After 200 the peer sends RESET_STREAM (error 0x10c) for the request stream; ReceiveAsync throws
// TlsQuicProxyException with Error MasqueTunnelClosed and "0x10c" in the message; SendAsync
// afterwards throws the same.

[Fact] public async Task AnOuterConnectionCloseSurfacesAsTunnelClosed()
// Peer sends an application CONNECTION_CLOSE with H3_NO_ERROR as a raw frame:
// SendOneRttRawFrameAsync([0x1d, 0x41, 0x00, 0x00]) (type 0x1d, error 0x100 as a two-byte
// varint, empty reason). The owner's next SendPendingAsync/pump throws InvalidOperationException
// from EnsureSendable (TlsQuicApplicationSendPath.cs:450-470); the catch wraps it as
// MasqueTunnelClosed; next ReceiveAsync throws it.

[Fact] public async Task DisposeIsIdempotentAndClosesTheOuter()
// DisposeAsync twice; the peer's LastConnectionClose is an application close with 0x100.
```

- [ ] **Step 2: Implement**

```csharp
public int DatagramOverhead => 0;

public async ValueTask SendAsync(IPEndPoint destination, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
{
    // destination is ignored: the tunnel's target was fixed by the CONNECT-UDP request.
    if (payload.Length > MaxDatagramPayloadSize)
    {
        throw new ArgumentOutOfRangeException(nameof(payload), payload.Length,
            $"This MASQUE tunnel carries at most {MaxDatagramPayloadSize} bytes per datagram.");
    }
    var framed = new byte[ContextIdLength + payload.Length];
    framed[0] = ContextIdUdpPayload;
    payload.Span.CopyTo(framed.AsSpan(ContextIdLength));
    try
    {
        await _outbound.Writer.WriteAsync(framed, cancellationToken).ConfigureAwait(false);
    }
    catch (ChannelClosedException closed)
    {
        throw closed.InnerException as TlsQuicProxyException ?? Closed(closed);
    }
    InterruptPump();
}

public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
{
    byte[] datagram;
    try
    {
        datagram = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
    }
    catch (ChannelClosedException closed)
    {
        throw closed.InnerException as TlsQuicProxyException ?? Closed(closed);
    }
    datagram.CopyTo(buffer);   // never longer than MaxDatagramPayloadSize: the owner dropped larger ones
    return new TlsQuicDatagramReceiveResult(datagram.Length, _targetEndPoint);
}

private async Task RunAsync()
{
    try
    {
        while (!_lifetime.IsCancellationRequested)
        {
            // Outbound first, and ALL of it: SendPendingAsync builds one 1-RTT packet per call
            // and Task 3 puts one DATAGRAM frame per packet, so one call per iteration would
            // trickle an inner Initial flight at one datagram per proxy packet or timer. Refill
            // the FIFO, send, repeat until a send builds nothing (window shut or queue empty);
            // that is a bounded loop, never a hot one. The FIFO refuses when full, and a
            // refused payload waits in _stalled so the channel keeps its order.
            do
            {
                while (true)
                {
                    var next = _stalled;
                    if (next is null && !_outbound.Reader.TryRead(out next))
                    {
                        break;
                    }
                    if (!_http3.TrySendDatagram(_streamId, next))
                    {
                        _stalled = next;
                        break;
                    }
                    _stalled = null;
                }
            }
            while (await _connection.SendPendingAsync(_lifetime.Token).ConfigureAwait(false));

            // The pump blocks until the proxy sends or a timer fires; a writer interrupts it.
            using (var interrupt = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token))
            {
                // Interlocked.Exchange, not Volatile.Write: the store of the source and the load
                // of the request counter below must not reorder, or a writer that ran between
                // them sees null and we see 0 - a lost wake-up with nothing else to end the
                // receive. Http3StreamMultiplexer.cs:267-273 explains the same pair.
                Interlocked.Exchange(ref _pumpInterrupt, interrupt);
                try
                {
                    if (Volatile.Read(ref _interruptRequests) > 0)
                    {
                        interrupt.Cancel();
                    }
                    if (!await _http3.PumpOnceAsync(interrupt.Token).ConfigureAwait(false))
                    {
                        throw new TlsQuicProxyException(TlsQuicProxyError.MasqueTunnelClosed,
                            $"The outer HTTP/3 connection failed with error 0x{_http3.ConnectionErrorCode:x}.");
                    }
                }
                catch (OperationCanceledException) when (!_lifetime.IsCancellationRequested)
                {
                    // stepped aside for a writer
                }
                finally
                {
                    Interlocked.Exchange(ref _pumpInterrupt, null);
                    Interlocked.Exchange(ref _interruptRequests, 0);
                }
            }

            foreach (var datagram in _http3.DrainDatagrams(_streamId))
            {
                if (datagram.Length < ContextIdLength || datagram[0] != ContextIdUdpPayload)
                {
                    _droppedWrongContext++;
                    continue;
                }
                if (datagram.Length - ContextIdLength > MaxDatagramPayloadSize)
                {
                    _droppedOversize++;
                    continue;
                }
                _inbound.Writer.TryWrite(datagram[ContextIdLength..]);
            }

            var response = _http3.ResponseFor(_streamId);
            if (response is null || response.IsReset || response.IsComplete)
            {
                throw new TlsQuicProxyException(TlsQuicProxyError.MasqueTunnelClosed,
                    response is { IsReset: true }
                        ? $"The proxy reset the tunnel stream with error 0x{response.ResetErrorCode:x}."
                        : "The proxy ended the tunnel stream.");
            }
        }
    }
    catch (Exception exception) when (!_lifetime.IsCancellationRequested)
    {
        var failure = exception as TlsQuicProxyException ?? Closed(exception);
        _inbound.Writer.TryComplete(failure);
        _outbound.Writer.TryComplete(failure);
    }
    catch (Exception)
    {
        // disposed: the channels are completed by DisposeAsync
    }
}

private void InterruptPump()
{
    Interlocked.Increment(ref _interruptRequests);
    try
    {
        Volatile.Read(ref _pumpInterrupt)?.Cancel();
    }
    catch (ObjectDisposedException)
    {
    }
}

private static TlsQuicProxyException Closed(Exception cause) => new(
    TlsQuicProxyError.MasqueTunnelClosed,
    $"The MASQUE tunnel ended: {cause.GetType().Name}: {cause.Message}");

public async ValueTask DisposeAsync()
{
    if (Interlocked.Exchange(ref _disposed, 1) != 0)
    {
        return;
    }
    var gone = new TlsQuicProxyException(TlsQuicProxyError.MasqueTunnelClosed, "The MASQUE tunnel was disposed.");
    _lifetime.Cancel();
    _inbound.Writer.TryComplete(gone);
    _outbound.Writer.TryComplete(gone);
    if (_owner is { } owner)
    {
        try { await owner.ConfigureAwait(false); } catch (Exception) { }
    }
    try
    {
        await _http3.CloseAsync(TlsQuicHttp3ErrorCode.H3NoError, CancellationToken.None).ConfigureAwait(false); // 0x100
    }
    catch (Exception) { }
    await _connection.DisposeAsync().ConfigureAwait(false);
    await _outer.DisposeAsync().ConfigureAwait(false);
    _lifetime.Dispose();
}
```

Two checks while wiring: `TlsQuicHttp3Connection.CloseAsync(TlsQuicHttp3ErrorCode, ct)` at `:1136` is the H3-level close; the owner task must not run concurrently with it (it has exited by then). And `RunAsync` must not be started before `_owner` is assigned in `ConnectAsync` (it is assigned from `Task.Run`'s return; the loop reads no field that needs it).

- [ ] **Step 3: Run the transport tests and the whole Quic suite**

Run: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~TlsQuicMasqueTransportTests|FullyQualifiedName~SharpTls.Tests.Quic"`.

- [ ] **Step 4: Commit**

```bash
git add SharpTls/src/SharpTls/Quic/TlsQuicMasqueTransport.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicMasqueTransportTests.cs
git commit -m "feat(quic): run the MASQUE tunnel from one owner task with delay-never-drop backpressure" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 9: SharpTls documentation

**Files:**
- Create: `SharpTls/docs/MASQUE-DATAGRAM-TRANSPORT.md`
- Modify: `SharpTls/docs/SOCKS5-DATAGRAM-TRANSPORT.md` (one pointer paragraph under "Error model")

- [ ] **Step 1: Write the doc** from the spec's Components 4, Error model and MTU arithmetic sections: purpose, the dial's five steps with the exact CONNECT-UDP header list, framing bytes (`[quarter stream id][0x00][payload]` inside a `0x31` frame), the owner task and its two channels, the five errors with when they fire, the 1392/1360/1358/1200 arithmetic (stated for an 8-byte server connection id: the outer short header carries the proxy's SCID, and a longer one lowers the capacity by the difference), `DropSummary`, and the tests-only options. Under 200 lines. Cite RFC 9221 s3/s4/s5.2/s5.4, RFC 9297 s2.1/s3.4, RFC 9298 s2/s3.1/s3.5/s4, RFC 8441 s3/s4, RFC 9220 s3.

- [ ] **Step 2: Add the pointer** in the SOCKS5 doc after the TLS-alert paragraph: "A proxy that only tunnels UDP into TCP cannot carry QUIC; providers that offer RFC 9298 CONNECT-UDP are reached through `TlsQuicMasqueTransport`, see MASQUE-DATAGRAM-TRANSPORT.md."

- [ ] **Step 3: Commit**

```bash
git add SharpTls/docs/MASQUE-DATAGRAM-TRANSPORT.md SharpTls/docs/SOCKS5-DATAGRAM-TRANSPORT.md
git commit -m "docs(quic): describe the MASQUE datagram transport on the wire" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Chunk 3: TlsClient wiring, live tests, docs

### Task 10: `TlsProxy.Masque`

**Files:**
- Modify: `TlsClient-main/src/TlsClient/TlsProxy.cs:56-78` (factories, `EffectivePort`), `:88-99` (`GetBasicAuthorizationValue`), `:176-183` (enum)
- Modify: `TlsClient-main/src/TlsClient/PublicAPI.Unshipped.txt`
- Test: `TlsClient-main/tests/TlsClient.Tests/TlsProxyMasqueTests.cs` (new)

- [ ] **Step 1: Write the failing tests**

```csharp
namespace TlsClient.Tests;

public sealed class TlsProxyMasqueTests
{
    [Fact]
    public void MasqueTakesAnHttpsAddressWithAnExplicitPort()
    {
        var proxy = TlsProxy.Masque("https://masque.oxylabs.io:50000", "customer-u", "p");

        Assert.Equal(TlsProxyType.Masque, proxy.Type);
        Assert.Equal(50000, proxy.EffectivePort);
        Assert.Equal("customer-u", proxy.Credentials!.UserName);
        Assert.Equal("p", proxy.Credentials.Password);
        Assert.Null(proxy.GetBasicAuthorizationValue()); // that helper is HTTP CONNECT's; MASQUE builds its own header
    }

    [Theory]
    [InlineData("https://masque.oxylabs.io")]      // no port
    [InlineData("http://masque.oxylabs.io:50000")] // wrong scheme
    public void MasqueRejectsAnAddressWithoutAPortOrWithAnotherScheme(string address) =>
        Assert.Throws<ArgumentException>(() => TlsProxy.Masque(address, "u", "p"));

    [Fact]
    public void TheEnumValueIsThree() => Assert.Equal(3, (int)TlsProxyType.Masque);
}
```

- [ ] **Step 2: Run, expect compile failure**

- [ ] **Step 3: Implement**

```csharp
public static TlsProxy Masque(
    string address,
    string username,
    string password,
    Action<TlsQuicOptions>? configureOuter = null)
{
    ArgumentNullException.ThrowIfNull(username);
    ArgumentNullException.ThrowIfNull(password);
    var uri = new Uri(address, UriKind.Absolute);
    if (uri.IsDefaultPort || uri.Port < 0)   // note: IsDefaultPort is also true for an explicit :443; a MASQUE proxy on 443 would need a different check
    {
        throw new ArgumentException(
            "A MASQUE proxy address must name a UDP port other than 443 explicitly, for example https://masque.oxylabs.io:50000.",
            nameof(address));
    }
    var proxy = Create(TlsProxyType.Masque, uri, Uri.UriSchemeHttps, new NetworkCredential(username, password));
    proxy.ConfigureOuterQuic = configureOuter;
    return proxy;
}

/// <summary>Shapes the OUTER QUIC connection to a MASQUE proxy; null means TlsClient's
/// defaults. Only Oxylabs sees that connection; the target sees the inner one.</summary>
internal Action<TlsQuicOptions>? ConfigureOuterQuic { get; private set; }
```

`EffectivePort`: `Type == TlsProxyType.Http ? 80 : Type == TlsProxyType.Masque ? throw new InvalidOperationException("MASQUE proxies always carry a port.") : 1080` (unreachable after the factory check; keeps the fallback honest). `GetBasicAuthorizationValue` stays HTTP-only; the tunnel builds its own `proxy-authorization` from `GetCredentials()`. Update the class summary at `TlsProxy.cs:7` to name the third kind. Enum: `Masque = 3,` with a summary. `PublicAPI.Unshipped.txt`: add

```
TlsClient.TlsProxyType.Masque = 3 -> TlsClient.TlsProxyType
static TlsClient.TlsProxy.Masque(string! address, string! username, string! password, System.Action<TlsClient.TlsQuicOptions!>? configureOuter = null) -> TlsClient.TlsProxy!
```

(the analyzer's error message prints the exact expected line; copy it if this differs).

- [ ] **Step 4: Run, expect pass**; also `FullyQualifiedName~ProxyTunnelTests` still green.

- [ ] **Step 5: Commit**

```bash
git add TlsClient-main/src/TlsClient/TlsProxy.cs TlsClient-main/src/TlsClient/PublicAPI.Unshipped.txt TlsClient-main/tests/TlsClient.Tests/TlsProxyMasqueTests.cs
git commit -m "feat(tlsclient): TlsProxy.Masque for RFC 9298 CONNECT-UDP proxies" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 11: `TlsQuicOptions.Proxy` and the outer options builder

**Files:**
- Modify: `TlsClient-main/src/TlsClient/TlsQuicOptions.cs:362` (beside `MaximumAssociationAttempts`), `:599-660` (`Snapshot`), `:743-753` (`TlsQuicConfiguration` record)
- Modify: `TlsClient-main/src/TlsClient/PublicAPI.Unshipped.txt`
- Test: `TlsClient-main/tests/TlsClient.Tests/Http3QuicOptionsTests.cs` (existing; add facts)

- [ ] **Step 1: Write the failing tests**

```csharp
[Fact]
public void QuicProxyAcceptsOnlyMasque()
{
    var options = new TlsSessionOptions();
    options.Quic.Proxy = TlsProxy.Socks5("socks5://127.0.0.1:1080");

    var exception = Assert.Throws<ArgumentException>(() => options.Snapshot());
    Assert.Contains("Masque", exception.Message);
}

[Fact]
public void TheOuterOptionsAreTheLibraryDefaultsPlusWhatTheGuideAsksFor()
{
    var outer = TlsQuicOptions.CreateMasqueOuter(configure: null);
    var snapshot = outer.Snapshot(new TlsHttp3Options());

    Assert.False(snapshot.ConnectionSpec.PathMtuDiscovery);
    Assert.Equal(1392, snapshot.ConnectionSpec.BasePathMtu);
    Assert.Equal(1392, snapshot.ConnectionSpec.MaximumPathMtu);
    Assert.Contains(outer.TransportParameters.Entries, e => e.Id == 0x20);
    Assert.Equal(1UL, TlsQuicHttp3Settings.Value(TlsQuicOptions.CreateMasqueOuterHttp3().Snapshot().Settings, 0x33));
}

[Fact]
public void TheOuterHookRunsLast()
{
    var outer = TlsQuicOptions.CreateMasqueOuter(o => o.MaximumPathMtu = 1300);
    Assert.Equal(1300, outer.MaximumPathMtu);
}
```

(`TlsQuicTransportParameterEntry.Id`, `TlsQuicTransportParameterOptions.cs:36`; `CreateMasqueOuterHttp3()` comes from Step 3.)

- [ ] **Step 2: Run, expect compile failure**

- [ ] **Step 3: Implement**

`TlsQuicOptions`:

```csharp
/// <summary>The MASQUE proxy an HTTP/3 dial tunnels through (RFC 9298 CONNECT-UDP), or null
/// to dial directly or through <see cref="TlsSessionOptions.Proxy"/>'s SOCKS5. Must be a
/// <see cref="TlsProxy.Masque"/>. TCP requests never use it.</summary>
public TlsProxy? Proxy { get; set; }

/// <summary>The outer connection's options for a MASQUE dial: this library's default
/// ClientHello, PMTUD off at 1392 both ways, an explicit max_datagram_frame_size, and
/// SETTINGS_H3_DATAGRAM = 1 on the HTTP/3 options that go with it. <paramref name="configure"/>
/// runs last.</summary>
internal static TlsQuicOptions CreateMasqueOuter(Action<TlsQuicOptions>? configure)
{
    var outer = new TlsQuicOptions
    {
        PathMtuDiscovery = false,
        BasePathMtu = 1392,
        MaximumPathMtu = 1392,
    };
    outer.TransportParameters.Entries.Add(
        TlsQuicTransportParameterEntry.Literal(0x20, [0x80, 0x00, 0xFF, 0xFF])); // 65535 as a varint
    configure?.Invoke(outer);
    return outer;
}

internal static TlsHttp3Options CreateMasqueOuterHttp3()
{
    var http3 = new TlsHttp3Options();
    http3.Settings.Add(new TlsHttp3Setting(0x33, 1));
    return http3;
}
```

Both additions are required: `TlsQuicHttp3Spec.DefaultSettings` is empty (`TlsQuicHttp3Spec.cs:189`) and the default transport parameters are `RfcMinimumParameters`, one entry (`TlsQuicTransportParameterSpec.cs:343-347`). The remark at `Http3Connection.cs:402-405` claiming the default preset carries 0x20 is stale; correct it while there (Task 12 touches that file).

In `Snapshot`, before constructing the record: `if (Proxy is { Type: not TlsProxyType.Masque }) throw new ArgumentException("TlsQuicOptions.Proxy must be a TlsProxy.Masque; SOCKS5 and HTTP proxies go in TlsSessionOptions.Proxy.", nameof(Proxy));` and pass `Proxy` as a new last positional parameter `TlsProxy? Proxy` of `TlsQuicConfiguration`. `PublicAPI.Unshipped.txt`: the `Proxy.get`/`Proxy.set` lines.

- [ ] **Step 4: Run, expect pass**

Run: `dotnet test TlsClient-main/tests/TlsClient.Tests --filter "FullyQualifiedName~Http3QuicOptionsTests|FullyQualifiedName~TlsPresetTests"`.

- [ ] **Step 5: Commit**

```bash
git add TlsClient-main/src/TlsClient/TlsQuicOptions.cs TlsClient-main/src/TlsClient/PublicAPI.Unshipped.txt TlsClient-main/tests/TlsClient.Tests/Http3QuicOptionsTests.cs
git commit -m "feat(tlsclient): options.Quic.Proxy and the outer options a MASQUE dial uses" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 12: The MASQUE dial branch and refusals

**Files:**
- Modify: `TlsClient-main/src/TlsClient/Http3Connection.cs:223-330` (`CreateAsync`)
- Modify: `TlsClient-main/src/TlsClient/HttpConnectionFactory.cs:22-40`
- Modify: `TlsClient-main/src/TlsClient/ProxyTunnel.cs:10-30`
- Modify: `TlsClient-main/src/TlsClient/TlsConnectEvent.cs:147` (enum tail)
- Test: `TlsClient-main/tests/TlsClient.Tests/MasqueRoutingTests.cs` (new)

- [ ] **Step 1: Write the failing tests**

```csharp
using SharpTls.Quic;

namespace TlsClient.Tests;

#pragma warning disable TLSCLIENT3 // Http3Only is [Experimental]; ProxyUsageDocTests.cs:58 does the same
public sealed class MasqueRoutingTests
{
    [Fact]
    public async Task AMasqueProxyInTheTcpSlotIsRefusedByName()
    {
        await using var transport = new MemoryStream();
        var exception = await Assert.ThrowsAsync<NotSupportedException>(async () =>
            await ProxyTunnel.EstablishAsync(
                transport, new Uri("https://example.com/"),
                TlsProxy.Masque("https://masque.test:50000", "u", "p"), 4096, CancellationToken.None));
        Assert.Contains("options.Quic.Proxy", exception.Message);
    }

    [Fact]
    public void AnHttpProxyBesideAMasqueQuicProxyIsALegalSession()
    {
        var options = new TlsSessionOptions
        {
            Proxy = TlsProxy.Http("http://127.0.0.1:8080"),
        };
        options.Quic.Proxy = TlsProxy.Masque("https://masque.test:50000", "u", "p");
        var configuration = options.Snapshot();
        // HttpConnectionFactory's h3 branch must not throw for the HTTP proxy when Quic.Proxy is set:
        // call the same static check the factory uses (extract it as
        // HttpConnectionFactory.ThrowIfProxyCannotCarryHttp3(TlsProxy? proxy, TlsQuicConfiguration quic))
        HttpConnectionFactory.ThrowIfProxyCannotCarryHttp3(options.Proxy, configuration.Quic);
    }

    [Fact]
    public void AnHttpProxyAloneStillCannotCarryHttp3()
    {
        var options = new TlsSessionOptions { Proxy = TlsProxy.Http("http://127.0.0.1:8080") };
        Assert.Throws<NotSupportedException>(() =>
            HttpConnectionFactory.ThrowIfProxyCannotCarryHttp3(options.Proxy, options.Snapshot().Quic));
    }

    [Fact]
    public async Task AMasqueDialThatCannotReachTheProxyFailsByName()
    {
        // 127.0.0.1:1 answers nothing (SIO_UDP_CONNRESET is disabled on the socket, so no
        // ICMP-driven reset either); HandshakeDeadline 2 s → MasqueTunnelRefused "did not come
        // up within". Http3Only is required: the default policy prefers h2 and would dial TCP.
        var options = new TlsSessionOptions { HttpVersionPolicy = TlsHttpVersionPolicy.Http3Only };
        options.Quic.Proxy = TlsProxy.Masque("https://127.0.0.1:1", "u", "p");
        options.Quic.HandshakeDeadline = TimeSpan.FromSeconds(2);
        options.Timeout = TimeSpan.FromSeconds(10);
        options.Retry.RetryConnectionFailures = false; // TlsRetryOptions.cs:28, default true; one attempt is the point
        await using var session = new TlsSession(options);

        var exception = await Assert.ThrowsAnyAsync<Exception>(
            () => session.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://example.com/")));

        Exception? cursor = exception;
        while (cursor is not null && cursor is not TlsQuicProxyException)
        {
            cursor = cursor.InnerException;
        }
        var proxyFailure = Assert.IsType<TlsQuicProxyException>(cursor);
        Assert.Equal(TlsQuicProxyError.MasqueTunnelRefused, proxyFailure.Error);
        Assert.Contains("did not come up within", proxyFailure.Message);
    }
}
#pragma warning restore TLSCLIENT3
```

The last test depends on Task 7 mapping BOTH `OperationCanceledException` (the linked deadline) and `TimeoutException` (SharpTls's own `HandshakeDeadline`, `TlsQuicConnection.cs:5181`, set to the same value) to `MasqueTunnelRefused` "did not come up within"; Task 7's listing does that.

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

`ProxyTunnel.EstablishAsync` switch: add

```csharp
TlsProxyType.Masque => throw new NotSupportedException(
    "MASQUE carries UDP; set options.Quic.Proxy to the MASQUE proxy and give options.Proxy a SOCKS5 or HTTP proxy for TCP."),
```

`HttpConnectionFactory`: extract the h3 check into

```csharp
internal static void ThrowIfProxyCannotCarryHttp3(TlsProxy? proxy, TlsQuicConfiguration quic)
{
    if (quic.Proxy is not null)
    {
        return;   // the MASQUE tunnel carries h3; options.Proxy is for TCP only
    }
    if (proxy is not null && proxy.Type != TlsProxyType.Socks5)
    {
        throw new NotSupportedException(/* existing message */);
    }
}
```

rewrite the remark above it AND the exception text (`HttpConnectionFactory.cs:33-36` says "only SOCKS5 relays datagrams ... Use a SOCKS5 proxy", which is now false): "HTTP/3 cannot be tunnelled through a {proxy.Type} proxy in options.Proxy: QUIC is UDP. Use a SOCKS5 proxy whose UDP ASSOCIATE relays datagrams, or an RFC 9298 MASQUE proxy in options.Quic.Proxy, or a TCP version policy for this one." `ProxyUsageDocTests.cs:84` pins the old phrase `"only SOCKS5 relays datagrams"`; change that assertion to `"options.Quic.Proxy"` (its `:83` check on `through a {type} proxy` still holds) and add the file to this task's commit. Call the helper where the inline check was; pass `configuration.Quic.Proxy is null ? proxy : null` to `Http3Connection.CreateAsync` so the SOCKS5 loop never sees a TCP proxy when MASQUE is in play. A per-request `TlsRequestOptions.Proxy` reaches the same check; nothing else to do for it.

Telemetry scope, stated so nobody looks for more: `MasqueTunnelOpened` fires on a completed dial and `MasqueTunnelClosed` on a failed one. A tunnel that dies mid-life surfaces as `MasqueTunnelClosed` on the request that hits it (an `IOException` through the pool's existing path) and emits no connect event, exactly as a SOCKS5 `AssociationTerminated` does today; USAGE says so in Task 13.

`Http3Connection.CreateAsync`: first extract the inner dial. Today the loop body (`Http3Connection.cs:309-489`) interleaves the options block, the SOCKS5 probe wiring on `relay.OnFirstInboundDatagram` (341-373), `ConnectAsync` with its two catch-to-`HttpRequestException` clauses (374-392), the ALPN check, `SendPendingAsync` (409), the `Socks5AssociationWatch` argument (431-437), `result.Start()`, and a catch that disposes and decides the retry (444-489). Move lines 313-442 into

```csharp
/// <summary>One inner dial over <paramref name="transport"/>: connection options, the
/// SOCKS5 probe deadline when <paramref name="relay"/> is set, handshake, ALPN check,
/// HTTP/3 control streams, the Http3Connection. On any failure the CONNECTION it created is
/// disposed here; the TRANSPORT belongs to the caller, which disposes it (and decides
/// whether to re-associate) in its own catch.</summary>
private static async ValueTask<Http3Connection> DialInnerAsync(
    Uri origin,
    TlsSessionConfiguration configuration,
    TlsQuicClientHelloProfileFactory factory,
    Tls13SessionCache tls13SessionCache,
    ITlsQuicDatagramTransport transport,
    IPEndPoint endPoint,
    Socks5LivenessTransport? relay,
    bool probing,
    TimeSpan handshakeTimeout,
    Guid connectionId,
    CancellationToken cancellationToken)
```

whose body is those lines with four mechanical changes: `spec` (read at `:314`) becomes `configuration.Quic.ConnectionSpec`; `tlsClient` (declared at `:310`, outside the span) becomes a local `CustomTlsQuicClient? tlsClient = null;` at the top of the helper; the `var handshakeTimeout = ...` (`~:340`) and `var probing = ...` (`~:352`) declarations are deleted because both are now parameters (leaving them is CS0136), and the loop computes them before the call; `connection` is a local disposed in a `catch { if (connection is not null) await connection.DisposeAsync(); throw; }` inside the helper. The loop then reads `return await DialInnerAsync(origin, configuration, factory, tls13SessionCache, transport, endPoint, relay, probing, handshakeTimeout, connectionId, cancellationToken);` with its existing outer catch keeping the transport disposal and retry decision. Also delete the `connection` disposal in the loop's outer catch (`Http3Connection.cs:446-449`), since `connection` now lives in the helper. Run `dotnet test TlsClient-main/tests/TlsClient.Tests --filter "FullyQualifiedName~Socks5Association|FullyQualifiedName~Http3"` before going further: this refactor must be behaviour-neutral.

Then, after `spec`/`factory` are built and BEFORE the origin is resolved (MASQUE never resolves the origin locally; move the `dnsResolver.ResolveAsync` block below this branch), add:

```csharp
if (configuration.Quic.Proxy is { } masque)
{
    return await CreateThroughMasqueAsync(origin, masque, configuration, factory, tls13SessionCache, connectionId, cancellationToken).ConfigureAwait(false);
}
```

`CreateThroughMasqueAsync`:

```csharp
private static async ValueTask<IHttpConnection> CreateThroughMasqueAsync(
    Uri origin, TlsProxy masque, TlsSessionConfiguration configuration,
    TlsQuicClientHelloProfileFactory factory, Tls13SessionCache tls13SessionCache,
    Guid connectionId, CancellationToken cancellationToken)
{
    var outer = TlsQuicOptions.CreateMasqueOuter(masque.ConfigureOuterQuic).Snapshot(TlsQuicOptions.CreateMasqueOuterHttp3());
    var startedAt = Stopwatch.GetTimestamp();
    var credentials = masque.GetCredentials()!;
    TlsQuicMasqueTransport tunnel;
    try
    {
        tunnel = await TlsQuicMasqueTransport.ConnectAsync(
            new TlsQuicMasqueOptions
            {
                ProxyEndPoint = new DnsEndPoint(masque.Address.IdnHost, masque.EffectivePort),
                TargetHost = origin.IdnHost,
                TargetPort = origin.Port,
                TargetEndPoint = new IPEndPoint(IPAddress.Any, origin.Port),
                Username = credentials.UserName,
                Password = credentials.Password,
                OuterSpec = outer.ConnectionSpec,
                OuterHttp3Spec = outer.Http3Spec,
                ConfigureOuterClientHello = outer.ConfigureClientHello,
                HandshakeDeadline = configuration.Quic.HandshakeDeadline ?? SharpTlsHandshakeDeadline,
            },
            cancellationToken).ConfigureAwait(false);
    }
    catch (Exception exception)
    {
        // Every failure of the outer dial, not only the named ones: a socket error or a
        // cancellation is still a tunnel that did not open.
        TlsConnectTelemetry.Emit(configuration.ConnectObserver, connectionId, TlsConnectEventKind.MasqueTunnelClosed,
            origin.IdnHost, origin.Port, elapsed: Stopwatch.GetElapsedTime(startedAt), exception: exception);
        throw;
    }
    TlsConnectTelemetry.Emit(configuration.ConnectObserver, connectionId, TlsConnectEventKind.MasqueTunnelOpened,
        origin.IdnHost, origin.Port, elapsed: Stopwatch.GetElapsedTime(startedAt));

    try
    {
        // The inner dial is the direct path over the tunnel: the endPoint is the same echo
        // value the tunnel returns, relay is null (no SOCKS5 wrapper), no probing. Note the
        // outer dial and the inner handshake each get a full deadline, so the worst case is
        // about twice HandshakeTimeout(configuration).
        return await DialInnerAsync(
            origin, configuration, factory, tls13SessionCache,
            tunnel, new IPEndPoint(IPAddress.Any, origin.Port),
            relay: null, probing: false, HandshakeTimeout(configuration), connectionId,
            cancellationToken).ConfigureAwait(false);
    }
    catch
    {
        await tunnel.DisposeAsync().ConfigureAwait(false);
        throw;
    }
    // After this point a MasqueTunnelClosed thrown by the tunnel's Send/Receive reaches the pool
    // through the same IOException path AssociationTerminated takes today.
}
```

`TlsConnectEventKind`: append `MasqueTunnelOpened = 17` and `MasqueTunnelClosed = 18` (after `Socks5AssociationWentSilent = 16`) with summaries; add to `PublicAPI.Unshipped.txt`:

```
TlsClient.TlsConnectEventKind.MasqueTunnelOpened = 17 -> TlsClient.TlsConnectEventKind
TlsClient.TlsConnectEventKind.MasqueTunnelClosed = 18 -> TlsClient.TlsConnectEventKind
```

- [ ] **Step 4: Run, expect pass**

Run: `dotnet test TlsClient-main/tests/TlsClient.Tests --filter "FullyQualifiedName~MasqueRoutingTests|FullyQualifiedName~ProxyTunnelTests|FullyQualifiedName~Socks5|FullyQualifiedName~Http3|FullyQualifiedName~ProxyUsageDocTests"`.

- [ ] **Step 5: Commit**

```bash
git add TlsClient-main/src/TlsClient/Http3Connection.cs TlsClient-main/src/TlsClient/HttpConnectionFactory.cs TlsClient-main/src/TlsClient/ProxyTunnel.cs TlsClient-main/src/TlsClient/TlsConnectEvent.cs TlsClient-main/src/TlsClient/PublicAPI.Unshipped.txt TlsClient-main/tests/TlsClient.Tests/MasqueRoutingTests.cs TlsClient-main/tests/TlsClient.Tests/ProxyUsageDocTests.cs
git commit -m "feat(tlsclient): dial HTTP/3 through a MASQUE tunnel when options.Quic.Proxy is set" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 13: Live tests, USAGE, full verification

**Files:**
- Create: `TlsClient-main/tests/TlsClient.Tests/MasqueLiveTests.cs`
- Modify: `TlsClient-main/tests/TlsClient.Tests/SpotifyPresetLiveParityTests.cs` (`NewRequest` → `internal static`; new `internal static AssertHandsetFingerprint(JsonDocument)` extracted from the h3 parity test)
- Modify: `TlsClient-main/docs/USAGE.md:201-210` (heading and proxy table), `:716` (h3 table row)

- [ ] **Step 1: Write the live tests**

```csharp
using System.Net;
using System.Text.Json;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>Dials through a real MASQUE proxy. Runs only when TLSCLIENT_LIVE_MASQUE holds
/// https://user:pass@host:port; the credential never lives in this repository.</summary>
public sealed class MasqueLiveTests
{
    private static TlsSessionOptions? Options(Action<TlsSessionOptions>? adjust = null)
    {
        if (Environment.GetEnvironmentVariable("TLSCLIENT_LIVE_MASQUE") is not { } url)
        {
            return null;
        }
        var proxy = new Uri(url);
        var credentials = proxy.UserInfo.Split(':', 2);
        var options = TlsPresets.Spotify.CreateOptions();
        options.Timeout = TimeSpan.FromSeconds(30);
        options.Quic.Proxy = TlsProxy.Masque(
            $"https://{proxy.Host}:{proxy.Port}",
            Uri.UnescapeDataString(credentials[0]),
            Uri.UnescapeDataString(credentials[1]));
        adjust?.Invoke(options);
        return options;
    }

    [Fact]
    public async Task TheTargetSeesTheHandsetThroughTheTunnel()
    {
        if (Options() is not { } options) return;
        await using var session = new TlsSession(options);
        var response = await session.SendAsync(SpotifyPresetLiveParityTests.NewRequest());
        Assert.Equal(HttpVersion.Version30, response.HttpVersion);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(response.Text);
        SpotifyPresetLiveParityTests.AssertHandsetFingerprint(document);
    }

    [Fact]
    public async Task ThreeRequestsOnOneTunnelledConnectionAllDecode()
    {
        if (Options() is not { } options) return;
        await using var session = new TlsSession(options);
        for (var i = 0; i < 3; i++)
        {
            var response = await session.SendAsync(SpotifyPresetLiveParityTests.NewRequest());
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    [Fact]
    public async Task AGoogleHostedTargetAnswersThroughTheTunnel()
    {
        if (Options() is not { } options) return;
        await using var session = new TlsSession(options);
        var request = new HttpRequestMessage(HttpMethod.Get, "https://spclient.wg.spotify.com/");
        request.AddHeader("user-agent", "Spotify/9.1.86 iOS/27.0 (iPhone17,2)");
        var response = await session.SendAsync(request);
        Assert.Equal(HttpVersion.Version30, response.HttpVersion);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Contains("envoy", response.Headers["server"]); // TlsHeaders indexer, TlsHeaders.cs:31
    }

    [Fact]
    public async Task AWrongPasswordIsRefusedByName()
    {
        if (Options(o => o.Quic.Proxy = TlsProxy.Masque(o.Quic.Proxy!.Address.ToString().TrimEnd('/'), o.Quic.Proxy.Credentials!.UserName, "wrong")) is not { } options) return;
        await using var session = new TlsSession(options);
        var exception = await Assert.ThrowsAnyAsync<Exception>(
            () => session.SendAsync(SpotifyPresetLiveParityTests.NewRequest()));
        Exception? cursor = exception;
        while (cursor is not null && cursor is not TlsQuicProxyException) cursor = cursor.InnerException;
        Assert.Equal(TlsQuicProxyError.MasqueAuthenticationRejected, Assert.IsType<TlsQuicProxyException>(cursor).Error);
    }
}
```

In `SpotifyPresetLiveParityTests.cs`: make `NewRequest()` `internal static`, and extract the body of `TheEndpointSeesTheHandsetsHelloSettingsTransportParametersAndHeaderOrder` after its `DialAsync()` call (JA3 hash and text, cipher list, transport-parameter rotation, SETTINGS, header order; from line 119 on) into `internal static void AssertHandsetFingerprint(JsonDocument document)`, called by both that test and the MASQUE one, so the four axes the spec's Testing section lists are asserted through the tunnel.

- [ ] **Step 2: Run live**

```bash
TLSCLIENT_LIVE_MASQUE='https://USER:PASS@masque.oxylabs.io:50000' dotnet test TlsClient-main/tests/TlsClient.Tests --filter "FullyQualifiedName~MasqueLiveTests" --logger "console;verbosity=normal"
```
Expected: 4 passed, each with a duration in the hundreds of milliseconds or more. Four passes at a few milliseconds each mean the env var was not seen and the tests returned early; that is not a pass. If `TheTargetSeesTheHandset` fails on a fingerprint axis, the tunnel altered bytes: stop and report; do not loosen the assertion.

- [ ] **Step 3: USAGE.md** — reword the heading at line 201 to "With HTTP/3 it must be SOCKS5 or MASQUE" and the sentence at `:203-204` ("the other two proxy types cannot") to name MASQUE as the second UDP-capable kind; add a `TlsProxy.Masque` row to the proxy table (`:206-208`) with the `options.Quic.Proxy` snippet; say that a tunnel closing mid-life reaches the caller as `TlsQuicProxyException` `MasqueTunnelClosed` on the next request, retried under the retry policy, with no connect event:

```csharp
options.Proxy = TlsProxy.Socks5("socks5://pr.oxylabs.io:7777", user, pass);          // h2, TCP
options.Quic.Proxy = TlsProxy.Masque("https://masque.oxylabs.io:50000", user, pass); // h3, UDP
```

and rewrite the `:716` row: MASQUE proxies carry h3 through `options.Quic.Proxy`; HTTP CONNECT and SOCKS5-without-real-UDP still cannot. `ProxyUsageDocTests` pins section 2a claims; run it.

- [ ] **Step 4: Full verification**

```bash
dotnet test SharpTls/tests/SharpTls.Tests
dotnet test TlsClient-main/tests/TlsClient.Tests
dotnet run --project TlsClient-main/tools/TlsClient.ProfileCatalog > TlsClient-main/docs/PROFILE-MANIFEST.md
```
Expected: SharpTls fails only the three pre-existing environmental tests (`UntrustedRootIsRejected`, `AFullRequestAndResponseCompleteAgainstSystemNetQuic`, `PlatformSslStreamClientAuthenticates...`); TlsClient all green; manifest unchanged (`git diff --stat` empty for it).

- [ ] **Step 5: Commit**

```bash
git add TlsClient-main/tests/TlsClient.Tests/MasqueLiveTests.cs TlsClient-main/tests/TlsClient.Tests/SpotifyPresetLiveParityTests.cs TlsClient-main/docs/USAGE.md
git commit -m "test(tlsclient): live MASQUE parity, three requests, Google-hosted target and a refused password" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

- [ ] **Step 6: Memory** — update `C:\Users\Admin\.claude\projects\c--Users-Admin-Desktop-PROJECTS-PeakTLS\memory\oxylabs-socks5-test-proxy.md` with "MASQUE shipped <commit>; live tests pass/fail on <date>", and the MEMORY.md line.
