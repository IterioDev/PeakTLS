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
        using var harness = await TlsQuicHttp3ConnectionTests.Harness.CreateAsync(
            cancellation.Token,
            flowControl: [TransportParameter(0x20, 65535)]);

        Assert.Equal(65535UL, harness.Connection.PeerMaxDatagramFrameSize);
    }

    [Fact]
    public async Task APeerThatSendsNoMaxDatagramFrameSizeLeavesItNull()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await TlsQuicHttp3ConnectionTests.Harness.CreateAsync(cancellation.Token);

        Assert.Null(harness.Connection.PeerMaxDatagramFrameSize);
    }

    // Same constructor the harness's flowControl entries use; varint-encoded value.
    internal static TlsQuicTransportParameter TransportParameter(ulong id, ulong value) =>
        new(id, QuicVariableLengthInteger.Encode(value));
}
```

`Harness` is `private sealed class` today; make it `internal sealed class` so this file can reach it (one-word change at `TlsQuicHttp3ConnectionTests.cs:2026`). If the default harness server already advertises 0x20 (check `Server(...)` in that file), assert the value it sends instead of `Null` in the second test and note why.

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
PeerMaxDatagramFrameSize = peer.Parameters
    .Get((ulong)TlsQuicTransportParameterId.MaxDatagramFrameSize)
    ?.GetVariableInteger();
```

`TlsQuicTransportParameterId.MaxDatagramFrameSize` exists (the parser's `case MaxDatagramFrameSize:` in `TlsQuicTransportParameters.cs:300` names it). RFC 9221 s3 forbids a value of 1 to 65535? No: any value; 0 means none. Treat 0 as null: `is 0 ? null : value`.

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

Find the existing round-trip pattern in `TlsQuicFramesTests.cs` (grep `MeasureFrame` or `TryReadFrame` there) and add:

```csharp
[Fact]
public void ADatagramFrameRoundTripsInItsLengthBearingForm()
{
    var frame = new TlsQuicFrame
    {
        RawType = (ulong)TlsQuicFrameType.Datagram | TlsQuicFrames.DatagramLengthBit,
        Data = new byte[] { 0x00, 0x00, 0xAA, 0xBB, 0xCC },
    };

    var written = WriteFrame(frame); // the helper the sibling round-trip tests use
    Assert.Equal(0x31, written[0]);
    Assert.Equal(5, written[1]);
    Assert.Equal(frame.Data.ToArray(), written[2..]);

    var read = ReadSingleFrame(written); // likewise
    Assert.Equal(TlsQuicFrameType.Datagram, read.Type);
    Assert.Equal(frame.Data.ToArray(), read.Data.ToArray());
    Assert.Equal(written.Length, TlsQuicFrames.MeasureFrame([], frame));
}
```

- [ ] **Step 2: Run, expect the ArgumentException**

Run: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~ADatagramFrameRoundTrips"`
Expected: FAIL, `ArgumentException: RFC 9221 DATAGRAM frames are parsed and dropped, never sent`.

- [ ] **Step 3: Implement**

In `TlsQuicConnectionFrames.cs`:

```csharp
/// <summary>RFC 9221 s4's DATAGRAM frame fields for the 0x31 form: Length (i) then
/// Datagram Data. Only that form is ever sent, because a length-less 0x30 frame must be
/// the last frame in its packet and TryBuildApplicationPacket may append an ACK after it.</summary>
internal static void WriteDatagramFrameFields(List<byte> destination, in TlsQuicFrame frame)
{
    // Same varint writer the sibling Write*FrameFields methods use.
    WriteVariableLengthInteger(destination, (ulong)frame.Data.Length);
    destination.AddRange(frame.Data.Span);
}
```

Replace the throw arm in `TlsQuicFrames.cs` with:

```csharp
case TlsQuicFrameType.Datagram:
    TlsQuicConnectionFrames.WriteDatagramFrameFields(destination, frame);
    return;
```

If the writer switch keys on `frame.Type` (derived) and the type byte is written by the caller from `RawType`, nothing else changes; if the 0x30 form would also reach this arm, throw `ArgumentException("Only the length-bearing DATAGRAM form (0x31) is sent.")` when `(frame.RawType & TlsQuicFrames.DatagramLengthBit) == 0`.

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
    using var harness = await TlsQuicHttp3ConnectionTests.Harness.CreateAsync(
        cancellation.Token, flowControl: [TransportParameter(0x20, 65535)]);
    var payload = Enumerable.Range(0, 300).Select(i => (byte)i).ToArray();

    Assert.True(harness.Connection.TryQueueDatagram(payload));
    Assert.Equal(1, harness.Connection.QueuedDatagrams);
    Assert.True(await harness.Connection.SendPendingAsync(cancellation.Token));
    Assert.Equal(0, harness.Connection.QueuedDatagrams);

    await harness.Peer.PumpOnceAsync(SentAt, cancellation.Token); // see Harness for SentAt
    var frames = harness.Peer.ReceivedFrames; // the (Level, Type) list at LoopbackQuicPeer.cs:515
    Assert.Contains(frames, f => f.Type == TlsQuicFrameType.Datagram);
    Assert.DoesNotContain(frames, f => f.Type == TlsQuicFrameType.Stream);
    // The payload itself: LoopbackQuicPeer keeps received datagram frame data if it has a
    // ReceivedDatagrams list; if not, add one next to ReceivedStreamFrames (Task 3 may touch
    // the peer) and assert Equal(payload, peer.ReceivedDatagrams.Single()).
}

[Fact]
public async Task TheQueueRefusesTheSixtyFifthDatagramAndNeverDrops()
{
    using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    using var harness = await TlsQuicHttp3ConnectionTests.Harness.CreateAsync(
        cancellation.Token, flowControl: [TransportParameter(0x20, 65535)]);

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
    using var harness = await TlsQuicHttp3ConnectionTests.Harness.CreateAsync(cancellation.Token);

    var exception = Assert.Throws<InvalidOperationException>(
        () => harness.Connection.TryQueueDatagram(new byte[] { 1 }));
    Assert.Contains("max_datagram_frame_size", exception.Message);
}

[Fact]
public async Task APayloadAboveTheFrameCeilingIsRefusedByName()
{
    using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    using var harness = await TlsQuicHttp3ConnectionTests.Harness.CreateAsync(
        cancellation.Token, flowControl: [TransportParameter(0x20, 65535)]);
    var ceiling = harness.Connection.MaximumDatagramFramePayload;

    Assert.True(ceiling >= 1200, $"ceiling {ceiling}");
    Assert.Throws<ArgumentOutOfRangeException>(
        () => harness.Connection.TryQueueDatagram(new byte[ceiling + 1]));
}

[Fact]
public async Task ACongestionBlockedWindowHoldsDatagramsAndReleasesThemInOrder()
{
    // Arrange the outer so the window is exhausted: queue enough stream data to fill
    // CongestionWindowBytes (read it from harness.Connection.Congestion), then queue two
    // datagrams, pump the peer's ACKs, and assert the peer sees datagram 1 before datagram 2
    // and both only after the window reopened. Use the same ACK-driving helpers the
    // TlsQuicConnectionRecovery tests use (grep "CongestionWindowBytes" in
    // SharpTls/tests/SharpTls.Tests/Quic for the pattern).
}
```

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

`DatagramPayloadBudget` is the property `TryBuildApplicationPacket` already reads (line 618); it lives in the send-path partial. If it is private to that file, it is still the same class.

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
    var next = _datagramsToSend.Peek();
    if (next.Length + 3 <= budget)
    {
        frames.Add(new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Datagram | TlsQuicFrames.DatagramLengthBit,
            Data = _datagramsToSend.Dequeue(),
        });
        carriesDatagram = true;
    }
}

if (!carriesDatagram && _streams is { } streams && streams.HasPendingFrames && SendGateAdmits(now))
```

(that is: the existing stream block gains the `!carriesDatagram &&` guard). `SendGateAdmits` counts a refusal per call; calling it twice in one build when both a datagram and stream data are pending double-counts `SendsRefusedByCongestionWindow` only in the refused case, which is acceptable; if a test in `TlsQuicApplicationSendPathTests` pins that counter, evaluate the gate once into a local and reuse it.

Then check three things and fix what is missing:
1. The packet's ack-eliciting flag: grep `IsAckEliciting` / `AckEliciting` in `TlsQuicPacketBuilder.cs` / `TlsQuicAcks*.cs`; a DATAGRAM frame must count as ack-eliciting (RFC 9221 s5.2). If the rule is "everything except ACK, PADDING, CONNECTION_CLOSE", nothing to do.
2. Loss handling: grep where lost packets' frames are re-queued (`OnPacketLost`, `Retransmit`). DATAGRAM frames must be skipped there (RFC 9221 s5.2 "MUST NOT be retransmitted").
3. `SendPendingAsync` returns true after a datagram-only packet (it returns whether a packet was sent; nothing to change unless it inspects frame kinds).

- [ ] **Step 5: Run the datagram tests and the send-path suite**

Run: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~TlsQuicConnectionDatagramTests|FullyQualifiedName~TlsQuicApplicationSendPath|FullyQualifiedName~TlsQuicConnectionTests"`
Expected: all pass. The loss test: use `ImpairingDatagramTransport` to drop the datagram packet and assert the peer never receives a second copy while a later stream frame still arrives.

- [ ] **Step 6: Commit**

```bash
git add SharpTls/src/SharpTls/Quic/TlsQuicConnection.cs SharpTls/src/SharpTls/Quic/TlsQuicApplicationSendPath.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicConnectionDatagramTests.cs SharpTls/tests/SharpTls.Tests/Quic/LoopbackQuicPeer.cs
git commit -m "feat(quic): send DATAGRAM frames from a bounded, congestion-gated queue" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 4: Extended CONNECT

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Request.cs:342` (CONNECT LIMITATION remark), `:508-530` (init properties), `:856-870` (emit loop)
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Spec.cs:215` (add `EnableConnectProtocolIdentifier`)
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Connection.cs:17-30` (`TlsQuicHttp3RequestRefusal`), `:595-640` (`TryOpenRequest`)
- Modify: `TlsClient-main/src/TlsClient/SharpTlsHttp3Streams.cs` (`Describe` switch on the refusal)
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

    [Fact]
    public void TheProtocolPseudoHeaderFollowsTheMethodWhateverTheOrder()
    {
        // Encode with the default spec and decode the QPACK block with the decoder the
        // TlsQuicHttp3RequestTests use (grep "DecodeFieldSection" there). Assert the decoded
        // field names, in order, are :method, :protocol, :scheme, :authority, :path,
        // proxy-authorization, capsule-protocol, and the values match ConnectUdp().
    }

    [Fact]
    public void ARequestWithoutProtocolStillHasNoProtocolLine()
    {
        // Same decode for an ordinary GET: no ":protocol" name anywhere.
    }

    [Fact]
    public async Task TheConnectionRefusesExtendedConnectUntilThePeerEnablesIt()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var harness = await TlsQuicHttp3ConnectionTests.Harness.CreateAsync(cancellation.Token);
        // The harness's peer SETTINGS are TestHttp3Settings.QpackCapable: no 0x08.

        var stream = harness.Http3.TryOpenRequest(ConnectUdp(), out var refusal, out _);

        Assert.Null(stream);
        Assert.Equal(TlsQuicHttp3RequestRefusal.ExtendedConnectNotEnabled, refusal);
    }

    [Fact]
    public async Task ThePeerEnablingItLetsTheRequestOpen()
    {
        // Build the harness with a peer SETTINGS list that adds (0x08, 1); find how the harness
        // sends peer SETTINGS (grep "QpackCapable" in TlsQuicHttp3ConnectionTests.cs) and pass
        // [.. TestHttp3Settings.QpackCapable, new TlsQuicHttp3Setting(0x08, 1)]. Then
        // TryOpenRequest(ConnectUdp(), ...) returns a stream and refusal is None.
    }
}
```

- [ ] **Step 2: Run, expect compile failures (`Protocol`, `ExtendedConnectNotEnabled`)**

- [ ] **Step 3: Implement**

`TlsQuicHttp3Request.cs`, after `Path`:

```csharp
/// <summary>RFC 9220 s3's <c>:protocol</c> for an extended CONNECT (RFC 8441 s4), for
/// example <c>connect-udp</c> (RFC 9298 s3.1). <see langword="null"/> for every other
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

`SharpTlsHttp3Streams.Describe`: add the arm `TlsQuicHttp3RequestRefusal.ExtendedConnectNotEnabled => new TlsHttpProtocolException("The peer did not send SETTINGS_ENABLE_CONNECT_PROTOCOL, so an extended CONNECT cannot be sent on this connection (RFC 8441 section 3).")`.

- [ ] **Step 4: Run, expect pass**

Run: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~TlsQuicHttp3ExtendedConnectTests|FullyQualifiedName~TlsQuicHttp3RequestTests"`.

- [ ] **Step 5: Commit**

```bash
git add SharpTls/src/SharpTls/Quic/TlsQuicHttp3Request.cs SharpTls/src/SharpTls/Quic/TlsQuicHttp3Spec.cs SharpTls/src/SharpTls/Quic/TlsQuicHttp3Connection.cs TlsClient-main/src/TlsClient/SharpTlsHttp3Streams.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3ExtendedConnectTests.cs
git commit -m "feat(http3): extended CONNECT with :protocol, gated on the peer's setting" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 5: Datagram-carrying exchanges on `TlsQuicHttp3Connection`

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Connection.cs:415-424` (`Exchange`), `:595-720` (`TryOpenRequest`, the `fin: true` at 699), `:795-831` (datagram receive), `:925-945` (`Response.TryRead` site), plus new members
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicHttp3Request.cs` (`TlsQuicHttp3Response.DiscardBody()` near `_body` at line 1418)
- Test: `SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3DatagramExchangeTests.cs` (new)

- [ ] **Step 1: Write the failing tests**

```csharp
public sealed class TlsQuicHttp3DatagramExchangeTests
{
    // Harness with peer SETTINGS [.. QpackCapable, (0x08,1), (0x33,1)] and server transport
    // parameter 0x20 = 65535; client spec Settings carry (0x33, 1) and the client hello
    // advertises 0x20 (the harness's maxDatagramFrameSize default 65536 does that).

    [Fact] public async Task ADatagramExchangeSendsItsHeadersWithoutFin()
    // Open ConnectUdp() with receivesDatagrams: true, SendPendingAsync, pump the peer, assert
    // the HEADERS stream frame the peer received has Fin == false; open an ordinary GET and
    // assert its frame has Fin == true.

    [Fact] public async Task ASentDatagramCarriesTheQuarterStreamIdAndNothingElse()
    // TrySendDatagram(stream.Id, [0x00, 0xAA, 0xBB]) then SendPendingAsync; the peer's received
    // DATAGRAM frame data equals [varint(stream.Id / 4), 0x00, 0xAA, 0xBB].

    [Fact] public async Task AReceivedDatagramForTheExchangeIsDrainedByItsStreamId()
    // Peer sends a raw DATAGRAM frame (0x31, length, varint(stream.Id/4), payload) with
    // SendOneRttRawFrameAsync; after Http3.PumpOnceAsync, DrainDatagrams(stream.Id) returns
    // exactly [payload] (quarter stream id stripped) and a second drain returns empty.

    [Fact] public async Task ADatagramForAnUnmarkedStreamIsCountedAndDropped()
    // Same, but quarter stream id of an ordinary GET's stream: DrainDatagrams for it is empty
    // and DroppedDatagramsWrongStream == 1.

    [Fact] public async Task TheExchangeKeepsNoBodyBytes()
    // Peer answers 200 then a DATA frame of 100 bytes on the stream, no FIN; after pumping,
    // ResponseFor(stream.Id).Status == 200 and Body.Length == 0.

    [Fact] public async Task PeerSettingsAreForwarded()
    // Http3.PeerSettingsReceived is true after the harness handshake and
    // TlsQuicHttp3Settings.Value(Http3.PeerSettings, 0x08) == 1.
}
```

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

`TlsQuicHttp3Response.DiscardBody()`: `internal void DiscardBody() => _body.Clear();` with a remark: a tunnel stream never FINs and its DATA frames are capsules nobody parses.

- [ ] **Step 4: Run, expect pass**

Run: `dotnet test SharpTls/tests/SharpTls.Tests --filter "FullyQualifiedName~TlsQuicHttp3DatagramExchangeTests|FullyQualifiedName~TlsQuicHttp3ConnectionTests"`.

- [ ] **Step 5: Commit**

```bash
git add SharpTls/src/SharpTls/Quic/TlsQuicHttp3Connection.cs SharpTls/src/SharpTls/Quic/TlsQuicHttp3Request.cs SharpTls/tests/SharpTls.Tests/Quic/TlsQuicHttp3DatagramExchangeTests.cs
git commit -m "feat(http3): exchanges that send and receive HTTP datagrams on an open request stream" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 6: Proxy error values

**Files:**
- Modify: `SharpTls/src/SharpTls/Quic/TlsQuicSocks5Protocol.cs:11-32` (`TlsQuicProxyError`)
- Regenerate: `SharpTls/tests/SharpTls.Tests/Api/PublicApi.Shipped.txt`

- [ ] **Step 1: Add the members** after `RelayDeliveredTlsAlert`, each with a one-line summary from the spec's error table: `MasqueNotOffered`, `MasqueAuthenticationRejected`, `MasqueTargetRejected`, `MasqueTunnelRefused`, `MasqueTunnelClosed`. The file is CRLF; keep it.

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

The tests need an outer "proxy" peer. Build `MasqueHarness` on the same parts `TlsQuicHttp3ConnectionTests.Harness` uses: `InMemoryDatagramTransport.CreatePair()`, `TestPki`, `Server(...)` with transport parameter 0x20 = 65535, `LoopbackQuicPeer.ForServer(...)`. The transport under test must accept an already-built transport pair instead of opening a UDP socket, so `ConnectAsync` takes its outer `ITlsQuicDatagramTransport` from the options (`OuterTransport`, null meaning "open a UDP socket to `ProxyEndPoint`"). The harness's peer script: run the handshake (`ConfirmedHandshake` pattern), send peer SETTINGS on the peer's control stream (copy the harness's settings-sending code, adding `(0x08, 1)` and `(0x33, 1)`), then read `ReceivedStreamFrames` for the CONNECT-UDP HEADERS, decode the header block with the test QPACK decoder, and answer with a HEADERS frame carrying the status the test wants. Write `MasqueHarness.AnswerConnectAsync(int status)` for that.

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

    /// <summary>Tests only: an already-connected outer transport, so no socket is opened.</summary>
    internal ITlsQuicDatagramTransport? OuterTransport { get; init; }

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
    // Decode the HEADERS the peer received: :method CONNECT, :protocol connect-udp, :scheme https,
    // :authority "proxy.test:50000", :path "/.well-known/masque/udp/target.test/443/",
    // proxy-authorization "Basic " + base64("user:pass"), capsule-protocol "?1"; Fin == false.

    [Theory] [InlineData(65535, 1358)] [InlineData(1300, 1295)]
    public async Task TheCapacityIsTheOuterFramePayloadMinusFraming(ulong peerLimit, int expected)
    // Server 0x20 = peerLimit, OuterSpec with BasePathMtu = MaximumPathMtu = 1392 and an 8-byte
    // DestinationConnectionIdLength; assert MaxDatagramPayloadSize == expected (stream 0 → 1-byte
    // quarter stream id, 1-byte context id).

    [Fact] public async Task ACapacityBelowAnInitialIsRefusedByName()
    // peerLimit 1100 → MasqueNotOffered, message contains "1200".

    [Fact] public async Task AResetBeforeTheResponseIsATunnelClosed()
    // Peer sends RESET_STREAM for the request stream instead of HEADERS → MasqueTunnelClosed.
}
```

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
                proxy = new IPEndPoint(IPAddress.Loopback, options.ProxyEndPoint.Port); // tests: echo value
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

            var transport = new TlsQuicMasqueTransport(connection, http3, outer, stream.Id, options.TargetEndPoint);
            if (transport.MaxDatagramPayloadSize < InnerInitialSize)
            {
                throw new TlsQuicProxyException(TlsQuicProxyError.MasqueNotOffered,
                    $"The tunnel carries at most {transport.MaxDatagramPayloadSize} bytes per datagram, below the {InnerInitialSize} an inner Initial needs (peer max_datagram_frame_size {connection.PeerMaxDatagramFrameSize}).");
            }
            transport._owner = Task.Run(transport.RunAsync);   // Task 8
            connection = null;
            outer = null;
            return transport;
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TlsQuicProxyException(TlsQuicProxyError.MasqueTunnelRefused,
                $"The MASQUE tunnel did not come up within {options.HandshakeDeadline}.");
        }
        finally
        {
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

Check against the code, not this listing: `CustomTlsQuicClient`'s constructor (see `Http3Connection.CreateTlsClient` at `Http3Connection.cs:1161`), `TlsQuicUdpDatagramTransport.Create`'s parameters, whether `TlsQuicConnectionOptions.HandshakeDeadline` is settable (`TlsQuicConnectionOptions.cs:81-89`), and `TlsQuicHttp3Response.ResetErrorCode`. `QuicVariableLengthInteger.Encode` is at `QuicVariableLengthInteger.cs:175`. The `ReceiveAsync`/`SendAsync`/`DisposeAsync` members come in Task 8; until then stub them to throw `NotImplementedException` so this task compiles.

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
// After a 200: SendAsync(any endpoint, [0xC0, 1, 2, 3]); the peer's next DATAGRAM frame data is
// [varint(streamId/4), 0x00, 0xC0, 1, 2, 3].

[Fact] public async Task APeerDatagramReachesReceiveAsyncWithoutItsFraming()
// Peer sends raw DATAGRAM frame [varint(streamId/4), 0x00, 9, 8, 7]; ReceiveAsync returns
// Length 3, buffer [9,8,7], RemoteEndPoint == TargetEndPoint.

[Fact] public async Task ANonZeroContextIdIsDroppedAndCounted()
// Peer sends [varint(qsid), 0x02, 1]; a following context-0 datagram is what ReceiveAsync
// returns, and DropSummary starts with "1 datagram(s) dropped for a context id other than 0".

[Fact] public async Task AnOversizePayloadIsRefusedByNameNotDropped()
// SendAsync with MaxDatagramPayloadSize + 1 bytes → ArgumentOutOfRangeException naming the ceiling.

[Fact] public async Task SendAwaitsWhenTheOuterIsCongestionBlocked()
// Block the outer window (as in Task 3's test); 70 SendAsync calls: the 65th onward does not
// complete until the peer ACKs; then all 70 arrive at the peer in order.

[Fact] public async Task AResetAfterTheResponseSurfacesAsTunnelClosedOnTheNextReceive()
// After 200 the peer sends RESET_STREAM (error 0x10c) for the request stream; ReceiveAsync throws
// TlsQuicProxyException with Error MasqueTunnelClosed and "0x10c" in the message; SendAsync
// afterwards throws the same.

[Fact] public async Task AnOuterConnectionCloseSurfacesAsTunnelClosed()
// Peer sends CONNECTION_CLOSE (H3_NO_ERROR); next ReceiveAsync throws MasqueTunnelClosed.

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
    datagram.CopyTo(buffer);
    return new TlsQuicDatagramReceiveResult(datagram.Length, _targetEndPoint);
}

private async Task RunAsync()
{
    try
    {
        while (!_lifetime.IsCancellationRequested)
        {
            // Outbound first: the FIFO refuses when full, and a refused payload waits in
            // _stalled so the channel keeps its order.
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
            await _connection.SendPendingAsync(_lifetime.Token).ConfigureAwait(false);

            // The pump blocks until the proxy sends or a timer fires; a writer interrupts it.
            using (var interrupt = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token))
            {
                Volatile.Write(ref _pumpInterrupt, interrupt);
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
                    Volatile.Write(ref _pumpInterrupt, null);
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
        await _http3.CloseAsync(TlsQuicHttp3ErrorCode.None, CancellationToken.None).ConfigureAwait(false); // H3_NO_ERROR: check the enum's name for 0x100
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

- [ ] **Step 1: Write the doc** from the spec's Components 4, Error model and MTU arithmetic sections: purpose, the dial's five steps with the exact CONNECT-UDP header list, framing bytes (`[quarter stream id][0x00][payload]` inside a `0x31` frame), the owner task and its two channels, the five errors with when they fire, the 1392/1360/1358/1200 arithmetic, `DropSummary`, and the tests-only options. Under 200 lines. Cite RFC 9221 s3/s4/s5.2/s5.4, RFC 9297 s2.1/s3.4, RFC 9298 s2/s3.1/s3.5/s4, RFC 8441 s3/s4, RFC 9220 s3.

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
        Assert.Equal("Basic " + Convert.ToBase64String("customer-u:p"u8.ToArray()), proxy.GetBasicAuthorizationValue());
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
    if (uri.IsDefaultPort || uri.Port < 0)
    {
        throw new ArgumentException(
            "A MASQUE proxy address must name its UDP port explicitly, for example https://masque.oxylabs.io:50000.",
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

`EffectivePort`: `Type == TlsProxyType.Http ? 80 : Type == TlsProxyType.Masque ? throw new InvalidOperationException("MASQUE proxies always carry a port.") : 1080` (unreachable after the factory check; keeps the fallback honest). `GetBasicAuthorizationValue`: allow `Type is TlsProxyType.Http or TlsProxyType.Masque`. Enum: `Masque = 3,` with a summary. `PublicAPI.Unshipped.txt`: add

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
    Assert.Contains(outer.TransportParameters.Entries, e => e.Identifier == 0x20);
    Assert.Equal(1UL, TlsQuicHttp3Settings.Value(snapshot.Http3Spec.Settings, 0x33));
}

[Fact]
public void TheOuterHookRunsLast()
{
    var outer = TlsQuicOptions.CreateMasqueOuter(o => o.MaximumPathMtu = 1300);
    Assert.Equal(1300, outer.MaximumPathMtu);
}
```

(`TlsQuicTransportParameterEntry` exposes its id as `Identifier` or `Id`; check `TlsQuicTransportParameterOptions.cs:40-60` and use that name.)

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
    http3.Settings.Add(new TlsHttp3Setting(0x33, 1));   // unless the defaults already carry it: then leave it
    return http3;
}
```

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
        // 127.0.0.1:1 answers nothing; HandshakeDeadline 2 s → the HttpRequestException wrapping
        // TlsQuicProxyException(MasqueTunnelRefused) with "did not come up within".
        var options = new TlsSessionOptions();
        options.Quic.Proxy = TlsProxy.Masque("https://127.0.0.1:1", "u", "p");
        options.Quic.HandshakeDeadline = TimeSpan.FromSeconds(2);
        options.Timeout = TimeSpan.FromSeconds(10);
        await using var session = new TlsSession(options);
        var exception = await Assert.ThrowsAnyAsync<Exception>(
            () => session.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://example.com/")));
        var proxyFailure = Enumerable.Range(0, 4).Select(_ => exception = exception.InnerException ?? exception).Last();
        // walk the chain for a TlsQuicProxyException with Error MasqueTunnelRefused
    }
}
```

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

rewrite the remark above it (the client now speaks RFC 9298 through `options.Quic.Proxy`), and call it where the inline check was; pass `configuration.Quic.Proxy is null ? proxy : null` to `Http3Connection.CreateAsync` so the SOCKS5 loop never sees a TCP proxy when MASQUE is in play.

`Http3Connection.CreateAsync`: after resolving `spec`/`factory`, branch:

```csharp
if (configuration.Quic.Proxy is { } masque)
{
    return await CreateThroughMasqueAsync(origin, masque, configuration, factory, tls13SessionCache, connectionId, cancellationToken).ConfigureAwait(false);
}
```

and skip the DNS resolution of the origin in that branch (move the resolve below the branch or resolve lazily). `CreateThroughMasqueAsync`:

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
    catch (TlsQuicProxyException exception)
    {
        TlsConnectTelemetry.Emit(configuration.ConnectObserver, connectionId, TlsConnectEventKind.MasqueTunnelClosed,
            origin.IdnHost, origin.Port, elapsed: Stopwatch.GetElapsedTime(startedAt), exception: exception);
        throw;
    }
    TlsConnectTelemetry.Emit(configuration.ConnectObserver, connectionId, TlsConnectEventKind.MasqueTunnelOpened,
        origin.IdnHost, origin.Port, elapsed: Stopwatch.GetElapsedTime(startedAt));

    // From here the direct-dial path applies verbatim: build the inner TlsQuicConnection over
    // `tunnel` with the SAME options block the loop body uses (HandshakeDeadline, IdleTimeout,
    // CreateTlsClient), ConnectAsync, ALPN check, TlsQuicHttp3Connection + OpenLocalStreams,
    // allowance, idleBudget, `new Http3Connection(tunnel, streams, null, tlsInfo, allowance, idleBudget)`.
    // Extract that body into a private static helper `DialInnerAsync(transport, endPoint, ...)`
    // and call it from both the loop and here, so nothing is duplicated. On any failure dispose
    // the tunnel and rethrow; the tunnel's MasqueTunnelClosed after this point reaches the pool as
    // an IOException like AssociationTerminated does.
}
```

`TlsConnectEventKind`: append `MasqueTunnelOpened` and `MasqueTunnelClosed` with summaries; add the two lines to `PublicAPI.Unshipped.txt`.

- [ ] **Step 4: Run, expect pass**

Run: `dotnet test TlsClient-main/tests/TlsClient.Tests --filter "FullyQualifiedName~MasqueRoutingTests|FullyQualifiedName~ProxyTunnelTests|FullyQualifiedName~Socks5|FullyQualifiedName~Http3Connection|FullyQualifiedName~ProxyUsageDocTests"`.

- [ ] **Step 5: Commit**

```bash
git add TlsClient-main/src/TlsClient/Http3Connection.cs TlsClient-main/src/TlsClient/HttpConnectionFactory.cs TlsClient-main/src/TlsClient/ProxyTunnel.cs TlsClient-main/src/TlsClient/TlsConnectEvent.cs TlsClient-main/src/TlsClient/PublicAPI.Unshipped.txt TlsClient-main/tests/TlsClient.Tests/MasqueRoutingTests.cs
git commit -m "feat(tlsclient): dial HTTP/3 through a MASQUE tunnel when options.Quic.Proxy is set" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

### Task 13: Live tests, USAGE, full verification

**Files:**
- Create: `TlsClient-main/tests/TlsClient.Tests/MasqueLiveTests.cs`
- Modify: `TlsClient-main/tests/TlsClient.Tests/SpotifyPresetLiveParityTests.cs` (`NewRequest` → `internal static`)
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
        var tls = document.RootElement.GetProperty("tls");
        Assert.Equal("48d08f334704479db85d91df80039756", tls.GetProperty("ja3").GetProperty("hash").GetString());
        // Reuse the transport-parameter rotation and header-order assertions from
        // SpotifyPresetLiveParityTests by extracting them into internal static helpers there.
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
        Assert.Contains("envoy", response.Headers.GetValues("server").Single());
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

Adjust `response.Headers` access to TlsClient's response header API (see how other tests read a header).

- [ ] **Step 2: Run live**

```bash
TLSCLIENT_LIVE_MASQUE='https://USER:PASS@masque.oxylabs.io:50000' dotnet test TlsClient-main/tests/TlsClient.Tests --filter "FullyQualifiedName~MasqueLiveTests" --logger "console;verbosity=normal"
```
Expected: 4 passed. If `TheTargetSeesTheHandset` fails on a fingerprint axis, the tunnel altered bytes: stop and report; do not loosen the assertion.

- [ ] **Step 3: USAGE.md** — reword the heading at line 201 to "With HTTP/3 it must be SOCKS5 or MASQUE", add a `TlsProxy.Masque` row to the proxy table (`:206-208`) with the `options.Quic.Proxy` snippet:

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
