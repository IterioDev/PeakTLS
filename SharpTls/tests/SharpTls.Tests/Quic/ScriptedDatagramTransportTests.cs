using System.Diagnostics;
using System.Net;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Same two groups as InMemoryDatagramTransportTests - the contract set the socket transports
// are held to, plus the aliasing witnesses a double needs - and one group of its own: what the
// script can and cannot express. The last group is the load-bearing one, because later tasks
// will build Retry, Version Negotiation and timeout evidence on top of exactly these
// affordances and will inherit whatever this file leaves unpinned.
public sealed class ScriptedDatagramTransportTests
{
    private static readonly IPEndPoint AnyPeer = new(IPAddress.Loopback, 443);

    // Byte-compared, not length-compared. A recording that kept lengths and lost bytes would
    // satisfy every test that only counts datagrams, and every later task reading Sent to
    // check what the connection emitted would be reading a record that cannot disagree with
    // it.
    [Fact]
    public async Task SendsAreRecordedInOrderWithTheirDestinationsAndBytes()
    {
        await using var transport = new ScriptedDatagramTransport();
        var second = new IPEndPoint(IPAddress.Loopback, 4433);

        await transport.SendAsync(AnyPeer, new byte[] { 1, 2 }, CancellationToken.None);
        await transport.SendAsync(second, new byte[] { 3, 4, 5 }, CancellationToken.None);

        var sent = transport.Sent;
        Assert.Equal(2, sent.Count);
        Assert.Equal(AnyPeer, sent[0].Destination);
        Assert.Equal(new byte[] { 1, 2 }, sent[0].Payload);
        Assert.Equal(second, sent[1].Destination);
        Assert.Equal(new byte[] { 3, 4, 5 }, sent[1].Payload);
    }

    // ALIASING WITNESS - the send side copies. Identical reasoning to
    // InMemoryDatagramTransportTests.ReusingTheSendBufferDoesNotChangeADeliveredDatagram,
    // with a sharper consequence here: a recording that aliased the caller buffer would go on
    // changing after the send, so the readout a later task diffs against a packet capture
    // would describe whatever the buffer holds now rather than what went out.
    [Fact]
    public async Task ReusingTheSendBufferDoesNotChangeARecordedSend()
    {
        await using var transport = new ScriptedDatagramTransport();

        var payload = new byte[] { 1, 2, 3, 4 };
        await transport.SendAsync(AnyPeer, payload, CancellationToken.None);
        payload.AsSpan().Fill(0xFF);

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, transport.Sent[0].Payload);
    }

    [Fact]
    public async Task ScriptedRepliesAreServedInOrder()
    {
        await using var transport = new ScriptedDatagramTransport();
        transport.EnqueueReceive(new byte[] { 1 });
        transport.EnqueueReceive(new byte[] { 2 });

        var buffer = new byte[8];
        _ = await ReceiveAsync(transport, buffer);
        Assert.Equal(1, buffer[0]);
        _ = await ReceiveAsync(transport, buffer);
        Assert.Equal(2, buffer[0]);
    }

    [Fact]
    public async Task AnEnqueuedByteArrayIsCopied()
    {
        await using var transport = new ScriptedDatagramTransport();

        var scripted = new byte[] { 1, 2, 3 };
        transport.EnqueueReceive(scripted);
        scripted.AsSpan().Fill(0xFF);

        var buffer = new byte[8];
        var result = await ReceiveAsync(transport, buffer);

        Assert.Equal(3, result.Length);
        Assert.Equal(new byte[] { 1, 2, 3 }, buffer[..3]);
    }

    // THE AFFORDANCE TASK 9b DEPENDS ON. A Retry packet carries an integrity tag computed
    // over the destination connection ID the client chose at random for this attempt, so a
    // reply of fixed bytes cannot answer one. A factory can, because it runs when the receive
    // that serves it is issued and is handed the sends recorded by then - here the count is
    // returned so the assertion pins when it ran, not merely that it did.
    [Fact]
    public async Task AReplyFactorySeesTheSendsRecordedWhenItIsServed()
    {
        await using var transport = new ScriptedDatagramTransport();
        transport.EnqueueReceive(sent => [(byte)sent.Count, sent[0].Payload[0]]);

        await transport.SendAsync(AnyPeer, new byte[] { 0x42 }, CancellationToken.None);

        var buffer = new byte[8];
        var result = await ReceiveAsync(transport, buffer);

        // Enqueued before the send and still saw it: evaluation is at serve time.
        Assert.Equal(2, result.Length);
        Assert.Equal(1, buffer[0]);
        Assert.Equal(0x42, buffer[1]);
    }

    // THE ORDERING THE DOCUMENTATION USED TO GET WRONG, AND THE ONE A CONNECTION LOOP MAKES.
    // The receive is issued first and blocks on an empty script; the send and the enqueue
    // both happen afterwards. A factory evaluated when its receive was issued would see no
    // sends at all and fail on sent[0]; evaluated at dequeue it sees the send. That is the
    // real contract, and this shape - a pump already parked in ReceiveAsync while the test
    // arranges the peer's answer - is what task 9a-ii's loop produces, so it is the case a
    // later task actually relies on. There is no race to lose: the reply is only readable
    // after EnqueueReceive writes it, which is after the send is recorded.
    [Fact]
    public async Task AReplyFactorySeesSendsMadeWhileAReceiveWasAlreadyBlocked()
    {
        await using var transport = new ScriptedDatagramTransport();

        var buffer = new byte[8];
        var pending = transport.ReceiveAsync(buffer, CancellationToken.None).AsTask();

        await transport.SendAsync(AnyPeer, new byte[] { 0x42 }, CancellationToken.None);
        transport.EnqueueReceive(sent => [(byte)sent.Count, sent[0].Payload[0]]);

        var result = await pending.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(2, result.Length);
        Assert.Equal(1, buffer[0]);
        Assert.Equal(0x42, buffer[1]);
    }

    // The limit that is actually true, on the far side of the dequeue: a factory sees the
    // record as it stood when it was dequeued, never a send that follows. Both replies are
    // enqueued up front here on purpose - that is what makes the two dequeues land either
    // side of the second send, which an enqueue-time evaluation would report as zero both
    // times.
    [Fact]
    public async Task AReplyFactoryDoesNotSeeSendsThatFollowItsDequeue()
    {
        await using var transport = new ScriptedDatagramTransport();
        transport.EnqueueReceive(sent => [(byte)sent.Count]);
        transport.EnqueueReceive(sent => [(byte)sent.Count]);

        await transport.SendAsync(AnyPeer, new byte[] { 1 }, CancellationToken.None);
        var buffer = new byte[8];
        _ = await ReceiveAsync(transport, buffer);
        Assert.Equal(1, buffer[0]);

        await transport.SendAsync(AnyPeer, new byte[] { 2 }, CancellationToken.None);
        _ = await ReceiveAsync(transport, buffer);
        Assert.Equal(2, buffer[0]);
    }

    // A SCRIPT THAT RAN OUT MUST NOT LOOK LIKE ONE THAT DELIVERED NOTHING. A zero-length
    // datagram is legal on the wire and a QUIC receiver discards it; a peer that stopped
    // answering is what an idle timeout and a handshake deadline exist for. Collapsing the
    // two would let a timeout test pass against a script that simply ended, which is the
    // failure this test exists to prevent.
    [Fact]
    public async Task AnExhaustedScriptGoesSilentRatherThanReturningEmpty()
    {
        var transport = new ScriptedDatagramTransport();
        transport.EnqueueReceive([]);

        var buffer = new byte[8];
        var empty = await ReceiveAsync(transport, buffer);
        Assert.Equal(0, empty.Length);
        Assert.Equal(0, transport.RemainingReplies);

        // Silence, bounded by the test rather than by the double: the wait below is the only
        // thing that ends it, which is exactly the property a deadline test needs.
        var pending = transport.ReceiveAsync(buffer, CancellationToken.None).AsTask();
        await Assert.ThrowsAsync<TimeoutException>(
            async () => await pending.WaitAsync(TimeSpan.FromMilliseconds(250)));

        await transport.DisposeAsync();
        await Assert.ThrowsAnyAsync<Exception>(async () => await pending);
    }

    [Fact]
    public async Task RemainingRepliesFallsAsRepliesAreServed()
    {
        await using var transport = new ScriptedDatagramTransport();
        Assert.Equal(0, transport.RemainingReplies);

        transport.EnqueueReceive(new byte[] { 1 });
        transport.EnqueueReceive(new byte[] { 2 });
        Assert.Equal(2, transport.RemainingReplies);

        var buffer = new byte[8];
        _ = await ReceiveAsync(transport, buffer);
        Assert.Equal(1, transport.RemainingReplies);
        _ = await ReceiveAsync(transport, buffer);
        Assert.Equal(0, transport.RemainingReplies);
    }

    // THE FAKE CLOCK, AND WHY THE WALL-CLOCK BOUND IS RELATIVE. The scripted delay is an
    // hour, so the elapsed real time is asserted only to be less than the delay itself. That
    // is not a performance budget and cannot flake on a slow machine, but it does kill the
    // one mutation that matters here - a double that slept for the delay instead of moving
    // the clock, which would make every later timeout test cost its own timeout in real time.
    [Fact]
    public async Task ADelayAdvancesFakeTimeAndNotTheWallClock()
    {
        await using var transport = new ScriptedDatagramTransport();
        var delay = TimeSpan.FromHours(1);
        transport.EnqueueReceive(new byte[] { 1 }, delay);

        var before = transport.Clock.GetUtcNow();
        var started = Stopwatch.GetTimestamp();
        _ = await ReceiveAsync(transport, new byte[8]);
        var elapsedReal = Stopwatch.GetElapsedTime(started);

        Assert.Equal(before + delay, transport.Clock.GetUtcNow());
        Assert.True(elapsedReal < delay, $"The receive waited in real time: {elapsedReal}.");
    }

    // The receive site claims a factory reading the clock sees the instant of delivery, which
    // means the delay is applied before the factory runs and not after. Nothing pinned that,
    // so moving the advance below the factory changed the order silently and no test noticed.
    // It matters for anything scripting a peer whose answer depends on the time it answered.
    [Fact]
    public async Task AFactoryReadsTheClockAfterTheScriptedDelayIsApplied()
    {
        await using var transport = new ScriptedDatagramTransport();
        var start = transport.Clock.GetUtcNow();
        var delay = TimeSpan.FromMinutes(5);
        var seen = default(DateTimeOffset);
        transport.EnqueueReceive(
            _ =>
            {
                seen = transport.Clock.GetUtcNow();
                return [1];
            },
            delay);

        _ = await ReceiveAsync(transport, new byte[8]);

        Assert.Equal(start + delay, seen);
    }

    [Fact]
    public async Task TheClockStandsStillWithoutAScriptedDelay()
    {
        await using var transport = new ScriptedDatagramTransport();
        transport.EnqueueReceive(new byte[] { 1 });

        var before = transport.Clock.GetUtcNow();
        await transport.SendAsync(AnyPeer, new byte[] { 1 }, CancellationToken.None);
        _ = await ReceiveAsync(transport, new byte[8]);

        Assert.Equal(before, transport.Clock.GetUtcNow());
    }

    [Fact]
    public async Task ATestCanAdvanceTheClockWithoutAnyScript()
    {
        await using var transport = new ScriptedDatagramTransport();

        var before = transport.Clock.GetUtcNow();
        transport.Clock.Advance(TimeSpan.FromSeconds(30));

        Assert.Equal(before + TimeSpan.FromSeconds(30), transport.Clock.GetUtcNow());
    }

    [Fact]
    public async Task ANegativeDelayIsRejected()
    {
        await using var transport = new ScriptedDatagramTransport();

        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => transport.EnqueueReceive(new byte[] { 1 }, TimeSpan.FromSeconds(-1)));
        Assert.Equal("delay", error.ParamName);
    }

    [Fact]
    public async Task ARepliedDatagramReportsTheDefaultOriginUnlessItNamesOne()
    {
        await using var transport = new ScriptedDatagramTransport();
        var elsewhere = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443);
        transport.EnqueueReceive(new byte[] { 1 });
        transport.EnqueueReceive(new byte[] { 2 }, from: elsewhere);

        var buffer = new byte[8];
        var first = await ReceiveAsync(transport, buffer);
        var second = await ReceiveAsync(transport, buffer);

        Assert.Equal(transport.RemoteEndPoint, first.RemoteEndPoint);
        Assert.Equal(elsewhere, second.RemoteEndPoint);
    }

    [Fact]
    public async Task AnOversizedPayloadIsRejected()
    {
        await using var transport = new ScriptedDatagramTransport();

        var error = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await transport.SendAsync(
                AnyPeer,
                new byte[transport.MaxDatagramPayloadSize + 1],
                CancellationToken.None));

        Assert.Equal("payload", error.ParamName);
    }

    [Fact]
    public async Task APayloadExactlyAtTheCeilingIsAccepted()
    {
        await using var transport = new ScriptedDatagramTransport();

        await transport.SendAsync(
            AnyPeer, new byte[transport.MaxDatagramPayloadSize], CancellationToken.None);

        Assert.Equal(transport.MaxDatagramPayloadSize, transport.Sent[0].Payload.Length);
    }

    [Fact]
    public async Task TheCeilingMatchesTheDirectUdpTransport()
    {
        await using var transport = new ScriptedDatagramTransport();

        Assert.Equal(
            TlsQuicUdpDatagramTransport.MaximumUdpPayload, transport.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task AScriptedDatagramLargerThanTheReceiveBufferIsRejected()
    {
        await using var transport = new ScriptedDatagramTransport();
        transport.EnqueueReceive(new byte[4]);

        // Bounded for the same reason as its InMemoryDatagramTransportTests counterpart: an
        // unbounded await hangs the run instead of failing when nothing is delivered.
        var error = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await transport.ReceiveAsync(new byte[3], CancellationToken.None)
                .AsTask().WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Equal("buffer", error.ParamName);
    }

    [Fact]
    public async Task AScriptedDatagramExactlyFillingTheReceiveBufferIsDelivered()
    {
        await using var transport = new ScriptedDatagramTransport();
        transport.EnqueueReceive(new byte[] { 1, 2, 3 });

        var buffer = new byte[3];
        var result = await ReceiveAsync(transport, buffer);

        Assert.Equal(3, result.Length);
        Assert.Equal(new byte[] { 1, 2, 3 }, buffer);
    }

    [Fact]
    public async Task DisposingTwiceIsSafe()
    {
        var transport = new ScriptedDatagramTransport();

        await transport.DisposeAsync();
        await transport.DisposeAsync();
    }

    [Fact]
    public async Task DisposingFaultsAPendingReceive()
    {
        var transport = new ScriptedDatagramTransport();
        var pending = transport.ReceiveAsync(new byte[64], CancellationToken.None).AsTask();

        await transport.DisposeAsync();

        var error = await Assert.ThrowsAnyAsync<Exception>(
            async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)));
        AssertDisposalCaused(error);
    }

    [Fact]
    public async Task SendingAfterDisposalThrows()
    {
        var transport = new ScriptedDatagramTransport();
        await transport.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await transport.SendAsync(AnyPeer, new byte[] { 1 }, CancellationToken.None));
    }

    [Fact]
    public async Task ReceiveHonoursCancellation()
    {
        await using var transport = new ScriptedDatagramTransport();

        using var cts = new CancellationTokenSource();
        var pending = transport.ReceiveAsync(new byte[64], cts.Token).AsTask();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task ANullDestinationIsRejected()
    {
        await using var transport = new ScriptedDatagramTransport();

        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await transport.SendAsync(null!, new byte[] { 1 }, CancellationToken.None));
    }

    private static Task<TlsQuicDatagramReceiveResult> ReceiveAsync(
        ScriptedDatagramTransport transport, byte[] buffer)
        => transport.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

    // Same rationale as the copy in InMemoryDatagramTransportTests: the closed-channel type
    // is an implementation detail, the ObjectDisposedException in its chain is the behaviour.
    private static void AssertDisposalCaused(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
        {
            if (current is ObjectDisposedException)
            {
                return;
            }
        }

        Assert.Fail($"Expected an ObjectDisposedException in the chain, got {error}.");
    }
}
