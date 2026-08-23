using System.Diagnostics;
using System.Net;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task A3-1 of the loss recovery phase, the mechanics half. Everything here runs over
// InMemoryDatagramTransport with no QUIC packet in sight, because what is under test is the
// instrument and not the traffic: whether the script this type takes says what a caller means,
// and whether it says the same thing twice. The other half - the same instrument carrying real
// Initial, Handshake and 1-RTT packets between endpoints that agreed keys - is in
// TlsQuicConnectionImpairmentTests, and it is the half that could not have been written with
// any double that existed before this one.
//
// ============================================================================
// WHAT THESE ASSERTIONS PIN, AND WHAT THEY CANNOT.
// ============================================================================
//
//   THEY PIN THE SCRIPT'S MEANING AND ITS REPRODUCIBILITY. Ordinals, verdicts, the order a
//   held datagram comes back in, and the fact that two runs of one script produce one
//   sequence. Every expected sequence below is written out as a literal rather than computed
//   from the script, so an implementation that agreed with itself about the wrong answer
//   would still have to agree with a list a human wrote.
//
//   THEY CANNOT PIN THAT THE IMPAIRMENT IS VISIBLE TO A QUIC CONNECTION. A drop that this
//   file sees as a missing entry in Delivered is only a LOSS if the far side was a peer that
//   wanted the packet. That claim needs keys, and it lives in the other file.
//
//   THEY CANNOT PIN ANYTHING ABOUT REALISM. This instrument models no bandwidth, no queue,
//   no path MTU and no correlation between losses. It is a way of writing down "the 3rd
//   datagram did not arrive", which is what makes a recovery bug reproducible; a loss RATE
//   would be a different instrument for a different question.
public sealed class ImpairingDatagramTransportTests : IDisposable
{
    // Sixteen bytes of the ordinal, repeated. Distinct per datagram so that a wrapper which
    // delivered the RIGHT NUMBER of datagrams in the right order but the wrong bytes - a
    // stale copy, a shared buffer, the held datagram delivered in place of the live one -
    // fails rather than passes.
    private const int PayloadLength = 16;

    // FIVE SECONDS, NOT THE SIXTY THE CONNECTION TESTS USE. Nothing in this class waits on
    // anything real - no socket, no clock, no key agreement - and the whole file runs in under
    // a second. The bound exists so that a datagram which never arrives FAILS rather than
    // hangs, and the only thing a generous bound buys is a slower failure: a mutation sweep
    // that provokes a missing delivery in most of these tests pays the bound once per test,
    // which at sixty seconds turned a four-minute run into a twenty-five-minute one. Measured.
    private readonly CancellationTokenSource _cancellation = new(TimeSpan.FromSeconds(5));

    public void Dispose() => _cancellation.Dispose();

    [Fact]
    public async Task AnUnscriptedWrapperDeliversEveryDatagramUnchangedAndInOrder()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);

        await SendAsync(wrapper, peer, 1, 2, 3, 4, 5);

        Assert.Equal(new[] { 1, 2, 3, 4, 5 }, wrapper.Delivered);
        Assert.Empty(wrapper.Dropped);
        Assert.Empty(wrapper.Held);
        Assert.Empty(wrapper.ReleaseFailures);
        await AssertArrivedAsync(peer, wrapper, 1, 2, 3, 4, 5);
    }

    [Fact]
    public async Task TheThirdDatagramIsDroppedAndNothingElseMoves()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        wrapper.Drop(3);

        await SendAsync(wrapper, peer, 1, 2, 3, 4, 5);

        Assert.Equal(new[] { 1, 2, 4, 5 }, wrapper.Delivered);
        Assert.Equal(new[] { 3 }, wrapper.Dropped);

        // THE ORDINALS DO NOT RENUMBER AROUND THE HOLE. The 4th datagram is still ordinal 4
        // after the 3rd vanished, which is what lets a script be edited one line at a time.
        Assert.Equal(5, wrapper.Offered.Count);
        await AssertArrivedAsync(peer, wrapper, 1, 2, 4, 5);
    }

    [Fact]
    public async Task TheFifthDatagramIsDeliveredTwice()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        wrapper.Duplicate(5);

        await SendAsync(wrapper, peer, 1, 2, 3, 4, 5, 6);

        // BACK TO BACK, BEFORE THE 6th. A duplicate that arrived at the end of the run would
        // be a reorder as well as a duplicate, and a receiver's packet-number logic treats
        // the two differently.
        Assert.Equal(new[] { 1, 2, 3, 4, 5, 5, 6 }, wrapper.Delivered);
        await AssertArrivedAsync(peer, wrapper, 1, 2, 3, 4, 5, 5, 6);
    }

    [Fact]
    public async Task TheSeventhDatagramArrivesBeforeTheSixth()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        wrapper.HoldUntilAfter(6, releaseAfterOrdinal: 7);

        await SendAsync(wrapper, peer, 1, 2, 3, 4, 5, 6, 7, 8);

        Assert.Equal(new[] { 1, 2, 3, 4, 5, 7, 6, 8 }, wrapper.Delivered);
        await AssertArrivedAsync(peer, wrapper, 1, 2, 3, 4, 5, 7, 6, 8);
    }

    [Fact]
    public async Task AHeldDatagramIsStillHeldUntilTheOrdinalThatReleasesItIsOffered()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        wrapper.HoldUntilAfter(2, releaseAfterOrdinal: 4);

        await SendAsync(wrapper, peer, 1, 2, 3);

        // THE MIDDLE OF THE REORDER, WHICH THE FINAL SEQUENCE ALONE CANNOT SHOW. An
        // implementation that queued the datagram and flushed the queue at the end of the run
        // would produce the same final order as one that honours the release ordinal, and
        // would be wrong: the point of a reorder is that the far side sees the gap while it
        // is open. This asserts the gap is open.
        Assert.Equal(new[] { 1, 3 }, wrapper.Delivered);
        Assert.Equal(new[] { 2 }, wrapper.Held);

        await SendAsync(wrapper, peer, 4);
        Assert.Equal(new[] { 1, 3, 4, 2 }, wrapper.Delivered);
        Assert.Empty(wrapper.Held);
    }

    [Fact]
    public async Task ADatagramHeldBehindAnOrdinalTheRunNeverReachesStaysHeldUntilItIsFlushed()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        wrapper.HoldUntilAfter(2, releaseAfterOrdinal: 99);

        await SendAsync(wrapper, peer, 1, 2, 3);

        // NOT AN EXCEPTION, WHICH IS THE DELIBERATE PART. A script that outruns its traffic is
        // an ordinary consequence of editing a test, and an instrument that threw for it would
        // turn a harmless leftover line into a failure that looks like a transport bug.
        Assert.Equal(new[] { 2 }, wrapper.Held);
        Assert.Equal(1, await wrapper.ReleaseHeldAsync(_cancellation.Token));
        Assert.Equal(new[] { 1, 3, 2 }, wrapper.Delivered);
        Assert.Equal(0, await wrapper.ReleaseHeldAsync(_cancellation.Token));
        await AssertArrivedAsync(peer, wrapper, 1, 3, 2);
    }

    [Fact]
    public async Task ReleaseHeldFlushesInTheOrderTheDatagramsWereHeld()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        wrapper.HoldUntilAfter(1, releaseAfterOrdinal: 98).HoldUntilAfter(2, releaseAfterOrdinal: 99);

        await SendAsync(wrapper, peer, 1, 2, 3);

        // TWO HELD AT ONCE, WHICH IS THE ONLY ARRANGEMENT IN WHICH THE FLUSH ORDER IS VISIBLE
        // AT ALL. Every other test in this file holds exactly one datagram, and with one held
        // datagram first-out and last-out agree - so a flush that reversed the queue passed the
        // whole suite. A mutation sweep found precisely that gap and this test is what closes
        // it. The order matters because it is the order the far side receives them in, which is
        // the one thing a reorder instrument exists to control.
        Assert.Equal(new[] { 1, 2 }, wrapper.Held);
        Assert.Equal(new[] { 3 }, wrapper.Delivered);

        Assert.Equal(2, await wrapper.ReleaseHeldAsync(_cancellation.Token));
        Assert.Equal(new[] { 3, 1, 2 }, wrapper.Delivered);
        await AssertArrivedAsync(peer, wrapper, 3, 1, 2);
    }

    [Fact]
    public async Task ReusingTheSendBufferDoesNotChangeADatagramTheWrapperIsHolding()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        wrapper.HoldUntilAfter(1, releaseAfterOrdinal: 2);

        var buffer = Payload(1);
        await wrapper.SendAsync(peer.LocalEndPoint, buffer, _cancellation.Token);

        // THE HOLD IS WHY THE ALIASING RULE BITES HARDER HERE THAN ON
        // InMemoryDatagramTransport. That double copies on send too, but its datagram is
        // queued and gone before SendAsync returns; a HELD one sits inside this wrapper across
        // an arbitrary amount of the caller's later work - and TlsQuicConnection builds every
        // datagram it sends into one reused buffer. A wrapper that queued the caller's memory
        // would deliver whatever that buffer happened to contain at release time, which is a
        // corruption no socket could produce and one that would be diagnosed as a packet-layer
        // bug.
        buffer.AsSpan().Fill(0xFF);
        await SendAsync(wrapper, peer, 2);
        Assert.Equal(new[] { 2, 1 }, wrapper.Delivered);

        // COMPARED AGAINST A FRESHLY BUILT PAYLOAD, not against Offered: if the wrapper aliased
        // the caller's buffer then Offered would have been overwritten too, and the two sides
        // of the comparison would move together and agree on the wrong bytes.
        var scratch = new byte[PayloadLength * 2];
        var first = await peer.ReceiveAsync(scratch, _cancellation.Token);
        Assert.Equal(Payload(2), scratch[..first.Length]);
        var second = await peer.ReceiveAsync(scratch, _cancellation.Token);
        Assert.Equal(Payload(1), scratch[..second.Length]);
    }

    [Fact]
    public async Task ADelayedDatagramArrivesOnlyOnceTheClockHasPassedItsDelay()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        wrapper.DelayBy(2, TimeSpan.FromMilliseconds(500));

        var wallClock = Stopwatch.StartNew();
        await SendAsync(wrapper, peer, 1, 2, 3);

        Assert.Equal(new[] { 1, 3 }, wrapper.Delivered);
        Assert.Equal(new[] { 2 }, wrapper.Held);

        // SHORT OF THE DELAY, THEN PAST IT. One advance would prove the datagram comes back;
        // two prove it comes back at the right INSTANT, which is the whole reason a delay is
        // scripted on a clock rather than on a call count.
        wrapper.Clock.Advance(TimeSpan.FromMilliseconds(499));
        Assert.Equal(new[] { 1, 3 }, wrapper.Delivered);

        wrapper.Clock.Advance(TimeSpan.FromMilliseconds(1));
        Assert.Equal(new[] { 1, 3, 2 }, wrapper.Delivered);
        Assert.Empty(wrapper.Held);
        Assert.Empty(wrapper.ReleaseFailures);
        wallClock.Stop();

        // HALF A SECOND OF FAKE TIME PASSED AND ESSENTIALLY NONE OF REAL TIME. The margin is
        // wide because a loaded build agent is slow, not because the figure is uncertain: a
        // delay implemented on the real clock could not come in under it.
        Assert.True(
            wallClock.Elapsed < TimeSpan.FromMilliseconds(400),
            $"The delayed release took {wallClock.Elapsed} of wall-clock time, so it did not "
                + "fire off the injected clock.");

        await AssertArrivedAsync(peer, wrapper, 1, 3, 2);
    }

    [Fact]
    public void ATimerCreatedFromTheClockFiresAtAFakeInstantWithNoWallClockTimeElapsed()
    {
        // THE OVERRIDE A3-1 ADDED, ON ITS OWN AND WITH NO TRANSPORT IN THE WAY.
        // ManualTimeProvider's own remarks used to say CreateTimer fell through to the base
        // implementation and scheduled against the real clock, and named the consequence for
        // "the phase that adds timers". This is that phase's witness for the fix.
        var start = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var clock = new ManualTimeProvider(start);
        var firedAt = new List<DateTimeOffset>();

        using var timer = clock.CreateTimer(
            _ => firedAt.Add(clock.GetUtcNow()),
            state: null,
            TimeSpan.FromHours(1),
            Timeout.InfiniteTimeSpan);

        var wallClock = Stopwatch.StartNew();
        clock.Advance(TimeSpan.FromMinutes(59));
        Assert.Empty(firedAt);

        clock.Advance(TimeSpan.FromMinutes(2));
        wallClock.Stop();

        // THE CALLBACK SAW ITS OWN DUE INSTANT, NOT THE END OF THE JUMP. The clock was moved
        // to 1h01m and the timer was due at 1h00m; a provider that fired callbacks after
        // setting the clock to the target would report the later instant, and every RTT
        // sample A3 takes inside a timer callback would be wrong by the size of the advance.
        Assert.Equal(new[] { start + TimeSpan.FromHours(1) }, firedAt);

        // AND IT DOES NOT FIRE AGAIN, because the period is infinite.
        clock.Advance(TimeSpan.FromHours(5));
        Assert.Single(firedAt);

        Assert.True(
            wallClock.Elapsed < TimeSpan.FromSeconds(30),
            $"An hour of fake time took {wallClock.Elapsed} of wall-clock time, so the timer "
                + "did not fire off the injected clock.");
    }

    [Fact]
    public void TwoTimersDueAtTheSameInstantFireInCreationOrder()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var order = new List<string>();

        using var first = clock.CreateTimer(
            _ => order.Add("first"), null, TimeSpan.FromSeconds(1), Timeout.InfiniteTimeSpan);
        using var second = clock.CreateTimer(
            _ => order.Add("second"), null, TimeSpan.FromSeconds(1), Timeout.InfiniteTimeSpan);
        using var earlier = clock.CreateTimer(
            _ => order.Add("earlier"), null, TimeSpan.FromMilliseconds(1),
            Timeout.InfiniteTimeSpan);

        clock.Advance(TimeSpan.FromSeconds(2));

        // DUE INSTANT FIRST, CREATION ORDER TO BREAK THE TIE. Without the tie-break the order
        // of two simultaneous timers would be whatever a list iteration happened to produce,
        // and A3-5's loss-detection timer and PTO can be due at the same instant.
        Assert.Equal(new[] { "earlier", "first", "second" }, order);
    }

    [Fact]
    public async Task TheSameScriptProducesTheSameDeliveryOrderOnEveryRun()
    {
        // FOUR VERDICTS AT ONCE, because the interesting failures are between them: a hold
        // that a duplicate's second delivery releases early, a delayed datagram counted as an
        // ordinal twice, a drop that renumbers what follows it.
        var first = await RunTheCombinedScriptAsync();
        var second = await RunTheCombinedScriptAsync();

        Assert.Equal(first, second);

        // AND THE ANSWER IS WRITTEN OUT, not merely stable. Two runs of a broken implementation
        // agree with each other; only a literal disagrees with both.
        //
        //   1 delivered.  2 delayed by an hour, so it goes after everything the sends produce.
        //   3 dropped.    4 delivered.  5 duplicated.
        //   6 held until 7 is offered.   7 delivered, then 6 behind it.   8 delivered.
        //   Then the clock advances and 2 comes back last.
        Assert.Equal(new[] { 1, 4, 5, 5, 7, 6, 8, 2 }, first);
    }

    [Fact]
    public async Task ALaterScriptLineReplacesAnEarlierOneForTheSameOrdinal()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        wrapper.Drop(2).Duplicate(2);

        // ONE DATAGRAM, ONE VERDICT. "Drop it and also duplicate it" has no meaning on a wire,
        // so the second line wins rather than both applying or the call failing - which is what
        // lets a shared helper script a run and one test override a single ordinal of it.
        Assert.Equal(ImpairmentVerdict.Duplicate, wrapper.VerdictFor(2));
        Assert.Equal(ImpairmentVerdict.Deliver, wrapper.VerdictFor(1));

        await SendAsync(wrapper, peer, 1, 2, 3);
        Assert.Equal(new[] { 1, 2, 2, 3 }, wrapper.Delivered);
        Assert.Empty(wrapper.Dropped);
    }

    [Fact]
    public async Task NoDatagramAndNoScriptStateMakesTheWrapperThrow()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);

        // EVERY SHAPE OF SCRIPT THAT DOES NOT MATCH ITS TRAFFIC, IN ONE PLACE. Each of these
        // is a plausible leftover from editing a test, and the instrument's promise is that
        // none of them is a failure with a transport's name on it.
        wrapper
            .Drop(99)
            .Duplicate(100)
            .HoldUntilAfter(2, releaseAfterOrdinal: 1)
            .DelayBy(3, TimeSpan.Zero)
            .HoldUntilAfter(101, releaseAfterOrdinal: 102);

        await wrapper.SendAsync(peer.LocalEndPoint, ReadOnlyMemory<byte>.Empty, _cancellation.Token);
        await SendAsync(wrapper, peer, 2, 3, 4);

        // Ordinal 2 is held behind ordinal 1, which is already past, so it never comes back on
        // its own. Ordinal 3's delay is zero, so its timer is due at the instant it was
        // scheduled and the next advance releases it.
        Assert.Equal(new[] { 2, 3 }, wrapper.Held);
        wrapper.Clock.Advance(TimeSpan.Zero);
        Assert.Contains(3, wrapper.Delivered);
        Assert.Equal(new[] { 2 }, wrapper.Held);

        // A destination nobody is listening on: InMemoryDatagramTransport counts it and does
        // not throw, exactly as a UDP socket would not, and the wrapper adds nothing.
        await wrapper.SendAsync(new IPEndPoint(IPAddress.Loopback, 9), new byte[4], _cancellation.Token);
        Assert.Equal(1, inner.MisdirectedSends);

        // A receive that is cancelled before it starts. The wrapper forwards the token and
        // does not swallow the cancellation into a different failure.
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await wrapper.ReceiveAsync(new byte[64], cancelled.Token));

        Assert.Empty(wrapper.ReleaseFailures);
        Assert.Equal(inner.MaxDatagramPayloadSize, wrapper.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task AnOversizedPayloadIsRefusedByTheInnerTransportRatherThanByTheWrapper()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        var oversized = new byte[inner.MaxDatagramPayloadSize + 1];

        // THE SAME EXCEPTION, FROM THE SAME PLACE. ITlsQuicDatagramTransport documents this
        // throw, so a decorator that validated first would be reproducing the contract rather
        // than passing it through - and would diverge the first time an inner transport with a
        // smaller ceiling, such as the SOCKS5 one, was wrapped.
        var direct = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            async () => await inner.SendAsync(peer.LocalEndPoint, oversized, _cancellation.Token));
        var wrapped = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            async () => await wrapper.SendAsync(peer.LocalEndPoint, oversized, _cancellation.Token));
        Assert.Equal(direct.ParamName, wrapped.ParamName);

        // THE ORDINAL WAS SPENT ANYWAY, and that is the honest behaviour rather than an
        // oversight: the datagram was offered, and renumbering around a refused send would
        // make an ordinal mean "sends that succeeded", which is not a thing a script can
        // predict.
        Assert.Single(wrapper.Offered);
        Assert.Empty(wrapper.Delivered);
    }

    [Fact]
    public async Task ADelayedReleaseIntoADisposedInnerTransportIsRecordedRatherThanThrown()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        wrapper.DelayBy(1, TimeSpan.FromSeconds(1));

        await SendAsync(wrapper, peer, 1);
        Assert.Equal(new[] { 1 }, wrapper.Held);

        await inner.DisposeAsync();

        // THE RELEASE RUNS INSIDE Advance, so a throw here would come out of a line that says
        // nothing about transports. Catching it keeps the promise; recording it keeps the
        // promise from hiding a transport that stopped working.
        wrapper.Clock.Advance(TimeSpan.FromSeconds(1));

        Assert.Empty(wrapper.Delivered);
        Assert.Single(wrapper.ReleaseFailures);
        Assert.Contains("ordinal 1", wrapper.ReleaseFailures[0], StringComparison.Ordinal);
        Assert.Contains(
            nameof(ObjectDisposedException), wrapper.ReleaseFailures[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task DisposingTheWrapperDiscardsWhatItIsHoldingAndDisposesTheInnerTransport()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        var wrapper = new ImpairingDatagramTransport(inner);
        wrapper.HoldUntilAfter(1, releaseAfterOrdinal: 99);

        await SendAsync(wrapper, peer, 1);
        Assert.Equal(new[] { 1 }, wrapper.Held);

        await wrapper.DisposeAsync();
        Assert.Empty(wrapper.Held);
        Assert.Empty(wrapper.Delivered);

        // THE INNER ONE WENT WITH IT. A decorator that left its inner transport open would
        // leak the endpoint every caller obtained through it, and the caller has no other
        // handle on it once it is wrapped.
        await Assert.ThrowsAsync<ObjectDisposedException>(
            async () => await inner.SendAsync(peer.LocalEndPoint, new byte[4], _cancellation.Token));

        // AND DISPOSING TWICE IS NOT A FAILURE, which an `await using` around a wrapper the
        // test also disposed by hand would otherwise produce.
        await wrapper.DisposeAsync();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task AScriptLineBeforeTheFirstDatagramIsRefused(int ordinal)
    {
        var (inner, _) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);

        // THE ONE ASYMMETRY IN THIS TYPE, AND IT IS DELIBERATE. The datagram seam never throws
        // because a peer's bytes are not a test author's bug; a script line is, and an
        // instrument that silently impaired nothing would report the bug as a passing test.
        Assert.Throws<ArgumentOutOfRangeException>(() => wrapper.Drop(ordinal));
        Assert.Throws<ArgumentOutOfRangeException>(() => wrapper.Duplicate(ordinal));
        Assert.Throws<ArgumentOutOfRangeException>(() => wrapper.HoldUntilAfter(1, ordinal));
        Assert.Throws<ArgumentOutOfRangeException>(() => wrapper.HoldUntilAfter(ordinal, 1));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => wrapper.DelayBy(ordinal, TimeSpan.FromSeconds(1)));

        // AND A NEGATIVE DELAY, which is the same class of test-author bug and would otherwise
        // schedule a timer in the past.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => wrapper.DelayBy(1, TimeSpan.FromSeconds(-1)));
    }

    // The script from TheSameScriptProducesTheSameDeliveryOrderOnEveryRun, run once against a
    // fresh pair. Returns the delivery order.
    private async Task<int[]> RunTheCombinedScriptAsync()
    {
        var (inner, peer) = InMemoryDatagramTransport.CreatePair();
        await using var wrapper = new ImpairingDatagramTransport(inner);
        wrapper
            .Drop(3)
            .Duplicate(5)
            .HoldUntilAfter(6, releaseAfterOrdinal: 7)
            .DelayBy(2, TimeSpan.FromHours(1));

        await SendAsync(wrapper, peer, 1, 2, 3, 4, 5, 6, 7, 8);
        wrapper.Clock.Advance(TimeSpan.FromHours(1));

        await AssertArrivedAsync(peer, wrapper, [.. wrapper.Delivered]);
        return [.. wrapper.Delivered];
    }

    private async Task SendAsync(
        ImpairingDatagramTransport wrapper, InMemoryDatagramTransport peer, params int[] ordinals)
    {
        foreach (var ordinal in ordinals)
        {
            await wrapper.SendAsync(peer.LocalEndPoint, Payload(ordinal), _cancellation.Token);
        }
    }

    // Drains the peer and asserts both the ORDER and the BYTES, the second read back off
    // Offered rather than recomputed from the ordinal - so a wrapper that delivered the right
    // sequence of the wrong buffers fails here.
    private async Task AssertArrivedAsync(
        InMemoryDatagramTransport peer, ImpairingDatagramTransport wrapper, params int[] ordinals)
    {
        var buffer = new byte[PayloadLength * 4];
        foreach (var ordinal in ordinals)
        {
            var received = await peer.ReceiveAsync(buffer, _cancellation.Token);
            Assert.Equal(wrapper.Offered[ordinal - 1], buffer[..received.Length]);
        }
    }

    private static byte[] Payload(int ordinal) =>
        [.. Enumerable.Repeat((byte)ordinal, PayloadLength)];
}
