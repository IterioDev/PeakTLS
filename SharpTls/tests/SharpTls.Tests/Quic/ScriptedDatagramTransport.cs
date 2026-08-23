using System.Collections.Concurrent;
using System.Net;
using System.Threading.Channels;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// ============================================================================
// THE MUTATION LEDGER
// ============================================================================
//
//   ROWS BELOW                    6  = numbered 1-6 with no gaps
//   KILLED WHEN FIRST RUN         6  = 6 rows, less 0 [WAS-SURVIVOR] and 0 [SURVIVED]
//   SURVIVED, THEN WITNESSED      0
//   SURVIVING STILL               0
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' ScriptedDatagramTransport.cs`                   must return 6
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' ScriptedDatagramTransport.cs`  must return 0
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' ScriptedDatagramTransport.cs`      must return 0
//
// ALL SIX ROWS ARE A3-1's AND ALL SIX ARE ManualTimeProvider's, because A3-1 changed nothing
// else in this file but comments. ScriptedDatagramTransport itself has never had a sweep; its
// own rows are somebody else's task and their absence is stated rather than implied.
//
// Counts are per xUnit CASE. Rows 2-6 were measured at A3-1's 2119-case gate; row 1 was
// re-run at the 2120-case gate, and the two figures are labelled rather than averaged.
//
// The harness was proved in both directions before any row was trusted - a known-bad mutation
// came back KILLED, an inert comment SURVIVED - and every run enforced a case-count floor, so
// a run that aborted early could not be misread as a survivor.
//
//    1. CreateTimer falls through to base, as before A3-1  6 tests
//    2. A callback sees the end of the jump, not its own due instant  ONLY ATimerCreatedFromTheClockFiresAtAFakeInstantWithNoWallClockTimeElapsed
//    3. A timer due exactly at the target instant does not fire  5 tests
//    4. Simultaneous timers fire in reverse creation order  ONLY TwoTimersDueAtTheSameInstantFireInCreationOrder
//    5. A timer's due instant ignores the requested delay  3 tests
//    6. A one-shot timer rearms and fires forever  2 tests
//
// Every citation above names a test in ImpairingDatagramTransportTests, which is where A3-1's
// clock witnesses live because the clock and the impairing transport are one task.
//
// ROW 1 IS THE WHOLE OF A3-1's CLOCK HALF, AND ITS FIRST FORM PROVED NOTHING. Replacing the
// body outright with `base.CreateTimer(...)` left the ManualTimer type and the _created field
// unreferenced, so the mutant came back KILLED-BY-COMPILER - a verdict that measures the
// compiler and not the suite. The form recorded above keeps the machinery referenced and
// disposes the manual timer before returning the base one, so Advance fires nothing and the
// behaviour is exactly the pre-A3-1 fall-through. Six tests then die, which is the answer the
// first form could not give.
//
// ROW 3 IS AN OFF-BY-ONE AT THE BOUNDARY AND IT IS THE ONE A REVIEWER WOULD MISS. Changing
// `due > target` to `due >= target` means a timer due at EXACTLY the instant the clock is
// advanced to never fires - and "advance by exactly the delay" is how every deadline test in
// A3 will be written. Five tests catch it because the delay tests advance to the due instant
// on purpose rather than past it.

/// <summary>A clock a test moves by hand.</summary>
/// <remarks>
/// <para>The same roughly ten-line subclass <c>Tls12SessionCacheTests</c>,
/// <c>Tls13SessionTests</c>, <c>TlsEchDnsResolverTests</c> and
/// <c>TlsQuicConnectionOptionsTests</c> each carry privately. This one is at namespace scope
/// so the QUIC tasks that follow share it rather than growing another copy;
/// <c>TlsQuicConnectionOptions</c> documents why the seam is <c>TimeProvider</c> at all.
/// </para>
/// <para>THE PHASE THAT ADDS TIMERS WAS A3, AND THIS IS NOW ITS CLOCK. The remark that stood
/// here said <c>CreateTimer</c> fell through to the base implementation and scheduled against
/// the real clock, and closed with "whoever adds a timer overrides <c>CreateTimer</c> too, or
/// the determinism this seam exists for is gone." A3-1 is that override. A timer created here
/// fires inside <see cref="Advance"/>, on the caller's own thread, with no wall-clock time
/// elapsed at all.</para>
/// <para>WHAT THAT CHANGED FOR CODE THAT WAS ALREADY USING THIS TYPE, and it is one thing:
/// <c>new CancellationTokenSource(delay, provider)</c> builds its timeout on
/// <c>TimeProvider.CreateTimer</c>, so a source built from this clock now cancels when the
/// clock passes its delay rather than never. <c>TlsQuicConnection.ReceiveBoundedAsync</c> is
/// the one place in the tree that builds one, and the deadline it bounds used to be reachable
/// on a fake clock only through its post-receive check - which is why a test that drops a
/// datagram outright, so that no receive ever completes, could not have been written before
/// this override existed.</para>
/// <para>DETERMINISM IS THE FIRING ORDER, NOT JUST THE INSTANT. <see cref="Advance"/> fires
/// every timer whose due instant falls inside the interval, earliest first, with the clock
/// reading that timer's own due instant while its callback runs - so a callback that reads
/// <see cref="GetUtcNow"/> or schedules another timer sees the time the RFC would have it see,
/// not the end of the jump. Timers due at the same instant fire in creation order. Nothing
/// here is scheduled on a pool thread, so there is no ordering left to race.</para>
/// </remarks>
internal sealed class ManualTimeProvider(DateTimeOffset value) : TimeProvider
{
    private readonly List<ManualTimer> _timers = [];
    private DateTimeOffset _value = value;
    private long _created;

    public override DateTimeOffset GetUtcNow() => _value;

    /// <inheritdoc />
    /// <remarks>The returned timer fires only from <see cref="Advance"/>. A caller that never
    /// advances the clock never sees it fire, which is the point.</remarks>
    public override ITimer CreateTimer(
        TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        ArgumentNullException.ThrowIfNull(callback);
        var timer = new ManualTimer(this, callback, state, _created++);
        _ = timer.Change(dueTime, period);
        return timer;
    }

    /// <summary>Moves the clock forward, firing every timer that falls due on the way.
    /// </summary>
    /// <remarks>A negative duration moves the clock back and fires nothing.</remarks>
    internal void Advance(TimeSpan duration)
    {
        var target = _value + duration;

        // NOT A foreach OVER A SNAPSHOT: a callback may create a timer, dispose one, or fire
        // a cancellation that disposes several, so the due timer is re-chosen every round.
        // The loop terminates because each round either fires a timer - which clears or
        // rearms its due instant strictly later - or finds none due.
        while (NextDueAtOrBefore(target) is { } timer)
        {
            _value = timer.DueAt!.Value;
            timer.Fire();
        }

        // GUARDED RATHER THAN ASSIGNED, because a callback is allowed to advance the clock
        // itself and this must not pull it back afterwards.
        if (target > _value)
        {
            _value = target;
        }
    }

    private ManualTimer? NextDueAtOrBefore(DateTimeOffset target)
    {
        ManualTimer? best = null;
        foreach (var timer in _timers)
        {
            if (timer.DueAt is not { } due || due > target)
            {
                continue;
            }

            if (best is null
                || due < best.DueAt!.Value
                || (due == best.DueAt!.Value && timer.Sequence < best.Sequence))
            {
                best = timer;
            }
        }

        return best;
    }

    private void Register(ManualTimer timer)
    {
        if (!_timers.Contains(timer))
        {
            _timers.Add(timer);
        }
    }

    private void Unregister(ManualTimer timer) => _timers.Remove(timer);

    private sealed class ManualTimer(
        ManualTimeProvider owner, TimerCallback callback, object? state, long sequence) : ITimer
    {
        private TimeSpan _period = Timeout.InfiniteTimeSpan;
        private bool _disposed;

        /// <summary>When this timer next fires, or <see langword="null"/> for one that is
        /// stopped, disposed, or has fired and is not periodic.</summary>
        internal DateTimeOffset? DueAt { get; private set; }

        /// <summary>Creation order, which breaks a tie between two timers due at the same
        /// instant so that the firing order is a property of the script rather than of the
        /// order a list happened to be walked in.</summary>
        internal long Sequence { get; } = sequence;

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            if (_disposed)
            {
                return false;
            }

            _period = period;
            DueAt = dueTime == Timeout.InfiniteTimeSpan ? null : owner.GetUtcNow() + dueTime;
            owner.Register(this);
            return true;
        }

        public void Dispose()
        {
            _disposed = true;
            DueAt = null;
            owner.Unregister(this);
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

        internal void Fire()
        {
            // REARMED BEFORE THE CALLBACK RUNS, not after, so that a callback which disposes
            // this timer - which is exactly what a CancellationTokenSource timeout does - wins
            // over the rearm rather than being silently undone by it.
            // Timeout.InfiniteTimeSpan is -1 millisecond, so the one comparison covers both
            // "not periodic" and a nonsensical negative period.
            DueAt = _period <= TimeSpan.Zero ? null : owner.GetUtcNow() + _period;
            callback(state);
        }
    }
}

/// <summary>One datagram a <see cref="ScriptedDatagramTransport"/> was asked to send, copied
/// at the moment of the call.</summary>
internal sealed record ScriptedSend(IPEndPoint Destination, byte[] Payload);

/// <summary>An <see cref="ITlsQuicDatagramTransport"/> that records every datagram sent and
/// serves a scripted sequence of received datagrams, with no socket and no real clock.</summary>
/// <remarks>
/// <para>WHAT THIS DOUBLE CAN EXPRESS, AND THE HARD LIMIT ON IT. A script can fabricate any
/// packet the <b>Initial</b> keys protect, because RFC 9001 section 5.2 derives Initial keys
/// from the destination connection ID and a published salt - no key agreement is involved, so
/// a test holding the connection ID can compute them. It <b>cannot</b> fabricate a Handshake
/// or 1-RTT packet: those keys descend from the client ephemeral share, which differs on
/// every run, so a fabricated one never decrypts and neither does a real server response
/// recorded once and replayed. Record-and-replay is dead past the first flight, and no amount
/// of scripting rescues it. Later tasks may rely on that as a limit of this type, not as an
/// omission from it: Retry, Version Negotiation, unknown versions, coalesced Initial packets,
/// reordering and duplication at Initial level, malformed and truncated datagrams, idle
/// timeout and the handshake deadline all live here because each is pre-key-agreement or
/// purely temporal. A handshake past the first flight belongs to a real peer.</para>
/// <para>AND A3-1 BUILT THE THING THAT GOES WHERE THIS ONE CANNOT. The A3 parent scoping read
/// the paragraph above and still scoped loss recovery as testable "by a test implementation of
/// <c>ITlsQuicDatagramTransport</c>" - pointing at this type. It is not this type.
/// <see cref="ImpairingDatagramTransport"/> is a DECORATOR over a transport between two
/// endpoints that really agree keys, so it fabricates nothing and reaches every level; drop,
/// duplicate, reorder and delay at Handshake or 1-RTT go there. The list above is still the
/// list of what belongs HERE, and it is still correct.</para>
/// <para>WHEN A REPLY IS COMPUTED, WHICH DECIDES WHAT IT CAN SEE. A reply enqueued as a
/// factory runs at DEQUEUE time - the later of the receive being issued and the reply being
/// enqueued - and is handed the sends recorded at that instant. That is what lets a Retry
/// script answer a connection ID the client chose at random, which a fixed byte array cannot
/// do.</para>
/// <para>Both orderings occur and both work. A test that enqueues up front and then lets the
/// connection receive is the obvious one. The other is a pump already blocked in
/// <c>ReceiveAsync</c> while the test sends and enqueues afterwards - which is what a
/// connection loop produces - and there the factory <b>does</b> see sends made after the
/// receive was issued. An earlier version of this remark claimed the opposite, that a factory
/// runs when its receive is issued and cannot see later sends; that was false in exactly the
/// ordering a connection loop creates, and the test that appeared to pin it only ever
/// exercised the enqueue-first case. Witness:
/// <c>ScriptedDatagramTransportTests.AReplyFactorySeesSendsMadeWhileAReceiveWasAlreadyBlocked</c>.
/// </para>
/// <para>The real limit is on the other side of the dequeue: a factory sees the record as it
/// stood when it was dequeued, never a send made after that. Witness:
/// <c>ScriptedDatagramTransportTests.AReplyFactoryDoesNotSeeSendsThatFollowItsDequeue</c>. A
/// peer that sends unprompted is likewise not modelled - every delivery comes from a scripted
/// reply.</para>
/// <para>DELAY IS FAKE TIME. A reply enqueued with a delay advances <see cref="Clock"/> by it
/// before delivering, so a test asserting a timeout has an unbounded wall-clock duration and
/// an exactly known elapsed fake time. Pass <see cref="Clock"/> to the connection options and
/// the connection reads the same instants this script writes.</para>
/// <para>ALIASING - IDENTICAL TO <see cref="InMemoryDatagramTransport"/> AND FOR THE SAME
/// REASONS, WHICH ARE WRITTEN OUT THERE. Sends are copied on the way in, so a recording is a
/// byte record and not a window onto a buffer the caller went on to reuse; receives are
/// copied into the caller buffer and no reference to it is kept, so the caller buffer remains
/// the one thing parsed headers and frames alias.</para>
/// </remarks>
internal sealed class ScriptedDatagramTransport : ITlsQuicDatagramTransport
{
    // SingleReader is deliberately NOT set, unlike InMemoryDatagramTransport. It selects a
    // specialised channel whose Count throws NotSupportedException, and RemainingReplies is
    // built on Count. The option is only a hint, so dropping it costs nothing here; it was
    // set at first and ScriptedDatagramTransportTests.RemainingRepliesFallsAsRepliesAreServed
    // is what found it.
    private readonly Channel<ScriptedReply> _script = Channel.CreateUnbounded<ScriptedReply>(
        new UnboundedChannelOptions { SingleWriter = true });

    private readonly ConcurrentQueue<ScriptedSend> _sent = new();
    private bool _disposed;

    /// <summary>Creates a transport whose script is empty and whose clock starts at a fixed
    /// instant.</summary>
    /// <remarks>The start instant is arbitrary and has no source; nothing may depend on its
    /// value, only on differences from it.</remarks>
    internal ScriptedDatagramTransport()
        => Clock = new ManualTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

    /// <summary>Gets the clock this script advances. Hand it to the connection options so the
    /// connection and the script share one timeline.</summary>
    internal ManualTimeProvider Clock { get; }

    /// <summary>Gets the address scripted datagrams arrive from unless a reply names another.
    /// </summary>
    internal IPEndPoint RemoteEndPoint { get; } = new(IPAddress.Loopback, 443);

    /// <summary>Gets every datagram sent so far, in order, each copied at the moment of its
    /// send.</summary>
    /// <remarks>A record of what the connection emitted is a claim like any other and carries
    /// its own witness: <c>ScriptedDatagramTransportTests.SendsAreRecordedInOrderWithTheir
    /// DestinationsAndBytes</c>.</remarks>
    internal IReadOnlyList<ScriptedSend> Sent => _sent.ToArray();

    /// <summary>Gets the number of scripted replies not yet served.</summary>
    /// <remarks>Also a claim with its own witness:
    /// <c>ScriptedDatagramTransportTests.RemainingRepliesFallsAsRepliesAreServed</c>. It is
    /// what distinguishes a script that has run out from one that is about to deliver an
    /// empty datagram - a distinction the receive behaviour itself also makes, and which
    /// <c>ScriptedDatagramTransportTests.AnExhaustedScriptGoesSilentRatherThanReturningEmpty</c>
    /// pins.</remarks>
    internal int RemainingReplies => _script.Reader.Count;

    /// <inheritdoc />
    /// <remarks>Matches the direct UDP transport ceiling: this double adds no encapsulation.
    /// </remarks>
    public int MaxDatagramPayloadSize => TlsQuicUdpDatagramTransport.MaximumUdpPayload;

    /// <summary>Appends a reply of fixed bytes.</summary>
    /// <param name="datagram">The bytes delivered, copied on the way in.</param>
    /// <param name="delay">Fake time to advance before delivering.</param>
    /// <param name="from">The origin reported, or <see cref="RemoteEndPoint"/>.</param>
    internal void EnqueueReceive(
        byte[] datagram, TimeSpan delay = default, IPEndPoint? from = null)
    {
        ArgumentNullException.ThrowIfNull(datagram);
        var copy = datagram.ToArray();
        EnqueueReceive(_ => copy, delay, from);
    }

    /// <summary>Appends a reply computed when it is served, from the sends recorded by then.
    /// </summary>
    /// <param name="reply">Produces the bytes delivered. See the remarks on the type for when
    /// it runs and what it can see.</param>
    /// <param name="delay">Fake time to advance before delivering.</param>
    /// <param name="from">The origin reported, or <see cref="RemoteEndPoint"/>.</param>
    internal void EnqueueReceive(
        Func<IReadOnlyList<ScriptedSend>, byte[]> reply,
        TimeSpan delay = default,
        IPEndPoint? from = null)
    {
        ArgumentNullException.ThrowIfNull(reply);
        ArgumentOutOfRangeException.ThrowIfLessThan(delay, TimeSpan.Zero, nameof(delay));
        _ = _script.Writer.TryWrite(new ScriptedReply(reply, delay, from ?? RemoteEndPoint));
    }

    /// <inheritdoc />
    public ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            payload.Length, MaxDatagramPayloadSize, nameof(payload));
        cancellationToken.ThrowIfCancellationRequested();

        // Copied, not aliased: the caller may reuse this buffer the moment the call returns,
        // exactly as it may over a socket, and a recording that aliased it would silently
        // change after the fact.
        _sent.Enqueue(new ScriptedSend(destination, payload.ToArray()));
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    /// <remarks>An exhausted script goes silent: the call waits for a reply that never comes,
    /// which is what a peer that stopped answering looks like and is what an idle timeout or
    /// a handshake deadline has to survive. It is therefore distinguishable from a scripted
    /// zero-length datagram, which returns a <see cref="TlsQuicDatagramReceiveResult"/> of
    /// length zero. A test that expects silence bounds it with its own timeout.</remarks>
    /// <exception cref="ArgumentException"><paramref name="buffer"/> is smaller than the
    /// scripted datagram.</exception>
    public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var reply = await _script.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);

        // Time passes before the reply exists, not after: the delay is how long the peer took
        // to answer, so a factory reading the clock sees the instant of delivery.
        if (reply.Delay > TimeSpan.Zero)
        {
            Clock.Advance(reply.Delay);
        }

        var datagram = reply.Produce(Sent);

        // Same decision, and the same reasoning, as InMemoryDatagramTransport.ReceiveAsync.
        if (datagram.Length > buffer.Length)
        {
            throw new ArgumentException(
                "The scripted datagram is larger than the supplied buffer.", nameof(buffer));
        }

        datagram.CopyTo(buffer.Span);
        return new TlsQuicDatagramReceiveResult(datagram.Length, reply.From);
    }

    /// <inheritdoc />
    /// <remarks>Faults a pending receive with an <see cref="ObjectDisposedException"/>
    /// somewhere in the exception chain, and keeps faulting later ones. Fixed rather than
    /// platform-dependent, so a test may assert it.</remarks>
    public ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;
            _ = _script.Writer.TryComplete(
                new ObjectDisposedException(nameof(ScriptedDatagramTransport)));
        }

        return ValueTask.CompletedTask;
    }

    private sealed record ScriptedReply(
        Func<IReadOnlyList<ScriptedSend>, byte[]> Produce, TimeSpan Delay, IPEndPoint From);
}
