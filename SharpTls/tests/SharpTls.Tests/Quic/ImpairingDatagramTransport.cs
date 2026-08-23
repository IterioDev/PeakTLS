using System.Net;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// ============================================================================
// THE MUTATION LEDGER
// ============================================================================
//
//   ROWS BELOW                   16  = numbered 1-16 with no gaps
//   KILLED WHEN FIRST RUN        15  = 16 rows, less 1 [WAS-SURVIVOR] and 0 [SURVIVED]
//   SURVIVED, THEN WITNESSED      1  = row 12
//   SURVIVING STILL               0
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' ImpairingDatagramTransport.cs`                   must return 16
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' ImpairingDatagramTransport.cs`  must return 1
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' ImpairingDatagramTransport.cs`      must return 0
//
// ManualTimeProvider's own six rows are NOT here. That type lives in
// ScriptedDatagramTransport.cs and carries its own ledger, per the one-ledger-per-file rule,
// so that each file's three greps stay about that file.
//
// Counts are per xUnit CASE, so a two-row Theory failing in both rows counts 2. Rows 1-11 and
// 13-16 were measured at A3-1's 2119-case gate; row 12 was re-run at the 2120-case gate its
// own fix produced, and the two figures are labelled rather than averaged.
//
// THE HARNESS WAS PROVED IN BOTH DIRECTIONS BEFORE ANY ROW WAS TRUSTED, which is the check
// that catches a sweep that compiles nothing and reads every mutant as a survivor. A
// known-bad mutation - Drop delivering instead of dropping - came back KILLED with 4 tests at
// total=2119; an inert added comment line came back SURVIVED with 0 at the same total. Every
// run below also enforced a 2119-case floor, so a run that aborted early could not be
// misread as a survivor.
//
//    1. Duplicate delivers once                   5 tests
//    2. HoldUntilAfter delivers instead of holding  8 tests
//    3. DelayBy delivers instead of scheduling    5 tests
//    4. The release runs BEFORE this ordinal's own verdict  5 tests
//    5. A hold is released by any LATER ordinal, not the named one  5 tests
//    6. Ordinals are 0-based                     20 tests
//    7. A delivery is recorded before the inner send  ONLY AnOversizedPayloadIsRefusedByTheInnerTransportRatherThanByTheWrapper
//    8. The payload is queued by reference, not copied  ONLY ReusingTheSendBufferDoesNotChangeADatagramTheWrapperIsHolding
//    9. MaxDatagramPayloadSize is a constant      ONLY NoDatagramAndNoScriptStateMakesTheWrapperThrow
//   10. The FIRST script line for an ordinal wins  ONLY ALaterScriptLineReplacesAnEarlierOneForTheSameOrdinal
//   11. An ordinal below one is accepted          2 tests
//   12. ReleaseHeldAsync flushes in reverse order  [WAS-SURVIVOR] -> now ONLY ReleaseHeldFlushesInTheOrderTheDatagramsWereHeld
//   13. Dispose flushes what is held              ONLY DisposingTheWrapperDiscardsWhatItIsHoldingAndDisposesTheInnerTransport
//   14. Dispose leaves the inner transport open   ONLY DisposingTheWrapperDiscardsWhatItIsHoldingAndDisposesTheInnerTransport
//   15. A delayed release does not remove its datagram from the held list  2 tests
//   16. A failed release is swallowed, not recorded  ONLY ADelayedReleaseIntoADisposedInnerTransportIsRecordedRatherThanThrown
//
// Every citation above names a test in ImpairingDatagramTransportTests.
//
// ROW 12 IS THE ONE THAT MATTERED, AND IT IS THE REASON A SWEEP IS RUN AT ALL. Reversing the
// flush order changed nothing that any test could see, because every test in the file held
// exactly ONE datagram at a time - and with one held datagram first-out and last-out are the
// same answer. The flush order is the order the far side receives them in, which is precisely
// what a reorder instrument exists to control, so the survivor was UNWITNESSED rather than
// vacuous or unreachable: ImpairingDatagramTransportTests.ReleaseHeldFlushesInTheOrderThe
// DatagramsWereHeld holds two and asserts the order, and the row is killed.
//
// ROW 6 IS THE BROADEST AND THE LEAST INTERESTING. Twenty tests die because a 0-based ordinal
// misaligns every script in the file at once. It is here because "the 3rd datagram" is the
// whole scripting surface and an off-by-one in it would silently impair the wrong packet;
// breadth is not evidence of subtlety.
//
// ROW 8 IS THE ONE A SHIPPED DOUBLE ALREADY LEARNED. InMemoryDatagramTransport copies on send
// and says at length why. This wrapper HOLDS datagrams across arbitrary later work, so the
// same rule binds harder here, and the row proves the copy is load-bearing rather than
// defensive.

/// <summary>What a script says happens to one datagram.</summary>
internal enum ImpairmentVerdict
{
    /// <summary>Forward it to the inner transport, once, immediately. The verdict for every
    /// ordinal a script does not name, so an empty script is a transparent wrapper.</summary>
    Deliver,

    /// <summary>Never forward it. The datagram is counted by
    /// <see cref="ImpairingDatagramTransport.Dropped"/> and nothing else happens.</summary>
    Drop,

    /// <summary>Forward it twice, back to back.</summary>
    Duplicate,

    /// <summary>Hold it, and forward it once another named ordinal has been offered - which
    /// is how a later datagram overtakes an earlier one.</summary>
    HoldUntilAfter,

    /// <summary>Hold it, and forward it when the clock has advanced by a named duration.
    /// </summary>
    DelayBy,
}

/// <summary>An <see cref="ITlsQuicDatagramTransport"/> that wraps another one and impairs the
/// datagrams passing out through it, following a script written before the run.</summary>
/// <remarks>
/// <para>WHY THIS EXISTS, AND WHAT THE SIX EXISTING DOUBLES COULD NOT DO. A3's plan
/// (2026-08-21-quic-a3-recovery-and-congestion.md, Finding 4) counted six implementations of
/// <see cref="ITlsQuicDatagramTransport"/> in the tree and none of them can drop, reorder or
/// duplicate a datagram: the two socket transports impair only by real network luck,
/// <see cref="InMemoryDatagramTransport"/> is a lossless pair whose one drop counts sends
/// addressed elsewhere, <c>RecordingTransport</c> observes and forwards, <c>NullTransport</c>
/// carries nothing, and <see cref="ScriptedDatagramTransport"/> - the double the parent
/// scoping pointed at - says in its own remarks that "record-and-replay is dead past the
/// first flight", so it cannot fabricate a Handshake or 1-RTT packet at all. Every loss
/// recovery task after this one is untestable without an instrument that can, and this is
/// it.</para>
/// <para>A DECORATOR, NOT A PEER, WHICH IS WHY IT REACHES HANDSHAKE AND 1-RTT. It carries
/// whatever the endpoint it wraps produced. Put it under one end of a real key agreement -
/// <see cref="TlsQuicConnection"/> facing <see cref="LoopbackQuicPeer"/>, or two
/// <c>LoopbackQuicPeer</c>s - and the datagrams it impairs are genuine Initial, Handshake and
/// 1-RTT packets that the far side really opens. Nothing here reads or decrypts them; the
/// script addresses a datagram by its position in the send sequence, which is the one
/// property available without keys.</para>
/// <para>A SCRIPT, NOT A LOSS RATE, AND THE DIFFERENCE IS THE WHOLE POINT. "Drop the 3rd
/// datagram" reproduces; "drop 5% of datagrams" reproduces only if the seed, the sequence
/// the RNG is drawn in and the code between draws all stay identical, which is three more
/// things to keep in step with a failure report. Loss RATES belong in a soak test. Nothing
/// in this file draws a random number, and the same script over the same traffic produces
/// the same delivery order on every machine and every run. Witness:
/// <c>ImpairingDatagramTransportTests.TheSameScriptProducesTheSameDeliveryOrderOnEveryRun
/// </c>.</para>
/// <para>THE SEND SIDE ONLY, AND WHY THAT IS NOT HALF A JOB. Impairment applies to
/// <see cref="SendAsync"/>; <see cref="ReceiveAsync"/> forwards untouched. A datagram lost
/// leaving A is the same event as a datagram lost arriving at B, so a caller wanting
/// server-to-client loss wraps the SERVER's transport rather than asking this type for a
/// second lane. One lane, two placements, and no ambiguity about which of two scripts a
/// given ordinal belongs to.</para>
/// <para>ORDINALS ARE 1-BASED AND COUNT EVERY DATAGRAM OFFERED TO
/// <see cref="SendAsync"/>, impaired or not. The 3rd datagram is ordinal 3 whether the 1st
/// was dropped or duplicated, so a script stays readable after it is edited.</para>
/// <para>THIS TYPE NEVER THROWS OF ITS OWN ACCORD ON THE DATAGRAM SEAM.
/// <see cref="SendAsync"/>, <see cref="ReceiveAsync"/> and <see cref="DisposeAsync"/> add no
/// validation: a payload the inner transport would refuse is refused by the inner transport,
/// with the inner transport's own exception, and everything else - an ordinal the run never
/// reaches, a hold whose release ordinal never arrives, a duplicate of a datagram that was
/// also delayed - is inert rather than fatal. The script-writing methods DO validate their
/// arguments, because those are a test author's input and not a peer's, and a silently
/// ignored <c>Drop(0)</c> is a green test that impaired nothing. Witness:
/// <c>ImpairingDatagramTransportTests.NoDatagramAndNoScriptStateMakesTheWrapperThrow</c>.
/// </para>
/// <para>ALIASING - COPIES ON SEND, EXACTLY LIKE <see cref="InMemoryDatagramTransport"/> AND
/// FOR THE REASONS WRITTEN OUT THERE. A held datagram outlives the <c>SendAsync</c> call that
/// offered it by construction, so queuing the caller's own memory would let a sender's buffer
/// reuse rewrite a datagram this type is still holding - a corruption no socket could produce
/// and one that would be diagnosed as a packet-layer bug. The receive direction keeps no
/// reference to the caller buffer because it never touches it.</para>
/// <para>CONCURRENCY FOLLOWS THE INTERFACE: one sender and one receiver. The lists below are
/// unsynchronised, as the interface's remarks permit, and the timer callbacks that release a
/// delayed datagram run on whichever thread calls <see cref="ManualTimeProvider.Advance"/> -
/// which is the test's own thread, not a pool one.</para>
/// </remarks>
internal sealed class ImpairingDatagramTransport : ITlsQuicDatagramTransport
{
    private readonly ITlsQuicDatagramTransport _inner;
    private readonly Dictionary<int, Impairment> _script = [];
    private readonly List<byte[]> _offered = [];
    private readonly List<int> _delivered = [];
    private readonly List<int> _dropped = [];
    private readonly List<HeldDatagram> _held = [];
    private readonly List<ITimer> _timers = [];
    private readonly List<string> _releaseFailures = [];
    private bool _disposed;

    /// <summary>Wraps <paramref name="inner"/>, with no impairment scripted.</summary>
    /// <param name="inner">The transport that actually carries the datagrams.</param>
    /// <param name="clock">The clock <see cref="DelayBy"/> schedules against, and the one a
    /// connection under test must also be given so that both read one timeline. A fresh one
    /// is created when the caller has no clock to share.</param>
    internal ImpairingDatagramTransport(
        ITlsQuicDatagramTransport inner, ManualTimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;

        // The same arbitrary start instant ScriptedDatagramTransport uses, and arbitrary for
        // the same reason: nothing may depend on its value, only on differences from it.
        Clock = clock
            ?? new ManualTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
    }

    /// <summary>Gets the clock this transport schedules delayed releases against.</summary>
    internal ManualTimeProvider Clock { get; }

    /// <summary>Gets every datagram offered to <see cref="SendAsync"/>, in offer order, each
    /// copied at the moment of its call. Index <c>n - 1</c> is ordinal <c>n</c>.</summary>
    /// <remarks>OFFERED, not delivered: a dropped datagram appears here and not in
    /// <see cref="Delivered"/>, and the difference between the two lists is the whole record
    /// of what this instrument did.</remarks>
    internal IReadOnlyList<byte[]> Offered => _offered;

    /// <summary>Gets the ordinal of each datagram this transport passed to the inner one, in
    /// the order the inner one received them.</summary>
    /// <remarks>A duplicated ordinal appears twice; a dropped one never appears; a held one
    /// appears after whatever overtook it. This is the sequence a determinism assertion reads.
    /// </remarks>
    internal IReadOnlyList<int> Delivered => _delivered;

    /// <summary>Gets the ordinals the script dropped, in offer order.</summary>
    internal IReadOnlyList<int> Dropped => _dropped;

    /// <summary>Gets the ordinals still being held - delayed, or waiting for the ordinal that
    /// releases them - in the order they were held.</summary>
    internal IReadOnlyList<int> Held => _held.Select(static h => h.Ordinal).ToArray();

    /// <summary>Gets a line per delayed release that the inner transport refused, naming the
    /// ordinal and the exception.</summary>
    /// <remarks>EXISTS BECAUSE THE ALTERNATIVE IS A SWALLOWED EXCEPTION. A release runs inside
    /// a timer callback, so a throw there would surface out of an unrelated
    /// <see cref="ManualTimeProvider.Advance"/> call or, worse, nowhere at all. Catching it
    /// keeps the promise that this type does not throw; recording it keeps that promise from
    /// hiding a transport that stopped working. A test asserting a clean run asserts this is
    /// empty. Witness:
    /// <c>ImpairingDatagramTransportTests.ADelayedReleaseIntoADisposedInnerTransportIsRecorded
    /// RatherThanThrown</c>.</remarks>
    internal IReadOnlyList<string> ReleaseFailures => _releaseFailures;

    /// <inheritdoc />
    public int MaxDatagramPayloadSize => _inner.MaxDatagramPayloadSize;

    /// <summary>Scripts the datagram at <paramref name="ordinal"/> to be dropped.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="ordinal"/> is less than
    /// one.</exception>
    internal ImpairingDatagramTransport Drop(int ordinal)
        => Script(ordinal, new Impairment(ImpairmentVerdict.Drop, 0, TimeSpan.Zero));

    /// <summary>Scripts the datagram at <paramref name="ordinal"/> to be delivered twice.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="ordinal"/> is less than
    /// one.</exception>
    internal ImpairingDatagramTransport Duplicate(int ordinal)
        => Script(ordinal, new Impairment(ImpairmentVerdict.Duplicate, 0, TimeSpan.Zero));

    /// <summary>Scripts the datagram at <paramref name="ordinal"/> to be held until the
    /// datagram at <paramref name="releaseAfterOrdinal"/> has been offered, so that the later
    /// one arrives first.</summary>
    /// <remarks>The release ordinal is honoured whatever ITS own verdict is - a datagram that
    /// is itself dropped still releases what it was named to release, because the trigger is
    /// the send happening and not the delivery. A release ordinal the run never reaches leaves
    /// the datagram held; <see cref="ReleaseHeldAsync"/> flushes it and
    /// <see cref="Held"/> shows it in the meantime.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Either ordinal is less than one.
    /// </exception>
    internal ImpairingDatagramTransport HoldUntilAfter(int ordinal, int releaseAfterOrdinal)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(releaseAfterOrdinal, 1);
        return Script(
            ordinal,
            new Impairment(ImpairmentVerdict.HoldUntilAfter, releaseAfterOrdinal, TimeSpan.Zero));
    }

    /// <summary>Scripts the datagram at <paramref name="ordinal"/> to be held until
    /// <see cref="Clock"/> has advanced by <paramref name="delay"/> past the instant it was
    /// offered.</summary>
    /// <remarks>FAKE TIME, NOT WALL-CLOCK TIME. The release runs on a timer this transport
    /// creates from <see cref="Clock"/>, so it fires inside
    /// <see cref="ManualTimeProvider.Advance"/> with no real time elapsed at all. That is only
    /// true because <see cref="ManualTimeProvider"/> overrides <c>CreateTimer</c>; before A3-1
    /// it overrode <c>GetUtcNow</c> alone and a delay here would have waited in real
    /// seconds.</remarks>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="ordinal"/> is less than
    /// one, or <paramref name="delay"/> is negative.</exception>
    internal ImpairingDatagramTransport DelayBy(int ordinal, TimeSpan delay)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(delay, TimeSpan.Zero);
        return Script(ordinal, new Impairment(ImpairmentVerdict.DelayBy, 0, delay));
    }

    /// <summary>Gets the verdict scripted for <paramref name="ordinal"/>, which is
    /// <see cref="ImpairmentVerdict.Deliver"/> for every ordinal no script line names.
    /// </summary>
    internal ImpairmentVerdict VerdictFor(int ordinal) =>
        _script.TryGetValue(ordinal, out var impairment)
            ? impairment.Verdict
            : ImpairmentVerdict.Deliver;

    /// <summary>Forwards every held datagram now, in the order it was held, and returns how
    /// many went out.</summary>
    /// <remarks>For the end of a test whose script holds something the traffic never released
    /// - a hold behind an ordinal the run did not reach, or a delay the clock never passed.
    /// Returns zero and does nothing when there is nothing held.</remarks>
    internal async ValueTask<int> ReleaseHeldAsync(CancellationToken cancellationToken = default)
    {
        var released = 0;
        while (_held.Count > 0)
        {
            var held = _held[0];
            _held.RemoveAt(0);
            await DeliverAsync(held.Destination, held.Ordinal, held.Payload, cancellationToken)
                .ConfigureAwait(false);
            released++;
        }

        return released;
    }

    /// <inheritdoc />
    /// <remarks>Adds no validation of its own: an oversized payload is refused by the inner
    /// transport with the inner transport's exception, which is what makes an unscripted
    /// wrapper indistinguishable from no wrapper at all.</remarks>
    public async ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        // COPIED BEFORE ANYTHING ELSE: see the aliasing paragraph on this type. A held
        // datagram outlives this call, so the caller's memory cannot be what is queued.
        var copy = payload.ToArray();
        _offered.Add(copy);
        var ordinal = _offered.Count;

        switch (VerdictFor(ordinal))
        {
            case ImpairmentVerdict.Drop:
                _dropped.Add(ordinal);
                break;

            case ImpairmentVerdict.Duplicate:
                await DeliverAsync(destination, ordinal, copy, cancellationToken)
                    .ConfigureAwait(false);
                await DeliverAsync(destination, ordinal, copy, cancellationToken)
                    .ConfigureAwait(false);
                break;

            case ImpairmentVerdict.HoldUntilAfter:
                _held.Add(new HeldDatagram(
                    ordinal, destination, copy, _script[ordinal].ReleaseAfterOrdinal));
                break;

            case ImpairmentVerdict.DelayBy:
                var delayed = new HeldDatagram(ordinal, destination, copy, releaseAfterOrdinal: 0);
                _held.Add(delayed);
                _timers.Add(Clock.CreateTimer(
                    ReleaseOnTimer,
                    delayed,
                    _script[ordinal].Delay,
                    Timeout.InfiniteTimeSpan));
                break;

            default:
                await DeliverAsync(destination, ordinal, copy, cancellationToken)
                    .ConfigureAwait(false);
                break;
        }

        // AFTER this ordinal's own verdict, so that "hold 6 until after 7" delivers 7 then 6
        // rather than the reverse. Keyed on the ordinal being OFFERED, so a release ordinal
        // that is itself dropped still releases what it was named for.
        await ReleaseWaitingOnAsync(ordinal, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    /// <remarks>Untouched. Impairment is a send-side concern here - see the remarks on this
    /// type for why a receive-side lane would be a second way to say the same thing.</remarks>
    public ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer, CancellationToken cancellationToken)
        => _inner.ReceiveAsync(buffer, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Discards anything still held rather than flushing it: a datagram the script
    /// never released did not reach the peer, and delivering it at dispose would make the
    /// recorded order depend on when the test happened to dispose. Disposing the wrapper
    /// disposes the inner transport, because a decorator that left its inner one open would
    /// leak the endpoint every caller obtained through it.</remarks>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (var timer in _timers)
        {
            timer.Dispose();
        }

        _timers.Clear();
        _held.Clear();
        await _inner.DisposeAsync().ConfigureAwait(false);
    }

    private ImpairingDatagramTransport Script(int ordinal, Impairment impairment)
    {
        // THE ONE PLACE THIS TYPE VALIDATES, AND IT IS NOT THE DATAGRAM SEAM. A test author
        // who writes Drop(0) has a bug, and an instrument that silently impaired nothing would
        // report it as a passing test.
        ArgumentOutOfRangeException.ThrowIfLessThan(ordinal, 1);

        // LAST LINE WINS, rather than a throw or a queue of verdicts. One datagram gets one
        // verdict: "drop it and also duplicate it" has no meaning on the wire, and a script
        // built up in a helper that a test then overrides for one ordinal is the ordinary case.
        _script[ordinal] = impairment;
        return this;
    }

    private async ValueTask ReleaseWaitingOnAsync(int ordinal, CancellationToken cancellationToken)
    {
        // Indexed rather than foreached because DeliverAsync runs while the list is being
        // walked, and a delayed release could reach the same list from a timer.
        for (var i = 0; i < _held.Count;)
        {
            if (_held[i].ReleaseAfterOrdinal != ordinal)
            {
                i++;
                continue;
            }

            var held = _held[i];
            _held.RemoveAt(i);
            await DeliverAsync(held.Destination, held.Ordinal, held.Payload, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private void ReleaseOnTimer(object? state)
    {
        var held = (HeldDatagram)state!;
        if (!_held.Remove(held))
        {
            return;
        }

        // BLOCKING ON A VALUETASK INSIDE A TIMER CALLBACK, DELIBERATELY. The callback runs on
        // the thread that called ManualTimeProvider.Advance - the test's own - and every
        // transport this wraps completes a send synchronously. Posting the send to a pool
        // thread instead would make the delivery order depend on scheduling, which is the one
        // thing this instrument exists to remove.
        try
        {
            _inner.SendAsync(held.Destination, held.Payload, CancellationToken.None)
                .AsTask()
                .GetAwaiter()
                .GetResult();
            _delivered.Add(held.Ordinal);
        }
        catch (Exception error)
        {
            _releaseFailures.Add($"ordinal {held.Ordinal}: {error.GetType().Name}: {error.Message}");
        }
    }

    private async ValueTask DeliverAsync(
        IPEndPoint destination,
        int ordinal,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        await _inner.SendAsync(destination, payload, cancellationToken).ConfigureAwait(false);

        // RECORDED AFTER THE INNER SEND RETURNS, so a send the inner transport refused is not
        // claimed as a delivery.
        _delivered.Add(ordinal);
    }

    private readonly record struct Impairment(
        ImpairmentVerdict Verdict, int ReleaseAfterOrdinal, TimeSpan Delay);

    // A CLASS RATHER THAN A RECORD STRUCT, because ReleaseOnTimer identifies its own datagram
    // by reference: two datagrams with identical bytes, destination and release ordinal would
    // be equal as a value and the wrong one could be removed from the held list.
    private sealed class HeldDatagram(
        int ordinal, IPEndPoint destination, byte[] payload, int releaseAfterOrdinal)
    {
        internal int Ordinal { get; } = ordinal;

        internal IPEndPoint Destination { get; } = destination;

        internal byte[] Payload { get; } = payload;

        /// <summary>The offered ordinal that releases this datagram, or <c>0</c> for one
        /// released by the clock instead.</summary>
        internal int ReleaseAfterOrdinal { get; } = releaseAfterOrdinal;
    }
}
