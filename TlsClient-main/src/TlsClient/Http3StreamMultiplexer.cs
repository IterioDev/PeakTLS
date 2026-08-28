using System.Collections.Concurrent;
using System.Collections.Immutable;
using SharpTls.Quic;

namespace TlsClient;

/// <summary>
/// Everything one HTTP/3 request stream has received so far, as values rather than as views
/// over SharpTls's own buffers.
/// </summary>
/// <remarks>
/// <para>A SNAPSHOT AND NOT A VIEW, WHICH IS THE WHOLE POINT OF THE TYPE.
/// <c>TlsQuicHttp3Response.Body</c> is a <see cref="ReadOnlySpan{T}"/> over a
/// <see cref="List{T}"/> that the next pump appends to, so it may only be read by the thread
/// that owns the pump. The header and trailer sections are already
/// <see cref="ImmutableArray{T}"/> and cross threads as they are; the body is the one member
/// that has to be copied, and <see cref="Http3StreamMultiplexer"/> copies it under the same
/// gate that serialises the pump.</para>
/// </remarks>
/// <param name="Status">The <c>:status</c> pseudo-header, or -1 before one arrived.</param>
/// <param name="HeaderFields">The header section, empty before it arrived.</param>
/// <param name="TrailerFields">The trailer section, empty before it arrived.</param>
/// <param name="BodyLength">How many body octets the reader holds.</param>
/// <param name="ReceiveComplete">Whether the peer closed its half of the stream.</param>
/// <param name="IsComplete">Whether the response is a complete RFC 9114 section 4.1 message.
/// </param>
internal readonly record struct Http3StreamSnapshot(
    int Status,
    ImmutableArray<TlsQuicHttp3Field> HeaderFields,
    ImmutableArray<TlsQuicHttp3Field> TrailerFields,
    int BodyLength,
    bool ReceiveComplete,
    bool IsComplete);

/// <summary>
/// The QUIC and HTTP/3 operations <see cref="Http3StreamMultiplexer"/> drives, narrowed to what
/// a read loop needs.
/// </summary>
/// <remarks>
/// <para>THIS INTERFACE EXISTS TO MAKE CONCURRENCY WITNESSABLE, and that is the only reason it
/// is not a direct call into SharpTls. <c>TlsQuicHttp3Connection</c> cannot be driven without a
/// real QUIC handshake — <c>TlsQuicStream</c>'s delivered-octet state is written only by a
/// <c>TlsQuicStreamSet</c> that a live peer feeds — so "two requests overlapped on one
/// connection" would otherwise be checkable only against a live server, which is exactly the
/// claim that must not rest on a live server. Every member here is a faithful narrowing of one
/// SharpTls member; see <see cref="SharpTlsHttp3Streams"/>.</para>
/// <para>NOTHING HERE THROWS FOR PEER INPUT. <c>TryOpenRequest</c> answers with a refusal and
/// <c>PumpOnceAsync</c> answers <see langword="false"/> with an RFC 9114 section 8.1 code, which
/// is SharpTls's contract and is preserved rather than re-wrapped.</para>
/// </remarks>
internal interface IHttp3Streams
{
    /// <summary>Gets the RFC 9114 section 8.1 code this connection took, or 0.</summary>
    ulong ConnectionErrorCode { get; }

    /// <summary>Gets the stream identifier a peer GOAWAY named, if one arrived.</summary>
    ulong? PeerGoawayStreamId { get; }

    /// <summary>Opens one request stream, or reports why it would not.</summary>
    /// <returns>The new stream's identifier, or <see langword="null"/>.</returns>
    ulong? TryOpenRequest(
        TlsQuicHttp3Request request,
        out TlsQuicHttp3RequestRefusal refusal,
        out TlsQuicHttp3RequestError malformed);

    /// <summary>Flushes whatever the connection has queued to send.</summary>
    ValueTask SendPendingAsync(CancellationToken cancellationToken);

    /// <summary>Receives one datagram and processes it.</summary>
    /// <returns>Whether the HTTP/3 layer is still usable.</returns>
    ValueTask<bool> PumpOnceAsync(CancellationToken cancellationToken);

    /// <summary>Reads one request stream's state without copying its body.</summary>
    Http3StreamSnapshot Peek(ulong streamId);

    /// <summary>Copies body octets <paramref name="start"/> up to <paramref name="end"/> out of
    /// the reader's buffer.</summary>
    byte[] CopyBody(ulong streamId, int start, int end);

    /// <summary>Turns a <see cref="TryOpenRequest"/> refusal into the exception a caller sees.
    /// </summary>
    Exception Describe(
        TlsQuicHttp3RequestRefusal refusal,
        TlsQuicHttp3RequestError malformed);
}

/// <summary>What one request thread has not yet consumed of its stream.</summary>
/// <param name="Status">The <c>:status</c> pseudo-header, or -1.</param>
/// <param name="HeaderFields">The header section.</param>
/// <param name="TrailerFields">The trailer section, meaningful once <paramref name="Done"/>.
/// </param>
/// <param name="Chunks">Body octets that arrived since the last read, oldest first, and only
/// for a request that asked for streaming delivery.</param>
/// <param name="Body">The whole body, non-null once <paramref name="Done"/> and only for a
/// request that did not ask for streaming delivery.</param>
/// <param name="Done">Whether the peer closed its half of the stream.</param>
/// <param name="ResponseIsComplete">Whether the reader considers the message complete.</param>
/// <param name="Fault">What ended this stream, if anything did.</param>
internal readonly record struct Http3StreamProgress(
    int Status,
    ImmutableArray<TlsQuicHttp3Field> HeaderFields,
    ImmutableArray<TlsQuicHttp3Field> TrailerFields,
    List<byte[]>? Chunks,
    byte[]? Body,
    bool Done,
    bool ResponseIsComplete,
    Exception? Fault);

/// <summary>
/// One in-flight HTTP/3 request stream: what the read loop has harvested for it, and what its
/// own request thread has yet to take.
/// </summary>
/// <remarks>THE READ LOOP WRITES AND THE REQUEST THREAD READS, so every mutable member is under
/// <see cref="Sync"/>. The lock is per stream and is never held across an await, so one slow
/// stream cannot delay the harvest of another — which is the head-of-line property this whole
/// change exists to restore.</remarks>
internal sealed class Http3StreamState(ulong streamId, bool wantsChunks, long bodyLimit)
{
    internal object Sync { get; } = new();

    internal ulong StreamId { get; } = streamId;

    /// <summary>Whether the body is delivered as it arrives rather than once at the end.</summary>
    /// <remarks>A request with no streaming consumer takes ONE copy of the body when the stream
    /// closes rather than a copy per datagram, so the ordinary path does not hold two full
    /// copies of every response at once.</remarks>
    internal bool WantsChunks { get; } = wantsChunks;

    internal long BodyLimit { get; } = bodyLimit;

    /// <summary>How many body octets have already been copied into <see cref="_chunks"/>.
    /// </summary>
    internal int Consumed { get; set; }

    private readonly List<byte[]> _chunks = [];
    private int _status = -1;
    private ImmutableArray<TlsQuicHttp3Field> _headerFields = [];
    private ImmutableArray<TlsQuicHttp3Field> _trailerFields = [];
    private byte[]? _body;
    private bool _done;
    private bool _responseIsComplete;
    private Exception? _fault;

    /// <summary>Gets whether nothing further will be harvested for this stream.</summary>
    internal bool IsFinished
    {
        get
        {
            lock (Sync)
            {
                return _done || _fault is not null;
            }
        }
    }

    /// <summary>Records everything one harvest found. Called by the read loop only.</summary>
    internal void Publish(
        int status,
        ImmutableArray<TlsQuicHttp3Field> headerFields,
        byte[]? chunk,
        ImmutableArray<TlsQuicHttp3Field> trailerFields,
        byte[]? body,
        bool done,
        bool responseIsComplete)
    {
        lock (Sync)
        {
            if (_fault is not null)
            {
                return;
            }
            _status = status;
            _headerFields = headerFields;
            if (chunk is not null)
            {
                _chunks.Add(chunk);
            }
            if (done)
            {
                _trailerFields = trailerFields;
                _body = body;
                _responseIsComplete = responseIsComplete;
                _done = true;
            }
        }
    }

    /// <summary>Ends this stream with a failure, unless it already ended.</summary>
    /// <remarks>The FIRST fault wins, so the read loop's own shutdown reason cannot overwrite
    /// the more specific reason a stream already failed for.</remarks>
    internal void Fail(Exception exception)
    {
        lock (Sync)
        {
            _fault ??= exception;
        }
    }

    /// <summary>Takes everything not yet consumed. Called by the request thread only.</summary>
    internal Http3StreamProgress Take()
    {
        lock (Sync)
        {
            List<byte[]>? chunks = null;
            if (_chunks.Count > 0)
            {
                chunks = [.. _chunks];
                _chunks.Clear();
            }
            return new Http3StreamProgress(
                _status,
                _headerFields,
                _trailerFields,
                chunks,
                _body,
                _done,
                _responseIsComplete,
                _fault);
        }
    }
}

/// <summary>
/// Runs one QUIC connection's read loop and hands each received frame to the request stream it
/// belongs to, so that N requests may be in flight at once on one connection.
/// </summary>
/// <remarks>
/// <para>THE SHAPE IS <c>Http2Connection.ReadLoopAsync</c>'S, deliberately, because a second
/// concurrency model in one library is a second set of deadlocks to reason about. One loop task
/// owns the wire; a dictionary keyed by stream identifier is the dispatch table; each entry
/// carries the <see cref="Http3StreamState"/> its request thread is waiting on; and the loop's
/// single exit point fails every entry, which is what makes a stopped loop a thrown exception
/// rather than a hang.</para>
/// <para>WHAT IS DIFFERENT FROM HTTP/2, AND WHY THERE IS A GATE. HTTP/2 reads a
/// <see cref="Stream"/> and writes a <see cref="Stream"/>, and those are two independently
/// usable halves — so its read loop never contends with a thread opening a request. QUIC is one
/// <c>TlsQuicConnection</c> object that both the receive path and the send path mutate, and it
/// is not thread-safe. <see cref="_quicGate"/> therefore serialises EVERY call into SharpTls:
/// the loop's pump, a new request's <c>TryOpenRequest</c>, and the body copies the harvest
/// takes.</para>
/// <para>AND THAT GATE WOULD DEADLOCK WITHOUT THE INTERRUPT, which is the one genuinely subtle
/// thing here. A pump parked in <c>ReceiveWithinDeadlineAsync</c> holds the gate until a
/// datagram arrives or the QUIC deadline passes, and that deadline is the connection's whole
/// lifetime — minutes. A second request arriving in that window would wait minutes for the
/// gate. So a thread that wants the gate cancels the pump's token first, and the loop reads a
/// cancellation that is not its own lifetime's as "step aside" rather than as a failure.
/// <see cref="EnterQuicAsync"/> and <see cref="RunAsync"/> then race in the Dekker shape: the
/// waiter's <see cref="Interlocked.Increment(ref int)"/> precedes its read of
/// <see cref="_pumpInterrupt"/>, and the loop's <see cref="Interlocked.Exchange{T}"/> publishing
/// that source precedes its read of the counter. Both are full fences, so at least one of the
/// two sees the other: either the waiter cancels a live pump, or the loop finds the counter
/// raised and pre-cancels the pump it was about to start. Neither order can park a waiter behind
/// a full-length receive.</para>
/// <para>NO CONSUMER CODE RUNS ON THE LOOP. The harvest copies octets into
/// <see cref="Http3StreamState"/> and returns; the <c>StreamingResponseContext.WriteAsync</c>
/// that hands them to a caller runs on that caller's own request thread. A consumer that never
/// returns therefore stalls its own request and nothing else, which is the head-of-line property
/// QUIC exists to provide and which a loop that awaited consumer code would have thrown away
/// again.</para>
/// </remarks>
internal sealed class Http3StreamMultiplexer(IHttp3Streams streams) : IAsyncDisposable
{
    private readonly IHttp3Streams _streams = streams;
    private readonly ConcurrentDictionary<ulong, Http3StreamState> _active = new();
    private readonly SemaphoreSlim _quicGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private CancellationTokenSource? _pumpInterrupt;
    private int _interruptRequests;
    private int _stopped;
    private int _disposed;
    private Exception? _fault;
    private TaskCompletionSource _pumped =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? _loop;

    /// <summary>Gets whether any request stream is still in flight.</summary>
    internal bool HasActiveStreams => !_active.IsEmpty;

    /// <summary>Gets whether the read loop has stopped, for whatever reason.</summary>
    internal bool IsStopped => Volatile.Read(ref _stopped) != 0;

    /// <summary>
    /// Gets what ended the read loop, or <see langword="null"/> if it is running or was merely
    /// disposed.
    /// </summary>
    /// <remarks>KEPT BECAUSE <see cref="FailAll"/> REACHES ONLY THE STREAMS THAT EXISTED. The
    /// loop's fault is delivered to every request registered at the instant it stopped, and
    /// until it was retained here it was then discarded — so every request that arrived
    /// afterwards was told that the loop had stopped and never what stopped it. On a connection
    /// serving a long run of requests that is nearly all of them: the first caller sees an
    /// <see cref="ArgumentException"/> out of QUIC packet construction and every later one sees
    /// a bare stale-connection error, or, once the retry budget is spent, a session timeout. The
    /// connection is evicted either way — <c>Http3Connection.IsReusable</c> reads
    /// <see cref="IsStopped"/> — so this changes what is REPORTED and not what is recovered.
    /// </remarks>
    internal Exception? Fault => Volatile.Read(ref _fault);

    /// <summary>
    /// Gets a task that completes the next time the read loop makes progress, or when it stops.
    /// </summary>
    /// <remarks>CAPTURE THIS BEFORE READING A STREAM'S STATE, NEVER AFTER. The loop publishes a
    /// harvest and only then replaces this task, so a caller holding the earlier task is woken
    /// by any harvest it did not already see. Reading the state first and capturing afterwards
    /// would lose the wake-up that happened in between and park the request until the next
    /// datagram — or forever, if that was the last one.</remarks>
    internal Task Pumped => Volatile.Read(ref _pumped).Task;

    /// <summary>Starts the read loop.</summary>
    internal void Start() => _loop = Task.Run(RunAsync);

    /// <summary>
    /// Opens one request stream and registers it for dispatch.
    /// </summary>
    /// <remarks>The registration happens under the gate and therefore cannot race a harvest:
    /// the loop either has not pumped since this stream existed, or it has and the stream is
    /// already in the table.</remarks>
    /// <exception cref="Exception">Whatever <see cref="IHttp3Streams.Describe"/> chose for the
    /// refusal, or a <see cref="StaleHttpConnectionException"/> if the loop has stopped.
    /// </exception>
    internal async ValueTask<Http3StreamState> OpenAsync(
        TlsQuicHttp3Request request,
        bool wantsChunks,
        long bodyLimit,
        CancellationToken cancellationToken)
    {
        // Read BEFORE the gate is asked for, because a disposed multiplexer has disposed the
        // gate too and a caller deserves the reason rather than an ObjectDisposedException
        // naming a SemaphoreSlim it has never heard of.
        ThrowIfStopped();
        try
        {
            await EnterQuicAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            throw Stopped();
        }
        try
        {
            ThrowIfStopped();
            var streamId = _streams.TryOpenRequest(request, out var refusal, out var malformed)
                ?? throw _streams.Describe(refusal, malformed);

            var state = new Http3StreamState(streamId, wantsChunks, bodyLimit);
            _active[streamId] = state;
            // RE-READ AFTER REGISTERING, AND THAT ORDER IS THE WHOLE OF THE PROOF. FailAll
            // raises _stopped BEFORE it walks the table, so a registration that the walk missed
            // is necessarily one that happened after the flag was raised and is caught here.
            // The other order would leave a stream registered with no loop to ever harvest it,
            // and its request thread would wait for a wake-up that cannot come.
            if (IsStopped)
            {
                _active.TryRemove(streamId, out _);
                throw Stopped();
            }

            try
            {
                await _streams.SendPendingAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                _active.TryRemove(streamId, out _);
                throw;
            }
            return state;
        }
        finally
        {
            ExitQuic();
        }
    }

    /// <summary>Forgets one request stream, whether it completed or was abandoned.</summary>
    /// <remarks>An abandoned stream — a cancelled request, say — is only forgotten HERE and is
    /// not reset on the wire, because SharpTls exposes no RESET_STREAM. Its octets keep arriving
    /// into a reader nothing drains, so the connection that carried it is retired by the caller
    /// rather than reused.</remarks>
    internal void Release(ulong streamId) => _active.TryRemove(streamId, out _);

    private async Task RunAsync()
    {
        Exception? fault = null;
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                await _quicGate.WaitAsync(_lifetime.Token).ConfigureAwait(false);
                var steppedAside = false;
                try
                {
                    using var interrupt = CancellationTokenSource.CreateLinkedTokenSource(
                        _lifetime.Token);
                    // Published BEFORE the counter is read; see the type's remarks for why the
                    // pair of full fences is what keeps a waiter off a full-length receive.
                    Interlocked.Exchange(ref _pumpInterrupt, interrupt);
                    try
                    {
                        if (Volatile.Read(ref _interruptRequests) > 0)
                        {
                            interrupt.Cancel();
                        }
                        if (!await _streams.PumpOnceAsync(interrupt.Token).ConfigureAwait(false))
                        {
                            // The HTTP/3 layer answers a malformed peer with an RFC 9114
                            // section 8.1 code rather than an exception, so the code is the
                            // diagnosis.
                            throw new TlsHttpProtocolException(
                                "The HTTP/3 connection was closed with error code " +
                                $"0x{_streams.ConnectionErrorCode:x} (RFC 9114 section 8.1).");
                        }
                    }
                    catch (OperationCanceledException)
                        when (!_lifetime.IsCancellationRequested)
                    {
                        // Someone wants the gate. Not a failure: no datagram was consumed and
                        // the connection is untouched.
                        steppedAside = true;
                    }
                    finally
                    {
                        Interlocked.Exchange(ref _pumpInterrupt, null);
                    }

                    if (!steppedAside)
                    {
                        Harvest();
                    }
                }
                finally
                {
                    _quicGate.Release();
                }

                SignalPumped();
                if (steppedAside)
                {
                    // Let the waiter that interrupted us actually take the gate before we ask
                    // for it again. Without this the loop can win its own re-acquisition and
                    // spin, cancelling itself on every iteration.
                    await Task.Yield();
                }
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            // Disposal.
        }
        catch (Exception exception) when (
            exception is TimeoutException or InvalidOperationException)
        {
            // The QUIC layer's two failure shapes: its deadline passed, or the peer sent a
            // CONNECTION_CLOSE. Neither is something a caller of TlsClient should have to know
            // SharpTls's types to catch.
            //
            // AN IOException AND NOT A TlsHttpProtocolException, BECAUSE THE TYPE IS THE RETRY
            // DECISION. TlsSession.ShouldRetryException retries an IOException and never a
            // TlsHttpProtocolException, so naming a dead transport a protocol violation is what
            // made an idempotent HTTP/3 GET whose connection died un-retryable while the
            // identical HTTP/2 GET was retried. Http2Connection's read loop draws exactly this
            // line — it re-raises a TlsHttpProtocolException as itself and wraps everything else
            // in `new IOException("The HTTP/2 connection failed.", exception)` — and neither
            // shape here is a violation of RFC 9114: a deadline is our own clock and a
            // CONNECTION_CLOSE is the peer leaving. The PumpOnceAsync arm above, which IS a
            // section 8.1 error code, stays a TlsHttpProtocolException and stays un-retryable.
            //
            // Retrying is still not automatic: TlsSession.CanRetry additionally requires a
            // replayable, idempotent request (RetryNonIdempotentMethods defaults to false), so
            // a POST whose response was cut off is reported rather than sent twice.
            fault = new IOException(
                "The HTTP/3 (QUIC) connection failed before the response was complete.",
                exception);
        }
        catch (Exception exception)
        {
            fault = exception;
        }
        finally
        {
            FailAll(fault);
            SignalPumped();
        }
    }

    /// <summary>
    /// Copies what the last pump delivered into every registered stream's own state.
    /// </summary>
    /// <remarks>Runs under <see cref="_quicGate"/>, which is what makes the span
    /// <c>TlsQuicHttp3Response.Body</c> hands out safe to copy from: no other thread may be
    /// inside SharpTls while this runs.</remarks>
    private void Harvest()
    {
        foreach (var pair in _active)
        {
            var state = pair.Value;
            if (state.IsFinished)
            {
                continue;
            }

            var snapshot = _streams.Peek(pair.Key);
            if (snapshot.BodyLength > state.BodyLimit)
            {
                // Terminal for this stream, and the caller retires the connection: nothing here
                // can stop the peer sending the rest of a body it was never asked to stop.
                state.Fail(new TlsHttpProtocolException(
                    "The HTTP/3 response body exceeds the configured limit."));
                continue;
            }

            byte[]? chunk = null;
            if (state.WantsChunks && snapshot.BodyLength > state.Consumed)
            {
                chunk = _streams.CopyBody(pair.Key, state.Consumed, snapshot.BodyLength);
                state.Consumed = snapshot.BodyLength;
            }
            var body = snapshot.ReceiveComplete && !state.WantsChunks
                ? _streams.CopyBody(pair.Key, 0, snapshot.BodyLength)
                : null;
            state.Publish(
                snapshot.Status,
                snapshot.HeaderFields,
                chunk,
                snapshot.TrailerFields,
                body,
                snapshot.ReceiveComplete,
                snapshot.IsComplete);
        }
    }

    /// <summary>
    /// Ends every registered stream, so that no request thread is left waiting on a loop that
    /// has stopped.
    /// </summary>
    /// <remarks>THE FLAG IS RAISED BEFORE THE WALK. <see cref="OpenAsync"/> re-reads it after
    /// registering, so the two orders between them cover every interleaving: a stream in the
    /// table when the walk runs is failed here, and one added afterwards sees the flag and is
    /// withdrawn there.</remarks>
    private void FailAll(Exception? fault)
    {
        // THE FAULT IS PUBLISHED BEFORE THE FLAG, for the same reason the flag precedes the
        // walk: OpenAsync re-reads IsStopped after registering, and a caller that finds the flag
        // raised must find the cause with it rather than a null that has not landed yet.
        Volatile.Write(ref _fault, fault);
        Volatile.Write(ref _stopped, 1);
        var ended = fault ?? Stopped();
        foreach (var pair in _active)
        {
            pair.Value.Fail(ended);
        }
    }

    /// <summary>Takes exclusive use of SharpTls, interrupting the pump if it holds it.</summary>
    private async ValueTask EnterQuicAsync(CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _interruptRequests);
        try
        {
            InterruptPump();
            await _quicGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            Interlocked.Decrement(ref _interruptRequests);
            throw;
        }
    }

    private void ExitQuic()
    {
        Interlocked.Decrement(ref _interruptRequests);
        _quicGate.Release();
    }

    private void InterruptPump()
    {
        try
        {
            Volatile.Read(ref _pumpInterrupt)?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The pump ended between the read and the cancel, so it is already not holding the
            // gate. The loop's next iteration reads the raised counter and pre-cancels.
        }
    }

    private void SignalPumped() =>
        Interlocked.Exchange(
            ref _pumped,
            new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously))
            .TrySetResult();

    private void ThrowIfStopped()
    {
        if (IsStopped)
        {
            throw Stopped();
        }
    }

    /// <summary>
    /// The refusal every entry point raises once the read loop has stopped, naming what stopped
    /// it.
    /// </summary>
    /// <remarks>NOT STATIC ANY MORE, WHICH IS THE POINT. A stopped loop is a
    /// <see cref="StaleHttpConnectionException"/> so that <c>TlsSession.ShouldRetryException</c>
    /// retries an idempotent request on a fresh connection and <c>TlsConnectionPool</c> evicts
    /// this one; both read the TYPE, so attaching <see cref="Fault"/> changes neither decision.
    /// What it changes is the report: without it a caller who arrived after the loop died was
    /// told only that it had died, and the QUIC fault that actually killed it — the one thing
    /// that says whether a fresh connection can help — reached nobody.</remarks>
    private StaleHttpConnectionException Stopped() => new(
        "The HTTP/3 connection's read loop has stopped, so it accepts no further requests." +
        (Fault is { } fault ? $" It stopped because: {fault.Message}" : string.Empty),
        Fault);

    /// <summary>
    /// Stops the read loop and waits for it to finish before anything it touches is disposed.
    /// </summary>
    /// <remarks>
    /// <para>BOUNDED AT EVERY STEP. The loop awaits exactly three things, and all of them
    /// observe <see cref="_lifetime"/>: the gate, the pump, and a yield. Cancelling the lifetime
    /// therefore ends the current one and the loop falls out of its <c>while</c>, so
    /// <c>await _loop</c> cannot wait indefinitely for a loop that is merely idle.</para>
    /// <para>THE ORDER IS THE ANTI-RACE. The loop is awaited to completion BEFORE the gate is
    /// taken and before the caller disposes SharpTls, so nothing can be inside a pump while the
    /// connection underneath it is torn down. Taking the gate afterwards waits only on a
    /// request thread inside <see cref="OpenAsync"/>, whose critical section is a synchronous
    /// encode and one datagram send.</para>
    /// </remarks>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            // Cancel() on an already-disposed CancellationTokenSource throws, so a second
            // disposal must not reach it. A connection is disposed twice routinely: once by the
            // pool retiring it and once by an `await using` that still holds it.
            return;
        }
        _lifetime.Cancel();
        if (_loop is { } loop)
        {
            try
            {
                await loop.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // RunAsync does not let exceptions escape, but a loop that never started
                // cleanly must not turn disposal into a throw either.
            }
        }
        else
        {
            // Nothing ever ran, so nothing else will end the streams a caller registered.
            FailAll(null);
            SignalPumped();
        }

        // BOUNDED, BECAUSE AN UNBOUNDED WAIT HERE IS THE ONE HANG DISPOSAL COULD STILL HAVE.
        // The only other holder is a request thread inside OpenAsync, whose critical section is
        // a synchronous encode and one UDP send; five seconds is far past either. Giving up
        // leaves the semaphore undisposed rather than pulling it out from under that thread —
        // an undisposed SemaphoreSlim costs a finalizable object, and a disposed one costs the
        // other thread an ObjectDisposedException it never asked for.
        if (await _quicGate.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false))
        {
            _quicGate.Release();
            _quicGate.Dispose();
        }
        _lifetime.Dispose();
    }
}
