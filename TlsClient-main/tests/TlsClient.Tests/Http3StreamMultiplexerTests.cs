using System.Collections.Immutable;
using System.Threading.Channels;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>
/// The witness that HTTP/3 requests genuinely overlap on one connection.
/// </summary>
/// <remarks>
/// <para>"N REQUESTS COMPLETED" IS NOT THE CLAIM, BECAUSE SERIALISATION SATISFIES IT TOO. Every
/// test here asserts something a one-request-at-a-time client could not produce: two streams
/// open at the same instant, a second response completing while the first has had nothing, or a
/// completion ORDER that is the reverse of the open order. A connection that still serialised
/// would fail them by deadlocking rather than by returning a wrong number, so every wait is
/// bounded and a bound that expires is the failure.</para>
/// <para>THE FAKE WIRE IS A CHANNEL, one posted item per datagram. Nothing arrives that a test
/// did not post, so "request A has received nothing yet" is a state a test can hold indefinitely
/// rather than one it has to race — which is what makes the head-of-line test an assertion
/// rather than a hope.</para>
/// </remarks>
public sealed class Http3StreamMultiplexerTests
{
    /// <summary>Every wait in this file. Long enough that a loaded CI machine does not trip it,
    /// short enough that a genuine deadlock fails the run rather than hanging it.</summary>
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);

    // ------------------------------------------------------------------------------
    // The fake wire.
    // ------------------------------------------------------------------------------

    private sealed class FakeStream
    {
        internal int Status { get; set; } = -1;

        internal ImmutableArray<TlsQuicHttp3Field> HeaderFields { get; set; } = [];

        internal ImmutableArray<TlsQuicHttp3Field> TrailerFields { get; set; } = [];

        internal List<byte> Body { get; } = [];

        internal bool ReceiveComplete { get; set; }

        internal bool IsComplete { get; set; }
    }

    /// <summary>
    /// An <see cref="IHttp3Streams"/> whose every datagram is posted by the test.
    /// </summary>
    /// <remarks><see cref="PumpOnceAsync"/> parks on the channel exactly as the real one parks
    /// on a UDP receive, so a test that opens a second request while it is parked is exercising
    /// the interrupt handshake and not a shortcut around it.</remarks>
    private sealed class FakeHttp3Streams : IHttp3Streams
    {
        private readonly Channel<Action<FakeHttp3Streams>> _wire =
            Channel.CreateUnbounded<Action<FakeHttp3Streams>>();

        private readonly Dictionary<ulong, FakeStream> _streams = [];
        private readonly object _sync = new();
        private ulong _nextStreamId;

        internal ulong ConnectionErrorCodeValue { get; set; }

        internal TlsQuicHttp3RequestRefusal RefuseWith { get; set; } =
            TlsQuicHttp3RequestRefusal.None;

        /// <summary>The largest number of streams that were open and unfinished at once.
        /// </summary>
        /// <remarks>THIS IS THE OVERLAP ITSELF, sampled where it happens rather than inferred
        /// from timings. A serialising connection can never drive it above 1.</remarks>
        internal int MaximumOpenAtOnce { get; private set; }

        internal int PumpCount;

        public ulong ConnectionErrorCode => ConnectionErrorCodeValue;

        public ulong? PeerGoawayStreamId => null;

        public ulong? TryOpenRequest(
            TlsQuicHttp3Request request,
            out TlsQuicHttp3RequestRefusal refusal,
            out TlsQuicHttp3RequestError malformed)
        {
            malformed = TlsQuicHttp3RequestError.None;
            refusal = RefuseWith;
            if (refusal != TlsQuicHttp3RequestRefusal.None)
            {
                return null;
            }
            lock (_sync)
            {
                var id = _nextStreamId;
                _nextStreamId += 4;
                _streams[id] = new FakeStream();
                var live = _streams.Values.Count(stream => !stream.ReceiveComplete);
                MaximumOpenAtOnce = Math.Max(MaximumOpenAtOnce, live);
                refusal = TlsQuicHttp3RequestRefusal.None;
                return id;
            }
        }

        public ValueTask SendPendingAsync(CancellationToken cancellationToken) =>
            ValueTask.CompletedTask;

        public async ValueTask<bool> PumpOnceAsync(CancellationToken cancellationToken)
        {
            var apply = await _wire.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref PumpCount);
            apply(this);
            return ConnectionErrorCodeValue == 0;
        }

        public Http3StreamSnapshot Peek(ulong streamId)
        {
            lock (_sync)
            {
                if (!_streams.TryGetValue(streamId, out var stream))
                {
                    return new Http3StreamSnapshot(-1, [], [], 0, false, false);
                }
                return new Http3StreamSnapshot(
                    stream.Status,
                    stream.HeaderFields,
                    stream.TrailerFields,
                    stream.Body.Count,
                    stream.ReceiveComplete,
                    stream.IsComplete);
            }
        }

        public byte[] CopyBody(ulong streamId, int start, int end)
        {
            lock (_sync)
            {
                return _streams.TryGetValue(streamId, out var stream)
                    ? [.. stream.Body.GetRange(start, end - start)]
                    : [];
            }
        }

        public Exception Describe(
            TlsQuicHttp3RequestRefusal refusal,
            TlsQuicHttp3RequestError malformed) =>
            new TlsHttpProtocolException($"refused: {refusal}");

        /// <summary>Delivers one datagram.</summary>
        internal void Post(Action<FakeHttp3Streams> apply) => _wire.Writer.TryWrite(apply);

        /// <summary>Delivers a datagram that changes nothing, so the loop takes a turn.</summary>
        internal void PostIdle() => Post(_ => { });

        /// <summary>Delivers a complete response on one stream.</summary>
        internal void PostResponse(ulong streamId, int status, byte[] body) => Post(fake =>
        {
            lock (fake._sync)
            {
                var stream = fake._streams[streamId];
                stream.Status = status;
                stream.HeaderFields = [new TlsQuicHttp3Field(":status", $"{status}")];
                stream.Body.AddRange(body);
                stream.ReceiveComplete = true;
                stream.IsComplete = true;
            }
        });

        /// <summary>Delivers a header section and some body, leaving the stream open.</summary>
        internal void PostPartial(ulong streamId, int status, byte[] body) => Post(fake =>
        {
            lock (fake._sync)
            {
                var stream = fake._streams[streamId];
                stream.Status = status;
                stream.HeaderFields = [new TlsQuicHttp3Field(":status", $"{status}")];
                stream.Body.AddRange(body);
            }
        });

        /// <summary>Delivers a datagram the HTTP/3 layer answers with a section 8.1 code.
        /// </summary>
        internal void PostConnectionError(ulong code) =>
            Post(fake => fake.ConnectionErrorCodeValue = code);

        /// <summary>Delivers a datagram whose processing throws the way a spent QUIC deadline
        /// does.</summary>
        internal void PostTransportFailure() =>
            Post(_ => throw new TimeoutException("the QUIC deadline passed"));
    }

    private static TlsQuicHttp3Request Request(string path = "/") => new()
    {
        Method = "GET",
        Scheme = "https",
        Authority = "example.com",
        Path = path,
    };

    private static async ValueTask<Http3StreamState> OpenAsync(
        Http3StreamMultiplexer multiplexer,
        CancellationToken cancellationToken = default) =>
        await multiplexer
            .OpenAsync(Request(), wantsChunks: false, bodyLimit: 1 << 20, cancellationToken)
            .AsTask()
            .WaitAsync(Bound, cancellationToken)
            .ConfigureAwait(false);

    /// <summary>Waits for one stream to finish and returns what it ended with.</summary>
    private static Task<Http3StreamProgress> FinishAsync(
        Http3StreamMultiplexer multiplexer,
        Http3StreamState state,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
        {
            while (true)
            {
                var pumped = multiplexer.Pumped;
                var progress = state.Take();
                if (progress.Done || progress.Fault is not null)
                {
                    return progress;
                }
                await pumped.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        });

    // ------------------------------------------------------------------------------
    // The overlap itself.
    // ------------------------------------------------------------------------------

    [Fact]
    public async Task TwoRequestsAreOpenOnTheConnectionAtTheSameTime()
    {
        // THE DIRECT WITNESS. Both streams exist before either has received anything, which a
        // connection that opened the second only after the first completed cannot produce —
        // and the fake counts them where they are opened rather than inferring it from a clock.
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var first = await OpenAsync(multiplexer);
        var second = await OpenAsync(multiplexer);

        Assert.Equal(2, fake.MaximumOpenAtOnce);
        Assert.NotEqual(first.StreamId, second.StreamId);

        fake.PostResponse(first.StreamId, 200, [1, 2, 3]);
        fake.PostResponse(second.StreamId, 201, [4]);
        var firstDone = await FinishAsync(multiplexer, first).WaitAsync(Bound);
        var secondDone = await FinishAsync(multiplexer, second).WaitAsync(Bound);
        Assert.Equal(200, firstDone.Status);
        Assert.Equal(201, secondDone.Status);
    }

    [Fact]
    public async Task ResponsesCompleteInTheOrderTheWireDeliversThemAndNotTheOrderTheyWereSent()
    {
        // SERIALISATION CANNOT PRODUCE THIS ORDER AT ALL. A client that opens a request only
        // after the previous one finished can never have the SECOND request complete first,
        // because the second does not exist until the first is done. The completion order here
        // is therefore the reverse of the open order, which is a fact about concurrency rather
        // than about timing, and no amount of machine load can flip it.
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var first = await OpenAsync(multiplexer);
        var second = await OpenAsync(multiplexer);

        var completions = new List<ulong>();
        var order = new object();
        var firstTask = Task.Run(async () =>
        {
            await FinishAsync(multiplexer, first).ConfigureAwait(false);
            lock (order)
            {
                completions.Add(first.StreamId);
            }
        });
        var secondTask = Task.Run(async () =>
        {
            await FinishAsync(multiplexer, second).ConfigureAwait(false);
            lock (order)
            {
                completions.Add(second.StreamId);
            }
        });

        fake.PostResponse(second.StreamId, 200, [7]);
        await secondTask.WaitAsync(Bound);
        Assert.False(firstTask.IsCompleted);

        fake.PostResponse(first.StreamId, 200, [8]);
        await firstTask.WaitAsync(Bound);

        Assert.Equal(new[] { second.StreamId, first.StreamId }, completions);
    }

    [Fact]
    public async Task AStalledResponseDoesNotBlockAnUnrelatedRequestOnTheSameConnection()
    {
        // THE HEAD-OF-LINE PROPERTY, WHICH IS WHY QUIC EXISTS. The first stream receives
        // nothing for the whole test — not "slowly", nothing — and the second still runs to
        // completion. Under the old pump the second request could not even have been opened.
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var stalled = await OpenAsync(multiplexer);
        var healthy = await OpenAsync(multiplexer);

        var stalledTask = FinishAsync(multiplexer, stalled);
        fake.PostResponse(healthy.StreamId, 204, []);

        var done = await FinishAsync(multiplexer, healthy).WaitAsync(Bound);
        Assert.Equal(204, done.Status);
        Assert.True(done.Done);
        Assert.False(stalledTask.IsCompleted);

        // And the stalled one ends when the connection does, rather than hanging.
        await multiplexer.DisposeAsync();
        var abandoned = await stalledTask.WaitAsync(Bound);
        Assert.NotNull(abandoned.Fault);
    }

    [Fact]
    public async Task ManyRequestsOverlapRatherThanQueueing()
    {
        // The plural of the first test, and the assertion is still the overlap and not the
        // count: sixteen requests that each waited for the last would report a maximum of 1.
        const int Count = 16;
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var states = new List<Http3StreamState>();
        for (var index = 0; index < Count; index++)
        {
            states.Add(await OpenAsync(multiplexer));
        }
        Assert.Equal(Count, fake.MaximumOpenAtOnce);

        // Answered back to front, so no prefix of the completion order matches the open order.
        var tasks = states.Select(state => FinishAsync(multiplexer, state)).ToArray();
        for (var index = Count - 1; index >= 0; index--)
        {
            fake.PostResponse(states[index].StreamId, 200 + index, []);
        }
        var results = await Task.WhenAll(tasks).WaitAsync(Bound);
        for (var index = 0; index < Count; index++)
        {
            Assert.Equal(200 + index, results[index].Status);
        }
    }

    [Fact]
    public async Task ASecondRequestIsAdmittedWhileTheReadLoopIsParkedOnTheWire()
    {
        // THE INTERRUPT HANDSHAKE, ISOLATED. The loop is parked on a receive that will never
        // complete on its own; opening a request has to take the connection away from it. If
        // the interrupt were dropped this call would wait for the parked pump — which is
        // forever here, and up to the QUIC connection's whole lifetime in production — so the
        // bound expiring IS the regression.
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var first = await OpenAsync(multiplexer);
        // Let the loop reach its parked receive before asking for the connection back.
        fake.PostIdle();
        await WaitForPumpAsync(fake, atLeast: 1);

        var second = await OpenAsync(multiplexer);
        Assert.NotEqual(first.StreamId, second.StreamId);
        Assert.Equal(2, fake.MaximumOpenAtOnce);

        // And the loop resumed afterwards rather than staying stepped aside.
        fake.PostResponse(second.StreamId, 200, []);
        var done = await FinishAsync(multiplexer, second).WaitAsync(Bound);
        Assert.Equal(200, done.Status);
    }

    // ------------------------------------------------------------------------------
    // Cancellation, faults and disposal: every one of them bounded.
    // ------------------------------------------------------------------------------

    [Fact]
    public async Task CancellingOneRequestLeavesAnotherOnTheSameConnectionRunning()
    {
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var cancelled = await OpenAsync(multiplexer);
        var survivor = await OpenAsync(multiplexer);

        using var source = new CancellationTokenSource();
        var cancelledTask = FinishAsync(multiplexer, cancelled, source.Token);
        await source.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => cancelledTask.WaitAsync(Bound));

        fake.PostResponse(survivor.StreamId, 200, [9]);
        var done = await FinishAsync(multiplexer, survivor).WaitAsync(Bound);
        Assert.Equal(200, done.Status);
    }

    [Fact]
    public async Task AConnectionErrorEndsEveryInFlightRequestRatherThanLeavingOneWaiting()
    {
        // RFC 9114 section 8.1's answer to a malformed peer is a code and not an exception, so
        // the loop reads `false` and turns it into the one exception every waiter gets. The
        // point of the test is that BOTH waiters get it: a loop that failed only the stream it
        // was harvesting would leave the other parked forever.
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var first = await OpenAsync(multiplexer);
        var second = await OpenAsync(multiplexer);
        var firstTask = FinishAsync(multiplexer, first);
        var secondTask = FinishAsync(multiplexer, second);

        fake.PostConnectionError(0x105);

        var firstEnd = await firstTask.WaitAsync(Bound);
        var secondEnd = await secondTask.WaitAsync(Bound);
        Assert.Contains("0x105", Assert.IsType<TlsHttpProtocolException>(firstEnd.Fault).Message);
        Assert.NotNull(secondEnd.Fault);
        Assert.True(multiplexer.IsStopped);
    }

    [Fact]
    public async Task AMalformedPeerIsReportedRatherThanThrownOutOfTheLoop()
    {
        // The loop must not let anything escape it, whatever the peer sent. Disposal after a
        // fault is the check: a loop that had faulted its task would make DisposeAsync throw.
        var fake = new FakeHttp3Streams();
        var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var state = await OpenAsync(multiplexer);
        var task = FinishAsync(multiplexer, state);
        fake.PostConnectionError(0x102);
        Assert.NotNull((await task.WaitAsync(Bound)).Fault);

        await multiplexer.DisposeAsync().AsTask().WaitAsync(Bound);
    }

    /// <summary>
    /// A dead QUIC transport ends every in-flight request with a TlsClient exception of the one
    /// shape the retry policy will act on.
    /// </summary>
    /// <remarks>THE TYPE IS THE CLAIM, NOT MERELY THE WRAPPING.
    /// <c>TlsSession.ShouldRetryException</c> retries an <see cref="IOException"/> and never a
    /// <see cref="TlsHttpProtocolException"/>, so reporting a dead transport as the latter — a
    /// subtype of the former, which <see cref="Assert.IsType{T}(object)"/> is exact enough to
    /// tell apart — is what made an idempotent HTTP/3 request whose connection died the one
    /// request TlsClient would not try again. <see cref="Http3ClientMachineryTests"/> holds the
    /// end-to-end half: that <c>TlsSession</c> really does take another QUIC connection.
    /// </remarks>
    [Fact]
    public async Task ATransportFailureEndsEveryInFlightRequestWithARetryableIOException()
    {
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var state = await OpenAsync(multiplexer);
        var task = FinishAsync(multiplexer, state);
        fake.PostTransportFailure();

        var end = await task.WaitAsync(Bound);
        var fault = Assert.IsType<IOException>(end.Fault);
        Assert.IsNotType<TlsHttpProtocolException>(end.Fault);
        Assert.IsType<TimeoutException>(fault.InnerException);
    }

    [Fact]
    public async Task DisposalEndsEveryInFlightRequestAndDoesNotHang()
    {
        var fake = new FakeHttp3Streams();
        var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var first = await OpenAsync(multiplexer);
        var second = await OpenAsync(multiplexer);
        var firstTask = FinishAsync(multiplexer, first);
        var secondTask = FinishAsync(multiplexer, second);

        await multiplexer.DisposeAsync().AsTask().WaitAsync(Bound);

        Assert.NotNull((await firstTask.WaitAsync(Bound)).Fault);
        Assert.NotNull((await secondTask.WaitAsync(Bound)).Fault);
        Assert.True(multiplexer.IsStopped);
    }

    [Fact]
    public async Task DisposingTwiceIsQuiet()
    {
        var fake = new FakeHttp3Streams();
        var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();
        await multiplexer.DisposeAsync().AsTask().WaitAsync(Bound);
        await multiplexer.DisposeAsync().AsTask().WaitAsync(Bound);
    }

    [Fact]
    public async Task ARequestOpenedAfterTheLoopStoppedIsRefusedRatherThanLeftWaiting()
    {
        // The window this closes is narrow and its cost is a hang: a stream registered after
        // FailAll walked the table would have no loop to harvest it and its caller would wait
        // for a wake-up that cannot come.
        var fake = new FakeHttp3Streams();
        var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();
        await multiplexer.DisposeAsync().AsTask().WaitAsync(Bound);

        await Assert.ThrowsAsync<StaleHttpConnectionException>(
            () => multiplexer.OpenAsync(Request(), false, 1 << 20, default).AsTask()
                .WaitAsync(Bound));
    }

    [Fact]
    public async Task ADisposedMultiplexerThatNeverStartedStillEndsItsStreams()
    {
        // Start() is the caller's to forget, and forgetting it must not turn into a hang.
        var multiplexer = new Http3StreamMultiplexer(new FakeHttp3Streams());
        await multiplexer.DisposeAsync().AsTask().WaitAsync(Bound);
        Assert.True(multiplexer.IsStopped);
    }

    [Fact]
    public async Task ARefusedRequestIsReportedAndOpensNoStream()
    {
        var fake = new FakeHttp3Streams
        {
            RefuseWith = TlsQuicHttp3RequestRefusal.GoawayReceived,
        };
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        await Assert.ThrowsAsync<TlsHttpProtocolException>(
            () => multiplexer.OpenAsync(Request(), false, 1 << 20, default).AsTask()
                .WaitAsync(Bound));
        Assert.False(multiplexer.HasActiveStreams);
    }

    // ------------------------------------------------------------------------------
    // Dispatch: the right octets reach the right stream.
    // ------------------------------------------------------------------------------

    [Fact]
    public async Task EachStreamReceivesOnlyItsOwnBody()
    {
        // The dispatch key is the stream identifier, and a multiplexer that ignored it would
        // still pass every test above — every one of them would simply hand both requests the
        // same bytes.
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var first = await OpenAsync(multiplexer);
        var second = await OpenAsync(multiplexer);
        fake.PostResponse(first.StreamId, 200, [1, 1, 1]);
        fake.PostResponse(second.StreamId, 200, [2, 2]);

        var firstEnd = await FinishAsync(multiplexer, first).WaitAsync(Bound);
        var secondEnd = await FinishAsync(multiplexer, second).WaitAsync(Bound);
        Assert.Equal(new byte[] { 1, 1, 1 }, firstEnd.Body);
        Assert.Equal(new byte[] { 2, 2 }, secondEnd.Body);
    }

    [Fact]
    public async Task AStreamingRequestTakesItsBodyAsItArrivesAndNotOnlyAtTheEnd()
    {
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var state = await multiplexer
            .OpenAsync(Request(), wantsChunks: true, bodyLimit: 1 << 20, default)
            .AsTask()
            .WaitAsync(Bound);

        fake.PostPartial(state.StreamId, 200, [1, 2]);
        await WaitForPumpAsync(fake, atLeast: 1);

        var early = state.Take();
        Assert.False(early.Done);
        Assert.Equal(new byte[] { 1, 2 }, Assert.Single(early.Chunks!));

        fake.PostResponse(state.StreamId, 200, [3]);
        var end = await FinishAsync(multiplexer, state).WaitAsync(Bound);
        Assert.True(end.Done);
        // Only the tail, because the first two octets were already taken.
        Assert.Equal(new byte[] { 3 }, Assert.Single(end.Chunks!));
        // And a streaming request is never handed a second, whole copy of the body.
        Assert.Null(end.Body);
    }

    [Fact]
    public async Task AResponseBodyPastTheLimitEndsThatStreamAndNotTheConnection()
    {
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var large = await multiplexer
            .OpenAsync(Request(), wantsChunks: false, bodyLimit: 2, default)
            .AsTask()
            .WaitAsync(Bound);
        var small = await OpenAsync(multiplexer);

        fake.PostResponse(large.StreamId, 200, [1, 2, 3, 4]);
        var end = await FinishAsync(multiplexer, large).WaitAsync(Bound);
        Assert.IsType<TlsHttpProtocolException>(end.Fault);

        fake.PostResponse(small.StreamId, 200, [5]);
        var survived = await FinishAsync(multiplexer, small).WaitAsync(Bound);
        Assert.Equal(200, survived.Status);
    }

    [Fact]
    public async Task TheFirstReasonAStreamFailedIsTheOneItsCallerIsTold()
    {
        // A stream that failed for a SPECIFIC reason and then outlived the read loop must keep
        // the specific reason. Disposal fails every registered stream with a generic "the read
        // loop has stopped", and letting that overwrite "the response body exceeds the
        // configured limit" would hand the caller the one message that does not say what went
        // wrong — while every other assertion in this file still passed.
        var fake = new FakeHttp3Streams();
        var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var state = await multiplexer
            .OpenAsync(Request(), wantsChunks: false, bodyLimit: 1, default)
            .AsTask()
            .WaitAsync(Bound);

        fake.PostResponse(state.StreamId, 200, [1, 2, 3]);
        var failed = await FinishAsync(multiplexer, state).WaitAsync(Bound);
        Assert.Contains("exceeds the configured limit", failed.Fault!.Message);

        await multiplexer.DisposeAsync().AsTask().WaitAsync(Bound);
        Assert.Contains("exceeds the configured limit", state.Take().Fault!.Message);
    }

    [Fact]
    public async Task AReleasedStreamIsNoLongerActive()
    {
        var fake = new FakeHttp3Streams();
        await using var multiplexer = new Http3StreamMultiplexer(fake);
        multiplexer.Start();

        var state = await OpenAsync(multiplexer);
        Assert.True(multiplexer.HasActiveStreams);
        multiplexer.Release(state.StreamId);
        Assert.False(multiplexer.HasActiveStreams);
    }

    /// <summary>Waits until the loop has processed at least <paramref name="atLeast"/> datagrams.
    /// </summary>
    /// <remarks>Bounded by <see cref="Bound"/> and polled rather than signalled, because the
    /// thing being waited for is the loop's own progress and a signal from the loop would be
    /// the very thing under test.</remarks>
    private static async Task WaitForPumpAsync(FakeHttp3Streams fake, int atLeast)
    {
        var deadline = DateTime.UtcNow + Bound;
        while (Volatile.Read(ref fake.PumpCount) < atLeast)
        {
            Assert.True(DateTime.UtcNow < deadline, "the read loop never pumped");
            await Task.Delay(5).ConfigureAwait(false);
        }
    }
}
