using System.Buffers.Binary;
using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

/// <summary>
/// Write batching is only observable through <see cref="Wire.Http2WireServer.ReadOnceAsync"/>:
/// one read returns what one record delivered, so the octet count is where the client
/// ended a batch. The frame-reading path uses ReadExactly and reports the reader's shape
/// instead.
/// </summary>
public sealed class Http2WriteBatchTests
{
    [Fact]
    public async Task FlushAfter_EndsTheRecordAtTheDeclaredBoundary()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.Preface =
        [
            new TlsHttp2SettingsFrame { Settings = [new(0x1, 4_096)], FlushAfter = true },
            new TlsHttp2WindowUpdateFrame { Increment = 1_000 },
        ];

        var delivered = 0;
        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, cancellationToken) => session.GetAsync(url, cancellationToken),
            async (server, cancellationToken) =>
            {
                // 24 magic + 15 SETTINGS = 39; the WINDOW_UPDATE's 13 must not join it.
                delivered = await server.ReadOnceAsync(52, cancellationToken);
                var headers = await server.ReadUntilAsync(Http2FrameType.Headers, cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    headers.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal(39, delivered);
    }

    /// <summary>
    /// A batch never holds more than its bound, so a persona cannot turn a declared batch
    /// into unbounded buffering. Asserted against the batch directly: no session-level
    /// knob reaches a 1 MiB batch yet, since every DATA frame still ends one.
    /// </summary>
    [Fact]
    public async Task Buffer_WritesEarlyRatherThanGrowingPastItsBound()
    {
        var transport = new MemoryStream();
        var batch = new Http2WriteBatch(transport);
        var chunk = new byte[512 * 1024];

        for (var index = 0; index < 3; index++)
        {
            await batch.WriteAsync(chunk, CancellationToken.None);
        }

        // Unbounded buffering would have written nothing yet, still holding all 1.5 MiB.
        Assert.InRange(transport.Length, 1, Http2WriteBatch.MaximumBufferedBytes);

        await batch.FlushAsync(CancellationToken.None);

        Assert.Equal(3L * chunk.Length, transport.Length);
    }

    /// <summary>
    /// A write that fails must not leave its octets in the buffer. The failure here is an
    /// <see cref="OperationCanceledException"/> from a per-request token, which says
    /// nothing about the transport, so the connection keeps going — and RFC 9113 section
    /// 4.1 has every frame begin with its own 9-octet header immediately followed by
    /// exactly its declared payload. Since a frame's header and payload are separate
    /// appends, a retained remnant can be a header with no payload, which desynchronizes
    /// the peer's framing rather than merely wasting octets.
    /// </summary>
    [Fact]
    public async Task Batch_DropsTheOctetsOfAFailedWriteInsteadOfPrependingThem()
    {
        var transport = new FailFirstWriteStream();
        var batch = new Http2WriteBatch(transport);

        await batch.WriteAsync(new byte[] { 1, 2, 3 }, CancellationToken.None);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await batch.FlushAsync(CancellationToken.None));

        await batch.WriteAsync(new byte[] { 4, 5 }, CancellationToken.None);
        await batch.FlushAsync(CancellationToken.None);

        Assert.Equal(new byte[] { 4, 5 }, transport.WrittenBytes);
    }

    // Three 4096-octet DATA frames plus the zero-length DATA that carries END_STREAM:
    // 3 * (9 + 4096) + 9. Small enough that one TLS record holds the lot, so the octets a
    // single read delivers say whether the client ended a batch per frame or per body.
    private const int ChunkSize = 4_096;
    private const int BodyOctets = 3 * ChunkSize;
    // Three DATA frames and their 9-octet headers. The last one carries END_STREAM: since
    // Task 14 the placement is the persona's, and its default puts the flag on the last DATA
    // frame of any body whose length the caller declared, streamed or buffered.
    private const int BodyFrameOctets = 3 * (9 + ChunkSize);

    // The peer's SETTINGS_MAX_FRAME_SIZE starts at 16384 and cannot be advertised below it
    // (RFC 9113 section 6.5.2), so one read of three times that becomes three DATA frames
    // without the peer having to say anything.
    private const int MaximumFrameSize = 16 * 1024;
    private const int LargeReadOctets = 3 * MaximumFrameSize;

    /// <summary>
    /// The coalescing the batch exists for: several DATA frames from one read of the
    /// content stream leave as one write, so the record boundaries fall where the
    /// transport's 16384-octet limit puts them rather than at each frame.
    /// </summary>
    [Fact]
    public async Task FlushAfterEveryDataFrame_False_CoalescesTheFramesOfOneRead()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.FlushAfterEveryDataFrame = false;

        var records = await PostOneLargeReadAsync(options);

        // One write of 3 * (9 + 16384) = 49179, cut into records by the transport. Per-frame
        // flushing would instead give 16384, 9, 16384, 9, 16384, 9 — every frame's own
        // boundary showing through.
        Assert.Equal([MaximumFrameSize, MaximumFrameSize, MaximumFrameSize, 27], records);
    }

    [Fact]
    public async Task FlushAfterEveryDataFrame_True_EndsTheRecordAtEachDataFrame()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };

        // The default, and today's behaviour.
        Assert.True(options.Http2.FlushAfterEveryDataFrame);

        var first = await PostThreeDataFramesAsync(options);

        Assert.Equal(9 + ChunkSize, first);
    }

    /// <summary>
    /// A streaming upload blocks on the caller's content stream between chunks. A producer
    /// whose next chunk depends on the peer having seen the last one — a duplex relay, any
    /// application-level acknowledgement — deadlocks if the batch is still holding those
    /// octets, so no persona may withhold them across that read. The content stream here
    /// makes the dependency explicit: its second chunk exists only after the server has
    /// read the first.
    /// </summary>
    [Fact]
    public async Task StreamedChunk_ReachesTheServerBeforeTheNextChunkIsProduced()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.FlushAfterEveryDataFrame = false;

        var acknowledged = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var received = 0;

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var content = new StreamContent(
                    new AcknowledgedChunkStream(ChunkSize, acknowledged.Task));
                content.Headers.ContentLength = 2 * ChunkSize;
                using var message = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = content,
                };
                message.AddHeader("content-length", "-1");
                await using var responseBody = new MemoryStream();
                return await session.SendStreamingAsync(
                    message,
                    responseBody,
                    new TlsStreamingOptions { BufferSize = ChunkSize },
                    cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);
                var headers = await server.ReadUntilAsync(
                    Http2FrameType.Headers,
                    cancellationToken);

                var first = await server.ReadUntilAsync(Http2FrameType.Data, cancellationToken);
                received = first.Payload.Length;

                // Only now can the producer make its second chunk.
                acknowledged.SetResult();

                while (received < 2 * ChunkSize)
                {
                    var frame = await server.ReadFrameAsync(cancellationToken);
                    if (frame.Type == Http2FrameType.Data)
                    {
                        received += frame.Payload.Length;
                    }
                }

                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    headers.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal(2 * ChunkSize, received);
    }

    /// <summary>
    /// RFC 9110 section 10.1.1: a client that sends <c>Expect: 100-continue</c> sends the
    /// header block and then waits for an interim response before the body. The peer
    /// cannot send one for a header block it never received, so the block leaves whatever
    /// <see cref="TlsHttp2Options.FlushAfterHeaderBlock"/> declares.
    /// </summary>
    [Fact]
    public async Task HeaderBlock_LeavesWithoutItsFlushWhenTheRequestExpectsAnInterimResponse()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.FlushAfterHeaderBlock = false;
        options.Http2.FlushAfterEveryDataFrame = false;

        // Longer than the harness's own deadline on purpose: a withheld header block must
        // fail this test as the deadlock it is, not as a wait that quietly expires and
        // releases the body anyway.
        options.Expect100ContinueTimeout = TimeSpan.FromSeconds(45);

        var body = new byte[BodyOctets];
        Random.Shared.NextBytes(body);
        var interimSent = false;
        var received = 0;

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var content = new StreamContent(new MemoryStream(body));
                content.Headers.ContentLength = body.Length;
                using var message = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = content,
                };
                message.AddHeader("content-length", "-1");
                message.AddHeader("Expect", "100-continue");
                await using var responseBody = new MemoryStream();
                return await session.SendStreamingAsync(
                    message,
                    responseBody,
                    new TlsStreamingOptions { BufferSize = ChunkSize },
                    cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);

                // Blocks forever unless the header block left without its declared flush.
                var headers = await server.ReadUntilAsync(
                    Http2FrameType.Headers,
                    cancellationToken);

                // ":status: 100" — the static-table name index 8 with a literal value.
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders,
                    headers.StreamId,
                    [0x08, 0x03, 0x31, 0x30, 0x30],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
                interimSent = true;

                while (received < body.Length)
                {
                    var frame = await server.ReadFrameAsync(cancellationToken);
                    if (frame.Type == Http2FrameType.Data)
                    {
                        received += frame.Payload.Length;
                    }
                }

                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    headers.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.True(interimSent);
        Assert.Equal(body.Length, received);
        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
    }

    /// <summary>
    /// RFC 9113 section 6.9.1: a peer credits only the octets it has received, so a client
    /// that waits for credit while holding those octets in a batch waits forever. Both
    /// flush scalars are off here and the body outruns the 65535-octet initial send window
    /// (RFC 9113 section 6.9.2), so the wait happens with a batch full of DATA.
    /// </summary>
    [Fact]
    public async Task Upload_CompletesWhenTheSendWindowRunsOutWithBothFlushesOff()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.FlushAfterHeaderBlock = false;
        options.Http2.FlushAfterEveryDataFrame = false;

        const int InitialSendWindow = 65_535;
        var body = new byte[InitialSendWindow + ChunkSize];
        Random.Shared.NextBytes(body);
        var received = 0;

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, cancellationToken) =>
                PostAsync(session, url, body, body.Length, cancellationToken),
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);

                // Both the header block and every DATA frame are withheld by declaration,
                // so nothing arrives at all unless the credit wait closes the batch.
                var headers = await server.ReadUntilAsync(
                    Http2FrameType.Headers,
                    cancellationToken);
                while (received < InitialSendWindow)
                {
                    var frame = await server.ReadFrameAsync(cancellationToken);
                    if (frame.Type == Http2FrameType.Data)
                    {
                        received += frame.Payload.Length;
                    }
                }

                // The stream and the connection are credited separately (RFC 9113
                // section 6.9); the client needs both to send the remainder.
                var increment = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(increment, ChunkSize);
                await server.WriteFrameAsync(
                    Http2FrameType.WindowUpdate,
                    0,
                    headers.StreamId,
                    increment,
                    cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.WindowUpdate,
                    0,
                    0,
                    increment,
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                while (received < body.Length)
                {
                    var frame = await server.ReadFrameAsync(cancellationToken);
                    if (frame.Type == Http2FrameType.Data)
                    {
                        received += frame.Payload.Length;
                    }
                }

                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    headers.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(body.Length, received);
        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
    }

    [Fact]
    public async Task FlushAfterHeaderBlock_False_LetsTheHeaderBlockRideTheFirstDataRecord()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };

        // The default, and today's behaviour: the header block leaves in a record of its own.
        Assert.True(options.Http2.FlushAfterHeaderBlock);
        options.Http2.FlushAfterHeaderBlock = false;

        // One preface frame that declares no boundary, so the preface is exactly 24 magic
        // plus a 9-octet empty SETTINGS and the read after it starts at the header block.
        options.Http2.Preface = [new TlsHttp2SettingsFrame()];

        var body = new byte[BodyOctets];
        Random.Shared.NextBytes(body);
        var afterPreface = 0;

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, cancellationToken) =>
                PostAsync(session, url, body, cancellationToken),
            async (server, cancellationToken) =>
            {
                Assert.Equal(33, await server.ReadOnceAsync(33, cancellationToken));

                // FlushAfterEveryDataFrame is left at true, so this record ends at the
                // first DATA frame — and it must have carried the header block too.
                afterPreface = await server.ReadOnceAsync(
                    BodyFrameOctets,
                    cancellationToken);
                var total = afterPreface;
                while (total < BodyFrameOctets)
                {
                    total += await server.ReadOnceAsync(BodyFrameOctets, cancellationToken);
                }

                // The first client stream, since InitialStreamId defaults to 1 and this is
                // the connection's only request.
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    1,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);

        // One DATA frame plus a header block, which cannot itself reach a DATA frame's size.
        Assert.InRange(afterPreface, 9 + ChunkSize + 1, 9 + ChunkSize + ChunkSize);
    }

    private static Task<TlsResponse> PostAsync(
        TlsSession session,
        string url,
        byte[] body,
        CancellationToken cancellationToken) =>
        PostAsync(session, url, body, ChunkSize, cancellationToken);

    private static async Task<TlsResponse> PostAsync(
        TlsSession session,
        string url,
        byte[] body,
        int bufferSize,
        CancellationToken cancellationToken)
    {
        using var content = new StreamContent(new MemoryStream(body));
        using var message = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        message.AddHeader("content-length", "-1");
        await using var responseBody = new MemoryStream();
        return await session.SendStreamingAsync(
            message,
            responseBody,
            new TlsStreamingOptions { BufferSize = bufferSize },
            cancellationToken);
    }

    /// <summary>
    /// POSTs <see cref="LargeReadOctets"/> octets that one read of the content stream
    /// delivers whole, and returns the length of every record the body arrived in.
    /// </summary>
    private static async Task<IReadOnlyList<int>> PostOneLargeReadAsync(TlsSessionOptions options)
    {
        var body = new byte[LargeReadOctets];
        Random.Shared.NextBytes(body);

        // Three DATA frames of 16384, the last of which carries END_STREAM.
        const int Expected = 3 * (9 + MaximumFrameSize);
        var records = new List<int>();

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, cancellationToken) =>
                PostAsync(session, url, body, LargeReadOctets, cancellationToken),
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);
                var headers = await server.ReadUntilAsync(
                    Http2FrameType.Headers,
                    cancellationToken);

                var total = 0;
                while (total < Expected)
                {
                    var delivered = await server.ReadOnceAsync(Expected, cancellationToken);
                    records.Add(delivered);
                    total += delivered;
                }
                Assert.Equal(Expected, total);

                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    headers.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
        return records;
    }

    /// <summary>
    /// POSTs <see cref="BodyOctets"/> octets as a streaming body read <see cref="ChunkSize"/>
    /// at a time — one DATA frame per read — and returns the octets the first read after the
    /// header block delivered.
    /// </summary>
    /// <remarks>
    /// The server never sends its own SETTINGS: acknowledging one would put a client-written
    /// frame of its own into the body's batch at a moment the read loop, not the test,
    /// chooses. The client does not wait for it.
    /// </remarks>
    private static async Task<int> PostThreeDataFramesAsync(TlsSessionOptions options)
    {
        var body = new byte[BodyOctets];
        Random.Shared.NextBytes(body);
        var first = 0;

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, cancellationToken) =>
                PostAsync(session, url, body, cancellationToken),
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);
                var headers = await server.ReadUntilAsync(
                    Http2FrameType.Headers,
                    cancellationToken);

                // Frame-aligned reading stops here: ReadOnceAsync returns whatever one
                // record carried, so the count is the writer's boundary, not the reader's.
                var total = 0;
                while (total < BodyFrameOctets)
                {
                    var delivered = await server.ReadOnceAsync(
                        BodyFrameOctets,
                        cancellationToken);
                    if (first == 0)
                    {
                        first = delivered;
                    }
                    total += delivered;
                }
                Assert.Equal(BodyFrameOctets, total);

                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    headers.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
        return first;
    }

    /// <summary>A transport whose first write fails and whose later writes succeed.</summary>
    private sealed class FailFirstWriteStream : Stream
    {
        private readonly MemoryStream _written = new();
        private bool _failed;

        public byte[] WrittenBytes => _written.ToArray();

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (!_failed)
            {
                _failed = true;
                throw new OperationCanceledException();
            }
            _written.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override void Write(byte[] buffer, int offset, int count) =>
            WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Flush()
        {
        }
    }

    /// <summary>
    /// A duplex producer: two chunks, the second of which exists only once
    /// <paramref name="acknowledged"/> completes.
    /// </summary>
    private sealed class AcknowledgedChunkStream(int chunkSize, Task acknowledged) : Stream
    {
        private int _reads;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
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
            if (_reads >= 2)
            {
                return 0;
            }
            if (_reads == 1)
            {
                await acknowledged.WaitAsync(cancellationToken);
            }
            _reads++;
            var count = Math.Min(chunkSize, buffer.Length);
            buffer.Span[..count].Fill(0x5a);
            return count;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Flush()
        {
        }
    }
}
