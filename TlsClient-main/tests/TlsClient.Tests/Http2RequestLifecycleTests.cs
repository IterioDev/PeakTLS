using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls.Certificates;
using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

/// <summary>
/// The per-request wire image: the frame script either side of the header block, where the
/// "this request's stream" sentinel is resolved, and which session values a request may
/// override for itself.
/// </summary>
public sealed class Http2RequestLifecycleTests
{
    /// <summary>
    /// <see cref="Http2WireCapture.MinimalExchange"/> stops reading at END_HEADERS, and
    /// <see cref="Http2WireServer.ClientFrames"/> only holds what the script actually read, so
    /// a test asserting on frames written after the header block has to ask for them. They are
    /// already on the wire: an after-frame shares the request's write batch, which a GET flushes
    /// before it waits for the response.
    /// </summary>
    private static Http2ServerScript ExchangeReadingFramesAfterHeaders(int afterFrames) =>
        async (server, cancellationToken) =>
        {
            await server.ReadPrefaceAsync(cancellationToken);
            await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
            await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
            await server.FlushAsync(cancellationToken);

            var headers = await server.ReadUntilAsync(Http2FrameType.Headers, cancellationToken);
            var frame = headers;
            while ((frame.Flags & Http2FrameFlags.EndHeaders) == 0)
            {
                frame = await server.ReadFrameAsync(cancellationToken);
            }
            for (var index = 0; index < afterFrames; index++)
            {
                await server.ReadFrameAsync(cancellationToken);
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

    [Fact]
    public async Task DeclaredFrames_SurroundTheHeaderBlockAndResolveTheStreamSentinel()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                var requestOptions = TlsRequestOptions.For(request);
                requestOptions.FramesBeforeHeaders =
                [
                    new TlsHttp2PingFrame { Payload = [1, 2, 3, 4, 5, 6, 7, 8] },
                ];
                requestOptions.FramesAfterHeaders =
                [
                    new TlsHttp2StreamPriorityFrame
                    {
                        Priority = new TlsHttp2Priority { Weight = 220 },
                    },
                ];
                return await session.SendAsync(request, cancellationToken);
            },
            ExchangeReadingFramesAfterHeaders(1));

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var scripted = result.ClientFrames
            .Where(frame => frame.Type
                is Http2FrameType.Ping or Http2FrameType.Headers or Http2FrameType.Priority)
            .ToArray();
        Assert.Equal(
            new[] { Http2FrameType.Ping, Http2FrameType.Headers, Http2FrameType.Priority },
            scripted.Select(frame => frame.Type).ToArray());

        var streamId = scripted[1].StreamId;
        Assert.Equal(1, streamId);
        // The PING keeps the 0 it declared — RFC 9113 section 6.7 associates it with no stream
        // — while the PRIORITY's placeholder becomes the request's own identifier. Weight is
        // emitted as the RFC 7540 section 5.3.2 wire value, one less than the declared 220.
        Http2WireAssert.EqualFrames(
            [
                new CapturedFrame(Http2FrameType.Ping, 0, 0, [1, 2, 3, 4, 5, 6, 7, 8]),
                new CapturedFrame(Http2FrameType.Priority, 0, streamId, [0, 0, 0, 0, 0xdb]),
            ],
            [scripted[0], scripted[2]],
            "the declared request frames");
    }

    /// <summary>
    /// RFC 9218 section 7.1 pins a PRIORITY_UPDATE frame's own header stream identifier to 0
    /// and names its target in the Prioritized Stream ID field, so the sentinel resolves into
    /// the first four payload octets rather than into the frame header.
    /// </summary>
    [Fact]
    public async Task DeclaredPriorityUpdate_ResolvesTheStreamInsideItsPayload()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.PriorityUpdate = null;

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                TlsRequestOptions.For(request).FramesBeforeHeaders =
                [
                    new TlsHttp2PriorityUpdateFrame { Value = "u=1, i" },
                ];
                return await session.SendAsync(request, cancellationToken);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var update = Assert.Single(
            result.ClientFrames,
            frame => frame.Type == Http2FrameType.PriorityUpdate);
        var headers = result.ClientFrames.First(frame => frame.Type == Http2FrameType.Headers);
        Assert.Equal(0, update.StreamId);
        Assert.Equal(headers.StreamId, BinaryPrimitives.ReadInt32BigEndian(update.Payload));
        Assert.NotEqual(0, headers.StreamId);
        Assert.Equal("u=1, i", Encoding.ASCII.GetString(update.Payload.AsSpan(4)));
    }

    /// <summary>
    /// The session-level PriorityUpdate is a fallback: a request declaring its own owns the
    /// placement, and exactly one frame reaches the wire. RFC 9218 section 7 makes each
    /// PRIORITY_UPDATE "a complete set of all priority parameters", so emitting both would
    /// leave the session's silently overriding the request's.
    /// </summary>
    /// <remarks>
    /// The body is what makes the count falsifiable. A GET writes nothing after its header
    /// block, so a superfluous session PRIORITY_UPDATE would be a frame the script waits 15
    /// seconds for rather than one it reads. A POST always ends with DATA, so reading on to
    /// the DATA frame drains everything the client wrote in between — including the surplus,
    /// which then shows up as a second PRIORITY_UPDATE in
    /// <see cref="Http2WireResult.ClientFrames"/>. Reading a fixed number of frames instead
    /// would race the SETTINGS acknowledgement, which the read loop writes on its own clock.
    /// </remarks>
    [Fact]
    public async Task DeclaredPriorityUpdate_ReplacesTheSessionOneRatherThanJoiningIt()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.PriorityUpdate = "u=3";

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent("body"),
                };
                TlsRequestOptions.For(request).FramesBeforeHeaders =
                [
                    new TlsHttp2PriorityUpdateFrame { Value = "u=0, i" },
                ];
                return await session.SendAsync(request, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);
                await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Settings,
                    0,
                    0,
                    [],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                var headers = await server.ReadUntilAsync(
                    Http2FrameType.Headers,
                    cancellationToken);
                var frame = headers;
                while ((frame.Flags & Http2FrameFlags.EndHeaders) == 0)
                {
                    frame = await server.ReadFrameAsync(cancellationToken);
                }
                await server.ReadUntilAsync(Http2FrameType.Data, cancellationToken);

                // 0x88 is the static-table entry for ":status: 200".
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    headers.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var frames = result.ClientFrames.ToList();
        var update = Assert.Single(
            frames,
            frame => frame.Type == Http2FrameType.PriorityUpdate);
        Assert.Equal("u=0, i", Encoding.ASCII.GetString(update.Payload.AsSpan(4)));
        Assert.True(
            frames.FindIndex(frame => frame.Type == Http2FrameType.PriorityUpdate) <
                frames.FindIndex(frame => frame.Type == Http2FrameType.Headers),
            "the declared PRIORITY_UPDATE did not precede the header block");
    }

    /// <summary>
    /// One frozen frame list, two streams. The frozen configuration is shared by every send of
    /// a request — <see cref="BufferedRequest.Redirect"/> is a record copy, so the redirected
    /// request points at the very same payload array — and the Prioritized Stream ID is
    /// resolved into it. Each send must therefore name its own stream, which is why the writer
    /// copies the payload before substituting rather than editing it where it lies.
    /// </summary>
    [Fact]
    public async Task DeclaredPriorityUpdate_NamesEachStreamItIsSentOn()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.PriorityUpdate = null;

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                TlsRequestOptions.For(request).FramesBeforeHeaders =
                [
                    new TlsHttp2PriorityUpdateFrame { Value = "u=2" },
                ];
                return await session.SendAsync(request, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);
                await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Settings,
                    0,
                    0,
                    [],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                var first = await ReadHeaderBlockAsync(server, cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    first.StreamId,
                    RedirectHeaderBlock("/redirected"),
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                var second = await ReadHeaderBlockAsync(server, cancellationToken);
                // 0x88 is the static-table entry for ":status: 200".
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    second.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var blocks = result.ClientFrames
            .Where(frame => frame.Type == Http2FrameType.Headers)
            .ToList();
        var updates = result.ClientFrames
            .Where(frame => frame.Type == Http2FrameType.PriorityUpdate)
            .ToList();
        Assert.Equal(2, blocks.Count);
        Assert.Equal(2, updates.Count);
        Assert.NotEqual(blocks[0].StreamId, blocks[1].StreamId);
        Assert.Equal(
            blocks[0].StreamId,
            BinaryPrimitives.ReadInt32BigEndian(updates[0].Payload));
        Assert.Equal(
            blocks[1].StreamId,
            BinaryPrimitives.ReadInt32BigEndian(updates[1].Payload));
    }

    /// <summary>
    /// A raw type-0x10 frame does not suppress the session-level
    /// <see cref="TlsHttp2Options.PriorityUpdate"/>, unlike a
    /// <see cref="TlsHttp2PriorityUpdateFrame"/>. Its stream identifier and its Prioritized
    /// Stream ID are both written verbatim, so it prioritizes whatever stream it names rather
    /// than this one, and suppressing the session frame would leave this request unprioritized.
    /// Two PRIORITY_UPDATE frames therefore reach the wire, naming two different streams.
    /// </summary>
    /// <remarks>
    /// The body is what makes the count falsifiable — see
    /// <see cref="DeclaredPriorityUpdate_ReplacesTheSessionOneRatherThanJoiningIt"/>: a POST
    /// always ends in DATA, so reading on to it drains whatever the client wrote in between
    /// without racing the SETTINGS acknowledgement.
    /// </remarks>
    [Fact]
    public async Task RawPriorityUpdateFrame_DoesNotSuppressTheSessionPriorityUpdate()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.PriorityUpdate = "u=3";

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent("body"),
                };
                TlsRequestOptions.For(request).FramesBeforeHeaders =
                [
                    new TlsHttp2RequestRawFrame
                    {
                        Type = 0x10,
                        StreamId = 0,
                        // Prioritized Stream ID 7 then the Priority Field Value, verbatim: a
                        // raw frame names its target itself (RFC 9218 section 7.1, Figure 1).
                        Payload = [0, 0, 0, 7, .. "u=1"u8],
                    },
                ];
                return await session.SendAsync(request, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);
                await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Settings,
                    0,
                    0,
                    [],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                var headers = await ReadHeaderBlockAsync(server, cancellationToken);
                await server.ReadUntilAsync(Http2FrameType.Data, cancellationToken);

                // 0x88 is the static-table entry for ":status: 200".
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    headers.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var updates = result.ClientFrames
            .Where(frame => frame.Type == Http2FrameType.PriorityUpdate)
            .ToList();
        var headerBlock = result.ClientFrames.First(
            frame => frame.Type == Http2FrameType.Headers);
        Assert.Equal(2, updates.Count);
        Assert.Equal(7, BinaryPrimitives.ReadInt32BigEndian(updates[0].Payload));
        Assert.Equal("u=1", Encoding.ASCII.GetString(updates[0].Payload.AsSpan(4)));
        Assert.Equal(
            headerBlock.StreamId,
            BinaryPrimitives.ReadInt32BigEndian(updates[1].Payload));
        Assert.Equal("u=3", Encoding.ASCII.GetString(updates[1].Payload.AsSpan(4)));
    }

    /// <summary>Reads a complete header block and returns its HEADERS frame.</summary>
    private static async Task<CapturedFrame> ReadHeaderBlockAsync(
        Http2WireServer server,
        CancellationToken cancellationToken)
    {
        var headers = await server.ReadUntilAsync(Http2FrameType.Headers, cancellationToken);
        var frame = headers;
        while ((frame.Flags & Http2FrameFlags.EndHeaders) == 0)
        {
            frame = await server.ReadFrameAsync(cancellationToken);
        }
        return headers;
    }

    /// <summary>
    /// A 302 response block. Both fields are literals without indexing and with a new name
    /// (RFC 7541 section 6.2.2), which leaves the encoder's dynamic table alone so the block
    /// can be written without tracking the connection's HPACK state.
    /// </summary>
    private static byte[] RedirectHeaderBlock(string location)
    {
        var block = new List<byte>();
        AppendLiteral(block, ":status", "302");
        AppendLiteral(block, "location", location);
        return [.. block];

        static void AppendLiteral(List<byte> block, string name, string value)
        {
            block.Add(0x00);
            block.Add((byte)name.Length);
            block.AddRange(Encoding.ASCII.GetBytes(name));
            block.Add((byte)value.Length);
            block.AddRange(Encoding.ASCII.GetBytes(value));
        }
    }

    /// <summary>
    /// RFC 9113 section 4.3 requires a field block to be a contiguous run of frames with no
    /// interleaving of any other type or from any other stream; sections 6.2 and 6.10 make a
    /// violation a connection error. An after-frame therefore follows the final CONTINUATION,
    /// never the HEADERS frame.
    /// </summary>
    [Fact]
    public async Task AfterFrames_FollowTheFinalContinuationRatherThanTheHeadersFrame()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                // Larger than the 16384-octet default maximum frame size however it compresses,
                // so the block cannot fit in one frame.
                request.Headers.TryAddWithoutValidation("x-filler", new string('a', 60_000));
                TlsRequestOptions.For(request).FramesAfterHeaders =
                [
                    new TlsHttp2StreamPriorityFrame
                    {
                        Priority = new TlsHttp2Priority { Weight = 220 },
                    },
                ];
                return await session.SendAsync(request, cancellationToken);
            },
            ExchangeReadingFramesAfterHeaders(1));

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var frames = result.ClientFrames;
        var start = 0;
        while (frames[start].Type != Http2FrameType.Headers)
        {
            start++;
        }
        var end = start;
        while ((frames[end].Flags & Http2FrameFlags.EndHeaders) == 0)
        {
            end++;
        }

        Assert.True(end > start, "the header block did not need a CONTINUATION frame");
        for (var index = start + 1; index <= end; index++)
        {
            Assert.Equal(Http2FrameType.Continuation, frames[index].Type);
            Assert.Equal(frames[start].StreamId, frames[index].StreamId);
        }
        Assert.Equal(Http2FrameType.Priority, frames[end + 1].Type);
        Assert.Equal(frames[start].StreamId, frames[end + 1].StreamId);
    }

    /// <summary>
    /// RFC 7540 section 5.3.1 — the rule RFC 9113 dropped along with the dependency tree, while
    /// keeping the wire fields. The stream identifier only exists at send time, so this is the
    /// only place the comparison can be made.
    /// </summary>
    [Fact]
    public async Task DeclaredPriority_RejectsAStreamThatDependsOnItself()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };

        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => Http2WireCapture.RunAsync(
                options,
                async (session, url, cancellationToken) =>
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, url);
                    var requestOptions = TlsRequestOptions.For(request);
                    // A rejected script is not a transport failure; without this the session
                    // retries onto a connection the single-accept harness cannot provide.
                    requestOptions.EnableRetries = false;
                    requestOptions.FramesAfterHeaders =
                    [
                        new TlsHttp2StreamPriorityFrame
                        {
                            // The identifier this session allocates to its first stream.
                            Priority = new TlsHttp2Priority { StreamDependency = 1 },
                        },
                    ];
                    return await session.SendAsync(request, cancellationToken);
                },
                // The request never reaches HEADERS, so the script must not wait for one.
                async (server, cancellationToken) =>
                {
                    await server.ReadPrefaceAsync(cancellationToken);
                    await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
                    await server.WriteFrameAsync(
                        Http2FrameType.Settings,
                        0,
                        0,
                        [],
                        cancellationToken);
                    await server.FlushAsync(cancellationToken);
                }));

        Assert.Equal("An HTTP/2 stream cannot depend on itself.", exception.Message);
    }

    /// <summary>
    /// The override is resolved per request at send time, not per connection, so two requests
    /// sharing one connection emit two different pseudo-header sequences. Neither matches the
    /// session order, which proves the fallback is not what produced either result.
    /// </summary>
    [Fact]
    public async Task PseudoHeaderOrder_IsResolvedPerRequestOnOneConnection()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.PseudoHeaderOrder = [":method", ":authority", ":scheme", ":path"];
        string[] first = [":method", ":path", ":authority", ":scheme"];
        string[] second = [":scheme", ":method", ":path", ":authority"];

        var blocks = new List<byte[]>();
        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                _ = await SendWithOrderAsync(session, url, first, cancellationToken);
                return await SendWithOrderAsync(session, url, second, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);
                await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Settings,
                    0,
                    0,
                    [],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                for (var request = 0; request < 2; request++)
                {
                    var headers = await server.ReadUntilAsync(
                        Http2FrameType.Headers,
                        cancellationToken);
                    var payload = headers.Payload.ToList();
                    var frame = headers;
                    while ((frame.Flags & Http2FrameFlags.EndHeaders) == 0)
                    {
                        frame = await server.ReadFrameAsync(cancellationToken);
                        payload.AddRange(frame.Payload);
                    }
                    blocks.Add([.. payload]);

                    // 0x88 is the static-table entry for ":status: 200".
                    await server.WriteFrameAsync(
                        Http2FrameType.Headers,
                        Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                        headers.StreamId,
                        [0x88],
                        cancellationToken);
                    await server.FlushAsync(cancellationToken);
                }
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal(2, blocks.Count);
        // One decoder for both blocks: the encoder's dynamic table is per connection, so the
        // second block indexes entries the first inserted and cannot be decoded on its own.
        var decoder = new HpackDecoder(4096);
        Assert.Equal(first, PseudoHeaderNames(decoder.Decode(blocks[0], 16 * 1024)));
        Assert.Equal(second, PseudoHeaderNames(decoder.Decode(blocks[1], 16 * 1024)));
    }

    /// <summary>
    /// The frame script is a property of the request, not of the connection. Two requests
    /// multiplexed over one connection each emit their own list and neither inherits the
    /// other's: the second request declares a different before-list and no after-list at all,
    /// so a script cached at connection level would show up as the first request's PING payload
    /// repeated, or as a second PRIORITY frame nobody asked for.
    /// </summary>
    /// <remarks>
    /// Both requests carry a body so the server can read to a DATA frame rather than count
    /// frames after the header block: the after-frames ride the same write batch and are
    /// drained on the way, while the SETTINGS acknowledgement the read loop writes on its own
    /// clock is drained with them instead of racing a fixed count.
    /// </remarks>
    [Fact]
    public async Task FrameLists_AreResolvedPerRequestOnOneConnection()
    {
        byte[] firstPing = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] secondPing = [8, 7, 6, 5, 4, 3, 2, 1];

        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var first = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent("first"),
                };
                var firstOptions = TlsRequestOptions.For(first);
                firstOptions.FramesBeforeHeaders =
                [
                    new TlsHttp2PingFrame { Payload = firstPing },
                ];
                firstOptions.FramesAfterHeaders =
                [
                    new TlsHttp2StreamPriorityFrame
                    {
                        Priority = new TlsHttp2Priority { Weight = 220 },
                    },
                ];
                _ = await session.SendAsync(first, cancellationToken);

                using var second = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent("second"),
                };
                // A different before-list and, deliberately, no after-list at all.
                TlsRequestOptions.For(second).FramesBeforeHeaders =
                [
                    new TlsHttp2PingFrame { Payload = secondPing },
                ];
                return await session.SendAsync(second, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);
                await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Settings,
                    0,
                    0,
                    [],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                for (var request = 0; request < 2; request++)
                {
                    var data = await server.ReadUntilAsync(
                        Http2FrameType.Data,
                        cancellationToken);
                    // 0x88 is the static-table entry for ":status: 200".
                    await server.WriteFrameAsync(
                        Http2FrameType.Headers,
                        Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                        data.StreamId,
                        [0x88],
                        cancellationToken);
                    await server.FlushAsync(cancellationToken);
                }
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var frames = result.ClientFrames.ToList();
        var pings = frames.FindAll(frame => frame.Type == Http2FrameType.Ping);
        var blocks = frames.FindAll(frame => frame.Type == Http2FrameType.Headers);
        var priorities = frames.FindAll(frame => frame.Type == Http2FrameType.Priority);

        // One PING per request, carrying that request's own payload rather than the first
        // request's repeated.
        Assert.Equal(2, pings.Count);
        Assert.Equal(2, blocks.Count);
        Assert.NotEqual(blocks[0].StreamId, blocks[1].StreamId);
        Http2WireAssert.EqualFrames(
            [
                new CapturedFrame(Http2FrameType.Ping, 0, 0, firstPing),
                new CapturedFrame(Http2FrameType.Ping, 0, 0, secondPing),
            ],
            pings,
            "the per-request PING frames");

        // The after-list belongs to the first request alone. Weight is emitted as the RFC 7540
        // section 5.3.2 wire value, one less than the declared 220.
        var priority = Assert.Single(priorities);
        Http2WireAssert.EqualFrames(
            [new CapturedFrame(Http2FrameType.Priority, 0, blocks[0].StreamId, [0, 0, 0, 0, 0xdb])],
            [priority],
            "the first request's after-frame");

        // And each list sits around its own header block: PING, block, PRIORITY, then the
        // second request's PING and block with nothing scripted after it.
        Assert.True(
            frames.IndexOf(pings[0]) < frames.IndexOf(blocks[0]) &&
                frames.IndexOf(blocks[0]) < frames.IndexOf(priority) &&
                frames.IndexOf(priority) < frames.IndexOf(pings[1]) &&
                frames.IndexOf(pings[1]) < frames.IndexOf(blocks[1]),
            "the scripted frames did not surround their own request's header block: " +
            string.Join(", ", frames.Select(frame => frame.Type)));
    }

    private static async Task<TlsResponse> SendWithOrderAsync(
        TlsSession session,
        string url,
        string[] pseudoHeaderOrder,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        TlsRequestOptions.For(request).PseudoHeaderOrder = pseudoHeaderOrder;
        return await session.SendAsync(request, cancellationToken);
    }

    private static string[] PseudoHeaderNames(IReadOnlyList<HpackHeader> headers) =>
        headers.Select(header => header.Name)
            .TakeWhile(name => name.StartsWith(':'))
            .ToArray();

    /// <summary>
    /// The remaining three overrides on one HTTP/2 request. Every session value here is
    /// different from the request's, so none of the assertions can pass on the fallback.
    /// </summary>
    [Fact]
    public async Task HeaderOrderPriorityAndPriorityUpdate_AreResolvedFromTheRequest()
    {
        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            HeaderOrder = ["x-beta", "x-alpha"],
        };
        options.Http2.HeaderPriority = new TlsHttp2Priority { Weight = 20 };
        options.Http2.PriorityUpdate = "u=5";

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent("body"),
                };
                request.Headers.TryAddWithoutValidation("x-alpha", "1");
                request.Headers.TryAddWithoutValidation("x-beta", "2");
                var requestOptions = TlsRequestOptions.For(request);
                requestOptions.HeaderOrder = ["x-alpha", "x-beta"];
                requestOptions.HeaderPriority = new TlsHttp2Priority { Weight = 200 };
                requestOptions.PriorityUpdate = "u=0, i";
                return await session.SendAsync(request, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                await server.ReadPrefaceAsync(cancellationToken);
                await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Settings,
                    0,
                    0,
                    [],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                var headers = await server.ReadUntilAsync(
                    Http2FrameType.Headers,
                    cancellationToken);
                // The PRIORITY_UPDATE follows the block; DATA follows that, and DATA is
                // guaranteed to arrive, so reading on to it drains both without a fixed count.
                await server.ReadUntilAsync(Http2FrameType.Data, cancellationToken);

                // 0x88 is the static-table entry for ":status: 200".
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    headers.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var block = Assert.Single(
            result.ClientFrames,
            frame => frame.Type == Http2FrameType.Headers);
        Assert.Equal(
            Http2FrameFlags.EndHeaders,
            block.Flags & Http2FrameFlags.EndHeaders);

        // RFC 9113 section 6.2: the PRIORITY flag prefixes the field block with the five-octet
        // priority payload. Weight is the RFC 7540 section 5.3.2 wire value, one less than the
        // declared 200 — and one less than 20 would be 19, which this is not.
        Assert.Equal(Http2FrameFlags.Priority, block.Flags & Http2FrameFlags.Priority);
        Assert.Equal(199, block.Payload[4]);

        var update = Assert.Single(
            result.ClientFrames,
            frame => frame.Type == Http2FrameType.PriorityUpdate);
        Assert.Equal("u=0, i", Encoding.ASCII.GetString(update.Payload.AsSpan(4)));

        var names = new HpackDecoder(4096)
            .Decode(block.Payload.AsSpan(5).ToArray(), 16 * 1024)
            .Select(header => header.Name)
            .ToList();
        Assert.True(
            names.IndexOf("x-alpha") < names.IndexOf("x-beta"),
            "the request HeaderOrder was not applied to the HTTP/2 field block");
    }

    /// <summary>
    /// HeaderOrder is the one per-request override HTTP/1.1 honours, because
    /// <c>Http11RequestWriter.Order</c> is already shared with the HTTP/2 header builder and
    /// splitting the semantics by protocol would be surprising. The session order here is the
    /// reverse of the request's, so the assertion cannot pass on the fallback.
    /// </summary>
    [Fact]
    public async Task HeaderOrder_IsHonouredPerRequestOnHttp11()
    {
        var requestHead = await SendOverHttp11Async(
            options => options.HeaderOrder = ["x-alpha", "x-beta"]);

        Assert.True(
            requestHead.IndexOf("x-alpha", StringComparison.OrdinalIgnoreCase) <
                requestHead.IndexOf("x-beta", StringComparison.OrdinalIgnoreCase),
            $"the request order was not applied:{Environment.NewLine}{requestHead}");
    }

    /// <summary>
    /// Every override other than HeaderOrder is HTTP/2 only and is ignored on an HTTP/1.1
    /// connection rather than throwing, so a persona survives a version fallback. The session
    /// HeaderOrder still applies, which is what proves the request was written normally rather
    /// than merely not crashing.
    /// </summary>
    [Fact]
    public async Task Http2OnlyOverrides_AreIgnoredRatherThanRejectedOnHttp11()
    {
        var requestHead = await SendOverHttp11Async(options =>
        {
            options.PseudoHeaderOrder = [":path", ":method", ":authority", ":scheme"];
            options.HeaderPriority = new TlsHttp2Priority { Weight = 200 };
            options.PriorityUpdate = "u=0, i";
        });

        Assert.StartsWith("GET /order HTTP/1.1", requestHead, StringComparison.Ordinal);
        // The session order, untouched by the ignored HTTP/2 overrides.
        Assert.True(
            requestHead.IndexOf("x-beta", StringComparison.OrdinalIgnoreCase) <
                requestHead.IndexOf("x-alpha", StringComparison.OrdinalIgnoreCase),
            $"the session order was not applied:{Environment.NewLine}{requestHead}");
    }

    /// <summary>
    /// Drives one request over an HTTP/1.1-only loopback connection and returns the request
    /// head the client wrote. The session declares the reverse of the per-request order, so
    /// whichever one the writer used is visible in the output.
    /// </summary>
    private static async Task<string> SendOverHttp11Async(Action<TlsRequestOptions> configure)
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var serverTask = TlsSessionLoopbackTests.RunSingleResponseServerAsync(
            listener,
            serverCredential,
            timeout.Token);

        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            HttpVersionPolicy = TlsHttpVersionPolicy.Http11Only,
            HeaderOrder = ["x-beta", "x-alpha"],
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        };
        await using var session = new TlsSession(options);

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://127.0.0.1:{port}/order");
        request.Headers.TryAddWithoutValidation("x-alpha", "1");
        request.Headers.TryAddWithoutValidation("x-beta", "2");
        configure(TlsRequestOptions.For(request));

        var response = await session.SendAsync(request, timeout.Token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await serverTask;
    }
}
