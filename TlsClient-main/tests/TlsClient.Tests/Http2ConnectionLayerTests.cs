using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

/// <summary>
/// The regression net for the declarative connection layer. Every assertion here is
/// against bytes the client actually put on the wire, or against traffic the client only
/// accepts if it derived its local receive state from the declared preface.
/// </summary>
public sealed class Http2ConnectionLayerTests
{
    [Fact]
    public async Task Settings_PutUnknownAndDuplicatedIdentifiersOnTheWireInDeclaredOrder()
    {
        var options = CreateOptions(
        [
            new TlsHttp2SettingsFrame
            {
                Settings =
                [
                    new(0x1, 4_096),
                    new(0xFA5A, 1),
                    new(0x5, 16_384),
                    new(0x5, 32_768),
                ],
            },
        ]);

        var result = await Http2WireCapture.RunAsync(options, Get, MinimalExchange);

        // Six octets per entry, in declaration order: the unknown identifier is carried
        // verbatim and the duplicate is written twice rather than collapsed.
        byte[] expected =
        [
            0x00, 0x01, 0x00, 0x00, 0x10, 0x00,
            0xFA, 0x5A, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x05, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x05, 0x00, 0x00, 0x80, 0x00,
        ];
        var settings = result.ClientFrames.First(frame => frame.Type == Http2FrameType.Settings);
        Assert.Equal(expected, settings.Payload);
    }

    [Fact]
    public async Task Settings_LastValueOfADuplicatedIdentifierGovernsLocalState()
    {
        // A client is bound by what it advertised last. The server sends a DATA frame
        // larger than the first declared MAX_FRAME_SIZE but within the second, so only an
        // encoder that took the last value can accept it.
        var options = CreateOptions(
        [
            new TlsHttp2SettingsFrame
            {
                Settings = [new(0x5, 16_384), new(0x5, 32_768)],
            },
        ]);

        var result = await Http2WireCapture.RunAsync(
            options,
            Get,
            (server, cancellationToken) => RespondWithBodyAsync(server, 20_000, cancellationToken));

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
    }

    [Fact]
    public async Task RawSettingsFrame_FeedsLocalReceiveState()
    {
        // The same bound, declared as an opaque frame rather than a typed one.
        var options = CreateOptions(
        [
            new TlsHttp2RawFrame
            {
                Type = 0x4,
                Payload = [0x00, 0x05, 0x00, 0x00, 0x80, 0x00],
            },
        ]);

        var result = await Http2WireCapture.RunAsync(
            options,
            Get,
            (server, cancellationToken) => RespondWithBodyAsync(server, 20_000, cancellationToken));

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
    }

    [Fact]
    public async Task RawWindowUpdateFrame_FeedsTheConnectionReceiveWindow()
    {
        // Without the increment the connection window is RFC 9113's 65535 default, so a
        // body past it stalls until the client sends a WINDOW_UPDATE of its own. The
        // declared increment is what lets this body arrive in one flight. The stream
        // window and frame size are raised alongside it so the connection window is the
        // only bound left under test.
        var options = CreateOptions(
        [
            new TlsHttp2SettingsFrame
            {
                Settings = [new(0x5, 131_072), new(0x4, 1_048_576)],
            },
            new TlsHttp2RawFrame
            {
                Type = 0x8,
                Payload = [0x00, 0x0F, 0x00, 0x01],
            },
        ]);

        var result = await Http2WireCapture.RunAsync(
            options,
            Get,
            (server, cancellationToken) => RespondWithBodyAsync(server, 100_000, cancellationToken));

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
    }

    [Fact]
    public async Task EmptySettingsList_WritesAZeroLengthSettingsFrame()
    {
        var options = CreateOptions([new TlsHttp2SettingsFrame()]);

        var result = await Http2WireCapture.RunAsync(options, Get, MinimalExchange);

        var settings = result.ClientFrames.First(frame => frame.Type == Http2FrameType.Settings);
        Assert.Empty(settings.Payload);
    }

    [Fact]
    public void Validation_RejectsAPrefaceThatDoesNotBeginWithSettings()
    {
        // RFC 9113 section 3.4: magic, then a SETTINGS frame that may be empty. A server
        // reading anything else answers GOAWAY(PROTOCOL_ERROR), so a preface opening any
        // other way is not a fingerprint a real client has.
        var empty = new TlsHttp2Options { Preface = [] };
        var windowUpdateFirst = new TlsHttp2Options
        {
            Preface =
            [
                new TlsHttp2WindowUpdateFrame { Increment = 1_000 },
                new TlsHttp2SettingsFrame { Settings = [new(0x1, 4_096)] },
            ],
        };

        foreach (var options in new[] { empty, windowUpdateFirst })
        {
            var failure = Assert.ThrowsAny<ArgumentException>(() => options.Snapshot());
            Assert.Contains("must begin with a SETTINGS frame", failure.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Validation_AcceptsARawSettingsFrameAsThePrefacesFirstFrame()
    {
        // The rule is about the type octet on the wire, not the declared C# shape.
        var options = new TlsHttp2Options
        {
            Preface = [new TlsHttp2RawFrame { Type = 0x4, Payload = [] }],
        };

        Assert.Equal(0x4, options.Snapshot().Preface[0].Type);
    }

    [Fact]
    public async Task RawFrame_AppearsAtItsDeclaredPositionInThePreface()
    {
        var options = CreateOptions(
        [
            new TlsHttp2SettingsFrame { Settings = [new(0x1, 4_096)] },
            new TlsHttp2RawFrame { Type = 0x2A, Payload = [0xDE, 0xAD] },
            new TlsHttp2WindowUpdateFrame { Increment = 1_000 },
        ]);

        var result = await Http2WireCapture.RunAsync(options, Get, MinimalExchange);

        Assert.Equal(
            [Http2FrameType.Settings, (Http2FrameType)0x2A, Http2FrameType.WindowUpdate],
            result.ClientFrames.Take(3).Select(frame => frame.Type));
        Assert.Equal([0xDE, 0xAD], result.ClientFrames[1].Payload);
    }

    [Fact]
    public async Task StreamIdentifiers_FollowTheDeclaredSequence()
    {
        var options = CreateOptions([new TlsHttp2SettingsFrame { Settings = [new(0x1, 4_096)] }]);
        options.Http2.InitialStreamId = 5;
        options.Http2.StreamIdStep = 4;

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                _ = await session.GetAsync(url, cancellationToken);
                _ = await session.GetAsync(url, cancellationToken);
                return await session.GetAsync(url, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                _ = await server.ReadPrefaceAsync(cancellationToken);
                for (var request = 0; request < 3; request++)
                {
                    var headers = await ReadHeaderBlockAsync(server, cancellationToken);
                    await RespondAsync(server, headers.StreamId, cancellationToken);
                }
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
        Assert.Equal(
            [5, 9, 13],
            result.ClientFrames
                .Where(frame => frame.Type == Http2FrameType.Headers)
                .Select(frame => frame.StreamId));
    }

    /// <summary>
    /// <c>FlushAfter</c> declares where a write batch ends, and a batch is one underlying
    /// write, so the boundary is a record boundary the peer can see. Only
    /// <c>ReadOnceAsync</c> can show it: the frame-reading path uses ReadExactly and so
    /// reports the reader's shape rather than the writer's.
    /// </summary>
    [Fact]
    public async Task FlushAfter_SplitsThePrefaceIntoTheDeclaredWriteBatches()
    {
        // The magic is 24 octets, the SETTINGS frame 9 + 6, the WINDOW_UPDATE 9 + 4. All
        // 52 arrive together when nothing flushes between them; a flush after SETTINGS
        // cuts the first record at 39.
        Assert.Equal(52, await CapturePrefaceTailReadAsync(flushBetween: false));
        Assert.Equal(39, await CapturePrefaceTailReadAsync(flushBetween: true));
    }

    [Theory]
    [InlineData(TlsHttp2SettingsAckPlacement.AfterNextBatch)]
    [InlineData(TlsHttp2SettingsAckPlacement.BeforeNextBatch)]
    public async Task AckPlacement_NeverLandsInsideAHeaderBlock(
        TlsHttp2SettingsAckPlacement placement)
    {
        // A header list far past the peer's 16384-octet frame size forces CONTINUATION.
        // RFC 9113 sections 6.2 and 6.10 forbid any frame between HEADERS and its
        // CONTINUATION frames, so the acknowledgement must sit outside the run.
        var options = CreateOptions([new TlsHttp2SettingsFrame { Settings = [new(0x1, 4_096)] }]);
        options.Http2.SettingsAckPlacement = placement;

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, cancellationToken) =>
            {
                // Large enough to force CONTINUATION. It rides on the request now, because a
                // session carries no headers of its own.
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.TryAddWithoutValidation("x-large", new string('a', 40_000));
                return session.SendAsync(request, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                _ = await server.ReadPrefaceAsync(cancellationToken);
                await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
                await server.FlushAsync(cancellationToken);

                var headers = await ReadHeaderBlockAsync(server, cancellationToken);
                await RespondAsync(server, headers.StreamId, cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);

        var types = result.ClientFrames.Select(frame => frame.Type).ToList();
        var headerStart = types.IndexOf(Http2FrameType.Headers);
        Assert.True(headerStart >= 0, "the client never sent HEADERS");
        var blockEnd = headerStart;
        while (blockEnd < result.ClientFrames.Count &&
               result.ClientFrames[blockEnd].Type is Http2FrameType.Headers
                   or Http2FrameType.Continuation)
        {
            blockEnd++;
        }
        Assert.True(
            blockEnd - headerStart > 1,
            "the header list was not large enough to require CONTINUATION");
    }

    [Fact]
    public void Validation_RejectsARawFrameUsingAReservedType()
    {
        var options = new TlsHttp2Options
        {
            Preface = [new TlsHttp2RawFrame { Type = 0x1 }],
        };

        var failure = Assert.ThrowsAny<ArgumentException>(() => options.Snapshot());

        Assert.Contains("HEADERS", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(0)]
    public void Validation_RejectsANonOddInitialStreamId(int initialStreamId)
    {
        var options = new TlsHttp2Options { InitialStreamId = initialStreamId };

        var failure = Assert.ThrowsAny<ArgumentException>(() => options.Snapshot());

        Assert.Contains("odd", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(0)]
    public void Validation_RejectsANonEvenStreamIdStep(int streamIdStep)
    {
        var options = new TlsHttp2Options { StreamIdStep = streamIdStep };

        var failure = Assert.ThrowsAny<ArgumentException>(() => options.Snapshot());

        Assert.Contains("even", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validation_RejectsASettingsFrameWithTooManyEntries()
    {
        var settings = Enumerable
            .Range(0, 2_731)
            .Select(index => new TlsHttp2SettingValue((ushort)index, 1))
            .ToArray();
        var options = new TlsHttp2Options
        {
            Preface = [new TlsHttp2SettingsFrame { Settings = settings }],
        };

        var failure = Assert.ThrowsAny<ArgumentException>(() => options.Snapshot());

        Assert.Contains("2730", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// "A server cannot set the SETTINGS_ENABLE_PUSH setting to a value other than 0"
    /// (RFC 9113 section 8.4): 0 is the one value a conformant server may send, and is how
    /// it announces it will never push. The exchange must complete unharmed. Every other
    /// loopback script here sends an empty SETTINGS frame, so this is the only place the
    /// identifier reaches the client at all.
    /// </summary>
    [Fact]
    public async Task Settings_EnablePushOfZeroFromTheServerIsAccepted()
    {
        var result = await Http2WireCapture.RunAsync(
            new TlsSessionOptions { Profile = TlsProfiles.Modern },
            Get,
            async (server, cancellationToken) =>
            {
                _ = await server.ReadPrefaceAsync(cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Settings,
                    0,
                    0,
                    [0x00, 0x02, 0x00, 0x00, 0x00, 0x00],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
                var headers = await ReadHeaderBlockAsync(server, cancellationToken);
                await RespondAsync(server, headers.StreamId, cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
    }

    /// <summary>
    /// Any other value stays an error. 1 is the initial value and the one a server that had
    /// the direction backwards would send; section 8.4 forbids it from a server, and section
    /// 6.5.2 makes anything outside {0, 1} a connection error of type PROTOCOL_ERROR
    /// outright. The setting is written only after the request block has been read, so the
    /// script cannot block on a client that is already tearing the connection down.
    /// </summary>
    [Fact]
    public async Task Settings_EnablePushOfOneFromTheServerFailsTheConnection()
    {
        var failure = await Assert.ThrowsAsync<TlsHttpProtocolException>(() =>
            Http2WireCapture.RunAsync(
                new TlsSessionOptions { Profile = TlsProfiles.Modern },
                Get,
                async (server, cancellationToken) =>
                {
                    _ = await server.ReadPrefaceAsync(cancellationToken);
                    _ = await ReadHeaderBlockAsync(server, cancellationToken);
                    await server.WriteFrameAsync(
                        Http2FrameType.Settings,
                        0,
                        0,
                        [0x00, 0x02, 0x00, 0x00, 0x00, 0x01],
                        cancellationToken);
                    await server.FlushAsync(cancellationToken);
                }));

        Assert.Contains("SETTINGS_ENABLE_PUSH", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// RFC 9110 section 5.5: "A field value does not include leading or trailing whitespace. When
    /// a specific version of HTTP allows such whitespace to appear in a message, a field parsing
    /// implementation MUST exclude such whitespace prior to evaluating the field value." The
    /// HTTP/1.1 reader has always done this, so this is also what makes a caller see the same
    /// string for the same field whichever version answered.
    /// </summary>
    [Fact]
    public async Task ResponseFieldValuePaddedWithWhitespace_ReachesTheCallerTrimmed()
    {
        var result = await Http2WireCapture.RunAsync(
            new TlsSessionOptions { Profile = TlsProfiles.Modern },
            Get,
            async (server, cancellationToken) =>
            {
                _ = await server.ReadPrefaceAsync(cancellationToken);
                var request = await ReadHeaderBlockAsync(server, cancellationToken);

                // 0x88 is ":status: 200"; the rest is one literal field without indexing —
                // 0x00, then a 5-octet name "x-pad", then a 5-octet value " \tv \t".
                byte[] block =
                [
                    0x88,
                    0x00,
                    0x05, (byte)'x', (byte)'-', (byte)'p', (byte)'a', (byte)'d',
                    0x05, (byte)' ', (byte)'\t', (byte)'v', (byte)' ', (byte)'\t',
                ];
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    request.StreamId,
                    block,
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal("v", result.Response.Headers["x-pad"]);
    }

    /// <summary>
    /// A field block that never ends. The octet cap on the accumulated block cannot see
    /// zero-length CONTINUATION frames, so the read loop — the only reader for every stream
    /// on the connection — used to spin on this forever (the CVE-2024-27316 shape; RFC 9113
    /// section 10.5 is what permits closing on it). The explicit deadline is what makes a
    /// regression fail here rather than hang CI.
    /// </summary>
    [Fact]
    public async Task ZeroLengthContinuationFlood_FailsTheConnectionInsteadOfSpinning()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var failure = await Assert.ThrowsAsync<TlsHttpProtocolException>(() =>
            Http2WireCapture.RunAsync(
                new TlsSessionOptions { Profile = TlsProfiles.Modern },
                Get,
                FloodWithZeroLengthContinuationsAsync,
                deadline.Token));

        Assert.Contains("too many frames", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Replies with a HEADERS frame that withholds END_HEADERS, then flushes zero-length
    /// CONTINUATION frames one at a time. Each carries nine octets of header and no
    /// payload, so the accumulated block never grows.
    /// </summary>
    private static async Task FloodWithZeroLengthContinuationsAsync(
        Http2WireServer server,
        CancellationToken cancellationToken)
    {
        _ = await server.ReadPrefaceAsync(cancellationToken);
        var request = await ReadHeaderBlockAsync(server, cancellationToken);

        // 0x88 is the static-table entry for ":status: 200"; END_HEADERS is withheld.
        await server.WriteFrameAsync(
            Http2FrameType.Headers,
            0,
            request.StreamId,
            [0x88],
            cancellationToken);
        try
        {
            // Comfortably past the client's bound, so the run outlives it either way.
            for (var index = 0; index < 512; index++)
            {
                await server.WriteFrameAsync(
                    Http2FrameType.Continuation,
                    0,
                    request.StreamId,
                    [],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            }
        }
        catch (IOException)
        {
            // Expected once the client tears the connection down partway through.
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static Task<TlsResponse> Get(
        TlsSession session,
        string url,
        CancellationToken cancellationToken) => session.GetAsync(url, cancellationToken);

    private static TlsSessionOptions CreateOptions(TlsHttp2PrefaceFrame[] preface)
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.Preface = preface;
        return options;
    }

    /// <summary>
    /// Returns how many octets one read delivers immediately after the connection magic,
    /// which is where the declared flush boundary becomes observable.
    /// </summary>
    private static async Task<int> CapturePrefaceTailReadAsync(bool flushBetween)
    {
        var options = CreateOptions(
        [
            new TlsHttp2SettingsFrame
            {
                Settings = [new(0x1, 4_096)],
                FlushAfter = flushBetween,
            },
            new TlsHttp2WindowUpdateFrame { Increment = 1_000 },
        ]);

        var delivered = 0;
        var result = await Http2WireCapture.RunAsync(
            options,
            Get,
            async (server, cancellationToken) =>
            {
                // One read across the whole preface: 24 octets of magic, a 15-octet
                // SETTINGS frame, a 13-octet WINDOW_UPDATE. Both outcomes end on a frame
                // boundary, so the frame reader below stays aligned either way. The
                // WINDOW_UPDATE is read there when the declared flush left it behind.
                delivered = await server.ReadOnceAsync(52, cancellationToken);

                var headers = await ReadHeaderBlockAsync(server, cancellationToken);
                await RespondAsync(server, headers.StreamId, cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
        return delivered;
    }

    /// <summary>
    /// Reads the client's preface frames and its complete request header block, then
    /// replies 200 with END_STREAM.
    /// </summary>
    private static Http2ServerScript MinimalExchange { get; } = async (server, cancellationToken) =>
    {
        _ = await server.ReadPrefaceAsync(cancellationToken);
        var headers = await ReadHeaderBlockAsync(server, cancellationToken);
        await RespondAsync(server, headers.StreamId, cancellationToken);
    };

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

    private static async Task RespondAsync(
        Http2WireServer server,
        int streamId,
        CancellationToken cancellationToken)
    {
        // 0x88 is the static-table entry for ":status: 200".
        await server.WriteFrameAsync(
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
            streamId,
            [0x88],
            cancellationToken);
        await server.FlushAsync(cancellationToken);
    }

    private static async Task RespondWithBodyAsync(
        Http2WireServer server,
        int bodyLength,
        CancellationToken cancellationToken)
    {
        _ = await server.ReadPrefaceAsync(cancellationToken);
        var headers = await ReadHeaderBlockAsync(server, cancellationToken);

        await server.WriteFrameAsync(
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders,
            headers.StreamId,
            [0x88],
            cancellationToken);
        await server.WriteFrameAsync(
            Http2FrameType.Data,
            Http2FrameFlags.EndStream,
            headers.StreamId,
            new byte[bodyLength],
            cancellationToken);
        await server.FlushAsync(cancellationToken);
    }
}
