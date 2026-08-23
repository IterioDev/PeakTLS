using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

/// <summary>
/// Proves the SETTINGS acknowledgement mechanism: that each
/// <see cref="TlsHttp2SettingsAckPlacement"/> value puts the acknowledgement where it
/// claims, that deferral survives an inbound frame rather than collapsing into
/// <see cref="TlsHttp2SettingsAckPlacement.Standalone"/>, and that a deferred
/// acknowledgement is always eventually written.
/// </summary>
/// <remarks>
/// Every script here sends the server's SETTINGS only after the client's request header
/// block has been read. That ordering is what makes the assertions deterministic: the
/// client's read loop processes frames one at a time and in arrival order, so an
/// acknowledgement produced by a SETTINGS frame the server sent at a chosen point can
/// only be carried by client writes that follow it.
/// </remarks>
public sealed class Http2SettingsAckPlacementTests
{
    private static readonly byte[] PingPayload = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    private static CapturedFrame SettingsAck =>
        new(Http2FrameType.Settings, Http2FrameFlags.Ack, 0, []);

    private static CapturedFrame PingAck =>
        new(Http2FrameType.Ping, Http2FrameFlags.Ack, 0, PingPayload);

    /// <summary>
    /// <c>Standalone</c> acknowledges on receipt. The client has already written its
    /// whole request and its stream is still open, so no write batch and no idle bound
    /// can produce the acknowledgement — only the receipt path can.
    /// </summary>
    [Fact]
    public async Task Standalone_AcknowledgesOnReceiptWithNoFurtherClientWrite()
    {
        CapturedFrame received = default;

        var result = await Http2WireCapture.RunAsync(
            CreateOptions(TlsHttp2SettingsAckPlacement.Standalone),
            (session, url, cancellationToken) => session.GetAsync(url, cancellationToken),
            async (server, cancellationToken) =>
            {
                var headers = await ReadRequestAsync(server, cancellationToken);

                await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
                await server.FlushAsync(cancellationToken);

                received = await server.ReadFrameAsync(cancellationToken);

                await RespondAsync(server, headers.StreamId, cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
        Http2WireAssert.EqualFrames(
            [SettingsAck],
            [received],
            "standalone acknowledgement");
    }

    /// <summary>
    /// The two coalescing values across a real one-flight arrival: SETTINGS and PING
    /// reach the read loop back to back, exactly the pattern that would make deferral
    /// unreachable if it were bounded on inbound frames. The acknowledgement must instead
    /// ride the PING acknowledgement's write batch, on the declared side of it.
    /// </summary>
    [Theory]
    [InlineData(TlsHttp2SettingsAckPlacement.BeforeNextBatch)]
    [InlineData(TlsHttp2SettingsAckPlacement.AfterNextBatch)]
    public async Task Coalescing_PlacesTheAcknowledgementOnItsDeclaredSideOfTheNextBatch(
        TlsHttp2SettingsAckPlacement placement)
    {
        var captured = new List<CapturedFrame>();

        var result = await Http2WireCapture.RunAsync(
            CreateOptions(placement),
            (session, url, cancellationToken) => session.GetAsync(url, cancellationToken),
            async (server, cancellationToken) =>
            {
                var headers = await ReadRequestAsync(server, cancellationToken);

                await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Ping,
                    0,
                    0,
                    PingPayload,
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                captured.Add(await server.ReadFrameAsync(cancellationToken));
                captured.Add(await server.ReadFrameAsync(cancellationToken));

                await RespondAsync(server, headers.StreamId, cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
        CapturedFrame[] expected = placement == TlsHttp2SettingsAckPlacement.BeforeNextBatch
            ? [SettingsAck, PingAck]
            : [PingAck, SettingsAck];
        Http2WireAssert.EqualFrames(expected, captured, $"{placement} around the PING batch");
    }

    /// <summary>
    /// The idle bound. The server sends its SETTINGS together with the response, so the
    /// client never writes another batch: the acknowledgement can only reach the wire
    /// because the connection went idle when its last stream closed.
    /// </summary>
    [Fact]
    public async Task Coalescing_FlushesADeferredAcknowledgementWhenTheConnectionGoesIdle()
    {
        CapturedFrame received = default;

        var result = await Http2WireCapture.RunAsync(
            CreateOptions(TlsHttp2SettingsAckPlacement.AfterNextBatch),
            (session, url, cancellationToken) => session.GetAsync(url, cancellationToken),
            async (server, cancellationToken) =>
            {
                var headers = await ReadRequestAsync(server, cancellationToken);

                await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
                await RespondAsync(server, headers.StreamId, cancellationToken);

                received = await server.ReadFrameAsync(cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
        Http2WireAssert.EqualFrames(
            [SettingsAck],
            [received],
            "idle-bound acknowledgement");
    }

    /// <summary>
    /// The superseding-SETTINGS bound. A second SETTINGS frame carries values the peer has
    /// not seen acknowledged yet, so the deferred acknowledgement goes out standalone
    /// before those values are applied. Two SETTINGS frames therefore produce two
    /// acknowledgements, and only the later one is still deferred onto the PING batch.
    /// </summary>
    [Fact]
    public async Task Coalescing_FlushesADeferredAcknowledgementBeforeApplyingLaterSettings()
    {
        var captured = new List<CapturedFrame>();

        var result = await Http2WireCapture.RunAsync(
            CreateOptions(TlsHttp2SettingsAckPlacement.AfterNextBatch),
            (session, url, cancellationToken) => session.GetAsync(url, cancellationToken),
            async (server, cancellationToken) =>
            {
                var headers = await ReadRequestAsync(server, cancellationToken);

                await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
                await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.Ping,
                    0,
                    0,
                    PingPayload,
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                captured.Add(await server.ReadFrameAsync(cancellationToken));
                captured.Add(await server.ReadFrameAsync(cancellationToken));
                captured.Add(await server.ReadFrameAsync(cancellationToken));

                await RespondAsync(server, headers.StreamId, cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
        Http2WireAssert.EqualFrames(
            [SettingsAck, PingAck, SettingsAck],
            captured,
            "superseded acknowledgement");
    }

    private static TlsSessionOptions CreateOptions(TlsHttp2SettingsAckPlacement placement)
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.SettingsAckPlacement = placement;
        return options;
    }

    /// <summary>
    /// Consumes the connection preface, the client's preface frames, and the complete
    /// request header block, and returns the HEADERS frame that opened it.
    /// </summary>
    private static async Task<CapturedFrame> ReadRequestAsync(
        Http2WireServer server,
        CancellationToken cancellationToken)
    {
        var preface = await server.ReadPrefaceAsync(cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray(), preface);

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
}
