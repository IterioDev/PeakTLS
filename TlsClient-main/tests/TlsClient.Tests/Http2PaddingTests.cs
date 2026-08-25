using System.Buffers.Binary;
using System.Net;
using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

/// <summary>
/// Declared HEADERS and DATA padding: the PADDED flag, the Pad Length octet, the pad's cost
/// against the frame-size budget, and its cost against the send window.
/// </summary>
public sealed class Http2PaddingTests
{
    /// <summary>
    /// The loopback authority carries the listener's ephemeral port, so two captures of the
    /// "same" request would not encode to the same field block. Pinning <c>Host</c> pins
    /// <c>:authority</c> — <c>BuildRequestHeaders</c> reads the authority out of the Host field
    /// when one is present and then drops the regular field — which is what lets a padded and
    /// an unpadded capture be compared octet for octet.
    /// </summary>
    private const string FixedAuthority = "padding.test";

    /// <summary>
    /// RFC 9113 section 6.9.2: "When an HTTP/2 connection is first established, new streams are
    /// created with an initial flow-control window size of 65,535 octets. The connection
    /// flow-control window is also 65,535 octets."
    /// </summary>
    private const int InitialSendWindow = 65_535;

    /// <summary>The RFC 9113 section 4.2 default for SETTINGS_MAX_FRAME_SIZE.</summary>
    private const int DefaultMaximumFrameSize = 16_384;

    /// <summary>
    /// Reads the client's request through the DATA frame carrying END_STREAM, then answers 200.
    /// Counting frames instead would race the SETTINGS ACK the read loop writes on its own
    /// clock, so this reads to a frame that is certain to arrive.
    /// </summary>
    private static readonly Http2ServerScript BodyExchange =
        async (server, cancellationToken) =>
        {
            var headers = await OpenAndReadHeadersAsync(server, cancellationToken);
            await ReadToEndOfBodyAsync(server, cancellationToken);
            await CompleteAsync(server, headers.StreamId, cancellationToken);
        };

    private static async Task<CapturedFrame> OpenAndReadHeadersAsync(
        Http2WireServer server,
        CancellationToken cancellationToken)
    {
        await server.ReadPrefaceAsync(cancellationToken);
        await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
        await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
        await server.FlushAsync(cancellationToken);
        return await server.ReadUntilAsync(Http2FrameType.Headers, cancellationToken);
    }

    private static async Task ReadToEndOfBodyAsync(
        Http2WireServer server,
        CancellationToken cancellationToken)
    {
        CapturedFrame frame;
        do
        {
            frame = await server.ReadFrameAsync(cancellationToken);
        }
        while (frame.Type != Http2FrameType.Data ||
            (frame.Flags & Http2FrameFlags.EndStream) == 0);
    }

    private static async Task CompleteAsync(
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

    private static async Task<CapturedFrame> CaptureHeadersFrameAsync(int? padding)
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.AddHeader("Host", FixedAuthority);
                TlsRequestOptions.For(request).HeadersPadding = padding;
                return await session.SendAsync(request, cancellationToken);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        return result.ClientFrames.Single(frame => frame.Type == Http2FrameType.Headers);
    }

    /// <summary>
    /// RFC 9113 section 6.2, Figure 4 orders a padded HEADERS frame as Pad Length, priority
    /// payload, field block fragment, padding. Section 6.2 also requires "Padding octets MUST
    /// be set to zero when sending".
    /// </summary>
    [Fact]
    public async Task PaddedHeaders_CarryTheFlagThePadOctetAndAZeroPad()
    {
        const int Padding = 16;

        var unpadded = await CaptureHeadersFrameAsync(null);
        var padded = await CaptureHeadersFrameAsync(Padding);

        Assert.Equal(0, unpadded.Flags & Http2FrameFlags.Padded);
        Assert.Equal(Http2FrameFlags.Padded, padded.Flags & Http2FrameFlags.Padded);
        Assert.Equal(Padding, padded.Payload[0]);
        // One Pad Length octet plus the pad itself, and nothing else moved.
        Assert.Equal(unpadded.Payload.Length + 1 + Padding, padded.Payload.Length);
        Assert.Equal(unpadded.Payload, padded.Payload[1..^Padding]);
        Assert.Equal(new byte[Padding], padded.Payload[^Padding..]);
    }

    /// <summary>
    /// The assertion the nullable design exists for. RFC 9113 section 6.2: "Note: A frame can
    /// be increased in size by one octet by including a Pad Length field with a value of zero."
    /// A plain <c>int</c> defaulting to 0 could not express the difference between these two.
    /// </summary>
    [Fact]
    public async Task HeadersPaddingOfZero_IsExactlyOneOctetLongerThanNoPadding()
    {
        var unpadded = await CaptureHeadersFrameAsync(null);
        var emptyPad = await CaptureHeadersFrameAsync(0);

        Assert.Equal(0, unpadded.Flags & Http2FrameFlags.Padded);
        Assert.Equal(Http2FrameFlags.Padded, emptyPad.Flags & Http2FrameFlags.Padded);
        Assert.Equal(unpadded.Payload.Length + 1, emptyPad.Payload.Length);
        Assert.Equal(0, emptyPad.Payload[0]);
        Assert.Equal(unpadded.Payload, emptyPad.Payload[1..]);
    }

    /// <summary>
    /// RFC 9113 section 6.1, Figure 3 orders a padded DATA frame as Pad Length, Data, Padding.
    /// </summary>
    [Fact]
    public async Task PaddedData_CarriesTheFlagThePadOctetAndAZeroPad()
    {
        const int Padding = 24;
        var body = new byte[40];
        Array.Fill(body, (byte)0x5a);

        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new ByteArrayContent(body),
                };
                request.AddHeader("content-length", "-1");
                TlsRequestOptions.For(request).DataPadding = Padding;
                return await session.SendAsync(request, cancellationToken);
            },
            BodyExchange);

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var data = Assert.Single(
            result.ClientFrames,
            frame => frame.Type == Http2FrameType.Data);
        Assert.Equal(Http2FrameFlags.Padded, data.Flags & Http2FrameFlags.Padded);
        Assert.Equal(Http2FrameFlags.EndStream, data.Flags & Http2FrameFlags.EndStream);
        Assert.Equal(Padding, data.Payload[0]);
        Assert.Equal(body.Length + 1 + Padding, data.Payload.Length);
        Assert.Equal(body, data.Payload[1..^Padding]);
        Assert.Equal(new byte[Padding], data.Payload[^Padding..]);
    }

    /// <summary>
    /// CONTINUATION has neither a PADDED flag nor a Pad Length field (RFC 9113 section 6.10,
    /// Figure 12), so only the leading HEADERS frame pays the pad — and it pays it out of the
    /// frame-size budget of RFC 9113 section 4.2, which covers the whole payload. Adding the
    /// pad on top of a full fragment instead would push the frame past
    /// SETTINGS_MAX_FRAME_SIZE, which section 4.2 makes a connection error of type
    /// FRAME_SIZE_ERROR because HEADERS carries a field block.
    /// </summary>
    [Fact]
    public async Task PaddingWithContinuation_IsPaidOnceOutOfTheFirstFramesBudget()
    {
        const int Padding = 32;

        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.AddHeader("Host", FixedAuthority);
                // Larger than the 16384-octet default maximum frame size however it
                // compresses, so the block cannot fit in one frame.
                request.AddHeader("x-filler", new string('a', 60_000));
                TlsRequestOptions.For(request).HeadersPadding = Padding;
                return await session.SendAsync(request, cancellationToken);
            });

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

        var headers = frames[start];
        Assert.Equal(Http2FrameFlags.Padded, headers.Flags & Http2FrameFlags.Padded);
        Assert.Equal(Padding, headers.Payload[0]);
        Assert.Equal(new byte[Padding], headers.Payload[^Padding..]);
        // The pad came out of the budget rather than being added to it: the frame fills the
        // peer's advertised maximum exactly and does not exceed it.
        Assert.Equal(DefaultMaximumFrameSize, headers.Payload.Length);

        for (var index = start + 1; index <= end; index++)
        {
            Assert.Equal(Http2FrameType.Continuation, frames[index].Type);
            Assert.Equal(0, frames[index].Flags & Http2FrameFlags.Padded);
            Assert.True(
                frames[index].Payload.Length <= DefaultMaximumFrameSize,
                $"fragment {index - start} is {frames[index].Payload.Length} octets");
        }
    }

    /// <summary>
    /// RFC 9113 section 6.1: "The entire DATA frame payload is included in flow control,
    /// including the Pad Length and Padding fields." A client that reserved only the body
    /// octets would put more than the peer's 65,535-octet initial window on the wire before
    /// any WINDOW_UPDATE arrived, which section 6.9.1 has the peer answer with
    /// FLOW_CONTROL_ERROR. Charging the pad, the client stops exactly on the window and
    /// finishes the upload once the peer credits it.
    /// </summary>
    [Fact]
    public async Task PaddedData_ChargesThePadAgainstTheSendWindow()
    {
        const int Padding = 7;
        var body = new byte[70_000];
        Array.Fill(body, (byte)0x5a);
        var chargedBeforeCredit = 0;

        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new ByteArrayContent(body),
                };
                request.AddHeader("content-length", "-1");
                TlsRequestOptions.For(request).DataPadding = Padding;
                return await session.SendAsync(request, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                var headers = await OpenAndReadHeadersAsync(server, cancellationToken);

                // Credit nothing until the client has spent the initial window. The loop
                // stops on the first frame that reaches it, so an over-sending client
                // overshoots the total instead of deadlocking the test.
                while (chargedBeforeCredit < InitialSendWindow)
                {
                    var frame = await server.ReadFrameAsync(cancellationToken);
                    if (frame.Type != Http2FrameType.Data)
                    {
                        continue;
                    }
                    Assert.Equal(Http2FrameFlags.Padded, frame.Flags & Http2FrameFlags.Padded);
                    Assert.Equal(Padding, frame.Payload[0]);
                    chargedBeforeCredit += frame.Payload.Length;
                }

                // RFC 9113 section 6.9: stream identifier 0 credits the connection window,
                // any other identifier credits that stream's.
                var increment = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(increment, InitialSendWindow);
                await server.WriteFrameAsync(
                    Http2FrameType.WindowUpdate,
                    0,
                    0,
                    increment,
                    cancellationToken);
                await server.WriteFrameAsync(
                    Http2FrameType.WindowUpdate,
                    0,
                    headers.StreamId,
                    increment,
                    cancellationToken);
                await server.FlushAsync(cancellationToken);

                await ReadToEndOfBodyAsync(server, cancellationToken);
                await CompleteAsync(server, headers.StreamId, cancellationToken);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        // Every octet of every padded payload counted, so the client spent the window to the
        // last octet and not one beyond it.
        Assert.Equal(InitialSendWindow, chargedBeforeCredit);
        // And the upload still completed, whole: the pad is overhead, not lost body.
        var sent = result.ClientFrames
            .Where(frame => frame.Type == Http2FrameType.Data)
            .Sum(frame => frame.Payload.Length - 1 - Padding);
        Assert.Equal(body.Length, sent);
    }

    /// <summary>The Pad Length field is one octet on both frame types (RFC 9113 sections 6.1
    /// and 6.2), so 255 is the largest pad the wire can describe.</summary>
    [Theory]
    [InlineData(-1)]
    [InlineData(256)]
    public void Padding_OutsideOneOctet_IsRejected(int padding)
    {
        using var headersRequest = new HttpRequestMessage(HttpMethod.Get, "https://example.test/");
        TlsRequestOptions.For(headersRequest).HeadersPadding = padding;
        Assert.Throws<ArgumentOutOfRangeException>(
            () => TlsRequestOptions.Snapshot(headersRequest));

        using var dataRequest = new HttpRequestMessage(HttpMethod.Get, "https://example.test/");
        TlsRequestOptions.For(dataRequest).DataPadding = padding;
        Assert.Throws<ArgumentOutOfRangeException>(
            () => TlsRequestOptions.Snapshot(dataRequest));
    }
}
