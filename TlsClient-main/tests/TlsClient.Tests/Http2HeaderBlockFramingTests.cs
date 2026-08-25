using System.Net;
using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

/// <summary>
/// How a request field block is cut into HEADERS and CONTINUATION frames: the declared
/// fragment size, the clamp against the peer's maximum frame size, and the interaction with
/// a per-request pad.
/// </summary>
public sealed class Http2HeaderBlockFramingTests
{
    /// <summary>
    /// The loopback authority carries the listener's ephemeral port, so pinning <c>Host</c>
    /// pins <c>:authority</c> and keeps the encoded block the same length from run to run.
    /// </summary>
    private const string FixedAuthority = "fragment.test";

    /// <summary>
    /// The RFC 9113 section 6.5.2 default for SETTINGS_MAX_FRAME_SIZE, which is what
    /// <see cref="Http2WireCapture.MinimalExchange"/> leaves in force — its SETTINGS frame is
    /// empty, so the peer never advertises anything larger.
    /// </summary>
    private const int DefaultMaximumFrameSize = 16_384;

    /// <summary>
    /// Every fragment is asserted, not merely the fact that the block was split. RFC 9113
    /// section 6.10 gives CONTINUATION no PADDED and no PRIORITY flag, so with neither
    /// declared each frame carries exactly the declared number of field-block octets until the
    /// remainder, which carries END_HEADERS.
    /// </summary>
    [Fact]
    public async Task DeclaredFragmentSize_SizesEveryFragmentAtThatSize()
    {
        const int FragmentSize = 64;

        var fragments = await CaptureHeaderBlockAsync(
            session => session.Http2.HeaderBlockFragmentSize = FragmentSize,
            // A bare GET encodes to well under one fragment, so the block is padded out with a
            // field long enough to need several.
            request => request.AddHeader("x-filler", new string('a', 300)));

        Assert.True(fragments.Length > 2, $"expected CONTINUATION, got {fragments.Length} frame(s)");
        Assert.Equal(Http2FrameType.Headers, fragments[0].Type);
        Assert.All(fragments[1..], frame => Assert.Equal(Http2FrameType.Continuation, frame.Type));

        for (var index = 0; index < fragments.Length - 1; index++)
        {
            Assert.Equal(FragmentSize, fragments[index].Payload.Length);
            Assert.Equal(0, fragments[index].Flags & Http2FrameFlags.EndHeaders);
        }

        var last = fragments[^1];
        Assert.InRange(last.Payload.Length, 1, FragmentSize);
        Assert.Equal(Http2FrameFlags.EndHeaders, last.Flags & Http2FrameFlags.EndHeaders);
    }

    /// <summary>
    /// The declared size can only fragment smaller than the peer permits. RFC 9113 section 4.2
    /// limits a frame payload to SETTINGS_MAX_FRAME_SIZE and makes an oversized field-block
    /// frame a connection error of type FRAME_SIZE_ERROR, so a larger declaration is clamped
    /// down rather than honoured. The peer here advertises nothing, which leaves the section
    /// 6.5.2 default of 16384 — the same value the pre-SETTINGS clamp is fixed at.
    /// </summary>
    [Fact]
    public async Task DeclaredFragmentSizeAboveThePeerMaximum_IsClampedDownToIt()
    {
        const int FragmentSize = 20_000;

        var fragments = await CaptureHeaderBlockAsync(
            session => session.Http2.HeaderBlockFragmentSize = FragmentSize,
            request => request.AddHeader(
                "x-large",
                new string('a', 40_000)));

        Assert.True(fragments.Length > 1, $"expected CONTINUATION, got {fragments.Length} frame(s)");
        for (var index = 0; index < fragments.Length - 1; index++)
        {
            Assert.Equal(DefaultMaximumFrameSize, fragments[index].Payload.Length);
        }
        Assert.InRange(fragments[^1].Payload.Length, 1, DefaultMaximumFrameSize);
    }

    /// <summary>
    /// The declared minimum of 6 covers the 5-octet priority payload, but a pad is declared per
    /// request and takes up to another 256 octets out of the same budget (RFC 9113 section 4.2
    /// limits the whole payload, pad included), so the two together can drive it negative. The
    /// request must still go out: one octet of field block is carried anyway, which overruns
    /// only the client's own declared size — section 4.2 floors the peer's own limit at 16384,
    /// far above the 262 octets a padded, prioritized 6-octet fragment can reach.
    /// </summary>
    [Fact]
    public async Task SmallestFragmentSizeWithTheLargestPad_StillWritesTheBlock()
    {
        var fragments = await CaptureHeaderBlockAsync(
            session =>
            {
                session.Http2.HeaderBlockFragmentSize = 6;
                session.Http2.HeaderPriority = new TlsHttp2Priority { Weight = 41 };
            },
            request => TlsRequestOptions.For(request).HeadersPadding = 255);

        // Pad Length octet, the 5-octet priority payload, one octet of field block, 255 of pad.
        Assert.Equal(1 + 5 + 1 + 255, fragments[0].Payload.Length);
        Assert.Equal(
            Http2FrameFlags.Padded | Http2FrameFlags.Priority,
            fragments[0].Flags & (Http2FrameFlags.Padded | Http2FrameFlags.Priority));
        // Pinned so the range below is provably non-empty: fragments[1..^1] over a two-frame
        // block ranges over nothing and asserts nothing at all. The block is entirely the
        // caller's own fields now — a session contributes none — and Host is pinned to
        // FixedAuthority, so the encoded size, and with it this count, is the same from run to
        // run: one octet of field block in the HEADERS frame and the rest in CONTINUATION
        // frames of at most 6.
        Assert.Equal(5, fragments.Length);
        // Neither flag exists on CONTINUATION (section 6.10), so the rest get the whole 6.
        Assert.All(
            fragments[1..^1],
            frame => Assert.Equal(6, frame.Payload.Length));
        Assert.Equal(
            Http2FrameFlags.EndHeaders,
            fragments[^1].Flags & Http2FrameFlags.EndHeaders);
    }

    /// <summary>
    /// The default declares nothing and splits only at the peer's limit, which is today's
    /// behaviour: a request whose block fits in one frame writes one frame.
    /// </summary>
    [Fact]
    public async Task NoDeclaredFragmentSize_WritesTheBlockInOneFrame()
    {
        var fragments = await CaptureHeaderBlockAsync(_ => { }, _ => { });

        var only = Assert.Single(fragments);
        Assert.Equal(Http2FrameType.Headers, only.Type);
        Assert.Equal(Http2FrameFlags.EndHeaders, only.Flags & Http2FrameFlags.EndHeaders);
    }

    /// <summary>
    /// Nothing generates RFC 9110 section 6.6.2's <c>trailer</c> field from the trailer list.
    /// A request that announces its trailers adds the field; one that does not — which is what
    /// real HTTP/2 clients generally do — simply sends none. The session switch that used to
    /// decide this is gone: it could only ever have contradicted the request's own list.
    /// <para>RFC 9113 section 8.2.1 lowercases every field name, so the added <c>Trailer</c>
    /// reaches the block as <c>trailer</c>.</para>
    /// </summary>
    [Fact]
    public async Task TheTrailerFieldIsTheOneTheRequestAddedOrNoneAtAll()
    {
        var announced = await CaptureTrailingRequestAsync(
            request => request.AddHeader("Trailer", "x-checksum, x-elapsed"));

        Assert.Equal("x-checksum, x-elapsed", Value(announced, "trailer"));

        var silent = await CaptureTrailingRequestAsync();

        Assert.Null(Value(silent, "trailer"));
    }

    /// <summary>
    /// Reads a POST whose body is followed by a trailing field block and returns the decoded
    /// request block, which is the first HEADERS frame — the trailers are a second one.
    /// </summary>
    private static async Task<IReadOnlyList<HpackHeader>> CaptureTrailingRequestAsync(
        Action<HttpRequestMessage>? configureRequest = null)
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent("body"),
                };
                request.AddHeader("Host", FixedAuthority);
                // Trailers force chunked, so the framing slot has to name Transfer-Encoding.
                // RFC 9113 section 8.2.2 forbids that field over HTTP/2, so it never reaches
                // the block — the slot exists to satisfy the framing rule, not the wire.
                request.AddHeader("transfer-encoding", "chunked");
                configureRequest?.Invoke(request);
                var trailers = TlsRequestOptions.For(request).Trailers;
                trailers.Set("x-checksum", "0");
                trailers.Set("x-elapsed", "1");
                return await session.SendAsync(request, cancellationToken);
            },
            TrailingExchange);

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var block = result.ClientFrames.First(frame => frame.Type == Http2FrameType.Headers);
        return new HpackDecoder(4096).Decode(block.Payload, 16 * 1024);
    }

    /// <summary>
    /// Reads to whichever frame carries END_STREAM instead of counting frames, because the
    /// SETTINGS acknowledgement is written by the read loop on its own clock. With trailers
    /// present END_STREAM lands on the trailing HEADERS frame, not on the last DATA frame.
    /// </summary>
    private static readonly Http2ServerScript TrailingExchange =
        async (server, cancellationToken) =>
        {
            await server.ReadPrefaceAsync(cancellationToken);
            await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
            await server.WriteFrameAsync(Http2FrameType.Settings, 0, 0, [], cancellationToken);
            await server.FlushAsync(cancellationToken);

            var headers = await server.ReadUntilAsync(Http2FrameType.Headers, cancellationToken);
            var frame = headers;
            while ((frame.Flags & Http2FrameFlags.EndStream) == 0)
            {
                frame = await server.ReadFrameAsync(cancellationToken);
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

    private static string? Value(IReadOnlyList<HpackHeader> headers, string name) =>
        headers.Where(header => header.Name == name).Select(header => header.Value)
            .FirstOrDefault();

    private static async Task<CapturedFrame[]> CaptureHeaderBlockAsync(
        Action<TlsSessionOptions> configureSession,
        Action<HttpRequestMessage> configureRequest)
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        configureSession(options);

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.AddHeader("Host", FixedAuthority);
                configureRequest(request);
                return await session.SendAsync(request, cancellationToken);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        return result.ClientFrames
            .Where(frame =>
                frame.Type is Http2FrameType.Headers or Http2FrameType.Continuation)
            .ToArray();
    }
}
