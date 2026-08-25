using System.Text;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>
/// The two halves of HTTP/3 request content that can be pinned without a peer: which octets
/// become <c>TlsQuicHttp3Request.Body</c>, and what a caller is told when SharpTls refuses to
/// open the request stream.
/// </summary>
/// <remarks>
/// <para>Both are reachable offline because both are pure functions —
/// <see cref="Http3Connection.ReadRequestBodyAsync"/> reads only the request and the
/// configuration, and <see cref="Http3Connection.Describe"/> takes the flow-control numbers as
/// arguments rather than reading them off a live connection. That shape is deliberate: the
/// refusal messages are the whole of what a caller uploading more than the peer's credit ever
/// sees, and a message only a live run can witness is a message nothing checks.</para>
/// <para><see cref="Http3LiveTests"/> holds the end-to-end half.</para>
/// </remarks>
public sealed class Http3RequestContentTests
{
    private static readonly Uri Url = new("https://example.com/upload");

    private static TlsSessionConfiguration Configuration(
        Action<TlsSessionOptions>? configure = null)
    {
        var options = new TlsSessionOptions();
        configure?.Invoke(options);
        return options.Snapshot();
    }

    // A body needs a framing slot, and the NAME chosen there decides the framing. The value is
    // a placeholder: only the position survives, and the real one is always computed.
    private static HeaderEntry Length => new("Content-Length", ["-1"]);

    private static HeaderEntry Chunked => new("Transfer-Encoding", ["chunked"]);

    private static BufferedRequest Buffered(byte[] body, bool hasContent = true) =>
        new("POST", Url, hasContent ? [Length] : [], body, hasContent);

    private static BufferedRequest Streaming(byte[] body, int bufferSize = 8) =>
        new(
            "POST",
            Url,
            [Chunked],
            [],
            HasContent: true,
            TlsHttpVersionPolicy.PreferHttp2,
            new StreamContent(new MemoryStream(body)),
            bufferSize);

    // ----- which octets become the DATA frame -----

    [Fact]
    public async Task ABufferedBodyReachesTheDataFrameVerbatim()
    {
        var payload = Encoding.UTF8.GetBytes("the exact octets, not a length");

        var body = await Http3Connection.ReadRequestBodyAsync(
            Buffered(payload), Configuration(), CancellationToken.None);

        Assert.Equal(payload, body);
    }

    /// <summary>
    /// The GET invariant, stated as a test rather than as a comment: SharpTls emits no DATA
    /// frame for an empty body, so a request that declares no content must produce zero octets
    /// here however many its <c>Body</c> array happens to hold. A redirect that dropped its
    /// body is exactly that shape.
    /// </summary>
    [Fact]
    public async Task ARequestThatDeclaresNoContentContributesNoOctets()
    {
        var body = await Http3Connection.ReadRequestBodyAsync(
            Buffered(Encoding.UTF8.GetBytes("stale octets"), hasContent: false),
            Configuration(),
            CancellationToken.None);

        Assert.Empty(body);
    }

    [Fact]
    public async Task AGetContributesNoOctets()
    {
        var request = new BufferedRequest("GET", Url, [], [], HasContent: false);

        Assert.Empty(await Http3Connection.ReadRequestBodyAsync(
            request, Configuration(), CancellationToken.None));
    }

    /// <summary>
    /// A streaming body is buffered whole rather than dropped. The read buffer is deliberately
    /// smaller than the payload, so a single-read implementation fails this.
    /// </summary>
    [Fact]
    public async Task AStreamedBodyIsBufferedWholeAcrossManyReads()
    {
        var payload = Encoding.UTF8.GetBytes(new string('x', 100) + "TAIL");

        var body = await Http3Connection.ReadRequestBodyAsync(
            Streaming(payload, bufferSize: 8), Configuration(), CancellationToken.None);

        Assert.Equal(payload, body);
    }

    [Fact]
    public async Task AnEmptyStreamedBodyContributesNoOctets() =>
        Assert.Empty(await Http3Connection.ReadRequestBodyAsync(
            Streaming([]), Configuration(), CancellationToken.None));

    [Fact]
    public async Task AStreamedBodyPastTheSessionLimitIsRefusedRatherThanBuffered()
    {
        var configuration = Configuration(options =>
            options.MaximumRequestBodyBytes = 16);

        var exception = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await Http3Connection.ReadRequestBodyAsync(
                Streaming(new byte[64], bufferSize: 8),
                configuration,
                CancellationToken.None));

        Assert.Contains("16-byte session limit", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The limit is a limit and not a rounding: a body of exactly the configured size is
    /// buffered, and one octet more is not.
    /// </summary>
    [Fact]
    public async Task ThePreciseLimitIsTheBoundary()
    {
        var configuration = Configuration(options =>
            options.MaximumRequestBodyBytes = 32);

        Assert.Equal(
            32,
            (await Http3Connection.ReadRequestBodyAsync(
                Streaming(new byte[32], bufferSize: 8),
                configuration,
                CancellationToken.None)).Length);
        await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await Http3Connection.ReadRequestBodyAsync(
                Streaming(new byte[33], bufferSize: 8),
                configuration,
                CancellationToken.None));
    }

    /// <summary>
    /// A zero-length read buffer makes every read return 0, which a naive loop reads as the end
    /// of the stream and sends the request with no body at all. The cancellation token bounds
    /// the other failure this could have been — a loop that never advances — so a hang is
    /// reported as a failure rather than holding the suite open.
    /// </summary>
    [Fact]
    public async Task AZeroLengthReadBufferDoesNotSilentlyEmptyTheBody()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var payload = Encoding.UTF8.GetBytes("no spin");

        var body = await Http3Connection.ReadRequestBodyAsync(
            Streaming(payload, bufferSize: 0), Configuration(), timeout.Token);

        Assert.Equal(payload, body);
    }

    // ------------------------------------------------------------------------------------
    // The wire image, which is the only offline witness that the DATA frame exists at all.
    //
    // These drive the WHOLE composition SendAsync performs — Http3FieldMapper's field section,
    // Http3FieldMapper's trailer section and ReadRequestBodyAsync's octets — through the same
    // TlsQuicHttp3Request.TryEncode that TryOpenRequest hands to the wire, then read the frames
    // back out. An implementation that dropped the body, or emitted an empty DATA frame for a
    // GET, or put the trailers before the body, fails here rather than only against a server.
    // ------------------------------------------------------------------------------------

    /// <summary>
    /// Encodes one request through the SAME composition <c>Http3Connection.SendAsync</c> hands
    /// to <c>TryOpenRequest</c>, and reads the frames back.
    /// </summary>
    /// <remarks><c>BuildRequestAsync</c> is called rather than reassembled here on purpose: a
    /// helper that rebuilt the request would witness itself, and every wiring fault in the real
    /// one — a dropped body, a missing trailer section, the wrong <c>:scheme</c> — would pass
    /// this file and reach the wire.</remarks>
    private static async Task<List<(ulong Type, byte[] Payload)>> EncodeAsync(
        BufferedRequest request,
        TlsSessionConfiguration? configuration = null)
    {
        configuration ??= Configuration();
        var encodable = await Http3Connection.BuildRequestAsync(request, null, configuration, CancellationToken.None);

        var encoded = new List<byte>();
        var succeeded = encodable.TryEncode(encoded, new TlsQuicHttp3Spec(), out var error);
        Assert.Equal(TlsQuicHttp3RequestError.None, error);
        Assert.True(succeeded);

        var frames = new List<(ulong, byte[])>();
        var span = System.Runtime.InteropServices.CollectionsMarshal.AsSpan(encoded);
        var offset = 0;
        while (offset < span.Length)
        {
            var status = TlsQuicHttp3Frames.TryRead(
                span, ref offset, out var type, out var payload, out _);
            Assert.Equal(TlsQuicHttp3FrameReadStatus.Complete, status);
            frames.Add((type, payload.ToArray()));
        }
        return frames;
    }

    private static ulong[] MessageFrames(List<(ulong Type, byte[] Payload)> frames) =>
        frames
            .Where(frame => frame.Type
                is (ulong)TlsQuicHttp3FrameType.Headers or (ulong)TlsQuicHttp3FrameType.Data)
            .Select(frame => frame.Type)
            .ToArray();

    /// <summary>
    /// The four pseudo-headers and the two optional sections, read off the request object
    /// SendAsync actually hands to <c>TryOpenRequest</c>. Section 4.3.1's set is not derivable
    /// from the encoded HEADERS payload without a QPACK decoder, so it is checked here.
    /// </summary>
    [Fact]
    public async Task TheRequestSendAsyncHandsToSharpTlsCarriesEveryPart()
    {
        var payload = "octets"u8.ToArray();
        var request = new BufferedRequest(
            "PUT",
            new Uri("https://example.com/deep/path?q=1"),
            [Chunked],
            payload,
            HasContent: true)
        {
            Trailers = [new HeaderEntry("Checksum", ["abc"])],
        };

        var encodable = await Http3Connection.BuildRequestAsync(request, null, Configuration(), CancellationToken.None);

        Assert.Equal("PUT", encodable.Method);
        Assert.Equal("https", encodable.Scheme);
        Assert.Equal("example.com", encodable.Authority);
        Assert.Equal("/deep/path?q=1", encodable.Path);
        Assert.Equal(payload, encodable.Body);
        Assert.Equal(
            ["checksum: abc"],
            encodable.Trailers.Select(field => $"{field.Name}: {field.Value}"));
    }

    /// <summary>
    /// An empty request-target becomes section 4.3.1's origin-form. Reached through
    /// <c>PathOverride</c>, which is the only way to get there: <see cref="Uri"/> normalises an
    /// https authority-only URL to "/" on its own, so the guard would be unreachable — and
    /// therefore untestable — if this drove the URL instead.
    /// </summary>
    [Fact]
    public async Task AnEmptyRequestTargetBecomesTheOriginForm()
    {
        var request = new BufferedRequest(
            "GET", new Uri("https://example.com"), [], [], HasContent: false)
        {
            PathOverride = string.Empty,
        };

        var encodable = await Http3Connection.BuildRequestAsync(request, null, Configuration(), CancellationToken.None);

        Assert.Equal("/", encodable.Path);
        Assert.Empty(encodable.Body);
        Assert.Empty(encodable.Trailers);
    }

    [Fact]
    public async Task APathOverrideIsSentVerbatim()
    {
        var request = new BufferedRequest(
            "OPTIONS", new Uri("https://example.com/ignored"), [], [], HasContent: false)
        {
            PathOverride = "*",
        };

        var encodable = await Http3Connection.BuildRequestAsync(request, null, Configuration(), CancellationToken.None);

        Assert.Equal("*", encodable.Path);
    }

    /// <summary>
    /// The unchanged-GET clause. SharpTls pins its own request's exact wire octets against an
    /// empty body; what this side owes is that a request without content still hands it one,
    /// so no DATA frame is emitted — not an empty one, none.
    /// </summary>
    [Fact]
    public async Task AGetEmitsOneHeadersFrameAndNoDataFrame()
    {
        var frames = await EncodeAsync(
            new BufferedRequest("GET", Url, [], [], HasContent: false));

        Assert.Equal([(ulong)TlsQuicHttp3FrameType.Headers], MessageFrames(frames));
    }

    [Fact]
    public async Task APostEmitsExactlyOneDataFrameCarryingTheBodyVerbatim()
    {
        var payload = "the exact octets, not a length"u8.ToArray();

        var frames = await EncodeAsync(Buffered(payload));

        Assert.Equal(
            [(ulong)TlsQuicHttp3FrameType.Headers, (ulong)TlsQuicHttp3FrameType.Data],
            MessageFrames(frames));
        Assert.Equal(
            payload,
            frames.Single(frame => frame.Type == (ulong)TlsQuicHttp3FrameType.Data).Payload);
    }

    /// <summary>
    /// RFC 9114 section 4.1's order: the header section, then the content, then the trailer
    /// section. Trailers before the body would be a second header section rather than a
    /// trailer section, and the peer would read them as one.
    /// </summary>
    [Fact]
    public async Task TrailersFollowTheBodyAsASecondHeadersFrame()
    {
        var request = new BufferedRequest("POST", Url, [Chunked], "body"u8.ToArray(), HasContent: true)
        {
            Trailers = [new HeaderEntry("Checksum", ["abc"])],
        };

        var frames = await EncodeAsync(request);

        Assert.Equal(
            [
                (ulong)TlsQuicHttp3FrameType.Headers,
                (ulong)TlsQuicHttp3FrameType.Data,
                (ulong)TlsQuicHttp3FrameType.Headers,
            ],
            MessageFrames(frames));
    }

    [Fact]
    public async Task AStreamedBodyReachesTheDataFrameToo()
    {
        var payload = "streamed, buffered, then framed"u8.ToArray();

        var frames = await EncodeAsync(Streaming(payload, bufferSize: 8));

        Assert.Equal(
            payload,
            frames.Single(frame => frame.Type == (ulong)TlsQuicHttp3FrameType.Data).Payload);
    }

    /// <summary>
    /// The content-length agreement, refused by SharpTls before a byte reaches the wire. This
    /// is the shape TlsClient can actually produce: a streaming content that DECLARES one
    /// length and yields another.
    /// </summary>
    [Fact]
    public async Task AContentLengthThatDisagreesWithTheBodyIsRefusedByTryEncode()
    {
        var content = new StreamContent(new MemoryStream("four"u8.ToArray()));
        content.Headers.ContentLength = 500;
        var request = new BufferedRequest(
            "POST",
            Url,
            [Length],
            [],
            HasContent: true,
            TlsHttpVersionPolicy.PreferHttp2,
            content);
        var configuration = Configuration();

        var encodable = await Http3Connection.BuildRequestAsync(request, null, configuration, CancellationToken.None);
        Assert.Contains(
            encodable.Fields, field => field is { Name: "content-length", Value: "500" });
        Assert.Equal(4, encodable.Body.Length);

        var encoded = new List<byte>();
        var succeeded = encodable.TryEncode(encoded, new TlsQuicHttp3Spec(), out var error);

        Assert.False(succeeded);
        Assert.Equal(TlsQuicHttp3RequestError.ContentLengthDisagreesWithBody, error);
        // Nothing partial was left behind for a caller to send anyway.
        Assert.Empty(encoded);
    }

    /// <summary>
    /// The agreement holds for every buffered request this mapper can build, which is what
    /// makes ordinary POSTs sendable at all. Sizes chosen to straddle QUIC's varint length
    /// boundaries (1, 2 and 4-byte forms), where a length written into the wrong width would
    /// desynchronise the frame stream.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(16_383)]
    [InlineData(16_384)]
    public async Task ABufferedBodyOfAnySizeAgreesWithItsDeclaredContentLength(int size)
    {
        var payload = new byte[size];
        Random.Shared.NextBytes(payload);

        var frames = await EncodeAsync(Buffered(payload));

        // Size 0 is the boundary that matters most: content-length: 0 agrees with an empty
        // body, and an empty body must still emit NO DATA frame.
        var data = frames
            .Where(frame => frame.Type == (ulong)TlsQuicHttp3FrameType.Data)
            .ToArray();
        if (size == 0)
        {
            Assert.Empty(data);
            return;
        }
        Assert.Equal(payload, Assert.Single(data).Payload);
    }

    // ----- what a refused caller is told -----

    /// <summary>
    /// A body larger than the peer's per-stream credit. Terminal rather than stale, because
    /// every connection to this peer starts every stream with the same
    /// <c>initial_max_stream_data_bidi_remote</c> and SharpTls processes no MAX_STREAM_DATA to
    /// raise it — a retry would spend another QUIC handshake to fail identically.
    /// </summary>
    [Fact]
    public void AnOverCreditBodyNamesTheStreamLimitAndIsNotRetried()
    {
        var exception = Http3Connection.Describe(
            TlsQuicHttp3RequestRefusal.PeerStreamCreditTooSmall,
            TlsQuicHttp3RequestError.None,
            streamCredit: 6_291_456,
            initialMaxData: 15_728_640,
            remainingConnectionData: 15_720_000,
            connectionErrorCode: 0);

        var protocol = Assert.IsType<TlsHttpProtocolException>(exception);
        Assert.Contains(
            "initial_max_stream_data_bidi_remote", protocol.Message, StringComparison.Ordinal);
        Assert.Contains("6291456", protocol.Message, StringComparison.Ordinal);
        Assert.Contains("MAX_STREAM_DATA", protocol.Message, StringComparison.Ordinal);
        // TlsSession.ShouldRetryException retries an IOException unless it is this type, and
        // TlsConnectionPool evicts on a StaleHttpConnectionException. Neither may happen here.
        Assert.IsNotType<StaleHttpConnectionException>(exception);
        // Nothing was written, so the connection survives the refusal.
        Assert.True(protocol.IsStreamScoped);
    }

    /// <summary>
    /// The connection-level pool, which is a DIFFERENT limit with a different remedy: this one
    /// a fresh connection really does fix, because the pool is drawn down by the streams
    /// already opened on this connection and starts full on the next.
    /// </summary>
    [Fact]
    public void AnExhaustedConnectionPoolIsReportedApartFromTheStreamLimit()
    {
        var exception = Http3Connection.Describe(
            TlsQuicHttp3RequestRefusal.PeerConnectionCreditTooSmall,
            TlsQuicHttp3RequestError.None,
            streamCredit: 6_291_456,
            initialMaxData: 15_728_640,
            remainingConnectionData: 4_096,
            connectionErrorCode: 0);

        Assert.IsType<StaleHttpConnectionException>(exception);
        Assert.Contains("initial_max_data", exception.Message, StringComparison.Ordinal);
        Assert.Contains("4096", exception.Message, StringComparison.Ordinal);
        Assert.Contains("15728640", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "initial_max_stream_data", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The two credit refusals must not be exchangeable. A caller told only "too small" cannot
    /// tell which transport parameter is in the way, which is the reason SharpTls made them two
    /// members rather than one.
    /// </summary>
    [Fact]
    public void TheTwoCreditRefusalsDoNotShareAMessage()
    {
        var stream = Http3Connection.Describe(
            TlsQuicHttp3RequestRefusal.PeerStreamCreditTooSmall,
            TlsQuicHttp3RequestError.None, 1, 2, 3, 0);
        var connection = Http3Connection.Describe(
            TlsQuicHttp3RequestRefusal.PeerConnectionCreditTooSmall,
            TlsQuicHttp3RequestError.None, 1, 2, 3, 0);

        Assert.NotEqual(stream.Message, connection.Message);
        Assert.NotEqual(stream.GetType(), connection.GetType());
    }

    /// <summary>
    /// Every refusal SharpTls can name has a message of its own. The fallback arm's wording is
    /// the marker, so a member added to <see cref="TlsQuicHttp3RequestRefusal"/> later fails
    /// this test rather than silently reaching a caller as its own enum name.
    /// </summary>
    [Fact]
    public void NoRefusalFallsThroughToTheUnnamedArm()
    {
        foreach (var refusal in Enum.GetValues<TlsQuicHttp3RequestRefusal>())
        {
            if (refusal == TlsQuicHttp3RequestRefusal.None)
            {
                continue;
            }
            var message = Http3Connection.Describe(
                refusal, TlsQuicHttp3RequestError.None, 1, 2, 3, 0).Message;
            Assert.DoesNotContain("was refused (", message, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// RFC 9114 section 4.1.2's rule about the message, which SharpTls applies to a REQUEST
    /// unconditionally — the "defined as never having content" escape is a response rule. The
    /// general field-section wording would misreport it, so it has its own.
    /// </summary>
    [Fact]
    public void ADisagreeingContentLengthIsNamedRatherThanCalledAFieldSectionFault()
    {
        var exception = Http3Connection.Describe(
            TlsQuicHttp3RequestRefusal.Malformed,
            TlsQuicHttp3RequestError.ContentLengthDisagreesWithBody,
            1, 2, 3, 0);

        var protocol = Assert.IsType<TlsHttpProtocolException>(exception);
        Assert.Contains("content-length", protocol.Message, StringComparison.Ordinal);
        Assert.Contains("4.1.2", protocol.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("field section", protocol.Message, StringComparison.Ordinal);
        // Refused before a stream ordinal was spent, so the connection is still good.
        Assert.True(protocol.IsStreamScoped);
    }

    [Fact]
    public void APseudoHeaderInATrailerSectionIsNamed()
    {
        var exception = Http3Connection.Describe(
            TlsQuicHttp3RequestRefusal.Malformed,
            TlsQuicHttp3RequestError.PseudoHeaderInTrailerSection,
            1, 2, 3, 0);

        Assert.Contains("trailer", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("pseudo-header", exception.Message, StringComparison.Ordinal);
        Assert.Contains("4.3", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOrdinaryFieldSectionFaultStillNamesItsRule()
    {
        var exception = Http3Connection.Describe(
            TlsQuicHttp3RequestRefusal.Malformed,
            TlsQuicHttp3RequestError.RegularFieldNameNotLowercase,
            1, 2, 3, 0);

        Assert.Contains(
            "RegularFieldNameNotLowercase", exception.Message, StringComparison.Ordinal);
    }
}
