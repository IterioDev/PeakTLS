using System.Collections.Immutable;
using System.Net;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>
/// The whole of HTTP/3's field mapping, exercised without a socket. SharpTls ships no
/// loopback HTTP/3 peer this assembly can reach, so a live run is the only end-to-end proof
/// available (see <see cref="Http3LiveTests"/>) and everything that can be pinned offline is
/// pinned here instead.
/// </summary>
public sealed class Http3FieldMapperTests
{
    private static TlsSessionConfiguration Configuration(Action<TlsSessionOptions>? configure = null)
    {
        var options = new TlsSessionOptions();
        configure?.Invoke(options);
        return options.Snapshot();
    }

    private static BufferedRequest Request(
        string method = "GET",
        string url = "https://example.com/path?q=1",
        params HeaderEntry[] headers) =>
        new(method, new Uri(url), headers, [], HasContent: false);

    private static string[] Rendered(ImmutableArray<TlsQuicHttp3Field> fields) =>
        fields.Select(field => $"{field.Name}: {field.Value}").ToArray();

    /// <summary>
    /// With no declared HeaderOrder and no session headers, the request's own insertion order
    /// is what reaches the wire, Content-Length included. Its declared VALUE is ignored — the
    /// real one is always computed — but the slot it was declared in is kept, so a caller can
    /// write a placeholder to reserve the position a captured client puts it in.
    /// </summary>
    [Fact]
    public void RequestFields_KeepInsertionOrderWhenNoHeaderOrderIsDeclared()
    {
        var request = new BufferedRequest(
            "POST",
            new Uri("https://login5.spotify.com/v4/login"),
            [
                new HeaderEntry("Content-Type", ["application/x-protobuf"]),
                new HeaderEntry("Accept", ["*/*"]),
                new HeaderEntry("Priority", ["u=3, i"]),
                new HeaderEntry("Accept-Encoding", ["gzip, deflate, br"]),
                new HeaderEntry("X-Retry-Count", ["0"]),
                new HeaderEntry("Cache-Control", ["no-cache, no-store, max-age=0"]),
                new HeaderEntry("Content-Length", ["404"]),
                new HeaderEntry("User-Agent", ["Spotify/9.1.76 iOS/27.0 (iPhone17,2)"]),
                new HeaderEntry("Accept-Language", ["en-US,en;q=0.9"]),
                new HeaderEntry("Client-Token", ["token"]),
            ],
            [],
            HasContent: true);

        var fields = Http3FieldMapper.BuildRequestFields(
            request,
            null,
            Configuration(options => options.HeaderOrder = null),
            out _);

        Assert.Equal(
            [
                "content-type", "accept", "priority", "accept-encoding", "x-retry-count",
                "cache-control", "content-length", "user-agent", "accept-language",
                "client-token",
            ],
            fields.Select(field => field.Name));

        // The placeholder "-1" never reaches the wire; the computed length does. This request
        // carries no body bytes, so that length is 0 — which is still the point: the value is
        // the transport's, the position is the caller's.
        Assert.Equal("0", fields.First(field => field.Name == "content-length").Value);
    }

#pragma warning disable TLSCLIENT3
    /// <summary>
    /// The login5 preset's captured POST order, pinned offline. A live observer is not enough
    /// here: tls3.peet.ws reports HTTP/3 field lines in an order that varies run to run, so
    /// only the bytes this mapper produces settle what reaches the wire.
    /// </summary>
    [Fact]
    public void RequestFields_FollowTheLogin5PresetOrderIncludingContentFields()
    {
        // The login5 v4 image, set explicitly. It used to come from a preset; presets no longer
        // declare a header order (one QUIC/TLS shape serves every endpoint, and header order is
        // the caller's), so the order under test is stated here where the expectation is.
        var options = TlsPresets.Spotify.CreateOptions();
        options.HeaderOrder =
        [
            "content-type", "accept", "priority", "accept-encoding", "x-retry-count",
            "cache-control", "content-length", "user-agent", "accept-language", "client-token",
        ];

        // Deliberately added in the WRONG order: the preset's declared header order is what
        // has to put them right, so scrambling the input is the whole point.
        var request = new BufferedRequest(
            "POST",
            new Uri("https://login5.spotify.com/v4/login"),
            [
                new HeaderEntry("Client-Token", ["token"]),
                new HeaderEntry("User-Agent", ["Spotify/9.1.76 iOS/27.0 (iPhone17,2)"]),
                new HeaderEntry("Content-Length", ["-1"]),
                new HeaderEntry("Accept-Language", ["en-US,en;q=0.9"]),
                new HeaderEntry("Content-Type", ["application/x-protobuf"]),
                new HeaderEntry("Cache-Control", ["no-cache, no-store, max-age=0"]),
                new HeaderEntry("Accept", ["*/*"]),
                new HeaderEntry("X-Retry-Count", ["0"]),
                new HeaderEntry("Priority", ["u=3, i"]),
                new HeaderEntry("Accept-Encoding", ["gzip, deflate, br"]),
            ],
            [],
            HasContent: true);

        var fields = Http3FieldMapper.BuildRequestFields(
            request,
            null,
            options.Snapshot(),
            out _);

        Assert.Equal(
            [
                "content-type", "accept", "priority", "accept-encoding", "x-retry-count",
                "cache-control", "content-length", "user-agent", "accept-language",
                "client-token",
            ],
            fields.Select(field => field.Name));
    }
#pragma warning restore TLSCLIENT3

    [Fact]
    public void RequestFields_LowercaseEveryName()
    {
        var fields = Http3FieldMapper.BuildRequestFields(
            Request(headers: [new HeaderEntry("Accept-Encoding", ["gzip"])]),
            null,
            Configuration(),
            out _);

        Assert.All(fields, field => Assert.Equal(field.Name.ToLowerInvariant(), field.Name));
        Assert.Contains("accept-encoding: gzip", Rendered(fields));
    }

    [Fact]
    public void RequestFields_DropTheHostFieldAndReportItAsTheAuthority()
    {
        var fields = Http3FieldMapper.BuildRequestFields(
            Request(headers: [new HeaderEntry("Host", ["cdn.example.com:8443"])]),
            null,
            Configuration(),
            out var authority);

        Assert.Equal("cdn.example.com:8443", authority);
        Assert.DoesNotContain(fields, field => field.Name == "host");
    }

    [Fact]
    public void RequestFields_DeriveTheAuthorityFromTheUrlWhenNoHostFieldIsDeclared()
    {
        _ = Http3FieldMapper.BuildRequestFields(
            Request(url: "https://example.com:4433/"),
            null,
            Configuration(),
            out var authority);

        Assert.Equal("example.com:4433", authority);
    }

    [Theory]
    [InlineData("Connection")]
    [InlineData("Proxy-Connection")]
    [InlineData("Keep-Alive")]
    [InlineData("Upgrade")]
    [InlineData("Transfer-Encoding")]
    [InlineData("Proxy-Authorization")]
    public void RequestFields_DropEveryConnectionSpecificField(string name)
    {
        var fields = Http3FieldMapper.BuildRequestFields(
            Request(headers: [new HeaderEntry(name, ["whatever"])]),
            null,
            Configuration(),
            out _);

        Assert.DoesNotContain(
            fields,
            field => string.Equals(
                field.Name,
                name,
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RequestFields_RejectTeWithAnyValueOtherThanTrailers()
    {
        var exception = Assert.Throws<HttpRequestException>(() =>
            Http3FieldMapper.BuildRequestFields(
                Request(headers: [new HeaderEntry("TE", ["gzip"])]),
                null,
                Configuration(),
                out _));

        Assert.Contains("trailers", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RequestFields_KeepTeWithTrailers()
    {
        var fields = Http3FieldMapper.BuildRequestFields(
            Request(headers: [new HeaderEntry("TE", ["trailers"])]),
            null,
            Configuration(),
            out _);

        Assert.Contains("te: trailers", Rendered(fields));
    }

    [Fact]
    public void RequestFields_JoinCookieCrumbsWithTheRfc6265Separator()
    {
        var fields = Http3FieldMapper.BuildRequestFields(
            Request(),
            "a=1; b=2",
            Configuration(),
            out _);

        Assert.Contains("cookie: a=1; b=2", Rendered(fields));
    }

    [Fact]
    public void RequestFields_EmitOneLinePerValueForAnOrdinaryMultiValuedField()
    {
        var fields = Http3FieldMapper.BuildRequestFields(
            Request(headers: [new HeaderEntry("Accept", ["text/html", "application/json"])]),
            null,
            Configuration(),
            out _);

        Assert.Equal(
            2,
            fields.Count(field => field.Name == "accept"));
    }

    [Fact]
    public void RequestFields_HonourTheDeclaredHeaderOrder()
    {
        var request = Request(headers:
        [
            new HeaderEntry("B-Header", ["2"]),
            new HeaderEntry("A-Header", ["1"]),
        ]) with
        {
            HeaderOrder = ["a-header", "b-header"],
        };

        var fields = Http3FieldMapper.BuildRequestFields(
            request,
            null,
            Configuration(),
            out _);

        var names = fields.Select(field => field.Name).ToArray();
        Assert.True(
            Array.IndexOf(names, "a-header") < Array.IndexOf(names, "b-header"),
            $"expected a-header before b-header, got [{string.Join(", ", names)}]");
    }

    [Fact]
    public void RequestFields_RejectAFieldSectionPastTheConfiguredLimit()
    {
        var configuration = Configuration(options => options.MaximumRequestHeaderBytes = 1024);
        var request = Request(headers:
        [
            new HeaderEntry("X-Large", [new string('v', 4096)]),
        ]);

        Assert.Throws<HttpRequestException>(() =>
            Http3FieldMapper.BuildRequestFields(request, null, configuration, out _));
    }

    // ------------------------------------------------------------------------------------
    // Request content: the field section around it, and the trailing field section after it.
    //
    // THE CONTENT-LENGTH AGREEMENT IS THE LOAD-BEARING ONE. TlsQuicHttp3Request.TryEncode
    // refuses the whole request with ContentLengthDisagreesWithBody if any content-length in
    // the field section is not exactly the body's length, and unlike the response rule there
    // is no "defined as never having content" escape. Every field section this mapper builds
    // is paired with Http3Connection.ReadRequestBodyAsync's octets, so the two must agree by
    // construction or no request with content is sendable at all.
    // ------------------------------------------------------------------------------------

    [Fact]
    public void RequestFields_DeclareAContentLengthThatMatchesTheBufferedBody()
    {
        var body = "twenty-four characters!!"u8.ToArray();
        var request = new BufferedRequest(
            "POST", new Uri("https://example.com/upload"), [], body, HasContent: true);

        var fields = Http3FieldMapper.BuildRequestFields(
            request, null, Configuration(), out _);

        Assert.Contains($"content-length: {body.Length}", Rendered(fields));
    }

    [Fact]
    public void RequestFields_DeclareNoContentLengthForARequestWithoutContent()
    {
        var fields = Http3FieldMapper.BuildRequestFields(
            Request(), null, Configuration(), out _);

        Assert.DoesNotContain(
            Rendered(fields), line => line.StartsWith("content-length:", StringComparison.Ordinal));
        Assert.DoesNotContain(
            Rendered(fields), line => line.StartsWith("trailer:", StringComparison.Ordinal));
    }

    /// <summary>
    /// A caller's own Content-Length never survives into the field section — MergeHeaders drops
    /// it and re-derives it — so it cannot contradict the body octets that follow.
    /// </summary>
    [Fact]
    public void RequestFields_ReplaceACallerDeclaredContentLengthWithTheRealOne()
    {
        var body = "four"u8.ToArray();
        var request = new BufferedRequest(
            "POST",
            new Uri("https://example.com/upload"),
            [new HeaderEntry("Content-Length", ["99999"])],
            body,
            HasContent: true);

        var fields = Http3FieldMapper.BuildRequestFields(
            request, null, Configuration(), out _);

        Assert.Contains("content-length: 4", Rendered(fields));
        Assert.DoesNotContain("content-length: 99999", Rendered(fields));
    }

    /// <summary>
    /// A request with trailers has no content-length at all: MergeHeaders reaches for
    /// Transfer-Encoding instead, and section 4.2 forbids that over HTTP/3, so the field
    /// section carries neither. An absent content-length is what section 4.1.2 permits.
    /// </summary>
    [Fact]
    public void RequestFields_CarryNeitherContentLengthNorTransferEncodingWhenTrailersFollow()
    {
        var fields = Http3FieldMapper.BuildRequestFields(
            RequestWithTrailers(), null, Configuration(), out _);

        Assert.DoesNotContain(
            Rendered(fields), line => line.StartsWith("content-length:", StringComparison.Ordinal));
        Assert.DoesNotContain(
            Rendered(fields),
            line => line.StartsWith("transfer-encoding:", StringComparison.Ordinal));
    }

    [Fact]
    public void RequestFields_AnnounceTrailersWhenTheSessionEmitsTheTrailerField()
    {
        var fields = Http3FieldMapper.BuildRequestFields(
            RequestWithTrailers(),
            null,
            Configuration(options => options.Http2.EmitTrailerHeader = true),
            out _);

        Assert.Contains("trailer: Checksum", Rendered(fields));
    }

    [Fact]
    public void RequestFields_OmitTheTrailerFieldWhenTheSessionSuppressesIt()
    {
        var fields = Http3FieldMapper.BuildRequestFields(
            RequestWithTrailers(),
            null,
            Configuration(options => options.Http2.EmitTrailerHeader = false),
            out _);

        Assert.DoesNotContain(
            Rendered(fields), line => line.StartsWith("trailer:", StringComparison.Ordinal));
    }

    [Fact]
    public void TrailerFields_AreEmptyWhenTheRequestDeclaresNone() =>
        Assert.Empty(Http3FieldMapper.BuildTrailerFields(Request(), Configuration()));

    [Fact]
    public void TrailerFields_LowercaseEveryNameAndEmitOneLinePerValue()
    {
        var request = RequestWithTrailers(
            new HeaderEntry("Checksum", ["abc"]),
            new HeaderEntry("X-Seen", ["one", "two"]));

        var trailers = Http3FieldMapper.BuildTrailerFields(request, Configuration());

        Assert.Equal(
            ["checksum: abc", "x-seen: one", "x-seen: two"], Rendered(trailers));
    }

    [Theory]
    [InlineData("Content-Length")]
    [InlineData("Transfer-Encoding")]
    [InlineData("Host")]
    [InlineData("TE")]
    [InlineData("Trailer")]
    [InlineData("Set-Cookie")]
    public void TrailerFields_RejectAFieldThatMayNotBeTrailed(string name) =>
        Assert.Throws<ArgumentException>(() => Http3FieldMapper.BuildTrailerFields(
            RequestWithTrailers(new HeaderEntry(name, ["x"])), Configuration()));

    [Fact]
    public void TrailerFields_RejectAValueCarryingADelimiter() =>
        Assert.ThrowsAny<Exception>(() => Http3FieldMapper.BuildTrailerFields(
            RequestWithTrailers(new HeaderEntry("Checksum", ["a\r\nInjected: 1"])),
            Configuration()));

    [Fact]
    public void TrailerFields_RejectASectionPastTheConfiguredLimit()
    {
        var configuration = Configuration(options => options.MaximumRequestHeaderBytes = 1024);
        var request = RequestWithTrailers(
            new HeaderEntry("Checksum", [new string('v', 4096)]));

        Assert.Throws<HttpRequestException>(() =>
            Http3FieldMapper.BuildTrailerFields(request, configuration));
    }

    /// <summary>
    /// Not filtered here on purpose: <c>TlsQuicHttp3Request.TryEncode</c> refuses the request
    /// with <c>PseudoHeaderInTrailerSection</c>, and dropping the field instead would send a
    /// trailer section the caller did not write. Pinned so a later "tidy-up" that swallows it
    /// fails rather than passes.
    /// </summary>
    [Fact]
    public void TrailerFields_LeaveAPseudoHeaderForSharpTlsToRefuse()
    {
        var trailers = Http3FieldMapper.BuildTrailerFields(
            RequestWithTrailers(new HeaderEntry(":status", ["200"])), Configuration());

        Assert.Equal([":status: 200"], Rendered(trailers));
    }

    private static BufferedRequest RequestWithTrailers(params HeaderEntry[] trailers) =>
        new(
            "POST",
            new Uri("https://example.com/upload"),
            [],
            "body"u8.ToArray(),
            HasContent: true)
        {
            Trailers = trailers.Length == 0
                ? [new HeaderEntry("Checksum", ["abc"])]
                : trailers,
        };

    [Fact]
    public void ResponseHeaders_ExcludeThePseudoHeaderSection()
    {
        var bytes = 0;
        var headers = Http3FieldMapper.BuildHeaders(
            [
                new TlsQuicHttp3Field(":status", "200"),
                new TlsQuicHttp3Field("content-type", "application/json"),
            ],
            maximumBytes: 8192,
            maximumCount: 64,
            ref bytes);

        // Not headers.Contains(":status"): TlsHeaders rejects a name that is not a token at
        // all, so asking it that question throws rather than answering false. Enumerating is
        // the only way to state "no pseudo-header survived" without asserting on the throw.
        Assert.DoesNotContain(
            headers.Select(header => header.Key),
            name => name.StartsWith(':'));
        Assert.Equal(1, headers.Count);
        Assert.Equal("application/json", headers["content-type"]);
    }

    [Fact]
    public void ResponseHeaders_TrimSurroundingWhitespaceRatherThanRejectingIt()
    {
        var bytes = 0;
        var headers = Http3FieldMapper.BuildHeaders(
            [new TlsQuicHttp3Field("server", "  nginx \t")],
            maximumBytes: 8192,
            maximumCount: 64,
            ref bytes);

        Assert.Equal("nginx", headers["server"]);
    }

    [Fact]
    public void ResponseHeaders_KeepEveryValueOfARepeatedField()
    {
        var bytes = 0;
        var headers = Http3FieldMapper.BuildHeaders(
            [
                new TlsQuicHttp3Field("set-cookie", "a=1"),
                new TlsQuicHttp3Field("set-cookie", "b=2"),
            ],
            maximumBytes: 8192,
            maximumCount: 64,
            ref bytes);

        Assert.True(headers.TryGetValues("set-cookie", out var values));
        Assert.Equal(["a=1", "b=2"], values);
    }

    [Theory]
    [InlineData("Content-Type")]
    [InlineData("content type")]
    [InlineData("contenttype")]
    [InlineData("content:type")]
    [InlineData("")]
    public void ResponseHeaders_RejectAProhibitedFieldName(string name)
    {
        Assert.Throws<TlsHttpProtocolException>(() =>
        {
            var consumed = 0;
            _ = Http3FieldMapper.BuildHeaders(
                [new TlsQuicHttp3Field(name, "value")],
                maximumBytes: 8192,
                maximumCount: 64,
                ref consumed);
        });
    }

    [Theory]
    [InlineData("va\rlue")]
    [InlineData("va\nlue")]
    [InlineData("va\0lue")]
    public void ResponseHeaders_RejectADelimiterInjectedIntoAValue(string value)
    {
        Assert.Throws<TlsHttpProtocolException>(() =>
        {
            var consumed = 0;
            _ = Http3FieldMapper.BuildHeaders(
                [new TlsQuicHttp3Field("x-test", value)],
                maximumBytes: 8192,
                maximumCount: 64,
                ref consumed);
        });
    }

    [Fact]
    public void ResponseHeaders_RejectMoreFieldsThanConfigured()
    {
        Assert.Throws<TlsHttpProtocolException>(() =>
        {
            var consumed = 0;
            _ = Http3FieldMapper.BuildHeaders(
                [
                    new TlsQuicHttp3Field("a", "1"),
                    new TlsQuicHttp3Field("b", "2"),
                ],
                maximumBytes: 8192,
                maximumCount: 1,
                ref consumed);
        });
    }

    [Fact]
    public void ResponseHeaders_CountBytesAcrossTheHeaderAndTrailerSectionsTogether()
    {
        var consumed = 0;
        _ = Http3FieldMapper.BuildHeaders(
            [new TlsQuicHttp3Field("x-first", "0123456789")],
            maximumBytes: 32,
            maximumCount: 64,
            ref consumed);

        // The second section starts from the first's total, so a response cannot spend the
        // whole budget twice by splitting its fields across a trailer section.
        Assert.Throws<TlsHttpProtocolException>(() =>
        {
            var running = consumed;
            _ = Http3FieldMapper.BuildHeaders(
                [new TlsQuicHttp3Field("x-second", "0123456789")],
                maximumBytes: 32,
                maximumCount: 64,
                ref running);
        });
    }

    [Theory]
    [InlineData(99)]
    [InlineData(-1)]
    [InlineData(1000)]
    public void ReadStatus_RejectsAnythingOutsideTheThreeDigitRange(int status) =>
        Assert.Throws<TlsHttpProtocolException>(() => Http3FieldMapper.ReadStatus(status));

    [Fact]
    public void ReadStatus_AcceptsAThreeDigitStatus() =>
        Assert.Equal(HttpStatusCode.OK, Http3FieldMapper.ReadStatus(200));

    [Theory]
    [InlineData("GET", 200, true)]
    [InlineData("HEAD", 200, false)]
    [InlineData("GET", 204, false)]
    [InlineData("GET", 304, false)]
    [InlineData("GET", 103, false)]
    public void HasResponseBody_FollowsRfc9110(string method, int status, bool expected) =>
        Assert.Equal(
            expected,
            Http3FieldMapper.HasResponseBody(method, (HttpStatusCode)status));

    [Fact]
    public void ValidateContentLength_AcceptsAgreement()
    {
        var headers = new TlsHeaders();
        headers.Set("Content-Length", "5");

        Http3FieldMapper.ValidateContentLength(headers, "GET", 5);
    }

    [Fact]
    public void ValidateContentLength_RejectsDisagreement()
    {
        var headers = new TlsHeaders();
        headers.Set("Content-Length", "5");

        Assert.Throws<TlsHttpProtocolException>(() =>
            Http3FieldMapper.ValidateContentLength(headers, "GET", 4));
    }

    [Fact]
    public void ValidateContentLength_LeavesAHeadResponseAlone()
    {
        var headers = new TlsHeaders();
        headers.Set("Content-Length", "1024");

        Http3FieldMapper.ValidateContentLength(headers, "HEAD", 0);
    }

    [Fact]
    public void ValidateContentLength_RejectsARepeatedField()
    {
        var headers = new TlsHeaders();
        headers.Add("Content-Length", "5");
        headers.Add("Content-Length", "6");

        Assert.Throws<TlsHttpProtocolException>(() =>
            Http3FieldMapper.ValidateContentLength(headers, "GET", 5));
    }
}
