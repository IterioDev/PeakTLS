namespace TlsClient.Tests;

using System.Net.Http.Headers;
using System.Text;

/// <summary>
/// What actually reaches the wire when a caller builds an <see cref="HttpRequestMessage"/> and
/// sets no header order. Written because the samples asserted this in prose and three of the
/// four claims turned out to be wrong: Host is synthesised, content fields cannot be placed by
/// insertion, and deriving an order from <c>request.Headers</c> is not a no-op.
/// </summary>
public sealed class InsertionOrderHeaderTests
{
    private static async Task<string[]> WireOrderAsync(HttpRequestMessage request, string[] order)
    {
        var buffered = await BufferedRequest.CreateAsync(
            request, maximumBodyBytes: 4096, TlsHttpVersionPolicy.PreferHttp2, CancellationToken.None);
        var merged = Http11RequestWriter.MergeHeaders(buffered, cookieHeader: null);
        return [.. Http11RequestWriter.Order(merged, order).Select(h => h.Name.ToLowerInvariant())];
    }

    private static async Task<List<HeaderEntry>> WireAsync(HttpRequestMessage request)
    {
        var buffered = await BufferedRequest.CreateAsync(
            request, maximumBodyBytes: 4096, TlsHttpVersionPolicy.PreferHttp2, CancellationToken.None);
        return Http11RequestWriter.MergeHeaders(buffered, cookieHeader: null);
    }

    [Fact]
    public async Task TheComputedLengthLandsInTheSlotTheCallerNamed()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/")
        {
            Content = new ReadOnlyMemoryContent(Encoding.UTF8.GetBytes("body")),
        };
        request.AddHeader("host", "example.com");
        request.AddHeader("content-type", "application/x-protobuf");
        request.AddHeader("accept", "*/*");
        request.AddHeader("content-length", "-1");
        request.AddHeader("user-agent", "agent");

        // The captured POST puts content-type first and content-length mid-block. The value
        // added there is a placeholder — only the position survives.
        var wire = await WireAsync(request);
        Assert.Equal(
            ["host", "content-type", "accept", "content-length", "user-agent"],
            wire.Select(header => header.Name.ToLowerInvariant()));
        Assert.Equal(
            ["4"],
            wire.Single(header =>
                header.Name.Equals("content-length", StringComparison.OrdinalIgnoreCase)).Values);
    }

    [Fact]
    public async Task NothingTheCallerDidNotAddReachesTheWire()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/")
        {
            Content = new StringContent("body", Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation("x-ignored", "1");
        request.AddHeader("content-type", "application/json");
        request.AddHeader("content-length", "-1");

        // No Host, no Connection, no Cookie, no x-ignored — and StringContent's own
        // "application/json; charset=utf-8" never appears, only the caller's exact bytes.
        var wire = await WireAsync(request);
        Assert.Equal(
            ["content-type", "content-length"],
            wire.Select(header => header.Name.ToLowerInvariant()));
        Assert.Equal(["application/json"], wire[0].Values);
    }

    [Fact]
    public async Task ABodyWithNoFramingNameThrows()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/")
        {
            Content = new ReadOnlyMemoryContent(Encoding.UTF8.GetBytes("body")),
        };
        request.AddHeader("accept", "*/*");

        await Assert.ThrowsAsync<InvalidOperationException>(() => WireAsync(request));
    }

    [Fact]
    public async Task NamingTransferEncodingForcesChunkedEvenWhenTheLengthIsKnown()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/")
        {
            Content = new ReadOnlyMemoryContent(Encoding.UTF8.GetBytes("body")),
        };
        request.AddHeader("host", "example.com");
        request.AddHeader("transfer-encoding", "chunked");
        request.AddHeader("accept", "*/*");

        var wire = await WireAsync(request);
        Assert.Equal(
            ["host", "transfer-encoding", "accept"],
            wire.Select(header => header.Name.ToLowerInvariant()));
        Assert.Equal(["chunked"], wire[1].Values);
    }

    [Fact]
    public async Task WithNoHeaderOrderTheCallersInsertionOrderSurvivesBehindASynthesisedHost()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        request.Headers.TryAddWithoutValidation("x-client-id", "id");
        request.Headers.TryAddWithoutValidation("accept-encoding", "gzip");
        request.Headers.TryAddWithoutValidation("user-agent", "agent");

        // Host is generated, not added, and leads. Over HTTP/3 it never reaches the wire under
        // that name — Http3FieldMapper drops it and emits :authority — so for an h3-only preset
        // the caller's own fields are the whole field section, in the order they were added.
        Assert.Equal(
            ["host", "accept", "x-client-id", "accept-encoding", "user-agent"],
            await WireOrderAsync(request, []));
    }

    [Fact]
    public async Task DerivingTheOrderFromRequestHeadersDisplacesHost()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        request.Headers.TryAddWithoutValidation("x-client-id", "id");
        request.Headers.TryAddWithoutValidation("user-agent", "agent");

        // HeaderOrder = req.Headers.Select(h => h.Key).ToArray() cannot name Host, because Host
        // is not in that collection — and Order() appends whatever the array does not name. So
        // the idiom is NOT a no-op over HTTP/1.1: it moves Host from first to last. Over HTTP/3
        // it is harmless only because Host is dropped there anyway.
        var derived = request.Headers.Select(h => h.Key).ToArray();
        Assert.Equal(
            ["accept", "x-client-id", "user-agent", "host"],
            await WireOrderAsync(request, derived));
    }

    [Fact]
    public async Task ContentFieldsCannotBePlacedByInsertionAndLandLast()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/")
        {
            Content = new ReadOnlyMemoryContent(Encoding.UTF8.GetBytes("body")),
        };

        // Both placeholders are attempted FIRST and neither takes. HttpRequestHeaders rejects
        // known content headers, so TryAddWithoutValidation is a silent no-op for these two
        // names and the real values arrive later from Content.Headers, which is appended after
        // request.Headers. Reserving a slot this way works only when the entries are built
        // directly; through HttpRequestMessage it cannot.
        request.Headers.TryAddWithoutValidation("content-type", "placeholder");
        request.Headers.TryAddWithoutValidation("content-length", "-1");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        request.Headers.TryAddWithoutValidation("user-agent", "agent");
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-protobuf");

        var wire = await WireOrderAsync(request, []);
        Assert.Equal(["host", "accept", "user-agent", "content-type", "content-length"], wire);
    }

    [Fact]
    public async Task NamingTheContentFieldsInHeaderOrderIsWhatPlacesThem()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/")
        {
            Content = new ReadOnlyMemoryContent(Encoding.UTF8.GetBytes("body")),
        };
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        request.Headers.TryAddWithoutValidation("user-agent", "agent");
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-protobuf");

        // The captured POST image puts content-type first and content-length mid-block. An
        // explicit order is the ONLY way to reach it from an HttpRequestMessage.
        // Host is named LAST here on purpose: over HTTP/3 it is dropped and becomes :authority,
        // so parking it at the end keeps the h3 field section exactly the captured image.
        Assert.Equal(
            ["content-type", "accept", "content-length", "user-agent", "host"],
            await WireOrderAsync(
                request,
                ["content-type", "accept", "content-length", "user-agent", "host"]));
    }
}
