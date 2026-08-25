namespace TlsClient.Tests;

using System.Text;

/// <summary>
/// The one rule, proved at the wire: a field reaches it if and only if <c>AddHeader</c> added
/// it, in the order it was added. One exception, and it covers the value only — the framing
/// field's computed value replaces the placeholder in the slot the caller named for it.
/// <para>This file used to document the opposite: that Host was synthesised, that content fields
/// could not be placed by insertion, and that deriving an order from <c>request.Headers</c> was
/// not a no-op. All three were consequences of routing fields through
/// <see cref="System.Net.Http.Headers.HttpRequestHeaders"/>, and none of them survive now that
/// nothing does.</para>
/// </summary>
public sealed class InsertionOrderHeaderTests
{
    private static async Task<List<HeaderEntry>> WireAsync(HttpRequestMessage request)
    {
        var buffered = await BufferedRequest.CreateAsync(
            request, maximumBodyBytes: 4096, TlsHttpVersionPolicy.PreferHttp2, CancellationToken.None);
        return Http11RequestWriter.MergeHeaders(buffered);
    }

    private static IEnumerable<string> Names(IEnumerable<HeaderEntry> wire) =>
        wire.Select(header => header.Name.ToLowerInvariant());

    [Fact]
    public async Task AGetsFieldSectionIsTheAddHeaderSequenceAndNothingElse()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeader("host", "example.com");
        request.AddHeader("accept", "*/*");
        request.AddHeader("x-client-id", "id");
        request.AddHeader("user-agent", "agent");

        Assert.Equal(
            ["host", "accept", "x-client-id", "user-agent"],
            Names(await WireAsync(request)));
    }

    /// <summary>
    /// Host is not generated. Over HTTP/1.1 that makes the request malformed by RFC 9112
    /// section 3.2, which is the caller's to fix by adding one; over HTTP/2 and HTTP/3 it costs
    /// nothing, because the field is dropped there anyway and <c>:authority</c> carries the
    /// value.
    /// </summary>
    [Fact]
    public async Task AnUnaddedHostIsSimplyAbsent()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeader("accept", "*/*");

        Assert.Equal(["accept"], Names(await WireAsync(request)));
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
            Names(wire));
        Assert.Equal(
            ["4"],
            wire.Single(header =>
                header.Name.Equals("content-length", StringComparison.OrdinalIgnoreCase)).Values);
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
        Assert.Equal(["host", "transfer-encoding", "accept"], Names(wire));
        Assert.Equal(["chunked"], wire[1].Values);
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
        Assert.Equal(["content-type", "content-length"], Names(wire));
        Assert.Equal(["application/json"], wire[0].Values);
    }

    /// <summary>
    /// The reflow regression guard. Through <c>HttpRequestHeaders</c> this value becomes three
    /// stored values and three field lines, and the separators differ per field — a comma for
    /// Accept-Encoding, a space for User-Agent — so no rejoin reproduces the bytes afterwards.
    /// The only fix is not to lose them, which is what bypassing that collection buys.
    /// </summary>
    [Fact]
    public async Task AMultiTokenValueStaysOneFieldLineCarryingItsExactBytes()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeader("accept-encoding", "gzip, deflate, br");
        request.AddHeader("accept-language", "en-US,en;q=0.9");

        var wire = await WireAsync(request);
        Assert.Equal(["gzip, deflate, br"], wire[0].Values);
        Assert.Equal(["en-US,en;q=0.9"], wire[1].Values);
    }

    /// <summary>
    /// The one filter that survives. It used to guard session headers; with those gone the
    /// credentials it protects are the caller's own, and a cross-origin redirect must still not
    /// carry them to the new host.
    /// </summary>
    [Fact]
    public async Task ACrossOriginRedirectStillDropsAuthorizationAndCookie()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://first.example/");
        request.AddHeader("host", "first.example");
        request.AddHeader("authorization", "Bearer secret");
        request.AddHeader("cookie", "sid=secret");
        request.AddHeader("accept", "*/*");

        var buffered = await BufferedRequest.CreateAsync(
            request, maximumBodyBytes: 4096, TlsHttpVersionPolicy.PreferHttp2, CancellationToken.None);
        var redirected = buffered.Redirect(
            new Uri("https://second.example/"), "GET", dropBody: false, originChanged: true);

        Assert.Equal(["accept"], Names(Http11RequestWriter.MergeHeaders(redirected)));
    }
}
