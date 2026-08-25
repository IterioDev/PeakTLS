using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

/// <summary>
/// Proves how a header with several values, and a cookie in particular, is split across
/// HTTP/2 fields. Both directions of that axis are real: stacks differ on whether they
/// join values into one field and on whether they crumble a cookie into several.
/// </summary>
public sealed class Http2HeaderFieldPolicyTests
{
    [Fact]
    public async Task CrumbleCookies_EmitsOneFieldPerCrumbInOrder()
    {
        var options = CreateOptions();
        options.Http2.Hpack.CrumbleCookies = true;

        var fields = await CaptureRequestFieldsAsync(options, new HeaderEntry("cookie", ["a=1; b=2; c=3"]));

        Assert.Equal(
            ["a=1", "b=2", "c=3"],
            fields.Where(field => field.Name == "cookie").Select(field => field.Value));
    }

    [Fact]
    public async Task CrumbleCookies_ReassemblesToTheOriginalCookie()
    {
        var options = CreateOptions();
        options.Http2.Hpack.CrumbleCookies = true;

        var fields = await CaptureRequestFieldsAsync(options, new HeaderEntry("cookie", ["a=1; b=2; c=3"]));

        // RFC 9113 section 8.2.3 has the server join the crumbs with "; " to recover the
        // single header field an origin sees.
        var reassembled = string.Join(
            "; ",
            fields.Where(field => field.Name == "cookie").Select(field => field.Value));
        Assert.Equal("a=1; b=2; c=3", reassembled);
    }

    [Fact]
    public async Task CrumbleCookiesOff_LeavesTheCookieAsOneField()
    {
        var options = CreateOptions();

        var fields = await CaptureRequestFieldsAsync(options, new HeaderEntry("cookie", ["a=1; b=2; c=3"]));

        Assert.Equal(
            ["a=1; b=2; c=3"],
            fields.Where(field => field.Name == "cookie").Select(field => field.Value));
    }

    [Fact]
    public async Task MultiValueSeparateFields_EmitsOneFieldPerValue()
    {
        var options = CreateOptions();

        var fields = await CaptureRequestFieldsAsync(options, new HeaderEntry("x-multi", ["one", "two"]));

        Assert.Equal(
            ["one", "two"],
            fields.Where(field => field.Name == "x-multi").Select(field => field.Value));
    }

    [Fact]
    public async Task MultiValueJoin_EmitsOneFieldWithTheDeclaredSeparator()
    {
        var options = CreateOptions();
        options.Http2.Hpack.MultiValue = TlsHpackMultiValue.Join;
        options.Http2.Hpack.MultiValueJoinSeparator = ", ";

        var fields = await CaptureRequestFieldsAsync(options, new HeaderEntry("x-multi", ["one", "two"]));

        Assert.Equal(
            ["one, two"],
            fields.Where(field => field.Name == "x-multi").Select(field => field.Value));
    }

    [Fact]
    public async Task MultiValueJoin_UsesTheCookieSeparatorForCookies()
    {
        // cookie is not a comma-separated list field. RFC 6265 section 5.4 joins crumbs
        // with "; ", so a joined cookie must not pick up MultiValueJoinSeparator.
        var options = CreateOptions();
        options.Http2.Hpack.MultiValue = TlsHpackMultiValue.Join;
        options.Http2.Hpack.MultiValueJoinSeparator = ", ";

        var fields = await CaptureRequestFieldsAsync(options, new HeaderEntry("cookie", ["a=1", "b=2"]));

        Assert.Equal(
            ["a=1; b=2"],
            fields.Where(field => field.Name == "cookie").Select(field => field.Value));
    }

    [Fact]
    public async Task PerHeaderMultiValue_OverridesTheGlobalPolicy()
    {
        var options = CreateOptions();
        options.Http2.Hpack.MultiValue = TlsHpackMultiValue.Join;
        options.Http2.Hpack.PerHeaderMultiValue["x-other"] = TlsHpackMultiValue.SeparateFields;

        var fields = await CaptureRequestFieldsAsync(options, new HeaderEntry("x-multi", ["one", "two"]), new HeaderEntry("x-other", ["three", "four"]));

        Assert.Equal(
            ["one, two"],
            fields.Where(field => field.Name == "x-multi").Select(field => field.Value));
        Assert.Equal(
            ["three", "four"],
            fields.Where(field => field.Name == "x-other").Select(field => field.Value));
    }

    private static TlsSessionOptions CreateOptions() =>
        new() { Profile = TlsProfiles.Modern };

    /// <summary>
    /// Drives one request over the loopback harness and decodes the header block the
    /// client actually put on the wire.
    /// </summary>
    private static async Task<IReadOnlyList<HpackHeader>> CaptureRequestFieldsAsync(
        TlsSessionOptions options,
        params HeaderEntry[] requestHeaders)
    {
        var block = Array.Empty<byte>();

        var result = await Http2WireCapture.RunAsync(
            options,
            (session, url, cancellationToken) =>
            {
                // Headers ride on the request now: a session carries none of its own.
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                foreach (var header in requestHeaders)
                {
                    foreach (var value in header.Values)
                    {
                        request.AddHeader(header.Name, value);
                    }
                }
                return session.SendAsync(request, cancellationToken);
            },
            async (server, cancellationToken) =>
            {
                _ = await server.ReadPrefaceAsync(cancellationToken);
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
                block = [.. payload];

                // 0x88 is the static-table entry for ":status: 200".
                await server.WriteFrameAsync(
                    Http2FrameType.Headers,
                    Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                    headers.StreamId,
                    [0x88],
                    cancellationToken);
                await server.FlushAsync(cancellationToken);
            });

        Assert.Equal(System.Net.HttpStatusCode.OK, result.Response.StatusCode);
        return new HpackDecoder(4096).Decode(block, 16 * 1024);
    }
}
