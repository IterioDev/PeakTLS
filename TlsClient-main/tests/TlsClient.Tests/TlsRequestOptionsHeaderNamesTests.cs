namespace TlsClient.Tests;

/// <content>
/// TlsRequestOptions.HeaderNamesOf, and the .NET behaviour it exists to avoid.
///
/// A CALLER WROTE `request.Headers.Select(header => header.Key)` TO ORDER HEADERS BY NAME and
/// their fingerprint changed: accept-encoding went out as three field lines, user-agent as
/// three, accept-language as two. Reading the validated view parses every known structured
/// header and replaces the caller's string with the parsed parts, so the damage is done before
/// this library ever sees the request.
/// </content>
public sealed class TlsRequestOptionsHeaderNamesTests
{
    // .NET CANONICALISES THE CASING OF KNOWN HEADER NAMES, so what comes back is
    // "Accept-Encoding" even though "accept-encoding" went in. It does not matter on the wire
    // here - RFC 9114 s4.2 requires field names to be lowercase in HTTP/3 and the encoder
    // lowercases them - and HeaderOrder matches names case-insensitively. Pinned so the
    // difference is a stated fact rather than a surprise to the next reader.
    private static readonly string[] ExpectedNames =
        ["Accept", "Accept-Encoding", "User-Agent", "Accept-Language"];

    private static readonly string[] WrittenAcceptEncoding = ["gzip, deflate, br"];

    private static readonly string[] WrittenUserAgent = ["Spotify/9.1.76 iOS/27.0 (iPhone17,2)"];

    private static readonly string[] WrittenAcceptLanguage = ["en-US,en;q=0.9"];

    private static readonly string[] SplitAcceptEncoding = ["gzip", "deflate", "br"];

    private static readonly string[] SplitUserAgent =
        ["Spotify/9.1.76", "iOS/27.0", "(iPhone17,2)"];

    private static readonly string[] SplitAcceptLanguage = ["en-US", "en; q=0.9"];

    private static HttpRequestMessage Request()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://example.test/");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        request.Headers.TryAddWithoutValidation("accept-encoding", "gzip, deflate, br");
        request.Headers.TryAddWithoutValidation("user-agent", "Spotify/9.1.76 iOS/27.0 (iPhone17,2)");
        request.Headers.TryAddWithoutValidation("accept-language", "en-US,en;q=0.9");
        return request;
    }

    private static string[] ValuesOf(HttpRequestMessage request, string name) =>
        request.Headers.NonValidated.TryGetValues(name, out var values)
            ? [.. values]
            : [];

    [Fact]
    public void TakingTheNamesLeavesEveryValueExactlyAsItWasWritten()
    {
        var request = Request();

        var names = TlsRequestOptions.HeaderNamesOf(request);

        Assert.Equal(ExpectedNames, names);

        // THE POINT OF THE HELPER. One value each, byte for byte, including the comma with no
        // space after it in accept-language - which the validated view reflows.
        Assert.Equal(WrittenAcceptEncoding, ValuesOf(request, "accept-encoding"));
        Assert.Equal(WrittenUserAgent, ValuesOf(request, "user-agent"));
        Assert.Equal(WrittenAcceptLanguage, ValuesOf(request, "accept-language"));
    }

    [Fact]
    public void TheValidatedViewIsWhatSplitsThem()
    {
        // NOT A TEST OF THIS LIBRARY - a test of the premise the helper is built on. If .NET
        // ever stops doing this, the helper stops being necessary and this fails, which is the
        // signal to revisit it rather than to keep carrying an explanation nobody can check.
        var request = Request();

        _ = request.Headers.Select(header => header.Key).ToArray();

        Assert.Equal(SplitAcceptEncoding, ValuesOf(request, "accept-encoding"));
        Assert.Equal(SplitUserAgent, ValuesOf(request, "user-agent"));

        // ...and the reflow that makes a rejoin unable to reproduce the original bytes.
        Assert.Equal(SplitAcceptLanguage, ValuesOf(request, "accept-language"));
    }

    [Fact]
    public void ContentHeadersFollowTheRequestsOwnAndDuplicatesAreListedOnce()
    {
        var request = Request();
        request.Content = new StringContent("{}");
        request.Content.Headers.TryAddWithoutValidation("content-language", "en");

        var names = TlsRequestOptions.HeaderNamesOf(request);

        // HeaderOrder requires distinct names, so a name on both collections is listed once.
        Assert.Equal(names.Length, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Contains("content-language", names, StringComparer.OrdinalIgnoreCase);
        Assert.True(
            Array.IndexOf(names, "accept") < names.Length - 1,
            "the request's own headers come first");
    }

    [Fact]
    public void TheNamesAreAcceptedByHeaderOrderValidation()
    {
        // The whole point is that this array can be handed straight to HeaderOrder, which
        // rejects duplicates and blanks.
        var request = Request();
        TlsRequestOptions.For(request).HeaderOrder = TlsRequestOptions.HeaderNamesOf(request);

        var snapshot = new TlsSessionOptions().Snapshot();
        Assert.NotNull(snapshot);
        Assert.Equal(4, TlsRequestOptions.For(request).HeaderOrder!.Count);
    }
}
