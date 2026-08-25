namespace TlsClient.Tests;

/// <summary>
/// The one rule: a field reaches the wire if and only if <c>AddHeader</c> added it, in the
/// order it was added. These cover the entry point itself; the wire image it produces is
/// <see cref="InsertionOrderHeaderTests"/>.
/// </summary>
public sealed class AddHeaderTests
{
    [Fact]
    public void AddHeaderRecordsNamesInInsertionOrderOnTheRequestsOptions()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeader("accept", "*/*");
        request.AddHeader("user-agent", "agent");

        var headers = TlsRequestOptions.For(request).Headers;
        Assert.Equal(["accept", "user-agent"], headers.Select(header => header.Key));
    }

    [Fact]
    public void AddHeaderKeepsAValueVerbatimRatherThanReflowingIt()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeader("accept-encoding", "gzip, deflate, br");

        // Through HttpRequestHeaders this becomes three stored values and three field lines,
        // and no rejoin reproduces the bytes afterwards. Nothing passes through it any more.
        Assert.True(
            TlsRequestOptions.For(request).Headers.TryGetValues("accept-encoding", out var values));
        Assert.Equal(["gzip, deflate, br"], values);
    }

    [Fact]
    public void AddingTheSameNameTwiceAppendsAValueAtTheNamesFirstPosition()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeader("a", "1");
        request.AddHeader("b", "2");
        request.AddHeader("a", "3");

        // The known ceiling: a repeated name does not take a second position, it adds a value
        // at the first one. No captured client interleaves duplicates.
        var headers = TlsRequestOptions.For(request).Headers;
        Assert.Equal(["a", "b"], headers.Select(header => header.Key));
        Assert.True(headers.TryGetValues("a", out var values));
        Assert.Equal(["1", "3"], values);
    }

    [Fact]
    public async Task TheBufferedFieldSectionIsTheAddHeaderSequence()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeader("host", "example.com");
        request.AddHeader("accept", "*/*");
        request.AddHeader("user-agent", "agent");

        var buffered = await BufferedRequest.CreateAsync(
            request,
            maximumBodyBytes: 4096,
            TlsHttpVersionPolicy.PreferHttp2,
            CancellationToken.None);

        Assert.Equal(
            ["host", "accept", "user-agent"],
            buffered.Headers.Select(header => header.Name.ToLowerInvariant()));
    }

    [Fact]
    public void AddHeaderRejectsANameThatIsNotAToken() =>
        Assert.Throws<ArgumentException>(() =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
            request.AddHeader("bad name", "value");
        });
}
