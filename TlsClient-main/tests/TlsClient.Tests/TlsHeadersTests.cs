namespace TlsClient.Tests;

public sealed class TlsHeadersTests
{
    [Fact]
    public void Set_IsCaseInsensitiveAndPreservesPosition()
    {
        var headers = new TlsHeaders();
        headers.Set("User-Agent", "first");
        headers.Set("Accept", "*/*");
        headers.Set("user-agent", "second");

        Assert.Equal(2, headers.Count);
        Assert.Equal("second", headers["USER-AGENT"]);
        Assert.Equal(["user-agent", "Accept"], headers.Select(header => header.Key));
    }

    [Fact]
    public void Add_PreservesMultipleValues()
    {
        var headers = new TlsHeaders();
        headers.Add("Accept", "text/html");
        headers.Add("Accept", "application/json");

        Assert.True(headers.TryGetValues("accept", out var values));
        Assert.Equal(["text/html", "application/json"], values);
    }

    [Theory]
    [InlineData("Bad Header", "value")]
    [InlineData("Good", "one\r\nInjected: yes")]
    public void Set_RejectsHeaderInjection(string name, string value)
    {
        var headers = new TlsHeaders();

        Assert.Throws<ArgumentException>(() => headers.Set(name, value));
    }

    /// <summary>
    /// RFC 9110 section 5.5: "A field value does not include leading or trailing whitespace."
    /// Rejected rather than trimmed: this client reproduces what a caller declares byte for
    /// byte, so quietly rewriting a value would be the wrong kind of help — and no mainstream
    /// client emits a padded field value, which makes one on the wire a distinguisher.
    /// </summary>
    [Theory]
    [InlineData(" bar")]
    [InlineData("bar ")]
    [InlineData("\tbar")]
    [InlineData("bar\t")]
    [InlineData(" ")]
    public void Set_RejectsAValuePaddedWithSpaceOrTab(string value)
    {
        var headers = new TlsHeaders();

        Assert.Throws<ArgumentException>(() => headers.Set("X-Foo", value));
    }

    [Theory]
    [InlineData("")]
    [InlineData("one two")]
    public void Set_KeepsWhitespaceThatIsNotAtAnEnd(string value)
    {
        var headers = new TlsHeaders();
        headers.Set("X-Foo", value);

        Assert.Equal(value, headers["x-foo"]);
    }
}
