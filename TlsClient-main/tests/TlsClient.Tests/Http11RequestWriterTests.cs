using System.Text;

namespace TlsClient.Tests;

public sealed class Http11RequestWriterTests
{
    /// <summary>
    /// The field section is the caller's list, in the caller's order, and nothing else: no
    /// synthesised Host, no injected Cookie, no generated Connection. Only the Content-Length
    /// VALUE is the writer's, and it lands in the slot the caller reserved for it.
    /// </summary>
    [Fact]
    public void SerializeHeaders_UsesOriginFormAndTheCallersOwnFieldSection()
    {
        var request = new BufferedRequest(
            "POST",
            new Uri("https://example.com:8443/a%20b?q=1#ignored"),
            [
                new HeaderEntry("Host", ["example.com:8443"]),
                new HeaderEntry("X-Test", ["request"]),
                new HeaderEntry("Content-Length", ["-1"]),
                new HeaderEntry("Accept", ["*/*"]),
                new HeaderEntry("Cookie", ["sid=abc"]),
            ],
            [1, 2, 3],
            HasContent: true);

        var text = Encoding.Latin1.GetString(Http11RequestWriter.SerializeHeaders(request));

        Assert.Equal(
            "POST /a%20b?q=1 HTTP/1.1\r\n" +
            "Host: example.com:8443\r\n" +
            "X-Test: request\r\n" +
            "Content-Length: 3\r\n" +
            "Accept: */*\r\n" +
            "Cookie: sid=abc\r\n" +
            "\r\n",
            text);
        Assert.DoesNotContain("ignored", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Redirect_StripsOriginBoundHeadersWhenOriginChanges()
    {
        var request = new BufferedRequest(
            "GET",
            new Uri("https://first.example/"),
            [
                new HeaderEntry("Authorization", ["Bearer secret"]),
                new HeaderEntry("Cookie", ["sid=secret"]),
                new HeaderEntry("Host", ["first.example"]),
                new HeaderEntry("Accept", ["*/*"]),
            ],
            [],
            HasContent: false);

        var redirected = request.Redirect(
            new Uri("https://second.example/"),
            "GET",
            dropBody: false,
            originChanged: true);

        Assert.Equal(["Accept"], redirected.Headers.Select(header => header.Name));
    }

    /// <summary>
    /// RFC 9113 section 8.5 defines a plain CONNECT's <c>:authority</c> as "the host and port
    /// to connect to (equivalent to the authority-form of the request-target of CONNECT
    /// requests; see Section 3.2.3 of [HTTP/1.1])", and RFC 9112 section 3.2.3 gives that form
    /// as "authority-form = uri-host ':' port" — no default to fall back on.
    /// Nothing synthesises a Host field any more, so this is the <c>:authority</c> fallback
    /// <c>Http2Connection.BuildRequestHeaders</c> and <c>Http3FieldMapper</c> use when the
    /// request added no Host of its own. The port has to survive here or the CONNECT reaches
    /// the wire malformed.
    /// </summary>
    [Fact]
    public void PlainConnect_ConveysAnAuthorityCarryingTheDefaultPort()
    {
        var authority = Authority("CONNECT", "https://example.com/", protocol: null);

        Assert.Equal("example.com:443", authority);
    }

    /// <summary>
    /// A CONNECT to an explicit port keeps it, as every method does.
    /// </summary>
    [Fact]
    public void PlainConnect_KeepsANonDefaultPort()
    {
        var authority = Authority("CONNECT", "https://example.com:8443/", protocol: null);

        Assert.Equal("example.com:8443", authority);
    }

    /// <summary>
    /// RFC 8441 section 4: "On requests bearing the :protocol pseudo-header field, the
    /// :authority pseudo-header field is interpreted according to Section 8.1.2.3 of [RFC7540]"
    /// — RFC 9113 section 8.3.1 — "instead of Section 8.3 of that document", so extended
    /// CONNECT elides a default port exactly as an ordinary method does. Both are asserted
    /// together because they are the same rule: only a plain CONNECT departs from it.
    /// </summary>
    [Fact]
    public void ExtendedConnectAndOrdinaryMethods_ConveyAnAuthorityWithoutADefaultPort()
    {
        Assert.Equal(
            "example.com",
            Authority("CONNECT", "https://example.com/", protocol: "websocket"));
        Assert.Equal("example.com", Authority("GET", "https://example.com/", protocol: null));
    }

    /// <summary>
    /// RFC 9112 section 3.2.3: "When making a CONNECT request to establish a tunnel through one
    /// or more proxies, a client MUST send only the host and port of the tunnel destination as
    /// the request-target ... except that it sends the scheme's default port if the target URI
    /// elides the port." No Host field accompanies it unless the caller added one — the
    /// request-line is what this pins.
    /// </summary>
    [Fact]
    public void PlainConnect_UsesTheAuthorityFormRequestTarget()
    {
        var text = Serialize("CONNECT", "https://example.com/", protocol: null);

        Assert.Equal("CONNECT example.com:443 HTTP/1.1\r\n\r\n", text);
    }

    /// <summary>
    /// An RFC 8441 extended CONNECT has no HTTP/1.1 expression at all, so it keeps the
    /// origin-form target every other method uses rather than being silently rewritten.
    /// </summary>
    [Fact]
    public void ExtendedConnect_KeepsTheOriginFormRequestTarget()
    {
        var text = Serialize("CONNECT", "https://example.com/chat", protocol: "websocket");

        Assert.StartsWith("CONNECT /chat HTTP/1.1\r\n", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// RFC 9112 section 3.2.4: "The 'asterisk-form' of request-target is only used for a
    /// server-wide OPTIONS request ... asterisk-form = '*'". No URI produces that string, so the
    /// declared path override is the only way to express it — and it has to survive a fallback
    /// from HTTP/2, because <c>OPTIONS *</c> and <c>OPTIONS /</c> address different resources.
    /// </summary>
    [Fact]
    public void PathOverride_ReachesTheHttp11RequestTargetVerbatim()
    {
        var text = Serialize("OPTIONS", "https://example.com/", protocol: null, pathOverride: "*");

        Assert.StartsWith("OPTIONS * HTTP/1.1\r\n", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// A CONNECT target is an authority by RFC 9112 section 3.2.3, so there is no path for the
    /// override to replace and the authority-form still wins.
    /// </summary>
    [Fact]
    public void PathOverride_DoesNotDisplaceTheConnectAuthorityForm()
    {
        var text = Serialize("CONNECT", "https://example.com/", protocol: null, pathOverride: "*");

        Assert.StartsWith("CONNECT example.com:443 HTTP/1.1\r\n", text, StringComparison.Ordinal);
    }

    private static string Serialize(
        string method,
        string url,
        string? protocol,
        string? pathOverride = null)
    {
        var request = new BufferedRequest(
            method,
            new Uri(url),
            [],
            [],
            HasContent: false)
        {
            Protocol = protocol,
            PathOverride = pathOverride,
        };

        return Encoding.Latin1.GetString(Http11RequestWriter.SerializeHeaders(request));
    }

    private static string Authority(string method, string url, string? protocol)
    {
        var request = new BufferedRequest(
            method,
            new Uri(url),
            [],
            [],
            HasContent: false)
        {
            Protocol = protocol,
        };

        return Http11RequestWriter.AuthorityFor(request);
    }
}
