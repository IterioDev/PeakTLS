using System.Net;
using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

/// <summary>
/// Declarative pseudo-header composition: which fields the declared order emits and in what
/// sequence, how the authority is conveyed, and the <c>:scheme</c>, <c>:path</c>, and
/// <c>:protocol</c> values that reach the wire.
/// </summary>
public sealed class Http2PseudoHeaderTests
{
    /// <summary>
    /// The loopback authority carries the listener's ephemeral port, so the authority a
    /// capture emits differs from run to run. Pinning <c>Host</c> pins <c>:authority</c> —
    /// <c>BuildRequestHeaders</c> reads the authority out of the Host field when one is
    /// present — which is what lets these tests assert an exact value.
    /// </summary>
    private const string FixedAuthority = "pseudo.test";

    /// <summary>
    /// RFC 9113 section 8.3.1 requires a client generating HTTP/2 requests directly to convey
    /// authority in <c>:authority</c>: "Clients that generate HTTP/2 requests directly MUST
    /// use the ':authority' pseudo-header field to convey authority information". The default
    /// mode obeys it, and the <c>host</c> field the request carried is dropped so the two
    /// cannot disagree.
    /// </summary>
    [Fact]
    public async Task AuthorityOnly_EmitsAuthorityAndDropsTheHostField()
    {
        var headers = await CaptureAsync(_ => { }, _ => { });

        Assert.Equal(FixedAuthority, Value(headers, ":authority"));
        Assert.Null(Value(headers, "host"));
    }

    /// <summary>
    /// The mode that deliberately departs from RFC 9113 section 8.3.1. No <c>:authority</c>
    /// is emitted at all; the authority travels in a regular <c>host</c> field, lowercased as
    /// section 8.2.1 requires of every field name.
    /// </summary>
    [Fact]
    public async Task HostHeaderOnly_EmitsAHostFieldAndNoAuthority()
    {
        var headers = await CaptureAsync(
            _ => { },
            request => request.AuthorityMode = TlsHttp2AuthorityMode.HostHeaderOnly);

        Assert.Null(Value(headers, ":authority"));
        Assert.Equal(FixedAuthority, Value(headers, "host"));
    }

    /// <summary>
    /// Both fields, carrying the same value. RFC 9113 section 8.3.1: "Clients MUST NOT
    /// generate a request with a Host header field that differs from the ':authority'
    /// pseudo-header field." Both are read from one source, so equality is structural rather
    /// than a coincidence of this fixture.
    /// </summary>
    [Fact]
    public async Task Both_EmitsAuthorityAndAHostFieldCarryingTheSameValue()
    {
        var headers = await CaptureAsync(
            _ => { },
            request => request.AuthorityMode = TlsHttp2AuthorityMode.Both);

        Assert.Equal(FixedAuthority, Value(headers, ":authority"));
        Assert.Equal(FixedAuthority, Value(headers, "host"));
    }

    /// <summary>
    /// Where that <c>host</c> field sits. RFC 9113 section 8.3: "All pseudo-header fields MUST
    /// appear in a field block before all regular field lines. Any request or response that
    /// contains a pseudo-header field that appears in a field block after a regular field line
    /// MUST be treated as malformed." <c>host</c> is a regular field, so under
    /// <see cref="TlsHttp2AuthorityMode.Both"/> it follows every pseudo-header including the
    /// <c>:authority</c> it duplicates — it does not sit beside it.
    /// </summary>
    /// <remarks>
    /// <see cref="EveryPseudoHeaderPrecedesEveryRegularField"/> cannot reach this: it captures
    /// under the default <see cref="TlsHttp2AuthorityMode.AuthorityOnly"/>, which drops the
    /// <c>host</c> field entirely, so the one regular field this mode adds is absent from the
    /// block it inspects. Indices are taken by name over the whole block rather than from a
    /// leading run, so a <c>host</c> emitted among the pseudo-headers is seen rather than
    /// silently skipped.
    /// </remarks>
    [Fact]
    public async Task Both_PutsTheHostFieldAfterEveryPseudoHeader()
    {
        var headers = await CaptureAsync(
            _ => { },
            request => request.AuthorityMode = TlsHttp2AuthorityMode.Both);

        var pseudo = Indices(headers, name => name.StartsWith(':'));
        var host = Assert.Single(Indices(headers, name => name == "host"));

        // Pinned so the comparison below is provably about ordering and not about an empty
        // set: :authority is the pseudo-header this mode duplicates, and it must be emitted.
        Assert.Contains(":authority", headers.Select(header => header.Name));
        Assert.True(
            pseudo.Max() < host,
            $"the host field at index {host} precedes a pseudo-header at index " +
            $"{pseudo.Max()}: {string.Join(", ", headers.Select(header => header.Name))}");
    }

    /// <summary>
    /// The session value is what a request with no override falls back to, which is the half
    /// of the fallback the per-request tests above cannot show.
    /// </summary>
    [Fact]
    public async Task SessionAuthorityMode_AppliesWhenTheRequestDeclaresNone()
    {
        var headers = await CaptureAsync(
            session => session.Http2.PseudoHeaders.AuthorityMode =
                TlsHttp2AuthorityMode.HostHeaderOnly,
            _ => { });

        Assert.Null(Value(headers, ":authority"));
        Assert.Equal(FixedAuthority, Value(headers, "host"));
    }

    /// <summary>
    /// RFC 9113 section 8.3.1 requires "an OPTIONS request for an 'http' or 'https' URI that
    /// does not include a path component" to carry a <c>:path</c> of <c>*</c>. No URI produces
    /// that string, so it is expressible only as a verbatim override.
    /// </summary>
    [Fact]
    public async Task PathOverride_PutsTheAsteriskFormOnTheWire()
    {
        var headers = await CaptureAsync(
            _ => { },
            request => request.PathOverride = "*",
            HttpMethod.Options);

        Assert.Equal("*", Value(headers, ":path"));
    }

    /// <summary>
    /// The order declares membership, not just sequence: a name it omits is never written.
    /// This one drops <c>:authority</c> and reverses the rest, so neither the default order
    /// nor a mere permutation of the four could produce it.
    /// </summary>
    [Fact]
    public async Task Order_EmitsExactlyTheDeclaredPseudoHeadersInTheDeclaredSequence()
    {
        var headers = await CaptureAsync(
            session => session.Http2.PseudoHeaders.Order = [":path", ":scheme", ":method"],
            _ => { });

        Assert.Equal([":path", ":scheme", ":method"], PseudoHeaderNames(headers));
    }

    /// <summary>
    /// The per-request order override resolves against the same rule, and the two captures
    /// share one declared order so only the request value can explain the difference.
    /// </summary>
    /// <remarks>
    /// Both orders carry the set a GET requires — RFC 9113 section 8.3.1 makes <c>:method</c>,
    /// <c>:scheme</c>, and <c>:path</c> mandatory — so only the sequence differs, which is the
    /// axis this test is about.
    /// </remarks>
    [Fact]
    public async Task RequestOrder_OverridesTheSessionOrder()
    {
        var headers = await CaptureAsync(
            session => session.Http2.PseudoHeaders.Order = [":method", ":path", ":scheme"],
            request => request.PseudoHeaderOrder =
                [":scheme", ":authority", ":method", ":path"]);

        Assert.Equal(
            [":scheme", ":authority", ":method", ":path"],
            PseudoHeaderNames(headers));
    }

    /// <summary>
    /// RFC 8441 section 4 adds <c>:protocol</c>, which "MAY be included on request HEADERS".
    /// It is emitted only where the order places it and only once a request supplies a value,
    /// so the same declared order yields two different field blocks. The order used here is
    /// the one RFC 8441 section 5.1 prints in its example.
    /// </summary>
    [Fact]
    public async Task Protocol_IsEmittedInItsDeclaredPositionOnlyWhenSet()
    {
        static void DeclareOrder(TlsSessionOptions session) =>
            session.Http2.PseudoHeaders.Order =
                [":method", ":protocol", ":scheme", ":path", ":authority"];

        var withProtocol = await CaptureAsync(
            DeclareOrder,
            request => request.Protocol = "websocket");
        var withoutProtocol = await CaptureAsync(DeclareOrder, _ => { });

        Assert.Equal(
            [":method", ":protocol", ":scheme", ":path", ":authority"],
            PseudoHeaderNames(withProtocol));
        Assert.Equal("websocket", Value(withProtocol, ":protocol"));
        Assert.Equal(
            [":method", ":scheme", ":path", ":authority"],
            PseudoHeaderNames(withoutProtocol));
    }

    /// <summary>
    /// RFC 9113 section 8.3.1: "':scheme' is not restricted to 'http' and 'https' schemed
    /// URIs." Both halves of the fallback are asserted, and the session value is neither
    /// <c>https</c> nor the request's, so no assertion here can pass on the old hardcode.
    /// </summary>
    [Fact]
    public async Task Scheme_ResolvesFromTheRequestThenTheSession()
    {
        static void DeclareScheme(TlsSessionOptions session) =>
            session.Http2.PseudoHeaders.Scheme = "ftp";

        var overridden = await CaptureAsync(DeclareScheme, request => request.Scheme = "coap");
        var inherited = await CaptureAsync(DeclareScheme, _ => { });

        Assert.Equal("coap", Value(overridden, ":scheme"));
        Assert.Equal("ftp", Value(inherited, ":scheme"));
    }

    /// <summary>
    /// The order names which pseudo-headers may be written, so a name outside the request set
    /// RFC 9113 section 8.3.1 and RFC 8441 section 4 define — <c>:status</c> is response-only
    /// per section 8.3.2 — is rejected before a connection is opened.
    /// </summary>
    [Fact]
    public void Snapshot_RejectsAnUnknownOrRepeatedPseudoHeaderName()
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        options.Http2.PseudoHeaders.Order = [":method", ":status"];
        Assert.Throws<ArgumentException>(options.Snapshot);

        options.Http2.PseudoHeaders.Order = [":method", ":path", ":method"];
        Assert.Throws<ArgumentException>(options.Snapshot);
    }

    /// <summary>
    /// RFC 9113 section 8.3.1 makes <c>:method</c> mandatory on every request, CONNECT
    /// included, so an order that omits it is malformed whatever the method.
    /// </summary>
    [Fact]
    public async Task Method_IsRequiredOfEveryRequest()
    {
        var exception = await RejectAsync(
            _ => { },
            message => TlsRequestOptions.For(message).PseudoHeaderOrder =
                [":authority", ":scheme", ":path"],
            HttpMethod.Get);

        Assert.Equal(
            "An HTTP/2 GET request must carry the :method pseudo-header " +
            "(RFC 9113 section 8.3.1).",
            exception.Message);
    }

    /// <summary>
    /// RFC 9113 section 8.5: on a CONNECT request "The ':scheme' and ':path' pseudo-header
    /// fields MUST be omitted", so the default order — legal for every other method — is
    /// malformed here. Nothing beyond <c>:method</c> and <c>:authority</c> is permitted.
    /// </summary>
    [Fact]
    public async Task PlainConnect_RejectsTheSchemeAndPathPseudoHeaders()
    {
        var exception = await RejectAsync(_ => { }, _ => { }, HttpMethod.Connect);

        Assert.Equal(
            "An HTTP/2 CONNECT request must not carry the :scheme pseudo-header " +
            "(RFC 9113 section 8.5).",
            exception.Message);
    }

    /// <summary>
    /// RFC 8441 section 4 restores what section 8.5 forbade: "On requests that contain the
    /// :protocol pseudo-header field, the :scheme and :path pseudo-header fields of the target
    /// URI […] MUST also be included." All five are then required, and this order drops
    /// <c>:path</c>.
    /// </summary>
    [Fact]
    public async Task ExtendedConnect_RequiresTheFullFivePseudoHeaderSet()
    {
        var exception = await RejectAsync(
            session => session.Http2.PseudoHeaders.Order =
                [":method", ":protocol", ":scheme", ":authority"],
            message => TlsRequestOptions.For(message).Protocol = "websocket",
            HttpMethod.Connect);

        Assert.Equal(
            "An HTTP/2 CONNECT request must carry the :path pseudo-header " +
            "(RFC 8441 section 4).",
            exception.Message);
    }

    /// <summary>
    /// RFC 9113 section 8.3.1: "All HTTP/2 requests MUST include exactly one valid value for
    /// the ':method', ':scheme', and ':path' pseudo-header fields, unless they are CONNECT
    /// requests." This order carries <c>:authority</c>, which is permitted, and drops
    /// <c>:scheme</c>, which is not.
    /// </summary>
    [Fact]
    public async Task NormalMethod_RequiresMethodSchemeAndPath()
    {
        var exception = await RejectAsync(
            _ => { },
            message => TlsRequestOptions.For(message).PseudoHeaderOrder =
                [":method", ":authority", ":path"],
            HttpMethod.Post);

        Assert.Equal(
            "An HTTP/2 POST request must carry the :scheme pseudo-header " +
            "(RFC 9113 section 8.3.1).",
            exception.Message);
    }

    /// <summary>
    /// RFC 9113 section 8.3.1: "Clients MUST NOT generate a request with a Host header field
    /// that differs from the ':authority' pseudo-header field." A second <c>Host</c> value is
    /// the one shape that reaches the divergence today — <c>:authority</c> is taken from the
    /// first — and a server resolving the disagreement by trusting one field over the other is
    /// a request-smuggling seam, so the request is refused rather than reconciled.
    /// </summary>
    [Fact]
    public async Task Both_RejectsAHostFieldThatDiffersFromTheAuthority()
    {
        var exception = await RejectAsync(
            _ => { },
            message =>
            {
                message.AddHeader("Host", "elsewhere.test");
                TlsRequestOptions.For(message).AuthorityMode = TlsHttp2AuthorityMode.Both;
            },
            HttpMethod.Get);

        Assert.Equal(
            "An HTTP/2 GET request must not carry a host field that differs from its " +
            ":authority pseudo-header (RFC 9113 section 8.3.1).",
            exception.Message);
    }

    /// <summary>
    /// RFC 9113 section 8.3: "All pseudo-header fields MUST appear in a field block before all
    /// regular field lines. Any request or response that contains a pseudo-header field that
    /// appears in a field block after a regular field line MUST be treated as malformed."
    /// Asserted on the emitted indices, which is the only shape that can catch a breach — a
    /// helper that reads the leading run of colon-prefixed names cannot see one by
    /// construction.
    /// </summary>
    [Fact]
    public async Task EveryPseudoHeaderPrecedesEveryRegularField()
    {
        // A session carries no headers, so a bare GET would have no regular field for the
        // ordering claim to be about. The caller supplies one.
        var headers = await CaptureAsync(
            _ => { },
            _ => { },
            extraHeaders: [("X-Regular", "value")]);

        var pseudo = Indices(headers, name => name.StartsWith(':'));
        var regular = Indices(headers, name => !name.StartsWith(':'));

        Assert.NotEmpty(pseudo);
        Assert.NotEmpty(regular);
        Assert.True(
            pseudo.Max() < regular.Min(),
            $"a pseudo-header at index {pseudo.Max()} follows a regular field at index " +
            $"{regular.Min()}: {string.Join(", ", headers.Select(header => header.Name))}");
    }

    /// <summary>
    /// RFC 9113 section 8.5 defines a plain CONNECT's <c>:authority</c> as "the host and port
    /// to connect to (equivalent to the authority-form of the request-target of CONNECT
    /// requests; see Section 3.2.3 of [HTTP/1.1])", and RFC 9112 section 3.2.3 gives that form
    /// as "authority-form = uri-host ':' port". A portless authority is not equivalent to it,
    /// which section 8.5 ends by calling malformed: "A CONNECT request that does not conform to
    /// these restrictions is malformed." A caller-pinned <c>host</c> field reaches
    /// <c>:authority</c> verbatim, which is how a portless one gets this far — the authority
    /// the writer seeds carries the port.
    /// </summary>
    [Fact]
    public async Task PlainConnect_RejectsAnAuthorityThatCarriesNoPort()
    {
        var exception = await RejectAsync(
            session => session.Http2.PseudoHeaders.Order = [":method", ":authority"],
            _ => { },
            HttpMethod.Connect);

        Assert.Equal(
            "An HTTP/2 CONNECT request must carry a port in its :authority pseudo-header " +
            "(RFC 9113 section 8.5, RFC 9112 section 3.2.3).",
            exception.Message);
    }

    /// <summary>
    /// A separator with nothing after it is not a port. RFC 9112 section 3.2.3's
    /// "authority-form = uri-host ':' port" takes its port production from RFC 3986 section
    /// 3.2.3, and an empty tail names none of the "host and port to connect to" that RFC 9113
    /// section 8.5 requires — so "pseudo.test:" is exactly as malformed as "pseudo.test".
    /// </summary>
    [Fact]
    public async Task PlainConnect_RejectsAnAuthorityWhoseSeparatorHasNoPortAfterIt()
    {
        var exception = await RejectAsync(
            session => session.Http2.PseudoHeaders.Order = [":method", ":authority"],
            _ => { },
            HttpMethod.Connect,
            FixedAuthority + ":");

        Assert.Equal(
            "An HTTP/2 CONNECT request must carry a port in its :authority pseudo-header " +
            "(RFC 9113 section 8.5, RFC 9112 section 3.2.3).",
            exception.Message);
    }

    /// <summary>
    /// RFC 3986 section 3.2.3 admits only digits in a port, so a non-numeric tail is outside
    /// the authority-form grammar RFC 9113 section 8.5 defers to and cannot name a port to
    /// tunnel to.
    /// </summary>
    [Fact]
    public async Task PlainConnect_RejectsAnAuthorityWhosePortIsNotNumeric()
    {
        var exception = await RejectAsync(
            session => session.Http2.PseudoHeaders.Order = [":method", ":authority"],
            _ => { },
            HttpMethod.Connect,
            FixedAuthority + ":abc");

        Assert.Equal(
            "An HTTP/2 CONNECT request must carry a port in its :authority pseudo-header " +
            "(RFC 9113 section 8.5, RFC 9112 section 3.2.3).",
            exception.Message);
    }

    /// <summary>
    /// The conformant shape: exactly the two pseudo-headers section 8.5 permits, the authority
    /// carrying its port verbatim.
    /// </summary>
    [Fact]
    public async Task PlainConnect_EmitsTheAuthorityWithItsPort()
    {
        var headers = await CaptureAsync(
            session => session.Http2.PseudoHeaders.Order = [":method", ":authority"],
            _ => { },
            HttpMethod.Connect,
            FixedAuthority + ":8443");

        Assert.Equal([":method", ":authority"], PseudoHeaderNames(headers));
        Assert.Equal(FixedAuthority + ":8443", Value(headers, ":authority"));
    }

    /// <summary>
    /// RFC 8441 section 4: "On requests bearing the :protocol pseudo-header field, the
    /// :authority pseudo-header field is interpreted according to Section 8.1.2.3 of [RFC7540]"
    /// — RFC 9113 section 8.3.1 — "instead of Section 8.3 of that document", where an authority
    /// needs no port. The server is forbidden from tunnelling to it, so the port section 8.5
    /// requires would name nothing.
    /// </summary>
    [Fact]
    public async Task ExtendedConnect_KeepsAnAuthorityWithNoPort()
    {
        var headers = await CaptureAsync(
            session => session.Http2.PseudoHeaders.Order =
                [":method", ":protocol", ":scheme", ":path", ":authority"],
            request => request.Protocol = "websocket",
            HttpMethod.Connect);

        Assert.Equal(FixedAuthority, Value(headers, ":authority"));
        Assert.Equal("websocket", Value(headers, ":protocol"));
    }

    /// <summary>
    /// Sends a request whose pseudo-header set its method does not allow and returns the
    /// rejection. The header block is never written, so the server script stops after the
    /// SETTINGS exchange rather than waiting for a HEADERS frame that never arrives.
    /// </summary>
    private static async Task<HttpRequestException> RejectAsync(
        Action<TlsSessionOptions> configureSession,
        Action<HttpRequestMessage> configureRequest,
        HttpMethod method,
        string authority = FixedAuthority)
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        configureSession(options);

        return await Assert.ThrowsAsync<HttpRequestException>(
            () => Http2WireCapture.RunAsync(
                options,
                async (session, url, cancellationToken) =>
                {
                    using var request = new HttpRequestMessage(method, url);
                    request.AddHeader("Host", authority);
                    // A rejected request is not a transport failure, so the session would
                    // replay it onto a second connection the single-accept harness cannot
                    // provide, and the test would hang for the harness's full timeout.
                    TlsRequestOptions.For(request).EnableRetries = false;
                    configureRequest(request);
                    return await session.SendAsync(request, cancellationToken);
                },
                async (server, cancellationToken) =>
                {
                    await server.ReadPrefaceAsync(cancellationToken);
                    await server.ReadUntilAsync(Http2FrameType.Settings, cancellationToken);
                    await server.WriteFrameAsync(
                        Http2FrameType.Settings,
                        0,
                        0,
                        [],
                        cancellationToken);
                    await server.FlushAsync(cancellationToken);
                }));
    }

    private static async Task<IReadOnlyList<HpackHeader>> CaptureAsync(
        Action<TlsSessionOptions> configureSession,
        Action<TlsRequestOptions> configureRequest,
        HttpMethod? method = null,
        string authority = FixedAuthority,
        (string Name, string Value)[]? extraHeaders = null)
    {
        var options = new TlsSessionOptions { Profile = TlsProfiles.Modern };
        configureSession(options);

        var result = await Http2WireCapture.RunAsync(
            options,
            async (session, url, cancellationToken) =>
            {
                using var request = new HttpRequestMessage(method ?? HttpMethod.Get, url);
                request.AddHeader("Host", authority);
                foreach (var header in extraHeaders ?? [])
                {
                    request.AddHeader(header.Name, header.Value);
                }
                configureRequest(TlsRequestOptions.For(request));
                return await session.SendAsync(request, cancellationToken);
            });

        Assert.Equal(HttpStatusCode.OK, result.Response.StatusCode);
        var block = result.ClientFrames.Single(frame => frame.Type == Http2FrameType.Headers);
        // Decoding is only ever used to read names and values back here; the encoder's own
        // representation choices are asserted by the golden tests, not by a round trip.
        return new HpackDecoder(4096).Decode(block.Payload, 16 * 1024);
    }

    /// <summary>
    /// Every emitted pseudo-header, wherever it sits in the block. Taking the leading run
    /// instead would make this helper structurally unable to see a breach of the very rule it
    /// documents — RFC 9113 section 8.3, "All pseudo-header fields MUST appear in a field block
    /// before all regular field lines" — because a pseudo-header emitted after a regular field
    /// would fall outside the run and simply go missing.
    /// <see cref="EveryPseudoHeaderPrecedesEveryRegularField"/> asserts the ordering itself.
    /// </summary>
    private static string[] PseudoHeaderNames(IReadOnlyList<HpackHeader> headers) =>
        headers.Where(header => header.Name.StartsWith(':'))
            .Select(header => header.Name)
            .ToArray();

    private static int[] Indices(
        IReadOnlyList<HpackHeader> headers,
        Func<string, bool> predicate) =>
        headers.Select((header, index) => (header.Name, index))
            .Where(entry => predicate(entry.Name))
            .Select(entry => entry.index)
            .ToArray();

    private static string? Value(IReadOnlyList<HpackHeader> headers, string name) =>
        headers.Where(header => header.Name == name).Select(header => header.Value)
            .FirstOrDefault();
}
