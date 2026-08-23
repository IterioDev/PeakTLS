using System.Net;
using System.Text;

namespace TlsClient.Tests;

public sealed class ProxyTunnelTests
{
    [Fact]
    public async Task Socks5_PerformsUsernamePasswordAndRemoteDnsConnect()
    {
        await using var transport = new ScriptedDuplexStream(
        [
            5, 2,
            1, 0,
            5, 0, 0, 1, 127, 0, 0, 1, 0x04, 0x38,
        ]);
        var proxy = TlsProxy.Socks5("socks5://user:pass@127.0.0.1:1080");

        await ProxyTunnel.EstablishAsync(
            transport,
            new Uri("https://example.com/"),
            proxy,
            4096,
            CancellationToken.None);

        Assert.Equal(3, transport.Writes.Count);
        Assert.Equal([5, 2, 0, 2], transport.Writes[0]);
        Assert.Equal(
            [1, 4, .. "user"u8.ToArray(), 4, .. "pass"u8.ToArray()],
            transport.Writes[1]);
        Assert.Equal(
            [5, 1, 0, 3, 11, .. "example.com"u8.ToArray(), 0x01, 0xbb],
            transport.Writes[2]);
    }

    [Fact]
    public async Task Socks5_UsesIpv6AddressTypeWithoutLocalDns()
    {
        await using var transport = new ScriptedDuplexStream(
        [
            5, 0,
            5, 0, 0, 4,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0,
        ]);

        await ProxyTunnel.EstablishAsync(
            transport,
            new Uri("https://[::1]:8443/"),
            TlsProxy.Socks5("socks5://127.0.0.1:1080"),
            4096,
            CancellationToken.None);

        Assert.Equal([5, 1, 0], transport.Writes[0]);
        Assert.Equal(4, transport.Writes[1][3]);
        Assert.Equal(IPAddress.IPv6Loopback.GetAddressBytes(), transport.Writes[1][4..20]);
        Assert.Equal([0x20, 0xfb], transport.Writes[1][20..22]);
    }

    /// <summary>
    /// The request-target of a CONNECT is authority-form, which RFC 9112 section 3.2.3 gives as
    /// "authority-form = uri-host ':' port". The port is not optional there, so an origin on
    /// its scheme's default port still names it — a proxy given a bare host has no port to
    /// dial.
    /// </summary>
    [Fact]
    public async Task Http_NamesThePortOfADefaultPortOriginInTheAuthorityForm()
    {
        await using var transport = new ScriptedDuplexStream(
            Encoding.Latin1.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n"));

        await ProxyTunnel.EstablishAsync(
            transport,
            new Uri("https://example.com/"),
            TlsProxy.Http("http://127.0.0.1:8080"),
            4096,
            CancellationToken.None);

        var request = Encoding.Latin1.GetString(Assert.Single(transport.Writes));

        Assert.StartsWith(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n",
            request,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// RFC 9110 section 9.3.6: the sender switches to tunnel mode "immediately after the response
    /// header section; data received after that header section is from the server identified by
    /// the request target". The reader used to parse the CONNECT response is dropped when the
    /// tunnel is established, so octets it read ahead would be lost silently.
    /// </summary>
    [Fact]
    public async Task Http_RejectsOctetsReadPastTheConnectResponseHead()
    {
        await using var transport = new ScriptedDuplexStream(
            Encoding.Latin1.GetBytes("HTTP/1.1 200 Connection established\r\n\r\nstray"));

        var exception = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await ProxyTunnel.EstablishAsync(
                transport,
                new Uri("https://example.com/"),
                TlsProxy.Http("http://127.0.0.1:8080"),
                4096,
                CancellationToken.None));

        Assert.Contains("unsolicited data", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// RFC 9110 section 15.2: "A client MUST be able to parse one or more 1xx responses received
    /// prior to a final response, even if the client does not expect one. A user agent MAY ignore
    /// unexpected 1xx responses." An interim response is not the CONNECT answer, so reporting it
    /// as a proxy rejection would fail a tunnel the proxy went on to establish.
    /// </summary>
    [Fact]
    public async Task Http_SkipsInterimResponsesBeforeTheConnectAnswer()
    {
        await using var transport = new ScriptedDuplexStream(
            Encoding.Latin1.GetBytes(
                "HTTP/1.1 100 Continue\r\n\r\n" +
                "HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n" +
                "HTTP/1.1 200 Connection established\r\n\r\n"));

        await ProxyTunnel.EstablishAsync(
            transport,
            new Uri("https://example.com/"),
            TlsProxy.Http("http://127.0.0.1:8080"),
            4096,
            CancellationToken.None);

        Assert.Single(transport.Writes);
    }

    [Fact]
    public async Task Socks5_RejectionIsSurfacedWithoutLeakingCredentials()
    {
        await using var transport = new ScriptedDuplexStream(
        [
            5, 0,
            5, 5, 0, 1,
        ]);
        var proxy = TlsProxy.Socks5("socks5://127.0.0.1:1080");

        var exception = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await ProxyTunnel.EstablishAsync(
                transport,
                new Uri("https://example.com/"),
                proxy,
                4096,
                CancellationToken.None));

        Assert.Contains("0x05", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Socks5_RejectsEmptyBoundDomain()
    {
        await using var transport = new ScriptedDuplexStream(
        [
            5, 0,
            5, 0, 0, 3, 0,
        ]);

        var exception = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await ProxyTunnel.EstablishAsync(
                transport,
                new Uri("https://example.com/"),
                TlsProxy.Socks5("socks5://127.0.0.1:1080"),
                4096,
                CancellationToken.None));

        Assert.Contains("empty domain", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RequestProxy_AssigningNullIsAnExplicitDirectOverride()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        var options = TlsRequestOptions.For(request);

        options.Proxy = null;
        var direct = TlsRequestOptions.Snapshot(request);
        options.UseSessionProxy();
        var inherited = TlsRequestOptions.Snapshot(request);

        Assert.True(direct.HasProxyOverride);
        Assert.Null(direct.Proxy);
        Assert.False(inherited.HasProxyOverride);
    }

    private static string ReadNullTerminated(
        byte[] bytes,
        int offset,
        out int nextOffset)
    {
        var end = Array.IndexOf(bytes, (byte)0, offset);
        Assert.True(end >= 0);
        nextOffset = end + 1;
        return Encoding.UTF8.GetString(bytes, offset, end - offset);
    }

    private sealed class ScriptedDuplexStream(byte[] response) : Stream
    {
        private readonly MemoryStream _response = new(response, writable: false);

        public List<byte[]> Writes { get; } = [];

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _response.ReadAsync(buffer, cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) =>
            _response.Read(buffer, offset, count);

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            Writes.Add(buffer.ToArray());
            return ValueTask.CompletedTask;
        }

        public override void Write(byte[] buffer, int offset, int count) =>
            Writes.Add(buffer.AsSpan(offset, count).ToArray());

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
