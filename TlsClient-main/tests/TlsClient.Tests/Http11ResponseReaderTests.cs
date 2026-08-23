using System.Text;

namespace TlsClient.Tests;

public sealed class Http11ResponseReaderTests
{
    [Fact]
    public async Task ReadAsync_ParsesInformationalAndFixedResponse()
    {
        var parsed = await ParseAsync(
            "HTTP/1.1 100 Continue\r\nX-Ignored: yes\r\n\r\n" +
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello");

        Assert.Equal(200, (int)parsed.StatusCode);
        Assert.Equal("hello", Encoding.ASCII.GetString(parsed.Body));
        Assert.Equal("yes", parsed.Headers["x-test"]);
        Assert.True(parsed.Reusable);
    }

    [Fact]
    public async Task ReadAsync_ParsesChunkedBodyAndTrailers()
    {
        var parsed = await ParseAsync(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "5\r\nhello\r\n6;ext=yes\r\n world\r\n0\r\nX-Trailer: done\r\n\r\n");

        Assert.Equal("hello world", Encoding.ASCII.GetString(parsed.Body));
        Assert.Equal("done", parsed.Trailers["x-trailer"]);
    }

    [Fact]
    public async Task ReadAsync_RejectsConflictingContentLengths()
    {
        await Assert.ThrowsAsync<TlsHttpProtocolException>(async () =>
            await ParseAsync(
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx"));
    }

    [Fact]
    public async Task ReadAsync_RejectsBodyOverLimit()
    {
        await Assert.ThrowsAsync<TlsHttpProtocolException>(async () =>
            await ParseAsync(
                "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n123456",
                maximumBodyBytes: 5));
    }

    /// <summary>
    /// RFC 9110 section 6.4.1: "2xx (Successful) responses to a CONNECT request method (Section
    /// 9.3.6) switch the connection to tunnel mode instead of having content." The peer behind a
    /// established tunnel is waiting for tunnel traffic and never closes, so a reader that falls
    /// through to the read-until-close path never returns — here the five-second budget stands in
    /// for the request budget that would otherwise be burned.
    /// </summary>
    [Fact]
    public async Task ReadAsync_SuccessfulConnectResponseReturnsWithoutWaitingForAClose()
    {
        await using var stream = new TunnelStream("HTTP/1.1 200 Connection Established\r\n\r\n");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var parsed = await Http11ResponseReader.ReadAsync(
            new BufferedHttpReader(stream),
            "CONNECT",
            16 * 1024,
            100,
            1024,
            timeout.Token);

        Assert.Equal(200, (int)parsed.StatusCode);
        Assert.Empty(parsed.Body);
        Assert.False(parsed.Reusable);
    }

    /// <summary>
    /// RFC 9112 section 6.1 item 3: a message with both a Transfer-Encoding and a Content-Length
    /// "ought to be handled as an error", because "the message sender might have retained a
    /// portion of the message, in buffer, that could be misinterpreted by further use of the
    /// connection". Transfer-Encoding still overrides the framing, as the same item requires.
    /// </summary>
    [Fact]
    public async Task ReadAsync_ContentLengthAlongsideTransferEncodingIsNotReusable()
    {
        var parsed = await ParseAsync(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n" +
            "5\r\nhello\r\n0\r\n\r\n");

        Assert.Equal("hello", Encoding.ASCII.GetString(parsed.Body));
        Assert.False(parsed.Reusable);
    }

    /// <summary>
    /// RFC 9112 section 7.1: "chunk-size = 1*HEXDIG". The grammar has no OWS production around
    /// the size, so a hop that accepts one framed the message differently from a hop that did
    /// not — the classic request-smuggling differential.
    /// </summary>
    [Theory]
    [InlineData(" 5")]
    [InlineData("5 ")]
    [InlineData("\t5")]
    public async Task ReadAsync_RejectsWhitespaceAroundAChunkSize(string chunkSize)
    {
        await Assert.ThrowsAsync<TlsHttpProtocolException>(async () =>
            await ParseAsync(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
                $"{chunkSize}\r\nhello\r\n0\r\n\r\n"));
    }

    /// <summary>
    /// The header budget is what is left of the allowance after the status line, and a maximal
    /// status line spends more than the allowance — <c>WireLength</c> counts the CRLF the
    /// allowance does not. The negative budget that follows must still surface as a
    /// <see cref="TlsHttpProtocolException"/>, because that is the type
    /// <c>TlsSession.ShouldRetryException</c> classifies a malformed peer response by; an
    /// <see cref="ArgumentOutOfRangeException"/> out of <c>new MemoryStream(-2)</c> escapes it
    /// on input the peer chooses the length of.
    /// </summary>
    [Fact]
    public async Task ReadAsync_MaximalStatusLineLeavesAProtocolErrorNotAnArgumentError()
    {
        var statusLine = "HTTP/1.1 200 " + new string('A', 27);
        Assert.Equal(40, statusLine.Length);

        await Assert.ThrowsAsync<TlsHttpProtocolException>(async () =>
            await ParseAsync(
                $"{statusLine}\r\nX: y\r\n\r\n",
                maximumHeaderBytes: 40));
    }

    private static async Task<ParsedHttpResponse> ParseAsync(
        string wire,
        int maximumBodyBytes = 1024,
        int maximumHeaderBytes = 16 * 1024)
    {
        await using var stream = new MemoryStream(Encoding.Latin1.GetBytes(wire));
        return await Http11ResponseReader.ReadAsync(
            new BufferedHttpReader(stream),
            "GET",
            maximumHeaderBytes,
            100,
            maximumBodyBytes,
            CancellationToken.None);
    }

    /// <summary>
    /// Serves a response head and then behaves like the far side of an established tunnel: it
    /// holds the connection open forever, waiting for tunnel traffic that a reader looking for a
    /// message body will never send.
    /// </summary>
    private sealed class TunnelStream(string head) : Stream
    {
        private readonly MemoryStream _head = new(Encoding.Latin1.GetBytes(head), writable: false);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var read = await _head.ReadAsync(buffer, cancellationToken);
            if (read != 0)
            {
                return read;
            }
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
