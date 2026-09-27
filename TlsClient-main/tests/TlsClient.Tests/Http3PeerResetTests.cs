using System.Net.Sockets;
using System.Threading.Channels;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>
/// A peer RESET_STREAM is an answer, not a silence: the request reader must end with the error
/// code the server chose, the connection must stay usable for the next request, and
/// H3_REQUEST_REJECTED must carry RFC 9114 s4.1.1's retry rule. Before this pinned it, a reset
/// before the header section left the reader waiting for a FIN that would never come.
/// </summary>
public sealed class Http3PeerResetTests
{
    private static readonly Uri Origin = new("https://example.test/");
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(20);

    [Theory]
    [InlineData(0x10bUL, "H3_REQUEST_REJECTED (0x10b)", true)]
    [InlineData(0x10cUL, "H3_REQUEST_CANCELLED (0x10c)", false)]
    [InlineData(0x9999UL, "application error 0x9999", false)]
    public async Task AResetBeforeTheHeaderSection_EndsTheRequestWithTheCodeAndKeepsTheConnection(
        ulong code,
        string expectedName,
        bool retryable)
    {
        var streams = new ResettingHttp3Streams(code);
        await using var connection = Connect(streams);

        var exception = await Assert
            .ThrowsAsync<TlsHttpProtocolException>(() => SendAsync(connection))
            .WaitAsync(Bound);

        Assert.Contains(expectedName, exception.Message, StringComparison.Ordinal);
        Assert.Contains("before any response header section", exception.Message, StringComparison.Ordinal);
        Assert.Equal(retryable, exception.Message.Contains("s4.1.1", StringComparison.Ordinal));
        Assert.True(exception.IsStreamScoped);
        Assert.True(connection.IsReusable);
    }

    private static Http3Connection Connect(IHttp3Streams streams)
    {
        var connection = new Http3Connection(
            TlsQuicUdpDatagramTransport.Create(AddressFamily.InterNetwork),
            streams,
            null,
            new TlsConnectionInfo(
                "witness",
                TlsProtocolVersion.Tls13,
                default,
                default,
                "h3",
                false,
                false,
                false,
                []),
            requestStreamAllowance: 100,
            idleBudget: null);
        connection.Start();
        return connection;
    }

    private static Task<ParsedHttpResponse> SendAsync(Http3Connection connection) =>
        connection.SendAsync(
            new BufferedRequest("GET", Origin, [], [], HasContent: false),
            null,
            new TlsSessionOptions().Snapshot(),
            CancellationToken.None).AsTask();

    /// <summary>Answers every request with a RESET_STREAM carrying the configured code and
    /// nothing else: no HEADERS, no FIN, exactly the shape SharpTls reports for a peer reset.</summary>
    private sealed class ResettingHttp3Streams(ulong code) : IHttp3Streams
    {
        private readonly Channel<ulong> _pending = Channel.CreateUnbounded<ulong>();
        private readonly HashSet<ulong> _reset = [];
        private readonly object _sync = new();
        private ulong _nextStreamId;

        public ulong ConnectionErrorCode => 0;

        public ulong? PeerGoawayStreamId => null;

        public ulong? TryOpenRequest(
            TlsQuicHttp3Request request,
            out TlsQuicHttp3RequestRefusal refusal,
            out TlsQuicHttp3RequestError malformed)
        {
            refusal = TlsQuicHttp3RequestRefusal.None;
            malformed = TlsQuicHttp3RequestError.None;
            lock (_sync)
            {
                var id = _nextStreamId;
                _nextStreamId += 4;
                _pending.Writer.TryWrite(id);
                return id;
            }
        }

        public ValueTask SendPendingAsync(CancellationToken cancellationToken) =>
            ValueTask.CompletedTask;

        public async ValueTask<bool> PumpOnceAsync(CancellationToken cancellationToken)
        {
            var id = await _pending.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            lock (_sync)
            {
                _reset.Add(id);
            }
            return true;
        }

        public Http3StreamSnapshot Peek(ulong streamId)
        {
            lock (_sync)
            {
                return _reset.Contains(streamId)
                    ? new Http3StreamSnapshot(-1, [], [], 0, false, false, code)
                    : new Http3StreamSnapshot(-1, [], [], 0, false, false);
            }
        }

        public byte[] CopyBody(ulong streamId, int start, int end) => [];

        public Exception Describe(
            TlsQuicHttp3RequestRefusal refusal,
            TlsQuicHttp3RequestError malformed) =>
            new TlsHttpProtocolException($"refused: {refusal}");

        public ValueTask CloseWithCurrentErrorAsync() => ValueTask.CompletedTask;

        public ValueTask DisposeAsync()
        {
            _pending.Writer.TryComplete();
            return ValueTask.CompletedTask;
        }
    }
}
