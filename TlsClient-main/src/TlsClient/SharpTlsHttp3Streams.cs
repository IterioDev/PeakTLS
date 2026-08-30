using SharpTls.Quic;

namespace TlsClient;

/// <summary>
/// <see cref="IHttp3Streams"/> over SharpTls's own QUIC and HTTP/3 objects.
/// </summary>
/// <remarks>
/// <para>EVERY MEMBER IS ONE SharpTls CALL AND NOTHING ELSE. No state is kept here — the
/// exchange table, the readers and the flow-control budgets all live in
/// <c>TlsQuicHttp3Connection</c> — so there is no second copy of the connection's state to
/// disagree with the first. The only member with any logic of its own is
/// <see cref="Describe"/>, and it forwards to <c>Http3Connection.Describe</c> so that the
/// refusal-to-exception mapping stays in one place.</para>
/// <para>NOT THREAD-SAFE, DELIBERATELY. <c>TlsQuicConnection</c> is not, and pretending
/// otherwise here would hide that from the one type that has to know:
/// <see cref="Http3StreamMultiplexer"/> serialises every call into this object behind its own
/// gate.</para>
/// </remarks>
internal sealed class SharpTlsHttp3Streams(
    TlsQuicConnection connection,
    TlsQuicHttp3Connection http3) : IHttp3Streams
{
    private readonly TlsQuicConnection _connection = connection;
    private readonly TlsQuicHttp3Connection _http3 = http3;

    public ulong ConnectionErrorCode => _http3.ConnectionErrorCode;

    public ulong? PeerGoawayStreamId => _http3.PeerGoawayStreamId;

    public ulong? TryOpenRequest(
        TlsQuicHttp3Request request,
        out TlsQuicHttp3RequestRefusal refusal,
        out TlsQuicHttp3RequestError malformed) =>
        _http3.TryOpenRequest(request, out refusal, out malformed)?.Id;

    public async ValueTask SendPendingAsync(CancellationToken cancellationToken) =>
        await _connection.SendPendingAsync(cancellationToken).ConfigureAwait(false);

    public ValueTask<bool> PumpOnceAsync(CancellationToken cancellationToken) =>
        _http3.PumpOnceAsync(cancellationToken);

    /// <summary>Reads one request stream's state.</summary>
    /// <remarks>An identifier this connection did not open — which cannot happen, since the
    /// multiplexer only ever asks about streams <see cref="TryOpenRequest"/> gave it — reads as
    /// an empty, incomplete stream rather than throwing.</remarks>
    public Http3StreamSnapshot Peek(ulong streamId)
    {
        var response = _http3.ResponseFor(streamId);
        if (response is null)
        {
            return new Http3StreamSnapshot(-1, [], [], 0, false, false);
        }
        return new Http3StreamSnapshot(
            response.Status,
            response.HeaderFields,
            response.TrailerFields,
            response.Body.Length,
            ReceiveComplete(streamId),
            response.IsComplete);
    }

    public byte[] CopyBody(ulong streamId, int start, int end)
    {
        var response = _http3.ResponseFor(streamId);
        return response is null ? [] : response.Body[start..end].ToArray();
    }

    public Exception Describe(
        TlsQuicHttp3RequestRefusal refusal,
        TlsQuicHttp3RequestError malformed) => Http3Connection.Describe(
            refusal,
            malformed,
            _connection.PeerFlowControl.InitialMaxStreamDataBidiRemote,
            _connection.PeerFlowControl.InitialMaxData,
            _connection.PeerFlowControl.RemainingConnectionData,
            _http3.ConnectionErrorCode);

    public ValueTask CloseWithCurrentErrorAsync() => _http3.CloseWithCurrentErrorAsync();

    /// <inheritdoc />
    /// <remarks>THE QUIC CONNECTION AND NOTHING BELOW IT. The UDP socket - or the RFC 1928
    /// section 7 relay standing in for one - is owned by <c>Http3Connection</c>, which disposes
    /// it after this, so a transport is never torn down under a connection still using it.
    /// </remarks>
    public ValueTask DisposeAsync() => _connection.DisposeAsync();

    /// <summary>Gets whether the peer closed its half of one request stream.</summary>
    /// <remarks><c>TlsQuicHttp3Connection</c> exposes the readers but not the streams, so the
    /// FIN is read off the stream set that owns them. A stream the set does not know reads as
    /// not complete, which is the same answer the null reader above gives.</remarks>
    private bool ReceiveComplete(ulong streamId) =>
        _connection.Streams.Find(streamId)?.ReceiveComplete ?? false;
}
