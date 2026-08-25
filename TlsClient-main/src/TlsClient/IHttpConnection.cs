namespace TlsClient;

internal interface IHttpConnection : IAsyncDisposable
{
    TlsConnectionInfo TlsInfo { get; }

    DateTimeOffset LastUsed { get; }

    bool HasCompletedRequest { get; }

    bool IsReusable { get; }

    bool IsDisposed { get; }

    bool HasActiveRequests { get; }

    int MaximumConcurrentRequests { get; }

    ValueTask<ParsedHttpResponse> SendAsync(
        BufferedRequest request,
        StreamingResponseContext? streamingResponse,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken);
}
