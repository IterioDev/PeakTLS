using System.Net;

namespace SharpTls.Quic;

/// <summary>TEMPORARY STUB for parallel TlsClient work; the real type lands on another branch
/// and replaces this file before merge. An RFC 9298 CONNECT-UDP tunnel as a datagram
/// transport.</summary>
internal sealed class TlsQuicMasqueTransport : ITlsQuicDatagramTransport
{
    /// <summary>Opens the tunnel. Stub: always throws.</summary>
    public static Task<TlsQuicMasqueTransport> ConnectAsync(
        TlsQuicMasqueOptions options,
        CancellationToken ct) => throw new NotImplementedException("stub");

    /// <inheritdoc />
    public int MaxDatagramPayloadSize => 1358;

    /// <summary>Gets the drop counters as text. Stub: empty.</summary>
    internal string DropSummary => "";

    /// <inheritdoc />
    public ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken) => throw new NotImplementedException("stub");

    /// <inheritdoc />
    public ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken) => throw new NotImplementedException("stub");

    /// <inheritdoc />
    public ValueTask DisposeAsync() => throw new NotImplementedException("stub");
}
