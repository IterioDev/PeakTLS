using System.Buffers;

namespace TlsClient;

/// <summary>
/// Coalesces the frames of one write batch into a single underlying write, so a declared
/// batch boundary becomes a record boundary the peer can observe. Without this every
/// frame is its own write and every <c>FlushAfter</c> is decorative.
/// </summary>
/// <remarks>
/// Not thread-safe by design: every caller already holds <c>Http2Connection._writeGate</c>,
/// which is what makes a batch a batch. Bytes never outlive the gated section that wrote
/// them, because every such section ends in <see cref="FlushAsync"/>.
/// </remarks>
internal sealed class Http2WriteBatch(Stream stream)
{
    /// <summary>
    /// The buffer is bounded so a declared batch cannot be turned into unbounded memory
    /// growth: a persona controls how many frames a batch holds, and a peer's
    /// SETTINGS_MAX_FRAME_SIZE reaches 16 MiB (RFC 9113 section 6.5.2). Past this the
    /// batch writes early and keeps going; correctness never depends on where a write
    /// lands, only on the order of the octets.
    /// </summary>
    internal const int MaximumBufferedBytes = 1024 * 1024;

    private readonly ArrayBufferWriter<byte> _buffer = new();

    /// <summary>Appends to the current batch, writing early if the bound is reached.</summary>
    public async ValueTask WriteAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken)
    {
        if (_buffer.WrittenCount + data.Length > MaximumBufferedBytes)
        {
            await DrainAsync(cancellationToken).ConfigureAwait(false);
            if (data.Length >= MaximumBufferedBytes)
            {
                // Buffering this could not shrink the write count and would only pin the
                // memory, so it goes straight out.
                await stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
                return;
            }
        }
        _buffer.Write(data.Span);
    }

    /// <summary>
    /// Ends the batch: one write of everything accumulated, then one flush. The next
    /// append starts a fresh batch.
    /// </summary>
    public async ValueTask FlushAsync(CancellationToken cancellationToken)
    {
        await DrainAsync(cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask DrainAsync(CancellationToken cancellationToken)
    {
        if (_buffer.WrittenCount == 0)
        {
            return;
        }
        // Snapshot and reset before the write, not after it. A write that throws on a
        // per-request cancellation token leaves the transport healthy, so the next batch
        // would otherwise be prepended with the abandoned one's octets. RFC 9113 section
        // 4.1 gives every frame a 9-octet header immediately followed by exactly its
        // declared payload length, and WriteFrameLockedAsync appends the header and the
        // payload as separate appends, so the survivor can be a header with no payload -
        // which desynchronizes the peer's framing for the rest of the connection.
        // Nothing appends to the buffer while this await runs: every caller holds
        // Http2Connection._writeGate, so the snapshot stays valid.
        var pending = _buffer.WrittenMemory;
        _buffer.ResetWrittenCount();
        await stream.WriteAsync(pending, cancellationToken).ConfigureAwait(false);
    }
}
