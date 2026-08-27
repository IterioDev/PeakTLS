namespace SharpTls.Quic;

/// <summary>
/// Bounded offset-aware CRYPTO stream reassembly. Matching retransmissions are accepted;
/// conflicting overlaps and data extending a discarded level fail closed.
/// </summary>
internal sealed class TlsQuicCryptoStreamReassembler
{
    // THE BUFFER IS CHUNKED, NOT DENSE, AND THAT IS THE WHOLE POINT OF THIS CONSTANT.
    // RFC 9000 s19.6 lets a CRYPTO frame name any offset below 2^62, and s7.5 requires an
    // endpoint to buffer out-of-order crypto data up to whatever limit it advertises - so
    // an offset near this reassembler's ceiling is legal input, not an attack signature,
    // and cannot simply be refused. A flat byte[] grown to the highest offset seen (plus
    // its parallel received-flag array) turned one such frame into two full-ceiling
    // allocations: 2 x 32 MiB at the constructor's upper bound, for one byte of payload.
    // Reaching it needs valid handshake keys, so the sender is a malicious SERVER rather
    // than anyone off-path, which is why this was low severity and not urgent - but a
    // peer choosing where the array lands is still a peer choosing how much memory to
    // commit.
    //
    // Chunking decouples the two: the chunk TABLE is sized to the highest offset (one
    // reference per 4 KiB, so 64 KiB of pointers at the 32 MiB ceiling), while chunks
    // themselves are allocated only where bytes actually arrive. The same far-offset
    // frame now costs about 136 KiB instead of 64 MiB, and a well-behaved handshake -
    // which fills from offset 0 - allocates exactly what it uses either way.
    //
    // The three numbers above are pinned by TlsQuicPrimitiveTests.CryptoStreamDoesNotComm
    // itItsWholeCeilingForOneFarOffsetFrame, which measures the allocation for exactly
    // that frame at exactly that ceiling. Prose is where numbers rot first; that test is
    // what makes these checkable.
    //
    // 4096 balances the two waste terms: bigger chunks waste more on a sparse write,
    // smaller ones grow the always-allocated pointer table.
    //
    // NOT A FREE PARAMETER BELOW ITS OWN VALUE, which is the one case the ceiling stops
    // bounding. The constructor floor is 1024 and the ceiling is caller-configured, so a
    // reassembler limited to 1024 bytes still rounds up to one chunk and commits 8 KiB -
    // data plus flags - on its first write, eight times the limit it was given. That is
    // deliberate and it stays: the overshoot is bounded by 2 * ChunkLength per instance
    // and there are three instances per connection, so the worst case is 24 KiB, which is
    // noise beside a connection's own buffers. Clamping the chunk size to the ceiling
    // would cost more than it saves - ChunkLength would have to become a field, and every
    // `index / ChunkLength` and `index % ChunkLength` in the accessors below would stop
    // const-folding into a shift and a mask, on the path that touches every received
    // CRYPTO byte. Revisit only if a caller ever wants a sub-chunk ceiling to mean
    // something.
    private const int ChunkLength = 4096;

    private readonly int _maximumLength;

    // Parallel tables, index i of each describing the same 4 KiB span. A null entry means
    // "no byte in this span has been received", which is why the flags cannot be folded
    // into _chunks: 0x00 is legitimate CRYPTO data, so an all-zero chunk is not evidence
    // of an absent one. Allocated as a pair, so a non-null _chunks[i] implies a non-null
    // _receivedChunks[i].
    private byte[]?[] _chunks = [];
    private byte[]?[] _receivedChunks = [];
    private int _deliveredLength;
    private int _highestReceivedEnd;
    private bool _discarded;

    internal TlsQuicCryptoStreamReassembler(int maximumLength)
    {
        if (maximumLength is < 1024 or > 32 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumLength));
        }
        _maximumLength = maximumLength;
    }

    internal int DeliveredLength => _deliveredLength;

    internal byte[] Add(ulong offset, ReadOnlySpan<byte> data)
    {
        if (offset > int.MaxValue || data.Length > _maximumLength ||
            offset > (ulong)(_maximumLength - data.Length))
        {
            throw new TlsQuicTransportException(
                TlsQuicTransportError.CryptoBufferExceeded,
                "CRYPTO stream data exceeds the configured buffer limit.");
        }
        var start = checked((int)offset);
        var end = start + data.Length;
        if (_discarded && end > _highestReceivedEnd)
        {
            throw new TlsQuicTransportException(
                TlsQuicTransportError.ProtocolViolation,
                "A discarded CRYPTO level received new data.");
        }
        EnsureCapacity(end);
        for (var index = 0; index < data.Length; index++)
        {
            var destinationIndex = start + index;
            if (IsReceived(destinationIndex))
            {
                if (ByteAt(destinationIndex) != data[index])
                {
                    throw new TlsQuicTransportException(
                        TlsQuicTransportError.ProtocolViolation,
                        "Overlapping CRYPTO data does not match the prior bytes.");
                }
                continue;
            }
            if (_discarded)
            {
                throw new TlsQuicTransportException(
                    TlsQuicTransportError.ProtocolViolation,
                    "A discarded CRYPTO level filled a previously missing range.");
            }
            Write(destinationIndex, data[index]);
        }
        _highestReceivedEnd = Math.Max(_highestReceivedEnd, end);

        var contiguousEnd = _deliveredLength;
        while (contiguousEnd < _highestReceivedEnd && IsReceived(contiguousEnd))
        {
            contiguousEnd++;
        }
        if (contiguousEnd == _deliveredLength)
        {
            return [];
        }
        // Every index in [_deliveredLength, contiguousEnd) passed IsReceived above, so its
        // chunk is allocated and ByteAt cannot dereference a null. A byte-at-a-time copy
        // rather than a span slice because the range can straddle a chunk boundary. It
        // runs on every Add that advances _deliveredLength - once per in-order CRYPTO
        // frame, not once per flight - but each byte is copied out exactly once over the
        // reassembler's whole life, since _deliveredLength only moves forward. Amortized
        // O(bytes delivered), which is the same total work the span slice it replaced did.
        var result = new byte[contiguousEnd - _deliveredLength];
        for (var index = 0; index < result.Length; index++)
        {
            result[index] = ByteAt(_deliveredLength + index);
        }
        _deliveredLength = contiguousEnd;
        return result;
    }

    internal void Discard()
    {
        if (_discarded)
        {
            return;
        }
        if (_deliveredLength != _highestReceivedEnd)
        {
            throw new TlsQuicTransportException(
                TlsQuicTransportError.ProtocolViolation,
                "A CRYPTO level was discarded with an undelivered gap.");
        }
        _discarded = true;
    }

    // Grows only the pointer TABLE, never the payload. Same doubling shape as the dense
    // version it replaces, counted in chunks instead of bytes, and still clamped to the
    // ceiling - Add's own bounds check has already refused anything above _maximumLength,
    // so the clamp is belt-and-braces rather than the enforcement point.
    private void EnsureCapacity(int required)
    {
        var chunksRequired = (required + ChunkLength - 1) / ChunkLength;
        if (chunksRequired <= _chunks.Length)
        {
            return;
        }
        var maximumChunks = (_maximumLength + ChunkLength - 1) / ChunkLength;
        var capacity = Math.Min(
            maximumChunks,
            Math.Max(chunksRequired, Math.Max(1, _chunks.Length * 2)));
        Array.Resize(ref _chunks, capacity);
        Array.Resize(ref _receivedChunks, capacity);
    }

    // A byte is received only if its chunk exists AND its flag is set. The null test is
    // not an optimisation: an unallocated chunk is the representation of "nothing here",
    // and collapsing it to a zero byte would report every hole as delivered data.
    private bool IsReceived(int index)
    {
        var flags = _receivedChunks[index / ChunkLength];
        return flags is not null && flags[index % ChunkLength] != 0;
    }

    // Only ever called for an index IsReceived has just returned true for, which is what
    // makes the null-forgiving operator sound: the pair is allocated together in Write.
    private byte ByteAt(int index) => _chunks[index / ChunkLength]![index % ChunkLength];

    private void Write(int index, byte value)
    {
        var chunkIndex = index / ChunkLength;
        var chunk = _chunks[chunkIndex];
        if (chunk is null)
        {
            chunk = new byte[ChunkLength];
            _chunks[chunkIndex] = chunk;
            _receivedChunks[chunkIndex] = new byte[ChunkLength];
        }
        var offset = index % ChunkLength;
        chunk[offset] = value;
        _receivedChunks[chunkIndex]![offset] = 1;
    }
}
