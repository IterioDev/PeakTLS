namespace TlsClient.Tests.Wire;

/// <summary>
/// Forwards every operation to an inner stream while recording the bytes that pass
/// through in each direction. Used to capture the exact decrypted HTTP/2 byte stream
/// a client sent.
/// </summary>
internal sealed class RecordingStream : Stream
{
    private readonly Stream _inner;
    private readonly bool _leaveOpen;
    private readonly MemoryStream _read = new();
    private readonly MemoryStream _written = new();
    private readonly List<int> _readSegments = [];
    private readonly Lock _sync = new();

    public RecordingStream(Stream inner, bool leaveOpen = true)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;
        _leaveOpen = leaveOpen;
    }

    public byte[] ReadBytes
    {
        get
        {
            lock (_sync)
            {
                return _read.ToArray();
            }
        }
    }

    public byte[] WrittenBytes
    {
        get
        {
            lock (_sync)
            {
                return _written.ToArray();
            }
        }
    }

    public IReadOnlyList<int> ReadSegmentLengths
    {
        get
        {
            lock (_sync)
            {
                return _readSegments.ToArray();
            }
        }
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => _inner.CanWrite;
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
        var read = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (read > 0)
        {
            lock (_sync)
            {
                _read.Write(buffer.Span[..read]);
                _readSegments.Add(read);
            }
        }
        return read;
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        // Record only after the write is confirmed, mirroring ReadAsync. Recording
        // first would let a cancelled or failed write leave bytes in WrittenBytes that
        // never reached the wire, which breaks the byte-equality guarantee the whole
        // harness exists to provide.
        await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        lock (_sync)
        {
            _written.Write(buffer.Span);
        }
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) =>
        _inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_leaveOpen)
        {
            _inner.Dispose();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (!_leaveOpen)
        {
            await _inner.DisposeAsync().ConfigureAwait(false);
        }
        await base.DisposeAsync().ConfigureAwait(false);
    }
}
