using System.Text;

namespace TlsClient;

internal sealed class BufferedHttpReader
{
    private readonly Stream _stream;
    private readonly byte[] _buffer = new byte[8192];
    private int _offset;
    private int _count;

    public BufferedHttpReader(Stream stream)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    /// <summary>
    /// Whether the read-ahead buffer still holds octets the caller has not consumed. A caller
    /// that abandons this reader and keeps using the underlying stream would lose them.
    /// </summary>
    public bool HasBufferedBytes => _offset < _count;

    public async ValueTask<HttpLine?> ReadLineAsync(
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        // Clamped, not just capped. A caller subtracts what it has already spent from its budget
        // — Http11ResponseReader takes the status line off the header allowance — and a maximal
        // line leaves that arithmetic negative, because WireLength counts the CRLF that
        // maximumBytes does not. new MemoryStream(-2) throws ArgumentOutOfRangeException, which
        // escapes the TlsHttpProtocolException contract ShouldRetryException classifies a
        // malformed peer response by. A zero budget instead reaches the limit check below and
        // throws the protocol exception every other malformed response throws.
        using var line = new MemoryStream(Math.Clamp(maximumBytes, 0, 256));
        var previousWasCarriageReturn = false;
        while (true)
        {
            var value = await ReadByteAsync(cancellationToken).ConfigureAwait(false);
            if (value < 0)
            {
                if (line.Length == 0 && !previousWasCarriageReturn)
                {
                    return null;
                }
                throw new EndOfStreamException("The HTTP stream ended in the middle of a line.");
            }

            if (previousWasCarriageReturn)
            {
                if (value != '\n')
                {
                    throw new TlsHttpProtocolException("HTTP lines must end with CRLF.");
                }
                return new HttpLine(Encoding.Latin1.GetString(line.ToArray()), checked((int)line.Length + 2));
            }

            if (value == '\r')
            {
                previousWasCarriageReturn = true;
                continue;
            }
            if (value == '\n')
            {
                throw new TlsHttpProtocolException("A bare LF is not a valid HTTP/1.1 line ending.");
            }
            if (line.Length >= maximumBytes)
            {
                throw new TlsHttpProtocolException("An HTTP line exceeded the configured limit.");
            }
            line.WriteByte((byte)value);
        }
    }

    public async ValueTask ReadExactlyAsync(
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var written = 0;
        while (written < destination.Length)
        {
            var read = await ReadAsync(destination[written..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The HTTP body ended before its declared length.");
            }
            written += read;
        }
    }

    public async ValueTask<int> ReadAsync(
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        if (destination.IsEmpty)
        {
            return 0;
        }
        if (_offset < _count)
        {
            var available = Math.Min(destination.Length, _count - _offset);
            _buffer.AsMemory(_offset, available).CopyTo(destination);
            _offset += available;
            return available;
        }

        return await _stream.ReadAsync(destination, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<int> ReadByteAsync(CancellationToken cancellationToken)
    {
        if (_offset == _count)
        {
            _count = await _stream.ReadAsync(_buffer, cancellationToken).ConfigureAwait(false);
            _offset = 0;
            if (_count == 0)
            {
                return -1;
            }
        }

        return _buffer[_offset++];
    }
}

internal sealed record HttpLine(string Text, int WireLength);
