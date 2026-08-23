using System.Buffers;
using System.Text;

namespace TlsClient;

internal readonly record struct HpackHeader(string Name, string Value);

internal static class HpackStaticTable
{
    public static readonly HpackHeader[] Entries =
    [
        new(":authority", ""),
        new(":method", "GET"),
        new(":method", "POST"),
        new(":path", "/"),
        new(":path", "/index.html"),
        new(":scheme", "http"),
        new(":scheme", "https"),
        new(":status", "200"),
        new(":status", "204"),
        new(":status", "206"),
        new(":status", "304"),
        new(":status", "400"),
        new(":status", "404"),
        new(":status", "500"),
        new("accept-charset", ""),
        new("accept-encoding", "gzip, deflate"),
        new("accept-language", ""),
        new("accept-ranges", ""),
        new("accept", ""),
        new("access-control-allow-origin", ""),
        new("age", ""),
        new("allow", ""),
        new("authorization", ""),
        new("cache-control", ""),
        new("content-disposition", ""),
        new("content-encoding", ""),
        new("content-language", ""),
        new("content-length", ""),
        new("content-location", ""),
        new("content-range", ""),
        new("content-type", ""),
        new("cookie", ""),
        new("date", ""),
        new("etag", ""),
        new("expect", ""),
        new("expires", ""),
        new("from", ""),
        new("host", ""),
        new("if-match", ""),
        new("if-modified-since", ""),
        new("if-none-match", ""),
        new("if-range", ""),
        new("if-unmodified-since", ""),
        new("last-modified", ""),
        new("link", ""),
        new("location", ""),
        new("max-forwards", ""),
        new("proxy-authenticate", ""),
        new("proxy-authorization", ""),
        new("range", ""),
        new("referer", ""),
        new("refresh", ""),
        new("retry-after", ""),
        new("server", ""),
        new("set-cookie", ""),
        new("strict-transport-security", ""),
        new("transfer-encoding", ""),
        new("user-agent", ""),
        new("vary", ""),
        new("via", ""),
        new("www-authenticate", ""),
    ];
}

internal sealed class HpackEncoder
{
    private readonly TlsHpackConfiguration _policy;
    private readonly List<HpackHeader> _dynamicTable = [];
    private readonly Queue<uint> _pendingTableSizeUpdates = new();
    private int _dynamicTableSize;
    private uint _maximumDynamicTableSize = 4096;
    private uint _peerMaximumDynamicTableSize = 4096;
    private bool _hasEncodedBlock;

    public HpackEncoder(TlsHpackConfiguration policy)
    {
        _policy = policy;
    }

    public void SetMaximumDynamicTableSize(uint value)
    {
        var boundedValue = Math.Min(value, 16U * 1024 * 1024);
        if (_peerMaximumDynamicTableSize == boundedValue)
        {
            return;
        }
        _peerMaximumDynamicTableSize = boundedValue;
        if (_policy.TableSizeUpdate == TlsHpackTableSizeUpdate.OnPeerSettingsChange)
        {
            QueueTableSizeUpdates();
        }
    }

    public byte[] Encode(IEnumerable<HpackHeader> headers)
    {
        var output = new ArrayBufferWriter<byte>();
        if (!_hasEncodedBlock)
        {
            _hasEncodedBlock = true;
            if (_policy.TableSizeUpdate == TlsHpackTableSizeUpdate.BeforeFirstRequest)
            {
                QueueTableSizeUpdates();
            }
        }

        // RFC 7541 section 4.2 permits consecutive updates, and every queued value is
        // applied to this encoder's own table as it is emitted, so the size the peer is
        // told about and the size evictions are computed against never diverge.
        while (_pendingTableSizeUpdates.TryDequeue(out var size))
        {
            if (size > _peerMaximumDynamicTableSize)
            {
                throw new HttpRequestException(
                    $"A declared HPACK table size update of {size} exceeds the peer's " +
                    $"advertised SETTINGS_HEADER_TABLE_SIZE of {_peerMaximumDynamicTableSize}. " +
                    "RFC 7541 section 6.3 makes that a COMPRESSION_ERROR at the peer.");
            }
            WriteInteger(output, checked((int)size), 5, 0x20);
            _maximumDynamicTableSize = size;
            Evict();
        }
        foreach (var header in headers)
        {
            ValidateHeader(header);
            var representation = _policy.PerHeader.TryGetValue(header.Name, out var perHeader)
                ? perHeader
                : _policy.DefaultRepresentation;

            // An indexed field is only expressible when the table already holds the exact
            // pair. Everything else falls back to the declared literal form, which
            // Snapshot() has already rejected as Indexed, so this cannot loop.
            if (representation == TlsHpackRepresentation.Indexed)
            {
                var exactIndex = FindExact(header.Name, header.Value);
                if (exactIndex != 0)
                {
                    WriteInteger(output, exactIndex, 7, 0x80);
                    continue;
                }
                representation = _policy.IndexedFallback;
            }

            // A field that resolved to a literal form stays literal even when the table
            // holds an exact match: the representation is the persona's declared wire
            // image, not an optimization the encoder is free to undo.
            var nameIndex = ResolveNameIndex(header.Name);
            var (prefixBits, prefixMask) = representation switch
            {
                TlsHpackRepresentation.LiteralIncrementalIndexing => (6, (byte)0x40),
                TlsHpackRepresentation.LiteralWithoutIndexing => (4, (byte)0x00),
                TlsHpackRepresentation.LiteralNeverIndexed => (4, (byte)0x10),
                _ => throw new InvalidOperationException(
                    $"Unhandled HPACK representation {representation}."),
            };
            WriteInteger(output, nameIndex, prefixBits, prefixMask);

            var huffman = _policy.PerHeaderHuffman.TryGetValue(header.Name, out var perHeaderHuffman)
                ? perHeaderHuffman
                : _policy.Huffman;
            if (nameIndex == 0)
            {
                WriteString(output, header.Name, huffman);
            }
            WriteString(output, header.Value, huffman);

            // RFC 7541 sections 6.2.2 and 6.2.3 require the other two literal forms to
            // leave the table untouched, so only incremental indexing inserts.
            if (representation == TlsHpackRepresentation.LiteralIncrementalIndexing &&
                _policy.UseDynamicTable)
            {
                Add(header);
            }
        }
        return output.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Queues the size updates this policy declares. An empty
    /// <see cref="TlsHpackConfiguration.TableSizeUpdateValues"/> means follow the peer,
    /// which is what an encoder with nothing of its own to say does.
    /// </summary>
    private void QueueTableSizeUpdates()
    {
        if (_policy.TableSizeUpdateValues.Length == 0)
        {
            _pendingTableSizeUpdates.Enqueue(_peerMaximumDynamicTableSize);
            return;
        }
        foreach (var value in _policy.TableSizeUpdateValues)
        {
            _pendingTableSizeUpdates.Enqueue(value);
        }
    }

    /// <summary>
    /// Resolves the table index used for a name-only reference, or 0 when the name must
    /// be written as a literal string.
    /// </summary>
    private int ResolveNameIndex(string name)
    {
        if (_policy.PerHeaderNameIndex.TryGetValue(name, out var declared))
        {
            return declared;
        }
        return _policy.NameIndex switch
        {
            TlsHpackNameIndex.HighestStatic => FindHighestStaticName(name) is var highest &&
                highest != 0
                    ? highest
                    : FindDynamicName(name),
            TlsHpackNameIndex.MostRecentDynamic => FindDynamicName(name) is var dynamic &&
                dynamic != 0
                    ? dynamic
                    : FindLowestStaticName(name),
            _ => FindName(name),
        };
    }

    private static int FindLowestStaticName(string name)
    {
        for (var index = 0; index < HpackStaticTable.Entries.Length; index++)
        {
            if (HpackStaticTable.Entries[index].Name == name)
            {
                return index + 1;
            }
        }
        return 0;
    }

    private static int FindHighestStaticName(string name)
    {
        for (var index = HpackStaticTable.Entries.Length - 1; index >= 0; index--)
        {
            if (HpackStaticTable.Entries[index].Name == name)
            {
                return index + 1;
            }
        }
        return 0;
    }

    private int FindDynamicName(string name)
    {
        for (var index = 0; index < _dynamicTable.Count; index++)
        {
            if (_dynamicTable[index].Name == name)
            {
                return HpackStaticTable.Entries.Length + index + 1;
            }
        }
        return 0;
    }

    private int FindExact(string name, string value)
    {
        for (var index = 0; index < HpackStaticTable.Entries.Length; index++)
        {
            var header = HpackStaticTable.Entries[index];
            if (header.Name == name && header.Value == value)
            {
                return index + 1;
            }
        }
        for (var index = 0; index < _dynamicTable.Count; index++)
        {
            var header = _dynamicTable[index];
            if (header.Name == name && header.Value == value)
            {
                return HpackStaticTable.Entries.Length + index + 1;
            }
        }
        return 0;
    }

    private int FindName(string name)
    {
        for (var index = 0; index < HpackStaticTable.Entries.Length; index++)
        {
            if (HpackStaticTable.Entries[index].Name == name)
            {
                return index + 1;
            }
        }
        for (var index = 0; index < _dynamicTable.Count; index++)
        {
            if (_dynamicTable[index].Name == name)
            {
                return HpackStaticTable.Entries.Length + index + 1;
            }
        }
        return 0;
    }

    private void Add(HpackHeader header)
    {
        var size = HeaderSize(header);
        if (size > _maximumDynamicTableSize)
        {
            _dynamicTable.Clear();
            _dynamicTableSize = 0;
            return;
        }
        _dynamicTable.Insert(0, header);
        _dynamicTableSize += size;
        Evict();
    }

    private void Evict()
    {
        while (_dynamicTableSize > _maximumDynamicTableSize && _dynamicTable.Count != 0)
        {
            var last = _dynamicTable[^1];
            _dynamicTable.RemoveAt(_dynamicTable.Count - 1);
            _dynamicTableSize -= HeaderSize(last);
        }
    }

    private static int HeaderSize(HpackHeader header) =>
        checked(32 + Encoding.UTF8.GetByteCount(header.Name) + Encoding.UTF8.GetByteCount(header.Value));

    private static void ValidateHeader(HpackHeader header)
    {
        if (header.Name.Length == 0 || header.Name.Any(character =>
                character is >= 'A' and <= 'Z' || character is '\0' or '\r' or '\n'))
        {
            throw new HttpRequestException("HTTP/2 header names must be lowercase tokens.");
        }
        if (header.Value.Any(character => character is '\0' or '\r' or '\n'))
        {
            throw new HttpRequestException("HTTP/2 header values cannot contain NUL, CR, or LF.");
        }
    }

    private static void WriteInteger(
        IBufferWriter<byte> output,
        int value,
        int prefixBits,
        byte prefixMask)
    {
        var maximumPrefixValue = (1 << prefixBits) - 1;
        if (value < maximumPrefixValue)
        {
            WriteByte(output, (byte)(prefixMask | value));
            return;
        }

        WriteByte(output, (byte)(prefixMask | maximumPrefixValue));
        value -= maximumPrefixValue;
        while (value >= 128)
        {
            WriteByte(output, (byte)((value & 0x7f) | 0x80));
            value >>= 7;
        }
        WriteByte(output, (byte)value);
    }

    private static void WriteString(
        IBufferWriter<byte> output,
        string value,
        TlsHpackHuffman huffman)
    {
        var source = Encoding.UTF8.GetBytes(value);
        var encodedBitLength = 0;
        foreach (var item in source)
        {
            encodedBitLength = checked(encodedBitLength + HpackHuffman.Encode(item).bitLength);
        }
        var encodedByteLength = (encodedBitLength + 7) / 8;
        var useHuffman = huffman switch
        {
            TlsHpackHuffman.Never => false,
            TlsHpackHuffman.Always => true,
            TlsHpackHuffman.WhenNotLonger => encodedByteLength <= source.Length,
            _ => encodedByteLength < source.Length,
        };
        if (!useHuffman)
        {
            WriteInteger(output, source.Length, 7, 0);
            output.Write(source);
            return;
        }

        WriteInteger(output, encodedByteLength, 7, 0x80);
        ulong accumulator = 0;
        var bits = 0;
        foreach (var item in source)
        {
            var (encoded, bitLength) = HpackHuffman.Encode(item);
            accumulator = accumulator << bitLength | encoded >> (32 - bitLength);
            bits += bitLength;
            while (bits >= 8)
            {
                bits -= 8;
                WriteByte(output, (byte)(accumulator >> bits));
                accumulator &= bits == 0 ? 0 : (1UL << bits) - 1;
            }
        }
        if (bits != 0)
        {
            var padding = 8 - bits;
            WriteByte(output, (byte)(accumulator << padding | (uint)((1 << padding) - 1)));
        }
    }

    private static void WriteByte(IBufferWriter<byte> output, byte value)
    {
        var span = output.GetSpan(1);
        span[0] = value;
        output.Advance(1);
    }
}

internal sealed class HpackDecoder
{
    private readonly List<HpackHeader> _dynamicTable = [];
    private readonly uint _configuredMaximumDynamicTableSize;
    private uint _maximumDynamicTableSize;
    private int _dynamicTableSize;

    public HpackDecoder(uint maximumDynamicTableSize)
    {
        _configuredMaximumDynamicTableSize = maximumDynamicTableSize;
        _maximumDynamicTableSize = Math.Min(maximumDynamicTableSize, 4096);
    }

    public IReadOnlyList<HpackHeader> Decode(ReadOnlySpan<byte> block, uint maximumHeaderListSize)
    {
        var headers = new List<HpackHeader>();
        var offset = 0;
        long headerListSize = 0;
        var mayResize = true;
        while (offset < block.Length)
        {
            var first = block[offset];
            HpackHeader header;
            // Whether this representation is a literal with incremental indexing, which RFC 7541
            // section 6.2.1 adds to the dynamic table. The insertion is deferred to the bottom of
            // the loop so a block rejected for its header-list size leaves the table untouched:
            // section 4.1 makes the table a mirror of the encoder's, and mutating it on a block
            // this decoder refuses is the shape that desynchronises the two ends. Today the
            // refusal is a connection error and the decoder is discarded with the connection, so
            // this is ordering hygiene rather than a live defect.
            var incrementalIndexing = false;
            if ((first & 0x80) != 0)
            {
                var index = ReadInteger(block, ref offset, 7);
                if (index == 0)
                {
                    throw HpackDecodingError.Create("HPACK indexed field used index zero.");
                }
                header = Get(index);
            }
            else if ((first & 0x40) != 0)
            {
                var name = ReadName(block, ref offset, 6);
                var value = ReadString(block, ref offset);
                header = new HpackHeader(name, value);
                incrementalIndexing = true;
            }
            else if ((first & 0x20) != 0)
            {
                if (!mayResize)
                {
                    throw HpackDecodingError.Create(
                        "An HPACK table-size update appeared after a header field.");
                }
                var size = ReadInteger(block, ref offset, 5);
                // RFC 7541 section 6.3 pins the ceiling to "the last value of the
                // SETTINGS_HEADER_TABLE_SIZE parameter ... received from the decoder and
                // acknowledged by the encoder". This compares against the configured value from
                // the very first field block, before any acknowledgement has arrived, so it errs
                // lenient inside that window: it accepts an update a strict reading would reject
                // until the peer has acknowledged our SETTINGS. Deliberate. The value is still
                // bounded by what this client advertises, so the window admits nothing larger
                // than the table it has already sized itself for, and tracking the
                // acknowledgement would mean threading connection state into the decoder for no
                // bound it does not already have.
                if ((uint)size > _configuredMaximumDynamicTableSize)
                {
                    throw HpackDecodingError.Create(
                        "The peer exceeded the advertised HPACK table size.");
                }
                _maximumDynamicTableSize = (uint)size;
                Evict();
                continue;
            }
            else
            {
                // The never-indexed bit is a re-encoding instruction for an intermediary.
                // TlsClient never re-encodes what it decodes, so the distinction is not
                // carried past this point.
                var name = ReadName(block, ref offset, 4);
                var value = ReadString(block, ref offset);
                header = new HpackHeader(name, value);
            }

            mayResize = false;
            headerListSize = checked(
                headerListSize + 32 + Encoding.UTF8.GetByteCount(header.Name) +
                Encoding.UTF8.GetByteCount(header.Value));
            if (headerListSize > maximumHeaderListSize)
            {
                throw HpackDecodingError.Create("The decoded HTTP/2 header list is too large.");
            }
            if (incrementalIndexing)
            {
                Add(header);
            }
            headers.Add(header);
        }
        return headers;
    }

    private string ReadName(ReadOnlySpan<byte> block, ref int offset, int prefixBits)
    {
        var index = ReadInteger(block, ref offset, prefixBits);
        return index == 0 ? ReadString(block, ref offset) : Get(index).Name;
    }

    private static int ReadInteger(ReadOnlySpan<byte> source, ref int offset, int prefixBits)
    {
        if ((uint)offset >= (uint)source.Length)
        {
            throw HpackDecodingError.Create("The HPACK block ended inside an integer.");
        }
        var maximumPrefixValue = (1 << prefixBits) - 1;
        var value = source[offset++] & maximumPrefixValue;
        if (value < maximumPrefixValue)
        {
            return value;
        }

        // The accumulator is widened and the shift ceiling lowered to 21 because C#'s
        // `checked` governs the arithmetic operators and the numeric conversions but not
        // `<<`: at a shift of 28 an int `127 << 28` truncated silently to -268435456, the
        // checked addition then saw no overflow, and the negative result reached the header
        // table. RFC 7541 section 7.4 requires "a limit for the values it accepts for
        // integers, as well as for the encoded length", and section 4.3 makes any decoding
        // error a connection error of type COMPRESSION_ERROR — so the limit is enforced
        // here rather than left to the caller. Four continuation octets still reach
        // 2^28-1, orders of magnitude past any length or index this decoder can use.
        var shift = 0;
        long accumulated = value;
        while (true)
        {
            if ((uint)offset >= (uint)source.Length || shift > 21)
            {
                throw HpackDecodingError.Create("The HPACK integer is truncated or too large.");
            }
            var next = source[offset++];
            accumulated += (long)(next & 0x7f) << shift;
            if (accumulated > int.MaxValue)
            {
                throw HpackDecodingError.Create("The HPACK integer is too large.");
            }
            if ((next & 0x80) == 0)
            {
                return (int)accumulated;
            }
            shift += 7;
        }
    }

    private static string ReadString(ReadOnlySpan<byte> block, ref int offset)
    {
        if ((uint)offset >= (uint)block.Length)
        {
            throw HpackDecodingError.Create("The HPACK block ended before a string.");
        }
        var huffman = (block[offset] & 0x80) != 0;
        var length = ReadInteger(block, ref offset, 7);
        if (length < 0 || length > block.Length - offset)
        {
            throw HpackDecodingError.Create("The HPACK string length exceeds its header block.");
        }
        var source = block.Slice(offset, length);
        offset += length;
        if (!huffman)
        {
            return DecodeUtf8(source);
        }

        var destination = new byte[Math.Max(32, checked(length * 2))];
        var decodedLength = HpackHuffman.Decode(source, ref destination);
        return DecodeUtf8(destination.AsSpan(0, decodedLength));
    }

    private static string DecodeUtf8(ReadOnlySpan<byte> value)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(value);
        }
        catch (DecoderFallbackException exception)
        {
            throw HpackDecodingError.Create("An HPACK string is not valid UTF-8.", exception);
        }
    }

    private HpackHeader Get(int index)
    {
        if (index <= HpackStaticTable.Entries.Length)
        {
            return HpackStaticTable.Entries[index - 1];
        }
        var dynamicIndex = index - HpackStaticTable.Entries.Length - 1;
        if ((uint)dynamicIndex >= (uint)_dynamicTable.Count)
        {
            throw HpackDecodingError.Create("The HPACK index is outside the header table.");
        }
        return _dynamicTable[dynamicIndex];
    }

    private void Add(HpackHeader header)
    {
        var size = HeaderSize(header);
        if (size > _maximumDynamicTableSize)
        {
            _dynamicTable.Clear();
            _dynamicTableSize = 0;
            return;
        }
        _dynamicTable.Insert(0, header);
        _dynamicTableSize += size;
        Evict();
    }

    private void Evict()
    {
        while (_dynamicTableSize > _maximumDynamicTableSize && _dynamicTable.Count != 0)
        {
            var last = _dynamicTable[^1];
            _dynamicTable.RemoveAt(_dynamicTable.Count - 1);
            _dynamicTableSize -= HeaderSize(last);
        }
    }

    private static int HeaderSize(HpackHeader header) =>
        checked(32 + Encoding.UTF8.GetByteCount(header.Name) + Encoding.UTF8.GetByteCount(header.Value));
}

/// <summary>
/// Builds the exception every HPACK decoding failure raises.
/// </summary>
/// <remarks>
/// RFC 9113 section 4.3: "A decoding error in a field block MUST be treated as a connection
/// error (Section 5.4.1) of type COMPRESSION_ERROR." The scope is genuinely connection-wide
/// here, unlike the malformed-message rules of section 8.1.1: the dynamic table is shared by
/// every stream on the connection and cannot be resynchronised once a block has been
/// misparsed, so only the code was ever wrong.
/// </remarks>
internal static class HpackDecodingError
{
    public static TlsHttpProtocolException Create(string message) =>
        new(message) { Http2ErrorCode = Http2ErrorCode.CompressionError };

    public static TlsHttpProtocolException Create(string message, Exception innerException) =>
        new(message, innerException) { Http2ErrorCode = Http2ErrorCode.CompressionError };
}
