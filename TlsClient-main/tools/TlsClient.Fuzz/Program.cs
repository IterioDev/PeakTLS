using System.IO.Compression;
using System.Text;
using System.Text.Json;
using TlsClient;

const int MaximumInputBytes = 64 * 1024;
string[] targets =
[
    "http1-response",
    "http2-frame",
    "hpack",
    "hpack-encode",
    "decompression",
    "proxy-http",
    "proxy-socks4",
    "proxy-socks5",
    "behavior-json",
    "clienthello",
    "headers",
];

if (args is ["--smoke", var iterationText] &&
    int.TryParse(iterationText, out var iterations) &&
    iterations is >= 1 and <= 1_000_000)
{
    await RunSmokeAsync(iterations);
    return;
}
if (args is not [var selectedTarget, var inputPath] || !targets.Contains(selectedTarget))
{
    Console.Error.WriteLine(
        "Usage: TlsClient.Fuzz <target> <input-file> | --smoke <iterations>\nTargets: " +
        string.Join(", ", targets));
    Environment.ExitCode = 2;
    return;
}

var file = new FileInfo(inputPath);
if (!file.Exists || file.Length > MaximumInputBytes)
{
    throw new ArgumentException($"Input must exist and be at most {MaximumInputBytes} bytes.");
}
await RunSafelyAsync(selectedTarget, await File.ReadAllBytesAsync(inputPath));

async Task RunSmokeAsync(int iterations)
{
    var random = new Random(0x544c5343);
    var perTarget = Math.Max(1, iterations / targets.Length);
    foreach (var target in targets)
    {
        var seed = CreateSeed(target);
        await RunSafelyAsync(target, seed);
        for (var index = 0; index < perTarget; index++)
        {
            await RunSafelyAsync(target, Mutate(seed, random));
        }
    }
    Console.WriteLine($"Fuzz smoke completed: {targets.Length * (perTarget + 1)} cases.");
}

async ValueTask RunSafelyAsync(string target, byte[] data)
{
    try
    {
        await RunTargetAsync(target, data);
    }
    catch (Exception exception) when (IsExpectedRejection(exception))
    {
    }
}

static async ValueTask RunTargetAsync(string target, byte[] data)
{
    switch (target)
    {
        case "http1-response":
            {
                await using var input = new MemoryStream(data, writable: false);
                var reader = new BufferedHttpReader(input);
                _ = await Http11ResponseReader.ReadAsync(
                    reader,
                    "GET",
                    maximumHeaderBytes: 8192,
                    maximumHeaderCount: 64,
                    maximumBodyBytes: MaximumInputBytes,
                    default);
                break;
            }
        case "http2-frame":
            _ = Http2FrameParser.ParseHeader(data, 16_384);
            break;
        case "hpack":
            {
                // One decoder over a sequence of length-prefixed blocks, so the
                // cross-block dynamic-table state machine — eviction, index drift, size
                // updates spanning blocks — is exercised rather than reset per input.
                var decoder = new HpackDecoder(4096);
                var cursor = 0;
                while (cursor < data.Length)
                {
                    var blockLength = Math.Min(data[cursor++], data.Length - cursor);
                    _ = decoder.Decode(data.AsSpan(cursor, blockLength), 16 * 1024);
                    cursor += blockLength;
                }
                break;
            }
        case "hpack-encode":
            RunHpackEncodeRoundTrip(data);
            break;
        case "decompression":
            {
                if (data.Length == 0)
                {
                    return;
                }
                var headers = new TlsHeaders();
                headers.Set("Content-Encoding", (data[0] % 3) switch
                {
                    0 => "gzip",
                    1 => "deflate",
                    _ => "br",
                });
                _ = await ResponseDecompressor.DecodeAsync(
                    data[1..],
                    headers,
                    maximumBytes: 128 * 1024,
                    default);
                break;
            }
        case "proxy-http":
            await RunProxyAsync(data, TlsProxy.Http("http://127.0.0.1:8080"));
            break;
        case "proxy-socks5":
            await RunProxyAsync(data, TlsProxy.Socks5("socks5://127.0.0.1:1080"));
            break;
        case "behavior-json":
            _ = TlsHttpBehaviorProfile.ImportJson(
                Encoding.UTF8.GetString(data),
                MaximumInputBytes);
            break;
        case "clienthello":
            _ = TlsFingerprintDiagnostics.InspectHandshake(data);
            break;
        case "headers":
            {
                var separator = Array.IndexOf(data, (byte)0);
                var nameBytes = separator < 0 ? data : data[..separator];
                var valueBytes = separator < 0 ? [] : data[(separator + 1)..];
                var headers = new TlsHeaders();
                headers.Add(
                    Encoding.Latin1.GetString(nameBytes),
                    Encoding.Latin1.GetString(valueBytes));
                break;
            }
        default:
            throw new ArgumentOutOfRangeException(nameof(target));
    }
}

static async ValueTask RunProxyAsync(byte[] data, TlsProxy proxy)
{
    await using var stream = new ReplayDuplexStream(data);
    await ProxyTunnel.EstablishAsync(
        stream,
        new Uri("https://example.com:443"),
        proxy,
        maximumHeaderBytes: 8192,
        default);
}

/// <summary>
/// Encodes a header list under a policy the input chooses, decodes it, and requires the
/// list to come back intact. The policy space is far too large for a fixed set of cases,
/// so representation, Huffman mode, name index preference, and dynamic table use are all
/// taken from the input.
/// </summary>
static void RunHpackEncodeRoundTrip(byte[] data)
{
    if (data.Length < 7)
    {
        return;
    }

    var options = new TlsHpackOptions
    {
        DefaultRepresentation = (TlsHpackRepresentation)(data[0] % 4),
        // Indexed is not a legal fallback, so the three literal forms start at 1.
        IndexedFallback = (TlsHpackRepresentation)(1 + data[1] % 3),
        UseDynamicTable = (data[2] & 1) != 0,
        Huffman = (TlsHpackHuffman)(data[3] % 4),
        NameIndex = (TlsHpackNameIndex)(data[4] % 3),
        MultiValue = (TlsHpackMultiValue)(data[5] % 2),
    };

    var headers = BuildFuzzHeaders(data.AsSpan(6));
    if (headers.Count == 0)
    {
        return;
    }

    var encoder = new HpackEncoder(options.Snapshot());
    var decoded = new HpackDecoder(4096).Decode(encoder.Encode(headers), 1024 * 1024);
    if (decoded.Count != headers.Count)
    {
        throw new InvalidProgramException(
            $"HPACK round-trip lost fields: encoded {headers.Count}, decoded {decoded.Count}.");
    }
    for (var index = 0; index < headers.Count; index++)
    {
        if (!string.Equals(decoded[index].Name, headers[index].Name, StringComparison.Ordinal) ||
            !string.Equals(decoded[index].Value, headers[index].Value, StringComparison.Ordinal))
        {
            throw new InvalidProgramException(
                $"HPACK round-trip altered field {index}: encoded " +
                $"'{headers[index].Name}: {headers[index].Value}', decoded " +
                $"'{decoded[index].Name}: {decoded[index].Value}'.");
        }
    }
}

static List<HpackHeader> BuildFuzzHeaders(ReadOnlySpan<byte> data)
{
    string[] names =
    [
        ":method", ":path", ":scheme", ":authority", "cookie", "authorization",
        "accept", "accept-encoding", "user-agent", "x-one", "x-two",
    ];
    var headers = new List<HpackHeader>();
    for (var index = 0; index + 1 < data.Length && headers.Count < 64; index += 2)
    {
        // Values are built rather than sliced: an arbitrary byte run would contain NUL,
        // CR, or LF, which the encoder rejects by design, and a rejection would tell us
        // nothing about the policy under test.
        var value = new string((char)('a' + data[index + 1] % 26), 1 + data[index + 1] % 8);
        headers.Add(new HpackHeader(names[data[index] % names.Length], value));
    }
    return headers;
}

static bool IsExpectedRejection(Exception exception) => exception is
    ArgumentException or
    FormatException or
    OverflowException or
    InvalidDataException or
    IOException or
    HttpRequestException or
    JsonException or
    NotSupportedException or
    InvalidOperationException;

static byte[] CreateSeed(string target) => target switch
{
    "http1-response" => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"u8.ToArray(),
    "http2-frame" => [0, 0, 0, 4, 0, 0, 0, 0, 0],
    // Length-prefixed blocks, matching the multi-block "hpack" target: a one-octet block
    // holding the indexed field 0x88, then the six-octet integer whose continuation run
    // overflowed a 32-bit shift and left the decoder indexing the static table negatively.
    "hpack" => [0x01, 0x88, 0x06, 0xFF, 0x80, 0x80, 0x80, 0x80, 0x7F],
    "hpack-encode" => [0, 1, 1, 0, 0, 0, 5, 1, 9],
    "decompression" => CreateCompressedSeed(),
    "proxy-http" => "HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(),
    "proxy-socks4" => [0, 0x5a, 0, 0, 0, 0, 0, 0],
    "proxy-socks5" => [5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0x01, 0xbb],
    "behavior-json" => Encoding.UTF8.GetBytes(
        TlsHttpBehaviorProfile.Capture("seed", new TlsSessionOptions()).ExportJson(false)),
    "clienthello" => TlsClientHello.BuildSnapshotForTesting(
        TlsProfiles.Modern,
        "example.com",
        new byte[32]).GetEncodedHandshake(),
    "headers" => "x-seed\0value"u8.ToArray(),
    _ => [],
};

static byte[] CreateCompressedSeed()
{
    using var output = new MemoryStream();
    output.WriteByte(0);
    using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
    {
        gzip.Write("seed payload"u8);
    }
    return output.ToArray();
}

static byte[] Mutate(byte[] seed, Random random)
{
    var length = random.Next(0, Math.Min(MaximumInputBytes, Math.Max(32, seed.Length * 3)) + 1);
    var value = new byte[length];
    var copied = Math.Min(seed.Length, value.Length);
    seed.AsSpan(0, copied).CopyTo(value);
    if (value.Length != 0)
    {
        var mutations = random.Next(1, Math.Min(32, value.Length) + 1);
        for (var index = 0; index < mutations; index++)
        {
            value[random.Next(value.Length)] = (byte)random.Next(256);
        }
    }
    return value;
}

internal sealed class ReplayDuplexStream(byte[] input) : Stream
{
    private readonly MemoryStream _input = new(input, writable: false);

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public override int Read(byte[] buffer, int offset, int count) =>
        _input.Read(buffer, offset, count);

    public override ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default) =>
        _input.ReadAsync(buffer, cancellationToken);

    public override void Write(byte[] buffer, int offset, int count)
    {
    }

    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default) =>
        ValueTask.CompletedTask;

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _input.Dispose();
        }
        base.Dispose(disposing);
    }
}
