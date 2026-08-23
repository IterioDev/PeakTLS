using System.Buffers.Binary;

namespace TlsClient.Tests.Wire;

/// <summary>
/// A single HTTP/2 frame captured from either a live loopback connection or a parsed
/// hex dump.
/// </summary>
/// <remarks>
/// This is a <c>record struct</c> with a <c>byte[]</c> member, so its generated
/// <see cref="IEquatable{T}"/> implementation compares <see cref="Payload"/> by
/// reference, not by value — two frames with byte-identical payloads from separate
/// arrays are unequal under <c>==</c> or <c>Assert.Equal</c>. Use
/// <see cref="Http2WireAssert.EqualFrames"/> to compare frame lists by value.
/// </remarks>
internal readonly record struct CapturedFrame(
    Http2FrameType Type,
    byte Flags,
    int StreamId,
    byte[] Payload);

/// <summary>
/// Server-side HTTP/2 framing primitives for loopback wire tests. Every frame read from
/// the client is retained in <see cref="ClientFrames"/> in arrival order.
/// </summary>
internal sealed class Http2WireServer(Stream stream)
{
    private readonly List<CapturedFrame> _clientFrames = [];

    public IReadOnlyList<CapturedFrame> ClientFrames => _clientFrames;

    public async Task<byte[]> ReadPrefaceAsync(CancellationToken cancellationToken)
    {
        var preface = new byte[24];
        await stream.ReadExactlyAsync(preface, cancellationToken).ConfigureAwait(false);
        return preface;
    }

    /// <summary>
    /// Issues exactly one read and returns the octets it delivered. The TLS stream
    /// surfaces at most one record per read, so this count is where the client flushed —
    /// something the <see cref="ReadFrameAsync"/> path cannot show, since ReadExactly asks
    /// for a frame-shaped length and so reports the reader's shape rather than the
    /// writer's.
    /// </summary>
    public async Task<int> ReadOnceAsync(int maximum, CancellationToken cancellationToken)
    {
        var buffer = new byte[maximum];
        return await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public async Task<CapturedFrame> ReadFrameAsync(CancellationToken cancellationToken)
    {
        var header = new byte[9];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        var length = header[0] << 16 | header[1] << 8 | header[2];
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        var frame = new CapturedFrame(
            (Http2FrameType)header[3],
            header[4],
            BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(5)) & 0x7fff_ffff,
            payload);
        _clientFrames.Add(frame);
        return frame;
    }

    /// <summary>Reads frames until one of <paramref name="type"/> arrives and returns it.</summary>
    public async Task<CapturedFrame> ReadUntilAsync(
        Http2FrameType type,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
            if (frame.Type == type)
            {
                return frame;
            }
        }
    }

    public async Task WriteFrameAsync(
        Http2FrameType type,
        byte flags,
        int streamId,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        header[0] = (byte)(payload.Length >> 16);
        header[1] = (byte)(payload.Length >> 8);
        header[2] = (byte)payload.Length;
        header[3] = (byte)type;
        header[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(5), streamId);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    public Task FlushAsync(CancellationToken cancellationToken) =>
        stream.FlushAsync(cancellationToken);
}
