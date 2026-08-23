using System.Diagnostics.CodeAnalysis;

namespace TlsClient.Tests.Wire;

public sealed class RecordingStreamTests
{
    /// <summary>
    /// Minimal stream that throws on WriteAsync to test failure recording.
    /// </summary>
    private sealed class ThrowingStream : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new InvalidOperationException("Write failed");

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask;
            throw new InvalidOperationException("WriteAsync failed");
        }

        public override void Flush() { }
    }

    [Fact]
    public async Task RecordsBytesReadAcrossMultipleCalls()
    {
        var source = new MemoryStream([1, 2, 3, 4, 5, 6]);
        await using var recording = new RecordingStream(source);

        var first = new byte[2];
        var second = new byte[4];
        await recording.ReadExactlyAsync(first);
        await recording.ReadExactlyAsync(second);

        Assert.Equal(new byte[] { 1, 2 }, first);
        Assert.Equal(new byte[] { 3, 4, 5, 6 }, second);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6 }, recording.ReadBytes);
        Assert.Empty(recording.WrittenBytes);
    }

    [Fact]
    public async Task RecordsBytesWrittenSeparatelyFromBytesRead()
    {
        var inner = new MemoryStream();
        await using var recording = new RecordingStream(inner);

        await recording.WriteAsync(new byte[] { 9, 8 });
        await recording.WriteAsync(new byte[] { 7 });

        Assert.Equal(new byte[] { 9, 8, 7 }, recording.WrittenBytes);
        Assert.Empty(recording.ReadBytes);
        Assert.Equal(new byte[] { 9, 8, 7 }, inner.ToArray());
    }

    [Fact]
    public async Task LeaveOpenFalseDisposesInnerStream()
    {
        var inner = new MemoryStream();
        var recording = new RecordingStream(inner, leaveOpen: false);

        await recording.DisposeAsync();

        Assert.Throws<ObjectDisposedException>(() => inner.Position);
    }

    [Fact]
    public async Task FailedWritesAreNotRecorded()
    {
        var inner = new ThrowingStream();
        await using var recording = new RecordingStream(inner);

        var bytes = new byte[] { 1, 2, 3 };
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => recording.WriteAsync(bytes).AsTask());

        Assert.Equal("WriteAsync failed", exception.Message);
        Assert.Empty(recording.WrittenBytes);
    }

    [Fact]
    public async Task RecordsTheLengthOfEachSuccessfulRead()
    {
        var source = new MemoryStream([1, 2, 3, 4, 5, 6]);
        await using var recording = new RecordingStream(source);

        var first = new byte[2];
        var second = new byte[4];
        await recording.ReadExactlyAsync(first);
        await recording.ReadExactlyAsync(second);

        Assert.Equal([2, 4], recording.ReadSegmentLengths);
    }

    [Fact]
    [SuppressMessage(
        "Reliability",
        "CA2022:Avoid inexact reads with stream.Read",
        Justification = "Intentionally reads without checking the returned length, to prove an end-of-stream read is not recorded as a segment.")]
    public async Task DoesNotRecordASegmentForAnEndOfStreamRead()
    {
        var source = new MemoryStream([1]);
        await using var recording = new RecordingStream(source);

        var buffer = new byte[4];
        await recording.ReadAsync(buffer);
        await recording.ReadAsync(buffer);

        Assert.Equal([1], recording.ReadSegmentLengths);
    }
}
