using System.Globalization;
using System.Text;
using Xunit.Sdk;

namespace TlsClient.Tests.Wire;

internal static class Http2WireAssert
{
    public static string ToHex(ReadOnlySpan<byte> bytes)
    {
        var builder = new StringBuilder(bytes.Length * 3);
        foreach (var value in bytes)
        {
            if (builder.Length != 0)
            {
                builder.Append(' ');
            }
            builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
        }
        return builder.ToString();
    }

    public static void EqualBytes(byte[] expected, ReadOnlySpan<byte> actual, string what)
    {
        ArgumentNullException.ThrowIfNull(expected);

        if (expected.Length != actual.Length)
        {
            throw new XunitException(
                $"{what}: length mismatch — expected {expected.Length} bytes, got {actual.Length}.{Environment.NewLine}" +
                $"  expected: {ToHex(expected)}{Environment.NewLine}" +
                $"  actual:   {ToHex(actual)}");
        }

        for (var offset = 0; offset < expected.Length; offset++)
        {
            if (expected[offset] == actual[offset])
            {
                continue;
            }

            var start = Math.Max(0, offset - 4);
            var length = Math.Min(12, expected.Length - start);
            throw new XunitException(
                $"{what}: differs at offset {offset} — expected {expected[offset]:x2}, got {actual[offset]:x2}.{Environment.NewLine}" +
                $"  expected[{start}..]: {ToHex(expected.AsSpan(start, length))}{Environment.NewLine}" +
                $"  actual  [{start}..]: {ToHex(actual.Slice(start, length))}");
        }
    }

    /// <summary>
    /// Compares two frame lists by value. <see cref="CapturedFrame"/> is a record
    /// struct with a <c>byte[]</c> member, so <c>Assert.Equal</c> on frame lists
    /// compares payloads by reference and can never pass for two independently parsed
    /// or captured lists — this is the intended replacement.
    /// </summary>
    public static void EqualFrames(
        IReadOnlyList<CapturedFrame> expected,
        IReadOnlyList<CapturedFrame> actual,
        string what)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(actual);

        if (expected.Count != actual.Count)
        {
            throw new XunitException(
                $"{what}: frame count mismatch — expected {expected.Count}, got {actual.Count}.");
        }

        for (var index = 0; index < expected.Count; index++)
        {
            var expectedFrame = expected[index];
            var actualFrame = actual[index];
            var label = $"{what}: frame[{index}]";

            if (expectedFrame.Type != actualFrame.Type)
            {
                throw new XunitException(
                    $"{label}: type mismatch — expected {expectedFrame.Type}, got {actualFrame.Type}.");
            }
            if (expectedFrame.Flags != actualFrame.Flags)
            {
                throw new XunitException(
                    $"{label}: flags mismatch — expected 0x{expectedFrame.Flags:x2}, got 0x{actualFrame.Flags:x2}.");
            }
            if (expectedFrame.StreamId != actualFrame.StreamId)
            {
                throw new XunitException(
                    $"{label}: stream id mismatch — expected {expectedFrame.StreamId}, got {actualFrame.StreamId}.");
            }

            EqualBytes(expectedFrame.Payload, actualFrame.Payload, $"{label} payload");
        }
    }
}
