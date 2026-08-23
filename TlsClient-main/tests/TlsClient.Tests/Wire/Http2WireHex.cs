using System.Buffers.Binary;
using System.Text;

namespace TlsClient.Tests.Wire;

/// <summary>
/// Turns a hex dump — as produced by Wireshark's "Copy as Hex Stream" — into the same
/// frame list a live capture produces, so a manually analysed dump and a recorded
/// connection are directly comparable.
/// </summary>
internal static class Http2WireHex
{
    private static readonly byte[] Magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    public static byte[] Parse(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        var builder = new StringBuilder(hex.Length);
        for (var index = 0; index < hex.Length; index++)
        {
            var character = hex[index];
            if (char.IsWhiteSpace(character) || character is ':' or '-' or ',')
            {
                continue;
            }
            if (!char.IsAsciiHexDigit(character))
            {
                // Every other error path in this file names a position, and a stray
                // non-hex character is the likeliest mistake when pasting by hand.
                // Convert.FromHexString's own exception carries no index and no hint.
                throw new FormatException(
                    $"Not a hex stream: unexpected '{character}' at index {index}. " +
                    "Wireshark's \"Copy as Hex Stream\" produces the expected form. " +
                    "A hex dump pane, which prefixes each line with an offset column " +
                    "and appends an ASCII column, is not accepted — its offset digits " +
                    "would be read as payload.");
            }
            builder.Append(character);
        }

        var cleaned = builder.ToString();
        if (cleaned.Length % 2 != 0)
        {
            throw new FormatException(
                $"A hex stream must have an even number of digits; got {cleaned.Length}.");
        }
        return Convert.FromHexString(cleaned);
    }

    public static IReadOnlyList<CapturedFrame> ParseFrames(string hex, bool expectPreface = true)
    {
        var bytes = Parse(hex);
        var offset = 0;

        if (expectPreface)
        {
            if (bytes.Length < Magic.Length ||
                !bytes.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            {
                throw new FormatException(
                    "The stream does not begin with the HTTP/2 connection preface magic. " +
                    "Pass expectPreface: false to read a mid-connection capture.");
            }
            offset = Magic.Length;
        }

        var frames = new List<CapturedFrame>();
        while (offset < bytes.Length)
        {
            if (bytes.Length - offset < 9)
            {
                throw new FormatException(
                    $"Frame header truncated at offset {offset}: " +
                    $"{bytes.Length - offset} bytes remain, 9 required.");
            }

            var length = bytes[offset] << 16 | bytes[offset + 1] << 8 | bytes[offset + 2];
            if (bytes.Length - offset - 9 < length)
            {
                throw new FormatException(
                    $"Frame payload truncated at offset {offset}: declared {length} bytes, " +
                    $"{bytes.Length - offset - 9} available.");
            }

            frames.Add(new CapturedFrame(
                (Http2FrameType)bytes[offset + 3],
                bytes[offset + 4],
                BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(offset + 5)) & 0x7fff_ffff,
                bytes.AsSpan(offset + 9, length).ToArray()));
            offset += 9 + length;
        }

        return frames;
    }
}
