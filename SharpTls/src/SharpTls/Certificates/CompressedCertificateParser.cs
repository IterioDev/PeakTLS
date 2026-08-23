using System.IO.Compression;
using SharpTls.IO;
using SharpTls.Protocol;
using ZstdSharp;

namespace SharpTls.Certificates;

internal static class CompressedCertificateParser
{
    private const ushort Zlib = 1;
    private const ushort Brotli = 2;
    private const ushort Zstd = 3;

    internal static byte[] Decompress(
        ReadOnlySpan<byte> body,
        ClientHelloConfiguration offer,
        TlsLimits limits)
    {
        ArgumentNullException.ThrowIfNull(offer);
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();

        var reader = new TlsBinaryReader(body);
        var algorithm = reader.ReadUInt16();
        var uncompressedLength = reader.ReadUInt24();
        var compressed = reader.ReadVector24(limits.MaxHandshakeMessageSize);
        reader.EnsureEnd("CompressedCertificate");
        if (uncompressedLength == 0 || uncompressedLength > limits.MaxHandshakeMessageSize)
        {
            throw BadCertificate("CompressedCertificate declares an invalid uncompressed length.");
        }
        if (compressed.IsEmpty)
        {
            throw BadCertificate("CompressedCertificate payload is empty.");
        }

        var offeredAlgorithms = ParseOfferedAlgorithms(offer);
        if (!offeredAlgorithms.Contains(algorithm))
        {
            throw BadCertificate(
                $"Server selected unoffered certificate compression algorithm {algorithm}.");
        }
        if (algorithm is not (Zlib or Brotli or Zstd))
        {
            throw BadCertificate(
                $"Certificate compression algorithm {algorithm} has no managed decompressor.");
        }

        try
        {
            if (algorithm == Zstd)
            {
                return DecompressZstd(compressed, uncompressedLength);
            }

            using var input = new MemoryStream(compressed.ToArray(), writable: false);
            using Stream decompressor = algorithm switch
            {
                Zlib => new ZLibStream(input, CompressionMode.Decompress, leaveOpen: false),
                Brotli => new BrotliStream(input, CompressionMode.Decompress, leaveOpen: false),
                _ => throw new InvalidOperationException("Compression algorithm validation invariant failed."),
            };

            var output = new byte[uncompressedLength];
            var written = 0;
            while (written < output.Length)
            {
                var read = decompressor.Read(output, written, output.Length - written);
                if (read == 0)
                {
                    throw BadCertificate(
                        "Decompressed Certificate is shorter than uncompressed_length.");
                }
                written += read;
            }
            if (decompressor.ReadByte() != -1)
            {
                throw BadCertificate(
                    "Decompressed Certificate exceeds uncompressed_length.");
            }

            return output;
        }
        catch (TlsProtocolException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // Every decompressor here decodes peer-controlled bytes, and none of them
            // documents a closed set of failure types: BrotliStream raises a bare
            // InvalidOperationException ("Decoder ran into invalid data.") rather than the
            // InvalidDataException this filter used to name, and ZstdSharp is third-party
            // unsafe code with its own hierarchy. RFC 8879 s5 requires a decompression
            // failure to be a protocol error, so every non-fatal escape is mapped to
            // bad_certificate rather than allowed to leave this boundary. OutOfMemory is a
            // host condition, not a peer's doing, and is deliberately left to propagate.
            throw new TlsProtocolException(
                TlsAlertDescription.BadCertificate,
                "CompressedCertificate decompression failed.",
                exception);
        }
    }

    /// <remarks>
    /// zstd has no in-box .NET decompressor, so RFC 8879 algorithm 3 runs through the
    /// third-party managed ZstdSharp port. The one-shot <see cref="Decompressor.Unwrap(ReadOnlySpan{byte}, Span{byte})"/>
    /// entry point is used deliberately in preference to <c>DecompressionStream</c>: it
    /// decodes straight into a destination sized at exactly <paramref name="uncompressedLength"/>
    /// -- already bounded above by <c>TlsLimits.MaxHandshakeMessageSize</c> -- so a peer cannot
    /// drive an allocation off the frame header's window descriptor, and cannot emit more bytes
    /// than the header it also supplied declares. That is the same bound the zlib and brotli
    /// paths enforce with their fixed-size output buffer.
    /// </remarks>
    private static byte[] DecompressZstd(ReadOnlySpan<byte> compressed, int uncompressedLength)
    {
        var output = new byte[uncompressedLength];
        using var decompressor = new Decompressor();
        var written = decompressor.Unwrap(compressed, output);
        if (written != output.Length)
        {
            throw BadCertificate(
                "Decompressed Certificate does not match uncompressed_length.");
        }

        return output;
    }

    private static HashSet<ushort> ParseOfferedAlgorithms(ClientHelloConfiguration offer)
    {
        var algorithms = new HashSet<ushort>();
        foreach (var extension in offer.ExtensionLayout)
        {
            if (extension.RawExtensionType != 27)
            {
                continue;
            }

            var reader = new TlsBinaryReader(extension.RawData);
            var encoded = new TlsBinaryReader(reader.ReadVector8());
            reader.EnsureEnd("compress_certificate offer");
            if (encoded.End || (encoded.Remaining & 1) != 0)
            {
                throw new InvalidOperationException(
                    "Configured compress_certificate offer has an invalid algorithm vector.");
            }
            while (!encoded.End)
            {
                if (!algorithms.Add(encoded.ReadUInt16()))
                {
                    throw new InvalidOperationException(
                        "Configured compress_certificate offer contains a duplicate algorithm.");
                }
            }
        }

        return algorithms;
    }

    private static TlsProtocolException BadCertificate(string message) =>
        new(TlsAlertDescription.BadCertificate, message);
}
