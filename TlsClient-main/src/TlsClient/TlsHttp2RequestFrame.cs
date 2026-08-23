using System.Buffers.Binary;
using System.Text;

namespace TlsClient;

/// <summary>
/// A frame written immediately before or after one request's header block. Nothing may sit
/// between HEADERS and its CONTINUATION frames — RFC 9113 section 4.3 requires a field block
/// to be a contiguous sequence of frames with no interleaving of any other type — so the
/// declared frames land outside the complete block, never inside it.
/// </summary>
public abstract class TlsHttp2RequestFrame
{
    /// <summary>
    /// Gets or sets whether the transport is flushed after this frame. The default keeps the
    /// frame in the request's write batch, so it shares a record with what follows.
    /// </summary>
    public bool FlushAfter { get; set; }
}

/// <summary>
/// A PRIORITY frame on the request's own stream, carrying the deprecated RFC 7540 dependency
/// and weight that RFC 9113 section 5.3.2 retains on the wire for interoperability. It always
/// targets the request's stream: RFC 9113 section 6.3 makes a PRIORITY frame on stream 0 a
/// connection error of type PROTOCOL_ERROR, so there is nothing to declare.
/// </summary>
public sealed class TlsHttp2StreamPriorityFrame : TlsHttp2RequestFrame
{
    /// <summary>Gets or sets the priority data.</summary>
    public TlsHttp2Priority Priority { get; set; } = new();
}

/// <summary>
/// An RFC 9218 PRIORITY_UPDATE frame prioritizing the request's own stream. The frame header's
/// stream identifier is always 0 — RFC 9218 section 7.1 requires it — and the Prioritized
/// Stream ID field names the request's stream, which is filled in when the frame is written.
/// Declaring one before the header block is legal: section 7 permits a client to prioritize a
/// stream that is still idle.
/// </summary>
public sealed class TlsHttp2PriorityUpdateFrame : TlsHttp2RequestFrame
{
    /// <summary>
    /// Gets or sets the Priority Field Value, for example <c>u=3, i</c>. RFC 9218 section 7.1
    /// carries it as ASCII text in the same representation as the Priority header field.
    /// </summary>
    public string Value { get; set; } = "";
}

/// <summary>
/// A client-initiated PING on stream 0. RFC 9113 section 6.7 fixes both the target stream and
/// the payload length; only the eight opaque octets vary, and they are a real fingerprint —
/// stacks differ between all-zero, a counter, and random data.
/// </summary>
public sealed class TlsHttp2PingFrame : TlsHttp2RequestFrame
{
    /// <summary>
    /// Gets or sets the eight opaque octets. RFC 9113 section 6.7: "PING frames MUST contain
    /// 8 octets of opaque data in the frame payload. A sender can include any value it chooses
    /// and use those octets in any fashion."
    /// </summary>
    public byte[] Payload { get; set; } = new byte[8];
}

/// <summary>
/// An arbitrary frame, for reproducing GREASE, extension frames, and connection-level frames
/// around a request. Frame types the request machinery owns are rejected. Unlike the frame
/// classes above, a raw frame's stream identifier is written verbatim rather than resolved to
/// the request's stream, so this is how a frame that genuinely targets stream 0 is declared.
/// </summary>
public sealed class TlsHttp2RequestRawFrame : TlsHttp2RequestFrame
{
    /// <summary>Gets or sets the frame type octet.</summary>
    public byte Type { get; set; }

    /// <summary>Gets or sets the frame flags octet.</summary>
    public byte Flags { get; set; }

    /// <summary>Gets or sets the stream identifier, written verbatim.</summary>
    public int StreamId { get; set; }

    /// <summary>Gets or sets the frame payload.</summary>
    public byte[] Payload { get; set; } = [];
}

/// <summary>
/// One request frame reduced to the octets it puts on the wire, plus whether the transport is
/// flushed after it and whether it names the request's own stream.
/// </summary>
/// <param name="Type">The frame type octet.</param>
/// <param name="Flags">The frame flags octet.</param>
/// <param name="StreamId">The frame header's stream identifier.</param>
/// <param name="Payload">The frame payload.</param>
/// <param name="FlushAfter">Whether the write batch closes after this frame.</param>
/// <param name="TargetsRequestStream">
/// Whether the request's allocated stream identifier is substituted when the frame is written.
/// For PRIORITY that is the frame header's stream identifier; for PRIORITY_UPDATE it is the
/// Prioritized Stream ID field in the first four payload octets, because RFC 9218 section 7.1
/// pins the frame header's own identifier to 0. Either way the placeholder here is 0.
/// </param>
internal sealed record TlsHttp2RequestFrameConfiguration(
    byte Type,
    byte Flags,
    int StreamId,
    byte[] Payload,
    bool FlushAfter,
    bool TargetsRequestStream);

/// <summary>Freezes a declared per-request frame list into the octets it emits.</summary>
internal static class TlsHttp2RequestFrameList
{
    private const int MaximumFrames = 16;
    private const int MaximumRawPayloadBytes = 16 * 1024;
    private const int PingPayloadBytes = 8;
    private const int PriorityPayloadBytes = 5;

    private const byte PriorityFrameType = 0x2;
    private const byte PingFrameType = 0x6;
    private const byte PriorityUpdateFrameType = 0x10;

    internal static TlsHttp2RequestFrameConfiguration[] Freeze(
        IReadOnlyList<TlsHttp2RequestFrame>? frames,
        string parameterName)
    {
        var declared = frames?.ToArray() ?? throw new ArgumentNullException(parameterName);
        if (declared.Length > MaximumFrames)
        {
            throw new ArgumentException(
                "A request frame list holds at most 16 frames.",
                parameterName);
        }

        var frozen = new TlsHttp2RequestFrameConfiguration[declared.Length];
        for (var index = 0; index < declared.Length; index++)
        {
            frozen[index] = FreezeFrame(declared[index], parameterName);
        }
        return frozen;
    }

    private static TlsHttp2RequestFrameConfiguration FreezeFrame(
        TlsHttp2RequestFrame frame,
        string parameterName) => frame switch
        {
            TlsHttp2StreamPriorityFrame priority => FreezePriority(priority, parameterName),
            TlsHttp2PriorityUpdateFrame update => FreezePriorityUpdate(update, parameterName),
            TlsHttp2PingFrame ping => FreezePing(ping, parameterName),
            TlsHttp2RequestRawFrame raw => FreezeRaw(raw, parameterName),
            null => throw new ArgumentException(
                "A request frame list cannot contain a null frame.",
                parameterName),
            _ => throw new ArgumentException(
                "A request frame list only accepts the frame types TlsClient declares.",
                parameterName),
        };

    private static TlsHttp2RequestFrameConfiguration FreezePriority(
        TlsHttp2StreamPriorityFrame frame,
        string parameterName)
    {
        var priority = (frame.Priority ??
            throw new ArgumentException(
                "A request PRIORITY frame is missing its priority data.",
                parameterName)).Snapshot();
        return new TlsHttp2RequestFrameConfiguration(
            PriorityFrameType,
            0,
            0,
            priority.BuildPayload(),
            frame.FlushAfter,
            TargetsRequestStream: true);
    }

    private static TlsHttp2RequestFrameConfiguration FreezePriorityUpdate(
        TlsHttp2PriorityUpdateFrame frame,
        string parameterName)
    {
        // RFC 9218 section 7.1 carries the Priority Field Value "in ASCII text, encoded using
        // Structured Fields", the same representation as the Priority header field. The bound
        // matches the session-level PriorityUpdate rule.
        var value = frame.Value;
        if (value is null ||
            value.Length is < 1 or > 256 ||
            value.Any(character => character is < ' ' or > '~'))
        {
            throw new ArgumentException(
                "A PRIORITY_UPDATE frame's Value must contain 1–256 visible ASCII characters " +
                "(RFC 9218 section 7.1).",
                parameterName);
        }

        // Prioritized Stream ID (31 bits) then the Priority Field Value (RFC 9218 section 7.1,
        // Figure 1). The identifier is left zero and filled in with the request's stream when
        // the frame is written, since it is not known while the options are built.
        var payload = new byte[4 + value.Length];
        BinaryPrimitives.WriteInt32BigEndian(payload, 0);
        Encoding.ASCII.GetBytes(value, payload.AsSpan(4));
        return new TlsHttp2RequestFrameConfiguration(
            PriorityUpdateFrameType,
            0,
            0,
            payload,
            frame.FlushAfter,
            TargetsRequestStream: true);
    }

    private static TlsHttp2RequestFrameConfiguration FreezePing(
        TlsHttp2PingFrame frame,
        string parameterName)
    {
        var declared = frame.Payload ??
            throw new ArgumentException(
                "A PING frame's payload cannot be null.",
                parameterName);
        ValidatePingPayloadLength(declared.Length, parameterName);
        return new TlsHttp2RequestFrameConfiguration(
            PingFrameType,
            0,
            0,
            declared.ToArray(),
            frame.FlushAfter,
            TargetsRequestStream: false);
    }

    private static TlsHttp2RequestFrameConfiguration FreezeRaw(
        TlsHttp2RequestRawFrame frame,
        string parameterName)
    {
        // DATA, HEADERS, RST_STREAM, GOAWAY and CONTINUATION belong to the request machinery;
        // PUSH_PROMISE from a client is a protocol error.
        if (frame.Type is 0x0 or 0x1 or 0x3 or 0x5 or 0x7 or 0x9)
        {
            throw new ArgumentException(
                "A raw request frame cannot use frame type DATA, HEADERS, RST_STREAM, " +
                "PUSH_PROMISE, GOAWAY, or CONTINUATION.",
                parameterName);
        }
        if (frame.StreamId < 0)
        {
            throw new ArgumentException(
                "A request frame's stream identifier must be within [0, 2^31 - 1].",
                parameterName);
        }
        var declared = frame.Payload ??
            throw new ArgumentException(
                "A raw request frame's payload cannot be null.",
                parameterName);
        if (declared.Length > MaximumRawPayloadBytes)
        {
            throw new ArgumentException(
                "A raw request frame payload holds at most 16384 bytes.",
                parameterName);
        }
        if (frame.Type == PingFrameType)
        {
            ValidatePingPayloadLength(declared.Length, parameterName);
            // RFC 9113 section 6.7: "If a PING frame is received with a Stream Identifier
            // field value other than 0x00, the recipient MUST respond with a connection error
            // of type PROTOCOL_ERROR." A different failure from the length rule, so a
            // different code and a different message.
            if (frame.StreamId != 0)
            {
                throw new ArgumentException(
                    "A PING frame must target stream 0; any other stream identifier is a " +
                    "PROTOCOL_ERROR (RFC 9113 section 6.7).",
                    parameterName);
            }
        }
        if (frame.Type == PriorityFrameType)
        {
            ValidatePriorityPayloadLength(declared.Length, parameterName);
            // RFC 9113 section 6.3: "The PRIORITY frame always identifies a stream. If a
            // PRIORITY frame is received with a stream identifier of 0x00, the recipient MUST
            // respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR." A
            // different failure from the length rule, so a different code and a different
            // message.
            if (frame.StreamId == 0)
            {
                throw new ArgumentException(
                    "A PRIORITY frame must identify a stream; stream 0 is a PROTOCOL_ERROR " +
                    "(RFC 9113 section 6.3).",
                    parameterName);
            }
        }

        return new TlsHttp2RequestFrameConfiguration(
            frame.Type,
            frame.Flags,
            frame.StreamId,
            declared.ToArray(),
            frame.FlushAfter,
            TargetsRequestStream: false);
    }

    // RFC 9113 section 6.7: "In addition to the frame header, PING frames MUST contain 8 octets
    // of opaque data in the frame payload." and "Receipt of a PING frame with a length field
    // value other than 8 MUST be treated as a connection error of type FRAME_SIZE_ERROR."
    private static void ValidatePingPayloadLength(int length, string parameterName)
    {
        if (length != PingPayloadBytes)
        {
            throw new ArgumentException(
                "A PING frame carries exactly 8 octets of opaque data; any other length is a " +
                "FRAME_SIZE_ERROR (RFC 9113 section 6.7).",
                parameterName);
        }
    }

    // RFC 9113 section 6.3 fixes the PRIORITY payload at Exclusive (1) + Stream Dependency (31)
    // + Weight (8): "A PRIORITY frame with a length other than 5 octets MUST be treated as a
    // stream error (Section 5.4.2) of type FRAME_SIZE_ERROR."
    private static void ValidatePriorityPayloadLength(int length, string parameterName)
    {
        if (length != PriorityPayloadBytes)
        {
            throw new ArgumentException(
                "A PRIORITY frame carries exactly 5 octets; any other length is a " +
                "FRAME_SIZE_ERROR (RFC 9113 section 6.3).",
                parameterName);
        }
    }
}
