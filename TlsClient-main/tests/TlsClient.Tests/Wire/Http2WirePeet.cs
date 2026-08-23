using System.Buffers.Binary;

namespace TlsClient.Tests.Wire;

internal sealed record PeetFrame(
    string FrameType,
    int Length,
    int? StreamId,
    IReadOnlyList<string>? Settings,
    uint? Increment,
    IReadOnlyList<string>? Flags);

/// <summary>
/// Renders captured frames in the vocabulary that tls.peet.ws/api/all reports, so an
/// observed response and an emitted connection can be compared without translation.
/// </summary>
internal static class Http2WirePeet
{
    public static IReadOnlyList<PeetFrame> Describe(IReadOnlyList<CapturedFrame> frames)
    {
        ArgumentNullException.ThrowIfNull(frames);
        var described = new List<PeetFrame>(frames.Count);
        foreach (var frame in frames)
        {
            described.Add(new PeetFrame(
                FrameTypeName(frame.Type),
                frame.Payload.Length,
                frame.StreamId == 0 ? null : frame.StreamId,
                frame.Type == Http2FrameType.Settings ? DescribeSettings(frame.Payload) : null,
                frame.Type == Http2FrameType.WindowUpdate && frame.Payload.Length == 4
                    ? BinaryPrimitives.ReadUInt32BigEndian(frame.Payload) & 0x7fff_ffffU
                    : null,
                DescribeFlags(frame.Type, frame.Flags)));
        }
        return described;
    }

    public static string AkamaiFingerprint(
        IReadOnlyList<CapturedFrame> frames,
        IReadOnlyList<string> pseudoHeaderOrder)
    {
        ArgumentNullException.ThrowIfNull(frames);
        ArgumentNullException.ThrowIfNull(pseudoHeaderOrder);

        var settingsFrame = frames.FirstOrDefault(
            frame => frame.Type == Http2FrameType.Settings);
        var settingsText = settingsFrame.Payload is null
            ? string.Empty
            : string.Join(';', ReadSettings(settingsFrame.Payload)
                .Select(setting => $"{setting.Identifier}:{setting.Value}"));

        var windowUpdate = frames.FirstOrDefault(
            frame => frame.Type == Http2FrameType.WindowUpdate && frame.StreamId == 0);
        var increment = windowUpdate.Payload is { Length: 4 }
            ? BinaryPrimitives.ReadUInt32BigEndian(windowUpdate.Payload) & 0x7fff_ffffU
            : 0u;

        // The Akamai priority segment is built from PRIORITY frames only. A HEADERS
        // frame carrying a priority payload does not contribute; that is a different
        // measurement, and TlsPresetWireTests asserts it separately.
        var priorities = frames
            .Where(frame => frame.Type == Http2FrameType.Priority && frame.Payload.Length == 5)
            .Select(frame =>
            {
                var raw = BinaryPrimitives.ReadUInt32BigEndian(frame.Payload);
                var exclusive = (raw & 0x8000_0000U) != 0 ? 1 : 0;
                var dependency = raw & 0x7fff_ffffU;
                return $"{frame.StreamId}:{exclusive}:{dependency}:{frame.Payload[4] + 1}";
            })
            .ToArray();
        var priorityText = priorities.Length == 0 ? "0" : string.Join(',', priorities);

        var pseudoText = string.Join(
            ',',
            pseudoHeaderOrder.Select(name => name.TrimStart(':')[..1]));

        return $"{settingsText}|{increment}|{priorityText}|{pseudoText}";
    }

    private static string FrameTypeName(Http2FrameType type) => type switch
    {
        Http2FrameType.Data => "DATA",
        Http2FrameType.Headers => "HEADERS",
        Http2FrameType.Priority => "PRIORITY",
        Http2FrameType.RstStream => "RST_STREAM",
        Http2FrameType.Settings => "SETTINGS",
        Http2FrameType.PushPromise => "PUSH_PROMISE",
        Http2FrameType.Ping => "PING",
        Http2FrameType.GoAway => "GOAWAY",
        Http2FrameType.WindowUpdate => "WINDOW_UPDATE",
        Http2FrameType.Continuation => "CONTINUATION",
        Http2FrameType.PriorityUpdate => "PRIORITY_UPDATE",
        _ => $"UNKNOWN(0x{(byte)type:x2})",
    };

    private static string SettingName(ushort identifier) => identifier switch
    {
        0x1 => "HEADER_TABLE_SIZE",
        0x2 => "ENABLE_PUSH",
        0x3 => "MAX_CONCURRENT_STREAMS",
        0x4 => "INITIAL_WINDOW_SIZE",
        0x5 => "MAX_FRAME_SIZE",
        0x6 => "MAX_HEADER_LIST_SIZE",
        0x8 => "ENABLE_CONNECT_PROTOCOL",
        0x9 => "NO_RFC7540_PRIORITIES",
        _ => $"UNKNOWN(0x{identifier:x4})",
    };

    private static IReadOnlyList<string> DescribeSettings(byte[] payload) =>
        [.. ReadSettings(payload)
            .Select(setting => $"{SettingName(setting.Identifier)} = {setting.Value}")];

    private static (ushort Identifier, uint Value)[] ReadSettings(byte[] payload)
    {
        var count = payload.Length / 6;
        var settings = new (ushort, uint)[count];
        for (var index = 0; index < count; index++)
        {
            var offset = index * 6;
            settings[index] = (
                BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(offset, 2)),
                BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset + 2, 4)));
        }
        return settings;
    }

    private static List<string>? DescribeFlags(Http2FrameType type, byte flags)
    {
        if (flags == 0)
        {
            return null;
        }
        var names = new List<string>();
        // Bit 0x1 is ACK on SETTINGS and PING, END_STREAM everywhere else — the same
        // bit means different things depending on frame type, per RFC 9113 §6.5/§6.7.
        if ((flags & 0x1) != 0)
        {
            names.Add(type is Http2FrameType.Settings or Http2FrameType.Ping
                ? "Ack (0x1)"
                : "EndStream (0x1)");
        }
        if ((flags & 0x4) != 0) names.Add("EndHeaders (0x4)");
        if ((flags & 0x8) != 0) names.Add("Padded (0x8)");
        if ((flags & 0x20) != 0) names.Add("Priority (0x20)");
        return names;
    }
}
