using System.Buffers.Binary;

namespace TlsClient;

/// <summary>Configures the HTTP/2 connection preface, header encoding, and stream identifiers.</summary>
public sealed class TlsHttp2Options
{
    private const int MaximumPrefaceFrames = 32;
    private const int MaximumSettingsEntries = 2730;
    private const int MaximumRawPayloadBytes = 16 * 1024;
    private const uint MaximumHeaderTableSize = 16 * 1024 * 1024;

    private const byte PriorityFrameType = 0x2;
    private const byte SettingsFrameType = 0x4;
    private const byte WindowUpdateFrameType = 0x8;

    // Not a const: CA2208 only accepts a compile-time paramName that names a parameter
    // of the throwing method, and these rejections all belong to the Preface property.
    private static readonly string PrefaceParameter = nameof(Preface);
    private static readonly string FlowControlParameter = nameof(FlowControl);

    /// <summary>
    /// Gets or sets the frames written after the connection preface magic, in exact order.
    /// The default is the minimum preface RFC 9113 section 3.4 conforms to — a single
    /// zero-length SETTINGS frame, declaring no persona and assuming no preset. An empty
    /// list sends the magic alone, for reproducing a client that really does that.
    /// </summary>
    public IReadOnlyList<TlsHttp2PrefaceFrame> Preface { get; set; } =
        [new TlsHttp2SettingsFrame()];

    /// <summary>Gets the HPACK send-side encoding policy.</summary>
    public TlsHpackOptions Hpack { get; } = new();

    /// <summary>Gets or sets the first client stream identifier. Must be odd.</summary>
    public int InitialStreamId { get; set; } = 1;

    /// <summary>Gets or sets the increment between client stream identifiers. Must be even.</summary>
    public int StreamIdStep { get; set; } = 2;

    /// <summary>Gets or sets where a SETTINGS acknowledgement sits in the outbound sequence.</summary>
    public TlsHttp2SettingsAckPlacement SettingsAckPlacement { get; set; }
        = TlsHttp2SettingsAckPlacement.Standalone;

    /// <summary>
    /// Gets which request pseudo-headers are emitted, in what order, and how the authority
    /// and scheme are conveyed.
    /// </summary>
    public TlsHttp2PseudoHeaderOptions PseudoHeaders { get; } = new();

    /// <summary>Gets how a request body is cut into DATA frames.</summary>
    public TlsHttp2DataOptions Data { get; } = new();

    /// <summary>Gets when the client returns receive-window credit, and how much.</summary>
    public TlsHttp2FlowControlOptions FlowControl { get; } = new();

    /// <summary>Gets how the client announces that it is finished with a connection.</summary>
    public TlsHttp2ShutdownOptions Shutdown { get; } = new();

    /// <summary>
    /// Gets or sets pseudo-headers in exact request wire order. A shorthand for
    /// <see cref="TlsHttp2PseudoHeaderOptions.Order"/>, over the same storage: reading or
    /// writing this property reads or writes <c>PseudoHeaders.Order</c>.
    /// </summary>
    public IReadOnlyList<string> PseudoHeaderOrder
    {
        get => PseudoHeaders.Order;
        set => PseudoHeaders.Order = value;
    }

    /// <summary>
    /// Gets or sets the size at which a request or trailer field block is split across
    /// CONTINUATION frames. <see langword="null"/>, the default, splits only at the peer's
    /// own limit, which is today's behaviour.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The effective split is <c>min(HeaderBlockFragmentSize, peerMaxFrameSize)</c>: this
    /// value can only produce fragments smaller than the peer permits, never larger, because
    /// RFC 9113 section 4.2 makes an oversized field-block frame a connection error of type
    /// FRAME_SIZE_ERROR.
    /// </para>
    /// <para>
    /// Before the peer's SETTINGS has been applied the clamp is the RFC 9113 section 6.5.2
    /// default of 16384, not whatever the peer later advertises. The peer's maximum only
    /// rises once its SETTINGS is processed, which races the first request because the
    /// preface is written before the read loop starts; clamping against the fixed default
    /// keeps a declared size above 16384 from fragmenting differently run to run.
    /// </para>
    /// </remarks>
    public int? HeaderBlockFragmentSize { get; set; }


    /// <summary>Gets or sets optional RFC 7540 priority data embedded in HEADERS.</summary>
    public TlsHttp2Priority? HeaderPriority { get; set; }

    /// <summary>
    /// Gets or sets an optional RFC 9218 Priority Field Value sent in a PRIORITY_UPDATE
    /// frame for every new request stream, for example <c>u=3, i</c>.
    /// </summary>
    public string? PriorityUpdate { get; set; }

    /// <summary>
    /// Gets or sets whether the request header block ends its write batch. The default,
    /// <see langword="true"/>, is today's behaviour: HEADERS, its CONTINUATION frames and
    /// any PRIORITY_UPDATE leave in a record of their own. When <see langword="false"/>
    /// they stay in the batch and leave with the first DATA frames, as a client that
    /// writes a whole small request in one go does.
    /// </summary>
    /// <remarks>
    /// The batch still closes when the header block is the last thing the request writes,
    /// or when the client is about to wait on the peer — an interim response cannot arrive
    /// for octets the peer has not received.
    /// </remarks>
    public bool FlushAfterHeaderBlock { get; set; } = true;

    /// <summary>
    /// Gets or sets whether every DATA frame ends its write batch. The default,
    /// <see langword="true"/>, is today's behaviour: one record per DATA frame. When
    /// <see langword="false"/> consecutive DATA frames coalesce into one write, which is
    /// what most clients do and is visible to any passive observer.
    /// </summary>
    /// <remarks>
    /// A DATA frame carrying END_STREAM always closes the batch — nothing further will be
    /// written on that stream to coalesce with — and so does the last frame before the
    /// client waits for flow-control credit, since RFC 9113 section 6.9.1 has the peer
    /// grant credit only for octets it has received.
    /// </remarks>
    public bool FlushAfterEveryDataFrame { get; set; } = true;

    internal TlsHttp2Configuration Snapshot()
    {
        var declared = Preface?.ToArray() ?? throw new ArgumentNullException(nameof(Preface));
        if (declared.Length > MaximumPrefaceFrames)
        {
            throw new ArgumentException(
                "The HTTP/2 preface holds at most 32 frames.",
                PrefaceParameter);
        }

        var state = new LocalReceiveState();
        var preface = new TlsHttp2PrefaceFrameConfiguration[declared.Length];
        for (var index = 0; index < declared.Length; index++)
        {
            preface[index] = FreezeFrame(declared[index], state);
        }

        // RFC 9113 section 3.4: the 24-octet magic is followed by a SETTINGS frame, which
        // may be empty but must be present and must come first. A server reading anything
        // else answers GOAWAY(PROTOCOL_ERROR), so no real client emits one — declaring a
        // preface that opens otherwise would not be a fingerprint, it would be a
        // connection failure. Checked after freezing so a raw frame is judged by the type
        // octet it actually emits.
        if (preface.Length == 0 || preface[0].Type != SettingsFrameType)
        {
            throw new ArgumentException(
                "The HTTP/2 preface must begin with a SETTINGS frame, which may be empty " +
                "(RFC 9113 section 3.4).",
                PrefaceParameter);
        }
        if (state.ConnectionReceiveWindow > int.MaxValue)
        {
            throw new ArgumentException(
                "The declared HTTP/2 connection receive window exceeds 2^31 - 1 " +
                "(RFC 9113 section 6.9.1).",
                PrefaceParameter);
        }

        if (InitialStreamId < 1 || (InitialStreamId & 1) == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(InitialStreamId),
                "InitialStreamId must be odd and within [1, 2^31 - 1].");
        }
        if (StreamIdStep is < 2 or > 65_536 || (StreamIdStep & 1) != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(StreamIdStep),
                "StreamIdStep must be even and within [2, 65536].");
        }
        if (!Enum.IsDefined(SettingsAckPlacement))
        {
            throw new ArgumentOutOfRangeException(
                nameof(SettingsAckPlacement),
                "SettingsAckPlacement must be a defined value.");
        }

        // The floor is 6, and it is enforced whether or not a priority payload is declared.
        // WriteHeaderBlockLockedAsync takes the 5-octet RFC 9113 section 6.3 priority payload
        // out of the fragment's own budget, so 1 to 5 leaves nothing for the field block;
        // priority is a per-request override, so the session cannot know whether any given
        // request will carry one. The ceiling is SETTINGS_MAX_FRAME_SIZE's own upper bound
        // (RFC 9113 section 4.2); anything above the peer's advertised value is clamped down
        // rather than rejected.
        if (HeaderBlockFragmentSize is < 6 or > 16_777_215)
        {
            throw new ArgumentOutOfRangeException(
                nameof(HeaderBlockFragmentSize),
                "HeaderBlockFragmentSize must be within [6, 16777215].");
        }

        var pseudoHeaders = PseudoHeaders.Snapshot();
        var data = Data.Snapshot();
        var flowControl = FlowControl.Snapshot();
        var shutdown = Shutdown.Snapshot();

        // A threshold larger than the window it draws on can never be reached: the peer
        // spends the whole window before that many octets are outstanding, no
        // WINDOW_UPDATE is ever emitted, and RFC 9113 section 6.9.1 — a peer may send only
        // what the advertised window permits — makes the stall permanent rather than slow.
        // Both sides of each comparison are declared here, so this is where the two meet:
        // the thresholds come from FlowControl and the windows from the preface script.
        //
        // Section 6.9.2 seeds a new stream's receive window at the declared
        // SETTINGS_INITIAL_WINDOW_SIZE, and section 6.9.1 seeds the connection's at 65535
        // — which SETTINGS_INITIAL_WINDOW_SIZE does not cover, so only the preface's own
        // WINDOW_UPDATE frames raise it. state carries both as the preface built them.
        if (flowControl.StreamWindowUpdateThreshold > state.InitialWindowSize)
        {
            throw new ArgumentException(
                "FlowControl.StreamWindowUpdateThreshold exceeds the declared " +
                "SETTINGS_INITIAL_WINDOW_SIZE, so the stream window is exhausted before " +
                "the threshold is reached and no WINDOW_UPDATE is ever emitted " +
                "(RFC 9113 section 6.9.1).",
                FlowControlParameter);
        }
        if (flowControl.ConnectionWindowUpdateThreshold > state.ConnectionReceiveWindow)
        {
            throw new ArgumentException(
                "FlowControl.ConnectionWindowUpdateThreshold exceeds the declared " +
                "connection receive window, so the connection window is exhausted before " +
                "the threshold is reached and no WINDOW_UPDATE is ever emitted " +
                "(RFC 9113 section 6.9.1).",
                FlowControlParameter);
        }

        ValidatePriorityUpdate(PriorityUpdate, nameof(PriorityUpdate));

        return new TlsHttp2Configuration(
            preface,
            Hpack.Snapshot(),
            InitialStreamId,
            StreamIdStep,
            SettingsAckPlacement,
            pseudoHeaders,
            data,
            HeaderBlockFragmentSize,
            HeaderPriority?.Snapshot(),
            PriorityUpdate,
            FlushAfterHeaderBlock,
            FlushAfterEveryDataFrame,
            state.HeaderTableSize,
            state.InitialWindowSize,
            state.MaxFrameSize,
            state.MaxHeaderListSize,
            state.EnablePush,
            (int)state.ConnectionReceiveWindow,
            flowControl,
            shutdown);
    }

    /// <summary>
    /// Validates an RFC 9218 Priority Field Value, session-wide or per request. Section 7.1
    /// carries it "in ASCII text, encoded using Structured Fields".
    /// </summary>
    internal static void ValidatePriorityUpdate(string? value, string parameterName)
    {
        if (value is not null &&
            (value.Length is < 1 or > 256 ||
                value.Any(character => character is < ' ' or > '~')))
        {
            throw new ArgumentException(
                "PriorityUpdate must contain 1–256 visible ASCII characters.",
                parameterName);
        }
    }

    private static TlsHttp2PrefaceFrameConfiguration FreezeFrame(
        TlsHttp2PrefaceFrame frame,
        LocalReceiveState state) => frame switch
        {
            TlsHttp2SettingsFrame settings => FreezeSettings(settings, state),
            TlsHttp2WindowUpdateFrame windowUpdate => FreezeWindowUpdate(windowUpdate, state),
            TlsHttp2PrefacePriorityFrame priority => FreezePriority(priority),
            TlsHttp2RawFrame raw => FreezeRaw(raw, state),
            null => throw new ArgumentException(
                "The HTTP/2 preface cannot contain a null frame.",
                PrefaceParameter),
            _ => throw new ArgumentException(
                "The HTTP/2 preface only accepts the frame types TlsClient declares.",
                PrefaceParameter),
        };

    private static TlsHttp2PrefaceFrameConfiguration FreezeSettings(
        TlsHttp2SettingsFrame frame,
        LocalReceiveState state)
    {
        var settings = frame.Settings ??
            throw new ArgumentException(
                "A SETTINGS frame's entry list cannot be null.",
                PrefaceParameter);
        if (settings.Count > MaximumSettingsEntries)
        {
            throw new ArgumentException(
                "A SETTINGS frame holds at most 2730 entries so its payload fits the " +
                "16384-octet default maximum frame size (RFC 9113 section 4.2).",
                PrefaceParameter);
        }

        var payload = new byte[settings.Count * 6];
        var offset = 0;
        foreach (var setting in settings)
        {
            ApplySetting(setting.Id, setting.Value, state);
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(offset, 2), setting.Id);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(offset + 2, 4), setting.Value);
            offset += 6;
        }
        return new TlsHttp2PrefaceFrameConfiguration(
            SettingsFrameType,
            0,
            0,
            payload,
            frame.FlushAfter);
    }

    private static TlsHttp2PrefaceFrameConfiguration FreezeWindowUpdate(
        TlsHttp2WindowUpdateFrame frame,
        LocalReceiveState state)
    {
        var payload = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(payload, frame.Increment);
        state.ConnectionReceiveWindow += frame.Increment;
        return new TlsHttp2PrefaceFrameConfiguration(
            WindowUpdateFrameType,
            0,
            0,
            payload,
            frame.FlushAfter);
    }

    private static TlsHttp2PrefaceFrameConfiguration FreezePriority(
        TlsHttp2PrefacePriorityFrame frame)
    {
        ValidateStreamId(frame.StreamId);
        var priority = (frame.Priority ??
            throw new ArgumentException(
                "A preface PRIORITY frame is missing its priority data.",
                PrefaceParameter)).Snapshot();
        if (priority.StreamDependency == frame.StreamId)
        {
            throw new ArgumentException(
                "A stream cannot depend on itself.",
                PrefaceParameter);
        }
        return new TlsHttp2PrefaceFrameConfiguration(
            PriorityFrameType,
            0,
            frame.StreamId,
            priority.BuildPayload(),
            frame.FlushAfter);
    }

    private static TlsHttp2PrefaceFrameConfiguration FreezeRaw(
        TlsHttp2RawFrame frame,
        LocalReceiveState state)
    {
        // DATA, HEADERS, RST_STREAM, GOAWAY and CONTINUATION are frames the connection
        // owns; PUSH_PROMISE from a client is a protocol error. SETTINGS and
        // WINDOW_UPDATE are permitted because the derivation below parses them.
        if (frame.Type is 0x0 or 0x1 or 0x3 or 0x5 or 0x7 or 0x9)
        {
            throw new ArgumentException(
                "A raw preface frame cannot use frame type DATA, HEADERS, RST_STREAM, " +
                "PUSH_PROMISE, GOAWAY, or CONTINUATION.",
                PrefaceParameter);
        }
        ValidateStreamId(frame.StreamId);
        var declared = frame.Payload ??
            throw new ArgumentException(
                "A raw preface frame's payload cannot be null.",
                PrefaceParameter);
        if (declared.Length > MaximumRawPayloadBytes)
        {
            throw new ArgumentException(
                "A raw preface frame payload holds at most 16384 bytes.",
                PrefaceParameter);
        }

        var payload = declared.ToArray();
        if (frame.Type == SettingsFrameType)
        {
            for (var offset = 0; offset + 6 <= payload.Length; offset += 6)
            {
                ApplySetting(
                    BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(offset, 2)),
                    BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset + 2, 4)),
                    state);
            }
        }
        else if (frame.Type == WindowUpdateFrameType &&
            frame.StreamId == 0 &&
            payload.Length >= 4)
        {
            state.ConnectionReceiveWindow += BinaryPrimitives.ReadUInt32BigEndian(payload);
        }
        return new TlsHttp2PrefaceFrameConfiguration(
            frame.Type,
            frame.Flags,
            frame.StreamId,
            payload,
            frame.FlushAfter);
    }

    private static void ApplySetting(ushort identifier, uint value, LocalReceiveState state)
    {
        switch (identifier)
        {
            case 0x1:
                if (value > MaximumHeaderTableSize)
                {
                    throw new ArgumentException(
                        "SETTINGS_HEADER_TABLE_SIZE must not exceed 16777216, the HPACK " +
                        "table capacity TlsClient will hold.",
                        PrefaceParameter);
                }
                state.HeaderTableSize = value;
                break;
            case 0x2:
                if (value > 1)
                {
                    throw new ArgumentException(
                        "SETTINGS_ENABLE_PUSH must be 0 or 1 (RFC 9113 section 6.5.2).",
                        PrefaceParameter);
                }
                state.EnablePush = value == 1;
                break;
            case 0x4:
                if (value > int.MaxValue)
                {
                    throw new ArgumentException(
                        "SETTINGS_INITIAL_WINDOW_SIZE must not exceed 2^31 - 1 " +
                        "(RFC 9113 section 6.5.2).",
                        PrefaceParameter);
                }
                state.InitialWindowSize = (int)value;
                break;
            case 0x5:
                if (value is < 16_384 or > 16_777_215)
                {
                    throw new ArgumentException(
                        "SETTINGS_MAX_FRAME_SIZE must be within [16384, 16777215] " +
                        "(RFC 9113 section 6.5.2).",
                        PrefaceParameter);
                }
                state.MaxFrameSize = (int)value;
                break;
            case 0x6:
                state.MaxHeaderListSize = value;
                break;
            default:
                // Unknown identifiers reach the wire and leave local receive state alone.
                break;
        }
    }

    private static void ValidateStreamId(int streamId)
    {
        if (streamId < 0)
        {
            throw new ArgumentException(
                "A preface frame's stream identifier must be within [0, 2^31 - 1].",
                PrefaceParameter);
        }
    }

    /// <summary>
    /// Local receive state derived from the preface, seeded with the RFC 9113 defaults
    /// that apply to every identifier the script leaves out. MAX_HEADER_LIST_SIZE has no
    /// default, so its absence means unbounded.
    /// </summary>
    private sealed class LocalReceiveState
    {
        public uint HeaderTableSize { get; set; } = 4096;

        public bool EnablePush { get; set; } = true;

        public int InitialWindowSize { get; set; } = 65_535;

        public int MaxFrameSize { get; set; } = 16_384;

        public uint? MaxHeaderListSize { get; set; }

        public long ConnectionReceiveWindow { get; set; } = 65_535;
    }
}
