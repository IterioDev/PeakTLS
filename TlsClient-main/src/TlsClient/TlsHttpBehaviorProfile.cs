using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TlsClient;

/// <summary>
/// Immutable, importable HTTP header order and HTTP/2 session behavior captured from
/// options: the preface script, the HPACK policy, stream identifiers, pseudo-header
/// composition, header and DATA framing, flow-control credit policy, shutdown codes, and
/// the write-batch flush points. Header values, cookies, credentials, and request bodies
/// are never captured.
/// </summary>
/// <remarks>
/// <para>
/// <b>A profile describes a session, not a request.</b> Everything it carries comes from
/// <see cref="TlsSessionOptions"/> and <see cref="TlsHttp2Options"/>, which is what makes
/// <see cref="ApplyTo"/> reproducible: applying a profile configures a connection, and every
/// request that connection then carries inherits it.
/// </para>
/// <para>
/// The per-request axes are deliberately <em>not</em> carried, and this is not an omission
/// waiting to be completed. <see cref="TlsRequestOptions.FramesBeforeHeaders"/>,
/// <see cref="TlsRequestOptions.FramesAfterHeaders"/>, and every other nullable
/// <see cref="TlsRequestOptions"/> override belong to one request rather than to the
/// connection it travels on: two requests on the same connection may each declare their own,
/// so there is no single value a profile could hold, and a profile that captured one
/// request's script would silently impose it on all of them. Carry those on the request.
/// </para>
/// </remarks>
public sealed class TlsHttpBehaviorProfile
{
    private const int DefaultMaximumDocumentSize = 256 * 1024;
    private const int MaximumAllowedDocumentSize = 4 * 1024 * 1024;
    private const string DocumentFormat = "tlsclient-http-behavior";

    // Version 3 carries the request-lifecycle session options. This is a private fork, so
    // version 2 is rejected rather than migrated.
    private const int DocumentVersion = 3;

    private static readonly JsonSerializerOptions IndentedJsonOptions = CreateJsonOptions(true);
    private static readonly JsonSerializerOptions CompactJsonOptions = CreateJsonOptions(false);

    private TlsHttpBehaviorProfile(
        string name,
        TlsHttpVersionPolicy httpVersionPolicy,
        string[] headerOrder,
        TlsHttp2Behavior http2)
    {
        Name = name;
        HttpVersionPolicy = httpVersionPolicy;
        HeaderOrder = Array.AsReadOnly(headerOrder);
        Http2 = http2;
    }

    /// <summary>Gets the caller-assigned behavior profile name.</summary>
    public string Name { get; }

    /// <summary>Gets the captured HTTP version and ALPN policy.</summary>
    public TlsHttpVersionPolicy HttpVersionPolicy { get; }

    /// <summary>Gets preferred regular-header names in exact order.</summary>
    public IReadOnlyList<string> HeaderOrder { get; }

    /// <summary>
    /// Gets the captured HTTP/2 connection behavior: the preface script, the HPACK policy,
    /// stream identifiers, pseudo-header composition, header and DATA framing, flow-control
    /// credit policy, shutdown codes, priority, and the write-batch flush points.
    /// </summary>
    public TlsHttp2Behavior Http2 { get; }

    /// <summary>
    /// Explicitly captures fingerprint-relevant HTTP behavior from mutable session options.
    /// </summary>
    public static TlsHttpBehaviorProfile Capture(string name, TlsSessionOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(options);
        if (!Enum.IsDefined(options.HttpVersionPolicy))
        {
            throw new ArgumentOutOfRangeException(nameof(options));
        }

        var headerOrder = options.HeaderOrder?.ToArray() ?? [];
        ValidateHeaderOrder(headerOrder);
        var http2 = options.Http2.Snapshot();
        return new TlsHttpBehaviorProfile(
            name,
            options.HttpVersionPolicy,
            headerOrder,
            TlsHttp2Behavior.FromConfiguration(http2));
    }

    /// <summary>Exports the behavior in TlsClient's strict, versioned JSON format.</summary>
    public string ExportJson(bool writeIndented = true) =>
        JsonSerializer.Serialize(
            ToDocument(),
            writeIndented ? IndentedJsonOptions : CompactJsonOptions);

    /// <summary>Imports a strict, bounded TlsClient HTTP behavior document.</summary>
    /// <param name="json">The versioned JSON document.</param>
    /// <param name="maximumDocumentSize">Maximum UTF-8 size, up to 4 MiB.</param>
    public static TlsHttpBehaviorProfile ImportJson(
        string json,
        int maximumDocumentSize = DefaultMaximumDocumentSize)
    {
        ArgumentNullException.ThrowIfNull(json);
        if (maximumDocumentSize is < 1 or > MaximumAllowedDocumentSize)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDocumentSize));
        }
        if (Encoding.UTF8.GetByteCount(json) > maximumDocumentSize)
        {
            throw new JsonException(
                $"The HTTP behavior document exceeds {maximumDocumentSize} UTF-8 bytes.");
        }

        using (var parsed = JsonDocument.Parse(
            json,
            new JsonDocumentOptions { MaxDepth = 32 }))
        {
            ValidateNoDuplicateProperties(parsed.RootElement);
        }

        var document = JsonSerializer.Deserialize<HttpBehaviorDocument>(
            json,
            CompactJsonOptions) ?? throw new JsonException("The document cannot be null.");
        if (!string.Equals(document.Format, DocumentFormat, StringComparison.Ordinal) ||
            document.Version != DocumentVersion)
        {
            throw new JsonException("Unsupported HTTP behavior format or version.");
        }
        ArgumentException.ThrowIfNullOrWhiteSpace(document.Name);
        if (!Enum.IsDefined(document.HttpVersionPolicy))
        {
            throw new JsonException("The HTTP version policy is not defined.");
        }
        if (document.HeaderOrder is null || document.Http2 is null)
        {
            throw new JsonException("The behavior document is missing required fields.");
        }

        ValidateHeaderOrder(document.HeaderOrder);
        var profile = new TlsHttpBehaviorProfile(
            document.Name,
            document.HttpVersionPolicy,
            (string[])document.HeaderOrder.Clone(),
            TlsHttp2Behavior.FromDocument(document.Http2));

        // Apply through the normal public option model so every production bound and
        // cross-field constraint is enforced by the same validation path.
        var validationOptions = new TlsSessionOptions();
        profile.ApplyTo(validationOptions);
        _ = validationOptions.Snapshot();
        return profile;
    }

    /// <summary>
    /// Applies the captured HTTP behavior to options without changing TLS, headers values,
    /// proxy, retry, cookie, or certificate policy.
    /// </summary>
    public void ApplyTo(TlsSessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.HttpVersionPolicy = HttpVersionPolicy;
        options.HeaderOrder = HeaderOrder.ToArray();
        Http2.ApplyTo(options.Http2);
    }

    private HttpBehaviorDocument ToDocument() => new(
        DocumentFormat,
        DocumentVersion,
        Name,
        HttpVersionPolicy,
        HeaderOrder.ToArray(),
        Http2.ToDocument());

    private static JsonSerializerOptions CreateJsonOptions(bool writeIndented) => new()
    {
        WriteIndented = writeIndented,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter() },
        MaxDepth = 32,
    };

    private static void ValidateHeaderOrder(string[] headerOrder)
    {
        if (headerOrder.Length > 256 ||
            headerOrder.Any(string.IsNullOrWhiteSpace) ||
            headerOrder.Distinct(StringComparer.OrdinalIgnoreCase).Count() != headerOrder.Length)
        {
            throw new JsonException(
                "Header order must contain at most 256 distinct, non-empty names.");
        }
    }

    private static void ValidateNoDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new JsonException($"Duplicate JSON property '{property.Name}'.");
                }
                ValidateNoDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                ValidateNoDuplicateProperties(item);
            }
        }
    }

    internal sealed record HttpBehaviorDocument(
        string Format,
        int Version,
        string Name,
        TlsHttpVersionPolicy HttpVersionPolicy,
        string[] HeaderOrder,
        Http2Document Http2);

    internal sealed record Http2Document(
        int InitialStreamId,
        int StreamIdStep,
        TlsHttp2SettingsAckPlacement SettingsAckPlacement,
        PseudoHeaderDocument PseudoHeaders,
        PriorityDocument? HeaderPriority,
        string? PriorityUpdate,
        PrefaceFrameDocument[] Preface,
        HpackDocument Hpack,
        DataDocument Data,
        FlowControlDocument FlowControl,
        ShutdownDocument Shutdown,
        int? HeaderBlockFragmentSize,
        bool FlushAfterHeaderBlock,
        bool FlushAfterEveryDataFrame);

    internal sealed record PriorityDocument(int StreamDependency, bool Exclusive, int Weight);

    internal sealed record PseudoHeaderDocument(
        string[] Order,
        TlsHttp2AuthorityMode AuthorityMode,
        string Scheme);

    internal sealed record DataDocument(
        int? MaxDataFrameSize,
        TlsHttp2EndStreamPlacement NonEmptyBody,
        bool EmptyBodyEndsOnHeaders);

    internal sealed record FlowControlDocument(
        int StreamWindowUpdateThreshold,
        int ConnectionWindowUpdateThreshold,
        TlsHttp2WindowUpdateTrigger Trigger,
        TlsHttp2WindowUpdateIncrement Increment,
        int FixedIncrement,
        TlsHttp2WindowUpdateOrder Order,
        bool CoalesceConnectionAndStream,
        bool SuppressStreamUpdateOnEndStream);

    /// <summary>
    /// The shutdown policy. <c>GoAwayDebugData</c> is base64 for the same reason a preface
    /// payload is: RFC 9113 section 6.8 makes it opaque octets with no text encoding.
    /// </summary>
    internal sealed record ShutdownDocument(
        bool SendGoAwayOnDispose,
        Http2ErrorCode GoAwayErrorCode,
        string? GoAwayDebugData,
        Http2ErrorCode CancellationResetCode,
        Http2ErrorCode LocalFailureResetCode,
        Http2ErrorCode PushRejectionResetCode);

    /// <summary>
    /// One preface frame as the octets it emits. Every declared frame type reduces to
    /// this, so a captured preface reproduces byte for byte whatever shape it was
    /// declared in.
    /// </summary>
    internal sealed record PrefaceFrameDocument(
        byte Type,
        byte Flags,
        int StreamId,
        string Payload,
        bool FlushAfter);

    internal sealed record HpackDocument(
        TlsHpackRepresentation DefaultRepresentation,
        TlsHpackRepresentation IndexedFallback,
        bool UseDynamicTable,
        Dictionary<string, TlsHpackRepresentation> PerHeader,
        TlsHpackHuffman Huffman,
        Dictionary<string, TlsHpackHuffman> PerHeaderHuffman,
        TlsHpackNameIndex NameIndex,
        Dictionary<string, int> PerHeaderNameIndex,
        TlsHpackMultiValue MultiValue,
        Dictionary<string, TlsHpackMultiValue> PerHeaderMultiValue,
        string MultiValueJoinSeparator,
        TlsHpackTableSizeUpdate TableSizeUpdate,
        uint[] TableSizeUpdateValues,
        bool CrumbleCookies,
        string CookieCrumbSeparator);

    /// <summary>
    /// Immutable HTTP/2 <em>session</em> behavior: stream identifiers, pseudo-header
    /// composition, header and DATA framing, flow-control credit policy, shutdown codes,
    /// ordering, priority, and flush points. Per-request overrides are not part of it — see
    /// the remarks on <see cref="TlsHttpBehaviorProfile"/>.
    /// </summary>
    public sealed class TlsHttp2Behavior
    {
        private readonly TlsHttp2PrefaceFrameConfiguration[] _preface;
        private readonly TlsHpackConfiguration _hpack;
        private readonly TlsHttp2PseudoHeaderConfiguration _pseudoHeaders;
        private readonly TlsHttp2DataConfiguration _data;
        private readonly TlsHttp2FlowControlConfiguration _flowControl;
        private readonly TlsHttp2ShutdownConfiguration _shutdown;
        private readonly int? _headerBlockFragmentSize;
        private readonly bool _flushAfterHeaderBlock;
        private readonly bool _flushAfterEveryDataFrame;

        private TlsHttp2Behavior(
            int initialStreamId,
            int streamIdStep,
            TlsHttp2SettingsAckPlacement settingsAckPlacement,
            TlsHttp2PseudoHeaderConfiguration pseudoHeaders,
            TlsHttp2PriorityBehavior? headerPriority,
            string? priorityUpdate,
            TlsHttp2PrefaceFrameConfiguration[] preface,
            TlsHpackConfiguration hpack,
            TlsHttp2DataConfiguration data,
            TlsHttp2FlowControlConfiguration flowControl,
            TlsHttp2ShutdownConfiguration shutdown,
            int? headerBlockFragmentSize,
            bool flushAfterHeaderBlock,
            bool flushAfterEveryDataFrame)
        {
            InitialStreamId = initialStreamId;
            StreamIdStep = streamIdStep;
            SettingsAckPlacement = settingsAckPlacement;
            PseudoHeaderOrder = Array.AsReadOnly(pseudoHeaders.Order);
            HeaderPriority = headerPriority;
            PriorityUpdate = priorityUpdate;
            _preface = preface;
            _hpack = hpack;
            _pseudoHeaders = pseudoHeaders;
            _data = data;
            _flowControl = flowControl;
            _shutdown = shutdown;
            _headerBlockFragmentSize = headerBlockFragmentSize;
            _flushAfterHeaderBlock = flushAfterHeaderBlock;
            _flushAfterEveryDataFrame = flushAfterEveryDataFrame;
        }

        /// <summary>Gets the first client stream identifier.</summary>
        public int InitialStreamId { get; }

        /// <summary>Gets the increment between client stream identifiers.</summary>
        public int StreamIdStep { get; }

        /// <summary>Gets where a SETTINGS acknowledgement sits in the outbound sequence.</summary>
        public TlsHttp2SettingsAckPlacement SettingsAckPlacement { get; }

        /// <summary>Gets pseudo-header names in exact wire order.</summary>
        public IReadOnlyList<string> PseudoHeaderOrder { get; }

        /// <summary>Gets optional priority data embedded in HEADERS.</summary>
        public TlsHttp2PriorityBehavior? HeaderPriority { get; }

        /// <summary>Gets the optional RFC 9218 Priority Field Value.</summary>
        public string? PriorityUpdate { get; }

        internal static TlsHttp2Behavior FromConfiguration(TlsHttp2Configuration value) => new(
            value.InitialStreamId,
            value.StreamIdStep,
            value.SettingsAckPlacement,
            value.PseudoHeaders with { Order = (string[])value.PseudoHeaders.Order.Clone() },
            TlsHttp2PriorityBehavior.FromConfiguration(value.HeaderPriority),
            value.PriorityUpdate,
            value.Preface,
            value.Hpack,
            value.Data,
            value.FlowControl,
            value.Shutdown,
            value.HeaderBlockFragmentSize,
            value.FlushAfterHeaderBlock,
            value.FlushAfterEveryDataFrame);

        internal static TlsHttp2Behavior FromDocument(Http2Document value)
        {
            if (!Enum.IsDefined(value.SettingsAckPlacement))
            {
                throw new JsonException("The SETTINGS acknowledgement placement is not defined.");
            }
            if (value.Preface is null ||
                value.Hpack is null ||
                value.PseudoHeaders is null ||
                value.Data is null ||
                value.FlowControl is null ||
                value.Shutdown is null)
            {
                throw new JsonException("The HTTP/2 document is missing required fields.");
            }
            return new TlsHttp2Behavior(
                value.InitialStreamId,
                value.StreamIdStep,
                value.SettingsAckPlacement,
                FromDocument(value.PseudoHeaders),
                TlsHttp2PriorityBehavior.FromDocument(value.HeaderPriority),
                value.PriorityUpdate,
                Array.ConvertAll(value.Preface, FromDocument),
                FromDocument(value.Hpack),
                FromDocument(value.Data),
                FromDocument(value.FlowControl),
                FromDocument(value.Shutdown),
                value.HeaderBlockFragmentSize,
                value.FlushAfterHeaderBlock,
                value.FlushAfterEveryDataFrame);
        }

        /// <summary>
        /// Rejects an enum value the document names by number rather than by one of its
        /// declared names. <see cref="JsonStringEnumConverter"/> accepts integers, so without
        /// this an out-of-range value reaches the option object and only surfaces later as an
        /// <see cref="ArgumentOutOfRangeException"/> from validation rather than as a
        /// rejected document.
        /// </summary>
        private static TEnum Defined<TEnum>(TEnum value, string what)
            where TEnum : struct, Enum =>
            Enum.IsDefined(value) ? value : throw new JsonException($"The {what} is not defined.");

        private static TlsHttp2PseudoHeaderConfiguration FromDocument(PseudoHeaderDocument value)
        {
            if (value.Order is null || value.Scheme is null)
            {
                throw new JsonException("The pseudo-header document is missing required fields.");
            }
            return new TlsHttp2PseudoHeaderConfiguration(
                (string[])value.Order.Clone(),
                Defined(value.AuthorityMode, "authority mode"),
                value.Scheme);
        }

        private static TlsHttp2DataConfiguration FromDocument(DataDocument value) => new(
            value.MaxDataFrameSize,
            Defined(value.NonEmptyBody, "END_STREAM placement"),
            value.EmptyBodyEndsOnHeaders);

        private static TlsHttp2FlowControlConfiguration FromDocument(FlowControlDocument value) =>
            new(
                value.StreamWindowUpdateThreshold,
                value.ConnectionWindowUpdateThreshold,
                Defined(value.Trigger, "WINDOW_UPDATE trigger"),
                Defined(value.Increment, "WINDOW_UPDATE increment"),
                value.FixedIncrement,
                Defined(value.Order, "WINDOW_UPDATE order"),
                value.CoalesceConnectionAndStream,
                value.SuppressStreamUpdateOnEndStream);

        private static TlsHttp2ShutdownConfiguration FromDocument(ShutdownDocument value)
        {
            byte[]? debugData = null;
            if (value.GoAwayDebugData is not null)
            {
                try
                {
                    debugData = Convert.FromBase64String(value.GoAwayDebugData);
                }
                catch (FormatException exception)
                {
                    throw new JsonException(
                        "The GOAWAY debug data is not valid base64.",
                        exception);
                }
            }
            return new TlsHttp2ShutdownConfiguration(
                value.SendGoAwayOnDispose,
                Defined(value.GoAwayErrorCode, "GOAWAY error code"),
                debugData,
                Defined(value.CancellationResetCode, "cancellation reset code"),
                Defined(value.LocalFailureResetCode, "local failure reset code"),
                Defined(value.PushRejectionResetCode, "push rejection reset code"));
        }

        private static TlsHttp2PrefaceFrameConfiguration FromDocument(PrefaceFrameDocument value)
        {
            if (value.Payload is null)
            {
                throw new JsonException("A preface frame is missing its payload.");
            }
            byte[] payload;
            try
            {
                payload = Convert.FromBase64String(value.Payload);
            }
            catch (FormatException exception)
            {
                throw new JsonException("A preface frame payload is not valid base64.", exception);
            }
            return new TlsHttp2PrefaceFrameConfiguration(
                value.Type,
                value.Flags,
                value.StreamId,
                payload,
                value.FlushAfter);
        }

        private static TlsHpackConfiguration FromDocument(HpackDocument value)
        {
            if (value.PerHeader is null ||
                value.PerHeaderHuffman is null ||
                value.PerHeaderNameIndex is null ||
                value.PerHeaderMultiValue is null ||
                value.TableSizeUpdateValues is null ||
                value.MultiValueJoinSeparator is null ||
                value.CookieCrumbSeparator is null)
            {
                throw new JsonException("The HPACK document is missing required fields.");
            }
            return new TlsHpackConfiguration(
                value.DefaultRepresentation,
                value.IndexedFallback,
                value.UseDynamicTable,
                value.PerHeader,
                value.Huffman,
                value.PerHeaderHuffman,
                value.NameIndex,
                value.PerHeaderNameIndex,
                value.MultiValue,
                value.PerHeaderMultiValue,
                value.MultiValueJoinSeparator,
                value.TableSizeUpdate,
                value.TableSizeUpdateValues,
                value.CrumbleCookies,
                value.CookieCrumbSeparator);
        }

        internal void ApplyTo(TlsHttp2Options options)
        {
            options.InitialStreamId = InitialStreamId;
            options.StreamIdStep = StreamIdStep;
            options.SettingsAckPlacement = SettingsAckPlacement;
            options.HeaderPriority = HeaderPriority?.ToOptions();
            options.PriorityUpdate = PriorityUpdate;
            options.HeaderBlockFragmentSize = _headerBlockFragmentSize;
            options.FlushAfterHeaderBlock = _flushAfterHeaderBlock;
            options.FlushAfterEveryDataFrame = _flushAfterEveryDataFrame;

            // Written through the option objects rather than through
            // TlsHttp2Options.PseudoHeaderOrder, which survives only as a forwarding
            // property over PseudoHeaders.Order and reaches none of the other two fields.
            var pseudoHeaders = options.PseudoHeaders;
            pseudoHeaders.Order = (string[])_pseudoHeaders.Order.Clone();
            pseudoHeaders.AuthorityMode = _pseudoHeaders.AuthorityMode;
            pseudoHeaders.Scheme = _pseudoHeaders.Scheme;

            var data = options.Data;
            data.MaxDataFrameSize = _data.MaxDataFrameSize;
            data.NonEmptyBody = _data.NonEmptyBody;
            data.EmptyBodyEndsOnHeaders = _data.EmptyBodyEndsOnHeaders;

            // The frozen configuration narrows each of these to int, and a document could
            // carry a negative one. The cast back to uint turns that into a value above
            // 2^31 - 1, which is exactly what TlsHttp2FlowControlOptions.Snapshot rejects,
            // so the import path's validation pass still catches it.
            var flowControl = options.FlowControl;
            flowControl.StreamWindowUpdateThreshold = (uint)_flowControl.StreamWindowUpdateThreshold;
            flowControl.ConnectionWindowUpdateThreshold =
                (uint)_flowControl.ConnectionWindowUpdateThreshold;
            flowControl.Trigger = _flowControl.Trigger;
            flowControl.Increment = _flowControl.Increment;
            flowControl.FixedIncrement = (uint)_flowControl.FixedIncrement;
            flowControl.Order = _flowControl.Order;
            flowControl.CoalesceConnectionAndStream = _flowControl.CoalesceConnectionAndStream;
            flowControl.SuppressStreamUpdateOnEndStream =
                _flowControl.SuppressStreamUpdateOnEndStream;

            var shutdown = options.Shutdown;
            shutdown.SendGoAwayOnDispose = _shutdown.SendGoAwayOnDispose;
            shutdown.GoAwayErrorCode = _shutdown.GoAwayErrorCode;
            shutdown.GoAwayDebugData = (byte[]?)_shutdown.GoAwayDebugData?.Clone();
            shutdown.CancellationResetCode = _shutdown.CancellationResetCode;
            shutdown.LocalFailureResetCode = _shutdown.LocalFailureResetCode;
            shutdown.PushRejectionResetCode = _shutdown.PushRejectionResetCode;

            // Every declared frame type freezes to the same octets, so restoring the
            // preface as raw frames reproduces the captured bytes exactly whatever shape
            // it was declared in. Local receive state is derived from those octets, so a
            // restored SETTINGS or WINDOW_UPDATE still feeds the receive bounds.
            options.Preface = Array.ConvertAll(
                _preface,
                frame => (TlsHttp2PrefaceFrame)new TlsHttp2RawFrame
                {
                    Type = frame.Type,
                    Flags = frame.Flags,
                    StreamId = frame.StreamId,
                    Payload = (byte[])frame.Payload.Clone(),
                    FlushAfter = frame.FlushAfter,
                });

            var hpack = options.Hpack;
            hpack.DefaultRepresentation = _hpack.DefaultRepresentation;
            hpack.IndexedFallback = _hpack.IndexedFallback;
            hpack.UseDynamicTable = _hpack.UseDynamicTable;
            hpack.Huffman = _hpack.Huffman;
            hpack.NameIndex = _hpack.NameIndex;
            hpack.MultiValue = _hpack.MultiValue;
            hpack.MultiValueJoinSeparator = _hpack.MultiValueJoinSeparator;
            hpack.TableSizeUpdate = _hpack.TableSizeUpdate;
            hpack.TableSizeUpdateValues = [.. _hpack.TableSizeUpdateValues];
            hpack.CrumbleCookies = _hpack.CrumbleCookies;
            hpack.CookieCrumbSeparator = _hpack.CookieCrumbSeparator;
            Replace(hpack.PerHeader, _hpack.PerHeader);
            Replace(hpack.PerHeaderHuffman, _hpack.PerHeaderHuffman);
            Replace(hpack.PerHeaderNameIndex, _hpack.PerHeaderNameIndex);
            Replace(hpack.PerHeaderMultiValue, _hpack.PerHeaderMultiValue);

            static void Replace<TValue>(
                IDictionary<string, TValue> target,
                Dictionary<string, TValue> source)
            {
                // Cleared rather than merged: the captured policy is the whole policy, and
                // TlsHpackOptions ships non-empty PerHeader defaults that would otherwise
                // survive a capture that removed them.
                target.Clear();
                foreach (var entry in source)
                {
                    target[entry.Key] = entry.Value;
                }
            }
        }

        internal Http2Document ToDocument() => new(
            InitialStreamId,
            StreamIdStep,
            SettingsAckPlacement,
            new PseudoHeaderDocument(
                (string[])_pseudoHeaders.Order.Clone(),
                _pseudoHeaders.AuthorityMode,
                _pseudoHeaders.Scheme),
            HeaderPriority?.ToDocument(),
            PriorityUpdate,
            Array.ConvertAll(
                _preface,
                frame => new PrefaceFrameDocument(
                    frame.Type,
                    frame.Flags,
                    frame.StreamId,
                    Convert.ToBase64String(frame.Payload),
                    frame.FlushAfter)),
            new HpackDocument(
                _hpack.DefaultRepresentation,
                _hpack.IndexedFallback,
                _hpack.UseDynamicTable,
                _hpack.PerHeader,
                _hpack.Huffman,
                _hpack.PerHeaderHuffman,
                _hpack.NameIndex,
                _hpack.PerHeaderNameIndex,
                _hpack.MultiValue,
                _hpack.PerHeaderMultiValue,
                _hpack.MultiValueJoinSeparator,
                _hpack.TableSizeUpdate,
                _hpack.TableSizeUpdateValues,
                _hpack.CrumbleCookies,
                _hpack.CookieCrumbSeparator),
            new DataDocument(
                _data.MaxDataFrameSize,
                _data.NonEmptyBody,
                _data.EmptyBodyEndsOnHeaders),
            new FlowControlDocument(
                _flowControl.StreamWindowUpdateThreshold,
                _flowControl.ConnectionWindowUpdateThreshold,
                _flowControl.Trigger,
                _flowControl.Increment,
                _flowControl.FixedIncrement,
                _flowControl.Order,
                _flowControl.CoalesceConnectionAndStream,
                _flowControl.SuppressStreamUpdateOnEndStream),
            new ShutdownDocument(
                _shutdown.SendGoAwayOnDispose,
                _shutdown.GoAwayErrorCode,
                _shutdown.GoAwayDebugData is null
                    ? null
                    : Convert.ToBase64String(_shutdown.GoAwayDebugData),
                _shutdown.CancellationResetCode,
                _shutdown.LocalFailureResetCode,
                _shutdown.PushRejectionResetCode),
            _headerBlockFragmentSize,
            _flushAfterHeaderBlock,
            _flushAfterEveryDataFrame);
    }

    /// <summary>Immutable HTTP/2 dependency, exclusivity, and weight.</summary>
    public sealed class TlsHttp2PriorityBehavior
    {
        private TlsHttp2PriorityBehavior(int streamDependency, bool exclusive, int weight)
        {
            StreamDependency = streamDependency;
            Exclusive = exclusive;
            Weight = weight;
        }

        /// <summary>Gets the dependency stream identifier.</summary>
        public int StreamDependency { get; }

        /// <summary>Gets whether the dependency is exclusive.</summary>
        public bool Exclusive { get; }

        /// <summary>Gets the relative weight.</summary>
        public int Weight { get; }

        internal static TlsHttp2PriorityBehavior? FromConfiguration(
            TlsHttp2PriorityConfiguration? value) => value is null
                ? null
                : new(value.StreamDependency, value.Exclusive, value.Weight);

        internal static TlsHttp2PriorityBehavior? FromDocument(PriorityDocument? value) =>
            value is null ? null : new(value.StreamDependency, value.Exclusive, value.Weight);

        internal TlsHttp2Priority ToOptions() => new()
        {
            StreamDependency = StreamDependency,
            Exclusive = Exclusive,
            Weight = Weight,
        };

        internal PriorityDocument ToDocument() => new(StreamDependency, Exclusive, Weight);
    }
}
