namespace TlsClient;

/// <summary>When the client returns receive-window credit for a DATA frame.</summary>
public enum TlsHttp2WindowUpdateTrigger
{
    /// <summary>Credit is returned when the application accepts the octets.</summary>
    OnConsume = 0,

    /// <summary>Credit is returned as soon as the DATA frame is received.</summary>
    OnReceive = 1,
}

/// <summary>How large a WINDOW_UPDATE increment the client returns.</summary>
public enum TlsHttp2WindowUpdateIncrement
{
    /// <summary>The increment equals the octets being credited.</summary>
    BytesAccounted = 0,

    /// <summary>The increment restores the window to its declared initial size.</summary>
    RefillToInitial = 1,

    /// <summary>
    /// The increment is always
    /// <see cref="TlsHttp2FlowControlOptions.FixedIncrement"/>.
    /// </summary>
    Fixed = 2,
}

/// <summary>Which WINDOW_UPDATE the client writes first.</summary>
public enum TlsHttp2WindowUpdateOrder
{
    /// <summary>The connection-level update, on stream 0, is written first.</summary>
    ConnectionFirst = 0,

    /// <summary>The stream-level update is written first.</summary>
    StreamFirst = 1,
}

/// <summary>
/// Configures when the client returns HTTP/2 receive-window credit, how much of it, and in
/// what shape the WINDOW_UPDATE frames reach the wire.
/// </summary>
/// <remarks>
/// Every axis here is spec-legal and produces a distinguishable trace. The only hard
/// bounds RFC 9113 section 6.9 places on the frame are that the increment is in
/// [1, 2^31 - 1], that the resulting window does not exceed 2^31 - 1 (section 6.9.1), and
/// that the payload is exactly 4 octets.
/// </remarks>
public sealed class TlsHttp2FlowControlOptions
{
    // CA2208 only accepts a compile-time paramName that names a parameter of the throwing
    // method, and this rejection belongs to a property of this object.
    private static readonly string FixedIncrementParameter = nameof(FixedIncrement);

    /// <summary>
    /// Gets or sets how many uncredited stream octets must accumulate before a
    /// stream-level WINDOW_UPDATE is emitted. <c>0</c>, the default, credits as octets are
    /// accounted, which is today's behaviour.
    /// </summary>
    public uint StreamWindowUpdateThreshold { get; set; }

    /// <summary>
    /// Gets or sets how many uncredited connection octets must accumulate before a
    /// connection-level WINDOW_UPDATE is emitted. <c>0</c>, the default, credits as octets
    /// are accounted, which is today's behaviour.
    /// </summary>
    public uint ConnectionWindowUpdateThreshold { get; set; }

    /// <summary>
    /// Gets or sets when credit is returned. The default,
    /// <see cref="TlsHttp2WindowUpdateTrigger.OnConsume"/>, is today's behaviour.
    /// </summary>
    public TlsHttp2WindowUpdateTrigger Trigger { get; set; }
        = TlsHttp2WindowUpdateTrigger.OnConsume;

    /// <summary>
    /// Gets or sets how large the returned increment is. The default,
    /// <see cref="TlsHttp2WindowUpdateIncrement.BytesAccounted"/>, is today's behaviour.
    /// </summary>
    /// <remarks>
    /// <see cref="TlsHttp2WindowUpdateIncrement.Fixed"/> is the one mode that can return
    /// less than was consumed. RFC 9113 section 6.9.1 has the peer send only what the
    /// advertised window permits, so a fixed increment below the average consumed amount
    /// shrinks the window on every update until the transfer stalls. Nothing rejects that
    /// — a real client that does it is still a real client — but it is not a default.
    /// </remarks>
    public TlsHttp2WindowUpdateIncrement Increment { get; set; }
        = TlsHttp2WindowUpdateIncrement.BytesAccounted;

    /// <summary>
    /// Gets or sets the increment used when <see cref="Increment"/> is
    /// <see cref="TlsHttp2WindowUpdateIncrement.Fixed"/>.
    /// </summary>
    /// <remarks>
    /// A value above 2^31 - 1 is rejected whatever <see cref="Increment"/> says, because the
    /// frozen configuration narrows this field to <see cref="int"/>. Only the rejection of
    /// <c>0</c> is gated on <see cref="TlsHttp2WindowUpdateIncrement.Fixed"/>, since <c>0</c>
    /// is also this property's default.
    /// </remarks>
    public uint FixedIncrement { get; set; }

    /// <summary>
    /// Gets or sets which level is written first. The default,
    /// <see cref="TlsHttp2WindowUpdateOrder.ConnectionFirst"/>, is today's behaviour.
    /// </summary>
    /// <remarks>
    /// RFC 9113 section 6.9 places no ordering constraint on the two levels — the
    /// connection window is addressed by stream 0 and each is accounted independently — so
    /// either order is a client's own choice.
    /// </remarks>
    public TlsHttp2WindowUpdateOrder Order { get; set; }
        = TlsHttp2WindowUpdateOrder.ConnectionFirst;

    /// <summary>
    /// Gets or sets whether the connection-level and stream-level updates share one write
    /// batch, so they reach the peer in a single transport write. The default,
    /// <see langword="false"/>, writes and flushes each on its own, which is today's
    /// behaviour; most real clients send them together.
    /// </summary>
    public bool CoalesceConnectionAndStream { get; set; }

    /// <summary>
    /// Gets or sets whether the stream-level update is skipped for the DATA frame that
    /// carries END_STREAM. The default, <see langword="true"/>, is today's behaviour.
    /// </summary>
    /// <remarks>
    /// Sending it anyway is explicitly legal, which is what makes this a fidelity axis
    /// rather than a conformance question. RFC 9113 section 6.9: "WINDOW_UPDATE can be
    /// sent by a peer that has sent a frame with the END_STREAM flag set. This means that
    /// a receiver could receive a WINDOW_UPDATE frame on a stream in a 'half-closed
    /// (remote)' or 'closed' state. A receiver MUST NOT treat this as an error."
    /// </remarks>
    public bool SuppressStreamUpdateOnEndStream { get; set; } = true;

    internal TlsHttp2FlowControlConfiguration Snapshot()
    {
        if (!Enum.IsDefined(Trigger))
        {
            throw new ArgumentOutOfRangeException(
                nameof(Trigger),
                "Trigger must be a defined value.");
        }
        if (!Enum.IsDefined(Increment))
        {
            throw new ArgumentOutOfRangeException(
                nameof(Increment),
                "Increment must be a defined value.");
        }
        if (!Enum.IsDefined(Order))
        {
            throw new ArgumentOutOfRangeException(
                nameof(Order),
                "Order must be a defined value.");
        }

        // RFC 9113 section 6.9: "The legal range for the increment to the flow-control
        // window is 1 to 2^31-1 (2,147,483,647) octets", and a receiver "MUST treat the
        // receipt of a WINDOW_UPDATE frame with a flow-control window increment of 0 as a
        // stream error ... of type PROTOCOL_ERROR".
        //
        // Only the lower bound is gated on Fixed, because 0 is also this property's default:
        // rejecting it unconditionally would reject every configuration that never emits a
        // fixed increment at all. The upper bound is deliberately NOT gated. The frozen
        // configuration narrows this field to int, so an ungated value above 2^31-1 would
        // wrap to a negative increment and sit in the snapshot until some later mode reads
        // it — 3_000_000_000 freezes as -1294967296.
        if (Increment == TlsHttp2WindowUpdateIncrement.Fixed && FixedIncrement == 0)
        {
            throw new ArgumentOutOfRangeException(
                FixedIncrementParameter,
                "FixedIncrement must be within [1, 2147483647] (RFC 9113 section 6.9).");
        }
        if (FixedIncrement > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                FixedIncrementParameter,
                "FixedIncrement must be within [1, 2147483647] (RFC 9113 section 6.9).");
        }

        // A flow-control window itself cannot exceed 2^31 - 1 (RFC 9113 section 6.9.1), so
        // a threshold above that can never be reached whatever the preface declares.
        if (StreamWindowUpdateThreshold > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(StreamWindowUpdateThreshold),
                "StreamWindowUpdateThreshold must not exceed 2147483647.");
        }
        if (ConnectionWindowUpdateThreshold > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ConnectionWindowUpdateThreshold),
                "ConnectionWindowUpdateThreshold must not exceed 2147483647.");
        }

        return new TlsHttp2FlowControlConfiguration(
            (int)StreamWindowUpdateThreshold,
            (int)ConnectionWindowUpdateThreshold,
            Trigger,
            Increment,
            (int)FixedIncrement,
            Order,
            CoalesceConnectionAndStream,
            SuppressStreamUpdateOnEndStream);
    }
}

/// <summary>The frozen flow-control credit policy a connection returns credit from.</summary>
internal sealed record TlsHttp2FlowControlConfiguration(
    int StreamWindowUpdateThreshold,
    int ConnectionWindowUpdateThreshold,
    TlsHttp2WindowUpdateTrigger Trigger,
    TlsHttp2WindowUpdateIncrement Increment,
    int FixedIncrement,
    TlsHttp2WindowUpdateOrder Order,
    bool CoalesceConnectionAndStream,
    bool SuppressStreamUpdateOnEndStream);
