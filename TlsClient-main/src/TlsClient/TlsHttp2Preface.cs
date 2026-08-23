namespace TlsClient;

/// <summary>One HTTP/2 SETTINGS entry, written verbatim in the order supplied.</summary>
/// <param name="Id">The setting identifier. Unknown and duplicate identifiers are permitted.</param>
/// <param name="Value">The setting value.</param>
public readonly record struct TlsHttp2SettingValue(ushort Id, uint Value);

/// <summary>A frame written as part of the HTTP/2 connection preface.</summary>
public abstract class TlsHttp2PrefaceFrame
{
    /// <summary>
    /// Gets or sets whether the transport is flushed after this frame. The default
    /// batches every preface frame into a single flush at the end.
    /// </summary>
    public bool FlushAfter { get; set; }
}

/// <summary>A SETTINGS frame. An empty list writes a zero-length payload.</summary>
public sealed class TlsHttp2SettingsFrame : TlsHttp2PrefaceFrame
{
    /// <summary>Gets or sets the settings, in exact wire order.</summary>
    public IReadOnlyList<TlsHttp2SettingValue> Settings { get; set; } = [];
}

/// <summary>
/// A connection-level WINDOW_UPDATE. It carries no stream identifier because no stream
/// exists at preface time; RFC 9113 section 5.1 makes any frame other than HEADERS or
/// PRIORITY on an idle stream a connection error.
/// </summary>
public sealed class TlsHttp2WindowUpdateFrame : TlsHttp2PrefaceFrame
{
    /// <summary>Gets or sets the window increment.</summary>
    public uint Increment { get; set; }
}

/// <summary>A PRIORITY frame emitted during the preface.</summary>
public sealed class TlsHttp2PrefacePriorityFrame : TlsHttp2PrefaceFrame
{
    /// <summary>Gets or sets the stream this priority applies to.</summary>
    public int StreamId { get; set; }

    /// <summary>Gets or sets the priority data.</summary>
    public TlsHttp2Priority Priority { get; set; } = new();
}

/// <summary>
/// An arbitrary frame, for reproducing GREASE and unknown frame types. Frame types the
/// connection owns are rejected at session construction.
/// </summary>
public sealed class TlsHttp2RawFrame : TlsHttp2PrefaceFrame
{
    /// <summary>Gets or sets the frame type octet.</summary>
    public byte Type { get; set; }

    /// <summary>Gets or sets the frame flags octet.</summary>
    public byte Flags { get; set; }

    /// <summary>Gets or sets the stream identifier.</summary>
    public int StreamId { get; set; }

    /// <summary>Gets or sets the frame payload.</summary>
    public byte[] Payload { get; set; } = [];
}

/// <summary>Where a SETTINGS acknowledgement is placed in the outbound frame sequence.</summary>
public enum TlsHttp2SettingsAckPlacement
{
    /// <summary>Its own write and flush, on receipt. The default.</summary>
    Standalone,

    /// <summary>Coalesced ahead of the next write batch this connection emits.</summary>
    BeforeNextBatch,

    /// <summary>Coalesced behind the next write batch this connection emits.</summary>
    AfterNextBatch,
}
