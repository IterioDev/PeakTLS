using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

namespace TlsClient;

/// <summary>Controls which HTTP protocol is advertised and accepted over SharpTls.</summary>
/// <remarks>
/// Every member is an explicit, caller-driven choice. TlsClient does not implement
/// Happy Eyeballs and never races or falls back between the TCP protocols and QUIC:
/// the selected policy either connects on its own transport or the request fails.
/// That is why there is no <c>PreferHttp3</c> member — "prefer" could only mean
/// "attempt QUIC, then silently retry over TCP", which is exactly the silent wire
/// change this project forbids. A caller that wants that behavior must implement it
/// itself by catching the failure and re-issuing under a different policy.
/// </remarks>
public enum TlsHttpVersionPolicy
{
    /// <summary>Advertise HTTP/2 and HTTP/1.1 over TCP, preferring HTTP/2.</summary>
    PreferHttp2,

    /// <summary>Advertise and accept only HTTP/1.1 over TCP.</summary>
    Http11Only,

    /// <summary>Advertise and accept only HTTP/2 over TCP.</summary>
    Http2Only,

    /// <summary>
    /// Advertise and accept only HTTP/3 over QUIC. The connection dials UDP and never
    /// touches the TCP transport, so a server without HTTP/3 fails the request instead
    /// of being downgraded to HTTP/2 or HTTP/1.1.
    /// </summary>
    /// <remarks>
    /// Experimental. <c>docs/HTTP3-EVALUATION.md</c> defines a seven-condition entry
    /// gate for HTTP/3 and several conditions are still unmet: QUIC loss recovery is
    /// incomplete (condition 2), pooling, redirects, cookies, retries and 0-RTT replay
    /// policy have no HTTP/3-specific semantics (condition 5), cross-platform CI
    /// coverage is unproven (condition 6), and no independent security review exists
    /// (condition 7). Selecting this member is an explicit opt-in to an unreviewed
    /// transport; suppress <c>TLSCLIENT3</c> to acknowledge that.
    /// </remarks>
    [Experimental("TLSCLIENT3")]
    Http3Only,
}

/// <summary>RFC 7540 stream dependency and weight.</summary>
public sealed class TlsHttp2Priority
{
    /// <summary>Gets or sets the dependency stream identifier, or zero for the root.</summary>
    public int StreamDependency { get; set; }

    /// <summary>Gets or sets whether this dependency is exclusive.</summary>
    public bool Exclusive { get; set; }

    /// <summary>Gets or sets the relative weight from 1 through 256.</summary>
    public int Weight { get; set; } = 16;

    internal TlsHttp2PriorityConfiguration Snapshot()
    {
        if (StreamDependency is < 0 || Weight is < 1 or > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(StreamDependency),
                "StreamDependency must be non-negative and Weight must be between 1 and 256.");
        }
        return new TlsHttp2PriorityConfiguration(StreamDependency, Exclusive, Weight);
    }
}

internal sealed record TlsHttp2Configuration(
    TlsHttp2PrefaceFrameConfiguration[] Preface,
    TlsHpackConfiguration Hpack,
    int InitialStreamId,
    int StreamIdStep,
    TlsHttp2SettingsAckPlacement SettingsAckPlacement,
    TlsHttp2PseudoHeaderConfiguration PseudoHeaders,
    TlsHttp2DataConfiguration Data,
    int? HeaderBlockFragmentSize,
    bool EmitTrailerHeader,
    TlsHttp2PriorityConfiguration? HeaderPriority,
    string? PriorityUpdate,
    bool FlushAfterHeaderBlock,
    bool FlushAfterEveryDataFrame,
    uint LocalHeaderTableSize,
    int LocalInitialWindowSize,
    int LocalMaxFrameSize,
    uint? LocalMaxHeaderListSize,
    bool LocalEnablePush,
    int ConnectionReceiveWindow,
    TlsHttp2FlowControlConfiguration FlowControl,
    TlsHttp2ShutdownConfiguration Shutdown);

/// <summary>
/// One preface frame reduced to the octets it puts on the wire, plus whether the
/// transport is flushed after it.
/// </summary>
internal sealed record TlsHttp2PrefaceFrameConfiguration(
    byte Type,
    byte Flags,
    int StreamId,
    byte[] Payload,
    bool FlushAfter);

internal sealed record TlsHttp2PriorityConfiguration(
    int StreamDependency,
    bool Exclusive,
    int Weight)
{
    /// <summary>Builds the five-octet RFC 7540 priority payload.</summary>
    internal byte[] BuildPayload()
    {
        var payload = new byte[5];
        var dependency = StreamDependency;
        if (Exclusive)
        {
            dependency |= int.MinValue;
        }
        BinaryPrimitives.WriteInt32BigEndian(payload, dependency);
        payload[4] = (byte)(Weight - 1);
        return payload;
    }
}
