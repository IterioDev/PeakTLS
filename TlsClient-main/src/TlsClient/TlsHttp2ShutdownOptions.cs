namespace TlsClient;

/// <summary>
/// The error codes RFC 9113 section 7 defines for RST_STREAM and GOAWAY.
/// </summary>
/// <remarks>
/// The table is not closed. Section 7: "Unknown or unsupported error codes MUST NOT trigger
/// any special behavior. These MAY be treated by an implementation as being equivalent to
/// INTERNAL_ERROR." The field itself is 32 bits wide, which is why the enum is
/// <see langword="uint"/>-backed.
/// </remarks>
public enum Http2ErrorCode : uint
{
    /// <summary>
    /// <c>NO_ERROR</c> (0x00). "The associated condition is not a result of an error. For
    /// example, a GOAWAY might include this code to indicate graceful shutdown of a
    /// connection."
    /// </summary>
    NoError = 0x0,

    /// <summary>
    /// <c>PROTOCOL_ERROR</c> (0x01). "The endpoint detected an unspecific protocol error.
    /// This error is for use when a more specific error code is not available."
    /// </summary>
    ProtocolError = 0x1,

    /// <summary>
    /// <c>INTERNAL_ERROR</c> (0x02). "The endpoint encountered an unexpected internal
    /// error."
    /// </summary>
    InternalError = 0x2,

    /// <summary>
    /// <c>FLOW_CONTROL_ERROR</c> (0x03). "The endpoint detected that its peer violated the
    /// flow-control protocol."
    /// </summary>
    FlowControlError = 0x3,

    /// <summary>
    /// <c>SETTINGS_TIMEOUT</c> (0x04). "The endpoint sent a SETTINGS frame but did not
    /// receive a response in a timely manner."
    /// </summary>
    SettingsTimeout = 0x4,

    /// <summary>
    /// <c>STREAM_CLOSED</c> (0x05). "The endpoint received a frame after a stream was
    /// half-closed."
    /// </summary>
    StreamClosed = 0x5,

    /// <summary>
    /// <c>FRAME_SIZE_ERROR</c> (0x06). "The endpoint received a frame with an invalid size."
    /// </summary>
    FrameSizeError = 0x6,

    /// <summary>
    /// <c>REFUSED_STREAM</c> (0x07). "The endpoint refused the stream prior to performing
    /// any application processing." Section 8.7 makes it the marker that a request was
    /// definitely not processed and is therefore safe to retry.
    /// </summary>
    RefusedStream = 0x7,

    /// <summary>
    /// <c>CANCEL</c> (0x08). "The endpoint uses this error code to indicate that the stream
    /// is no longer needed."
    /// </summary>
    Cancel = 0x8,

    /// <summary>
    /// <c>COMPRESSION_ERROR</c> (0x09). "The endpoint is unable to maintain the field
    /// section compression context for the connection."
    /// </summary>
    CompressionError = 0x9,

    /// <summary>
    /// <c>CONNECT_ERROR</c> (0x0a). "The connection established in response to a CONNECT
    /// request was reset or abnormally closed."
    /// </summary>
    ConnectError = 0xa,

    /// <summary>
    /// <c>ENHANCE_YOUR_CALM</c> (0x0b). "The endpoint detected that its peer is exhibiting
    /// a behavior that might be generating excessive load."
    /// </summary>
    EnhanceYourCalm = 0xb,

    /// <summary>
    /// <c>INADEQUATE_SECURITY</c> (0x0c). "The underlying transport has properties that do
    /// not meet minimum security requirements."
    /// </summary>
    InadequateSecurity = 0xc,

    /// <summary>
    /// <c>HTTP_1_1_REQUIRED</c> (0x0d). "The endpoint requires that HTTP/1.1 be used
    /// instead of HTTP/2."
    /// </summary>
    Http11Required = 0xd,
}

/// <summary>
/// Configures whether the client announces that it is done with a connection, and with what.
/// </summary>
/// <remarks>
/// Announcing shutdown is a genuine emulation axis rather than a conformance question. RFC
/// 9113 section 6.8 only says "Endpoints SHOULD always send a GOAWAY frame before closing a
/// connection", and section 5.4.1's requirement to close the transport afterwards applies to
/// a GOAWAY sent for an error condition. Closing the socket silently is what this client does
/// today, and real clients differ.
/// </remarks>
public sealed class TlsHttp2ShutdownOptions
{
    // RFC 9113 section 4.2 floors SETTINGS_MAX_FRAME_SIZE at 16384 octets, and section 6.8
    // spends 8 of a GOAWAY payload on Last-Stream-ID and Error Code. Debug data within this
    // bound is emittable whatever the peer advertises.
    private const int MaximumDebugDataBytes = (16 * 1024) - 8;

    // CA2208 only accepts a compile-time paramName that names a parameter of the throwing
    // method, and this rejection belongs to a property of this object.
    private static readonly string GoAwayDebugDataParameter = nameof(GoAwayDebugData);

    /// <summary>
    /// Gets or sets whether a GOAWAY frame is written before the connection is closed. The
    /// default, <see langword="false"/>, closes without announcing, which is today's
    /// behaviour.
    /// </summary>
    public bool SendGoAwayOnDispose { get; set; }

    /// <summary>
    /// Gets or sets the error code carried by that GOAWAY. The default,
    /// <see cref="Http2ErrorCode.NoError"/>, is what RFC 9113 section 7 names for a graceful
    /// shutdown.
    /// </summary>
    public Http2ErrorCode GoAwayErrorCode { get; set; } = Http2ErrorCode.NoError;

    /// <summary>
    /// Gets or sets the opaque debug data appended to that GOAWAY, or <see langword="null"/>
    /// for none.
    /// </summary>
    /// <remarks>
    /// RFC 9113 section 6.8: "Endpoints MAY append opaque data to the frame payload of any
    /// GOAWAY frame. Additional debug data is intended for diagnostic purposes only and
    /// carries no semantic value." Content is unconstrained; only the frame-size bound of
    /// section 4.2 applies.
    /// </remarks>
    public byte[]? GoAwayDebugData { get; set; }

    /// <summary>
    /// Gets or sets the RST_STREAM error code used when the caller cancels a request, or
    /// when a final response arrives and abandons an upload still in flight. The default is
    /// <see cref="Http2ErrorCode.Cancel"/>, which is today's behaviour.
    /// </summary>
    /// <remarks>
    /// A convention, not a requirement. RFC 9113 section 7 gives CANCEL the matching
    /// meaning — "the endpoint uses this error code to indicate that the stream is no longer
    /// needed" — but section 5.4 leaves the choice open: "an endpoint MAY use any applicable
    /// error code when it detects an error condition; a generic error code (such as
    /// PROTOCOL_ERROR or INTERNAL_ERROR) can always be used in place of more specific error
    /// codes." Which code a stack picks is therefore a discriminator, not conformance.
    /// </remarks>
    public Http2ErrorCode CancellationResetCode { get; set; } = Http2ErrorCode.Cancel;

    /// <summary>
    /// Gets or sets the RST_STREAM error code used when the request fails locally after the
    /// header block was written — a body stream that threw, for instance. The default is
    /// <see cref="Http2ErrorCode.InternalError"/>, which is today's behaviour.
    /// </summary>
    /// <remarks>
    /// A convention, not a requirement. RFC 9113 section 7 describes INTERNAL_ERROR as "the
    /// endpoint encountered an unexpected internal error", and section 5.4 explicitly blesses
    /// it as an always-available generic, but no rule binds it to this cause.
    /// </remarks>
    public Http2ErrorCode LocalFailureResetCode { get; set; } = Http2ErrorCode.InternalError;

    /// <summary>
    /// Gets or sets the RST_STREAM error code used to decline a server-pushed stream. The
    /// default is <see cref="Http2ErrorCode.Cancel"/>, which is today's behaviour.
    /// </summary>
    /// <remarks>
    /// A convention, not a requirement. RFC 9113 sections 6.6 and 8.4 have a client reject a
    /// promised stream with RST_STREAM but name no error code for it; both CANCEL and
    /// REFUSED_STREAM are used in the wild.
    /// </remarks>
    public Http2ErrorCode PushRejectionResetCode { get; set; } = Http2ErrorCode.Cancel;

    internal TlsHttp2ShutdownConfiguration Snapshot()
    {
        if (!Enum.IsDefined(GoAwayErrorCode))
        {
            throw new ArgumentOutOfRangeException(
                nameof(GoAwayErrorCode),
                "GoAwayErrorCode must be an error code RFC 9113 section 7 defines.");
        }
        if (!Enum.IsDefined(CancellationResetCode))
        {
            throw new ArgumentOutOfRangeException(
                nameof(CancellationResetCode),
                "CancellationResetCode must be an error code RFC 9113 section 7 defines.");
        }
        if (!Enum.IsDefined(LocalFailureResetCode))
        {
            throw new ArgumentOutOfRangeException(
                nameof(LocalFailureResetCode),
                "LocalFailureResetCode must be an error code RFC 9113 section 7 defines.");
        }
        if (!Enum.IsDefined(PushRejectionResetCode))
        {
            throw new ArgumentOutOfRangeException(
                nameof(PushRejectionResetCode),
                "PushRejectionResetCode must be an error code RFC 9113 section 7 defines.");
        }
        if (GoAwayDebugData is { Length: > MaximumDebugDataBytes })
        {
            throw new ArgumentOutOfRangeException(
                GoAwayDebugDataParameter,
                "GoAwayDebugData must not exceed 16376 octets, so the GOAWAY frame fits the " +
                "smallest maximum frame size RFC 9113 section 4.2 permits a peer to declare.");
        }

        return new TlsHttp2ShutdownConfiguration(
            SendGoAwayOnDispose,
            GoAwayErrorCode,
            GoAwayDebugData?.ToArray(),
            CancellationResetCode,
            LocalFailureResetCode,
            PushRejectionResetCode);
    }
}

/// <summary>The frozen shutdown policy a connection announces itself with.</summary>
internal sealed record TlsHttp2ShutdownConfiguration(
    bool SendGoAwayOnDispose,
    Http2ErrorCode GoAwayErrorCode,
    byte[]? GoAwayDebugData,
    Http2ErrorCode CancellationResetCode,
    Http2ErrorCode LocalFailureResetCode,
    Http2ErrorCode PushRejectionResetCode);
