using SharpTls.Protocol;

namespace SharpTls.Quic;

/// <summary>QUIC versions whose TLS key-separation labels are implemented.</summary>
public enum TlsQuicVersion : uint
{
    /// <summary>RFC 9000 QUIC version 1.</summary>
    Version1 = 0x00000001,
    /// <summary>RFC 9369 QUIC version 2.</summary>
    Version2 = 0x6B3343CF,
}

/// <summary>RFC 9001 TLS/QUIC encryption levels.</summary>
public enum TlsQuicEncryptionLevel
{
    /// <summary>Initial CRYPTO data; keys are derived by QUIC from the destination CID.</summary>
    Initial,
    /// <summary>Replayable client 0-RTT packet protection; CRYPTO frames never use this level.</summary>
    EarlyData,
    /// <summary>TLS handshake CRYPTO data and secrets.</summary>
    Handshake,
    /// <summary>Authenticated 1-RTT data and post-handshake CRYPTO data.</summary>
    Application,
}

/// <summary>Direction of a TLS-produced QUIC traffic secret.</summary>
public enum TlsQuicSecretDirection
{
    /// <summary>Packets written by the local endpoint.</summary>
    Write,
    /// <summary>Packets read from the peer.</summary>
    Read,
}

/// <summary>Endpoint role used for transport-parameter context validation.</summary>
public enum TlsQuicEndpointRole
{
    /// <summary>QUIC client.</summary>
    Client,
    /// <summary>QUIC server.</summary>
    Server,
}

/// <summary>Errors owned by the QUIC transport rather than the TLS alert registry.</summary>
/// <remarks>
/// Values are copied from the RFC 9000 s20.1 capture in
/// docs/superpowers/specs/reference-captures/rfc9000-section20-transport-error-codes.txt.
/// Only the codes this library can actually raise are listed; s20.1 defines
/// more.
/// </remarks>
public enum TlsQuicTransportError : ulong
{
    /// <summary>
    /// RFC 9000 s20.1 NO_ERROR (0x00): "An endpoint uses this with
    /// CONNECTION_CLOSE to signal that the connection is being closed
    /// abruptly in the absence of any error." Being 0x00 it is also the
    /// default of this enum, which is what a Try-shaped parser reports
    /// alongside a successful read.
    /// </summary>
    NoError = 0x00,
    /// <summary>
    /// RFC 9000 s20.1 FLOW_CONTROL_ERROR (0x03): "An endpoint received more
    /// data than it permitted in its advertised data limits; see Section 4."
    /// Raised by <see cref="TlsQuicStream"/> when a peer's STREAM frame runs
    /// past the bytes this endpoint will hold for one stream.
    /// </summary>
    FlowControlError = 0x03,
    /// <summary>
    /// RFC 9000 s20.1 STREAM_LIMIT_ERROR (0x04): "An endpoint received a frame
    /// for a stream identifier that exceeded its advertised stream limit for the
    /// corresponding stream type." Raised by <see cref="TlsQuicStreamSet"/> when
    /// a peer opens more streams than this endpoint will track.
    /// </summary>
    StreamLimitError = 0x04,
    /// <summary>
    /// RFC 9000 s20.1 STREAM_STATE_ERROR (0x05): "An endpoint received a frame
    /// for a stream that was not in a state that permitted that frame; see
    /// Section 3." Raised by <see cref="TlsQuicStreamSet"/> for s19.8's two
    /// named cases - a STREAM frame on a locally initiated stream that was never
    /// created, and one on a send-only stream.
    /// </summary>
    StreamStateError = 0x05,
    /// <summary>
    /// RFC 9000 s20.1 FINAL_SIZE_ERROR (0x06): "(1) An endpoint received a
    /// STREAM frame containing data that exceeded the previously established
    /// final size, (2) an endpoint received a STREAM frame or a RESET_STREAM
    /// frame containing a final size that was lower than the size of stream data
    /// that was already received, or (3) an endpoint received a STREAM frame or
    /// a RESET_STREAM frame containing a different final size to the one already
    /// established." Raised by <see cref="TlsQuicStream"/> for all three; this
    /// phase sends and handles no RESET_STREAM, so only the STREAM halves are
    /// reachable.
    /// </summary>
    FinalSizeError = 0x06,
    /// <summary>
    /// RFC 9000 s20.1 FRAME_ENCODING_ERROR (0x07): "An endpoint received a
    /// frame that was badly formatted -- for instance, a frame of an unknown
    /// type or an ACK frame that has more acknowledgment ranges than the
    /// remainder of the packet could carry."
    /// </summary>
    FrameEncodingError = 0x07,
    /// <summary>RFC 9000 PROTOCOL_VIOLATION.</summary>
    ProtocolViolation = 0x0A,
    /// <summary>RFC 9000 TRANSPORT_PARAMETER_ERROR.</summary>
    TransportParameterError = 0x08,
    /// <summary>
    /// RFC 9000 s20.1 APPLICATION_ERROR (0x0c): "The application or application
    /// protocol caused the connection to be closed." Raised by
    /// <see cref="TlsQuicConnection"/> when the peer's transport parameters are
    /// legal QUIC but deny the application protocol something it requires - the
    /// one case today being RFC 9114 s6.2's three unidirectional streams. It is
    /// deliberately not TRANSPORT_PARAMETER_ERROR, which would accuse the peer of
    /// an RFC 9000 violation it did not commit.
    /// </summary>
    ApplicationError = 0x0C,
    /// <summary>RFC 9000 CRYPTO_BUFFER_EXCEEDED.</summary>
    CryptoBufferExceeded = 0x0D,
    /// <summary>
    /// RFC 9000 s20.1 KEY_UPDATE_ERROR (0x0e): "An endpoint detected errors in
    /// performing key updates; see Section 6 of [QUIC-TLS]." Raised by
    /// <see cref="TlsQuicPacketReceiver"/> when an authenticated 1-RTT packet
    /// announces a key phase other than the installed one.
    /// </summary>
    KeyUpdateError = 0x0E,
}

/// <summary>A fail-closed QUIC transport error raised by the recordless TLS boundary.</summary>
public sealed class TlsQuicTransportException : IOException
{
    /// <summary>Creates a QUIC transport failure.</summary>
    public TlsQuicTransportException(TlsQuicTransportError error, string message)
        : base(message)
    {
        Error = error;
    }

    /// <summary>Gets the RFC 9000 transport error.</summary>
    public TlsQuicTransportError Error { get; }

    /// <summary>Maps a fatal TLS alert to the RFC 9001 CRYPTO_ERROR range.</summary>
    public static ulong GetCryptoErrorCode(TlsAlertDescription alert) =>
        0x100UL + (byte)alert;
}

/// <summary>Known QUIC transport-parameter identifiers. Unknown IDs remain supported.</summary>
public enum TlsQuicTransportParameterId : ulong
{
    /// <summary>Connection ID from the client's first Initial packet.</summary>
    OriginalDestinationConnectionId = 0x00,
    /// <summary>Maximum idle timeout in milliseconds.</summary>
    MaxIdleTimeout = 0x01,
    /// <summary>Server-only 16-byte stateless reset token.</summary>
    StatelessResetToken = 0x02,
    /// <summary>Largest UDP datagram payload accepted by the endpoint.</summary>
    MaxUdpPayloadSize = 0x03,
    /// <summary>Initial connection-level flow-control limit.</summary>
    InitialMaxData = 0x04,
    /// <summary>Initial local bidirectional-stream flow-control limit.</summary>
    InitialMaxStreamDataBidiLocal = 0x05,
    /// <summary>Initial peer bidirectional-stream flow-control limit.</summary>
    InitialMaxStreamDataBidiRemote = 0x06,
    /// <summary>Initial unidirectional-stream flow-control limit.</summary>
    InitialMaxStreamDataUni = 0x07,
    /// <summary>Initial peer-opened bidirectional-stream count.</summary>
    InitialMaxStreamsBidi = 0x08,
    /// <summary>Initial peer-opened unidirectional-stream count.</summary>
    InitialMaxStreamsUni = 0x09,
    /// <summary>Exponent used to decode ACK delay.</summary>
    AckDelayExponent = 0x0A,
    /// <summary>Maximum ACK delay in milliseconds.</summary>
    MaxAckDelay = 0x0B,
    /// <summary>Empty flag disabling active connection migration.</summary>
    DisableActiveMigration = 0x0C,
    /// <summary>Server-only preferred IPv4/IPv6 address and connection ID.</summary>
    PreferredAddress = 0x0D,
    /// <summary>Minimum number of active connection IDs the endpoint can store.</summary>
    ActiveConnectionIdLimit = 0x0E,
    /// <summary>Sender's Initial source connection ID.</summary>
    InitialSourceConnectionId = 0x0F,
    /// <summary>Server source connection ID carried in Retry.</summary>
    RetrySourceConnectionId = 0x10,
    /// <summary>RFC 9368 chosen and available compatible versions.</summary>
    VersionInformation = 0x11,
    /// <summary>RFC 9221 maximum DATAGRAM frame size.</summary>
    MaxDatagramFrameSize = 0x20,
    /// <summary>RFC 9287 empty grease_quic_bit capability.</summary>
    GreaseQuicBit = 0x2AB2,
}
