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

/// <summary>When the QPACK encoder Huffman-codes a string literal.</summary>
/// <remarks>
/// <para>RFC 9204 section 4.1.2's H bit is per string, and the choice is observable: two
/// encoders given the same header list produce different bytes. That makes this fingerprint
/// surface rather than a compression setting.</para>
/// <para>WHY THE THIRD MEMBER HAD TO EXIST. This was a <see langword="bool"/>, and the two
/// values it could take are the two policies no real encoder uses. Chrome and nghttp2 both
/// emit whichever form is SHORTER for each string - the RFC leaves the choice open and every
/// deployed HPACK/QPACK encoder resolves it the same way - so a library whose purpose is
/// imitating them could express every policy except theirs. The in-source argument for the
/// bool was that "a size-dependent choice would make the wire bytes depend on the header value
/// ... a deterministic flag is reproducible; a heuristic is a leak", and it has it backwards
/// for this library: the heuristic is the behaviour being replicated, and reproducibility is a
/// property of a test harness rather than of the wire.</para>
/// </remarks>
public enum TlsQuicQpackHuffmanPolicy
{
    /// <summary>Never Huffman-code; every string literal goes out as its own octets.</summary>
    Never,

    /// <summary>Always Huffman-code, even when the coded form is longer.</summary>
    Always,

    /// <summary>Huffman-code a string only when the coded form is strictly shorter.</summary>
    /// <remarks>TIES GO TO THE LITERAL, which is what <c>nghttp2</c> and Chromium do: the
    /// comparison is <c>huffmanLength &lt; data.Length</c>, so a string that codes to exactly
    /// its own length is emitted uncoded.</remarks>
    ShorterOfTheTwo,
}

/// <summary>What this endpoint writes into RFC 9000 section 17.4's latency spin bit.</summary>
/// <remarks>
/// <para>EVERY MEMBER IS THE SPIN BIT DISABLED, and all three are conformant. s17.4: "Each
/// endpoint unilaterally decides if the spin bit is enabled or disabled for a connection", and
/// for a disabled one "endpoints MAY set the spin bit to any value and MUST accept any value
/// received." So this is a fingerprint choice and not a correctness one.</para>
/// <para>THERE IS NO `Enabled` MEMBER, DELIBERATELY. Participating in the spin means echoing
/// the spin of the highest-numbered 1-RTT packet received, which needs receive state this
/// connection does not keep - and no capture in this repo measures a peer that spins, so it
/// would be a feature written against nothing. Adding it is a receiver change plus a fourth
/// member, not a fourth branch on the sender.</para>
/// </remarks>
public enum TlsQuicSpinBitPolicy
{
    /// <summary>Always zero. The shipped default, and what Chromium sends.</summary>
    Zero,

    /// <summary>One value drawn per connection and held for its life - s17.4's "chosen
    /// independently for each connection" reading of a disabled spin bit.</summary>
    RandomPerConnection,

    /// <summary>A fresh value on every 1-RTT packet.</summary>
    RandomPerPacket,
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

    /// <summary>
    /// RFC 9000 s20.1 AEAD_LIMIT_REACHED (0x0f): "The endpoint has reached the
    /// confidentiality or integrity limit for the AEAD algorithm used by the given
    /// connection." Raised by <see cref="TlsQuicConnection"/> when RFC 9001 s6.6's
    /// integrity limit is passed, or when its confidentiality limit is reached and no
    /// key update is possible.
    /// </summary>
    AeadLimitReached = 0x0F,

    // ---------------------------------------------------------------------------------
    // THE REST OF RFC 9000 s20.1, PLUS RFC 9368's. The six below completed the registry;
    // before them a CONNECTION_CLOSE carrying any of these codes - sent or received - had
    // no name, and TlsQuicConnection had no code to send for two conditions it can now
    // actually detect (0x09 under s5.1.1, 0x01 for an internal fault).
    //
    // TWO OF THE SIX ARE SERVER-SIDE AND THIS CLIENT WILL NEVER SEND THEM. They are defined
    // anyway because this enum also NAMES a received code: s10.2.1 lets a server close with
    // any of them, and an undefined member renders in a diagnostic as a bare number.
    // ---------------------------------------------------------------------------------

    /// <summary>
    /// RFC 9000 s20.1 INTERNAL_ERROR (0x01): "The endpoint encountered an internal error and
    /// cannot continue with the connection."
    /// </summary>
    InternalError = 0x01,

    /// <summary>
    /// RFC 9000 s20.1 CONNECTION_REFUSED (0x02): "The server refused to accept a new
    /// connection." Server-side; named here for a received CONNECTION_CLOSE.
    /// </summary>
    ConnectionRefused = 0x02,

    /// <summary>
    /// RFC 9000 s20.1 CONNECTION_ID_LIMIT_ERROR (0x09): "The number of connection IDs provided
    /// by the peer exceeds the advertised active_connection_id_limit." Raised by
    /// <see cref="TlsQuicConnection"/> when a NEW_CONNECTION_ID frame would push the count of
    /// unretired peer connection IDs past the limit this endpoint advertised under 0x0E, which
    /// s5.1.1 requires: "An endpoint MUST NOT provide more connection IDs than the peer's
    /// limit."
    /// </summary>
    ConnectionIdLimitError = 0x09,

    /// <summary>
    /// RFC 9000 s20.1 INVALID_TOKEN (0x0b): "A server received a client Initial that contained
    /// an invalid Token field." Server-side; named here for a received CONNECTION_CLOSE.
    /// </summary>
    InvalidToken = 0x0B,

    /// <summary>
    /// RFC 9000 s20.1 NO_VIABLE_PATH (0x10): "An endpoint has determined that the network path
    /// is incapable of supporting QUIC. An endpoint is unlikely to receive a CONNECTION_CLOSE
    /// frame carrying this code except when the path does not support a large enough MTU."
    /// </summary>
    NoViablePath = 0x10,

    /// <summary>
    /// RFC 9368 s6 VERSION_NEGOTIATION_ERROR (0x11): raised when the version_information
    /// transport parameter is missing, malformed, or names a Chosen Version that disagrees with
    /// the version in use.
    /// </summary>
    VersionNegotiationError = 0x11,
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
