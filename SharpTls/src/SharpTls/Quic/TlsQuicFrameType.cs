namespace SharpTls.Quic;

// RFC 9000 s12.4 Table 3: every frame type value this version of QUIC
// defines - twenty of them - PLUS ONE EXTENSION ROW FROM ANOTHER DOCUMENT,
// RFC 9221's DATAGRAM. Twenty-one members, and the twenty-first is marked as
// such on its own declaration and everywhere it is counted, because "the enum
// is Table 3" was true until task C17 and several comments still lean on the
// count. `grep -cE "^\s+[A-Z][A-Za-z]+ = 0x" TlsQuicFrameType.cs` gives 21;
// Table 3's own row count, 20, is 21 minus the one DATAGRAM row.
//
// The frame type field itself is a variable-length integer
// (QuicVariableLengthInteger), not a byte - s12.4: "The Frame Type field
// uses a variable-length integer encoding (see Section 16), with one
// exception."
//
// That exception is a shortest-encoding rule, and it binds senders and
// receivers differently. s12.4, verbatim: "To ensure simple and efficient
// implementations of frame parsing, a frame type MUST use the shortest
// possible encoding. For frame types defined in this document, this means a
// single-byte encoding, even though it is possible to encode these values as
// a two-, four-, or eight-byte variable-length integer. [...] An endpoint MAY
// treat the receipt of a frame type that uses a longer encoding than
// necessary as a connection error of type PROTOCOL_VIOLATION."
//
// Sending, the MUST: every value below fits in 6 bits, and
// QuicVariableLengthInteger.Write always picks the width
// GetEncodedLength(value) gives, which is by construction the shortest - so
// TlsQuicFrames.WriteFrame satisfies the MUST structurally, with no check to
// forget. Receiving, the MAY: this code declines it and accepts an over-long
// frame type, resolving it by decoded value; TlsQuicFrames.TryReadFrame
// records why.
//
// Five names here are the low end of a *range*, not a single value - s12.4:
// "The Frame Type in ACK, STREAM, MAX_STREAMS, STREAMS_BLOCKED, and
// CONNECTION_CLOSE frames is used to carry other frame-specific flags. For
// all other frames, the Frame Type field simply identifies the frame." Each
// ranged member's doc comment below gives its full range and what the low
// bits mean. TlsQuicFrame keeps the exact wire value in RawType and derives
// the base value here from it in Type, so a reader for one of those types
// never has to mask by hand or compare for exact equality.
//
// DATAGRAM is a sixth range and s12.4's sentence does not cover it - that
// sentence enumerates five frame names and DATAGRAM is not one of them,
// because s12.4 predates RFC 9221. Its flag comes from RFC 9221 s4 instead,
// quoted on the member itself, and is read out of that section rather than
// inferred from the shape of the five above.
internal enum TlsQuicFrameType : ulong
{
    /// <summary>No fields. RFC 9000 s19.1.</summary>
    Padding = 0x00,

    /// <summary>No fields. RFC 9000 s19.2.</summary>
    Ping = 0x01,

    /// <summary>
    /// Range 0x02-0x03. Low bit selects whether ECN Counts are present
    /// (0x03) or absent (0x02). RFC 9000 s19.3.
    /// </summary>
    Ack = 0x02,

    /// <summary>RFC 9000 s19.4.</summary>
    ResetStream = 0x04,

    /// <summary>RFC 9000 s19.5.</summary>
    StopSending = 0x05,

    /// <summary>No flags in the type; CRYPTO always uses exactly 0x06. RFC 9000 s19.6.</summary>
    Crypto = 0x06,

    /// <summary>RFC 9000 s19.7.</summary>
    NewToken = 0x07,

    /// <summary>
    /// Range 0x08-0x0f. Low 3 bits are the OFF, LEN, and FIN flags. RFC 9000 s19.8.
    /// </summary>
    Stream = 0x08,

    /// <summary>RFC 9000 s19.9.</summary>
    MaxData = 0x10,

    /// <summary>RFC 9000 s19.10.</summary>
    MaxStreamData = 0x11,

    /// <summary>
    /// Range 0x12-0x13. Low bit selects bidirectional (0x12) vs
    /// unidirectional (0x13) streams. RFC 9000 s19.11.
    /// </summary>
    MaxStreams = 0x12,

    /// <summary>RFC 9000 s19.12.</summary>
    DataBlocked = 0x14,

    /// <summary>RFC 9000 s19.13.</summary>
    StreamDataBlocked = 0x15,

    /// <summary>
    /// Range 0x16-0x17. Low bit selects bidirectional (0x16) vs
    /// unidirectional (0x17) streams. RFC 9000 s19.14.
    /// </summary>
    StreamsBlocked = 0x16,

    /// <summary>RFC 9000 s19.15.</summary>
    NewConnectionId = 0x18,

    /// <summary>RFC 9000 s19.16.</summary>
    RetireConnectionId = 0x19,

    /// <summary>RFC 9000 s19.17.</summary>
    PathChallenge = 0x1a,

    /// <summary>RFC 9000 s19.18.</summary>
    PathResponse = 0x1b,

    /// <summary>
    /// Range 0x1c-0x1d. Low bit selects a QUIC-layer error (0x1c, allowed
    /// in any packet number space) vs an application error (0x1d,
    /// application data space only). RFC 9000 s19.19 and s12.5.
    /// </summary>
    ConnectionClose = 0x1c,

    /// <summary>No fields. RFC 9000 s19.20.</summary>
    HandshakeDone = 0x1e,

    /// <summary>
    /// Range 0x30-0x31, and the only member here that is NOT a row of RFC 9000
    /// s12.4 Table 3. RFC 9221 s4 defines it: "The Type field in the DATAGRAM
    /// frame takes the form 0b0011000X (or the values 0x30 and 0x31). The least
    /// significant bit of the Type field in the DATAGRAM frame is the LEN bit
    /// (0x01), which indicates whether there is a Length field present: if this
    /// bit is set to 0, the Length field is absent and the Datagram Data field
    /// extends to the end of the packet; if this bit is set to 1, the Length
    /// field is present." RFC 9221 s7.2 registers the pair as "Value: 0x30-0x31,
    /// Frame Name: DATAGRAM".
    ///
    /// THIS CLOSES AN ADVERTISEMENT, NOT A FEATURE. SharpTls accepts and
    /// discards DATAGRAM frames; it does not implement datagrams. It exists
    /// because <see cref="TlsQuicTransportParameterSpec"/>'s default preset
    /// emits <c>max_datagram_frame_size</c> = 65536 and
    /// <see cref="TlsQuicHttp3Spec"/>'s default emits
    /// <c>SETTINGS_H3_DATAGRAM</c> = 1, so this client tells every peer it is
    /// willing to receive something it previously had no parser for - an
    /// arriving DATAGRAM was an unknown frame type and killed the connection.
    /// <see cref="TlsQuicFrames.TryReadDatagram"/> parses the framing and drops
    /// the payload; <see cref="TlsQuicFrames.WriteFrame"/> refuses to emit one.
    /// </summary>
    Datagram = 0x30,
}
