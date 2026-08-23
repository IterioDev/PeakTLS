namespace SharpTls.Quic;

// RFC 9000 s16: the QUIC variable-length integer encoding that every frame
// field, packet header length/offset field, and transport parameter ID/
// length/value in src/SharpTls/Quic/ is built on ("The QUIC variable-length
// integer encoding reserves the two most significant bits of the first byte
// to encode the base-2 logarithm of the integer encoding length in bytes.
// The integer value is encoded on the remaining bits, in network byte
// order.") - see reference-captures/rfc9000-section16-variable-length-
// integers.txt. s16 also states that "Values do not need to be encoded on
// the minimum number of bytes necessary, with the sole exception of the
// Frame Type field" - this codec does not special-case that field (see
// TlsQuicFrames.TryReadFrame's own comment on accepting over-long frame
// types), so neither Read, TryRead nor Write here requires or enforces a
// minimal encoding for any value, frame type included.
internal static class QuicVariableLengthInteger
{
    // RFC 9000 s16, Table 4: the 62-bit range tops out at 4611686018427387903,
    // i.e. 2^62 - 1 - the largest value the 8-byte ("11" prefix) form can hold.
    internal const ulong MaximumValue = (1UL << 62) - 1;

    // RFC 9000 s16, Table 4's four (Length, Range) rows: 1 byte up to 63,
    // 2 bytes up to 16383, 4 bytes up to 1073741823, 8 bytes up to MaximumValue.
    internal static int GetEncodedLength(ulong value) => value switch
    {
        <= 63 => 1,
        <= 16_383 => 2,
        <= 1_073_741_823 => 4,
        <= MaximumValue => 8,
        _ => throw new ArgumentOutOfRangeException(nameof(value)),
    };

    // RFC 9000 s16, the sentence the minimal form above does NOT implement:
    // "Values do not need to be encoded on the minimum number of bytes
    // necessary, with the sole exception of the Frame Type field; see Section
    // 12.4." So a sender may deliberately widen a field, which makes the width
    // observable - see TlsQuicVarintWidth, and A4's plan Finding 5. This
    // resolves a requested width against a value: Minimal defers to the
    // overload above, and any other width is honoured as long as the value
    // fits it. A width too narrow for the value is a caller error and not a
    // silent truncation.
    //
    // The frame type exemption is not enforced here for the same reason the
    // type header of this file gives: this codec has no idea which field it is
    // encoding. Nothing in src/ passes a non-Minimal width for a frame type -
    // TlsQuicFrames.WriteFrame calls the minimal Write overload above and has
    // no width parameter at all.
    //
    // Witnessed by TlsQuicPrimitiveTests.WidenedEncodingUsesTheRequestedWidth
    // and TlsQuicPrimitiveTests.AWidthTooNarrowForTheValueIsRejected.
    internal static int GetEncodedLength(ulong value, TlsQuicVarintWidth width)
    {
        var minimal = GetEncodedLength(value);
        if (width == TlsQuicVarintWidth.Minimal)
        {
            return minimal;
        }

        var requested = (int)width;
        if (requested < minimal)
        {
            throw new ArgumentOutOfRangeException(
                nameof(width),
                width,
                $"A {requested}-byte variable-length integer cannot hold {value}, which needs {minimal}.");
        }
        return requested;
    }

    internal static void Write(List<byte> destination, ulong value) =>
        Write(destination, value, TlsQuicVarintWidth.Minimal);

    // The width-carrying form, added by A4 task 5 so that
    // TlsQuicStreamFrames.WriteCryptoFrameFields can honour
    // TlsQuicConnectionSpec.CryptoOffsetVarintWidth and CryptoLengthVarintWidth - two
    // knobs that were validated, stored and then silently ignored because no writer
    // took a width. Minimal is the default, so every existing caller keeps writing the
    // shortest form; GetEncodedLength(value, width) above is what resolves the two.
    internal static void Write(List<byte> destination, ulong value, TlsQuicVarintWidth width)
    {
        ArgumentNullException.ThrowIfNull(destination);
        var length = GetEncodedLength(value, width);
        Span<byte> encoded = stackalloc byte[8];
        EncodeInto(encoded, value, length);
        for (var index = 0; index < length; index++)
        {
            destination.Add(encoded[index]);
        }
    }

    // The one transcription of RFC 9000 s16's encode step. Both Write above and
    // Encode below run through it, so widening a field cannot pick up a second,
    // separately maintained copy of the bit arithmetic.
    private static void EncodeInto(Span<byte> destination, ulong value, int lengthInBytes)
    {
        // RFC 9000 s16, Table 4's "2MSB" column: the two most significant bits
        // of the first byte are the base-2 logarithm of the length - 00/01/10/11
        // for the 1/2/4/8-byte forms, i.e. 0x00/0x40/0x80/0xC0 once shifted into
        // the top of the byte. Resolved before the loop so an unrepresentable
        // length fails the same way for every value, including 0, which would
        // otherwise index an empty destination below.
        var prefix = lengthInBytes switch
        {
            1 => (byte)0x00,
            2 => (byte)0x40,
            4 => (byte)0x80,
            8 => (byte)0xC0,
            _ => throw new InvalidOperationException(),
        };
        for (var index = lengthInBytes - 1; index >= 0; index--)
        {
            destination[index] = (byte)value;
            value >>= 8;
        }
        destination[0] |= prefix;
    }

    // Throwing form, kept for the callers that are themselves specified to throw
    // on malformed input rather than to report it - TlsQuicTransportParameters.
    // Parse's own doc comment ("Strictly parses...") and ReadInteger's use inside
    // ValidatePeer, both decoding the transport parameters extension exactly
    // once per handshake attempt, not in the per-frame receive loop task 6 adds.
    // Implemented on top of TryRead rather than repeating the bit arithmetic, so
    // there is exactly one transcription of RFC 9000 s16's decode to review - the
    // A2 plan's own warning about a second, undiffed copy of the same formula.
    internal static ulong Read(ReadOnlySpan<byte> source, ref int offset)
    {
        if (!TryRead(source, ref offset, out var value))
        {
            throw ParameterError("Truncated QUIC variable-length integer.");
        }
        return value;
    }

    // Try-shaped, never-throwing twin of Read, for every parse-path caller in
    // src/SharpTls/Quic/ that exists only to honour its own Try-shaped contract -
    // a packet or frame off the network is attacker-controlled, and per handoff
    // s8 item 5, every malformed field previously cost a
    // TlsQuicTransportException allocation plus its message on that path. Same
    // decode as Read, reported through a bool instead of thrown: `offset` only
    // advances on success, matching every TryReadXxx convention elsewhere in
    // this namespace (TlsQuicPacketHeader.TryReadLongHeader,
    // TlsQuicFrames.TryReadFrame, and the rest).
    internal static bool TryRead(ReadOnlySpan<byte> source, ref int offset, out ulong value)
    {
        value = 0;
        if ((uint)offset >= (uint)source.Length)
        {
            return false;
        }
        // RFC 9000 s16: length in bytes is 2 raised to the first byte's top two
        // bits (0, 1, 2 or 3), giving 1, 2, 4 or 8. No check here rejects a
        // non-minimal encoding - s16 permits one for every field this codec
        // reads except the Frame Type field, and this codec does not carve out
        // that exception (see the class comment above).
        var length = 1 << (source[offset] >> 6);
        if (source.Length - offset < length)
        {
            return false;
        }
        // RFC 9000 s16: "The integer value is encoded on the remaining bits, in
        // network byte order" - the first byte's low 6 bits (masked by 0x3F)
        // are the most significant bits of the value, followed by (length - 1)
        // more big-endian bytes.
        ulong decoded = (ulong)(source[offset] & 0x3F);
        for (var index = 1; index < length; index++)
        {
            decoded = (decoded << 8) | source[offset + index];
        }
        offset += length;
        value = decoded;
        return true;
    }

    internal static byte[] Encode(ulong value) => Encode(value, GetEncodedLength(value));

    // `lengthInBytes` is a resolved width, normally from GetEncodedLength's
    // two-argument overload; 1, 2, 4 and 8 are the only lengths RFC 9000 s16
    // Table 4 defines and anything else is rejected by EncodeInto.
    internal static byte[] Encode(ulong value, int lengthInBytes)
    {
        var encoded = new byte[lengthInBytes];
        EncodeInto(encoded, value, lengthInBytes);
        return encoded;
    }

    internal static ulong ReadExact(ReadOnlySpan<byte> source, string parameterName)
    {
        var offset = 0;
        var value = Read(source, ref offset);
        if (offset != source.Length)
        {
            throw ParameterError(
                $"QUIC transport parameter {parameterName} is not one exact variable-length integer.");
        }
        return value;
    }

    internal static TlsQuicTransportException ParameterError(string message) => new(
        TlsQuicTransportError.TransportParameterError,
        message);
}
