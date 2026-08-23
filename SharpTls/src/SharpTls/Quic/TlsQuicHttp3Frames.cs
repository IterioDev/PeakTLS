using System.Collections.Immutable;
using System.Globalization;

namespace SharpTls.Quic;

/// <summary>An RFC 9114 s8.1 HTTP/3 error code, as the application error code a CONNECTION_CLOSE
/// would carry.</summary>
/// <remarks>
/// <para>Only the codes this subsystem actually raises are members. s8.1 defines seventeen and
/// rfc9114-section8-error-handling.txt carries all of them; an enum row for a code nothing
/// raises would be a claim that something does.</para>
/// <para>The numeric values are s11.2.3 Table 4's, which
/// rfc9114-section11.2-new-registries.txt carries alongside s8.1's prose - two independent
/// statements of the same numbers in the same repo.</para>
/// <para>QPACK_DECOMPRESSION_FAILED IS DELIBERATELY NOT A MEMBER, and task C10's source note
/// asking for it was half right. It is an RFC 9204 s6 code, not an RFC 9114 s8.1 one -
/// rfc9114-section8-error-handling.txt's seventeen codes run 0x0100..0x0110 and 0x0200 is not
/// among them - and it already exists, once, as
/// <see cref="TlsQuicQpackDecoder.QpackDecompressionFailed"/>. A second spelling here would be
/// a transcription of a number this repo already holds, in an enum whose own summary line says
/// its members are s8.1's. That is why the response reader's error out-parameter stays a
/// <c>ulong</c>: one channel has to carry both registries, and only the varint they share
/// can.</para>
/// <para>THIS ENUM HAS NO MUTATION LEDGER OF ITS OWN. The four rows that mutate these values -
/// C10b-1 to C10b-4 - are in the single C10b ledger at the foot of TlsQuicHttp3Request.cs,
/// where the rest of that task's rows live, rather than split across two files by which line
/// each edit happens to touch.</para>
/// </remarks>
internal enum TlsQuicHttp3ErrorCode : ulong
{
    /// <summary>NOT AN RFC CODE. The enum's "nothing to report", so a
    /// <c>Try</c>-shaped method's error out-parameter has a value on the success path. 0x00
    /// appears nowhere in s11.2.3 Table 4, whose lowest entry is H3_NO_ERROR at 0x0100, so
    /// this member cannot collide with one - the same argument
    /// <see cref="TlsQuicQpackError.None"/> rests on.</summary>
    None = 0,

    /// <summary>H3_NO_ERROR (0x0100): "No error. This is used when the connection or stream
    /// needs to be closed, but there is no error to signal."</summary>
    /// <remarks>NOT THE SAME THING AS <see cref="None"/>, and the two must not be conflated.
    /// <see cref="None"/> is 0x00, is not an RFC code at all, and means "this out-parameter has
    /// nothing to report". This member is s8.1's own code and goes ON THE WIRE, in a
    /// CONNECTION_CLOSE or a STOP_SENDING, to say that a close was deliberate. s8 adds a wrinkle
    /// worth knowing before sending it: "Implementations SHOULD select an error code from
    /// [the 0x1f * N + 0x21 reserved] space with some probability when they would have sent
    /// H3_NO_ERROR" - see <see cref="TlsQuicHttp3Frames.ReservedIdentifier(ulong)"/>.</remarks>
    H3NoError = 0x0100,

    /// <summary>H3_STREAM_CREATION_ERROR (0x0103): "The endpoint detected that its peer
    /// created a stream that it will not accept."</summary>
    H3StreamCreationError = 0x0103,

    /// <summary>H3_CLOSED_CRITICAL_STREAM (0x0104): "A stream required by the HTTP/3
    /// connection was closed or reset."</summary>
    H3ClosedCriticalStream = 0x0104,

    /// <summary>H3_FRAME_UNEXPECTED (0x0105): "A frame was received that was not permitted in
    /// the current state or on the current stream."</summary>
    H3FrameUnexpected = 0x0105,

    /// <summary>H3_FRAME_ERROR (0x0106): "A frame that fails to satisfy layout requirements or
    /// with an invalid size was received."</summary>
    H3FrameError = 0x0106,

    /// <summary>H3_ID_ERROR (0x0108): "A stream ID or push ID was used incorrectly, such as
    /// exceeding a limit, reducing a limit, or being reused."</summary>
    H3IdError = 0x0108,

    /// <summary>H3_SETTINGS_ERROR (0x0109): "An endpoint detected an error in the payload of a
    /// SETTINGS frame."</summary>
    H3SettingsError = 0x0109,

    /// <summary>H3_MISSING_SETTINGS (0x010a): "No SETTINGS frame was received at the beginning
    /// of the control stream."</summary>
    H3MissingSettings = 0x010a,

    /// <summary>H3_MESSAGE_ERROR (0x010e): "An HTTP message was malformed and cannot be
    /// processed."</summary>
    /// <remarks>THE ONLY MEMBER HERE THAT NAMES A STREAM ERROR RATHER THAN A CONNECTION ERROR,
    /// and the distinction is s8's own: "This is referred to as a 'stream error'" against "This
    /// is referred to as a 'connection error'". s4.1.2 puts this code on the stream side without
    /// ambiguity - "Malformed requests or responses that are detected MUST be treated as a
    /// stream error of type H3_MESSAGE_ERROR" - so a caller that reads this code off
    /// <see cref="TlsQuicHttp3Response.TryRead"/> resets the one stream and leaves the
    /// connection up. Nothing in this enum encodes which of the two a member is; s8 grants an
    /// endpoint the choice anyway ("An endpoint MAY choose to treat a stream error as a
    /// connection error under certain circumstances"), so the fact is stated here rather than
    /// modelled.</remarks>
    H3MessageError = 0x010e,
}

/// <summary>An RFC 9114 s11.2.1 Table 2 frame type this client sends or must recognise.</summary>
/// <remarks>The Reserved rows of Table 2 - 0x02, 0x06, 0x08 and 0x09 - are deliberately NOT
/// members. They are the HTTP/2-inherited types whose receipt s7.2.8 makes a connection error;
/// giving them names would put them one cast away from being sent. They are recognised by
/// <see cref="TlsQuicHttp3Frames.IsHttp2ReservedFrameType(ulong)"/> instead.</remarks>
internal enum TlsQuicHttp3FrameType : ulong
{
    /// <summary>DATA, 0x00.</summary>
    Data = 0x00,

    /// <summary>HEADERS, 0x01.</summary>
    Headers = 0x01,

    /// <summary>CANCEL_PUSH, 0x03. Payload is a single push ID varint.</summary>
    CancelPush = 0x03,

    /// <summary>SETTINGS, 0x04.</summary>
    Settings = 0x04,

    /// <summary>PUSH_PROMISE, 0x05.</summary>
    PushPromise = 0x05,

    /// <summary>GOAWAY, 0x07. Payload is a single stream-ID-or-push-ID varint.</summary>
    Goaway = 0x07,

    /// <summary>MAX_PUSH_ID, 0x0d. Payload is a single push ID varint.</summary>
    MaxPushId = 0x0d,
}

/// <summary>What one call to <see cref="TlsQuicHttp3Frames.TryRead"/> concluded.</summary>
/// <remarks>THREE OUTCOMES AND NOT TWO, because s7 says "unlike QUIC frames, HTTP/3 frames can
/// span multiple packets". A declared Length longer than the bytes in hand on a STREAM is the
/// ordinary case of a frame still arriving, and collapsing it into the error case would make
/// every large HEADERS frame a connection error. The bound on how long a caller waits is not
/// this codec's: <see cref="TlsQuicStream.ReceiveLimit"/> already caps what a single stream
/// may buffer, so a Length no sender can ever satisfy dies there rather than here.</remarks>
internal enum TlsQuicHttp3FrameReadStatus
{
    /// <summary>A whole frame was read and the offset advanced past it.</summary>
    Complete = 0,

    /// <summary>The bytes in hand stop inside the frame. Nothing was consumed; call again with
    /// more. Not an error.</summary>
    Incomplete = 1,

    /// <summary>The bytes cannot be a legal frame. Nothing was consumed and the out error
    /// carries the s8.1 code to close with.</summary>
    Error = 2,
}

/// <summary>RFC 9114 s7.1's Type/Length/Payload framing, and s7.2.8's and s7.2.4.1's reserved
/// identifier arithmetic.</summary>
/// <remarks>
/// <para>NOTHING HERE THROWS ON PEER INPUT. Every method that reads bytes is
/// <c>Try</c>-shaped and every rejection is a return value, because these bytes arrive on a
/// QUIC stream the peer writes. The rejecting paths allocate nothing: the payload is handed
/// back as a slice of the caller's buffer, not a copy.</para>
/// <para>THE VARINTS ARE QUIC VARINTS, not QPACK prefixed integers.
/// <see cref="QuicVariableLengthInteger"/> is the only codec used; s7.1's three fields are
/// all "(i)".</para>
/// </remarks>
internal static class TlsQuicHttp3Frames
{
    /// <summary>The step in RFC 9114 s7.2.8's "0x1f * N + 0x21".</summary>
    internal const ulong ReservedStep = 0x1f;

    /// <summary>The base in RFC 9114 s7.2.8's "0x1f * N + 0x21".</summary>
    internal const ulong ReservedBase = 0x21;

    /// <summary>The largest N for which <see cref="ReservedIdentifier(ulong)"/> stays inside a
    /// QUIC varint.</summary>
    /// <remarks>s11.2.1, s11.2.2, s11.2.3 and s11.2.4 all print the same series, "0x21, 0x40,
    /// ..., through 0x3ffffffffffffffe", and 0x3ffffffffffffffe is
    /// <see cref="QuicVariableLengthInteger.MaximumValue"/> minus one. This is that endpoint
    /// solved for N rather than retyped, so a reader can check the RFC's last term against
    /// <c>ReservedStep * MaximumN + ReservedBase</c>.</remarks>
    internal const ulong MaximumReservedN =
        (QuicVariableLengthInteger.MaximumValue - ReservedBase) / ReservedStep;

    /// <summary>Gets whether an identifier is one of RFC 9114 s7.2.8's reserved (GREASE)
    /// values, by recomputing the form rather than consulting a table.</summary>
    /// <remarks>
    /// <para>ONE PREDICATE FOR FOUR REGISTRIES. s11.2.1 (frame types), s11.2.2 (settings),
    /// s11.2.3 (error codes) and s11.2.4 (stream types) each reserve the identical
    /// "0x1f * N + 0x21" series, in identical words. They are separate reservations in
    /// separate registries - a reserved frame type and a reserved setting identifier are not
    /// the same thing and must not be conflated - but the ARITHMETIC is one function, and
    /// writing it four times would be four chances to get it wrong.</para>
    /// <para>The <c>&gt;= ReservedBase</c> half is not redundant, and the reason is narrower
    /// than it first looks. Unsigned subtraction below the base wraps to
    /// <c>2^64 + identifier - 0x21</c>, and 2^64 mod 0x1f is 16, so the wrapped value is a
    /// multiple of 0x1f exactly when <c>identifier + 14 == 0 (mod 31)</c> - which below 0x21
    /// has the single solution <b>0x11</b>. An earlier draft of this comment claimed 0x00
    /// wrapped onto the series; it does not (0x00 lands on 14), and the sweep that mutated
    /// this line survived because the test's four values had been chosen to match that wrong
    /// claim. Witnessed by
    /// TlsQuicHttp3FramesTests.IdentifiersBelowTheReservedBaseAreNotReserved, whose 0x11 row
    /// is the only one of its rows that fails without the guard.</para>
    /// </remarks>
    internal static bool IsReservedIdentifier(ulong identifier) =>
        identifier >= ReservedBase && (identifier - ReservedBase) % ReservedStep == 0;

    /// <summary>Gets the reserved (GREASE) identifier for a given N, RFC 9114 s7.2.8's
    /// "0x1f * N + 0x21".</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="n"/> is above
    /// <see cref="MaximumReservedN"/>, so the identifier would not fit a QUIC varint.</exception>
    internal static ulong ReservedIdentifier(ulong n)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(n, MaximumReservedN, nameof(n));
        return (ReservedStep * n) + ReservedBase;
    }

    /// <summary>Gets whether a frame type is one RFC 9114 s11.2.1 Table 2 reserves from
    /// HTTP/2 - one whose receipt s7.2.8 makes a connection error of type
    /// H3_FRAME_UNEXPECTED.</summary>
    /// <remarks>The four values are Table 2's four "Reserved" rows read off in order: 0x02,
    /// 0x06, 0x08, 0x09. They are HTTP/2's PRIORITY, SETTINGS, PING and GOAWAY, which HTTP/3
    /// either dropped or moved - which is WHY they are reserved, and is not a rule anything
    /// here derives from.</remarks>
    internal static bool IsHttp2ReservedFrameType(ulong frameType) =>
        frameType is 0x02 or 0x06 or 0x08 or 0x09;

    /// <summary>Gets whether a setting identifier is one RFC 9114 s11.2.2 Table 3 reserves
    /// from HTTP/2 - one that s7.2.4.1 says "MUST NOT be sent" and whose "receipt MUST be
    /// treated as a connection error of type H3_SETTINGS_ERROR".</summary>
    /// <remarks>
    /// <para>Table 3's five "Reserved" rows: 0x00, 0x02, 0x03, 0x04, 0x05. NOTE THE SHAPE
    /// DIFFERENCE FROM THE FRAME LIST - the settings series starts at 0x00 and runs 0x02
    /// through 0x05, the frame series is 0x02, 0x06, 0x08, 0x09. They look similar enough to
    /// invite one shared list, and one shared list would be wrong in both directions: 0x00 is
    /// DATA as a frame type and reserved as a setting; 0x06 is MAX_FIELD_SECTION_SIZE as a
    /// setting and reserved as a frame type.</para>
    /// <para>0x01 and 0x07 are absent from Table 3 because RFC 9204 s5 registers them
    /// (QPACK_MAX_TABLE_CAPACITY and QPACK_BLOCKED_STREAMS); the capture sends both.</para>
    /// </remarks>
    internal static bool IsHttp2ReservedSettingIdentifier(ulong identifier) =>
        identifier is 0x00 or 0x02 or 0x03 or 0x04 or 0x05;

    /// <summary>Appends one RFC 9114 s7.1 frame - Type, Length, Payload.</summary>
    /// <remarks>NO CHECK THAT THE TYPE IS SENDABLE. A caller that passes an HTTP/2-reserved
    /// type gets those bytes; the s7.2.8 "MUST NOT be sent" half is enforced where a type is
    /// CHOSEN, not here, because this is also the writer the tests use to build the hostile
    /// input <see cref="TryRead"/> is measured against, and a writer that cannot express an
    /// illegal frame cannot be used to witness that the reader rejects one.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="destination"/> is
    /// <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="frameType"/> is above
    /// <see cref="QuicVariableLengthInteger.MaximumValue"/>.</exception>
    internal static void Write(
        List<byte> destination, ulong frameType, ReadOnlySpan<byte> payload)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            frameType, QuicVariableLengthInteger.MaximumValue, nameof(frameType));

        QuicVariableLengthInteger.Write(destination, frameType);
        QuicVariableLengthInteger.Write(destination, (ulong)payload.Length);
        foreach (var b in payload)
        {
            destination.Add(b);
        }
    }

    /// <summary>Reads one RFC 9114 s7.1 frame, advancing <paramref name="offset"/> only when a
    /// whole one was there.</summary>
    /// <remarks>
    /// <para>NEVER THROWS, for any input. Truncation at any of the three fields is
    /// <see cref="TlsQuicHttp3FrameReadStatus.Incomplete"/>; a varint whose continuation runs
    /// off the end is the same thing, because <see cref="QuicVariableLengthInteger.TryRead"/>
    /// already answers false rather than reading past its span.</para>
    /// <para>THE ONE PLACE A LENGTH IS AN ERROR RATHER THAN A WAIT. A Length above
    /// <see cref="int.MaxValue"/> cannot ever be handed back as a
    /// <see cref="ReadOnlySpan{T}"/>, whose Length is an <see cref="int"/> - so no quantity of
    /// further bytes turns that frame into a readable one, and reporting Incomplete would be
    /// a promise the type system cannot keep. That bound is DERIVED from the platform, not
    /// invented: it is not a policy limit on frame size, and a caller wanting one applies it
    /// on top. s8.1's H3_FRAME_ERROR is "a frame ... with an invalid size", which this
    /// is.</para>
    /// </remarks>
    internal static TlsQuicHttp3FrameReadStatus TryRead(
        ReadOnlySpan<byte> source,
        ref int offset,
        out ulong frameType,
        out ReadOnlySpan<byte> payload,
        out TlsQuicHttp3ErrorCode error)
    {
        frameType = 0;
        payload = default;
        error = TlsQuicHttp3ErrorCode.None;

        var cursor = offset;
        if (!QuicVariableLengthInteger.TryRead(source, ref cursor, out var type)
            || !QuicVariableLengthInteger.TryRead(source, ref cursor, out var length))
        {
            return TlsQuicHttp3FrameReadStatus.Incomplete;
        }

        // s7.2.8: "Frame types that were used in HTTP/2 where there is no corresponding HTTP/3
        // frame have also been reserved. These frame types MUST NOT be sent, and their receipt
        // MUST be treated as a connection error of type H3_FRAME_UNEXPECTED." Checked BEFORE
        // the length is honoured, so an illegal type with an unsatisfiable length is reported
        // as the illegal type it is rather than waiting forever for bytes.
        if (IsHttp2ReservedFrameType(type))
        {
            error = TlsQuicHttp3ErrorCode.H3FrameUnexpected;
            return TlsQuicHttp3FrameReadStatus.Error;
        }

        if (length > int.MaxValue)
        {
            error = TlsQuicHttp3ErrorCode.H3FrameError;
            return TlsQuicHttp3FrameReadStatus.Error;
        }

        if (source.Length - cursor < (int)length)
        {
            return TlsQuicHttp3FrameReadStatus.Incomplete;
        }

        frameType = type;
        payload = source.Slice(cursor, (int)length);
        offset = cursor + (int)length;
        return TlsQuicHttp3FrameReadStatus.Complete;
    }

    /// <summary>Reads a frame payload that RFC 9114 defines as exactly one variable-length
    /// integer - CANCEL_PUSH (s7.2.3), GOAWAY (s7.2.6) and MAX_PUSH_ID (s7.2.7).</summary>
    /// <remarks>
    /// <para>THIS IS s7.1's EQUALITY, NOT A BOUNDS CHECK. "A frame payload that contains
    /// additional bytes after the identified fields or a frame payload that terminates before
    /// the end of the identified fields MUST be treated as a connection error of type
    /// H3_FRAME_ERROR", and s10.8 restates it: "An implementation MUST ensure that the length
    /// of a frame exactly matches the length of the fields it contains." So the cursor must
    /// land on the payload's END, not merely inside it - a five-byte payload holding a
    /// one-byte varint is as invalid as a payload that stops mid-varint. A parser written with
    /// <c>&lt;=</c> here accepts the attacker's four spare bytes and is the "security risk to
    /// an incautious implementer" s10.8 names.</para>
    /// <para>Truncation is H3_FRAME_ERROR and not Incomplete: the payload's extent is already
    /// fixed by the Length <see cref="TryRead"/> honoured, so there are no further bytes
    /// coming for THIS frame.</para>
    /// </remarks>
    internal static bool TryReadSingleVarintPayload(
        ReadOnlySpan<byte> payload, out ulong value, out TlsQuicHttp3ErrorCode error)
    {
        value = 0;
        var cursor = 0;
        if (!QuicVariableLengthInteger.TryRead(payload, ref cursor, out value)
            || cursor != payload.Length)
        {
            value = 0;
            error = TlsQuicHttp3ErrorCode.H3FrameError;
            return false;
        }

        error = TlsQuicHttp3ErrorCode.None;
        return true;
    }
}

/// <summary>RFC 9114 s7.2.4's SETTINGS frame, encoded from and decoded into an ORDERED list of
/// s7.2.4 "Setting { Identifier (i), Value (i) }" pairs.</summary>
/// <remarks>
/// <para>ORDER SURVIVES IN BOTH DIRECTIONS. The encoder writes the spec's list as given and is
/// forbidden to sort it; the decoder returns the peer's pairs in the peer's order, because the
/// peer's order is as much a fingerprint as ours and subsystem B will want to read it. A
/// dictionary would have been the obvious container and would have destroyed the one property
/// this file exists to preserve.</para>
/// </remarks>
internal static class TlsQuicHttp3Settings
{
    /// <summary>The token <see cref="Render"/> substitutes for a reserved (GREASE)
    /// identifier.</summary>
    /// <remarks>The capture's fingerprint string, line 47, ends
    /// <c>...;51:1;GREASE</c> - the reserved pair is rendered as the bare word and neither its
    /// identifier nor its value appears, because both are chosen fresh per connection and
    /// printing them would make every connection a different fingerprint.</remarks>
    internal const string ReservedToken = "GREASE";

    /// <summary>Finds what <paramref name="settings"/> says about <paramref name="identifier"/>,
    /// or <see langword="null"/> if it says nothing.</summary>
    /// <remarks>
    /// <para>ONE WALK, IN ONE PLACE. C16 collapsed two identical copies into this - the
    /// datagram-willingness lookup in <see cref="TlsQuicHttp3Streams"/> and the field-section
    /// limit lookup in <see cref="TlsQuicHttp3Connection"/> - rather than adding a third for
    /// QPACK's two identifiers. Both copies also read the FIRST match, which this keeps:
    /// s7.2.4's "The same setting identifier MUST NOT occur more than once" is enforced by
    /// <see cref="TryDecodePayload"/>, so by the time a peer's list reaches here there is at
    /// most one, and a locally built list with two has made a mistake this lookup should not
    /// paper over differently in different callers.</para>
    /// <para>ABSENT IS NOT ZERO, which is why the answer is nullable. A peer that sends no
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY has said nothing; RFC 9204 s5 supplies the default of
    /// 0 separately, and a caller that wants it says so.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="settings"/> is
    /// <see langword="null"/>.</exception>
    internal static ulong? Value(IReadOnlyList<TlsQuicHttp3Setting> settings, ulong identifier)
    {
        ArgumentNullException.ThrowIfNull(settings);

        for (var i = 0; i < settings.Count; i++)
        {
            if (settings[i].Identifier == identifier)
            {
                return settings[i].Value;
            }
        }

        return null;
    }

    /// <summary>Encodes a whole SETTINGS frame - s7.1's Type 0x04, Length, and the pairs -
    /// from the spec's ordered list.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="destination"/> or
    /// <paramref name="spec"/> is <see langword="null"/>.</exception>
    internal static void Encode(List<byte> destination, TlsQuicHttp3Spec spec)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(spec);

        var payload = new List<byte>();
        EncodePayload(payload, spec.Settings);
        TlsQuicHttp3Frames.Write(
            destination,
            (ulong)TlsQuicHttp3FrameType.Settings,
            System.Runtime.InteropServices.CollectionsMarshal.AsSpan(payload));
    }

    /// <summary>Appends just the s7.2.4 payload - the pairs, in the given order, with nothing
    /// around them.</summary>
    /// <remarks>THE LOOP IS `for (i = 0; i &lt; count; i++)` OVER THE LIST AS GIVEN. There is
    /// no sort, no stable-sort and no "canonical" ordering step, and
    /// TlsQuicHttp3SettingsTests.APairListInDescendingIdentifierOrderEncodesInThatOrder is the
    /// test that would fail if one were added.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="destination"/> or
    /// <paramref name="settings"/> is <see langword="null"/>.</exception>
    internal static void EncodePayload(
        List<byte> destination, IReadOnlyList<TlsQuicHttp3Setting> settings)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(settings);

        for (var i = 0; i < settings.Count; i++)
        {
            QuicVariableLengthInteger.Write(destination, settings[i].Identifier);
            QuicVariableLengthInteger.Write(destination, settings[i].Value);
        }
    }

    /// <summary>Decodes an s7.2.4 payload into the peer's pairs, in the peer's order.</summary>
    /// <remarks>
    /// <para>NEVER THROWS. Every rejection below is a return value with the s8.1 code the RFC
    /// names for it.</para>
    /// <para>ZERO PAIRS IS A SUCCESS, NOT AN ABSENCE. s7.2.4: "The payload of a SETTINGS frame
    /// consists of zero or more parameters." An empty payload decodes to an empty list and
    /// true - which is a different fact from no SETTINGS frame having arrived at all, and that
    /// second fact is H3_MISSING_SETTINGS and belongs to
    /// <see cref="TlsQuicHttp3Streams"/>.</para>
    /// <para>THE DUPLICATE RULE IS A MAY AND IS TAKEN. s7.2.4: "The same setting identifier
    /// MUST NOT occur more than once in the SETTINGS frame. A receiver MAY treat the presence
    /// of duplicate setting identifiers as a connection error of type H3_SETTINGS_ERROR." The
    /// alternative a MAY leaves open is silently keeping one of the two, and which one is
    /// unspecified - so an implementation that ignores the duplicate has a peer-controlled
    /// choice of which value it ends up honouring. Rejecting is the answer with no such
    /// branch.</para>
    /// <para>THE SCAN IS QUADRATIC IN THE PAIR COUNT. A peer choosing to send a hundred
    /// thousand distinct settings would cost the square of that in comparisons. Not a real
    /// exposure here, because the payload is bounded by
    /// <see cref="TlsQuicStream.ReceiveLimit"/> and every pair costs at least two bytes; a set
    /// would be the fix if that bound ever rises.</para>
    /// </remarks>
    internal static bool TryDecodePayload(
        ReadOnlySpan<byte> payload,
        out ImmutableArray<TlsQuicHttp3Setting> settings,
        out TlsQuicHttp3ErrorCode error)
    {
        settings = [];
        var decoded = ImmutableArray.CreateBuilder<TlsQuicHttp3Setting>();
        var cursor = 0;

        while (cursor < payload.Length)
        {
            if (!QuicVariableLengthInteger.TryRead(payload, ref cursor, out var identifier)
                || !QuicVariableLengthInteger.TryRead(payload, ref cursor, out var value))
            {
                // s7.1: "a frame payload that terminates before the end of the identified
                // fields MUST be treated as a connection error of type H3_FRAME_ERROR". A pair
                // whose value varint is missing is exactly that, and it is H3_FRAME_ERROR
                // rather than H3_SETTINGS_ERROR because the fault is the layout, not the
                // meaning of any setting.
                error = TlsQuicHttp3ErrorCode.H3FrameError;
                return false;
            }

            // s7.2.4.1: reserved-from-HTTP/2 identifiers' "receipt MUST be treated as a
            // connection error of type H3_SETTINGS_ERROR".
            if (TlsQuicHttp3Frames.IsHttp2ReservedSettingIdentifier(identifier))
            {
                error = TlsQuicHttp3ErrorCode.H3SettingsError;
                return false;
            }

            // RFC 9297 s2.1.1: "If the SETTINGS_H3_DATAGRAM setting is received with a value
            // that is neither 0 nor 1, the receiver MUST terminate the connection with error
            // H3_SETTINGS_ERROR."
            if (identifier == TlsQuicHttp3Spec.H3DatagramIdentifier && value > 1)
            {
                error = TlsQuicHttp3ErrorCode.H3SettingsError;
                return false;
            }

            for (var i = 0; i < decoded.Count; i++)
            {
                if (decoded[i].Identifier == identifier)
                {
                    error = TlsQuicHttp3ErrorCode.H3SettingsError;
                    return false;
                }
            }

            decoded.Add(new TlsQuicHttp3Setting(identifier, value));
        }

        settings = decoded.ToImmutable();
        error = TlsQuicHttp3ErrorCode.None;
        return true;
    }

    /// <summary>Renders the settings segment of the fingerprint string - the capture's
    /// <c>1:65536;6:262144;7:100;51:1;GREASE</c>.</summary>
    /// <remarks>
    /// <para>The separator is <c>;</c> and a pair is <c>identifier:value</c>, both read off
    /// the capture's line 47. A reserved identifier renders as
    /// <see cref="ReservedToken"/> alone, decided by
    /// <see cref="TlsQuicHttp3Frames.IsReservedIdentifier(ulong)"/> - by the arithmetic, so a
    /// browser that picks a different N next connection still renders the same token.</para>
    /// <para><see cref="CultureInfo.InvariantCulture"/> because a fingerprint string with
    /// digit grouping or non-ASCII digits in it is not the fingerprint.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="settings"/> is
    /// <see langword="null"/>.</exception>
    internal static string Render(IReadOnlyList<TlsQuicHttp3Setting> settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var parts = new string[settings.Count];
        for (var i = 0; i < settings.Count; i++)
        {
            parts[i] = TlsQuicHttp3Frames.IsReservedIdentifier(settings[i].Identifier)
                ? ReservedToken
                : string.Create(
                    CultureInfo.InvariantCulture,
                    $"{settings[i].Identifier}:{settings[i].Value}");
        }

        return string.Join(';', parts);
    }
}


// ============================================================================
// THE MUTATION LEDGER - TASK C16 (this file: TlsQuicHttp3Settings.Value, the
// settings walk C16 collapsed two copies into)
// ============================================================================
//
//   ROWS BELOW                    2  = C16-34 to C16-35 with no gaps
//   KILLED WHEN FIRST RUN         1  = 2 rows, less 0 [WAS-SURVIVOR] and 1 [SURVIVED]
//   SURVIVING STILL               1  = row C16-34, classified at the row
//
//   1 + 1 = 2. The task's other 33 rows are in TlsQuicQpackDecoder.cs (11),
//   TlsQuicQpackPrimitives.cs (2), TlsQuicHttp3Request.cs (7), TlsQuicHttp3Streams.cs (7) and
//   TlsQuicHttp3Connection.cs (6). 2 + 33 = 35 rows for the task.
//
//   `grep -cE '^// +C16-[0-9]+\. ' TlsQuicHttp3Frames.cs`                  must return 2
//   `grep -cE '^// +C16-[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicHttp3Frames.cs` must return 0
//   `grep -cE '^// +C16-[0-9]+\..*\[SURVIVED\]' TlsQuicHttp3Frames.cs`     must return 1
//
// Same harness, same gate and the same three harness defects as TlsQuicQpackDecoder.cs's C16
// block, which records them in full.
//
//  C16-34. [SURVIVED] The walk returns the LAST match rather than the first.
//        UNREACHABLE BY CONSTRUCTION, AND NO TEST IS WRITTEN - one would have to build a list
//        no caller can hand over. s7.2.4's "The same setting identifier MUST NOT occur more
//        than once in the SETTINGS frame" is enforced twice before anything reaches here:
//        TryDecodePayload refuses a peer's duplicate with H3_SETTINGS_ERROR, and
//        TlsQuicHttp3Spec.Settings THROWS on a locally built one. With at most one match in
//        every reachable list, first and last are the same entry. A test that reached this by
//        calling Value directly with a hand-made duplicate would be asserting a tie-breaking
//        rule no caller can observe, which is the false witness this project's rules forbid.
//  C16-35. Absent conflated with zero, so a peer that advertised NOTHING is read as having
//        advertised 0 and every caller's own RFC default is bypassed. Killed by 25 - the
//        broadest kill in the sweep, because the nullable answer is what
//        Http3DatagramsPermittedToSend, AsFieldSectionLimit and both of C16's QPACK lookups
//        each layer their own default on top of.
//
// ============================================================================
