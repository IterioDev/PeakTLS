using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task C3: RFC 9114 s7.2.4's SETTINGS frame, encoded from and decoded into an ORDERED list.
//
// ============================================================================
// WHAT THE CAPTURE CAN AND CANNOT SETTLE ABOUT ORDER.
// ============================================================================
//
//   The capture's five identifiers are 1, 6, 7, 51 and 126585778853 - STRICTLY ASCENDING.
//   So the capture is consistent with the browser having written them in that order AND
//   with the browser having sorted them, and it cannot distinguish the two. That is an
//   honestly not-yet-known fact, and no test in this file claims otherwise.
//
//   What the tests below do claim, and what is checkable:
//
//     1. Our encoder reproduces the capture's sequence - byte-exactly for the four small
//        pairs, and by re-parse for all five including the reserved one, whose two numbers
//        are re-chosen per connection by a real browser and are here only as a shape.
//     2. Our encoder DOES NOT SORT. TlsQuicHttp3SettingsTests.APairListInDescendingIdentifier
//        OrderEncodesInThatOrder passes a descending list and reads the bytes back in that
//        order. An implementation that sorted would reproduce the capture perfectly and
//        fail this one - which is exactly why the capture cannot be the only evidence.
//     3. The peer's order survives decoding, because it is the peer's fingerprint.
//
//   Point 2 is the whole reason C1 models SETTINGS as a sequence. If wire order turns out to
//   be sorted after all, the sequence still expresses it; the reverse is not true.
public sealed class TlsQuicHttp3SettingsTests
{
    // The capture's four non-reserved pairs, hand-encoded from RFC 9000 s16's varint table
    // rather than produced by the writer under test:
    //
    //   1        -> 0x01                    (1-byte form, values to 63)
    //   65536    -> 0x80 0x01 0x00 0x00     (4-byte form: 0x80000000 | 0x00010000)
    //   6        -> 0x06
    //   262144   -> 0x80 0x04 0x00 0x00     (4-byte form: 0x80000000 | 0x00040000)
    //   7        -> 0x07
    //   100      -> 0x40 0x64               (2-byte form: 0x4000 | 0x0064)
    //   51       -> 0x33
    //   1        -> 0x01
    //
    // A round trip proves the encoder and decoder agree while both are wrong; these bytes
    // are the check that they are not.
    private static readonly byte[] CaptureFourPairPayload =
    [
        0x01, 0x80, 0x01, 0x00, 0x00,
        0x06, 0x80, 0x04, 0x00, 0x00,
        0x07, 0x40, 0x64,
        0x33, 0x01,
    ];

    [Fact]
    public void TheCapturesFourNamedSettingsEncodeToHandDerivedBytes()
    {
        var payload = new List<byte>();
        TlsQuicHttp3Settings.EncodePayload(
            payload,
            [new(1, 65536), new(6, 262144), new(7, 100), new(51, 1)]);

        Assert.Equal(CaptureFourPairPayload, payload.ToArray());
    }

    [Fact]
    public void TheCapturesFiveSettingsReParseToTheSameFivePairsInTheSameOrder()
    {
        var spec = new TlsQuicHttp3Spec();
        var frame = new List<byte>();
        TlsQuicHttp3Settings.Encode(frame, spec);
        var bytes = frame.ToArray();

        var offset = 0;
        var status = TlsQuicHttp3Frames.TryRead(
            bytes, ref offset, out var frameType, out var payload, out _);
        Assert.Equal(TlsQuicHttp3FrameReadStatus.Complete, status);
        Assert.Equal(0x04UL, frameType);

        Assert.True(TlsQuicHttp3Settings.TryDecodePayload(payload, out var decoded, out var error));
        Assert.Equal(TlsQuicHttp3ErrorCode.None, error);
        Assert.Equal(spec.Settings.ToArray(), decoded.ToArray());

        // Element by element as well as as a whole, so a failure names the position rather
        // than printing two five-element arrays.
        for (var i = 0; i < spec.Settings.Length; i++)
        {
            Assert.Equal(spec.Settings[i], decoded[i]);
        }
    }

    [Fact]
    public void TheEncodedFrameCarriesTypeZeroFourAndItsOwnPayloadLength()
    {
        var frame = new List<byte>();
        TlsQuicHttp3Settings.Encode(
            frame, new TlsQuicHttp3Spec { Settings = [new(7, 100), new(51, 1)] });

        // s7.2.4's "SETTINGS Frame { Type (i) = 0x04, Length (i), Setting (..) ... }". The
        // payload is 0x07 0x40 0x64 0x33 0x01 - five bytes.
        Assert.Equal(new byte[] { 0x04, 0x05, 0x07, 0x40, 0x64, 0x33, 0x01 }, frame.ToArray());
    }

    [Fact]
    public void APairListInDescendingIdentifierOrderEncodesInThatOrder()
    {
        // THE NO-SORT TEST. The capture cannot settle whether the browser sorts, so the one
        // property that CAN be pinned is that our encoder is faithful to whatever list it is
        // handed. An encoder with a sort passes every capture-shaped test in this file and
        // fails only this one.
        var settings = new TlsQuicHttp3Setting[]
        {
            new(51, 1), new(7, 100), new(6, 262144), new(1, 65536),
        };

        var payload = new List<byte>();
        TlsQuicHttp3Settings.EncodePayload(payload, settings);

        Assert.Equal(
            new byte[]
            {
                0x33, 0x01,
                0x07, 0x40, 0x64,
                0x06, 0x80, 0x04, 0x00, 0x00,
                0x01, 0x80, 0x01, 0x00, 0x00,
            },
            payload.ToArray());

        Assert.True(TlsQuicHttp3Settings.TryDecodePayload(
            payload.ToArray(), out var decoded, out _));
        Assert.Equal(settings, decoded);
    }

    [Fact]
    public void TheRenderedSettingsSegmentEqualsTheCapturesCharacterForCharacter()
    {
        // 2026-08-16-brave-151-http3-impersonate-pro.md line 47's first field, verbatim.
        Assert.Equal(
            "1:65536;6:262144;7:100;51:1;GREASE",
            TlsQuicHttp3Settings.Render(new TlsQuicHttp3Spec().Settings));
    }

    [Fact]
    public void TheGreaseTokenIsSubstitutedByTheArithmeticAndNotByTheCapturesValue()
    {
        // A browser picks a fresh N each connection, so the renderer must produce the same
        // token for a reserved identifier the capture never contained. 0x21 is the series'
        // first term; 0x22 is one past it and renders as a number.
        Assert.Equal("GREASE", TlsQuicHttp3Settings.Render([new(0x21, 999)]));
        Assert.Equal("GREASE", TlsQuicHttp3Settings.Render([new(0x40, 0)]));
        Assert.Equal("34:999", TlsQuicHttp3Settings.Render([new(0x22, 999)]));
    }

    [Fact]
    public void AnEmptySettingsListRendersAsTheEmptyString()
    {
        Assert.Equal(string.Empty, TlsQuicHttp3Settings.Render([]));
    }

    // ------------------------------------------------------------------------
    // Decoding the peer's SETTINGS.
    // ------------------------------------------------------------------------

    [Fact]
    public void AnEmptyPayloadDecodesToZeroSettingsAndSucceeds()
    {
        // ZERO VERSUS ABSENT. s7.2.4: "The payload of a SETTINGS frame consists of zero or
        // more parameters." A SETTINGS frame with nothing in it is legal and is a DIFFERENT
        // fact from no SETTINGS frame having arrived, which is H3_MISSING_SETTINGS and lives
        // in TlsQuicHttp3StreamsTests.
        Assert.True(TlsQuicHttp3Settings.TryDecodePayload([], out var decoded, out var error));
        Assert.Empty(decoded);
        Assert.Equal(TlsQuicHttp3ErrorCode.None, error);
    }

    [Fact]
    public void TheDecoderPreservesThePeersOrderRatherThanSortingIt()
    {
        // The peer's order is as much a fingerprint as ours, and subsystem B will read it.
        Assert.True(TlsQuicHttp3Settings.TryDecodePayload(
            [0x33, 0x01, 0x07, 0x40, 0x64, 0x01, 0x41, 0x00], out var decoded, out _));

        Assert.Equal(
            new TlsQuicHttp3Setting[] { new(51, 1), new(7, 100), new(1, 256) }, decoded);
    }

    [Fact]
    public void ADuplicateIdentifierIsRejectedWithH3SettingsError()
    {
        // s7.2.4: "The same setting identifier MUST NOT occur more than once in the SETTINGS
        // frame. A receiver MAY treat the presence of duplicate setting identifiers as a
        // connection error of type H3_SETTINGS_ERROR." The MAY is taken; see
        // TlsQuicHttp3Settings.TryDecodePayload's remarks for why the alternative has a
        // peer-controlled branch in it.
        Assert.False(TlsQuicHttp3Settings.TryDecodePayload(
            [0x07, 0x01, 0x01, 0x02, 0x07, 0x03], out var decoded, out var error));

        Assert.Equal(TlsQuicHttp3ErrorCode.H3SettingsError, error);
        Assert.Empty(decoded);
    }

    [Theory]
    [InlineData((byte)0x00)]
    [InlineData((byte)0x02)]
    [InlineData((byte)0x03)]
    [InlineData((byte)0x04)]
    [InlineData((byte)0x05)]
    public void AnHttp2InheritedIdentifierIsRejectedWithH3SettingsError(byte identifier)
    {
        // s7.2.4.1: "Setting identifiers that were defined in [HTTP/2] where there is no
        // corresponding HTTP/3 setting have also been reserved. These reserved settings MUST
        // NOT be sent, and their receipt MUST be treated as a connection error of type
        // H3_SETTINGS_ERROR." s11.2.2 Table 3's five Reserved rows.
        Assert.False(TlsQuicHttp3Settings.TryDecodePayload(
            [identifier, 0x01], out _, out var error));

        Assert.Equal(TlsQuicHttp3ErrorCode.H3SettingsError, error);
    }

    [Theory]
    [InlineData((byte)0x01)]
    [InlineData((byte)0x06)]
    [InlineData((byte)0x07)]
    public void TheIdentifiersInsideTheReservedRunsGapsAreAccepted(byte identifier)
    {
        // 0x01 and 0x07 are RFC 9204 s5's QPACK settings and 0x06 is
        // MAX_FIELD_SECTION_SIZE; all three sit between or beside s11.2.2's Reserved rows.
        // A rejection written as a range instead of the five values fails here.
        Assert.True(TlsQuicHttp3Settings.TryDecodePayload(
            [identifier, 0x01], out var decoded, out _));

        Assert.Equal((ulong)identifier, decoded[0].Identifier);
    }

    [Theory]
    [InlineData((byte)0x02)]
    [InlineData((byte)0x3f)]
    public void AnH3DatagramValueOtherThanZeroOrOneIsRejectedWithH3SettingsError(byte value)
    {
        // RFC 9297 s2.1.1: "If the SETTINGS_H3_DATAGRAM setting is received with a value that
        // is neither 0 nor 1, the receiver MUST terminate the connection with error
        // H3_SETTINGS_ERROR." Identifier 0x33 is 51, the capture's.
        Assert.False(TlsQuicHttp3Settings.TryDecodePayload(
            [0x33, value], out _, out var error));

        Assert.Equal(TlsQuicHttp3ErrorCode.H3SettingsError, error);
    }

    [Theory]
    [InlineData((byte)0x00)]
    [InlineData((byte)0x01)]
    public void BothLegalH3DatagramValuesAreAccepted(byte value)
    {
        // The other side of s2.1.1's MUST, and the zero-versus-absent pair: 51:0 is a
        // received pair that says "not willing", not a missing pair.
        Assert.True(TlsQuicHttp3Settings.TryDecodePayload(
            [0x33, value], out var decoded, out _));

        Assert.Single(decoded);
        Assert.Equal((ulong)value, decoded[0].Value);
    }

    [Theory]
    [InlineData(new byte[] { 0x07 })] // an identifier with no value
    [InlineData(new byte[] { 0x07, 0x40 })] // a value varint that stops mid-field
    [InlineData(new byte[] { 0x07, 0x01, 0x01 })] // a whole pair, then half of another
    public void APayloadThatEndsInsideAPairIsRejectedWithH3FrameError(byte[] payload)
    {
        // s7.1: "a frame payload that terminates before the end of the identified fields
        // MUST be treated as a connection error of type H3_FRAME_ERROR". H3_FRAME_ERROR and
        // not H3_SETTINGS_ERROR because the fault is the layout rather than the meaning of
        // any one setting - both are defensible readings and this file states which it took.
        Assert.False(TlsQuicHttp3Settings.TryDecodePayload(payload, out var decoded, out var error));

        Assert.Equal(TlsQuicHttp3ErrorCode.H3FrameError, error);
        Assert.Empty(decoded);
    }

    [Fact]
    public void AReservedIdentifierFromThePeerIsAcceptedAndKeptInPlace()
    {
        // s7.2.4.1: "Endpoints MUST NOT consider such settings to have any meaning upon
        // receipt" - which is not the same as dropping them. Keeping the pair is what lets
        // subsystem B report the peer's GREASE position.
        Assert.True(TlsQuicHttp3Settings.TryDecodePayload(
            [0x21, 0x05, 0x07, 0x01], out var decoded, out _));

        Assert.Equal(2, decoded.Length);
        Assert.Equal(0x21UL, decoded[0].Identifier);
        Assert.True(TlsQuicHttp3Frames.IsReservedIdentifier(decoded[0].Identifier));
    }

    [Fact]
    public void NoPayloadMakesTheSettingsDecoderThrow()
    {
        var failures = new List<string>();

        for (var first = 0; first < 256; first++)
        {
            for (var tail = 0; tail <= 9; tail++)
            {
                var bytes = new byte[1 + tail];
                bytes[0] = (byte)first;
                for (var i = 1; i < bytes.Length; i++)
                {
                    bytes[i] = (byte)((first * 13) + (i * 29));
                }

                try
                {
                    TlsQuicHttp3Settings.TryDecodePayload(bytes, out _, out _);
                }
                catch (Exception threw)
                {
                    failures.Add($"first=0x{first:x2} tail={tail}: {threw.GetType().Name}");
                }
            }
        }

        Assert.Empty(failures);
    }
}
