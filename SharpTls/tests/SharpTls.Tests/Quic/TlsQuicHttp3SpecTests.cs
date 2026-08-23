using System.Text.RegularExpressions;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task C1: the HTTP/3 layout spec. No behaviour, so every test here is either a default
// checked against the capture or a guard checked for reachability.
//
// ============================================================================
// WHY EVERY GUARD GETS ITS OWN TEST AND ITS OWN NAME.
// ============================================================================
//
//   Subsystem B populates this object from outside the library, so every value a guard
//   rejects is a value a caller can write - there are no unreachable guards here, and a
//   guard with no test is a mutation nobody would notice. TlsQuicConnectionSpec.cs's header
//   states the rule; this file is the other half of it for the layer above.
//
//   The negative tests assert the PARAMETER NAME as well as the exception type. A single
//   property with two guards can throw the same exception type from either, and asserting
//   the type alone lets a test pass because a DIFFERENT guard fired.
public sealed class TlsQuicHttp3SpecTests
{
    // ------------------------------------------------------------------------
    // The defaults, against the capture.
    // ------------------------------------------------------------------------

    [Fact]
    public void TheDefaultSettingsAreTheCapturesFiveInTheCapturesOrder()
    {
        // 2026-08-16-brave-151-http3-impersonate-pro.md lines 64-68, written out by hand
        // rather than read from TlsQuicHttp3Spec.CaptureSettings - a comparison against the
        // thing under test cannot fail.
        var spec = new TlsQuicHttp3Spec();

        Assert.Equal(5, spec.Settings.Length);
        Assert.Equal(new TlsQuicHttp3Setting(1, 65536), spec.Settings[0]);
        Assert.Equal(new TlsQuicHttp3Setting(6, 262144), spec.Settings[1]);
        Assert.Equal(new TlsQuicHttp3Setting(7, 100), spec.Settings[2]);
        Assert.Equal(new TlsQuicHttp3Setting(51, 1), spec.Settings[3]);
        Assert.Equal(new TlsQuicHttp3Setting(126585778853, 2585972839), spec.Settings[4]);
    }

    [Fact]
    public void TheH3DatagramIdentifierIsBothTheRfcs0x33AndTheCaptures51()
    {
        // rfc9297-section2.1-http3-datagrams.txt names the setting 0x33; the capture line 67
        // prints 51. This is the arithmetic that makes those one identifier rather than two
        // numbers that happen to sit near each other in a comment.
        Assert.Equal(51UL, TlsQuicHttp3Spec.H3DatagramIdentifier);
        Assert.Equal(0x33UL, TlsQuicHttp3Spec.H3DatagramIdentifier);
    }

    [Fact]
    public void TheCapturesGreaseSettingIdentifierIsAReservedOne()
    {
        // Line 68's identifier, recomputed against s7.2.4.1's form rather than asserted
        // against a table: 0x1f * 4083412220 + 0x21.
        const ulong Captured = 126585778853;

        Assert.True(TlsQuicHttp3Frames.IsReservedIdentifier(Captured));
        Assert.Equal(Captured, TlsQuicHttp3Frames.ReservedIdentifier(4083412220));
    }

    [Fact]
    public void TheDefaultPseudoHeaderOrderIsTheCapturesMethodAuthoritySchemePath()
    {
        // Capture line 70, `m,a,s,p`.
        var spec = new TlsQuicHttp3Spec();

        Assert.Equal(
            new[]
            {
                TlsQuicHttp3PseudoHeader.Method,
                TlsQuicHttp3PseudoHeader.Authority,
                TlsQuicHttp3PseudoHeader.Scheme,
                TlsQuicHttp3PseudoHeader.Path,
            },
            spec.PseudoHeaderOrder.ToArray());
    }

    [Fact]
    public void TheDefaultStreamOpenOrderIsControlThenEncoderThenDecoder()
    {
        // THE PLACEHOLDER, asserted so that changing it is a deliberate act with a failing
        // test attached rather than a silent edit. Nothing in the capture settles it; see
        // TlsQuicHttp3Spec.UnidirectionalStreamOpenOrder's remarks.
        var spec = new TlsQuicHttp3Spec();

        Assert.Equal(
            new[]
            {
                TlsQuicHttp3StreamType.Control,
                TlsQuicHttp3StreamType.QpackEncoder,
                TlsQuicHttp3StreamType.QpackDecoder,
            },
            spec.UnidirectionalStreamOpenOrder.ToArray());
    }

    [Fact]
    public void TheStreamTypeMembersCarryTheirWireValues()
    {
        // s11.2.4 Table 5 for 0x00 and 0x01; rfc9204-section4.1-4.2-primitives-and-streams
        // .txt for 0x02 and 0x03.
        Assert.Equal(0x00UL, (ulong)TlsQuicHttp3StreamType.Control);
        Assert.Equal(0x01UL, (ulong)TlsQuicHttp3StreamType.Push);
        Assert.Equal(0x02UL, (ulong)TlsQuicHttp3StreamType.QpackEncoder);
        Assert.Equal(0x03UL, (ulong)TlsQuicHttp3StreamType.QpackDecoder);
    }

    // ------------------------------------------------------------------------
    // Settings guards.
    // ------------------------------------------------------------------------

    [Fact]
    public void ADefaultValuedSettingsListIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => new TlsQuicHttp3Spec { Settings = default });

        Assert.Equal("Settings", error.ParamName);
    }

    [Fact]
    public void AnEmptySettingsListIsAccepted()
    {
        // ZERO IS NOT ABSENT. s7.2.4's payload "consists of zero or more parameters", so a
        // client that sends SETTINGS with nothing in it is conforming - and that is a
        // different thing from sending no SETTINGS frame, which is not expressible here at
        // all because s6.2.1 makes it a connection error.
        var spec = new TlsQuicHttp3Spec { Settings = [] };

        Assert.Empty(spec.Settings);
    }

    [Theory]
    [InlineData(0x00UL)]
    [InlineData(0x02UL)]
    [InlineData(0x03UL)]
    [InlineData(0x04UL)]
    [InlineData(0x05UL)]
    public void AnHttp2ReservedSettingIdentifierIsRejected(ulong identifier)
    {
        // s11.2.2 Table 3's five Reserved rows; s7.2.4.1: "These reserved settings MUST NOT
        // be sent". One row per InlineData because the five are read off a table and a loop
        // over a range would silently drift if 0x01 or 0x06 were ever mis-added.
        var error = Assert.Throws<ArgumentException>(
            () => new TlsQuicHttp3Spec { Settings = [new(identifier, 1)] });

        Assert.Equal("Settings", error.ParamName);
    }

    [Theory]
    [InlineData(0x01UL)]
    [InlineData(0x06UL)]
    [InlineData(0x07UL)]
    public void TheThreeIdentifiersAdjacentToTheReservedRunAreAccepted(ulong identifier)
    {
        // The other half of the previous test, and the one that would fail if the reserved
        // predicate were written as a range: 0x01 and 0x07 are QPACK's, 0x06 is
        // MAX_FIELD_SECTION_SIZE, and all three sit inside any range spanning 0x00 to 0x05
        // that got its endpoints wrong by one.
        var spec = new TlsQuicHttp3Spec { Settings = [new(identifier, 1)] };

        Assert.Equal(identifier, spec.Settings[0].Identifier);
    }

    [Fact]
    public void ADuplicateSettingIdentifierIsRejected()
    {
        // s7.2.4: "The same setting identifier MUST NOT occur more than once in the SETTINGS
        // frame."
        var error = Assert.Throws<ArgumentException>(
            () => new TlsQuicHttp3Spec { Settings = [new(7, 100), new(1, 65536), new(7, 200)] });

        Assert.Equal("Settings", error.ParamName);
    }

    [Fact]
    public void ASettingIdentifierAboveTheVarintMaximumIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicHttp3Spec
            {
                Settings = [new(QuicVariableLengthInteger.MaximumValue + 1, 1)],
            });

        Assert.Equal("Settings", error.ParamName);
    }

    [Fact]
    public void ASettingValueAboveTheVarintMaximumIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicHttp3Spec
            {
                Settings = [new(7, QuicVariableLengthInteger.MaximumValue + 1)],
            });

        Assert.Equal("Settings", error.ParamName);
    }

    [Fact]
    public void AnH3DatagramValueAboveOneIsRejected()
    {
        // RFC 9297 s2.1.1: "The value of the SETTINGS_H3_DATAGRAM setting MUST be either 0
        // or 1."
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicHttp3Spec
            {
                Settings = [new(TlsQuicHttp3Spec.H3DatagramIdentifier, 2)],
            });

        Assert.Equal("Settings", error.ParamName);
    }

    [Fact]
    public void AnH3DatagramValueOfZeroIsAcceptedAndIsNotTheSameAsOmittingIt()
    {
        // ZERO VERSUS ABSENT AGAIN, and here the two states differ on the wire: 51:0 puts a
        // pair in the SETTINGS frame and an omission does not, while both leave
        // Http3DatagramsPermittedToSend false.
        var explicitZero = new TlsQuicHttp3Spec
        {
            Settings = [new(TlsQuicHttp3Spec.H3DatagramIdentifier, 0)],
        };
        var omitted = new TlsQuicHttp3Spec { Settings = [new(7, 100)] };

        Assert.Equal(0UL, explicitZero.Settings[0].Value);
        Assert.DoesNotContain(
            omitted.Settings, s => s.Identifier == TlsQuicHttp3Spec.H3DatagramIdentifier);
    }

    // ------------------------------------------------------------------------
    // Stream-open-order guards.
    // ------------------------------------------------------------------------

    [Fact]
    public void ADefaultValuedStreamOpenOrderIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => new TlsQuicHttp3Spec { UnidirectionalStreamOpenOrder = default });

        Assert.Equal("UnidirectionalStreamOpenOrder", error.ParamName);
    }

    [Fact]
    public void AnUndefinedStreamTypeInTheOpenOrderIsRejected()
    {
        // The reachable path is a cast from an arbitrary ulong, which is what subsystem B
        // holds. 0x04 is one past QPACK's decoder stream and is registered to nothing.
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicHttp3Spec
            {
                UnidirectionalStreamOpenOrder =
                    [TlsQuicHttp3StreamType.Control, (TlsQuicHttp3StreamType)0x04],
            });

        Assert.Equal("UnidirectionalStreamOpenOrder", error.ParamName);
    }

    [Fact]
    public void APushStreamInTheOpenOrderIsRejected()
    {
        // s6.2.2: "Only servers can push; if a server receives a client-initiated push
        // stream, this MUST be treated as a connection error of type
        // H3_STREAM_CREATION_ERROR."
        var error = Assert.Throws<ArgumentException>(
            () => new TlsQuicHttp3Spec
            {
                UnidirectionalStreamOpenOrder =
                    [TlsQuicHttp3StreamType.Control, TlsQuicHttp3StreamType.Push],
            });

        Assert.Equal("UnidirectionalStreamOpenOrder", error.ParamName);
    }

    [Fact]
    public void AStreamOpenOrderWithoutTheControlStreamIsRejected()
    {
        // s6.2.1: "Each side MUST initiate a single control stream at the beginning of the
        // connection and send its SETTINGS frame as the first frame on this stream."
        var error = Assert.Throws<ArgumentException>(
            () => new TlsQuicHttp3Spec
            {
                UnidirectionalStreamOpenOrder =
                    [TlsQuicHttp3StreamType.QpackEncoder, TlsQuicHttp3StreamType.QpackDecoder],
            });

        Assert.Equal("UnidirectionalStreamOpenOrder", error.ParamName);
    }

    [Fact]
    public void ADuplicateStreamTypeInTheOpenOrderIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => new TlsQuicHttp3Spec
            {
                UnidirectionalStreamOpenOrder =
                [
                    TlsQuicHttp3StreamType.Control,
                    TlsQuicHttp3StreamType.QpackEncoder,
                    TlsQuicHttp3StreamType.Control,
                ],
            });

        Assert.Equal("UnidirectionalStreamOpenOrder", error.ParamName);
    }

    [Fact]
    public void AReorderedStreamOpenOrderIsAccepted()
    {
        // The knob is a knob: the placeholder default is not the only accepted value.
        var spec = new TlsQuicHttp3Spec
        {
            UnidirectionalStreamOpenOrder =
            [
                TlsQuicHttp3StreamType.QpackDecoder,
                TlsQuicHttp3StreamType.QpackEncoder,
                TlsQuicHttp3StreamType.Control,
            ],
        };

        Assert.Equal(TlsQuicHttp3StreamType.QpackDecoder, spec.UnidirectionalStreamOpenOrder[0]);
        Assert.Equal(TlsQuicHttp3StreamType.Control, spec.UnidirectionalStreamOpenOrder[2]);
    }

    // ------------------------------------------------------------------------
    // Pseudo-header and QPACK-policy guards.
    // ------------------------------------------------------------------------

    [Fact]
    public void ADefaultValuedPseudoHeaderOrderIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => new TlsQuicHttp3Spec { PseudoHeaderOrder = default });

        Assert.Equal("PseudoHeaderOrder", error.ParamName);
    }

    [Fact]
    public void AnUndefinedPseudoHeaderIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicHttp3Spec
            {
                PseudoHeaderOrder = [(TlsQuicHttp3PseudoHeader)4],
            });

        Assert.Equal("PseudoHeaderOrder", error.ParamName);
    }

    [Fact]
    public void ADuplicatePseudoHeaderIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => new TlsQuicHttp3Spec
            {
                PseudoHeaderOrder =
                [
                    TlsQuicHttp3PseudoHeader.Method,
                    TlsQuicHttp3PseudoHeader.Method,
                ],
            });

        Assert.Equal("PseudoHeaderOrder", error.ParamName);
    }

    [Fact]
    public void AnUndefinedQpackNameMatchPolicyIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicHttp3Spec
            {
                QpackNameMatchPolicy = (TlsQuicQpackNameMatchPolicy)7,
            });

        Assert.Equal("QpackNameMatchPolicy", error.ParamName);
    }

    [Fact]
    public void TheNotYetWiredKnobsCarryTheirDeclaredDefaults()
    {
        // These four are recorded as NOT YET WIRED in TlsQuicHttp3Spec.cs's header table,
        // owed by task C9. This test does not claim they change any byte - it pins the
        // declared placeholder so C9 inherits a stated starting point rather than whatever
        // the field initialiser happened to be.
        var spec = new TlsQuicHttp3Spec();

        Assert.True(spec.QpackHuffmanStringLiterals);
        Assert.Equal(TlsQuicQpackNameMatchPolicy.NameReference, spec.QpackNameMatchPolicy);
        Assert.False(spec.SendReservedFramesOnRequestStreams);
        Assert.Equal(4, spec.PseudoHeaderOrder.Length);
    }

    [Fact]
    public void TheKnobsThatAreWiredAreSettableToSomethingOtherThanTheirDefault()
    {
        // A knob that only ever holds its default is indistinguishable from a constant.
        var spec = new TlsQuicHttp3Spec
        {
            QpackHuffmanStringLiterals = false,
            QpackNameMatchPolicy = TlsQuicQpackNameMatchPolicy.LiteralName,
            SendReservedFramesOnRequestStreams = true,
            PseudoHeaderOrder =
                [TlsQuicHttp3PseudoHeader.Path, TlsQuicHttp3PseudoHeader.Method],
        };

        Assert.False(spec.QpackHuffmanStringLiterals);
        Assert.Equal(TlsQuicQpackNameMatchPolicy.LiteralName, spec.QpackNameMatchPolicy);
        Assert.True(spec.SendReservedFramesOnRequestStreams);
        Assert.Equal(TlsQuicHttp3PseudoHeader.Path, spec.PseudoHeaderOrder[0]);
    }

    [Fact]
    public void NoLayoutLiteralEscapesTheDefaultsBlock()
    {
        // C1's done-when: "a grep of the task's own diff finds no numeric layout literal
        // outside the defaults block". Asserted here rather than left to a reviewer's grep,
        // because the file grows.
        //
        // The scan covers the region after the defaults block's closing marker, and looks for
        // a decimal or hex literal in CODE - comments and string literals are where the RFC's
        // own section numbers and quoted sentences live, and quoting them is the point. A
        // scan that did not strip strings would report `RFC 9114` as a layout literal, which
        // is the shape of a check that is deleted the first time it is wrong rather than
        // tightened.
        var source = File.ReadAllLines(SpecSourcePath);
        var end = Array.FindIndex(source, line => line.Contains(
            "End of the defaults block.", StringComparison.Ordinal));
        Assert.True(end > 0, "The defaults block's closing marker moved or was removed.");

        var offenders = new List<string>();
        for (var i = end; i < source.Length; i++)
        {
            var line = source[i];
            var code = line.TrimStart();
            if (code.StartsWith("//", StringComparison.Ordinal)
                || code.StartsWith("///", StringComparison.Ordinal))
            {
                continue;
            }

            code = StringLiteral.Replace(code, " ");

            // 0 and 1 are excluded: they are RFC 9297 s2.1.1's two legal SETTINGS_H3_DATAGRAM
            // values and array-index arithmetic, neither of which is a layout choice. Every
            // other numeral would be.
            foreach (var token in code.Split(
                [' ', '(', ')', ',', ';', '[', ']', '{', '}', '<', '>', '=', '+', '-', '*', '/'],
                StringSplitOptions.RemoveEmptyEntries))
            {
                if (token is "0" or "1" or "0x" || !char.IsAsciiDigit(token[0]))
                {
                    continue;
                }
                offenders.Add($"{i + 1}: {token}");
            }
        }

        Assert.Empty(offenders);
    }

    // A C# string literal with backslash escapes honoured, so a `\"` inside a message does
    // not end the match early and leak the rest of the sentence back into the scan.
    private static readonly Regex StringLiteral = new(
        "\"(?:\\\\.|[^\"\\\\])*\"", RegexOptions.Compiled);

    private static string SpecSourcePath
    {
        get
        {
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null
                && !Directory.Exists(Path.Combine(directory.FullName, "src", "SharpTls")))
            {
                directory = directory.Parent;
            }

            Assert.NotNull(directory);
            return Path.Combine(
                directory.FullName, "src", "SharpTls", "Quic", "TlsQuicHttp3Spec.cs");
        }
    }
}
