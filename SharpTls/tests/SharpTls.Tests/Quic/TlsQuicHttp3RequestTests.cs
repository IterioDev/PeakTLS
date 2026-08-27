using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task C9: RFC 9114 s7.2.2's HEADERS frame carrying an s4.3 request field section.
// Task C10: RFC 9114 s4.1's response, read back off the same request stream. Its cases begin
// at the "Task C10" banner below and carry their own helpers; the two halves share only this
// file and TlsQuicHttp3Field.
//
// ============================================================================
// THE ORDER IS READ BACK, NOT ASSERTED AGAINST THE INPUT.
// ============================================================================
//
//   Every order claim in this file goes through TlsQuicQpackDecoder (task C8) - the bytes
//   are decoded and the resulting names compared. Asserting that the encoder emitted what
//   it was given would be a test of a variable assignment. The property that matters is
//   that a DECODER sees :method, :authority, :scheme, :path in that sequence, because a
//   decoder is what the endpoint being fingerprinted runs.
//
//   The one thing that cannot cancel this way is a mistake shared by our encoder and our
//   decoder. It is bounded here: the ORDER of field lines is not something either side can
//   permute - RFC 9204 s4.5 gives a field section no reordering mechanism at all - so a
//   shared defect could corrupt a name or a value, and the values are checked against the
//   literal strings the request was built from.
//
// ============================================================================
// THE FOUR KNOBS TASK C9 OWES A READER
// ============================================================================
//
//   TlsQuicHttp3Spec's header carried four rows reading NOT YET WIRED. Each now has a test
//   below that sets it on the spec and reads the BYTES change - A4's standing rule that "a
//   knob is honoured only if a caller setting it on the type changes the bytes, with a test
//   that witnesses the change":
//
//     PseudoHeaderOrder                   .ReorderingThePseudoHeadersChangesTheBytes
//     QpackHuffmanStringLiterals          .TurningHuffmanOffChangesTheBytes
//     QpackNameMatchPolicy                .TheLiteralNamePolicyChangesTheBytes
//     SendReservedFramesOnRequestStreams  .TheReservedFrameIsPresentOnlyWhenTheSpecAsks
//
//   Three of the four also assert that the DECODED FIELDS ARE UNCHANGED, which is the half
//   that says the knob moves the representation and not the message. A "witness" that only
//   showed the bytes differing would pass equally against a mutant that dropped a header.
public sealed class TlsQuicHttp3RequestTests
{
    // The endpoint the handoff's live spike reached, and the one C9's done-when names.
    private const string CaptureAuthority = "fp.impersonate.pro";
    private const string CapturePath = "/api/http3";

    private static TlsQuicHttp3Request CaptureGet() => new()
    {
        Method = "GET",
        Authority = CaptureAuthority,
        Scheme = "https",
        Path = CapturePath,
    };

    // ------------------------------------------------------------------
    // The done-when itself.
    // ------------------------------------------------------------------

    [Fact]
    public void AGetForTheCaptureEndpointDecodesInTheCapturesPseudoHeaderOrder()
    {
        var encoded = Encode(CaptureGet(), new TlsQuicHttp3Spec());

        var frames = ReadFrames(encoded);
        var frame = Assert.Single(frames);
        Assert.Equal((ulong)TlsQuicHttp3FrameType.Headers, frame.Type);

        Assert.Equal(
            [
                (":method", "GET"),
                (":authority", CaptureAuthority),
                (":scheme", "https"),
                (":path", CapturePath),
            ],
            DecodeFieldSection(frame.Payload));
    }

    // RFC 9114 s7.2.2: "The HEADERS frame (type=0x01)". A one-byte QUIC varint holds 0x01 as
    // itself, so the frame's first octet IS the type - which is worth pinning separately from
    // the decode above, because TlsQuicHttp3Frames.Write would happily have written any type
    // and the decode would not have noticed.
    [Fact]
    public void TheFrameTypeOctetIsTheHeadersType()
    {
        var encoded = Encode(CaptureGet(), new TlsQuicHttp3Spec());
        Assert.Equal(0x01, encoded[0]);
    }

    // RFC 9204 Appendix B.1's field section prefix, "0000 | Required Insert Count = 0,
    // Base = 0". This encoder never references the dynamic table, so the prefix is those two
    // octets for every request - the anchor that says the HEADERS payload really is a QPACK
    // field section and not the field lines alone.
    [Fact]
    public void TheFieldSectionBeginsWithTheTwoZeroPrefixOctets()
    {
        var frame = Assert.Single(ReadFrames(Encode(CaptureGet(), new TlsQuicHttp3Spec())));
        Assert.Equal(0x00, frame.Payload[0]);
        Assert.Equal(0x00, frame.Payload[1]);
    }

    // ------------------------------------------------------------------
    // Knob 1: PseudoHeaderOrder.
    // ------------------------------------------------------------------

    [Fact]
    public void ReorderingThePseudoHeadersChangesTheBytes()
    {
        var capture = Encode(CaptureGet(), new TlsQuicHttp3Spec());

        // s4.3.1's own definition order - :method, :scheme, :authority, :path - which is a
        // different sequence from the capture's and is equally conforming. That is the whole
        // point of the knob.
        var definitionOrder = Encode(
            CaptureGet(),
            new TlsQuicHttp3Spec
            {
                PseudoHeaderOrder =
                [
                    TlsQuicHttp3PseudoHeader.Method,
                    TlsQuicHttp3PseudoHeader.Scheme,
                    TlsQuicHttp3PseudoHeader.Authority,
                    TlsQuicHttp3PseudoHeader.Path,
                ],
            });

        Assert.NotEqual(capture, definitionOrder);

        var frame = Assert.Single(ReadFrames(definitionOrder));
        Assert.Equal(
            [":method", ":scheme", ":authority", ":path"],
            DecodeFieldSection(frame.Payload).Select(line => line.Name).ToArray());
    }

    // The strongest form of the same claim: EVERY permutation of the four is emitted as
    // given. A hard-coded order that happened to match the capture would pass the test above
    // for one of the two lists and fail here on twenty-three of twenty-four.
    [Fact]
    public void EveryPermutationOfTheFourPseudoHeadersIsEmittedAsGiven()
    {
        var permutations = 0;

        foreach (var order in Permutations(
            [
                TlsQuicHttp3PseudoHeader.Method,
                TlsQuicHttp3PseudoHeader.Authority,
                TlsQuicHttp3PseudoHeader.Scheme,
                TlsQuicHttp3PseudoHeader.Path,
            ]))
        {
            permutations++;
            var encoded = Encode(
                CaptureGet(),
                new TlsQuicHttp3Spec { PseudoHeaderOrder = [.. order] });

            var frame = Assert.Single(ReadFrames(encoded));
            var names = DecodeFieldSection(frame.Payload).Select(line => line.Name).ToArray();
            Assert.Equal(order.Select(NameOf).ToArray(), names);
        }

        // 4! = 24, recomputed from the loop rather than asserted as a literal.
        Assert.Equal(4 * 3 * 2 * 1, permutations);
    }

    // ------------------------------------------------------------------
    // Knob 2: QpackHuffmanStringLiterals.
    // ------------------------------------------------------------------

    [Fact]
    public void TurningHuffmanOffChangesTheBytes()
    {
        var huffman = Encode(CaptureGet(), new TlsQuicHttp3Spec());
        var plain = Encode(
            CaptureGet(), new TlsQuicHttp3Spec { QpackHuffmanStringLiterals = TlsQuicQpackHuffmanPolicy.Never });

        Assert.NotEqual(huffman, plain);

        // The message is the same message; only the string literals' representation moved.
        Assert.Equal(
            DecodeFieldSection(Assert.Single(ReadFrames(huffman)).Payload),
            DecodeFieldSection(Assert.Single(ReadFrames(plain)).Payload));
    }

    // With Huffman off the authority appears in the field section as its own ASCII bytes;
    // with it on it does not. A direct reading of which of the two the flag produced, rather
    // than an inference from a length or an inequality.
    [Fact]
    public void TheHuffmanFlagDecidesWhetherTheAuthorityIsOnTheWireAsAscii()
    {
        var authority = Encoding.UTF8.GetBytes(CaptureAuthority);

        var plain = Assert.Single(
            ReadFrames(
                Encode(CaptureGet(), new TlsQuicHttp3Spec { QpackHuffmanStringLiterals = TlsQuicQpackHuffmanPolicy.Never })));
        Assert.True(plain.Payload.AsSpan().IndexOf(authority) >= 0);

        var huffman = Assert.Single(ReadFrames(Encode(CaptureGet(), new TlsQuicHttp3Spec())));
        Assert.True(huffman.Payload.AsSpan().IndexOf(authority) < 0);
    }

    // ------------------------------------------------------------------
    // Knob 3: QpackNameMatchPolicy.
    // ------------------------------------------------------------------

    [Fact]
    public void TheLiteralNamePolicyChangesTheBytes()
    {
        var nameReference = Encode(CaptureGet(), new TlsQuicHttp3Spec());
        var literalName = Encode(
            CaptureGet(),
            new TlsQuicHttp3Spec
            {
                QpackNameMatchPolicy = TlsQuicQpackNameMatchPolicy.LiteralName,
            });

        Assert.NotEqual(nameReference, literalName);

        // RFC 9204 s4.5.6 spells the name out where s4.5.4 references it, so the literal-name
        // encoding is the longer of the two for a name the static table holds.
        Assert.True(literalName.Count > nameReference.Count);

        Assert.Equal(
            DecodeFieldSection(Assert.Single(ReadFrames(nameReference)).Payload),
            DecodeFieldSection(Assert.Single(ReadFrames(literalName)).Payload));
    }

    // The policy governs the NAME-matches-but-value-does-not case only. ":scheme https" is a
    // full static match, so RFC 9204 s4.5.2's indexed field line applies under either policy
    // and the two encodings of a request that carries ONLY full matches are identical. This
    // is the test that stops the policy from being read as "never use the static table".
    [Fact]
    public void ThePolicyDoesNotDisturbAFullStaticMatch()
    {
        // ":method GET", ":scheme https" and ":path /" are all Appendix A rows in full;
        // ":authority" is dropped from the order and its place taken by a `host` field, which
        // s4.3.1 permits, so that no name-only match is left in the section.
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = string.Empty,
            Scheme = "https",
            Path = "/",
            Fields = [new("host", CaptureAuthority)],
        };

        var order = ImmutableArray.Create(
            TlsQuicHttp3PseudoHeader.Method,
            TlsQuicHttp3PseudoHeader.Scheme,
            TlsQuicHttp3PseudoHeader.Path);

        var nameReference = Encode(request, new TlsQuicHttp3Spec { PseudoHeaderOrder = order });
        var literalName = Encode(
            request,
            new TlsQuicHttp3Spec
            {
                PseudoHeaderOrder = order,
                QpackNameMatchPolicy = TlsQuicQpackNameMatchPolicy.LiteralName,
            });

        // Only the `host` line differs; the three pseudo-headers are byte-identical prefixes.
        Assert.Equal(
            nameReference.Take(TlsQuicQpackEncoderPrefixAndThreeIndexedLines),
            literalName.Take(TlsQuicQpackEncoderPrefixAndThreeIndexedLines));
    }

    // The HEADERS frame header is two varints (type 0x01, length), the field section prefix is
    // two octets, and an indexed field line at an index below 63 is one octet. So the first
    // 2 + 2 + 3 = 7 octets are the frame header, the prefix and the three indexed lines.
    private const int TlsQuicQpackEncoderPrefixAndThreeIndexedLines = 7;

    // ------------------------------------------------------------------
    // Knob 4: SendReservedFramesOnRequestStreams.
    // ------------------------------------------------------------------

    [Fact]
    public void TheReservedFrameIsPresentOnlyWhenTheSpecAsks()
    {
        var without = ReadFrames(Encode(CaptureGet(), new TlsQuicHttp3Spec()));
        var only = Assert.Single(without);
        Assert.Equal((ulong)TlsQuicHttp3FrameType.Headers, only.Type);

        var with = ReadFrames(
            Encode(
                CaptureGet(),
                new TlsQuicHttp3Spec { SendReservedFramesOnRequestStreams = true }));
        Assert.Equal(2, with.Count);
        Assert.True(TlsQuicHttp3Frames.IsReservedIdentifier(with[0].Type));
        Assert.Empty(with[0].Payload);
        Assert.Equal((ulong)TlsQuicHttp3FrameType.Headers, with[1].Type);

        // The HEADERS frame is untouched by the reserved one - same type, same payload.
        Assert.Equal(only.Payload, with[1].Payload);
    }

    // RFC 9114 s7.2.8's "0x1f * N + 0x21", recomputed rather than asserted as 0x21.
    [Fact]
    public void TheReservedRequestStreamFrameTypeIsAReservedIdentifier()
    {
        Assert.True(
            TlsQuicHttp3Frames.IsReservedIdentifier(
                TlsQuicHttp3Request.ReservedRequestStreamFrameType));
        Assert.Equal(
            (TlsQuicHttp3Frames.ReservedStep * 0) + TlsQuicHttp3Frames.ReservedBase,
            TlsQuicHttp3Request.ReservedRequestStreamFrameType);
    }

    // ------------------------------------------------------------------
    // RFC 9114 s4.3.1's mandatory-field rules.
    // ------------------------------------------------------------------

    // "All HTTP/3 requests MUST include exactly one value for the :method, :scheme, and :path
    // pseudo-header fields". One row per omitted mandatory name. The rows are the NAMES and
    // not the enum members because TlsQuicHttp3PseudoHeader is internal and an xUnit theory
    // method must be public - the mapping back is NameOf, the same helper the order
    // assertions use.
    [Theory]
    [InlineData(":method")]
    [InlineData(":scheme")]
    [InlineData(":path")]
    public void AnOrderMissingAMandatoryPseudoHeaderIsRefused(string omittedName)
    {
        var order = ImmutableArray.CreateRange(
            TlsQuicHttp3Spec.CapturePseudoHeaderOrder.Where(
                pseudoHeader => NameOf(pseudoHeader) != omittedName));
        Assert.Equal(TlsQuicHttp3Spec.CapturePseudoHeaderOrder.Length - 1, order.Length);
        var destination = new List<byte>();

        Assert.False(
            CaptureGet().TryEncode(
                destination, new TlsQuicHttp3Spec { PseudoHeaderOrder = order }, out var error));
        Assert.Equal(TlsQuicHttp3RequestError.MandatoryPseudoHeaderOmitted, error);
        Assert.Empty(destination);
    }

    // :authority is the fourth member of the capture's order and is NOT on that list - s4.3.1
    // makes it conditional, not mandatory. The complement of the theory above, and the row
    // that would fail if the check were written as "the order must hold all four".
    [Fact]
    public void AnOrderMissingOnlyTheAuthorityIsAccepted()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = string.Empty,
            Scheme = "https",
            Path = CapturePath,
            Fields = [new("host", CaptureAuthority)],
        };

        var encoded = Encode(
            request,
            new TlsQuicHttp3Spec
            {
                PseudoHeaderOrder = TlsQuicHttp3Spec.CapturePseudoHeaderOrder.Remove(
                    TlsQuicHttp3PseudoHeader.Authority),
            });

        Assert.Equal(
            [(":method", "GET"), (":scheme", "https"), (":path", CapturePath),
             ("host", CaptureAuthority)],
            DecodeFieldSection(Assert.Single(ReadFrames(encoded)).Payload));
    }

    // "An HTTP request that omits mandatory pseudo-header fields or contains invalid values
    // for those pseudo-header fields is malformed."
    [Theory]
    [InlineData("", "https", "/")]
    [InlineData("GET", "", "/")]
    public void AnEmptyMethodOrSchemeIsRefused(string method, string scheme, string path)
    {
        var destination = new List<byte>();
        var request = new TlsQuicHttp3Request
        {
            Method = method,
            Authority = CaptureAuthority,
            Scheme = scheme,
            Path = path,
        };

        Assert.False(request.TryEncode(destination, new TlsQuicHttp3Spec(), out var error));
        Assert.Equal(TlsQuicHttp3RequestError.MandatoryPseudoHeaderValueInvalid, error);
        Assert.Empty(destination);
    }

    // ":path ... MUST NOT be empty for \"http\" or \"https\" URIs". BOTH HALVES OF THE
    // CONDITION: the two http-family schemes refuse an empty path and a scheme outside the
    // family does not, because s4.3.1's rule is scoped and a stricter one here would be this
    // project inventing a MUST.
    [Theory]
    [InlineData("https", false)]
    [InlineData("http", false)]
    [InlineData("HTTPS", false)]
    [InlineData("ftp", true)]
    public void AnEmptyPathIsRefusedForHttpSchemesOnly(string scheme, bool accepted)
    {
        var destination = new List<byte>();
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = CaptureAuthority,
            Scheme = scheme,
            Path = string.Empty,
        };

        Assert.Equal(
            accepted, request.TryEncode(destination, new TlsQuicHttp3Spec(), out var error));
        Assert.Equal(
            accepted
                ? TlsQuicHttp3RequestError.None
                : TlsQuicHttp3RequestError.MandatoryPseudoHeaderValueInvalid,
            error);
    }

    // ------------------------------------------------------------------
    // s4.3.1's authority rule.
    // ------------------------------------------------------------------

    // "the request MUST contain either an :authority pseudo-header field or a Host header
    // field."
    [Fact]
    public void AnHttpsRequestWithNeitherAuthorityNorHostIsRefused()
    {
        var destination = new List<byte>();
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = string.Empty,
            Scheme = "https",
            Path = CapturePath,
        };

        Assert.False(
            request.TryEncode(
                destination,
                new TlsQuicHttp3Spec
                {
                    PseudoHeaderOrder = TlsQuicHttp3Spec.CapturePseudoHeaderOrder.Remove(
                        TlsQuicHttp3PseudoHeader.Authority),
                },
                out var error));
        Assert.Equal(TlsQuicHttp3RequestError.AuthorityMissing, error);
        Assert.Empty(destination);
    }

    // The authority rule is SCOPED TO THE SCHEME, and this is the row that says so. s4.3.1's
    // requirement fires only "If the :scheme pseudo-header field identifies a scheme that has
    // a mandatory authority component (including \"http\" and \"https\")", and its next
    // sentence goes the other way outright: "If the scheme does not have a mandatory authority
    // component and none is provided in the request target, the request MUST NOT contain the
    // :authority pseudo-header or Host header fields." So a request outside the http family
    // with neither is accepted, and a check that demanded one regardless would be this project
    // inventing a rule s4.3.1 does not have.
    [Fact]
    public void ASchemeOutsideTheHttpFamilyNeedsNeitherAuthorityNorHost()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = string.Empty,
            Scheme = "ftp",
            Path = "/pub",
        };

        var encoded = Encode(
            request,
            new TlsQuicHttp3Spec
            {
                PseudoHeaderOrder = TlsQuicHttp3Spec.CapturePseudoHeaderOrder.Remove(
                    TlsQuicHttp3PseudoHeader.Authority),
            });

        Assert.Equal(
            [(":method", "GET"), (":scheme", "ftp"), (":path", "/pub")],
            DecodeFieldSection(Assert.Single(ReadFrames(encoded)).Payload));
    }

    // "If these fields are present, they MUST NOT be empty." One row per field that can be
    // the present-and-empty one.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AnEmptyAuthorityOrHostIsRefused(bool useAuthority)
    {
        var destination = new List<byte>();
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = useAuthority ? string.Empty : CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = useAuthority ? [] : [new("host", string.Empty)],
        };

        Assert.False(request.TryEncode(destination, new TlsQuicHttp3Spec(), out var error));
        Assert.Equal(TlsQuicHttp3RequestError.AuthorityEmpty, error);
        Assert.Empty(destination);
    }

    // ------------------------------------------------------------------
    // s4.3's boundary and s4.2's field names.
    // ------------------------------------------------------------------

    // "All pseudo-header fields MUST appear in the header section before regular header
    // fields." Read back off the decoded section: four pseudo-headers, then the two ordinary
    // fields in the order given, whatever the spec's pseudo order was.
    [Fact]
    public void EveryRegularFieldFollowsEveryPseudoHeader()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = [new("accept", "*/*"), new("user-agent", "sharptls")],
        };

        var lines = DecodeFieldSection(
            Assert.Single(ReadFrames(Encode(request, new TlsQuicHttp3Spec()))).Payload);

        Assert.Equal(
            [":method", ":authority", ":scheme", ":path", "accept", "user-agent"],
            lines.Select(line => line.Name).ToArray());
        Assert.Equal("*/*", lines[4].Value);
        Assert.Equal("sharptls", lines[5].Value);
    }

    // s4.3: "Endpoints MUST NOT generate pseudo-header fields other than those defined in
    // this document", and any pseudo-header among the regular fields would land after them.
    [Fact]
    public void ARegularFieldWhoseNameBeginsWithAColonIsRefused()
    {
        AssertRefused(
            [new(":method", "POST")],
            TlsQuicHttp3RequestError.PseudoHeaderAmongRegularFields);
    }

    // s4.2: "A request or response containing uppercase characters in field names MUST be
    // treated as malformed." Refused rather than silently lowercased - see the comment at the
    // check.
    [Theory]
    [InlineData("User-Agent")]
    [InlineData("accepT")]
    public void AnUppercaseRegularFieldNameIsRefused(string name)
    {
        AssertRefused(
            [new(name, "x")], TlsQuicHttp3RequestError.RegularFieldNameNotLowercase);
    }

    // An uppercase VALUE is untouched - s4.2's rule is about names.
    [Fact]
    public void AnUppercaseRegularFieldValueIsKeptAsGiven()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = [new("user-agent", "SharpTls/1.0 (Windows NT 10.0)")],
        };

        var lines = DecodeFieldSection(
            Assert.Single(ReadFrames(Encode(request, new TlsQuicHttp3Spec()))).Payload);
        Assert.Equal("SharpTls/1.0 (Windows NT 10.0)", lines[^1].Value);
    }

    [Fact]
    public void AnEmptyRegularFieldNameIsRefused() =>
        AssertRefused([new(string.Empty, "x")], TlsQuicHttp3RequestError.RegularFieldNameEmpty);

    // ------------------------------------------------------------------
    // Totality: nothing on this path throws, for any input.
    // ------------------------------------------------------------------

    // A null name is answered, not dereferenced. `default` gives a
    // TlsQuicHttp3Field whose two strings are null, which is reachable without a null
    // suppression and is exactly what a struct array element starts as.
    [Fact]
    public void ADefaultConstructedFieldIsRefusedRatherThanThrowing() =>
        AssertRefused([default], TlsQuicHttp3RequestError.RegularFieldNameEmpty);

    // A null VALUE reaches the encoder rather than the validator, so it is the other half of
    // the same claim: it encodes as an empty value.
    [Fact]
    public void ANullRegularFieldValueEncodesAsAnEmptyValue()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = [new("accept", null!)],
        };

        var lines = DecodeFieldSection(
            Assert.Single(ReadFrames(Encode(request, new TlsQuicHttp3Spec()))).Payload);
        Assert.Equal(("accept", string.Empty), lines[^1]);
    }

    // ONE ROW PER PSEUDO-HEADER, and the rows are separate on purpose: a single test that
    // nulls all four is satisfied by the first check that fires, and leaves the other three
    // dereferences unmeasured. The mutation sweep found exactly that - `Path ?? string.Empty`
    // could be turned into `Path!` and every test still passed, because the :method check
    // always returned first.
    [Theory]
    [InlineData("method")]
    [InlineData("authority")]
    [InlineData("scheme")]
    [InlineData("path")]
    public void ANullPseudoHeaderValueIsRefusedRatherThanThrowing(string nullField)
    {
        var destination = new List<byte>();
        var request = new TlsQuicHttp3Request
        {
            Method = nullField == "method" ? null! : "GET",
            Authority = nullField == "authority" ? null! : CaptureAuthority,
            Scheme = nullField == "scheme" ? null! : "https",
            Path = nullField == "path" ? null! : CapturePath,
        };

        // Which error depends on which field - an absent authority is s4.3.1's non-empty rule
        // and the other three are its invalid-value rule - so the claim here is the one all
        // four share: a refusal rather than a NullReferenceException, and no bytes written.
        Assert.False(request.TryEncode(destination, new TlsQuicHttp3Spec(), out var error));
        Assert.NotEqual(TlsQuicHttp3RequestError.None, error);
        Assert.Empty(destination);
    }

    // A default-valued ImmutableArray is a null reference wearing a struct. TlsQuicHttp3Spec
    // throws on one because it is a configuration surface; this type reads it as "no fields",
    // because its contract is to answer rather than throw.
    [Fact]
    public void ADefaultValuedFieldsArrayIsReadAsNoFields()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = default,
        };

        var lines = DecodeFieldSection(
            Assert.Single(ReadFrames(Encode(request, new TlsQuicHttp3Spec()))).Payload);
        Assert.Equal(4, lines.Count);
    }

    // The field section is built into an array that doubles until it fits. A value well past
    // the initial length exercises at least one doubling; Huffman is off so that the coded
    // size cannot shrink back under the threshold and leave the growth path unrun.
    [Fact]
    public void AFieldSectionLargerThanTheInitialBufferStillRoundTrips()
    {
        var large = new string('a', 4096);
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = [new("cookie", large)],
        };

        var lines = DecodeFieldSection(
            Assert.Single(
                ReadFrames(
                    Encode(
                        request,
                        new TlsQuicHttp3Spec { QpackHuffmanStringLiterals = TlsQuicQpackHuffmanPolicy.Never })))
                .Payload);
        Assert.Equal(("cookie", large), lines[^1]);
    }

    // Nothing is appended when the request is refused, so a caller need not undo a partial
    // write. Witnessed on a destination that already holds bytes, which a test on an empty
    // list could not distinguish from "wrote nothing yet".
    [Fact]
    public void NothingIsAppendedToANonEmptyDestinationWhenTheRequestIsRefused()
    {
        var destination = new List<byte> { 0xaa, 0xbb };
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = string.Empty,
        };

        Assert.False(request.TryEncode(destination, new TlsQuicHttp3Spec(), out _));
        Assert.Equal([0xaa, 0xbb], destination);
    }

    // The frames are APPENDED, not written from zero - the same property
    // TlsQuicHttp3Settings.Encode has, and what lets a caller put SETTINGS and a request into
    // one buffer.
    [Fact]
    public void TheFramesAreAppendedAfterWhateverTheDestinationAlreadyHeld()
    {
        var destination = new List<byte> { 0xaa };
        Assert.True(CaptureGet().TryEncode(destination, new TlsQuicHttp3Spec(), out _));
        Assert.Equal(0xaa, destination[0]);
        Assert.True(destination.Count > 1);
    }

    // The two reference parameters keep TlsQuicHttp3Settings.Encode's shape: a caller bug with
    // no meaningful error code stays an exception.
    [Fact]
    public void ANullDestinationOrSpecThrows()
    {
        Assert.Throws<ArgumentNullException>(
            () => CaptureGet().TryEncode(null!, new TlsQuicHttp3Spec(), out _));
        Assert.Throws<ArgumentNullException>(
            () => CaptureGet().TryEncode([], null!, out _));
    }

    // ------------------------------------------------------------------
    // Task C10b: s4.2's connection-specific field ban, and the TE carve-out.
    // ------------------------------------------------------------------
    //
    // EVERY NAME BELOW IS SPELLED OUT IN THIS FILE rather than read from the source's
    // ConnectionSpecificFieldNames array. A theory driven by the array would pass against a
    // mutant that emptied it, which is the definition of a false witness - the same reason C9's
    // pseudo-header tests read the ORDER back through a decoder instead of comparing it to the
    // spec that produced it.

    // RFC 9110 s7.6.1's five bullets, verbatim from the extract: "Proxy-Connection ...
    // Keep-Alive ... TE ... Transfer-Encoding ... Upgrade". `te` is absent from this theory
    // because s4.2 carves it out; it has its own two cases below.
    [Theory]
    [InlineData("proxy-connection")]
    [InlineData("keep-alive")]
    [InlineData("transfer-encoding")]
    [InlineData("upgrade")]
    public void AConnectionSpecificFieldFromSection761sListIsRefused(string name) =>
        AssertRefused(
            [new TlsQuicHttp3Field(name, "x")],
            TlsQuicHttp3RequestError.ConnectionSpecificField);

    // THE TRAP THE CAPTURE WAS TAKEN FOR. `connection` is NOT one of s7.6.1's five bullets - it
    // is removed by the separate MUST paragraph above them, which ends "and then remove the
    // Connection header field itself" - so a ban assembled by copying the bullet list alone
    // lets the one field s4.2 names in its own prose straight through. Both a bare `connection`
    // and one carrying options are refused, because it is the field that is forbidden and not
    // any particular option.
    [Theory]
    [InlineData("")]
    [InlineData("keep-alive")]
    [InlineData("te")]
    public void TheConnectionFieldItselfIsRefusedThoughItIsNotOneOfTheFiveBullets(string value) =>
        AssertRefused(
            [new TlsQuicHttp3Field("connection", value)],
            TlsQuicHttp3RequestError.ConnectionSpecificField);

    // s4.2: "The only exception to this is the TE header field, which MAY be present in an
    // HTTP/3 request header; when it is, it MUST NOT contain any value other than
    // \"trailers\"." MAY BE PRESENT - so this must ENCODE, and the field must come back out of
    // a real decode rather than merely fail to be refused.
    [Fact]
    public void ATeFieldCarryingTrailersIsAcceptedAndEmitted()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = [new TlsQuicHttp3Field("te", "trailers")],
        };

        var frame = Assert.Single(ReadFrames(Encode(request, new TlsQuicHttp3Spec())));

        Assert.Equal(
            [
                (":method", "GET"),
                (":authority", CaptureAuthority),
                (":scheme", "https"),
                (":path", CapturePath),
                ("te", "trailers"),
            ],
            DecodeFieldSection(frame.Payload));
    }

    // "MUST NOT contain any value other than \"trailers\"" - the second half of the same
    // sentence. A list CONTAINING trailers is not a value of "trailers"; nor is the empty
    // value; nor is any other transfer coding. "TRAILERS" is refused too, and that is a stated
    // choice rather than an oversight: s4.2 writes the permitted value as a lowercase literal
    // and no capture in this repo says a TE value is case-insensitive, so the encoder refuses
    // rather than emit a byte sequence it cannot defend. See IsPermittedTe's own comment.
    [Theory]
    [InlineData("")]
    [InlineData("gzip")]
    [InlineData("trailers, deflate")]
    [InlineData("deflate, trailers")]
    [InlineData("trailersx")]
    [InlineData("TRAILERS")]
    [InlineData("Trailers")]
    public void ATeFieldCarryingAnythingButTrailersIsRefused(string value) =>
        AssertRefused(
            [new TlsQuicHttp3Field("te", value)],
            TlsQuicHttp3RequestError.ConnectionSpecificField);

    // "The only exception to this is the TE header field" - ONLY TE. The carve-out is keyed on
    // the NAME as well as the value, and a check that looked only at the value would let every
    // other connection-specific field through by writing "trailers" in it. That mutant passes
    // every case above, which is why this one exists.
    [Theory]
    [InlineData("connection")]
    [InlineData("upgrade")]
    [InlineData("keep-alive")]
    [InlineData("transfer-encoding")]
    [InlineData("proxy-connection")]
    public void AConnectionSpecificFieldIsRefusedEvenWhenItsValueIsTrailers(string name) =>
        AssertRefused(
            [new TlsQuicHttp3Field(name, "trailers")],
            TlsQuicHttp3RequestError.ConnectionSpecificField);

    // THE CONVERSE, so none of the above passes because everything is refused. s7.6.1's list is
    // six names and not "every field a request carries", and these four are what the capture's
    // own request sends.
    //
    // THE VALUE IS NOW A COLUMN, AND ONLY BECAUSE OF THE content-length ROW. Every row used to
    // carry the filler "x", which stopped being a legal content-length when request bodies
    // arrived: TryValidateContentLength requires that field to be a non-negative decimal
    // integer equal to Body.Length, so "x" now refuses the request through
    // ContentLengthDisagreesWithBody. THAT IS THE NEW RULE WORKING, NOT THIS TEST BREAKING -
    // this theory's question is s7.6.1's six-name list and nothing else, so the row is given a
    // value its own subject does not object to, and the content-length rule is witnessed where
    // it belongs, in AContentLengthMustDescribeTheBodyOrTheRequestIsRefused. "0" is chosen and
    // not "5": these requests carry no body, so 0 is the sum of their DATA frame lengths.
    [Theory]
    [InlineData("accept-encoding", "gzip")]
    [InlineData("user-agent", "x")]
    [InlineData("content-length", "0")]
    [InlineData("connection-id", "x")]
    public void AnOrdinaryFieldIsNotRefusedByTheConnectionSpecificBan(string name, string value)
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = [new TlsQuicHttp3Field(name, value)],
        };

        var frame = Assert.Single(ReadFrames(Encode(request, new TlsQuicHttp3Spec())));
        Assert.Contains((name, value), DecodeFieldSection(frame.Payload));
    }

    // s4.2's uppercase rule runs FIRST, in the same loop iteration, which is what makes the
    // Ordinal comparison against six lowercase names safe. So "TE" is refused - but for being
    // uppercase, not for being connection-specific, and the two codes must not be confused. If
    // the two checks were ever reordered this case is the one that changes.
    [Theory]
    [InlineData("TE")]
    [InlineData("Upgrade")]
    [InlineData("Connection")]
    public void AnUppercaseConnectionSpecificNameIsRefusedForItsCaseFirst(string name) =>
        AssertRefused(
            [new TlsQuicHttp3Field(name, "trailers")],
            TlsQuicHttp3RequestError.RegularFieldNameNotLowercase);

    // ------------------------------------------------------------------
    // Task C10b: the CONNECT limitation, pinned rather than implemented.
    // ------------------------------------------------------------------

    // NOT A TEST OF CONNECT SUPPORT - there is none, deliberately. This pins the CONSEQUENCE
    // the source's THE CONNECT LIMITATION banner states, so that a later reader finds a named
    // gap with a witness instead of discovering it from a server.
    //
    // rfc9114-section4.4-connect.txt: "The :scheme and :path pseudo-header fields are omitted".
    // Omitting them from the order is therefore what a conforming CONNECT looks like, and this
    // validator - written from s4.3.1, whose rule is the exact inverse - refuses it.
    // The omitted name arrives as a string because an InlineData row cannot carry an internal
    // enum through a public test method's signature.
    [Theory]
    [InlineData("scheme")]
    [InlineData("path")]
    [InlineData("both")]
    public void AConnectShapedRequestIsRefusedBecauseConnectIsNotImplemented(string omitted)
    {
        var order = new List<TlsQuicHttp3PseudoHeader>
        {
            TlsQuicHttp3PseudoHeader.Method,
            TlsQuicHttp3PseudoHeader.Authority,
            TlsQuicHttp3PseudoHeader.Scheme,
            TlsQuicHttp3PseudoHeader.Path,
        };

        if (omitted is "scheme" or "both")
        {
            order.Remove(TlsQuicHttp3PseudoHeader.Scheme);
        }

        if (omitted is "path" or "both")
        {
            order.Remove(TlsQuicHttp3PseudoHeader.Path);
        }

        var request = new TlsQuicHttp3Request
        {
            Method = "CONNECT",
            Authority = "fp.impersonate.pro:443",
            Scheme = string.Empty,
            Path = string.Empty,
        };

        var destination = new List<byte>();
        Assert.False(
            request.TryEncode(
                destination,
                new TlsQuicHttp3Spec { PseudoHeaderOrder = [.. order] },
                out var error));

        Assert.Equal(TlsQuicHttp3RequestError.MandatoryPseudoHeaderOmitted, error);
        Assert.Empty(destination);
    }

    // The other half of the same gap: a caller who "fixes" the refusal above by supplying
    // :scheme and :path gets an encode, and what it encodes is a request s4.4's last sentence
    // calls malformed - "A CONNECT request that does not conform to these restrictions is
    // malformed." Nothing here refuses it, and that is exactly the limitation being recorded.
    [Fact]
    public void AConnectWithSchemeAndPathEncodesAndIsMalformedByS44()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "CONNECT",
            Authority = "fp.impersonate.pro:443",
            Scheme = "https",
            Path = "/",
        };

        var frame = Assert.Single(ReadFrames(Encode(request, new TlsQuicHttp3Spec())));
        var decoded = DecodeFieldSection(frame.Payload);

        Assert.Contains((":method", "CONNECT"), decoded);
        Assert.Contains((":scheme", "https"), decoded);
        Assert.Contains((":path", "/"), decoded);
    }

    // ------------------------------------------------------------------
    // Helpers.
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // RFC 9114 s4.1's items 2 and 3: the content and the trailer section.
    //
    // EVERY ONE OF THESE READS THE BYTES BACK THROUGH ReadFrames, which is
    // TlsQuicHttp3Frames.TryRead - the same parser TlsQuicHttp3Response's own frame loop uses.
    // Asserting that the encoder was HANDED a body would pass against an encoder that dropped
    // it; asserting the frame the parser finds is what says it left.
    // ------------------------------------------------------------------

    // s4.1: an HTTP message is "the header section ... sent as a single HEADERS frame",
    // "optionally, the content ... sent as a series of DATA frames", and "optionally, the
    // trailer section ... sent as a single HEADERS frame". All three, in that order, from one
    // TryEncode.
    [Fact]
    public void ARequestWithABodyAndTrailersEmitsHeadersThenDataThenTrailingHeaders()
    {
        var body = Encoding.UTF8.GetBytes("{\"q\":\"http3\"}");
        var request = new TlsQuicHttp3Request
        {
            Method = "POST",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = [new TlsQuicHttp3Field("content-length", body.Length.ToString(
                CultureInfo.InvariantCulture))],
            Body = [.. body],
            Trailers = [new TlsQuicHttp3Field("x-checksum", "9f")],
        };

        var frames = ReadFrames(Encode(request, new TlsQuicHttp3Spec()));

        Assert.Equal(
            [
                (ulong)TlsQuicHttp3FrameType.Headers,
                (ulong)TlsQuicHttp3FrameType.Data,
                (ulong)TlsQuicHttp3FrameType.Headers,
            ],
            frames.Select(frame => frame.Type).ToArray());

        // s7.2.1's DATA frame "convey[s] arbitrary, variable-length sequences of bytes" - the
        // payload is the body verbatim, not a re-encoding of it.
        Assert.Equal(body, frames[1].Payload);

        // The two field sections are INDEPENDENTLY DECODABLE, which is what says each carried
        // its own RFC 9204 s4.5.1 prefix. A trailer section written into the header section's
        // buffer would decode as gibberish or not at all.
        Assert.Contains((":method", "POST"), DecodeFieldSection(frames[0].Payload));
        Assert.Equal([("x-checksum", "9f")], DecodeFieldSection(frames[2].Payload));
    }

    // THE FINGERPRINT PIN AT THE ENCODER. An empty body must emit NO DATA frame - not a DATA
    // frame of length zero, which is two bytes (type 0x00, length 0x00) that would show up in
    // every h3 request this library ever sends and that no capture in this repository records.
    // Byte equality against the pre-body encoder's output is the strongest form of this: a
    // count assertion would pass against an encoder that appended an empty DATA frame and
    // dropped something else.
    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    public void ARequestWithNoBodyEmitsNoDataFrameAtAll(string method)
    {
        var spec = new TlsQuicHttp3Spec();
        var request = new TlsQuicHttp3Request
        {
            Method = method,
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
        };

        var withDefaultedBody = Encode(request, spec);
        var withExplicitlyEmptyBody = Encode(
            new TlsQuicHttp3Request
            {
                Method = method,
                Authority = CaptureAuthority,
                Scheme = "https",
                Path = CapturePath,
                Body = [],
                Trailers = [],
            },
            spec);

        Assert.Equal(withDefaultedBody, withExplicitlyEmptyBody);
        Assert.Equal(
            [(ulong)TlsQuicHttp3FrameType.Headers],
            ReadFrames(withDefaultedBody).Select(frame => frame.Type).ToArray());
    }

    // A default-valued ImmutableArray is a null reference wearing a struct, and both new
    // properties are structs a caller can leave in that state through `default`. Neither may
    // throw; both read as empty.
    [Fact]
    public void ADefaultValuedBodyAndTrailerArrayEncodeAsAbsentRatherThanThrowing()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Body = default,
            Trailers = default,
        };

        Assert.Equal(
            [(ulong)TlsQuicHttp3FrameType.Headers],
            ReadFrames(Encode(request, new TlsQuicHttp3Spec()))
                .Select(frame => frame.Type)
                .ToArray());
    }

    // s4.1.2: "A request or response that is defined as having content when it contains a
    // Content-Length header field ... is malformed if the value of the Content-Length header
    // field does not equal the sum of the DATA frame lengths received."
    //
    // THE SUM IS THE BODY'S LENGTH, so every row here is decidable before a byte is sent. The
    // "5"/5 and "0"/0 rows are the agreements; the rest are the ways the two can disagree,
    // including a value that is not a count at all.
    [Theory]
    [InlineData("5", 5, true)]
    [InlineData("0", 0, true)]
    [InlineData("5", 4, false)]
    [InlineData("5", 0, false)]
    [InlineData("0", 5, false)]
    [InlineData("", 0, false)]
    [InlineData("+5", 5, false)]
    [InlineData("-5", 0, false)]
    [InlineData(" 5", 5, false)]
    [InlineData("five", 5, false)]
    public void AContentLengthMustDescribeTheBodyOrTheRequestIsRefused(
        string declared, int bodyLength, bool accepted)
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "POST",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = [new TlsQuicHttp3Field("content-length", declared)],
            Body = [.. new byte[bodyLength]],
        };

        var destination = new List<byte>();
        Assert.Equal(
            accepted, request.TryEncode(destination, new TlsQuicHttp3Spec(), out var error));
        Assert.Equal(
            accepted
                ? TlsQuicHttp3RequestError.None
                : TlsQuicHttp3RequestError.ContentLengthDisagreesWithBody,
            error);

        // "NOTHING IS APPENDED WHEN THIS RETURNS false" is TryEncode's own contract, and a
        // check that ran after the HEADERS frame was written would break it silently.
        Assert.Equal(accepted, destination.Count != 0);
    }

    // EVERY content-length, NOT THE FIRST. s4.1.2 says "the Content-Length header field" in the
    // singular and nothing upstream enforces the singular, so a request carrying two is
    // expressible - and a check that stopped at the first would send this one.
    [Fact]
    public void ASecondContentLengthThatDisagreesIsStillCaught()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "POST",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields =
            [
                new TlsQuicHttp3Field("content-length", "4"),
                new TlsQuicHttp3Field("content-length", "9"),
            ],
            Body = [.. new byte[4]],
        };

        Assert.False(request.TryEncode([], new TlsQuicHttp3Spec(), out var error));
        Assert.Equal(TlsQuicHttp3RequestError.ContentLengthDisagreesWithBody, error);
    }

    // s4.1.2 makes the rule conditional on the field being PRESENT. A body with no
    // content-length is not malformed by this sentence and must still encode - HTTP/3 has no
    // transfer-encoding to declare instead ("the Transfer-Encoding header field MUST NOT be
    // used"), so the stream's FIN is what bounds it.
    [Fact]
    public void ABodyWithNoContentLengthAtAllIsStillSent()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "POST",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Body = [1, 2, 3],
        };

        var frames = ReadFrames(Encode(request, new TlsQuicHttp3Spec()));
        Assert.Equal((ulong)TlsQuicHttp3FrameType.Data, frames[1].Type);
        Assert.Equal([1, 2, 3], frames[1].Payload);
    }

    // s4.3: "Pseudo-header fields MUST NOT appear in trailer sections." A DIFFERENT SENTENCE
    // from the ordering rule that governs Fields, so a different error - and the two are
    // asserted side by side here, because a shared member would let this test pass while
    // telling a caller the wrong section was at fault.
    [Fact]
    public void APseudoHeaderInTheTrailerSectionNamesTheTrailerRule()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "POST",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Body = [1],
            Trailers = [new TlsQuicHttp3Field(":status", "200")],
        };

        Assert.False(request.TryEncode([], new TlsQuicHttp3Spec(), out var error));
        Assert.Equal(TlsQuicHttp3RequestError.PseudoHeaderInTrailerSection, error);

        var inTheHeaderSection = new TlsQuicHttp3Request
        {
            Method = "POST",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = [new TlsQuicHttp3Field(":status", "200")],
            Body = [1],
        };

        Assert.False(
            inTheHeaderSection.TryEncode(
                [], new TlsQuicHttp3Spec(), out var headerError));
        Assert.Equal(
            TlsQuicHttp3RequestError.PseudoHeaderAmongRegularFields, headerError);
    }

    // s4.2 governs "an HTTP/3 field section" and a trailer section is one, so its uppercase
    // rule and its connection-specific ban reach the trailers UNCHANGED - which is the whole
    // argument for reusing the validator rather than writing a second one. A trailer arm that
    // skipped these would emit bytes s4.2 calls malformed.
    //
    // THE EXPECTED MEMBER IS PASSED AS ITS ORDINAL because the enum is internal and an xUnit
    // theory method must be public; the cast back below is what makes the comparison the enum's
    // and not an int's.
    [Theory]
    [InlineData("X-Trace", "1", (int)TlsQuicHttp3RequestError.RegularFieldNameNotLowercase)]
    [InlineData("", "1", (int)TlsQuicHttp3RequestError.RegularFieldNameEmpty)]
    [InlineData("upgrade", "h2c", (int)TlsQuicHttp3RequestError.ConnectionSpecificField)]
    [InlineData("te", "gzip", (int)TlsQuicHttp3RequestError.ConnectionSpecificField)]
    public void TheTrailerSectionObeysTheSameFieldRulesAsTheHeaderSection(
        string name, string value, int expectedError)
    {
        var expected = (TlsQuicHttp3RequestError)expectedError;
        var request = new TlsQuicHttp3Request
        {
            Method = "POST",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Body = [1],
            Trailers = [new TlsQuicHttp3Field(name, value)],
        };

        var destination = new List<byte>();
        Assert.False(request.TryEncode(destination, new TlsQuicHttp3Spec(), out var error));
        Assert.Equal(expected, error);
        Assert.Empty(destination);
    }

    // s4.1's item 3 is optional and its item 2 is separately optional, so a trailer section
    // with no content in front of it is a legal message and must not grow a DATA frame to
    // justify itself.
    [Fact]
    public void TrailersWithNoBodyEmitTwoHeadersFramesAndNoData()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "POST",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Trailers = [new TlsQuicHttp3Field("x-checksum", "00")],
        };

        Assert.Equal(
            [(ulong)TlsQuicHttp3FrameType.Headers, (ulong)TlsQuicHttp3FrameType.Headers],
            ReadFrames(Encode(request, new TlsQuicHttp3Spec()))
                .Select(frame => frame.Type)
                .ToArray());
    }

    // s7.2.8's reserved frame keeps its place at the FRONT when a body follows. Its position is
    // this project's declared placeholder (see ReservedRequestStreamFrameType), and a body path
    // that appended frames without regard to it could easily have put DATA before HEADERS -
    // which s4.1 makes "a connection error of type H3_FRAME_UNEXPECTED" in as many words: "a
    // DATA frame before any HEADERS frame ... is considered invalid".
    [Fact]
    public void TheReservedFrameStillLeadsWhenABodyAndTrailersFollow()
    {
        var request = new TlsQuicHttp3Request
        {
            Method = "POST",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Body = [7],
            Trailers = [new TlsQuicHttp3Field("x-checksum", "07")],
        };

        var frames = ReadFrames(
            Encode(request, new TlsQuicHttp3Spec { SendReservedFramesOnRequestStreams = true }));

        Assert.Equal(
            [
                TlsQuicHttp3Request.ReservedRequestStreamFrameType,
                (ulong)TlsQuicHttp3FrameType.Headers,
                (ulong)TlsQuicHttp3FrameType.Data,
                (ulong)TlsQuicHttp3FrameType.Headers,
            ],
            frames.Select(frame => frame.Type).ToArray());
    }

    // A body big enough that its s7.1 Length needs a two-byte QUIC varint rather than a
    // one-byte one, so the frame writer's own length encoding is exercised by the read-back
    // rather than assumed. 64 is the one-byte varint's ceiling (RFC 9000 s16), and 8192 is well
    // past it.
    [Fact]
    public void ALargeBodyRoundTripsThroughTheFrameParserByteForByte()
    {
        var body = new byte[8192];
        for (var i = 0; i < body.Length; i++)
        {
            body[i] = (byte)(i * 31);
        }

        var request = new TlsQuicHttp3Request
        {
            Method = "POST",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = [new TlsQuicHttp3Field("content-length", "8192")],
            Body = [.. body],
        };

        var frames = ReadFrames(Encode(request, new TlsQuicHttp3Spec()));
        Assert.Equal(2, frames.Count);
        Assert.Equal((ulong)TlsQuicHttp3FrameType.Data, frames[1].Type);
        Assert.Equal(body, frames[1].Payload);
    }

    private static List<byte> Encode(TlsQuicHttp3Request request, TlsQuicHttp3Spec spec)
    {
        var destination = new List<byte>();
        Assert.True(request.TryEncode(destination, spec, out var error));
        Assert.Equal(TlsQuicHttp3RequestError.None, error);
        return destination;
    }

    private static void AssertRefused(
        ImmutableArray<TlsQuicHttp3Field> fields, TlsQuicHttp3RequestError expected)
    {
        var destination = new List<byte>();
        var request = new TlsQuicHttp3Request
        {
            Method = "GET",
            Authority = CaptureAuthority,
            Scheme = "https",
            Path = CapturePath,
            Fields = fields,
        };

        Assert.False(request.TryEncode(destination, new TlsQuicHttp3Spec(), out var error));
        Assert.Equal(expected, error);
        Assert.Empty(destination);
    }

    // Every frame in the buffer, read back through the C2 codec rather than by slicing at
    // offsets this file computed.
    private static List<(ulong Type, byte[] Payload)> ReadFrames(List<byte> encoded)
    {
        var bytes = encoded.ToArray();
        var frames = new List<(ulong, byte[])>();
        var offset = 0;

        while (offset < bytes.Length)
        {
            var status = TlsQuicHttp3Frames.TryRead(
                bytes, ref offset, out var type, out var payload, out var error);
            Assert.Equal(TlsQuicHttp3FrameReadStatus.Complete, status);
            Assert.Equal(TlsQuicHttp3ErrorCode.None, error);
            frames.Add((type, payload.ToArray()));
        }

        return frames;
    }

    // Task C8's decoder, which is what makes every order claim here a read-back rather than a
    // restatement of the encoder's input.
    private static List<(string Name, string Value)> DecodeFieldSection(byte[] section)
    {
        var buffer = new byte[64 * 1024];
        var lines = new TlsQuicQpackDecodedFieldLine[64];

        Assert.True(
            TlsQuicQpackDecoder.TryDecodeFieldSection(
                section, buffer, lines, long.MaxValue, out int count, out _, out var error));
        Assert.Equal(TlsQuicQpackError.None, error);

        var decoded = new List<(string, string)>(count);
        for (var i = 0; i < count; i++)
        {
            decoded.Add((
                Encoding.UTF8.GetString(buffer, lines[i].NameOffset, lines[i].NameLength),
                Encoding.UTF8.GetString(buffer, lines[i].ValueOffset, lines[i].ValueLength)));
        }

        return decoded;
    }

    private static string NameOf(TlsQuicHttp3PseudoHeader pseudoHeader) => pseudoHeader switch
    {
        TlsQuicHttp3PseudoHeader.Method => ":method",
        TlsQuicHttp3PseudoHeader.Authority => ":authority",
        TlsQuicHttp3PseudoHeader.Scheme => ":scheme",
        _ => ":path",
    };

    // Heap's algorithm would be shorter; this is the recursive one because it is the one a
    // reader can check by eye, and 24 permutations of a four-element list is not a place to
    // be clever.
    private static IEnumerable<List<TlsQuicHttp3PseudoHeader>> Permutations(
        List<TlsQuicHttp3PseudoHeader> items)
    {
        if (items.Count <= 1)
        {
            yield return items;
            yield break;
        }

        for (var i = 0; i < items.Count; i++)
        {
            var rest = new List<TlsQuicHttp3PseudoHeader>(items);
            rest.RemoveAt(i);
            foreach (var tail in Permutations(rest))
            {
                yield return [items[i], .. tail];
            }
        }
    }

    // ==================================================================
    // Task C10: RFC 9114 s4.1's response.
    // ==================================================================
    //
    // THE BODY IS COMPARED BYTE FOR BYTE AND THE FIELDS ARE COMPARED AFTER A REAL DECODE.
    // Every scripted response below is built with TlsQuicHttp3Frames.Write and
    // TlsQuicQpackEncoder - the same two writers a server would use - rather than with hand
    // counted offsets, so a test that passes says the reader agrees with the codec and not
    // that it agrees with this file's arithmetic.
    //
    // s8.1's H3_FRAME_UNEXPECTED is spelled through the enum member at every use, never as
    // 0x0105, so no expectation here is a second transcription of the s8 extract.

    private static readonly byte[] FirstBodyPart = Encoding.UTF8.GetBytes("{\"protocol\": \"htt");
    private static readonly byte[] SecondBodyPart = Encoding.UTF8.GetBytes("p3\", \"ok\": true}");

    private const ulong FrameUnexpected = (ulong)TlsQuicHttp3ErrorCode.H3FrameUnexpected;
    private const ulong IdError = (ulong)TlsQuicHttp3ErrorCode.H3IdError;
    private const ulong FrameError = (ulong)TlsQuicHttp3ErrorCode.H3FrameError;

    // C10b's code, spelled through the enum member for the same reason: 0x010e appears nowhere
    // in this file, so no expectation here is a second transcription of the s8 extract.
    private const ulong MessageError = (ulong)TlsQuicHttp3ErrorCode.H3MessageError;

    // ------------------------------------------------------------------
    // The done-when itself: HEADERS, two DATA frames, FIN.
    // ------------------------------------------------------------------

    [Fact]
    public void AResponseOfHeadersAndTwoDataFramesYieldsTheConcatenatedBody()
    {
        var response = ReadWhole(OkWithTwoDataFrames());

        Assert.True(response.IsComplete);
        Assert.Equal(200, response.Status);

        // s7.2.1's "arbitrary, variable-length sequences of bytes", concatenated in order and
        // compared as bytes rather than as a decoded string - a string comparison would hide a
        // UTF-8 replacement character where a byte went missing.
        byte[] expected = [.. FirstBodyPart, .. SecondBodyPart];
        Assert.Equal(expected, response.Body.ToArray());

        Assert.Equal(
            [(":status", "200"), ("content-type", "application/json")],
            Pairs(response.HeaderFields));
        Assert.Empty(response.TrailerFields);
        Assert.Empty(response.InterimHeaderSections);
    }

    // ------------------------------------------------------------------
    // s4.1's three named invalid sequences, one witness each.
    // ------------------------------------------------------------------

    // "a DATA frame before any HEADERS frame".
    [Fact]
    public void ADataFrameBeforeAnyHeadersFrameIsRefused() =>
        Assert.Equal(
            FrameUnexpected,
            Refuse(Script(
                (Data, FirstBodyPart),
                (Headers, EncodeSection((":status", "200"))))));

    // "a HEADERS ... frame after the trailing HEADERS frame".
    [Fact]
    public void AHeadersFrameAfterTheTrailingHeadersFrameIsRefused() =>
        Assert.Equal(
            FrameUnexpected,
            Refuse(Script(
                (Headers, EncodeSection((":status", "200"))),
                (Data, FirstBodyPart),
                (Headers, EncodeSection(("grpc-status", "0"))),
                (Headers, EncodeSection(("x-late", "1"))))));

    // "a ... DATA frame after the trailing HEADERS frame".
    [Fact]
    public void ADataFrameAfterTheTrailingHeadersFrameIsRefused() =>
        Assert.Equal(
            FrameUnexpected,
            Refuse(Script(
                (Headers, EncodeSection((":status", "200"))),
                (Data, FirstBodyPart),
                (Headers, EncodeSection(("grpc-status", "0"))),
                (Data, SecondBodyPart))));

    // NOT ONE OF THE THREE, and the source says so. s4.1's list is introduced with "In
    // particular", so it is examples of an "invalid sequence of frames" rather than the whole
    // set, and s4.1's own "Interim responses do not contain content or trailer sections" makes
    // this one. The witness is here rather than folded into the three above because a reader
    // checking the RFC will not find this case in the list.
    [Fact]
    public void ADataFrameAfterOnlyAnInterimResponseIsRefused() =>
        Assert.Equal(
            FrameUnexpected,
            Refuse(Script(
                (Headers, EncodeSection((":status", "103"), ("link", "</s.css>"))),
                (Data, FirstBodyPart))));

    // ------------------------------------------------------------------
    // s4.1 and s9: other frame types, interleaved.
    // ------------------------------------------------------------------

    [Fact]
    public void AnUnknownFrameTypeBetweenTheHeadersAndTheDataIsSkipped()
    {
        // 0x21 is s7.2.8's first reserved frame type and 0x1f4a is simply not assigned. s4.1:
        // "Frames of unknown types (Section 9), including reserved frames (Section 7.2.8) MAY
        // be sent on a request or push stream before, after, or interleaved with other frames".
        var response = ReadWhole(Script(
            (Headers, EncodeSection((":status", "200"))),
            (TlsQuicHttp3Frames.ReservedIdentifier(0), Encoding.UTF8.GetBytes("padding")),
            (0x1f4a, []),
            (Data, FirstBodyPart),
            (TlsQuicHttp3Frames.ReservedIdentifier(7), []),
            (Data, SecondBodyPart)));

        byte[] expected = [.. FirstBodyPart, .. SecondBodyPart];
        Assert.Equal(expected, response.Body.ToArray());
        Assert.Equal(200, response.Status);
        Assert.True(response.IsComplete);
    }

    // s7.2.5: "A client MUST treat receipt of a PUSH_PROMISE frame that contains a larger push
    // ID than the client has advertised as a connection error of H3_ID_ERROR."
    //
    // THIS TEST EXISTS BECAUSE THE INVERSION IS EASY TO GET BACKWARDS. s7.2.5 does permit
    // PUSH_PROMISE on a request stream, and s4.1 does say "These PUSH_PROMISE frames are not
    // part of the response" - which is why this frame was once skipped. But this client never
    // sends MAX_PUSH_ID, so the advertised maximum does not exist and push ID 0 is already
    // larger than it. Server push being unimplemented is what MAKES the rule bind, not what
    // excuses it.
    //
    // Push ID 0 is deliberate: the smallest legal value still fails, so no reader can conclude
    // the check is a bound on how large the identifier may grow.
    [Fact]
    public void APushPromiseFrameIsIdErrorBecauseNoPushIdWasEverAdvertised() =>
        Assert.Equal(
            IdError,
            Refuse(Script(
                (Headers, EncodeSection((":status", "200"))),
                ((ulong)TlsQuicHttp3FrameType.PushPromise,
                    [0x00, .. EncodeSection((":method", "GET"))]),
                (Data, FirstBodyPart))));

    // s7.2.5 gives PUSH_PROMISE a "Push ID (i)" field, so an empty payload has no push ID to
    // find too large. That is malformed framing - H3_FRAME_ERROR - and the ORDER matters: the
    // varint is read before the comparison, or every truncated PUSH_PROMISE would be reported
    // as an identifier problem it does not have.
    [Fact]
    public void APushPromiseFrameWithNoReadablePushIdIsFrameError() =>
        Assert.Equal(
            FrameError,
            Refuse(Script(
                (Headers, EncodeSection((":status", "200"))),
                ((ulong)TlsQuicHttp3FrameType.PushPromise, []),
                (Data, FirstBodyPart))));

    // The s7 Table 1 "No" column for request streams. Each subsection states it separately -
    // s7.2.3, s7.2.4, s7.2.6, s7.2.7 - and all four say H3_FRAME_UNEXPECTED. Without this the
    // default arm would swallow them as though they were s9 unknowns, which they are not.
    [Theory]
    [InlineData((ulong)TlsQuicHttp3FrameType.CancelPush)]
    [InlineData((ulong)TlsQuicHttp3FrameType.Settings)]
    [InlineData((ulong)TlsQuicHttp3FrameType.Goaway)]
    [InlineData((ulong)TlsQuicHttp3FrameType.MaxPushId)]
    public void AControlStreamOnlyFrameIsRefusedOnARequestStream(ulong frameType) =>
        Assert.Equal(
            FrameUnexpected,
            Refuse(Script(
                (Headers, EncodeSection((":status", "200"))),
                (frameType, [0x00]),
                (Data, FirstBodyPart))));

    // s7.2.8's HTTP/2-inherited reserved types. Refused by TlsQuicHttp3Frames.TryRead rather
    // than by this reader - the point of the test is that the codec's code is PROPAGATED and
    // not overwritten by the reader's own idea of what an unknown type is.
    [Fact]
    public void AnHttp2ReservedFrameTypeIsRefusedWithTheCodecsCode() =>
        Assert.Equal(
            FrameUnexpected,
            Refuse(Script(
                (Headers, EncodeSection((":status", "200"))),
                (0x02, []))));

    // ------------------------------------------------------------------
    // s7: "HTTP/3 frames can span multiple packets".
    // ------------------------------------------------------------------

    [Fact]
    public void ADataFrameSplitAcrossTwoStreamFramesReassembles()
    {
        var script = OkWithTwoDataFrames().ToArray();

        // A cut inside the FIRST DATA frame's payload: past the HEADERS frame and past the
        // DATA frame's own type and length octets, so the reader is holding a frame it has
        // measured but cannot yet complete.
        var cut = script.Length - SecondBodyPart.Length - FirstBodyPart.Length + 3;

        var response = new TlsQuicHttp3Response();
        Assert.True(response.TryRead(script.AsSpan(0, cut), endOfStream: false, out var error));
        Assert.Equal(0ul, error);
        Assert.False(response.IsComplete);

        Assert.True(response.TryRead(script.AsSpan(cut), endOfStream: true, out error));
        Assert.Equal(0ul, error);

        byte[] expected = [.. FirstBodyPart, .. SecondBodyPart];
        Assert.Equal(expected, response.Body.ToArray());
        Assert.True(response.IsComplete);
    }

    // THE PREVIOUS TEST WITH ITS ONE CHOSEN CUT REPLACED BY ALL OF THEM. A reassembler can be
    // right at one boundary and wrong at the boundary inside a length varint or between a
    // frame's last byte and the next frame's first; there is no reason to pick one and hope.
    [Fact]
    public void EveryPossibleSplitPointYieldsTheSameResponse()
    {
        var script = OkWithTwoDataFrames().ToArray();
        byte[] expected = [.. FirstBodyPart, .. SecondBodyPart];

        for (var cut = 0; cut <= script.Length; cut++)
        {
            var response = new TlsQuicHttp3Response();
            Assert.True(
                response.TryRead(script.AsSpan(0, cut), endOfStream: false, out var error),
                $"cut {cut} refused the first half with {error}");
            Assert.True(
                response.TryRead(script.AsSpan(cut), endOfStream: true, out error),
                $"cut {cut} refused the second half with {error}");

            Assert.Equal(expected, response.Body.ToArray());
            Assert.Equal(200, response.Status);
            Assert.True(response.IsComplete);
        }
    }

    // One byte at a time, which is the degenerate case of the above and the one a QUIC stream
    // can genuinely produce when a response is spread across many small STREAM frames.
    [Fact]
    public void AResponseDeliveredOneByteAtATimeReadsTheSame()
    {
        var script = OkWithTwoDataFrames().ToArray();
        var response = new TlsQuicHttp3Response();

        for (var i = 0; i < script.Length; i++)
        {
            Assert.True(
                response.TryRead(script.AsSpan(i, 1), endOfStream: false, out var error),
                $"byte {i} refused with {error}");
        }

        Assert.True(response.TryRead([], endOfStream: true, out _));

        byte[] expected = [.. FirstBodyPart, .. SecondBodyPart];
        Assert.Equal(expected, response.Body.ToArray());
        Assert.True(response.IsComplete);
    }

    // ------------------------------------------------------------------
    // s4.1's interim responses and s4.1's item 3, the trailer section.
    // ------------------------------------------------------------------

    [Fact]
    public void InterimResponsesPrecedingTheFinalOneAreToleratedAndKept()
    {
        var response = ReadWhole(Script(
            (Headers, EncodeSection((":status", "103"), ("link", "</s.css>"))),
            (Headers, EncodeSection((":status", "100"))),
            (Headers, EncodeSection((":status", "200"), ("content-type", "application/json"))),
            (Data, FirstBodyPart)));

        // The final response is the one that lands in Status and HeaderFields; the interim
        // ones are neither discarded nor mistaken for it.
        Assert.Equal(200, response.Status);
        Assert.Equal(
            [(":status", "200"), ("content-type", "application/json")],
            Pairs(response.HeaderFields));

        Assert.Equal(2, response.InterimHeaderSections.Count);
        Assert.Equal(
            [(":status", "103"), ("link", "</s.css>")],
            Pairs(response.InterimHeaderSections[0]));
        Assert.Equal([(":status", "100")], Pairs(response.InterimHeaderSections[1]));

        Assert.Equal(FirstBodyPart, response.Body.ToArray());
        Assert.True(response.IsComplete);
    }

    // s4.1's "(1xx)" is the whole of the interim rule, so 199 is interim and 200 is not. The
    // boundary rows exist because an off-by-one at either end turns a final response into an
    // interim one, which loses the body silently rather than loudly.
    [Theory]
    [InlineData("100", true, -1)]
    [InlineData("103", true, -1)]
    [InlineData("199", true, -1)]
    [InlineData("200", false, 200)]
    [InlineData("204", false, 204)]
    [InlineData("500", false, 500)]
    public void OnlyA1xxStatusMakesAHeaderSectionInterim(
        string status, bool interim, int expectedStatus)
    {
        var response = ReadWhole(Script((Headers, EncodeSection((":status", status)))));

        Assert.Equal(interim ? 0 : 1, response.HeaderFields.Length);
        Assert.Equal(interim ? 1 : 0, response.InterimHeaderSections.Count);
        Assert.Equal(expectedStatus, response.Status);

        // s4.1: interim responses are "followed by a single final HTTP response", so a stream
        // that ended after one carries no complete message.
        Assert.Equal(!interim, response.IsComplete);
    }

    [Fact]
    public void TheHeadersFrameAfterTheFinalOneIsReadAsTheTrailerSection()
    {
        var response = ReadWhole(Script(
            (Headers, EncodeSection((":status", "200"))),
            (Data, FirstBodyPart),
            (Headers, EncodeSection(("grpc-status", "0"), ("grpc-message", "ok")))));

        Assert.Equal(
            [("grpc-status", "0"), ("grpc-message", "ok")], Pairs(response.TrailerFields));
        Assert.Equal([(":status", "200")], Pairs(response.HeaderFields));
        Assert.Equal(FirstBodyPart, response.Body.ToArray());
        Assert.True(response.IsComplete);
    }

    // POSITION AND NOT CONTENT decides. A 1xx after the final response is s4.1's "additional
    // HTTP response following a final HTTP response", which s4.1 makes MALFORMED rather than a
    // frame-sequence error - so it is not refused here, it is read as the trailer section its
    // position makes it. The alternative, treating it as a second interim, would let a server
    // reopen a finished message.
    [Fact]
    public void AOneHundredStatusAfterTheFinalResponseIsStillTheTrailerSection()
    {
        var response = ReadWhole(Script(
            (Headers, EncodeSection((":status", "200"))),
            (Headers, EncodeSection((":status", "100")))));

        Assert.Equal(200, response.Status);
        Assert.Equal([(":status", "100")], Pairs(response.TrailerFields));
        Assert.Empty(response.InterimHeaderSections);
    }

    // ------------------------------------------------------------------
    // s4.3.2's :status, and what its absence does. CHANGED BY C10b.
    // ------------------------------------------------------------------
    //
    // C10 wrote these two cases the other way round - Status -1 and TryRead answering true -
    // and said in as many words that it was pinning a limitation rather than a rule, because
    // TlsQuicHttp3ErrorCode had no H3_MESSAGE_ERROR member. It has one now, so s4.3.2's
    // "otherwise, the response is malformed" and s4.1.2's "Clients MUST NOT accept a malformed
    // response" are what these cases assert instead.

    // s4.3.2: ":status ... MUST be included in all responses; otherwise, the response is
    // malformed (see Section 4.1.2)". s4.1.2: "Malformed requests or responses that are
    // detected MUST be treated as a stream error of type H3_MESSAGE_ERROR."
    [Fact]
    public void AResponseWithoutAStatusIsRefusedAsAMessageError()
    {
        var refused = Refuse(Script(
            (Headers, EncodeSection(("content-type", "application/json"))),
            (Data, FirstBodyPart)));

        Assert.Equal(MessageError, refused);

        // NOT H3_FRAME_UNEXPECTED. The frame sequence here is perfectly legal - s4.1's item 1
        // then item 2 - and only the MESSAGE is malformed, so a mutant reporting this file's
        // other code would be reporting a sequence error that did not happen.
        Assert.NotEqual(FrameUnexpected, refused);
    }

    // s4.1.2's third bullet, "invalid values for pseudo-header fields", reached through the
    // same -1. NumberStyles.None is what makes " 200" and "+200" invalid values rather than
    // 200, and none of these throws - the refusal is a return value.
    [Theory]
    [InlineData("")]
    [InlineData(" 200")]
    [InlineData("200 ")]
    [InlineData("+200")]
    [InlineData("-200")]
    [InlineData("2e2")]
    [InlineData("two hundred")]
    [InlineData("99999999999999999999")]
    public void AStatusThatIsNotAPlainDecimalIsRefusedRatherThanThrowing(string status)
    {
        Assert.Equal(MessageError, Refuse(Script((Headers, EncodeSection((":status", status))))));
    }

    // THE CONVERSE, so the theory above is not passing because everything is refused. A plain
    // decimal outside every range anyone would call a status code is still a plain decimal, and
    // s4.3.2 bounds :status nowhere - it says only that the field "carries the HTTP status
    // code". Inventing a 100..599 range here would refuse a response the RFC permits.
    [Theory]
    [InlineData("0", 0)]
    [InlineData("007", 7)]
    [InlineData("200", 200)]
    [InlineData("599", 599)]
    [InlineData("999", 999)]
    public void APlainDecimalStatusIsAcceptedWhateverItsValue(string status, int expected)
    {
        var response = ReadWhole(Script((Headers, EncodeSection((":status", status)))));

        Assert.Equal(expected, response.Status);
        Assert.Equal([(":status", status)], Pairs(response.HeaderFields));
    }

    // ------------------------------------------------------------------
    // Task C10b: s4.1.2's Content-Length rule, and the sentence that bounds it.
    // ------------------------------------------------------------------
    //
    // The declared length in every case below is computed from the body parts rather than
    // typed, so a case cannot pass because two hand-counted numbers happen to agree.

    // s4.1.2: "A request or response that is defined as having content when it contains a
    // Content-Length header field ... is malformed if the value of the Content-Length header
    // field does not equal the sum of the DATA frame lengths received." The sum is across every
    // DATA frame, which is why the agreeing case is scripted with two of them.
    [Fact]
    public void AContentLengthEqualToTheSumOfTheDataFrameLengthsIsAccepted()
    {
        var total = FirstBodyPart.Length + SecondBodyPart.Length;
        var response = ReadWhole(Script(
            (Headers, EncodeSection((":status", "200"), ("content-length", $"{total}"))),
            (Data, FirstBodyPart),
            (Data, SecondBodyPart)));

        Assert.True(response.IsComplete);
        Assert.Equal(total, response.Body.Length);
    }

    // Both directions of "does not equal": short by one and long by one. An off-by-one is the
    // mismatch a >= or a <= would let through, and a test that only declared 0 against a real
    // body would pass against either.
    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    [InlineData(-17)]
    [InlineData(1000)]
    public void AContentLengthDisagreeingWithTheDataSumIsRefusedAsAMessageError(int delta)
    {
        var declared = FirstBodyPart.Length + SecondBodyPart.Length + delta;
        var refused = Refuse(Script(
            (Headers, EncodeSection((":status", "200"), ("content-length", $"{declared}"))),
            (Data, FirstBodyPart),
            (Data, SecondBodyPart)));

        Assert.Equal(MessageError, refused);
        Assert.NotEqual(FrameUnexpected, refused);
    }

    // The zero-length body case is the one place s6.4.1's set and the rule agree, so it is
    // pinned separately: content-length: 0 with no DATA is accepted whether or not the escape
    // applies, and a mutant that dropped the escape entirely would still pass this - which is
    // why the C10c cases below exist as well.
    [Fact]
    public void AZeroContentLengthWithNoDataFrameIsAccepted()
    {
        var response = ReadWhole(Script(
            (Headers, EncodeSection((":status", "204"), ("content-length", "0")))));

        Assert.True(response.IsComplete);
        Assert.Empty(response.Body.ToArray());
    }

    // s4.1.2's rule applied per field line rather than to the first one found. Two
    // content-length lines cannot both equal one sum, so a disagreeing pair is refused without
    // this file needing a duplicate-value rule of its own. RFC 9110 s8.6 is captured now and
    // offers none that would help: its one licence is for a comma-separated repeat of ONE value
    // inside a SINGLE field line, and it binds senders and forwarders rather than recipients.
    [Fact]
    public void TwoContentLengthFieldsThatDisagreeWithEachOtherAreRefused()
    {
        var refused = Refuse(Script(
            (Headers, EncodeSection(
                (":status", "200"),
                ("content-length", $"{FirstBodyPart.Length}"),
                ("content-length", $"{FirstBodyPart.Length + 1}"))),
            (Data, FirstBodyPart)));

        Assert.Equal(MessageError, refused);
    }

    // NO RULE INVENTED FOR A VALUE s4.1.2 DOES NOT DESCRIBE. "the value of the Content-Length
    // header field" is a number or the sentence does not apply; NumberStyles.None is what draws
    // that line, as it does for :status. These are not refused HERE - a receiver that wants to
    // refuse them is enforcing RFC 9110 s8.6's own ABNF, and s8.6, now captured, puts that duty
    // on senders and forwarders rather than on a recipient: "a sender MUST NOT forward a message
    // with a Content-Length header field value that does not match the ABNF above".
    //
    // THE DIGITS ARE DELIBERATELY NOT THE BODY'S LENGTH. FirstBodyPart happens to be 17 bytes,
    // so an earlier draft of these rows read " 17" and "+17" - and under the mutant that
    // relaxes NumberStyles.None to Integer those parse to exactly the right number, agree with
    // the sum and pass. Two of the six rows were witnessing nothing. A value that cannot equal
    // the body length is what makes every row of this theory carry its weight.
    [Theory]
    [InlineData("")]
    [InlineData(" 1")]
    [InlineData("+1")]
    [InlineData("-1")]
    [InlineData("0x11")]
    [InlineData("seventeen")]
    public void AnUnparsableContentLengthIsNotTreatedAsADisagreement(string declared)
    {
        var response = ReadWhole(Script(
            (Headers, EncodeSection((":status", "200"), ("content-length", declared))),
            (Data, FirstBodyPart)));

        Assert.True(response.IsComplete);
        Assert.Equal(FirstBodyPart, response.Body.ToArray());
    }

    // s4.2: an uppercase field name is not the field the RFC defines, so an Ordinal lookup is
    // the only correct one - the same contrast C10's row 41 draws for :status. Under
    // OrdinalIgnoreCase this response would be refused, and it is not.
    [Fact]
    public void AnUppercaseContentLengthNameIsNotReadAsTheContentLength()
    {
        var response = ReadWhole(Script(
            (Headers, EncodeSection((":status", "200"), ("Content-Length", "999999"))),
            (Data, FirstBodyPart)));

        Assert.True(response.IsComplete);
        Assert.Equal(FirstBodyPart, response.Body.ToArray());
    }

    // s4.1.2's subject is the message's Content-Length, which lives in the header section. A
    // content-length arriving in the TRAILER section is not it - RFC 9114 s4.1 item 3 is a
    // separate field section - so the check reads HeaderFields and not TrailerFields, and this
    // case is what would change if it ever read both.
    [Fact]
    public void AContentLengthInTheTrailerSectionIsNotTheMessagesContentLength()
    {
        var response = ReadWhole(Script(
            (Headers, EncodeSection((":status", "200"))),
            (Data, FirstBodyPart),
            (Headers, EncodeSection(("content-length", "999999")))));

        Assert.True(response.IsComplete);
        Assert.Equal(FirstBodyPart, response.Body.ToArray());
        Assert.Equal([("content-length", "999999")], Pairs(response.TrailerFields));
    }

    // s7.1's truncated-frame error OUTRANKS this one, and the order is the source's claim
    // rather than an accident: bytes that are not a whole frame have not been read at all, so
    // "the sum of the DATA frame lengths received" is not yet a quantity anything can disagree
    // with. Moving the Content-Length check above the leftover check is what this case refuses.
    //
    // THE SCRIPT HAS TO CARRY A COMPLETE DATA FRAME AS WELL AS A TRUNCATED ONE, and the first
    // draft of this case did not. With only a truncated DATA frame the body is empty, the
    // carve-out returns true whichever order the two checks run in, and the case passed against
    // the hoisted mutant - a false witness. One whole frame ahead of the truncated one is what
    // makes the two orders disagree.
    [Fact]
    public void AStreamEndingInsideAFrameIsAFrameErrorEvenWithAMismatchedContentLength()
    {
        var declared = FirstBodyPart.Length + SecondBodyPart.Length;
        var script = Script(
            (Headers, EncodeSection((":status", "200"), ("content-length", $"{declared}"))),
            (Data, FirstBodyPart),
            (Data, SecondBodyPart)).ToArray();

        var response = new TlsQuicHttp3Response();
        Assert.False(
            response.TryRead(script.AsSpan(0, script.Length - 4), endOfStream: true, out var error));

        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3FrameError, error);
        Assert.NotEqual(MessageError, error);
    }

    // The refusal is a return value and it sticks, like every other on this path.
    //
    // AND THE SECOND CALL CARRIES THE BYTES THAT WOULD FIX IT, which is the whole point. A
    // second EMPTY call proves nothing here: this refusal is re-derivable from state the reader
    // still holds, so a non-sticky implementation simply computes the same code again and
    // answers identically - the defect C10's row C10-5 records, in a new place. The bytes below
    // complete the declared content, so a reader that had not recorded the failure would accept
    // the very response it has already told its caller to reject.
    [Fact]
    public void AContentLengthRefusalIsNotRevivedByTheDataThatWouldHaveSatisfiedIt()
    {
        var declared = FirstBodyPart.Length + SecondBodyPart.Length;
        var head = Script(
            (Headers, EncodeSection((":status", "200"), ("content-length", $"{declared}"))),
            (Data, FirstBodyPart)).ToArray();
        var rest = Script((Data, SecondBodyPart)).ToArray();

        var response = new TlsQuicHttp3Response();
        Assert.False(response.TryRead(head, endOfStream: true, out var first));
        Assert.Equal(MessageError, first);

        Assert.False(response.TryRead(rest, endOfStream: true, out var second));
        Assert.Equal(first, second);
        Assert.False(response.IsComplete);
    }

    // ------------------------------------------------------------------
    // Task C10c: RFC 9110 s6.4.1's never-having-content set, all five cases.
    // ------------------------------------------------------------------
    //
    // C10b accepted EVERY zero-DATA response whatever it declared, because s6.4.1 was not among
    // this repository's captures and the set could not be written down. It is captured now, as
    // rfc9110-section6.4.1-content-semantics.txt, and it made the carve-out SMALLER rather than
    // larger. Its closing sentence is the one that decides these cases: "All other responses do
    // include content, although that content might be of zero length."
    //
    // s6.4.1 contains no MUST, SHOULD or MAY anywhere. It supplies the set; RFC 9114 s4.1.2
    // supplies the strength, and every refusal below is s4.1.2's H3_MESSAGE_ERROR.

    // THE CASE C10b GOT WRONG, and the reason this task exists. A 200 is not in s6.4.1's set,
    // so it is a response "defined as having content"; the sum of its DATA frame lengths is 0;
    // 0 does not equal 1234; s4.1.2 calls that malformed. This is the exact script C10b's
    // .ANonZeroContentLengthWithNoDataFrameAtAllIsNotRefused asserted an ACCEPTANCE for, which
    // is why that case is gone rather than added to.
    [Fact]
    public void ANonZeroContentLengthWithNoDataFrameAtAllIsRefusedAsAMessageError()
    {
        var refused = Refuse(Script(
            (Headers, EncodeSection((":status", "200"), ("content-length", "1234")))));

        Assert.Equal(MessageError, refused);

        // NOT H3_FRAME_UNEXPECTED: one HEADERS frame then a FIN is s4.1's item 1 and nothing
        // else, a perfectly legal frame sequence carrying a malformed MESSAGE.
        Assert.NotEqual(FrameUnexpected, refused);
    }

    // s6.4.1: "All 1xx (Informational), 204 (No Content), and 304 (Not Modified) responses do
    // not include content." 204 and 304 are decidable from :status alone. The declared length is
    // non-zero against an empty body, so a reader with no escape at all refuses both rows.
    [Theory]
    [InlineData("204")]
    [InlineData("304")]
    public void AStatusThatNeverHasContentMayDeclareAContentLengthItSendsNoDataFor(string status)
    {
        var response = ReadWhole(Script(
            (Headers, EncodeSection((":status", status), ("content-length", "1234")))));

        Assert.True(response.IsComplete);
        Assert.Empty(response.Body.ToArray());
    }

    // THE NEIGHBOURS OF BOTH, so the set cannot be read as a range. 203 and 205 bracket 204 and
    // 303 and 305 bracket 304, one on each side; "All other responses do include content" is
    // what refuses them. A `>= 204`, a `204..304` or an off-by-one written for either arm passes
    // the theory above and fails this one.
    [Theory]
    [InlineData("200")]
    [InlineData("203")]
    [InlineData("205")]
    [InlineData("303")]
    [InlineData("305")]
    [InlineData("404")]
    public void AStatusOutsideThatSetIsHeldToItsContentLength(string status)
    {
        Assert.Equal(
            MessageError,
            Refuse(Script(
                (Headers, EncodeSection((":status", status), ("content-length", "1234"))))));
    }

    // s6.4.1: "Responses to the HEAD request method (Section 9.3.2) never include content; the
    // associated response header fields indicate only what their values would have been if the
    // request method had been GET (Section 9.3.1)." So a HEAD response carries the Content-Length
    // a GET would have and sends no DATA, which is precisely s4.1.2's escape sentence.
    //
    // THIS IS THE ONE CASE THAT JUSTIFIES THE CONSTRUCTOR ARGUMENT. RFC 9110 s8.6 makes the
    // other four moot or decidable: a server MUST NOT send Content-Length in a 1xx, in a 204 or
    // in a 2xx to CONNECT, so on the wire only a HEAD response and a 304 may carry one - and 304
    // is a status. Without the method this response is refused, which would be every legal HEAD
    // response refused.
    [Fact]
    public void AHeadResponseMayDeclareAContentLengthItSendsNoDataFor()
    {
        var response = ReadWhole(
            Script((Headers, EncodeSection((":status", "200"), ("content-length", "1234")))),
            requestMethod: "HEAD");

        Assert.True(response.IsComplete);
        Assert.Equal(200, response.Status);
        Assert.Empty(response.Body.ToArray());
    }

    // THE CONSTRUCTOR'S OWN DEFAULT, WHICH NO OTHER CASE HERE REACHES, and this one was written
    // because the sweep found it unwitnessed. ReadWhole and Refuse pass requestMethod
    // EXPLICITLY - null is still an argument - so a default of "HEAD" in place of null would let
    // every response escape s4.1.2's rule and every other case in this section would still pass.
    // The default is not a formality either: TlsQuicHttp3Connection constructs this type with
    // the field-section limit alone, so what the default means IS what the connection does.
    [Fact]
    public void TheDefaultConstructorNamesNoMethodAndSoExcusesNoContentLength()
    {
        var response = new TlsQuicHttp3Response();

        Assert.False(response.TryRead(
            Script((Headers, EncodeSection((":status", "200"), ("content-length", "1234"))))
                .ToArray(),
            endOfStream: true,
            out var error));

        Assert.Equal(MessageError, error);
    }

    // Ordinal, which IsDefinedAsNeverHavingContent argues rather than defaults to: a request
    // whose :method read "head" is not a HEAD request to any server, so the escape must not
    // reach it. BOTH comparers are measured here - under OrdinalIgnoreCase the "head"/"Head"
    // rows escape through the HEAD arm and the "connect"/"Connect" rows escape through the
    // CONNECT arm, since the status below is a 2xx. The trailing-space rows fail under either
    // comparer and pin exact match rather than the comparer; "GET" and "POST" are the converse
    // the theory needs, an ordinary method escaping nothing. A null method, the default, is the
    // case above at .ANonZeroContentLengthWithNoDataFrameAtAllIsRefusedAsAMessageError.
    [Theory]
    [InlineData("head")]
    [InlineData("Head")]
    [InlineData("HEAD ")]
    [InlineData("connect")]
    [InlineData("Connect")]
    [InlineData("CONNECT ")]
    [InlineData("GET")]
    [InlineData("POST")]
    public void OnlyAMethodSpelledAsRfc9110SpellsItEscapesTheContentLengthRule(string method)
    {
        Assert.Equal(
            MessageError,
            Refuse(
                Script((Headers, EncodeSection((":status", "200"), ("content-length", "1234")))),
                requestMethod: method));
    }

    // s6.4.1: "2xx (Successful) responses to a CONNECT request method (Section 9.3.6) switch the
    // connection to tunnel mode instead of having content." 2xx AND NOT ANY STATUS - a CONNECT
    // that failed is an ordinary response with ordinary content - so the false rows sit beside
    // the true ones, 299/300 bracketing the top of the range and 0 sitting below its bottom.
    //
    // NOTHING THIS CLIENT SENDS REACHES THIS ARM: see THE CONNECT LIMITATION in the source,
    // which refuses every legal CONNECT request at the encoder. The arm is reachable only
    // through this argument, and it is written because s6.4.1 states the case, not because a
    // request here can produce it.
    [Theory]
    [InlineData("200", true)]
    [InlineData("299", true)]
    [InlineData("300", false)]
    [InlineData("0", false)]
    [InlineData("502", false)]
    public void OnlyATwoHundredLevelResponseToAConnectEscapesTheRule(string status, bool escapes)
    {
        var script = Script(
            (Headers, EncodeSection((":status", status), ("content-length", "1234"))));

        if (escapes)
        {
            Assert.True(ReadWhole(script, requestMethod: "CONNECT").IsComplete);
            return;
        }

        Assert.Equal(MessageError, Refuse(script, requestMethod: "CONNECT"));
    }

    // s6.4.1: "All 1xx (Informational), 204 (No Content), and 304 (Not Modified) responses do
    // not include content." THE 1xx CASE IS THE ONE A FOUR-CASE LIST DROPS, and it is also the
    // one this reader cannot be made to get wrong: TryAcceptHeaders routes every 100..199 field
    // section into InterimHeaderSections without advancing the stage, so a 1xx is never the
    // response whose Content-Length is checked and escapes by never arriving rather than by
    // IsDefinedAsNeverHavingContent's 1xx arm.
    //
    // SO THIS CASE SAYS WHAT IT DOES NOT WITNESS. It pins that a 103 declaring a content-length
    // is accepted - which is what s6.4.1 requires of it, and what a reader that applied the rule
    // to interim sections with a four-case set would break - but the 1xx ARM itself is
    // unreachable by construction, C10c's ledger records it as a survivor, and a case written to
    // "witness" it would pass against the four-case mutant too and be a false witness.
    //
    // RFC 9110 s8.6 says a server MUST NOT send this field in a 1xx at all, so this is a
    // response no conforming server writes - which is exactly why a client must not tear the
    // exchange down over it.
    [Fact]
    public void AnInterimResponseDeclaringAContentLengthIsNotRefused()
    {
        var response = ReadWhole(Script(
            (Headers, EncodeSection((":status", "103"), ("content-length", "1234"))),
            (Headers, EncodeSection((":status", "200")))));

        Assert.True(response.IsComplete);
        Assert.Equal(200, response.Status);
        Assert.Equal(
            [(":status", "103"), ("content-length", "1234")],
            Pairs(response.InterimHeaderSections[0]));
    }

    // BOTH HALVES OF s4.1.2's ESCAPE SENTENCE, and this is the half a reader drops: "...can have
    // a non-zero Content-Length header field even though NO CONTENT IS INCLUDED IN DATA FRAMES."
    // A response in s6.4.1's set that nonetheless carried DATA is not excused, because the
    // sentence licences the mismatch only where no content arrived. Refused on the method arm and
    // on the status arm both, so dropping the `_body.Count == 0` conjunct fails either way.
    [Theory]
    [InlineData("200", "HEAD")]
    [InlineData("304", null)]
    [InlineData("200", "CONNECT")]
    public void AResponseThatNeverHasContentIsStillHeldToItsLengthOnceDataArrives(
        string status, string? method)
    {
        var refused = Refuse(
            Script(
                (Headers, EncodeSection((":status", status), ("content-length", "1234"))),
                (Data, FirstBodyPart)),
            requestMethod: method);

        Assert.Equal(MessageError, refused);
    }

    // ------------------------------------------------------------------
    // Where the stream ends.
    // ------------------------------------------------------------------

    // s7.1: "a frame payload that terminates before the end of the identified fields MUST be
    // treated as a connection error of type H3_FRAME_ERROR". Before the FIN the same bytes are
    // Incomplete and not an error, which the split tests above already exercise.
    [Fact]
    public void AStreamThatEndsInsideAFrameIsAFrameError()
    {
        var script = OkWithTwoDataFrames().ToArray();
        var response = new TlsQuicHttp3Response();

        Assert.False(
            response.TryRead(script.AsSpan(0, script.Length - 4), endOfStream: true, out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3FrameError, error);
    }

    [Fact]
    public void BytesArrivingAfterTheStreamEndedAreRefused()
    {
        var response = ReadWhole(OkWithTwoDataFrames());

        // A second FIN carrying nothing is not a frame and is not refused - only bytes are.
        Assert.True(response.TryRead([], endOfStream: true, out var error));
        Assert.Equal(0ul, error);

        Assert.False(
            response.TryRead(
                Script((Headers, EncodeSection((":status", "200")))).ToArray(),
                endOfStream: true,
                out error));
        Assert.Equal(FrameUnexpected, error);
    }

    [Fact]
    public void AResponseWithNoDataFramesHasAnEmptyBody()
    {
        var response = ReadWhole(Script((Headers, EncodeSection((":status", "204")))));

        Assert.Empty(response.Body.ToArray());
        Assert.Equal(204, response.Status);
        Assert.True(response.IsComplete);
    }

    [Fact]
    public void AStreamThatCarriesNoFrameAtAllIsNotComplete()
    {
        var response = new TlsQuicHttp3Response();

        Assert.True(response.TryRead([], endOfStream: true, out var error));
        Assert.Equal(0ul, error);
        Assert.False(response.IsComplete);
    }

    // ------------------------------------------------------------------
    // The QPACK boundary, task C8's.
    // ------------------------------------------------------------------

    // A field section this decoder cannot read is RFC 9204's QPACK_DECOMPRESSION_FAILED and
    // not one of s8.1's codes. The expectation is read from the decoder itself rather than
    // written as 0x0200, so this test cannot disagree with C8 about the number.
    [Fact]
    public void AnUndecodableFieldSectionIsRefusedWithTheQpackCode()
    {
        // RFC 9204 s4.5.1's Required Insert Count is non-zero here, which this dynamic-table-
        // free decoder refuses - a field section that is well-formed as a FRAME and unreadable
        // as a SECTION, so the refusal can only have come from the decoder.
        var refused = Refuse(Script((Headers, [0x7f, 0x00])));

        Assert.True(
            TlsQuicQpackDecoder.TryGetHttp3ErrorCode(
                TlsQuicQpackError.RequiredInsertCountNotZero, out var expected));
        Assert.Equal(expected, refused);
        Assert.NotEqual(FrameUnexpected, refused);
    }

    // The doubling loop in TryDecodeFieldSection, witnessed the way C9 witnesses its own: with
    // a section that is larger than BOTH initial constants - more than 32 field lines and more
    // than 1024 decoded bytes - rather than by asserting either number.
    [Fact]
    public void AFieldSectionLargerThanTheInitialDecodeScratchStillDecodes()
    {
        var fields = new List<(string, string)> { (":status", "200") };
        for (var i = 0; i < 80; i++)
        {
            fields.Add(($"x-header-{i:D3}", new string((char)('a' + (i % 26)), 64)));
        }

        var response = ReadWhole(Script((Headers, EncodeSection([.. fields]))));

        Assert.Equal(200, response.Status);
        Assert.Equal(fields, Pairs(response.HeaderFields));
    }

    // s4.2.2's limit, which this type takes as a constructor argument because neither the
    // spec's settings list nor the peer's is reachable from here. The knob is honoured only if
    // setting it changes the answer, so both directions are read.
    [Fact]
    public void TheMaximumFieldSectionSizeIsHonoured()
    {
        var script = Script(
            (Headers, EncodeSection((":status", "200"), ("content-type", "application/json"))))
            .ToArray();

        var unlimited = new TlsQuicHttp3Response();
        Assert.True(unlimited.TryRead(script, endOfStream: true, out _));
        Assert.Equal(200, unlimited.Status);

        var limited = new TlsQuicHttp3Response(maximumFieldSectionSize: 8);
        Assert.False(limited.TryRead(script, endOfStream: true, out var error));

        Assert.True(
            TlsQuicQpackDecoder.TryGetHttp3ErrorCode(
                TlsQuicQpackError.FieldSectionTooLarge, out var expected));
        Assert.Equal(expected, error);
    }

    // ------------------------------------------------------------------
    // The buffering ceiling - audit finding #6's third buffer, and a fourth.
    // ------------------------------------------------------------------

    // WHAT HAPPENS AT THE BOUNDARY, IN BOTH DIRECTIONS, because the shipped default of 64 MiB
    // is a behaviour change for anyone fetching more than that and "refused, not truncated" is
    // the half a caller must be able to rely on. A reader that answered true with a short Body
    // would satisfy the over-the-line row alone; the under-the-line row is what says a response
    // exactly AT the ceiling is a complete response and not a near miss.
    //
    // THE CEILING IS CHARGED AGAINST WHAT IS RETAINED, WHICH IS WHY THE NUMBER IS THE BODY'S.
    // By the time TryRead returns, the DATA frame's own type and length octets have been parsed
    // and dropped; only the payload is still held. So a ceiling of 128 admits a 128-byte body
    // and refuses a 129-byte one, and the frame overhead does not enter into it.
    [Theory]
    [InlineData(128, true)]
    [InlineData(129, false)]
    public void AResponseIsRefusedOnlyOnceItsRetainedBytesPassTheCeiling(int bodyLength, bool accepted)
    {
        var script = Script(
            (Headers, EncodeSection((":status", "200"))),
            (Data, new byte[bodyLength]))
            .ToArray();

        var response = new TlsQuicHttp3Response(maximumBufferedBytes: 128);
        Assert.Equal(accepted, response.TryRead(script, endOfStream: true, out var error));

        if (accepted)
        {
            Assert.Equal(0ul, error);
            Assert.Equal(bodyLength, response.Body.Length);
            Assert.True(response.IsComplete);
        }
        else
        {
            Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3ExcessiveLoad, error);

            // THE REFUSAL IS STICKY, WHICH IS WHAT MAKES "refused, not truncated" TRUE FOR A
            // CALLER RATHER THAN ONLY FOR THIS CALL. A reader that answered false once and
            // then resumed would let a caller that pumped again read a Body it had already
            // been told not to trust. _errorCode is the same sticky slot every other s8.1
            // failure here uses, so the second answer carries the first code.
            Assert.False(response.TryRead([], endOfStream: true, out var again));
            Assert.Equal(error, again);
            Assert.False(response.IsComplete);
        }
    }

    // THE SHIPPED DEFAULT, WHICH THE THEORY ABOVE DELIBERATELY DOES NOT EXERCISE: it narrows
    // the ceiling to 128 so that the MECHANISM can be witnessed without allocating anything.
    // That leaves the number a caller actually gets unpinned, and the number is a behaviour
    // change - a response past it is refused. Pinned here rather than by a 64 MiB test, which
    // would be a test about allocation speed.
    //
    // TlsQuicHttp3ConnectionTests' AResponsePastTheSpecsCeilingIsExcessiveLoad is the other
    // half: it narrows MaximumBufferedResponseBytes on a SPEC and reads the refusal off a real
    // connection, so together the two say that TryOpenRequest hands the spec's value through
    // and that the spec's value defaults to this constant.
    [Fact]
    public void TheDefaultResponseCeilingIsTheSpecsShippedNumber()
    {
        Assert.Equal(
            TlsQuicHttp3Spec.DefaultMaximumBufferedResponseBytes,
            new TlsQuicHttp3Spec().MaximumBufferedResponseBytes);
        Assert.Equal(64 * 1024 * 1024, TlsQuicHttp3Spec.DefaultMaximumBufferedResponseBytes);
    }

    // The reader's own reset invariant, with no connection above it. RFC 9114 s4.1 makes a
    // response whose stream was reset a FAILED one rather than a short one, and this type is
    // driven directly by the fuzz targets and by this file - so the guarantee has to be the
    // reader's rather than TlsQuicHttp3Connection's sequencing.
    //
    // endOfStream IS PASSED TRUE ON PURPOSE, which is the pairing a connection no longer
    // produces: TlsQuicStream.ReceiveComplete stopped folding a reset in, so the two can only
    // meet here. A direct caller that has both facts must still not get a complete response.
    [Fact]
    public void AResetResponseIsNeverCompleteEvenAtEndOfStream()
    {
        var script = Script(
            (Headers, EncodeSection((":status", "200"))),
            (Data, Encoding.UTF8.GetBytes("half")))
            .ToArray();

        var response = new TlsQuicHttp3Response();
        Assert.True(response.OnPeerReset(0x010c));
        Assert.True(response.TryRead(script, endOfStream: true, out var error));

        Assert.Equal(0ul, error);
        Assert.False(response.IsComplete);
        Assert.True(response.IsReset);
        Assert.Equal(0x010cUL, response.ResetErrorCode);

        // s4.1's "begin processing partial HTTP messages once enough of the message has been
        // received to make progress" - what arrived is still read.
        //
        // THE RESET IS RECORDED FIRST HERE, WHICH IS THE ORDER A CONNECTION NEVER PRODUCES and
        // is deliberately the harder one: OnPeerReset releases the reader's buffers, so a body
        // read AFTER it accumulates in lists that were just trimmed. That is fine and is worth
        // pinning - the release is a one-shot reclaim of what a dead exchange was holding, not a
        // latch that makes the reader refuse to parse - and the ceiling still governs whatever
        // arrives next, because the check that enforces it runs per TryRead.

        Assert.Equal(200, response.Status);
        Assert.Equal("half", Encoding.UTF8.GetString(response.Body));

        // s19.4 admits one RESET_STREAM per stream, so the first code stands and the
        // once-per-stream gate one layer up answers false the second time - which also means
        // the buffer release cannot run twice and cannot discard a body read since.
        Assert.False(response.OnPeerReset(0x0100));
        Assert.Equal(0x010cUL, response.ResetErrorCode);
        Assert.Equal("half", Encoding.UTF8.GetString(response.Body));
    }

    // THE FOURTH BUFFER, WHICH THE AUDIT DID NOT NAME AND THE FIRST FIX ASSERTED AWAY. That
    // fix's comment claimed _pending and _body were "the only two lists here that a peer can
    // grow"; RFC 9114 s4.1 permits "zero or more interim HTTP responses" with no bound on the
    // count, and an interim section's bytes pass through _pending, are consumed, and never
    // reach _body - so neither of the two counted numbers moves while the reader grows.
    //
    // NOTHING HERE IS MALFORMED. Every 103 below is a legal interim response in a legal place;
    // s4.1 would let this stream run forever. The refusal is s8.1's excessive load and not
    // s4.1's malformed message, and the assertion on InterimHeaderSections is what says the
    // reader really was accumulating them rather than rejecting the second one on some other
    // rule.
    [Fact]
    public void AFloodOfInterimResponsesIsRefusedOnceItPassesTheCeiling()
    {
        // Each 103 costs its two fields' names and values plus s4.2.2's 32 bytes apiece, so a
        // handful clears a ceiling of 512 while no single one comes close to it.
        var interim = Script(
            (Headers, EncodeSection((":status", "103"), ("link", "</style.css>; rel=preload"))))
            .ToArray();

        var response = new TlsQuicHttp3Response(maximumBufferedBytes: 512);

        ulong error = 0;
        var refusedAt = -1;
        for (var i = 0; i < 64 && refusedAt < 0; i++)
        {
            if (!response.TryRead(interim, endOfStream: false, out error))
            {
                refusedAt = i;
            }
        }

        Assert.InRange(refusedAt, 1, 63);
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3ExcessiveLoad, error);

        // ONE MORE SECTION THAN THE CALL THAT REFUSED, and the off-by-one is the design rather
        // than a slip: the ceiling is measured AFTER the parse, so the section that crossed it
        // is kept and then the reader fails. Charging it before it was decoded would mean
        // guessing an uncompressed size from compressed bytes, which is the thing RFC 9204
        // s4.5's representations make impossible to do in advance.
        Assert.Equal(refusedAt + 1, response.InterimHeaderSections.Count);
    }

    // ------------------------------------------------------------------
    // The failure is sticky, and nothing throws.
    // ------------------------------------------------------------------

    [Fact]
    public void OnceRefusedTheReaderKeepsAnsweringWithTheSameCode()
    {
        var response = new TlsQuicHttp3Response();
        var refused = Script((Data, FirstBodyPart)).ToArray();

        Assert.False(response.TryRead(refused, endOfStream: false, out var first));
        Assert.Equal(FrameUnexpected, first);

        // A perfectly good response after the refusal does not resurrect it, and does not
        // change the code the caller is going to close the connection with.
        Assert.False(
            response.TryRead(OkWithTwoDataFrames().ToArray(), endOfStream: true, out var second));
        Assert.Equal(first, second);
        Assert.False(response.IsComplete);
    }

    // THE STICKY CHECK IS NOT REDUNDANT WITH THE STATE MACHINE, and this is the case that
    // shows it. In the test above, a reader that had dropped the check would re-derive the
    // same refusal from the same unconsumed bytes and look correct. s7.1's truncated frame is
    // different: it is detected AFTER _pending has been advanced past every whole frame, so
    // without the check the very next call completes the frame, answers true and quietly
    // revives a connection whose caller has already been told to close it.
    [Fact]
    public void AFrameErrorAtTheEndOfTheStreamIsNotRevivedByLaterBytes()
    {
        var script = OkWithTwoDataFrames().ToArray();
        var response = new TlsQuicHttp3Response();

        Assert.False(
            response.TryRead(script.AsSpan(0, script.Length - 4), endOfStream: true, out var first));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3FrameError, first);

        Assert.False(
            response.TryRead(script.AsSpan(script.Length - 4), endOfStream: true, out var second));
        Assert.Equal(first, second);
        Assert.False(response.IsComplete);
    }

    // THE DONE-WHEN SAYS PROVE IT, NOT ASSERT IT. Three families: every prefix of a real
    // response with and without the FIN, every single-byte corruption of one, and pseudo-random
    // noise from a fixed seed so a failure is reproducible. xUnit fails this test on any
    // exception, so the assertion is the absence of one.
    [Fact]
    public void NothingOnTheResponsePathThrowsForAnyInput()
    {
        var script = Script(
            (Headers, EncodeSection((":status", "103"))),
            (Headers, EncodeSection((":status", "200"), ("content-type", "application/json"))),
            (TlsQuicHttp3Frames.ReservedIdentifier(0), Encoding.UTF8.GetBytes("pad")),
            (Data, FirstBodyPart),
            (Data, SecondBodyPart),
            (Headers, EncodeSection(("grpc-status", "0")))).ToArray();

        // EVERY CASE TWICE, AND C16 ADDED THE SECOND RUN. A null table is C8's static-only
        // arm; a NON-NULL one reaches s2.2.1s block, s2.2.3s bound and every dynamic
        // resolution path, none of which the first run can enter at all. The table is rebuilt
        // per response so that one cases inserts cannot change what a later case decodes to -
        // which would make a failure depend on iteration order.
        foreach (var withTable in new[] { false, true })
        {
            for (var cut = 0; cut <= script.Length; cut++)
            {
                foreach (var fin in new[] { false, true })
                {
                    _ = Reader(withTable).TryRead(script.AsSpan(0, cut), fin, out _);
                }

                var halves = Reader(withTable);
                _ = halves.TryRead(script.AsSpan(0, cut), endOfStream: false, out _);
                _ = halves.TryRead(script.AsSpan(cut), endOfStream: true, out _);
            }

            foreach (var replacement in new byte[] { 0x00, 0x01, 0x02, 0x40, 0x7f, 0x80, 0xc0, 0xff })
            {
                for (var i = 0; i < script.Length; i++)
                {
                    var corrupted = (byte[])script.Clone();
                    corrupted[i] = replacement;
                    _ = Reader(withTable).TryRead(corrupted, endOfStream: true, out _);
                }
            }

            var random = new Random(20260820);
            for (var trial = 0; trial < 4000; trial++)
            {
                var noise = new byte[random.Next(0, 96)];
                random.NextBytes(noise);

                var response = Reader(withTable);
                _ = response.TryRead(noise, endOfStream: false, out _);
                _ = response.TryRead(noise, endOfStream: true, out _);

                // A blocked reader is re-presented, because that is what a connection does and
                // because re-presenting is the one call this task added that runs on bytes the
                // reader has already refused once.
                _ = response.TryRead([], endOfStream: true, out _);
            }
        }

        // Four entries so that both s3.2.5s relative arithmetic and s3.2.6s post-Base
        // arithmetic have somewhere to land, and so a random index is as likely to resolve as
        // to fail.
        static TlsQuicHttp3Response Reader(bool withTable) =>
            new(table: withTable ? TableWith(4) : null);
    }

    // THE POSITION CHECK RUNS BEFORE THE DECODE, and this is what says so. A HEADERS frame
    // after the trailers whose field section is ALSO unreadable must still be refused for
    // where it is: s4.1's invalid-sequence rule is what the connection error should name, not
    // the QPACK failure the reader would have hit a line later.
    [Fact]
    public void AnUndecodableHeadersFrameAfterTheTrailersIsRefusedForItsPositionFirst()
    {
        var refused = Refuse(Script(
            (Headers, EncodeSection((":status", "200"))),
            (Headers, EncodeSection(("grpc-status", "0"))),
            (Headers, [0x7f, 0x00])));

        Assert.Equal(FrameUnexpected, refused);
    }

    // s4.2: "A request or response containing uppercase characters in field names MUST be
    // treated as malformed." So ":STATUS" is not s4.3.2's pseudo-header and must not be read
    // as one - a case-insensitive lookup here would accept a field the RFC calls malformed and
    // would silently turn this response interim, losing its body.
    //
    // C10b MOVED THE OBSERVABLE AND KEPT THE PROPERTY. C10 read this as Status -1 with the
    // response accepted; now the same -1 is a refusal. The mutation the case exists for -
    // Ordinal weakened to OrdinalIgnoreCase - still changes the answer, and by more than
    // before: under the mutant ":STATUS: 103" is an INTERIM section, so the stream carries no
    // final response at all, TryRead answers true and nothing is refused.
    [Fact]
    public void AnUppercaseStatusNameIsNotReadAsTheStatus()
    {
        Assert.Equal(MessageError, Refuse(Script((Headers, EncodeSection((":STATUS", "103"))))));
    }

    // ------------------------------------------------------------------
    // Task C10 helpers.
    // ------------------------------------------------------------------

    private const ulong Data = (ulong)TlsQuicHttp3FrameType.Data;
    private const ulong Headers = (ulong)TlsQuicHttp3FrameType.Headers;

    private static List<byte> OkWithTwoDataFrames() => Script(
        (Headers, EncodeSection((":status", "200"), ("content-type", "application/json"))),
        (Data, FirstBodyPart),
        (Data, SecondBodyPart));

    // The frames a server would write, written by the same codec a server would use.
    private static List<byte> Script(params (ulong Type, byte[] Payload)[] frames)
    {
        var script = new List<byte>();
        foreach (var (type, payload) in frames)
        {
            TlsQuicHttp3Frames.Write(script, type, payload);
        }

        return script;
    }

    // Task C7's encoder, so a HEADERS payload here is a real RFC 9204 s4.5 field section and
    // not bytes this file believes decode to one.
    private static byte[] EncodeSection(params (string Name, string Value)[] fields)
    {
        var buffer = new byte[64 * 1024];
        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(buffer, out int offset));

        foreach (var (name, value) in fields)
        {
            Assert.True(
                TlsQuicQpackEncoder.TryEncodeFieldLine(
                    Encoding.UTF8.GetBytes(name),
                    Encoding.UTF8.GetBytes(value),
                    huffman: TlsQuicQpackHuffmanPolicy.Always,
                    preferNameReference: true,
                    buffer.AsSpan(offset),
                    out int count));
            offset += count;
        }

        return buffer[..offset];
    }

    // requestMethod defaults to null, which is what every case before C10c passes and what
    // TlsQuicHttp3Response reads as "neither a HEAD nor a CONNECT".
    private static TlsQuicHttp3Response ReadWhole(List<byte> script, string? requestMethod = null)
    {
        var response = new TlsQuicHttp3Response(requestMethod: requestMethod);
        Assert.True(response.TryRead(script.ToArray(), endOfStream: true, out var error));
        Assert.Equal(0ul, error);
        return response;
    }

    private static ulong Refuse(List<byte> script, string? requestMethod = null)
    {
        var response = new TlsQuicHttp3Response(requestMethod: requestMethod);
        Assert.False(response.TryRead(script.ToArray(), endOfStream: true, out var error));
        Assert.NotEqual(0ul, error);
        return error;
    }

    private static List<(string Name, string Value)> Pairs(
        IEnumerable<TlsQuicHttp3Field> fields)
    {
        var pairs = new List<(string, string)>();
        foreach (var field in fields)
        {
            pairs.Add((field.Name, field.Value));
        }

        return pairs;
    }

    // ========================================================================
    // C16 - RFC 9204 s2.2.1's blocked decoding, at the response reader
    // ========================================================================
    //
    // EVERY PREFIX BELOW IS HAND-DERIVED, NEVER ROUND-TRIPPED THROUGH THE ENCODER. C7's
    // encoder is static-only: it writes s4.5.1's prefix as two zero bytes and cannot produce a
    // non-zero Required Insert Count at all, so a test that asked it for one would be asking
    // the code under test to supply its own vector. s4.5.1.1's transform is
    // `EncInsertCount = (ReqInsertCount mod (2 * MaxEntries)) + 1`, and with the capture's
    // MaxTableCapacity of 65536 the extract's `MaxEntries = floor(65536 / 32)` is 2048, so
    // FullRange is 4096 and every Required Insert Count these tests use encodes as itself plus
    // one. See EncodedInsertCount, which asserts the range that makes that arithmetic hold.

    // s2.2.1, THE BOUNDARY, AND NO PUBLISHED VECTOR REACHES IT. Appendix B always feeds the
    // encoder stream before the field section, so every example there has an Insert Count
    // already at or above the Required Insert Count and none of them can tell "greater than"
    // from "greater than or equal". The RIC-1 row is the whole point: at Insert Count 1 a
    // section needing exactly 1 is processable "immediately" and MUST NOT block.
    [Theory]
    [InlineData(1u, false)]
    [InlineData(2u, true)]
    public void ASectionBlocksWhenItsRequiredInsertCountExceedsTheInsertCountAndNotWhenItEqualsIt(
        ulong requiredInsertCount, bool expectBlocked)
    {
        var table = TableWith(1);
        var response = new TlsQuicHttp3Response(table: table);

        Assert.True(response.TryRead(
            Script((Headers, DynamicSectionAt(requiredInsertCount))).ToArray(),
            endOfStream: false,
            out var error));

        Assert.Equal(0ul, error);
        Assert.Equal(expectBlocked, response.IsBlocked);
    }

    // THE ONE-LINE TEST THE PLAN CALLS #4, AND IT FAILED BEFORE THE FIX WENT IN. s2.2.1's
    // block is not a connection error, but TlsQuicQpackDecoder.TryGetHttp3ErrorCode writes
    // QPACK_DECOMPRESSION_FAILED into its out parameter unconditionally and answers false to
    // say "do not use this". A caller that discards that answer - which is what
    // TryDecodeFieldSection did - turns every blocked section into connection error 0x0200 and
    // closes a healthy connection over ordinary QUIC stream reordering, which is the exact
    // failure s2.1.2 exists to describe.
    [Fact]
    public void ABlockedSectionLeavesTheErrorCodeAtZeroRatherThanQpackDecompressionFailed()
    {
        var response = new TlsQuicHttp3Response(table: TableWith(1));

        Assert.True(response.TryRead(
            Script((Headers, DynamicSectionAt(2))).ToArray(), endOfStream: false, out var error));

        Assert.Equal(0ul, error);
        Assert.True(response.IsBlocked);
        Assert.Equal(2ul, response.BlockedRequiredInsertCount);

        // And nothing was committed: s2.2.1 decides from the prefix "upon receipt", before any
        // representation is read, so no field escaped and the stream did not advance a stage.
        Assert.Empty(response.HeaderFields);
        Assert.False(response.IsComplete);
    }

    // THE SAME BYTES DECODE ONCE THE TABLE CATCHES UP, and they are the same bytes: nothing is
    // handed over a second time. This is what "park by not advancing the offset" buys - the
    // blocked frame stayed in the reader's own _pending, and a read with an EMPTY span
    // re-presents it.
    [Fact]
    public void AParkedSectionDecodesOnTheNextReadOnceTheTableHasCaughtUp()
    {
        var table = TableWith(1);
        var response = new TlsQuicHttp3Response(table: table);

        Assert.True(response.TryRead(
            Script((Headers, StatusSectionAt(2))).ToArray(), endOfStream: false, out _));
        Assert.True(response.IsBlocked);

        InsertNumbered(table, 1, 1);

        Assert.True(response.TryRead([], endOfStream: false, out var error));
        Assert.Equal(0ul, error);
        Assert.False(response.IsBlocked);
        Assert.Equal(0ul, response.BlockedRequiredInsertCount);
        Assert.Equal(200, response.Status);
    }

    // AND THE FRAMES BEHIND IT WAIT THEIR TURN. s2.2.1 blocks the STREAM, not the frame: a
    // DATA frame that arrived in the same delivery as a parked HEADERS must not be read past
    // it, or a body would be assembled for a response whose header section is still unknown.
    [Fact]
    public void FramesBehindAParkedSectionAreNotReadPastIt()
    {
        var table = TableWith(1);
        var response = new TlsQuicHttp3Response(table: table);

        Assert.True(response.TryRead(
            Script(
                (Headers, StatusSectionAt(2)),
                (Data, "hello"u8.ToArray())).ToArray(),
            endOfStream: false,
            out _));
        Assert.True(response.IsBlocked);
        Assert.Empty(response.Body.ToArray());

        InsertNumbered(table, 1, 1);

        Assert.True(response.TryRead([], endOfStream: false, out _));
        Assert.False(response.IsBlocked);
        Assert.Equal(200, response.Status);
        Assert.Equal("hello", Encoding.UTF8.GetString(response.Body));
    }

    // s7.1's "a frame payload that terminates before the end of the identified fields MUST be
    // treated as a connection error of type H3_FRAME_ERROR" is about a frame no further byte
    // can complete. A PARKED one is not that: s2.1.2's whole premise is that the encoder
    // instructions travel on a different stream with no ordering guarantee, so a peer may
    // legally FIN its response stream while they are still in flight.
    [Fact]
    public void AFinWhileBlockedIsNotAFrameErrorAndTheResponseCompletesWhenItUnblocks()
    {
        var table = TableWith(1);
        var response = new TlsQuicHttp3Response(table: table);

        Assert.True(response.TryRead(
            Script((Headers, StatusSectionAt(2))).ToArray(), endOfStream: true, out var error));
        Assert.Equal(0ul, error);
        Assert.True(response.IsBlocked);
        Assert.False(response.IsComplete);

        InsertNumbered(table, 1, 1);

        Assert.True(response.TryRead([], endOfStream: true, out error));
        Assert.Equal(0ul, error);
        Assert.False(response.IsBlocked);
        Assert.True(response.IsComplete);
        Assert.Equal(200, response.Status);
    }

    // s2.2.2.1's MUST is per FIELD SECTION - "After the decoder finishes decoding a field
    // section encoded using representations containing dynamic table references, it MUST emit
    // a Section Acknowledgment instruction" - and s4.4.1 bounds it to a non-zero declared
    // count. A section decoded once must therefore appear here once however many times it is
    // re-presented, and a zero-count section must never appear at all.
    [Fact]
    public void EachDecodedSectionIsAcknowledgedOnceAndAZeroCountSectionNeverIs()
    {
        var table = TableWith(2);
        var response = new TlsQuicHttp3Response(table: table);

        // A blocked section contributes nothing, however many reads it sits through.
        Assert.True(response.TryRead(
            Script((Headers, StatusSectionAt(3))).ToArray(), endOfStream: false, out _));
        Assert.True(response.TryRead([], endOfStream: false, out _));
        Assert.True(response.TryRead([], endOfStream: false, out _));
        Assert.Empty(response.SectionAcknowledgments);

        InsertNumbered(table, 2, 1);
        Assert.True(response.TryRead([], endOfStream: false, out _));
        Assert.Equal(new[] { 3ul }, response.SectionAcknowledgments);

        // Two further reads over the same reader add nothing, which is the difference between
        // "once per section" and "once per pump".
        Assert.True(response.TryRead([], endOfStream: false, out _));
        Assert.True(response.TryRead([], endOfStream: false, out _));
        Assert.Equal(new[] { 3ul }, response.SectionAcknowledgments);

        // And a trailer section that used no dynamic entry declares 0 and is not acknowledged.
        Assert.True(response.TryRead(
            Script(
                (Data, "body"u8.ToArray()),
                (Headers, EncodeSection(("grpc-status", "0")))).ToArray(),
            endOfStream: true,
            out _));
        Assert.Equal(new[] { 3ul }, response.SectionAcknowledgments);
    }

    // ------------------------------------------------------------------------
    // C16 helpers
    // ------------------------------------------------------------------------

    // s4.5.1's two-byte prefix for `requiredInsertCount` with a Delta Base of zero and a Sign
    // of 0 - s4.5.1.2's "both the Sign bit and the Delta Base will be set to zero", which
    // makes the Base equal the count - then s4.5.2's Indexed Field Line twice: once with T = 1
    // at static index 25, ":status: 200", and once with T = 0 at relative index 0. s3.2.5
    // makes the second the entry at Base - 1, which s2.1.2 makes the largest absolute index a
    // section declaring this count may name.
    //
    // THE :status IS NOT DECORATION. s4.3.2 makes a response without one malformed and C11
    // refuses it with H3_MESSAGE_ERROR, so a field section carrying only the dynamic reference
    // would be rejected by the message rules before this test could see the QPACK answer -
    // which is how the first draft of this vector failed for the wrong reason.
    private static byte[] DynamicSectionAt(ulong requiredInsertCount) =>
        [EncodedInsertCount(requiredInsertCount), 0x00, 0b1100_0000 | 25, 0b1000_0000];

    // The same prefix, but the body is a real :status 200 through the STATIC table, so a
    // section that unblocks can be checked for WHAT it decoded to rather than only for
    // whether it decoded. s3.1's static entry 25 is ":status: 200"; s4.5.2's T bit is 1.
    private static byte[] StatusSectionAt(ulong requiredInsertCount) =>
        [EncodedInsertCount(requiredInsertCount), 0x00, 0b1100_0000 | 25];

    // s4.5.1.1's transform, applied rather than assumed. Every count these tests use is far
    // below FullRange, so `(count mod 4096) + 1` is `count + 1` - and the range assertion is
    // what says so, instead of leaving it to be noticed.
    private static byte EncodedInsertCount(ulong requiredInsertCount)
    {
        Assert.InRange(requiredInsertCount, 1ul, 63ul);
        return (byte)(requiredInsertCount + 1);
    }

    // A table at the capacity this stack actually advertises, holding `count` entries, so that
    // s4.5.1.1's MaxEntries here is the one a real peer would compute.
    private static TlsQuicQpackDynamicTable TableWith(int count)
    {
        var table = new TlsQuicQpackDynamicTable((int)SharpTls.Tests.Quic.TestHttp3Settings.DatagramCapable
            .Single(setting =>
                setting.Identifier == TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier)
            .Value);
        SetCapacity(table, table.MaximumCapacity);
        InsertNumbered(table, 0, count);
        return table;
    }

    // s4.3.3's Insert With Literal Name, `count` times, named from `first` so a second call
    // continues where the first stopped and a misread index yields a WRONG field rather than a
    // plausible one.
    private static void InsertNumbered(TlsQuicQpackDynamicTable table, int first, int count)
    {
        for (var i = first; i < first + count; i++)
        {
            var instruction = new byte[128];
            Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
                Encoding.ASCII.GetBytes($"n{i}"), 6, 0b0100_0000, huffman: false,
                instruction, out var nameLength));
            Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
                Encoding.ASCII.GetBytes($"v{i}"), 8, 0, huffman: false,
                instruction.AsSpan(nameLength), out var valueLength));
            Feed(table, instruction[..(nameLength + valueLength)]);
        }

        Assert.Equal((ulong)(first + count), table.InsertCount);
    }

    // s4.3.1's Set Dynamic Table Capacity: the 001 pattern, then the capacity on a 5-bit
    // prefix.
    private static void SetCapacity(TlsQuicQpackDynamicTable table, int capacity)
    {
        var instruction = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(
            (ulong)capacity, 5, 0b0010_0000, instruction, out var written));
        Feed(table, instruction[..written]);
    }

    private static void Feed(TlsQuicQpackDynamicTable table, byte[] instructions)
    {
        Assert.True(table.TryReadEncoderInstructions(
            instructions, out var consumed, out var error));
        Assert.Equal(TlsQuicQpackEncoderStreamError.None, error);
        Assert.Equal(instructions.Length, consumed);
    }
}
