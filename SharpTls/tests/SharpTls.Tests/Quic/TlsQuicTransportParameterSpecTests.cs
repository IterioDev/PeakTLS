using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// THE ONE TEST IN THIS FILE THAT MATTERS MOST IS NOT THE PRESET'S.
// AnArbitraryListIsEmittedAsGivenDownToTheByte and its siblings are the acceptance
// criterion for this seam: the library's goal is to reproduce a fingerprint it has never
// seen, so a caller handing over an unknown identifier, arbitrary bytes and an arbitrary
// order must get exactly those bytes back. Everything about a preset is a default a
// caller replaces; nothing about it may narrow what a caller can express.
//
// WHERE THE EXPECTATIONS COME FROM. The capture's own table is PARSED, not retyped - a test
// that compared the composed order to a hand-written list would pass against an
// implementation that hard-coded that same hand-written list, which is precisely the mutant
// that survived task C9's stated done-when. The RFC-derived facts (s18.1's reserved form,
// RFC 9368 s3's reserved-version pattern, s16's one-byte varint) are recomputed from the
// form rather than compared to the number the source already holds.
public sealed class TlsQuicTransportParameterSpecTests
{
    // The B plan, which the source's unverified markers cite by task number.
    private const string PlanPath =
        "docs/superpowers/plans/2026-08-20-quic-b-fingerprint-spec-scoping.md";

    private const string CapturePath =
        "docs/superpowers/specs/reference-captures/" +
        "the preset that measured it";

    private const string SourcePath = "src/SharpTls/Quic/TlsQuicTransportParameterSpec.cs";

    // ------------------------------------------------------------------------------
    // The composed list is the capture's, read back from the encodable set.
    // ------------------------------------------------------------------------------



    // THE CAPTURE'S OWN NUMBERS, READ OUT OF THE CAPTURE. Ten of the fourteen rows publish
    // their value as a plain integer; the other four publish hex, prose or a structure, and
    // are checked by their own tests. Nothing in this method names a parameter's number: the
    // identifier, the value and which rows qualify all come from parsing the table, so a
    // preset entry drifting off the capture fails here without any test being edited -
    // including the six the flow-control spec places, whose defaults are rows of this same
    // table and which therefore have to keep agreeing with it.
    // A TEST WHOSE SUBJECT WAS DELETED. It asserted the CONTENT of the library's default
    // transport-parameter list - a captured browser's fourteen entries, their wire order,
    // their values, and the bookkeeping that kept them all inside one preset block.
    // SharpTls ships no captured persona now: the default is RfcMinimumParameters, RFC
    // 9000 s7.3's single mandatory initial_source_connection_id. A persona's list, its
    // order and its values are asserted where the persona lives - see TlsPresetTests.


    // THE CAPTURE-CONTAINMENT TEST IS GONE WITH THE CAPTURE. It asserted that the
    // library's declared initial_rtt range contained one draw a captured browser was observed
    // to make - the only checkable constraint on a range nobody measured. The library declares
    // no such range now: its default transport-parameter list is RFC 9000 s7.3's single
    // mandatory entry and advertises no initial_rtt at all, so a preset that emits one
    // declares its own range beside the capture that bounds it.


    // ------------------------------------------------------------------------------
    // The six flow-control values are PLACED, so they cannot diverge.
    // ------------------------------------------------------------------------------

    [Fact]
    public void TheComposedFlowControlValuesAreTheOnesTheFlowControlSpecEmits()
    {
        // Deliberately NOT the capture's six. A composition that restated that client's numbers
        // instead of placing the spec's would pass a test run against the defaults and fail
        // this one, which is the whole reason RFC 9000 s4.1 forbids typing them twice.
        var flowControl = new TlsQuicLocalFlowControlSpec
        {
            InitialMaxData = 111,
            InitialMaxStreamDataBidiLocal = 222,
            InitialMaxStreamDataBidiRemote = 333,
            InitialMaxStreamDataUni = 444,
            InitialMaxStreamsBidi = 555,
            InitialMaxStreamsUni = 666,
        };
        var connectionSpec = new TlsQuicConnectionSpec { LocalFlowControl = flowControl };

        var composed = SampleSpec().Compose(connectionSpec, []);

        var expected = flowControl.ToTransportParameters();
        Assert.NotEmpty(expected);
        foreach (var parameter in expected)
        {
            var emitted = composed.Get(parameter.Id);
            Assert.NotNull(emitted);
            Assert.Equal(parameter.Value, emitted.Value);
        }
    }

    [Fact]
    public void TheComposedSourceConnectionIdIsTheOneTheConnectionSuppliesAtItsDeclaredLength()
    {
        var connectionSpec = new TlsQuicConnectionSpec { SourceConnectionIdLength = 4 };
        byte[] connectionId = [0x11, 0x22, 0x33, 0x44];

        var composed = SampleSpec()
            .Compose(connectionSpec, connectionId);

        var emitted = composed.Get(
            (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId);
        Assert.NotNull(emitted);
        Assert.Equal(connectionId, emitted.Value);
    }

    [Fact]
    public void TheDefaultSpecEmitsAnEmptySourceConnectionIdAtTheCapturesZeroLength()
    {
        // Capture line 86: "empty, consistent with a zero-length source CID", which is
        // TlsQuicConnectionSpec.SourceConnectionIdLength's default of 0.
        var composed = SampleSpec()
            .Compose(new TlsQuicConnectionSpec(), []);

        var emitted = composed.Get(
            (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId);
        Assert.NotNull(emitted);
        Assert.Empty(emitted.Value);
    }

    // ------------------------------------------------------------------------------
    // The acceptance criterion: an arbitrary list comes out as the list it went in as.
    // ------------------------------------------------------------------------------

    [Fact]
    public void AnArbitraryListIsEmittedAsGivenDownToTheByte()
    {
        // Three identifiers small enough that RFC 9000 s16's one-byte form (2-bit prefix 00,
        // six-bit value, so 0 to 63) holds each of them and its length, which is what makes
        // the expected encoding writable by hand instead of by calling the encoder twice.
        var spec = new TlsQuicTransportParameterSpec
        {
            Parameters =
            [
                TlsQuicTransportParameterSlot.Literal(0x3f, []),
                TlsQuicTransportParameterSlot.Literal(0x01, [0x01]),
                TlsQuicTransportParameterSlot.Literal(0x00, [0xff]),
            ],
        };

        var encoded = spec.Compose(new TlsQuicConnectionSpec(), []).Encode();

        Assert.Equal<byte[]>(
            [
                0x3f, 0x00,             // id 63, length 0
                0x01, 0x01, 0x01,       // id 1, length 1, value 01
                0x00, 0x01, 0xff,       // id 0, length 1, value ff
            ],
            encoded);
    }

    [Fact]
    public void IdentifiersThisLibraryHasNoNameForSurviveCompositionWithTheirBytes()
    {
        var longValue = new byte[300];
        for (var index = 0; index < longValue.Length; index++)
        {
            longValue[index] = (byte)index;
        }

        // Unknown, both Google-private ones, a reserved one and the largest identifier a
        // QUIC variable-length integer can carry - none of which is in
        // TlsQuicTransportParameterId, and none of which this type has a property for.
        ImmutableArray<TlsQuicTransportParameterSlot> slots =
        [
            TlsQuicTransportParameterSlot.Literal(
                QuicVariableLengthInteger.MaximumValue, [0xde, 0xad, 0xbe, 0xef]),
            TlsQuicTransportParameterSlot.Literal(12583, longValue),
            TlsQuicTransportParameterSlot.Literal(12584, []),
            TlsQuicTransportParameterSlot.Literal(
                TlsQuicTransportParameterSpec.ReservedIdentifier(1), [0xfb]),
            TlsQuicTransportParameterSlot.Literal(0x4242, [0x00, 0x00, 0x00]),
        ];

        var composed = new TlsQuicTransportParameterSpec { Parameters = slots }
            .Compose(new TlsQuicConnectionSpec(), []);

        // Through the encoder and back out of the parser, so the claim is about bytes on the
        // wire rather than about the object that produced them.
        var reparsed = TlsQuicTransportParameters.Parse(composed.Encode()).Parameters;
        Assert.Equal(slots.Length, reparsed.Count);
        for (var index = 0; index < slots.Length; index++)
        {
            Assert.Equal(slots[index].Id, reparsed[index].Id);
            Assert.Equal(slots[index].LiteralSpan.ToArray(), reparsed[index].Value);
        }
    }

    [Fact]
    public void TheOrderTheCallerListsIsTheOrderEmittedForEveryOrderTried()
    {
        var connectionSpec = new TlsQuicConnectionSpec();

        // THE DRAWS ARE FROZEN FIRST, and without that this test would stop meaning anything
        // the moment tasks B3-B5 made three entries per-connection: the rotation by zero
        // repeats the capture's own order, so two compositions of the same order would
        // produce different bytes and the count below would read 17 for a reason that has
        // nothing to do with ordering. Pinning turns the randomness off and leaves the
        // property under test - that order reaches the wire - the only thing varying.
        var capture = PinnedPreset();

        // The capture's own order, sorted ascending, descending, and every rotation of it:
        // 3 + 14 = 17 orders, of which only one is the capture's. An implementation that
        // sorted, or that hard-coded the capture's order, fails all but one of them.
        List<ImmutableArray<TlsQuicTransportParameterSlot>> orders =
        [
            capture,
            [.. capture.OrderBy(slot => slot.Id)],
            [.. capture.OrderByDescending(slot => slot.Id)],
        ];
        for (var rotation = 0; rotation < capture.Length; rotation++)
        {
            orders.Add([.. capture.Skip(rotation), .. capture.Take(rotation)]);
        }
        Assert.Equal(17, orders.Count);

        var distinctEncodings = new HashSet<string>(StringComparer.Ordinal);
        foreach (var order in orders)
        {
            var composed = new TlsQuicTransportParameterSpec { Parameters = order }
                .Compose(connectionSpec, []);
            Assert.Equal(
                order.Select(slot => slot.Id).ToArray(),
                composed.Parameters.Select(parameter => parameter.Id).ToArray());
            distinctEncodings.Add(Convert.ToHexString(composed.Encode()));
        }

        // The rotation by 0 repeats the capture's own order, so 17 orders produce 16
        // distinct byte strings. If order did not reach the wire they would all be one.
        Assert.Equal(16, distinctEncodings.Count);
    }

    [Fact]
    public void AnEmptyListComposesToAClientThatSendsNoTransportParameters()
    {
        var composed = new TlsQuicTransportParameterSpec { Parameters = [] }
            .Compose(new TlsQuicConnectionSpec(), []);

        Assert.Empty(composed.Parameters);
        Assert.Empty(composed.Encode());
    }

    // ------------------------------------------------------------------------------
    // Rejections. One witness per branch, and every branch is reachable from a caller.
    // ------------------------------------------------------------------------------

    [Fact]
    public void ALiteralValueForAnIdentifierThisSpecPlacesIsRejected()
    {
        var placedIdentifiers = PlacedIdentifiers();
        Assert.NotEmpty(placedIdentifiers);

        foreach (var identifier in placedIdentifiers)
        {
            var spec = new TlsQuicTransportParameterSpec
            {
                Parameters = [TlsQuicTransportParameterSlot.Literal(identifier, [0x01])],
            };
            var error = Assert.Throws<ArgumentException>(
                () => spec.Compose(new TlsQuicConnectionSpec(), []));
            Assert.Contains("takes its value from the connection spec", error.Message);
        }
    }

    [Fact]
    public void APlacedEntryUnderAnIdentifierNothingPlacesIsRejected()
    {
        var spec = new TlsQuicTransportParameterSpec
        {
            // max_idle_timeout is a real parameter and is emitted by the default preset -
            // as a literal. Nothing places a value for it, so naming it without one is a
            // request the composer cannot fill.
            Parameters =
            [
                TlsQuicTransportParameterSlot.Placed(
                    (ulong)TlsQuicTransportParameterId.MaxIdleTimeout),
            ],
        };

        var error = Assert.Throws<ArgumentException>(
            () => spec.Compose(new TlsQuicConnectionSpec(), []));
        Assert.Contains("nothing places a value for it", error.Message);
    }

    [Fact]
    public void ADefaultValuedEntryIsRejectedRatherThanEmittingIdentifierZero()
    {
        // The reachable path is an uninitialised element of a caller-built array. Because
        // the entry is a struct it cannot be null, so the failure it produces is this named
        // rejection rather than a NullReferenceException with no ParamName.
        var spec = new TlsQuicTransportParameterSpec
        {
            Parameters = [default],
        };

        var error = Assert.Throws<ArgumentException>(
            () => spec.Compose(new TlsQuicConnectionSpec(), []));
        Assert.Contains("0x0", error.Message);
        Assert.Contains("nothing places a value for it", error.Message);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(4, 3)]
    [InlineData(4, 5)]
    [InlineData(8, 0)]
    public void ASourceConnectionIdThatIsNotTheSpecsDeclaredLengthIsRejected(
        int declaredLength,
        int suppliedLength)
    {
        var connectionSpec = new TlsQuicConnectionSpec
        {
            SourceConnectionIdLength = declaredLength,
        };
        var supplied = new byte[suppliedLength];

        var error = Assert.Throws<ArgumentException>(
            () => SampleSpec().Compose(connectionSpec, supplied));
        Assert.Equal("sourceConnectionId", error.ParamName);
    }

    [Fact]
    public void ASourceConnectionIdOfTheDeclaredLengthIsAcceptedAtBothEndsOfTheRange()
    {
        // The boundary either side of the rejections above: the guard is an equality, so
        // both a zero-length and a maximum-length agreement must be accepted.
        foreach (var length in new[] { 0, 20 })
        {
            var connectionSpec = new TlsQuicConnectionSpec
            {
                SourceConnectionIdLength = length,
            };
            var composed = SampleSpec()
                .Compose(connectionSpec, new byte[length]);
            var emitted = composed.Get(
                (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId);
            Assert.NotNull(emitted);
            Assert.Equal(length, emitted.Value.Length);
        }
    }

    [Fact]
    public void ComposeRejectsANullConnectionSpec()
    {
        var spec = SampleSpec();

        Assert.Throws<ArgumentNullException>(() => spec.Compose(null!, []));
    }

    [Fact]
    public void ADefaultValuedParameterListIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => new TlsQuicTransportParameterSpec
            {
                Parameters = default,
            });
        Assert.Equal("Parameters", error.ParamName);
    }

    [Fact]
    public void ReservedIdentifierRejectsAnNWhoseIdentifierWouldNotFitAVarint()
    {
        var largest = (QuicVariableLengthInteger.MaximumValue -
            TlsQuicTransportParameterSpec.ReservedIdentifierBase) /
            TlsQuicTransportParameterSpec.ReservedIdentifierStep;

        // The boundary either side, so the bound is an off-by-one witness and not just a
        // rejection of something absurdly large.
        Assert.True(
            TlsQuicTransportParameterSpec.ReservedIdentifier(largest) <=
                QuicVariableLengthInteger.MaximumValue);
        Assert.Throws<ArgumentOutOfRangeException>(
            () => TlsQuicTransportParameterSpec.ReservedIdentifier(largest + 1));
    }

    [Fact]
    public void EncodeVersionInformationRejectsANullVersionList()
    {
        Assert.Throws<ArgumentNullException>(
            () => TlsQuicTransportParameterSpec.EncodeVersionInformation(1, null!));
    }

    // ------------------------------------------------------------------------------
    // The three values the capture cannot bound, and the RFC forms that do bound them.
    // ------------------------------------------------------------------------------

    [Fact]
    public void TheReservedIdentifierIsOfSection18Point1sFormAndInsideTheCapturesInterval()
    {
        var identifier = TestQuicSpecValues.SampleReservedIdentifier;

        // RFC 9000 s18.1's "31 * N + 27", recomputed from N rather than compared to itself.
        Assert.Equal(
            (TlsQuicTransportParameterSpec.ReservedIdentifierStep *
                TestQuicSpecValues.SampleReservedIdentifierN) +
                TlsQuicTransportParameterSpec.ReservedIdentifierBase,
            identifier);
        Assert.True(TlsQuicTransportParameterSpec.IsReservedIdentifier(identifier));
        Assert.True(identifier <= QuicVariableLengthInteger.MaximumValue);

        // Capture line 107 prints "id ~ 3.7457e18" and nothing more precise. Five
        // significant digits denote the half-open interval below, which is the whole of
        // what the capture bounds.
        const ulong Low = 3_745_650_000_000_000_000;
        const ulong High = 3_745_750_000_000_000_000;
        Assert.InRange(identifier, Low, High - 1);

        // AND THE CAPTURE DOES NOT PIN IT, which is why the source marks it unverified: the
        // neighbouring N is inside the same interval and equally consistent with the
        // capture. A test asserting one exact number here would be claiming a measurement
        // nobody took.
        Assert.InRange(
            TlsQuicTransportParameterSpec.ReservedIdentifier(
                TestQuicSpecValues.SampleReservedIdentifierN - 1),
            Low,
            High - 1);

        // The interval still discriminates - a different reserved identifier is outside it,
        // so the two assertions above are not true of every ulong.
        Assert.False(TlsQuicTransportParameterSpec.ReservedIdentifier(1) >= Low);

        // And the form predicate discriminates: the identifier either side of a reserved one
        // is not reserved, which is 30 of every 31 values. Without this the predicate could
        // return true unconditionally and every use of it above would still pass.
        Assert.False(TlsQuicTransportParameterSpec.IsReservedIdentifier(identifier + 1));
        Assert.False(TlsQuicTransportParameterSpec.IsReservedIdentifier(identifier - 1));
        Assert.False(TlsQuicTransportParameterSpec.IsReservedIdentifier(
            TlsQuicTransportParameterSpec.ReservedIdentifierBase - 1));
    }

    [Fact]
    public void EveryDrawnGreaseVersionMatchesRfc9368sReservedPattern()
    {
        // rfc9368-section3-and-10.1-version-information.txt: versions "following the pattern
        // 0x?a?a?a?a" are "reserved to exercise version negotiation". Recomputed nibble by
        // nibble over many draws rather than compared to any constant - there is no longer a
        // constant to compare to, which is task B3's point: the preset draws from the whole
        // pattern instead of choosing one member of it.
        foreach (var version in DrawnGreaseVersions(Draws))
        {
            for (var shift = 0; shift < 32; shift += 8)
            {
                Assert.Equal(0x0au, (version >> shift) & 0x0fu);
            }
            Assert.True(TlsQuicTransportParameterSpec.IsReservedVersion(version));
        }

        // And the predicate distinguishes, byte by byte. Version 1 - the chosen one - is not
        // reserved, and neither is a version whose LOW byte alone matches: a predicate that
        // checked one byte instead of four would accept the second of these, so this is what
        // makes the assertions above a check on the whole pattern.
        Assert.False(TlsQuicTransportParameterSpec.IsReservedVersion(1));
        Assert.False(TlsQuicTransportParameterSpec.IsReservedVersion(0x0000000au));
        Assert.False(TlsQuicTransportParameterSpec.IsReservedVersion(0x0a0a0a0bu));
    }

    [Fact]
    public void TwoCompositionsOfOneSpecDrawTwoDifferentGreaseVersions()
    {
        // ONE spec, many compositions - the shape task B5's clause names for initial_rtt and
        // which applies identically here, because a GREASE version cached at spec
        // construction is as pinned across connections as a literal would be.
        var drawn = DrawnGreaseVersions(Draws).ToHashSet();

        // WHY THIS IS A WITNESS AND NOT A COIN FLIP. RFC 9368 s3's pattern fixes four nibbles
        // and frees four, so it names 16^4 = 65536 versions. An implementation that draws
        // once and caches yields exactly one distinct value and fails with probability 1; a
        // correct one fails only if all Draws draws collide, which is 65536^-(Draws-1).
        Assert.True(
            drawn.Count > 1,
            $"{Draws} compositions of one spec produced {drawn.Count} distinct GREASE "
            + "version(s); a cached draw produces exactly one.");
    }

    [Fact]
    public void TheVersionInformationEmitsTheChosenVersionAndTheAvailableListAndNotTheChosenTwice()
    {
        // THE MUTANT THIS EXISTS FOR emits the chosen version in place of the drawn one, so
        // the value becomes chosen-chosen-chosen. Its LENGTH is identical - three 32-bit
        // words either way - so a length check does not see it, and neither does a test that
        // only asserts the chosen version appears.
        foreach (var versions in DecodedVersionInformation(Draws))
        {
            Assert.Equal(3, versions.Count);

            // Capture line 87, "chosen 1, available [GREASE, 1]": word 0 is the chosen
            // version, word 1 is the GREASE entry and word 2 repeats the chosen one.
            Assert.Equal(1u, versions[0]);
            Assert.Equal(versions[0], versions[2]);

            // The two assertions that kill the mutant. The available list's first entry is
            // NOT the chosen version, and it is reserved under RFC 9368 s3's pattern - which
            // version 1 is not, so the second assertion alone would also catch it.
            Assert.NotEqual(versions[0], versions[1]);
            Assert.True(TlsQuicTransportParameterSpec.IsReservedVersion(versions[1]));
            Assert.False(TlsQuicTransportParameterSpec.IsReservedVersion(versions[0]));
        }
    }

    [Fact]
    public void TheAvailableVersionsListKeepsItsOrderAndReorderingItChangesTheEncodedBytes()
    {
        // Capture line 107, of the GREASE transport parameter and the GREASE version alike:
        // "Both are positional." So the available list's order has to reach the wire, and the
        // witness is that swapping the two entries changes the bytes. Both lists are fully
        // pinned - no nulls - so the only difference between them is the order.
        const uint Grease = 0x1a2a3a4au;
        Assert.True(TlsQuicTransportParameterSpec.IsReservedVersion(Grease));

        var greaseFirst = EncodedVersionInformation([Grease, 1u]);
        var greaseSecond = EncodedVersionInformation([1u, Grease]);

        Assert.NotEqual(greaseFirst, greaseSecond);

        // And the same order twice is the same bytes, so the inequality above is about order
        // and not about the entry being nondeterministic.
        Assert.Equal(greaseFirst, EncodedVersionInformation([Grease, 1u]));
    }

    // The entry type's equality, which is what makes an assertion comparing two lists of
    // entries mean anything. An implementation comparing identifiers alone would pass every
    // list comparison in this suite, because the preset's identifiers are distinct.
    [Fact]
    public void TwoEntriesAreEqualOnlyWhenBothIdentifierAndValueAgree()
    {
        Assert.Equal(
            TlsQuicTransportParameterSlot.Literal(1, [0x01]),
            TlsQuicTransportParameterSlot.Literal(1, [0x01]));
        Assert.NotEqual(
            TlsQuicTransportParameterSlot.Literal(1, [0x01]),
            TlsQuicTransportParameterSlot.Literal(1, [0x02]));
        Assert.NotEqual(
            TlsQuicTransportParameterSlot.Literal(1, [0x01]),
            TlsQuicTransportParameterSlot.Literal(2, [0x01]));

        // A placed entry is not a literal empty one, which is the distinction Compose turns
        // into two different parameters on the wire.
        Assert.NotEqual(
            TlsQuicTransportParameterSlot.Literal(1, []),
            TlsQuicTransportParameterSlot.Placed(1));
        Assert.Equal(
            TlsQuicTransportParameterSlot.Placed(1),
            TlsQuicTransportParameterSlot.Placed(1));

        // A drawn entry is equal to itself and to nothing else, including another drawn entry
        // built the same way. Comparing two draws by their RESULTS would make equality
        // nondeterministic, so the function is what is compared - and the default-valued
        // entry, which is Placed(0), must not be equal to a drawn one whose Id is also 0.
        TlsQuicTransportParameter? Draw(TlsQuicConnectionSpec _) => null;
        var drawn = TlsQuicTransportParameterSlot.Drawn(Draw);
        Assert.Equal(drawn, drawn);
        Assert.NotEqual(drawn, TlsQuicTransportParameterSlot.Drawn(_ => null));
        Assert.NotEqual(drawn, TlsQuicTransportParameterSlot.Placed(0));
        Assert.NotEqual(drawn, default);
    }

    [Fact]
    public void TheVersionInformationEntryCarriesTheChosenVersionInsideItsAvailableList()
    {
        var composed = SampleSpec()
            .Compose(new TlsQuicConnectionSpec(), []);

        var emitted = composed.Get((ulong)TlsQuicTransportParameterId.VersionInformation);
        Assert.NotNull(emitted);

        // RFC 9368 s3 Figure 2: Chosen Version (32), then Available Versions (32)... - so
        // the value is decoded here rather than compared to the bytes that built it.
        var value = emitted.Value;
        Assert.Equal(0, value.Length % sizeof(uint));
        var versions = new List<uint>();
        for (var offset = 0; offset < value.Length; offset += sizeof(uint))
        {
            versions.Add(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(
                value.AsSpan(offset)));
        }

        // Capture line 87: chosen 1, available [GREASE, 1] - three 32-bit words.
        Assert.Equal(3, versions.Count);
        Assert.Equal(1u, versions[0]);
        Assert.True(TlsQuicTransportParameterSpec.IsReservedVersion(versions[1]));
        Assert.Equal(versions[0], versions[2]);
    }


    [Fact]
    public void TheDefaultSetSurvivesEncodingParsingAndClientSideValidation()
    {
        // ONCE PER DRAW AND NOT ONCE. Three of the fourteen entries are redrawn per
        // composition, so a single pass validates one sample of a set that differs every
        // time - and the validator this reaches, ValidateVersionInformation, is a length and
        // structure check over exactly one of those drawn values. Repeating is what makes the
        // claim "our composed set validates" rather than "one composition of it did".
        for (var draw = 0; draw < Draws; draw++)
        {
            var composed = SampleSpec()
                .Compose(new TlsQuicConnectionSpec(), []);

            var reparsed = TlsQuicTransportParameters.Parse(composed.Encode());

            // ValidatePeer is reached only for parameters a peer sent, so nothing in this
            // library has ever put a set WE built through it. This is the first time.
            reparsed.ValidatePeer(TlsQuicEndpointRole.Client);
            Assert.Equal(
                composed.Parameters.Select(parameter => parameter.Id).ToArray(),
                reparsed.Parameters.Select(parameter => parameter.Id).ToArray());
            Assert.Equal(
                composed.Parameters.Select(parameter => parameter.Value).ToArray(),
                reparsed.Parameters.Select(parameter => parameter.Value).ToArray());
        }
    }

    // ------------------------------------------------------------------------------
    // Task B4: the reserved parameter is drawn per connection, and its POSITION is the
    // part the fingerprint service hashes.
    // ------------------------------------------------------------------------------

    [Fact]
    public void EveryDrawnReservedIdentifierSatisfiesSection18Point1sFormByRecomputation()
    {
        // "31 * N + 27", recomputed: recover N from the identifier and rebuild the
        // identifier from it. Checked against the form and never against a table, because a
        // table of reserved identifiers is a table this library would have to be right about
        // twice.
        var step = TlsQuicTransportParameterSpec.ReservedIdentifierStep;
        var origin = TlsQuicTransportParameterSpec.ReservedIdentifierBase;

        foreach (var identifier in DrawnReservedIdentifiers(Draws))
        {
            Assert.True(identifier >= origin);
            Assert.Equal(0ul, (identifier - origin) % step);
            Assert.Equal(identifier, (step * ((identifier - origin) / step)) + origin);
            Assert.True(TlsQuicTransportParameterSpec.IsReservedIdentifier(identifier));
            Assert.True(identifier <= QuicVariableLengthInteger.MaximumValue);
        }
    }

    [Fact]
    public void TwoCompositionsOfOneSpecDrawTwoDifferentReservedIdentifiers()
    {
        var drawn = DrawnReservedIdentifiers(Draws).ToHashSet();

        // The draw is over 0..MaximumReservedIdentifierN, which is (2^62 - 1 - 27) / 31 -
        // upwards of 10^17 values - so a correct implementation repeating itself across
        // Draws compositions is not a scenario worth budgeting for, while a cached draw
        // yields exactly one distinct identifier and fails every time.
        Assert.True(
            drawn.Count > 1,
            $"{Draws} compositions of one spec produced {drawn.Count} distinct reserved "
            + "identifier(s); a cached draw produces exactly one.");
    }

    [Fact]
    public void ADrawnReservedIdentifierCannotCollideWithAnyIdentifierThisLibraryDefines()
    {
        // s18.1 reserves 1 identifier in every 31, and every identifier RFC 9000 s18.2
        // defines plus both Google-private ones fall in the other 30 - so a drawn identifier
        // cannot collide with any of them whatever N comes up. Checked by recomputing the
        // form over the whole set rather than by drawing and hoping.
        ulong[] defined =
        [
            .. Enum.GetValues<TlsQuicTransportParameterId>().Select(id => (ulong)id),
            TlsQuicTransportParameterSpec.InitialRttIdentifier,
            TlsQuicTransportParameterSpec.GoogleConnectionOptionsIdentifier,
        ];
        Assert.NotEmpty(defined);

        foreach (var identifier in defined)
        {
            Assert.False(
                TlsQuicTransportParameterSpec.IsReservedIdentifier(identifier),
                $"0x{identifier:X} is a defined identifier of RFC 9000 s18.1's reserved "
                + "form, so a drawn reserved identifier could collide with it.");
        }

        // THE BOUNDARY WITNESS, without which the loop above would pass against a predicate
        // that returned false for everything. For each defined identifier, some value within
        // one step of it IS reserved - so the loop is a statement about those identifiers
        // and not about the predicate being inert.
        var step = TlsQuicTransportParameterSpec.ReservedIdentifierStep;
        foreach (var identifier in defined)
        {
            Assert.Contains(
                Enumerable.Range(0, (int)step + 1).Select(offset => identifier + (ulong)offset),
                candidate => TlsQuicTransportParameterSpec.IsReservedIdentifier(candidate));
        }

        // And the drawn identifiers really are absent from the defined set on the wire.
        foreach (var identifier in DrawnReservedIdentifiers(Draws))
        {
            Assert.DoesNotContain(identifier, defined);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    public void ADrawnEntryIsEmittedAtTheIndexItWasListedAtForEveryIndexTried(int index)
    {
        // THE MUTANT THIS EXISTS FOR appends the drawn parameter last regardless of where it
        // was listed. At index 4 - the end of this five-entry list - such a mutant is right by
        // accident, which is why the same claim is made at four indices and why the index is
        // read back from the composed parameter list rather than asserted from the spec.
        //
        // Finding 3, measured at commit 4ed90bf against the live endpoint: reordering the
        // list moved perk_hash while leaving perk_hash_normalized identical. Position is the
        // hashed part of this parameter; its identifier and value are not hashed at all.
        // Identifiers nothing places and none of them reserved, so the only entry the
        // assertions below can find by RFC 9000 s18.1's form is the drawn one. 0x04 and its
        // neighbours would not do: those are flow-control identifiers Compose places.
        var others = new List<TlsQuicTransportParameterSlot>
        {
            TlsQuicTransportParameterSlot.Literal(0x21, [0x21]),
            TlsQuicTransportParameterSlot.Literal(0x22, [0x22]),
            TlsQuicTransportParameterSlot.Literal(0x23, [0x23]),
            TlsQuicTransportParameterSlot.Literal(0x24, [0x24]),
        };
        Assert.All(
            others,
            slot => Assert.False(
                TlsQuicTransportParameterSpec.IsReservedIdentifier(slot.Id)));
        var slots = new List<TlsQuicTransportParameterSlot>(others);
        slots.Insert(
            index,
            TlsQuicTransportParameterSpec.DrawnReservedParameter(
                0,
                TlsQuicTransportParameterSpec.MaximumReservedIdentifierN,
                [0xfb]));

        var emitted = new TlsQuicTransportParameterSpec { Parameters = [.. slots] }
            .Compose(new TlsQuicConnectionSpec(), [])
            .Parameters;

        Assert.Equal(slots.Count, emitted.Count);
        var reservedIndices = emitted
            .Select((parameter, position) => (parameter, position))
            .Where(entry =>
                TlsQuicTransportParameterSpec.IsReservedIdentifier(entry.parameter.Id))
            .Select(entry => entry.position)
            .ToArray();

        // Exactly one entry is reserved and it is at the index it was listed at. The
        // "exactly one" half matters: without it, an implementation emitting the reserved
        // entry both in place and again at the end would pass.
        Assert.Equal([index], reservedIndices);
        Assert.Equal<byte[]>([0xfb], emitted[index].Value);

        // The four fixed entries keep their relative order around it, so the insertion did
        // not merely land somewhere that happens to satisfy the check above.
        Assert.Equal(
            others.Select(slot => slot.Id).ToArray(),
            emitted.Where((_, position) => position != index)
                .Select(parameter => parameter.Id)
                .ToArray());
    }

    // ------------------------------------------------------------------------------
    // Task B5: initial_rtt is drawn per connection, from a range two knobs can set.
    // ------------------------------------------------------------------------------

    [Fact]
    public void ComposeRunsADrawnEntrysFunctionOncePerCompositionAndNeverCachesIt()
    {
        // THE DETERMINISTIC HALF OF THE CACHING WITNESS, and the reason it exists: a test
        // that only asserts two random draws differ can pass against a caching mutant by
        // luck. This one cannot. The function returns a counter, so a correct Compose yields
        // 1 then 2 and a Compose that cached its result yields 1 twice - a difference no
        // random number generator participates in.
        var calls = 0;
        var spec = new TlsQuicTransportParameterSpec
        {
            Parameters =
            [
                TlsQuicTransportParameterSlot.Drawn(_ =>
                {
                    calls++;
                    return new TlsQuicTransportParameter(
                        0x20,
                        QuicVariableLengthInteger.Encode((ulong)calls));
                }),
            ],
        };

        var first = spec.Compose(new TlsQuicConnectionSpec(), []);
        var second = spec.Compose(new TlsQuicConnectionSpec(), []);

        Assert.Equal(2, calls);
        Assert.Equal(1ul, first.Parameters[0].GetVariableInteger());
        Assert.Equal(2ul, second.Parameters[0].GetVariableInteger());
    }

    [Fact]
    public void TwoCompositionsOfOneSpecDrawTwoDifferentInitialRttValues()
    {
        // A4's instruction, quoted by the B plan: "pin it: two consecutive connections must
        // produce two different initial_rtt values." ONE spec, many compositions, which is
        // the arrangement a real caller has - the spec is built once and used per connection.
        var spec = SampleSpec();
        var connectionSpec = new TlsQuicConnectionSpec();

        var drawn = Enumerable.Range(0, Draws)
            .Select(_ => spec.Compose(connectionSpec, [])
                .Get(TlsQuicTransportParameterSpec.InitialRttIdentifier))
            .Select(parameter =>
            {
                Assert.NotNull(parameter);
                return parameter.GetVariableInteger();
            })
            .ToHashSet();

        // The preset's declared range spans 200000 microseconds, so a correct draw repeating
        // itself Draws times over is negligible while a cached one yields exactly one value.
        Assert.True(
            drawn.Count > 1,
            $"{Draws} compositions of one spec produced {drawn.Count} distinct initial_rtt "
            + "value(s); a cached draw produces exactly one, which is the pinned parameter "
            + "capture line 95 warns about.");
    }

    [Fact]
    public void EveryDrawnInitialRttLiesInsideTheRangeTheConnectionSpecDeclares()
    {
        // Checked against the range OBJECT rather than against a literal, so a test edit is
        // not what a range change needs.
        var range = (Minimum: TimeSpan.FromMicroseconds(1234), Maximum: TimeSpan.FromMicroseconds(5678));
        var connectionSpec = new TlsQuicConnectionSpec { InitialRttRange = range };
        var spec = SampleSpec();

        var drawn = new HashSet<ulong>();
        for (var draw = 0; draw < Draws; draw++)
        {
            var parameter = spec.Compose(connectionSpec, [])
                .Get(TlsQuicTransportParameterSpec.InitialRttIdentifier);
            Assert.NotNull(parameter);
            var microseconds = parameter.GetVariableInteger();
            Assert.InRange(
                microseconds,
                (ulong)(range.Minimum.Ticks / TimeSpan.TicksPerMicrosecond),
                (ulong)(range.Maximum.Ticks / TimeSpan.TicksPerMicrosecond));
            drawn.Add(microseconds);
        }

        // THE CONNECTION SPEC'S RANGE IS WHAT WAS USED, not the entry's fallback. The two
        // intervals are disjoint - the preset's is 100000..300000 microseconds and this one
        // ends at 5678 - so an implementation ignoring this knob fails the bound above rather
        // than passing by overlap. That disjointness is what makes this the wiring test the
        // standing rule "a knob that exists is not a knob that is wired" asks for.
        Assert.True(range.Maximum < TestQuicSpecValues.SampleInitialRttRange.Minimum);
        Assert.True(drawn.Count > 1);
    }

    [Fact]
    public void ARangeWhoseBoundsAreEqualEmitsThatValueRatherThanFailing()
    {
        // The degenerate case as a decision rather than a crash: TlsQuicConnectionSpec
        // already accepts equal bounds, so the composer has to mean something by them.
        var pinned = TimeSpan.FromMicroseconds(4242);
        var connectionSpec = new TlsQuicConnectionSpec
        {
            InitialRttRange = (pinned, pinned),
        };

        var parameter = SampleSpec()
            .Compose(connectionSpec, [])
            .Get(TlsQuicTransportParameterSpec.InitialRttIdentifier);

        Assert.NotNull(parameter);
        Assert.Equal(
            (ulong)(pinned.Ticks / TimeSpan.TicksPerMicrosecond),
            parameter.GetVariableInteger());

        // AND THE RANGE IS INCLUSIVE AT THE TOP, which the degenerate case above cannot show
        // because it short-circuits before the draw. Over a range exactly one microsecond
        // wide, both endpoints must appear: an implementation whose upper bound is exclusive
        // emits the minimum every time and would pass every other assertion in this file.
        var narrow = new TlsQuicConnectionSpec
        {
            InitialRttRange = (TimeSpan.FromMicroseconds(4242), TimeSpan.FromMicroseconds(4243)),
        };
        var spec = SampleSpec();
        var seen = new HashSet<ulong>();
        for (var draw = 0; draw < Draws; draw++)
        {
            var value = spec.Compose(narrow, [])
                .Get(TlsQuicTransportParameterSpec.InitialRttIdentifier);
            Assert.NotNull(value);
            seen.Add(value.GetVariableInteger());
        }

        // Two outcomes over 32 fair draws; a one-sided implementation yields one, and a
        // correct one misses the second with probability 2^-31.
        Assert.Equal([4242ul, 4243ul], seen.OrderBy(value => value).ToArray());
    }

    [Fact]
    public void ADrawnEntryReturningNothingOmitsTheParameterAndShortensTheList()
    {
        // THE ABSENT BRANCH. Both ranges null - the entry declares no fallback and the
        // connection spec names none - so the client sends no initial_rtt at all. That is a
        // caller's decision here rather than this library's refusal: the default preset
        // passes a fallback and therefore always emits.
        var spec = new TlsQuicTransportParameterSpec
        {
            Parameters =
            [
                TlsQuicTransportParameterSlot.Literal(0x01, [0x01]),
                TlsQuicTransportParameterSpec.DrawnInitialRtt(
                    TlsQuicTransportParameterSpec.InitialRttIdentifier, null),
                TlsQuicTransportParameterSlot.Literal(0x03, [0x03]),
            ],
        };
        var composed = spec.Compose(new TlsQuicConnectionSpec(), []);

        Assert.Null(composed.Get(TlsQuicTransportParameterSpec.InitialRttIdentifier));
        Assert.Equal([0x01ul, 0x03ul], composed.Parameters.Select(p => p.Id).ToArray());

        // THE PRESENT BRANCH, from the same entry, so the two are one decision and not two
        // code paths that could drift: the only change is that the connection spec now names
        // a range, and the parameter reappears at the index it was listed at.
        var withRange = spec.Compose(
            new TlsQuicConnectionSpec
            {
                InitialRttRange = (TimeSpan.FromMicroseconds(1000), TimeSpan.FromMicroseconds(2000)),
            },
            []);
        Assert.NotNull(withRange.Get(TlsQuicTransportParameterSpec.InitialRttIdentifier));
        Assert.Equal(
            TlsQuicTransportParameterSpec.InitialRttIdentifier,
            withRange.Parameters[1].Id);

        // And the default preset does emit it, so "absent" is a configuration and not what
        // this library does when nobody looks.
        Assert.NotNull(SampleSpec()
            .Compose(new TlsQuicConnectionSpec(), [])
            .Get(TlsQuicTransportParameterSpec.InitialRttIdentifier));
    }

    // ------------------------------------------------------------------------------
    // The draw factories' rejections. One witness per branch.
    // ------------------------------------------------------------------------------

    [Fact]
    public void DrawnRejectsANullFunction()
    {
        Assert.Throws<ArgumentNullException>(
            () => TlsQuicTransportParameterSlot.Drawn(null!));
    }

    [Fact]
    public void DrawnReservedParameterRejectsANullValue()
    {
        Assert.Throws<ArgumentNullException>(
            () => TlsQuicTransportParameterSpec.DrawnReservedParameter(0, 1, null!));
    }

    [Fact]
    public void DrawnReservedParameterRejectsAnNRangeOutsideTheVarintCeilingOrInverted()
    {
        var largest = TlsQuicTransportParameterSpec.MaximumReservedIdentifierN;

        // The boundary either side of the ceiling, so the bound is an off-by-one witness.
        _ = TlsQuicTransportParameterSpec.DrawnReservedParameter(largest, largest, [0x00]);
        var tooLarge = Assert.Throws<ArgumentOutOfRangeException>(
            () => TlsQuicTransportParameterSpec.DrawnReservedParameter(0, largest + 1, [0x00]));
        Assert.Equal("maximumN", tooLarge.ParamName);

        // And an inverted range, which would otherwise reach Random with a negative width.
        var inverted = Assert.Throws<ArgumentOutOfRangeException>(
            () => TlsQuicTransportParameterSpec.DrawnReservedParameter(2, 1, [0x00]));
        Assert.Equal("minimumN", inverted.ParamName);
    }

    [Fact]
    public void DrawnVersionInformationRejectsANullList()
    {
        Assert.Throws<ArgumentNullException>(
            () => TlsQuicTransportParameterSpec.DrawnVersionInformation(1, null!));
    }

    [Theory]
    [InlineData(0, 300)]
    [InlineData(300, 100)]
    public void DrawnInitialRttRejectsAFallbackRangeTheConnectionSpecWouldAlsoReject(
        int minimumMicroseconds,
        int maximumMicroseconds)
    {
        // The same two bounds TlsQuicConnectionSpec.InitialRttRange enforces - a
        // non-positive minimum and a maximum below it - so the fallback and the override
        // cannot accept different things. Each row is one of the two branches.
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => TlsQuicTransportParameterSpec.DrawnInitialRtt(
                TlsQuicTransportParameterSpec.InitialRttIdentifier,
                (TimeSpan.FromMicroseconds(minimumMicroseconds),
                    TimeSpan.FromMicroseconds(maximumMicroseconds))));
        Assert.Equal("fallbackRange", error.ParamName);
    }

    // ------------------------------------------------------------------------------
    // The markers, and the plan they cite.
    // ------------------------------------------------------------------------------

    // THE MARKER'S FORM IS DEFINED HERE AND NOWHERE ELSE: the word UNVERIFIED in capitals,
    // a comma, then "settled by task B" and the task's number. Every occurrence of the word
    // in the source must carry one, and every number must name a task the B plan actually
    // has - which is what stops an unbounded choice from shipping as though it were
    // measured, and stops the citation from rotting into a reference to nothing.


    // ------------------------------------------------------------------------------
    // Helpers.
    // ------------------------------------------------------------------------------

    // HOW MANY COMPOSITIONS A "TWO DRAWS DIFFER" CLAIM IS MADE OVER. Two would be enough for
    // the claim; it is 32 because these tests are also run under a mutation sweep, where a
    // caching mutant that survived one lucky pair would be recorded as a survivor. With 32
    // draws the smallest support any of the three draws has is RFC 9368's 16^4 versions, so
    // a correct implementation collides on all of them with probability 65536^-31 while a
    // cached one collides every time.
    private const int Draws = 32;

    // The preset with its three per-connection draws frozen to one composition's results, so
    // a test about ORDER is not also a test about randomness. Each drawn entry becomes the
    // literal it drew; the seven placed and four literal entries pass through untouched, so
    // the list still has fourteen entries in the capture's order.
    private static ImmutableArray<TlsQuicTransportParameterSlot> PinnedPreset()
    {
        var slots = SampleSpec().Parameters;
        var drawn = SampleSpec()
            .Compose(new TlsQuicConnectionSpec(), []).Parameters;
        Assert.Equal(slots.Length, drawn.Count);
        return
        [
            .. slots.Select((slot, index) => slot.IsDrawn
                ? TlsQuicTransportParameterSlot.Literal(drawn[index].Id, drawn[index].Value)
                : slot),
        ];
    }

    // One spec, composed `count` times, yielding the reserved identifier each composition
    // drew. The spec is built ONCE on purpose: a draw cached at spec construction is exactly
    // the defect these callers are looking for, and rebuilding the spec per composition would
    // hide it.
    private static IEnumerable<ulong> DrawnReservedIdentifiers(int count)
    {
        var spec = SampleSpec();
        var connectionSpec = new TlsQuicConnectionSpec();
        for (var draw = 0; draw < count; draw++)
        {
            var reserved = spec.Compose(connectionSpec, []).Parameters
                .Where(parameter =>
                    TlsQuicTransportParameterSpec.IsReservedIdentifier(parameter.Id))
                .ToArray();
            Assert.Single(reserved);
            yield return reserved[0].Id;
        }
    }

    // The same, for version_information: each composition's value decoded into its 32-bit
    // words. RFC 9368 s3 Figure 2 - Chosen Version (32), then Available Versions (32)... -
    // so the words are read out of the bytes rather than compared to what built them.
    private static IEnumerable<List<uint>> DecodedVersionInformation(int count)
    {
        var spec = SampleSpec();
        var connectionSpec = new TlsQuicConnectionSpec();
        for (var draw = 0; draw < count; draw++)
        {
            var parameter = spec.Compose(connectionSpec, [])
                .Get((ulong)TlsQuicTransportParameterId.VersionInformation);
            Assert.NotNull(parameter);
            var value = parameter.Value;
            Assert.Equal(0, value.Length % sizeof(uint));
            var versions = new List<uint>();
            for (var offset = 0; offset < value.Length; offset += sizeof(uint))
            {
                versions.Add(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(
                    value.AsSpan(offset)));
            }
            yield return versions;
        }
    }

    // The GREASE half of each of those, which capture line 87 places second in the available
    // list: word 0 is the chosen version and word 1 is the drawn one.
    private static IEnumerable<uint> DrawnGreaseVersions(int count) =>
        DecodedVersionInformation(count).Select(versions => versions[1]);

    // A version_information entry built from a fully pinned available list - no nulls, so
    // nothing is drawn - encoded through the composer. Used to compare two orderings of the
    // same versions, which is only a comparison of orderings if neither side varies.
    private static byte[] EncodedVersionInformation(uint?[] availableVersions)
    {
        var parameter = new TlsQuicTransportParameterSpec
        {
            Parameters =
            [
                TlsQuicTransportParameterSpec.DrawnVersionInformation(1, availableVersions),
            ],
        }
            .Compose(new TlsQuicConnectionSpec(), [])
            .Parameters[0];
        return parameter.Value;
    }

    // The capture's "QUIC transport parameters, in wire order" table, parsed out of the
    // capture itself. Scoped to that section so the HTTP/3 SETTINGS table above it - whose
    // rows also begin with a number - cannot contribute a row.
    private static List<(int Ordinal, string Identifier, string Value)> CaptureWireOrder()
    {
        var capture = File.ReadAllText(Path.Combine(RepositoryRoot(), CapturePath));
        const string heading = "## QUIC transport parameters, in wire order";
        var start = capture.IndexOf(heading, StringComparison.Ordinal);
        Assert.True(start >= 0, $"{CapturePath} no longer contains '{heading}'.");
        var end = capture.IndexOf("\n## ", start + heading.Length, StringComparison.Ordinal);
        Assert.True(end > start, $"{CapturePath}'s wire-order section has no successor.");

        // Four columns: the row's ordinal, its identifier, its name and its value. The name
        // column is allowed to be empty because the capture's GREASE row has no name.
        var rows = new List<(int, string, string)>();
        foreach (Match match in Regex.Matches(
            capture[start..end],
            @"^\| (\d+) \| ([^|]+?) \| ([^|]*?) \| ([^|]+?) \|",
            RegexOptions.Multiline))
        {
            rows.Add((
                int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture),
                match.Groups[2].Value.Trim(),
                match.Groups[4].Value.Trim()));
        }
        return rows;
    }

    // The identifiers Compose supplies a value for, derived the way Compose derives them
    // rather than listed: whatever the flow-control spec emits, plus the source connection
    // ID. Listing them here would be the second copy this whole design exists to prevent.
    private static HashSet<ulong> PlacedIdentifiers()
    {
        var identifiers = new TlsQuicLocalFlowControlSpec()
            .ToTransportParameters()
            .Select(parameter => parameter.Id)
            .ToHashSet();
        identifiers.Add((ulong)TlsQuicTransportParameterId.InitialSourceConnectionId);
        return identifiers;
    }

    // Walks up from the test assembly to the directory holding both trees, the same way
    // QuicCommentReferencesTests.RepositoryRoot does; there is no repository-root property
    // to read and neither the plan nor the capture is copied to the output.
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !Directory.Exists(Path.Combine(directory.FullName, "src", "SharpTls", "Quic")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory.FullName;
    }

    // ------------------------------------------------------------------------------
    // THE FIXTURE THESE TESTS USED TO GET FOR FREE.
    //
    // `new TlsQuicTransportParameterSpec()` used to be a captured browser's fourteen
    // parameters, so a test about the COMPOSER - drawn entries redrawing, placed entries taking
    // the connection spec's value, list order surviving - could use the default and have all
    // three slot kinds present. SharpTls ships no persona now and that default is RFC 9000
    // s7.3's single mandatory entry, which exercises one kind.
    //
    // SO THE FIXTURE IS WRITTEN OUT HERE, and it is a fixture rather than a persona: neutral
    // round numbers, chosen to put every slot kind and every drawn family in one list. Nothing
    // in it is evidence about any client and nothing may be cited as such.
    // ------------------------------------------------------------------------------

    private const uint SampleChosenVersion = 1;

    private static readonly (TimeSpan Minimum, TimeSpan Maximum) SampleRttRange =
        TestQuicSpecValues.SampleInitialRttRange;

    private static TlsQuicTransportParameterSpec SampleSpec() => new()
    {
        Parameters =
        [
            TlsQuicTransportParameterSlot.Literal(
                TlsQuicTransportParameterSpec.GoogleConnectionOptionsIdentifier,
                System.Text.Encoding.ASCII.GetBytes("TEST")),
            TlsQuicTransportParameterSpec.DrawnReservedParameter(
                0, TlsQuicTransportParameterSpec.MaximumReservedIdentifierN, [0xfb]),
            TlsQuicTransportParameterSlot.Literal(
                (ulong)TlsQuicTransportParameterId.MaxDatagramFrameSize,
                QuicVariableLengthInteger.Encode(65536)),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxStreamsUni),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxStreamsBidi),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataUni),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId),
            TlsQuicTransportParameterSpec.DrawnVersionInformation(
                SampleChosenVersion, [null, SampleChosenVersion]),
            TlsQuicTransportParameterSlot.Literal(
                (ulong)TlsQuicTransportParameterId.MaxIdleTimeout,
                QuicVariableLengthInteger.Encode(30000)),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote),
            TlsQuicTransportParameterSlot.Placed(
                (ulong)TlsQuicTransportParameterId.InitialMaxData),
            TlsQuicTransportParameterSpec.DrawnInitialRtt(
                TlsQuicTransportParameterSpec.InitialRttIdentifier, SampleRttRange),
            TlsQuicTransportParameterSlot.Literal(
                (ulong)TlsQuicTransportParameterId.MaxUdpPayloadSize,
                QuicVariableLengthInteger.Encode(1472)),
        ],
    };

}
