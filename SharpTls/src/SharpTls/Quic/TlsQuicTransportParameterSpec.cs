using System.Collections.Immutable;
using System.Text;

namespace SharpTls.Quic;

/// <summary>One entry in a client's transport-parameter list: an identifier, and either the
/// bytes to emit under it or a declaration that the value is placed here from elsewhere.
/// </summary>
/// <remarks>
/// <para>AN IDENTIFIER/VALUE PAIR AND NOT A NAMED PROPERTY, because the Brave 151 capture's
/// table is headed "in wire order" and says "This ordering is the fingerprint. It is not
/// sorted, and it is not the RFC's presentation order." A set of named properties has no
/// order to express, and an enum of known identifiers cannot carry the two Google-private
/// identifiers (12583, 12584) or a reserved one. Both are in the capture; neither is in
/// <see cref="TlsQuicTransportParameterId"/>. So the identifier here is a bare
/// <see cref="ulong"/> and the value is bare bytes: whatever a caller lists is what
/// <see cref="TlsQuicTransportParameterSpec.Compose"/> emits, in the order it is listed.
/// </para>
/// <para>THE TWO KINDS EXIST BECAUSE TWO VALUES MUST NOT BE TYPED HERE.
/// <see cref="Placed(ulong)"/> names an identifier without a value; the composer fills it
/// from the one place that owns the number. RFC 9000 s4.1 makes a receiver's limits the ones
/// it advertised, so the six flow-control numbers on the wire and the six
/// <see cref="TlsQuicStreamSet"/> enforces have to be the same numbers, and
/// <c>TlsQuicConnectionSpec.cs</c>'s <c>LocalFlowControl</c> remarks record what happened when
/// they were typed twice. <c>initial_source_connection_id</c> is the connection's actual
/// source connection ID, whose length <c>TlsQuicConnectionSpec.SourceConnectionIdLength</c>
/// already fixes. A literal on any of those seven identifiers is rejected rather than
/// silently preferred - see <see cref="TlsQuicTransportParameterSpec.Compose"/>.</para>
/// <para>A THIRD KIND EXISTS BECAUSE THREE OF THE CAPTURE'S FOURTEEN ARE REDRAWN PER
/// CONNECTION AND NOT PER SPEC. <see cref="Drawn"/> carries a function rather than bytes, and
/// <see cref="TlsQuicTransportParameterSpec.Compose"/> calls it once per composition - so one
/// spec used for two connections puts two different values on the wire, which is what
/// <c>initial_rtt</c>, the reserved parameter's identifier and the GREASE version inside
/// <c>version_information</c> each require. A literal cannot express that: bytes fixed when
/// the list is built are bytes every connection repeats, and a pinned per-connection field is
/// itself a fingerprint. It is a FUNCTION rather than an enum of the three known draws
/// because a client this library has never seen may randomise a field none of the three
/// covers, and an enum would have to be edited to admit it.</para>
/// <para>A READONLY STRUCT rather than a class so an element of a caller-supplied
/// <see cref="ImmutableArray{T}"/> can never be <see langword="null"/>. The default value is
/// <c>Placed(0)</c>, which <see cref="TlsQuicTransportParameterSpec.Compose"/> rejects with a
/// named message because identifier 0 is <c>original_destination_connection_id</c> and nothing
/// places it - so an uninitialised element fails loudly instead of throwing
/// <see cref="NullReferenceException"/>.</para>
/// </remarks>
internal readonly struct TlsQuicTransportParameterSlot : IEquatable<TlsQuicTransportParameterSlot>
{
    private readonly byte[]? _value;
    private readonly Func<TlsQuicConnectionSpec, TlsQuicTransportParameter?>? _draw;

    private TlsQuicTransportParameterSlot(
        ulong id,
        byte[]? value,
        Func<TlsQuicConnectionSpec, TlsQuicTransportParameter?>? draw)
    {
        Id = id;
        _value = value;
        _draw = draw;
    }

    /// <summary>Gets the identifier this entry is emitted under.</summary>
    public ulong Id { get; }

    /// <summary>Gets whether this entry carries its own bytes, as opposed to naming an
    /// identifier whose value <see cref="TlsQuicTransportParameterSpec.Compose"/> places or
    /// carrying a per-connection draw.</summary>
    public bool HasLiteralValue => _value is not null;

    /// <summary>Gets whether this entry's identifier and value are drawn afresh for every
    /// composition rather than fixed when the list was built.</summary>
    public bool IsDrawn => _draw is not null;

    /// <summary>An entry emitting exactly these bytes under this identifier.</summary>
    /// <remarks>No bound on <paramref name="id"/> or on the value's length is applied here:
    /// <see cref="TlsQuicTransportParameter"/>'s constructor already rejects an identifier
    /// above <see cref="QuicVariableLengthInteger.MaximumValue"/> and a value longer than
    /// <see cref="ushort.MaxValue"/>, and restating either bound would give this project two
    /// places to change it.</remarks>
    public static TlsQuicTransportParameterSlot Literal(ulong id, ReadOnlySpan<byte> value) =>
        new(id, value.ToArray(), null);

    /// <summary>An entry naming an identifier whose value is placed by the composer from the
    /// spec that owns it, never typed into the list.</summary>
    public static TlsQuicTransportParameterSlot Placed(ulong id) => new(id, null, null);

    /// <summary>An entry whose identifier and value are produced afresh by
    /// <paramref name="draw"/> on every composition.</summary>
    /// <remarks>
    /// <para>THE FUNCTION IS CALLED ONCE PER <see cref="TlsQuicTransportParameterSpec.Compose"/>
    /// AND ITS RESULT IS NEVER CACHED, which is the entire point: a client that redraws a
    /// field per connection and a client that draws once are different clients on the wire,
    /// and only the second is detectable by anyone who watches two connections.</para>
    /// <para>RETURNING <see langword="null"/> OMITS THE PARAMETER. That is how a caller
    /// expresses "this client sends no <c>initial_rtt</c> at all" without deleting the entry
    /// and losing its position, and it is a decision the caller makes rather than one this
    /// library takes: an absent parameter is as much a fingerprint as a present one.</para>
    /// <para><see cref="Id"/> is zero on this kind, because the identifier is not known until
    /// the draw runs - <see cref="TlsQuicTransportParameterSpec.Compose"/> therefore tests
    /// <see cref="IsDrawn"/> before it looks an identifier up.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="draw"/> is
    /// <see langword="null"/>.</exception>
    public static TlsQuicTransportParameterSlot Drawn(
        Func<TlsQuicConnectionSpec, TlsQuicTransportParameter?> draw)
    {
        ArgumentNullException.ThrowIfNull(draw);
        return new(0, null, draw);
    }

    /// <inheritdoc/>
    /// <remarks>Two drawn entries are equal only when they carry the same function. Comparing
    /// their results instead would make equality nondeterministic, which is the one property
    /// an equality must not have.</remarks>
    public bool Equals(TlsQuicTransportParameterSlot other) =>
        Id == other.Id &&
        _draw == other._draw &&
        (_value is null
            ? other._value is null
            : other._value is not null && _value.AsSpan().SequenceEqual(other._value));

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is TlsQuicTransportParameterSlot other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Id, _value?.Length ?? -1, _draw);

    /// <summary>Compares two entries by identifier and bytes.</summary>
    public static bool operator ==(
        TlsQuicTransportParameterSlot left,
        TlsQuicTransportParameterSlot right) => left.Equals(right);

    /// <summary>Compares two entries by identifier and bytes.</summary>
    public static bool operator !=(
        TlsQuicTransportParameterSlot left,
        TlsQuicTransportParameterSlot right) => !left.Equals(right);

    // Empty for a Placed entry, which is why Compose reads HasLiteralValue rather than this
    // span's length: Literal(id, []) and Placed(id) are different entries and only the first
    // puts a zero-length parameter on the wire.
    internal ReadOnlySpan<byte> LiteralSpan => _value.AsSpan();

    // Runs this entry's draw. Only ever called behind IsDrawn, so the null-forgiving operator
    // is guarded by the branch rather than by an assumption.
    internal TlsQuicTransportParameter? Draw(TlsQuicConnectionSpec connectionSpec) =>
        _draw!(connectionSpec);
}

// ADDING A PARAMETER TO THE PRESET BELOW? THREE THINGS ARE OWED.
//
//   1. CITE THE CAPTURE LINE. Every value in the preset block names the line of
//      docs/superpowers/specs/reference-captures/2026-08-16-brave-151-http3-impersonate-pro.md
//      it came from. A value with no citation is a value nobody can check.
//   2. IF THE CAPTURE CANNOT BOUND IT, MARK IT. The marker's exact form is stated and
//      enforced by TlsQuicTransportParameterSpecTests.EveryUnverifiedPresetChoice
//      NamesATaskThatExistsInTheBPlan, which counts the markers in this file, counts
//      the ones carrying a task reference, and resolves
//      each reference against the B plan's headings. A marker with no task reference,
//      or one naming a task that does not exist, fails that test. Copy the form off an
//      existing marker below rather than from this comment - which deliberately does
//      not spell it, so that this paragraph is not itself counted as a marker.
//   3. PUT THE NUMBER IN THE PRESET BLOCK AND NOWHERE ELSE. Every numeric parameter
//      value in this file is between the "PRESET BLOCK" banner and its end marker.
//
// WHAT THIS FILE DELIBERATELY DOES NOT DO, and the user's design directive that
// settled it: "no placeholder values, everything must be configurable if different
// clients/browsers/apps/systems could send a different value ... the final goal of
// this library is to reproduce pretty much any fingerprint given, if the stack
// allows it." So there is no refusal here. Every parameter a client could vary is a
// settable entry, including the three the capture cannot bound. What the standing
// rule "a constant nobody can check is not allowed" forbids is presenting an
// invented value as measured - not offering a knob. The reconciliation is that the
// values live in a cited preset a caller replaces wholesale, and the unbounded ones
// are marked as unverified rather than omitted.

// TASKS B3, B4 AND B5 - MUTATION LEDGER. 26 rows: 2 controls + 6 B3 + 6 B4 + 8 B5 +
// 4 Compose. 2 + 6 + 6 + 8 + 4 = 26. Killed 25; the single survivor is the harness's
// own inert control, which is what a survivor is supposed to look like.
//
// Swept in a private git worktree at 865fbc8 with only this task's four files copied
// in, because another task was editing TlsQuicFrames.cs in the shared tree at the same
// time and it did not compile there. That task then landed as e95fa3c mid-sweep, which
// is why the gate figures in this commit are measured against e95fa3c and the sweep's
// against 865fbc8: the two commits touch disjoint files, and the pristine gate was
// re-measured at e95fa3c rather than inherited. Every run rebuilt --no-incremental and was
// rejected unless the runner reported at least 1800 executed cases: an aborted run
// prints an ordinary "Failed: 0, Passed: <m>" line and would otherwise be recorded as
// a survivor that never ran. All 26 runs reported 1862.
//
// -- controls, proved before anything else was trusted -- 2 rows --------------------
// C1 IsReservedIdentifier never returns true ......... KILLED    many
// C2 an inert comment added to this class ............ SURVIVED  by construction
//
// -- B3, version_information and the GREASE version -- 6 rows -----------------------
// M01 the GREASE version is the bare fixed pattern ... KILLED  TwoCompositionsOfOneSpec
//     DrawTwoDifferentGreaseVersions
// M02 free nibbles written over the fixed ones ....... KILLED  EveryDrawnGreaseVersion...
// M03 chosen version emitted in place of the drawn one KILLED  TheVersionInformation
//     EmitsTheChosenVersionAndTheAvailableListAndNotTheChosenTwice
//     THE MUTANT THE PLAN NAMES FOR B3. Its length is identical - three 32-bit words
//     either way - so the length check RFC 9368 s10.1 asks for does not see it. What
//     sees it is that the available list's first entry must be reserved under s3's
//     pattern and version 1 is not.
// M04 the draw hoisted out of the delegate and cached  KILLED  TwoCompositionsOfOneSpec...
// M05 the available-versions list reversed ........... KILLED  TheVersionInformation...
// M06 the preset's GREASE slot moved to position 1 ... KILLED  TheVersionInformation...
//
// -- B4, the reserved parameter -- 6 rows -------------------------------------------
// M07 the identifier drawn once and cached ........... KILLED  TwoCompositionsOfOneSpec
//     DrawTwoDifferentReservedIdentifiers
// M08 N emitted as the identifier, s18.1's form lost . KILLED  EveryDrawnReserved...
// M09 s18.1's base 27 -> 28 .......................... KILLED  TheReservedIdentifier...
// M10 s18.1's step 31 -> 32 .......................... KILLED  TheReservedIdentifier...
// M11 the IsDrawn branch made unreachable ............ KILLED  many - reachability
// M12 the preset's N range collapsed to a point ...... KILLED  TwoCompositionsOfOneSpec...
//
// -- B5, initial_rtt -- 8 rows ------------------------------------------------------
// M13 the connection spec's range loses to the entry's KILLED  TheInitialRttRangeIsRead
//     ByTheTransportParameterComposer, and EveryDrawnInitialRtt...
//     THE WIRING ROW. Killed only because the two ranges in those tests are DISJOINT;
//     overlapping ones would have let the swap through, which is the same trap
//     TlsQuicFingerprintReadout.cs's M20 records.
// M14 initial_rtt pinned at its range's minimum ...... KILLED  TwoCompositionsOfOneSpec
//     DrawTwoDifferentInitialRttValues
// M15 the parameter dropped whenever a range exists .. KILLED  ADrawnEntryReturning...
// M16 the range's upper bound made exclusive ......... KILLED  ARangeWhoseBoundsAreEqual
//     EmitsThatValueRatherThanFailing
//     Killed only by that test's second half, the one-microsecond-wide range. Every
//     other assertion in the suite passes against an exclusive bound.
// M17 every draw returns its minimum ................. KILLED  many
// M18 the declared range collapsed to a point ........ KILLED  TheDeclaredInitialRtt...
// M19 the declared range no longer holds 192859 ...... KILLED  TheDeclaredInitialRtt
//     RangeContainsTheCapturesObservedDraw
// M20 the preset stops emitting initial_rtt .......... KILLED  ADrawnEntryReturning...
//
// -- Compose's handling of the drawn kind -- 4 rows ---------------------------------
// M21 the omit branch removed ........................ KILLED  ADrawnEntryReturning
//     NothingOmitsTheParameterAndShortensTheList
// M22 drawn entries appended last, whatever the index  KILLED  ADrawnEntryIsEmittedAt
//     TheIndexItWasListedAtForEveryIndexTried
//     THE MUTANT THE PLAN NAMES FOR B4, and a done-when checking only presence would
//     have passed it. Killed at three of the four indices tried; at index 4 - the end
//     of the list - the mutant is right by accident, which is why the theory has four
//     rows and not one.
// M23 a drawn entry also reports a literal value ..... KILLED  TheDefaultSpecsEntries
//     SplitIntoThreeKindsAndReconcileWithTheCapture
// M24 IsDrawn inverted ............................... KILLED  many
//
// WHAT THE RANDOMISED ROWS ARE WITNESSED BY, AND WHY IT IS NOT LUCK. A test asserting
// that two draws differ can pass against a caching mutant by coincidence, so the
// caching rows are covered twice. TlsQuicTransportParameterSpecTests
// .ComposeRunsADrawnEntrysFunctionOncePerCompositionAndNeverCachesIt uses a counting
// function rather than a random one and yields 1 then 2, so a cached Compose fails it
// with probability 1 and no generator is involved. The three preset draws are then
// each asserted over 32 compositions of ONE spec: a cached draw yields exactly one
// distinct value every time, while the smallest support any of the three has is RFC
// 9368's 16^4 versions, so a correct implementation collides on all 32 with
// probability 65536^-31.

/// <summary>The ordered transport-parameter list a client emits, as identifier/value pairs.
/// Subsystem B populates one of these to imitate a particular browser.</summary>
/// <remarks>
/// <para>THE ONE PLACE IN <c>src/</c> THAT COMPOSES A CLIENT PARAMETER LIST. Before this type
/// there was none: the builder took a list, several call sites parsed and rebuilt somebody
/// else's, and the only code that composed one was a test fixture - so "SharpTls sends eight
/// parameters" was a statement about that fixture and not about this library.</para>
/// <para>ARBITRARY BY CONSTRUCTION, because a fingerprint this library has never seen is the
/// point. <see cref="Parameters"/> accepts any identifiers - registered, unknown,
/// Google-private, reserved - any bytes, any order, and any subset; and
/// <see cref="Compose"/> emits that list unchanged. The two constraints that remain are not
/// this type's: <see cref="TlsQuicTransportParameters"/> rejects a duplicate identifier,
/// which RFC 9000 s18 requires, and caps the count and the encoded length.</para>
/// <para>THE DEFAULT IS THE PRESET, NOT A SET OF PER-PROPERTY DEFAULTS. There are no named
/// value properties on this type to carry a default, which is what stops Brave's numbers from
/// spreading: they exist once, in <see cref="Brave151Parameters"/>, each citing its capture
/// line. This follows <c>TlsQuicHttp3Spec.CaptureSettings</c>.</para>
/// <para>NOTHING READS THIS YET. <see cref="TlsQuicConnectionSpec.TransportParameters"/> holds
/// it and task B8's profile factory is what will pass <see cref="Compose"/>'s output to
/// <c>ClientHelloBuilder.WithQuicTransportParameters</c>; task B11 is the live run. Until
/// then this is a knob that is present and not yet wired, and this paragraph is here because
/// <c>TlsQuicConnectionSpec.cs</c>'s own notice requires an unwired knob to say so and to name
/// the task that wires it.</para>
/// </remarks>
internal sealed class TlsQuicTransportParameterSpec
{
    // ------------------------------------------------------------------------------
    // THE PRESET BLOCK. Every numeric parameter value in this file is below this line
    // and above the "END OF THE PRESET BLOCK" marker; nothing else in this file
    // carries one.
    // ------------------------------------------------------------------------------

    /// <summary>RFC 9000 s18.1's reserved-identifier step, the 31 of "31 * N + 27".</summary>
    /// <remarks>rfc9000-section18-transport-parameters.txt lines 50-53: "Transport parameters
    /// with an identifier of the form <c>31 * N + 27</c> for integer values of N are reserved
    /// to exercise the requirement that unknown transport parameters be ignored. These
    /// transport parameters have no semantics and can carry arbitrary values." Note this is
    /// NOT RFC 9114 s7.2.8's <c>0x1f * N + 0x21</c>, which
    /// <see cref="TlsQuicHttp3Frames.ReservedIdentifier(ulong)"/> implements for HTTP/3
    /// settings and frame types; the two families share a step and differ in base, so reusing
    /// the HTTP/3 helper here would produce identifiers that are not reserved for QUIC.
    /// </remarks>
    internal const ulong ReservedIdentifierStep = 31;

    /// <summary>RFC 9000 s18.1's reserved-identifier base, the 27 of "31 * N + 27".</summary>
    internal const ulong ReservedIdentifierBase = 27;

    /// <summary>One N consistent with the reserved identifier the capture observed. NOT what
    /// this preset emits - the preset draws a fresh N per connection.</summary>
    /// <remarks>
    /// <para>UNVERIFIED, settled by task B12. The capture publishes the reserved parameter's
    /// VALUE - line 80's <c>0xfb</c> - and does not publish its identifier: line 107 prints
    /// only "id ~ 3.7457e18", five significant digits of an identifier that Chromium redraws
    /// per connection. So the capture bounds this to two things and no further - RFC 9000
    /// s18.1's form, and the interval those five digits denote - and MANY N satisfy both.
    /// This is one of them, which is what makes it unverified rather than measured; only a
    /// packet capture, task B12, could name the one Chromium drew.
    /// TlsQuicTransportParameterSpecTests.TheReservedIdentifierIsOfSection18Point1s
    /// FormAndInsideTheCapturesInterval checks the form and the interval by recomputing
    /// both, and checks that the neighbouring N is inside the interval too, so the test
    /// states what the capture leaves open instead of pinning a number it cannot see.</para>
    /// <para>KEPT AS EVIDENCE AND NOT AS A CHOICE. Task B4 replaced this preset's single N
    /// with a per-connection draw over <see cref="MaximumReservedIdentifierN"/>'s whole
    /// range, so nothing is chosen here any more; this constant survives only so the test
    /// above can go on stating what the capture does and does not bound.</para>
    /// </remarks>
    internal const ulong Brave151ReservedIdentifierN = 120829032258064516;

    /// <summary>The reserved (GREASE) transport-parameter identifier the capture's five
    /// significant digits are consistent with. See <see cref="Brave151ReservedIdentifierN"/>
    /// for why this is evidence rather than the preset's emitted value.</summary>
    internal const ulong Brave151ReservedIdentifier =
        (ReservedIdentifierStep * Brave151ReservedIdentifierN) + ReservedIdentifierBase;

    /// <summary>The capture's reserved-parameter value, line 80's <c>0xfb</c>.</summary>
    /// <remarks>Published outright by the capture, unlike the identifier it rides under.
    /// s18.1 says a reserved parameter "can carry arbitrary values", so this single byte is a
    /// choice the capture observed and not a form anything constrains.</remarks>
    private static readonly byte[] Brave151ReservedValue = [0xfb];

    /// <summary>The version <c>version_information</c> chooses, capture line 87's "chosen 1" -
    /// RFC 9000's version 1.</summary>
    /// <remarks>THERE IS NO COMPANION CONSTANT FOR THE GREASE VERSION, and its absence is task
    /// B3's result rather than an omission. Capture line 87 gives <c>version_information</c> as
    /// "chosen 1, available <c>[GREASE, 1]</c>": the chosen version and the list's shape are
    /// published, the GREASE entry's four bytes are not, because the fingerprint string renders
    /// it as a bare token. RFC 9368 s3 bounds it to a pattern -
    /// rfc9368-section3-and-10.1-version-information.txt lines 71-74, "Clients and servers MAY
    /// both include versions following the pattern <c>0x?a?a?a?a</c> in their Available
    /// Versions list. Those versions are reserved to exercise version negotiation ... and will
    /// never be selected when choosing a version to use." A pattern over four nibbles is a set
    /// of exactly 16^4 versions, so B3 draws uniformly from that whole set per connection
    /// rather than choosing one member of it. Nothing is invented, so nothing here is marked
    /// unverified: the SUPPORT is the RFC's, and only the distribution Chromium uses within it
    /// is unknown - which changes no byte a fingerprint service reads, because Finding 3 shows
    /// this half of the parameter is tokenised rather than hashed.</remarks>
    private const uint Brave151ChosenVersion = 1;

    /// <summary><c>google_connection_options</c> (12584)'s value, capture line 79's
    /// <c>0x4f524947</c>, which that line also glosses as ASCII <c>ORIG</c>.</summary>
    /// <remarks>Written as the four characters and encoded to bytes here, so the capture's hex
    /// is what a test derives rather than what it copies - four raw bytes, not a variable-
    /// length integer, since 0x4f524947 exceeds the 2^30-1 a four-byte varint holds and the
    /// capture's value is four bytes on the wire.</remarks>
    private const string Brave151GoogleConnectionOptions = "ORIG";

    /// <summary>The Google-private identifier the capture carries an <c>initial_rtt</c> draw
    /// under, capture line 91. Not an RFC 9000 s18.2 parameter and not in
    /// <see cref="TlsQuicTransportParameterId"/> - there is no specification for it.</summary>
    /// <remarks>THE ONLY DECLARATION OF THIS NUMBER IN <c>src/</c>, AND TASK B10 IS WHAT MADE
    /// IT SO. <c>TlsQuicFingerprintReadout.cs</c> carried a private
    /// <c>InitialRttParameterId</c> holding the same 12583, declared there while the
    /// parameter's ABSENCE was the reported deviation and an absence needed an identity. B5
    /// and B8 turned that absence into a presence, so the readout now cites this constant
    /// instead - the identifier is declared once, in the file that composes the parameter onto
    /// the wire, and read from there by the file that reads it back off.</remarks>
    internal const ulong InitialRttIdentifier = 12583;

    /// <summary>The Google-private identifier the capture carries
    /// <c>google_connection_options</c> under, capture line 79. As with
    /// <see cref="InitialRttIdentifier"/>, no specification defines it.</summary>
    internal const ulong GoogleConnectionOptionsIdentifier = 12584;

    /// <summary>The one <c>initial_rtt</c> draw the capture observed, line 91's 192859
    /// microseconds. NOT what this preset emits - the preset draws afresh per connection.
    /// </summary>
    /// <remarks>Capture line 95: "192859 is not a constant to copy - uQUIC models this as
    /// <c>ChromeRandomInitialRTT()</c>. A fixed value here would itself be a fingerprint." So
    /// this is evidence and not a choice, and task B5 stopped emitting it. It survives because
    /// it is the ONE fact the capture establishes about the distribution - that 192859 is in
    /// its support - which is the only checkable constraint on
    /// <see cref="Brave151InitialRttRange"/> and is what
    /// TlsQuicTransportParameterSpecTests.TheDeclaredInitialRttRangeContainsTheCaptures
    /// ObservedDraw checks.</remarks>
    internal const ulong Brave151InitialRtt = 192859;

    /// <summary>The inclusive range this preset draws <c>initial_rtt</c> from when the
    /// connection spec names none.</summary>
    /// <remarks>
    /// <para>UNVERIFIED, settled by task B12 - and it is the only genuinely invented bound in
    /// this file, which is why it is the one carrying this marker. The reserved identifier and
    /// the GREASE version are drawn over sets RFC 9000 s18.1 and RFC 9368 s3 define, so their
    /// supports are recomputable; <c>initial_rtt</c> is Google-private and no specification
    /// describes it, so nothing outside a capture bounds it. What would settle it is uQUIC's
    /// <c>ChromeRandomInitialRTT()</c>, whose bounds and distribution task B12 acquires
    /// alongside the packet capture.</para>
    /// <para>HOW THESE TWO NUMBERS WERE PICKED, STATED PLAINLY SO NOBODY LATER READS THEM AS
    /// MEASURED: the WIDTH is arbitrary. The single property the capture does establish is
    /// that the range must CONTAIN 192859 microseconds, because that draw happened; these
    /// bounds are the round hundred-millisecond interval either side of it that does. Any
    /// other interval containing it would be equally consistent with the evidence.</para>
    /// <para>SHIPPING AN ARBITRARY WIDTH BEATS BOTH ALTERNATIVES. Refusing to emit the
    /// parameter makes this client distinguishable from Chromium by an absence, and pinning
    /// the capture's single draw makes it distinguishable to anyone who watches two
    /// connections - capture line 95 names that second failure exactly. Finding 3 measured at
    /// commit 4ed90bf that the fingerprint service hashes neither this value nor its absence,
    /// so a wrong width costs nothing at the gate and a pinned value costs everything at a
    /// packet capture.</para>
    /// <para>A KNOB. <c>TlsQuicConnectionSpec.InitialRttRange</c> overrides this per spec, and
    /// the entry itself is one slot a caller replaces with any draw at all.</para>
    /// </remarks>
    internal static readonly (TimeSpan Minimum, TimeSpan Maximum) Brave151InitialRttRange =
        (TimeSpan.FromMicroseconds(100000), TimeSpan.FromMicroseconds(300000));

    /// <summary>The Brave 151 capture's fourteen transport parameters, in the capture's wire
    /// order.</summary>
    /// <remarks>
    /// <para>2026-08-16-brave-151-http3-impersonate-pro.md, the table headed "QUIC transport
    /// parameters, in wire order", lines 79-92 - one entry per line, in the table's order,
    /// which line 74 states is "the fingerprint. It is not sorted, and it is not the RFC's
    /// presentation order."</para>
    /// <para>SEVEN OF THE FOURTEEN ARE <see cref="TlsQuicTransportParameterSlot.Placed(ulong)"/>
    /// AND CARRY NO VALUE HERE: the six flow-control identifiers, whose numbers
    /// <c>TlsQuicLocalFlowControlSpec</c> owns and already cites the same capture rows for, and
    /// <c>initial_source_connection_id</c>, whose value is the connection's own source
    /// connection ID.</para>
    /// <para>THREE MORE ARE <see cref="TlsQuicTransportParameterSlot.Drawn"/> AND CARRY A
    /// FUNCTION RATHER THAN BYTES: rows 2, 9 and 13, the three the capture cannot bound and
    /// which Chromium redraws per connection. 7 placed + 3 drawn + 4 literal = 14, and the
    /// three drawn ones are exactly the three Finding 3 shows the fingerprint string renders
    /// as a bare token instead of hashing.</para>
    /// <para>THE ORDER IS DATA AND NOT CODE. A caller wanting a different client's order
    /// assigns a different <see cref="ImmutableArray{T}"/> to <see cref="Parameters"/>;
    /// nothing in <see cref="Compose"/> knows this order exists.</para>
    /// </remarks>
    internal static readonly ImmutableArray<TlsQuicTransportParameterSlot> Brave151Parameters =
    [
        // 1: line 79, 12584 google_connection_options = 0x4f524947 (ASCII ORIG).
        TlsQuicTransportParameterSlot.Literal(
            GoogleConnectionOptionsIdentifier,
            Encoding.ASCII.GetBytes(Brave151GoogleConnectionOptions)),
        // 2: line 80, a reserved (GREASE) identifier carrying 0xfb. The VALUE is the
        // capture's; the IDENTIFIER is redrawn per connection over the whole of RFC 9000
        // s18.1's reserved set, because line 107 publishes only five significant digits of
        // one connection's draw. The POSITION - second of fourteen - is the part Finding 3
        // measured as hashed, and it is expressed by this entry's index in this list and
        // by nothing else.
        DrawnReservedParameter(0, MaximumReservedIdentifierN, Brave151ReservedValue),
        // 3: line 81, 32 max_datagram_frame_size = 65536.
        TlsQuicTransportParameterSlot.Literal(
            (ulong)TlsQuicTransportParameterId.MaxDatagramFrameSize,
            QuicVariableLengthInteger.Encode(65536)),
        // 4: line 82, 9 initial_max_streams_uni = 103.
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxStreamsUni),
        // 5: line 83, 8 initial_max_streams_bidi = 100.
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxStreamsBidi),
        // 6: line 84, 7 initial_max_stream_data_uni = 6291456.
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataUni),
        // 7: line 85, 5 initial_max_stream_data_bidi_local = 6291456.
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal),
        // 8: line 86, 15 initial_source_connection_id - "empty, consistent with a
        // zero-length source CID", which is what SourceConnectionIdLength's default of 0
        // produces without this entry naming a length of its own.
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId),
        // 9: line 87, 17 version_information - chosen 1, available [GREASE, 1]. The null is
        // the GREASE slot, redrawn per connection; capture line 107 says of both GREASE
        // values "Both are positional", so which entry of the available list is the drawn
        // one is data in this list and not a flag beside it.
        DrawnVersionInformation(
            Brave151ChosenVersion,
            [null, Brave151ChosenVersion]),
        // 10: line 88, 1 max_idle_timeout = 30000.
        TlsQuicTransportParameterSlot.Literal(
            (ulong)TlsQuicTransportParameterId.MaxIdleTimeout,
            QuicVariableLengthInteger.Encode(30000)),
        // 11: line 89, 6 initial_max_stream_data_bidi_remote = 6291456.
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote),
        // 12: line 90, 4 initial_max_data = 15728640.
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxData),
        // 13: line 91, 12583 initial_rtt. NOT 192859 - capture line 95 says that number "is
        // not a constant to copy", so this is a fresh microsecond draw per connection from
        // TlsQuicConnectionSpec.InitialRttRange when that is set and from
        // Brave151InitialRttRange when it is not.
        DrawnInitialRtt(InitialRttIdentifier, Brave151InitialRttRange),
        // 14: line 92, 3 max_udp_payload_size = 1472. NOT PaddingTarget and NOT the
        // transport's ceiling - capture line 103: "Advertised parameter and actual ceiling
        // are separate concerns and must not be wired together." Three numbers, three
        // meanings; no arithmetic between them anywhere in this codebase.
        TlsQuicTransportParameterSlot.Literal(
            (ulong)TlsQuicTransportParameterId.MaxUdpPayloadSize,
            QuicVariableLengthInteger.Encode(1472)),
    ];

    // ------------------------------------------------------------------------------
    // END OF THE PRESET BLOCK.
    // ------------------------------------------------------------------------------

    private readonly ImmutableArray<TlsQuicTransportParameterSlot> _parameters =
        Brave151Parameters;

    /// <summary>Gets the entries this client emits, in the order it emits them.</summary>
    /// <remarks>ANY IDENTIFIER, ANY BYTES, ANY ORDER, ANY SUBSET. Nothing here narrows what a
    /// caller may list; see this type's remarks. The default is
    /// <see cref="Brave151Parameters"/>.</remarks>
    /// <exception cref="ArgumentException">Set to a default-valued
    /// <see cref="ImmutableArray{T}"/>.</exception>
    public ImmutableArray<TlsQuicTransportParameterSlot> Parameters
    {
        get => _parameters;
        init
        {
            // default(ImmutableArray<T>) wraps a null array, so Length, the indexer and the
            // enumerator all throw NullReferenceException - reachable from a hand-populated
            // spec, and the least diagnosable exception in .NET with no ParamName. Rejected
            // the way TlsQuicConnectionSpec rejects the same shape.
            // Witnessed by
            // TlsQuicTransportParameterSpecTests.ADefaultValuedParameterListIsRejected.
            if (value.IsDefault)
            {
                throw new ArgumentException(
                    "A default-valued array carries no elements and no length; pass an empty "
                    + "one to mean a client that sends no transport parameters.",
                    nameof(Parameters));
            }
            _parameters = value;
        }
    }

    /// <summary>The largest N for which RFC 9000 s18.1's "31 * N + 27" still fits a QUIC
    /// variable-length integer, and therefore the top of the reserved set.</summary>
    /// <remarks>NOT A CHOICE AND NOT IN THE PRESET BLOCK, because it is not a value: it is
    /// s18.1's form solved for its own ceiling, recomputed from the two named constants and
    /// <see cref="QuicVariableLengthInteger.MaximumValue"/>. It is what
    /// <see cref="Brave151Parameters"/>' reserved entry draws over, so that entry invents no
    /// range - the support is the whole of the set the RFC defines.</remarks>
    internal const ulong MaximumReservedIdentifierN =
        (QuicVariableLengthInteger.MaximumValue - ReservedIdentifierBase) /
            ReservedIdentifierStep;

    /// <summary>Gets a reserved (GREASE) transport-parameter identifier, RFC 9000 s18.1's
    /// "31 * N + 27".</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="n"/> is large enough that
    /// the identifier would not fit a QUIC variable-length integer.</exception>
    internal static ulong ReservedIdentifier(ulong n)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(n, MaximumReservedIdentifierN, nameof(n));
        return (ReservedIdentifierStep * n) + ReservedIdentifierBase;
    }

    /// <summary>Gets whether an identifier is one RFC 9000 s18.1 reserves.</summary>
    internal static bool IsReservedIdentifier(ulong identifier) =>
        identifier >= ReservedIdentifierBase &&
        (identifier - ReservedIdentifierBase) % ReservedIdentifierStep == 0;

    /// <summary>The nibbles RFC 9368 s3's <c>0x?a?a?a?a</c> pattern fixes - the low one of
    /// each of the four bytes.</summary>
    private const uint ReservedVersionNibbles = 0x0a0a0a0au;

    /// <summary>The nibbles that pattern leaves free, as a mask.</summary>
    private const uint ReservedVersionMask = 0x0f0f0f0fu;

    /// <summary>How many values one free nibble takes, and therefore the exclusive bound a
    /// draw over it uses.</summary>
    private const int NibbleValues = 16;

    /// <summary>Gets whether a QUIC version matches RFC 9368 s3's <c>0x?a?a?a?a</c> reserved
    /// pattern - the low nibble of each of the four bytes is <c>a</c>.</summary>
    internal static bool IsReservedVersion(uint version) =>
        (version & ReservedVersionMask) == ReservedVersionNibbles;

    /// <summary>Draws one version uniformly from RFC 9368 s3's reserved pattern.</summary>
    /// <remarks>FOUR INDEPENDENT NIBBLES AND NOT ONE NUMBER, so the size of the set drawn from
    /// is the pattern's own arithmetic - four free nibbles of
    /// <see cref="NibbleValues"/> values each - rather than a literal restating it. The fixed
    /// nibbles are OR-ed in afterwards from the same constant
    /// <see cref="IsReservedVersion(uint)"/> tests against, so a draw that stopped matching the
    /// predicate would have to disagree with itself.</remarks>
    private static uint DrawReservedVersion()
    {
        var version = ReservedVersionNibbles;
        // The free nibble of each byte sits four bits above that byte's fixed one.
        for (var shift = 4; shift < sizeof(uint) * 8; shift += 8)
        {
            version |= (uint)Random.Shared.Next(0, NibbleValues) << shift;
        }
        return version;
    }

    // One inclusive draw, used by every factory below so that the degenerate case is decided
    // once: minimum == maximum yields that value rather than reaching Random with an empty
    // interval. Witnessed for initial_rtt by
    // TlsQuicTransportParameterSpecTests.ARangeWhoseBoundsAreEqualEmitsThatValue
    // RatherThanFailing, whose second half also witnesses the inclusive upper bound.
    private static ulong DrawInclusive(ulong minimum, ulong maximum) =>
        minimum >= maximum
            ? minimum
            : minimum + (ulong)Random.Shared.NextInt64(0, (long)(maximum - minimum) + 1);

    /// <summary>Encodes RFC 9368 s3's Figure 2 - a Chosen Version, then the Available Versions
    /// - as the value of a <c>version_information</c> parameter.</summary>
    /// <remarks>rfc9368-section3-and-10.1-version-information.txt lines 35-38: "Version
    /// Information { Chosen Version (32), Available Versions (32) ..., }". Both fields are
    /// 32-bit, and QUIC's long-header Version field is big-endian, which is the order
    /// <see cref="TlsQuicTransportParameters"/>' own <c>ValidateVersionInformation</c> reads
    /// them back in.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="availableVersions"/> is
    /// <see langword="null"/>.</exception>
    internal static byte[] EncodeVersionInformation(
        uint chosenVersion,
        IReadOnlyList<uint> availableVersions)
    {
        ArgumentNullException.ThrowIfNull(availableVersions);
        var encoded = new byte[sizeof(uint) * (1 + availableVersions.Count)];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(encoded, chosenVersion);
        for (var index = 0; index < availableVersions.Count; index++)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
                encoded.AsSpan(sizeof(uint) * (1 + index)),
                availableVersions[index]);
        }
        return encoded;
    }

    // ------------------------------------------------------------------------------
    // The three per-connection draws, as named entries a caller parameterises. Each is
    // an ordinary element of the ordered list and carries no index of its own: C3's
    // precedent, restated by the B plan for the reserved parameter - "a list already
    // says both and a flag-plus-index is a second weaker way to say the same thing that
    // can disagree with the list."
    //
    // A CALLER WHO WANTS A DRAW NONE OF THE THREE DESCRIBES DOES NOT NEED ONE OF THESE.
    // TlsQuicTransportParameterSlot.Drawn takes any function at all; these three exist
    // because they are the three the capture shows Chromium making, not because the
    // seam is limited to them.
    // ------------------------------------------------------------------------------

    /// <summary>An entry emitting <paramref name="value"/> under an RFC 9000 s18.1 reserved
    /// identifier drawn afresh per connection from the N in
    /// <paramref name="minimumN"/>..<paramref name="maximumN"/> inclusive.</summary>
    /// <remarks>s18.1, rfc9000-section18-transport-parameters.txt lines 50-53: identifiers of
    /// the form "31 * N + 27" are "reserved to exercise the requirement that unknown transport
    /// parameters be ignored. These transport parameters have no semantics and can carry
    /// arbitrary values." Both halves matter here - the form is what
    /// <see cref="ReservedIdentifier(ulong)"/> computes, and "arbitrary values" is why the
    /// value is a caller's bytes and not something this method derives.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is
    /// <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maximumN"/> exceeds
    /// <see cref="MaximumReservedIdentifierN"/>, or <paramref name="minimumN"/> exceeds
    /// <paramref name="maximumN"/>.</exception>
    internal static TlsQuicTransportParameterSlot DrawnReservedParameter(
        ulong minimumN,
        ulong maximumN,
        byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            maximumN, MaximumReservedIdentifierN, nameof(maximumN));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(minimumN, maximumN, nameof(minimumN));

        // Copied once here rather than on every draw: the array is this method's private
        // state from now on, so a caller mutating theirs afterwards cannot change what a
        // later connection emits.
        var bytes = value.ToArray();
        return TlsQuicTransportParameterSlot.Drawn(_ => new TlsQuicTransportParameter(
            ReservedIdentifier(DrawInclusive(minimumN, maximumN)),
            bytes));
    }

    /// <summary>A <c>version_information</c> entry whose available-versions list is
    /// <paramref name="availableVersions"/>, with every <see langword="null"/> element drawn
    /// afresh per connection from RFC 9368 s3's reserved pattern.</summary>
    /// <remarks>THE NULLS ARE POSITIONS AND THAT IS DELIBERATE. Capture line 107, of the
    /// GREASE transport parameter and the GREASE version alike: "Both are positional." So
    /// which entry of the available list is the drawn one is expressed by where the null sits
    /// in this list, exactly as the reserved parameter's position is expressed by where its
    /// entry sits in <see cref="Parameters"/>; there is no separate index to disagree with
    /// it.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="availableVersions"/> is
    /// <see langword="null"/>.</exception>
    internal static TlsQuicTransportParameterSlot DrawnVersionInformation(
        uint chosenVersion,
        IReadOnlyList<uint?> availableVersions)
    {
        ArgumentNullException.ThrowIfNull(availableVersions);
        var pattern = availableVersions.ToArray();
        return TlsQuicTransportParameterSlot.Drawn(_ =>
        {
            var versions = new uint[pattern.Length];
            for (var index = 0; index < pattern.Length; index++)
            {
                versions[index] = pattern[index] ?? DrawReservedVersion();
            }
            return new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.VersionInformation,
                EncodeVersionInformation(chosenVersion, versions));
        });
    }

    /// <summary>An <c>initial_rtt</c> entry carrying a microsecond value drawn afresh per
    /// connection from <c>TlsQuicConnectionSpec.InitialRttRange</c>, or from
    /// <paramref name="fallbackRange"/> when the connection spec names none.</summary>
    /// <remarks>
    /// <para>TWO KNOBS AND NOT ONE, because they answer different questions. The connection
    /// spec's range is the caller's policy for a particular connection and wins whenever it is
    /// set; this entry's fallback is what the preset that contains the entry believes about
    /// the client it imitates. A client whose ranges differ per profile therefore needs no
    /// edit to the connection spec.</para>
    /// <para>BOTH NULL MEANS THE PARAMETER IS ABSENT, and absence is a position this seam lets
    /// a caller take rather than one it takes for them: a client that sends no
    /// <c>initial_rtt</c> is a real client, and so is one that sends a drawn one. The preset
    /// here passes a non-null fallback, so the Brave profile always emits it.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="fallbackRange"/>'s
    /// minimum is not positive, or its maximum is below its minimum - the same bounds
    /// <c>TlsQuicConnectionSpec.InitialRttRange</c> enforces, so the two cannot accept
    /// different things.</exception>
    internal static TlsQuicTransportParameterSlot DrawnInitialRtt(
        ulong identifier,
        (TimeSpan Minimum, TimeSpan Maximum)? fallbackRange)
    {
        if (fallbackRange is { } declared)
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(
                declared.Minimum, TimeSpan.Zero, nameof(fallbackRange));
            ArgumentOutOfRangeException.ThrowIfLessThan(
                declared.Maximum, declared.Minimum, nameof(fallbackRange));
        }

        return TlsQuicTransportParameterSlot.Drawn(connectionSpec =>
        {
            if ((connectionSpec.InitialRttRange ?? fallbackRange) is not { } range)
            {
                return null;
            }
            var microseconds = DrawInclusive(
                (ulong)(range.Minimum.Ticks / TimeSpan.TicksPerMicrosecond),
                (ulong)(range.Maximum.Ticks / TimeSpan.TicksPerMicrosecond));
            return new TlsQuicTransportParameter(
                identifier,
                QuicVariableLengthInteger.Encode(microseconds));
        });
    }

    /// <summary>Composes <see cref="Parameters"/> into the encodable set, placing the values
    /// this spec deliberately does not carry.</summary>
    /// <remarks>
    /// <para>THE LIST IS EMITTED AS GIVEN. Identifiers, values and order all pass through
    /// unchanged; no entry is added, reordered or defaulted. The only entries this method
    /// supplies a value for are the ones that asked it to, by being
    /// <see cref="TlsQuicTransportParameterSlot.Placed(ulong)"/> or
    /// <see cref="TlsQuicTransportParameterSlot.Drawn"/> - and the only entry that can be
    /// REMOVED is a drawn one whose own function returned <see langword="null"/>, which is
    /// the caller's list saying "omit this", not this method editing it.</para>
    /// <para>WHAT IT PLACES, AND FROM WHERE. The six flow-control values come from
    /// <paramref name="connectionSpec"/>'s <c>LocalFlowControl</c> - by calling its
    /// <c>ToTransportParameters</c>, so the bytes on the wire are literally the ones that spec
    /// emits and a divergence cannot be typed into existence. Which six they are is read out
    /// of that call's result rather than listed here, so adding a seventh there needs no edit
    /// here. <c>initial_source_connection_id</c> takes
    /// <paramref name="sourceConnectionId"/>.</para>
    /// <para>WHY A LITERAL ON A PLACED IDENTIFIER IS REFUSED RATHER THAN PREFERRED. RFC 9000
    /// s4.1 makes the limit a receiver enforces the one it advertised, so a typed
    /// <c>initial_max_data</c> would advertise one number while <c>TlsQuicStreamSet</c>
    /// enforced another - a divergence that produces a connection error under load and nothing
    /// at all during a handshake test. The knob still exists; it is
    /// <c>TlsQuicConnectionSpec.LocalFlowControl</c>, and it is fully settable. This refusal
    /// is about which of two places owns the number, not about whether it can be
    /// changed.</para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="connectionSpec"/> is
    /// <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="sourceConnectionId"/>'s length is
    /// not <paramref name="connectionSpec"/>'s <c>SourceConnectionIdLength</c>; or an entry
    /// carries a literal for an identifier this method places; or an entry is
    /// <see cref="TlsQuicTransportParameterSlot.Placed(ulong)"/> under an identifier nothing
    /// places.</exception>
    public TlsQuicTransportParameters Compose(
        TlsQuicConnectionSpec connectionSpec,
        ReadOnlySpan<byte> sourceConnectionId)
    {
        ArgumentNullException.ThrowIfNull(connectionSpec);

        // RFC 9000 s7.3: "If a zero-length connection ID is selected, the corresponding
        // transport parameter is included with a zero-length value." The parameter carries
        // the connection's actual source connection ID, and SourceConnectionIdLength is what
        // fixes that ID's length - so a mismatch here is a spec disagreeing with itself, and
        // emitting either one silently would put a connection ID on the wire that the Initial
        // packet's own Source Connection ID field contradicts.
        // Witnessed by TlsQuicTransportParameterSpecTests.ASourceConnectionIdThatIs
        // NotTheSpecsDeclaredLengthIsRejected.
        if (sourceConnectionId.Length != connectionSpec.SourceConnectionIdLength)
        {
            throw new ArgumentException(
                $"The source connection ID is {sourceConnectionId.Length} bytes but the "
                + $"connection spec declares {connectionSpec.SourceConnectionIdLength}.",
                nameof(sourceConnectionId));
        }

        var placed = new Dictionary<ulong, byte[]>();
        foreach (var parameter in connectionSpec.LocalFlowControl.ToTransportParameters())
        {
            placed[parameter.Id] = parameter.Value;
        }
        placed[(ulong)TlsQuicTransportParameterId.InitialSourceConnectionId] =
            sourceConnectionId.ToArray();

        var composed = new List<TlsQuicTransportParameter>(_parameters.Length);
        foreach (var slot in _parameters)
        {
            // FIRST, AND ONCE PER CALL. A drawn entry's identifier is not known until its
            // function has run, so it cannot be looked up in `placed` beforehand; and the
            // result is added straight to the list at this position rather than appended
            // afterwards, which is what makes a drawn entry's place in the wire order the
            // place its caller listed it. Witnessed by
            // TlsQuicTransportParameterSpecTests.ADrawnEntryIsEmittedAtTheIndexItWas
            // ListedAtForEveryIndexTried.
            if (slot.IsDrawn)
            {
                var drawn = slot.Draw(connectionSpec);
                // Witnessed by TlsQuicTransportParameterSpecTests.ADrawnEntryReturning
                // NothingOmitsTheParameterAndShortensTheList.
                if (drawn is not null)
                {
                    composed.Add(drawn);
                }
                continue;
            }
            if (placed.TryGetValue(slot.Id, out var placedValue))
            {
                // Witnessed once per placed identifier by
                // TlsQuicTransportParameterSpecTests.ALiteralValueForAnIdentifierThis
                // SpecPlacesIsRejected.
                if (slot.HasLiteralValue)
                {
                    throw new ArgumentException(
                        $"Transport parameter 0x{slot.Id:X} takes its value from the "
                        + "connection spec and must be listed with "
                        + $"{nameof(TlsQuicTransportParameterSlot)}."
                        + $"{nameof(TlsQuicTransportParameterSlot.Placed)}.",
                        nameof(Parameters));
                }
                composed.Add(new TlsQuicTransportParameter(slot.Id, placedValue));
                continue;
            }
            // Witnessed by TlsQuicTransportParameterSpecTests.APlacedEntryUnderAn
            // IdentifierNothingPlacesIsRejected, and by
            // TlsQuicTransportParameterSpecTests.ADefaultValuedEntryIsRejectedRather
            // ThanEmittingIdentifierZero for the uninitialised-struct path into the
            // same branch.
            if (!slot.HasLiteralValue)
            {
                throw new ArgumentException(
                    $"Transport parameter 0x{slot.Id:X} is listed without a value, but "
                    + "nothing places a value for it.",
                    nameof(Parameters));
            }
            composed.Add(new TlsQuicTransportParameter(slot.Id, slot.LiteralSpan));
        }

        return new TlsQuicTransportParameters(composed);
    }
}
