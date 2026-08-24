using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;

namespace SharpTls.Quic;

/// <summary>One entry in a client's transport-parameter list: an identifier, and either the
/// bytes to emit under it or a declaration that the value is placed here from elsewhere.
/// </summary>
/// <remarks>
/// <para>AN IDENTIFIER/VALUE PAIR AND NOT A NAMED PROPERTY, because the wire order IS the
/// fingerprint: a client's transport-parameter list is neither sorted nor in the RFC's
/// presentation order, and which order it is in identifies it. A set of named properties has no
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

// THERE IS NO PRESET IN THIS FILE ANY MORE, AND THAT IS THE RULE.
//
//   1. NO PERSONA LIVES HERE. This file used to carry a captured browser's fourteen
//      parameters as the DEFAULT for every spec, each value citing the capture line it
//      came from. A persona's values, its wire order and its citations now live in the
//      preset that measured it, and the default here is RfcMinimumParameters: RFC 9000
//      s7.3's single mandatory initial_source_connection_id and nothing else.
//   2. NO NUMBER WITHOUT A SPECIFICATION. What may still be written in this file is a
//      value a specification defines - an identifier, a bound, a form - because that is
//      recomputable by a reader. A number that is somebody's measurement is a preset's,
//      and a number that is neither is the placeholder the standing rule forbids.
//   3. THE KNOBS STAY OPEN. Removing the persona removed no capability: Parameters
//      still accepts any identifier, any bytes, any order and any subset, and the three
//      drawn families - reserved parameter, version_information, initial_rtt - are still
//      here as factories a preset calls.
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
/// value properties on this type to carry a default, which is what stops one client's numbers
/// from spreading: a persona's values exist once, in the preset that measured them, each citing its capture
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
    // THE PRESET BLOCK IS GONE, AND ITS ABSENCE IS THE DESIGN.
    //
    // This file used to carry a captured browser's fourteen transport parameters as the
    // DEFAULT for every TlsQuicTransportParameterSpec - its Google-private connection-options
    // string, its GREASE parameter, its max_datagram_frame_size, its max_idle_timeout, its
    // max_udp_payload_size and its version_information. A bare TlsQuicConnectionSpec therefore
    // dialled as that browser, and any persona that did not override a field inherited that
    // browser's value for it without saying so.
    //
    // SharpTls now ships NO captured persona at all. What is left below is identifiers that
    // RFC 9000 and the Google-private registry DEFINE - facts recomputable from a
    // specification rather than measurements of somebody's client - and a default list holding
    // the one parameter RFC 9000 s7.3 makes mandatory. A persona is a preset's whole
    // responsibility; nothing here supplies half of one, which is what makes an unset field a
    // visible omission instead of an inherited stranger.
    // ------------------------------------------------------------------------------


    internal const ulong ReservedIdentifierStep = 31;

    /// <summary>RFC 9000 s18.1's reserved-identifier base, the 27 of "31 * N + 27".</summary>
    internal const ulong ReservedIdentifierBase = 27;

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

    /// <summary>
    /// The default list: RFC 9000 section 7.3's mandatory <c>initial_source_connection_id</c>,
    /// and nothing else.
    /// </summary>
    /// <remarks>
    /// <para>ONE ENTRY, BECAUSE ONE IS MANDATORY. s7.3: "The client MUST include the
    /// initial_source_connection_id transport parameter", and a server that does not receive it
    /// closes with TRANSPORT_PARAMETER_ERROR. Every other parameter has an s18.2 default that
    /// applies when it is absent, so a list of exactly this length is the shortest one a
    /// conforming client can send.</para>
    /// <para>IT IS NOT A PERSONA AND IS NOT MEANT TO BE ONE. A connection built on this default
    /// is conformant and anonymous - it looks like nothing in particular, which is the honest
    /// state for a library that has not been told who to imitate. Presets supply the rest.</para>
    /// </remarks>
    internal static readonly ImmutableArray<TlsQuicTransportParameterSlot> RfcMinimumParameters =
    [
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId),
    ];

    // ------------------------------------------------------------------------------
    // END OF THE IDENTIFIER BLOCK.
    // ------------------------------------------------------------------------------

    private readonly ImmutableArray<TlsQuicTransportParameterSlot> _parameters =
        RfcMinimumParameters;

    private readonly int _cyclicRotationLength;

    /// <summary>
    /// How many leading entries of <see cref="Parameters"/> rotate cyclically, by an offset
    /// redrawn for every connection. Zero - the default - emits the list as written.
    /// </summary>
    /// <remarks>
    /// <para>A LENGTH RATHER THAN A BOOLEAN, because the capture that needs it does not rotate
    /// the whole list. The Spotify iOS capture's 91 connections produced exactly seven
    /// transport-parameter orders and every one was a cyclic rotation of one sequence - never a
    /// shuffle, which would have drawn from 7! = 5040 - while its Google-private
    /// <c>0xff080808</c> sat LAST in 4 of 4 proxy captures regardless of where the rotation
    /// started. So seven entries rotate and the eighth does not, and only a length can say
    /// that.</para>
    /// <para>REDRAWN PER CONNECTION, WHICH IS THE WHOLE POINT. Rotating once when the options
    /// object is built gives every connection in a pooled session the same order: one of seven
    /// rather than one of one, but still a constant for the life of the session, and a peer
    /// that sees two connections sees the same order twice where the real client shows two.
    /// <see cref="Compose"/> runs once per connection, from
    /// <c>TlsQuicClientHelloProfileFactory.Create</c>, which is where the offset now comes
    /// from.</para>
    /// <para>THE ROTATION IS OF SLOTS, NOT OF COMPOSED VALUES, so a drawn entry still draws at
    /// the position it lands in and a placed entry still takes its value from the connection
    /// spec. Rotating afterwards would reorder a list a drawn entry may already have shortened
    /// by returning null.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    public int CyclicRotationLength
    {
        get => _cyclicRotationLength;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value, nameof(CyclicRotationLength));
            _cyclicRotationLength = value;
        }
    }

    /// <summary>This connection's slot order: the list as written, with its first
    /// <see cref="CyclicRotationLength"/> entries rotated by a freshly drawn offset.</summary>
    private ImmutableArray<TlsQuicTransportParameterSlot> RotateForThisConnection()
    {
        var length = _cyclicRotationLength;
        if (length > _parameters.Length)
        {
            throw new InvalidOperationException(
                $"{nameof(CyclicRotationLength)} is {length} but "
                + $"{nameof(Parameters)} has {_parameters.Length} entries. The rotating block "
                + "cannot be longer than the list it is the front of.");
        }

        // A rotation of one is the identity, and so is an offset of zero. Both are answered
        // without allocating rather than by building a copy of the same order.
        if (length < 2)
        {
            return _parameters;
        }

        var offset = RandomNumberGenerator.GetInt32(length);
        if (offset == 0)
        {
            return _parameters;
        }

        var rotated = ImmutableArray.CreateBuilder<TlsQuicTransportParameterSlot>(
            _parameters.Length);
        for (var i = 0; i < length; i++)
        {
            rotated.Add(_parameters[(i + offset) % length]);
        }
        for (var i = length; i < _parameters.Length; i++)
        {
            rotated.Add(_parameters[i]);
        }

        return rotated.MoveToImmutable();
    }

    /// <summary>Gets the entries this client emits, in the order it emits them.</summary>
    /// <remarks>ANY IDENTIFIER, ANY BYTES, ANY ORDER, ANY SUBSET. Nothing here narrows what a
    /// caller may list; see this type's remarks. The default is
    /// a preset's own list.</remarks>
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
    /// a preset's reserved entry draws over, so that entry invents no
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
    private static ulong DrawInclusive(ulong minimum, ulong maximum)
    {
        if (minimum >= maximum)
        {
            return minimum;
        }

        var span = maximum - minimum;

        // THE NARROW PATH IS THE ONLY ONE ANY CALLER IN THIS FILE TAKES, and it used to be the
        // only one there was: `(long)(maximum - minimum) + 1`. NextInt64's exclusive bound is a
        // long, so a span at or above long.MaxValue casts NEGATIVE and NextInt64 throws - the
        // failure is an ArgumentOutOfRangeException naming a bound the caller never wrote.
        // MaximumReservedIdentifierN is about 1.49e17 and every other range here is smaller, so
        // no shipped preset can reach it. But Parameters accepts ANY identifier by design - see
        // this type's "ARBITRARY BY CONSTRUCTION" remarks - so a caller can, and a knob that
        // throws on a legal argument is not a knob.
        if (span < long.MaxValue)
        {
            return minimum + (ulong)Random.Shared.NextInt64(0, (long)span + 1);
        }

        Span<byte> bytes = stackalloc byte[8];
        RandomNumberGenerator.Fill(bytes);
        var draw = BinaryPrimitives.ReadUInt64LittleEndian(bytes);

        // span == ulong.MaxValue means every ulong is in range, so the draw IS the answer.
        // Taking the general path instead would compute span + 1, which wraps to zero, and
        // divide by it.
        return span == ulong.MaxValue ? draw : minimum + (draw % (span + 1));
    }

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
    /// here passes a non-null fallback, so a preset that wants the parameter emitted
    /// unconditionally supplies one.</para>
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

    /// <summary>Whether this list emits <paramref name="id"/> at all.</summary>
    /// <remarks>
    /// <para>THE QUESTION ENFORCEMENT HAS TO ASK BEFORE IT ENFORCES. <see cref="Compose"/> emits
    /// a flow-control parameter only when a <see cref="TlsQuicTransportParameterSlot.Placed"/>
    /// slot names it, and a list that names none of them is a legal list - the Spotify capture
    /// carries seven parameters and <c>initial_max_streams_bidi</c> (0x08) is not one of them.
    /// RFC 9000 s18.2 then makes the peer's understanding of that limit ZERO, while
    /// <c>TlsQuicLocalFlowControlSpec</c> still held the spec's default of 100 and
    /// <c>TlsQuicStreamSet</c> still enforced it. That is a limit policed but never advertised,
    /// which is exactly the divergence TlsQuicStreams.cs's block comment says must not
    /// happen.</para>
    /// <para>DRAWN SLOTS ANSWER FALSE, DELIBERATELY. A drawn entry's identifier is not known
    /// until its function runs, so it cannot be answered for statically - and
    /// <see cref="Compose"/> refuses outright to let a drawn entry emit an identifier this
    /// method places, so the false is not an approximation but the truth.</para>
    /// </remarks>
    internal bool Places(ulong id)
    {
        foreach (var slot in _parameters)
        {
            if (!slot.IsDrawn && slot.Id == id)
            {
                return true;
            }
        }

        return false;
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
        foreach (var slot in RotateForThisConnection())
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
                    // THE OTHER WAY INTO THE ADVERTISE/ENFORCE SPLIT, closed here because it is
                    // the only place it is visible. A literal under a placed identifier is
                    // rejected below on the grounds that two places would own one number; a
                    // DRAWN entry returning the same identifier would slip past that check,
                    // because its identifier is not known until its function has run. The
                    // result would be a flow-control limit on the wire that came from a
                    // draw while TlsQuicStreamSet enforced the one on LocalFlowControl.
                    if (placed.ContainsKey(drawn.Id))
                    {
                        throw new ArgumentException(
                            $"A drawn transport-parameter entry returned 0x{drawn.Id:X}, which "
                            + "takes its value from the connection spec. Drawn entries cannot "
                            + "emit a placed identifier: the value on the wire and the value "
                            + $"{nameof(TlsQuicConnectionSpec)} enforces would be two different "
                            + "numbers.",
                            nameof(Parameters));
                    }

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
