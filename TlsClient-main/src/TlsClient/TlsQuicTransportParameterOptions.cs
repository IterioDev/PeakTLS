using System.Collections.Immutable;
using SharpTls.Quic;

namespace TlsClient;

/// <summary>
/// One slot in the QUIC transport-parameter list: an identifier, and either literal bytes, a
/// per-connection draw, or nothing at all when the connection supplies the value.
/// </summary>
/// <remarks>
/// <para>THE IDENTIFIER IS A BARE <see cref="ulong"/> AND THE VALUE IS BARE BYTES. That is the
/// point of this type. A real capture carries identifiers no registry lists — the Brave 151
/// capture has the two Google-private ones (12583, 12584) and a reserved GREASE identifier
/// redrawn per connection — so nothing here narrows what a caller may list. Any identifier,
/// any bytes, any order, any subset, duplicates included (SharpTls rejects duplicate
/// identifiers at compose time, as RFC 9000 section 18 requires).</para>
/// <para>THREE KINDS EXIST BECAUSE SOME VALUES MUST NOT BE TYPED BY THE CALLER.
/// <see cref="Placed"/> names an identifier whose value the connection owns — the six
/// flow-control limits and <c>initial_source_connection_id</c>, whose numbers live in
/// <see cref="TlsQuicFlowControlOptions"/> and <see cref="TlsQuicOptions.SourceConnectionIdLength"/>
/// and would otherwise be typed twice. <see cref="Drawn(ulong, Func{byte[]})"/> carries a function called once per
/// connection rather than once per configuration, which is what a client that redraws a GREASE
/// identifier or a jittered <c>initial_rtt</c> on every connection requires.</para>
/// <para>A CLASS RATHER THAN A STRUCT so an element of a caller's list can never be a
/// silently-wrong default value; a null element is rejected by name at snapshot time.</para>
/// </remarks>
public sealed class TlsQuicTransportParameterEntry
{
    private TlsQuicTransportParameterEntry(ulong id, TlsQuicTransportParameterSlot slot)
    {
        Id = id;
        Slot = slot;
    }

    /// <summary>Gets the identifier this entry is emitted under.</summary>
    public ulong Id { get; }

    /// <summary>Gets whether this entry carries its own bytes.</summary>
    public bool HasLiteralValue => Slot.HasLiteralValue;

    /// <summary>Gets whether this entry redraws its value on every connection.</summary>
    public bool IsDrawn => Slot.IsDrawn;

    /// <summary>
    /// Gets whether the connection supplies this entry's value — a <see cref="Placed"/> entry.
    /// </summary>
    public bool IsPlaced => !HasLiteralValue && !IsDrawn;

    /// <summary>The SharpTls slot this entry wraps, one-to-one and losslessly.</summary>
    internal TlsQuicTransportParameterSlot Slot { get; }

    /// <summary>Creates an entry carrying exact bytes under an exact identifier.</summary>
    /// <param name="id">Any identifier a QUIC variable-length integer can hold.</param>
    /// <param name="value">The value's exact bytes, emitted verbatim.</param>
    public static TlsQuicTransportParameterEntry Literal(ulong id, ReadOnlySpan<byte> value) =>
        new(id, TlsQuicTransportParameterSlot.Literal(id, value));

    /// <summary>
    /// Creates an entry naming an identifier whose value the connection places — the six
    /// flow-control limits and <c>initial_source_connection_id</c>.
    /// </summary>
    /// <param name="id">The identifier to place a value under.</param>
    public static TlsQuicTransportParameterEntry Placed(ulong id) =>
        new(id, TlsQuicTransportParameterSlot.Placed(id));

    /// <summary>
    /// Creates an entry whose bytes are drawn afresh for every connection. Return
    /// <see langword="null"/> from <paramref name="draw"/> to omit the entry on that
    /// connection.
    /// </summary>
    /// <param name="id">The identifier the drawn bytes are emitted under.</param>
    /// <param name="draw">Called once per connection, never cached.</param>
    /// <exception cref="ArgumentNullException"><paramref name="draw"/> is null.</exception>
    public static TlsQuicTransportParameterEntry Drawn(ulong id, Func<byte[]?> draw)
    {
        ArgumentNullException.ThrowIfNull(draw);
        return new(
            id,
            TlsQuicTransportParameterSlot.Drawn(
                _ => draw() is { } drawn ? new TlsQuicTransportParameter(id, drawn) : null));
    }

    /// <summary>
    /// Creates an entry whose identifier is also drawn per connection, for reproducing a
    /// client that redraws a GREASE identifier as well as its value.
    /// </summary>
    /// <param name="draw">
    /// Called once per connection, returning the identifier and bytes to emit, or
    /// <see langword="null"/> to omit the entry on that connection.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="draw"/> is null.</exception>
    public static TlsQuicTransportParameterEntry Drawn(Func<(ulong Id, byte[] Value)?> draw)
    {
        ArgumentNullException.ThrowIfNull(draw);
        return new(
            0,
            TlsQuicTransportParameterSlot.Drawn(
                _ => draw() is { } drawn
                    ? new TlsQuicTransportParameter(drawn.Id, drawn.Value)
                    : null));
    }

    /// <summary>Wraps a preset slot, preserving a draw whose function SharpTls owns.</summary>
    internal static TlsQuicTransportParameterEntry FromSlot(TlsQuicTransportParameterSlot slot) =>
        new(slot.Id, slot);
}

/// <summary>
/// Configures the QUIC transport parameters as an ordered list of slots — the shape SharpTls's
/// <c>TlsQuicTransportParameterSpec</c> uses, mirrored rather than flattened.
/// </summary>
/// <remarks>
/// <para>WIRE ORDER IS FINGERPRINTED, SO IT IS THE SHAPE OF THIS API. The reference endpoint
/// publishes both <c>perk_hash</c> (raw wire order) and <c>perk_hash_normalized</c> (sorted by
/// identifier) for the same parameter set, which makes any reordering — including a helpful
/// sort — independently detectable. A named-property design could express neither order nor an
/// unknown identifier, so there is deliberately no such design here.</para>
/// <para><see cref="Entries"/> starts as the Brave 151 capture's fourteen slots, read from
/// SharpTls's preset rather than re-typed, and is mutable in place: reorder it, delete from it,
/// insert a <see cref="TlsQuicTransportParameterEntry.Literal"/> of an identifier this library
/// has never heard of, and those exact bytes go out in that exact position.</para>
/// </remarks>
public sealed class TlsQuicTransportParameterOptions
{
    // Not a const: see TlsQuicOptions.AlpnParameter for why CA2208 needs a field here.
    private static readonly string EntriesParameter = nameof(Entries);

    /// <summary>
    /// Gets or sets the transport parameters, in exact wire order. The default is the Brave 151
    /// capture's fourteen entries — seven placed, four literal and three drawn.
    /// </summary>
    public IList<TlsQuicTransportParameterEntry> Entries { get; set; } =
        [.. TlsQuicTransportParameterSpec.Brave151Parameters
            .Select(TlsQuicTransportParameterEntry.FromSlot)];

    /// <summary>Builds the SharpTls spec, rejecting a null list or a null element by name.</summary>
    internal TlsQuicTransportParameterSpec Snapshot()
    {
        ArgumentNullException.ThrowIfNull(Entries, nameof(Entries));
        var slots = ImmutableArray.CreateBuilder<TlsQuicTransportParameterSlot>(Entries.Count);
        for (var index = 0; index < Entries.Count; index++)
        {
            var entry = Entries[index];
            if (entry is null)
            {
                throw new ArgumentException(
                    $"{EntriesParameter}[{index}] is null; every transport parameter entry "
                        + "must be a Literal, Placed or Drawn entry.",
                    EntriesParameter);
            }
            slots.Add(entry.Slot);
        }
        return new TlsQuicTransportParameterSpec { Parameters = slots.DrainToImmutable() };
    }
}
