using SharpTls.Quic;

namespace TlsClient;

/// <summary>One HTTP/3 request pseudo-header, as RFC 9114 section 4.3.1 names them.</summary>
/// <remarks>Mirrors <c>SharpTls.Quic.TlsQuicHttp3PseudoHeader</c> value for value. That type is
/// <see langword="internal"/> to SharpTls and cannot appear on a public TlsClient API, so the
/// two are kept numerically identical and cast rather than translated by a lookup table.
/// </remarks>
public enum TlsHttp3PseudoHeader
{
    /// <summary><c>:method</c>.</summary>
    Method = 0,

    /// <summary><c>:authority</c>.</summary>
    Authority = 1,

    /// <summary><c>:scheme</c>.</summary>
    Scheme = 2,

    /// <summary><c>:path</c>.</summary>
    Path = 3,
}

/// <summary>An HTTP/3 unidirectional stream type, by its RFC 9114 section 6.2 wire code.</summary>
/// <remarks>Mirrors <c>SharpTls.Quic.TlsQuicHttp3StreamType</c> value for value; see
/// <see cref="TlsHttp3PseudoHeader"/> for why a mirror rather than a re-export.</remarks>
public enum TlsHttp3StreamType : ulong
{
    /// <summary>The control stream, 0x00.</summary>
    Control = 0x00,

    /// <summary>A push stream, 0x01.</summary>
    Push = 0x01,

    /// <summary>The QPACK encoder stream, 0x02.</summary>
    QpackEncoder = 0x02,

    /// <summary>The QPACK decoder stream, 0x03.</summary>
    QpackDecoder = 0x03,
}

/// <summary>How a QPACK field line names a header the static table already carries.</summary>
/// <remarks>Mirrors <c>SharpTls.Quic.TlsQuicQpackNameMatchPolicy</c> value for value.</remarks>
public enum TlsQpackNameMatchPolicy
{
    /// <summary>Reference the static-table entry by index.</summary>
    NameReference = 0,

    /// <summary>Spell the name out as a literal even when the static table has it.</summary>
    LiteralName = 1,
}

/// <summary>
/// One HTTP/3 SETTINGS entry. The identifier is a bare <see cref="ulong"/> rather than an enum
/// because a real client sends identifiers no registry lists — a client capture's fifth
/// entry, 126585778853, is a GREASE identifier of exactly that kind.
/// </summary>
/// <param name="Identifier">The setting identifier, any QUIC variable-length integer.</param>
/// <param name="Value">The setting value, any QUIC variable-length integer.</param>
public readonly record struct TlsHttp3Setting(ulong Identifier, ulong Value)
{
    /// <summary>
    /// Gets the function that draws this entry afresh for every connection, or
    /// <see langword="null"/> for a literal pair.
    /// </summary>
    /// <remarks>RFC 9114 section 7.2.4.1 reserves the whole <c>0x1f * N + 0x21</c> family so a
    /// peer sees settings it must ignore. A client that draws one per connection and a client
    /// that ships one constant pair forever are trivially told apart, and the constant is the
    /// stronger fingerprint of the two: it names the implementation rather than hiding
    /// it.</remarks>
    public Func<TlsHttp3Setting>? Draw { get; init; }

    /// <summary>Gets whether this entry redraws on every connection.</summary>
    public bool IsDrawn => Draw is not null;

    /// <summary>Creates an entry whose identifier and value are drawn for each connection.</summary>
    /// <param name="draw">Runs once per connection. The pair on the returned entry is used and
    /// its own <see cref="Draw"/> is discarded.</param>
    /// <exception cref="ArgumentNullException"><paramref name="draw"/> is
    /// <see langword="null"/>.</exception>
    public static TlsHttp3Setting Drawn(Func<TlsHttp3Setting> draw)
    {
        ArgumentNullException.ThrowIfNull(draw);
        return new TlsHttp3Setting(0, 0) { Draw = draw };
    }
}

/// <summary>
/// Configures the HTTP/3 layer's SETTINGS, stream-open order, pseudo-header order and QPACK
/// encoding — every member of SharpTls's <c>TlsQuicHttp3Spec</c>.
/// </summary>
/// <remarks>
/// <para>DEFAULTS ARE READ FROM THE SPEC, NEVER RE-TYPED. Every default below is copied out of
/// a freshly constructed <c>TlsQuicHttp3Spec</c> at static-initialisation time, so the shipped
/// numbers keep living in SharpTls's cited preset block and cannot drift out of step with it.
/// Re-typing them here would create a second copy of a captured fingerprint, which is exactly
/// what <c>TlsQuicHttp3Spec.CaptureSettings</c>' remarks forbid.</para>
/// <para>THE LISTS ARE ORDERED AND THE ORDER IS THE FINGERPRINT. <see cref="Settings"/> and
/// <see cref="PseudoHeaderOrder"/> are emitted in exactly the order they are listed. They are
/// mutable <see cref="IList{T}"/>s pre-filled with the default so a caller can reorder, insert
/// or delete in place rather than having to restate a whole capture to change one entry.</para>
/// </remarks>
public sealed class TlsHttp3Options
{
    private static readonly TlsQuicHttp3Spec SpecDefaults = new();

    /// <summary>
    /// Gets or sets the SETTINGS entries, in exact wire order. The default is the a captured client
    /// capture's five pairs, read from <c>TlsQuicHttp3Spec</c>'s own preset.
    /// </summary>
    public IList<TlsHttp3Setting> Settings { get; set; } =
        [.. SpecDefaults.Settings.Select(FromSpec)];

    /// <summary>Maps one SharpTls SETTINGS entry to this surface, drawn entries included.</summary>
    /// <remarks>A DRAWN ENTRY MAPS TO A DRAWN ENTRY, not to one sample of it. Reading
    /// <c>setting.Identifier</c> and <c>setting.Value</c> off a drawn entry would copy the
    /// (0, 0) placeholder; calling its function once here would freeze one draw as this
    /// options object's constant, which is the very thing the drawn slot exists to
    /// prevent.</remarks>
    private static TlsHttp3Setting FromSpec(TlsQuicHttp3Setting setting) =>
        setting.IsDrawn
            ? TlsHttp3Setting.Drawn(() =>
                {
                    var drawn = setting.Draw!();
                    return new TlsHttp3Setting(drawn.Identifier, drawn.Value);
                })
            : new TlsHttp3Setting(setting.Identifier, setting.Value);

    /// <summary>The inverse of <see cref="FromSpec"/>, for <c>Snapshot</c>.</summary>
    private static TlsQuicHttp3Setting ToSpec(TlsHttp3Setting setting) =>
        setting.IsDrawn
            ? TlsQuicHttp3Setting.Drawn(() =>
                {
                    var drawn = setting.Draw!();
                    return new TlsQuicHttp3Setting(drawn.Identifier, drawn.Value);
                })
            : new TlsQuicHttp3Setting(setting.Identifier, setting.Value);

    /// <summary>
    /// Gets or sets the unidirectional streams this client opens, in exact open order.
    /// </summary>
    public IList<TlsHttp3StreamType> UnidirectionalStreamOpenOrder { get; set; } =
        [.. SpecDefaults.UnidirectionalStreamOpenOrder
            .Select(type => (TlsHttp3StreamType)type)];

    /// <summary>
    /// Gets or sets the request pseudo-headers, in exact wire order. The default is the
    /// capture's <c>m,a,s,p</c>.
    /// </summary>
    public IList<TlsHttp3PseudoHeader> PseudoHeaderOrder { get; set; } =
        [.. SpecDefaults.PseudoHeaderOrder.Select(header => (TlsHttp3PseudoHeader)header)];

    /// <summary>Gets or sets whether QPACK string literals are Huffman-coded.</summary>
    public SharpTls.Quic.TlsQuicQpackHuffmanPolicy QpackHuffmanStringLiterals { get; set; } =
        SpecDefaults.QpackHuffmanStringLiterals;

    /// <summary>Gets or sets how a QPACK field line names a static-table header.</summary>
    public TlsQpackNameMatchPolicy QpackNameMatchPolicy { get; set; } =
        (TlsQpackNameMatchPolicy)SpecDefaults.QpackNameMatchPolicy;

    /// <summary>
    /// Gets or sets whether a reserved (GREASE) frame is sent on each request stream.
    /// </summary>
    public bool SendReservedFramesOnRequestStreams { get; set; } =
        SpecDefaults.SendReservedFramesOnRequestStreams;

    /// <summary>
    /// Gets or sets whether <c>SETTINGS_H3_DATAGRAM</c> may be sent without the matching
    /// <c>max_datagram_frame_size</c> transport parameter. SharpTls refuses that pairing by
    /// default; a client that really sends it needs this set.
    /// </summary>
    public bool AllowDatagramSettingWithoutTransportParameter { get; set; } =
        SpecDefaults.AllowDatagramSettingWithoutTransportParameter;

    /// <summary>Builds the SharpTls spec, validating every list and enum on the way.</summary>
    internal TlsQuicHttp3Spec Snapshot()
    {
        ArgumentNullException.ThrowIfNull(Settings, nameof(Settings));
        ArgumentNullException.ThrowIfNull(
            UnidirectionalStreamOpenOrder,
            nameof(UnidirectionalStreamOpenOrder));
        ArgumentNullException.ThrowIfNull(PseudoHeaderOrder, nameof(PseudoHeaderOrder));

        // NO Enum.IsDefined GUARD HERE, DELIBERATELY. Every property below rejects an
        // undefined value in its own init accessor, with Enum.IsDefined and with the same
        // paramName these properties carry — so a guard here would be a second copy that
        // changes no outcome and hides SharpTls's better message. A mutation sweep confirmed
        // it: removing the guard killed nothing, because SharpTls was already doing the work.
        return new TlsQuicHttp3Spec
        {
            Settings = [.. Settings.Select(ToSpec)],
            UnidirectionalStreamOpenOrder =
            [
                .. UnidirectionalStreamOpenOrder.Select(
                    type => (TlsQuicHttp3StreamType)type),
            ],
            PseudoHeaderOrder =
            [
                .. PseudoHeaderOrder.Select(header => (TlsQuicHttp3PseudoHeader)header),
            ],
            QpackHuffmanStringLiterals = QpackHuffmanStringLiterals,
            QpackNameMatchPolicy = (TlsQuicQpackNameMatchPolicy)QpackNameMatchPolicy,
            SendReservedFramesOnRequestStreams = SendReservedFramesOnRequestStreams,
            AllowDatagramSettingWithoutTransportParameter =
                AllowDatagramSettingWithoutTransportParameter,
        };
    }
}
