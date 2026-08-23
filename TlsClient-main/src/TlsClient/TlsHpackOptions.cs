namespace TlsClient;

/// <summary>How a header field is represented in the encoded HPACK block.</summary>
public enum TlsHpackRepresentation
{
    /// <summary>An indexed header field, referencing an exact name/value match by index.</summary>
    Indexed,

    /// <summary>A literal header field that is inserted into the dynamic table.</summary>
    LiteralIncrementalIndexing,

    /// <summary>A literal header field that is not inserted into the dynamic table.</summary>
    LiteralWithoutIndexing,

    /// <summary>
    /// A literal header field that is never indexed, signalling downstream re-encoders
    /// must preserve the literal representation.
    /// </summary>
    LiteralNeverIndexed,
}

/// <summary>Controls when Huffman coding is applied to a literal string.</summary>
public enum TlsHpackHuffman
{
    /// <summary>Huffman-encode only when the result is strictly shorter than raw.</summary>
    WhenShorter,

    /// <summary>Huffman-encode when the result is no longer than raw, including ties.</summary>
    WhenNotLonger,

    /// <summary>Always Huffman-encode.</summary>
    Always,

    /// <summary>Never Huffman-encode.</summary>
    Never,
}

/// <summary>Controls when a dynamic table size update is written.</summary>
public enum TlsHpackTableSizeUpdate
{
    /// <summary>Never write a dynamic table size update.</summary>
    Never,

    /// <summary>Write a dynamic table size update when the peer's settings change.</summary>
    OnPeerSettingsChange,

    /// <summary>Write a dynamic table size update before the first request.</summary>
    BeforeFirstRequest,
}

/// <summary>Selects which table entry a name-only index reference prefers.</summary>
public enum TlsHpackNameIndex
{
    /// <summary>Prefer the lowest-numbered static table entry for the name.</summary>
    LowestStatic,

    /// <summary>Prefer the highest-numbered static table entry for the name.</summary>
    HighestStatic,

    /// <summary>Prefer the most recently inserted dynamic table entry for the name.</summary>
    MostRecentDynamic,
}

/// <summary>Controls how a header with multiple values is encoded.</summary>
public enum TlsHpackMultiValue
{
    /// <summary>Encode each value as a separate header field.</summary>
    SeparateFields,

    /// <summary>Join every value into a single header field.</summary>
    Join,
}

/// <summary>Policy controlling how <c>HpackEncoder</c> represents header fields on the wire.</summary>
public sealed class TlsHpackOptions
{
    /// <summary>Gets or sets the representation used when no per-header override applies.</summary>
    public TlsHpackRepresentation DefaultRepresentation { get; set; }
        = TlsHpackRepresentation.Indexed;

    /// <summary>
    /// Gets or sets the representation used when a header resolves to
    /// <see cref="TlsHpackRepresentation.Indexed"/> but no exact name/value match exists.
    /// </summary>
    public TlsHpackRepresentation IndexedFallback { get; set; }
        = TlsHpackRepresentation.LiteralIncrementalIndexing;

    /// <summary>Gets or sets whether the dynamic table is used at all.</summary>
    public bool UseDynamicTable { get; set; } = true;

    /// <summary>Gets the per-header-name representation overrides, keyed by header name.</summary>
    public IDictionary<string, TlsHpackRepresentation> PerHeader { get; }
        = new Dictionary<string, TlsHpackRepresentation>(StringComparer.Ordinal)
        {
            ["cookie"] = TlsHpackRepresentation.LiteralNeverIndexed,
            ["authorization"] = TlsHpackRepresentation.LiteralNeverIndexed,
        };

    /// <summary>Gets or sets the Huffman policy used when no per-header override applies.</summary>
    public TlsHpackHuffman Huffman { get; set; } = TlsHpackHuffman.WhenShorter;

    /// <summary>Gets the per-header-name Huffman policy overrides, keyed by header name.</summary>
    public IDictionary<string, TlsHpackHuffman> PerHeaderHuffman { get; }
        = new Dictionary<string, TlsHpackHuffman>(StringComparer.Ordinal);

    /// <summary>Gets or sets the name index preference used when no per-header override applies.</summary>
    public TlsHpackNameIndex NameIndex { get; set; } = TlsHpackNameIndex.LowestStatic;

    /// <summary>Gets the per-header-name index preference overrides, keyed by header name.</summary>
    public IDictionary<string, int> PerHeaderNameIndex { get; }
        = new Dictionary<string, int>(StringComparer.Ordinal);

    /// <summary>Gets or sets the multi-value policy used when no per-header override applies.</summary>
    public TlsHpackMultiValue MultiValue { get; set; } = TlsHpackMultiValue.SeparateFields;

    /// <summary>Gets the per-header-name multi-value policy overrides, keyed by header name.</summary>
    public IDictionary<string, TlsHpackMultiValue> PerHeaderMultiValue { get; }
        = new Dictionary<string, TlsHpackMultiValue>(StringComparer.Ordinal);

    /// <summary>Gets or sets the separator used to join values under <see cref="TlsHpackMultiValue.Join"/>.</summary>
    public string MultiValueJoinSeparator { get; set; } = ", ";

    /// <summary>Gets or sets when a dynamic table size update is written.</summary>
    public TlsHpackTableSizeUpdate TableSizeUpdate { get; set; }
        = TlsHpackTableSizeUpdate.OnPeerSettingsChange;

    /// <summary>Gets or sets the dynamic table size update values to write, in order.</summary>
    public IReadOnlyList<uint> TableSizeUpdateValues { get; set; } = [];

    /// <summary>
    /// Gets or sets whether the <c>cookie</c> header is crumbled into separate fields, as
    /// RFC 9113 section 8.2.3 permits. A stack that crumbles generally does so in order to
    /// index individual crumbs, so a crumbling persona will usually also move
    /// <see cref="PerHeader"/>'s <c>cookie</c> entry off its never-indexed default.
    /// Applies to HTTP/2 only.
    /// </summary>
    public bool CrumbleCookies { get; set; }

    /// <summary>Gets or sets the separator used between crumbled cookie fields.</summary>
    public string CookieCrumbSeparator { get; set; } = "; ";

    internal TlsHpackConfiguration Snapshot()
    {
        RequireDefined(DefaultRepresentation, nameof(DefaultRepresentation));
        RequireDefined(IndexedFallback, nameof(IndexedFallback));
        RequireDefined(Huffman, nameof(Huffman));
        RequireDefined(NameIndex, nameof(NameIndex));
        RequireDefined(MultiValue, nameof(MultiValue));
        RequireDefined(TableSizeUpdate, nameof(TableSizeUpdate));
        if (IndexedFallback == TlsHpackRepresentation.Indexed)
        {
            throw new ArgumentException(
                "IndexedFallback is what an indexed field falls back to, so it cannot be Indexed.",
                nameof(IndexedFallback));
        }

        var perHeader = Freeze(PerHeader, nameof(PerHeader));
        var perHeaderHuffman = Freeze(PerHeaderHuffman, nameof(PerHeaderHuffman));
        var perHeaderNameIndex = Freeze(PerHeaderNameIndex, nameof(PerHeaderNameIndex));
        var perHeaderMultiValue = Freeze(PerHeaderMultiValue, nameof(PerHeaderMultiValue));
        foreach (var entry in perHeader)
        {
            RequireDefined(entry.Value, nameof(PerHeader));
        }
        foreach (var entry in perHeaderHuffman)
        {
            RequireDefined(entry.Value, nameof(PerHeaderHuffman));
        }
        foreach (var entry in perHeaderMultiValue)
        {
            RequireDefined(entry.Value, nameof(PerHeaderMultiValue));
        }
        foreach (var entry in perHeaderNameIndex)
        {
            if (entry.Value < 1 ||
                entry.Value > HpackStaticTable.Entries.Length ||
                !string.Equals(
                    HpackStaticTable.Entries[entry.Value - 1].Name,
                    entry.Key,
                    StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "Every PerHeaderNameIndex value must reference an HPACK static table " +
                    "entry whose name matches its key.",
                    nameof(PerHeaderNameIndex));
            }
        }

        if (string.IsNullOrEmpty(MultiValueJoinSeparator))
        {
            throw new ArgumentException(
                "MultiValueJoinSeparator cannot be empty.",
                nameof(MultiValueJoinSeparator));
        }
        if (string.IsNullOrEmpty(CookieCrumbSeparator))
        {
            throw new ArgumentException(
                "CookieCrumbSeparator cannot be empty.",
                nameof(CookieCrumbSeparator));
        }

        var tableSizeUpdateValues = TableSizeUpdateValues?.ToArray() ??
            throw new ArgumentNullException(nameof(TableSizeUpdateValues));
        if (Array.Exists(tableSizeUpdateValues, value => value > 16 * 1024 * 1024))
        {
            throw new ArgumentException(
                "Every TableSizeUpdateValues entry must not exceed 16777216, the HPACK " +
                "table capacity TlsClient will hold. RFC 7541 section 6.3 makes a value " +
                "larger than the peer's SETTINGS_HEADER_TABLE_SIZE a COMPRESSION_ERROR.",
                nameof(TableSizeUpdateValues));
        }
        if (tableSizeUpdateValues.Length > 2)
        {
            throw new ArgumentException(
                "TableSizeUpdateValues holds at most two entries. RFC 7541 section 4.2 " +
                "allows a size that changed more than once between header blocks to be " +
                "signalled as the smallest size followed by the size that will be used, " +
                "and nothing longer. Decoders reject a third as a COMPRESSION_ERROR.",
                nameof(TableSizeUpdateValues));
        }
        if (tableSizeUpdateValues.Length == 2 &&
            tableSizeUpdateValues[0] >= tableSizeUpdateValues[1])
        {
            throw new ArgumentException(
                "A two-entry TableSizeUpdateValues must be the smallest size followed by " +
                "the larger size that will be used (RFC 7541 section 4.2). Use a single " +
                "entry to shrink the table.",
                nameof(TableSizeUpdateValues));
        }

        return new TlsHpackConfiguration(
            DefaultRepresentation,
            IndexedFallback,
            UseDynamicTable,
            perHeader,
            Huffman,
            perHeaderHuffman,
            NameIndex,
            perHeaderNameIndex,
            MultiValue,
            perHeaderMultiValue,
            MultiValueJoinSeparator,
            TableSizeUpdate,
            tableSizeUpdateValues,
            CrumbleCookies,
            CookieCrumbSeparator);
    }

    private static void RequireDefined<TEnum>(TEnum value, string name)
        where TEnum : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(name, $"{name} must be a defined value.");
        }
    }

    /// <summary>
    /// Copies a per-header dictionary and checks its keys against the same rule
    /// <c>HpackEncoder.ValidateHeader</c> applies on the wire: a non-empty name with no
    /// uppercase letter, NUL, CR, or LF.
    /// </summary>
    private static Dictionary<string, TValue> Freeze<TValue>(
        IDictionary<string, TValue> source,
        string name)
    {
        ArgumentNullException.ThrowIfNull(source, name);
        var frozen = new Dictionary<string, TValue>(source.Count, StringComparer.Ordinal);
        foreach (var entry in source)
        {
            if (string.IsNullOrEmpty(entry.Key) || entry.Key.Any(character =>
                    character is >= 'A' and <= 'Z' || character is '\0' or '\r' or '\n'))
            {
                throw new ArgumentException(
                    $"Every {name} key must be a lowercase HTTP header name.",
                    name);
            }
            frozen[entry.Key] = entry.Value;
        }
        return frozen;
    }
}

internal sealed record TlsHpackConfiguration(
    TlsHpackRepresentation DefaultRepresentation,
    TlsHpackRepresentation IndexedFallback,
    bool UseDynamicTable,
    Dictionary<string, TlsHpackRepresentation> PerHeader,
    TlsHpackHuffman Huffman,
    Dictionary<string, TlsHpackHuffman> PerHeaderHuffman,
    TlsHpackNameIndex NameIndex,
    Dictionary<string, int> PerHeaderNameIndex,
    TlsHpackMultiValue MultiValue,
    Dictionary<string, TlsHpackMultiValue> PerHeaderMultiValue,
    string MultiValueJoinSeparator,
    TlsHpackTableSizeUpdate TableSizeUpdate,
    uint[] TableSizeUpdateValues,
    bool CrumbleCookies,
    string CookieCrumbSeparator);
