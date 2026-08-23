namespace SharpTls;

/// <summary>Identifies a semantic RFC 8701 GREASE placement.</summary>
public enum ClientHelloGreaseSlot
{
    /// <summary>The leading cipher_suites value.</summary>
    CipherSuite,
    /// <summary>The leading supported_versions value.</summary>
    SupportedVersion,
    /// <summary>The leading supported_groups value.</summary>
    SupportedGroup,
    /// <summary>The leading key_share entry.</summary>
    KeyShare,
    /// <summary>The empty GREASE extension type.</summary>
    Extension,
    /// <summary>The optional second GREASE extension type.</summary>
    SecondaryExtension,
    /// <summary>
    /// The optional GREASE value spliced into signature_algorithms. BoringSSL gives this
    /// its own <c>ssl_grease_signature_algorithm</c> seed index (`ssl/internal.h` @ main
    /// L1685), so it is an independent placement rather than a reuse of another slot.
    /// </summary>
    SignatureAlgorithm,
}

/// <summary>
/// Defines which GREASE placements share a generated value. It never fixes the
/// actual GREASE code point; secure generation chooses fresh values per connection.
/// </summary>
public sealed class ClientHelloGreasePolicy
{
    /// <summary>
    /// Derived from <see cref="ClientHelloGreaseSlot"/> so a new slot never needs a second
    /// edit here. Every factory builds its request array in declaration order.
    /// </summary>
    private static readonly int SlotCount = Enum.GetValues<ClientHelloGreaseSlot>().Length;

    /// <summary>
    /// The arity of <see cref="Create"/> and the width of <see cref="ValueClasses"/>. Frozen
    /// at five for API compatibility: it is not a slot count and must not track new slots.
    /// </summary>
    private const int LegacyValueClassCount = 5;

    private readonly int[] _valueClasses;

    private ClientHelloGreasePolicy(int[] valueClasses)
    {
        _valueClasses = valueClasses;
        DistinctValueCount = valueClasses.Distinct().Count();
    }

    /// <summary>Gets a policy which uses one fresh GREASE value in every placement.</summary>
    public static ClientHelloGreasePolicy Consistent { get; } = Create(0, 0, 0, 0, 0);

    /// <summary>Gets a policy which uses a distinct fresh value in every placement.</summary>
    public static ClientHelloGreasePolicy PerSlot { get; } =
        CreateWithSignatureAlgorithm(0, 1, 2, 3, 4, 5, 6);

    /// <summary>Gets the number of independently generated GREASE values.</summary>
    public int DistinctValueCount { get; }

    /// <summary>
    /// Creates an equality pattern for cipher suite, supported version, supported
    /// group, key share, and extension placements, in that order. Equal class labels
    /// share a generated value; label numbers are normalized by first occurrence.
    /// </summary>
    public static ClientHelloGreasePolicy Create(
        int cipherSuiteClass,
        int supportedVersionClass,
        int supportedGroupClass,
        int keyShareClass,
        int extensionClass)
        => CreateWithSecondaryExtension(
            cipherSuiteClass,
            supportedVersionClass,
            supportedGroupClass,
            keyShareClass,
            extensionClass,
            extensionClass);

    /// <summary>
    /// Creates an equality pattern including an optional second GREASE extension slot. The
    /// signature_algorithms slot shares <paramref name="extensionClass"/>; use
    /// <see cref="CreateWithSignatureAlgorithm"/> to give it a class of its own.
    /// </summary>
    public static ClientHelloGreasePolicy CreateWithSecondaryExtension(
        int cipherSuiteClass,
        int supportedVersionClass,
        int supportedGroupClass,
        int keyShareClass,
        int extensionClass,
        int secondaryExtensionClass)
        => CreateWithSignatureAlgorithm(
            cipherSuiteClass,
            supportedVersionClass,
            supportedGroupClass,
            keyShareClass,
            extensionClass,
            secondaryExtensionClass,
            extensionClass);

    /// <summary>
    /// Creates an equality pattern for all placements including the signature_algorithms
    /// GREASE value. The signature_algorithms class is only consulted when the caller
    /// enables signature_algorithms GREASE on the builder.
    /// </summary>
    public static ClientHelloGreasePolicy CreateWithSignatureAlgorithm(
        int cipherSuiteClass,
        int supportedVersionClass,
        int supportedGroupClass,
        int keyShareClass,
        int extensionClass,
        int secondaryExtensionClass,
        int signatureAlgorithmClass)
    {
        int[] requested =
        [
            cipherSuiteClass,
            supportedVersionClass,
            supportedGroupClass,
            keyShareClass,
            extensionClass,
            secondaryExtensionClass,
            signatureAlgorithmClass,
        ];
        if (requested.Any(value => value is < 0 or > 15))
        {
            throw new ArgumentOutOfRangeException(
                nameof(cipherSuiteClass),
                "GREASE value-class labels must be between 0 and 15.");
        }

        var normalized = new int[SlotCount];
        var classes = new Dictionary<int, int>();
        for (var index = 0; index < requested.Length; index++)
        {
            if (!classes.TryGetValue(requested[index], out var normalizedClass))
            {
                normalizedClass = classes.Count;
                classes.Add(requested[index], normalizedClass);
            }
            normalized[index] = normalizedClass;
        }

        return new ClientHelloGreasePolicy(normalized);
    }

    /// <summary>Gets the normalized generated-value class for a placement.</summary>
    public int GetValueClass(ClientHelloGreaseSlot slot)
    {
        if (!Enum.IsDefined(slot))
        {
            throw new ArgumentOutOfRangeException(nameof(slot));
        }
        return _valueClasses[(int)slot];
    }

    /// <summary>Gets a copy of the original five normalized classes in documented slot order.</summary>
    public IReadOnlyList<int> ValueClasses => Array.AsReadOnly(_valueClasses[..LegacyValueClassCount]);

    /// <summary>Gets the normalized generated-value class for the optional second GREASE extension.</summary>
    public int SecondaryExtensionValueClass => _valueClasses[(int)ClientHelloGreaseSlot.SecondaryExtension];

    /// <summary>Gets the normalized generated-value class for the signature_algorithms GREASE value.</summary>
    public int SignatureAlgorithmValueClass => _valueClasses[(int)ClientHelloGreaseSlot.SignatureAlgorithm];

    /// <summary>
    /// Gets the number of independently generated values needed to fill <paramref name="slots"/>.
    /// Class labels are dense over all slots but not over an arbitrary subset, so this is one
    /// past the largest class present rather than a distinct count.
    /// </summary>
    internal int GetGeneratedValueCount(ReadOnlySpan<ClientHelloGreaseSlot> slots)
    {
        var highest = -1;
        foreach (var slot in slots)
        {
            var index = (int)slot;
            if ((uint)index < (uint)_valueClasses.Length && _valueClasses[index] > highest)
            {
                highest = _valueClasses[index];
            }
        }

        return highest + 1;
    }

    internal ClientHelloGreasePolicy Snapshot() => new((int[])_valueClasses.Clone());
}
