namespace SharpTls.Quic;

/// <summary>One immutable QUIC transport parameter with an arbitrary registered or private ID.</summary>
public sealed class TlsQuicTransportParameter
{
    private readonly byte[] _value;

    /// <summary>Creates an opaque parameter. ID and value are encoded exactly once.</summary>
    public TlsQuicTransportParameter(ulong id, ReadOnlySpan<byte> value)
    {
        if (id > QuicVariableLengthInteger.MaximumValue)
        {
            throw new ArgumentOutOfRangeException(nameof(id));
        }
        if (value.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
        Id = id;
        _value = value.ToArray();
    }

    /// <summary>Gets the parameter ID.</summary>
    public ulong Id { get; }

    /// <summary>Gets a defensive copy of the opaque value.</summary>
    public byte[] Value => (byte[])_value.Clone();

    /// <summary>Creates a parameter whose value is one canonical QUIC variable-length integer.</summary>
    public static TlsQuicTransportParameter VariableInteger(
        TlsQuicTransportParameterId id,
        ulong value) => new((ulong)id, QuicVariableLengthInteger.Encode(value));

    /// <summary>Creates an empty flag parameter.</summary>
    public static TlsQuicTransportParameter Empty(TlsQuicTransportParameterId id) =>
        new((ulong)id, []);

    /// <summary>Decodes this value as exactly one QUIC variable-length integer.</summary>
    public ulong GetVariableInteger() => QuicVariableLengthInteger.ReadExact(
        _value,
        $"0x{Id:X}");

    internal ReadOnlySpan<byte> ValueSpan => _value;
}

/// <summary>
/// Immutable, ordered RFC 9000 transport parameters with unknown-ID preservation,
/// duplicate rejection, bounded parsing and endpoint-context validation.
/// </summary>
// RFC 9000 s18: transport parameters are "encoded as a sequence of transport
// parameters" (Figure 20), each one an (identifier, length, value) tuple
// (Figure 21) - the (id, length, value) triple Encode/Parse below read and
// write. s18 states no ordering requirement of its own; this type preserves
// insertion/wire order rather than imposing one (see Parameters below),
// which is what matters for subsystem B - reference-captures/2026-08-16-
// brave-151-http3-impersonate-pro.md publishes both perk_hash (raw wire
// order) and perk_hash_normalized (sorted by ID) for the same parameter
// set, confirming a real client's wire order is independently checkable and
// must be reproduced, not merely any legal encoding of the same values.
// See reference-captures/rfc9000-section18-transport-parameters.txt.
public sealed class TlsQuicTransportParameters
{
    private const int MaximumEncodedLength = ushort.MaxValue;
    private const int MaximumParameterCount = 256;
    private readonly TlsQuicTransportParameter[] _parameters;

    /// <summary>Creates and validates a duplicate-free ordered parameter set.</summary>
    public TlsQuicTransportParameters(IEnumerable<TlsQuicTransportParameter> parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        _parameters = parameters.Select(parameter =>
        {
            ArgumentNullException.ThrowIfNull(parameter);
            return new TlsQuicTransportParameter(parameter.Id, parameter.ValueSpan);
        }).ToArray();
        if (_parameters.Length > MaximumParameterCount)
        {
            throw new ArgumentOutOfRangeException(nameof(parameters));
        }
        if (_parameters.Select(parameter => parameter.Id).Distinct().Count() !=
            _parameters.Length)
        {
            throw new ArgumentException(
                "QUIC transport parameters contain a duplicate ID.",
                nameof(parameters));
        }
        _ = Encode();
    }

    /// <summary>Gets defensive immutable parameter copies in wire order.</summary>
    public IReadOnlyList<TlsQuicTransportParameter> Parameters => Array.AsReadOnly(
        _parameters.Select(parameter =>
            new TlsQuicTransportParameter(parameter.Id, parameter.ValueSpan)).ToArray());

    /// <summary>Gets a defensive copy of a parameter by ID, or null.</summary>
    public TlsQuicTransportParameter? Get(ulong id)
    {
        var parameter = _parameters.FirstOrDefault(candidate => candidate.Id == id);
        return parameter is null
            ? null
            : new TlsQuicTransportParameter(parameter.Id, parameter.ValueSpan);
    }

    /// <summary>Encodes the extension body with canonical IDs and lengths.</summary>
    public byte[] Encode()
    {
        var encoded = new List<byte>();
        foreach (var parameter in _parameters)
        {
            QuicVariableLengthInteger.Write(encoded, parameter.Id);
            QuicVariableLengthInteger.Write(
                encoded,
                checked((ulong)parameter.ValueSpan.Length));
            foreach (var value in parameter.ValueSpan)
            {
                encoded.Add(value);
            }
            if (encoded.Count > MaximumEncodedLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(_parameters),
                    "QUIC transport parameters exceed the TLS extension length limit.");
            }
        }
        return [.. encoded];
    }

    /// <summary>Strictly parses a bounded extension body and rejects duplicate IDs.</summary>
    public static TlsQuicTransportParameters Parse(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length > MaximumEncodedLength)
        {
            throw new TlsQuicTransportException(
                TlsQuicTransportError.TransportParameterError,
                "QUIC transport parameters exceed the TLS extension length limit.");
        }
        var parameters = new List<TlsQuicTransportParameter>();
        var seen = new HashSet<ulong>();
        var offset = 0;
        while (offset < encoded.Length)
        {
            if (parameters.Count == MaximumParameterCount)
            {
                throw QuicVariableLengthInteger.ParameterError(
                    "QUIC transport parameters exceed the parameter-count limit.");
            }
            var id = QuicVariableLengthInteger.Read(encoded, ref offset);
            var length = QuicVariableLengthInteger.Read(encoded, ref offset);
            if (length > (ulong)(encoded.Length - offset))
            {
                throw QuicVariableLengthInteger.ParameterError(
                    "QUIC transport parameter value is truncated.");
            }
            if (!seen.Add(id))
            {
                throw QuicVariableLengthInteger.ParameterError(
                    $"QUIC transport parameter 0x{id:X} is duplicated.");
            }
            var intLength = checked((int)length);
            parameters.Add(new TlsQuicTransportParameter(
                id,
                encoded.Slice(offset, intLength)));
            offset += intLength;
        }
        return new TlsQuicTransportParameters(parameters);
    }

    /// <summary>Validates RFC-defined value and sender-role constraints.</summary>
    public void ValidatePeer(TlsQuicEndpointRole senderRole)
    {
        if (!Enum.IsDefined(senderRole))
        {
            throw new ArgumentOutOfRangeException(nameof(senderRole));
        }
        foreach (var parameter in _parameters)
        {
            ValidateParameter(parameter, senderRole);
        }
    }

    internal bool PermitsRememberedZeroRttLimits(
        TlsQuicTransportParameters remembered)
    {
        ArgumentNullException.ThrowIfNull(remembered);
        ReadOnlySpan<TlsQuicTransportParameterId> nonDecreasing =
        [
            TlsQuicTransportParameterId.MaxUdpPayloadSize,
            TlsQuicTransportParameterId.InitialMaxData,
            TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal,
            TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote,
            TlsQuicTransportParameterId.InitialMaxStreamDataUni,
            TlsQuicTransportParameterId.InitialMaxStreamsBidi,
            TlsQuicTransportParameterId.InitialMaxStreamsUni,
            TlsQuicTransportParameterId.ActiveConnectionIdLimit,
            TlsQuicTransportParameterId.MaxDatagramFrameSize,
        ];
        foreach (var id in nonDecreasing)
        {
            if (GetIntegerOrDefault(id) < remembered.GetIntegerOrDefault(id))
            {
                return false;
            }
        }
        return true;
    }

    private ulong GetIntegerOrDefault(TlsQuicTransportParameterId id)
    {
        var parameter = _parameters.FirstOrDefault(candidate => candidate.Id == (ulong)id);
        if (parameter is not null)
        {
            return parameter.GetVariableInteger();
        }
        // RFC 9000 s18.2, max_udp_payload_size (0x03): "The default for this
        // parameter is the maximum permitted UDP payload of 65527." s18.2,
        // active_connection_id_limit (0x0e): "If this transport parameter is
        // absent, a default of 2 is assumed."
        return id switch
        {
            TlsQuicTransportParameterId.MaxUdpPayloadSize => 65527,
            TlsQuicTransportParameterId.ActiveConnectionIdLimit => 2,
            _ => 0,
        };
    }

    private static void ValidateParameter(
        TlsQuicTransportParameter parameter,
        TlsQuicEndpointRole senderRole)
    {
        var id = (TlsQuicTransportParameterId)parameter.Id;
        switch (id)
        {
            case TlsQuicTransportParameterId.OriginalDestinationConnectionId:
            case TlsQuicTransportParameterId.RetrySourceConnectionId:
                RequireServer(senderRole, id);
                ValidateConnectionId(parameter, id, allowEmpty: true);
                break;
            case TlsQuicTransportParameterId.StatelessResetToken:
                RequireServer(senderRole, id);
                // RFC 9000 s18.2, stateless_reset_token (0x02): "This parameter
                // is a sequence of 16 bytes."
                RequireLength(parameter, 16, id);
                break;
            case TlsQuicTransportParameterId.PreferredAddress:
                RequireServer(senderRole, id);
                ValidatePreferredAddress(parameter);
                break;
            case TlsQuicTransportParameterId.InitialSourceConnectionId:
                ValidateConnectionId(parameter, id, allowEmpty: true);
                break;
            case TlsQuicTransportParameterId.DisableActiveMigration:
            case TlsQuicTransportParameterId.GreaseQuicBit:
                RequireLength(parameter, 0, id);
                break;
            case TlsQuicTransportParameterId.MaxUdpPayloadSize:
                // RFC 9000 s18.2, max_udp_payload_size (0x03): "Values below
                // 1200 are invalid."
                if (ReadInteger(parameter, id) < 1200)
                {
                    throw ParameterError("max_udp_payload_size is smaller than 1200.");
                }
                break;
            case TlsQuicTransportParameterId.AckDelayExponent:
                // RFC 9000 s18.2, ack_delay_exponent (0x0a): "Values above 20
                // are invalid."
                if (ReadInteger(parameter, id) > 20)
                {
                    throw ParameterError("ack_delay_exponent exceeds 20.");
                }
                break;
            case TlsQuicTransportParameterId.MaxAckDelay:
                // RFC 9000 s18.2, max_ack_delay (0x0b): "Values of 2^14 or
                // greater are invalid."
                if (ReadInteger(parameter, id) >= (1UL << 14))
                {
                    throw ParameterError("max_ack_delay exceeds its 14-bit limit.");
                }
                break;
            case TlsQuicTransportParameterId.ActiveConnectionIdLimit:
                // RFC 9000 s18.2, active_connection_id_limit (0x0e): "The value
                // of the active_connection_id_limit parameter MUST be at least
                // 2."
                if (ReadInteger(parameter, id) < 2)
                {
                    throw ParameterError("active_connection_id_limit is smaller than 2.");
                }
                break;
            case TlsQuicTransportParameterId.InitialMaxStreamsBidi:
            case TlsQuicTransportParameterId.InitialMaxStreamsUni:
                if (ReadInteger(parameter, id) > (1UL << 60))
                {
                    throw ParameterError("initial_max_streams exceeds 2^60.");
                }
                break;
            case TlsQuicTransportParameterId.MaxIdleTimeout:
            case TlsQuicTransportParameterId.InitialMaxData:
            case TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal:
            case TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote:
            case TlsQuicTransportParameterId.InitialMaxStreamDataUni:
            case TlsQuicTransportParameterId.MaxDatagramFrameSize:
                _ = ReadInteger(parameter, id);
                break;
            case TlsQuicTransportParameterId.VersionInformation:
                ValidateVersionInformation(parameter);
                break;
            default:
                break;
        }
    }

    private static void ValidatePreferredAddress(TlsQuicTransportParameter parameter)
    {
        var value = parameter.ValueSpan;
        // RFC 9000 s18.2, Figure 22: IPv4 Address (32 bits = 4 bytes), IPv4
        // Port (16 = 2), IPv6 Address (128 = 16), IPv6 Port (16 = 2),
        // Connection ID Length (8 = 1), [Connection ID - variable, excluded
        // here], Stateless Reset Token (128 = 16). 4+2+16+2+1+16 = 41.
        const int fixedLengthWithoutConnectionId = 4 + 2 + 16 + 2 + 1 + 16;
        if (value.Length < fixedLengthWithoutConnectionId + 1)
        {
            throw ParameterError("preferred_address is truncated.");
        }
        var connectionIdLength = value[24];
        if (connectionIdLength is 0 or > 20 ||
            value.Length != fixedLengthWithoutConnectionId + connectionIdLength)
        {
            throw ParameterError("preferred_address contains an invalid connection ID.");
        }
    }

    /// <summary>
    /// Reads RFC 9368 section 3's <c>version_information</c> body into its Chosen Version and
    /// its Available Versions.
    /// </summary>
    /// <remarks>TRY-SHAPED AND SHARED WITH THE VALIDATOR'S RULES BUT NOT ITS THROW. The
    /// validator below runs on a parameter list as it is parsed and rejects a malformed body
    /// outright; this runs on a body already in hand - our own ClientHello's, or a peer's that
    /// has already been through that validator - and answers false rather than throwing so the
    /// caller can name the connection error RFC 9368 s4 asks for.</remarks>
    /// <param name="value">The parameter's value bytes.</param>
    /// <param name="chosenVersion">The Chosen Version field.</param>
    /// <param name="availableVersions">The Available Versions list, in the order sent.</param>
    /// <returns>Whether the body is well formed.</returns>
    internal static bool TryDecodeVersionInformation(
        ReadOnlySpan<byte> value,
        out uint chosenVersion,
        out uint[] availableVersions)
    {
        chosenVersion = 0;
        availableVersions = [];

        // s3 Figure 2: a 32-bit Chosen Version then one or more 32-bit Available Versions, so
        // the shortest legal body is eight bytes and every legal body is a multiple of four.
        if (value.Length < 8 || (value.Length & 3) != 0)
        {
            return false;
        }

        chosenVersion = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(value);
        var versions = new uint[(value.Length / 4) - 1];
        for (var index = 0; index < versions.Length; index++)
        {
            versions[index] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(
                value[(4 * (index + 1))..]);
        }

        availableVersions = versions;
        return true;
    }

    private static void ValidateVersionInformation(TlsQuicTransportParameter parameter)
    {
        var value = parameter.ValueSpan;
        if (value.Length < 8 || (value.Length & 3) != 0)
        {
            throw ParameterError(
                "version_information must contain a chosen and at least one available version.");
        }
        var available = new HashSet<uint>();
        var chosen = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(value);
        for (var offset = 4; offset < value.Length; offset += 4)
        {
            var version = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(
                value[offset..]);
            if (!available.Add(version))
            {
                throw ParameterError("version_information contains a duplicate version.");
            }
        }
        if (!available.Contains(chosen))
        {
            throw ParameterError(
                "version_information chosen version is absent from available versions.");
        }
    }

    private static ulong ReadInteger(
        TlsQuicTransportParameter parameter,
        TlsQuicTransportParameterId id) => QuicVariableLengthInteger.ReadExact(
        parameter.ValueSpan,
        id.ToString());

    private static void ValidateConnectionId(
        TlsQuicTransportParameter parameter,
        TlsQuicTransportParameterId id,
        bool allowEmpty)
    {
        if (parameter.ValueSpan.Length > 20 ||
            (!allowEmpty && parameter.ValueSpan.Length == 0))
        {
            throw ParameterError($"{id} contains an invalid connection ID length.");
        }
    }

    private static void RequireLength(
        TlsQuicTransportParameter parameter,
        int expected,
        TlsQuicTransportParameterId id)
    {
        if (parameter.ValueSpan.Length != expected)
        {
            throw ParameterError($"{id} has an invalid length.");
        }
    }

    private static void RequireServer(
        TlsQuicEndpointRole senderRole,
        TlsQuicTransportParameterId id)
    {
        if (senderRole != TlsQuicEndpointRole.Server)
        {
            throw ParameterError($"A QUIC client sent server-only parameter {id}.");
        }
    }

    private static TlsQuicTransportException ParameterError(string message) => new(
        TlsQuicTransportError.TransportParameterError,
        message);
}
