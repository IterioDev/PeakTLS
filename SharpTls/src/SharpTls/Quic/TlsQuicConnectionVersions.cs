using System.Buffers.Binary;

namespace SharpTls.Quic;

/// <content>
/// RFC 9368's compatible version negotiation: the version this connection's first flight uses,
/// the versions its ClientHello offered, and the switch it performs when the server answers in
/// a different one.
///
/// WHY THE CAPTURES DO NOT SETTLE THIS. Every capture in this repo is version 1, and that is a
/// property of the CAPTURE TOOL rather than of the clients: the proxy the connections were
/// recorded through speaks version 1 only, so a client that would have negotiated version 2
/// against a real server could not have done so through it. "No capture shows version 2" is
/// therefore not evidence that no client uses it, and the mechanism belongs here so that a
/// server which chooses version 2 gets version 2.
///
/// THE ADVERTISEMENT GATES THE ADOPTION, and there is deliberately no separate knob for it.
/// s2.3 lets a server pick only from the Available Versions the client sent, so a profile that
/// sends no <c>version_information</c> cannot negotiate at all and a profile that sends one can
/// negotiate exactly what it listed. A knob would be a second answer to a question the wire
/// already answers - the same rule the six flow-control parameters and
/// <c>grease_quic_bit</c> follow.
/// </content>
internal sealed partial class TlsQuicConnection
{
    /// <summary>The version this connection's packets carry.</summary>
    /// <remarks>NOT A CONSTANT ANY MORE. It starts at
    /// <c>TlsQuicConnectionSpec.Version</c> and moves at most once, in
    /// <see cref="TryAdoptNegotiatedVersion"/>, when the server answers the first flight in a
    /// compatible version this client offered.</remarks>
    private TlsQuicVersion _version;

    /// <summary>The versions this client's own <c>version_information</c> listed as
    /// available, or empty when it sent none.</summary>
    private uint[] _offeredVersions = [];

    /// <summary>The chosen version this client's own <c>version_information</c> declared.</summary>
    private uint _offeredChosenVersion;

    /// <summary>Whether <see cref="TryAdoptNegotiatedVersion"/> has already moved the version.</summary>
    /// <remarks>ONCE, AND s2.3 IS WHY: "the client MUST NOT change the version it is using
    /// after processing the server's first flight." A second move would also mean a second
    /// Initial key derivation, which s4.9.1's discard makes an error rather than a
    /// re-key.</remarks>
    private bool _adoptedNegotiatedVersion;

    /// <summary>The version in use, for tests and readouts.</summary>
    internal TlsQuicVersion NegotiatedVersion => _version;

    /// <summary>Whether the server chose a version other than the one this client started in.</summary>
    internal bool VersionWasNegotiated => _adoptedNegotiatedVersion;

    /// <summary>The versions this endpoint can actually speak, whatever it offered.</summary>
    /// <remarks>OFFERING IS NOT IMPLEMENTING. RFC 9368 s3 expects an Available Versions list to
    /// carry GREASE entries - <c>TlsQuicTransportParameterSpec.DrawnVersionInformation</c>
    /// draws them - and a reserved version this client cannot speak must not be adopted just
    /// because it was listed. Both tests have to pass.</remarks>
    private static bool IsImplementedVersion(uint version) =>
        version == (uint)TlsQuicVersion.Version1 || version == (uint)TlsQuicVersion.Version2;

    /// <summary>
    /// Reads this client's own <c>version_information</c> out of the ClientHello it is about to
    /// send, so the adoption test below can be "did we offer this" rather than "do we like it".
    /// </summary>
    private void ReadOfferedVersions()
    {
        var parameter = _client?.AdvertisedVersionInformation;
        if (parameter is null
            || !TlsQuicTransportParameters.TryDecodeVersionInformation(
                parameter.Value.Span, out var chosen, out var available))
        {
            _offeredVersions = [];
            _offeredChosenVersion = 0;
            return;
        }

        _offeredChosenVersion = chosen;
        _offeredVersions = available;

        // THE ADVERTISED CHOSEN VERSION WINS, for the same reason the advertised
        // ack_delay_exponent does. RFC 9368 s3: "The Chosen Version field ... MUST be set to
        // the version that the sender has chosen to use" - so if a profile's
        // version_information says one version and TlsQuicConnectionSpec.Version says another,
        // the wire has already committed and the spec property is the copy that is wrong.
        //
        // FREE HERE AND ONLY HERE. This runs before the Initial keys are installed, so moving
        // the version costs no re-derivation; a mismatch discovered later would.
        if (_offeredChosenVersion != (uint)_version && IsImplementedVersion(_offeredChosenVersion))
        {
            _version = (TlsQuicVersion)_offeredChosenVersion;
            _receiver.Version = _offeredChosenVersion;
            _keys.AdoptVersion(_version);
        }
    }

    /// <summary>
    /// RFC 9368 section 2.3: adopts the version the server answered in, when this client
    /// offered it and can speak it.
    /// </summary>
    /// <remarks>
    /// <para>THE SERVER'S FIRST FLIGHT IS ALREADY IN THE NEW VERSION, which is what makes this
    /// a packet-level decision rather than a transport-parameter one. s2.3: "the server sends
    /// its first flight using the negotiated version" - and that flight is Initial packets,
    /// which arrive long before the EncryptedExtensions that carry the server's own
    /// <c>version_information</c>. So the version field of the header is the signal and
    /// <see cref="ValidateServerVersionInformation"/> is the confirmation.</para>
    /// <para>THE INITIAL KEYS ARE RE-DERIVED FROM THE SAME CONNECTION ID. RFC 9369 s3.1 changes
    /// the salt with the version and nothing else: the Destination Connection ID of the
    /// client's first Initial is still the input. This mirrors the Retry path, which re-derives
    /// for the opposite reason - there the salt is fixed and the connection ID moves.</para>
    /// <para>PACKET NUMBERS DO NOT RESET. s2.3 changes the version, not the packet number
    /// spaces, and nothing here touches <c>_nextPacketNumber</c>.</para>
    /// </remarks>
    /// <param name="version">The version on the incoming long header.</param>
    /// <returns>Whether the version was adopted; false leaves the packet to be discarded as an
    /// unknown version, which is what it is.</returns>
    internal bool TryAdoptNegotiatedVersion(uint version)
    {
        if (_adoptedNegotiatedVersion
            || version == (uint)_version
            || !IsImplementedVersion(version))
        {
            return false;
        }

        // s2.3: "the server MUST NOT select a version that the client did not include in its
        // Available Versions". Enforcing that from this side is what stops an off-path sender
        // moving the connection to a version this client never offered - a forged Initial
        // header is unauthenticated, and adopting on it would let one datagram re-key the
        // handshake.
        if (Array.IndexOf(_offeredVersions, version) < 0)
        {
            return false;
        }

        _version = (TlsQuicVersion)version;
        _receiver.Version = version;
        _keys.AdoptVersion(_version);
        _keys.InstallInitialKeys(_destinationConnectionId, isClient: true);
        _adoptedNegotiatedVersion = true;
        return true;
    }

    /// <summary>
    /// RFC 9368 section 4: checks the server's <c>version_information</c> against the version
    /// actually in use.
    /// </summary>
    /// <remarks>
    /// <para>s4: "If the Chosen Version field does not match the version of the connection, the
    /// client MUST close the connection with a connection error of type
    /// VERSION_NEGOTIATION_ERROR." That code is 0x11, and it did not exist in this tree until
    /// the audit's C2 added it - which is a small illustration of why a missing error code is
    /// not a cosmetic gap.</para>
    /// <para>A SERVER THAT SENDS NONE IS NOT AN ERROR. s4 makes the parameter's absence mean
    /// the server does not implement RFC 9368, and a connection that never switched versions is
    /// then perfectly ordinary. Only a switch with no confirmation is a problem, and that is
    /// the second branch.</para>
    /// </remarks>
    /// <param name="peer">The server's transport parameters.</param>
    /// <param name="error">The s20.1 code to close with, when this returns false.</param>
    /// <param name="reason">Human-readable detail for the CONNECTION_CLOSE.</param>
    /// <returns>Whether the pair is consistent.</returns>
    internal bool ValidateServerVersionInformation(
        TlsQuicTransportParameters peer,
        out TlsQuicTransportError error,
        out string reason)
    {
        error = TlsQuicTransportError.NoError;
        reason = string.Empty;

        var parameter = peer.Get((ulong)TlsQuicTransportParameterId.VersionInformation);
        if (parameter is null)
        {
            if (!_adoptedNegotiatedVersion)
            {
                return true;
            }

            error = TlsQuicTransportError.VersionNegotiationError;
            reason =
                $"This connection moved to QUIC version 0x{(uint)_version:X8} because the "
                + "server's first flight arrived in it, but the server sent no "
                + "version_information (RFC 9368 s3) to confirm the choice.";
            return false;
        }

        if (!TlsQuicTransportParameters.TryDecodeVersionInformation(
                parameter.ValueSpan, out var chosen, out _))
        {
            error = TlsQuicTransportError.VersionNegotiationError;
            reason = "The server's version_information (RFC 9368 s3) is malformed.";
            return false;
        }

        if (chosen != (uint)_version)
        {
            error = TlsQuicTransportError.VersionNegotiationError;
            reason =
                $"The server's version_information names chosen version 0x{chosen:X8} but its "
                + $"packets carry 0x{(uint)_version:X8}. RFC 9368 s4 makes that a "
                + "VERSION_NEGOTIATION_ERROR.";
            return false;
        }

        return true;
    }
}
