namespace SharpTls.Quic;

/// <content>
/// RFC 9000 section 5.1's connection-ID lifecycle: the peer's NEW_CONNECTION_ID frames, the
/// Retire Prior To they carry, and the RETIRE_CONNECTION_ID frames this endpoint owes back.
///
/// WHY THIS IS A FILE AND NOT FOUR LINES IN THE FRAME SWITCH. Before it, NEW_CONNECTION_ID was
/// parsed in full - TlsQuicConnectionFrames.TryReadNewConnectionId validates every field and
/// fills RetirePriorTo - and then fell into the frame switch's `default:` arm and was dropped.
/// Nothing in src/ read RetirePriorTo at all. Three consequences, and only the first is a
/// conformance one:
///
///   1. s19.15's MUST was unmet. "Upon receipt of an increased Retire Prior To field, the peer
///      MUST stop using the corresponding connection IDs and retire them with
///      RETIRE_CONNECTION_ID frames" - neither half happened.
///   2. s5.1.1's CONNECTION_ID_LIMIT_ERROR was unenforceable, because nothing counted the
///      connection IDs the peer had provided.
///   3. No connection ID rotation, so the linkability defence s5.1 exists for was off - and
///      that one is a fingerprint, not just a conformance gap. The shipped Spotify preset
///      advertises active_connection_id_limit = 64, which is a standing invitation to send
///      exactly the frames that were being ignored.
/// </content>
internal sealed partial class TlsQuicConnection
{
    /// <summary>RFC 9000 s18.2's default when the ClientHello carries no
    /// <c>active_connection_id_limit</c> (0x0E): "If this transport parameter is absent, a
    /// default of 2 is assumed."</summary>
    internal const ulong DefaultActiveConnectionIdLimit = 2;

    /// <summary>The peer's unretired connection IDs, by s19.15 sequence number.</summary>
    /// <remarks>THE HANDSHAKE'S IS SEQUENCE 0 AND IS NOT IN HERE. s5.1.1: "The initial
    /// connection ID issued by an endpoint is sent in the Source Connection ID field of the
    /// long header packet during the handshake" and carries sequence number 0. It is tracked by
    /// <see cref="_activeConnectionIdSequence"/> instead, because it arrived as a header field
    /// rather than as a frame and has no stateless reset token beside it.</remarks>
    private readonly Dictionary<ulong, byte[]> _peerConnectionIds = [];

    /// <summary>Sequence numbers owed a RETIRE_CONNECTION_ID frame and not yet queued.</summary>
    private readonly List<ulong> _retireConnectionIdsOwed = [];

    /// <summary>Every sequence number ever retired, so none is retired twice.</summary>
    private readonly HashSet<ulong> _retiredSequences = [];

    /// <summary>The sequence number of the destination connection ID in use.</summary>
    private ulong _activeConnectionIdSequence;

    /// <summary>The highest <c>Retire Prior To</c> any NEW_CONNECTION_ID frame has carried.</summary>
    /// <remarks>MONOTONIC BY s19.15: "Receipt of a NEW_CONNECTION_ID frame with a Retire Prior
    /// To field that is less than one previously received" is not an error - the frame is
    /// simply ignored for retirement purposes - so this only ever rises.</remarks>
    private ulong _retirePriorTo;

    /// <summary>
    /// The RFC 9000 s20.1 code the last protocol failure should close with, when it is not
    /// PROTOCOL_VIOLATION.
    /// </summary>
    /// <remarks>A FIELD RATHER THAN A THROW ARGUMENT, because this connection has no immediate
    /// -close path yet: a protocol failure raises InvalidOperationException carrying only a
    /// message, and the comment at that throw records that the s20.1 codes will have to be told
    /// apart when the close lands. CONNECTION_ID_LIMIT_ERROR (0x09) is the first failure in this
    /// tree whose code is neither PROTOCOL_VIOLATION nor a stream error, so it is recorded here
    /// rather than lost - and the message names it too, so nothing is only in a field.</remarks>
    internal TlsQuicTransportError? ProtocolFailureCode { get; private set; }

    /// <summary>How many NEW_CONNECTION_ID frames the peer has sent, for tests and readouts.</summary>
    internal int NewConnectionIdsReceived { get; private set; }

    /// <summary>How many RETIRE_CONNECTION_ID frames this endpoint has queued, likewise.</summary>
    internal int RetireConnectionIdsSent { get; private set; }

    /// <summary>The peer connection IDs held and not retired, sequence 0 included.</summary>
    /// <remarks>SEQUENCE 0 IS COUNTED BY ITS ABSENCE FROM THE RETIRED SET, not by a dictionary
    /// entry. It never arrives as a NEW_CONNECTION_ID frame - s5.1.1 issues it as the Source
    /// Connection ID of the server's first long-header packet - so there is nothing to store,
    /// but s5.1.1 still counts it against active_connection_id_limit and s19.16 still retires
    /// it by number.</remarks>
    internal int ActivePeerConnectionIds =>
        _peerConnectionIds.Count + (_retiredSequences.Contains(0) ? 0 : 1);

    /// <summary>
    /// RFC 9000 s19.15: takes one NEW_CONNECTION_ID frame, and either records the connection ID
    /// or names the connection error the frame is.
    /// </summary>
    /// <remarks>
    /// <para>THE PARSER HAS ALREADY CHECKED THE FRAME'S SHAPE - s19.15's "Retire Prior To ...
    /// MUST be less than or equal to Sequence Number", the 1..20 length bound, the 16-byte
    /// token. What is left is everything that needs CONNECTION state to decide, which is why it
    /// is here and not there.</para>
    /// <para>ORDER MATTERS AMONG THE FOUR CHECKS BELOW, and it is s19.15's own order of
    /// severity: a frame that may not be sent at all is refused before its contents are read.
    /// </para>
    /// </remarks>
    /// <param name="frame">The parsed frame.</param>
    /// <param name="error">The s20.1 code to close with, when this returns false.</param>
    /// <param name="reason">Human-readable detail for the CONNECTION_CLOSE.</param>
    /// <returns>Whether the frame was acceptable.</returns>
    internal bool ReceiveNewConnectionId(
        in TlsQuicFrame frame,
        out TlsQuicTransportError error,
        out string reason)
    {
        error = TlsQuicTransportError.NoError;
        reason = string.Empty;
        NewConnectionIdsReceived++;

        // s19.15: "An endpoint that is sending packets with a zero-length Destination
        // Connection ID MUST treat receipt of a NEW_CONNECTION_ID frame as a connection error
        // of type PROTOCOL_VIOLATION." Our destination connection ID is the peer's, and a
        // profile is free to ask for a zero-length one - TlsQuicConnectionSpec
        // .DestinationConnectionIdLength - so this is reachable rather than theoretical.
        if (_destinationConnectionId.Length == 0)
        {
            error = TlsQuicTransportError.ProtocolViolation;
            reason =
                "The peer sent a NEW_CONNECTION_ID frame (RFC 9000 s19.15) while this endpoint "
                + "sends packets with a zero-length Destination Connection ID, which s19.15 "
                + "makes a PROTOCOL_VIOLATION.";
            return false;
        }

        var connectionId = frame.ConnectionId.ToArray();

        // s19.15: "If an endpoint receives a NEW_CONNECTION_ID frame that repeats a previously
        // issued connection ID with a different Sequence Number or a different Stateless Reset
        // Token, or if a sequence number is used for different connection IDs, the endpoint MAY
        // treat that receipt as a connection error of type PROTOCOL_VIOLATION."
        //
        // THE MAY IS TAKEN, for the reason the duplicate-SETTINGS rule is taken elsewhere in
        // this tree: the alternative a MAY leaves open is silently keeping one of two values,
        // and which one is unspecified - so a peer would get to choose which connection ID this
        // endpoint ends up believing in.
        if (_peerConnectionIds.TryGetValue(frame.SequenceNumber, out var known))
        {
            if (!known.AsSpan().SequenceEqual(connectionId))
            {
                error = TlsQuicTransportError.ProtocolViolation;
                reason =
                    $"The peer reused NEW_CONNECTION_ID sequence number {frame.SequenceNumber} "
                    + "for a different connection ID, which RFC 9000 s19.15 permits treating as "
                    + "a PROTOCOL_VIOLATION.";
                return false;
            }

            // A genuine retransmission of a frame already held. s13.3 makes that ordinary.
            RaiseRetirePriorTo(frame.RetirePriorTo);
            return true;
        }

        // s5.1.1: "An endpoint that receives a NEW_CONNECTION_ID frame with a sequence number
        // smaller than the Retire Prior To field of a previously received NEW_CONNECTION_ID
        // frame MUST send a corresponding RETIRE_CONNECTION_ID frame that retires the newly
        // received connection ID, unless it has already done so for that sequence number."
        // Retired on arrival, never stored, so it cannot be counted against the limit below.
        if (frame.SequenceNumber < _retirePriorTo)
        {
            OweRetire(frame.SequenceNumber);
            RaiseRetirePriorTo(frame.RetirePriorTo);
            return true;
        }

        _peerConnectionIds[frame.SequenceNumber] = connectionId;
        RaiseRetirePriorTo(frame.RetirePriorTo);

        // s5.1.1: "An endpoint MUST NOT provide more connection IDs than the peer's limit. An
        // endpoint that receives more connection IDs than its advertised
        // active_connection_id_limit MUST close the connection with an error of type
        // CONNECTION_ID_LIMIT_ERROR."
        //
        // COUNTED AFTER RETIREMENT, NOT BEFORE. s5.1.1 counts what is ACTIVE, and the frame
        // that pushes the count up is very often the same frame whose Retire Prior To brings it
        // back down - a peer rotating one-for-one is the normal case, not an abusive one.
        // Checking before RaiseRetirePriorTo would close those connections.
        var limit = AdvertisedActiveConnectionIdLimit;
        if ((ulong)ActivePeerConnectionIds > limit)
        {
            error = TlsQuicTransportError.ConnectionIdLimitError;
            reason =
                $"The peer has provided {ActivePeerConnectionIds} active connection IDs but "
                + $"this endpoint advertised active_connection_id_limit = {limit} (RFC 9000 "
                + "s18.2 0x0E). s5.1.1 makes that a CONNECTION_ID_LIMIT_ERROR.";
            return false;
        }

        return true;
    }

    /// <summary>This endpoint's advertised <c>active_connection_id_limit</c> (0x0E).</summary>
    /// <remarks>READ FROM THE PROFILE, NOT FROM A SPEC PROPERTY, for the reason
    /// <c>CustomTlsQuicClient.AdvertisedAckDelayExponent</c>'s remarks give: the ClientHello is
    /// the one place a transport parameter is written, and a second copy would be a second
    /// source of truth for one advertised number. Enforcing a limit other than the advertised
    /// one is the divergence TlsQuicStreams.cs's block comment forbids.</remarks>
    private ulong AdvertisedActiveConnectionIdLimit =>
        _client?.AdvertisedActiveConnectionIdLimit ?? DefaultActiveConnectionIdLimit;

    /// <summary>
    /// RFC 9000 s19.15's Retire Prior To: retires every connection ID below
    /// <paramref name="retirePriorTo"/> and owes a RETIRE_CONNECTION_ID frame for each.
    /// </summary>
    /// <remarks>
    /// <para>s5.1.2: "An endpoint MUST NOT use a connection ID it has retired", and s19.16
    /// forbids retiring the one in use without replacing it first. So the active connection ID
    /// is SWITCHED before it is retired.</para>
    /// <para>THE NO-SUCCESSOR BRANCH IS DEFENSIVE AND IS NOT REACHABLE TODAY, which is stated
    /// rather than left for a reader to work out. s19.15 requires "Retire Prior To ... less
    /// than or equal to Sequence Number" and TlsQuicConnectionFrames.TryReadNewConnectionId
    /// enforces it, so the very frame that raises the floor also supplies a connection ID at or
    /// above it. Should that invariant ever move - a server role, a relaxed parser - the
    /// retirement of the active ID is DEFERRED rather than the connection broken: a peer that
    /// raises Retire Prior To without supplying a successor has violated s5.1.1, and answering
    /// its bug by killing a working connection helps nobody. Every OTHER connection ID below
    /// the floor is retired immediately, and a deferred one is picked up by the next
    /// NEW_CONNECTION_ID frame through this same method.</para>
    /// <para>MONOTONIC. s19.15 makes a lower Retire Prior To than one already seen a no-op
    /// rather than an error, which is what the first guard is.</para>
    /// </remarks>
    private void RaiseRetirePriorTo(ulong retirePriorTo)
    {
        if (retirePriorTo <= _retirePriorTo)
        {
            return;
        }

        _retirePriorTo = retirePriorTo;

        // The successor is the lowest sequence at or above the new floor. Lowest rather than
        // any, so two endpoints reading the same frames make the same choice and a packet
        // capture is reproducible.
        ulong? successor = null;
        foreach (var sequence in _peerConnectionIds.Keys)
        {
            if (sequence >= retirePriorTo && (successor is null || sequence < successor))
            {
                successor = sequence;
            }
        }

        var mustReplaceActive = _activeConnectionIdSequence < retirePriorTo;
        if (mustReplaceActive && successor is { } replacement)
        {
            _destinationConnectionId = _peerConnectionIds[replacement];
            _activeConnectionIdSequence = replacement;
            mustReplaceActive = false;
        }

        var retiring = new List<ulong>();
        foreach (var sequence in _peerConnectionIds.Keys)
        {
            if (sequence < retirePriorTo)
            {
                retiring.Add(sequence);
            }
        }

        foreach (var sequence in retiring)
        {
            // The one exception: the active connection ID with no successor to move to. It
            // stays held and unretired until one arrives.
            if (mustReplaceActive && sequence == _activeConnectionIdSequence)
            {
                continue;
            }

            _peerConnectionIds.Remove(sequence);
            OweRetire(sequence);
        }

        // Sequence 0 came from the handshake rather than from a frame, so it is not in the
        // dictionary - but it is still a connection ID the peer issued and s19.16 still wants
        // it retired by number.
        if (!mustReplaceActive && retirePriorTo > 0 && _activeConnectionIdSequence >= retirePriorTo)
        {
            OweRetire(0);
        }
    }

    /// <summary>Records that a RETIRE_CONNECTION_ID frame is owed, at most once per sequence
    /// number.</summary>
    /// <remarks>
    /// <para>s5.1.1's "unless it has already done so for that sequence number" is the duplicate
    /// check, and <see cref="_retiredSequences"/> rather than the owed list is what answers it:
    /// the owed list empties as frames are queued, so asking it would let a sequence be retired
    /// twice once the first frame had left.</para>
    /// <para>OWED HERE, QUEUED IN THE SEND PATH. The 1-RTT frame queue lives on
    /// <c>TlsQuicStreamSet</c>, which does not exist until the peer's transport parameters
    /// arrive - so touching it from a frame handler would be an ordering hazard for the sake of
    /// one line. <see cref="FlushRetireConnectionIds"/> drains this into that queue from the
    /// send path, which already tests for the set.</para>
    /// </remarks>
    private void OweRetire(ulong sequenceNumber)
    {
        if (!_retiredSequences.Add(sequenceNumber))
        {
            return;
        }

        _retireConnectionIdsOwed.Add(sequenceNumber);
        RetireConnectionIdsSent++;
    }

    /// <summary>Moves every owed RETIRE_CONNECTION_ID onto the 1-RTT frame queue.</summary>
    /// <remarks>Called from the application send path, so the frames are budgeted, coalesced
    /// behind an ACK and repaired on loss by the machinery MAX_DATA and MAX_STREAM_DATA already
    /// use, rather than by a send path of their own.</remarks>
    internal void FlushRetireConnectionIds()
    {
        if (_retireConnectionIdsOwed.Count == 0 || _streams is not { } streams)
        {
            return;
        }

        foreach (var sequenceNumber in _retireConnectionIdsOwed)
        {
            streams.QueueConnectionFrame(new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.RetireConnectionId,
                SequenceNumber = sequenceNumber,
            });
        }

        _retireConnectionIdsOwed.Clear();
    }
}
