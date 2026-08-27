using System.Collections.Immutable;
using System.Runtime.InteropServices;

namespace SharpTls.Quic;

/// <summary>RFC 9114 s6.2's unidirectional streams: the three this client opens, in the spec's
/// order, and the peer's, dispatched by their stream-type varint.</summary>
/// <remarks>
/// <para>NEVER THROWS ON PEER INPUT. <see cref="TryProcessPeerStreams"/> and everything it
/// calls answer with a connection error code; the only throwing members are the ones a LOCAL
/// caller drives, and they throw on local misuse. C16 widened that code from
/// <see cref="TlsQuicHttp3ErrorCode"/> to a <see cref="ulong"/> so RFC 9204 s6's 0x0201 fits,
/// and it is the same widening that keeps the promise: the three s4.4 senders DO throw, and
/// the constructor refuses a dynamic table whenever a peer could otherwise reach one.</para>
/// <para>C16 ROUTED THE PEER'S ENCODER STREAM, which this paragraph used to say was left
/// alone. RFC 9204 s4.3's instructions now drive <see cref="Table"/>, and s4.4's three
/// decoder instructions are sent back on our own decoder stream. The peer's DECODER stream is
/// still discarded, and <see cref="TryTakeStreamType"/> says why: it acknowledges our
/// encoder's table, and our encoder is static-only. Request streams are task C9's and
/// connection teardown is C11's.</para>
/// <para>C11 ADDED GOAWAY, and only the part that belongs on the control stream: s7.2.6's two
/// MUSTs about the identifier, and recording it on <see cref="PeerGoawayStreamId"/>. What the
/// identifier MEANS for a request - s5.2's "requests ... with the indicated identifier or
/// greater are rejected" and its "MUST NOT initiate new requests" - is
/// <see cref="TlsQuicHttp3Connection"/>'s, because this class knows nothing about request
/// streams.</para>
/// </remarks>
internal sealed class TlsQuicHttp3Streams
{
    // The unparsed tail of one peer-initiated unidirectional stream, plus what we have
    // concluded about it. A List<byte> rather than a slice of TlsQuicStream.Received because
    // this class consumes a PREFIX at a time and needs to keep the remainder across calls;
    // mirroring the delivered bytes here costs one copy and avoids reimplementing 14e's
    // in-order reassembly, which is what a second offset-tracking buffer would amount to.
    private sealed class PeerStreamState
    {
        // BOUNDED, BUT ONLY AS A RESIDUE AND NOT AS AN ARRIVAL. This list is filled from the
        // peer's bytes and drained by whichever parser the stream's type selects, so what
        // survives a pass through TryProcessPeerStream is exactly the prefix that parser could
        // not take - a frame or an instruction whose declared length has not arrived. That
        // leftover is what the two ceilings measure, each at the point its own parser has
        // finished; a check taken before the parse would refuse a peer merely sending fast.
        internal readonly List<byte> Unparsed = [];

        // How many of TlsQuicStream.Received's bytes have been copied into Unparsed. Not how
        // many have been PARSED - Unparsed shrinks as frames are taken, this only grows.
        internal int Copied;

        internal ulong? StreamType;

        // Set once the stream's type is known and is anything but the control stream. Its
        // bytes are then dropped as they arrive rather than accumulated.
        //
        // ONE FLAG FOR "UNKNOWN" AND FOR "KNOWN BUT NOT OURS", which the first draft of this
        // file split in two. s6.2's "Recipients of unknown stream types MUST either abort
        // reading of the stream or discard incoming data without further processing" is the
        // rule for the first; a QPACK encoder stream reaching a static-only decoder gets the
        // same treatment for a different reason, and NOTHING IN THIS TASK CAN TELL THE TWO
        // APART - a mutation sweep found the branch that distinguished them survived, because
        // both ended in the same place. Merging them removed the survivor rather than writing
        // a test that asserted a difference nothing observes.
        //
        // C16 TOOK THE ENCODER STREAM OUT OF THIS FLAG, and the sentence C15 left here - "the
        // peer's encoder stream is still discarded" - is no longer true. It is now parsed, in
        // TryReadEncoderStream. The merge argued above still holds for what remains: a push
        // stream, the peer's DECODER stream, a GREASE stream and an unknown type are all
        // discarded and nothing observes a difference between them.
        //
        // NOT THE SAME AS "there is no table". A zero advertised capacity leaves Table null and
        // the encoder stream's bytes are dropped in TryReadEncoderStream instead - a different
        // place on purpose, because that stream's TYPE is known and s4.2 makes the zero-capacity
        // choice a configuration rather than an unknown.
        internal bool Ignoring;

        internal bool FirstFrameSeen;
    }

    private readonly TlsQuicHttp3Spec _spec;
    private readonly TlsQuicStreamSet _streams;
    private readonly Dictionary<ulong, PeerStreamState> _peerStreams = [];
    private readonly List<ulong> _localStreamIds = [];

    // RFC 9204 s4.4's three instructions and s2.1.4's Known Received Count, which is
    // per-connection state and so lives with the connection's streams rather than with the
    // static decoder that reads field sections.
    private readonly TlsQuicQpackDecoderStream _decoderStream = new();

    // How much of the peer's encoder stream may sit unparsed. Resolved ONCE, in the
    // constructor, because it is derived from this endpoint's own advertised
    // SETTINGS_QPACK_MAX_TABLE_CAPACITY and those cannot change after the SETTINGS frame is
    // sent. See DeriveEncoderStreamCeiling for the derivation and for why the spec's knob is
    // an override rather than the source. The control stream's ceiling needs no field: it is
    // read straight off the spec, having nothing to derive from.
    private readonly int _encoderStreamCeiling;

    /// <summary>Creates the HTTP/3 stream layer over 14e's QUIC stream set.</summary>
    /// <exception cref="ArgumentNullException">Either argument is
    /// <see langword="null"/>.</exception>
    internal TlsQuicHttp3Streams(TlsQuicHttp3Spec spec, TlsQuicStreamSet streams)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(streams);
        _spec = spec;
        _streams = streams;

        // C16. BOTH NUMBERS COME FROM OUR OWN SETTINGS, never from a constant here, so that
        // TlsQuicHttp3Spec.CaptureSettings's shipped 65536 and 100 and a test's narrowed 0 and
        // 0 flow through the same code. RFC 9204 s5 supplies the default for a setting we do
        // not send - "The initial value ... is zero" for both - which is what `?? 0` is.
        //
        // s7.2.4's Value is a varint and runs to 2^62-1 while the table's capacity is an int,
        // so this saturates the way TlsQuicHttp3Connection.AsFieldSectionLimit does rather than
        // casting: an unchecked cast of a huge advertised capacity wraps to a negative and the
        // table's constructor throws on it, turning our own SETTINGS into an exception.
        var capacity =
            TlsQuicHttp3Settings.Value(spec.Settings, TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier) ?? 0;

        // TWO CONDITIONS, NOT ONE, AND THE SECOND IS NOT BELT-AND-BRACES. A zero capacity has
        // no table by s3.2.2. But s4.2 permits omitting the DECODER STREAM only "if its decoder
        // sets the maximum capacity of the dynamic table to zero", so a spec whose open order
        // leaves that stream out has said it decodes at zero whatever else it advertises - and
        // a table without one would let a peer's non-zero Required Insert Count drive us into
        // the InvalidOperationException the three s4.4 senders raise. Nothing a peer sends may
        // reach a throw, so the table is refused instead.
        var decoderStreamPlanned =
            spec.UnidirectionalStreamOpenOrder.Contains(TlsQuicHttp3StreamType.QpackDecoder);

        Table = capacity > 0 && decoderStreamPlanned
            ? new TlsQuicQpackDynamicTable(capacity < int.MaxValue ? (int)capacity : int.MaxValue)
            : null;

        BlockedStreams = new TlsQuicQpackBlockedStreams(
            TlsQuicHttp3Settings.Value(spec.Settings, TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier) ?? 0);

        // THE SAME `capacity` THE TABLE WAS BUILT FROM, which is the point: what this endpoint
        // told the peer it would hold in its dynamic table is also what bounds the instruction
        // stream that fills it. A null knob means derive; a value means the caller has said it
        // knows better, and this is the only place either is read.
        _encoderStreamCeiling =
            spec.MaximumBufferedEncoderStreamBytes ?? DeriveEncoderStreamCeiling(capacity);
    }

    /// <summary>Gets the QUIC stream ids this client opened, in the order it opened
    /// them.</summary>
    /// <remarks>A convenience for a caller that has the ids and not the frames. It is NOT what
    /// witnesses the open order - TlsQuicHttp3StreamsTests.TheThreeStreamsAreOpenedInTheSpecs
    /// Order reads the recorded STREAM frames instead, because this list and the spec are both
    /// things this class was told and neither is a thing it did.</remarks>
    internal IReadOnlyList<ulong> LocalStreamIds => _localStreamIds;

    /// <summary>Gets this client's control stream, or <see langword="null"/> before
    /// <see cref="OpenLocalStreams"/>.</summary>
    internal TlsQuicStream? LocalControlStream { get; private set; }

    /// <summary>Gets this client's QPACK decoder stream, or <see langword="null"/> before
    /// <see cref="OpenLocalStreams"/> or when the spec's open order omits it.</summary>
    /// <remarks>NULLABLE FOR A REASON THE CONTROL STREAM'S IS NOT.
    /// <see cref="TlsQuicHttp3Spec.UnidirectionalStreamOpenOrder"/> requires
    /// <see cref="TlsQuicHttp3StreamType.Control"/> to be present and does not require this
    /// one, because RFC 9204 s4.2 permits omitting the decoder stream "if its decoder sets the
    /// maximum capacity of the dynamic table to zero". A spec that omits it has made that
    /// choice, and the three senders below then refuse rather than inventing a stream.</remarks>
    internal TlsQuicStream? LocalDecoderStream { get; private set; }

    /// <summary>Gets s2.1.4's Known Received Count, as this decoder has reported it.</summary>
    internal ulong KnownReceivedCount => _decoderStream.KnownReceivedCount;

    /// <summary>Gets the QUIC stream id of the peer's control stream, or
    /// <see langword="null"/> until its type varint has arrived.</summary>
    internal ulong? PeerControlStreamId { get; private set; }

    /// <summary>Gets whether the peer's SETTINGS frame has been read.</summary>
    /// <remarks>ZERO IS NOT ABSENT. A peer that sends a SETTINGS frame with an empty payload
    /// sets this to <see langword="true"/> with <see cref="PeerSettings"/> empty - s7.2.4
    /// allows "zero or more parameters" - and that is a different state from no SETTINGS frame
    /// having arrived, which is what H3_MISSING_SETTINGS names.</remarks>
    internal bool PeerSettingsReceived { get; private set; }

    /// <summary>Gets the peer's settings, in the peer's wire order.</summary>
    internal ImmutableArray<TlsQuicHttp3Setting> PeerSettings { get; private set; } = [];

    /// <summary>Gets the identifier of the most recent GOAWAY the peer sent, or
    /// <see langword="null"/> if it has sent none.</summary>
    /// <remarks>
    /// <para>ZERO IS A REAL IDENTIFIER AND NOT AN ABSENCE, which is why this is nullable rather
    /// than a <see cref="ulong"/> defaulting to 0. s5.2: "This identifier MAY be zero if no
    /// requests or pushes were processed" - the strongest GOAWAY a server can send, rejecting
    /// every request including stream 0 - so a design that read 0 as "none" would treat the
    /// most severe shutdown as no shutdown at all.</para>
    /// <para>THE MOST RECENT AND NOT THE FIRST. s5.2 lets an endpoint "send multiple GOAWAY
    /// frames indicating different identifiers", each no greater than the last, and the
    /// paragraph explaining why - a first frame at the maximum value followed by a narrower one
    /// - only works if the later, smaller identifier is the one that stands.</para>
    /// </remarks>
    internal ulong? PeerGoawayStreamId { get; private set; }

    /// <summary>Gets whether RFC 9297 s2.1.1 permits sending QUIC DATAGRAM frames yet.</summary>
    /// <remarks>
    /// <para>s2.1.1: "QUIC DATAGRAM frames MUST NOT be sent until the SETTINGS_H3_DATAGRAM
    /// setting has been both sent and received with a value of 1." BOTH halves, which is why
    /// this is an <c>&amp;&amp;</c> of two lookups and not a read of the spec alone. It is
    /// what stops <see cref="TlsQuicHttp3Spec.Settings"/>'s <c>51:1</c> default from being a
    /// constant that licenses something: advertising willingness to RECEIVE says nothing about
    /// permission to SEND.</para>
    /// <para>It is false today for every peer, because nothing in this stack sends a DATAGRAM
    /// frame - <see cref="TlsQuicFrameType"/> has no such member. It is here so that the
    /// sending task cannot be written without meeting the gate.</para>
    /// </remarks>
    internal bool Http3DatagramsPermittedToSend =>
        DatagramWillingness(_spec.Settings) && DatagramWillingness(PeerSettings);

    // Absent is not willing, which is why the null-coalesce is to 0 and not to 1.
    private static bool DatagramWillingness(IReadOnlyList<TlsQuicHttp3Setting> settings) =>
        TlsQuicHttp3Settings.Value(settings, TlsQuicHttp3Spec.H3DatagramIdentifier) == 1;

    /// <summary>Gets the dynamic table the peer's encoder stream drives, or
    /// <see langword="null"/> when this endpoint decodes on RFC 9204 s3.2.3's zero-capacity
    /// arm.</summary>
    /// <remarks>See the constructor for the two conditions that decide which.</remarks>
    internal TlsQuicQpackDynamicTable? Table { get; }

    /// <summary>Gets RFC 9204 s2.1.2's registry of streams blocked at once, bounded by the
    /// <c>SETTINGS_QPACK_BLOCKED_STREAMS</c> this endpoint advertised.</summary>
    internal TlsQuicQpackBlockedStreams BlockedStreams { get; }

    /// <summary>Opens this client's unidirectional streams in
    /// <see cref="TlsQuicHttp3Spec.UnidirectionalStreamOpenOrder"/>'s order, writing each
    /// stream's s6.2 type varint and, on the control stream, the SETTINGS frame.</summary>
    /// <remarks>
    /// <para>THE TYPE VARINT AND THE SETTINGS FRAME GO IN ONE SEND. s6.2.1 requires SETTINGS
    /// to be "the first frame on this stream", which is a statement about the stream's byte
    /// order and not about packetisation, and one send is the shortest way to make the byte
    /// order unarguable. A second send would be equally conforming and would put the two in
    /// two STREAM frames that a peer could see arrive apart.</para>
    /// <para>NO FIN. s6.2.1: "The sender MUST NOT close the control stream", so nothing here
    /// passes <c>fin: true</c>, and the QPACK streams stay open for the same reason RFC 9204
    /// s4.2 gives.</para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">Already called, or the peer's
    /// initial_max_streams_uni cannot cover the spec's list - RFC 9114 s6.2's "the transport
    /// parameters sent by both clients and servers MUST allow the peer to create at least
    /// three unidirectional streams" is the peer's obligation and 14d reports a peer that
    /// breaks it.</exception>
    internal void OpenLocalStreams()
    {
        if (_localStreamIds.Count != 0)
        {
            throw new InvalidOperationException(
                "RFC 9114 s6.2.1: \"Only one control stream per peer is permitted\", so the "
                    + "opening flight is sent once.");
        }

        var bytes = new List<byte>();
        foreach (var streamType in _spec.UnidirectionalStreamOpenOrder)
        {
            bytes.Clear();
            QuicVariableLengthInteger.Write(bytes, (ulong)streamType);
            if (streamType == TlsQuicHttp3StreamType.Control)
            {
                TlsQuicHttp3Settings.Encode(bytes, _spec);
            }

            var stream = _streams.OpenUnidirectional();
            _streams.Send(stream, bytes.ToArray());
            _localStreamIds.Add(stream.Id);
            if (streamType == TlsQuicHttp3StreamType.Control)
            {
                LocalControlStream = stream;
            }
            else if (streamType == TlsQuicHttp3StreamType.QpackDecoder)
            {
                LocalDecoderStream = stream;
            }
        }
    }

    // ============================================================================
    // RFC 9204 s4.4's decoder instructions, sent on the s4.2 decoder stream
    // ============================================================================
    //
    // Three thin senders over TlsQuicQpackDecoderStream, which owns the bytes and s2.1.4's
    // Known Received Count. Everything RFC-shaped is there; what is here is the stream.
    //
    // THESE THROW, unlike everything the peer drives. They are LOCAL calls - nothing a peer
    // sends reaches them - and the two ways to get them wrong are calling before
    // OpenLocalStreams and calling on a spec whose open order left the decoder stream out.
    // Both are this endpoint's mistake, and s4.2 makes the second a deliberate configuration
    // rather than an accident, so failing loudly is the only answer that distinguishes them.

    /// <summary>Emits RFC 9204 s4.4.1's Section Acknowledgment for a field section decoded on
    /// <paramref name="streamId"/>, or nothing at all if its Required Insert Count was
    /// zero.</summary>
    /// <returns><see langword="true"/> if an instruction was sent.</returns>
    /// <remarks>THE ZERO CASE SENDS NOTHING AND IS NOT AN ERROR. s4.4.1 acknowledges only "an
    /// encoded field section whose declared Required Insert Count is not zero"; an
    /// acknowledgment sent for one that used no dynamic entry is a
    /// QPACK_DECODER_STREAM_ERROR at the peer's encoder.</remarks>
    /// <exception cref="InvalidOperationException">There is no local decoder stream.</exception>
    internal bool SendSectionAcknowledgment(ulong streamId, ulong requiredInsertCount)
    {
        byte[] instruction = NewInstructionBuffer();
        return Emit(
            _decoderStream.TryWriteSectionAcknowledgment(streamId, requiredInsertCount, instruction, out int written),
            instruction,
            written);
    }

    /// <summary>Emits RFC 9204 s4.4.2's Stream Cancellation for a request stream that was
    /// reset or whose reading was abandoned.</summary>
    /// <returns><see langword="true"/> always; the shape matches its two siblings, neither of
    /// which always sends.</returns>
    /// <exception cref="InvalidOperationException">There is no local decoder stream.</exception>
    internal bool SendStreamCancellation(ulong streamId)
    {
        byte[] instruction = NewInstructionBuffer();
        return Emit(
            _decoderStream.TryWriteStreamCancellation(streamId, instruction, out int written),
            instruction,
            written);
    }

    /// <summary>Emits RFC 9204 s4.4.3's Insert Count Increment carrying
    /// <paramref name="insertCount"/> less s2.1.4's Known Received Count, or nothing at all if
    /// that difference is zero.</summary>
    /// <returns><see langword="true"/> if an instruction was sent.</returns>
    /// <remarks><paramref name="insertCount"/> is
    /// <see cref="TlsQuicQpackDynamicTable.InsertCount"/>, the running total; the Increment is
    /// derived from it. A zero Increment is suppressed - s4.4.3 makes one a
    /// QPACK_DECODER_STREAM_ERROR at the peer's encoder - which is what happens when a Section
    /// Acknowledgment has already pulled the Known Received Count up to the insert
    /// count.</remarks>
    /// <exception cref="InvalidOperationException">There is no local decoder stream.</exception>
    internal bool SendInsertCountIncrement(ulong insertCount)
    {
        byte[] instruction = NewInstructionBuffer();
        return Emit(
            _decoderStream.TryWriteInsertCountIncrement(insertCount, instruction, out int written),
            instruction,
            written);
    }

    // The scratch every instruction is built into. A FRESH ARRAY PER CALL rather than a reused
    // field, because it escapes into TlsQuicStreamSet.Send's ReadOnlyMemory and a shared one
    // would be rewritten under a send that has not been flushed yet. Eleven bytes.
    private byte[] NewInstructionBuffer()
    {
        // Checked before the instruction is built, not after, so that the suppressed cases -
        // a zero Required Insert Count, a zero Increment - fail here too. A caller asking this
        // endpoint to acknowledge on a stream it chose never to open has made the same mistake
        // whichever way the suppression happens to fall, and a check that only fires half the
        // time is a check that gets found in production.
        if (LocalDecoderStream is null)
        {
            throw new InvalidOperationException(
                "RFC 9204 s4.2: the decoder stream may be omitted only \"if its decoder sets the "
                    + "maximum capacity of the dynamic table to zero\". This spec's "
                    + "UnidirectionalStreamOpenOrder omits it, or OpenLocalStreams has not run, "
                    + "so there is no stream to send a decoder instruction on.");
        }

        return new byte[TlsQuicQpackDecoderStream.MaximumInstructionLength];
    }

    private bool Emit(bool encoded, byte[] instruction, int written)
    {
        // MaximumInstructionLength is the longest a single prefixed integer can be and every
        // s4.4 instruction is exactly one, so `encoded` being false is a bug in this file
        // rather than anything a peer or a caller did.
        if (!encoded)
        {
            throw new InvalidOperationException(
                "A decoder instruction did not fit TlsQuicQpackDecoderStream.MaximumInstructionLength.");
        }

        // s4.4.1's and s4.4.3's suppressed cases. Nothing is sent and nothing is wrong.
        if (written == 0)
        {
            return false;
        }

        // NO FIN, for RFC 9204 s4.2's reason: "The sender MUST NOT close either of these
        // streams" - and a decoder stream that closes leaves the peer's encoder unable to
        // learn anything further about our table.
        _streams.Send(LocalDecoderStream!, instruction.AsMemory(0, written));
        return true;
    }

    /// <summary>Reads everything the peer has delivered on its unidirectional streams,
    /// dispatching by s6.2 stream type, and reports the s8.1 code to close with if it cannot
    /// be accepted.</summary>
    /// <remarks>
    /// <para>NEVER THROWS, for any input. Idempotent and resumable: bytes already parsed are
    /// not reparsed, and a stream that stops mid-field is left for the next call.</para>
    /// <para>A STREAM WITH NO TYPE VARINT YET IS NOT AN ERROR, EVEN AT FIN. s6.2: "A receiver
    /// MUST tolerate unidirectional streams being closed or reset prior to the reception of
    /// the unidirectional stream header." So a peer stream that carries zero bytes and ends is
    /// dropped silently - and it is dropped rather than left pending, because a stream whose
    /// type never arrived can never become the control stream and holding state for it is how
    /// a peer makes us leak.</para>
    /// <para>THE CODE IS A <see cref="ulong"/> AND NOT A <see cref="TlsQuicHttp3ErrorCode"/>,
    /// which C16 widened it to. RFC 9204 s6's <c>QPACK_ENCODER_STREAM_ERROR</c> is 0x0201 and
    /// sits outside that enum's 0x0100..0x010e range - the same reason and the same shape as
    /// TlsQuicHttp3Response.TryRead's own code, whose comment argues it at length. Every s8.1
    /// answer below is still the enum, cast at the one place it leaves.</para>
    /// </remarks>
    internal bool TryProcessPeerStreams(out ulong error)
    {
        foreach (var stream in _streams.PeerInitiated)
        {
            // s6.1: "Clients MUST treat receipt of a server-initiated bidirectional stream as
            // a connection error of type H3_STREAM_CREATION_ERROR unless such an extension has
            // been negotiated." None is.
            if (stream.Direction == TlsQuicStreamDirection.Bidirectional)
            {
                error = (ulong)TlsQuicHttp3ErrorCode.H3StreamCreationError;
                return false;
            }

            if (!TryProcessPeerStream(stream, out error))
            {
                return false;
            }
        }

        error = (ulong)TlsQuicHttp3ErrorCode.None;
        return true;
    }

    private bool TryProcessPeerStream(TlsQuicStream stream, out ulong error)
    {
        error = (ulong)TlsQuicHttp3ErrorCode.None;

        if (!_peerStreams.TryGetValue(stream.Id, out var state))
        {
            state = new PeerStreamState();
            _peerStreams.Add(stream.Id, state);
        }

        if (state.Ignoring)
        {
            // s6.2's second legal answer to an unknown type: "discard incoming data without
            // further processing", and "The recipient MUST NOT consider unknown stream types
            // to be a connection error of any kind."
            return true;
        }

        var delivered = stream.Received;
        for (var i = state.Copied; i < delivered.Count; i++)
        {
            state.Unparsed.Add(delivered[i]);
        }
        state.Copied = delivered.Count;

        if (state.StreamType is null && !TryTakeStreamType(stream, state, out var typeError))
        {
            error = (ulong)typeError;
            return typeError == TlsQuicHttp3ErrorCode.None;
        }

        // C16's encoder-stream arm, and the ONE stream type that is neither the control stream
        // nor discarded. RFC 9204 s4.3's instructions are what drive the dynamic table, and
        // s2.1.2 is why they arrive here rather than inside a field section: "encoded field
        // sections and encoder stream instructions arrive on separate streams".
        if (state.StreamType == (ulong)TlsQuicHttp3StreamType.QpackEncoder)
        {
            if (!TryReadEncoderStream(state, out error))
            {
                return false;
            }

            // THE RESIDUE, AND THE ZERO-CAPACITY ARM IS WHY THE ORDER MATTERS RATHER THAN
            // MERELY BEING TIDIER. TryReadEncoderStream CLEARS this buffer when there is no
            // table to drive, so an endpoint that advertised capacity 0 discards a peer's
            // encoder burst harmlessly - and a ceiling checked ahead of that discard would
            // close the connection over bytes this endpoint had already decided to throw away.
            if (state.Unparsed.Count > _encoderStreamCeiling)
            {
                error = TlsQuicQpackDynamicTable.QpackEncoderStreamError;
                return false;
            }

            return true;
        }

        // NO SECOND `if (state.Ignoring)` HERE, and its absence is deliberate. A stream that
        // was just marked ignored has had its buffer cleared, so this call parses nothing and
        // answers Incomplete. An earlier draft had the redundant check; the sweep killed
        // neither it nor the one above, because either alone sufficed, and a guard that cannot
        // be witnessed because a sibling covers it is a guard to delete rather than to test.
        if (!TryParseControlFrames(state, out var frameError))
        {
            error = (ulong)frameError;
            return false;
        }

        // WHAT THE LOOP ABOVE COULD NOT TAKE, WHICH IS THE ONLY QUANTITY WORTH BOUNDING.
        // TryParseControlFrames runs until TlsQuicHttp3Frames.TryRead answers Incomplete, so
        // every whole frame is already gone and what is left is one frame that has not finished
        // arriving. THIS IS A CORRECTION OF THE FIRST ATTEMPT AT THIS GUARD, which measured the
        // buffer BEFORE the loop and so refused a pass that delivered a lot of perfectly legal,
        // wholly parseable frames at once - a peer sending fast is not a peer sending a Length
        // it will never satisfy, and only the residue tells the two apart.
        //
        // s8.1's H3_EXCESSIVE_LOAD, "The endpoint detected that its peer is exhibiting a
        // behavior that might be generating excessive load", and NOT H3_FRAME_ERROR: s7.1's
        // Length is a varint to 2^62-1 and a frame declaring more than we will hold is legal,
        // so the fault named is the load and not the layout. TlsQuicHttp3Frames.TryRead keeps
        // H3_FRAME_ERROR for the one Length that IS invalid - above int.MaxValue, which no
        // ReadOnlySpan could ever carry.
        //
        // BEFORE s6.2.1's FIN RULE BELOW AND NOT AFTER, because a peer that flooded us and then
        // closed flooded first; both answers end the connection, and this one names the cause.
        if (state.Unparsed.Count > _spec.MaximumBufferedControlStreamBytes)
        {
            error = (ulong)TlsQuicHttp3ErrorCode.H3ExcessiveLoad;
            return false;
        }

        // s6.2.1: "If either control stream is closed at any point, this MUST be treated as a
        // connection error of type H3_CLOSED_CRITICAL_STREAM." Checked AFTER the frames, so a
        // control stream that delivered a legal SETTINGS and then closed still reports the
        // close rather than being rejected before its settings were read - the peer's settings
        // are worth keeping even when the connection is about to end.
        //
        // THE CONTROL-STREAM TEST IS UNREACHABLE-BY-CONSTRUCTION TODAY, and this comment says
        // so because an earlier version of it claimed the opposite and the sweep proved the
        // claim false: deleting the test changed no test's result. The invariant that makes it
        // redundant is thirty lines up - a stream with a known non-control type has Ignoring
        // set and returns before here, and a stream whose type has not arrived returns at the
        // TryTakeStreamType call - so StreamType is necessarily Control by this point.
        //
        // It is kept rather than deleted because the invariant lives at a distance and the
        // rule it enforces is narrow: s6.2.1's sentence is about the control stream, while
        // s6.2's general rule is that "A sender can close or reset a unidirectional stream
        // unless otherwise specified", so a QPACK or GREASE stream that ends is ordinary. If
        // the early return ever moves, this line is what stops a peer's ordinary GREASE-stream
        // close from becoming a connection error. Recorded as a surviving mutation, classified
        // unreachable-by-construction, with no test written for it.
        if (state.StreamType == (ulong)TlsQuicHttp3StreamType.Control && stream.FinalSizeKnown)
        {
            error = (ulong)TlsQuicHttp3ErrorCode.H3ClosedCriticalStream;
            return false;
        }

        return true;
    }

    // WHERE THE ENCODER STREAM'S CEILING COMES FROM, AND WHY IT IS NOT A CONSTANT. RFC 9204
    // s3.2.2 bounds a dynamic table entry by the capacity THIS endpoint advertised in
    // SETTINGS_QPACK_MAX_TABLE_CAPACITY - "It is an error if the encoder attempts to add an
    // entry that is larger than the dynamic table capacity" - so the longest s4.3.2 Insert With
    // Literal Name a conforming peer can usefully send is that capacity plus the entry's own
    // 32-byte allowance and two prefixed integers. The ceiling is therefore DERIVED from the
    // number we advertised rather than fixed: a caller who raises the capacity through
    // TlsQuicHttp3Spec.Settings raises what its peer may legally send in one instruction, and a
    // constant here would fire on the first legal one.
    //
    // THE FIRST VERSION OF THIS WAS 256 KiB TAKEN FROM A TEST FIXTURE'S 65536, which is the
    // placeholder-value defect this project's rules forbid twice over: it read one preset's
    // choice as the library's capability, and it did so through a file under tests/.
    //
    // s7.4's HEADROOM IS WHAT THE ADDITION IS FOR, AND THE TERM IT ACTUALLY BUYS IS THE
    // DEFERRAL WINDOW. "These limits SHOULD be large enough to process the largest individual
    // field the HTTP implementation can be configured to accept", and the largest field is the
    // capacity - but the capacity only pays for a RESIDUE, which is what this buffer holds
    // everywhere except one place. TryReadEncoderStream parses nothing at all while
    // LocalDecoderStream is null, so in that window residue equals arrival and arrival is a
    // multi-instruction backlog: a legal encoder inserting and evicting against a 64 KiB table
    // can send far more than 64 KiB of instructions. EncoderStreamCeilingHeadroomBytes is sized
    // for that backlog rather than for one instruction's prefixes, and its own remarks derive
    // the number. SATURATING rather than wrapping, because s7.2.4's Value is a varint
    // to 2^62-1 and an unchecked cast of a huge advertised capacity gives a negative ceiling
    // that every buffer breaches - the same trap the table's own construction avoids above.
    private static int DeriveEncoderStreamCeiling(ulong advertisedCapacity)
    {
        var ceiling = advertisedCapacity + TlsQuicHttp3Spec.EncoderStreamCeilingHeadroomBytes;
        return ceiling < int.MaxValue ? (int)ceiling : int.MaxValue;
    }

    // RFC 9204 s4.3's encoder instructions, and s2.2.2.3's feedback for them.
    //
    // PeerStreamState.Unparsed IS THE REASSEMBLY, and no second buffer is introduced.
    // TlsQuicQpackDynamicTable.TryReadEncoderInstructions reports how many octets it consumed
    // and leaves a partial instruction unconsumed - the same contract TlsQuicHttp3Frames.TryRead
    // answers Incomplete with, and TryParseControlFrames above treats it identically. Dropping
    // exactly `consumed` is what makes an instruction split at any byte boundary end in the
    // same table as one fed whole.
    //
    // s2.2.2.3 lets the decoder choose WHEN to acknowledge new entries and this one chooses
    // "after every read that consumed something", which is its "timeliest feedback" end. A zero
    // Increment is suppressed inside TlsQuicQpackDecoderStream, so a read that consumed only a
    // Set Dynamic Table Capacity - no insertion, no change to the Insert Count - sends nothing.
    private bool TryReadEncoderStream(PeerStreamState state, out ulong error)
    {
        error = (ulong)TlsQuicHttp3ErrorCode.None;

        // A capacity of zero means there is no table to drive. s6.2's "discard incoming data
        // without further processing" is still a legal answer for a stream we have nothing to
        // do with, and it is the answer this endpoint has already committed to by advertising
        // zero - so the bytes are dropped rather than parsed into nowhere.
        if (Table is null)
        {
            state.Unparsed.Clear();
            return true;
        }

        // NOT YET, RATHER THAN WITHOUT FEEDBACK. A peer may deliver its encoder stream before
        // OpenLocalStreams has run - nothing orders the two - and reading it here would leave
        // s2.2.2.3's Insert Count Increment with no stream to go out on, which is the one way
        // a peer could reach the InvalidOperationException the three s4.4 senders raise.
        //
        // THE BYTES ARE KEPT UNPARSED, NOT PARSED-AND-UNACKNOWLEDGED. Skipping the send would
        // advance the table while silently dropping the feedback s2.2.2.1 and s2.2.2.3 owe;
        // leaving them here defers BOTH, and the first pass after OpenLocalStreams reads the
        // whole backlog and sends one Increment for it. s2.2.2.3 makes that timing the
        // decoder's to choose: "the decoder chooses when to emit Insert Count Increment
        // instructions".
        if (LocalDecoderStream is null)
        {
            return true;
        }

        var span = CollectionsMarshal.AsSpan(state.Unparsed);
        if (!Table.TryReadEncoderInstructions(span, out var consumed, out var tableError))
        {
            // s2.2.3's second paragraph and s6: every fault the table can raise came off THIS
            // stream, so every one of them is QPACK_ENCODER_STREAM_ERROR - 0x0201, which is why
            // this method reports a ulong. TryGetHttp3ErrorCode owns the mapping.
            TlsQuicQpackDynamicTable.TryGetHttp3ErrorCode(tableError, out error);
            return false;
        }

        state.Unparsed.RemoveRange(0, consumed);

        // UNCONDITIONAL, AND A GUARD WAS DELETED HERE RATHER THAN DOCUMENTED. An earlier draft
        // wrapped this in `if (consumed > 0)`. The sweep found that mutation SURVIVED, and it
        // survived because the guard was redundant: a read that consumed nothing cannot have
        // moved the Insert Count, so the difference against s2.1.4's Known Received Count is
        // zero, and TlsQuicQpackDecoderStream.TryWriteInsertCountIncrement already suppresses a
        // zero Increment - s4.4.3 makes one a QPACK_DECODER_STREAM_ERROR at the peer's encoder.
        // A guard whose removal no test can see is a guard to delete, which is the same rule
        // TryProcessPeerStream's own "NO SECOND if (state.Ignoring)" note applies.
        SendInsertCountIncrement(Table.InsertCount);

        return true;
    }

    // Returns false either because the type is not fully here yet - error None, caller keeps
    // going - or because the type is one that ends the connection.
    private bool TryTakeStreamType(
        TlsQuicStream stream, PeerStreamState state, out TlsQuicHttp3ErrorCode error)
    {
        error = TlsQuicHttp3ErrorCode.None;

        var cursor = 0;
        var span = CollectionsMarshal.AsSpan(state.Unparsed);
        if (!QuicVariableLengthInteger.TryRead(span, ref cursor, out var streamType))
        {
            // s6.2: "A receiver MUST tolerate unidirectional streams being closed or reset
            // prior to the reception of the unidirectional stream header." Nothing is
            // concluded and nothing fails, whether or not the stream has ended - a FIN here
            // needs no special case, because a stream whose type never arrived is re-scanned
            // over the same short buffer and keeps concluding nothing.
            return false;
        }

        state.Unparsed.RemoveRange(0, cursor);

        if (streamType == (ulong)TlsQuicHttp3StreamType.Control)
        {
            // s6.2.1: "Only one control stream per peer is permitted; receipt of a second
            // stream claiming to be a control stream MUST be treated as a connection error of
            // type H3_STREAM_CREATION_ERROR."
            if (PeerControlStreamId is not null)
            {
                error = TlsQuicHttp3ErrorCode.H3StreamCreationError;
                return false;
            }
            PeerControlStreamId = stream.Id;
        }
        else if (streamType == (ulong)TlsQuicHttp3StreamType.QpackEncoder)
        {
            // C16 SPLIT THIS OUT OF THE BLANKET ARM BELOW. Ignoring is deliberately NOT set:
            // the peer's encoder instructions are the only thing that advances our dynamic
            // table, so this is the one non-control type whose bytes are kept. What happens to
            // them is TryReadEncoderStream's, including the case where we advertised a capacity
            // of zero and there is no table to drive - which discards them there rather than
            // here, so that the two reasons for discarding stay one line apart from each other
            // rather than merged into a flag that cannot tell them apart.
            //
            // NO "only one encoder stream per peer" CHECK. s6.2.1's uniqueness sentence is
            // about the CONTROL stream; RFC 9204 s4.2 says "Only one ... encoder stream ... can
            // be created" without naming an error code, and inventing one would close
            // connections on a rule the RFC declined to enforce. A second encoder stream simply
            // feeds the same table, which is what a duplicate would do anyway.
        }
        else
        {
            // EVERY OTHER TYPE, WITH NO BRANCH BETWEEN THEM. A push stream, the peer's QPACK
            // DECODER stream, an s6.2.3 reserved (GREASE) stream and a type from an extension
            // nobody here implements all end up here, and this task does exactly the same
            // thing with all four: takes s6.2's second answer, "discard incoming data without
            // further processing", which is also the answer that satisfies "The recipient MUST
            // NOT consider unknown stream types to be a connection error of any kind."
            //
            // THE PEER'S DECODER STREAM IS STILL DISCARDED AND THAT IS NOT AN OVERSIGHT. s4.4's
            // instructions acknowledge OUR encoder's dynamic table, and this client's encoder
            // is static-only - TlsQuicQpackEncoder never inserts - so a Section Acknowledgment
            // or an Insert Count Increment from the peer refers to state that does not exist.
            state.Ignoring = true;
            state.Unparsed.Clear();
        }

        state.StreamType = streamType;
        return true;
    }

    private bool TryParseControlFrames(PeerStreamState state, out TlsQuicHttp3ErrorCode error)
    {
        error = TlsQuicHttp3ErrorCode.None;

        while (true)
        {
            var offset = 0;
            var span = CollectionsMarshal.AsSpan(state.Unparsed);
            var status = TlsQuicHttp3Frames.TryRead(
                span, ref offset, out var frameType, out var payload, out error);
            if (status == TlsQuicHttp3FrameReadStatus.Incomplete)
            {
                error = TlsQuicHttp3ErrorCode.None;
                return true;
            }
            if (status == TlsQuicHttp3FrameReadStatus.Error)
            {
                return false;
            }

            if (!TryAcceptControlFrame(state, frameType, payload, out error))
            {
                return false;
            }

            state.Unparsed.RemoveRange(0, offset);
        }
    }

    private bool TryAcceptControlFrame(
        PeerStreamState state,
        ulong frameType,
        ReadOnlySpan<byte> payload,
        out TlsQuicHttp3ErrorCode error)
    {
        // s6.2.1: "Each side MUST initiate a single control stream at the beginning of the
        // connection and send its SETTINGS frame as the first frame on this stream. If the
        // first frame of the control stream is any other frame type, this MUST be treated as
        // a connection error of type H3_MISSING_SETTINGS."
        //
        // ANY OTHER TYPE, WITH NO EXEMPTION FOR RESERVED ONES. s7.2.8 lets a reserved frame be
        // sent "on any stream where frames are allowed to be sent" and s9 says ignore unknown
        // frames, so a reader could argue a GREASE frame ahead of SETTINGS should be skipped.
        // s6.2.1's sentence does not carve one out, and the two rules meet only here; this
        // takes s6.2.1 literally because it is the more specific of the two and because the
        // alternative lets a peer push SETTINGS arbitrarily far back behind padding.
        if (!state.FirstFrameSeen)
        {
            state.FirstFrameSeen = true;
            if (frameType != (ulong)TlsQuicHttp3FrameType.Settings)
            {
                error = TlsQuicHttp3ErrorCode.H3MissingSettings;
                return false;
            }

            if (!TlsQuicHttp3Settings.TryDecodePayload(payload, out var settings, out error))
            {
                return false;
            }

            PeerSettings = settings;
            PeerSettingsReceived = true;
            return true;
        }

        switch (frameType)
        {
            // s7.2.4: "If an endpoint receives a second SETTINGS frame on the control stream,
            // the endpoint MUST respond with a connection error of type H3_FRAME_UNEXPECTED."
            case (ulong)TlsQuicHttp3FrameType.Settings:

            // s7 Table 1's "Control Stream: No" rows. s7.2.1 and s7.2.2 each state it as a
            // MUST in their own words; PUSH_PROMISE is Table 1's row alone.
            case (ulong)TlsQuicHttp3FrameType.Data:
            case (ulong)TlsQuicHttp3FrameType.Headers:
            case (ulong)TlsQuicHttp3FrameType.PushPromise:
                error = TlsQuicHttp3ErrorCode.H3FrameUnexpected;
                return false;

            // s7.2.6's frame, whose identifier C11 both checks and keeps.
            case (ulong)TlsQuicHttp3FrameType.Goaway:
                return TryAcceptGoaway(payload, out error);

            // s7.2.3's CANCEL_PUSH, whose payload s7.2.3 defines as exactly one varint.
            // Nothing here acts on the value - server push is refused by never sending
            // MAX_PUSH_ID - but the payload is still parsed, because s7.1's "A frame payload
            // that contains additional bytes after the identified fields ... MUST be treated as
            // a connection error of type H3_FRAME_ERROR" is a check on receipt, not on use.
            case (ulong)TlsQuicHttp3FrameType.CancelPush:
                return TlsQuicHttp3Frames.TryReadSingleVarintPayload(payload, out _, out error);

            // s7.2.7: "A server MUST NOT send a MAX_PUSH_ID frame.  A client MUST treat the
            // receipt of a MAX_PUSH_ID frame as a connection error of type
            // H3_FRAME_UNEXPECTED."
            //
            // THE SHARED PAYLOAD SHAPE IS WHY THIS WAS WRONG ONCE. CANCEL_PUSH and MAX_PUSH_ID
            // are both "the control stream, one varint", so they were merged into a single arm
            // and MAX_PUSH_ID inherited CANCEL_PUSH's rule. Their rules are OPPOSITE: one is
            // legal on this stream, the other is never legal from a server at all. Do not merge
            // them again, however identical the payloads look.
            //
            // s7.2.7's OTHER two MUSTs - the wrong-stream rule and the non-increasing-value
            // rule - are unreachable behind this one. A frame a client must reject outright
            // cannot also be rejected for arriving in the wrong place or carrying the wrong
            // number. TlsQuicHttp3Request rejects it on request streams for its own reason.
            case (ulong)TlsQuicHttp3FrameType.MaxPushId:
                error = TlsQuicHttp3ErrorCode.H3FrameUnexpected;
                return false;

            // An unknown frame type, reserved or not, is ignored. Its payload was already
            // skipped by TlsQuicHttp3Frames.TryRead honouring the Length.
            //
            // RFC 9114 s9 IS UNCAPTURED IN THIS REPO. s7.2.8's captured text names it - the
            // reserved types exist "to exercise the requirement that unknown types be ignored
            // (Section 9)" - so the requirement's existence is checkable here and its exact
            // wording is not. Reported as an uncaptured dependency rather than extracted,
            // since another agent may own the capture directory.
            default:
                error = TlsQuicHttp3ErrorCode.None;
                return true;
        }
    }

    // ============================================================================
    // THE MUTATION LEDGER - TASK C11 (this file: s7.2.6's GOAWAY only)
    // ============================================================================
    //
    //   ROWS BELOW                    9  = C11-37 to C11-45 with no gaps
    //   KILLED WHEN FIRST RUN         9  = 9 rows, less 0 [WAS-SURVIVOR] and 0 [SURVIVED]
    //   SURVIVING STILL               0
    //
    //   The other 36 rows are in TlsQuicHttp3Connection.cs's C11 ledger, C11-1 to C11-36.
    //   36 + 9 = 45 rows for the task. C4's own survivors are recorded inline above, not here;
    //   this block covers only what C11 added to this file.
    //
    //   C11-37. s7.2.6's initiator half dropped, so a SERVER-initiated bidirectional id is
    //        accepted. Killed by 1, .AGoawayNamingAStreamThatIsNotClientBidirectionalIsIdError.
    //   C11-38. s7.2.6's direction half dropped, so a client UNIDIRECTIONAL id is accepted.
    //        Killed by 1, the same test. C11-37 and C11-38 are separate rows because the check is
    //        TWO bits and a test that exercised one of them would pass against the other's
    //        mutant; the Theory carries all three of s2.1's other rows for that reason.
    //   C11-39. s7.2.6's stream-id-type MUST removed entirely. Killed by 3, the Theory's three
    //        rows. Written as a condition no varint can satisfy rather than `if (false)`, which
    //        is CS0162 and would have been a build error rather than a verdict.
    //   C11-40. s5.2's "MUST NOT be greater" becomes "MUST be less", so a REPEATED identifier is
    //        wrongly refused. Killed by 1,
    //        .ASecondGoawayNoGreaterThanTheFirstIsAcceptedAndReplacesIt - the row where both
    //        identifiers are 4, which exists to pin the comparison at equality.
    //   C11-41. s5.2's narrowing rule inverted. Killed by 2.
    //   C11-42. s5.2's monotonic rule removed. Killed by 1,
    //        .ASecondGoawayWithALargerIdentifierIsIdError.
    //   C11-43. The identifier parsed and discarded, as C4 left it. Killed by 5.
    //   C11-44. Only the FIRST GOAWAY stands, so s5.2's narrowing sequence never narrows. Killed
    //        by 1, .ASecondGoawayNoGreaterThanTheFirstIsAcceptedAndReplacesIt.
    //   C11-45. GOAWAY falls back to the generic single-varint case - no checks, no record.
    //        Killed by 8.

    // ============================================================================
    // THE MUTATION LEDGER - TASK C15 (this file: RFC 9204 s4.2's decoder stream only)
    // ============================================================================
    //
    //   ROWS BELOW                    5  = C15-46 to C15-50 with no gaps
    //   KILLED WHEN FIRST RUN         5  = 5 rows, less 0 [WAS-SURVIVOR] and 0 [SURVIVED]
    //   SURVIVING STILL               0
    //
    //   The other 45 rows are in TlsQuicQpackDecoder.cs's C15 ledger, C15-1 to C15-45.
    //   45 + 5 = 50 rows for the task. C4's and C11's rows are counted in their own blocks;
    //   this one covers only what C15 added to this file.
    //
    //   Same harness, same gate, same 2032-case baseline and 95% floor as the decoder's block,
    //   which records the two-directional calibration.
    //
    //   C15-46. The local decoder stream taken from QpackEncoder's type rather than
    //        QpackDecoder's, so every instruction goes out on the wrong stream. Killed by 3,
    //        including .AReorderedSpecStillFindsTheDecoderStreamByItsType - the row that exists
    //        because at the default open order the two streams are adjacent and a test that
    //        only counted frames would not care which one they landed on.
    //   C15-47. A suppressed instruction sent as an EMPTY STREAM frame rather than not sent.
    //        Killed by exactly one case, .ASuppressedInstructionPutsNoFrameOnTheDecoderStream -
    //        and the reason that test asserts on the frame COUNT rather than on the writer's
    //        `written` is this mutant, which satisfies `written == 0` and still puts a frame on
    //        the connection.
    //   C15-48. The whole 11-byte scratch buffer sent rather than the instruction's octets, so
    //        every instruction is followed by ten zero bytes - which a peer reads as ten more
    //        Insert Count Increments of zero, each its own QPACK_DECODER_STREAM_ERROR.
    //        Killed by 1.
    //   C15-49. [RE-LISTED as a different edit of the same line as C15-48] the send given
    //        `fin: true`, breaking s4.2's "The sender MUST NOT close either of these streams".
    //        Killed by 2.
    //   C15-50. The missing-decoder-stream check removed, so a spec that took s4.2's MAY and
    //        omitted the stream faults on a null reference instead of saying what is wrong.
    //        Killed by 1.
    // s7.2.6's GOAWAY, received by a client on the peer's control stream.
    //
    // TWO CHECKS AND NOT ONE, because s7.2.6 and s5.2 each attach H3_ID_ERROR to a DIFFERENT
    // fault and a single check would pin whichever fired first:
    //
    //   * s7.2.6: "In the server-to-client direction, it carries a QUIC stream ID for a
    //     client-initiated bidirectional stream encoded as a variable-length integer. A client
    //     MUST treat receipt of a GOAWAY frame containing a stream ID of any other type as a
    //     connection error of type H3_ID_ERROR." Both bits of RFC 9000 s2.1's low two must be
    //     clear, so THREE of the four stream types are refused and testing only one of them
    //     would leave the other two open.
    //
    //   * s5.2: "the identifier in each frame MUST NOT be greater than the identifier in any
    //     previous frame, since clients might already have retried unprocessed requests on
    //     another HTTP connection. Receiving a GOAWAY containing a larger identifier than
    //     previously received MUST be treated as a connection error of type H3_ID_ERROR."
    //     STRICTLY GREATER - an identifier REPEATED is legal, which is what "MUST NOT be
    //     greater than" says and what a `>=` here would wrongly refuse.
    //
    // s7.2.6's third MUST - "A client MUST treat a GOAWAY frame on a stream other than the
    // control stream as a connection error of type H3_FRAME_UNEXPECTED" - is NOT here and needs
    // no line: this method is reachable only from the control stream's frame loop, and a GOAWAY
    // on a request stream meets TlsQuicHttp3Response's own s7 Table 1 rejection instead.
    private bool TryAcceptGoaway(ReadOnlySpan<byte> payload, out TlsQuicHttp3ErrorCode error)
    {
        if (!TlsQuicHttp3Frames.TryReadSingleVarintPayload(payload, out var identifier, out error))
        {
            return false;
        }

        if (TlsQuicStreamId.InitiatorOf(identifier) != TlsQuicStreamInitiator.Client
            || TlsQuicStreamId.DirectionOf(identifier) != TlsQuicStreamDirection.Bidirectional)
        {
            error = TlsQuicHttp3ErrorCode.H3IdError;
            return false;
        }

        if (PeerGoawayStreamId is { } previous && identifier > previous)
        {
            error = TlsQuicHttp3ErrorCode.H3IdError;
            return false;
        }

        PeerGoawayStreamId = identifier;
        return true;
    }
}


// ============================================================================
// THE MUTATION LEDGER - TASK C16 (this file: RFC 9204 s4.3's encoder stream,
// s2.2.2.3's feedback, and where the table and the bound come from)
// ============================================================================
//
//   ROWS BELOW                    7  = C16-21 to C16-27 with no gaps
//   KILLED WHEN FIRST RUN         5  = 7 rows, less 1 [WAS-SURVIVOR] and 1 [TARGET DELETED]
//   SURVIVED, THEN WITNESSED      1  = row C16-27
//   SURVIVED, CODE DELETED        1  = row C16-23
//   SURVIVING STILL               0
//
//   5 + 1 + 1 = 7. The task's other 28 rows are in TlsQuicQpackDecoder.cs (11),
//   TlsQuicQpackPrimitives.cs (2), TlsQuicHttp3Request.cs (7), TlsQuicHttp3Connection.cs (6)
//   and TlsQuicHttp3Frames.cs (2). 7 + 28 = 35 rows for the task.
//
// A UNIQUE ROW PREFIX, because this file's C11 block counts `C11-` and its C15 block counts
// `C15-`. Its own three:
//   `grep -cE '^// +C16-[0-9]+\. ' TlsQuicHttp3Streams.cs`                  must return 7
//   `grep -cE '^// +C16-[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicHttp3Streams.cs` must return 1
//   `grep -cE '^// +C16-[0-9]+\..*\[SURVIVED\]' TlsQuicHttp3Streams.cs`     must return 0
//
// Same harness, same gate and the same three harness defects as TlsQuicQpackDecoder.cs's C16
// block, which records them in full.
//
//  C16-21. The encoder-stream arm restored to Ignoring, so the peer's s4.3 instructions are
//        discarded and the table never advances. Killed by 8. [RESTATED] for the
//        literal-`false` reason the decoder's block records.
//  C16-22. `consumed` ignored - the whole buffer dropped after a read - so an instruction split
//        across two STREAM frames loses its first half. Killed by 2, and the witness splits one
//        Insert With Literal Name at EVERY byte boundary rather than at one chosen offset,
//        because a single chosen split survives most such mutants.
//  C16-23. [TARGET DELETED] The `if (consumed > 0)` around SendInsertCountIncrement removed, so
//        s2.2.2.3's feedback goes out on every read. IT SURVIVED, AND THE SURVIVAL WAS THE
//        ANSWER: the guard was redundant. A read that consumed nothing cannot have moved the
//        Insert Count, so the difference against s2.1.4's Known Received Count is zero, and
//        TlsQuicQpackDecoderStream.TryWriteInsertCountIncrement already suppresses a zero
//        Increment. The guard was DELETED rather than given a test - a guard whose removal no
//        test can see is a guard to delete, which is the rule TryProcessPeerStream's own "NO
//        SECOND if (state.Ignoring)" note applies to itself - so this row has no target any
//        more. .APartialInstructionSendsNoInsertCountIncrement still holds the property, now
//        against the suppression that actually enforces it.
//  C16-24. The table built even at a zero advertised capacity, so every narrowed-settings
//        caller leaves C8's static-only arm. Killed by 1.
//  C16-25. s2.1.2's bound taken from the constant 100 instead of our own SETTINGS - the
//        placeholder-value defect this project's rules forbid, and the one that would make a
//        narrowed test silently exercise the shipped number. Killed by 3.
//  C16-26. An encoder-stream fault swallowed: the s6 code is never fetched, so
//        QPACK_ENCODER_STREAM_ERROR is reported as success. Killed by 1.
//  C16-27. [WAS-SURVIVOR] The pre-OpenLocalStreams guard removed, so a peer that opens its
//        encoder stream before we open ours drives us into the s4.4 senders'
//        InvalidOperationException - A THROW REACHABLE FROM WIRE INPUT, which this file's
//        header forbids outright. IT SURVIVED because no test delivered an encoder stream
//        before OpenLocalStreams: nothing orders the two, and every existing test happened to
//        open first. .AnEncoderStreamThatArrivesBeforeOurOwnStreamsAreOpenIsDeferredRatherThan
//        Dropped is that ordering, and it also pins the half that makes deferring correct
//        rather than merely safe - the backlog is read on the first pass after OpenLocalStreams
//        and ONE Increment covers all of it. Killed by 2.
//
// ============================================================================
