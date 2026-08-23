using System.Collections.Immutable;

namespace SharpTls.Quic;

/// <summary>One packet to place inside a datagram: everything
/// <see cref="TlsQuicPacketBuilder.Build"/> needs except the destination span and the
/// send time, which belong to the datagram rather than to the packet.</summary>
/// <remarks>
/// <para>THE KEYS TRAVEL WITH THE PACKET, NOT WITH THE DATAGRAM, and that is the whole
/// reason coalescing exists. RFC 9000 s12.2: "A sender can coalesce multiple QUIC packets
/// (typically a Handshake packet and a 1-RTT packet) into one UDP datagram." Those two are
/// at different encryption levels and therefore under different keys, so a datagram-wide
/// key would make the common case unexpressible.</para>
/// <para>LIFETIME: every <c>ReadOnlyMemory&lt;byte&gt;</c> here is borrowed for the
/// duration of the call, matching <see cref="TlsQuicPacketPlan"/> and
/// <see cref="TlsQuicFrame"/>. They are <c>ReadOnlyMemory</c> rather than
/// <c>ReadOnlySpan</c> only because a struct cannot hold a span; the builder passes them
/// straight through as spans.</para>
/// </remarks>
internal readonly struct TlsQuicPacketToSend
{
    /// <summary>The header fields; see <see cref="TlsQuicPacketPlan"/>.</summary>
    internal TlsQuicPacketPlan Plan { get; init; }

    /// <summary>The frames, in exactly the order they are written. The datagram builder
    /// adds PADDING to the last packet of an Initial-carrying datagram and changes nothing
    /// else - no merging, no reordering.</summary>
    internal IReadOnlyList<TlsQuicFrame> Frames { get; init; }

    /// <summary>RFC 9001 s5.3's AEAD.</summary>
    internal TlsQuicPacketProtectionCipher PacketProtectionCipher { get; init; }

    /// <summary>RFC 9001 s5.1's packet protection key.</summary>
    internal ReadOnlyMemory<byte> Key { get; init; }

    /// <summary>RFC 9001 s5.3's IV.</summary>
    internal ReadOnlyMemory<byte> Iv { get; init; }

    /// <summary>RFC 9001 s5.4's header protection cipher.</summary>
    internal TlsQuicHeaderProtectionCipher HeaderProtectionCipher { get; init; }

    /// <summary>RFC 9001 s5.4's header protection key.</summary>
    internal ReadOnlyMemory<byte> HeaderProtectionKey { get; init; }
}

/// <summary>RFC 9000 s12.2 and s14.1: places built packets into UDP datagrams, expands
/// Initial-carrying datagrams to the spec's padding target, and carves the Initial CRYPTO
/// stream into the frames and datagrams the spec's flight plan declares.</summary>
/// <remarks>
/// <para>WHY THE MULTI-DATAGRAM INITIAL IS THE NORMAL CASE AND NOT A CORNER. The Brave 151
/// capture's X25519MLKEM768 key share is 1216 bytes on its own, so a Chromium-shaped
/// ClientHello cannot fit the 1200-byte datagram s14.1 pins the floor at. A design in which
/// one Initial is one datagram cannot express the target at all, which is why
/// <see cref="TlsQuicConnectionSpec.InitialCryptoFramesPerDatagram"/> exists.</para>
/// <para>WHAT THIS FILE DOES NOT DO: no connection state, no receive path, no ACK
/// generation, no retransmission. It turns an ordered list of packets into bytes and
/// nothing else. A4 tasks 6, 8 and 9a-ii own the rest.</para>
/// </remarks>
internal static class TlsQuicDatagramBuilder
{
    // RFC 9000 s16 Table 4's four encoded lengths, narrowest first. Named rather than
    // written inline so the step function the padding solver walks is the RFC's list and
    // not four numbers a reader has to recognise.
    private static ReadOnlySpan<int> Table4Widths => [1, 2, 4, 8];

    // RFC 9000 s18.2, verbatim from rfc9000-section18-transport-parameters.txt line 93: "The
    // default for this parameter is the maximum permitted UDP payload of 65527." That is the
    // largest payload a UDP datagram can carry at all, so it is the size of the buffer
    // BuildInitialFlight writes each datagram into.
    //
    // DECLARED LOCALLY, for the reason TlsQuicConnectionSpec's own copy gives: the number
    // that bounds a padding target, the number a transport reports as its ceiling, and this
    // one are three different quantities that happen to coincide today, and aliasing them
    // would propagate the day one moves. Written from the source quoted above.
    private const int MaximumUdpPayload = 65527;

    /// <summary>Writes one datagram: every packet in order, with the last one expanded to
    /// <see cref="TlsQuicConnectionSpec.PaddingTarget"/> when the datagram carries an
    /// Initial packet.</summary>
    /// <remarks>
    /// <para>RFC 9000 s14.1, verbatim from
    /// <c>rfc9000-section14-datagram-size-and-pmtu.txt</c> lines 65-68:</para>
    /// <para><i>"A client MUST expand the payload of all UDP datagrams carrying Initial
    /// packets to at least the smallest allowed maximum datagram size of 1200 bytes by
    /// adding PADDING frames to the Initial packet or by coalescing the Initial packet; see
    /// Section 12.2."</i></para>
    /// <para>ALL UDP DATAGRAMS - so the test is per datagram and not per flight, and a
    /// two-datagram Initial pads both. That is the entire basis for the rule; the
    /// amplification limit of s8.1 is secondary colour and is deliberately not restated
    /// here as an argument, because an earlier draft of this plan argued it from arithmetic
    /// that did not hold. "Chromium does it too" is a behavioural observation and not a
    /// justification either. The MUST is the reason.</para>
    /// <para>WHICH OF s14.1's TWO ROUTES IS TAKEN. The sentence names both - PADDING frames
    /// or coalescing, and it adds that "Initial packets can even be coalesced with invalid
    /// packets, which a receiver will discard." This builder implements the PADDING route,
    /// which is Chromium's; see the remark on
    /// <see cref="TlsQuicConnectionSpec.PaddingTarget"/> for why that choice is a candidate
    /// fingerprint field rather than an implementation detail, and why no knob selects
    /// between the two while only one is built. The coalescing route arrives for free in
    /// one direction already: a datagram of Initial-then-Handshake pads inside the
    /// Handshake packet, because that is the last one.</para>
    /// <para>WHERE THE PADDING GOES: inside the last packet's payload, as PADDING frames,
    /// never as trailing bytes after the last packet. Trailing zeroes outside a packet are
    /// not covered by any packet's Length field and a receiver would try to parse them as
    /// another packet's first byte.</para>
    /// <para>s12.2 requires every packet but the last to carry a Length field so the
    /// receiver can find the next one. Nothing needs guarding here for that: every long
    /// header <see cref="TlsQuicPacketBuilder.Build"/> can produce has one, and Retry -
    /// the packet type s12.2 singles out as unfollowable, because s17.2.5 gives it no
    /// Length - is rejected by Build before it could reach a datagram. Witnessed by
    /// TlsQuicDatagramBuilderTests.ARetryPacketCannotBeCoalescedIntoADatagram.</para>
    /// <para>s12.2's OTHER sender rule, which this method does enforce itself, is quoted at
    /// the guard below.</para>
    /// </remarks>
    /// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
    internal static int BuildDatagram(
        TlsQuicConnectionSpec spec,
        IReadOnlyList<TlsQuicPacketToSend> packets,
        DateTimeOffset sentAt,
        Span<byte> destination,
        ICollection<TlsQuicSentPacket>? sentPackets = null)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(packets);

        // A datagram carrying no packet is not a datagram. The same case
        // TlsQuicPacketBuilder.Build rejects one level down for frames, and reachable the
        // same way - a flight plan that produced no packets for a datagram.
        // Witnessed by TlsQuicDatagramBuilderTests.ADatagramWithNoPacketsIsRejected.
        if (packets.Count == 0)
        {
            throw new ArgumentException("A datagram must carry at least one packet.", nameof(packets));
        }

        // RFC 9000 s12.2, verbatim from rfc9000-section12-packets-and-frames.txt lines 85-89:
        //
        //   "Receivers MAY route based on the information in the first packet contained in a
        //    UDP datagram.  Senders MUST NOT coalesce QUIC packets with different connection
        //    IDs into a single UDP datagram.  Receivers SHOULD ignore any subsequent packets
        //    with a different Destination Connection ID than the first packet in the
        //    datagram."
        //
        // BOTH IDs, NOT ONLY THE DESTINATION, and the two sentences are why. The MUST NOT is
        // addressed to senders and says "connection IDs" with no qualifier; it is the
        // RECEIVER's SHOULD in the next sentence that narrows to the Destination Connection
        // ID. A sender that matched only the receiver's leniency would still be breaking the
        // sentence written for it, and s17.2 gives a long header both IDs, so both are
        // compared against the first packet's - the one s12.2 says a receiver may route on.
        // Witnessed on both fields, one row each, by
        // TlsQuicDatagramBuilderTests.CoalescingPacketsWithDifferentConnectionIdsIsRejected.
        //
        // Comparing every packet against packets[0] rather than against its predecessor is
        // the same relation - equality is transitive - and it is the one s12.2 states.
        // RFC 9000 s12.2, verbatim from rfc9000-section12-packets-and-frames.txt lines
        // 100-105:
        //
        //   "Retry packets (Section 17.2.5), Version Negotiation packets
        //    (Section 17.2.1), and packets with a short header (Section 17.3) do
        //    not contain a Length field and so cannot be followed by other packets
        //    in the same UDP datagram.  Note also that there is no situation where
        //    a Retry or Version Negotiation packet is coalesced with another
        //    packet."
        //
        // THE THIRD MEMBER OF THAT LIST IS THE ONE THIS GUARD IS FOR. The other two are
        // already unreachable here and the comment on this method's remarks says how:
        // Build rejects Retry outright, and no Version Negotiation packet is buildable at
        // all. A short-header packet is the only one of the three this builder can place.
        //
        // The same section says it a second time and in different words, at lines 79-80,
        // which is an independent statement of the same rule rather than this file's
        // reading of one sentence: "A packet with a short header does not include a
        // length, so it can only be the last packet included in a UDP datagram."
        //
        // CANNOT, not SHOULD NOT: without a Length field nothing says where the
        // short-header packet's payload stops. TlsQuicPacketHeader.cs:418-421 already
        // states the read side - TryReadShortHeader sets `consumed` to the whole remaining
        // datagram - so a sender that emitted a follower would be producing bytes its own
        // parser reads as part of the payload above them.
        //
        // The test is on the PREDECESSOR, not on the packet itself: a short header is
        // legal as the only packet of a datagram and as the last of a coalesced one, which
        // is s12.2's own "typically a Handshake packet and a 1-RTT packet" example. Only
        // "followed by" is forbidden.
        // Witnessed by
        // TlsQuicDatagramBuilderTests.NothingMayBeCoalescedAfterAShortHeaderPacket.
        for (var index = 1; index < packets.Count; index++)
        {
            if (packets[index - 1].Plan.Type is null)
            {
                throw new ArgumentException(
                    "RFC 9000 s12.2: \"Packets with a short header (Section 17.3) do not contain a "
                    + "Length field and so cannot be followed by other packets in the same UDP "
                    + $"datagram.\" Packet {index - 1} of this datagram has a short header and "
                    + $"packet {index} follows it.",
                    nameof(packets));
            }
        }

        for (var index = 1; index < packets.Count; index++)
        {
            // THE SOURCE HALF IS SKIPPED FOR A SHORT HEADER, and the sentence quoted above
            // is why rather than convenience: it says "QUIC packets with different
            // connection IDs", and RFC 9000 s17.3.1's field list gives the short header a
            // Destination Connection ID and NO Source Connection ID at all. There is no
            // second ID on that packet to be different from anything - comparing the plan's
            // empty one against a long header's non-empty one would reject the arrangement
            // s12.2 itself names as typical, "a Handshake packet and a 1-RTT packet",
            // whenever the endpoint uses a non-empty source connection ID. The DESTINATION
            // half still applies to both forms, because both carry that field, and it is
            // the one the next sentence makes a receiver route on.
            // Witnessed by
            // TlsQuicDatagramBuilderTests.AShortHeaderHasNoSourceConnectionIdToCompare.
            var comparesSource = packets[index].Plan.Type is not null;
            if (!packets[index].Plan.DestinationConnectionId.Span.SequenceEqual(
                    packets[0].Plan.DestinationConnectionId.Span)
                || (comparesSource
                    && !packets[index].Plan.SourceConnectionId.Span.SequenceEqual(
                        packets[0].Plan.SourceConnectionId.Span)))
            {
                throw new ArgumentException(
                    "RFC 9000 s12.2: \"Senders MUST NOT coalesce QUIC packets with different "
                    + $"connection IDs into a single UDP datagram.\" Packet {index} carries a "
                    + "connection ID the first packet of this datagram does not.",
                    nameof(packets));
            }
        }

        // A destination too small for the expanded datagram is NOT checked here.
        // TlsQuicPacketBuilder.Build already bounds every packet against the span it is
        // handed and throws ArgumentException naming `destination`, so a check here would be
        // a second check on the same input where `ParamName` is the only thing telling the
        // two apart - which A2's rules call invisible rather than merely unpinned. The bound
        // that matters is kept where the bytes are actually written.
        // Witnessed by TlsQuicDatagramBuilderTests.ADestinationTooSmallForTheExpandedDatagramIsRejected.
        //
        // CORRECTION TO THE REASONING COMMIT d174193 RECORDED FOR DELETING THAT BOUND. It
        // said the deleted check "would throw the same exception type on the same ParamName
        // for the same input". The deletion is safe - every input that reached it still
        // throws - but the ParamName half was overstated: at a target the padding solver
        // cannot hit, SolvePaddingFrameCount rejects FIRST, naming `spec` rather than
        // `destination`, because the target is unreachable before the buffer is even
        // consulted. Same type, different ParamName, and it is the type the tests assert on.
        var expand = CarriesInitial(packets);
        var written = 0;
        for (var index = 0; index < packets.Count; index++)
        {
            var packet = packets[index];
            var frames = packet.Frames;
            ArgumentNullException.ThrowIfNull(frames, nameof(packets));

            if (expand && index == packets.Count - 1)
            {
                frames = Expand(spec, packet, spec.PaddingTarget - written);
            }

            var sent = TlsQuicPacketBuilder.Build(
                packet.Plan,
                frames,
                packet.PacketProtectionCipher,
                packet.Key.Span,
                packet.Iv.Span,
                packet.HeaderProtectionCipher,
                packet.HeaderProtectionKey.Span,
                sentAt,
                destination[written..]);

            sentPackets?.Add(sent);
            written += sent.Size;
        }

        return written;
    }

    /// <summary>Builds the whole client Initial flight: the CRYPTO stream split into the
    /// frames and datagrams <paramref name="spec"/> declares, one buffer per
    /// datagram.</summary>
    /// <remarks>
    /// <para>The packet number advances by one per datagram from
    /// <c>template.Plan.PacketNumber</c>. RFC 9000 s12.3: "A QUIC endpoint MUST NOT reuse a
    /// packet number within a packet number space in the same connection", and every
    /// datagram of this flight is one Initial packet in the Initial space. The step is 1
    /// rather than a knob because subsystem B's field list does not contain one - the
    /// starting value is <see cref="TlsQuicConnectionSpec.InitialPacketNumber"/> and the
    /// encoded width is <see cref="TlsQuicConnectionSpec.PacketNumberEncodedLength"/>, and
    /// neither the capture nor RFC 9000 offers ground truth for a gapped sequence.</para>
    /// <para><c>template.Frames</c> must be empty: this method produces the frame list from
    /// the CRYPTO split, and a non-empty one would be silently discarded. Rejected rather
    /// than ignored.</para>
    /// <para>A DATAGRAM OF THIS FLIGHT MAY LEGALLY EXCEED
    /// <see cref="TlsQuicConnectionSpec.PaddingTarget"/>, because s14.1 makes that target a
    /// floor and not a ceiling: "Datagrams containing Initial packets MAY exceed 1200 bytes
    /// if the sender believes that the network path and peer both support the size that it
    /// chooses." The size a flight actually reaches is therefore bounded by s18.2's UDP
    /// payload, not by the target; see the buffer below.</para>
    /// </remarks>
    internal static List<byte[]> BuildInitialFlight(
        TlsQuicConnectionSpec spec,
        in TlsQuicPacketToSend template,
        ReadOnlyMemory<byte> cryptoStream,
        DateTimeOffset sentAt,
        ICollection<TlsQuicSentPacket>? sentPackets = null)
    {
        ArgumentNullException.ThrowIfNull(spec);

        // Witnessed by TlsQuicDatagramBuilderTests.AFlightTemplateCarryingItsOwnFramesIsRejected.
        if (template.Frames is { Count: > 0 })
        {
            throw new ArgumentException(
                "The flight template's frames come from the CRYPTO split; leave them empty.",
                nameof(template));
        }

        var plan = PlanInitialCryptoFrames(spec, cryptoStream);

        // A datagram whose CRYPTO stream alone outruns s18.2's UDP payload is not a datagram
        // at any padding target, and the two knobs that decide how much stream lands in one
        // are the caller's. Rejected here, naming them, rather than surfacing two layers down
        // as a bound on a `destination` this method does not have.
        //
        // A NECESSARY CONDITION ON THE DATA ALONE, deliberately: the frame and header bytes
        // that travel with it are bounded where they are written, by
        // TlsQuicPacketBuilder.Build against the span it is handed, which is the same
        // delegation BuildDatagram documents. Re-deriving them here would be the second
        // encoder this phase bans.
        // Witnessed by TlsQuicDatagramBuilderTests.AFlightDatagramLargerThanAUdpPayloadIsRejected.
        for (var index = 0; index < plan.Count; index++)
        {
            var streamBytes = 0;
            for (var frame = 0; frame < plan[index].Count; frame++)
            {
                streamBytes += plan[index][frame].Data.Length;
            }

            if (streamBytes >= MaximumUdpPayload)
            {
                throw new ArgumentException(
                    $"Datagram {index} of the flight would carry {streamBytes} bytes of CRYPTO "
                    + $"stream, which RFC 9000 s18.2's {MaximumUdpPayload}-byte UDP payload "
                    + "cannot hold; InitialCryptoFrameByteCounts and "
                    + "InitialCryptoFramesPerDatagram put too much into one datagram.",
                    nameof(spec));
            }
        }

        var datagrams = new List<byte[]>(plan.Count);

        // THE BUFFER IS THE PHYSICAL CEILING, NOT THE TARGET. Sizing it from
        // spec.PaddingTarget made every legal overshoot throw - and throw from
        // TlsQuicPacketBuilder.Build, naming a `destination` no caller of this method can
        // pass, which is a diagnostic pointing at a knob that does not exist. The Brave 151
        // capture's 1216-byte X25519MLKEM768 key share in one CRYPTO frame against the
        // 1200-byte default target is exactly that input, and it is the case this file's
        // header comment says the method exists for.
        //
        // The contract is therefore: OVERSHOOT IS ALLOWED, because s14.1 permits it in the
        // sentence quoted on the summary above, and because BuildDatagram already allows it
        // for a caller that supplies its own span - a flight that rejected what a single
        // datagram accepts would be two contracts for one builder. One buffer of this size
        // per flight, reused across its datagrams, and each datagram is copied out at its
        // own length.
        // Witnessed by TlsQuicDatagramBuilderTests.AFlightDatagramMayExceedThePaddingTarget.
        var buffer = new byte[MaximumUdpPayload];

        for (var index = 0; index < plan.Count; index++)
        {
            var packet = template with
            {
                Plan = template.Plan with { PacketNumber = template.Plan.PacketNumber + (ulong)index },
                Frames = plan[index],
            };

            var written = BuildDatagram(spec, [packet], sentAt, buffer, sentPackets);
            datagrams.Add(buffer[..written]);
        }

        return datagrams;
    }

    /// <summary>Carves <paramref name="cryptoStream"/> into CRYPTO frames at the offsets
    /// <see cref="TlsQuicConnectionSpec.InitialCryptoFrameByteCounts"/> declares, then
    /// groups them into datagrams by
    /// <see cref="TlsQuicConnectionSpec.InitialCryptoFramesPerDatagram"/>.</summary>
    /// <remarks>
    /// <para>THE TWO ARRAYS ARE READ SEPARATELY AND ON PURPOSE. Bytes-per-frame and
    /// frames-per-datagram are independent degrees of freedom - two frames may share one
    /// datagram or take one each, and the two produce different wire images. The spec's own
    /// cross-check already guarantees the second accounts for exactly the frames the first
    /// produces, so this method never re-derives one from the other.</para>
    /// <para>Offsets are RFC 9000 s19.6's stream offsets and run consecutively from 0: the
    /// split says where the boundaries fall, not where the stream starts.</para>
    /// <para>LIFETIME - AND IT IS THE OPPOSITE OF <see cref="TlsQuicPacketToSend"/>'s, which
    /// is why it is stated here rather than left to the namespace's habit. Every returned
    /// frame's <c>Data</c> is a SLICE of <paramref name="cryptoStream"/>, not a copy, and the
    /// returned lists OUTLIVE this call: nothing is written to a wire here, so the caller
    /// must keep <paramref name="cryptoStream"/> alive and unmutated until the last of those
    /// frames has been built into a packet. Mutating it in between changes bytes that have
    /// already been planned but not yet sealed. <see cref="TlsQuicPacketToSend"/>'s memories
    /// are borrowed for the duration of one call; these are not.</para>
    /// </remarks>
    /// <returns>One list per datagram, each holding that datagram's CRYPTO frames in stream
    /// order, with data slices borrowed from <paramref name="cryptoStream"/> as above.
    /// </returns>
    internal static List<List<TlsQuicFrame>> PlanInitialCryptoFrames(
        TlsQuicConnectionSpec spec, ReadOnlyMemory<byte> cryptoStream)
    {
        ArgumentNullException.ThrowIfNull(spec);

        // A flight with nothing to send is not a flight, and the alternative is a CRYPTO
        // frame with a zero-length Length field - legal on the wire, meaningless here, and
        // the thing TlsQuicConnectionSpec's own "every element must be at least 1" bound
        // exists to prevent one step earlier.
        // Witnessed by TlsQuicDatagramBuilderTests.AnEmptyCryptoStreamIsRejected.
        if (cryptoStream.IsEmpty)
        {
            throw new ArgumentException(
                "An Initial flight carries at least one byte of CRYPTO stream.", nameof(cryptoStream));
        }

        var frames = SplitIntoFrames(spec.InitialCryptoFrameByteCounts, cryptoStream);
        return GroupIntoDatagrams(spec.InitialCryptoFramesPerDatagram, frames);
    }

    /// <summary>How many bytes of CRYPTO stream one datagram of a Brave 151-shaped Initial
    /// flight carries. Hand it to <see cref="PlanInitialFlightSplit"/> to get the two
    /// <see cref="TlsQuicConnectionSpec"/> arrays for a stream of a given length.</summary>
    /// <remarks>
    /// <para>THE EXACT SPLIT POINT IS UNVERIFIED, AND TASK B12 IS WHAT WOULD SETTLE IT. The
    /// Brave 151 capture, lines 30-33, lists <i>"per-datagram Initial flight plans, CRYPTO
    /// frame splitting"</i> among the things neither verification endpoint inspects, so no
    /// live run can confirm or refute this number - a wrong split ships silently and passes
    /// every gate. B12 acquires uQUIC's <c>InitialPackets []InitialPacketPlan</c>, which is
    /// the per-packet plan this one number approximates; a packet capture of Chromium's own
    /// Initial flight would do as well. Until one of those exists this is a headroom
    /// calculation and not a measurement, and it is a KNOB rather than a constant precisely
    /// because a different client splits differently: pass your own figure here, or bypass
    /// this method entirely and set
    /// <see cref="TlsQuicConnectionSpec.InitialCryptoFrameByteCounts"/> and
    /// <see cref="TlsQuicConnectionSpec.InitialCryptoFramesPerDatagram"/> yourself.</para>
    /// <para>WHAT THE CAPTURE DOES BOUND, and where 1400 comes from. Its
    /// <c>max_udp_payload_size</c> is 1472 - the capture's own line 101 derives that as
    /// 1500 - 20 (IPv4) - 8 (UDP) - so a datagram this client sends and expects a path to
    /// carry stops there, while RFC 9000 s14.1 puts a 1200-byte floor under every one of
    /// them. A Brave-shaped Initial packet spends 43 bytes before its CRYPTO data: 20 of
    /// s17.2 header (1 first byte, 4 Version, 1 + 8 Destination Connection ID, 1 + 0 Source
    /// Connection ID, 1 zero Token Length, 4 Packet Number), a 2-byte Length varint, 5 of
    /// s19.6 CRYPTO frame (1 Type, up to 2 Offset, up to 2 Length) and a 16-byte AEAD tag.
    /// 1472 - 43 = 1429, and 1400 is that rounded down so the same figure still fits when a
    /// longer connection ID, a Retry token or a wider varint makes the overhead larger than
    /// the shape it was derived from. The rounding hides no unknown; the unknown is where
    /// Chromium actually cuts, which is the paragraph above.</para>
    /// <para>WRITTEN FROM THAT ARITHMETIC AND CONNECTED TO NOTHING, which is the same
    /// discipline <c>MaximumUdpPayload</c> two hundred lines above keeps and for a reason the
    /// capture states in its own words: <i>"Advertised parameter and actual ceiling are
    /// separate concerns and must not be wired together."</i> So this number is NOT read from
    /// <c>TlsQuicConnectionSpec.TransportParameters</c>'s <c>max_udp_payload_size</c> at run
    /// time, even though 1472 is where it came from. A client may advertise one figure and
    /// send at another; wiring the split to the advertised parameter would make changing what
    /// we tell a server silently change what we put on the wire.</para>
    /// <para>Witnessed by
    /// <c>TlsQuicDatagramBuilderTests.TheCapturesKeyShareForcesAMultiDatagramInitialAndEveryDatagramFitsThePath</c>,
    /// which builds the ClientHello from the B8 factory and checks the floor and the ceiling
    /// on EACH datagram, and by
    /// <c>TlsQuicDatagramBuilderTests.TheSameClientHelloWithTheSplitRemovedIsOneDatagramOverTheAdvertisedCeiling</c>,
    /// which pins what happens without this: one datagram, 90 bytes over the ceiling, and
    /// not one exception between them.</para>
    /// </remarks>
    internal const int Brave151InitialCryptoStreamBytesPerDatagram = 1400;

    /// <summary>Carves a CRYPTO stream of <paramref name="cryptoStreamLength"/> bytes into
    /// frames of at most <paramref name="cryptoStreamBytesPerDatagram"/> bytes, one frame per
    /// datagram, as the two arrays <see cref="TlsQuicConnectionSpec"/> takes.</summary>
    /// <remarks>
    /// <para>A HELPER, NOT A DEFAULT, AND NOTHING CONSULTS IT BEHIND A CALLER'S BACK. The
    /// spec's two arrays remain the knob: state them and they are honoured exactly, and this
    /// method never runs. It exists because those arrays are ABSOLUTE byte counts while a
    /// ClientHello's length is not fixed - one more character of server name moves it - so a
    /// preset written as two literal arrays fits exactly one ClientHello and makes
    /// <c>SplitIntoFrames</c> throw for the next one. Deriving them from the stream actually
    /// in hand is the only form of that preset which is total.</para>
    /// <para>ONE FRAME PER DATAGRAM IS PART OF THE GUESS and not a consequence of the byte
    /// count. A client may put two CRYPTO frames in one datagram, which is why
    /// <see cref="TlsQuicConnectionSpec.InitialCryptoFramesPerDatagram"/> is a separate
    /// array; this method takes the simplest reading of the capture's two-datagram Initial
    /// and carries the same B12 caveat as
    /// <see cref="Brave151InitialCryptoStreamBytesPerDatagram"/>.</para>
    /// <para>The last frame is short whenever the stream does not divide evenly, which is
    /// exactly what <see cref="TlsQuicConnectionSpec.InitialCryptoFrameByteCounts"/> permits
    /// of its final element and of no other - so every plan this method returns is one both
    /// that property and its cross-check against
    /// <see cref="TlsQuicConnectionSpec.InitialCryptoFramesPerDatagram"/> accept. Witnessed
    /// by <c>TlsQuicDatagramBuilderTests.EveryPlannedSplitIsOneTheSpecAndTheBuilderBothAccept</c>,
    /// which walks every stream length up to twice the budget at three budgets; by
    /// <c>TlsQuicDatagramBuilderTests.ThePlannedSplitStraddlesItsBudgetExactly</c> for the
    /// boundary itself; and by
    /// <c>TlsQuicDatagramBuilderTests.TheBudgetIsAKnobAndNotThePresetsNumber</c> for a
    /// caller's own figure. That a hand-written split is honoured instead of this one is
    /// <c>TlsQuicDatagramBuilderTests.ACallerSuppliedSplitIsHonouredExactlyAndThePresetIsNotConsulted</c>.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Either argument is below 1. A
    /// zero-length stream has no flight to plan, and a zero-byte datagram budget describes a
    /// flight of infinitely many empty datagrams. Witnessed by
    /// <c>TlsQuicDatagramBuilderTests.APlanWithNoStreamOrNoBudgetIsRejectedNamingTheArgument</c>.
    /// </exception>
    internal static (ImmutableArray<int> FrameByteCounts, ImmutableArray<int> FramesPerDatagram)
        PlanInitialFlightSplit(int cryptoStreamLength, int cryptoStreamBytesPerDatagram)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(
            cryptoStreamLength, 1, nameof(cryptoStreamLength));
        ArgumentOutOfRangeException.ThrowIfLessThan(
            cryptoStreamBytesPerDatagram, 1, nameof(cryptoStreamBytesPerDatagram));

        // ceil(length / budget), written so that neither operand is widened and no datagram
        // of zero bytes can appear: length is at least 1 and (length - 1) / budget is the
        // count of FULL datagrams that precede the last one.
        var datagrams = ((cryptoStreamLength - 1) / cryptoStreamBytesPerDatagram) + 1;
        var byteCounts = ImmutableArray.CreateBuilder<int>(datagrams);
        var framesPerDatagram = ImmutableArray.CreateBuilder<int>(datagrams);
        var remaining = cryptoStreamLength;
        for (var index = 0; index < datagrams; index++)
        {
            byteCounts.Add(Math.Min(cryptoStreamBytesPerDatagram, remaining));
            framesPerDatagram.Add(1);
            remaining -= cryptoStreamBytesPerDatagram;
        }

        return (byteCounts.MoveToImmutable(), framesPerDatagram.MoveToImmutable());
    }

    private static List<TlsQuicFrame> SplitIntoFrames(
        ImmutableArray<int> byteCounts, ReadOnlyMemory<byte> cryptoStream)
    {
        // "Empty means one frame carrying everything" - the property's own words, and not
        // the same as an empty datagram plan, which genuinely says nothing.
        if (byteCounts.IsEmpty)
        {
            return [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Crypto, Offset = 0, Data = cryptoStream }];
        }

        var frames = new List<TlsQuicFrame>(byteCounts.Length);
        var offset = 0;
        for (var index = 0; index < byteCounts.Length; index++)
        {
            var remaining = cryptoStream.Length - offset;

            // "The final element may be short if the stream runs out" - so the final one
            // takes what is left and any EARLIER one that cannot be filled means the split
            // describes a longer stream than it was given. Two reachable paths, two
            // messages, two witnesses:
            // TlsQuicDatagramBuilderTests.ASplitWhoseNonFinalFrameOutrunsTheStreamIsRejected
            // and TlsQuicDatagramBuilderTests.ASplitThatDoesNotCoverTheWholeStreamIsRejected.
            var isFinal = index == byteCounts.Length - 1;
            if (!isFinal && remaining < byteCounts[index])
            {
                throw new ArgumentException(
                    $"CRYPTO frame {index} of the split wants {byteCounts[index]} bytes but only "
                    + $"{remaining} remain; only the final frame may be short.",
                    nameof(cryptoStream));
            }

            var take = Math.Min(byteCounts[index], remaining);
            if (take < 1)
            {
                throw new ArgumentException(
                    $"CRYPTO frame {index} of the split has no stream left to carry.",
                    nameof(cryptoStream));
            }

            frames.Add(new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.Crypto,
                Offset = (ulong)offset,
                Data = cryptoStream.Slice(offset, take),
            });
            offset += take;
        }

        if (offset != cryptoStream.Length)
        {
            throw new ArgumentException(
                $"The CRYPTO split covers {offset} bytes but the stream is {cryptoStream.Length}.",
                nameof(cryptoStream));
        }

        return frames;
    }

    // The five-line walk the plan's "SETTLED - the flight plan stays two flat arrays"
    // amendment describes, and the only place the flat form is grouped. Empty means one
    // datagram holding every frame; the spec's cross-check has already made the counts sum
    // to frames.Count, so no bound is re-checked here.
    private static List<List<TlsQuicFrame>> GroupIntoDatagrams(
        ImmutableArray<int> framesPerDatagram, List<TlsQuicFrame> frames)
    {
        if (framesPerDatagram.IsEmpty)
        {
            return [frames];
        }

        var datagrams = new List<List<TlsQuicFrame>>(framesPerDatagram.Length);
        var taken = 0;
        for (var index = 0; index < framesPerDatagram.Length; index++)
        {
            datagrams.Add(frames.GetRange(taken, framesPerDatagram[index]));
            taken += framesPerDatagram[index];
        }
        return datagrams;
    }

    // RFC 9000 s14.1 keys on what the datagram carries, not on what the last packet is: a
    // datagram of Initial-then-Handshake is "carrying Initial packets" and is expanded, and
    // a Handshake-only datagram is not. Checking only the last packet - the one the PADDING
    // frames land in - would get the coalesced case exactly backwards.
    // Witnessed by TlsQuicDatagramBuilderTests.AHandshakeOnlyDatagramIsNotExpanded and
    // TlsQuicDatagramBuilderTests.AnInitialCoalescedWithAHandshakePacketIsPaddedInTheLastPacket.
    private static bool CarriesInitial(IReadOnlyList<TlsQuicPacketToSend> packets)
    {
        for (var index = 0; index < packets.Count; index++)
        {
            if (packets[index].Plan.Type == TlsQuicLongPacketType.Initial)
            {
                return true;
            }
        }
        return false;
    }

    // Appends (or prepends) exactly enough PADDING frames to make this packet `budget`
    // bytes. RFC 9000 s19.1 makes one PADDING frame one byte - "a PADDING frame consists of
    // the single byte that identifies the frame as a PADDING frame" - so a byte count and a
    // frame count are the same number here, and a default TlsQuicFrame is one: RawType
    // 0x00.
    //
    // The payload length is MEASURED by running the real frame writer, never re-derived
    // from the field diagrams. The alternative is a second encoder that has to be kept in
    // step with TlsQuicFrames.WriteFrame for every frame type and every varint width, which
    // is the transcription this phase bans; the cost is one extra pass over about a
    // kilobyte, once per datagram.
    private static IReadOnlyList<TlsQuicFrame> Expand(
        TlsQuicConnectionSpec spec, in TlsQuicPacketToSend packet, int budget)
    {
        var scratch = new List<byte>();
        for (var index = 0; index < packet.Frames.Count; index++)
        {
            TlsQuicFrames.WriteFrame(
                scratch,
                packet.Frames[index],
                packet.Plan.CryptoOffsetVarintWidth,
                packet.Plan.CryptoLengthVarintWidth);
        }

        var count = SolvePaddingFrameCount(packet.Plan, scratch.Count, budget, nameof(spec));
        if (count == 0)
        {
            return packet.Frames;
        }

        var padded = new List<TlsQuicFrame>(packet.Frames.Count + count);
        var leads = PaddingLeads(spec, packet.Frames);
        if (!leads)
        {
            padded.AddRange(packet.Frames);
        }
        for (var index = 0; index < count; index++)
        {
            padded.Add(default);
        }
        if (leads)
        {
            padded.AddRange(packet.Frames);
        }
        return padded;
    }

    // HOW GetLongHeaderLength's DOCUMENTED CIRCULARITY IS RESOLVED, because that comment
    // names it and leaves it to this task. At TlsQuicVarintWidth.Minimal the Length field's
    // own width depends on header.Length, which depends on the payload, which depends on
    // how much PADDING fits, which depends on the header length. The dependency is RFC 9000
    // s16 Table 4's four steps, so instead of iterating to a fixed point - which oscillates
    // by one byte at a step boundary - this enumerates the four widths and keeps the one
    // that is self-consistent. At most one ever is, and the arithmetic says why:
    //
    //   packetSize = fixedHeader + w + payload + count + tag
    //   Length     = packetNumberLength + payload + count + tag
    //
    // where fixedHeader is everything in the header except the Length varint - byte 0, the
    // version, both connection IDs with their length bytes, the token with its length
    // varint for an Initial, and the packet number. Setting packetSize to the budget and
    // solving gives, for each candidate w:
    //
    //   count  = budget - fixedHeader - w - payload - tag
    //   Length = packetNumberLength + budget - fixedHeader - w
    //
    // A w one step wider costs one to four bytes of Length, so a Length that needs w+1 at
    // width w needs it at width w+1 too - the two candidates cannot both be consistent. The
    // gap this leaves is real and is not an implementation limit, and it is EXACTLY
    // (w_next - w_prev) VALUES WIDE at each Table 4 boundary, which is derivable from the
    // two lines above. Writing H for fixedHeader less the packet number, the packet number
    // cancels and Length = budget - H - w. So w_prev is self-consistent while
    // budget <= H + w_prev + max(w_prev), and w_next only once
    // budget >= H + w_next + max(w_prev) + 1, leaving the closed interval
    // [H + w_prev + max(w_prev) + 1, H + w_next + max(w_prev)] reachable at neither:
    //
    //   1/2 boundary: 1 value,  budget = H + 65
    //   2/4 boundary: 2 values, budget = H + 16386 and H + 16387
    //   4/8 boundary: 4 values, budget = H + 1073741828 .. H + 1073741831
    //
    // An earlier revision of this comment said "a one-byte range", which its own witness
    // contradicted: that witness carries two rows. Rejected rather than rounded, since
    // rounding would silently miss the target a fingerprint spec asked for.
    // Witnessed at the 1/2 boundary by
    // TlsQuicDatagramBuilderTests.ACoalescedBudgetOnTheOneByteTableFourStepIsRejected, which
    // needs a coalesced budget because PaddingTarget's own floor is 1200, and at the 2/4
    // boundary by TlsQuicDatagramBuilderTests.APaddingTargetOnTheTableFourStepIsRejected. The
    // 4/8 boundary is UNREACHABLE BY CONSTRUCTION and has no witness: it needs a budget past
    // a billion, and s18.2 caps PaddingTarget - the only source of budget - at 65527.
    //
    // fixedHeader is obtained by asking GetLongHeaderLength for the one-byte form and
    // removing that one byte, rather than by adding up the s17.2 fields a second time here.
    //
    // `paramName` is the CALLER's parameter, passed down because this method's own `plan` is
    // private and naming it sent a reader looking for an argument no caller ever supplied.
    // The knob that actually decides the budget is spec.PaddingTarget.
    private static int SolvePaddingFrameCount(
        in TlsQuicPacketPlan plan, int payloadLength, int budget, string paramName)
    {
        // RFC 9000 s17.3.1: a short header is byte 0, the Destination Connection ID and
        // the Packet Number, and no Length field - so the circularity GetLongHeaderLength's
        // comment documents, and the Table 4 search below that resolves it, DO NOT ARISE.
        // The header is a fixed size, the count is one subtraction, and there is no width
        // for the budget to step over: the throw below is unreachable from here, which is
        // why this returns before it rather than threading a null Type through the search.
        //
        // Reachable because s12.2 puts the short-header packet last and this method is
        // called for the last packet of an Initial-carrying datagram; s14.1's expansion
        // therefore lands inside it. Witnessed by
        // TlsQuicDatagramBuilderTests.AnInitialCoalescedWithAShortHeaderPacketIsPaddedInThe
        // ShortHeaderOne.
        if (plan.Type is null)
        {
            var shortFixedHeader =
                1 + plan.DestinationConnectionId.Length + plan.PacketNumberEncodedLength;
            return Math.Max(
                0,
                budget - shortFixedHeader - payloadLength - TlsQuicPacketBuilder.AuthenticationTagLength);
        }

        var probe = new TlsQuicLongHeader
        {
            Type = plan.Type.Value,
            Version = plan.Version,
            DestinationConnectionId = plan.DestinationConnectionId,
            SourceConnectionId = plan.SourceConnectionId,
            Token = plan.Token,
            Length = 0,
            PacketNumberLength = plan.PacketNumberEncodedLength,
        };
        var fixedHeader =
            TlsQuicPacketHeader.GetLongHeaderLength(probe, TlsQuicVarintWidth.OneByte) - 1;

        var tag = TlsQuicPacketBuilder.AuthenticationTagLength;
        var requested = plan.LengthVarintWidth;
        var narrowest = requested == TlsQuicVarintWidth.Minimal ? 1 : (int)requested;

        // The largest count any candidate can yield is the one at the narrowest width. If
        // that is already negative the packet fills the budget on its own, which s14.1
        // permits - "Datagrams containing Initial packets MAY exceed 1200 bytes" - so it is
        // not an error and no PADDING is added.
        // Witnessed by TlsQuicDatagramBuilderTests.APacketThatAlreadyFillsTheTargetIsNotPadded.
        if (budget - fixedHeader - narrowest - payloadLength - tag < 0)
        {
            return 0;
        }

        foreach (var width in Table4Widths)
        {
            if (requested != TlsQuicVarintWidth.Minimal && width != narrowest)
            {
                continue;
            }

            var count = budget - fixedHeader - width - payloadLength - tag;
            if (count < 0)
            {
                continue;
            }

            var length = (ulong)(plan.PacketNumberEncodedLength + payloadLength + count + tag);
            if (QuicVariableLengthInteger.GetEncodedLength(length, requested) == width)
            {
                return count;
            }
        }

        throw new ArgumentException(
            $"No RFC 9000 s16 Table 4 width makes a {plan.Type} packet exactly "
            + $"{budget} bytes at a {requested} Length field; the reachable sizes step over it. "
            + "PaddingTarget, less whatever earlier packets of this datagram already took, is "
            + "what set that size.",
            paramName);
    }

    // Where the PADDING sits relative to the frames the caller supplied is a layout choice,
    // and TlsQuicConnectionSpec.InitialFrameOrder is where a client declares it. This
    // builder never reorders the caller's frames - that is the connection layer's job and
    // the contract TlsQuicPacketBuilder.Build keeps - so the only question here is whether
    // the PADDING it adds itself leads or trails.
    //
    // PADDING LEADS ONLY WHEN THE SPEC PUTS SOMETHING AFTER IT THAT THIS PACKET CARRIES.
    // Stated positively like that rather than as "nothing listed before it", which is the
    // same thing only when some family is listed at all: a packet of frames the order does
    // not mention would flip to padding-first under the negative form, which no spec asked
    // for. That is a real defect this code had during development - a PING-only Handshake
    // packet got its PADDING first - and it is the behaviour
    // TlsQuicConnectionSpec.InitialFrameOrder now documents, because an earlier wording of
    // that property implied the opposite and nothing but this comment arbitrated. The
    // default order is CRYPTO then PADDING, so PADDING trails, which is what RFC 9001 A.2
    // shows and what Chromium sends.
    // Witnessed on both sides by
    // TlsQuicDatagramBuilderTests.PaddingLeadsWhenTheSpecOrdersItBeforeCrypto and
    // TlsQuicDatagramBuilderTests.AHandshakeOnlyDatagramIsNotExpanded's coalesced sibling,
    // TlsQuicDatagramBuilderTests.AnInitialCoalescedWithAHandshakePacketIsPaddedInTheLastPacket,
    // whose only frame is a PING the default order never names.
    private static bool PaddingLeads(TlsQuicConnectionSpec spec, IReadOnlyList<TlsQuicFrame> frames)
    {
        var order = spec.InitialFrameOrder;
        var padding = order.IndexOf(TlsQuicFrameType.Padding);
        if (padding < 0)
        {
            return false;
        }

        for (var index = 0; index < frames.Count; index++)
        {
            // A PADDING frame the CALLER supplied says nothing about where the ones this
            // builder adds belong - PADDING is not listed after itself. Skipping it also
            // makes `>` and `>=` the same comparison here, since no two families share an
            // index, so that boundary is closed by construction rather than by a witness.
            if (frames[index].Type == TlsQuicFrameType.Padding)
            {
                continue;
            }

            if (order.IndexOf(frames[index].Type) > padding)
            {
                return true;
            }
        }
        return false;
    }
}
