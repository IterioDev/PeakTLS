using System.Globalization;
using System.Text;

namespace SharpTls.Quic;

/// <summary>
/// Reads the fingerprint-bearing layout choices back out of the datagrams a connection
/// actually emitted, and renders them as a diffable text block shaped like the QUIC section
/// of <c>docs/superpowers/specs/reference-captures/2026-08-16-brave-151-http3-impersonate-pro.md</c>.
/// </summary>
/// <remarks>
/// <para>A READOUT THAT READS THE SPEC BACK IS A TAUTOLOGY, NOT A MEASUREMENT. Every field in
/// the <c>"quic"</c> block below is parsed out of the emitted bytes: connection ID lengths and
/// the token come out of the long header in the clear; the packet number, its encoded length,
/// the frame order and the CRYPTO splits come out of packets this type OPENS, with keys
/// RFC 9001 s5.2 derives from the Destination Connection ID the first Initial packet carries -
/// which is itself read off the wire here rather than handed in. A caller cannot make this
/// type report a number the datagrams do not contain.</para>
/// <para>THAT LAST SENTENCE IS A CLAIM WITH ONE WITNESS, AND THE WITNESS ONCE LEAKED.
/// TlsQuicFingerprintReadoutTests.TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith renders one
/// recording against two specs and requires an identical block - but it left six spec
/// properties unset on both sides, and four fields could therefore be rendered off the spec
/// with the whole suite still green. The specs now disagree on every property
/// <see cref="TlsQuicConnectionSpec"/> declares. A property added to that type without being
/// added to both specs re-opens the hole, and the sentence above stops being true.</para>
/// <para>SEGMENT 3 OF THE <c>perk</c> STRING IS RENDERED HERE TOO, in its own section below the
/// <c>"quic"</c> block, with C12's three-valued verdict column and no fourth value. It is the
/// same measurement as everything else on this page: the parameters come out of the
/// ClientHello these datagrams carried, never out of
/// <see cref="TlsQuicTransportParameterSpec"/>'s composed list, so a connection whose extension
/// 57 never reached the wire renders no rows rather than fourteen. See
/// <see cref="RenderPerkSegment3"/> for why the encoded ClientHello beat the composed set as
/// the source.</para>
/// <para>THE TWO EXCEPTIONS ARE LABELLED AS SUCH, in their own section and never inside the
/// <c>"quic"</c> block: <see cref="TlsQuicConnectionSpec.CoalesceAscendingByLevel"/> and
/// <see cref="TlsQuicConnectionSpec.AckLeadsInPacket"/> are taken from the spec. Their
/// *consequences* are still measured - the per-datagram packet-kind sequence and the frame
/// order inside every Initial packet are both printed from bytes - so a reader can see when
/// the recording corroborates the knob and when it is simply silent about it.</para>
/// <para>THE AEAD IS THIS TYPE'S OWN WITNESS FOR THE PACKET NUMBER. RFC 9001 s5.3 builds the
/// nonce from the FULL packet number, so a reconstruction that is wrong in any bit makes
/// <see cref="TlsQuicPacketProtection.TryOpen"/> fail rather than return wrong plaintext.
/// Every number this type prints for an opened packet is therefore backed by a successful
/// tag check, not by a parse that could have gone quietly astray.</para>
/// <para>Nothing here is on any send or receive path. It throws on a datagram it cannot parse,
/// deliberately and unlike every other reader in this namespace: those walk attacker-controlled
/// input where a throw is a remote kill, and this walks bytes we produced ourselves, where a
/// silently wrong number is the only failure that matters.</para>
/// </remarks>
// ============================================================================================
// MUTATION LEDGER. Every row was applied in a git worktree, run against
// `dotnet test --filter "FullyQualifiedName~Quic"`, and reverted. Rows are the lines beginning
// "// M" below.
//
// SELF-CHECK, RUN LITERALLY AGAINST THIS FILE AND CONFIRMED:
//   grep -c '^// M[0-9][0-9] '           -> 33
//   grep -c '^// M[0-9][0-9] .*KILLED'   -> 25
//   grep -c '^// M[0-9][0-9] .*SURVIVED' -> 8
//   33 - 25 = 8, and the eight survivors split 3 unreachable-by-construction (M04, M05,
//   M07) + 1 vacuous (M12) + 4 unwitnessed (M15, M16, M22, M31) = 8. The patterns anchor
//   on the row prefix so that this block's own prose cannot inflate its own counts - which
//   a plain grep for the verdict words does, by several, as written here.
//
// TWO ROWS CHANGED VERDICT BECAUSE OF THE FIRST SWEEP, which is the whole point of running
// one: rows 3 and 17 survived on the first pass and are killed now by tests written for them.
//
// FOUR MORE CHANGED VERDICT BECAUSE OF THE SECOND. M25, M26, M27 and M33 were re-run against
// the pre-fix commit and SURVIVED 1069/1069 there: the anti-tautology witness rendered one
// recording against two specs that left Token, InitialCryptoFrameByteCounts,
// InitialCryptoFramesPerDatagram, InitialFrameOrder, InitialRttRange and AckRangeLimit unset
// on BOTH sides, so it did not constrain the six fields it was the only guard for. THAT
// FALSIFIED THIS TYPE'S OWN HEADLINE CLAIM - a caller could make it report a number the
// datagrams do not contain, and did, four times. The two specs now disagree on every property
// TlsQuicConnectionSpec declares, and the same four mutants die: three of them fail ONLY the
// witness, which is what shows the coverage is the witness's and not some other test's.
//
// M01 empty-recording guard removed .................. KILLED  AnEmptyRecordingIsRefused
// M02 first-datagram guard removed, both disjuncts ... KILLED  ARecordingWhoseFirstDatagram...
// M03 only the Initial TYPE disjunct removed ......... KILLED  ARecordingWhoseFirstDatagram...
//     Survived the first pass: a header that does not PARSE fires the other disjunct first,
//     so the type check had no witness at all. A Handshake packet that parses cleanly is now
//     the second half of that test. PRESENCE IS NOT IDENTITY, again.
// M04 header Length varint cross-check removed ....... SURVIVED  unreachable by construction
//     See HeaderLengthVarintWidthOf's remarks: two independent walks of the same header,
//     separable only by a future edit to one of them or by an out-of-contract Retry packet.
// M05 header-protection-removal failure ignored ...... SURVIVED  unreachable by construction
//     TryRemove fails only on a packet too short to hold its own sample; every packet here
//     was built by TlsQuicPacketBuilder and carries one. Reaching it needs a forged datagram,
//     which the "datagrams this connection emitted" contract excludes.
// M06 AEAD open failure ignored ...................... KILLED  AnInitialPacketThatDoesNotOpen...
// M07 frame-parse failure ignored .................... SURVIVED  unreachable by construction
//     The bytes walked here are AEAD-verified plaintext of frames we serialized with
//     TlsQuicFrames' own writer. A malformed one cannot be among them. The mutant is an
//     infinite loop rather than a wrong number, so the guard stays.
// M08 flight membership test All -> Any .............. KILLED  AnInitialOnlyDatagram..., snapshot
// M09 flight TakeWhile -> Where ...................... KILLED  AnInitialOnlyDatagram...
// M10 varint width shift 6 -> 7 ...................... KILLED  EveryLayoutKnob..., and 4 more
// M11 client/server CID lengths swapped .............. KILLED  EveryLayoutKnob..., snapshot
//     The one field with real ground truth in the Brave capture, so this row matters most.
//     Killed only because that test uses 7 and 12 rather than one length twice.
// M12 padding bytes counted as one per frame ......... SURVIVED  vacuous
//     RFC 9000 s19.1 makes PADDING a single byte and TlsQuicFrames yields one frame per byte,
//     so `offset - frameStart` IS 1 at every reachable call. A test would pass against the
//     mutant and stand as a false witness, so none is written.
// M13 run-length run test inverted ................... KILLED  TheCryptoSplit..., snapshot
// M14 Distinct dropped from the width fields ......... KILLED  snapshot
// M15 CRYPTO stream contiguity check removed ......... SURVIVED  unwitnessed, shadowed
// M16 ClientHello handshake-type check removed ....... SURVIVED  unwitnessed, shadowed
//     M15 and M16 shadow each other and M17: every incomplete stream this contract admits is
//     caught by whichever of the three it reaches first, and no in-contract recording
//     separates them. They are kept because M15 is the check that is right BY REASON, while
//     the other two reject the same input by the happenstance of what the gap's first bytes
//     hold. A witness isolating M15 would need a gapped stream whose concatenation still
//     looks like a well-formed handshake message, which nothing here can construct.
// M17 declared-length coverage check removed ......... KILLED  ACryptoStreamThatDoesNot...
//     Survived the first pass. The gap case reached M15 instead; the TRUNCATED case - the
//     first datagram of a two-datagram flight, contiguous from zero and simply short - is
//     the one that reaches only this check, and it is now in that test.
// M18 zero-length source CID branch never taken ...... KILLED  AZeroLengthSourceConnectionId...
// M19 initial_source_connection_id comparison inverted  KILLED  TheAbsentInitialRtt..., snapshot
// M20 the two order knobs printed under each other ... KILLED  TheQuicBlockIsUnchangedBy...
//     Killed only because each spec in that test sets the two knobs to DIFFERENT values.
//     Both-true against both-false would have let this swap straight through.
// M21 multi-level corroboration > 1 becomes >= 1 ..... KILLED  snapshot
// M22 ack corroboration stops excluding PADDING ...... SURVIVED  unwitnessed BY THIS CORPUS
//     NARROWED WORDING: this is not unwitnessABLE. No recording this phase produces holds a
//     packet carrying an ACK beside PADDING and nothing else - datagram 1's Initial packet
//     carries the ACK alone, and the Handshake packet fills the datagram - but a recording
//     whose ACK-only Initial is PADDED to a datagram target separates it outright, and that
//     is a recording a later task can construct. The exclusion is a judgement about what
//     corroborates AckLeadsInPacket (PADDING has no position to lead or trail).
// M23 token prefix truncated to four bytes ........... KILLED  TheTokenLengthAndPrefix...
// M24 non-Initial long headers opened too ............ KILLED  6 tests
//
// ---- SECOND SWEEP, after the two review gates on task 11 ---------------------------------
// M25 token_length/token_prefix rendered from spec ... KILLED  TheQuicBlockIsUnchangedBy...,
//     TheTokenLengthAndPrefixAreReadOffTheHeaderRatherThanAssumedEmpty. SURVIVED pre-fix.
// M26 crypto_frames_per_datagram rendered from spec .. KILLED  TheQuicBlockIsUnchangedBy...
//     and nothing else, which is the isolation that makes it the witness's kill rather than
//     some other test's. SURVIVED pre-fix: both guard specs left the property at its default.
// M27 crypto_frame_byte_counts rendered from spec .... KILLED  TheQuicBlockIsUnchangedBy...
//     alone. SURVIVED pre-fix, same cause.
// M28 the whole source-CID verdict becomes a constant  KILLED  AnInitialSourceConnectionId...
//     The defect both gates converged on. With the length-only comparison this row replaced,
//     hardcoding the verdict survived 1069/1069, because no recording in the corpus
//     advertised a parameter that disagreed with the header at all.
// M29 the source-CID comparison weakened to lengths .. KILLED  AnInitialSourceConnectionId...
//     RFC 9000 s7.3 requires the VALUE to agree. Five bytes agreeing about nothing reported
//     agreement, under a field name that says "equals_header_source".
// M30 ClientHello walk bounds checks removed ......... KILLED  ACryptoStreamThatIsNotA...
//     Not a pass/fail flip: the mutant throws IndexOutOfRangeException where this type's
//     remarks promise InvalidOperationException, and Assert.Throws is exact about which.
// M31 CRYPTO frame type width assumed to be one byte . SURVIVED  unwitnessed BY THIS CORPUS
//     TlsQuicFrames' WRITER always uses s12.4's shortest type encoding, so typeWidth is 1 in
//     every recording anything here can produce and the mutant is an identity. Its READER
//     declines s12.4's receiver MAY on purpose, so a foreign capture carrying an over-long
//     CRYPTO type is admissible input and separates this row outright - the mutant would
//     sample an interior Offset byte and print a width that is simply wrong. A witness needs
//     a packet TlsQuicPacketBuilder cannot build, so none is written here.
// M32 initial_frame_order rendered from spec ......... KILLED  TheQuicBlockIsUnchangedBy...,
//     TheCryptoSplitAndTheFlightPlan..., TheReadoutMatchesTheCheckedInSnapshot
// M33 initial_rtt_parameter_present from spec range .. KILLED  TheQuicBlockIsUnchangedBy...
//     alone. SURVIVED pre-fix - and this is the field the plan's amendments single out as
//     MEASURED rather than restated, so the leak ran straight through the phase's headline.
//
// ---- TASK B10, perk segment 3 ------------------------------------------------------------
//
// A SEPARATE ROW PREFIX ON PURPOSE. The rows below begin "// B10-" so that the M-row
// self-check above cannot be inflated by them and this one cannot be inflated by the M rows.
//
// SELF-CHECK, RUN LITERALLY AGAINST THIS FILE AND CONFIRMED:
//   grep -c '^// B10-[0-9]* '            -> 18
//   grep -c '^// B10-[0-9]* .*KILLED'    -> 17
//   grep -c '^// B10-[0-9]* .*SURVIVED'  ->  1
//   18 - 17 = 1, and the one survivor is 1 vacuous + 0 unreachable + 0 unwitnessed = 1.
//   Rows are contiguous, B10-1 to B10-18, no gaps.
//
// HOW. mutate-b10.py, in a private git worktree at f83331f with only this task's four files
// modified, because the shared tree carries two other tasks' edits. Every run rebuilt with
// `dotnet build --no-incremental` and then ran `dotnet test --filter FullyQualifiedName~Quic
// --no-build`. Each run's TOTAL case count was checked against a floor of 1900 and a run
// below it would have been REJECTED rather than read - an aborted run prints an ordinary
// "Failed: 0, Passed: <m>" line indistinguishable from a survivor. The first twenty runs
// reported 1939 and the three re-runs 1940, the difference being the case this sweep added.
//
// THE HARNESS WAS PROVED IN BOTH DIRECTIONS BEFORE ANY ROW, and neither control is counted
// among the eighteen. Known-bad - the capture's `3:1472` token changed to `3:1500` - KILLED.
// Inert - one added comment line above this class - SURVIVED.
//
// B10-1  rows scored by membership instead of at their index . KILLED  TheSwapOfTwoAdjacent...
//        THE ROW THIS TASK EXISTS FOR. Commit 4ed90bf measured 12/12 against the live service
//        that reordering moves perk_hash and leaves perk_hash_normalized identical, so a set
//        comparison scores a sorted list as a match and a sorted list is a different client.
// B10-2  the emitted list sorted before it is scored ......... KILLED  snapshot, and 13 more
// B10-3  PerkToken's reserved-identifier branch removed ...... KILLED  TheShippedPreset...
// B10-4  PerkToken's AUTO branch removed ..................... KILLED  TheShippedPreset...
// B10-5  initial_rtt alone scored on value, not AUTO ......... KILLED  TheShippedPreset...
//        THE ROW THE PLAN NAMES. The service hashes neither 12583's value nor 15's, so a row
//        that scored them on value would report a MISMATCH the fingerprint cannot see.
// B10-6  RFC 9368 s3's reserved-version predicate ignored .... KILLED  TheShippedPreset...
//        This is why the GREASE version is NOT in the third column: the token is recomputed
//        from the emitted bytes, so it is verifiable rather than not-yet-known.
// B10-7  version_information's available list dropped ........ KILLED  TheShippedPreset...
// B10-8  the whole-segment row's verdict hard-coded to match . KILLED  snapshot
// B10-9  the extras row's verdict hard-coded to match ........ KILLED  snapshot
// B10-10 IdentifierPartOf returns the whole token ............ KILLED  AChangedValueIsA
//        MismatchAtItsIndexAndNotAnUnlistedParameter, and nothing else - the isolation that
//        makes it that test's kill. Every other recording here either reproduces the
//        capture's tokens exactly or differs in the identifier too.
// B10-11 an unrecoverable ClientHello renders an empty set ... KILLED  ARecordingThatYields
//        NoClientHelloRendersNoSegmentThreeRowsAtAll
// B10-12 counts taken from the capture's length, not the rows  KILLED  TheSegmentThree...
// B10-13 the two width rows verdicted match, not not-yet-known KILLED  TheShippedPreset...
// B10-14 ReservedIdentifierN drops s18.1's base ............. SURVIVED  vacuous
//        s18.1's identifier is 31 * N + 27 and 27 < 31, so integer division gives
//        identifier / 31 == (identifier - 27) / 31 for EVERY identifier of that form - the
//        mutant is an identity over the whole domain the call site admits, since the value
//        reaches it only behind IsReservedIdentifier. A witness would need an identifier
//        that is not of s18.1's form, which no caller can produce, and the test would then
//        stand as a witness for something this method does not exist to do. No test written.
// B10-15 the segment diff always reports the two identical ... KILLED  ASegmentThatIsA
//        PrefixOfTheCapturesIsNotReportedIdentical.
//        SURVIVED THE FIRST PASS, and the reason is the shape of this file's corpus: every
//        other recording differs from the capture INSIDE the shared prefix, so the walk stops
//        at a character both strings have and the mutant never fires. A client sending the
//        capture's first thirteen parameters and stopping runs out of string instead, and the
//        mutant then prints `identical` directly above a row reading MISMATCH. That recording
//        is now in the suite.
// B10-16 IntegerOrHex drops the whole-value coverage check ... KILLED  AParameterValueThat
//        IsNotOneWholeVarintIsRenderedAsItsBytes
// B10-17 the folded initial_rtt identifier moved off 12583 ... KILLED  TheShippedPreset...
//        THE ROW THAT PROVES THE FOLD COST NOTHING. Deleting this file's private copy of
//        12583 in favour of TlsQuicTransportParameterSpec.InitialRttIdentifier could have
//        made the identifier unwitnessed here - both sides would move together. They do not:
//        the capture's token is the third witness and it does not move.
// B10-18 the perk separator changed from ';' to ',' ......... KILLED  TheShippedPreset...
// ============================================================================================
internal static class TlsQuicFingerprintReadout
{
    /// <summary>How many leading token bytes the readout prints. The whole token would be a
    /// fingerprint field in its own right; A4-minimal never sends one, so the prefix is what
    /// tells a later reader whether that is still true.</summary>
    private const int TokenPrefixBytes = 8;

    /// <summary>RFC 9001 s8.2's <c>quic_transport_parameters</c> ClientHello extension.</summary>
    private const ushort QuicTransportParametersExtension = 0x0039;

    /// <summary>RFC 8446 s4.1.2: a ClientHello is handshake type 1.</summary>
    private const byte ClientHelloHandshakeType = 0x01;

    /// <summary>RFC 9000 s18.2 <c>initial_source_connection_id</c>.</summary>
    private const ulong InitialSourceConnectionIdParameterId = 0x0f;

    /// <summary>RFC 9001 s5.3: every AEAD this phase uses has a 16-byte tag.</summary>
    private const int AeadTagLength = 16;

    /// <summary>What a cell says when the recording never yielded the ClientHello.</summary>
    private const string NotRecoverable = "not-recoverable-from-this-recording";

    /// <summary>What a cell says when the ClientHello was read and holds no such
    /// parameter.</summary>
    private const string AbsentToken = "absent";

    // ---- the capture's published figures, and nothing else ---------------------------------
    //
    // EVERY CONSTANT IN THIS SECTION HAS AN EXTERNAL SOURCE, which is what separates it from
    // the snapshot the tests hold. Line numbers are into
    // docs/superpowers/specs/reference-captures/2026-08-16-brave-151-http3-impersonate-pro.md.
    //
    // 12583 IS NOT AMONG THEM ANY MORE, AND THAT IS TASK B10's SECOND CORRECTION. This file
    // used to carry a private InitialRttParameterId holding the same 12583 that
    // TlsQuicTransportParameterSpec.InitialRttIdentifier holds, declared here because the
    // parameter's ABSENCE was a reported deviation. B5 and B8 turned that absence into a
    // presence, so the readout now names the same identifier the composer emits under -
    // one declaration, in the file that puts it on the wire, cited from here.

    /// <summary>The capture's <c>perk</c> segment 3, quoted from line 47 - the text between
    /// its second and third pipe.</summary>
    /// <remarks>THE ORDER IS THE FINGERPRINT. Capture line 74: "This ordering is the
    /// fingerprint. It is not sorted, and it is not the RFC's presentation order." Commit
    /// 4ed90bf then measured it against the live service over 12/12 attempts: reordering the
    /// parameters moved <c>perk_hash</c> and left <c>perk_hash_normalized</c> byte-identical,
    /// so wire order is hashed and every row below is scored AT ITS INDEX rather than by
    /// membership.</remarks>
    private const string CaptureSegment3 =
        "12584:0x4f524947;GREASE;32:65536;9:103;8:100;7:6291456;5:6291456;15:AUTO;"
        + "17:1@GREASE,1;1:30000;6:6291456;4:15728640;12583:AUTO;3:1472";

    /// <summary>How the <c>perk</c> string separates one parameter from the next, capture line
    /// 47.</summary>
    private const char PerkSeparator = ';';

    /// <summary>How the <c>perk</c> string separates a parameter's identifier from its
    /// rendered value, capture line 47.</summary>
    private const char PerkValueSeparator = ':';

    /// <summary>The bare token the <c>perk</c> string renders a reserved (GREASE) identifier
    /// and a reserved version as, capture line 47.</summary>
    private const string GreaseToken = "GREASE";

    /// <summary>The token the <c>perk</c> string renders instead of a value it declines to
    /// hash, capture lines 98-99: "The <c>perk_text</c> reflects this by rendering it
    /// <c>12583:AUTO</c> rather than embedding the number, and does the same for
    /// <c>initial_source_connection_id</c> at <c>15:AUTO</c>."</summary>
    private const string AutoToken = "AUTO";

    /// <summary>Line 47's segment 3 split into its fourteen tokens, which is what every row
    /// below is scored against.</summary>
    /// <remarks>SPLIT RATHER THAN RE-TYPED, so the table's rows and the whole-segment row
    /// cannot disagree about what the capture says. Witnessed by
    /// TlsQuicFingerprintReadoutTests.TheCapturesFourteenTokensAndItsFourteenTableRowsAgree,
    /// which cross-checks this split against the capture's OTHER rendering of the same
    /// fourteen parameters - the table at lines 79-92 - so the two halves of the capture
    /// corroborate each other rather than one being copied from the other.</remarks>
    private static readonly string[] CaptureTokens = CaptureSegment3.Split(PerkSeparator);

    /// <summary>The fourteen parameters' names, from the capture's own table at lines 79-92,
    /// in that table's order.</summary>
    /// <remarks>Names only. Every VALUE scored here comes from <see cref="CaptureTokens"/>,
    /// so no number in the capture's table is typed twice into this file.</remarks>
    private static readonly string[] CaptureParameterNames =
    [
        "12584 google_connection_options",
        "reserved (GREASE) parameter",
        "32 max_datagram_frame_size",
        "9 initial_max_streams_uni",
        "8 initial_max_streams_bidi",
        "7 initial_max_stream_data_uni",
        "5 initial_max_stream_data_bidi_local",
        "15 initial_source_connection_id",
        "17 version_information",
        "1 max_idle_timeout",
        "6 initial_max_stream_data_bidi_remote",
        "4 initial_max_data",
        "12583 initial_rtt",
        "3 max_udp_payload_size",
    ];

    /// <summary>What the capture publishes about <c>initial_rtt</c>, line 91's single draw and
    /// line 96's refusal to treat it as a constant.</summary>
    private const string CaptureInitialRttCell = "192859, one draw - capture lines 91 and 96";

    /// <summary>What the capture publishes about the reserved parameter's identifier, line 107
    /// - five significant digits and no more.</summary>
    private const string CaptureReservedIdentifierCell = "id ~ 3.7457e18 - capture line 107";

    /// <summary>Renders the readout for one recording.</summary>
    /// <param name="emittedDatagrams">Every datagram the connection sent, in send order.</param>
    /// <param name="spec">The spec the connection was built with. Read for exactly two fields,
    /// both reported in the spec-sourced section - see the remarks on this type.</param>
    internal static string Describe(
        IReadOnlyList<ReadOnlyMemory<byte>> emittedDatagrams,
        TlsQuicConnectionSpec spec)
    {
        ArgumentNullException.ThrowIfNull(emittedDatagrams);
        ArgumentNullException.ThrowIfNull(spec);
        if (emittedDatagrams.Count == 0)
        {
            throw new ArgumentException(
                "A fingerprint readout needs at least one emitted datagram.",
                nameof(emittedDatagrams));
        }

        return Render(Read(emittedDatagrams), spec);
    }

    // ---- reading -------------------------------------------------------------------------

    private static List<DatagramReadout> Read(IReadOnlyList<ReadOnlyMemory<byte>> datagrams)
    {
        // RFC 9001 s5.2: the Initial secrets come from "the Destination Connection ID field
        // from the client's first Initial packet" and nothing else. So the keys that open our
        // own Initial packets are recoverable FROM THE RECORDING - which is what lets this
        // whole readout be a measurement rather than a restatement, and is also why an
        // on-path observer can read every field below off a real capture.
        if (!TlsQuicPacketHeader.TryReadLongHeader(datagrams[0], out var first, out _)
            || first.Type != TlsQuicLongPacketType.Initial)
        {
            throw new InvalidOperationException(
                "The first emitted datagram does not begin with an Initial packet, so RFC 9001 "
                + "s5.2's key input cannot be recovered from the recording.");
        }

        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, first.DestinationConnectionId.Span);
        using var keys = secrets.DeriveClientPacketProtectionKeys(TlsQuicVersion.Version1);
        var headerProtectionKey = keys.CopyHeaderProtectionKey();
        var key = keys.CopyKey();
        var iv = keys.CopyIv();

        var result = new List<DatagramReadout>(datagrams.Count);
        for (var i = 0; i < datagrams.Count; i++)
        {
            var datagram = new DatagramReadout { Index = i, Bytes = datagrams[i].Length };

            // TlsQuicDatagramReader.Read yields slices that alias the datagram and parses
            // lazily; this foreach runs to completion in place, which is the contract its
            // LIFETIME remarks ask for.
            foreach (var coalesced in TlsQuicDatagramReader.Read(datagrams[i]))
            {
                datagram.Packets.Add(ReadPacket(coalesced, headerProtectionKey, key, iv));
            }

            result.Add(datagram);
        }

        return result;
    }

    private static PacketReadout ReadPacket(
        TlsQuicCoalescedPacket coalesced,
        byte[] headerProtectionKey,
        byte[] key,
        byte[] iv)
    {
        if (coalesced.Kind != TlsQuicCoalescedPacketKind.Long)
        {
            return new PacketReadout
            {
                Kind = coalesced.Kind == TlsQuicCoalescedPacketKind.Short
                    ? "1-RTT"
                    : "VersionNegotiation",
                Bytes = coalesced.Packet.Length,
            };
        }

        if (!TlsQuicPacketHeader.TryReadLongHeader(coalesced.Packet, out var header, out _))
        {
            throw new InvalidOperationException(
                "A long header packet we emitted did not parse back.");
        }

        var packet = new PacketReadout
        {
            Kind = header.Type.ToString(),
            Bytes = coalesced.Packet.Length,
            DestinationConnectionIdLength = header.DestinationConnectionId.Length,
            // THE BYTES, NOT THE LENGTH. initial_source_connection_id is compared against this
            // field by VALUE below - RFC 9000 s7.3 makes it the value that must agree - and a
            // readout that kept only the length would report agreement for a parameter holding
            // five entirely different bytes.
            SourceConnectionId = header.SourceConnectionId.ToArray(),
            HeaderLengthVarintWidth = HeaderLengthVarintWidthOf(coalesced.Packet.Span, header),
        };

        if (header.Type != TlsQuicLongPacketType.Initial)
        {
            // Handshake and 0-RTT keys come out of the TLS handshake, not out of the wire, so
            // an observer - this readout included - sees only the cleartext header. Everything
            // under the AEAD at those levels is genuinely unreadable here, which is the honest
            // half of the claim the two spec-sourced knobs rest on.
            return packet;
        }

        packet.TokenLength = header.Token.Length;
        packet.TokenPrefix = Convert.ToHexString(
            header.Token.Span[..Math.Min(TokenPrefixBytes, header.Token.Length)]);

        Open(packet, coalesced.Packet, header, headerProtectionKey, key, iv);
        return packet;
    }

    /// <summary>The encoded width of the long header's Length varint, located from the
    /// header's own layout rather than from any constant.</summary>
    /// <remarks>RFC 9000 s16 line 44, verbatim: "Values do not need to be encoded on the
    /// minimum number of bytes necessary, with the sole exception of the Frame Type field."
    /// That sentence is what makes this width a sender choice and therefore a fingerprint
    /// field (A4 Finding 5). s16 Table 4 puts the width in the varint's leading two bits.
    /// <para>THE EQUALITY AGAINST <see cref="TlsQuicLongHeader.PacketNumberOffset"/> IS A
    /// CROSS-CHECK BETWEEN TWO INDEPENDENT WALKS OF THE SAME HEADER - the parser's and this
    /// one - and it is DELIBERATELY UNTESTED. No in-contract input can break it: these
    /// datagrams are ones a client emitted, so the only long header types present are those
    /// <see cref="TlsQuicPacketHeader.TryReadLongHeader"/> gives a packet number, and both
    /// walks then derive their offsets from the same parsed field lengths. It is reachable
    /// only by a future edit to one walk and not the other - which is what it is for - or by
    /// a Retry packet, which RFC 9000 s17.2.5 makes server-sent and therefore out of contract
    /// here. A test would have to feed that out-of-contract packet, and would then stand as a
    /// witness for something this check does not exist to do. Classification: UNREACHABLE BY
    /// CONSTRUCTION, no test written.</para>
    /// </remarks>
    private static int HeaderLengthVarintWidthOf(
        ReadOnlySpan<byte> packet, in TlsQuicLongHeader header)
    {
        // RFC 9000 s17.2: first byte, 4-byte Version, then each connection ID behind its own
        // one-byte length. s17.2.2 then adds Token Length and Token, for Initial only.
        var offset = 1 + 4
            + 1 + header.DestinationConnectionId.Length
            + 1 + header.SourceConnectionId.Length;
        if (header.Type == TlsQuicLongPacketType.Initial)
        {
            offset += VarintWidthAt(packet, offset) + header.Token.Length;
        }

        var width = VarintWidthAt(packet, offset);
        if (offset + width != header.PacketNumberOffset)
        {
            throw new InvalidOperationException(
                $"The Length varint was located at {offset} width {width}, which does not meet "
                + $"the parsed packet number offset {header.PacketNumberOffset}. A Retry packet "
                + "(RFC 9000 s17.2.5) has neither field and is not something this phase emits.");
        }

        return width;
    }

    /// <summary>RFC 9000 s16 Table 4: a varint's leading two bits give its length in bytes -
    /// 00 one, 01 two, 10 four, 11 eight.</summary>
    private static int VarintWidthAt(ReadOnlySpan<byte> bytes, int offset) =>
        1 << (bytes[offset] >> 6);

    private static void Open(
        PacketReadout readout,
        ReadOnlyMemory<byte> packetMemory,
        in TlsQuicLongHeader header,
        byte[] headerProtectionKey,
        byte[] key,
        byte[] iv)
    {
        // A copy, because removing header protection writes back over the protected bytes and
        // the caller's recording must stay exactly as it was emitted.
        var packet = packetMemory.ToArray();

        if (!TlsQuicHeaderProtection.TryRemove(
            TlsQuicHeaderProtectionCipher.Aes,
            headerProtectionKey,
            packet,
            header.PacketNumberOffset,
            out var packetNumberLength))
        {
            throw new InvalidOperationException(
                "Header protection would not come off an Initial packet we emitted.");
        }

        var headerLength = header.PacketNumberOffset + packetNumberLength;
        var ciphertext = packet.AsSpan(headerLength, (int)header.Length - packetNumberLength);
        var plaintext = new byte[ciphertext.Length - AeadTagLength];

        var packetNumber = 0UL;
        for (var i = 0; i < packetNumberLength; i++)
        {
            packetNumber = (packetNumber << 8) | packet[header.PacketNumberOffset + i];
        }

        // RFC 9001 s5.3 xors the FULL packet number into the nonce, so this open succeeding is
        // the proof that the truncated field above reconstructs to the full number. A sender
        // whose InitialPacketNumber does not fit its own encoded length fails here rather than
        // being reported wrong.
        if (!TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.AesGcm,
            key,
            iv,
            packetNumber,
            packet.AsSpan(0, headerLength),
            ciphertext,
            plaintext))
        {
            throw new InvalidOperationException(
                "An Initial packet we emitted did not open under the keys RFC 9001 s5.2 derives "
                + "from its own Destination Connection ID.");
        }

        readout.Opened = true;
        readout.PacketNumber = packetNumber;
        readout.PacketNumberEncodedLength = packetNumberLength;
        ReadFrames(readout, plaintext);
    }

    private static void ReadFrames(PacketReadout readout, byte[] plaintext)
    {
        var offset = 0;
        while (offset < plaintext.Length)
        {
            var frameStart = offset;
            if (!TlsQuicFrames.TryReadFrame(plaintext, ref offset, out var frame, out var error))
            {
                throw new InvalidOperationException(
                    $"A frame we emitted did not parse back at offset {frameStart}: {error}.");
            }

            readout.Frames.Add(frame.Type);
            if (frame.Type == TlsQuicFrameType.Padding)
            {
                readout.PaddingBytes += offset - frameStart;
            }

            if (frame.Type != TlsQuicFrameType.Crypto)
            {
                continue;
            }

            // RFC 9000 s19.6: type varint, then Offset, then Length. THE TYPE'S OWN WIDTH IS
            // MEASURED RATHER THAN ASSUMED TO BE ONE. s12.4 makes the shortest encoding a
            // SENDER's MUST and leaves the receiver a MAY, and TlsQuicFrames' reader declines
            // that MAY on purpose - see its remarks: it "resolves the frame type by decoded
            // value and never looks at how many bytes carried it". So a frame this walk accepts
            // may carry an over-long type, and reading the Offset varint at frameStart + 1
            // would then sample an interior Offset byte and report a width that is simply
            // wrong, silently. Our own writer is minimal, so this arithmetic is an identity
            // today; it stops being one the moment a recording from elsewhere is read.
            var typeWidth = VarintWidthAt(plaintext, frameStart);
            var offsetWidth = VarintWidthAt(plaintext, frameStart + typeWidth);
            readout.CryptoOffsetVarintWidths.Add(offsetWidth);
            readout.CryptoLengthVarintWidths.Add(
                VarintWidthAt(plaintext, frameStart + typeWidth + offsetWidth));
            readout.CryptoChunks.Add((frame.Offset, frame.Data.ToArray()));
        }
    }

    // ---- the TLS layer, still from the same bytes ------------------------------------------

    /// <summary>Concatenates the CRYPTO chunks of the Initial flight into the ClientHello, or
    /// returns null when the recording does not hold a contiguous stream from offset zero.
    /// </summary>
    private static byte[]? ReassembleClientHello(IEnumerable<PacketReadout> initialFlight)
    {
        var chunks = initialFlight
            .SelectMany(packet => packet.CryptoChunks)
            .OrderBy(chunk => chunk.Offset)
            .ToList();

        var stream = new List<byte>();
        foreach (var (chunkOffset, data) in chunks)
        {
            if (chunkOffset != (ulong)stream.Count)
            {
                return null;
            }

            stream.AddRange(data);
        }

        // RFC 8446 s4: handshake type, then a 3-byte length. A stream shorter than the message
        // it declares is a flight this recording only saw part of, not a defect.
        if (stream.Count < 4 || stream[0] != ClientHelloHandshakeType)
        {
            return null;
        }

        var declared = (stream[1] << 16) | (stream[2] << 8) | stream[3];
        return stream.Count < 4 + declared ? null : stream.ToArray();
    }

    /// <summary>Finds RFC 9001 s8.2's extension inside a ClientHello and parses its body, or
    /// returns null when the extension is absent.</summary>
    /// <remarks>EVERY READ HERE IS BOUNDS-CHECKED, and the reason is that this type's contract
    /// is a comment rather than a type: <see cref="Describe"/> is <c>internal</c> and its
    /// signature accepts any <see cref="IReadOnlyList{T}"/> of datagrams, so a reassembled
    /// stream that passes the handshake-type and declared-length checks above and is still not
    /// a ClientHello reaches this walk. The type's remarks promise an
    /// <see cref="InvalidOperationException"/> on input it cannot parse; an unchecked index
    /// would deliver <see cref="IndexOutOfRangeException"/> instead, which is a different
    /// promise. Handling the input the signature actually accepts was chosen over narrowing the
    /// signature, because the narrowing C# offers - a distinct recording type - would buy
    /// nothing this check does not.</remarks>
    private static TlsQuicTransportParameters? ReadTransportParameters(byte[] clientHello)
    {
        // RFC 8446 s4.1.2 ClientHello, field by field: handshake header (4), legacy_version
        // (2), random (32), legacy_session_id (1 + n), cipher_suites (2 + n),
        // legacy_compression_methods (1 + n), extensions (2 + n).
        var offset = 4 + 2 + 32;
        Need(offset + 1);
        offset += 1 + clientHello[offset];
        Need(offset + 2);
        offset += 2 + ((clientHello[offset] << 8) | clientHello[offset + 1]);
        Need(offset + 1);
        offset += 1 + clientHello[offset];

        Need(offset + 2);
        var extensionsEnd = offset + 2 + ((clientHello[offset] << 8) | clientHello[offset + 1]);
        Need(extensionsEnd);
        offset += 2;

        while (offset + 4 <= extensionsEnd)
        {
            var type = (ushort)((clientHello[offset] << 8) | clientHello[offset + 1]);
            var length = (clientHello[offset + 2] << 8) | clientHello[offset + 3];
            offset += 4;
            if (offset + length > extensionsEnd)
            {
                throw new InvalidOperationException(
                    $"Extension {type} declares {length} bytes, which runs past the end of the "
                    + $"extensions block at {extensionsEnd}.");
            }

            if (type == QuicTransportParametersExtension)
            {
                return TlsQuicTransportParameters.Parse(
                    clientHello.AsSpan(offset, length));
            }

            offset += length;
        }

        return null;

        void Need(int end)
        {
            if (end > clientHello.Length)
            {
                throw new InvalidOperationException(
                    $"A reassembled ClientHello of {clientHello.Length} bytes does not reach "
                    + $"offset {end}, so it is not the RFC 8446 s4.1.2 message it declares.");
            }
        }
    }

    // ---- rendering ---------------------------------------------------------------------

    private static string Render(List<DatagramReadout> datagrams, TlsQuicConnectionSpec spec)
    {
        // THE INITIAL FLIGHT IS DEFINED BY WHAT THE BYTES SAY, not by a datagram count handed
        // in: it is the leading run of datagrams every packet of which is Initial. The first
        // datagram carrying a Handshake packet ends it, and RFC 9000 s12.2 lets that same
        // datagram still carry an Initial packet - which is why "contains an Initial packet"
        // would be the wrong test and "contains only Initial packets" is the right one.
        var flight = datagrams
            .TakeWhile(datagram => datagram.Packets.All(packet => packet.Kind == "Initial"))
            .ToList();
        var flightPackets = flight.SelectMany(datagram => datagram.Packets).ToList();
        var firstInitial = datagrams[0].Packets[0];

        var clientHello = ReassembleClientHello(flightPackets);
        var parameters = clientHello is null ? null : ReadTransportParameters(clientHello);

        var text = new StringBuilder();
        text.Append(Preamble);

        text.Append("\"quic\": {\n");
        Field(text, "client_connection_id_length", firstInitial.SourceConnectionId.Length);
        Field(text, "server_connection_id_length", firstInitial.DestinationConnectionIdLength);
        Field(text, "initial_packet_number", firstInitial.PacketNumber);
        Field(text, "initial_packet_number_encoded_length",
            firstInitial.PacketNumberEncodedLength);
        Field(text, "token_length", firstInitial.TokenLength);
        Field(text, "token_prefix", Quote(firstInitial.TokenPrefix));
        Field(text, "initial_flight_datagram_count", flight.Count);
        Field(text, "initial_flight_datagram_sizes",
            List(flight.Select(datagram => datagram.Bytes.ToString(CultureInfo.InvariantCulture))));
        Field(text, "initial_flight_packets_per_datagram",
            List(flight.Select(datagram =>
                datagram.Packets.Count.ToString(CultureInfo.InvariantCulture))));
        Field(text, "initial_flight_crypto_frames_per_datagram",
            List(flight.Select(datagram => datagram.Packets
                .Sum(packet => packet.CryptoChunks.Count)
                .ToString(CultureInfo.InvariantCulture))));
        Field(text, "initial_crypto_frame_byte_counts",
            List(flightPackets.SelectMany(packet => packet.CryptoChunks)
                .Select(chunk => chunk.Data.Length.ToString(CultureInfo.InvariantCulture))));
        Field(text, "initial_frame_order",
            List(flightPackets.Select(packet => Quote(RunLength(packet.Frames)))));
        Field(text, "initial_padding_bytes",
            List(flightPackets.Select(packet =>
                packet.PaddingBytes.ToString(CultureInfo.InvariantCulture))));
        Field(text, "datagram_padding_target",
            Distinct(flight.Select(datagram => datagram.Bytes)));
        // SCOPE DIFFERS FROM THE TWO CRYPTO WIDTH FIELDS BELOW, deliberately and worth saying
        // because every field above this one is scoped to the Initial FLIGHT. The long header's
        // Length varint is cleartext at every level, so the honest scope for it is the WHOLE
        // recording; the CRYPTO widths sit under Initial keys and can only be scoped to the
        // flight. That is why the snapshot's default profile reads [2, 1] here - the 1 comes
        // from datagram 1's short Initial, outside the flight - while the crypto rows read a
        // single width each.
        Field(text, "header_length_varint_widths_whole_recording",
            Distinct(datagrams
                .SelectMany(datagram => datagram.Packets)
                .Where(packet => packet.HeaderLengthVarintWidth > 0)
                .Select(packet => packet.HeaderLengthVarintWidth)));
        Field(text, "crypto_offset_varint_widths",
            Distinct(flightPackets.SelectMany(packet => packet.CryptoOffsetVarintWidths)));
        Field(text, "crypto_length_varint_widths",
            Distinct(flightPackets.SelectMany(packet => packet.CryptoLengthVarintWidths)));
        Field(text, "transport_parameters_wire_order",
            parameters is null
                ? Quote(NotRecoverable)
                : List(parameters.Parameters.Select(parameter =>
                    parameter.Id.ToString(CultureInfo.InvariantCulture))));
        Field(text, "initial_rtt_parameter_present",
            parameters is null
                ? Quote(NotRecoverable)
                : Bool(parameters.Get(
                    TlsQuicTransportParameterSpec.InitialRttIdentifier) is not null));
        Field(text, "initial_source_connection_id_equals_header_source",
            InitialSourceConnectionIdVerdict(parameters, firstInitial), last: true);
        text.Append("}\n\n");

        RenderPerkSegment3(text, parameters);
        RenderRecording(text, datagrams);
        RenderSpecSourced(text, spec, datagrams);
        text.Append(Deviations);
        return text.ToString();
    }

    // ---- perk segment 3 ---------------------------------------------------------------

    // One rendered row. The verdict is one of TlsQuicHttp3FingerprintReadout's three constants
    // and nothing else - REUSED rather than redeclared, because two files holding their own
    // copy of the string "MISMATCH" is how the two readouts start disagreeing about what a
    // verdict is, and because C12's column is the one this table follows.
    private sealed record PerkRow(string Parameter, string Ours, string Brave, string Verdict);

    /// <summary>Renders <c>perk</c> segment 3 - the QUIC transport parameters in wire order -
    /// from the parameters parsed back out of the ClientHello this recording carried.</summary>
    /// <remarks>
    /// <para>THE ENCODED CLIENTHELLO IS THE SOURCE, AND IT IS THE RIGHT ONE OF THE TWO
    /// CANDIDATES. <paramref name="parameters"/> reaches here from
    /// <see cref="ReadTransportParameters"/>, which finds RFC 9001 s8.2's extension inside a
    /// ClientHello reassembled from the CRYPTO frames of AEAD-verified Initial packets this
    /// connection emitted. The other candidate was
    /// <c>TlsQuicTransportParameterSpec.Compose</c>'s returned
    /// <see cref="TlsQuicTransportParameters"/>, and it was rejected: composing is what the
    /// ClientHello is built FROM, so a readout of it would restate the input and would still
    /// print fourteen parameters for a connection whose extension 57 never reached the wire.
    /// The bytes read here crossed a packet builder, a header protection mask and an AEAD seal
    /// before this type opened them again.</para>
    /// <para>NO ROW IS RENDERED WHEN THE CLIENTHELLO IS NOT RECOVERABLE. A MISMATCH scored
    /// against bytes nobody read is a deviation claimed on no evidence, which is exactly what
    /// <c>initial_rtt_parameter_present</c> refuses two fields above by saying
    /// not-recoverable instead of false.</para>
    /// </remarks>
    private static void RenderPerkSegment3(
        StringBuilder text, TlsQuicTransportParameters? parameters)
    {
        text.Append(PerkSegment3Preamble);
        if (parameters is null)
        {
            text.Append(
                "  This recording does not yield the ClientHello, so nothing about segment 3\n"
                + "  is measurable from it and no row is rendered. A row scored against bytes\n"
                + "  that were never read would be a deviation claimed on no evidence.\n\n");
            return;
        }

        var ours = parameters.Parameters.Select(PerkToken).ToList();
        var segment = string.Join(PerkSeparator, ours);
        RenderSegmentDiff(text, segment);

        var rows = new List<PerkRow>();
        // The capture's fourteen, each scored AT ITS INDEX. A membership test would pass
        // against a readout that sorted the list, and commit 4ed90bf measured that the live
        // service hashes the order.
        for (var index = 0; index < CaptureTokens.Length; index++)
        {
            var token = index < ours.Count ? ours[index] : AbsentToken;
            rows.Add(new PerkRow(
                CaptureParameterNames[index],
                token,
                CaptureTokens[index],
                Verdict(token == CaptureTokens[index])));
        }

        rows.Add(new PerkRow(
            "perk segment 3, the whole string",
            segment.Length == 0 ? AbsentToken : segment,
            CaptureSegment3,
            Verdict(segment == CaptureSegment3)));

        // TASK B6's REMOVAL, PINNED FROM THE OTHER SIDE. B6 took active_connection_id_limit
        // out of the preset because RFC 9000 s18.2 makes absent and present-at-2 the same
        // advertisement; nothing in a row-by-row comparison against the capture's fourteen
        // notices a FIFTEENTH parameter reappearing beside them, so this row counts what we
        // send that the capture does not name at all.
        var extra = ours.Where(token => !CaptureIdentifiers.Contains(IdentifierPartOf(token)))
            .ToList();
        rows.Add(new PerkRow(
            "parameters emitted that the capture does not list",
            extra.Count == 0 ? "none" : string.Join(PerkSeparator, extra),
            "none",
            Verdict(extra.Count == 0)));

        // ---- the third column, and it has exactly two members --------------------------
        //
        // WHAT IS AND IS NOT IN IT. The capture settles the fourteen identifiers, the wire
        // order and the four values it publishes outright AFFIRMATIVELY, so none of those may
        // sit here. The GREASE version inside version_information is NOT here either: RFC
        // 9368 s3 bounds it to the pattern 0x?a?a?a?a exactly, so row 9's GREASE token is
        // produced by recomputing that predicate over the emitted bytes and is verifiable
        // rather than unknown. What remains is two WIDTHS that only a packet capture can
        // bound - task B12 - and both are rendered from the draw this connection actually
        // made, so the row measures something even while its verdict says the target does
        // not.
        var initialRtt = parameters.Get(TlsQuicTransportParameterSpec.InitialRttIdentifier);
        rows.Add(new PerkRow(
            "initial_rtt (12583) draw - the RANGE it is drawn from is unverified, task B12",
            initialRtt is null ? AbsentToken : IntegerOrHex(initialRtt.ValueSpan),
            CaptureInitialRttCell,
            TlsQuicHttp3FingerprintReadout.NotYetKnown));

        var reserved = parameters.Parameters.FirstOrDefault(parameter =>
            TlsQuicTransportParameterSpec.IsReservedIdentifier(parameter.Id));
        rows.Add(new PerkRow(
            "reserved parameter's N in s18.1's 31 * N + 27 - unverified, task B12",
            reserved is null
                ? AbsentToken
                : ReservedIdentifierN(reserved.Id).ToString(CultureInfo.InvariantCulture),
            CaptureReservedIdentifierCell,
            TlsQuicHttp3FingerprintReadout.NotYetKnown));

        RenderPerkTable(text, rows);
        RenderPerkCounts(text, rows);
        text.Append(PerkSegment3Notes);
    }

    /// <summary>Renders one emitted parameter the way impersonate.pro's <c>perk</c> string
    /// renders it, so that a token comparison is a comparison against the capture's own
    /// rendering rather than against a re-encoding of it.</summary>
    /// <remarks>THE TWO TOKENISED KINDS ARE RECOMPUTED, NOT ASSUMED. A reserved identifier
    /// becomes <see cref="GreaseToken"/> only when
    /// <see cref="TlsQuicTransportParameterSpec.IsReservedIdentifier(ulong)"/> says the
    /// emitted identifier has RFC 9000 s18.1's form, and a reserved version only when
    /// <see cref="TlsQuicTransportParameterSpec.IsReservedVersion(uint)"/> says the emitted
    /// version has RFC 9368 s3's. An identifier that merely sits where a GREASE one should
    /// renders as its own number and its row fails.</remarks>
    private static string PerkToken(TlsQuicTransportParameter parameter)
    {
        if (TlsQuicTransportParameterSpec.IsReservedIdentifier(parameter.Id))
        {
            return GreaseToken;
        }

        var id = parameter.Id.ToString(CultureInfo.InvariantCulture);
        // Capture lines 98-99 name these two and only these two.
        if (parameter.Id == InitialSourceConnectionIdParameterId
            || parameter.Id == TlsQuicTransportParameterSpec.InitialRttIdentifier)
        {
            return $"{id}{PerkValueSeparator}{AutoToken}";
        }

        if (parameter.Id == (ulong)TlsQuicTransportParameterId.VersionInformation)
        {
            return $"{id}{PerkValueSeparator}{VersionInformationToken(parameter.ValueSpan)}";
        }

        // NO SPECIAL CASE FOR 12584, AND NONE IS NEEDED. Capture line 79 renders its value as
        // hex, and the general rule below already does: 0x4f524947's leading byte declares a
        // two-byte varint, which does not cover the four bytes present, so IntegerOrHex falls
        // through to the bytes. A branch naming the identifier would be a second way to say
        // the same thing, and the two could disagree.
        return $"{id}{PerkValueSeparator}{IntegerOrHex(parameter.ValueSpan)}";
    }

    /// <summary>Renders a <c>version_information</c> body as the capture's
    /// <c>1@GREASE,1</c>.</summary>
    /// <remarks>RFC 9368 s3 Figure 2, rfc9368-section3-and-10.1-version-information.txt lines
    /// 35-38: a 32-bit Chosen Version, then the Available Versions as 32-bit words. A body
    /// that is not a whole number of them is not that structure, and is rendered as its bytes
    /// rather than mis-parsed - <see cref="TlsQuicTransportParameters.Parse"/> does not
    /// validate what it parses, so a foreign ClientHello can carry one.</remarks>
    private static string VersionInformationToken(ReadOnlySpan<byte> value)
    {
        if (value.Length < sizeof(uint) || value.Length % sizeof(uint) != 0)
        {
            return HexToken(value);
        }

        var available = new List<string>();
        for (var offset = sizeof(uint); offset < value.Length; offset += sizeof(uint))
        {
            var version = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(
                value[offset..]);
            available.Add(TlsQuicTransportParameterSpec.IsReservedVersion(version)
                ? GreaseToken
                : version.ToString(CultureInfo.InvariantCulture));
        }

        var chosen = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(value);
        return $"{chosen.ToString(CultureInfo.InvariantCulture)}@{string.Join(',', available)}";
    }

    /// <summary>Renders a parameter body as the integer it holds, or as its bytes when it is
    /// not one whole RFC 9000 s16 variable-length integer.</summary>
    private static string IntegerOrHex(ReadOnlySpan<byte> value)
    {
        var offset = 0;
        return QuicVariableLengthInteger.TryRead(value, ref offset, out var parsed)
            && offset == value.Length
                ? parsed.ToString(CultureInfo.InvariantCulture)
                : HexToken(value);
    }

    /// <summary>Renders bytes the way capture line 79 renders 12584's value.</summary>
    private static string HexToken(ReadOnlySpan<byte> value) =>
        $"0x{Convert.ToHexString(value).ToLowerInvariant()}";

    /// <summary>Solves RFC 9000 s18.1's <c>31 * N + 27</c> for N, so the row reports the draw
    /// this connection made rather than the identifier it made it into.</summary>
    private static ulong ReservedIdentifierN(ulong identifier) =>
        (identifier - TlsQuicTransportParameterSpec.ReservedIdentifierBase)
            / TlsQuicTransportParameterSpec.ReservedIdentifierStep;

    /// <summary>A token's identifier half - everything before the first
    /// <see cref="PerkValueSeparator"/>, which leaves the bare <see cref="GreaseToken"/>
    /// whole.</summary>
    private static string IdentifierPartOf(string token)
    {
        var separator = token.IndexOf(PerkValueSeparator, StringComparison.Ordinal);
        return separator < 0 ? token : token[..separator];
    }

    /// <summary>The identifier halves of the capture's fourteen tokens, derived from
    /// <see cref="CaptureTokens"/> so that no identifier is typed into this file twice.
    /// </summary>
    private static readonly HashSet<string> CaptureIdentifiers =
        [.. CaptureTokens.Select(IdentifierPartOf)];

    private static string Verdict(bool matches) => matches
        ? TlsQuicHttp3FingerprintReadout.Match
        : TlsQuicHttp3FingerprintReadout.Mismatch;

    /// <summary>Diffs our whole segment against the capture's, character by character.
    /// </summary>
    private static void RenderSegmentDiff(StringBuilder text, string ours)
    {
        text.Append("    ours   ").Append(ours).Append('\n')
            .Append("    brave  ").Append(CaptureSegment3).Append('\n');

        var index = 0;
        while (index < ours.Length
            && index < CaptureSegment3.Length
            && ours[index] == CaptureSegment3[index])
        {
            index++;
        }

        if (index == ours.Length && index == CaptureSegment3.Length)
        {
            text.Append("    identical\n\n");
            return;
        }

        text.Append("    first difference at index ")
            .Append(index.ToString(CultureInfo.InvariantCulture))
            .Append(": ours ")
            .Append(index < ours.Length ? $"'{ours[index]}'" : "<end>")
            .Append(", brave ")
            .Append(index < CaptureSegment3.Length ? $"'{CaptureSegment3[index]}'" : "<end>")
            .Append("\n\n");
    }

    private static void RenderPerkTable(StringBuilder text, List<PerkRow> rows)
    {
        text.Append("| # | parameter | ours | brave | verdict |\n")
            .Append("| --- | --- | --- | --- | --- |\n");
        for (var index = 0; index < rows.Count; index++)
        {
            var row = rows[index];
            text.Append("| ")
                .Append((index + 1).ToString(CultureInfo.InvariantCulture))
                .Append(" | ").Append(row.Parameter)
                .Append(" | ").Append(row.Ours)
                .Append(" | ").Append(row.Brave)
                .Append(" | ").Append(row.Verdict)
                .Append(" |\n");
        }

        text.Append('\n');
    }

    private static void RenderPerkCounts(StringBuilder text, List<PerkRow> rows)
    {
        // COUNTED FROM THE RENDERED LIST, never written beside it - C12's rule, so a row
        // added here cannot leave the arithmetic behind.
        var match = rows.Count(row => row.Verdict == TlsQuicHttp3FingerprintReadout.Match);
        var mismatch = rows.Count(row => row.Verdict == TlsQuicHttp3FingerprintReadout.Mismatch);
        var unknown = rows.Count(row => row.Verdict == TlsQuicHttp3FingerprintReadout.NotYetKnown);
        text.Append("## perk segment 3 verdict counts, derived from the rows above\n\n")
            .Append("    rows                            ")
            .Append(rows.Count.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("    match                           ")
            .Append(match.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("    MISMATCH                        ")
            .Append(mismatch.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("    not-yet-known-from-the-capture  ")
            .Append(unknown.ToString(CultureInfo.InvariantCulture)).Append('\n')
            .Append("    ")
            .Append(match.ToString(CultureInfo.InvariantCulture)).Append(" + ")
            .Append(mismatch.ToString(CultureInfo.InvariantCulture)).Append(" + ")
            .Append(unknown.ToString(CultureInfo.InvariantCulture)).Append(" = ")
            .Append((match + mismatch + unknown).ToString(CultureInfo.InvariantCulture))
            .Append("\n\n");
    }

    private static void RenderRecording(StringBuilder text, List<DatagramReadout> datagrams)
    {
        text.Append(
            "## The whole recording, datagram by datagram (measured)\n\n"
            + "Each row is one emitted datagram: its size, then every packet coalesced into it\n"
            + "in wire order. RFC 9000 s17.2's long header type is cleartext, so the ORDER of\n"
            + "levels within a datagram is measurable here even where the payloads are not.\n\n");
        foreach (var datagram in datagrams)
        {
            text.Append(CultureInfo.InvariantCulture,
                $"  datagram {datagram.Index}: {datagram.Bytes} bytes | ");
            text.Append(string.Join(
                " + ",
                datagram.Packets.Select(packet => packet.Opened
                    ? $"{packet.Kind}(pn={packet.PacketNumber},pnlen={packet.PacketNumberEncodedLength},"
                        + $"frames={RunLength(packet.Frames)})"
                    : $"{packet.Kind}({packet.Bytes} bytes, sealed - no keys on the wire)")));
            text.Append('\n');
        }

        text.Append('\n');
    }

    private static void RenderSpecSourced(
        StringBuilder text, TlsQuicConnectionSpec spec, List<DatagramReadout> datagrams)
    {
        // Corroboration, stated only where the recording can carry it. A datagram holding one
        // encryption level says nothing about a coalescing ORDER, and a packet holding one
        // frame says nothing about where an ACK would sit; printing "agrees" in either case
        // would be a witness that cannot fail.
        var multiLevelDatagrams = datagrams
            .Count(datagram => datagram.Packets.Select(packet => packet.Kind).Distinct().Count() > 1);
        var ackPacketsWithCompany = datagrams
            .SelectMany(datagram => datagram.Packets)
            .Count(packet => packet.Opened
                && packet.Frames.Contains(TlsQuicFrameType.Ack)
                && packet.Frames.Any(frame =>
                    frame is not TlsQuicFrameType.Ack and not TlsQuicFrameType.Padding));

        text.Append(
            "## SPEC-SOURCED, not measured - the two order knobs\n\n"
            + "Both sit under the AEAD at levels whose keys never appear on the wire, so a\n"
            + "recording cannot always settle them. They are read from the TlsQuicConnectionSpec\n"
            + "the connection was built with, and that is the only reason they are outside the\n"
            + "block above. Neither has ground truth in the Brave capture.\n\n");
        text.Append(CultureInfo.InvariantCulture,
            $"  spec.CoalesceAscendingByLevel = {Bool(spec.CoalesceAscendingByLevel)}\n");
        text.Append(CultureInfo.InvariantCulture,
            $"  spec.AckLeadsInPacket         = {Bool(spec.AckLeadsInPacket)}\n\n");
        text.Append(CultureInfo.InvariantCulture,
            $"  corroborating datagrams carrying more than one encryption level: {multiLevelDatagrams}\n");
        text.Append(CultureInfo.InvariantCulture,
            $"  corroborating opened packets carrying an ACK beside another frame: {ackPacketsWithCompany}\n");
        text.Append(
            "  A zero on either line means this recording is SILENT about that knob, not that\n"
            + "  it agrees with it. Read the datagram rows above for the levels it does show.\n\n");
    }

    private static string InitialSourceConnectionIdVerdict(
        TlsQuicTransportParameters? parameters, PacketReadout firstInitial)
    {
        if (parameters is null)
        {
            return Quote(NotRecoverable);
        }

        var parameter = parameters.Get(InitialSourceConnectionIdParameterId);
        if (parameter is null)
        {
            return Quote(AbsentToken);
        }

        // UNOBSERVABLE AT THE TARGET'S OWN SHAPE. Chromium's source connection ID is zero
        // bytes, so at the target profile both sides of this comparison are empty and it holds
        // for a connection that never took the header's value from anywhere - which is why the
        // tests behind this readout advertise a five-byte one instead.
        // BY VALUE. RFC 9000 s7.3: "An endpoint MUST treat [...] absence of the
        // initial_source_connection_id transport parameter [...] as a connection error", and the
        // requirement it states is that the parameter's VALUE equal the Source Connection ID
        // field of the packet. A length-only test would print agreement for five bytes that
        // agree about nothing, which is the witness-that-cannot-fail this file's own remark at
        // RenderSpecSourced forbids - so the verdict words say value, not length.
        return firstInitial.SourceConnectionId.Length == 0
            ? Quote("unobservable-at-zero-length-source-cid")
            : Quote(parameter.ValueSpan.SequenceEqual(firstInitial.SourceConnectionId)
                ? "same-value"
                : "different-value");
    }

    // ---- text helpers ------------------------------------------------------------------

    private static void Field(StringBuilder text, string name, int value, bool last = false) =>
        Field(text, name, value.ToString(CultureInfo.InvariantCulture), last);

    private static void Field(StringBuilder text, string name, ulong value, bool last = false) =>
        Field(text, name, value.ToString(CultureInfo.InvariantCulture), last);

    private static void Field(StringBuilder text, string name, string value, bool last = false)
    {
        text.Append(CultureInfo.InvariantCulture, $"  \"{name}\": {value}");
        text.Append(last ? "\n" : ",\n");
    }

    private static string Quote(string value) => $"\"{value}\"";

    private static string Bool(bool value) => value ? "true" : "false";

    private static string List(IEnumerable<string> values) => $"[{string.Join(", ", values)}]";

    /// <summary>Renders the distinct values a field took across the recording, in first-seen
    /// order.</summary>
    /// <remarks>A single-element list is the interesting case and it still prints as a list:
    /// collapsing it to a scalar would make "every packet agreed" and "there was only one
    /// packet" print identically, and those are different claims.</remarks>
    private static string Distinct(IEnumerable<int> values) =>
        List(values.Distinct().Select(value => value.ToString(CultureInfo.InvariantCulture)));

    /// <summary>Run-length encodes a frame sequence, because a padded Initial packet holds
    /// hundreds of PADDING frames and the ORDER is the fingerprint, not the repetition.
    /// </summary>
    private static string RunLength(List<TlsQuicFrameType> frames)
    {
        var runs = new List<string>();
        var index = 0;
        while (index < frames.Count)
        {
            var run = 1;
            while (index + run < frames.Count && frames[index + run] == frames[index])
            {
                run++;
            }

            runs.Add(run == 1
                ? frames[index].ToString()
                : string.Create(CultureInfo.InvariantCulture, $"{frames[index]}x{run}"));
            index += run;
        }

        return string.Join(",", runs);
    }

    private const string Preamble =
        "# QUIC fingerprint readout - SNAPSHOT\n"
        + "\n"
        + "SNAPSHOT. Every number in the \"quic\" block below was produced by\n"
        + "TlsQuicFingerprintReadout from the datagrams this connection emitted, and NONE of it\n"
        + "has an external source. Per A2's standing rule, a checked-in number with no external\n"
        + "source is a snapshot and is labelled one: it pins what we do today, and it is evidence\n"
        + "about nothing else. The comparison against the Brave capture is hand-written and lives\n"
        + "in the task 11 report, not here.\n"
        + "\n"
        + "Shape follows the QUIC section of\n"
        + "docs/superpowers/specs/reference-captures/2026-08-16-brave-151-http3-impersonate-pro.md,\n"
        + "whose own block carries the first two fields and nothing else.\n"
        + "\n";

    private const string PerkSegment3Preamble =
        "## perk segment 3 - the QUIC transport parameters in wire order (measured)\n"
        + "\n"
        + "SNAPSHOT IN THE \"ours\" COLUMN, EXTERNAL SOURCE IN THE \"brave\" COLUMN. Every\n"
        + "\"ours\" cell was produced here from the transport parameters parsed back out of\n"
        + "the ClientHello these datagrams carried - reassembled from the CRYPTO frames of\n"
        + "Initial packets this type opened under keys RFC 9001 s5.2 derives from the wire -\n"
        + "so it has no external source and pins only what we do today. Every \"brave\" cell\n"
        + "is quoted from\n"
        + "docs/superpowers/specs/reference-captures/2026-08-16-brave-151-http3-impersonate-pro.md\n"
        + "and none of it is measured here.\n"
        + "\n";

    private const string PerkSegment3Notes =
        "### Notes on segment 3\n"
        + "\n"
        + "A MISMATCH HERE IS ABOUT THIS RECORDING'S CALLER, NOT ABOUT THIS LIBRARY, and\n"
        + "reading it the other way is the mistake subsystem B's Finding 1 is entirely about.\n"
        + "The rows score the ClientHello these datagrams carried, and whoever built that\n"
        + "ClientHello chose its transport parameters. A connection built through\n"
        + "TlsQuicClientHelloProfileFactory emits TlsQuicTransportParameterSpec's shipped\n"
        + "preset and reproduces the capture's fourteen exactly, which is asserted by\n"
        + "TlsQuicFingerprintReadoutTests.TheShippedPresetReproducesTheCapturesSegmentThree.\n"
        + "A connection whose caller hand-composed a shorter list emits the shorter list,\n"
        + "and this table says so.\n"
        + "\n"
        + "EVERY ROW IS SCORED AT ITS INDEX, NOT BY MEMBERSHIP. Capture line 74 says the\n"
        + "ordering is the fingerprint, and commit 4ed90bf measured it against the live\n"
        + "service 12/12: reordering the parameters moved perk_hash and left\n"
        + "perk_hash_normalized byte-identical. A set comparison would score a sorted list\n"
        + "as a match, and a sorted list is a different client.\n"
        + "\n"
        + "THREE ROWS ARE SCORED ON POSITION BECAUSE THE SERVICE DOES NOT HASH THEIR VALUES.\n"
        + "The perk string renders 12583 and 15 as AUTO (capture lines 98-99) and the\n"
        + "reserved parameter as the bare token GREASE, so their tokens carry an identifier\n"
        + "and no number; commit 4ed90bf confirmed it from the other side, by sending\n"
        + "initial_rtt at 100000 and at 900000 and moving neither hash. Those rows therefore\n"
        + "say \"an AUTO-rendered 12583 was emitted thirteenth\" and claim nothing about the\n"
        + "microseconds inside it. The same measurement found the service strips neither an\n"
        + "unknown identifier nor a zero-length value, so an emitted 12583 or 15 is a token\n"
        + "the service really does render rather than one it might drop.\n"
        + "\n"
        + "THE GREASE VERSION INSIDE version_information IS NOT IN THE THIRD COLUMN, and its\n"
        + "absence from it is a result rather than an oversight. RFC 9368 s3 bounds the form\n"
        + "exactly - \"versions following the pattern 0x?a?a?a?a\" - so row 9's GREASE token\n"
        + "is produced by recomputing that predicate over the four emitted bytes. A version\n"
        + "outside the pattern renders as its own number and the row fails. What the capture\n"
        + "leaves open is only WHICH member of a 16^4 set Chromium drew, and the perk string\n"
        + "tokenises that, so nothing about it is unknown here.\n"
        + "\n"
        + "THE TWO ROWS THAT ARE IN IT ARE BOTH WIDTHS, AND BOTH ARE TASK B12's. The capture\n"
        + "publishes one initial_rtt draw and five significant digits of one reserved\n"
        + "identifier; neither bounds the interval it came from, and only a packet capture\n"
        + "can. Both rows still render the draw THIS connection made, so they measure\n"
        + "something even while their verdict says the target does not settle it.\n"
        + "\n";

    private const string Deviations =
        "## Known deviations from the target, named rather than omitted\n\n"
        + "1. initial_rtt'S RANGE IS UNVERIFIED - THE PARAMETER ITSELF IS SENT. This entry used\n"
        + "   to say that nothing sent Google-private parameter 12583 at all, and that was true\n"
        + "   when it was written. Tasks B5 and B8 made it false: the preset in\n"
        + "   TlsQuicTransportParameterSpec carries a DrawnInitialRtt entry that redraws a\n"
        + "   microsecond value per connection, and B8's TlsQuicClientHelloProfileFactory is what\n"
        + "   puts the composed blob into the ClientHello - so a connection built through that\n"
        + "   factory emits 12583. TlsQuicConnectionSpec.InitialRttRange is still null by default,\n"
        + "   but a null now OVERRIDES nothing rather than suppressing the parameter: the preset\n"
        + "   entry's own fallback range is what it falls back to.\n"
        + "   WHAT REMAINS UNSETTLED IS THE RANGE AND NOT THE PRESENCE. The Brave capture holds\n"
        + "   exactly one draw (value 192859), which fixes neither bounds nor distribution, so the\n"
        + "   preset's interval is marked unverified where it is declared. Bounding it - by\n"
        + "   capturing enough connections, or by reading uQUIC's ChromeRandomInitialRTT() - is\n"
        + "   what changes this line. A connection NOT built through that factory still sends\n"
        + "   whatever its own caller typed, so transport_parameters_wire_order above stays the\n"
        + "   measurement and this paragraph stays prose.\n\n"
        + "2. A KNOWINGLY VIOLATED MUST: A4-minimal never acknowledges a 1-RTT packet, including\n"
        + "   the one carrying HANDSHAKE_DONE, because it cannot send a 1-RTT packet at all.\n"
        + "   RFC 9000 s13.2.1, whole sentence past its line wrap (extract lines 59-61): \"An\n"
        + "   endpoint MUST acknowledge all ack-eliciting Initial and Handshake packets\n"
        + "   immediately and all ack-eliciting 0-RTT and 1-RTT packets within its advertised\n"
        + "   max_ack_delay, with the following exception.\" One MUST, two conjuncts; 1-RTT is\n"
        + "   named and only its DEADLINE is relaxed. s13.2.1's exception covers an endpoint that\n"
        + "   \"might not have packet protection keys for decrypting Handshake, 0-RTT, or 1-RTT\n"
        + "   packets when they are received\" - we decrypted the packet, so it does not apply.\n"
        + "   A server will retransmit its HANDSHAKE_DONE unacknowledged. THIS IS A VIOLATION,\n"
        + "   not a soft deviation, and task 14 closes it.\n\n"
        + "3. AckDelayExponent IS WIRED AND VALIDATED BUT NOT OBSERVABLE. The connection loop\n"
        + "   reads the clock once per pump, so every ack_delay it reports is structurally zero\n"
        + "   and the exponent scales a zero - it moves no wire byte yet. RFC 9000 s13.2.5's\n"
        + "   reader subtracts the reported delay from its RTT sample, so under-reporting makes\n"
        + "   the peer's estimate more conservative, which is the safe direction and is taken\n"
        + "   deliberately. The connection fails loudly at construction if the scaled and\n"
        + "   advertised values disagree.\n\n"
        + "4. AckRangeLimit's DEFAULT OF 32 IS A PLACEHOLDER. The Brave capture says nothing\n"
        + "   about ACK ranges and no published vector does either, so it sits in the same\n"
        + "   not-yet-known-from-the-capture category as the initial packet number and the\n"
        + "   initial_rtt range. It is a real knob - it bounds bytes on the wire - but its value\n"
        + "   is not evidence about Chromium.\n\n"
        + "5. initial_source_connection_id FRESHNESS IS UNOBSERVABLE AT THE TARGET'S OWN SHAPE.\n"
        + "   Chromium's source connection ID is zero bytes, which erases the header field that\n"
        + "   would witness the parameter agreeing with it. The connections behind this readout\n"
        + "   advertise a five-byte one so the agreement is witnessable at all; the field above\n"
        + "   says so rather than claiming a witness the target's shape removes.\n";

    // ---- the parsed recording ------------------------------------------------------------

    private sealed class DatagramReadout
    {
        internal int Index { get; init; }

        internal int Bytes { get; init; }

        internal List<PacketReadout> Packets { get; } = [];
    }

    private sealed class PacketReadout
    {
        internal string Kind { get; init; } = "";

        internal int Bytes { get; init; }

        internal int DestinationConnectionIdLength { get; init; }

        internal byte[] SourceConnectionId { get; init; } = [];

        internal int HeaderLengthVarintWidth { get; init; }

        internal int TokenLength { get; set; }

        internal string TokenPrefix { get; set; } = "";

        internal bool Opened { get; set; }

        internal ulong PacketNumber { get; set; }

        internal int PacketNumberEncodedLength { get; set; }

        internal List<TlsQuicFrameType> Frames { get; } = [];

        internal int PaddingBytes { get; set; }

        internal List<int> CryptoOffsetVarintWidths { get; } = [];

        internal List<int> CryptoLengthVarintWidths { get; } = [];

        internal List<(ulong Offset, byte[] Data)> CryptoChunks { get; } = [];
    }
}
