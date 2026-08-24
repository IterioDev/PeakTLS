using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using SharpTls.Protocol;

namespace SharpTls.Quic;

/// <summary>
/// Reads the fingerprint-bearing HTTP/3 choices back out of the QUIC STREAM frames a connection
/// actually emitted, and renders them one row per field with a verdict against
/// <c>docs/superpowers/specs/reference-captures/2026-08-16-brave-151-http3-impersonate-pro.md</c>.
/// </summary>
/// <remarks>
/// <para>THE THIRD COLUMN IS THE PRODUCT. Task 11 established that a readout's most valuable
/// output is the list of rows the capture cannot settle, because that list is the shopping list
/// subsystem B takes to a packet capture. <c>match</c> and <c>MISMATCH</c> are work items;
/// <c>not-yet-known-from-the-capture</c> is a measurement nobody has taken yet, and the two must
/// never be confused - a placeholder scored as a match is a lie about Chromium.</para>
/// <para>NO <c>TlsQuicHttp3Spec</c> REACHES THIS TYPE. Task 11's readout took a spec for two
/// fields it could not measure and needed
/// <c>TlsQuicFingerprintReadoutTests.TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith</c> to
/// prove the rest were not restatements. This one takes no spec at all, so segments 1 and 2
/// CANNOT be restatements: there is no parameter to restate from. The signature is the witness
/// and the test is the corroboration, not the other way round.</para>
/// </remarks>
// Task C12: the HTTP/3 fingerprint readout.
//
// ============================================================================
// WHAT IS MEASURED HERE, AND WHAT IS NOT.
// ============================================================================
//
//   MEASURED, from `emittedStreamFrames` - the QUIC STREAM frames the connection put on the
//   wire, reassembled per stream in emission order:
//
//     perk segment 1  the h3 SETTINGS pairs and their wire order, off the control stream's
//                     first frame
//     perk segment 2  the pseudo-header order, off the request stream's HEADERS frame
//     s4.2.2          both halves, one from the SETTINGS we advertised and one from the
//                     emitted field section decoded back
//     the four        unidirectional stream open order, Huffman policy, QPACK representation
//     placeholders    choice, and the reserved-frame triple
//
//   NOT MEASURED HERE, and said so in every row that carries it: perk segments 3 and 4. The
//   transport parameters and the connection ID lengths live in the ClientHello, under RFC 9001
//   s5.2's Initial keys, and TlsQuicFingerprintReadout ALREADY reads them off the emitted
//   datagrams. A second copy of that reader in this file would be a second transcription of
//   RFC 8446 s4.1.2's ClientHello walk, which the standing rules forbid, so the parameters are
//   handed in and the rows say where they came from.
//
// ============================================================================
// A ROW SAYS WHAT THAT RECORDING DID, NOT WHAT THE PROJECT DOES.
// ============================================================================
//
//   Rendered against `new TlsQuicHttp3Spec()` this readout scores segment 1 an EXACT match,
//   because TlsQuicHttp3Spec's default Settings IS the capture's five pairs - 51:1 and the
//   reserved pair included. Rendered against the spec the live run of 2026-08-20 used, the
//   same code scores three MISMATCHes, because that run advertised
//   SETTINGS_QPACK_MAX_TABLE_CAPACITY 0 and SETTINGS_QPACK_BLOCKED_STREAMS 0 - C5-C8's decoder
//   is static-only and 65536 would advertise a dynamic table nothing can fill.
//
//   BOTH RENDERS ARE CORRECT AND THEY ARE NOT ABOUT THE SAME THING. So the snapshot pins the
//   default, and TlsQuicConnectionTests.TheLiveMeasurementOfTheTwentiethOfAugustIsReproduced
//   Offline pins the live one, and a reader who takes the snapshot's fifteen matches as "the
//   project reproduces Brave's HTTP/3 SETTINGS" has read a row as a project status. It is not
//   one. The default is a fingerprint TARGET expressed as a default; whether the stack behind
//   it can honour every pair is C14's and C17's question, not this file's.
//
// ============================================================================
// FINDING 7 IS NOT RETIRED, AND THE HANDOFF SAYING IT WAS IS WRONG.
// ============================================================================
//
//   The prompt for this task claimed C11 had shown SETTINGS wire order can now be read off the
//   emitted STREAM frames, "which retires Finding 7's not-yet-known status". The first half is
//   true - `settings_wire_order` below is measured, and
//   TlsQuicConnectionTests.TheOpeningFlightIsSettingsFirstOnTheControlStreamAsTheWireSawIt
//   already read a descending-order list back off the wire. THE SECOND HALF DOES NOT FOLLOW.
//
//   Finding 7's not-yet-known-ness is a statement about the CAPTURE, not about us. Its own
//   words: the capture's identifiers are "1, 6, 7, 51, 126585778853 - strictly ascending. So
//   Chromium's emission order and a sort by identifier are indistinguishable from this capture
//   alone." Reading OUR order more precisely cannot make BRAVE's order knowable. Being able to
//   measure one side of a comparison is a prerequisite for the row existing at all; it is not
//   evidence about the other side.
//
//   So `settings_wire_order` is measured AND its verdict is not-yet-known-from-the-capture, and
//   those two facts are not in tension. A packet capture of Chromium emitting a NON-ascending
//   set is what retires it. -> subsystem B.
//
// ============================================================================
// THE ALPN ROW IS MEASURED NOW - TASK B8 CORRECTED THIS BLOCK.
// ============================================================================
//
//   WHAT THIS BLOCK USED TO SAY, AND WHY IT WAS TRUE THEN. The capture settles `h3`
//   affirmatively - it is an HTTP/3 capture - yet the row sat in the third column, because this
//   readout could not measure it: RFC 9114 s3.2's token lives in the ClientHelloProfile handed
//   to CustomTlsQuicClient and no STREAM frame carries it, so `Describe` never saw it. The
//   block then cited TlsQuicHttp3Connection.cs's claim that no profile under src/ offered h3.
//   That citation was a citation of a comment, not of a measurement, and the comment it cited
//   was itself a pasted grep result that had come to match itself.
//
//   WHAT CHANGED. `Describe` now REQUIRES the encoded ClientHello the connection sent, and the
//   row is decoded out of it by ClientHelloCapture.Import - the same parser the library uses to
//   import somebody else's capture. So the value in the `ours` column is a function of emitted
//   bytes, exactly like every other row here, and a test that names its own ALPN is scoring
//   its own ClientHello rather than a fixture the readout was told about.
//
//   THE PARAMETER IS REQUIRED AND NOT OPTIONAL ON PURPOSE. An optional one would let a caller
//   silently return the row to the third column by omitting an argument, which is the exact
//   failure this block is a correction of.
//
// ============================================================================
// THE MUTATION LEDGER - TASK C12 (this file)
// ============================================================================
//
//   ROWS BELOW                   20  = C12-1 to C12-20 with no gaps
//   KILLED WHEN FIRST RUN        16  = 20 rows, less 2 [WAS-SURVIVOR], 1 [SURVIVED]
//                                      and 1 [RE-LISTED] inert proof
//   SURVIVED, THEN WITNESSED      2  = rows C12-8 and C12-13
//   SURVIVING STILL               1  = row C12-10, classified below
//   SURVIVED ON PURPOSE           1  = row C12-20, the harness's inert proof
//
//   THE HARNESS WAS PROVED IN BOTH DIRECTIONS BEFORE ANY VERDICT WAS BELIEVED, for the reason
//   C11's ledger gives at length: VSTest leaves testhost.exe holding SharpTls.Tests.dll, the
//   next build fails its copy with MSB3027, and `dotnet test` then runs the PREVIOUS binary.
//   mutate-c12.py kills test hosts through PowerShell, builds the mutant EXPLICITLY and
//   refuses to test unless that build succeeded, runs with --no-build, rejects any run
//   reporting fewer than 1,700 cases as a non-result rather than a verdict, and checks each
//   row's ORIGINAL text against the file both before applying it and after restoring it. The
//   proof pair: a known-bad - the pseudo-header order rendered from the literal "p,s,a,m" -
//   reported KILLED by 25 cases, and an inert comment reported SURVIVED by 0.
//
//   AND A SECOND HAZARD THIS SWEEP HAD THAT C11's DID NOT: two other agents were editing the
//   same working tree while it ran. The harness therefore records the FAILING TEST NAMES per
//   row and not only the count, and every name in every row below is one of this task's own -
//   so no row's verdict is somebody else's broken build wearing a kill.
//
//   Counts are per xUnit CASE, so a Theory failing in three rows counts three.
//
//   C12-1. The control stream's SETTINGS read from its second frame rather than its first.
//        Killed by 8, including
//        TlsQuicConnectionTests.SettingsWireOrderStaysNotYetKnownEvenThoughItIsMeasured and
//        .TheReadoutMatchesTheCheckedInSnapshot.
//   C12-2. The wire order sorted ascending before rendering. Killed by 1,
//        .ADescendingSettingsListRendersDescending - which is the whole of Finding 7's point:
//        a canonicalising renderer would make every emitter look like Chromium, because
//        Chromium's own identifiers are ascending and the capture cannot tell the two apart.
//   C12-3. The wire-order row's verdict changed from not-yet-known to match. Killed by 2,
//        .SettingsWireOrderStaysNotYetKnownEvenThoughItIsMeasured and the snapshot.
//   C12-4. The pseudo-header order rendered from the capture's constant instead of the decoded
//        field lines - C9's mutant, which passed that task's stated done-when. Killed by 23,
//        .EveryPseudoHeaderOrderRendersItself, one case per permutation other than the
//        capture's own, AND BY NOTHING ELSE IN THIS FILE. That is C9's finding reproduced.
//   C12-5. The verdict comparison inverted, so match and MISMATCH swap. Killed by 36.
//   C12-6. The reserved-frame triple collapsed by dropping the payload row. Killed by 2,
//        .AReservedFrameOnTheRequestStreamIsMeasured and the snapshot.
//   C12-7. The verdict counts written as the three constants the default recording produces
//        rather than counted from the rows. Killed by 1,
//        .TheVerdictCountsAreDerivedFromTheRowsAndNotAssertedBesideThem - and only after that
//        test was given a SECOND recording, because against the default one the constants and
//        the counts agree by construction.
//   C12-8. [WAS-SURVIVOR] s7.2.4.1's reserved form tested as `identifier > ReservedBase`
//        instead of being recomputed. SURVIVED: every spec in the suite used identifiers that
//        are either below 0x21 or genuinely reserved, so the two agreed everywhere.
//        UNWITNESSED, not vacuous - any identifier above 0x21 that is NOT of the form
//        0x1f * N + 0x21 separates them, and 0x22 is the smallest. Now killed by 1,
//        .AnExtraSettingIdentifierAddsARow, which sends 0x22 and asserts no GREASE pair.
//   C12-9. The Huffman row counting field lines rather than string literals. Killed by 3,
//        including both rows of .TheHuffmanRowCountsStringLiteralsAndNotFieldLines. The
//        capture request encodes four field lines and exactly two literals, so the two
//        denominators differ.
//   C12-10. [SURVIVED] s4.5.1's field-section prefix skipped as two literal octets instead of
//        being decoded. UNREACHABLE BY CONSTRUCTION, and no test is written for it: C5-C8's
//        encoder is static-only, so the Required Insert Count is ALWAYS zero and s4.5.1's
//        prefix is ALWAYS exactly two octets. A recording that separates them needs a dynamic
//        table, which is C14's. A test written now would pass against the mutant and become a
//        false witness. The decode stays because it stops being a no-op the day C14 lands.
//   C12-11. The s4.5.2 branch tested after s4.5.4, so an indexed field line reads as a literal
//        with a name reference and the walk desynchronises. Killed by 4, including
//        .TheRepresentationScanAgreesWithTheProductionDecoder. RECORDED BECAUSE THREE EARLIER
//        ATTEMPTS AT THIS ROW WERE VACUOUS: mutating a PREFIX WIDTH desynchronises nothing
//        here - every index in the capture request is small enough that a 4-bit and a 6-bit
//        prefix consume the same single octet - so branch ORDER is the mutation that actually
//        separates the two walks.
//   C12-12. The unidirectional open order taken from ascending stream id rather than emission
//        order. Killed by 1, .TheStreamOpenOrderIsEmissionOrderAndNotIdentifierOrder, which
//        has to build its recording BY HAND: TlsQuicStreamSet hands out s2.1 ordinals in open
//        order, so for anything the HTTP/3 layer emits the two orders coincide.
//   C12-13. [WAS-SURVIVOR] The contiguity check on stream offsets removed. SURVIVED: every
//        producer in this tree hands over frames a QUIC receiver already reassembled, so no
//        recording in the suite carried a hole. UNWITNESSED, not vacuous - the guard exists
//        for an out-of-contract caller, and this readout reports BYTE POSITIONS, so a hole
//        would shift every field after it rather than fail. Now killed by 1,
//        .AHoleInTheRecordingIsRefused.
//   C12-14. s4.2.2's send half scored on the presence of a HEADERS frame rather than on
//        whether it fits the capture's advertised 262144. Killed by 1,
//        .TheSendHalfOfMaxFieldSectionSizeIsMeasuredAgainstTheCapture.
//   C12-15. The [subsystem B] marker dropped from the transport-parameter row names, which is
//        the difference between RENDERING task 11's finding and RE-FILING it against C. Killed
//        by 7, including .SegmentsThreeAndFourAreNamedAsSubsystemBs.
//   C12-16. The six flow-control values hard-coded to the capture's, so every row reads match.
//        Killed by 6, .AFlowControlParameterThatMovesFlipsItsRow, one case per parameter -
//        and by nothing else, because TlsQuicLocalFlowControlSpec's defaults ALREADY are the
//        capture's six, so the constant and the measurement agree on every other recording.
//   C12-17. The character-for-character diff reporting the first difference one index late.
//        Killed by 1, .TheSegmentDiffNamesTheFirstDifferingIndex.
//   C12-18. The empty-recording guard removed. Killed by 1, .AnEmptyRecordingIsRefused.
//   C12-19. [RE-LISTED as the harness's known-bad proof] The pseudo-header order rendered from
//        the literal "p,s,a,m". Killed by 25.
//   C12-20. [RE-LISTED as the harness's inert proof] A comment added above the class
//        declaration. SURVIVED by 0, which is the other half of the harness proof and is not
//        a defect: an inert edit reporting KILLED would mean the runs were not measuring the
//        binary they had just built.
internal static class TlsQuicHttp3FingerprintReadout
{
    /// <summary>The verdict for a field the capture publishes and we reproduce.</summary>
    internal const string Match = "match";

    /// <summary>The verdict for a field the capture publishes and we do not reproduce.</summary>
    internal const string Mismatch = "MISMATCH";

    /// <summary>The verdict for a field the capture cannot settle at all.</summary>
    /// <remarks>NOT A SYNONYM FOR "we have not done it yet". It means a packet capture is
    /// needed before anyone can say what Chromium does, so the value on our side is a declared
    /// placeholder rather than a target that was missed.</remarks>
    internal const string NotYetKnown = "not-yet-known-from-the-capture";

    // ---- the capture's published figures -------------------------------------------------
    //
    // EVERY CONSTANT IN THIS SECTION HAS AN EXTERNAL SOURCE, which is the whole difference
    // between this block and the snapshot the tests hold. The line numbers are into
    // docs/superpowers/specs/reference-captures/2026-08-16-brave-151-http3-impersonate-pro.md.

    /// <summary>The capture's whole first perk segment, line 47.</summary>
    private const string CaptureSettingsSegment = "1:65536;6:262144;7:100;51:1;GREASE";

    /// <summary>The capture's second perk segment, lines 47 and 70.</summary>
    private const string CapturePseudoHeaderOrder = "m,a,s,p";

    /// <summary>The capture's fourth perk segment, lines 47 and 57.</summary>
    private const string CaptureConnectionIdLengths = "0,8";

    /// <summary>The capture's ALPN offer, line 121: <c>16 `alpn` (`h3`)</c> - ONE token, and
    /// the row below compares the whole offered list against it rather than asking whether h3
    /// is somewhere in it.</summary>
    /// <remarks>RFC 9114 s3.2 permits more - "Support for other application-layer protocols MAY
    /// be offered in the same handshake" - so a client offering <c>h3,h3-29</c> is conforming
    /// and is a DIFFERENT client from the captured one. A containment test would score both
    /// the same and is therefore the wrong test for a fingerprint.</remarks>
    private const string CaptureAlpn = "h3";

    /// <summary>The capture's third segment in wire order, its table at lines 79-92, with the
    /// reserved parameter rendered as the perk string renders it.</summary>
    private const string CaptureTransportParameterWireOrder =
        "12584,GREASE,32,9,8,7,5,15,17,1,6,4,12583,3";

    /// <summary>The capture's SETTINGS table, lines 64-68, in the table's own order.</summary>
    /// <remarks>The reserved row is last and carries no value, because s7.2.4.1 leaves the
    /// value free and the perk string renders the pair as the bare token.</remarks>
    private static readonly ImmutableArray<(ulong Identifier, string Name, string Value)>
        CaptureSettings =
        [
            (TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier,
                "SETTINGS_QPACK_MAX_TABLE_CAPACITY", "65536"),
            (TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier,
                "SETTINGS_MAX_FIELD_SECTION_SIZE", "262144"),
            (TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier,
                "SETTINGS_QPACK_BLOCKED_STREAMS", "100"),
            (TlsQuicHttp3Spec.H3DatagramIdentifier, "SETTINGS_H3_DATAGRAM", "1"),
        ];

    /// <summary>The capture's six flow-control transport parameters, from its wire-order table
    /// at lines 79-92, in ASCENDING IDENTIFIER ORDER.</summary>
    /// <remarks>ASCENDING AND NOT WIRE ORDER, ON PURPOSE. These rows score VALUES. Their wire
    /// order is one separate row, it is subsystem B's, and interleaving the two would let a
    /// reader take a value row's verdict as a statement about order.</remarks>
    private static readonly ImmutableArray<(ulong Id, string Name, ulong Value)>
        CaptureFlowControlParameters =
        [
            (0x04, "initial_max_data", 15728640),
            (0x05, "initial_max_stream_data_bidi_local", 6291456),
            (0x06, "initial_max_stream_data_bidi_remote", 6291456),
            (0x07, "initial_max_stream_data_uni", 6291456),
            (0x08, "initial_max_streams_bidi", 100),
            (0x09, "initial_max_streams_uni", 103),
        ];

    /// <summary>RFC 9000 s18.2's <c>initial_source_connection_id</c>, whose VALUE LENGTH is the
    /// first half of the perk string's fourth segment.</summary>
    private const ulong InitialSourceConnectionIdParameterId = 0x0f;

    /// <summary>The s4.2.2 limit the capture advertises, used as the bound the emitted field
    /// section is decoded against.</summary>
    private const long CaptureMaximumFieldSectionSize = 262144;

    /// <summary>What a cell says when the capture publishes nothing about the field.</summary>
    private const string NotPublished = "not-published-by-the-capture";

    /// <summary>What a cell says when the recording holds no such thing at all.</summary>
    private const string Absent = "absent";

    /// <summary>Renders the readout for one recording of emitted STREAM frames.</summary>
    /// <param name="emittedStreamFrames">Every QUIC STREAM frame the connection sent, in send
    /// order, as stream id, offset, payload and s19.8's FIN bit. Shaped to be handed
    /// <c>LoopbackQuicPeer.ReceivedStreamFrames</c> straight, because a peer that decrypted
    /// them is the only witness that they were emitted rather than merely encoded.</param>
    /// <param name="emittedTransportParameters">The transport parameters the ClientHello
    /// carried. NOT READ OFF THE WIRE HERE - see this type's header. Every row sourced from
    /// them says so and names subsystem B as their owner.</param>
    /// <param name="destinationConnectionIdLength">The Destination Connection ID length the
    /// first Initial packet carried, which is the second half of the perk string's fourth
    /// segment. Same provenance and same caveat as the parameters.</param>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="emittedStreamFrames"/> is
    /// empty.</exception>
    /// <exception cref="InvalidOperationException">The recording is not a set of contiguous
    /// streams from offset zero.</exception>
    /// <param name="encodedClientHello">The ClientHello handshake message this connection sent,
    /// as encoded. The ALPN row is decoded out of these bytes; see this type's header for why it
    /// is required rather than optional. Bytes this library cannot parse are reported in the row
    /// rather than thrown, because a readout of a connection is not the place to fail.</param>
    internal static string Describe(
        IReadOnlyList<(ulong StreamId, ulong Offset, byte[] Data, bool Fin)> emittedStreamFrames,
        TlsQuicTransportParameters emittedTransportParameters,
        int destinationConnectionIdLength,
        byte[] encodedClientHello)
    {
        ArgumentNullException.ThrowIfNull(emittedStreamFrames);
        ArgumentNullException.ThrowIfNull(emittedTransportParameters);
        ArgumentNullException.ThrowIfNull(encodedClientHello);
        if (emittedStreamFrames.Count == 0)
        {
            throw new ArgumentException(
                "An HTTP/3 fingerprint readout needs at least one emitted STREAM frame. An "
                    + "empty recording would render every row as an absence, which is a "
                    + "different claim from a connection that sent nothing.",
                nameof(emittedStreamFrames));
        }

        var streams = Reassemble(emittedStreamFrames);
        return Render(
            streams,
            emittedTransportParameters,
            destinationConnectionIdLength,
            encodedClientHello);
    }

    // ---- reading -------------------------------------------------------------------------

    /// <summary>One stream, reassembled from the frames that carried it.</summary>
    private sealed class StreamReadout
    {
        internal ulong Id { get; init; }

        /// <summary>Where in the emitted frame sequence this stream's FIRST frame sat.</summary>
        /// <remarks>THE FIELD THAT MAKES OPEN ORDER MEASURABLE. Sorting by id instead would
        /// report a canonical order for every emitter, which is the same defect Finding 7
        /// warns about one layer up.</remarks>
        internal int FirstFrameIndex { get; init; }

        internal List<byte> Bytes { get; } = [];

        internal bool Fin { get; set; }
    }

    private static List<StreamReadout> Reassemble(
        IReadOnlyList<(ulong StreamId, ulong Offset, byte[] Data, bool Fin)> frames)
    {
        var streams = new List<StreamReadout>();
        for (var index = 0; index < frames.Count; index++)
        {
            var frame = frames[index];
            var stream = streams.Find(candidate => candidate.Id == frame.StreamId);
            if (stream is null)
            {
                stream = new StreamReadout { Id = frame.StreamId, FirstFrameIndex = index };
                streams.Add(stream);
            }

            // RFC 9000 s2.2: "the data that is sent ... is a sequence of bytes". This readout
            // reports byte layout, so a hole would silently shift every field after it.
            if (frame.Offset != (ulong)stream.Bytes.Count)
            {
                throw new InvalidOperationException(
                    $"STREAM frame {index} on stream {frame.StreamId} declares offset "
                        + $"{frame.Offset} where the reassembled stream is "
                        + $"{stream.Bytes.Count} bytes long, so this recording is not a "
                        + "contiguous sequence from offset zero and no field position in it "
                        + "can be trusted.");
            }

            stream.Bytes.AddRange(frame.Data);
            stream.Fin |= frame.Fin;
        }

        return streams;
    }

    /// <summary>RFC 9000 s2.1: bit 0x02 of the identifier is the directionality.</summary>
    private static bool IsUnidirectional(ulong streamId) => (streamId & 0x02) != 0;

    /// <summary>RFC 9000 s2.1 Table 1: 0x00 is a client-initiated bidirectional stream, which
    /// s6.1 makes the request stream.</summary>
    private static bool IsClientRequestStream(ulong streamId) => (streamId & 0x03) == 0;

    /// <summary>The s6.2 stream type varint at the head of a unidirectional stream, and the
    /// bytes after it.</summary>
    private static (ulong Type, byte[] Body) ReadStreamType(StreamReadout stream)
    {
        var bytes = stream.Bytes.ToArray();
        var cursor = 0;
        if (!QuicVariableLengthInteger.TryRead(bytes, ref cursor, out var type))
        {
            throw new InvalidOperationException(
                $"Unidirectional stream {stream.Id} carries no readable s6.2 stream type "
                    + "varint, so nothing about it can be classified.");
        }

        return (type, bytes[cursor..]);
    }

    /// <summary>Every s7.1 frame on one stream, in wire order.</summary>
    private static List<(ulong Type, byte[] Payload)> ReadFrames(ReadOnlySpan<byte> bytes)
    {
        var frames = new List<(ulong, byte[])>();
        var cursor = 0;
        while (cursor < bytes.Length)
        {
            var status = TlsQuicHttp3Frames.TryRead(
                bytes, ref cursor, out var frameType, out var payload, out _);
            if (status != TlsQuicHttp3FrameReadStatus.Complete)
            {
                // A partial trailing frame is a recording that stopped mid-frame, not a defect.
                // The frames before it are still whole and still measurable.
                break;
            }

            frames.Add((frameType, payload.ToArray()));
        }

        return frames;
    }

    // ---- the QPACK representation scan ---------------------------------------------------

    /// <summary>What RFC 9204 s4.5 representation each field line used, and how many string
    /// literals were Huffman-coded.</summary>
    /// <remarks>A SECOND WALK OVER THE SAME BYTES, AND NOT A SECOND DECODER.
    /// TlsQuicQpackDecoder is authoritative for names and values and this type uses it for
    /// them; what it does NOT report is which of s4.5's representations carried each line and
    /// whether each literal set H, because a decoder's job is to make those choices invisible.
    /// This scan exists precisely to report what that one discards, and
    /// .TheRepresentationScanAgreesWithTheProductionDecoder pins the two walks to the same
    /// field-line count so a mis-read pattern here cannot go unnoticed.</remarks>
    private sealed class FieldSectionScan
    {
        internal List<string> Representations { get; } = [];

        internal int StringLiterals { get; set; }

        internal int HuffmanStringLiterals { get; set; }
    }

    // A byte[] and NOT a ReadOnlySpan<byte>, because the three local functions below have
    // to share the cursor and C# forbids a ref-like parameter inside a local function (CS9108).
    private static FieldSectionScan ScanRepresentations(byte[] section)
    {
        var scan = new FieldSectionScan();

        // s4.5.1's prefix: an 8-bit-prefix Required Insert Count and a Sign-plus-7-bit Delta
        // Base. Decoded rather than skipped as two octets, because a non-zero Required Insert
        // Count is more than one octet long and every field position after it would shift.
        if (!TlsQuicQpackPrimitives.TryDecodeInteger(section, 8, out _, out var consumed, out _))
        {
            return scan;
        }

        var offset = consumed;
        if (!TlsQuicQpackPrimitives.TryDecodeInteger(
            section.AsSpan(offset), 7, out _, out consumed, out _))
        {
            return scan;
        }

        offset += consumed;
        while (offset < section.Length)
        {
            var first = section[offset];
            bool ok;
            if ((first & 0b1000_0000) != 0)
            {
                // s4.5.2 Indexed Field Line: '1', T, then a 6-bit prefix index. No literal.
                ok = Integer(6, "4.5.2");
            }
            else if ((first & 0b0100_0000) != 0)
            {
                // s4.5.4 Literal Field Line With Name Reference: '01', N, T, a 4-bit prefix
                // name index, then an 8-bit prefix string literal for the value.
                ok = Integer(4, "4.5.4") && Literal(8);
            }
            else if ((first & 0b0010_0000) != 0)
            {
                // s4.5.6 Literal Field Line With Literal Name: '001', N, then a 4-bit prefix
                // string literal for the name and an 8-bit prefix one for the value.
                ok = Record("4.5.6") && Literal(4) && Literal(8);
            }
            else if ((first & 0b0001_0000) != 0)
            {
                // s4.5.3 Indexed Field Line With Post-Base Index.
                ok = Integer(4, "4.5.3");
            }
            else
            {
                // s4.5.5 Literal Field Line With Post-Base Name Reference.
                ok = Integer(3, "4.5.5") && Literal(8);
            }

            if (!ok)
            {
                break;
            }
        }

        return scan;

        bool Record(string representation)
        {
            scan.Representations.Add(representation);
            return true;
        }

        bool Integer(int prefixBits, string representation)
        {
            if (!TlsQuicQpackPrimitives.TryDecodeInteger(
                section.AsSpan(offset), prefixBits, out _, out var read, out _))
            {
                return false;
            }

            offset += read;
            return Record(representation);
        }

        bool Literal(int prefixBits)
        {
            if (!TlsQuicQpackPrimitives.TryDecodeStringLiteral(
                section.AsSpan(offset), prefixBits, out var huffman, out _, out var read, out _))
            {
                return false;
            }

            offset += read;
            scan.StringLiterals++;
            if (huffman)
            {
                scan.HuffmanStringLiterals++;
            }

            return true;
        }
    }

    // ---- rendering -----------------------------------------------------------------------

    // One rendered row. Verdict is one of the three constants above and nothing else - there
    // is no fourth value and no free-form cell, because a verdict a reader has to interpret is
    // a verdict subsystem B cannot count.
    private sealed record Row(string Field, string Ours, string Brave, string Verdict);

    private static string Render(
        List<StreamReadout> streams,
        TlsQuicTransportParameters parameters,
        int destinationConnectionIdLength,
        byte[] encodedClientHello)
    {
        // ---- segment 1: the control stream's SETTINGS ----
        var settings = ImmutableArray<TlsQuicHttp3Setting>.Empty;
        var openOrder = new List<string>();
        foreach (var stream in streams.Where(candidate => IsUnidirectional(candidate.Id))
            .OrderBy(candidate => candidate.FirstFrameIndex))
        {
            var (type, body) = ReadStreamType(stream);
            openOrder.Add(StreamTypeName(type));
            if (type != (ulong)TlsQuicHttp3StreamType.Control)
            {
                continue;
            }

            var frames = ReadFrames(body);
            if (frames.Count > 0
                && frames[0].Type == (ulong)TlsQuicHttp3FrameType.Settings
                && TlsQuicHttp3Settings.TryDecodePayload(frames[0].Payload, out var decoded, out _))
            {
                settings = decoded;
            }
        }

        // ---- segment 2 and the QPACK rows: the request stream's HEADERS ----
        var request = streams.Where(candidate => IsClientRequestStream(candidate.Id))
            .OrderBy(candidate => candidate.FirstFrameIndex)
            .FirstOrDefault();
        var requestFrames = request is null
            ? new List<(ulong Type, byte[] Payload)>()
            : ReadFrames(request.Bytes.ToArray());
        var headers = requestFrames.FindIndex(
            frame => frame.Type == (ulong)TlsQuicHttp3FrameType.Headers);
        var section = headers < 0 ? Array.Empty<byte>() : requestFrames[headers].Payload;
        var scan = ScanRepresentations(section);
        var (pseudoOrder, decodedLines, withinCaptureLimit) = DecodeFieldSection(section);

        var rows = new List<Row>();
        RenderSettingsRows(rows, settings);
        rows.Add(new Row(
            "pseudo-header order (perk segment 2)",
            headers < 0 ? Absent : pseudoOrder,
            CapturePseudoHeaderOrder,
            Verdict(headers >= 0 && pseudoOrder == CapturePseudoHeaderOrder)));
        RenderFieldSectionSizeRows(rows, settings, headers >= 0, decodedLines, withinCaptureLimit);
        RenderPlaceholderRows(rows, openOrder, scan, requestFrames, headers);
        // Kept at the index the placeholder version occupied, so the correction shows up in the
        // snapshot as a changed row and not as a moved one.
        RenderAlpnRow(rows, encodedClientHello);
        RenderSubsystemBRows(rows, parameters, destinationConnectionIdLength);

        var text = new StringBuilder();
        text.Append(Preamble);
        RenderPerkLine(text, settings, headers < 0 ? Absent : pseudoOrder);
        RenderSegmentDiff(text, TlsQuicHttp3Settings.Render(settings));
        RenderTable(text, rows);
        RenderCounts(text, rows);
        text.Append(Notes);
        return text.ToString();
    }

    private static void RenderSettingsRows(
        List<Row> rows, ImmutableArray<TlsQuicHttp3Setting> settings)
    {
        // The capture's four numbered identifiers, in the capture's own table order.
        foreach (var (identifier, name, value) in CaptureSettings)
        {
            var ours = Ours(settings, identifier);
            rows.Add(new Row(
                $"settings 0x{identifier:x2} {name}",
                ours,
                value,
                Verdict(ours == value)));
        }

        // s7.2.4.1's reserved pair. Neither identifier nor value is hashed - only presence and
        // position - so the cells carry presence and the wire-order row carries position.
        var reserved = settings.Any(
            setting => TlsQuicHttp3Frames.IsReservedIdentifier(setting.Identifier));
        rows.Add(new Row(
            "settings reserved (GREASE) pair",
            reserved ? "present" : Absent,
            "present",
            Verdict(reserved)));

        // Anything we send that the capture does not name at all. Zero rows for a spec whose
        // identifiers are a subset of the capture's, which is why the row COUNT below is
        // counted rather than written down.
        foreach (var setting in settings.Where(setting =>
            !TlsQuicHttp3Frames.IsReservedIdentifier(setting.Identifier)
            && !CaptureSettings.Any(row => row.Identifier == setting.Identifier)))
        {
            rows.Add(new Row(
                $"settings 0x{setting.Identifier:x2} sent by us, absent from the capture",
                setting.Value.ToString(CultureInfo.InvariantCulture),
                Absent,
                Mismatch));
        }

        // FINDING 7. Measured, and still not-yet-known - see this type's header for why those
        // are not in tension.
        rows.Add(new Row(
            "settings wire order",
            settings.IsEmpty
                ? Absent
                : string.Join(',', settings.Select(RenderIdentifier)),
            "1,6,7,51,GREASE",
            NotYetKnown));

        rows.Add(new Row(
            "perk segment 1, whole",
            TlsQuicHttp3Settings.Render(settings),
            CaptureSettingsSegment,
            Verdict(TlsQuicHttp3Settings.Render(settings) == CaptureSettingsSegment)));
    }

    private static void RenderFieldSectionSizeRows(
        List<Row> rows,
        ImmutableArray<TlsQuicHttp3Setting> settings,
        bool sentHeaders,
        int decodedLines,
        bool withinCaptureLimit)
    {
        // s4.2.2's RECEIVE half: the limit we advertise, which C11 plumbs into every response
        // reader. Its value is row 2's; this row is about the half, not a second value.
        var advertised = Ours(settings, TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier);
        rows.Add(new Row(
            "s4.2.2 receive half - the limit we advertise",
            advertised,
            CaptureMaximumFieldSectionSize.ToString(CultureInfo.InvariantCulture),
            Verdict(advertised
                == CaptureMaximumFieldSectionSize.ToString(CultureInfo.InvariantCulture))));

        // s4.2.2's SEND half, measured by DECODING THE EMITTED FIELD SECTION BACK against the
        // capture's own advertised limit. Decoded rather than summed here for the reason C11's
        // header gives: s4.2.2's "length of the name and value in bytes plus an overhead of 32
        // bytes for each field" is implemented once, in TlsQuicQpackDecoder, and a second
        // implementation would be a second transcription with no independent source.
        rows.Add(new Row(
            "s4.2.2 send half - the emitted field section against that limit",
            sentHeaders
                ? $"{decodedLines} field lines, "
                    + (withinCaptureLimit ? "within" : "over")
                : Absent,
            $"<= {CaptureMaximumFieldSectionSize.ToString(CultureInfo.InvariantCulture)}",
            Verdict(sentHeaders && withinCaptureLimit)));
    }

    private static void RenderPlaceholderRows(
        List<Row> rows,
        List<string> openOrder,
        FieldSectionScan scan,
        List<(ulong Type, byte[] Payload)> requestFrames,
        int headersIndex)
    {
        rows.Add(new Row(
            "unidirectional stream open order",
            openOrder.Count == 0 ? Absent : string.Join(',', openOrder),
            NotPublished,
            NotYetKnown));

        rows.Add(new Row(
            "QPACK Huffman flag policy",
            $"H set on {scan.HuffmanStringLiterals} of {scan.StringLiterals} string literals",
            NotPublished,
            NotYetKnown));

        // s4.5.2 against s4.5.4 for a line whose name AND value both match the static table.
        // The distinguishing evidence is the representation of the FIRST line, because an
        // encoder that preferred name references would push a full match down to s4.5.4.
        rows.Add(new Row(
            "QPACK name-match policy, s4.5.2 against s4.5.4",
            scan.Representations.Count == 0
                ? Absent
                : string.Join(',', scan.Representations),
            NotPublished,
            NotYetKnown));

        // THREE ROWS, NOT ONE. C9 established that the reserved frame's N, its payload and its
        // position are three independent unknowns: an emitter could match the position and miss
        // the length distribution, or the reverse, and one row would hide it.
        var reserved = requestFrames.FindIndex(
            frame => TlsQuicHttp3Frames.IsReservedIdentifier(frame.Type));
        rows.Add(new Row(
            "reserved (GREASE) request-stream frame - N",
            reserved < 0
                ? "none emitted"
                : ((requestFrames[reserved].Type - TlsQuicHttp3Frames.ReservedBase)
                    / TlsQuicHttp3Frames.ReservedStep)
                    .ToString(CultureInfo.InvariantCulture),
            NotPublished,
            NotYetKnown));
        rows.Add(new Row(
            "reserved (GREASE) request-stream frame - payload",
            reserved < 0
                ? "none emitted"
                : $"{requestFrames[reserved].Payload.Length} bytes, "
                    + Convert.ToHexString(requestFrames[reserved].Payload),
            NotPublished,
            NotYetKnown));
        rows.Add(new Row(
            "reserved (GREASE) request-stream frame - position",
            reserved < 0
                ? "none emitted"
                : headersIndex < 0
                    ? $"frame {reserved}, no HEADERS on the stream"
                    : reserved < headersIndex ? "before HEADERS" : "after HEADERS",
            NotPublished,
            NotYetKnown));

    }

    /// <summary>Renders the ALPN row from the encoded ClientHello. See this type's header for
    /// why this is a measured row now and was a placeholder before.</summary>
    /// <remarks>THE DECODE IS THE LIBRARY'S OWN IMPORTER and not a hand-written extension walk,
    /// so a ClientHello this readout can read is one the library can round-trip. A failure is a
    /// row value rather than an exception: this method's whole job is to describe a connection
    /// that already happened, and throwing would destroy the other twenty-four rows over one
    /// unparsable input.</remarks>
    private static void RenderAlpnRow(List<Row> rows, byte[] encodedClientHello)
    {
        string ours;
        try
        {
            var offered = ClientHelloCapture.Import(encodedClientHello).Spec.AlpnProtocols;
            ours = offered.Count == 0 ? Absent : string.Join(',', offered);
        }
        catch (Exception exception) when (exception is TlsProtocolException or ArgumentException)
        {
            ours = "unparsable-ClientHello";
        }

        rows.Add(new Row(
            "ALPN token (RFC 9114 s3.2)",
            ours,
            CaptureAlpn,
            Verdict(ours == CaptureAlpn)));
    }

    private static void RenderSubsystemBRows(
        List<Row> rows, TlsQuicTransportParameters parameters, int destinationConnectionIdLength)
    {
        foreach (var (id, name, value) in CaptureFlowControlParameters)
        {
            var parameter = parameters.Get(id);
            var ours = parameter is null
                ? Absent
                : parameter.GetVariableInteger().ToString(CultureInfo.InvariantCulture);
            rows.Add(new Row(
                $"transport parameter 0x{id:x2} {name} [subsystem B]",
                ours,
                value.ToString(CultureInfo.InvariantCulture),
                Verdict(ours == value.ToString(CultureInfo.InvariantCulture))));
        }

        // NOT RE-FILED AS C's FAILURE. Task 11's readout already recorded this as a MISMATCH
        // from the emitted datagrams and the plan forbids C filing it again; the row exists so
        // the perk string's third segment is not silently missing from a perk readout, and the
        // owner is in the field name.
        var ourOrder = string.Join(
            ',',
            parameters.Parameters.Select(parameter => parameter.Id.ToString(
                CultureInfo.InvariantCulture)));
        rows.Add(new Row(
            "transport parameter wire order (perk segment 3) [subsystem B]",
            ourOrder.Length == 0 ? Absent : ourOrder,
            CaptureTransportParameterWireOrder,
            Verdict(ourOrder == CaptureTransportParameterWireOrder)));

        // s18.2's initial_source_connection_id carries its own length, which is the first half
        // of the pair; the second is the Destination Connection ID the first Initial packet
        // carried, which no STREAM frame can show.
        var source = parameters.Get(InitialSourceConnectionIdParameterId);
        var ourLengths = source is null
            ? Absent
            : $"{source.Value.Length},{destinationConnectionIdLength}";
        rows.Add(new Row(
            "connection ID length pair (perk segment 4) [subsystem B]",
            ourLengths,
            CaptureConnectionIdLengths,
            Verdict(ourLengths == CaptureConnectionIdLengths)));
    }

    // ---- cells and text --------------------------------------------------------------------

    private static string Verdict(bool matches) => matches ? Match : Mismatch;

    private static string Ours(ImmutableArray<TlsQuicHttp3Setting> settings, ulong identifier)
    {
        foreach (var setting in settings)
        {
            if (setting.Identifier == identifier)
            {
                return setting.Value.ToString(CultureInfo.InvariantCulture);
            }
        }

        return Absent;
    }

    private static string RenderIdentifier(TlsQuicHttp3Setting setting) =>
        TlsQuicHttp3Frames.IsReservedIdentifier(setting.Identifier)
            ? TlsQuicHttp3Settings.ReservedToken
            : setting.Identifier.ToString(CultureInfo.InvariantCulture);

    private static string StreamTypeName(ulong type) => type switch
    {
        (ulong)TlsQuicHttp3StreamType.Control => "control",
        (ulong)TlsQuicHttp3StreamType.Push => "push",
        (ulong)TlsQuicHttp3StreamType.QpackEncoder => "qpack-encoder",
        (ulong)TlsQuicHttp3StreamType.QpackDecoder => "qpack-decoder",
        _ => TlsQuicHttp3Frames.IsReservedIdentifier(type)
            ? "reserved"
            : $"0x{type:x}",
    };

    /// <summary>The pseudo-header order, the field line count, and whether the section fits the
    /// capture's advertised s4.2.2 limit - all three from ONE decode by the production
    /// decoder.</summary>
    private static (string Order, int Lines, bool WithinCaptureLimit) DecodeFieldSection(
        byte[] section)
    {
        if (section.Length == 0)
        {
            return (Absent, 0, false);
        }

        // A field line costs at least one octet, so the octet count bounds the line count; a
        // Huffman-coded string can expand, and s7.2 fixes no bound on the ratio, so the buffer
        // is sized from the decoder's own limit rather than from a guessed multiple.
        var buffer = new byte[CaptureMaximumFieldSectionSize];
        var lines = new TlsQuicQpackDecodedFieldLine[section.Length];
        if (!TlsQuicQpackDecoder.TryDecodeFieldSection(
            section,
            buffer,
            lines,
            CaptureMaximumFieldSectionSize,
            out var lineCount,
            out _,
            out _))
        {
            return ("not-decodable", 0, false);
        }

        var order = new StringBuilder();
        for (var index = 0; index < lineCount; index++)
        {
            var line = lines[index];
            if (line.NameLength < 2 || buffer[line.NameOffset] != (byte)':')
            {
                continue;
            }

            if (order.Length > 0)
            {
                order.Append(',');
            }

            // The perk string abbreviates each pseudo-header to the first letter after the
            // colon: :method, :authority, :scheme, :path -> m, a, s, p.
            order.Append((char)buffer[line.NameOffset + 1]);
        }

        return (order.Length == 0 ? Absent : order.ToString(), lineCount, true);
    }

    private static void RenderPerkLine(
        StringBuilder text,
        ImmutableArray<TlsQuicHttp3Setting> settings,
        string pseudoOrder)
    {
        text.Append("## The perk string's first two segments\n\n")
            .Append("    ours   ")
            .Append(TlsQuicHttp3Settings.Render(settings))
            .Append(" | ")
            .Append(pseudoOrder)
            .Append('\n')
            .Append("    brave  ")
            .Append(CaptureSettingsSegment)
            .Append(" | ")
            .Append(CapturePseudoHeaderOrder)
            .Append("\n\n");
    }

    private static void RenderSegmentDiff(StringBuilder text, string ours)
    {
        text.Append("## Segment 1, character for character against the capture's\n\n")
            .Append("    ours   ").Append(ours).Append('\n')
            .Append("    brave  ").Append(CaptureSettingsSegment).Append('\n');

        var index = 0;
        while (index < ours.Length
            && index < CaptureSettingsSegment.Length
            && ours[index] == CaptureSettingsSegment[index])
        {
            index++;
        }

        if (index == ours.Length && index == CaptureSettingsSegment.Length)
        {
            text.Append("    identical\n\n");
            return;
        }

        text.Append("    first difference at index ")
            .Append(index.ToString(CultureInfo.InvariantCulture))
            .Append(": ours ")
            .Append(index < ours.Length ? $"'{ours[index]}'" : "<end>")
            .Append(", brave ")
            .Append(index < CaptureSettingsSegment.Length
                ? $"'{CaptureSettingsSegment[index]}'"
                : "<end>")
            .Append("\n\n");
    }

    private static void RenderTable(StringBuilder text, List<Row> rows)
    {
        text.Append("## The rows\n\n")
            .Append("| # | field | ours | brave | verdict |\n")
            .Append("| --- | --- | --- | --- | --- |\n");
        for (var index = 0; index < rows.Count; index++)
        {
            var row = rows[index];
            text.Append("| ")
                .Append((index + 1).ToString(CultureInfo.InvariantCulture))
                .Append(" | ").Append(row.Field)
                .Append(" | ").Append(row.Ours)
                .Append(" | ").Append(row.Brave)
                .Append(" | ").Append(row.Verdict)
                .Append(" |\n");
        }

        text.Append('\n');
    }

    private static void RenderCounts(StringBuilder text, List<Row> rows)
    {
        // COUNTED FROM THE RENDERED LIST, never written beside it. The plan's done-when asks
        // for exactly this, and it is what makes an added row impossible to render without the
        // header arithmetic moving with it.
        var match = rows.Count(row => row.Verdict == Match);
        var mismatch = rows.Count(row => row.Verdict == Mismatch);
        var unknown = rows.Count(row => row.Verdict == NotYetKnown);
        text.Append("## Verdict counts, derived from the rows above\n\n")
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
            .Append('\n');
    }

    private const string Preamble =
        "# HTTP/3 fingerprint readout - SNAPSHOT\n"
        + "\n"
        + "SNAPSHOT. Every value in the \"ours\" column below was produced by\n"
        + "TlsQuicHttp3FingerprintReadout from the QUIC STREAM frames this connection emitted,\n"
        + "and NONE of it has an external source. Per A2's standing rule, a checked-in number\n"
        + "with no external source is a snapshot and is labelled one: it pins what we do today,\n"
        + "and it is evidence about nothing else. The \"brave\" column is the opposite - every\n"
        + "one of its cells is quoted from\n"
        + "docs/superpowers/specs/reference-captures/2026-08-16-brave-151-http3-impersonate-pro.md\n"
        + "and none of it is measured here.\n"
        + "\n";

    private const string Notes =
        "\n"
        + "## Notes on the third column\n"
        + "\n"
        + "SETTINGS WIRE ORDER IS MEASURED AND STILL NOT-YET-KNOWN, and those are not in\n"
        + "tension. Finding 7: the capture's identifiers are \"1, 6, 7, 51, 126585778853 -\n"
        + "strictly ascending. So Chromium's emission order and a sort by identifier are\n"
        + "indistinguishable from this capture alone.\" Reading OUR order off the wire, which\n"
        + "this readout does, says nothing about BRAVE's. A capture of Chromium emitting a\n"
        + "non-ascending set retires it.\n"
        + "\n"
        + "THE ALPN ROW IS DECODED FROM THE CLIENTHELLO. It used to sit in the third column\n"
        + "with a pasted grep result for a value, because this readout was never handed the\n"
        + "ClientHello. It is now: Describe requires the encoded handshake message and the row\n"
        + "is read back out of it by the library's own importer, so the ours column is a\n"
        + "function of emitted bytes like every other row here. The whole offered list is\n"
        + "compared against the capture's single token, not searched for h3 inside it - RFC\n"
        + "9114 s3.2 lets a conforming client offer more, and one that does is a different\n"
        + "client.\n"
        + "\n"
        + "THE ROWS MARKED [subsystem B] ARE NOT SCORED AGAINST C. Perk segments 3 and 4 live\n"
        + "in the ClientHello, under RFC 9001 s5.2's Initial keys, and TlsQuicFingerprintReadout\n"
        + "already reads them off the emitted datagrams - it is the instrument, not this file.\n"
        + "The transport-parameter wire order MISMATCH is task 11's finding re-rendered so a\n"
        + "perk readout is not silently missing a perk segment, not a fresh filing against C.\n"
        + "\n"
        + "THE FIVE SETTINGS PAIRS AND THE PSEUDO-HEADER ORDER ARE NEVER not-yet-known. The\n"
        + "capture publishes both affirmatively - its SETTINGS table at lines 64-68 and its\n"
        + "pseudo-header line at 70 - so those rows carry match or MISMATCH and nothing else.\n";
}
