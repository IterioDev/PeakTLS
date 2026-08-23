using System.Collections.Immutable;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task C12: the HTTP/3 fingerprint readout.
//
// ============================================================================
// THE SAME PARTIAL CLASS AS C11's, FOR THE SAME REASON.
// ============================================================================
//
//   Harness, Spec, Connection, Server, Credential and ConfirmedHandshake are reused rather
//   than copied. A copy of Harness would be a second opening flight, and the whole claim of
//   this file is that what it renders is what a PEER DECRYPTED off the wire - which only a
//   real handshake against a real LoopbackQuicPeer can witness.
//
// ============================================================================
// WHY SOME TESTS BUILD THEIR RECORDING BY HAND, AND WHY THAT IS NOT CHEATING.
// ============================================================================
//
//   Describe's input is a list of emitted STREAM frames, so a test can hand it one. The tests
//   that do - the 24-permutation theory, the two QPACK-representation tests and the
//   s4.2.2 send-half test - all encode their request stream through
//   TlsQuicHttp3Request.TryEncode, which is the SAME encoder TlsQuicHttp3Connection calls;
//   what they skip is the handshake, not the encoding. The end-to-end claim is carried by
//   .TheReadoutMatchesTheCheckedInSnapshot and by every settings test here, each of which
//   drives a full handshake and reads LoopbackQuicPeer.ReceivedStreamFrames.
//
//   THE SPLIT IS DELIBERATE AND WAS MEASURED. Running 24 permutations through 24 handshakes
//   costs 24 fresh TestPki key generations for a row that depends on four bytes of QPACK.
//
// ============================================================================
// WHAT NO TEST HERE CAN DO, restated from task 11 because it is still true.
// ============================================================================
//
//   Nothing here can tell a plausible HTTP/3 layout from Chromium's. Only a packet capture
//   can, and the not-yet-known-from-the-capture rows of the rendered readout ARE the list of
//   what to capture. That list is the deliverable; these tests only prove it is honest.
public sealed partial class TlsQuicConnectionTests
{
    // The live measurement of 2026-08-20 drove exactly this request against
    // https://fp.impersonate.pro/api/http3, so the snapshot is the offline, repeatable form of
    // the thing that was measured by hand.
    private const string ReadoutAuthority = "fp.impersonate.pro";
    private const string ReadoutPath = "/api/http3";

    // ------------------------------------------------------------------------
    // The snapshot.
    // ------------------------------------------------------------------------

    [Fact]
    public async Task TheReadoutMatchesTheCheckedInSnapshot()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        var recording = await RecordHttp3Async(cancellation.Token, request: ReadoutRequest());
        var readout = Describe(recording);

        var expected = NormalizeReadout(
            await File.ReadAllTextAsync(Http3SnapshotPath, cancellation.Token));
        var actual = NormalizeReadout(readout);
        if (expected == actual)
        {
            return;
        }

        // THE MESSAGE NAMES THE ROW THAT MOVED, for the reason task 11's snapshot test gives:
        // a failure reading "strings differ" invites a re-baseline, and a re-baseline silently
        // throws away the fingerprint the snapshot exists to hold.
        var expectedLines = expected.Split('\n');
        var actualLines = actual.Split('\n');
        var line = 0;
        while (line < expectedLines.Length
            && line < actualLines.Length
            && expectedLines[line] == actualLines[line])
        {
            line++;
        }

        var scratch = Path.Combine(
            Path.GetTempPath(), "quic-http3-fingerprint-readout.actual.txt");
        await File.WriteAllTextAsync(scratch, actual, cancellation.Token);
        Assert.Fail(
            $"The HTTP/3 readout no longer matches the snapshot at line {line + 1}.\n"
            + $"  snapshot: {(line < expectedLines.Length ? expectedLines[line] : "<end of file>")}\n"
            + $"  actual:   {(line < actualLines.Length ? actualLines[line] : "<end of file>")}\n"
            + "RE-BASELINE ONLY IF THAT ROW WAS MEANT TO MOVE - a verdict that changes from\n"
            + "MISMATCH to match is a claim about Chromium, and a not-yet-known that becomes\n"
            + "either of the other two is a claim that somebody captured something.\n"
            + $"Whole actual written to {scratch}.");
    }

    // ------------------------------------------------------------------------
    // Segment 1: the SETTINGS, read off the control stream.
    // ------------------------------------------------------------------------

    // THE ANTI-RESTATEMENT WITNESS. Describe takes no TlsQuicHttp3Spec at all, so a restatement
    // has no parameter to restate FROM; this is the corroboration that the bytes are what moves
    // the render. Two specs whose SETTINGS disagree in identifier, value and order, and the
    // rendered segment tracks each one's own emitted bytes.
    [Fact]
    public async Task TheSettingsSegmentTracksTheEmittedBytesAndNotAConstant()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        var one = Describe(await RecordHttp3Async(
            cancellation.Token,
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 41),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 4242),
                ],
            }));
        var two = Describe(await RecordHttp3Async(
            cancellation.Token,
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 262144),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 7),
                ],
            }));

        Assert.Contains("    ours   7:41;6:4242 |", one, StringComparison.Ordinal);
        Assert.Contains("    ours   6:262144;1:7 |", two, StringComparison.Ordinal);

        // And the value cells moved with them, which a renderer reading a constant could not do.
        Assert.Equal("4242", CellOf(one, "settings 0x06 SETTINGS_MAX_FIELD_SECTION_SIZE", 2));
        Assert.Equal("262144", CellOf(two, "settings 0x06 SETTINGS_MAX_FIELD_SECTION_SIZE", 2));
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Mismatch,
            CellOf(one, "settings 0x06 SETTINGS_MAX_FIELD_SECTION_SIZE", 4));
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Match,
            CellOf(two, "settings 0x06 SETTINGS_MAX_FIELD_SECTION_SIZE", 4));
    }

    // FINDING 7's WHOLE POINT. A renderer that sorted before printing would make every emitter
    // look like Chromium, because Chromium's own identifiers are ascending and the capture
    // therefore cannot tell an emitter from a sorter.
    [Fact]
    public async Task ADescendingSettingsListRendersDescending()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        var readout = Describe(await RecordHttp3Async(
            cancellation.Token,
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 1),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 2),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 3),
                ],
            }));

        Assert.Equal("7,6,1", CellOf(readout, "settings wire order", 2));
    }

    // MEASURED AND STILL NOT-YET-KNOWN, which is the correction this task makes to its own
    // brief. Even when our identifiers are EXACTLY the capture's, in the capture's order, the
    // verdict stays not-yet-known - because the capture cannot distinguish Chromium's emission
    // order from a sort, so there is nothing on the other side of the comparison to match.
    [Fact]
    public async Task SettingsWireOrderStaysNotYetKnownEvenThoughItIsMeasured()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        var readout = Describe(await RecordHttp3Async(
            cancellation.Token,
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 65536),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 262144),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 100),
                ],
            }));

        Assert.Equal("1,6,7", CellOf(readout, "settings wire order", 2));
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.NotYetKnown,
            CellOf(readout, "settings wire order", 4));

        // The three pairs themselves ARE settled, and this is the row set that proves the two
        // are scored separately: same recording, three matches and one unknown.
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Match,
            CellOf(readout, "settings 0x01 SETTINGS_QPACK_MAX_TABLE_CAPACITY", 4));
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Match,
            CellOf(readout, "settings 0x07 SETTINGS_QPACK_BLOCKED_STREAMS", 4));
    }

    // A setting the capture never names is a row of its own, which is why the header count is
    // counted from the list instead of written beside it.
    //
    // 0x22 IS CHOSEN AND NOT ARBITRARY. It is above s7.2.4.1's reserved BASE of 0x21 and is NOT
    // of the reserved form - (0x22 - 0x21) % 0x1f is 1, not 0 - so it is the one shape that
    // separates "recomputed the reserved form" from "compared against the base", and a readout
    // that compared would report a GREASE pair this spec never sent.
    [Fact]
    public async Task AnExtraSettingIdentifierAddsARow()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        var without = Describe(await RecordHttp3Async(cancellation.Token));
        var with = Describe(await RecordHttp3Async(
            cancellation.Token,
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 262144),
                    new TlsQuicHttp3Setting(0x22, 1),
                ],
            }));

        Assert.Equal(RowsOf(without).Count + 1, RowsOf(with).Count);
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Mismatch,
            CellOf(with, "settings 0x22 sent by us, absent from the capture", 4));

        // s7.2.4.1's reserved form is RECOMPUTED, not compared against the base: 0x22 is above
        // 0x21 and is not reserved, so this spec sent no GREASE pair and the row must say so.
        Assert.Equal("absent", CellOf(with, "settings reserved (GREASE) pair", 2));
        Assert.Equal("6:262144;34:1", CellOf(with, "perk segment 1, whole", 2));
    }

    // THE CONTIGUITY GUARD. Every producer inside this tree hands over frames a QUIC receiver
    // has already reassembled, so no in-contract recording can carry a hole - but this readout
    // reports BYTE POSITIONS, and a hole would silently shift every field after it rather than
    // fail. An out-of-contract caller gets a named failure instead of a plausible readout.
    [Fact]
    public void AHoleInTheRecordingIsRefused()
    {
        var whole = RequestOnlyRecording(ReadoutRequest(), new TlsQuicHttp3Spec());
        var holed = new List<(ulong StreamId, ulong Offset, byte[] Data, bool Fin)>
        {
            (FirstRequestStreamId, 0UL, whole[0].Data[..4], false),
            (FirstRequestStreamId, 8UL, whole[0].Data[4..], true),
        };

        var thrown = Assert.Throws<InvalidOperationException>(
            () => TlsQuicHttp3FingerprintReadout.Describe(
                holed, SpecTransportParameters(), DefaultDestinationConnectionIdLength, ReadoutClientHello));
        Assert.Contains("contiguous sequence from offset zero", thrown.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheSegmentDiffNamesTheFirstDifferingIndex()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        var readout = Describe(await RecordHttp3Async(
            cancellation.Token,
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 6),
                ],
            }));

        // ours "1:6", brave "1:65536;..." - identical for three characters, then ours ends.
        Assert.Contains(
            "first difference at index 3: ours <end>, brave '5'",
            readout,
            StringComparison.Ordinal);
    }

    // THE HAND-RUN MEASUREMENT OF 2026-08-20, MADE OFFLINE AND REPEATABLE - which is what this
    // task exists for. That run drove TlsQuicHttp3Connection against
    // https://fp.impersonate.pro/api/http3 and its perk_text read
    // `1:0;6:262144;7:0 | m,a,s,p`, three MISMATCHes and one match in segment 1 and an exact
    // match in segment 2.
    //
    // AND IT USED A NARROWED SPEC, WHICH THE HANDOFF DID NOT SAY. TlsQuicHttp3Spec's DEFAULT
    // Settings is CaptureSettings - all five of the capture's pairs, 51:1 and the reserved pair
    // included - so `new TlsQuicHttp3Spec()` renders segment 1 as an exact match, which is what
    // the snapshot pins. The live run overrode it to advertise QPACK_MAX_TABLE_CAPACITY 0 and
    // QPACK_BLOCKED_STREAMS 0, because C5-C8's decoder is static-only and advertising 65536
    // would be advertising a dynamic table nothing can fill. BOTH READINGS ARE CORRECT AND THEY
    // ARE ABOUT DIFFERENT SPECS; this test pins the live one so the two can never be confused.
    [Fact]
    public async Task TheLiveMeasurementOfTheTwentiethOfAugustIsReproducedOffline()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        // THE NARROWING STAYS, AND AFTER C16 IT IS A DELIBERATE CONFIGURATION RATHER THAN A
        // LIMITATION. This test reproduces a DATED measurement - the twentieth of August - and
        // the assertion below pins the exact string `1:0;6:262144;7:0` that run emitted. Those
        // are the settings that run sent, so they are the settings this reproduction must send;
        // swapping them for the shipped defaults would not fix anything, it would change what
        // is being reproduced. C16 made the default arm reachable, which is asserted where the
        // default arm belongs - TlsQuicHttp3StreamsTests.TheShippedDefaultsGiveATableAndThe
        // CapturesBlockedStreamBound and the live interop run - and not here.
        var readout = Describe(await RecordHttp3Async(
            cancellation.Token,
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 0),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 262144),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 0),
                ],
            },
            ReadoutRequest()));

        Assert.Contains(
            "    ours   1:0;6:262144;7:0 | m,a,s,p", readout, StringComparison.Ordinal);
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Mismatch,
            CellOf(readout, "settings 0x01 SETTINGS_QPACK_MAX_TABLE_CAPACITY", 4));
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Match,
            CellOf(readout, "settings 0x06 SETTINGS_MAX_FIELD_SECTION_SIZE", 4));
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Mismatch,
            CellOf(readout, "settings 0x07 SETTINGS_QPACK_BLOCKED_STREAMS", 4));
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Mismatch,
            CellOf(readout, "settings 0x33 SETTINGS_H3_DATAGRAM", 4));
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Mismatch,
            CellOf(readout, "settings reserved (GREASE) pair", 4));

        // Segment 2 matched live against a server we do not control, and it matches here.
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Match,
            CellOf(readout, "pseudo-header order (perk segment 2)", 4));

        // Segment 3's order, as the live run's own profile assembled it.
        Assert.Equal(
            "15,14,4,5,6,7,8,9",
            CellOf(readout, "transport parameter wire order (perk segment 3) [subsystem B]", 2));
    }

    // ------------------------------------------------------------------------
    // Segment 2: the pseudo-header order.
    // ------------------------------------------------------------------------

    // THE ALL-PERMUTATIONS TEST, AND THE REASON IT EXISTS. C9 recorded a mutant that hard-coded
    // the capture's order and passed its stated done-when, because every test used that order.
    // Twenty-four rows: the rendered order must be the EMITTED order every time, and the
    // verdict must be match for exactly one of them.
    [Theory]
    [MemberData(nameof(PseudoHeaderPermutations))]
    public void EveryPseudoHeaderOrderRendersItself(string expected)
    {
        var order = expected.Split(',').Select(letter => letter switch
        {
            "m" => TlsQuicHttp3PseudoHeader.Method,
            "a" => TlsQuicHttp3PseudoHeader.Authority,
            "s" => TlsQuicHttp3PseudoHeader.Scheme,
            _ => TlsQuicHttp3PseudoHeader.Path,
        }).ToImmutableArray();

        var readout = TlsQuicHttp3FingerprintReadout.Describe(
            RequestOnlyRecording(ReadoutRequest(), new TlsQuicHttp3Spec { PseudoHeaderOrder = order }),
            SpecTransportParameters(),
            DefaultDestinationConnectionIdLength, ReadoutClientHello);

        Assert.Equal(expected, CellOf(readout, "pseudo-header order (perk segment 2)", 2));
        Assert.Equal(
            expected == "m,a,s,p"
                ? TlsQuicHttp3FingerprintReadout.Match
                : TlsQuicHttp3FingerprintReadout.Mismatch,
            CellOf(readout, "pseudo-header order (perk segment 2)", 4));
    }

    public static TheoryData<string> PseudoHeaderPermutations()
    {
        var data = new TheoryData<string>();
        string[] letters = ["m", "a", "s", "p"];
        foreach (var first in letters)
        {
            foreach (var second in letters.Where(letter => letter != first))
            {
                foreach (var third in letters.Where(
                    letter => letter != first && letter != second))
                {
                    var fourth = letters.Single(
                        letter => letter != first && letter != second && letter != third);
                    data.Add($"{first},{second},{third},{fourth}");
                }
            }
        }

        return data;
    }

    // ------------------------------------------------------------------------
    // The QPACK rows, which stay not-yet-known however precisely they are measured.
    // ------------------------------------------------------------------------

    // STRING LITERALS, NOT FIELD LINES. The capture request encodes four field lines and
    // exactly two string literals - :method GET and :scheme https are full static matches and
    // carry none - so a scan counting lines would report a different denominator.
    [Theory]
    [InlineData(true, "H set on 2 of 2 string literals")]
    [InlineData(false, "H set on 0 of 2 string literals")]
    public void TheHuffmanRowCountsStringLiteralsAndNotFieldLines(bool huffman, string expected)
    {
        var readout = TlsQuicHttp3FingerprintReadout.Describe(
            RequestOnlyRecording(
                ReadoutRequest(),
                new TlsQuicHttp3Spec { QpackHuffmanStringLiterals = huffman }),
            SpecTransportParameters(),
            DefaultDestinationConnectionIdLength, ReadoutClientHello);

        Assert.Equal(expected, CellOf(readout, "QPACK Huffman flag policy", 2));

        // Finding 5: the capture decides neither, so no amount of measurement moves this cell.
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.NotYetKnown,
            CellOf(readout, "QPACK Huffman flag policy", 4));
    }

    // THE GUARD ON THE SECOND WALK. TlsQuicQpackDecoder is authoritative for names and values;
    // the representation scan is a separate walk over the same bytes for the two things the
    // decoder throws away. If the scan mis-read one of s4.5's patterns it would drift out of
    // step, so its entry count is pinned to the pseudo-header count the decoder produced.
    [Fact]
    public void TheRepresentationScanAgreesWithTheProductionDecoder()
    {
        var readout = TlsQuicHttp3FingerprintReadout.Describe(
            RequestOnlyRecording(ReadoutRequest(), new TlsQuicHttp3Spec()),
            SpecTransportParameters(),
            DefaultDestinationConnectionIdLength, ReadoutClientHello);

        // Four field lines from the decoder, four representations from the scan, and the two
        // full static matches sit where the encoder's own header says they will: s4.5.2 for
        // name-and-value, s4.5.4 for a name reference with a literal value.
        Assert.Equal("m,a,s,p", CellOf(readout, "pseudo-header order (perk segment 2)", 2));
        Assert.Equal(
            "4.5.2,4.5.4,4.5.2,4.5.4",
            CellOf(readout, "QPACK name-match policy, s4.5.2 against s4.5.4", 2));
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.NotYetKnown,
            CellOf(readout, "QPACK name-match policy, s4.5.2 against s4.5.4", 4));
    }

    // s4.2.2's SEND half, measured against the capture's own advertised 262144 by decoding the
    // emitted field section back. A field section past it flips the row.
    [Fact]
    public void TheSendHalfOfMaxFieldSectionSizeIsMeasuredAgainstTheCapture()
    {
        var within = TlsQuicHttp3FingerprintReadout.Describe(
            RequestOnlyRecording(ReadoutRequest(), new TlsQuicHttp3Spec()),
            SpecTransportParameters(),
            DefaultDestinationConnectionIdLength, ReadoutClientHello);
        Assert.Equal(
            "4 field lines, within",
            CellOf(within, "s4.2.2 send half - the emitted field section against that limit", 2));
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Match,
            CellOf(within, "s4.2.2 send half - the emitted field section against that limit", 4));

        var over = TlsQuicHttp3FingerprintReadout.Describe(
            RequestOnlyRecording(
                new TlsQuicHttp3Request
                {
                    Method = "GET",
                    Scheme = "https",
                    Authority = ReadoutAuthority,
                    Path = "/" + new string('a', 300_000),
                },
                new TlsQuicHttp3Spec()),
            SpecTransportParameters(),
            DefaultDestinationConnectionIdLength, ReadoutClientHello);
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Mismatch,
            CellOf(over, "s4.2.2 send half - the emitted field section against that limit", 4));
    }

    // ------------------------------------------------------------------------
    // The remaining not-yet-known rows.
    // ------------------------------------------------------------------------

    // EMISSION ORDER, NOT IDENTIFIER ORDER. s6.2 fixes no order for the three unidirectional
    // streams and the capture publishes none, so a readout that sorted by stream id would
    // report a canonical answer for every emitter - the same defect Finding 7 names one layer
    // up. The spec's order here is the reverse of the default.
    [Fact]
    public async Task TheStreamOpenOrderIsEmissionOrderAndNotIdOrder()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        var readout = Describe(await RecordHttp3Async(
            cancellation.Token,
            new TlsQuicHttp3Spec
            {
                UnidirectionalStreamOpenOrder =
                [
                    TlsQuicHttp3StreamType.QpackDecoder,
                    TlsQuicHttp3StreamType.QpackEncoder,
                    TlsQuicHttp3StreamType.Control,
                ],
            }));

        Assert.Equal(
            "qpack-decoder,qpack-encoder,control",
            CellOf(readout, "unidirectional stream open order", 2));
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.NotYetKnown,
            CellOf(readout, "unidirectional stream open order", 4));

        // And the SETTINGS still came off the control stream wherever it was opened - the
        // spec's default five, since this test overrides only the stream order.
        Assert.Equal("1,6,7,51,GREASE", CellOf(readout, "settings wire order", 2));
    }

    // THE ONE RECORDING THAT SEPARATES EMISSION ORDER FROM IDENTIFIER ORDER, and it has to be
    // built by hand because no connection in this tree can produce one: TlsQuicStreamSet hands
    // out s2.1 ordinals in open order, so for anything the HTTP/3 layer emits the two orders
    // COINCIDE. A readout that sorted by stream id would be indistinguishable on every real
    // recording and wrong the first time it read someone else's.
    [Fact]
    public void TheStreamOpenOrderIsEmissionOrderAndNotIdentifierOrder()
    {
        var readout = TlsQuicHttp3FingerprintReadout.Describe(
            [
                UniStreamFrame(10, TlsQuicHttp3StreamType.Control),
                UniStreamFrame(2, TlsQuicHttp3StreamType.QpackDecoder),
                UniStreamFrame(6, TlsQuicHttp3StreamType.QpackEncoder),
            ],
            SpecTransportParameters(),
            DefaultDestinationConnectionIdLength, ReadoutClientHello);

        Assert.Equal(
            "control,qpack-decoder,qpack-encoder",
            CellOf(readout, "unidirectional stream open order", 2));
    }

    private static (ulong StreamId, ulong Offset, byte[] Data, bool Fin) UniStreamFrame(
        ulong streamId, TlsQuicHttp3StreamType type)
    {
        var bytes = new List<byte>();
        QuicVariableLengthInteger.Write(bytes, (ulong)type);
        return (streamId, 0UL, bytes.ToArray(), false);
    }

    // THREE ROWS, NOT ONE - C9's finding. N, payload and position are independent unknowns and
    // one row would let an emitter match one while missing another.
    [Fact]
    public async Task AReservedFrameOnTheRequestStreamIsMeasured()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        var none = Describe(await RecordHttp3Async(
            cancellation.Token, request: ReadoutRequest()));
        Assert.Equal(
            "none emitted", CellOf(none, "reserved (GREASE) request-stream frame - N", 2));

        var greased = Describe(await RecordHttp3Async(
            cancellation.Token,
            new TlsQuicHttp3Spec { SendReservedFramesOnRequestStreams = true },
            ReadoutRequest()));

        Assert.NotEqual(
            "none emitted", CellOf(greased, "reserved (GREASE) request-stream frame - N", 2));
        foreach (var half in new[] { "N", "payload", "position" })
        {
            Assert.Equal(
                TlsQuicHttp3FingerprintReadout.NotYetKnown,
                CellOf(greased, $"reserved (GREASE) request-stream frame - {half}", 4));
        }
    }

    // ------------------------------------------------------------------------
    // The whole-table properties.
    // ------------------------------------------------------------------------

    [Fact]
    public async Task TheVerdictCountsAreDerivedFromTheRowsAndNotAssertedBesideThem()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);

        // TWO RECORDINGS WHOSE COUNTS DIFFER, because one is not enough: the default spec
        // renders 15 / 2 / 8 and a renderer that wrote those three numbers down instead of
        // counting them would pass against it forever. The live run's narrower SETTINGS move
        // five rows between the first two columns and nothing would notice.
        //
        // C16 LEFT THIS ONE ALONE AND THE NARROWING IS INCIDENTAL. What this test needs is TWO
        // SPECS WHOSE ROW COUNTS DIFFER; the narrowed one is simply a second spec that happens
        // to be at hand, and any other pair would do. It is not asserting anything about QPACK
        // capacity, so there is nothing here for C16 to have closed.
        AssertCountsAreCounted(Describe(await RecordHttp3Async(
            cancellation.Token, request: ReadoutRequest())));
        AssertCountsAreCounted(Describe(await RecordHttp3Async(
            cancellation.Token,
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 0),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 262144),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 0),
                ],
            },
            ReadoutRequest())));
    }

    private static void AssertCountsAreCounted(string readout)
    {
        var rows = RowsOf(readout);

        // THE VERDICT COLUMN HOLDS THREE VALUES AND NOTHING ELSE. A fourth would be a verdict
        // subsystem B cannot count, and this is the only assertion that would see one.
        string[] allowed =
        [
            TlsQuicHttp3FingerprintReadout.Match,
            TlsQuicHttp3FingerprintReadout.Mismatch,
            TlsQuicHttp3FingerprintReadout.NotYetKnown,
        ];
        foreach (var row in rows)
        {
            Assert.Contains(row[^1], allowed);
        }

        var match = rows.Count(row => row[^1] == TlsQuicHttp3FingerprintReadout.Match);
        var mismatch = rows.Count(row => row[^1] == TlsQuicHttp3FingerprintReadout.Mismatch);
        var unknown = rows.Count(row => row[^1] == TlsQuicHttp3FingerprintReadout.NotYetKnown);

        Assert.Contains($"    rows                            {rows.Count}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    match                           {match}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    MISMATCH                        {mismatch}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    not-yet-known-from-the-capture  {unknown}\n", readout, StringComparison.Ordinal);
        Assert.Contains($"    {match} + {mismatch} + {unknown} = {rows.Count}\n", readout, StringComparison.Ordinal);

        // The plan's floor: the five SETTINGS pairs and the pseudo-header order are settled and
        // must NEVER carry the third value.
        foreach (var settled in new[]
        {
            "settings 0x01 SETTINGS_QPACK_MAX_TABLE_CAPACITY",
            "settings 0x06 SETTINGS_MAX_FIELD_SECTION_SIZE",
            "settings 0x07 SETTINGS_QPACK_BLOCKED_STREAMS",
            "settings 0x33 SETTINGS_H3_DATAGRAM",
            "settings reserved (GREASE) pair",
            "pseudo-header order (perk segment 2)",
        })
        {
            Assert.NotEqual(
                TlsQuicHttp3FingerprintReadout.NotYetKnown, CellOf(readout, settled, 4));
        }
    }

    // The plan forbids C re-filing the transport-parameter wire order as its own failure. The
    // rows exist so a perk readout is not missing a perk segment, and they name their owner.
    [Fact]
    public async Task SegmentsThreeAndFourAreNamedAsSubsystemBs()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        var readout = Describe(await RecordHttp3Async(
            cancellation.Token, request: ReadoutRequest()));

        foreach (var row in RowsOf(readout).Where(row => row[1].Contains(
            "[subsystem B]", StringComparison.Ordinal)))
        {
            Assert.NotEqual(TlsQuicHttp3FingerprintReadout.NotYetKnown, row[^1]);
        }

        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Mismatch,
            CellOf(readout, "transport parameter wire order (perk segment 3) [subsystem B]", 4));
        Assert.Contains("[subsystem B] ARE NOT SCORED AGAINST C", readout, StringComparison.Ordinal);
    }

    // The six flow-control values the live measurement confirmed. Hard-coding them to the
    // capture's would read match on every row forever, and the default spec already carries
    // exactly the capture's six - so only moving one can tell the two apart.
    [Theory]
    [InlineData(0x04UL, "initial_max_data")]
    [InlineData(0x05UL, "initial_max_stream_data_bidi_local")]
    [InlineData(0x06UL, "initial_max_stream_data_bidi_remote")]
    [InlineData(0x07UL, "initial_max_stream_data_uni")]
    [InlineData(0x08UL, "initial_max_streams_bidi")]
    [InlineData(0x09UL, "initial_max_streams_uni")]
    public void AFlowControlParameterThatMovesFlipsItsRow(ulong id, string name)
    {
        var field = $"transport parameter 0x{id:x2} {name} [subsystem B]";
        var recording = RequestOnlyRecording(ReadoutRequest(), new TlsQuicHttp3Spec());

        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Match,
            CellOf(
                TlsQuicHttp3FingerprintReadout.Describe(
                    recording, SpecTransportParameters(), DefaultDestinationConnectionIdLength, ReadoutClientHello),
                field,
                4));

        var moved = SpecTransportParameters().Parameters
            .Select(parameter => parameter.Id == id
                ? new TlsQuicTransportParameter(parameter.Id, new byte[] { 0x01 })
                : parameter)
            .ToList();
        Assert.Equal(
            TlsQuicHttp3FingerprintReadout.Mismatch,
            CellOf(
                TlsQuicHttp3FingerprintReadout.Describe(
                    recording,
                    new TlsQuicTransportParameters(moved),
                    DefaultDestinationConnectionIdLength, ReadoutClientHello),
                field,
                4));
    }

    // ------------------------------------------------------------------------
    // The ALPN row, which task B8 moved out of the third column. See the readout's own
    // header for why it used to sit there.
    // ------------------------------------------------------------------------

    [Fact]
    public void TheAlpnRowRendersTheWholeOfferedListAndScoresItAgainstTheCapturesOne()
    {
        // NOT A CONTAINMENT TEST. RFC 9114 s3.2 lets a conforming client offer more than h3,
        // and the capture's client offers exactly one token - so a client offering two is a
        // different client and the row must say so. A readout that asked "is h3 in there?"
        // would score this `match` and is killed here.
        var readout = TlsQuicHttp3FingerprintReadout.Describe(
            RequestOnlyRecording(ReadoutRequest(), new TlsQuicHttp3Spec()),
            SpecTransportParameters(),
            DefaultDestinationConnectionIdLength,
            new TlsQuicClientHelloProfileFactory { AlpnProtocols = ["h3", "http/1.1"] }
                .Create([])
                .BuildDeterministicForTesting("example.test", [0x42]));

        Assert.Equal("h3,http/1.1", CellOf(readout, AlpnField, 2));
        Assert.Equal(TlsQuicHttp3FingerprintReadout.Mismatch, CellOf(readout, AlpnField, 4));
    }

    [Fact]
    public void AClientHelloOfferingNoAlpnRendersAbsentRatherThanAnEmptyCell()
    {
        var readout = TlsQuicHttp3FingerprintReadout.Describe(
            RequestOnlyRecording(ReadoutRequest(), new TlsQuicHttp3Spec()),
            SpecTransportParameters(),
            DefaultDestinationConnectionIdLength,
            ClientHelloProfiles.ModernTls13.BuildDeterministicForTesting("example.test", [0x42]));

        Assert.Equal("absent", CellOf(readout, AlpnField, 2));
        Assert.Equal(TlsQuicHttp3FingerprintReadout.Mismatch, CellOf(readout, AlpnField, 4));
    }

    [Fact]
    public void BytesThatDoNotParseAsAClientHelloBecomeARowRatherThanAnException()
    {
        // A readout describes a connection that already happened. Throwing here would destroy
        // the other twenty-four rows over one unparsable input, which is the opposite of what
        // this file is for.
        var readout = TlsQuicHttp3FingerprintReadout.Describe(
            RequestOnlyRecording(ReadoutRequest(), new TlsQuicHttp3Spec()),
            SpecTransportParameters(),
            DefaultDestinationConnectionIdLength,
            [0x01, 0x02, 0x03]);

        Assert.Equal("unparsable-ClientHello", CellOf(readout, AlpnField, 2));
        Assert.Equal(TlsQuicHttp3FingerprintReadout.Mismatch, CellOf(readout, AlpnField, 4));
    }

    [Fact]
    public void ADescribeWithoutAClientHelloIsRefused()
    {
        var thrown = Assert.Throws<ArgumentNullException>(
            () => TlsQuicHttp3FingerprintReadout.Describe(
                RequestOnlyRecording(ReadoutRequest(), new TlsQuicHttp3Spec()),
                SpecTransportParameters(),
                DefaultDestinationConnectionIdLength,
                null!));
        Assert.Equal("encodedClientHello", thrown.ParamName);
    }

    private const string AlpnField = "ALPN token (RFC 9114 s3.2)";

    [Fact]
    public void AnEmptyRecordingIsRefused()
    {
        var empty = new List<(ulong StreamId, ulong Offset, byte[] Data, bool Fin)>();
        var thrown = Assert.Throws<ArgumentException>(
            () => TlsQuicHttp3FingerprintReadout.Describe(
                empty, SpecTransportParameters(), DefaultDestinationConnectionIdLength, ReadoutClientHello));
        Assert.Equal("emittedStreamFrames", thrown.ParamName);
    }

    // ------------------------------------------------------------------------
    // Helpers.
    // ------------------------------------------------------------------------

    /// <summary>TlsQuicConnectionSpec's own default, which is RFC 9000 s7.2's floor for a
    /// client-chosen Destination Connection ID.</summary>
    private const int DefaultDestinationConnectionIdLength = 8;

    /// <summary>The ClientHello every readout on this class is described against: task B8's
    /// factory with its own defaults, encoded.</summary>
    /// <remarks>THE FACTORY'S REAL OUTPUT AND NOT A HAND-BUILT PROFILE, because the ALPN row
    /// exists to measure what this library actually sends. A fixture that named "h3" itself
    /// would score the fixture - which is precisely the failure the readout's ALPN block is a
    /// correction of - and would go on passing if the factory stopped offering h3.</remarks>
    private static readonly byte[] ReadoutClientHello =
        new TlsQuicClientHelloProfileFactory()
            .Create([])
            .BuildDeterministicForTesting("example.test", [0x42]);

    private static string Http3SnapshotPath => Path.Combine(
        AppContext.BaseDirectory, "Quic", "quic-http3-fingerprint-readout.snapshot.txt");

    private static string NormalizeReadout(string text) =>
        text.Replace("\r\n", "\n", StringComparison.Ordinal);

    private static TlsQuicHttp3Request ReadoutRequest() => new()
    {
        Method = "GET",
        Scheme = "https",
        Authority = ReadoutAuthority,
        Path = ReadoutPath,
    };

    /// <summary>The transport parameters a client of this tree puts in its ClientHello, IN THE
    /// ORDER IT PUTS THEM THERE.</summary>
    /// <remarks>
    /// <para>THE ORDER IS COPIED FROM THE ONE CALLER THAT HAS EVER REACHED A REAL SERVER,
    /// QuicPublicEndpointInteropTests' profile: initial_source_connection_id, then
    /// active_connection_id_limit, then TlsQuicLocalFlowControlSpec.ToTransportParameters()'s
    /// six. Getting that order from anywhere else would make the wire-order row a statement
    /// about this test rather than about the client, and order is the whole content of that
    /// row.</para>
    /// <para>SUPPLIED, NOT MEASURED, and TlsQuicHttp3FingerprintReadout's header says why:
    /// re-reading them off the emitted datagrams would be a second copy of
    /// TlsQuicFingerprintReadout's ClientHello walk.</para>
    /// </remarks>
    private static TlsQuicTransportParameters SpecTransportParameters(
        byte[]? sourceConnectionId = null) =>
        new(
        [
            new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
                sourceConnectionId ?? new byte[SourceConnectionIdLength]),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.ActiveConnectionIdLimit, 2),
            .. new TlsQuicConnectionSpec().LocalFlowControl.ToTransportParameters(),
        ]);

    private static string Describe(
        (IReadOnlyList<(ulong StreamId, ulong Offset, byte[] Data, bool Fin)> Frames,
            TlsQuicTransportParameters Parameters,
            int DestinationConnectionIdLength) recording) =>
        TlsQuicHttp3FingerprintReadout.Describe(
            recording.Frames, recording.Parameters, recording.DestinationConnectionIdLength, ReadoutClientHello);

    /// <summary>Drives one HTTP/3 connection to its opening flight, optionally one request, and
    /// hands back exactly the STREAM frames the loopback PEER DECRYPTED.</summary>
    private static async Task<(
        IReadOnlyList<(ulong StreamId, ulong Offset, byte[] Data, bool Fin)> Frames,
        TlsQuicTransportParameters Parameters,
        int DestinationConnectionIdLength)>
        RecordHttp3Async(
            CancellationToken cancellationToken,
            TlsQuicHttp3Spec? spec = null,
            TlsQuicHttp3Request? request = null)
    {
        using var harness = await Harness.CreateAsync(
            cancellationToken, spec, openLocalStreams: false);
        harness.Http3.OpenLocalStreams();
        await harness.FlushAsync(cancellationToken);

        if (request is not null)
        {
            var stream = harness.Http3.TryOpenRequest(request, out var refusal, out var malformed);
            Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
            Assert.Equal(TlsQuicHttp3RequestError.None, malformed);
            Assert.NotNull(stream);
            await harness.FlushAsync(cancellationToken);
        }

        return (
            harness.Peer.ReceivedStreamFrames.ToList(),
            SpecTransportParameters(harness.Connection.SourceConnectionId.ToArray()),
            harness.Connection.OriginalDestinationConnectionId.Length);
    }

    /// <summary>A recording holding one request stream and nothing else, encoded through the
    /// same TlsQuicHttp3Request.TryEncode the connection calls.</summary>
    private static List<(ulong StreamId, ulong Offset, byte[] Data, bool Fin)>
        RequestOnlyRecording(TlsQuicHttp3Request request, TlsQuicHttp3Spec spec)
    {
        var bytes = new List<byte>();
        Assert.True(request.TryEncode(bytes, spec, out var error), $"encode refused: {error}");
        return [(FirstRequestStreamId, 0UL, bytes.ToArray(), true)];
    }

    /// <summary>Every table row of a rendered readout, split into its cells.</summary>
    private static List<string[]> RowsOf(string readout) =>
        NormalizeReadout(readout).Split('\n')
            .Where(line => line.StartsWith("| ", StringComparison.Ordinal)
                && !line.StartsWith("| # |", StringComparison.Ordinal)
                && !line.StartsWith("| ---", StringComparison.Ordinal))
            .Select(line => line.Trim('|').Split('|').Select(cell => cell.Trim()).ToArray())
            .ToList();

    /// <summary>One cell of the row whose field name is <paramref name="field"/>. Column 2 is
    /// "ours", 3 is "brave" and 4 is the verdict.</summary>
    private static string CellOf(string readout, string field, int column)
    {
        var row = RowsOf(readout).SingleOrDefault(
            candidate => candidate[1] == field);
        Assert.True(row is not null, $"No row named \"{field}\" in the readout.");
        return row![column];
    }
}
