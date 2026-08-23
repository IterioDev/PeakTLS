using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Protocol;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task 11 of A4-minimal: the fingerprint readout.
//
// ============================================================================
// WHAT THESE ASSERTIONS PIN, AND WHAT THEY CANNOT.
// ============================================================================
//
// THE SNAPSHOT IS NOT EVIDENCE ABOUT CHROMIUM. It is evidence that today's emitted bytes are
// the same bytes as yesterday's. Every number in it was produced by us, so it can only catch a
// CHANGE, never a wrong choice - which is exactly what A2's rule about numbers with no external
// source says, and why the file says SNAPSHOT in its first line.
//
// THE ONE ASSERTION HERE THAT IS NOT A SNAPSHOT is
// TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith. It is the anti-tautology witness: the same
// recording is rendered twice against two specs that disagree on every knob, and the "quic"
// block must come out identical. A readout that read any of those fields off the spec fails it.
// Without that test the whole readout could be a restatement and every other test here would
// still pass.
//
// WHAT NO TEST HERE CAN DO is tell a plausible layout from Chromium's. Only a packet capture
// can, and the not-yet-known column of the task 11 report is the list of what to capture.
public sealed class TlsQuicFingerprintReadoutTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(60);

    // NON-ZERO ON PURPOSE, for the reason TlsQuicConnectionTests gives: the target profile's
    // source connection ID is zero bytes, which erases the header field that witnesses
    // initial_source_connection_id agreeing with it.
    private const int SourceConnectionIdLength = 5;

    private static readonly DateTimeOffset SentAt =
        new(2026, 8, 18, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task TheReadoutMatchesTheCheckedInSnapshot()
    {
        var (datagrams, spec) = await RecordAFullHandshakeAsync();
        var readout = TlsQuicFingerprintReadout.Describe(datagrams, spec);

        var expected = Normalize(await File.ReadAllTextAsync(SnapshotPath));
        var actual = Normalize(readout);
        if (expected != actual)
        {
            // THE MESSAGE NAMES THE FIELD THAT MOVED, and that is the whole difference between
            // a ratchet and a ratchet with a pawl. `initial_frame_order`, `initial_padding_bytes`
            // and the per-datagram rows are pinned by this snapshot ALONE, so a later task that
            // moves the wire output sees only this failure - and a failure reading "strings
            // differ, actual written to a temp file that CI has already discarded" invites a
            // re-baseline, which silently throws away the fingerprint this task exists to hold.
            var expectedLines = expected.Split('\n');
            var actualLines = actual.Split('\n');
            var line = 0;
            while (line < expectedLines.Length
                && line < actualLines.Length
                && expectedLines[line] == actualLines[line])
            {
                line++;
            }

            var expectedLine = line < expectedLines.Length ? expectedLines[line] : "<end of file>";
            var actualLine = line < actualLines.Length ? actualLines[line] : "<end of file>";

            // Written out as well, because the FIRST difference is not always the whole story.
            var scratch = Path.Combine(Path.GetTempPath(), "quic-fingerprint-readout.actual.txt");
            await File.WriteAllTextAsync(scratch, actual);
            Assert.Fail(
                $"The readout no longer matches the snapshot at {FieldNameIn(expectedLine)}, "
                + $"snapshot line {line + 1}.\n"
                + $"  snapshot: {expectedLine}\n"
                + $"  actual:   {actualLine}\n"
                + "RE-BASELINE ONLY IF THAT FIELD WAS MEANT TO MOVE - it is pinned here and\n"
                + $"nowhere else. Whole actual written to {scratch}.");
        }
    }

    /// <summary>The rendered field name on a readout line, or a description of the line when it
    /// carries no field - prose lines and the datagram rows both reach here.</summary>
    private static string FieldNameIn(string line)
    {
        var start = line.IndexOf('"');
        if (start < 0)
        {
            return "a line outside the \"quic\" block";
        }

        var end = line.IndexOf('"', start + 1);
        return end < 0 ? "a line outside the \"quic\" block" : line[start..(end + 1)];
    }

    [Fact]
    public async Task TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith()
    {
        // THE ANTI-TAUTOLOGY WITNESS. One recording, two specs that disagree on every layout
        // knob the readout reports - including both order knobs - and the measured block must
        // be byte-identical. Any field the renderer took from the spec instead of from the
        // datagrams moves here and fails.
        //
        // "EVERY KNOB" IS MEANT LITERALLY, AND USED NOT TO BE. An earlier revision left Token,
        // InitialCryptoFrameByteCounts, InitialCryptoFramesPerDatagram, InitialFrameOrder,
        // InitialRttRange and AckRangeLimit unset on both specs, so a renderer reading
        // token_length, token_prefix, initial_crypto_frame_byte_counts,
        // initial_flight_crypto_frames_per_datagram, initial_frame_order or
        // initial_rtt_parameter_present straight off the spec came out identical on both sides
        // and passed - four of those mutations were applied and survived 1069/1069. A guard
        // that leaks on the fields it is the only guard for is worse than no guard, because it
        // is cited as if it covered them. EVERY PROPERTY TlsQuicConnectionSpec DECLARES IS SET
        // BELOW, TO A DIFFERENT VALUE ON EACH SIDE. Adding a property to that type without
        // adding it here re-opens exactly this hole.
        var (datagrams, _) = await RecordAFullHandshakeAsync();

        var one = TlsQuicFingerprintReadout.Describe(datagrams, new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = 1,
            DestinationConnectionIdLength = 20,
            InitialPacketNumber = 4242,
            PacketNumberEncodedLength = 2,
            Token = new byte[] { 0xde, 0xad, 0xbe, 0xef, 0x01 },
            // TlsQuicConnectionSpec cross-checks these two: the per-datagram frame counts must
            // sum to the number of byte counts. 2 == 2 here, 1 + 2 == 3 below, so the two sides
            // disagree on both arrays while each stays internally valid.
            InitialCryptoFrameByteCounts = [64, 65000],
            InitialCryptoFramesPerDatagram = [2],
            InitialFrameOrder = [TlsQuicFrameType.Crypto, TlsQuicFrameType.Padding],
            HeaderLengthVarintWidth = TlsQuicVarintWidth.EightBytes,
            CryptoOffsetVarintWidth = TlsQuicVarintWidth.EightBytes,
            CryptoLengthVarintWidth = TlsQuicVarintWidth.EightBytes,
            InitialRttRange = null,
            AckRangeLimit = 32,
            // THE TWO KNOBS DISAGREE WITH EACH OTHER HERE, and with their opposites below, so
            // that a renderer printing one under the other's name is caught. Setting both to
            // true and both to false would let that swap through.
            CoalesceAscendingByLevel = true,
            AckLeadsInPacket = false,
        });
        var other = TlsQuicFingerprintReadout.Describe(datagrams, new TlsQuicConnectionSpec
        {
            PaddingTarget = 1400,
            SourceConnectionIdLength = 17,
            DestinationConnectionIdLength = 8,
            InitialPacketNumber = 0,
            PacketNumberEncodedLength = 4,
            Token = new byte[] { 0x77, 0x77 },
            InitialCryptoFrameByteCounts = [37, 41, 65000],
            InitialCryptoFramesPerDatagram = [1, 2],
            InitialFrameOrder = [TlsQuicFrameType.Padding, TlsQuicFrameType.Crypto],
            HeaderLengthVarintWidth = TlsQuicVarintWidth.Minimal,
            CryptoOffsetVarintWidth = TlsQuicVarintWidth.Minimal,
            CryptoLengthVarintWidth = TlsQuicVarintWidth.Minimal,
            InitialRttRange = (TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(300)),
            AckRangeLimit = 7,
            CoalesceAscendingByLevel = false,
            AckLeadsInPacket = true,
        });

        Assert.Equal(QuicBlockOf(one), QuicBlockOf(other));

        // B10 EXTENDS THE SAME WITNESS TO SEGMENT 3. Its rows are the readout's other
        // measurement of the ClientHello, and the two specs above differ in
        // TransportParameters as well - `one` keeps the default and `other` is given a spec
        // whose list is empty - so a renderer that composed segment 3 off the spec would
        // print fourteen rows on one side and none on the other.
        var third = TlsQuicFingerprintReadout.Describe(datagrams, new TlsQuicConnectionSpec
        {
            TransportParameters = new TlsQuicTransportParameterSpec { Parameters = [] },
        });
        Assert.Equal(SegmentThreeSectionOf(one), SegmentThreeSectionOf(third));

        // And the two knobs that ARE spec-sourced did move, which is what makes the equality
        // above a claim about the block rather than about a renderer that ignores its spec.
        Assert.Contains("spec.CoalesceAscendingByLevel = true", one, StringComparison.Ordinal);
        Assert.Contains("spec.CoalesceAscendingByLevel = false", other, StringComparison.Ordinal);
        Assert.Contains("spec.AckLeadsInPacket         = false", one, StringComparison.Ordinal);
        Assert.Contains("spec.AckLeadsInPacket         = true", other, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EveryLayoutKnobTheConnectionEmittedIsReadBackOutOfTheBytes()
    {
        // The other half of the same claim: change what the connection EMITS and every field
        // moves. Together with the test above this pins each field to the datagrams and to
        // nothing else. The values are deliberately all different from the snapshot's.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1300,
            SourceConnectionIdLength = 7,
            DestinationConnectionIdLength = 12,
            InitialPacketNumber = 127,
            PacketNumberEncodedLength = 1,
            HeaderLengthVarintWidth = TlsQuicVarintWidth.FourBytes,
            CryptoOffsetVarintWidth = TlsQuicVarintWidth.FourBytes,
            CryptoLengthVarintWidth = TlsQuicVarintWidth.FourBytes,
        };
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, spec, transport.Clock),
            source => TlsClient(pki, source));

        await connection.StartAsync(cancellation.Token);

        var readout = TlsQuicFingerprintReadout.Describe(Recorded(transport), spec);

        Assert.Contains("\"client_connection_id_length\": 7", readout, StringComparison.Ordinal);
        Assert.Contains("\"server_connection_id_length\": 12", readout, StringComparison.Ordinal);
        Assert.Contains("\"initial_packet_number\": 127", readout, StringComparison.Ordinal);
        Assert.Contains(
            "\"initial_packet_number_encoded_length\": 1", readout, StringComparison.Ordinal);
        Assert.Contains("\"datagram_padding_target\": [1300]", readout, StringComparison.Ordinal);
        Assert.Contains("\"header_length_varint_widths_whole_recording\": [4]", readout, StringComparison.Ordinal);
        Assert.Contains("\"crypto_offset_varint_widths\": [4]", readout, StringComparison.Ordinal);
        Assert.Contains("\"crypto_length_varint_widths\": [4]", readout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheCryptoSplitAndTheFlightPlanAreReadBackOutOfTheBytes()
    {
        // Two CRYPTO frames in one packet, which is the shape InitialCryptoFrameByteCounts
        // exists to produce. The readout must report BOTH halves separately - the split and
        // the per-datagram grouping - which is the affordance the plan's amendment after task
        // 1 kept the two arrays flat for.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            // 64 then "the rest": the final element may run short when the stream ends, which
            // is how the spec expresses a remainder no test may hardcode.
            InitialCryptoFrameByteCounts = [64, 65000],
            InitialCryptoFramesPerDatagram = [2],
        };
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, spec, transport.Clock),
            source => TlsClient(pki, source));

        await connection.StartAsync(cancellation.Token);

        // A DIFFERENT SPEC THAN THE ONE THAT BUILT THE CONNECTION, on purpose. Asserting
        // "[64, ...]" against the very object that says [64, 65000] is asserting a value
        // against the source of that value: a readout rendering these two fields off the spec
        // would pass it unchanged. Describe reads a spec for the two order knobs alone, and a
        // default spec agrees with this one on both, so the section it drives stays accurate.
        var readout = TlsQuicFingerprintReadout.Describe(
            Recorded(transport), new TlsQuicConnectionSpec());

        Assert.Contains("\"initial_flight_datagram_count\": 1", readout, StringComparison.Ordinal);
        Assert.Contains(
            "\"initial_flight_crypto_frames_per_datagram\": [2]", readout, StringComparison.Ordinal);

        // The first chunk's 64 bytes are the knob; the second is whatever the ClientHello has
        // left, which no test may hardcode - so this asserts the FIRST count and the presence
        // of a second, not a total nobody can recompute.
        var counts = FieldOf(readout, "initial_crypto_frame_byte_counts");
        Assert.StartsWith("[64, ", counts, StringComparison.Ordinal);
        Assert.Equal(2, counts.Split(',').Length);

        // Frame ORDER, not just frame presence: two CRYPTO frames then the padding run.
        Assert.Contains("\"initial_frame_order\": [\"Cryptox2,Padding", readout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheTokenLengthAndPrefixAreReadOffTheHeaderRatherThanAssumedEmpty()
    {
        // PRESENCE IS NOT IDENTITY: every other test here sees a zero-length token, which is
        // also what a field hardcoded to "empty" would report. Only a non-empty token can tell
        // the two apart, and RFC 9000 s17.2.2 puts the Token in the Initial header in the
        // clear, so it is measurable without any key.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            Token = new byte[] { 0xde, 0xad, 0xbe, 0xef, 0x01 },
        };
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, spec, transport.Clock),
            source => TlsClient(pki, source));

        await connection.StartAsync(cancellation.Token);

        // A DEFAULT SPEC, whose Token is empty - so these two assertions cannot be satisfied by
        // a readout that renders them off the spec it is handed. Feeding back the same spec
        // object made this test pass identically against a spec-reading renderer, which is the
        // defect shape this file keeps paying for.
        var readout = TlsQuicFingerprintReadout.Describe(
            Recorded(transport), new TlsQuicConnectionSpec());

        Assert.Contains("\"token_length\": 5", readout, StringComparison.Ordinal);
        Assert.Contains("\"token_prefix\": \"DEADBEEF01\"", readout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AZeroLengthSourceConnectionIdIsReportedAsErasingItsOwnWitness()
    {
        // THE TARGET'S OWN SHAPE. Chromium's client_connection_id_length is 0, and at zero
        // length both sides of the initial_source_connection_id comparison are empty - so the
        // agreement holds for a connection that never took the value from anywhere. The
        // readout must say the witness is gone rather than print a pass.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = 0,
        };
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, spec, transport.Clock),
            source => TlsClient(pki, source));

        await connection.StartAsync(cancellation.Token);

        var readout = TlsQuicFingerprintReadout.Describe(Recorded(transport), spec);

        Assert.Contains("\"client_connection_id_length\": 0", readout, StringComparison.Ordinal);
        Assert.Contains(
            "\"initial_source_connection_id_equals_header_source\": "
                + "\"unobservable-at-zero-length-source-cid\"",
            readout,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnInitialSourceConnectionIdThatDisagreesWithTheHeaderIsReportedAsDifferent()
    {
        // THE WITNESS THAT THIS VERDICT CAN FAIL AT ALL. Every other recording in this file
        // advertises a parameter equal to the header's Source Connection ID, so "agrees" is
        // also what a comparison doing nothing would print - and it is what the LENGTH-only
        // comparison this field used to make printed for five bytes agreeing about nothing.
        // Replacing the whole verdict with the constant survived 1069/1069 before this test.
        // The ClientHello here carries the bitwise complement of the connection's own five-byte
        // source CID: same length, no byte in common, so only a value test can separate them.
        // RFC 9000 s7.3 makes that a disagreement rather than a shrug.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
        };
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, spec, transport.Clock),
            source => TlsClient(pki, source.ToArray().Select(b => (byte)~b).ToArray()));

        await connection.StartAsync(cancellation.Token);

        var readout = TlsQuicFingerprintReadout.Describe(
            Recorded(transport), new TlsQuicConnectionSpec());

        Assert.Contains("\"client_connection_id_length\": 5", readout, StringComparison.Ordinal);
        Assert.Contains(
            "\"initial_source_connection_id_equals_header_source\": \"different-value\"",
            readout,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ACryptoStreamThatIsNotAClientHelloIsRefusedRatherThanIndexedPastItsEnd()
    {
        // DESCRIBE IS internal AND TAKES ANY IReadOnlyList<ReadOnlyMemory<byte>>, so "the
        // datagrams this connection emitted" is a comment and not a type. This datagram is one
        // built here rather than emitted: a well-formed Initial packet whose CRYPTO stream
        // starts at offset 0, is contiguous, begins with RFC 8446 s4.1.2's ClientHello
        // handshake type, and declares a length its eight bytes fully cover - so it passes all
        // three reassembly checks - and is then far short of the 38-byte fixed prefix the
        // ClientHello walk must cross before it reaches an extension. Bounds-checked, that is
        // the InvalidOperationException this type's remarks promise for input it cannot parse;
        // unchecked it was IndexOutOfRangeException, a different promise.
        var destinationConnectionId = Convert.FromHexString("0001020304050607");
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, destinationConnectionId);
        using var keys = secrets.DeriveClientPacketProtectionKeys(TlsQuicVersion.Version1);

        var plan = new TlsQuicPacketPlan
        {
            Type = TlsQuicLongPacketType.Initial,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = destinationConnectionId,
            SourceConnectionId = new byte[SourceConnectionIdLength],
            Token = ReadOnlyMemory<byte>.Empty,
            PacketNumber = 0,
            PacketNumberEncodedLength = 4,
            LengthVarintWidth = TlsQuicVarintWidth.Minimal,
        };

        // 01 - handshake type ClientHello. 00 00 04 - a three-byte length of four. Then the
        // four bytes it declares, and nothing else.
        TlsQuicFrame[] frames =
            [new() { RawType = 0x06, Offset = 0, Data = Convert.FromHexString("01000004DEADBEEF") }];

        var buffer = new byte[1200];
        var sent = TlsQuicPacketBuilder.Build(
            plan,
            frames,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            SentAt,
            buffer);

        var refused = Assert.Throws<InvalidOperationException>(
            () => TlsQuicFingerprintReadout.Describe(
                [(ReadOnlyMemory<byte>)buffer[..sent.Size]], new TlsQuicConnectionSpec()));
        Assert.Contains("does not reach offset", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACryptoStreamThatDoesNotStartAtOffsetZeroIsReportedUnrecoverableAndNotAbsent()
    {
        // THE DISTINCTION THIS PINS IS THE ONE THAT COULD LIE. A recording missing part of the
        // flight cannot yield the ClientHello, and reporting initial_rtt as ABSENT from a
        // stream that was never assembled would be a deviation claimed on no evidence. The
        // readout must say not-recoverable instead.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            InitialCryptoFrameByteCounts = [64, 65000],
            InitialCryptoFramesPerDatagram = [1, 1],
        };
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, spec, transport.Clock),
            source => TlsClient(pki, source));

        await connection.StartAsync(cancellation.Token);

        var recorded = Recorded(transport);
        Assert.Equal(2, recorded.Count);

        // The whole flight reassembles and finds the parameters; the second datagram alone
        // begins at CRYPTO offset 64 and cannot. Both halves are asserted so that the second
        // is a statement about the gap and not about a reader that never works.
        Assert.Contains(
            "\"initial_rtt_parameter_present\": false",
            TlsQuicFingerprintReadout.Describe(recorded, spec),
            StringComparison.Ordinal);
        Assert.Contains(
            "\"initial_rtt_parameter_present\": \"not-recoverable-from-this-recording\"",
            TlsQuicFingerprintReadout.Describe([recorded[1]], spec),
            StringComparison.Ordinal);

        // TRUNCATION, which is the other way a recording falls short and the one that reaches
        // a DIFFERENT check: the first datagram alone starts at offset 0 and is contiguous, so
        // only the declared-length coverage test can tell that 64 bytes are not the whole
        // 4-byte-headed handshake message they claim to be.
        Assert.Contains(
            "\"initial_rtt_parameter_present\": \"not-recoverable-from-this-recording\"",
            TlsQuicFingerprintReadout.Describe([recorded[0]], spec),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnInitialOnlyDatagramAfterTheFlightHasEndedDoesNotRejoinIt()
    {
        // The Initial flight is a PREFIX, not a filter. A4-minimal has no retransmission, but
        // A3 will, and a re-sent Initial datagram arriving after the Handshake level has
        // opened is not part of the opening flight - a per-datagram flight plan that counted
        // it would be reporting a layout the client never used.
        var (datagrams, spec) = await RecordAFullHandshakeAsync();

        // THREE SINCE A4 TASK 14c, AND THE THIRD IS THE POINT OF THIS COUNT BEING ASSERTED AT
        // ALL. Datagrams 0 and 1 are the Initial flight and its answer; datagram 2 is the
        // 1-RTT packet acknowledging the server's HANDSHAKE_DONE - RFC 9000 s13.2.1's MUST,
        // which this connection violated knowingly until that task. Only 0 and 1 are handed
        // to the readout below, because a 1-RTT packet is not part of an Initial flight and
        // this test is about what rejoins one.
        Assert.Equal(3, datagrams.Count);

        var readout = TlsQuicFingerprintReadout.Describe(
            [datagrams[0], datagrams[1], datagrams[0]], spec);

        Assert.Contains("\"initial_flight_datagram_count\": 1", readout, StringComparison.Ordinal);
        Assert.Contains(
            "\"initial_flight_packets_per_datagram\": [1]", readout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheAbsentInitialRttParameterIsMeasuredFromTheClientHelloAndNamedADeviation()
    {
        var (datagrams, spec) = await RecordAFullHandshakeAsync();
        var readout = TlsQuicFingerprintReadout.Describe(datagrams, spec);

        // MEASURED, not restated: the wire order comes from parsing the reassembled
        // ClientHello's RFC 9001 s8.2 extension out of the CRYPTO frames, so the absence of
        // 12583 is an observation about the bytes rather than a reading of
        // TlsQuicConnectionSpec.InitialRttRange.
        Assert.Contains("\"initial_rtt_parameter_present\": false", readout, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "12583", FieldOf(readout, "transport_parameters_wire_order"), StringComparison.Ordinal);

        // And the parameters that ARE sent were found, so the false above is an absence inside
        // a list that was read rather than a list that was never located. EXACT, IN ORDER:
        // 15 is initial_source_connection_id and 14 is active_connection_id_limit, and the
        // Brave capture's own perk string shows that wire ORDER is what gets fingerprinted -
        // a set assertion here would pass against a readout that sorted them.
        Assert.Equal("[15, 14]", FieldOf(readout, "transport_parameters_wire_order"));
        Assert.Contains(
            "\"initial_source_connection_id_equals_header_source\": \"same-value\"",
            readout,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheKnowinglyViolatedMustIsNamedAsAViolationAndNotAsASoftDeviation()
    {
        var (datagrams, spec) = await RecordAFullHandshakeAsync();
        var readout = TlsQuicFingerprintReadout.Describe(datagrams, spec);

        Assert.Contains("A KNOWINGLY VIOLATED MUST", readout, StringComparison.Ordinal);

        // THE WHOLE SENTENCE PAST ITS LINE WRAP. Three readers this phase quoted the truncated
        // half and concluded the MUST was scoped to Initial and Handshake. The second conjunct
        // is what makes it a violation, so the readout must carry it verbatim.
        Assert.Contains(
            "all ack-eliciting 0-RTT and 1-RTT packets within its advertised",
            readout,
            StringComparison.Ordinal);
        Assert.Contains("THIS IS A VIOLATION,", readout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheOtherThreeOwedItemsAreNamedRatherThanOmitted()
    {
        var (datagrams, spec) = await RecordAFullHandshakeAsync();
        var readout = TlsQuicFingerprintReadout.Describe(datagrams, spec);

        // CORRECTED BY B8. This used to assert "NO initial_rtt TRANSPORT PARAMETER AT ALL",
        // which was true while nothing read the transport-parameter seam. B5 gave the preset a
        // per-connection draw and B8 wired the seam into a ClientHello, so what is owed now is
        // the RANGE and not the parameter - and asserting the old sentence would have kept a
        // false deviation in the readout by making its removal a test failure.
        Assert.Contains(
            "initial_rtt'S RANGE IS UNVERIFIED - THE PARAMETER ITSELF IS SENT",
            readout,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "NO initial_rtt TRANSPORT PARAMETER AT ALL", readout, StringComparison.Ordinal);
        Assert.Contains(
            "AckDelayExponent IS WIRED AND VALIDATED BUT NOT OBSERVABLE",
            readout,
            StringComparison.Ordinal);
        Assert.Contains(
            "AckRangeLimit's DEFAULT OF 32 IS A PLACEHOLDER", readout, StringComparison.Ordinal);
        Assert.Contains(
            "FRESHNESS IS UNOBSERVABLE AT THE TARGET'S OWN SHAPE", readout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARecordingWhoseFirstDatagramIsNotAnInitialPacketIsRefused()
    {
        // RFC 9001 s5.2 takes its salt input from "the client's first Initial packet"; without
        // one there is no key material anywhere in the recording, and reporting the cleartext
        // half alone would be a readout that quietly stopped measuring most of its fields.
        var (datagrams, spec) = await RecordAFullHandshakeAsync();

        var shortHeader = new byte[64];
        RandomNumberGenerator.Fill(shortHeader);
        shortHeader[0] &= 0x7f;

        var refusedShort = Assert.Throws<InvalidOperationException>(
            () => TlsQuicFingerprintReadout.Describe([shortHeader, .. datagrams], spec));
        Assert.Contains("s5.2", refusedShort.Message, StringComparison.Ordinal);

        // THE SECOND HALF OF THE SAME GUARD, and the half a header-that-does-not-parse leaves
        // untouched: a long header that parses perfectly and is not Initial. A mutation sweep
        // found the type check unwitnessed because the case above never reaches it - the
        // parse-failure disjunct fires first. PRESENCE IS NOT IDENTITY.
        var handshakePacket = TlsQuicDatagramReader.Read(datagrams[1]).ElementAt(1).Packet.ToArray();
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(handshakePacket, out var header, out _));
        Assert.Equal(TlsQuicLongPacketType.Handshake, header.Type);

        var refusedHandshake = Assert.Throws<InvalidOperationException>(
            () => TlsQuicFingerprintReadout.Describe([handshakePacket, .. datagrams], spec));
        Assert.Contains("s5.2", refusedHandshake.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyRecordingIsRefused() =>
        Assert.Throws<ArgumentException>(
            () => TlsQuicFingerprintReadout.Describe([], new TlsQuicConnectionSpec()));

    [Fact]
    public async Task AnInitialPacketThatDoesNotOpenUnderItsOwnDerivedKeysIsRefused()
    {
        // THE AEAD IS THE READOUT'S OWN WITNESS, and this is what makes that claim testable:
        // one flipped ciphertext byte and the tag check fails, so the readout throws rather
        // than reporting a packet number and a frame order it could not actually verify.
        // Deleting the TryOpen check leaves ReadFrames walking whatever AesGcm left behind.
        var (datagrams, spec) = await RecordAFullHandshakeAsync();

        var mutated = datagrams[0].ToArray();
        mutated[^1] ^= 0x01;

        var exception = Assert.Throws<InvalidOperationException>(
            () => TlsQuicFingerprintReadout.Describe([mutated], spec));
        Assert.Contains("did not open", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ChangingTheDestinationConnectionIdBreaksTheKeysTheReadoutDerivesForItself()
    {
        // RFC 9001 s5.2 takes the Initial secrets from the Destination Connection ID FIELD OF
        // THE FIRST INITIAL PACKET, which this readout reads off the recording rather than
        // taking from a caller. Rewriting that field is therefore rewriting the key input, and
        // the packet stops opening - which is the evidence that the keys really do come from
        // the bytes. A readout handed its keys would be indifferent to this edit.
        var (datagrams, spec) = await RecordAFullHandshakeAsync();

        var mutated = datagrams[0].ToArray();
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(mutated, out var header, out _));
        Assert.Equal(8, header.DestinationConnectionId.Length);
        mutated[1 + 4 + 1] ^= 0xff;

        Assert.Throws<InvalidOperationException>(
            () => TlsQuicFingerprintReadout.Describe([mutated], spec));
    }

    // ==========================================================================================
    // TASK B10 - perk segment 3.
    // ==========================================================================================
    //
    // THE OBVIOUS WRONG IMPLEMENTATION OF THIS SECTION IS A SET COMPARISON, and it would pass
    // any done-when that only said "the fourteen parameters are rendered and verdicted". Commit
    // 4ed90bf measured against the live service that wire ORDER is hashed and that AUTO-rendered
    // VALUES are not, so a readout that scored membership would call a sorted list a match and a
    // sorted list is a different client. TheSwapOfTwoAdjacentParametersMovesExactlyThoseTwoRows
    // is a theory over all thirteen adjacent pairs for exactly that reason: a swap leaves the
    // multiset of parameters untouched and moves precisely two rows, so an index-insensitive
    // comparison survives every weaker test and dies at all thirteen of these.

    [Fact]
    public void TheCapturesFourteenTokensAndItsFourteenTableRowsAgree()
    {
        // THE CAPTURE CORROBORATING ITSELF. The reference document renders the same fourteen
        // parameters twice - once as perk segment 3 on line 47 and once as a table at lines
        // 79-92 - and the readout's brave column is derived from the first. This reads BOTH out
        // of the file at test time and requires them to agree, so a mistyped token or a
        // mis-ordered name list fails here rather than being scored against for ever.
        var (tokens, identifiers) = CaptureSegmentThree();
        Assert.Equal(14, tokens.Length);
        Assert.Equal(14, identifiers.Count);

        var table = SegmentThreeRowsOf(
            TlsQuicFingerprintReadout.Describe(
                RecordingCarrying(PresetClientHello()), new TlsQuicConnectionSpec()));

        for (var index = 0; index < tokens.Length; index++)
        {
            // The brave cell is the capture's own token, character for character.
            Assert.Equal(tokens[index], table[index].Brave);

            // And the row is NAMED for the parameter the capture's table puts at that
            // position, which is what pins the name list to the table's order.
            Assert.StartsWith(
                identifiers[index] == "GREASE" ? "reserved" : identifiers[index],
                table[index].Parameter,
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheShippedPresetReproducesTheCapturesSegmentThree()
    {
        // THE HEADLINE. The bytes are a real encoded ClientHello from B8's factory, carried in
        // a CRYPTO frame inside an Initial packet, sealed under RFC 9001 s5.2's keys and opened
        // again by the readout - so every cell below crossed the wire format. Nothing here is
        // handed the composed TlsQuicTransportParameters.
        var readout = TlsQuicFingerprintReadout.Describe(
            RecordingCarrying(PresetClientHello()), new TlsQuicConnectionSpec());

        var (tokens, _) = CaptureSegmentThree();
        Assert.Contains(
            "    ours   " + string.Join(';', tokens), readout, StringComparison.Ordinal);
        Assert.Contains("    identical\n", Normalize(readout), StringComparison.Ordinal);

        var rows = SegmentThreeRowsOf(readout);
        Assert.Equal(18, rows.Count);
        AssertVerdictCountsReconcile(readout, rows);

        // 14 parameter rows + the whole-segment row + the "nothing extra" row = 16 match; the
        // two width rows that only a packet capture can settle = 2 not-yet-known; nothing else.
        Assert.Equal(16, rows.Count(row => row.Verdict == "match"));
        Assert.Equal(0, rows.Count(row => row.Verdict == "MISMATCH"));
        Assert.Equal(
            2, rows.Count(row => row.Verdict == "not-yet-known-from-the-capture"));

        // NAMED, not merely counted. The two in the third column are B12's two widths and
        // nothing else may drift into it - the GREASE version least of all, since RFC 9368 s3
        // bounds its form exactly and row 9's token is produced by recomputing that predicate.
        var unknown = rows.Where(row => row.Verdict == "not-yet-known-from-the-capture").ToList();
        Assert.Contains("initial_rtt", unknown[0].Parameter, StringComparison.Ordinal);
        Assert.Contains("31 * N + 27", unknown[1].Parameter, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "version_information",
            string.Join('\n', unknown.Select(row => row.Parameter)),
            StringComparison.Ordinal);

        // The two width rows still MEASURE. Their ours cells are this connection's own draws,
        // read back out of the same bytes, so the third column is not a place rows go to stop
        // being measurements.
        Assert.Matches(@"^\d+$", unknown[0].Ours);
        Assert.Matches(@"^\d+$", unknown[1].Ours);

        // AND THE N ROUND-TRIPS. RFC 9000 s18.1's identifier is 31 * N + 27, so recomputing it
        // from the reported N must land on the identifier the SAME readout printed in
        // transport_parameters_wire_order - two independently rendered fields agreeing about
        // one drawn number. Reporting N as identifier / 31, which is close and wrong, moves
        // one and not the other.
        var order = FieldOf(readout, "transport_parameters_wire_order")
            .Trim('[', ']')
            .Split(", ");
        Assert.Equal(14, order.Length);
        Assert.Equal(
            ulong.Parse(order[1], CultureInfo.InvariantCulture),
            TlsQuicTransportParameterSpec.ReservedIdentifier(
                ulong.Parse(unknown[1].Ours, CultureInfo.InvariantCulture)));
    }

    [Fact]
    public void AParameterValueThatIsNotOneWholeVarintIsRenderedAsItsBytes()
    {
        // WHAT THE CAPTURE'S 12584 NEEDS, EXPRESSED AS A RULE RATHER THAN AS A NAMED
        // IDENTIFIER. 0x4f524947's leading byte declares a two-byte RFC 9000 s16 varint over
        // four bytes present, so reading it as an integer would print a number made of half
        // its value and drop the rest silently. The row below is the general case of that,
        // and it is the witness that the coverage check is doing work rather than being an
        // identity over every value the preset happens to carry.
        var spec = new TlsQuicConnectionSpec
        {
            TransportParameters = new TlsQuicTransportParameterSpec
            {
                Parameters =
                [
                    .. TlsQuicTransportParameterSpec.Brave151Parameters,
                    // 0x01 is a one-byte varint holding 1; the 0x02 after it is not part of
                    // it. An integer rendering prints "1" and loses a byte.
                    TlsQuicTransportParameterSlot.Literal(99, [0x01, 0x02]),
                ],
            },
        };

        var rows = SegmentThreeRowsOf(TlsQuicFingerprintReadout.Describe(
            RecordingCarrying(PresetClientHello(spec)), new TlsQuicConnectionSpec()));

        Assert.Equal("99:0x0102", rows[15].Ours);

        // And the capture's own 12584 goes down the same path, so the rule is the one that
        // reproduces the capture rather than a rule the capture merely tolerates.
        Assert.Equal("12584:0x4f524947", rows[0].Ours);
    }

    [Fact]
    public void ASegmentThatIsAPrefixOfTheCapturesIsNotReportedIdentical()
    {
        // THE CASE A FIRST-DIFFERENCE WALK GETS WRONG, and the one no other recording in this
        // file produces. Every other "ours" here differs from the capture inside the shared
        // prefix, so the walk stops at a character both strings have; a client sending the
        // capture's first thirteen parameters and stopping runs out of string instead, and a
        // diff that treated "one side ended" as "the two agree" would print `identical`
        // directly above a row reading MISMATCH. A mutation sweep found this branch
        // unwitnessed, which is what this case is for.
        var parameters = TlsQuicTransportParameterSpec.Brave151Parameters;
        var spec = new TlsQuicConnectionSpec
        {
            TransportParameters = new TlsQuicTransportParameterSpec
            {
                Parameters = [.. parameters.Take(parameters.Length - 1)],
            },
        };

        var readout = TlsQuicFingerprintReadout.Describe(
            RecordingCarrying(PresetClientHello(spec)), new TlsQuicConnectionSpec());

        Assert.DoesNotContain("    identical\n", Normalize(readout), StringComparison.Ordinal);
        Assert.Contains("ours <end>, brave ';'", readout, StringComparison.Ordinal);

        var rows = SegmentThreeRowsOf(readout);
        Assert.Equal("absent", rows[13].Ours);
        Assert.Equal("MISMATCH", rows[13].Verdict);
        Assert.Equal("MISMATCH", rows[14].Verdict);
    }

    [Fact]
    public void AChangedValueIsAMismatchAtItsIndexAndNotAnUnlistedParameter()
    {
        // THE EXTRAS ROW COUNTS IDENTIFIERS, NOT TOKENS, and the difference only shows here.
        // A client advertising max_udp_payload_size at 1500 sends a parameter the capture DOES
        // list, with a value it does not - one defect, and it belongs to row 14. Matching the
        // extras row on whole tokens would report it twice and would make "we send a parameter
        // Chromium does not" mean "we send a value Chromium does not", which is a different
        // claim about a different fingerprint.
        var parameters = TlsQuicTransportParameterSpec.Brave151Parameters.ToBuilder();
        parameters[13] = TlsQuicTransportParameterSlot.Literal(
            (ulong)TlsQuicTransportParameterId.MaxUdpPayloadSize,
            QuicVariableLengthInteger.Encode(1500));
        var spec = new TlsQuicConnectionSpec
        {
            TransportParameters = new TlsQuicTransportParameterSpec
            {
                Parameters = parameters.ToImmutable(),
            },
        };

        var rows = SegmentThreeRowsOf(TlsQuicFingerprintReadout.Describe(
            RecordingCarrying(PresetClientHello(spec)), new TlsQuicConnectionSpec()));

        Assert.Equal("3:1500", rows[13].Ours);
        Assert.Equal("MISMATCH", rows[13].Verdict);
        Assert.Equal("none", rows[15].Ours);
        Assert.Equal("match", rows[15].Verdict);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(12)]
    public void TheSwapOfTwoAdjacentParametersMovesExactlyThoseTwoRows(int first)
    {
        // EVERY ADJACENT PAIR, because a comparison that is index-insensitive at one position
        // may be index-sensitive at another - the C9 mutant that hard-coded the capture's
        // pseudo-header order passed a done-when and died only to an all-permutations test.
        // Fourteen parameters make 14! orderings unreachable; the thirteen adjacent
        // transpositions generate the whole symmetric group, so a readout that survives all
        // thirteen of these is order-sensitive at every position.
        var swapped = TlsQuicTransportParameterSpec.Brave151Parameters.ToBuilder();
        (swapped[first], swapped[first + 1]) = (swapped[first + 1], swapped[first]);
        var spec = new TlsQuicConnectionSpec
        {
            TransportParameters = new TlsQuicTransportParameterSpec
            {
                Parameters = swapped.ToImmutable(),
            },
        };

        var rows = SegmentThreeRowsOf(TlsQuicFingerprintReadout.Describe(
            RecordingCarrying(PresetClientHello(spec)), new TlsQuicConnectionSpec()));

        // The same fourteen parameters are present, so a set comparison sees no change at all.
        // Two rows move, and they are the two the swap occupies.
        Assert.Equal("MISMATCH", rows[first].Verdict);
        Assert.Equal("MISMATCH", rows[first + 1].Verdict);
        for (var index = 0; index < 14; index++)
        {
            if (index != first && index != first + 1)
            {
                Assert.Equal("match", rows[index].Verdict);
            }
        }

        // 12 parameter rows + the "nothing extra" row still match; the two swapped rows and
        // the whole-segment row do not. 13 + 3 + 2 = 18.
        Assert.Equal(13, rows.Count(row => row.Verdict == "match"));
        Assert.Equal(3, rows.Count(row => row.Verdict == "MISMATCH"));
        Assert.Equal(18, rows.Count);
    }

    [Fact]
    public void AParameterTheCaptureDoesNotListIsReportedSoThatTaskB6sRemovalCannotRegress()
    {
        // B6 dropped active_connection_id_limit because RFC 9000 s18.2 makes absent and
        // present-at-2 the same advertisement. Nothing in a row-by-row comparison against the
        // capture's FOURTEEN notices a fifteenth parameter arriving after them, so the extras
        // row is what makes that removal a thing a test can hold.
        var spec = new TlsQuicConnectionSpec
        {
            TransportParameters = new TlsQuicTransportParameterSpec
            {
                Parameters =
                [
                    .. TlsQuicTransportParameterSpec.Brave151Parameters,
                    TlsQuicTransportParameterSlot.Literal(
                        (ulong)TlsQuicTransportParameterId.ActiveConnectionIdLimit,
                        QuicVariableLengthInteger.Encode(2)),
                ],
            },
        };

        var rows = SegmentThreeRowsOf(TlsQuicFingerprintReadout.Describe(
            RecordingCarrying(PresetClientHello(spec)), new TlsQuicConnectionSpec()));

        // The fourteen the capture lists are all still where it puts them...
        for (var index = 0; index < 14; index++)
        {
            Assert.Equal("match", rows[index].Verdict);
        }

        // ...and only the extras row and the whole-segment row notice the fifteenth.
        Assert.Equal("14:2", rows[15].Ours);
        Assert.Equal("MISMATCH", rows[15].Verdict);
        Assert.Equal("MISMATCH", rows[14].Verdict);
    }

    [Fact]
    public async Task TheSegmentThreeVerdictColumnHoldsOnlyTheThreeValuesAndItsArithmeticReconciles()
    {
        // Over BOTH shapes this file produces: a recording whose ClientHello reproduces the
        // capture, and the hand-composed two-parameter one the snapshot pins. A fourth verdict
        // value, or a count written beside the rows rather than derived from them, fails here.
        var (datagrams, spec) = await RecordAFullHandshakeAsync();
        foreach (var readout in new[]
        {
            TlsQuicFingerprintReadout.Describe(
                RecordingCarrying(PresetClientHello()), new TlsQuicConnectionSpec()),
            TlsQuicFingerprintReadout.Describe(datagrams, spec),
        })
        {
            var rows = SegmentThreeRowsOf(readout);
            Assert.Equal(18, rows.Count);
            Assert.All(
                rows,
                row => Assert.Contains(
                    row.Verdict,
                    new[] { "match", "MISMATCH", "not-yet-known-from-the-capture" }));
            AssertVerdictCountsReconcile(readout, rows);
        }
    }

    [Fact]
    public async Task ARecordingThatYieldsNoClientHelloRendersNoSegmentThreeRowsAtAll()
    {
        // A MISMATCH scored against bytes nobody read is a deviation claimed on no evidence -
        // the same distinction initial_rtt_parameter_present already makes by saying
        // not-recoverable rather than false. Eighteen MISMATCH rows would be eighteen such
        // claims, and they would land in the same third column the real unknowns live in.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        var spec = new TlsQuicConnectionSpec
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            InitialCryptoFrameByteCounts = [64, 65000],
            InitialCryptoFramesPerDatagram = [1, 1],
        };
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, spec, transport.Clock),
            source => TlsClient(pki, source));

        await connection.StartAsync(cancellation.Token);

        var recorded = Recorded(transport);
        var readout = TlsQuicFingerprintReadout.Describe([recorded[1]], spec);

        Assert.Empty(SegmentThreeRowsOf(readout));
        Assert.Contains(
            "does not yield the ClientHello", readout, StringComparison.Ordinal);
        Assert.DoesNotContain("| MISMATCH |", readout, StringComparison.Ordinal);

        // And the whole flight, which does assemble, renders the table - so the assertion
        // above is about the gap and not about a section that never renders.
        Assert.Equal(
            18,
            SegmentThreeRowsOf(TlsQuicFingerprintReadout.Describe(recorded, spec)).Count);
    }

    // ---- scaffolding -------------------------------------------------------------------

    private static string SnapshotPath => Path.Combine(
        AppContext.BaseDirectory, "Quic", "quic-fingerprint-readout.snapshot.txt");

    private static string Normalize(string text) =>
        text.Replace("\r\n", "\n", StringComparison.Ordinal);

    /// <summary>The rendered "quic" block, which is the part no spec may influence.</summary>
    private static string QuicBlockOf(string readout)
    {
        var start = readout.IndexOf("\"quic\": {", StringComparison.Ordinal);
        Assert.True(start >= 0);
        var end = readout.IndexOf("\n}\n", start, StringComparison.Ordinal);
        Assert.True(end > start);
        return readout[start..end];
    }

    private static string FieldOf(string readout, string name)
    {
        var start = readout.IndexOf($"\"{name}\": ", StringComparison.Ordinal);
        Assert.True(start >= 0);
        start += name.Length + 4;
        var end = readout.IndexOf('\n', start);
        return readout[start..end].TrimEnd(',');
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> Recorded(ScriptedDatagramTransport transport) =>
        transport.Sent.Select(send => (ReadOnlyMemory<byte>)send.Payload.ToArray()).ToList();

    // ---- perk segment 3 scaffolding -----------------------------------------------------

    private const string CapturePath =
        "docs/superpowers/specs/reference-captures/"
        + "2026-08-16-brave-151-http3-impersonate-pro.md";

    /// <summary>One row of the rendered segment 3 table.</summary>
    private sealed record SegmentRow(string Parameter, string Ours, string Brave, string Verdict);

    /// <summary>The capture's own segment 3, read out of the reference document at test time -
    /// its fourteen tokens from the perk line, and the fourteen identifiers from the separate
    /// table further down the same file.</summary>
    /// <remarks>Two independent renderings of the same fourteen parameters, so neither can be
    /// a copy of the other and a disagreement between them is a defect in the document.
    /// </remarks>
    private static (string[] Tokens, IReadOnlyList<string> Identifiers) CaptureSegmentThree()
    {
        var lines = File.ReadAllLines(Path.Combine(RepositoryRoot(), CapturePath));

        // The perk line is the only one carrying all four pipe-separated segments.
        var perk = lines.Single(line =>
            line.StartsWith("1:65536;", StringComparison.Ordinal) && line.Count(c => c == '|') == 3);
        var tokens = perk.Split('|')[2].Split(';');

        // The parameter table's rows have five cells - #, ID, name, value - where the SETTINGS
        // table's have four, which is what separates the two markdown tables in the file.
        var identifiers = lines
            .Select(line => line.Split('|'))
            .Where(cells => cells.Length == 6 && int.TryParse(cells[1].Trim(), out _))
            .Select(cells => cells[2].Trim())
            .ToList();

        return (tokens, identifiers);
    }

    /// <summary>The rendered segment 3 section, which is the part no spec may influence.
    /// </summary>
    private static string SegmentThreeSectionOf(string readout)
    {
        var text = Normalize(readout);
        var start = text.IndexOf("## perk segment 3 - ", StringComparison.Ordinal);
        Assert.True(start >= 0);
        var end = text.IndexOf(
            "## perk segment 3 verdict counts", start, StringComparison.Ordinal);
        return end < 0 ? text[start..] : text[start..end];
    }

    /// <summary>The rows of the rendered segment 3 table, parsed back out of the readout.
    /// </summary>
    private static List<SegmentRow> SegmentThreeRowsOf(string readout)
    {
        return SegmentThreeSectionOf(readout).Split('\n')
            .Where(line => line.StartsWith("| ", StringComparison.Ordinal))
            .Select(line => line.Split('|', StringSplitOptions.None))
            .Where(cells => cells.Length == 7 && int.TryParse(cells[1].Trim(), out _))
            .Select(cells => new SegmentRow(
                cells[2].Trim(), cells[3].Trim(), cells[4].Trim(), cells[5].Trim()))
            .ToList();
    }

    /// <summary>Requires the rendered counts block to be the counts of the rendered rows.
    /// </summary>
    private static void AssertVerdictCountsReconcile(string readout, List<SegmentRow> rows)
    {
        var match = rows.Count(row => row.Verdict == "match");
        var mismatch = rows.Count(row => row.Verdict == "MISMATCH");
        var unknown = rows.Count(row => row.Verdict == "not-yet-known-from-the-capture");
        var text = Normalize(readout);
        var start = text.IndexOf("## perk segment 3 verdict counts", StringComparison.Ordinal);
        Assert.True(start >= 0);
        var block = text[start..];

        Assert.Contains($"    rows                            {rows.Count}\n", block, StringComparison.Ordinal);
        Assert.Contains($"    match                           {match}\n", block, StringComparison.Ordinal);
        Assert.Contains($"    MISMATCH                        {mismatch}\n", block, StringComparison.Ordinal);
        Assert.Contains($"    not-yet-known-from-the-capture  {unknown}\n", block, StringComparison.Ordinal);
        Assert.Contains(
            $"    {match} + {mismatch} + {unknown} = {rows.Count}\n", block, StringComparison.Ordinal);
    }

    /// <summary>One encoded ClientHello from B8's factory, carrying the shipped preset's
    /// fourteen parameters composed for a zero-length source connection ID - Chromium's own
    /// shape, capture lines 24-25.</summary>
    private static byte[] PresetClientHello(TlsQuicConnectionSpec? spec = null) =>
        new TlsQuicClientHelloProfileFactory { ConnectionSpec = spec ?? new TlsQuicConnectionSpec() }
            .Create(default)
            .BuildDeterministicForTesting("example.test", [0x2b]);

    /// <summary>A one-datagram recording whose Initial packet carries
    /// <paramref name="clientHello"/> in a CRYPTO frame at offset zero.</summary>
    /// <remarks>BUILT RATHER THAN HANDSHAKED, and the difference is deliberate. The preset
    /// redraws three of its fourteen entries per composition and one of them - the reserved
    /// identifier, drawn over the whole of RFC 9000 s18.1's set - varies in ENCODED WIDTH, so a
    /// preset-driven handshake produces a ClientHello of a different length every run. These
    /// bytes still reach the readout the only way any bytes reach it: through
    /// TlsQuicPacketBuilder, a header protection mask and an AEAD seal, opened again under the
    /// keys RFC 9001 s5.2 derives from the packet's own Destination Connection ID.</remarks>
    private static IReadOnlyList<ReadOnlyMemory<byte>> RecordingCarrying(byte[] clientHello)
    {
        var destinationConnectionId = Convert.FromHexString("0001020304050607");
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, destinationConnectionId);
        using var keys = secrets.DeriveClientPacketProtectionKeys(TlsQuicVersion.Version1);

        var plan = new TlsQuicPacketPlan
        {
            Type = TlsQuicLongPacketType.Initial,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = destinationConnectionId,
            SourceConnectionId = ReadOnlyMemory<byte>.Empty,
            Token = ReadOnlyMemory<byte>.Empty,
            PacketNumber = 0,
            PacketNumberEncodedLength = 4,
            LengthVarintWidth = TlsQuicVarintWidth.Minimal,
        };

        TlsQuicFrame[] frames =
            [new() { RawType = 0x06, Offset = 0, Data = clientHello }];

        var buffer = new byte[4096];
        var sent = TlsQuicPacketBuilder.Build(
            plan,
            frames,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            SentAt,
            buffer);

        return [(ReadOnlyMemory<byte>)buffer[..sent.Size]];
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !Directory.Exists(Path.Combine(directory.FullName, "src", "SharpTls", "Quic")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory.FullName;
    }

    /// <summary>Drives one handshake to CONFIRMED, step by step rather than concurrently, and
    /// hands back exactly the datagrams the client put on the wire.</summary>
    /// <remarks>Stepped on purpose: the snapshot pins the per-datagram flight plan, and a
    /// concurrently pumped peer could interleave the client's sends differently between runs
    /// while every other assertion stayed green.</remarks>
    private static async Task<(IReadOnlyList<ReadOnlyMemory<byte>> Datagrams, TlsQuicConnectionSpec Spec)>
        RecordAFullHandshakeAsync()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        var spec = Spec();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(clientTransport, serverTransport.LocalEndPoint, spec),
            source => TlsClient(pki, source));
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.True(connection.IsHandshakeConfirmed);

        return (clientTransport.Sent.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToList(), spec);
    }

    private static TlsQuicConnectionSpec Spec() => new()
    {
        // 1200 is RFC 9000 s14.1's floor rather than a fingerprint choice. Every other knob
        // but the source connection ID length is TlsQuicConnectionSpec's default, so the
        // snapshot pins the defaults and not a configuration invented for it.
        PaddingTarget = 1200,
        SourceConnectionIdLength = SourceConnectionIdLength,
    };

    // Same profile TlsQuicConnectionTests uses, and for the same reasons: a fresh
    // ClientHelloProfile per attempt carrying THIS attempt's source connection ID.
    //
    // CORRECTED BY B10. This comment used to end "and no initial_rtt (12583) because no range
    // in the repo bounds Chromium's". B5 put a range in the repo -
    // TlsQuicTransportParameterSpec.Brave151InitialRttRange - so the reason was false while the
    // fact stayed true, which is this project's most expensive comment shape. The real reason
    // 12583 is absent here is that this fixture hand-composes two parameters instead of going
    // through B8's TlsQuicClientHelloProfileFactory, AND THAT IS DELIBERATE: three of the
    // preset's fourteen entries are redrawn per connection and one of them - the reserved
    // identifier, drawn over the whole of RFC 9000 s18.1's set - changes the ClientHello's
    // LENGTH between runs, so a preset-driven recording cannot be snapshotted byte for byte.
    // The preset is exercised instead by the segment 3 tests below, whose assertions are over
    // the tokenised rendering and are therefore stable across the draws.
    private static CustomTlsQuicClient TlsClient(TestPki pki, ReadOnlyMemory<byte> sourceConnectionId) =>
        new(new CustomTlsQuicClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.Secp256r1)
                .WithAlpn("h3")
                .WithQuicTransportParameters(new TlsQuicTransportParameters(
                [
                    new TlsQuicTransportParameter(
                        (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
                        sourceConnectionId.ToArray()),
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.ActiveConnectionIdLimit, 2),
                ]))),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });

    private static TlsServerCertificate Credential(TestPki pki) =>
        new(pki.Leaf, (RSA)pki.LeafKey, [pki.Root]);

    // RFC 9000 s7.3 makes both connection ID parameters mandatory from a server, and this
    // helper sent neither until task 9b - see TlsQuicConnectionTests.Server for the whole
    // quote. Both values are the client's original Destination Connection ID because
    // LoopbackQuicPeer echoes it as its own Source Connection ID.
    //
    // THE FLOW-CONTROL PARAMETERS ARE TASK 14d's, AND THIS HELPER SENT NONE OF THEM EITHER.
    // RFC 9114 s6.2: "the transport parameters sent by both clients and servers MUST allow
    // the peer to create at least three unidirectional streams." A server that omits
    // initial_max_streams_uni has advertised 0 of them - s18.2's "Transport parameters have
    // a default value of 0 if the transport parameter is absent" - so it is non-conforming,
    // and every test here drove one until the client learned to check. That is task 9b's
    // lesson repeated exactly: the cooperative peer was the thing that had never been asked
    // to conform. The values themselves are TlsQuicConnectionTests.FlowControlParameters'.
    private static CustomTlsQuicServer Server(
        TlsServerCertificate credential, ReadOnlyMemory<byte> originalDestinationConnectionId) =>
        new(new CustomTlsQuicServerOptions
        {
            Tls = new CustomTlsServerOptions
            {
                AutomaticSessionTicketCount = 0,
                ServerCertificate = credential,
                SupportedVersions = [TlsProtocolVersion.Tls13],
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                SupportedGroups = [NamedGroup.Secp256r1],
                AlpnProtocols = ["h3"],
                RequireAlpn = true,
            },
            TransportParameters = new TlsQuicTransportParameters(
            [
                TlsQuicTransportParameter.VariableInteger(
                    TlsQuicTransportParameterId.ActiveConnectionIdLimit, 4),
                new TlsQuicTransportParameter(
                    (ulong)TlsQuicTransportParameterId.OriginalDestinationConnectionId,
                    originalDestinationConnectionId.Span),
                new TlsQuicTransportParameter(
                    (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
                    originalDestinationConnectionId.Span),
                .. TlsQuicConnectionTests.FlowControlParameters(),
            ]),
        });
}
