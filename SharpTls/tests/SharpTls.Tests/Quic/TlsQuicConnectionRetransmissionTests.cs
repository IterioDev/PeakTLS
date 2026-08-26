using System.Net.Security;
using System.Runtime.Versioning;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;
using SharpTls.Tests.Interop;

namespace SharpTls.Tests.Quic;

// Task A3-8 of the loss recovery phase: RFC 9000 s13.3's retransmission of INFORMATION, which
// is the first thing in this subsystem that repairs anything. A3-4 measures, A3-6 detects and
// A3-7 probes; until this task landed, a lost packet was correctly identified and then
// forgotten.
//
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's, 14c's, A3-1's, A3-3's, A3-5's, A3-6's AND A3-7's,
// for the reason those files give: Spec, Connection, TlsClient, Server, Credential, IdleOn,
// FakeClock, PacketAt, AckFrame, Acknowledge and LossDetectionConnectionOn are reused rather
// than copied.
//
// ============================================================================
// THE ONE DISTINCTION THIS FILE EXISTS TO PIN.
// ============================================================================
//
// rfc9000-section13.3-retransmission-of-information.txt lines 21-25: "QUIC packets that are
// determined to be lost are not retransmitted whole. The same applies to the frames that are
// contained within lost packets. Instead, the information that might be carried in frames is
// sent again in new frames as needed."
//
// A build that re-sent the whole lost PACKET would repair a handshake, repair a transfer, and
// pass every completion assertion in this file. The plan says so in as many words - "a mutant
// that re-sends the whole lost packet rather than its information is killed ... it repairs the
// transfer and passes every completion test, and fails only a test that reads the retransmitted
// frame's offsets back off the wire". So the completion tests are not the evidence for the
// split; the three group witnesses and the offset assertions are, and they are marked below.
//
// AND THE SPLIT IS THREE-WAY RATHER THAN TWO-WAY, which is the transcription defect this task
// was warned about. s13.3 says different things about a RESET_STREAM (content "MUST NOT change
// when it is sent again"), a MAX_DATA ("An updated value is sent") and a PATH_RESPONSE ("sent
// just once"), and collapsing any pair of those into one rule is a wire defect no completion
// test can see.
public sealed partial class TlsQuicConnectionTests
{
    // The 72-column wrap the captures carry, collapsed so a quotation can be written as one
    // sentence. Compiled once because the table below asks it twenty questions.
    private static readonly System.Text.RegularExpressions.Regex Whitespace =
        new(@"\s+", System.Text.RegularExpressions.RegexOptions.Compiled);

    // One tick past RFC 9002 s6.1.2's loss delay for a connection that has taken no RTT sample.
    // COMPUTED FROM THE SPEC rather than typed: a literal here would stop tracking the knobs the
    // moment anything moved kInitialRtt or kTimeThreshold, and every loss in this file would
    // quietly stop being declared.
    private static TimeSpan TimeThresholdGap =>
        LossDelayOf(new TlsQuicRecoverySpec()) + TimeSpan.FromMilliseconds(1);

    private const string Section133Capture =
        "docs/superpowers/specs/reference-captures/"
            + "rfc9000-section13.3-retransmission-of-information.txt";

    // ========================================================================
    // GROUP 1 OF 3 - RETRANSMITTED: THE FRAME GOES AGAIN, UNCHANGED.
    // ========================================================================
    //
    // s13.3 for RESET_STREAM: "The content of a RESET_STREAM frame MUST NOT change when it is
    // sent again." For NEW_CONNECTION_ID: "Retransmissions of this frame carry the same
    // sequence number value." For HANDSHAKE_DONE: "The HANDSHAKE_DONE frame MUST be
    // retransmitted until it is acknowledged."
    //
    // WHY THE FRAME IS FABRICATED RATHER THAN PROVOKED, SAID PLAINLY. This client sends none of
    // s13.3's Resend group: it is a client, so HANDSHAKE_DONE and NEW_TOKEN are the server's,
    // and it opens no stream it later resets and issues no connection ID. The classification
    // and the mechanism are still live code on the live path - RecordRepairable is what every
    // build site calls and Acknowledge drives A.7's real loss pass - so what this test cannot
    // claim is that the client originates such a frame, and it says so rather than implying it.
    [Fact]
    public async Task AFrameInSection133sRetransmittedGroupGoesAgainWithItsBytesUnchanged()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        // s19.19-shaped opaque payload. The point of the assertion below is that these exact
        // bytes come back, so they are chosen to be distinguishable from anything else here.
        ReadOnlyMemory<byte> token = new byte[] { 0xA5, 0x5A, 0x11, 0x22, 0x33 };
        var newToken = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.NewToken,
            Data = token,
        };

        connection.RecordRepairable(TlsQuicEncryptionLevel.Application, 0, [newToken]);
        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Application, 0, clock.GetUtcNow()));
        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Application, 1, clock.GetUtcNow()));

        // s6.1.2's TIME THRESHOLD is what declares the loss below, so the clock moves past the
        // loss delay first. The packet threshold would need three packet numbers of headroom
        // and would make every packet number here arithmetic about kPacketThreshold rather
        // than about the repair.
        clock.Advance(TimeThresholdGap);
        var lost = Acknowledge(connection, TlsQuicEncryptionLevel.Application, 1);
        Assert.Equal([0UL], lost.Select(static p => p.PacketNumber));

        var owed = connection.RepairsOwed(TlsQuicEncryptionLevel.Application);
        var repaired = Assert.Single(owed);
        Assert.Equal(TlsQuicFrameType.NewToken, repaired.Type);

        // UNCHANGED, BYTE FOR BYTE. This is the assertion a build that repaired every group the
        // same way would still pass; the two below are the ones that tell the groups apart.
        Assert.Equal(token.ToArray(), repaired.Data.ToArray());
        Assert.Equal(newToken.RawType, repaired.RawType);
    }

    // ========================================================================
    // GROUP 2 OF 3 - INFORMATION IN A NEW FRAME: THE OFFSET IS THE INFORMATION.
    // ========================================================================
    //
    // s13.3: "Data sent in CRYPTO frames is retransmitted according to the rules in
    // [QUIC-RECOVERY], until all data has been acknowledged."
    //
    // THIS IS THE TEST THE PLAN NAMES AS THE ONE THAT KILLS THE WHOLE-PACKET MUTANT: it "reads
    // the retransmitted frame's offsets back off the wire". A build that re-sent the lost
    // PACKET would put the CRYPTO bytes back on the wire at the same offset too - so the
    // stronger half is that the repair arrives as a FRAME in the queue the ordinary send path
    // drains, at the level the packet was protected at, and that a packet with no repairable
    // frame in it produces no repair at all.
    [Fact]
    public async Task ALostCryptoFrameIsRepairedAsANewFrameCarryingItsOwnOffsetAndBytes()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        // A NON-ZERO OFFSET, DELIBERATELY. A repair that dropped the offset field and rebuilt
        // the frame at 0 would pass every "the bytes came back" assertion and would splice the
        // second half of a ClientHello over the first half at the peer.
        ReadOnlyMemory<byte> second = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Handshake,
            7,
            [new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.Crypto,
                Offset = 4096,
                Data = second,
            }]);

        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 7, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 8, clock.GetUtcNow()));

        Assert.Empty(connection.RepairsOwed(TlsQuicEncryptionLevel.Handshake));

        // s6.1.2's TIME THRESHOLD is what declares the loss below, so the clock moves past the
        // loss delay first. The packet threshold would need three packet numbers of headroom
        // and would make every packet number here arithmetic about kPacketThreshold rather
        // than about the repair.
        clock.Advance(TimeThresholdGap);
        var lost = Acknowledge(connection, TlsQuicEncryptionLevel.Handshake, 8);
        Assert.Equal([7UL], lost.Select(static p => p.PacketNumber));

        var repaired = Assert.Single(connection.RepairsOwed(TlsQuicEncryptionLevel.Handshake));
        Assert.Equal(TlsQuicFrameType.Crypto, repaired.Type);
        Assert.Equal(4096UL, repaired.Offset);
        Assert.Equal(second.ToArray(), repaired.Data.ToArray());

        // AND IT IS AT THE LEVEL THE LOST PACKET WAS PROTECTED AT, not somewhere a build that
        // kept one queue would put it. s12.4 Table 3 confines CRYPTO to IH_1, so a Handshake
        // repair emitted at Initial would be legal and wrong, and one at Application would be
        // rejected by the builder.
        Assert.Empty(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));
        Assert.Empty(connection.RepairsOwed(TlsQuicEncryptionLevel.Application));
    }

    // ========================================================================
    // GROUP 3 OF 3 - DROPPED: AND THE WITNESS CANNOT BE AN ABSENCE.
    // ========================================================================
    //
    // s13.3: "Responses to path validation using PATH_RESPONSE frames are sent just once." And
    // "PING and PADDING frames contain no information, so lost PING or PADDING frames do not
    // require repair." And of ACK: "resending old ACK frames can cause the peer to generate an
    // inflated RTT sample or unnecessarily disable ECN."
    //
    // "NO PATH_RESPONSE WAS RETRANSMITTED" IS ALSO TRUE OF A BUILD THAT RETRANSMITS NOTHING,
    // which is why the excluded frames share a packet with a CRYPTO frame here. The packet is
    // lost once; the CRYPTO half must come back and the other four must not, and no
    // single-sided build satisfies both halves.
    /// <summary>
    /// A REPAIR FILLS THE DATAGRAM IT IS GOING INTO, AND STOPS. RFC 9000 section 14.2 bounds
    /// the DATAGRAM, and a drain that emptied the queue regardless produced datagrams no path
    /// carries: the Spotify preset splits its ClientHello into a 999-byte CRYPTO frame and a
    /// ~492-byte one, sent as two 1200-byte datagrams - and repaired as ONE datagram of about
    /// 1525, which a DF-set socket refuses with SocketError.MessageSize. Field-reported at
    /// exactly 1525 and 1520 bytes for two hosts whose names differ by five characters, which
    /// is the second frame carrying the SNI.
    /// <para>THE SIBLING PATH ALREADY DID THIS. AppendProbeData, twenty lines further down the
    /// same file, fills to a budget and leaves the remainder owed. The two answered the same
    /// question differently, and the ordinary answer path was the one with no bound.</para>
    /// </summary>
    [Fact]
    public async Task ARepairDrainStopsAtTheDatagramBudgetAndLeavesTheRestOwed()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        // The captured shape: one 999-byte CRYPTO frame and the remainder, each sent in its own
        // datagram because that is what fitted.
        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Initial,
            0,
            [
                new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.Crypto,
                    Offset = 0,
                    Data = new byte[999],
                },
            ]);
        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Initial,
            1,
            [
                new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.Crypto,
                    Offset = 999,
                    Data = new byte[492],
                },
            ]);

        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 0, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 1, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 2, clock.GetUtcNow()));

        clock.Advance(TimeThresholdGap);
        Acknowledge(connection, TlsQuicEncryptionLevel.Initial, 2);
        Assert.Equal(2, connection.RepairsOwed(TlsQuicEncryptionLevel.Initial).Count);

        // A 1200-byte datagram carries the first frame and not both. The budget is the payload
        // one Initial packet has left, which is under 1200 by the long header this test does not
        // restate; 1100 is comfortably inside it and comfortably outside 999 + 492.
        var first = new List<TlsQuicFrame>();
        connection.TakeRepairsInto(TlsQuicEncryptionLevel.Initial, first, 1100);

        // ONE OF THE TWO, WHICHEVER THE LOSS PASS QUEUED FIRST - the assertion is the BUDGET,
        // not the order. Queue order is send order within a level, but which of two packets
        // declared lost in the same pass is walked first is loss detection's business and not
        // this bound's; a CRYPTO frame carries its own offset, so either order reassembles.
        Assert.Single(first);
        Assert.True(
            first[0].Data.Length <= 1100,
            $"a {first[0].Data.Length}-byte repair went into a 1100-byte budget");

        // AND THE REMAINDER IS STILL OWED, NOT DROPPED. A bound that discarded the overflow
        // would pass the assertion above and stall the handshake, which is a worse failure
        // than the one being fixed.
        var stillOwed = Assert.Single(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));
        Assert.NotEqual(first[0].Data.Length, stillOwed.Data.Length);

        // The next datagram takes it, and the two together are the whole flight - 1491 bytes
        // that never shared one datagram.
        var second = new List<TlsQuicFrame>();
        connection.TakeRepairsInto(TlsQuicEncryptionLevel.Initial, second, 1100);
        Assert.Single(second);
        Assert.Equal(1491, first[0].Data.Length + second[0].Data.Length);
        Assert.Empty(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));
    }

    /// <summary>
    /// A SINGLE FRAME LARGER THAN THE WHOLE BUDGET STILL GOES OUT. It cannot be split here - a
    /// CRYPTO frame's offsets belong to the TLS endpoint that produced it - so the choice is
    /// between an oversized datagram the send path reports as a refusal, and a queue that never
    /// drains behind a frame that never fits. The second is a handshake that hangs with no
    /// error, which is strictly worse than the size bug this budget exists to fix.
    /// </summary>
    [Fact]
    public async Task ARepairTooLargeForTheBudgetIsStillSentRatherThanStarved()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Initial,
            0,
            [
                new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.Crypto,
                    Offset = 0,
                    Data = new byte[1400],
                },
            ]);

        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 0, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 1, clock.GetUtcNow()));

        clock.Advance(TimeThresholdGap);
        Acknowledge(connection, TlsQuicEncryptionLevel.Initial, 1);
        Assert.Single(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));

        var drained = new List<TlsQuicFrame>();
        connection.TakeRepairsInto(TlsQuicEncryptionLevel.Initial, drained, 1100);

        Assert.Equal(1400, Assert.Single(drained).Data.Length);
        Assert.Empty(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public async Task TheFramesSection133ExcludesAreNotRepairedWhileTheirPacketmateIs()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        ReadOnlyMemory<byte> challenge = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Application,
            0,
            [
                new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ack },
                new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping },
                new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Padding },
                new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.PathResponse,
                    Data = challenge,
                },
                new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.ConnectionClose },
                new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.Crypto,
                    Offset = 0,
                    Data = new byte[] { 9, 9 },
                },
            ]);

        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Application, 0, clock.GetUtcNow()));
        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Application, 1, clock.GetUtcNow()));

        // s6.1.2's TIME THRESHOLD is what declares the loss below, so the clock moves past the
        // loss delay first. The packet threshold would need three packet numbers of headroom
        // and would make every packet number here arithmetic about kPacketThreshold rather
        // than about the repair.
        clock.Advance(TimeThresholdGap);
        var lost = Acknowledge(connection, TlsQuicEncryptionLevel.Application, 1);
        Assert.Equal([0UL], lost.Select(static p => p.PacketNumber));

        // THE POSITIVE HALF. Exactly one frame came back and it is the one s13.3 repairs.
        var repaired = Assert.Single(connection.RepairsOwed(TlsQuicEncryptionLevel.Application));
        Assert.Equal(TlsQuicFrameType.Crypto, repaired.Type);

        // AND IT COUNTS AS A RETRANSMISSION ONLY WHEN IT IS HANDED TO A BUILDER, which is what
        // FramesRetransmitted means - see its remarks. Owed and sent are different states, and
        // a build that counted at the queue would report a repair a shut window withheld.
        Assert.Equal(0, connection.FramesRetransmitted);
        var drained = new List<TlsQuicFrame>();
        connection.TakeRepairsInto(TlsQuicEncryptionLevel.Application, drained, TlsQuicUdpDatagramTransport.MaximumUdpPayload);
        Assert.Single(drained);
        Assert.Equal(1, connection.FramesRetransmitted);

        // THE NEGATIVE HALF, AND IT IS A COUNTER RATHER THAN AN EMPTY LIST. The five excluded
        // frames were never even recorded - RecordRepairable filters them at the build site,
        // which is what keeps the steady-state ACK path free of a dictionary entry per packet -
        // so FramesNotRepaired stays at zero here and the evidence is the RECORD's shape.
        Assert.Equal(0, connection.FramesNotRepaired);
    }

    // ========================================================================
    // THE TABLE, AGAINST THE EXTRACT RATHER THAN AGAINST A RETYPED LIST.
    // ========================================================================
    //
    // The plan asks for "a witness per excluded type read from the extract and not retyped".
    // Each row below carries the sentence s13.3 uses to place that type, and the test asserts
    // BOTH that the sentence is present in the captured file byte-for-byte AND that
    // TlsQuicRetransmission.ActionFor agrees with it. A row whose sentence is not in the
    // extract fails on the first assertion, so no row can drift into being this test's own
    // invention; a classifier that moved a type between groups fails on the second.
    [Fact]
    public void EveryFrameTypeIsInTheGroupTheCapturedSectionPutsItIn()
    {
        // A FACT WITH A TABLE RATHER THAN A THEORY WITH ROWS, and the reason is the type system
        // rather than taste: TlsQuicFrameType and TlsQuicRepairAction are internal, and an
        // xUnit theory's parameters must be at least as accessible as its public method. The
        // table below IS the theory's rows and the loop is its runner.
        //
        // WHITESPACE IS NORMALISED ON BOTH SIDES AND NOTHING ELSE IS. The extract is hard-
        // wrapped at 72 columns, so a sentence copied out of it carries newlines and six-space
        // indents that no C# literal should; collapsing runs of whitespace to one space on the
        // FILE and writing the sentences unwrapped keeps the comparison a comparison of words.
        // Nothing else is touched - a row that changed a word, dropped a clause or reordered a
        // list still fails, which is the whole point of reading the capture rather than
        // asserting a constant.
        (TlsQuicFrameType Type, TlsQuicRepairAction Expected, string Sentence)[] rows =
        [
            (TlsQuicFrameType.ResetStream, TlsQuicRepairAction.Resend,
                "The content of a RESET_STREAM frame MUST NOT change when it is "
                    + "sent again."),
            (TlsQuicFrameType.StopSending, TlsQuicRepairAction.Resend,
                "a request to cancel stream transmission, as encoded in a "
                    + "STOP_SENDING frame, is sent until"),
            (TlsQuicFrameType.NewConnectionId, TlsQuicRepairAction.Resend,
                "New connection IDs are sent in NEW_CONNECTION_ID frames and "
                    + "retransmitted if the packet containing them is lost."),
            (TlsQuicFrameType.RetireConnectionId, TlsQuicRepairAction.Resend,
                "retired connection IDs are sent in RETIRE_CONNECTION_ID frames and "
                    + "retransmitted if the packet containing them is lost."),
            (TlsQuicFrameType.NewToken, TlsQuicRepairAction.Resend,
                "NEW_TOKEN frames are retransmitted if the packet containing them "
                    + "is lost."),
            (TlsQuicFrameType.HandshakeDone, TlsQuicRepairAction.Resend,
                "The HANDSHAKE_DONE frame MUST be retransmitted until it is "
                    + "acknowledged."),
            (TlsQuicFrameType.Crypto, TlsQuicRepairAction.Refresh,
                "Data sent in CRYPTO frames is retransmitted according to the rules "
                    + "in [QUIC-RECOVERY], until all data has been acknowledged."),
            (TlsQuicFrameType.Stream, TlsQuicRepairAction.Refresh,
                "Application data sent in STREAM frames is retransmitted in new "
                    + "STREAM frames"),
            (TlsQuicFrameType.MaxData, TlsQuicRepairAction.Refresh,
                "An updated value is sent in a MAX_DATA frame if the packet "
                    + "containing the most recently sent MAX_DATA frame is declared lost"),
            (TlsQuicFrameType.MaxStreamData, TlsQuicRepairAction.Refresh,
                "The current maximum stream data offset is sent in MAX_STREAM_DATA "
                    + "frames."),
            (TlsQuicFrameType.MaxStreams, TlsQuicRepairAction.Refresh,
                "The limit on streams of a given type is sent in MAX_STREAMS "
                    + "frames."),
            (TlsQuicFrameType.DataBlocked, TlsQuicRepairAction.Refresh,
                "Blocked signals are carried in DATA_BLOCKED, STREAM_DATA_BLOCKED, "
                    + "and STREAMS_BLOCKED frames."),
            (TlsQuicFrameType.StreamDataBlocked, TlsQuicRepairAction.Refresh,
                "These frames always include the limit that is causing blocking at "
                    + "the time that they are transmitted."),
            (TlsQuicFrameType.StreamsBlocked, TlsQuicRepairAction.Refresh,
                "A new frame is sent if a packet containing the most recent frame "
                    + "for a scope is lost"),
            (TlsQuicFrameType.Ack, TlsQuicRepairAction.Drop,
                "resending old ACK frames can cause the peer to generate an "
                    + "inflated RTT sample or unnecessarily disable ECN."),
            (TlsQuicFrameType.ConnectionClose, TlsQuicRepairAction.Drop,
                "Connection close signals, including packets that contain "
                    + "CONNECTION_CLOSE frames, are not sent again when packet loss is "
                    + "detected."),
            (TlsQuicFrameType.PathResponse, TlsQuicRepairAction.Drop,
                "Responses to path validation using PATH_RESPONSE frames are sent "
                    + "just once."),
            (TlsQuicFrameType.PathChallenge, TlsQuicRepairAction.Drop,
                "PATH_CHALLENGE frames include a different payload each time they "
                    + "are sent."),
            (TlsQuicFrameType.Ping, TlsQuicRepairAction.Drop,
                "PING and PADDING frames contain no information, so lost PING or "
                    + "PADDING frames do not require repair."),
            (TlsQuicFrameType.Padding, TlsQuicRepairAction.Drop,
                "PING and PADDING frames contain no information, so lost PING or "
                    + "PADDING frames do not require repair."),
        ];

        var capture = Whitespace.Replace(
            File.ReadAllText(Path.Combine(RepositoryRoot(), Section133Capture)), " ");

        foreach (var (type, expected, sentence) in rows)
        {
            Assert.True(
                capture.Contains(sentence, StringComparison.Ordinal),
                $"The sentence this row classifies {type} by is not in {Section133Capture}, so "
                    + "the row is this test's own invention rather than a reading of the "
                    + "extract.");

            Assert.Equal(expected, TlsQuicRetransmission.ActionFor(type));
        }

        // A row deleted to make a failure go away is a row this count catches.
        Assert.Equal(20, rows.Length);
    }

    // THE CALIBRATION CONTROL FOR THE THEORY ABOVE, AND IT HAS TO ACTUALLY RUN. A theory whose
    // rows all assert the same action would pass against a classifier that returned one
    // constant, and every row of a twenty-row theory reading `Drop` is exactly what a
    // one-constant classifier produces. This asserts the three groups are all non-empty AND
    // that they partition the rows, so a collapse in either direction fails here rather than
    // nowhere.
    [Fact]
    public void TheCapturedSectionsThreeGroupsAreAllInhabitedAndNoTypeIsInTwo()
    {
        var byAction = Enum.GetValues<TlsQuicFrameType>()
            .Distinct()
            .GroupBy(TlsQuicRetransmission.ActionFor)
            .ToDictionary(static g => g.Key, static g => g.ToArray());

        Assert.Equal(3, byAction.Count);
        Assert.NotEmpty(byAction[TlsQuicRepairAction.Resend]);
        Assert.NotEmpty(byAction[TlsQuicRepairAction.Refresh]);
        Assert.NotEmpty(byAction[TlsQuicRepairAction.Drop]);

        // The partition. GroupBy cannot put one key in two groups, so what this really pins is
        // that every declared frame type reached the switch at all - a type added to
        // TlsQuicFrameType and forgotten here falls to the `_` arm and lands in Drop, which is
        // the safe direction and is counted rather than hidden.
        Assert.Equal(
            Enum.GetValues<TlsQuicFrameType>().Distinct().Count(),
            byAction.Values.Sum(static v => v.Length));
    }

    // s13.3 IS AN ENUMERATION, SO A TYPE IT DOES NOT NAME HAS NO RULE - and a wire varint can
    // carry 2^62 of them. Nothing here may throw, and the answer for all of them is the
    // conservative one.
    [Theory]
    [InlineData(0x03UL)]
    [InlineData(0x0fUL)]
    [InlineData(0x1fUL)]
    [InlineData(0x20UL)]
    [InlineData(0x31UL)]
    [InlineData(0x3fffffffUL)]
    [InlineData((1UL << 62) - 1)]
    public void AFrameTypeTheCapturedSectionNeverNamesIsNotRepairedAndDoesNotThrow(ulong rawType)
    {
        var frame = new TlsQuicFrame { RawType = rawType };

        // 0x03 AND 0x0f ARE NOT UNNAMED AND ARE HERE ON PURPOSE. They are inside s12.4's FLAG
        // RANGES, so TlsQuicFrame.Type maps 0x03 onto ACK and 0x0f onto STREAM - which is why
        // this theory reads the DERIVED type and why those two rows expect their base type's
        // group rather than Drop. They are the rows that would fail a classifier switching on
        // RawType, which is the defect that would silently stop repairing every STREAM frame
        // that carries an offset, a length or a FIN.
        var expected = rawType switch
        {
            0x03 => TlsQuicRepairAction.Drop,      // ACK with the ECN bit.
            0x0f => TlsQuicRepairAction.Refresh,   // STREAM with OFF, LEN and FIN all set.
            _ => TlsQuicRepairAction.Drop,
        };

        Assert.Equal(expected, TlsQuicRetransmission.ActionFor(frame.Type));
    }

    // ========================================================================
    // THE HEADLINE: A REAL HANDSHAKE COMPLETES THROUGH AN INDUCED LOSS.
    // ========================================================================
    //
    // A3-1's decorator drops the client's SECOND datagram, which
    // TheImpairedClientSendSequenceCarriesInitialThenHandshakeThenOneRtt establishes carries a
    // Handshake packet - and that packet carries the client's Finished. Before this task the
    // server would wait for it for ever; Finding 9 states the same thing as a debt: "A lost
    // CRYPTO frame today ends the handshake."
    //
    // THE PROBE IS WHAT CARRIES THE REPAIR HERE, AND THAT IS s6.2.4 RATHER THAN A SHORTCUT.
    // rfc9002-section6.2-probe-timeout.txt lines 205-206: "An endpoint SHOULD include new data
    // in packets that are sent on PTO expiration. Previously sent data MAY be sent if no new
    // data can be sent." Nothing has acknowledged anything in the Handshake space, so A.10's
    // opening largest_acked test returns before it can declare the loss - the probe is the only
    // thing that moves, and knob 11 is what decides whether it moves anything useful.
    [Fact]
    public async Task AHandshakeCompletesThroughADroppedHandshakeFlightWhenTheProbeCarriesData()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        await using var connection = Connection(
            impaired, serverTransport, pki, RetransmittingProbeSpec(), clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, RetransmittingProbeSpec());

        impaired.Drop(2);

        // Ordinal 1 - the ClientHello - arrives, and the server answers.
        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // Ordinal 2 - the client's Initial ACK coalesced with its Handshake Finished - is
        // DROPPED. The server therefore sees nothing and its handshake does not finish, which
        // is asserted rather than assumed: a test in which the drop silently failed would
        // "prove" retransmission from a run that never lost anything.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal([2], impaired.Dropped);
        Assert.False(server.IsHandshakeComplete);

        // s6.2.1's PTO. The timer is armed because the dropped datagram left an ack-eliciting
        // Handshake packet in flight; the clock moves to it and the pump takes A.9's send rung.
        var armed = Assert.IsType<DateTimeOffset>(connection.LossDetectionTimer);
        impaired.Clock.Advance(armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.True(connection.ProbeDatagramsSent > 0);

        // AND THE REPAIR IS ON THE WIRE. The server opens the probe, finds the Finished it
        // never received, and completes - which is the whole claim of this task in one
        // assertion, made by the FAR SIDE rather than by this connection's own opinion.
        // THE PUMP'S RETURN IS DISCARDED because it reports whether the SERVER answered, and a
        // server that has just finished its handshake owes nothing until it chooses to send
        // HANDSHAKE_DONE - which this harness does on request rather than unprompted.
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        Assert.True(
            server.IsHandshakeComplete,
            "The probe carried no repair, so the server never received the client's Finished.");
        Assert.True(connection.FramesRetransmitted > 0);

        // Confirmed, not merely complete: RFC 9001 s4.1.2's HANDSHAKE_DONE, from the peer.
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.True(connection.IsHandshakeConfirmed);
    }

    // THE CALIBRATION CONTROL FOR THE TEST ABOVE, AND IT IS THE SAME SCRIPT WITH KNOB 11 AT ITS
    // OTHER VALUE. s6.2.4 leaves the probe's contents open - "Implementations MAY use
    // alternative strategies for determining the content of probe packets" - so a PING-only
    // probe is legal, and s6.2.3 lines 180-183 name it outright: "a client can coalesce an
    // Initial packet containing PING and PADDING frames with a 0-RTT data packet". It just
    // cannot repair a handshake by itself, because a PING carries no information (s13.3: "PING
    // and PADDING frames contain no information"). Without this control the test above would
    // pass against a build that repaired on some path other than the probe, and knob 11 would
    // be decorative.
    //
    // AND SINCE TASK A3-14 THIS TEST ASKS FOR Ping BY NAME RATHER THAN INHERITING IT. It read
    // the shipped default until A3-14 changed that default to RetransmittedData, which would
    // have turned this control into a duplicate of the test above - the worst possible failure
    // mode for a calibration row, because it would have gone on passing. This is now also the
    // WITNESS that Ping survives as an explicit choice.
    [Fact]
    public async Task APingOnlyProbeCarriesNoRepairAndLeavesTheServerWaiting()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        await using var connection = Connection(
            impaired, serverTransport, pki, PingOnlyProbeSpec(), clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, PingOnlyProbeSpec());

        // Asserted rather than assumed - this control is only a control while the knob is at
        // the other value from the test above, and it no longer gets there by default.
        Assert.Equal(
            TlsQuicProbeContents.Ping, PingOnlyProbeSpec().Recovery.ProbeContents);
        Assert.NotEqual(
            PingOnlyProbeSpec().Recovery.ProbeContents,
            RetransmittingProbeSpec().Recovery.ProbeContents);

        impaired.Drop(2);
        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal([2], impaired.Dropped);

        var armed = Assert.IsType<DateTimeOffset>(connection.LossDetectionTimer);
        impaired.Clock.Advance(armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.True(connection.ProbeDatagramsSent > 0);

        Assert.Equal(0, connection.FramesRetransmitted);
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(server.IsHandshakeComplete);
    }

    // ========================================================================
    // TASK A3-14: THE DEFAULT MOVED AND NOT ONE UNIMPAIRED BYTE MOVED WITH IT.
    // ========================================================================
    //
    // A3-14 changed knob 11's shipped default from Ping to RetransmittedData. That knob has
    // exactly one reader - TlsQuicConnection.TryBuildProbeDatagram - and it runs only when a
    // PTO expires, so a connection that loses nothing must emit the same wire it emitted
    // before. THE PROJECT'S `perk_hash` PARITY DEPENDS ON THAT, which is why it is pinned here
    // rather than reasoned about in a comment.
    //
    // WHAT THIS COMPARES, AND THE ONE THING IT HONESTLY CANNOT. Two connections cannot be
    // compared byte for byte: TLS randomises the ClientHello random and the ephemeral key
    // share, and everything after the Initial is AEAD-sealed, so two runs of the SAME build
    // differ in content by design and a byte-equality assertion here would be a flake generator
    // rather than a pin. What is exactly comparable is the SHAPE - how many datagrams, and how
    // long each one is - and that is what a probe would disturb: RetransmittedData appends
    // repair frames and PingWithPadding expands to the padding target, so either one leaking
    // onto the unimpaired path lengthens a datagram or adds one. Combined with
    // ProbeDatagramsSent == 0, which says the only reader never ran, the knob cannot have
    // contributed a byte.
    //
    // THE BYTE-EXACT HALF IS ALREADY IN THE GATE and is not restated here:
    // quic-fingerprint-readout.snapshot.txt and quic-http3-fingerprint-readout.snapshot.txt
    // pin the emitted fingerprint itself, neither mentions ProbeContents, and both pass
    // unchanged across A3-14.
    //
    // ALL THREE MEMBERS RATHER THAN THE TWO THAT CHANGED, so that "nothing throws for any
    // input" is witnessed on the ordinary path as well as at the setter.
    [Fact]
    public async Task TheProbeContentsDefaultChangesNothingOnAnUnimpairedPath()
    {
        var shapes = new Dictionary<TlsQuicProbeContents, List<int>>();

        foreach (var contents in Enum.GetValues<TlsQuicProbeContents>())
        {
            var spec = new TlsQuicConnectionSpec
            {
                PaddingTarget = 1200,
                SourceConnectionIdLength = SourceConnectionIdLength,
                Recovery = new TlsQuicRecoverySpec { ProbeContents = contents },
            };

            using var cancellation = new CancellationTokenSource(TestTimeout);
            using var pki = TestPki.Create();
            using var credential = Credential(pki);
            var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();

            // The impairing decorator with NO script: it impairs nothing and contributes the
            // ManualTimeProvider, which is what keeps the run off the wall clock. A wall clock
            // would let ACK timing vary between arms and turn a real difference into noise.
            await using var impaired = new ImpairingDatagramTransport(clientTransport);
            await using var connection = Connection(
                impaired, serverTransport, pki, spec, clock: impaired.Clock);
            await using var server = Server(
                credential, connection.OriginalDestinationConnectionId);
            await using var serverPeer = LoopbackQuicPeer.ForServer(
                serverTransport, clientTransport.LocalEndPoint, server, spec);

            await connection.StartAsync(cancellation.Token);
            Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
            Assert.False(await connection.PumpOnceAsync(cancellation.Token));
            _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);

            // NOT SCENERY: an arm that never completed would emit a short prefix of the same
            // lengths as the other arms and compare equal, which is the vacuous pass this
            // whole file exists to refuse.
            Assert.True(
                server.IsHandshakeComplete,
                $"The unimpaired handshake did not complete with ProbeContents={contents}.");

            await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
            Assert.True(await connection.PumpOnceAsync(cancellation.Token));
            Assert.True(connection.IsHandshakeConfirmed);

            // NOTHING WAS LOST, so nothing may have been probed or repaired. If a future build
            // ever armed a PTO on a clean path these three would catch it before the shape
            // comparison did, and would say why.
            Assert.Equal(0, connection.ProbeDatagramsSent);
            Assert.Equal(0, connection.FramesRetransmitted);
            Assert.Empty(impaired.Dropped);

            shapes[contents] = [.. impaired.Offered.Select(datagram => datagram.Length)];
        }

        // The opening flight is padded to 1200 by RFC 9000 s8.1, so a shape that did not start
        // there is not the handshake this test means to be comparing.
        var reference = shapes[TlsQuicProbeContents.RetransmittedData];
        Assert.NotEmpty(reference);
        Assert.Equal(1200, reference[0]);

        Assert.All(
            shapes,
            arm => Assert.Equal(reference, arm.Value));

        // AND THE SHIPPED DEFAULT IS THE ARM THE REFERENCE WAS TAKEN FROM, asserted here so
        // that this test still means what it says if the default moves again.
        Assert.Equal(
            TlsQuicProbeContents.RetransmittedData,
            new TlsQuicRecoverySpec().ProbeContents);
    }

    // s6.2.4's probe CONTENTS, read off the wire rather than off a counter. The probe still
    // carries the PING that line 192's "All probe packets sent on a PTO MUST be ack-eliciting"
    // requires, AND the previously-sent CRYPTO beside it - the two are not alternatives.
    [Fact]
    public async Task ARetransmittingProbeCarriesBothThePingAndThePreviouslySentCrypto()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        await using var connection = Connection(
            impaired, serverTransport, pki, RetransmittingProbeSpec(), clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, RetransmittingProbeSpec());

        impaired.Drop(2);
        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        var armed = Assert.IsType<DateTimeOffset>(connection.LossDetectionTimer);
        impaired.Clock.Advance(armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);

        // THE FAR SIDE'S REPORT OF WHAT THE PROBE CONTAINED, which is the only statement about
        // a protected packet's frames that cannot be made by the sender about itself.
        var carried = serverPeer.LastDatagramFrames;
        Assert.Contains(
            carried,
            f => f.Level == TlsQuicEncryptionLevel.Handshake
                && f.Type == TlsQuicFrameType.Ping);
        Assert.Contains(
            carried,
            f => f.Level == TlsQuicEncryptionLevel.Handshake
                && f.Type == TlsQuicFrameType.Crypto);
    }

    // ========================================================================
    // THE OPENING FLIGHT, WHICH IS THE ONE FLIGHT EVERY CONNECTION HAS.
    // ========================================================================
    //
    // A3-3's own comment on BuildInitialFlight names this as the case that must not be missed:
    // it "produces the FIRST packets this connection ever sends. Leaving it out would have left
    // the opening flight - the one flight guaranteed to exist on every connection - untracked".
    // A mutation sweep found exactly that gap here: deleting the ledger entry for the opening
    // flight left the whole gate green, because every other repair test starts from a handshake
    // that had already got past it.
    //
    // AND THIS IS THE HARDEST CASE IN THE SUBSYSTEM. Nothing has been acknowledged, so RFC 9002
    // A.10 returns at its first line - s6.1's condition is "was sent prior to an acknowledged
    // packet" - and no loss can be declared at all. The ONLY thing that moves is s6.2.4's probe,
    // and the only thing that makes it useful is that the flight was recorded when it was built.
    [Fact]
    public async Task ADroppedClientHelloIsRetransmittedByTheProbeAndTheHandshakeCompletes()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        // ONE PROBE DATAGRAM AND NOT knob 10's TWO, which is s6.2.4's floor - "a sender MUST
        // send at least one ack-eliciting packet in the packet number space as a probe" - and is
        // what keeps the datagram sequence below deterministic. With two, the second probe is a
        // duplicate ClientHello sitting in the peer's queue AHEAD of this client's next flight,
        // and the pump-by-pump script would be reading it instead. That is legal on the wire and
        // it is not what this test is about.
        var spec = RetransmittingProbeSpec(probePacketsPerPto: 1);
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);

        // ORDINAL 1 IS THE ClientHello, and dropping it means the server has never heard of this
        // connection. Nothing on the far side can be pumped until the client says it again.
        impaired.Drop(1);
        await connection.StartAsync(cancellation.Token);
        Assert.Equal([1], impaired.Dropped);
        Assert.Empty(impaired.Delivered);

        // s6.2.1's PTO, on the wrapper's clock.
        var armed = Assert.IsType<DateTimeOffset>(connection.LossDetectionTimer);
        impaired.Clock.Advance(armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.True(connection.ProbeDatagramsSent > 0);

        // NOTHING WAS DECLARED LOST, ASSERTED RATHER THAN ASSUMED. This is what makes the probe
        // the only route: a build that repaired via the loss path would leave this non-zero and
        // would be passing this test for a different reason than the one it claims.
        Assert.Equal(0, connection.PacketsDeclaredLost);
        Assert.True(connection.FramesRetransmitted > 0);

        // AND THE SERVER, WHICH HAS SEEN NOTHING UNTIL NOW, ANSWERS. Only a datagram carrying a
        // complete ClientHello at the right CRYPTO offset produces this.
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        Assert.True(
            server.IsHandshakeComplete,
            "The retransmitted ClientHello did not carry the handshake through.");

        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.True(connection.IsHandshakeConfirmed);
    }

    // ========================================================================
    // THE DEADLOCK ROW: A LOST GRANT, REPAIRED WITH THE CURRENT LIMIT.
    // ========================================================================
    //
    // TlsQuicStreams.cs:120-126 wrote this failure down before anything could repair it: "A
    // grant is computed once per threshold crossing, so if the datagram carrying it is lost the
    // peer stops at the old limit, sends nothing more, and nothing on this side crosses a
    // threshold again - the two ends wait on each other."
    //
    // AND THE TEST IS ABOUT THE VALUE, NOT ABOUT THE ARRIVAL. s13.3 says "an updated value is
    // sent", so the limit is raised between the send and the loss; a build that replayed the
    // lost frame would put the OLD number back, and s19.10's "MAX_STREAM_DATA frames that do
    // not increase the stream limit MUST be ignored" would make that repair a no-op the peer
    // discards - a repair that arrives, satisfies every "it came back" assertion, and still
    // deadlocks. THAT IS THE MUTANT THIS TEST EXISTS FOR.
    [Fact]
    public void ALostMaximumStreamDataGrantIsRepairedWithTheLimitAsItStandsNow()
    {
        var streams = RepairSet();
        var stream = streams.OpenBidirectional();

        // Two crossings of the update threshold, so the limit this endpoint grants moves twice.
        var first = DriveOneGrant(streams, stream);
        var second = DriveOneGrant(streams, stream);
        Assert.True(
            second > first,
            "The second grant did not raise the limit, so this test could not tell a refreshed "
                + "value from a replayed one.");

        // The FIRST grant's frame is the one whose packet was lost, and the limit has since
        // moved on to the second.
        var lost = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.MaxStreamData,
            StreamId = stream.Id,
            MaximumStreamData = first,
        };

        Assert.True(streams.TryRefreshGrant(lost, out var repaired));
        Assert.Equal(TlsQuicFrameType.MaxStreamData, repaired.Type);
        Assert.Equal(stream.Id, repaired.StreamId);
        Assert.Equal(second, repaired.MaximumStreamData);
        Assert.NotEqual(first, repaired.MaximumStreamData);
    }

    // The connection-scope twin. s13.3: "The current connection maximum data is sent in MAX_DATA
    // frames. An updated value is sent in a MAX_DATA frame if the packet containing the most
    // recently sent MAX_DATA frame is declared lost".
    [Fact]
    public void ALostMaximumDataGrantIsRepairedWithTheConnectionLimitAsItStandsNow()
    {
        var streams = RepairSet();
        var stream = streams.OpenBidirectional();

        DriveOneGrant(streams, stream);
        var connectionGrant = LastConnectionGrant(streams, stream);

        Assert.True(
            streams.TryRefreshGrant(
                new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.MaxData, MaximumData = 1 },
                out var repaired));
        Assert.Equal(TlsQuicFrameType.MaxData, repaired.Type);
        Assert.Equal(connectionGrant, repaired.MaximumData);
        Assert.NotEqual(1UL, repaired.MaximumData);
    }

    // s13.3's one SHOULD pointing the other way: "An endpoint SHOULD stop sending
    // MAX_STREAM_DATA frames when the receiving part of the stream enters a "Size Known" or
    // "Reset Recvd" state." Size Known is s3.2's state on the peer's FIN, after which no further
    // grant can matter - the peer has already said how much it will ever send.
    [Fact]
    public void AGrantIsNotRepairedOnceThePeersFinalSizeIsKnown()
    {
        var streams = RepairSet();
        var stream = streams.OpenBidirectional();
        var granted = DriveOneGrant(streams, stream);

        var lost = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.MaxStreamData,
            StreamId = stream.Id,
            MaximumStreamData = granted,
        };

        // BEFORE the FIN it is repaired, which is what makes the refusal below a refusal rather
        // than a stream this set never had.
        Assert.True(streams.TryRefreshGrant(lost, out _));

        Assert.True(stream.TryReceive(
            (ulong)stream.Received.Count, ReadOnlySpan<byte>.Empty, true, out _));
        Assert.True(stream.FinReceived);

        Assert.False(streams.TryRefreshGrant(lost, out _));
    }

    // A grant naming a stream this set does not hold. Never throws, and answers rather than
    // rejects - the frame is ours but the moment it is repaired at is the peer's.
    [Fact]
    public void AGrantForAStreamThatIsNotHeldIsDeclinedRatherThanThrown()
    {
        var streams = RepairSet();

        Assert.False(streams.TryRefreshGrant(
            new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.MaxStreamData,
                StreamId = 0xDEAD,
                MaximumStreamData = 1,
            },
            out _));

        // And a frame type that is not a grant at all, which is what routes CRYPTO and STREAM
        // past this method rather than through it.
        Assert.False(streams.TryRefreshGrant(
            new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Crypto }, out _));
    }

    // s13.3: "Endpoints SHOULD prioritize retransmission of data over sending new data, unless
    // priorities specified by the application indicate otherwise." The 1-RTT drain is where that
    // sentence is observable, and the ORDER WITHIN each half is preserved - two frames on one
    // stream carry consecutive offsets, and TakePendingFrames' own remark says reordering them
    // "hides a defect that would not work against a peer counting on s2.2".
    [Fact]
    public void RepairsLeaveTheOneRttDrainAheadOfNewDataAndInQueueOrder()
    {
        var streams = RepairSet();
        var stream = streams.OpenBidirectional();

        streams.Send(stream, new byte[] { 1, 2 });
        streams.Send(stream, new byte[] { 3, 4 });

        streams.RepairsOwed.Add(new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.MaxData, MaximumData = 111,
        });
        streams.RepairsOwed.Add(new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.MaxData, MaximumData = 222,
        });

        // A POSITIVE ASSERTION, AND IT IS DELIBERATELY NOT DISCRIMINATING - see ledger row
        // A38-M48. _pending is non-empty here too, so this line passes whether or not the flag
        // can see repairs. It is kept because it states the invariant a reader expects; what it
        // is NOT is evidence, and the reason no sharper test was written is that
        // HasPendingFrames has no production caller at all - grep returns tests only. Widening
        // it to include repairs is forward-looking consistency, not live behaviour, and a test
        // that pinned a property nothing reads would be witnessing its own fake.
        Assert.True(streams.HasPendingFrames);

        var taken = streams.TakePendingFrames();

        Assert.Equal(4, taken.Count);
        Assert.Equal(111UL, taken[0].MaximumData);
        Assert.Equal(222UL, taken[1].MaximumData);
        Assert.Equal(0UL, taken[2].Offset);
        Assert.Equal(2UL, taken[3].Offset);

        Assert.Equal(2, streams.RepairsSent);
        Assert.Empty(streams.RepairsOwed);
        Assert.False(streams.HasPendingFrames);
    }

    // THE CALIBRATION CONTROL FOR THE DRAIN, and it has to actually run: with nothing owed the
    // drain must return exactly what it always did, which is what keeps every existing 1-RTT
    // test green. A drain that always allocated the concatenation would pass the test above and
    // would also be indistinguishable from one that dropped the pending frames.
    [Fact]
    public void TheOneRttDrainWithNothingOwedReturnsThePendingFramesUnchanged()
    {
        var streams = RepairSet();
        var stream = streams.OpenBidirectional();

        streams.Send(stream, new byte[] { 1, 2 });
        streams.Send(stream, new byte[] { 3, 4 });

        Assert.Empty(streams.RepairsOwed);
        var taken = streams.TakePendingFrames();

        Assert.Equal(2, taken.Count);
        Assert.Equal(0UL, taken[0].Offset);
        Assert.Equal(2UL, taken[1].Offset);
        Assert.Equal(0, streams.RepairsSent);
    }

    // s13.3: "Application data sent in STREAM frames is retransmitted in new STREAM frames".
    // THE OFFSET IS THE INFORMATION, so the repair carries the lost frame's own offset and not
    // the stream's current send offset - and the two have diverged here by a second send.
    //
    // THROUGH A CONFIRMED HANDSHAKE, so that the repair travels the 1-RTT path the connection
    // really uses: TlsQuicConnection.QueueRepair hands it to the stream set, and the peer's own
    // report of what arrived is the assertion.
    [Fact]
    public async Task ALostStreamFrameIsRepairedAtItsOwnOffsetAndReachesThePeerThere()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        // THE WRAPPER'S CLOCK DRIVES THE CONNECTION, which is A3-1's whole reason for owning
        // one: the loss below is declared by s6.1.2's TIME threshold, and on TimeProvider.System
        // that would mean sleeping for a real loss delay in a unit test.
        // WITHOUT THE PATH MTU SEARCH, because this test drops a specific datagram BY ORDINAL
        // and then reads the frames of the one that follows. A PMTU probe is an ordinary
        // ack-eliciting datagram, so leaving the search on inserts an unrelated datagram into
        // the very sequence the drop is counted against. See SpecWithoutPathMtuSearch.
        var spec = SpecWithoutPathMtuSearch();
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, spec);
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenBidirectional();
        connection.Streams.Send(stream, new byte[] { 0x11, 0x22, 0x33 });

        // The datagram carrying offset 0 is DROPPED. The next ordinal is the one this send
        // produces, so the script is written against the count the wrapper has already seen.
        impaired.Drop(impaired.Offered.Count + 1);
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.Empty(serverPeer.ReceivedStreamFrames);

        // A second send moves the stream's own offset to 3, so a repair that read SendOffset
        // would put those three bytes back at 3 and the peer would splice them past bytes it
        // has never seen. THAT MUTANT PASSES EVERY "the transfer completed" TEST.
        connection.Streams.Send(stream, new byte[] { 0x44, 0x55 });
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(5UL, stream.SendOffset);

        // The peer acknowledges the SECOND packet, which is what lets A.10 run at all - s6.1's
        // first condition is "was sent prior to an acknowledged packet" - and the clock has
        // moved past the loss delay, which is what makes the FIRST packet meet s6.1.2's time
        // threshold. This is the loopback's own ACK rather than one this test fabricated.
        var spentBeforeTheRepair = stream.Budget!.Remaining;
        impaired.Clock.Advance(TimeThresholdGap);
        await serverPeer.SendAckAsync(SentAt, cancellation.Token);

        // ONE PUMP DOES BOTH HALVES, AND THAT IS THE POINT RATHER THAN A SHORTCUT. The pump
        // opens the ACK, A.7 runs A.10, A.10 declares the first packet lost, s13.3 queues the
        // repair - and the pump's own closing send pass, the ordinary one that has always been
        // there, carries it. NOTHING ON THE REPAIR PATH SENDS A DATAGRAM OF ITS OWN.
        //
        // THE RETURN IS DISCARDED AND THAT IS NOT LAZINESS. TlsQuicConnection.PumpOnceAsync
        // returns RFC 9001 s4.1.2's CONFIRMED flag, which is already true here and stays true;
        // asserting it would be asserting the handshake this test set up rather than the ACK it
        // just delivered.
        _ = await connection.PumpOnceAsync(cancellation.Token);

        Assert.True(
            connection.PacketsDeclaredLost > 0,
            "Nothing was declared lost, so the repair below would be vacuous.");

        // AND THERE IS NOTHING LEFT OWED, because the pump above already sent it. A build whose
        // repair needed a second, separate send would leave something here.
        Assert.False(await connection.SendPendingAsync(cancellation.Token));
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);

        // THE PEER'S REPORT. The three bytes came back AT OFFSET 0.
        var repaired = Assert.Single(serverPeer.ReceivedStreamFrames, f => f.Offset == 0);
        Assert.Equal(stream.Id, repaired.StreamId);
        Assert.Equal(new byte[] { 0x11, 0x22, 0x33 }, repaired.Data);
        Assert.True(connection.FramesRetransmitted > 0);

        // RFC 9000 s4.1 counts flow control by the HIGHEST OFFSET SENT, so a retransmission
        // spends nothing further. A repair routed back through TlsQuicStreamSet.Send would
        // charge the budget twice and stall a transfer at the peer's limit for a reason nothing
        // on the wire could explain.
        Assert.Equal(spentBeforeTheRepair, stream.Budget!.Remaining);
    }

    // ========================================================================
    // THE DEADLOCK, END TO END: A DROPPED GRANT REACHES THE PEER ANYWAY.
    // ========================================================================
    //
    // The unit tests above pin the VALUE the repair carries. This one pins that it travels: a
    // MAX_STREAM_DATA frame whose datagram is dropped is queued again by s13.3 and arrives at
    // the peer, through the ordinary 1-RTT send path and with no schedule of its own -
    // TlsQuicStreams.cs:120-126 ruled that out ("a receiver that re-sent grants on a timer
    // would be duplicating A3's loss detection in one frame type's private schedule").
    //
    // WHAT THIS TEST CANNOT CLAIM, SAID PLAINLY RATHER THAN IMPLIED. The plan asks for "the
    // transfer completes rather than stalling", and LoopbackQuicPeer CANNOT STALL: it has no
    // flow-control state at all - TlsQuicConnectionStreamTests' header says "LoopbackQuicPeer
    // has no stream implementation" - so it would keep sending past a limit it never read. The
    // stall is the PEER's behaviour and the repair is ours; this asserts the half that is ours,
    // and the arrival is what a stalling peer would have been waiting for.
    [Fact]
    public async Task ADroppedMaximumStreamDataGrantIsRepairedAndReachesThePeer()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        await using var connection = Connection(
            impaired, serverTransport, pki, GrantRepairSpec(), clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, GrantRepairSpec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenBidirectional();
        var window = connection.Streams.LocalFlowControl.ReceiveLimitFor(stream.Id);

        // ENOUGH TO CROSS THE UPDATE THRESHOLD, computed from the window rather than typed: the
        // grant is owed when the outstanding credit falls below half of it.
        await serverPeer.SendStreamFramesAsync(
            [PeerStreamFrame(stream.Id, 0, new byte[(int)window - 1])],
            cancellation.Token);

        // THE PUMP THAT RECEIVES THE DATA IS ALSO THE PUMP THAT SENDS THE GRANT, and the
        // datagram it sends is the one dropped. The ordinal is the wrapper's own count plus
        // one rather than a literal, because the handshake above spends a different number of
        // datagrams than the other tests in this file.
        impaired.Drop(impaired.Offered.Count + 1);
        _ = await connection.PumpOnceAsync(cancellation.Token);
        Assert.Equal([impaired.Offered.Count], impaired.Dropped);

        // The grant left this side's queue with that datagram, so nothing here is owed and the
        // peer has not seen it. A build that repaired grants on a timer would fail from here on
        // for the right reason and the wrong one at once.
        Assert.False(connection.Streams.HasPendingFrames);

        // A SECOND ARRIVAL, so that this side sends a later 1-RTT packet the peer can name in
        // an acknowledgement - s6.1's first condition is "was sent prior to an acknowledged
        // packet", and without one A.10 returns before it can declare anything.
        await serverPeer.SendStreamFramesAsync(
            [PeerStreamFrame(stream.Id, window - 1, [0x99])], cancellation.Token);
        _ = await connection.PumpOnceAsync(cancellation.Token);
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);

        // s6.1.2's time threshold, on the wrapper's clock. A bounded advance rather than a real
        // wait: the deadline this test runs under is the fake clock's, which is the plan's
        // "bounded fake-clock deadline".
        impaired.Clock.Advance(TimeThresholdGap);
        await serverPeer.SendAckAsync(SentAt, cancellation.Token);
        _ = await connection.PumpOnceAsync(cancellation.Token);

        Assert.True(
            connection.PacketsDeclaredLost > 0,
            "Nothing was declared lost, so the repair below would be vacuous.");
        Assert.True(connection.FramesRetransmitted > 0);

        // THE FAR SIDE'S REPORT. The grant arrived, in a 1-RTT packet, without this side ever
        // crossing a threshold a second time.
        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        Assert.Contains(
            serverPeer.LastDatagramFrames,
            f => f.Level == TlsQuicEncryptionLevel.Application
                && f.Type == TlsQuicFrameType.MaxStreamData);
    }

    // THE DEFENSIVE COPY, WITNESSED RATHER THAN ASSERTED IN A COMMENT. The repair ledger's field
    // remark calls the copy "load-bearing rather than cautious", and a mutation sweep found that
    // claim had no test behind it: deleting the ToArray left the whole gate green.
    //
    // THE HAZARD IS THE ORDINARY SHAPE OF THE SEND PATH, not a contrived one. A CRYPTO frame's
    // Data is a window onto a TlsQuicCryptoDataEvent's buffer, and SendAnswerAsync disposes
    // every result in a finally block on the way out of the pump - so a ledger holding that
    // window would retransmit whatever the buffer held next, with no error anywhere and a peer
    // that fails the handshake on a MAC check it cannot explain. Finding 1 states the same thing
    // from the other end: CustomTlsQuicClient "hands over the only copy".
    //
    // OVERWRITING THE ARRAY IS HOW A TEST SEES IT. The bytes handed to RecordRepairable are
    // scribbled over before the loss is declared; a ledger that kept the reference repairs the
    // scribble, and one that copied repairs what was sent.
    [Fact]
    public async Task ARepairCarriesTheBytesAsTheyWereSentAndNotTheBuffersLaterContents()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        var buffer = new byte[] { 0x11, 0x22, 0x33, 0x44 };
        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Handshake,
            0,
            [new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.Crypto,
                Offset = 0,
                Data = buffer,
            }]);

        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 0, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 1, clock.GetUtcNow()));

        // The buffer is reused, which is exactly what TlsQuicProcessResult.Dispose and every
        // pooled receive buffer in this tree do to theirs.
        Array.Fill(buffer, (byte)0xFF);

        clock.Advance(TimeThresholdGap);
        Acknowledge(connection, TlsQuicEncryptionLevel.Handshake, 1);

        var repaired = Assert.Single(connection.RepairsOwed(TlsQuicEncryptionLevel.Handshake));
        Assert.Equal(new byte[] { 0x11, 0x22, 0x33, 0x44 }, repaired.Data.ToArray());
    }

    // ========================================================================
    // THE TWO HAZARDS THE BRIEF NAMES: A DUPLICATE, AND A LOOP.
    // ========================================================================

    // "The same information is never sent twice concurrently at two offsets, with a witness."
    // The opening flight records the whole CRYPTO stream against every packet of it - see
    // BuildInitialFlight - so two lost packets of one flight both owe the same bytes, and a
    // queue that took both would put the ClientHello into one packet twice.
    [Fact]
    public async Task InformationTwoLostPacketsBothCarriedIsQueuedOnce()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        ReadOnlyMemory<byte> hello = new byte[] { 0x01, 0x00, 0x02, 0x03 };
        var crypto = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Crypto,
            Offset = 0,
            Data = hello,
        };

        connection.RecordRepairable(TlsQuicEncryptionLevel.Initial, 0, [crypto]);
        connection.RecordRepairable(TlsQuicEncryptionLevel.Initial, 1, [crypto]);
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 0, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 1, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 2, clock.GetUtcNow()));

        // s6.1.2's TIME THRESHOLD is what declares the loss below, so the clock moves past the
        // loss delay first. The packet threshold would need three packet numbers of headroom
        // and would make every packet number here arithmetic about kPacketThreshold rather
        // than about the repair.
        clock.Advance(TimeThresholdGap);
        var lost = Acknowledge(connection, TlsQuicEncryptionLevel.Initial, 2);
        Assert.Equal(2, lost.Count);

        var repaired = Assert.Single(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(0UL, repaired.Offset);
        Assert.Equal(hello.ToArray(), repaired.Data.ToArray());
    }

    // A DIFFERENT OFFSET IS DIFFERENT INFORMATION, which is the other half of the sentence
    // above and the calibration control for it: a duplicate check that compared nothing would
    // pass the test above and would also collapse these two into one, losing four bytes of a
    // handshake with no error anywhere.
    [Fact]
    public async Task TheSameBytesAtTwoOffsetsAreTwoRepairsAndNotOne()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        ReadOnlyMemory<byte> bytes = new byte[] { 7, 7, 7, 7 };
        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Initial,
            0,
            [new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.Crypto, Offset = 0, Data = bytes,
            }]);
        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Initial,
            1,
            [new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.Crypto, Offset = 4, Data = bytes,
            }]);
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 0, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 1, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 2, clock.GetUtcNow()));

        // s6.1.2's TIME THRESHOLD is what declares the loss below, so the clock moves past the
        // loss delay first. The packet threshold would need three packet numbers of headroom
        // and would make every packet number here arithmetic about kPacketThreshold rather
        // than about the repair.
        clock.Advance(TimeThresholdGap);
        Acknowledge(connection, TlsQuicEncryptionLevel.Initial, 2);

        Assert.Equal(
            [0UL, 4UL],
            connection.RepairsOwed(TlsQuicEncryptionLevel.Initial)
                .Select(static f => f.Offset)
                .Order());
    }

    // "A hang is impossible - prove it. A retransmission loop that re-sends what it just sent is
    // the obvious hazard." The proof is structural and this test is what makes it observable:
    // a repair leaves the queue when it is taken, and it can only re-enter by a NEW packet being
    // declared lost - so a hundred rounds of lose-repair-send leave the queue bounded by one
    // entry and the work per round constant, rather than growing by one repair per round.
    [Fact]
    public async Task RepairingARepairTerminatesAndTheQueueDoesNotGrow()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        ReadOnlyMemory<byte> payload = new byte[] { 0x42 };
        ulong number = 0;

        for (var round = 0; round < 100; round++)
        {
            connection.RecordRepairable(
                TlsQuicEncryptionLevel.Initial,
                number,
                [new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.Crypto, Offset = 0, Data = payload,
                }]);
            connection.OnPacketSent(
                PacketAt(TlsQuicEncryptionLevel.Initial, number, clock.GetUtcNow()));
            connection.OnPacketSent(
                PacketAt(TlsQuicEncryptionLevel.Initial, number + 1, clock.GetUtcNow()));

            clock.Advance(TimeThresholdGap);
            Acknowledge(connection, TlsQuicEncryptionLevel.Initial, number + 1);

            // ONE, EVERY ROUND. Not zero - the loss is real and the repair is owed - and not
            // `round`, which is what a queue that never drained would show.
            Assert.Single(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));

            // The drain the send path performs - the same method BuildAnswerDatagram calls.
            var drained = new List<TlsQuicFrame>();
            connection.TakeRepairsInto(TlsQuicEncryptionLevel.Initial, drained, TlsQuicUdpDatagramTransport.MaximumUdpPayload);
            Assert.Single(drained);
            Assert.Empty(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));

            number += 2;
        }

        Assert.Equal(100, connection.FramesRetransmitted);
    }

    // ========================================================================
    // RFC 9002 s7's SEND GATE, ON THE ONE PATH THIS TASK OWNS.
    // ========================================================================
    //
    // "A retransmission that ignores congestion control is a defect, not a feature." The gate is
    // the controller knob 4 names, and a refused repair STAYS OWED - dropping it would turn a
    // full window into a lost handshake, which is worse than the send it was avoiding.
    [Fact]
    public async Task ARepairIsWithheldWhileTheWindowIsFullAndIsStillOwedAfterwards()
    {
        var clock = FakeClock();
        var gate = new ScriptedSendGate { Open = false };
        await using var connection = LossDetectionConnectionOn(
            clock, new TlsQuicRecoverySpec { CongestionController = () => gate });

        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Initial,
            0,
            [new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.Crypto,
                Offset = 0,
                Data = new byte[] { 1, 2, 3 },
            }]);
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 0, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 1, clock.GetUtcNow()));
        // s6.1.2's TIME THRESHOLD is what declares the loss below, so the clock moves past the
        // loss delay first. The packet threshold would need three packet numbers of headroom
        // and would make every packet number here arithmetic about kPacketThreshold rather
        // than about the repair.
        clock.Advance(TimeThresholdGap);
        Acknowledge(connection, TlsQuicEncryptionLevel.Initial, 1);

        Assert.Single(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));

        // REFUSED, AND NOT LOST.
        var refused = new List<TlsQuicFrame>();
        connection.TakeRepairsInto(TlsQuicEncryptionLevel.Initial, refused, TlsQuicUdpDatagramTransport.MaximumUdpPayload);
        Assert.Empty(refused);
        Assert.Single(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(0, connection.FramesRetransmitted);

        // AND THE GATE WAS ASKED ABOUT THE BYTES THIS PASS WOULD ADD, not about zero - a gate
        // handed a constant would answer the same for a full window and an empty one.
        Assert.Equal([3], gate.Asked);

        gate.Open = true;
        var admitted = new List<TlsQuicFrame>();
        connection.TakeRepairsInto(TlsQuicEncryptionLevel.Initial, admitted, TlsQuicUdpDatagramTransport.MaximumUdpPayload);
        Assert.Single(admitted);
        Assert.Equal(1, connection.FramesRetransmitted);
    }

    // THE CALIBRATION CONTROL FOR THE GATE, and it is the same script with knob 4 left at its
    // shipped null. NULL IS NOT "NO CONGESTION CONTROL" - the knob's own remarks say null "means
    // the NewReno controller RFC 9002 s7 specifies, which task A3-9 supplies", and until this
    // task nothing constructed one, so that sentence was false. This asserts it is true: an
    // unconfigured connection runs NewReno, its window is s7.2's initial window, and a repair
    // that fits inside it is admitted.
    [Fact]
    public async Task TheShippedDefaultRunsNewRenoAndAdmitsARepairThatFitsItsWindow()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);
        Assert.Null(new TlsQuicRecoverySpec().CongestionController);

        // THE SEAM'S OWN NAME, not a type test - the readout task A3-12 reports this string, and
        // a connection that hard-coded a controller would still answer it.
        Assert.Equal("NewReno", connection.CongestionControl.Name);
        Assert.True(connection.CongestionControl.CongestionWindowBytes > 0);

        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Initial,
            0,
            [new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.Crypto,
                Offset = 0,
                Data = new byte[] { 1, 2, 3 },
            }]);
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 0, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 1, clock.GetUtcNow()));
        // s6.1.2's TIME THRESHOLD is what declares the loss below, so the clock moves past the
        // loss delay first. The packet threshold would need three packet numbers of headroom
        // and would make every packet number here arithmetic about kPacketThreshold rather
        // than about the repair.
        clock.Advance(TimeThresholdGap);
        Acknowledge(connection, TlsQuicEncryptionLevel.Initial, 1);

        var drained = new List<TlsQuicFrame>();
        connection.TakeRepairsInto(TlsQuicEncryptionLevel.Initial, drained, TlsQuicUdpDatagramTransport.MaximumUdpPayload);
        Assert.Single(drained);
        Assert.Equal(1, connection.FramesRetransmitted);
    }

    // RFC 9002 s7.5 lines 195-197: "Probe packets MUST NOT be blocked by the congestion
    // controller. A sender MUST however count these packets as being additionally in flight."
    // The probe therefore carries its repair through a shut gate, which is the opposite of the
    // test two above and is the sentence rather than an inconsistency.
    [Fact]
    public async Task AProbeCarriesItsRepairThroughAShutCongestionWindow()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var gate = new ScriptedSendGate { Open = false };
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);
        var spec = RetransmittingProbeSpec(gate);
        await using var connection = Connection(
            impaired, serverTransport, pki, spec, clock: impaired.Clock);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        impaired.Drop(2);
        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        var armed = Assert.IsType<DateTimeOffset>(connection.LossDetectionTimer);
        impaired.Clock.Advance(armed - impaired.Clock.GetUtcNow() + TimeSpan.FromMilliseconds(1));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        _ = await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        Assert.True(server.IsHandshakeComplete);
        Assert.True(connection.FramesRetransmitted > 0);
    }

    // A3-9's interface asks for exactly this test and says why: "THE CONTROLLER'S OWN COUNTER,
    // not a view of TlsQuicConnection.BytesInFlight. The two are computed from the same events
    // and should agree, and a test that asserts they do is worth more than a shared field would
    // be." Until this task nothing constructed a controller, so there was no second counter to
    // compare against and the sentence had no witness.
    //
    // THE THREE EVENTS THAT MOVE EITHER COUNTER ARE ALL EXERCISED - a send, an acknowledgement
    // and a loss - because a wiring that fed the controller only one of them would keep the two
    // in step through the first and diverge on the rest.
    [Fact]
    public async Task TheControllersBytesInFlightAgreesWithTheConnectionsThroughSendAckAndLoss()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);
        var controller = connection.CongestionControl;

        Assert.Equal(connection.BytesInFlight, controller.BytesInFlight);

        // B.4's OnPacketSentCC.
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 0, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 1, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 2, clock.GetUtcNow()));
        Assert.True(connection.BytesInFlight > 0);
        Assert.Equal(connection.BytesInFlight, controller.BytesInFlight);

        // B.5's OnPacketsAcked and, in the same pass, B.8's OnPacketsLost - the acknowledgement
        // of packet 2 retires it and declares 0 and 1 lost on s6.1.2's time threshold.
        clock.Advance(TimeThresholdGap);
        var lost = Acknowledge(connection, TlsQuicEncryptionLevel.Handshake, 2);
        Assert.Equal([0UL, 1UL], lost.Select(static p => p.PacketNumber).Order());

        Assert.Equal(0L, connection.BytesInFlight);
        Assert.Equal(connection.BytesInFlight, controller.BytesInFlight);

        // AND THE LOSS WAS A CONGESTION EVENT, not merely an accounting one. s7.3.2 halves the
        // window on entering recovery, so a controller that had been handed the packets but not
        // the event would agree on bytes in flight and disagree on everything that matters.
        Assert.True(
            controller.CongestionWindowBytes
                < new TlsQuicNewRenoCongestionController(
                    new TlsQuicRecoverySpec(), Spec().PaddingTarget).CongestionWindowBytes,
            "The window did not shrink, so B.8's congestion event never reached the controller.");
    }

    // B.9's RemoveFromBytesInFlight, which the interface warns about by name: without it "a
    // handshake's worth of Initial bytes stays in flight for the life of the connection and
    // permanently shrinks the room CanSend reports". A key discard is the one path that retires
    // packets without acknowledging or losing them.
    [Fact]
    public async Task AKeyDiscardTakesItsPacketsOutOfBothBytesInFlightCounters()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);
        var controller = connection.CongestionControl;

        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 0, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 1, clock.GetUtcNow()));
        var windowBeforeTheDiscard = controller.CongestionWindowBytes;
        Assert.True(controller.BytesInFlight > 0);

        connection.ForgetSpace(TlsQuicEncryptionLevel.Initial);

        Assert.Equal(0L, connection.BytesInFlight);
        Assert.Equal(0L, controller.BytesInFlight);

        // NOT A CONGESTION EVENT, which is the half a test watching only the counter would miss:
        // B.9 "touch[es] bytes in flight and nothing else - no window change, no recovery
        // period - because a discarded packet is neither delivered nor lost".
        Assert.Equal(windowBeforeTheDiscard, controller.CongestionWindowBytes);
    }

    // ========================================================================
    // A3-10's THREE OWED CALL LINES, WITNESSED ON THE LIVE LOSS PASS.
    // ========================================================================
    //
    // A3-10 built RFC 9002 s7.6's predicate and recorded that nothing called it: "Nothing calls
    // TlsQuicPersistentCongestion from TlsQuicConnection.cs or TlsQuicLossDetection.cs ... The
    // call site is three lines - OnPacketsLost, then IsEstablished, then OnPersistentCongestion,
    // in B.8's order." Those files are this task's, so this task wrote them, and these two tests
    // are what stops them being inert - which is exactly what loss detection was between A3-6
    // and A3-7.
    //
    // THE SPAN AND THE DURATION BOTH COME FROM THE PRODUCTION FORMULA, not from a literal.
    // TlsQuicPersistentCongestion.DurationFor is the owner; the blackout is built to exceed
    // what it returns for THIS connection's live estimator, so a change to kPersistentCongestion
    // Threshold moves the test with the code instead of stranding it.
    [Fact]
    public async Task ABlackoutLongerThanSection76sDurationCollapsesTheWindow()
    {
        var clock = FakeClock();
        var gate = new ScriptedSendGate { Open = true };
        var recovery = new TlsQuicRecoverySpec { CongestionController = () => gate };
        await using var connection = LossDetectionConnectionOn(clock, recovery);

        var duration = AnchorWithAnRttSample(connection, clock, recovery);

        // TWO ACK-ELICITING PACKETS SPANNING MORE THAN THE DURATION. Two is s7.6's floor -
        // IsEstablished returns false below two candidates, because a "period" needs two edges -
        // and the span is one tick over, which is the boundary rather than a comfortable margin.
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 1, clock.GetUtcNow()));
        clock.Advance(duration + TimeSpan.FromTicks(1));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 2, clock.GetUtcNow()));

        // The packet that ENDS the blackout, and the one whose acknowledgement declares the
        // other two lost - A.10 only ever considers packets below largest_acked, so the
        // declaring acknowledgement is always for a packet sent after the span.
        clock.Advance(TimeThresholdGap);
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 3, clock.GetUtcNow()));

        var lost = Acknowledge(connection, TlsQuicEncryptionLevel.Handshake, 3);
        Assert.Equal([1UL, 2UL], lost.Select(static p => p.PacketNumber).Order());

        // B.8's ORDER, READ OFF THE CONTROLLER RATHER THAN ASSUMED. OnPacketsLost has to come
        // first: it is what takes the lost bytes out of bytes_in_flight, and a collapse
        // evaluated before it would shrink a window with the flight still counted against it.
        Assert.Equal(["OnPacketsLost", "OnPersistentCongestion"], gate.Calls);
        Assert.Equal(1, connection.PersistentCongestionEvents);
    }

    // THE CALIBRATION CONTROL, AND IT IS THE TEST ABOVE WITH ONE TICK TAKEN OFF THE SPAN.
    // s7.6.1's period must EXCEED the duration - IsEstablished ends "newest - oldest > duration"
    // - so a span exactly equal to it is loss and not persistent congestion. Without this row a
    // wiring that called OnPersistentCongestion on every loss would pass the test above.
    [Fact]
    public async Task ABlackoutExactlyAsLongAsTheDurationIsLossAndNotPersistentCongestion()
    {
        var clock = FakeClock();
        var gate = new ScriptedSendGate { Open = true };
        var recovery = new TlsQuicRecoverySpec { CongestionController = () => gate };
        await using var connection = LossDetectionConnectionOn(clock, recovery);

        var duration = AnchorWithAnRttSample(connection, clock, recovery);

        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 1, clock.GetUtcNow()));
        clock.Advance(duration);
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 2, clock.GetUtcNow()));

        clock.Advance(TimeThresholdGap);
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 3, clock.GetUtcNow()));

        var lost = Acknowledge(connection, TlsQuicEncryptionLevel.Handshake, 3);
        Assert.Equal([1UL, 2UL], lost.Select(static p => p.PacketNumber).Order());

        // THE LOSS IS STILL REPORTED. A control that saw nothing at all would also pass a build
        // that had stopped calling the controller entirely.
        Assert.Equal(["OnPacketsLost"], gate.Calls);
        Assert.Equal(0, connection.PersistentCongestionEvents);
    }

    // ========================================================================
    // TOTALITY: NOTHING HERE THROWS, FOR ANY INPUT.
    // ========================================================================
    //
    // Every argument on this path is either the peer's - the ACK whose timing decides when a
    // loss is declared - or a frame this connection built out of the TLS engine's bytes. A
    // throw on either takes a connection down at the moment the network was already misbehaving.
    [Fact]
    public async Task NoShapeOfRecordedFrameMakesTheRepairPathThrow()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        connection.RecordRepairable(TlsQuicEncryptionLevel.Initial, 0, null);
        connection.RecordRepairable(TlsQuicEncryptionLevel.Initial, 0, []);

        // A grant for a stream that does not exist, a frame type nothing declares, an empty
        // payload, and a maximal offset - all recorded against one packet, all lost at once.
        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Application,
            0,
            [
                new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.MaxStreamData,
                    StreamId = 0xDEAD,
                    MaximumStreamData = ulong.MaxValue,
                },
                new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.MaxData },
                new TlsQuicFrame { RawType = 0x3fffffff },
                new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.Crypto,
                    Offset = ulong.MaxValue,
                    Data = ReadOnlyMemory<byte>.Empty,
                },
            ]);

        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Application, 0, clock.GetUtcNow()));
        connection.OnPacketSent(
            PacketAt(TlsQuicEncryptionLevel.Application, 1, clock.GetUtcNow()));

        // s6.1.2's TIME THRESHOLD is what declares the loss below, so the clock moves past the
        // loss delay first. The packet threshold would need three packet numbers of headroom
        // and would make every packet number here arithmetic about kPacketThreshold rather
        // than about the repair.
        clock.Advance(TimeThresholdGap);
        Acknowledge(connection, TlsQuicEncryptionLevel.Application, 1);

        // The two grants had no stream set to refresh from, so both were declined; the maximal
        // CRYPTO offset was repaired, because an offset is a number and s16 permits that one.
        Assert.Equal(2, connection.FramesNotRepaired);
        Assert.Single(connection.RepairsOwed(TlsQuicEncryptionLevel.Application));

        // And the timer arm again, twice, with nothing left to lose. A.9's rung 1 walks an
        // empty space and A.9's send rungs decide a probe for one whose keys never existed;
        // nothing on either path may throw for that.
        clock.Advance(TimeThresholdGap);
        connection.OnLossDetectionTimeout();
        connection.OnLossDetectionTimeout();
    }

    // RFC 9000 s13.3: "Data in CRYPTO frames for Initial and Handshake packets is discarded when
    // keys for the corresponding packet number space are discarded." A repair owed at a level
    // whose keys have gone can never be protected, so it must not survive the discard - and the
    // failure it would otherwise cause is silent, because BuildAnswerDatagram's discarded-level
    // arm drops such a packet without an error for the life of the connection.
    [Fact]
    public async Task RepairsOwedAtALevelDoNotSurviveThatLevelsKeyDiscard()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Initial,
            0,
            [new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.Crypto,
                Offset = 0,
                Data = new byte[] { 1 },
            }]);
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 0, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Initial, 1, clock.GetUtcNow()));
        // s6.1.2's TIME THRESHOLD is what declares the loss below, so the clock moves past the
        // loss delay first. The packet threshold would need three packet numbers of headroom
        // and would make every packet number here arithmetic about kPacketThreshold rather
        // than about the repair.
        clock.Advance(TimeThresholdGap);
        Acknowledge(connection, TlsQuicEncryptionLevel.Initial, 1);
        Assert.Single(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));

        connection.ForgetSpace(TlsQuicEncryptionLevel.Initial);

        Assert.Empty(connection.RepairsOwed(TlsQuicEncryptionLevel.Initial));
        Assert.Empty(connection.SentPackets(TlsQuicEncryptionLevel.Initial));
    }

    // s13.3's closing advice, and it is the reason Forget is the single exit: "A sender SHOULD
    // avoid retransmitting information from packets once they are acknowledged." An
    // acknowledged packet's ledger entry goes with the packet, so a LATER loss in the same space
    // cannot resurrect it.
    [Fact]
    public async Task AnAcknowledgedPacketsInformationIsNeverRepairedAfterwards()
    {
        var clock = FakeClock();
        await using var connection = LossDetectionConnectionOn(clock);

        connection.RecordRepairable(
            TlsQuicEncryptionLevel.Handshake,
            0,
            [new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.Crypto,
                Offset = 0,
                Data = new byte[] { 0xAA },
            }]);
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 0, clock.GetUtcNow()));

        // Packet 0 is ACKNOWLEDGED, so its information leaves with it.
        // s6.1.2's TIME THRESHOLD is what declares the loss below, so the clock moves past the
        // loss delay first. The packet threshold would need three packet numbers of headroom
        // and would make every packet number here arithmetic about kPacketThreshold rather
        // than about the repair.
        clock.Advance(TimeThresholdGap);
        Acknowledge(connection, TlsQuicEncryptionLevel.Handshake, 0);
        Assert.Empty(connection.RepairsOwed(TlsQuicEncryptionLevel.Handshake));

        // A later packet in the same space is then lost. If the ledger had kept packet 0's
        // entry, this pass would repair CRYPTO bytes the peer already has.
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 1, clock.GetUtcNow()));
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 2, clock.GetUtcNow()));
        // s6.1.2's TIME THRESHOLD is what declares the loss below, so the clock moves past the
        // loss delay first. The packet threshold would need three packet numbers of headroom
        // and would make every packet number here arithmetic about kPacketThreshold rather
        // than about the repair.
        clock.Advance(TimeThresholdGap);
        var lost = Acknowledge(connection, TlsQuicEncryptionLevel.Handshake, 2);

        Assert.Equal([1UL], lost.Select(static p => p.PacketNumber));
        Assert.Empty(connection.RepairsOwed(TlsQuicEncryptionLevel.Handshake));
    }

    // ------------------------------------------------------------------------
    // Helpers.
    // ------------------------------------------------------------------------

    // KNOB 11 AT ITS FIRST VALUE, WHICH SINCE TASK A3-14 IS NO LONGER THE DEFAULT AND SO HAS TO
    // BE ASKED FOR BY NAME. It shipped as the default until A3-14 measured what it costs;
    // A3-13's live run met a server that answers a PING-only Initial probe with
    // CONNECTION_CLOSE 0x0a. The value stays selectable because a real client may send exactly
    // that, and this helper is the witness that selecting it still works end to end.
    private static TlsQuicConnectionSpec PingOnlyProbeSpec() => new()
    {
        PaddingTarget = 1200,
        SourceConnectionIdLength = SourceConnectionIdLength,
        Recovery = new TlsQuicRecoverySpec
        {
            ProbeContents = TlsQuicProbeContents.Ping,
        },
    };

    // Knob 11 at its third value, which is the only member of TlsQuicProbeContents A3-7 could
    // not make observable - its own comment names this task for it. SINCE TASK A3-14 THIS IS
    // ALSO THE SHIPPED DEFAULT, and it is still set explicitly here: a test that means to
    // exercise one arm of a knob should say which arm, not inherit it.
    private static TlsQuicConnectionSpec RetransmittingProbeSpec(
        ITlsQuicCongestionController? controller = null,
        int? probePacketsPerPto = null) => new()
        {
            PaddingTarget = 1200,
            SourceConnectionIdLength = SourceConnectionIdLength,
            Recovery = new TlsQuicRecoverySpec
            {
                ProbeContents = TlsQuicProbeContents.RetransmittedData,
                ProbePacketsPerPto =
                    probePacketsPerPto ?? TlsQuicRecoverySpec.DefaultProbePacketsPerPto,
                CongestionController = controller is null ? null : () => controller,
            },
        };

    // Takes one RFC 9002 s5 RTT sample and leaves s7.6's anchor on the sampled packet, then
    // returns the persistent-congestion duration THIS connection's estimator implies.
    //
    // THE SAMPLE IS NOT OPTIONAL SCENERY: IsEstablished's first test is that a first RTT sample
    // exists, and its second discards any lost packet sent at or before it - so a blackout built
    // without one is not a weaker test, it is a vacuous one.
    private static TimeSpan AnchorWithAnRttSample(
        TlsQuicConnection connection, ManualTimeProvider clock, TlsQuicRecoverySpec recovery)
    {
        connection.OnPacketSent(PacketAt(TlsQuicEncryptionLevel.Handshake, 0, clock.GetUtcNow()));
        clock.Advance(TimeSpan.FromMilliseconds(20));

        // THE SAMPLING OVERLOAD, which is the one that moves latest_rtt and first_rtt_sample.
        // The four-argument one the other tests here use deliberately does not sample.
        var frame = AckFrame(new TlsQuicAckRange(0, 0));
        Assert.True(connection.Acks.ProcessAckFrame(
            TlsQuicEncryptionLevel.Handshake,
            frame,
            clock.GetUtcNow(),
            connection.SentPackets(TlsQuicEncryptionLevel.Handshake),
            out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        connection.OnAckReceived(TlsQuicEncryptionLevel.Handshake, frame);

        Assert.NotNull(connection.Acks.FirstRttSampleAt);
        Assert.Empty(connection.SentPackets(TlsQuicEncryptionLevel.Handshake));

        // s7.6's second filter discards a lost packet sent AT the first sample instant, so the
        // blackout starts strictly after it.
        clock.Advance(TimeSpan.FromTicks(1));

        return TlsQuicPersistentCongestion.DurationFor(
            recovery,
            connection.Acks.SmoothedRtt,
            connection.Acks.RttVariation,
            TlsQuicAckTracker.DefaultMaxAckDelay);
    }

    // A spec whose per-stream receive window is small enough that one frame crosses the update
    // threshold. THE WINDOW IS THE ONLY KNOB MOVED - everything else is the default Spec() -
    // because the grant's arithmetic is TlsQuicLocalFlowControlSpec's and this test is about
    // what happens to the frame it produces.
    private static TlsQuicConnectionSpec GrantRepairSpec() => new()
    {
        PaddingTarget = 1200,
        SourceConnectionIdLength = SourceConnectionIdLength,
        LocalFlowControl = new TlsQuicLocalFlowControlSpec
        {
            // 64 IS THE SUBJECT - a window small enough that one frame crosses the update
            // threshold. The other five are s18.2's zero by default now that SharpTls ships no
            // captured persona, and a zero connection-level limit refuses the frame before the
            // grant this test is about is ever owed.
            InitialMaxData = 1_000_000,
            InitialMaxStreamDataBidiLocal = 64,
            InitialMaxStreamDataBidiRemote = 100_000,
            InitialMaxStreamDataUni = 100_000,
            InitialMaxStreamsBidi = 100,
            InitialMaxStreamsUni = 100,
        },

        // ...and the slots that advertise them, because enforcement reads the advertisement.
        TransportParameters = TestQuicSpecValues.HarnessParameters,
    };

    // One RFC 9000 s19.8 STREAM frame as the PEER would send it. LoopbackQuicPeer builds no
    // stream state of its own, so the four fields are supplied here.
    private static TlsQuicFrame PeerStreamFrame(ulong streamId, ulong offset, byte[] data) =>
        new()
        {
            RawType = (ulong)TlsQuicFrameType.Stream
                | TlsQuicStreamFrames.LengthBit
                | (offset == 0 ? 0 : TlsQuicStreamFrames.OffsetBit),
            StreamId = streamId,
            Offset = offset,
            Data = data,
        };

    // A stream set built the way TlsQuicStreamsTests builds one, with a receive window small
    // enough that one frame crosses the update threshold. Six lines rather than a shared test
    // utility nobody owns; the peer limits are generous because nothing here is about them.
    private static TlsQuicStreamSet RepairSet() =>
        new(TlsQuicPeerFlowControlBudget.FromPeerParameters(new TlsQuicTransportParameters(
        [
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxData, 1 << 20),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal, 1 << 16),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote, 1 << 16),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamDataUni, 1 << 16),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamsBidi, 8),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamsUni, 8),
        ])),
        new TlsQuicLocalFlowControlSpec
        {
            InitialMaxData = 4096,
            InitialMaxStreamDataBidiLocal = 256,
            InitialMaxStreamDataBidiRemote = 256,
            InitialMaxStreamDataUni = 256,
        });

    // Delivers enough bytes to cross this stream's update threshold once, and returns the limit
    // the crossing granted. The value is READ OFF THE QUEUED FRAME rather than computed, which
    // keeps this helper out of the business of restating TlsQuicLocalFlowControlSpec's
    // arithmetic - and makes it the stream set's own answer rather than the test's.
    private static ulong DriveOneGrant(TlsQuicStreamSet streams, TlsQuicStream stream)
    {
        var at = (ulong)stream.Received.Count;
        var window = checked((int)(stream.ReceiveLimit - at));
        Assert.True(window > 0);

        Assert.True(
            streams.TryReceive(
                new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.Stream
                        | TlsQuicStreamFrames.LengthBit
                        | (at == 0 ? 0 : TlsQuicStreamFrames.OffsetBit),
                    StreamId = stream.Id,
                    Offset = at,
                    Data = new byte[window],
                },
                out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);

        var queued = streams.TakePendingFrames();
        return queued.First(static f => f.Type == TlsQuicFrameType.MaxStreamData)
            .MaximumStreamData;
    }

    // The connection-scope grant the same crossing produced, if it produced one. A crossing
    // credits both scopes, so this reads the MAX_DATA frame beside the MAX_STREAM_DATA one.
    private static ulong LastConnectionGrant(TlsQuicStreamSet streams, TlsQuicStream stream)
    {
        // One more crossing, so that a MAX_DATA frame is in the queue to read the value off.
        DriveOneGrant(streams, stream);
        Assert.True(
            streams.TryRefreshGrant(
                new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.MaxData }, out var current));
        return current.MaximumData;
    }

    // A controller that answers one question and records what it was asked, so that "the gate
    // was consulted" and "the gate was consulted about the right number" are separate claims.
    // Every other member is a no-op: this is a gate, not a second NewReno.
    private sealed class ScriptedSendGate : ITlsQuicCongestionController
    {
        private readonly List<int> _asked = [];

        internal bool Open { get; set; }

        internal IReadOnlyList<int> Asked => _asked;

        // WHICH SEAM MEMBERS WERE CALLED, IN ORDER. B.8 puts OnPacketsLost before any collapse,
        // and "both were called" is a weaker claim than "these two, in this order" - a wiring
        // that collapsed first satisfies the former.
        internal IReadOnlyList<string> Calls => _calls;

        private readonly List<string> _calls = [];

        public string Name => "scripted-send-gate";

        public long CongestionWindowBytes => 0;

        public long BytesInFlight => 0;

        public bool CanSend(int bytes)
        {
            _asked.Add(bytes);
            return Open;
        }

        public void OnPacketSent(in TlsQuicSentPacket sent)
        {
        }

        public void OnPacketsAcked(IReadOnlyList<TlsQuicSentPacket>? ackedPackets)
        {
        }

        public void OnPacketsLost(IReadOnlyList<TlsQuicSentPacket>? lostPackets)
        {
            _calls.Add(nameof(OnPacketsLost));
        }

        public void OnPersistentCongestion()
        {
            _calls.Add(nameof(OnPersistentCongestion));
        }

        public void OnPacketsDiscarded(IReadOnlyList<TlsQuicSentPacket>? discardedPackets)
        {
        }
    }

    // Where the reference captures live, relative to the repository root. Copied from
    // TlsQuicRecoverySpecTests, which says QuicCommentReferencesTests.RepositoryRoot is the
    // original; three copies of six lines is cheaper than a shared test utility nobody owns.
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
}


// THE MsQuic HALF LIVES IN ITS OWN CLASS BECAUSE OF ONE ATTRIBUTE, NOT BECAUSE IT IS A DIFFERENT
// SUBJECT. System.Net.Quic is platform-gated, and CA1416 is an ERROR in this tree - so every
// call site needs [SupportedOSPlatform], which cannot be put on TlsQuicConnectionTests without
// putting it on the eight other files that share that partial class. MsQuicLoopbackTests carries
// the same three attributes for the same reason.
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("osx")]
public sealed class TlsQuicRetransmissionMsQuicTests
{
// ============================================================================
// THE FOREIGN-CODE PROOF, AND THE CLAIM TASK A3-9 REPORTED IT COULD NOT MAKE.
// ============================================================================
//
// A3-9's done-when asked for "a transfer completes through the MsQuic listener under a scripted
// loss pattern" and A3-9 recorded that it was NOT REACHABLE, because nothing retransmitted: its
// own test could assert only that the exchange continued. This task is what that was waiting
// for, and this is the assertion it could not write.
//
// WHY THE FOREIGN PEER IS WORTH A SEPARATE TEST AT ALL. LoopbackQuicPeer and TlsQuicConnection
// share this repository's reading of RFC 9000, so a loopback run cannot distinguish "the repair
// is correct" from "both ends make the same mistake". MsQuic shares none of it: it decides for
// itself whether the retransmitted CRYPTO frame is at the offset it was waiting for, and it
// refuses the handshake if it is not.
//
// AND THE PROBE HERE IS THE SHIPPED DEFAULT, WHICH TASK A3-14 MOVED.
// MsQuicLoopbackServer.ConnectAsync builds `new TlsQuicConnectionSpec { PaddingTarget = 1200 }`
// and sets no recovery knobs, so knob 11 is whatever ships - Ping until A3-14, and
// TlsQuicProbeContents.RetransmittedData since.
//
// THAT ADDS A ROUTE TO COMPLETION HERE RATHER THAN REPLACING ONE, and the older route is still
// the one that matters most, so it is recorded rather than deleted: the probe elicits an
// acknowledgement, the acknowledgement is what lets RFC 9002 A.10 run at all - s6.1's first
// condition is "was sent prior to an acknowledged packet" - A.10 declares the dropped packet
// lost, and s13.3's repair goes out on the pump's ordinary send pass. Since A3-14 the probe
// ALSO carries the repair itself. This test asserts completion against foreign code and does
// not name which of the two arrived first, so it is sound either way; the loopback pair
// AHandshakeCompletesThroughADroppedHandshakeFlightWhenTheProbeCarriesData and
// APingOnlyProbeCarriesNoRepairAndLeavesTheServerWaiting are where the two are told apart, and
// both of those now set knob 11 by name instead of inheriting it.
[MsQuicLoopbackFact]
public async Task OurClientCompletesAHandshakeAgainstMsQuicThroughADroppedHandshakeFlight()
{
    await using var server = await MsQuicLoopbackServer.StartAsync();

    using var timeout = new CancellationTokenSource(
        MsQuicLoopbackServer.HandshakeDeadline + TimeSpan.FromSeconds(10));
    await using var udp =
        TlsQuicUdpDatagramTransport.Create(server.EndPoint.AddressFamily);
    await using var impaired = new ImpairingDatagramTransport(udp);

    // ORDINAL 3, AND THE ORDINAL IS MEASURED AGAINST THIS PEER RATHER THAN CARRIED OVER FROM
    // THE LOOPBACK ONE. MsQuic splits its flight differently from LoopbackQuicPeer, so this
    // client's send sequence against it is four datagrams and not three:
    //
    //   #1  1200 bytes, first byte 0xc2  Initial, padded    - the ClientHello.
    //   #2  1200 bytes, first byte 0xc2  Initial, padded    - the Initial ACK, coalesced.
    //   #3    98 bytes, first byte 0xe9  Handshake          - the client's Finished.
    //   #4    35 bytes, first byte 0x4d  short header       - the 1-RTT ACK.
    //
    // Those four were READ OFF AN UNIMPAIRED RUN of this same fixture, not predicted; the first
    // draft of this test dropped ordinal 2 on the loopback peer's schedule and the handshake
    // completed in 220ms with nothing declared lost, because against MsQuic ordinal 2 is an
    // acknowledgement its own retransmission repairs. THE ASSERTIONS AT THE END ARE WHAT
    // CAUGHT THAT, and they are why they are there.
    //
    // A DROP HERE IS THE HARD CASE: nothing in the Handshake space has been acknowledged when
    // it happens, so A.10 cannot declare anything lost until a probe earns an acknowledgement
    // first.
    impaired.Drop(3);

    // A FAILURE HERE IS A FINDING ABOUT OUR CLIENT, NOT A REASON TO LOOSEN THE TEST. Before
    // this task the same script ended in a TimeoutException at the handshake deadline, because
    // the client had no way to send the Finished a second time.
    await using var connection = await server.ConnectAsync(impaired, timeout.Token);
    await using var accepted = await server.AcceptAsync(timeout.Token);

    Assert.Equal([3], impaired.Dropped);
    Assert.True(connection.IsHandshakeComplete, "TLS did not finish through the induced loss.");

    // Confirmed, not merely complete: RFC 9001 s4.1.2 confirms a client's handshake on a
    // received HANDSHAKE_DONE, and only a real peer sends one unprompted.
    Assert.True(
        connection.IsHandshakeConfirmed,
        "No HANDSHAKE_DONE arrived, so MsQuic did not consider the handshake finished.");

    // The server's view, which is the half this side cannot fake.
    Assert.Equal(new SslApplicationProtocol("h3"), accepted.NegotiatedApplicationProtocol);

    // AND IT COMPLETED BY REPAIRING RATHER THAN BY LUCK. Both counters have to move, and TASK
    // A3-14 CHANGED WHICH TWO. This asserted PacketsDeclaredLost > 0 while knob 11 shipped as
    // Ping: the probe could then carry no repair, so the ONLY route to completion ran through
    // an acknowledgement earned by the probe and A.10 declaring the drop lost, and a zero there
    // meant the run had proved nothing. Since A3-14 the default is RetransmittedData, the probe
    // carries the Finished itself, MsQuic completes on the probe, and no acknowledgement ever
    // arrives that A.10 could declare a loss from - so PacketsDeclaredLost is legitimately
    // ZERO here and asserting otherwise pins a route rather than a repair.
    //
    // THE ANTI-VACUITY GUARANTEE IS NOT WEAKENED BY DROPPING IT, because the job it was really
    // doing is done twice over already: `Assert.Equal([3], impaired.Dropped)` above is the
    // direct witness that the drop did not silently fail - which is what the original comment
    // wanted PacketsDeclaredLost for - and ProbeDatagramsSent below is the witness for the
    // route that now carries the repair. A run in which MsQuic tolerated the gap some other way
    // still leaves FramesRetransmitted at zero and still fails.
    Assert.True(
        connection.ProbeDatagramsSent > 0,
        "No probe was sent, so the PTO never fired and this run proves nothing about recovery.");
    Assert.True(
        connection.FramesRetransmitted > 0,
        "Nothing was retransmitted, so this run proves something other than what it claims.");
}

}
