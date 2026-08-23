using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// RFC 9000 s12.4 Table 3's Pkts column, transcribed a second time and compared
// against TlsQuicFrameLegality's copy.
//
// WHY A SECOND TRANSCRIPTION AND NOT A LOOP OVER THE FIRST. This task has no wire
// format, no test vector and no round trip. Every other file in A2 can be checked
// against bytes; nothing here can. A test that read its expectations out of
// TlsQuicFrameLegality.Pkts would assert the table equals itself - it would pass
// against a single mistyped character, against a table permitting everything, and
// against a systematically inverted one. That is the same failure as a round trip
// proving an encoder and a decoder agree while both are wrong, one level up.
//
// So the only real check available is two readings of the RFC compared with each
// other, and the two readings have to be able to disagree.
//
// HOW THEY ARE KEPT INDEPENDENT, concretely, rather than asserted to be. The
// source reads Table 3 ALONG ITS ROWS: for each frame type it copies that row's
// four-character Pkts cell as printed - "IH_1", "__01". This file reads the same
// table DOWN ITS COLUMNS: for each of the four packet types it lists the frame
// types whose cell has a letter in that column position, which means walking the
// table vertically and looking at one character of each of the twenty rows.
//
// The two orientations fail differently, which is the whole point:
//
//   * A row-wise slip - copying CRYPTO's "IH_1" as "IH01" - is a single-character
//     typo in one string. Reproducing it here would take a separate, unrelated
//     decision to put CRYPTO into the 0-RTT list while walking that column. There
//     is no shared step between the two that a mistake can pass through.
//   * A systematic inversion of the source table cannot be matched at all: these
//     lists name only what IS permitted, so an inverted table disagrees with the
//     first row it reaches.
//   * An all-permissive table disagrees with every underscore cell; an all-empty
//     one disagrees with every letter cell. Both orientations have to be wrong in
//     the same direction, and a list of names cannot be "all true".
//
// Neither reading was produced from the other, and neither was produced from
// memory: both come from the Table 3 block in
// docs/superpowers/specs/reference-captures/rfc9000-section12-packets-and-frames.txt.
// A reviewer checking this should re-derive the table from that extract directly
// rather than compare the two copies here to each other - two copies agreeing is
// evidence only if they were read differently, and this comment is the claim about
// that which the reviewer is being asked to check.
//
// THE ASYMMETRIC ROWS ARE WHERE A WRONG CELL WOULD HIDE. Counted off the table:
// twelve rows are `__01`, three are `___1`, two are `IH01`, two are `IH_1` and one
// is `ih01`. So more than half the table is a single repeated string, and a
// transcription that got only those twelve right would still look plausible at a
// glance. The rows that discriminate are
// ACK and CRYPTO (`IH_1`, permitted in Initial and Handshake but not 0-RTT),
// NEW_TOKEN, PATH_RESPONSE and HANDSHAKE_DONE (`___1`, 1-RTT only), and
// CONNECTION_CLOSE (`ih01`, whose Initial and Handshake cells depend on the frame's
// raw type value). Those six carry their own named tests below in addition to
// their rows in the cross product.
//
// THE CROSS PRODUCT IS NO LONGER EIGHTY CELLS. Task C17 added RFC 9221's DATAGRAM
// to TlsQuicFrameType, and the theory's frame axis is the enum, so it is 21 x 4 =
// 84: Table 3's eighty plus that one row's four. The DATAGRAM row is not a
// transcription of anything - RFC 9221 prints no Pkts cell - and its own second
// reading is set out where its arrays are declared, below.
//
// One structural fact worth writing down because it weakens a test that looks
// strong: no row of Table 3 distinguishes Initial from Handshake. Every cell has the
// same character class in positions 0 and 1. So the Initial and Handshake lists
// below are deliberately identical, and swapping those two columns is a no-op for
// all eighty cells.
//
// (The noun "class" in the sentence above is load-bearing in a second way, and this
// is the only place it can do that job: it sits ABOVE this file's class declaration,
// which is where QuicCommentReferencesTests' regex used to go wrong. That checker
// takes the first class-declaration match in a file, and before the regex was
// anchored, this sentence hijacked it - the tests here registered under the class
// name "of" or "in" and every citation of them was reported as naming a test that
// does not exist. The same sentence below the declaration would prove nothing,
// because the real declaration is matched first. Removing the word from here is what
// silently un-pins that fix, so it is cited from that file's mutation record.)
//
// That mutation was performed and it SURVIVED - the only survivor of the sweep
// recorded in TlsQuicFrameLegality. It is unreachable by construction, not
// unwitnessed, and no test is written for it: any test claiming to pin the
// Initial/Handshake distinction would pass against the swapped code too and would be
// a false witness. What would end the argument is a future row - a QUIC version or
// an extension frame - whose Pkts cell has a letter in one of positions 0 and 1 and
// an underscore in the other. At that point the swap becomes reachable and needs a
// row.
//
// The Handshake/0-RTT confusion is a different matter. That is the one a cast from
// TlsQuicEncryptionLevel's ordinal would actually cause, since that enum declares
// its members in handshake order, and it IS reachable. Performed, and these are the
// failing test names as the run printed them:
//
//     2 TlsQuicFrameLegalityTests.ApplicationErrorConnectionCloseIsRejected
//       InInitialAndHandshakePackets
//    28 TlsQuicFrameLegalityTests.EveryTable3FrameTypeMatchesTheColumnwise
//       Transcription
//     1 TlsQuicFrameLegalityTests.RetireConnectionIdKeepsTable3sZeroRttCell
//       AgainstTheSection125Note
//
// The 28 are fourteen frame types - ACK, CRYPTO and the twelve `__01` rows - each in
// both Handshake and EarlyData. CONNECTION_CLOSE is NOT among them, which is worth
// stating because it is the row you would expect to break: for type 0x1c both
// positions 1 and 2 are permissive, so exchanging them changes nothing the theory
// can see. It is the 0x1d rows of the CONNECTION_CLOSE test that catch it instead,
// which is why that test appears above and why the pasted list is kept rather than
// a summary of it.
public sealed class TlsQuicFrameLegalityTests
{
    // ---- Second transcription: Table 3 read down its columns ----------------
    //
    // Table 3's Pkts cells have four character positions, I H 0 1. Each list below
    // is one of those positions, holding every frame type whose cell shows a letter
    // there rather than an underscore, in Table 3's own top-to-bottom row order so
    // the walk can be replayed against the extract.

    // Position 0, "I". Walking the twenty rows: PADDING IH01, PING IH01, ACK IH_1,
    // CRYPTO IH_1, CONNECTION_CLOSE ih01. Every other row shows `_` here.
    // CONNECTION_CLOSE's is the lowercase `i`, which the legend restricts to type
    // 0x1c; these rows use the base value 0x1c, and 0x1d has its own test.
    private static readonly TlsQuicFrameType[] PermittedInInitial =
    [
        TlsQuicFrameType.Padding,
        TlsQuicFrameType.Ping,
        TlsQuicFrameType.Ack,
        TlsQuicFrameType.Crypto,
        TlsQuicFrameType.ConnectionClose,
    ];

    // Position 1, "H". The same five rows: no Table 3 cell has a different character
    // class in position 1 than in position 0. Written out rather
    // than aliased to PermittedInInitial, because the aliasing would encode that
    // coincidence as a rule and would make a future row that broke it untestable.
    private static readonly TlsQuicFrameType[] PermittedInHandshake =
    [
        TlsQuicFrameType.Padding,
        TlsQuicFrameType.Ping,
        TlsQuicFrameType.Ack,
        TlsQuicFrameType.Crypto,
        TlsQuicFrameType.ConnectionClose,
    ];

    // Position 2, "0". Fifteen rows show `0` here. Listed rather than derived as
    // "all except five": a subtraction would be a step taken from the other
    // reading's shape instead of from the table.
    private static readonly TlsQuicFrameType[] PermittedInZeroRtt =
    [
        TlsQuicFrameType.Padding,
        TlsQuicFrameType.Ping,
        TlsQuicFrameType.ResetStream,
        TlsQuicFrameType.StopSending,
        TlsQuicFrameType.Stream,
        TlsQuicFrameType.MaxData,
        TlsQuicFrameType.MaxStreamData,
        TlsQuicFrameType.MaxStreams,
        TlsQuicFrameType.DataBlocked,
        TlsQuicFrameType.StreamDataBlocked,
        TlsQuicFrameType.StreamsBlocked,
        TlsQuicFrameType.NewConnectionId,
        TlsQuicFrameType.RetireConnectionId,
        TlsQuicFrameType.PathChallenge,
        TlsQuicFrameType.ConnectionClose,
    ];

    // Position 3, "1". Every one of the twenty rows shows `1`. s12.4 says so in
    // prose immediately after the legend, which is a third and independent reading
    // of this column: "Note that all frames can appear in 1-RTT packets."
    private static readonly TlsQuicFrameType[] PermittedInOneRtt =
    [
        TlsQuicFrameType.Padding,
        TlsQuicFrameType.Ping,
        TlsQuicFrameType.Ack,
        TlsQuicFrameType.ResetStream,
        TlsQuicFrameType.StopSending,
        TlsQuicFrameType.Crypto,
        TlsQuicFrameType.NewToken,
        TlsQuicFrameType.Stream,
        TlsQuicFrameType.MaxData,
        TlsQuicFrameType.MaxStreamData,
        TlsQuicFrameType.MaxStreams,
        TlsQuicFrameType.DataBlocked,
        TlsQuicFrameType.StreamDataBlocked,
        TlsQuicFrameType.StreamsBlocked,
        TlsQuicFrameType.NewConnectionId,
        TlsQuicFrameType.RetireConnectionId,
        TlsQuicFrameType.PathChallenge,
        TlsQuicFrameType.PathResponse,
        TlsQuicFrameType.ConnectionClose,
        TlsQuicFrameType.HandshakeDone,
    ];

    // ---- A second table, from a second document: RFC 9221's DATAGRAM row ----
    //
    // Task C17. RFC 9221 publishes no Pkts cell to transcribe - s7.2 registers only
    // "Value: 0x30-0x31, Frame Name: DATAGRAM" - so the independence this file gets
    // everywhere else from reading a table down its columns is not available here.
    // What replaces it is that the two readings are of DIFFERENT SENTENCES, and the
    // arrays are kept apart from Table 3's four so that neither reading can be
    // mistaken for the other:
    //
    //   * TlsQuicFrameLegality derives the row from the key restriction in RFC 9221
    //     s5: "Like STREAM frames, DATAGRAM frames contain application data and MUST
    //     be protected with either 0-RTT or 1-RTT keys."
    //   * This file derives the same four cells from s5.1's statement of what a
    //     DATAGRAM belongs to - "DATAGRAM frames belong to a QUIC connection as a
    //     whole" - taken together with s5's MUST read for its EXCLUSIONS rather than
    //     its permissions: the two key types it does not name are Initial and
    //     Handshake, and RFC 9001 s5.2 is what says an Initial packet is protected
    //     with Initial keys and a Handshake packet with Handshake keys.
    //
    // That is a weaker independence than the column walk and it is stated as weaker.
    // The one thing it does buy is the thing that matters most for a hand-argued
    // row: a table that permitted DATAGRAM in Initial or Handshake disagrees with
    // both readings, and a table that forbade it in 0-RTT or 1-RTT disagrees with
    // both, so no single-cell slip in the source can be matched here.
    //
    // Four arrays and not two, two of them empty. Aliasing the empty pair, or
    // dropping them and special-casing Datagram in Column below, would encode "no
    // extension frame is ever permitted in Initial or Handshake" as a rule of this
    // file rather than as a fact about this one row - which is the same mistake the
    // Table 3 comment above refuses to make when it writes PermittedInHandshake out
    // in full instead of aliasing PermittedInInitial.

    // Position 0, "I". RFC 9221 s5's MUST names 0-RTT and 1-RTT keys; Initial keys
    // are not among them, so no extension frame from RFC 9221 belongs here.
    private static readonly TlsQuicFrameType[] Rfc9221PermittedInInitial = [];

    // Position 1, "H". The same reading, for Handshake keys.
    private static readonly TlsQuicFrameType[] Rfc9221PermittedInHandshake = [];

    // Position 2, "0". RFC 9221 s5 names 0-RTT keys explicitly as one of the two a
    // DATAGRAM frame may be protected with.
    private static readonly TlsQuicFrameType[] Rfc9221PermittedInZeroRtt =
    [
        TlsQuicFrameType.Datagram,
    ];

    // Position 3, "1". RFC 9221 s5 names 1-RTT keys explicitly as the other.
    private static readonly TlsQuicFrameType[] Rfc9221PermittedInOneRtt =
    [
        TlsQuicFrameType.Datagram,
    ];

    private static TlsQuicFrameType[] Rfc9221Column(TlsQuicEncryptionLevel packetType) => packetType switch
    {
        TlsQuicEncryptionLevel.Initial => Rfc9221PermittedInInitial,
        TlsQuicEncryptionLevel.Handshake => Rfc9221PermittedInHandshake,
        TlsQuicEncryptionLevel.EarlyData => Rfc9221PermittedInZeroRtt,
        TlsQuicEncryptionLevel.Application => Rfc9221PermittedInOneRtt,
        _ => throw new ArgumentOutOfRangeException(nameof(packetType)),
    };

    // TlsQuicFrameLegality.Permits takes the whole frame, so that a production caller
    // cannot reach for TlsQuicFrame.Type when only RawType answers the CONNECTION_CLOSE
    // row correctly. These tests drive the table by raw wire value - that is the axis
    // Table 3 is indexed on - so they wrap the construction here rather than repeating
    // it at every call. The wrapper is the only place in this file that builds a frame,
    // which is also what keeps the 0x1d and flag-bit rows honest: they differ from
    // their base values in RawType and nothing else.
    private static bool Permits(ulong rawFrameType, TlsQuicEncryptionLevel packetType) =>
        TlsQuicFrameLegality.Permits(new TlsQuicFrame { RawType = rawFrameType }, packetType);

    // Table 3's column joined to RFC 9221's, rather than one list holding both:
    // concatenating at the point of use keeps each document's reading in its own
    // array, so a reviewer checking the Table 3 walk against
    // rfc9000-section12-packets-and-frames.txt never has to subtract an extension
    // row out of it first.
    private static TlsQuicFrameType[] Column(TlsQuicEncryptionLevel packetType) =>
        [.. Table3Column(packetType), .. Rfc9221Column(packetType)];

    private static TlsQuicFrameType[] Table3Column(TlsQuicEncryptionLevel packetType) => packetType switch
    {
        TlsQuicEncryptionLevel.Initial => PermittedInInitial,
        TlsQuicEncryptionLevel.Handshake => PermittedInHandshake,
        TlsQuicEncryptionLevel.EarlyData => PermittedInZeroRtt,
        TlsQuicEncryptionLevel.Application => PermittedInOneRtt,
        _ => throw new ArgumentOutOfRangeException(nameof(packetType)),
    };

    // The four packet types Table 3 has a column for, named as encryption levels.
    // Retry is absent because s12.4 says Retry packets contain no frames.
    private static readonly TlsQuicEncryptionLevel[] PacketTypes =
    [
        TlsQuicEncryptionLevel.Initial,
        TlsQuicEncryptionLevel.Handshake,
        TlsQuicEncryptionLevel.EarlyData,
        TlsQuicEncryptionLevel.Application,
    ];

    // Every Table 3 row against every Table 3 column. The frame axis comes from the
    // enum rather than from a list here, so a frame type that exists and was left
    // out of this file's transcription is still asked about - it would simply be
    // absent from every column list, and any row of the source permitting it fails.
    //
    // The axis is widened to ulong on the way out because TlsQuicFrameType is
    // internal and a public xunit signature cannot name it; TlsQuicFramesTests
    // widens the same enum the same way. TlsQuicEncryptionLevel is public and is
    // passed as itself.
    public static TheoryData<ulong, TlsQuicEncryptionLevel> EveryCell()
    {
        TheoryData<ulong, TlsQuicEncryptionLevel> data = [];
        foreach (var frameType in Enum.GetValues<TlsQuicFrameType>())
        {
            foreach (var packetType in PacketTypes)
            {
                data.Add((ulong)frameType, packetType);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EveryCell))]
    public void EveryTable3FrameTypeMatchesTheColumnwiseTranscription(
        ulong rawFrameType, TlsQuicEncryptionLevel packetType)
    {
        var frameType = (TlsQuicFrameType)rawFrameType;
        var expected = Column(packetType).Contains(frameType);
        var actual = Permits(rawFrameType, packetType);

        // Assert.True with a message rather than Assert.Equal, so a failure names
        // the cell. A bare True/False mismatch across eighty rows identifies the
        // row only by two raw theory arguments, and the whole value of this test is
        // that it says which cell the two transcriptions disagree about.
        var source = frameType == TlsQuicFrameType.Datagram
            ? "RFC 9221 s5"
            : "RFC 9000 s12.4 Table 3";
        Assert.True(
            expected == actual,
            $"{source}: {frameType} in a {packetType} packet - this file's "
            + $"column-wise reading says {expected}, TlsQuicFrameLegality says {actual}.");
    }

    // The cross product above is only as wide as the two axes it is built from, and
    // both are read from something other than a literal count here: a frame type
    // deleted from the enum, or a column list that lost an entry to a bad merge,
    // would shrink the theory silently and every remaining row would still pass.
    //
    // The four sizes are the populations of Table 3's four columns, counted off the
    // extract by hand - five rows with a letter in position 0, five in position 1,
    // fifteen in position 2, twenty in position 3 - not by counting the arrays
    // above, which would make this assertion say nothing. Twenty is Table 3's row
    // count. None of these five numbers is a count of tests; they are all facts
    // about the RFC, and they go stale only if the RFC does.
    // The enum is no longer Table 3 alone: task C17 added RFC 9221's DATAGRAM, so
    // the twenty is asserted as a subtraction with both terms named rather than
    // being quietly bumped to twenty-one. Twenty-one members minus the one
    // extension row is Table 3's own count, and if a future extension arrives
    // without extending the right-hand side this line goes red - which is what it
    // is for.
    [Fact]
    public void Table3HasTwentyRowsAndItsFourColumnsHaveThePopulationsTranscribed()
    {
        TlsQuicFrameType[] notInTable3 = [TlsQuicFrameType.Datagram];
        Assert.Equal(21, Enum.GetValues<TlsQuicFrameType>().Length);
        Assert.Equal(20, Enum.GetValues<TlsQuicFrameType>().Length - notInTable3.Length);
        Assert.Equal(5, PermittedInInitial.Length);
        Assert.Equal(5, PermittedInHandshake.Length);
        Assert.Equal(15, PermittedInZeroRtt.Length);
        Assert.Equal(20, PermittedInOneRtt.Length);

        // RFC 9221's row, counted the same way: no Initial or Handshake cell, one
        // frame type in each of the other two.
        // Assert.Empty/Single rather than Assert.Equal on Length: xUnit2013 is an
        // error in this tree. The four Table 3 lengths above keep Assert.Equal
        // because none of their populations is 0 or 1.
        Assert.Empty(Rfc9221PermittedInInitial);
        Assert.Empty(Rfc9221PermittedInHandshake);
        Assert.Single(Rfc9221PermittedInZeroRtt);
        Assert.Single(Rfc9221PermittedInOneRtt);
    }

    // Task C17's row, asserted as a shape and not only cell by cell.
    //
    // The theory above already covers all four of its cells, so what this adds is
    // the PAIRING: DATAGRAM is permitted in exactly the two packet types RFC 9221
    // s5's MUST names and in neither of the two it does not. A test asserting only
    // the two permissions would pass against a table that permitted DATAGRAM
    // everywhere - which is the likelier wrong table, since "extension frames are
    // fine anywhere" is the guess someone makes when the RFC prints no Pkts cell to
    // copy.
    //
    // Driven by raw wire value, and by BOTH of them: 0x30 and 0x31 are one row (RFC
    // 9221 s7.2, "Value: 0x30-0x31") and the LEN bit must not reach the table. That
    // is the same property FlagBitsInARangedFrameTypeDoNotChangeItsRow asserts for
    // the four RFC 9000 ranges, asserted here against a literal expectation rather
    // than against the base value's own answer, so this test cannot be satisfied by
    // two equal wrong answers.
    [Theory]
    [InlineData(0x30UL, TlsQuicEncryptionLevel.Initial, false)]
    [InlineData(0x30UL, TlsQuicEncryptionLevel.Handshake, false)]
    [InlineData(0x30UL, TlsQuicEncryptionLevel.EarlyData, true)]
    [InlineData(0x30UL, TlsQuicEncryptionLevel.Application, true)]
    [InlineData(0x31UL, TlsQuicEncryptionLevel.Initial, false)]
    [InlineData(0x31UL, TlsQuicEncryptionLevel.Handshake, false)]
    [InlineData(0x31UL, TlsQuicEncryptionLevel.EarlyData, true)]
    [InlineData(0x31UL, TlsQuicEncryptionLevel.Application, true)]
    public void DatagramIsPermittedExactlyWhereRfc9221sKeyRestrictionAllowsIt(
        ulong rawFrameType, TlsQuicEncryptionLevel packetType, bool expected)
    {
        Assert.Equal(expected, Permits(rawFrameType, packetType));
    }

    // The `ih` legend entry, which is the one cell in Table 3 whose answer is not
    // decided by the frame's base type: "Only a CONNECTION_CLOSE frame of type 0x1c
    // can appear in Initial or Handshake packets."
    //
    // The theory above covers 0x1c, the base of the 0x1c-0x1d range, so this covers
    // 0x1d - and it covers it in all four packet types rather than only the two the
    // legend restricts, because the interesting claim is a pair: 0x1d differs from
    // 0x1c in Initial and Handshake and is identical to it in 0-RTT and 1-RTT. A
    // test asserting only the two rejections would pass against an implementation
    // that rejected 0x1d everywhere, which is a different and equally wrong table.
    //
    // s12.5's second bullet is the same rule stated in number-space terms:
    // "CONNECTION_CLOSE frames signaling errors at the QUIC layer (type 0x1c) MAY
    // appear in any packet number space. CONNECTION_CLOSE frames signaling
    // application errors (type 0x1d) MUST only appear in the application data
    // packet number space." The application data space is the one 0-RTT and 1-RTT
    // packets share, so the two sections agree here.
    [Theory]
    [InlineData(TlsQuicEncryptionLevel.Initial, false)]
    [InlineData(TlsQuicEncryptionLevel.Handshake, false)]
    [InlineData(TlsQuicEncryptionLevel.EarlyData, true)]
    [InlineData(TlsQuicEncryptionLevel.Application, true)]
    public void ApplicationErrorConnectionCloseIsRejectedInInitialAndHandshakePackets(
        TlsQuicEncryptionLevel packetType, bool expected)
    {
        Assert.Equal(expected, Permits(0x1d, packetType));
    }

    // The other four ranged types carry flags in the low bits and Table 3 gives each
    // range a single row, so every value in a range must answer identically. Each
    // row here is the high end of a range - the value with every flag bit set - and
    // is compared against its own range's base rather than against a literal
    // expectation, which is the one place in this file where comparing two answers
    // is the right assertion: the claim being tested is that they are equal, not
    // what they are.
    //
    // CONNECTION_CLOSE is deliberately absent. Its range is the exception to this
    // property and asserting it here would contradict the test above.
    [Theory]
    [InlineData(0x03UL, 0x02UL)]
    [InlineData(0x0fUL, 0x08UL)]
    [InlineData(0x13UL, 0x12UL)]
    [InlineData(0x17UL, 0x16UL)]

    // RFC 9221's range, which behaves the same way for the same reason - s7.2
    // registers "Value: 0x30-0x31" as one entry, so the LEN bit does not select a
    // row - even though the rule it obeys is not the s12.4 sentence the four rows
    // above obey. See DatagramIsPermittedExactlyWhereRfc9221sKeyRestrictionAllowsIt
    // for the same pair asserted against literal expectations instead.
    [InlineData(0x31UL, 0x30UL)]
    public void FlagBitsInARangedFrameTypeDoNotChangeItsRow(ulong withFlags, ulong baseValue)
    {
        foreach (var packetType in PacketTypes)
        {
            Assert.Equal(
                Permits(baseValue, packetType),
                Permits(withFlags, packetType));
        }
    }

    // Values Table 3 assigns to nothing. 0x1f is the first value past HANDSHAKE_DONE
    // and 0x40 is the first that needs a two-byte varint; both are outside every
    // range, so neither has a row.
    //
    // This is not the table claiming these are protocol violations - s12.4 gives an
    // unknown frame type FRAME_ENCODING_ERROR, a different code, and
    // TlsQuicFrames.TryReadFrame already rejects one with it. The assertion is only
    // that a missing row does not read as permission, which is what would happen if
    // the source's default arm returned a cell string instead of an empty one.
    // 0x2f and 0x32 were added by task C17 and are the two values immediately
    // outside RFC 9221's 0x30-0x31 range. They are the rows that would catch a
    // range written one value too wide in either direction - a defect 0x1f and 0x40
    // are both too far away to see, since a `>= 0x30 and <= 0x31` arm slipped to
    // `<= 0x32` still answers "no row" for them.
    [Theory]
    [InlineData(0x1fUL)]
    [InlineData(0x2fUL)]
    [InlineData(0x32UL)]
    [InlineData(0x40UL)]
    public void FrameTypeValuesTable3NeverAssignsArePermittedNowhere(ulong rawFrameType)
    {
        foreach (var packetType in PacketTypes)
        {
            Assert.False(Permits(rawFrameType, packetType));
        }
    }

    // RFC 9000 disagrees with itself about this one cell, and this test pins which
    // side the table takes so that a later reader who notices the disagreement
    // cannot quietly change it.
    //
    // s12.4 Table 3 row 0x19 gives RETIRE_CONNECTION_ID `__01`, permitting it in
    // 0-RTT packets. s12.5's closing paragraph says "it is not possible to send the
    // following frames in 0-RTT packets for various reasons: ACK, CRYPTO,
    // HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE, and RETIRE_CONNECTION_ID. A server
    // MAY treat receipt of these frames in 0-RTT packets as a connection error of
    // type PROTOCOL_VIOLATION." The first five of those six already show `_` in
    // Table 3's 0-RTT position; RETIRE_CONNECTION_ID is the sixth and does not, and
    // it is the only place in either section where the two disagree.
    //
    // The table follows s12.4 because encoding s12.4's table is what it is for, and
    // because the two possible errors are not symmetric: permitting what could have
    // been rejected forgoes an optional rejection, while rejecting permitted traffic
    // breaks conforming peers in the way that is hardest to diagnose from either
    // end. Note that answering false here would NOT violate s12.4 - its MUST is a
    // MUST-reject-the-impermissible, not a MUST-accept-the-permissible, so declining
    // the frame would be exercising s12.5's MAY. The argument is about which section
    // this file transcribes and which way it is safe to be wrong, not about strength
    // of obligation; see TlsQuicFrameLegality for the full form of it.
    //
    // The five rows that agree are asserted alongside it, so this test also fails if
    // someone applies the s12.5 note by flipping the whole list - which is the
    // likelier edit than flipping one cell.
    [Fact]
    public void RetireConnectionIdKeepsTable3sZeroRttCellAgainstTheSection125Note()
    {
        Assert.True(Permits(
            (ulong)TlsQuicFrameType.RetireConnectionId, TlsQuicEncryptionLevel.EarlyData));

        foreach (var frameType in new[]
        {
            TlsQuicFrameType.Ack,
            TlsQuicFrameType.Crypto,
            TlsQuicFrameType.HandshakeDone,
            TlsQuicFrameType.NewToken,
            TlsQuicFrameType.PathResponse,
        })
        {
            Assert.False(Permits(
                (ulong)frameType, TlsQuicEncryptionLevel.EarlyData));
        }
    }

    // TlsQuicEncryptionLevel has a member for each of Table 3's four columns and no
    // member for anything else, but a C# enum still holds any value of its
    // underlying type, so the out-of-range case is reachable from a cast.
    //
    // The 0x1f row - a value Table 3 never assigns - is the reason this is a theory
    // rather than a fact, and it is the only row that pins the ORDER of the two
    // lookups in Permits. Mutation check (performed and reverted): moving the Column
    // call below the Pkts lookup fails the 0x1f row and only it. 0x00 has a row, so
    // the reordered code still reaches `pkts[column]` and still throws; 0x1f has
    // none, so the reordered code returns a confident `false` for a caller who
    // passed a packet type that does not exist. That asymmetry is exactly why both
    // rows are here - the 0x00 row alone cannot see this defect.
    [Theory]
    [InlineData(0x00UL)]
    [InlineData(0x1fUL)]
    public void APacketTypeOutsideTable3sFourColumnsThrows(ulong rawFrameType)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Permits(rawFrameType, (TlsQuicEncryptionLevel)99));
    }
}
