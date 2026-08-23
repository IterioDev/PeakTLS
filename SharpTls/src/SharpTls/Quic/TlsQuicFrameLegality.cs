namespace SharpTls.Quic;

// RFC 9000 s12.4 Table 3, "Pkts" column: which of the four frame-carrying packet
// types each frame type may appear in - plus ONE ROW THAT IS NOT FROM TABLE 3,
// RFC 9221's DATAGRAM, added by task C17 and marked as such at its own arm. It
// is twenty-one rows and eighty-four cells; Table 3 itself is twenty and eighty,
// which is 84 minus the one four-cell DATAGRAM row.
//
// NOTHING HERE ENFORCES ANYTHING. s12.4 ends the paragraph describing this column
// with "An endpoint MUST treat receipt of a frame in a packet type that is not
// permitted as a connection error of type PROTOCOL_VIOLATION", and raising that
// error needs a connection, which this layer does not have - the same split every
// other A2 file makes between a property of the bytes and a property of the
// connection. No reader or writer in this namespace calls into this file. It is
// the data a later phase will consult.
//
// THE TABLE IS THE RFC's OWN NOTATION, NOT A TRANSLATION OF IT. Each row below is
// the four characters Table 3 prints in that row's Pkts cell, unmodified, so the
// whole table can be diffed against
// docs/superpowers/specs/reference-captures/rfc9000-section12-packets-and-frames.txt
// character by character rather than re-derived. Translating "IH_1" into a flags
// enum at authoring time would put a transcription step between the RFC and the
// source that no reviewer can check by looking.
//
// s12.4 gives the legend for those characters verbatim:
//
//   The "Pkts" column in Table 3 lists the types of packets that each frame
//   type could appear in, indicated by the following characters:
//
//   I:   Initial (Section 17.2.2)
//   H:   Handshake (Section 17.2.4)
//   0:   0-RTT (Section 17.2.3)
//   1:   1-RTT (Section 17.3.1)
//   ih:  Only a CONNECTION_CLOSE frame of type 0x1c can appear in Initial
//        or Handshake packets.
//
// So the four character positions are, in order, Initial / Handshake / 0-RTT /
// 1-RTT, an underscore is "not permitted", and lowercase is a restriction the
// legend spells out for exactly one row. The legend does NOT define a general
// "lowercase means restricted" rule, so Permits below does not invent one: it
// applies the sentence the legend actually writes, about CONNECTION_CLOSE and the
// value 0x1c. Pinned by
// TlsQuicFrameLegalityTests.ApplicationErrorConnectionCloseIsRejectedInInitialAnd
// HandshakePackets.
//
// The "Spec" column is NOT transcribed here and is out of scope. Its four markings
// are, per s12.4, about ack-eliciting packets (N), bytes in flight (C), path
// probing (P) and flow control (F) - properties of the packet a frame is bundled
// into and of connection state, not of which packet types the frame may appear in.
// s12.4 also notes that neither column "form[s] part of the IANA registry".
//
// TABLE 3 HAS NO COLUMN FOR RETRY, VERSION NEGOTIATION OR STATELESS RESET because,
// per s12.4's first paragraph, "Version Negotiation, Stateless Reset, and Retry
// packets do not contain frames." That is why TlsQuicLongPacketType - which has a
// Retry member and no 1-RTT member, since 1-RTT is a short header - is not the
// enum this file keys on; see Column.
//
// s12.5 AND WHAT IT ADDS. s12.5 restates these rules in terms of packet number
// spaces, and for nineteen of the twenty rows it says the same thing as Table 3 or
// something weaker: PADDING/PING/CRYPTO and ACK and CONNECTION_CLOSE 0x1c/0x1d get
// bullets that match their Pkts cells, and "All other frame types MUST only be
// sent in the application data packet number space" is exactly the `__01` and
// `___1` rows, the application data space being the one 0-RTT and 1-RTT packets
// share.
//
// The exception is RETIRE_CONNECTION_ID, and it is a real divergence rather than a
// restatement. Table 3 gives it `__01`, permitting it in 0-RTT. s12.5's closing
// paragraph says: "Note that it is not possible to send the following frames in
// 0-RTT packets for various reasons: ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN,
// PATH_RESPONSE, and RETIRE_CONNECTION_ID. A server MAY treat receipt of these
// frames in 0-RTT packets as a connection error of type PROTOCOL_VIOLATION." Five
// of those six already have `_` in Table 3's 0-RTT position. RETIRE_CONNECTION_ID
// is the sixth and does not.
//
// This table stays with Table 3 and keeps that cell permitted, deliberately - but
// NOT because folding in the s12.5 note would break a MUST. It would not, and an
// earlier version of this comment said so wrongly. s12.4's MUST is a
// MUST-reject-the-impermissible: "An endpoint MUST treat receipt of a frame in a
// packet type that is not permitted as a connection error of type
// PROTOCOL_VIOLATION." It obliges an endpoint to reject what the table forbids; it
// never obliges one to accept what the table permits. Rejecting
// RETIRE_CONNECTION_ID in 0-RTT would therefore be exercising s12.5's MAY, which is
// allowed, not violating s12.4.
//
// Two reasons that are actually load-bearing:
//
//   * The task this file exists to do is to encode s12.4's Table 3. A table that
//     silently folds in a rule from another section is no longer a transcription of
//     the thing it claims to transcribe, and the line-by-line check against the
//     extract - the only defence this file has, since it has no wire format and no
//     test vector - stops working.
//   * The two errors are not symmetric in the field. A table that permits something
//     it could have rejected costs an optional rejection this endpoint declines to
//     make. A table that rejects permitted traffic kills conforming connections,
//     and does it in the way that is worst to diagnose: the peer did nothing wrong,
//     the failure is ours, and nothing in the peer's logs explains it. The reverse
//     error is caught by the peer.
//
// So the s12.5 MAY belongs to whatever phase decides policy, alongside the rest of
// s12.4's PROTOCOL_VIOLATION handling; it is not a property of the table. Pinned,
// so that a later reader who finds the divergence cannot quietly "correct" it,
// by TlsQuicFrameLegalityTests.RetireConnectionIdKeepsTable3sZeroRttCellAgainstThe
// Section125Note.
internal static class TlsQuicFrameLegality
{
    // Table 3's twenty rows, in Table 3's order, each holding that row's Pkts cell
    // exactly as printed, and then RFC 9221's DATAGRAM row below them. The switch
    // is over the base type because Table 3's Type Value column is itself written
    // as ranges - "0x02-0x03", "0x08-0x0f" - so one row already covers every flag
    // combination of a ranged type; RFC 9221 s7.2 writes its own registration the
    // same way, "Value: 0x30-0x31", so the same collapse is right for it. See
    // Permits for how a raw wire value reaches its row.
    //
    // Mutation check (performed and reverted): every character of every row was
    // flipped between its letter and `_`, one at a time - every cell of the table,
    // individually; eighty when this sweep was run, and task C17's four DATAGRAM
    // cells swept the same way and recorded at that row - and all of them failed
    // TlsQuicFrameLegalityTests.EveryTable3FrameTypeMatchesTheColumnwiseTranscript
    // ion, naming the frame and packet type. None survived, so no cell here is
    // unpinned.
    //
    // Eight of the eighty flips fail a second test as well, and which eight was
    // measured rather than reasoned:
    //
    //   * the six 0-RTT cells - ACK, CRYPTO, NEW_TOKEN, RETIRE_CONNECTION_ID,
    //     PATH_RESPONSE, HANDSHAKE_DONE - also fail
    //     TlsQuicFrameLegalityTests.RetireConnectionIdKeepsTable3sZeroRttCellAgainst
    //     TheSection125Note.
    //   * the CONNECTION_CLOSE row's 0-RTT and 1-RTT cells, `ih01`->`ih_1` and
    //     `ih01`->`ih0_`, also fail
    //     TlsQuicFrameLegalityTests.ApplicationErrorConnectionCloseIsRejectedInIniti
    //     alAndHandshakePackets.
    //
    // NOT the two lowercase cells, which is the thing worth recording because it is
    // the opposite of the guess. `ih01`->`_h01` and `ih01`->`i_01` each fail the
    // transcription theory and nothing else: the CONNECTION_CLOSE test only asks
    // about type 0x1d, and 0x1d is already rejected in Initial and Handshake
    // whether the cell reads `i`/`h` or `_`, so blanking those cells is invisible
    // to it.
    //
    // Replacing the whole table with "IH01" everywhere, with "___1" everywhere, and
    // with each row's complement (an inverted table) failed it too. The theory's
    // expectations are transcribed down Table 3's columns rather than along its
    // rows, so no single mis-copy here can be matched by the same mis-copy there.
    private static string Pkts(TlsQuicFrameType type) => type switch
    {
        TlsQuicFrameType.Padding => "IH01",
        TlsQuicFrameType.Ping => "IH01",
        TlsQuicFrameType.Ack => "IH_1",
        TlsQuicFrameType.ResetStream => "__01",
        TlsQuicFrameType.StopSending => "__01",
        TlsQuicFrameType.Crypto => "IH_1",
        TlsQuicFrameType.NewToken => "___1",
        TlsQuicFrameType.Stream => "__01",
        TlsQuicFrameType.MaxData => "__01",
        TlsQuicFrameType.MaxStreamData => "__01",
        TlsQuicFrameType.MaxStreams => "__01",
        TlsQuicFrameType.DataBlocked => "__01",
        TlsQuicFrameType.StreamDataBlocked => "__01",
        TlsQuicFrameType.StreamsBlocked => "__01",
        TlsQuicFrameType.NewConnectionId => "__01",
        TlsQuicFrameType.RetireConnectionId => "__01",
        TlsQuicFrameType.PathChallenge => "__01",
        TlsQuicFrameType.PathResponse => "___1",
        TlsQuicFrameType.ConnectionClose => "ih01",
        TlsQuicFrameType.HandshakeDone => "___1",

        // ---- Not a Table 3 row: RFC 9221 s4's DATAGRAM ----------------------
        //
        // Task C17. The twenty rows above are transcribed from a table; this one
        // is DERIVED FROM A SENTENCE, because RFC 9221 publishes no Pkts cell -
        // its s7.2 IANA registration carries only "Value: 0x30-0x31, Frame Name:
        // DATAGRAM, Status: permanent, Specification: RFC 9221", and s12.4 says
        // of its own two columns that neither "form[s] part of the IANA
        // registry". So there is nothing to copy and the four characters have to
        // be argued for, one at a time.
        //
        // THE SENTENCE, RFC 9221 s5, third paragraph, quoted whole:
        //
        //   Like STREAM frames, DATAGRAM frames contain application data and
        //   MUST be protected with either 0-RTT or 1-RTT keys.
        //
        // Cell by cell, and each from that MUST rather than from a neighbouring
        // row:
        //
        //   position 0, Initial   -> `_`. An Initial packet is protected with
        //     Initial keys (RFC 9001 s5.2), which are neither of the two the
        //     MUST admits. "either A or B" is exhaustive, so a DATAGRAM in an
        //     Initial packet violates it and Table 3's `_` - "not permitted" -
        //     is what that maps to.
        //   position 1, Handshake -> `_`. Identically: Handshake packets carry
        //     Handshake keys, also neither.
        //   position 2, 0-RTT     -> `0`. Named by the MUST in as many words.
        //   position 3, 1-RTT     -> `1`. Named by the MUST in as many words,
        //     and agreeing with s12.4's own prose that "all frames can appear in
        //     1-RTT packets".
        //
        // WHY THE "LIKE STREAM FRAMES" CLAUSE IS NOT THE JUSTIFICATION, even
        // though STREAM's row is `__01` and so is this one. That clause is a
        // simile about carrying application data; borrowing STREAM's cell from
        // it would make this row a copy of a row rather than a reading of a
        // rule, and would be wrong on its own terms the moment an extension
        // frame carried application data under some other key restriction. The
        // agreement is a result here, not an input - and it is worth stating
        // that it IS an agreement, because a reviewer who spots `__01` twice
        // should be able to tell which way the derivation ran.
        //
        // NOTHING IN RFC 9221 s5.1 TO s5.4 NARROWS ANY OF THE FOUR. Read for
        // exactly that: s5.1 is about multiplexing at the application layer and
        // says DATAGRAM frames "are not associated with any stream ID at the
        // QUIC layer"; s5.2 makes them ack-eliciting; s5.3 removes them from
        // flow control; s5.4 puts them under the congestion controller. Those
        // are s12.4's *Spec* column's subject matter - N, C, P and F - which
        // this file states above it does not transcribe. None of them mentions a
        // packet type.
        //
        // Mutation check (performed and reverted): each of the four characters
        // flipped between its letter and `_`, one at a time, and all four fail
        // TlsQuicFrameLegalityTests.EveryTable3FrameTypeMatchesTheColumnwise
        // Transcription naming Datagram and the packet type. The two 0-RTT and
        // 1-RTT flips additionally fail
        // TlsQuicFrameLegalityTests.DatagramIsPermittedExactlyWhereRfc9221sKey
        // RestrictionAllowsIt.
        TlsQuicFrameType.Datagram => "__01",

        // A value Table 3 never assigns - 0x1f and up, or any of the gaps. Not a
        // row, so not a cell, and Permits reports it unpermitted everywhere. That
        // is not this file deciding the error: s12.4 gives an unknown frame type
        // its own and different code, "An endpoint MUST treat the receipt of a
        // frame of unknown type as a connection error of type
        // FRAME_ENCODING_ERROR", and TlsQuicFrames.TryReadFrame already rejects
        // such a type with exactly that code before any frame reaches this table.
        // The arm exists so that a caller holding a raw ulong from somewhere else
        // cannot read a missing row as permission.
        //
        // Mutation check (performed and reverted): returning "IH01" here instead
        // fails TlsQuicFrameLegalityTests.FrameTypeValuesTable3NeverAssignsArePermi
        // ttedNowhere.
        _ => string.Empty,
    };

    // Which character position of a Pkts cell a packet type is.
    //
    // TlsQuicEncryptionLevel is reused rather than a fifth packet-type enum being
    // added, because it is the only type in this namespace with one member for each
    // of Table 3's four columns and no member for anything else. Its own doc
    // comments already assert the mapping this method relies on - EarlyData is
    // "Replayable client 0-RTT packet protection", Application is "Authenticated
    // 1-RTT data" - and RFC 9001 s4.1.1 is where that correspondence comes from.
    // TlsQuicLongPacketType cannot serve: it carries Retry, which s12.4 says holds
    // no frames, and it has no member for 1-RTT, which is a short header.
    //
    // The mapping is written out rather than taken from the enum's ordinal on
    // purpose. TlsQuicEncryptionLevel declares its members in handshake order -
    // Initial, EarlyData, Handshake, Application - and Table 3 prints its columns
    // in I, H, 0, 1 order, so the two disagree in the middle two positions. A cast
    // to int would silently swap Handshake and 0-RTT, which is precisely the pair
    // of columns that differ for ACK and CRYPTO.
    //
    // Mutation check (performed and reverted): swapping the Handshake and EarlyData
    // arms - the cast-to-ordinal bug written out - fails thirty-one tests. Pasted
    // from the run rather than summarised, because summarising it is how an earlier
    // version of this record came to name a frame that does not in fact break:
    //
    //     2 TlsQuicFrameLegalityTests.ApplicationErrorConnectionCloseIsRejected
    //       InInitialAndHandshakePackets
    //    28 TlsQuicFrameLegalityTests.EveryTable3FrameTypeMatchesTheColumnwise
    //       Transcription
    //     1 TlsQuicFrameLegalityTests.RetireConnectionIdKeepsTable3sZeroRttCell
    //       AgainstTheSection125Note
    //
    // (Class prefixes added as this was pasted. The run prints bare method names,
    // and only the qualified form is enforceable, so pasting output verbatim
    // quietly grows the set of citations nothing can check.)
    //
    // The 28 cells are ACK, CRYPTO and the twelve `__01` rows, each in Handshake and
    // in EarlyData. CONNECTION_CLOSE contributes none of them: for type 0x1c its
    // positions 1 and 2 are both permissive, so exchanging the two columns is
    // invisible there. What catches it is
    // TlsQuicFrameLegalityTests.ApplicationErrorConnectionCloseIsRejectedInInitialAn
    // dHandshakePackets, which asks about 0x1d.
    //
    // Swapping the Initial and Handshake arms instead SURVIVES, and is the sweep's
    // only survivor. It is unreachable by construction rather than unwitnessed: no
    // row of Table 3 has a letter in one of positions 0 and 1 and an underscore in
    // the other, so the two columns are equal for all twenty rows and exchanging
    // them cannot change an answer. No test is written for it, deliberately - one
    // would pass against the swapped code and become a false witness. A future row
    // that distinguishes Initial from Handshake is what would make it reachable; the
    // argument is recorded at length in TlsQuicFrameLegalityTests' header.
    private static int Column(TlsQuicEncryptionLevel packetType) => packetType switch
    {
        TlsQuicEncryptionLevel.Initial => 0,
        TlsQuicEncryptionLevel.Handshake => 1,
        TlsQuicEncryptionLevel.EarlyData => 2,
        TlsQuicEncryptionLevel.Application => 3,
        _ => throw new ArgumentOutOfRangeException(
            nameof(packetType),
            packetType,
            "Not one of the four packet types RFC 9000 s12.4 Table 3 has a column for."),
    };

    /// <summary>
    /// Whether RFC 9000 s12.4 Table 3 permits <paramref name="frame"/> to appear in a
    /// packet of <paramref name="packetType"/>. False for a frame type Table 3 does
    /// not assign.
    /// </summary>
    /// <param name="frame">
    /// The whole frame, rather than either of its two type fields.
    ///
    /// THAT IS THE POINT OF THE SIGNATURE. The answer depends on
    /// <see cref="TlsQuicFrame.RawType"/> and not on <see cref="TlsQuicFrame.Type"/>,
    /// because one Table 3 row genuinely distinguishes two values of a single base
    /// type: the `ih` legend entry permits CONNECTION_CLOSE in Initial and Handshake
    /// packets only for type 0x1c, and 0x1c and 0x1d share a base type. An earlier
    /// version of this method took a bare <c>ulong</c>, which meant
    /// <c>Permits(frame.Type, ...)</c> compiled, was right for nineteen rows, and was
    /// silently wrong for 0x1d - a trap with no production caller yet to fall into
    /// it. Taking the frame makes the wrong field impossible to pass.
    ///
    /// Every other ranged type - ACK, STREAM, MAX_STREAMS, STREAMS_BLOCKED - has one
    /// row for its whole range, so a STREAM frame with FIN set gets the same answer
    /// as one without.
    /// </param>
    /// <param name="packetType">
    /// The packet the frame appeared in, as the RFC 9001 encryption level that
    /// names it: <see cref="TlsQuicEncryptionLevel.EarlyData"/> is a 0-RTT packet
    /// and <see cref="TlsQuicEncryptionLevel.Application"/> a 1-RTT one.
    /// </param>
    internal static bool Permits(in TlsQuicFrame frame, TlsQuicEncryptionLevel packetType)
    {
        // Column first, so an out-of-range packet type throws whatever the frame
        // type is - including for a type with no row, which would otherwise return
        // false before the argument was ever looked at and turn a caller's bug into
        // a plausible answer. Pinned by
        // TlsQuicFrameLegalityTests.APacketTypeOutsideTable3sFourColumnsThrows,
        // whose rows include a frame type that has no row here.
        var column = Column(packetType);

        // The range collapse is TlsQuicFrame.Type's, not a second copy of it. Those
        // five ranges are already written down once, with their own mutation record
        // and their own theory, and a private duplicate here could drift from them
        // while both stayed green. Pinned by
        // TlsQuicFrameLegalityTests.FlagBitsInARangedFrameTypeDoNotChangeItsRow.
        var pkts = Pkts(frame.Type);
        if (pkts.Length == 0)
        {
            return false;
        }

        return pkts[column] switch
        {
            '_' => false,

            // The legend's `ih` entry, applied as the sentence it is: "Only a
            // CONNECTION_CLOSE frame of type 0x1c can appear in Initial or
            // Handshake packets." Reached only from the CONNECTION_CLOSE row, the
            // only row printing a lowercase character, and only at columns 0 and 1.
            // TlsQuicFrameType.ConnectionClose is 0x1c - the QUIC-layer variant is
            // the low end of the 0x1c-0x1d range, so the comparison is to the
            // named base value rather than to a bare literal.
            'i' or 'h' => frame.RawType == (ulong)TlsQuicFrameType.ConnectionClose,

            _ => true,
        };
    }
}
