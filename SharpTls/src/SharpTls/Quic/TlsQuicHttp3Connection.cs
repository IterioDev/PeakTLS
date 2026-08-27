using System.Runtime.InteropServices;

namespace SharpTls.Quic;

/// <summary>Why <see cref="TlsQuicHttp3Connection.TryOpenRequest"/> would not open a request
/// stream.</summary>
/// <remarks>
/// <para>ONE MEMBER PER CAUSE, AND NOT A BOOL, for the reason
/// TlsQuicHttp3StreamsTests' header gives about s8.1 codes: five different conditions refuse a
/// request here and "it failed" would let any two be exchanged. Four of the five are the
/// PEER's doing - its stream allowance, its per-stream credit, its
/// SETTINGS_MAX_FIELD_SECTION_SIZE and its GOAWAY - so none of them may be an exception; the
/// fifth is our own malformed request and it is reported through
/// <see cref="TlsQuicHttp3RequestError"/> instead, which already enumerates s4.2 and s4.3.1's
/// rules.</para>
/// </remarks>
internal enum TlsQuicHttp3RequestRefusal
{
    /// <summary>No refusal.</summary>
    None = 0,

    /// <summary>The request is malformed; see the accompanying
    /// <see cref="TlsQuicHttp3RequestError"/>.</summary>
    Malformed,

    /// <summary>RFC 9114 s5.2: "Endpoints MUST NOT initiate new requests or promise new pushes
    /// on the connection after receipt of a GOAWAY frame from the peer."</summary>
    GoawayReceived,

    /// <summary>The peer's <c>initial_max_streams_bidi</c> (0x08) allowance is spent, so
    /// RFC 9000 s4.6 permits no further client-initiated bidirectional stream.</summary>
    /// <remarks>Checked rather than caught: <see cref="TlsQuicStreamSet.OpenBidirectional"/>
    /// throws on an exhausted budget, and a peer that advertised zero must not be able to
    /// raise an exception out of this path.</remarks>
    PeerBidirectionalStreamsExhausted,

    /// <summary>The peer advertised <c>initial_max_stream_data_bidi_remote</c> (0x06) of ZERO,
    /// so a request stream opened to it could not carry its first byte.</summary>
    /// <remarks>
    /// <para>NO LONGER A SIZE COMPARISON, AND THE HANDOVER THIS PARAGRAPH USED TO NAME HAS
    /// HAPPENED. It said the refusal stood "until the send path grows a MAX_STREAM_DATA
    /// handler"; it has one. TlsQuicConnection's dispatch feeds s19.9 and s19.10 to
    /// TlsQuicStreamSet.ReceiveFlowControlFrame, TlsQuicStreamBudget.TryRaiseLimit moves
    /// <c>Remaining</c>, and <see cref="TlsQuicStreamSet.Send"/> splits an over-credit write at
    /// <c>Available</c> and holds the tail. s19.10 binds the sender to "the LARGEST maximum
    /// stream data value advertised", and the advertised initial is only the first of those, so
    /// a message past it is PACED now and no longer refused.</para>
    /// <para>ZERO IS WHAT REMAINS, AND IT IS A DIFFERENT CLAIM FROM "TOO SMALL". A peer that
    /// grants late must not be refused; a peer whose own transport parameters say no byte may be
    /// written to a bidirectional stream is refused before
    /// <see cref="TlsQuicStreamSet.OpenBidirectional"/> spends an ordinal - and an ordinal comes
    /// out of <c>initial_max_streams_bidi</c>, which nothing in this tree raises, there being no
    /// MAX_STREAMS arm in that same dispatch. Note that RFC 9000 s19.9 is SILENT on ignoring a
    /// smaller limit; the explicit MUST-ignore belongs to s19.11 and MAX_STREAMS, so no symmetry
    /// between the two is assumed here.</para>
    /// </remarks>
    PeerStreamCreditTooSmall,

    /// <summary>The peer's connection-level <c>initial_max_data</c> (0x04) pool, already reduced
    /// by s6.2's opening flight and by every earlier request, has NOTHING left.</summary>
    /// <remarks>
    /// <para>A SECOND MEMBER AND NOT A REUSE OF <see cref="PeerStreamCreditTooSmall"/>, because
    /// they are two different limits with two different frames that lift them - s19.10's
    /// MAX_STREAM_DATA and s19.9's MAX_DATA - and a caller told only "no credit" could not tell
    /// which one it is waiting on.</para>
    /// <para>AND IT IS A REMAINING RATHER THAN AN INITIAL, WHICH IS NOW THE ONLY WAY IT IS
    /// REACHED. The per-stream arm reads the advertised initial because a freshly opened stream
    /// has spent none of it; this pool is shared, so
    /// <see cref="TlsQuicHttp3Connection.OpenLocalStreams"/> and every earlier request draw it
    /// down - and a request PACED against it draws it to exactly zero, because
    /// <see cref="TlsQuicStreamSet.Send"/> consumes precisely
    /// <c>Math.Min(stream, connection)</c>. Reading <c>InitialMaxData</c> here would miss every
    /// one of those.</para>
    /// <para>ZERO RATHER THAN TOO SMALL, for the reason given under
    /// <see cref="PeerStreamCreditTooSmall"/>: a shortfall is paced and signalled with s19.12's
    /// DATA_BLOCKED, an empty pool cannot move one byte and so cannot justify an
    /// ordinal.</para>
    /// </remarks>
    PeerConnectionCreditTooSmall,

    /// <summary>The field section exceeds the peer's advertised
    /// <c>SETTINGS_MAX_FIELD_SECTION_SIZE</c>.</summary>
    /// <remarks>RFC 9114 s4.2.2: "An implementation that has received this parameter SHOULD
    /// NOT send an HTTP message header that exceeds the indicated size, as the peer will
    /// likely refuse to process it."</remarks>
    FieldSectionTooLargeForPeer,

    /// <summary>The connection has already taken an s8.1 connection error, so there is no
    /// state in which a new request could be answered.</summary>
    ConnectionErrored,
}

// Task C11: the HTTP/3 connection - C1-C10 wired into one object, replacing the throwaway
// Http3GetSpike.
//
// ============================================================================
// WHERE THE ALPN TOKEN COMES FROM, STATED RATHER THAN ASSUMED.
// ============================================================================
//
//   RFC 9114 s3.2: "During connection establishment, HTTP/3 support is indicated by selecting
//   the ALPN token \"h3\" in the TLS handshake." NOTHING IN THIS FILE CAN SUPPLY IT and
//   nothing in this file checks for it, because the token lives in the ClientHelloProfile
//   handed to CustomTlsQuicClient, one layer below - by the time a TlsQuicConnection reaches
//   this constructor the handshake is over and the choice was made.
//
//   CORRECTED BY TASK B8. This block used to say that no profile under src/ offered h3 and to
//   quote a grep as the evidence. Both halves have since failed. The claim is now FALSE:
//   TlsQuicClientHelloProfileFactory, in src/SharpTls/ClientHello/, offers RFC 9114 s3.2's
//   token by default and composes extension 57's body afresh for every connection - which is
//   why it is a factory and not a profile, A4's Finding 1 having required a FRESH PROFILE PER
//   CONNECTION. And the evidence was never evidence: the grep matched this very comment, so
//   the sentence was a witness of itself. Cite a grep; do not paste its answer into the tree
//   it searches.
//
//   WHAT SURVIVES INTACT IS THE PART THIS FILE DEPENDS ON: nothing here supplies the token and
//   nothing here checks for it. The factory's profile reaches CustomTlsQuicClient through
//   TlsQuicConnection's client factory, one layer below.
//
//   SO THIS TASK'S DONE-WHEN DOES NOT ASSUME A PROFILE SUPPLIES IT. Every test in
//   TlsQuicHttp3ConnectionTests names its own ALPN, and the one that runs against MsQuic
//   asserts the SERVER's negotiated protocol - the only half we cannot fake. If a future
//   profile silently dropped h3, MsQuic would fail the handshake outright, which is the check
//   this file is entitled to lean on and is not entitled to perform.
//
// ============================================================================
// THE APPLICATION CONNECTION_CLOSE: BOTH HALVES ARE CLOSED NOW.
// ============================================================================
//
//   s8.1's codes are what "a QUIC application CONNECTION_CLOSE" carries, and that frame is
//   RFC 9000 s19.19's type 0x1d. TlsQuicConnectionFrames CAN encode one - it has
//   ApplicationErrorBit and a writer for the 0x1d layout.
//
//   THIS BLOCK HAS BEEN WRONG TWICE AND BOTH VERSIONS ARE RECORDED, because each was restated
//   from the previous one rather than re-measured. C11 wrote that no packet in this tree could
//   carry a 0x1d, quoting BuildCloseDatagram's "Application is absent because no short header
//   can be built"; the quoted line was itself stale, since A4 task 14b taught
//   TlsQuicPacketBuilder to build a short header - a null TlsQuicPacketPlan.Type is what it
//   reads as one - and 14c gave this connection ShortHeaderPlan and the 1-RTT packet that
//   carries its ACKs, PATH_RESPONSEs and STREAM frames. A4 then fixed the close path's level
//   walk to take the branch RFC 9000 s10.2.3 asks for - 1-RTT after confirmation, because
//   "After the handshake is confirmed ... an endpoint MUST send any CONNECTION_CLOSE frames in
//   a 1-RTT packet" - and rewrote this block to say the frame existed but that THIS class did
//   not yet ask for it. That second version is the one that is now false.
//
//   CloseAsync CALLS TlsQuicConnection.CloseWithApplicationErrorAsync, so the s8.1 code rides
//   s19.19's Error Code field UNTRANSLATED: "A CONNECTION_CLOSE frame of type 0x1d uses codes
//   defined by the application protocol; see Section 20.2." The application protocol here is
//   the one ALPN selected, and s8.1's codes are "defined for use when abruptly terminating
//   streams, aborting reading of streams, or immediately closing HTTP/3 connections" - so they
//   ARE that space, and no mapping onto s20.1 happens for anything to be lost in. RFC 9000
//   s20.2 itself is NOT among the captures under docs/superpowers/specs/reference-captures, so
//   nothing above is quoted from it; s19.19's sentence and s8.1's are, and they are enough.
//
//   WHAT THAT REPLACED, AND WHY IT WAS WORTH REPLACING. CloseAsync used to map every s8.1 code
//   onto TlsQuicTransportError.ApplicationError (RFC 9000 s20.1: "The application or
//   application protocol caused the connection to be closed") and put the s8.1 code in the
//   Reason Phrase. s19.19 permits that close - "an endpoint can send a CONNECTION_CLOSE frame
//   (type 0x1c) with an error code of APPLICATION_ERROR" - so it was lossy rather than
//   illegal, and the loss was real: H3_MISSING_SETTINGS (0x010a) read as an s20.1 code falls
//   inside CRYPTO_ERROR's 0x0100-0x01ff range, so a peer had no way to recover it from the
//   frame and had to parse prose instead.
//
//   THE REASON PHRASE IS STILL SENT AND IS NOW ONLY DIAGNOSTIC, which is what s19.19 calls it:
//   "Additional diagnostic information for the closure. This can be zero length if the sender
//   chooses not to give details beyond the Error Code value."
//
//   <see cref="ApplicationCloseErrorCode"/> IS NO LONGER THE WITNESS, and it is kept for the
//   question it does answer - which code this class ASKED to close with. That is not the same
//   question as what left: s10.2.3 converts a 0x1d built for a level that cannot carry it and
//   drops the code, and a connection already draining sends nothing at all.
//   TlsQuicConnection.ClosedWithApplicationErrorCode is taken from the frame that was actually
//   built, and the DATAGRAM is what the two tests below read - a LoopbackQuicPeer opens the
//   1-RTT packet and reports s19.19's raw Type and Error Code. Both are in the HTTP/3
//   connection test file, on the partial class it shares with the rest of the QUIC connection
//   tests:
//   TlsQuicConnectionTests.APeerControlStreamWhoseFirstFrameIsNotSettingsClosesWithMissing
//   Settings, which C11 pinned as ClosedWith == null when no close left this connection at
//   all, and .AGracefulCloseUsesH3NoError.
//
// ============================================================================
// BOTH HALVES OF SETTINGS_MAX_FIELD_SECTION_SIZE LAND HERE.
// ============================================================================
//
//   s4.2.2 has a send side and a receive side and C9 and C10 each left one open, for the same
//   structural reason: neither TlsQuicHttp3Request nor TlsQuicHttp3Response holds a reference
//   to the other endpoint's SETTINGS. This class holds both.
//
//   RECEIVE: <see cref="MaximumFieldSectionSizeAdvertised"/> is read off OUR spec's SETTINGS
//   and handed to every TlsQuicHttp3Response's constructor argument, which C10 left defaulting
//   to no limit.
//
//   SEND: the encoded field section is DECODED BACK and measured against the peer's advertised
//   value. It is done that way rather than by summing name and value lengths here because
//   s4.2.2's arithmetic - "the length of the name and value in bytes plus an overhead of 32
//   bytes for each field" - is already implemented once, in TlsQuicQpackDecoder, and a second
//   implementation of it in this file would be a second transcription with no independent
//   source. The decode also costs nothing worth counting: a request field section is a few
//   dozen bytes.
// ============================================================================
// THE MUTATION LEDGER - TASK C11 (this file)
// ============================================================================
//
//   ROWS BELOW                   36  = C11-1 to C11-36 with no gaps
//   KILLED WHEN FIRST RUN        27  = 36 rows, less 5 [WAS-SURVIVOR], 2 [SURVIVED]
//                                      and 2 [TARGET DELETED]
//   SURVIVED, THEN WITNESSED      5  = rows C11-4, C11-12, C11-14, C11-17 and C11-20
//   SURVIVING STILL               2  = rows C11-15 and C11-19, both classified below
//   SURVIVED, CODE DELETED        2  = rows C11-26 and C11-30
//
//   The other nine rows are in TlsQuicHttp3Streams.cs's own C11 ledger, C11-37 to C11-45,
//   which is where this task's GOAWAY code lives. 36 + 9 = 45 rows for the task.
//
// THE HARNESS WAS DISTRUSTED, AND IT WAS RIGHT TO DISTRUST IT. The first two sweeps produced
// GARBAGE and were thrown away whole. VSTest leaves testhost.exe alive after `dotnet test`
// returns; it holds SharpTls.Tests.dll, the next build fails its copy with MSB3027, and
// `dotnet test` then runs the PREVIOUS binary. The tell was row C11-5 coming back carrying
// rows C11-24 and C11-25's kill list - a mutation reporting another mutation's witnesses.
// The harness now (1) kills testhost through PowerShell, because Git Bash mangles taskkill's
// /F into a path and the kill silently did nothing, (2) builds the mutant EXPLICITLY and
// refuses to test unless that build succeeded, (3) runs with --no-build so the binary is the
// one it just built, and (4) rejects any run reporting fewer than 1,700 cases as a non-result
// rather than a verdict. Only then was the proof pair re-run: the known-bad (the request's
// FIN dropped) reported KILLED by exactly the two full request/response tests, and an inert
// comment reported SURVIVED.
//
// AND A SECOND SELF-INFLICTED CONTAMINATION, RECORDED BECAUSE IT NEARLY LANDED. The harness
// keeps a pristine copy to restore from after each row. A copy taken while row C11-20's
// mutant was applied made that mutant the "original", and three green gate runs went by
// without noticing - because C11-20 survives. It was caught by checking every row's ORIGINAL
// text against the file rather than by reading the diff. A backup is not a baseline unless
// something proves it.
//
// Counts are per xUnit CASE, so a Theory failing in three rows counts three.
//
//   C11-1. The OpenLocalStreams-first guard removed. Killed by 1,
//        .ARequestBeforeTheOpeningFlightIsLocalMisuseAndThrows.
//   C11-2. A request accepted after an s8.1 connection error. Killed by 1,
//        .AConnectionErrorIsStickyAndRefusesFurtherRequests.
//   C11-3. s5.2's "MUST NOT initiate new requests" removed. Killed by 1,
//        .AGoawayForbidsANewRequest.
//   C11-4. [WAS-SURVIVOR] s5.2's MUST NOT compared against the stream the next request would
//        take rather than being unconditional. SURVIVED: .AGoawayForbidsANewRequest uses the
//        identifier 404 against zero open exchanges, so the mutant refuses too. UNWITNESSED,
//        not vacuous - s5.2's "This identifier MAY be zero if no requests or pushes were
//        processed" is a reachable case that separates them. Now killed by 1,
//        .AGoawayOfZeroStillForbidsANewRequest.
//   C11-5. s4.2.2's send half removed. Killed by 1,
//        .ThePeersMaximumFieldSectionSizeBoundsTheRequest.
//   C11-6. The peer's spent initial_max_streams_bidi not checked, so OpenBidirectional throws
//        instead of refusing. Killed by 1,
//        .APeerBidirectionalStreamAllowanceOfZeroRefusesRatherThanThrows.
//   C11-7. The peer's per-stream credit not checked, so Send throws. Killed by 1,
//        .APeerStreamCreditTooSmallForTheHeadersFrameRefusesRatherThanThrows.
//   C11-8. s18.2's 0x06 read as 0x05 - the swap TlsQuicPeerFlowControlBudget's header calls
//        the most likely defect in that file. Killed by 1, the same test, which is why
//        FlowControlParameters gives every limit a value ending in its own parameter id.
//   C11-9. [RE-LISTED as the harness's known-bad proof] The request stream's FIN dropped.
//        Killed by 2, .AFullRequestAndResponseCompleteAgainstTheLoopbackPeer and
//        .AFullRequestAndResponseCompleteAgainstSystemNetQuic - one per peer, which is the
//        clearest evidence the two done-when arms are independent.
//   C11-10. s4.2.2's receive half: the advertised limit not plumbed into the reader. Killed
//        by 1, .TheAdvertisedMaximumFieldSectionSizeBoundsTheResponse.
//   C11-11. The advertised limit thrown away at construction. Killed by 2, the same test's
//        two Theory rows. Two rows because the knob has two places to be lost.
//   C11-12. [WAS-SURVIVOR] The spec not handed to the request encoder, so C9's four knobs
//        change no byte. SURVIVED: every test used a spec whose knobs equalled the default.
//        UNWITNESSED. Now killed by 1,
//        .TheConnectionEncodesTheRequestWithItsOwnSpecAndNotADefaultOne, which reads the
//        reserved frame off the wire.
//   C11-13. An ABSENT peer limit refuses and a PRESENT one is ignored. Killed by 12.
//   C11-14. [WAS-SURVIVOR] The first frame measured whatever it is, so s7.2.8's reserved
//        frame is measured as a field section. SURVIVED: no test combined
//        SendReservedFramesOnRequestStreams with a peer limit. UNWITNESSED. Now killed by 1,
//        .TheReservedFrameIsNotMeasuredAsTheFieldSection.
//   C11-15. [SURVIVED] Any QPACK decode failure refuses the request, not only s4.2.2's
//        FieldSectionTooLarge. UNREACHABLE BY CONSTRUCTION, and no test is written: the only
//        input this measurement ever sees is bytes THIS encoder produced one line earlier,
//        and TlsQuicQpackEncoderTests and TlsQuicQpackDecoderTests pin the round trip against
//        RFC 9204 Appendix B's published vectors. A test would have to make our encoder emit
//        something our decoder rejects, which no path admits - it would pass against the
//        mutant and be a false witness.
//   C11-16. The peer's limit not applied to the measurement. Killed by 1,
//        .ThePeersMaximumFieldSectionSizeBoundsTheRequest.
//   C11-17. [WAS-SURVIVOR] SettingValue returns the FIRST setting whatever its identifier.
//        SURVIVED: every test that read a setting had the wanted one first, or had only one.
//        UNWITNESSED. Now killed by 2, .ASettingIsFoundByItsIdentifierRatherThanByItsPosition
//        and .OurSpecWithoutAMaxFieldSectionSizeAdvertisesNoLimit.
//   C11-18. The PEER's limit read off OUR spec. Killed by 4.
//   C11-19. [SURVIVED] AsFieldSectionLimit's saturating cast becomes an unchecked one.
//        UNREACHABLE BY CONSTRUCTION, and no test is written. s7.2.4's Value is a
//        variable-length integer, so every value either side can express is at most
//        QuicVariableLengthInteger.MaximumValue = 2^62-1; long.MaxValue is 2^63-1; so
//        `value < long.MaxValue` is TRUE for every expressible value and the saturating
//        branch cannot be reached from any wire input. TlsQuicHttp3Spec.Settings enforces the
//        same bound on our own side. The guard is kept because it is the correct answer if
//        the type ever widens, and it is recorded here rather than asserted to be
//        load-bearing.
//   C11-20. [WAS-SURVIVOR] An ABSENT limit read as zero rather than as no limit. SURVIVED:
//        every spec in the tests carried MAX_FIELD_SECTION_SIZE, so null never reached the
//        constructor's call. UNWITNESSED, and the same absent-versus-zero shape as the
//        finding that stopped HTTP/3 starting at all - rfc9114-section7-framing-layer.txt:
//        "SETTINGS_MAX_FIELD_SECTION_SIZE (0x06): The default value is unlimited." Now killed
//        by 1, .OurSpecWithoutAMaxFieldSectionSizeAdvertisesNoLimit.
//   C11-21. s5.2's "identifier or greater" becomes strictly greater. Killed by 1,
//        .AGoawayMidRequestIsRecordedAndTheResponseStillCompletes.
//   C11-22. The rejection window inverted. Killed by 1, the same test.
//   C11-23. The peer's control stream read and its verdict discarded. Killed by 6.
//   C11-24. The connection error not sticky in TryProcess. Killed by 3.
//   C11-25. Fail does not record the code, so nothing is sticky and nothing can be closed
//        with. Killed by 3.
//   C11-26. [SURVIVED - TARGET DELETED] End of stream reported on every later pump. See
//        C11-30; the flag both rows mutate no longer exists.
//   C11-27. A FIN arriving with no new bytes never reported, so no response completes. Killed
//        by 1, .AFinThatArrivesWithNoNewBytesEndsTheResponseOnce.
//   C11-28. The fresh bytes taken from the start of the stream rather than from the cursor.
//        Killed by 1, .AResponseSplitAcrossThreeStreamFramesIsReassembled.
//   C11-29. The cursor never advances, so every byte is handed to the reader again. Killed
//        by 3.
//   C11-30. [SURVIVED - TARGET DELETED] The end-of-stream report not remembered. C11-26 and
//        C11-30 mutate the read and the write of one EndOfStreamReported flag and BOTH
//        survived the whole gate, for one reason: a repeated report carries zero bytes, and
//        TlsQuicHttp3Response.TryRead only answers s4.1's "additional HTTP response following
//        a final HTTP response" when bytes.Length > 0. Two survivors on one flag is a flag
//        that does nothing, so it was DELETED rather than documented or witnessed - a test
//        for either row would have passed against its mutant and been a false witness.
//   C11-31. The FIN never passed to the reader, so s4.1 never completes a message. Killed
//        by 5.
//   C11-32. Every response lookup answers with the FIRST request's reader - the spike's
//        literal id 0, reintroduced. Killed by 1,
//        .TwoRequestsOnOneConnectionEachLandOnTheirOwnReader.
//   C11-33. The s8.1 code the close carries not recorded. Killed by 2.
//   C11-34. Every close graceful, so the s8.1 fault code never reaches one. Killed by 1,
//        .APeerControlStreamWhoseFirstFrameIsNotSettingsClosesWithMissingSettings.
//   C11-35. s5.2's "SHOULD use the H3_NO_ERROR error code" becomes a zero. Killed by 1,
//        .AGracefulCloseUsesH3NoError.
//   C11-36. The opening flight runs but is not recorded, so no request may follow. Killed
//        by 16.
//
// TWO ROWS THIS BUILD REFUSED TO EXPRESS THE OBVIOUS WAY, recorded because the handoff's rule
// is that a build error is a non-result rather than a verdict. C11-29 written as
// `x = x` is CS1717 and C11-36 as a deleted assignment is CS0649; rewritten `+= 0` and
// `|= false` they build and they kill. C11-39 in the sibling ledger is the CS0162 case.
//
// ============================================================================
// THE MUTATION LEDGER - THE TWO OWED DEBTS (this file)
// ============================================================================
//
//   ROWS BELOW                   10  = OWED-1 to OWED-10 with no gaps
//   THE HARNESS PROOF PAIR        2  = OWED-1 known-bad (KILLED) and OWED-2 inert (SURVIVED)
//   REAL MUTATIONS                8  = 10 rows less the 2 proof rows, so OWED-3 to OWED-10
//   KILLED                        9  = 10 rows less 1 [SURVIVED]
//   SURVIVING                     1  = row OWED-2, VACUOUS, classified at the row
//
//   9 + 1 = 10 and 2 + 8 = 10.
//
// THE SWEEP RAN IN A PRIVATE WORKTREE, for the reason C10c's ledger gives rather than for
// tidiness: `taskkill /F /IM testhost.exe` matches EVERY concurrent agent's test host and not
// this one's, and it aborted runs in both directions last session. A worktree needs no kill.
//
// EVERY RUN WAS HELD TO AN EXACT CASE COUNT. A test host that dies mid-run prints an ordinary
// `Failed: 0, Passed: <m>` line with a SMALLER Total, which reads as a survivor that never ran.
// The harness reads the run's own `Total:` and rejects anything other than 1,805 - this suite in
// an isolated tree - retrying a row up to three times. It builds `--no-incremental` and tests
// `--no-build`, because a C# optional-parameter default is baked into the CALLING assembly and
// row OWED-7 mutates exactly such a call; C10c's row C10c-23 was invisible until the test project
// was recompiled. A build failure prints BUILD-ERROR, which is a non-result and not a verdict,
// and a pattern matching other than exactly once prints NO-MATCH.
//
// THE HARNESS WAS PROVED IN BOTH DIRECTIONS BEFORE ANY ROW WAS BELIEVED - not by argument but by
// two rows inside the same sweep, which is why they are numbered rather than described.
//
//   OWED-1. [PROOF, KNOWN-BAD] The whole of debt 1 reverted: CloseAsync routed back through
//        _connection.CloseAsync(TlsQuicTransportError.ApplicationError, ...), which is the
//        mapping this task replaced. Killed by 2,
//        .APeerControlStreamWhoseFirstFrameIsNotSettingsClosesWithMissingSettings and
//        .AGracefulCloseUsesH3NoError - one per s8.1 code, and the demonstration that both
//        witnesses read the FRAME: this mutant leaves ApplicationCloseErrorCode untouched, so a
//        test reading that property would have passed against it.
//   OWED-2. [PROOF, INERT - SURVIVED] A comment inserted above the ApplicationCloseErrorCode
//        assignment. 0 failures of 1,805. VACUOUS, and NO TEST IS WRITTEN: a comment changes no
//        emitted byte and no observable state, so anything claiming to witness it would be
//        witnessing something else. A harness that cannot report SURVIVED is measuring the
//        suite rather than the mutant.
//   OWED-3. s19.19's Error Code field carries one constant - H3_NO_ERROR - whatever code was
//        asked for. Killed by 1,
//        .APeerControlStreamWhoseFirstFrameIsNotSettingsClosesWithMissingSettings. ONE AND NOT
//        TWO IS THE POINT: .AGracefulCloseUsesH3NoError closes with exactly that constant and
//        passes against this mutant, which is why two codes are witnessed rather than one.
//   OWED-4. ApplicationCloseErrorCode records `errorCode + 1`, so what this class asked for is
//        not what it reports. Killed by 2.
//   OWED-5. s19.19's Reason Phrase dropped, the frame sent with none. Killed by 2. The phrase is
//        diagnostic now rather than load-bearing and it is still pinned, because a frame that
//        quietly stopped carrying one is a wire change.
//   OWED-6. The Reason Phrase's hex case flipped, `0x{errorCode:x}` -> `:X`. Killed by 1:
//        H3_NO_ERROR (0x0100) has no hex letter in it, so only the 0x010a witness can see this.
//        The pair of codes earns its keep a second time.
//   OWED-7. [DEBT 2, THE PRE-CHANGE ROW] request.Method not passed to the reader, which is the
//        code exactly as C11 left it. Killed by 1, the "HEAD" row of
//        .OnlyAHeadResponseMayDeclareAContentLengthItSendsNoDataFor - the demonstration that
//        this task's case fails against the code as it stood, rather than an assertion that it
//        would have.
//   OWED-8. Every response read as a HEAD response, the argument a constant "HEAD". Killed by 1,
//        the "GET" row of the same theory - which exists for exactly this mutant, the cheapest
//        way to get a one-argument change wrong.
//   OWED-9. request.Path passed where request.Method belongs: the same type, the wrong field,
//        and the one substitution the compiler cannot object to. Killed by 1, the "HEAD" row.
//   OWED-10. [IN THE TEST, DELIBERATELY] The theory's `Method = method` pinned to "GET", so the
//        parameter never reaches the request that is opened. Killed by 1, the "HEAD" row. This
//        row asks whether the two Theory rows differ in anything that reaches the connection at
//        all, which is the one question a passing two-row theory cannot answer about itself.
internal sealed class TlsQuicHttp3Connection
{
    // One request stream and the reader draining it. A class rather than a tuple because
    // Consumed and Finished are MUTATED per pump and a tuple in a List cannot be.
    private sealed class Exchange(TlsQuicStream stream, TlsQuicHttp3Response response)
    {
        internal TlsQuicStream Stream { get; } = stream;

        internal TlsQuicHttp3Response Response { get; } = response;

        // How many of Stream.Received's bytes have been handed to Response. The reader holds
        // its own partial-frame remainder, so this only ever grows.
        internal int Consumed;

        // How many of Response.SectionAcknowledgments have been emitted on the decoder stream.
        // The same shape as Consumed and for the same reason: RFC 9204 s2.2.2.1's MUST is per
        // FIELD SECTION, and a pump that re-presents a stream carrying no new section must send
        // nothing. Comparing a count against a list that only grows is what makes that hold
        // without a per-section flag.
        internal int Acknowledged;
    }

    private readonly TlsQuicConnection _connection;
    private readonly TlsQuicHttp3Spec _spec;
    private readonly TlsQuicHttp3Streams _streams;
    private readonly List<Exchange> _exchanges = [];
    private bool _opened;

    /// <summary>Creates the HTTP/3 layer over a QUIC connection whose handshake has been
    /// confirmed.</summary>
    /// <remarks>NOTHING IS SENT HERE. s6.2.1's opening flight is
    /// <see cref="OpenLocalStreams"/>, kept separate so a caller chooses when the first bytes
    /// are queued and so this constructor cannot fail on a connection that is not ready.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Either argument is
    /// <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="spec"/> sends
    /// <c>SETTINGS_H3_DATAGRAM</c> = 1 while <paramref name="connection"/> advertised no
    /// non-zero <c>max_datagram_frame_size</c>, and
    /// <see cref="TlsQuicHttp3Spec.AllowDatagramSettingWithoutTransportParameter"/> is not
    /// set.</exception>
    internal TlsQuicHttp3Connection(TlsQuicConnection connection, TlsQuicHttp3Spec spec)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(spec);

        // THE ONE RULE THAT SPANS THE TWO SPECS, AND THIS CONSTRUCTOR IS WHERE THEY MEET.
        // The HTTP/3 half of "I will receive datagrams" is spec.Settings' 0x33; the QUIC half
        // is a transport parameter inside the ClientHello the connection already sent. Neither
        // type can see the other, so an inconsistent pair is composable from outside and its
        // only symptom is remote: fp.impersonate.pro answers it with H3_SETTINGS_ERROR, task
        // C17 having measured 0/3 without the parameter against 3/3 with it. Raising it HERE
        // costs a caller one exception at the line that composed the pair, instead of a 0x109
        // from a peer with no obligation to explain itself - and RFC 9114 s8.1 lets a peer
        // close for any SETTINGS it dislikes, so 0x109 does not even identify which pair.
        //
        // NOT AN RFC RULE. See TlsQuicHttp3Spec.AllowDatagramSettingWithoutTransportParameter's
        // remarks for the search that establishes RFC 9297 does not require this and for the
        // deployed implementation that enforces it anyway. That is exactly why the exemption
        // exists and why this check reads it rather than being unconditional.
        //
        // AFTER THE NULL GUARDS AND BEFORE ANY FIELD IS ASSIGNED, so a rejected pair leaves no
        // half-built object and allocates nothing on the way out but the message.
        if (!spec.AllowDatagramSettingWithoutTransportParameter
            && TlsQuicHttp3Settings.Value(spec.Settings, TlsQuicHttp3Spec.H3DatagramIdentifier)
                is 1
            && connection.AdvertisedMaxDatagramFrameSize is null)
        {
            throw new ArgumentException(
                "This connection sends SETTINGS_H3_DATAGRAM (0x33) = 1 but its ClientHello "
                    + "advertised no max_datagram_frame_size (RFC 9221 s3's 0x20) with a "
                    + "non-zero value, so it claims to receive HTTP/3 datagrams over a "
                    + "transport it did not negotiate. Deployed servers close such a "
                    + "connection with H3_SETTINGS_ERROR (0x0109) and say nothing about which "
                    + "setting they meant. Add max_datagram_frame_size to the transport "
                    + "parameters the ClientHello carries, or drop 0x33 from "
                    + "TlsQuicHttp3Spec.Settings or send it as 0. If the client being "
                    + "reproduced really does send this pair, set "
                    + "TlsQuicHttp3Spec.AllowDatagramSettingWithoutTransportParameter.",
                nameof(spec));
        }

        _connection = connection;
        _spec = spec;
        _streams = new TlsQuicHttp3Streams(spec, connection.Streams);
        MaximumFieldSectionSizeAdvertised = AsFieldSectionLimit(
            TlsQuicHttp3Settings.Value(spec.Settings, TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier));
    }

    /// <summary>Gets s6.2's stream layer, for the peer's SETTINGS and control-stream
    /// state.</summary>
    internal TlsQuicHttp3Streams Streams => _streams;

    /// <summary>Gets the s8.1 code this connection took, or 0.</summary>
    /// <remarks>A <see cref="ulong"/> and not a <see cref="TlsQuicHttp3ErrorCode"/> because
    /// TlsQuicHttp3Response reports RFC 9204's QPACK codes through the same channel, and
    /// s8.1's own text makes the widening safe: "use of an error code in an unexpected context
    /// or receipt of an unknown error code MUST be treated as equivalent to H3_NO_ERROR", so a
    /// code outside the enum is a value to carry rather than a value to reject. Zero means
    /// none - <see cref="TlsQuicHttp3ErrorCode.None"/> is 0 and every real s8.1 or RFC 9204
    /// code is non-zero.</remarks>
    internal ulong ConnectionErrorCode { get; private set; }

    /// <summary>Gets the s8.1 code
    /// <see cref="CloseAsync(TlsQuicHttp3ErrorCode, CancellationToken)"/> closed with, or
    /// <see langword="null"/> if it has not been called.</summary>
    /// <remarks>WHAT WAS ASKED FOR, NOT WHAT LEFT. RFC 9000 s10.2.3 converts a type 0x1d frame
    /// that cannot be sent at 0-RTT or 1-RTT and drops the code, and s10.2.2 forbids a draining
    /// connection from sending anything at all, so this can name a code no peer ever saw. The
    /// frame's own code is TlsQuicConnection.ClosedWithApplicationErrorCode, and the datagram is
    /// what the tests read.</remarks>
    internal ulong? ApplicationCloseErrorCode { get; private set; }

    /// <summary>Gets the s4.2.2 limit this connection advertised, or
    /// <see cref="long.MaxValue"/> when its SETTINGS carry no
    /// <c>SETTINGS_MAX_FIELD_SECTION_SIZE</c>.</summary>
    internal long MaximumFieldSectionSizeAdvertised { get; }

    /// <summary>Gets the peer's advertised <c>SETTINGS_MAX_FIELD_SECTION_SIZE</c>, or
    /// <see langword="null"/> until its SETTINGS have arrived or if they omit it.</summary>
    internal ulong? PeerMaximumFieldSectionSize =>
        TlsQuicHttp3Settings.Value(_streams.PeerSettings, TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier);

    /// <summary>Gets the stream id the peer's GOAWAY named, or <see langword="null"/> if none
    /// has arrived.</summary>
    internal ulong? PeerGoawayStreamId => _streams.PeerGoawayStreamId;

    /// <summary>Gets the request streams opened here, in open order.</summary>
    internal IReadOnlyList<ulong> RequestStreamIds =>
        _exchanges.ConvertAll(exchange => exchange.Stream.Id);

    /// <summary>Sends s6.2.1's opening flight: the spec's unidirectional streams, with SETTINGS
    /// as the control stream's first frame.</summary>
    /// <remarks>Delegates to <see cref="TlsQuicHttp3Streams.OpenLocalStreams"/> rather than
    /// repeating it, so there is one place that writes a stream-type varint. Queued, not sent -
    /// the bytes leave on the next <see cref="TlsQuicConnection.SendPendingAsync"/>.</remarks>
    /// <exception cref="InvalidOperationException">Already called, or the peer's
    /// <c>initial_max_streams_uni</c> cannot cover the spec's list.</exception>
    internal void OpenLocalStreams()
    {
        _streams.OpenLocalStreams();
        _opened = true;
    }

    /// <summary>Opens a request stream, queues RFC 9114 s4.1's whole message - a HEADERS frame,
    /// then <see cref="TlsQuicHttp3Request.Body"/> as a DATA frame if there is one, then
    /// <see cref="TlsQuicHttp3Request.Trailers"/> as a trailing HEADERS frame if there is one -
    /// and closes the sending half with s19.8's FIN.</summary>
    /// <remarks>
    /// <para>NEVER THROWS FOR ANY PEER STATE. Every condition the peer controls - a spent
    /// stream allowance, either of the two credits being too small for the message, a field
    /// section past its advertised limit, a GOAWAY already received - is a
    /// <see cref="TlsQuicHttp3RequestRefusal"/> and not an exception, even though the
    /// TlsQuicStreamSet calls underneath throw on all of them.</para>
    /// <para>STILL ONE Send AND STILL ONE FIN, WHICH IS WHY A GET'S BYTES DID NOT MOVE. s4.1's
    /// three items are three HTTP/3 frames inside ONE QUIC stream, not three stream writes:
    /// TryEncode appends all of them to one list and the single
    /// <see cref="TlsQuicStreamSet.Send"/> below carries it with the FIN, exactly as it did
    /// when only a HEADERS frame could be in that list. A request with an empty Body and no
    /// Trailers therefore produces the identical STREAM frame it produced before either
    /// existed, which TlsQuicConnectionTests.AGetsBytesOnTheWireAreUnchangedByTheBodyPath pins
    /// against a transcript recorded at pristine HEAD.</para>
    /// <para>s4.1's "After sending a request, a client MUST close the stream for sending" is
    /// what the FIN is, and it is unconditional here rather than deferred - the same sentence
    /// carves out only CONNECT, which TlsQuicHttp3Request refuses at the encoder.</para>
    /// <para>THE ORDER IS DELIBERATE: everything that can refuse runs BEFORE
    /// <see cref="TlsQuicStreamSet.OpenBidirectional"/>, because that call spends an ordinal
    /// and RFC 9000 s3.2 makes a spent ordinal a stream the peer opens implicitly - a hole
    /// nothing would ever send to.</para>
    /// </remarks>
    /// <param name="request">The request to encode.</param>
    /// <param name="refusal">Why nothing was opened, or
    /// <see cref="TlsQuicHttp3RequestRefusal.None"/>.</param>
    /// <param name="malformed">The s4.2 or s4.3.1 rule the request broke when
    /// <paramref name="refusal"/> is <see cref="TlsQuicHttp3RequestRefusal.Malformed"/>.</param>
    /// <returns>The request stream, or <see langword="null"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is
    /// <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException"><see cref="OpenLocalStreams"/> has not run.
    /// s6.2.1's "Each side MUST initiate a single control stream at the beginning of the
    /// connection and send its SETTINGS frame as the first frame on this stream" is a local
    /// obligation, so failing it is local misuse rather than a refusal.</exception>
    internal TlsQuicStream? TryOpenRequest(
        TlsQuicHttp3Request request,
        out TlsQuicHttp3RequestRefusal refusal,
        out TlsQuicHttp3RequestError malformed)
    {
        ArgumentNullException.ThrowIfNull(request);
        malformed = TlsQuicHttp3RequestError.None;

        if (!_opened)
        {
            throw new InvalidOperationException(
                "RFC 9114 s6.2.1: \"Each side MUST initiate a single control stream at the "
                    + "beginning of the connection and send its SETTINGS frame as the first "
                    + "frame on this stream.\" Call OpenLocalStreams before the first request.");
        }

        if (ConnectionErrorCode != 0)
        {
            refusal = TlsQuicHttp3RequestRefusal.ConnectionErrored;
            return null;
        }

        // s5.2: "Endpoints MUST NOT initiate new requests or promise new pushes on the
        // connection after receipt of a GOAWAY frame from the peer. Clients MAY establish a new
        // connection to send additional requests." NO COMPARISON AGAINST THE IDENTIFIER HERE -
        // the MUST NOT is unconditional, and the identifier bounds which ALREADY-SENT requests
        // were processed (see IsRejectedByGoaway), not which new ones may be opened.
        if (_streams.PeerGoawayStreamId is not null)
        {
            refusal = TlsQuicHttp3RequestRefusal.GoawayReceived;
            return null;
        }

        var frame = new List<byte>();
        if (!request.TryEncode(frame, _spec, out malformed))
        {
            refusal = TlsQuicHttp3RequestRefusal.Malformed;
            return null;
        }

        if (!FitsPeerFieldSectionLimit(frame))
        {
            refusal = TlsQuicHttp3RequestRefusal.FieldSectionTooLargeForPeer;
            return null;
        }

        var budget = _connection.PeerFlowControl;
        if (budget.RemainingBidirectionalStreams == 0)
        {
            refusal = TlsQuicHttp3RequestRefusal.PeerBidirectionalStreamsExhausted;
            return null;
        }

        // NO SIZE COMPARISON HERE ANY MORE, AND s19.10 IS WHY: "The data sent on a stream MUST
        // NOT exceed the LARGEST maximum stream data value advertised by the receiver". LARGEST,
        // not initial. The advertised initial_max_stream_data_bidi_remote is only the first
        // member of that set, and the set grows - TlsQuicConnection's dispatch now feeds
        // MAX_STREAM_DATA and MAX_DATA to TlsQuicStreamSet.ReceiveFlowControlFrame, which is the
        // exact handover PeerStreamCreditTooSmall's remarks named. So a message larger than the
        // initial credit is something to PACE rather than refuse: TlsQuicStreamSet.Send splits it
        // at TlsQuicStreamBudget.Available - Math.Min of both limits, so Consume cannot throw
        // behind it - sends what fits, holds the tail, and emits s19.13's STREAM_DATA_BLOCKED so
        // the peer has a reason to grant. Comparing frame.Count against a number no grant moves
        // was refusing requests this tree can now complete.
        //
        // WHAT IS STILL REFUSED IS A PEER THAT ADVERTISED NOTHING. At zero not one byte leaves,
        // so opening the stream would spend an ordinal out of initial_max_streams_bidi - which
        // nothing here can raise, there being no MAX_STREAMS arm in that same dispatch - to buy a
        // wait with no lower bound. That trade is worth refusing by name, and it is the peer's
        // own standing statement rather than a transient shortfall.
        if (budget.InitialMaxStreamDataBidiRemote == 0)
        {
            refusal = TlsQuicHttp3RequestRefusal.PeerStreamCreditTooSmall;
            return null;
        }

        // THE SAME RULE AT s19.9's SCOPE, AND STILL THE REMAINING POOL RATHER THAN THE ADVERTISED
        // initial_max_data. OpenLocalStreams and every earlier request have already drawn on it,
        // and a request that was PACED against it drew it down to exactly zero - which is the
        // reachable way to get here now that nothing refuses on size.
        if (budget.RemainingConnectionData == 0)
        {
            refusal = TlsQuicHttp3RequestRefusal.PeerConnectionCreditTooSmall;
            return null;
        }

        var stream = _connection.Streams.OpenBidirectional();
        _connection.Streams.Send(stream, frame.ToArray(), fin: true);

        // request.Method IS PASSED, and it is the one place it can be. RFC 9110 s6.4.1's
        // never-having-content set opens with "Responses to the HEAD request method
        // (Section 9.3.2) never include content", which is a property of the REQUEST and not of
        // anything on the response stream - so a reader that is not told the method reads
        // s4.1.2's Content-Length rule strictly and refuses a HEAD response that legally
        // declares a length it sends no DATA for. s8.6 is why HEAD is the case that cannot be
        // worked around: it forbids a Content-Length outright in a 1xx, a 204 and a 2xx to a
        // CONNECT, so "only a HEAD response and a 304 MAY carry one at all" and the 304 is
        // decidable from :status. C10c named this the one-argument change C11 owed; the
        // argument's default is null and null is read as neither HEAD nor CONNECT, so leaving
        // it off was a silent refusal rather than a compile error.
        // THE TABLE IS THE STREAM LAYER'S AND IS PASSED, NOT REBUILT. It is null on the
        // zero-capacity arm, which is what leaves every narrowed-settings caller on C8's
        // static-only path unchanged.
        // AND THE BUFFERING CEILING IS THE SPEC'S, for the reason every other number this call
        // hands over is: TlsQuicHttp3Response is told its limits and reaches for none. Its own
        // default is int.MaxValue, so a caller that constructed one directly and a request
        // opened here would otherwise disagree about how much of a response to hold - which is
        // the difference between an audit finding and a knob.
        _exchanges.Add(new Exchange(
            stream,
            new TlsQuicHttp3Response(
                MaximumFieldSectionSizeAdvertised,
                request.Method,
                _streams.Table,
                _spec.MaximumBufferedResponseBytes)));
        refusal = TlsQuicHttp3RequestRefusal.None;
        return stream;
    }

    /// <summary>Gets the reader draining one request stream, or <see langword="null"/> if that
    /// id is not one this connection opened.</summary>
    /// <remarks>
    /// <para>THE READER IS WHERE A REQUEST'S OUTCOME LIVES, ALL THREE OF THEM, and no fourth
    /// accessor here restates any of them.
    /// <see cref="TlsQuicHttp3Response.IsComplete"/> is a whole response;
    /// <see cref="TlsQuicHttp3Response.ResetErrorCode"/> is a failed one and carries the RFC
    /// 9114 s4.1.1 code that decides whether it may be retried; neither is a response still
    /// arriving. A reset is a STREAM error - s8's own word - so it does not appear in
    /// <see cref="ConnectionErrorCode"/> and does not stop the sibling exchanges.</para>
    /// <para>THE SENDING HALF IS THE STREAM'S AND NOT THIS TYPE'S.
    /// <see cref="TlsQuicStream.SendStopped"/> and
    /// <see cref="TlsQuicStream.StopSendingErrorCode"/> say whether the peer cut our request
    /// body short, on the very stream <see cref="TryOpenRequest"/> returned. They are
    /// deliberately not mirrored onto the response: RFC 9114 s4.1's "Clients MUST NOT discard
    /// complete responses as a result of having their request terminated abruptly" makes
    /// STOP_SENDING a routine half of a SUCCESSFUL exchange, and a mirror on the reader would
    /// invite a caller to read it as a failure.</para>
    /// </remarks>
    internal TlsQuicHttp3Response? ResponseFor(ulong streamId)
    {
        foreach (var exchange in _exchanges)
        {
            if (exchange.Stream.Id == streamId)
            {
                return exchange.Response;
            }
        }
        return null;
    }

    /// <summary>Gets whether a peer GOAWAY has said this request will not be processed.</summary>
    /// <remarks>s5.2: "Requests or pushes with the indicated identifier or greater are rejected
    /// ... by the sender of the GOAWAY", and "if the client has already sent requests with a
    /// stream ID greater than or equal to the identifier contained in the GOAWAY frame, those
    /// requests will not be processed." GREATER THAN OR EQUAL, so the named stream is itself
    /// rejected - an off-by-one here silently reports a lost request as a served one.</remarks>
    internal bool IsRejectedByGoaway(ulong streamId) =>
        _streams.PeerGoawayStreamId is { } goaway && streamId >= goaway;

    /// <summary>Reads everything the peer has delivered - its unidirectional streams and every
    /// open request stream - and reports the s8.1 code to close with if it cannot be
    /// accepted.</summary>
    /// <remarks>
    /// <para>NEVER THROWS, FOR ANY INPUT, and idempotent: bytes already handed to a reader are
    /// not handed to it twice, and a frame that stops mid-field is left for the next call.</para>
    /// <para>THE CONTROL STREAM IS READ FIRST. A peer whose control stream opened with
    /// something other than SETTINGS has failed s6.2.1 and the response bytes on a request
    /// stream are then beside the point; reading them first would report whichever fault the
    /// iteration order happened to reach.</para>
    /// <para>ONCE IT ANSWERS <see langword="false"/> IT KEEPS ANSWERING <see langword="false"/>
    /// with the same code, matching TlsQuicHttp3Response.TryRead - an s8.1 connection error
    /// leaves no state to parse into.</para>
    /// </remarks>
    /// <param name="errorCode">The s8.1 or RFC 9204 code to close with, or 0.</param>
    internal bool TryProcess(out ulong errorCode)
    {
        errorCode = ConnectionErrorCode;
        if (ConnectionErrorCode != 0)
        {
            return false;
        }

        // RFC 9297 s2.1's two receipt rules, BEFORE the streams, because both are connection
        // errors and s2.1 attaches them to receipt rather than to use. A datagram naming a
        // stream is not read as naming one until it has passed these.
        //
        // THE QUIC HALF IS ALREADY DONE. TlsQuicConnection applied RFC 9221 s3's transport
        // rules as the frames arrived and refused anything this endpoint never invited; what
        // reaches here is a payload it did.
        foreach (var datagram in _connection.DrainReceivedDatagrams())
        {
            var cursor = 0;
            if (!QuicVariableLengthInteger.TryRead(datagram, ref cursor, out var quarterStreamId))
            {
                // s2.1: "Receipt of a QUIC DATAGRAM frame whose payload is too short to allow
                // parsing the Quarter Stream ID field MUST be treated as an HTTP/3 connection
                // error of type H3_DATAGRAM_ERROR (0x33)." An empty payload is the whole of
                // that case here - s4's "empty (i.e., zero-length) datagrams are allowed" at
                // the QUIC layer is exactly what HTTP/3 refuses at this one - and so is a
                // multi-byte varint prefix with its continuation bytes missing.
                return Fail((ulong)TlsQuicHttp3ErrorCode.H3DatagramError, out errorCode);
            }

            if (quarterStreamId > MaximumQuarterStreamId)
            {
                // s2.1: "The largest legal QUIC stream ID value is 2^62-1, so the largest legal
                // value of the Quarter Stream ID field is 2^60-1.  Receipt of an HTTP/3
                // Datagram that includes a larger value MUST be treated as an HTTP/3 connection
                // error of type H3_DATAGRAM_ERROR (0x33)."
                //
                // REACHABLE, WHICH IS NOT OBVIOUS. A variable-length integer holds up to
                // 2^62-1, so the four values between 2^60 and 2^62-1 are encodable and this
                // check is the only thing that refuses them.
                return Fail((ulong)TlsQuicHttp3ErrorCode.H3DatagramError, out errorCode);
            }

            // AND THE PAYLOAD GOES NOWHERE. s2.1's remaining rule is "If a datagram is received
            // after the corresponding stream's receive side is closed, the received datagrams
            // MUST be silently dropped", and with no extension in this tree consuming HTTP
            // datagrams every one of them is in that position. Dropping after validating is the
            // point: the connection errors above are what a peer can observe, and they are
            // raised whether or not anything would have used the bytes.
        }

        // THE PEER'S STREAMS FIRST, AND C16 MADE THAT ORDERING LOAD-BEARING. It was already the
        // order - the control stream's SETTINGS decide what a request stream's bytes mean - and
        // it is now also what makes a parked field section unblock in the SAME pump the encoder
        // instructions arrive in: the table advances here, the exchange loop below re-presents
        // the parked bytes against it. Reversing these two would cost a whole round trip per
        // blocked section, which no test would fail on and every live request would pay.
        if (!_streams.TryProcessPeerStreams(out var streamsError))
        {
            return Fail(streamsError, out errorCode);
        }

        foreach (var exchange in _exchanges)
        {
            // A STREAM ALREADY RECORDED AS RESET IS DONE BEING READ. RFC 9000 s4.5 leaves the
            // bytes below the reset's final size undelivered forever, so nothing further can
            // arrive; the pump that carried the reset has already read everything that did.
            // Without this a response parked on RFC 9204 s2.2.1's block would be re-presented
            // on every later pump for the life of the connection, on a stream nothing will ever
            // unblock.
            if (exchange.Response.IsReset)
            {
                continue;
            }

            // s19.5's STOP_SENDING NEEDS NO ARM HERE, AND s4.1 SAYS SO IN A MUST NOT: "Clients
            // MUST NOT discard complete responses as a result of having their request
            // terminated abruptly." A server that has all it needs "MAY abort reading the
            // request stream, send a complete response, and cleanly close the sending part of
            // the stream", with "The error code H3_NO_ERROR ... when requesting that the client
            // stop sending" - so STOP_SENDING is a routine half of a SUCCESSFUL exchange and an
            // arm that failed the request on it would break conforming servers. The transport
            // half is already done where it belongs: TlsQuicStreamSet stops queueing on a
            // stopped stream and answers s19.5's RESET_STREAM. A caller that needs to know its
            // request body was cut short reads TlsQuicStream.SendStopped and
            // StopSendingErrorCode on the stream TryOpenRequest handed back.
            var delivered = exchange.Stream.Received;
            var fresh = delivered.Count - exchange.Consumed;

            // s19.8's FIN and the last byte can arrive in the same STREAM frame or in two, so
            // "the stream ended" is a separate question from "there are new bytes".
            //
            // NO "REPORTED ONCE" FLAG, AND ITS ABSENCE IS MEASURED. An earlier draft carried an
            // EndOfStreamReported bool so that a completed stream was not re-reported on every
            // later pump. TWO separate mutations of it survived the whole gate - deleting the
            // flag's read and deleting its write - because re-reporting is a no-op:
            // TlsQuicHttp3Response.TryRead only answers s4.1's "additional HTTP response
            // following a final HTTP response" when bytes.Length > 0, and a repeat carries
            // none. A flag whose removal no test can see is a flag to delete rather than to
            // document, so it was deleted; AFinThatArrivesWithNoNewBytesEndsTheResponseOnce
            // pumps three further times and pins that the repeat stays benign.
            //
            // A RESET IS NOT AN END OF STREAM, AND ReceiveComplete NOW SAYS SO ITSELF. This
            // line briefly read `ReceiveComplete && !ResetReceived`, because RFC 9000 s4.5's
            // "A RESET_STREAM ... also establishes the final size" meant a reset set the same
            // field a FIN did - so a peer that reset naming a final size equal to what it had
            // already sent satisfied the size comparison exactly, with no FIN anywhere, and
            // would have set IsComplete on a response s4.1 calls incomplete. The stream layer
            // now answers the three questions separately: ReceiveComplete is normal completion
            // and excludes every reset, FinalSizeKnown is s4.5's union, ResetReceived is
            // abandonment. The conjunct was deleted rather than kept as belt-and-braces,
            // because a second copy of a rule is a second thing to disagree with the first.
            var endOfStream = exchange.Stream.ReceiveComplete;

            // `&& !IsBlocked` IS C16'S, AND WITHOUT IT NOTHING EVER UNBLOCKS. What a parked
            // field section is waiting for arrives on the peer's ENCODER stream, so the
            // response stream itself is silent by definition while it waits - which is exactly
            // the shape this `continue` skips. Re-presenting is safe with no new bytes:
            // TlsQuicHttp3Response.TryRead re-reads its own _pending over an empty span.
            //
            // RE-PRESENTED UNCONDITIONALLY WHILE BLOCKED, rather than only when the Insert
            // Count has moved. The decoder answers Blocked again in the same breath if it has
            // not, at the cost of re-reading one prefix, and it is self-correcting: there is no
            // second copy of s2.2.1's comparison here to disagree with the decoder's.
            //
            // ONCE PER PUMP AND NEVER IN A LOOP. A section that never unblocks is re-presented
            // once per PumpOnceAsync and PumpOnceAsync is bounded by TlsQuicConnection's
            // deadline - see the note on TryHoldBlocked below.
            // `&& !ResetReceived` KEEPS A RESET-ONLY PUMP FROM BEING SKIPPED. A peer that
            // resets without sending anything alongside it leaves `fresh` at zero, and
            // ReceiveComplete is false because no reset is completion - so
            // without this conjunct the arm below would never run and the reset would go
            // unrecorded. It costs one empty TryRead on that pump, which is the same no-op
            // this loop already makes for a blocked section.
            if (fresh == 0 && !endOfStream && !exchange.Response.IsBlocked
                && !exchange.Stream.ResetReceived)
            {
                continue;
            }

            var chunk = new byte[fresh];
            for (var i = 0; i < fresh; i++)
            {
                chunk[i] = delivered[exchange.Consumed + i];
            }
            exchange.Consumed = delivered.Count;

            if (!exchange.Response.TryRead(chunk, endOfStream, out var responseError))
            {
                return Fail(responseError, out errorCode);
            }

            // RFC 9000 s19.4's RESET_STREAM, which s4.1.1 makes an ordinary thing for a server
            // to send: "servers cancel requests if they are unable to or choose not to
            // respond". THIS EXCHANGE IS OVER AND THE CONNECTION IS NOT - s8 separates "This is
            // referred to as a 'stream error'" from "This is referred to as a 'connection
            // error'", and closing the connection here would take every sibling request down
            // for one server's decision about this one. Nothing calls Fail.
            //
            // AFTER THE READ, AND THE FIRST CUT OF THIS FIX HAD IT BEFORE. Recording the reset
            // first meant `continue`-ing past TryRead, so a pump carrying both the response's
            // HEADERS frame and the RESET_STREAM - the ordinary shape, since a server cancelling
            // mid-response has already sent some of it - parsed none of it: Status stayed -1 and
            // HeaderFields stayed empty, while the comment here promised the opposite. Reading
            // first is what makes s4.1's "endpoints SHOULD begin processing partial HTTP
            // messages once enough of the message has been received to make progress" true of
            // this loop rather than merely asserted by it.
            //
            // AND IT IS SAFE, WHICH IS WHY THE ORDER IS A FREE CHOICE RATHER THAN A TRADE.
            // TlsQuicHttp3Response.IsComplete is assigned only inside TryRead's `endOfStream`
            // block, and `endOfStream` is TlsQuicStream.ReceiveComplete, which is false for
            // every reset - normal completion is the only question that property answers. A
            // frame the reset cut in half simply stays in the reader's pending buffer,
            // unparsed, as any partial frame does.
            //
            // s4.1 AND RFC 9000 s3.2 TOGETHER ARE WHY A RESET AFTER A WHOLE RESPONSE IS
            // IGNORED. s3.2 lets a receiver in "Data Recvd" or "Data Read" discard a
            // RESET_STREAM, and s4.1 turns the permission into an instruction: "Clients MUST NOT
            // discard complete responses as a result of having their request terminated
            // abruptly." So a reset arriving after IsComplete is neither recorded nor answered
            // with s4.4.2's Stream Cancellation - the section it would cancel has already been
            // acknowledged.
            //
            // THE SAME-PUMP FIN-AND-RESET RACE RESOLVES TO "RESET", WHICH IS THE OTHER
            // DIRECTION FROM THE PARAGRAPH ABOVE AND IS THE SAFE ONE. When a FIN and a
            // RESET_STREAM arrive in the SAME pump there is no observable order between them -
            // both wrote the same `_finalSize` - so IsComplete has not been set yet when this
            // arm runs and the exchange is reported reset. A caller then retries a request that
            // had in fact completed, which costs a round trip; the opposite mistake hands over
            // a body the peer disowned. Once a FIN has completed a response on any EARLIER
            // pump, IsComplete is already true and s4.1's MUST NOT is honoured exactly.
            if (exchange.Stream.ResetReceived && !exchange.Response.IsComplete)
            {
                if (exchange.Response.OnPeerReset(exchange.Stream.ResetErrorCode!.Value))
                {
                    OnRequestStreamAbandoned(exchange);
                }

                // s2.1.2's slot has just been released by OnRequestStreamAbandoned and
                // TrySynchroniseQpackState would re-hold it for a section that will never
                // decode.
                continue;
            }

            if (!TrySynchroniseQpackState(exchange, out errorCode))
            {
                return false;
            }
        }

        return true;
    }

    // RFC 9204 s2.2.2.2's two obligations for a request stream that will decode nothing
    // further, run exactly once per stream because the loop above gates them on
    // TlsQuicHttp3Response.OnPeerReset's first-time answer.
    //
    // s2.2.2.2: "When an endpoint receives a stream reset before the end of a stream or before
    // all encoded field sections are processed on that stream, or when it abandons reading of a
    // stream, it generates a Stream Cancellation instruction; see Section 4.4.2. This signals
    // to the encoder that all references to the dynamic table on that stream are no longer
    // outstanding."
    //
    // THE RELEASE IS THE MORE URGENT OF THE TWO AND IS THIS CHANGE'S OWN DEBT. s2.1.2's
    // registry is held per blocked stream and TrySynchroniseQpackState is what normally lets a
    // slot go - which the reset arm above now skips. A stream that was parked on s2.2.1's block
    // when the peer reset it would otherwise hold its slot for the life of the connection, and
    // SETTINGS_QPACK_BLOCKED_STREAMS slots are a small number: leaking them ends as
    // QPACK_DECOMPRESSION_FAILED on some later, innocent request.
    //
    // THE CANCELLATION IS CONDITIONED ON THE TABLE, AND s2.2.2.2 GRANTS EXACTLY THAT: "A
    // decoder with a maximum dynamic table capacity (Section 3.2.3) equal to zero MAY omit
    // sending Stream Cancellations, because the encoder cannot have any dynamic table
    // references." Table is null on precisely that arm, so the MAY is taken - which is also
    // what keeps a default-spec client's bytes unchanged, its SETTINGS being empty and its
    // advertised capacity therefore zero.
    //
    // AND IT IS THE CONDITION THAT KEEPS THE PEER AWAY FROM A THROW. SendStreamCancellation
    // raises InvalidOperationException when there is no local decoder stream, and a peer's
    // RESET_STREAM must never reach one. A non-null Table is sufficient rather than merely
    // convenient: TlsQuicHttp3Streams' constructor builds one only when the open order contains
    // QpackDecoder as well, so a table existing here implies OpenLocalStreams opened that
    // stream - and OpenLocalStreams has necessarily run, TryOpenRequest throwing without it and
    // there being no exchange to reset otherwise.
    private void OnRequestStreamAbandoned(Exchange exchange)
    {
        _streams.BlockedStreams.Release(exchange.Stream.Id);

        if (_streams.Table is not null)
        {
            _streams.SendStreamCancellation(exchange.Stream.Id);
        }
    }

    // RFC 9204 s2.1.2's bound and s2.2.2.1's acknowledgment, both of which are about a field
    // section and neither of which TlsQuicHttp3Response can do for itself: one needs the whole
    // connection's blocked count and the other needs the decoder stream.
    private bool TrySynchroniseQpackState(Exchange exchange, out ulong errorCode)
    {
        errorCode = 0;
        var response = exchange.Response;

        if (response.IsBlocked)
        {
            // s2.1.2: "If a decoder encounters more blocked streams than it promised to
            // support, it MUST treat this as a connection error of type
            // QPACK_DECOMPRESSION_FAILED." Held rather than counted, so a stream that blocks on
            // pump after pump occupies ONE slot and not one per pump.
            //
            // THIS IS WHERE THE HANG WOULD BE IF THERE WERE ONE, AND THERE IS NOT. Nothing
            // waits here. TryProcess returns, its caller's PumpOnceAsync returns, and every
            // PumpOnceAsync goes through TlsQuicConnection.ReceiveWithinDeadlineAsync, which is
            // bounded by the deadline assigned once at construction and never reassigned. A
            // section that never unblocks therefore ends as that deadline's TimeoutException -
            // A4 9a-ii's "THIS IS A TIMEOUT, NOT A RETRANSMISSION" - rather than as a spin. No
            // timer is added here and none is needed; adding a second one would be a second
            // clock to disagree with the first.
            //
            // THE CODE IS OBTAINED BY CALLING TryGetHttp3ErrorCode, not by naming 0x0200 here.
            // That is the same rule TlsQuicHttp3Response.TryRead's own comment states for the
            // same number: one spelling, in the decoder, and a caller that wants it asks.
            if (!_streams.BlockedStreams.TryHold(
                    exchange.Stream.Id, response.BlockedRequiredInsertCount, out var holdError))
            {
                TlsQuicQpackDecoder.TryGetHttp3ErrorCode(holdError, out var holdCode);
                return Fail(holdCode, out errorCode);
            }

            return true;
        }

        // s2.2.1's unblock, and s2.2.2.2's abandonment, which are the same call. Released
        // unconditionally rather than only when a hold exists - TlsQuicQpackBlockedStreams
        // documents the no-op - so that a stream which never blocked costs no branch here.
        _streams.BlockedStreams.Release(exchange.Stream.Id);

        // s2.2.2.1's MUST, one instruction per section and in decode order. The senders throw
        // when there is no decoder stream, which is why TlsQuicHttp3Streams refuses a dynamic
        // table unless the spec's open order includes one: with no table the list below stays
        // empty and this loop never runs.
        var acknowledgments = response.SectionAcknowledgments;
        while (exchange.Acknowledged < acknowledgments.Count)
        {
            _streams.SendSectionAcknowledgment(
                exchange.Stream.Id, acknowledgments[exchange.Acknowledged]);
            exchange.Acknowledged++;
        }

        return true;
    }

    /// <summary>Receives one datagram, answers it, and then runs
    /// <see cref="TryProcess"/>.</summary>
    /// <remarks>
    /// <para>ONE DATAGRAM PER CALL, which is TlsQuicConnection.PumpOnceAsync's shape and not a
    /// choice made here. A caller loops until whatever it is waiting for is true, against a
    /// deadline of its own - THIS CLASS HOLDS NO TIMEOUT, which is the first of the four things
    /// the deleted spike hard-coded.</para>
    /// <para>Returns whether the HTTP/3 layer is still usable. A transport-level failure comes
    /// out as the exception TlsQuicConnection already raises; only s8.1 faults answer
    /// <see langword="false"/>.</para>
    /// </remarks>
    /// <param name="cancellationToken">Cancels the receive.</param>
    internal async ValueTask<bool> PumpOnceAsync(
        CancellationToken cancellationToken = default)
    {
        await _connection.PumpOnceAsync(cancellationToken).ConfigureAwait(false);
        return TryProcess(out _);
    }

    /// <summary>Sends an s8.1 error code as RFC 9000 s19.19's application CONNECTION_CLOSE.
    /// </summary>
    /// <remarks>See THE APPLICATION CONNECTION_CLOSE: BOTH HALVES ARE CLOSED NOW at the top of
    /// this file for what reaches the wire. s5.2: "An endpoint that completes a graceful
    /// shutdown SHOULD use the H3_NO_ERROR error code when closing the connection", which is
    /// why the graceful overload names that code rather than zero.</remarks>
    internal ValueTask CloseAsync(
        TlsQuicHttp3ErrorCode errorCode, CancellationToken cancellationToken = default) =>
        CloseAsync((ulong)errorCode, cancellationToken);

    /// <summary>Sends an s8.1 or RFC 9204 error code as RFC 9000 s19.19's application
    /// CONNECTION_CLOSE.</summary>
    /// <remarks>
    /// <para>NEVER THROWS FOR ANY CODE. s8.1's and RFC 9204 s6's spaces both fit s20's "62-bit
    /// unsigned integers" many times over, but this overload takes a raw <see cref="ulong"/> for
    /// the reason <see cref="ConnectionErrorCode"/> gives, so a wider one can arrive;
    /// TlsQuicConnection.CloseWithApplicationErrorAsync converts rather than rejects it, and
    /// this is the teardown path.</para>
    /// <para>THE REASON PHRASE NAMES THE SAME CODE THE Error Code FIELD NOW CARRIES, and that
    /// is diagnostic rather than load-bearing - s19.19: "Additional diagnostic information for
    /// the closure." It is the only trace left when s10.2.3's conversion applies, and s10.2.3
    /// clears it in exactly that case, so nothing reads it back.</para>
    /// </remarks>
    internal ValueTask CloseAsync(ulong errorCode, CancellationToken cancellationToken = default)
    {
        ApplicationCloseErrorCode = errorCode;
        return _connection.CloseWithApplicationErrorAsync(
            errorCode,
            $"HTTP/3 (RFC 9114 s8.1) error code 0x{errorCode:x}.",
            cancellationToken);
    }

    /// <summary>Closes with whatever s8.1 code this connection took, or with
    /// <see cref="TlsQuicHttp3ErrorCode.H3NoError"/> if it took none.</summary>
    internal ValueTask CloseWithCurrentErrorAsync(CancellationToken cancellationToken = default) =>
        CloseAsync(
            ConnectionErrorCode != 0
                ? ConnectionErrorCode
                : (ulong)TlsQuicHttp3ErrorCode.H3NoError,
            cancellationToken);

    // RFC 9297 s2.1: "The largest legal QUIC stream ID value is 2^62-1, so the largest legal
    // value of the Quarter Stream ID field is 2^60-1." Written as the shift rather than as a
    // decimal literal so the arithmetic is the sentence's and not a transcription of it.
    private const ulong MaximumQuarterStreamId = (1UL << 60) - 1;

    private bool Fail(ulong code, out ulong errorCode)
    {
        ConnectionErrorCode = code;
        errorCode = code;
        return false;
    }

    // s4.2.2's send side. Returns true when there is no limit to apply or the section fits.
    //
    // THE MEASUREMENT IS A DECODE, NOT AN ADDITION. TlsQuicQpackDecoder.TryDecodeFieldSection
    // already applies s4.2.2's "uncompressed size of fields, including the length of the name
    // and value in bytes plus an overhead of 32 bytes for each field" to whatever it decodes,
    // so handing it our own bytes with the PEER's limit asks the one implementation of that
    // arithmetic the question directly.
    //
    // ANY DECODE FAILURE THAT IS NOT FieldSectionTooLarge LETS THE REQUEST THROUGH, and that is
    // deliberate rather than lax: this method's question is s4.2.2's SHOULD NOT and nothing
    // else. A field section our own encoder produced and our own decoder cannot read is a
    // defect in one of those two, which the C5-C8 round-trip tests are the place to catch;
    // refusing to send here would convert it into a silent no-request.
    private bool FitsPeerFieldSectionLimit(List<byte> frame)
    {
        if (PeerMaximumFieldSectionSize is not { } advertised)
        {
            return true;
        }

        var limit = AsFieldSectionLimit(advertised);
        var span = CollectionsMarshal.AsSpan(frame);
        var offset = 0;

        // EVERY HEADERS frame is the one s4.2.2 talks about, and there can now be two of them.
        // A reserved (GREASE) frame may precede the first when
        // TlsQuicHttp3Spec.SendReservedFramesOnRequestStreams is set and carries no field
        // section, and a DATA frame may sit between them, so the frames are walked and the
        // non-HEADERS ones skipped rather than any position being assumed.
        //
        // NOT `return` ON THE FIRST MATCH, AND THAT IS THE WHOLE OF WHAT TRAILERS CHANGED HERE.
        // s4.2.2's limit is "the maximum size of the message header it will accept on an
        // individual HTTP message", and s4.2 makes QPACK compress "header and trailer sections"
        // alike - so a trailer section past the peer's limit is the same SHOULD NOT. Returning
        // on the header section would have checked the half that is almost never the large one
        // and waved the other through.
        while (TlsQuicHttp3Frames.TryRead(
                   span, ref offset, out var frameType, out var payload, out _)
            == TlsQuicHttp3FrameReadStatus.Complete)
        {
            if (frameType != (ulong)TlsQuicHttp3FrameType.Headers)
            {
                continue;
            }

            // Sized from the encoded payload: one decoded line cannot come from fewer than one
            // encoded byte, and RFC 7541's longest Huffman code is 30 bits, so a coded string
            // is under four times its input - the same bound TlsQuicHttp3Request's own comment
            // reasons from. Transient, and a request field section is a few dozen bytes.
            var lines = new TlsQuicQpackDecodedFieldLine[payload.Length + 1];
            var buffer = new byte[(payload.Length * 4) + 1024];
            if (!TlsQuicQpackDecoder.TryDecodeFieldSection(
                    payload, buffer, lines, limit, out _, out _, out var error)
                && error == TlsQuicQpackError.FieldSectionTooLarge)
            {
                return false;
            }
        }

        // Either no HEADERS frame was found in bytes TlsQuicHttp3Request.TryEncode just
        // produced - which it writes on every success, so that arm is unreachable by
        // construction - or every one of them fit. Answering "it fits" keeps this method total;
        // throwing here would turn a defect in the encoder into an exception on the request
        // path, which the class header forbids.
        return true;
    }

    // s7.2.4's Value is a varint and so runs to 2^62-1, while TlsQuicQpackDecoder's limit is a
    // long. SATURATING RATHER THAN CASTING: an unchecked cast of a value above long.MaxValue
    // would wrap to a negative limit and refuse every field section, which is the opposite of
    // what a peer advertising a huge number asked for. Absent means no limit, which is
    // s4.2.2's own default - the parameter is how an implementation "wishes to advise its peer
    // of this limit", so a peer that sends none has advised nothing.
    private static long AsFieldSectionLimit(ulong? advertised) =>
        advertised is { } value && value < long.MaxValue ? (long)value : long.MaxValue;
}


// ============================================================================
// THE MUTATION LEDGER - TASK C16 (this file: re-presenting a parked section,
// s2.1.2's bound and s2.2.2.1's acknowledgment)
// ============================================================================
//
//   ROWS BELOW                    6  = C16-28 to C16-33 with no gaps
//   KILLED WHEN FIRST RUN         4  = 6 rows, less 2 [WAS-SURVIVOR] and 0 [SURVIVED]
//   SURVIVED, THEN WITNESSED      2  = rows C16-28 and C16-30
//   SURVIVING STILL               0
//
//   4 + 2 = 6. The task's other 29 rows are in TlsQuicQpackDecoder.cs (11),
//   TlsQuicQpackPrimitives.cs (2), TlsQuicHttp3Request.cs (7), TlsQuicHttp3Streams.cs (7) and
//   TlsQuicHttp3Frames.cs (2). 6 + 29 = 35 rows for the task.
//
// A UNIQUE ROW PREFIX, because this file's C11 block counts `C11-` and its OWED block counts
// `OWED-`. Its own three:
//   `grep -cE '^// +C16-[0-9]+\. ' TlsQuicHttp3Connection.cs`                  must return 6
//   `grep -cE '^// +C16-[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicHttp3Connection.cs` must return 2
//   `grep -cE '^// +C16-[0-9]+\..*\[SURVIVED\]' TlsQuicHttp3Connection.cs`     must return 0
//
// Same harness, same gate and the same three harness defects as TlsQuicQpackDecoder.cs's C16
// block, which records them in full.
//
//  C16-28. [WAS-SURVIVOR] `!IsBlocked` dropped from the `fresh == 0` guard, so a parked section
//        is never re-presented - and what unblocks it arrives on a DIFFERENT stream, so its
//        own stream is silent by definition while it waits. THE PLAN SAID ONLY ONE SHAPE OF
//        TEST CATCHES THIS AND IT WAS RIGHT; the first attempt was not that shape. The
//        reordering theory sends its response with fin: true, which leaves `endOfStream` true
//        forever after, so the guard never fires and the mutant survived the whole gate.
//        .AParkedSectionIsRePresentedEvenWhileItsOwnStreamIsSilentAndUnfinished sends NO FIN,
//        which is the only arrangement where fresh is 0, endOfStream is false, and IsBlocked is
//        the sole thing distinguishing a stream worth re-reading from one with nothing to say.
//        Killed by exactly one case.
//  C16-29. TryHold's answer ignored, so s2.1.2's bound is counted and never enforced. Killed by
//        exactly one case, .MoreBlockedStreamsThanPromisedIsAConnectionError.
//  C16-30. [WAS-SURVIVOR] Release never called, so an unblocked stream keeps its slot forever.
//        IT SURVIVED because every existing test blocked a stream and left it blocked; nothing
//        unblocked one and then asked for the slot back. At an advertised
//        SETTINGS_QPACK_BLOCKED_STREAMS of 1 the mutant closes the connection on the second
//        request that ever blocks, however long after the first finished - "one, ever" instead
//        of s2.1.2's "at all times". .AnUnblockedStreamGivesItsSlotBackSoTheNextOneMayBlock is
//        the sequence that separates them. Killed by exactly one case.
//  C16-31. [RESTATED] s2.2.2.1's acknowledgment sent once per PUMP instead of once per SECTION,
//        which is a QPACK_DECODER_STREAM_ERROR at the peer's encoder. As first written it
//        dropped the Acknowledged bookkeeping entirely and did not COMPILE, which is weaker
//        evidence than a test failure - the same restatement C15-44 and C15-45 needed and for
//        the same reason. Restated to keep the field assigned while still sending per pump;
//        killed by exactly one case,
//        .ADecodedSectionSendsOneSectionAcknowledgmentAndFurtherPumpsSendNone.
//  C16-32. The whole QPACK synchronisation step deleted: nothing holds, nothing releases and
//        nothing acknowledges. Killed by 3. [RESTATED] for the literal-`false` reason above.
//  C16-33. [RESTATED] The stream layer's table not passed to the reader, so a connection
//        advertising 65536 still decodes on the static-only arm. As first written its anchor
//        came from the PLAN's quotation of this line rather than from the file and matched
//        nothing, which the harness reported ANCHOR-MISSING rather than as a verdict - the
//        doc-versus-code pattern this phase's handoff records losing six times running.
//        Restated against the file and killed by 7.
//
// ============================================================================


// ============================================================================
// THE MUTATION LEDGER - TASK H3B (this file: the two flow-control credits a
// request with content spends, and s4.2.2's limit reaching the trailer section)
// ============================================================================
//
//   ROWS BELOW                    4  = H3B-12 to H3B-15 with no gaps
//   KILLED BY A FAILING CASE      4
//   KILLED-BY-COMPILER            0
//   SURVIVED                      0
//
//   4 + 0 = 4. The task's other 15 rows are in TlsQuicHttp3Request.cs, whose block carries
//   the harness description, the gate figures and the two calibration rows. 4 + 15 = 19 rows
//   for the task, 0 survivors.
//
// A UNIQUE ROW PREFIX, because this file already counts `C11-`, `C16-` and `OWED-`. Its own
// three:
//   `grep -cE '^// +H3B-[0-9]+\. ' TlsQuicHttp3Connection.cs`                  must return 4
//   `grep -cE '^// +H3B-[0-9]+\..*\[RESTATED\]' TlsQuicHttp3Connection.cs`     must return 0
//   `grep -cE '^// +H3B-[0-9]+\..*\[SURVIVED\]' TlsQuicHttp3Connection.cs`     must return 0
//
//  H3B-12. Killed by 1. The connection-level check reads the ADVERTISED initial_max_data
//        instead of what is LEFT of it, so a later request that no longer fits is let through
//        and TlsQuicPeerFlowControlBudget.ConsumeConnectionData throws out of a path whose
//        documented contract is that no peer state can raise an exception from it. Killed by
//        exactly one case, .ASecondBodyThatFitsTheAdvertisedPoolButNotTheRemainderIsRefused -
//        the only test that sends two bodies that each fit the pool and do not fit it
//        together, which is the only arrangement where the two quantities differ.
//  H3B-13. Killed by 2. The connection-level check deleted outright, so initial_max_data
//        refuses nothing and Send throws.
//  H3B-14. Killed by 2. The per-stream check stops counting the message and refuses only a
//        zero-byte credit - the pre-body behaviour, which a HEADERS-only test cannot tell
//        apart from the correct one because a HEADERS frame fits any credit that is not
//        nearly zero.
//  H3B-15. Killed by 1. FitsPeerFieldSectionLimit returns on the FIRST HEADERS frame again,
//        which is exactly what it did before this task, so a trailer section past the peer's
//        advertised SETTINGS_MAX_FIELD_SECTION_SIZE is never measured. Killed by exactly one
//        case, .ATrailerSectionPastThePeersFieldSectionLimitIsRefused, which first asserts
//        that the same request WITHOUT the trailer is accepted - so the refusal it then
//        measures can only be the trailer section's.
