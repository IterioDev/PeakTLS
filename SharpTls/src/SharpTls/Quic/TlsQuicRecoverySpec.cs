namespace SharpTls.Quic;

/// <summary>A sender-side congestion controller: the object that decides how many bytes may
/// be in flight, and therefore the shape of this client's send rate under loss.</summary>
/// <remarks>
/// <para>AN INTERFACE AND NOT AN ENUM, AND THIS IS THE LARGEST SINGLE FINGERPRINT IN LOSS
/// RECOVERY. RFC 9002 s7 makes the controller replaceable in its own words -
/// rfc9002-section7-congestion-control.txt lines 22-27: "The signals QUIC provides for
/// congestion control are generic and are designed to support different sender-side
/// algorithms. A sender can unilaterally choose a different algorithm to use, such as CUBIC
/// [RFC8312]. If a sender uses a different controller than that specified in this document,
/// the chosen controller MUST conform to the congestion control guidelines specified in
/// Section 3.1 of [RFC8085]." RFC 9002 specifies NewReno (line 20: "a sender-side congestion
/// controller for QUIC similar to TCP NewReno [RFC6582]") and that is what task A3-9 will
/// implement; Chromium is widely said to run BBR, which is neither, and a caller reproducing a
/// Chromium fingerprint would supply their own implementation here rather than pick a member
/// out of an enum this library wrote. An enum with one member is an abstraction with no
/// second case, and an enum with three members two of which throw is worse.</para>
/// <para>DELIBERATELY TWO MEMBERS AND NOT THE WHOLE OF APPENDIX B, AS THIS SEAM SHIPPED AT
/// A3-2. The acknowledgement, loss and persistent-congestion events an implementation needs
/// take a set of sent packets, and that record - <c>SentPacket</c> in RFC 9002 Appendix A.1.1 -
/// was task A3-3's to introduce. Declaring those signatures against a type that did not exist
/// yet would either have invented it in the wrong task or forced A3-3 to match a shape guessed
/// before its fields were read out of the extract. <b>Task A3-9 widened it</b> and <b>task
/// A3-10 folded the widening back here</b>, which is why the members below are no longer two.
/// A3-9 could not edit this file, so it declared the six signal members on a derived
/// <c>ITlsQuicCongestionControlSignals</c> in TlsQuicCongestionControl.cs and recorded that the
/// derived interface "should be deleted the moment they can be moved there". A3-10 moved them
/// and deleted it.</para>
/// <para>WHAT WAS DELIBERATELY LEFT OFF, AND IT IS THE WHOLE POINT OF A SEAM. A3-9's
/// <c>TlsQuicCongestionState</c> - slow start, recovery, congestion avoidance - and its
/// <c>SlowStartThresholdBytes</c> are NOT here. Those three states are NewReno's own vocabulary
/// (rfc9002-section7-congestion-control.txt lines 90-91); BBR's are Startup, Drain, ProbeBW and
/// ProbeRTT and they are not these, and CUBIC has no recovery period shaped like this one. A
/// seam that demanded either of them would be a seam that admits only NewReno, which is exactly
/// what this interface exists to avoid. They stay on
/// <c>TlsQuicNewRenoCongestionController</c>.</para>
/// <para>WHY THESE SIGNALS AND NOT APPENDIX B'S FUNCTION LIST. RFC 9002 Appendix B publishes
/// nine numbered fragments; six of them - B.4 OnPacketSent, B.5 OnPacketsAcked, B.6
/// OnCongestionEvent, B.7 ProcessECN, B.8 OnPacketsLost, B.9 RemoveFromBytesInFlight - are
/// entry points, and three of those are NewReno-internal rather than signals a sender raises.
/// B.6 is called only from B.7 and B.8 and is a NewReno reaction, not an event; B.7 needs an
/// ECN-CE counter this library does not yet read off an ACK frame. So the seam carries the four
/// events a sender genuinely raises - sent, acknowledged, lost, discarded - plus
/// <see cref="OnPersistentCongestion"/>, which s7.6.2 makes a MUST for every controller and not
/// only for this one, plus the one question the send path asks,
/// <see cref="CanSend"/>, plus <see cref="BytesInFlight"/>, which
/// rfc9002-appendix-a-and-b-pseudocode-and-constants.txt line 511 makes the controller's own
/// variable and not the connection's.</para>
/// <para>STILL DELIBERATELY ABSENT. There is no pacing member: s7.7 is prose with no pseudocode
/// at all and is task A3-11's. There is no ECN member: s7.1 defers to RFC 9000 s13.4.2 for the
/// response and nothing in this library reads an ACK frame's ECN counts yet. Adding either here
/// would be guessing a shape for a task that has not read its extract.</para>
/// <para>EVERY MEMBER BELOW IS TOTAL. No implementation of this interface may throw for any
/// input, including a null list, a fabricated packet with a negative size, or a size that would
/// overflow. A controller that threw on an acknowledgement would take the connection down at
/// exactly the moment the network was already misbehaving, and the send path has no sensible
/// recovery from it. Construction is the one place validation belongs, because a mis-built
/// controller is a programming error rather than a network event.</para>
/// </remarks>
internal interface ITlsQuicCongestionController
{
    /// <summary>Gets the controller's name, as task A3-12's readout renders it.</summary>
    /// <remarks>A STRING RATHER THAN A BOOLEAN OR AN ENUM, because the readout has to be able
    /// to print a name this library has never heard of: the whole point of the seam is that a
    /// caller supplies a controller, and a closed set of names would make the readout unable
    /// to describe the very case the seam exists for.</remarks>
    string Name { get; }

    /// <summary>Gets the current congestion window, in bytes: the limit on bytes in flight
    /// that RFC 9002 Appendix B.2 calls <c>congestion_window</c>.</summary>
    long CongestionWindowBytes { get; }

    /// <summary>Gets RFC 9002 B.2's <c>bytes_in_flight</c> as this controller counts it: the
    /// summed size of every packet handed to <see cref="OnPacketSent"/> with
    /// <see cref="TlsQuicSentPacket.IsInFlight"/> set that has not since been acknowledged,
    /// declared lost, or discarded.</summary>
    /// <remarks>THE CONTROLLER'S OWN COUNTER, not a view of
    /// <c>TlsQuicConnection.BytesInFlight</c>. The two are computed from the same events and
    /// should agree, and a test that asserts they do is worth more than a shared field would
    /// be: a controller that took the connection's counter could not be driven at all without
    /// a connection, and every state-machine test would need a live handshake.</remarks>
    long BytesInFlight { get; }

    /// <summary>Answers RFC 9002 s7's send gate: may a packet of <paramref name="bytes"/> bytes
    /// be sent without pushing bytes in flight past the congestion window?</summary>
    /// <remarks>
    /// <para>rfc9002-section7-congestion-control.txt lines 46-49: "An endpoint MUST NOT send a
    /// packet if it would cause bytes_in_flight (see Appendix B.2) to be larger than the
    /// congestion window, unless the packet is sent on a PTO timer expiration (see Section 6.2)
    /// or when entering recovery (see Section 7.3.2)." LARGER THAN, so a send that lands
    /// exactly on the window is permitted and this returns true for it. The two exceptions are
    /// the CALLER's: a PTO probe is sent without asking, and s7.5 lines 195-197 then require it
    /// to be counted anyway - "Probe packets MUST NOT be blocked by the congestion controller. A
    /// sender MUST however count these packets as being additionally in flight". Putting the
    /// exceptions here would mean this method sometimes answers a question it was not asked, and
    /// a send path that forgot to pass a flag would silently ignore the window.</para>
    /// </remarks>
    /// <param name="bytes">The size of the packet the sender is considering. A non-positive
    /// value is answered rather than rejected; see the interface's totality note.</param>
    bool CanSend(int bytes);

    /// <summary>RFC 9002 B.4's <c>OnPacketSentCC</c>: add a packet's bytes to bytes in flight,
    /// if it counts toward them.</summary>
    /// <remarks>B.4 lines 538-542 add unconditionally because A.5 has already tested
    /// <c>in_flight</c> before calling; an implementation that tests
    /// <see cref="TlsQuicSentPacket.IsInFlight"/> itself lets a caller which hands over every
    /// packet it sent get B.2's exclusion (lines 507-509: "Packets only containing ACK frames do
    /// not count toward bytes_in_flight") rather than an inflated counter.</remarks>
    void OnPacketSent(in TlsQuicSentPacket sent);

    /// <summary>RFC 9002 B.5's <c>OnPacketsAcked</c>: remove newly acknowledged packets from
    /// bytes in flight and grow the window, unless a rule says otherwise.</summary>
    /// <param name="ackedPackets">The packets this acknowledgement newly acknowledged. Null is
    /// treated as none.</param>
    void OnPacketsAcked(IReadOnlyList<TlsQuicSentPacket>? ackedPackets);

    /// <summary>RFC 9002 B.8's <c>OnPacketsLost</c>: remove lost packets from bytes in flight
    /// and raise a congestion event if any of them was in flight.</summary>
    /// <remarks>THIS DOES NOT DECLARE PERSISTENT CONGESTION, and the split is deliberate. B.8
    /// runs its own congestion event and its persistent-congestion collapse in one body, but the
    /// collapse's condition - s7.6.2 - needs the RTT estimator, the peer's max_ack_delay and the
    /// send times of packets ACKNOWLEDGED across all packet number spaces, none of which a list
    /// of lost packets carries and none of which a controller should be reaching for. So the
    /// predicate is <c>TlsQuicPersistentCongestion.IsEstablished</c>, the sender evaluates it,
    /// and <see cref="OnPersistentCongestion"/> is what it calls when it holds.</remarks>
    /// <param name="lostPackets">The packets loss detection has just declared lost. Null is
    /// treated as none.</param>
    void OnPacketsLost(IReadOnlyList<TlsQuicSentPacket>? lostPackets);

    /// <summary>RFC 9002 s7.6.2's collapse: the sender has established persistent congestion,
    /// so reduce the congestion window to the minimum congestion window.</summary>
    /// <remarks>
    /// <para>ON THE SEAM AND NOT ONLY ON NEWRENO, because s7.6.2 lines 276-279 are a MUST
    /// addressed to senders rather than to a controller: "When persistent congestion is declared,
    /// the sender's congestion window MUST be reduced to the minimum congestion window
    /// (kMinimumWindow), similar to a TCP sender's response on an RTO [RFC5681]." A caller
    /// supplying a BBR or CUBIC controller is bound by that sentence too, and a seam with no way
    /// to say it would leave every such controller unable to obey it. Contrast
    /// <c>TlsQuicCongestionState</c>, which stays off the seam precisely because it is NOT
    /// something every controller has.</para>
    /// <para>NO ARGUMENTS, BECAUSE THE DECISION IS ALREADY MADE. Everything s7.6.2 weighs -
    /// which packets were lost, what was acknowledged between them, the RTT estimator's state -
    /// belongs to the detection, and passing it here would invite a second, disagreeing copy of
    /// the predicate inside each controller. This is the verdict, not the evidence.</para>
    /// </remarks>
    void OnPersistentCongestion();

    /// <summary>RFC 9002 B.9's <c>RemoveFromBytesInFlight</c>: when Initial or Handshake keys
    /// are discarded, the packets sent in that space stop counting.</summary>
    /// <remarks>NOT A CONGESTION EVENT. B.9 lines 650-654 touch bytes in flight and nothing else
    /// - no window change, no recovery period - because a discarded packet is neither delivered
    /// nor lost. Without this the window jams: a handshake's worth of Initial bytes stays in
    /// flight for the life of the connection and permanently shrinks the room
    /// <see cref="CanSend"/> reports.</remarks>
    /// <param name="discardedPackets">The packets whose keys were just dropped. Null is treated
    /// as none.</param>
    void OnPacketsDiscarded(IReadOnlyList<TlsQuicSentPacket>? discardedPackets);
}

/// <summary>What this client puts in a packet sent because a probe timeout expired.</summary>
/// <remarks>RFC 9002 s6.2.4 LEAVES THIS OPEN AND SAYS SO REPEATEDLY, which is what makes it a
/// knob rather than a rule. rfc9002-section6.2-probe-timeout.txt lines 205-210: "An endpoint
/// SHOULD include new data in packets that are sent on PTO expiration. Previously sent data
/// MAY be sent if no new data can be sent. Implementations MAY use alternative strategies for
/// determining the content of probe packets, including sending new or retransmitted data based
/// on the application's priorities." Lines 215-217 add the no-data case: "When there is no data
/// to send, the sender SHOULD send a PING or other ack-eliciting frame in a single packet,
/// rearming the PTO timer." The one hard rule is line 192 - "All probe packets sent on a PTO
/// MUST be ack-eliciting" - and every member below satisfies it.</remarks>
internal enum TlsQuicProbeContents
{
    /// <summary>A PING frame alone, in a packet no larger than the frame needs.</summary>
    /// <remarks>LEGAL, SELECTABLE, AND NOT THE DEFAULT. s6.2.3 lines 180-183 name this packet
    /// as an example of correct behaviour - "a client can coalesce an Initial packet containing
    /// PING and PADDING frames with a 0-RTT data packet" - so nothing here is a workaround for
    /// an illegal probe. It is not the default because s6.2.4 reserves the bare PING for "when
    /// there is no data to send", and because it carries no repair (RFC 9000 s13.3: "PING and
    /// PADDING frames contain no information"): a flight only a probe can repair never
    /// completes, and one measured production server closes on it with PROTOCOL_VIOLATION. See
    /// <see cref="TlsQuicRecoverySpec.ProbeContents"/>.</remarks>
    Ping,

    /// <summary>A PING frame padded out to a full-sized datagram. s6.2.4 line 188 permits
    /// "up to two full-sized datagrams containing ack-eliciting packets"; the size of a probe
    /// is visible on the wire without decrypting it, which is why this is not the same choice
    /// as <see cref="Ping"/>.</summary>
    PingWithPadding,

    /// <summary>Data already sent and not yet acknowledged, re-sent as the probe. THE SHIPPED
    /// DEFAULT.</summary>
    /// <remarks>s6.2.4's whole algorithm rather than one of its branches: it takes line 206's
    /// "Previously sent data MAY be sent" where there is any, and degrades to exactly
    /// <see cref="Ping"/>'s bytes where there is not, which is lines 215-217's fallback reached
    /// the way the section reaches it. A PING stays in front of the repair so that line 192's
    /// "All probe packets sent on a PTO MUST be ack-eliciting" holds structurally rather than
    /// conditionally.</remarks>
    RetransmittedData,
}

/// <summary>Whether this client acknowledges a 1-RTT packet as soon as it arrives or holds the
/// acknowledgement back.</summary>
/// <remarks>
/// <para>A LIVE DECISION RATHER THAN A CONSTANT, AND THE CURRENT CODE RECORDS THE OTHER SIDE OF
/// IT. <c>TlsQuicApplicationSendPath</c>'s remarks record the shipped choice as
/// "max_ack_delay is honoured by being beaten rather than by being scheduled against" - which
/// is legal, because beating a delay bound never violates it, and which is also a fingerprint:
/// an endpoint that acknowledges every packet immediately emits a different number of ACK
/// packets, differently spaced, from one that batches.</para>
/// <para>THE DELAY ITSELF IS NOT A MEMBER OF THIS TYPE OR OF ANY OTHER TYPE IN THIS FILE.
/// <c>max_ack_delay</c> is transport parameter 0x0B, so the bound this client is entitled to
/// use is the one it advertised, and the bound the peer may use is the one the peer
/// advertised. A number here would be a second source of truth for an advertised value, which
/// is the defect <c>TlsQuicConnectionSpec.LocalFlowControl</c>'s remarks record from the six
/// flow-control limits. See <see cref="TlsQuicTransportParameterId.MaxAckDelay"/>.</para>
/// </remarks>
internal enum TlsQuicAckPolicy
{
    /// <summary>Acknowledge as soon as an ack-eliciting packet is processed.</summary>
    Immediate,

    /// <summary>Hold an acknowledgement back, up to the advertised <c>max_ack_delay</c>, so
    /// that several acknowledgements can be carried by one packet.</summary>
    DelayedToMaxAckDelay,
}

// ADDING A KNOB TO THIS FILE? THREE THINGS ARE OWED, and they are the same three
// TlsQuicTransportParameterSpec.cs states for the parameter preset, because this is the same
// seam one layer down.
//
//   1. CITE THE EXTRACT LINE. Every value below names the file and the lines under
//      docs/superpowers/specs/reference-captures/ it was read out of. A value with no
//      citation is a value nobody can check, and RFC 9002 is captured precisely so that
//      nothing here has to be recalled.
//   2. IF NOTHING BOUNDS CHROMIUM'S, MARK IT. The marker's exact form is stated and enforced
//      by TlsQuicRecoverySpecTests.EveryUnverifiedPresetChoiceNamesATaskThatExistsInTheAPlan,
//      which counts the markers in this file, counts the ones carrying a task reference, and
//      resolves each reference against the A3 plan's headings. A marker with no task
//      reference, or one naming a task that does not exist, fails that test. Copy the form
//      off an existing marker below rather than from this comment - which deliberately does
//      not spell it, so that this paragraph is not itself counted as a marker.
//   3. PUT THE NUMBER IN THE PRESET BLOCK AND NOWHERE ELSE. Outside the block the only
//      numeric literals in this file's code are 0 and 1, both structural - an exclusive upper
//      bound's increment and a floor of one - and
//      TlsQuicRecoverySpecTests.NoRecoveryConstantLivesOutsideThePresetBlock enforces it.
//
// WHAT THIS FILE DELIBERATELY DOES NOT DO, and the user's design directive that settled it:
// "no placeholder values, everything must be configurable if different clients/browsers/apps/
// systems could send a different value ... the final goal of this library is to reproduce
// pretty much any fingerprint given, if the stack allows it." So there is no refusal here and
// no silent choice. Every one of the A3 plan's fourteen knobs is settable; the four the
// capture cannot bound carry a marker naming the task that would settle them. The standing
// rule "a constant nobody can check is not allowed" forbids presenting an invented value as
// measured - it never forbade offering a knob.
//
// AND THE CAVEAT THAT APPLIES TO ALL FOURTEEN AT ONCE, recorded here rather than left to be
// rediscovered: NO ENDPOINT THIS PROJECT CAN CURRENTLY REACH OBSERVES ANY OF THEM. The `perk`
// fingerprint has four segments - h3 SETTINGS, pseudo-header order, transport parameters in
// wire order, connection-ID lengths - and not one is a timing field. So every value below is
// consistent with RFC 9002 and none of them is evidence about Chromium; the difference between
// those two claims is what the markers exist to keep visible.

// TASK A3-2 - MUTATION LEDGER. 34 rows: 2 controls + 17 validation guards + 4 the draw +
// 2 the store and the connection spec + 7 the presets + 2 the markers and the preset block.
// 2 + 17 + 4 + 2 + 7 + 2 = 34. Killed 33; the single survivor is the harness's own inert
// control, which is what a survivor is supposed to look like.
//
// Swept in a private git worktree at 2304698 - a detached checkout of pristine HEAD, because
// two other tasks were editing TlsQuicConnection.cs and adding a transport under tests/ in the
// shared tree at the same time and a sweep there would have been scoring their work. The gate
// figures in this commit are measured in that worktree: 2087 passing at pristine HEAD, 2138
// after this task, 2138 - 2087 = 51 cases added. Every run rebuilt --no-incremental and was
// rejected unless the runner reported at least 2143 executed cases: an aborted run prints an
// ordinary "Failed: 0, Passed: <m>" line and would otherwise be recorded as a survivor that
// never ran. The first sweep of A32-M01 to A32-M32 ran at a floor of 2142 and all 32 reported
// 2142; A32-C1, A32-C2, A32-M04, A32-M07 and A32-M10 were re-run at 2143 after the fix below
// and all five reported 2143.
//
// THIS COMMIT LANDS ON A LATER COMMIT THAN THE ONE IT WAS SWEPT AT, because task A3-3
// landed mid-sweep. The two touch disjoint files - `git diff --stat 2304698..744b0ce --
// src/SharpTls/Quic/TlsQuicConnectionSpec.cs` is empty - so the sweep's verdicts stand.
// What does NOT carry over is the gate TOTAL, since A3-3 added cases of its own; the
// 2087/2138 pair above is the measurement at 2304698 and nothing here restates it as a
// figure anyone should expect to see on this branch's tip.
//
// -- controls, proved before anything else was trusted -- 2 rows ---------------------
// A32-C1 ThrowIfNotDefined never fires (&& false) .... KILLED    AnUndeclaredProbeContentIs
//        Rejected, AnUndeclaredAckPolicyIsRejected
// A32-C2 an inert comment added to this class ........ SURVIVED  by construction
//
// -- the validation guards, one row per rejecting branch -- 17 rows ------------------
// A32-M01 window multiplier guard weakened to allow 0  KILLED  AnInitialCongestionWindow
//         OutsideSection7Point2sShapeIsRejected
// A32-M02 window byte-cap guard deleted .............. KILLED  same
// A32-M03 minimum-window guard deleted ............... KILLED  AMinimumCongestionWindowOfNo
//         DatagramsIsRejected
// A32-M04 LossReductionFactor finiteness deleted ..... KILLED  APositiveNotANumberIsRejected
//         ByEveryFloatingPointKnob
//         [WAS-SURVIVOR] AND THE MOST VALUABLE ROW HERE. It survived the first sweep, and
//         the reason is a fact about .NET rather than about this file: double.NaN's sign bit
//         is SET, ThrowIfNegativeOrZero tests the sign bit rather than a comparison, and so
//         the literal NaN every test used was being rejected BY ACCIDENT. A NaN with the bit
//         clear passes every comparison guard. NOT AN EQUIVALENT MUTANT - it changes what the
//         setter accepts - and the test named above is the witness that was missing. The
//         comment on the guard said the opposite of the truth and now says this.
// A32-M05 LossReductionFactor upper guard deleted .... KILLED  ALossReductionFactorThatIsNot
//         AReductionIsRejected
// A32-M06 PacketThreshold guard deleted .............. KILLED  APacketThresholdOfZeroIsRejected
// A32-M07 TimeThreshold finiteness deleted ........... KILLED  ATimeThresholdThatIsNotA
//         PositiveMultiplierIsRejected (the +infinity row; positive NaN also reaches it)
// A32-M08 TimeThreshold positivity deleted ........... KILLED  same
// A32-M09 PersistentCongestionThreshold guard deleted  KILLED  APersistentCongestionThreshold
//         OfZeroIsRejected
// A32-M10 PtoBackoff finiteness deleted .............. KILLED  APtoBackoffThatDoesNotBackOff
//         IsRejected
// A32-M11 PtoBackoff factor lower bound deleted ...... KILLED  same
// A32-M12 PtoBackoff ceiling guard deleted ........... KILLED  same
// A32-M13 ProbePacketsPerPto lower guard deleted ..... KILLED  AProbeCountOutsideSection6
//         Point2Point4sOneOrTwoIsRejected
// A32-M14 ProbePacketsPerPto upper guard deleted ..... KILLED  same
// A32-M15 ProbeContents IsDefined deleted ............ KILLED  AnUndeclaredProbeContentIs
//         Rejected
// A32-M16 AckPolicy IsDefined deleted ................ KILLED  AnUndeclaredAckPolicyIsRejected
// A32-M17 PacingBurstDatagrams guard deleted ......... KILLED  APacingBurstOfNoDatagramsIs
//         Rejected
//
// -- the draw -- 4 rows --------------------------------------------------------------
// A32-M18 DrawInitialRtt reads kInitialRtt uncondition KILLED  DrawInitialRttReadsTheSpecs
//         -ally (`|| true`)                                    RangeAndFallsBackOnlyWhenThere
//                                                              IsNone
//         THE MUTANT THE PLAN NAMES FOR A3-2. It satisfies every arithmetic invariant task
//         A3-7 can state about a PTO, because 333 ms is an ordinary RTT; only a range that
//         EXCLUDES it catches it, and the shipped preset's 100-300 ms is such a range.
// A32-M19 DrawInitialRtt returns the range's minimum . KILLED  same (the two-halves assertion)
// A32-M20 the TimeSpan.MaxValue overflow guard deleted KILLED  DrawInitialRttAcceptsTheWidest
//         RangeTheSpecAllows
// A32-M21 the caller's Random ignored for the shared . KILLED  DrawInitialRttDrawsAfreshAnd
//         one                                                  DefaultsItsRandomSource
//         ALSO A NEAR-MISS. Nothing in the first draft observed this - every other assertion
//         about the draw is about its range or its spread, and both hold for either source.
//         The equally-seeded-sequences assertion was added for it.
//
// -- the store, and the connection spec's own setter -- 2 rows ------------------------
// A32-M22 a setter stores the default instead of the . KILLED  EveryKnobOnTheRecoverySpecIs
//         value it was given                                   ReadableAndSettable
// A32-M23 Recovery accepts null ...................... KILLED  TheConnectionSpecCarriesA
//         RecoverySpecAndRejectsANullOne
//
// -- the presets, each moved off the number the extract states -- 7 rows --------------
// A32-M24 kPacketThreshold 3 -> 4 .................... KILLED  TheDefaultsAreTheNumbersThe
//         ExtractStates
// A32-M25 kInitialWindow byte cap 14720 -> 14721 ..... KILLED  same
// A32-M26 kLossReductionFactor 0.5 -> 0.25 ........... KILLED  same
// A32-M27 kTimeThreshold 9/8 -> 5/4 .................. KILLED  same. THE PLAUSIBLE WRONG ONE:
//         s6.1.2's own note names 5/4 as TCP RACK's threshold, so this is the value a reader
//         working from memory would write.
// A32-M28 probes per PTO 2 -> 1 ...................... KILLED  same
// A32-M29 pacing burst derived from the MINIMUM window KILLED  same (s7.7 says the initial
//         rather than the initial one                          congestion window)
// A32-M30 kInitialRtt 333 ms -> 334 ms ............... KILLED  same
//
// -- the markers and the preset block -- 2 rows --------------------------------------
// A32-M31 the AckPolicy unverified marker deleted .... KILLED  EveryUnverifiedPresetChoice
//         NamesATaskThatExistsInTheAPlan
// A32-M32 a recovery number written outside the block  KILLED  NoRecoveryConstantLives
//         OutsideThePresetBlock

/// <summary>The loss-recovery and congestion-control values this client's behaviour is shaped
/// by: the timers that decide when a retransmission leaves, the window that decides how many
/// packets go out before the first acknowledgement, and the controller that shapes the send
/// rate under loss.</summary>
/// <remarks>
/// <para>ON <see cref="TlsQuicConnectionSpec"/> AND NOT ON <see cref="TlsQuicConnectionOptions"/>,
/// and that is the opposite of where a recovery implementer would reach.
/// <c>TlsQuicConnectionOptions</c>'s remarks state the rule in one sentence: "Neither timeout
/// below is a fingerprint knob: they gate when this client gives up and change no byte a peer
/// or an observer sees. Layout knobs live on <c>TlsQuicConnectionSpec</c> and nowhere else."
/// Every value here changes what an observer sees, so every value here is on the spec, beside
/// <c>PaddingTarget</c> and <c>InitialRttRange</c> - even though none of it is "layout" in the
/// ordinary sense. A maximum probe count before abandoning the connection would go the other
/// way, and there is no such member here.</para>
/// <para>TWO OF THE FOURTEEN KNOBS ARE NOT RE-DECLARED HERE, and both omissions are load-bearing
/// rather than oversights. <see cref="TlsQuicConnectionSpec.InitialRttRange"/> is knob 1 and
/// already ships, populated and advertised as transport parameter 12583 by
/// <see cref="TlsQuicTransportParameterSpec"/>; a second initial-RTT number here would be a
/// second place to keep in step with an advertisement, which is exactly the defect
/// <c>TlsQuicConnectionSpec.LocalFlowControl</c>'s remarks record from the six flow-control
/// values. <see cref="TlsQuicConnectionSpec.AckRangeLimit"/> is knob 13 and is wired to
/// <see cref="TlsQuicAckTracker"/>. So the count reconciles as 12 members here + 2 already on
/// the connection spec = 14, and
/// TlsQuicRecoverySpecTests.EveryKnobInThePlansTableIsReachableFromTheConnectionSpec derives all
/// three numbers rather than asserting the total beside them.</para>
/// <para>NO BEHAVIOUR. Nothing under <c>src/</c> reads any member of this type yet; tasks A3-3
/// through A3-11 wire them one at a time, and task A3-12 renders them. Saying so is the point -
/// the task-4b amendment already ruled that "a knob that accepts a value and ignores it is
/// worse than an absent one", and the answer there was the same as here: record the debt
/// where it will be found rather than let it be rediscovered. The check is one grep,
/// <c>Spec\.Recovery</c>.</para>
/// <para>VALIDATED AS SET, like every other knob under this spec, so a spec that exists is a
/// spec in range and no later task has to re-check one. Every rejecting branch below has a
/// test naming the input that reaches it.</para>
/// </remarks>
internal sealed class TlsQuicRecoverySpec
{
    // ------------------------------------------------------------------------------
    // THE PRESET BLOCK. Every numeric recovery value in this file is below this line and
    // above the "END OF THE PRESET BLOCK" marker; outside it the only numeric literals in
    // code are 0 and 1.
    // ------------------------------------------------------------------------------

    /// <summary>RFC 9002's <c>kInitialRtt</c>: the round-trip time used before a sample
    /// exists, and the fallback when <see cref="TlsQuicConnectionSpec.InitialRttRange"/> names
    /// none.</summary>
    /// <remarks>
    /// <para>A SHOULD WITH A CONDITION ON IT, NOT A FIXED CONSTANT, and the condition is the
    /// reason a spec-supplied initial RTT is conforming rather than a deviation.
    /// rfc9002-section6.2-probe-timeout.txt lines 111-116: "Resumed connections over the same
    /// network MAY use the previous connection's final smoothed RTT value as the resumed
    /// connection's initial RTT. <b>When no previous RTT is available</b>, the initial RTT
    /// SHOULD be set to 333 milliseconds. This results in handshakes starting with a PTO of 1
    /// second, as recommended for TCP's initial RTO." Appendix A.2 states the same value as a
    /// constant - rfc9002-appendix-a-and-b-pseudocode-and-constants.txt lines 90-91,
    /// "kInitialRtt: The RTT used before an RTT sample is taken. The value recommended in
    /// Section 6.2.2 is 333 ms" - and the prose is the one carrying the condition.</para>
    /// <para>SO THIS IS THE FALLBACK ARM AND NOT THE DEFAULT ARM. See
    /// <see cref="DrawInitialRtt(TlsQuicConnectionSpec, Random?)"/>.</para>
    /// </remarks>
    internal static readonly TimeSpan KInitialRtt = TimeSpan.FromMilliseconds(333);

    /// <summary>RFC 9002 s7.2's initial congestion window, as a multiple of the maximum
    /// datagram size.</summary>
    /// <remarks>
    /// <para>rfc9002-section7-congestion-control.txt lines 62-68: "QUIC begins every connection
    /// in slow start with the congestion window set to an initial value. Endpoints SHOULD use
    /// an initial congestion window of ten times the maximum datagram size
    /// (max_datagram_size), while limiting the window to the larger of 14,720 bytes or twice
    /// the maximum datagram size."</para>
    /// <para>UNVERIFIED, settled by task A3-14. Ten is what RFC 9002 recommends and it is not
    /// evidence about Chromium, which is free to use any window and is not obliged to follow
    /// a SHOULD. This is the knob the A3 plan calls the boundary the two-datagram Initial
    /// flight already sits at, so a capture that counts datagrams before the first
    /// acknowledgement would settle it.</para>
    /// </remarks>
    internal const int KInitialWindowDatagrams = 10;

    /// <summary>RFC 9002 s7.2's byte floor on the cap applied to the initial congestion
    /// window: the window is limited to the larger of this and twice the maximum datagram
    /// size.</summary>
    /// <remarks>rfc9002-section7-congestion-control.txt lines 64-68, quoted on
    /// <see cref="KInitialWindowDatagrams"/>, with the RFC's own reason at lines 68-71: "This
    /// follows the analysis and recommendations in [RFC6928], increasing the byte limit to
    /// account for the smaller 8-byte overhead of UDP compared to the 20-byte overhead for
    /// TCP."</remarks>
    internal const int KInitialWindowByteCap = 14720;

    /// <summary>RFC 9002 s7.2's minimum congestion window, as a multiple of the maximum
    /// datagram size.</summary>
    /// <remarks>rfc9002-section7-congestion-control.txt lines 83-86: "The minimum congestion
    /// window is the smallest value the congestion window can attain in response to loss, an
    /// increase in the peer-reported ECN-CE count, or persistent congestion. The RECOMMENDED
    /// value is 2 * max_datagram_size."</remarks>
    internal const int KMinimumWindowDatagrams = 2;

    /// <summary>RFC 9002's <c>kLossReductionFactor</c>.</summary>
    /// <remarks>THE NUMERAL IS IN APPENDIX B.1 AND NOWHERE ELSE, which is why this cites
    /// Appendix B rather than s7.3.2. rfc9002-appendix-a-and-b-pseudocode-and-constants.txt
    /// lines 477-480: "kLossReductionFactor: Scaling factor applied to reduce the congestion
    /// window when a new loss event is detected. Section 7 recommends a value of 0.5."
    /// Section 7.3.2 states the same rule in words and never writes the number -
    /// rfc9002-section7-congestion-control.txt lines 142-144: "On entering a recovery period,
    /// a sender MUST set the slow start threshold to half the value of the congestion window
    /// when loss is detected."</remarks>
    internal const double KLossReductionFactor = 0.5;

    /// <summary>The largest <see cref="LossReductionFactor"/> this spec accepts: a factor
    /// above one would grow the congestion window on loss, which is not a reduction.</summary>
    internal const double MaximumLossReductionFactor = 1.0;

    /// <summary>RFC 9002's <c>kPacketThreshold</c>.</summary>
    /// <remarks>rfc9002-section6-loss-detection.txt lines 60-65: "The RECOMMENDED initial
    /// value for the packet reordering threshold (kPacketThreshold) is 3, based on best
    /// practices for TCP loss detection [RFC5681] [RFC6675]. In order to remain similar to
    /// TCP, implementations SHOULD NOT use a packet threshold less than 3; see [RFC5681]."
    /// A SHOULD NOT, so a smaller threshold is accepted here rather than rejected - lines
    /// 67-74 name adaptive thresholds as a thing implementations do.</remarks>
    internal const int KPacketThreshold = 3;

    /// <summary>RFC 9002's <c>kTimeThreshold</c>, the 9/8 of s6.1.2, written as the division
    /// rather than as 1.125 so that the extract's own numerals appear here.</summary>
    /// <remarks>rfc9002-section6-loss-detection.txt lines 100-102: "The RECOMMENDED time
    /// threshold (kTimeThreshold), expressed as an RTT multiplier, is 9/8. The RECOMMENDED
    /// value of the timer granularity (kGranularity) is 1 millisecond." The granularity is
    /// deliberately NOT a knob in this file: the A3 plan's fixed table calls it a platform
    /// timer-resolution floor, and a knob for it would express what clock the machine
    /// has.</remarks>
    internal const double KTimeThreshold = 9.0 / 8.0;

    /// <summary>RFC 9002's <c>kPersistentCongestionThreshold</c>.</summary>
    /// <remarks>rfc9002-section7-congestion-control.txt lines 231-233: "The RECOMMENDED value
    /// for kPersistentCongestionThreshold is 3, which results in behavior that is
    /// approximately equivalent to a TCP sender declaring an RTO after two TLPs." Appendix
    /// B.1 agrees at lines 481-484.</remarks>
    internal const int KPersistentCongestionThreshold = 3;

    /// <summary>The factor a probe timeout's period is multiplied by each time the timer
    /// expires.</summary>
    /// <remarks>rfc9002-section6.2-probe-timeout.txt lines 81-83: "When a PTO timer expires,
    /// the PTO backoff MUST be increased, resulting in the PTO period being set to twice its
    /// current value." A MUST on the increase; the factor two is the increase the sentence
    /// names.</remarks>
    internal const double DefaultPtoBackoffFactor = 2.0;

    /// <summary>The smallest <see cref="PtoBackoff"/> factor this spec accepts. A factor below
    /// one would shrink the probe timeout on each expiry, which is a decrease rather than the
    /// increase s6.2.1 requires.</summary>
    internal const double MinimumPtoBackoffFactor = 1.0;

    /// <summary>How many ack-eliciting packets leave when a probe timeout expires.</summary>
    /// <remarks>rfc9002-section6.2-probe-timeout.txt lines 187-192: "When a PTO timer expires,
    /// a sender MUST send at least one ack-eliciting packet in the packet number space as a
    /// probe. An endpoint MAY send up to two full-sized datagrams containing ack-eliciting
    /// packets to avoid an expensive consecutive PTO expiration due to a single lost datagram
    /// or to transmit data from multiple packet number spaces." Two is the default here rather
    /// than the floor of one because lines 227-230 state the reason in the RFC's own voice:
    /// "Sending two packets on PTO expiration increases resilience to packet drops, thus
    /// reducing the probability of consecutive PTO events."</remarks>
    internal const int DefaultProbePacketsPerPto = 2;

    /// <summary>The most probe packets s6.2.4 permits per expiry: "up to two full-sized
    /// datagrams", rfc9002-section6.2-probe-timeout.txt line 188.</summary>
    internal const int MaximumProbePacketsPerPto = 2;

    /// <summary>The burst this client's pacer allows, in datagrams.</summary>
    /// <remarks>
    /// <para>rfc9002-section7-congestion-control.txt lines 336-345: "A sender SHOULD pace
    /// sending of all in-flight packets based on input from the congestion controller. ...
    /// Senders MUST either use pacing or limit such bursts. Senders SHOULD limit bursts to the
    /// initial congestion window; see Section 7.2. A sender with knowledge that the network
    /// path to the receiver can absorb larger bursts MAY use a higher limit." So the burst
    /// defaults to the initial congestion window, which is why this is written as
    /// <see cref="KInitialWindowDatagrams"/> rather than as its own numeral.</para>
    /// <para>UNVERIFIED, settled by task A3-14. That Chromium paces at all is a widely
    /// repeated claim this project has not measured, and the burst size is not bounded by
    /// anything in the capture. A capture showing the spacing of a window's worth of datagrams
    /// would settle both halves at once.</para>
    /// </remarks>
    internal const int DefaultPacingBurstDatagrams = KInitialWindowDatagrams;

    /// <summary>RFC 9002 s7.7's <c>N</c>: the factor the paced rate is multiplied by, and the
    /// divisor of the inter-packet interval.</summary>
    /// <remarks>
    /// <para>rfc9002-section7-congestion-control.txt lines 361-371, which is the whole of the
    /// arithmetic s7.7 publishes: "rate = N * congestion_window / smoothed_rtt. Or expressed
    /// as an inter-packet interval in units of time: interval = ( smoothed_rtt * packet_size /
    /// congestion_window ) / N. Using a value for "N" that is small, but at least 1 (for
    /// example, 1.25) ensures that variations in RTT do not result in underutilization of the
    /// congestion window."</para>
    /// <para>1.25 IS THE RFC'S OWN PARENTHETICAL AND NOTHING STRONGER. s7.7 gives it as an
    /// example inside a sentence whose only constraint is "small, but at least 1" - there is no
    /// SHOULD attached to the number and no other value is named. It is the shipped default
    /// because a default has to be something and this is the only figure the document prints;
    /// it is not a measurement.</para>
    /// <para>WHY IT IS A KNOB AT ALL, AND WHY IT IS A SEPARATE ONE FROM
    /// <see cref="DefaultPacingBurstDatagrams"/>. The burst decides how many datagrams may
    /// leave back to back; this decides how fast the allowance refills, which is the SPACING
    /// between one burst and the next. Two clients with the same burst and different N put the
    /// same number of datagrams on the wire with visibly different gaps, and the gap is exactly
    /// what a pcap measures. Without this member the spacing would be derived entirely from the
    /// congestion window and the RTT - neither of which a caller sets directly - so pacing would
    /// have an off switch and a burst size and no way at all to say how fast to pace.</para>
    /// <para>UNVERIFIED, settled by task A3-14, for the same reason and by the same capture as
    /// <see cref="DefaultPacingBurstDatagrams"/>.</para>
    /// </remarks>
    internal const double DefaultPacingIntervalScale = 1.25;

    // END OF THE PRESET BLOCK.

    private readonly (int DatagramMultiplier, int ByteCap) _initialCongestionWindow =
        (KInitialWindowDatagrams, KInitialWindowByteCap);
    private readonly int _minimumCongestionWindowDatagrams = KMinimumWindowDatagrams;
    private readonly double _lossReductionFactor = KLossReductionFactor;
    private readonly int _packetThreshold = KPacketThreshold;
    private readonly double _timeThreshold = KTimeThreshold;
    private readonly int _persistentCongestionThreshold = KPersistentCongestionThreshold;
    private readonly (double Factor, TimeSpan? Maximum) _ptoBackoff =
        (DefaultPtoBackoffFactor, null);
    private readonly int _probePacketsPerPto = DefaultProbePacketsPerPto;

    // KNOB 11'S SHIPPED DEFAULT, AND IT WAS `Ping` UNTIL TASK A3-14 MEASURED WHAT THAT COSTS.
    //
    // THE MEASUREMENT, from task A3-13's live run under induced loss -
    // docs/superpowers/specs/reference-captures/2026-08-22-sharptls-a3-13-live-run-under-
    // induced-loss.md, finding 2. Its two DROP_OPENING_* arms drop the ClientHello and differ
    // in this initialiser and nothing else, same host, same minute, 4 attempts per cell:
    //
    //                            fp.impersonate.pro   tls3.peet.ws
    //     ProbeContents = Ping           0/4              4/4
    //     ProbeContents = RetransmittedData
    //                                    4/4              4/4
    //
    // Against fp.impersonate.pro all four `Ping` attempts ended in the PEER's
    // CONNECTION_CLOSE with error 0x0a, PROTOCOL_VIOLATION (RFC 9000 s20.1). The capture
    // records `discarded=0`, `idle_timed_out=False`, `initial_datagrams=3`: by this project's
    // own classifier that is neither loss nor a flake, it is the probe. tls3.peet.ws ACKs the
    // identical probe. THE TWO ENDPOINTS DISAGREE AND THE DISAGREEMENT IS NOT TO BE AVERAGED.
    //
    // WHAT THE RFC ACTUALLY PERMITS, WHICH IS NOT WHAT THE FAILURE LOOKS LIKE. A PING-only
    // client Initial IS LEGAL, and the fix below is NOT an accommodation of one strict server.
    // Three citations, because the tempting diagnosis is wrong twice over:
    //
    //   * rfc9002-section6.2-probe-timeout.txt lines 180-183 names this exact packet as an
    //     example of correct behaviour: "a client can coalesce an Initial packet containing
    //     PING and PADDING frames with a 0-RTT data packet". A client Initial carrying PING
    //     and PADDING and no CRYPTO is the construction the RFC itself writes down.
    //   * RFC 9000 s12.4 Table 3 gives PING the row "IH01" - legal in every space, Initial
    //     included. s19.2: "The receiver of this frame simply needs to acknowledge it."
    //   * AND THE SIZE RULE WAS ALREADY MET, so s8.1 is not the violation either.
    //     rfc9000-section8-address-validation-and-amplification.txt lines 43-44 - "Clients
    //     MUST ensure that UDP datagrams containing Initial packets have UDP payloads of at
    //     least 1200 bytes, adding PADDING frames as necessary" - and lines 55-59 repeat it
    //     for the PTO case specifically. TlsQuicDatagramBuilder.BuildDatagram expands the last
    //     packet of any Initial-carrying datagram out to TlsQuicConnectionSpec.PaddingTarget,
    //     whose floor is s14.1's 1200, so the rejected probe was a full 1200 bytes. The
    //     capture's own words are "PING and PADDING and no CRYPTO". fp.impersonate.pro is
    //     therefore being STRICTER THAN RFC 9000 REQUIRES, and s14.1 lines 59-60 even tell it
    //     not to be: "an endpoint MUST NOT close a connection when it receives a datagram that
    //     does not meet size constraints".
    //
    // SO WHY CHANGE THE DEFAULT AT ALL? BECAUSE s6.2.4 ORDERS THE THREE CHOICES AND `Ping` IS
    // THE LAST ONE, which is a defect in this default independent of any server. Lines 205-206:
    // "An endpoint SHOULD include new data in packets that are sent on PTO expiration.
    // Previously sent data MAY be sent if no new data can be sent." Lines 211-217 then scope
    // the PING to one case in its own sentence: "It is possible the sender has no new or
    // previously sent data to send ... WHEN THERE IS NO DATA TO SEND, the sender SHOULD send a
    // PING or other ack-eliciting frame in a single packet."
    //
    // `Ping` as the DEFAULT made this client take that fallback branch UNCONDITIONALLY -
    // including in the failing scenario, where it was holding unacknowledged Initial CRYPTO and
    // so plainly did have previously sent data. It never satisfied the SHOULD at line 205 and
    // never took the MAY at line 206. That is the correctness defect; PROTOCOL_VIOLATION is
    // only the symptom that made it visible, and it stayed invisible for as long as this client
    // met tolerant servers only.
    //
    // `RetransmittedData` IS s6.2.4'S WHOLE ALGORITHM RATHER THAN ITS LAST BRANCH, which is why
    // it is the default and not merely the value that passes. TlsQuicConnection's
    // TryBuildProbeDatagram keeps the PING in front of the repair and AppendProbeData may
    // decline to add anything, so when there is genuinely nothing owed and nothing retained
    // this arm emits EXACTLY `Ping`'s bytes - lines 215-217's fallback, reached the way the
    // section reaches it instead of being hardwired as the only behaviour.
    //
    // `Ping` REMAINS SELECTABLE AND THAT IS DELIBERATE, per the user's standing directive that
    // this library reproduce arbitrary clients: "everything must be configurable if different
    // clients/browsers/apps/systems could send a different value". A probe's size and frames
    // are both observable - the size without decrypting anything - so a client that really does
    // send a bare PING is a fingerprint this library must be able to wear. WHAT IT COSTS, now
    // witnessed rather than assumed: a PING repairs nothing by itself (s13.3: "PING and PADDING
    // frames contain no information"), so a flight that only a probe can repair never completes
    // (TlsQuicConnectionTests.APingOnlyProbeCarriesNoRepairAndLeavesTheServerWaiting), and at
    // least one production server answers it with PROTOCOL_VIOLATION and closes.
    //
    // THIS CHANGES NO UNIMPAIRED BYTE. TryBuildProbeDatagram is the only reader of this knob
    // and runs only on a PTO expiry; the capture's CONTROL arm reports probes=0 on all 8
    // unimpaired attempts. Pinned by TheProbeContentsDefaultChangesNothingOnAnUnimpairedPath.
    private readonly TlsQuicProbeContents _probeContents = TlsQuicProbeContents.RetransmittedData;
    private readonly TlsQuicAckPolicy _ackPolicy = TlsQuicAckPolicy.Immediate;
    private readonly int? _pacingBurstDatagrams = DefaultPacingBurstDatagrams;
    private readonly double _pacingIntervalScale = DefaultPacingIntervalScale;

    /// <summary>Knob 2. Gets RFC 9002 s7.2's initial congestion window, expressed the way the
    /// section expresses it: a multiple of the maximum datagram size, and a byte floor on the
    /// cap that multiple is limited to.</summary>
    /// <remarks>
    /// <para>ONE MEMBER FOR ONE KNOB, because s7.2 states one rule -
    /// <c>min(DatagramMultiplier * mds, max(ByteCap, 2 * mds))</c> - and splitting it into two
    /// properties would let a caller set half of it. See
    /// <see cref="KInitialWindowDatagrams"/> and <see cref="KInitialWindowByteCap"/> for the
    /// quotation.</para>
    /// <para>UNVERIFIED, settled by task A3-14, for both halves. Ten and 14,720 are what RFC
    /// 9002 s7.2 recommends and neither is evidence about Chromium, which is free to use any
    /// window and is not obliged to follow a SHOULD.</para>
    /// <para>THE MAXIMUM DATAGRAM SIZE IS NOT A MEMBER OF THIS TYPE. It is the connection's,
    /// and <c>TlsQuicConnectionSpec.PaddingTarget</c> together with path MTU already decide
    /// it; a second copy here would be a second source of truth for one number.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">The datagram multiplier is not positive,
    /// or the byte cap is negative.</exception>
    public (int DatagramMultiplier, int ByteCap) InitialCongestionWindow
    {
        get => _initialCongestionWindow;
        init
        {
            // A multiplier of zero is a connection that may never send its first packet, so
            // the floor is one rather than zero. The byte cap may legitimately be zero - s7.2
            // limits to the LARGER of it and twice the datagram size, so a zero cap simply
            // means "twice the datagram size" - and only a negative is meaningless.
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
                value.DatagramMultiplier, nameof(InitialCongestionWindow));
            ArgumentOutOfRangeException.ThrowIfNegative(
                value.ByteCap, nameof(InitialCongestionWindow));
            _initialCongestionWindow = value;
        }
    }

    /// <summary>Knob 3. Gets RFC 9002 s7.2's minimum congestion window, as a multiple of the
    /// maximum datagram size: the floor the window settles at on a heavily lossy path, and
    /// therefore the steady-state send rate an observer of such a path measures.</summary>
    /// <remarks>See <see cref="KMinimumWindowDatagrams"/> for the quotation.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not positive. A floor of zero is a
    /// connection that can never recover from one loss.</exception>
    public int MinimumCongestionWindowDatagrams
    {
        get => _minimumCongestionWindowDatagrams;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
                value, nameof(MinimumCongestionWindowDatagrams));
            _minimumCongestionWindowDatagrams = value;
        }
    }

    /// <summary>Knob 4. Gets the congestion controller this client runs, as a factory called
    /// once per connection.</summary>
    /// <remarks>
    /// <para>THE LARGEST SINGLE FINGERPRINT IN LOSS RECOVERY. Read
    /// <see cref="ITlsQuicCongestionController"/>'s remarks first: RFC 9002 s7 specifies
    /// NewReno and explicitly permits a sender to run something else, Chromium is said to run
    /// BBR, and the two produce visibly different send-rate curves in a single recovery
    /// episode.</para>
    /// <para>A FACTORY AND NOT AN INSTANCE, because a controller is per-connection mutable
    /// state and a spec is meant to be reused across connections. That is the same reason
    /// <c>TlsQuicTransportParameterSlot.Drawn</c> carries a function rather than bytes, and
    /// the failure mode is the same one: an instance pinned into a spec would carry one
    /// connection's congestion window into the next.</para>
    /// <para>UNVERIFIED, settled by task A3-14. <see langword="null"/> - the shipped default -
    /// means the NewReno controller RFC 9002 s7 specifies, which task A3-9 supplies; nothing
    /// this project can currently observe says whether that is what Chromium runs, and the
    /// A3 plan records that it very probably is not.</para>
    /// </remarks>
    public Func<ITlsQuicCongestionController>? CongestionController { get; init; }

    /// <summary>Knob 5. Gets RFC 9002's <c>kLossReductionFactor</c>: the fraction the
    /// congestion window is scaled by when a loss event is detected.</summary>
    /// <remarks>NewReno halves; a controller that does not halve - BBR does not - diverges
    /// from this within one recovery episode, which is why the factor is observable
    /// separately from <see cref="CongestionController"/>. See
    /// <see cref="KLossReductionFactor"/> for the quotation and for which of the two places
    /// RFC 9002 states it in was cited.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not a finite number, not positive, or
    /// above <see cref="MaximumLossReductionFactor"/>.</exception>
    public double LossReductionFactor
    {
        get => _lossReductionFactor;
        init
        {
            // FINITENESS IS CHECKED FIRST AND EXPLICITLY, and the case it exists for is
            // narrower and stranger than "NaN". Every comparison against a NaN is false, so
            // ThrowIfGreaterThan never rejects one; ThrowIfNegativeOrZero rejects SOME of
            // them, because it tests the sign bit rather than a comparison and .NET's
            // double.NaN literal happens to have that bit SET. A NaN with the bit clear
            // passes every guard below and would reach the congestion controller as a factor
            // that turns the window into NaN on the first loss. Witnessed by
            // TlsQuicRecoverySpecTests.APositiveNotANumberIsRejectedByEveryFloatingPointKnob,
            // which a mutation sweep is what forced: deleting this line survived a suite
            // whose only NaN was the negative literal.
            ThrowIfNotFinite(value, nameof(LossReductionFactor));
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
                value, nameof(LossReductionFactor));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                value, MaximumLossReductionFactor, nameof(LossReductionFactor));
            _lossReductionFactor = value;
        }
    }

    /// <summary>Knob 6. Gets RFC 9002's <c>kPacketThreshold</c>: how many packets may be
    /// acknowledged after an unacknowledged one before it is declared lost.</summary>
    /// <remarks>This is the reordering tolerance, and it decides whether a reordered packet
    /// triggers a retransmission at all - so two clients with different thresholds emit
    /// different numbers of packets on the same reordering path. See
    /// <see cref="KPacketThreshold"/> for the quotation, including why s6.1.1's "SHOULD NOT
    /// use a packet threshold less than 3" is not enforced as a bound here.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not positive. A threshold of zero
    /// declares a packet lost before any later packet has been acknowledged.</exception>
    public int PacketThreshold
    {
        get => _packetThreshold;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value, nameof(PacketThreshold));
            _packetThreshold = value;
        }
    }

    /// <summary>Knob 7. Gets RFC 9002's <c>kTimeThreshold</c>: the same reordering tolerance
    /// as <see cref="PacketThreshold"/>, on the time axis, expressed as an RTT
    /// multiplier.</summary>
    /// <remarks>See <see cref="KTimeThreshold"/> for the quotation, and for why
    /// <c>kGranularity</c> - which floors the threshold s6.1.2 computes from this multiplier -
    /// is not a knob.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not a finite number, or not
    /// positive.</exception>
    public double TimeThreshold
    {
        get => _timeThreshold;
        init
        {
            ThrowIfNotFinite(value, nameof(TimeThreshold));
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value, nameof(TimeThreshold));
            _timeThreshold = value;
        }
    }

    /// <summary>Knob 8. Gets RFC 9002's <c>kPersistentCongestionThreshold</c>: how many probe
    /// timeout periods a blackout must last before the congestion window collapses to
    /// <see cref="MinimumCongestionWindowDatagrams"/>.</summary>
    /// <remarks>See <see cref="KPersistentCongestionThreshold"/> for the quotation. The
    /// duration FORMULA this multiplies is not a knob - the A3 plan's fixed table says so -
    /// and only the multiplier varies.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not positive.</exception>
    public int PersistentCongestionThreshold
    {
        get => _persistentCongestionThreshold;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
                value, nameof(PersistentCongestionThreshold));
            _persistentCongestionThreshold = value;
        }
    }

    /// <summary>Knob 9. Gets the exponential shape of the probe timeout: the factor the period
    /// is multiplied by on each expiry, and the ceiling it stops growing at.</summary>
    /// <remarks>
    /// <para>ONE MEMBER FOR ONE KNOB, because the two halves are one behaviour: two clients
    /// with the same factor and different ceilings are indistinguishable until the ceiling
    /// binds, and the A3 plan's row says they diverge by the third probe.</para>
    /// <para>THE FACTOR IS CITED AND THE CEILING IS NOT, and the asymmetry is real rather than
    /// an omission. RFC 9002 s6.2.1 states the doubling as a MUST - see
    /// <see cref="DefaultPtoBackoffFactor"/> - and never mentions a ceiling at all, so
    /// <see langword="null"/>, meaning "no ceiling", is what the RFC describes. A ceiling is an
    /// implementation choice a caller may take, and taking one is not a deviation from
    /// anything RFC 9002 says.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">The factor is not a finite number or is
    /// below <see cref="MinimumPtoBackoffFactor"/>, or the ceiling is present and not
    /// positive.</exception>
    public (double Factor, TimeSpan? Maximum) PtoBackoff
    {
        get => _ptoBackoff;
        init
        {
            ThrowIfNotFinite(value.Factor, nameof(PtoBackoff));
            ArgumentOutOfRangeException.ThrowIfLessThan(
                value.Factor, MinimumPtoBackoffFactor, nameof(PtoBackoff));
            if (value.Maximum is { } maximum)
            {
                ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(
                    maximum, TimeSpan.Zero, nameof(PtoBackoff));
            }

            _ptoBackoff = value;
        }
    }

    /// <summary>Knob 10. Gets how many ack-eliciting packets leave when a probe timeout
    /// expires.</summary>
    /// <remarks>Byte-countable by anyone watching the connection stall and resume. See
    /// <see cref="DefaultProbePacketsPerPto"/> for the quotation, and for why the default is
    /// the RFC's recommended two rather than its required floor of one.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not positive - s6.2.4 requires at least
    /// one - or above <see cref="MaximumProbePacketsPerPto"/>, which is the "up to two" the
    /// same sentence permits.</exception>
    public int ProbePacketsPerPto
    {
        get => _probePacketsPerPto;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
                value, nameof(ProbePacketsPerPto));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                value, MaximumProbePacketsPerPto, nameof(ProbePacketsPerPto));
            _probePacketsPerPto = value;
        }
    }

    /// <summary>Knob 11. Gets what this client puts in a probe packet. Defaults to
    /// <see cref="TlsQuicProbeContents.RetransmittedData"/>.</summary>
    /// <remarks>
    /// <para>Observable twice over: the size of a probe datagram is visible without
    /// decrypting it, and its frames are visible to anyone holding the keys. See
    /// <see cref="TlsQuicProbeContents"/> for what s6.2.4 does and does not
    /// constrain.</para>
    /// <para>THE DEFAULT IS s6.2.4's FIRST CHOICE AND NOT ITS LAST. The section says an
    /// endpoint "SHOULD include new data in packets that are sent on PTO expiration",
    /// that "Previously sent data MAY be sent if no new data can be sent", and reserves the
    /// bare PING for "when there is no data to send".
    /// <see cref="TlsQuicProbeContents.Ping"/> shipped as the default until task A3-14 and
    /// took that fallback unconditionally; the field initialiser carries the live measurement
    /// that settled it, the RFC reading, and what selecting
    /// <see cref="TlsQuicProbeContents.Ping"/> still costs.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not a declared member of
    /// <see cref="TlsQuicProbeContents"/>.</exception>
    public TlsQuicProbeContents ProbeContents
    {
        get => _probeContents;
        init
        {
            // An enum is an integer in a hat: (TlsQuicProbeContents)9 is a legal cast and
            // would otherwise reach A3-7's switch as a case nothing handles.
            ThrowIfNotDefined(value, nameof(ProbeContents));
            _probeContents = value;
        }
    }

    /// <summary>Knob 12. Gets whether this client acknowledges immediately or holds
    /// acknowledgements back to the advertised <c>max_ack_delay</c>.</summary>
    /// <remarks>
    /// <para>Changes how many ACK packets this client emits and how they are spaced, both of
    /// which are countable off a capture without decrypting anything. See
    /// <see cref="TlsQuicAckPolicy"/> for why the delay itself is not a member of this
    /// type.</para>
    /// <para>READ BY SOMETHING SINCE A3-13, AND THIS PARAGRAPH IS THE ONLY PLACE THAT SAYS
    /// SO IN PROSE - which is deliberate, because prose is what decayed everywhere else in
    /// this tree. <c>TlsQuicAckTracker</c>'s constructor takes it, <c>TryBuildAck</c> obeys
    /// it, and <c>TlsQuicConnection.EarliestDeadline</c> races the instant it falls due;
    /// A3-12's readout row <c>ack_policy_in_force</c> re-establishes all of that BY
    /// MEASUREMENT on every run, so if this sentence ever goes stale the table says so
    /// without anyone having to notice this line.</para>
    /// <para>APPLIES TO 0-RTT AND 1-RTT AND TO NOTHING ELSE. RFC 9000 s13.2.1 puts both
    /// halves in one sentence: "An endpoint MUST acknowledge all ack-eliciting Initial and
    /// Handshake packets immediately and all ack-eliciting 0-RTT and 1-RTT packets within
    /// its advertised max_ack_delay". So <see cref="TlsQuicAckPolicy.DelayedToMaxAckDelay"/>
    /// leaves Initial and Handshake exactly where
    /// <see cref="TlsQuicAckPolicy.Immediate"/> leaves them - not as a conservatism, but
    /// because no setting of this knob is entitled to waive that MUST.</para>
    /// <para>UNVERIFIED, settled by task A3-14. <see cref="TlsQuicAckPolicy.Immediate"/> is
    /// the behaviour this client already has, not a measurement of Chromium's; the A3 plan
    /// records that Chromium does not acknowledge every 1-RTT packet immediately, and a
    /// capture counting ACK packets against data packets would settle it. WIRING IT DID NOT
    /// MEASURE IT, and the marker stays for exactly that reason: what A3-13 changed is that
    /// the answer is now settable, not that the answer is now known.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not a declared member of
    /// <see cref="TlsQuicAckPolicy"/>.</exception>
    public TlsQuicAckPolicy AckPolicy
    {
        get => _ackPolicy;
        init
        {
            ThrowIfNotDefined(value, nameof(AckPolicy));
            _ackPolicy = value;
        }
    }

    /// <summary>Knob 14. Gets the pacer's burst allowance in datagrams, or
    /// <see langword="null"/> for a sender that does not pace.</summary>
    /// <remarks>
    /// <para>ONE MEMBER FOR ONE KNOB, AND <see langword="null"/> IS THE OFF SWITCH. The A3
    /// plan's row is "pacing on/off, and the pacer's burst size", and a separate boolean would
    /// admit the meaningless state "pacing off, burst 10". s7.7 makes the two halves one
    /// choice in one sentence - see <see cref="DefaultPacingBurstDatagrams"/> - because a
    /// sender that does not pace is exactly a sender whose burst is unlimited.</para>
    /// <para>UNVERIFIED, settled by task A3-14, for both halves at once. See
    /// <see cref="DefaultPacingBurstDatagrams"/>.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Present and not positive. A burst of zero
    /// datagrams is a sender that may never send.</exception>
    public int? PacingBurstDatagrams
    {
        get => _pacingBurstDatagrams;
        init
        {
            if (value is { } burst)
            {
                ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
                    burst, nameof(PacingBurstDatagrams));
            }

            _pacingBurstDatagrams = value;
        }
    }

    /// <summary>Knob 15. Gets RFC 9002 s7.7's <c>N</c>: how fast the pacer's allowance refills,
    /// which is the SPACING between the datagrams <see cref="PacingBurstDatagrams"/> sizes.
    /// </summary>
    /// <remarks>
    /// <para>See <see cref="DefaultPacingIntervalScale"/> for the quotation, for why 1.25 is an
    /// example rather than a recommendation, and for why the spacing needs a member of its own
    /// rather than riding on the burst.</para>
    /// <para>IT IS KNOB 15 AND THE TABLE IS NOW FIFTEEN LONG. The A3 plan's knob table stops at
    /// 14 and its task A3-12 derives a 16-row readout from it - 14 knobs, plus the controller's
    /// identity, plus the ACK policy. That arithmetic becomes 15 + 2 = 17 with this member, and
    /// it is written here rather than left for the readout to discover, because the plan's own
    /// Finding 10 rule is that growing the table must keep the arithmetic line reconciling.
    /// The plan's row 14 reads "pacing on/off, and the burst size" and this is neither of those
    /// two things; folding it into row 14 would have been the cheaper edit and a false one.
    /// </para>
    /// <para>NO EFFECT WHEN <see cref="PacingBurstDatagrams"/> IS <see langword="null"/>, which
    /// is not a contradiction of the one-member-per-knob rule but its consequence: an off pacer
    /// has no rate, and a caller who sets a scale and no burst has asked for a spacing on a
    /// sender that does not space. That combination is accepted rather than rejected - it is
    /// two independent settings, and refusing it would make the order in which a caller writes
    /// two initialisers matter.</para>
    /// <para>UNVERIFIED, settled by task A3-14. See
    /// <see cref="DefaultPacingIntervalScale"/>.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Not a finite number, or not positive. A
    /// scale of zero is a rate of zero, which is a pacer that never releases anything.
    /// </exception>
    public double PacingIntervalScale
    {
        get => _pacingIntervalScale;
        init
        {
            ThrowIfNotFinite(value, nameof(PacingIntervalScale));
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
                value, nameof(PacingIntervalScale));
            _pacingIntervalScale = value;
        }
    }

    /// <summary>Knob 1, and it is deliberately a method rather than a property: the initial
    /// round-trip time this connection starts with, taken from
    /// <see cref="TlsQuicConnectionSpec.InitialRttRange"/> when that names a range and from
    /// <see cref="KInitialRtt"/> only when it does not.</summary>
    /// <remarks>
    /// <para>THE INITIAL RTT IS NOT A CONSTANT AND THIS PROJECT ALREADY OWNS THE KNOB.
    /// <see cref="TlsQuicConnectionSpec.InitialRttRange"/> ships populated, and
    /// <see cref="TlsQuicTransportParameterSpec"/> advertises a draw from it as Google-private
    /// transport parameter 12583. A second initial-RTT number on this type would be a second
    /// place to keep in step with an advertisement - the exact defect
    /// <c>TlsQuicConnectionSpec.LocalFlowControl</c>'s remarks record from the six
    /// flow-control values - so there is no such member and this method reads the existing one
    /// instead.</para>
    /// <para>A SPEC-SUPPLIED INITIAL RTT IS CONFORMING, and the reason is a condition inside
    /// the SHOULD rather than a liberty taken with it: s6.2.2's 333 ms applies "when no
    /// previous RTT is available", and a spec that names a range has made one available. See
    /// <see cref="KInitialRtt"/>.</para>
    /// <para>A DRAW AND NOT A MIDPOINT, because <see cref="TlsQuicConnectionSpec.InitialRttRange"/>
    /// is a range precisely so that two connections from one spec do not start with the same
    /// number - a pinned per-connection field is itself a fingerprint. The draw is uniform
    /// over ticks and inclusive of both bounds.</para>
    /// <para>AND A DIVERGENCE THE SHIPPED DEFAULTS CURRENTLY HAVE, recorded here rather than
    /// left to be rediscovered. <see cref="TlsQuicConnectionSpec.InitialRttRange"/> defaults
    /// to <see langword="null"/>, while the transport-parameter preset advertises
    /// <c>initial_rtt</c> drawn from
    /// <see cref="TlsQuicTransportParameterSpec.Brave151InitialRttRange"/> - 100 to 300 ms -
    /// because that entry declares its own fallback range for exactly the case where this
    /// property names none. So an unconfigured client ADVERTISES a number between 100 and
    /// 300 ms and, by the fallback arm below, would START from 333 ms. Both are legal and
    /// nothing observes the second yet, but they are two answers to one question, which is
    /// the shape of defect this project has already paid for once. A caller who cares sets
    /// <see cref="TlsQuicConnectionSpec.InitialRttRange"/>, which makes the two agree. The
    /// task that has to decide whether the default should agree by construction is A3-7,
    /// with A3-14's capture in hand.</para>
    /// <para>THE OPEN QUESTION THIS METHOD DOES NOT SETTLE, recorded because it inverts a
    /// dependency if it goes the other way: if Chromium's <c>initial_rtt</c> is derived from
    /// the path rather than drawn, then this value is A3's OUTPUT and the transport parameter
    /// should be composed from it rather than the reverse. Task A3-14's capture request asks
    /// for two connections to the same host in sequence, which is the one experiment that
    /// tells a draw from an estimate.</para>
    /// </remarks>
    /// <param name="connectionSpec">The connection spec whose
    /// <see cref="TlsQuicConnectionSpec.InitialRttRange"/> is read.</param>
    /// <param name="random">The source of the draw, or <see langword="null"/> for
    /// <see cref="Random.Shared"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="connectionSpec"/> is
    /// <see langword="null"/>.</exception>
    public static TimeSpan DrawInitialRtt(
        TlsQuicConnectionSpec connectionSpec,
        Random? random = null)
    {
        ArgumentNullException.ThrowIfNull(connectionSpec);
        if (connectionSpec.InitialRttRange is not { } range)
        {
            return KInitialRtt;
        }

        var minimumTicks = range.Minimum.Ticks;
        var maximumTicks = range.Maximum.Ticks;

        // NextInt64's upper bound is exclusive and the range's is inclusive, so the bound
        // passed is one tick past the maximum - except at TimeSpan.MaxValue, where that
        // increment would overflow to long.MinValue and NextInt64 would throw on a range the
        // spec accepts. There the largest single tick is excluded instead, which is the only
        // input on which this method is not exactly inclusive and is worth one branch to keep
        // "nothing on this path throws" true. The spec's own validation permits
        // (1 tick, TimeSpan.MaxValue), so the branch is reachable rather than defensive.
        var exclusiveUpperBound =
            maximumTicks == long.MaxValue ? long.MaxValue : maximumTicks + 1;
        return TimeSpan.FromTicks(
            (random ?? Random.Shared).NextInt64(minimumTicks, exclusiveUpperBound));
    }

    // Shared by the three floating-point guards, for the reason LossReductionFactor states at
    // length: a NaN whose sign bit is clear compares false against everything AND is not
    // negative, so no chain of ThrowIf* calls rejects it.
    private static void ThrowIfNotFinite(double value, string paramName)
    {
        if (!double.IsFinite(value))
        {
            throw new ArgumentOutOfRangeException(
                paramName, value, "A recovery factor must be a finite number.");
        }
    }

    // Shared by the two enum knobs, for the reason ProbeContents states.
    private static void ThrowIfNotDefined<T>(T value, string paramName)
        where T : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                value,
                $"Not a declared member of {typeof(T).Name}.");
        }
    }
}
