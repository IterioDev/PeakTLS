namespace SharpTls.Quic;

/// <summary>The three states RFC 9002 s7.3 Figure 1 gives the NewReno controller, and the
/// only NewReno-shaped thing this file puts on a property rather than behind the seam.
/// </summary>
/// <remarks>
/// <para>NOT ON <see cref="ITlsQuicCongestionController"/>, AND THAT IS THE POINT. "Slow
/// start", "recovery" and "congestion avoidance" are NewReno's own vocabulary -
/// rfc9002-section7-congestion-control.txt lines 90-91: "The NewReno congestion controller
/// described in this document has three distinct states". BBR's states are Startup, Drain,
/// ProbeBW and ProbeRTT and they are not these; CUBIC has no recovery period shaped like
/// this one. A seam that demanded this enum of every controller would be a seam that only
/// admits NewReno, which is exactly what the A3 plan says the controller seam must not be.
/// So this lives on <see cref="TlsQuicNewRenoCongestionController"/> and the interface
/// carries only the generic signals s7 says are generic.</para>
/// </remarks>
internal enum TlsQuicCongestionState
{
    /// <summary>RFC 9002 s7.3.1: the congestion window is below the slow start threshold, and
    /// each acknowledgement grows the window by the bytes it acknowledges.</summary>
    SlowStart,

    /// <summary>RFC 9002 s7.3.2: a recovery period is running. The window does not change in
    /// response to new losses while it does.</summary>
    Recovery,

    /// <summary>RFC 9002 s7.3.3: the window is at or above the slow start threshold and no
    /// recovery period is running.</summary>
    CongestionAvoidance,
}

/// <summary>RFC 9002 s7.6's persistent congestion: the duration s7.6.1 states as a formula, and
/// the predicate B.8 calls <c>InPersistentCongestion</c> and never defines.</summary>
/// <remarks>
/// <para>THIS TYPE EXISTS BECAUSE RFC 9002 STOPS HERE, TWICE OVER, AND A READER WHO GOES LOOKING
/// FOR THE MISSING HALF WILL NOT FIND IT. rfc9002-appendix-a-and-b-pseudocode-and-constants.txt
/// lines 21-28 list <c>InPersistentCongestion</c> among seven functions "called and never defined
/// anywhere in this document" - B.8 line 639 invokes it and no fragment supplies a body - and
/// lines 27-28 record separately that "Pacing (Section 7.7) and the persistent congestion duration
/// (Section 7.6.1) have" no pseudocode either. So both halves below are derived from prose, and
/// every step of the derivation is written out here rather than left for a reader to reconstruct,
/// because THERE IS NOTHING TO CHECK THE CODE AGAINST. Six transcription defects have already
/// been found in this subsystem where pseudocode DID exist; where it does not, the prose is the
/// only witness and the argument has to be legible.</para>
/// <para>STATIC AND NOT A MEMBER OF THE CONTROLLER, and not on the seam. s7.6.2's conditions are
/// about the TIMELINE - what was sent, what came back, and when - and are identical whether the
/// controller underneath is NewReno, CUBIC or BBR; only the response differs, and the response is
/// <see cref="ITlsQuicCongestionController.OnPersistentCongestion"/>. Putting the predicate on the
/// controller would oblige every replacement controller to re-derive prose that has nothing to do
/// with it, and would put the evidence and the verdict in the same place, which is how a
/// half-implemented predicate hides.</para>
/// <para>WHO CALLS IT. The sender, on the same acknowledgement that drove loss detection:
/// <c>controller.OnPacketsLost(lost)</c>, then this predicate, then
/// <c>controller.OnPersistentCongestion()</c> if it holds. That is B.8's own order - B.8 lines
/// 628-641 run the congestion event first and the collapse second - and the order matters, because
/// the congestion event opens a recovery period that the collapse then discards.</para>
/// </remarks>
internal static class TlsQuicPersistentCongestion
{
    /// <summary>RFC 9002 s7.6.1's persistent congestion duration.</summary>
    /// <remarks>
    /// <para>THE FORMULA, QUOTED WHOLE, because it is stated once in the document and nowhere
    /// transcribed. rfc9002-section7-congestion-control.txt lines 209-214:</para>
    /// <para><c>(smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay) *
    /// kPersistentCongestionThreshold</c></para>
    /// <para>DERIVATION, TERM BY TERM, AND WHY EACH TERM IS THE THING IT IS.</para>
    /// <para>1. THE PARENTHESISED BASE IS s6.2.1's PTO PERIOD WITH pto_count HELD AT ZERO. s6.2.1
    /// writes "PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay" and then doubles
    /// it per expiry; s7.6.1 writes the identical expression and multiplies by a CONSTANT
    /// instead. The difference is not decoration. s7.6.1 lines 236-242 say why in as many words:
    /// "This design does not use consecutive PTO events to establish persistent congestion, since
    /// application patterns impact PTO expiration ... The use of a duration enables a sender to
    /// establish persistent congestion without depending on PTO expiration." SO THE BACKOFF MUST
    /// NOT BE APPLIED HERE. Reusing <c>TlsQuicConnection.PtoDuration</c> - which does apply
    /// <c>PtoBackoff.Factor ^ pto_count</c>, and a ceiling, and s6.2.1's own kGranularity floor on
    /// the whole period - would make the blackout threshold grow with every probe the sender had
    /// already sent, so a sender several probes deep would need an ever longer blackout to notice
    /// one. That is the exact dependence on PTO expiration the paragraph forbids. This method is
    /// therefore a separate computation and not a call into that one, and the divergence is
    /// pinned by a test asserting both candidate numbers.</para>
    /// <para>2. max_ack_delay IS ADDED UNCONDITIONALLY, WHICH IS NOT WHAT s6.2.1 DOES. A.8 adds
    /// <c>max_ack_delay</c> for the Application Data space only, and
    /// <c>TlsQuicConnection.PtoDuration</c> is called with it for Application Data and with zero
    /// for Initial and Handshake, witnessed by
    /// <c>ThePeersMaxAckDelayIsAddedForApplicationDataAndNotForHandshake</c>. s7.6.1 lines 216-219
    /// overrule that here and say so explicitly: "Unlike the PTO computation in Section 6.2, this
    /// duration includes the max_ack_delay IRRESPECTIVE of the packet number spaces in which
    /// losses are established." Hence this method has no packet number space parameter at all -
    /// there is no space for which the term is dropped, so there is nothing to pass. A version
    /// that took a space and zeroed the term for two of them would shorten the blackout threshold
    /// by max_ack_delay for handshake losses and declare persistent congestion sooner than the
    /// document allows.</para>
    /// <para>3. THE kGranularity FLOOR IS ON <c>4*rttvar</c> ALONE, NOT ON THE SUM AND NOT ON THE
    /// PRODUCT. The parentheses in the quoted line put <c>max(...)</c> around the rttvar term
    /// only. s6.2.1 separately requires "The PTO period MUST be at least kGranularity" of ITS
    /// period; s7.6 states no such floor for this duration, and it needs none, because the floored
    /// term already makes the base at least kGranularity and the threshold is a positive integer.
    /// Applying a second floor to the product would be inventing a rule; applying the floor to the
    /// sum instead of the term would be the defect already found once in this subsystem at
    /// s6.2.1.</para>
    /// <para>4. kGranularity ITSELF IS READ FROM <see cref="TlsQuicConnection.KGranularity"/> AND
    /// NOT DECLARED AGAIN. That field's own comment records the debt - it belongs on
    /// <see cref="TlsQuicRecoverySpec"/> beside A.2's other seven constants and was put on the
    /// connection because A3-5 could not edit this seam's file - and says a later task "should
    /// move it rather than declare a second copy". A3-10 may not edit that file either, so it
    /// reads the one copy. TWO COPIES OF A TIMER GRANULARITY THAT DRIFTED APART WOULD BE INVISIBLE:
    /// both would be 1 ms today and the divergence would appear only in whichever knob a caller
    /// tuned.</para>
    /// <para>5. kPersistentCongestionThreshold IS KNOB 8 AND NOT THE LITERAL 3.
    /// s7.6.1 lines 231-233 make 3 a RECOMMENDED value - "The RECOMMENDED value for
    /// kPersistentCongestionThreshold is 3, which results in behavior that is approximately
    /// equivalent to a TCP sender declaring an RTO after two TLPs" - and lines 225-230 describe
    /// what moving it does in both directions, which is the definition of a knob. It is read from
    /// <see cref="TlsQuicRecoverySpec.PersistentCongestionThreshold"/>; no number in this method
    /// is a literal.</para>
    /// <para>ARITHMETIC IN DOUBLE TICKS, FOR THE REASON <c>TlsQuicConnection.PtoDuration</c> GIVES:
    /// every input here is peer-influenced or clock-influenced, and TimeSpan's own <c>*</c> and
    /// <c>+</c> operators THROW on overflow. A duration computed on the loss path must not be able
    /// to kill a connection with an <c>OverflowException</c> because a peer chose a large
    /// max_ack_delay.</para>
    /// <para>NEGATIVE INPUTS ARE CLAMPED TO ZERO RATHER THAN PROPAGATED, and this is a totality
    /// guard rather than a reading of the RFC - no RTT estimator produces one, and A3-4's cannot.
    /// It matters anyway because the failure is one-sided and catastrophic: a negative
    /// smoothed_rtt large enough to cancel the other terms would make the duration non-positive,
    /// every pair of losses would "exceed" it, and the window would collapse to the minimum on any
    /// loss at all. Clamping keeps the base at or above kGranularity for every input.</para>
    /// </remarks>
    /// <param name="spec">The recovery spec carrying knob 8.</param>
    /// <param name="smoothedRtt">RFC 9002 s5.3's <c>smoothed_rtt</c>, from A3-4's estimator.</param>
    /// <param name="rttVariation">s5.3's <c>rttvar</c>, from the same estimator.</param>
    /// <param name="maxAckDelay">The peer's <c>max_ack_delay</c>, added whatever the space.</param>
    /// <returns>The duration a blackout must exceed. Always strictly positive.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="spec"/> is null.</exception>
    internal static TimeSpan DurationFor(
        TlsQuicRecoverySpec spec,
        TimeSpan smoothedRtt,
        TimeSpan rttVariation,
        TimeSpan maxAckDelay)
    {
        ArgumentNullException.ThrowIfNull(spec);

        var smoothed = Math.Max((double)smoothedRtt.Ticks, 0);
        var ackDelay = Math.Max((double)maxAckDelay.Ticks, 0);
        var variation = Math.Max(
            Math.Max((double)rttVariation.Ticks, 0) * 4.0,
            TlsQuicConnection.KGranularity.Ticks);

        var period = (smoothed + variation + ackDelay) * spec.PersistentCongestionThreshold;

        return period >= TimeSpan.MaxValue.Ticks
            ? TimeSpan.MaxValue
            : new TimeSpan((long)period);
    }

    /// <summary>RFC 9002 B.8's <c>InPersistentCongestion</c>: has this loss established the
    /// blackout s7.6.2 defines?</summary>
    /// <remarks>
    /// <para>s7.6.2 lines 246-256, WHICH ARE A CONJUNCTION AND NOT A LIST OF HINTS. "A sender
    /// establishes persistent congestion after the receipt of an acknowledgment if two packets
    /// that are ack-eliciting are declared lost, and: across all packet number spaces, none of the
    /// packets sent between the send times of these two packets are acknowledged; the duration
    /// between the send times of these two packets exceeds the persistent congestion duration
    /// (Section 7.6.1); and a prior RTT sample existed when these two packets were sent." Four
    /// clauses, all required. A predicate that took only the third - which is the one a reader
    /// remembers, and the only one B.8's <c>pc_lost</c> argument carries enough information to
    /// evaluate - collapses the window on any two losses far enough apart and passes every
    /// "persistent congestion collapses the window" assertion anyone would write.</para>
    /// <para>AND B.8'S ARGUMENT LIST IS THE DEFECT HERE, WHICH IS WHY THIS SIGNATURE IS WIDER THAN
    /// ITS ONE. B.8 line 639 calls <c>InPersistentCongestion(pc_lost)</c> where <c>pc_lost</c> is a
    /// list of lost packets and nothing else. From that list alone the second clause CANNOT BE
    /// EVALUATED - it asks what was ACKNOWLEDGED between two send times, and no lost packet knows
    /// that - and the first clause cannot be applied either, because B.8 builds <c>pc_lost</c>
    /// with no ack-eliciting filter at all while s7.6.2 line 258 says the two packets "MUST be
    /// ack-eliciting". A body written to match B.8's call site is therefore forced to drop two of
    /// the four clauses. This one takes what the clauses actually need.</para>
    /// <para>THE FIRST CLAUSE. Only <see cref="TlsQuicSentPacket.IsAckEliciting"/> packets are
    /// candidates. s7.6.2 lines 258-261 give the reason rather than only the rule: "These two
    /// packets MUST be ack-eliciting, since a receiver is required to acknowledge only
    /// ack-eliciting packets within its maximum acknowledgment delay". A silent stretch of
    /// ACK-only packets is not evidence of a blackout, because the peer was never obliged to
    /// acknowledge them and their loss says nothing about the path. At least TWO must survive the
    /// filters; s7.6.2 says "two packets" and one packet compared against itself spans no time at
    /// all.</para>
    /// <para>THE SECOND CLAUSE, AND THE ONE DEPARTURE IN THIS METHOD. "Across all packet number
    /// spaces, none of the packets sent between the send times of these two packets are
    /// acknowledged." Answering it exactly would need the send time of every acknowledged packet,
    /// which is a second copy of A3-3's retained-packet map. Instead the candidate window is
    /// required to START AT OR AFTER <paramref name="latestAcknowledgedSendTime"/>, the newest send
    /// time among packets the sender has seen acknowledged in ANY space. That is sufficient: every
    /// acknowledged packet was sent at or before that instant, so none can fall strictly inside a
    /// window that begins at or after it. AT OR AFTER, NOT AFTER, because s7.6.2 line 252 says
    /// "sent BETWEEN the send times of these two packets" and between excludes its endpoints - an
    /// acknowledged packet sent at the very instant the oldest lost packet was sent is not between
    /// them. Tightening this to a strict comparison discards a whole qualifying blackout whenever
    /// a sender put two packets on the wire at one timestamp and only one came back, which a
    /// sender that fills its window in a burst does constantly. It is not necessary - a qualifying window lying entirely
    /// BEFORE the newest acknowledgement is rejected - so this errs toward NOT declaring persistent
    /// congestion. THE DIRECTION OF THE ERROR IS THE POINT: s7.6.2 lines 271-275 accept the
    /// opposite error explicitly for senders that cannot compare send times across spaces ("This
    /// might result in erroneously declaring persistent congestion"), and collapsing a window that
    /// should not have collapsed costs throughput on a healthy path, whereas declining to collapse
    /// one leaves the sender at a window s7.6 has other machinery to reduce. s7.6.3's own worked
    /// example still qualifies under this rule: packet #1 is acknowledged at t=1.2 but was SENT at
    /// t=0, and the lost run begins at t=1, after it.</para>
    /// <para>THE THIRD CLAUSE IS A STRICT INEQUALITY. "the duration between the send times of these
    /// two packets EXCEEDS the persistent congestion duration". s7.6.3 works the example at lines
    /// 320-325 - "The congestion period is calculated as the time between the oldest and newest
    /// lost packets: 8 - 1 = 7. The persistent congestion duration is 2 * 3 = 6. Because the
    /// threshold was reached ..." - and 7 exceeds 6 with room to spare, so the example does not
    /// settle the boundary. The word does: a gap exactly equal to the duration does not exceed it
    /// and does not qualify. Written as <c>&gt;=</c> this would declare persistent congestion one
    /// whole tick early, which no test built out of round numbers would ever notice.</para>
    /// <para>THE FOURTH CLAUSE, WHICH IS TWO RULES AND NOT ONE. "A prior RTT sample existed when
    /// these two packets were sent." B.8 lines 634-638 spell out both halves: <c>if
    /// (first_rtt_sample == 0): return</c>, and then <c>for lost in lost_packets: if
    /// lost.time_sent &gt; first_rtt_sample: pc_lost.insert(lost)</c>. So a sender with NO sample
    /// yet declares nothing at all, AND a sender that has one still discards every candidate sent
    /// at or before the sample arrived. s7.6.2 lines 262-267 give the reason: "Before the first RTT
    /// sample, a sender arms its PTO timer based on the initial RTT (Section 6.2.2), which could be
    /// substantially larger than the actual RTT. Requiring a prior RTT sample prevents a sender
    /// from establishing persistent congestion with potentially too few probes." Dropping only the
    /// first half leaves a sender that got its first sample late still able to declare persistent
    /// congestion over a stretch of packets sent while it was guessing.</para>
    /// <para>A NON-POSITIVE <paramref name="duration"/> ANSWERS FALSE RATHER THAN COMPARING. Nothing
    /// <see cref="DurationFor"/> returns can be non-positive, so this can only be a caller passing
    /// a value it did not compute - and the safe answer to nonsense is the one that does not
    /// collapse the window. Without it, a zero duration turns this predicate into "any two
    /// ack-eliciting losses at different times", which is precisely the half-implementation A3-9
    /// declined to write.</para>
    /// <para>TOTAL FOR EVERY INPUT: a null list, an empty one, a list holding the same packet
    /// repeatedly, fabricated send times at <see cref="DateTimeOffset.MinValue"/> or
    /// <see cref="DateTimeOffset.MaxValue"/>. The subtraction cannot overflow because the distance
    /// between those two instants is about 3.2e18 ticks and <see cref="TimeSpan.MaxValue"/> is
    /// 9.2e18.</para>
    /// </remarks>
    /// <param name="lostPackets">The packets loss detection has just declared lost. Null or empty
    /// is answered false.</param>
    /// <param name="firstRttSampleAt">A3-4's <c>TlsQuicAckTracker.FirstRttSampleAt</c>: when the
    /// first RTT sample arrived, or null if none has. Null is answered false.</param>
    /// <param name="latestAcknowledgedSendTime">The newest <see cref="TlsQuicSentPacket.SentAt"/>
    /// among packets acknowledged in any packet number space, or <c>default</c> when nothing has
    /// been acknowledged yet.</param>
    /// <param name="duration">What <see cref="DurationFor"/> returned.</param>
    /// <returns>True when all four of s7.6.2's clauses hold.</returns>
    internal static bool IsEstablished(
        IReadOnlyList<TlsQuicSentPacket>? lostPackets,
        DateTimeOffset? firstRttSampleAt,
        DateTimeOffset latestAcknowledgedSendTime,
        TimeSpan duration)
    {
        if (lostPackets is null || duration <= TimeSpan.Zero)
        {
            return false;
        }

        // B.8 line 635's `if (first_rtt_sample == 0): return`, as a null rather than a sentinel:
        // A3-4 stores the instant itself and DateTimeOffset has no spare zero the way B.8's
        // untyped time does.
        if (firstRttSampleAt is not { } firstSample)
        {
            return false;
        }

        var oldest = DateTimeOffset.MaxValue;
        var newest = DateTimeOffset.MinValue;
        var candidates = 0;

        foreach (var lost in lostPackets)
        {
            if (!lost.IsAckEliciting
                || lost.SentAt <= firstSample
                || lost.SentAt < latestAcknowledgedSendTime)
            {
                continue;
            }

            candidates++;

            if (lost.SentAt < oldest)
            {
                oldest = lost.SentAt;
            }

            if (lost.SentAt > newest)
            {
                newest = lost.SentAt;
            }
        }

        // s7.6.2's "two packets". With a positive duration this is implied - one candidate makes
        // newest and oldest the same instant and a zero gap exceeds nothing - but it is not
        // implied for a caller-supplied duration, and it is the clause the sentence leads with.
        if (candidates < 2)
        {
            return false;
        }

        return newest - oldest > duration;
    }
}

// TASK A3-9 - MUTATION LEDGER. See the end of this file.
//
// WHERE THIS FILE'S NUMBERS COME FROM: nowhere in this file. Every congestion constant -
// the initial window's multiplier and byte cap, the minimum window, the loss reduction
// factor - is read off a TlsQuicRecoverySpec at construction, and TlsQuicRecoverySpec's
// preset block is where the extract's values live. There is no numeric literal in this
// file's code except 0 and 1, both structural, exactly as A3-2's file requires of itself.

/// <summary>RFC 9002 s7's NewReno congestion controller: the three states of s7.3 Figure 1,
/// driven by the four signals a sender raises, with every constant taken from a
/// <see cref="TlsQuicRecoverySpec"/>.</summary>
/// <remarks>
/// <para>NEWRENO IS RFC 9002'S CONTROLLER AND NOT A MEASUREMENT OF CHROMIUM'S. This is the
/// single largest behavioural fingerprint in loss recovery and it is shipped UNVERIFIED
/// against any real client. rfc9002-section7-congestion-control.txt line 20 says this document
/// "specifies a sender-side congestion controller for QUIC similar to TCP NewReno [RFC6582]",
/// and lines 23-27 say a sender "can unilaterally choose a different algorithm to use, such as
/// CUBIC [RFC8312]" - so the RFC itself treats the controller as replaceable. Chromium is
/// widely reported to run BBR, which is neither NewReno nor CUBIC and whose send-rate curve
/// does not look like this one at all. NewReno is implemented first because it is the
/// controller whose correctness can be checked against a document instead of against a guess,
/// NOT because anything here measured Chromium running it. A packet capture is what would
/// settle it: task A3-14. Until A3-14, this choice belongs in task A3-12's readout third
/// column, next to the initial congestion window, and a reader who takes the shipped default
/// for evidence has read it wrong.</para>
/// <para>A DIFFERENT CONTROLLER PLUGS IN WITHOUT TOUCHING THIS CLASS. The knob is
/// <see cref="TlsQuicRecoverySpec.CongestionController"/>, a factory rather than an instance
/// so that each connection gets its own state - s7 lines 39-41: "The congestion controller is
/// per path". A BBR implementation would implement
/// <see cref="ITlsQuicCongestionController"/>, ignore
/// <see cref="TlsQuicRecoverySpec.LossReductionFactor"/> entirely, and never mention
/// <see cref="TlsQuicCongestionState"/>; nothing in the seam requires a slow start threshold
/// or a recovery period to exist.</para>
/// <para>WHERE THIS IMPLEMENTATION DIVERGES FROM APPENDIX B, all three named at their site as
/// well as here, because "the pseudocode is line-by-line transcribable" is a claim that has
/// already been falsified four times in this subsystem:</para>
/// <para>1. CONGESTION AVOIDANCE COUNTS BYTES INSTEAD OF DIVIDING. B.5 lines 578-580 write
/// <c>congestion_window += max_datagram_size * acked_packet.sent_bytes / congestion_window</c>
/// and lines 549-552 warn in the same breath that "implementers that use an integer
/// representation for congestion_window should be careful with division and can use the
/// alternative approach suggested in Section 2.1 of [RFC3465]". Transcribed literally into
/// integer arithmetic that expression EVALUATES TO ZERO for every acknowledgement once the
/// window exceeds max_datagram_size squared - about 1.4 MB at a 1200-byte datagram - so
/// congestion avoidance silently stops increasing forever, which no arithmetic invariant and
/// no short test would notice. See <see cref="Grow"/>.</para>
/// <para>2. THE "LAST LOSS" SENTINEL IS A NULL AND NOT A ZERO. B.8 lines 619-627 initialise
/// <c>sent_time_of_last_loss = 0</c> and then test <c>if (sent_time_of_last_loss != 0)</c> to
/// mean "some in-flight packet was lost", so a packet genuinely sent at the zero instant reads
/// as no loss at all. THIS ONE IS HYGIENE AND NOT A DEFECT, AND A MUTATION SWEEP IS WHAT
/// SETTLED WHICH: restoring B.8's sentinel changes no observable behaviour, because B.3 line
/// 531 starts <c>congestion_recovery_start_time</c> at the same zero and B.6's guard therefore
/// returns early for a zero-instant loss anyway. The two bugs cancel. The nullable is kept
/// because it does not depend on that coincidence - a controller that ever set the recovery
/// start time from something other than a clock would lose the cancellation and keep the
/// sentinel. See <see cref="OnPacketsLost"/>.</para>
/// <para>3. THE RECOVERY PERIOD IS A FLAG AS WELL AS A TIMESTAMP. B has no "in recovery"
/// variable; it re-derives the answer per packet from
/// <c>sent_time &lt;= congestion_recovery_start_time</c> (lines 554-555), which cannot
/// distinguish "the period is running" from "the period ended and the timestamp is still
/// set". s7.3.2 lines 160-164 describe a period that ENDS, and Figure 1 draws it as a state,
/// so the state is stored. The flag is set exactly where B.6 sets the timestamp and cleared
/// exactly where B.5 first takes its <c>!InCongestionRecovery</c> branch, so no behaviour
/// changes - only the readout gains an answer. See <see cref="State"/>.</para>
/// <para>AND ONE PLACE THE PROSE AND THE PSEUDOCODE DISAGREE OUTRIGHT. s7.3.2 lines 142-144
/// say a sender "MUST set the slow start threshold to HALF the value of the congestion window
/// when loss is detected" - the number 0.5, written into the prose. B.6 line 596 says
/// <c>ssthresh = congestion_window * kLossReductionFactor</c> - a named constant that B.1
/// lines 477-479 describe as one "Section 7 recommends a value of 0.5" for. THIS
/// IMPLEMENTATION FOLLOWS B.6, because a recommended value is a knob and A3-2 made it one; a
/// spec carrying a factor of 0.25 halves nothing and reduces to a quarter. The prose's 0.5
/// survives as the shipped default and nothing else.</para>
/// <para>AND TWO OF APPENDIX B'S UNDEFINED FUNCTIONS LAND IN THIS FILE.
/// <c>IsAppOrFlowControlLimited</c> is defined here, from s7.8's prose, and its definition is
/// argued at <see cref="IsAppOrFlowControlLimited"/> because the obvious one is wrong in a way
/// that stops the window growing at all. <c>InPersistentCongestion</c> is NOT defined here and
/// is not stubbed: it is task A3-10's, along with the collapse B.8 lines 639-641 trigger with
/// it, and a half-implementation that collapsed on a single loss would pass every "the window
/// collapses" test A3-10 could write. <c>MaybeSendOnePacket</c> (B.6 line 599) is a send-path
/// action rather than controller state and s7.3.2 lines 147-153 make it a MAY; it is not
/// implemented and the window is reduced immediately, which is the same lines' first
/// alternative.</para>
/// </remarks>
internal sealed class TlsQuicNewRenoCongestionController : ITlsQuicCongestionController
{
    private readonly TimeProvider _timeProvider;
    private readonly long _maxDatagramSize;
    private readonly long _minimumWindow;
    private readonly double _lossReductionFactor;

    private long _congestionWindow;
    private long _bytesInFlight;
    private long _slowStartThreshold;
    private long _congestionAvoidanceAckedBytes;
    private DateTimeOffset _congestionRecoveryStartTime;
    private bool _inRecovery;

    /// <summary>Builds a controller for one path, with every constant read off
    /// <paramref name="spec"/>.</summary>
    /// <remarks>
    /// <para>THE ONLY MEMBER OF THIS CLASS THAT MAY THROW, and it throws only on inputs that
    /// are programming errors rather than network events - a null spec, or a datagram size of
    /// zero or less. RFC 9002 B.2 lines 490-495 make max_datagram_size "The sender's current
    /// maximum payload size ... with a minimum value of 1200 bytes", but that 1200 is a
    /// statement about how an endpoint derives the value from its PMTU, not a rule this
    /// controller may impose on a caller who legitimately knows better; the floor enforced
    /// here is the one that makes the arithmetic below meaningful, which is one byte.</para>
    /// <para>WHY THE DATAGRAM SIZE IS A PARAMETER AND NOT A KNOB. It is not a fingerprint: it
    /// is a property of the path, and A3-2's spec deliberately expresses the initial window as
    /// a MULTIPLIER of it rather than a byte count for exactly that reason.</para>
    /// </remarks>
    /// <para>THE CLOCK MUST BE THE SAME ONE THAT STAMPED <see cref="TlsQuicSentPacket.SentAt"/>
    /// - in practice <c>TlsQuicConnectionOptions.TimeProvider</c>. RFC 9002 B.6 line 595 sets
    /// <c>congestion_recovery_start_time = now()</c> and B.5 line 555 then compares packet
    /// SEND times against it, so the two readings must come off one clock or the recovery
    /// period's boundary is nonsense. That is the entire reason this controller takes a clock
    /// at all; nothing else here reads the time.</para>
    /// <param name="spec">The recovery spec whose congestion knobs this controller obeys.</param>
    /// <param name="maxDatagramSize">RFC 9002 B.2's <c>max_datagram_size</c> for this path.</param>
    /// <param name="timeProvider">The connection's clock, defaulting to
    /// <see cref="TimeProvider.System"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="spec"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxDatagramSize"/> is not
    /// positive.</exception>
    internal TlsQuicNewRenoCongestionController(
        TlsQuicRecoverySpec spec,
        int maxDatagramSize,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            maxDatagramSize, nameof(maxDatagramSize));

        _timeProvider = timeProvider ?? TimeProvider.System;
        _maxDatagramSize = maxDatagramSize;
        _lossReductionFactor = spec.LossReductionFactor;
        _minimumWindow = (long)spec.MinimumCongestionWindowDatagrams * maxDatagramSize;
        _congestionWindow = InitialWindowFor(spec, maxDatagramSize);

        // RFC 9002 B.3 lines 529-534. `ssthresh = infinite` becomes long.MaxValue, which is
        // safe here for a reason worth stating rather than assuming: this value is only ever
        // an operand of `<` in Grow and of `<=` in State. It is never added to, multiplied,
        // or converted to a duration - which is precisely how A.8's `infinite` timer armament
        // went wrong elsewhere in this subsystem. The first congestion event overwrites it.
        _slowStartThreshold = long.MaxValue;
        _bytesInFlight = 0;
        _congestionRecoveryStartTime = default;
        _inRecovery = false;
    }

    /// <inheritdoc />
    /// <remarks>The controller's identity for task A3-12's readout. It names the ALGORITHM and
    /// not this class, because the readout's reader wants to know what shape the send rate
    /// has, and "NewReno" is that answer whoever implemented it.</remarks>
    public string Name => "NewReno";

    /// <inheritdoc />
    public long CongestionWindowBytes => _congestionWindow;

    /// <inheritdoc />
    public long BytesInFlight => _bytesInFlight;

    /// <summary>RFC 9002 B.2's <c>ssthresh</c>: the slow start threshold in bytes, or
    /// <see cref="long.MaxValue"/> standing for B.3's "infinite" while no congestion event has
    /// happened yet.</summary>
    /// <remarks>NOT ON THE SEAM. A slow start threshold is a NewReno concept; see the note on
    /// <see cref="TlsQuicCongestionState"/>. It is exposed because it is the value s7.3.1 and
    /// s7.3.3 define their states in terms of, and a test that could see the states but not
    /// the threshold could not check that the states were derived from the right thing.
    /// </remarks>
    internal long SlowStartThresholdBytes => _slowStartThreshold;

    /// <summary>RFC 9002 s7.3 Figure 1's current state.</summary>
    /// <remarks>
    /// <para>DERIVED AND NOT STORED, apart from the recovery flag, so that it cannot drift
    /// from the window and threshold it is defined in terms of. s7.3.2 lines 168-170: a sender
    /// "is in congestion avoidance any time the congestion window is at or above the slow
    /// start threshold and not in a recovery period"; s7.3.1 lines 118-119: "in slow start any
    /// time the congestion window is below the slow start threshold". The recovery period wins
    /// over both, which is what "and not in a recovery period" says.</para>
    /// <para>THE ONE CASE WORTH NAMING: immediately after a congestion event, B.6 line 597
    /// leaves the window at <c>max(ssthresh, kMinimumWindow)</c>, which is at or above
    /// ssthresh - so the instant the recovery period ends the state is congestion avoidance
    /// and never slow start, exactly as Figure 1 draws it. Slow start is re-entered only when
    /// something pushes the window BELOW the threshold without touching the threshold, and
    /// s7.3.1 lines 131-133 say that "only occurs after persistent congestion is declared" -
    /// so <see cref="OnPersistentCongestion"/> is the ONLY method in this class whose effect on
    /// this property can be SlowStart, and it produces it by lowering the window rather than by
    /// naming the state.</para>
    /// </remarks>
    internal TlsQuicCongestionState State =>
        _inRecovery ? TlsQuicCongestionState.Recovery
        : _congestionWindow < _slowStartThreshold ? TlsQuicCongestionState.SlowStart
        : TlsQuicCongestionState.CongestionAvoidance;

    /// <summary>RFC 9002 s7.2's initial congestion window, computed from a spec and a datagram
    /// size.</summary>
    /// <remarks>
    /// <para>STATIC AND INTERNAL SO A TEST CAN ASK IT DIRECTLY, because s7.2's sentence is the
    /// single easiest thing in this file to get backwards and an implementation that got it
    /// backwards would still start, still send, and still pass every state-machine test.
    /// rfc9002-section7-congestion-control.txt lines 63-66: "Endpoints SHOULD use an initial
    /// congestion window of ten times the maximum datagram size (max_datagram_size), WHILE
    /// LIMITING THE WINDOW TO THE LARGER OF 14,720 bytes or twice the maximum datagram size."
    /// So there are two operations and they nest in one order only: the LARGER of the byte cap
    /// and a small multiple forms the limit, and the ten-times figure is then held DOWN to it.
    /// Written wrong - as a max of the multiple and the cap, or a min against the cap alone -
    /// it produces 14,720 bytes at a 1200-byte datagram instead of 12,000, and 3,000 instead
    /// of 14,720 at a 1500-byte one.</para>
    /// <para>WHERE THE "TWICE" COMES FROM, since this file may not write a 2. s7.2's cap floor
    /// and s7.2 lines 83-86's minimum congestion window - "The RECOMMENDED value is 2 *
    /// max_datagram_size" - are the same quantity said twice, and A3-2 gave the second one a
    /// knob and the first one none. So the floor is read from
    /// <see cref="TlsQuicRecoverySpec.MinimumCongestionWindowDatagrams"/>. The consequence is
    /// worth stating: a spec that raises the minimum window raises the initial window's floor
    /// with it, which is the behaviour s7.2 describes if the two sentences mean one thing, and
    /// the only alternative was a literal this file is not allowed to hold.</para>
    /// <para>THE INITIAL WINDOW IS NOT CLAMPED UP TO THE MINIMUM WINDOW, and that is not an
    /// oversight. s7.2 lines 83-85 scope the minimum precisely: it "is the smallest value the
    /// congestion window can attain IN RESPONSE TO loss, an increase in the peer-reported
    /// ECN-CE count, or persistent congestion". It constrains reductions. A caller who asks
    /// for a one-datagram initial window is asking for a fingerprint, not making a mistake,
    /// and gets one.</para>
    /// <para>UNVERIFIED AGAINST CHROMIUM. The shipped multiplier and byte cap are RFC 9002's
    /// SHOULD, and no capture this project holds bounds what a real client sends. Task A3-14
    /// is what would settle it; task A3-12's readout third column is where it belongs until
    /// then.</para>
    /// </remarks>
    /// <param name="spec">The spec carrying the multiplier and the byte cap.</param>
    /// <param name="maxDatagramSize">RFC 9002 B.2's <c>max_datagram_size</c>.</param>
    /// <returns>The window in bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="spec"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxDatagramSize"/> is not
    /// positive.</exception>
    internal static long InitialWindowFor(TlsQuicRecoverySpec spec, int maxDatagramSize)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            maxDatagramSize, nameof(maxDatagramSize));

        var (datagramMultiplier, byteCap) = spec.InitialCongestionWindow;

        // Long arithmetic throughout: the multiplier and the datagram size are both ints and
        // a caller may legitimately hold a jumbo path and a large multiplier, whose int
        // product would wrap to a negative window and open the send gate forever.
        var tenTimes = (long)datagramMultiplier * maxDatagramSize;
        var floor = (long)spec.MinimumCongestionWindowDatagrams * maxDatagramSize;
        var limit = Math.Max(byteCap, floor);
        return Math.Min(tenTimes, limit);
    }

    /// <inheritdoc />
    public bool CanSend(int bytes)
    {
        // s7 lines 46-47's "larger than", so equality passes. The addition is long + int and
        // cannot overflow for any int, which is why bytes is not range-checked: a negative
        // one answers "yes" and is the caller's nonsense, not an exception.
        return _bytesInFlight + bytes <= _congestionWindow;
    }

    /// <inheritdoc />
    public void OnPacketSent(in TlsQuicSentPacket sent)
    {
        if (!sent.IsInFlight)
        {
            return;
        }

        _bytesInFlight = SaturatingAdd(_bytesInFlight, sent.Size);
    }

    /// <inheritdoc />
    public void OnPacketsAcked(IReadOnlyList<TlsQuicSentPacket>? ackedPackets)
    {
        if (ackedPackets is null || ackedPackets.Count == 0)
        {
            return;
        }

        // s7.8'S CHECK IS TAKEN ONCE, HERE, BEFORE ANY BYTES ARE REMOVED - and getting this
        // wrong is how a NewReno controller stops growing altogether. B.5 lines 561-569 call
        // IsAppOrFlowControlLimited from INSIDE the per-packet loop and AFTER
        // `bytes_in_flight -= acked_packet.sent_bytes`. Any definition of that predicate in
        // terms of bytes in flight is then reading a counter the loop has already drained: a
        // sender that filled its window perfectly looks under-utilised from the second packet
        // of the very first acknowledgement onward, and the window never doubles in slow
        // start. The predicate asks about how full the window WAS while these packets were
        // outstanding, so it is evaluated on the state before this batch is applied.
        var appLimited = IsAppOrFlowControlLimited();

        foreach (var acked in ackedPackets)
        {
            // B.5 lines 562-563: `if (!acked_packet.in_flight): return`. An acknowledgement
            // of an ACK-only packet moves nothing at all - not bytes in flight, not the
            // window - which is s7 lines 32-33's "packets containing only ACK frames do not
            // count toward bytes in flight and are not congestion controlled" seen from the
            // acknowledgement side.
            if (!acked.IsInFlight)
            {
                continue;
            }

            _bytesInFlight = SaturatingSubtract(_bytesInFlight, acked.Size);

            // s7.3.2 lines 160-162: "A recovery period ends and the sender enters congestion
            // avoidance when a packet sent during the recovery period is acknowledged." B.5
            // lines 554-555 spell "sent during or before" as
            // `sent_time <= congestion_recovery_start_time`, so a packet sent at exactly the
            // instant recovery started is still an OLD packet and does not end the period.
            if (acked.SentAt > _congestionRecoveryStartTime)
            {
                _inRecovery = false;
            }
            else
            {
                // B.5 lines 570-572: no growth from a packet that predates the recovery
                // period. This is what limits the reduction to once per round trip from the
                // growth side, the same way OnCongestionEvent does from the loss side.
                continue;
            }

            if (appLimited)
            {
                continue;
            }

            Grow(acked.Size);
        }
    }

    /// <inheritdoc />
    public void OnPacketsLost(IReadOnlyList<TlsQuicSentPacket>? lostPackets)
    {
        if (lostPackets is null || lostPackets.Count == 0)
        {
            return;
        }

        // B.8 lines 619-627, with the sentinel replaced by a nullable. B.8 writes
        // `sent_time_of_last_loss = 0` and later tests `!= 0` to mean "something in flight was
        // lost", so a packet sent at the zero instant reads as no loss at all.
        //
        // AND THE SWEEP SAYS THAT COSTS NOTHING TODAY, which is worth recording rather than
        // overclaiming: B.3 starts congestion_recovery_start_time at the same zero, so B.6's
        // guard already returns early for a zero-instant loss and the two mistakes cancel.
        // A39-M27 restored the sentinel and no test could see it. The nullable stays because
        // it says what was meant and does not rely on the cancellation.
        DateTimeOffset? sentTimeOfLastLoss = null;

        foreach (var lost in lostPackets)
        {
            // The `if lost_packet.in_flight` of B.8 line 622 gates BOTH statements in its
            // body, so losing an ACK-only packet is not a congestion event - the window does
            // not move at all. s7 lines 33-37 say the same thing in prose and then say QUIC
            // "MAY use that information to adjust the congestion controller ... but this
            // document does not describe a mechanism for doing so", so not moving is the
            // specified behaviour rather than an omission.
            if (!lost.IsInFlight)
            {
                continue;
            }

            _bytesInFlight = SaturatingSubtract(_bytesInFlight, lost.Size);

            if (sentTimeOfLastLoss is not { } last || lost.SentAt > last)
            {
                sentTimeOfLastLoss = lost.SentAt;
            }
        }

        if (sentTimeOfLastLoss is { } sentTime)
        {
            OnCongestionEvent(sentTime);
        }

        // AND HERE IS WHERE B.8 STOPS AND TASK A3-10 PICKS UP - BUT NOT INSIDE THIS METHOD.
        // B.8 lines 630-641 continue into `if (InPersistentCongestion(pc_lost)):
        // congestion_window = kMinimumWindow; congestion_recovery_start_time = 0`. A3-9 left
        // that branch out rather than stub it, and A3-10 did not put it back here, because
        // B.8's own call site is where the defect is: `pc_lost` is a list of lost packets, and
        // s7.6.2's second clause asks what was ACKNOWLEDGED between two send times while its
        // fourth asks when the first RTT sample arrived. Neither is answerable from anything
        // this method is handed. So the predicate is TlsQuicPersistentCongestion.IsEstablished,
        // which takes what the clauses need; the sender evaluates it on the same
        // acknowledgement that produced this loss and calls OnPersistentCongestion when it
        // holds, in B.8's order - congestion event first, collapse second.
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>RFC 9002 B.8 lines 639-641, both statements. `congestion_window = kMinimumWindow`
    /// is the minimum read off A3-2's knob rather than a literal, and it is an ASSIGNMENT and
    /// not a reduction: s7.6.2 lines 276-279's MUST names the value, so a window already below
    /// the minimum through a spec whose loss reduction drove it there comes back UP to it. That
    /// is also why this is not <c>Math.Min</c> - which would be the natural shape for "collapse"
    /// and would silently do nothing whenever the window had already been reduced past the
    /// minimum.</para>
    /// <para>`congestion_recovery_start_time = 0` IS WHAT ENDS THE RECOVERY PERIOD, and this
    /// class needs both of its two representations set to say it. B has no recovery flag: B.5
    /// line 555 derives InCongestionRecovery from the timestamp alone, so writing zero there
    /// makes every future packet's send time later than the period's start and the period is
    /// over. This class keeps the flag as well - see <see cref="State"/> - so the flag is
    /// cleared here too. Clearing only the timestamp would leave <see cref="State"/> reporting
    /// Recovery forever, since nothing else clears the flag except an acknowledgement of a
    /// packet sent after a start time that no longer exists.</para>
    /// <para>AND THIS IS THE ONE ROUTE BACK INTO SLOW START, which is why the collapse is not
    /// simply a smaller number. s7.3.1 lines 131-133: "A sender re-enters slow start any time
    /// the congestion window is less than ssthresh, which only occurs after persistent
    /// congestion is declared." <see cref="State"/> derives that rather than being told it: the
    /// window is now the minimum and ssthresh is whatever the last congestion event left, so a
    /// sender whose window was halved from anything larger than twice the minimum lands in slow
    /// start. THE DEGENERATE CASE IS REAL AND IS NOT PATCHED OVER: a spec whose minimum window
    /// is at or above the surviving ssthresh leaves the window NOT below it, and s7.3.3's
    /// definition then makes the state congestion avoidance. Forcing slow start by also
    /// lowering ssthresh would be inventing a rule - RFC 9002 never touches ssthresh on
    /// persistent congestion - and would make the collapse reduce a threshold s7.6 does not
    /// mention.</para>
    /// <para>THE ACCUMULATOR IS DISCARDED FOR THE REASON <see cref="OnCongestionEvent"/> GIVES:
    /// bytes counted toward one whole congestion window are meaningless once the window has
    /// become the minimum, and carrying them over would hand the next state an increase earned
    /// under a window many times the size. B says nothing about it because B does no
    /// accumulating.</para>
    /// <para>IDEMPOTENT AND TOTAL. Calling this twice, or on a controller that has never sent
    /// anything, sets the same three fields to the same values. BYTES IN FLIGHT IS NOT TOUCHED:
    /// persistent congestion is a statement about the WINDOW, and the packets that established
    /// it were already removed from flight by <see cref="OnPacketsLost"/>. Zeroing it here would
    /// double-subtract them and open the send gate.</para>
    /// </remarks>
    public void OnPersistentCongestion()
    {
        _congestionWindow = _minimumWindow;
        _congestionRecoveryStartTime = default;
        _inRecovery = false;
        _congestionAvoidanceAckedBytes = 0;
    }

    /// <inheritdoc />
    public void OnPacketsDiscarded(IReadOnlyList<TlsQuicSentPacket>? discardedPackets)
    {
        if (discardedPackets is null)
        {
            return;
        }

        foreach (var discarded in discardedPackets)
        {
            if (discarded.IsInFlight)
            {
                _bytesInFlight = SaturatingSubtract(_bytesInFlight, discarded.Size);
            }
        }
    }

    /// <summary>RFC 9002 B.6's <c>OnCongestionEvent</c>: enter a recovery period, drop the
    /// slow start threshold and reduce the window - unless a recovery period is already
    /// running.</summary>
    /// <remarks>
    /// <para>THE EARLY RETURN IS THE WHOLE POINT AND IS WHERE NEWRENO IS MOST OFTEN WRITTEN
    /// WRONG. B.6 lines 590-592 and s7.3.2 lines 155-158: "The recovery period aims to limit
    /// congestion window reduction to once per round trip. Therefore, during a recovery
    /// period, the congestion window does not change in response to new losses". A window's
    /// worth of packets is typically all lost together but detected in several batches, and a
    /// controller that reduced on each batch would quarter or eighth the window where the RFC
    /// halves it - which still looks like a congestion controller, still converges, and still
    /// passes every "loss reduces the window" test. The test that catches it is one that loses
    /// a SECOND packet, sent BEFORE the period started, and asserts the window did not move
    /// again.</para>
    /// <para>The comparison is <c>&lt;=</c> because B.5 line 555's InCongestionRecovery is,
    /// so a packet sent at the exact instant the period began counts as an old packet.</para>
    /// <para>THE GUARD DOES NOT CONSULT THE RECOVERY FLAG, and an earlier draft of this file
    /// that ANDed the two was wrong in the exact way this method's remarks warn about. B.6
    /// lines 591-592 test the timestamp alone. Once a recovery period has ended, the start
    /// time it ran from is still the boundary that says which packets predate it - so a
    /// straggling loss of a packet sent before that period must not open a second one on the
    /// strength of a window that was already reduced for it. Adding <c>_inRecovery &amp;&amp;</c>
    /// re-opens recovery for every old packet the moment the period ends, halving the window
    /// twice for one round trip's losses.</para>
    /// </remarks>
    /// <param name="sentTime">The send time of the newest in-flight packet in this loss.</param>
    private void OnCongestionEvent(DateTimeOffset sentTime)
    {
        if (sentTime <= _congestionRecoveryStartTime)
        {
            return;
        }

        // B.6 line 595: congestion_recovery_start_time = now(), read off the connection's
        // clock rather than taken from the lost packet's send time. The two are not
        // interchangeable: the recovery period runs from the moment loss was DETECTED, so
        // every packet already on the wire when it opened - sent after the loss but before
        // the detection - is inside the period and must not end it when acknowledged. Using
        // the loss's own send time would let the first such acknowledgement end the period
        // early and resume growth inside the round trip s7.3.2 lines 155-156 exist to
        // protect.
        _congestionRecoveryStartTime = _timeProvider.GetUtcNow();
        _inRecovery = true;

        // B.6 line 596. NOT the prose's literal half - see this class's remarks. A factor of
        // 1.0, which A3-2's spec permits as its maximum, therefore reduces nothing and is a
        // legal no-reduction controller.
        //
        // THE CAST IS GUARDED BECAUSE AN UNGUARDED ONE IS SILENTLY SIGNED. Converting a double
        // that exceeds long.MaxValue back to a long is unchecked-undefined in C# and on this
        // runtime yields long.MinValue - so a window that had saturated, times a factor of
        // 1.0, would produce a NEGATIVE slow start threshold, and every subsequent
        // `congestion_window < ssthresh` test would answer false and pin the controller in
        // congestion avoidance forever. Only reachable through fabricated packet sizes, and
        // guarded anyway for the same reason the rest of this class saturates.
        var reduced = _congestionWindow * _lossReductionFactor;
        _slowStartThreshold = reduced < long.MaxValue ? (long)Math.Max(reduced, 0) : long.MaxValue;

        // B.6 line 597. The window is reduced IMMEDIATELY, which s7.3.2 lines 147-150 offer as
        // the first of two alternatives - "Implementations MAY reduce the congestion window
        // immediately upon entering a recovery period or use other mechanisms, such as
        // Proportional Rate Reduction [PRR]". PRR is not implemented; B.6 is.
        _congestionWindow = Math.Max(_slowStartThreshold, _minimumWindow);

        // A fresh recovery period means the previous congestion-avoidance accounting is
        // measured against a window that no longer exists. B says nothing about this because
        // B does no accumulating; carrying it over would hand the next state a partial
        // increase earned under a window twice the size.
        _congestionAvoidanceAckedBytes = 0;
    }

    /// <summary>RFC 9002 B.5 lines 573-580's growth: slow start below the threshold, additive
    /// increase at or above it.</summary>
    /// <remarks>
    /// <para>THE SLOW START HALF IS B.5 LINE 575 VERBATIM: the window grows by the bytes
    /// acknowledged, which is s7.3.1 lines 122-125's exponential growth.</para>
    /// <para>THE CONGESTION AVOIDANCE HALF IS NOT B.5 LINES 578-580, AND THIS IS THE
    /// DIVERGENCE THAT MATTERS. B.5 writes
    /// <c>congestion_window += max_datagram_size * acked_packet.sent_bytes /
    /// congestion_window</c>. In integer arithmetic that quotient is zero whenever
    /// <c>max_datagram_size * sent_bytes &lt; congestion_window</c> - at a 1200-byte datagram
    /// and full-size packets, whenever the window exceeds 1,440,000 bytes - so a literal
    /// transcription STOPS GROWING PERMANENTLY at about 1.4 MB and reports a perfectly
    /// plausible window while doing it. B.5's own lines 549-552 flag exactly this: "In
    /// congestion avoidance, implementers that use an integer representation for
    /// congestion_window should be careful with division and can use the alternative approach
    /// suggested in Section 2.1 of [RFC3465]." That alternative is the byte counter below: sum
    /// the acknowledged bytes, and add one maximum datagram size each time the sum reaches a
    /// whole congestion window.</para>
    /// <para>IT IS ALSO THE ONLY FORM THAT SATISFIES s7.3.3 EXACTLY. Lines 172-175 require an
    /// AIMD approach that "MUST limit the increase to the congestion window to at most one
    /// maximum datagram size for each congestion window that is acknowledged" - a statement
    /// about a whole window's worth of acknowledgements, which a counter measures and a
    /// per-packet quotient only approximates.</para>
    /// <para>The while loop terminates because the window is positive - the initial window is
    /// at least one multiplier times one byte and no path below reduces it to zero - and the
    /// positivity is nonetheless tested rather than argued, because a loop whose termination
    /// depends on a constructor argument is a hang waiting for a future caller.</para>
    /// </remarks>
    /// <param name="ackedBytes">The size of the packet just acknowledged.</param>
    private void Grow(int ackedBytes)
    {
        if (_congestionWindow < _slowStartThreshold)
        {
            _congestionWindow = SaturatingAdd(_congestionWindow, ackedBytes);
            return;
        }

        _congestionAvoidanceAckedBytes = SaturatingAdd(_congestionAvoidanceAckedBytes, ackedBytes);

        while (_congestionWindow > 0 && _congestionAvoidanceAckedBytes >= _congestionWindow)
        {
            _congestionAvoidanceAckedBytes -= _congestionWindow;
            _congestionWindow = SaturatingAdd(_congestionWindow, _maxDatagramSize);
        }
    }

    /// <summary>RFC 9002 B.5's <c>IsAppOrFlowControlLimited</c>, which RFC 9002 never defines:
    /// was there room in the congestion window for another full datagram that the sender did
    /// not use?</summary>
    /// <remarks>
    /// <para>DEFINED HERE BECAUSE THE DOCUMENT DOES NOT DEFINE IT ANYWHERE. The extract's own
    /// header, lines 21-25, lists <c>IsAppOrFlowControlLimited</c> among seven functions
    /// "called and never defined anywhere in this document". The rule it has to enforce is
    /// s7.8 lines 384-388: "When bytes in flight is smaller than the congestion window and
    /// sending is not pacing limited, the congestion window is underutilized. This can happen
    /// due to insufficient application data or flow control limits. When this occurs, the
    /// congestion window SHOULD NOT be increased in either slow start or congestion
    /// avoidance."</para>
    /// <para>WHY NOT SIMPLY <c>bytes_in_flight &lt; congestion_window</c>, which is what s7.8's
    /// first clause literally says. Because a window is almost never an exact multiple of a
    /// datagram. A sender with a 12,500-byte window and 1,200-byte packets fills it to 12,000
    /// and cannot fit an eleventh packet; under the literal reading it is "under-utilised"
    /// forever and its window never grows again, at any RTT, in either state. The strict
    /// reading of "underutilized" is the one that matches the sentence's own explanation -
    /// "insufficient application data or flow control limits" - and that is: another whole
    /// datagram would have fitted and the sender had nothing to put in it. Hence the
    /// max_datagram_size term. A sender filling its window as tightly as packetisation allows
    /// is not application limited.</para>
    /// <para>WHEN IT IS EVALUATED IS PART OF THE DEFINITION, and is argued at the call site in
    /// <see cref="OnPacketsAcked"/>: once per acknowledgement, on the state before the batch's
    /// bytes are removed. B.5's placement - inside the loop, after the subtraction - makes any
    /// bytes-in-flight-based predicate answer "limited" for every packet after the first.</para>
    /// <para>THE FLOW CONTROL HALF NEEDS NO SEPARATE TEST. A sender blocked by a stream or
    /// connection flow-control limit cannot put bytes in flight, so it is under-utilising the
    /// window by exactly this measure; the two causes s7.8 names are one observation.</para>
    /// <para>THE PACING CLAUSE IS TASK A3-11'S, IT IS STILL NOT HERE, AND THAT IS NOW A NAMED
    /// CEILING RATHER THAN A DEFERRAL. s7.8 lines 390-393: a sender "SHOULD NOT consider itself
    /// application limited if it would have fully utilized the congestion window without pacing
    /// delay". A3-11 added <see cref="TlsQuicPacer"/>, so the premise of the old note - "nothing
    /// paces yet, so no send is delayed" - has gone, and the exemption now has something to
    /// exempt: a pass the pacer holds leaves bytes in flight BELOW the window, this predicate
    /// reads that as under-utilisation, and the window stops growing for a reason that is the
    /// sender's own spacing rather than the network's.</para>
    /// <para>WHY IT IS NOT IMPLEMENTED HERE, STATED SO IT IS NOT MISTAKEN FOR AN OVERSIGHT. The
    /// signal needed is "this send would have gone but for the pacer", which is the SEND PATH's
    /// knowledge and not this class's; nothing in
    /// <see cref="ITlsQuicCongestionController"/> can carry it today, and the seam is where the
    /// decision costs something. Widening it means answering whether a caller's BBR or CUBIC
    /// controller receives the signal too - s7.8 addresses SENDERS, so the honest answer is
    /// probably yes - and that is a knob-shaped decision belonging with task A3-12's readout or
    /// a task of its own, not a line added in passing by the task that happened to build the
    /// pacer. s7.8 itself keeps the door open: "A sender MAY implement alternative mechanisms
    /// to update its congestion window after periods of underutilization".</para>
    /// <para>THE EXPOSURE, BOUNDED. It needs the pacer ON and the pacer BINDING - a sender
    /// trying to put more than a whole burst on the wire inside one RTT - which no test in this
    /// tree does at the shipped default of ten datagrams. It bites first on a bulk transfer,
    /// and the symptom is a window that grows more slowly than it should, never one that grows
    /// wrongly. A caller who cares today can turn pacing off:
    /// <see cref="TlsQuicRecoverySpec.PacingBurstDatagrams"/> null.</para>
    /// </remarks>
    /// <returns>True when the window was under-utilised by at least one whole datagram.</returns>
    private bool IsAppOrFlowControlLimited() =>
        SaturatingAdd(_bytesInFlight, _maxDatagramSize) <= _congestionWindow;

    // Saturating rather than checked, because this class may not throw on a signal path and a
    // wrapped window is worse than a stuck one: a negative congestion window opens the send
    // gate to everything, which is the exact failure a congestion controller exists to
    // prevent. Reaching long.MaxValue bytes in flight requires a caller fabricating packets;
    // reaching it honestly would need more bytes than the connection could ever carry.
    private static long SaturatingAdd(long left, long right)
    {
        var sum = unchecked(left + right);

        // Overflow in two's complement is exactly "the operands agreed in sign and the result
        // did not". Only reachable for a fabricated size, which is why it is a clamp and not
        // an exception.
        if (((left ^ sum) & (right ^ sum)) < 0)
        {
            return left > 0 ? long.MaxValue : long.MinValue;
        }

        return sum;
    }

    // Bytes in flight is clamped at zero rather than allowed to go negative, which is the
    // opposite of the choice TlsQuicConnection.BytesInFlight documents for itself - and
    // deliberately so. There a negative total is a visible report of a double-subtraction bug.
    // Here the same negative would be ARITHMETIC the send gate uses: CanSend would answer true
    // for packets the window has no room for, so a bookkeeping bug upstream would turn into an
    // unbounded send. RFC 9002 gives no dedup rule of its own - A.7's
    // DetectAndRemoveAckedPackets is another of the seven functions the document never defines
    // - so the guarantee that a packet is reported acknowledged, lost or discarded exactly
    // once belongs to the caller, and this clamp bounds the damage when it is broken.
    private static long SaturatingSubtract(long left, long right) =>
        right >= left ? 0 : left - right;
}

// TASK A3-9 - MUTATION LEDGER. 38 rows: 2 controls + 5 the initial and minimum windows +
// 2 the send gate + 3 the ACK-only exclusion + 4 s7.8's predicate + 6 the recovery period's
// boundaries + 5 B.6's reduction + 2 B.8's newest-loss selection + 4 B.5's growth + 5 the
// initialisation, the discard and the arithmetic guards.
// 2 + 5 + 2 + 3 + 4 + 6 + 5 + 2 + 4 + 5 = 38. Killed 35, survived 3; 35 + 3 = 38.
//
// Swept in a private git worktree detached at 1a17be7, pristine HEAD, because another task was
// editing TlsQuicAckTracker.cs in the shared tree at the same time and a sweep there would
// have been scoring its work. The gate figures in this commit are measured in that worktree:
// 2236 passing at pristine HEAD, 2272 after this task, 2272 - 2236 = 36 cases added. Every run
// rebuilt --no-incremental and then tested --no-build, and was rejected unless the runner
// reported at least 2277 EXECUTED cases: an aborted run prints an ordinary
// "Failed: 0, Passed: <m>" line and would otherwise be recorded as a survivor that never ran.
// KILLED-BY-COMPILER is assigned from the build's exit code before any test runs, never parsed
// out of a log where "KILLED" would shadow it. Every row asserted its search string occurred
// EXACTLY ONCE before mutating, so no row could report SURVIVED against pristine source.
//
// TWO ROUNDS, AND THE SECOND IS WHY THIS FILE HAS SIX MORE TESTS THAN IT DID. The first sweep
// left nine rows unwitnessed and two scored KILLED-BY-COMPILER for the wrong reason. Six
// tests were written for the nine, two mutant forms were corrected, and the thirteen affected
// rows were re-run at the higher floor. Rows not re-run keep their first-round verdict; the
// two runs differ only in the six tests added between them, which can turn a survivor into a
// kill and never the reverse.
//
// AND THE ONE THING THE FIRST SWEEP GOT WRONG ABOUT ITSELF. A39-M07 makes CanSend stop gating,
// which made the test helper's "send until the gate refuses" loop spin forever. The suite
// HUNG rather than failed - no summary line, no verdict, and every row after it unrun. A hung
// suite is strictly worse than a wrong answer because it looks identical to a slow one. The
// helper is now bounded and fails with a name, and the harness treats a timeout as a kill
// with no named witness rather than as a crash.
//
// -- controls, proved before anything else was trusted -- 2 rows ---------------------
// A39-C1  an inert comment added to this class ..... SURVIVED  by construction
// A39-C2  Name reports "BBR" instead of "NewReno" .. KILLED    AFreshControllerIsInSlowStart
//         THE OTHER DIRECTION, and the reason C1 alone is not a control: C1 proves the        AtTheSpecsInitialWindow,
//         harness restores the file, C2 proves a mutation reaches compiled code at all.       TheSpecsFactoryKnobProducesAFreshControllerPerCall
//
// -- s7.2, the initial and minimum windows -- 5 rows ---------------------------------
// A39-M01 s7.2's nesting inverted to a max .......... KILLED  ALossInSlowStartEntersRecovery
//         14 tests fail, because every window in this file starts here.
// A39-M02 s7.2's cap floor inverted to a min ........ KILLED  same, 14 tests
// A39-M03 s7.2's cap floor dropped entirely ......... KILLED  TheInitialWindowIsTheMultiple
//                                                             HeldDownToTheLargerOfTheCapAndTheFloor
// A39-M04 the initial window clamped UP to the ...... KILLED  same. s7.2 lines 83-85 scope the
//         minimum window                                      minimum to REDUCTIONS, so a
//         one-datagram initial window is a fingerprint and not a mistake to be corrected.
// A39-M05 the minimum window read as datagrams ...... KILLED  TheWindowNeverFallsBelowThe
//         rather than bytes                                   SpecsMinimumAcrossALongLossSequence
//
// -- s7's send gate -- 2 rows ---------------------------------------------------------
// A39-M06 CanSend refuses a packet landing exactly .. KILLED  TheSendGateAdmitsAPacketLanding
//         on the window (<= to <)                             ExactlyOnTheWindow...
// A39-M07 CanSend ignores bytes in flight ........... KILLED  15 tests. THE ROW THAT HUNG THE
//         FIRST SWEEP; see the note above.
//
// -- A.4's ACK-only exclusion, all three sides -- 3 rows ------------------------------
// A39-M08 OnPacketSent counts ACK-only packets ...... KILLED  AnAckOnlyPacketNeitherCounts
//                                                             InFlightNorGrowsTheWindow...
// A39-M09 OnPacketsAcked drops B.5's in_flight gate . KILLED  same
// A39-M10 OnPacketsLost drops B.8's in_flight gate .. KILLED  LosingAnAckOnlyPacketIsNota
//                                                             CongestionEvent
//
// -- s7.8's undefined predicate -- 4 rows ---------------------------------------------
// A39-M11 the predicate takes s7.8's first clause ... KILLED  AWindowThatIsNotAWholeNumberOf
//         literally (bytes_in_flight < cwnd)                  DatagramsIsStillFullyUtilised
//         THE ROW THE DEFINITION EXISTS FOR. A sender whose window is not a whole number of
//         datagrams is "underutilised" forever under the literal reading and never grows again.
// A39-M12 the predicate never fires ................. KILLED  AnAppLimitedSenderDoesNotGrow
//                                                             ItsWindow
// A39-M13 the predicate always fires ................ KILLED  ASenderThatFilledItsWindowIsNot
//                                                             AppLimitedAndDoesGrow
// A39-M14 the predicate re-evaluated per packet ..... KILLED  AnAcknowledgementInSlowStart
//         AFTER the subtraction, which is B.5's own            GrowsTheWindowByExactlyThe
//         placement                                           BytesAcknowledged
//         THE TRAP IN B.5's OWN PSEUDOCODE. Any bytes-in-flight predicate placed where B.5
//         calls it reads a counter the loop has already drained, and slow start stops doubling.
//
// -- s7.3.2's recovery period, both boundaries -- 6 rows ------------------------------
// A39-M15 the period ends on a packet sent AT the ... KILLED  APacketSentAtTheVeryInstant
//         start instant (> to >=)                             RecoveryBeganIsAnOldPacketOnBothBoundaries
//         [WAS-SURVIVOR] Every other test advances the fake clock between a send and the loss
//         after it, so this boundary could be moved a notch and nothing noticed.
// A39-M16 the period ends on any acknowledgement .... KILLED  AnAcknowledgementOfAPacketSent
//                                                             DuringRecoveryEntersCongestionAvoidance
// A39-M17 growth NOT suppressed for packets .......... KILLED  AWindowfulOfPacketsSentBefore
//         predating the period                                RecoveryDoesNotGrowTheWindowDuringIt
//         [WAS-SURVIVOR] AND THE MOST INSTRUCTIVE ROW HERE. Acknowledging ONE old packet during
//         recovery moves the window by nothing even with the suppression gone, because the
//         reduced window puts the controller in congestion avoidance where a single packet
//         accumulates too little. Only a WHOLE WINDOW of old packets makes the difference
//         visible, and the test that was missing is the one that acknowledges nine.
// A39-M18 B.6's guard deleted: every loss opens a ... KILLED  APacketSentBeforeRecoveryStarted
//         new period                                          DoesNotReduceTheWindowASecondTime
//         THE CLASSIC PLACE NEWRENO IS WRITTEN WRONG. It still looks like a congestion
//         controller and still converges; it just quarters where the RFC halves.
// A39-M19 B.6's guard ANDed with the recovery flag .. KILLED  AStragglingLossFromBeforeAn
//         - the straggler bug                                 EndedRecoveryPeriodStartsNoNewOne
//         AN EARLIER DRAFT OF THIS FILE HAD EXACTLY THIS. Once a period ends, its start time is
//         still the boundary saying which packets predate it; ANDing the flag re-opens recovery
//         for every straggler and halves the window twice for one round trip's losses.
// A39-M20 B.6's guard boundary moved from <= to < ... KILLED  APacketSentAtTheVeryInstant
//                                                             RecoveryBeganIsAnOldPacketOnBothBoundaries
//         [WAS-SURVIVOR] The same blind spot as M15, from the loss side.
//
// -- B.6's reduction -- 5 rows ---------------------------------------------------------
// A39-M21 the reduction takes s7.3.2's PROSE half ... KILLED  TheReductionFollowsTheSpecs
//         instead of the spec's factor                        FactorAndNotTheProsesLiteralHalf
//         THE PLACE THE PROSE AND THE PSEUDOCODE DISAGREE. s7.3.2 lines 142-144 write the
//         number 0.5 into a MUST; B.6 line 596 writes kLossReductionFactor. This file follows
//         B.6, and the test spells both candidate windows - 3,000 and 6,000.
// A39-M22 the minimum-window clamp deleted .......... KILLED  TheWindowNeverFallsBelowThe
//                                                             SpecsMinimumAcrossALongLossSequence
// A39-M23 the minimum-window clamp inverted to a min  KILLED  same
// A39-M24 the period starts at the lost packet's .... KILLED  TheRecoveryPeriodRunsFromThe
//         send time rather than now()                         DetectionInstantAndNotTheLostPacketsSendTime
//         [WAS-SURVIVOR] AND THIS FILE HAD IT WRONG FIRST. B.6 line 595 says now(); the first
//         draft used the lost packet's send time and reasoned its way to it in a comment. Every
//         packet already on the wire when loss was detected then ends the period early.
// A39-M25 the congestion-avoidance accumulator ...... KILLED  ACongestionEventDiscardsThe
//         survives a congestion event                         CongestionAvoidanceAccumulator
//         [WAS-SURVIVOR] Bytes accumulated against a window that has since halved grant the
//         next state an increase earned at twice the size.
//
// -- B.8's newest-loss selection -- 2 rows ----------------------------------------------
// A39-M26 the OLDEST loss reaches OnCongestionEvent . KILLED  ALossBatchIsJudgedByItsNewest
//         instead of the newest                               PacketAndNotItsOldest
//         [WAS-SURVIVOR] Needs a batch spanning two eras - one straggler from before the
//         current period, one genuinely new loss - which no single-packet loss test builds.
// A39-M27 B.8's zero sentinel restored .............. SURVIVED  EQUIVALENT MUTANT
//         NOT UNWITNESSED - UNOBSERVABLE. B.3 starts congestion_recovery_start_time at the same
//         zero the sentinel uses, so B.6's guard already returns early for a zero-instant loss
//         and the two mistakes cancel exactly. No test can distinguish them and none was
//         written. The nullable is kept as hygiene, not as a fix; the doc comment above now
//         says so rather than claiming a defect this sweep disproved.
//
// -- B.5's growth, both states -- 4 rows -------------------------------------------------
// A39-M28 slow start's boundary moved from < to <= .. KILLED  AnAcknowledgementOfAPacketSent
//                                                             DuringRecoveryEntersCongestionAvoidance
// A39-M29 congestion avoidance transcribed LITERALLY  KILLED  5 tests, incl. CongestionAvoidance
//         from B.5's quotient                                 StillGrowsWhereAppendixBsLiteral
//                                                             QuotientWouldBeZero
//         THE DIVERGENCE THAT WOULD HAVE SHIPPED A DEFECT. B.5 lines 578-580's expression
//         evaluates to ZERO for every acknowledgement once the window exceeds max_datagram_size
//         squared - about 1.4 MB here - so a literal transcription stops growing permanently
//         while reporting an ordinary window. B.5's own lines 549-552 warn about it.
//         [WAS KILLED-BY-COMPILER FOR THE WRONG REASON in round one: the mutant form left the
//         accumulator field assigned and never read, which is CS0414 and an error here, so the
//         row scored a compiler kill without ever testing the quotient. The form was corrected
//         and the row re-run.]
// A39-M30 congestion avoidance adds a datagram per .. KILLED  CongestionAvoidanceAddsOne
//         PACKET rather than per window                       DatagramPerWindowAcknowledged...
// A39-M31 slow start grows by a fixed datagram ...... KILLED  SlowStartGrowsByTheBytes
//         rather than the bytes acknowledged                  AcknowledgedAndNotByAWholeDatagram
//         [WAS-SURVIVOR] Every slow start test sent maximum-size packets, where the two are the
//         same number. The witness that was missing acknowledges a 400-byte packet.
//
// -- B.3's initialisation, B.9's discard, the guards, the readout -- 5 rows ---------------
// A39-M32 ssthresh initialised to zero rather than .. KILLED  AFreshControllerIsInSlowStart
//         B.3's infinite                                      AtTheSpecsInitialWindow
// A39-M33 B.9's discard removes nothing from flight . KILLED  DiscardingAPacketRemovesItFrom
//                                                             FlightWithoutTouchingTheWindow
// A39-M34 bytes in flight allowed to go negative .... KILLED  NoSignalThrowsForAnyInput
//                                                             IncludingFabricatedAndDegenerateOnes
// A39-M35 the saturating add wraps instead of ....... SURVIVED  UNREACHABLE BY ANY TERMINATING
//         clamping                                              TEST
//         Reaching the overflow needs roughly 4x10^9 fabricated maximum-size packets in one
//         run. NO TEST WAS WRITTEN FOR IT, because the only test that could reach it would not
//         finish, and a test that asserts the clamp by calling a private helper would assert
//         the implementation rather than the behaviour. Kept as a guard: a wrapped window is
//         NEGATIVE, and a negative window opens the send gate to everything.
// A39-M36 State ignores the recovery flag ........... KILLED  9 tests, incl. ADatagramThe
//                                                             ImpairingTransportDropsDrives
//                                                             TheControllerIntoRecovery
//         [WAS KILLED-BY-COMPILER FOR THE WRONG REASON in round one, same CS0414 cause as M29;
//         re-run with the sanctioned `COND && false` form.]

// TASK A3-10 - MUTATION LEDGER. 30 rows: 2 controls + 6 s7.6.2's collapse + 7 s7.6.1's
// duration + 11 s7.6.2's four clauses + 4 A3-9 pins re-verified.
// 2 + 6 + 7 + 11 + 4 = 30. Killed 26, killed by the compiler 1, survived 3;
// 26 + 1 + 3 = 30.
//
// Swept in a private git worktree detached at 889509c, pristine HEAD, because another task was
// editing TlsQuicConnection.cs and TlsQuicLossDetection.cs in the shared tree at the same time
// and a sweep there would have been scoring its work. THE GATE FIGURES IN THIS COMMIT ARE
// MEASURED IN THAT WORKTREE AND NOT INHERITED FROM A BRIEF: 2294 passing / 0 failing / 5
// skipped at pristine 889509c, 2315 / 0 / 5 after this task, 2315 - 2294 = 21 cases added,
// which is exactly the 21 [Fact]s below. (A3-9's commit message says 2272, which was true at
// 1a17be7 and stopped being true when A3-6 landed 22 cases at 2d805be. It was measured again
// rather than copied.)
//
// Every run rebuilt --no-incremental and then tested --no-build, and was rejected unless the
// runner reported at least 2315 EXECUTED cases - an aborted run prints an ordinary
// "Failed: 0, Passed: <m>" line and would otherwise be recorded as a survivor that never ran.
// KILLED-BY-COMPILER is assigned structurally from the build's exit code before any test runs,
// never parsed out of a log. Every row asserted its search string occurred EXACTLY ONCE before
// mutating, and the harness re-reads and compares every mutated file at the end, so no row can
// report SURVIVED against source it silently failed to restore.
//
// AND THE CONTROLS ARE A PAIR FOR A REASON THIS SUBSYSTEM LEARNED THE HARD WAY. `if (true)` and
// `if (false)` are both CS0162 here, which is an error, so a control written that way scores
// KILLED-BY-COMPILER and never executes - a self-check that always passes and proves nothing.
// A310-C2 is an arithmetic change that compiles, runs, and names four witnesses, so it proves
// the harness reaches compiled code; A310-C1 is inert and proves the harness restores the file.
//
// -- controls -- 2 rows ---------------------------------------------------------------
// A310-C1  an inert comment in TlsQuicPersistentCongestion  SURVIVED  by construction
// A310-C2  the collapse lands on _minimumWindow + 1 ....... KILLED    4 tests, incl.
//                                                                     TheCollapseAssignsThe
//                                                                     MinimumRatherThanReducingTowardIt
//
// -- s7.6.2's collapse -- 6 rows --------------------------------------------------------
// A310-M01 OnPersistentCongestion does nothing at all ..... KILLED  5 tests
// A310-M02 the collapse becomes Math.Min(window, minimum) . KILLED  TheCollapseAssignsTheMinimum
//                                                                   RatherThanReducingTowardIt
//          THE MUTANT THE NATURAL WORDING INVITES. "Collapse" reads as a reduction, and a
//          reduction is silently wrong: s7.6.2 lines 276-279 name the VALUE. It is only visible
//          through a spec whose initial window is below its own minimum, which A3-9's A39-M04
//          deliberately allows - so this row and that one hold each other up.
// A310-M03 B.8 line 640's congestion_recovery_start_time . KILLED  TheCollapseDiscardsTheRecovery
//          = 0 dropped                                              PeriodsStartTimeSoAStraggler
//                                                                   StillOpensANewOne
//          [WAS-SURVIVOR] State consults the recovery FLAG first, so clearing the flag alone
//          hides the stale timestamp completely. It surfaces only on a loss of a packet sent
//          BEFORE the discarded period, which B.6's guard then swallows - the sender takes no
//          congestion event for it at all. The witness that was missing loses a straggler.
// A310-M04 the recovery flag not cleared .................. KILLED  2 tests
// A310-M05 the congestion-avoidance accumulator survives .. KILLED  TheCollapseDiscardsThe
//          the collapse                                             CongestionAvoidanceAccumulator
//          [WAS-SURVIVOR] Reachable, not vacuous - but only when the collapse lands in
//          congestion avoidance rather than slow start, which needs a spec whose minimum window
//          is at or above the surviving ssthresh. Every other test here collapses into slow
//          start, where the accumulator is not read at all.
// A310-M06 the collapse also zeroes bytes in flight ....... KILLED  TheCollapseLeavesBytesInFlightAlone
//
// -- s7.6.1's duration, ALL OF IT DERIVED FROM PROSE -- 7 rows ---------------------------
// A310-M07 the threshold hard-coded to 3 rather than ...... KILLED  ThePersistentCongestion
//          read from knob 8                                         DurationIsSection761sFormula
//                                                                   OverALiveEstimator
// A310-M08 the threshold dropped entirely ................. KILLED  4 tests
// A310-M09 max_ack_delay dropped - s6.2.1's space rule .... KILLED  4 tests, incl.
//          leaking in                                               TheDurationIncludesMaxAckDelay
//                                                                   ForEverySpace...
//          s7.6.1 lines 216-219 overrule s6.2.1 in as many words: this duration includes
//          max_ack_delay "IRRESPECTIVE of the packet number spaces in which losses are
//          established", where A.8 adds it for Application Data only. A handshake-space blackout
//          judged by s6.2.1's rule is declared persistently congested sooner than s7.6 allows.
// A310-M10 the kGranularity floor on 4*rttvar dropped ..... KILLED  2 tests
// A310-M11 the floor moved from the rttvar TERM to the .... KILLED  TheFourRttvarTermIsFloored
//          whole SUM                                                AtTheTimerGranularityAndNot
//                                                                   TheWholeSum
//          THE DEFECT THIS SUBSYSTEM ALREADY FOUND ONCE, at s6.2.1, in the other direction. The
//          parentheses in s7.6.1's line put max(...) around one term; a floor on the sum is
//          invisible whenever smoothed_rtt already exceeds kGranularity, which is always.
// A310-M12 the 4 in 4*rttvar becomes 1 .................... KILLED  2 tests
// A310-M13 the negative-input clamps removed .............. KILLED  TheDurationIsTotalAndStrictly
//                                                                   PositiveForEveryInput...
//          NOT PEDANTRY. A negative smoothed_rtt cancels the other terms, the duration goes
//          non-positive, and EVERY pair of losses then exceeds it - the window collapses to the
//          minimum on any loss at all. One-sided and catastrophic, so it is guarded even though
//          A3-4's estimator cannot produce the input.
//
// -- s7.6.2's four clauses, and B.8's argument list is where the defect is -- 11 rows -----
// A310-M14 the ack-eliciting filter dropped, which is ..... KILLED  ABlackoutOfAckOnlyPacketsIs
//          exactly what B.8's pc_lost gives you                     NotPersistentCongestion
//          B.8 lines 636-638 build pc_lost with NO ack-eliciting filter while s7.6.2 line 258
//          says the two packets "MUST be ack-eliciting". A body written to match B.8's call site
//          drops this clause, and a silence of ACK-only packets - which the peer was never
//          obliged to acknowledge - then reads as a blackout.
// A310-M15 B.8 line 635's early return on no RTT sample ... KILLED  WithNoRttSampleYetNothingIs
//          dropped                                                  PersistentCongestion
// A310-M16 B.8 line 637's per-packet first_rtt_sample ..... KILLED  PacketsSentBeforeTheFirstRtt
//          filter dropped - the half an implementation              SampleAreNotCandidates...
//          forgets, because the early return looks sufficient
// A310-M17 that filter's boundary moved from <= to < ...... KILLED  same
//          [WAS-SURVIVOR] The first draft of that test paired the boundary packet with one a
//          single tick away, so admitting the boundary packet changed the candidate COUNT and
//          nothing else - the span was far below the duration either way and the verdict never
//          moved. The pair is now separated by more than the duration, so the one-tick boundary
//          is the only thing deciding it.
// A310-M18 the acknowledged-send-time clause dropped ...... KILLED  AnAcknowledgementInsideThe
//          entirely - s7.6.2's second bullet, which B.8's            BlackoutPreventsPersistent
//          pc_lost argument CANNOT express                           Congestion
// A310-M19 that clause's boundary moved from < to <= ...... KILLED  same
//          AND THIS FILE HAD IT WRONG FIRST, caught by a failing test rather than by the sweep.
//          s7.6.2 line 252 says packets "sent BETWEEN the send times of these two packets", and
//          between excludes its endpoints - so an acknowledgement of a packet sent at the very
//          instant the oldest lost packet was sent does not disqualify the window. Written <=,
//          a sender that fills its window in a burst loses every qualifying blackout, because
//          several packets share one timestamp and only some come back.
// A310-M20 "exceeds" read as >= .......................... KILLED  ABlackoutExactlyEqualToThe
//                                                                   DurationIsNotPersistent
//                                                                   CongestionBecauseExceedsIsStrict
//          s7.6.3's worked example is 7 against 6 and never touches the boundary, so the word is
//          the only evidence. One tick early, and no test built out of round numbers sees it.
// A310-M21 s7.6.2's "two packets" relaxed to one ......... SURVIVED  EQUIVALENT MUTANT
//          NOT UNWITNESSED - UNOBSERVABLE, AND HERE IS THE ARITHMETIC. The guard one line above
//          returns false for any duration <= 0, so every comparison below runs with duration > 0.
//          With ONE candidate, newest and oldest are the same instant, the span is exactly 0,
//          and 0 > duration is false. With ZERO candidates the sentinels stand: newest is
//          DateTimeOffset.MinValue and oldest is MaxValue, so the span is about -3.15e18 ticks,
//          which is also not greater than a positive duration. Both cases already answer false,
//          so no test can distinguish the two forms and none was written. The check is kept
//          because s7.6.2 leads with "two packets that are ack-eliciting are declared lost" and
//          a reader must be able to see that clause in the code - not because it is load-bearing
//          today. THE SAME SHAPE AS A39-M27, and recorded the same way rather than dressed up.
// A310-M22 the non-positive-duration guard dropped ....... KILLED  NoPersistentCongestionInput
//                                                                  ThrowsIncludingFabricatedAnd
//                                                                  DegenerateOnes
// A310-M23 the null-list guard dropped ................... KILLED-BY-COMPILER  error CS8602
//          STRUCTURALLY ASSIGNED FROM THE BUILD'S EXIT CODE, before any test ran. The nullable
//          reference analysis refuses to dereference the parameter with its own null check
//          removed, so this guard is enforced twice over - by the compiler and by the totality
//          test that would have caught it at runtime.
// A310-M24 oldest and newest swapped ..................... KILLED  7 tests
//
// -- A3-9's pins, re-verified against this task's change -- 4 rows -----------------------
// A39-M27  B.8's zero sentinel restored ................. SURVIVED  STILL EQUIVALENT
//          RE-RUN BECAUSE THIS TASK COULD HAVE MADE IT OBSERVABLE AND DID NOT. A3-9 proved the
//          two mistakes cancel: B.3 starts congestion_recovery_start_time at the same zero the
//          sentinel uses, so B.6's guard already returns early for a zero-instant loss.
//          OnPersistentCongestion now writes that same zero BACK - B.8 line 640 - so after a
//          collapse the controller is in exactly the state B.3 left it in, and the cancellation
//          holds for the same reason it held before. The sweep confirms it: 0 of 2315 failed.
//          The classification is unchanged.
// A39-M04  the initial window clamped UP to the minimum .. KILLED  TheCollapseAssignsTheMinimum
//                                                                  RatherThanReducingTowardIt,
//                                                                  TheInitialWindowIsTheMultiple
//                                                                  HeldDownToTheLargerOfTheCap...
//          RE-RUN BECAUSE THIS TASK NOW DEPENDS ON IT. A310-M02's witness is a spec whose window
//          starts below its own minimum, which only exists because A3-9 refused this clamp.
// A39-M36  State ignores the recovery flag .............. KILLED  12 tests, now including
//                                                                 AScriptedBlackoutOneInterval
//                                                                 ShorterIsLossButNotPersistent
//                                                                 Congestion
// A39-M22  the minimum-window clamp in B.6 deleted ...... KILLED  2 tests, now including
//                                                                 TheCollapseDiscardsTheCongestion
//                                                                 AvoidanceAccumulator
//
// WHAT THIS TASK DID NOT DO, NAMED SO IT IS NOT MISTAKEN FOR AN OVERSIGHT. Nothing calls
// TlsQuicPersistentCongestion from TlsQuicConnection.cs or TlsQuicLossDetection.cs. Both files
// were being edited by another task while this one ran, and A3-6 and A3-9 both stopped at that
// boundary rather than reach across it, which is why this subsystem's history is clean. The
// call site is three lines - OnPacketsLost, then IsEstablished, then OnPersistentCongestion, in
// B.8's order - and the shape is pinned by RunScriptedBlackoutAsync, which performs exactly
// those three lines against loss the impairing transport really produced.

// ============================================================================
// TASK A3-11 - RFC 9002 s7.7's PACER, AND WHY ITS DERIVATION IS WRITTEN OUT HERE
// ============================================================================
//
// THERE IS NO PSEUDOCODE FOR THIS AND THAT IS THE WHOLE REASON FOR THE LENGTH BELOW. Appendix
// A and Appendix B between them transcribe every other algorithm in RFC 9002 - OnPacketSent,
// OnAckReceived, DetectAndRemoveLostPackets, OnPacketsAcked, OnPacketsLost, the constants.
// s7.7 has NONE. Task A3-0 established that "s7.7 pacing and s7.6.1's duration are prose only",
// and A3-10 wrote s7.6.1's derivation into its source for the same reason this one is written
// here: THE NEXT READER CANNOT CHECK THIS AGAINST A LISTING. Everything below has to be
// checkable against the two lines of arithmetic the section prints and against nothing else,
// so those two lines are quoted verbatim and every step away from them is named.
//
// THE TWO LINES, rfc9002-section7-congestion-control.txt lines 361-368, verbatim:
//
//     rate = N * congestion_window / smoothed_rtt
//
//     interval = ( smoothed_rtt * packet_size / congestion_window ) / N
//
// THEY ARE THE SAME STATEMENT AND THIS FILE IMPLEMENTS THE FIRST. `interval` is `packet_size /
// rate` with the first line substituted in, so a pacer that tracks a RATE and one that tracks
// an INTERVAL cannot disagree about when a packet leaves. The rate form is implemented because
// it is the one that composes with a burst: an interval is a statement about two consecutive
// packets and says nothing about how many may leave at once, while a rate plus a bucket
// capacity says both. s7.7 lines 378-381 name that structure itself - "One possible
// implementation strategy for pacing uses a leaky bucket algorithm, where the capacity of the
// bucket is limited to the maximum burst size and the rate the bucket fills is determined
// by the above function" - so the bucket is the RFC's own suggestion and not an invention here.
//
// THE UNITS, SPELLED OUT, BECAUSE THIS IS WHERE A PROSE-ONLY FORMULA GOES WRONG SILENTLY.
// congestion_window is BYTES (s7 lines 43-44: "The algorithm in this document specifies and
// uses the controller's congestion window in bytes"). smoothed_rtt is a DURATION. So `rate` is
// BYTES PER UNIT TIME, and the implementation must pick one time unit and hold it: seconds are
// used below, TimeSpan.TotalSeconds is the only conversion, and no other unit appears. A
// version of this that mixed ticks into the numerator and seconds into the denominator would
// be wrong by a factor of ten million and would still pace - just seven orders of magnitude
// off, which no invariant test and no round trip would catch.
//
// N IS A KNOB AND NOT A CONSTANT - TlsQuicRecoverySpec.PacingIntervalScale, knob 15. s7.7
// lines 369-371 bound it only as "small, but at least 1 (for example, 1.25)". This file holds
// no numeral for it, exactly as the rest of this file holds none for the window constants.
//
// WHAT IS DELIBERATELY NOT PACED, EACH WITH THE SENTENCE THAT EXEMPTS IT:
//
//   ACK-ONLY DATAGRAMS. s7.7 lines 353-355: "Timely delivery of ACK frames is important for
//   efficient loss recovery. To avoid delaying their delivery to the peer, packets containing
//   only ACK frames SHOULD therefore not be paced." The exemption is structural rather than a
//   test in this class: the send path consults the pacer only where it is about to add
//   IN-FLIGHT frames, so a pass that produces nothing but an ACK never reaches this code at
//   all. See TlsQuicApplicationSendPath's SendGateAdmits.
//
//   PTO PROBES. s7.5 lines 195-196: "Probe packets MUST NOT be blocked by the congestion
//   controller." The pacer is not the congestion controller, but a pacer that held a probe
//   would reintroduce the deadlock the probe exists to break - RFC 9000 s8.1's anti-deadlock
//   probe is the case task A3-7 closed - so the probe path does not consult this class either.
//
// AND THE PROOF THAT THIS CANNOT WEDGE A CONNECTION, WHICH IS THE ONE PROPERTY A PACER MUST
// CARRY. A pacer that never releases is indistinguishable from a hang. Three facts together
// make the wait finite:
//
//   (i)   The bucket's capacity is at least one datagram, because the burst is at least one
//         datagram (TlsQuicRecoverySpec.PacingBurstDatagrams refuses zero) - so there is no
//         packet the bucket can never hold.
//   (ii)  The refill rate is strictly positive whenever it is used at all: N is validated
//         positive and finite, and the two remaining factors are checked before the division
//         rather than assumed - a non-positive congestion window or a non-positive smoothed
//         RTT ADMITS rather than defers. A pacer that deferred on a zero rate would wait for
//         ever by arithmetic.
//   (iii) The computed wait is clamped to one smoothed RTT. The clamp is derived, not picked:
//         at the paced rate a whole congestion window leaves in smoothed_rtt / N, so nothing
//         that fits in a window can honestly need longer than an RTT of credit, and s7.7 lines
//         374-376 license the deviation in the sender's own direction - "Practical
//         considerations, such as packetization, scheduling delays, and computational
//         efficiency, can cause a sender to deviate from this rate". The clamp releases EARLY
//         and never late, so it can only ever weaken the pacing, never stall it.
//
// A fourth fact belongs to the connection rather than to this class and is recorded where it
// lives: the release instant joins TlsQuicConnection's EarliestDeadline earliest-of table, and
// that table's own note already argues that adding an entry "can only ever SHORTEN a wait that
// already terminated at HEAD, never lengthen one" - the handshake deadline and RFC 9000
// s10.1's idle timeout are re-read on every wake and still end the attempt.

/// <summary>RFC 9002 s7.7's pacer: a leaky bucket whose capacity is the spec's burst and whose
/// fill rate is <c>N * congestion_window / smoothed_rtt</c>.</summary>
/// <remarks>
/// <para>ONE PER CONNECTION AND NOT SHARED, for the reason s7 lines 39-41 give the congestion
/// controller: "The congestion controller is per path". The rate is read off the controller on
/// every call rather than cached, so a window that moves moves the pacing with it and there is
/// no second copy of a number to keep in step.</para>
/// <para>NOTHING HERE THROWS AFTER CONSTRUCTION, for the reason
/// <see cref="ITlsQuicCongestionController"/>'s remarks give: this is on the send path, its
/// inputs are a live congestion window and a live RTT estimate, and a pacer that threw would
/// take the connection down at the moment the network was already misbehaving.</para>
/// <para>DISABLED IS A REAL STATE AND NOT A ZERO RATE. A null burst makes
/// <see cref="IsEnabled"/> false and <see cref="TryTake"/> admit everything without reading a
/// clock, which is what "this client does not pace" means on the wire: the datagrams leave in
/// the order and at the instants the send path produced them, byte for byte identical to a
/// build with no pacer in it at all.</para>
/// </remarks>
internal sealed class TlsQuicPacer
{
    private readonly long _capacityBytes;
    private readonly double _intervalScale;
    private readonly long _maxDatagramSize;

    private double _creditBytes;
    private DateTimeOffset _lastRefill;
    private bool _refillStarted;

    /// <summary>Builds a pacer for one path from knobs 14 and 15.</summary>
    /// <param name="spec">The spec carrying the burst and the interval scale.</param>
    /// <param name="maxDatagramSize">RFC 9002 B.2's <c>max_datagram_size</c>, which is
    /// <c>TlsQuicConnectionSpec.PaddingTarget</c> here for the reason the controller's own
    /// construction note gives.</param>
    /// <exception cref="ArgumentNullException"><paramref name="spec"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxDatagramSize"/> is not
    /// positive.</exception>
    internal TlsQuicPacer(TlsQuicRecoverySpec spec, int maxDatagramSize)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            maxDatagramSize, nameof(maxDatagramSize));

        _maxDatagramSize = maxDatagramSize;
        _intervalScale = spec.PacingIntervalScale;

        // s7.7 lines 342-344: "Senders SHOULD limit bursts to the initial congestion window;
        // see Section 7.2." The burst is expressed in DATAGRAMS by the knob and in BYTES here,
        // because that is the unit the rate and the packet sizes are in - and knob 14's own
        // default is written as the initial window's datagram count for exactly this reason.
        _capacityBytes = spec.PacingBurstDatagrams is { } burst
            ? (long)burst * maxDatagramSize
            : 0;

        // THE BUCKET STARTS FULL, WHICH IS WHAT A BURST ALLOWANCE MEANS. s7.7 permits a burst
        // of the initial congestion window; a bucket that started empty would space out the
        // very first window, which is the one case the section explicitly allows to go out
        // together.
        _creditBytes = _capacityBytes;
    }

    /// <summary>Whether this client paces at all: knob 14's on/off position.</summary>
    internal bool IsEnabled => _capacityBytes > 0;

    /// <summary>The bucket's capacity in bytes - the burst, in the unit the rate is in.
    /// </summary>
    internal long CapacityBytes => _capacityBytes;

    /// <summary>The bucket's current contents in bytes, rounded down.</summary>
    /// <remarks>A witness rather than a control. A test that could see only whether a send was
    /// admitted could not tell a pacer that refills at the right rate from one that refills at
    /// any other.</remarks>
    internal long CreditBytes => (long)_creditBytes;

    /// <summary>How many times this pacer has deferred a send.</summary>
    /// <remarks>THE ASSERTION THAT THE PACER ENGAGED AT ALL. A transfer that completes proves
    /// nothing about pacing - it completes with the pacer off too - so every live test asserts
    /// this moved.</remarks>
    internal int Deferrals { get; private set; }

    /// <summary>When the deferred send may leave, or <see langword="null"/> if nothing is
    /// currently deferred.</summary>
    /// <remarks>THE ENTRY, NOT A TIMER. This is read by
    /// <c>TlsQuicConnection.EarliestDeadline</c> and raced against the deadlines already there,
    /// which is task A3-5's weave rather than a scheduler of this class's own. Cleared by the
    /// take that succeeds, so a pump that sent does not wake itself again for nothing.</remarks>
    internal DateTimeOffset? ReleaseAt { get; private set; }

    /// <summary>The burst in the unit knob 14 states it in, recovered from the byte capacity so
    /// that no second literal exists.</summary>
    internal int BurstDatagrams =>
        _capacityBytes <= 0 ? 0 : (int)(_capacityBytes / _maxDatagramSize);

    /// <summary>Asks whether <paramref name="bytes"/> of in-flight data may leave now, and if
    /// not, records when it may.</summary>
    /// <remarks>
    /// <para>THE CREDIT IS SPENT ONLY ON SUCCESS. A refused call leaves the bucket untouched,
    /// so asking twice costs nothing and a caller that asks and then does not send has not
    /// silently consumed an allowance.</para>
    /// <para>NON-POSITIVE <paramref name="bytes"/> IS ADMITTED AND SPENDS NOTHING, matching
    /// <see cref="ITlsQuicCongestionController.CanSend"/>'s treatment of the same nonsense:
    /// answered rather than rejected.</para>
    /// </remarks>
    /// <param name="bytes">The in-flight bytes the send path is about to add.</param>
    /// <param name="now">The pump's instant, which is the same instant every other decision in
    /// this pass is made at.</param>
    /// <param name="congestionWindowBytes">s7.7's <c>congestion_window</c>, read live off the
    /// controller.</param>
    /// <param name="smoothedRtt">s7.7's <c>smoothed_rtt</c>.</param>
    /// <returns>True when the send may go now.</returns>
    internal bool TryTake(
        int bytes, DateTimeOffset now, long congestionWindowBytes, TimeSpan smoothedRtt)
    {
        if (!IsEnabled || bytes <= 0)
        {
            ReleaseAt = null;
            return true;
        }

        // FACT (ii) OF THE ANTI-WEDGE PROOF, CHECKED AND NOT ASSUMED. A rate needs a positive
        // window and a positive RTT; without either there is no rate s7.7 defines, and the
        // honest answer to "how long until credit accrues" is "never". ADMITTING is the only
        // safe reading: the congestion window is already refused separately by s7's own gate,
        // and a smoothed RTT of zero means no sample has been taken, which is the state a
        // connection is in before it has sent anything worth pacing.
        var rate = RateBytesPerSecond(congestionWindowBytes, smoothedRtt);
        if (rate <= 0)
        {
            ReleaseAt = null;
            return true;
        }

        Refill(now, rate);

        if (_creditBytes >= bytes)
        {
            _creditBytes -= bytes;
            ReleaseAt = null;
            return true;
        }

        Deferrals++;
        ReleaseAt = Advance(now, WaitFor(bytes - _creditBytes, rate, smoothedRtt));
        return false;
    }

    // s7.7 line 361 exactly: rate = N * congestion_window / smoothed_rtt. In bytes per SECOND,
    // and TotalSeconds is the only unit conversion in this class.
    private double RateBytesPerSecond(long congestionWindowBytes, TimeSpan smoothedRtt)
    {
        if (congestionWindowBytes <= 0 || smoothedRtt <= TimeSpan.Zero)
        {
            return 0;
        }

        var rate = _intervalScale * congestionWindowBytes / smoothedRtt.TotalSeconds;

        // A caller cannot reach this with a non-finite scale - knob 15 validates it - but the
        // product of a finite scale and a finite window can still overflow to infinity, and an
        // infinite rate would make every wait NaN rather than zero. Treated as "no rate", which
        // admits; see the note at the call site.
        return double.IsFinite(rate) && rate > 0 ? rate : 0;
    }

    private void Refill(DateTimeOffset now, double rate)
    {
        if (!_refillStarted)
        {
            _refillStarted = true;
            _lastRefill = now;
            return;
        }

        var elapsed = now - _lastRefill;

        // A CLOCK THAT WENT BACKWARDS ADDS NOTHING AND IS NOT AN ERROR. TimeProvider makes no
        // monotonicity promise about GetUtcNow, and a negative elapsed multiplied by the rate
        // would DRAIN the bucket for a reason that has nothing to do with sending.
        if (elapsed <= TimeSpan.Zero)
        {
            return;
        }

        _lastRefill = now;

        var added = rate * elapsed.TotalSeconds;
        if (!double.IsFinite(added))
        {
            // A very long stall times a finite rate. The bucket is capped anyway, so the
            // saturated answer and the arithmetic one are the same value.
            _creditBytes = _capacityBytes;
            return;
        }

        _creditBytes = Math.Min(_capacityBytes, _creditBytes + added);
    }

    // FACT (iii) OF THE ANTI-WEDGE PROOF. The honest wait is deficit / rate; the clamp is one
    // smoothed RTT, because at this rate a whole congestion window leaves in smoothed_rtt / N
    // and nothing that fits in a window can need longer. The floor of one tick keeps the
    // release instant STRICTLY in the future, so the deadline this becomes cannot be one the
    // pump has already passed and re-wake immediately in a spin.
    private static TimeSpan WaitFor(double deficitBytes, double rate, TimeSpan smoothedRtt)
    {
        var seconds = deficitBytes / rate;

        // THE CLAMP IS APPLIED IN DOUBLES, BEFORE THE CONVERSION, AND A MUTATION SWEEP'S
        // TOTALITY ROW IS WHY. TimeSpan.FromSeconds THROWS an OverflowException for a duration
        // it cannot represent, and a finite double can be far larger than TimeSpan.MaxValue -
        // so a version of this that converted first and clamped afterwards took the connection
        // down for a very small rate, which is exactly the arithmetic a pacer must survive.
        // NaN fails every comparison, so `!(seconds > 0)` catches it here as well.
        if (!(seconds > 0) || seconds > smoothedRtt.TotalSeconds)
        {
            return smoothedRtt > TimeSpan.Zero ? smoothedRtt : new TimeSpan(1);
        }

        var wait = TimeSpan.FromSeconds(seconds);
        return wait > TimeSpan.Zero ? wait : new TimeSpan(1);
    }

    // The same hazard one level up: a smoothed RTT near TimeSpan.MaxValue would push the
    // release instant past DateTimeOffset.MaxValue and throw. The connection cannot reach it -
    // an RTT estimate is measured off a clock - so this is a bound rather than a behaviour, and
    // it is here because "nothing on the send path throws for any input" is a claim about
    // fabricated input too.
    private static DateTimeOffset Advance(DateTimeOffset now, TimeSpan wait)
    {
        var room = DateTimeOffset.MaxValue - now;
        return wait < room ? now + wait : DateTimeOffset.MaxValue;
    }
}

// ============================================================================
// TASK A3-11 - MUTATION LEDGER. 32 rows, contiguous A311-C1, A311-C2, A311-M01 .. A311-M30.
// ============================================================================
//
// THE ARITHMETIC, SHOWN. 2 controls + 14 the pacer (M01-M14) + 4 s7's send gate (M15-M18) +
// 4 s7's second exception (M19-M22) + 2 s7.7 on the send path (M23-M24) + 4 A3-5's deadline
// table (M25-M28) + 1 the order of the two gates (M30) + 1 A3-8's row M48 re-run (M29).
// 2 + 14 + 4 + 4 + 2 + 4 + 1 + 1 = 32. The row numbers run M01..M30 with no gaps; M29 and M30
// are listed last because they were added after the first sweep and their NUMBERS are the order
// they were written, not the order they are read.
//
// WHERE IT WAS RUN, AND WHY NOT IN THE SHARED TREE. A private git worktree detached at
// ebdcc89 - pristine HEAD - with this task's files copied in. Nothing else was in SharpTls, but
// a sweep writes a mutant into a source file and restores it, and doing that in the tree the
// gate is measured from is how a "dead sweep leaves a mutant applied" becomes a commit.
//
// THE BASELINE WAS MEASURED, NOT INHERITED, AND THAT IS NOT A FORMALITY. The brief for this
// task carried 2406/0/5 and warned that twenty-seven agents in a row had inherited a stale
// figure. It was re-measured at pristine ebdcc89 in a second private worktree: 2406 passing, 0
// failing, 5 skipped. The brief was right this time. The SAME BRIEF's other inherited figure was
// NOT: it said TlsQuicConnection.cs stood at 1404 code lines and the same `grep -vcE` returns
// 1443 at that commit - see this task's note beside A3-7's in TlsQuicConnection.cs.
//
// WHAT THE HARNESS ENFORCES STRUCTURALLY, mutate-a3-11.py in the worktree:
//   * KILLED-BY-COMPILER is assigned from the BUILD's exit code, before any test runs. It is
//     never parsed out of a log, where a test name containing "KILLED" would shadow it.
//   * Every row asserted its search string occurred EXACTLY ONCE before mutating. All 32 did,
//     checked in one pass before the sweep started; a row that did not would have been reported
//     BAD-SEARCH rather than silently scoring pristine source.
//   * Every run was rejected unless the runner reported at least 2428 EXECUTED cases (passed +
//     failed; the 5 skips are excluded). An aborted run prints an ordinary
//     "Failed: 0, Passed: <m>" line and would otherwise be recorded as a survivor that never ran.
//   * EVERY WAIT IS BOUNDED, which matters more here than in any earlier sweep in this
//     subsystem because half these rows are TIMING mutations. The build carries a 420-second
//     cap and the test run a 900-second one, and a timeout is recorded as KILLED-BY-TIMEOUT
//     with no named witness - never as a survivor and never as a crash. Inside the suite the
//     bounds are the tests' own: every live test runs under a 60-second CancellationTokenSource,
//     and RunPacingScriptAsync's release loop is capped at 32 attempts with a named failure, so
//     a pacer that never released fails by name instead of hanging. A3-9's sweep hung on a mutant
//     exactly like these and lost every row after it; none of these did.
//   * The mutated file is restored in a `finally`, and the sweep's own restart proved it: the
//     first run of this sweep was killed mid-row on purpose (see below) and `git status` in the
//     worktree came back clean before it was restarted.
//
// AND THE SWEEP WAS RESTARTED FROM SCRATCH ONCE, WHICH IS WORTH RECORDING RATHER THAN HIDING.
// Six rows into the first run, reading the source for another reason turned up a real defect in
// SendGateAdmits: s7.3.2's single-packet exemption was consumed BEFORE s7.7's pacer had been
// asked, so a pass the pacer then held burned the grant and the release pass that followed found
// the window shut and the exemption gone. The comment beside it claimed "the packet still
// leaves". It did not. A sweep against source that is not the source that ships is worth
// nothing, so the run was killed - matched by command line, never by image name - the fix and
// its witness (TheRecoveryExemptionSurvivesAPassThePacerHoldsAndIsSpentOnTheRelease) landed, and
// the whole 32 rows were run again from a re-synced worktree. Row A311-M30 is that defect,
// re-injected as a mutant.
//
// TWO KNOWN DIFFERENCES BETWEEN THE SWEPT TREE AND THE COMMITTED ONE, both in the conservative
// direction and both named rather than glossed:
//   (1) The swept tree's gate is 2428 cases; the committed one is 2429. The extra case is
//       APacerHoldingOrdinaryDataDoesNotHoldThePtoProbeInTheSamePump, written after the sweep
//       started. A test added between two runs can turn a survivor into a kill and never the
//       reverse - A3-9's ledger states the same rule - so every verdict below is the WORST case.
//       And it can change none of them in fact: no row in this table mutates the probe path,
//       because the probe path's exemption from both gates is STRUCTURAL - SendOwedProbeAsync
//       simply does not call SendGateAdmits - so there is no line for a mutant to edit.
//   (2) Comment-only edits landed in TlsQuicConnection.cs and TlsQuicCongestionControl.cs while
//       the sweep ran: the re-measured line count, and s7.8's pacing clause re-stated as a named
//       ceiling now that a pacer exists. Neither changes a compiled byte and neither is a search
//       string for any row.
//
// COUNTS ARE PER xUNIT CASE, so a three-row Theory failing in every row counts 3. Where a row
// says ONLY, that test was the entire failure set.
// A311-C1 [cong] an inert comment added to the pacer                     SURVIVED
// A311-C2 [cong] BurstDatagrams reports bytes instead of datagrams       KILLED  TheBucketStartsAtTheSpecsBurstAndTheFirstSendPastItIsHeld; TheBurstIsTheSpecsAndTheHoldHappensExactlyThere
// A311-M01 [cong] s7.7's burst read as bytes rather than datagrams       KILLED  82 tests, incl. ABidirectionalStreamCarriesBytesBothWaysOverTheLoopbackPeer
// A311-M02 [cong] the bucket starts EMPTY instead of full                KILLED  81 tests, incl. ABidirectionalStreamCarriesBytesBothWaysOverTheLoopbackPeer
// A311-M03 [cong] IsEnabled true for a null burst - no off switch        KILLED  3 tests, incl. APacerWithNoBurstIsOffAndAdmitsEverythingWithoutDeferringOnce
// A311-M04 [cong] credit spent before the test, so a refusal drains it   KILLED  TheBucketStartsAtTheSpecsBurstAndTheFirstSendPastItIsHeld; TheIntervalScaleIsTheSpecsAndTwoScalesSpaceTheSameDataDifferently
// A311-M05 [cong] the credit test's boundary moved, >= to >              KILLED  14 tests, incl. ADeferredReleaseIsAlwaysInTheFutureAndNeverBeyondOneSmoothedRtt
// A311-M06 [cong] s7.7's N dropped from the rate                         KILLED  TheIntervalScaleIsTheSpecsAndTwoScalesSpaceTheSameDataDifferently; TheRefillIsSectionSevenSevensRateTimesTheElapsedTime
// A311-M07 [cong] the rate's denominator in TICKS, not seconds           KILLED  5 tests, incl. APacingReleaseWakesThePumpWithoutRunningTheLossDetectionTimeout
// A311-M08 [cong] the no-rate guard removed: a zero rate DEFERS          KILLED  ONLY NoRateMeansAdmitRatherThanWaitForEver
// A311-M09 [cong] a backwards clock drains the bucket                    KILLED  ONLY AClockThatGoesBackwardsNeitherDrainsTheBucketNorThrows
// A311-M10 [cong] the refill is not capped at the burst                  KILLED  ONLY TheBucketNeverAccumulatesPastTheSpecsBurstHoweverLongItIsIdle
// A311-M11 [cong] the one-smoothed-RTT clamp on the wait removed         KILLED  ADeferredReleaseIsAlwaysInTheFutureAndNeverBeyondOneSmoothedRtt; NoShapeOfInputMakesThePacerThrow
// A311-M12 [cong] the one-tick floor on the wait removed                 KILLED  ONLY ADeferralAtAnImmenseRateStillNamesAnInstantStrictlyAfterNow
// A311-M13 [cong] ReleaseAt not cleared by an admitted take              KILLED  ONLY AnAdmittedTakeClearsTheDeferralSoThePumpDoesNotWakeForNothing
// A311-M14 [cong] Deferrals never incremented                            KILLED  ONLY TheBucketStartsAtTheSpecsBurstAndTheFirstSendPastItIsHeld
// A311-M15 [send] s7's gate INVERTED: an open window refuses             KILLED  74 tests, incl. ABidirectionalStreamCarriesBytesBothWaysOverTheLoopbackPeer
// A311-M16 [send] the gate never asked before the 1-RTT drain            KILLED  7 tests, incl. APacingReleaseWakesThePumpWithoutRunningTheLossDetectionTimeout
// A311-M17 [send] HasPendingFrames dropped, so empty passes gate         KILLED  ONLY AnAckOnlyAnswerStillLeavesThroughAClosedWindow
// A311-M18 [send] the gate asks about 0 bytes, so it never refuses       KILLED  4 tests, incl. APacingReleaseWakesThePumpWithoutRunningTheLossDetectionTimeout
// A311-M19 [send] s7's second exception armed on a window INCREASE       KILLED  EnteringRecoveryCarriesExactlyOnePacketPastAClosedWindow; TheRecoveryExemptionSurvivesAPassThePacerHoldsAndIsSpentOnTheRelease
// A311-M20 [send] the exemption counted but never consumed               KILLED  ONLY EnteringRecoveryCarriesExactlyOnePacketPastAClosedWindow
// A311-M21 [send] the window baseline never updated                      KILLED-BY-COMPILER
// A311-M22 [send] s7's second exception removed entirely                 KILLED-BY-COMPILER
// A311-M23 [send] the pacer asked about 0 bytes, so it never holds       KILLED  4 tests, incl. APacingReleaseWakesThePumpWithoutRunningTheLossDetectionTimeout
// A311-M24 [send] PacingReleaseAt always null - no deadline entry        KILLED  4 tests, incl. APacingReleaseWakesThePumpWithoutRunningTheLossDetectionTimeout
// A311-M25 [conn] the pacing entry removed from EarliestDeadline         KILLED  ONLY APacingReleaseWakesThePumpWithoutRunningTheLossDetectionTimeout
// A311-M26 [conn] a pacing wake also runs A.9's OnLossDetectionTimeout   KILLED  ONLY APacingReleaseWakesThePumpWithoutRunningTheLossDetectionTimeout
// A311-M27 [conn] a pacing wake ABANDONS the attempt                     KILLED  ONLY APacingReleaseWakesThePumpWithoutRunningTheLossDetectionTimeout
// A311-M28 [conn] the pacing entry wins ties, < to <=                    SURVIVED
// A311-M30 [send] s7.3.2's grant spent before s7.7 has had its say       KILLED  ONLY TheRecoveryExemptionSurvivesAPassThePacerHoldsAndIsSpentOnTheRelease
// A311-M29 [strm] A38-M48 re-run: HasPendingFrames blind to repairs      KILLED  ADroppedMaximumStreamDataGrantIsRepairedAndReachesThePeer; ALostStreamFrameIsRepairedAtItsOwnOffsetAndReachesThePeerThere
// TOTALS killed=28 compiler=2 survived=2 other=0 rows=32
//
// ============================================================================
// THE TWO SURVIVORS, EACH CLASSIFIED. A survivor is UNWITNESSED, UNREACHABLE BY CONSTRUCTION,
// or VACUOUS, and saying which is the whole value of listing it.
// ============================================================================
//
//   A311-C1 IS THE CONTROL AND SURVIVES BY CONSTRUCTION. An inert comment changes no compiled
//   byte, so a green run proves the harness restored the file and the gate was really re-run.
//   A311-C2 is the other half and is why C1 alone is not enough: it proves a mutation reaches
//   compiled code at all. Both are asserted rather than assumed - a sweep whose control kills
//   is measuring its own restore, and one whose control never runs measures nothing.
//
//   A311-M28 IS UNWITNESSED, AND REACHABLE BUT OBSCURE. It moves the pacing entry's comparison
//   from `<` to `<=`, so a pacing release that TIES exactly with the handshake deadline, the
//   idle timeout or A.8's loss detection timer wins the race instead of losing it. Witnessing it
//   needs two independent deadlines landing on the same tick, one of them computed from
//   `deficit / (N * congestion_window / smoothed_rtt)` - constructible on a fake clock by
//   solving for the spec that produces it, and a test whose whole content would be that
//   arithmetic. THE BEHAVIOURAL COST OF THE TIE IS ONE PUMP, and it is bounded in the safe
//   direction either way: if the pacing entry wins a tie with an abandonment, the post-wake
//   check re-reads both abandonment deadlines and ends the attempt on the very next pass, which
//   is exactly the argument EarliestDeadline's own remarks already make for A3-5's third entry;
//   if it wins a tie with the loss timer, A.9 runs one pump later. Named here rather than left
//   as an unexplained green, which is A3-8's row M52 treatment of the same shape.
//
// ============================================================================
// FOUR ROWS SURVIVED THE FIRST ROUND AND WERE THEN KILLED, AND WHAT THEY FOUND IS THE POINT.
// ============================================================================
//
//   A311-M09 FOUND A VACUOUS TEST OF THIS TASK'S OWN. AClockThatGoesBackwardsNeitherDrainsThe
//   BucketNorThrows asked TryTake for ZERO bytes, which is answered by the early return at the
//   top of the method - so the test never reached Refill and the mutation that lets a backwards
//   clock drain the bucket sailed past it. The test was scoring an early return while naming a
//   guard. It now asks for one byte and asserts the credit moved by exactly one; the zero-byte
//   ask is kept as a second line, because it is a real case and was the only thing the first
//   version tested. THE STANDING RULE IN ONE ROW: a done-when clause is a floor, and "nothing
//   throws for any input" was satisfied by a test that exercised nothing.
//
//   A311-M10 WAS A REAL GAP IN THE KNOB. Without the cap the bucket accumulates for as long as
//   the connection is idle, so the burst that follows a silence is sized by the SILENCE and not
//   by knob 14 - an hour at the shipped rate is about five hundred megabytes of credit against a
//   burst of 2400 bytes. The knob would still be settable and would still be read, and it would
//   simply stop being what the wire showed. TheBucketNeverAccumulatesPastTheSpecsBurstHowever
//   LongItIsIdle is the witness.
//
//   A311-M12 AND A311-M13 ARE BOTH SPINS RATHER THAN STALLS, WHICH IS WHY NO TIMEOUT FOUND
//   THEM. M12 removes the one-tick floor, so at a rate high enough that s7.7's arithmetic gives
//   a sub-tick wait the release instant is one the pump has ALREADY passed: it wakes, is held
//   again for the same reason, and loops as fast as the machine allows. M13 leaves ReleaseAt
//   standing after the take it was armed for, so EarliestDeadline keeps returning a stale
//   instant for the life of the connection. Neither hangs, both burn a core, and a suite that
//   only bounded its waits would have called both of them green.
//
// ============================================================================
// AND THE ROW THAT IS NOT THIS TASK'S: A311-M29.
// ============================================================================
//
// A3-8 classified its row M48 - HasPendingFrames blind to the repair queue - as UNREACHABLE BY
// CONSTRUCTION, with the reason stated in full: "The property has no production caller at all -
// grep returns tests only - so no send decision depends on it". That premise is gone. This task
// made HasPendingFrames the first thing TryBuildApplicationPacket asks, because it is what keeps
// an ACK-only pass from spending the pacer's credit and arming a pacing deadline for a datagram
// that does not exist. Re-run here at this task's gate, the same mutation KILLS - and it kills
// through A3-8's OWN repair tests, which is the strongest possible statement that the property
// is now load-bearing. A38-M48's entry in TlsQuicLossDetection.cs is annotated rather than
// edited: the classification is correct for the tree A3-8 measured and wrong for this one.
//
// THE OTHER THREE A3-8 SURVIVORS THIS TASK WAS ASKED ABOUT STAND UNCHANGED, checked rather than
// assumed. M32 (the probe's full-datagram bound) is on the probe path, which this task
// deliberately does not touch - s7.5 exempts it and the exemption is structural. M34 (Forget
// leaving a ledger entry) is about _repairable's readers, and nothing here reads it. M52 (s7.6's
// anchor monotonicity) is in the loss pass, upstream of every line this task added.
//
// AND THE THREE GREPS THAT PIN THIS TABLE, run from this file's directory:
//   `grep -cE '^// A311-(C|M)[0-9]+ ' TlsQuicCongestionControl.cs`               must return 32
//   `grep -cE '^// A311-(C|M)[0-9]+ .*SURVIVED' TlsQuicCongestionControl.cs`     must return 2
//   `grep -cE '^// A311-(C|M)[0-9]+ .*KILLED-BY-COMPILER' …`                     must return 2
// 28 killed + 2 killed-by-compiler + 2 survived = 32, which is the row count above.
