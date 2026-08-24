namespace SharpTls.Quic;

/// <summary>RFC 8899 s5.2's DPLPMTUD states, as RFC 9000 s14.3 binds them to QUIC.</summary>
/// <remarks>
/// <para>FOUR OF THE FIVE. RFC 8899 s5.2 also defines DISABLED - "the initial state before
/// probing has started ... also entered from any other state, when the PL indicates loss of
/// connectivity" - and this type spends its whole life inside one QUIC connection, which HAS
/// no state after connectivity is lost. <see cref="Base"/> before the handshake completes is
/// that condition expressed as the state the RFC says to leave DISABLED for.</para>
/// <para>ERROR IS PRESENT AND REACHABLE, unlike the state machines that omit it: s5.2 makes it
/// "the case where either the network path is not known to support a PLPMTU of at least the
/// BASE_PLPMTU size", and RFC 9000 s14.2 attaches a hard consequence - an endpoint that finds
/// the path cannot carry 1200 bytes "MUST immediately cease sending QUIC packets, except for
/// those in PMTU probes or those containing CONNECTION_CLOSE frames".</para>
/// </remarks>
internal enum TlsQuicPathMtuState
{
    /// <summary>RFC 8899 s5.2's BASE: BASE_PLPMTU is what the path is known to carry, and
    /// nothing larger has been confirmed.</summary>
    Base,

    /// <summary>s5.2's SEARCHING: "the main probing state".</summary>
    Searching,

    /// <summary>s5.2's SEARCH_COMPLETE: "the normal maintenance state, where the PL is not
    /// probing to update the PLPMTU".</summary>
    SearchComplete,

    /// <summary>s5.2's ERROR: the path is not known to carry even BASE_PLPMTU.</summary>
    Error,
}

/// <summary>RFC 8899's Datagram Packetization Layer PMTU Discovery, as RFC 9000 s14.3
/// specifies it for QUIC: the search that raises the maximum datagram size above the 1200
/// bytes every path is required to carry.</summary>
/// <remarks>
/// <para>PURE STATE, NO CLOCK AND NO I/O. Everything this type needs arrives as a call -
/// a probe was sent, a packet was acknowledged, a packet was lost - and everything it decides
/// leaves as a return value. That is what lets the whole state machine be tested without a
/// connection, which matters because the interesting transitions are the ones a live run
/// almost never reaches.</para>
/// <para>NO PROBE_TIMER, AND THAT IS RFC 8899 s6.3's DOING RATHER THAN A SIMPLIFICATION. s5.1.1
/// configures a PROBE_TIMER "to expire after a period longer than the maximum time to receive
/// an acknowledgment to a probe packet ... SHOULD be larger than 15 seconds", which exists
/// because a datagram PL may have no other way to learn a probe was lost. QUIC does: s6.3 calls
/// QUIC "a UDP-based PL that provides reception feedback" and RFC 9000 s14.4 makes PMTU probes
/// "ack-eliciting packets", so the connection's own loss detection declares a probe lost long
/// before any 15-second timer would, and it does so on evidence rather than on a deadline.
/// <see cref="OnPacketLost"/> is that signal arriving.</para>
/// <para>NO CONFIRMATION_TIMER EITHER, and this one the RFC rules out by name. RFC 9000
/// s14.3.2: "QUIC is an acknowledged PL; therefore, a QUIC sender does not implement a DPLPMTUD
/// CONFIRMATION_TIMER while in the SEARCH_COMPLETE state." RFC 8899 s5.1.1 agrees from the
/// other side: "When an acknowledged PL is used, this timer MUST NOT be used."</para>
/// <para>NO PMTU_RAISE_TIMER, AND THIS ONE IS A DELIBERATE OMISSION RATHER THAN AN EXEMPTION.
/// s5.1.1 gives it a 600-second period, after which a sender re-enters the search in case the
/// path grew. This client's connections are short - a handful of requests - so a 10-minute
/// re-search would never fire on the great majority of them and would need a clock this type
/// otherwise does not have. A connection that outlives its path's MTU keeps the smaller figure,
/// which costs throughput and is never incorrect.</para>
/// </remarks>
internal sealed class TlsQuicPathMtu
{
    /// <summary>RFC 8899 s5.1.2's MAX_PROBES: "the maximum value of the PROBE_COUNT counter ...
    /// the limit for the number of consecutive probe attempts of any size ... The default value
    /// of MAX_PROBES is 3."</summary>
    /// <remarks>s5.1.2 gives the reason a value above one matters: "Search algorithms benefit
    /// from a MAX_PROBES value greater than 1 because this can provide robustness to isolated
    /// packet loss." A probe lost to congestion rather than to size would otherwise end the
    /// search at whatever had been confirmed so far.</remarks>
    internal const int MaximumProbes = 3;

    /// <summary>RFC 8899 s5.3.2's "minimum useful gain in PLPMTU", below which the search stops
    /// rather than spending another probe.</summary>
    /// <remarks>s5.3.2: "The search algorithm determines a minimum useful gain in PLPMTU. It
    /// would not be constructive for a PL sender to attempt to probe for all sizes. This would
    /// incur unnecessary load on the path." Sixteen bytes is under one percent of the range
    /// between 1200 and 1472, so the search converges within a byte or two of the true figure
    /// while a narrower gain would buy a rounding error for a whole round trip.</remarks>
    internal const int MinimumUsefulGain = 16;

    private readonly int _base;
    private readonly int _maximum;

    // RFC 8899 s5.3.1's search range. `_confirmed` is the largest size a probe has been
    // acknowledged at - the PLPMTU - and `_ceiling` the largest size not yet ruled out. The
    // search ends when they meet, or when what is between them is not worth a probe.
    private int _confirmed;
    private int _ceiling;

    // s5.1.3's PROBED_SIZE and PROBE_COUNT. PROBED_SIZE is "a tentative value for the PLPMTU,
    // which is awaiting confirmation by an acknowledgment"; the packet number is how this type
    // recognises that acknowledgment, since it holds no packets of its own.
    private int _probedSize;
    private int _probeCount;
    private ulong? _outstandingProbe;

    // s4.3's third black hole indicator - "excessive loss of data sent with a specific packet
    // size" - counted over ORDINARY packets larger than BASE_PLPMTU. See OnPacketLost.
    private int _consecutiveLargePacketLosses;

    // RFC 8899 s5.1.1's licence to hold a probe back: "DPLPMTUD MAY inhibit sending probe
    // packets when no application data has been sent since the previous probe packet."
    private bool _applicationDataSinceLastProbe;

    /// <summary>Creates a state machine for one path.</summary>
    /// <param name="basePathMtu">RFC 8899 s5.1.2's BASE_PLPMTU, which RFC 9000 s14.3 makes
    /// "consistent with QUIC's smallest allowed maximum datagram size" and s14.3 also makes
    /// MIN_PLPMTU: "The MIN_PLPMTU is the same as the BASE_PLPMTU."</param>
    /// <param name="maximumPathMtu">s5.1.2's MAX_PLPMTU, "the largest size of PLPMTU".</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maximumPathMtu"/> is below
    /// <paramref name="basePathMtu"/>.</exception>
    internal TlsQuicPathMtu(int basePathMtu, int maximumPathMtu)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumPathMtu, basePathMtu, nameof(maximumPathMtu));

        _base = basePathMtu;
        _maximum = maximumPathMtu;
        _confirmed = basePathMtu;
        _ceiling = maximumPathMtu;
    }

    /// <summary>Gets RFC 8899 s5.1.3's PLPMTU: the largest datagram this path is known to
    /// carry, and therefore the size every non-probe datagram is bounded by.</summary>
    /// <remarks>RFC 9000 s14.2 calls this "the endpoint's maximum datagram size" and s14.3
    /// makes it the DPLPMTUD "Maximum Packet Size (MPS)". It only ever moves on evidence: up
    /// when a probe of that size is acknowledged, down when a black hole is detected.</remarks>
    internal int MaximumDatagramSize => _confirmed;

    /// <summary>Gets the current RFC 8899 s5.2 state.</summary>
    internal TlsQuicPathMtuState State { get; private set; } = TlsQuicPathMtuState.Base;

    /// <summary>Gets how many probes have been sent over this path's lifetime.</summary>
    internal int ProbesSent { get; private set; }

    /// <summary>Gets how many times the search has raised the maximum datagram size.</summary>
    internal int Raises { get; private set; }

    /// <summary>Gets how many times a black hole has dropped it back to BASE_PLPMTU.</summary>
    internal int BlackHolesDetected { get; private set; }

    /// <summary>Gets whether a probe is outstanding and has not yet been acknowledged or
    /// declared lost.</summary>
    internal bool HasOutstandingProbe => _outstandingProbe is not null;

    /// <summary>Enters RFC 8899's search, which RFC 9000 s14.3.1 permits once the handshake is
    /// done.</summary>
    /// <remarks>
    /// <para>s14.3.1: "From the perspective of DPLPMTUD, QUIC is an acknowledged Packetization
    /// Layer (PL). A QUIC sender can therefore enter the DPLPMTUD BASE state when the QUIC
    /// connection handshake has been completed."</para>
    /// <para>AND IT GOES STRAIGHT TO SEARCHING, SKIPPING BASE'S PROBE. RFC 8899 s5.2 leaves
    /// BASE "when the probe packet is acknowledged", the probe being one of BASE_PLPMTU bytes -
    /// and a completed QUIC handshake has already done exactly that. RFC 9000 s14.1 requires
    /// every client Initial datagram to be expanded "to at least the smallest allowed maximum
    /// datagram size of 1200 bytes", and the handshake does not complete unless those datagrams
    /// arrived and were acknowledged. Sending a 1200-byte PING to re-learn it would be a round
    /// trip spent confirming what the connection is standing on.</para>
    /// <para>IDEMPOTENT, because handshake confirmation can be observed more than once - a
    /// repeated HANDSHAKE_DONE is a frame the peer may resend - and re-entering the search
    /// would discard a PLPMTU already raised.</para>
    /// </remarks>
    internal void OnHandshakeConfirmed()
    {
        if (State != TlsQuicPathMtuState.Base)
        {
            return;
        }

        // s5.3.2's "maximize the gain in PLPMTU from each search step", taken literally for
        // the first step: probe the ceiling, so an ordinary untunnelled path is settled in one
        // round trip.
        _probedSize = _ceiling;
        State = _ceiling > _confirmed ? TlsQuicPathMtuState.Searching : TlsQuicPathMtuState.SearchComplete;
    }

    /// <summary>Records that application data has gone out, which is what makes a probe worth
    /// sending.</summary>
    /// <remarks>
    /// <para>RFC 8899 s5.1.1: "DPLPMTUD MAY inhibit sending probe packets when no application
    /// data has been sent since the previous probe packet. A PL preferring to use an up-to-date
    /// PMTU once user data is sent again can choose to continue PMTU discovery for each path.
    /// However, this will result in sending additional packets." This client takes the first
    /// option.</para>
    /// <para>WHICH MAKES THE PROBE FOLLOW A REASON TO WANT ONE. A connection that opens, sends
    /// one small request and closes gains nothing from a larger datagram, so probing it spends
    /// a round trip and an extra datagram to learn a number nothing will use. Waiting also
    /// keeps the probe out of the opening flight, which is the part of a connection an observer
    /// is most likely to be looking at.</para>
    /// </remarks>
    internal void OnApplicationDataSent() => _applicationDataSinceLastProbe = true;

    /// <summary>Reports the size of the next probe datagram to send, if one is due.</summary>
    /// <remarks>
    /// <para>ONE PROBE AT A TIME. RFC 8899 s5.3.1 ties PROBE_COUNT to a single outstanding
    /// probe - "Each time a probe packet is sent to the destination, the PROBE_TIMER is
    /// started" - and a second probe in flight would make an acknowledgment ambiguous about
    /// which size it confirmed.</para>
    /// <para>THE FIRST PROBE JUMPS TO MAX_PLPMTU RATHER THAN TO THE MIDPOINT, which is
    /// s5.3.2's advice taken literally: "Implementations SHOULD select the set of probe packet
    /// sizes to maximize the gain in PLPMTU from each search step." On an ordinary untunnelled
    /// path the ceiling is the answer, so the common case costs ONE probe and one round trip
    /// instead of the five a binary search from the midpoint would spend. When it fails, the
    /// search below is a binary one and pays the usual cost.</para>
    /// </remarks>
    /// <param name="size">The datagram size to build the probe at.</param>
    /// <returns><see langword="true"/> when a probe is due.</returns>
    internal bool TryGetProbeSize(out int size)
    {
        size = 0;
        if (State != TlsQuicPathMtuState.Searching || _outstandingProbe is not null)
        {
            return false;
        }

        // s5.1.1's inhibition. See OnApplicationDataSent.
        if (!_applicationDataSinceLastProbe)
        {
            return false;
        }

        // THE SIZE IS CHOSEN WHERE THE SEARCH RANGE MOVES, NEVER HERE. This method used to
        // reset _probedSize to the ceiling whenever PROBE_COUNT was zero, which is true both of
        // the first probe ever AND of the first attempt at a size the search had just narrowed
        // to - so a size ruled out by three losses was immediately probed again and the search
        // could not descend. OnHandshakeConfirmed, OnPacketAcknowledged and OnProbeFailed each
        // set it when they move the range; this reads it.
        //
        // A probe already chosen and lost is therefore retried at the SAME size until
        // PROBE_COUNT runs out, which is s5.3.1's "a new probe of the same size or any other
        // size (determined by the search algorithm) can be sent" and is what makes MAX_PROBES
        // robustness to isolated loss rather than an accelerated descent.
        if (_probedSize <= _confirmed)
        {
            State = TlsQuicPathMtuState.SearchComplete;
            return false;
        }

        size = _probedSize;
        return true;
    }

    /// <summary>Records that the probe reported by <see cref="TryGetProbeSize"/> went out as
    /// <paramref name="packetNumber"/>.</summary>
    internal void OnProbeSent(ulong packetNumber)
    {
        _outstandingProbe = packetNumber;
        _applicationDataSinceLastProbe = false;
        ProbesSent++;
    }

    /// <summary>Takes an acknowledgment. Only the outstanding probe's packet number does
    /// anything; every other number is ignored.</summary>
    /// <remarks>RFC 8899 s5.3.1: "The timer is canceled when the PL receives acknowledgment
    /// that the probe packet has been successfully sent across the path. This confirms that the
    /// PROBED_SIZE is supported, and the PROBED_SIZE value is then assigned to the PLPMTU. The
    /// search algorithm can continue to send subsequent probe packets of an increasing
    /// size."</remarks>
    internal void OnPacketAcknowledged(ulong packetNumber)
    {
        // An acknowledgment of ANY packet is evidence the path is carrying traffic, so the
        // black hole counter - which counts CONSECUTIVE losses - resets here as well.
        _consecutiveLargePacketLosses = 0;

        if (_outstandingProbe != packetNumber)
        {
            return;
        }

        _outstandingProbe = null;

        // s5.2, SEARCHING: "Each time a probe packet is acknowledged, the PROBE_COUNT is set to
        // zero, the PLPMTU is set to the PROBED_SIZE, and then the PROBED_SIZE is increased
        // using the search algorithm."
        _probeCount = 0;
        if (_probedSize > _confirmed)
        {
            _confirmed = _probedSize;
            Raises++;
        }

        // s5.2's exit: "a probe of size MAX_PLPMTU is acknowledged (PLPMTU = MAX_PLPMTU)".
        if (_confirmed >= _maximum || _ceiling - _confirmed < MinimumUsefulGain)
        {
            State = TlsQuicPathMtuState.SearchComplete;
            return;
        }

        // Halfway between what is confirmed and what is not yet ruled out. Rounded up so a
        // range of one still probes the larger of the two rather than re-probing the confirmed
        // size forever.
        _probedSize = _confirmed + ((_ceiling - _confirmed + 1) / 2);
    }

    /// <summary>Takes a loss. A lost probe advances RFC 8899 s5.1.3's PROBE_COUNT; a lost
    /// ORDINARY packet larger than BASE_PLPMTU counts toward s4.3's black hole
    /// detection.</summary>
    /// <remarks>
    /// <para>THE TWO CASES ARE DIFFERENT EVIDENCE AND MUST NOT BE MERGED. RFC 9000 s14.4: "Loss
    /// of a QUIC packet that is carried in a PMTU probe is therefore not a reliable indication
    /// of congestion" - a probe is EXPECTED to be dropped when it is too big, which is the
    /// whole point of sending it. An ordinary packet at a size already confirmed is the
    /// opposite: it should have got through, and repeated failures are s4.3's "excessive loss
    /// of data sent with a specific packet size and then conclude that this excessive loss
    /// could be a result of an invalid PLPMTU".</para>
    /// <para>WHAT THIS BLACK HOLE DETECTION IS NOT. s4.3 lists three indicators; this
    /// implements the third. The first is a validated ICMP PTB message, which this client
    /// cannot use because it reads no ICMP at all - and s4.3 forbids relying on it alone
    /// anyway: "A DPLPMTUD method MUST NOT rely solely on this method." The second is a
    /// CONFIRMATION_TIMER, which RFC 9000 s14.3.2 rules out for QUIC by name. So the third is
    /// not a shortcut past the other two; it is the only one available here.</para>
    /// </remarks>
    /// <param name="packetNumber">The lost packet's number.</param>
    /// <param name="size">Its datagram size in bytes.</param>
    internal void OnPacketLost(ulong packetNumber, int size)
    {
        if (_outstandingProbe == packetNumber)
        {
            _outstandingProbe = null;
            OnProbeFailed();
            return;
        }

        if (size <= _base || State == TlsQuicPathMtuState.Base)
        {
            // A packet no larger than BASE_PLPMTU says nothing about size: the path is required
            // to carry it, so its loss is ordinary congestion or corruption.
            return;
        }

        if (++_consecutiveLargePacketLosses < MaximumProbes)
        {
            return;
        }

        // s5.2: "When a black hole is detected in the SEARCHING state, this causes the PL
        // sender to enter the BASE state." s4.3: "When the method detects that the current
        // PLPMTU is not supported, DPLPMTUD sets a lower PLPMTU and a lower MPS."
        //
        // BACK TO BASE_PLPMTU AND NOT TO SOMETHING BETWEEN. The path has just demonstrated it
        // will not carry the confirmed size, and BASE_PLPMTU is the one figure RFC 9000 s14
        // says every path must carry; halving toward it would be guessing with the connection's
        // throughput while it is already failing.
        _confirmed = _base;
        _ceiling = _maximum;
        _probeCount = 0;
        _probedSize = _maximum;
        _consecutiveLargePacketLosses = 0;
        BlackHolesDetected++;

        // Straight back into the search rather than into BASE, for the reason
        // OnHandshakeConfirmed gives: BASE exists to confirm BASE_PLPMTU, and a connection that
        // is still delivering packets at that size has confirmed it continuously.
        State = TlsQuicPathMtuState.Searching;
    }

    // s5.2, SEARCHING: "When a probe packet is sent and not acknowledged within the period of
    // the PROBE_TIMER, the PROBE_COUNT is incremented, and a new probe packet is transmitted.
    // The state is exited to enter SEARCH_COMPLETE when the PROBE_COUNT reaches MAX_PROBES".
    //
    // AND THE SIZE IS RULED OUT RATHER THAN THE SEARCH ABANDONED. s5.2's literal reading ends
    // the search at MAX_PROBES; s5.3.1 permits more - "a new probe of the same size or any
    // other size (determined by the search algorithm) can be sent" - and a binary search that
    // stopped at the first failed size would leave the whole range below it unexplored. So
    // MAX_PROBES failures lower the ceiling to just under the size that failed and the search
    // continues below it, which reaches SEARCH_COMPLETE by the minimum-useful-gain test
    // instead.
    private void OnProbeFailed()
    {
        if (++_probeCount < MaximumProbes)
        {
            return;
        }

        _probeCount = 0;
        _ceiling = _probedSize - 1;

        if (_ceiling - _confirmed < MinimumUsefulGain)
        {
            State = TlsQuicPathMtuState.SearchComplete;
            return;
        }

        _probedSize = _confirmed + ((_ceiling - _confirmed + 1) / 2);
    }
}
