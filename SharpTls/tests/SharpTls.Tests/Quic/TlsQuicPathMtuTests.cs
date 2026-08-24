using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// RFC 8899's DPLPMTUD state machine, as RFC 9000 s14.3 binds it to QUIC. Normative text is
// quoted from docs/superpowers/specs/reference-captures/rfc8899-section4-and-5-dplpmtud.txt and
// rfc9000-section14-datagram-size-and-pmtu.txt.
//
// TESTED WITHOUT A CONNECTION, WHICH IS WHY THE TYPE HOLDS NO CLOCK AND NO SOCKET. The
// transitions that matter are the ones a live run almost never reaches - three consecutive
// probe losses, a black hole under a confirmed size, a path that will not carry 1200 bytes -
// and every one of them is a method call here rather than a network condition to reproduce.
public sealed class TlsQuicPathMtuTests
{
    private const int Base = 1200;
    private const int Maximum = 1472;

    [Fact]
    public void NothingIsProbedBeforeTheHandshakeCompletes()
    {
        // RFC 9000 s14.3.1: "A QUIC sender can therefore enter the DPLPMTUD BASE state when the
        // QUIC connection handshake has been completed." Before that there is nothing to probe
        // with - s14.4 makes PMTU probes ack-eliciting 1-RTT traffic - and the handshake's own
        // 1200-byte Initial datagrams are already establishing BASE_PLPMTU.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnApplicationDataSent();

        Assert.Equal(TlsQuicPathMtuState.Base, path.State);
        Assert.Equal(Base, path.MaximumDatagramSize);
        Assert.False(path.TryGetProbeSize(out _));
    }

    [Fact]
    public void NoProbeIsSentUntilApplicationDataHas()
    {
        // RFC 8899 s5.1.1: "DPLPMTUD MAY inhibit sending probe packets when no application data
        // has been sent since the previous probe packet." A connection that opens, confirms its
        // handshake and sends nothing gains nothing from a larger datagram, so probing it would
        // spend a round trip and an extra datagram learning a number nothing will use.
        //
        // IT ALSO KEEPS THE PROBE OUT OF THE OPENING FLIGHT, which is the part of a connection
        // an observer is most likely to be reading.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();

        Assert.Equal(TlsQuicPathMtuState.Searching, path.State);
        Assert.False(path.TryGetProbeSize(out _));

        path.OnApplicationDataSent();
        Assert.True(path.TryGetProbeSize(out var size));
        Assert.Equal(Maximum, size);
    }

    [Fact]
    public void OneProbePerBurstOfApplicationData()
    {
        // s5.1.1 says "since the previous probe packet", so sending the probe consumes the
        // permission. Without that, a search that lost a probe would re-probe on every pass
        // while the connection sat idle - which is the "additional packets" the same paragraph
        // warns about.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();

        Assert.True(path.TryGetProbeSize(out _));
        path.OnProbeSent(1);
        path.OnPacketLost(1, Maximum);

        Assert.False(path.TryGetProbeSize(out _));

        path.OnApplicationDataSent();
        Assert.True(path.TryGetProbeSize(out _));
    }

    [Fact]
    public void TheFirstProbeJumpsStraightToTheCeiling()
    {
        // RFC 8899 s5.3.2: "Implementations SHOULD select the set of probe packet sizes to
        // maximize the gain in PLPMTU from each search step." On an ordinary untunnelled path
        // MAX_PLPMTU is the answer, so probing it first settles the search in one round trip
        // where a binary search from the midpoint would spend five.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();

        Assert.Equal(TlsQuicPathMtuState.Searching, path.State);
        Assert.True(path.TryGetProbeSize(out var size));
        Assert.Equal(Maximum, size);
    }

    [Fact]
    public void AnAcknowledgedCeilingProbeCompletesTheSearchInOneRoundTrip()
    {
        // s5.2, SEARCHING: "Each time a probe packet is acknowledged, the PROBE_COUNT is set to
        // zero, the PLPMTU is set to the PROBED_SIZE". And the exit: "a probe of size
        // MAX_PLPMTU is acknowledged (PLPMTU = MAX_PLPMTU)".
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();
        Assert.True(path.TryGetProbeSize(out var size));
        path.OnProbeSent(7);

        // NOT RAISED UNTIL THE ACKNOWLEDGMENT, which is the difference between DPLPMTUD and
        // guessing: s5.1.3 calls PROBED_SIZE "a tentative value for the PLPMTU, which is
        // awaiting confirmation by an acknowledgment".
        Assert.Equal(Base, path.MaximumDatagramSize);

        path.OnPacketAcknowledged(7);

        Assert.Equal(Maximum, path.MaximumDatagramSize);
        Assert.Equal(TlsQuicPathMtuState.SearchComplete, path.State);
        Assert.Equal(1, path.ProbesSent);
        Assert.Equal(1, path.Raises);
        Assert.False(path.TryGetProbeSize(out _));
    }

    [Fact]
    public void OneLostProbeIsRetriedAtTheSameSize()
    {
        // s5.1.2 on MAX_PROBES: "Search algorithms benefit from a MAX_PROBES value greater
        // than 1 because this can provide robustness to isolated packet loss." A probe dropped
        // by congestion rather than by size must not narrow the search.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();
        Assert.True(path.TryGetProbeSize(out var first));
        path.OnProbeSent(1);
        path.OnPacketLost(1, first);
        path.OnApplicationDataSent();

        Assert.True(path.TryGetProbeSize(out var second));
        Assert.Equal(first, second);
        Assert.Equal(TlsQuicPathMtuState.Searching, path.State);
    }

    [Fact]
    public void ThreeLostProbesRuleOutThatSizeAndTheSearchContinuesBelowIt()
    {
        // s5.2's literal exit is SEARCH_COMPLETE at MAX_PROBES. s5.3.1 permits more - "a new
        // probe of the same size or any other size (determined by the search algorithm) can be
        // sent" - and stopping at the first failed size would leave the entire range below it
        // unexplored, which on a 1400-byte tunnel means staying at 1200 forever.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();

        for (var attempt = 1; attempt <= TlsQuicPathMtu.MaximumProbes; attempt++)
        {
            Assert.True(path.TryGetProbeSize(out var size));
            Assert.Equal(Maximum, size);
            path.OnProbeSent((ulong)attempt);
            path.OnPacketLost((ulong)attempt, size);
            path.OnApplicationDataSent();
        }

        Assert.Equal(TlsQuicPathMtuState.Searching, path.State);
        Assert.True(path.TryGetProbeSize(out var narrowed));

        // Halfway between the confirmed 1200 and the new ceiling of 1471.
        Assert.Equal(Base + ((Maximum - 1 - Base + 1) / 2), narrowed);
        Assert.InRange(narrowed, Base + 1, Maximum - 1);
    }

    [Fact]
    public void TheSearchConvergesOnATunnelledPathAndStops()
    {
        // THE CASE THE WHOLE FEATURE IS FOR. A path that carries 1400 bytes and not 1401 - a
        // VPN or a tunnelled proxy - is exactly where a fixed 1472-byte ceiling sends every
        // datagram into a black hole and a fixed 1200 leaves throughput on the floor.
        //
        // The loop answers every probe truthfully against a real limit rather than following a
        // script, so it tests the SEARCH rather than a transcript of one.
        const int Actual = 1400;
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();

        ulong packet = 0;
        for (var step = 0; step < 64 && path.TryGetProbeSize(out var size); step++)
        {
            path.OnProbeSent(++packet);
            path.OnApplicationDataSent();
            if (size <= Actual)
            {
                path.OnPacketAcknowledged(packet);
            }
            else
            {
                path.OnPacketLost(packet, size);
            }
        }

        Assert.Equal(TlsQuicPathMtuState.SearchComplete, path.State);

        // WITHIN THE MINIMUM USEFUL GAIN OF THE TRUTH, AND NEVER OVER IT. s5.3.2 makes the
        // gain a deliberate stopping point rather than a defect: "It would not be constructive
        // for a PL sender to attempt to probe for all sizes."
        Assert.InRange(
            path.MaximumDatagramSize, Actual - TlsQuicPathMtu.MinimumUsefulGain, Actual);
    }

    [Fact]
    public void APathThatCarriesNothingAboveTheBaseEndsAtTheBase()
    {
        // The tunnelled case taken to its limit: nothing above 1200 gets through. The search
        // must end at BASE_PLPMTU rather than below it - RFC 9000 s14.3 makes MIN_PLPMTU the
        // same as BASE_PLPMTU - and must stop probing rather than retry forever.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();

        ulong packet = 0;
        for (var step = 0; step < 64 && path.TryGetProbeSize(out var size); step++)
        {
            path.OnProbeSent(++packet);
            path.OnApplicationDataSent();
            path.OnPacketLost(packet, size);
        }

        Assert.Equal(TlsQuicPathMtuState.SearchComplete, path.State);
        Assert.Equal(Base, path.MaximumDatagramSize);
        Assert.Equal(0, path.Raises);
    }

    [Fact]
    public void AnAcknowledgmentOfSomethingElseNeitherRaisesNorClearsTheProbe()
    {
        // The probe is recognised by its packet number and by nothing else. An implementation
        // that raised on any acknowledgment would raise on the first ACK after the probe went
        // out, which is the ordinary traffic the probe was sent alongside.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();
        Assert.True(path.TryGetProbeSize(out _));
        path.OnProbeSent(42);

        path.OnPacketAcknowledged(41);
        path.OnPacketAcknowledged(43);

        Assert.Equal(Base, path.MaximumDatagramSize);
        Assert.Equal(0, path.Raises);
        Assert.True(path.HasOutstandingProbe);
        Assert.False(path.TryGetProbeSize(out _));
    }

    [Fact]
    public void OnlyOneProbeIsOutstandingAtATime()
    {
        // s5.3.1 ties PROBE_COUNT to a single outstanding probe. Two in flight would make an
        // acknowledgment ambiguous about which size it confirmed.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();

        Assert.True(path.TryGetProbeSize(out _));
        path.OnProbeSent(1);
        Assert.False(path.TryGetProbeSize(out _));
    }

    [Fact]
    public void ThreeLostFullSizePacketsAreABlackHoleAndDropTheSizeBackToTheBase()
    {
        // RFC 8899 s4.3's third indicator: "excessive loss of data sent with a specific packet
        // size and then conclude that this excessive loss could be a result of an invalid
        // PLPMTU". s5.2: "When a black hole is detected in the SEARCHING state, this causes the
        // PL sender to enter the BASE state."
        //
        // THE PATH IS RAISED FIRST, so the drop is a drop rather than a no-op.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();
        Assert.True(path.TryGetProbeSize(out _));
        path.OnProbeSent(1);
        path.OnPacketAcknowledged(1);
        Assert.Equal(Maximum, path.MaximumDatagramSize);

        for (ulong packet = 10; packet < 10 + TlsQuicPathMtu.MaximumProbes; packet++)
        {
            path.OnPacketLost(packet, Maximum);
        }

        Assert.Equal(Base, path.MaximumDatagramSize);
        Assert.Equal(1, path.BlackHolesDetected);
    }

    [Fact]
    public void LostPacketsAtTheBaseSizeAreNotABlackHole()
    {
        // A packet no larger than BASE_PLPMTU says nothing about size: RFC 9000 s14 requires
        // every path to carry 1200 bytes, so losing one is congestion or corruption. An
        // implementation that counted these would drop the PLPMTU on any lossy path and never
        // raise it again.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();
        Assert.True(path.TryGetProbeSize(out _));
        path.OnProbeSent(1);
        path.OnPacketAcknowledged(1);

        for (ulong packet = 10; packet < 30; packet++)
        {
            path.OnPacketLost(packet, Base);
        }

        Assert.Equal(Maximum, path.MaximumDatagramSize);
        Assert.Equal(0, path.BlackHolesDetected);
    }

    [Fact]
    public void AnAcknowledgmentBetweenLossesBreaksTheBlackHoleRun()
    {
        // s4.3 counts SUCCESSIVE losses. A path dropping one large packet in three is lossy,
        // not black-holed, and dropping its PLPMTU would cost throughput on exactly the paths
        // that can least afford it.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();
        Assert.True(path.TryGetProbeSize(out _));
        path.OnProbeSent(1);
        path.OnPacketAcknowledged(1);

        for (ulong round = 0; round < 10; round++)
        {
            path.OnPacketLost(100 + round, Maximum);
            path.OnPacketLost(200 + round, Maximum);
            path.OnPacketAcknowledged(300 + round);
        }

        Assert.Equal(Maximum, path.MaximumDatagramSize);
        Assert.Equal(0, path.BlackHolesDetected);
    }

    [Fact]
    public void AfterABlackHoleTheSearchRunsAgain()
    {
        // s5.2 leaves BASE for SEARCHING once BASE_PLPMTU is confirmed, and a connection still
        // delivering 1200-byte datagrams is confirming it continuously. A black hole that
        // ended discovery for the rest of the connection would make a transient path change
        // permanent.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();
        Assert.True(path.TryGetProbeSize(out _));
        path.OnProbeSent(1);
        path.OnPacketAcknowledged(1);

        for (ulong packet = 10; packet < 10 + TlsQuicPathMtu.MaximumProbes; packet++)
        {
            path.OnPacketLost(packet, Maximum);
        }

        Assert.Equal(TlsQuicPathMtuState.Searching, path.State);
        path.OnApplicationDataSent();
        Assert.True(path.TryGetProbeSize(out var size));
        Assert.Equal(Maximum, size);
    }

    [Fact]
    public void ABaseEqualToTheMaximumNeverProbes()
    {
        // A caller that pins both knobs to the same figure is asking for a fixed datagram size.
        // There is no range to search, so the search must complete rather than probe a size it
        // has already got.
        var path = new TlsQuicPathMtu(Base, Base);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();

        Assert.Equal(TlsQuicPathMtuState.SearchComplete, path.State);
        Assert.False(path.TryGetProbeSize(out _));
        Assert.Equal(Base, path.MaximumDatagramSize);
        Assert.Equal(0, path.ProbesSent);
    }

    [Fact]
    public void AMaximumBelowTheBaseIsRejected() =>
        // RFC 8899 s5.1.2 orders them: BASE_PLPMTU "is equal to or larger than the MIN_PLPMTU
        // and smaller than the MAX_PLPMTU". An inverted pair would make the search range
        // negative and every probe smaller than the size already in use.
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicPathMtu(Base, Base - 1));

    [Fact]
    public void HandshakeConfirmationIsIdempotent()
    {
        // HANDSHAKE_DONE is a frame the peer may resend, and RFC 9001 s4.1.2's confirmation can
        // be observed more than once. Re-entering the search would discard a PLPMTU already
        // raised and spend the round trips again.
        var path = new TlsQuicPathMtu(Base, Maximum);
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();
        Assert.True(path.TryGetProbeSize(out _));
        path.OnProbeSent(1);
        path.OnPacketAcknowledged(1);
        Assert.Equal(Maximum, path.MaximumDatagramSize);

        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();
        path.OnHandshakeConfirmed();
        path.OnApplicationDataSent();

        Assert.Equal(Maximum, path.MaximumDatagramSize);
        Assert.Equal(TlsQuicPathMtuState.SearchComplete, path.State);
        Assert.Equal(1, path.ProbesSent);
    }
}
