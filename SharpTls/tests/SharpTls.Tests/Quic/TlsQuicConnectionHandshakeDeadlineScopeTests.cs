using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// THE HANDSHAKE DEADLINE BOUNDS THE HANDSHAKE AND NOTHING AFTER IT.
//
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's, 14c's, A3-1's, A3-3's AND A3-5's, for the reason
// those give: Spec, Connection, TlsClient, Server, Credential and RunToOneRttAsync are reused
// rather than copied.
//
// ============================================================================
// WHAT THIS FILE PINS, AND WHY NONE OF THE EXISTING DEADLINE TESTS COULD.
// ============================================================================
//
// TlsQuicConnection.StartAsync set `_deadline = startedAt + HandshakeDeadline` once and nothing
// ever moved it, while ReceiveWithinDeadlineAsync re-read it on every wake for the whole life of
// the connection. Every test of that arrangement in this tree drove an UNCONFIRMED connection -
// they had to, because the deadline is the thing they were asserting - so the case where it
// keeps applying to a connection whose handshake succeeded was, until this file, a state no test
// entered. The field report is a proxied HTTP/3 dial on the shipped ten-second default: 19 to 48
// datagrams relayed over 9.2 seconds AFTER the handshake, every QUIC discard and retention
// counter zero, then a fault at the ten-second mark blaming a handshake that had confirmed nine
// seconds earlier.
//
// SO THE FIRST TEST BELOW IS THE ONE THE FIX IS FOR AND THE OTHER THREE ARE THE FENCES ROUND IT.
// A fix that simply stopped abandoning connections would pass the first and fail the second; one
// that stopped consulting the idle timeout as well would pass the first two and fail the third;
// one that let the idle period reach a timer unclamped would pass the first three and fail the
// fourth. RFC 9000 s10.1's three-PTO floor is fenced by
// TlsQuicConnectionTests.AShortAdvertisedIdleTimeoutIsRaisedToThreeProbeTimeouts, which needs
// nothing added here: the floor lives in EffectiveIdlePeriod, which one expression serves for
// both confirmed and unconfirmed connections.
public sealed partial class TlsQuicConnectionTests
{
    // ========================================================================
    // THE ONE THE FIX IS FOR.
    // ========================================================================

    // RFC 9000 s10.1: "If a max_idle_timeout is specified by either endpoint in its transport
    // parameters (Section 18.2), the connection is silently closed and its state is discarded
    // when it remains idle for longer than the minimum of the max_idle_timeout value advertised
    // by both endpoints." IDLE is the condition, and this connection is not idle - it is
    // exchanging 1-RTT packets with a peer that is answering. Nothing else in RFC 9000 bounds
    // it, and the handshake deadline is local policy about a handshake that is over.
    //
    // A SECOND AND ORDER OF MAGNITUDE OF FAKE TIME, SO THE CLAIM IS NOT ABOUT A MARGIN. The
    // deadline is one second and the clock is moved ten seconds past confirmation before the
    // first exchange and ten more before the second, on ManualTimeProvider - so the whole test
    // costs no real time and no jitter can blur the pre-fix and post-fix outcomes.
    //
    // TWO EXCHANGES AND NOT ONE, because the field evidence is 19 to 48 datagrams and a fix that
    // let exactly one through - by clearing some flag on first use - would be a different bug
    // wearing this one's clothes.
    [Fact]
    public async Task AConfirmedConnectionKeepsExchangingDatagramsPastTheHandshakeDeadline()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var impaired = new ImpairingDatagramTransport(clientTransport);

        // ONE SECOND OF DEADLINE AND AN HOUR OF IDLE TIMEOUT, which is the pairing the Connection
        // helper's own remarks warn has to be chosen deliberately: a test asserting that the
        // deadline has stopped applying must put the idle timeout far enough out that it cannot
        // be what let the pump through.
        var handshakeDeadline = TimeSpan.FromSeconds(1);
        await using var connection = Connection(
            new TlsQuicConnectionOptions(
                impaired, serverTransport.LocalEndPoint, Spec(), impaired.Clock)
            {
                HandshakeDeadline = handshakeDeadline,
                IdleTimeout = TimeSpan.FromHours(1),
            },
            pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await RunToOneRttAsync(connection, serverPeer, cancellation.Token);
        Assert.True(connection.IsHandshakeConfirmed);

        // PAST THE DEADLINE BEFORE THE FIRST EXCHANGE, not after it, so the pump is entered in
        // the state the field report describes rather than entering it partway through.
        impaired.Clock.Advance(handshakeDeadline * 10);

        // RFC 9000 s19.2 makes PING ack-eliciting, so the client owes an acknowledgment and the
        // pump returning true is the claim that it built and sent one - a stronger statement
        // than "no exception was thrown", which a pump that received nothing would also satisfy.
        for (var exchange = 0; exchange < 2; exchange++)
        {
            await serverPeer.SendOneRttFramesAsync(
                [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
                cancellation.Token);
            Assert.True(await connection.PumpOnceAsync(cancellation.Token));
            impaired.Clock.Advance(handshakeDeadline * 10);
        }

        // AND IT WAS NEVER GIVEN UP ON BY EITHER BOUND. IdleTimedOut is only written by
        // AbandonAsync, so a false here is a statement that AbandonAsync never ran - and
        // ClosedWith null is the same statement from the wire's side, since an abandonment that
        // is not the idle one owes s10.1's immediate close.
        Assert.False(connection.IdleTimedOut);
        Assert.Null(connection.ClosedWith);
        Assert.True(connection.IsHandshakeConfirmed);
    }

    // ========================================================================
    // THE THREE FENCES.
    // ========================================================================

    // THE HANDSHAKE PATH IS UNCHANGED, WHICH IS THE HALF OF THE FIX THAT IS A NON-EVENT. An
    // attempt that has not reached RFC 9001 s4.1.2's confirmation still dies at
    // TlsQuicConnectionOptions.HandshakeDeadline and still says so, because that deadline is a
    // bound on the handshake and the handshake is still running.
    //
    // THE MESSAGE IS ASSERTED AND NOT JUST THE TYPE. DeadlineExceeded's opening sentence claims
    // a handshake did not confirm; the whole point of the fix is that the sentence is now only
    // ever raised where it is true, so a test that accepted any TimeoutException would not be
    // pinning the half of the claim that is about the wording.
    [Fact]
    public async Task AnUnconfirmedConnectionStillDiesOnTheHandshakeDeadline()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // A SECOND OF DEADLINE AGAINST AN HOUR OF IDLE TIMEOUT, so the deadline is unambiguously
        // the nearer of the two and the answer is not an accident of the defaults.
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromSeconds(1),
            idleTimeout: TimeSpan.FromHours(1));

        // THE REPLY IS SCRIPTED PAST THE DEADLINE, which is how ScriptedDatagramTransport drives
        // the fake clock forward: the receive is armed at one second, the script would not
        // answer until two, and the timer fires on the way.
        transport.EnqueueReceive([1, 2, 3, 4], delay: TimeSpan.FromSeconds(2));

        await connection.StartAsync(cancellation.Token);
        Assert.False(connection.IsHandshakeConfirmed);

        var error = await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        Assert.False(connection.IdleTimedOut);
        Assert.Contains("did not confirm within", error.Message, StringComparison.Ordinal);
        Assert.False(connection.IsHandshakeConfirmed);
    }

    // RFC 9000 s10.1 STILL ENDS A CONFIRMED CONNECTION, AND THIS IS THE TEST THAT SAYS THE FIX
    // IS A NARROWING RATHER THAN A REMOVAL. A confirmed connection whose peer goes silent is
    // exactly the state s10.1 was written for - "the connection is silently closed and its state
    // is discarded" - and a fix that answered the field report by never abandoning a confirmed
    // connection would leak one of these per dead peer.
    //
    // ON THE REAL CLOCK BY NAME, for the reason
    // TlsQuicConnectionTests.APeerThatGoesSilentIsBoundedByTheIdleTimeoutToo gives: a peer that
    // goes SILENT never produces a clock reading, so only the CancellationTokenSource bounding
    // the await can end the receive, and ManualTimeProvider fires that source only from an
    // Advance no thread is left to call. So this one costs 250 milliseconds of wall clock and
    // says so.
    //
    // 250 MILLISECONDS IS ALSO THE HANDSHAKE'S OWN MARGIN AND THAT IS SAFE: s10.1's timer
    // restarts on every packet processed, the loopback handshake's gaps are in-process and
    // measured in microseconds, and everything expensive - the PKI, the credential, the server -
    // is built before StartAsync is called.
    //
    // NOTHING ADVERTISED, so the period is TlsQuicConnectionOptions.IdleTimeout unraised -
    // s10.1's floor applies to the advertised period and not to the local fallback, which is the
    // distinction EffectiveIdlePeriod's remarks draw and which keeps this test at a quarter of a
    // second instead of at three PTOs.
    [Fact]
    public async Task AConfirmedConnectionThatGoesSilentStillDiesOnTheIdleTimeout()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();

        // THIRTY SECONDS OF DEADLINE, so a mutant that abandoned on the handshake deadline
        // instead would be caught by the elapsed assertion below rather than passing this test
        // for the wrong reason.
        await using var connection = Connection(
            new TlsQuicConnectionOptions(
                clientTransport, serverTransport.LocalEndPoint, Spec(), TimeProvider.System)
            {
                HandshakeDeadline = TimeSpan.FromSeconds(30),
                IdleTimeout = TimeSpan.FromMilliseconds(250),
            },
            pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await RunToOneRttAsync(connection, serverPeer, cancellation.Token);
        Assert.True(connection.IsHandshakeConfirmed);

        var wallClock = System.Diagnostics.Stopwatch.StartNew();
        var error = await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        wallClock.Stop();

        // TRUE, AND TRUTHFULLY SO. AbandonAsync picks between the two abandonment deadlines by
        // which remaining is smaller, and on a confirmed connection the handshake one is
        // DateTimeOffset.MaxValue - so idle wins every time. That is not the comparison
        // degenerating: it is the only abandonment such a connection has.
        Assert.True(connection.IdleTimedOut);
        Assert.Contains("s10.1", error.Message, StringComparison.Ordinal);
        Assert.True(
            wallClock.Elapsed < TimeSpan.FromSeconds(10),
            $"The idle timeout took {wallClock.Elapsed}, so the receive was bounded by "
                + "something other than the 250-millisecond idle deadline.");
    }

    // THE IDLE PERIOD REACHES A REAL TIMER NOW, SO IT HAS TO BE A PERIOD A REAL TIMER ACCEPTS.
    // Before confirmation retired the handshake deadline, EarliestDeadline's minimum was capped
    // by it and nothing downstream could see a long period; afterwards the idle deadline arms
    // ReceiveWithinDeadlineAsync's CancellationTokenSource on its own, and that constructor
    // throws above roughly fifty days rather than clamping.
    //
    // AND THE NUMBER IS THE PEER'S, WHICH IS WHY THIS IS A GUARD AND NOT A TIDY-UP. RFC 9000
    // s18.2 states max_idle_timeout as a varint with no ceiling but s16's, and ToIdleTimeout
    // saturates it at a year precisely because "A PEER CHOOSES THIS NUMBER, so a conversion that
    // threw would be a remote kill switch". A year is fourteen hundred times what a timer can be
    // armed for, so without EffectiveIdlePeriod's clamp one legal transport parameter would turn
    // every post-handshake receive on this connection into an ArgumentOutOfRangeException.
    //
    // CANCELLED RATHER THAN EXPIRED, because the point is what the ARMING does and waiting out
    // the clamp would take fifty days. An OperationCanceledException from the outer token is a
    // receive that was armed and then interrupted; the pre-clamp failure is an
    // ArgumentOutOfRangeException thrown before the receive is ever entered, and the two are
    // told apart by type alone.
    [Fact]
    public async Task AConfirmedConnectionArmsAnIdlePeriodTheTimerCanExpress()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(
            new TlsQuicConnectionOptions(
                clientTransport, serverTransport.LocalEndPoint, Spec(), TimeProvider.System),
            pki);

        // s16's largest varint, the same value
        // TlsQuicConnectionTests.APeerAdvertisingTheLargestVarintIdleTimeoutSaturatesRatherThan
        // Overflowing uses - about 146 million years as milliseconds.
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            maxIdleTimeoutMilliseconds: (1UL << 62) - 1);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await RunToOneRttAsync(connection, serverPeer, cancellation.Token);
        Assert.True(connection.IsHandshakeConfirmed);

        // THE ADVERTISED VALUE IS UNTOUCHED BY THE CLAMP, which is the same separation
        // EffectiveIdleTimeout keeps from s10.1's floor: it is a fact about what the two
        // endpoints said, and the clamp is a fact about what this endpoint can arm.
        Assert.Equal(TimeSpan.FromDays(365), connection.EffectiveIdleTimeout());

        using var interrupt = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await connection.PumpOnceAsync(interrupt.Token));
    }
}
