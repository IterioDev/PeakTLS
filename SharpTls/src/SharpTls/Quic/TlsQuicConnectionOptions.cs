using System.Net;

namespace SharpTls.Quic;

// ============================================================================
// THE MUTATION LEDGER
// ============================================================================
//
//   ROWS BELOW                    1  = numbered 1-1 with no gaps
//   KILLED WHEN FIRST RUN         1  = 1 row, less 0 [WAS-SURVIVOR] and 0 [SURVIVED]
//   SURVIVED, THEN FIXED OR       0
//     WITNESSED
//   SURVIVING STILL               0
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' TlsQuicConnectionOptions.cs`                    must return 1
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicConnectionOptions.cs`   must return 0
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' TlsQuicConnectionOptions.cs`       must return 0
//
// ONE ROW, AND A LEDGER FOR IT RATHER THAN A ROW IN SOMEBODY ELSE'S. The rule this phase runs
// on is one ledger per file, so that each file's three greps stay about that file; a single
// mutation is a small ledger, not a reason to file it under TlsQuicConnection.cs. This file
// had no ledger before task 14d because until then it held only two timeouts and an exponent,
// each of which the connection's own rows already covered.
//
// Run against task 14d's 1166-case gate. Counts are per xUnit CASE, so a two-row Theory
// failing in both rows counts 2.
//
//    1. the required uni-stream count defaults to 0 instead of 3  4 tests
//
// THE FOUR ARE THE TWO s6.2 REFUSAL TESTS AND BOTH ROWS OF THE ABSENT-VERSUS-ZERO ONE, and
// what the row measures is that the DEFAULT is load-bearing rather than the option's
// existence: a 0 default makes the connection accept every peer, and the only test that sets
// the option explicitly - ACallerThatDoesNotSpeakHttp3CanLowerTheSection62Floor - sets it to
// 0 and so keeps passing. An option nobody defaults correctly is an option nobody has.

/// <summary>Everything one QUIC connection attempt needs that is not a layout decision: the
/// transport to send on, who to send to, the layout spec, and the clock.</summary>
/// <remarks>
/// <para>THE CLOCK IS A SEAM, NOT A CONVENIENCE. Every deadline this phase and A3 add reads
/// <see cref="TimeProvider"/> and never <c>DateTimeOffset.UtcNow</c>, <c>Stopwatch</c>,
/// <c>Task.Delay</c> or <c>Timer</c>. A test injects a subclass whose <c>GetUtcNow</c>
/// returns a field it moves by hand, so an idle timeout or a handshake deadline fires with
/// zero wall-clock time elapsed and fires at the same instant on every machine. The QUIC
/// sources contain no other clock today; anything that adds one puts the behaviour it
/// controls out of reach of a deterministic test, which is why the seam is decided here
/// rather than wherever the first timer happens to land.</para>
/// <para><see cref="TimeProvider"/> is .NET's own abstraction and already this repo's house
/// style - <c>Tls12SessionCache</c>, <c>Tls13SessionCache</c>, <c>Tls12ServerSessionCache</c>
/// and <c>TlsEchDnsResolver</c> all take one the same way, and their tests all drive it with
/// a hand-rolled subclass rather than a package. Do not add
/// <c>Microsoft.Extensions.TimeProvider.Testing</c> for it.</para>
/// <para>Neither timeout below is a fingerprint knob: they gate when this client gives up
/// and change no byte a peer or an observer sees. Layout knobs live on
/// <see cref="TlsQuicConnectionSpec"/> and nowhere else.</para>
/// </remarks>
internal sealed class TlsQuicConnectionOptions
{
    // Local policy, not an RFC constant and not copied from the capture.
    //
    // RFC 9000 s10.1 puts the authority elsewhere: "Each endpoint advertises a
    // max_idle_timeout, but the effective value at an endpoint is computed as the minimum of
    // the two advertised values (or the sole advertised value, if only one endpoint
    // advertises a non-zero value)." That minimum is applied by
    // TlsQuicConnection.EffectiveIdleTimeout, and THIS VALUE IS WHAT RUNS WHEN THERE IS NO
    // SUCH MINIMUM - s18.2's "Idle timeout is disabled when both endpoints omit this transport
    // parameter or specify a value of 0", where a client that never gave up would simply leak
    // an attempt. Chosen to match the max_idle_timeout of 30000 that the target profile
    // advertises, so the two do not disagree before the peer is heard from.
    private static readonly TimeSpan DefaultIdleTimeout = TimeSpan.FromSeconds(30);

    // Local policy with no RFC or capture source at all, and the one place where A3's
    // absence is visible from this file.
    //
    // A4-minimal has no loss detection and no PTO, so a single lost packet stalls the
    // handshake forever with no diagnosable error. This deadline ends that attempt cleanly.
    // IT IS A TIMEOUT, NOT A RETRANSMISSION: nothing is resent, and recovering from a lost
    // packet means starting a new attempt at the process level. When A3 adds a PTO this
    // stops being the only thing standing between a lost packet and a hung connection.
    private static readonly TimeSpan DefaultHandshakeDeadline = TimeSpan.FromSeconds(10);

    // RFC 9000 s18.2, ack_delay_exponent: "if this value is absent, a default value of 3 is
    // assumed (indicating a multiplier of 8)." and "Values above 20 are invalid."
    private const int DefaultAckDelayExponent = 3;
    private const int MaximumAckDelayExponent = 20;

    private readonly TimeSpan _idleTimeout = DefaultIdleTimeout;
    private readonly TimeSpan _handshakeDeadline = DefaultHandshakeDeadline;
    private readonly int _ackDelayExponent = DefaultAckDelayExponent;

    /// <summary>Creates connection options that read the system clock.</summary>
    /// <exception cref="ArgumentNullException">Any argument is
    /// <see langword="null"/>.</exception>
    public TlsQuicConnectionOptions(
        ITlsQuicDatagramTransport transport,
        IPEndPoint remoteEndPoint,
        TlsQuicConnectionSpec spec)
        : this(transport, remoteEndPoint, spec, TimeProvider.System)
    {
    }

    /// <summary>Creates connection options with an injected clock.</summary>
    /// <remarks>The public/internal split is the shape the repo's other
    /// <see cref="System.TimeProvider"/> consumers use, so that promoting this type out of
    /// <c>internal</c> would not leak the test seam. While the type itself is internal the
    /// distinction carries no access difference - it is kept for the shape.</remarks>
    /// <exception cref="ArgumentNullException">Any argument is
    /// <see langword="null"/>.</exception>
    internal TlsQuicConnectionOptions(
        ITlsQuicDatagramTransport transport,
        IPEndPoint remoteEndPoint,
        TlsQuicConnectionSpec spec,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(remoteEndPoint);
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(timeProvider);
        Transport = transport;
        RemoteEndPoint = remoteEndPoint;
        Spec = spec;
        TimeProvider = timeProvider;
    }

    /// <summary>Gets the transport datagrams are sent on and received from. Not owned: the
    /// caller disposes it.</summary>
    public ITlsQuicDatagramTransport Transport { get; }

    /// <summary>Gets the peer this connection sends to.</summary>
    public IPEndPoint RemoteEndPoint { get; }

    /// <summary>Gets every packet-layout decision this connection makes.</summary>
    public TlsQuicConnectionSpec Spec { get; }

    /// <summary>Gets the clock every deadline on this connection reads.</summary>
    public TimeProvider TimeProvider { get; }

    /// <summary>Gets how long the connection may sit idle before it is closed, until the
    /// peer's <c>max_idle_timeout</c> is known and RFC 9000 s10.1's minimum applies.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Not positive.</exception>
    public TimeSpan IdleTimeout
    {
        get => _idleTimeout;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(
                value, TimeSpan.Zero, nameof(IdleTimeout));
            _idleTimeout = value;
        }
    }

    /// <summary>Gets how long a handshake attempt may run before it fails cleanly. A
    /// timeout, never a retransmission - see the remark on the default.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Not positive.</exception>
    public TimeSpan HandshakeDeadline
    {
        get => _handshakeDeadline;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(
                value, TimeSpan.Zero, nameof(HandshakeDeadline));
            _handshakeDeadline = value;
        }
    }

    /// <summary>Gets the <c>ack_delay_exponent</c> THIS endpoint advertises, which is the
    /// one every ACK frame this connection generates is scaled by.</summary>
    /// <remarks>
    /// <para>RFC 9000 s19.3, ACK Delay: the field "is decoded by multiplying the value in
    /// the field by 2 to the power of the <c>ack_delay_exponent</c> transport parameter
    /// sent by the sender of the ACK frame." We are the sender of the ACKs we build, so
    /// this is OUR advertised value and never the peer's. The peer's exponent decodes ACKs
    /// we RECEIVE and belongs to A3's RTT sampling, which does not exist yet.</para>
    /// <para>IT IS HERE BECAUSE THE CONNECTION CANNOT READ IT FROM THE ONE PLACE IT IS
    /// ALREADY WRITTEN. The value we advertise lives in the <c>ack_delay_exponent</c>
    /// transport parameter baked into the immutable <c>ClientHelloProfile</c>, and
    /// <see cref="CustomTlsQuicClient"/> exposes neither its options nor that profile - so
    /// there is no path from the connection loop to the number it must agree with.
    /// <b>A caller that advertises a value MUST set the same one here.</b> A mismatch is
    /// silent in both directions: both values are legal, every frame still parses, and
    /// every delay we report is simply mis-scaled by 2^(advertised - this).</para>
    /// <para>The default is RFC 9000 s18.2's: "if this value is absent, a default value of
    /// 3 is assumed (indicating a multiplier of 8)." So leaving both unset agrees by
    /// construction, which is the only configuration this file can guarantee.</para>
    /// <para>Not a fingerprint knob in the <see cref="TlsQuicConnectionSpec"/> sense - the
    /// number an observer sees is the transport parameter, which subsystem B owns. This is
    /// the local copy the ACK encoder needs.</para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Negative, or above the 20 RFC 9000
    /// s18.2 caps the parameter at.</exception>
    public int AckDelayExponent
    {
        get => _ackDelayExponent;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value, nameof(AckDelayExponent));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(
                value, MaximumAckDelayExponent, nameof(AckDelayExponent));
            _ackDelayExponent = value;
        }
    }

    /// <summary>Gets how many unidirectional streams the peer must permit before this
    /// connection will proceed past the handshake. Defaults to RFC 9114 s6.2's three.</summary>
    /// <remarks>
    /// <para>THE NUMBER IS RFC 9114's, SO THE CHECK IS THE APPLICATION PROTOCOL'S AND NOT
    /// QUIC's - which is the entire reason it is a knob rather than a constant. s6.2, read
    /// past the wrap after "at least three": "Each endpoint needs to create at least one
    /// unidirectional stream for the HTTP control stream.  QPACK requires two additional
    /// unidirectional streams, and other extensions might require further streams.
    /// Therefore, the transport parameters sent by both clients and servers MUST allow the
    /// peer to create at least three unidirectional streams." A peer that advertises fewer
    /// has broken no RFC 9000 rule, so a QUIC connection carrying some other ALPN has every
    /// right to accept it; a caller says so by setting this to 0.</para>
    /// <para>The default is 3 rather than 0 because every profile this repo builds negotiates
    /// <c>h3</c>, and the precedent is task 9b's: the s7.3 connection ID checks were made
    /// unconditional and the cooperative test peers were changed to conform, because the
    /// permissive default was what had let a non-conforming peer through unnoticed.</para>
    /// <para>THE 1,024-BYTE CREDIT IN s6.2's NEXT SENTENCE IS NOT CHECKED, AND THAT IS NOT AN
    /// OVERSIGHT: "These transport parameters SHOULD also provide at least 1,024 bytes of
    /// flow-control credit to each unidirectional stream" is a SHOULD, and rejecting a peer
    /// for missing it would invent a MUST. Pinned by
    /// <c>TheThousandTwentyFourByteUnidirectionalCreditIsAShouldAndIsNotEnforced</c>.</para>
    /// </remarks>
    public ulong RequiredPeerUnidirectionalStreams { get; init; } =
        TlsQuicPeerFlowControlBudget.Http3RequiredUnidirectionalStreams;
}
