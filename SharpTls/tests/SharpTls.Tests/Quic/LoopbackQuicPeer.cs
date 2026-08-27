using System.Net;
using System.Runtime.InteropServices;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task 7 of A4-minimal: the loopback peer. One side's QUIC packet layer - tasks 4b, 5, 6
// and 9a-i - bolted under one TLS endpoint, over InMemoryDatagramTransport. Two instances
// of this class facing each other run a whole handshake in process, with no socket and no
// clock.
//
// ============================================================================
// WHAT THIS HARNESS CAN AND CANNOT WITNESS. READ THIS BEFORE TRUSTING A GREEN RUN.
// ============================================================================
//
// A loopback against ourselves shares our bugs. Seal and open are inverses, encode and
// decode are inverses, and this file wires our seal to our open and our encode to our
// decode. Any defect that lives in a matched pair - a wrong nonce construction used
// identically on both sides, an off-by-one in a CRYPTO offset written and read by the same
// arithmetic, a header protection sample offset computed the same way twice - cancels out
// exactly and leaves every test in LoopbackQuicPeerTests green.
//
// SO, ITEMISED:
//
//   SURVIVES A BUG SHARED BY BOTH HALVES - assertions about SEQUENCING. These are pinned
//   against the TLS state machine and the RFC 9001 s4 flight structure, neither of which
//   this file implements, so a symmetric packet-layer defect cannot forge them:
//     - the number of round trips a handshake takes, and that HelloRetryRequest costs
//       exactly one more (LoopbackQuicPeerTests.*RoundTrips*)
//     - the ORDER the flights arrive in. Not the level they are labelled with - see the
//       DOES NOT SURVIVE list below, where that half of this row now lives. Order is
//       anchored because a flight can only be opened once the keys it needs exist, and
//       those come out of the PREVIOUS flight's CRYPTO payload by way of the TLS state
//       machine: mutation row 14 coalesces the levels in descending order and kills 8
//       tests, not because anything reads the ordering but because the handshake stalls
//       when a packet arrives before the packet that yields its keys.
//     - that the client reaches complete strictly before the server does
//     - that a level's keys are installed before that level's first packet is built, and
//       that a discarded level cannot be written again
//     - how many packets each side built in each packet number space
//
//   SURVIVES FOR ONE SPECIFIC REASON, and it is the only byte-level fact here that does:
//   THE SERVER'S INITIAL READ DIRECTION. RFC 9001 s5.2 gives the two roles different
//   Initial secrets, and this harness pairs a client whose direction is anchored to
//   published vectors - TlsQuicKeySetTests pins isClient: true's write side against A.2
//   and its read side against A.3 - with a server whose isClient: false must be the exact
//   complement or nothing opens. So an inverted server direction cannot cancel: it would
//   have to be matched by an inverted client direction, and the client's is nailed down
//   outside this file by bytes we did not produce. Witnessed twice, positively by the
//   handshake completing at all and negatively by
//   LoopbackQuicPeerTests.AnInitialPacketProtectedWithTheServerSecretDoesNotOpenAtTheServer.
//
//   DOES NOT SURVIVE - assertions about BYTES. Nothing here pins the wire format:
//     - that our AEAD nonce is RFC 9001 s5.3's
//     - that our header protection mask is s5.4's
//     - that our Initial secrets are s5.2's
//     - that a long header is laid out as RFC 9000 s17.2 draws it
//     - WHICH ENCRYPTION LEVEL EACH FLIGHT ARRIVES AT. This row was in the SURVIVES list
//       above and it was WRONG. The level is a BYTE - RFC 9000 s17.2 Table 5's Long
//       Packet Type, 0x00 Initial / 0x01 0-RTT / 0x02 Handshake / 0x03 Retry - written
//       into byte 0 by our builder and read back out of it by our receiver, both through
//       TlsQuicLongPacketType's own numbering. Swapping ZeroRtt = 0x01 and Handshake =
//       0x02 in that enum survived all 1024 tests, this file's eleven included, because
//       encode and decode are inverses over the same table and cancel exactly. Nor could
//       leg 1 catch it: RFC 9001 Appendix A publishes an Initial client packet (A.2), an
//       Initial server packet (A.3) and a Retry (A.4), and NO HANDSHAKE PACKET at all,
//       so there is no vector whose bytes the swap would break. Now pinned outside this
//       file by TlsQuicPacketBuilderTests.EachLongHeaderTypeIsStampedIntoByteZeroWith
//       Table5sValue, which asserts the byte for all four types against the table.
//   Those are leg 1's job - the published vectors of RFC 9001 Appendix A, asserted byte
//   for byte in TlsQuicPacketBuilderTests (A.2, A.3), TlsQuicHeaderProtectionTests (A.5)
//   and TlsQuicKeySetTests (A.1 read direction against A.3's server packet). And leg 3's -
//   MsQuic, which is an implementation that does not share our bugs. THIS FILE IS NOT
//   INDEPENDENT VERIFICATION AND MUST NOT BE CITED AS ANY.
//
// Task 9a-i's read direction was inverted and passed all 1004 tests because every read
// assertion went through a boolean. "The handshake completed" is that same shape. It is
// true here only because the sequencing above is also true, and the sequencing is what the
// tests name.
//
// ============================================================================
// ROLE NEUTRALITY, WHICH IS WHY THIS IS ONE CLASS AND NOT TWO
// ============================================================================
//
// Tasks 4b, 5 and 6 take keys and a plan, never a role:
//   - TlsQuicPacketBuilder.Build(plan, frames, cipher, key, iv, ...) - no role parameter,
//     and its only client mentions are prose in remarks.
//   - TlsQuicDatagramBuilder.BuildDatagram(spec, packets, sentAt, destination) - same.
//     (BuildInitialFlight IS documented as the client's, and is deliberately not used
//     here: this harness does its own per-level framing so one code path serves both
//     sides. See SendAsync.)
//   - TlsQuicPacketReceiver.Receive(datagram, handler) - decrypts with whatever read keys
//     are installed and never asks who it is.
// Only TlsQuicKeySet.InstallInitialKeys takes an explicit isClient, which is RFC 9001
// s5.2's asymmetry and not an assumption: it selects which of the two Initial secrets
// protects writes. So both sides of this harness are the same class with that one flag.
//
// ============================================================================
// ONE LOOP, ONE THREAD OF CONTROL
// ============================================================================
//
// CustomTlsQuicClient's StartHandshake, NotifyHandshakePacketSent and ConfirmHandshake
// mutate state without taking the semaphore that guards ProcessCryptoDataAsync (A4
// Finding 6). RunHandshakeAsync therefore drives strictly one peer at a time and never
// concurrently. PumpOnceAsync is not safe to call on two peers in parallel and nothing
// here does.
//
// WHAT IS DELIBERATELY NOT BUILT, because the done-when does not need it and every line
// here is a line that can be wrong:
//   - ACK frames. TlsQuicAckTracker exists and is tested; a handshake completes without
//     one, because nothing in this harness retransmits.
//   - 1-RTT (short header) sending. TlsQuicPacketBuilder builds long headers only, and
//     both endpoints reach IsHandshakeComplete at the Handshake level. A caller that asks
//     for an Application-level send gets a NotSupportedException naming this.
//   - Loss, reordering, duplication and delay. NOT BUILT HERE AND NOT ScriptedDatagramTransport's
//     EITHER, WHICH IS WHAT THIS LINE USED TO SAY. That double's own remarks had already ruled
//     itself out - "record-and-replay is dead past the first flight" - so its reordering and
//     duplication are Initial-level only, and A3 needs both at Handshake and 1-RTT level.
//     A3-1 built ImpairingDatagramTransport for it: a decorator that wraps the transport
//     handed to ForClient or ForServer and impairs by a script of ordinals. That is why the
//     _transport field below is the interface rather than the concrete in-memory double.
//   - Coalescing more than one packet per datagram beyond what a flight naturally produces,
//     and path MTU. Still nobody's.
// ============================================================================
// THE MUTATION LEDGER
// ============================================================================
//
//   ROWS BELOW                   27  = numbered 1-27 with no gaps
//   KILLED WHEN FIRST RUN        21  = 27 rows, less 1 [WAS-SURVIVOR] and 5 [SURVIVED]
//   SURVIVED, THEN FIXED          1  = row 16
//   SURVIVING STILL               5  = rows 18-22, every one of them classified below
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' LoopbackQuicPeer.cs`                    must return 27
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' LoopbackQuicPeer.cs`   must return 1
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' LoopbackQuicPeer.cs`       must return 5
//
// ROWS 23-24 ARE A4 TASK 14c's, run against its 1136-test gate, re-measured after that task's
// last test landed. Counts are per xUnit CASE, so a two-row Theory failing in both counts 2. That task gave this file a
// 1-RTT RECEIVE path, which is the day ForServer's connection-ID length stopped being inert -
// row 23 is the value it used to be given.
//
// Rows 1-17 were run twice: once when written, and once more after row 16's fix added an
// eleventh test, so the kill counts below are all out of the 11 tests that exist now and
// not out of the 10 that existed during the first pass. A ledger whose figures were
// counted against an earlier suite is the flaw three ledgers in a row shipped with.
// Rows 18-22 are the fix round's own sweep, run once, against the 1026-test gate that
// round produced; row 2 and row 5 were re-run in it because the fix changed what they
// mean, and both are annotated with what the re-run showed.
//
//    1. The long-header guard deleted            ONLY ADatagramThatDoesNotOpenWithALongHeaderIsNamedRatherThanKeyedFromNothing
//    2. The ReceiveOne guard deleted entirely    ONLY AnInitialPacketProtectedWithTheServerSecretDoesNotOpenAtTheServer
//    3. A keyless level skipped, not named       ONLY WritingAtALevelWhoseKeysAreGoneIsNamedRatherThanSentUnprotected
//    4. Application CRYPTO built as Handshake    ONLY ASessionTicketIsRefusedByNameBecauseNoOneRttSendPathExists
//    5. Whole datagram opened in one Receive     8 tests
//    6. Secrets installed after the datagram     8 tests
//    7. Discards applied before the send         2 tests
//    8. NotifyHandshakePacketSent never called   ONLY BothSidesDiscardTheirInitialKeysWhileTheHandshakeIsStillRunning
//    9. Notify after any packet, not a Handshake one  9 tests
//   10. The packet number never advances         2 tests
//   11. Stall tested before completion           6 tests
//   12. The two connection IDs swapped on adoption  9 tests
//   13. The server keys its Initial level as a client  10 tests
//   14. Levels coalesced in descending order     8 tests
//   15. A datagram built for a flight with no CRYPTO  8 tests
//   16. Every frame delivered, not only CRYPTO   [WAS-SURVIVOR] -> now ONLY APaddedInitialDatagramDeliversOneChunkOfCryptoStreamAndNotOneThousand
//   17. The client keys its Initial level as a server  9 tests
//   18. The defensive .ToArray() dropped        [SURVIVED] 0 of 1026 - unwitnessable
//   19. The guard's `Discarded > 0` dropped     [SURVIVED] 0 of 1026 - unreachable here
//   20. The guard's `Unprocessed != None` dropped   [SURVIVED] 0 of 1026 - unreachable here
//   21. The NotifyHandshakePacketSent event-kind check deleted  [SURVIVED] 0 of 1026
//   22. The guard's `Processed == 0` dropped    [SURVIVED] 0 of 1026 - unreachable here
//   23. The short-header length back to the client's SOURCE one  3 tests
//   24. The ACK names a packet number one too low  ONLY AOneRttPacketThisConnectionSentIsAcknowledgedByTheLoopbackPeer
//   25. The STREAM frame recording deleted      3 tests
//   26. The FIN read off the wire type replaced with a constant false  2 tests
//   27. The recorded offset replaced with 0     ONLY AUnidirectionalStreamCarriesItsBytesToTheLoopbackPeerWithOffsetsAndFin
//
// ROWS 25-27 ARE TASK 14e's AND WERE MEASURED AT ITS OWN 1303-CASE GATE, not at the 1026 rows
// 1-24 carry; the two figures are not comparable and are labelled rather than averaged.
//
// THE THREE ARE SEPARATE ROWS BECAUSE THEY FAIL AT DIFFERENT DEPTHS, and the shallowest is the
// one worth having. Row 25 removes the recording outright and takes three tests with it - that
// is the harness not looking. Rows 26 and 27 keep the recording and corrupt ONE FIELD of it,
// which is the failure mode a test asserting "a STREAM frame arrived" cannot see at all: RFC
// 9000 s19.8's offset and FIN bit are the two fields that make a stream a stream rather than a
// bag of bytes, and a peer that reported both as zero would agree with a send path that never
// advanced its offset and never set its FIN.
//
// ROW 23 IS THE ONE THAT MATTERED IN TASK 14c, AND IT WAS A REAL DEFECT RATHER THAN A CHECK.
// ForServer took a parameter called peerSourceConnectionIdLength, documented as "the
// Destination Connection ID length this peer would need to parse a short header", and every
// caller passed the length of the client's SOURCE connection ID - 5 where the answer is 8.
// The parameter said of itself that it was "only load-bearing the day a 1-RTT receive path
// arrives here", and that day arrived with this task: a short header from the client carries
// as its destination whatever RFC 9000 s7.2 had the client ADOPT, which is this peer's own
// Source Connection ID, copied out of the first Initial packet's DESTINATION field. The
// parameter is gone and the length comes off TlsQuicConnectionSpec, so no caller can restate
// it wrongly. A COMMENT THAT NAMES THE DAY ITS VALUE STARTS TO MATTER IS WORTH WRITING; this
// one was right about the day and wrong about the value.
//
// ROW 5 IS THE ONE THAT MATTERED, and it is the only row here that was a real defect
// rather than a check on a guard: the first version of this file did hand the whole
// datagram to TlsQuicPacketReceiver in one call, and the handshake stalled with every
// packet accounted for and nothing wrong on the wire. See PumpOnceAsync.
//
// ROWS 13 AND 17 ARE THE PAIR THAT ANSWERS "PRESENCE IS NOT IDENTITY" HERE. Inverting
// either side's Initial direction kills nine or ten of eleven tests, and row 13 also
// flips the negative test from passing to failing, because a server reading with the
// server secret opens the very packet that test says it must not. Task 9a-i's inversion
// survived 1004 tests; here it cannot survive one, because the two directions are wired
// to each other and one of them is anchored outside this file to RFC 9001 Appendix A.
//
// ROW 16 WAS UNWITNESSED, NOT VACUOUS. Handing every frame to the TLS endpoint left all
// ten tests then green: the only non-CRYPTO frame this harness meets is PADDING, whose
// Data is empty and whose offset is zero, and both endpoints treat an empty chunk at
// offset zero as a no-op. So the mutant was observationally identical for as long as
// nothing else carried bytes - which is an accident of what the TLS layer tolerates and
// not a property of the filter. Fixed by making the delivery COUNT observable rather than
// by loosening anything: DeliveredCryptoChunks, asserted at 1 against a 1200-byte padded
// Initial packet holding roughly a thousand PADDING frames beside its one CRYPTO frame.
//
// ============================================================================
// AMENDMENTS AFTER TASK 7
// ============================================================================
//
// Both review gates passed this file and both left findings. Task 6 was NOT defective and
// the split loop below is NOT a workaround - both reviewers reached that independently and
// it was verified against the mechanism, not the comments. What follows is what they found
// instead, kept here because the next task down the chain needs it before it starts.
//
// A. THE COALESCING SPLIT IS PERMANENT, AND IT COSTS THE CONNECTION ID CHECK.
//
//    TlsQuicPacketReceiver.Receive ALREADY walks coalesced packets - RFC 9000 s12.2,
//    "Receivers MUST be able to process coalesced packets" - with the same
//    TlsQuicDatagramReader.Read iterator and the same running-offset re-slice PumpOnceAsync
//    uses below. What it cannot do is install keys PART-WAY THROUGH that walk, because key
//    installation goes through the TLS engine and that is async, while Receive's own header
//    guarantees one synchronous pass over unsynchronised _keys and _scratch. That is BY
//    CONSTRUCTION and will not be fixed later. s12.2 says coalescing in increasing
//    encryption level order "makes it more likely that the receiver will be able to process
//    all the packets in a single pass"; MORE LIKELY, not certain, and for Initial+Handshake
//    it never can be, because the Handshake keys come out of the Initial packet's payload.
//
//    So splitting is a PERMANENT CALLER RESPONSIBILITY. It is now written into Receive's
//    own doc-comment rather than living only here, because task 9a-ii's connection loop is
//    a different caller that will otherwise rediscover it as a stall.
//
//    AND SPLITTING SILENTLY FORFEITS s12.2's "Receivers SHOULD ignore any subsequent
//    packets with a different Destination Connection ID than the first packet in the
//    datagram." That check is enforced inside Receive by a LOCAL, re-nulled on every call,
//    so one call per packet means one "first packet" per packet and the clause never
//    applies. Measured: a mutation neutering that check dies to exactly ONE test - task 6's
//    own ASubsequentPacketWithADifferentConnectionIdIsIgnored - and to ZERO of this file's.
//    A splitting caller that wants the clause back must compare the IDs across its own
//    calls. TlsQuicReceiveResult.DiscardedForMissingKeys was added in the same round so the
//    stall can be DETECTED rather than inferred.
//
// B. AN UNWITNESSED WIRE CONSTANT, AND WHY LEG 1 COULD NOT SEE IT.
//
//    Swapping ZeroRtt = 0x01 and Handshake = 0x02 in TlsQuicLongPacketType survived all
//    1024 tests. The values were RIGHT - RFC 9000 s17.2 Table 5: 0x00 Initial, 0x01 0-RTT,
//    0x02 Handshake, 0x03 Retry - but nothing asserted them. This is a CLASS of defect,
//    not one bug: a WIRE CONSTANT whose only uses are an encode/decode pair over the same
//    table cancels exactly, and when no published vector covers it, LEG 1 IS BLIND TO IT BY
//    CONSTRUCTION. RFC 9001 Appendix A gives an Initial client packet, an Initial server
//    packet and a Retry, and no Handshake packet at all - so every Handshake packet this
//    library sent would have gone out stamped 0-RTT, MsQuic would have rejected it, and
//    nothing in this repository would have noticed until leg 3.
//
//    Now killed by TlsQuicPacketBuilderTests.EachLongHeaderTypeIsStampedIntoByteZeroWith
//    Table5sValue, which pins the byte for all four types against the table on built
//    packets. WHOEVER ADDS THE NEXT WIRE CONSTANT: ask whether anything outside the
//    encode/decode pair reads it. If not, it needs a byte assertion quoted from the RFC,
//    not a round trip.
//
// C. A FALSE ROW IN THE HONESTY SECTION, WHICH IS THE WORST PLACE TO HAVE ONE.
//
//    "Which encryption level each flight arrives at, and in which order" was filed under
//    SURVIVES A BUG SHARED BY BOTH HALVES. The LEVEL half did not survive - it is B's byte,
//    written and read by this file's own pair - and B is the proof. It has been moved to
//    DOES NOT SURVIVE; the ORDER half stayed, and now carries the reason it is anchored
//    (a flight cannot be opened before the flight that yields its keys, which is row 14).
//
//    WHAT THAT SAYS ABOUT SELF-CHECKING HARNESSES. The honesty section is the most valuable
//    thing in this file precisely because a reader trusts it INSTEAD OF re-deriving it, so
//    a wrong row is worse than no row: it converts an unwitnessed fact into a fact someone
//    believes is witnessed. The row was wrong in the specific way that is easiest to get
//    wrong - the SEQUENCING it claimed really is anchored, and the LABEL riding along with
//    it is not, and the two were written on one line. When a row bundles two facts, split
//    it and check them separately; symmetric harnesses are exactly where that difference
//    stops being visible.
internal sealed class LoopbackQuicPeer : IAsyncDisposable
{
    private const int DatagramBufferSize = 65527;

    // THE INTERFACE RATHER THAN InMemoryDatagramTransport, WHICH IS THE ONLY THING A3-1
    // CHANGED IN THIS FILE. Nothing here ever needed more than SendAsync, ReceiveAsync and
    // DisposeAsync - the concrete type was never load-bearing - and the interface is what lets
    // ImpairingDatagramTransport sit under this peer, so that a datagram this side sends can
    // be dropped, duplicated, reordered or delayed at Handshake and 1-RTT level. Every caller
    // still passes an InMemoryDatagramTransport and none of them had to change.
    private readonly ITlsQuicDatagramTransport _transport;
    private readonly IPEndPoint _peerEndPoint;
    private readonly TlsQuicPacketReceiver _receiver;

    /// <summary>How many packets this peer's receiver has discarded as RFC 9000 s12.3
    /// duplicates.</summary>
    internal int DuplicatesSuppressed => _receiver.DuplicatesSuppressed;
    private readonly TlsQuicKeySet _keys;
    private readonly TlsQuicConnectionSpec _spec;
    private readonly bool _isClient;
    private readonly ProcessCryptoData _processCryptoData;
    private readonly Func<bool> _isHandshakeComplete;
    private readonly Func<TlsQuicProcessResult>? _notifyHandshakePacketSent;
    private readonly byte[] _receiveBuffer = new byte[DatagramBufferSize];
    private readonly byte[] _sendBuffer = new byte[DatagramBufferSize];

    // Indexed by TlsQuicEncryptionLevel. Initial, Handshake and Application are three
    // separate packet number spaces (RFC 9000 s12.3); EarlyData shares Application's and is
    // never used here because this harness sends no 0-RTT.
    private readonly ulong[] _nextPacketNumber = new ulong[4];

    private byte[] _destinationConnectionId;
    private byte[] _sourceConnectionId;
    private bool _initialKeysInstalled;
    private bool _disposed;

    internal delegate ValueTask<TlsQuicProcessResult> ProcessCryptoData(
        TlsQuicEncryptionLevel level,
        ulong offset,
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken);

    private LoopbackQuicPeer(
        ITlsQuicDatagramTransport transport,
        IPEndPoint peerEndPoint,
        TlsQuicConnectionSpec spec,
        bool isClient,
        byte[] destinationConnectionId,
        byte[] sourceConnectionId,
        ProcessCryptoData processCryptoData,
        Func<bool> isHandshakeComplete,
        Func<TlsQuicProcessResult>? notifyHandshakePacketSent,
        int receiverConnectionIdLength)
    {
        _transport = transport;
        _peerEndPoint = peerEndPoint;
        _spec = spec;
        _isClient = isClient;
        _destinationConnectionId = destinationConnectionId;
        _sourceConnectionId = sourceConnectionId;
        _processCryptoData = processCryptoData;
        _isHandshakeComplete = isHandshakeComplete;
        _notifyHandshakePacketSent = notifyHandshakePacketSent;

        // FROM THE SPEC, NOT A LITERAL. RFC 9369's version 2 changes the Initial salt, the
        // key-derivation labels and the long-header type numbering all at once, so a harness
        // pinned to version 1 can only ever prove version 1 works. Both sides read the same
        // property, which is what lets one test run a whole handshake in version 2.
        _receiver = new TlsQuicPacketReceiver(
            (uint)spec.Version, receiverConnectionIdLength);
        _keys = new TlsQuicKeySet(_receiver, spec.Version);
    }

    /// <summary>The client side. It chooses both connection IDs, so its Initial keys are
    /// available before the first packet exists.</summary>
    internal static LoopbackQuicPeer ForClient(
        ITlsQuicDatagramTransport transport,
        IPEndPoint peerEndPoint,
        CustomTlsQuicClient client,
        byte[] destinationConnectionId,
        byte[] sourceConnectionId,
        TlsQuicConnectionSpec spec)
    {
        ArgumentNullException.ThrowIfNull(client);

        var peer = new LoopbackQuicPeer(
            transport,
            peerEndPoint,
            spec,
            isClient: true,
            destinationConnectionId,
            sourceConnectionId,
            client.ProcessCryptoDataAsync,
            () => client.IsHandshakeComplete,
            client.NotifyHandshakePacketSent,
            // A short header from the server would carry this peer's own Source Connection
            // ID as its destination, and that is the length the receiver needs to find the
            // packet number behind it.
            sourceConnectionId.Length);

        // RFC 9001 s5.2: the client's Initial secrets come from the Destination Connection
        // ID it chose itself, so there is nothing to learn from the wire first.
        peer._keys.InstallInitialKeys(destinationConnectionId, isClient: true);
        peer._initialKeysInstalled = true;
        return peer;
    }

    /// <summary>The server side. It has no connection IDs and no Initial keys until the
    /// first Initial packet arrives, exactly as RFC 9001 s5.2 leaves it.</summary>
    /// <remarks>
    /// THE SHORT-HEADER CONNECTION ID LENGTH IS THE CLIENT'S <i>DESTINATION</i> ONE, AND IT
    /// USED TO BE A PARAMETER CARRYING THE CLIENT'S <i>SOURCE</i> LENGTH. That parameter said
    /// of itself that it was "only load-bearing the day a 1-RTT receive path arrives here",
    /// and task 14c is that day: it was wrong, and it was passed 5 where the answer is 8.
    /// A short header from the client carries as its Destination Connection ID whatever RFC
    /// 9000 s7.2 had the client adopt - this peer's own Source Connection ID, which
    /// <see cref="AdoptConnectionIdsAndKeyTheInitialLevel"/> copies out of the first Initial
    /// packet's DESTINATION field. So the length is <see cref="TlsQuicConnectionSpec.Destinat
    /// ionConnectionIdLength"/>, off the same spec the client builds its packets from, and no
    /// caller has to restate it.
    /// </remarks>
    internal static LoopbackQuicPeer ForServer(
        ITlsQuicDatagramTransport transport,
        IPEndPoint peerEndPoint,
        CustomTlsQuicServer server,
        TlsQuicConnectionSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);

        ArgumentNullException.ThrowIfNull(server);

        // Zero-length placeholders for the connection IDs themselves. The first received
        // long header replaces both, and until then this peer cannot build a packet at all -
        // which is correct, because it has nothing to say and no keys to say it with.
        var peer = new LoopbackQuicPeer(
            transport,
            peerEndPoint,
            spec,
            isClient: false,
            destinationConnectionId: [],
            sourceConnectionId: [],
            server.ProcessCryptoDataAsync,
            () => server.IsHandshakeComplete,
            notifyHandshakePacketSent: null,
            spec.DestinationConnectionIdLength);
        return peer;
    }

    internal bool IsHandshakeComplete => _isHandshakeComplete();

    /// <summary>The Source Connection ID this peer puts on the packets it builds. For the
    /// server this is the client-chosen Destination Connection ID it learned from the
    /// wire, which is also what its Initial keys were derived from.</summary>
    internal ReadOnlyMemory<byte> SourceConnectionId => _sourceConnectionId;

    /// <summary>The next packet number this peer will use at <paramref name="level"/>,
    /// which is also the count of packets it has built there.</summary>
    internal ulong NextPacketNumber(TlsQuicEncryptionLevel level) =>
        _nextPacketNumber[(int)level];

    internal TlsQuicKeyLevelState WriteStateOf(TlsQuicEncryptionLevel level) =>
        _keys.WriteStateOf(level);

    internal bool HasReadKeys(TlsQuicEncryptionLevel level) => _receiver.HasReadKeys(level);

    /// <summary>The largest packet number this peer has opened in RFC 9000 s12.3's
    /// Application space, or <see langword="null"/> if it has opened none there. What
    /// <see cref="SendAckAsync"/> acknowledges.</summary>
    internal ulong? LargestApplicationPacketNumberReceived { get; private set; }

    /// <summary>The Data of the last PATH_RESPONSE frame this peer opened, or
    /// <see langword="null"/> if it has opened none. RFC 9000 s19.18 requires it to equal the
    /// Data of the PATH_CHALLENGE that provoked it.</summary>
    internal ReadOnlyMemory<byte>? LastPathResponseData { get; private set; }

    /// <summary>The last CONNECTION_CLOSE frame this peer opened, as the three RFC 9000 s19.19
    /// fields that decide what it says - the raw Type (0x1c or 0x1d), the Error Code, and the
    /// Reason Phrase - or <see langword="null"/> if it has opened none. The encryption level is
    /// the fourth, and it is the one s12.4 Table 3 and s10.2.3 constrain.</summary>
    /// <remarks>
    /// THE RAW TYPE RATHER THAN <see cref="TlsQuicFrame.Type"/>, because s19.19 spends a whole
    /// frame type on the distinction this records - "Type (i) = 0x1c..0x1d" - while
    /// TlsQuicFrame.Type maps both onto TlsQuicFrameType.ConnectionClose. A witness reading
    /// Type could not tell an application close from a transport one, which is the entire
    /// question s10.2.3's conversion rule turns on. <see cref="LastDatagramFrames"/> carries
    /// only that same collapsed type, for the same reason the STREAM and PATH_RESPONSE
    /// recorders above exist beside it.
    /// </remarks>
    internal (ulong RawType, ulong ErrorCode, byte[] ReasonPhrase, TlsQuicEncryptionLevel Level)?
        LastConnectionClose
    { get; private set; }

    /// <summary>Every RFC 9000 s19.8 STREAM frame this peer has opened, in arrival order, as
    /// the four fields s19.8 gives one: the stream id, the offset (0 when the OFF bit was
    /// clear, which s19.8 says is the same value), the Stream Data, and the FIN bit.</summary>
    /// <remarks>NOT CLEARED PER PUMP, unlike <see cref="LastDatagramFrames"/>: a stream is a
    /// sequence across datagrams and the claim task 14e makes - that offsets and ordering
    /// round-trip - is about the whole sequence rather than one datagram's slice of it.
    /// </remarks>
    internal List<(ulong StreamId, ulong Offset, byte[] Data, bool Fin)> ReceivedStreamFrames
    { get; } = [];

    /// <summary>How many pieces of CRYPTO stream this peer has handed to its TLS
    /// endpoint.</summary>
    /// <remarks>
    /// EXISTS TO WITNESS THE FRAME FILTER IN <see cref="ReceiveOne"/>, which nothing else
    /// could see. Delivering every frame rather than only CRYPTO ones leaves all ten tests
    /// green: the only non-CRYPTO frame this harness ever meets is PADDING, whose Data is
    /// empty and whose offset is zero, and both TLS endpoints treat an empty chunk at
    /// offset zero as a no-op. The filter is therefore right for a reason the handshake
    /// cannot show - it would stop being a no-op the first time any other frame carried
    /// bytes - so the count is asserted instead.
    /// </remarks>
    internal int DeliveredCryptoChunks { get; private set; }

    /// <summary>Every frame the LAST <see cref="PumpOnceAsync"/> opened, in wire order, with
    /// the encryption level of the packet that carried it. Cleared per pump.</summary>
    /// <remarks>Exists so the two order knobs on <c>TlsQuicConnectionSpec</c> -
    /// <c>CoalesceAscendingByLevel</c> and <c>AckLeadsInPacket</c> - can be witnessed. Both
    /// decide bytes that sit under the AEAD, so the sending side cannot read them back and
    /// the receiving side is the only vantage point there is.</remarks>
    internal IReadOnlyList<(TlsQuicEncryptionLevel Level, TlsQuicFrameType Type)>
        LastDatagramFrames => _lastDatagramFrames;

    private readonly List<(TlsQuicEncryptionLevel Level, TlsQuicFrameType Type)>
        _lastDatagramFrames = [];

    /// <summary>Drives one whole handshake, one peer at a time, and returns how many pumps
    /// it took. The client's opening flight is sent before the first pump, so the count is
    /// the number of flights that answered it.</summary>
    /// <remarks>
    /// STRICTLY SEQUENTIAL, and that is a correctness requirement rather than a style: A4
    /// Finding 6 records that CustomTlsQuicClient's StartHandshake, NotifyHandshakePacketSent
    /// and ConfirmHandshake mutate state outside the semaphore that guards
    /// ProcessCryptoDataAsync. Two peers pumped concurrently would race that state.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The handshake stalled - a peer took a
    /// datagram and produced nothing to send back while neither side was complete - or it
    /// ran past <paramref name="maximumRounds"/>.</exception>
    internal static async ValueTask<int> RunHandshakeAsync(
        LoopbackQuicPeer client,
        LoopbackQuicPeer server,
        TlsQuicProcessResult start,
        DateTimeOffset sentAt,
        int maximumRounds = 8,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(start);

        await client.SendAsync(start, sentAt, cancellationToken).ConfigureAwait(false);

        var turn = server;
        for (var round = 1; round <= maximumRounds; round++)
        {
            var sent = await turn.PumpOnceAsync(sentAt, cancellationToken).ConfigureAwait(false);

            // CHECKED BEFORE THE STALL TEST, not after. The last pump of a handshake is the
            // one where the server takes the client's Finished and has nothing to answer
            // with; that is completion, not a stall.
            if (client.IsHandshakeComplete && server.IsHandshakeComplete)
            {
                return round;
            }

            if (!sent)
            {
                throw new InvalidOperationException(
                    $"The handshake stalled at round {round}: "
                        + $"{(turn._isClient ? "the client" : "the server")} took a datagram and "
                        + "produced nothing to send, with neither side complete.");
            }

            turn = ReferenceEquals(turn, server) ? client : server;
        }

        throw new InvalidOperationException(
            $"The handshake did not complete within {maximumRounds} rounds.");
    }

    /// <summary>Takes exactly one datagram, feeds every CRYPTO frame in it to this peer's
    /// TLS endpoint in arrival order, and sends whatever that produced. Returns whether
    /// anything went back out.</summary>
    internal async ValueTask<bool> PumpOnceAsync(
        DateTimeOffset sentAt, CancellationToken cancellationToken = default)
    {
        var received = await _transport
            .ReceiveAsync(_receiveBuffer, cancellationToken)
            .ConfigureAwait(false);
        var datagram = _receiveBuffer.AsMemory(0, received.Length);

        _lastDatagramFrames.Clear();

        if (!_initialKeysInstalled)
        {
            AdoptConnectionIdsAndKeyTheInitialLevel(datagram);
        }

        var results = new List<TlsQuicProcessResult>();
        try
        {
            // ONE COALESCED PACKET AT A TIME, with the keys from each installed before the
            // next is opened. RFC 9000 s12.2 lets a server put its whole flight in one
            // datagram - an Initial packet carrying ServerHello followed by a Handshake
            // packet carrying the rest - and RFC 9001 s4.1.1 means the second is protected
            // with keys the TLS layer only derives from the first. Handing the whole
            // datagram to TlsQuicPacketReceiver in one call meets the Handshake packet with
            // no Handshake read keys and discards it, and the handshake then stalls with
            // every packet accounted for and nothing wrong on the wire.
            //
            // MEASURED, NOT PREDICTED: that is exactly how this file failed before this loop
            // existed, and it is why LoopbackQuicPeerTests drives the non-HRR case pump by
            // pump - a stall here has no symptom other than a flight that produced nothing.
            //
            // ============================================================================
            // THIS LOOP AWAITS INSIDE A LAZY ITERATOR. TlsQuicDatagramReader.Read's own
            // contract says the sequence "MUST therefore be enumerated synchronously and
            // completely, in place ... never stored across an await", and the
            // ProcessCryptoDataAsync below is inside the foreach body. This is the ONLY
            // place in the tree that does it, and it is safe here for reasons that are
            // arithmetic rather than luck - so the arithmetic is written down, because
            // whoever copies this shape into a context with two writers needs to know
            // exactly what they would be relying on:
            //
            //   1. THE READER'S CURSOR ONLY MOVES FORWARD, AND THE WRITES ONLY GO BACKWARD
            //      OF IT. When the body runs for the packet at [offset - packet.Length,
            //      offset), Read has already parsed that packet's header and advanced its
            //      own cursor to `offset`. Everything ReceiveOne does to the buffer -
            //      RFC 9001 s5.4 header protection removal, which is in place, and the AEAD
            //      open, which writes into the receiver's own scratch and not into this
            //      buffer at all - lands at or after `offset - packet.Length` and strictly
            //      before `offset`. So the bytes the reader has yet to look at are byte-for-
            //      byte identical when it resumes, and the boundaries it yields after the
            //      await are the same ones it would have yielded before it.
            //   2. THERE IS EXACTLY ONE WRITER OF _receiveBuffer, and it is the
            //      ReceiveAsync at the top of this method. RunHandshakeAsync drives one peer
            //      at a time and never two in parallel (see ONE LOOP, ONE THREAD OF CONTROL
            //      above), so no await inside this loop can let another receive refill the
            //      buffer under the reader.
            //
            // BOTH ARE LOAD-BEARING. (1) alone is not enough - a second writer would
            // invalidate the whole datagram, not just the part behind the cursor - and (2)
            // alone is not enough either, because a body that wrote FORWARD of `offset`
            // would corrupt boundaries the reader has not read yet even with one writer.
            // ============================================================================
            var offset = 0;
            foreach (var coalesced in TlsQuicDatagramReader.Read(datagram))
            {
                // The reader hands back a read-only view; the receiver needs the writable
                // one, because removing header protection is done in place. Same running
                // offset the receiver keeps internally, for the same reason.
                var packet = _receiveBuffer.AsMemory(offset, coalesced.Packet.Length);
                offset += packet.Length;

                foreach (var chunk in ReceiveOne(packet))
                {
                    var result = await _processCryptoData(
                            chunk.Level, chunk.Offset, chunk.Data, cancellationToken)
                        .ConfigureAwait(false);
                    results.Add(result);
                    DeliveredCryptoChunks++;

                    // Before the next packet of this datagram is opened, not after the whole
                    // datagram is done.
                    InstallSecrets(result);
                }
            }

            return await SendAndDiscardAsync(results, sentAt, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            // AFTER SendAsync, never before. TlsQuicProcessResult.Dispose zeroes the traffic
            // secrets it carries, and TlsQuicKeySet.InstallFromTrafficSecret rejects an
            // all-zero secret precisely so that this ordering mistake is a throw rather than
            // a handshake that stalls with structurally valid keys nobody can decrypt.
            foreach (var result in results)
            {
                result.Dispose();
            }
        }
    }

    /// <summary>Installs the keys one result carries, sends its CRYPTO data, then applies
    /// its key discards. The caller keeps ownership of <paramref name="result"/>.</summary>
    internal ValueTask<bool> SendAsync(
        TlsQuicProcessResult result,
        DateTimeOffset sentAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        InstallSecrets(result);
        return SendAndDiscardAsync([result], sentAt, cancellationToken);
    }

    /// <summary>Sends one 1-RTT packet carrying a HANDSHAKE_DONE frame - RFC 9001 s4.1.2's
    /// only client-side trigger for handshake CONFIRMED.</summary>
    /// <remarks>
    /// <para>THE ONE SHORT HEADER THIS FILE WRITES, and it is written by hand rather than
    /// through <see cref="TlsQuicPacketBuilder"/> because that builder is long-header only
    /// (RFC 9000 s17.2); task 14 owns 1-RTT sending under <c>src/</c>. It exists because task
    /// 9a-ii's done-when needs a real HANDSHAKE_DONE to arrive from a peer, and nothing else
    /// in this tree can produce one.</para>
    /// <para>WHAT IT WITNESSES: SEQUENCING, and one thing more. That a client confirms on
    /// receipt of this frame and not on TLS completion is a statement about order that a
    /// symmetric packet-layer defect cannot forge, because the trigger is a frame type from
    /// RFC 9000 s19.20 and the state it releases is RFC 9001 s4.9.2's. And the AEAD opening
    /// at all proves the two TLS endpoints agreed on the Application traffic secret, which is
    /// the TLS state machine's doing rather than this file's.</para>
    /// <para>WHAT IT DOES NOT WITNESS: BYTES. Every constant below - the short header layout,
    /// the key phase bit, the nonce construction, the sample offset - is written here and
    /// read by our own receiver, and RFC 9001 Appendix A publishes NO 1-RTT vector, so a
    /// defect shared by the two halves cancels exactly. This is the same blindness the file
    /// header's amendment B names for TlsQuicLongPacketType, and it is worse here: a long
    /// header at least has A.2 and A.3 behind two of its four types.</para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">No Application write keys - the handshake
    /// has not produced them yet.</exception>
    /// <param name="pathChallengeData">
    /// Eight bytes to send as an RFC 9000 s19.17 PATH_CHALLENGE frame beside HANDSHAKE_DONE,
    /// or <see langword="null"/> for none. It rides in this packet because s12.4 Table 3 gives
    /// PATH_CHALLENGE the row "__01" - a 1-RTT packet is the only one a server can put one in,
    /// and this method builds the only 1-RTT packet in the test tree.
    /// </param>
    internal ValueTask SendHandshakeDoneAsync(
        DateTimeOffset sentAt,
        CancellationToken cancellationToken = default,
        byte[]? pathChallengeData = null)
    {
        _ = sentAt;

        var frames = new List<TlsQuicFrame>
        {
            new() { RawType = (ulong)TlsQuicFrameType.HandshakeDone },
        };

        if (pathChallengeData is not null)
        {
            frames.Add(new TlsQuicFrame
            {
                RawType = (ulong)TlsQuicFrameType.PathChallenge,
                Data = pathChallengeData,
            });
        }

        var written = BuildShortHeaderDatagram(frames);
        return _transport.SendAsync(
            _peerEndPoint, _sendBuffer.AsMemory(0, written), cancellationToken);
    }

    /// <summary>Sends one 1-RTT packet carrying exactly the frames given, for the dispatch
    /// rules whose input is a frame type this peer has no other reason to send.</summary>
    /// <remarks>
    /// <para>DELIBERATELY UNVALIDATED. A conforming server would not send a
    /// RETIRE_CONNECTION_ID to an endpoint with a zero-length connection ID, which is exactly
    /// why the client's refusal of one needs a peer willing to. Every other send method here
    /// builds a frame a conforming server WOULD send; this one builds whatever it is handed.
    /// </para>
    /// <para>1-RTT ONLY, because s12.4 Table 3 gives every frame this is used for the row
    /// "__01" or "___1", and because the short header is the only packet
    /// <see cref="BuildShortHeaderDatagram"/> builds. A frame this method sends still passes
    /// through TlsQuicFrameLegality on the way in, so a type Table 3 forbids at 1-RTT would be
    /// refused for that reason instead and the test would be measuring the wrong check.</para>
    /// </remarks>
    internal ValueTask SendOneRttFramesAsync(
        IReadOnlyList<TlsQuicFrame> frames, CancellationToken cancellationToken = default)
    {
        var written = BuildShortHeaderDatagram(frames);
        return _transport.SendAsync(
            _peerEndPoint, _sendBuffer.AsMemory(0, written), cancellationToken);
    }

    /// <summary>Performs an RFC 9001 s6.1 key update on this peer, so that its next 1-RTT
    /// packet is protected with generation n+1 and announces the flipped Key Phase bit.</summary>
    /// <remarks>THE PEER'S KEY SET DOES THE WORK, which is the point: this harness holds a
    /// real TlsQuicKeySet, so the derivation under test on the client's side is the same code
    /// that produces the packets it is tested against. A hand-rolled "quic ku" here would let
    /// one shared mistake cancel itself, which is the failure mode this whole file exists to
    /// avoid.</remarks>
    internal void UpdateKeys() => _keys.ApplyKeyUpdate(locallyInitiated: true);

    /// <summary>Gets the RFC 9001 s6 key phase this peer protects 1-RTT packets with.</summary>
    internal bool WriteKeyPhase => _keys.WriteKeyPhase;

    /// <summary>Sends one 1-RTT packet whose payload is the given already-encoded frame
    /// bytes.</summary>
    /// <remarks>FOR RFC 9221 s4's DATAGRAM FRAME AND NOTHING ELSE SO FAR. Every other frame
    /// this peer sends goes through TlsQuicFrames.WriteFrame; DATAGRAM cannot, because that
    /// writer throws on it deliberately. The bytes are written by the caller against s4's
    /// two-field format, which keeps the encoding in the test that asserts on it rather than
    /// in a helper no test reads back.</remarks>
    internal ValueTask SendOneRttRawFrameAsync(
        byte[] encodedFrame, CancellationToken cancellationToken = default)
    {
        var written = BuildShortHeaderDatagram([], rawFrames: encodedFrame);
        return _transport.SendAsync(
            _peerEndPoint, _sendBuffer.AsMemory(0, written), cancellationToken);
    }

    /// <summary>Sends one datagram carrying an ack-eliciting Handshake packet coalesced with
    /// the 1-RTT packet that carries HANDSHAKE_DONE.</summary>
    /// <remarks>
    /// <para>A CONFORMING SERVER DOES THIS, AND IT IS THE ONLY THING THAT MAKES THE CLIENT OWE
    /// AN ACK AT TWO LEVELS IN ONE ANSWER. RFC 9000 s12.2 permits the coalescing outright -
    /// "A sender can coalesce multiple QUIC packets ... into one UDP datagram" - and a server
    /// retransmitting its Handshake flight beside HANDSHAKE_DONE is the ordinary shape of it.
    /// Without a datagram like this, the position of the client's own short header inside its
    /// answer is unobservable, because its answer never holds two packets.</para>
    /// <para>PING RATHER THAN CRYPTO, because s19.2 makes PING the frame whose whole purpose
    /// is to be ack-eliciting and carry nothing, and because this peer has no Handshake CRYPTO
    /// left to send once the handshake is done. s12.4 Table 3 permits PING in every packet
    /// type.</para>
    /// </remarks>
    internal ValueTask SendHandshakePingCoalescedWithHandshakeDoneAsync(
        DateTimeOffset sentAt, CancellationToken cancellationToken = default)
    {
        var written = BuildHandshakePingAndHandshakeDone(sentAt);
        return _transport.SendAsync(
            _peerEndPoint, _sendBuffer.AsMemory(0, written), cancellationToken);
    }

    // NOT async, for the ref struct reason every builder in this file carries.
    private int BuildHandshakePingAndHandshakeDone(DateTimeOffset sentAt)
    {
        if (!_keys.TryGetWriteKeys(TlsQuicEncryptionLevel.Handshake, out var keys, out var state))
        {
            throw new InvalidOperationException(
                $"No write keys at Handshake for a coalesced PING; the level is {state}.");
        }

        var written = TlsQuicDatagramBuilder.BuildDatagram(
            _spec,
            [
                new TlsQuicPacketToSend
                {
                    Plan = PlanFor(TlsQuicEncryptionLevel.Handshake),
                    Frames = [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping }],
                    PacketProtectionCipher = keys.PacketCipher,
                    Key = keys.Key.ToArray(),
                    Iv = keys.Iv.ToArray(),
                    HeaderProtectionCipher = keys.HeaderCipher,
                    HeaderProtectionKey = keys.HeaderProtectionKey.ToArray(),
                },
            ],
            sentAt,
            _sendBuffer);

        return written + BuildShortHeaderDatagram(
            [new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.HandshakeDone }], written);
    }

    /// <summary>Acknowledges the 1-RTT packets this peer has opened, in a 1-RTT packet.
    /// </summary>
    /// <remarks>
    /// <para>THIS IS THE ANSWER SIDE OF RFC 9000 s13.2.1's MUST, seen from the peer. A4 task
    /// 14c's done-when is that a 1-RTT packet the connection sent is acknowledged by the
    /// loopback peer, and until this method existed nothing in the tree could acknowledge one
    /// - <see cref="SendHandshakeDoneAsync"/> was the only short header it wrote.</para>
    /// <para>WHAT IT WITNESSES, AND WHAT IT DOES NOT. It witnesses that the client's 1-RTT
    /// packet PARSED AND OPENED at a peer that did not build it, and that the packet number it
    /// carried survived the round trip into the client's own Application-space
    /// largest-acknowledged. It does NOT witness the BYTES: this file's short header, its
    /// nonce and its sample offset are read back by our own receiver, RFC 9001 Appendix A
    /// publishes no 1-RTT vector, and a defect shared by the two halves cancels exactly - the
    /// same blindness <see cref="SendHandshakeDoneAsync"/> records for itself.</para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">No 1-RTT packet has been opened, so there
    /// is nothing to acknowledge and RFC 9000 s19.3's mandatory Largest Acknowledged field has
    /// no value.</exception>
    /// <summary>Sends one 1-RTT packet carrying the given RFC 9000 s19.8 STREAM frames, in the
    /// order given.</summary>
    /// <remarks>
    /// <para>TASK 14e's SERVER HALF, and it takes ALREADY-BUILT FRAMES rather than a stream id
    /// and some bytes on purpose. The tests that use it script an out-of-order arrival, an
    /// overlapping retransmission, a zero-length frame and a FIN with no data - none of which
    /// a helper that owned an offset counter could express, and all of which are what a peer
    /// this endpoint does not control can do. A helper that maintained the offsets itself
    /// would also be a second send-side stream implementation, which is what this file exists
    /// to avoid being.</para>
    /// <para>WHAT IT WITNESSES AND WHAT IT DOES NOT: exactly what
    /// <see cref="SendHandshakeDoneAsync"/> records. The short header, the nonce and the
    /// sample offset are shared with the receiving half and RFC 9001 Appendix A publishes no
    /// 1-RTT vector, so a symmetric defect cancels. What does NOT cancel is the STREAM frame
    /// itself: TlsQuicStreamFrames encodes it here and decodes it there, and its own eight
    /// hand-derived wire forms in TlsQuicStreamFramesTests are the byte-level evidence.</para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">No Application write keys.</exception>
    internal ValueTask SendStreamFramesAsync(
        IReadOnlyList<TlsQuicFrame> frames, CancellationToken cancellationToken = default)
    {
        var written = BuildShortHeaderDatagram(frames);
        return _transport.SendAsync(
            _peerEndPoint, _sendBuffer.AsMemory(0, written), cancellationToken);
    }

    /// <summary>Acknowledges EVERY 1-RTT packet this peer has opened, as one contiguous
    /// RFC 9000 s19.3 range from zero to the largest.</summary>
    /// <remarks>
    /// <para>THE DIFFERENCE FROM <see cref="SendAckAsync"/> IS THE FIRST ACK RANGE, and it
    /// matters more than it looks. That method acknowledges ONE packet, which is what a test
    /// wants when it is asserting on an ACK's shape. Handed to a client with a dozen packets in
    /// flight, it says the other eleven were not received - so RFC 9002 s6.1's reordering
    /// threshold declares them lost and s13.3's repairs re-send ranges the peer already has.
    /// Measured: a drain that used it read stream offset 5670 where it had already reached
    /// 10206.</para>
    /// <para>ZERO IS A SAFE FLOOR HERE BECAUSE THE TRANSPORT IS LOSSLESS. InMemoryDatagramTransport
    /// delivers everything, so every number up to the largest really was received and a
    /// contiguous range is the truthful ACK rather than a convenient one. A test driving the
    /// impairing transport must not use this.</para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">No 1-RTT packet has been opened.</exception>
    internal ValueTask SendCumulativeAckAsync(CancellationToken cancellationToken = default)
    {
        if (LargestApplicationPacketNumberReceived is not { } largest)
        {
            throw new InvalidOperationException(
                "This peer has opened no 1-RTT packet, so it has no Largest Acknowledged to "
                    + "put in an ACK frame (RFC 9000 s19.3).");
        }

        var encoded = new List<byte>();
        TlsQuicAckFrames.WriteAckFrame(
            encoded,
            (ulong)TlsQuicFrameType.Ack,
            ackDelay: 0,
            [new TlsQuicAckRange(largest, 0)]);

        var offset = 0;
        if (!TlsQuicFrames.TryReadFrame(encoded.ToArray(), ref offset, out var ack, out var error))
        {
            throw new InvalidOperationException(
                $"An ACK frame this peer just encoded did not read back: {error}.");
        }

        var written = BuildShortHeaderDatagram([ack]);
        return _transport.SendAsync(
            _peerEndPoint, _sendBuffer.AsMemory(0, written), cancellationToken);
    }

    internal ValueTask SendAckAsync(
        DateTimeOffset sentAt, CancellationToken cancellationToken = default)
    {
        _ = sentAt;

        if (LargestApplicationPacketNumberReceived is not { } largest)
        {
            throw new InvalidOperationException(
                "This peer has opened no 1-RTT packet, so it has no Largest Acknowledged to "
                    + "put in an ACK frame (RFC 9000 s19.3).");
        }

        // ONE RANGE, THE ONE PACKET. s19.3's First ACK Range is "the number of contiguous
        // packets preceding the Largest Acknowledged that are being acknowledged", and a
        // single-packet range makes it zero. A2's writer encodes it; nothing here does.
        var encoded = new List<byte>();
        TlsQuicAckFrames.WriteAckFrame(
            encoded,
            (ulong)TlsQuicFrameType.Ack,
            ackDelay: 0,
            [new TlsQuicAckRange(largest, largest)]);

        var offset = 0;
        if (!TlsQuicFrames.TryReadFrame(encoded.ToArray(), ref offset, out var ack, out var error))
        {
            throw new InvalidOperationException(
                $"An ACK frame this peer just encoded did not read back: {error}.");
        }

        var written = BuildShortHeaderDatagram([ack]);
        return _transport.SendAsync(
            _peerEndPoint, _sendBuffer.AsMemory(0, written), cancellationToken);
    }

    // NOT async, for the same reason as BuildDatagram: TlsQuicWriteKeyMaterial is a ref
    // struct and must not live in an async state machine.
    //
    // STILL HAND-WRITTEN, THOUGH A4 TASK 14b GAVE TlsQuicPacketBuilder A SHORT-HEADER PATH.
    // Routing this through that builder would make this peer's send side and the connection's
    // send side the SAME code, and this file's whole reason for existing is that they are not:
    // a defect in the builder would then be written and read by one implementation and cancel
    // itself in every loopback test. The duplication IS the evidence.
    private int BuildShortHeaderDatagram(
        IReadOnlyList<TlsQuicFrame> frames, int at = 0, byte[]? rawFrames = null)
    {
        // RFC 9000 s12.2 puts a short-header packet last in its datagram, so this may follow
        // long-header bytes already in the buffer but nothing may follow it.
        var target = _sendBuffer.AsSpan(at);

        if (!_keys.TryGetWriteKeys(TlsQuicEncryptionLevel.Application, out var keys, out var state))
        {
            throw new InvalidOperationException(
                $"No write keys at Application for a 1-RTT packet; the level is {state}.");
        }

        var payload = new List<byte>();
        foreach (var frame in frames)
        {
            TlsQuicFrames.WriteFrame(payload, frame);
        }

        // THE ESCAPE HATCH FOR FRAMES THE LIBRARY REFUSES TO WRITE. TlsQuicFrames.WriteFrame
        // throws on a DATAGRAM frame by design - this client never sends one, and
        // TlsQuicFramesTests.WritingADatagramFrameThrowsBecauseThisLibraryNeverSendsOne pins
        // that - so a test peer that needs to send one has to hand-encode it. RFC 9221 s4's
        // format is two fields, which is why the bytes come in already formed rather than
        // through a second writer here: a writer would be the very thing the library refuses
        // to own, and it would drift from s4 with nothing reading it back.
        if (rawFrames is not null)
        {
            payload.AddRange(rawFrames);
        }

        // RFC 9001 s5.4.2: "sample_offset = pn_offset + 4", and the sample is 16 bytes of the
        // protected packet - so a packet needs pn_offset + 20 bytes to exist at all. s5.4.2
        // states the consequence itself: "this results in needing at least 3 bytes of frames
        // in the unprotected payload if the packet number is encoded on a single byte". The
        // 16-byte tag covers all but the packet number field, so the shortfall is exactly
        // 4 - pn_length bytes, made up with RFC 9000 s19.1 PADDING, which "has no semantic
        // value". An ACK-only packet is the shortest thing this method builds, which is what
        // makes the loop reachable at the default one-byte packet number.
        while (payload.Count < 4 - _spec.PacketNumberEncodedLength)
        {
            TlsQuicFrames.WriteFrame(
                payload, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Padding });
        }

        var packetNumber = _nextPacketNumber[(int)TlsQuicEncryptionLevel.Application]++;
        var truncated = new byte[_spec.PacketNumberEncodedLength];
        for (var i = 0; i < truncated.Length; i++)
        {
            truncated[i] = (byte)(packetNumber >> (8 * (truncated.Length - 1 - i)));
        }

        // RFC 9000 s17.3.1. Spin bit clear; the key phase is whatever generation this peer's
        // write keys are at. It read `KeyPhase = false` with the reason "key update is out of
        // scope for this phase" until RFC 9001 s6 was implemented - and a hardcoded false here
        // would make every key-update test silently test nothing, because the packet would
        // announce the old phase while being sealed under the new keys and the client would
        // discard it as a forgery rather than following the update.
        var headerLength = TlsQuicPacketHeader.WriteShortHeader(
            target,
            new TlsQuicShortHeader
            {
                SpinBit = false,
                KeyPhase = _keys.WriteKeyPhase,
                DestinationConnectionId = _destinationConnectionId,
                PacketNumberLength = truncated.Length,
                PacketNumber = truncated,
            },
            out _);

        // RFC 9001 s5.3: "When constructing packets, the AEAD function is applied prior to
        // applying header protection". The associated data is the header up to and including
        // the unprotected packet number, which is exactly the bytes just written, and the
        // nonce takes the FULL packet number rather than the truncated wire form.
        var size = headerLength + payload.Count + TlsQuicPacketBuilder.AuthenticationTagLength;
        TlsQuicPacketProtection.Seal(
            keys.PacketCipher,
            keys.Key.Span,
            keys.Iv.Span,
            packetNumber,
            target[..headerLength],
            CollectionsMarshal.AsSpan(payload),
            target.Slice(headerLength, payload.Count + TlsQuicPacketBuilder.AuthenticationTagLength));

        // pn_offset for a short header is byte 0 plus the Destination Connection ID; there is
        // no length prefix and no Length field (s17.3.1), which is also why the receiver has
        // to be told our connection ID length out of band.
        var packetNumberOffset = 1 + _destinationConnectionId.Length;
        if (!TlsQuicHeaderProtection.TryApply(
                keys.HeaderCipher, keys.HeaderProtectionKey.Span, target[..size], packetNumberOffset))
        {
            throw new InvalidOperationException(
                "The 1-RTT packet is too short for RFC 9001 s5.4.2's 16-byte sample.");
        }

        return size;
    }

    /// <summary>Installs every traffic secret one result carries, and nothing else.</summary>
    /// <remarks>
    /// INSTALL, SEND, THEN DISCARD, and the three are separate calls because they belong at
    /// different points.
    ///
    /// Install first, and per result rather than per flight, because a flight is routinely
    /// protected by keys the same result delivered: the server's ServerHello arrives with
    /// the Handshake secrets that protect the packet coalesced behind it.
    ///
    /// Discard last because RFC 9001 s4.9 discards a level once its keys are no longer
    /// needed, and "no longer needed" is after the send rather than before it. The client's
    /// completion result carries its Finished at the Handshake level; applying a discard
    /// from that same result first would leave nothing to protect it with.
    /// </remarks>
    private void InstallSecrets(TlsQuicProcessResult result)
    {
        foreach (var raised in result.Events)
        {
            if (raised is TlsQuicTrafficSecretEvent secret)
            {
                _keys.InstallFromTrafficSecret(secret.Secret);
            }
        }
    }

    private async ValueTask<bool> SendAndDiscardAsync(
        IReadOnlyList<TlsQuicProcessResult> results,
        DateTimeOffset sentAt,
        CancellationToken cancellationToken)
    {
        var crypto = new List<TlsQuicCryptoDataEvent>();
        foreach (var result in results)
        {
            foreach (var raised in result.Events)
            {
                if (raised is TlsQuicCryptoDataEvent data)
                {
                    crypto.Add(data);
                }
            }
        }

        var sentAnything = false;
        if (crypto.Count > 0)
        {
            var written = BuildDatagram(crypto, sentAt, out var carriedHandshakePacket);
            await _transport
                .SendAsync(_peerEndPoint, _sendBuffer.AsMemory(0, written), cancellationToken)
                .ConfigureAwait(false);
            sentAnything = true;

            // RFC 9001 s4.9.1: "a client MUST discard Initial keys when it first sends a
            // Handshake packet". Client-only - CustomTlsQuicServer has no such method, and
            // s4.9.1's server trigger is receiving a Handshake packet instead.
            if (carriedHandshakePacket && _notifyHandshakePacketSent is not null)
            {
                using var notified = _notifyHandshakePacketSent();

                // ApplyDiscards LOOKS AT DISCARD EVENTS ONLY, and that is correct exactly
                // as long as NotifyHandshakePacketSent raises nothing else - which today it
                // does not: it returns discards or an empty result. The day it also raises a
                // traffic secret or CRYPTO data, this call would drop it in silence and the
                // handshake would fail somewhere else entirely. So the assumption is checked
                // where it is made rather than written down and hoped for.
                //
                // DELIBERATELY UNWITNESSED - mutation row 21. It cannot fire against the
                // current CustomTlsQuicClient, so a test for it would have to fake the
                // notification and would then be witnessing its own fake. Unlike the
                // unreachable-by-construction guards elsewhere in this tree, this one guards
                // a contract in ANOTHER class that can change, which is why it exists at all.
                foreach (var raised in notified.Events)
                {
                    if (raised is not TlsQuicDiscardKeysEvent)
                    {
                        throw new InvalidOperationException(
                            $"NotifyHandshakePacketSent raised {raised.GetType().Name}. This "
                                + "harness only knows how to apply discards from it; see the "
                                + "note here and handle the new event before widening that.");
                    }
                }

                ApplyDiscards(notified);
            }
        }

        foreach (var result in results)
        {
            ApplyDiscards(result);
        }

        return sentAnything;
    }

    private void ApplyDiscards(TlsQuicProcessResult result)
    {
        foreach (var raised in result.Events)
        {
            if (raised is TlsQuicDiscardKeysEvent discard)
            {
                _keys.DiscardKeys(discard.Level);
            }
        }
    }

    // NOT async, and it cannot be: TlsQuicWriteKeyMaterial is a ref struct, so the key
    // material never lives in an async state machine.
    private int BuildDatagram(
        IReadOnlyList<TlsQuicCryptoDataEvent> crypto,
        DateTimeOffset sentAt,
        out bool carriedHandshakePacket)
    {
        carriedHandshakePacket = false;
        var packets = new List<TlsQuicPacketToSend>();

        // Ascending encryption level, which is ascending enum ordinal. RFC 9000 s12.2's
        // coalescing rule is about connection IDs rather than order, but a receiver
        // processes a datagram front to back, and a peer that met the Handshake packet
        // before the ServerHello that keyed it would have to buffer.
        for (var level = TlsQuicEncryptionLevel.Initial;
             level <= TlsQuicEncryptionLevel.Application;
             level++)
        {
            var frames = new List<TlsQuicFrame>();
            foreach (var data in crypto)
            {
                if (data.Level != level)
                {
                    continue;
                }

                // The offset is the TLS endpoint's, never recomputed here. A running total
                // kept by this harness would be a second piece of offset arithmetic, wrong
                // in the same way on both sides - exactly the cancelling defect this file's
                // header warns about.
                frames.Add(new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.Crypto,
                    Offset = data.Offset,
                    Data = data.Data,
                });
            }

            if (frames.Count == 0)
            {
                continue;
            }

            if (!_keys.TryGetWriteKeys(level, out var keys, out var state))
            {
                throw new InvalidOperationException(
                    $"No write keys at {level} for a flight that carries {level} CRYPTO data; "
                        + $"the level is {state}.");
            }

            packets.Add(new TlsQuicPacketToSend
            {
                Plan = PlanFor(level),
                Frames = frames,
                PacketProtectionCipher = keys.PacketCipher,
                Key = keys.Key.ToArray(),
                Iv = keys.Iv.ToArray(),
                HeaderProtectionCipher = keys.HeaderCipher,
                HeaderProtectionKey = keys.HeaderProtectionKey.ToArray(),
            });

            carriedHandshakePacket |= level == TlsQuicEncryptionLevel.Handshake;
        }

        return TlsQuicDatagramBuilder.BuildDatagram(_spec, packets, sentAt, _sendBuffer);
    }

    private TlsQuicPacketPlan PlanFor(TlsQuicEncryptionLevel level) => new()
    {
        Type = level switch
        {
            TlsQuicEncryptionLevel.Initial => TlsQuicLongPacketType.Initial,
            TlsQuicEncryptionLevel.Handshake => TlsQuicLongPacketType.Handshake,

            // Application means a short header, which TlsQuicPacketBuilder does not build,
            // and EarlyData means 0-RTT, which carries no CRYPTO frames at all (RFC 9001
            // s4.1.3). Both are reachable only by asking this harness for something it says
            // in its own header comment it does not do - a session ticket, say.
            _ => throw new NotSupportedException(
                $"LoopbackQuicPeer sends long header packets only, so it cannot carry {level} "
                    + "CRYPTO data. See this type's remarks."),
        },
        Version = (uint)_spec.Version,
        DestinationConnectionId = _destinationConnectionId,
        SourceConnectionId = _sourceConnectionId,
        Token = default,
        PacketNumber = _nextPacketNumber[(int)level]++,
        PacketNumberEncodedLength = _spec.PacketNumberEncodedLength,
        LargestAcknowledged = null,
        LengthVarintWidth = _spec.HeaderLengthVarintWidth,
        CryptoOffsetVarintWidth = _spec.CryptoOffsetVarintWidth,
        CryptoLengthVarintWidth = _spec.CryptoLengthVarintWidth,
    };

    /// <summary>Opens one coalesced packet and returns the CRYPTO frames it carried.</summary>
    private List<CryptoChunk> ReceiveOne(Memory<byte> packet)
    {
        var chunks = new List<CryptoChunk>();
        var duplicatesBefore = _receiver.DuplicatesSuppressed;
        var outcome = _receiver.Receive(
            packet,
            (in TlsQuicFrame frame, in TlsQuicReceivedPacket received) =>
            {
                // THE ONLY PLACE IN THE TREE THAT SEES A PEER'S PACKETS OPENED. The frame
                // ORDER inside a packet and the LEVEL order of the packets coalesced into one
                // datagram are both fingerprint dimensions, and both are invisible from the
                // sending side once the AEAD has closed over them - a test there would have to
                // re-derive the Handshake keys, which no test can. Recorded here so the two
                // TlsQuicConnectionSpec knobs that decide them can be witnessed at all.
                _lastDatagramFrames.Add((received.Level, frame.Type));

                // RFC 9000 s12.3's Application packet number space, recorded so this peer can
                // acknowledge what the client sent there. ONE NUMBER, NOT A RANGE SET: this
                // harness has no ack tracker and needs none - the tests that use it send one
                // 1-RTT packet at a time, and a range set built here would be a second
                // implementation of TlsQuicAckTracker sitting opposite the one under test.
                if (received.Level == TlsQuicEncryptionLevel.Application)
                {
                    LargestApplicationPacketNumberReceived =
                        LargestApplicationPacketNumberReceived is { } seen
                            ? Math.Max(seen, received.PacketNumber)
                            : received.PacketNumber;
                }

                if (frame.Type == TlsQuicFrameType.Stream)
                {
                    // TASK 14e. LastDatagramFrames carries only the frame TYPE, and this
                    // task's whole claim is about the four s19.8 FIELDS - which stream, at
                    // which offset, how many bytes, and whether the FIN bit is set. A test
                    // that could see only "a STREAM frame arrived" would pass against a send
                    // path that put the right bytes at the wrong offset, which is precisely
                    // the defect an offset exists to have.
                    //
                    // .ToArray() FOR THE REASON THE TWO COPIES BELOW ARE MADE: frame.Data
                    // aliases TlsQuicPacketReceiver's decrypt scratch, and these are read by
                    // an assertion long after the next Receive has refilled it.
                    //
                    // THE FIN IS READ OFF frame.RawType AND NOT OFF A FIELD, because
                    // TlsQuicFrame has none - TlsQuicStreamFrames.IsFin is the one reader of
                    // s19.8's bit, so there is no copy of it here to disagree with the wire.
                    ReceivedStreamFrames.Add((
                        frame.StreamId,
                        frame.Offset,
                        frame.Data.ToArray(),
                        TlsQuicStreamFrames.IsFin(frame.RawType)));
                }

                if (frame.Type == TlsQuicFrameType.PathResponse)
                {
                    // .ToArray() FOR THE SAME REASON THE CRYPTO COPY BELOW IS MADE: this
                    // aliases the receiver's decrypt scratch, and it is read by an assertion
                    // long after the next Receive has refilled it. Recorded because
                    // LastDatagramFrames carries only the frame TYPE, and RFC 9000 s19.18's
                    // requirement is about the eight bytes rather than the frame's presence.
                    LastPathResponseData = frame.Data.ToArray();
                }

                if (frame.Type == TlsQuicFrameType.ConnectionClose)
                {
                    // RECORDED WITH received.Level, which is the half of RFC 9000 s10.2.3 that
                    // no assertion on the client could reach: "After the handshake is confirmed
                    // ... an endpoint MUST send any CONNECTION_CLOSE frames in a 1-RTT packet"
                    // is a claim about the PACKET the frame travelled in, and the packet is
                    // opaque until this receiver has opened it.
                    //
                    // .ToArray() FOR THE REASON THE COPIES ABOVE ARE MADE: frame.ReasonPhrase
                    // aliases TlsQuicPacketReceiver's decrypt scratch.
                    LastConnectionClose = (
                        frame.RawType,
                        frame.ErrorCode,
                        frame.ReasonPhrase.ToArray(),
                        received.Level);
                }

                if (frame.Type == TlsQuicFrameType.Crypto)
                {
                    // .ToArray() COPIES OUT OF THE RECEIVER'S SCRATCH. frame.Data is a
                    // window onto TlsQuicPacketReceiver's decrypt buffer, which that class
                    // reuses across every later Receive call - its own
                    // TlsQuicPacketReceiverTests.ARetainedFrameAliasesTheDecryptBufferAndIs
                    // NotSafeToKeep demonstrates exactly this across two calls.
                    //
                    // DELETING THE COPY SURVIVES THE WHOLE GATE, 0 of 1026, and that is not
                    // because it is unnecessary. It survives because of a TIMING accident
                    // one caller up: PumpOnceAsync consumes each packet's chunks - awaits
                    // ProcessCryptoDataAsync on them - before it calls ReceiveOne again, so
                    // no alias is ever alive across a refill. A later task that BUFFERS
                    // chunks across the packets of one datagram (to hand the TLS engine one
                    // batch, say) breaks that silently: no compiler error, no exception,
                    // just the next packet's plaintext read as the previous packet's.
                    //
                    // UNWITNESSABLE FROM OUTSIDE THIS FILE, and recorded as such rather than
                    // given a test that would not be one. The hazard is a read of stale
                    // bytes, and it only becomes observable once the buffering it warns
                    // about exists - a test written today would have to introduce that
                    // buffering itself, and would then be testing its own scaffold rather
                    // than this line. The honest precedent is task 9a-i's zeroing path.
                    // Mutation row 18.
                    chunks.Add(new CryptoChunk(received.Level, frame.Offset, frame.Data.ToArray()));
                }
            });

        // ONE EXCEPTION, AND IT IS THE ONE THING A LOOPBACK CAN LEGITIMATELY DROP. RFC 9000
        // s12.3's duplicate suppression discards an authenticated packet whose number this
        // space has already processed, and a test transport that duplicates a datagram on
        // purpose - ImpairingDatagramTransport.Duplicate - produces exactly that. It is not a
        // key problem and not a forgery, so the guard below would misreport it as both.
        //
        // MEASURED ON THE RECEIVER'S OWN COUNTER rather than inferred from the shape.
        // Processed=0, Discarded=1 is also what a stray packet from nowhere looks like, and
        // this file exists to tell those apart rather than to let one stand for the other.
        if (_receiver.DuplicatesSuppressed != duplicatesBefore)
        {
            return chunks;
        }

        // ANYTHING OTHER THAN ONE CLEANLY PROCESSED PACKET IS A BUG HERE. In a loopback
        // there is no unopenable packet from the only peer that exists, so a discard is
        // never the ordinary drop a real endpoint makes: RFC 9000 s12.2 has the receiver
        // discard what it cannot open "because the keys are not available or for any other
        // reason", and neither reason can arise between two halves of one process that
        // built each other's keys.
        //
        // WHY THIS IS NOT `Processed == 0` ALONE, WHICH IS WHAT IT WAS. The failure this
        // guard exists for is the COALESCING STALL - the whole datagram handed to one
        // Receive call, the Handshake packet inside it meeting no Handshake keys yet - and
        // that stall's shape is PROCESSED=1, DISCARDED=1, on which `Processed == 0` never
        // fires. Measured, not predicted: reverting the split loop in PumpOnceAsync
        // (mutation row 5) kills 8 of 11 tests and NOT ONE of the failures came from here.
        // The shape is pinned outside this file by TlsQuicPacketReceiverTests.ACoalesced
        // PacketWhoseKeysHaveNotArrivedIsCountedApartFromOneThatSimplyDoesNotOpen.
        //
        // AT THIS CALL SITE the three disjuncts are equivalent, because the split loop
        // hands over exactly one packet per call, so Processed >= 1 forces Discarded == 0.
        // They are kept apart anyway because the guard's SHAPE is what task 9a-ii ports to
        // a connection loop, and there the datagram may hold several packets and only
        // `Discarded > 0` still fires. Mutation rows 19 and 20 record that: dropping either
        // added disjunct survives, UNREACHABLE AT THIS CALL SITE rather than vacuous.
        if (outcome.Processed == 0
            || outcome.Discarded > 0
            || outcome.Unprocessed != TlsQuicUnprocessedPacket.None)
        {
            throw new InvalidOperationException(
                $"A {packet.Length}-byte packet did not yield exactly one processed packet: "
                    + $"{outcome.Processed} processed, {outcome.Discarded} discarded "
                    + $"({outcome.DiscardedForMissingKeys} for want of keys), "
                    + $"unprocessed {outcome.Unprocessed}.");
        }

        return chunks;
    }

    /// <summary>The server's half of RFC 9001 s5.2: both connection IDs and the Initial
    /// secrets come off the first long header it sees.</summary>
    /// <remarks>
    /// DELIBERATELY FROM THE WIRE rather than handed to the constructor, even though this
    /// harness builds both peers and knows the answer. A Destination Connection ID passed
    /// out of band would key the server correctly no matter what the client actually
    /// encoded, so an ID written into the header wrongly would still decrypt. Taking it off
    /// the packet makes the header field load-bearing: RFC 9001 s5.2 derives the Initial
    /// secret from it, and s5.3's AEAD covers the header as associated data, so a wrong
    /// encoding fails to open here rather than passing.
    /// </remarks>
    private void AdoptConnectionIdsAndKeyTheInitialLevel(ReadOnlyMemory<byte> datagram)
    {
        if (!TlsQuicPacketHeader.TryReadLongHeader(datagram, out var header, out _))
        {
            throw new InvalidOperationException(
                "The first datagram a server peer sees must open with a long header.");
        }

        _sourceConnectionId = header.DestinationConnectionId.ToArray();
        _destinationConnectionId = header.SourceConnectionId.ToArray();
        _keys.InstallInitialKeys(_sourceConnectionId, isClient: _isClient);
        _initialKeysInstalled = true;
    }

    private readonly record struct CryptoChunk(
        TlsQuicEncryptionLevel Level, ulong Offset, ReadOnlyMemory<byte> Data);

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _keys.Dispose();
        _receiver.Dispose();
        await _transport.DisposeAsync().ConfigureAwait(false);
    }
}
