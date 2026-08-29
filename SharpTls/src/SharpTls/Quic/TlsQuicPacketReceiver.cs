using System.Security.Cryptography;

namespace SharpTls.Quic;

// What a datagram pass found that it deliberately did not process. RFC 9000 s12.2:
// "Retry packets (Section 17.2.5), Version Negotiation packets (Section 17.2.1), and
// packets with a short header (Section 17.3) do not contain a Length field and so
// cannot be followed by other packets in the same UDP datagram. Note also that there
// is no situation where a Retry or Version Negotiation packet is coalesced with
// another packet." So at most one of these can occur per datagram, and it is always
// the whole datagram.
//
// The bytes themselves are NOT carried here, deliberately: they alias the receive
// buffer, whose lifetime ends with the pass (see TlsQuicPacketReceiver.Receive). Task
// 9b owns Retry and Version Negotiation handling and must copy what it needs inside
// the pass - a handler, not a field on this result.
internal enum TlsQuicUnprocessedPacket
{
    None,
    VersionNegotiation,
    Retry,
}

// One authenticated packet, as context for each frame dispatched out of it. Task 8
// (ACK generation) needs exactly this pair per received packet: RFC 9000 s12.3 -
// "Initial packets can only be sent with Initial packet protection keys and
// acknowledged in packets that are also Initial packets" - so an acknowledgement is
// keyed by (space, packet number) and nothing else this receiver knows.
internal readonly struct TlsQuicReceivedPacket
{
    internal TlsQuicEncryptionLevel Level { get; init; }
    internal ulong PacketNumber { get; init; }
}

// LIFETIME: `frame` and every ReadOnlyMemory field inside it alias the receive
// buffer and the decrypt scratch buffer, both of which the receiver owns for the
// duration of one Receive call and reuses across the packets coalesced into that
// datagram. A handler that needs anything past its own return MUST copy it - see
// TlsQuicPacketReceiver.Receive's LIFETIME comment for why this is the whole
// contract and not a caution.
internal delegate void TlsQuicFrameHandler(in TlsQuicFrame frame, in TlsQuicReceivedPacket packet);

// The outcome of one datagram pass. Counts, plus at most one connection error.
internal readonly struct TlsQuicReceiveResult
{
    // Packets that authenticated and whose frames were all dispatched.
    internal int Processed { get; init; }

    // Packets dropped without processing. RFC 9000 s12.2: "For example, if decryption
    // fails (because the keys are not available or for any other reason), the receiver
    // MAY either discard or buffer the packet for later processing and MUST attempt to
    // process the remaining packets." Discarding is the option taken; a failed decrypt
    // is NOT an error and never sets CloseError.
    internal int Discarded { get; init; }

    // The subset of Discarded that had NO READ KEYS at the packet's level - s12.2's
    // "because the keys are not available", told apart from its "or for any other
    // reason". Always <= Discarded.
    //
    // This exists so the COALESCING STALL described in Receive's remarks can be
    // DETECTED rather than inferred. A caller that splits a datagram because its keys
    // arrive mid-flight needs to know the difference between "a packet I could open
    // later" and "a packet nobody can open": the first is the whole datagram handed
    // over too early and is fixed by splitting, the second is a forged or stray packet
    // and is fixed by nothing. Discarded alone cannot tell them apart, and the shape
    // that matters - Processed=1, Discarded=1 - is indistinguishable from a healthy
    // datagram with one stray packet appended.
    //
    // WHAT A NON-ZERO VALUE MEANS SINCE RFC 9001 s5.7 RETENTION LANDED, and it is no
    // longer "the connection is stalled". A packet counted here is counted for THIS
    // PASS, in which it really was not processed; most of them are now also RETAINED and
    // replayed a moment later out of <see cref="TlsQuicPacketReceiver.ReplayOneRetainedPacket"/>,
    // where they land in a later pass's Processed. So:
    //   - non-zero here with PacketsRetainedForKeys rising in step is ORDINARY
    //     REORDERING that the retention buffer absorbed - the number a proxied path
    //     produces and recovers from;
    //   - non-zero here with PacketsRetainedForKeys NOT rising is a packet that could
    //     not be retained at all: the level's keys were already discarded under s4.9, or
    //     the retention ceiling was full. That is the shape that still ends in a stall.
    // The pair is what the deadline message reports; neither number alone says which.
    internal int DiscardedForMissingKeys { get; init; }

    internal TlsQuicUnprocessedPacket Unprocessed { get; init; }

    // Non-null means the connection must be closed with this RFC 9000 s20.1 code. Only
    // a check that ran on an AEAD-authenticated packet can set it; see Receive.
    internal TlsQuicTransportError? CloseError { get; init; }

    // Why, for the CONNECTION_CLOSE Reason Phrase and for test diagnostics. Never
    // carries attacker bytes.
    internal string? CloseReason { get; init; }
}

// RFC 9000 s12.2 / s17.2 / s17.3.1 and RFC 9001 s5.3 / s5.4: one UDP datagram in,
// dispatched frames out. Datagram -> TlsQuicDatagramReader.Read -> per packet: remove
// header protection, decode the truncated packet number against the largest received
// IN THAT NUMBER SPACE, open the AEAD, then TlsQuicFrames.TryReadFrame in a loop until
// the payload is consumed.
//
// Long AND short headers. A 1-RTT packet uses a short header (s17.3.1) and is where
// HANDSHAKE_DONE arrives, which RFC 9001 s4.1.2 makes the client's only trigger for
// handshake *confirmed*: "At the client, the handshake is considered confirmed when a
// HANDSHAKE_DONE frame is received." That is a different state from handshake
// complete, and only confirmation releases Handshake keys.
//
// NOTHING HERE THROWS FOR ANY INPUT. Every byte reaching this class is
// attacker-controlled and this is the loop that reads it, so every rejection is a
// discard or a reported close, never an exception. The one thing that can propagate
// is a throw from the caller's own handler, which is caller code, not input. The
// constructor is the one exception and it is not input - see its own note.
//
// RETENTION - RFC 9001 s5.7, AND WHAT IT DOES NOT FIX.
//
// A packet that meets no read keys at its level is retained and replayed once
// InstallReadKeys supplies them. s5.7's own reason is the diagnosis: "Due to reordering
// and loss, protected packets might be received by an endpoint before the final TLS
// handshake messages are received", and its permission is "Received packets protected
// with 1-RTT keys MAY be stored and later decrypted and used once the handshake is
// complete." The section grants the server-side mirror in the same words - "The server
// MAY retain these packets for later decryption in anticipation of receiving a
// ClientHello" - so the retain branch is written per level rather than per role.
//
// THIS IS THE CROSS-DATAGRAM CASE AND NOTHING ELSE. The IN-datagram case - a Handshake
// packet coalesced behind the Initial packet that carries its keys - is the caller's, is
// already solved by splitting, and is what the COALESCING note in Receive's remarks is
// about. Retention is for the case splitting CANNOT reach: the Handshake packet arrives
// in an EARLIER datagram than the Initial one, so at the moment it is walked there is no
// later packet in its datagram and no amount of splitting produces one. A relay that
// re-emits each datagram on its own path makes that reordering ordinary rather than rare,
// which is why the symptom shows up proxied and not direct.
//
// THE ENTRY POINTS ARE Retain (private, from ProcessPacket's keys-are-null branch) and
// ReplayOneRetainedPacket (internal, drained by the caller). Read the latter's remarks
// for the termination argument and for why the exactly-once accounting of s6.6's
// integrity limit, s12.3's duplicate window and s17.1's largest-received is a consequence
// of WHERE the retain branch sits rather than of bookkeeping.
//
// WITNESSED AT BOTH LEVELS. At this class's own seam by
// TlsQuicPacketReceiverTests.AHandshakePacketThatArrivedBeforeItsKeysIsReplayedOnceThose
// KeysArrive, and end to end - a real flight from a real peer, split so the Handshake
// packet arrives in the earlier datagram - by
// TlsQuicConnectionTests.AHandshakePacketDeliveredBeforeItsInitialStillCompletesTheHandshake.
// The bug itself is kept reproducible rather than described, by
// TlsQuicConnectionTests.TheSameReorderingEndsOnTheHandshakeDeadlineWhenRetentionIsTurnedOff,
// which is the same exchange with the ceiling set to zero.
//
// NOT THREAD-SAFE, and that is a requirement on the caller rather than a note on the
// implementation. _keys, _largestReceived and _scratch are unsynchronised mutable
// state, so ONE THREAD OF CONTROL owns a receiver: never two Receive calls at once,
// and never InstallReadKeys or DiscardReadKeys racing one. CustomTlsQuicClient carries
// the identical requirement one layer up - StartHandshake, NotifyHandshakePacketSent
// and ConfirmHandshake mutate its state without taking the semaphore that guards
// ProcessCryptoDataAsync - so task 9a-ii's connection loop must satisfy both, with one
// loop and no parallel send/receive pumps. Receive's "one synchronous pass" is a
// BUFFER rule about aliasing; this is the separate concurrency one.
//
// MUTATION RECORD (performed in a worktree and reverted). The SURVIVORS are the part
// of this record that is itemised, because they are the part a reader must act on:
//
//   1. the ciphertext tag-length floor in ProcessPacket. UNREACHABLE BY CONSTRUCTION,
//      with its arithmetic written at the guard itself, and deliberately unwitnessed.
//   2. the long-header re-parse in Receive's default branch. Same classification, same
//      reasoning, also written at the guard - confirmed still a survivor when this
//      record was corrected.
//
// A test for either would pass against the mutant that deletes it and become a false
// witness, so neither has one and neither should get one.
//
// Everything else mutated was killed. The first sweep counted 44 mutations as eight
// asserted BUCKET SIZES (reserved bits, key phase, packet number arithmetic, number
// spaces, AEAD framing, frame handling, version/kind dispatch, the coalescing walk),
// not as a list, and the individual mutations were not written down - so 44 is
// APPROXIMATE and is recorded as such rather than restated as a fact nobody can
// recompute. It also silently counted survivor 2 as killed. Later sweeps append here.
//
// Four mutations survived the first sweep and three of them were real test gaps, all
// of the same shape - a check that could be moved or widened without any test noticing:
//   - the reserved-bits check moved to BEFORE the AEAD, which is what this file's own
//     comment says it must not be. Now killed by
//     TlsQuicPacketReceiverTests.ReservedBitsFlippedInTransitAreDiscardedRatherThanClosingTheConnection
//   - the key phase check widened to long headers, where 0x04 is a reserved bit. Now
//     killed by TlsQuicPacketReceiverTests.AKeyPhaseInstalledAtALongHeaderLevelIsNeverConsulted
//   - the Application number space collapsed onto the Handshake one. Now killed by
//     TlsQuicPacketReceiverTests.TheHandshakeAndApplicationSpacesAreSeparateFromEachOther
//
// The equivalent ordering mutation for the KEY PHASE was killed from the start, by
// TlsQuicPacketReceiverTests.AKeyPhaseBitFlippedInTransitIsDiscardedRatherThanClosingTheConnection
// - which is why the reserved-bits gap was visible at all: two checks with the same
// ordering requirement, one witnessed and one not.
//
// The review sweep is itemised, because a list is the only form of this record worth
// writing. Seven mutations, six killed and one survivor - and the survivor is not new,
// it is survivor 2 above, which the first sweep had counted as killed:
//   1. delete CryptographicOperations.ZeroMemory(_scratch) in Dispose
//      -> DisposeZeroesTheDecryptedPlaintextLeftInTheScratch
//   2. delete the same call on the growth path in Receive
//      -> GrowingTheScratchZeroesThePlaintextItAbandons
//   3. IsTheDatagramsConnectionId always returns true
//      -> ASubsequentPacketWithADifferentConnectionIdIsIgnored(sameConnectionId: false)
//   4. the same compares connection ID LENGTHS instead of contents
//      -> the same test, which is why its two IDs are both four bytes
//   5. delete the constructor's connection-ID length bound
//      -> AConnectionIdLengthOutsideTheVersion1RangeIsRejectedAtConstruction, both rows
//   6. TlsQuicTransportError.KeyUpdateError 0x0E -> 0x0F
//      -> TlsQuicPrimitiveTests.EveryTransportErrorCarriesItsSection201CodePoint and
//         TheTransportErrorCodePointsAreExactlyTheSixPinnedAbove. It had survived the
//         whole Quic gate AND PublicApiBaselineTests, because the API baseline records
//         the SYMBOL and never the number.
//   7. delete the long-header re-parse guard entirely - SURVIVED, 925/925 green, which
//      is what confirms survivor 2's classification rather than assuming it.
// 6 + 1 = 7.
//
// TASK 7's FIX ROUND appended three more, all killed, against the 1026-test Quic gate:
//   8. delete discardedForMissingKeys++ in ProcessPacket's keys-is-null branch
//      -> ACoalescedPacketWhoseKeysHaveNotArrivedIsCountedApartFromOneThatSimplyDoesNotOpen
//   9. also increment it on the TryOpen failure, which would make it an alias of Discarded
//      -> the same test, and LoopbackQuicPeerTests.AnInitialPacketProtectedWithTheServer
//         SecretDoesNotOpenAtTheServer, which asserts the zero from the other side
//  10. IsTheDatagramsConnectionId always returns true, RE-RUN because Receive's remarks now
//      state that a splitting caller forfeits s12.2's connection ID clause. Killed by
//      exactly ONE test - ASubsequentPacketWithADifferentConnectionIdIsIgnored - and by
//      ZERO of LoopbackQuicPeerTests, which is the measurement behind that sentence: the
//      harness splits, so the clause is already not running for it.
// 9 + 1 = 10.
//
// RFC 9001 s5.7's RETENTION appended five more, all killed, against the 3165-test suite
// (3126 passing before these tests existed, 3134 after; the three known failures -
// UntrustedRootIsRejected, PlatformSslStreamClientAuthenticatesSharpTlsServerAndExchanges
// Traffic(Tls13) and AFullRequestAndResponseCompleteAgainstSystemNetQuic - are unrelated and
// present in every row below):
//  11. Retain never retains (its ceiling test rewritten to `packet.Length > 0 - _retainedBytes`,
//      which is always true) - the whole feature deleted, with the API left in place so the
//      verdict measures the suite and not the compiler
//      -> 6 tests: AHandshakePacketThatArrivedBeforeItsKeysIsReplayedOnceThoseKeysArrive,
//         TheRetentionCeilingRefusesThePacketThatWouldCrossItAndKeepsWhatIsAlreadyHeld,
//         DiscardingALevelsKeysDropsThePacketsRetainedAtThatLevel,
//         AReplayedPacketEntersTheDuplicateWindowExactlyOnce,
//         ARetainedPacketsNumberIsDecodedAgainstTheLargestReceivedAtReplayTime (all
//         TlsQuicPacketReceiverTests) and
//         TlsQuicConnectionTests.AHandshakePacketDeliveredBeforeItsInitialStillCompletesTheHandshake.
//         The two retention-OFF rows stayed green, which is the check that they are asserting
//         the absence of retention rather than passing for its own reasons.
//  12. DiscardReadKeys keeps the level's retained packets (its `Level != level` test forced true)
//      -> ONLY TlsQuicPacketReceiverTests.DiscardingALevelsKeysDropsThePacketsRetainedAtThatLevel
//  13. the ceiling is ignored (`packet.Length > int.MaxValue`)
//      -> 3 tests: TheRetentionCeilingRefusesThePacketThatWouldCrossItAndKeepsWhatIsAlreadyHeld,
//         RetentionIsOffWhenTheCeilingIsZero, and
//         TlsQuicConnectionTests.TheSameReorderingEndsOnTheHandshakeDeadlineWhenRetentionIsTurnedOff
//  14. the post-s4.9 refill bar deleted (`false && _keysDiscarded[...]`)
//      -> ONLY TlsQuicPacketReceiverTests.DiscardingALevelsKeysDropsThePacketsRetainedAtThatLevel,
//         which is why that test re-offers an Initial packet AFTER the discard instead of
//         stopping at the drop
//  15. TlsQuicConnection's drain loop never runs a second round (`HasReplayablePacket || true`)
//      -> ONLY TlsQuicConnectionTests.AHandshakePacketDeliveredBeforeItsInitialStillCompletes
//         TheHandshake. The receiver rows all stayed green, which is the measurement behind
//         "the trigger is the caller's": retention and replay are correct at this class's seam
//         and still do nothing at all unless the pump drains them.
// 14 + 1 = 15.
internal sealed class TlsQuicPacketReceiver : IDisposable
{
    // RFC 9000 s17.2, Reserved Bits: "Two bits (those with a mask of 0x0c) of byte 0
    // are reserved across multiple packet types."
    private const byte LongHeaderReservedBits = 0x0c;

    // RFC 9000 s17.3.1, Reserved Bits: "The next two bits (those with a mask of 0x18)
    // of byte 0 are reserved."
    private const byte ShortHeaderReservedBits = 0x18;

    // RFC 9000 s17.3.1, Key Phase: "The next bit (0x04) of byte 0 indicates the key
    // phase, which allows a recipient of a packet to identify the packet protection
    // keys that are used to protect the packet."
    private const byte KeyPhaseBit = 0x04;

    // RFC 9001 s5.3: "These cipher suites have a 16-byte authentication tag and
    // produce an output 16 bytes larger than their input."
    private const int AuthenticationTagLength = 16;

    // RFC 9000 s12.3's three spaces: Initial, Handshake, and the one Application data
    // space that "0-RTT (Section 17.2.3) and 1-RTT (Section 17.3.1) packets" share.
    private const int PacketNumberSpaceCount = 3;

    private uint _version;

    /// <summary>The QUIC version this receiver accepts long headers for.</summary>
    /// <remarks>SETTABLE FOR RFC 9368 s2.3 AND FOR NOTHING ELSE. The connection moves it once,
    /// when the server answers the first flight in a compatible version the client offered; see
    /// <c>TlsQuicConnection.TryAdoptNegotiatedVersion</c>. Every other packet with an unexpected
    /// version is still discarded, which is what the long-header walk below does with it.</remarks>
    internal uint Version
    {
        get => _version;
        set => _version = value;
    }
    private readonly int _destinationConnectionIdLength;
    private readonly ReadKeys?[] _keys = new ReadKeys?[4];
    private readonly ulong[] _largestReceived = new ulong[PacketNumberSpaceCount];

    // RFC 9000 s12.3's duplicate suppression, one sliding window per packet number space.
    //
    // THREE ARRAYS AND NOT ONE, because packet number 0 is legal and a zeroed
    // <see cref="_duplicateWindowHighest"/> cannot be told from "0 has been processed".
    // s12.3's test is "certain that it has not processed another packet with the same packet
    // number", and certainty about the empty case is what the flag carries.
    //
    // <see cref="_duplicateWindow"/>'s bit i means "highest - i has been processed", so bit 0
    // is always set once anything has been. UInt128 rather than ulong doubles the window for
    // one word of state and no extra branch.
    private readonly ulong[] _duplicateWindowHighest = new ulong[PacketNumberSpaceCount];

    // RFC 9001 s6's key update, all of it 1-RTT only - s6.1's Note: "Keys of packets other
    // than the 1-RTT packets are never updated; their keys are derived solely from the TLS
    // handshake state." So these are single fields rather than per-level arrays, and
    // _keys[Application] is the CURRENT set they sit either side of.
    //
    // s6.3 IS WHY _next IS HELD RATHER THAN DERIVED ON DEMAND: "Endpoints responding to an
    // apparent key update MUST NOT generate a timing side-channel signal that might indicate
    // that the Key Phase bit was invalid", and s6.3 names deriving-on-receipt as exactly that
    // signal - "An endpoint MAY generate new keys as part of packet processing, but this
    // creates a timing signal". Holding both is also s6.3's own MUST: "endpoints MUST be able
    // to retain two sets of packet protection keys for receiving packets: the current and the
    // next."
    //
    // _previous IS s6.5's SHOULD, not a MUST, and it is kept because dropping it costs
    // retransmits: "Retaining old packet protection keys allows these [delayed] packets to be
    // successfully processed."
    private ReadKeys? _nextApplicationKeys;
    private ReadKeys? _previousApplicationKeys;

    // s6.5's discriminator: "A recovered packet number that is lower than any packet number
    // from the current key phase uses the previous packet protection keys." Null until a
    // packet has been opened in the current phase, which is a state s6.5 does not name and
    // this endpoint reaches every time it initiates an update itself - see
    // _awaitingPeerKeyPhaseCatchUp.
    private ulong? _currentPhaseLowestPacketNumber;

    // Set when THIS endpoint initiated the update, cleared by the first packet that arrives at
    // the new phase. While it is set, a packet at the OTHER phase is the peer still using the
    // old keys rather than the peer initiating an update of its own - the two are identical on
    // the wire and only this flag tells them apart.
    private bool _awaitingPeerKeyPhaseCatchUp;
    private readonly UInt128[] _duplicateWindow = new UInt128[PacketNumberSpaceCount];
    private readonly bool[] _duplicateWindowStarted = new bool[PacketNumberSpaceCount];
    private byte[] _scratch = [];
    private bool _disposed;

    // RFC 9001 s5.7's retention, and the whole of its state. See the RETENTION block in
    // this class's remarks for the design; what lives here is:
    //
    // ONE LIST IN ARRIVAL ORDER, NOT ONE PER LEVEL. Replay walks it front to back and
    // takes the first entry whose level now has keys, so a level's own packets come back
    // in the order they arrived AND a Handshake packet retained before a 1-RTT one is
    // replayed before it. Per-level lists would keep the first property and lose the
    // second, and s12.2's advice - coalescing "in order of increasing encryption levels
    // ... makes it more likely that the receiver will be able to process all the packets
    // in a single pass" - is about exactly that ordering.
    //
    // THE BYTES ARE THE PROTECTED ONES, COPIED BEFORE ANY UNMASKING. The retain branch
    // in ProcessPacket runs before TlsQuicHeaderProtection.TryRemove, so the copy is the
    // packet as it came off the wire and the replay re-runs the whole of ProcessPacket
    // over it - header protection removal, packet number decoding, the AEAD, the s12.3
    // duplicate window - exactly once, at replay time. That is what keeps every counter
    // in this class exactly-once rather than nearly-once; see ReplayOneRetainedPacket.
    private readonly int _retainedPacketBufferBytes;
    private readonly List<RetainedPacket> _retained = [];
    private int _retainedBytes;

    // RFC 9001 s4.9's other half, per level. Set by DiscardReadKeys and cleared by
    // InstallReadKeys, so that a level whose keys are gone stops ACCEPTING retentions as
    // well as losing the ones it had. Without it the buffer refills forever after
    // s4.9.1's "a client MUST discard Initial keys when it first sends a Handshake
    // packet": every stray or replayed Initial packet the network still carries would be
    // retained against keys that can never come back, and would crowd out the Handshake
    // and 1-RTT packets retention exists for.
    private readonly bool[] _keysDiscarded = new bool[4];

    /// <summary>
    /// Whether a packet whose QUIC Bit is 0 is accepted rather than discarded.
    /// </summary>
    /// <remarks>
    /// <para>SET FROM WHAT THIS ENDPOINT ADVERTISED, NOT FROM A KNOB. RFC 9287 s3: "An endpoint
    /// that advertises the grease_quic_bit transport parameter MUST accept packets with the
    /// QUIC Bit set to 0." The obligation follows the advertisement, so
    /// <c>CustomTlsQuicClient.AdvertisedGreaseQuicBit</c> is the only thing that may set this -
    /// a separate knob could disagree with the wire and would be the advertise/enforce
    /// divergence this tree refuses everywhere else.</para>
    /// <para>A PROPERTY RATHER THAN A CONSTRUCTOR ARGUMENT because the ClientHello does not
    /// exist when this receiver is built: the connection draws its source connection ID first
    /// and composes the profile around it.</para>
    /// <para>Default false is RFC 9000 s17.2's rule for an endpoint that granted no such
    /// permission: "Packets containing a zero value for this bit are not valid packets in this
    /// version and MUST be discarded."</para>
    /// </remarks>
    internal bool AcceptGreasedQuicBit { get; set; }

    /// <param name="version">
    /// The connection's QUIC version, compared against every long header's Version
    /// field. Not a constant: RFC 9369 defines a second version this project targets.
    /// </param>
    /// <param name="destinationConnectionIdLength">
    /// The length of OUR connection ID, which is what a peer puts in a short header's
    /// Destination Connection ID field. RFC 9000 s17.3.1 gives that field no length
    /// prefix, so the receiver must already know it - and subsystem B varies it per
    /// imitated client, so it is a parameter here and never a layout constant.
    /// </param>
    internal TlsQuicPacketReceiver(uint version, int destinationConnectionIdLength)
        : this(
            version,
            destinationConnectionIdLength,
            TlsQuicConnectionSpec.DefaultRetainedPacketBufferBytes)
    {
    }

    /// <param name="version">The connection's QUIC version; see the two-argument
    /// overload.</param>
    /// <param name="destinationConnectionIdLength">The length of OUR connection ID; see
    /// the two-argument overload.</param>
    /// <param name="retainedPacketBufferBytes">
    /// The RFC 9001 s5.7 retention ceiling, in bytes of protected packet held at once
    /// across every level. <c>0</c> disables retention entirely, which is exactly this
    /// receiver's behaviour before s5.7 landed: a packet that meets no keys is discarded
    /// and nothing is ever replayed. The knob and its default are
    /// <see cref="TlsQuicConnectionSpec.RetainedPacketBufferBytes"/>; read that property's
    /// remarks for why the bound is bytes rather than a packet count.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="retainedPacketBufferBytes"/> is negative. Same reasoning as the
    /// connection ID bound below: this is a caller's configuration value and never a byte
    /// off the wire, so a wrong one is surfaced loudly.
    /// </exception>
    internal TlsQuicPacketReceiver(
        uint version, int destinationConnectionIdLength, int retainedPacketBufferBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(
            retainedPacketBufferBytes, nameof(retainedPacketBufferBytes));
        _retainedPacketBufferBytes = retainedPacketBufferBytes;

        // This THROWS where TlsQuicPacketHeader.TryReadShortHeader returns false at the
        // identical bound, and both are right for their seam. That one judges ATTACKER
        // bytes mid-walk, where the only sound rejection is a discard. This one judges a
        // CALLER's argument: the length is subsystem B's per-client profile value, never
        // a byte off the wire, so a wrong one is a configuration bug to surface loudly
        // and not a packet to drop. Receive still throws for no input; a constructor
        // argument is not input.
        // Witnessed by
        // TlsQuicPacketReceiverTests.AConnectionIdLengthOutsideTheVersion1RangeIsRejectedAtConstruction.
        if (destinationConnectionIdLength is < 0 or > TlsQuicPacketHeader.MaximumConnectionIdLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(destinationConnectionIdLength),
                destinationConnectionIdLength,
                $"RFC 9000 s17.2: a version 1 connection ID is at most {TlsQuicPacketHeader.MaximumConnectionIdLength} bytes.");
        }

        _version = version;
        _destinationConnectionIdLength = destinationConnectionIdLength;
    }

    /// <summary>
    /// RFC 9000 s17.1: "the largest packet number received in a successfully
    /// authenticated packet", per number space - the third argument the s17.2 /
    /// Appendix A.3 decoder needs, and what task 8 acknowledges against.
    /// </summary>
    internal ulong LargestReceived(TlsQuicEncryptionLevel level) => _largestReceived[SpaceOf(level)];

    /// <summary>Gets how many authenticated packets this receiver has discarded under RFC 9000
    /// s12.3 because their packet number had already been processed in that space.</summary>
    /// <remarks>A RUNNING TOTAL ACROSS THE CONNECTION, not a per-datagram figure, and it counts
    /// into <see cref="TlsQuicReceiveResult.Discarded"/> as well. Non-zero is not by itself a
    /// fault: s12.3 exists because networks duplicate datagrams. It rising steadily while
    /// nothing else does is the shape worth reading.</remarks>
    internal int DuplicatesSuppressed { get; private set; }

    /// <summary>Whether read keys are installed at <paramref name="level"/>.</summary>
    internal bool HasReadKeys(TlsQuicEncryptionLevel level) => _keys[(int)level] is not null;

    /// <summary>Gets the RFC 9001 s6 key phase the Application read keys are at, or
    /// <see langword="false"/> before they are installed.</summary>
    internal bool ApplicationKeyPhase =>
        _keys[(int)TlsQuicEncryptionLevel.Application]?.KeyPhase ?? false;

    /// <summary>Gets whether a peer-initiated key update has been detected and not yet
    /// answered by updating the send keys.</summary>
    /// <remarks>s6.2: "Sending keys MUST be updated before sending an acknowledgment for the
    /// packet that was received with updated keys." This flag is what carries that obligation
    /// out of the receive path; <see cref="ConsumeKeyUpdate"/> clears it.</remarks>
    internal bool KeyUpdatePending { get; private set; }

    /// <summary>Gets how many peer-initiated key updates this receiver has completed.</summary>
    internal int KeyUpdatesReceived { get; private set; }

    /// <summary>Gets how many received packets have failed authentication, across all keys and
    /// all levels, for the lifetime of this receiver.</summary>
    /// <remarks>s6.6: "In addition to counting packets sent, endpoints MUST count the number of
    /// received packets that fail authentication during the lifetime of a connection." ACROSS
    /// ALL KEYS is the section's own phrase and is why this is one counter and not one per
    /// level or per key phase. The limit itself is enforced by TlsQuicConnection, which is
    /// where a connection can be closed from.</remarks>
    internal long AuthenticationFailures { get; private set; }

    /// <summary>Takes the pending key-update signal, clearing it.</summary>
    internal bool ConsumeKeyUpdate()
    {
        if (!KeyUpdatePending)
        {
            return false;
        }

        KeyUpdatePending = false;
        return true;
    }

    /// <summary>
    /// Installs read keys for one encryption level, replacing any already there. The
    /// key material is copied, because RFC 9001's own key objects are caller-owned and
    /// TlsQuicProcessResult.Dispose zeroes unconsumed secrets - install before
    /// disposing the result that produced them.
    /// </summary>
    /// <remarks>
    /// <c>keyPhase</c> is the key phase these keys belong to. Read only for short headers: RFC 9000 s17.2
    /// defines no Key Phase field on the long header, so the value carried at the other
    /// levels is never consulted rather than being accepted and ignored.
    /// <para>INSTALLING AT THE APPLICATION LEVEL RESETS RFC 9001 s6's STATE, because this is
    /// generation zero of the 1-RTT keys and any next or previous set beside it belongs to a
    /// connection that no longer exists. <see cref="InstallNextApplicationReadKeys"/> is how
    /// generation n+1 is armed; <see cref="PromoteApplicationKeysForLocalUpdate"/> is how this
    /// endpoint's own update is applied.</para>
    /// </remarks>
    internal void InstallReadKeys(
        TlsQuicEncryptionLevel level,
        TlsQuicPacketProtectionCipher packetCipher,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        TlsQuicHeaderProtectionCipher headerCipher,
        ReadOnlySpan<byte> headerProtectionKey,
        bool keyPhase)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _keys[(int)level]?.Dispose();
        _keys[(int)level] = new ReadKeys
        {
            PacketCipher = packetCipher,
            HeaderCipher = headerCipher,
            Key = key.ToArray(),
            Iv = iv.ToArray(),
            HeaderProtectionKey = headerProtectionKey.ToArray(),
            KeyPhase = keyPhase,
        };

        // RFC 9001 s4.9's flag, lifted: this level has keys again, so it may retain again.
        // In practice only the Application level ever reaches this line twice - Initial
        // and Handshake keys are installed once and then discarded for good - but the
        // pairing is written both ways so that neither half has to know which.
        _keysDiscarded[(int)level] = false;

        if (level == TlsQuicEncryptionLevel.Application)
        {
            ResetKeyUpdateState();
        }
    }

    /// <summary>Gets how many packets have been retained under RFC 9001 s5.7 because their
    /// level's read keys had not arrived.</summary>
    /// <remarks>A RUNNING TOTAL ACROSS THE CONNECTION, and it is the companion number to
    /// <see cref="TlsQuicReceiveResult.DiscardedForMissingKeys"/> - see that member's own
    /// remarks for how the pair tells ordinary reordering apart from a real stall. A retained
    /// packet is still counted as discarded for the pass that could not open it; retention is
    /// a second chance, not a reclassification.</remarks>
    internal int PacketsRetainedForKeys { get; private set; }

    /// <summary>Gets how many retained packets have been replayed through the frame handler
    /// once their level's read keys arrived.</summary>
    /// <remarks>Always &lt;= <see cref="PacketsRetainedForKeys"/>. The difference is packets
    /// still waiting plus packets dropped by <see cref="DiscardReadKeys"/> under RFC 9001
    /// s4.9. Replayed is not the same as opened: a replayed packet still has to pass the AEAD,
    /// and one that does not lands in <see cref="AuthenticationFailures"/> exactly as it would
    /// have on the live path.</remarks>
    internal int PacketsReplayed { get; private set; }

    /// <summary>Gets how many packets are retained right now, waiting for keys.</summary>
    internal int RetainedPacketCount => _retained.Count;

    /// <summary>Gets whether at least one retained packet's level now has read keys, so that
    /// <see cref="ReplayOneRetainedPacket"/> would do something.</summary>
    /// <remarks>A LINEAR SCAN, deliberately. The list is bounded by the retention ceiling in
    /// bytes and this is consulted once per replay round, so the worst case is the ceiling
    /// divided by the smallest packet that can reach the retain branch - a few hundred entries
    /// against a 16 KiB default - and an index keyed by level would be four more fields to keep
    /// in step with two mutation sites.</remarks>
    internal bool HasReplayablePacket => IndexOfReplayable() >= 0;

    /// <summary>
    /// Replays ONE retained packet whose level now has read keys - RFC 9001 s5.7's "Received
    /// packets protected with 1-RTT keys MAY be stored and later decrypted and used once the
    /// handshake is complete", applied at whichever level was missing keys.
    /// </summary>
    /// <remarks>
    /// <para>ONE PER CALL, AND THAT IS THE CALLER'S ACK CORRECTNESS RATHER THAN A STYLE
    /// CHOICE. RFC 9000 s13.1: "A packet MUST NOT be acknowledged until packet protection has
    /// been successfully removed and all frames contained in the packet have been processed."
    /// <c>TlsQuicConnection.PumpOnceAsync</c> accumulates one packet's frames, awaits the TLS
    /// engine on them and only then tells the ACK tracker which packet it just finished; a call
    /// that replayed several packets into that one set of accumulators would acknowledge the
    /// last and silently lose the rest.</para>
    /// <para>NOT CALLED FROM <see cref="InstallReadKeys"/>, WHICH IS WHERE THE TRIGGER IS.
    /// Installing keys happens deep inside the caller's own frame walk - the Handshake keys
    /// come out of a CRYPTO frame that is still being processed - so replaying from there would
    /// re-enter a handler whose accumulators are mid-iteration. The keys therefore only ARM the
    /// replay and the caller drains it at a point where no handler is live.</para>
    /// <para>TERMINATION. The entry is removed from the buffer BEFORE it is processed, and
    /// ProcessPacket only ever retains a packet whose level has no keys - which this one's has,
    /// or it would not have been selected. So a replayed packet cannot re-enter the buffer, and
    /// each call strictly decreases <see cref="RetainedPacketCount"/> by one. A replayed
    /// packet's frames may install further keys and make OTHER retained entries replayable, but
    /// those entries were already in the buffer and are already counted; nothing but a live
    /// <see cref="Receive"/> of a new datagram can add one. A drain loop therefore runs at most
    /// <see cref="RetainedPacketCount"/> times, which the retention ceiling bounds.</para>
    /// <para>EXACTLY-ONCE ACCOUNTING FALLS OUT OF WHERE THE RETAIN BRANCH SITS rather than out
    /// of bookkeeping here. That branch is the first thing in ProcessPacket, before header
    /// protection is removed, before RFC 9000 A.3's packet number decode, before the AEAD and
    /// before s12.3's duplicate window - so a retained packet has touched none of them and the
    /// replay is its FIRST pass through all four. <see cref="AuthenticationFailures"/> (RFC
    /// 9001 s6.6's integrity limit) and <see cref="DuplicatesSuppressed"/> are therefore
    /// incremented at most once, and <c>_largestReceived</c> is both READ and WRITTEN at replay
    /// time - so A.3's largest_pn is the value in force when the packet is actually opened,
    /// which is the only value s17.1 lets it be: "the largest packet number received in a
    /// successfully authenticated packet". Decoding at arrival and re-checking here would have
    /// been the bug the RFC names, because the number was not yet authenticated then.
    /// Witnessed by
    /// TlsQuicPacketReceiverTests.AReplayedPacketEntersTheDuplicateWindowExactlyOnce for s12.3
    /// and s6.6, and by
    /// TlsQuicPacketReceiverTests.ARetainedPacketsNumberIsDecodedAgainstTheLargestReceivedAt
    /// ReplayTime for s17.1 - which builds a truncated number that resolves to 44 against a
    /// largest of 0 and to 300 against the largest actually in force, and lets the AEAD say
    /// which one the receiver used.</para>
    /// <para>Returns a result whose <c>Processed</c>/<c>Discarded</c> describe the one packet.
    /// When nothing is replayable it returns the empty result and does no work, so a caller may
    /// use it without consulting <see cref="HasReplayablePacket"/> first.</para>
    /// </remarks>
    internal TlsQuicReceiveResult ReplayOneRetainedPacket(TlsQuicFrameHandler handler)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(handler);

        var index = IndexOfReplayable();
        if (index < 0)
        {
            return default;
        }

        var retained = _retained[index];
        _retained.RemoveAt(index);
        _retainedBytes -= retained.Packet.Length;
        PacketsReplayed++;

        // The same sizing rule Receive uses, and the same reason it zeroes first: the
        // outgoing array still holds the previous pass's decrypted payload.
        if (_scratch.Length < retained.Packet.Length)
        {
            CryptographicOperations.ZeroMemory(_scratch);
            _scratch = new byte[retained.Packet.Length];
        }

        var processed = 0;
        var discarded = 0;
        var discardedForMissingKeys = 0;

        // s12.2's connection ID clause is NOT re-applied here, and that is not an omission.
        // "Receivers SHOULD ignore any subsequent packets with a different Destination
        // Connection ID than the first packet in the datagram" is a rule about one datagram,
        // and this packet's datagram was walked and judged when it arrived - by Receive if the
        // caller handed it whole datagrams, and by the caller itself if it splits, which
        // TlsQuicConnection.PumpOnceAsync does. Re-running it against whatever datagram happens
        // to be in flight now would compare a packet against a "first packet" it never shared a
        // datagram with.
        var outcome = ProcessPacket(
            retained.Packet,
            retained.PacketNumberOffset,
            retained.Level,
            retained.IsShortHeader,
            handler,
            ref processed,
            ref discarded,
            ref discardedForMissingKeys);

        return outcome is not null
            ? Close(outcome.Value, processed, discarded, discardedForMissingKeys)
            : new TlsQuicReceiveResult
            {
                Processed = processed,
                Discarded = discarded,
                DiscardedForMissingKeys = discardedForMissingKeys,
            };
    }

    /// <summary>Arms RFC 9001 s6.3's "next" set of Application read keys - generation n+1,
    /// carrying the opposite key phase to the installed keys.</summary>
    /// <remarks>
    /// <para>s6.3: "endpoints MUST be able to retain two sets of packet protection keys for
    /// receiving packets: the current and the next." Armed AHEAD of any packet that needs it,
    /// which is the same section's timing rule: "An endpoint MAY generate new keys as part of
    /// packet processing, but this creates a timing signal that could be used by an attacker
    /// to learn when key updates happen and thus leak the value of the Key Phase bit."</para>
    /// <para>THE HEADER PROTECTION KEY AND CIPHERS ARE COPIED FROM THE CURRENT SET RATHER THAN
    /// PASSED IN, because s6.1 says outright: "The header protection key is not updated." A
    /// caller handing one in could hand in the freshly derived one - which
    /// TlsQuicTrafficSecret.DerivePacketProtectionKeys does produce - and the peer would then
    /// be unable to remove header protection at all. Taking it from the current set makes that
    /// mistake unexpressible.</para>
    /// </remarks>
    internal void InstallNextApplicationReadKeys(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var current = _keys[(int)TlsQuicEncryptionLevel.Application]
            ?? throw new InvalidOperationException(
                "RFC 9001 s6.3's next Application read keys cannot be armed before the "
                    + "current ones are installed: the phase they carry is defined as the "
                    + "opposite of the current phase.");

        _nextApplicationKeys?.Dispose();
        _nextApplicationKeys = new ReadKeys
        {
            PacketCipher = current.PacketCipher,
            HeaderCipher = current.HeaderCipher,
            Key = key.ToArray(),
            Iv = iv.ToArray(),
            HeaderProtectionKey = (byte[])current.HeaderProtectionKey.Clone(),
            KeyPhase = !current.KeyPhase,
        };
    }

    /// <summary>Applies an update this endpoint initiated: the armed next keys become current,
    /// the current become previous, and the peer is expected to catch up.</summary>
    /// <remarks>
    /// <para>s6.1: "The endpoint that initiates a key update also updates the keys that it uses
    /// for receiving packets.  These keys will be needed to process packets the peer sends
    /// after updating."</para>
    /// <para>AND UNTIL THE PEER DOES, ITS PACKETS CARRY THE OLD PHASE. That is
    /// indistinguishable on the wire from the peer initiating an update of its own, so
    /// <c>_awaitingPeerKeyPhaseCatchUp</c> records which of the two this is. Without it, the
    /// first packet after a locally initiated update would be read as a peer update, opened
    /// against generation n+2 keys that do not exist, and discarded - the connection would
    /// stall at exactly the moment the AEAD limit forced the update.</para>
    /// </remarks>
    internal void PromoteApplicationKeysForLocalUpdate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_nextApplicationKeys is null)
        {
            throw new InvalidOperationException(
                "RFC 9001 s6.1's key update cannot be applied without the next read keys "
                    + "armed: this endpoint would be unable to read the packets the peer "
                    + "sends in response.");
        }

        Promote();
        _awaitingPeerKeyPhaseCatchUp = true;
    }

    /// <summary>
    /// Discards read keys at one level and zeroes them. After this, packets at that
    /// level are discarded exactly like packets whose keys never arrived - RFC 9000
    /// s12.2's "the keys are not available" case.
    /// </summary>
    /// <remarks>
    /// AND THE LEVEL'S RETAINED PACKETS GO WITH THE KEYS. RFC 9001 s4.9.1 states the
    /// consequence for the level this matters most at: "This results in abandoning loss
    /// recovery state for the Initial encryption level and ignoring any outstanding Initial
    /// packets." A packet retained under s5.7 is an outstanding packet at that level and there
    /// will never again be a key to open it, so retaining it past this point is memory held
    /// against an event that cannot happen. The level is also barred from retaining anything
    /// further; see <c>_keysDiscarded</c>.
    /// </remarks>
    internal void DiscardReadKeys(TlsQuicEncryptionLevel level)
    {
        _keys[(int)level]?.Dispose();
        _keys[(int)level] = null;
        _keysDiscarded[(int)level] = true;

        for (var i = _retained.Count - 1; i >= 0; i--)
        {
            if (_retained[i].Level != level)
            {
                continue;
            }

            _retainedBytes -= _retained[i].Packet.Length;
            _retained.RemoveAt(i);
        }
    }

    /// <summary>
    /// Processes one received UDP datagram, dispatching every frame of every packet it
    /// could authenticate.
    /// </summary>
    /// <remarks>
    /// LIFETIME - three contracts, all of them load-bearing:
    ///
    /// 1. TlsQuicDatagramReader.Read is a LAZY ITERATOR. `yield return` defers the
    ///    whole method body, so storing the returned IEnumerable across an await means
    ///    the WALK ITSELF runs later, against whatever the buffer then holds - yielding
    ///    packet boundaries that were never true of any single datagram, silently,
    ///    because never-throwing is that method's contract. The foreach below is
    ///    therefore synchronous and complete, inside this pass, and this method is not
    ///    async.
    ///
    /// 2. Parsed frames ALIAS the receive buffer (and the decrypt scratch). One
    ///    datagram's buffer is owned by ONE synchronous pass; anything that must
    ///    outlive the pass is COPIED, not aliased. In practice the only thing that
    ///    outlives it is CRYPTO payload, because the TLS engine's ProcessCryptoDataAsync
    ///    is async - so the handler copies those bytes (TlsQuicCryptoStreamReassembler.
    ///    Add takes a ReadOnlySpan and copies into its own buffer, which is exactly
    ///    that copy) and consumes everything else before returning.
    ///
    /// 3. The caller allocates a FRESH receive buffer per datagram and DOES NOT POOL.
    ///    Pooling is an A3-era optimisation and it is precisely the change that would
    ///    silently break (2): a pooled buffer handed back and refilled turns every
    ///    retained alias into a read of the next datagram, with no compiler error and
    ///    no exception. The decrypt scratch below is the one buffer this class reuses,
    ///    and it is an INSTANCE FIELD - it lives as long as the receiver and is
    ///    refilled by every later Receive call, not only by later packets in this one.
    ///    So the scratch IS that pool, one layer down, for exactly the CRYPTO payload
    ///    (2) is about, which is why (2) is a rule rather than a caution. Whoever
    ///    writes task 9a-ii's or task 14's frame handler: a ReadOnlyMemory you keep
    ///    past your return reads the NEXT datagram's plaintext, not yours.
    ///    TlsQuicPacketReceiverTests.ARetainedFrameAliasesTheDecryptBufferAndIsNotSafeToKeep
    ///    demonstrates precisely that, across two Receive calls.
    ///
    /// DEFERRED DECISION, recorded here because this loop is where it comes due:
    /// ITlsQuicDatagramTransport.ReceiveAsync allocates one IPEndPoint per datagram.
    /// .NET 9's Socket.ReceiveFromAsync(Memory&lt;byte&gt;, SocketFlags, SocketAddress,
    /// CancellationToken) reuses a caller-owned SocketAddress and allocates nothing.
    /// The transport scoping assigns that call to subsystem A (this one), not to the
    /// socket layer, and says it should be decided when there is a packet loop to
    /// measure. This is that loop, and A4-minimal DEFERS it with the interface
    /// unchanged: a handshake is about ten datagrams, so the allocation is invisible at
    /// that volume, and reshaping the receive result would land on
    /// TlsQuicUdpDatagramTransport, TlsQuicSocks5Transport and both test doubles before
    /// there is anything to measure. Revisit when A3 has a steady-state packet rate.
    ///
    /// COALESCING - A PERMANENT CALLER RESPONSIBILITY, NOT A WORKAROUND:
    ///
    /// This method DOES walk coalesced packets itself. RFC 9000 s12.2: "Receivers MUST
    /// be able to process coalesced packets", and the foreach below is that walk - the
    /// same TlsQuicDatagramReader.Read iterator and the same running-offset re-slice a
    /// caller would write. What it CANNOT do is install read keys part-way through that
    /// walk, because key installation goes through the TLS engine and that is async,
    /// while contract (1) above forces this method to be synchronous. That is by
    /// construction and will not change: an await inside this loop would break the
    /// iterator contract AND put a suspension point across the unsynchronised _keys and
    /// _scratch state this pass owns.
    ///
    /// So: A CALLER WHOSE KEYS ARRIVE BETWEEN COALESCED PACKETS MUST SPLIT THE DATAGRAM
    /// ITSELF - enumerate TlsQuicDatagramReader.Read, re-slice the writable datagram at
    /// the running offset, and call Receive ONCE PER PACKET, installing whatever the
    /// previous packet's CRYPTO data produced before the next call. s12.2 says
    /// coalescing "in order of increasing encryption levels (Initial, 0-RTT, Handshake,
    /// 1-RTT ...) makes it more likely that the receiver will be able to process all
    /// the packets in a single pass"; MORE LIKELY, not certain, and for an
    /// Initial+Handshake flight a single pass is never enough, because the Handshake
    /// keys are derived from the Initial packet's own CRYPTO payload. Without the split
    /// the Handshake packet meets no Handshake keys, is discarded, and the handshake
    /// stalls with every packet accounted for and nothing wrong on the wire - see
    /// DiscardedForMissingKeys, which is how that is detected rather than guessed.
    /// LoopbackQuicPeer.PumpOnceAsync is the worked example.
    ///
    /// SPLITTING SILENTLY FORFEITS s12.2's CONNECTION ID CHECK. The clause is
    /// "Receivers SHOULD ignore any subsequent packets with a different Destination
    /// Connection ID than the first packet in the datagram." That check is enforced
    /// below by firstDestinationConnectionId, which is a LOCAL - it is re-nulled on
    /// every call. A caller that makes one call per packet therefore has one "first
    /// packet" per packet, and the clause stops applying: there is no subsequent packet
    /// for it to judge. It is a SHOULD, and the AEAD gates the same forgery in
    /// practice, so this is a deliberate and acceptable trade - but a splitting caller
    /// that wants the clause back must compare the Destination Connection IDs across
    /// its own calls, because nothing here will.
    ///
    /// <c>datagram</c> is the received bytes, mutable because RFC 9001 s5.4 header
    /// protection is removed IN PLACE - byte 0 and the Packet Number field are unmasked
    /// where they lie.
    /// </remarks>
    internal TlsQuicReceiveResult Receive(Memory<byte> datagram, TlsQuicFrameHandler handler)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(handler);

        var processed = 0;
        var discarded = 0;
        var discardedForMissingKeys = 0;

        // Sized once per pass, from the datagram: no packet's plaintext can exceed the
        // datagram that carried it, and the packets coalesced into one datagram are
        // processed strictly one after another, so one buffer serves them all.
        //
        // Zeroed BEFORE it is abandoned. The outgoing array still holds the PREVIOUS
        // datagram's decrypted payload - CRYPTO frames carry the TLS handshake - and
        // replacing the reference would drop that plaintext on the GC heap intact.
        // Growth is peer-triggerable and needs no keys at all: a small datagram
        // followed by a larger one is enough, and the resize happens before anything is
        // parsed or authenticated. Same material and same reason as Dispose below;
        // witnessed by
        // TlsQuicPacketReceiverTests.GrowingTheScratchZeroesThePlaintextItAbandons.
        if (_scratch.Length < datagram.Length)
        {
            CryptographicOperations.ZeroMemory(_scratch);
            _scratch = new byte[datagram.Length];
        }

        // RFC 9000 s12.2: "Receivers SHOULD ignore any subsequent packets with a
        // different Destination Connection ID than the first packet in the datagram."
        // Null until the first packet that has one; every later packet is compared
        // against it. Task 5 closed the sender half of the same clause - "Senders MUST
        // NOT coalesce QUIC packets with different connection IDs into a single UDP
        // datagram" - so a mismatch here is not something a conforming peer produces.
        ReadOnlyMemory<byte>? firstDestinationConnectionId = null;

        var offset = 0;
        foreach (var coalesced in TlsQuicDatagramReader.Read(datagram, AcceptGreasedQuicBit))
        {
            // The reader yields contiguous slices starting at the running offset - a
            // long header packet is remaining.Slice(0, consumed), and a short header or
            // Version Negotiation packet is all of `remaining`. Tracking the offset is
            // how a ReadOnlyMemory slice is turned back into the writable view header
            // protection removal needs, without a ToArray copy.
            var packet = datagram.Slice(offset, coalesced.Packet.Length);
            offset += packet.Length;

            switch (coalesced.Kind)
            {
                case TlsQuicCoalescedPacketKind.VersionNegotiation:
                    // RFC 9000 s17.2.1 via s12.2: it "consumes an entire UDP datagram"
                    // and is never coalesced, so there is nothing after it to process.
                    return new TlsQuicReceiveResult
                    {
                        Processed = processed,
                        Discarded = discarded,
                        DiscardedForMissingKeys = discardedForMissingKeys,
                        Unprocessed = TlsQuicUnprocessedPacket.VersionNegotiation,
                    };

                case TlsQuicCoalescedPacketKind.Short:
                {
                    if (!TlsQuicPacketHeader.TryReadShortHeader(
                            packet,
                            _destinationConnectionIdLength,
                            out var shortHeader,
                            out _,
                            AcceptGreasedQuicBit))
                    {
                        discarded++;
                        break;
                    }

                    if (!IsTheDatagramsConnectionId(
                            ref firstDestinationConnectionId, shortHeader.DestinationConnectionId))
                    {
                        discarded++;
                        break;
                    }

                    var outcome = ProcessPacket(
                        packet.Span,
                        shortHeader.PacketNumberOffset,
                        TlsQuicEncryptionLevel.Application,
                        isShortHeader: true,
                        handler,
                        ref processed,
                        ref discarded,
                        ref discardedForMissingKeys);
                    if (outcome is not null)
                    {
                        return Close(outcome.Value, processed, discarded, discardedForMissingKeys);
                    }

                    // s12.2: "A packet with a short header does not include a length, so
                    // it can only be the last packet included in a UDP datagram."
                    break;
                }

                default:
                {
                    if (!TlsQuicPacketHeader.TryReadLongHeader(
                            packet, out var longHeader, out _, AcceptGreasedQuicBit))
                    {
                        // Unreachable from here by construction: the reader already ran
                        // this same parse to find the boundary and stopped the walk when
                        // it failed, so a Long kind means it succeeded. Kept because the
                        // out-value is needed and a Try-shaped API's false branch must
                        // not be ignored; deliberately unwitnessed. This is SURVIVOR 2
                        // in the mutation record at the top of the file - deleting the
                        // branch changes no test, which is what unreachable means.
                        discarded++;
                        break;
                    }

                    if (longHeader.Version != _version)
                    {
                        // RFC 9000 s17.2: "The header form bit, Destination and Source
                        // Connection ID lengths, Destination and Source Connection ID
                        // fields, and Version fields of a long header packet are version
                        // independent. The other fields in the first byte are version
                        // specific." The Length field is NOT on that list, so an unknown
                        // version leaves no trustworthy boundary for whatever follows -
                        // this is why the walk stops rather than continuing the way it
                        // does after a decryption failure, where the Length field is
                        // intact and s12.2's "MUST attempt to process the remaining
                        // packets" applies.
                        discarded++;
                        return new TlsQuicReceiveResult
                        {
                            Processed = processed,
                            Discarded = discarded,
                            DiscardedForMissingKeys = discardedForMissingKeys,
                        };
                    }

                    if (longHeader.Type == TlsQuicLongPacketType.Retry)
                    {
                        // s12.2: never coalesced, and s17.2.5 gives it no packet number
                        // and no AEAD payload - the Retry Integrity Tag is task 9b's.
                        return new TlsQuicReceiveResult
                        {
                            Processed = processed,
                            Discarded = discarded,
                            DiscardedForMissingKeys = discardedForMissingKeys,
                            Unprocessed = TlsQuicUnprocessedPacket.Retry,
                        };
                    }

                    // After the version and Retry checks, not before: those two decide
                    // whether the walk can continue at all, and s12.2's clause is about
                    // which of the packets a continuing walk yields get processed.
                    if (!IsTheDatagramsConnectionId(
                            ref firstDestinationConnectionId, longHeader.DestinationConnectionId))
                    {
                        discarded++;
                        break;
                    }

                    var outcome = ProcessPacket(
                        packet.Span,
                        longHeader.PacketNumberOffset,
                        LevelOf(longHeader.Type),
                        isShortHeader: false,
                        handler,
                        ref processed,
                        ref discarded,
                        ref discardedForMissingKeys);
                    if (outcome is not null)
                    {
                        return Close(outcome.Value, processed, discarded, discardedForMissingKeys);
                    }

                    break;
                }
            }
        }

        return new TlsQuicReceiveResult
        {
            Processed = processed,
            Discarded = discarded,
            DiscardedForMissingKeys = discardedForMissingKeys,
        };
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        for (var i = 0; i < _keys.Length; i++)
        {
            _keys[i]?.Dispose();
            _keys[i] = null;
        }

        // RFC 9001 s6's other two generations. Key material either side of the current set is
        // the same class of secret and is zeroed on the same terms.
        _nextApplicationKeys?.Dispose();
        _nextApplicationKeys = null;
        _previousApplicationKeys?.Dispose();
        _previousApplicationKeys = null;

        // The scratch holds decrypted payload - CRYPTO frames carry the TLS handshake,
        // so this is the same class of material TlsQuicPacketProtectionKeys.Dispose and
        // TlsQuicSecrets.Dispose zero. Witnessed by
        // TlsQuicPacketReceiverTests.DisposeZeroesTheDecryptedPlaintextLeftInTheScratch;
        // deleting this line was a surviving mutation until that test existed.
        CryptographicOperations.ZeroMemory(_scratch);
        _scratch = [];

        // The RFC 9001 s5.7 buffer holds PROTECTED packets, so there is no plaintext here to
        // zero - only memory to let go of. Every level's keys have just been disposed above,
        // so nothing in it could be replayed even if a caller reached this object again.
        _retained.Clear();
        _retainedBytes = 0;
    }

    // Returns null when the packet was processed or discarded, and a close reason when
    // an AEAD-AUTHENTICATED packet violated a MUST. Every check that can close runs
    // after TryOpen has succeeded: RFC 9000 s17.2 and s17.3.1 both say a reserved-bits
    // violation is judged "after removing both packet and header protection", and add
    // the reason - "Discarding such a packet after only removing header protection can
    // expose the endpoint to attacks". A check on a still-unauthenticated header bit is
    // an off-path attacker's remote kill switch; a check on an authenticated one is not.
    private (TlsQuicTransportError Error, string Reason)? ProcessPacket(
        Span<byte> packet,
        int packetNumberOffset,
        TlsQuicEncryptionLevel level,
        bool isShortHeader,
        TlsQuicFrameHandler handler,
        ref int processed,
        ref int discarded,
        ref int discardedForMissingKeys)
    {
        var keys = _keys[(int)level];
        if (keys is null)
        {
            // s12.2: "if decryption fails (because the keys are not available or for any
            // other reason), the receiver MAY either discard or buffer the packet".
            // THIS branch is the "keys are not available" half and it is the only one
            // that counts into discardedForMissingKeys - the TryRemove and TryOpen
            // failures below are the "or for any other reason" half, which no amount of
            // waiting fixes. See TlsQuicReceiveResult.DiscardedForMissingKeys.
            discarded++;
            discardedForMissingKeys++;

            // AND s12.2's OTHER OPTION IS TAKEN AS WELL AS THE DISCARD, WHICH IS NOT A
            // CONTRADICTION: the packet is discarded from THIS pass - it contributes no
            // frames, no acknowledgement and no processed count - and a copy is retained so
            // that a later pass can open it. RFC 9001 s5.7 is the section that says why this
            // is worth doing rather than merely allowed: "Due to reordering and loss,
            // protected packets might be received by an endpoint before the final TLS
            // handshake messages are received", and "Received packets protected with 1-RTT
            // keys MAY be stored and later decrypted and used once the handshake is complete."
            // The same section grants the mirror case a server sees - "The server MAY retain
            // these packets for later decryption in anticipation of receiving a ClientHello" -
            // so the permission is not 1-RTT-only in spirit and the retain branch is not
            // level-specific.
            //
            // s5.7 ALSO MAKES THE DELAY MANDATORY IN ONE DIRECTION, and retaining is how this
            // client obeys it rather than a way around it: "Even if it has 1-RTT secrets, a
            // client MUST NOT process incoming 1-RTT protected packets before the TLS
            // handshake is complete." Replay is driven by InstallReadKeys, and the Application
            // read keys are installed when the handshake completes - so a 1-RTT packet that
            // arrives early is held, not opened, which is the MUST NOT stated as a mechanism.
            //
            // BOUNDED, BECAUSE ANYONE WHO CAN SEND A DATAGRAM CAN FILL THIS. The ceiling is
            // TlsQuicConnectionSpec.RetainedPacketBufferBytes and refusing is silent: an
            // over-ceiling packet is simply the discard this branch already performed, which
            // is s12.2's other option and needs no error of its own.
            Retain(packet, packetNumberOffset, level, isShortHeader);
            return null;
        }

        // Through the level's own prepared key schedule rather than through its raw key: same
        // s5.4 mask over the same sample, without re-deriving the block cipher for every packet
        // that arrives. The schedule belongs to `keys` and dies with them.
        if (!TlsQuicHeaderProtection.TryRemove(
                keys.HeaderProtection, packet, packetNumberOffset, out var pnLength))
        {
            discarded++;
            return null;
        }

        var packetNumberEnd = packetNumberOffset + pnLength;

        ulong truncated = 0;
        for (var i = 0; i < pnLength; i++)
        {
            truncated = (truncated << 8) | packet[packetNumberOffset + i];
        }

        // RFC 9000 s17.1: "The full packet number is then reconstructed based on the
        // number of significant bits present, the value of those bits, and the largest
        // packet number received in a successfully authenticated packet." Appendix A.3's
        // pn_nbits is "the number of bits in the Packet Number field (8, 16, 24, or 32)",
        // hence the *8; and largest_pn is "the largest packet number that has been
        // successfully processed in the current packet number space" - per space, which
        // is why SpaceOf collapses the four levels onto s12.3's three spaces and not
        // onto one connection-wide counter.
        var space = SpaceOf(level);
        var packetNumber = TlsQuicPacketNumber.Decode(_largestReceived[space], truncated, pnLength * 8);

        // RFC 9001 s5.3: "The associated data, A, for the AEAD is the contents of the
        // QUIC header, starting from the first byte of either the short or long header,
        // up to and including the unprotected packet number." Up to AND INCLUDING - the
        // slice ends after the packet number, not at it.
        var associatedData = packet[..packetNumberEnd];
        var ciphertext = packet[packetNumberEnd..];

        // UNREACHABLE BY CONSTRUCTION, and deliberately unwitnessed - a test for it
        // would pass against the mutant that deletes it and become a false witness.
        // TryRemove has already succeeded above, and RFC 9001 s5.4.2's sample is 16
        // bytes taken at packet_number_offset + 4, so header protection removal only
        // succeeds when packet.Length >= packetNumberOffset + 20. The Packet Number
        // field is at most 4 bytes (s17.1: "encoded in 1 to 4 bytes"), so what remains
        // after it is always at least 16 - exactly the tag length. Kept anyway: this
        // method must not throw for ANY input, and without it a negative length would
        // reach AsSpan the moment header protection's own bound ever changes.
        if (ciphertext.Length < AuthenticationTagLength)
        {
            discarded++;
            return null;
        }

        var plaintext = _scratch.AsSpan(0, ciphertext.Length - AuthenticationTagLength);

        // RFC 9001 s6's three generations, and WHICH ONE TO TRY IS DECIDED BEFORE ANY AEAD
        // WORK, not by trying them all.
        //
        // A matching Key Phase bit is the current keys and nothing else. A DIFFERING one is
        // ambiguous on the wire and s6.5 gives the discriminator: "A recovered packet number
        // that is lower than any packet number from the current key phase uses the previous
        // packet protection keys; a recovered packet number that is higher than any packet
        // number from the current key phase requires the use of the next packet protection
        // keys."
        //
        // AND ONE STATE s6.5 DOES NOT NAME: this endpoint has just updated its own keys and
        // the peer has not caught up. Then EVERY packet still carries the old phase, at
        // numbers above anything seen in the new phase, and s6.5's number test would send all
        // of them to the next generation. _awaitingPeerKeyPhaseCatchUp is what distinguishes
        // "the peer is behind me" from "the peer is ahead of me"; nothing on the wire does.
        var opening = keys;
        var opened = KeyGeneration.Current;
        ReadKeys? fallback = null;

        if (isShortHeader
            && level == TlsQuicEncryptionLevel.Application
            && ((packet[0] & KeyPhaseBit) != 0) != keys.KeyPhase)
        {
            var previousFirst = _awaitingPeerKeyPhaseCatchUp
                || (_previousApplicationKeys is not null
                    && _currentPhaseLowestPacketNumber is { } lowest
                    && packetNumber < lowest);

            (opening, fallback) = previousFirst
                ? (_previousApplicationKeys, _nextApplicationKeys)
                : (_nextApplicationKeys, _previousApplicationKeys);
            opened = previousFirst ? KeyGeneration.Previous : KeyGeneration.Next;

            if (opening is null)
            {
                (opening, fallback) = (fallback, null);
                opened = opened == KeyGeneration.Previous
                    ? KeyGeneration.Next
                    : KeyGeneration.Previous;
            }

            if (opening is null)
            {
                // Nothing to try. s5.5: "a packet that appears to trigger a key update but
                // cannot be unprotected successfully MUST be discarded" - and a packet with no
                // candidate keys at all cannot be unprotected successfully. Counted as a
                // failure for the same reason s6.6 counts the ones that do reach the AEAD:
                // this is a packet the connection could not authenticate, and an attacker who
                // could make it free would have an unbounded forgery budget.
                discarded++;
                AuthenticationFailures++;
                return null;
            }
        }

        if (!TlsQuicPacketProtection.TryOpen(
                opening.PacketCipher, opening.Key, opening.Iv,
                packetNumber, associatedData, ciphertext, plaintext))
        {
            // THE SECOND CANDIDATE EXISTS FOR s6.4's MUST AND FOR NOTHING ELSE: "An endpoint
            // that successfully removes protection with old keys when newer keys were used for
            // packets with lower packet numbers MUST treat this as a connection error of type
            // KEY_UPDATE_ERROR." That violation can only be SEEN by trying the old keys on a
            // packet s6.5's number test had already routed to the new ones, so a receiver that
            // stopped at one attempt could never raise it.
            //
            // THE EXTRA AEAD RUN IS ON A PATH THAT HAS ALREADY FAILED ONE, so an ordinary
            // packet never pays it, and the Key Phase bit is header-protected - s5.4.1 covers
            // "the least significant five bits of the first byte" - so an off-path sender
            // cannot steer packets down this branch without the header protection key. That is
            // the s6.3 timing argument for this shape; the primary answer to s6.3 is that both
            // generations are derived ahead of time and none of this derives anything.
            if (fallback is null
                || !TlsQuicPacketProtection.TryOpen(
                    fallback.PacketCipher, fallback.Key, fallback.Iv,
                    packetNumber, associatedData, ciphertext, plaintext))
            {
                // s12.2, and the reason this is a count and not a close: a failed decrypt is
                // what every stray, forged, or replayed datagram produces. s6.6's integrity
                // limit is the thing that eventually acts on the total.
                discarded++;
                AuthenticationFailures++;
                return null;
            }

            opened = opened == KeyGeneration.Next
                ? KeyGeneration.Previous
                : KeyGeneration.Next;
        }

        // Authenticated from here. Everything below judges bytes the peer's own AEAD
        // tag covers.

        var reservedBits = isShortHeader ? ShortHeaderReservedBits : LongHeaderReservedBits;
        if ((packet[0] & reservedBits) != 0)
        {
            // s17.2 / s17.3.1: "An endpoint MUST treat receipt of a packet that has a
            // non-zero value for these bits, after removing both packet and header
            // protection, as a connection error of type PROTOCOL_VIOLATION."
            return (TlsQuicTransportError.ProtocolViolation, "Reserved bits were non-zero.");
        }

        if (isShortHeader && level == TlsQuicEncryptionLevel.Application)
        {
            // THIS BLOCK USED TO BE A CLOSE AND NOTHING ELSE. It read "key update is out of
            // scope for this phase, so a phase other than the one installed is not something
            // to ignore" and returned KEY_UPDATE_ERROR for every flipped Key Phase bit. A
            // conforming server updating its keys - which s6 lets it do at any time after the
            // handshake is confirmed - was met with a connection error. The close is still
            // here, but for s6.4's violation rather than for the update itself.
            if (opened == KeyGeneration.Next)
            {
                // s6.2: "If a packet is successfully processed using the next key and IV, then
                // the peer has initiated a key update.  The endpoint MUST update its send keys
                // to the corresponding key phase in response." The send half is
                // TlsQuicConnection's, which is what KeyUpdatePending carries; promoting the
                // read half is this receiver's and happens here, because the packet in hand
                // was already opened with the new keys.
                Promote();
                KeyUpdatePending = true;
                KeyUpdatesReceived++;
            }
            else if (opened == KeyGeneration.Previous
                && _currentPhaseLowestPacketNumber is { } newestPhaseLowest
                && packetNumber > newestPhaseLowest)
            {
                // s6.4: "Packets with higher packet numbers MUST be protected with either the
                // same or newer packet protection keys than packets with lower packet numbers.
                // An endpoint that successfully removes protection with old keys when newer
                // keys were used for packets with lower packet numbers MUST treat this as a
                // connection error of type KEY_UPDATE_ERROR."
                //
                // AUTHENTICATED BEFORE IT IS JUDGED, like every other close in this method:
                // the packet opened, under keys only the peer holds, so this is the peer's own
                // ordering and not a forgery.
                return (
                    TlsQuicTransportError.KeyUpdateError,
                    "A packet protected with the previous key phase carried a higher packet "
                        + "number than a packet already opened with the current one.");
            }

            if (opened != KeyGeneration.Previous)
            {
                // The peer is at our phase, so a locally initiated update is complete. Set
                // unconditionally rather than under a test: it is already false in the common
                // case and a branch would only hide which packet clears it.
                _awaitingPeerKeyPhaseCatchUp = false;

                // s6.5's "any packet number from the current key phase", kept as the lowest so
                // the comparison it feeds is the one s6.5 states. Promote() cleared it a few
                // lines above when this packet was the update itself, so that case lands here
                // as the first number of the new phase.
                if (_currentPhaseLowestPacketNumber is not { } known || packetNumber < known)
                {
                    _currentPhaseLowestPacketNumber = packetNumber;
                }
            }
        }

        // s17.1's "largest packet number received in a successfully authenticated
        // packet" - so this update belongs after TryOpen, not after the decode. Max, not
        // assignment: a reordered packet is authenticated too and must not pull the
        // largest back down.
        if (packetNumber > _largestReceived[space])
        {
            _largestReceived[space] = packetNumber;
        }

        if (IsDuplicate(space, packetNumber))
        {
            // COUNTED AS DISCARDED, WITH ITS OWN RUNNING TOTAL BESIDE IT. Every packet this
            // method sees has to land in exactly one of `processed` or `discarded` - callers
            // assert on the sum, and a packet in neither reads as a packet that never arrived.
            // s12.2 already calls dropping a packet without processing it "discarding", so the
            // bucket is right; DuplicatesSuppressed exists so that a duplicate is still
            // distinguishable from a failed decrypt, which is the same argument
            // DiscardedForMissingKeys carries and it is not carried on the per-datagram result
            // for the same reason it is: no caller has a decision to make per datagram.
            discarded++;
            DuplicatesSuppressed++;

            // s12.3: "A receiver MUST discard a newly unprotected packet unless it is certain
            // that it has not processed another packet with the same packet number from the
            // same packet number space.  Duplicate suppression MUST happen after removing
            // packet protection for the reasons described in Section 9.5 of [QUIC-TLS]."
            //
            // AFTER TryOpen AND AFTER THE s17.1 LARGEST UPDATE, WHICH IS BOTH MUSTs AT ONCE.
            // Suppressing before the AEAD would let an off-path sender who guessed a packet
            // number silence the real one, which is the attack s12.3's second sentence points
            // at. The largest received is updated first for the opposite reason: s17.1 defines
            // it over "a successfully authenticated packet", and a duplicate is authenticated -
            // holding it back would move the packet-number decoding window on the next packet.
            //
            // NOT AN ERROR, AND NOT PROCESSED EITHER. `processed` is not incremented below,
            // so a duplicate does not restart s10.1's idle timer and does not arm s17.2.5.2's
            // "after the client has received and processed" Retry rule. It is also not
            // acknowledged: no frame reaches the handler, so TlsQuicAckTracker never sees the
            // number - which is right, because the original occurrence already put it in an
            // ACK range.
            return null;
        }

        if (plaintext.Length == 0)
        {
            // RFC 9000 s12.4: "The payload of a packet that contains frames MUST contain
            // at least one frame... An endpoint MUST treat receipt of a packet
            // containing no frames as a connection error of type PROTOCOL_VIOLATION."
            // A zero-length payload is a real, reachable input distinct from an absent
            // one: the packet still carried a 16-byte tag and still authenticated.
            return (TlsQuicTransportError.ProtocolViolation, "Packet contained no frames.");
        }

        var payload = _scratch.AsMemory(0, plaintext.Length);
        var received = new TlsQuicReceivedPacket { Level = level, PacketNumber = packetNumber };

        var frameOffset = 0;
        while (frameOffset < payload.Length)
        {
            if (!TlsQuicFrames.TryReadFrame(payload, ref frameOffset, out var frame, out var error))
            {
                // s12.4 assigns different codes to different malformations and
                // TryReadFrame already resolved which - including "An endpoint MUST
                // treat the receipt of a frame of unknown type as a connection error of
                // type FRAME_ENCODING_ERROR", which is why the legality check below
                // never sees an unknown type.
                return (error, "Frame could not be decoded.");
            }

            if (!TlsQuicFrameLegality.Permits(frame, level))
            {
                // s12.4: "An endpoint MUST treat receipt of a frame in a packet type
                // that is not permitted as a connection error of type
                // PROTOCOL_VIOLATION."
                return (TlsQuicTransportError.ProtocolViolation, "Frame is not permitted in this packet type.");
            }

            handler(frame, received);
        }

        processed++;
        return null;
    }

    /// <summary>Reports whether this packet number has already been processed in this space,
    /// recording it when it has not.</summary>
    /// <remarks>
    /// <para>THE WINDOW HAS A CEILING AND IT IS STATED RATHER THAN HIDDEN: 128 packets below
    /// the highest processed. A packet further back than that is treated as a duplicate and
    /// discarded, which is s12.3's own suggested shape - "the data required for detecting
    /// duplicates can be limited by maintaining a minimum packet number below which all
    /// packets are immediately dropped" - and it is conservative in the direction s12.3 asks
    /// for, since its rule is "unless it is CERTAIN that it has not processed" one.</para>
    /// <para>THE COST OF THAT CEILING IS A RETRANSMIT, NOT DATA LOSS. A genuine packet
    /// reordered more than 128 behind is dropped and never acknowledged, so the peer's loss
    /// detection resends its frames in a new packet with a new number. Raising the window is a
    /// wider integer here and nothing else; 128 is chosen because measured QUIC reordering
    /// sits far below it and the state is one word per space.</para>
    /// <para>THE MAXIMUM SHIFT IS GUARDED because C# shift counts are taken modulo the operand
    /// width: <c>window &lt;&lt; 128</c> would be <c>window &lt;&lt; 0</c> and would keep every
    /// stale bit rather than clearing them. A jump of 128 or more clears the window
    /// outright.</para>
    /// </remarks>
    private bool IsDuplicate(int space, ulong packetNumber)
    {
        const int WindowBits = 128;

        if (!_duplicateWindowStarted[space])
        {
            _duplicateWindowStarted[space] = true;
            _duplicateWindowHighest[space] = packetNumber;
            _duplicateWindow[space] = UInt128.One;
            return false;
        }

        var highest = _duplicateWindowHighest[space];

        if (packetNumber > highest)
        {
            var advance = packetNumber - highest;
            _duplicateWindow[space] = advance >= WindowBits
                ? UInt128.Zero
                : _duplicateWindow[space] << (int)advance;
            _duplicateWindow[space] |= UInt128.One;
            _duplicateWindowHighest[space] = packetNumber;
            return false;
        }

        var back = highest - packetNumber;
        if (back >= WindowBits)
        {
            return true;
        }

        var bit = UInt128.One << (int)back;
        if ((_duplicateWindow[space] & bit) != UInt128.Zero)
        {
            return true;
        }

        _duplicateWindow[space] |= bit;
        return false;
    }

    // RFC 9001 s5.7's retention, refused in two cases and silent in both.
    //
    // 1. THE LEVEL'S KEYS ARE GONE FOR GOOD (s4.9). Nothing will ever open this packet, so
    //    holding it is memory spent on an impossible event - and worse, it is memory an
    //    off-path sender chooses, because s4.9.1 discards Initial keys early and the Initial
    //    header is entirely in the clear.
    // 2. THE CEILING IS FULL. This buffer is filled by whoever can send this endpoint a
    //    datagram and by nothing else, so an unbounded one is a remote memory-exhaustion
    //    vector rather than a theoretical one. RFC 9001 s4.3 makes the same point about the
    //    other place QUIC buffers unauthenticated peer input - buffering fragments "could
    //    consume excessive resources if the client's address has not yet been validated" -
    //    and the answer here is the same in kind: a stated bound, refused at the edge.
    //
    // BYTES AND NOT A PACKET COUNT, because bytes is the resource and a count is only a
    // proxy for it: one knob that means what it protects cannot be set to a pair of values
    // that disagree. The count is bounded as a consequence - every entry costs at least the
    // smallest packet that reaches this branch, so the default ceiling admits a few hundred
    // entries at worst - which is what makes the linear scans over this list affordable.
    //
    // OLDEST-WINS RATHER THAN EVICTING TO MAKE ROOM. The packets retention is for arrive in a
    // burst, ahead of one key installation, so the first ones in are the ones the handshake
    // is waiting on; evicting them to admit later arrivals would let a sender who floods
    // after the real flight displace exactly the packets that matter.
    //
    // Both refusals are witnessed. The ceiling by
    // TlsQuicPacketReceiverTests.TheRetentionCeilingRefusesThePacketThatWouldCrossItAndKeeps
    // WhatIsAlreadyHeld and, for the ceiling of zero that turns retention off outright, by
    // TlsQuicPacketReceiverTests.RetentionIsOffWhenTheCeilingIsZero; the discarded-level bar by
    // TlsQuicPacketReceiverTests.DiscardingALevelsKeysDropsThePacketsRetainedAtThatLevel, whose
    // second half re-offers an Initial packet after the discard and asserts nothing is held.
    private void Retain(
        ReadOnlySpan<byte> packet,
        int packetNumberOffset,
        TlsQuicEncryptionLevel level,
        bool isShortHeader)
    {
        if (_keysDiscarded[(int)level]
            || packet.Length > _retainedPacketBufferBytes - _retainedBytes)
        {
            return;
        }

        _retained.Add(new RetainedPacket(
            level, packetNumberOffset, isShortHeader, packet.ToArray()));
        _retainedBytes += packet.Length;
        PacketsRetainedForKeys++;
    }

    // Front to back, so arrival order is replay order; see the _retained field's note.
    private int IndexOfReplayable()
    {
        for (var i = 0; i < _retained.Count; i++)
        {
            if (_keys[(int)_retained[i].Level] is not null)
            {
                return i;
            }
        }

        return -1;
    }

    // One packet held under RFC 9001 s5.7, as it came off the wire. The two header facts are
    // carried rather than re-parsed because ProcessPacket needs exactly them and the parse
    // that produced them already ran, on these same bytes, in the pass that retained it.
    //
    // THE BYTES ARE STILL PROTECTED and are therefore not secret material: header protection
    // has not been removed and the AEAD has not been opened, so unlike _scratch there is
    // nothing here to zero. Replay removes the entry before processing it, so the in-place
    // unmasking ProcessPacket performs can never be seen by a second replay.
    private readonly record struct RetainedPacket(
        TlsQuicEncryptionLevel Level,
        int PacketNumberOffset,
        bool IsShortHeader,
        byte[] Packet);

    // RFC 9000 s12.2's receiver half: the first packet in the datagram sets the
    // Destination Connection ID, and every subsequent one must repeat it or be ignored.
    // SHOULD, not MUST, and the AEAD gates it anyway in practice - a third party
    // appending bytes to a real datagram does not hold read keys - so this is cheap
    // defence in depth ahead of the crypto rather than the thing keeping the peer out.
    // Deleting it is killed by
    // TlsQuicPacketReceiverTests.ASubsequentPacketWithADifferentConnectionIdIsIgnored.
    private static bool IsTheDatagramsConnectionId(
        ref ReadOnlyMemory<byte>? first, ReadOnlyMemory<byte> destinationConnectionId)
    {
        if (first is null)
        {
            first = destinationConnectionId;
            return true;
        }

        return first.Value.Span.SequenceEqual(destinationConnectionId.Span);
    }

    private static TlsQuicReceiveResult Close(
        (TlsQuicTransportError Error, string Reason) outcome,
        int processed,
        int discarded,
        int discardedForMissingKeys) =>
        new()
        {
            Processed = processed,
            Discarded = discarded,
            DiscardedForMissingKeys = discardedForMissingKeys,
            CloseError = outcome.Error,
            CloseReason = outcome.Reason,
        };

    // RFC 9000 s17.2 Table 5's four long header types, mapped to the RFC 9001 s4.1.4
    // encryption levels TlsQuicFrameLegality and the key store are indexed by. Retry
    // never reaches here - it has no packet protection and Receive returns before this.
    private static TlsQuicEncryptionLevel LevelOf(TlsQuicLongPacketType type) => type switch
    {
        TlsQuicLongPacketType.Initial => TlsQuicEncryptionLevel.Initial,
        TlsQuicLongPacketType.ZeroRtt => TlsQuicEncryptionLevel.EarlyData,
        _ => TlsQuicEncryptionLevel.Handshake,
    };

    // RFC 9000 s12.3: an Initial space, a Handshake space, and one Application data
    // space, because "0-RTT and 1-RTT data exist in the same packet number space to
    // make loss recovery algorithms easier to implement between the two packet types."
    private static int SpaceOf(TlsQuicEncryptionLevel level) => level switch
    {
        TlsQuicEncryptionLevel.Initial => 0,
        TlsQuicEncryptionLevel.Handshake => 1,
        _ => 2,
    };

    // The shared half of both promotions - s6.5's three sets shifting one place along.
    //
    // THE PREVIOUS SET IS REPLACED, NOT ACCUMULATED. s6.5's alternative is explicit that two
    // sets are enough: "endpoints can retain only two sets of packet protection keys, swapping
    // previous for next after enough time has passed to allow for reordering in the network."
    // Keeping three is this receiver's choice; keeping four would be keeping a generation no
    // rule can select.
    //
    // _currentPhaseLowestPacketNumber IS CLEARED because it describes the phase that just
    // stopped being current. Carrying it forward would make s6.5's "lower than any packet
    // number from the current key phase" a comparison against the wrong phase's numbers.
    private void Promote()
    {
        _previousApplicationKeys?.Dispose();
        _previousApplicationKeys = _keys[(int)TlsQuicEncryptionLevel.Application];
        _keys[(int)TlsQuicEncryptionLevel.Application] = _nextApplicationKeys;
        _nextApplicationKeys = null;
        _currentPhaseLowestPacketNumber = null;
    }

    // Generation zero. Called only from InstallReadKeys at the Application level, where the
    // keys being installed came from the TLS handshake rather than from "quic ku".
    private void ResetKeyUpdateState()
    {
        _nextApplicationKeys?.Dispose();
        _nextApplicationKeys = null;
        _previousApplicationKeys?.Dispose();
        _previousApplicationKeys = null;
        _currentPhaseLowestPacketNumber = null;
        _awaitingPeerKeyPhaseCatchUp = false;
        KeyUpdatePending = false;
    }

    // Which of RFC 9001 s6.5's three sets opened a packet. Not a field - it lives for one
    // call - but named rather than a pair of bools, because "previous" and "next" are
    // mutually exclusive and a bool pair would admit a fourth state that means nothing.
    private enum KeyGeneration
    {
        Previous,
        Current,
        Next,
    }

    private sealed class ReadKeys : IDisposable
    {
        internal required TlsQuicPacketProtectionCipher PacketCipher { get; init; }
        internal required TlsQuicHeaderProtectionCipher HeaderCipher { get; init; }
        internal required byte[] Key { get; init; }
        internal required byte[] Iv { get; init; }
        internal required byte[] HeaderProtectionKey { get; init; }
        internal required bool KeyPhase { get; init; }

        // RFC 9001 s5.4's block cipher, prepared once for this key rather than per packet -
        // see TlsQuicHeaderProtectionKeySchedule, whose whole lifetime rule is that it is
        // built beside the key and destroyed by whatever zeroes it. That is this class:
        // HeaderProtectionKey is zeroed below and the schedule goes with it, so no level's
        // key survives its own discard in either form. Lazy so that the three places that
        // build a ReadKeys do not each have to remember it.
        private TlsQuicHeaderProtectionKeySchedule? _headerProtection;

        internal TlsQuicHeaderProtectionKeySchedule HeaderProtection =>
            _headerProtection ??= new TlsQuicHeaderProtectionKeySchedule(
                HeaderCipher, HeaderProtectionKey);

        public void Dispose()
        {
            _headerProtection?.Dispose();
            _headerProtection = null;
            CryptographicOperations.ZeroMemory(Key);
            CryptographicOperations.ZeroMemory(Iv);
            CryptographicOperations.ZeroMemory(HeaderProtectionKey);
        }
    }
}
