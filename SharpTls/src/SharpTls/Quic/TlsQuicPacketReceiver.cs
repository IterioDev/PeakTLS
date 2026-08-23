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

    private readonly uint _version;
    private readonly int _destinationConnectionIdLength;
    private readonly ReadKeys?[] _keys = new ReadKeys?[4];
    private readonly ulong[] _largestReceived = new ulong[PacketNumberSpaceCount];
    private byte[] _scratch = [];
    private bool _disposed;

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
    {
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

    /// <summary>Whether read keys are installed at <paramref name="level"/>.</summary>
    internal bool HasReadKeys(TlsQuicEncryptionLevel level) => _keys[(int)level] is not null;

    /// <summary>
    /// Installs read keys for one encryption level, replacing any already there. The
    /// key material is copied, because RFC 9001's own key objects are caller-owned and
    /// TlsQuicProcessResult.Dispose zeroes unconsumed secrets - install before
    /// disposing the result that produced them.
    /// </summary>
    /// <remarks>
    /// <c>keyPhase</c> is the key phase these keys belong to. Read only for short headers: RFC 9000 s17.2
    /// defines no Key Phase field on the long header, so the value carried at the other
    /// levels is never consulted rather than being accepted and ignored. Key update is
    /// out of scope for this phase, so this receiver never rotates it - the caller
    /// states which phase it installed and a packet claiming another one is an error;
    /// see Receive.
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
    }

    /// <summary>
    /// Discards read keys at one level and zeroes them. After this, packets at that
    /// level are discarded exactly like packets whose keys never arrived - RFC 9000
    /// s12.2's "the keys are not available" case.
    /// </summary>
    internal void DiscardReadKeys(TlsQuicEncryptionLevel level)
    {
        _keys[(int)level]?.Dispose();
        _keys[(int)level] = null;
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
        foreach (var coalesced in TlsQuicDatagramReader.Read(datagram))
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
                            packet, _destinationConnectionIdLength, out var shortHeader, out _))
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
                    if (!TlsQuicPacketHeader.TryReadLongHeader(packet, out var longHeader, out _))
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

        // The scratch holds decrypted payload - CRYPTO frames carry the TLS handshake,
        // so this is the same class of material TlsQuicPacketProtectionKeys.Dispose and
        // TlsQuicSecrets.Dispose zero. Witnessed by
        // TlsQuicPacketReceiverTests.DisposeZeroesTheDecryptedPlaintextLeftInTheScratch;
        // deleting this line was a surviving mutation until that test existed.
        CryptographicOperations.ZeroMemory(_scratch);
        _scratch = [];
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
            return null;
        }

        if (!TlsQuicHeaderProtection.TryRemove(
                keys.HeaderCipher, keys.HeaderProtectionKey, packet, packetNumberOffset, out var pnLength))
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
        if (!TlsQuicPacketProtection.TryOpen(
                keys.PacketCipher, keys.Key, keys.Iv, packetNumber, associatedData, ciphertext, plaintext))
        {
            // s12.2 again, and the reason this is a count and not a close: a failed
            // decrypt is what every stray, forged, or replayed datagram produces.
            discarded++;
            return null;
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

        if (isShortHeader && ((packet[0] & KeyPhaseBit) != 0) != keys.KeyPhase)
        {
            // Key update is out of scope for this phase, so a phase other than the one
            // installed is not something to ignore. RFC 9000 s20.1: "KEY_UPDATE_ERROR
            // (0x0e): An endpoint detected errors in performing key updates".
            //
            // Note precisely what this can and cannot see, because the AEAD decides it.
            // Byte 0 is inside the associated data, so a bit flipped in transit fails
            // the tag and is discarded above, never reaching here. A peer genuinely
            // rotating keys protects with keys we do not hold, which also fails the tag
            // and is discarded. What reaches here is a peer that ANNOUNCED a phase
            // change and then protected the packet with the unrotated keys anyway -
            // authenticated, self-contradictory, and exactly s20.1's "errors in
            // performing key updates". Closing before TryOpen instead would cover the
            // rotation case too, at the cost of handing any off-path attacker a
            // one-datagram connection kill - the trade s17.3.1 warns about by name.
            return (TlsQuicTransportError.KeyUpdateError, "Key phase differed from the installed phase.");
        }

        // s17.1's "largest packet number received in a successfully authenticated
        // packet" - so this update belongs after TryOpen, not after the decode. Max, not
        // assignment: a reordered packet is authenticated too and must not pull the
        // largest back down.
        if (packetNumber > _largestReceived[space])
        {
            _largestReceived[space] = packetNumber;
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

    private sealed class ReadKeys : IDisposable
    {
        internal required TlsQuicPacketProtectionCipher PacketCipher { get; init; }
        internal required TlsQuicHeaderProtectionCipher HeaderCipher { get; init; }
        internal required byte[] Key { get; init; }
        internal required byte[] Iv { get; init; }
        internal required byte[] HeaderProtectionKey { get; init; }
        internal required bool KeyPhase { get; init; }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Key);
            CryptographicOperations.ZeroMemory(Iv);
            CryptographicOperations.ZeroMemory(HeaderProtectionKey);
        }
    }
}
