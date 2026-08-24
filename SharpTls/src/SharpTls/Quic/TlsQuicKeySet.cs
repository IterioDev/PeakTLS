using System;
using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Quic;

/// <summary>
/// RFC 9001 s4.1.1/s4.9: owns packet-protection keys per encryption level and per
/// direction, and is the single place that decides whether a level is usable.
/// </summary>
/// <remarks>
/// <para>
/// WHY THIS DRIVES THE RECEIVER RATHER THAN DUPLICATING IT. Task 6's
/// <see cref="TlsQuicPacketReceiver"/> already owns read keys - it copies the material,
/// disposes what it replaces, and zeroes on discard, all of it reviewed and witnessed.
/// A second key store the receiver did not consult would be worse than none: two places
/// could disagree about whether a level is usable, and the disagreement would surface as
/// a packet that will not decrypt rather than as an error anyone can localise. So this
/// type owns the WRITE keys outright and DRIVES the receiver for the read half. One
/// object sequences both directions; the receiver stays the executor for reads.
/// </para>
/// <para>
/// THREE STATES THAT ALL LOOK LIKE "NO KEY", AND WHY THEY ARE KEPT APART. A level may be
/// never-installed, installed-then-discarded, or installed-from-a-secret-that-was-already
/// -zeroed. All three yield "cannot protect a packet here", and collapsing them loses the
/// only information a caller can act on: the first is a sequencing bug, the second is
/// correct steady state per s4.9, and the third is the disposal trap below. They are
/// distinguished by <see cref="TlsQuicKeyLevelState"/> and each is witnessed.
/// </para>
/// <para>
/// THE DISPOSAL TRAP, AND WHAT ACTUALLY GUARDS IT. <c>TlsQuicProcessResult.Dispose()</c>
/// zeroes unconsumed secrets (TlsQuicEvents.cs:137-148), so install BEFORE disposing the
/// result that produced one. But the trap does not surface as zeros: disposing the result
/// disposes the <see cref="TlsQuicTrafficSecret"/>, and its <c>CopySecret</c> then THROWS
/// <see cref="ObjectDisposedException"/>. That check - which already existed - is the real
/// defence, and the plan's done-when ("installing after disposal yields zeros") describes
/// a behaviour the type does not have.
/// </para>
/// <para>
/// The all-zero rejection in <see cref="InstallFromTrafficSecret"/> is therefore NOT the
/// disposal guard, and must not be described as one: <c>CopySecret</c> throws long before
/// it is reached. It covers a secret constructed all-zero by hand, which no disposal path
/// produces. Kept as defence in depth, because deriving from all-zero material yields a
/// structurally valid key that produces packets no peer can decrypt - a stalled handshake
/// rather than a localisable error - but its reachability is that narrow.
/// </para>
/// <para>
/// THREADING. Same requirement as the receiver: one loop, one thread of control. Nothing
/// here is synchronised, and CustomTlsQuicClient's StartHandshake, NotifyHandshakePacketSent
/// and ConfirmHandshake mutate their own state without taking the semaphore that guards
/// ProcessCryptoDataAsync. See the note at the head of TlsQuicPacketReceiver.
/// </para>
/// </remarks>
// MUTATION RECORD (performed in a git worktree and reverted).
//
// The figures below are DERIVED from the list, not asserted beside it - see the standing
// rule at the head of TlsQuicConnectionSpec.cs. Two earlier tasks shipped ledgers whose
// headline numbers could not be rebuilt from their own entries, and both authors believed
// they had complied.
//
//   ROWS BELOW                   21  = numbered 1-21 with no gaps
//   KILLED WHEN FIRST RUN        10  = 21 rows, less 10 [WAS-SURVIVOR] and 1 [SURVIVED]
//   SURVIVED, THEN FIXED         10  = rows 4, 5, 14-21
//   SURVIVING STILL               1  = row 13
//
// Two greps, both anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves:
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' `      must return 1
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' `  must return 10
//   `grep -cE '^// +[0-9]+\. ' `                   must return 21
// A plain `grep -c` of a bare marker does NOT work - it returns 6 for the first, because
// the prose matches too. Task 8's ledger shipped with exactly that flaw and an earlier
// draft of this one repeated it one commit after fixing it.
//
// Rows 1-13 are the implementer's own sweep. Rows 14-21 are the two review gates', and
// every one of those was a survivor: seven real defects and one dead guard. The ratio is
// the point - a self-run sweep found one defect, adversarial review found eight.
//
//    1. IsAllZero always returns false           ONLY InstallingFromASecretZeroedByDisposalIsRejected
//    2. WriteKeys.Dispose stops zeroing          3 tests
//    3. DiscardKeys does not record the discard  3 tests
//    4. Install clears _discarded unconditionally  [WAS-SURVIVOR] -> defect, see below
//    5. Install clears _discarded on write only    [WAS-SURVIVOR] -> dead code, deleted
//    6. Initial uses ChaCha20 not s5.4.1's AES   ONLY TheInitialLevelUsesAesRegardlessOfWhatIsNegotiatedLater
//    7. isClient inverted for the write side     3 tests
//    8. Replace does not zero superseded keys    ONLY ReDerivingZeroesTheSupersededMaterial
//    9. DiscardKeys spares the receiver's keys   ONLY DiscardingTakesTheReceiversReadKeysWithIt
//   10. WriteStateOf swaps Discarded/NeverInstalled  4 tests
//   11. TryGetWriteKeys serves after disposal    ONLY UsingADisposedKeySetThrowsRatherThanReturningStaleKeys
//   12. Undefined version accepted at ctor       ONLY AnUndefinedVersionIsRejectedAtConstruction
//   13. Read-key temporaries left un-zeroed      [SURVIVED] -> unwitnessed, see below
//   14. isClient inverted for the READ side      [WAS-SURVIVOR] -> now AClientsInitialReadKeysDecryptAppendixA3sServerPacket
//   15. Initial re-derived after its discard     [WAS-SURVIVOR] -> now InitialKeysCannotBeReDerivedAfterSection491sDiscard
//   16. Dispose loop capped at level 0           [WAS-SURVIVOR] -> now DisposeZeroesEveryLevelNotOnlyTheFirst
//   17. DiscardReadKeys(Initial) hardcoded       [WAS-SURVIVOR] -> now DiscardingRoutesToTheLevelAskedForNotAlwaysInitial
//   18. TryGetWriteKeys' own level guard deleted [WAS-SURVIVOR] -> dead, deleted; WriteStateOf re-checks
//   19. WriteStateOf without a disposal guard    [WAS-SURVIVOR] -> now WriteStateOfThrowsAfterDisposalRatherThanReportingNeverInstalled
//   20. Dispose leaves the receiver's read keys  [WAS-SURVIVOR] -> now DisposeTakesTheReceiversReadKeysAtEveryLevel
//   21. Write half committed before the read one [WAS-SURVIVOR] -> now AFailedReadInstallLeavesNoHalfInstalledLevel
//
// ROW 14 IS THE ONE THAT MATTERED. Inverting the READ derivation - a client reading with
// the client secret, which decrypts nothing - passed all 1004 tests. Every read assertion
// here went through TlsQuicPacketReceiver.HasReadKeys, which reports PRESENCE, never
// identity; the write half had A.1 as an external oracle and the read half had none. Both
// review gates found it independently. The fix is A.3's published server Initial, which
// someone else protected with the server secret, so it is an oracle we cannot fake.
// PRESENCE IS NOT IDENTITY - that is this task's transferable lesson.
//
// ROWS 4/5 were the sweep's own find. Clearing _discarded on any install reported
// NeverInstalled for a level whose writes had been discarded under s4.9. Narrowing it to
// write installs survived too, because WriteStateOf tests _write first and the flag is
// unreadable whenever write keys are present - so the clear was dead either way and the
// fix was deletion. Re-running row 4 kills exactly one named test, verified by both gates.
//
// ROW 13 IS UNWITNESSED, NOT VACUOUS, AND NOT REACHABLE BY A TEST. The three temporaries
// in Install are locals handed to the receiver, which copies them via .ToArray(); nothing
// outside this file can observe whether they were zeroed before falling out of scope, and
// a ReadOnlySpan cannot be captured for later inspection. The zeroing is correct and stays
// - task 6 shipped precisely this gap and its own zeroing mutation survived a green suite
// - but no test can pin it, and one written to look like it would be pinning the
// receiver's copy instead. A reviewer tried to break this classification and could not.
// Distinguished from the unreachable arm in CiphersFor, which no input can reach at all.
internal sealed class TlsQuicKeySet : IDisposable
{
    private const int LevelCount = 4;

    private readonly TlsQuicPacketReceiver _receiver;
    private readonly TlsQuicVersion _version;
    private readonly WriteKeys?[] _write = new WriteKeys?[LevelCount];
    private readonly bool[] _discarded = new bool[LevelCount];
    private bool _disposed;

    // RFC 9001 s6's key update needs the 1-RTT traffic SECRETS, not just the keys derived from
    // them: s6.1 derives generation n+1 from "the existing write secret" with the "quic ku"
    // label, and a key cannot be walked back to the secret that produced it. Kept only for
    // Application, because s6.1's Note is explicit - "Keys of packets other than the 1-RTT
    // packets are never updated".
    //
    // EACH ALWAYS DESCRIBES THE GENERATION CURRENTLY INSTALLED, which is what makes
    // NextGeneration correct to call on it. The read secret advances in step with the
    // receiver's current keys and the write secret in step with _write[Application]; letting
    // either drift would derive a generation the other side of the connection is not at.
    private TlsQuicTrafficSecret? _applicationReadSecret;
    private TlsQuicTrafficSecret? _applicationWriteSecret;

    /// <param name="receiver">
    /// The receiver whose read keys this set sequences. Required, not optional: an
    /// unattached key set is exactly the second store the remarks above rule out.
    /// </param>
    /// <param name="version">
    /// The connection's QUIC version. Not a constant - RFC 9369 defines a second version
    /// this project targets, and the two salt Initial secrets differently.
    /// </param>
    internal TlsQuicKeySet(TlsQuicPacketReceiver receiver, TlsQuicVersion version)
    {
        ArgumentNullException.ThrowIfNull(receiver);
        if (!Enum.IsDefined(version))
        {
            throw new ArgumentOutOfRangeException(nameof(version));
        }

        _receiver = receiver;
        _version = version;
    }

    /// <summary>Gets the RFC 9001 s6 key phase this endpoint protects its 1-RTT packets
    /// with.</summary>
    /// <remarks>s6: "The Key Phase bit is initially set to 0 for the first set of 1-RTT packets
    /// and toggled to signal each subsequent key update." The send path writes this into the
    /// short header; it is a property here rather than a constant there because the two must
    /// move together with <see cref="_applicationWriteSecret"/> and the write keys.</remarks>
    internal bool WriteKeyPhase { get; private set; }

    /// <summary>Gets how many RFC 9001 s6 key updates have been applied to this set, in either
    /// direction.</summary>
    internal int KeyUpdatesApplied { get; private set; }

    /// <summary>Gets whether an RFC 9001 s6 key update can be performed - both 1-RTT secrets
    /// are held.</summary>
    /// <remarks>s6.6 makes the negative answer consequential rather than merely informative:
    /// "If a key update is not possible or integrity limits are reached, the endpoint MUST stop
    /// using the connection". The caller that reaches an AEAD confidentiality limit asks this
    /// before it asks for the update.</remarks>
    internal bool CanUpdateKeys =>
        !_disposed
        && _applicationReadSecret is not null
        && _applicationWriteSecret is not null
        && _write[(int)TlsQuicEncryptionLevel.Application] is not null;

    /// <summary>Advances both 1-RTT directions one RFC 9001 s6 generation.</summary>
    /// <param name="locallyInitiated">
    /// <see langword="true"/> for s6.1's "initiating a key update", where this endpoint moves
    /// first and the peer is still at the old phase; <see langword="false"/> for s6.2's
    /// response, where the receiver has already promoted its read keys because a packet
    /// arrived protected with them.
    /// </param>
    /// <remarks>
    /// <para>BOTH DIRECTIONS, ALWAYS, WHICHEVER SIDE STARTED IT. s6: "Initiating a key update
    /// results in both endpoints updating keys.  This differs from TLS where endpoints can
    /// update keys independently."</para>
    /// <para>THE READ SECRET ADVANCES EVEN WHEN THE RECEIVER PROMOTED ITS OWN KEYS, because
    /// the receiver holds derived keys and this type holds the secret they came from. Skipping
    /// it would leave the next generation being derived from the generation before last, and
    /// the failure would be a peer whose second key update this endpoint cannot follow.</para>
    /// <para>THE NEXT SET IS ARMED IMMEDIATELY, which is s6.3's answer to the timing question:
    /// "Endpoints are generally expected to have current and next receive packet protection
    /// keys available", precisely so that responding to an update does not have to derive
    /// anything and cannot be timed.</para>
    /// </remarks>
    internal void ApplyKeyUpdate(bool locallyInitiated)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_applicationReadSecret is not { } readSecret
            || _applicationWriteSecret is not { } writeSecret
            || _write[(int)TlsQuicEncryptionLevel.Application] is not { } write)
        {
            throw new InvalidOperationException(
                "RFC 9001 s6's key update needs both 1-RTT traffic secrets and installed write "
                    + "keys. Ask CanUpdateKeys first; s6.6 makes a connection that cannot "
                    + "update one that must stop being used.");
        }

        // READ SIDE FIRST, so that a throw anywhere in here leaves the write keys at a
        // generation this endpoint can still be read at by the peer. A half-applied update
        // that moved the write keys and not the read ones is a connection that talks and
        // cannot listen.
        var nextRead = readSecret.NextGeneration(_version);
        _applicationReadSecret = nextRead;
        readSecret.Dispose();

        if (locallyInitiated)
        {
            // s6.1: "The endpoint that initiates a key update also updates the keys that it
            // uses for receiving packets." For a peer-initiated update the receiver has
            // already done this - it had to, to open the packet that announced it.
            _receiver.PromoteApplicationKeysForLocalUpdate();
        }

        ArmNextReadKeys();

        // WRITE SIDE. s6.1: "An endpoint initiates a key update by updating its packet
        // protection write secret and using that to protect new packets ... The endpoint
        // toggles the value of the Key Phase bit and uses the updated key and IV to protect
        // all subsequent packets."
        var nextWrite = writeSecret.NextGeneration(_version);
        _applicationWriteSecret = nextWrite;
        writeSecret.Dispose();

        using var derived = nextWrite.DerivePacketProtectionKeys(_version);
        var replacement = new WriteKeys
        {
            PacketCipher = write.PacketCipher,
            HeaderCipher = write.HeaderCipher,
            Key = derived.CopyKey(),
            Iv = derived.CopyIv(),

            // s6.1: "The header protection key is not updated." Carried across from the set
            // being replaced rather than taken from `derived`, which did compute a new one -
            // using it would leave the peer unable to remove header protection at all, and the
            // symptom would be every subsequent packet silently discarded.
            HeaderProtectionKey = (byte[])write.HeaderProtectionKey.Clone(),
        };

        _write[(int)TlsQuicEncryptionLevel.Application] = replacement;
        write.Dispose();

        WriteKeyPhase = !WriteKeyPhase;
        KeyUpdatesApplied++;
    }

    /// <summary>
    /// Gets which of the three states a level's WRITE keys are in; see the type's
    /// remarks. Read state belongs to the receiver - ask
    /// <see cref="TlsQuicPacketReceiver.HasReadKeys"/> for that.
    /// </summary>
    /// <remarks>
    /// Named for the direction on purpose. A read-only install leaves this reporting
    /// <see cref="TlsQuicKeyLevelState.NeverInstalled"/>, which is true of the writes and
    /// false of the level, and an unqualified <c>StateOf</c> invited a caller to read it
    /// as the latter.
    /// </remarks>
    internal TlsQuicKeyLevelState WriteStateOf(TlsQuicEncryptionLevel level)
    {
        // Without this, a disposed set reports NeverInstalled - "a sequencing bug",
        // per that member's own doc - for a level whose keys it just zeroed. The one
        // method that exists to keep zeroed apart from absent was the one collapsing
        // them.
        ObjectDisposedException.ThrowIf(_disposed, this);
        ThrowIfLevelUndefined(level);
        if (_write[(int)level] is not null)
        {
            return TlsQuicKeyLevelState.Installed;
        }

        return _discarded[(int)level]
            ? TlsQuicKeyLevelState.Discarded
            : TlsQuicKeyLevelState.NeverInstalled;
    }

    /// <summary>
    /// RFC 9001 s5.2: derives Initial keys for both directions from
    /// <paramref name="destinationConnectionId"/> and installs them.
    /// </summary>
    /// <remarks>
    /// Re-deriving with a different connection ID is legal and required, not an error -
    /// after a Retry the client re-derives against the server's Source Connection ID
    /// (task 9b's path), and s5.2 makes the CID the only input that changes. So this
    /// replaces rather than refuses, and the replaced material is zeroed.
    ///
    /// The ciphers are fixed here and that is the RFC's choice, not a hardcoded layout
    /// decision. s5.4.1: "Prior to TLS selecting a cipher suite, AES header protection is
    /// used (Section 5.4.3), matching the AEAD_AES_128_GCM packet protection."
    /// </remarks>
    /// <param name="destinationConnectionId">
    /// RFC 9001 s5.2's sole input to the Initial derivation. After a Retry this is the
    /// server's Source Connection ID rather than the client's own first choice.
    /// </param>
    /// <param name="isClient">
    /// Which secret protects our writes. s5.2 gives the client and server different
    /// secrets from the same derivation, so this is not inferable from the CID.
    /// </param>
    internal void InstallInitialKeys(ReadOnlySpan<byte> destinationConnectionId, bool isClient)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // s4.9.1: "Endpoints MUST NOT send Initial packets after this point." The design
        // enforces that by TryGetWriteKeys refusing a discarded level - but re-deriving
        // would repopulate the slot and quietly re-arm Initial sending. Retry cannot
        // legitimately land here: it answers the first Initial, long before the client
        // sends a Handshake packet, so a re-derivation after the discard is a sequencing
        // bug rather than the Retry path task 9b needs.
        // Witnessed by TlsQuicKeySetTests.InitialKeysCannotBeReDerivedAfterSection491sDiscard.
        if (_discarded[(int)TlsQuicEncryptionLevel.Initial])
        {
            throw new InvalidOperationException(
                "RFC 9001 s4.9.1 forbids sending Initial packets after the Initial keys "
                    + "are discarded, so they cannot be re-derived.");
        }

        using var secrets = TlsQuicInitialSecrets.Derive(_version, destinationConnectionId);
        using var writeKeys = isClient
            ? secrets.DeriveClientPacketProtectionKeys(_version)
            : secrets.DeriveServerPacketProtectionKeys(_version);
        using var readKeys = isClient
            ? secrets.DeriveServerPacketProtectionKeys(_version)
            : secrets.DeriveClientPacketProtectionKeys(_version);

        Install(
            TlsQuicEncryptionLevel.Initial,
            writeKeys,
            readKeys,
            TlsQuicPacketProtectionCipher.AesGcm,
            TlsQuicHeaderProtectionCipher.Aes);
    }

    /// <summary>
    /// Installs one direction of one level from a TLS traffic secret. The secret carries
    /// its own level, direction and cipher suite, so nothing is inferred here.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// The secret is all zeroes - see the disposal trap in the type's remarks - or its
    /// cipher suite is not one RFC 9001 s5.3 defines an AEAD for.
    /// </exception>
    internal void InstallFromTrafficSecret(TlsQuicTrafficSecret secret)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(secret);

        // Witnessed by TlsQuicKeySetTests.InstallingFromASecretZeroedByDisposalIsRejected.
        // A zeroed secret derives a structurally valid key that no peer can decrypt
        // against, so the failure would otherwise surface as "the handshake stalls".
        var raw = secret.CopySecret();
        try
        {
            if (IsAllZero(raw))
            {
                throw new ArgumentException(
                    "The traffic secret is all zeroes, which means the result that carried "
                        + "it was disposed before this install. Install before disposing.",
                    nameof(secret));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }

        var (packetCipher, headerCipher) = CiphersFor(secret.CipherSuite);
        using var keys = secret.DerivePacketProtectionKeys(_version);

        if (secret.Direction == TlsQuicSecretDirection.Write)
        {
            Install(secret.Level, keys, readKeys: null, packetCipher, headerCipher);
        }
        else
        {
            Install(secret.Level, writeKeys: null, keys, packetCipher, headerCipher);
        }

        if (secret.Level != TlsQuicEncryptionLevel.Application)
        {
            return;
        }

        // GENERATION ZERO OF THE 1-RTT SECRETS, kept because RFC 9001 s6.1 derives every later
        // generation from the one before and a derived key cannot be walked back.
        //
        // A COPY, NOT THE CALLER'S OBJECT. The remarks above this method say why the material
        // is copied at all - "RFC 9001's own key objects are caller-owned and
        // TlsQuicProcessResult.Dispose zeroes unconsumed secrets" - and a secret is exactly
        // that. Holding the caller's would give this set a field that turns into zeroes at a
        // moment it does not control, and the first symptom would be a key update deriving
        // from an all-zero secret.
        var retained = secret.CopySecret();
        try
        {
            var owned = new TlsQuicTrafficSecret(
                secret.Level, secret.Direction, secret.CipherSuite, retained);

            if (secret.Direction == TlsQuicSecretDirection.Write)
            {
                _applicationWriteSecret?.Dispose();
                _applicationWriteSecret = owned;

                // s6: "The Key Phase bit is initially set to 0 for the first set of 1-RTT
                // packets." Reset rather than left, because installing a fresh Application
                // write secret is generation zero however many updates preceded it.
                WriteKeyPhase = false;
            }
            else
            {
                _applicationReadSecret?.Dispose();
                _applicationReadSecret = owned;

                // s6.3's next set, armed before any packet can need it.
                ArmNextReadKeys();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(retained);
        }
    }

    // s6.3: "endpoints MUST be able to retain two sets of packet protection keys for receiving
    // packets: the current and the next." Derives generation n+1 from the secret describing
    // the generation currently installed and hands the receiver its key and IV; the header
    // protection key is s6.1's "not updated" and the receiver copies its own.
    private void ArmNextReadKeys()
    {
        if (_applicationReadSecret is not { } current)
        {
            return;
        }

        using var next = current.NextGeneration(_version);
        using var keys = next.DerivePacketProtectionKeys(_version);
        var key = keys.CopyKey();
        var iv = keys.CopyIv();
        try
        {
            _receiver.InstallNextApplicationReadKeys(key, iv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(iv);
        }
    }

    /// <summary>
    /// RFC 9001 s4.9: discards both directions at one level and zeroes the material.
    /// Idempotent - discarding twice is the same state, and s4.9.1's trigger can be
    /// reached by more than one path.
    /// </summary>
    /// <remarks>
    /// s4.9 is explicit that this is not automatic on installing a newer level: "it is
    /// possible that keys for a lower encryption level are needed for a short time after
    /// keys for a newer encryption level are available", because retransmitted CRYPTO
    /// frames and acknowledgements both stay at their own level. So discard is driven by
    /// the caller reaching s4.9.1's or s4.9.2's trigger, never inferred here from a
    /// newer level arriving.
    /// </remarks>
    internal void DiscardKeys(TlsQuicEncryptionLevel level)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ThrowIfLevelUndefined(level);

        _write[(int)level]?.Dispose();
        _write[(int)level] = null;
        _discarded[(int)level] = true;
        _receiver.DiscardReadKeys(level);

        if (level == TlsQuicEncryptionLevel.Application)
        {
            // The RFC 9001 s6 secrets go with the keys they describe. A retained 1-RTT secret
            // after the level is discarded is live key material for a level this type has just
            // declared unusable - the same disagreement between the two stores that Dispose's
            // remarks below rule out, reached by the other path.
            DisposeApplicationSecrets();
        }
    }

    // Zeroes both 1-RTT secrets and forgets the key phase. Not a public step: every caller
    // reaches it through a discard or a disposal, because a set with keys and no secret can no
    // longer perform s6's update and a set with a secret and no keys can no longer use one.
    private void DisposeApplicationSecrets()
    {
        _applicationReadSecret?.Dispose();
        _applicationReadSecret = null;
        _applicationWriteSecret?.Dispose();
        _applicationWriteSecret = null;
        WriteKeyPhase = false;
    }

    /// <summary>
    /// Gets the write keys for one level, or false if the level is unusable. The
    /// <paramref name="state"/> says which of the three states applies, so a caller can
    /// tell a sequencing bug from correct post-discard steady state.
    /// </summary>
    internal bool TryGetWriteKeys(
        TlsQuicEncryptionLevel level,
        out TlsQuicWriteKeyMaterial keys,
        out TlsQuicKeyLevelState state)
    {
        // No ThrowIfLevelUndefined here: WriteStateOf below re-checks it, so a guard on
        // this line is dead - deleting it left the suite green, and the test named for
        // it was pinning WriteStateOf's copy the whole time.
        ObjectDisposedException.ThrowIf(_disposed, this);

        state = WriteStateOf(level);
        var stored = _write[(int)level];
        if (stored is null)
        {
            keys = default;
            return false;
        }

        keys = new TlsQuicWriteKeyMaterial(
            stored.PacketCipher, stored.Key, stored.Iv, stored.HeaderCipher, stored.HeaderProtectionKey);
        return true;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        for (var level = 0; level < LevelCount; level++)
        {
            _write[level]?.Dispose();
            _write[level] = null;

            // THE READ HALF GOES TOO. Zeroing only the write material left the receiver
            // holding live read keys for a level this object had just declared gone -
            // and because every mutating method throws once _disposed is set, DiscardKeys
            // was no longer a route back to them. A type that calls itself the single
            // place deciding whether a level is usable cannot leave the other store
            // disagreeing on the one path out.
            // Witnessed by TlsQuicKeySetTests.DisposeTakesTheReceiversReadKeysAtEveryLevel.
            _receiver.DiscardReadKeys((TlsQuicEncryptionLevel)level);
        }

        DisposeApplicationSecrets();
        _disposed = true;
    }

    /// <summary>
    /// RFC 9001 s5.3 defines AEADs for AEAD_AES_128_GCM, AEAD_AES_128_CCM,
    /// AEAD_AES_256_GCM and AEAD_CHACHA20_POLY1305; s5.4.3 pairs each with its header
    /// protection. Anything else has no defined mapping and is rejected rather than
    /// defaulted - a wrong default here produces packets that will not decrypt.
    /// </summary>
    /// <remarks>
    /// <para>
    /// THE REJECTION ARM IS UNREACHABLE TODAY AND HAS NO TEST, deliberately.
    /// <see cref="TlsQuicTrafficSecret"/>'s constructor calls <c>CipherSuiteInfo.Get</c>,
    /// which supports three suites and throws for anything else - so nothing reaches here
    /// that this arm would catch, and a test aimed at it pins that constructor instead.
    /// </para>
    /// <para>
    /// THE RFC PERMITS FOUR, NOT THREE, AND THE MISSING ONE WOULD BE WRONGLY REJECTED
    /// HERE. s5.3: "QUIC can use any of the cipher suites defined in [TLS13] with the
    /// exception of TLS_AES_128_CCM_8_SHA256." TLS 1.3 defines five, so four are legal,
    /// and s5.4.1 names an AEAD for the one this switch omits - TLS_AES_128_CCM_SHA256,
    /// whose AEAD_AES_128_CCM takes AES header protection. So the arm is not a safety net
    /// waiting for an unsupported suite: <b>add TLS_AES_128_CCM_SHA256 to
    /// <c>CipherSuiteInfo</c> and this switch starts refusing a suite RFC 9001 allows.</b>
    /// Whoever does that owes this arm a fourth case, not a witness.
    /// </para>
    /// </remarks>
    private static (TlsQuicPacketProtectionCipher, TlsQuicHeaderProtectionCipher) CiphersFor(
        TlsCipherSuite suite) => suite switch
    {
        TlsCipherSuite.TlsAes128GcmSha256 or TlsCipherSuite.TlsAes256GcmSha384 =>
            (TlsQuicPacketProtectionCipher.AesGcm, TlsQuicHeaderProtectionCipher.Aes),
        TlsCipherSuite.TlsChaCha20Poly1305Sha256 =>
            (TlsQuicPacketProtectionCipher.ChaCha20Poly1305, TlsQuicHeaderProtectionCipher.ChaCha20),
        _ => throw new ArgumentException(
            $"RFC 9001 s5.3 defines no QUIC AEAD for cipher suite {suite}.", nameof(suite)),
    };

    private void Install(
        TlsQuicEncryptionLevel level,
        TlsQuicPacketProtectionKeys? writeKeys,
        TlsQuicPacketProtectionKeys? readKeys,
        TlsQuicPacketProtectionCipher packetCipher,
        TlsQuicHeaderProtectionCipher headerCipher)
    {
        ThrowIfLevelUndefined(level);

        // ORDER MATTERS, AND THE ORDER IS: BUILD, THEN READ, THEN COMMIT THE WRITE SLOT.
        // An earlier draft committed the write half first, so a receiver that threw -
        // an already-disposed one is enough, no exotic failure needed - left the level
        // reporting Installed with write keys served and no read keys anywhere. A level
        // that encrypts and never decrypts is precisely the two-stores-disagree failure
        // this type exists to prevent, arrived at from the inside.
        //
        // Building first also closes the window where the old WriteKeys is already
        // zeroed and the new one is not yet assigned: a throw in between would leave
        // _write non-null over zeroed arrays, which is Installed with an all-zero key -
        // the same shape as the disposal trap rejected in InstallFromTrafficSecret.
        var replacement = writeKeys is null
            ? null
            : new WriteKeys
            {
                PacketCipher = packetCipher,
                HeaderCipher = headerCipher,
                Key = writeKeys.CopyKey(),
                Iv = writeKeys.CopyIv(),
                HeaderProtectionKey = writeKeys.CopyHeaderProtectionKey(),
            };

        try
        {
            if (readKeys is not null)
            {
                var key = readKeys.CopyKey();
                var iv = readKeys.CopyIv();
                var headerProtectionKey = readKeys.CopyHeaderProtectionKey();
                try
                {
                    // keyPhase: false. Key update is out of scope for this phase, so
                    // every level is installed at the initial phase and the receiver
                    // closes on a packet claiming the other one; see
                    // TlsQuicPacketReceiver.Receive.
                    _receiver.InstallReadKeys(
                        level, packetCipher, key, iv, headerCipher, headerProtectionKey, keyPhase: false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                    CryptographicOperations.ZeroMemory(iv);
                    CryptographicOperations.ZeroMemory(headerProtectionKey);
                }
            }
        }
        catch
        {
            // Nothing was committed, so nothing is half-installed - but the material we
            // built and are about to drop is still key material.
            replacement?.Dispose();
            throw;
        }

        if (replacement is not null)
        {
            // Zeroes what it replaces. Re-derivation after Retry lands here, and the
            // superseded Initial key must not outlive it on the heap.
            _write[(int)level]?.Dispose();
            _write[(int)level] = replacement;
        }

        // NOTHING CLEARS _discarded, AND THAT IS DELIBERATE. An earlier draft cleared it
        // here unconditionally, which reported NeverInstalled for a level whose writes
        // really had been discarded under s4.9 - the one answer false in both
        // directions, since something was installed and the writes are gone. Narrowing
        // it to write installs then made it dead: StateOf tests _write FIRST, so the
        // flag is unreadable whenever write keys are present, and the only other path
        // that nulls _write is DiscardKeys, which sets the flag itself. So the clear had
        // no reachable effect worth keeping and the honest form is its absence.
        // Found by mutation M4, which survived both the unconditional and the narrowed
        // form. Witnessed by
        // TlsQuicKeySetTests.AReadInstallDoesNotReopenALevelWhoseWritesWereDiscarded,
        // which fails against the unconditional clear.
    }

    private static bool IsAllZero(ReadOnlySpan<byte> value)
    {
        return !value.ContainsAnyExcept((byte)0);
    }

    private static void ThrowIfLevelUndefined(TlsQuicEncryptionLevel level)
    {
        if (!Enum.IsDefined(level))
        {
            throw new ArgumentOutOfRangeException(nameof(level));
        }
    }

    private sealed class WriteKeys : IDisposable
    {
        internal required TlsQuicPacketProtectionCipher PacketCipher { get; init; }
        internal required TlsQuicHeaderProtectionCipher HeaderCipher { get; init; }
        internal required byte[] Key { get; init; }
        internal required byte[] Iv { get; init; }
        internal required byte[] HeaderProtectionKey { get; init; }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Key);
            CryptographicOperations.ZeroMemory(Iv);
            CryptographicOperations.ZeroMemory(HeaderProtectionKey);
        }
    }
}

/// <summary>
/// Which of the three "no usable key" states one encryption level is in. They are kept
/// apart because they call for different responses; see <see cref="TlsQuicKeySet"/>.
/// </summary>
internal enum TlsQuicKeyLevelState
{
    /// <summary>No key was ever installed here. Reaching this is a sequencing bug.</summary>
    NeverInstalled,

    /// <summary>Keys are installed and usable.</summary>
    Installed,

    /// <summary>Keys were installed and then discarded per RFC 9001 s4.9. Correct steady state.</summary>
    Discarded,
}

/// <summary>
/// Borrowed write-key material. The spans alias <see cref="TlsQuicKeySet"/>'s own arrays
/// and are valid until the next install or discard at that level, or the set's disposal -
/// all three zero what they replace. Copy anything that must outlive the call.
/// </summary>
internal readonly ref struct TlsQuicWriteKeyMaterial
{
    internal TlsQuicWriteKeyMaterial(
        TlsQuicPacketProtectionCipher packetCipher,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        TlsQuicHeaderProtectionCipher headerCipher,
        ReadOnlySpan<byte> headerProtectionKey)
    {
        PacketCipher = packetCipher;
        Key = key;
        Iv = iv;
        HeaderCipher = headerCipher;
        HeaderProtectionKey = headerProtectionKey;
    }

    internal TlsQuicPacketProtectionCipher PacketCipher { get; }
    internal ReadOnlySpan<byte> Key { get; }
    internal ReadOnlySpan<byte> Iv { get; }
    internal TlsQuicHeaderProtectionCipher HeaderCipher { get; }
    internal ReadOnlySpan<byte> HeaderProtectionKey { get; }
}
