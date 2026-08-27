using System;
using System.Linq;
using SharpTls.Protocol;
using SharpTls.Quic;
using Xunit;

namespace SharpTls.Tests.Quic;

/// <summary>
/// RFC 9001 s4.1.1/s4.9/s5.2 key ownership. No handshake is driven here by design: the
/// task was split out of 9a precisely so these failures are attributable on their own,
/// rather than arriving as "the handshake does not complete".
/// </summary>
public class TlsQuicKeySetTests
{
    // RFC 9001 A.1's connection ID and its published keys. NOT retyped from the RFC -
    // these are the same literals TlsQuicPrimitiveTests.Rfc9001InitialSecretsAndKeysMatchAppendixA
    // already pins, reused so the two cannot drift apart.
    private const string AppendixACid = "8394C8F03E515708";
    private const string AppendixAClientKey = "1F369613DD76D5467730EFCBE3B1A22D";
    private const string AppendixAClientIv = "FA044B2F42A3FD3B46FB255C";
    private const string AppendixAClientHp = "9F50449E04A0E810283A1E9933ADEDD2";
    private const string AppendixAServerKey = "CF3A5331653C364C88F0F379B6067E37";
    private const string AppendixAServerIv = "0AC1493CA1905853B0BBA03E";
    private const string AppendixAServerHp = "C206B8D9B9F0F37644430B490EEAA314";

    private static TlsQuicPacketReceiver NewReceiver() => new(0x00000001u, 8);

    private static TlsQuicTrafficSecret Secret(
        TlsQuicEncryptionLevel level,
        TlsQuicSecretDirection direction,
        TlsCipherSuite suite = TlsCipherSuite.TlsAes128GcmSha256,
        byte fill = 0xAB)
    {
        var length = suite == TlsCipherSuite.TlsAes256GcmSha384 ? 48 : 32;
        return new TlsQuicTrafficSecret(level, direction, suite, Enumerable.Repeat(fill, length).ToArray());
    }

    // ---- the external oracle -------------------------------------------------------

    [Fact]
    public void InitialWriteKeysMatchAppendixAForAClient()
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);

        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);

        Assert.True(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Initial, out var keys, out var state));
        Assert.Equal(TlsQuicKeyLevelState.Installed, state);
        Assert.Equal(AppendixAClientKey, Convert.ToHexString(keys.Key.Span));
        Assert.Equal(AppendixAClientIv, Convert.ToHexString(keys.Iv.Span));
        Assert.Equal(AppendixAClientHp, Convert.ToHexString(keys.HeaderProtectionKey.Span));
    }

    [Fact]
    public void AServerWritesWithTheServerSecretNotTheClientOne()
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);

        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: false);

        Assert.True(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Initial, out var keys, out _));
        Assert.Equal(AppendixAServerKey, Convert.ToHexString(keys.Key.Span));
        Assert.Equal(AppendixAServerIv, Convert.ToHexString(keys.Iv.Span));
        Assert.Equal(AppendixAServerHp, Convert.ToHexString(keys.HeaderProtectionKey.Span));
    }

    [Fact]
    public void InitialKeysReDeriveWhenTheDestinationConnectionIdChanges()
    {
        // Task 9b's Retry path: RFC 9001 s5.2 makes the CID the only input, so a second
        // install against the server's Source Connection ID must REPLACE rather than be
        // refused as a duplicate.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);

        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);
        keySet.InstallInitialKeys(Convert.FromHexString("0102030405060708"), isClient: true);

        Assert.True(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Initial, out var keys, out _));
        Assert.NotEqual(AppendixAClientKey, Convert.ToHexString(keys.Key.Span));

        // And re-deriving against the original CID returns exactly A.1 again, so the
        // change is the CID's doing and not an install counter.
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);
        Assert.True(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Initial, out var restored, out _));
        Assert.Equal(AppendixAClientKey, Convert.ToHexString(restored.Key.Span));
    }

    // ---- the three states ----------------------------------------------------------

    [Fact]
    public void ALevelWithNoInstallReportsNeverInstalledRatherThanDiscarded()
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);

        Assert.Equal(TlsQuicKeyLevelState.NeverInstalled, keySet.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
        Assert.False(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Handshake, out _, out var state));
        Assert.Equal(TlsQuicKeyLevelState.NeverInstalled, state);
    }

    [Fact]
    public void ADiscardedLevelIsUnusableAndSaysDiscardedNotNeverInstalled()
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);

        keySet.DiscardKeys(TlsQuicEncryptionLevel.Initial);

        Assert.False(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Initial, out _, out var state));
        Assert.Equal(TlsQuicKeyLevelState.Discarded, state);
        // The distinction is the whole point: a level nobody installed is a sequencing
        // bug, a discarded one is RFC 9001 s4.9's correct steady state.
        Assert.NotEqual(TlsQuicKeyLevelState.NeverInstalled, state);
    }

    [Fact]
    public void DiscardingIsIdempotentBecauseSection491sTriggerHasMoreThanOnePath()
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);

        keySet.DiscardKeys(TlsQuicEncryptionLevel.Initial);
        keySet.DiscardKeys(TlsQuicEncryptionLevel.Initial);

        Assert.Equal(TlsQuicKeyLevelState.Discarded, keySet.WriteStateOf(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public void DiscardingALevelNeverInstalledStillReportsDiscarded()
    {
        // Zero-versus-absent: discarding what was never there is not an error, but it
        // must not report NeverInstalled afterwards or a caller cannot tell it acted.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);

        keySet.DiscardKeys(TlsQuicEncryptionLevel.Handshake);

        Assert.Equal(TlsQuicKeyLevelState.Discarded, keySet.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
    }

    // ---- the disposal trap ---------------------------------------------------------

    [Fact]
    public void InstallingFromASecretZeroedByDisposalIsRejected()
    {
        // TlsQuicProcessResult.Dispose zeroes unconsumed secrets. Deriving from the
        // zeroed remains yields a structurally valid key no peer can decrypt against,
        // so the symptom would be a stalled handshake rather than a localisable error.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        var zeroed = new TlsQuicTrafficSecret(
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicSecretDirection.Write,
            TlsCipherSuite.TlsAes128GcmSha256,
            new byte[32]);

        var error = Assert.Throws<ArgumentException>(() => keySet.InstallFromTrafficSecret(zeroed));
        Assert.Equal("secret", error.ParamName);
    }

    [Fact]
    public void TheRealProcessResultDisposalIsWhatTheGuardCatches()
    {
        // The test above hand-zeroes a byte[32], which pins the guard but simulates the
        // trap. The trap actually lives in TlsQuicProcessResult.Dispose, so drive it:
        // build a result carrying a traffic-secret event, dispose it, then try to
        // install from the secret it zeroed. This is the plan's done-when - "a test that
        // reads a secret after disposal" - against the real type rather than a stand-in.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        var secret = Secret(TlsQuicEncryptionLevel.Handshake, TlsQuicSecretDirection.Write);
        var result = new TlsQuicProcessResult([new TlsQuicTrafficSecretEvent(secret)]);

        // Non-zero while the result is alive: without this the assertion below would
        // pass against a secret that was never populated.
        Assert.Contains(secret.CopySecret(), b => b != 0);
        result.Dispose();

        // THE PLAN'S DONE-WHEN IS WRONG ABOUT THIS, and only the real type shows it.
        // It says "installing after disposal yields zeros, pinned by a test that reads a
        // secret after disposal". Reading a disposed secret does not yield zeros - it
        // THROWS. TlsQuicProcessResult.Dispose disposes the event, which disposes the
        // TlsQuicTrafficSecret, and CopySecret then refuses outright.
        Assert.Throws<ObjectDisposedException>(() => secret.CopySecret());

        // So the all-zero guard in InstallFromTrafficSecret is NOT what defends the
        // disposal trap - it cannot be, because CopySecret throws before the guard is
        // reached. TlsQuicTrafficSecret's own disposed check is the real defence, and it
        // was already there. The guard covers a different case: a secret constructed
        // all-zero by hand, which no disposal produces. Recorded in the plan's
        // amendments for task 9a-i.
        Assert.Throws<ObjectDisposedException>(() => keySet.InstallFromTrafficSecret(secret));
    }

    [Fact]
    public void ASecretThatIsAllZeroExceptOneByteIsAccepted()
    {
        // Pins that the rejection above is "all zero", not "starts with zero" or
        // "mostly zero" - only the disposal case is refused.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        var raw = new byte[32];
        raw[31] = 1;
        using var secret = new TlsQuicTrafficSecret(
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicSecretDirection.Write,
            TlsCipherSuite.TlsAes128GcmSha256,
            raw);

        keySet.InstallFromTrafficSecret(secret);

        Assert.Equal(TlsQuicKeyLevelState.Installed, keySet.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
    }

    // ---- zeroing, witnessed rather than assumed ------------------------------------
    //
    // THE WITNESS IS TryPeekLiveWriteKeyStorage AND NOT TryGetWriteKeys, AND THE SWAP IS THE
    // POINT OF THE FIX THESE TESTS SIT BESIDE. The zeroing is defence in depth over memory
    // this type has stopped referencing, so from outside the only way to see it is to hold
    // the array being zeroed. TryGetWriteKeys used to provide that incidentally - and that
    // was the bug: every 1-RTT send path held the aliased material across the packet plan,
    // which is where RFC 9001 s6.6's key update fires, and shipped packets sealed under the
    // all-zero array these tests are watching. The safe accessor now copies; the alias lives
    // under a name no send path reaches for, and the zeroing keeps its witness.

    [Fact]
    public void DiscardZeroesTheWriteKeyMaterialItDrops()
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);

        // These ALIAS the set's own arrays, so holding them across the discard reads the very
        // bytes the discard was supposed to zero. Without this the zeroing has no witness at
        // all - task 6 shipped exactly that gap, and the mutation deleting its existing
        // zeroing survived a green suite.
        Assert.True(keySet.TryPeekLiveWriteKeyStorage(
            TlsQuicEncryptionLevel.Initial, out var key, out var iv, out var headerProtectionKey));
        Assert.Contains(key.ToArray(), b => b != 0);

        keySet.DiscardKeys(TlsQuicEncryptionLevel.Initial);

        Assert.All(key.ToArray(), b => Assert.Equal(0, b));
        Assert.All(iv.ToArray(), b => Assert.Equal(0, b));
        Assert.All(headerProtectionKey.ToArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public void ReDerivingZeroesTheSupersededMaterial()
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);

        Assert.True(keySet.TryPeekLiveWriteKeyStorage(
            TlsQuicEncryptionLevel.Initial, out var superseded, out _, out _));
        keySet.InstallInitialKeys(Convert.FromHexString("0102030405060708"), isClient: true);

        // The Retry path replaces rather than discards, and the old Initial key must not
        // outlive it on the heap.
        Assert.All(superseded.ToArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public void DisposeZeroesEveryInstalledLevel()
    {
        using var receiver = NewReceiver();
        var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);

        Assert.True(keySet.TryPeekLiveWriteKeyStorage(
            TlsQuicEncryptionLevel.Initial, out var key, out _, out _));
        keySet.Dispose();

        Assert.All(key.ToArray(), b => Assert.Equal(0, b));
    }

    // ---- and what the zeroing must NOT reach: material already handed out ----------

    [Fact]
    public void WriteKeyMaterialStillHoldsItsKeyAfterTheKeyUpdateThatReplacesIt()
    {
        // THE BUG THIS PINS, IN ONE SENTENCE: TryGetWriteKeys used to hand back spans over
        // the set's live arrays, ApplyKeyUpdate zeroes those arrays as it installs the
        // replacement (RFC 9001 s6.1: "An endpoint initiates a key update by updating its
        // packet protection write secret and using that to protect new packets"), and every
        // 1-RTT send path took the material BEFORE building the packet plan - which is where
        // s6.6's confidentiality-limit update fires - and copied the key AFTER. The packet
        // went out AEAD-sealed and header-protected under an all-zero key with the new phase
        // bit set: undecryptable by the peer, and indistinguishable from a forgery.
        //
        // WHY THE ASSERTION IS "UNCHANGED" AND NOT "NOT ALL ZERO". A key set whose update
        // derived a fresh generation into the same arrays would pass a zero check while
        // still handing the caller bytes it never asked for. The snapshot taken before the
        // update is the only correct answer, so it is the one asserted.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        using var write = Secret(TlsQuicEncryptionLevel.Application, TlsQuicSecretDirection.Write);
        using var read = Secret(
            TlsQuicEncryptionLevel.Application, TlsQuicSecretDirection.Read, fill: 0xCD);
        keySet.InstallFromTrafficSecret(write);
        keySet.InstallFromTrafficSecret(read);

        Assert.True(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Application, out var keys, out _));

        // Taken through ToArray, so this is a copy that the update below cannot touch under
        // any implementation - it is the oracle, not part of what is under test.
        var key = keys.Key.ToArray();
        var iv = keys.Iv.ToArray();
        var headerProtectionKey = keys.HeaderProtectionKey.ToArray();
        Assert.Contains(key, b => b != 0);

        // s6: "Initiating a key update results in both endpoints updating keys."
        Assert.True(keySet.CanUpdateKeys);
        keySet.ApplyKeyUpdate(locallyInitiated: true);

        Assert.Equal(key, keys.Key.ToArray());
        Assert.Equal(iv, keys.Iv.ToArray());

        // s6.1: "The header protection key is not updated" - so this one is carried across
        // rather than re-derived, which makes it the array the update Clones and then zeroes.
        Assert.Equal(headerProtectionKey, keys.HeaderProtectionKey.ToArray());
    }

    [Fact]
    public void WriteKeyMaterialStillHoldsItsKeyAfterTheLevelIsDiscardedAndTheSetDisposed()
    {
        // The same ownership question asked of the other two paths that zero in place, so
        // that a fix aimed only at ApplyKeyUpdate cannot pass. RFC 9001 s4.9's discard is the
        // ordinary steady state, and a datagram half-built when it happens must still go out
        // under the keys it was planned with.
        using var receiver = NewReceiver();
        var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);

        Assert.True(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Initial, out var keys, out _));

        keySet.DiscardKeys(TlsQuicEncryptionLevel.Initial);
        keySet.Dispose();

        Assert.Equal(AppendixAClientKey, Convert.ToHexString(keys.Key.Span));
        Assert.Equal(AppendixAClientIv, Convert.ToHexString(keys.Iv.Span));
        Assert.Equal(AppendixAClientHp, Convert.ToHexString(keys.HeaderProtectionKey.Span));
    }

    // ---- it drives the receiver rather than shadowing it ---------------------------

    [Fact]
    public void InstallingInitialKeysGivesTheReceiverItsReadKeys()
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);

        Assert.False(receiver.HasReadKeys(TlsQuicEncryptionLevel.Initial));
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);
        Assert.True(receiver.HasReadKeys(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public void AClientsInitialReadKeysDecryptAppendixA3sServerPacket()
    {
        // PRESENCE IS NOT IDENTITY. HasReadKeys only reports that a slot is non-null, so
        // every other read assertion here would pass with the client and server secrets
        // swapped - RFC 9001 s5.2 gives them different labels ("client in" / "server
        // in"), and a client that reads with the client secret decrypts nothing.
        // Inverting isClient on the READ ternary survived all 1004 tests until this
        // existed. A.3's published server Initial is the only oracle that tells the two
        // apart, because it was protected with the server secret by someone else.
        //
        // destinationConnectionIdLength 0: A.3's own Destination Connection ID field is
        // empty, though its keys derive from A.1's 8-byte client-chosen CID.
        using var receiver = new TlsQuicPacketReceiver((uint)TlsQuicVersion.Version1, 0);
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);

        var datagram = Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex);
        var frames = 0;
        var result = receiver.Receive(datagram, (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => frames++);

        Assert.Equal(1, result.Processed);
        Assert.Equal(0, result.Discarded);
        // A.3's plaintext is one ACK and one CRYPTO frame; a failed decrypt would be
        // discarded silently per s12.2 and yield zero.
        Assert.Equal(2, frames);
    }

    [Fact]
    public void AServersInitialReadKeysDoNotDecryptAnotherServersPacket()
    {
        // The other side of the same coin: a SERVER reads with the client secret, so
        // A.3's server-protected packet must NOT decrypt. Without this, a mutation that
        // ignored isClient on the read side and always used the server secret would pass
        // the test above.
        using var receiver = new TlsQuicPacketReceiver((uint)TlsQuicVersion.Version1, 0);
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: false);

        var datagram = Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex);
        var result = receiver.Receive(datagram, (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { });

        // s12.2: a packet that fails AEAD is discarded, not an error.
        Assert.Equal(0, result.Processed);
        Assert.Equal(1, result.Discarded);
    }

    [Fact]
    public void DiscardingTakesTheReceiversReadKeysWithIt()
    {
        // The two stores cannot disagree about whether a level is usable, which is the
        // reason this type drives the receiver instead of standing beside it.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);

        keySet.DiscardKeys(TlsQuicEncryptionLevel.Initial);

        Assert.False(receiver.HasReadKeys(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public void AWriteSecretDoesNotInstallReadKeysAndAReadSecretDoesNotInstallWriteKeys()
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);

        using var write = Secret(TlsQuicEncryptionLevel.Handshake, TlsQuicSecretDirection.Write);
        keySet.InstallFromTrafficSecret(write);
        Assert.Equal(TlsQuicKeyLevelState.Installed, keySet.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
        Assert.False(receiver.HasReadKeys(TlsQuicEncryptionLevel.Handshake));

        using var read = Secret(TlsQuicEncryptionLevel.Application, TlsQuicSecretDirection.Read);
        keySet.InstallFromTrafficSecret(read);
        Assert.True(receiver.HasReadKeys(TlsQuicEncryptionLevel.Application));
        Assert.False(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Application, out _, out _));
    }

    [Fact]
    public void AnEventSequenceInstallsEachLevelInOrder()
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);

        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);
        foreach (var level in new[]
                 {
                     TlsQuicEncryptionLevel.EarlyData,
                     TlsQuicEncryptionLevel.Handshake,
                     TlsQuicEncryptionLevel.Application,
                 })
        {
            using var write = Secret(level, TlsQuicSecretDirection.Write);
            using var read = Secret(level, TlsQuicSecretDirection.Read);
            keySet.InstallFromTrafficSecret(write);
            keySet.InstallFromTrafficSecret(read);
        }

        Assert.All(
            Enum.GetValues<TlsQuicEncryptionLevel>(),
            level => Assert.Equal(TlsQuicKeyLevelState.Installed, keySet.WriteStateOf(level)));
    }

    [Fact]
    public void InstallingALowerLevelDoesNotDiscardItWhenAHigherOneArrives()
    {
        // RFC 9001 s4.9: "it is possible that keys for a lower encryption level are
        // needed for a short time after keys for a newer encryption level are
        // available", because retransmitted CRYPTO frames and acknowledgements both
        // stay at their own level. Discard is the caller reaching s4.9.1's trigger,
        // never inferred here.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);

        using var handshake = Secret(TlsQuicEncryptionLevel.Handshake, TlsQuicSecretDirection.Write);
        keySet.InstallFromTrafficSecret(handshake);

        Assert.Equal(TlsQuicKeyLevelState.Installed, keySet.WriteStateOf(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public void AReadInstallDoesNotReopenALevelWhoseWritesWereDiscarded()
    {
        // StateOf reports the WRITE direction - that is what TryGetWriteKeys serves.
        // A read install arriving after an s4.9 discard must not make the level look
        // never-installed: something was installed, and the writes are still gone.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        using var write = Secret(TlsQuicEncryptionLevel.Handshake, TlsQuicSecretDirection.Write);
        keySet.InstallFromTrafficSecret(write);
        keySet.DiscardKeys(TlsQuicEncryptionLevel.Handshake);

        using var read = Secret(TlsQuicEncryptionLevel.Handshake, TlsQuicSecretDirection.Read);
        keySet.InstallFromTrafficSecret(read);

        Assert.Equal(TlsQuicKeyLevelState.Discarded, keySet.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
        Assert.True(receiver.HasReadKeys(TlsQuicEncryptionLevel.Handshake));
    }

    [Fact]
    public void InitialKeysCannotBeReDerivedAfterSection491sDiscard()
    {
        // s4.9.1: "Endpoints MUST NOT send Initial packets after this point." Refusing
        // the level is what enforces it; a re-derivation would silently re-arm sending.
        // Retry cannot reach here legitimately - it answers the first Initial, long
        // before any Handshake packet is sent.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);
        keySet.DiscardKeys(TlsQuicEncryptionLevel.Initial);

        Assert.Throws<InvalidOperationException>(
            () => keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true));
        Assert.Equal(TlsQuicKeyLevelState.Discarded, keySet.WriteStateOf(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public void AWriteInstallDoesReopenADiscardedLevel()
    {
        // The other side of the same guard, so the narrowing above is not a blanket
        // "never clear" that would leave a re-installed level reporting Discarded.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.DiscardKeys(TlsQuicEncryptionLevel.Handshake);

        using var write = Secret(TlsQuicEncryptionLevel.Handshake, TlsQuicSecretDirection.Write);
        keySet.InstallFromTrafficSecret(write);

        Assert.Equal(TlsQuicKeyLevelState.Installed, keySet.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
    }

    // ---- the cipher mapping that existed nowhere before ----------------------------

    // The cipher enums are internal, so they cannot appear in a public test signature.
    // The bool is which FAMILY s5.3/s5.4.3 pairs the suite with, and both halves are
    // asserted below - an AES suite must not reach ChaCha20 header protection and vice
    // versa, which is the pairing a wrong mapping would break.
    [Theory]
    [InlineData(TlsCipherSuite.TlsAes128GcmSha256, true)]
    [InlineData(TlsCipherSuite.TlsAes256GcmSha384, true)]
    [InlineData(TlsCipherSuite.TlsChaCha20Poly1305Sha256, false)]
    public void EachSuiteRfc9001DefinesAnAeadForMapsToItsOwnCiphers(TlsCipherSuite suite, bool isAes)
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        using var secret = Secret(TlsQuicEncryptionLevel.Handshake, TlsQuicSecretDirection.Write, suite);

        keySet.InstallFromTrafficSecret(secret);

        Assert.True(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Handshake, out var keys, out _));
        Assert.Equal(
            isAes ? TlsQuicPacketProtectionCipher.AesGcm : TlsQuicPacketProtectionCipher.ChaCha20Poly1305,
            keys.PacketCipher);
        Assert.Equal(
            isAes ? TlsQuicHeaderProtectionCipher.Aes : TlsQuicHeaderProtectionCipher.ChaCha20,
            keys.HeaderCipher);
    }

    // NO TEST for CiphersFor's rejection arm, deliberately. It is unreachable by
    // construction: TlsQuicTrafficSecret's constructor calls CipherSuiteInfo.Get, which
    // supports exactly the three TLS 1.3 suites RFC 9001 s5.3 defines QUIC AEADs for and
    // throws NotSupportedException on anything else. A test aimed at the arm pins that
    // constructor instead - it fired first when this test existed - so it would pass
    // against a mutated mapping and become a false witness. The reachability condition
    // is recorded at the arm itself.

    [Fact]
    public void TheInitialLevelUsesAesRegardlessOfWhatIsNegotiatedLater()
    {
        // RFC 9001 s5.4.1: "Prior to TLS selecting a cipher suite, AES header protection
        // is used (Section 5.4.3), matching the AEAD_AES_128_GCM packet protection."
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);

        using var chacha = Secret(
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicSecretDirection.Write,
            TlsCipherSuite.TlsChaCha20Poly1305Sha256);
        keySet.InstallFromTrafficSecret(chacha);

        Assert.True(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Initial, out var initial, out _));
        Assert.Equal(TlsQuicPacketProtectionCipher.AesGcm, initial.PacketCipher);
        Assert.Equal(TlsQuicHeaderProtectionCipher.Aes, initial.HeaderCipher);
    }

    // ---- argument guards -----------------------------------------------------------

    [Fact]
    public void AnUndefinedEncryptionLevelIsRejected()
    {
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);

        Assert.Throws<ArgumentOutOfRangeException>(() => keySet.WriteStateOf((TlsQuicEncryptionLevel)99));
        Assert.Throws<ArgumentOutOfRangeException>(() => keySet.DiscardKeys((TlsQuicEncryptionLevel)99));
    }

    [Fact]
    public void AnUndefinedVersionIsRejectedAtConstruction()
    {
        using var receiver = NewReceiver();

        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicKeySet(receiver, (TlsQuicVersion)7));
    }

    [Fact]
    public void ANullReceiverIsRejectedBecauseAnUnattachedKeySetIsTheSecondStore()
    {
        Assert.Throws<ArgumentNullException>(() => new TlsQuicKeySet(null!, TlsQuicVersion.Version1));
    }

    [Fact]
    public void UsingADisposedKeySetThrowsRatherThanReturningStaleKeys()
    {
        using var receiver = NewReceiver();
        var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);
        keySet.Dispose();

        Assert.Throws<ObjectDisposedException>(
            () => keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Initial, out _, out _));
    }

    [Fact]
    public void DisposeZeroesEveryLevelNotOnlyTheFirst()
    {
        // The loop bound was unwitnessed: capping it at level 0 left the suite green,
        // because the only disposal test installed Initial (=0) alone.
        using var receiver = NewReceiver();
        var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);
        using var handshake = Secret(TlsQuicEncryptionLevel.Handshake, TlsQuicSecretDirection.Write);
        using var application = Secret(TlsQuicEncryptionLevel.Application, TlsQuicSecretDirection.Write);
        keySet.InstallFromTrafficSecret(handshake);
        keySet.InstallFromTrafficSecret(application);

        Assert.True(keySet.TryPeekLiveWriteKeyStorage(
            TlsQuicEncryptionLevel.Initial, out var initial, out _, out _));
        Assert.True(keySet.TryPeekLiveWriteKeyStorage(
            TlsQuicEncryptionLevel.Handshake, out var hs, out _, out _));
        Assert.True(keySet.TryPeekLiveWriteKeyStorage(
            TlsQuicEncryptionLevel.Application, out var app, out _, out _));
        keySet.Dispose();

        Assert.All(initial.ToArray(), b => Assert.Equal(0, b));
        Assert.All(hs.ToArray(), b => Assert.Equal(0, b));
        Assert.All(app.ToArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public void DisposeTakesTheReceiversReadKeysAtEveryLevel()
    {
        // Zeroing only the write half left the receiver holding live read keys for a
        // level this object had declared gone - and with every method throwing once
        // disposed, DiscardKeys was no longer a route back to them.
        using var receiver = NewReceiver();
        var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);
        using var read = Secret(TlsQuicEncryptionLevel.Handshake, TlsQuicSecretDirection.Read);
        keySet.InstallFromTrafficSecret(read);

        keySet.Dispose();

        Assert.False(receiver.HasReadKeys(TlsQuicEncryptionLevel.Initial));
        Assert.False(receiver.HasReadKeys(TlsQuicEncryptionLevel.Handshake));
    }

    [Fact]
    public void DiscardingRoutesToTheLevelAskedForNotAlwaysInitial()
    {
        // Hardcoding DiscardReadKeys(Initial) survived, because the only discard test
        // ever discarded Initial. Task 9a-ii discards HANDSHAKE on HANDSHAKE_DONE -
        // exactly the level that breaks.
        using var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);
        using var read = Secret(TlsQuicEncryptionLevel.Handshake, TlsQuicSecretDirection.Read);
        keySet.InstallFromTrafficSecret(read);

        keySet.DiscardKeys(TlsQuicEncryptionLevel.Handshake);

        Assert.False(receiver.HasReadKeys(TlsQuicEncryptionLevel.Handshake));
        Assert.True(receiver.HasReadKeys(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public void WriteStateOfThrowsAfterDisposalRatherThanReportingNeverInstalled()
    {
        // NeverInstalled's own doc says reaching it is a sequencing bug. Reporting it
        // for a level whose keys were just zeroed collapses the very distinction this
        // method exists to keep.
        using var receiver = NewReceiver();
        var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true);
        keySet.Dispose();

        Assert.Throws<ObjectDisposedException>(() => keySet.WriteStateOf(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public void AFailedReadInstallLeavesNoHalfInstalledLevel()
    {
        // The write half used to be committed first, so a receiver that threw left the
        // level reporting Installed with write keys served and no read keys anywhere -
        // a level that encrypts and never decrypts, which is the two-stores-disagree
        // failure this type exists to prevent, arrived at from the inside.
        var receiver = NewReceiver();
        using var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);
        receiver.Dispose();

        Assert.Throws<ObjectDisposedException>(
            () => keySet.InstallInitialKeys(Convert.FromHexString(AppendixACid), isClient: true));
        Assert.Equal(TlsQuicKeyLevelState.NeverInstalled, keySet.WriteStateOf(TlsQuicEncryptionLevel.Initial));
        Assert.False(keySet.TryGetWriteKeys(TlsQuicEncryptionLevel.Initial, out _, out _));
    }

    [Fact]
    public void DisposeIsIdempotent()
    {
        using var receiver = NewReceiver();
        var keySet = new TlsQuicKeySet(receiver, TlsQuicVersion.Version1);

        keySet.Dispose();
        keySet.Dispose();
    }
}
