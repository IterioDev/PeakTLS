using System.Runtime.InteropServices;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task 6's receive pipeline. Three kinds of ground truth, in descending order of
// independence:
//
// 1. RFC 9001 Appendix A.3's server Initial - published bytes, published plaintext,
//    and a published packet number. It is the only input here nobody in this repo
//    chose. It anchors DEFAULTS and nothing else: its packet number is 1 in two
//    bytes, its Destination Connection ID is empty, its version is 1, and its
//    largest-received is 0. Task 4b measured what that blindness costs - 13 of its
//    24 mutations left A.2 AND A.3 green - so every non-default case below carries a
//    hand-derived expectation instead.
//
// 2. Hand-derived packet number decoding. The truncated bytes on the wire and the
//    full packet number are written as two SEPARATE literals, each derived by hand
//    from RFC 9000 Appendix A.3's pseudocode, and the AEAD is the oracle that joins
//    them: the nonce is built from the DECODED number (RFC 9001 s5.3), so a decode
//    that lands anywhere else fails the tag and the packet is discarded rather than
//    silently processed with a wrong number. That is why these tests assert
//    Processed, not just PacketNumber - the two cannot both be right by accident.
//
// 3. Hand-assembled packets for everything else. These do NOT go through
//    TlsQuicPacketBuilder: a builder round trip proves the encoder and decoder agree,
//    and they can agree while both being wrong. The header bytes below are laid out
//    from RFC 9000 s17.2 / s17.3.1 field by field. Only Seal and TryApply are reused,
//    because those two are pinned independently against A.2, A.3 and A.5 in
//    TlsQuicPacketProtectionTests and TlsQuicHeaderProtectionTests - the crypto is not
//    what this file is at risk of getting wrong; the arithmetic and the ordering are.
public sealed class TlsQuicPacketReceiverTests
{
    // RFC 9001 Appendix A: "These packets use an 8-byte client-chosen Destination
    // Connection ID of 0x8394c8f03e515708." A.3's server keys derive from it (A.1)
    // even though A.3's own Destination Connection ID field is empty.
    private const string AppendixAConnectionIdHex = "8394C8F03E515708";

    private const uint Version1 = (uint)TlsQuicVersion.Version1;

    // A version this connection is not speaking. Not 0: that is Version Negotiation's
    // reserved value (RFC 9000 s17.2.1), which TlsQuicDatagramReader routes elsewhere,
    // so using it here would pin the wrong check. Not 2 either, which RFC 9369 defines
    // - an unknown version has to be genuinely unknown.
    private const uint UnknownVersion = 0x0a0b0c0d;

    // Hand-derived, from the two frame layouts in RFC 9000 s19.3 and s19.6, against
    // A.3's published plaintext:
    //   02 00 00 00 00   ACK: type, Largest Acknowledged, ACK Delay, ACK Range Count,
    //                    First ACK Range - five one-byte varints.
    //   06 00 405a       CRYPTO: type, Offset 0, Length 0x405a. The 0x40 prefix is
    //                    s16's two-byte form, so the value is 0x005a = 90.
    //   ...90 bytes...   the CRYPTO Data field.
    // 5 + 4 + 90 = 99, which closes against the 99-byte published plaintext.
    private const int A3CryptoOffset = 0;
    private const int A3CryptoLength = 90;
    private const int A3AckFrameLength = 5;
    private const int A3CryptoHeaderLength = 4;

    // ---------------------------------------------------------------- A.3, leg 1

    [Fact]
    public void AppendixA3ServerInitialDecryptsAndItsCryptoFrameReachesTheReassembler()
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var datagram = Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex);
        var reassembler = new TlsQuicCryptoStreamReassembler(4096);
        var recorder = new Recorder(reassembler);

        var result = receiver.Receive(datagram, recorder.Handle);

        Assert.Equal(1, result.Processed);
        Assert.Equal(0, result.Discarded);
        Assert.Null(result.CloseError);
        Assert.Equal(TlsQuicUnprocessedPacket.None, result.Unprocessed);

        // "The header from the server includes a new connection ID and a 2-byte packet
        // number encoding for a packet number of 1."
        Assert.Equal(1UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Initial));

        // Per space, not per connection: nothing arrived at the other two.
        Assert.Equal(0UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));
        Assert.Equal(0UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Application));

        Assert.Equal(
            [TlsQuicFrameType.Ack, TlsQuicFrameType.Crypto],
            recorder.Frames.Select(f => f.Type));
        Assert.All(recorder.Frames, f => Assert.Equal(TlsQuicEncryptionLevel.Initial, f.Level));
        Assert.All(recorder.Frames, f => Assert.Equal(1UL, f.PacketNumber));

        var ack = recorder.Frames[0];
        Assert.Equal(0UL, ack.LargestAcknowledged);
        Assert.Equal(0UL, ack.AckDelay);
        Assert.Equal(0UL, ack.AckRangeCount);
        Assert.Equal(0UL, ack.FirstAckRange);

        var crypto = recorder.Frames[1];
        Assert.Equal((ulong)A3CryptoOffset, crypto.Offset);
        Assert.Equal(A3CryptoLength, crypto.DataLength);
        Assert.Equal(A3CryptoLength, reassembler.DeliveredLength);

        // The delivered bytes, sliced out of the published plaintext by the two
        // hand-derived frame lengths above - not by anything this pipeline computed.
        var plaintext = Convert.FromHexString(TlsQuicPacketProtectionTests.A3PlaintextHex);
        var expected = plaintext.AsSpan(A3AckFrameLength + A3CryptoHeaderLength, A3CryptoLength).ToArray();
        Assert.Equal(expected, recorder.CryptoBytes);
    }

    // ------------------------------------------------- the buffer lifetime contract

    [Fact]
    public void NothingRetainedAfterThePassAliasesTheReceiveBuffer()
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var datagram = Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex);
        var reassembler = new TlsQuicCryptoStreamReassembler(4096);
        var recorder = new Recorder(reassembler);

        Assert.Equal(1, receiver.Receive(datagram, recorder.Handle).Processed);
        Assert.Equal(A3CryptoLength, reassembler.DeliveredLength);

        // The pass is over. Scribble over every byte of the receive buffer, exactly as
        // reusing it for the next datagram - or returning it to a pool - would.
        datagram.AsSpan().Fill(0xFF);

        var plaintext = Convert.FromHexString(TlsQuicPacketProtectionTests.A3PlaintextHex);
        var expected = plaintext.AsSpan(A3AckFrameLength + A3CryptoHeaderLength, A3CryptoLength).ToArray();

        // The reassembler's own overlap rule is the assertion, and it is not a vacuous
        // one: Add compares each supplied byte against the byte it already stored and
        // throws TlsQuicTransportException on a mismatch. Re-adding the published CRYPTO
        // bytes at the same offset therefore passes only if the reassembler's copy still
        // holds them - if it had kept an alias, it would now be reading 0xFF.
        Assert.Empty(reassembler.Add(A3CryptoOffset, expected));
        Assert.Equal(A3CryptoLength, reassembler.DeliveredLength);

        // And the handler's own copy, taken inside the pass, is equally unaffected.
        Assert.Equal(expected, recorder.CryptoBytes);
    }

    [Fact]
    public void ARetainedFrameAliasesTheDecryptBufferAndIsNotSafeToKeep()
    {
        // The other half of the contract, stated as a witness rather than as prose:
        // the copy above is load-bearing BECAUSE the alias is real. A handler that
        // keeps the ReadOnlyMemory instead of copying it observes the receiver's
        // scratch buffer being reused - here by a second datagram - and the same
        // ReadOnlyMemory now reads different bytes. This is what "one synchronous pass
        // owns the buffer" is protecting against; a reader who doubts the rule should
        // see it fail.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        ReadOnlyMemory<byte> retained = default;
        var datagram = Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex);
        receiver.Receive(datagram, (in TlsQuicFrame frame, in TlsQuicReceivedPacket _) =>
        {
            if (frame.Type == TlsQuicFrameType.Crypto)
            {
                retained = frame.Data;
            }
        });

        var snapshot = retained.ToArray();

        // A second, different datagram at the same level. Its plaintext lands in the
        // same scratch.
        using var secondKeys = ServerInitialKeys();
        var second = BuildLongPacket(
            TlsQuicLongPacketType.Initial,
            Version1,
            destinationConnectionId: [],
            sourceConnectionId: Convert.FromHexString("F067A5502A4262B5"),
            token: [],
            fullPacketNumber: 2,
            truncatedPacketNumber: [0x00, 0x02],
            // Deliberately no larger than A.3's datagram: the scratch only grows, so a
            // bigger second datagram would allocate a fresh array and the stale alias
            // would keep reading the old one - which would make this test pass for the
            // wrong reason.
            plaintext: Enumerable.Repeat((byte)0x01, A3CryptoLength).ToArray(),
            keys: secondKeys);
        receiver.Receive(second, static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { });

        Assert.NotEqual(snapshot, retained.ToArray());
    }

    // ------------------------------------------------------- short header, 1-RTT

    [Fact]
    public void ShortHeaderOneRttPacketCarryingHandshakeDoneIsReadAndDispatched()
    {
        // RFC 9001 s4.1.2: "At the client, the handshake is considered confirmed when a
        // HANDSHAKE_DONE frame is received." HANDSHAKE_DONE is 0x1e and arrives in a
        // 1-RTT packet, which has a short header - so this path is the only trigger the
        // connection loop has for confirmation, and the reason task 6 is not long-header
        // only.
        var connectionId = Convert.FromHexString("B1B2B3B4B5B6B7B8B9BA");
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, connectionId.Length);
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.Application,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            keyPhase: false);

        // 0x1e HANDSHAKE_DONE, 0x01 PING, 0x00 PADDING. Three bytes, not one, and the
        // reason is a real floor rather than padding for its own sake: RFC 9001 s5.4.2
        // samples 16 bytes starting at pn_offset + 4, so a packet needs
        // pn_length + payload >= 4 before a sample exists at all. With a one-byte packet
        // number that is a three-byte payload - the smallest 1-RTT packet this vector
        // can be.
        var packet = BuildShortPacket(
            connectionId,
            keyPhase: false,
            spinBit: true,
            fullPacketNumber: 7,
            truncatedPacketNumber: [0x07],
            plaintext: [0x1e, 0x01, 0x00],
            keys: keys);

        var recorder = new Recorder(null);
        var result = receiver.Receive(packet, recorder.Handle);

        Assert.Equal(1, result.Processed);
        Assert.Null(result.CloseError);
        Assert.Equal(
            [TlsQuicFrameType.HandshakeDone, TlsQuicFrameType.Ping, TlsQuicFrameType.Padding],
            recorder.Frames.Select(f => f.Type));
        Assert.All(recorder.Frames, f => Assert.Equal(TlsQuicEncryptionLevel.Application, f.Level));
        Assert.All(recorder.Frames, f => Assert.Equal(7UL, f.PacketNumber));
        Assert.Equal(7UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Application));
    }

    [Theory]
    // Both directions of the comparison, because the guard is reachable by two paths
    // and one witness would pin only whichever the test happened to take: keys
    // installed at phase 0 meeting a packet announcing 1, and keys installed at phase 1
    // meeting a packet announcing 0.
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void AnAuthenticatedShortHeaderAnnouncingTheOtherKeyPhaseClosesTheConnection(
        bool installedPhase, bool packetPhase)
    {
        var connectionId = Convert.FromHexString("C1C2C3");
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, connectionId.Length);
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.Application,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            installedPhase);

        var packet = BuildShortPacket(
            connectionId,
            packetPhase,
            spinBit: false,
            fullPacketNumber: 3,
            truncatedPacketNumber: [0x03],
            plaintext: [0x1e, 0x01, 0x00],
            keys: keys);

        var recorder = new Recorder(null);
        var result = receiver.Receive(packet, recorder.Handle);

        // RFC 9000 s20.1: "KEY_UPDATE_ERROR (0x0e): An endpoint detected errors in
        // performing key updates". Not ignored, and not a discard - the packet
        // authenticated, so its Key Phase bit is the peer's own signed statement.
        Assert.Equal(TlsQuicTransportError.KeyUpdateError, result.CloseError);
        Assert.Equal(0, result.Processed);
        Assert.Empty(recorder.Frames);
    }

    [Fact]
    public void AKeyPhaseBitFlippedInTransitIsDiscardedRatherThanClosingTheConnection()
    {
        // The companion to the test above, and the reason the phase check sits AFTER
        // TryOpen. RFC 9000 s17.3.1 on the neighbouring reserved bits: "Discarding such
        // a packet after only removing header protection can expose the endpoint to
        // attacks". Byte 0 is inside RFC 9001 s5.3's associated data, so an off-path
        // attacker flipping the Key Phase bit breaks the tag - and this pipeline must
        // report that as a discard. Checking the bit before the AEAD would instead hand
        // that attacker a one-datagram connection kill.
        var connectionId = Convert.FromHexString("C1C2C3");
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, connectionId.Length);
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.Application,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            keyPhase: false);

        var packet = BuildShortPacket(
            connectionId,
            keyPhase: false,
            spinBit: false,
            fullPacketNumber: 3,
            truncatedPacketNumber: [0x03],
            plaintext: [0x1e, 0x01, 0x00],
            keys: keys);

        // Flip the Key Phase bit where it lies, on the wire, still under header
        // protection - which is exactly what an attacker can do and a peer cannot.
        packet[0] ^= 0x04;

        var recorder = new Recorder(null);
        var result = receiver.Receive(packet, recorder.Handle);

        Assert.Null(result.CloseError);
        Assert.Equal(1, result.Discarded);
        Assert.Equal(0, result.Processed);
    }

    [Theory]
    // RFC 9000 s17.2: long header reserved bits are "those with a mask of 0x0c".
    // s17.3.1: short header reserved bits are "those with a mask of 0x18". Each mask's
    // two bits are witnessed separately, so a mask narrowed to one bit is caught.
    [InlineData(false, (byte)0x04)]
    [InlineData(false, (byte)0x08)]
    [InlineData(true, (byte)0x08)]
    [InlineData(true, (byte)0x10)]
    public void NonZeroReservedBitsOnAnAuthenticatedPacketAreAProtocolViolation(
        bool shortHeader, byte reservedBit)
    {
        var connectionId = Convert.FromHexString("C1C2C3");
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, connectionId.Length);

        byte[] packet;
        if (shortHeader)
        {
            receiver.InstallReadKeys(
                TlsQuicEncryptionLevel.Application,
                TlsQuicPacketProtectionCipher.AesGcm,
                keys.CopyKey(), keys.CopyIv(),
                TlsQuicHeaderProtectionCipher.Aes, keys.CopyHeaderProtectionKey(),
                keyPhase: false);
            packet = BuildShortPacket(
                connectionId, keyPhase: false, spinBit: false,
                fullPacketNumber: 3, truncatedPacketNumber: [0x03],
                plaintext: [0x1e, 0x01, 0x00], keys, firstByteExtraBits: reservedBit);
        }
        else
        {
            InstallInitial(receiver, keys);
            packet = BuildLongPacket(
                TlsQuicLongPacketType.Initial, Version1,
                destinationConnectionId: connectionId, sourceConnectionId: [], token: [],
                fullPacketNumber: 3, truncatedPacketNumber: [0x03],
                plaintext: [0x01, 0x00, 0x00], keys, firstByteExtraBits: reservedBit);
        }

        var recorder = new Recorder(null);
        var result = receiver.Receive(packet, recorder.Handle);

        // The bit is set BEFORE sealing, so it is inside the associated data and the
        // packet authenticates with it - which is what makes this a connection error
        // and not a discard. "An endpoint MUST treat receipt of a packet that has a
        // non-zero value for these bits, after removing both packet and header
        // protection, as a connection error of type PROTOCOL_VIOLATION."
        Assert.Equal(TlsQuicTransportError.ProtocolViolation, result.CloseError);
        Assert.Empty(recorder.Frames);
    }

    [Fact]
    public void ReservedBitsFlippedInTransitAreDiscardedRatherThanClosingTheConnection()
    {
        // The companion the mutation sweep demanded. Setting the reserved bits BEFORE
        // sealing (the theory above) closes whether the check runs before or after the
        // AEAD, so it pins the mask but NOT the ordering - and the ordering is the whole
        // of RFC 9000 s17.2's "Discarding such a packet after only removing header
        // protection can expose the endpoint to attacks; see Section 9.5 of [QUIC-TLS]."
        //
        // Setting the bits in transit separates the two: byte 0 is inside RFC 9001
        // s5.3's associated data, so the tag now fails. A check placed before TryOpen
        // would close the connection on a bit any off-path attacker can flip.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var packet = BuildLongPacket(
            TlsQuicLongPacketType.Initial, Version1, [], [], [],
            fullPacketNumber: 3, truncatedPacketNumber: [0x03],
            plaintext: [0x01, 0x00, 0x00], keys);

        // 0x08 is one of the long header's two reserved bits and is inside RFC 9001
        // s5.4's long-header protection mask (0x0f), so this is a bit an attacker
        // reaches on the wire.
        packet[0] ^= 0x08;

        var recorder = new Recorder(null);
        var result = receiver.Receive(packet, recorder.Handle);

        Assert.Null(result.CloseError);
        Assert.Equal(1, result.Discarded);
        Assert.Equal(0, result.Processed);
    }

    [Fact]
    public void AKeyPhaseInstalledAtALongHeaderLevelIsNeverConsulted()
    {
        // The doc-comment on InstallReadKeys says the key phase is "Read only for short
        // headers: RFC 9000 s17.2 defines no Key Phase field on the long header". This
        // is that claim executed rather than asserted: keys installed at phase 1 at a
        // level that only ever carries long headers, and a perfectly ordinary Handshake
        // packet, which must still be processed.
        //
        // The bit the short header spends on Key Phase (0x04) is, in a long header, one
        // of s17.2's two reserved bits - so a receiver that consulted it here would be
        // reading a bit the RFC requires to be zero and closing every packet.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(), keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes, keys.CopyHeaderProtectionKey(),
            keyPhase: true);

        var packet = BuildLongPacket(
            TlsQuicLongPacketType.Handshake, Version1, [], [], null,
            fullPacketNumber: 4, truncatedPacketNumber: [0x04],
            plaintext: [0x01, 0x00, 0x00], keys);

        var recorder = new Recorder(null);
        var result = receiver.Receive(packet, recorder.Handle);

        Assert.Equal(1, result.Processed);
        Assert.Null(result.CloseError);
        Assert.Equal(4UL, recorder.Frames[0].PacketNumber);
    }

    // ------------------------------------- packet number decoding, hand-derived

    [Fact]
    public void RfcAppendixA3sWorkedDecodingExampleIsReproducedThroughThePipeline()
    {
        // RFC 9000 Appendix A.3: "if the highest successfully authenticated packet had
        // a packet number of 0xa82f30ea, then a packet containing a 16-bit value of
        // 0x9b32 will be decoded as 0xa82f9b32." Reaching that largest through the
        // receiver takes two hops, because a 4-byte packet number can only move the
        // largest by at most pn_hwin = 2^31 per packet: 0 -> 0x54178775 -> 0xa82f30ea.
        // Each hop's own decode is checked, so the climb is not a blind setup step.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallHandshake(receiver, keys);

        ReceiveHandshake(receiver, keys, 0x54178775, [0x54, 0x17, 0x87, 0x75]);
        Assert.Equal(0x54178775UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));

        ReceiveHandshake(receiver, keys, 0xa82f30ea, [0xa8, 0x2f, 0x30, 0xea]);
        Assert.Equal(0xa82f30eaUL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));

        var recorder = ReceiveHandshake(receiver, keys, 0xa82f9b32, [0x9b, 0x32]);
        Assert.Equal(0xa82f9b32UL, recorder.Frames[0].PacketNumber);
    }

    [Theory]
    // The lower half-window edge, derived by hand from Appendix A.3's pseudocode with
    // pn_nbits = 8, so pn_win = 256, pn_hwin = 128, pn_mask = 0xff.
    //
    // largest_pn = 1000, so expected_pn = 1001 and expected_pn & ~pn_mask = 768.
    // candidate_pn = 768 | truncated_pn, and the first branch fires when
    // candidate_pn <= expected_pn - pn_hwin = 873, i.e. when truncated_pn <= 105.
    //
    //   truncated 105 -> candidate 873, 873 <= 873 fires -> 873 + 256 = 1129.
    //   truncated 106 -> candidate 874, 874 <= 873 does not -> and 874 > 1129 does not
    //                    either -> 874.
    //
    // Both results are consistent with their own truncated bits (1129 & 0xff = 105,
    // 874 & 0xff = 106), so only the window rule tells them apart. A `<=` weakened to
    // `<` moves the first row to 873 and leaves the second alone.
    [InlineData((byte)105, 1129UL)]
    [InlineData((byte)106, 874UL)]
    public void TheLowerHalfWindowEdgeDecodesEitherSideOfTheBoundary(byte truncated, ulong expected)
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallHandshake(receiver, keys);

        ReceiveHandshake(receiver, keys, 1000, [0x00, 0x00, 0x03, 0xe8]);
        Assert.Equal(1000UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));

        var recorder = ReceiveHandshake(receiver, keys, expected, [truncated]);
        Assert.Equal(expected, recorder.Frames[0].PacketNumber);
    }

    [Theory]
    // The upper half-window edge, same pseudocode, chosen so the second branch is
    // reachable at all: candidate_pn > expected_pn + pn_hwin needs
    // truncated_pn > (expected_pn & pn_mask) + 128, which with an 8-bit field is only
    // possible when expected_pn mod 256 is small.
    //
    // largest_pn = 255, so expected_pn = 256, expected_pn & ~pn_mask = 256, and
    // expected_pn + pn_hwin = 384.
    //
    //   truncated 128 -> candidate 384, 384 > 384 does not fire -> 384.
    //   truncated 129 -> candidate 385, 385 > 384 fires, 385 >= 256 -> 385 - 256 = 129.
    //
    // Again both are consistent with their bits (384 & 0xff = 128, 129 & 0xff = 129).
    [InlineData((byte)128, 384UL)]
    [InlineData((byte)129, 129UL)]
    public void TheUpperHalfWindowEdgeDecodesEitherSideOfTheBoundary(byte truncated, ulong expected)
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallHandshake(receiver, keys);

        ReceiveHandshake(receiver, keys, 255, [0x00, 0x00, 0x00, 0xff]);
        Assert.Equal(255UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));

        var recorder = ReceiveHandshake(receiver, keys, expected, [truncated]);
        Assert.Equal(expected, recorder.Frames[0].PacketNumber);
    }

    [Theory]
    // ONE truncated byte, TWO largest-received values, TWO different full numbers -
    // the property that makes largest_pn an input rather than a formality. 0x80 = 128:
    //
    //   largest 255  -> expected 256,  base 256, 256|128 = 384, in window     -> 384.
    //   largest 1000 -> expected 1001, base 768, 768|128 = 896, in window     -> 896.
    //
    // A pipeline that ignored largest_pn, or read it from the wrong space, would have
    // to give the same answer twice.
    [InlineData(255UL, new byte[] { 0x00, 0x00, 0x00, 0xff }, 384UL)]
    [InlineData(1000UL, new byte[] { 0x00, 0x00, 0x03, 0xe8 }, 896UL)]
    public void OneTruncatedByteDecodesDifferentlyAgainstDifferentLargestReceived(
        ulong largest, byte[] largestOnTheWire, ulong expected)
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallHandshake(receiver, keys);

        ReceiveHandshake(receiver, keys, largest, largestOnTheWire);
        var recorder = ReceiveHandshake(receiver, keys, expected, [0x80]);
        Assert.Equal(expected, recorder.Frames[0].PacketNumber);
    }

    [Fact]
    public void TheUnderflowGuardHoldsWhenNothingHasBeenReceivedYet()
    {
        // The one edge reachable from a fresh connection, and the zero-versus-absent
        // case for largest_pn: nothing has been received, so largest_pn is 0 and
        // expected_pn is 1. pn_win = 256, pn_hwin = 128, expected_pn + pn_hwin = 129.
        //
        //   truncated 130 -> candidate 130, 130 > 129 fires, but 130 >= 256 does NOT,
        //                    so the subtraction is skipped -> 130.
        //
        // Without that second condition the result underflows past zero, the nonce
        // changes, and the packet fails its tag instead of decoding.
        //
        // The corresponding ceiling guard - candidate_pn < (1 << 62) - pn_win - is
        // UNREACHABLE through this receiver by construction, and deliberately has no
        // test here: largest_pn only advances by at most pn_hwin per authenticated
        // packet, so reaching 2^62 needs about 2^31 packets. It is
        // TlsQuicPacketNumber.Decode's own guard and TlsQuicPacketNumberTests owns it.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallHandshake(receiver, keys);

        Assert.Equal(0UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));
        var recorder = ReceiveHandshake(receiver, keys, 130, [130]);
        Assert.Equal(130UL, recorder.Frames[0].PacketNumber);
    }

    [Fact]
    public void EachNumberSpaceDecodesAgainstItsOwnLargestReceived()
    {
        // RFC 9000 s12.3: "Packet numbers in each space start at packet number 0", and
        // s17.1 decodes against "the largest packet number received in a successfully
        // authenticated packet" - in that space. A single connection-wide largest would
        // decode the Handshake packet below against 1000 instead of 0.
        //
        // truncated 0x80 = 128, 8-bit. Against the Handshake space's own largest of 0:
        // expected 1, base 0, candidate 128; 128 > 1 + 128 is false, so 128.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);
        InstallHandshake(receiver, keys);

        var initial = BuildLongPacket(
            TlsQuicLongPacketType.Initial, Version1, [], [], [],
            fullPacketNumber: 1000, truncatedPacketNumber: [0x00, 0x00, 0x03, 0xe8],
            plaintext: [0x01, 0x00, 0x00], keys);
        Assert.Equal(1, receiver.Receive(initial, static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { }).Processed);
        Assert.Equal(1000UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Initial));

        var recorder = ReceiveHandshake(receiver, keys, 128, [0x80]);
        Assert.Equal(128UL, recorder.Frames[0].PacketNumber);
        Assert.Equal(128UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));
        Assert.Equal(1000UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public void TheHandshakeAndApplicationSpacesAreSeparateFromEachOther()
    {
        // The Initial/Handshake split is pinned above; this is the other seam, and it
        // needs its own witness because collapsing Application onto Handshake leaves
        // that one green. RFC 9000 s12.3 names three spaces and puts 0-RTT and 1-RTT in
        // the third - not in the Handshake one.
        var connectionId = Convert.FromHexString("C1C2C3");
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, connectionId.Length);
        InstallHandshake(receiver, keys);
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.Application,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(), keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes, keys.CopyHeaderProtectionKey(),
            keyPhase: false);

        ReceiveHandshake(receiver, keys, 40, [0x00, 0x00, 0x00, 0x28]);

        var oneRtt = BuildShortPacket(
            connectionId, keyPhase: false, spinBit: false,
            fullPacketNumber: 6, truncatedPacketNumber: [0x06],
            plaintext: [0x1e, 0x01, 0x00], keys);
        var recorder = new Recorder(null);
        Assert.Equal(1, receiver.Receive(oneRtt, recorder.Handle).Processed);

        // A one-byte 0x06 decoded against the Handshake space's largest of 40 would be
        // 6 as well, so the packet number alone cannot separate the two spaces - the
        // two largests must.
        Assert.Equal(6UL, recorder.Frames[0].PacketNumber);
        Assert.Equal(40UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));
        Assert.Equal(6UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Application));
    }

    [Fact]
    public void AReorderedPacketDoesNotPullTheLargestReceivedBackDown()
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallHandshake(receiver, keys);

        ReceiveHandshake(receiver, keys, 20, [0x00, 0x00, 0x00, 0x14]);
        var recorder = ReceiveHandshake(receiver, keys, 9, [0x09]);

        Assert.Equal(9UL, recorder.Frames[0].PacketNumber);
        Assert.Equal(20UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));
    }

    [Fact]
    public void APacketThatFailsItsTagDoesNotAdvanceTheLargestReceived()
    {
        // RFC 9000 s17.1 says "the largest packet number received in a SUCCESSFULLY
        // AUTHENTICATED packet", so the update belongs after TryOpen, not after the
        // decode. Moving it earlier lets any forged datagram move the decoding window.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallHandshake(receiver, keys);

        var packet = BuildLongPacket(
            TlsQuicLongPacketType.Handshake, Version1, [], [], null,
            fullPacketNumber: 5000, truncatedPacketNumber: [0x00, 0x00, 0x13, 0x88],
            plaintext: [0x01, 0x00, 0x00], keys);
        packet[^1] ^= 0xFF;

        var result = receiver.Receive(packet, static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { });

        Assert.Equal(1, result.Discarded);
        Assert.Equal(0UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));
    }

    // ------------------------------------------------- the six malformed inputs

    [Fact]
    public void AnUnknownVersionIsDiscardedAndStopsTheWalk()
    {
        // RFC 9000 s17.2: "The header form bit, Destination and Source Connection ID
        // lengths, Destination and Source Connection ID fields, and Version fields of a
        // long header packet are version independent. The other fields in the first byte
        // are version specific." The Length field is not on that list, so an unknown
        // version leaves no boundary to trust for whatever follows it in the datagram -
        // unlike a decryption failure, where the Length field is intact.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var packet = BuildLongPacket(
            TlsQuicLongPacketType.Initial, UnknownVersion, [], [], [],
            fullPacketNumber: 1, truncatedPacketNumber: [0x01],
            plaintext: [0x01, 0x00, 0x00], keys);
        var datagram = packet.Concat(Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex)).ToArray();

        var recorder = new Recorder(null);
        var result = receiver.Receive(datagram, recorder.Handle);

        Assert.Equal(1, result.Discarded);
        Assert.Equal(0, result.Processed);
        Assert.Null(result.CloseError);
        Assert.Empty(recorder.Frames);
    }

    [Fact]
    public void AVersionNegotiationPacketIsReportedNotProcessed()
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        // RFC 9000 s17.2.1: Header Form 1, an unconstrained remainder of byte 0, a
        // Version field of 0, the two connection IDs, then Supported Versions.
        var datagram = new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08 }
            .Concat(Convert.FromHexString("F067A5502A4262B5"))
            .Concat(new byte[] { 0x00, 0x00, 0x00, 0x01 })
            .ToArray();

        var recorder = new Recorder(null);
        var result = receiver.Receive(datagram, recorder.Handle);

        Assert.Equal(TlsQuicUnprocessedPacket.VersionNegotiation, result.Unprocessed);
        Assert.Equal(0, result.Processed);
        Assert.Null(result.CloseError);
        Assert.Empty(recorder.Frames);
    }

    [Fact]
    public void ARetryPacketIsReportedNotProcessed()
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        // RFC 9000 s17.2.5: type 0x03, no Length, no Packet Number, a Retry Token, and
        // a 128-bit Retry Integrity Tag. Verifying that tag is task 9b's; this pipeline
        // must only decline to feed it to the AEAD.
        var datagram = new byte[] { 0xF0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08 }
            .Concat(Convert.FromHexString("F067A5502A4262B5"))
            .Concat(Convert.FromHexString("7465737420746F6B656E"))
            .Concat(Enumerable.Repeat((byte)0xAB, 16))
            .ToArray();

        var recorder = new Recorder(null);
        var result = receiver.Receive(datagram, recorder.Handle);

        Assert.Equal(TlsQuicUnprocessedPacket.Retry, result.Unprocessed);
        Assert.Equal(0, result.Processed);
        Assert.Null(result.CloseError);
        Assert.Empty(recorder.Frames);
    }

    [Fact]
    public void APacketThatFailsTheAeadIsDiscardedSilentlyAndTheRestOfTheDatagramIsStillProcessed()
    {
        // RFC 9000 s12.2, quoted whole because this is the clause: "Every QUIC packet
        // that is coalesced into a single UDP datagram is separate and complete. The
        // receiver of coalesced QUIC packets MUST individually process each QUIC packet
        // and separately acknowledge them, as if they were received as the payload of
        // different UDP datagrams. For example, if decryption fails (because the keys
        // are not available or for any other reason), the receiver MAY either discard or
        // buffer the packet for later processing and MUST attempt to process the
        // remaining packets."
        //
        // So a failed decrypt is not an error, and it does not end the walk. Both halves
        // are asserted here, and only a coalesced datagram can assert the second.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);
        InstallHandshake(receiver, keys);

        var broken = BuildLongPacket(
            TlsQuicLongPacketType.Initial, Version1, [], [], [],
            fullPacketNumber: 4, truncatedPacketNumber: [0x04],
            plaintext: [0x01, 0x00, 0x00], keys);
        broken[^1] ^= 0xFF;

        var good = BuildLongPacket(
            TlsQuicLongPacketType.Handshake, Version1, [], [], null,
            fullPacketNumber: 9, truncatedPacketNumber: [0x09],
            plaintext: [0x01, 0x00, 0x00], keys);

        var recorder = new Recorder(null);
        var result = receiver.Receive(broken.Concat(good).ToArray(), recorder.Handle);

        Assert.Null(result.CloseError);
        Assert.Equal(1, result.Discarded);
        Assert.Equal(1, result.Processed);
        Assert.Equal(9UL, Assert.Single(recorder.Frames, f => f.Type == TlsQuicFrameType.Ping).PacketNumber);
        Assert.Equal(0UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Initial));
    }

    [Theory]
    // Truncation at three places that reach three different rejections, so no row
    // pins only whichever check happens to fire first: 8 bytes cannot hold the long
    // header at all, 30 cuts inside the packet-number-protection sample, and one byte
    // short of the full packet leaves the AEAD a payload it cannot authenticate.
    [InlineData(8)]
    [InlineData(30)]
    [InlineData(-1)]
    public void ATruncatedDatagramIsHandledWithoutThrowing(int length)
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var full = Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex);
        var datagram = full[..(length < 0 ? full.Length - 1 : length)];

        var recorder = new Recorder(null);
        var result = receiver.Receive(datagram, recorder.Handle);

        Assert.Equal(0, result.Processed);
        Assert.Null(result.CloseError);
        Assert.Empty(recorder.Frames);
        Assert.Equal(0UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public void TrailingBytesThatAreNotAPacketLeaveTheRealPacketProcessed()
    {
        // A.3's packet is complete and its Length field delimits it, so the trailing
        // garbage is a separate "packet" as far as s12.2's walk is concerned - and one
        // whose header cannot be parsed. The real packet must still be processed.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var datagram = Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex)
            .Concat(new byte[] { 0xC0, 0xFF })
            .ToArray();

        var reassembler = new TlsQuicCryptoStreamReassembler(4096);
        var recorder = new Recorder(reassembler);
        var result = receiver.Receive(datagram, recorder.Handle);

        Assert.Equal(1, result.Processed);
        Assert.Null(result.CloseError);
        Assert.Equal(A3CryptoLength, reassembler.DeliveredLength);
    }

    // ------------------------------------------------------------ frame handling

    [Fact]
    public void APacketWithNoKeysAtItsLevelIsDiscarded()
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);
        Assert.False(receiver.HasReadKeys(TlsQuicEncryptionLevel.Handshake));

        var packet = BuildLongPacket(
            TlsQuicLongPacketType.Handshake, Version1, [], [], null,
            fullPacketNumber: 1, truncatedPacketNumber: [0x01],
            plaintext: [0x01, 0x00, 0x00], keys);

        var result = receiver.Receive(packet, static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { });

        Assert.Equal(1, result.Discarded);
        Assert.Null(result.CloseError);
    }

    [Fact]
    public void AZeroRttPacketIsReadAtTheEarlyDataLevelAndNotAtTheApplicationLevel()
    {
        // RFC 9000 s17.2 Table 5 maps type 0x01 to 0-RTT, and RFC 9001 s4.1.4 makes that
        // its own encryption level with its own keys - separate from 1-RTT, even though
        // s12.3 puts both in one packet number space. So Application keys must not open
        // a 0-RTT packet. A client never receives one, but the server role task 7 wraps
        // does, which is what makes this reachable rather than theoretical.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.Application,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(), keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes, keys.CopyHeaderProtectionKey(),
            keyPhase: false);
        Assert.False(receiver.HasReadKeys(TlsQuicEncryptionLevel.EarlyData));

        var packet = BuildLongPacket(
            TlsQuicLongPacketType.ZeroRtt, Version1, [], [], null,
            fullPacketNumber: 1, truncatedPacketNumber: [0x01],
            plaintext: [0x01, 0x00, 0x00], keys);

        var recorder = new Recorder(null);
        var result = receiver.Receive(packet, recorder.Handle);

        Assert.Equal(1, result.Discarded);
        Assert.Equal(0, result.Processed);
        Assert.Null(result.CloseError);
        Assert.Empty(recorder.Frames);

        // And the same packet IS read once its own level has keys - so the assertion
        // above is about which level was selected, not about the packet being unreadable.
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.EarlyData,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(), keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes, keys.CopyHeaderProtectionKey(),
            keyPhase: false);
        Assert.Equal(1, receiver.Receive(packet, recorder.Handle).Processed);
        Assert.Equal(TlsQuicEncryptionLevel.EarlyData, recorder.Frames[0].Level);

        // s12.3: "0-RTT and 1-RTT data exist in the same packet number space", so the
        // 0-RTT packet's number lands in the space the Application level reports.
        Assert.Equal(1UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Application));
    }

    [Fact]
    public void DiscardedKeysMakeTheirLevelUnreadableAgain()
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);
        receiver.DiscardReadKeys(TlsQuicEncryptionLevel.Initial);
        Assert.False(receiver.HasReadKeys(TlsQuicEncryptionLevel.Initial));

        var datagram = Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex);
        var result = receiver.Receive(datagram, static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { });

        Assert.Equal(1, result.Discarded);
        Assert.Equal(0, result.Processed);
    }

    [Fact]
    public void AnAuthenticatedPacketWithAZeroLengthPayloadIsAProtocolViolation()
    {
        // RFC 9000 s12.4: "The payload of a packet that contains frames MUST contain at
        // least one frame... An endpoint MUST treat receipt of a packet containing no
        // frames as a connection error of type PROTOCOL_VIOLATION."
        //
        // Zero-length is not the same as absent: the packet still carries its 16-byte
        // tag and still authenticates, so this arrives as a real, decrypted, empty
        // payload. A four-byte packet number is required and not decorative - RFC 9001
        // s5.4.2 needs pn_length + payload >= 4 for a header protection sample to exist,
        // and with an empty payload the packet number has to supply all four.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var packet = BuildLongPacket(
            TlsQuicLongPacketType.Initial, Version1, [], [], [],
            fullPacketNumber: 1, truncatedPacketNumber: [0x00, 0x00, 0x00, 0x01],
            plaintext: [], keys);

        var recorder = new Recorder(null);
        var result = receiver.Receive(packet, recorder.Handle);

        Assert.Equal(TlsQuicTransportError.ProtocolViolation, result.CloseError);
        Assert.Empty(recorder.Frames);
    }

    [Fact]
    public void AFrameNotPermittedInThisPacketTypeIsAProtocolViolation()
    {
        // RFC 9000 s12.4: "An endpoint MUST treat receipt of a frame in a packet type
        // that is not permitted as a connection error of type PROTOCOL_VIOLATION."
        // 0x08 is STREAM, whose Table 3 row permits 0-RTT and 1-RTT only.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var packet = BuildLongPacket(
            TlsQuicLongPacketType.Initial, Version1, [], [], [],
            fullPacketNumber: 1, truncatedPacketNumber: [0x01],
            plaintext: [0x08, 0x04, 0x41, 0x42], keys);

        var recorder = new Recorder(null);
        var result = receiver.Receive(packet, recorder.Handle);

        Assert.Equal(TlsQuicTransportError.ProtocolViolation, result.CloseError);
        Assert.Empty(recorder.Frames);
    }

    [Fact]
    public void AnUnknownFrameTypeIsAFrameEncodingErrorNotAProtocolViolation()
    {
        // RFC 9000 s12.4: "An endpoint MUST treat the receipt of a frame of unknown type
        // as a connection error of type FRAME_ENCODING_ERROR." TlsQuicFrames.TryReadFrame
        // resolves which of s12.4's codes a malformation maps to, and this pipeline
        // reports its answer rather than flattening everything to PROTOCOL_VIOLATION -
        // which is also why TlsQuicFrameLegality.Permits can never see an unknown type
        // here. 0x1f has no row.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var packet = BuildLongPacket(
            TlsQuicLongPacketType.Initial, Version1, [], [], [],
            fullPacketNumber: 1, truncatedPacketNumber: [0x01],
            plaintext: [0x01, 0x1f, 0x00], keys);

        var recorder = new Recorder(null);
        var result = receiver.Receive(packet, recorder.Handle);

        Assert.Equal(TlsQuicTransportError.FrameEncodingError, result.CloseError);

        // The PING before it was already dispatched: s12.2 processes a packet's frames
        // in order and the error is detected where it lies.
        Assert.Equal([TlsQuicFrameType.Ping], recorder.Frames.Select(f => f.Type));
    }

    [Fact]
    public void EveryPacketInACoalescedDatagramIsProcessedSeparately()
    {
        // s12.2: "The receiver of coalesced QUIC packets MUST individually process each
        // QUIC packet and separately acknowledge them, as if they were received as the
        // payload of different UDP datagrams." Different levels, different spaces,
        // different packet numbers, one datagram.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);
        InstallHandshake(receiver, keys);

        var datagram = Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex)
            .Concat(BuildLongPacket(
                TlsQuicLongPacketType.Handshake, Version1, [], [], null,
                fullPacketNumber: 3, truncatedPacketNumber: [0x03],
                plaintext: [0x01, 0x00, 0x00], keys))
            .ToArray();

        var reassembler = new TlsQuicCryptoStreamReassembler(4096);
        var recorder = new Recorder(reassembler);
        var result = receiver.Receive(datagram, recorder.Handle);

        Assert.Equal(2, result.Processed);
        Assert.Equal(0, result.Discarded);
        Assert.Equal(1UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(3UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));
        // A.3's two frames at Initial, then the appended packet's PING and its two
        // PADDING bytes at Handshake - 2 + 3 = 5, which is the whole list.
        Assert.Equal(
            [
                TlsQuicEncryptionLevel.Initial, TlsQuicEncryptionLevel.Initial,
                TlsQuicEncryptionLevel.Handshake, TlsQuicEncryptionLevel.Handshake,
                TlsQuicEncryptionLevel.Handshake,
            ],
            recorder.Frames.Select(f => f.Level));
        Assert.Equal(A3CryptoLength, reassembler.DeliveredLength);
    }

    [Fact]
    public void AShortHeaderEndsTheWalkEvenWhenBytesFollowIt()
    {
        // s12.2: "A packet with a short header does not include a length, so it can only
        // be the last packet included in a UDP datagram." So the Handshake packet
        // appended below is payload of the 1-RTT packet, not a packet - and it must not
        // be processed as one. The Handshake keys ARE installed, so only the walk's
        // shape can be what stops it.
        var connectionId = Convert.FromHexString("C1C2C3");
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, connectionId.Length);
        InstallHandshake(receiver, keys);
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.Application,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(), keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes, keys.CopyHeaderProtectionKey(),
            keyPhase: false);

        var trailing = BuildLongPacket(
            TlsQuicLongPacketType.Handshake, Version1, [], [], null,
            fullPacketNumber: 3, truncatedPacketNumber: [0x03],
            plaintext: [0x01, 0x00, 0x00], keys);

        var oneRtt = BuildShortPacket(
            connectionId, keyPhase: false, spinBit: false,
            fullPacketNumber: 5, truncatedPacketNumber: [0x05],
            plaintext: [0x1e, 0x01, 0x00], keys);

        // Appending the Handshake packet AFTER a complete 1-RTT packet is the whole
        // point: a short header has no Length field, so those bytes are not a second
        // packet - they are part of this one's ciphertext, and the tag therefore fails.
        // The 1-RTT packet is discarded, and the Handshake packet is never seen at all
        // even though its keys are installed and its own bytes are perfectly valid.
        var recorder = new Recorder(null);
        var result = receiver.Receive(oneRtt.Concat(trailing).ToArray(), recorder.Handle);

        Assert.Equal(0, result.Processed);
        Assert.Equal(1, result.Discarded);
        Assert.Null(result.CloseError);
        Assert.Empty(recorder.Frames);
        Assert.Equal(0UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Handshake));

        // And the same Handshake packet on its own IS processed, so the assertion above
        // is about the walk stopping, not about that packet being unreadable.
        Assert.Equal(1, receiver.Receive(trailing, static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { }).Processed);
    }

    [Fact]
    public void AnEmptyDatagramIsHandledWithoutThrowing()
    {
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var result = receiver.Receive(Array.Empty<byte>(), static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { });

        Assert.Equal(0, result.Processed);
        Assert.Equal(0, result.Discarded);
        Assert.Null(result.CloseError);
    }

    // ------------------------------------------------------------------ helpers

    // ------------------------------------------------- the scratch buffer's contents

    [Fact]
    public void GrowingTheScratchZeroesThePlaintextItAbandons()
    {
        // The scratch is replaced, not resized, when a bigger datagram arrives - and the
        // outgoing array holds the PREVIOUS datagram's decrypted CRYPTO plaintext, which
        // is TLS handshake material. Dispose already zeroes it and says why; this is the
        // other place the same array is let go.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var scratch = CaptureScratch(
            receiver, Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex));

        // Growth needs no keys and no valid packet: the resize is at the top of Receive,
        // before a single byte is parsed or authenticated. One larger datagram from
        // anyone on the path is the entire trigger, which is what makes the un-zeroed
        // abandon peer-driven rather than theoretical.
        receiver.Receive(
            new byte[scratch.Length + 1], static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { });

        Assert.DoesNotContain(scratch, b => b != 0);
    }

    [Fact]
    public void DisposeZeroesTheDecryptedPlaintextLeftInTheScratch()
    {
        using var keys = ServerInitialKeys();
        var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var scratch = CaptureScratch(
            receiver, Convert.FromHexString(TlsQuicPacketProtectionTests.A3FullProtectedPacketHex));

        receiver.Dispose();

        Assert.DoesNotContain(scratch, b => b != 0);
    }

    [Fact]
    public void ACoalescedPacketWhoseKeysHaveNotArrivedIsCountedApartFromOneThatSimplyDoesNotOpen()
    {
        // THE COALESCING STALL, AS A SHAPE. RFC 9000 s12.2: "Receivers MUST be able to
        // process coalesced packets", and "if decryption fails (because the keys are not
        // available or for any other reason), the receiver MAY either discard or buffer
        // the packet for later processing and MUST attempt to process the remaining
        // packets." This receiver discards, and until now Discarded fused the clause's
        // two halves into one number.
        //
        // The halves are not the same fault. A server flight is an Initial packet
        // followed by a Handshake packet in one datagram, and the Handshake keys come
        // out of the Initial packet's own CRYPTO payload - which only the TLS engine can
        // derive, asynchronously, after this synchronous pass has returned. So the
        // Handshake packet meets no keys and is discarded, and the outcome is
        // PROCESSED=1, DISCARDED=1: a caller guard written as "Processed == 0" never
        // fires on it, and the handshake stalls with every packet accounted for. That is
        // what DiscardedForMissingKeys makes visible, and it is why Receive's remarks
        // make splitting a permanent caller responsibility rather than a workaround.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        // Deliberately NOT InstallHandshake: this is the flight arriving before its keys.
        var initial = BuildLongPacket(
            TlsQuicLongPacketType.Initial, Version1, [], [], [],
            fullPacketNumber: 0, truncatedPacketNumber: [0x00],
            plaintext: [0x01, 0x00, 0x00], keys);
        var handshake = BuildLongPacket(
            TlsQuicLongPacketType.Handshake, Version1, [], [], null,
            fullPacketNumber: 0, truncatedPacketNumber: [0x00],
            plaintext: [0x01, 0x00, 0x00], keys);

        byte[] flight = [.. initial, .. handshake];
        var stalled = receiver.Receive(flight, new Recorder(null).Handle);

        Assert.Equal(1, stalled.Processed);
        Assert.Equal(1, stalled.Discarded);
        Assert.Equal(1, stalled.DiscardedForMissingKeys);

        // THE OTHER HALF OF THE CLAUSE, so the new counter cannot just be an alias of
        // Discarded. Same packet, keys now installed, one ciphertext byte flipped: the
        // AEAD fails, which is what every stray, forged or replayed datagram produces
        // and which no amount of waiting fixes. Discarded counts it; DiscardedForMissing
        // Keys must not.
        InstallHandshake(receiver, keys);
        handshake[^1] ^= 0xFF;

        var forged = receiver.Receive(handshake, new Recorder(null).Handle);

        Assert.Equal(0, forged.Processed);
        Assert.Equal(1, forged.Discarded);
        Assert.Equal(0, forged.DiscardedForMissingKeys);
    }

    // Reaches the receiver's scratch the only way a caller ever can, and with no
    // test-only accessor on the production type: a dispatched frame's ReadOnlyMemory IS
    // a window onto that buffer - which is exactly what
    // ARetainedFrameAliasesTheDecryptBufferAndIsNotSafeToKeep exists to demonstrate - so
    // the array behind the window is the array under test.
    private static byte[] CaptureScratch(TlsQuicPacketReceiver receiver, byte[] datagram)
    {
        byte[]? scratch = null;
        var result = receiver.Receive(datagram, (in TlsQuicFrame frame, in TlsQuicReceivedPacket _) =>
        {
            if (frame.Type == TlsQuicFrameType.Crypto
                && MemoryMarshal.TryGetArray(frame.Data, out var segment)
                && segment.Array is not null)
            {
                scratch = segment.Array;
            }
        });

        Assert.Equal(1, result.Processed);
        Assert.NotNull(scratch);

        // The precondition both callers depend on. Without it each would pass vacuously
        // against the mutant that deletes the zeroing, because a never-written buffer is
        // already all zeroes - a false witness rather than a witness.
        Assert.Contains(scratch, b => b != 0);
        return scratch;
    }

    // ---------------------------------------------- s12.2's connection ID, and the ctor

    [Theory]
    [InlineData(true, 2, 0)]
    [InlineData(false, 1, 1)]
    public void ASubsequentPacketWithADifferentConnectionIdIsIgnored(
        bool sameConnectionId, int expectedProcessed, int expectedDiscarded)
    {
        // RFC 9000 s12.2: "Receivers SHOULD ignore any subsequent packets with a
        // different Destination Connection ID than the first packet in the datagram."
        // Task 5 closed the sender half of the same paragraph; this is the receiver half.
        //
        // The two rows differ in ONE byte sequence - the second packet's Destination
        // Connection ID - so nothing else can be what moves the counts. Both packets
        // authenticate under the same keys either way, because the connection ID sits
        // inside the AEAD's associated data and Protect seals whatever header was built;
        // the discard is this check's, not the tag's.
        byte[] first = [0xAA, 0xBB, 0xCC, 0xDD];
        byte[] second = sameConnectionId ? first : [0x11, 0x22, 0x33, 0x44];

        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var datagram = BuildLongPacket(
                TlsQuicLongPacketType.Initial, Version1, first, [], [],
                fullPacketNumber: 1, truncatedPacketNumber: [0x01],
                plaintext: [0x01, 0x00, 0x00], keys)
            .Concat(BuildLongPacket(
                TlsQuicLongPacketType.Initial, Version1, second, [], [],
                fullPacketNumber: 2, truncatedPacketNumber: [0x02],
                plaintext: [0x01, 0x00, 0x00], keys))
            .ToArray();

        var result = receiver.Receive(datagram, static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { });

        Assert.Equal(expectedProcessed, result.Processed);
        Assert.Equal(expectedDiscarded, result.Discarded);
        Assert.Null(result.CloseError);

        // "Ignore", not "close": s12.2 gives this no error code, and the largest received
        // must not have moved for the packet that was ignored.
        Assert.Equal(sameConnectionId ? 2UL : 1UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Initial));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(TlsQuicPacketHeader.MaximumConnectionIdLength + 1)]
    public void AConnectionIdLengthOutsideTheVersion1RangeIsRejectedAtConstruction(int length)
    {
        // The only throw this class has, and the standing rule wants a witness for every
        // reachable guard. Subsystem B varies this length per imitated client, so by
        // provenance it is caller input and always reachable. RFC 9000 s17.2: "In QUIC
        // version 1, this value MUST NOT exceed 20 bytes."
        var exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicPacketReceiver(Version1, length));
        Assert.Equal("destinationConnectionIdLength", exception.ParamName);

        // Both in-range edges, so the bound is pinned as a bound rather than as a
        // direction: widening or narrowing it by one fails here.
        using var zero = new TlsQuicPacketReceiver(Version1, 0);
        using var maximum = new TlsQuicPacketReceiver(
            Version1, TlsQuicPacketHeader.MaximumConnectionIdLength);
    }

    private sealed record Dispatched(
        TlsQuicFrameType Type,
        TlsQuicEncryptionLevel Level,
        ulong PacketNumber,
        ulong Offset,
        int DataLength,
        ulong LargestAcknowledged,
        ulong AckDelay,
        ulong AckRangeCount,
        ulong FirstAckRange);

    // The handler every test shares. It is the caller's side of the lifetime contract:
    // it COPIES CRYPTO payload into the reassembler inside the pass and keeps only
    // value types otherwise. Nothing here retains a ReadOnlyMemory.
    private sealed class Recorder(TlsQuicCryptoStreamReassembler? reassembler)
    {
        internal List<Dispatched> Frames { get; } = [];
        internal byte[] CryptoBytes { get; private set; } = [];

        internal void Handle(in TlsQuicFrame frame, in TlsQuicReceivedPacket packet)
        {
            Frames.Add(new Dispatched(
                frame.Type, packet.Level, packet.PacketNumber,
                frame.Offset, frame.Data.Length,
                frame.LargestAcknowledged, frame.AckDelay, frame.AckRangeCount, frame.FirstAckRange));

            if (frame.Type == TlsQuicFrameType.Crypto)
            {
                CryptoBytes = frame.Data.ToArray();
                reassembler?.Add(frame.Offset, frame.Data.Span);
            }
        }
    }

    private static TlsQuicPacketProtectionKeys ServerInitialKeys()
    {
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, Convert.FromHexString(AppendixAConnectionIdHex));
        return secrets.DeriveServerPacketProtectionKeys(TlsQuicVersion.Version1);
    }

    private static void InstallInitial(TlsQuicPacketReceiver receiver, TlsQuicPacketProtectionKeys keys) =>
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.Initial,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(), keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes, keys.CopyHeaderProtectionKey(),
            keyPhase: false);

    // The Handshake level reuses A.3's server Initial key material on purpose. These
    // tests are about packet number spaces and dispatch, not key derivation, and
    // sharing the bytes makes it impossible for a level mix-up to be masked by a
    // decrypt failure that looks like the same discard.
    private static void InstallHandshake(TlsQuicPacketReceiver receiver, TlsQuicPacketProtectionKeys keys) =>
        receiver.InstallReadKeys(
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(), keys.CopyIv(),
            TlsQuicHeaderProtectionCipher.Aes, keys.CopyHeaderProtectionKey(),
            keyPhase: false);

    private static Recorder ReceiveHandshake(
        TlsQuicPacketReceiver receiver,
        TlsQuicPacketProtectionKeys keys,
        ulong fullPacketNumber,
        byte[] truncatedPacketNumber)
    {
        var packet = BuildLongPacket(
            TlsQuicLongPacketType.Handshake, Version1, [], [], null,
            fullPacketNumber, truncatedPacketNumber,
            plaintext: [0x01, 0x00, 0x00], keys);

        var recorder = new Recorder(null);
        var result = receiver.Receive(packet, recorder.Handle);

        // The AEAD is the oracle: the nonce is built from the DECODED packet number, so
        // a wrong decode fails the tag here rather than producing a wrong PacketNumber.
        Assert.Equal(1, result.Processed);
        return recorder;
    }

    // RFC 9000 s17.2, field by field, so nothing about the layout is taken from
    // TlsQuicPacketHeader.WriteLongHeader - the reader under test and the writer would
    // otherwise be checking each other. `token` is null for the types that have no
    // Token field (s17.2.4's Handshake packet).
    // ------------------------------------------------------------------------
    // RFC 9000 s12.3: duplicate suppression.
    // ------------------------------------------------------------------------

    [Fact]
    public void APacketNumberSeenTwiceInOneDatagramIsProcessedOnce()
    {
        // s12.3: "A receiver MUST discard a newly unprotected packet unless it is certain that
        // it has not processed another packet with the same packet number from the same packet
        // number space.  Duplicate suppression MUST happen after removing packet protection
        // for the reasons described in Section 9.5 of [QUIC-TLS]."
        //
        // THE TWO PACKETS ARE BYTE-IDENTICAL, which is what a duplicated datagram delivers.
        // Both authenticate - the AEAD has no memory - so the second is refused by this rule
        // and by nothing else.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var one = BuildLongPacket(
            TlsQuicLongPacketType.Initial, Version1, [0xAA, 0xBB], [], [],
            fullPacketNumber: 1, truncatedPacketNumber: [0x01],
            plaintext: [0x01, 0x00, 0x00], keys);

        var frames = 0;
        var result = receiver.Receive(
            one.Concat(one).ToArray(),
            (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => frames++);

        Assert.Equal(1, result.Processed);
        Assert.Equal(1, result.Discarded);
        Assert.Equal(1, receiver.DuplicatesSuppressed);
        Assert.Null(result.CloseError);

        // NOT A DECRYPT FAILURE, which Discarded alone cannot say. The copy opened cleanly;
        // it was refused afterwards.
        Assert.Equal(0, result.DiscardedForMissingKeys);

        // AND ITS FRAMES NEVER REACHED THE HANDLER. The plaintext is one PING (0x01) and two
        // PADDING (0x00), so ONE packet dispatches three frames and six would mean the
        // duplicate was walked as well. That second walk is the consequence the rule exists to
        // prevent - a duplicated ACK re-read as a fresh one, s12.3's own reason - and it is
        // what this count measures rather than the discard itself.
        Assert.Equal(3, frames);
    }

    [Theory]
    [InlineData(73UL, 2, 0)]
    [InlineData(72UL, 1, 1)]
    public void AReorderedPacketIsAcceptedInsideTheWindowAndDroppedBelowIt(
        ulong reordered, int expectedProcessed, int expectedDiscarded)
    {
        // THE WINDOW'S EDGE, BOTH SIDES OF IT, AND THE ROWS DIFFER BY ONE. The window is 128
        // packets below the highest processed, so against a highest of 200: number 73 is 127
        // back and inside it, number 72 is 128 back and outside. A window written with the
        // wrong comparison moves exactly one of these rows.
        //
        // s12.3 SANCTIONS THE CEILING: "the data required for detecting duplicates can be
        // limited by maintaining a minimum packet number below which all packets are
        // immediately dropped". Neither number has been seen before, so the second row is the
        // rule being conservative rather than correct - it drops a packet it cannot be certain
        // about, which is the direction s12.3's "unless it is certain" points.
        //
        // A FOUR-BYTE PACKET NUMBER IS WHAT MAKES THE REORDERING EXPRESSIBLE. s17.1 decodes a
        // truncated number to the candidate nearest the largest received, so one byte cannot
        // name 73 when 200 is already in hand - it would decode to 329.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var datagram = BuildLongPacket(
                TlsQuicLongPacketType.Initial, Version1, [0xAA, 0xBB], [], [],
                fullPacketNumber: 200, truncatedPacketNumber: [0x00, 0x00, 0x00, 0xC8],
                plaintext: [0x01, 0x00, 0x00], keys)
            .Concat(BuildLongPacket(
                TlsQuicLongPacketType.Initial, Version1, [0xAA, 0xBB], [], [],
                fullPacketNumber: reordered,
                truncatedPacketNumber:
                [
                    0x00, 0x00, (byte)(reordered >> 8), (byte)reordered,
                ],
                plaintext: [0x01, 0x00, 0x00], keys))
            .ToArray();

        var result = receiver.Receive(
            datagram, static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { });

        Assert.Equal(expectedProcessed, result.Processed);
        Assert.Equal(expectedDiscarded, result.Discarded);
        Assert.Equal(expectedDiscarded, receiver.DuplicatesSuppressed);
        Assert.Null(result.CloseError);

        // s17.1's largest is unmoved either way - it is defined over "a successfully
        // authenticated packet" and neither of these is larger than 200.
        Assert.Equal(200UL, receiver.LargestReceived(TlsQuicEncryptionLevel.Initial));
    }

    [Fact]
    public void PacketNumberZeroIsNotMistakenForAnEmptyWindow()
    {
        // THE FLAG THE WINDOW CARRIES, AND WHY IT EXISTS. The highest-processed number starts
        // at zero, and zero is a legal packet number - RFC 9000 s17.1 starts every space at 0 -
        // so a window that inferred "nothing processed yet" from a zero would discard the very
        // first packet of every connection as a duplicate of itself.
        //
        // MEASURED AS ACCEPTED, NOT AS not-discarded: a first packet counted into Processed is
        // the whole handshake's first step.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);

        var result = receiver.Receive(
            BuildLongPacket(
                TlsQuicLongPacketType.Initial, Version1, [0xAA, 0xBB], [], [],
                fullPacketNumber: 0, truncatedPacketNumber: [0x00],
                plaintext: [0x01, 0x00, 0x00], keys),
            static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { });

        Assert.Equal(1, result.Processed);
        Assert.Equal(0, result.Discarded);
        Assert.Equal(0, receiver.DuplicatesSuppressed);
    }

    [Fact]
    public void TheSamePacketNumberInTwoSpacesIsNotADuplicate()
    {
        // s12.3 scopes the rule to "the same packet number space", and s12.2's three spaces
        // number independently - so an Initial 1 and a Handshake 1 are different packets that
        // happen to share a number. A single window shared across spaces would discard the
        // second and stall the handshake, which is why the window is an array.
        using var keys = ServerInitialKeys();
        using var receiver = new TlsQuicPacketReceiver(Version1, destinationConnectionIdLength: 0);
        InstallInitial(receiver, keys);
        InstallHandshake(receiver, keys);

        var datagram = BuildLongPacket(
                TlsQuicLongPacketType.Initial, Version1, [0xAA, 0xBB], [], [],
                fullPacketNumber: 1, truncatedPacketNumber: [0x01],
                plaintext: [0x01, 0x00, 0x00], keys)
            .Concat(BuildLongPacket(
                TlsQuicLongPacketType.Handshake, Version1, [0xAA, 0xBB], [], null,
                fullPacketNumber: 1, truncatedPacketNumber: [0x01],
                plaintext: [0x01, 0x00, 0x00], keys))
            .ToArray();

        var result = receiver.Receive(
            datagram, static (in TlsQuicFrame _, in TlsQuicReceivedPacket _) => { });

        Assert.Equal(2, result.Processed);
        Assert.Equal(0, result.Discarded);
        Assert.Equal(0, receiver.DuplicatesSuppressed);
    }

    private static byte[] BuildLongPacket(
        TlsQuicLongPacketType type,
        uint version,
        byte[] destinationConnectionId,
        byte[] sourceConnectionId,
        byte[]? token,
        ulong fullPacketNumber,
        byte[] truncatedPacketNumber,
        byte[] plaintext,
        TlsQuicPacketProtectionKeys keys,
        byte firstByteExtraBits = 0)
    {
        var header = new List<byte>
        {
            // Header Form (0x80) | Fixed Bit (0x40) | Long Packet Type << 4 |
            // Packet Number Length - 1. Reserved bits (0x0c) left clear unless a test
            // asks for them.
            (byte)(0x80 | 0x40 | ((int)type << 4) | (truncatedPacketNumber.Length - 1) | firstByteExtraBits),
            (byte)(version >> 24), (byte)(version >> 16), (byte)(version >> 8), (byte)version,
            (byte)destinationConnectionId.Length,
        };
        header.AddRange(destinationConnectionId);
        header.Add((byte)sourceConnectionId.Length);
        header.AddRange(sourceConnectionId);
        if (token is not null)
        {
            header.AddRange(Varint((ulong)token.Length));
            header.AddRange(token);
        }

        // s17.2: "The length includes both the Packet Number and Payload fields", and
        // the payload on the wire is the AEAD output, 16 bytes longer than the plaintext.
        header.AddRange(Varint((ulong)(truncatedPacketNumber.Length + plaintext.Length + 16)));

        var packetNumberOffset = header.Count;
        header.AddRange(truncatedPacketNumber);
        return Protect(header, packetNumberOffset, fullPacketNumber, plaintext, keys);
    }

    // RFC 9000 s17.3.1, field by field.
    private static byte[] BuildShortPacket(
        byte[] destinationConnectionId,
        bool keyPhase,
        bool spinBit,
        ulong fullPacketNumber,
        byte[] truncatedPacketNumber,
        byte[] plaintext,
        TlsQuicPacketProtectionKeys keys,
        byte firstByteExtraBits = 0)
    {
        var header = new List<byte>
        {
            // Header Form 0 | Fixed Bit (0x40) | Spin Bit (0x20) | Reserved (0x18) |
            // Key Phase (0x04) | Packet Number Length - 1.
            (byte)(0x40
                   | (spinBit ? 0x20 : 0)
                   | (keyPhase ? 0x04 : 0)
                   | (truncatedPacketNumber.Length - 1)
                   | firstByteExtraBits),
        };
        header.AddRange(destinationConnectionId);

        var packetNumberOffset = header.Count;
        header.AddRange(truncatedPacketNumber);
        return Protect(header, packetNumberOffset, fullPacketNumber, plaintext, keys);
    }

    // RFC 9001 s5.3 then s5.4, in that order: "When constructing packets, the AEAD
    // function is applied prior to applying header protection." The associated data is
    // "the contents of the QUIC header, starting from the first byte of either the short
    // or long header, up to and including the unprotected packet number" - which is the
    // whole of `header` as built above, by construction.
    private static byte[] Protect(
        List<byte> header,
        int packetNumberOffset,
        ulong fullPacketNumber,
        byte[] plaintext,
        TlsQuicPacketProtectionKeys keys)
    {
        var packet = new byte[header.Count + plaintext.Length + 16];
        header.CopyTo(packet);

        TlsQuicPacketProtection.Seal(
            TlsQuicPacketProtectionCipher.AesGcm,
            keys.CopyKey(),
            keys.CopyIv(),
            fullPacketNumber,
            packet.AsSpan(0, header.Count),
            plaintext,
            packet.AsSpan(header.Count));

        Assert.True(TlsQuicHeaderProtection.TryApply(
            TlsQuicHeaderProtectionCipher.Aes,
            keys.CopyHeaderProtectionKey(),
            packet,
            packetNumberOffset));

        return packet;
    }

    // RFC 9000 s16's one- and two-byte forms, which is everything these vectors need.
    private static byte[] Varint(ulong value) =>
        value < 64
            ? [(byte)value]
            : [(byte)(0x40 | (value >> 8)), (byte)value];
}
