using System.Net;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// RFC 9001 s5.7 retention, driven end to end against a real peer rather than against the
// receiver alone.
//
// THE FIELD REPORT THIS ANSWERS. Over SOCKS5-UDP, roughly one first request in eight to a new
// host died on the handshake deadline with a non-zero want-of-keys count, and proxyless never
// showed it. The message blamed the coalescing stall, and that was the wrong reading: the
// in-datagram case is already handled, because TlsQuicConnection.PumpOnceAsync calls
// TlsQuicPacketReceiver.Receive once per COALESCED PACKET and installs each packet's secrets
// before the next is opened - so a Handshake packet sitting behind ServerHello IN THE SAME
// DATAGRAM meets keys the previous packet in that same datagram produced.
//
// What splitting cannot reach is a Handshake packet that arrives in an EARLIER DATAGRAM than
// the Initial one carrying its keys. At the moment that datagram is walked there is no later
// packet in it and no split produces one, so before s5.7 retention the packet was discarded
// permanently, nothing retransmitted it, and the handshake ran out its deadline with every
// packet accounted for. A relay re-emits each datagram on its own path, which is why the
// reordering is ordinary proxied and rare direct - exactly the reported pattern.
//
// ============================================================================
// WHY A NEW DECORATOR AND NOT ImpairingDatagramTransport.
// ============================================================================
//
// ImpairingDatagramTransport reorders WHOLE DATAGRAMS - Drop, Duplicate, HoldUntilAfter,
// DelayBy - and that is the wrong granularity here, because LoopbackQuicPeer emits its whole
// server flight as ONE coalesced datagram (see its BuildDatagram: ascending encryption level,
// one datagram). Holding it changes when the flight arrives, never the order of the packets
// inside it. ScriptedDatagramTransport cannot help either, and says so in its own remarks:
// it "cannot fabricate a Handshake or 1-RTT packet", because those keys descend from the
// client ephemeral share.
//
// SplittingRelayTransport below fabricates nothing either. It takes a datagram the peer really
// built, walks it with the same TlsQuicDatagramReader the receiver uses, and re-emits each
// coalesced packet as its own datagram in reverse order - which is what a relay that spreads a
// datagram over several paths does to a flight, and is the smallest instrument that reaches
// the reported case. Every packet the client opens below is one LoopbackQuicPeer really sealed.
public sealed partial class TlsQuicConnectionTests
{
    [Fact]
    public async Task AHandshakePacketDeliveredBeforeItsInitialStillCompletesTheHandshake()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();

        // THE RELAY IS ON THE SERVER'S SIDE, so it is the SERVER-TO-CLIENT direction that is
        // reordered. The client's own sends go out untouched, which keeps the server's view of
        // the exchange ordinary and leaves the client as the only endpoint under test.
        await using var relay = new SplittingRelayTransport(serverTransport);

        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            relay, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);

        // The server answers the ClientHello with Initial + Handshake coalesced; the relay
        // splits that into two datagrams and sends the Handshake one FIRST.
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(2, relay.EmittedDatagrams);
        Assert.Equal(
            [TlsQuicEncryptionLevel.Handshake, TlsQuicEncryptionLevel.Initial],
            relay.EmittedLevels);

        // DATAGRAM ONE: the Handshake packet, ahead of the keys that open it. Nothing is
        // processed and RFC 9000 s12.2's want-of-keys count rises - the shape that used to be
        // terminal - but the packet is now retained under RFC 9001 s5.7 rather than dropped.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.DiscardedForMissingKeys);
        Assert.Equal(1, connection.RetainedForLaterKeys);
        Assert.Equal(0, connection.ReplayedAfterKeysArrived);
        Assert.False(connection.HasReadKeys(TlsQuicEncryptionLevel.Handshake));

        // DATAGRAM TWO: ServerHello. Its CRYPTO payload yields the Handshake secrets, and the
        // replay round in PumpOnceAsync opens the packet that had been waiting for them - so
        // the whole server flight is consumed inside this one pump.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.ReplayedAfterKeysArrived);
        Assert.True(connection.HasReadKeys(TlsQuicEncryptionLevel.Handshake));

        // WITHOUT THE RETENTION THIS IS WHERE IT ENDED: the Handshake flight was gone, the TLS
        // handshake never completed, and the next thing to happen was the handshake deadline.
        // Application read keys exist only once that flight has been consumed.
        Assert.True(connection.HasReadKeys(TlsQuicEncryptionLevel.Application));

        // AND THE EXCHANGE CARRIES ON NORMALLY FROM HERE, which is the claim worth making:
        // the replayed packet left the connection in the state it would have been in had the
        // datagrams arrived in order. The client's answer carries its Finished, and the pump
        // reports FALSE because the server has no CRYPTO left to send in reply - the same
        // verdict the in-order harness records at this point of the exchange.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.True(server.IsHandshakeComplete);

        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
    }

    [Fact]
    public async Task TheSameReorderingEndsOnTheHandshakeDeadlineWhenRetentionIsTurnedOff()
    {
        // THE OTHER HALF OF THE WITNESS ABOVE, and the reason the knob has a zero. With
        // TlsQuicConnectionSpec.RetainedPacketBufferBytes = 0 the receiver behaves exactly as
        // it did before s5.7 retention existed, so this test IS the bug - reproduced on
        // purpose, against the same relay and the same peer, with one spec value changed.
        // It is what keeps the test above from passing for some reason other than the fix.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var relay = new SplittingRelayTransport(serverTransport);

        var spec = SpecWithRetention(0);
        await using var connection = Connection(clientTransport, serverTransport, pki, spec);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            relay, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.DiscardedForMissingKeys);
        Assert.Equal(0, connection.RetainedForLaterKeys);

        // ServerHello lands, the Handshake keys are derived - and the packet they would have
        // opened is gone. The handshake cannot complete and no Application keys ever appear.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.True(connection.HasReadKeys(TlsQuicEncryptionLevel.Handshake));
        Assert.False(connection.HasReadKeys(TlsQuicEncryptionLevel.Application));
        Assert.Equal(0, connection.ReplayedAfterKeysArrived);
    }

    private static TlsQuicConnectionSpec SpecWithRetention(int retainedPacketBufferBytes) => new()
    {
        PaddingTarget = 1200,
        SourceConnectionIdLength = SourceConnectionIdLength,
        LocalFlowControl = TestQuicSpecValues.HarnessFlowControl,
        RetainedPacketBufferBytes = retainedPacketBufferBytes,
        TransportParameters = new TlsQuicTransportParameterSpec
        {
            Parameters =
            [
                TlsQuicTransportParameterSlot.Placed(
                    (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId),
                TlsQuicTransportParameterSlot.Placed(
                    (ulong)TlsQuicTransportParameterId.InitialMaxData),
                TlsQuicTransportParameterSlot.Placed(
                    (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal),
                TlsQuicTransportParameterSlot.Placed(
                    (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote),
                TlsQuicTransportParameterSlot.Placed(
                    (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataUni),
                TlsQuicTransportParameterSlot.Placed(
                    (ulong)TlsQuicTransportParameterId.InitialMaxStreamsBidi),
                TlsQuicTransportParameterSlot.Placed(
                    (ulong)TlsQuicTransportParameterId.InitialMaxStreamsUni),
            ],
        },
    };

    // A relay that re-emits each coalesced packet of an outgoing datagram as its own datagram,
    // last packet first. RFC 9000 s12.2 permits every one of those datagrams - each is a
    // legal, complete packet the sender really built and sealed - so nothing here is a forgery
    // and no key material is touched.
    //
    // REVERSED RATHER THAN SHUFFLED, because the case under test is one specific order:
    // "Senders SHOULD order packets in a datagram in increasing order of encryption level"
    // (s12.2), so reversing a conforming sender's datagram puts the highest level first, which
    // is precisely the Handshake-before-Initial delivery the field report produced. A random
    // order would make the test's outcome depend on a seed.
    //
    // A DATAGRAM WITH ONE PACKET PASSES THROUGH UNCHANGED, so the client's later exchanges -
    // and the server's HANDSHAKE_DONE - are not disturbed by an instrument aimed at the flight.
    private sealed class SplittingRelayTransport(ITlsQuicDatagramTransport inner)
        : ITlsQuicDatagramTransport
    {
        private readonly List<TlsQuicEncryptionLevel> _emittedLevels = [];

        internal int EmittedDatagrams { get; private set; }

        internal IReadOnlyList<TlsQuicEncryptionLevel> EmittedLevels => _emittedLevels;

        public int MaxDatagramPayloadSize => inner.MaxDatagramPayloadSize;

        public async ValueTask SendAsync(
            IPEndPoint destination, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            // COPIED BEFORE THE WALK, because TlsQuicDatagramReader.Read is a lazy iterator and
            // the pieces are sent across awaits - the same aliasing rule the receiver's own
            // remarks state, applied to a caller's send buffer.
            var datagram = payload.ToArray();

            var pieces = new List<(TlsQuicEncryptionLevel Level, byte[] Bytes)>();
            var offset = 0;
            foreach (var coalesced in TlsQuicDatagramReader.Read(datagram))
            {
                var length = coalesced.Packet.Length;
                pieces.Add((LevelOf(datagram, offset, coalesced.Kind), datagram[offset..(offset + length)]));
                offset += length;
            }

            // Anything the reader could not account for - it stops the walk rather than
            // throwing - stays attached to the last piece, so no byte the peer sent is lost.
            if (pieces.Count > 0 && offset < datagram.Length)
            {
                var last = pieces[^1];
                pieces[^1] = (last.Level, [.. last.Bytes, .. datagram[offset..]]);
            }

            if (pieces.Count == 0)
            {
                await inner.SendAsync(destination, datagram, cancellationToken).ConfigureAwait(false);
                EmittedDatagrams++;
                return;
            }

            for (var i = pieces.Count - 1; i >= 0; i--)
            {
                _emittedLevels.Add(pieces[i].Level);
                await inner.SendAsync(destination, pieces[i].Bytes, cancellationToken)
                    .ConfigureAwait(false);
                EmittedDatagrams++;
            }
        }

        public ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
            Memory<byte> buffer, CancellationToken cancellationToken)
            => inner.ReceiveAsync(buffer, cancellationToken);

        public ValueTask DisposeAsync() => inner.DisposeAsync();

        // Reported for the assertions only. RFC 9000 s17.2 Table 5's Long Packet Type is bits
        // 0x30 of byte 0; a short header is 1-RTT and therefore the Application level.
        private static TlsQuicEncryptionLevel LevelOf(
            byte[] datagram, int offset, TlsQuicCoalescedPacketKind kind) => kind switch
        {
            TlsQuicCoalescedPacketKind.Short => TlsQuicEncryptionLevel.Application,
            TlsQuicCoalescedPacketKind.Long => (datagram[offset] & 0x30) switch
            {
                0x00 => TlsQuicEncryptionLevel.Initial,
                0x10 => TlsQuicEncryptionLevel.EarlyData,
                0x20 => TlsQuicEncryptionLevel.Handshake,
                _ => TlsQuicEncryptionLevel.Initial,
            },
            _ => TlsQuicEncryptionLevel.Initial,
        };
    }
}
