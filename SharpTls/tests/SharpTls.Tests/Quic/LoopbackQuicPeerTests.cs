using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Protocol;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task 7 of A4-minimal. LoopbackQuicPeer's own header comment itemises which of these
// assertions survive a bug shared by both halves and which do not; read it before citing
// anything in this file. The one-line version: the sequencing ones do, the byte ones do
// not, and the single exception is the server's Initial read direction, which cannot
// cancel because the client's direction is anchored outside this file to RFC 9001
// Appendix A.
//
// NOT A THEORY OVER CIPHER SUITES OR GROUPS. CustomTlsQuicServerTests already runs that
// matrix over the same two endpoints with the packet layer removed. Everything below adds
// exactly the packet layer, so it varies only what the packet layer can see: whether a
// HelloRetryRequest adds a round trip.
public sealed class LoopbackQuicPeerTests
{
    // No clock. Every packet in every test below is built at this instant, and nothing in
    // the harness reads DateTimeOffset.UtcNow.
    private static readonly DateTimeOffset SentAt = new(2026, 8, 18, 12, 0, 0, TimeSpan.Zero);

    // The client's chosen Destination Connection ID - RFC 9001 s5.2's Initial secret input -
    // and its own Source Connection ID. Different lengths on purpose: an 8-byte and a 5-byte
    // ID cannot be swapped without the swap showing, which a matched pair could hide.
    private static readonly byte[] ChosenDestinationConnectionId =
        Convert.FromHexString("D1D2D3D4D5D6D7D8");
    private static readonly byte[] ClientSourceConnectionId = Convert.FromHexString("C1C2C3C4C5");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AClientAndServerReachHandshakeCompleteOverTheInMemoryTransport(
        bool forceHelloRetryRequest)
    {
        using var cancellation = Timeout();
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        await using var client = Client(pki, forceHelloRetryRequest);
        await using var server = Server(credential);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var clientPeer = ClientPeer(clientTransport, serverTransport, client);
        await using var serverPeer = ServerPeer(serverTransport, clientTransport, server);

        // DRIVEN A PUMP AT A TIME rather than through RunHandshakeAsync, because the
        // interleaving is the assertion. Completion alone is the boolean shape task 9a-i's
        // inverted read direction hid inside; "the client completed and the server had not
        // yet" is a statement about order that a symmetric packet-layer defect cannot fake,
        // since the order comes from RFC 9001 s4.1.1 and s4.1.2's flight structure.
        using (var start = client.StartHandshake())
        {
            Assert.True(await clientPeer.SendAsync(start, SentAt, cancellation.Token));
        }

        if (forceHelloRetryRequest)
        {
            // The server answers the first ClientHello with a HelloRetryRequest at the
            // Initial level and nothing else - it has no Handshake keys yet, and would not
            // have them until a ClientHello it accepts.
            Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
            Assert.Equal(TlsQuicKeyLevelState.NeverInstalled,
                serverPeer.WriteStateOf(TlsQuicEncryptionLevel.Handshake));

            Assert.True(await clientPeer.PumpOnceAsync(SentAt, cancellation.Token));
            Assert.False(client.IsHandshakeComplete);
        }

        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(client.IsHandshakeComplete);
        Assert.False(server.IsHandshakeComplete);

        Assert.True(await clientPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.True(client.IsHandshakeComplete);
        Assert.False(server.IsHandshakeComplete);

        // The last pump sends nothing: the server takes the client's Finished and has no
        // answer for it at any level this harness can write.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.True(server.IsHandshakeComplete);
        Assert.True(client.IsHandshakeComplete);

        // The negotiated result is the same one CustomTlsQuicServerTests gets with no packet
        // layer at all, which is the point: the packet layer carried the handshake without
        // changing it.
        Assert.Equal("example.com", server.ServerName);
        Assert.Equal("h3", server.NegotiatedApplicationProtocol);
        Assert.Equal("h3", client.NegotiatedApplicationProtocol);
        Assert.Equal(forceHelloRetryRequest, client.HandshakeUsedHelloRetryRequest);
        Assert.Equal(forceHelloRetryRequest, server.HandshakeUsedHelloRetryRequest);
    }

    [Theory]
    [InlineData(false, 3)]
    [InlineData(true, 5)]
    public async Task AHelloRetryRequestCostsExactlyOneMoreRoundTrip(
        bool forceHelloRetryRequest, int expectedRounds)
    {
        using var cancellation = Timeout();
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        await using var client = Client(pki, forceHelloRetryRequest);
        await using var server = Server(credential);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var clientPeer = ClientPeer(clientTransport, serverTransport, client);
        await using var serverPeer = ServerPeer(serverTransport, clientTransport, server);

        using var start = client.StartHandshake();
        var rounds = await LoopbackQuicPeer.RunHandshakeAsync(
            clientPeer, serverPeer, start, SentAt, cancellationToken: cancellation.Token);

        // 3 = the server's flight, the client's Finished, the server taking it. 5 = the same
        // with a HelloRetryRequest and the second ClientHello in front. Both counts come from
        // RFC 9001 s4.1.1's flight structure and not from anything in the packet layer.
        Assert.Equal(expectedRounds, rounds);
        Assert.True(client.IsHandshakeComplete);
        Assert.True(server.IsHandshakeComplete);

        // ONE PACKET PER FLIGHT PER SPACE, counted. A HelloRetryRequest adds exactly one
        // Initial packet to each side and none at the Handshake level, where the flights
        // are unchanged. NextPacketNumber is also the count of packets built, so a packet
        // number reused or skipped shows here as a wrong total.
        var expectedInitialPackets = forceHelloRetryRequest ? 2UL : 1UL;
        Assert.Equal(expectedInitialPackets,
            clientPeer.NextPacketNumber(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(expectedInitialPackets,
            serverPeer.NextPacketNumber(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(1UL, clientPeer.NextPacketNumber(TlsQuicEncryptionLevel.Handshake));
        Assert.Equal(1UL, serverPeer.NextPacketNumber(TlsQuicEncryptionLevel.Handshake));
        Assert.Equal(0UL, clientPeer.NextPacketNumber(TlsQuicEncryptionLevel.Application));
        Assert.Equal(0UL, serverPeer.NextPacketNumber(TlsQuicEncryptionLevel.Application));
    }

    [Fact]
    public async Task BothSidesDiscardTheirInitialKeysWhileTheHandshakeIsStillRunning()
    {
        using var cancellation = Timeout();
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        await using var client = Client(pki, forceHelloRetryRequest: false);
        await using var server = Server(credential);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var clientPeer = ClientPeer(clientTransport, serverTransport, client);
        await using var serverPeer = ServerPeer(serverTransport, clientTransport, server);

        using var start = client.StartHandshake();
        await LoopbackQuicPeer.RunHandshakeAsync(
            clientPeer, serverPeer, start, SentAt, cancellationToken: cancellation.Token);

        // RFC 9001 s4.9.1's two triggers, one per role: the client discards Initial keys
        // when it first sends a Handshake packet - CustomTlsQuicClient.NotifyHandshakePacketSent,
        // which the harness calls at that moment - and the server when it first receives one.
        // Discarded, not NeverInstalled: the distinction is the whole reason TlsQuicKeyLevelState has
        // three values, and a level that was never keyed reads NeverInstalled.
        Assert.Equal(TlsQuicKeyLevelState.Discarded,
            clientPeer.WriteStateOf(TlsQuicEncryptionLevel.Initial));
        Assert.Equal(TlsQuicKeyLevelState.Discarded,
            serverPeer.WriteStateOf(TlsQuicEncryptionLevel.Initial));
        Assert.False(clientPeer.HasReadKeys(TlsQuicEncryptionLevel.Initial));
        Assert.False(serverPeer.HasReadKeys(TlsQuicEncryptionLevel.Initial));

        // And the level the handshake finished at is discarded too, on the side that has
        // seen the last thing it will ever carry.
        Assert.Equal(TlsQuicKeyLevelState.Discarded,
            serverPeer.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
    }

    [Fact]
    public async Task APaddedInitialDatagramDeliversOneChunkOfCryptoStreamAndNotOneThousand()
    {
        using var cancellation = Timeout();
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        await using var client = Client(pki, forceHelloRetryRequest: false);
        await using var server = Server(credential);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var clientPeer = ClientPeer(clientTransport, serverTransport, client);
        await using var serverPeer = ServerPeer(serverTransport, clientTransport, server);

        using (var start = client.StartHandshake())
        {
            await clientPeer.SendAsync(start, SentAt, cancellation.Token);
        }
        await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);

        // The ClientHello arrives in one Initial packet expanded to RFC 9000 s14.1's 1200
        // bytes with PADDING frames, so the packet the server opened held one CRYPTO frame
        // and roughly a thousand PADDING frames beside it. ONE, not one thousand and one.
        //
        // THIS IS THE ONLY THING THAT SEES THE FRAME FILTER. Handing every frame to the TLS
        // endpoint leaves the handshake completing exactly as before, because a PADDING
        // frame carries no data and both endpoints take an empty chunk at offset zero as a
        // no-op - so a count is the only observable that separates the two.
        Assert.Equal(1, serverPeer.DeliveredCryptoChunks);
    }

    [Fact]
    public async Task TheServerTakesItsConnectionIdsAndItsInitialKeysOffTheWire()
    {
        using var cancellation = Timeout();
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        await using var client = Client(pki, forceHelloRetryRequest: false);
        await using var server = Server(credential);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var clientPeer = ClientPeer(clientTransport, serverTransport, client);
        await using var serverPeer = ServerPeer(serverTransport, clientTransport, server);

        using var start = client.StartHandshake();
        await LoopbackQuicPeer.RunHandshakeAsync(
            clientPeer, serverPeer, start, SentAt, cancellationToken: cancellation.Token);

        // The server was constructed knowing neither ID. It ends up with the client's chosen
        // Destination Connection ID as its own source, which is also what it derived its
        // Initial secrets from - so the header field is load-bearing rather than decorative,
        // and a Destination Connection ID encoded wrongly would have failed to open rather
        // than being papered over by an out-of-band copy. Length included: the client's two
        // IDs are 8 and 5 bytes, so picking up the wrong one is visible.
        Assert.Equal(ChosenDestinationConnectionId, serverPeer.SourceConnectionId.ToArray());
        Assert.Equal(8, serverPeer.SourceConnectionId.Length);
    }

    [Fact]
    public async Task AnInitialPacketProtectedWithTheServerSecretDoesNotOpenAtTheServer()
    {
        using var cancellation = Timeout();
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        await using var server = Server(credential);
        var (senderTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var senderSide = senderTransport;
        await using var serverPeer = ServerPeer(serverTransport, senderTransport, server);

        // RFC 9001 s5.2 derives two Initial secrets from the same Destination Connection ID,
        // one per direction. This packet is well formed, correctly padded and protected with
        // the SERVER secret - the one the server writes with and must never read with. The
        // header protection key differs too, so the packet number decodes to something else
        // before the AEAD is even reached; either way nothing opens.
        //
        // NOT A REDUNDANT NEGATIVE. It is the counterpart to the whole handshake opening,
        // and together they pin isClient: false's read direction to the client secret. The
        // positive alone would still hold if BOTH directions were inverted; this one would
        // not, because it is the same packet the server writes itself.
        var datagram = ServerSecretInitialDatagram();
        await senderTransport.SendAsync(
            serverTransport.LocalEndPoint, datagram, cancellation.Token);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Contains("did not yield exactly one processed packet", error.Message, StringComparison.Ordinal);
        Assert.Contains("1 discarded", error.Message, StringComparison.Ordinal);

        // AND NOT FOR WANT OF KEYS. RFC 9000 s12.2 discards a packet "because the keys are
        // not available or for any other reason"; this is the second half. The server DID
        // install Initial keys - it took them off this very packet's header - and they are
        // simply the wrong direction's, so the AEAD is what refuses. Asserting the zero is
        // what keeps this test distinct from the coalescing stall, whose whole signature is
        // a non-zero here.
        Assert.Contains("(0 for want of keys)", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADatagramThatDoesNotOpenWithALongHeaderIsNamedRatherThanKeyedFromNothing()
    {
        using var cancellation = Timeout();
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        await using var server = Server(credential);
        var (senderTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var senderSide = senderTransport;
        await using var serverPeer = ServerPeer(serverTransport, senderTransport, server);

        // A short header (RFC 9000 s17.3): high bit clear, fixed bit set. A server has no
        // 1-RTT keys before a handshake and no connection ID to parse one with, so this
        // cannot be the first thing it sees - and TryReadLongHeader returning false is the
        // only signal that says so. Without the guard the server would carry on with two
        // zero-length connection IDs and derive Initial secrets from an empty ID, which
        // derives successfully and decrypts nothing.
        var shortHeader = new byte[64];
        RandomNumberGenerator.Fill(shortHeader);
        shortHeader[0] = 0x40;

        await senderTransport.SendAsync(
            serverTransport.LocalEndPoint, shortHeader, cancellation.Token);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Contains("long header", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ASessionTicketIsRefusedByNameBecauseNoOneRttSendPathExists()
    {
        using var cancellation = Timeout();
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        await using var client = Client(pki, forceHelloRetryRequest: false);
        using var ticketProtector = new Tls13ServerSessionTicketProtector(
            "quic-loopback", RandomNumberGenerator.GetBytes(32));
        await using var server = Server(credential, ticketProtector);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var clientPeer = ClientPeer(clientTransport, serverTransport, client);
        await using var serverPeer = ServerPeer(serverTransport, clientTransport, server);

        using var start = client.StartHandshake();
        await LoopbackQuicPeer.RunHandshakeAsync(
            clientPeer, serverPeer, start, SentAt, cancellationToken: cancellation.Token);

        // CustomTlsQuicServer.IssueSessionTicketAsync raises its NewSessionTicket at the
        // Application level, which RFC 9001 s4.1.2 carries in a 1-RTT packet and
        // TlsQuicPacketBuilder does not build. THE REACHABLE PATH TO THAT GUARD, and the
        // reason it is a named refusal rather than a level quietly skipped: a skipped level
        // would look to a caller like a ticket that was sent and lost.
        using var ticket = await server.IssueSessionTicketAsync(cancellation.Token);
        Assert.Contains(
            ticket.Events.OfType<TlsQuicCryptoDataEvent>(),
            item => item.Level == TlsQuicEncryptionLevel.Application);

        var error = await Assert.ThrowsAsync<NotSupportedException>(
            async () => await serverPeer.SendAsync(ticket, SentAt, cancellation.Token));
        Assert.Contains("long header packets only", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WritingAtALevelWhoseKeysAreGoneIsNamedRatherThanSentUnprotected()
    {
        using var cancellation = Timeout();
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        await using var client = Client(pki, forceHelloRetryRequest: false);
        await using var server = Server(credential);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var clientPeer = ClientPeer(clientTransport, serverTransport, client);
        await using var serverPeer = ServerPeer(serverTransport, clientTransport, server);

        using var start = client.StartHandshake();
        await LoopbackQuicPeer.RunHandshakeAsync(
            clientPeer, serverPeer, start, SentAt, cancellationToken: cancellation.Token);

        // The server discarded its Handshake keys on completing (RFC 9001 s4.9.2). A late
        // CRYPTO frame at that level - a retransmit that outlived the discard - has nothing
        // to protect it. The state is REACHED by the handshake rather than forced, so the
        // only thing built by hand here is the result carrying the frame.
        Assert.Equal(TlsQuicKeyLevelState.Discarded,
            serverPeer.WriteStateOf(TlsQuicEncryptionLevel.Handshake));

        using var late = new TlsQuicProcessResult(
        [
            new TlsQuicCryptoDataEvent(TlsQuicEncryptionLevel.Handshake, 0, [1, 2, 3, 4]),
        ]);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await serverPeer.SendAsync(late, SentAt, cancellation.Token));
        Assert.Contains("No write keys at Handshake", error.Message, StringComparison.Ordinal);
        Assert.Contains("Discarded", error.Message, StringComparison.Ordinal);
    }

    private static CancellationTokenSource Timeout() => new(TimeSpan.FromSeconds(60));

    // 1200 is RFC 9000 s14.1's floor rather than a fingerprint choice, and this file asserts
    // nothing about the number. Every other knob is TlsQuicConnectionSpec's default.
    private static TlsQuicConnectionSpec Spec() => new() { PaddingTarget = 1200 };

    private static LoopbackQuicPeer ClientPeer(
        InMemoryDatagramTransport transport,
        InMemoryDatagramTransport peer,
        CustomTlsQuicClient client) =>
        LoopbackQuicPeer.ForClient(
            transport,
            peer.LocalEndPoint,
            client,
            ChosenDestinationConnectionId,
            ClientSourceConnectionId,
            Spec());

    private static LoopbackQuicPeer ServerPeer(
        InMemoryDatagramTransport transport,
        InMemoryDatagramTransport peer,
        CustomTlsQuicServer server) =>
        LoopbackQuicPeer.ForServer(
            transport,
            peer.LocalEndPoint,
            server,
            Spec());

    private static TlsServerCertificate Credential(TestPki pki) =>
        new(pki.Leaf, (RSA)pki.LeafKey, [pki.Root]);

    private static CustomTlsQuicClient Client(TestPki pki, bool forceHelloRetryRequest) =>
        new(new CustomTlsQuicClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(forceHelloRetryRequest
                    ? [NamedGroup.Secp384r1, NamedGroup.Secp256r1]
                    : [NamedGroup.Secp256r1])
                .WithKeyShares(forceHelloRetryRequest
                    ? [NamedGroup.Secp384r1]
                    : [NamedGroup.Secp256r1])
                .WithAlpn("h3")
                .WithQuicTransportParameters(ClientParameters())),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });

    // AutomaticSessionTicketCount 0 so that a ticket is only ever issued by the test that
    // asks for one. At the default of 2 the server would raise Application-level CRYPTO data
    // as part of completing, and every handshake here would end in the 1-RTT refusal rather
    // than the one test that is about it.
    private static CustomTlsQuicServer Server(
        TlsServerCertificate credential,
        Tls13ServerSessionTicketProtector? ticketProtector = null) =>
        new(new CustomTlsQuicServerOptions
        {
            Tls = new CustomTlsServerOptions
            {
                SessionTicketProtector = ticketProtector,
                AutomaticSessionTicketCount = 0,
                ServerCertificate = credential,
                SupportedVersions = [TlsProtocolVersion.Tls13],
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                SupportedGroups = [NamedGroup.Secp256r1],
                AlpnProtocols = ["h3"],
                RequireAlpn = true,
            },
            TransportParameters = ServerParameters(),
        });

    private static TlsQuicTransportParameters ClientParameters() => new(
    [
        new TlsQuicTransportParameter(
            (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
            ClientSourceConnectionId),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.ActiveConnectionIdLimit, 2),
    ]);

    private static TlsQuicTransportParameters ServerParameters() => new(
    [
        new TlsQuicTransportParameter(
            (ulong)TlsQuicTransportParameterId.OriginalDestinationConnectionId,
            ChosenDestinationConnectionId),
        new TlsQuicTransportParameter(
            (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
            ChosenDestinationConnectionId),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.ActiveConnectionIdLimit, 4),
    ]);

    // One Initial packet carrying one CRYPTO frame, protected with the SERVER Initial
    // secret. Built through the same task 4b and task 5 code the harness uses, so the only
    // thing that differs from a packet the server would accept is which of s5.2's two
    // secrets protects it.
    private static byte[] ServerSecretInitialDatagram()
    {
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1, ChosenDestinationConnectionId);
        using var keys = secrets.DeriveServerPacketProtectionKeys(TlsQuicVersion.Version1);

        var spec = Spec();
        var packet = new TlsQuicPacketToSend
        {
            Plan = new TlsQuicPacketPlan
            {
                Type = TlsQuicLongPacketType.Initial,
                Version = (uint)TlsQuicVersion.Version1,
                DestinationConnectionId = ChosenDestinationConnectionId,
                SourceConnectionId = ClientSourceConnectionId,
                PacketNumber = 0,
                PacketNumberEncodedLength = spec.PacketNumberEncodedLength,
                LengthVarintWidth = spec.HeaderLengthVarintWidth,
                CryptoOffsetVarintWidth = spec.CryptoOffsetVarintWidth,
                CryptoLengthVarintWidth = spec.CryptoLengthVarintWidth,
            },
            Frames = [new TlsQuicFrame { RawType = 0x06, Offset = 0, Data = new byte[] { 9, 9, 9, 9 } }],
            PacketProtectionCipher = TlsQuicPacketProtectionCipher.AesGcm,
            Key = keys.CopyKey(),
            Iv = keys.CopyIv(),
            HeaderProtectionCipher = TlsQuicHeaderProtectionCipher.Aes,
            HeaderProtectionKey = keys.CopyHeaderProtectionKey(),
        };

        var buffer = new byte[spec.PaddingTarget];
        var written = TlsQuicDatagramBuilder.BuildDatagram(spec, [packet], SentAt, buffer);
        return buffer[..written];
    }
}
