using System.Diagnostics;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task 9b of A4-minimal: Retry, Version Negotiation, close, idle timeout, PATH_CHALLENGE, and
// RFC 9000 s7.3's connection ID authentication.
//
// ONE CLASS ACROSS TWO FILES, ON PURPOSE. This is `partial` so that task 9a-ii's scaffolding -
// Spec, Connection, TlsClient, Server, ServerPacket, ConnectionIdsFrom, OpenOwnInitialPacket -
// is reused rather than copied; a second class would have had to duplicate all of it or promote
// it, and a copy of ServerPacket is a second packet writer, which this phase bans by name. The
// split is by SUBJECT: 9a-ii's file is the happy path, and a failure there means "the handshake
// does not complete", while a failure here means "an unusual server response is mishandled".
//
// ============================================================================
// WHAT THESE ASSERTIONS PIN, AND WHAT THEY CANNOT.
// ============================================================================
//
//   THE RETRY AND VERSION NEGOTIATION HALVES ARE NOT SELF-CHECKING. Both packet types are
//   built HERE, by hand, from bytes this file chooses - a Retry's integrity tag is computed
//   with TlsQuicRetry.ComputeTag over an ODCID read off the connection's own first datagram,
//   exactly as a server would - and every assertion is against a value that exists nowhere
//   else. A connection that ignored the Retry entirely fails them.
//
//   THE s7.3 HALF CANNOT BE SCRIPTED, AND THE TASK TEXT ASKING FOR IT WAS WRONG ABOUT THAT.
//   Transport parameters arrive inside EncryptedExtensions, which is Handshake-level CRYPTO,
//   and ScriptedDatagramTransport's own remarks say what it cannot do: "It cannot fabricate a
//   Handshake or 1-RTT packet: those keys descend from the client ephemeral share, which
//   differs on every run." So s7.3 is driven from LoopbackQuicPeer with a server whose
//   connection ID parameters are DOCTORED HERE - which is the same property the scripted half
//   has, a mismatched value that exists only in this file, reached the only way it can be.
//
//   WHAT SURVIVES A SHARED BUG: nothing in the Retry half, because our own code neither
//   computes nor checks the tag on both sides - ComputeTag is called here and TryVerify in the
//   connection, and RFC 9001 A.4's published vector pins the pair in TlsQuicRetryTests.
public sealed partial class TlsQuicConnectionTests
{
    // ---- RFC 9000 s17.2.5: Retry ---------------------------------------------------------

    [Fact]
    public async Task AValidRetryMovesTheConnectionIdAndTokenAndRederivesTheInitialKeys()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // Two values that exist NOWHERE ELSE - not on the connection, not in its spec, not in
        // any reply this file builds for another test. The trap task 9a-ii's amendment names is
        // exactly this one: against a peer that echoes our own connection ID back, a connection
        // that never adopted would pass, so the adopted value has to be unforgeable from the
        // inside.
        var retrySource = Convert.FromHexString("A1A2A3A4A5A6A7A8");
        var token = Convert.FromHexString("7E57C0DE");
        transport.EnqueueReceive(sent => RetryDatagram(sent, retrySource, token));

        await connection.StartAsync(cancellation.Token);
        var original = connection.OriginalDestinationConnectionId.ToArray();
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // s17.2.5.2: "A client sets the Destination Connection ID field of this Initial packet
        // to the value from the Source Connection ID field in the Retry packet ... It also sets
        // the Token field to the token provided in the Retry packet." READ OFF THE WIRE, not
        // off the connection's properties, because the properties are what the code under test
        // sets and the header is what a server sees.
        Assert.Equal(2, transport.Sent.Count);
        var answer = transport.Sent[1].Payload;
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(answer, out var header, out _));
        Assert.Equal(retrySource, header.DestinationConnectionId.ToArray());
        Assert.Equal(token, header.Token.ToArray());
        Assert.Equal(connection.SourceConnectionId.ToArray(), header.SourceConnectionId.ToArray());

        // s7.2: "The Destination Connection ID field from the first Initial packet sent by a
        // client is used to determine packet protection keys for Initial packets. These keys
        // change after receiving a Retry packet." BOTH DIRECTIONS, because only the pair is
        // the claim: presence of new keys is not identity, and a connection that re-derived
        // from the wrong value would satisfy the first assertion alone.
        Assert.True(TryOpenOwnInitialPacket(answer, retrySource, out var plaintext));
        Assert.False(TryOpenOwnInitialPacket(answer, original, out _));

        // s17.2.5.3: "A client MUST use the same cryptographic handshake message it included in
        // this packet." The first datagram's CRYPTO payload, byte for byte.
        Assert.Equal(
            CryptoBytesIn(OpenOwnInitialPacket(transport.Sent[0].Payload, original)),
            CryptoBytesIn(plaintext));

        // s17.2.5.3: "A client MUST NOT reset the packet number for any packet number space
        // after processing a Retry packet." The opening flight used 0, so the answer uses 1.
        Assert.Equal(2UL, connection.NextPacketNumber(TlsQuicEncryptionLevel.Initial));

        // The original is RETAINED - it is what RFC 9001 s5.8's tag was verified against and
        // what s7.3's original_destination_connection_id must equal - while the one we address
        // has moved.
        Assert.Equal(original, connection.OriginalDestinationConnectionId.ToArray());
        Assert.Equal(retrySource, connection.DestinationConnectionId.ToArray());
        Assert.Equal(retrySource, connection.RetrySourceConnectionId!.Value.ToArray());
        Assert.Equal(token, connection.RetryToken.ToArray());
        Assert.Equal(0, connection.IgnoredRetryPackets);
    }

    [Fact]
    public async Task ARetryWhoseIntegrityTagDoesNotValidateIsIgnored()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // RFC 9000 s17.2.5.2: "Clients MUST discard Retry packets that have a Retry Integrity
        // Tag that cannot be validated." ONE BIT, in the tag and nowhere else: every other
        // field is what the valid case above sends, so the tag is the only thing that can
        // reject this packet and the check cannot be passing for another reason.
        var retrySource = Convert.FromHexString("A1A2A3A4A5A6A7A8");
        transport.EnqueueReceive(
            sent => RetryDatagram(sent, retrySource, Convert.FromHexString("7E57C0DE"), corruptTag: true));

        await connection.StartAsync(cancellation.Token);
        var original = connection.OriginalDestinationConnectionId.ToArray();
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.IgnoredRetryPackets);
        Assert.Single(transport.Sent);
        Assert.Equal(original, connection.DestinationConnectionId.ToArray());
        Assert.Null(connection.RetrySourceConnectionId);
        Assert.True(connection.RetryToken.IsEmpty);

        // AND IT DID NOT THROW. RFC 9000 s17.2.5: "A Retry packet does not contain any
        // protected fields", so this is unauthenticated peer input and s12.2's rule applies -
        // a discard, not the end of the connection. An off-path sender must not be able to
        // kill an attempt with sixteen wrong bytes.
        Assert.False(connection.IsDraining);
    }

    [Fact]
    public async Task ASecondRetryIsIgnoredEvenThoughItsIntegrityTagValidates()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        var first = Convert.FromHexString("A1A2A3A4A5A6A7A8");
        var second = Convert.FromHexString("B1B2B3B4B5B6B7B8");
        transport.EnqueueReceive(
            sent => RetryDatagram(sent, first, Convert.FromHexString("7E57C0DE")));

        // THE SECOND RETRY IS VALID IN EVERY OTHER RESPECT, and that is the point of the test.
        // Its tag is computed over the same original Destination Connection ID - which is what
        // a server sending a second Retry would use, since s7.3 defines that value as "the
        // first Initial packet received before sending the Retry packet" - so only s17.2.5.2's
        // once-only rule can reject it.
        transport.EnqueueReceive(
            sent => RetryDatagram(sent, second, Convert.FromHexString("DEADBEEF")));

        await connection.StartAsync(cancellation.Token);
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // s17.2.5.2: "A client MUST accept and process at most one Retry packet for each
        // connection attempt."
        Assert.Equal(1, connection.IgnoredRetryPackets);
        Assert.Equal(first, connection.DestinationConnectionId.ToArray());
        Assert.Equal(first, connection.RetrySourceConnectionId!.Value.ToArray());
        Assert.Equal(Convert.FromHexString("7E57C0DE"), connection.RetryToken.ToArray());

        // Two datagrams, not three: the opening flight and the one answer the first Retry
        // earned. A connection that honoured the second would have sent a third.
        Assert.Equal(2, transport.Sent.Count);
    }

    [Fact]
    public async Task ARetryWithAZeroLengthTokenIsIgnored()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // RFC 9000 s17.2.5.2: "A client MUST discard a Retry packet with a zero-length Retry
        // Token field." The tag is computed over this exact packet and therefore VALIDATES, so
        // the token-length check is the only thing that can reject it.
        var retrySource = Convert.FromHexString("A1A2A3A4A5A6A7A8");
        transport.EnqueueReceive(sent => RetryDatagram(sent, retrySource, []));

        await connection.StartAsync(cancellation.Token);
        var original = connection.OriginalDestinationConnectionId.ToArray();
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.IgnoredRetryPackets);
        Assert.Single(transport.Sent);
        Assert.Equal(original, connection.DestinationConnectionId.ToArray());
    }

    [Fact]
    public async Task ARetryWhoseSourceConnectionIdEqualsOurDestinationIsIgnored()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // RFC 9000 s17.2.5.1: "A client MUST discard a Retry packet that contains a Source
        // Connection ID field that is identical to the Destination Connection ID field of its
        // Initial packet." Again the tag validates - the Source Connection ID is under it -
        // so this check is the only rejection available.
        transport.EnqueueReceive(sent => RetryDatagram(
            sent,
            serverSourceConnectionId: ConnectionIdsFrom(sent).Destination,
            token: Convert.FromHexString("7E57C0DE")));

        await connection.StartAsync(cancellation.Token);
        var original = connection.OriginalDestinationConnectionId.ToArray();
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.IgnoredRetryPackets);
        Assert.Single(transport.Sent);
        Assert.Equal(original, connection.DestinationConnectionId.ToArray());
    }

    [Fact]
    public async Task ARetryWhoseSourceConnectionIdEqualsOurFirstInitialsDestinationIsIgnored()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // THE SAME MUST AS ARetryWhoseSourceConnectionIdEqualsOurDestinationIsIgnored. RFC 9000
        // s17.2.5.1: "A client MUST discard a Retry packet that contains a Source Connection ID
        // field that is identical to the Destination Connection ID field of ITS INITIAL PACKET."
        //
        // THE TWO OPERANDS THIS ROW ONCE PRISED APART CAN NO LONGER BE SEPARATED, AND SAYING SO
        // IS THE POINT OF KEEPING IT. It used to inject an unopenable Initial to move the
        // CURRENT Destination Connection ID away from the one we DREW, so that a comparison
        // written against the wrong operand would read "ODCID != attacker value" and adopt the
        // forgery. Audit finding 7 put s7.2's adoption behind the AEAD, so nothing an attacker
        // can send moves it - and before any packet the AEAD opens, the drawn value and the
        // addressed value are the same bytes by construction. The only thing that could separate
        // them now is a VALID server Initial, and ARetryThatFollowsASuccessfullyProcessedServer
        // PacketIsIgnored is the rule that makes the Retry unreachable after one of those. So
        // the mutation "compare against the current Destination Connection ID" is vacuous today;
        // the source keeps OriginalDestinationConnectionId because s17.2.5.1 names it, not
        // because a test can tell.
        //
        // THE INJECTION IS KEPT AS THE INERTNESS CHECK IT HAS BECOME. It is sealed with RFC 9001
        // s5.2's CLIENT secret, so a client cannot open it and _processedServerPacket stays
        // false - which is what keeps the Retry path reachable at all.
        var attackerConnectionId = Convert.FromHexString("ADADADADADADADAD");
        transport.EnqueueReceive(sent => ClientSecretInitialReply(sent, attackerConnectionId));

        // The Retry then carries, as its Source Connection ID, the Destination Connection ID of
        // our FIRST Initial packet - exactly what s17.2.5.1 names. Its version is ours, its
        // token is non-empty, its integrity tag is computed over the true original Destination
        // Connection ID and verifies, and no server packet has been processed. Four of the five
        // discard rules pass it; only the identical-Source-Connection-ID rule can reject it, and
        // only when that rule is compared against OriginalDestinationConnectionId. Compared
        // against the CURRENT Destination Connection ID it reads "ODCID != attacker value" and
        // the forgery is adopted.
        transport.EnqueueReceive(sent => RetryDatagram(
            sent,
            serverSourceConnectionId: ConnectionIdsFrom(sent).Destination,
            token: Convert.FromHexString("7E57C0DE")));

        await connection.StartAsync(cancellation.Token);

        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.DiscardedPackets);
        Assert.NotEqual(attackerConnectionId, connection.DestinationConnectionId.ToArray());

        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.IgnoredRetryPackets);
        Assert.Null(connection.RetrySourceConnectionId);
        Assert.True(connection.RetryToken.IsEmpty);

        // Neither the token nor a second flight went anywhere: the opening flight is still the
        // only datagram on the wire, and we are still addressing the connection ID we drew -
        // neither the injected value nor the one the discarded Retry offered.
        Assert.Single(transport.Sent);
        Assert.Equal(
            connection.OriginalDestinationConnectionId.ToArray(),
            connection.DestinationConnectionId.ToArray());
    }

    [Fact]
    public async Task ARetryThatFollowsASuccessfullyProcessedServerPacketIsIgnored()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // A real server Initial packet first - sealed with RFC 9001 s5.2's server secret, so
        // the AEAD opens it and it counts as "received and processed".
        transport.EnqueueReceive(sent => ServerInitialReply(sent, Convert.FromHexString("5E5E5E")));

        // Then a Retry that is valid in every respect. s17.2.5.2: "After the client has
        // received and processed an Initial or Retry packet from the server, it MUST discard
        // any subsequent Retry packets that it receives."
        transport.EnqueueReceive(sent => RetryDatagram(
            sent, Convert.FromHexString("A1A2A3A4A5A6A7A8"), Convert.FromHexString("7E57C0DE")));

        await connection.StartAsync(cancellation.Token);
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // s7.2's adoption has already moved the Destination Connection ID to the server's
        // Source Connection ID; the Retry must not move it again.
        Assert.Equal(Convert.FromHexString("5E5E5E"), connection.DestinationConnectionId.ToArray());

        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.IgnoredRetryPackets);
        Assert.Equal(Convert.FromHexString("5E5E5E"), connection.DestinationConnectionId.ToArray());
        Assert.Null(connection.RetrySourceConnectionId);
    }

    [Fact]
    public async Task ARetryAnnouncingAnotherQuicVersionIsIgnored()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // THE TAG VERIFIES. It is computed here with version 1's RFC 9001 s5.8 constants over a
        // packet whose Version field says 2, which is exactly what a v1 endpoint's own
        // TlsQuicRetry.TryVerify recomputes - so the integrity check cannot reject this packet
        // and the version check is the only thing that can. TlsQuicPacketReceiver orders these
        // two the same way for every other long header packet, and intercepting Retry ahead of
        // it is what made the order this connection's business.
        transport.EnqueueReceive(sent => RetryDatagram(
            sent,
            Convert.FromHexString("A1A2A3A4A5A6A7A8"),
            Convert.FromHexString("7E57C0DE"),
            version: TlsQuicVersion.Version2));

        await connection.StartAsync(cancellation.Token);
        var original = connection.OriginalDestinationConnectionId.ToArray();
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.IgnoredRetryPackets);
        Assert.Single(transport.Sent);
        Assert.Equal(original, connection.DestinationConnectionId.ToArray());
        Assert.Null(connection.RetrySourceConnectionId);
    }

    // ---- RFC 9000 s17.2.1: Version Negotiation -------------------------------------------

    [Fact]
    public async Task AVersionNegotiationPacketEndsTheAttemptAndNamesTheVersionsOffered()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        transport.EnqueueReceive(sent => VersionNegotiationDatagram(
            destinationEcho: ConnectionIdsFrom(sent).Source,
            sourceEcho: ConnectionIdsFrom(sent).Destination,
            versions: [0x6b3343cf, 0x00000002]));

        await connection.StartAsync(cancellation.Token);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        // A4-minimal REPORTS rather than negotiates, and the report is the list itself: a
        // caller choosing 0x00000002 (RFC 9369's QUIC v2) starts a new attempt built for it.
        Assert.Contains("Version Negotiation", error.Message, StringComparison.Ordinal);
        Assert.Equal(new uint[] { 0x6b3343cf, 0x00000002 }, connection.OfferedVersions);
        Assert.Equal(0, connection.IgnoredVersionNegotiationPackets);
        Assert.Equal(1, connection.UnprocessedPackets);
    }

    [Fact]
    public async Task AVersionNegotiationPacketAfterASuccessfullyProcessedPacketIsIgnored()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        transport.EnqueueReceive(sent => ServerInitialReply(sent, Convert.FromHexString("5E5E5E")));
        transport.EnqueueReceive(sent => VersionNegotiationDatagram(
            destinationEcho: ConnectionIdsFrom(sent).Source,
            sourceEcho: ConnectionIdsFrom(sent).Destination,
            versions: [0x00000002]));

        await connection.StartAsync(cancellation.Token);
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // TlsQuicVersionNegotiation's own contract, and the reason it is stated there rather
        // than here: a Version Negotiation packet "MUST be ignored once a packet for the
        // connection has been successfully processed". It echoes both connection IDs
        // correctly, so only that rule can reject it.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.IgnoredVersionNegotiationPackets);
        Assert.Null(connection.OfferedVersions);
        Assert.False(connection.IsDraining);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task AVersionNegotiationPacketThatDoesNotEchoBothConnectionIdsIsIgnored(
        bool echoDestination, bool echoSource)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // RFC 9000 s17.2.1, and it is the sentence AFTER the two MUSTs that says why this is
        // checked at all: "Echoing both connection IDs gives clients some assurance that the
        // server received the packet and that the Version Negotiation packet was not generated
        // by an entity that did not observe the Initial packet." Without it, a packet nobody
        // authenticated - RFC 9001 s5 gives this type no protection whatsoever - ends the
        // attempt, which is the off-path kill switch this project has already shipped once.
        //
        // ONE ROW PER ECHO, because a guard with two disjuncts needs an input that reaches
        // each: the wrong-Destination row cannot fire the Source half and vice versa.
        transport.EnqueueReceive(sent => VersionNegotiationDatagram(
            destinationEcho: echoDestination
                ? ConnectionIdsFrom(sent).Source
                : Convert.FromHexString("CCCCCCCCCC"),
            sourceEcho: echoSource
                ? ConnectionIdsFrom(sent).Destination
                : Convert.FromHexString("DDDDDDDDDDDDDDDD"),
            versions: [0x00000002]));

        await connection.StartAsync(cancellation.Token);
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.IgnoredVersionNegotiationPackets);
        Assert.Null(connection.OfferedVersions);
        Assert.False(connection.IsDraining);
    }

    [Fact]
    public async Task AVersionNegotiationPacketThatListsTheVersionWeSelectedIsIgnored()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // RFC 9000 s6.2's THIRD normative sentence, which is the one that runs past the line
        // wrap in the extract and was missed because of it: "A client that supports only this
        // version of QUIC MUST abandon the current connection attempt if it receives a Version
        // Negotiation packet, with the following two exceptions. A client MUST discard any
        // Version Negotiation packet if it has received and successfully processed any other
        // packet, including an earlier Version Negotiation packet. A client MUST discard a
        // Version Negotiation packet that lists the QUIC version selected by the client."
        //
        // THIS IS THE ONLY REJECTION AVAILABLE TO IT. Both connection IDs are echoed exactly as
        // s17.2.1 requires, so the echo check passes; nothing has been received and processed,
        // so the second exception does not arm; and it parses. The list is the single version
        // this connection is already speaking.
        //
        // WHAT IT COSTS AN ATTACKER WITHOUT IT: one observed Initial packet. The echo check
        // proves only that the sender SAW our Initial - s17.2.1 says exactly that much,
        // "Echoing both connection IDs gives clients some assurance that ... the Version
        // Negotiation packet was not generated by an entity that did not observe the Initial
        // packet" - so an off-path sender who did observe it ends the attempt with a packet
        // that, read at face value, claims the server does not support the version it is
        // offering us. s6.2 says discard, and the count below is the discard.
        transport.EnqueueReceive(sent => VersionNegotiationDatagram(
            destinationEcho: ConnectionIdsFrom(sent).Source,
            sourceEcho: ConnectionIdsFrom(sent).Destination,
            versions: [(uint)TlsQuicVersion.Version1]));

        await connection.StartAsync(cancellation.Token);
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.IgnoredVersionNegotiationPackets);
        Assert.Equal(1, connection.UnprocessedPackets);
        Assert.Null(connection.OfferedVersions);
        Assert.False(connection.IsDraining);
        Assert.Null(connection.ClosedWith);
    }

    [Fact]
    public async Task AVersionNegotiationPacketListingOurVersionAmongOthersIsStillIgnored()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // s6.2 says "lists", not "lists only", and the difference is the whole of the guard's
        // shape: a membership test rather than an equality test on a one-element list. A packet
        // offering v2 alongside the version we already selected is still one this client
        // discards, and the row above cannot tell a membership test from an equality test.
        transport.EnqueueReceive(sent => VersionNegotiationDatagram(
            destinationEcho: ConnectionIdsFrom(sent).Source,
            sourceEcho: ConnectionIdsFrom(sent).Destination,
            versions: [0x6b3343cf, (uint)TlsQuicVersion.Version1, 0x00000002]));

        await connection.StartAsync(cancellation.Token);
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.IgnoredVersionNegotiationPackets);
        Assert.Null(connection.OfferedVersions);
    }

    [Fact]
    public async Task ADatagramShapedLikeAVersionNegotiationPacketButUnparseableIsIgnored()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // Header Form set and Version 0, which is all TlsQuicDatagramReader inspects before
        // calling this a Version Negotiation packet - then a Destination Connection ID Length
        // of 255 with no bytes behind it, which TlsQuicVersionNegotiation.TryRead rejects.
        // NOTHING MAY THROW: this is six bytes anyone can send, and RFC 9001 s5 gives the
        // packet type no protection at all.
        transport.EnqueueReceive([0xC0, 0x00, 0x00, 0x00, 0x00, 0xFF]);

        await connection.StartAsync(cancellation.Token);
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(1, connection.IgnoredVersionNegotiationPackets);
        Assert.Equal(1, connection.UnprocessedPackets);
        Assert.Null(connection.OfferedVersions);
        Assert.False(connection.IsDraining);
    }

    // ---- RFC 9000 s10.2: immediate close, and s19.17: PATH_CHALLENGE ---------------------

    [Fact]
    public async Task ClosingSendsAConnectionCloseCarryingTheSection201CodeItWasGiven()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        await connection.StartAsync(cancellation.Token);
        await connection.CloseAsync(
            TlsQuicTransportError.TransportParameterError, "witness", cancellation.Token);

        // THE FRAME IS READ OFF THE WIRE, out of a packet opened with keys a server would
        // derive, which is what makes every s7.3 test below able to assert ClosedWith instead:
        // this is the one place the property and the bytes are tied together.
        Assert.Equal(2, transport.Sent.Count);
        var plaintext = OpenOwnInitialPacket(
            transport.Sent[1].Payload, connection.OriginalDestinationConnectionId);
        var close = Assert.Single(
            FramesIn(plaintext), f => f.Type == TlsQuicFrameType.ConnectionClose);

        // s19.19, and RFC 9000 s12.4 Table 3's "ih" note - "Only a CONNECTION_CLOSE frame of
        // type 0x1c can appear in Initial or Handshake packets" - so the type is not a choice.
        Assert.Equal((ulong)TlsQuicFrameType.ConnectionClose, close.RawType);
        Assert.Equal(0x08UL, close.ErrorCode);
        Assert.Equal((ulong)TlsQuicTransportError.TransportParameterError, close.ErrorCode);
        Assert.Equal("witness"u8.ToArray(), close.ReasonPhrase.ToArray());

        Assert.Equal(TlsQuicTransportError.TransportParameterError, connection.ClosedWith);

        // s10.2: "After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the
        // closing state", which this connection implements as far as "stop sending, stop
        // delivering" and no further.
        Assert.True(connection.IsDraining);
        var stopped = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        Assert.Contains("s10.2", stopped.Message, StringComparison.Ordinal);
        Assert.Equal(2, transport.Sent.Count);
    }

    [Fact]
    public async Task APeerConnectionCloseEntersDrainingAndStopsSendingAndDelivering()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // An Initial packet carrying CONNECTION_CLOSE, which RFC 9000 s12.4 Table 3 permits
        // ("ih01"), and an ack-eliciting PING beside it. The PING is what makes the "stops
        // sending" half a claim rather than an accident: s13.2.1 would otherwise owe an ACK
        // immediately, so a connection that entered draining but kept sending would emit one.
        transport.EnqueueReceive(sent =>
        {
            var (destination, source) = ConnectionIdsFrom(sent);
            return ServerPacket(
                destination,
                destinationOnPacket: source,
                sourceOnPacket: [],
                packetNumber: 0,
                frames:
                [
                    new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping },
                    new TlsQuicFrame
                    {
                        RawType = (ulong)TlsQuicFrameType.ConnectionClose,
                        ErrorCode = (ulong)TlsQuicTransportError.ProtocolViolation,
                        ReasonPhrase = "go away"u8.ToArray(),
                    },
                ],
                useServerSecret: true);
        });

        await connection.StartAsync(cancellation.Token);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        // s10.2: "After receiving a CONNECTION_CLOSE frame, endpoints enter the draining
        // state", and s10.2.2: "an endpoint in the draining state MUST NOT send any packets."
        Assert.Contains("0xa", error.Message, StringComparison.Ordinal);
        Assert.Equal((ulong)TlsQuicTransportError.ProtocolViolation, connection.PeerCloseErrorCode);
        Assert.True(connection.IsDraining);
        Assert.Single(transport.Sent);

        // AND WE SENT NOTHING OF OUR OWN. s10.2.2: "An endpoint that receives a
        // CONNECTION_CLOSE frame MAY send a single packet containing a CONNECTION_CLOSE frame
        // before entering the draining state" - a MAY this connection declines, which is why
        // ClosedWith stays null.
        Assert.Null(connection.ClosedWith);
    }

    // TASK 9b's PATH_CHALLENGE TEST IS NOT DELETED, IT MOVED AND INVERTED. It lived here as
    // APathChallengeIsRecordedAndTheAnswerIsTheOneLevelThisPhaseCannotSend and its closing
    // assertion was that NO datagram followed, because RFC 9000 s12.4 Table 3 gives
    // PATH_RESPONSE the row "___1" and TlsQuicPacketBuilder built no short header. Task 14b
    // built one and task 14c sends it, so the assertion is now the other way round and the
    // test is TlsQuicConnectionApplicationSendTests.cs's
    // TlsQuicConnectionTests.APathChallengeIsAnsweredWithAPathResponseInAOneRttPacket -
    // filed with the send path it now exercises rather than with 9b's unusual-server cases.
    // Mutation ledger row 68 is still killed by it.

    // ============================================================================
    // THIS TEST USED TO BE AfterConfirmationThereIsNoLevelLeftForA4MinimalToCloseAt,
    // AND ITS MEANING IS INVERTED RATHER THAN ITS NAME CHANGED.
    // ============================================================================
    //
    //   It asserted `Assert.Equal(sentBefore, clientTransport.Sent.Count)` and
    //   `Assert.Null(connection.ClosedWith)` - no datagram, no recorded close - and its stated
    //   reason was "TlsQuicPacketBuilder builds no short header, so A4-minimal cannot obey it".
    //   A4 task 14b built one and 14c gave this connection ShortHeaderPlan, so the reason was
    //   stale before the assertion was: the close path walked [Handshake, Initial] on a
    //   connection where RFC 9001 s4.9 had discarded both, and wrote nothing.
    //
    //   THE MUST IT USED TO PIN AS VIOLATED IS THE ONE IT NOW PINS AS OBEYED, which is why the
    //   test is inverted in place rather than deleted and replaced: the row a reader should be
    //   able to find changing is this one. Same harness, same confirmed connection, same call.
    [Fact]
    public async Task AfterConfirmationTheCloseGoesOutInAOneRttPacketAsSection1023Requires()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // THE PEER IS DRAINED HERE, AND THAT IS LOAD-BEARING RATHER THAN TIDINESS. The pump
        // above answered HANDSHAKE_DONE with a 1-RTT ACK, so one datagram is already queued;
        // LoopbackQuicPeer.PumpOnceAsync reads ONE datagram per call, so without this the pump
        // after the close would open the ACK and the close assertions would read a stale null.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Null(serverPeer.LastConnectionClose);

        // THE TWO LEVELS THE OLD WALK USED ARE GONE, READ OFF THE KEY SET RATHER THAN ASSUMED -
        // RFC 9001 s4.9.1 discarded Initial at the first Handshake packet and s4.9.2 discarded
        // Handshake at confirmation. This is what made the old assertion true, and it is
        // asserted here so that the new one cannot be satisfied by a close that quietly went
        // out at a level s10.2.3's MUST forbids.
        Assert.True(connection.IsHandshakeConfirmed);
        Assert.Equal(
            TlsQuicKeyLevelState.Discarded,
            connection.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
        Assert.Equal(
            TlsQuicKeyLevelState.Discarded,
            connection.WriteStateOf(TlsQuicEncryptionLevel.Initial));

        // RFC 9000 s10.2.3: "After the handshake is confirmed (see Section 4.1.2 of [QUIC-TLS]),
        // an endpoint MUST send any CONNECTION_CLOSE frames in a 1-RTT packet."
        var sentBefore = clientTransport.Sent.Count;
        await connection.CloseAsync(TlsQuicTransportError.NoError, "bye", cancellation.Token);
        Assert.Equal(sentBefore + 1, clientTransport.Sent.Count);

        // AND THE PEER OPENS IT, which is the assertion the whole inversion is for. The level
        // comes off the packet THIS PEER decrypted, not off a flag the sender set: a close that
        // claimed 1-RTT and rode a long header would not reach Application here.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        var close = Assert.NotNull(serverPeer.LastConnectionClose);
        Assert.Equal(TlsQuicEncryptionLevel.Application, close.Level);

        // s19.19: "Type (i) = 0x1c..0x1d", and this is the TRANSPORT form - CloseAsync takes a
        // TlsQuicTransportError, so 0x1c is the type and the Error Code is s20.1's NO_ERROR
        // (0x00): "An endpoint uses this with CONNECTION_CLOSE to signal that the connection is
        // being closed abruptly in the absence of any error."
        Assert.Equal(0x1cUL, close.RawType);
        Assert.Equal((ulong)TlsQuicFrameType.ConnectionClose, close.RawType);
        Assert.Equal(0x00UL, close.ErrorCode);

        // s19.19's Reason Phrase, carried and NOT cleared: s10.2.3's clearing MUST applies only
        // "when converting to a CONNECTION_CLOSE of type 0x1c", and nothing was converted here.
        Assert.Equal("bye"u8.ToArray(), close.ReasonPhrase);

        Assert.Equal(TlsQuicTransportError.NoError, connection.ClosedWith);
        Assert.Null(connection.ClosedWithApplicationErrorCode);

        // s10.2: "After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the
        // closing state."
        Assert.True(connection.IsDraining);
    }

    [Fact]
    public async Task AfterConfirmationAnApplicationCloseGoesOutAsSection1919sType0x1d()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // THE PEER IS DRAINED HERE, AND THAT IS LOAD-BEARING RATHER THAN TIDINESS. The pump
        // above answered HANDSHAKE_DONE with a 1-RTT ACK, so one datagram is already queued;
        // LoopbackQuicPeer.PumpOnceAsync reads ONE datagram per call, so without this the pump
        // after the close would open the ACK and the close assertions would read a stale null.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Null(serverPeer.LastConnectionClose);

        // RFC 9114 s8.1's H3_MISSING_SETTINGS (0x010a), which is the code C11's HTTP/3
        // connection had no way to put on the wire. IT IS ALSO INSIDE RFC 9000 s20.1's
        // CRYPTO_ERROR RANGE (0x0100-0x01ff), which is the whole reason the two spaces cannot
        // share one property: as a transport code this value would name a handshake failure.
        const ulong H3MissingSettings = 0x010a;

        var sentBefore = clientTransport.Sent.Count;
        await connection.CloseWithApplicationErrorAsync(
            H3MissingSettings, "no settings", cancellation.Token);
        Assert.Equal(sentBefore + 1, clientTransport.Sent.Count);

        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        var close = Assert.NotNull(serverPeer.LastConnectionClose);

        // s19.19: "The CONNECTION_CLOSE frame with a type of 0x1d is used to signal an error
        // with the application that uses QUIC", and s12.4 Table 3 gives 0x1d the row "__01" -
        // so the level below is not a preference, it is the only column the row permits.
        Assert.Equal(0x1dUL, close.RawType);
        Assert.Equal(TlsQuicEncryptionLevel.Application, close.Level);

        // s19.19: "A CONNECTION_CLOSE frame of type 0x1d uses codes defined by the application
        // protocol" - so the code arrives UNTRANSLATED, which is the half a 0x1c close cannot
        // do and the half TlsQuicHttp3Connection had to give up when it mapped onto
        // APPLICATION_ERROR and put the s8.1 code in the reason phrase instead.
        Assert.Equal(H3MissingSettings, close.ErrorCode);
        Assert.NotEqual((ulong)TlsQuicTransportError.ApplicationError, close.ErrorCode);
        Assert.Equal("no settings"u8.ToArray(), close.ReasonPhrase);

        Assert.Equal(H3MissingSettings, connection.ClosedWithApplicationErrorCode);

        // NOT REPORTED AS A TRANSPORT CLOSE, which is the property pair's whole point: nothing
        // in s20.1 was sent, so nothing in s20.1 is reported.
        Assert.Null(connection.ClosedWith);
        Assert.True(connection.IsDraining);
    }

    // RFC 9000 s10.2.3's conversion, in the one window where it can be reached: the client has
    // Handshake write keys and no Application ones, so an application close cannot be sent as
    // s19.19's 0x1d - s12.4 Table 3's "__01" row forbids it in a Handshake packet - and
    // s10.2.3 says what to do instead rather than leaving the connection unclosable.
    [Fact]
    public async Task AnApplicationCloseBeforeOneRttKeysIsConvertedToType0x1cAndLosesItsReason()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        // NOT CONFIRMED AND NOT EVEN HANDSHAKING: after StartAsync the only write keys are
        // Initial, so s12.4 Table 3's "ih01" row is what the frame must satisfy and its "i"
        // cell is the legend's "Only a CONNECTION_CLOSE frame of type 0x1c can appear in
        // Initial or Handshake packets".
        await connection.StartAsync(cancellation.Token);
        Assert.False(connection.IsHandshakeConfirmed);

        await connection.CloseWithApplicationErrorAsync(
            0x010a, "leaks application state", cancellation.Token);

        Assert.Equal(2, transport.Sent.Count);
        var plaintext = OpenOwnInitialPacket(
            transport.Sent[1].Payload, connection.OriginalDestinationConnectionId);
        var close = Assert.Single(
            FramesIn(plaintext), f => f.Type == TlsQuicFrameType.ConnectionClose);

        // s10.2.3: "A CONNECTION_CLOSE of type 0x1d MUST be replaced by a CONNECTION_CLOSE of
        // type 0x1c when sending the frame in Initial or Handshake packets."
        Assert.Equal((ulong)TlsQuicFrameType.ConnectionClose, close.RawType);
        Assert.NotEqual(0x1dUL, close.RawType);

        // s10.2.3: "SHOULD use the APPLICATION_ERROR code when converting", and s20.1 puts
        // APPLICATION_ERROR at 0x0c. THE APPLICATION CODE IS GONE, which is the point of the
        // rule rather than a loss: "Otherwise, information about the application state might
        // be revealed."
        Assert.Equal((ulong)TlsQuicTransportError.ApplicationError, close.ErrorCode);
        Assert.Equal(0x0cUL, close.ErrorCode);
        Assert.NotEqual(0x010aUL, close.ErrorCode);

        // s10.2.3: "Endpoints MUST clear the value of the Reason Phrase field". EMPTY RATHER
        // THAN ABSENT - s19.19 has no way to omit it, so the MUST is satisfied by a Reason
        // Phrase Length of 0, and this asserts the bytes are gone rather than merely different.
        Assert.Empty(close.ReasonPhrase.ToArray());

        // The conversion is visible in what the connection reports, not only on the wire: a
        // converted close carried an s20.1 code, so that is the property that is set.
        Assert.Equal(TlsQuicTransportError.ApplicationError, connection.ClosedWith);
        Assert.Null(connection.ClosedWithApplicationErrorCode);
        Assert.True(connection.IsDraining);
    }

    // "Nothing on this path throws for any input", asked of the two arguments that are not
    // enums: an application error code is a bare ulong from whatever protocol ALPN chose, and a
    // reason phrase is a bare string. RFC 9000 s20 bounds the first - "QUIC transport error
    // codes and application error codes are 62-bit unsigned integers" - and s19.19 bounds the
    // second by the packet: "Because a CONNECTION_CLOSE frame cannot be split between packets,
    // any limits on packet size will also limit the space available for a reason phrase."
    [Fact]
    public async Task AnUnencodableApplicationErrorCodeIsConvertedRatherThanThrown()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // THE PEER IS DRAINED HERE, AND THAT IS LOAD-BEARING RATHER THAN TIDINESS. The pump
        // above answered HANDSHAKE_DONE with a 1-RTT ACK, so one datagram is already queued;
        // LoopbackQuicPeer.PumpOnceAsync reads ONE datagram per call, so without this the pump
        // after the close would open the ACK and the close assertions would read a stale null.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Null(serverPeer.LastConnectionClose);

        // ONE PAST s20's 62-BIT CEILING, so the varint writer cannot encode it and the frame
        // writer's RequireEncodableVarint would throw if it ever saw it. A CLOSE STILL GOES
        // OUT: dropping the teardown because a caller's code was too wide would leave the peer
        // on RFC 9000 s10.1's idle timeout, which is the failure this whole task is closing.
        var tooWide = QuicVariableLengthInteger.MaximumValue + 1;
        var sentBefore = clientTransport.Sent.Count;
        await connection.CloseWithApplicationErrorAsync(tooWide, "dropped", cancellation.Token);
        Assert.Equal(sentBefore + 1, clientTransport.Sent.Count);

        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        var close = Assert.NotNull(serverPeer.LastConnectionClose);

        // CONVERTED BY s10.2.3's RULE, applied to the second situation that makes the code
        // uncarryable rather than only to the one about packet types: 0x1c, APPLICATION_ERROR,
        // and a cleared Reason Phrase. The level is still 1-RTT, because that is not what
        // failed - s10.2.3's MUST still binds a confirmed connection.
        Assert.Equal((ulong)TlsQuicFrameType.ConnectionClose, close.RawType);
        Assert.Equal((ulong)TlsQuicTransportError.ApplicationError, close.ErrorCode);
        Assert.Empty(close.ReasonPhrase);
        Assert.Equal(TlsQuicEncryptionLevel.Application, close.Level);

        Assert.Equal(TlsQuicTransportError.ApplicationError, connection.ClosedWith);
        Assert.Null(connection.ClosedWithApplicationErrorCode);
        Assert.True(connection.IsDraining);
    }

    // THE BOUNDARY ITSELF, which the row above misses by one. RFC 9000 s20 makes the ceiling
    // INCLUSIVE - "62-bit unsigned integers" - so the largest legal application error code is
    // (1 << 62) - 1 and it must travel as itself, not as a conversion.
    [Fact]
    public async Task TheLargestEncodableApplicationErrorCodeIsSentRatherThanConverted()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // THE PEER IS DRAINED HERE, AND THAT IS LOAD-BEARING RATHER THAN TIDINESS. The pump
        // above answered HANDSHAKE_DONE with a 1-RTT ACK, so one datagram is already queued;
        // LoopbackQuicPeer.PumpOnceAsync reads ONE datagram per call, so without this the pump
        // after the close would open the ACK and the close assertions would read a stale null.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Null(serverPeer.LastConnectionClose);

        var sentBefore = clientTransport.Sent.Count;
        await connection.CloseWithApplicationErrorAsync(
            QuicVariableLengthInteger.MaximumValue, "at the ceiling", cancellation.Token);

        // ASSERTED BEFORE THE PEER IS PUMPED, so that a close which never left fails HERE
        // rather than hanging the peer on a datagram that is not coming.
        Assert.Equal(sentBefore + 1, clientTransport.Sent.Count);
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        var close = Assert.NotNull(serverPeer.LastConnectionClose);

        // 0x1d AND THE CODE ITSELF: an off-by-one in the encodability test would convert this
        // to 0x1c with APPLICATION_ERROR and an empty reason, which is what the row above pins
        // for the value ONE HIGHER. The two rows together fix the comparison exactly.
        Assert.Equal(0x1dUL, close.RawType);
        Assert.Equal(QuicVariableLengthInteger.MaximumValue, close.ErrorCode);
        Assert.Equal("at the ceiling"u8.ToArray(), close.ReasonPhrase);
        Assert.Equal(QuicVariableLengthInteger.MaximumValue, connection.ClosedWithApplicationErrorCode);
        Assert.Null(connection.ClosedWith);
    }

    // THE TRANSPORT SPACE HAS NO SUBSTITUTE CODE, so an unencodable one sends NOTHING - and
    // "nothing" has to be asserted as nothing rather than inferred from the absence of a throw.
    // RFC 9000 s10.2's closing state is entered regardless: "After sending a CONNECTION_CLOSE
    // frame, an endpoint immediately enters the closing state", and a connection that could not
    // send one is closing whether or not the peer can be told.
    [Fact]
    public async Task AnUnencodableTransportErrorCodeSendsNothingAndStillEntersTheClosingState()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = Connection(transport, pki);

        await connection.StartAsync(cancellation.Token);
        var sentBefore = transport.Sent.Count;

        // s20 again, cast onto the enum because that is the only way a caller can express a
        // value s20.1 never assigned - and the close path must not throw on it.
        await connection.CloseAsync(
            (TlsQuicTransportError)(QuicVariableLengthInteger.MaximumValue + 1),
            "unsendable",
            cancellation.Token);

        Assert.Equal(sentBefore, transport.Sent.Count);

        // NEITHER PROPERTY IS SET, because neither frame was built. A close recorded without a
        // datagram would be the exact defect this whole task removed from the confirmed path.
        Assert.Null(connection.ClosedWith);
        Assert.Null(connection.ClosedWithApplicationErrorCode);
        Assert.True(connection.IsDraining);
    }

    [Fact]
    public async Task AReasonPhraseTooLongForAPacketIsTruncatedOnAUtf8BoundaryRatherThanThrown()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // THE PEER IS DRAINED HERE, AND THAT IS LOAD-BEARING RATHER THAN TIDINESS. The pump
        // above answered HANDSHAKE_DONE with a 1-RTT ACK, so one datagram is already queued;
        // LoopbackQuicPeer.PumpOnceAsync reads ONE datagram per call, so without this the pump
        // after the close would open the ACK and the close assertions would read a stale null.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Null(serverPeer.LastConnectionClose);

        // U+00E9 IS TWO UTF-8 BYTES, WHICH IS THE WHOLE POINT OF THE CHARACTER CHOSEN: 512 is
        // even and the character is two bytes wide, so a cut at exactly 512 bytes lands
        // BETWEEN characters here - and a naive `bytes[..512]` on an ODD-width character would
        // not. The odd case is the row below.
        var wide = new string('é', 4000);
        var sentBefore = clientTransport.Sent.Count;
        await connection.CloseAsync(TlsQuicTransportError.NoError, wide, cancellation.Token);
        Assert.Equal(sentBefore + 1, clientTransport.Sent.Count);

        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        var close = Assert.NotNull(serverPeer.LastConnectionClose);

        // s19.19's Reason Phrase "SHOULD be a UTF-8 encoded string [RFC3629]", so what arrived
        // must round-trip through a STRICT decoder. Encoding.UTF8 alone replaces bad bytes with
        // U+FFFD and would pass against a cut through a character; this throws instead.
        var strict = new System.Text.UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        var decoded = strict.GetString(close.ReasonPhrase);
        Assert.Equal(new string('é', 256), decoded);
        Assert.Equal(512, close.ReasonPhrase.Length);
    }

    [Fact]
    public async Task AThreeByteCharacterStraddlingTheReasonPhraseCapIsDroppedWhole()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // THE PEER IS DRAINED HERE, AND THAT IS LOAD-BEARING RATHER THAN TIDINESS. The pump
        // above answered HANDSHAKE_DONE with a 1-RTT ACK, so one datagram is already queued;
        // LoopbackQuicPeer.PumpOnceAsync reads ONE datagram per call, so without this the pump
        // after the close would open the ACK and the close assertions would read a stale null.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Null(serverPeer.LastConnectionClose);

        // U+20AC IS THREE UTF-8 BYTES AND 512 IS NOT A MULTIPLE OF THREE, so the 171st
        // character starts at byte 510 and would be cut after two of its three bytes. THIS IS
        // THE ROW A `bytes[..512]` IMPLEMENTATION FAILS and the even-width row above passes.
        var sentBefore = clientTransport.Sent.Count;
        await connection.CloseAsync(
            TlsQuicTransportError.NoError, new string('€', 4000), cancellation.Token);

        // ASSERTED BEFORE THE PEER IS PUMPED, for the reason given on the row above.
        Assert.Equal(sentBefore + 1, clientTransport.Sent.Count);
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        var close = Assert.NotNull(serverPeer.LastConnectionClose);

        // 170 whole characters, 510 bytes - SHORTER THAN THE CAP, because the boundary is where
        // a character ends rather than where the budget does.
        var strict = new System.Text.UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        Assert.Equal(new string('€', 170), strict.GetString(close.ReasonPhrase));
        Assert.Equal(510, close.ReasonPhrase.Length);
    }

    // ---- RFC 9000 s10.1: idle timeout ----------------------------------------------------

    [Fact]
    public async Task TheIdleTimeoutFiresOnTheFakeClockWithNoWallClockTimeElapsed()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // A MINUTE OF IDLE AGAINST AN HOUR OF DEADLINE, and a reply two hours late. Only the
        // idle timeout can fire first, and no real run can have waited out any of the three.
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromHours(1),
            idleTimeout: TimeSpan.FromHours(3),
            maxIdleTimeoutMilliseconds: 60_000);
        transport.EnqueueReceive([1, 2, 3, 4], delay: TimeSpan.FromHours(2));

        await connection.StartAsync(cancellation.Token);
        Assert.Equal(TimeSpan.FromSeconds(60), connection.EffectiveIdleTimeout());

        var wallClock = Stopwatch.StartNew();
        var error = await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        wallClock.Stop();

        Assert.True(
            wallClock.Elapsed < TimeSpan.FromSeconds(30),
            $"The idle timeout took {wallClock.Elapsed} of wall-clock time, so it did not fire "
                + "off the injected clock.");
        Assert.Equal(TimeSpan.FromHours(2), transport.Clock.GetUtcNow() - StartOfScriptedTime);

        Assert.True(connection.IdleTimedOut);
        Assert.Contains("s10.1", error.Message, StringComparison.Ordinal);

        // s10.1: "the connection is SILENTLY closed and its state is discarded" - so the one
        // datagram on the wire is the opening flight and there is no CONNECTION_CLOSE behind
        // it. The peer's own timer is expiring at the same moment, which is what the
        // minimum-of-both rule buys and what makes silence correct rather than rude.
        Assert.Single(transport.Sent);
        Assert.Null(connection.ClosedWith);
    }

    [Fact]
    public async Task AbandoningBeforeTheAdvertisedIdleTimeoutSendsTheCloseItCommittedTo()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // THREE HOURS ADVERTISED, ONE HOUR OF DEADLINE. s10.1: "By announcing a
        // max_idle_timeout, an endpoint commits to initiating an immediate close (Section 10.2)
        // if it abandons the connection prior to the effective value." The handshake deadline
        // is exactly that abandonment - local policy with no RFC source - so the commitment
        // falls due, and this is the only test in which it does.
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromHours(1),
            idleTimeout: TimeSpan.FromHours(4),
            maxIdleTimeoutMilliseconds: 3 * 60 * 60 * 1000);
        transport.EnqueueReceive([1, 2, 3, 4], delay: TimeSpan.FromHours(2));

        await connection.StartAsync(cancellation.Token);
        var error = await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        Assert.False(connection.IdleTimedOut);
        Assert.Contains("NOT A RETRANSMISSION", error.Message, StringComparison.Ordinal);

        // s20.1 NO_ERROR (0x00): "An endpoint uses this with CONNECTION_CLOSE to signal that
        // the connection is being closed abruptly in the absence of any error."
        Assert.Equal(2, transport.Sent.Count);
        Assert.Equal(TlsQuicTransportError.NoError, connection.ClosedWith);
        var close = Assert.Single(
            FramesIn(OpenOwnInitialPacket(
                transport.Sent[1].Payload, connection.OriginalDestinationConnectionId)),
            f => f.Type == TlsQuicFrameType.ConnectionClose);
        Assert.Equal(0UL, close.ErrorCode);
    }

    [Theory]
    [InlineData(60_000UL, 90_000UL, 60)]
    [InlineData(90_000UL, 60_000UL, 60)]
    public async Task TheEffectiveIdleTimeoutIsTheMinimumOfTheTwoAdvertisedValues(
        ulong ours, ulong theirs, int expectedSeconds)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();

        // RFC 9000 s10.1, past the wrap that makes it look like a simple minimum: "the
        // effective value at an endpoint is computed as the minimum of the two advertised
        // values (or the sole advertised value, if only one endpoint advertises a non-zero
        // value)." TWO ROWS THAT SWAP WHICH SIDE IS SMALLER, so an implementation that always
        // took its own value fails the second and one that always took the peer's fails the
        // first.
        await using var connection = Connection(
            new TlsQuicConnectionOptions(
                clientTransport, serverTransport.LocalEndPoint, Spec()),
            pki,
            maxIdleTimeoutMilliseconds: ours);
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            maxIdleTimeoutMilliseconds: theirs);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);

        // Before the peer is heard from, only our own value is known - s10.1's "or the sole
        // advertised value" case, reached here on the way past rather than by a separate test.
        Assert.Equal(TimeSpan.FromMilliseconds(ours), connection.EffectiveIdleTimeout());

        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(
            TimeSpan.FromSeconds(expectedSeconds), connection.EffectiveIdleTimeout());
    }

    [Fact]
    public async Task APeerAdvertisingTheLargestVarintIdleTimeoutSaturatesRatherThanOverflowing()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(
            new TlsQuicConnectionOptions(clientTransport, serverTransport.LocalEndPoint, Spec()),
            pki);

        // RFC 9000 s18.2 states max_idle_timeout in milliseconds with no ceiling but the
        // varint's, and s16's largest is 2^62-1 - about 146 million years, which overflows both
        // TimeSpan and every DateTimeOffset sum built from one. A PEER CHOOSES THIS NUMBER, so
        // an arithmetic overflow here would be a remote kill switch reachable from one legal
        // transport parameter.
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            maxIdleTimeoutMilliseconds: (1UL << 62) - 1);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(TimeSpan.FromDays(365), connection.EffectiveIdleTimeout());
    }

    [Fact]
    public async Task APeerThatGoesSilentIsBoundedByTheIdleTimeoutToo()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // THE OTHER HALF OF THE MECHANISM, AND THE ONE THAT RUNS ON A REAL TIMER. A peer that
        // answers LATE is caught by the GetUtcNow comparison after the receive returns; a peer
        // that goes SILENT never produces a clock reading at all, so only the token source
        // bounding the await can end it. So this one costs 250 ms of wall clock and says so,
        // exactly as the handshake deadline's silent half does.
        //
        // TimeProvider.System BY NAME, WHICH IT DID NOT USED TO NEED. This comment used to end
        // "a ManualTimeProvider that overrides GetUtcNow and nothing else inherits the REAL
        // timer", and that was true until A3-1 overrode CreateTimer as well - at which point
        // this test stopped firing on any clock and waited out its own 60-second token. The
        // real timer is what it means to pin, so it now asks for the real clock by name, the
        // way APeerThatGoesSilentIsBoundedByTheDeadlineToo always has. A3's own silent-peer
        // test drives the fake clock instead and is a different claim:
        // TlsQuicConnectionTests.ADroppedInitialEndsTheAttemptOnTheHandshakeDeadlineRather
        // ThanRecovering.
        //
        // WHAT IT PINS THAT THE FAKE-CLOCK TEST CANNOT: that the receive is bounded by the
        // NEARER of the two deadlines. With the idle bound dropped, this waits out the 30-second
        // handshake deadline instead, which the elapsed assertion below catches.
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromSeconds(30),
            idleTimeout: TimeSpan.FromMilliseconds(250),
            clock: TimeProvider.System);

        await connection.StartAsync(cancellation.Token);

        var wallClock = Stopwatch.StartNew();
        var error = await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        wallClock.Stop();

        Assert.True(
            wallClock.Elapsed < TimeSpan.FromSeconds(10),
            $"The idle timeout took {wallClock.Elapsed}, so the receive was bounded by the "
                + "handshake deadline rather than by the nearer idle deadline.");
        Assert.True(connection.IdleTimedOut);
        Assert.Contains("s10.1", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AProcessedPacketRestartsTheIdleTimer()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // RFC 9000 s10.1: "An endpoint restarts its idle timer when a packet from its peer is
        // received and processed successfully." TWO REPLIES, EACH FIFTY SECONDS LATE, AGAINST A
        // SIXTY-SECOND IDLE TIMEOUT: the pair only survives if the first restarts the timer,
        // and a connection that measured idleness from the start of the attempt would give up
        // on the second at a hundred seconds.
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromMinutes(10),
            idleTimeout: TimeSpan.FromSeconds(60));

        var serverSource = Convert.FromHexString("5E5E5E");
        transport.EnqueueReceive(
            sent => ServerInitialReply(sent, serverSource), delay: TimeSpan.FromSeconds(50));
        transport.EnqueueReceive(
            sent => ServerInitialReply(sent, serverSource), delay: TimeSpan.FromSeconds(50));

        await connection.StartAsync(cancellation.Token);
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.False(connection.IdleTimedOut);
        Assert.Equal(
            TimeSpan.FromSeconds(100), transport.Clock.GetUtcNow() - StartOfScriptedTime);
    }

    [Fact]
    public async Task ARetryAnswerDoesNotRestartTheIdleTimerBecauseNothingHasBeenReceived()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // RFC 9000 s10.1's CONDITION, which AProcessedPacketRestartsTheIdleTimer does not reach
        // and which nothing reached until this test: "An endpoint also restarts its idle timer
        // when sending an ack-eliciting packet IF NO OTHER ACK-ELICITING PACKETS HAVE BEEN SENT
        // SINCE LAST RECEIVING AND PROCESSING A PACKET."
        //
        // A RETRY ANSWER IS THE SECOND ACK-ELICITING SEND IN A SILENCE THAT NEVER BROKE. The
        // opening flight is the first. A Retry reaches no AEAD - s17.2.5, "A Retry packet does
        // not contain any protected fields" - so it sets neither "received and processed" nor
        // the idle timer, and at the answer NOTHING has been received and processed since the
        // opening flight went out. So the condition is FALSE and the timer must not restart.
        //
        // NINE MINUTES INTO A TEN-MINUTE BOUND, ANSWERED, THEN A DATAGRAM AT ELEVEN. If the
        // answer restarts the timer the deadline moves to nineteen minutes and the datagram at
        // eleven arrives comfortably inside it; if it does not, the deadline stands at ten and
        // the eleven-minute datagram is already too late. The two readings differ by whether
        // this throws, which is what makes them separable at all - and both of them passed the
        // whole 1104-test gate before this test existed.
        await using var connection = Connection(
            transport,
            pki,
            handshakeDeadline: TimeSpan.FromHours(1),
            idleTimeout: TimeSpan.FromMinutes(10));

        transport.EnqueueReceive(
            sent => RetryDatagram(
                sent,
                serverSourceConnectionId: Convert.FromHexString("5E5E5E"),
                token: Convert.FromHexString("7E57C0DE")),
            delay: TimeSpan.FromMinutes(9));
        transport.EnqueueReceive([1, 2, 3, 4], delay: TimeSpan.FromMinutes(2));

        await connection.StartAsync(cancellation.Token);

        // The Retry is valid and IS acted on - the second datagram on the wire is its answer -
        // so this pins the no-restart against a Retry that was accepted, not one that was
        // discarded on some other rule.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(2, transport.Sent.Count);
        Assert.Equal(
            Convert.FromHexString("5E5E5E"), connection.RetrySourceConnectionId!.Value.ToArray());

        var wallClock = Stopwatch.StartNew();
        var error = await Assert.ThrowsAsync<TimeoutException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        wallClock.Stop();

        Assert.True(
            wallClock.Elapsed < TimeSpan.FromSeconds(30),
            $"The idle timeout took {wallClock.Elapsed} of wall-clock time, so it did not fire "
                + "off the injected clock.");
        Assert.True(connection.IdleTimedOut);
        Assert.Contains("s10.1", error.Message, StringComparison.Ordinal);
    }

    // ---- RFC 9000 s7.3: authenticating connection IDs ------------------------------------

    [Fact]
    public async Task AConformingServersConnectionIdParametersPassSection73()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        // THE CONTROL FOR EVERY MISMATCH BELOW. Without it, a check that rejected EVERY server
        // would pass all six of them, which is the "witness that cannot fail" inverted.
        Assert.True(connection.IsHandshakeComplete);
        Assert.Null(connection.ClosedWith);
        Assert.False(connection.IsDraining);
    }

    [Theory]
    [InlineData("original_destination_connection_id (0x00)")]
    [InlineData("initial_source_connection_id (0x0F)")]
    public async Task AServerConnectionIdParameterThatDoesNotMatchClosesWithTransportParameterError(
        string parameter)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);

        // EIGHT BYTES CHOSEN HERE, and the values they must match are drawn from a CSPRNG per
        // attempt - so this is a mismatch by construction rather than by a comparison this test
        // performs. One parameter is doctored per row; the other stays conforming, so the
        // failing branch belongs to exactly one comparison.
        var wrong = Convert.FromHexString("F0F1F2F3F4F5F6F7");
        var isOriginal = parameter.StartsWith("original", StringComparison.Ordinal);
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            overrideOriginalDestination: isOriginal ? wrong : null,
            overrideInitialSource: isOriginal ? null : wrong);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        // s7.3: "a mismatch between values received from a peer in these transport parameters
        // and the value sent in the corresponding Destination or Source Connection ID fields of
        // Initial packets" is one of the three arms s7.3 lets an endpoint report as either
        // TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION. s20.1 settles it: 0x08 is defined to
        // cover parameters that "included an invalid value", and 0x0a is defined as compliance
        // errors "not covered by more specific error codes".
        Assert.Contains(parameter, error.Message, StringComparison.Ordinal);
        Assert.Contains("f0f1f2f3f4f5f6f7", error.Message, StringComparison.Ordinal);
        Assert.Equal(TlsQuicTransportError.TransportParameterError, connection.ClosedWith);
        Assert.True(connection.IsDraining);

        // s10.2.3: "Generally, this means sending the frame in a packet with the highest level
        // of packet protection to avoid the packet being discarded." Handshake keys exist by
        // now, so the close goes out at Handshake and not at Initial - READ OFF THE PROTECTED
        // PACKET, because RFC 9000 s17.2's Long Packet Type bits sit above the four bits RFC
        // 9001 s5.4.1's header protection masks, so they are legible without any key at all.
        var closeDatagram = clientTransport.Sent[^1];
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(closeDatagram, out var closeHeader, out _));
        Assert.Equal(TlsQuicLongPacketType.Handshake, closeHeader.Type);
    }

    [Fact]
    public async Task AnInjectedFirstInitialDoesNotMoveTheDestinationConnectionId()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);

        // THE ATTACK RFC 9000 s7.3 NAMES, BUILT - AND SINCE AUDIT FINDING 7 IT COSTS NOTHING AT
        // ALL. s7.3's purpose clause is the sentence that used to be the only thing standing
        // behind the adoption: "Including connection ID values in transport parameters and
        // verifying them ensures that an attacker cannot influence the choice of connection ID
        // for a successful connection by injecting packets carrying attacker-chosen connection
        // IDs during the handshake." Note what it promises and what it does not - no SUCCESSFUL
        // connection is influenced. The attempt still died, on every injection, from anywhere on
        // the internet, with no key material at all.
        //
        // ZERO KEY MATERIAL IS STILL NEEDED TO SEND THIS PACKET, which is exactly why the
        // adoption may not read it. Our Initial Destination Connection ID travels in the clear
        // - RFC 9001 s5.2 keys the Initial secrets from it, so it cannot be hidden - so an
        // off-path sender who observes or guesses it can put this long header on the path ahead
        // of the server's reply. It is sealed with s5.2's CLIENT secret, so a client cannot
        // open it; the adoption used to run before _receiver.Receive and take its Source
        // Connection ID anyway, and _adoptedServerConnectionId latched, so the genuine server
        // packet could never correct it.
        var attackerConnectionId = Convert.FromHexString("ADADADADADADADAD");
        await serverTransport.SendAsync(
            clientTransport.LocalEndPoint,
            ClientSecretInitialReply(
                [new ScriptedSend(serverTransport.LocalEndPoint, clientTransport.Sent[0])],
                attackerConnectionId),
            cancellation.Token);

        // The forgery is discarded by the AEAD and does NOT end the attempt - s12.2 - and it now
        // takes nothing with it: s7.2's adoption sits behind `outcome.Processed > 0`, which this
        // packet never reaches.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(1, connection.DiscardedPackets);
        Assert.NotEqual(attackerConnectionId, connection.DestinationConnectionId.ToArray());
        Assert.Equal(
            connection.OriginalDestinationConnectionId.ToArray(),
            connection.DestinationConnectionId.ToArray());

        // The honest server now answers, and its flight opens perfectly well: the AEAD key comes
        // from the Destination Connection ID of our FIRST Initial packet, not from the field on
        // any later one, so the injection could not have stopped it either.
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // AND THE HANDSHAKE PROCEEDS RATHER THAN CLOSING. This is the whole of the finding: the
        // same script used to end here in a TRANSPORT_PARAMETER_ERROR raised by s7.3 against the
        // attacker's value, which is a connection killed by a stranger's datagram. s7.3 still
        // runs - AConformingServersConnectionIdParametersPassSection73 is its witness - it just
        // has nothing to catch, because the value it checks was never moved.
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Null(connection.ClosedWith);
        Assert.False(connection.IsDraining);

        // We are addressing the server's Source Connection ID, taken from the packet its AEAD
        // opened - not the attacker's, and not our own draw any more either.
        Assert.Equal(
            serverPeer.SourceConnectionId.ToArray(),
            connection.DestinationConnectionId.ToArray());
    }

    [Theory]
    [InlineData("original_destination_connection_id (0x00)")]
    [InlineData("initial_source_connection_id (0x0F)")]
    public async Task AServerThatOmitsAConnectionIdParameterClosesWithTransportParameterError(
        string parameter)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);

        // s7.3, and this arm is NOT one of the three where the code is a choice: "An endpoint
        // MUST treat the absence of the initial_source_connection_id transport parameter from
        // either endpoint or the absence of the original_destination_connection_id transport
        // parameter from the server as a connection error of type TRANSPORT_PARAMETER_ERROR."
        var isOriginal = parameter.StartsWith("original", StringComparison.Ordinal);
        var parameters = new List<TlsQuicTransportParameter>
        {
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.ActiveConnectionIdLimit, 4),
        };
        if (!isOriginal)
        {
            parameters.Add(new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.OriginalDestinationConnectionId,
                connection.OriginalDestinationConnectionId.Span));
        }
        else
        {
            parameters.Add(new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
                connection.OriginalDestinationConnectionId.Span));
        }

        await using var server = ServerWith(
            credential, new TlsQuicTransportParameters(parameters));
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        Assert.Contains($"{parameter} is absent", error.Message, StringComparison.Ordinal);
        Assert.Equal(TlsQuicTransportError.TransportParameterError, connection.ClosedWith);
    }

    [Fact]
    public async Task ARetrySourceConnectionIdSentWithoutARetryClosesWithTransportParameterError()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);

        // s7.3: "presence of the retry_source_connection_id transport parameter when no Retry
        // packet was received" - which s20.1's 0x08 names directly as "included a forbidden
        // transport parameter".
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            retrySource: Convert.FromHexString("A1A2A3A4A5A6A7A8"));
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        Assert.Contains(
            "retry_source_connection_id (0x10) is present although no Retry packet was received",
            error.Message,
            StringComparison.Ordinal);
        Assert.Equal(TlsQuicTransportError.TransportParameterError, connection.ClosedWith);
    }

    [Theory]
    [InlineData(RetryParameterCase.Correct)]
    [InlineData(RetryParameterCase.Mismatched)]
    [InlineData(RetryParameterCase.Absent)]
    public async Task AHandshakeAfterARetryValidatesRetrySourceConnectionId(
        RetryParameterCase parameterCase)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);

        // RFC 9000 s7.3, Figure 8's whole exchange in one test: the client's first Initial
        // carries DCID=S1, the Retry answers with SCID=S2, the client's second Initial carries
        // DCID=S2, and the server's transport parameters then owe
        // original_destination_connection_id=S1 and retry_source_connection_id=S2.
        var s1 = connection.OriginalDestinationConnectionId.ToArray();
        var s2 = Convert.FromHexString("A1A2A3A4A5A6A7A8");

        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            // The loopback peer echoes the Destination Connection ID it receives as its own
            // Source Connection ID, and after the Retry that is S2 - so initial_source is S2
            // here, while original_destination stays S1.
            overrideInitialSource: s2,
            retrySource: parameterCase switch
            {
                RetryParameterCase.Correct => s2,
                RetryParameterCase.Mismatched => Convert.FromHexString("BBBBBBBBBBBBBBBB"),
                _ => null,
            });
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);

        // THE SERVER CONSUMES THE FIRST INITIAL AND ANSWERS WITH A RETRY, which is what
        // s17.2.5.1 describes and what LoopbackQuicPeer cannot do itself - it has no Retry send
        // path, so the datagram is built here and the peer is left to meet the SECOND Initial
        // as its first, exactly as a real server behind a Retry does.
        var drained = new byte[65527];
        var firstInitial = await serverTransport.ReceiveAsync(drained, cancellation.Token);
        await serverTransport.SendAsync(
            clientTransport.LocalEndPoint,
            RetryDatagram(
                [new ScriptedSend(clientTransport.LocalEndPoint, drained[..firstInitial.Length])],
                s2,
                Convert.FromHexString("7E57C0DE")),
            cancellation.Token);

        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(s2, connection.DestinationConnectionId.ToArray());
        Assert.Equal(s1, connection.OriginalDestinationConnectionId.ToArray());

        // The peer meets the post-Retry Initial and derives its keys from S2 - which only works
        // because the connection really did re-derive its own from the same value.
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        if (parameterCase == RetryParameterCase.Correct)
        {
            Assert.False(await connection.PumpOnceAsync(cancellation.Token));
            Assert.True(connection.IsHandshakeComplete);
            Assert.Null(connection.ClosedWith);
            return;
        }

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        // s7.3: "absence of the retry_source_connection_id transport parameter from the server
        // after receiving a Retry packet" and the mismatch arm, both TRANSPORT_PARAMETER_ERROR
        // for the reason ValidateConnectionIdsUnderSection73 derives from s20.1.
        Assert.Contains("retry_source_connection_id (0x10)", error.Message, StringComparison.Ordinal);
        Assert.Contains(
            parameterCase == RetryParameterCase.Absent ? "is absent" : "bbbbbbbbbbbbbbbb",
            error.Message,
            StringComparison.Ordinal);
        Assert.Equal(TlsQuicTransportError.TransportParameterError, connection.ClosedWith);
    }

    public enum RetryParameterCase
    {
        Correct,
        Mismatched,
        Absent,
    }

    // ---- scaffolding ---------------------------------------------------------------------

    private static TlsQuicConnection Connection(
        TlsQuicConnectionOptions options, TestPki pki, ulong? maxIdleTimeoutMilliseconds = null) =>
        new(options,
            source => TlsClient(
                pki, source, maxIdleTimeoutMilliseconds: maxIdleTimeoutMilliseconds));

    // RFC 9000 Figure 18's Retry packet, written through the ONE encoder for it
    // (TlsQuicPacketHeader.WriteLongHeader) and tagged through the one implementation of RFC
    // 9001 s5.8 (TlsQuicRetry.ComputeTag) - the same pattern TlsQuicRetryTests uses, and for
    // the same reason: a second copy of either would be the second wire writer this phase bans.
    //
    // THE ODCID FOR THE TAG IS READ OFF THE CLIENT'S FIRST DATAGRAM, which is exactly what a
    // real server has and all it has. That is what makes a forged Retry impossible to tag
    // without seeing that packet, and it is why the corrupt-tag row below only has to change
    // one byte to become one.
    private static byte[] RetryDatagram(
        IReadOnlyList<ScriptedSend> sent,
        byte[] serverSourceConnectionId,
        byte[] token,
        bool corruptTag = false,
        TlsQuicVersion version = TlsQuicVersion.Version1)
    {
        var (originalDestination, clientSource) = ConnectionIdsFrom(sent);

        var header = new TlsQuicLongHeader
        {
            Type = TlsQuicLongPacketType.Retry,
            Version = (uint)version,

            // s17.2.5.1: "The server populates the Destination Connection ID with the connection
            // ID that the client included in the Source Connection ID of the Initial packet."
            DestinationConnectionId = clientSource,
            SourceConnectionId = serverSourceConnectionId,
            Token = token,
            RetryIntegrityTag = new byte[16],
        };

        var buffer = new byte[256];
        var written = TlsQuicPacketHeader.WriteLongHeader(buffer, header, out _);
        var packet = buffer[..written];

        var tag = new byte[16];
        TlsQuicRetry.ComputeTag(
            TlsQuicVersion.Version1, originalDestination, packet.AsSpan(..^16), tag);
        if (corruptTag)
        {
            tag[0] ^= 0xFF;
        }
        tag.CopyTo(packet.AsSpan(packet.Length - 16));
        return packet;
    }

    private static byte[] VersionNegotiationDatagram(
        byte[] destinationEcho, byte[] sourceEcho, uint[] versions)
    {
        var buffer = new byte[256];
        var written = TlsQuicVersionNegotiation.Write(
            buffer,
            new TlsQuicVersionNegotiationPacket
            {
                DestinationConnectionId = destinationEcho,
                SourceConnectionId = sourceEcho,
                SupportedVersions = versions,
            });
        return buffer[..written];
    }

    private static List<TlsQuicFrame> FramesIn(byte[] payload)
    {
        var frames = new List<TlsQuicFrame>();
        var offset = 0;
        while (offset < payload.Length)
        {
            Assert.True(
                TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out var error),
                $"A frame at offset {offset} did not decode: {error}.");
            frames.Add(frame);
        }
        return frames;
    }

    private static byte[] CryptoBytesIn(byte[] payload)
    {
        var crypto = new List<byte>();
        foreach (var frame in FramesIn(payload))
        {
            if (frame.Type == TlsQuicFrameType.Crypto)
            {
                crypto.AddRange(frame.Data.Span);
            }
        }
        Assert.NotEmpty(crypto);
        return [.. crypto];
    }
}
