using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

/// <content>
/// RFC 9000 section 5.1's connection-ID lifecycle. Every test here drives
/// <c>TlsQuicConnection.ReceiveNewConnectionId</c> directly rather than pushing a 1-RTT packet
/// through the transport, because the decisions under test are all connection STATE - which
/// sequence numbers are held, which is active, which are owed a retirement - and none of them
/// is reached by the parser, which the frame tests already cover in full.
///
/// THE CONNECTION IS STARTED FIRST IN EVERY TEST. The destination connection ID is drawn in
/// StartAsync, and s19.15's first rule turns on its length.
/// </content>
public sealed partial class TlsQuicConnectionTests
{
    private static TlsQuicFrame NewConnectionId(
        ulong sequenceNumber,
        ulong retirePriorTo,
        byte fill) =>
        new()
        {
            RawType = (ulong)TlsQuicFrameType.NewConnectionId,
            SequenceNumber = sequenceNumber,
            RetirePriorTo = retirePriorTo,
            ConnectionId = Enumerable.Repeat(fill, 8).ToArray(),
            StatelessResetToken = Enumerable.Repeat(fill, 16).ToArray(),
        };

    [Fact]
    public async Task ANewConnectionIdIsRecordedAndAnIncreasedRetirePriorToRetiresTheOldOnes()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock),
            source => TlsClient(pki, source));
        await connection.StartAsync(cancellation.Token);

        var handshakeConnectionId = connection.DestinationConnectionId.ToArray();

        // Sequence 1, retiring nothing. s19.15 makes this the ordinary case: the peer offers a
        // spare and keeps the one in use.
        Assert.True(connection.ReceiveNewConnectionId(NewConnectionId(1, 0, 0xA1), out _, out _));
        Assert.Equal(2, connection.ActivePeerConnectionIds);
        Assert.Equal(0, connection.RetireConnectionIdsSent);
        Assert.Equal(handshakeConnectionId, connection.DestinationConnectionId.ToArray());

        // Sequence 2 with Retire Prior To 2. s19.15: "Upon receipt of an increased Retire Prior
        // To field, the peer MUST stop using the corresponding connection IDs and retire them
        // with RETIRE_CONNECTION_ID frames." Both halves are asserted: the ID in use MOVES to
        // sequence 2, and 0 and 1 are owed retirements.
        Assert.True(connection.ReceiveNewConnectionId(NewConnectionId(2, 2, 0xB2), out _, out _));
        Assert.Equal(Enumerable.Repeat((byte)0xB2, 8), connection.DestinationConnectionId.ToArray());
        Assert.NotEqual(handshakeConnectionId, connection.DestinationConnectionId.ToArray());
        Assert.Equal(2, connection.RetireConnectionIdsSent);
        Assert.Equal(1, connection.ActivePeerConnectionIds);
    }

    [Fact]
    public async Task ANewConnectionIdBelowTheStandingRetirePriorToIsRetiredOnArrival()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock),
            source => TlsClient(pki, source));
        await connection.StartAsync(cancellation.Token);

        Assert.True(connection.ReceiveNewConnectionId(NewConnectionId(3, 3, 0xC3), out _, out _));
        var retiredSoFar = connection.RetireConnectionIdsSent;

        // s5.1.1: "An endpoint that receives a NEW_CONNECTION_ID frame with a sequence number
        // smaller than the Retire Prior To field of a previously received NEW_CONNECTION_ID
        // frame MUST send a corresponding RETIRE_CONNECTION_ID frame that retires the newly
        // received connection ID." Retired on arrival, and NOT counted as active - which is the
        // half that matters, because counting it would push a rotating peer over its own limit.
        var active = connection.ActivePeerConnectionIds;
        Assert.True(connection.ReceiveNewConnectionId(NewConnectionId(1, 0, 0xD4), out _, out _));

        Assert.Equal(retiredSoFar + 1, connection.RetireConnectionIdsSent);
        Assert.Equal(active, connection.ActivePeerConnectionIds);
    }

    [Fact]
    public async Task ReusingASequenceNumberForADifferentConnectionIdIsAProtocolViolation()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock),
            source => TlsClient(pki, source));
        await connection.StartAsync(cancellation.Token);

        Assert.True(connection.ReceiveNewConnectionId(NewConnectionId(1, 0, 0xA1), out _, out _));

        // A byte-identical repeat is a retransmission and s13.3 makes that ordinary.
        Assert.True(connection.ReceiveNewConnectionId(NewConnectionId(1, 0, 0xA1), out _, out _));
        Assert.Equal(2, connection.ActivePeerConnectionIds);

        // A DIFFERENT connection ID under the same sequence number is s19.15's "a sequence
        // number is used for different connection IDs", whose MAY this endpoint takes.
        Assert.False(connection.ReceiveNewConnectionId(
            NewConnectionId(1, 0, 0xEE), out var error, out var reason));
        Assert.Equal(TlsQuicTransportError.ProtocolViolation, error);
        Assert.Contains("s19.15", reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MoreConnectionIdsThanTheAdvertisedLimitIsAConnectionIdLimitError()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock),
            source => TlsClient(pki, source));
        await connection.StartAsync(cancellation.Token);

        // The helper's ClientHello advertises active_connection_id_limit = 2, and the handshake
        // connection ID is sequence 0 - so one spare fits and a second does not. s5.1.1: "An
        // endpoint that receives more connection IDs than its advertised
        // active_connection_id_limit MUST close the connection with an error of type
        // CONNECTION_ID_LIMIT_ERROR."
        Assert.Equal(2UL, TlsQuicConnection.DefaultActiveConnectionIdLimit);
        Assert.True(connection.ReceiveNewConnectionId(NewConnectionId(1, 0, 0xA1), out _, out _));

        Assert.False(connection.ReceiveNewConnectionId(
            NewConnectionId(2, 0, 0xB2), out var error, out var reason));
        Assert.Equal(TlsQuicTransportError.ConnectionIdLimitError, error);
        Assert.Contains("active_connection_id_limit", reason, StringComparison.Ordinal);
        Assert.Equal(
            TlsQuicTransportError.ConnectionIdLimitError,
            TlsQuicTransportError.ConnectionIdLimitError);
    }

    [Fact]
    public async Task ARotatingPeerNeverTripsItsOwnLimitBecauseRetirementIsCountedFirst()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock),
            source => TlsClient(pki, source));
        await connection.StartAsync(cancellation.Token);

        // THE ORDERING TRAP THIS PINS. The frame that pushes the count up is usually the same
        // frame whose Retire Prior To brings it back down - one-for-one rotation is the normal
        // case. Counting before retiring would close every such connection at the second frame,
        // and the limit here is only 2.
        for (ulong sequence = 1; sequence <= 8; sequence++)
        {
            Assert.True(
                connection.ReceiveNewConnectionId(
                    NewConnectionId(sequence, sequence, (byte)(0x10 + sequence)),
                    out var error,
                    out var reason),
                $"sequence {sequence} was refused: {error} {reason}");
        }

        Assert.Equal(1, connection.ActivePeerConnectionIds);
        Assert.Equal(8, connection.NewConnectionIdsReceived);

        // Eight arrivals, eight retirements: sequences 0 through 7. Sequence 8 is the one in
        // use and is not retired.
        Assert.Equal(8, connection.RetireConnectionIdsSent);
        Assert.Equal(
            Enumerable.Repeat((byte)0x18, 8),
            connection.DestinationConnectionId.ToArray());
    }

    [Fact]
    public async Task AnIncreasedRetirePriorToNeverLeavesTheActiveConnectionIdBelowIt()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock),
            source => TlsClient(pki, source));
        await connection.StartAsync(cancellation.Token);

        var handshakeConnectionId = connection.DestinationConnectionId.ToArray();

        // s5.1.2: "An endpoint MUST NOT use a connection ID it has retired." A Retire Prior To
        // ABOVE the active sequence must therefore move the active one, and the frame that
        // raises the floor is always able to supply the replacement: s19.15 requires "Retire
        // Prior To ... less than or equal to Sequence Number", so the arriving connection ID is
        // itself at or above the new floor. A gap here would leave this endpoint sending a
        // retired connection ID, which is the one outcome s5.1.2 names.
        //
        // 5 with a floor of 1 is the awkward shape rather than the easy one: the floor lands
        // between the handshake ID and the arriving one, so a switch is required and the
        // arriving frame is the only thing that can satisfy it.
        Assert.True(connection.ReceiveNewConnectionId(NewConnectionId(5, 1, 0xE5), out _, out _));
        Assert.Equal(
            Enumerable.Repeat((byte)0xE5, 8),
            connection.DestinationConnectionId.ToArray());
        Assert.NotEqual(handshakeConnectionId, connection.DestinationConnectionId.ToArray());

        // Sequence 0 was below the floor and is retired by number even though it never arrived
        // as a frame - see ActivePeerConnectionIds' remarks.
        Assert.Equal(1, connection.RetireConnectionIdsSent);
        Assert.Equal(1, connection.ActivePeerConnectionIds);

        // ...and a further raise moves it again, through the same path.
        Assert.True(connection.ReceiveNewConnectionId(NewConnectionId(6, 6, 0xF6), out _, out _));
        Assert.Equal(
            Enumerable.Repeat((byte)0xF6, 8),
            connection.DestinationConnectionId.ToArray());
    }
}
