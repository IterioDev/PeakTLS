using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task 14e of A4-minimal, over the task 7 loopback peer: a stream carrying bytes both ways,
// offsets and FIN round-tripping, and the peer-initiated unidirectional streams RFC 9204 s4.2
// requires this endpoint to allow.
//
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's, 14c's AND 14d's, for the reason those give: Spec,
// Connection, TlsClient, Server and FlowControlParameters are reused rather than copied, and a
// copy of any of them would be a second packet writer.
//
// ============================================================================
// WHAT THESE ASSERTIONS PIN, AND WHAT THEY CANNOT.
// ============================================================================
//
//   THE LOOPBACK SHARES OUR BUGS AND THAT IS MEASURED, NOT SUSPECTED. Task 7's inverted AEAD
//   nonce killed 0 of its 11 loopback tests while killing 18 elsewhere. Both halves here share
//   TlsQuicPacketHeader, TlsQuicHeaderProtection and TlsQuicPacketProtection, and RFC 9001
//   Appendix A publishes no 1-RTT vector, so a symmetric defect in any of the three cancels
//   exactly. "The peer received it" proves SEQUENCING.
//
//   WHAT DOES NOT CANCEL IS THE FRAME. TlsQuicStreamFrames encodes the STREAM frame on one
//   side and decodes it on the other, and its eight wire forms are pinned independently
//   against hand-derived bytes in TlsQuicStreamFramesTests - so the s19.8 field layout has
//   evidence outside this file. What these tests add on top is that the OFFSET a stream
//   chooses and the ORDER it delivers in survive a real packet: the peer reads back the offset
//   this connection put on the second frame, and a send path that restarted every frame at
//   zero would be reported here and nowhere else.
//
//   THE STREAM STATE ITSELF IS NOT SYMMETRIC. LoopbackQuicPeer has no stream implementation at
//   all - it records the four s19.8 fields and sends frames a test hands it - so nothing on
//   the far side can agree with a defect in TlsQuicStreamSet. That is the opposite of the
//   packet layer's position and it is why the peer-initiated tests below script their frames
//   by hand rather than asking the peer to "open a stream".
public sealed partial class TlsQuicConnectionTests
{
    [Fact]
    public async Task AUnidirectionalStreamCarriesItsBytesToTheLoopbackPeerWithOffsetsAndFin()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        // RFC 9000 s2.1's 0x02 row, which is what subsystem C's HTTP control stream and
        // QPACK's two streams are. THE ID IS ASSERTED HERE rather than only in the unit tests
        // because this is the value that actually goes on the wire.
        var stream = connection.Streams.OpenUnidirectional();
        Assert.Equal(2UL, stream.Id);

        connection.Streams.Send(stream, new byte[] { 0x11, 0x22, 0x33 });
        connection.Streams.Send(stream, new byte[] { 0x44, 0x55 }, fin: true);
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // THE OFFSET IS THE ASSERTION THAT MATTERS. A send path that put the right bytes at
        // the wrong offset - restarting each frame at zero, or counting frames instead of
        // bytes - passes every "the peer received it" test and fails this one.
        Assert.Equal(2, serverPeer.ReceivedStreamFrames.Count);
        AssertStreamFrame(2, 0, [0x11, 0x22, 0x33], false, serverPeer.ReceivedStreamFrames[0]);
        AssertStreamFrame(2, 3, [0x44, 0x55], true, serverPeer.ReceivedStreamFrames[1]);

        // AND THE STREAM AGREES WITH WHAT IT SENT. s19.8: "The final size of the stream is the
        // sum of the offset and the length of this frame."
        Assert.Equal(5UL, stream.SendOffset);
        Assert.True(stream.FinSent);
    }

    [Fact]
    public async Task ABidirectionalStreamCarriesBytesBothWaysOverTheLoopbackPeer()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        // s2.1's 0x00 row - the request stream shape.
        var stream = connection.Streams.OpenBidirectional();
        Assert.Equal(0UL, stream.Id);

        connection.Streams.Send(stream, new byte[] { 0xa1, 0xa2 }, fin: true);
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        AssertStreamFrame(
            0, 0, [0xa1, 0xa2], true, Assert.Single(serverPeer.ReceivedStreamFrames));

        // AND BACK, ON THE SAME STREAM, WHICH IS THE HALF A UNIDIRECTIONAL STREAM CANNOT SHOW.
        // The peer's two frames arrive in one datagram; the second carries the FIN.
        await serverPeer.SendStreamFramesAsync(
            [
                Stream(0, 0, [0xb1, 0xb2]),
                Stream(0, 2, [0xb3], fin: true),
            ],
            cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(new byte[] { 0xb1, 0xb2, 0xb3 }, stream.Received);
        Assert.True(stream.ReceiveComplete);
        Assert.Equal(3UL, stream.FinalSize);
    }

    [Fact]
    public async Task APeerInitiatedUnidirectionalStreamIsAcceptedAndItsBytesDeliveredInOrder()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        // RFC 9204 s4.2: "An endpoint MUST allow its peer to create an encoder stream and a
        // decoder stream even if the connection's settings prevent their use." THREE STREAMS
        // AT ONCE, because that is what an HTTP/3 server opens - control, QPACK encoder, QPACK
        // decoder - and it opens them before this client has said anything. Nothing here
        // opened them; s19.8's "STREAM frames implicitly create a stream" did.
        await serverPeer.SendStreamFramesAsync(
            [
                Stream(3, 0, [0xc0]),
                Stream(7, 0, [0xc1]),
                Stream(11, 0, [0xc2]),
            ],
            cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(
            new ulong[] { 3, 7, 11 },
            connection.Streams.PeerInitiated.Select(peerStream => peerStream.Id));

        // OUT OF ORDER, ACROSS TWO DATAGRAMS, AND THE LATER BYTES FIRST. This is the ordering
        // claim stated where a real packet boundary is involved: the second datagram's bytes
        // sit undelivered until the first datagram's gap is filled.
        await serverPeer.SendStreamFramesAsync([Stream(3, 3, [0xd3, 0xd4])], cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        var control = connection.Streams.Find(3)!;
        Assert.Equal(new byte[] { 0xc0 }, control.Received);

        await serverPeer.SendStreamFramesAsync(
            [Stream(3, 1, [0xd1, 0xd2], fin: false)], cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(new byte[] { 0xc0, 0xd1, 0xd2, 0xd3, 0xd4 }, control.Received);
        Assert.False(control.FinalSizeKnown);
    }

    [Fact]
    public async Task AStreamFrameOnAStreamThisClientNeverOpenedEndsTheConnection()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        // s19.8: "An endpoint MUST terminate the connection with error STREAM_STATE_ERROR if
        // it receives a STREAM frame for a locally initiated stream that has not yet been
        // created". Stream 0 is client-initiated and this client has opened nothing.
        //
        // A FAILURE AND NOT A CRASH: the refusal comes back from TlsQuicStreamSet as a value
        // and becomes this connection's failure at the same place a malformed ACK does.
        // TlsQuicStreamsTests.NoPeerControlledStreamFrameMakesTryReceiveThrow is the half that
        // pins the absence of a throw underneath.
        await serverPeer.SendStreamFramesAsync([Stream(0, 0, [0xff])], cancellation.Token);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        Assert.Contains("StreamStateError", error.Message, StringComparison.Ordinal);
        Assert.Contains("stream 0", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WhenOneDatagramCarriesTwoUnacceptableStreamFramesTheFirstIsReported()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        // FIRST FAILURE WINS, AND THIS IS THE ONLY PLACE THAT IS VISIBLE. RFC 9000 s12.2 has
        // the receiver process every frame of a datagram, so a second bad STREAM frame is
        // still walked after the first has already decided the connection is over - and the
        // code it would report describes a state the first refusal made meaningless. Both ids
        // below are client-initiated and neither was opened, so the two refusals are the same
        // kind and only their ORDER separates the messages.
        //
        // WRITTEN BECAUSE THE MUTATION SURVIVED: turning `failure ??=` into `failure =` left
        // the whole 1262-case gate green, because no other test puts two bad frames in one
        // datagram.
        await serverPeer.SendStreamFramesAsync(
            [Stream(0, 0, [0xff]), Stream(4, 0, [0xfe])], cancellation.Token);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        Assert.Contains("stream 0,", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("stream 4,", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExhaustingThePeersAdvertisedStreamCreditFailsRatherThanSendingPastIt()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,

            // RFC 9114 s6.2's floor is still met - three unidirectional streams - so what this
            // peer denies is BYTES and not streams, and the refusal below cannot be the s6.2
            // check firing instead. Four is also below s6.2's 1,024-byte SHOULD, which nothing
            // enforces; TlsQuicConnectionTests.TheThousandTwentyFourByteUnidirectionalCreditIs
            // AShouldAndIsNotEnforced is where that is pinned.
            flowControl: FlowControlParameters(uni: 4, streamsUni: 3));
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenUnidirectional();
        Assert.Equal(4UL, stream.Budget!.Limit);

        // FIVE BYTES AGAINST FOUR, AND THE FIFTH IS NOW HELD RATHER THAN REFUSED. This test
        // asserted a throw until MAX_STREAM_DATA was handled; what has NOT changed is the
        // thing the throw was protecting - the fifth byte is still not on the wire, because
        // putting it there is the flow-control violation s19.9 and s19.10 answer with
        // FLOW_CONTROL_ERROR. Only four leave.
        connection.Streams.Send(stream, new byte[] { 1, 2, 3, 4, 5 });
        Assert.Equal(4UL, stream.SendOffset);
        Assert.Equal(1UL, stream.BlockedBytes);

        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        AssertStreamFrame(
            2, 0, [1, 2, 3, 4], false, Assert.Single(serverPeer.ReceivedStreamFrames));

        // AND THE PEER WAS TOLD, IN THE SAME PACKET. s19.13: "A sender SHOULD send a
        // STREAM_DATA_BLOCKED frame (type=0x15) when it wishes to send data but is unable to
        // do so due to stream-level flow control." Read off the PEER's decode of our datagram,
        // which is the only vantage point that proves the frame was written and not merely
        // queued.
        Assert.Contains(
            (TlsQuicEncryptionLevel.Application, TlsQuicFrameType.StreamDataBlocked),
            serverPeer.LastDatagramFrames);
    }

    [Fact]
    public async Task ABodySixteenTimesThePeersInitialStreamCreditCompletesOnRealGrants()
    {
        // ============================================================================
        // THE ACCEPTANCE TEST, AND HOW THE GRANT IS PRODUCED.
        // ============================================================================
        //
        // The peer advertises initial_max_stream_data_uni of 1,024 and the body is 16,384
        // bytes - sixteen times what any part of this library could send before
        // MAX_STREAM_DATA was handled, and the shape of the ~6 MB request-body ceiling in
        // miniature. Every one of the fifteen grants below is a REAL frame: built as a
        // TlsQuicFrame, encoded by TlsQuicFlowControlFrames.WriteMaximumStreamDataFrameFields
        // through TlsQuicFrames.WriteFrame, protected by the peer's own AEAD, put on the
        // InMemoryDatagramTransport, and decoded by TlsQuicPacketReceiver on the way back in.
        // Nothing calls TryRaiseLimit directly.
        //
        // WHAT IS ASSERTED IS NOT "the body completed". A body can complete because the limit
        // was ignored, which is the defect this whole task is about - so the window is
        // measured at every step: the limit MOVES to the granted value, the send offset
        // NEVER passes it, and the run refuses to be vacuous because ProgressAt records what
        // each grant released and the assertion at the end demands fifteen distinct steps.
        //
        // THE ACK EACH ROUND IS CONGESTION CONTROL AND NOT FLOW CONTROL. A3-11's send gate is
        // a second, independent limit: sixteen unacknowledged kilobytes would exhaust the
        // initial congestion window and stall this test for a reason that has nothing to do
        // with s19.10. Acknowledging keeps that limit out of the way so the one under test is
        // the one being measured.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();

        // A MANUAL CLOCK, AND IT IS HERE FOR CONGESTION CONTROL RATHER THAN FOR FLOW CONTROL.
        // A3-11's pacer defers a send pass until its release instant, which is a third limit
        // again - a packet held by the pacer is neither flow-controlled nor
        // congestion-windowed, it is early. On the wall clock a sixteen-packet body finishes
        // in well under one pacing interval, so the run would end with packets still held and
        // report them as body bytes that never arrived. Advancing the clock between rounds
        // takes that limit out of the way; it grants no credit and moves no window.
        // AND THE PATH MTU SEARCH IS OFF, WHICH IS A FOURTH LIMIT BY THE SAME ARGUMENT. The
        // paragraph above takes the pacer out of the way and the one above that takes the
        // congestion window out of the way, both so that RFC 9000 s19.10's flow control is the
        // only limit being measured. An RFC 9000 s14.4 PMTU probe is another ack-eliciting
        // datagram competing for the same window and pacing slots, and it grants no credit
        // either. See SpecWithoutPathMtuSearch.
        var clock = new ManualTimeProvider(SentAt);
        await using var connection = Connection(
            clientTransport, serverTransport, pki, SpecWithoutPathMtuSearch(), clock: clock);
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            flowControl: FlowControlParameters(initialMaxData: 1_000_000, uni: 1024));
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        const int Step = 1024;
        const int Body = Step * 16;
        var body = new byte[Body];
        for (var i = 0; i < body.Length; i++)
        {
            body[i] = (byte)(i * 7);
        }

        var stream = connection.Streams.OpenUnidirectional();
        Assert.Equal((ulong)Step, stream.Budget!.Limit);

        connection.Streams.Send(stream, body, fin: true);
        Assert.Equal((ulong)Step, stream.SendOffset);
        Assert.Equal((ulong)(Body - Step), stream.BlockedBytes);

        // THE PEER READS EVERY DATAGRAM THE CLIENT HAS SENT AND NOT ONE PER ROUND. A3-11's
        // congestion gate and pacer can hold a pass, so a round may put nothing on the wire
        // and the next may put two packets there; a fixed one-pump-per-round drifts out of
        // step with that and leaves the tail unread - which is a congestion-control artefact
        // reported as body bytes that never arrived.
        //
        // THE COUNTER IS TAKEN BEFORE THE FIRST DATA SEND, WHICH IS THE WHOLE POINT OF THE
        // LINE. ConfirmedHandshake leaves the peer having read every datagram the client sent,
        // so this is the high-water mark of what is already consumed; taking it one line later
        // would leave the peer permanently one datagram behind and lose exactly the last one.
        var read = clientTransport.Sent.Count;
        async Task DrainToPeerAsync()
        {
            while (read < clientTransport.Sent.Count)
            {
                read++;
                Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
            }
        }

        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        await DrainToPeerAsync();

        var progressAt = new List<ulong> { stream.SendOffset };
        for (var limit = (ulong)(Step * 2); limit <= Body; limit += Step)
        {
            clock.Advance(TimeSpan.FromMilliseconds(50));
            await serverPeer.SendAckAsync(SentAt, cancellation.Token);
            await connection.PumpOnceAsync(cancellation.Token);

            clock.Advance(TimeSpan.FromMilliseconds(50));
            await serverPeer.SendStreamFramesAsync(
                [MaxStreamData(stream.Id, limit)], cancellation.Token);
            await connection.PumpOnceAsync(cancellation.Token);

            // THE WINDOW MOVED, AND TO EXACTLY WHAT WAS GRANTED. Not "at least": a limit that
            // grew by more than the frame said would mean the frame was not what raised it.
            Assert.Equal(limit, stream.Budget!.Limit);

            // AND THE SEND OFFSET FOLLOWED IT WITHOUT PASSING IT. s19.10: "The data sent on a
            // stream MUST NOT exceed the largest maximum stream data value advertised by the
            // receiver."
            Assert.Equal(limit, stream.SendOffset);
            progressAt.Add(stream.SendOffset);

            await DrainToPeerAsync();
        }

        // WHATEVER THE GATE STILL HOLDS, FLUSHED. Nothing here can raise the send offset - the
        // last grant already released the final byte - so this moves congestion-held packets
        // and not flow-controlled ones.
        for (var guard = 0; guard < 32 && connection.Streams.HasPendingFrames; guard++)
        {
            clock.Advance(TimeSpan.FromMilliseconds(50));
            await serverPeer.SendAckAsync(SentAt, cancellation.Token);
            await connection.PumpOnceAsync(cancellation.Token);
            await DrainToPeerAsync();
        }

        // ============================================================================
        // THE BODY COMPLETED, AND THE RUN WAS NOT VACUOUS.
        // ============================================================================
        //
        // Sixteen distinct offsets - the initial credit and fifteen grants - so a build in
        // which the first send emitted everything, or in which the loop released nothing,
        // fails here rather than passing in silence with a green "the body completed".
        Assert.Equal(16, progressAt.Distinct().Count());
        Assert.Equal((ulong)Body, stream.SendOffset);
        Assert.False(stream.HasBlockedData);
        Assert.True(stream.FinSent);

        // AND THE BYTES ARRIVED, IN ORDER, ONCE. Reassembled from the peer's own decode rather
        // than from anything this connection reports about itself.
        var received = new List<byte>();
        var expectedOffset = 0UL;
        foreach (var (streamId, offset, data, _) in serverPeer.ReceivedStreamFrames)
        {
            Assert.Equal(stream.Id, streamId);
            Assert.Equal(expectedOffset, offset);
            expectedOffset += (ulong)data.Length;
            received.AddRange(data);
        }

        Assert.Equal(body, received);
        Assert.True(serverPeer.ReceivedStreamFrames[^1].Fin);
    }

    [Fact]
    public async Task AStaleSmallerMaxStreamDataDoesNotShrinkTheWindow()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            flowControl: FlowControlParameters(initialMaxData: 1_000_000, uni: 4));
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenUnidirectional();
        connection.Streams.Send(stream, new byte[64]);
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(4UL, stream.SendOffset);

        await serverPeer.SendStreamFramesAsync(
            [MaxStreamData(stream.Id, 40)], cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Equal(40UL, stream.Budget!.Limit);
        Assert.Equal(40UL, stream.SendOffset);
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // THE REPLAY. s19.10's "the LARGEST maximum stream data value advertised by the
        // receiver" is what makes this a no-op, and A3-8's outbound TryRefreshGrant is built
        // on a peer that reads it the same way - it re-sends the CURRENT limit after a loss
        // rather than the lost one, on the ground that a stale replay would be discarded.
        // This is the discarding half, and the two 20s below are the value the peer's window
        // stood at BEFORE the 40 - reordered onto the wire behind it.
        await serverPeer.SendStreamFramesAsync(
            [MaxStreamData(stream.Id, 20), MaxStreamData(stream.Id, 40)], cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // NOT 20, AND NOT 40-MINUS-ANYTHING. A window that took the latest value would now be
        // 20, below the 40 bytes already sent, and the remaining 24 of the body would be
        // stranded behind a limit the peer never lowered.
        Assert.Equal(40UL, stream.Budget!.Limit);
        Assert.Equal(40UL, stream.SendOffset);
        Assert.Equal(0UL, stream.Budget!.Remaining);
        Assert.Equal(24UL, stream.BlockedBytes);

        // AND THE REPLAY QUEUED NOTHING, which is what separates "ignored" from "applied as
        // zero": a shrunk window would have re-signalled, and a raised one would have drained.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Equal(2, serverPeer.ReceivedStreamFrames.Count);
    }

    [Fact]
    public async Task AConnectionLevelBlockSendsDataBlockedAndAMaxDataReleasesEveryStream()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,

            // THE CONNECTION LIMIT IS THE TIGHT ONE HERE and the per-stream limit is roomy,
            // which is the reverse of every other test in this file. RFC 9000 s19.9 and s19.10
            // are two limits and a sender is bound by both; a build that read only the stream's
            // would put 40 bytes on the wire against a connection allowance of 10.
            flowControl: FlowControlParameters(initialMaxData: 10, uni: 1000));
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var first = connection.Streams.OpenUnidirectional();
        var second = connection.Streams.OpenUnidirectional();
        connection.Streams.Send(first, new byte[40]);
        connection.Streams.Send(second, new byte[40]);

        Assert.Equal(10UL, first.SendOffset);
        Assert.Equal(0UL, second.SendOffset);
        Assert.Equal(30UL, first.BlockedBytes);
        Assert.Equal(40UL, second.BlockedBytes);

        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // s19.12: "A sender SHOULD send a DATA_BLOCKED frame (type=0x14) when it wishes to
        // send data but is unable to do so due to connection-level flow control." ONE, not
        // two, though two streams are blocked on it: the frame's scope is the connection, and
        // s13.3 says a new one is sent "only while the endpoint is blocked on the
        // corresponding limit" rather than once per write.
        Assert.Equal(
            1,
            serverPeer.LastDatagramFrames.Count(
                each => each.Type == TlsQuicFrameType.DataBlocked));

        await serverPeer.SendAckAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        await serverPeer.SendStreamFramesAsync([MaxData(80)], cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // BOTH STREAMS DRAINED, IN IDENTIFIER ORDER, AND THE POOL RAN OUT PART WAY THROUGH
        // THE SECOND. 70 new bytes: 30 finish the first stream and 40 finish the second, which
        // is the whole 80 minus the 10 already spent - so the second stream's last byte is
        // exactly the connection's last byte.
        Assert.Equal(40UL, first.SendOffset);
        Assert.Equal(40UL, second.SendOffset);
        Assert.False(first.HasBlockedData);
        Assert.False(second.HasBlockedData);
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
    }

    [Fact]
    public async Task ABodyThatIsNeverGrantedEndsOnTheDeadlineRatherThanHanging()
    {
        // NO DEADLOCK, PROVEN RATHER THAN ARGUED. The blocked queue holds bytes indefinitely
        // BY DESIGN, so the question this test answers is what bounds the wait: the connection
        // owns one deadline, set once at StartAsync, and a pump that receives nothing is
        // bounded by it whether or not a stream is blocked. Nothing in the flow-control path
        // adds a wait of its own, which is the property a second timer would have broken.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                clientTransport, serverTransport.LocalEndPoint, Spec(), TimeProvider.System)
            {
                HandshakeDeadline = TimeSpan.FromSeconds(3),
            },
            source => TlsClient(pki, source));
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            flowControl: FlowControlParameters(initialMaxData: 1_000_000, uni: 4));
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        var stream = connection.Streams.OpenUnidirectional();
        connection.Streams.Send(stream, new byte[64], fin: true);
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.Equal(60UL, stream.BlockedBytes);

        // THE PEER SAYS NOTHING AT ALL FROM HERE. No grant, no ACK, no close.
        //
        // PUMPED IN A LOOP AND NOT ONCE, because a pump can also wake on RFC 9002's probe
        // timeout - which is a THIRD limit, distinct from both flow control and congestion
        // control - send a probe and return normally. That is the connection making progress
        // rather than hanging, so the loop lets it, and what the loop proves is that every one
        // of those wakes is bounded and that the sequence ends at the abandonment deadline.
        // The guard is what would fail if any of them blocked forever.
        var timeout = await Assert.ThrowsAsync<TimeoutException>(async () =>
        {
            for (var guard = 0; guard < 1000; guard++)
            {
                await connection.PumpOnceAsync(cancellation.Token);
            }
        });

        // THE CONNECTION'S OWN DEADLINE, BY NAME, and not the test's 60-second guard: a hang
        // would have surfaced as the CancellationTokenSource firing instead.
        Assert.Contains("did not confirm within", timeout.Message, StringComparison.Ordinal);
        Assert.False(cancellation.IsCancellationRequested);

        // AND THE BYTES ARE STILL HELD RATHER THAN LOST OR DOUBLE-SENT.
        Assert.Equal(60UL, stream.BlockedBytes);
        Assert.Equal(4UL, stream.SendOffset);
    }

    [Theory]

    // s19.10, first MUST: "Receiving a MAX_STREAM_DATA frame for a locally initiated stream
    // that has not yet been created MUST be treated as a connection error of type
    // STREAM_STATE_ERROR." We are the client, so s2.1's client-initiated ids are the locally
    // initiated ones - 0 bidirectional and 2 unidirectional, neither opened by this test.
    [InlineData(0UL)]
    [InlineData(2UL)]

    // s19.10, second MUST: "An endpoint that receives a MAX_STREAM_DATA frame for a
    // receive-only stream MUST terminate the connection with error STREAM_STATE_ERROR." s2.1's
    // 0x03 row - server-initiated unidirectional - is the one this endpoint can never send on,
    // and id 3 is opened below by a STREAM frame before the grant arrives, so the refusal is
    // the receive-only rule and not the not-created one.
    [InlineData(3UL)]
    public async Task AMaxStreamDataThatSection1910RefusesClosesWithStreamStateError(
        ulong streamId)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        if (streamId == 3)
        {
            await serverPeer.SendStreamFramesAsync(
                [Stream(3, 0, [0x01])], cancellation.Token);
            Assert.True(await connection.PumpOnceAsync(cancellation.Token));
            Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        }

        await serverPeer.SendStreamFramesAsync(
            [MaxStreamData(streamId, 4096)], cancellation.Token);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));
        Assert.Contains("RFC 9000 s19.10", error.Message, StringComparison.Ordinal);
        Assert.Contains("StreamStateError", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AMaxStreamDataForAPeerStreamThisEndpointHasNotSeenIsIgnored()
    {
        // s19.10 HAS NO RULE FOR THIS ONE and this test is what pins the reading. Its two
        // MUSTs cover a LOCALLY initiated stream that does not exist and a RECEIVE-ONLY
        // stream; id 1 is s2.1's server-initiated BIDIRECTIONAL row, which is neither, so
        // closing the connection over it would invent an error the RFC does not define.
        // Ignoring costs credit this tree could not spend - nothing here ever sends on a
        // server-initiated bidirectional stream - where implicitly creating the stream would
        // spend a peer stream allowance s19.8 spends only for a STREAM frame.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(credential, connection.OriginalDestinationConnectionId);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());
        await ConfirmedHandshake(connection, serverPeer, cancellation.Token);

        await serverPeer.SendStreamFramesAsync([MaxStreamData(1, 4096)], cancellation.Token);

        Assert.True(await connection.PumpOnceAsync(cancellation.Token));
        Assert.Null(connection.Streams.Find(1));
        Assert.Equal(0UL, connection.PeerCloseErrorCode ?? 0UL);
    }

    // ---- Scaffolding ----------------------------------------------------------------------

    // The handshake through RFC 9001 s4.1.2's HANDSHAKE_DONE and the ACK that answers it -
    // task 14c's sequence, which every test here starts from and none of them is about. The
    // ACK is drained by the trailing pump so that ReceivedStreamFrames holds only what this
    // task's own sends put there.
    private static async ValueTask ConfirmedHandshake(
        TlsQuicConnection connection,
        LoopbackQuicPeer serverPeer,
        CancellationToken cancellationToken)
    {
        await connection.StartAsync(cancellationToken);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellationToken));
        Assert.False(await connection.PumpOnceAsync(cancellationToken));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellationToken));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellationToken);
        Assert.True(await connection.PumpOnceAsync(cancellationToken));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellationToken));
        Assert.True(connection.IsHandshakeConfirmed);
        Assert.Empty(serverPeer.ReceivedStreamFrames);
    }

    // FIELD BY FIELD AND NOT AS A TUPLE. ValueTuple's equality compares the byte[] element by
    // REFERENCE, so `Assert.Equal((id, offset, bytes, fin), actual)` would fail for every
    // correct frame - and, worse, a version of it that happened to pass would be comparing
    // identity rather than content.
    private static void AssertStreamFrame(
        ulong streamId,
        ulong offset,
        byte[] data,
        bool fin,
        (ulong StreamId, ulong Offset, byte[] Data, bool Fin) actual)
    {
        Assert.Equal(streamId, actual.StreamId);
        Assert.Equal(offset, actual.Offset);
        Assert.Equal(data, actual.Data);
        Assert.Equal(fin, actual.Fin);
    }

    // s19.8's frame, built here rather than by TlsQuicStreamSet: these are the PEER's frames,
    // and a helper that reused the send path would make the two sides one implementation -
    // the duplication LoopbackQuicPeer.BuildShortHeaderDatagram's own note defends.
    private static TlsQuicFrame Stream(
        ulong streamId, ulong offset, byte[] data, bool fin = false)
    {
        var rawType = (ulong)TlsQuicFrameType.Stream | TlsQuicStreamFrames.LengthBit;
        if (offset != 0)
        {
            rawType |= TlsQuicStreamFrames.OffsetBit;
        }

        if (fin)
        {
            rawType |= TlsQuicStreamFrames.FinBit;
        }

        return new TlsQuicFrame
        {
            RawType = rawType,
            StreamId = streamId,
            Offset = offset,
            Data = data,
        };
    }

    // s19.10's and s19.9's frames, built here for the reason Stream's note gives: these are the
    // PEER's, and reusing the send path's own construction would make the two sides one
    // implementation. Both go out through TlsQuicFrames.WriteFrame, so the BYTES on the wire
    // are the library's writer and the decode is the library's reader - what is hand-built
    // here is only the decision to send them.
    private static TlsQuicFrame MaxStreamData(ulong streamId, ulong maximumStreamData) => new()
    {
        RawType = (ulong)TlsQuicFrameType.MaxStreamData,
        StreamId = streamId,
        MaximumStreamData = maximumStreamData,
    };

    private static TlsQuicFrame MaxData(ulong maximumData) => new()
    {
        RawType = (ulong)TlsQuicFrameType.MaxData,
        MaximumData = maximumData,
    };
}
