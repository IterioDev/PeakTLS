using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

// Task 14d of A4-minimal: the peer's six RFC 9000 s18.2 flow-control limits, the static budget
// they bound, and RFC 9114 s6.2's three-unidirectional-stream MUST.
//
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's AND 14c's, for the reason those give: Spec,
// Connection, TlsClient, Server and FlowControlParameters are reused rather than copied.
//
// ============================================================================
// SIX WITNESSES AND NOT ONE, WHICH IS THE WHOLE POINT OF THE FIRST SECTION.
// ============================================================================
//
//   A WITNESS PER PARAMETER, NOT A WITNESS PER METHOD. Task 11 shipped a field named
//   "..._equals_header_source" that compared LENGTH ONLY, and replacing the entire comparison
//   with a constant survived 1069 tests. Six reads of the same shape, written in one sitting,
//   is that hazard exactly: one test asserting all six passes or fails as a block and cannot
//   say WHICH read is wrong, and a single test is satisfied by a single correct read.
//
//   So the six below each script all six parameters with values that differ from one another
//   AND assert exactly ONE of them. Deleting one read kills one named test. SWAPPING two -
//   the 0x05/0x06 confusion TlsQuicPeerFlowControlBudget.cs's header calls the most likely
//   defect in the file - kills exactly the two whose parameters were swapped, and the failure
//   message names the parameter the value wrongly came from, because
//   FlowControlParameters' defaults each end in their own parameter's ID.
//
//   WHAT THEY CANNOT PIN. Every one of them reads the budget through a completed handshake
//   against LoopbackQuicPeer, so a defect in TlsQuicTransportParameters.Get or in
//   QuicVariableLengthInteger that was SYMMETRIC across encode and decode would cancel here.
//   That pair is pinned independently in TlsQuicTransportParametersTests and
//   TlsQuicPrimitiveTests against hand-written bytes; these tests pin RETENTION, which is
//   what Finding 6 found missing, and nothing else.
//
//   THE s6.2 AND EXHAUSTION HALVES ARE SPLIT BY WHICH CHECK FIRES. A parameter set that
//   advertises two unidirectional streams AND a tiny per-stream credit fails only the first
//   check, and a test written over both would pin only that one - so the 1,024-byte SHOULD
//   has its own test, with a conforming stream COUNT, and it asserts the connection COMPLETES.
public sealed partial class TlsQuicConnectionTests
{
    // ---- The six witnesses ---------------------------------------------------------------

    [Fact]
    public async Task InitialMaxDataReachesTheBudgetAsTheConnectionLevelLimit() =>
        // s18.2: "initial_max_data (0x04):  The initial maximum data parameter is an integer
        // value that contains the initial value for the maximum amount of data that can be
        // sent on the connection."
        Assert.Equal(1_000_004UL, (await ScriptedBudget()).InitialMaxData);

    [Fact]
    public async Task InitialMaxStreamDataBidiLocalReachesTheBudget() =>
        // s18.2: "initial_max_stream_data_bidi_local (0x05): ... the initial flow control
        // limit for locally initiated bidirectional streams." LOCALLY, from the sender's side
        // - the peer's - so from ours it is the limit on server-initiated streams.
        Assert.Equal(1_000_005UL, (await ScriptedBudget()).InitialMaxStreamDataBidiLocal);

    [Fact]
    public async Task InitialMaxStreamDataBidiRemoteReachesTheBudget() =>
        // s18.2: "initial_max_stream_data_bidi_remote (0x06): ... the initial flow control
        // limit for peer-initiated bidirectional streams." Peer-initiated from the sender's
        // side, so this is the one that bounds OUR request streams.
        Assert.Equal(1_000_006UL, (await ScriptedBudget()).InitialMaxStreamDataBidiRemote);

    [Fact]
    public async Task InitialMaxStreamDataUniReachesTheBudget() =>
        // s18.2: "initial_max_stream_data_uni (0x07): ... the initial flow control limit for
        // unidirectional streams."
        Assert.Equal(1_000_007UL, (await ScriptedBudget()).InitialMaxStreamDataUni);

    [Fact]
    public async Task InitialMaxStreamsBidiReachesTheBudget() =>
        // s18.2: "initial_max_streams_bidi (0x08): ... the initial maximum number of
        // bidirectional streams the endpoint that receives this transport parameter is
        // permitted to initiate."
        Assert.Equal(108UL, (await ScriptedBudget()).InitialMaxStreamsBidi);

    [Fact]
    public async Task InitialMaxStreamsUniReachesTheBudget() =>
        // s18.2: "initial_max_streams_uni (0x09): ... the initial maximum number of
        // unidirectional streams the endpoint that receives this transport parameter is
        // permitted to initiate." NINE and not three: the s6.2 floor and the advertised value
        // are different numbers, so a read that returned the floor instead of the parameter
        // fails here.
        Assert.Equal(9UL, (await ScriptedBudget()).InitialMaxStreamsUni);

    // ---- RFC 9000 s18.2: absent and zero ------------------------------------------------

    [Theory]
    [InlineData(TlsQuicTransportParameterId.InitialMaxData)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamDataUni)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamsBidi)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamsUni)]
    public void AnAbsentFlowControlLimitReadsAsZeroExactlyLikeAnExplicitZero(
        TlsQuicTransportParameterId id)
    {
        // THE TASK BRIEF SAID THESE SIX HAVE ABSENT DEFAULTS THAT DIFFER FROM AN EXPLICIT 0,
        // AND FOR THESE SIX THAT IS FALSE. reference-captures/
        // rfc9000-section18-transport-parameters.txt lines 62-64: "Transport parameters have a
        // default value of 0 if the transport parameter is absent, unless otherwise stated."
        // None of the six states otherwise, and two of them restate it - lines 139 and 148
        // fold both cases into one clause, "If this parameter is absent or zero, the peer
        // cannot open bidirectional streams until a MAX_STREAMS frame is sent", and lines
        // 250-252 say for the three per-stream limits "If the transport parameter is absent,
        // streams of that type start with a flow control limit of 0."
        //
        // The four parameters that DO carry a non-zero absent default are ones this task does
        // not touch: max_udp_payload_size (65527), ack_delay_exponent (3), max_ack_delay (25)
        // and active_connection_id_limit (2).
        //
        // SO THE DISTINCTION IS TESTED AS AN EQUIVALENCE RATHER THAN A DIVERGENCE, and the
        // consequence that matters is the one the next test drives: an omitted
        // initial_max_streams_uni is a peer that granted nothing, not a peer that granted
        // everything.
        var absent = Budget(Omitting(id));
        var zero = Budget(FlowControlParameters(
            initialMaxData: id == TlsQuicTransportParameterId.InitialMaxData ? 0 : null,
            bidiLocal: id == TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal ? 0 : null,
            bidiRemote: id == TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote ? 0 : null,
            uni: id == TlsQuicTransportParameterId.InitialMaxStreamDataUni ? 0 : null,
            streamsBidi: id == TlsQuicTransportParameterId.InitialMaxStreamsBidi ? 0 : null,
            streamsUni: id == TlsQuicTransportParameterId.InitialMaxStreamsUni ? 0 : null));

        Assert.Equal(0UL, Read(absent, id));
        Assert.Equal(Read(zero, id), Read(absent, id));

        // AND THE OMISSION MOVED NOTHING ELSE. Without this a budget that read every limit
        // off the first parameter present would pass the two assertions above on every row.
        foreach (var other in AllSix.Where(candidate => candidate != id))
        {
            Assert.Equal(Expected(other), Read(absent, other));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0UL)]
    public async Task AnAbsentInitialMaxStreamsUniFailsSection62ExactlyLikeAnExplicitZero(
        ulong? advertised)
    {
        // The pair of rows is the point: a peer that OMITS the parameter has not left the
        // allowance open, and a client that treated absence as "no stated limit" would open
        // three unidirectional streams against an allowance of zero and then wait for a
        // MAX_STREAMS this phase never handles.
        var error = await RefusedHandshake(FlowControlParameters(streamsUni: advertised));

        Assert.Contains("at least three", error.Message, StringComparison.Ordinal);
        Assert.Contains(
            "initial_max_streams_uni (0x09) of 0", error.Message, StringComparison.Ordinal);
    }

    // ---- RFC 9114 s6.2 -------------------------------------------------------------------

    [Theory]
    [InlineData(1UL)]
    [InlineData(2UL)]
    public async Task AServerAdvertisingFewerThanThreeUnidirectionalStreamsIsRefusedUnderSection62(
        ulong advertised)
    {
        // reference-captures/rfc9114-section6-stream-mapping-and-usage.txt lines 101-108, read
        // PAST the wrap after "at least three": "Each endpoint needs to create at least one
        // unidirectional stream for the HTTP control stream.  QPACK requires two additional
        // unidirectional streams, and other extensions might require further streams.
        // Therefore, the transport parameters sent by both clients and servers MUST allow the
        // peer to create at least three unidirectional streams."
        //
        // ONE AND TWO RATHER THAN ZERO, because zero is the previous test's and because these
        // two are the rows that separate "the parameter was read" from "the parameter was
        // tested for presence" - a check written as `Get(0x09) is null` passes both of these
        // and is wrong in both.
        var error = await RefusedHandshake(FlowControlParameters(streamsUni: advertised));

        Assert.Contains(
            $"initial_max_streams_uni (0x09) of {advertised}",
            error.Message,
            StringComparison.Ordinal);
        Assert.Contains("RFC 9114 s6.2", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AServerAdvertisingExactlyThreeUnidirectionalStreamsIsAccepted()
    {
        // THE BOUNDARY, AND THE ONLY TEST THAT SEPARATES `<` FROM `<=`. s6.2 says "at least
        // three", so three conforms; a check written as "fewer than or equal to three" refuses
        // a conforming server and is caught nowhere else, since every other peer in this suite
        // advertises nine.
        var budget = await ScriptedBudget(FlowControlParameters(streamsUni: 3));

        Assert.Equal(3UL, budget.InitialMaxStreamsUni);
    }

    [Fact]
    public async Task TheThousandTwentyFourByteUnidirectionalCreditIsAShouldAndIsNotEnforced()
    {
        // s6.2's VERY NEXT SENTENCE after the MUST, and it is a SHOULD: "These transport
        // parameters SHOULD also provide at least 1,024 bytes of flow-control credit to each
        // unidirectional stream." Rejecting a peer for missing it would invent a MUST.
        //
        // THE STREAM COUNT CONFORMS ON PURPOSE. A peer that failed both s6.2 requirements
        // would be refused by the count check and this test would pass while pinning nothing
        // about the credit - the "a test that exercises two checks pins only whichever fires
        // first" trap. Nine streams, 1023 bytes: only the SHOULD is unmet, and the handshake
        // completing is the assertion.
        var budget = await ScriptedBudget(FlowControlParameters(uni: 1023));

        Assert.Equal(1023UL, budget.InitialMaxStreamDataUni);
        Assert.True(1023 < TlsQuicPeerFlowControlBudget.Http3RecommendedUnidirectionalStreamCredit);
    }

    [Fact]
    public async Task ACallerThatDoesNotSpeakHttp3CanLowerTheSection62Floor()
    {
        // The floor is RFC 9114's, so a QUIC connection carrying some other application
        // protocol has every right to accept a peer below it, and says so by setting the
        // option to 0. Without this test the option could be ignored and the constant read
        // directly, with the whole suite green - every other test here leaves it at its
        // default.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(
            new TlsQuicConnectionOptions(
                clientTransport, serverTransport.LocalEndPoint, Spec())
            {
                RequiredPeerUnidirectionalStreams = 0,
            },
            pki);
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            flowControl: FlowControlParameters(streamsUni: 0));
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        Assert.Equal(0UL, connection.PeerFlowControl.InitialMaxStreamsUni);
    }

    [Fact]
    public async Task TheBudgetIsUnreachableBeforeThePeersParametersArrive()
    {
        // Zero is not the answer to "what has the peer advertised?" before the peer has
        // advertised anything, and a budget that answered 0 there would refuse every send on
        // a connection that had simply not finished its handshake.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);

        await connection.StartAsync(cancellation.Token);

        var error = Assert.Throws<InvalidOperationException>(
            () => connection.PeerFlowControl);
        Assert.Contains("have not arrived yet", error.Message, StringComparison.Ordinal);
    }

    // ---- The budget is spent, and it never grows -----------------------------------------

    [Fact]
    public void OpeningMoreUnidirectionalStreamsThanThePeerAllowedFailsRatherThanExceedingIt()
    {
        var budget = Budget(FlowControlParameters(streamsUni: 3));

        budget.OpenUnidirectionalStream();
        budget.OpenUnidirectionalStream();
        budget.OpenUnidirectionalStream();
        Assert.Equal(0UL, budget.RemainingUnidirectionalStreams);

        // THE FOURTH IS THE ONE THAT MATTERS, and it is HTTP/3's shape exactly: control,
        // QPACK encoder, QPACK decoder, and then anything at all. The peer has granted three
        // and sent no MAX_STREAMS since, so silently opening a fourth would exceed a limit it
        // never gave.
        var error = Assert.Throws<InvalidOperationException>(
            () => budget.OpenUnidirectionalStream());

        Assert.Contains("initial_max_streams_uni (0x09)", error.Message, StringComparison.Ordinal);

        // AND THE MESSAGE NAMES THE ONE THING THAT WOULD LIFT IT. It used to say the budget was
        // static because nothing handled RFC 9000 s19.11 at all; audit finding 11 wired that
        // frame up, so the message now names it as the route rather than denying it exists -
        // which is the difference between "you cannot" and "the peer has not".
        Assert.Contains("MAX_STREAMS frame of type 0x13", error.Message, StringComparison.Ordinal);
    }

    // ---- RFC 9000 s19.11: MAX_STREAMS, audit finding 11 -----------------------------------

    /// <summary>
    /// THE FINDING ITSELF. RFC 9000 s19.11's MAX_STREAMS was parsed by
    /// <c>TlsQuicFlowControlFrames.TryReadMaximumStreams</c>, reached the frame switch, fell into
    /// its <c>default:</c> arm and was dropped - so the peer's stream allowance could only ever
    /// go down. s19.11: "A MAX_STREAMS frame with a type of 0x12 applies to bidirectional
    /// streams", and its Maximum Streams field is "A count of the cumulative number of streams of
    /// the corresponding type that can be opened over the lifetime of the connection."
    /// <para>ONE BIDIRECTIONAL STREAM ADVERTISED, WHICH IS HTTP/3's SHAPE AND NOT A CONTRIVANCE.
    /// RFC 9114 s4.1 puts each request on its own client-initiated bidirectional stream, so a
    /// peer that grants a small number up front and extends it as requests finish is the ordinary
    /// case - and request N+1 on a reused connection is exactly the call that threw.</para>
    /// <para>THROUGH THE WIRE, NOT THROUGH THE BUDGET. The frame is built by the harness's real
    /// peer, encoded by <c>TlsQuicFrames.WriteFrame</c>, sealed in a 1-RTT packet and opened by
    /// the connection's own AEAD, so what is under test is the DISPATCH the finding names rather
    /// than the two methods it dispatches to.</para>
    /// </summary>
    [Fact]
    public async Task AMaximumStreamsFrameRaisesTheExhaustedBidirectionalAllowance()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(clientTransport, serverTransport, pki);
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            flowControl: FlowControlParameters(streamsBidi: 1));
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        await serverPeer.SendHandshakeDoneAsync(SentAt, cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        var budget = connection.PeerFlowControl;
        Assert.Equal(1UL, budget.InitialMaxStreamsBidi);
        Assert.Equal(1UL, budget.BidirectionalStreamLimit);

        budget.OpenBidirectionalStream();
        var exhausted = Assert.Throws<InvalidOperationException>(
            () => budget.OpenBidirectionalStream());
        Assert.Contains("exhausted", exhausted.Message, StringComparison.Ordinal);

        // s19.11's grant: three streams over the lifetime of the connection, so two more than
        // the one already spent.
        await serverPeer.SendOneRttFramesAsync(
            [
                new TlsQuicFrame
                {
                    RawType = (ulong)TlsQuicFrameType.MaxStreams,
                    MaximumStreams = 3,
                },
            ],
            cancellation.Token);
        Assert.True(await connection.PumpOnceAsync(cancellation.Token));

        // CUMULATIVE, SO THE CREDIT IS THE DIFFERENCE. Three granted minus one spent is two, and
        // an implementation that treated the field as an increment would find three here.
        Assert.Equal(3UL, budget.BidirectionalStreamLimit);
        Assert.Equal(2UL, budget.RemainingBidirectionalStreams);
        budget.OpenBidirectionalStream();
        budget.OpenBidirectionalStream();
        Assert.Throws<InvalidOperationException>(() => budget.OpenBidirectionalStream());

        // AND initial_max_streams_bidi STILL REPORTS WHAT WAS ADVERTISED. A property named for
        // the transport parameter that moved with the frames would make its two readers - the
        // RFC 9114 pre-flight and this file's own refusal messages - lie.
        Assert.Equal(1UL, budget.InitialMaxStreamsBidi);
    }

    /// <summary>
    /// s19.11's OTHER HALF, and it is a MUST about a frame that must NOT act: "MAX_STREAMS frames
    /// that do not increase the stream limit MUST be ignored." s19.11 supplies the cause in the
    /// same paragraph - "Loss or reordering can cause an endpoint to receive a MAX_STREAMS frame
    /// with a lower stream limit than was previously received" - which is why a decrease is
    /// dropped rather than treated as a violation: the peer did nothing wrong, the network
    /// shuffled two datagrams.
    /// </summary>
    [Fact]
    public void AMaximumStreamsFrameThatDoesNotIncreaseTheLimitIsIgnored()
    {
        var budget = Budget(FlowControlParameters(streamsBidi: 4, streamsUni: 4));

        budget.OpenBidirectionalStream();
        budget.OpenUnidirectionalStream();
        Assert.Equal(3UL, budget.RemainingBidirectionalStreams);
        Assert.Equal(3UL, budget.RemainingUnidirectionalStreams);

        // A stale grant, an equal one, and a raise, in that order. The first two must move
        // nothing; the third must credit exactly its difference and no more.
        Assert.False(budget.TryRaiseBidirectionalStreamLimit(2));
        Assert.False(budget.TryRaiseUnidirectionalStreamLimit(2));
        Assert.False(budget.TryRaiseBidirectionalStreamLimit(4));
        Assert.False(budget.TryRaiseUnidirectionalStreamLimit(4));
        Assert.Equal(3UL, budget.RemainingBidirectionalStreams);
        Assert.Equal(3UL, budget.RemainingUnidirectionalStreams);

        // THE TWO DIRECTIONS ARE RAISED SEPARATELY, and the values differ so that a
        // single-counter implementation - or a negated direction test - cannot pass. s19.11
        // spends a whole frame type on the distinction: "Type (i) = 0x12..0x13".
        Assert.True(budget.TryRaiseBidirectionalStreamLimit(6));
        Assert.Equal(6UL, budget.BidirectionalStreamLimit);
        Assert.Equal(5UL, budget.RemainingBidirectionalStreams);
        Assert.Equal(4UL, budget.UnidirectionalStreamLimit);
        Assert.Equal(3UL, budget.RemainingUnidirectionalStreams);

        Assert.True(budget.TryRaiseUnidirectionalStreamLimit(9));
        Assert.Equal(9UL, budget.UnidirectionalStreamLimit);
        Assert.Equal(8UL, budget.RemainingUnidirectionalStreams);
        Assert.Equal(6UL, budget.BidirectionalStreamLimit);
        Assert.Equal(5UL, budget.RemainingBidirectionalStreams);
    }

    /// <summary>
    /// s19.11's ceiling, asserted at the level a peer can observe rather than at the parser.
    /// "This value cannot exceed 2^60, as it is not possible to encode stream IDs larger than
    /// 2^62-1. Receipt of a frame that permits opening of a stream larger than this limit MUST be
    /// treated as a connection error of type FRAME_ENCODING_ERROR."
    /// <para>THE BOUND HAS EXACTLY ONE OWNER, which is why this test exists in this file at all.
    /// <c>TlsQuicFlowControlFrames.TryReadMaximumStreams</c> enforces it and
    /// <c>TlsQuicFlowControlFramesTests</c> pins it there; what was never witnessed is that the
    /// refusal actually reaches the peer as a connection error rather than dying inside the
    /// parser. Writing the constant a second time in the dispatch would have been two owners for
    /// one wire value, so the OUTCOME is asserted instead.</para>
    /// <para>HAND-ENCODED BYTES, BECAUSE NO WRITER IN THIS LIBRARY WILL PRODUCE THEM.
    /// <c>WriteMaximumStreamsFrameFields</c> throws on a count above the bound, by design - so
    /// the frame is written here against s19.11's two-field format: the type byte 0x12, then
    /// 2^60+1 as RFC 9000 s16's eight-byte variable-length integer (the two-bit 0b11 prefix over
    /// 0x1000000000000001 gives 0xD000000000000001).</para>
    /// </summary>
    [Fact]
    public async Task AMaximumStreamsFrameAboveTheStreamCountBoundClosesWithFrameEncodingError()
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

        // DRAINED, FOR THE REASON AfterConfirmationTheCloseGoesOutInAOneRttPacketAsSection1023
        // Requires gives: the pump above answered HANDSHAKE_DONE with a 1-RTT ACK, and
        // LoopbackQuicPeer.PumpOnceAsync reads ONE datagram per call.
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.Null(serverPeer.LastConnectionClose);

        await serverPeer.SendOneRttRawFrameAsync(
            [0x12, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], cancellation.Token);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        // s20.1 FRAME_ENCODING_ERROR (0x07): "A frame was received that was badly formatted."
        // And it was SENT, not merely recorded - which is audit finding 9's half of this test.
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, connection.ClosedWith);
        await serverPeer.PumpOnceAsync(SentAt, cancellation.Token);
        var close = Assert.NotNull(serverPeer.LastConnectionClose);
        Assert.Equal((ulong)TlsQuicTransportError.FrameEncodingError, close.ErrorCode);
    }

    [Fact]
    public void OpeningMoreBidirectionalStreamsThanThePeerAllowedFailsRatherThanExceedingIt()
    {
        var budget = Budget(FlowControlParameters(streamsBidi: 1));

        budget.OpenBidirectionalStream();

        var error = Assert.Throws<InvalidOperationException>(
            () => budget.OpenBidirectionalStream());

        Assert.Contains("initial_max_streams_bidi (0x08)", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SendingPastAStreamsOwnLimitFailsRatherThanExceedingIt()
    {
        // The connection-level limit is left enormous so that ONLY the per-stream one can
        // fire; the next test does the reverse. Written apart because a single test with both
        // limits tight pins whichever is checked first and says nothing about the other.
        var budget = Budget(FlowControlParameters(initialMaxData: 1_000_000, uni: 10));
        var stream = budget.OpenUnidirectionalStream();

        stream.Consume(10);
        Assert.Equal(0UL, stream.Remaining);

        // THE GUARD IS NOW AN INVARIANT AND NOT THE POLICY, and it is witnessed HERE rather
        // than through TlsQuicStreamSet.Send because Send no longer reaches it: it splits at
        // Available and holds the excess for a MAX_STREAM_DATA. This test is what keeps the
        // guard from becoming an unwitnessed survivor - a caller that computed its own split
        // wrongly must meet a throw and not put the byte on the wire.
        var error = Assert.Throws<InvalidOperationException>(() => stream.Consume(1));

        Assert.Contains(
            "initial_max_stream_data_uni (0x07), currently 10",
            error.Message,
            StringComparison.Ordinal);
        Assert.Contains("MAX_STREAM_DATA", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SendingPastTheConnectionLimitFailsEvenWhenEveryStreamFitsItsOwn()
    {
        // RFC 9000 s4.1's two-level scheme, and the case a per-stream-only implementation gets
        // wrong: three streams that each fit their 10-byte limit exhaust a 25-byte
        // initial_max_data between them. Nothing here exceeds any per-stream limit, so a
        // budget that charged only the stream would let all thirty bytes out.
        var budget = Budget(FlowControlParameters(initialMaxData: 25, uni: 10));
        var first = budget.OpenUnidirectionalStream();
        var second = budget.OpenUnidirectionalStream();
        var third = budget.OpenUnidirectionalStream();

        first.Consume(10);
        second.Consume(10);
        Assert.Equal(5UL, budget.RemainingConnectionData);

        var error = Assert.Throws<InvalidOperationException>(() => third.Consume(10));

        Assert.Contains("initial_max_data (0x04) of 25", error.Message, StringComparison.Ordinal);
        Assert.Contains("MAX_DATA", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ARefusedSendMovesNeitherCounter()
    {
        // A throw AFTER the subtraction leaks credit on every refusal, and every assertion
        // above still passes: the exception type, the message and the first refusal are all
        // unchanged. Only the state afterwards separates them.
        var budget = Budget(FlowControlParameters(initialMaxData: 25, uni: 10));
        var stream = budget.OpenUnidirectionalStream();

        Assert.Throws<InvalidOperationException>(() => stream.Consume(11));

        Assert.Equal(10UL, stream.Remaining);
        Assert.Equal(25UL, budget.RemainingConnectionData);
    }

    // ---- ...and now it grows: s19.9's MAX_DATA and s19.10's MAX_STREAM_DATA ----------------

    [Fact]
    public void AMaxStreamDataCreditsTheDifferenceAndNotTheWholeLimit()
    {
        var budget = Budget(FlowControlParameters(initialMaxData: 1_000_000, uni: 10));
        var stream = budget.OpenUnidirectionalStream();

        stream.Consume(10);
        Assert.Equal(0UL, stream.Remaining);

        Assert.True(stream.TryRaiseLimit(25));

        // FIFTEEN, NOT TWENTY-FIVE. _remaining is limit-minus-spent, so assigning the new
        // limit to it would refund the ten bytes already on the wire and let thirty-five out
        // against a twenty-five byte grant - a FLOW_CONTROL_ERROR that no assertion on the
        // limit alone would catch.
        Assert.Equal(15UL, stream.Remaining);
        Assert.Equal(25UL, stream.Limit);
    }

    [Theory]

    // s19.10: "The data sent on a stream MUST NOT exceed the LARGEST maximum stream data value
    // advertised by the receiver" - largest, not latest.
    [InlineData(9UL)]
    [InlineData(0UL)]

    // EQUAL IS ALSO IGNORED, and it is a separate row because it is a separate defect: `<`
    // rather than `<=` would report a window movement for a frame that granted nothing, and a
    // caller draining on that report would loop without progress.
    [InlineData(10UL)]
    public void AStaleOrEqualMaxStreamDataNeitherShrinksTheWindowNorReportsMovement(
        ulong replayed)
    {
        var budget = Budget(FlowControlParameters(initialMaxData: 1_000_000, uni: 10));
        var stream = budget.OpenUnidirectionalStream();

        stream.Consume(4);

        Assert.False(stream.TryRaiseLimit(replayed));
        Assert.Equal(10UL, stream.Limit);
        Assert.Equal(6UL, stream.Remaining);
    }

    [Fact]
    public void AStaleSmallerMaxDataIsIgnoredAndTheAlternativeReadingIsNamed()
    {
        // ============================================================================
        // THE ONE PLACE THE EXTRACT DOES NOT DECIDE, PINNED UNDER BOTH READINGS.
        // ============================================================================
        //
        // s19.10 carries the word "largest" and s19.11 states the ignore-rule for MAX_STREAMS
        // as a MUST with its cause - "Loss or reordering can cause an endpoint to receive a
        // MAX_STREAMS frame with a lower stream limit than was previously received". s19.9
        // carries NEITHER. Its strongest sentence, "An endpoint MUST terminate a connection
        // with an error of type FLOW_CONTROL_ERROR if it receives more data than the maximum
        // data value that it has sent", is satisfied by a stale lower value as much as by the
        // largest one, so the frame-formats extract genuinely leaves MAX_DATA open.
        //
        // FOLLOWED: the running maximum, on s19.11's stated cause rather than on s19.9's
        // silence. Both assertions below are written out so that a future reader who decides
        // the other way edits a test that names the choice instead of finding a behaviour
        // change with no record.
        var budget = Budget(FlowControlParameters(initialMaxData: 100, uni: 1_000_000));
        var stream = budget.OpenUnidirectionalStream();

        stream.Consume(40);
        Assert.True(budget.TryRaiseConnectionLimit(200));
        Assert.Equal(160UL, budget.RemainingConnectionData);

        Assert.False(budget.TryRaiseConnectionLimit(100));

        // EQUAL IS IGNORED TOO, AND THIS LINE EXISTS BECAUSE THE MUTATION SURVIVED WITHOUT IT.
        // Sweep row A4C-04 turned `maximumData <= ConnectionLimit` into `<` and the whole
        // 2,473-case gate stayed green: every stale MAX_DATA in the suite was STRICTLY smaller,
        // so nothing measured the boundary. A re-advertised limit grants no byte, and reporting
        // movement for it would send a caller draining a window that did not move. The stream
        // half of the same off-by-one is AStaleOrEqualMaxStreamDataNeitherShrinksTheWindowNor
        // ReportsMovement's third Theory row, which is why row A4C-01 died and A4C-04 did not.
        Assert.False(budget.TryRaiseConnectionLimit(200));
        Assert.Equal(200UL, budget.ConnectionLimit);
        Assert.Equal(160UL, budget.RemainingConnectionData);

        // FOLLOWED - the running maximum: the limit stays at 200 and 160 remain.
        Assert.Equal(200UL, budget.ConnectionLimit);
        Assert.Equal(160UL, budget.RemainingConnectionData);

        // NOT FOLLOWED - obey the latest value: the limit would be back at 100 and 60 would
        // remain. Asserted as an inequality so this test fails the moment the reading changes.
        Assert.NotEqual(100UL, budget.ConnectionLimit);
        Assert.NotEqual(60UL, budget.RemainingConnectionData);

        // AND initial_max_data STILL SAYS WHAT THE PEER ADVERTISED, which is why it is a
        // separate property from ConnectionLimit: the RFC 9114 request pre-flight reads it as
        // the advertised value and a property named "initial" that moved would lie to it.
        Assert.Equal(100UL, budget.InitialMaxData);
    }

    [Fact]
    public void AvailableIsTheSmallerOfTheTwoLimitsAndBothCanBeTheBinding()
    {
        // RFC 9000 s19.9 and s19.10 are two limits and a sender is bound by both. This is the
        // read TlsQuicStreamSet.Send splits on, so a version of it that consulted one would
        // put bytes on the wire past the other.
        var budget = Budget(FlowControlParameters(initialMaxData: 25, uni: 10));
        var stream = budget.OpenUnidirectionalStream();

        // The stream is the binding limit.
        Assert.Equal(10UL, stream.Available);

        stream.TryRaiseLimit(1_000);

        // Now the connection is.
        Assert.Equal(25UL, stream.Available);

        budget.TryRaiseConnectionLimit(2_000);
        Assert.Equal(1_000UL, stream.Available);
    }

    [Fact]
    public void TheSixMegabyteCeilingIsGoneBecauseNeitherLimitIsCappedByWhatWasAdvertised()
    {
        // WHAT THIS TASK ACTUALLY REMOVED, stated as a number. The peer's advertised limits
        // are capture-shaped and small; the grants are not, and nothing clamps a grant to the
        // initial value. Sixty-four megabytes is not a supported figure - it is an arbitrary
        // point well past the ~6 MB the static budget imposed, chosen to show the old ceiling
        // was a property of the missing receive path and not of any cap that remains.
        var budget = Budget(FlowControlParameters(initialMaxData: 6_291_456, uni: 6_291_456));
        var stream = budget.OpenUnidirectionalStream();

        Assert.True(stream.TryRaiseLimit(64UL * 1024 * 1024));
        Assert.True(budget.TryRaiseConnectionLimit(64UL * 1024 * 1024));

        Assert.Equal(64UL * 1024 * 1024, stream.Available);
    }

    [Fact]
    public void RaisingEitherLimitToTheVarintCeilingDoesNotOverflow()
    {
        // s16 caps a variable-length integer at 2^62-1, which is what the write side refuses to
        // exceed - so that is the largest grant that can arrive, and a delta-plus-remainder at
        // it is at most 2^63-2. Asserted rather than reasoned because an unchecked wrap here
        // would present as a budget that suddenly refuses everything.
        var budget = Budget(FlowControlParameters(initialMaxData: 1, uni: 1));
        var stream = budget.OpenUnidirectionalStream();

        Assert.True(stream.TryRaiseLimit(QuicVariableLengthInteger.MaximumValue));
        Assert.True(budget.TryRaiseConnectionLimit(QuicVariableLengthInteger.MaximumValue));

        Assert.Equal(QuicVariableLengthInteger.MaximumValue, stream.Available);
        Assert.Equal(QuicVariableLengthInteger.MaximumValue, budget.ConnectionLimit);
    }

    [Fact]
    public void AnOutgoingBidirectionalStreamTakesItsLimitFromBidiRemoteAndNotBidiLocal()
    {
        // THE SWAP THIS FILE EXISTS TO CATCH. s18.2 on 0x06: it "applies to newly created
        // bidirectional streams opened by the endpoint that RECEIVES the transport parameter"
        // - us - while 0x05 "applies to newly created bidirectional streams opened by the
        // endpoint that SENDS the transport parameter". Our own request streams therefore take
        // 0x06. Against any peer that advertises the two equally the swap is invisible, which
        // is why FlowControlParameters gives them different values.
        var budget = Budget(FlowControlParameters());

        Assert.Equal(1_000_006UL, budget.OpenBidirectionalStream().Limit);
    }

    [Fact]
    public void AnIncomingBidirectionalStreamTakesItsLimitFromBidiLocal()
    {
        // The other half of the same sentence, and the half that keeps the test above from
        // being satisfiable by a budget that used 0x06 for everything.
        var budget = Budget(FlowControlParameters());

        Assert.Equal(1_000_005UL, budget.AcceptBidirectionalStream().Limit);
    }

    [Fact]
    public void AUnidirectionalStreamTakesItsLimitFromInitialMaxStreamDataUni()
    {
        var budget = Budget(FlowControlParameters());

        Assert.Equal(1_000_007UL, budget.OpenUnidirectionalStream().Limit);
    }

    [Fact]
    public void AcceptingAPeerOpenedStreamSpendsNoneOfOurOwnStreamAllowance()
    {
        // initial_max_streams_bidi bounds the streams WE open. A peer-opened stream is spent
        // against the allowance we advertised to it, which A4-minimal does not track at all -
        // so charging one here would refuse work the peer is entitled to.
        var budget = Budget(FlowControlParameters(streamsBidi: 1));

        budget.AcceptBidirectionalStream();
        budget.AcceptBidirectionalStream();

        Assert.Equal(1UL, budget.RemainingBidirectionalStreams);
    }

    // ---- Scaffolding ---------------------------------------------------------------------

    private static readonly TlsQuicTransportParameterId[] AllSix =
    [
        TlsQuicTransportParameterId.InitialMaxData,
        TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal,
        TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote,
        TlsQuicTransportParameterId.InitialMaxStreamDataUni,
        TlsQuicTransportParameterId.InitialMaxStreamsBidi,
        TlsQuicTransportParameterId.InitialMaxStreamsUni,
    ];

    private static ulong Read(
        TlsQuicPeerFlowControlBudget budget, TlsQuicTransportParameterId id) => id switch
    {
        TlsQuicTransportParameterId.InitialMaxData => budget.InitialMaxData,
        TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal =>
            budget.InitialMaxStreamDataBidiLocal,
        TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote =>
            budget.InitialMaxStreamDataBidiRemote,
        TlsQuicTransportParameterId.InitialMaxStreamDataUni => budget.InitialMaxStreamDataUni,
        TlsQuicTransportParameterId.InitialMaxStreamsBidi => budget.InitialMaxStreamsBidi,
        TlsQuicTransportParameterId.InitialMaxStreamsUni => budget.InitialMaxStreamsUni,
        _ => throw new ArgumentOutOfRangeException(nameof(id)),
    };

    // FlowControlParameters' defaults, restated as data so that the "the omission moved
    // nothing else" loop has something to compare against. Restated and not derived, because
    // deriving it from the same helper would compare the helper with itself.
    private static ulong Expected(TlsQuicTransportParameterId id) => id switch
    {
        TlsQuicTransportParameterId.InitialMaxData => 1_000_004,
        TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal => 1_000_005,
        TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote => 1_000_006,
        TlsQuicTransportParameterId.InitialMaxStreamDataUni => 1_000_007,
        TlsQuicTransportParameterId.InitialMaxStreamsBidi => 108,
        TlsQuicTransportParameterId.InitialMaxStreamsUni => 9,
        _ => throw new ArgumentOutOfRangeException(nameof(id)),
    };

    private static List<TlsQuicTransportParameter> Omitting(TlsQuicTransportParameterId id) =>
        FlowControlParameters(
            initialMaxData: id == TlsQuicTransportParameterId.InitialMaxData ? null : 1_000_004,
            bidiLocal: id == TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal
                ? null : 1_000_005,
            bidiRemote: id == TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote
                ? null : 1_000_006,
            uni: id == TlsQuicTransportParameterId.InitialMaxStreamDataUni ? null : 1_000_007,
            streamsBidi: id == TlsQuicTransportParameterId.InitialMaxStreamsBidi ? null : 108,
            streamsUni: id == TlsQuicTransportParameterId.InitialMaxStreamsUni ? null : 9);

    private static TlsQuicPeerFlowControlBudget Budget(
        IEnumerable<TlsQuicTransportParameter> parameters) =>
        TlsQuicPeerFlowControlBudget.FromPeerParameters(
            new TlsQuicTransportParameters(parameters));

    // One completed handshake against a LoopbackQuicPeer whose server advertises exactly the
    // parameters given, and the budget the connection built from them. The s7.3 connection ID
    // parameters and the h3 ALPN come from Server, unchanged.
    private static async Task<TlsQuicPeerFlowControlBudget> ScriptedBudget(
        IReadOnlyList<TlsQuicTransportParameter>? flowControl = null)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(
            new TlsQuicConnectionOptions(clientTransport, serverTransport.LocalEndPoint, Spec()),
            pki);
        await using var server = Server(
            credential,
            connection.OriginalDestinationConnectionId,
            flowControl: flowControl ?? FlowControlParameters());
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));
        Assert.False(await connection.PumpOnceAsync(cancellation.Token));

        return connection.PeerFlowControl;
    }

    // The same handshake, refused. Asserting the close code here rather than in each caller
    // keeps every s6.2 test about the number it advertised.
    private static async Task<InvalidOperationException> RefusedHandshake(
        IReadOnlyList<TlsQuicTransportParameter> flowControl)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        using var credential = Credential(pki);
        var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
        await using var connection = Connection(
            new TlsQuicConnectionOptions(clientTransport, serverTransport.LocalEndPoint, Spec()),
            pki);
        await using var server = Server(
            credential, connection.OriginalDestinationConnectionId, flowControl: flowControl);
        await using var serverPeer = LoopbackQuicPeer.ForServer(
            serverTransport, clientTransport.LocalEndPoint, server, Spec());

        await connection.StartAsync(cancellation.Token);
        Assert.True(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await connection.PumpOnceAsync(cancellation.Token));

        // RFC 9000 s20.1 APPLICATION_ERROR (0x0c): "The application or application protocol
        // caused the connection to be closed." NOT TransportParameterError, which would accuse
        // the peer of an RFC 9000 violation it did not commit - every value it sent is inside
        // s18.2's bounds. The assertion is here because a close code is not visible in the
        // exception and would otherwise go unpinned.
        Assert.Equal(TlsQuicTransportError.ApplicationError, connection.ClosedWith);
        return error;
    }
}
