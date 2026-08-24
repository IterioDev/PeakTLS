using System.Globalization;
using System.Net.Quic;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls.Certificates;
using SharpTls.Protocol;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;
using SharpTls.Tests.Interop;

namespace SharpTls.Tests.Quic;

// Task C11: the HTTP/3 connection, and the retirement of tests/SharpTls.Tests/Interop/
// Http3GetSpike.cs.
//
// ============================================================================
// THE SAME PARTIAL CLASS AS 9a-ii's, 9b's, 14c's, 14d's AND 14e's.
// ============================================================================
//
//   Spec, Connection, TlsClient, Server, Credential, FlowControlParameters, ConfirmedHandshake,
//   Stream and AssertStreamFrame are reused rather than copied, for the reason those tasks
//   give: a copy of any of them would be a second packet writer, and the six flow-control
//   values that name their own parameter ID are the whole reason a refusal below can say WHICH
//   limit refused it.
//
// ============================================================================
// OUR OWN SETTINGS ARE READ BACK OFF THE STREAM FRAMES THE PEER RECEIVED.
// ============================================================================
//
//   TheOpeningFlightIsSettingsFirstOnTheControlStreamAsTheWireSawIt does not ask
//   TlsQuicHttp3Connection what its settings are and does not ask the spec either. It takes
//   LoopbackQuicPeer.ReceivedStreamFrames[0].Data - bytes that were encoded, packed into a
//   1-RTT packet, protected, sent, unprotected and decoded by the other side - strips s6.2's
//   stream-type varint and decodes what follows as an s7.1 frame. A readout of bytes that were
//   never emitted is a restatement of the input; this is the emission.
//
//   AND ITS SPEC IS NOT THE DEFAULT ONE. The settings asserted are a list no other test in the
//   tree uses, in an order that is not ascending, so an implementation that ignored the spec
//   and wrote TlsQuicHttp3Spec.CaptureSettings - or sorted - fails here and passes a test that
//   used the default.
//
// ============================================================================
// EVERY REFUSAL AND EVERY CONNECTION ERROR NAMES ITS CAUSE.
// ============================================================================
//
//   Six different conditions refuse a request and five different s8.1 codes end a connection.
//   Asserting "it failed" would let any two be exchanged, which is the rule
//   TlsQuicHttp3StreamsTests' header states for the three codes s6.2.1 attaches to one stream.
//
// ============================================================================
// WHAT THE DELETED SPIKE PROVED THAT THESE TESTS DO NOT.
// ============================================================================
//
//   The spike reached fp.impersonate.pro over the real internet and got back a 4,943-byte body
//   whose first field was "protocol": "http3" - an endpoint that refuses to answer unless h3
//   was genuinely negotiated. NOTHING OFFLINE CAN REPLACE THAT. It is preserved as
//   AFullRequestAndResponseCompleteAgainstALiveHttp3Endpoint below, behind
//   SHARPTLS_RUN_INTEROP=1 exactly as QuicPublicEndpointInteropTests is, and rewritten to drive
//   TlsQuicHttp3Connection rather than the four hard-coded buffers the spike carried.
//
//   What is NOT preserved, deliberately: the spike's 20-second deadline, its 4 KiB / 64 KiB /
//   128-line fixed buffers, its re-finding of the request stream by the literal id 0, and its
//   one-request lifetime. Each is now either a caller's choice (the deadline), sized from the
//   input (the buffers), returned by the opening call (the stream), or covered by
//   TwoRequestsOnOneConnectionEachLandOnTheirOwnReader.
public sealed partial class TlsQuicConnectionTests
{
    // s2.1: a server-initiated unidirectional stream is 3 mod 4.
    private const ulong PeerControlStreamId = 3;

    // s6.1: "the client's first request occurs on QUIC stream 0, with subsequent requests on
    // streams 4, 8, and so on."
    private const ulong FirstRequestStreamId = 0;
    private const ulong SecondRequestStreamId = 4;

    // ------------------------------------------------------------------------
    // The opening flight.
    // ------------------------------------------------------------------------

    [Fact]
    public async Task TheOpeningFlightIsSettingsFirstOnTheControlStreamAsTheWireSawIt()
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

        // NOT THE DEFAULT LIST AND NOT IN ASCENDING ORDER. s7.2.4 fixes no order, so this is
        // the one thing the capture cannot settle and the one thing an encoder could silently
        // canonicalise.
        var http3 = new TlsQuicHttp3Connection(
            connection,
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 41),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 4242),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 43),
                ],
            });
        http3.OpenLocalStreams();
        Assert.True(await connection.SendPendingAsync(cancellation.Token));
        Assert.False(await serverPeer.PumpOnceAsync(SentAt, cancellation.Token));

        // Three streams left, in the spec's order; C4 pins the ORDER, so what is read here is
        // the control stream's payload.
        Assert.Equal(3, serverPeer.ReceivedStreamFrames.Count);
        var control = serverPeer.ReceivedStreamFrames[0].Data;
        Assert.Equal(0UL, serverPeer.ReceivedStreamFrames[0].Offset);

        var cursor = 0;
        Assert.True(QuicVariableLengthInteger.TryRead(control, ref cursor, out var streamType));
        Assert.Equal((ulong)TlsQuicHttp3StreamType.Control, streamType);

        // s6.2.1: "send its SETTINGS frame as the FIRST frame on this stream." The frame read
        // here is the one at the stream-type varint's far side, so "first" is asserted rather
        // than assumed.
        Assert.Equal(
            TlsQuicHttp3FrameReadStatus.Complete,
            TlsQuicHttp3Frames.TryRead(
                control, ref cursor, out var frameType, out var payload, out _));
        Assert.Equal((ulong)TlsQuicHttp3FrameType.Settings, frameType);
        Assert.True(TlsQuicHttp3Settings.TryDecodePayload(payload, out var settings, out _));
        Assert.Equal(
            new[]
            {
                new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 41),
                new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 4242),
                new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 43),
            },
            settings);

        // s6.2.1: "The sender MUST NOT close the control stream."
        Assert.False(serverPeer.ReceivedStreamFrames[0].Fin);

        // And nothing follows the SETTINGS frame on it.
        Assert.Equal(control.Length, cursor);
    }

    [Fact]
    public async Task ARequestBeforeTheOpeningFlightIsLocalMisuseAndThrows()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token, openLocalStreams: false);

        // s6.2.1's "at the beginning of the connection" is OUR obligation, not the peer's, so
        // breaking it is misuse and not a refusal - the same split TlsQuicHttp3Streams draws
        // between members a local caller drives and members that read peer input.
        Assert.Throws<InvalidOperationException>(
            () => harness.Http3.TryOpenRequest(Request(), out _, out _));
    }

    // ------------------------------------------------------------------------
    // A whole request and response, against LoopbackQuicPeer.
    // ------------------------------------------------------------------------

    [Fact]
    public async Task AFullRequestAndResponseCompleteAgainstTheLoopbackPeer()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        var stream = harness.Http3.TryOpenRequest(Request(), out var refusal, out var malformed);
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
        Assert.Equal(TlsQuicHttp3RequestError.None, malformed);
        Assert.NotNull(stream);

        // s6.1's stream 0, and the id comes back from the call rather than being looked up -
        // the spike re-found this stream by the literal 0.
        Assert.Equal(FirstRequestStreamId, stream.Id);

        await harness.FlushAsync(cancellation.Token);

        // THE REQUEST REACHED THE PEER, WITH THE FIN. s4.1: a request with no content ends
        // with its header section.
        var sent = Assert.Single(harness.Peer.ReceivedStreamFrames);
        Assert.Equal(FirstRequestStreamId, sent.StreamId);
        Assert.Equal(0UL, sent.Offset);
        Assert.True(sent.Fin);

        // And the bytes are one HEADERS frame, read back off the wire rather than compared to
        // what the encoder was asked for.
        var offset = 0;
        Assert.Equal(
            TlsQuicHttp3FrameReadStatus.Complete,
            TlsQuicHttp3Frames.TryRead(
                sent.Data, ref offset, out var requestFrameType, out _, out _));
        Assert.Equal((ulong)TlsQuicHttp3FrameType.Headers, requestFrameType);
        Assert.Equal(sent.Data.Length, offset);

        await harness.PeerSendsAsync(
            cancellation.Token,
            PeerControl(),
            Stream(
                FirstRequestStreamId,
                0,
                ResponseBytes(200, [("server", "loopback")], "hello http/3"u8.ToArray()),
                fin: true));

        var response = harness.Http3.ResponseFor(FirstRequestStreamId);
        Assert.NotNull(response);
        Assert.True(response.IsComplete);
        Assert.Equal(200, response.Status);
        Assert.Equal("loopback", FieldValue(response, "server"));
        Assert.Equal("hello http/3", Encoding.UTF8.GetString(response.Body));

        // The peer's own opening flight was read on the way past, which is the half that makes
        // the connection an HTTP/3 one rather than a byte pipe.
        Assert.True(harness.Http3.Streams.PeerSettingsReceived);
        Assert.Equal(PeerControlStreamId, harness.Http3.Streams.PeerControlStreamId);
    }

    [Fact]
    public async Task TwoRequestsOnOneConnectionEachLandOnTheirOwnReader()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        var first = harness.Http3.TryOpenRequest(Request(path: "/one"), out _, out _);
        var second = harness.Http3.TryOpenRequest(Request(path: "/two"), out _, out _);
        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal(FirstRequestStreamId, first.Id);
        Assert.Equal(SecondRequestStreamId, second.Id);
        await harness.FlushAsync(cancellation.Token);

        // THE SECOND STREAM IS ANSWERED FIRST, and the two responses differ in status, header
        // and body. An implementation that fed every arriving byte to one reader, or that
        // re-found the request stream by the literal id 0 as the spike did, gets one of these
        // three wrong on at least one stream.
        await harness.PeerSendsAsync(
            cancellation.Token,
            PeerControl(),
            Stream(
                SecondRequestStreamId,
                0,
                ResponseBytes(404, [("x-which", "two")], "second"u8.ToArray()),
                fin: true),
            Stream(
                FirstRequestStreamId,
                0,
                ResponseBytes(200, [("x-which", "one")], "first"u8.ToArray()),
                fin: true));

        var one = harness.Http3.ResponseFor(FirstRequestStreamId);
        var two = harness.Http3.ResponseFor(SecondRequestStreamId);
        Assert.NotNull(one);
        Assert.NotNull(two);
        Assert.Equal(200, one.Status);
        Assert.Equal(404, two.Status);
        Assert.Equal("one", FieldValue(one, "x-which"));
        Assert.Equal("two", FieldValue(two, "x-which"));
        Assert.Equal("first", Encoding.UTF8.GetString(one.Body));
        Assert.Equal("second", Encoding.UTF8.GetString(two.Body));
        Assert.Equal(
            new[] { FirstRequestStreamId, SecondRequestStreamId }, harness.Http3.RequestStreamIds);
    }

    [Fact]
    public async Task AResponseSplitAcrossThreeStreamFramesIsReassembled()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);
        Assert.NotNull(harness.Http3.TryOpenRequest(Request(), out _, out _));
        await harness.FlushAsync(cancellation.Token);

        // s7: "unlike QUIC frames, HTTP/3 frames can span multiple packets." The split is at
        // byte 3 and byte 9, chosen to fall INSIDE the HEADERS frame's payload rather than on a
        // frame boundary, so a reader that assumed each STREAM frame carried whole frames fails
        // and one that buffers passes. Three separate datagrams, one pump each.
        var response = ResponseBytes(200, [], "split"u8.ToArray());
        await harness.PeerSendsAsync(cancellation.Token, PeerControl());
        await harness.PeerSendsAsync(cancellation.Token, Stream(FirstRequestStreamId, 0, response[..3]));
        await harness.PeerSendsAsync(cancellation.Token, Stream(FirstRequestStreamId, 3, response[3..9]));
        await harness.PeerSendsAsync(
            cancellation.Token, Stream(FirstRequestStreamId, 9, response[9..], fin: true));

        var read = harness.Http3.ResponseFor(FirstRequestStreamId);
        Assert.NotNull(read);
        Assert.True(read.IsComplete);
        Assert.Equal(200, read.Status);
        Assert.Equal("split", Encoding.UTF8.GetString(read.Body));
    }

    [Fact]
    public async Task AFinThatArrivesWithNoNewBytesEndsTheResponseOnce()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);
        Assert.NotNull(harness.Http3.TryOpenRequest(Request(), out _, out _));
        await harness.FlushAsync(cancellation.Token);

        // The whole response, then a bare FIN at the final offset. s4.1 makes a second report
        // of end-of-stream an "additional HTTP response following a final HTTP response", so a
        // pump that re-reported it would fail with H3_FRAME_UNEXPECTED - and this test pumps
        // three more times after the FIN to say the report does not repeat.
        var response = ResponseBytes(204, [], []);
        await harness.PeerSendsAsync(cancellation.Token, PeerControl());
        await harness.PeerSendsAsync(cancellation.Token, Stream(FirstRequestStreamId, 0, response));
        await harness.PeerSendsAsync(
            cancellation.Token,
            Stream(FirstRequestStreamId, (ulong)response.Length, [], fin: true));

        for (var i = 0; i < 3; i++)
        {
            Assert.True(harness.Http3.TryProcess(out var repeated));
            Assert.Equal(0UL, repeated);
        }

        var read = harness.Http3.ResponseFor(FirstRequestStreamId);
        Assert.NotNull(read);
        Assert.True(read.IsComplete);
        Assert.Equal(204, read.Status);
    }

    // ------------------------------------------------------------------------
    // s6.2.1's H3_MISSING_SETTINGS, and the s8.1 mapping onto a QUIC close.
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // RFC 9110 s6.4.1's never-having-content set, in the half only this class can supply.
    // ------------------------------------------------------------------------

    // s6.4.1 opens its set with "Responses to the HEAD request method (Section 9.3.2) never
    // include content", which is a property of the REQUEST - so the response reader cannot
    // decide it and C10c gave TlsQuicHttp3Response an optional requestMethod for exactly this.
    // Nothing passed it until now, and the argument DEFAULTS to null, so the omission was a
    // silent refusal of a legal response rather than a compile error.
    //
    // HEAD IS THE ONLY UNAVOIDABLE CASE, and RFC 9110 s8.6 is why rather than convenience: "A
    // server MUST NOT send a Content-Length header field in any response with a status code of
    // 1xx (Informational) or 204 (No Content). A server MUST NOT send a Content-Length header
    // field in any 2xx (Successful) response to a CONNECT request." That leaves a HEAD response
    // and a 304 as the only two that MAY carry one, and 304 is decidable from :status alone.
    //
    // BOTH ROWS ARE THE WITNESS, NOT ONE. The HEAD row fails against a reader that was told
    // nothing; the GET row fails against one told a constant "HEAD" - which is the shape a
    // one-argument change gets wrong most cheaply. A single row would pass against one of the
    // two wrong implementations.
    [Theory]
    [InlineData("HEAD", true)]
    [InlineData("GET", false)]
    public async Task OnlyAHeadResponseMayDeclareAContentLengthItSendsNoDataFor(
        string method, bool accepted)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        Assert.NotNull(
            harness.Http3.TryOpenRequest(Request(method: method), out var refusal, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
        await harness.FlushAsync(cancellation.Token);

        // content-length: 1234 AND NO DATA FRAME AT ALL. s4.1.2 makes that malformed for a
        // message "defined as having content" however the sum is reached, and s6.4.1 closes with
        // "All other responses do include content, although that content might be of zero
        // length" - so the GET row is a message with zero-length content that declared 1234.
        await harness.PeerSendsAsync(
            cancellation.Token,
            expectAccepted: accepted,
            PeerControl(),
            Stream(
                FirstRequestStreamId,
                0,
                ResponseBytes(200, [("content-length", "1234")], []),
                fin: true));

        Assert.Equal(accepted, harness.Http3.TryProcess(out var errorCode));
        var response = harness.Http3.ResponseFor(FirstRequestStreamId);
        Assert.NotNull(response);

        if (accepted)
        {
            // s4.1.2's "Clients MUST NOT accept a malformed response" is not in play, so the
            // message completes - and it completes with the declared length still on it, which
            // is the whole point of s6.4.1's escape rather than a length that was ignored.
            Assert.Equal(0UL, errorCode);
            Assert.True(response.IsComplete);
            Assert.Equal(200, response.Status);
            Assert.Equal("1234", FieldValue(response, "content-length"));
            Assert.Equal(0, response.Body.Length);
            Assert.Equal(0UL, harness.Http3.ConnectionErrorCode);
        }
        else
        {
            // s4.1.2: "Malformed requests or responses that are detected MUST be treated as a
            // stream error of type H3_MESSAGE_ERROR." NAMED rather than asserted as "it failed":
            // five s8.1 codes end a connection here and any two would otherwise be exchangeable.
            Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3MessageError, errorCode);
            Assert.False(response.IsComplete);
            Assert.Equal(
                (ulong)TlsQuicHttp3ErrorCode.H3MessageError, harness.Http3.ConnectionErrorCode);
        }
    }

    [Fact]
    public async Task APeerControlStreamWhoseFirstFrameIsNotSettingsClosesWithMissingSettings()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        // s6.2.1: "If the first frame of the control stream is any other frame type, this MUST
        // be treated as a connection error of type H3_MISSING_SETTINGS." MAX_PUSH_ID is a
        // perfectly legal control-stream frame in every other position, which is what makes it
        // a sharper witness here than a malformed one.
        var control = new List<byte> { (byte)TlsQuicHttp3StreamType.Control };
        var maxPushId = new List<byte>();
        QuicVariableLengthInteger.Write(maxPushId, 7);
        TlsQuicHttp3Frames.Write(
            control, (ulong)TlsQuicHttp3FrameType.MaxPushId, maxPushId.ToArray());

        await harness.PeerSendsAsync(
            cancellation.Token,
            expectAccepted: false,
            Stream(PeerControlStreamId, 0, control.ToArray()));

        Assert.False(harness.Http3.TryProcess(out var errorCode));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3MissingSettings, errorCode);
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3MissingSettings, harness.Http3.ConnectionErrorCode);

        // ---- and the s8.1 code reaches a QUIC connection close ----
        var close = await harness.CloseAndReadTheDatagramAsync(cancellation.Token);

        // WHAT THIS CLASS ASKED FOR. Kept beside the frame rather than instead of it: the two
        // can disagree, because RFC 9000 s10.2.3 converts a 0x1d that cannot be sent at 1-RTT
        // and drops the code with it.
        Assert.Equal(
            (ulong)TlsQuicHttp3ErrorCode.H3MissingSettings,
            harness.Http3.ApplicationCloseErrorCode);

        // RFC 9000 s10.2's closing state is entered whether or not the peer can be told.
        Assert.True(harness.Connection.IsDraining);

        // ============================================================================
        // AND THE FRAME ON THE WIRE. THESE ASSERTIONS HAVE BEEN INVERTED TWICE, NOT DELETED.
        // ============================================================================
        //
        // C11 WROTE `Assert.Null(harness.Connection.ClosedWith)`, and the reason given was that
        // BuildCloseDatagram walked [Handshake, Initial] - "Application is absent because no
        // short header can be built" - while RFC 9001 s4.9 had discarded both of those levels by
        // the time HTTP/3 exists. The two key-state assertions below were the measurement, and
        // they still hold: those levels really are gone.
        //
        // A4 INVERTED THAT HALF. Task 14b built the short header and 14c gave this connection
        // ShortHeaderPlan, so "no short header can be built" was already false; the close path
        // simply never looked at the Application level. BuildCloseDatagram now takes RFC 9000
        // s10.2.3's confirmed branch - "After the handshake is confirmed ... an endpoint MUST
        // send any CONNECTION_CLOSE frames in a 1-RTT packet" - so a close now goes out. A4 left
        // `Assert.Equal(TlsQuicTransportError.ApplicationError, ClosedWith)` here and said in as
        // many words that it "is what would fail the moment this class is rewired to the 0x1d
        // path". This is that moment.
        Assert.Equal(
            TlsQuicKeyLevelState.Discarded,
            harness.Connection.WriteStateOf(TlsQuicEncryptionLevel.Handshake));
        Assert.Equal(
            TlsQuicKeyLevelState.Discarded,
            harness.Connection.WriteStateOf(TlsQuicEncryptionLevel.Initial));

        // s19.19: "The CONNECTION_CLOSE frame with a type of 0x1d is used to signal an error
        // with the application that uses QUIC", and s12.4 Table 3 gives 0x1d the row "__01", so
        // the level is the only column that row permits rather than a preference.
        Assert.Equal(0x1dUL, close.RawType);
        Assert.Equal(TlsQuicEncryptionLevel.Application, close.Level);

        // THE POINT OF THE WHOLE CHANGE, READ OFF THE FRAME AND NOT OFF A PROPERTY. s19.19: "A
        // CONNECTION_CLOSE frame of type 0x1d uses codes defined by the application protocol",
        // so H3_MISSING_SETTINGS arrives as itself. THE SECOND ASSERTION IS NOT REDUNDANT: the
        // mapping this replaced put s20.1's APPLICATION_ERROR (0x0c) in this field and the s8.1
        // code in the Reason Phrase, and 0x010a is inside s20.1's CRYPTO_ERROR range
        // (0x0100-0x01ff), so a reader of the old frame recovered a handshake failure.
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3MissingSettings, close.ErrorCode);
        Assert.NotEqual((ulong)TlsQuicTransportError.ApplicationError, close.ErrorCode);

        // s19.19's Reason Phrase is "additional diagnostic information" and nothing now depends
        // on it, but it is still sent, so it is still pinned - a frame that quietly stopped
        // carrying one is a wire change.
        Assert.Equal(
            "HTTP/3 (RFC 9114 s8.1) error code 0x10a."u8.ToArray(), close.ReasonPhrase);

        // NOTHING IN s20.1 WAS SENT, SO NOTHING IN s20.1 IS REPORTED.
        Assert.Equal(
            (ulong)TlsQuicHttp3ErrorCode.H3MissingSettings,
            harness.Connection.ClosedWithApplicationErrorCode);
        Assert.Null(harness.Connection.ClosedWith);
    }

    [Fact]
    public async Task AConnectionErrorIsStickyAndRefusesFurtherRequests()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        var control = new List<byte> { (byte)TlsQuicHttp3StreamType.Control };
        TlsQuicHttp3Frames.Write(control, (ulong)TlsQuicHttp3FrameType.Data, []);
        await harness.PeerSendsAsync(
            cancellation.Token,
            expectAccepted: false,
            Stream(PeerControlStreamId, 0, control.ToArray()));

        Assert.False(harness.Http3.TryProcess(out var first));
        Assert.False(harness.Http3.TryProcess(out var second));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3MissingSettings, first);
        Assert.Equal(first, second);

        Assert.Null(harness.Http3.TryOpenRequest(Request(), out var refusal, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.ConnectionErrored, refusal);
    }

    [Fact]
    public async Task AGracefulCloseUsesH3NoError()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        // s5.2: "An endpoint that completes a graceful shutdown SHOULD use the H3_NO_ERROR
        // error code when closing the connection."
        var close = await harness.CloseAndReadTheDatagramAsync(cancellation.Token);
        Assert.Equal(
            (ulong)TlsQuicHttp3ErrorCode.H3NoError, harness.Http3.ApplicationCloseErrorCode);
        Assert.NotEqual(0UL, harness.Http3.ApplicationCloseErrorCode);

        // THE SECOND CODE ON THE WIRE, AND THAT IS WHY THIS TEST READS THE FRAME TOO. The
        // missing-SETTINGS test above witnesses 0x010a; an implementation that wrote one
        // constant into s19.19's Error Code field would pass exactly one of the two.
        //
        // H3_NO_ERROR IS 0x0100, WHICH IS THE BASE OF s20.1's CRYPTO_ERROR (0x0100-0x01ff): "The
        // cryptographic handshake failed. A range of 256 values is reserved for carrying error
        // codes specific to the cryptographic handshake that is used." So a graceful HTTP/3
        // shutdown read as a transport code is a handshake failure, which is as wrong as this
        // frame can be while still parsing. s19.19's 0x1d is what keeps the two spaces apart.
        Assert.Equal(0x1dUL, close.RawType);
        Assert.Equal(TlsQuicEncryptionLevel.Application, close.Level);
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3NoError, close.ErrorCode);
        Assert.NotEqual((ulong)TlsQuicTransportError.ApplicationError, close.ErrorCode);
        Assert.Equal(
            "HTTP/3 (RFC 9114 s8.1) error code 0x100."u8.ToArray(), close.ReasonPhrase);
        Assert.Null(harness.Connection.ClosedWith);
    }

    // ------------------------------------------------------------------------
    // s5.2 and s7.2.6's GOAWAY.
    // ------------------------------------------------------------------------

    [Fact]
    public async Task AGoawayMidRequestIsRecordedAndTheResponseStillCompletes()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);
        Assert.NotNull(harness.Http3.TryOpenRequest(Request(), out _, out _));
        await harness.FlushAsync(cancellation.Token);

        // The GOAWAY arrives while stream 0 is outstanding and names stream 4, so s5.2's
        // "Requests on stream IDs less than the stream ID in a GOAWAY frame from the server
        // might have been processed" covers our request - and it then IS processed.
        await harness.PeerSendsAsync(
            cancellation.Token,
            PeerControl(),
            Stream(
                PeerControlStreamId,
                (ulong)PeerControl().Data.Length,
                GoawayFrame(SecondRequestStreamId)));
        await harness.PeerSendsAsync(
            cancellation.Token,
            Stream(
                FirstRequestStreamId,
                0,
                ResponseBytes(200, [], "served anyway"u8.ToArray()),
                fin: true));

        Assert.Equal(SecondRequestStreamId, harness.Http3.PeerGoawayStreamId);
        Assert.Equal(0UL, harness.Http3.ConnectionErrorCode);

        // s5.2: "Requests or pushes with the indicated identifier or greater are rejected."
        // GREATER THAN OR EQUAL - the named stream is itself rejected.
        Assert.False(harness.Http3.IsRejectedByGoaway(FirstRequestStreamId));
        Assert.True(harness.Http3.IsRejectedByGoaway(SecondRequestStreamId));
        Assert.True(harness.Http3.IsRejectedByGoaway(SecondRequestStreamId + 4));

        var response = harness.Http3.ResponseFor(FirstRequestStreamId);
        Assert.NotNull(response);
        Assert.True(response.IsComplete);
        Assert.Equal(200, response.Status);
        Assert.Equal("served anyway", Encoding.UTF8.GetString(response.Body));
    }

    [Fact]
    public async Task AGoawayForbidsANewRequest()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        // s5.2's identifier is the MAXIMUM one still processed, and this one is larger than the
        // stream the next request would take - so a check that compared the two, rather than
        // taking s5.2's "MUST NOT initiate new requests" unconditionally, would let it through.
        await harness.PeerSendsAsync(
            cancellation.Token, PeerControlWithGoaway(SecondRequestStreamId + 400));

        Assert.Null(harness.Http3.TryOpenRequest(Request(), out var refusal, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.GoawayReceived, refusal);
        Assert.Empty(harness.Http3.RequestStreamIds);
        Assert.Empty(harness.Peer.ReceivedStreamFrames);
    }

    [Theory]
    // s2.1's other three rows: client-initiated unidirectional, and both server-initiated
    // kinds. ALL THREE, because s7.2.6's "a stream ID of any other type" is two bits and a
    // check that tested one of them would pass here for the other two.
    [InlineData(1UL)]
    [InlineData(2UL)]
    [InlineData(3UL)]
    public async Task AGoawayNamingAStreamThatIsNotClientBidirectionalIsIdError(ulong identifier)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        await harness.PeerSendsAsync(
            cancellation.Token, expectAccepted: false, PeerControlWithGoaway(identifier));

        // s7.2.6: "A client MUST treat receipt of a GOAWAY frame containing a stream ID of any
        // other type as a connection error of type H3_ID_ERROR."
        Assert.False(harness.Http3.TryProcess(out var errorCode));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3IdError, errorCode);
        Assert.Null(harness.Http3.PeerGoawayStreamId);
    }

    [Fact]
    public async Task ASecondGoawayWithALargerIdentifierIsIdError()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        var control = PeerControlWithGoaway(SecondRequestStreamId);
        await harness.PeerSendsAsync(cancellation.Token, control);
        Assert.Equal(SecondRequestStreamId, harness.Http3.PeerGoawayStreamId);

        // s5.2: "Receiving a GOAWAY containing a larger identifier than previously received
        // MUST be treated as a connection error of type H3_ID_ERROR."
        await harness.PeerSendsAsync(
            cancellation.Token,
            expectAccepted: false,
            Stream(
                PeerControlStreamId,
                (ulong)control.Data.Length,
                GoawayFrame(SecondRequestStreamId + 4)));

        Assert.False(harness.Http3.TryProcess(out var errorCode));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3IdError, errorCode);

        // The rejected identifier did not replace the accepted one.
        Assert.Equal(SecondRequestStreamId, harness.Http3.PeerGoawayStreamId);
    }

    [Theory]
    // s5.2's rule is "MUST NOT be GREATER than the identifier in any previous frame", so an
    // identifier repeated is legal and a smaller one is the documented narrowing. A `>=`
    // where the source has `>` fails the first row and passes the second.
    [InlineData(SecondRequestStreamId, SecondRequestStreamId)]
    [InlineData(SecondRequestStreamId, FirstRequestStreamId)]
    public async Task ASecondGoawayNoGreaterThanTheFirstIsAcceptedAndReplacesIt(
        ulong first, ulong second)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        var control = PeerControlWithGoaway(first);
        await harness.PeerSendsAsync(cancellation.Token, control);
        await harness.PeerSendsAsync(
            cancellation.Token,
            Stream(PeerControlStreamId, (ulong)control.Data.Length, GoawayFrame(second)));

        // s5.2's narrowing sequence - "the endpoint can send another GOAWAY frame indicating
        // which requests or pushes it might accept" - only works if the LATER one stands.
        Assert.Equal(0UL, harness.Http3.ConnectionErrorCode);
        Assert.Equal(second, harness.Http3.PeerGoawayStreamId);
    }

    // ------------------------------------------------------------------------
    // s4.2.2's SETTINGS_MAX_FIELD_SECTION_SIZE, both halves.
    // ------------------------------------------------------------------------

    [Theory]
    // The receive half, which C10 left as a constructor argument defaulting to no limit. The
    // two rows straddle one response: at 4096 it decodes, at 64 the s4.2.2 arithmetic - name
    // plus value plus 32 per field - is already past the limit on the first field line.
    [InlineData(4096UL, true)]
    [InlineData(64UL, false)]
    public async Task TheAdvertisedMaximumFieldSectionSizeBoundsTheResponse(
        ulong advertised, bool accepted)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token,
            spec: new TlsQuicHttp3Spec
            {
                Settings = [new TlsQuicHttp3Setting(
                    TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, advertised)],
            });
        Assert.Equal((long)advertised, harness.Http3.MaximumFieldSectionSizeAdvertised);
        Assert.NotNull(harness.Http3.TryOpenRequest(Request(), out _, out _));
        await harness.FlushAsync(cancellation.Token);

        await harness.PeerSendsAsync(cancellation.Token, PeerControl());
        await harness.PeerSendsAsync(
            cancellation.Token,
            expectAccepted: accepted,
            Stream(
                FirstRequestStreamId,
                0,
                ResponseBytes(
                    200,
                    [("x-padding", new string('p', 200))],
                    "body"u8.ToArray()),
                fin: true));

        var succeeded = harness.Http3.TryProcess(out var errorCode);
        Assert.Equal(accepted, succeeded);
        if (!accepted)
        {
            // RFC 9204 s6's code for exactly this, reported through the same channel as s8.1's.
            Assert.NotEqual(0UL, errorCode);
            Assert.NotEqual((ulong)TlsQuicHttp3ErrorCode.H3MissingSettings, errorCode);
            return;
        }

        var response = harness.Http3.ResponseFor(FirstRequestStreamId);
        Assert.NotNull(response);
        Assert.Equal(200, response.Status);
    }

    [Theory]
    // The send half, which C9 left unenforced because TlsQuicHttp3Request holds no reference to
    // the peer's SETTINGS. s4.2.2: "An implementation that has received this parameter SHOULD
    // NOT send an HTTP message header that exceeds the indicated size." The same request is
    // sent against two advertised limits and only the small one refuses it.
    [InlineData(4096UL, true)]
    [InlineData(48UL, false)]
    public async Task ThePeersMaximumFieldSectionSizeBoundsTheRequest(
        ulong advertised, bool sent)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);
        await harness.PeerSendsAsync(
            cancellation.Token,
            PeerControl(
                new TlsQuicHttp3Setting(
                    TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, advertised)));
        Assert.Equal(advertised, harness.Http3.PeerMaximumFieldSectionSize);

        var stream = harness.Http3.TryOpenRequest(Request(), out var refusal, out _);
        if (sent)
        {
            Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
            Assert.NotNull(stream);
            return;
        }

        Assert.Equal(TlsQuicHttp3RequestRefusal.FieldSectionTooLargeForPeer, refusal);
        Assert.Null(stream);

        // NOTHING WAS SPENT. RFC 9000 s3.2 makes an ordinal taken and not sent to a stream the
        // peer opens implicitly and nothing ever writes to, so a refusal that had already
        // called OpenBidirectional would leave a hole in s2.1's numbering.
        Assert.Empty(harness.Http3.RequestStreamIds);
        await harness.FlushAsync(cancellation.Token, expectPacket: false);
        Assert.Empty(harness.Peer.ReceivedStreamFrames);
    }

    [Fact]
    public async Task APeerThatAdvertisesNoFieldSectionLimitBoundsNothing()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        // s4.2.2 makes the parameter how an implementation "wishes to advise its peer of this
        // limit", so a peer that sends none has advised nothing - and an implementation that
        // read an absent setting as zero would refuse every request here.
        await harness.PeerSendsAsync(cancellation.Token, PeerControl());
        Assert.Null(harness.Http3.PeerMaximumFieldSectionSize);
        Assert.NotNull(harness.Http3.TryOpenRequest(Request(), out var refusal, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
    }

    // ------------------------------------------------------------------------
    // The witnesses the mutation sweep asked for.
    // ------------------------------------------------------------------------

    [Fact]
    public async Task AGoawayOfZeroStillForbidsANewRequest()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        // s5.2: "This identifier MAY be zero if no requests or pushes were processed." Zero is
        // the STRONGEST GOAWAY a server can send, not an absent one, and stream 0 is s2.1's
        // client-initiated bidirectional row so s7.2.6 accepts it.
        //
        // THIS IS THE ROW-4 WITNESS. A refusal that compared the identifier against the stream
        // the next request would take - rather than taking s5.2's "MUST NOT initiate new
        // requests" unconditionally - reads 0 > 0 as false here and lets the request through.
        // AGoawayForbidsANewRequest cannot see that, because its identifier is 404.
        await harness.PeerSendsAsync(cancellation.Token, PeerControlWithGoaway(0));
        Assert.Equal(0UL, harness.Http3.PeerGoawayStreamId);

        Assert.Null(harness.Http3.TryOpenRequest(Request(), out var refusal, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.GoawayReceived, refusal);
        Assert.True(harness.Http3.IsRejectedByGoaway(FirstRequestStreamId));
    }

    [Fact]
    public async Task TheConnectionEncodesTheRequestWithItsOwnSpecAndNotADefaultOne()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token,
            spec: new TlsQuicHttp3Spec { SendReservedFramesOnRequestStreams = true });

        Assert.NotNull(harness.Http3.TryOpenRequest(Request(), out _, out _));
        await harness.FlushAsync(cancellation.Token);

        // s7.2.8's reserved frame is emitted only because THIS connection's spec asked for it.
        // A connection that built a fresh TlsQuicHttp3Spec for the encoder would send a bare
        // HEADERS frame and every other assertion in this file would still pass - which is
        // what row 12 of the sweep did until this test existed.
        var sent = Assert.Single(harness.Peer.ReceivedStreamFrames);
        var offset = 0;
        Assert.Equal(
            TlsQuicHttp3FrameReadStatus.Complete,
            TlsQuicHttp3Frames.TryRead(sent.Data, ref offset, out var first, out _, out _));
        Assert.True(
            TlsQuicHttp3Frames.IsReservedIdentifier(first),
            $"The first frame was 0x{first:x}, not a reserved one.");

        // And the HEADERS frame still follows it.
        Assert.Equal(
            TlsQuicHttp3FrameReadStatus.Complete,
            TlsQuicHttp3Frames.TryRead(sent.Data, ref offset, out var second, out _, out _));
        Assert.Equal((ulong)TlsQuicHttp3FrameType.Headers, second);
    }

    [Fact]
    public async Task TheReservedFrameIsNotMeasuredAsTheFieldSection()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token,
            spec: new TlsQuicHttp3Spec { SendReservedFramesOnRequestStreams = true });
        await harness.PeerSendsAsync(
            cancellation.Token,
            PeerControl(
                new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 48)));

        // s4.2.2's limit applies to the HEADERS frame's field section. With a reserved frame in
        // front of it, a measurement that took the FIRST frame would measure s7.2.8's empty
        // payload, fail to decode that as a field section, and let an oversized request
        // through.
        Assert.Null(
            harness.Http3.TryOpenRequest(
                Request(field: ("x-big", new string('b', 300))), out var refusal, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.FieldSectionTooLargeForPeer, refusal);
        Assert.Empty(harness.Http3.RequestStreamIds);
    }

    [Fact]
    public async Task ASettingIsFoundByItsIdentifierRatherThanByItsPosition()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        // s7.2.4 fixes no order, so the wanted identifier can sit anywhere. The decoy is FIRST
        // and carries a value that would be a legal - and wrong - answer. A lookup that
        // returned the first pair regardless of identifier reads 1 here instead of 4096.
        await harness.PeerSendsAsync(
            cancellation.Token,
            PeerControl(
                new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 1),
                new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 4096)));

        Assert.Equal(4096UL, harness.Http3.PeerMaximumFieldSectionSize);
    }

    [Fact]
    public async Task OurSpecWithoutAMaxFieldSectionSizeAdvertisesNoLimit()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);

        // rfc9114-section7-framing-layer.txt: "SETTINGS_MAX_FIELD_SECTION_SIZE (0x06): The
        // default value is unlimited." So a connection whose own SETTINGS omit 0x06 has advised
        // nothing and must bound no response - an absent setting read as ZERO would refuse
        // every field section the peer ever sent, which is Finding 1's absent-versus-zero shape
        // exactly.
        using var harness = await Harness.CreateAsync(
            cancellation.Token,
            spec: new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 0),
                ],
            });
        Assert.Equal(long.MaxValue, harness.Http3.MaximumFieldSectionSizeAdvertised);

        Assert.NotNull(harness.Http3.TryOpenRequest(Request(), out _, out _));
        await harness.FlushAsync(cancellation.Token);
        await harness.PeerSendsAsync(cancellation.Token, PeerControl());
        await harness.PeerSendsAsync(
            cancellation.Token,
            Stream(
                FirstRequestStreamId,
                0,
                ResponseBytes(200, [("x-padding", new string('p', 400))], "body"u8.ToArray()),
                fin: true));

        var response = harness.Http3.ResponseFor(FirstRequestStreamId);
        Assert.NotNull(response);
        Assert.True(response.IsComplete);
        Assert.Equal(200, response.Status);
    }

    // ------------------------------------------------------------------------
    // The peer's flow-control limits refuse rather than throw.
    // ------------------------------------------------------------------------

    [Fact]
    public async Task APeerBidirectionalStreamAllowanceOfZeroRefusesRatherThanThrows()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token, flowControl: FlowControlParameters(streamsBidi: 0));

        // TlsQuicStreamSet.OpenBidirectional throws on an exhausted budget, and a peer must not
        // be able to raise an exception out of this path.
        Assert.Null(harness.Http3.TryOpenRequest(Request(), out var refusal, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.PeerBidirectionalStreamsExhausted, refusal);
        Assert.Empty(harness.Http3.RequestStreamIds);
    }

    [Fact]
    public async Task APeerStreamCreditOfZeroRefusesRatherThanSpendingAnOrdinal()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token, flowControl: FlowControlParameters(bidiRemote: 0));

        // ZERO, NOT MERELY SMALL - and the difference is the whole of this task. A credit that
        // is too small for the message is now PACED (see
        // ABodyPastThePeersInitialStreamCreditIsPacedAgainstRealGrants below); a credit of zero
        // is the peer's own transport parameters saying no byte may be written to a
        // bidirectional stream at all, so spending an ordinal out of initial_max_streams_bidi -
        // which no frame this tree handles can raise - buys nothing.
        //
        // A refusal that read the wrong parameter would find 1_000_005 or 1_000_007 here and
        // let it through.
        Assert.Null(harness.Http3.TryOpenRequest(Request(), out var refusal, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.PeerStreamCreditTooSmall, refusal);
        Assert.Empty(harness.Http3.RequestStreamIds);
    }

    // AND THE ADJACENT VALUE IS ACCEPTED, which is what makes the arm above a zero test rather
    // than a size test wearing a smaller number. One byte of credit cannot carry the 29-octet
    // HEADERS frame either, so the old `<` comparison refused this too; the request now opens,
    // sends the one byte it is allowed and holds the rest.
    [Fact]
    public async Task APeerStreamCreditOfOneOpensTheStreamRatherThanRefusingIt()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token, flowControl: FlowControlParameters(bidiRemote: 1));

        var stream = harness.Http3.TryOpenRequest(Request(), out var refusal, out _);
        Assert.NotNull(stream);
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
        Assert.True(stream.HasBlockedData);
    }

    [Fact]
    public async Task AMalformedRequestIsRefusedWithoutOpeningAStream()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        // s4.3.1: ":path ... MUST NOT be empty for \"http\" or \"https\" URIs."
        Assert.Null(
            harness.Http3.TryOpenRequest(Request(path: ""), out var refusal, out var malformed));
        Assert.Equal(TlsQuicHttp3RequestRefusal.Malformed, refusal);
        Assert.Equal(TlsQuicHttp3RequestError.MandatoryPseudoHeaderValueInvalid, malformed);
        Assert.Empty(harness.Http3.RequestStreamIds);
    }

    // ========================================================================================
    // TASK C17: THE TWO HALVES OF THE DATAGRAM CLAIM, AND THE ONLY PLACE THEY MEET.
    //
    // SETTINGS_H3_DATAGRAM (0x33) lives on TlsQuicHttp3Spec; max_datagram_frame_size (0x20)
    // lives in the ClientHello, one layer down and behind a different spec. Neither can see
    // the other, so "I will receive HTTP/3 datagrams" is composable as a half-claim - and the
    // half-claim's only symptom used to be remote. C16 stopped the live HTTP/3 test narrowing
    // its SETTINGS, so it began sending CaptureSettings' 51:1 over a hand-typed parameter list
    // with no 0x20 in it, and fp.impersonate.pro answered H3_SETTINGS_ERROR (0x0109) five times
    // out of five with discarded=0 - not loss, a verdict.
    //
    // THE FOUR TESTS BELOW ARE THE FOUR STATES OF THAT PAIR, and each is a direction the check
    // has to get right rather than a restatement of the constructor:
    //   1:1 with no 0x20            refused, and the message names both halves.
    //   1:1 with 0x20 = 0           refused too - RFC 9221 s3 makes a zero and an absence one
    //                               state: "MUST NOT send DATAGRAM frames until it has received
    //                               the max_datagram_frame_size transport parameter with a
    //                               NON-ZERO value".
    //   51:0, or 51 absent, no 0x20 allowed - nothing was claimed, so nothing is inconsistent.
    //   1:1, no 0x20, exemption set allowed - a caller reproducing a client that really sends
    //                               the pair is not overruled. THIS IS THE ONE THAT MAKES IT A
    //                               DEFAULT RATHER THAN A RULE, and without it the check would
    //                               be the library deciding a fingerprint on the caller's
    //                               behalf.
    // ========================================================================================

    [Fact]
    public async Task AnH3DatagramSettingWithoutTheTransportParameterIsRefusedAtComposition()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            async () => await Harness.CreateAsync(
                cancellation.Token, maxDatagramFrameSize: null));

        // BOTH HALVES NAMED, because 0x109 names neither and that is the whole reason this
        // moved local. A caller who reads only the message must be able to find both lines.
        Assert.Contains("SETTINGS_H3_DATAGRAM (0x33)", exception.Message, StringComparison.Ordinal);
        Assert.Contains("max_datagram_frame_size", exception.Message, StringComparison.Ordinal);
        Assert.Contains(
            nameof(TlsQuicHttp3Spec.AllowDatagramSettingWithoutTransportParameter),
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AZeroMaxDatagramFrameSizeIsTreatedAsNoDatagramSupport()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        await Assert.ThrowsAsync<ArgumentException>(
            async () => await Harness.CreateAsync(cancellation.Token, maxDatagramFrameSize: 0));
    }

    [Theory]
    [InlineData(0UL)]
    [InlineData(null)]
    public async Task NotClaimingDatagramsNeedsNoTransportParameter(ulong? datagramSetting)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        System.Collections.Immutable.ImmutableArray<TlsQuicHttp3Setting> settings =
            datagramSetting is { } value
            ? [.. TlsQuicHttp3Spec.CaptureSettings
                .Select(s => s.Identifier == TlsQuicHttp3Spec.H3DatagramIdentifier
                    ? new TlsQuicHttp3Setting(s.Identifier, value)
                    : s)]
            : [.. TlsQuicHttp3Spec.CaptureSettings
                .Where(s => s.Identifier != TlsQuicHttp3Spec.H3DatagramIdentifier)];

        using var harness = await Harness.CreateAsync(
            cancellation.Token,
            new TlsQuicHttp3Spec { Settings = settings },
            maxDatagramFrameSize: null);

        Assert.NotNull(harness.Http3);
    }

    [Fact]
    public async Task TheExemptionLetsACallerComposeTheInconsistentPairOnPurpose()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        var spec = new TlsQuicHttp3Spec { AllowDatagramSettingWithoutTransportParameter = true };
        using var harness = await Harness.CreateAsync(
            cancellation.Token, spec, maxDatagramFrameSize: null);

        // AND THE PAIR IS STILL SENT UNCHANGED - the exemption suppresses the refusal, it does
        // not quietly drop 0x33 or invent a transport parameter. A check that "fixed" the
        // fingerprint would be worse than the one it replaced.
        Assert.NotNull(harness.Http3);
        Assert.Equal(
            1UL,
            TlsQuicHttp3Settings.Value(
                spec.Settings, TlsQuicHttp3Spec.H3DatagramIdentifier));
        Assert.Null(harness.Connection.AdvertisedMaxDatagramFrameSize);
    }

    // ------------------------------------------------------------------------
    // Scaffolding.
    // ------------------------------------------------------------------------

    // The whole offline setup in one place: two in-memory transports, our connection, the
    // loopback server peer, a confirmed handshake and an HTTP/3 layer with its opening flight
    // queued. It is a class rather than a method because six disposables have to outlive the
    // call and xunit has no scoped-using helper for that shape.
    // ------------------------------------------------------------------------
    // RFC 9114 s4.1's content and trailer section, on the wire.
    //
    // EVERY ONE OF THESE READS harness.Peer.ReceivedStreamFrames - bytes that were encoded,
    // packed into a 1-RTT packet, protected, sent, unprotected and decoded by the other side -
    // and walks them with TlsQuicHttp3Frames.TryRead, the parser TlsQuicHttp3Response's own
    // frame loop uses. Asserting what TryOpenRequest was HANDED would pass against a
    // TryOpenRequest that dropped the body on the floor.
    // ------------------------------------------------------------------------

    [Fact]
    public async Task ARequestWithABodyReachesTheWireAsHeadersThenDataThenOneFin()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);
        var body = "{\"hello\":\"http3\"}"u8.ToArray();

        var stream = harness.Http3.TryOpenRequest(
            Request(
                method: "POST",
                field: ("content-length", body.Length.ToString(CultureInfo.InvariantCulture)),
                body: body),
            out var refusal,
            out var malformed);
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
        Assert.Equal(TlsQuicHttp3RequestError.None, malformed);
        Assert.NotNull(stream);

        await harness.FlushAsync(cancellation.Token);

        // ONE STREAM FRAME AND ONE FIN. s4.1's three items are three HTTP/3 frames inside one
        // QUIC stream, and s4.1's "After sending a request, a client MUST close the stream for
        // sending" is that one FIN - not one per HTTP/3 frame.
        var sent = Assert.Single(harness.Peer.ReceivedStreamFrames);
        Assert.Equal(FirstRequestStreamId, sent.StreamId);
        Assert.Equal(0UL, sent.Offset);
        Assert.True(sent.Fin);

        var frames = ReadHttp3Frames(sent.Data);
        Assert.Equal(
            [(ulong)TlsQuicHttp3FrameType.Headers, (ulong)TlsQuicHttp3FrameType.Data],
            frames.ConvertAll(frame => frame.Type).ToArray());
        Assert.Equal(body, frames[1].Payload);
    }

    // THE FINGERPRINT PIN, AND IT IS A TRANSCRIPT RATHER THAN A SHAPE. h3's request-stream
    // fingerprint is the exact octets a request stream carries, and the easiest way to break it
    // while every structural assertion still passes is to start emitting an empty DATA frame
    // for a body-less request - two octets, 0x00 0x00, that no capture in this repository
    // records. A frame-type list would not notice a Length that changed; a byte comparison
    // does.
    //
    // THE EXPECTED STRING IS THE PRE-BODY ENCODER'S OUTPUT, recorded off this same wire before
    // Body and Trailers existed, and it must not be regenerated from the code it checks - a pin
    // rewritten from its own subject pins nothing. If a deliberate change to the request
    // encoding ever moves it, the new value belongs here with the reason beside it.
    [Fact]
    public async Task AGetsBytesOnTheWireAreUnchangedByTheBodyPath()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        Assert.NotNull(harness.Http3.TryOpenRequest(Request(), out var refusal, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
        await harness.FlushAsync(cancellation.Token);

        var sent = Assert.Single(harness.Peer.ReceivedStreamFrames);
        Assert.True(sent.Fin);
        Assert.Equal(GetTranscript, Convert.ToHexString(sent.Data.ToArray()));
    }

    // The recorded octets of Request()'s GET on the default spec. See the test above for why
    // this is a literal.
    //
    // MEASURED AT PRISTINE HEAD (3d1fbef) AND NOT AT THE CHANGE THAT ADDED IT, which is the
    // difference between a pin and a photograph of the mutant. The whole working tree was
    // stashed, AFullRequestAndResponseCompleteAgainstTheLoopbackPeer was given a one-line
    // Assert.Fail(Convert.ToHexString(sent.Data)) probe, and the pre-body encoder printed these
    // 29 octets - 0x01 HEADERS, 0x1B length 27, the RFC 9204 s4.5.1 prefix 00 00, then the four
    // pseudo-header lines. Recording it from the new code would have made the test agree with
    // whatever the new code does, including an empty DATA frame.
    private const string GetTranscript =
        "011B0000D1508CA0E7AE3193AAE5F23A6BA0BFD7518760759989D29AD9";

    // THE ACCEPTANCE TEST: A BODY SIXTEEN TIMES THE PEER'S INITIAL PER-STREAM CREDIT, COMPLETED
    // THROUGH THE HTTP/3 PATH AND DRIVEN BY REAL GRANTS OFF THE WIRE.
    //
    // This is the test that used to assert the opposite. RFC 9000 s19.10 binds a sender to "the
    // LARGEST maximum stream data value advertised by the receiver", and the advertised initial
    // is only the first member of that set - so pre-flighting the whole encoded message against
    // initial_max_stream_data_bidi_remote refused requests the stream layer can now complete.
    //
    // THE GRANTS ARE REAL, NOT INJECTED. Each one is a MAX_STREAM_DATA frame the loopback peer
    // encrypts into a 1-RTT datagram, which the client opens through TlsQuicConnection's own
    // receive dispatch. Nothing here calls TryReceiveMaxStreamData directly, which is the
    // difference between witnessing the path and witnessing the helper.
    //
    // AND COMPLETION ALONE IS NOT THE ASSERTION. A body that never left, or one grant that
    // covered everything, would both "complete". The count of grants, the offset after the
    // first flush and the offset at the end are asserted separately so that a send path which
    // quietly ignored the credit would fail rather than pass fast.
    [Fact]
    public async Task ABodyPastThePeersInitialStreamCreditIsPacedAgainstRealGrants()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);

        // 512 BYTES OF CREDIT AND AN 8 KiB BODY - SIXTEEN TIMES IT - AND THE SIZE HAS A
        // MEASURED CEILING ABOVE IT THAT IS NOT FLOW CONTROL. Nothing in this harness
        // acknowledges: LoopbackQuicPeer.SendAckAsync writes a single-packet range ("ONE RANGE,
        // THE ONE PACKET"), which cannot keep a multi-packet flow acknowledged, and calling it
        // per round made things worse rather than better - loss detection declared the
        // unacknowledged remainder lost. So the client never leaves RFC 9002's INITIAL
        // congestion window, and the exchange must fit inside it. Bisected on this test: a
        // 13312-byte body completes and a 14336-byte one stops at 14336 of 16424 bytes
        // delivered, with the datagrams after that carrying an ACK and no STREAM frame. That is
        // the ~14720-byte initial window, and it is the TEST PEER's ceiling rather than the send
        // path's - ASixteenKilobyteBodyReachesThePeerByteForByte moves 16 KiB in a single
        // window. 8 KiB sits comfortably under it so this test is not pinned to that boundary.
        const ulong InitialCredit = 512;
        const ulong GrantStep = 2048;
        using var harness = await Harness.CreateAsync(
            cancellation.Token,
            flowControl: FlowControlParameters(bidiRemote: (int)InitialCredit));
        var body = PatternedBody(8192);

        var stream = harness.Http3.TryOpenRequest(
            Request(
                method: "POST",
                field: ("content-length", body.Length.ToString(CultureInfo.InvariantCulture)),
                body: body),
            out var refusal,
            out _);

        // OPENED, NOT REFUSED. The encoded message is past 8 KiB and the credit is 512 bytes,
        // so the old `budget.InitialMaxStreamDataBidiRemote < (ulong)frame.Count` refused it.
        Assert.NotNull(stream);
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);

        // THE FIRST FLUSH CARRIES EXACTLY THE INITIAL CREDIT AND NOT A BYTE MORE. A send path
        // that ignored the peer's limit would put the whole message out here and every later
        // assertion would then be vacuous.
        await harness.FlushAsync(cancellation.Token);
        Assert.Equal(InitialCredit, stream.SendOffset);
        Assert.True(stream.HasBlockedData);

        // s19.13's STREAM_DATA_BLOCKED went out with it - the half without which the deferral
        // would be a hang - but that frame is TlsQuicStreams.cs's contract and is asserted
        // there; LoopbackQuicPeer records only STREAM frames, so this file cannot read it back
        // off the wire without reaching into a helper that is not this task's.

        // SEVERAL REAL GRANTS, NOT ONE. A single grant to 2^62-1 would also complete the body
        // and would prove much less - it could not tell a send path that paces from one that
        // gave up on the limit entirely. The step is larger than the initial credit because
        // every round costs a datagram out of the window above.
        var grants = 0;
        for (var limit = InitialCredit + GrantStep; stream.HasBlockedData; limit += GrantStep)
        {
            Assert.True(grants < 64, "the body never drained, so a grant is not being applied");
            Assert.True(await harness.GrantStreamCreditAsync(cancellation.Token, stream, limit));
            grants++;
            await harness.DrainToPeerAsync(cancellation.Token);
        }

        Assert.False(stream.HasBlockedData);
        Assert.True(grants >= 4, $"expected at least 4 grants, paced on {grants}");

        // THE OFFSET ADVANCED PAST THE INITIAL CREDIT, ASSERTED AS ITS OWN FACT.
        Assert.True(stream.SendOffset > InitialCredit);
        Assert.Equal((ulong)harness.Peer.ReceivedStreamFrames.Sum(f => f.Data.Length),
            stream.SendOffset);

        // AND THE BYTES ARRIVED, IN ORDER, THROUGH THE HTTP/3 FRAMING.
        var reassembled = new List<byte>();
        var fin = false;
        foreach (var frame in harness.Peer.ReceivedStreamFrames)
        {
            Assert.Equal(stream.Id, frame.StreamId);
            Assert.Equal((ulong)reassembled.Count, frame.Offset);
            reassembled.AddRange(frame.Data.ToArray());
            fin |= frame.Fin;
        }

        Assert.True(fin);
        var frames = ReadHttp3Frames(reassembled.ToArray());
        Assert.Equal(
            [(ulong)TlsQuicHttp3FrameType.Headers, (ulong)TlsQuicHttp3FrameType.Data],
            frames.ConvertAll(frame => frame.Type).ToArray());
        Assert.Equal(body, frames[1].Payload);
    }

    // THE OTHER HALF OF THE SAME CLAIM: A BODY NOBODY EVER GRANTS FAILS ON THE DEADLINE. Pacing
    // instead of refusing is only correct if the wait is bounded - otherwise the change trades a
    // named refusal for a hang, which is strictly worse. The peer here is given the request and
    // simply never sends MAX_STREAM_DATA.
    [Fact]
    public async Task ABodyThatIsNeverGrantedStopsOnTheDeadlineRatherThanHanging()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token, flowControl: FlowControlParameters(bidiRemote: 1024));

        var stream = harness.Http3.TryOpenRequest(
            Request(method: "POST", body: PatternedBody(16 * 1024)), out var refusal, out _);
        Assert.NotNull(stream);
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);

        await harness.FlushAsync(cancellation.Token);
        Assert.Equal(1024ul, stream.SendOffset);
        Assert.True(stream.HasBlockedData);

        // NOTHING MORE GOES OUT, AND NOTHING SPINS. SendPendingAsync has no frame to build once
        // the credit is spent and the blocked signal is already claimed, so it answers false
        // rather than looping - the tail sits in the stream's queue holding slices of the
        // caller's own buffer.
        Assert.False(await harness.Connection.SendPendingAsync(cancellation.Token));
        Assert.True(stream.HasBlockedData);
        Assert.Equal(1024ul, stream.SendOffset);

        // AND THE BOUND IS THE CONNECTION'S, NOT THE TEST'S. A deadline in the past makes the
        // wait terminate by assertion here instead of by TestTimeout, which is the difference
        // between proving a bound and observing one.
        var expired = new CancellationTokenSource();
        await expired.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await harness.Connection.PumpOnceAsync(expired.Token));
    }

    // THE OTHER LIMIT Consume CHARGES, and until bodies existed nothing read it. The per-stream
    // credit here is the default million, so a refusal that checked only that parameter would
    // let this request through and TlsQuicStreamSet.Send would then throw out of a path whose
    // documented contract is that no peer state can raise an exception from it.
    [Fact]
    public async Task ABodyPastThePeersConnectionCreditNamesTheConnectionLimit()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token, flowControl: FlowControlParameters(initialMaxData: 2048));

        // THE FIRST REQUEST DRAINS THE POOL TO EXACTLY ZERO, and it does so by being PACED
        // rather than by being sized: TlsQuicStreamSet.Send consumes precisely
        // Math.Min(stream, connection), so a body larger than what is left takes all of what is
        // left and holds the rest. That is now the only way this refusal is reached, and it is
        // what makes the check read RemainingConnectionData - initial_max_data is still 2048
        // here, so an implementation comparing against the advertised figure would let the
        // second request through.
        Assert.NotNull(
            harness.Http3.TryOpenRequest(
                Request(method: "POST", body: PatternedBody(4096)), out var first, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, first);
        Assert.Equal(0ul, harness.Connection.PeerFlowControl.RemainingConnectionData);

        var refusal = TlsQuicHttp3RequestRefusal.None;
        TlsQuicStream? stream = null;

        // NOT THROWN, ASSERTED AS SUCH. TlsQuicPeerFlowControlBudget.ConsumeConnectionData
        // throws on this exact condition, and TryOpenRequest's contract is that no peer state
        // can raise an exception out of it.
        Assert.Null(
            Record.Exception(
                () => stream = harness.Http3.TryOpenRequest(
                    Request(method: "POST", body: PatternedBody(4096)), out refusal, out _)));

        Assert.Null(stream);
        Assert.Equal(TlsQuicHttp3RequestRefusal.PeerConnectionCreditTooSmall, refusal);
        Assert.Equal([FirstRequestStreamId], harness.Http3.RequestStreamIds);
    }

    // THE CONNECTION-LEVEL LIMIT PACES TOO, AND s19.9's MAX_DATA IS WHAT RELEASES IT. Both
    // requests here are identical and both fit the advertised initial_max_data on their own;
    // only the second exceeds what is LEFT of it. That used to be a refusal. It is now a partial
    // send that resumes when the pool is raised - the connection-scope twin of
    // ABodyPastThePeersInitialStreamCreditIsPacedAgainstRealGrants, reached through a limit the
    // per-stream credit is nowhere near.
    [Fact]
    public async Task ASecondBodyPastWhatIsLeftOfThePoolIsPacedUntilMaxDataArrives()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token, flowControl: FlowControlParameters(initialMaxData: 6000));
        var body = PatternedBody(4096);

        Assert.NotNull(
            harness.Http3.TryOpenRequest(
                Request(method: "POST", body: body), out var first, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, first);

        var second = harness.Http3.TryOpenRequest(
            Request(method: "POST", body: body), out var refusal, out _);
        Assert.NotNull(second);
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);

        // THE POOL IS THE BINDING LIMIT, NOT THE STREAM'S OWN CREDIT. The second stream is
        // fresh, so its per-stream credit is the untouched default million; everything it failed
        // to send it failed to send for want of connection-level room.
        Assert.Equal(0ul, harness.Connection.PeerFlowControl.RemainingConnectionData);
        Assert.True(second.HasBlockedData);
        var stalledAt = second.SendOffset;
        await harness.DrainToPeerAsync(cancellation.Token);
        Assert.Equal(stalledAt, second.SendOffset);

        // ONE MAX_DATA, AND THE TAIL GOES. 64 KiB is comfortably past both bodies together.
        Assert.True(
            await harness.GrantConnectionCreditAsync(cancellation.Token, 64 * 1024));
        await harness.DrainToPeerAsync(cancellation.Token);

        Assert.False(second.HasBlockedData);
        Assert.True(second.SendOffset > stalledAt);
        Assert.Equal([FirstRequestStreamId, FirstRequestStreamId + 4],
            harness.Http3.RequestStreamIds);
    }

    // ------------------------------------------------------------------------
    // RFC 9000 s14.2: no datagram exceeds the maximum datagram size.
    // ------------------------------------------------------------------------

    [Theory]
    [InlineData(512)]
    [InlineData(2048)]
    [InlineData(8192)]
    [InlineData(32768)]
    public async Task NoDatagramExceedsThePathMtuHoweverLargeTheBody(int bodyBytes)
    {
        // s14.2: "All QUIC packets that are not sent in a PMTU probe SHOULD be sized to fit
        // within the maximum datagram size to avoid the datagram being fragmented or dropped",
        // and, in the absence of discovery, "QUIC endpoints SHOULD NOT send datagrams larger
        // than the smallest allowed maximum datagram size" - 1200 bytes.
        //
        // THIS TEST EXISTS BECAUSE THE AUDIT DID NOT HAVE IT AND THE BUG WAS REAL. There was no
        // ceiling on the send path at all: Drain moved an entire request body into one STREAM
        // frame bounded only by the peer's flow-control credit, and the datagram builder packed
        // it into one datagram bounded only by the 65527-byte send buffer. Measured before the
        // fix, one datagram per row: 577, 2113, 8257 and 32837 bytes.
        //
        // AND IT IS A REAL FAILURE, NOT A LATENT ONE. RFC 9000 s14 requires the DF bit to be
        // set - "In IPv4, the Don't Fragment (DF) bit MUST be set if possible" - and both
        // shipped transports set it, so on a 1500-byte MTU every datagram over 1472 bytes is
        // refused at the socket with SocketError.MessageSize. Verified against a live interface
        // at exactly that boundary: 1472 sent, 1473 threw.
        //
        // THE ROWS STRADDLE THE THRESHOLD. 512 bytes fitted a single datagram before the fix
        // and still does, so it is the control; the other three did not and now do not.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token, flowControl: FlowControlParameters(bidiRemote: 1024 * 1024));

        var before = harness.ClientTransport.Sent.Count;
        Assert.NotNull(harness.Http3.TryOpenRequest(
            Request(method: "POST", body: PatternedBody(bodyBytes)), out var refusal, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);

        await harness.DrainToPeerAsync(cancellation.Token);

        var sent = harness.ClientTransport.Sent.Skip(before).ToArray();
        Assert.NotEmpty(sent);

        // THE CEILING IS THE CONNECTION'S OWN FIGURE, not a literal repeated here: reading it
        // back means a spec whose BasePathMtu was raised still gets checked against what it
        // asked for rather than against 1200.
        var ceiling = harness.Connection.DatagramPayloadBudget;
        foreach (var datagram in sent)
        {
            Assert.True(
                datagram.Length <= ceiling,
                $"a datagram of {datagram.Length} bytes exceeds the {ceiling}-byte budget");
        }

        // AND THE BODY STILL ARRIVES WHOLE. A ceiling that dropped the tail would pass every
        // assertion above, which is the failure this line exists to catch.
        var reassembled = new List<byte>();
        foreach (var frame in harness.Peer.ReceivedStreamFrames)
        {
            reassembled.AddRange(frame.Data.ToArray());
        }

        var frames = ReadHttp3Frames(reassembled.ToArray());
        Assert.Equal(bodyBytes, frames[^1].Payload.Length);
    }

    // A BODY MANY TIMES THE SIZE OF ANY HEADERS FRAME, ARRIVING INTACT. 16 KiB is past the
    // one-byte and two-byte QUIC varint ceilings for the s7.1 Length (RFC 9000 s16 puts those
    // at 63 and 16383), so the frame writer's length encoding, the STREAM frame's own length
    // and the packet builder all carry a value none of the small-body cases reach.
    [Fact]
    public async Task ASixteenKilobyteBodyReachesThePeerByteForByte()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);
        var body = PatternedBody(16 * 1024);

        Assert.NotNull(
            harness.Http3.TryOpenRequest(
                Request(
                    method: "POST",
                    field: ("content-length", body.Length.ToString(CultureInfo.InvariantCulture)),
                    body: body),
                out var refusal,
                out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);

        // DrainToPeerAsync AND NOT FlushAsync, WHICH IS THE CHANGE RFC 9000 s14.2 FORCED. Flush
        // sends exactly one datagram and asserts one was built; that was enough while a 16 KiB
        // body went out as a single 16473-byte datagram. It no longer does - the path MTU
        // ceiling caps a datagram at 1200 bytes, so this body is about fifteen of them - and a
        // one-datagram flush now leaves the FIN unsent. The paragraph below anticipated exactly
        // this and is why nothing else in the test had to move.
        await harness.DrainToPeerAsync(cancellation.Token);

        // REASSEMBLED FROM WHATEVER FRAMES IT TOOK. Nothing here assumes one STREAM frame - if
        // the send path ever splits a large body, this still reads the stream rather than the
        // first frame of it, and a split that lost or reordered a range fails the comparison.
        var reassembled = new List<byte>();
        var fin = false;
        foreach (var frame in harness.Peer.ReceivedStreamFrames)
        {
            Assert.Equal(FirstRequestStreamId, frame.StreamId);
            Assert.Equal((ulong)reassembled.Count, frame.Offset);
            reassembled.AddRange(frame.Data.ToArray());
            fin |= frame.Fin;
        }

        Assert.True(fin);

        // AND IT TOOK MORE THAN ONE FRAME, which is the RFC 9000 s14.2 ceiling showing through.
        // Before it, this body was one STREAM frame in one 16473-byte datagram; the assertion
        // above passed either way, so without this line the split could silently revert.
        Assert.True(
            harness.Peer.ReceivedStreamFrames.Count > 1,
            $"expected the body to be split across datagrams, got "
            + $"{harness.Peer.ReceivedStreamFrames.Count} frame(s)");

        var frames = ReadHttp3Frames(reassembled.ToArray());
        Assert.Equal(
            [(ulong)TlsQuicHttp3FrameType.Headers, (ulong)TlsQuicHttp3FrameType.Data],
            frames.ConvertAll(frame => frame.Type).ToArray());
        Assert.Equal(body, frames[1].Payload);
    }

    // s4.1's item 3 on the wire, AFTER the content. s4.1 fixes the order in as many words - "a
    // HEADERS or DATA frame after the trailing HEADERS frame[] is considered invalid" - so a
    // trailer that arrived before the DATA would be a connection error of type
    // H3_FRAME_UNEXPECTED at the peer rather than a cosmetic reordering.
    [Fact]
    public async Task ATrailerSectionReachesTheWireAfterTheContent()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        Assert.NotNull(
            harness.Http3.TryOpenRequest(
                Request(
                    method: "POST",
                    field: ("content-length", "3"),
                    body: [9, 8, 7],
                    trailer: ("x-checksum", "18")),
                out var refusal,
                out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);

        await harness.FlushAsync(cancellation.Token);

        var sent = Assert.Single(harness.Peer.ReceivedStreamFrames);
        Assert.True(sent.Fin);

        var frames = ReadHttp3Frames(sent.Data);
        Assert.Equal(
            [
                (ulong)TlsQuicHttp3FrameType.Headers,
                (ulong)TlsQuicHttp3FrameType.Data,
                (ulong)TlsQuicHttp3FrameType.Headers,
            ],
            frames.ConvertAll(frame => frame.Type).ToArray());
        Assert.Equal(new byte[] { 9, 8, 7 }, frames[1].Payload);
    }

    // s4.2.2's SHOULD NOT reaches the TRAILER section too. s4.2.2 bounds "the message header
    // ... on an individual HTTP message" and s4.2 has QPACK compressing "header and trailer
    // sections" alike, so both are field sections the peer's advertised limit governs. The
    // header section here is a few dozen bytes and passes on its own, so an implementation that
    // stopped at the first HEADERS frame sends this - which is exactly what FitsPeerFieldSection
    // Limit did before it stopped returning on the first match.
    [Fact]
    public async Task ATrailerSectionPastThePeersFieldSectionLimitIsRefused()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);
        await harness.PeerSendsAsync(
            cancellation.Token,
            PeerControl(
                new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 4096)));

        // The same request WITHOUT the trailer is accepted, so the refusal below can only be
        // the trailer section's - which is the half that separates this from a header-section
        // test wearing a trailer.
        Assert.NotNull(
            harness.Http3.TryOpenRequest(
                Request(method: "POST", body: [1]), out var withoutTrailer, out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, withoutTrailer);

        Assert.Null(
            harness.Http3.TryOpenRequest(
                Request(
                    method: "POST",
                    body: [1],
                    trailer: ("x-checksum", new string('a', 5000))),
                out var refusal,
                out _));
        Assert.Equal(TlsQuicHttp3RequestRefusal.FieldSectionTooLargeForPeer, refusal);
    }

    // s4.1.2's rule, refused at the connection rather than only at the encoder - the caller of
    // TryOpenRequest sees a named malformed reason and no stream, and no ordinal is spent.
    [Fact]
    public async Task AContentLengthThatDisagreesWithTheBodyIsRefusedWithoutOpeningAStream()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        Assert.Null(
            harness.Http3.TryOpenRequest(
                Request(method: "POST", field: ("content-length", "99"), body: [1, 2, 3]),
                out var refusal,
                out var malformed));
        Assert.Equal(TlsQuicHttp3RequestRefusal.Malformed, refusal);
        Assert.Equal(TlsQuicHttp3RequestError.ContentLengthDisagreesWithBody, malformed);
        Assert.Empty(harness.Http3.RequestStreamIds);
        await harness.FlushAsync(cancellation.Token, expectPacket: false);
        Assert.Empty(harness.Peer.ReceivedStreamFrames);
    }

    // Every s7.1 frame in a request stream's bytes, through the reader rather than through a
    // second parser written for the assertion.
    // ------------------------------------------------------------------------
    // RFC 9221 s3 and RFC 9297 s2.1: what arrives on the datagram invitation.
    // ------------------------------------------------------------------------
    //
    // THE INVITATION IS REAL, WHICH IS WHY THESE ARE NOT HYPOTHETICAL.
    // TlsQuicTransportParameterSpec's Brave 151 preset sends max_datagram_frame_size = 65536
    // and TlsQuicHttp3Spec.CaptureSettings sends SETTINGS_H3_DATAGRAM = 1, because the client
    // being impersonated does. A server is entitled to take both at their word.
    //
    // THE FRAMES ARE HAND-ENCODED against RFC 9221 s4's two fields - Type 0x30 or 0x31, then
    // an optional Length, then Datagram Data - because TlsQuicFrames.WriteFrame throws on a
    // DATAGRAM frame and must keep throwing. 0x31 is the LEN-present form.

    [Fact]
    public async Task ADatagramFrameWithoutTheTransportParameterClosesTheConnection()
    {
        // RFC 9221 s3: "An endpoint that receives a DATAGRAM frame when it has not indicated
        // support via the transport parameter MUST terminate the connection with an error of
        // type PROTOCOL_VIOLATION."
        //
        // THE HARDEST VERSION OF THE CASE, DELIBERATELY. SETTINGS_H3_DATAGRAM = 1 still goes
        // out, so the server has seen this client claim at the HTTP/3 layer that it will
        // receive datagrams; only the QUIC transport parameter is missing. s3 does not care -
        // it names the transport parameter and nothing else - and the connection closes anyway.
        //
        // AllowDatagramSettingWithoutTransportParameter IS WHAT LETS THAT PAIR BE BUILT.
        // TlsQuicHttp3Connection normally refuses the inconsistent spec in its constructor, so
        // without this knob the test would die before reaching the rule it is about.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token,
            spec: new TlsQuicHttp3Spec { AllowDatagramSettingWithoutTransportParameter = true },
            maxDatagramFrameSize: null);

        await harness.Peer.SendOneRttRawFrameAsync(
            [0x31, 0x03, 0xaa, 0xbb, 0xcc], cancellation.Token);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await harness.Connection.PumpOnceAsync(cancellation.Token));
        Assert.Contains("max_datagram_frame_size", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADatagramFrameLargerThanWeAdvertisedClosesTheConnection()
    {
        // RFC 9221 s3: "an endpoint that receives a DATAGRAM frame that is larger than the
        // value it sent in its max_datagram_frame_size transport parameter MUST terminate the
        // connection with an error of type PROTOCOL_VIOLATION."
        //
        // THE FRAME IS FIVE BYTES AND THE LIMIT IS FOUR, AND THE PAYLOAD IS THREE. s3 measures
        // "including the frame type, length, and payload", so a check written against the
        // payload alone would see 3 against 4 and accept this. That is the whole point of the
        // row: 0x31 0x03 aa bb cc is five bytes on the wire.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token, maxDatagramFrameSize: 4);

        await harness.Peer.SendOneRttRawFrameAsync(
            [0x31, 0x03, 0xaa, 0xbb, 0xcc], cancellation.Token);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await harness.Connection.PumpOnceAsync(cancellation.Token));
        Assert.Contains("5 byte(s) against", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADatagramTooShortForAQuarterStreamIdIsH3DatagramError()
    {
        // RFC 9297 s2.1: "Receipt of a QUIC DATAGRAM frame whose payload is too short to allow
        // parsing the Quarter Stream ID field MUST be treated as an HTTP/3 connection error of
        // type H3_DATAGRAM_ERROR (0x33)."
        //
        // AND RFC 9221 s4 CALLS THE SAME FRAME LEGAL: "Note that empty (i.e., zero-length)
        // datagrams are allowed." So the transport accepts it and HTTP/3 refuses it, which is
        // why the QUIC pump below does NOT throw and TryProcess does fail. A test that only
        // pumped would see nothing wrong.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        await harness.Peer.SendOneRttRawFrameAsync([0x31, 0x00], cancellation.Token);
        await harness.Connection.PumpOnceAsync(cancellation.Token);

        Assert.False(harness.Http3.TryProcess(out var errorCode));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3DatagramError, errorCode);
        Assert.Equal(0x33UL, errorCode);
    }

    [Fact]
    public async Task ADatagramWithAQuarterStreamIdAbove2Pow60MinusOneIsH3DatagramError()
    {
        // RFC 9297 s2.1: "The largest legal QUIC stream ID value is 2^62-1, so the largest
        // legal value of the Quarter Stream ID field is 2^60-1.  Receipt of an HTTP/3 Datagram
        // that includes a larger value MUST be treated as an HTTP/3 connection error of type
        // H3_DATAGRAM_ERROR (0x33)."
        //
        // 0xd0 0x00 ... 0x00 IS THE EIGHT-BYTE VARINT FOR EXACTLY 2^60: the 0b11 prefix marks the RFC 9000 s16 gives the
        // eight-byte form and the remaining 62 bits carry 0x1000000000000000. RFC 9000 s16 gives
        // that field 62 bits, so 2^60 is encodable and is the first value this rule refuses -
        // exactly one above 2^60-1, which is what separates a > from a >= here.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        await harness.Peer.SendOneRttRawFrameAsync(
            [0x31, 0x08, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], cancellation.Token);
        await harness.Connection.PumpOnceAsync(cancellation.Token);

        Assert.False(harness.Http3.TryProcess(out var errorCode));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3DatagramError, errorCode);
    }

    [Fact]
    public async Task ADatagramWithALegalQuarterStreamIdIsAcceptedAndDropped()
    {
        // THE NEGATIVE CONTROL, without which the two rules above would pass against an
        // implementation that refused every datagram. Quarter Stream ID 0 names client stream
        // 0, s2.1's division by four run backwards, and the payload after it is free-form.
        //
        // ACCEPTED IS NOT DELIVERED. s2.1: "If a datagram is received after the corresponding
        // stream's receive side is closed, the received datagrams MUST be silently dropped" -
        // and with no extension in this tree consuming HTTP datagrams, every one is dropped
        // after validating. There is deliberately nothing to assert about the bytes.
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        await harness.Peer.SendOneRttRawFrameAsync(
            [0x31, 0x03, 0x00, 0xaa, 0xbb], cancellation.Token);
        await harness.Connection.PumpOnceAsync(cancellation.Token);

        Assert.True(harness.Http3.TryProcess(out var errorCode));
        Assert.Equal(0UL, errorCode);
    }

    private static List<(ulong Type, byte[] Payload)> ReadHttp3Frames(ReadOnlyMemory<byte> bytes)
    {
        var frames = new List<(ulong, byte[])>();
        var span = bytes.Span;
        var offset = 0;

        while (offset < span.Length)
        {
            Assert.Equal(
                TlsQuicHttp3FrameReadStatus.Complete,
                TlsQuicHttp3Frames.TryRead(
                    span, ref offset, out var type, out var payload, out _));
            frames.Add((type, payload.ToArray()));
        }

        return frames;
    }

    private sealed class Harness : IDisposable
    {
        private readonly TestPki _pki;
        private readonly TlsServerCertificate _credential;
        private readonly CustomTlsQuicServer _server;

        private Harness(
            TestPki pki,
            TlsServerCertificate credential,
            CustomTlsQuicServer server,
            TlsQuicConnection connection,
            InMemoryDatagramTransport clientTransport,
            LoopbackQuicPeer peer,
            TlsQuicHttp3Connection http3)
        {
            _pki = pki;
            _credential = credential;
            _server = server;
            Connection = connection;
            ClientTransport = clientTransport;
            Peer = peer;
            Http3 = http3;

            // THE HANDSHAKE AND THE s6.2.1 OPENING FLIGHT ARE ALREADY PUMPED BY THE TIME THIS
            // RUNS, so the peer's inbox is empty here and this is the zero from which
            // DrainToPeerAsync counts what it still owes.
            _peerConsumed = clientTransport.Sent.Count;
        }

        // How many of the client's datagrams the peer has opened. Peer.PumpOnceAsync BLOCKS on
        // an empty inbox, so a loop that pumped hopefully would hang until the test deadline;
        // this is what lets DrainToPeerAsync pump exactly the backlog and no more.
        private int _peerConsumed;

        internal TlsQuicConnection Connection { get; }

        /// <summary>The client half of the transport pair, for the datagram COUNT.</summary>
        /// <remarks>Exposed so that <see cref="PumpPeerUntilConnectionCloseAsync"/> can prove a
        /// close datagram exists before it waits for one. LoopbackQuicPeer.PumpOnceAsync blocks
        /// on an empty inbox, so a loop that pumps hopefully would hang until the test's own
        /// deadline rather than fail an assertion.</remarks>
        internal InMemoryDatagramTransport ClientTransport { get; }

        internal LoopbackQuicPeer Peer { get; }

        internal TlsQuicHttp3Connection Http3 { get; }

        internal static async ValueTask<Harness> CreateAsync(
            CancellationToken cancellationToken,
            TlsQuicHttp3Spec? spec = null,
            IReadOnlyList<TlsQuicTransportParameter>? flowControl = null,
            bool openLocalStreams = true,
            ulong? maxDatagramFrameSize = 65536)
        {
            var pki = TestPki.Create();
            var credential = Credential(pki);
            var (clientTransport, serverTransport) = InMemoryDatagramTransport.CreatePair();
            // 65536 IS THE CAPTURE'S NUMBER - TlsQuicTransportParameterSpec.Brave151Parameters
            // row 3, "32 max_datagram_frame_size = 65536" - and it is here because this harness
            // sends TlsQuicHttp3Spec.CaptureSettings, whose 51:1 is the HTTP/3 half of the same
            // claim. Advertising only one half is what TlsQuicHttp3Connection's constructor now
            // refuses, so this line is the harness saying what it means rather than the harness
            // opting out of the check.
            var connection = Connection(
                clientTransport, serverTransport, pki,
                maxDatagramFrameSize: maxDatagramFrameSize);
            var server = Server(
                credential, connection.OriginalDestinationConnectionId, flowControl: flowControl);
            var peer = LoopbackQuicPeer.ForServer(
                serverTransport, clientTransport.LocalEndPoint, server, Spec());
            await ConfirmedHandshake(connection, peer, cancellationToken);

            var http3 = new TlsQuicHttp3Connection(connection, spec ?? new TlsQuicHttp3Spec());
            if (openLocalStreams)
            {
                http3.OpenLocalStreams();

                // EVERY DATAGRAM THIS SEND PRODUCED, not one. The Harness constructor then sets
                // _peerConsumed to the sent count, so anything left unread here would be
                // recorded as consumed and never pumped again - and the next FlushAsync would
                // open THAT stale datagram instead of the one the test had just sent.
                //
                // It became two once RFC 9000 s14.3's path MTU search was on by default: opening
                // the control streams is application data, which is what RFC 8899 s5.1.1 makes
                // a probe wait for, so the probe follows in the same pass.
                var before = clientTransport.Sent.Count;
                Assert.True(await connection.SendPendingAsync(cancellationToken));
                for (var datagram = before; datagram < clientTransport.Sent.Count; datagram++)
                {
                    Assert.False(await peer.PumpOnceAsync(SentAt, cancellationToken));
                }

                peer.ReceivedStreamFrames.Clear();
            }

            return new Harness(
                pki, credential, server, connection, clientTransport, peer, http3);
        }

        /// <summary>Closes the HTTP/3 layer and hands the peer the datagram that carries the
        /// close, returning RFC 9000 s19.19's four recorded fields.</summary>
        /// <remarks>
        /// <para>THE CLOSE IS NOT QUEUED. TlsQuicConnection.CloseCoreAsync sends straight down
        /// the transport rather than through SendPendingAsync, so the datagram exists the moment
        /// the call returns - which the Sent count below asserts BEFORE any pump, so the loop
        /// that follows cannot be waiting for something that was never written.</para>
        /// <para>AND IT IS PUMPED FOR RATHER THAN PUMPED ONCE. Connection.PumpOnceAsync answers
        /// what it receives, so a test that had the peer send anything is holding an ACK
        /// datagram the peer has not opened yet; one pump would read that and the close
        /// assertions would then read a stale null. The close is the LAST datagram queued, so
        /// stopping at the first CONNECTION_CLOSE consumes exactly the backlog and no more, and
        /// the loop can never outrun the inbox.</para>
        /// </remarks>
        internal async ValueTask<(ulong RawType, ulong ErrorCode, byte[] ReasonPhrase,
            TlsQuicEncryptionLevel Level)> CloseAndReadTheDatagramAsync(
            CancellationToken cancellationToken)
        {
            Assert.Null(Peer.LastConnectionClose);
            var sentBefore = ClientTransport.Sent.Count;
            await Http3.CloseWithCurrentErrorAsync(cancellationToken);
            Assert.Equal(sentBefore + 1, ClientTransport.Sent.Count);

            for (var pump = 0; pump < 16 && Peer.LastConnectionClose is null; pump++)
            {
                await Peer.PumpOnceAsync(SentAt, cancellationToken);
            }

            return Assert.NotNull(Peer.LastConnectionClose);
        }

        /// <summary>Sends whatever is queued and lets the peer take it.</summary>
        internal async ValueTask FlushAsync(
            CancellationToken cancellationToken, bool expectPacket = true)
        {
            Assert.Equal(expectPacket, await Connection.SendPendingAsync(cancellationToken));

            // EVERY UNCONSUMED DATAGRAM, NOT ONE. This pumped exactly once per send, which held
            // while one SendPendingAsync produced at most one datagram. RFC 9000 s14.3's path
            // MTU search broke that: a pass may now send its answer AND a PMTU probe, and a peer
            // pumped once would read the answer and leave the probe in the inbox - so the NEXT
            // flush's single pump would open that stale probe instead of the datagram the test
            // had just sent. The symptom was a request stream that never reached the peer at
            // all, which the HTTP/3 readout reported as an absent pseudo-header order.
            //
            // DrainToPeerAsync below has always done it this way and says why. This is the same
            // loop, and the counter it advances is the same one.
            while (_peerConsumed < ClientTransport.Sent.Count)
            {
                Assert.False(await Peer.PumpOnceAsync(SentAt, cancellationToken));
                _peerConsumed++;
            }
        }

        /// <summary>Sends whatever is pending, however many datagrams that takes, and stops when
        /// nothing is.</summary>
        /// <remarks>NOT <see cref="FlushAsync"/>, which asserts that a packet WAS built. After a
        /// grant the caller cannot know: <see cref="TlsQuicConnection.PumpOnceAsync"/> answers
        /// the datagram it just read, and the bytes the grant unblocked may already have left
        /// with that answer. Asserting a packet there was asserting a scheduling detail. Bounded
        /// so that a send path which never runs dry fails rather than spins.</remarks>
        internal async ValueTask DrainToPeerAsync(CancellationToken cancellationToken)
        {
            // PASSES, NOT DATAGRAMS, SINCE THE s14.2 CEILING LANDED. A pass that the pacer
            // defers builds nothing, so a bound counting datagrams would be spent by waiting
            // rather than by sending. 512 passes is far more than the fifteen datagrams a
            // 16 KiB body takes and still fails a send path that never runs dry.
            for (var pass = 0; pass < 512; pass++)
            {
                var built = await Connection.SendPendingAsync(cancellationToken);

                // EVERY UNOPENED DATAGRAM, NOT JUST THE ONE JUST BUILT. PumpOnceAsync answers
                // the datagram it read, so the client may already have written the grant's
                // bytes while this test was still inside GrantStreamCreditAsync; a drain that
                // pumped only after a SendPendingAsync of its own would leave those in the
                // peer's inbox and the reassembly below would read a short stream.
                while (_peerConsumed < ClientTransport.Sent.Count)
                {
                    Assert.False(await Peer.PumpOnceAsync(SentAt, cancellationToken));
                    _peerConsumed++;

                }

                if (built)
                {
                    continue;
                }

                // NOTHING WAS BUILT, WHICH IS NOT THE SAME AS NOTHING BEING LEFT. Since the
                // RFC 9000 s14.2 datagram ceiling landed, a body larger than the initial
                // congestion window goes out as many datagrams rather than one oversized one -
                // 16 KiB is about fifteen - and RFC 9002 s7's "MUST NOT send ... in excess of
                // the congestion window" then refuses the rest until something is acknowledged.
                // Before the ceiling this could not arise: one datagram passed the gate while
                // bytes_in_flight was zero and carried the whole body past the window.
                //
                // So the peer acknowledges and the client reads it, which is the round trip a
                // real connection would make anyway. Only when a pass builds nothing AND the
                // stream set has nothing queued is the drain actually finished.
                if (!Connection.Streams.HasPendingFrames)
                {
                    return;
                }

                // BOTH GATES BIND, IN SEQUENCE, AND EACH NEEDS A DIFFERENT THING. Measured at
                // 16 KiB rather than assumed: waiting alone left refusedByWindow=501, and
                // acknowledging alone left deferredByPacer=238. RFC 9002 s7.7's pacer opens on
                // the CLOCK, which no amount of pumping moves; s7's congestion window opens on
                // an ACKNOWLEDGMENT, which no amount of waiting produces.
                //
                // THE ACK MUST BE CUMULATIVE. SendAckAsync acknowledges one packet, which told
                // the client the other twelve were lost: s13.3's repairs re-sent ranges the
                // peer already had and the reassembly below read offset 5670 where it had
                // reached 10206. SendCumulativeAckAsync acknowledges everything, which is the
                // truth on a lossless in-memory transport.
                await Peer.SendCumulativeAckAsync(cancellationToken);
                await Connection.PumpOnceAsync(cancellationToken);
                await Task.Delay(TimeSpan.FromMilliseconds(1), cancellationToken);
            }

            Assert.Fail(
                "the connection still had frames to send after 512 passes. "
                + $"sent={ClientTransport.Sent.Count} "
                + $"refusedByWindow={Connection.SendsRefusedByCongestionWindow} "
                + $"deferredByPacer={Connection.SendsDeferredByPacer} "
                + $"pending={Connection.Streams.HasPendingFrames}");
        }

        /// <summary>Has the peer send one RFC 9000 s19.10 MAX_STREAM_DATA raising
        /// <paramref name="stream"/>'s send limit to <paramref name="maximumStreamData"/>, and
        /// pumps until the client has actually applied it.</summary>
        /// <remarks>NOT <see cref="PeerSendsAsync"/>, and the reason is its Delivered() helper:
        /// that counts bytes RECEIVED on a stream, and a MAX_STREAM_DATA carries none, so it
        /// would report the frame delivered before the datagram had been opened and pump zero
        /// times. The condition here is the one that actually matters - the budget moved.
        /// Bounded, so a dispatch that stopped applying grants fails rather than hangs.</remarks>
        internal async ValueTask<bool> GrantStreamCreditAsync(
            CancellationToken cancellationToken, TlsQuicStream stream, ulong maximumStreamData)
        {
            await Peer.SendStreamFramesAsync(
                [
                    new TlsQuicFrame
                    {
                        RawType = (ulong)TlsQuicFrameType.MaxStreamData,
                        StreamId = stream.Id,
                        MaximumStreamData = maximumStreamData,
                    },
                ],
                cancellationToken);

            for (var pump = 0; pump < 16 && stream.Budget?.Limit != maximumStreamData; pump++)
            {
                await Connection.PumpOnceAsync(cancellationToken);
            }

            return stream.Budget?.Limit == maximumStreamData;
        }

        /// <summary>The s19.9 twin of <see cref="GrantStreamCreditAsync"/>: one MAX_DATA raising
        /// the shared connection pool, pumped until <c>ConnectionLimit</c> reports it.</summary>
        internal async ValueTask<bool> GrantConnectionCreditAsync(
            CancellationToken cancellationToken, ulong maximumData)
        {
            await Peer.SendStreamFramesAsync(
                [
                    new TlsQuicFrame
                    {
                        RawType = (ulong)TlsQuicFrameType.MaxData,
                        MaximumData = maximumData,
                    },
                ],
                cancellationToken);

            for (var pump = 0;
                pump < 16 && Connection.PeerFlowControl.ConnectionLimit != maximumData;
                pump++)
            {
                await Connection.PumpOnceAsync(cancellationToken);
            }

            return Connection.PeerFlowControl.ConnectionLimit == maximumData;
        }

        /// <summary>Puts the peer's frames in one datagram, takes it, and runs the HTTP/3
        /// layer over what arrived.</summary>
        /// <remarks>ONE DATAGRAM PER CALL so that a test choosing to split a response across
        /// several calls is choosing something the transport can actually do.
        /// <paramref name="expectAccepted"/> is what TryProcess should answer, asserted here so
        /// that a test about a LATER assertion cannot pass because an earlier pump quietly
        /// failed.</remarks>
        internal async ValueTask PeerSendsAsync(
            CancellationToken cancellationToken,
            bool expectAccepted,
            params TlsQuicFrame[] frames)
        {
            await Peer.SendStreamFramesAsync(frames, cancellationToken);

            // PUMPED UNTIL THESE FRAMES' BYTES ARE ACTUALLY DELIVERED, NOT EXACTLY ONCE, AND
            // THAT IS A MEASURED FIX RATHER THAN CAUTION. TlsQuicConnection.PumpOnceAsync takes
            // ONE datagram; the connection's receive queue can already hold another, so a single
            // pump may consume a datagram these frames did not ride in. The assertion that
            // follows then reads state that has not arrived. It made the four GOAWAY tests
            // intermittent - one gate run in three failed AGoawayForbidsANewRequest with
            // "Assert.Null() Failure: Value is not null", because the GOAWAY had not landed and
            // s5.2's refusal therefore had nothing to refuse on.
            //
            // BOUNDED, so a bug that stops delivery fails the test rather than hanging.
            for (var pump = 0; pump < 16 && !Delivered(frames); pump++)
            {
                await Connection.PumpOnceAsync(cancellationToken);
            }

            Assert.Equal(expectAccepted, Http3.TryProcess(out _));
        }

        // Whether every frame's bytes - and its FIN, when it carries one - have reached the
        // stream set. s19.8's final size is offset plus length, and TlsQuicStream.Received
        // counts IN-ORDER delivered bytes, so this is the same arithmetic from the other side.
        // The FIN is checked separately because a bare-FIN frame carries no bytes at all and
        // would otherwise look delivered before it arrived.
        private bool Delivered(TlsQuicFrame[] frames)
        {
            foreach (var frame in frames)
            {
                var stream = Connection.Streams.Find(frame.StreamId);
                if (stream is null
                    || (ulong)stream.Received.Count < frame.Offset + (ulong)frame.Data.Length)
                {
                    return false;
                }

                if ((frame.RawType & TlsQuicStreamFrames.FinBit) != 0 && !stream.FinReceived)
                {
                    return false;
                }
            }

            return true;
        }

        internal ValueTask PeerSendsAsync(
            CancellationToken cancellationToken, params TlsQuicFrame[] frames) =>
            PeerSendsAsync(cancellationToken, expectAccepted: true, frames);

        public void Dispose()
        {
            Peer.DisposeAsync().AsTask().GetAwaiter().GetResult();
            Connection.DisposeAsync().AsTask().GetAwaiter().GetResult();
            _server.DisposeAsync().AsTask().GetAwaiter().GetResult();
            _credential.Dispose();
            _pki.Dispose();
        }
    }

    private static TlsQuicHttp3Request Request(
        string path = "/api/http3",
        (string Name, string Value)? field = null,
        string method = "GET",
        byte[]? body = null,
        (string Name, string Value)? trailer = null) => new()
    {
        Method = method,
        Scheme = "https",
        Authority = "loopback.example",
        Path = path,
        Fields = field is { } one ? [new TlsQuicHttp3Field(one.Name, one.Value)] : [],
        Body = body is null ? [] : [.. body],
        Trailers = trailer is { } tail
            ? [new TlsQuicHttp3Field(tail.Name, tail.Value)]
            : [],
    };

    // A body whose bytes are POSITION-DEPENDENT, so a send path that truncated it, padded it,
    // repeated a chunk or reordered two would be caught by the comparison rather than by the
    // length alone. 31 is coprime with 256, so the pattern does not repeat inside a page.
    private static byte[] PatternedBody(int length)
    {
        var body = new byte[length];
        for (var i = 0; i < length; i++)
        {
            body[i] = (byte)((i * 31) + (i >> 8));
        }

        return body;
    }

    // The peer's s6.2.1 opening flight: the stream-type varint and a SETTINGS frame, as one
    // STREAM frame at offset 0 with no FIN.
    private static TlsQuicFrame PeerControl(params TlsQuicHttp3Setting[] settings)
    {
        var bytes = new List<byte> { (byte)TlsQuicHttp3StreamType.Control };
        var payload = new List<byte>();
        TlsQuicHttp3Settings.EncodePayload(payload, settings);
        TlsQuicHttp3Frames.Write(
            bytes, (ulong)TlsQuicHttp3FrameType.Settings, payload.ToArray());
        return Stream(PeerControlStreamId, 0, bytes.ToArray());
    }

    private static TlsQuicFrame PeerControlWithGoaway(ulong identifier)
    {
        var control = PeerControl();
        var bytes = new List<byte>(control.Data.ToArray());
        bytes.AddRange(GoawayFrame(identifier));
        return Stream(PeerControlStreamId, 0, bytes.ToArray());
    }

    private static byte[] GoawayFrame(ulong identifier)
    {
        var payload = new List<byte>();
        QuicVariableLengthInteger.Write(payload, identifier);
        var frame = new List<byte>();
        TlsQuicHttp3Frames.Write(
            frame, (ulong)TlsQuicHttp3FrameType.Goaway, payload.ToArray());
        return frame.ToArray();
    }

    // A response as bytes: one HEADERS frame then, when there is content, one DATA frame.
    //
    // BUILT WITH OUR OWN QPACK ENCODER, which means a defect symmetric across
    // TlsQuicQpackEncoder and TlsQuicQpackDecoder would cancel here exactly as task 7's
    // inverted nonce cancelled in the loopback packet tests. That is measured rather than
    // ignored: RFC 9204 Appendix B's published byte vectors are decoded in
    // TlsQuicQpackDecoderTests and encoded in TlsQuicQpackEncoderTests against bytes neither
    // side produced, so the field-line layout has evidence outside this file. What these tests
    // add is the SEQUENCE - that a field section reaches a reader through a QUIC stream, a
    // frame layer and a response state machine, in that order.
    private static byte[] ResponseBytes(
        int status, (string Name, string Value)[] fields, byte[] body)
    {
        var section = new byte[4096];
        var span = section.AsSpan();
        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(span, out var written));
        written += EncodeLine(span[written..], ":status", status.ToString());
        foreach (var (name, value) in fields)
        {
            while (true)
            {
                if (written + 16 < section.Length
                    && TlsQuicQpackEncoder.TryEncodeFieldLine(
                        Encoding.ASCII.GetBytes(name),
                        Encoding.ASCII.GetBytes(value),
                        huffman: true,
                        preferNameReference: true,
                        span[written..],
                        out var count))
                {
                    written += count;
                    break;
                }

                var grown = new byte[section.Length * 2];
                section.AsSpan(0, written).CopyTo(grown);
                section = grown;
                span = section.AsSpan();
            }
        }

        var bytes = new List<byte>();
        TlsQuicHttp3Frames.Write(
            bytes, (ulong)TlsQuicHttp3FrameType.Headers, section.AsSpan(0, written));
        if (body.Length > 0)
        {
            TlsQuicHttp3Frames.Write(bytes, (ulong)TlsQuicHttp3FrameType.Data, body);
        }
        return bytes.ToArray();
    }

    private static int EncodeLine(Span<byte> destination, string name, string value)
    {
        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldLine(
            Encoding.ASCII.GetBytes(name),
            Encoding.ASCII.GetBytes(value),
            huffman: true,
            preferNameReference: true,
            destination,
            out var written));
        return written;
    }

    private static string? FieldValue(TlsQuicHttp3Response response, string name)
    {
        foreach (var field in response.HeaderFields)
        {
            if (string.Equals(field.Name, name, StringComparison.Ordinal))
            {
                return field.Value;
            }
        }
        return null;
    }

    // ========================================================================
    // C16 - a field section that arrives before the encoder instructions it needs
    // ========================================================================
    //
    // RFC 9204 s2.1.2 names the hazard exactly: "Because QUIC does not guarantee order between
    // data on different streams, a decoder might encounter a representation that references a
    // dynamic table entry that it has not yet received." These run on the SHIPPED spec - no
    // narrowed SETTINGS anywhere below - so what they exercise is the configuration this stack
    // actually advertises.

    // BOTH ORDERS, AND THE REVERSED ONE IS THE ONLY THING THAT CATCHES "parks but never
    // re-presents". A decoder that parked a section and waited for more bytes on the RESPONSE
    // stream would pass the in-order row and hang forever on the reordered one, because what
    // unblocks it arrives on a different stream and that stream is then silent.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AFieldSectionDecodesWhicheverOrderItAndItsEncoderInstructionsArriveIn(
        bool encoderStreamFirst)
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        var stream = harness.Http3.TryOpenRequest(Request(), out _, out _);
        Assert.NotNull(stream);
        await harness.FlushAsync(cancellation.Token);

        var encoder = PeerEncoderStream(("x-dynamic", "from-the-table"));
        var response = Stream(
            FirstRequestStreamId, 0, DynamicResponseBytes(requiredInsertCount: 1), fin: true);

        await harness.PeerSendsAsync(cancellation.Token, PeerControl());

        var reader = harness.Http3.ResponseFor(FirstRequestStreamId);
        Assert.NotNull(reader);

        if (encoderStreamFirst)
        {
            await harness.PeerSendsAsync(cancellation.Token, encoder);
            Assert.False(reader.IsBlocked);

            // s2.2.1: "the field section can be processed immediately" - one pump, no block.
            await harness.PeerSendsAsync(cancellation.Token, response);
            Assert.False(reader.IsBlocked);
        }
        else
        {
            await harness.PeerSendsAsync(cancellation.Token, response);

            // BLOCKED, WITH NO ERROR AND NO FIELDS. The FIN rode in with it and did not turn
            // the leftover frame into s7.1's H3_FRAME_ERROR either.
            Assert.True(reader.IsBlocked);
            Assert.Equal(1ul, reader.BlockedRequiredInsertCount);
            Assert.Equal(0ul, harness.Http3.ConnectionErrorCode);
            Assert.Empty(reader.HeaderFields);
            Assert.False(reader.IsComplete);

            // THE RESPONSE STREAM IS SILENT FROM HERE. This delivery carries bytes on the
            // ENCODER stream only, so the exchange loop sees fresh == 0 with no new FIN - the
            // shape TryProcess's `continue` skips, and the shape `&& !IsBlocked` exists for.
            await harness.PeerSendsAsync(cancellation.Token, encoder);
            Assert.False(reader.IsBlocked);
        }

        Assert.Equal(200, reader.Status);
        Assert.Equal("from-the-table", FieldValue(reader, "x-dynamic"));
        Assert.True(reader.IsComplete);
        Assert.Equal(0ul, harness.Http3.ConnectionErrorCode);
    }

    // THE fresh == 0 TRAP, AND IT NEEDS A RESPONSE STREAM WITH NO FIN. The theory above sends
    // its response with fin: true, which makes endOfStream true forever after - so TryProcess's
    // `fresh == 0 && !endOfStream` guard never fires and the parked section is re-presented
    // whether or not `&& !IsBlocked` is there. THE SWEEP PROVED THAT: dropping `!IsBlocked`
    // survived the whole gate until this test existed, which is exactly the "parks but never
    // re-presents" failure the plan warned only one shape could catch.
    //
    // WITHOUT A FIN the response stream is genuinely silent while it waits, because what
    // unblocks it is on the peer's ENCODER stream - s2.1.2: "QUIC does not guarantee order
    // between data on different streams". fresh is 0, endOfStream is false, and only IsBlocked
    // distinguishes a stream worth re-reading from one with nothing to say.
    [Fact]
    public async Task AParkedSectionIsRePresentedEvenWhileItsOwnStreamIsSilentAndUnfinished()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        Assert.NotNull(harness.Http3.TryOpenRequest(Request(), out _, out _));
        await harness.FlushAsync(cancellation.Token);
        await harness.PeerSendsAsync(cancellation.Token, PeerControl());

        // NO FIN. The response is complete as bytes and unfinished as a stream.
        await harness.PeerSendsAsync(
            cancellation.Token,
            Stream(FirstRequestStreamId, 0, DynamicResponseBytes(requiredInsertCount: 1)));

        var reader = harness.Http3.ResponseFor(FirstRequestStreamId);
        Assert.NotNull(reader);
        Assert.True(reader.IsBlocked);
        Assert.False(harness.Connection.Streams.Find(FirstRequestStreamId)!.ReceiveComplete);

        // Bytes on the ENCODER stream only. Stream 0 delivers nothing at all this pump.
        await harness.PeerSendsAsync(
            cancellation.Token, PeerEncoderStream(("x-dynamic", "from-the-table")));

        Assert.False(reader.IsBlocked);
        Assert.Equal(200, reader.Status);
        Assert.Equal("from-the-table", FieldValue(reader, "x-dynamic"));
        Assert.Equal(0ul, harness.Http3.ConnectionErrorCode);
    }

    // s2.2.1's unblock GIVES THE SLOT BACK, which is what makes an advertised bound of 1 mean
    // "one at a time" rather than "one, ever". Without the release, a connection that promised
    // SETTINGS_QPACK_BLOCKED_STREAMS = 1 would close itself on the second request that ever
    // blocked, however long after the first one finished - and the sweep found that deleting
    // the release survived every other test here.
    [Fact]
    public async Task AnUnblockedStreamGivesItsSlotBackSoTheNextOneMayBlock()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token,
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 65536),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 1),
                ],
            });

        Assert.NotNull(harness.Http3.TryOpenRequest(Request(path: "/one"), out _, out _));
        Assert.NotNull(harness.Http3.TryOpenRequest(Request(path: "/two"), out _, out _));
        await harness.FlushAsync(cancellation.Token);
        await harness.PeerSendsAsync(cancellation.Token, PeerControl());

        // The first blocks, taking the only promised slot.
        await harness.PeerSendsAsync(
            cancellation.Token,
            Stream(FirstRequestStreamId, 0, DynamicResponseBytes(1), fin: true));
        Assert.True(harness.Http3.ResponseFor(FirstRequestStreamId)!.IsBlocked);
        Assert.Equal(1, harness.Http3.Streams.BlockedStreams.Count);

        // The first insertion unblocks it and the slot comes back.
        await harness.PeerSendsAsync(
            cancellation.Token, PeerEncoderStream(("x-dynamic", "first")));
        Assert.False(harness.Http3.ResponseFor(FirstRequestStreamId)!.IsBlocked);
        Assert.Equal(0, harness.Http3.Streams.BlockedStreams.Count);

        // So the second stream may now block on a count the table has not reached - a Required
        // Insert Count of 2 against an Insert Count of 1 - rather than closing the connection.
        await harness.PeerSendsAsync(
            cancellation.Token,
            Stream(SecondRequestStreamId, 0, DynamicResponseBytes(2), fin: true));

        Assert.True(harness.Http3.ResponseFor(SecondRequestStreamId)!.IsBlocked);
        Assert.Equal(0ul, harness.Http3.ConnectionErrorCode);
        Assert.Equal(1, harness.Http3.Streams.BlockedStreams.Count);
    }

    // s2.2.2.1's MUST reaching the wire, once per section. The instruction is s4.4.1's Section
    // Acknowledgment: the 1 pattern on a 7-bit prefix carrying the stream id, so stream 0 is a
    // single 0x80 octet.
    [Fact]
    public async Task ADecodedSectionSendsOneSectionAcknowledgmentAndFurtherPumpsSendNone()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        var stream = harness.Http3.TryOpenRequest(Request(), out _, out _);
        Assert.NotNull(stream);
        await harness.FlushAsync(cancellation.Token);
        WatchDecoderStream(harness);
        await harness.PeerSendsAsync(cancellation.Token, PeerControl());

        await harness.PeerSendsAsync(
            cancellation.Token,
            Stream(FirstRequestStreamId, 0, DynamicResponseBytes(1), fin: true));
        Assert.True(harness.Http3.ResponseFor(FirstRequestStreamId)!.IsBlocked);

        // Nothing is acknowledged for a section that has not been decoded.
        Assert.DoesNotContain(
            await DecoderStreamBytesAsync(harness, cancellation.Token), b => b == 0x80);

        await harness.PeerSendsAsync(
            cancellation.Token, PeerEncoderStream(("x-dynamic", "from-the-table")));

        // s4.4.1's Section Acknowledgment for stream 0, and s4.4.3's Insert Count Increment of
        // 1 - which is 0x01 - for the one insertion. Both, once.
        var afterUnblock = await DecoderStreamBytesAsync(harness, cancellation.Token);
        Assert.Equal(1, afterUnblock.Count(b => b == 0x80));

        // FOUR MORE PUMPS AND NOTHING FURTHER GOES OUT, which is the difference between "once
        // per section" and "once per pump". A duplicate Section Acknowledgment is a
        // QPACK_DECODER_STREAM_ERROR at the peer's encoder, so this is a real fault and not
        // merely waste.
        for (var pump = 0; pump < 4; pump++)
        {
            Assert.True(harness.Http3.TryProcess(out var error));
            Assert.Equal(0ul, error);
        }

        Assert.Equal(afterUnblock, await DecoderStreamBytesAsync(harness, cancellation.Token));
    }

    // s2.1.2: "If a decoder encounters more blocked streams than it promised to support, it
    // MUST treat this as a connection error of type QPACK_DECOMPRESSION_FAILED." Advertised as
    // ONE here so the boundary is two streams away rather than a hundred, and the value comes
    // from the spec so the shipped 100 travels the same path.
    [Fact]
    public async Task MoreBlockedStreamsThanPromisedIsAConnectionError()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(
            cancellation.Token,
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 65536),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 1),
                ],
            });

        Assert.NotNull(harness.Http3.TryOpenRequest(Request(path: "/one"), out _, out _));
        Assert.NotNull(harness.Http3.TryOpenRequest(Request(path: "/two"), out _, out _));
        await harness.FlushAsync(cancellation.Token);
        await harness.PeerSendsAsync(cancellation.Token, PeerControl());

        // The first stream blocks and takes the one promised slot.
        await harness.PeerSendsAsync(
            cancellation.Token,
            Stream(FirstRequestStreamId, 0, DynamicResponseBytes(1), fin: true));
        Assert.True(harness.Http3.ResponseFor(FirstRequestStreamId)!.IsBlocked);
        Assert.Equal(0ul, harness.Http3.ConnectionErrorCode);

        // The second asks for a slot that was promised to nobody.
        await harness.PeerSendsAsync(
            cancellation.Token,
            expectAccepted: false,
            Stream(SecondRequestStreamId, 0, DynamicResponseBytes(1), fin: true));

        Assert.Equal(TlsQuicQpackDecoder.QpackDecompressionFailed, harness.Http3.ConnectionErrorCode);
    }

    // A SECTION THAT NEVER UNBLOCKS DOES NOT SPIN AND DOES NOT ESCALATE. Nothing here waits:
    // TryProcess re-presents the parked bytes ONCE and returns, so the bound on a peer that
    // never sends the instructions is TlsQuicConnection's own - the handshake deadline and RFC
    // 9000 s10.1's idle timeout, whichever is nearer, both applied inside
    // ReceiveWithinDeadlineAsync. See ThePumpNeverCatchesTheDeadlineAndNeverLoopsInternally for
    // the half of that promise this task actually owes.
    [Fact]
    public async Task ASectionThatNeverUnblocksStaysBlockedAcrossManyPumpsWithNoError()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var harness = await Harness.CreateAsync(cancellation.Token);

        Assert.NotNull(harness.Http3.TryOpenRequest(Request(), out _, out _));
        await harness.FlushAsync(cancellation.Token);
        await harness.PeerSendsAsync(cancellation.Token, PeerControl());
        await harness.PeerSendsAsync(
            cancellation.Token,
            Stream(FirstRequestStreamId, 0, DynamicResponseBytes(1), fin: true));

        var reader = harness.Http3.ResponseFor(FirstRequestStreamId);
        Assert.NotNull(reader);

        // BOUNDED BY A COUNT, NOT BY A CLOCK, so a spin fails this test rather than wedging a
        // mutation sweep on it. Every call returns; that it returns is the assertion.
        for (var pump = 0; pump < 64; pump++)
        {
            Assert.True(harness.Http3.TryProcess(out var error));
            Assert.Equal(0ul, error);
            Assert.True(reader.IsBlocked);
        }

        Assert.Equal(0ul, harness.Http3.ConnectionErrorCode);
        Assert.False(reader.IsComplete);
        Assert.Equal(1, harness.Http3.Streams.BlockedStreams.Count);
    }

    // WHAT C16 OWES THE DEADLINE, AS SOURCE RATHER THAN AS PROSE. The deadline already exists
    // and TlsQuicConnectionTests.TheHandshakeDeadlineFiresOnTheFakeClockWithNoWallClockTime
    // Elapsed already witnesses it firing; this task's obligation is only that blocking does
    // not defeat it. Two ways it could: swallowing the TimeoutException, or re-presenting a
    // parked section inside a loop of its own so that a pump never returns to the receive that
    // the deadline bounds.
    [Fact]
    public void ThePumpNeverCatchesTheDeadlineAndNeverLoopsInternally()
    {
        foreach (var name in new[]
        {
            "TlsQuicHttp3Connection.cs",
            "TlsQuicHttp3Request.cs",
            "TlsQuicHttp3Streams.cs",
        })
        {
            var source = File.ReadAllText(Path.Combine(Http3SourceDirectory(), name));

            // COMMENTS STRIPPED FIRST. The rule is about CODE - these files discuss the
            // deadline at length, and TrySynchroniseQpackState's own remarks name
            // TimeoutException in the sentence explaining why nothing here waits.
            Assert.DoesNotContain(
                "TimeoutException", WithoutComments(source), StringComparison.Ordinal);
            Assert.DoesNotContain(
                "catch (Exception", WithoutComments(source), StringComparison.Ordinal);
        }

        // AND THE RE-PRESENTATION IS NOT IN A LOOP OF ITS OWN. TryProcess walks _exchanges
        // once per call with a single `foreach`; a `while` around that walk - retrying until
        // something unblocked - would be the shape that never returns to the receive. The
        // check is that the only loops between the method's opening brace and its closing one
        // are the `foreach (var exchange in _exchanges)` walk itself.
        var connection = File.ReadAllText(
            Path.Combine(Http3SourceDirectory(), "TlsQuicHttp3Connection.cs"));
        var body = TryProcessBody(connection);

        Assert.Contains("foreach (var exchange in _exchanges)", body, StringComparison.Ordinal);
        Assert.DoesNotContain("while (", body, StringComparison.Ordinal);
        Assert.DoesNotContain("do\n", body, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------------
    // C16 helpers
    // ------------------------------------------------------------------------

    // s6.2's type 0x02 stream carrying RFC 9204 s4.3.1's Set Dynamic Table Capacity and one
    // s4.3.3 Insert With Literal Name per field, so the peer's encoder is doing the inserting
    // and this helper only supplies the bytes it would send.
    private static TlsQuicFrame PeerEncoderStream(params (string Name, string Value)[] entries)
    {
        var bytes = new List<byte> { (byte)TlsQuicHttp3StreamType.QpackEncoder };

        var capacity = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(
            4096, 5, 0b0010_0000, capacity, out var capacityLength));
        bytes.AddRange(capacity[..capacityLength]);

        foreach (var (name, value) in entries)
        {
            var instruction = new byte[512];
            Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
                Encoding.ASCII.GetBytes(name), 6, 0b0100_0000, huffman: false,
                instruction, out var nameLength));
            Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
                Encoding.ASCII.GetBytes(value), 8, 0, huffman: false,
                instruction.AsSpan(nameLength), out var valueLength));
            bytes.AddRange(instruction[..(nameLength + valueLength)]);
        }

        return Stream(PeerEncoderStreamId, 0, bytes.ToArray());
    }

    // A HEADERS frame whose field section is HAND-DERIVED, because this repo's own encoder is
    // static-only and cannot produce a non-zero Required Insert Count at all - so a helper
    // that asked it for one would be asking the code under test for its own vector.
    //
    // s4.5.1.1: EncInsertCount = (ReqInsertCount mod (2 * MaxEntries)) + 1, and with the
    // capture's 65536-byte table MaxEntries is floor(65536 / 32) = 2048, so a count of 1
    // encodes as 2. s4.5.1.2: Sign 0 and Delta Base 0 put the Base at the count. Then s4.5.2
    // twice: T = 1 at static index 25 is ":status: 200", and T = 0 at relative index 0 is
    // s3.2.5's entry at Base - 1, which for a count of 1 is absolute 0.
    private static byte[] DynamicResponseBytes(ulong requiredInsertCount)
    {
        Assert.InRange(requiredInsertCount, 1ul, 63ul);
        byte[] section =
        [
            (byte)(requiredInsertCount + 1),
            0x00,
            0b1100_0000 | 25,
            0b1000_0000,
        ];

        var bytes = new List<byte>();
        TlsQuicHttp3Frames.Write(bytes, (ulong)TlsQuicHttp3FrameType.Headers, section);
        return bytes.ToArray();
    }

    // How many of the client's datagrams the loopback peer has already taken. Harness.
    // PeerSendsAsync never pumps the PEER, so our own ACK datagrams pile up in its inbox
    // unread - and LoopbackQuicPeer.PumpOnceAsync blocks on an empty one, so a helper that
    // pumped hopefully would hang rather than fail. Counting is what bounds the drain.
    private int _peerDatagramsTaken;

    // The baseline for that count: every datagram the client has sent up to now has already
    // been taken by the peer, so only later ones are owed. Called once, after the request has
    // been flushed and before the peer starts sending.
    private void WatchDecoderStream(Harness harness) =>
        _peerDatagramsTaken = harness.ClientTransport.Sent.Count;

    // Every byte this client has written on its own s4.2 decoder stream, from the STREAM
    // frames the loopback peer recorded - so what is asserted is what reached the wire and not
    // what a sender was asked to write.
    private async ValueTask<byte[]> DecoderStreamBytesAsync(
        Harness harness, CancellationToken cancellationToken)
    {
        await harness.Connection.SendPendingAsync(cancellationToken);

        // EXACTLY THE BACKLOG SINCE THE BASELINE AND NO MORE, so this can never outrun the
        // inbox. WatchDecoderStream sets the baseline; without it this would try to re-take
        // the datagrams Harness.CreateAsync and FlushAsync already had the peer consume, and
        // would block on an empty inbox until the test timeout - which is how the first draft
        // of this helper failed, in sixty seconds rather than in an assertion.
        while (_peerDatagramsTaken < harness.ClientTransport.Sent.Count)
        {
            await harness.Peer.PumpOnceAsync(SentAt, cancellationToken);
            _peerDatagramsTaken++;
        }

        var decoderStreamId = harness.Http3.Streams.LocalDecoderStream!.Id;
        var bytes = new List<byte>();
        foreach (var frame in harness.Peer.ReceivedStreamFrames)
        {
            if (frame.StreamId == decoderStreamId)
            {
                bytes.AddRange(frame.Data.ToArray());
            }
        }

        return bytes.ToArray();
    }

    // s2.1: a server-initiated unidirectional stream is 3 mod 4, so 3 is the control stream
    // and 7 is the next one the peer opens.
    private const ulong PeerEncoderStreamId = 7;

    // Line comments and doc comments removed, so a source-level rule about code is neither
    // defeated nor satisfied by prose. Block comments are not used in these files.
    private static string WithoutComments(string source)
    {
        var kept = new List<string>();
        foreach (var line in source.Split('\n'))
        {
            if (!line.TrimStart().StartsWith("//", StringComparison.Ordinal))
            {
                kept.Add(line);
            }
        }

        return string.Join('\n', kept);
    }

    private static string Http3SourceDirectory()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
               && !Directory.Exists(Path.Combine(directory.FullName, "src", "SharpTls", "Quic")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return Path.Combine(directory.FullName, "src", "SharpTls", "Quic");
    }

    // The text between TryProcess's signature and the next method's, found by the brace depth
    // rather than by a regex over the whole file - a comment inside the method mentioning
    // "while (" would otherwise be indistinguishable from code, and there is one two methods
    // away.
    private static string TryProcessBody(string source)
    {
        var start = source.IndexOf("internal bool TryProcess(out ulong errorCode)", StringComparison.Ordinal);
        Assert.True(start >= 0, "TryProcess was not found in TlsQuicHttp3Connection.cs.");

        var open = source.IndexOf('{', start);
        var depth = 0;
        for (var i = open; i < source.Length; i++)
        {
            if (source[i] == '{')
            {
                depth++;
            }
            else if (source[i] == '}' && --depth == 0)
            {
                return source[open..i];
            }
        }

        Assert.Fail("TryProcess's body was not balanced.");
        return string.Empty;
    }
}

// The SECOND peer C11's done-when names, and the one that is not ours: a QuicListener from
// System.Net.Quic, driven from A4 task 10's fixture.
//
// WHAT THIS ADDS OVER THE LOOPBACK PEER. LoopbackQuicPeer shares our packet header, our header
// protection and our packet protection, so a symmetric defect in any of the three cancels
// exactly - that is measured, not suspected, and task 7's inverted AEAD nonce is the recorded
// instance. MsQuic shares none of them. It also enforces its own stream limits, its own
// flow control and its own ALPN, so a request that completes here is one a QUIC implementation
// we did not write agreed to carry.
//
// WHAT IT STILL CANNOT DO: MsQuic speaks QUIC and not HTTP/3, so the HTTP/3 half of the server
// below is written here, in the test, out of QuicStream reads and writes. The frame layer on
// the far side is therefore OURS again. The split is exactly the one the loopback file already
// records: the TRANSPORT is foreign and the FRAMING is not.
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("osx")]
public sealed class TlsQuicHttp3MsQuicLoopbackTests
{

    [MsQuicLoopbackFact]
    public async Task AFullRequestAndResponseCompleteAgainstSystemNetQuic()
    {
        await using var server = await MsQuicLoopbackServer.StartAsync();
        using var timeout = new CancellationTokenSource(
            MsQuicLoopbackServer.HandshakeDeadline + TimeSpan.FromSeconds(10));
        await using var transport =
            TlsQuicUdpDatagramTransport.Create(server.EndPoint.AddressFamily);
        await using var connection = await server.ConnectAsync(transport, timeout.Token);
        await using var accepted = await server.AcceptAsync(timeout.Token);

        // s3.2's ALPN token, asserted on the SERVER's side - the only half we cannot fake, and
        // the reason this task states where "h3" comes from rather than assuming a profile
        // supplies it. Nothing under src/ offers it; MsQuicLoopbackServer's own client profile
        // does, freshly per connection, which is A4's Finding 1.
        Assert.Equal(
            new System.Net.Security.SslApplicationProtocol("h3"),
            accepted.NegotiatedApplicationProtocol);

        var http3 = new TlsQuicHttp3Connection(connection, new TlsQuicHttp3Spec());
        http3.OpenLocalStreams();
        var stream = http3.TryOpenRequest(
            new TlsQuicHttp3Request
            {
                Method = "GET",
                Scheme = "https",
                Authority = "localhost",
                Path = "/api/http3",
            },
            out var refusal,
            out var malformed);
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
        Assert.Equal(TlsQuicHttp3RequestError.None, malformed);
        Assert.NotNull(stream);
        Assert.True(await connection.SendPendingAsync(timeout.Token));

        // The server half runs concurrently, because our request stream's HEADERS and the
        // server's control stream cross in flight and a sequential driver would deadlock on
        // whichever it waited for first.
        var serving = Task.Run(() => ServeOneRequestAsync(accepted, timeout.Token), timeout.Token);

        while (!stream.ReceiveComplete)
        {
            Assert.True(await http3.PumpOnceAsync(timeout.Token), "The HTTP/3 layer refused.");
            timeout.Token.ThrowIfCancellationRequested();
        }

        await serving;

        var response = http3.ResponseFor(stream.Id);
        Assert.NotNull(response);
        Assert.True(response.IsComplete);
        Assert.Equal(200, response.Status);
        Assert.Equal(ResponseBody, Encoding.UTF8.GetString(response.Body));

        // The peer opened its own control stream and its SETTINGS were read - RFC 9114 s3.2's
        // "a SETTINGS frame MUST be sent by each endpoint as the initial frame of their
        // respective HTTP control stream", from the side we do not control.
        Assert.True(http3.Streams.PeerSettingsReceived);
    }

    private const string ResponseBody = "{\"protocol\":\"http3\",\"peer\":\"msquic\"}";

    // A minimal HTTP/3 server over System.Net.Quic's streams: s6.2.1's control stream with
    // SETTINGS first, then one request stream answered with HEADERS and DATA.
    private static async Task ServeOneRequestAsync(
        QuicConnection connection, CancellationToken cancellationToken)
    {
        await using var control = await connection.OpenOutboundStreamAsync(
            QuicStreamType.Unidirectional, cancellationToken);
        var opening = new List<byte> { (byte)TlsQuicHttp3StreamType.Control };
        var settings = new List<byte>();
        TlsQuicHttp3Settings.EncodePayload(
            settings,
            [new TlsQuicHttp3Setting(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier, 262144)]);
        TlsQuicHttp3Frames.Write(
            opening, (ulong)TlsQuicHttp3FrameType.Settings, settings.ToArray());
        await control.WriteAsync(opening.ToArray(), cancellationToken);
        await control.FlushAsync(cancellationToken);

        // ACCEPT UNTIL A BIDIRECTIONAL ONE ARRIVES, and KEEP the ones that are not. This is
        // where the first draft of this test deadlocked, twice over. AcceptInboundStreamAsync
        // yields ANY inbound stream, and the client's three s6.2 unidirectional streams travel
        // in the same datagram as its request, so the first stream offered is the control
        // stream - whose sending half s6.2.1 forbids the client to close, so a read of it never
        // returns. Disposing the skipped ones instead did not help: QuicStream.DisposeAsync on
        // an unread inbound stream does not return promptly, and the accept loop never reached
        // the second stream. Holding them until the connection goes away is what works, and a
        // real HTTP/3 server would be reading them as the peer's control and QPACK streams.
        var skipped = new List<QuicStream>();
        QuicStream? request = null;
        while (request is null)
        {
            var inbound = await connection.AcceptInboundStreamAsync(cancellationToken);
            if (inbound.Type == QuicStreamType.Bidirectional)
            {
                request = inbound;
            }
            else
            {
                skipped.Add(inbound);
            }
        }

        // Drain to the client's FIN. The request carries no content, so this is the whole
        // HEADERS frame - and reading it to the end is what proves our FIN arrived.
        var buffer = new byte[4096];
        var received = 0;
        while (true)
        {
            var read = await request.ReadAsync(buffer.AsMemory(received), cancellationToken);
            if (read == 0)
            {
                break;
            }
            received += read;
            if (received == buffer.Length)
            {
                // GROWN BEFORE THE NEXT READ, not after it. buffer.AsMemory(buffer.Length) is
                // an EMPTY memory and ReadAsync answers 0 for one - which this loop reads as
                // the FIN, so a full buffer would end the read silently and short.
                Array.Resize(ref buffer, buffer.Length * 2);
            }
        }

        var offset = 0;
        Assert.Equal(
            TlsQuicHttp3FrameReadStatus.Complete,
            TlsQuicHttp3Frames.TryRead(
                buffer.AsSpan(0, received), ref offset, out var frameType, out _, out _));
        Assert.Equal((ulong)TlsQuicHttp3FrameType.Headers, frameType);

        var section = new byte[1024];
        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(section, out var written));
        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldLine(
            ":status"u8, "200"u8, huffman: true, preferNameReference: true,
            section.AsSpan(written), out var count));
        written += count;

        var response = new List<byte>();
        TlsQuicHttp3Frames.Write(
            response, (ulong)TlsQuicHttp3FrameType.Headers, section.AsSpan(0, written));
        TlsQuicHttp3Frames.Write(
            response, (ulong)TlsQuicHttp3FrameType.Data, Encoding.UTF8.GetBytes(ResponseBody));
        await request.WriteAsync(response.ToArray(), completeWrites: true, cancellationToken);

        // The request stream is disposed only after its write completes; the skipped ones are
        // released here rather than in the accept loop, for the reason that loop records.
        await request.DisposeAsync();
        foreach (var stream in skipped)
        {
            await stream.DisposeAsync();
        }
    }
}

// WHAT THE DELETED SPIKE PROVED THAT NOTHING OFFLINE CAN.
//
// fp.impersonate.pro/api/http3 answers only when h3 was GENUINELY negotiated - it reports the
// protocol it was reached over, so a fallback to HTTP/2 or HTTP/1.1 cannot satisfy it. That is
// evidence about the whole stack against a server nobody here configured, over a real network
// with real loss, and neither LoopbackQuicPeer nor MsQuic on loopback can stand in for it.
// tests/SharpTls.Tests/Interop/Http3GetSpike.cs is deleted and this is what it becomes.
//
// FOUR THINGS THE SPIKE HARD-CODED AND THIS DOES NOT:
//
//   1. ITS 20-SECOND DEADLINE, used for the handshake, the idle timer and the response wait
//      alike. Here each is a separate value passed in by this test, and TlsQuicHttp3Connection
//      holds no timeout at all.
//   2. ITS 4 KiB / 64 KiB / 128-LINE FIXED BUFFERS. The request field section grows by doubling
//      inside TlsQuicHttp3Request (C9) and the response's is sized from the encoded payload
//      inside TlsQuicHttp3Response (C10); neither number appears anywhere.
//   3. ITS RE-FINDING OF THE REQUEST STREAM BY THE LITERAL ID 0. TryOpenRequest returns the
//      stream.
//   4. ITS ONE-REQUEST LIFETIME. TwoRequestsOnOneConnectionEachLandOnTheirOwnReader is the
//      offline witness for the general case.
[Collection(nameof(PublicInteropCollection))]
public sealed class TlsQuicHttp3PublicEndpointInteropTests
{
    private const string Host = "fp.impersonate.pro";

    [InteropFact]
    public async Task AFullRequestAndResponseCompleteAgainstALiveHttp3Endpoint()
    {
        var handshakeDeadline = TimeSpan.FromSeconds(15);
        var responseDeadline = TimeSpan.FromSeconds(20);

        var addresses = await System.Net.Dns.GetHostAddressesAsync(Host);
        var address =
            addresses.FirstOrDefault(
                a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            ?? addresses.FirstOrDefault()
            ?? throw new InvalidOperationException($"{Host} resolved to no addresses.");
        var endPoint = new System.Net.IPEndPoint(address, 443);

        await using var transport =
            TlsQuicUdpDatagramTransport.Create(endPoint.AddressFamily);
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, endPoint, new TlsQuicConnectionSpec { PaddingTarget = 1200 })
            {
                HandshakeDeadline = handshakeDeadline,
                IdleTimeout = handshakeDeadline + responseDeadline,
            },
            LiveClient);
        await connection.ConnectAsync();

        // THE SHIPPED DEFAULTS, AND C16 IS WHY THEY ARE REACHABLE. This used to narrow to
        // QPACK_MAX_TABLE_CAPACITY 0 and QPACK_BLOCKED_STREAMS 0 because RFC 9204 s3.2.3 leaves
        // the peer's encoder unable to use the dynamic table at capacity 0, which is what made
        // the static-only decoder C5-C8 shipped a CORRECT decoder here rather than a lucky one.
        //
        // THE COMMENT THAT STOOD HERE SAID THAT GAP WAS "SUBSYSTEM B'S". IT WAS NOT - IT WAS
        // C16'S, and this line is the whole of the correction. C14 built the dynamic table,
        // C15 the decoder-stream instructions and C16 s2.2.1's blocking, so the capture's own
        // 65536 and 100 are what this connection now advertises and what a live peer answers.
        var http3 = new TlsQuicHttp3Connection(connection, new TlsQuicHttp3Spec());
        http3.OpenLocalStreams();

        var stream = http3.TryOpenRequest(
            new TlsQuicHttp3Request
            {
                Method = "GET",
                Scheme = "https",
                Authority = Host,
                Path = "/api/http3",
            },
            out var refusal,
            out var malformed);
        Assert.Equal(TlsQuicHttp3RequestRefusal.None, refusal);
        Assert.Equal(TlsQuicHttp3RequestError.None, malformed);
        Assert.NotNull(stream);
        Assert.True(await connection.SendPendingAsync());

        var clock = System.Diagnostics.Stopwatch.StartNew();
        while (!stream.ReceiveComplete && clock.Elapsed < responseDeadline)
        {
            Assert.True(
                await http3.PumpOnceAsync(),
                $"The HTTP/3 layer refused with 0x{http3.ConnectionErrorCode:x}.");
        }

        var response = http3.ResponseFor(stream.Id);
        Assert.NotNull(response);
        Assert.True(
            response.IsComplete,
            $"No complete response after {clock.Elapsed}. "
                + $"received={stream.Received.Count} fin={stream.FinReceived} "
                + $"peer_settings={TlsQuicHttp3Settings.Render(http3.Streams.PeerSettings)}");
        Assert.Equal(200, response.Status);

        // The endpoint reports the protocol it was reached over, and it is the only assertion
        // in this repo that h3 was negotiated end to end against a server we did not configure.
        Assert.Contains("\"protocol\": \"http3\"", Encoding.UTF8.GetString(response.Body));
    }

    // A FRESH PROFILE PER CONNECTION, which is A4's Finding 1, and the ALPN token this whole
    // task turns on. `grep -rn '"h3"' src/ --include=*.cs` returns nothing: no profile under
    // src/ offers h3, so every caller that has negotiated it in this repo has built its own
    // through .WithAlpn("h3") - here, and in MsQuicLoopbackServer. Supplying one is subsystem
    // B's and E's, and C's tests do not assume it.
    private static CustomTlsQuicClient LiveClient(ReadOnlyMemory<byte> sourceConnectionId) =>
        new(new CustomTlsQuicClientOptions
        {
            ServerName = Host,
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(
                    TlsCipherSuite.TlsAes128GcmSha256,
                    TlsCipherSuite.TlsAes256GcmSha384)
                .WithSupportedGroups(
                    NamedGroup.X25519, NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.X25519)
                .WithAlpn("h3")
                .WithQuicTransportParameters(new TlsQuicTransportParameters(
                [
                    new TlsQuicTransportParameter(
                        (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
                        sourceConnectionId.ToArray()),
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.ActiveConnectionIdLimit, 2),

                    // RFC 9221 s3's 0x20, at the Brave capture's 65536, for the reason the
                    // offline Harness passes the same number: this client sends
                    // TlsQuicHttp3Spec.CaptureSettings, whose 51:1 says it will receive HTTP/3
                    // datagrams, and TlsQuicHttp3Connection's constructor refuses that claim
                    // when the ClientHello carries no transport half of it. MsQuic tolerates
                    // the inconsistent pair and fp.impersonate.pro does not - which is exactly
                    // why the loopback test never caught it and the live one did.
                    TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.MaxDatagramFrameSize, 65536),

                    // THE SIX FLOW-CONTROL LIMITS COME FROM THE SPEC NOW, not from the round
                    // numbers the spike hard-coded. TlsQuicConnectionSpec.LocalFlowControl
                    // advertises them and TlsQuicStreamSet enforces the same values it
                    // advertised, which is the half the spike's second finding said was
                    // missing - it promised a window nothing ever raised.
                    .. new TlsQuicConnectionSpec().LocalFlowControl.ToTransportParameters(),
                ]))),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                // An OCSP fetch inside the pump loop would be recorded as QUIC loss, which is
                // the same reason the A4 live run gives.
                RevocationMode =
                    X509RevocationMode.NoCheck,
            },
        });
}
