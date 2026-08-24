using System.Text;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task C4: RFC 9114 s6.2's unidirectional streams and s6.2.1's control stream.
//
// ============================================================================
// THE OPEN ORDER IS ASSERTED FROM THE WIRE, NOT FROM THE SPEC OBJECT.
// ============================================================================
//
//   TlsQuicHttp3StreamsTests.TheThreeStreamsAreOpenedInTheSpecsOrder reads the STREAM frames
//   14e recorded and takes each one's first byte, which is s6.2's stream-type varint. A test
//   that compared TlsQuicHttp3Streams.LocalStreamIds against the spec's list would be
//   comparing two things the object was TOLD, and would pass on an implementation that
//   opened the streams in spec order and then wrote the wrong type byte on each.
//
// ============================================================================
// EVERY PEER-INPUT REJECTION NAMES ITS s8.1 CODE.
// ============================================================================
//
//   s6.2.1 attaches three different codes to three different faults on one stream, and they
//   are easy to swap: H3_MISSING_SETTINGS for a first frame that is not SETTINGS,
//   H3_STREAM_CREATION_ERROR for a second control stream, H3_CLOSED_CRITICAL_STREAM for a
//   close. Asserting only "it failed" would let any two be exchanged.
public sealed class TlsQuicHttp3StreamsTests
{
    // s2.1: a server-initiated unidirectional stream has both type bits set, so its id is
    // 3 mod 4. These are the first three.
    private const ulong PeerUni0 = 3;
    private const ulong PeerUni1 = 7;

    // s2.1: a server-initiated bidirectional stream is 1 mod 4.
    private const ulong PeerBidi0 = 1;

    // ------------------------------------------------------------------------
    // What we open.
    // ------------------------------------------------------------------------

    [Fact]
    public void TheThreeStreamsAreOpenedInTheSpecsOrder()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        http3.OpenLocalStreams();
        var frames = set.TakePendingFrames();

        Assert.Equal(3, frames.Count);
        Assert.Equal(0x00, frames[0].Data.Span[0]); // s6.2.1's control stream
        Assert.Equal(0x02, frames[1].Data.Span[0]); // RFC 9204 s4.2's encoder stream
        Assert.Equal(0x03, frames[2].Data.Span[0]); // RFC 9204 s4.2's decoder stream
    }

    [Fact]
    public void AReorderedSpecChangesTheStreamTypeBytesOnTheWire()
    {
        // The knob is live: the placeholder default is not the only order the code can emit,
        // which is what stops UnidirectionalStreamOpenOrder from being a constant wearing an
        // ImmutableArray.
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(
            new TlsQuicHttp3Spec
            {
                UnidirectionalStreamOpenOrder =
                [
                    TlsQuicHttp3StreamType.QpackDecoder,
                    TlsQuicHttp3StreamType.Control,
                    TlsQuicHttp3StreamType.QpackEncoder,
                ],
            },
            set);

        http3.OpenLocalStreams();
        var frames = set.TakePendingFrames();

        Assert.Equal(0x03, frames[0].Data.Span[0]);
        Assert.Equal(0x00, frames[1].Data.Span[0]);
        Assert.Equal(0x02, frames[2].Data.Span[0]);
    }

    [Fact]
    public void SettingsIsTheFirstFrameOnOurControlStreamAndCarriesTheSpecsPairs()
    {
        // s6.2.1: "Each side MUST initiate a single control stream at the beginning of the
        // connection and send its SETTINGS frame as the first frame on this stream." Read
        // back off the wire: type varint, then a whole s7.1 frame whose type is 0x04.
        var set = Set();
        var spec = new TlsQuicHttp3Spec();
        var http3 = new TlsQuicHttp3Streams(spec, set);

        http3.OpenLocalStreams();
        var control = set.TakePendingFrames()[0].Data.ToArray();

        var offset = 0;
        Assert.True(QuicVariableLengthInteger.TryRead(control, ref offset, out var streamType));
        Assert.Equal(0x00UL, streamType);

        Assert.Equal(
            TlsQuicHttp3FrameReadStatus.Complete,
            TlsQuicHttp3Frames.TryRead(
                control, ref offset, out var frameType, out var payload, out _));
        Assert.Equal(0x04UL, frameType);
        Assert.True(TlsQuicHttp3Settings.TryDecodePayload(payload, out var settings, out _));
        Assert.Equal(spec.Settings.ToArray(), settings.ToArray());
        Assert.Equal(control.Length, offset);
    }

    [Fact]
    public void TheOpeningFlightIsSentOnce()
    {
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), Set());
        http3.OpenLocalStreams();

        Assert.Throws<InvalidOperationException>(http3.OpenLocalStreams);
    }

    // ------------------------------------------------------------------------
    // The peer's control stream.
    // ------------------------------------------------------------------------

    [Fact]
    public void APeerControlStreamStartingWithSettingsIsAcceptedInThePeersOrder()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        // Stream type 0x00, then SETTINGS (0x04) with a five-byte payload holding
        // (51, 1) and (7, 100) - deliberately not ascending.
        Deliver(set, PeerUni0, [0x00, 0x04, 0x05, 0x33, 0x01, 0x07, 0x40, 0x64]);

        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.None, error);
        Assert.Equal(PeerUni0, http3.PeerControlStreamId);
        Assert.True(http3.PeerSettingsReceived);
        Assert.Equal(
            new TlsQuicHttp3Setting[] { new(51, 1), new(7, 100) }, http3.PeerSettings);
    }

    [Theory]
    [InlineData((byte)0x00)] // DATA
    [InlineData((byte)0x01)] // HEADERS
    [InlineData((byte)0x07)] // GOAWAY - legal on a control stream, illegal as the FIRST frame
    [InlineData((byte)0x21)] // a reserved (GREASE) frame; s6.2.1 carves out no exemption
    public void AFirstControlFrameThatIsNotSettingsIsRejectedWithH3MissingSettings(byte frameType)
    {
        // s6.2.1: "If the first frame of the control stream is any other frame type, this
        // MUST be treated as a connection error of type H3_MISSING_SETTINGS."
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, frameType, 0x01, 0x00]);

        Assert.False(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3MissingSettings, error);
        Assert.False(http3.PeerSettingsReceived);
    }

    [Fact]
    public void APeerSettingsFrameWithAnEmptyPayloadIsReceivedRatherThanMissing()
    {
        // ZERO VERSUS ABSENT, and here the two states have different s8.1 answers: an empty
        // SETTINGS frame satisfies s6.2.1 and leaves PeerSettings empty, while no SETTINGS
        // frame at all is H3_MISSING_SETTINGS. An implementation that keyed "settings
        // received" off the pair count would conflate them.
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x00]);

        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.None, error);
        Assert.True(http3.PeerSettingsReceived);
        Assert.Empty(http3.PeerSettings);
    }

    [Fact]
    public void ASecondPeerControlStreamIsRejectedWithH3StreamCreationError()
    {
        // s6.2.1: "Only one control stream per peer is permitted; receipt of a second stream
        // claiming to be a control stream MUST be treated as a connection error of type
        // H3_STREAM_CREATION_ERROR."
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x00]);
        Deliver(set, PeerUni1, [0x00, 0x04, 0x00]);

        Assert.False(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3StreamCreationError, error);
        Assert.Equal(PeerUni0, http3.PeerControlStreamId);
    }

    [Fact]
    public void AClosedPeerControlStreamIsRejectedWithH3ClosedCriticalStream()
    {
        // s6.2.1: "If either control stream is closed at any point, this MUST be treated as
        // a connection error of type H3_CLOSED_CRITICAL_STREAM."
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x00], fin: true);

        Assert.False(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3ClosedCriticalStream, error);

        // The settings arrived before the close and are kept: the close is reported AFTER
        // the frames, which is what lets subsystem B still read what the peer said.
        Assert.True(http3.PeerSettingsReceived);
    }

    [Fact]
    public void ASecondSettingsFrameOnTheControlStreamIsRejectedWithH3FrameUnexpected()
    {
        // s7.2.4: "If an endpoint receives a second SETTINGS frame on the control stream,
        // the endpoint MUST respond with a connection error of type H3_FRAME_UNEXPECTED."
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x00, 0x04, 0x00]);

        Assert.False(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3FrameUnexpected, error);
    }

    [Theory]
    [InlineData((byte)0x00)] // DATA - s7.2.1 states it as its own MUST
    [InlineData((byte)0x01)] // HEADERS - s7.2.2 likewise
    [InlineData((byte)0x05)] // PUSH_PROMISE - s7 Table 1's "Control Stream: No" row
    public void ARequestStreamFrameAfterSettingsIsRejectedWithH3FrameUnexpected(byte frameType)
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x00, frameType, 0x01, 0x00]);

        Assert.False(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3FrameUnexpected, error);
    }

    [Fact]
    public void AMaxPushIdFrameOnTheControlStreamIsRejectedWithH3FrameUnexpected()
    {
        // s7.2.7: "A server MUST NOT send a MAX_PUSH_ID frame.  A client MUST treat the
        // receipt of a MAX_PUSH_ID frame as a connection error of type H3_FRAME_UNEXPECTED."
        //
        // THE PAYLOAD IS DELIBERATELY WELL FORMED. MAX_PUSH_ID and CANCEL_PUSH are both "one
        // varint on the control stream", and a single arm once handled both - so MAX_PUSH_ID
        // was parsed and accepted under CANCEL_PUSH's rule. A malformed payload here would
        // pass even with the arms merged again, because the varint read would fail on its own.
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x00, 0x0d, 0x01, 0x00]);

        Assert.False(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3FrameUnexpected, error);
    }

    [Fact]
    public void ACancelPushFrameOnTheControlStreamIsStillAccepted()
    {
        // The other half of the split above. s7.2.3 puts CANCEL_PUSH on the control stream
        // legitimately, so rejecting MAX_PUSH_ID must not have been done by rejecting the
        // shape they share. Same encoding, same length, opposite verdict.
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x00, 0x03, 0x01, 0x00]);

        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.None, error);
        Assert.True(http3.PeerSettingsReceived);
    }

    [Fact]
    public void AReservedFrameAfterSettingsOnTheControlStreamIsIgnored()
    {
        // s7.2.8: reserved frames "have no semantics ... Endpoints MUST NOT consider these
        // frames to have any meaning upon receipt". A peer padding its control stream must not
        // kill the connection. (s9 carries the general ignore-unknown-frames requirement and
        // is uncaptured in this repo; s7.2.8's captured text names it but does not quote it.)
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x00, 0x21, 0x03, 0xaa, 0xbb, 0xcc]);

        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.None, error);
        Assert.True(http3.PeerSettingsReceived);
    }

    [Fact]
    public void AGoawayWithTrailingBytesIsRejectedWithH3FrameError()
    {
        // s7.1's equality reaching the control stream: GOAWAY's payload is exactly one
        // varint, and a payload of three bytes holding a one-byte varint is
        // H3_FRAME_ERROR. This is the reader that makes
        // TlsQuicHttp3Frames.TryReadSingleVarintPayload's check live rather than a helper
        // nothing calls.
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x00, 0x07, 0x03, 0x00, 0xff, 0xff]);

        Assert.False(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3FrameError, error);
    }

    [Fact]
    public void AGoawayWhosePayloadIsExactlyItsVarintIsAccepted()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x00, 0x07, 0x01, 0x00]);

        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.None, error);
    }

    // ------------------------------------------------------------------------
    // The peer's other streams.
    // ------------------------------------------------------------------------

    // THE TYPE IS PASSED AS ITS ENCODED BYTES, NOT AS A NUMBER. s6.2's stream type is a QUIC
    // varint, and 0x40 is NOT the one-byte encoding of 64 - the top two bits select the form,
    // so a lone 0x40 byte is the first half of a two-byte varint. An earlier version of this
    // theory passed 0x40 as one byte; it decoded as stream type 0, the CONTROL stream, and the
    // test passed anyway because the junk that followed happened to be an incomplete frame.
    [Theory]
    [InlineData(new byte[] { 0x21 })] // s6.2.3's reserved series at N = 0, one-byte form
    [InlineData(new byte[] { 0x40, 0x40 })] // the same series at N = 1, two-byte form
    [InlineData(new byte[] { 0x3f })] // not reserved, not registered - merely unknown
    public void AnUnknownPeerStreamTypeIsToleratedAndTheConnectionSurvives(byte[] streamType)
    {
        // s6.2: "Recipients of unknown stream types MUST either abort reading of the stream
        // or discard incoming data without further processing ... The recipient MUST NOT
        // consider unknown stream types to be a connection error of any kind."
        //
        // The witness that the connection SURVIVES is the second stream: a legal control
        // stream opened afterwards is still read.
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        // The four bytes after the type are DATA-frame-shaped on purpose: an implementation
        // that consumed the stream type and then fell into the control-stream frame parser
        // would read them as a DATA frame and answer H3_MISSING_SETTINGS.
        Deliver(set, PeerUni0, [.. streamType, 0x00, 0x01, 0xff]);
        Deliver(set, PeerUni1, [0x00, 0x04, 0x02, 0x07, 0x01]);

        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.None, error);
        Assert.Equal(PeerUni1, http3.PeerControlStreamId);
        Assert.Equal(new TlsQuicHttp3Setting[] { new(7, 1) }, http3.PeerSettings);
    }

    [Fact]
    public void AUnidirectionalStreamClosedBeforeItsTypeVarintIsTolerated()
    {
        // s6.2: "A receiver MUST tolerate unidirectional streams being closed or reset prior
        // to the reception of the unidirectional stream header."
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [], fin: true);

        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.None, error);
        Assert.Null(http3.PeerControlStreamId);
    }

    [Fact]
    public void AUnidirectionalStreamStoppedHalfwayThroughItsTypeVarintIsTolerated()
    {
        // The other truncation: a multi-byte stream-type varint whose remaining bytes have
        // not arrived. Nothing is concluded and nothing fails; a later call finishes it.
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0xc0, 0x00]);
        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.None, error);
        Assert.Null(http3.PeerControlStreamId);
    }

    [Fact]
    public void AServerInitiatedBidirectionalStreamIsRejectedWithH3StreamCreationError()
    {
        // s6.1: "Clients MUST treat receipt of a server-initiated bidirectional stream as a
        // connection error of type H3_STREAM_CREATION_ERROR unless such an extension has
        // been negotiated." None is.
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerBidi0, [0x00]);

        Assert.False(http3.TryProcessPeerStreams(out var error));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.H3StreamCreationError, error);
    }

    [Fact]
    public void AControlStreamDeliveredOneByteAtATimeReachesTheSameConclusion()
    {
        // Resumability, which is where a parser that reparses from zero each call or that
        // forgets its partial frame goes wrong. The same eight bytes as
        // TlsQuicHttp3StreamsTests.APeerControlStreamStartingWithSettingsIsAcceptedInThe
        // PeersOrder, split into eight deliveries with a process pass between each.
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);
        byte[] bytes = [0x00, 0x04, 0x05, 0x33, 0x01, 0x07, 0x40, 0x64];

        for (var i = 0; i < bytes.Length; i++)
        {
            Deliver(set, PeerUni0, [bytes[i]], offset: (ulong)i);
            Assert.True(http3.TryProcessPeerStreams(out var error));
            Assert.Equal((ulong)TlsQuicHttp3ErrorCode.None, error);
        }

        Assert.True(http3.PeerSettingsReceived);
        Assert.Equal(
            new TlsQuicHttp3Setting[] { new(51, 1), new(7, 100) }, http3.PeerSettings);
    }

    [Fact]
    public void TheQpackStreamsBytesAreDroppedRatherThanParsedAsFrames()
    {
        // RFC 9204 s4.2's decoder stream. It carries QPACK instructions, not s7.1 frames, so
        // parsing its bytes as frames is wrong twice over - it invents meaning, and here it
        // would invent a CONNECTION ERROR, since 0x00 0x01 0xff reads as a DATA frame and a
        // first frame that is not SETTINGS is H3_MISSING_SETTINGS.
        //
        // C16 TOOK THE ENCODER STREAM OUT OF THIS TEST. Type 0x02 used to be here beside
        // 0x03 and is now parsed as s4.3 instructions - see ThePeersEncoderStreamDrivesThe
        // DynamicTable. The DECODER stream is still discarded, for the reason
        // TryTakeStreamType gives: s4.4's instructions acknowledge OUR encoder's dynamic
        // table, and this client's encoder is static-only. 0x21 stands in for the unknown
        // types s6.2's "MUST NOT consider unknown stream types to be a connection error"
        // covers, so the merged flag still has two members to merge.
        //
        // THE SECOND DELIVERY IS WHAT MAKES THE DROP OBSERVABLE. Bytes that arrive after the
        // type varint has been consumed are the ones an implementation that merely skipped
        // the type and then fell through would parse. Both halves of the ignore path - the
        // flag being set and the flag being honoured on the next pass - fail this test.
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x21, 0x00, 0x01, 0xff]);
        Deliver(set, PeerUni1, [0x03, 0x00, 0x01, 0xff]);
        Assert.True(http3.TryProcessPeerStreams(out var first));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.None, first);

        // The FIN says the ordinary case is ordinary: s6.2.1's H3_CLOSED_CRITICAL_STREAM is
        // about the CONTROL stream, and s6.2's general rule is that "A sender can close or
        // reset a unidirectional stream unless otherwise specified", so a QPACK stream that
        // ends is not an error. It is NOT a witness for the control-stream test inside that
        // close check - the sweep showed deleting that test changes nothing here, because an
        // ignored stream returns before the check is reached. See the check's own comment.
        Deliver(set, PeerUni0, [0x00, 0x01, 0xff], offset: 4, fin: true);
        Deliver(set, PeerUni1, [0x00, 0x01, 0xff], offset: 4, fin: true);
        Assert.True(http3.TryProcessPeerStreams(out var second));
        Assert.Equal((ulong)TlsQuicHttp3ErrorCode.None, second);

        Assert.Null(http3.PeerControlStreamId);
    }

    // ------------------------------------------------------------------------
    // RFC 9297 s2.1.1's both-halves gate.
    // ------------------------------------------------------------------------

    [Fact]
    public void SendingFiftyOneOneAloneDoesNotPermitDatagrams()
    {
        // s2.1.1: "QUIC DATAGRAM frames MUST NOT be sent until the SETTINGS_H3_DATAGRAM
        // setting has been both sent and received with a value of 1." This is the half the
        // capture's 51:1 supplies; on its own it licenses nothing.
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), Set());

        Assert.False(http3.Http3DatagramsPermittedToSend);
    }

    [Fact]
    public void ReceivingFiftyOneOneWithoutSendingItDoesNotPermitDatagrams()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(
            new TlsQuicHttp3Spec { Settings = [new(7, 100)] }, set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x02, 0x33, 0x01]);
        Assert.True(http3.TryProcessPeerStreams(out _));

        Assert.False(http3.Http3DatagramsPermittedToSend);
    }

    [Fact]
    public void BothHalvesTogetherPermitDatagrams()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x02, 0x33, 0x01]);
        Assert.True(http3.TryProcessPeerStreams(out _));

        Assert.True(http3.Http3DatagramsPermittedToSend);
    }

    [Fact]
    public void APeerThatAnswersFiftyOneZeroDoesNotPermitDatagrams()
    {
        // ZERO VERSUS ABSENT on the peer's side: 51:0 is a received pair that says "not
        // willing", and it must not be read as the same thing as a value of 1.
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Deliver(set, PeerUni0, [0x00, 0x04, 0x02, 0x33, 0x00]);
        Assert.True(http3.TryProcessPeerStreams(out _));

        Assert.True(http3.PeerSettingsReceived);
        Assert.False(http3.Http3DatagramsPermittedToSend);
    }

    // ------------------------------------------------------------------------
    // The sweep.
    // ------------------------------------------------------------------------

    [Fact]
    public void NoPeerBytesMakeTheStreamLayerThrow()
    {
        var failures = new List<string>();

        for (var first = 0; first < 256; first++)
        {
            var set = Set();
            var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);
            byte[] bytes =
            [
                (byte)first,
                (byte)(first ^ 0x5a),
                (byte)(first + 0x11),
                (byte)(first * 3),
                0xff,
                0x00,
            ];

            try
            {
                Deliver(set, PeerUni0, bytes);
                http3.TryProcessPeerStreams(out _);
                Deliver(set, PeerUni0, bytes, offset: (ulong)bytes.Length, fin: true);
                http3.TryProcessPeerStreams(out _);
            }
            catch (Exception threw)
            {
                failures.Add($"first=0x{first:x2}: {threw.GetType().Name}: {threw.Message}");
            }
        }

        Assert.Empty(failures);
    }

    // ------------------------------------------------------------------------
    // Helpers.
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // C15: RFC 9204 s4.4's instructions, on the s4.2 decoder stream.
    // ------------------------------------------------------------------------
    //
    // WHAT IS ASSERTED HERE IS THE STREAM, NOT THE BYTES. Which octets each instruction is
    // made of is TlsQuicQpackDecoderTests', anchored on Appendix B and on hand-derived prefix
    // boundaries. What these rows add is that the bytes go out on the DECODER stream - type
    // 0x03, s4.2 - and that the two suppressed cases send nothing at all rather than a legal
    // instruction with a zero in it.

    [Fact]
    public void TheThreeDecoderInstructionsGoOutOnTheDecoderStream()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);
        http3.OpenLocalStreams();

        // The opening flight, discarded: what follows is what C15 adds to it.
        var opening = set.TakePendingFrames();
        Assert.Equal(0x03, opening[2].Data.Span[0]);
        Assert.Equal(opening[2].StreamId, http3.LocalDecoderStream!.Id);

        Assert.True(http3.SendSectionAcknowledgment(streamId: 4, requiredInsertCount: 2));
        Assert.True(http3.SendStreamCancellation(streamId: 8));
        Assert.True(http3.SendInsertCountIncrement(insertCount: 3));

        var frames = set.TakePendingFrames();
        Assert.Equal(3, frames.Count);
        Assert.All(frames, frame => Assert.Equal(http3.LocalDecoderStream!.Id, frame.StreamId));

        // s4.2: "The sender MUST NOT close either of these streams."
        Assert.All(frames, frame => Assert.Equal(0ul, frame.RawType & TlsQuicStreamFrames.FinBit));

        // Appendix B's three octets, in the three shapes. Named here only so that a swap
        // between the two senders that share a 6-bit prefix would be visible from this file
        // too - the derivation lives in TlsQuicQpackDecoderTests.
        Assert.Equal([0x84], frames[0].Data.ToArray());
        Assert.Equal([0x48], frames[1].Data.ToArray());
        Assert.Equal([0x01], frames[2].Data.ToArray());
    }

    // s4.4.1's non-zero condition and s4.4.3's zero-Increment MUST, at the layer that would
    // actually put the bytes on the wire. NOTHING IS SENT, which is a stronger statement than
    // the writer's `written == 0`: an implementation that emitted an empty STREAM frame would
    // satisfy that and would still be adding a frame to the connection.
    [Fact]
    public void ASuppressedInstructionPutsNoFrameOnTheDecoderStream()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);
        http3.OpenLocalStreams();
        set.TakePendingFrames();

        // s4.4.1: a field section whose Required Insert Count is zero is not acknowledged.
        Assert.False(http3.SendSectionAcknowledgment(streamId: 4, requiredInsertCount: 0));
        Assert.Empty(set.TakePendingFrames());
        Assert.Equal(0ul, http3.KnownReceivedCount);

        // s4.4.3: an Increment of zero is a connection error at the peer, so it is not sent.
        Assert.True(http3.SendSectionAcknowledgment(streamId: 4, requiredInsertCount: 2));
        Assert.Single(set.TakePendingFrames());
        Assert.Equal(2ul, http3.KnownReceivedCount);

        Assert.False(http3.SendInsertCountIncrement(insertCount: 2));
        Assert.Empty(set.TakePendingFrames());

        // And a cancellation is never suppressed - s4.4.2 has no such clause, and a stream
        // that referenced nothing is still cancelled.
        Assert.True(http3.SendStreamCancellation(streamId: 8));
        Assert.Single(set.TakePendingFrames());
    }

    // s4.2's MAY: "An endpoint MAY avoid creating a decoder stream if its decoder sets the
    // maximum capacity of the dynamic table to zero." UnidirectionalStreamOpenOrder permits
    // that shape - it requires only the control stream - so a spec can legally leave this
    // endpoint with nothing to send an instruction on. Asking anyway is LOCAL misuse and
    // throws, which is this class's rule for everything a local caller drives.
    [Fact]
    public void AskingForADecoderInstructionWithNoDecoderStreamIsLocalMisuse()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(
            new TlsQuicHttp3Spec
            {
                UnidirectionalStreamOpenOrder =
                [
                    TlsQuicHttp3StreamType.Control,
                    TlsQuicHttp3StreamType.QpackEncoder,
                ],
            },
            set);

        // Before OpenLocalStreams there is no stream either, and it is the same mistake.
        Assert.Throws<InvalidOperationException>(() => http3.SendStreamCancellation(8));

        http3.OpenLocalStreams();
        Assert.Null(http3.LocalDecoderStream);

        Assert.Throws<InvalidOperationException>(() => http3.SendSectionAcknowledgment(4, 2));
        Assert.Throws<InvalidOperationException>(() => http3.SendStreamCancellation(8));
        Assert.Throws<InvalidOperationException>(() => http3.SendInsertCountIncrement(3));

        // THE SUPPRESSED CASES THROW TOO. A check that fired only when something was actually
        // written would pass here for a zero Required Insert Count and leave the misuse to be
        // found later, on the first section that happened to reference the dynamic table.
        Assert.Throws<InvalidOperationException>(() => http3.SendSectionAcknowledgment(4, 0));
        Assert.Throws<InvalidOperationException>(() => http3.SendInsertCountIncrement(0));
    }

    // The decoder stream is found by its TYPE and not by its position, which a spec that
    // reorders the open order is the only way to witness.
    [Fact]
    public void AReorderedSpecStillFindsTheDecoderStreamByItsType()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(
            new TlsQuicHttp3Spec
            {
                UnidirectionalStreamOpenOrder =
                [
                    TlsQuicHttp3StreamType.QpackDecoder,
                    TlsQuicHttp3StreamType.Control,
                    TlsQuicHttp3StreamType.QpackEncoder,
                ],
            },
            set);

        http3.OpenLocalStreams();
        var opening = set.TakePendingFrames();

        // The decoder stream is now FIRST, so an implementation that took the third stream
        // would be pointing at the encoder stream here.
        Assert.Equal(0x03, opening[0].Data.Span[0]);
        Assert.Equal(opening[0].StreamId, http3.LocalDecoderStream!.Id);

        Assert.True(http3.SendStreamCancellation(8));
        var frames = set.TakePendingFrames();
        Assert.Equal(opening[0].StreamId, Assert.Single(frames).StreamId);
    }

    // Hands 14e's stream set one RFC 9000 s19.8 STREAM frame from the peer, which is the
    // only way a peer-initiated stream comes into existence here.
    private static void Deliver(
        TlsQuicStreamSet set, ulong streamId, byte[] data, ulong offset = 0, bool fin = false)
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

        Assert.True(
            set.TryReceive(
                new TlsQuicFrame
                {
                    RawType = rawType,
                    StreamId = streamId,
                    Offset = offset,
                    Data = data,
                },
                out _));
    }

    // s18.2 values large enough that nothing here is refused for flow control; the six are
    // distinct so a misread names the parameter it came from.
    private static TlsQuicStreamSet Set() =>
        new(TlsQuicPeerFlowControlBudget.FromPeerParameters(new TlsQuicTransportParameters(
        [
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxData, 1_000_004),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal, 5005),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote, 6006),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamDataUni, 7007),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamsBidi, 108),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxStreamsUni, 109),
        ])));

    // ========================================================================
    // C16 - the peer's QPACK encoder stream, RFC 9204 s4.3 and s2.2.2.3
    // ========================================================================

    // s6.2's type 0x02 is the encoder stream, and C15 discarded it. s2.1.2 is why it cannot
    // stay discarded: "encoded field sections and encoder stream instructions arrive on
    // separate streams", and the instructions are the only thing that advances the table a
    // field section resolves against.
    [Fact]
    public void ThePeersEncoderStreamDrivesTheDynamicTable()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);
        http3.OpenLocalStreams();
        set.TakePendingFrames();

        Assert.NotNull(http3.Table);
        Assert.Equal(0ul, http3.Table.InsertCount);

        // Stream type 0x02, then s4.3.1's Set Dynamic Table Capacity and two of s4.3.3's
        // Insert With Literal Name.
        Deliver(set, PeerUni0, [0x02, .. SetCapacity(4096), .. Insert("a", "1"), .. Insert("b", "2")]);

        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal(0ul, error);
        Assert.Equal(2ul, http3.Table.InsertCount);

        // s2.2.2.3's feedback went out on our own decoder stream. s4.4.3's Increment is the
        // 001 pattern on a 6-bit prefix, so an increment of 2 is a single 0x02 octet.
        var sent = Assert.Single(set.TakePendingFrames());
        Assert.Equal(http3.LocalDecoderStream!.Id, sent.StreamId);
        Assert.Equal([0x02], sent.Data.ToArray());
        Assert.Equal(2ul, http3.KnownReceivedCount);
    }

    // s4.3's instructions are a byte stream and a QUIC STREAM frame may end anywhere in one.
    // PeerStreamState.Unparsed IS the reassembly - the same buffer the control stream's frames
    // already use - and TryReadEncoderInstructions reports `consumed` so a partial instruction
    // stays put. Split at EVERY boundary rather than at one chosen offset, because an
    // implementation that dropped the unconsumed tail would survive most single choices.
    [Fact]
    public void AnEncoderInstructionSplitAtEveryByteBoundaryEndsInTheSameTable()
    {
        byte[] instructions = [.. SetCapacity(4096), .. Insert("longish-name", "longish-value")];

        var whole = Fed([[0x02, .. instructions]]);
        Assert.Equal(1ul, whole.InsertCount);

        for (var cut = 0; cut <= instructions.Length; cut++)
        {
            var split = Fed(
            [
                [0x02, .. instructions.AsSpan(0, cut)],
                [.. instructions.AsSpan(cut)],
            ]);

            Assert.Equal(whole.InsertCount, split.InsertCount);
            Assert.Equal(whole.Size, split.Size);
            Assert.Equal(whole.Capacity, split.Capacity);

            // And the entry itself is identical, not merely a table of the same shape.
            Assert.True(split.TryLookupAbsolute(0, out var name, out var value, out _));
            Assert.Equal("longish-name", Encoding.ASCII.GetString(name));
            Assert.Equal("longish-value", Encoding.ASCII.GetString(value));
        }
    }

    // A read that consumed nothing must send nothing. s4.4.3 makes a zero Increment a
    // QPACK_DECODER_STREAM_ERROR at the peer's encoder, so a decoder that emitted one per
    // delivery would break the connection on the first partial instruction.
    [Fact]
    public void APartialInstructionSendsNoInsertCountIncrement()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);
        http3.OpenLocalStreams();
        set.TakePendingFrames();

        byte[] insert = Insert("a", "1");

        // The capacity instruction alone changes no Insert Count, and the insert is one byte
        // short of complete.
        Deliver(set, PeerUni0, [0x02, .. SetCapacity(4096), .. insert.AsSpan(0, insert.Length - 1)]);
        Assert.True(http3.TryProcessPeerStreams(out _));
        Assert.Equal(0ul, http3.Table!.InsertCount);
        Assert.Empty(set.TakePendingFrames());

        // The last byte completes it, and now exactly one instruction goes out.
        Deliver(set, PeerUni0, [insert[^1]], offset: (ulong)(1 + SetCapacity(4096).Length + insert.Length - 1));
        Assert.True(http3.TryProcessPeerStreams(out _));
        Assert.Equal(1ul, http3.Table.InsertCount);
        Assert.Equal([0x01], Assert.Single(set.TakePendingFrames()).Data.ToArray());
    }

    // s2.2.3's second paragraph: "If the decoder encounters a reference in an encoder
    // instruction to a dynamic table entry that has already been evicted, it MUST treat this
    // as a connection error of type QPACK_ENCODER_STREAM_ERROR." 0x0201 is OUTSIDE
    // TlsQuicHttp3ErrorCode's 0x0100..0x010e range, which is why C16 widened the reported code
    // to a ulong - an enum-shaped answer could not have carried it.
    [Fact]
    public void AFaultOnTheEncoderStreamIsReportedAsQpackEncoderStreamError()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);
        http3.OpenLocalStreams();
        set.TakePendingFrames();

        // s4.3.3's Insert With Literal Name with no Set Dynamic Table Capacity before it:
        // s3.2.2 makes the initial capacity zero, so the entry cannot fit.
        Deliver(set, PeerUni0, [0x02, .. Insert("a", "1")]);

        Assert.False(http3.TryProcessPeerStreams(out var error));
        Assert.Equal(0x0201ul, error);

        // And it is not one of the s8.1 codes, which is the half that says the widening was
        // needed rather than cosmetic.
        Assert.False(Enum.IsDefined((TlsQuicHttp3ErrorCode)error));
    }

    // RFC 9204 s4.2 permits omitting the decoder stream "if its decoder sets the maximum
    // capacity of the dynamic table to zero", and s3.2.3's zero capacity means there is no
    // table to drive. The encoder stream's bytes are then discarded - and, critically, nothing
    // throws: the three s4.4 senders raise InvalidOperationException when there is no local
    // decoder stream, and a peer must never be able to reach one.
    [Theory]
    [InlineData(0ul, true)]
    [InlineData(65536ul, false)]
    public void AZeroAdvertisedCapacityLeavesNoTableAndDiscardsTheEncoderStream(
        ulong capacity, bool expectNullTable)
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, capacity),
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, 0),
                ],
            },
            set);
        http3.OpenLocalStreams();
        set.TakePendingFrames();

        Assert.Equal(expectNullTable, http3.Table is null);

        Deliver(set, PeerUni0, [0x02, .. SetCapacity(4096), .. Insert("a", "1")]);
        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal(0ul, error);

        if (expectNullTable)
        {
            Assert.Empty(set.TakePendingFrames());
        }
        else
        {
            Assert.Single(set.TakePendingFrames());
        }
    }

    // s4.2 again, from the other side: a spec whose open order omits the decoder stream has
    // declared it decodes at zero capacity, whatever its SETTINGS happen to say. Building a
    // table anyway would let a peer's encoder instruction reach SendInsertCountIncrement,
    // which throws when there is no stream to send on - and NOTHING A PEER SENDS MAY THROW.
    [Fact]
    public void ASpecThatOmitsTheDecoderStreamHasNoTableHoweverMuchCapacityItAdvertises()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(
            new TlsQuicHttp3Spec
            {
                UnidirectionalStreamOpenOrder =
                [
                    TlsQuicHttp3StreamType.Control,
                    TlsQuicHttp3StreamType.QpackEncoder,
                ],
            },
            set);
        http3.OpenLocalStreams();
        set.TakePendingFrames();

        // The spec still advertises the capture's 65536.
        Assert.Equal(
            65536ul,
            TlsQuicHttp3Settings.Value(
                new TlsQuicHttp3Spec().Settings,
                TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier));
        Assert.Null(http3.LocalDecoderStream);
        Assert.Null(http3.Table);

        Deliver(set, PeerUni0, [0x02, .. SetCapacity(4096), .. Insert("a", "1")]);
        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal(0ul, error);
    }

    // NOTHING A PEER SENDS MAY THROW, AND THIS IS THE ORDERING THAT COULD. Nothing orders the
    // peer's encoder stream against our own OpenLocalStreams - RFC 9204 s4.2's streams are
    // opened independently at each end - so a peer may deliver s4.3 instructions before we
    // have a decoder stream to answer on. The three s4.4 senders throw when there is none, and
    // that exception would be reachable from wire input.
    //
    // THE BYTES ARE DEFERRED, NOT DISCARDED AND NOT PARSED-WITHOUT-FEEDBACK. Discarding them
    // would lose the table; parsing them and skipping the send would owe s2.2.2.3 an Insert
    // Count Increment that never comes. So the whole backlog waits, and the first pass after
    // OpenLocalStreams reads it and sends ONE Increment covering all of it.
    [Fact]
    public void AnEncoderStreamThatArrivesBeforeOurOwnStreamsAreOpenIsDeferredRatherThanDropped()
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);

        Assert.Null(http3.LocalDecoderStream);
        Deliver(set, PeerUni0, [0x02, .. SetCapacity(4096), .. Insert("a", "1"), .. Insert("b", "2")]);

        // No throw, no error, and nothing has been read yet.
        Assert.True(http3.TryProcessPeerStreams(out var early));
        Assert.Equal(0ul, early);
        Assert.Equal(0ul, http3.Table!.InsertCount);

        http3.OpenLocalStreams();
        set.TakePendingFrames();

        // The backlog is read now, and s2.2.2.3's feedback is ONE instruction for BOTH
        // insertions - s4.4.3's Increment on a 6-bit prefix, so an increment of 2 is 0x02.
        Assert.True(http3.TryProcessPeerStreams(out var later));
        Assert.Equal(0ul, later);
        Assert.Equal(2ul, http3.Table.InsertCount);
        Assert.Equal([0x02], Assert.Single(set.TakePendingFrames()).Data.ToArray());
    }

    // s2.1.2's bound comes from OUR OWN advertised SETTINGS_QPACK_BLOCKED_STREAMS and from
    // nothing else, so the capture's 100 and a narrowed 0 both flow through the same code.
    [Theory]
    [InlineData(0ul)]
    [InlineData(7ul)]
    public void TheBlockedStreamBoundIsTheValueThisEndpointAdvertised(ulong advertised)
    {
        var http3 = new TlsQuicHttp3Streams(
            new TlsQuicHttp3Spec
            {
                Settings =
                [
                    new TlsQuicHttp3Setting(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier, advertised),
                ],
            },
            Set());

        Assert.Equal(advertised, http3.BlockedStreams.MaximumBlockedStreams);
    }

    // And the SHIPPED default is the capture's, read from the spec rather than typed here.
    [Fact]
    public void TheShippedDefaultsGiveATableAndTheCapturesBlockedStreamBound()
    {
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), Set());

        Assert.NotNull(http3.Table);
        Assert.Equal(
            (int)TlsQuicHttp3Settings.Value(
                TlsQuicHttp3Spec.CaptureSettings,
                TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier)!.Value,
            http3.Table.MaximumCapacity);
        Assert.Equal(
            TlsQuicHttp3Settings.Value(
                TlsQuicHttp3Spec.CaptureSettings,
                TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier),
            http3.BlockedStreams.MaximumBlockedStreams);
    }

    // s6.2's other types are still discarded, and the peer's DECODER stream is one of them:
    // s4.4's instructions acknowledge OUR encoder's dynamic table, and this client's encoder
    // is static-only. A test that only checked "0x02 is kept" would pass against an
    // implementation that kept 0x03 too.
    [Theory]
    [InlineData(0x03)]
    [InlineData(0x01)]
    [InlineData(0x21)]
    public void EveryOtherPeerStreamTypeIsStillDiscarded(byte streamType)
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);
        http3.OpenLocalStreams();
        set.TakePendingFrames();

        // The same bytes that would drive the table if this were the encoder stream.
        Deliver(set, PeerUni0, [streamType, .. SetCapacity(4096), .. Insert("a", "1")]);

        Assert.True(http3.TryProcessPeerStreams(out var error));
        Assert.Equal(0ul, error);
        Assert.Equal(0ul, http3.Table!.InsertCount);
        Assert.Empty(set.TakePendingFrames());
    }

    // ------------------------------------------------------------------------
    // C16 helpers
    // ------------------------------------------------------------------------

    // A fresh stream layer fed `deliveries` in order on one peer stream, each at the offset
    // the previous ones left off, so a split is a real QUIC stream split and not a second call
    // to the same parser.
    private static TlsQuicQpackDynamicTable Fed(byte[][] deliveries)
    {
        var set = Set();
        var http3 = new TlsQuicHttp3Streams(new TlsQuicHttp3Spec(), set);
        http3.OpenLocalStreams();

        var offset = 0ul;
        foreach (var delivery in deliveries)
        {
            if (delivery.Length > 0)
            {
                Deliver(set, PeerUni0, delivery, offset);
                offset += (ulong)delivery.Length;
            }

            Assert.True(http3.TryProcessPeerStreams(out var error));
            Assert.Equal(0ul, error);
        }

        return Assert.IsType<TlsQuicQpackDynamicTable>(http3.Table);
    }

    // s4.3.1's Set Dynamic Table Capacity: the 001 pattern, then the capacity on a 5-bit
    // prefix.
    private static byte[] SetCapacity(int capacity)
    {
        var instruction = new byte[16];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeInteger(
            (ulong)capacity, 5, 0b0010_0000, instruction, out var written));
        return instruction[..written];
    }

    // s4.3.3's Insert With Literal Name: the 01 pattern, then the name as a 6-bit prefix
    // string literal and the value as an 8-bit prefix one.
    private static byte[] Insert(string name, string value)
    {
        var instruction = new byte[256];
        Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
            Encoding.ASCII.GetBytes(name), 6, 0b0100_0000, huffman: false,
            instruction, out var nameLength));
        Assert.True(TlsQuicQpackPrimitives.TryEncodeStringLiteral(
            Encoding.ASCII.GetBytes(value), 8, 0, huffman: false,
            instruction.AsSpan(nameLength), out var valueLength));
        return instruction[..(nameLength + valueLength)];
    }
}
