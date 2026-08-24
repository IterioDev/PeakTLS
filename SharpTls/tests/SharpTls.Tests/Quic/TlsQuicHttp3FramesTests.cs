using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task C2: RFC 9114 s7.1's Type/Length/Payload framing.
//
// ============================================================================
// THIS PARSER READS ATTACKER-CONTROLLED BYTES.
// ============================================================================
//
//   The control stream is written by the peer, so every byte TlsQuicHttp3Frames.TryRead
//   sees is a byte someone chose. A2's rule binds: a Try-shaped parser must never throw,
//   and this file's last test is the one that would catch a throw the named cases missed -
//   it walks a deterministic sweep of hostile inputs and asserts only that nothing escapes.
//
// ============================================================================
// INCOMPLETE IS NOT AN ERROR, AND THE DISTINCTION IS THE HARD PART.
// ============================================================================
//
//   s7: "unlike QUIC frames, HTTP/3 frames can span multiple packets." So a declared Length
//   longer than the bytes in hand is the ordinary case of a frame still arriving. The
//   tempting simplification - treat any overrun as H3_FRAME_ERROR - passes every test that
//   feeds it a whole frame and kills the connection the first time a real HEADERS frame
//   crosses a packet boundary, which is a defect a green suite would not find.
//
//   The one length that IS an error is one above int.MaxValue, because a
//   ReadOnlySpan<byte> cannot be that long and so no quantity of further bytes makes the
//   frame readable. That bound is derived from the platform, not chosen as a policy.
public sealed class TlsQuicHttp3FramesTests
{
    // ------------------------------------------------------------------------
    // Task C10b: s8.1's error-code values.
    // ------------------------------------------------------------------------

    // rfc9114-section8-error-handling.txt s8.1: "H3_MESSAGE_ERROR (0x010e): An HTTP message was
    // malformed and cannot be processed." rfc9114-section11.2-new-registries.txt states the
    // same number a second time in its Table 4 row, "| H3_MESSAGE_ERROR | 0x010e | Malformed |
    // Section 8.1 |". This is the one place in the repository the number is asserted, and it is
    // asserted rather than derived because a transcription error is precisely what it guards.
    // The other two members C10b added are pinned in the same place and for the same reason.
    // H3_NO_ERROR and H3_ID_ERROR were added at the request of the concurrent connection task,
    // which references them; their VALUES are still read out of the s8.1 extract here -
    // "H3_NO_ERROR (0x0100)" and "H3_ID_ERROR (0x0108)" - so a member added to unblock someone
    // else is not a member nothing checks.
    // A Fact and not a Theory: an InlineData row cannot carry an internal enum value through a
    // public test method signature, and casting each row to ulong at the call site would put
    // the enum member and its expected value in the same expression, which is not a check.
    [Fact]
    public void TheErrorCodesAddedByC10bAreTheValuesSection81States()
    {
        Assert.Equal(0x010eUL, (ulong)TlsQuicHttp3ErrorCode.H3MessageError);
        Assert.Equal(0x0100UL, (ulong)TlsQuicHttp3ErrorCode.H3NoError);
        Assert.Equal(0x0108UL, (ulong)TlsQuicHttp3ErrorCode.H3IdError);
    }

    // s8 draws a line this enum does not model and a caller must not lose: H3_NO_ERROR is an
    // s8.1 WIRE code, None is this enum's local "nothing to report" at 0x00. Conflating them
    // would put a zero into a CONNECTION_CLOSE where 0x0100 belongs.
    [Fact]
    public void NoneAndH3NoErrorAreDifferentValues() =>
        Assert.NotEqual((ulong)TlsQuicHttp3ErrorCode.None, (ulong)TlsQuicHttp3ErrorCode.H3NoError);

    // THE STRUCTURAL HALF, which a single equality cannot give. The s8 extract's own header
    // derives the range - "they run 0x0100..0x0110 inclusive, and 0x110 - 0x100 + 1 = 17
    // reconciles" - so every member except None belongs inside it, and no two members may share
    // a value. A future addition that typed 0x0210 for an s8.1 code, or reused an existing
    // number, fails here rather than on the wire.
    //
    // ONE MEMBER IS EXEMPT AND IS NAMED, NOT SKIPPED BY A PREDICATE. H3_DATAGRAM_ERROR is
    // RFC 9297 s2.1's 0x33, from a different document and outside s8.1's block entirely; it
    // shares this enum because both registries are one varint on the wire. Exempting it by
    // name means a second out-of-range member cannot arrive quietly behind it - the next one
    // has to be argued for here.
    [Fact]
    public void EveryErrorCodeExceptNoneLiesInsideSection81sContiguousRange()
    {
        var seen = new HashSet<ulong>();
        foreach (var code in Enum.GetValues<TlsQuicHttp3ErrorCode>())
        {
            if (code == TlsQuicHttp3ErrorCode.None)
            {
                continue;
            }

            if (code == TlsQuicHttp3ErrorCode.H3DatagramError)
            {
                Assert.Equal(0x33UL, (ulong)code);
                Assert.True(seen.Add((ulong)code), $"{code} duplicates another member's value");
                continue;
            }

            Assert.InRange((ulong)code, 0x0100UL, 0x0110UL);
            Assert.True(seen.Add((ulong)code), $"{code} duplicates another member's value");
        }

        // And the enum is not vacuously conforming because it is empty. Seven members carry an
        // s8.1 code today - H3_STREAM_CREATION_ERROR, H3_CLOSED_CRITICAL_STREAM,
        // H3_FRAME_UNEXPECTED, H3_FRAME_ERROR, H3_SETTINGS_ERROR, H3_MISSING_SETTINGS and
        // H3_MESSAGE_ERROR - which is a floor and not a pin, because s8.1 defines seventeen and
        // this enum carries only the ones something raises.
        Assert.True(seen.Count >= 7);
    }

    // ------------------------------------------------------------------------
    // s7.2.8's and s7.2.4.1's reserved-identifier arithmetic.
    // ------------------------------------------------------------------------

    [Theory]
    [InlineData(0UL)]
    [InlineData(1UL)]
    [InlineData(2UL)]
    [InlineData(7UL)]
    [InlineData(1000UL)]
    [InlineData(4083412220UL)]
    [InlineData(TlsQuicHttp3Frames.MaximumReservedN)]
    public void TheReservedIdentifierGeneratorSatisfiesTheFormByRecomputation(ulong n)
    {
        // C2's done-when: "the reserved-identifier generator's output satisfies
        // (id - 0x21) mod 0x1f == 0 for a range of N, checked by recomputation and not
        // against a table". The two constants are written out here rather than referenced,
        // so a mutation that changed both the generator and TlsQuicHttp3Frames.ReservedStep
        // would still fail.
        var identifier = TlsQuicHttp3Frames.ReservedIdentifier(n);

        Assert.True(identifier >= 0x21);
        Assert.Equal(0UL, (identifier - 0x21) % 0x1f);
        Assert.True(TlsQuicHttp3Frames.IsReservedIdentifier(identifier));
    }

    [Fact]
    public void TheLargestReservedIdentifierIsTheRfcsPrintedLastTerm()
    {
        // s11.2.1, s11.2.2, s11.2.3 and s11.2.4 each print the series as "0x21, 0x40, ...,
        // through 0x3ffffffffffffffe". This is that last term, and it is the check that
        // TlsQuicHttp3Frames.MaximumReservedN's division did not go one step wrong.
        Assert.Equal(
            0x3ffffffffffffffeUL,
            TlsQuicHttp3Frames.ReservedIdentifier(TlsQuicHttp3Frames.MaximumReservedN));
        Assert.Equal(0x21UL, TlsQuicHttp3Frames.ReservedIdentifier(0));
        Assert.Equal(0x40UL, TlsQuicHttp3Frames.ReservedIdentifier(1));
    }

    [Fact]
    public void AReservedIdentifierPastTheVarintRangeIsRefused()
    {
        // Local misuse rather than peer input, so this one throws. The generator is called
        // by whoever picks a GREASE value; nothing parses through it.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => TlsQuicHttp3Frames.ReservedIdentifier(TlsQuicHttp3Frames.MaximumReservedN + 1));
    }

    [Theory]
    [InlineData(0x00UL)]
    [InlineData(0x01UL)]
    [InlineData(0x11UL)] // the wrap case - see below
    [InlineData(0x1fUL)]
    [InlineData(0x20UL)]
    public void IdentifiersBelowTheReservedBaseAreNotReserved(ulong identifier)
    {
        // THE UNSIGNED-WRAP CASE, AND ONLY ONE ROW IS IT. Without the `>= ReservedBase` half,
        // `identifier - 0x21` wraps to 2^64 + identifier - 0x21. 2^64 mod 0x1f is 16, so that
        // is a multiple of 0x1f exactly when identifier + 14 == 0 (mod 31) - below 0x21 the
        // only solution is 0x11.
        //
        // The first version of this test carried 0x00, 0x01, 0x1f and 0x20 on the belief that
        // 0x00 wrapped onto the series. It does not: 0x00 lands on 14. The mutation that drops
        // the `>= ReservedBase` guard SURVIVED that version, which is what a sweep is for -
        // four plausible values, none of them the one value that mattered.
        Assert.False(TlsQuicHttp3Frames.IsReservedIdentifier(identifier));
    }

    [Theory]
    [InlineData(0x22UL)]
    [InlineData(0x3fUL)]
    [InlineData(0x41UL)]
    public void IdentifiersOffTheReservedSeriesAreNotReserved(ulong identifier)
    {
        // One either side of 0x21 and 0x40 - the series' first two terms - so an
        // off-by-one in the base or the step shows up as an acceptance here.
        Assert.False(TlsQuicHttp3Frames.IsReservedIdentifier(identifier));
    }

    // ------------------------------------------------------------------------
    // Round trips.
    // ------------------------------------------------------------------------

    [Theory]
    [InlineData(0x00UL)] // DATA, s7.2.1
    [InlineData(0x01UL)] // HEADERS, s7.2.2
    [InlineData(0x03UL)] // CANCEL_PUSH, s7.2.3
    [InlineData(0x04UL)] // SETTINGS, s7.2.4
    [InlineData(0x05UL)] // PUSH_PROMISE, s7.2.5
    [InlineData(0x07UL)] // GOAWAY, s7.2.6
    [InlineData(0x0dUL)] // MAX_PUSH_ID, s7.2.7
    [InlineData(0x21UL)] // Reserved, s7.2.8 at N = 0 - the first GREASE form
    [InlineData(0x40UL)] // Reserved, s7.2.8 at N = 1
    [InlineData(126585778853UL)] // Reserved, at the capture's own N
    public void EveryTypeInSection7sTableRoundTrips(ulong frameType)
    {
        // s11.2.1 Table 2's every non-Reserved-from-HTTP/2 row, plus three of s7.2.8's
        // reserved series. The HTTP/2-inherited rows are absent by design: they have their
        // own test, and it asserts a rejection.
        ReadOnlySpan<byte> payload = [0xde, 0xad, 0xbe, 0xef];
        var written = new List<byte>();
        TlsQuicHttp3Frames.Write(written, frameType, payload);

        var offset = 0;
        var status = TlsQuicHttp3Frames.TryRead(
            written.ToArray(), ref offset, out var read, out var readPayload, out var error);

        Assert.Equal(TlsQuicHttp3FrameReadStatus.Complete, status);
        Assert.Equal(TlsQuicHttp3ErrorCode.None, error);
        Assert.Equal(frameType, read);
        Assert.Equal(payload.ToArray(), readPayload.ToArray());
        Assert.Equal(written.Count, offset);
    }

    [Fact]
    public void AZeroLengthPayloadIsAWholeFrameAndNotAnAbsentOne()
    {
        // ZERO VERSUS ABSENT. A DATA frame with Length 0 is two bytes on the wire and is a
        // complete frame; an implementation that treated an empty payload as "nothing here
        // yet" would stall on it forever.
        var written = new List<byte>();
        TlsQuicHttp3Frames.Write(written, 0x00, []);

        var offset = 0;
        var status = TlsQuicHttp3Frames.TryRead(
            written.ToArray(), ref offset, out var read, out var payload, out var error);

        Assert.Equal([0x00, 0x00], written);
        Assert.Equal(TlsQuicHttp3FrameReadStatus.Complete, status);
        Assert.Equal(TlsQuicHttp3ErrorCode.None, error);
        Assert.Equal(0UL, read);
        Assert.Equal(0, payload.Length);
        Assert.Equal(2, offset);
    }

    [Fact]
    public void TwoFramesBackToBackAreReadInOrderFromOneBuffer()
    {
        var written = new List<byte>();
        TlsQuicHttp3Frames.Write(written, 0x04, [0x07, 0x64]);
        TlsQuicHttp3Frames.Write(written, 0x0d, [0x00]);
        var buffer = written.ToArray();

        var offset = 0;
        Assert.Equal(
            TlsQuicHttp3FrameReadStatus.Complete,
            TlsQuicHttp3Frames.TryRead(buffer, ref offset, out var first, out _, out _));
        Assert.Equal(
            TlsQuicHttp3FrameReadStatus.Complete,
            TlsQuicHttp3Frames.TryRead(buffer, ref offset, out var second, out _, out _));

        Assert.Equal(0x04UL, first);
        Assert.Equal(0x0dUL, second);
        Assert.Equal(buffer.Length, offset);
    }

    // ------------------------------------------------------------------------
    // Rejections and waits.
    // ------------------------------------------------------------------------

    [Theory]
    [InlineData(0x02UL)]
    [InlineData(0x06UL)]
    [InlineData(0x08UL)]
    [InlineData(0x09UL)]
    public void AnHttp2InheritedFrameTypeIsRejectedWithH3FrameUnexpected(ulong frameType)
    {
        // s7.2.8: "Frame types that were used in HTTP/2 where there is no corresponding
        // HTTP/3 frame have also been reserved. These frame types MUST NOT be sent, and
        // their receipt MUST be treated as a connection error of type H3_FRAME_UNEXPECTED."
        // The four values are s11.2.1 Table 2's four Reserved rows.
        var written = new List<byte>();
        TlsQuicHttp3Frames.Write(written, frameType, [0x00]);

        var offset = 0;
        var status = TlsQuicHttp3Frames.TryRead(
            written.ToArray(), ref offset, out _, out _, out var error);

        Assert.Equal(TlsQuicHttp3FrameReadStatus.Error, status);
        Assert.Equal(TlsQuicHttp3ErrorCode.H3FrameUnexpected, error);
        Assert.Equal(0, offset);
    }

    [Fact]
    public void AnHttp2InheritedTypeIsRejectedEvenWhenItsPayloadHasNotArrived()
    {
        // The type check runs BEFORE the length is honoured. Otherwise a peer sends type
        // 0x06 with Length 2^62-1 and the connection waits forever for bytes that will never
        // come, on a frame that was already illegal at its first byte.
        ReadOnlySpan<byte> bytes = [0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

        var offset = 0;
        var status = TlsQuicHttp3Frames.TryRead(bytes, ref offset, out _, out _, out var error);

        Assert.Equal(TlsQuicHttp3FrameReadStatus.Error, status);
        Assert.Equal(TlsQuicHttp3ErrorCode.H3FrameUnexpected, error);
    }

    [Fact]
    public void ALengthThatOverrunsTheBytesInHandIsIncompleteAndNotAnError()
    {
        // s7: HTTP/3 frames "can span multiple packets". This is the mutation the C2 brief
        // names on the length bound: a parser that returns Error here still passes every
        // whole-frame test in this file and kills a real connection.
        ReadOnlySpan<byte> bytes = [0x01, 0x10, 0xaa, 0xbb];

        var offset = 0;
        var status = TlsQuicHttp3Frames.TryRead(bytes, ref offset, out _, out _, out var error);

        Assert.Equal(TlsQuicHttp3FrameReadStatus.Incomplete, status);
        Assert.Equal(TlsQuicHttp3ErrorCode.None, error);
        Assert.Equal(0, offset);
    }

    [Fact]
    public void ALengthOneByteShortIsIncompleteAndTheSameLengthExactlyMetIsComplete()
    {
        // The bound itself, from both sides: 4 bytes declared with 3 present waits, and 4
        // present completes. A parser written with `<=` where it needs `<` passes the first
        // of these and fails the second by reading one byte past the buffer - or, with a
        // span, by throwing, which is the outcome A2's rule forbids outright.
        ReadOnlySpan<byte> shortBy1 = [0x01, 0x04, 0xaa, 0xbb, 0xcc];
        ReadOnlySpan<byte> exact = [0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd];

        var offset = 0;
        Assert.Equal(
            TlsQuicHttp3FrameReadStatus.Incomplete,
            TlsQuicHttp3Frames.TryRead(shortBy1, ref offset, out _, out _, out _));

        offset = 0;
        Assert.Equal(
            TlsQuicHttp3FrameReadStatus.Complete,
            TlsQuicHttp3Frames.TryRead(exact, ref offset, out _, out var payload, out _));
        Assert.Equal([0xaa, 0xbb, 0xcc, 0xdd], payload.ToArray());
        Assert.Equal(6, offset);
    }

    [Fact]
    public void ALengthAboveTheSpanMaximumIsRejectedWithH3FrameError()
    {
        // 0xc0.. is s16's 8-byte varint form; this one declares 0x3fffffffffffffff bytes of
        // payload, which no span can address. s8.1's H3_FRAME_ERROR is "a frame ... with an
        // invalid size".
        ReadOnlySpan<byte> bytes = [0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

        var offset = 0;
        var status = TlsQuicHttp3Frames.TryRead(bytes, ref offset, out _, out _, out var error);

        Assert.Equal(TlsQuicHttp3FrameReadStatus.Error, status);
        Assert.Equal(TlsQuicHttp3ErrorCode.H3FrameError, error);
        Assert.Equal(0, offset);
    }

    [Theory]
    [InlineData(new byte[0])] // nothing at all
    [InlineData(new byte[] { 0x01 })] // a type and no length
    [InlineData(new byte[] { 0x01, 0x40 })] // a length varint that stops mid-field
    [InlineData(new byte[] { 0xc0, 0x00, 0x00 })] // a TYPE varint that never ends
    public void EveryTruncationOfTheHeaderIsIncomplete(byte[] bytes)
    {
        var offset = 0;
        var status = TlsQuicHttp3Frames.TryRead(bytes, ref offset, out _, out _, out var error);

        Assert.Equal(TlsQuicHttp3FrameReadStatus.Incomplete, status);
        Assert.Equal(TlsQuicHttp3ErrorCode.None, error);
        Assert.Equal(0, offset);
    }

    [Fact]
    public void AnIncompleteReadLeavesAnOffsetThatAlreadyPointedPastEarlierFramesAlone()
    {
        // Resumability: the caller advances through a buffer, and a partial frame at the end
        // must not rewind the offset past the frames it already consumed.
        var written = new List<byte>();
        TlsQuicHttp3Frames.Write(written, 0x04, [0x07, 0x64]);
        written.Add(0x01);
        written.Add(0x10);

        var offset = 0;
        TlsQuicHttp3Frames.TryRead(written.ToArray(), ref offset, out _, out _, out _);
        var afterFirst = offset;
        var status = TlsQuicHttp3Frames.TryRead(
            written.ToArray(), ref offset, out _, out _, out _);

        Assert.Equal(TlsQuicHttp3FrameReadStatus.Incomplete, status);
        Assert.Equal(afterFirst, offset);
    }

    // ------------------------------------------------------------------------
    // s7.1's equality rule on a payload of exactly one varint.
    // ------------------------------------------------------------------------

    [Fact]
    public void ASingleVarintPayloadThatFillsItsLengthExactlyIsAccepted()
    {
        Assert.True(TlsQuicHttp3Frames.TryReadSingleVarintPayload(
            [0x40, 0x64], out var value, out var error));
        Assert.Equal(100UL, value);
        Assert.Equal(TlsQuicHttp3ErrorCode.None, error);
    }

    [Fact]
    public void TrailingBytesAfterASingleVarintPayloadAreRejectedWithH3FrameError()
    {
        // s7.1: "A frame payload that contains additional bytes after the identified fields
        // ... MUST be treated as a connection error of type H3_FRAME_ERROR", and s10.8: "An
        // implementation MUST ensure that the length of a frame exactly matches the length
        // of the fields it contains."
        //
        // THE MUTATION THIS KILLS is `cursor != payload.Length` weakened to
        // `cursor > payload.Length`, which is the bounds check a reader reaches for when
        // they read s10.8 as being about overruns. The varint below is one byte; the payload
        // is three.
        Assert.False(TlsQuicHttp3Frames.TryReadSingleVarintPayload(
            [0x00, 0xff, 0xff], out var value, out var error));
        Assert.Equal(0UL, value);
        Assert.Equal(TlsQuicHttp3ErrorCode.H3FrameError, error);
    }

    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0x40 })]
    [InlineData(new byte[] { 0xc0, 0x00 })]
    public void ASingleVarintPayloadThatStopsShortIsRejectedWithH3FrameError(byte[] payload)
    {
        // s7.1's other half: "a frame payload that terminates before the end of the
        // identified fields". H3_FRAME_ERROR and not Incomplete, because the payload's
        // extent is already fixed by the Length that got us here - there are no more bytes
        // coming for this frame.
        Assert.False(TlsQuicHttp3Frames.TryReadSingleVarintPayload(
            payload, out _, out var error));
        Assert.Equal(TlsQuicHttp3ErrorCode.H3FrameError, error);
    }

    // ------------------------------------------------------------------------
    // The sweep.
    // ------------------------------------------------------------------------

    [Fact]
    public void NoInputMakesTheFrameCodecThrow()
    {
        // Deterministic rather than random, so a failure reproduces. The seed sweeps the
        // first byte across every varint prefix and every reserved and defined type, and
        // varies the tail length so the truncation boundary is crossed in both directions.
        var failures = new List<string>();

        for (var first = 0; first < 256; first++)
        {
            for (var tail = 0; tail <= 9; tail++)
            {
                var bytes = new byte[1 + tail];
                bytes[0] = (byte)first;
                for (var i = 1; i < bytes.Length; i++)
                {
                    bytes[i] = (byte)((first * 31) + (i * 17));
                }

                try
                {
                    var offset = 0;
                    TlsQuicHttp3Frames.TryRead(bytes, ref offset, out _, out _, out _);
                    TlsQuicHttp3Frames.TryReadSingleVarintPayload(bytes, out _, out _);
                }
                catch (Exception threw)
                {
                    failures.Add($"first=0x{first:x2} tail={tail}: {threw.GetType().Name}");
                }
            }
        }

        Assert.Empty(failures);
    }
}
