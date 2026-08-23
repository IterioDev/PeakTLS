using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// STREAM frames (RFC 9000 s19.8) and CRYPTO frames (s19.6). Split from
// TlsQuicFramesTests for the same reason ACK was: STREAM alone has eight wire
// forms and both types carry validity rules of their own.
//
// CRYPTO is the one frame type in this whole phase with a published test vector -
// RFC 9001 A.2's client Initial plaintext, asserted below. Everything else here
// is hand-derived from the s19.8 Figure 32 and s19.6 Figure 30 field lists and
// the s16 variable-length integer rules, with the derivation written out above
// each test and asserted against the encoder directly, because a round-trip test
// on its own would only prove this library's encoder and decoder agree with each
// other and they could agree while both being wrong.
//
//   STREAM Frame {                      CRYPTO Frame {
//     Type (i) = 0x08..0x0f,              Type (i) = 0x06,
//     Stream ID (i),                      Offset (i),
//     [Offset (i)],                       Length (i),
//     [Length (i)],                       Crypto Data (..),
//     Stream Data (..),                 }
//   }
//
// STREAM's two bracketed fields are present exactly when the type's OFF (0x04)
// and LEN (0x02) bits are set; the third low bit, FIN (0x01), adds no field.
// CRYPTO brackets nothing - both its fields are unconditional and it has no
// flags at all, which is why it needs no eight-form treatment.
//
// Every value in these vectors is 63 or below except where noted, so it encodes
// as a single byte whose value is the value itself: s16 gives the first byte's
// two most significant bits as the log2 of the encoded length, so 0b00 means one
// byte with six value bits.
public sealed class TlsQuicStreamFramesTests
{
    // 2^62 - 1, the largest value a variable-length integer can carry, and by
    // s19.8 and s19.6 also the largest offset a stream may deliver: s16 spends
    // the first byte's two most significant bits on the length, leaving 62 value
    // bits in the 8-byte form. Not 2^64 - 1.
    private const ulong VarintMaximum = (1UL << 62) - 1;

    // The 8-byte encoding of VarintMaximum: first byte 0b11_000000 for length
    // 2^3 = 8, or'd with the top 6 value bits (all ones) = 0xff, then seven more
    // 0xff bytes of value. VarintMaximum - 1 differs only in the last byte.
    private static readonly byte[] VarintMaximumEncoded =
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

    private static readonly byte[] VarintMaximumMinusOneEncoded =
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe];

    // The payload every STREAM vector below carries, and the three field values
    // every one of them uses. Stream ID, Offset and Length are deliberately
    // three *different* small numbers: a reader or writer that emitted them in
    // the wrong order, or read Offset where Length belongs in the 0x0e/0x0f
    // forms, would still produce plausible-looking output if they were equal.
    private static readonly byte[] Payload = [0xa1, 0xa2, 0xa3];
    private const ulong StreamId = 4;
    private const ulong Offset = 8;

    // All eight of s19.8's wire forms, each derived from Figure 32 by dropping
    // the fields its type's low bits say are absent. s19.8: "The Type field in
    // the STREAM frame takes the form 0b00001XXX (or the set of values from 0x08
    // to 0x0f). The three low-order bits of the frame type determine the fields
    // that are present in the frame."
    //
    // With Stream ID = 4 (-> 0x04), Offset = 8 (-> 0x08), Length = 3 (-> 0x03,
    // the length of Stream Data = a1 a2 a3):
    //
    //   type  OFF LEN FIN   bytes
    //   0x08   -   -   -    08 04       a1 a2 a3
    //   0x09   -   -   F    09 04       a1 a2 a3
    //   0x0a   -   L   -    0a 04    03 a1 a2 a3
    //   0x0b   -   L   F    0b 04    03 a1 a2 a3
    //   0x0c   O   -   -    0c 04 08    a1 a2 a3
    //   0x0d   O   -   F    0d 04 08    a1 a2 a3
    //   0x0e   O   L   -    0e 04 08 03 a1 a2 a3
    //   0x0f   O   L   F    0f 04 08 03 a1 a2 a3
    //
    // Eight hand-derived vectors and not one vector plus seven round-trips: the
    // three bits are independent, so a bug in one field's presence logic hides
    // behind another's. Concretely, the four LEN-clear rows are the only ones
    // that can catch a writer that emits a Length field unconditionally, and the
    // four OFF-clear rows are the only ones that can catch a reader that reads an
    // Offset unconditionally - which is the mutation recorded at
    // TlsQuicStreamFrames.TryReadStream's HasOffset condition, and which fails
    // exactly those four rows.
    //
    // The FIN bit adds no field, so its four rows differ from their partners only
    // in the type byte. That is the point: FIN survives a round trip only because
    // TlsQuicFrame.RawType keeps the exact wire type, and a writer that emitted
    // (ulong)frame.Type instead would collapse all eight rows onto 0x08.
    //
    // Mutation checks (performed and reverted), with the rows of *this* test each
    // one fails; the other tests each also fails are named because several of
    // them reuse the OFF-clear and LEN-clear forms, so this test is not the sole
    // witness for those four mutations:
    //   * replacing frame.RawType with (ulong)frame.Type in
    //     TlsQuicStreamFrames.WriteStreamFrameFields' first Write call - fails
    //     the seven rows whose type is not 0x08, plus
    //     AZeroLengthStreamFrameIsLegalInBothTheExplicitAndImplicitForms,
    //     OffBitSetWithOffsetZeroIsLegalAndIsADistinctWireFormFromOffClear and
    //     WritingAStreamFrameWhoseLargestOffsetEqualsTheStreamMaximumIsAllowed.
    //   * deleting the HasOffset condition in TryReadStream (reading an Offset
    //     unconditionally) - fails the four OFF-clear rows, plus those same two
    //     other-form tests and ALenLessStreamFrameSwallowsWhateverFollowsIt.
    //   * deleting the `if (HasOffset(...))` guard around the Offset write in
    //     WriteStreamFrameFields - fails exactly the same set as the read-side
    //     one above.
    //   * deleting the `if (HasLength(...))` guard around the Length write -
    //     fails the four LEN-clear rows, plus the same three other tests.
    //   * swapping the Offset and Length writes - fails only the two rows that
    //     carry both (0x0e, 0x0f), which is the pair that exists for that
    //     mutation, plus
    //     WritingAStreamFrameWhoseLargestOffsetEqualsTheStreamMaximumIsAllowed
    //     (type 0x0e). No other test in the Quic suite fails for any of the five.
    [Theory]
    [InlineData(0x08UL, new byte[] { 0x08, 0x04, 0xa1, 0xa2, 0xa3 })]
    [InlineData(0x09UL, new byte[] { 0x09, 0x04, 0xa1, 0xa2, 0xa3 })]
    [InlineData(0x0aUL, new byte[] { 0x0a, 0x04, 0x03, 0xa1, 0xa2, 0xa3 })]
    [InlineData(0x0bUL, new byte[] { 0x0b, 0x04, 0x03, 0xa1, 0xa2, 0xa3 })]
    [InlineData(0x0cUL, new byte[] { 0x0c, 0x04, 0x08, 0xa1, 0xa2, 0xa3 })]
    [InlineData(0x0dUL, new byte[] { 0x0d, 0x04, 0x08, 0xa1, 0xa2, 0xa3 })]
    [InlineData(0x0eUL, new byte[] { 0x0e, 0x04, 0x08, 0x03, 0xa1, 0xa2, 0xa3 })]
    [InlineData(0x0fUL, new byte[] { 0x0f, 0x04, 0x08, 0x03, 0xa1, 0xa2, 0xa3 })]
    public void EachStreamFormMatchesItsHandDerivedBytes(ulong rawType, byte[] expected)
    {
        // s19.8: "When the Offset field is absent, the offset is 0." So the
        // OFF-clear rows must be written with Offset 0, not with 8 - see
        // WritingAStreamFrameWithAnOffsetButNoOffBitThrows for the frame that
        // sets one anyway.
        var hasOffset = TlsQuicStreamFrames.HasOffset(rawType);
        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            StreamId = StreamId,
            Offset = hasOffset ? Offset : 0,
            Data = Payload,
        };

        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, frame);
        Assert.Equal(expected, destination);

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(expected, ref offset, out var read, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(expected.Length, offset);

        // RawType, not Type: all eight forms have base type STREAM, so Type
        // alone cannot tell them apart and asserting only on it would let the
        // writer collapse the eight rows onto one.
        Assert.Equal(rawType, read.RawType);
        Assert.Equal(TlsQuicFrameType.Stream, read.Type);
        Assert.Equal(StreamId, read.StreamId);
        Assert.Equal(hasOffset ? Offset : 0UL, read.Offset);
        Assert.Equal(Payload, read.Data.ToArray());

        // The FIN bit has no field of its own, so this is the only assertion
        // that can observe it at all.
        Assert.Equal((rawType & 0x01) != 0, TlsQuicStreamFrames.IsFin(read.RawType));
    }

    // The three s19.8 flag helpers over all eight type values, asserted against
    // the bit values the RFC names rather than against the constants the code
    // defines: "The OFF bit (0x04)", "The LEN bit (0x02)", "The FIN bit (0x01)".
    //
    // The vectors above would catch OffsetBit and LengthBit being swapped, since
    // that changes which fields are written. FinBit adds no field, so this is
    // where IsFin's bit is pinned.
    //
    // Mutation check (performed and reverted): making IsFin read LengthBit
    // instead of FinBit - the realistic transposition, since the two constants
    // sit next to each other - fails the four rows here where the LEN and FIN
    // bits differ (0x09, 0x0a, 0x0d, 0x0e), the four rows of
    // EachStreamFormMatchesItsHandDerivedBytes that assert IsFin, and
    // CryptoMatchesItsHandDerivedBytes, which asserts a CRYPTO frame has no FIN
    // (0x06 & 0x02 is nonzero, so the mutant reports one). Nothing else in the
    // Quic suite fails.
    [Theory]
    [InlineData(0x08UL, false, false, false)]
    [InlineData(0x09UL, false, false, true)]
    [InlineData(0x0aUL, false, true, false)]
    [InlineData(0x0bUL, false, true, true)]
    [InlineData(0x0cUL, true, false, false)]
    [InlineData(0x0dUL, true, false, true)]
    [InlineData(0x0eUL, true, true, false)]
    [InlineData(0x0fUL, true, true, true)]
    public void StreamFlagHelpersReadTheThreeLowBitsOfTheType(
        ulong rawType, bool off, bool len, bool fin)
    {
        Assert.Equal(off, TlsQuicStreamFrames.HasOffset(rawType));
        Assert.Equal(len, TlsQuicStreamFrames.HasLength(rawType));
        Assert.Equal(fin, TlsQuicStreamFrames.IsFin(rawType));
    }

    // s19.8's OFF bit description gives the absent case an offset of 0, so a
    // frame with OFF set and Offset 0 and a frame with OFF clear encode the same
    // decoded fields as two *different* byte sequences. Both are legal: s12.4's
    // shortest-encoding MUST is about the frame type's varint width, not about a
    // sender's choice among the eight STREAM forms, and which form a client picks
    // is observable - which is exactly the kind of thing subsystem B later has to
    // reproduce.
    //
    //   OFF set, Offset 0:  0c 04 00 a1     (Type, Stream ID, Offset, Data)
    //   OFF clear:          08 04    a1     (Type, Stream ID, Data)
    //
    // Deleting the `if (HasOffset(...))` guard on the Offset write would make
    // these two identical, which the Assert.NotEqual below catches directly
    // rather than by inference. That mutation is verified above (it fails this
    // test among others); this test's value is that it is the one place the two
    // forms are compared *to each other*, which no round trip can do.
    [Fact]
    public void OffBitSetWithOffsetZeroIsLegalAndIsADistinctWireFormFromOffClear()
    {
        byte[] withOffBit = [0x0c, 0x04, 0x00, 0xa1];
        byte[] withoutOffBit = [0x08, 0x04, 0xa1];

        List<byte> explicitZero = [];
        TlsQuicFrames.WriteFrame(explicitZero, new TlsQuicFrame
        {
            RawType = 0x0c,
            StreamId = StreamId,
            Offset = 0,
            Data = new byte[] { 0xa1 },
        });
        Assert.Equal(withOffBit, explicitZero);

        List<byte> implicitZero = [];
        TlsQuicFrames.WriteFrame(implicitZero, new TlsQuicFrame
        {
            RawType = 0x08,
            StreamId = StreamId,
            Data = new byte[] { 0xa1 },
        });
        Assert.Equal(withoutOffBit, implicitZero);

        Assert.NotEqual<byte>(withOffBit, withoutOffBit);

        // Both decode to offset 0, and only RawType records which form arrived.
        foreach (var encoded in new[] { withOffBit, withoutOffBit })
        {
            var offset = 0;
            Assert.True(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var read, out _));
            Assert.Equal(encoded.Length, offset);
            Assert.Equal(0UL, read.Offset);
            Assert.Equal<byte>([0xa1], read.Data.ToArray());
            Assert.Equal(encoded[0], (byte)read.RawType);
        }
    }

    // A zero-length STREAM frame is legal, and s19.8 says what it means:
    // "When a Stream Data field has a length of 0, the offset in the STREAM frame
    // is the offset of the next byte that would be sent." It is legal with FIN
    // too, and s19.8's OFF bit description names that case explicitly - the
    // absent-Offset form covers "the end of a stream that includes no data".
    //
    // A zero length is *not* the same thing as an absent Length field, and the
    // two are distinguishable on the wire:
    //
    //   LEN set, Length 0, FIN clear:  0a 04 00     (three bytes)
    //   LEN clear,         FIN clear:  08 04        (two bytes)
    //   LEN set, Length 0, FIN set:    0b 04 00
    //   LEN clear,         FIN set:    09 04
    //
    // The LEN-clear rows are zero-length only because nothing follows them in the
    // payload; the LEN-set rows are zero-length no matter what follows. After
    // decoding, both have Data.Length 0 and only RawType's LEN bit separates
    // them - which is the reason TlsQuicFrame has no Length field and keeps the
    // raw type instead.
    [Theory]
    [InlineData(0x0aUL, new byte[] { 0x0a, 0x04, 0x00 })]
    [InlineData(0x08UL, new byte[] { 0x08, 0x04 })]
    [InlineData(0x0bUL, new byte[] { 0x0b, 0x04, 0x00 })]
    [InlineData(0x09UL, new byte[] { 0x09, 0x04 })]
    public void AZeroLengthStreamFrameIsLegalInBothTheExplicitAndImplicitForms(
        ulong rawType, byte[] expected)
    {
        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            StreamId = StreamId,
            Data = ReadOnlyMemory<byte>.Empty,
        };

        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, frame);
        Assert.Equal(expected, destination);

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(expected, ref offset, out var read, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(expected.Length, offset);
        Assert.Equal(rawType, read.RawType);
        Assert.Equal(0, read.Data.Length);
        Assert.Equal(0UL, read.Offset);
        Assert.Equal(TlsQuicStreamFrames.HasLength(rawType), expected.Length == 3);
    }

    // THE IMPLICIT-LENGTH TRAP, documented as a test rather than asserted as a
    // feature. s19.8's LEN bit: "If this bit is set to 0, the Length field is
    // absent and the Stream Data field extends to the end of the packet." s12.4:
    // the payload "consists of a sequence of complete frames" and "Frames always
    // fit within a single QUIC packet and cannot span multiple packets."
    //
    // Together those confine a LEN-less STREAM frame to the end of a payload: it
    // consumes every remaining byte, so nothing can follow it. The reader does
    // not enforce that separately and cannot - it enforces it structurally, by
    // advancing offset to payload.Length, after which the caller's read loop has
    // nothing left to read. There is no input on which "not last" is observable.
    //
    // The writer cannot enforce it either: WriteFrame appends one frame and knows
    // nothing of what a caller appends next, deliberately, since subsystem B owns
    // frame layout. So this test writes the mistake on purpose - a LEN-less
    // STREAM carrying one byte, then a PING - and asserts what a peer would
    // actually see: one frame, whose Stream Data is two bytes, the second of
    // which is the PING's type byte. Not two frames.
    //
    //   08 04 a1     LEN-less STREAM, Stream ID 4, data a1
    //   01           PING (s19.2), one byte, no fields
    //   -> reads as one STREAM frame with Stream Data = a1 01
    [Fact]
    public void ALenLessStreamFrameSwallowsWhateverFollowsIt()
    {
        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, new TlsQuicFrame
        {
            RawType = 0x08,
            StreamId = StreamId,
            Data = new byte[] { 0xa1 },
        });
        TlsQuicFrames.WriteFrame(
            destination, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping });

        // The writer did emit both frames, in order, unmerged - that part is
        // correct and required.
        Assert.Equal<byte>([0x08, 0x04, 0xa1, 0x01], destination);

        byte[] payload = [.. destination];
        var offset = 0;
        List<TlsQuicFrame> read = [];
        while (offset < payload.Length)
        {
            Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out _));
            read.Add(frame);
        }

        // One frame, not two: the PING is gone, absorbed as stream data.
        Assert.Single(read);
        Assert.Equal(0x08UL, read[0].RawType);
        Assert.Equal<byte>([0xa1, 0x01], read[0].Data.ToArray());
        Assert.Equal(payload.Length, offset);
    }

    // CRYPTO's own hand-derived vector, from s19.6 Figure 30. Both fields are
    // unconditional - s19.6: "they do not carry markers for optional offset,
    // optional length, and the end of the stream" - so there is one form, not
    // eight, and no Stream ID between the type and the offset.
    //
    //   Type   = 0x06
    //   Offset = 8  -> 0x08
    //   Length = 3  -> 0x03
    //   Crypto Data = a1 a2 a3
    //
    // Offset and Length are again different numbers, so a writer that emitted
    // them in Figure 30's reverse order would fail here. Note this is three
    // header bytes where the equivalent STREAM form (0x0e) has four: CRYPTO
    // carries no Stream ID.
    [Fact]
    public void CryptoMatchesItsHandDerivedBytes()
    {
        byte[] expected = [0x06, 0x08, 0x03, 0xa1, 0xa2, 0xa3];

        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Crypto,
            Offset = Offset,
            Data = Payload,
        });
        Assert.Equal(expected, destination);

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(expected, ref offset, out var read, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(expected.Length, offset);
        Assert.Equal((ulong)TlsQuicFrameType.Crypto, read.RawType);
        Assert.Equal(TlsQuicFrameType.Crypto, read.Type);
        Assert.Equal(Offset, read.Offset);
        Assert.Equal(Payload, read.Data.ToArray());

        // s19.6: "The stream does not have an explicit end, so CRYPTO frames do
        // not have a FIN bit", and CRYPTO bears no stream identifier. Neither is
        // representable in type 0x06, so both come back at their defaults.
        Assert.Equal(0UL, read.StreamId);
        Assert.False(TlsQuicStreamFrames.IsFin(read.RawType));
    }

    // THE PUBLISHED VECTOR. RFC 9001 A.2: "The client sends an Initial packet.
    // The unprotected payload of this packet contains the following CRYPTO frame,
    // plus enough PADDING frames to make a 1162-byte payload". The frame's own
    // bytes begin:
    //
    //   06 00 40 f1 01 00 00 ed ...
    //   ^  ^  ^^^^^ ^^^^^^^^^^^
    //   |  |  |     TLS ClientHello: handshake type 0x01, 3-byte length 0x0000ed
    //   |  |  Length: 0x40f1 is a 2-byte varint (first byte 0b01......), so its
    //   |  |          value is 0x40f1 & 0x3fff = 0x00f1 = 241
    //   |  Offset: one-byte varint, 0
    //   Type 0x06, CRYPTO
    //
    // So the frame is 1 + 1 + 2 + 241 = 245 bytes, which matches the RFC's own
    // arithmetic once the padding is accounted for: 1162 - 245 = 917 PADDING
    // frames, and s19.1 makes each PADDING frame a single 0x00 byte.
    //
    // Cross-check on the Length: 241 = 4 + 237, the TLS handshake header plus its
    // declared 0x0000ed = 237 body bytes, so the CRYPTO frame carries exactly one
    // whole ClientHello and nothing more.
    //
    // This is the only assertion in the phase that checks the frame layer against
    // bytes the IETF published rather than against a derivation of ours, which is
    // why it also walks the padding: reading the whole 1162-byte payload as a
    // frame sequence proves the CRYPTO frame ended where the RFC says it does,
    // not merely that its first three fields decoded to plausible numbers.
    //
    // The frame's bytes come from TlsQuicPacketProtectionTests, which already
    // held them for the AEAD vectors and extracted them mechanically from the
    // reference capture; a second transcription of 245 bytes of hex here would be
    // exactly the wire defect this phase's ground-truth rule exists to prevent.
    //
    // Mutation check (performed and reverted): passing `hasLength: false` at
    // TlsQuicStreamFrames.TryReadCrypto's TryReadData call fails this test - the
    // frame swallows its own Length field and all 917 PADDING bytes, giving a
    // length of 1160 instead of 241. It also fails every other CRYPTO test in
    // this file (CryptoMatchesItsHandDerivedBytes,
    // CryptoLargestOffsetIsBoundedAtTheStreamMaximum,
    // CryptoTruncatedInItsLengthFieldIsRejected,
    // CryptoWhoseExplicitLengthOverrunsThePayloadIsRejected and
    // WriterEmitsCryptoAndStreamInTheOrderGivenWithoutMergingOrPadding), so this
    // test is not that mutation's only witness - what it is the only witness for
    // is that 241 is the number the IETF published, rather than the number this
    // library's own writer would have produced.
    //
    // Note that CRYPTO's Offset and Length reads cannot be swapped as a mutation
    // the way STREAM's writes can: the Offset is read in TryReadCrypto and the
    // Length in the shared TryReadData, so there is no single expression pair to
    // exchange. The order is instead pinned by CryptoMatchesItsHandDerivedBytes,
    // whose Offset (8) and Length (3) differ.
    [Fact]
    public void Rfc9001AppendixA2ClientInitialCryptoFrameParsesToItsPublishedOffsetAndLength()
    {
        var payload = TlsQuicPacketProtectionTests.BuildA2Plaintext();
        Assert.Equal(TlsQuicPacketProtectionTests.A2PayloadLength, payload.Length);

        var expectedFrame = Convert.FromHexString(TlsQuicPacketProtectionTests.A2CryptoFrameHex);
        Assert.Equal(245, expectedFrame.Length);

        var offset = 0;
        Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var crypto, out var error));
        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(TlsQuicFrameType.Crypto, crypto.Type);
        Assert.Equal(0UL, crypto.Offset);
        Assert.Equal(241, crypto.Data.Length);

        // The frame ended exactly where the RFC's own byte count puts it.
        Assert.Equal(245, offset);

        // And its Crypto Data is the tail of the published frame, header
        // stripped: 4 bytes of type/offset/length, then 241 of ClientHello.
        Assert.Equal(expectedFrame[4..], crypto.Data.ToArray());

        // s19.1: PADDING is type 0x00 and "has no semantic value", one byte each.
        // 917 of them fill the payload out to 1162.
        var padding = 0;
        while (offset < payload.Length)
        {
            Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out _));
            Assert.Equal(TlsQuicFrameType.Padding, frame.Type);
            padding++;
        }
        Assert.Equal(917, padding);
        Assert.Equal(payload.Length, offset);

        // Re-encoding the decoded frame reproduces the published bytes, so the
        // writer agrees with the IETF and not merely with this library's reader.
        List<byte> rewritten = [];
        TlsQuicFrames.WriteFrame(rewritten, crypto);
        Assert.Equal(expectedFrame, rewritten);
    }

    // The plan's encoder requirement, for the two types this task adds: "the
    // encoder must accept an arbitrary ordered sequence of frames and emit them
    // in that order. No reordering, no coalescing of adjacent frames, no
    // automatic padding." Splitting a CRYPTO stream across frames and placing a
    // PING between the pieces is precisely what subsystem B needs to control, so
    // two adjacent CRYPTO frames whose offsets are contiguous must stay two
    // frames rather than being merged into one.
    //
    //   06 00 02 a1 a2     CRYPTO offset 0, length 2
    //   01                 PING
    //   06 02 01 a3        CRYPTO offset 2, length 1
    //
    // Every STREAM frame here carries an explicit length, since a LEN-less one
    // would swallow the rest - see ALenLessStreamFrameSwallowsWhateverFollowsIt.
    [Fact]
    public void WriterEmitsCryptoAndStreamInTheOrderGivenWithoutMergingOrPadding()
    {
        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Crypto,
            Offset = 0,
            Data = new byte[] { 0xa1, 0xa2 },
        });
        TlsQuicFrames.WriteFrame(
            destination, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping });
        TlsQuicFrames.WriteFrame(destination, new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Crypto,
            Offset = 2,
            Data = new byte[] { 0xa3 },
        });

        Assert.Equal<byte>([0x06, 0x00, 0x02, 0xa1, 0xa2, 0x01, 0x06, 0x02, 0x01, 0xa3], destination);

        byte[] payload = [.. destination];
        var offset = 0;
        List<TlsQuicFrameType> read = [];
        while (offset < payload.Length)
        {
            Assert.True(TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out _));
            read.Add(frame.Type);
        }

        Assert.Equal<TlsQuicFrameType>(
            [TlsQuicFrameType.Crypto, TlsQuicFrameType.Ping, TlsQuicFrameType.Crypto], read);
        Assert.Equal(payload.Length, offset);
    }

    // Truncated Stream ID or Offset - the catch around TryReadStream's own two
    // varint reads. Every row is a complete frame type followed by a field that
    // runs off the end, so TlsQuicFrames.TryReadFrame's own catch cannot fire
    // (the type byte is a complete one-byte varint in all three rows) and no
    // later check is reached at all.
    //
    //   08                 STREAM, LEN clear: Stream ID missing entirely
    //   08 40              Stream ID declares a 2-byte varint, second byte absent
    //   0c 04 40           OFF set: Stream ID 4 reads, then the Offset is truncated
    //
    // The third row is the only one that can distinguish the Offset read from the
    // Stream ID read; the first two cannot reach the Offset read at all, because
    // their types have OFF clear.
    //
    // Mutation check (performed and reverted): deleting the
    // `catch (TlsQuicTransportException)` around those two reads in
    // TlsQuicStreamFrames.TryReadStream makes all three rows fail with an
    // unhandled TlsQuicTransportException instead of a false return - a thrown
    // exception, not a quiet wrong answer, which is what the Try-shaped contract
    // forbids. Nothing else in the Quic suite fails.
    [Theory]
    [InlineData(new byte[] { 0x08 })]
    [InlineData(new byte[] { 0x08, 0x40 })]
    [InlineData(new byte[] { 0x0c, 0x04, 0x40 })]
    public void StreamTruncatedInItsHeaderFieldsIsRejected(byte[] encoded)
    {
        var offset = 0;
        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // Truncated Length - a different catch from the one above, inside
    // TryReadData. Input 0a 04 40: LEN set and OFF clear, so the Stream ID (4)
    // reads cleanly, the Offset read is skipped entirely, and 0x40 declares a
    // 2-byte varint whose second byte never arrives. Nothing but TryReadData's
    // own catch can reject this.
    //
    // Mutation check (performed and reverted): deleting that catch fails exactly
    // this test and its CRYPTO counterpart below with an unhandled
    // TlsQuicTransportException.
    [Fact]
    public void StreamTruncatedInItsLengthFieldIsRejected()
    {
        byte[] encoded = [0x0a, 0x04, 0x40];
        var offset = 0;
        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // Truncated CRYPTO Offset - TryReadCrypto's own catch, the third distinct
    // catch in this file. Row 06 has no Offset byte at all; row 06 40 has a
    // 2-byte varint prefix with the second byte absent. CRYPTO has no Stream ID
    // and no flags, so the Offset is the very first field after the type and
    // nothing earlier can reject either row.
    //
    // Mutation check (performed and reverted): deleting that catch fails both
    // rows with an unhandled TlsQuicTransportException and nothing else in the
    // Quic suite.
    [Theory]
    [InlineData(new byte[] { 0x06 })]
    [InlineData(new byte[] { 0x06, 0x40 })]
    public void CryptoTruncatedInItsOffsetIsRejected(byte[] encoded)
    {
        var offset = 0;
        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // The CRYPTO side of TryReadData's Length catch: 06 00 40 is Offset 0 read
    // cleanly, then a truncated Length. This pins the *wiring* as much as the
    // check - TryReadCrypto passes hasLength unconditionally true, and a
    // mutation to hasLength: false would make this input a legal zero-length
    // CRYPTO frame rather than a rejection.
    [Fact]
    public void CryptoTruncatedInItsLengthFieldIsRejected()
    {
        byte[] encoded = [0x06, 0x00, 0x40];
        var offset = 0;
        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // An explicit Length that reaches past the end of the payload. s12.4: "Frames
    // always fit within a single QUIC packet and cannot span multiple packets",
    // so this is malformed rather than incomplete and there is nothing to wait
    // for.
    //
    //   0a 04 04 a1 a2 a3
    //   LEN set, Stream ID 4, Length 4, but only 3 bytes of payload remain.
    //
    //   0a 04 c0 00 00 01 00 00 00 00 a1
    //   LEN set, Stream ID 4, Length as an 8-byte varint, then one byte of
    //   payload. The varint's first byte 0xc0 is 0b11...... so s16 gives it
    //   length 2^3 = 8 and six value bits; the value is the remaining 62 bits,
    //   0x00_00_01_00_00_00_00 placed at byte index 3 of 8, which weighs
    //   2^(8*(7-3)) = 2^32. So Length = 4294967296.
    //
    //   That byte position is the whole point of the row and it is easy to get
    //   wrong: this vector originally put the 0x01 one byte later, which encodes
    //   2^24 rather than 2^32, and 2^24 survives the very mutation the row exists
    //   to kill. The low 32 bits of 2^32 are all zero, so a bound written as
    //   `walked + (int)declared > payload.Length` truncates the declared length
    //   to 0, finds 0 in bounds, and accepts the frame with empty Stream Data -
    //   whereas the low 32 bits of 2^24 are 2^24, which such a check still
    //   rejects. The check compares as ulong precisely so neither can happen.
    //
    // Both rows have Offset 0 (OFF clear), so the largest-offset bound below
    // cannot be what rejects them; both are complete varints, so no catch can.
    //
    // Mutation checks (performed and reverted): deleting the
    // `declared > remaining` comparison in TlsQuicStreamFrames.TryReadData fails
    // both rows here and the CRYPTO row below - the first row then throws
    // ArgumentOutOfRangeException out of Memory.Slice, which is itself a
    // Try-contract violation. Replacing it with the int-truncating form above
    // fails only the second row, and only with the 0x01 at index 3.
    [Theory]
    [InlineData(new byte[] { 0x0a, 0x04, 0x04, 0xa1, 0xa2, 0xa3 })]
    [InlineData(new byte[] { 0x0a, 0x04, 0xc0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa1 })]
    public void StreamWhoseExplicitLengthOverrunsThePayloadIsRejected(byte[] encoded)
    {
        var offset = 0;
        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out var frame, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(0, frame.Data.Length);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // The CRYPTO half of the same bound, reached through the other caller of
    // TryReadData: 06 00 04 a1 a2 a3 is Offset 0, Length 4, three bytes left.
    [Fact]
    public void CryptoWhoseExplicitLengthOverrunsThePayloadIsRejected()
    {
        byte[] encoded = [0x06, 0x00, 0x04, 0xa1, 0xa2, 0xa3];
        var offset = 0;
        Assert.False(TlsQuicFrames.TryReadFrame(encoded, ref offset, out _, out var error));
        Assert.Equal(0, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
    }

    // s19.8: "The largest offset delivered on a stream -- the sum of the offset
    // and data length -- cannot exceed 2^62-1, as it is not possible to provide
    // flow control credit for that data. Receipt of a frame that exceeds this
    // limit MUST be treated as a connection error of type FRAME_ENCODING_ERROR or
    // FLOW_CONTROL_ERROR." Read side, OFF always set so the Offset is explicit.
    //
    // The check has TWO reachable paths, because the data length reaching it comes
    // from a different place in each: with LEN set it is the decoded Length field,
    // and with LEN clear it is `payload.Length - walked`, the implicit remainder.
    // Both are covered, type 0x0e for the first and 0x0c for the second:
    //
    //   0e 04 <offset, 8 bytes> <length> [data]      explicit Length
    //   0c 04 <offset, 8 bytes>          [data]      implicit, runs to the end
    //
    //   type  offset   data  sum       outcome
    //   0x0e  2^62-1   1     2^62      rejected
    //   0x0e  2^62-2   1     2^62-1    accepted
    //   0x0e  2^62-1   0     2^62-1    accepted
    //   0x0c  2^62-1   1     2^62      rejected
    //   0x0c  2^62-2   1     2^62-1    accepted
    //   0x0c  2^62-1   0     2^62-1    accepted
    //
    // The 0x0c rows were added after review found the LEN-clear path unwitnessed:
    // conditioning the check on `hasLength` survived the whole suite, because the
    // three original rows were all type 0x0e. They are an addition - the 0x0e rows
    // keep the exact bytes they had, since moving them would have un-pinned
    // whatever they were the sole witness for.
    //
    // "Cannot exceed" makes equality legal, so the accepted rows are what pins the
    // comparison as `>` and not `>=` - a rejection-only test would pass under a
    // too-strict check. The zero-length rows matter separately from the 2^62-2
    // rows: a check written against the offset alone (`frameOffset >=
    // MaximumValue`) would reject them. For 0x0c a zero data length means the
    // frame ends exactly at the payload's end with no bytes left over, which is
    // the implicit form's own boundary.
    //
    // Nothing else can decide these rows: every varint is complete, every explicit
    // Length is within the remaining payload, and the Stream ID is 4.
    //
    // Mutation checks (performed and reverted), all in
    // TlsQuicStreamFrames.TryReadData:
    //   * deleting the largest-offset comparison - fails both rejecting rows here
    //     and the rejecting row of the CRYPTO test. It also fails
    //     TryReadStreamCommitsNothingWhenTheOffsetBoundRejects and its CRYPTO
    //     counterpart, which use this bound as their rejection trigger and so are
    //     not independent of it; they witness the sub-readers' Try-shape, not this
    //     bound. Five rows in all, and nothing else in the Quic suite.
    //   * weakening it to `>=` - fails all four accepting rows here and both of
    //     the CRYPTO test's, six rows, and nothing else.
    //   * guarding it as `if (hasLength && frameOffset > ...)` - fails only the
    //     0x0c rejecting row, here and nowhere else. That is the mutation the
    //     0x0c rows exist for; before them it survived the entire suite.
    [Theory]
    [InlineData(0x0eUL, true, 1, false)]
    [InlineData(0x0eUL, false, 1, true)]
    [InlineData(0x0eUL, true, 0, true)]
    [InlineData(0x0cUL, true, 1, false)]
    [InlineData(0x0cUL, false, 1, true)]
    [InlineData(0x0cUL, true, 0, true)]
    public void StreamLargestOffsetIsBoundedAtTheStreamMaximum(
        ulong rawType, bool offsetAtMaximum, int dataLength, bool accepted)
    {
        var offsetBytes = offsetAtMaximum ? VarintMaximumEncoded : VarintMaximumMinusOneEncoded;
        List<byte> encoded = [(byte)rawType, 0x04, .. offsetBytes];

        // s19.8: the Length field is present only when the LEN bit is set. For
        // 0x0c there is no Length byte at all and the data is whatever remains,
        // which is what puts the implicit branch of the bound under test.
        if (TlsQuicStreamFrames.HasLength(rawType))
        {
            encoded.Add((byte)dataLength);
        }

        for (var index = 0; index < dataLength; index++)
        {
            encoded.Add(0xa1);
        }

        byte[] payload = [.. encoded];
        var offset = 0;
        var read = TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out var error);

        Assert.Equal(accepted, read);
        if (!accepted)
        {
            Assert.Equal(0, offset);
            Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
            return;
        }

        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(payload.Length, offset);
        Assert.Equal(offsetAtMaximum ? VarintMaximum : VarintMaximum - 1, frame.Offset);
        Assert.Equal(dataLength, frame.Data.Length);
    }

    // The CRYPTO half of the same bound. s19.6 carries the identical sentence,
    // offering FRAME_ENCODING_ERROR or CRYPTO_BUFFER_EXCEEDED; this reader
    // reports FRAME_ENCODING_ERROR, the alternative common to both sections and
    // the only one it can justify without connection state - see the quote block
    // at TlsQuicStreamFrames.TryReadData.
    //
    //   06 <offset, 8 bytes> <length> [data]
    [Theory]
    [InlineData(true, 1, false)]
    [InlineData(false, 1, true)]
    [InlineData(true, 0, true)]
    public void CryptoLargestOffsetIsBoundedAtTheStreamMaximum(
        bool offsetAtMaximum, int dataLength, bool accepted)
    {
        var offsetBytes = offsetAtMaximum ? VarintMaximumEncoded : VarintMaximumMinusOneEncoded;
        List<byte> encoded = [0x06, .. offsetBytes, (byte)dataLength];
        for (var index = 0; index < dataLength; index++)
        {
            encoded.Add(0xa1);
        }

        byte[] payload = [.. encoded];
        var offset = 0;
        var read = TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out var error);

        Assert.Equal(accepted, read);
        if (!accepted)
        {
            Assert.Equal(0, offset);
            Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
            return;
        }

        Assert.Equal(TlsQuicTransportError.NoError, error);
        Assert.Equal(payload.Length, offset);
        Assert.Equal(offsetAtMaximum ? VarintMaximum : VarintMaximum - 1, frame.Offset);
    }

    // Write side. s19.8: "When the Offset field is absent, the offset is 0." A
    // frame whose OFF bit is clear but whose Offset is not 0 asks for something
    // no STREAM form can express, and the failure without this check is silent -
    // the offset is simply not written, the peer reads the data at offset 0, and
    // nothing on the wire records what the caller meant.
    //
    // All four OFF-clear types, not just 0x08: a check written as
    // `RawType == 0x08` would let 0x09, 0x0a and 0x0b through, and the LEN and
    // FIN bits have nothing to do with whether an Offset is present.
    //
    // Offset 5 is small and the data is one byte, so the largest-offset bound
    // cannot fire, and the Stream ID is 0, so its varint bound cannot either.
    // Note that this check and RequireLargestOffsetInRange both throw
    // ArgumentException with ParamName "frame", so ParamName does *not*
    // distinguish them - the input is what isolates this one, which is why the
    // Offset here is 5 rather than something near the maximum.
    //
    // `destination` is seeded with a sentinel and asserted to stay alone, not
    // merely that something threw: this check sits above four Write calls, and
    // moved below even the first of them the exception type would be unchanged
    // while a stray type byte reached the caller's buffer.
    //
    // Mutation checks (performed and reverted), each failing all four rows here
    // and nothing else in the Quic suite:
    //   * deleting the check - Assert.Throws fails outright, because no exception
    //     is raised at all: a perfectly well-formed frame goes out with the
    //     caller's offset silently dropped.
    //   * moving the check below the RawType write, leaving the check itself
    //     intact - fails on the *destination* assertion only, with the exception
    //     type and ParamName both unchanged: observed
    //     "Expected: [170] / Actual: [170, 11]" and so on for each row. This is
    //     the standing-rule case in the plan; without the sentinel assertion this
    //     mutation would have survived a green suite.
    [Theory]
    [InlineData(0x08UL)]
    [InlineData(0x09UL)]
    [InlineData(0x0aUL)]
    [InlineData(0x0bUL)]
    public void WritingAStreamFrameWithAnOffsetButNoOffBitThrows(ulong rawType)
    {
        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            Offset = 5,
            Data = new byte[] { 0xa1 },
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("frame", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // s2.1 makes a stream ID a variable-length integer, so 2^62-1 is the largest
    // there is (s16 leaves 62 value bits) and 2^62 has no encoding. Checked in
    // TlsQuicStreamFrames.WriteStreamFrameFields rather than left to
    // QuicVariableLengthInteger.Write, which would raise
    // ArgumentOutOfRangeException *after* the frame type byte was already in the
    // caller's buffer - hence the sentinel assertion, which is the half of this
    // test that catches a bound moved below the writes.
    //
    // Both rows have OFF clear with Offset 0, so the OFF/Offset check above cannot
    // fire, and empty data, so the largest-offset bound cannot either. Only the
    // Stream ID bound can reject either frame.
    //
    // Two rows, 0x0a (LEN set) and 0x08 (LEN clear), for the reason review found
    // in the read-side offset bound: the check is one unconditional call, and the
    // cheapest way to break it is to condition it on a type bit. With only the
    // 0x0a row, `if (HasLength(frame.RawType)) RequireEncodableVarint(...)`
    // survived; the 0x08 row is what kills it. The 0x0a row is unchanged.
    //
    // The ParamName is "streamId", a string literal in
    // TlsQuicStreamFrames.RequireEncodableVarint rather than nameof()-derived -
    // there is no parameter of that name on the method that passes it - so
    // renaming TlsQuicFrame.StreamId will not update it and this assertion will
    // not fail if it goes stale.
    //
    // Mutation checks (performed and reverted), neither failing anything else in
    // the Quic suite:
    //   * deleting the RequireEncodableVarint call - fails both rows with
    //     ArgumentOutOfRangeException (a different type, from
    //     QuicVariableLengthInteger, naming a parameter "value" this namespace
    //     does not have) and with the type byte already in the destination, which
    //     is why Assert.Throws' exact-type match and the sentinel both matter.
    //   * conditioning the call on HasLength - fails only the 0x08 row.
    [Theory]
    [InlineData(0x0aUL)]
    [InlineData(0x08UL)]
    public void WritingAStreamFrameWhoseStreamIdExceedsTheVarintMaximumThrows(ulong rawType)
    {
        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            StreamId = VarintMaximum + 1,
            Data = ReadOnlyMemory<byte>.Empty,
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("streamId", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The write side of s19.8's largest-offset bound, and THE OVERFLOW ROW.
    //
    // On the read path both operands are small enough that a sum cannot wrap: the
    // offset came from a varint so it is at most 2^62-1, and the length is an int.
    // Here frame.Offset is whatever the caller put on the struct - any ulong - so
    // `frame.Offset + (ulong)frame.Data.Length` **wraps**:
    //
    //   Offset = 2^62-1        + 1 byte = 2^62           -> exceeds, no wrap
    //   Offset = 2^64-1        + 1 byte = 0              -> WRAPS to zero
    //
    // The second row is the one that only the pre-combination form catches. A
    // check written as `frame.Offset + (ulong)frame.Data.Length > MaximumValue`
    // computes 0 for it, finds 0 well within range, and writes an eight-byte
    // varint of... nothing: QuicVariableLengthInteger.Write would then reject
    // 2^64-1 itself with ArgumentOutOfRangeException, after the type and stream
    // ID bytes were already in the caller's buffer. Same defect class as the ACK
    // range underflow this phase already had to fix - check before you combine.
    //
    // OFF is set in every row, so the OFF/Offset check above cannot fire, and the
    // Stream ID is 0, so its bound cannot either. In fact OFF *must* be set for
    // this check to be reachable with a nonzero Offset at all: the four OFF-clear
    // forms are rejected by the OFF/Offset check first, so 0x0c..0x0f are the only
    // forms that can reach here.
    //
    // Both LEN states are covered - 0x0e (LEN set) and 0x0c (LEN clear) - for the
    // same reason as the read-side bound: with only 0x0e rows, conditioning the
    // call on `HasLength(frame.RawType)` survived. The 0x0e rows are unchanged.
    //
    // Mutation checks (performed and reverted), all in
    // TlsQuicStreamFrames.RequireLargestOffsetInRange or its STREAM call site, and
    // none failing anything in the Quic suite beyond the tests named:
    //   * deleting the comparison - fails every row here and every row of the
    //     CRYPTO test below.
    //   * replacing it with the naive `frame.Offset + (ulong)frame.Data.Length >
    //     MaximumValue` - fails only the two one-byte 2^64-1 rows here and the
    //     CRYPTO test's one. The 2^62-1 rows pass either way, and so does the
    //     emptyData row (with a zero length there is nothing to wrap), so the
    //     one-byte ulong.MaxValue rows are its only witnesses.
    //   * conditioning the STREAM call site on HasLength - fails only the two
    //     0x0c rows.
    //   * guarding it as `if (frame.Data.Length > 0 && ...)` - fails only the
    //     emptyData row, here and in the CRYPTO test. See below for why that row
    //     exists and why the naive-sum mutation cannot be what catches it.
    //   * weakening it to `>=` - fails none of these rows. It is caught only by
    //     WritingAStreamFrameWhoseLargestOffsetEqualsTheStreamMaximumIsAllowed
    //     below, which is the sole witness for that direction.
    //
    // THE EMPTY-DATA ROW. With no data the guard degenerates to `frame.Offset >
    // MaximumValue`, which is exactly the offset-encodability check
    // RequireLargestOffsetInRange's own comment claims it subsumes - so that claim
    // had nothing behind it while every row carried a byte of data, and
    // conditioning the guard on a nonempty Data survived the whole suite. Under
    // that mutation an unencodable Offset reaches
    // QuicVariableLengthInteger.Write, which raises ArgumentOutOfRangeException -
    // the wrong exception type, naming a parameter "value" this namespace does not
    // have - with the type byte already in the caller's buffer. Both of the defects
    // the exact-type match and the sentinel exist to catch.
    //
    // The row must use ulong.MaxValue and not VarintMaximum: with empty data,
    // offset 2^62-1 gives a largest offset of exactly 2^62-1, which "cannot exceed
    // 2^62-1" *allows*, so that combination is legal and belongs to the
    // ...EqualsTheStreamMaximumIsAllowed test's territory, not here. Note also
    // that the naive sum-then-compare mutation is NOT what this row catches - with
    // a zero length there is nothing to wrap, so `Offset + 0 > MaximumValue` still
    // rejects ulong.MaxValue correctly. The one-byte rows remain the sole witness
    // for that one; this row and those rows are not substitutes.
    //
    // The four existing rows keep their exact inputs - a byte of data and the two
    // offsets - per the add-a-row rule.
    [Theory]
    [InlineData(0x0eUL, VarintMaximum, false)]
    [InlineData(0x0eUL, ulong.MaxValue, false)]
    [InlineData(0x0cUL, VarintMaximum, false)]
    [InlineData(0x0cUL, ulong.MaxValue, false)]
    [InlineData(0x0eUL, ulong.MaxValue, true)]
    public void WritingAStreamFrameWhoseLargestOffsetExceedsTheStreamMaximumThrows(
        ulong rawType, ulong frameOffset, bool emptyData)
    {
        var frame = new TlsQuicFrame
        {
            RawType = rawType,
            Offset = frameOffset,
            Data = emptyData ? ReadOnlyMemory<byte>.Empty : new byte[] { 0xa1 },
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("frame", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The CRYPTO half, pinning the second call site of
    // RequireLargestOffsetInRange separately - deleting only that call would
    // leave the STREAM test above green.
    //
    // The emptyData row is here for the same reason as the STREAM one: the shared
    // guard is one expression, so `if (frame.Data.Length > 0 && ...)` has to die on
    // both call sites, and this is the row that kills it here. CRYPTO has no LEN
    // bit, so there is no flag axis to cover on this side - the data length is the
    // only thing that branches the guard, which is exactly why it was the axis left
    // uncovered. The two existing rows keep their exact inputs.
    [Theory]
    [InlineData(VarintMaximum, false)]
    [InlineData(ulong.MaxValue, false)]
    [InlineData(ulong.MaxValue, true)]
    public void WritingACryptoFrameWhoseLargestOffsetExceedsTheStreamMaximumThrows(
        ulong frameOffset, bool emptyData)
    {
        var frame = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Crypto,
            Offset = frameOffset,
            Data = emptyData ? ReadOnlyMemory<byte>.Empty : new byte[] { 0xa1 },
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("frame", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The legal edge of the same bound, so the check is pinned from both sides on
    // the write path as well as the read path: offset 2^62-2 plus one byte of data
    // is a largest offset of exactly 2^62-1, which "cannot exceed 2^62-1" allows.
    //
    //   0e ff ff ff ff ff ff ff fe 01 a1
    //   Type 0x0e, Stream ID 0, Offset 2^62-2 as an 8-byte varint, Length 1, data.
    //
    // Deleting nothing makes this fail; a `>=` in RequireLargestOffsetInRange
    // does. Without this test that mutation would survive - the rejection tests
    // above pass under a too-strict bound.
    [Fact]
    public void WritingAStreamFrameWhoseLargestOffsetEqualsTheStreamMaximumIsAllowed()
    {
        var frame = new TlsQuicFrame
        {
            RawType = 0x0e,
            StreamId = 0,
            Offset = VarintMaximum - 1,
            Data = new byte[] { 0xa1 },
        };

        List<byte> destination = [];
        TlsQuicFrames.WriteFrame(destination, frame);
        Assert.Equal<byte>(
            [0x0e, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x01, 0xa1], destination);
    }

    // s19.6: CRYPTO frames "do not bear a stream identifier", and "the CRYPTO
    // frame carries data for a single stream per encryption level". Figure 30 has
    // no Stream ID field, so a caller that set one asked for something the frame
    // cannot express and writing anyway would drop it silently - the same defect
    // class as the OFF/Offset contradiction, and the same reason
    // TlsQuicAckFrames.WriteFrameFields rejects a type 0x02 ACK carrying ECN
    // counts rather than dropping them.
    //
    // Offset 0 and one byte of data, so the largest-offset bound cannot fire;
    // only the Stream ID check can reject this frame. Sentinel asserted, since
    // this check sits above three Write calls.
    //
    // Mutation check (performed and reverted): deleting the check makes this test
    // fail because no exception is thrown at all - a valid CRYPTO frame
    // [0xaa, 0x06, 0x00, 0x01, 0xa1] is written, silently missing the stream the
    // caller named. Nothing else in the Quic suite fails.
    [Fact]
    public void WritingACryptoFrameWithAStreamIdThrows()
    {
        var frame = new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.Crypto,
            StreamId = StreamId,
            Offset = 0,
            Data = new byte[] { 0xa1 },
        };
        List<byte> destination = [0xaa];

        var exception = Assert.Throws<ArgumentException>(
            () => TlsQuicFrames.WriteFrame(destination, frame));
        Assert.Equal("frame", exception.ParamName);
        Assert.Equal<byte>([0xaa], destination);
    }

    // The two sub-readers' own Try-shaped contract, called directly rather than
    // through TlsQuicFrames.TryReadFrame. This is deliberately the one place in
    // this file that does not go through the public entry point, and it exists
    // because the promise is otherwise unobservable: TryReadFrame publishes its
    // `offset` only on success and leaves `frame` at default on failure, so a
    // sub-reader that advanced its caller's cursor or populated its `frame` on the
    // way out would be invisible from outside. Review found the comments claiming
    // that promise had nothing pinning them, and this is the pin.
    //
    // Both rows use a frame the largest-offset bound rejects - the last check
    // either reader runs, so the most bytes have already been walked past when it
    // fires and there is the most for a leak to expose. The Stream ID and Offset
    // are read, the Length is read, and the failure still commits nothing.
    //
    //   STREAM: 0e 04 ff ff ff ff ff ff ff ff 01 a1   offset 2^62-1, length 1
    //   CRYPTO: 06    ff ff ff ff ff ff ff ff 01 a1   offset 2^62-1, length 1
    //
    // `offset` starts at 1 rather than 0, past the frame type, because that is
    // where TryReadFrame leaves it - and starting at a nonzero value is what makes
    // "exactly as passed in" distinguishable from "reset to zero".
    //
    // Mutation checks (performed and reverted), each failing only its own row here
    // and nothing else in the Quic suite: adding `offset = walked;` before the
    // `return false;` on the TryReadData failure path of TryReadStream, and the
    // same in TryReadCrypto.
    //
    // Note what this does NOT reach: the private TryReadData's own identical
    // promise. Its `offset` is a local of whichever sub-reader called it, and
    // neither publishes that local on the failure path, so no test can observe
    // whether TryReadData left it alone. That comment is marked as
    // defence-in-depth rather than pinned - see TryReadData's own remark.
    [Fact]
    public void TryReadStreamCommitsNothingWhenTheOffsetBoundRejects()
    {
        byte[] payload = [0x0e, 0x04, .. VarintMaximumEncoded, 0x01, 0xa1];
        var offset = 1;

        Assert.False(TlsQuicStreamFrames.TryReadStream(
            payload, ref offset, 0x0e, out var frame, out var error));
        Assert.Equal(1, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(default, frame.StreamId);
        Assert.Equal(default, frame.Offset);
        Assert.Equal(0, frame.Data.Length);
    }

    [Fact]
    public void TryReadCryptoCommitsNothingWhenTheOffsetBoundRejects()
    {
        byte[] payload = [0x06, .. VarintMaximumEncoded, 0x01, 0xa1];
        var offset = 1;

        Assert.False(TlsQuicStreamFrames.TryReadCrypto(
            payload, ref offset, out var frame, out var error));
        Assert.Equal(1, offset);
        Assert.Equal(TlsQuicTransportError.FrameEncodingError, error);
        Assert.Equal(default, frame.RawType);
        Assert.Equal(default, frame.Offset);
        Assert.Equal(0, frame.Data.Length);
    }
}
