namespace SharpTls.Quic;

// ============================================================================
// THE MUTATION LEDGER
// ============================================================================
//
//   ROWS BELOW                   14  = numbered 1-14 with no gaps
//   KILLED WHEN FIRST RUN        13  = 14 rows, less 0 [WAS-SURVIVOR] and 1 [SURVIVED]
//   SURVIVED, THEN FIXED OR       0  = none
//     WITNESSED
//   SURVIVING STILL               1  = row 12, classified below
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry
// the markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' TlsQuicQpackPrimitives.cs`                  must return 14
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicQpackPrimitives.cs` must return 0
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' TlsQuicQpackPrimitives.cs`     must return 1
//
// Every row was run against task C5's gate, in a `git worktree`, one edit at a time, each
// restored before the next. Counts are per xUnit CASE, so a Theory that fails in three
// rows counts 3.
//
//    1. `TryEncodeInteger`: `value < mask` -> `value <= mask`.
//       THE PREFIX-FILL BOUNDARY the task names. RFC 7541 s5.1 says the value goes in
//       the prefix only if it is "strictly less than 2^N-1", so 2^N-1 itself must spill
//       into a continuation octet that encodes 0. The mutant encodes 31-at-5-bits as the
//       single byte 0x1F, which on the wire is the *start* of thirty-one-or-more.
//       Killed by TlsQuicQpackPrimitivesTests.AValueThatExactlyFillsThePrefixSpillsInto
//       AZeroContinuationOctet, in 12 cases.
//       THE FIRST VERSION OF THIS ROW ALSO CLAIMED C.1.2 KILLED IT, AND THAT WAS WRONG. The
//       sweep reads the failing tests out of the run, and C.1.2 was not among them: 1337 is
//       far above a 5-bit prefix 31, so `value <= mask` is false either way and the published
//       vector never reaches the boundary at all. C.1.2 kills row 2, the decoder half, where
//       reading 0x1F as a complete 31 does break it.
//    2. `TryDecodeInteger`: `result < mask` -> `result <= mask`.
//       The same boundary read back: the mutant stops at 0x1F and reports 31 without
//       consuming the continuation octet, so `consumed` is 1 where it must be 2.
//       Killed by TlsQuicQpackPrimitivesTests.AValueThatExactlyFillsThePrefixSpillsInto
//       AZeroContinuationOctet.
//    3. `TryDecodeInteger`: delete the `shift >= 63` guard.
//       THE CONTINUATION CHAIN THAT NEVER ENDS. Without it `MaximumInteger >> shift` runs
//       with shift >= 64, which C# masks to `shift & 63`, so the value bound on row 4
//       silently compares against the wrong number and a long 0x80 run is accepted.
//       Killed by TlsQuicQpackPrimitivesTests.AContinuationChainLongerThanSixtyTwoBitsIs
//       RejectedWithoutAThrow.
//    4. `TryDecodeInteger`: delete the `chunk > (MaximumInteger >> shift)` guard.
//       The single-octet value bound. Constructed so only this can reject: the chain is
//       short enough that row 3 is not reached, and the running total is small enough
//       that row 5 is not reached - only the last chunk is too wide for what is left.
//       Killed by TlsQuicQpackPrimitivesTests.AFinalContinuationOctetWiderThanTheRemaining
//       BitsIsRejected.
//    5. `TryDecodeInteger`: delete the `result > MaximumInteger - addend` guard.
//       The SUM bound, a different failure from row 4: every individual chunk fits and the
//       chain is short enough, but the prefix plus the chunks crosses 2^62.
//       Killed by TlsQuicQpackPrimitivesTests.AnIntegerOneAboveTheSixtyTwoBitCeilingIs
//       Rejected.
//    6. `TryDecodeInteger`: `index >= source.Length` -> `index > source.Length`.
//       The truncation guard on the continuation loop; the mutant indexes one past the
//       end. Killed by TlsQuicQpackPrimitivesTests.ATruncatedContinuationChainIsRejected
//       WithoutAThrow.
//    7. `TryDecodeInteger`: `source.IsEmpty` -> `false`.
//       The truncation guard on the prefix octet itself - the zero-versus-absent case, an
//       integer of 0 being one octet and an absent one being none.
//       Killed by TlsQuicQpackPrimitivesTests.AnEmptyBufferIsRejectedRatherThanReadAsZero.
//    8. `TryDecodeStringLiteral`: `length > remaining` -> `length >= remaining`.
//       Off by one on the overrun check, which then rejects a literal whose declared
//       length exactly fits. The zero-length literal is the sharp end: 0 >= 0 rejects it.
//       Killed by TlsQuicQpackPrimitivesTests.AZeroLengthStringLiteralDecodesToAnEmpty
//       SpanRatherThanBeingAbsent.
//    9. `TryDecodeStringLiteral`: delete the `length > remaining` check.
//       THE LENGTH THAT OVERRUNS. Without it the Slice throws instead of returning false,
//       which is the whole no-throw contract.
//       Killed by TlsQuicQpackPrimitivesTests.AStringLiteralWhoseDeclaredLengthOverruns
//       TheBufferIsRejectedWithoutAThrow.
//   10. `TryDecodeStringLiteral`: `1u << (prefixBits - 1)` -> `1u << prefixBits`.
//       The Huffman flag's BIT POSITION under RFC 9204 s4.1.2's N-bit prefix string
//       literal, where H is the top bit of the N-bit window and not of the octet. At
//       N = 8 the two coincide, so a test that only covers N = 8 witnesses nothing here.
//       Killed by TlsQuicQpackPrimitivesTests.TheHuffmanFlagSitsAtTheTopOfTheNBitWindow.
//   11. `TryEncodeStringLiteral`: the same edit on the encoding side.
//       Killed by the same named test, which asserts hand-derived header octets at three
//       prefix widths rather than round-tripping the encoder against the decoder.
//   12. `TryEncodeInteger`: delete the `(precedingBits & mask) != 0` throw. [SURVIVED]
//       VACUOUS, AND DELIBERATELY UNWITNESSED. It guards a CALLER error, not wire input:
//       every call site passes a `precedingBits` whose low bits are already clear, so no
//       test reaches it without being written to reach it, and a test written to reach it
//       asserts only that a programming mistake throws - which is the check restating
//       itself. Per A2's rule the honest record is a survivor with a reason, not a test
//       that would also pass against the mutant on every input the wire can carry.
//   13. `TryEncodeInteger`: `destination.Length < length` -> `destination.Length < 1`.
//       The encoder's overrun bound, weakened to the shape it had before the scratch
//       buffer went in. The mutant admits a one-octet destination for a multi-octet value
//       and the CopyTo then throws - which is the same defect as writing part of a chain
//       into a buffer that cannot hold it, just louder.
//       Killed by TlsQuicQpackPrimitivesTests.AnEncodeIntoATooSmallBufferReturnsFalseAnd
//       LeavesTheBufferUntouched.
//   14. `GetIntegerEncodedLength`: `value < mask` -> `value <= mask`.
//       The same prefix-fill boundary a third time, in the sizing helper. It is a SEPARATE
//       row because the helper is the independent computation the encoder's `written` is
//       checked against - if both carried the bug the check would agree and prove nothing.
//       Killed by TlsQuicQpackPrimitivesTests.TheSizingHelperAgreesWithWhatTheEncoder
//       ActuallyWrote.
//
// ============================================================================

// RFC 7541 s5.1's prefixed integer and s5.2's string literal, which RFC 9204 s4.1.1 and
// s4.1.2 adopt by name - "The format from [RFC7541] is used unmodified" and "The string
// literal defined by Section 5.2 of [RFC7541] is also used throughout". See
// reference-captures/rfc7541-section5-primitive-type-representations.txt and
// reference-captures/rfc9204-section4.1-4.2-primitives-and-streams.txt.
//
// THESE ARE NOT QUIC VARINTS AND MUST NOT BE ROUTED THROUGH QuicVariableLengthInteger.
// That codec is RFC 9000 s16's two-bit-length-prefix form; this one is a bit-width
// parameter N plus a 7-bit continuation chain. The two agree on no value wider than a
// nibble, and they share only the 2^62-1 ceiling - which even so arrives here from a
// different sentence, RFC 9204 s4.1.1's "QPACK implementations MUST be able to decode
// integers up to and including 62 bits long", not RFC 9000's Table 4.
//
// ON THE SPLIT WITH TlsQuicQpackHuffman. s5.2 makes H a one-bit field of the string
// literal header; it does not make the Huffman codec part of the literal. So
// TryEncodeStringLiteral writes whatever H it is told to and copies `data` verbatim - a
// caller passing H = 1 has already Huffman-encoded `data`, and RFC 9204 s4.1.2's "the
// indicated length is the size of the string after encoding" is why that is the right way
// round. TryDecodeStringLiteral likewise hands back the raw slice and the flag and leaves
// the Huffman decode to the caller.
internal enum TlsQuicQpackError
{
    None = 0,

    // The buffer ended inside a field: no prefix octet at all, a continuation chain that
    // stops before its terminating octet, or a literal whose declared length runs past the
    // end. RFC 7541 s5.1's "Integer encodings that exceed implementation limits -- in
    // value or octet length -- MUST be treated as decoding errors" covers the middle one.
    Truncated,

    // The decoded integer would exceed RFC 9204 s4.1.1's 62 bits, either because one
    // continuation octet is too wide for what is left, because the sum is, or because the
    // chain itself ran past 62 bits of payload - s5.1's named attack, "an encoder to send
    // a large number of zero values, which can waste octets and could be used to overflow
    // integer values".
    IntegerOverflow,

    // RFC 7541 s5.2: "A Huffman-encoded string literal containing the EOS symbol MUST be
    // treated as a decoding error." Raised by TlsQuicQpackHuffman.
    EosSymbol,

    // RFC 7541 s5.2: "A padding strictly longer than 7 bits MUST be treated as a decoding
    // error." Raised by TlsQuicQpackHuffman.
    PaddingTooLong,

    // RFC 7541 s5.2: "A padding not corresponding to the most significant bits of the code
    // for the EOS symbol MUST be treated as a decoding error." Raised by
    // TlsQuicQpackHuffman.
    PaddingNotEos,

    // A reference to the DYNAMIC table that could not be resolved. RFC 9204 s2.2.3's first
    // sentence names two of the ways - "a dynamic table entry that has already been evicted"
    // and one whose index runs past the insertion point - and s3.2.5's relative arithmetic
    // adds a third, an index that underflows the Base. All three are one outcome, so they are
    // one member; see the note at TlsQuicQpackDecoder.TryResolveDynamic.
    //
    // C16 CORRECTED THIS COMMENT. It used to say "Raised by TlsQuicQpackDecoder, which is
    // static-only", which stopped being true when C15 added the table arm and is now wrong
    // twice over: on the TABLE arm this member means a genuine resolution failure, and it is
    // only on the null arm that it means "this decoder has no dynamic table at all". The two
    // rejection sites say which.
    DynamicTableReference,

    // A static table index at or past RFC 9204 s3.1's 99 entries. Distinct from
    // DynamicTableReference: the T bit said static and the index simply is not one.
    StaticIndexOutOfRange,

    // RFC 9204 s4.5.1.1's Required Insert Count was non-zero on a decoder that advertises
    // SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0 - the NULL ARM, and nothing else. Raised by
    // TlsQuicQpackDecoder.
    //
    // C16 SPLIT THIS MEMBER, because its name had become narrower than its meaning: C15 also
    // reported s4.5.1.1's three "could not have been produced by a conformant encoder"
    // rejections through it, none of which is about a count being non-zero. Those are now
    // RequiredInsertCountNotEncodable. Both still map to QPACK_DECOMPRESSION_FAILED, so the
    // split changes no wire behaviour; it changes what a failing test can tell you.
    RequiredInsertCountNotZero,

    // RFC 9204 s4.5.1.1: "If the decoder encounters a value of EncodedInsertCount that could
    // not have been produced by a conformant encoder, it MUST treat this as a connection error
    // of type QPACK_DECOMPRESSION_FAILED." Its three arms - EncodedInsertCount above
    // FullRange, the wrap correction's own bound, and "Value of 0 must be encoded as 0" - all
    // say the same thing about the same field and so share one member.
    RequiredInsertCountNotEncodable,

    // RFC 9204 s2.2.3: "If the decoder encounters a reference in a field line representation
    // to a dynamic table entry that ... has an absolute index greater than or equal to the
    // declared Required Insert Count (Section 4.5.1), it MUST treat this as a connection error
    // of type QPACK_DECOMPRESSION_FAILED."
    //
    // THIS IS ALSO s2.2.1'S "SMALLER THAN EXPECTED" MUST, EXACTLY AND NOT APPROXIMATELY.
    // s2.1.2 fixes the expected value: "the Required Insert Count is one larger than the
    // largest absolute index of all referenced dynamic table entries", so "Required Insert
    // Count smaller than expected" is "some reference has an absolute index >= the declared
    // count" - the same predicate, per reference instead of per section. One check, both
    // sentences; a second section-level check would be a second transcription that could
    // disagree with this one.
    //
    // DISTINCT FROM DynamicTableReference on purpose. That member means the entry is not
    // there; this one means it IS there and the section had no right to name it, which is a
    // different defect in the peer's encoder and a different thing for a failing test to say.
    ReferenceAtOrAboveRequiredInsertCount,

    // RFC 9204 s2.2.1: "Otherwise, the stream on which the field section was received becomes
    // blocked." NOT AN ERROR AND NOT ABOUT THE PEER - like DestinationTooSmall it is a "not
    // yet", and TlsQuicQpackDecoder.TryGetHttp3ErrorCode refuses to map it to a connection
    // error for the same reason: the very same bytes decode once the encoder stream catches
    // up. A caller that maps this to QPACK_DECOMPRESSION_FAILED closes a healthy connection
    // over ordinary QUIC stream reordering, which is the defect s2.1.2 exists to avoid.
    Blocked,

    // RFC 9204 s2.1.2: "If a decoder encounters more blocked streams than it promised to
    // support, it MUST treat this as a connection error of type QPACK_DECOMPRESSION_FAILED."
    // The promise is SETTINGS_QPACK_BLOCKED_STREAMS; see TlsQuicQpackBlockedStreams.
    BlockedStreamLimitExceeded,

    // RFC 9204 s4.5.1.2: "An endpoint MUST treat a field block with a Sign bit of 1 as
    // invalid if the value of Required Insert Count is less than or equal to the value of
    // Delta Base." With Required Insert Count pinned at 0 and Delta Base non-negative, that
    // condition holds for EVERY Delta Base, so a Sign bit of 1 is invalid outright here.
    InvalidBase,

    // RFC 9114 s4.2.2's limit: "The size of a field list is calculated based on the
    // uncompressed size of fields, including the length of the name and value in bytes plus
    // an overhead of 32 bytes for each field." Raised by TlsQuicQpackDecoder when the
    // running total passes the advertised SETTINGS_MAX_FIELD_SECTION_SIZE.
    FieldSectionTooLarge,

    // NOT AN RFC DECODING ERROR, and the only member here that says nothing about the peer.
    // TlsQuicQpackHuffman.TryDecode expands its input and cannot know how far in advance, so
    // a destination shorter than TlsQuicQpackHuffman.GetMaximumDecodedLength reports this
    // rather than throwing. It is a local sizing answer: the same bytes with a large enough
    // buffer may decode perfectly, so a caller must not map it to a connection error.
    DestinationTooSmall,
}

internal static class TlsQuicQpackPrimitives
{
    // RFC 9204 s4.1.1: "QPACK implementations MUST be able to decode integers up to and
    // including 62 bits long." That sentence is a floor on what a decoder must accept;
    // this codec takes it as the ceiling too, which s5.1 sanctions - "Different limits can
    // be set for each of the different uses of integers, based on implementation
    // constraints."
    internal const int MaximumIntegerBits = 62;
    internal const ulong MaximumInteger = (1UL << MaximumIntegerBits) - 1;

    // RFC 7541 s5.1: "The prefix size, N, is always between 1 and 8 bits."
    internal const int MinimumIntegerPrefixBits = 1;
    internal const int MaximumPrefixBits = 8;

    // RFC 9204 s4.1.2, the extension HPACK does not have: "The prefix size, N, can have a
    // value between 2 and 8, inclusive." Two rather than one because the H bit takes one
    // of the N and the length integer needs at least one bit left.
    internal const int MinimumStringPrefixBits = 2;

    // The widest encoding this codec can produce: the prefix octet plus ten continuation
    // octets, which is what ulong.MaxValue costs at N = 1 (64 bits of payload at 7 bits an
    // octet is 10 octets, and the prefix contributes one more). It is sized for the whole
    // ulong range rather than for RFC 9204 s4.1.1's 62 bits ON PURPOSE. The encoder is
    // total over ulong while TryDecodeInteger enforces the 62-bit ceiling, and that
    // asymmetry is deliberate: a caller encoding a value above the ceiling has a bug that
    // its own peer's decoder will catch, and a second throw here would be one more guard
    // no wire input can reach. See the ledger's row 12 on why such a guard is not worth
    // its row. TlsQuicQpackPrimitivesTests.TheScratchBufferHoldsTheWidestEncodingAnyUlong
    // CanProduce pins the 11.
    internal const int MaximumIntegerEncodedLength = 11;

    // The number of octets TryEncodeInteger will write, derived from s5.1's pseudocode
    // rather than from the encoder, so the encoder's `written` has something independent to
    // be checked against - see the ledger's row 14 on why that separation matters.
    internal static int GetIntegerEncodedLength(ulong value, int prefixBits)
    {
        ThrowIfIntegerPrefixOutOfRange(prefixBits);
        uint mask = PrefixMask(prefixBits);
        if (value < mask)
        {
            return 1;
        }

        value -= mask;
        int length = 2;
        while (value >= 128)
        {
            value /= 128;
            length++;
        }

        return length;
    }

    // RFC 7541 s5.1's encoding pseudocode, verbatim in shape:
    //     if I < 2^N - 1, encode I on N bits
    //     else
    //         encode (2^N - 1) on N bits
    //         I = I - (2^N - 1)
    //         while I >= 128
    //              encode (I % 128 + 128) on 8 bits
    //              I = I / 128
    //         encode I on 8 bits
    //
    // `precedingBits` carries the (8 - N) bits of the previous field that share the first
    // octet - s5.1's "An integer representation can start anywhere within an octet". It
    // arrives already positioned, and its low N bits must be clear.
    internal static bool TryEncodeInteger(
        ulong value,
        int prefixBits,
        byte precedingBits,
        Span<byte> destination,
        out int written)
    {
        ThrowIfIntegerPrefixOutOfRange(prefixBits);
        uint mask = PrefixMask(prefixBits);
        if ((precedingBits & mask) != 0)
        {
            throw new ArgumentException(
                "precedingBits must leave the low prefixBits bits clear.",
                nameof(precedingBits));
        }

        written = 0;

        // Built in scratch and copied only once it is known to fit, so a destination that
        // is too small comes back untouched rather than half-written. Encoding straight
        // into `destination` and bailing mid-chain would leave the caller a buffer this
        // method has scribbled on and then reported nothing written for.
        Span<byte> scratch = stackalloc byte[MaximumIntegerEncodedLength];
        int length;
        if (value < mask)
        {
            scratch[0] = (byte)(precedingBits | (uint)value);
            length = 1;
        }
        else
        {
            scratch[0] = (byte)(precedingBits | mask);
            ulong remainder = value - mask;
            length = 1;
            while (remainder >= 128)
            {
                scratch[length++] = (byte)((remainder % 128) + 128);
                remainder /= 128;
            }

            scratch[length++] = (byte)remainder;
        }

        if (destination.Length < length)
        {
            return false;
        }

        scratch[..length].CopyTo(destination);
        written = length;
        return true;
    }

    // RFC 7541 s5.1's decoding pseudocode:
    //     decode I from the next N bits
    //     if I < 2^N - 1, return I
    //     else
    //         M = 0
    //         repeat
    //             B = next octet
    //             I = I + (B & 127) * 2^M
    //             M = M + 7
    //         while B & 128 == 128
    //         return I
    //
    // NOTHING HERE THROWS on any `source`. The three ways that pseudocode as written can be
    // driven off a cliff - no octet at all, a chain that ends without a terminator, and a
    // chain that never stops contributing - are the three guards below, and s5.1 asks for
    // the last of them by name.
    internal static bool TryDecodeInteger(
        ReadOnlySpan<byte> source,
        int prefixBits,
        out ulong value,
        out int consumed,
        out TlsQuicQpackError error)
    {
        ThrowIfIntegerPrefixOutOfRange(prefixBits);
        value = 0;
        consumed = 0;

        if (source.IsEmpty)
        {
            error = TlsQuicQpackError.Truncated;
            return false;
        }

        uint mask = PrefixMask(prefixBits);
        ulong result = source[0] & mask;
        int index = 1;
        if (result < mask)
        {
            value = result;
            consumed = index;
            error = TlsQuicQpackError.None;
            return true;
        }

        int shift = 0;
        byte octet;
        do
        {
            if (index >= source.Length)
            {
                error = TlsQuicQpackError.Truncated;
                return false;
            }

            // The chain bound. 62 bits of payload is reached at shift 56, so 63 is the
            // first position at which no octet - not even a zero one - can belong to a
            // legal encoding. It is checked BEFORE the value bound because that bound
            // shifts by `shift`, and C# masks a ulong shift count to `shift & 63`, which
            // would silently turn a 64-bit shift back into a 0-bit one.
            if (shift >= 63)
            {
                error = TlsQuicQpackError.IntegerOverflow;
                return false;
            }

            octet = source[index++];
            ulong chunk = (ulong)(octet & 0x7F);
            if (chunk > (MaximumInteger >> shift))
            {
                error = TlsQuicQpackError.IntegerOverflow;
                return false;
            }

            ulong addend = chunk << shift;
            if (result > MaximumInteger - addend)
            {
                error = TlsQuicQpackError.IntegerOverflow;
                return false;
            }

            result += addend;
            shift += 7;
        }
        while ((octet & 0x80) == 0x80);

        value = result;
        consumed = index;
        error = TlsQuicQpackError.None;
        return true;
    }

    // RFC 7541 s5.2's string literal, widened by RFC 9204 s4.1.2 to start mid-octet: "An
    // 'N-bit prefix string literal' begins mid-byte, with the first (8-N) bits allocated to
    // a previous field. The string uses one bit for the Huffman flag, followed by the
    // length of the encoded string as a (N-1)-bit prefix integer."
    //
    // So H is the top bit of the N-bit WINDOW, not of the octet, and the length integer
    // gets N-1 bits.
    internal static bool TryEncodeStringLiteral(
        ReadOnlySpan<byte> data,
        int prefixBits,
        byte precedingBits,
        bool huffman,
        Span<byte> destination,
        out int written)
    {
        ThrowIfStringPrefixOutOfRange(prefixBits);
        written = 0;

        byte header = precedingBits;
        if (huffman)
        {
            header |= (byte)(1u << (prefixBits - 1));
        }

        if (!TryEncodeInteger((ulong)data.Length, prefixBits - 1, header, destination, out int headerLength))
        {
            return false;
        }

        if (destination.Length - headerLength < data.Length)
        {
            return false;
        }

        data.CopyTo(destination[headerLength..]);
        written = headerLength + data.Length;
        return true;
    }

    // The read-back. `data` is a slice of `source`, never a copy, and it is EMPTY rather
    // than absent when the declared length is zero - a zero-length field value is legal and
    // is a different thing from a literal that is not there, which is the `false` return.
    internal static bool TryDecodeStringLiteral(
        ReadOnlySpan<byte> source,
        int prefixBits,
        out bool huffman,
        out ReadOnlySpan<byte> data,
        out int consumed,
        out TlsQuicQpackError error)
    {
        ThrowIfStringPrefixOutOfRange(prefixBits);
        huffman = false;
        data = default;
        consumed = 0;

        if (source.IsEmpty)
        {
            error = TlsQuicQpackError.Truncated;
            return false;
        }

        bool flag = (source[0] & (1u << (prefixBits - 1))) != 0;
        if (!TryDecodeInteger(source, prefixBits - 1, out ulong length, out int headerLength, out error))
        {
            return false;
        }

        // The length that overruns, compared in ulong BEFORE any narrowing, so a declared
        // length near 2^62 cannot wrap into a small int and then slice successfully.
        ulong remaining = (ulong)(source.Length - headerLength);
        if (length > remaining)
        {
            error = TlsQuicQpackError.Truncated;
            return false;
        }

        huffman = flag;
        data = source.Slice(headerLength, (int)length);
        consumed = headerLength + (int)length;
        error = TlsQuicQpackError.None;
        return true;
    }

    // 2^N - 1. At N = 8 this is 255, which is why the prefix-fill boundary is reachable at
    // every legal N and not only at the narrow ones.
    private static uint PrefixMask(int prefixBits) => (1u << prefixBits) - 1;

    private static void ThrowIfIntegerPrefixOutOfRange(int prefixBits)
    {
        if (prefixBits is < MinimumIntegerPrefixBits or > MaximumPrefixBits)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixBits));
        }
    }

    private static void ThrowIfStringPrefixOutOfRange(int prefixBits)
    {
        if (prefixBits is < MinimumStringPrefixBits or > MaximumPrefixBits)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixBits));
        }
    }
}


// ============================================================================
// THE MUTATION LEDGER - TASK C16 (this file: the members C16 added and split)
// ============================================================================
//
//   ROWS BELOW                    2  = C16-12 to C16-13 with no gaps
//   KILLED WHEN FIRST RUN         1  = 2 rows, less 1 [WAS-SURVIVOR] and 0 [SURVIVED]
//   SURVIVED, THEN WITNESSED      1  = row C16-13
//   SURVIVING STILL               0
//
//   1 + 1 = 2. The task's other 33 rows are in TlsQuicQpackDecoder.cs (11),
//   TlsQuicHttp3Request.cs (7), TlsQuicHttp3Streams.cs (7), TlsQuicHttp3Connection.cs (6) and
//   TlsQuicHttp3Frames.cs (2). 2 + 33 = 35 rows for the task.
//
// A UNIQUE ROW PREFIX, because this file's own ledger at the top counts itself with
// `grep -cE '^// +[0-9]+\. '` and must keep returning 14. Its own three:
//   `grep -cE '^// +C16-[0-9]+\. ' TlsQuicQpackPrimitives.cs`                  must return 2
//   `grep -cE '^// +C16-[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicQpackPrimitives.cs` must return 1
//   `grep -cE '^// +C16-[0-9]+\..*\[SURVIVED\]' TlsQuicQpackPrimitives.cs`     must return 0
//
// Same harness, same gate and the same three harness defects as TlsQuicQpackDecoder.cs's C16
// block, which records them in full.
//
//  C16-12. Blocked given the same value as None, so a block reads as a clean decode. Killed
//        by 3.
//  C16-13. [WAS-SURVIVOR] ReferenceAtOrAboveRequiredInsertCount aliased onto
//        DynamicTableReference, collapsing C16's split of s2.2.3's two clauses.
//        IT SURVIVED THE WHOLE GATE, and the reason is worth more than the row: every
//        behavioural assertion in the suite compares one member against another, and two
//        aliases compare equal, so no test that decodes anything can see the difference. The
//        split exists so a failing test says WHICH defect the peer committed - an entry
//        "already evicted" or one whose index the section had no right to name - and that is a
//        claim about the enum's own shape rather than about any decode.
//        .TheTwoInvalidReferenceMembersAreDistinctThoughTheyShareOneWireCode is that claim,
//        and it also pins that both still map to the SAME s6 code, so it cannot be satisfied
//        by letting the two diverge on the wire. Killed by exactly one case.
//
// ============================================================================
