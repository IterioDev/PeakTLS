namespace SharpTls.Quic;

// ============================================================================
// THE MUTATION LEDGER - TASK C7 (this file and TlsQuicQpackStaticTable.cs)
// ============================================================================
//
//   ROWS BELOW                   18  = numbered 1-18 with no gaps
//   KILLED WHEN FIRST RUN        18  = 18 rows, less 0 [WAS-SURVIVOR] and 0 [SURVIVED]
//   SURVIVED, THEN FIXED OR       0  = none
//     WITNESSED
//   SURVIVING STILL               0  = none
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' TlsQuicQpackEncoder.cs`                  must return 18
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicQpackEncoder.cs` must return 0
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' TlsQuicQpackEncoder.cs`     must return 0
//
// Every row was run in a `git worktree` of its own, one edit at a time, each restored before
// the next, against `dotnet test --filter FullyQualifiedName~Qpack`. Counts are per xUnit
// CASE, so a Theory that fails in three of its rows counts three.
//
// A note on how this sweep nearly went wrong, because it is the same class of defect the
// ledger exists to catch. The first run of the harness reported all 32 mutations SURVIVING,
// including one that clears the static-table T bit. That is impossible, and it was the
// harness: at `-v q` the failures print as `... [FAIL]` and the harness was looking for
// `Failed <name>`, so it read every run as clean. A sweep that reports what you want to hear
// is worth less than no sweep at all. The verdict now comes from the run's own
// `Failed: <n>` summary line.
//
//   1. TlsQuicQpackStaticTable, row 52: `text/html; charset=utf-8` -> the row 54 spelling
//      `text/plain;charset=utf-8`. THE MOST IMPORTANT ROW HERE. Those two values differ only
//      in a space, they are the two halves of the wrapped-value rejoin, and an encode/decode
//      round trip cannot see the difference because both directions read this array. Killed
//      by three CAPTURE tests: TlsQuicQpackStaticTableTests.TheTableMatchesTheCaptured
//      AppendixARowForRow, .TheWrappedValuesRejoinTheOnlyWayTheCaptureAllows and
//      .BothHalvesOfTheJoinRuleHaveAWitness. No round trip anywhere killed it.
//   2. TlsQuicQpackStaticTable, row 54: the WRONG rejoin, `text/plain; charset=utf-8` with a
//      space. This is the exact mistake a transcriber makes who assumes the renderer always
//      breaks at spaces. Killed by the same three, and by the geometry one in particular:
//      that value would have been rendered `text/plain;` + `charset=utf-8`, and the capture
//      shows `text/` + `plain;charset=utf-8`.
//   3. TlsQuicQpackStaticTable: row 1 deleted, taking the count to 98. Killed by 27 cases,
//      including .TheRowCountIsDerivedFromTheCaptureRatherThanAsserted.
//   4. TlsQuicQpackStaticTable.TryLookup: `>= Count` -> `> Count`, so index 99 resolves to a
//      row past the end. Killed by 5 including .AnIndexOutsideTheTableDoesNotResolveAndDoes
//      NotThrow and TlsQuicQpackDecoderTests.AStaticIndexPastTheTableIsRejected.
//   5. TlsQuicQpackStaticTable.TryFindNameAndValue: value comparison dropped, making it a
//      second TryFindName - the "the table is a name-to-value map" mistake, in code. Killed
//      by 16.
//   6. TlsQuicQpackStaticTable.TryFindName: scan reversed, so the HIGHEST matching row wins
//      instead of the lowest. Legal-looking and wrong: Appendix A orders the table so the
//      first match is the cheapest to encode. Killed by exactly one case,
//      .NamesRepeatSoTheTwoLookupsAreDifferentOperations.
//   7. Indexed field line pattern 0b1100_0000 -> 0b1000_0000, clearing T. THE STATIC-VERSUS-
//      DYNAMIC BIT. Killed by 8 including .TheEncoderNeverEmitsADynamicTableReference.
//   8. Literal-with-name-reference pattern 0b0101_0000 -> 0b0100_0000, clearing T. The same
//      bit in the other representation. Killed by 9, B.1 among them.
//   9. IndexedFieldLinePrefixBits 6 -> 5. Invisible at index 1, which is why
//      .AnIndexedFieldLineSpansThePrefixFillBoundary exists. Killed by 6.
//  10. ValueLiteralPrefixBits 8 -> 7, which moves the H bit and narrows the length. Killed
//      by 5.
//  11. NameLiteralPrefixBits 4 -> 3. Killed by 5.
//  12. TryEncodeFieldLine: the s4.5.2 full-match branch disabled, so everything falls to
//      s4.5.4. Killed by 4 including .AFullMatchOnNameAndValueEmitsAnIndexedFieldLine.
//  13. TryEncodeString: the H bit dropped from the Huffman header, so coded bytes are
//      announced as plaintext. Killed by 3.
//  14. TryEncodeString: the declared length taken from the plaintext instead of from
//      TlsQuicQpackHuffman.GetEncodedLength. RFC 9204 s4.1.2 says "the indicated length is
//      the size of the string after encoding". Killed by 4.
//  15. TryEncodeString: the `huffman` branch inverted. Killed by 7, B.1 among them.
//  16. TryEncodeFieldSectionPrefix: `written = count + baseCount` -> `written = count`, so
//      the prefix is one octet. Killed by 22.
//  17. TryEncodeFieldLine: `preferNameReference` dropped from the condition, so s4.5.4 is
//      always taken. Killed by exactly one case,
//      .PreferNameReferenceSelectsBetweenSection454AndSection456.
//  18. TryEncodeFieldLine: `written` set before a failed value write, so a short destination
//      half-writes. Killed by exactly one case, .ADestinationOneOctetShortFailsWithoutWriting.
//
// ============================================================================

// RFC 9204 s4.5's field line representations, encoding side, STATIC REFERENCES ONLY. See
// reference-captures/rfc9204-section4.5-field-line-representations.txt and
// reference-captures/rfc9204-appendix-b-encoding-and-decoding-examples.txt.
//
// Three of the six representations are reachable from here and three are not, and the split
// is structural rather than a policy this class enforces with a check:
//
//   s4.5.2 Indexed Field Line              - emitted, always with T = 1
//   s4.5.4 Literal With Name Reference     - emitted, always with T = 1
//   s4.5.6 Literal With Literal Name       - emitted, has no table reference at all
//   s4.5.3 Indexed With Post-Base Index    - NOT emitted; post-Base indexing is dynamic-only
//   s4.5.5 Literal With Post-Base Name Ref - NOT emitted; likewise
//   s4.5.2/s4.5.4 with T = 0               - NOT emitted; T is a literal 1 in both writers
//
// WHY THERE IS NO DYNAMIC ARM. RFC 9204 s3.2.3: "When the maximum table capacity is zero,
// the encoder MUST NOT insert entries into the dynamic table and MUST NOT send any encoder
// instructions on the encoder stream." s5 makes SETTINGS_QPACK_MAX_TABLE_CAPACITY default
// to zero, and s3.2.3 makes the peer's maximum "0 until the encoder processes a SETTINGS
// frame with a non-zero value". So an encoder that never touches the dynamic table is the
// CONFORMING DEFAULT, not a degraded mode.
//
// The field section prefix is therefore a constant two zero octets: s4.5.1.1's transform
// maps Required Insert Count 0 to an encoded 0, and s4.5.1.2 says "A field section that was
// encoded without references to the dynamic table can use any value for the Base; setting
// Delta Base to zero is one of the most efficient encodings" - Sign 0, Delta Base 0. RFC
// 9204 Appendix B.1 shows exactly those two octets in front of its one field line.
//
// ON THE TWO POLICY FLAGS. `huffman` and `preferNameReference` are PARAMETERS, not
// constants, because the plan's task C1 owns them: "QPACK encoder policy: Huffman on or off
// per string, and whether a header with a static name match prefers s4.5.4 (name reference)
// or s4.5.6 (literal name)". Both are fingerprint surface. In particular `huffman` is
// applied UNCONDITIONALLY and is not a "use it when it comes out shorter" heuristic: a
// size-dependent choice would make the wire bytes depend on the header value, and RFC 9204
// s7.2 is explicit that the Huffman choice is observable. A deterministic flag is
// reproducible; a heuristic is a leak.
internal static class TlsQuicQpackEncoder
{
    // s4.5.1: an 8-bit-prefix Required Insert Count octet and a Sign-plus-7-bit Delta Base
    // octet. Constant in this arm, so constant in length too.
    internal const int FieldSectionPrefixLength = 2;

    // s4.5.2's first octet with the '1' pattern and T = 1 already set, leaving the low 6
    // bits to the index. THE T BIT IS THE WHOLE POINT: clear it and this becomes a relative
    // index into a dynamic table that does not exist, which a peer resolves to some other
    // field entirely rather than rejecting.
    private const byte IndexedFieldLineStaticPattern = 0b1100_0000;

    // s4.5.4's first octet: '01' pattern, N = 0, T = 1, low 4 bits to the name index.
    private const byte LiteralNameReferenceStaticPattern = 0b0101_0000;

    // s4.5.6's first octet: '001' pattern, N = 0. The next bit is H and the low 3 bits are
    // the name length, both of which the string literal writer fills in.
    private const byte LiteralLiteralNamePattern = 0b0010_0000;

    // s4.5.2's index is a 6-bit prefix integer; s4.5.4's name index a 4-bit one; s4.5.6's
    // name is a 4-bit prefix string literal (H plus a 3-bit length) and every value is an
    // 8-bit prefix string literal (H plus a 7-bit length).
    private const int IndexedFieldLinePrefixBits = 6;
    private const int NameReferencePrefixBits = 4;
    private const int NameLiteralPrefixBits = 4;
    private const int ValueLiteralPrefixBits = 8;

    // The two-octet prefix of RFC 9204 s4.5.1, which in this arm is `00 00`. Written through
    // the integer codec rather than as two literal zeroes so that the encoding of "zero at
    // an 8-bit prefix" and "zero at a 7-bit prefix behind a clear Sign bit" is the codec's
    // answer and not this file's assumption.
    internal static bool TryEncodeFieldSectionPrefix(Span<byte> destination, out int written)
    {
        written = 0;
        if (!TlsQuicQpackPrimitives.TryEncodeInteger(0, 8, 0, destination, out int count))
        {
            return false;
        }

        // Sign = 0, Delta Base = 0. The Sign bit is the top bit of this octet, so it is the
        // `precedingBits` argument and the integer gets the remaining 7.
        if (!TlsQuicQpackPrimitives.TryEncodeInteger(0, 7, 0, destination[count..], out int baseCount))
        {
            return false;
        }

        written = count + baseCount;
        return true;
    }

    // One field line. Picks among s4.5.2, s4.5.4 and s4.5.6 by what the static table holds:
    //
    //   name AND value both present            -> s4.5.2, no literal at all
    //   name present, value not, and caller
    //     asked for name references            -> s4.5.4, value as a literal
    //   otherwise                              -> s4.5.6, both as literals
    //
    // The first branch needs TryFindNameAndValue and the second TryFindName, and they are
    // genuinely different lookups - see TlsQuicQpackStaticTable's header on why the table is
    // not a name-to-value map.
    //
    // Returns false, without writing anything, if `destination` is too small. It never
    // throws: every argument here is ours, and the only failure is sizing.
    internal static bool TryEncodeFieldLine(
        ReadOnlySpan<byte> name,
        ReadOnlySpan<byte> value,
        TlsQuicQpackHuffmanPolicy huffman,
        bool preferNameReference,
        Span<byte> destination,
        out int written)
    {
        written = 0;

        if (TlsQuicQpackStaticTable.TryFindNameAndValue(name, value, out int index))
        {
            return TlsQuicQpackPrimitives.TryEncodeInteger(
                (ulong)index,
                IndexedFieldLinePrefixBits,
                IndexedFieldLineStaticPattern,
                destination,
                out written);
        }

        if (preferNameReference && TlsQuicQpackStaticTable.TryFindName(name, out int nameIndex))
        {
            if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                    (ulong)nameIndex,
                    NameReferencePrefixBits,
                    LiteralNameReferenceStaticPattern,
                    destination,
                    out int headerLength))
            {
                return false;
            }

            if (!TryEncodeString(value, ValueLiteralPrefixBits, 0, huffman, destination[headerLength..], out int valueLength))
            {
                return false;
            }

            written = headerLength + valueLength;
            return true;
        }

        if (!TryEncodeString(
                name,
                NameLiteralPrefixBits,
                LiteralLiteralNamePattern,
                huffman,
                destination,
                out int nameLength))
        {
            return false;
        }

        if (!TryEncodeString(value, ValueLiteralPrefixBits, 0, huffman, destination[nameLength..], out int literalValueLength))
        {
            return false;
        }

        written = nameLength + literalValueLength;
        return true;
    }

    // A string literal that may be Huffman-coded, written straight into `destination` with
    // no scratch buffer: RFC 9204 s4.1.2's "the indicated length is the size of the string
    // after encoding" means the length is needed BEFORE the payload, and
    // TlsQuicQpackHuffman.GetEncodedLength supplies it without encoding anything.
    //
    // With `huffman` false this is byte-for-byte
    // TlsQuicQpackPrimitives.TryEncodeStringLiteral, and
    // TlsQuicQpackEncoderTests.TheNonHuffmanStringPathAgreesWithThePrimitive pins that so
    // the two cannot drift.
    private static bool TryEncodeString(
        ReadOnlySpan<byte> data,
        int prefixBits,
        byte precedingBits,
        TlsQuicQpackHuffmanPolicy huffman,
        Span<byte> destination,
        out int written)
    {
        written = 0;

        // THE LENGTH IS COMPUTED BEFORE THE DECISION, because under ShorterOfTheTwo it IS the
        // decision. GetEncodedLength walks the string without emitting anything, so the cost of
        // asking is one pass over bytes that are about to be walked again either way.
        int length = TlsQuicQpackHuffman.GetEncodedLength(data);

        // s4.1.2 leaves the choice to the encoder and every deployed one resolves it the same
        // way: strictly shorter wins, ties go to the literal. An empty string takes the literal
        // branch here too - 0 < 0 is false - which is what nghttp2 emits for one.
        var useHuffman = huffman switch
        {
            TlsQuicQpackHuffmanPolicy.Always => true,
            TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo => length < data.Length,
            _ => false,
        };

        if (!useHuffman)
        {
            return TlsQuicQpackPrimitives.TryEncodeStringLiteral(
                data,
                prefixBits,
                precedingBits,
                huffman: false,
                destination,
                out written);
        }

        // H is the top bit of the N-bit window, so it rides in with `precedingBits` and the
        // length integer gets N-1 bits - the same split TryEncodeStringLiteral uses.
        byte header = (byte)(precedingBits | (1u << (prefixBits - 1)));
        if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                (ulong)length,
                prefixBits - 1,
                header,
                destination,
                out int headerLength))
        {
            return false;
        }

        if (!TlsQuicQpackHuffman.TryEncode(data, destination[headerLength..], out int payloadLength))
        {
            return false;
        }

        written = headerLength + payloadLength;
        return true;
    }
}
