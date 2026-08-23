namespace SharpTls.Quic;

// ============================================================================
// THE MUTATION LEDGER
// ============================================================================
//
//   ROWS BELOW                   13  = numbered 1-13 with no gaps
//   KILLED WHEN FIRST RUN        10  = 13 rows, less 1 [WAS-SURVIVOR] and 2 [SURVIVED]
//   SURVIVED, THEN FIXED OR       1  = row 2, whose test was too loose and was tightened
//     WITNESSED
//   SURVIVING STILL               2  = rows 8 and 11, both classified below
//
// Three greps, all anchored to a numbered row so that THESE lines, which also carry the
// markers, do not match themselves. Run from this file's directory:
//   `grep -cE '^// +[0-9]+\. ' TlsQuicQpackHuffman.cs`                  must return 13
//   `grep -cE '^// +[0-9]+\..*\[WAS-SURVIVOR\]' TlsQuicQpackHuffman.cs` must return 1
//   `grep -cE '^// +[0-9]+\..*\[SURVIVED\]' TlsQuicQpackHuffman.cs`     must return 2
//
// Every row was run against the 83-case TlsQuicQpack subset (46 from task C5, 37 from this
// task), in a `git worktree`, one edit at a time, each restored before the next. THE SUBSET
// RATHER THAN THE FULL QUIC GATE ON PURPOSE: task 14e was landing commits into the same tree
// throughout this sweep, so a whole-gate count would have mixed its movement into these
// figures. Nothing outside these two test classes touches either file, so the subset and the
// gate kill identically. Counts are per xUnit CASE, so a Theory failing in three of its rows
// counts as three. EVERY TEST NAMED BELOW WAS READ OUT OF THE FAILING RUN, not predicted.
//
//    1. `TryDecode`: `symbol == EosSymbol` -> `symbol == -1`.                      kills 1
//       RFC 7541 s5.2s "A Huffman-encoded string literal containing the EOS symbol MUST be
//       treated as a decoding error." The mutant emits EOS as octet 0x00 and carries on.
//       Killed by TlsQuicQpackHuffmanTests.TheEosSymbolIsRejectedRatherThanEndingTheString.
//    2. `TryDecode`: `depth > 7` -> `depth > 8`.                     [WAS-SURVIVOR] kills 1
//       THE PADDING-LENGTH BOUND, and the one mutation in this task that got through first
//       time. The test then had only an 11-bit pad in it - 0x1F followed by 0xFF - and 11 is
//       over 8 as well as over 7, so a bound of 8 rejected it just as happily. The bound was
//       never witnessed AT 8, which is the only place it can be witnessed. Fixed by adding a
//       payload that ends exactly on an octet boundary (eight zero-digit symbols, 40 bits)
//       plus one 0xFF, giving a pad of exactly 8 - one bit over, nothing else wrong with it.
//       Killed by TlsQuicQpackHuffmanTests.PaddingLongerThanSevenBitsIsRejected.
//    3. `TryDecode`: `partial != expected` -> `partial != expected && depth > 99`.  kills 1
//       s5.2s "A padding not corresponding to the most significant bits of the code for the
//       EOS symbol MUST be treated as a decoding error." Separable from row 2 by
//       construction: three bits of pad is well inside the length bound, so only the bit
//       pattern can reject it.
//       Killed by TlsQuicQpackHuffmanTests.PaddingThatIsNotTheEosPrefixIsRejected.
//    4. `TryDecode`: `for (int bit = 7; bit >= 0; bit--)` -> ascending.            kills 16
//       Bit order. s5.2s codes are read most significant bit first; the mutant reads each
//       octet backwards and produces symbol sequences that are still well-formed, which is
//       why it takes a published vector rather than a round trip to see it.
//       Killed by TlsQuicQpackHuffmanTests.ThePublishedVectorsDecodeToTheirRfcPlaintext,
//       among others.
//    5. `TryEncode`: `padBits = CodeTable[EosSymbol] >> ...` -> `padBits = 0`.     kills 14
//       Padding with zeros instead of s5.2s EOS prefix. Zeros are a legal prefix of several
//       real codes, so the output is not merely non-conforming - it decodes to extra symbols.
//       Killed by TlsQuicQpackHuffmanTests.TheEncoderPadsWithTheMostSignificantBitsOfEos and
//       by TlsQuicQpackHuffmanTests.ThePublishedVectorsReEncodeToTheirRfcBytes.
//    6. `TryEncode`: `destination.Length < required` -> `destination.Length < 0`.   kills 1
//       Killed by TlsQuicQpackHuffmanTests.ADestinationTooSmallIsReportedRatherThanThrown.
//    7. `TryDecode`: `count >= destination.Length` -> `count > destination.Length`. kills 1
//       One past the end of the caller buffer.
//       Killed by TlsQuicQpackHuffmanTests.ADestinationTooSmallIsReportedRatherThanThrown.
//    8. `TryEncode`: delete `accumulator &= (1UL << accumulated) - 1;`.        [SURVIVED]
//       VACUOUS, AND DELIBERATELY UNWITNESSED. The mask cannot change any output: the only
//       reader of `accumulator` is `(byte)(accumulator >> accumulated)`, which truncates to
//       eight bits, and every bit above those eight has already been emitted. Left in place
//       because it is what makes "accumulator holds exactly `accumulated` bits" true as
//       written rather than true only after reasoning about the cast - but NO test is written
//       for it, because any such test would pass against the mutant too and would be a false
//       witness rather than a real one.
//    9. `TryDecode`: delete the `depth = 0;` reset after a completed symbol.       kills 18
//       Without it `depth` counts every bit of the whole input rather than the bits since the
//       last completed code, so the padding check reads a number with nothing to do with the
//       padding. Killed by, among others,
//       TlsQuicQpackHuffmanTests.AnEncodingThatEndsOnAnOctetBoundaryCarriesNoPaddingAtAll.
//   10. `TryDecode`: delete the `partial = 0;` reset after a completed symbol.     kills 15
//       The same defect on the bit pattern rather than on the count.
//       Killed by TlsQuicQpackHuffmanTests.ThePublishedVectorsDecodeToTheirRfcPlaintext.
//   11. Static ctor: `tree[slot] == 0` -> `tree[slot] == int.MinValue`.        [SURVIVED]
//       The completeness loop.
//       UNREACHABLE BY CONSTRUCTION, and provably so rather than apparently so. The loop
//       asserts every slot of the trie has a child, which holds exactly when the code is
//       complete, which holds exactly when Kraft equality does - and
//       TlsQuicQpackHuffmanTests.TheTableSatisfiesKraftEqualityAndIsPrefixFree measures that
//       the 257 lengths sum to exactly 1. So nothing reaches this throw while the table is
//       the transcribed one, and the only way to reach it is to corrupt the table, which is
//       row 13 and is caught earlier and far better by the capture witness. NOT DELETED,
//       because it is the precondition the decode loop absence of a bounds branch rests on,
//       and an unstated precondition is how that branch gets added back by someone later.
//   12. `GetEncodedLength`: `(bits + 7) / 8` -> `bits / 8`.                        kills 13
//       Truncating instead of rounding up drops the final partial octet, so every string
//       whose bit length is not a multiple of 8 loses its last symbols.
//       Killed by TlsQuicQpackHuffmanTests.ThePublishedVectorsReEncodeToTheirRfcBytes.
//   13. `CodeTable`: swap rows 2 and 3 - 0x0FFFFFE2 and 0x0FFFFFE3, both 28 bits.  kills 1
//       THE ROW THAT JUSTIFIES THIS TASK METHOD, and the reason C6 does not rest on round
//       trips. It is a LENGTH-PRESERVING PERMUTATION, so the code stays complete, stays
//       prefix-free, passes Kraft, loads without complaint, and every one of the 256
//       single-symbol round trips still passes - because the encoder and the decoder read the
//       same wrong table and agree with each other perfectly. The twelve published vectors
//       never touch symbols 2 or 3 and do not see it either. EXACTLY ONE test kills it, and
//       it is the one that compares the table against the capture on disk:
//       TlsQuicQpackHuffmanTests.TheTableMatchesTheCapturedAppendixBRowForRow.
//
// ============================================================================

// RFC 7541 Appendix B's Huffman code and s5.2's rules for using it, which RFC 9204 s4.1.2
// adopts verbatim: "the Huffman table from Appendix B of [RFC7541] is used without
// modification". See reference-captures/rfc7541-appendix-b-huffman-code.txt.
//
// HOW THE 257 ROWS WERE PUT HERE, AND WHY THAT IS NOT A ROUND TRIP. The two tables below
// were generated by parsing the capture, not typed from it and not recalled. Each row of
// the capture carries the same code THREE times over - as binary split into 8-bit groups,
// as hex, and as a bit count in brackets - and the parse asserted all three agree on every
// row before emitting anything. That is the only check on this transcription that does not
// route through code in this file: an encoder and a decoder sharing one wrong row agree
// with each other perfectly, which is Finding 5 and the reason C6 does both directions in
// one task. TlsQuicQpackHuffmanTests.TheTableMatchesTheCapturedAppendixBRowForRow re-runs
// the same three-way agreement against the capture at test time.
//
// THE ROW COUNT IS DERIVED, NOT ASSERTED. The capture's body has 257 lines ending in a
// bracketed bit count, and the parenthesised index on those lines is each of 0..256 exactly
// once, so 256 - 0 + 1 = 257 reconciles with the line count. That grep is safe despite the
// six page footers interior to the range because a footer ends "[Page 51]" and P is not a
// digit. TlsQuicQpackHuffmanTests.TheRowCountIsDerivedFromTheCaptureRatherThanAsserted runs
// it again over the file on disk.
//
// WHAT THE PUBLISHED VECTORS ACTUALLY COVER, which is much less than the table. RFC 7541
// C.4 and C.6 are the only Huffman test vectors that exist, and between them their twelve
// Huffman-coded strings exercise 55 of the 256 octet symbols and only code lengths 5, 6, 7
// and 8. Every row of length 10 or more - 201 symbols, including every one of the 4- and
// 5-nibble codes and EOS itself - has NO external witness anywhere, and no amount of round
// tripping creates one. What stands in for it is the structural evidence above plus the
// completeness check in the static constructor: the 257 lengths satisfy Kraft equality
// exactly, so no single row's length can be altered without the sum ceasing to be 1.
internal static class TlsQuicQpackHuffman
{
    // RFC 7541 Appendix B's last row, "EOS (256)". It is a symbol of the code like any
    // other and has a place in the table, but s5.2 forbids it appearing in a literal, so it
    // exists here only to be the source of the padding bits and the thing to reject.
    internal const int EosSymbol = 256;

    private static readonly uint[] CodeTable =
    [
        0x00001FF8, 0x007FFFD8, 0x0FFFFFE2, 0x0FFFFFE3, 0x0FFFFFE4, 0x0FFFFFE5, 0x0FFFFFE6, 0x0FFFFFE7, // 0-7
        0x0FFFFFE8, 0x00FFFFEA, 0x3FFFFFFC, 0x0FFFFFE9, 0x0FFFFFEA, 0x3FFFFFFD, 0x0FFFFFEB, 0x0FFFFFEC, // 8-15
        0x0FFFFFED, 0x0FFFFFEE, 0x0FFFFFEF, 0x0FFFFFF0, 0x0FFFFFF1, 0x0FFFFFF2, 0x3FFFFFFE, 0x0FFFFFF3, // 16-23
        0x0FFFFFF4, 0x0FFFFFF5, 0x0FFFFFF6, 0x0FFFFFF7, 0x0FFFFFF8, 0x0FFFFFF9, 0x0FFFFFFA, 0x0FFFFFFB, // 24-31
        0x00000014, 0x000003F8, 0x000003F9, 0x00000FFA, 0x00001FF9, 0x00000015, 0x000000F8, 0x000007FA, // 32-39
        0x000003FA, 0x000003FB, 0x000000F9, 0x000007FB, 0x000000FA, 0x00000016, 0x00000017, 0x00000018, // 40-47
        0x00000000, 0x00000001, 0x00000002, 0x00000019, 0x0000001A, 0x0000001B, 0x0000001C, 0x0000001D, // 48-55
        0x0000001E, 0x0000001F, 0x0000005C, 0x000000FB, 0x00007FFC, 0x00000020, 0x00000FFB, 0x000003FC, // 56-63
        0x00001FFA, 0x00000021, 0x0000005D, 0x0000005E, 0x0000005F, 0x00000060, 0x00000061, 0x00000062, // 64-71
        0x00000063, 0x00000064, 0x00000065, 0x00000066, 0x00000067, 0x00000068, 0x00000069, 0x0000006A, // 72-79
        0x0000006B, 0x0000006C, 0x0000006D, 0x0000006E, 0x0000006F, 0x00000070, 0x00000071, 0x00000072, // 80-87
        0x000000FC, 0x00000073, 0x000000FD, 0x00001FFB, 0x0007FFF0, 0x00001FFC, 0x00003FFC, 0x00000022, // 88-95
        0x00007FFD, 0x00000003, 0x00000023, 0x00000004, 0x00000024, 0x00000005, 0x00000025, 0x00000026, // 96-103
        0x00000027, 0x00000006, 0x00000074, 0x00000075, 0x00000028, 0x00000029, 0x0000002A, 0x00000007, // 104-111
        0x0000002B, 0x00000076, 0x0000002C, 0x00000008, 0x00000009, 0x0000002D, 0x00000077, 0x00000078, // 112-119
        0x00000079, 0x0000007A, 0x0000007B, 0x00007FFE, 0x000007FC, 0x00003FFD, 0x00001FFD, 0x0FFFFFFC, // 120-127
        0x000FFFE6, 0x003FFFD2, 0x000FFFE7, 0x000FFFE8, 0x003FFFD3, 0x003FFFD4, 0x003FFFD5, 0x007FFFD9, // 128-135
        0x003FFFD6, 0x007FFFDA, 0x007FFFDB, 0x007FFFDC, 0x007FFFDD, 0x007FFFDE, 0x00FFFFEB, 0x007FFFDF, // 136-143
        0x00FFFFEC, 0x00FFFFED, 0x003FFFD7, 0x007FFFE0, 0x00FFFFEE, 0x007FFFE1, 0x007FFFE2, 0x007FFFE3, // 144-151
        0x007FFFE4, 0x001FFFDC, 0x003FFFD8, 0x007FFFE5, 0x003FFFD9, 0x007FFFE6, 0x007FFFE7, 0x00FFFFEF, // 152-159
        0x003FFFDA, 0x001FFFDD, 0x000FFFE9, 0x003FFFDB, 0x003FFFDC, 0x007FFFE8, 0x007FFFE9, 0x001FFFDE, // 160-167
        0x007FFFEA, 0x003FFFDD, 0x003FFFDE, 0x00FFFFF0, 0x001FFFDF, 0x003FFFDF, 0x007FFFEB, 0x007FFFEC, // 168-175
        0x001FFFE0, 0x001FFFE1, 0x003FFFE0, 0x001FFFE2, 0x007FFFED, 0x003FFFE1, 0x007FFFEE, 0x007FFFEF, // 176-183
        0x000FFFEA, 0x003FFFE2, 0x003FFFE3, 0x003FFFE4, 0x007FFFF0, 0x003FFFE5, 0x003FFFE6, 0x007FFFF1, // 184-191
        0x03FFFFE0, 0x03FFFFE1, 0x000FFFEB, 0x0007FFF1, 0x003FFFE7, 0x007FFFF2, 0x003FFFE8, 0x01FFFFEC, // 192-199
        0x03FFFFE2, 0x03FFFFE3, 0x03FFFFE4, 0x07FFFFDE, 0x07FFFFDF, 0x03FFFFE5, 0x00FFFFF1, 0x01FFFFED, // 200-207
        0x0007FFF2, 0x001FFFE3, 0x03FFFFE6, 0x07FFFFE0, 0x07FFFFE1, 0x03FFFFE7, 0x07FFFFE2, 0x00FFFFF2, // 208-215
        0x001FFFE4, 0x001FFFE5, 0x03FFFFE8, 0x03FFFFE9, 0x0FFFFFFD, 0x07FFFFE3, 0x07FFFFE4, 0x07FFFFE5, // 216-223
        0x000FFFEC, 0x00FFFFF3, 0x000FFFED, 0x001FFFE6, 0x003FFFE9, 0x001FFFE7, 0x001FFFE8, 0x007FFFF3, // 224-231
        0x003FFFEA, 0x003FFFEB, 0x01FFFFEE, 0x01FFFFEF, 0x00FFFFF4, 0x00FFFFF5, 0x03FFFFEA, 0x007FFFF4, // 232-239
        0x03FFFFEB, 0x07FFFFE6, 0x03FFFFEC, 0x03FFFFED, 0x07FFFFE7, 0x07FFFFE8, 0x07FFFFE9, 0x07FFFFEA, // 240-247
        0x07FFFFEB, 0x0FFFFFFE, 0x07FFFFEC, 0x07FFFFED, 0x07FFFFEE, 0x07FFFFEF, 0x07FFFFF0, 0x03FFFFEE, // 248-255
        0x3FFFFFFF,                                                                  // 256-256
    ];

    private static readonly byte[] CodeLengthTable =
    [
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,              // 0-15
        28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,              // 16-31
        6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,                      // 32-47
        5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,                           // 48-63
        13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,                             // 64-79
        7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,                          // 80-95
        15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,                             // 96-111
        6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,                         // 112-127
        20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,              // 128-143
        24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,              // 144-159
        22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,              // 160-175
        21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,              // 176-191
        26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,              // 192-207
        19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,              // 208-223
        20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,              // 224-239
        26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,              // 240-255
        30,                                                                          // 256-256
    ];

    // A binary trie over the 257 codes, two slots per node. A slot holds 0 for an absent
    // child, a positive node index for an internal one, and -(symbol + 1) for a leaf.
    //
    // Bit-at-a-time rather than a multi-bit lookup table on purpose. The decoder reads
    // attacker-chosen bytes and the thing that must be impossible is walking off the end of
    // a structure; with the completeness check below, every node has both children and
    // every step of the walk lands somewhere, so the loop needs no bounds branch at all and
    // there is no dead defensive arm to misclassify in the ledger.
    private static readonly int[] Tree;

    // The shortest code in the table, read off the transcription rather than written down.
    // It sets how far a byte can expand: at 5 bits a symbol, 8 bits of input can become at
    // most 8/5 symbols.
    private static readonly int ShortestCode;

    static TlsQuicQpackHuffman()
    {
        List<int> tree = [0, 0];
        for (int symbol = 0; symbol < CodeTable.Length; symbol++)
        {
            uint code = CodeTable[symbol];
            int length = CodeLengthTable[symbol];
            int node = 0;
            for (int bit = length - 1; bit >= 0; bit--)
            {
                int slot = (node * 2) + (int)((code >> bit) & 1);
                if (bit == 0)
                {
                    if (tree[slot] != 0)
                    {
                        throw new InvalidOperationException(
                            $"RFC 7541 Appendix B row {symbol} collides with an earlier code.");
                    }

                    tree[slot] = -(symbol + 1);
                    break;
                }

                if (tree[slot] == 0)
                {
                    tree.Add(0);
                    tree.Add(0);
                    tree[slot] = (tree.Count / 2) - 1;
                }
                else if (tree[slot] < 0)
                {
                    throw new InvalidOperationException(
                        $"RFC 7541 Appendix B row {symbol} extends an earlier code.");
                }

                node = tree[slot];
            }
        }

        // COMPLETENESS, which is what lets the decode loop have no absent-child branch.
        // Appendix B is a canonical Huffman code over 257 symbols and its lengths satisfy
        // Kraft equality exactly, so every internal node has both children and no bit
        // pattern leads nowhere. Checked here rather than assumed, once, at type load.
        for (int slot = 0; slot < tree.Count; slot++)
        {
            if (tree[slot] == 0)
            {
                throw new InvalidOperationException(
                    "RFC 7541 Appendix B is not a complete code; slot " + slot + " has no child.");
            }
        }

        Tree = [.. tree];

        int shortest = int.MaxValue;
        foreach (byte length in CodeLengthTable)
        {
            if (length < shortest)
            {
                shortest = length;
            }
        }

        ShortestCode = shortest;
    }

    // The transcribed code for each symbol, right-aligned in a uint. Read alongside
    // CodeLengths: 0x00000000 at length 5 is the five-bit code for '0' and not a zero-width
    // one, so neither array means anything without the other.
    internal static ReadOnlySpan<uint> Codes => CodeTable;

    // The bit count of each code, RFC 7541 Appendix B's bracketed column.
    internal static ReadOnlySpan<byte> CodeLengths => CodeLengthTable;

    // RFC 7541 s5.2: "The encoded data is the bitwise concatenation of the codes
    // corresponding to each octet of the string literal", then padded "up to the next octet
    // boundary". Long, because 256 octets of the widest code is 960 octets out.
    internal static int GetEncodedLength(ReadOnlySpan<byte> value)
    {
        long bits = 0;
        foreach (byte octet in value)
        {
            bits += CodeLengthTable[octet];
        }

        return (int)((bits + 7) / 8);
    }

    // The most symbols `encodedLength` octets can decode to, for sizing a destination. An
    // upper bound and not an estimate: nothing shorter than ShortestCode bits exists in the
    // table, so 8 bits of input cannot yield more than 8/ShortestCode symbols.
    internal static int GetMaximumDecodedLength(int encodedLength) =>
        (int)Math.Min(int.MaxValue, (long)encodedLength * 8 / ShortestCode);

    // RFC 7541 s5.2's encoder. The padding is the interesting half: "As the Huffman-encoded
    // data doesn't always end at an octet boundary, some padding is inserted after it, up to
    // the next octet boundary. To prevent this padding from being misinterpreted as part of
    // the string literal, the most significant bits of the code corresponding to the EOS
    // (end-of-string) symbol are used."
    //
    // Those bits are taken from row 256 of the table rather than written out as ones, so a
    // transcription that got EOS wrong would produce padding that its own decoder rejects
    // rather than a matched pair of mistakes.
    internal static bool TryEncode(ReadOnlySpan<byte> value, Span<byte> destination, out int written)
    {
        written = 0;
        int required = GetEncodedLength(value);
        if (destination.Length < required)
        {
            return false;
        }

        ulong accumulator = 0;
        int accumulated = 0;
        int index = 0;
        foreach (byte octet in value)
        {
            int length = CodeLengthTable[octet];
            accumulator = (accumulator << length) | CodeTable[octet];
            accumulated += length;
            while (accumulated >= 8)
            {
                accumulated -= 8;
                destination[index++] = (byte)(accumulator >> accumulated);
                accumulator &= (1UL << accumulated) - 1;
            }
        }

        if (accumulated > 0)
        {
            int padding = 8 - accumulated;
            uint padBits = CodeTable[EosSymbol] >> (CodeLengthTable[EosSymbol] - padding);
            destination[index++] = (byte)((accumulator << padding) | padBits);
        }

        written = index;
        return true;
    }

    // RFC 7541 s5.2's decoder, and the three MUSTs at the end of it:
    //
    //   "Upon decoding, an incomplete code at the end of the encoded data is to be
    //    considered as padding and discarded. A padding strictly longer than 7 bits MUST be
    //    treated as a decoding error. A padding not corresponding to the most significant
    //    bits of the code for the EOS symbol MUST be treated as a decoding error. A
    //    Huffman-encoded string literal containing the EOS symbol MUST be treated as a
    //    decoding error."
    //
    // Three sentences, three separate rejections, and they are separable on the wire: an
    // extra 0xFF octet is over-long padding whose bits ARE the EOS prefix, and a trailing
    // 110 is short enough but is not. Each has its own named test for that reason.
    //
    // NOTHING HERE THROWS on any `source`. A code that never terminates cannot happen -
    // the table is complete and the longest code is 30 bits, so any 30 bits reach a leaf -
    // and everything else is a bound.
    internal static bool TryDecode(
        ReadOnlySpan<byte> source,
        Span<byte> destination,
        out int written,
        out TlsQuicQpackError error)
    {
        written = 0;
        int node = 0;
        uint partial = 0;
        int depth = 0;
        int count = 0;

        foreach (byte octet in source)
        {
            for (int bit = 7; bit >= 0; bit--)
            {
                int value = (octet >> bit) & 1;
                node = Tree[(node * 2) + value];
                partial = (partial << 1) | (uint)value;
                depth++;
                if (node >= 0)
                {
                    continue;
                }

                int symbol = -node - 1;

                // "A Huffman-encoded string literal containing the EOS symbol MUST be
                // treated as a decoding error." Reached only by 30 one-bits, which is why
                // it is a rejection and not an end-of-string marker.
                if (symbol == EosSymbol)
                {
                    error = TlsQuicQpackError.EosSymbol;
                    return false;
                }

                if (count >= destination.Length)
                {
                    error = TlsQuicQpackError.DestinationTooSmall;
                    return false;
                }

                destination[count++] = (byte)symbol;
                node = 0;
                partial = 0;
                depth = 0;
            }
        }

        if (depth > 0)
        {
            // "A padding strictly longer than 7 bits MUST be treated as a decoding error."
            // A whole octet of padding is the case this catches, and its bits are perfectly
            // good EOS prefix bits, so the length is the only thing wrong with it.
            if (depth > 7)
            {
                error = TlsQuicQpackError.PaddingTooLong;
                return false;
            }

            // "A padding not corresponding to the most significant bits of the code for the
            // EOS symbol MUST be treated as a decoding error." Taken from row 256 of the
            // table rather than compared against all-ones, so this stays a statement about
            // the transcription and not about a constant that happens to match it.
            uint expected = CodeTable[EosSymbol] >> (CodeLengthTable[EosSymbol] - depth);
            if (partial != expected)
            {
                error = TlsQuicQpackError.PaddingNotEos;
                return false;
            }
        }

        written = count;
        error = TlsQuicQpackError.None;
        return true;
    }
}
