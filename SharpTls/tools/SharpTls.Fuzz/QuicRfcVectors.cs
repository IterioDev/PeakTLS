namespace SharpTls.Fuzzing;

// The one IETF-published frame-level vector this phase has, in the one place
// every assembly that needs it can reach.
//
// WHY THIS FILE EXISTS. A2 task 3b needed RFC 9001 Appendix A.2's 245-byte
// CRYPTO frame in a second test class and widened TlsQuicPacketProtectionTests'
// constant from private to internal rather than transcribing 245 bytes of hex
// twice. That was the right call and it does not survive task 7:
// tools/SharpTls.Fuzz is a different assembly, and `internal` on a test class
// is invisible from it. The alternative - a third transcription - is exactly
// the copy that goes wrong silently, which is what task 3b avoided.
//
// WHY IT HOLDS BYTES AND NOT TYPES, WHICH IS THE WHOLE CONSTRAINT.
// tests/SharpTls.Tests does NOT project-reference tools/SharpTls.Fuzz; it
// source-links ProtocolFuzzTargets.cs through a <Compile Include=... Link=.../>
// item, and this file is linked the same way. So this source compiles into both
// assemblies and yields two distinct CLR types that happen to share a name.
// Values cross that boundary fine; the types do not. Everything below is
// therefore a `const string`, a `const int`, or a method returning `byte[]` -
// primitives and a framework type - and nothing declared in this file ever
// appears in a signature. Adding, say, a `readonly record struct QuicVector`
// here and returning it would compile in each assembly separately and fail the
// moment one handed a value to the other.
//
// Extracted mechanically from
// docs/superpowers/specs/reference-captures/rfc9001-appendix-a-test-vectors.txt,
// never retyped.
//
// THE NEXT ADDITION GOES HERE, NOT IN A THIRD PLACE. A3 (RFC 9002 loss
// detection) and C (RFC 9114/9204 HTTP/3 and QPACK) will each want their own
// IETF-published vectors in more than one assembly, for the same reason this
// file exists. Add them beside these, as another `const string`/`byte[]`
// pair with its own RFC citation - bytes only, never a type, per the header
// above.
internal static class QuicRfcVectors
{
    // The CRYPTO frame RFC 9001 Appendix A.2 prints explicitly (245 bytes):
    // frame type 0x06, Offset 0x00, Length 0x40f1 (a 2-byte varint for 241),
    // then 241 bytes of ClientHello. Pinned as a frame by
    // TlsQuicStreamFramesTests.Rfc9001AppendixA2ClientInitialCryptoFrameParses
    // ToItsPublishedOffsetAndLength, and as AEAD plaintext by
    // TlsQuicPacketProtectionTests.AppendixA2ClientInitialSealProducesPublished
    // Ciphertext.
    internal const string A2CryptoFrameHex =
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b" +
        "69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff0100010" +
        "0000a00080006001d0017001800100007000504616c706e0005000501000000000033002600240" +
        "01d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000" +
        "3020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900" +
        "320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f08839" +
        "4c8f03e51570806048000ffff";

    /// <summary>
    /// The declared payload length of RFC 9001 Appendix A.2's client Initial:
    /// the CRYPTO frame above plus PADDING out to this many bytes.
    /// </summary>
    internal const int A2PayloadLength = 1162;

    /// <summary>
    /// The number of PADDING frames RFC 9001 Appendix A.2's payload carries
    /// after its CRYPTO frame. RFC 9000 s19.1 makes PADDING a single zero byte
    /// with no body, and this reader yields one frame per byte rather than
    /// coalescing a run, so the payload is 1 CRYPTO frame + this many frames.
    /// </summary>
    internal const int A2PaddingFrameCount = A2PayloadLength - 245;

    /// <summary>
    /// RFC 9001 Appendix A.2's complete client Initial plaintext: the published
    /// CRYPTO frame followed by PADDING to <see cref="A2PayloadLength"/>.
    /// </summary>
    internal static byte[] BuildA2Plaintext()
    {
        var plaintext = new byte[A2PayloadLength];
        Convert.FromHexString(A2CryptoFrameHex).CopyTo(plaintext, 0);
        // Remaining bytes stay zero: the RFC says the payload is this frame
        // "plus enough PADDING frames to make a 1162-byte payload", and RFC
        // 9000 s19.1 makes PADDING frame type 0x00, one byte, no body. So the
        // 917 trailing bytes are already correct as allocated, and are not
        // transcribed by hand.
        return plaintext;
    }

    /// <summary>RFC 9001 Appendix A.2's CRYPTO frame on its own, with no PADDING after it.</summary>
    internal static byte[] BuildA2CryptoFrame() => Convert.FromHexString(A2CryptoFrameHex);

    // ------------------------------------------------------------------------
    // RFC 9204 Appendix B - the ONLY worked QPACK vectors the RFC publishes.
    //
    // Taken from docs/superpowers/specs/reference-captures/
    // rfc9204-appendix-b-encoding-and-decoding-examples.txt, left-hand hex only,
    // annotations dropped. Every one of these is peer-controlled input on the
    // wire: B.1-B.5's encoder-stream bytes are what a hostile server's encoder
    // sends us, and their field sections are what its HEADERS frames carry.
    //
    // WHY THE FUZZER NEEDS THEM AND NOT JUST RANDOM BYTES. A field section that
    // references the dynamic table cannot be reached by mutating noise: the
    // s4.5.1.1 prefix has to reconstruct to a Required Insert Count the table
    // can satisfy before ANY representation is read, so a fuzzer with no valid
    // section to mutate from never gets past the prefix and the whole dynamic
    // arm is dead code the campaign never sees. That is the certificate-
    // compression failure - a target that appeared to cover three algorithms
    // covered one - restated for QPACK. These five examples are the anchors
    // the mutation walk starts from.
    // ------------------------------------------------------------------------

    /// <summary>B.1's encoded field section: prefix 0/0 then one Literal Field Line with
    /// Name Reference into static index 1, <c>:path=/index.html</c>.</summary>
    internal const string QpackB1FieldSectionHex = "0000510b2f696e6465782e68746d6c";

    /// <summary>B.2's encoder stream: Set Dynamic Table Capacity=220, then two Insert With
    /// Name Reference instructions against static indices 0 and 1.</summary>
    internal const string QpackB2EncoderStreamHex =
        "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468";

    /// <summary>B.2's field section: Required Insert Count = 2, Base = 0, then two Indexed
    /// Field Line With Post-Base Index representations. THE ONLY PUBLISHED POST-BASE
    /// VECTOR.</summary>
    internal const string QpackB2FieldSectionHex = "03811011";

    /// <summary>B.3's encoder stream: one Insert With Literal Name
    /// (<c>custom-key=custom-value</c>).</summary>
    internal const string QpackB3EncoderStreamHex =
        "4a637573746f6d2d6b65790c637573746f6d2d76616c7565";

    /// <summary>B.4's encoder stream: Duplicate with Relative Index = 2.</summary>
    internal const string QpackB4EncoderStreamHex = "02";

    /// <summary>B.4's field section: Required Insert Count = 4, Base = 4, then an Indexed
    /// Field Line against the dynamic table, an Indexed Field Line against the static table,
    /// and a second dynamic one. THE ONLY PUBLISHED FIELD-RELATIVE VECTOR.</summary>
    internal const string QpackB4FieldSectionHex = "050080c181";

    /// <summary>B.5's encoder stream: Insert With Name Reference against DYNAMIC relative
    /// index 1, which evicts the oldest entry.</summary>
    internal const string QpackB5EncoderStreamHex = "810d637573746f6d2d76616c756532";

    /// <summary>B.2's Section Acknowledgment for stream 4, B.3's Insert Count Increment of 1,
    /// and B.4's Stream Cancellation for stream 8, in that order - the three decoder
    /// instructions Appendix B publishes.</summary>
    internal const string QpackAppendixBDecoderInstructionsHex = "840148";

    /// <summary>
    /// Appendix B's encoder stream in publication order: B.2, B.3, B.4, B.5 concatenated.
    /// Replaying this whole run against one table walks every s4.3 instruction - capacity,
    /// both name-reference forms, literal name, duplicate - and ends in B.5's eviction.
    /// </summary>
    internal static byte[] BuildQpackAppendixBEncoderStream() =>
        Convert.FromHexString(
            QpackB2EncoderStreamHex +
            QpackB3EncoderStreamHex +
            QpackB4EncoderStreamHex +
            QpackB5EncoderStreamHex);

    /// <summary>Appendix B's encoder stream up to and including B.4's Duplicate - the state
    /// B.4's field section is decoded against, before B.5 evicts anything.</summary>
    internal static byte[] BuildQpackAppendixBEncoderStreamThroughB4() =>
        Convert.FromHexString(
            QpackB2EncoderStreamHex + QpackB3EncoderStreamHex + QpackB4EncoderStreamHex);
}
