using System.Text;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

/// <content>
/// RFC 9204 section 4.1.2's H bit as a three-valued policy. It was a <see langword="bool"/>,
/// and the two values a bool can take are the two policies no deployed encoder uses: Chrome and
/// nghttp2 both emit whichever form is shorter for each string.
///
/// EVERY CASE ENCODES ONE FIELD LINE WHOSE NAME IS A STATIC-TABLE REFERENCE, so the only string
/// literal in the output is the value. The policy applies to the name as well, and a name that
/// was itself a literal would make a whole-output comparison say "these differ" without saying
/// which half differed.
/// </content>
public sealed class TlsQuicQpackHuffmanPolicyTests
{
    // Lowercase ASCII is what RFC 7541 Appendix B's code is weighted for, so it codes SHORTER.
    private static ReadOnlySpan<byte> Compressible => "application/json; charset=utf-8"u8;

    // Octets at or above 0x80 have no short code at all in Appendix B - they cost far more than
    // the eight bits they replace - so this codes LONGER. RFC 9110 s5.5's obs-text makes such a
    // field value legal, and a binary-ish header is where an encoder's policy shows.
    private static byte[] Incompressible { get; } =
        [.. Enumerable.Range(0, 24).Select(i => (byte)(0x80 + i))];

    private static byte[] Encode(ReadOnlySpan<byte> value, TlsQuicQpackHuffmanPolicy policy)
    {
        var buffer = new byte[512];
        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldLine(
            ":authority"u8, value, policy, preferNameReference: true, buffer, out var written));
        return buffer[..written];
    }

    [Fact]
    public void TheTwoSamplesReallyDoCompressInOppositeDirections()
    {
        // ASSERTED, NOT ASSUMED. Every test below is meaningless if these two samples do not
        // actually straddle the break-even point, and a Huffman table change would move it
        // without touching a line of policy code.
        Assert.True(
            TlsQuicQpackHuffman.GetEncodedLength(Compressible) < Compressible.Length);
        Assert.True(
            TlsQuicQpackHuffman.GetEncodedLength(Incompressible) > Incompressible.Length);
    }

    [Fact]
    public void ShorterOfTheTwoTakesTheHuffmanFormOnlyWhenItIsActuallyShorter()
    {
        // BYTE IDENTITY WITH THE POLICY THAT WOULD HAVE BEEN RIGHT, in both directions. An
        // assertion on length alone would pass for an encoder that chose correctly and then
        // wrote a different header.
        Assert.Equal(
            Encode(Compressible, TlsQuicQpackHuffmanPolicy.Always),
            Encode(Compressible, TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo));
        Assert.Equal(
            Encode(Incompressible, TlsQuicQpackHuffmanPolicy.Never),
            Encode(Incompressible, TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo));

        // ...and it is a CHOICE rather than an alias for one of them: the same policy disagrees
        // with each of the other two on one of the two samples.
        Assert.NotEqual(
            Encode(Incompressible, TlsQuicQpackHuffmanPolicy.Always),
            Encode(Incompressible, TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo));
        Assert.NotEqual(
            Encode(Compressible, TlsQuicQpackHuffmanPolicy.Never),
            Encode(Compressible, TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo));
    }

    [Fact]
    public void AlwaysStillEmitsTheHuffmanFormWhenItIsLonger()
    {
        // The old bool's `true` behaviour, kept as a member rather than dropped: a client that
        // really does code unconditionally has to remain expressible.
        Assert.True(
            Encode(Incompressible, TlsQuicQpackHuffmanPolicy.Always).Length
                > Encode(Incompressible, TlsQuicQpackHuffmanPolicy.Never).Length);
    }

    [Fact]
    public void AnEmptyValueTakesTheLiteralFormUnderShorterOfTheTwo()
    {
        // 0 < 0 is false, so the tie goes to the literal - which is what nghttp2 emits for an
        // empty string, and the boundary a `<=` would silently move.
        Assert.Equal(
            Encode(default, TlsQuicQpackHuffmanPolicy.Never),
            Encode(default, TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo));
    }

    [Fact]
    public void TheChoiceIsPerStringAndNotPerConnection()
    {
        // s4.1.2's H bit is on each string literal, so one field section can carry both forms.
        // A policy resolved once per connection - which is what the bool was - cannot produce
        // this, and this is the shape a real request has: a compressible content-type beside an
        // incompressible token.
        var mixed = new byte[512];
        var written = 0;

        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldLine(
            ":authority"u8,
            Compressible,
            TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo,
            preferNameReference: true,
            mixed,
            out var first));
        written += first;

        Assert.True(TlsQuicQpackEncoder.TryEncodeFieldLine(
            ":authority"u8,
            Incompressible,
            TlsQuicQpackHuffmanPolicy.ShorterOfTheTwo,
            preferNameReference: true,
            mixed.AsSpan(written),
            out var second));

        Assert.Equal(
            Encode(Compressible, TlsQuicQpackHuffmanPolicy.Always),
            mixed[..first]);
        Assert.Equal(
            Encode(Incompressible, TlsQuicQpackHuffmanPolicy.Never),
            mixed[written..(written + second)]);
    }
}
