using System.Collections.Immutable;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// TlsQuicHttp3Request.TryEncode's five-argument overload: the header section comes from the
// policy's plan, the trailer section stays static-only, and without a policy the bytes are
// the three-argument overload's, byte for byte.
public sealed class TlsQuicHttp3RequestPolicyTests
{
    private static TlsQuicHttp3Request Post(params (string Name, string Value)[] fields) =>
        Post(trailers: [], fields);

    private static TlsQuicHttp3Request Post(
        ImmutableArray<TlsQuicHttp3Field> trailers, params (string Name, string Value)[] fields) => new()
    {
        Method = "POST",
        Authority = "spclient.wg.spotify.com",
        Scheme = "https",
        Path = "/a",
        Fields = [.. fields.Select(f => new TlsQuicHttp3Field(f.Name, f.Value))],
        Body = [1, 2, 3],
        Trailers = trailers,
    };

    private static TlsQuicQpackEncoderPolicy ActivePolicy(TlsQuicHttp3Spec spec)
    {
        var policy = new TlsQuicQpackEncoderPolicy(spec);
        Assert.False(policy.OnPeerSettings(4096, 16).IsEmpty);
        return policy;
    }

    private static List<(ulong Type, byte[] Payload)> ReadFrames(List<byte> encoded)
    {
        var bytes = encoded.ToArray();
        var frames = new List<(ulong, byte[])>();
        var offset = 0;
        while (offset < bytes.Length)
        {
            var status = TlsQuicHttp3Frames.TryRead(bytes, ref offset, out var type, out var payload, out var error);
            Assert.Equal(TlsQuicHttp3FrameReadStatus.Complete, status);
            Assert.Equal(TlsQuicHttp3ErrorCode.None, error);
            frames.Add((type, payload.ToArray()));
        }

        return frames;
    }

    [Fact]
    public void WithoutAPolicyTheTwoOverloadsAgreeByteForByte()
    {
        var spec = new TlsQuicHttp3Spec();
        var request = Post(("content-length", "3"), ("x-a", "1"));

        var three = new List<byte>();
        Assert.True(request.TryEncode(three, spec, out _));
        var five = new List<byte>();
        Assert.True(request.TryEncodeWithPolicy(five, spec, null, out var plan, out _));

        Assert.Null(plan);
        Assert.Equal(three, five);
    }

    [Fact]
    public void WithAnInactivePolicyTheBytesAreStillTheStaticOnes()
    {
        var spec = new TlsQuicHttp3Spec { QpackEncoderDynamicTableCapacity = 4096, QpackInsertPolicy = TlsQuicQpackInsertPolicy.OnSecondUse };
        var policy = new TlsQuicQpackEncoderPolicy(spec);   // no peer SETTINGS yet
        var request = Post(("content-length", "3"), ("x-a", "1"));

        var three = new List<byte>();
        Assert.True(request.TryEncode(three, spec, out _));
        var five = new List<byte>();
        Assert.True(request.TryEncodeWithPolicy(five, spec, policy, out var plan, out _));

        Assert.NotNull(plan);
        Assert.True(plan.EncoderStreamBytes.IsEmpty);
        Assert.Equal(three, five);
    }

    [Fact]
    public void WithAnActivePolicyTheHeaderSectionIsThePlansAndTheTrailerSectionStaysStatic()
    {
        var spec = new TlsQuicHttp3Spec { QpackEncoderDynamicTableCapacity = 4096, QpackInsertPolicy = TlsQuicQpackInsertPolicy.OnSecondUse };
        var policy = ActivePolicy(spec);
        var request = Post(
            trailers: [new TlsQuicHttp3Field("x-trailer", "t")],
            ("content-length", "3"),
            ("x-a", "1"));

        // First use: seen, static. Second use: inserts.
        var first = new List<byte>();
        Assert.True(request.TryEncodeWithPolicy(first, spec, policy, out var firstPlan, out _));
        policy.Commit(firstPlan!, 0);
        var second = new List<byte>();
        Assert.True(request.TryEncodeWithPolicy(second, spec, policy, out var secondPlan, out _));

        Assert.NotEmpty(secondPlan!.Inserts);
        var frames = ReadFrames(second);
        Assert.Equal(3, frames.Count);                                  // HEADERS, DATA, HEADERS
        Assert.Equal((ulong)TlsQuicHttp3FrameType.Headers, frames[0].Type);
        Assert.Equal(secondPlan.FieldSection.ToArray(), frames[0].Payload);
        Assert.NotEqual(0, frames[0].Payload[0]);                       // a non-zero Required Insert Count
        Assert.Equal((ulong)TlsQuicHttp3FrameType.Headers, frames[2].Type);
        Assert.Equal(new byte[] { 0x00, 0x00 }, frames[2].Payload[..2]); // trailers: static prefix

        // Nothing was committed by encoding: the plan is the caller's to apply.
        Assert.Equal(1, policy.UseCount("x-a"u8, "1"u8));
    }

    [Fact]
    public void TheSpecRefusesAnOutOfRangeCapacityAndUndefinedPolicies()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicHttp3Spec { QpackEncoderDynamicTableCapacity = -1 });
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicHttp3Spec { QpackEncoderDynamicTableCapacity = 1 << 30 });
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicHttp3Spec { QpackInsertPolicy = (TlsQuicQpackInsertPolicy)7 });
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicHttp3Spec { UnidirectionalStreamOpening = (TlsQuicHttp3UnidirectionalStreamOpening)7 });

        var spec = new TlsQuicHttp3Spec { QpackEncoderDynamicTableCapacity = (1 << 30) - 1 };
        Assert.Equal((1 << 30) - 1, spec.QpackEncoderDynamicTableCapacity);
        Assert.Equal(TlsQuicQpackInsertPolicy.Never, spec.QpackInsertPolicy);
        Assert.Equal(TlsQuicHttp3UnidirectionalStreamOpening.AtConnectionStart, spec.UnidirectionalStreamOpening);
    }
}
