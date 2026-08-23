using SharpTls;

namespace TlsClient.Tests;

public sealed class TlsProfileTests
{
    [Theory]
    [MemberData(nameof(BrowserProfiles))]
    public void Http11Profile_AdvertisesOnlyHttp11(TlsProfile profile)
    {
        var spec = profile.Http11ClientHello.Spec;

        Assert.Equal(["http/1.1"], spec.AlpnProtocols);
        Assert.DoesNotContain(
            spec.Extensions,
            extension => extension.BuiltInKind == ClientHelloExtensionKind.ApplicationSettings);
    }

    // WAS SEVEN BROWSER FAMILIES. They went with the uTLS profiles they were built on, and
    // the claim survives them: whatever profiles remain, an http/1.1 ClientHello must offer
    // http/1.1 alone and must not carry ALPS, which is an HTTP/2 extension.
    public static TheoryData<TlsProfile> BrowserProfiles => new()
    {
        TlsProfiles.Modern,
        TlsProfiles.Spotify917602050IOS270Quic,
    };
}
