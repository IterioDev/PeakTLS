namespace SharpTls.Tests.ClientHello;

/// <summary>
/// A wire pin for the one shipped capture profile. This file exists because there was NOT one:
/// the per-profile snapshots that used to cover the catalogue lived in the uTLS profile test
/// files, and those were deleted along with the 52 uTLS profiles. Between that deletion and this
/// test, the profile's cipher order could be edited and the whole suite still went green.
/// </summary>
public sealed class SpotifyIosQuicProfileWireTests
{
    private static byte[] Hello() =>
        ClientHelloProfiles.Spotify917602050IOS270Quic
            .BuildDeterministicForTesting("gew4-spclient.spotify.com", [7, 7, 4, 2]);

    [Fact]
    public void CipherSuitesReachTheWireInTheProxyCapturedOrder()
    {
        // 0x1302, 0x1303, 0x1301. Asserting the superseded direct-capture order is ABSENT is the
        // half that bites: the three codepoints are identical between the two orders, so a test
        // that only looked for their presence would pass on either.
        Assert.Contains(Convert.ToHexString([0x13, 0x02, 0x13, 0x03, 0x13, 0x01]), Hex());
        Assert.DoesNotContain(Convert.ToHexString([0x13, 0x02, 0x13, 0x01, 0x13, 0x03]), Hex());
    }

    [Fact]
    public void TheVendorTransportParameterIsPresentAndTrailsTheKnownOnes()
    {
        // 0xff080808 needs the 8-byte varint form (0xc0 prefix) because it exceeds 2^30 - 1;
        // then length 0x01, then payload 0x09. Ten bytes, which is exactly the second Initial
        // CRYPTO frame's 487 -> 497 growth that identified this parameter in the first place.
        var hex = Hex();
        var vendor = Convert.ToHexString([0xC0, 0x00, 0x00, 0x00, 0xFF, 0x08, 0x08, 0x08, 0x01, 0x09]);
        Assert.Contains(vendor, hex);

        // 0x0F (initial_source_connection_id, empty) is the last of the seven known parameters,
        // so the vendor entry must come after it rather than anywhere earlier in the block.
        Assert.True(
            hex.IndexOf(vendor, StringComparison.Ordinal) > hex.IndexOf("0F00", StringComparison.Ordinal),
            "the vendor transport parameter did not trail the known ones");
    }

    private static string Hex() => Convert.ToHexString(Hello());
}
