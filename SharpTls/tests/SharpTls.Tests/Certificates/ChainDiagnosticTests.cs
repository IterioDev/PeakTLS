using System.Security.Cryptography.X509Certificates;

namespace SharpTls.Tests.Certificates;

/// <summary>
/// An environmental precondition for the certificate interop tests, and the control that
/// identifies what is wrong when they fail.
/// </summary>
/// <remarks>
/// On this machine <c>X509Chain.Build</c> under the DEFAULT policy THROWS
/// <c>CryptographicException("An unknown chain building error occurred.")</c> for a TestPki leaf
/// rather than returning false, with no TLS involved. That is the same exception
/// <c>CertificateValidationTests.UntrustedRootIsRejected</c> and
/// <c>CustomTlsServerInteropTests.PlatformSslStreamClientAuthenticatesSharpTlsServerAndExchangesTraffic</c>
/// surface, so one platform behaviour explains both — it is not a protocol or profile fault.
/// <para>The test below uses CustomRootTrust and PASSES, which is what rules out the
/// certificates themselves: the chain is well formed and buildable. Should this one ever start
/// failing, the certificate interop failures are the machine, not the library.</para>
/// </remarks>
public sealed class ChainDiagnosticTests
{
    [Fact]
    public void PlatformBuildsTheTestPkiChainUnderCustomRootTrust()
    {
        using var pki = TestPki.Create();
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(pki.Root);

        var built = chain.Build(pki.Leaf);
        var status = string.Join(
            ", ",
            chain.ChainStatus.Select(entry => $"{entry.Status}: {entry.StatusInformation.Trim()}"));
        Assert.True(built, $"X509Chain.Build failed with: {status}");
    }
}
