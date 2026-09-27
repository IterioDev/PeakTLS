namespace TlsClient.Tests;

public sealed class TlsProxyMasqueTests
{
    [Fact]
    public void MasqueTakesAnHttpsAddressWithAnExplicitPort()
    {
        var proxy = TlsProxy.Masque("https://masque.oxylabs.io:50000", "customer-u", "p");

        Assert.Equal(TlsProxyType.Masque, proxy.Type);
        Assert.Equal(50000, proxy.EffectivePort);
        Assert.Equal("customer-u", proxy.Credentials!.UserName);
        Assert.Equal("p", proxy.Credentials.Password);
        Assert.Null(proxy.GetBasicAuthorizationValue()); // that helper is HTTP CONNECT's; MASQUE builds its own header
    }

    [Theory]
    [InlineData("https://masque.oxylabs.io")]      // no port
    [InlineData("http://masque.oxylabs.io:50000")] // wrong scheme
    public void MasqueRejectsAnAddressWithoutAPortOrWithAnotherScheme(string address) =>
        Assert.Throws<ArgumentException>(() => TlsProxy.Masque(address, "u", "p"));

    [Fact]
    public void TheEnumValueIsThree() => Assert.Equal(3, (int)TlsProxyType.Masque);
}
