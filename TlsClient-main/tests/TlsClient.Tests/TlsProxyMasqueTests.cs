namespace TlsClient.Tests;

public sealed class TlsProxyMasqueTests
{
    [Fact]
    public void MasqueTakesAnHttpsAddressWithAnExplicitPort()
    {
        var configure = new Action<TlsQuicOptions>(_ => { });
        var proxy = TlsProxy.Masque("https://masque.example:50000", "customer-u", "p", configure);

        Assert.Equal(TlsProxyType.Masque, proxy.Type);
        Assert.Equal(50000, proxy.EffectivePort);
        Assert.Equal("customer-u", proxy.Credentials!.UserName);
        Assert.Equal("p", proxy.Credentials.Password);
        Assert.Null(proxy.GetBasicAuthorizationValue()); // that helper is HTTP CONNECT's; MASQUE builds its own header
        Assert.Same(configure, proxy.ConfigureOuterQuic);
    }

    [Theory]
    [InlineData("https://masque.example")]      // no port
    [InlineData("https://masque.example:443")]  // explicit default port
    [InlineData("http://masque.example:50000")] // wrong scheme
    public void MasqueRejectsAnAddressWithoutAPortOrWithAnotherScheme(string address) =>
        Assert.Throws<ArgumentException>(() => TlsProxy.Masque(address, "u", "p"));

    [Fact]
    public void TheEnumValueIsThree() => Assert.Equal(3, (int)TlsProxyType.Masque);
}
