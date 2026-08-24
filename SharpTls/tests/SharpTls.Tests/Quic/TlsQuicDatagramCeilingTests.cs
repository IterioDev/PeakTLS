namespace SharpTls.Tests.Quic;

using System.Net.Sockets;
using SharpTls.Quic;

/// <summary>
/// The advertised datagram ceiling must be one a socket of that family actually accepts.
/// </summary>
/// <remarks>
/// RFC 9000 s18.2's 65527 is the protocol maximum and is reachable only over IPv6. An IPv4
/// socket refuses anything above 65507 with SocketError.MessageSize (WSAEMSGSIZE 10040), so a
/// transport that advertised 65527 on IPv4 overstated its ceiling by 20 bytes and turned a
/// caller's legal-looking datagram into a socket exception it could not have predicted.
/// </remarks>
public sealed class TlsQuicDatagramCeilingTests
{
    [Fact]
    public void TheAdvertisedCeilingMatchesWhatTheFamilyAccepts()
    {
        Assert.Equal(65507, TlsQuicUdpDatagramTransport.MaximumFor(AddressFamily.InterNetwork));
        Assert.Equal(65527, TlsQuicUdpDatagramTransport.MaximumFor(AddressFamily.InterNetworkV6));

        // Non-vacuous: the two families must not agree, or this test would pass on a transport
        // that had gone back to reporting one number for both.
        Assert.NotEqual(
            TlsQuicUdpDatagramTransport.MaximumFor(AddressFamily.InterNetwork),
            TlsQuicUdpDatagramTransport.MaximumFor(AddressFamily.InterNetworkV6));
    }

    [Theory]
    [InlineData(AddressFamily.InterNetwork)]
    [InlineData(AddressFamily.InterNetworkV6)]
    public async Task ATransportOfEachFamilyAdvertisesItsOwnCeiling(AddressFamily family)
    {
        await using var transport = TlsQuicUdpDatagramTransport.Create(family);

        Assert.Equal(
            TlsQuicUdpDatagramTransport.MaximumFor(family),
            transport.MaxDatagramPayloadSize);
    }

    /// <summary>
    /// The ceiling is a claim about a real socket, so it is checked against one. This is the
    /// measurement the constants came from rather than a number copied out of a document.
    /// </summary>
    [Theory]
    [InlineData(AddressFamily.InterNetwork)]
    [InlineData(AddressFamily.InterNetworkV6)]
    public void TheSocketAcceptsTheCeilingAndRefusesOneByteMore(AddressFamily family)
    {
        var ceiling = TlsQuicUdpDatagramTransport.MaximumFor(family);
        using var socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        var destination = new System.Net.IPEndPoint(
            family == AddressFamily.InterNetworkV6
                ? System.Net.IPAddress.IPv6Loopback
                : System.Net.IPAddress.Loopback,
            9);

        socket.SendTo(new byte[ceiling], destination);

        if (ceiling < TlsQuicUdpDatagramTransport.MaximumUdpPayload)
        {
            var tooLarge = Assert.Throws<SocketException>(
                () => socket.SendTo(new byte[ceiling + 1], destination));
            Assert.Equal(SocketError.MessageSize, tooLarge.SocketErrorCode);
        }
    }
}
