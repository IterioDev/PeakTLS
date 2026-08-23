using System.Net;
using System.Net.Sockets;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicSocks5ProtocolTests
{
    [Fact]
    public void ProxyExceptionCarriesItsError()
    {
        var exception = new TlsQuicProxyException(
            TlsQuicProxyError.CredentialsRejected,
            "rejected");

        Assert.Equal(TlsQuicProxyError.CredentialsRejected, exception.Error);
        Assert.Equal("rejected", exception.Message);
        Assert.IsAssignableFrom<IOException>(exception);
    }

    [Fact]
    public void GreetingOffersNoAuthenticationOnlyWithoutCredentials()
    {
        // RFC 1928 s3: VER | NMETHODS | METHODS
        Assert.Equal(
            new byte[] { 0x05, 0x01, 0x00 },
            TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: false));
    }

    [Fact]
    public void GreetingOffersBothMethodsWithCredentials()
    {
        Assert.Equal(
            new byte[] { 0x05, 0x02, 0x00, 0x02 },
            TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: true));
    }

    // 0xFF (NO ACCEPTABLE METHODS) is returned, not thrown: mapping it to a
    // failure is the transport's job, so the codec stays free of policy.
    [Theory]
    [InlineData(0x00)]
    [InlineData(0x02)]
    [InlineData(0xFF)]
    public void MethodSelectionReturnsTheChosenMethod(byte method)
    {
        Assert.Equal(
            method,
            TlsQuicSocks5Protocol.ParseMethodSelection([0x05, method]));
    }

    [Fact]
    public void MethodSelectionRejectsWrongVersion()
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ParseMethodSelection([0x04, 0x00]));

        Assert.Equal(TlsQuicProxyError.MalformedProxyResponse, exception.Error);
    }

    [Theory]
    [InlineData(new byte[] { 0x05 })]
    [InlineData(new byte[] { 0x05, 0x00, 0x00 })]
    [InlineData(new byte[0])]
    public void MethodSelectionRejectsWrongLength(byte[] response)
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ParseMethodSelection(response));

        Assert.Equal(TlsQuicProxyError.MalformedProxyResponse, exception.Error);
    }

    [Fact]
    public void AuthenticationRequestMatchesRfc1929Layout()
    {
        // RFC 1929 s2: VER | ULEN | UNAME | PLEN | PASSWD, VER is 0x01.
        Assert.Equal(
            new byte[] { 0x01, 0x02, (byte)'a', (byte)'b', 0x03, (byte)'x', (byte)'y', (byte)'z' },
            TlsQuicSocks5Protocol.EncodeAuthenticationRequest("ab", "xyz"));
    }

    [Theory]
    [InlineData("", "password")]
    [InlineData("username", "")]
    public void AuthenticationRequestRejectsEmptyFields(string username, string password)
    {
        // RFC 1929 gives ULEN and PLEN a range of 1 to 255, so zero is unrepresentable.
        Assert.Throws<ArgumentException>(
            () => TlsQuicSocks5Protocol.EncodeAuthenticationRequest(username, password));
    }

    [Fact]
    public void AuthenticationRequestRejectsOversizedFields()
    {
        Assert.Throws<ArgumentException>(
            () => TlsQuicSocks5Protocol.EncodeAuthenticationRequest(new string('u', 256), "p"));
        Assert.Throws<ArgumentException>(
            () => TlsQuicSocks5Protocol.EncodeAuthenticationRequest("u", new string('p', 256)));
    }

    [Fact]
    public void AuthenticationRequestMeasuresUtf8BytesNotCharacters()
    {
        // A 128-character string of 2-byte code points is 256 bytes and must be rejected.
        Assert.Throws<ArgumentException>(
            () => TlsQuicSocks5Protocol.EncodeAuthenticationRequest(new string('é', 128), "p"));
    }

    [Fact]
    public void AuthenticationRequestAcceptsMaximumLengthFields()
    {
        // 255 bytes is the largest representable value, and must NOT be rejected.
        var encoded = TlsQuicSocks5Protocol.EncodeAuthenticationRequest(
            new string('u', 255), new string('p', 255));

        Assert.Equal(3 + 255 + 255, encoded.Length);
        Assert.Equal(0xFF, encoded[1]);
        Assert.Equal(0xFF, encoded[2 + 255]);
    }

    [Fact]
    public void AuthenticationSuccessIsAccepted()
    {
        TlsQuicSocks5Protocol.ValidateAuthenticationReply([0x01, 0x00]);
    }

    [Fact]
    public void AuthenticationFailureIsRejected()
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ValidateAuthenticationReply([0x01, 0x01]));

        Assert.Equal(TlsQuicProxyError.CredentialsRejected, exception.Error);
    }

    [Theory]
    [InlineData(new byte[] { 0x05, 0x00 })]     // wrong subnegotiation version
    [InlineData(new byte[] { 0x01 })]           // truncated
    [InlineData(new byte[] { 0x01, 0x00, 0x00 })] // over-long
    [InlineData(new byte[0])]
    public void AuthenticationReplyRejectsMalformedInput(byte[] reply)
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ValidateAuthenticationReply(reply));

        Assert.Equal(TlsQuicProxyError.MalformedProxyResponse, exception.Error);
    }

    // Tripwire, not a behavioural test: this method never receives credentials today.
    // It exists so that adding them to the message for debuggability fails loudly.
    [Fact]
    public void AuthenticationFailureMessageDoesNotLeakCredentials()
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ValidateAuthenticationReply([0x01, 0x01]));

        Assert.DoesNotContain("password", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AssociateRequestSendsAllZeroAddressForIPv4()
    {
        // RFC 1928 s4: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT.
        // Zeros are sent because a bound local port is rewritten by NAT.
        Assert.Equal(
            new byte[] { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 },
            TlsQuicSocks5Protocol.EncodeAssociateRequest(AddressFamily.InterNetwork));
    }

    [Fact]
    public void AssociateRequestSendsAllZeroAddressForIPv6()
    {
        var expected = new byte[4 + 16 + 2];
        expected[0] = 0x05;
        expected[1] = 0x03;
        expected[3] = 0x04;

        Assert.Equal(
            expected,
            TlsQuicSocks5Protocol.EncodeAssociateRequest(AddressFamily.InterNetworkV6));
    }

    [Theory]
    [InlineData(0x01)]
    [InlineData(0x02)]
    [InlineData(0x03)]
    [InlineData(0x04)]
    [InlineData(0x05)]
    [InlineData(0x06)]
    [InlineData(0x07)]
    [InlineData(0x08)]
    public void AssociateReplyHeaderRejectsEveryFailureCode(byte reply)
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ValidateAssociateReplyHeader([0x05, reply, 0x00, 0x01]));

        Assert.Equal(TlsQuicProxyError.AssociateRejected, exception.Error);
        Assert.Contains($"0x{reply:X2}", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AssociateReplyHeaderRejectsWrongVersion()
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ValidateAssociateReplyHeader([0x04, 0x00, 0x00, 0x01]));

        Assert.Equal(TlsQuicProxyError.MalformedProxyResponse, exception.Error);
    }

    [Theory]
    [InlineData(new byte[] { 0x05, 0x00, 0x00 })]
    [InlineData(new byte[] { 0x05, 0x00, 0x00, 0x01, 0x00 })]
    [InlineData(new byte[0])]
    public void AssociateReplyHeaderRejectsWrongLength(byte[] header)
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ValidateAssociateReplyHeader(header));

        Assert.Equal(TlsQuicProxyError.MalformedProxyResponse, exception.Error);
    }

    [Fact]
    public void AssociateReplyHeaderAcceptsSuccessAndReturnsAddressType()
    {
        Assert.Equal(
            0x01,
            TlsQuicSocks5Protocol.ValidateAssociateReplyHeader([0x05, 0x00, 0x00, 0x01]));
        Assert.Equal(
            0x04,
            TlsQuicSocks5Protocol.ValidateAssociateReplyHeader([0x05, 0x00, 0x00, 0x04]));
    }

    [Fact]
    public void AssociateReplyHeaderIgnoresNonZeroReserved()
    {
        // RSV is deliberately unchecked: RFC 1928 marks it RESERVED without mandating
        // a reply-path value and deployed relays have been observed setting it.
        // This pins that decision so it cannot be "fixed" back into an interop break.
        Assert.Equal(
            0x01,
            TlsQuicSocks5Protocol.ValidateAssociateReplyHeader([0x05, 0x00, 0xFF, 0x01]));
    }

    [Fact]
    public void RelayEndPointUsesTheAddressTheProxyReturned()
    {
        var relay = TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            TlsQuicSocks5Protocol.AddressIPv4,
            [203, 0, 113, 9],
            port: 1080,
            proxyAddress: IPAddress.Parse("198.51.100.1"));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.9"), 1080), relay);
    }

    [Fact]
    public void RelayEndPointSubstitutesTheProxyForAWildcardAddress()
    {
        // Many relays answer 0.0.0.0, meaning "the host you are already talking to".
        var relay = TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            TlsQuicSocks5Protocol.AddressIPv4,
            [0, 0, 0, 0],
            port: 1080,
            proxyAddress: IPAddress.Parse("198.51.100.1"));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("198.51.100.1"), 1080), relay);
    }

    [Fact]
    public void RelayEndPointUsesARealIPv6Address()
    {
        var address = IPAddress.Parse("2001:db8::1").GetAddressBytes();

        var relay = TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            TlsQuicSocks5Protocol.AddressIPv6,
            address,
            port: 1080,
            proxyAddress: IPAddress.Parse("198.51.100.1"));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("2001:db8::1"), 1080), relay);
    }

    [Fact]
    public void RelayEndPointSubstitutesTheProxyForAWildcardIPv6Address()
    {
        var relay = TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            TlsQuicSocks5Protocol.AddressIPv6,
            new byte[16],
            port: 1080,
            proxyAddress: IPAddress.Parse("2001:db8::1"));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("2001:db8::1"), 1080), relay);
    }

    [Fact]
    public void RelayEndPointRejectsADomainNameReply()
    {
        // The client never sends ATYP 0x03, so a name in the reply is anomalous.
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ResolveRelayEndPoint(
                TlsQuicSocks5Protocol.AddressDomainName,
                "relay.example"u8,
                port: 1080,
                proxyAddress: IPAddress.Loopback));

        Assert.Equal(TlsQuicProxyError.MalformedProxyResponse, exception.Error);
    }

    [Theory]
    // ATYP says IPv4 but 16 bytes supplied.
    [InlineData(0x01, 16)]
    // ATYP says IPv6 but 4 bytes supplied.
    [InlineData(0x04, 4)]
    // Empty address.
    [InlineData(0x01, 0)]
    public void RelayEndPointRejectsAnAddressLengthMismatch(byte addressType, int length)
    {
        var exception = Assert.Throws<TlsQuicProxyException>(
            () => TlsQuicSocks5Protocol.ResolveRelayEndPoint(
                addressType, new byte[length], port: 1080, proxyAddress: IPAddress.Loopback));

        Assert.Equal(TlsQuicProxyError.MalformedProxyResponse, exception.Error);
    }

    [Fact]
    public void RelayEndPointPreservesHighPortNumbers()
    {
        // Port is a ushort; 65535 must survive the round trip without sign damage.
        var relay = TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            TlsQuicSocks5Protocol.AddressIPv4,
            [203, 0, 113, 9],
            port: 65535,
            proxyAddress: IPAddress.Loopback);

        Assert.Equal(65535, relay.Port);
    }

    [Fact]
    public void RelayEndPointSubstitutesTheProxyForAnIPv4MappedWildcard()
    {
        // ::ffff:0.0.0.0 is a wildcard in substance but is equal to neither
        // IPAddress.Any nor IPAddress.IPv6Any.
        var mappedWildcard = new byte[16];
        mappedWildcard[10] = 0xFF;
        mappedWildcard[11] = 0xFF;

        var relay = TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            TlsQuicSocks5Protocol.AddressIPv6,
            mappedWildcard,
            port: 1080,
            proxyAddress: IPAddress.Parse("198.51.100.1"));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("198.51.100.1"), 1080), relay);
    }

    [Fact]
    public void UdpHeaderMatchesRfc1928Layout()
    {
        var buffer = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv4];
        var written = TlsQuicSocks5Protocol.WriteUdpHeader(
            buffer,
            new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443));

        // RSV(2)=0 | FRAG(1)=0 | ATYP(1)=1 | DST.ADDR(4) | DST.PORT(2, network order)
        Assert.Equal(TlsQuicSocks5Protocol.UdpHeaderSizeIPv4, written);
        Assert.Equal(
            new byte[] { 0x00, 0x00, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xBB },
            buffer);
    }

    [Fact]
    public void UdpHeaderForIPv6IsTwentyTwoBytes()
    {
        var buffer = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv6];
        var written = TlsQuicSocks5Protocol.WriteUdpHeader(
            buffer,
            new IPEndPoint(IPAddress.Parse("2001:db8::1"), 443));

        Assert.Equal(22, written);
        Assert.Equal(TlsQuicSocks5Protocol.AddressIPv6, buffer[3]);
        Assert.Equal(new byte[] { 0x01, 0xBB }, buffer[20..22]);
    }

    [Fact]
    public void UdpHeaderRoundTripsIPv4()
    {
        var origin = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 443);
        var datagram = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv4 + 3];
        TlsQuicSocks5Protocol.WriteUdpHeader(datagram, origin);

        Assert.True(TlsQuicSocks5Protocol.TryReadUdpHeader(
            datagram, out var parsed, out var headerLength));
        Assert.Equal(origin, parsed);
        Assert.Equal(TlsQuicSocks5Protocol.UdpHeaderSizeIPv4, headerLength);
    }

    [Fact]
    public void UdpHeaderRoundTripsIPv6()
    {
        var origin = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 65535);
        var datagram = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv6 + 3];
        TlsQuicSocks5Protocol.WriteUdpHeader(datagram, origin);

        Assert.True(TlsQuicSocks5Protocol.TryReadUdpHeader(
            datagram, out var parsed, out var headerLength));
        Assert.Equal(origin, parsed);
        Assert.Equal(TlsQuicSocks5Protocol.UdpHeaderSizeIPv6, headerLength);
    }

    [Theory]
    // RSV must be 0x0000.
    [InlineData(new byte[] { 0x01, 0x00, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xBB })]
    [InlineData(new byte[] { 0x00, 0x01, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xBB })]
    // FRAG other than 0x00 must be dropped by an implementation without fragmentation.
    [InlineData(new byte[] { 0x00, 0x00, 0x01, 0x01, 203, 0, 113, 9, 0x01, 0xBB })]
    [InlineData(new byte[] { 0x00, 0x00, 0x80, 0x01, 203, 0, 113, 9, 0x01, 0xBB })]
    // Declares a 4-byte name but ends inside it.
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x03, 0x04, (byte)'h', (byte)'o' })]
    // Unknown ATYP.
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x09, 203, 0, 113, 9, 0x01, 0xBB })]
    // Truncated: header declares IPv4 but the datagram ends inside DST.PORT.
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x01, 203, 0, 113, 9, 0x01 })]
    // Truncated: shorter than the fixed 4-byte prefix.
    [InlineData(new byte[] { 0x00, 0x00, 0x00 })]
    [InlineData(new byte[0])]
    // Declares IPv6 but carries only an IPv4-sized address.
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x04, 203, 0, 113, 9, 0x01, 0xBB })]
    public void MalformedUdpHeadersAreRejectedWithoutThrowing(byte[] datagram)
    {
        Assert.False(TlsQuicSocks5Protocol.TryReadUdpHeader(datagram, out _, out _));
    }

    /// <summary>
    /// A relay may echo the destination in the form we sent it, and the domain form IS sent now
    /// - a proxy whose ruleset forbids literal addresses accepts nothing else. Rejecting the
    /// echo would drop every reply on such a proxy, so the payload offset has to be read past a
    /// name as well as past an address.
    /// </summary>
    [Fact]
    public void ADomainFormReplyIsAcceptedAndItsPayloadOffsetIsCorrect()
    {
        byte[] datagram =
        [
            0x00, 0x00, 0x00, 0x03,
            0x04, (byte)'h', (byte)'o', (byte)'s', (byte)'t',
            0x01, 0xBB,
            0xDE, 0xAD,
        ];

        Assert.True(TlsQuicSocks5Protocol.TryReadUdpHeader(datagram, out var origin, out var headerLength));
        Assert.Equal(11, headerLength);
        Assert.Equal(443, origin.Port);
        Assert.Equal(new byte[] { 0xDE, 0xAD }, datagram[headerLength..]);
    }

    /// <summary>The domain form round-trips: what is written is what is read back.</summary>
    [Fact]
    public void ADomainFormHeaderRoundTrips()
    {
        var buffer = new byte[TlsQuicSocks5Protocol.HeaderSizeForDomain("example.com")];
        var written = TlsQuicSocks5Protocol.WriteUdpHeader(buffer, "example.com", 443);

        Assert.Equal(buffer.Length, written);
        Assert.Equal(TlsQuicSocks5Protocol.AddressDomainName, buffer[3]);
        Assert.Equal((byte)"example.com".Length, buffer[4]);
        Assert.True(TlsQuicSocks5Protocol.TryReadUdpHeader(buffer, out var origin, out var headerLength));
        Assert.Equal(written, headerLength);
        Assert.Equal(443, origin.Port);
    }

    [Fact]
    public void ZeroLengthPayloadIsStillAValidDatagram()
    {
        var datagram = new byte[TlsQuicSocks5Protocol.UdpHeaderSizeIPv4];
        TlsQuicSocks5Protocol.WriteUdpHeader(
            datagram, new IPEndPoint(IPAddress.Loopback, 443));

        Assert.True(TlsQuicSocks5Protocol.TryReadUdpHeader(datagram, out _, out var length));
        Assert.Equal(datagram.Length, length);
    }

    [Fact]
    public void RejectedDatagramsReportZeroHeaderLength()
    {
        // The caller slices by headerLength; a non-zero value on a false return
        // would let a rejected datagram be sliced as if it had parsed.
        Assert.False(TlsQuicSocks5Protocol.TryReadUdpHeader(
            [0x00, 0x00, 0x00, 0x01, 203, 0, 113], out _, out var headerLength));
        Assert.Equal(0, headerLength);
    }

    [Fact]
    public void HeaderSizeMatchesTheAddressFamily()
    {
        Assert.Equal(10, TlsQuicSocks5Protocol.HeaderSizeFor(AddressFamily.InterNetwork));
        Assert.Equal(22, TlsQuicSocks5Protocol.HeaderSizeFor(AddressFamily.InterNetworkV6));
    }
}
