using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SharpTls.Quic;

/// <summary>Reasons a SOCKS5 proxy association failed.</summary>
public enum TlsQuicProxyError
{
    /// <summary>The proxy offered no authentication method this client supports.</summary>
    NoAcceptableAuthenticationMethod,
    /// <summary>The proxy selected username/password but no credentials were configured.</summary>
    CredentialsRequired,
    /// <summary>The proxy rejected the supplied credentials.</summary>
    CredentialsRejected,
    /// <summary>The proxy refused the UDP ASSOCIATE request.</summary>
    AssociateRejected,
    /// <summary>A proxy reply was truncated, malformed, or carried an unexpected version.</summary>
    MalformedProxyResponse,
    /// <summary>The control connection closed, which ends the UDP association.</summary>
    AssociationTerminated,
}

/// <summary>A SOCKS5 proxy failure. Distinct from <see cref="TlsQuicTransportException"/>,
/// which carries an RFC 9000 transport error code.</summary>
public sealed class TlsQuicProxyException : IOException
{
    /// <summary>Creates a proxy failure.</summary>
    public TlsQuicProxyException(TlsQuicProxyError error, string message)
        : base(message)
    {
        Error = error;
    }

    /// <summary>Gets the reason the association failed.</summary>
    public TlsQuicProxyError Error { get; }
}

internal static class TlsQuicSocks5Protocol
{
    // RFC 1928 section 3.
    internal const byte Version = 0x05;
    internal const byte MethodNoAuthentication = 0x00;
    internal const byte MethodUsernamePassword = 0x02;
    internal const byte MethodNone = 0xFF;

    // RFC 1929 section 2. The subnegotiation version is 0x01, not 0x05.
    internal const byte AuthenticationVersion = 0x01;
    internal const byte AuthenticationSuccess = 0x00;

    // RFC 1928 section 4.
    internal const byte CommandUdpAssociate = 0x03;

    // RFC 1928 section 5.
    internal const byte AddressIPv4 = 0x01;
    internal const byte AddressDomainName = 0x03;
    internal const byte AddressIPv6 = 0x04;

    // RFC 1928 section 7: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2).
    internal const int UdpHeaderSizeIPv4 = 10;
    internal const int UdpHeaderSizeIPv6 = 22;

    internal static TlsQuicProxyException Malformed(string message) =>
        new(TlsQuicProxyError.MalformedProxyResponse, message);

    // RFC 1928 s3: VER | NMETHODS | METHODS. The count byte is NMETHODS,
    // not a method identifier, even where its value coincides with one.
    internal static byte[] EncodeGreeting(bool offerUsernamePassword) =>
        offerUsernamePassword
            ? [Version, 0x02, MethodNoAuthentication, MethodUsernamePassword]
            : [Version, 0x01, MethodNoAuthentication];

    internal static byte ParseMethodSelection(ReadOnlySpan<byte> response)
    {
        if (response.Length != 2)
        {
            throw Malformed(
                $"SOCKS5 method selection must be 2 bytes, received {response.Length}.");
        }

        if (response[0] != Version)
        {
            throw Malformed(
                $"SOCKS5 method selection VER was 0x{response[0]:X2}, expected 0x05.");
        }

        return response[1];
    }

    // RFC 1929 s2: VER | ULEN | UNAME | PLEN | PASSWD. VER is 0x01 here,
    // distinct from the 0x05 SOCKS version used everywhere else.
    internal static byte[] EncodeAuthenticationRequest(string username, string password)
    {
        var user = Encoding.UTF8.GetBytes(username);
        var pass = Encoding.UTF8.GetBytes(password);

        try
        {
            // RFC 1929 s2: ULEN and PLEN are "1 to 255" — length is measured
            // in encoded UTF-8 bytes, not string.Length (UTF-16 chars).
            if (user.Length is 0 or > 255)
            {
                throw new ArgumentException(
                    "SOCKS5 username must encode to 1 to 255 UTF-8 bytes.", nameof(username));
            }

            if (pass.Length is 0 or > 255)
            {
                throw new ArgumentException(
                    "SOCKS5 password must encode to 1 to 255 UTF-8 bytes.", nameof(password));
            }

            var buffer = new byte[3 + user.Length + pass.Length];
            buffer[0] = AuthenticationVersion;
            buffer[1] = (byte)user.Length;
            user.CopyTo(buffer, 2);
            buffer[2 + user.Length] = (byte)pass.Length;
            pass.CopyTo(buffer, 3 + user.Length);
            return buffer;
        }
        finally
        {
            // Zero the intermediate copies on every exit path, including
            // validation failures — a rejected password should not linger
            // on the heap any longer than an accepted one. The returned
            // buffer still holds the credentials; the caller must zero it
            // with CryptographicOperations.ZeroMemory once it has been
            // written to the socket.
            CryptographicOperations.ZeroMemory(user);
            CryptographicOperations.ZeroMemory(pass);
        }
    }

    internal static void ValidateAuthenticationReply(ReadOnlySpan<byte> reply)
    {
        if (reply.Length != 2)
        {
            throw Malformed(
                $"SOCKS5 authentication reply must be 2 bytes, received {reply.Length}.");
        }

        if (reply[0] != AuthenticationVersion)
        {
            throw Malformed(
                $"SOCKS5 authentication reply VER was 0x{reply[0]:X2}, expected 0x01.");
        }

        if (reply[1] != AuthenticationSuccess)
        {
            throw new TlsQuicProxyException(
                TlsQuicProxyError.CredentialsRejected,
                $"SOCKS5 proxy rejected the supplied credentials with status 0x{reply[1]:X2}.");
        }
    }

    internal static byte[] EncodeAssociateRequest(AddressFamily family)
    {
        var addressLength = family == AddressFamily.InterNetworkV6 ? 16 : 4;
        var request = new byte[4 + addressLength + 2];
        request[0] = Version;
        request[1] = CommandUdpAssociate;
        request[2] = 0x00;
        request[3] = family == AddressFamily.InterNetworkV6 ? AddressIPv6 : AddressIPv4;
        // DST.ADDR and DST.PORT stay zero: RFC 1928 permits this when the client
        // cannot know the address it will send datagrams from, and a bound local
        // port is usually rewritten by NAT before the relay observes it.
        return request;
    }

    // Validates VER and REP and returns the reply's ATYP. RSV is deliberately not
    // checked: RFC 1928 marks it RESERVED without mandating a reply-path value, and
    // deployed relays have been observed setting it.
    internal static byte ValidateAssociateReplyHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length != 4)
        {
            throw Malformed(
                $"SOCKS5 reply header must be 4 bytes, received {header.Length}.");
        }

        if (header[0] != Version)
        {
            throw Malformed(
                $"SOCKS5 reply VER was 0x{header[0]:X2}, expected 0x05.");
        }

        if (header[1] != 0x00)
        {
            throw new TlsQuicProxyException(
                TlsQuicProxyError.AssociateRejected,
                $"SOCKS5 proxy refused UDP ASSOCIATE with REP 0x{header[1]:X2}: " +
                DescribeReplyCode(header[1]));
        }

        return header[3];
    }

    // RFC 1928 s6.
    private static string DescribeReplyCode(byte code) => code switch
    {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unassigned reply code",
    };

    internal static IPEndPoint ResolveRelayEndPoint(
        byte addressType,
        ReadOnlySpan<byte> address,
        ushort port,
        IPAddress proxyAddress)
    {
        if (addressType is not (AddressIPv4 or AddressIPv6))
        {
            throw Malformed(
                $"SOCKS5 reply ATYP was 0x{addressType:X2}; only 0x01 and 0x04 are accepted.");
        }

        var expected = addressType == AddressIPv4 ? 4 : 16;
        if (address.Length != expected)
        {
            throw Malformed(
                $"SOCKS5 reply address was {address.Length} bytes, expected {expected}.");
        }

        var bound = new IPAddress(address);

        // A wildcard BND.ADDR means "the host you are already talking to".
        // IPAddress.Equals compares family and bytes exactly and does not normalise
        // IPv4-mapped forms, so ::ffff:0.0.0.0 must be unwrapped before the test or
        // it slips through and the client sends datagrams to a null route.
        var comparand = bound.IsIPv4MappedToIPv6 ? bound.MapToIPv4() : bound;
        if (comparand.Equals(IPAddress.Any) || comparand.Equals(IPAddress.IPv6Any))
        {
            bound = proxyAddress;
        }

        return new IPEndPoint(bound, port);
    }

    internal static int HeaderSizeFor(AddressFamily family) =>
        family == AddressFamily.InterNetworkV6 ? UdpHeaderSizeIPv6 : UdpHeaderSizeIPv4;

    /// <summary>
    /// RSV(2) FRAG(1) ATYP(1) LEN(1) NAME DST.PORT(2) for the domain form. Longer than either
    /// address form, so it shrinks the usable datagram payload by the length of the name.
    /// </summary>
    internal static int HeaderSizeForDomain(string host) =>
        4 + 1 + Encoding.ASCII.GetByteCount(host) + 2;

    /// <summary>
    /// Writes the RFC 1928 section 7 header with ATYP=DOMAINNAME. Some proxies reject a
    /// literal address by ruleset and accept only a name, so the destination travels as text
    /// and the PROXY resolves it.
    /// </summary>
    internal static int WriteUdpHeader(Span<byte> destination, string host, int port)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        var nameLength = Encoding.ASCII.GetByteCount(host);
        if (nameLength > 255)
        {
            throw new ArgumentException(
                $"A SOCKS5 domain name is at most 255 bytes; '{host}' needs {nameLength}.",
                nameof(host));
        }

        var headerLength = 4 + 1 + nameLength + 2;
        if (destination.Length < headerLength)
        {
            throw new ArgumentException(
                $"Datagram header needs {headerLength} bytes, destination has {destination.Length}.",
                nameof(destination));
        }

        destination[0] = 0x00;                  // RSV
        destination[1] = 0x00;                  // RSV
        destination[2] = 0x00;                  // FRAG, never fragmented
        destination[3] = AddressDomainName;     // ATYP
        destination[4] = (byte)nameLength;
        Encoding.ASCII.GetBytes(host, destination[5..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination[(5 + nameLength)..], (ushort)port);
        return headerLength;
    }

    internal static int WriteUdpHeader(Span<byte> destination, IPEndPoint target)
    {
        var isIPv6 = target.AddressFamily == AddressFamily.InterNetworkV6;
        var headerLength = HeaderSizeFor(target.AddressFamily);

        if (destination.Length < headerLength)
        {
            throw new ArgumentException(
                $"Datagram header needs {headerLength} bytes, destination has {destination.Length}.",
                nameof(destination));
        }

        destination[0] = 0x00;                                   // RSV
        destination[1] = 0x00;                                   // RSV
        destination[2] = 0x00;                                   // FRAG, never fragmented
        destination[3] = isIPv6 ? AddressIPv6 : AddressIPv4;     // ATYP

        if (!target.Address.TryWriteBytes(destination[4..], out var addressLength))
        {
            throw new ArgumentException(
                "Destination address did not fit the datagram header.", nameof(target));
        }

        BinaryPrimitives.WriteUInt16BigEndian(
            destination[(4 + addressLength)..], (ushort)target.Port);
        return headerLength;
    }

    // Try-shaped and never throws: RFC 9000 s14 requires a malformed datagram to be
    // discarded rather than to fail the connection, so a hostile packet must not be
    // able to terminate a QUIC session.
    internal static bool TryReadUdpHeader(
        ReadOnlySpan<byte> datagram,
        [MaybeNullWhen(false)] out IPEndPoint origin,
        out int headerLength)
    {
        origin = null;
        headerLength = 0;

        if (datagram.Length < 4)
        {
            return false;
        }

        // RSV must be X'0000' and FRAG must be X'00': RFC 1928 s7 permits an
        // implementation without fragmentation support to drop anything else.
        if (datagram[0] != 0x00 || datagram[1] != 0x00 || datagram[2] != 0x00)
        {
            return false;
        }

        if (datagram[3] == AddressDomainName)
        {
            // A relay may echo the destination as the name we sent. The payload offset is what
            // matters here; the name is not resolved back into an endpoint.
            var nameLength = datagram[4];
            var domainHeader = 4 + 1 + nameLength + 2;
            if (datagram.Length < domainHeader)
            {
                origin = null!;
                headerLength = 0;
                return false;
            }

            origin = new IPEndPoint(
                IPAddress.None,
                BinaryPrimitives.ReadUInt16BigEndian(datagram[(5 + nameLength)..domainHeader]));
            headerLength = domainHeader;
            return true;
        }

        var addressLength = datagram[3] switch
        {
            AddressIPv4 => 4,
            AddressIPv6 => 16,
            _ => 0,
        };

        if (addressLength == 0)
        {
            return false;
        }

        var declaredLength = 4 + addressLength + 2;
        if (datagram.Length < declaredLength)
        {
            return false;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(
            datagram[(4 + addressLength)..declaredLength]);
        origin = new IPEndPoint(
            new IPAddress(datagram[4..(4 + addressLength)]), port);
        headerLength = declaredLength;
        return true;
    }
}
