using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace TlsClient;

internal static class ProxyTunnel
{
    public static ValueTask EstablishAsync(
        Stream transport,
        Uri origin,
        TlsProxy proxy,
        int maximumHeaderBytes,
        CancellationToken cancellationToken) => proxy.Type switch
        {
            TlsProxyType.Http => EstablishHttpAsync(
                transport,
                origin,
                proxy,
                maximumHeaderBytes,
                cancellationToken),
            TlsProxyType.Socks5 => EstablishSocks5Async(
                transport,
                origin,
                proxy,
                cancellationToken),
            _ => throw new ArgumentOutOfRangeException(nameof(proxy)),
        };

    private static async ValueTask EstablishHttpAsync(
        Stream transport,
        Uri origin,
        TlsProxy proxy,
        int maximumHeaderBytes,
        CancellationToken cancellationToken)
    {
        // The request-target of a CONNECT is authority-form, which RFC 9112 section 3.2.3 gives
        // as "authority-form = uri-host ':' port" — the port is not optional there, so an origin
        // on its scheme's default port still names it.
        var authority = Http11RequestWriter.FormatAuthority(origin, includeDefaultPort: true);
        var request = new StringBuilder()
            .Append("CONNECT ").Append(authority).Append(" HTTP/1.1\r\n")
            .Append("Host: ").Append(authority).Append("\r\n")
            .Append("Proxy-Connection: keep-alive\r\n");
        var authorization = proxy.GetBasicAuthorizationValue();
        if (authorization is not null)
        {
            request.Append("Proxy-Authorization: ").Append(authorization).Append("\r\n");
        }
        request.Append("\r\n");

        await transport.WriteAsync(
            Encoding.Latin1.GetBytes(request.ToString()),
            cancellationToken).ConfigureAwait(false);
        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);

        var reader = new BufferedHttpReader(transport);
        var consumed = 0;
        int statusCode;
        string reason;
        // RFC 9110 section 15.2: "A client MUST be able to parse one or more 1xx responses
        // received prior to a final response, even if the client does not expect one. A user
        // agent MAY ignore unexpected 1xx responses." An interim response is not the CONNECT
        // answer, so it is read past rather than reported as a proxy rejection. The whole
        // exchange shares one header budget, which is what bounds the loop: a proxy looping on
        // 1xx runs out of allowance instead of running forever.
        do
        {
            var status = await reader.ReadLineAsync(maximumHeaderBytes, cancellationToken)
                .ConfigureAwait(false) ?? throw new HttpRequestException(
                    "The proxy closed before returning a CONNECT response.");
            consumed = checked(consumed + status.WireLength);
            (_, statusCode, reason) = Http11ResponseReader.ParseStatusLine(status.Text);
            while (true)
            {
                var line = await reader.ReadLineAsync(maximumHeaderBytes, cancellationToken)
                    .ConfigureAwait(false) ?? throw new HttpRequestException(
                    "The proxy closed in the middle of its CONNECT response.");
                consumed = checked(consumed + line.WireLength);
                if (consumed > maximumHeaderBytes)
                {
                    throw new HttpRequestException(
                        "The proxy CONNECT response headers were too large.");
                }
                if (line.Text.Length == 0)
                {
                    break;
                }
            }
        }
        while (statusCode is >= 100 and < 200);
        if (statusCode != 200)
        {
            throw new HttpRequestException(
                $"The proxy rejected CONNECT with HTTP {statusCode} {reason}.");
        }

        // RFC 9110 section 9.3.6: the sender switches to tunnel mode "immediately after the
        // response header section; data received after that header section is from the server
        // identified by the request target". This reader is dropped when the method returns and
        // the caller hands the bare stream to the TLS handshake, so anything read ahead into it
        // is lost. A conforming proxy sends nothing between the blank line and our ClientHello;
        // preserving the octets would mean threading a prepend-stream through the transport for
        // a case that can only be a misbehaving proxy on an https-only client, so this fails
        // with a diagnostic instead of losing the data into a confusing handshake failure.
        if (reader.HasBufferedBytes)
        {
            throw new HttpRequestException(
                "The proxy sent unsolicited data after the CONNECT response.");
        }
    }

    private static async ValueTask EstablishSocks5Async(
        Stream transport,
        Uri origin,
        TlsProxy proxy,
        CancellationToken cancellationToken)
    {
        var credentials = proxy.GetCredentials();
        var greeting = credentials is null
            ? new byte[] { 5, 1, 0 }
            : new byte[] { 5, 2, 0, 2 };
        await transport.WriteAsync(greeting, cancellationToken).ConfigureAwait(false);
        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);
        var method = new byte[2];
        await ReadExactlyAsync(transport, method, cancellationToken).ConfigureAwait(false);
        if (method[0] != 5 || method[1] == 0xff)
        {
            throw new HttpRequestException("The SOCKS5 proxy did not accept an authentication method.");
        }
        if (method[1] == 2)
        {
            if (credentials is null)
            {
                throw new HttpRequestException(
                    "The SOCKS5 proxy requires username/password authentication.");
            }
            await AuthenticateSocks5Async(
                transport,
                credentials,
                cancellationToken).ConfigureAwait(false);
        }
        else if (method[1] != 0)
        {
            throw new HttpRequestException(
                $"The SOCKS5 proxy selected unsupported method 0x{method[1]:x2}.");
        }

        var destination = CreateSocks5Destination(origin);
        await transport.WriteAsync(destination, cancellationToken).ConfigureAwait(false);
        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);
        var response = new byte[4];
        await ReadExactlyAsync(transport, response, cancellationToken).ConfigureAwait(false);
        if (response[0] != 5 || response[2] != 0)
        {
            throw new HttpRequestException("The SOCKS5 proxy returned a malformed CONNECT response.");
        }
        if (response[1] != 0)
        {
            throw new HttpRequestException(
                $"The SOCKS5 proxy rejected CONNECT with status 0x{response[1]:x2}.");
        }
        var addressLength = response[3] switch
        {
            1 => 4,
            4 => 16,
            3 => await ReadByteAsync(transport, cancellationToken).ConfigureAwait(false),
            _ => throw new HttpRequestException(
                "The SOCKS5 proxy returned an unknown address type."),
        };
        if (response[3] == 3 && addressLength == 0)
        {
            throw new HttpRequestException(
                "The SOCKS5 proxy returned an empty domain address.");
        }
        var remainder = new byte[checked(addressLength + 2)];
        await ReadExactlyAsync(transport, remainder, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask AuthenticateSocks5Async(
        Stream transport,
        NetworkCredential credentials,
        CancellationToken cancellationToken)
    {
        var username = Encoding.UTF8.GetBytes(credentials.UserName);
        var password = Encoding.UTF8.GetBytes(credentials.Password);
        if (username.Length is < 1 or > 255 || password.Length is < 1 or > 255)
        {
            throw new HttpRequestException(
                "SOCKS5 usernames and passwords must each encode to 1–255 bytes.");
        }
        var request = new byte[checked(username.Length + password.Length + 3)];
        request[0] = 1;
        request[1] = (byte)username.Length;
        username.CopyTo(request, 2);
        request[username.Length + 2] = (byte)password.Length;
        password.CopyTo(request, username.Length + 3);
        await transport.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);
        var response = new byte[2];
        await ReadExactlyAsync(transport, response, cancellationToken).ConfigureAwait(false);
        if (response[0] != 1 || response[1] != 0)
        {
            throw new HttpRequestException(
                "The SOCKS5 proxy rejected username/password authentication.");
        }
    }

    private static byte[] CreateSocks5Destination(Uri origin)
    {
        var host = origin.IdnHost;
        byte addressType;
        byte[] addressBytes;
        if (IPAddress.TryParse(host, out var address))
        {
            addressType = address.AddressFamily ==
                System.Net.Sockets.AddressFamily.InterNetwork ? (byte)1 : (byte)4;
            addressBytes = address.GetAddressBytes();
        }
        else
        {
            addressType = 3;
            var hostBytes = Encoding.ASCII.GetBytes(host);
            if (hostBytes.Length is < 1 or > 255)
            {
                throw new HttpRequestException(
                    "The SOCKS5 destination hostname must encode to 1–255 bytes.");
            }
            addressBytes = new byte[hostBytes.Length + 1];
            addressBytes[0] = (byte)hostBytes.Length;
            hostBytes.CopyTo(addressBytes, 1);
        }
        var request = new byte[checked(addressBytes.Length + 6)];
        request[0] = 5;
        request[1] = 1;
        request[2] = 0;
        request[3] = addressType;
        addressBytes.CopyTo(request, 4);
        BinaryPrimitives.WriteUInt16BigEndian(
            request.AsSpan(request.Length - 2),
            checked((ushort)origin.Port));
        return request;
    }

    private static async ValueTask<int> ReadByteAsync(
        Stream transport,
        CancellationToken cancellationToken)
    {
        var value = new byte[1];
        await ReadExactlyAsync(transport, value, cancellationToken).ConfigureAwait(false);
        return value[0];
    }

    private static async ValueTask ReadExactlyAsync(
        Stream transport,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await transport.ReadAsync(destination[offset..], cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new HttpRequestException("The proxy closed during tunnel negotiation.");
            }
            offset += read;
        }
    }
}
