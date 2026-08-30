using SharpTls;

namespace TlsClient;

internal static class HttpConnectionFactory
{
    public static async ValueTask<IHttpConnection> ConnectAsync(
        Uri origin,
        TlsHttpVersionPolicy versionPolicy,
        TlsProxy? proxy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        DnsEndpointResolver dnsResolver,
        Socks5AssociationGate associationGate,
        CancellationToken cancellationToken)
    {
        // HTTP/3 forks before the TCP transport is dialled: QUIC opens its own UDP socket
        // inside Http3Connection and never produces a SharpTlsTransport. Selecting h3 after
        // SharpTlsTransport.ConnectAsync would mean a TCP connection had already negotiated
        // h2 or http/1.1, which is the silent downgrade this policy exists to prevent.
#pragma warning disable TLSCLIENT3 // HTTP/3 is experimental; the factory must still route it.
        if (versionPolicy == TlsHttpVersionPolicy.Http3Only)
#pragma warning restore TLSCLIENT3
        {
            // ONLY SOCKS5 CAN CARRY QUIC, and the refusal names the type rather than
            // blaming proxies as a category. RFC 1928 section 7's UDP ASSOCIATE is the only
            // one of the three that relays datagrams: HTTP CONNECT tunnels a TCP byte stream
            // and SOCKS4 has no UDP at all. RFC 9298's CONNECT-UDP would give the HTTP arm a
            // path, but it needs the proxy to implement it and this client does not speak it.
            if (proxy is not null && proxy.Type != TlsProxyType.Socks5)
            {
                throw new NotSupportedException(
                    $"HTTP/3 cannot be tunnelled through a {proxy.Type} proxy: QUIC is UDP " +
                    "and only SOCKS5 relays datagrams, through RFC 1928 UDP ASSOCIATE. Use a " +
                    "SOCKS5 proxy for HTTP/3, a TCP version policy for this one, or clear " +
                    "the proxy.");
            }
            return await Http3Connection.CreateAsync(
                origin,
                proxy,
                configuration,
                tls13SessionCache,
                dnsResolver,
                associationGate,
                cancellationToken).ConfigureAwait(false);
        }

        var transport = await SharpTlsTransport.ConnectAsync(
            origin,
            versionPolicy,
            proxy,
            configuration,
            tls13SessionCache,
            dnsResolver,
            cancellationToken).ConfigureAwait(false);
        if (transport.ApplicationProtocol == "h2")
        {
            return await Http2Connection.CreateAsync(
                transport,
                configuration,
                cancellationToken).ConfigureAwait(false);
        }
        return new Http11Connection(transport);
    }
}
