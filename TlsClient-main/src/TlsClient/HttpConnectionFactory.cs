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
            ThrowIfProxyCannotCarryHttp3(proxy, configuration.Quic);
            return await Http3Connection.CreateAsync(
                origin,
                configuration.Quic.Proxy is null ? proxy : null,
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

    /// <summary>Refuses an HTTP/3 dial whose TCP-side proxy cannot carry QUIC. When
    /// <see cref="TlsQuicConfiguration.Proxy"/> names a MASQUE proxy the tunnel carries h3 and
    /// <paramref name="proxy"/> is TCP's business only, so nothing is checked.</summary>
    internal static void ThrowIfProxyCannotCarryHttp3(TlsProxy? proxy, TlsQuicConfiguration quic)
    {
        if (quic.Proxy is not null)
        {
            return;
        }
        if (proxy is not null && proxy.Type != TlsProxyType.Socks5)
        {
            throw new NotSupportedException(
                $"HTTP/3 cannot be tunnelled through a {proxy.Type} proxy in options.Proxy: QUIC is UDP. "
                + "Use a SOCKS5 proxy whose UDP ASSOCIATE relays datagrams, or an RFC 9298 MASQUE proxy in "
                + "options.Quic.Proxy, or a TCP version policy for this one.");
        }
    }
}
