using System.Net;

namespace SharpTls.Quic;

/// <summary>What a caller keeping one outer MASQUE connection per proxy session needs of it:
/// whether it has ended, whether it has been used, and a tunnel on it. Implemented by
/// <see cref="TlsQuicMasqueConnection"/>; a test stands in a fake.</summary>
internal interface ITlsQuicMasqueConnection : IAsyncDisposable
{
    /// <summary>Whether the outer connection has ended, by failure or by disposal: every later
    /// <see cref="OpenTunnelAsync"/> fails at once, so the caller dials a new one.</summary>
    bool IsClosed { get; }

    /// <summary>Tunnels ever asked for, open or not: zero means a connection nothing has used
    /// yet.</summary>
    int TunnelsRequested { get; }

    /// <summary>Tunnels open on the connection right now.</summary>
    int TunnelCount { get; }

    /// <summary>Datagrams the proxy has sent on the outer connection so far. A tunnel open that
    /// failed while this did not move is a proxy that has gone silent on this connection; one
    /// that failed while it moved is a proxy that answered, and the connection is fine.</summary>
    int DatagramsReceived { get; }

    /// <summary>Opens one RFC 9298 CONNECT-UDP tunnel to a target.</summary>
    /// <param name="targetHost">The target, written into the RFC 9298 s2 URI template.</param>
    /// <param name="targetPort">The target UDP port, written into the template.</param>
    /// <param name="targetEndPoint">Echoed in every receive result.</param>
    /// <param name="cancellationToken">Cancels the open.</param>
    /// <returns>The tunnel.</returns>
    Task<TlsQuicMasqueTransport> OpenTunnelAsync(
        string targetHost, int targetPort, IPEndPoint targetEndPoint, CancellationToken cancellationToken);
}
