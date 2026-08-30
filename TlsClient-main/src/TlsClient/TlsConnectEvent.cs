using System.Net;

namespace TlsClient;

/// <summary>Identifies one stage of establishing a new network connection.</summary>
public enum TlsConnectEventKind
{
    /// <summary>A cached DNS result was reused.</summary>
    DnsCacheHit,

    /// <summary>DNS resolution started.</summary>
    DnsResolutionStarted,

    /// <summary>DNS resolution completed.</summary>
    DnsResolutionCompleted,

    /// <summary>DNS resolution failed.</summary>
    DnsResolutionFailed,

    /// <summary>One TCP address attempt started.</summary>
    TcpAttemptStarted,

    /// <summary>One TCP address attempt failed.</summary>
    TcpAttemptFailed,

    /// <summary>A TCP address attempt won the Happy Eyeballs race.</summary>
    TcpConnected,

    /// <summary>An HTTP CONNECT tunnel started.</summary>
    ProxyTunnelStarted,

    /// <summary>An HTTP CONNECT tunnel completed.</summary>
    ProxyTunnelCompleted,

    /// <summary>An HTTP CONNECT tunnel failed.</summary>
    ProxyTunnelFailed,

    /// <summary>The SharpTls handshake started.</summary>
    TlsHandshakeStarted,

    /// <summary>The SharpTls handshake completed.</summary>
    TlsHandshakeCompleted,

    /// <summary>The SharpTls handshake failed.</summary>
    TlsHandshakeFailed,

    /// <summary>
    /// An HTTP/3 dial was admitted by the per-proxy-session gate that serialises RFC 1928
    /// section 7 UDP ASSOCIATE setup, and is about to open its association.
    /// </summary>
    /// <remarks>
    /// <para><see cref="TlsConnectEvent.Elapsed"/> IS THE WHOLE POINT: it is how long this dial
    /// queued behind another dial's ASSOCIATE through the same proxy session. Zero means the
    /// gate was free. A run whose stalls persist despite serialised setup is only interpretable
    /// if these show that dials genuinely queued — otherwise "we serialised and it did not
    /// help" cannot be told apart from "we never actually serialised anything".</para>
    /// <para>Emitted only for a proxied HTTP/3 dial. A direct UDP dial takes no gate and
    /// reports nothing.</para>
    /// </remarks>
    Socks5AssociationGateEntered,

    /// <summary>
    /// A proxied HTTP/3 dial abandoned an RFC 1928 section 7 UDP association that had been
    /// established but never relayed a single inbound datagram, and is opening a fresh one.
    /// </summary>
    /// <remarks>
    /// <para>WHAT IT MEANS: the ASSOCIATE succeeded — control connection up, section 6 reply
    /// well-formed, a routable BND returned — and then nothing whatsoever came back within
    /// <see cref="TlsQuicOptions.AssociationLivenessDeadline"/>. Six to eight per cent of fresh
    /// associations behave this way, independent of load, so this firing occasionally is the
    /// system working rather than a fault.</para>
    /// <para>THREE OUTCOMES, AND THIS EVENT SEPARATES ALL OF THEM when read alongside the
    /// dial's own result, which is what makes the fix measurable at all:</para>
    /// <list type="bullet">
    /// <item>NEVER NEEDED TO RETRY — the dial returned a connection and emitted no event with
    /// this kind for its <see cref="TlsConnectEvent.ConnectionId"/>.</item>
    /// <item>RETRIED AND SUCCEEDED — the dial returned a connection and emitted one or more.
    /// <see cref="TlsConnectEvent.AddressCount"/> carries the number of the attempt being
    /// abandoned, so the highest one plus one is the attempt that worked.</item>
    /// <item>RETRIED AND STILL FAILED — the dial threw, having emitted
    /// <see cref="TlsQuicOptions.MaximumAssociationAttempts"/> minus one of these. The
    /// exception says so in words rather than reporting a bare timeout.</item>
    /// </list>
    /// <para><see cref="TlsConnectEvent.Elapsed"/> is how long the abandoned association was
    /// given, and <see cref="TlsConnectEvent.Exception"/> is the failure that ended it — kept
    /// because a dead association and a genuinely broken path are told apart by this event
    /// being present, never by the exception, which looks the same either way.</para>
    /// <para>Emitted only for a proxied HTTP/3 dial. A direct UDP dial has no association to be
    /// dead and never reports this.</para>
    /// </remarks>
    Socks5AssociationRetried,

    /// <summary>
    /// A proxied HTTP/3 connection opened its FIRST request stream, reporting how long its RFC
    /// 1928 section 7 UDP association had been idle since the QUIC handshake completed.
    /// </summary>
    /// <remarks>
    /// <para>THIS GAP WAS INVISIBLE AND MAY BE THE WHOLE ANSWER. Stalls over SOCKS5-UDP happen
    /// only on the first request to a new host, after a handshake the association demonstrably
    /// carried — so the suspect is the window between the two. A connection dialled, returned
    /// to the pool and used later has spent that whole window silent, which is exactly what an
    /// idle-reaping proxy needs to discard the association. Nothing else on the record shows
    /// how long that window was.</para>
    /// <para><see cref="TlsConnectEvent.Elapsed"/> is the window: the time from the handshake
    /// completing to this request being built. <see cref="TlsConnectEvent.AddressCount"/> is
    /// how many datagrams arrived DURING it, counting the ones the
    /// <c>TlsQuicSocks5RelaySource</c> policy or the section 7 header parser threw away.
    /// Zero is the ordinary value — nothing ack-eliciting is sent between requests, so a
    /// healthy connection is also silent while idle (RFC 9000 section 10.1) — which is why the
    /// gap and not the count is the interesting half.</para>
    /// <para>Emitted once per connection, and only for a proxied HTTP/3 one. A direct UDP dial
    /// has no association to be reaped and reports nothing.</para>
    /// </remarks>
    Socks5AssociationFirstRequest,

    /// <summary>
    /// A request on a proxied HTTP/3 connection was failed because its RFC 1928 section 7 UDP
    /// association had relayed nothing whatsoever since the QUIC handshake.
    /// </summary>
    /// <remarks>
    /// <para>WHAT IT MEANS: the association carried the handshake, the connection was handed
    /// back healthy, and then this request waited
    /// <see cref="TlsQuicOptions.AssociationSilenceDeadline"/> with not one datagram of any
    /// kind coming back — so the association was reaped or blackholed rather than the origin
    /// being slow. RFC 1928 section 7 lets an association end only with its control connection,
    /// which is still open, so silence is the only symptom a proxy that does this produces.
    /// </para>
    /// <para>THREE OUTCOMES, AND THIS EVENT SEPARATES ALL OF THEM, which is what makes the fix
    /// measurable:</para>
    /// <list type="bullet">
    /// <item>NEVER AFFECTED — no event of this kind for the run.</item>
    /// <item>DETECTED AND RECOVERED — one of these, then a
    /// <see cref="Socks5AssociationGateEntered"/> under a NEW
    /// <see cref="TlsConnectEvent.ConnectionId"/> and a response. The failure is a
    /// <c>StaleHttpConnectionException</c>, which the pool evicts on and
    /// <c>TlsSession</c>'s retry policy re-dials, so a replayable idempotent request recovers
    /// on a fresh association by itself.</item>
    /// <item>DETECTED AND STILL FAILED — one of these per attempt the retry policy allowed, and
    /// the caller sees the last of them. The exception says the association went silent rather
    /// than reporting a bare timeout.</item>
    /// </list>
    /// <para><see cref="TlsConnectEvent.Elapsed"/> is how long the association had been silent
    /// in total — from the handshake, not from the request — and
    /// <see cref="TlsConnectEvent.Exception"/> is what the caller was given.</para>
    /// <para>Emitted only for a proxied HTTP/3 connection.</para>
    /// </remarks>
    Socks5AssociationWentSilent,
}

/// <summary>Reports a structured, non-secret connection-establishment event.</summary>
public sealed record TlsConnectEvent
{
    internal TlsConnectEvent(
        Guid connectionId,
        TlsConnectEventKind kind,
        string host,
        int port,
        IPAddress? address,
        int addressCount,
        TimeSpan elapsed,
        string? applicationProtocol,
        Exception? exception)
    {
        ConnectionId = connectionId;
        Kind = kind;
        Host = host;
        Port = port;
        Address = address;
        AddressCount = addressCount;
        Elapsed = elapsed;
        ApplicationProtocol = applicationProtocol;
        Exception = exception;
        Timestamp = DateTimeOffset.UtcNow;
    }

    /// <summary>Gets the identifier shared by events for one connection.</summary>
    public Guid ConnectionId { get; }

    /// <summary>Gets the event stage.</summary>
    public TlsConnectEventKind Kind { get; }

    /// <summary>Gets the host being resolved or connected.</summary>
    public string Host { get; }

    /// <summary>Gets the TCP port.</summary>
    public int Port { get; }

    /// <summary>Gets the attempted or selected IP address, when applicable.</summary>
    public IPAddress? Address { get; }

    /// <summary>Gets the number of addresses returned by DNS, when applicable.</summary>
    public int AddressCount { get; }

    /// <summary>Gets elapsed time for this stage or attempt.</summary>
    public TimeSpan Elapsed { get; }

    /// <summary>Gets the negotiated ALPN value after a completed TLS handshake.</summary>
    public string? ApplicationProtocol { get; }

    /// <summary>Gets the failure associated with a failed stage.</summary>
    public Exception? Exception { get; }

    /// <summary>Gets when the event was emitted.</summary>
    public DateTimeOffset Timestamp { get; }
}

internal static class TlsConnectTelemetry
{
    public static void Emit(
        Action<TlsConnectEvent>? observer,
        Guid connectionId,
        TlsConnectEventKind kind,
        string host,
        int port,
        IPAddress? address = null,
        int addressCount = 0,
        TimeSpan elapsed = default,
        string? applicationProtocol = null,
        Exception? exception = null)
    {
        var connectEvent = new TlsConnectEvent(
            connectionId,
            kind,
            host,
            port,
            address,
            addressCount,
            elapsed,
            applicationProtocol,
            exception);
        TlsDiagnostics.RecordConnectEvent(connectEvent);
        if (observer is null)
        {
            return;
        }
        try
        {
            observer(connectEvent);
        }
        catch (Exception)
        {
            // Instrumentation cannot change connection behavior.
        }
    }
}
