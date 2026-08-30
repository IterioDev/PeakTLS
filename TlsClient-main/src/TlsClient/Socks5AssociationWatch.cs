using System.Diagnostics;

namespace TlsClient;

/// <summary>
/// What one live HTTP/3 connection remembers about the RFC 1928 section 7 UDP association
/// underneath it: when its handshake finished, what the relay had carried by then, and whether
/// it has carried anything since.
/// </summary>
/// <remarks>
/// <para>WHY THIS EXISTS: A WORKING ASSOCIATION IS NOT A LASTING ONE.
/// <see cref="Socks5LivenessTransport"/> answers the setup-phase question — has this association
/// EVER relayed? — and the re-association it drives fires zero times against the failure this
/// type addresses, which is what proves the two are different failures. Field testing over
/// SOCKS5-UDP stalls about five times per hundred and nine dials, always on the FIRST request to
/// a new host, always with the association having relayed the whole QUIC handshake first. So the
/// association sets up, carries the handshake, is handed back as a healthy connection, and then
/// the first request gets nothing at all.</para>
/// <para>RFC 1928 SECTION 7 NAMES ONLY ONE WAY AN ASSOCIATION ENDS: "a UDP association
/// terminates when the TCP connection that the UDP ASSOCIATE request arrived on terminates".
/// <c>TlsQuicSocks5Transport</c> already watches that control connection and raises
/// <c>AssociationTerminated</c> when it closes — and the observed failure is SILENCE and not
/// that exception. So the provider either blackholes the association while holding the control
/// connection open, or reaps it on UDP idleness; either way the wire says nothing and only the
/// absence of inbound datagrams distinguishes it.</para>
/// <para>TWO MEASUREMENTS, AND THE FIRST MAY BE THE WHOLE ANSWER. The gap between the handshake
/// finishing and the first request going out is currently invisible, and an idle-reaping proxy
/// explains "only ever the first request to a new host" exactly: a connection dialled, returned
/// to the pool and used later has been silent for the whole of that gap.
/// <see cref="ReportFirstRequest"/> puts it on the record through the same
/// <c>ConnectObserver</c> channel the setup-phase events already use, so the hypothesis can be
/// confirmed or discarded from a run's events rather than argued about.</para>
/// <para>THE TRIGGER IS AS NARROW AS THE SETUP-PHASE ONE, DELIBERATELY.
/// <see cref="IsSilent"/> compares a running total against a baseline taken at the handshake, so
/// ONE datagram of any kind — including one the <c>TlsQuicSocks5RelaySource</c> policy or the
/// section 7 header parser discarded — clears it permanently for the life of the connection. A
/// slow origin is not silence: RFC 9000 section 13.2.1 obliges a peer to acknowledge an
/// ack-eliciting packet within its advertised <c>max_ack_delay</c>, so a live path answers a
/// request in milliseconds even when the response itself takes seconds. Narrowness is the
/// property that made the setup-phase fix trustworthy and it is worth more here than reach.
/// </para>
/// </remarks>
internal sealed class Socks5AssociationWatch
{
    private readonly Socks5LivenessTransport _relay;
    private readonly Guid _connectionId;
    private readonly string _host;
    private readonly int _port;
    private readonly long _handshakeCompletedAt;
    private readonly long _relayedAtHandshake;
    private int _firstRequestReported;

    public Socks5AssociationWatch(
        Socks5LivenessTransport relay,
        Guid connectionId,
        string host,
        int port)
    {
        ArgumentNullException.ThrowIfNull(relay);
        _relay = relay;
        _connectionId = connectionId;
        _host = host;
        _port = port;
        _handshakeCompletedAt = Stopwatch.GetTimestamp();
        _relayedAtHandshake = relay.RelayedTotal;
    }

    /// <summary>
    /// Gets whether the relay has carried nothing whatsoever since the handshake completed.
    /// </summary>
    /// <remarks>THE ONE CONDITION THAT NAMES THIS FAILURE. False the instant anything arrives,
    /// and false for good: a connection that has been answered once is a connection whose
    /// association works, and whatever goes wrong later goes wrong above it.</remarks>
    public bool IsSilent => _relay.RelayedTotal == _relayedAtHandshake;

    /// <summary>Gets how much the relay has carried since the handshake completed.</summary>
    public long RelayedSinceHandshake => _relay.RelayedTotal - _relayedAtHandshake;

    /// <summary>Gets how long ago the handshake completed.</summary>
    public TimeSpan SinceHandshake => Stopwatch.GetElapsedTime(_handshakeCompletedAt);

    /// <summary>Gets the inner relay's account of every datagram it dropped.</summary>
    public string DropSummary => _relay.DropSummary;

    /// <summary>
    /// Reports the gap between the handshake completing and this connection's first request,
    /// exactly once per connection.
    /// </summary>
    /// <remarks>
    /// <para>EMITTED BEFORE THE REQUEST STREAM IS OPENED, so the elapsed time it carries is the
    /// idle window and not the request's own latency. <c>AddressCount</c> carries
    /// <see cref="RelayedSinceHandshake"/> — how many datagrams arrived DURING that window —
    /// which is what separates "the connection sat idle and the association was reaped" from
    /// "the connection sat idle and the path stayed warm". Zero is the interesting value and
    /// the common one, since nothing ack-eliciting is sent between requests (RFC 9000 section
    /// 10.1).</para>
    /// <para>ONCE, BECAUSE THE QUESTION IS ABOUT THE FIRST REQUEST. Later requests on a pooled
    /// connection measure a different gap and are not what the field failure selects for.
    /// </para>
    /// </remarks>
    public void ReportFirstRequest(Action<TlsConnectEvent>? observer)
    {
        if (Interlocked.Exchange(ref _firstRequestReported, 1) != 0)
        {
            return;
        }
        TlsConnectTelemetry.Emit(
            observer,
            _connectionId,
            TlsConnectEventKind.Socks5AssociationFirstRequest,
            _host,
            _port,
            addressCount: (int)Math.Min(RelayedSinceHandshake, int.MaxValue),
            elapsed: SinceHandshake);
    }

    /// <summary>
    /// Reports a request that waited <paramref name="waited"/> on an association that has
    /// relayed nothing since the handshake, and names the failure the caller will see.
    /// </summary>
    /// <remarks>
    /// <para>A <see cref="StaleHttpConnectionException"/> BECAUSE THE TYPE IS THE DECISION, AND
    /// BOTH DECISIONS ARE RIGHT HERE. It is an <c>IOException</c>, which
    /// <c>TlsSession.ShouldRetryException</c> retries for a replayable idempotent request; and
    /// <c>TlsConnectionPool.SendCoreAsync</c> evicts the entry that raised one, so the retry
    /// cannot be handed the same dead association back. A fresh dial takes a fresh RFC 1928
    /// ASSOCIATE, which is the only thing that fixes this, so the request re-dials onto a
    /// working association and the user-visible stall disappears.</para>
    /// <para>NAMED RATHER THAN A BARE TIMEOUT, WHICH IS THE POINT OF THE WHOLE CHANGE. A
    /// timeout is indistinguishable from a slow origin, so the pool could not act on it and
    /// four rounds of investigation read it as a QUIC fault. <see cref="DropSummary"/> is
    /// spliced in because its all-zero form is the positive statement that nothing reached the
    /// socket at all.</para>
    /// </remarks>
    public Exception Reap(
        Action<TlsConnectEvent>? observer,
        TimeSpan waited,
        TimeSpan deadline)
    {
        var sinceHandshake = SinceHandshake;
        var failure = new StaleHttpConnectionException(
            $"The SOCKS5 UDP association to '{_host}' relayed the HTTP/3 (QUIC) handshake and " +
            $"then stopped: nothing at all has come back through it in the {sinceHandshake} " +
            $"since the handshake completed, and this request has been waiting {waited} of " +
            $"that. RFC 1928 section 7 gives an association no way to say it has ended other " +
            $"than closing the control connection, which is still open, so a proxy that " +
            $"blackholes or reaps an idle association is silent by construction and this " +
            $"silence is the only symptom there is. The connection is retired and a fresh " +
            $"ASSOCIATE is the fix. Raise " +
            $"{nameof(TlsQuicOptions)}." +
            $"{nameof(TlsQuicOptions.AssociationSilenceDeadline)} (currently {deadline}) if " +
            $"this path's round trip is genuinely longer than that. {DropSummary}");
        TlsConnectTelemetry.Emit(
            observer,
            _connectionId,
            TlsConnectEventKind.Socks5AssociationWentSilent,
            _host,
            _port,
            elapsed: sinceHandshake,
            exception: failure);
        return failure;
    }
}
