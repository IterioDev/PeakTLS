using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SharpTls.Quic;

/// <summary>Relays QUIC datagrams through a SOCKS5 UDP association (RFC 1928 section 4,
/// RFC 1929). Owns a TCP control connection and a UDP relay socket; the control
/// connection must stay open for the association's lifetime.</summary>
public sealed class TlsQuicSocks5Transport : ITlsQuicDatagramTransport
{
    private readonly Socket _control;
    private readonly Socket _udp;
    private readonly IPEndPoint _relayEndPoint;
    private readonly IPEndPoint _receiveTemplate;
    private readonly int _headerSize;
    private readonly string? _destinationHost;
    private readonly TlsQuicSocks5RelaySource _relaySource;
    private readonly CancellationTokenSource _terminationCts = new();
    private readonly Task _controlWatcher;
    private volatile bool _disposed;

    private TlsQuicSocks5Transport(
        Socket control,
        Socket udp,
        IPEndPoint relayEndPoint,
        string? destinationHost,
        TlsQuicSocks5RelaySource relaySource)
    {
        _control = control;
        _udp = udp;
        _relayEndPoint = relayEndPoint;
        _destinationHost = destinationHost;
        _relaySource = relaySource;

        // The domain form is the longer header, so sizing from it keeps MaxDatagramPayloadSize
        // honest: QUIC's path MTU accounting reads that number and a datagram built against a
        // smaller figure would not fit once the name is prepended.
        _headerSize = destinationHost is null
            ? TlsQuicSocks5Protocol.HeaderSizeFor(relayEndPoint.AddressFamily)
            : Math.Max(
                TlsQuicSocks5Protocol.HeaderSizeForDomain(destinationHost),
                TlsQuicSocks5Protocol.HeaderSizeFor(relayEndPoint.AddressFamily));
        _receiveTemplate = new IPEndPoint(
            udp.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

        // RFC 1928: the association ends when the control connection ends. This task
        // watches for that so a pending ReceiveAsync does not hang forever after the
        // proxy (or the peer) has already walked away.
        _controlWatcher = Task.Run(() => WatchControlConnectionAsync(_terminationCts.Token));
    }

    /// <inheritdoc />
    // The relay socket's own family decides the ceiling, and the SOCKS5 header eats into it:
    // every datagram this transport sends is header + payload on the wire, so a payload sized
    // against the bare maximum produces an oversized datagram and SocketError.MessageSize.
    public int MaxDatagramPayloadSize =>
        TlsQuicUdpDatagramTransport.MaximumFor(_udp.AddressFamily) - _headerSize;

    /// <inheritdoc />
    /// <remarks>The same RFC 1928 section 7 header <see cref="MaxDatagramPayloadSize"/>
    /// subtracts, reported on its own so the path MTU budget can charge for it too. Sizing a
    /// QUIC datagram against the path and then prepending this is exactly how a datagram that
    /// fits the path becomes one that does not: on a 1500-byte Ethernet MTU the ceiling is
    /// 1472 bytes of UDP payload, and a 32-byte domain-form header turns a conforming
    /// 1472-byte QUIC datagram into a 1504-byte one that a DF-set socket refuses outright with
    /// SocketError.MessageSize.</remarks>
    public int DatagramOverhead => _headerSize;

    // WHY THESE COUNTERS EXIST AT ALL, AND WHY NOWHERE ELSE COULD CARRY THEM.
    //
    // Every drop in ReceiveAsync's loop used to be a bare `continue`. A datagram that arrived
    // and was discarded here therefore looked, from every vantage point above this class,
    // exactly like a datagram that never arrived: the QUIC layer counts what it is handed, so
    // TlsQuicConnection.DiscardedPackets, DiscardedForMissingKeys, RetainedForLaterKeys and
    // ReplayedAfterKeysArrived all read zero either way. A field report of "no handshake
    // response, every QUIC counter zero" is consistent with BOTH, and picking between them is
    // the first thing anyone debugging a relayed stall needs to do.
    //
    // THEY ARE READ OFF THIS TYPE BY THE CALLER THAT CONSTRUCTED IT, deliberately, and
    // ITlsQuicDatagramTransport is not widened to carry them. The interface is what
    // TlsQuicConnection holds, and a connection cannot act on these numbers - they describe
    // one particular encapsulation that most transports do not perform. So ConnectAsync
    // returns TlsQuicSocks5Transport rather than the interface, and a caller whose handshake
    // threw TimeoutException reads DropSummary off the transport it already owns and appends
    // it to what TlsQuicConnection.DeadlineExceeded said. That is the honest shape: an
    // optional diagnostic interface with exactly one implementation would be the same coupling
    // with a layer of ceremony on top.
    //
    // NOT SYNCHRONISED, matching the interface's "one concurrent send and one concurrent
    // receive" contract: only the receive loop writes them. A caller reading them from another
    // thread after a failed handshake sees an int and a reference, both of which this platform
    // reads atomically - it may see a value one datagram stale, which no diagnosis turns on.

    /// <summary>Gets how many relayed datagrams were dropped because their source did not
    /// satisfy <see cref="TlsQuicSocks5Options.RelaySource"/>.</summary>
    /// <remarks>NON-ZERO WITH A SILENT HANDSHAKE IS THE POOLED-RELAY DIAGNOSIS: traffic is
    /// coming back, and this transport is throwing it away before QUIC ever sees it. Read
    /// <see cref="LastUnexpectedSource"/> next to find out from where, and loosen the policy to
    /// match. Under <see cref="TlsQuicSocks5RelaySource.Any"/> nothing can fail the check, so
    /// this stays zero by construction.</remarks>
    public int DatagramsFromUnexpectedSource { get; private set; }

    /// <summary>Gets the source of the most recent datagram
    /// <see cref="DatagramsFromUnexpectedSource"/> counted, or <see langword="null"/> if none
    /// has been dropped.</summary>
    /// <remarks>THE COUNTER ALONE CANNOT CLOSE THE INVESTIGATION. "Something arrived from the
    /// wrong place" and "the relay at 203.0.113.7:1080 replied from 203.0.113.7:51413" lead to
    /// different next actions, and only the second says which
    /// <see cref="TlsQuicSocks5RelaySource"/> setting would carry the traffic. Compare it
    /// against the BND.ADDR:BND.PORT the ASSOCIATE reply carried: a differing port alone is the
    /// ordinary pooled case, a differing address means the pool answers from a sibling
    /// host.</remarks>
    public IPEndPoint? LastUnexpectedSource { get; private set; }

    /// <summary>Gets how many relayed datagrams were dropped because their RFC 1928 section 7
    /// UDP request header did not parse - a non-zero RSV, a FRAG this transport does not
    /// reassemble, an unknown ATYP, or a header running past the end of the datagram.</summary>
    /// <remarks>Section 7's "Implementation of fragmentation is optional; an implementation
    /// that does not support fragmentation MUST drop any datagram whose FRAG field is other
    /// than X'00'" is one of the ways to land here, and against a relay that fragments it would
    /// be the whole explanation for a stall.</remarks>
    public int MalformedRelayHeaders { get; private set; }

    /// <summary>Gets how many relayed datagrams were dropped because the payload left after
    /// the RFC 1928 section 7 header would not fit the buffer the caller passed to
    /// <see cref="ReceiveAsync"/>.</summary>
    /// <remarks>QUIC sizes its own receive buffer, so this rising means the peer is sending
    /// datagrams larger than this connection is prepared to read rather than anything the relay
    /// did wrong.</remarks>
    public int OversizedRelayPayloads { get; private set; }

    /// <summary>Gets a one-line summary of every datagram this transport dropped, for splicing
    /// into whatever a failed handshake reports.</summary>
    /// <remarks>The counters are individually readable above; this exists so the caller that
    /// catches a <see cref="TimeoutException"/> out of a QUIC handshake can say what happened
    /// BELOW the layer that threw it without hand-formatting four numbers. All zeros really
    /// does mean nothing reached this socket.</remarks>
    public string DropSummary =>
        $"SOCKS5 relay drops: {DatagramsFromUnexpectedSource} from an unexpected source"
            + (LastUnexpectedSource is null ? string.Empty : $" (last {LastUnexpectedSource})")
            + $" under {_relaySource} against BND {_relayEndPoint}, "
            + $"{MalformedRelayHeaders} with an unparseable RFC 1928 s7 header, "
            + $"{OversizedRelayPayloads} too large for the caller's buffer. "
            + "ALL ZERO MEANS NOTHING ARRIVED AT THIS SOCKET AT ALL; a non-zero unexpected-source "
            + "count means the relay is answering from somewhere other than BND and "
            + "TlsQuicSocks5Options.RelaySource is discarding it.";

    /// <summary>Connects to a SOCKS5 proxy and establishes a UDP association for relaying
    /// QUIC datagrams.</summary>
    /// <exception cref="ArgumentException"><see cref="TlsQuicSocks5Options.Username"/> and
    /// <see cref="TlsQuicSocks5Options.Password"/> were not both supplied or both
    /// omitted.</exception>
    /// <exception cref="TlsQuicProxyException">The proxy rejected the negotiation, the
    /// authentication, or the UDP ASSOCIATE request.</exception>
    /// <remarks>RETURNS THE CONCRETE TYPE, not <see cref="ITlsQuicDatagramTransport"/>, so the
    /// caller keeps a handle on <see cref="DropSummary"/> and the counters behind it. A QUIC
    /// connection takes the interface and is unaffected; what a relayed datagram dropped for a
    /// SOCKS5 reason needs is a reader on this side of the abstraction.</remarks>
    public static async Task<TlsQuicSocks5Transport> ConnectAsync(
        TlsQuicSocks5Options options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if ((options.Username is null) != (options.Password is null))
        {
            throw new ArgumentException(
                "Username and Password must both be supplied or both omitted.", nameof(options));
        }

        Socket? control = null;
        Socket? udp = null;
        try
        {
            control = await ConnectControlSocketAsync(options.ProxyEndPoint, cancellationToken)
                .ConfigureAwait(false);

            var proxy = (IPEndPoint)control.RemoteEndPoint!;

            udp = new Socket(proxy.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(
                proxy.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
            TlsQuicUdpDatagramTransport.SetDontFragment(udp, proxy.AddressFamily);

            // THE RELAY SOCKET NEEDS IT MOST. A SOCKS5 relay that drops its association,
            // restarts, or simply has no listener for a moment answers with ICMP Port
            // Unreachable, and Windows then fails this socket's NEXT receive with
            // WSAECONNRESET - a datagram unrelated to the one that bounced.
            TlsQuicUdpDatagramTransport.DisableUdpConnectionReset(udp);

            await NegotiateAsync(control, options, cancellationToken).ConfigureAwait(false);
            var relayEndPoint = await AssociateAsync(control, proxy, cancellationToken).ConfigureAwait(false);

            var transport = new TlsQuicSocks5Transport(
                control, udp, relayEndPoint, options.DestinationHost, options.RelaySource);
            control = null;
            udp = null;
            return transport;
        }
        finally
        {
            udp?.Dispose();
            control?.Dispose();
        }
    }

    // Resolves a DnsEndPoint (TlsQuicSocks5Options documents that it is accepted) and
    // connects with a socket created for that exact address family. Deferring the family
    // to the OS (`new Socket(SocketType, ProtocolType)` + instance ConnectAsync) looks
    // equivalent but is not: on this platform it silently produces a dual-stack IPv6
    // socket even for a literal IPv4 target, so control.RemoteEndPoint reports
    // InterNetworkV6 — which then mismatches the IPv4 relay address a real SOCKS5
    // ASSOCIATE reply carries, and every UDP send fails with a family mismatch.
    private static async Task<Socket> ConnectControlSocketAsync(
        EndPoint proxyEndPoint, CancellationToken cancellationToken)
    {
        if (proxyEndPoint is DnsEndPoint dns)
        {
            var addresses = await System.Net.Dns
                .GetHostAddressesAsync(dns.Host, cancellationToken).ConfigureAwait(false);
            if (addresses.Length == 0)
            {
                throw new SocketException((int)SocketError.HostNotFound);
            }

            proxyEndPoint = new IPEndPoint(addresses[0], dns.Port);
        }

        var target = (IPEndPoint)proxyEndPoint;
        var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(target, cancellationToken).ConfigureAwait(false);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    // RFC 1928 s3 greeting/method-selection, then RFC 1929 s2 subnegotiation if selected.
    private static async Task NegotiateAsync(
        Socket control, TlsQuicSocks5Options options, CancellationToken cancellationToken)
    {
        var hasCredentials = options.Username is not null;

        // RFC 1928 s3: "The server selects from one of the methods given in METHODS" — the
        // server chooses, we don't get to hint. Offer MethodUsernamePassword only when we
        // actually hold credentials: offering it unconditionally would advertise a
        // capability we don't have, and a proxy configured to accept either method (a
        // common configuration) could then select username/password and fail a connection
        // that offering only MethodNoAuthentication would have let succeed.
        await WriteAsync(
            control, TlsQuicSocks5Protocol.EncodeGreeting(offerUsernamePassword: hasCredentials), cancellationToken)
            .ConfigureAwait(false);

        var selection = await ReadExactAsync(control, 2, cancellationToken).ConfigureAwait(false);
        var method = TlsQuicSocks5Protocol.ParseMethodSelection(selection);

        switch (method)
        {
            case TlsQuicSocks5Protocol.MethodNoAuthentication:
                return;

            case TlsQuicSocks5Protocol.MethodUsernamePassword when hasCredentials:
                var request = TlsQuicSocks5Protocol.EncodeAuthenticationRequest(
                    options.Username!, options.Password!);
                try
                {
                    await WriteAsync(control, request, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    // The codec's comment is explicit: the returned buffer still holds the
                    // credentials, and the caller — us — must zero it once it has been
                    // written to the socket, even if the write itself failed.
                    CryptographicOperations.ZeroMemory(request);
                }

                var reply = await ReadExactAsync(control, 2, cancellationToken).ConfigureAwait(false);
                TlsQuicSocks5Protocol.ValidateAuthenticationReply(reply);
                return;

            // Unreachable against a compliant proxy: we never offer MethodUsernamePassword
            // without credentials (see the greeting above), and RFC 1928 s3 requires the
            // server to select only from what was offered. Kept as a defensive branch for
            // a non-compliant proxy that selects a method we didn't offer — not dead code.
            case TlsQuicSocks5Protocol.MethodUsernamePassword:
                throw new TlsQuicProxyException(
                    TlsQuicProxyError.CredentialsRequired,
                    "The SOCKS5 proxy requires username/password authentication but none were configured.");

            default:
                // RFC 1928 s3: METHOD 0xFF means none of the offered methods were
                // acceptable, and "the client MUST close the connection" — control.Dispose()
                // in ConnectAsync's finally handles that since this throw unwinds there.
                throw new TlsQuicProxyException(
                    TlsQuicProxyError.NoAcceptableAuthenticationMethod,
                    hasCredentials
                        ? $"The SOCKS5 proxy accepted none of the offered authentication methods " +
                          $"(selected 0x{method:X2})."
                        : "The SOCKS5 proxy accepted none of the offered authentication methods. No " +
                          "credentials were configured, so only 'no authentication' was offered; this proxy " +
                          "appears to require a username and password.");
        }
    }

    // RFC 1928 s4/s6: CMD is UDP ASSOCIATE; the reply carries the relay endpoint to send
    // encapsulated datagrams to.
    private static async Task<IPEndPoint> AssociateAsync(
        Socket control, IPEndPoint proxy, CancellationToken cancellationToken)
    {
        await WriteAsync(
            control, TlsQuicSocks5Protocol.EncodeAssociateRequest(proxy.AddressFamily), cancellationToken)
            .ConfigureAwait(false);

        byte[] header;
        try
        {
            header = await ReadExactAsync(control, 4, cancellationToken).ConfigureAwait(false);
        }
        catch (TlsQuicProxyException exception)
            when (exception.Error == TlsQuicProxyError.MalformedProxyResponse)
        {
            // Authentication already succeeded to get here, so the proxy speaks SOCKS5 and the
            // credentials are good — it closed on seeing CMD=UDP ASSOCIATE. That is the normal
            // behaviour of a TCP-only proxy, which most commercial residential pools are: they
            // implement CONNECT and nothing else. QUIC is UDP, so there is no client-side way
            // around it.
            throw new TlsQuicProxyException(
                TlsQuicProxyError.MalformedProxyResponse,
                "The SOCKS5 proxy closed the control connection without answering UDP ASSOCIATE. " +
                "Authentication had already succeeded, so this proxy almost certainly relays TCP " +
                "only and does not implement RFC 1928 section 7 UDP ASSOCIATE - which QUIC " +
                $"requires. Use a proxy that relays UDP, or a TCP version policy for this one. " +
                $"({exception.Message})");
        }

        var addressType = TlsQuicSocks5Protocol.ValidateAssociateReplyHeader(header);

        var addressLength = addressType == TlsQuicSocks5Protocol.AddressIPv6 ? 16 : 4;
        var tail = await ReadExactAsync(control, addressLength + 2, cancellationToken).ConfigureAwait(false);
        var port = BinaryPrimitives.ReadUInt16BigEndian(tail.AsSpan(addressLength, 2));

        return TlsQuicSocks5Protocol.ResolveRelayEndPoint(
            addressType, tail.AsSpan(0, addressLength), port, proxy.Address);
    }

    private static ValueTask<int> WriteAsync(Socket control, byte[] buffer, CancellationToken cancellationToken) =>
        control.SendAsync(buffer, SocketFlags.None, cancellationToken);

    // Reads exactly `length` bytes or throws. A short read followed by a graceful close
    // is reported by name — how many of how many bytes arrived — rather than as a bare
    // IOException, since that is what a caller debugging a flaky proxy needs to see.
    private static async Task<byte[]> ReadExactAsync(Socket control, int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await control
                .ReceiveAsync(buffer.AsMemory(offset, length - offset), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw TlsQuicSocks5Protocol.Malformed(
                    $"SOCKS5 control connection closed after {offset} of {length} expected bytes.");
            }

            offset += read;
        }

        return buffer;
    }

    // THE SAME WINSOCK LIFECYCLE FAULT AS THE PLAIN UDP TRANSPORT, WITH ONE MORE WAY TO
    // ARRIVE. TlsQuicUdpDatagramTransport.IsTeardownFault has the full account of why
    // WSA_OPERATION_ABORTED (995) and ObjectDisposedException are lifecycle events rather than
    // network errors, and it is shared rather than restated so the two transports cannot drift
    // on which SocketErrors are real.
    //
    // WHAT IS DIFFERENT HERE IS THAT THERE ARE TWO THINGS TO TEAR DOWN. This transport owns a
    // UDP relay socket AND a TCP control connection, and RFC 1928 makes the association end
    // when the control connection ends - so a pending receive can be aborted by our own
    // disposal, by the caller's token, or by the control watcher cancelling the internal
    // token, and those are three different answers to "what happened". The order below is the
    // order of authority: the caller's own request outranks our disposal, which outranks a
    // proxy-side end that the disposal would have caused anyway.
    //
    // THE FILTER AT EACH CALL SITE GUARANTEES THE LAST BRANCH IS REACHED ONLY WHEN IT IS TRUE,
    // so an abort with none of the three causes - Winsock's other documented cause is a thread
    // exit - is never relabelled as a teardown this transport performed. It propagates
    // untouched instead.
    private Exception TranslateTeardown(Exception cause, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return new OperationCanceledException(
                "The SOCKS5 relayed socket operation was cancelled.", cause, cancellationToken);
        }

        if (_disposed)
        {
            return new ObjectDisposedException(
                nameof(TlsQuicSocks5Transport),
                "The SOCKS5 UDP transport was disposed while a socket operation was pending.");
        }

        return new TlsQuicProxyException(
            TlsQuicProxyError.AssociationTerminated,
            "The SOCKS5 UDP association has ended; the control connection closed.");
    }

    // True when one of the three teardowns above is the reason a socket call failed.
    private bool IsTeardownInProgress(CancellationToken cancellationToken) =>
        cancellationToken.IsCancellationRequested
            || _disposed
            || _terminationCts.IsCancellationRequested;

    /// <inheritdoc />
    public async ValueTask SendAsync(
        IPEndPoint destination, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            payload.Length, MaxDatagramPayloadSize, nameof(payload));

        if (_terminationCts.IsCancellationRequested)
        {
            throw new TlsQuicProxyException(
                TlsQuicProxyError.AssociationTerminated,
                "The SOCKS5 UDP association has ended; the control connection closed.");
        }

        // Rented, not allocated: this is the per-datagram hot path.
        var rented = ArrayPool<byte>.Shared.Rent(_headerSize + payload.Length);
        try
        {
            // A proxy whose ruleset forbids literal-address destinations needs the name.
            var headerLength = _destinationHost is null
                ? TlsQuicSocks5Protocol.WriteUdpHeader(rented, destination)
                : TlsQuicSocks5Protocol.WriteUdpHeader(
                    rented, _destinationHost, destination.Port);
            payload.Span.CopyTo(rented.AsSpan(headerLength));

            await _udp
                .SendToAsync(
                    rented.AsMemory(0, headerLength + payload.Length),
                    SocketFlags.None,
                    _relayEndPoint,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (
            TlsQuicUdpDatagramTransport.IsTeardownFault(exception)
                && IsTeardownInProgress(cancellationToken))
        {
            // The check at the top of this method closes the association-already-ended case
            // BEFORE the send; this closes the one that opens between that check and the
            // socket call. SocketError.MessageSize is outside IsTeardownFault and so still
            // propagates - TlsQuicConnection reads it as the host refusing an oversized
            // datagram, which is the only feedback path MTU discovery has.
            throw TranslateTeardown(exception, cancellationToken);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    // WHETHER A REPLY'S SOURCE IS CLOSE ENOUGH TO BND TO BE THIS ASSOCIATION'S TRAFFIC.
    //
    // THIS USED TO BE `_relayEndPoint.Equals(result.RemoteEndPoint)` AND THAT IS STRICTER THAN
    // RFC 1928 ASKS FOR. Section 7 constrains BND in one direction only - "In the reply to a
    // UDP ASSOCIATE request, the BND.PORT and BND.ADDR fields indicate the port number/address
    // where the client MUST send UDP request messages to be relayed" - and says of the return
    // direction merely that the relay "MUST encapsulate that datagram using the above UDP
    // request header". Nothing anywhere in RFC 1928 says the reply's source will be, or must
    // be, BND. Section 6 goes out of its way in the other direction: "The supplied BND.ADDR is
    // often different from the IP address that the client uses to reach the SOCKS server, since
    // such servers are often multi-homed."
    //
    // SO EQUALITY WAS AN ASSUMPTION WEARING A SPEC CITATION, and a pooled or load-balanced
    // relay that answers from another ephemeral port on the same host - which is ordinary
    // behaviour, not a violation - had every reply discarded here, invisibly, and the handshake
    // simply timed out.
    //
    // WHAT THE DEFAULT IS ANCHORED TO INSTEAD is the one source test section 7 does mandate,
    // pointed back at the relay: "The UDP relay server MUST acquire from the SOCKS server the
    // expected IP address of the client ... It MUST drop any datagrams arriving from any source
    // IP address other than the one recorded for the particular association." An IP address,
    // with no port. TlsQuicSocks5RelaySource.AddressOnly is that, and it holds the line that
    // matters: this socket is bound to a wildcard address and any host that can route to it can
    // send to it, so a forged datagram must at minimum come from the relay's own address before
    // the QUIC layer will look at it.
    //
    // TlsQuicDatagramTransportTests.ARelayReplyingFromAnotherPortIsAccepted
    // ByDefault pins the loosening, and TlsQuicDatagramTransportTests.AnExact
    // RelaySourceDropsAReplyFromAnotherPortAndNamesIt pins that the strict setting still
    // rejects and, unlike the code this replaced, says what it rejected.
    private bool IsFromRelay(EndPoint source) => _relaySource switch
    {
        TlsQuicSocks5RelaySource.Any => true,
        TlsQuicSocks5RelaySource.AddressOnly =>
            source is IPEndPoint endPoint && _relayEndPoint.Address.Equals(endPoint.Address),

        // Exact, and anything a future value forgets to handle: the pre-existing behaviour,
        // which is the safe direction to fail in.
        _ => _relayEndPoint.Equals(source),
    };

    /// <inheritdoc />
    public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer, CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, _terminationCts.Token);
        var scratchLength = _headerSize + buffer.Length;

        while (true)
        {
            var rented = ArrayPool<byte>.Shared.Rent(scratchLength);
            try
            {
                SocketReceiveFromResult result;
                try
                {
                    result = await _udp
                        .ReceiveFromAsync(
                            rented.AsMemory(0, scratchLength), SocketFlags.None, _receiveTemplate, linked.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException exception)
                    when (IsTeardownInProgress(cancellationToken))
                {
                    // THE RECEIVE RUNS ON A LINKED TOKEN, SO THE EXCEPTION .NET RAISES NAMES
                    // THE LINK AND NOT ITS CAUSE. All three teardowns cancel that one token:
                    // the caller's own request flows into it, DisposeAsync cancels the
                    // internal source before closing the sockets, and the control watcher
                    // cancels it on seeing the association end. TranslateTeardown re-reads the
                    // sources in order of authority and re-raises the shape that belongs to
                    // each - a caller cancel carrying the CALLER's token rather than a linked
                    // one it never held, a disposal as a disposal, and only what is left as
                    // RFC 1928's association-ended.
                    //
                    // The filter clause this replaced was `!cancellationToken.Is
                    // CancellationRequested && _terminationCts.IsCancellationRequested &&
                    // !_disposed`, which is the same order of authority written as one
                    // condition - it just had nowhere to send the two cases it excluded.
                    throw TranslateTeardown(exception, cancellationToken);
                }
                catch (Exception exception) when (
                    TlsQuicUdpDatagramTransport.IsTeardownFault(exception)
                        && IsTeardownInProgress(cancellationToken))
                {
                    // WHY THIS CLAUSE IS NEEDED WHEN THE ONE ABOVE ALREADY EXISTS. That one
                    // catches an OperationCanceledException, which is what .NET produces when
                    // the token the receive was STARTED with is the thing that fired. Neither
                    // of this transport's own teardowns is guaranteed to arrive that way: the
                    // UDP socket's Dispose aborts the pending overlapped receive with
                    // WSA_OPERATION_ABORTED and no token cancelled, and a receive re-entered
                    // after that disposal - this loop continues past a datagram it drops -
                    // throws ObjectDisposedException before it reaches the wire. Both used to
                    // escape as themselves.
                    //
                    // TlsQuicDatagramTransportTests.DisposingARelayedTransportWhileAReceiveIs
                    // PendingSurfacesAsDisposal pins it.
                    throw TranslateTeardown(exception, cancellationToken);
                }

                // RFC 9000 s14: a datagram that fails validation is dropped and the receive
                // loop keeps waiting — never fatal, or any host reaching this UDP port could
                // kill the connection with one junk packet.
                //
                // EACH OF THE THREE DROPS BELOW IS COUNTED BEFORE IT CONTINUES. They were bare
                // `continue`s, and a bare `continue` here is indistinguishable from silence on
                // the wire to everything above this class - see the counters' own remarks.
                if (!IsFromRelay(result.RemoteEndPoint))
                {
                    DatagramsFromUnexpectedSource++;

                    // The receive template is not reused: ReceiveFromAsync creates a fresh
                    // EndPoint from the address it actually read, so retaining it does not
                    // capture something the next receive will overwrite.
                    LastUnexpectedSource = result.RemoteEndPoint as IPEndPoint;
                    continue;
                }

                if (!TlsQuicSocks5Protocol.TryReadUdpHeader(
                        rented.AsSpan(0, result.ReceivedBytes), out var origin, out var headerLength))
                {
                    MalformedRelayHeaders++;
                    continue;
                }

                var payloadLength = result.ReceivedBytes - headerLength;
                if (payloadLength > buffer.Length)
                {
                    OversizedRelayPayloads++;
                    continue;
                }

                rented.AsSpan(headerLength, payloadLength).CopyTo(buffer.Span);
                return new TlsQuicDatagramReceiveResult(payloadLength, origin);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    // RFC 1928: the association ends when the control connection ends. Any completion —
    // zero bytes, a byte, or a socket error — ends it; only the exceptions expected from
    // our own shutdown path are swallowed.
    private async Task WatchControlConnectionAsync(CancellationToken cancellationToken)
    {
        try
        {
            _ = await _control
                .ReceiveAsync(new byte[1], SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return; // Disposal already signalled termination.
        }
        catch (ObjectDisposedException)
        {
            return; // Disposal already signalled termination.
        }
        catch (SocketException)
        {
            // Disposal, or the peer resetting the connection, can surface this way instead
            // of a graceful zero-byte read — either way the association is over.
        }

        if (!cancellationToken.IsCancellationRequested)
        {
            await _terminationCts.CancelAsync().ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        await _terminationCts.CancelAsync().ConfigureAwait(false);

        // The UDP socket closes first: a pending ReceiveAsync then faults from that
        // disposal directly rather than from the control connection closing a moment later.
        // What the caller sees is no longer platform-dependent - _disposed is already true
        // above, so whichever shape the platform produces (an OperationCanceledException from
        // the internal token, WSA_OPERATION_ABORTED from closing the handle under a posted
        // overlapped receive, or ObjectDisposedException from a receive re-entered after it)
        // is translated to ObjectDisposedException by TranslateTeardown.
        _udp.Dispose();
        _control.Dispose();

        try
        {
            await _controlWatcher.ConfigureAwait(false);
        }
        catch
        {
            // WatchControlConnectionAsync already swallows the exceptions its own
            // shutdown path produces; this is a defensive backstop, not an expected path.
        }

        _terminationCts.Dispose();
    }
}
