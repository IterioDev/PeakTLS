using System.Net;
using System.Threading.Channels;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

/// <summary>One datagram an <see cref="InMemoryDatagramTransport"/> pair carried, as it was
/// handed to <c>SendAsync</c>.</summary>
internal sealed record InMemoryDatagram(IPEndPoint From, byte[] Payload);

/// <summary>Two <see cref="ITlsQuicDatagramTransport"/> endpoints wired to each other in
/// memory, so two connection objects can exchange datagrams with no socket, no port and no
/// network. Created only in pairs.</summary>
/// <remarks>
/// <para>ALIASING - THIS DOUBLE COPIES EXACTLY WHERE THE SOCKET TRANSPORTS COPY AND NOWHERE
/// ELSE, AND THAT SYMMETRY IS THE WHOLE POINT OF THE TYPE. A double that copies where the
/// real transport aliases hides an aliasing bug in every task that runs through it; a double
/// that aliases where the real transport copies manufactures a bug that does not exist over
/// a socket. Both directions were considered and the rule below is the one that matches
/// <see cref="TlsQuicUdpDatagramTransport"/> and <see cref="TlsQuicSocks5Transport"/>
/// behaviour for behaviour.</para>
/// <para>SEND COPIES. <c>TlsQuicUdpDatagramTransport.SendAsync</c> hands the payload to
/// <c>Socket.SendToAsync</c> and <c>TlsQuicSocks5Transport.SendAsync</c> copies it into a
/// rented buffer, so under either one the caller may reuse its payload buffer the moment
/// <c>SendAsync</c> returns. This double therefore copies the payload on the way in. Queuing
/// the caller's own memory instead would let a sender's buffer reuse rewrite a datagram
/// already in flight - which cannot happen over a socket, so a test failing that way would
/// be diagnosing the double. Witness:
/// <c>InMemoryDatagramTransportTests.ReusingTheSendBufferDoesNotChangeADeliveredDatagram</c>.
/// </para>
/// <para>RECEIVE COPIES INTO THE CALLER BUFFER AND RETAINS NOTHING. Both socket transports
/// write into the <c>buffer</c> argument and keep no reference to it once the call returns;
/// the packet and frame parsers then alias that buffer, which the caller owns outright. This
/// double does the same. It never hands back memory of its own - the interface signature does
/// not permit it to - so the zero-copy contract on
/// <see cref="ITlsQuicDatagramTransport.ReceiveAsync"/> means here exactly what it means over
/// a socket: the caller buffer is the only thing parsed results alias, and it stays valid
/// until the caller reuses it. Witness:
/// <c>InMemoryDatagramTransportTests.TheTransportRetainsNoAliasOfTheReceiveBuffer</c>.</para>
/// <para>Concurrency follows the interface: one sender and one receiver per endpoint. The
/// queue between them is a channel rather than a lock, because the handoff is genuinely
/// cross-thread here where the socket implementations push it into the kernel.</para>
/// </remarks>
internal sealed class InMemoryDatagramTransport : ITlsQuicDatagramTransport
{
    private readonly Channel<InMemoryDatagram> _inbox = Channel.CreateUnbounded<InMemoryDatagram>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });

    // Assigned by CreatePair, the only way to obtain an instance, so this is never observed
    // null. Not a property: nothing outside the pair may repoint the link.
    private InMemoryDatagramTransport _peer = null!;
    private readonly List<byte[]> _sent = [];
    private int _misdirectedSends;
    private bool _disposed;

    private InMemoryDatagramTransport(IPEndPoint localEndPoint) => LocalEndPoint = localEndPoint;

    /// <summary>Creates two endpoints that deliver to each other.</summary>
    /// <remarks>The endpoints are labels, not bindings: no socket is created and no port is
    /// reserved, so several pairs can coexist carrying the same addresses.</remarks>
    internal static (InMemoryDatagramTransport Client, InMemoryDatagramTransport Server) CreatePair()
    {
        var client = new InMemoryDatagramTransport(new IPEndPoint(IPAddress.Loopback, 50000));
        var server = new InMemoryDatagramTransport(new IPEndPoint(IPAddress.Loopback, 443));
        client._peer = server;
        server._peer = client;
        return (client, server);
    }

    /// <summary>Gets the address this endpoint appears to send from. A datagram it sends
    /// arrives at the peer with this as its
    /// <see cref="TlsQuicDatagramReceiveResult.RemoteEndPoint"/>.</summary>
    internal IPEndPoint LocalEndPoint { get; }

    /// <summary>Gets the number of datagrams dropped because they were addressed somewhere
    /// other than the peer.</summary>
    /// <remarks>A real UDP socket sending where nobody is listening succeeds and the datagram
    /// vanishes, so this double drops rather than throwing - silence is the honest behaviour
    /// and a diagnostic is not. But a silent drop with no signal at all turns "the loopback
    /// handshake hangs" into an unattributable symptom, so the drop is counted and nothing
    /// more. This counter is a claim about what the double did and carries its own witness:
    /// <c>InMemoryDatagramTransportTests.ADatagramSentToTheWrongEndPointIsDroppedAndCounted</c>.
    /// </remarks>
    internal int MisdirectedSends => _misdirectedSends;

    /// <summary>Gets every datagram this endpoint actually delivered, in send order.</summary>
    /// <remarks>DELIVERED, not attempted: a misdirected send is counted by
    /// <see cref="MisdirectedSends"/> and does not appear here, because a datagram nobody
    /// received is not something an observer could have fingerprinted. This is the recording
    /// <c>TlsQuicFingerprintReadout</c> reads, and it is the whole reason task 11 needs no
    /// network - a socket would have shown exactly these bytes.</remarks>
    internal IReadOnlyList<byte[]> Sent => _sent;

    /// <inheritdoc />
    /// <remarks>Matches the direct UDP transport ceiling: this double adds no encapsulation,
    /// so subtracting anything would be an invented limit.</remarks>
    public int MaxDatagramPayloadSize => TlsQuicUdpDatagramTransport.MaximumUdpPayload;

    /// <inheritdoc />
    public ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            payload.Length, MaxDatagramPayloadSize, nameof(payload));
        cancellationToken.ThrowIfCancellationRequested();

        if (!destination.Equals(_peer.LocalEndPoint))
        {
            _misdirectedSends++;
            return ValueTask.CompletedTask;
        }

        // The copy is the aliasing decision, not an optimisation to remove: see the remarks
        // on this type. TryWrite fails only once the peer is disposed, which is a peer that
        // walked away - a socket send to it would also succeed and go nowhere.
        // A SECOND copy, not a shared one: the recording must stay byte-identical to what was
        // emitted however the receiving half treats its own datagram, and header protection
        // removal is an in-place write.
        _sent.Add(payload.ToArray());
        _ = _peer._inbox.Writer.TryWrite(new InMemoryDatagram(LocalEndPoint, payload.ToArray()));
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentException"><paramref name="buffer"/> is smaller than the
    /// datagram waiting for it.</exception>
    public async ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var datagram = await _inbox.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);

        // DELIBERATELY LOUDER THAN EITHER REAL TRANSPORT, AND DELIBERATELY THE SAME ON EVERY
        // MACHINE. The two diverge from each other here, so there is no single behaviour to
        // copy: over a raw UDP socket the outcome is platform-dependent (Windows raises
        // SocketError.MessageSize, Linux truncates silently), while TlsQuicSocks5Transport
        // drops the datagram and keeps waiting, so an oversized one there looks like a
        // receive that simply never completes. Both hide the fault - one behind a platform,
        // one behind a stall - and a double that copied either would let an undersized
        // receive buffer reach a later task as a hang or a one-platform failure. Throwing
        // names the caller buffer, which is what is actually wrong. Worth knowing while
        // debugging a stalled receive against the SOCKS5 path: this double throws where that
        // transport waits. The datagram is consumed either way - a test that provokes this is
        // diagnosing a bug, not continuing.
        if (datagram.Payload.Length > buffer.Length)
        {
            throw new ArgumentException(
                "The datagram is larger than the supplied buffer.", nameof(buffer));
        }

        datagram.Payload.CopyTo(buffer.Span);
        return new TlsQuicDatagramReceiveResult(datagram.Payload.Length, datagram.From);
    }

    /// <inheritdoc />
    /// <remarks>Faults this endpoint pending receive with an
    /// <see cref="ObjectDisposedException"/> somewhere in the exception chain. The interface
    /// calls the type platform-dependent because a socket one is; this one is fixed, so a
    /// test may assert it. Disposing one endpoint leaves the other usable, exactly as closing
    /// one socket does.</remarks>
    public ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;
            _ = _inbox.Writer.TryComplete(
                new ObjectDisposedException(nameof(InMemoryDatagramTransport)));
        }

        return ValueTask.CompletedTask;
    }
}
