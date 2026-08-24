using System.Net;

namespace SharpTls.Quic;

/// <summary>The result of receiving one datagram.</summary>
public readonly struct TlsQuicDatagramReceiveResult
{
    /// <summary>Creates a receive result.</summary>
    public TlsQuicDatagramReceiveResult(int length, IPEndPoint remoteEndPoint)
    {
        Length = length;
        RemoteEndPoint = remoteEndPoint;
    }

    /// <summary>Gets the number of payload bytes written to the caller's buffer.</summary>
    public int Length { get; }

    /// <summary>Gets the address of the peer that originated the datagram. For a relayed
    /// transport this is the decapsulated origin address, never the relay.</summary>
    public IPEndPoint RemoteEndPoint { get; }
}

/// <summary>Sends and receives UDP datagrams on behalf of a QUIC connection.</summary>
/// <remarks>One concurrent send and one concurrent receive are permitted. The shipped
/// implementations perform no internal locking.</remarks>
public interface ITlsQuicDatagramTransport : IAsyncDisposable
{
    /// <summary>Gets the largest payload this transport can carry after its own
    /// encapsulation. This is an endpoint ceiling, not a path MTU: QUIC path MTU
    /// discovery operates below this value.</summary>
    int MaxDatagramPayloadSize { get; }

    /// <summary>Gets the bytes this transport prepends to every datagram before it reaches
    /// the network, which the path MTU has to carry alongside the QUIC payload.</summary>
    /// <remarks>
    /// <para>ZERO FOR A PLAIN UDP SOCKET, and non-zero for anything that encapsulates - a
    /// SOCKS5 UDP relay writes an RFC 1928 section 7 header in front of the payload, so a
    /// QUIC datagram built exactly to the path MTU leaves the interface that many bytes over
    /// it. RFC 9000 s14.2 measures the maximum datagram size as "the total UDP payload size
    /// of a single UDP datagram", which for a relayed transport is header + payload.</para>
    /// <para>DISTINCT FROM <see cref="MaxDatagramPayloadSize"/> BECAUSE THE TWO ANSWER
    /// DIFFERENT QUESTIONS. That property is a 64-kilobyte endpoint ceiling and never binds
    /// in practice; this one is a per-datagram cost that has to come off a path budget of
    /// around 1200-1500 bytes, where it is 2% of the total. Deriving one from the other would
    /// require the transport to know the path MTU, which it does not.</para>
    /// <para>A DEFAULT IMPLEMENTATION, so an existing transport outside this assembly keeps
    /// compiling and keeps its previous behaviour: no encapsulation, nothing to subtract.
    /// RFC 9000 s14.2's "A QUIC implementation MAY be more conservative in computing the
    /// maximum datagram size to allow for unknown tunnel overheads" is the sentence a wrong
    /// zero would be relying on, and it is a MAY - so a transport that does encapsulate is
    /// expected to say so here rather than hope the peer's budget has slack.</para>
    /// </remarks>
    int DatagramOverhead => 0;

    /// <summary>Sends one datagram.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The payload exceeds
    /// <see cref="MaxDatagramPayloadSize"/>.</exception>
    /// <remarks>Disposing the transport while this call is pending causes it to fault
    /// rather than complete. The exact exception type is platform-dependent.</remarks>
    ValueTask SendAsync(
        IPEndPoint destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken);

    /// <summary>Receives one datagram. Malformed or unauthorised datagrams are discarded
    /// and the call keeps waiting; it does not fail the connection.</summary>
    /// <remarks>
    /// <para>Disposing the transport while this call is pending causes it to fault
    /// rather than complete. The exact exception type is platform-dependent.</para>
    /// <para>The QUIC packet and frame parsers in this namespace return fields that alias
    /// the buffer passed here rather than copying it. Aliasing is the default for every
    /// variable-length field they decode, not a property of particular ones: packet header
    /// fields are zero-copy slices of it, and any <c>ReadOnlyMemory&lt;byte&gt;</c> or
    /// <c>ReadOnlySpan&lt;byte&gt;</c> on a parsed header or frame is a slice of it too.
    /// A caller must therefore not mutate, reuse or return <paramref name="buffer"/> to a
    /// pool while any parsed header or frame derived from it is still in use - a decoded
    /// frame outlives its bytes just as visibly as a connection ID does, and reading such a
    /// field back reads that same slice. Enumerating which fields alias would go stale every
    /// time a frame type is added, so treat the rule as covering all of them; the individual
    /// members carry a LIFETIME remark saying so.</para>
    /// </remarks>
    ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken);
}
