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
