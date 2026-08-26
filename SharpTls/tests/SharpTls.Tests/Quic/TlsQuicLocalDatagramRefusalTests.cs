using System.Net;
using System.Net.Sockets;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

/// <content>
/// What happens when the LOCAL HOST refuses a datagram for its size - Windows WSAEMSGSIZE,
/// .NET <see cref="SocketError.MessageSize"/> - rather than the network dropping it.
/// <para>NOTHING IN THIS SUITE COULD PRODUCE THAT CONDITION BEFORE THIS FILE, WHICH IS WHY THE
/// BUG SHIPPED. Every datagram double here either delivers, drops, delays or duplicates. All
/// four are NETWORK verdicts, and a connection behaves identically for a datagram the network
/// dropped and one that never left the host - so no test could tell them apart. A local refusal
/// is neither: it is a synchronous throw out of the send, on a connection that is otherwise
/// healthy, and the path-MTU search had no branch for it at all.</para>
/// <para>THREE MUTANTS RUN, TWO KILLED, ONE SURVIVING AND SAID SO. Making the refusal reset its
/// counters without moving the search kills both search tests; catching a different
/// <see cref="SocketError"/> kills the Initial-flight test. <c>_ceiling = size</c> in place of
/// <c>size - 1</c> SURVIVES, and is left unwitnessed rather than papered over with an assertion
/// written to catch it: the midpoint the next line computes is strictly below the ceiling
/// either way, so the refused size is never re-offered and the descent is the same one. The row
/// is here so the next reader knows that off-by-one was measured rather than missed.</para>
/// </content>
public sealed partial class TlsQuicConnectionTests
{
    /// <summary>
    /// THE BUG THIS FILE EXISTS FOR. A ceiling above what the interface carries produced an
    /// unbounded stream of identical refusals rather than a search that descended: the throw
    /// came before <c>OnProbeSent</c>, so no outstanding probe was recorded, PROBE_COUNT never
    /// advanced, the RFC 8899 section 5.1.1 inhibition never engaged - it is <c>OnProbeSent</c>
    /// that clears it - and the next pump offered the same size again, forever.
    /// </summary>
    [Fact]
    public void ALocallyRefusedProbeLowersTheCeilingOnTheFirstRefusalRatherThanAfterThree()
    {
        var pathMtu = new TlsQuicPathMtu(1200, 1472);
        pathMtu.OnHandshakeConfirmed();
        pathMtu.OnApplicationDataSent();

        Assert.True(pathMtu.TryGetProbeSize(out var first));
        Assert.Equal(1472, first);

        pathMtu.OnProbeRefusedLocally(first);

        // Descended, on ONE refusal. A LOST probe of the same size would still be at 1472 here
        // and for two more attempts, because loss is ambiguous and a local refusal is not.
        pathMtu.OnApplicationDataSent();
        Assert.True(pathMtu.TryGetProbeSize(out var second));
        Assert.True(
            second < first,
            $"the search did not descend: probed {second} after {first} was refused");
    }

    /// <summary>
    /// The descent terminates. A search that lowered the ceiling but never reached
    /// SEARCH_COMPLETE would trade an unbounded loop of identical probes for an unbounded loop
    /// of shrinking ones, which is the same bug wearing a disguise.
    /// </summary>
    [Fact]
    public void RepeatedLocalRefusalsEndTheSearchInsteadOfProbingForever()
    {
        var pathMtu = new TlsQuicPathMtu(1200, 1472);
        pathMtu.OnHandshakeConfirmed();

        var sizes = new List<int>();
        for (var i = 0; i < 64 && pathMtu.State == TlsQuicPathMtuState.Searching; i++)
        {
            pathMtu.OnApplicationDataSent();
            if (!pathMtu.TryGetProbeSize(out var size))
            {
                break;
            }

            sizes.Add(size);
            pathMtu.OnProbeRefusedLocally(size);
        }

        Assert.Equal(TlsQuicPathMtuState.SearchComplete, pathMtu.State);

        // A binary descent across a 272-byte range with a 16-byte minimum useful gain. The exact
        // count is an implementation detail; that it is bounded and never repeats a size is not.
        Assert.InRange(sizes.Count, 1, 8);
        Assert.Equal(sizes.Count, sizes.Distinct().Count());

        // The PLPMTU never moved: nothing was acknowledged at any of those sizes, so every
        // datagram still leaves at BASE - the conformant answer for a path this client could
        // not measure.
        Assert.Equal(1200, pathMtu.MaximumDatagramSize);
    }

    /// <summary>
    /// The other half: a refusal that is NOT a probe still has to reach the caller, and the
    /// message has to name what Windows will not. A 1200-byte Initial that a route refuses is
    /// unfixable by any knob - RFC 9000 section 14.1 fixes 1200 as the floor - so the failure
    /// must say so rather than read as a tuning problem.
    /// </summary>
    [Fact]
    public async Task ARefusedInitialFlightFailsWithTheSizesRatherThanTheWindowsText()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new RefusingDatagramTransport(refuseAtOrAbove: 1000);
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), TimeProvider.System),
            source => TlsClient(pki, source));

        var failure = await Assert.ThrowsAsync<IOException>(
            () => connection.StartAsync(cancellation.Token).AsTask());

        // The inner exception is the machine-readable half, and the contract a caller that wants
        // to switch transports on this specific condition tests against.
        var inner = Assert.IsType<SocketException>(failure.InnerException);
        Assert.Equal(SocketError.MessageSize, inner.SocketErrorCode);

        // The three numbers Windows omits. The transport header is the one nothing else reports
        // and the one that makes MTU arithmetic done against the QUIC size alone come out wrong.
        Assert.Contains("bytes of QUIC plus", failure.Message, StringComparison.Ordinal);
        Assert.Contains("bytes of transport header", failure.Message, StringComparison.Ordinal);
        Assert.Contains(
            nameof(TlsQuicConnectionSpec.MaximumPathMtu),
            failure.Message,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(TlsQuicConnectionSpec.PathMtuDiscovery),
            failure.Message,
            StringComparison.Ordinal);

        // WHICH BUILDER, AND WHAT WAS IN THE DATAGRAM. Five builders in the connection can
        // produce a refusal and the size alone does not say which; three fixes were aimed at
        // this error from arithmetic before the message was made to name its own origin.
        Assert.Contains(
            "SendInitialFlightAsync", failure.Message, StringComparison.Ordinal);

        // The coalescing walk, reading only clear-text header fields. An Initial flight is one
        // Initial packet filling the datagram, so this is what the walk must say about it - and
        // it is what makes a report of "Initial + Handshake" or "Initial + Initial" from the
        // field a fact rather than an inference.
        Assert.Contains("[SendInitialFlightAsync: Initial ", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("truncated", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("overruns", failure.Message, StringComparison.Ordinal);

        // ONE refusal, not a storm: the Initial flight stops at the first datagram it cannot
        // send rather than working through the rest of the flight.
        Assert.Equal(1, transport.RefusedSends);
    }

    /// <summary>
    /// A transport whose LOCAL send refuses anything at or above a size, the way a DF-set socket
    /// on a small-MTU interface does. NOT an impairment: it throws synchronously out of the send
    /// rather than declining to deliver, and that difference is the whole point of this file.
    /// </summary>
    private sealed class RefusingDatagramTransport(
        int refuseAtOrAbove,
        int datagramOverhead = 32) : ITlsQuicDatagramTransport
    {
        internal int RefusedSends { get; private set; }

        internal IPEndPoint RemoteEndPoint { get; } = new(IPAddress.Loopback, 443);

        public int MaxDatagramPayloadSize => 65507 - datagramOverhead;

        public int DatagramOverhead => datagramOverhead;

        public ValueTask SendAsync(
            IPEndPoint destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            // The interface sees header + payload, which is exactly the sum a caller sizing
            // against the QUIC figure alone forgets to charge for.
            if (payload.Length + datagramOverhead >= refuseAtOrAbove)
            {
                RefusedSends++;
                throw new SocketException((int)SocketError.MessageSize);
            }

            return ValueTask.CompletedTask;
        }

        public ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
            Memory<byte> buffer, CancellationToken cancellationToken) =>
            ValueTask.FromCanceled<TlsQuicDatagramReceiveResult>(
                new CancellationToken(canceled: true));

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
