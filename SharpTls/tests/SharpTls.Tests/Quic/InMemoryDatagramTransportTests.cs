using System.Net;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// The doubles are code and fail the same ways the code under test does, so they are tested
// like it. Two groups of tests live here: the contract group, which is the same set
// TlsQuicDatagramTransportTests applies to the two socket transports (round trip, sender
// reporting, the payload ceiling, disposal, cancellation), and the aliasing group, which is
// specific to a double and is the reason this file is longer than the type it covers.
//
// A double gets aliasing wrong in two opposite ways and both are silent. Copying where the
// real transport aliases hides a real bug in every later task; aliasing where the real
// transport copies invents one. So each of the two decisions has its own named witness rather
// than being asserted in passing by a round-trip test.
public sealed class InMemoryDatagramTransportTests
{
    [Fact]
    public async Task ADatagramCrossesToThePeerByteForByte()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        await client.SendAsync(server.LocalEndPoint, new byte[] { 1, 2, 3 }, CancellationToken.None);

        var buffer = new byte[16];
        var result = await server.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(3, result.Length);
        Assert.Equal(new byte[] { 1, 2, 3 }, buffer[..3]);
    }

    [Fact]
    public async Task AReceivedDatagramReportsTheSenderNotTheDestination()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        await client.SendAsync(server.LocalEndPoint, new byte[] { 9 }, CancellationToken.None);

        var result = await server.ReceiveAsync(new byte[8], CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        // RemoteEndPoint is documented as the peer that originated the datagram. The two
        // endpoints differ, so a double that reported the destination instead would still
        // return a plausible address and pass a weaker assertion.
        Assert.Equal(client.LocalEndPoint, result.RemoteEndPoint);
        Assert.NotEqual(server.LocalEndPoint, result.RemoteEndPoint);
    }

    [Fact]
    public async Task BothDirectionsCarryIndependently()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        await client.SendAsync(server.LocalEndPoint, new byte[] { 1 }, CancellationToken.None);
        await server.SendAsync(client.LocalEndPoint, new byte[] { 2 }, CancellationToken.None);

        var atServer = new byte[8];
        var atClient = new byte[8];
        var serverResult = await server.ReceiveAsync(atServer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        var clientResult = await client.ReceiveAsync(atClient, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        // A single shared queue would deliver one endpoint the other datagram, or deliver
        // one endpoint its own.
        Assert.Equal(1, atServer[0]);
        Assert.Equal(2, atClient[0]);
        Assert.Equal(client.LocalEndPoint, serverResult.RemoteEndPoint);
        Assert.Equal(server.LocalEndPoint, clientResult.RemoteEndPoint);
    }

    // ALIASING WITNESS 1 - the send side copies.
    //
    // Over a socket the payload is gone into the kernel by the time SendAsync returns, so the
    // caller is free to reuse the buffer immediately, and the connection loop this double
    // exists for does exactly that. A double that queued the caller memory would let that
    // reuse rewrite a datagram already in flight: a failure with no counterpart on a real
    // network, appearing in whichever later task happened to reuse a buffer.
    [Fact]
    public async Task ReusingTheSendBufferDoesNotChangeADeliveredDatagram()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        var payload = new byte[] { 1, 2, 3, 4 };
        await client.SendAsync(server.LocalEndPoint, payload, CancellationToken.None);
        payload.AsSpan().Fill(0xFF);

        var buffer = new byte[8];
        var result = await server.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(4, result.Length);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, buffer[..4]);
    }

    // ALIASING WITNESS 2 - the receive side keeps no reference to the caller buffer.
    //
    // ITlsQuicDatagramTransport.ReceiveAsync documents that parsed headers and frames are
    // slices of the buffer passed in, valid while that buffer is unmodified. That is only
    // true if the transport stops touching the buffer when the call returns. Here the first
    // buffer is checked after a second datagram has been received into a different one: if
    // the transport had retained the first, the second delivery would have overwritten
    // results a caller still holds - an aliasing violation invisible to a round-trip test.
    [Fact]
    public async Task TheTransportRetainsNoAliasOfTheReceiveBuffer()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        await client.SendAsync(server.LocalEndPoint, new byte[] { 1, 1, 1 }, CancellationToken.None);
        await client.SendAsync(server.LocalEndPoint, new byte[] { 2, 2, 2 }, CancellationToken.None);

        var first = new byte[8];
        _ = await server.ReceiveAsync(first, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        var second = new byte[8];
        var secondResult = await server.ReceiveAsync(second, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(new byte[] { 1, 1, 1 }, first[..3]);
        Assert.Equal(new byte[] { 2, 2, 2 }, second[..3]);
        Assert.Equal(3, secondResult.Length);
    }

    // The caller mutating its own buffer after the pass is the normal case, not a hazard -
    // that is precisely what the aliasing contract permits once parsed results are done with.
    // It must not reach back into anything the transport still holds.
    [Fact]
    public async Task MutatingAReceiveBufferAfterThePassDoesNotDisturbTheQueue()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        await client.SendAsync(server.LocalEndPoint, new byte[] { 7, 7 }, CancellationToken.None);
        await client.SendAsync(server.LocalEndPoint, new byte[] { 8, 8 }, CancellationToken.None);

        var buffer = new byte[8];
        _ = await server.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        buffer.AsSpan().Fill(0xAA);

        var result = await server.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(2, result.Length);
        Assert.Equal(new byte[] { 8, 8 }, buffer[..2]);
    }

    [Fact]
    public async Task ADatagramSentToTheWrongEndPointIsDroppedAndCounted()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        Assert.Equal(0, client.MisdirectedSends);

        await client.SendAsync(
            new IPEndPoint(IPAddress.Loopback, 9), new byte[] { 1 }, CancellationToken.None);

        Assert.Equal(1, client.MisdirectedSends);

        // And it really did not arrive: the peer sees only the correctly addressed one.
        await client.SendAsync(server.LocalEndPoint, new byte[] { 2 }, CancellationToken.None);
        var buffer = new byte[8];
        var result = await server.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, result.Length);
        Assert.Equal(2, buffer[0]);
        Assert.Equal(1, client.MisdirectedSends);
    }

    [Fact]
    public async Task AnOversizedPayloadIsRejected()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        var error = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await client.SendAsync(
                server.LocalEndPoint,
                new byte[client.MaxDatagramPayloadSize + 1],
                CancellationToken.None));

        Assert.Equal("payload", error.ParamName);
    }

    // The ceiling is inclusive. Without this the guard could be off by one in the strict
    // direction and every test above would still pass.
    [Fact]
    public async Task APayloadExactlyAtTheCeilingIsAccepted()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        await client.SendAsync(
            server.LocalEndPoint,
            new byte[client.MaxDatagramPayloadSize],
            CancellationToken.None);
    }

    [Fact]
    public async Task TheCeilingMatchesTheDirectUdpTransport()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        // This double adds no encapsulation, so RFC 9000 s18.2 maximum UDP payload is the
        // honest ceiling; the SOCKS5 transport subtracts its header and this one must not.
        Assert.Equal(
            TlsQuicUdpDatagramTransport.MaximumUdpPayload, client.MaxDatagramPayloadSize);
    }

    [Fact]
    public async Task ADatagramLargerThanTheReceiveBufferIsRejected()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        await client.SendAsync(server.LocalEndPoint, new byte[4], CancellationToken.None);

        // Bounded like every other receive in this file. An unbounded await here hangs the
        // whole run rather than failing when the datagram does not arrive - which is what a
        // mutation to the delivery path does, and a sweep that hangs reports nothing at all.
        var error = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await server.ReceiveAsync(new byte[3], CancellationToken.None)
                .AsTask().WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Equal("buffer", error.ParamName);
    }

    [Fact]
    public async Task ADatagramExactlyFillingTheReceiveBufferIsDelivered()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        await client.SendAsync(server.LocalEndPoint, new byte[] { 1, 2, 3 }, CancellationToken.None);

        var buffer = new byte[3];
        var result = await server.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(3, result.Length);
        Assert.Equal(new byte[] { 1, 2, 3 }, buffer);
    }

    [Fact]
    public async Task DisposingTwiceIsSafe()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var serverLink = server;

        await client.DisposeAsync();
        await client.DisposeAsync();
    }

    // The interface requires disposal to fault a pending call rather than complete it. It
    // calls the exception type platform-dependent because a socket one is; a double has no
    // platform, so the type is fixed here and asserted, which is what kills a mutation that
    // completes the queue without an error.
    [Fact]
    public async Task DisposingFaultsAPendingReceive()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;

        var pending = server.ReceiveAsync(new byte[64], CancellationToken.None).AsTask();
        await server.DisposeAsync();

        var error = await Assert.ThrowsAnyAsync<Exception>(
            async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)));
        AssertDisposalCaused(error);
    }

    [Fact]
    public async Task AReceiveIssuedAfterDisposalAlsoFaults()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;

        await server.DisposeAsync();

        var error = await Assert.ThrowsAnyAsync<Exception>(async () =>
            await server.ReceiveAsync(new byte[64], CancellationToken.None)
                .AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        AssertDisposalCaused(error);
    }

    [Fact]
    public async Task SendingAfterDisposalThrows()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var serverLink = server;

        await client.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await client.SendAsync(
                server.LocalEndPoint, new byte[] { 1 }, CancellationToken.None));
    }

    // Closing one socket does not close the other, and neither does this. A datagram already
    // queued for the survivor still arrives; one sent to the closed endpoint vanishes the way
    // a UDP send to a closed socket does, without faulting the sender.
    [Fact]
    public async Task DisposingOneEndpointLeavesThePeerUsable()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;

        await server.SendAsync(client.LocalEndPoint, new byte[] { 5 }, CancellationToken.None);
        await server.DisposeAsync();

        var buffer = new byte[8];
        var result = await client.ReceiveAsync(buffer, CancellationToken.None)
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(5, buffer[0]);
        Assert.Equal(1, result.Length);

        await client.SendAsync(server.LocalEndPoint, new byte[] { 6 }, CancellationToken.None);
        Assert.Equal(0, client.MisdirectedSends);
    }

    [Fact]
    public async Task ReceiveHonoursCancellation()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        using var cts = new CancellationTokenSource();
        var pending = server.ReceiveAsync(new byte[64], cts.Token).AsTask();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task ANullDestinationIsRejected()
    {
        var (client, server) = InMemoryDatagramTransport.CreatePair();
        await using var clientLink = client;
        await using var serverLink = server;

        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await client.SendAsync(null!, new byte[] { 1 }, CancellationToken.None));
    }

    // Walks the chain because a channel reports a completion error as the inner exception of
    // its own closed-channel type, and asserting on that type instead would pin an
    // implementation detail rather than the behaviour the interface documents.
    private static void AssertDisposalCaused(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
        {
            if (current is ObjectDisposedException)
            {
                return;
            }
        }

        Assert.Fail($"Expected an ObjectDisposedException in the chain, got {error}.");
    }
}
