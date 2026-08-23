using System.Net;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// The clock seam, and the four null guards that sit next to it.
//
// TimeProvider is the whole point of this type: it is the only way a later task can make an
// idle timeout or a handshake deadline fire without waiting for one, and the only reason the
// deadline tests in tasks 9a-ii and 9b can be deterministic. ManualTimeProvider below is the
// same ~10-line subclass Tls12SessionCacheTests, Tls13SessionTests and TlsEchDnsResolverTests
// each carry; the seam needs no package.
public sealed class TlsQuicConnectionOptionsTests
{
    private static readonly IPEndPoint AnyPeer = new(IPAddress.Loopback, 443);

    [Fact]
    public void TheDefaultConstructorUsesTheSystemClock()
    {
        var transport = new NullTransport();

        var options = new TlsQuicConnectionOptions(transport, AnyPeer, new TlsQuicConnectionSpec());

        Assert.Same(TimeProvider.System, options.TimeProvider);
    }

    // HOW A TEST DRIVES THE SEAM, in the smallest form the later tasks will use: hold the
    // fake, read the time through the options, move the fake by hand, read again. No wall
    // clock is consulted and the elapsed real time is zero, so a deadline built on this is
    // reproducible on any machine and at any speed.
    [Fact]
    public void AnInjectedClockIsTheOneTheOptionsRead()
    {
        var transport = new NullTransport();
        var start = new DateTimeOffset(2026, 8, 17, 0, 0, 0, TimeSpan.Zero);
        var clock = new ManualTimeProvider(start);

        var options = new TlsQuicConnectionOptions(
            transport, AnyPeer, new TlsQuicConnectionSpec(), clock);

        Assert.Same(clock, options.TimeProvider);
        Assert.Equal(start, options.TimeProvider.GetUtcNow());

        clock.Advance(TimeSpan.FromSeconds(45));

        Assert.Equal(start + TimeSpan.FromSeconds(45), options.TimeProvider.GetUtcNow());
    }

    // One witness per guarded argument. A single test passing null for one of them would
    // leave the other three unpinned, and ParamName is what separates them - all four throw
    // the same exception type on the same value.
    [Fact]
    public void ANullTransportIsRejected()
    {
        var error = Assert.Throws<ArgumentNullException>(
            () => _ = new TlsQuicConnectionOptions(null!, AnyPeer, new TlsQuicConnectionSpec()));
        Assert.Equal("transport", error.ParamName);
    }

    [Fact]
    public void ANullRemoteEndPointIsRejected()
    {
        var transport = new NullTransport();
        var error = Assert.Throws<ArgumentNullException>(
            () => _ = new TlsQuicConnectionOptions(transport, null!, new TlsQuicConnectionSpec()));
        Assert.Equal("remoteEndPoint", error.ParamName);
    }

    [Fact]
    public void ANullSpecIsRejected()
    {
        var transport = new NullTransport();
        var error = Assert.Throws<ArgumentNullException>(
            () => _ = new TlsQuicConnectionOptions(transport, AnyPeer, null!));
        Assert.Equal("spec", error.ParamName);
    }

    [Fact]
    public void ANullTimeProviderIsRejected()
    {
        var transport = new NullTransport();
        var error = Assert.Throws<ArgumentNullException>(
            () => _ = new TlsQuicConnectionOptions(
                transport, AnyPeer, new TlsQuicConnectionSpec(), null!));
        Assert.Equal("timeProvider", error.ParamName);
    }

    [Fact]
    public void TheThreeSuppliedValuesAreTheOnesExposed()
    {
        var transport = new NullTransport();
        var spec = new TlsQuicConnectionSpec { DestinationConnectionIdLength = 12 };

        var options = new TlsQuicConnectionOptions(transport, AnyPeer, spec);

        Assert.Same(transport, options.Transport);
        Assert.Same(AnyPeer, options.RemoteEndPoint);
        Assert.Same(spec, options.Spec);
    }

    // SNAPSHOT: both defaults are local policy with no RFC and no capture behind them, so
    // this pins a decision rather than deriving an expectation. It exists because a silent
    // change to either would change when a connection gives up, and nothing else would fail.
    [Fact]
    public void TheDeadlineDefaultsArePositiveAndPinned()
    {
        var transport = new NullTransport();

        var options = new TlsQuicConnectionOptions(transport, AnyPeer, new TlsQuicConnectionSpec());

        Assert.Equal(TimeSpan.FromSeconds(30), options.IdleTimeout);
        Assert.Equal(TimeSpan.FromSeconds(10), options.HandshakeDeadline);
    }

    [Fact]
    public void TheDeadlinesAreKeptWhenGiven()
    {
        var transport = new NullTransport();

        var options = new TlsQuicConnectionOptions(transport, AnyPeer, new TlsQuicConnectionSpec())
        {
            IdleTimeout = TimeSpan.FromSeconds(5),
            HandshakeDeadline = TimeSpan.FromSeconds(2),
        };

        Assert.Equal(TimeSpan.FromSeconds(5), options.IdleTimeout);
        Assert.Equal(TimeSpan.FromSeconds(2), options.HandshakeDeadline);
    }

    // Zero and negative are separate rows because zero is the one a caller reaches by
    // accident - a TimeSpan field left unset - and it is the value a `< Zero` mutant would
    // let through while still rejecting the negative.
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ANonPositiveIdleTimeoutIsRejected(int seconds)
    {
        var transport = new NullTransport();
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionOptions(transport, AnyPeer, new TlsQuicConnectionSpec())
            {
                IdleTimeout = TimeSpan.FromSeconds(seconds),
            });
        Assert.Equal("IdleTimeout", error.ParamName);
    }

    // NOT LOCAL POLICY, UNLIKE THE TWO ABOVE. RFC 9000 s18.2, ack_delay_exponent: "if this
    // value is absent, a default value of 3 is assumed (indicating a multiplier of 8)", so
    // this default is the RFC's and a caller who advertises nothing agrees with us by
    // construction. Zero is asserted apart from the default because zero is a LEGAL value a
    // caller may advertise, and a guard written as `if (value == 0) use the default` would be
    // wrong rather than merely lax.
    [Fact]
    public void TheAckDelayExponentDefaultsToSectionEighteenTwosThreeAndKeepsAnExplicitZero()
    {
        var transport = new NullTransport();

        Assert.Equal(
            3,
            new TlsQuicConnectionOptions(transport, AnyPeer, new TlsQuicConnectionSpec())
                .AckDelayExponent);
        Assert.Equal(
            0,
            new TlsQuicConnectionOptions(transport, AnyPeer, new TlsQuicConnectionSpec())
            {
                AckDelayExponent = 0,
            }.AckDelayExponent);
        Assert.Equal(
            20,
            new TlsQuicConnectionOptions(transport, AnyPeer, new TlsQuicConnectionSpec())
            {
                AckDelayExponent = 20,
            }.AckDelayExponent);
    }

    // s18.2: "Values above 20 are invalid." 21 is the first invalid one and 20 is asserted
    // legal above, so the pair brackets the boundary rather than testing one side of it.
    [Theory]
    [InlineData(-1)]
    [InlineData(21)]
    public void AnAckDelayExponentOutsideSectionEighteenTwosRangeIsRejected(int exponent)
    {
        var transport = new NullTransport();
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionOptions(transport, AnyPeer, new TlsQuicConnectionSpec())
            {
                AckDelayExponent = exponent,
            });
        Assert.Equal("AckDelayExponent", error.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ANonPositiveHandshakeDeadlineIsRejected(int seconds)
    {
        var transport = new NullTransport();
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionOptions(transport, AnyPeer, new TlsQuicConnectionSpec())
            {
                HandshakeDeadline = TimeSpan.FromSeconds(seconds),
            });
        Assert.Equal("HandshakeDeadline", error.ParamName);
    }

    // ManualTimeProvider used to be a private copy here, byte-identical to the ones in
    // Tls12SessionCacheTests, Tls13SessionTests and TlsEchDnsResolverTests. Task 3 needed one
    // too and promoted it to namespace scope in ScriptedDatagramTransport.cs, which for a
    // while made five copies rather than four; this file now uses the shared one, and the
    // remark about CreateTimer that lived here lives on the type. Later QUIC tasks should
    // reuse it rather than grow a sixth.

    // Task 1 has no I/O, so this stands in for a transport only as a non-null reference. The
    // real doubles - a paired in-memory channel and a scripted one - are task 3's, and this
    // is deliberately not a head start on them: it sends nowhere and receives nothing.
    private sealed class NullTransport : ITlsQuicDatagramTransport
    {
        public int MaxDatagramPayloadSize => 1200;

        public ValueTask SendAsync(
            IPEndPoint destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
