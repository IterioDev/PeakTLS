using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

/// <content>
/// RFC 9368's compatible version negotiation.
///
/// WHY THIS EXISTS AT ALL, GIVEN EVERY CAPTURE IS VERSION 1. The captures are version 1 because
/// the proxy they were recorded through speaks version 1 only - so they say nothing about what
/// a client would do against a version 2 server, and "no capture shows version 2" is a fact
/// about the tool rather than about the clients.
/// </content>
public sealed partial class TlsQuicConnectionTests
{
    private const uint Version1 = (uint)TlsQuicVersion.Version1;
    private const uint Version2 = (uint)TlsQuicVersion.Version2;

    private static TlsQuicConnectionSpec VersionSpec(TlsQuicVersion version) => new()
    {
        PaddingTarget = 1200,
        SourceConnectionIdLength = SourceConnectionIdLength,
        Version = version,
    };

    [Fact]
    public async Task AConnectionStartsInTheVersionItsSpecNames()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, VersionSpec(TlsQuicVersion.Version2),
                transport.Clock),
            source => TlsClient(pki, source, availableVersions: [Version2], chosenVersion: Version2));

        await connection.StartAsync(cancellation.Token);

        Assert.Equal(TlsQuicVersion.Version2, connection.NegotiatedVersion);
        Assert.False(connection.VersionWasNegotiated);

        // ON THE WIRE, NOT ONLY IN THE FIELD. The Initial packet's long header carries the
        // version verbatim - RFC 9000 s17.2's Version field is version independent - so the
        // first datagram is where the claim is checkable.
        var initial = Assert.Single(transport.Sent).Payload;
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(initial, out var header, out _));
        Assert.Equal(Version2, header.Version);
        Assert.Equal(TlsQuicLongPacketType.Initial, header.Type);
    }

    [Fact]
    public async Task TheAdvertisedChosenVersionOverridesTheSpecProperty()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // THE SAME RULE AS ack_delay_exponent, ONE FIELD OVER. RFC 9368 s3 makes the Chosen
        // Version "the version that the sender has chosen to use", so a profile that advertises
        // one version while the spec property names another has already committed on the wire.
        // The spec property is the copy that loses.
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, VersionSpec(TlsQuicVersion.Version1),
                transport.Clock),
            source => TlsClient(pki, source, availableVersions: [Version2], chosenVersion: Version2));

        await connection.StartAsync(cancellation.Token);

        Assert.Equal(TlsQuicVersion.Version2, connection.NegotiatedVersion);
        Assert.True(TlsQuicPacketHeader.TryReadLongHeader(
            Assert.Single(transport.Sent).Payload, out var header, out _));
        Assert.Equal(Version2, header.Version);
    }

    [Fact]
    public async Task AVersionTheClientNeverOfferedIsNotAdopted()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock),
            source => TlsClient(pki, source));
        await connection.StartAsync(cancellation.Token);

        // The default helper sends no version_information at all, which is the state RFC 9368
        // s2.3 makes un-negotiable: the server may choose only from what the client listed, and
        // the client listed nothing. This is also the shipped Spotify preset's state.
        Assert.False(connection.TryAdoptNegotiatedVersion(Version2));
        Assert.Equal(TlsQuicVersion.Version1, connection.NegotiatedVersion);
        Assert.False(connection.VersionWasNegotiated);
    }

    [Fact]
    public async Task AnOfferedVersionIsAdoptedAndMovesTheConnection()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock),
            source => TlsClient(pki, source, availableVersions: [Version1, Version2]));
        await connection.StartAsync(cancellation.Token);

        Assert.Equal(TlsQuicVersion.Version1, connection.NegotiatedVersion);
        Assert.True(connection.TryAdoptNegotiatedVersion(Version2));
        Assert.Equal(TlsQuicVersion.Version2, connection.NegotiatedVersion);
        Assert.True(connection.VersionWasNegotiated);

        // ONCE. s2.3: "the client MUST NOT change the version it is using after processing the
        // server's first flight." A second move would also be a second Initial key derivation,
        // which s4.9.1's discard turns into an error rather than a re-key.
        Assert.False(connection.TryAdoptNegotiatedVersion(Version1));
        Assert.Equal(TlsQuicVersion.Version2, connection.NegotiatedVersion);
    }

    [Fact]
    public async Task AnOfferedButUnimplementedVersionIsNotAdopted()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();

        // 0x1a2a3a4a is RFC 9368 s3's reserved pattern - the shape
        // TlsQuicTransportParameterSpec.DrawnVersionInformation draws for GREASE. OFFERING IS
        // NOT IMPLEMENTING: a client lists these precisely so that a server ignores them, and
        // adopting one because it appeared in the list would turn the GREASE entry into a
        // remote way to break the connection.
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock),
            source => TlsClient(pki, source, availableVersions: [0x1A2A3A4A, Version1]));
        await connection.StartAsync(cancellation.Token);

        Assert.False(connection.TryAdoptNegotiatedVersion(0x1A2A3A4A));
        Assert.Equal(TlsQuicVersion.Version1, connection.NegotiatedVersion);
    }

    [Fact]
    public async Task TheServersChosenVersionMustMatchTheVersionInUse()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock),
            source => TlsClient(pki, source, availableVersions: [Version1, Version2]));
        await connection.StartAsync(cancellation.Token);

        // s4: "If the Chosen Version field does not match the version of the connection, the
        // client MUST close the connection with a connection error of type
        // VERSION_NEGOTIATION_ERROR." 0x11 did not exist in this tree until the audit's C2
        // added it, which is why a missing error code is not a cosmetic gap.
        var mismatched = new TlsQuicTransportParameters(
        [
            new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.VersionInformation,
                TlsQuicTransportParameterSpec.EncodeVersionInformation(
                    Version2, [Version2, Version1])),
        ]);

        Assert.False(connection.ValidateServerVersionInformation(
            mismatched, out var error, out var reason));
        Assert.Equal(TlsQuicTransportError.VersionNegotiationError, error);
        Assert.Contains("s4", reason, StringComparison.Ordinal);

        // ...and the matching one is accepted, so the assertion above is about the mismatch
        // rather than about the check refusing everything.
        var matching = new TlsQuicTransportParameters(
        [
            new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.VersionInformation,
                TlsQuicTransportParameterSpec.EncodeVersionInformation(
                    Version1, [Version1, Version2])),
        ]);
        Assert.True(connection.ValidateServerVersionInformation(matching, out _, out _));
    }

    [Fact]
    public async Task AServerThatSendsNoVersionInformationIsOnlyAnErrorAfterASwitch()
    {
        using var cancellation = new CancellationTokenSource(TestTimeout);
        using var pki = TestPki.Create();
        await using var transport = new ScriptedDatagramTransport();
        await using var connection = new TlsQuicConnection(
            new TlsQuicConnectionOptions(
                transport, transport.RemoteEndPoint, Spec(), transport.Clock),
            source => TlsClient(pki, source, availableVersions: [Version1, Version2]));
        await connection.StartAsync(cancellation.Token);

        var silent = new TlsQuicTransportParameters([]);

        // s4 makes the parameter's absence mean the server does not implement RFC 9368, which
        // for a connection that never switched is entirely ordinary.
        Assert.True(connection.ValidateServerVersionInformation(silent, out _, out _));

        // A switch with no confirmation is the case that is not ordinary: the connection moved
        // on the strength of an unauthenticated header and nothing authenticated ever agreed.
        Assert.True(connection.TryAdoptNegotiatedVersion(Version2));
        Assert.False(connection.ValidateServerVersionInformation(silent, out var error, out _));
        Assert.Equal(TlsQuicTransportError.VersionNegotiationError, error);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(9)]
    [InlineData(13)]
    public void AMalformedVersionInformationBodyIsRefusedRatherThanGuessed(int length)
    {
        // s3 Figure 2: a 32-bit Chosen Version then one or more 32-bit Available Versions. So
        // eight is the shortest legal body and every legal body is a multiple of four - 0 and 4
        // are too short, 9 and 13 are not multiples.
        Assert.False(TlsQuicTransportParameters.TryDecodeVersionInformation(
            new byte[length], out _, out _));
    }

    [Fact]
    public void TheDecoderIsTheEncodersInverse()
    {
        var encoded = TlsQuicTransportParameterSpec.EncodeVersionInformation(
            Version2, [Version2, Version1, 0x1A2A3A4A]);

        Assert.True(TlsQuicTransportParameters.TryDecodeVersionInformation(
            encoded, out var chosen, out var available));
        Assert.Equal(Version2, chosen);
        Assert.Equal(new uint[] { Version2, Version1, 0x1A2A3A4A }, available);
    }
}
