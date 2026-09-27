using System.Net;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>
/// Pins the one verdict <see cref="Socks5LivenessTransport"/> reaches on its own: a relay whose
/// first datagram is a TLS alert record is writing UDP ASSOCIATE payload into a TCP TLS
/// connection and cannot carry QUIC, so the association fails by name instead of sitting out
/// the handshake deadline. Field logs showed exactly this — four discards of
/// <c>15 03 01 00 02 02 46</c> and a ten-second timeout per attempt.
/// </summary>
public sealed class Socks5LivenessTransportTests
{
    // OpenSSL's and BoringSSL's answer to a first record that is not TLS: fatal protocol_version.
    private static readonly byte[] TlsAlert = Convert.FromHexString("15030100020246");

    // A long header with RFC 9000 s17.2's fixed bit set; the receiver would parse or discard it.
    private static readonly byte[] QuicShaped = [0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];

    [Fact]
    public async Task ATlsAlertBeforeAnyQuicDatagram_FailsTheAssociationByName()
    {
        await using var transport = new Socks5LivenessTransport(new ScriptedRelay(TlsAlert));

        var exception = await Assert.ThrowsAsync<TlsQuicProxyException>(
            async () => await transport.ReceiveAsync(new byte[1500], default));

        Assert.Equal(TlsQuicProxyError.RelayDeliveredTlsAlert, exception.Error);
        Assert.Contains("15030100020246", exception.Message, StringComparison.Ordinal);
        Assert.Contains("HTTP/2 over TCP", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ATlsAlertAfterAQuicDatagram_IsHandedUpForTheReceiverToDiscard()
    {
        await using var transport = new Socks5LivenessTransport(
            new ScriptedRelay(QuicShaped, TlsAlert));
        var buffer = new byte[1500];

        Assert.Equal(QuicShaped.Length, (await transport.ReceiveAsync(buffer, default)).Length);
        Assert.Equal(TlsAlert.Length, (await transport.ReceiveAsync(buffer, default)).Length);
    }

    [Theory]
    [InlineData("15030100020246", true)]     // fatal protocol_version at the pre-negotiation version
    [InlineData("15030300020228", true)]     // fatal handshake_failure at the TLS 1.2 record version
    [InlineData("15030100020146", true)]     // a warning-level alert is still a TLS record
    [InlineData("1503010002024600", false)]  // one byte too many to be a lone alert record
    [InlineData("150301000202", false)]      // one byte short
    [InlineData("16030100020246", false)]    // handshake content type: not an alert
    [InlineData("15030500020246", false)]    // no such record version
    [InlineData("40000000000000", false)]    // QUIC short header
    [InlineData("c0000000010800", false)]    // QUIC long header
    [InlineData("", false)]
    public void OnlyASevenByteAlertRecordCounts(string hex, bool expected) =>
        Assert.Equal(
            expected,
            Socks5LivenessTransport.IsTlsAlertRecord(Convert.FromHexString(hex)));

    private sealed class ScriptedRelay(params byte[][] datagrams) : ITlsQuicDatagramTransport
    {
        private int _next;

        public int MaxDatagramPayloadSize => 1200;

        public ValueTask SendAsync(
            IPEndPoint destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken) => ValueTask.CompletedTask;

        public ValueTask<TlsQuicDatagramReceiveResult> ReceiveAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken)
        {
            var datagram = datagrams[_next++];
            datagram.CopyTo(buffer);
            return ValueTask.FromResult(new TlsQuicDatagramReceiveResult(
                datagram.Length,
                new IPEndPoint(IPAddress.Loopback, 1080)));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
