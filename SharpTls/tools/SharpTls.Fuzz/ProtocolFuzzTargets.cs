using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Dns;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Quic;
using SharpTls.Records;
using SharpTls.Sessions;

namespace SharpTls.Fuzzing;

internal sealed class ProtocolFuzzTargets : IDisposable
{
    internal const int MaximumInputLength = 65_535;
    private const int MaximumStateMachineActions = 512;
    private const ushort InitialClientRecordVersion = 0x0301;

    private static readonly string[] Names =
    [
        "clienthello",
        "serverflight",
        "certificates",
        "records",
        "sessions",
        "ech-quic-dns",
        "state-machines",
        "socks5",
        "quic-packets",
        "quic-frames",
        "qpack",
        "http3",
    ];

    private readonly ClientHelloBuildResult _offer;
    private readonly ClientHelloConfiguration _certificateOffer;
    private readonly TlsLimits _limits = new()
    {
        MaxHandshakeMessageSize = 64 * 1024,
        MaxCertificateListSize = 64 * 1024,
        MaxCertificateCount = 8,
        MaxHandshakeTranscriptSize = 128 * 1024,
    };

    internal ProtocolFuzzTargets()
    {
        using var random = new DeterministicRandomSource("SharpTls-fuzz-corpus-v1"u8.ToArray());
        // The seeds below hardcode an X25519 key share and a Secp384r1 HelloRetryRequest, so
        // the offer states those groups explicitly rather than inheriting whatever a shipped
        // profile happens to carry. A profile change must not silently invalidate the corpus.
        _offer = ClientHelloEncoder.Build(
            "fuzz.invalid",
            ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithSupportedGroups(
                    NamedGroup.X25519,
                    NamedGroup.Secp256r1,
                    NamedGroup.Secp384r1)
                .WithKeyShares(NamedGroup.X25519)
                .WithAlpn("h2", "http/1.1")
                .WithSessionResumption()).Spec.SnapshotConfiguration(),
            random,
            new KeyShareSet(deterministicForTesting: true),
            retry: null);
        _certificateOffer = CreateCertificateOffer();
    }

    internal static IReadOnlyList<string> TargetNames => Array.AsReadOnly(Names);

    internal void VerifyStructuralSeeds()
    {
        var handshake = (byte[])_offer.EncodedHandshake.Clone();
        var clientHelloBody = handshake[TlsConstants.HandshakeHeaderLength..];
        _ = Tls13ClientHelloParser.Parse(clientHelloBody);
        _ = ClientHelloCapture.Import(BuildRecord(
            TlsContentType.Handshake,
            handshake,
            InitialClientRecordVersion));
        _ = ClientHelloSpecJson.Deserialize(
            ClientHelloSpecJson.SerializeUtf8(ClientHelloProfiles.ModernTls13.Spec));

        _ = ServerHelloParser.Parse(BuildTls13ServerHello(), _offer);
        _ = ServerHelloParser.Parse(
            Tls13ServerHandshakeMessages.BuildHelloRetryRequest(
                _offer.SessionId,
                TlsCipherSuite.TlsAes128GcmSha256,
                NamedGroup.Secp384r1)[TlsConstants.HandshakeHeaderLength..],
            _offer);
        _ = EncryptedExtensionsParser.Parse(
            Tls13ServerHandshakeMessages.BuildEncryptedExtensions(true, "h2")
                [TlsConstants.HandshakeHeaderLength..],
            _offer.Configuration);
        var certificateRequest = Tls13ServerHandshakeMessages.BuildCertificateRequest(
            [SignatureScheme.EcdsaSecp256r1Sha256])
            [TlsConstants.HandshakeHeaderLength..];
        _ = CertificateRequestParser.ParseInitial(certificateRequest);
        _ = CertificateRequestParser.ParsePostHandshake(certificateRequest);
        _ = KeyUpdateProcessor.ParseRequestUpdate([0]);
        _ = KeyUpdateProcessor.ParseRequestUpdate([1]);

        var tls13Certificate = BuildTls13CertificateBody();
        using (CertificateMessageParser.Parse(tls13Certificate, _limits, _certificateOffer)) { }
        using (ClientCertificateMessageParser.Parse(tls13Certificate, _limits)) { }
        VerifyCompressedCertificateSeed(
            tls13Certificate,
            (ushort)TlsCertificateCompressionAlgorithm.Brotli);
        VerifyCompressedCertificateSeed(tls13Certificate, ZstdAlgorithm);
        var decompressed = CompressedCertificateParser.Decompress(
            BuildCompressedCertificateBody(
                tls13Certificate,
                (ushort)TlsCertificateCompressionAlgorithm.Zlib),
            _certificateOffer,
            _limits);
        if (!decompressed.AsSpan().SequenceEqual(tls13Certificate))
        {
            throw new InvalidOperationException("Compressed certificate fuzz seed does not round-trip.");
        }

        var recordBytes = BuildRecord(
            TlsContentType.Handshake,
            handshake,
            InitialClientRecordVersion);
        using (var stream = new MemoryStream(recordBytes, writable: false))
        {
            var reader = new TlsRecordReader(stream);
            _ = reader.ReadAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult()
                ?? throw new InvalidOperationException("TLS record fuzz seed did not parse.");
        }
        var tls13Ciphertext = BuildTls13CiphertextSeed();
        var tls13Suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using (var decryptor = new Tls13RecordCipher(
            tls13Suite,
            new byte[tls13Suite.KeyLength],
            new byte[tls13Suite.IvLength],
            maximumRecords: 1))
        {
            _ = decryptor.Decrypt(tls13Ciphertext);
        }

        VerifySessionSeeds();
        _ = TlsEchConfigList.Parse(BuildEchConfigList());
        _ = TlsQuicTransportParameters.Parse(BuildQuicTransportParameters());
        var dns = BuildDnsHttpsNoDataResponse();
        _ = DnsMessageParser.ParseHttpsResponse(
            dns,
            0x1234,
            "fuzz.invalid",
            MaximumInputLength,
            maximumRecords: 256);
        VerifyStateMachineSeeds();
        VerifyQuicSeeds();
        VerifyQuicFrameSeeds();
        VerifyQpackSeeds();
        VerifyHttp3Seeds();
    }

    internal IReadOnlyList<byte[]> CreateSeedCorpus(string target = "all")
    {
        if (string.Equals(target, "all", StringComparison.Ordinal))
        {
            var unique = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (var name in Names)
            {
                foreach (var seed in CreateSeedCorpus(name))
                {
                    unique.TryAdd(Convert.ToBase64String(seed), seed);
                }
            }
            return [.. unique.Values];
        }
        if (!Names.Contains(target, StringComparer.Ordinal))
        {
            throw new ArgumentException($"Unknown fuzz target '{target}'.", nameof(target));
        }

        var seeds = CreateBoundarySeeds();
        switch (target)
        {
            case "clienthello":
                AddClientHelloSeeds(seeds);
                break;
            case "serverflight":
                AddServerFlightSeeds(seeds);
                break;
            case "certificates":
                AddCertificateSeeds(seeds);
                break;
            case "records":
                AddRecordSeeds(seeds);
                break;
            case "sessions":
                AddSessionSeeds(seeds);
                break;
            case "ech-quic-dns":
                AddEchQuicDnsSeeds(seeds);
                break;
            case "state-machines":
                AddStateMachineSeeds(seeds);
                break;
            case "socks5":
                AddSocks5Seeds(seeds);
                break;
            case "quic-packets":
                AddQuicPacketsSeeds(seeds);
                break;
            case "quic-frames":
                AddQuicFramesSeeds(seeds);
                break;
            case "qpack":
                AddQpackSeeds(seeds);
                break;
            case "http3":
                AddHttp3Seeds(seeds);
                break;
        }
        return seeds;
    }

    private void AddClientHelloSeeds(List<byte[]> seeds)
    {
        var handshake = (byte[])_offer.EncodedHandshake.Clone();
        var body = handshake.Length >= 4 ? handshake[4..] : [];
        seeds.Add(handshake);
        seeds.Add(body);
        seeds.Add(BuildRecord(TlsContentType.Handshake, handshake, InitialClientRecordVersion));
        seeds.Add(ClientHelloProfiles.ModernTls13.BuildDeterministicForTesting(
            "fuzz.invalid",
            "SharpTls-fuzz-firefox120"u8.ToArray()));
        seeds.Add(ClientHelloSpecJson.SerializeUtf8(ClientHelloProfiles.ModernTls13.Spec));
    }

    private void AddServerFlightSeeds(List<byte[]> seeds)
    {
        seeds.Add(BuildTls13ServerHello());
        seeds.Add(Tls13ServerHandshakeMessages.BuildHelloRetryRequest(
            _offer.SessionId,
            TlsCipherSuite.TlsAes128GcmSha256,
            NamedGroup.Secp384r1)[TlsConstants.HandshakeHeaderLength..]);
        seeds.Add(Tls13ServerHandshakeMessages.BuildEncryptedExtensions(
            acknowledgeSni: true,
            alpn: "h2")[TlsConstants.HandshakeHeaderLength..]);
        seeds.Add(Tls13ServerHandshakeMessages.BuildCertificateRequest(
            [SignatureScheme.EcdsaSecp256r1Sha256])
            [TlsConstants.HandshakeHeaderLength..]);
        seeds.Add([0]);
        seeds.Add([1]);
        seeds.Add([1, 0, 0, 1, 0x30]);
        seeds.Add([]);
    }

    private void AddCertificateSeeds(List<byte[]> seeds)
    {
        var tls13 = BuildTls13CertificateBody();
        seeds.Add(tls13);
        seeds.Add(BuildCompressedCertificateBody(tls13, (ushort)TlsCertificateCompressionAlgorithm.Zlib));
        seeds.Add(BuildCompressedCertificateBody(tls13, (ushort)TlsCertificateCompressionAlgorithm.Brotli));
        seeds.Add(BuildCompressedCertificateBody(tls13, ZstdAlgorithm));
    }

    private void AddRecordSeeds(List<byte[]> seeds)
    {
        var handshake = (byte[])_offer.EncodedHandshake.Clone();
        seeds.Add(BuildRecord(TlsContentType.Handshake, handshake, InitialClientRecordVersion));
        seeds.Add(BuildRecord(TlsContentType.ChangeCipherSpec, [1], TlsConstants.LegacyRecordVersion));

        seeds.Add(BuildTls13CiphertextSeed());
    }

    private static void AddSessionSeeds(List<byte[]> seeds)
    {
        var extensions = new TlsBinaryWriter();
        var earlyData = new TlsBinaryWriter();
        earlyData.WriteUInt32(4_096);
        extensions.WriteUInt16((ushort)TlsExtensionType.EarlyData);
        extensions.WriteVector16(earlyData.WrittenSpan);
        var tls13Ticket = new TlsBinaryWriter();
        tls13Ticket.WriteUInt32(3_600);
        tls13Ticket.WriteUInt32(0x1020_3040);
        tls13Ticket.WriteVector8([1, 2, 3]);
        tls13Ticket.WriteVector16([4, 5, 6, 7]);
        tls13Ticket.WriteVector16(extensions.WrittenSpan);
        seeds.Add(tls13Ticket.ToArray());

        using (var tls13State = new Tls13ServerSessionTicketState(
            1_700_000_000_000,
            3_600,
            0x5566_7788,
            TlsCipherSuite.TlsAes128GcmSha256,
            "fuzz.invalid",
            "h2",
            new byte[32]))
        {
            seeds.Add(tls13State.Encode());
        }
    }

    private static void AddEchQuicDnsSeeds(List<byte[]> seeds)
    {
        seeds.Add(BuildEchConfigList());
        seeds.Add(BuildQuicTransportParameters());
        seeds.Add(BuildDnsHttpsNoDataResponse());
    }

    private static byte[] BuildQuicTransportParameters() =>
        new TlsQuicTransportParameters(
        [
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.MaxUdpPayloadSize,
                1200),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxData,
                65_536),
        ]).Encode();

    private static void AddStateMachineSeeds(List<byte[]> seeds)
    {
        // Direct and HelloRetryRequest TLS 1.3 client paths, including client auth.
        seeds.Add([0, 1, 4, 5, 7, 8, 9, 13, 14, 15]);
        seeds.Add([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 129, 12, 13, 14, 15]);
        // Direct and HRR TLS 1.3 server paths.
        seeds.Add([0, 2, 3, 4, 5, 6]);
        seeds.Add([0, 1, 2, 3, 4, 5, 6]);
        // TLS 1.2 full, client-auth, and abbreviated handshakes.
        seeds.Add([0, 1, 2, 7, 9, 11, 13, 15, 16, 17, 18, 19, 20, 21]);
        seeds.Add([0, 1, 2, 7, 8, 9, 10, 11, 144, 13, 14, 15, 16, 17, 18, 19, 20, 21]);
        seeds.Add([0, 1, 134, 3, 4, 5, 6, 20, 21]);
    }

    private static void AddSocks5Seeds(List<byte[]> seeds)
    {
        seeds.Add([0x05, 0x00]);
        seeds.Add([0x01, 0x00]);
        seeds.Add([0x05, 0x00, 0x00, 0x01]);
        seeds.Add([0x00, 0x00, 0x00, 0x01, 0xCB, 0x00, 0x71, 0x09, 0x01, 0xBB]);

        // REP != 0: exercises the AssociateRejected path and DescribeReplyCode.
        seeds.Add([0x05, 0x01, 0x00, 0x01]);

        // 22-byte IPv6 UDP header, for TryReadUdpHeader's IPv6 branch.
        seeds.Add(
        [
            0x00, 0x00, 0x00, 0x04,
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0xBB,
        ]);

        // ResolveRelayEndPoint(addressType, address, port, proxyAddress) reads
        // input[0] as ATYP, input[1..^2] as the address, and the last two bytes
        // as the port. These three land exactly in the wildcard/mapped-address
        // substitution branches, which random mutation alone would rarely hit.
        seeds.Add([0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x38]); // IPv4 wildcard, 7 bytes.
        seeds.Add(
        [
            0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x04, 0x38,
        ]); // IPv6 wildcard, 19 bytes.
        seeds.Add(
        [
            0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF,
            203, 0, 113, 9,
            0x04, 0x38,
        ]); // IPv4-mapped IPv6, 19 bytes.
    }

    private static void AddQuicPacketsSeeds(List<byte[]> seeds)
    {
        // RFC 9001 Appendix A.2: a real, spec-published Initial header,
        // padded with zero payload bytes out to its own declared Length
        // (1182) so TryReadLongHeader actually returns true - mirrors
        // TlsQuicPacketHeaderTests.ParsesAppendixA2ClientInitialHeader.
        // Copied verbatim from docs/superpowers/specs/reference-captures/
        // rfc9001-appendix-a-test-vectors.txt, not retyped.
        var appendixA2Header = Convert.FromHexString("c300000001088394c8f03e5157080000449e00000002");
        var appendixA2Initial = new byte[18 + 1182];
        appendixA2Header.CopyTo(appendixA2Initial, 0);
        seeds.Add(appendixA2Initial);
        seeds.Add(appendixA2Header); // The bare header alone, which fails the declared-Length cross-check.

        // RFC 9001 Appendix A.5: a real, spec-published protected short
        // header packet with an empty Destination Connection ID.
        seeds.Add(Convert.FromHexString("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));

        // RFC 9001 Appendix A.4: a real, spec-published Retry packet.
        seeds.Add(Convert.FromHexString(
            "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"));

        // A synthetic but structurally valid Version Negotiation packet -
        // RFC 9001 Appendix A has no vector of its own for this wire format
        // (it covers s5 packet/header protection only), so this is built
        // through the real serializer instead, mirroring
        // TlsQuicDatagramReaderTests.BuildVersionNegotiationBytes.
        seeds.Add(BuildQuicVersionNegotiationSeed());

        // A coalesced two-packet datagram: Initial followed by Handshake,
        // both built through the real wire-serialization path so the
        // boundary between them is exact - mirrors
        // TlsQuicDatagramReaderTests.CoalescedInitialAndHandshakeAreBoth
        // FoundWithCorrectBoundaries.
        var coalescedInitial = BuildQuicLongHeaderSeed(
            TlsQuicLongPacketType.Initial, destinationConnectionIdLength: 8, sourceConnectionIdLength: 4, packetNumberLength: 2);
        var coalescedHandshake = BuildQuicLongHeaderSeed(
            TlsQuicLongPacketType.Handshake, destinationConnectionIdLength: 8, sourceConnectionIdLength: 4, packetNumberLength: 3);
        seeds.Add([.. coalescedInitial, .. coalescedHandshake]);

        // Hazard flagged during A1 review: RFC 9000 s12.2 says a Version-
        // Negotiation-shaped packet (Header Form set, Version == 0) never
        // appears anywhere but offset 0 of a datagram from a conforming
        // sender. TlsQuicDatagramReader only special-cases that detection at
        // offset 0; a later occurrence falls through to the ordinary
        // long-header parse instead (see its own comment), which blind
        // mutation is unlikely to ever construct unaided. First packet: a
        // valid Initial. Second: a structurally valid 10-byte long header
        // (Initial-shaped: byte0, Version(4)=0, DCID len 0, SCID len 0,
        // Token length varint 0, Length varint 1, 1 packet number byte)
        // whose Version field is 0 - exactly what the offset-0 special case
        // would have caught had it appeared first instead.
        var validFirstPacket = BuildQuicLongHeaderSeed(
            TlsQuicLongPacketType.Initial, destinationConnectionIdLength: 8, sourceConnectionIdLength: 0, packetNumberLength: 1);
        byte[] versionZeroShapedTail =
        [
            0xC0, 0x00, 0x00, 0x00, 0x00, // Header Form + Fixed Bit + Initial type + pn-length 1; Version = 0.
            0x00, // DCID length 0.
            0x00, // SCID length 0.
            0x00, // Token length varint = 0 (Initial carries a token field).
            0x01, // Length varint = 1 (covers exactly the 1-byte packet number).
            0xAA, // Packet Number.
        ];
        seeds.Add([.. validFirstPacket, .. versionZeroShapedTail]);
    }

    private static byte[] BuildQuicLongHeaderSeed(
        TlsQuicLongPacketType type, int destinationConnectionIdLength, int sourceConnectionIdLength, int packetNumberLength)
    {
        var header = new TlsQuicLongHeader
        {
            Type = type,
            Version = (uint)TlsQuicVersion.Version1,
            DestinationConnectionId = SequentialQuicSeedBytes(destinationConnectionIdLength, seed: 0x10),
            SourceConnectionId = SequentialQuicSeedBytes(sourceConnectionIdLength, seed: 0x20),
            Token = ReadOnlyMemory<byte>.Empty,
            // Zero-length payload: Length covers only the Packet Number field, so the written
            // bytes are themselves a complete packet - matches the pattern already established by
            // TlsQuicDatagramReaderTests.BuildLongHeaderBytes.
            Length = (ulong)packetNumberLength,
            PacketNumberLength = packetNumberLength,
            PacketNumber = SequentialQuicSeedBytes(packetNumberLength, seed: 0x40),
        };

        var buffer = new byte[64];
        var written = TlsQuicPacketHeader.WriteLongHeader(buffer, header, out _);
        return buffer[..written];
    }

    private static byte[] BuildQuicVersionNegotiationSeed()
    {
        var packet = new TlsQuicVersionNegotiationPacket
        {
            DestinationConnectionId = SequentialQuicSeedBytes(8, seed: 0x10),
            SourceConnectionId = SequentialQuicSeedBytes(4, seed: 0x20),
            SupportedVersions = new uint[] { (uint)TlsQuicVersion.Version1, (uint)TlsQuicVersion.Version2 },
        };

        var buffer = new byte[64];
        var written = TlsQuicVersionNegotiation.Write(buffer, packet);
        return buffer[..written];
    }

    private static byte[] SequentialQuicSeedBytes(int length, byte seed)
    {
        var bytes = new byte[length];
        for (var index = 0; index < length; index++)
        {
            bytes[index] = (byte)(seed + index);
        }
        return bytes;
    }

    // Every raw frame type RFC 9000 s12.4 Table 3 defines: 0x00 through 0x1e
    // with no gaps. Raw, not collapsed - a per-frame-type breakdown keyed on
    // TlsQuicFrameType could not tell "every STREAM form was exercised" from
    // "one was", because all eight share a row. The five flag ranges get one
    // slot per wire value here for exactly that reason.
    private const int QuicRawFrameTypeCount = 0x1f;

    // Task C17. RFC 9221 s7.2 registers "Value: 0x30-0x31, Frame Name: DATAGRAM" -
    // two wire values, contiguous, well above Table 3's 0x00-0x1e block and with a
    // seventeen-value gap between. So the raw-type reachability arrays cannot stay
    // indexed by raw value without seventeen dead rows in every report, and they
    // are indexed by SLOT instead: slots 0x00-0x1e are the raw values themselves,
    // and the two after them are 0x30 and 0x31. QuicRawFrameTypeSlot and
    // QuicRawFrameTypeForSlot are the two directions of that map and are each
    // other's inverse over exactly these thirty-three values.
    private const int QuicDatagramRawFrameTypeCount = 2;
    private const int QuicRawFrameSlotCount = QuicRawFrameTypeCount + QuicDatagramRawFrameTypeCount;
    private const ulong QuicDatagramWithLengthFrameType =
        (ulong)TlsQuicFrameType.Datagram | TlsQuicFrames.DatagramLengthBit;

    // -1 for a raw type with no slot, which is every value the reader never
    // accepts. Callers treat that as "no row", never as index 0.
    private static int QuicRawFrameTypeSlot(ulong rawType)
    {
        if (rawType < QuicRawFrameTypeCount)
        {
            return (int)rawType;
        }

        if (rawType >= (ulong)TlsQuicFrameType.Datagram && rawType <= QuicDatagramWithLengthFrameType)
        {
            return QuicRawFrameTypeCount + (int)(rawType - (ulong)TlsQuicFrameType.Datagram);
        }

        return -1;
    }

    private static ulong QuicRawFrameTypeForSlot(int slot) =>
        slot < QuicRawFrameTypeCount
            ? (ulong)slot
            : (ulong)TlsQuicFrameType.Datagram + (ulong)(slot - QuicRawFrameTypeCount);

    private const ulong QuicMaximumStreamFrameType =
        (ulong)TlsQuicFrameType.Stream |
        TlsQuicStreamFrames.OffsetBit |
        TlsQuicStreamFrames.LengthBit |
        TlsQuicStreamFrames.FinBit;
    private const ulong QuicAckWithEcnFrameType =
        (ulong)TlsQuicFrameType.Ack | TlsQuicAckFrames.EcnCountsBit;
    private const ulong QuicUnidirectionalMaxStreamsFrameType =
        (ulong)TlsQuicFrameType.MaxStreams | TlsQuicFlowControlFrames.UnidirectionalBit;
    private const ulong QuicUnidirectionalStreamsBlockedFrameType =
        (ulong)TlsQuicFrameType.StreamsBlocked | TlsQuicFlowControlFrames.UnidirectionalBit;
    private const ulong QuicApplicationConnectionCloseFrameType =
        (ulong)TlsQuicFrameType.ConnectionClose | TlsQuicConnectionFrames.ApplicationErrorBit;

    // Field values for the encoder-built seeds below. Every one sits in
    // 0x20-0x3f, so each is a single-byte varint, each differs from every other
    // field in the same frame, and none can equal a frame type byte (Table 3
    // runs 0x00-0x1e) or any length these seeds write. That is task 5's rule:
    // its RESET_STREAM vector used Stream ID 4 against a type byte of 0x04, so
    // "write the Stream ID before the frame type" produced byte-identical
    // output and survived a green suite. It matters as much for a seed as for a
    // vector, because VerifyQuicFrameSeeds asserts on decoded values and two
    // fields sharing one value make a transposition invisible to it too.
    private const ulong QuicFrameSeedStreamId = 0x2a;
    private const ulong QuicFrameSeedOffset = 0x2b;
    private const ulong QuicFrameSeedErrorCode = 0x2c;
    private const ulong QuicFrameSeedFinalSize = 0x2d;
    private const ulong QuicFrameSeedMaximumData = 0x2e;
    private const ulong QuicFrameSeedMaximumStreamData = 0x2f;
    private const ulong QuicFrameSeedMaximumStreams = 0x30;
    private const ulong QuicFrameSeedSequenceNumber = 0x31;
    private const ulong QuicFrameSeedRetirePriorTo = 0x28; // s19.15 MUST be <= Sequence Number.
    private const ulong QuicFrameSeedLargestAcknowledged = 0x3a;
    private const ulong QuicFrameSeedAckDelay = 0x33;
    private const ulong QuicFrameSeedFirstAckRange = 0x20; // s19.3.1 MUST NOT underflow Largest Acknowledged.
    private const ulong QuicFrameSeedTriggerFrameType = 0x34;
    private const ulong QuicFrameSeedEct0 = 0x35;
    private const ulong QuicFrameSeedEct1 = 0x36;
    private const ulong QuicFrameSeedEcnCe = 0x37;

    // One additional ACK Range: Gap 0x05, ACK Range Length 0x0a. RFC 9000
    // s19.3.1 makes the next range's largest = smallest - gap - 2 and its
    // smallest = largest - length, so with Largest Acknowledged 0x3a and First
    // ACK Range 0x20 these decode to (58, 26) and (19, 9): four distinct
    // numbers, which is what lets VerifyQuicFrameSeeds tell a correct decode
    // from a transposed one.
    private static readonly byte[] QuicFrameSeedAckRanges = [0x05, 0x0a];

    private static readonly byte[] QuicFrameSeedData = [0x41, 0x42, 0x43];
    private static readonly byte[] QuicFrameSeedToken = [0x71, 0x72, 0x73, 0x74];
    private static readonly byte[] QuicFrameSeedConnectionId = [0x51, 0x52, 0x53, 0x54, 0x55];
    private static readonly byte[] QuicFrameSeedStatelessResetToken = SequentialQuicSeedBytes(
        TlsQuicConnectionFrames.StatelessResetTokenLength, seed: 0x60);
    private static readonly byte[] QuicFrameSeedPathData = SequentialQuicSeedBytes(
        TlsQuicConnectionFrames.PathDataLength, seed: 0x91);
    private static readonly byte[] QuicFrameSeedReasonPhrase = [0x81, 0x82, 0x83];

    // RFC 9221 s4's Datagram Data field. Bytes chosen so that none of them is a
    // frame type this reader accepts: 0xa1-0xa3 are all one-byte varints well above
    // 0x31, so a seed whose DATAGRAM extent were measured short would leave the
    // walk on a byte it rejects rather than on a plausible frame. A payload of
    // 0x00s would have hidden that - every leftover byte would have read as PADDING
    // and the walk would have finished clean over a wrong extent.
    private static readonly byte[] QuicFrameSeedDatagramData = [0xa1, 0xa2, 0xa3];

    private static void AddQuicFramesSeeds(List<byte[]> seeds)
    {
        // RFC 9001 Appendix A.2's client Initial plaintext - the only
        // IETF-published frame encoding this phase has: one 245-byte CRYPTO
        // frame followed by PADDING out to 1162 bytes. Taken from
        // QuicRfcVectors, which is source-linked into the test assembly too, so
        // these bytes are transcribed once for both; see that file's header for
        // why it may share bytes but never a type.
        seeds.Add(QuicRfcVectors.BuildA2Plaintext());

        // The same CRYPTO frame with nothing after it, so its declared Length
        // ends exactly at the buffer's end rather than well short of it - the
        // off-by-one neighbourhood the padded form never visits.
        seeds.Add(QuicRfcVectors.BuildA2CryptoFrame());

        // One instance of every frame type, each built by the real encoder, and
        // one seed per wire value rather than per enum member: all eight STREAM
        // forms, both ACK forms, both MAX_STREAMS, both STREAMS_BLOCKED and both
        // CONNECTION_CLOSE forms get their own seed.
        for (var rawType = 0UL; rawType < QuicRawFrameTypeCount; rawType++)
        {
            List<byte> single = [];
            TlsQuicFrames.WriteFrame(single, BuildQuicSeedFrame(rawType));
            seeds.Add([.. single]);
        }

        // Task C17's two DATAGRAM forms, RFC 9221 s4's 0x30 and 0x31 - HAND-BUILT
        // BYTES, and they have to be. Every seed above is encoder output, but
        // WriteFrame refuses to emit a DATAGRAM by design: this library parses and
        // drops them to honour an advertisement it makes by default, and
        // implements no datagram semantics to send. So these two are transcribed
        // from s4's frame diagram instead - Type (i) = 0x30..0x31, then [Length
        // (i)], then Datagram Data (..).
        //
        // QuicFrameSeedDatagramData is shared with the sequence seed below and is
        // three bytes, so the LEN-present form declares Length 3.
        seeds.Add([(byte)TlsQuicFrameType.Datagram, .. QuicFrameSeedDatagramData]);
        seeds.Add([(byte)QuicDatagramWithLengthFrameType, (byte)QuicFrameSeedDatagramData.Length, .. QuicFrameSeedDatagramData]);

        // A packet payload holding several frames in sequence, ascending by
        // type. The four LEN-clear STREAM forms are excluded and seeded only on
        // their own above: RFC 9000 s19.8 gives a LEN-clear STREAM frame "all of
        // the remaining bytes in the packet", so one placed mid-sequence would
        // swallow every frame after it and the walk would never reach them.
        List<byte> sequence = [];
        for (var rawType = 0UL; rawType < QuicRawFrameTypeCount; rawType++)
        {
            if (IsLengthlessQuicStreamFrameType(rawType))
            {
                continue;
            }
            TlsQuicFrames.WriteFrame(sequence, BuildQuicSeedFrame(rawType));
        }

        // DATAGRAM 0x31 tails the sequence, appended rather than written because
        // there is no writer. 0x30 is excluded for exactly the reason the LEN-clear
        // STREAM forms are: RFC 9221 s4 gives it "the end of the packet", so
        // mid-sequence it would swallow everything after it. This is what puts a
        // DATAGRAM in front of the walk with real frames BEFORE it, which the
        // single-frame seeds above cannot do - the offset a DATAGRAM is entered at
        // is the thing its extent arithmetic is applied to.
        sequence.Add((byte)QuicDatagramWithLengthFrameType);
        sequence.Add((byte)QuicFrameSeedDatagramData.Length);
        sequence.AddRange(QuicFrameSeedDatagramData);
        seeds.Add([.. sequence]);
    }

    private static bool IsQuicStreamFrameType(ulong rawType) =>
        rawType >= (ulong)TlsQuicFrameType.Stream && rawType <= QuicMaximumStreamFrameType;

    private static bool IsLengthlessQuicStreamFrameType(ulong rawType) =>
        IsQuicStreamFrameType(rawType) && !TlsQuicStreamFrames.HasLength(rawType);

    private static TlsQuicFrame BuildQuicSeedFrame(ulong rawType)
    {
        if (IsQuicStreamFrameType(rawType))
        {
            // s19.8: the OFF bit decides whether an Offset field is present at
            // all, and WriteStreamFrameFields rejects a nonzero Offset without
            // it ("When the Offset field is absent, the offset is 0"), so the
            // four OFF-clear forms must carry 0 here rather than the seed value.
            return new TlsQuicFrame
            {
                RawType = rawType,
                StreamId = QuicFrameSeedStreamId,
                Offset = TlsQuicStreamFrames.HasOffset(rawType) ? QuicFrameSeedOffset : 0,
                Data = QuicFrameSeedData,
            };
        }

        return rawType switch
        {
            (ulong)TlsQuicFrameType.Padding or
            (ulong)TlsQuicFrameType.Ping or
            (ulong)TlsQuicFrameType.HandshakeDone => new TlsQuicFrame { RawType = rawType },

            (ulong)TlsQuicFrameType.Ack => BuildQuicSeedAckFrame(rawType, null),
            QuicAckWithEcnFrameType => BuildQuicSeedAckFrame(
                rawType,
                new TlsQuicEcnCounts(QuicFrameSeedEct0, QuicFrameSeedEct1, QuicFrameSeedEcnCe)),

            (ulong)TlsQuicFrameType.ResetStream => new TlsQuicFrame
            {
                RawType = rawType,
                StreamId = QuicFrameSeedStreamId,
                ApplicationProtocolErrorCode = QuicFrameSeedErrorCode,
                FinalSize = QuicFrameSeedFinalSize,
            },
            (ulong)TlsQuicFrameType.StopSending => new TlsQuicFrame
            {
                RawType = rawType,
                StreamId = QuicFrameSeedStreamId,
                ApplicationProtocolErrorCode = QuicFrameSeedErrorCode,
            },
            // s19.6: a CRYPTO frame bears no stream identifier, and
            // WriteCryptoFrameFields rejects a nonzero StreamId.
            (ulong)TlsQuicFrameType.Crypto => new TlsQuicFrame
            {
                RawType = rawType,
                Offset = QuicFrameSeedOffset,
                Data = QuicFrameSeedData,
            },
            // s19.7: "The token MUST NOT be empty."
            (ulong)TlsQuicFrameType.NewToken => new TlsQuicFrame
            {
                RawType = rawType,
                Token = QuicFrameSeedToken,
            },
            (ulong)TlsQuicFrameType.MaxData or
            (ulong)TlsQuicFrameType.DataBlocked => new TlsQuicFrame
            {
                RawType = rawType,
                MaximumData = QuicFrameSeedMaximumData,
            },
            (ulong)TlsQuicFrameType.MaxStreamData or
            (ulong)TlsQuicFrameType.StreamDataBlocked => new TlsQuicFrame
            {
                RawType = rawType,
                StreamId = QuicFrameSeedStreamId,
                MaximumStreamData = QuicFrameSeedMaximumStreamData,
            },
            (ulong)TlsQuicFrameType.MaxStreams or
            QuicUnidirectionalMaxStreamsFrameType or
            (ulong)TlsQuicFrameType.StreamsBlocked or
            QuicUnidirectionalStreamsBlockedFrameType => new TlsQuicFrame
            {
                RawType = rawType,
                MaximumStreams = QuicFrameSeedMaximumStreams,
            },
            // s19.15 bounds all three of these: Retire Prior To <= Sequence
            // Number, a 1-to-20-byte connection ID, and a 128-bit token.
            (ulong)TlsQuicFrameType.NewConnectionId => new TlsQuicFrame
            {
                RawType = rawType,
                SequenceNumber = QuicFrameSeedSequenceNumber,
                RetirePriorTo = QuicFrameSeedRetirePriorTo,
                ConnectionId = QuicFrameSeedConnectionId,
                StatelessResetToken = QuicFrameSeedStatelessResetToken,
            },
            (ulong)TlsQuicFrameType.RetireConnectionId => new TlsQuicFrame
            {
                RawType = rawType,
                SequenceNumber = QuicFrameSeedSequenceNumber,
            },
            // s19.17: "This 8-byte field contains arbitrary data."
            (ulong)TlsQuicFrameType.PathChallenge or
            (ulong)TlsQuicFrameType.PathResponse => new TlsQuicFrame
            {
                RawType = rawType,
                Data = QuicFrameSeedPathData,
            },
            (ulong)TlsQuicFrameType.ConnectionClose => new TlsQuicFrame
            {
                RawType = rawType,
                ErrorCode = QuicFrameSeedErrorCode,
                TriggerFrameType = QuicFrameSeedTriggerFrameType,
                ReasonPhrase = QuicFrameSeedReasonPhrase,
            },
            // s19.19: "The application-specific variant of CONNECTION_CLOSE
            // (type 0x1d) does not include this field", so TriggerFrameType is
            // left at 0 and WriteConnectionCloseFrameFields would reject any
            // other value.
            QuicApplicationConnectionCloseFrameType => new TlsQuicFrame
            {
                RawType = rawType,
                ErrorCode = QuicFrameSeedErrorCode,
                ReasonPhrase = QuicFrameSeedReasonPhrase,
            },

            _ => throw new InvalidOperationException(
                $"No quic-frames seed is defined for raw frame type 0x{rawType:x2}; RFC 9000 s12.4 " +
                "Table 3 covers 0x00-0x1e with no gaps, so this means a type was added without a seed."),
        };
    }

    private static TlsQuicFrame BuildQuicSeedAckFrame(ulong rawType, TlsQuicEcnCounts? ecnCounts) => new()
    {
        RawType = rawType,
        LargestAcknowledged = QuicFrameSeedLargestAcknowledged,
        AckDelay = QuicFrameSeedAckDelay,
        AckRangeCount = 1,
        FirstAckRange = QuicFrameSeedFirstAckRange,
        AckRanges = QuicFrameSeedAckRanges,
        EcnCounts = ecnCounts,
    };

    internal void Run(string target, ReadOnlySpan<byte> input)
    {
        if (input.Length > MaximumInputLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(input),
                $"Fuzz inputs are bounded to {MaximumInputLength} bytes.");
        }

        var owned = input.ToArray();
        if (string.Equals(target, "all", StringComparison.Ordinal))
        {
            foreach (var name in Names)
            {
                RunCore(name, owned);
            }
            return;
        }

        if (!Names.Contains(target, StringComparer.Ordinal))
        {
            throw new ArgumentException($"Unknown fuzz target '{target}'.", nameof(target));
        }
        RunCore(target, owned);
    }

    public void Dispose() => _offer.Dispose();

    private void RunCore(string target, byte[] input)
    {
        switch (target)
        {
            case "clienthello":
                RunClientHello(input);
                break;
            case "serverflight":
                RunServerFlight(input);
                break;
            case "certificates":
                RunCertificates(input);
                break;
            case "records":
                RunRecords(input);
                break;
            case "sessions":
                RunSessions(input);
                break;
            case "ech-quic-dns":
                RunEchQuicDns(input);
                break;
            case "state-machines":
                RunStateMachines(input);
                break;
            case "socks5":
                FuzzSocks5(input);
                break;
            case "quic-packets":
                RunQuicPackets(input);
                break;
            case "quic-frames":
                RunQuicFrames(input);
                break;
            case "qpack":
                RunQpack(input);
                break;
            case "http3":
                RunHttp3(input);
                break;
            default:
                throw new InvalidOperationException("Validated fuzz target was not dispatched.");
        }
    }

    private static void RunClientHello(byte[] input)
    {
        ProtocolBoundary(() => Tls13ClientHelloParser.Parse(input));
        CaptureBoundary(() => ClientHelloCapture.Import(input));
        JsonBoundary(() => ClientHelloSpecJson.Deserialize(input));
        Deframe(input);
    }

    private void RunServerFlight(byte[] input)
    {
        ProtocolBoundary(() => ServerHelloParser.Parse(input, _offer));
        ProtocolBoundary(() => EncryptedExtensionsParser.Parse(
            input,
            _offer.Configuration,
            offeredEarlyData: true,
            allowApplicationSettingsWithEarlyData: true,
            echWasRejected: true));
        ProtocolBoundary(() => CertificateRequestParser.ParseInitial(input));
        ProtocolBoundary(() => CertificateRequestParser.ParsePostHandshake(input));
        ProtocolBoundary(() => KeyUpdateProcessor.ParseRequestUpdate(input));
    }

    private void RunCertificates(byte[] input)
    {
        ProtocolBoundary(() =>
        {
            using var parsed = CertificateMessageParser.Parse(
                input,
                _limits,
                _certificateOffer);
        });
        ProtocolBoundary(() =>
        {
        });
        ProtocolBoundary(() =>
        {
            using var parsed = ClientCertificateMessageParser.Parse(input, _limits);
        });
        ProtocolBoundary(() =>
        {
        });
        ProtocolBoundary(() => CompressedCertificateParser.Decompress(
            input,
            _certificateOffer,
            _limits));
    }

    private static void RunRecords(byte[] input)
    {
        ProtocolBoundary(() =>
        {
            using var stream = new MemoryStream(input, writable: false);
            var reader = new TlsRecordReader(stream);
            for (var count = 0; count < 8; count++)
            {
                if (reader.ReadAsync(CancellationToken.None).AsTask()
                    .GetAwaiter().GetResult() is null)
                {
                    break;
                }
            }
        });
        Deframe(input);
        ProtocolBoundary(() =>
        {
            var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
            using var cipher = new Tls13RecordCipher(
                suite,
                new byte[suite.KeyLength],
                new byte[suite.IvLength],
                maximumRecords: 1);
            _ = cipher.Decrypt(input);
        });
    }

    private static void RunSessions(byte[] input)
    {
        ProtocolBoundary(() => Tls13NewSessionTicketParser.Parse(input));
        ProtocolBoundary(() => Tls13ServerSessionTicketState.Decode(input));
    }

    private static void RunEchQuicDns(byte[] input)
    {
        ProtocolBoundary(() => TlsEchConfigList.Parse(input));
        QuicBoundary(() => TlsQuicTransportParameters.Parse(input));
        QuicBoundary(() =>
        {
            var reassembler = new TlsQuicCryptoStreamReassembler(64 * 1024);
            _ = reassembler.Add(0, input);
            _ = reassembler.Add(0, input);
            reassembler.Discard();
            if (input.Length != 0)
            {
                _ = reassembler.Add((ulong)input.Length, input.AsSpan(0, 1));
            }
        });
        DnsBoundary(() => DnsMessageParser.HasTruncatedFlag(input));
        DnsBoundary(() => DnsMessageParser.ParseHttpsResponse(
            input,
            input.Length >= 2 ? (ushort)((input[0] << 8) | input[1]) : (ushort)0,
            "fuzz.invalid",
            MaximumInputLength,
            maximumRecords: 256));
    }

    private static void RunStateMachines(byte[] input)
    {
        var client13 = new Tls13ClientStateMachine();
        var server13 = new Tls13ServerStateMachine();
        // State space saturates quickly, while rejected transitions allocate
        // exceptions. Keep each fuzz invocation strictly bounded so long random
        // inputs cannot dominate a coverage campaign without adding coverage.
        foreach (var value in input.AsSpan(0, Math.Min(input.Length, MaximumStateMachineActions)))
        {
            ProtocolBoundary(() => ApplyTls13ClientAction(client13, value));
            ProtocolBoundary(() => ApplyTls13ServerAction(server13, value));
        }
    }

    private byte[] BuildTls13ServerHello()
    {
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16((ushort)TlsExtensionType.SupportedVersions);
        extensions.WriteVector16([0x03, 0x04]);
        var keyShare = new TlsBinaryWriter();
        keyShare.WriteUInt16((ushort)NamedGroup.X25519);
        keyShare.WriteVector16(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray());
        extensions.WriteUInt16((ushort)TlsExtensionType.KeyShare);
        extensions.WriteVector16(keyShare.WrittenSpan);
        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(Enumerable.Range(0, TlsConstants.RandomLength).Select(value => (byte)value).ToArray());
        body.WriteVector8(_offer.SessionId);
        body.WriteUInt16((ushort)TlsCipherSuite.TlsAes128GcmSha256);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return body.ToArray();
    }


    private static byte[] BuildTls13CiphertextSeed()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var encryptor = new Tls13RecordCipher(
            suite,
            new byte[suite.KeyLength],
            new byte[suite.IvLength],
            maximumRecords: 1);
        return encryptor.Encrypt(TlsContentType.ApplicationData, "tls13-seed"u8);
    }


    private static byte[] BuildTls13CertificateBody()
    {
        var entries = new TlsBinaryWriter();
        entries.WriteVector24(FuzzCertificateDer);
        entries.WriteVector16([]);
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector24(entries.WrittenSpan);
        return body.ToArray();
    }


    private static byte[] BuildCompressedCertificateBody(
        ReadOnlySpan<byte> certificateBody,
        ushort algorithm)
    {
        using var output = new MemoryStream();
        using (Stream compressor = algorithm switch
        {
            (ushort)TlsCertificateCompressionAlgorithm.Zlib =>
                new ZLibStream(output, CompressionLevel.SmallestSize, leaveOpen: true),
            (ushort)TlsCertificateCompressionAlgorithm.Brotli =>
                new BrotliStream(output, CompressionLevel.SmallestSize, leaveOpen: true),
            ZstdAlgorithm => new ZstdSharp.CompressionStream(output, level: 19, leaveOpen: true),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        })
        {
            compressor.Write(certificateBody);
        }
        var body = new TlsBinaryWriter();
        body.WriteUInt16(algorithm);
        body.WriteUInt24(certificateBody.Length);
        body.WriteVector24(output.ToArray());
        return body.ToArray();
    }

    private void VerifyCompressedCertificateSeed(
        ReadOnlySpan<byte> certificateBody,
        ushort algorithm)
    {
        var decompressed = CompressedCertificateParser.Decompress(
            BuildCompressedCertificateBody(certificateBody, algorithm),
            _certificateOffer,
            _limits);
        if (!decompressed.AsSpan().SequenceEqual(certificateBody))
        {
            throw new InvalidOperationException(
                $"Compressed certificate fuzz seed for algorithm {algorithm} does not round-trip.");
        }
    }

    private static byte[] BuildEchConfigList()
    {
        var suites = new TlsBinaryWriter();
        suites.WriteUInt16((ushort)TlsHpkeKdfId.HkdfSha256);
        suites.WriteUInt16((ushort)TlsHpkeAeadId.Aes128Gcm);
        var contents = new TlsBinaryWriter();
        contents.WriteUInt8(7);
        contents.WriteUInt16((ushort)TlsHpkeKemId.DhkemX25519HkdfSha256);
        contents.WriteVector16(Enumerable.Repeat((byte)1, 32).ToArray());
        contents.WriteVector16(suites.WrittenSpan);
        contents.WriteUInt8(0);
        contents.WriteVector8("public.example"u8);
        contents.WriteVector16([]);
        var config = new TlsBinaryWriter();
        config.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
        config.WriteVector16(contents.WrittenSpan);
        var list = new TlsBinaryWriter();
        list.WriteVector16(config.WrittenSpan);
        return list.ToArray();
    }

    private static byte[] BuildDnsHttpsNoDataResponse()
    {
        var response = new TlsBinaryWriter();
        response.WriteUInt16(0x1234);
        response.WriteUInt16(0x8180);
        response.WriteUInt16(1);
        response.WriteUInt16(0);
        response.WriteUInt16(0);
        response.WriteUInt16(0);
        response.WriteVector8("fuzz"u8);
        response.WriteVector8("invalid"u8);
        response.WriteUInt8(0);
        response.WriteUInt16(65);
        response.WriteUInt16(1);
        return response.ToArray();
    }

    private static void VerifySessionSeeds()
    {
        var seeds = CreateBoundarySeeds();
        AddSessionSeeds(seeds);
        // AddSessionSeeds appends exactly two entries now that the TLS 1.2 ticket and
        // ticket-state seeds are gone: the 1.3 NewSessionTicket then the 1.3 ticket state.
        _ = Tls13NewSessionTicketParser.Parse(seeds[^2]);
        using (Tls13ServerSessionTicketState.Decode(seeds[^1])) { }
    }

    // The quic-packets campaign's entire value rests on its seeds - blind
    // mutation reaches almost nothing past the first gate (see
    // AddQuicPacketsSeeds' own comments) - yet unlike every other target's
    // seeds above, they had no equivalent self-check. A future refactor of a
    // writer or parser could silently change what a seed means, and nothing
    // would catch it short of someone re-deriving it by hand again: a
    // silently broken seed turns a meaningful campaign into 200,000 rejected
    // inputs that still report clean. This pins exactly what
    // AddQuicPacketsSeeds claims about its own output.
    internal void VerifyQuicSeeds()
    {
        var seeds = CreateBoundarySeeds();
        AddQuicPacketsSeeds(seeds);

        // AddQuicPacketsSeeds appends exactly 7 items in a fixed order;
        // indexed from the end so this does not depend on CreateBoundarySeeds'
        // own count, matching VerifySessionSeeds' existing pattern above.
        var appendixA2PaddedInitial = seeds[^7];
        var appendixA2BareHeader = seeds[^6];
        var appendixA5ShortHeaderPacket = seeds[^5];
        var versionNegotiationPacket = seeds[^3];
        var versionZeroAfterOffsetZero = seeds[^1];

        if (!TlsQuicPacketHeader.TryReadLongHeader(appendixA2PaddedInitial, out _, out _))
        {
            throw new InvalidOperationException(
                "QUIC fuzz seed regression: the RFC 9001 Appendix A.2 padded Initial seed no longer parses.");
        }
        if (TlsQuicPacketHeader.TryReadLongHeader(appendixA2BareHeader, out _, out _))
        {
            throw new InvalidOperationException(
                "QUIC fuzz seed regression: the RFC 9001 Appendix A.2 bare-header seed unexpectedly parses.");
        }
        if (!TlsQuicPacketHeader.TryReadShortHeader(appendixA5ShortHeaderPacket, 0, out _, out _))
        {
            throw new InvalidOperationException(
                "QUIC fuzz seed regression: the RFC 9001 Appendix A.5 short header seed no longer parses.");
        }
        if (!TlsQuicVersionNegotiation.TryRead(versionNegotiationPacket, out _))
        {
            throw new InvalidOperationException(
                "QUIC fuzz seed regression: the Version Negotiation seed no longer parses.");
        }

        var packetCount = TlsQuicDatagramReader.Read(versionZeroAfterOffsetZero).Count();
        if (packetCount != 2)
        {
            throw new InvalidOperationException(
                "QUIC fuzz seed regression: the version-zero-after-offset-0 datagram yielded " +
                $"{packetCount} packet(s) instead of 2.");
        }
    }

    // The quic-frames corpus is worth even less than quic-packets' without this.
    // Its seeds are not hand-written bytes but encoder output, so a writer
    // change silently changes what every one of them means, and a seed that no
    // longer parses is a seed that fuzzes nothing: the campaign would still
    // report clean while reaching only the reject path. Each claim
    // AddQuicFramesSeeds makes about its own output is pinned here.
    internal void VerifyQuicFrameSeeds()
    {
        var seeds = CreateBoundarySeeds();
        AddQuicFramesSeeds(seeds);

        // AddQuicFramesSeeds appends, in order: the A.2 payload, the A.2 CRYPTO
        // frame alone, one seed per raw frame type 0x00-0x1e, the two RFC 9221
        // DATAGRAM forms, then the several-frames-in-sequence payload. Indexed
        // from the end so this does not depend on CreateBoundarySeeds' own count,
        // matching VerifyQuicSeeds.
        //
        // The count is 31 + 5: two A.2 seeds, thirty-one per-type seeds, two
        // DATAGRAM seeds and one sequence seed is 36, and QuicRawFrameTypeCount is
        // 31. The DATAGRAM pair is inserted BEFORE the sequence seed on purpose -
        // it leaves `seeds[^1]` meaning the sequence, and leaves the per-type
        // index arithmetic below unchanged, so this task edits one number rather
        // than four.
        var appended = QuicRawFrameTypeCount + QuicDatagramRawFrameTypeCount + 3;
        var a2Payload = seeds[^appended];
        var a2CryptoFrame = seeds[^(appended - 1)];
        var datagramLengthless = seeds[^3];
        var datagramWithLength = seeds[^2];
        var sequence = seeds[^1];

        List<ulong> walked = [];

        // RFC 9001 A.2: one CRYPTO frame at offset 0 carrying 241 bytes and
        // spanning 245, then one PADDING frame per remaining byte - this reader
        // yields one frame per zero byte rather than coalescing the run.
        // Mirrors TlsQuicStreamFramesTests.Rfc9001AppendixA2ClientInitialCrypto
        // FrameParsesToItsPublishedOffsetAndLength.
        var offset = 0;
        if (!TlsQuicFrames.TryReadFrame(a2Payload, ref offset, out var crypto, out _) ||
            crypto.Type != TlsQuicFrameType.Crypto ||
            crypto.Offset != 0 ||
            crypto.Data.Length != 241 ||
            offset != 245)
        {
            throw new InvalidOperationException(
                "QUIC frame fuzz seed regression: the RFC 9001 Appendix A.2 CRYPTO frame no longer " +
                $"parses to offset 0 with 241 data bytes over a 245-byte extent (ended at {offset}).");
        }
        var consumed = WalkQuicFrameSeed(a2Payload, walked);
        if (consumed != QuicRfcVectors.A2PayloadLength ||
            walked.Count != QuicRfcVectors.A2PaddingFrameCount + 1 ||
            walked[0] != (ulong)TlsQuicFrameType.Crypto ||
            walked.Exists(rawType => rawType != (ulong)TlsQuicFrameType.Padding &&
                                     rawType != (ulong)TlsQuicFrameType.Crypto))
        {
            throw new InvalidOperationException(
                "QUIC frame fuzz seed regression: the RFC 9001 Appendix A.2 payload no longer walks " +
                $"to 1 CRYPTO frame plus {QuicRfcVectors.A2PaddingFrameCount} PADDING frames over " +
                $"{QuicRfcVectors.A2PayloadLength} bytes (got {walked.Count} frame(s) over {consumed}).");
        }

        walked.Clear();
        consumed = WalkQuicFrameSeed(a2CryptoFrame, walked);
        if (consumed != a2CryptoFrame.Length || walked.Count != 1 ||
            walked[0] != (ulong)TlsQuicFrameType.Crypto)
        {
            throw new InvalidOperationException(
                "QUIC frame fuzz seed regression: the bare RFC 9001 Appendix A.2 CRYPTO frame seed no " +
                $"longer walks to exactly one frame filling its {a2CryptoFrame.Length} bytes.");
        }

        // Every per-type seed must parse back to the wire value it was built
        // from and fill its own buffer exactly. The seed index is the raw type.
        for (var rawType = 0UL; rawType < QuicRawFrameTypeCount; rawType++)
        {
            var seed = seeds[^(appended - 2 - (int)rawType)];
            walked.Clear();
            consumed = WalkQuicFrameSeed(seed, walked);
            if (consumed != seed.Length || walked.Count != 1 || walked[0] != rawType)
            {
                throw new InvalidOperationException(
                    $"QUIC frame fuzz seed regression: the seed for raw frame type 0x{rawType:x2} no " +
                    $"longer walks to exactly one frame of that type filling its {seed.Length} bytes " +
                    $"(got {walked.Count} frame(s) over {consumed}).");
            }
        }

        // The ACK seeds carry range bytes, and a count/largest/first triple the
        // decoder walks them with. Asserting the decoded pairs rather than the
        // frame's raw fields is what makes a transposed write visible: the four
        // numbers are all distinct (see QuicFrameSeedAckRanges).
        foreach (var ackRawType in new[] { (ulong)TlsQuicFrameType.Ack, QuicAckWithEcnFrameType })
        {
            var seed = seeds[^(appended - 2 - (int)ackRawType)];
            var ackOffset = 0;
            List<TlsQuicAckRange> ranges = [];
            if (!TlsQuicFrames.TryReadFrame(seed, ref ackOffset, out var ack, out _) ||
                !TlsQuicAckFrames.TryGetRanges(ack, ranges, out _) ||
                ranges.Count != 2 ||
                ranges[0] != new TlsQuicAckRange(QuicFrameSeedLargestAcknowledged, 26) ||
                ranges[1] != new TlsQuicAckRange(19, 9))
            {
                throw new InvalidOperationException(
                    $"QUIC frame fuzz seed regression: the ACK seed for type 0x{ackRawType:x2} no " +
                    "longer decodes to the ranges (58, 26) and (19, 9).");
            }
        }

        // The two RFC 9221 DATAGRAM seeds. Both must walk to exactly one frame
        // filling their own buffer, and the pair is what pins the LEN bit: the
        // 0x30 seed carries three data bytes with no Length field at all, so a
        // reader that looked for one would take 0xa1 as a Length of 33 and reject
        // the seed outright; the 0x31 seed's Length is 3 with 3 bytes following,
        // so a reader that ignored Length and ran to the end would still consume
        // the buffer - which is why the sequence seed below carries the 0x31 form
        // with real frames in front of it rather than relying on this row.
        foreach (var (datagramSeed, datagramRawType) in new[]
        {
            (datagramLengthless, (ulong)TlsQuicFrameType.Datagram),
            (datagramWithLength, QuicDatagramWithLengthFrameType),
        })
        {
            walked.Clear();
            consumed = WalkQuicFrameSeed(datagramSeed, walked);
            if (consumed != datagramSeed.Length || walked.Count != 1 ||
                walked[0] != datagramRawType)
            {
                throw new InvalidOperationException(
                    $"QUIC frame fuzz seed regression: the RFC 9221 DATAGRAM seed for raw frame " +
                    $"type 0x{datagramRawType:x2} no longer walks to exactly one frame of that " +
                    $"type filling its {datagramSeed.Length} bytes (got {walked.Count} frame(s) " +
                    $"over {consumed}).");
            }
        }

        // The sequence seed is every raw type except the four LEN-clear STREAM
        // forms, ascending, then the LEN-present DATAGRAM, and the walk must reach
        // all of them - a seed whose tail is unreachable fuzzes only its head. The
        // DATAGRAM is last and is the row that matters most here: it is reached at
        // a nonzero offset, after every other frame type, so a wrong extent shows
        // up as a short walk rather than as a lone rejected seed.
        walked.Clear();
        consumed = WalkQuicFrameSeed(sequence, walked);
        var expected = new List<ulong>();
        for (var rawType = 0UL; rawType < QuicRawFrameTypeCount; rawType++)
        {
            if (!IsLengthlessQuicStreamFrameType(rawType))
            {
                expected.Add(rawType);
            }
        }
        expected.Add(QuicDatagramWithLengthFrameType);
        if (consumed != sequence.Length || !walked.SequenceEqual(expected))
        {
            throw new InvalidOperationException(
                "QUIC frame fuzz seed regression: the several-frames-in-sequence seed no longer walks " +
                $"to {expected.Count} frames in ascending type order over its {sequence.Length} bytes " +
                $"(got {walked.Count} frame(s) over {consumed}).");
        }
    }

    private static int WalkQuicFrameSeed(byte[] payload, List<ulong> rawTypes)
    {
        var offset = 0;
        while (offset < payload.Length &&
               TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out _))
        {
            rawTypes.Add(frame.RawType);
        }
        return offset;
    }

    private static void VerifyStateMachineSeeds()
    {
        var client13Direct = new Tls13ClientStateMachine();
        foreach (var value in new byte[] { 0, 1, 4, 5, 7, 8, 9, 13, 14, 15 })
        {
            ApplyTls13ClientAction(client13Direct, value);
        }
        var client13RetryAndAuth = new Tls13ClientStateMachine();
        foreach (var value in new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 129, 12, 13, 14, 15 })
        {
            ApplyTls13ClientAction(client13RetryAndAuth, value);
        }
        var server13Direct = new Tls13ServerStateMachine();
        foreach (var value in new byte[] { 0, 2, 3, 4, 5, 6 })
        {
            ApplyTls13ServerAction(server13Direct, value);
        }
        var server13Retry = new Tls13ServerStateMachine();
        foreach (var value in new byte[] { 0, 1, 2, 3, 4, 5, 6 })
        {
            ApplyTls13ServerAction(server13Retry, value);
        }
        if (client13Direct.State != Tls13ClientState.Closed ||
            client13RetryAndAuth.State != Tls13ClientState.Closed ||
            server13Direct.State != Tls13ServerState.Closed ||
            server13Retry.State != Tls13ServerState.Closed)
        {
            throw new InvalidOperationException("TLS 1.3 state-machine fuzz seed did not reach Closed.");
        }
    }


    private static byte[] BuildRecord(
        TlsContentType contentType,
        ReadOnlySpan<byte> payload,
        ushort version)
    {
        var record = new TlsBinaryWriter(TlsConstants.RecordHeaderLength + payload.Length);
        record.WriteUInt8((byte)contentType);
        record.WriteUInt16(version);
        record.WriteVector16(payload);
        return record.ToArray();
    }

    private static List<byte[]> CreateBoundarySeeds() =>
    [
        [],
        [0],
        [1],
        [0, 0],
        [0, 1, 0],
        [0, 0, 0, 0],
    ];

    /// <summary>
    /// RFC 8879 zstd. <see cref="TlsCertificateCompressionAlgorithm"/> has no member for it
    /// because the SharpTls server does not compress with zstd; the client decompresses it.
    /// </summary>
    private const ushort ZstdAlgorithm = 3;

    private static ClientHelloConfiguration CreateCertificateOffer() =>
        ClientHelloProfiles.Custom(builder => builder.WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.Raw(
                (ushort)TlsExtensionType.CompressCertificate,
                [
                    6,
                    0, (byte)TlsCertificateCompressionAlgorithm.Zlib,
                    0, (byte)TlsCertificateCompressionAlgorithm.Brotli,
                    0, (byte)ZstdAlgorithm,
                ])))
        .Spec
        .SnapshotConfiguration();

    private static byte[] FuzzCertificateDer { get; } = Convert.FromBase64String(
        "MIIBgjCCASmgAwIBAgIUfUfnL0XmgEWwqQqC2bzr3q/G1AMwCgYIKoZIzj0EAwIw" +
        "FzEVMBMGA1UEAwwMZnV6ei5pbnZhbGlkMB4XDTI2MDcxODE4NTQ1NloXDTM2MDcx" +
        "NTE4NTQ1NlowFzEVMBMGA1UEAwwMZnV6ei5pbnZhbGlkMFkwEwYHKoZIzj0CAQYI" +
        "KoZIzj0DAQcDQgAEDX5+lnWIJzxtu0gpsCzSXG7+4QGm96nUAJoFWdaeIUpcOM/2" +
        "9IvLYYDSm00vIJvsMkVfbht9hLKS1uesiKdxz6NTMFEwHQYDVR0OBBYEFN8Oclx7" +
        "oGXsVqax++GJ8dGf3FdBMB8GA1UdIwQYMBaAFN8Oclx7oGXsVqax++GJ8dGf3FdB" +
        "MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgFckvFfrFEKYuWqlD" +
        "YSrJU5HCExdwJQc6AHf8f473YyACIAWpUp7HsxX2QLZwpNCeyhZmlLRE+njgIB5n" +
        "ZoCbLaO9");

    private static void ApplyTls13ClientAction(Tls13ClientStateMachine state, byte value)
    {
        switch (value % 17)
        {
            case 0: state.TransportConnected(); break;
            case 1: state.ClientHelloSent(); break;
            case 2: state.HelloRetryRequestReceived(); break;
            case 3: state.SecondClientHelloSent(); break;
            case 4: state.ServerHelloReceived(); break;
            case 5: state.EncryptedExtensionsReceived(); break;
            case 6: state.CertificateRequestReceived(); break;
            case 7: state.CertificateReceived(); break;
            case 8: state.CertificateVerifyReceived(); break;
            case 9: state.ServerFinishedReceived((value & 0x80) != 0); break;
            case 10: state.ClientCertificateSent((value & 0x80) != 0); break;
            case 11: state.ClientApplicationSettingsSent(); break;
            case 12: state.ClientCertificateVerifySent(); break;
            case 13: state.ClientFinishedSent(); break;
            case 14: state.BeginClose(); break;
            case 15: state.Closed(); break;
            case 16: state.Fail(); break;
        }
    }

    private static void ApplyTls13ServerAction(Tls13ServerStateMachine state, byte value)
    {
        switch (value % 8)
        {
            case 0: state.TransportAccepted(); break;
            case 1: state.HelloRetryRequestSent(); break;
            case 2: state.ClientHelloAccepted(); break;
            case 3: state.ServerFlightSent(); break;
            case 4: state.ClientFinishedReceived(); break;
            case 5: state.BeginClose(); break;
            case 6: state.Closed(); break;
            case 7: state.Fail(); break;
        }
    }


    private static void FuzzSocks5(byte[] input)
    {
        ProxyBoundary(() => _ = TlsQuicSocks5Protocol.ParseMethodSelection(input));
        ProxyBoundary(() => TlsQuicSocks5Protocol.ValidateAuthenticationReply(input));
        ProxyBoundary(() => _ = TlsQuicSocks5Protocol.ValidateAssociateReplyHeader(input));
        ProxyBoundary(() =>
        {
            if (input.Length >= 3)
            {
                _ = TlsQuicSocks5Protocol.ResolveRelayEndPoint(
                    input[0],
                    input.AsSpan(1, input.Length - 3),
                    (ushort)((input[^2] << 8) | input[^1]),
                    IPAddress.Loopback);
            }
        });

        // TryReadUdpHeader is Try-shaped and must never throw for ANY input.
        // It is deliberately NOT wrapped in a boundary helper: if it throws,
        // the fuzzer must fail, because a hostile datagram would otherwise be
        // able to kill a live QUIC connection.
        _ = TlsQuicSocks5Protocol.TryReadUdpHeader(input, out _, out _);
    }

    // Every parser called below is Try-shaped by contract - TryReadLongHeader,
    // TryReadShortHeader, TryRead, TryApply, TryRemove, TryOpen, and TryVerify
    // all return false rather than throw for hostile input, the same contract
    // TlsQuicSocks5Protocol.TryReadUdpHeader has above. So, unlike every other
    // RunXxx method in this file, NONE of these calls are wrapped in a
    // boundary helper that would catch and discard an exception type: a
    // boundary helper here would hide exactly the defect this target exists
    // to find. If any of these throw, the fuzzer must fail and report the
    // input untouched.
    //
    // Review already found and fixed two throw-on-hostile-input defects in
    // this namespace before this target existed: an integer overflow in
    // TlsQuicHeaderProtection's bounds guard (see OffsetNearIntMaxDoesNot
    // OverflowTheSampleBoundsGuard) and TlsQuicRetry.TryVerify throwing on a
    // peer-controlled version field. Both are fuzzed below alongside
    // everything else, not specially isolated, since the same "never throws"
    // property is now checked continuously rather than by one-off review.
    // "200,013 inputs, clean" cannot by itself distinguish a seed-anchored
    // campaign that reaches every parser's success path from one that never
    // does - this project's earlier SOCKS5 target ran 200,000 inputs and
    // never reached the two branches that mattered, and the headline number
    // alone could not tell the difference. These counters, and
    // DescribeQuicPacketsReachability below, answer that question for the
    // parsers this target drives. Deliberately scoped to this one target
    // rather than a general per-target mechanism: the other eight targets
    // already have their own seed verification, and reworking the shared
    // harness reporting for all nine is a bigger change than this calls for.
    private long _quicPacketsInputCount;
    private long _quicLongHeaderTrueCount;
    private long _quicShortHeaderTrueCount;
    private long _quicMultiPacketDatagramCount;
    private long _quicVersionNegotiationTrueCount;
    private long _quicPacketProtectionOpenTrueCount;
    private long _quicRetryVerifyTrueCount;

    private void RunQuicPackets(byte[] input)
    {
        _quicPacketsInputCount++;

        if (TlsQuicPacketHeader.TryReadLongHeader(input, out _, out _))
        {
            _quicLongHeaderTrueCount++;
        }

        // destinationConnectionIdLength is caller-supplied, not read from the
        // wire (RFC 9000 s17.3.1's short header carries no length field for
        // it) - swept across the legal range plus one value just past
        // TlsQuicPacketHeader.MaximumConnectionIdLength (20) to hit the
        // early bounds-rejection branch too. Counted once per input (true if
        // ANY of the five calls succeeded), not once per call: the question
        // this reachability count answers is "how many inputs exercise this
        // parser's success path," not "how many of five deterministic sweeps
        // per input succeed."
        var shortHeaderTrue = TlsQuicPacketHeader.TryReadShortHeader(input, 0, out _, out _);
        shortHeaderTrue |= TlsQuicPacketHeader.TryReadShortHeader(input, 1, out _, out _);
        shortHeaderTrue |= TlsQuicPacketHeader.TryReadShortHeader(input, 8, out _, out _);
        shortHeaderTrue |= TlsQuicPacketHeader.TryReadShortHeader(input, 20, out _, out _);
        shortHeaderTrue |= TlsQuicPacketHeader.TryReadShortHeader(input, 21, out _, out _);
        if (shortHeaderTrue)
        {
            _quicShortHeaderTrueCount++;
        }

        if (TlsQuicVersionNegotiation.TryRead(input, out _))
        {
            _quicVersionNegotiationTrueCount++;
        }

        if (RunBoundedQuicDatagramReader(input) >= 2)
        {
            _quicMultiPacketDatagramCount++;
        }

        RunQuicHeaderProtection(input);

        if (RunQuicPacketProtection(input))
        {
            _quicPacketProtectionOpenTrueCount++;
        }

        if (RunQuicRetry(input))
        {
            _quicRetryVerifyTrueCount++;
        }

        RunQuicPacketNumberDecode(input);
    }

    // Printed once at the end of a run (see Program.cs) rather than per
    // input. Null whenever the quic-packets target never ran in this
    // process, so every other target's output is unaffected.
    internal string? DescribeQuicPacketsReachability()
    {
        if (_quicPacketsInputCount == 0)
        {
            return null;
        }

        return string.Join(Environment.NewLine,
        [
            $"quic-packets reachability over {_quicPacketsInputCount} input(s):",
            FormatQuicReachabilityLine("TryReadLongHeader", _quicLongHeaderTrueCount, _quicPacketsInputCount),
            FormatQuicReachabilityLine("TryReadShortHeader", _quicShortHeaderTrueCount, _quicPacketsInputCount),
            FormatQuicReachabilityLine("Read (multi-packet datagram)", _quicMultiPacketDatagramCount, _quicPacketsInputCount),
            FormatQuicReachabilityLine("TryRead (version negotiation)", _quicVersionNegotiationTrueCount, _quicPacketsInputCount),
            FormatQuicReachabilityLine("TryOpen", _quicPacketProtectionOpenTrueCount, _quicPacketsInputCount),
            FormatQuicReachabilityLine("TryVerify (retry)", _quicRetryVerifyTrueCount, _quicPacketsInputCount),
        ]);
    }

    private static string FormatQuicReachabilityLine(string name, long trueCount, long total) =>
        $"  {name}: {trueCount}/{total} ({(100.0 * trueCount / total).ToString("F2", CultureInfo.InvariantCulture)}% true)";

    // TlsQuicDatagramReader.Read is a lazy IEnumerable driven by each long
    // header's declared Length field. A declared Length - or any other
    // computed advance - that comes out to zero would loop forever: RFC 9000
    // s12.2 gives the reader no bound of its own on how many packets one
    // datagram may contain, only that each step must consume the bytes it
    // read. An infinite loop would not surface as an exception - plain
    // unguarded enumeration would simply hang the fuzzer instead of failing
    // it - so it is bounded two independent ways rather than left to a
    // boundary helper, which only catches throws.
    private static readonly TimeSpan QuicDatagramReaderTimeout = TimeSpan.FromMilliseconds(250);

    private static int RunBoundedQuicDatagramReader(byte[] input)
    {
        // Every successful iteration of TlsQuicDatagramReader.Read's loop
        // must consume at least 1 byte (`offset += consumed`, and consumed
        // >= 1 for every yield the current implementation can produce), so a
        // correct implementation can never yield more than input.Length + 1
        // packets from an input.Length-byte datagram. That makes this a real
        // deadlock detector, not a guess: exceeding it means some iteration
        // advanced the offset by zero (or fewer) bytes - the non-advancing
        // loop this target exists to catch. The wall-clock cap below is an
        // independent second check for the same failure mode.
        var maximumPackets = input.Length + 1;
        var started = Stopwatch.GetTimestamp();
        var count = 0;

        foreach (var packet in TlsQuicDatagramReader.Read(input))
        {
            count++;
            if (count > maximumPackets || Stopwatch.GetElapsedTime(started) > QuicDatagramReaderTimeout)
            {
                throw new InvalidOperationException(
                    $"TlsQuicDatagramReader.Read did not terminate within {maximumPackets} packet(s) / " +
                    $"{QuicDatagramReaderTimeout.TotalMilliseconds:F0} ms for a {input.Length}-byte datagram " +
                    "(non-advancing loop suspected).");
            }
            _ = packet.Kind;
        }

        return count;
    }

    // TryApply/TryRemove mutate their `packet` argument in place, so every
    // call below runs against a fresh clone of `input` - `input` is the same
    // array instance ProtocolFuzzTargets.Run reuses across every other RunXxx
    // method for this fuzz iteration (its `owned` array, shared when target
    // is "all"), and must come out the other side unmodified.
    private static readonly int[] QuicHeaderProtectionOffsets = [0, 1, 4, 5, 18, 21];

    private static void RunQuicHeaderProtection(byte[] input)
    {
        var aesKey = new byte[16];
        var chaChaKey = new byte[32];

        // Fixed offsets that land inside, at the edge of, and past a small
        // input. A real caller always derives packetNumberOffset from a
        // header this same namespace already parsed (PacketNumberOffset on
        // TlsQuicLongHeader/TlsQuicShortHeader), but TryApply/TryRemove take
        // it as a bare int with no such guarantee, so it is exercised
        // independently of `input`'s own bytes too.
        foreach (var packetNumberOffset in QuicHeaderProtectionOffsets)
        {
            ApplyAndRemoveHeaderProtection(TlsQuicHeaderProtectionCipher.Aes, aesKey, input, packetNumberOffset);
            ApplyAndRemoveHeaderProtection(TlsQuicHeaderProtectionCipher.ChaCha20, chaChaKey, input, packetNumberOffset);
        }

        ApplyAndRemoveHeaderProtection(TlsQuicHeaderProtectionCipher.Aes, aesKey, input, input.Length);
        ApplyAndRemoveHeaderProtection(TlsQuicHeaderProtectionCipher.ChaCha20, chaChaKey, input, input.Length);

        // The already-fixed integer-overflow regression this target exists to
        // catch: TlsQuicHeaderProtectionTests.OffsetNearIntMaxDoesNotOverflow
        // TheSampleBoundsGuard pins the same value for the unit test; this
        // exercises it under mutation instead of a single fixed case.
        ApplyAndRemoveHeaderProtection(TlsQuicHeaderProtectionCipher.Aes, aesKey, input, int.MaxValue - 10);
        ApplyAndRemoveHeaderProtection(TlsQuicHeaderProtectionCipher.Aes, aesKey, input, int.MinValue);

        // An offset derived from the input's own bytes, including negative
        // values (ReadInt32BigEndian can yield those) - the closest this
        // target gets to attacker-chosen offset bytes.
        if (input.Length >= 4)
        {
            var derivedOffset = BinaryPrimitives.ReadInt32BigEndian(input.AsSpan(0, 4));
            ApplyAndRemoveHeaderProtection(TlsQuicHeaderProtectionCipher.Aes, aesKey, input, derivedOffset);
        }
    }

    private static void ApplyAndRemoveHeaderProtection(
        TlsQuicHeaderProtectionCipher cipher, byte[] key, byte[] input, int packetNumberOffset)
    {
        var forApply = (byte[])input.Clone();
        _ = TlsQuicHeaderProtection.TryApply(cipher, key, forApply, packetNumberOffset);

        var forRemove = (byte[])input.Clone();
        _ = TlsQuicHeaderProtection.TryRemove(cipher, key, forRemove, packetNumberOffset, out _);
    }

    // TryOpen never mutates `ciphertext` (it writes into the caller-supplied
    // `plaintext` destination instead), so `input` is used directly with no
    // cloning, unlike header protection above. key/iv are fixed, well-formed
    // local secrets - never wire-derived - sized correctly per cipher so a
    // mismatched-key-length exception (a caller bug, not a network-input
    // defect) is not what gets exercised here.
    private static readonly byte[] QuicPacketProtectionAesKey = new byte[16];
    private static readonly byte[] QuicPacketProtectionChaChaKey = new byte[32];

    private static bool RunQuicPacketProtection(byte[] input)
    {
        var iv = new byte[12]; // NonceLength.
        var plaintextLength = input.Length >= 16 ? input.Length - 16 : 0;
        var plaintext = new byte[plaintextLength];

        var opened = TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.AesGcm, QuicPacketProtectionAesKey, iv,
            packetNumber: 0, associatedData: ReadOnlySpan<byte>.Empty, input, plaintext);

        opened |= TlsQuicPacketProtection.TryOpen(
            TlsQuicPacketProtectionCipher.ChaCha20Poly1305, QuicPacketProtectionChaChaKey, iv,
            packetNumber: 0, associatedData: ReadOnlySpan<byte>.Empty, input, plaintext);

        return opened;
    }

    // TryVerify never mutates any of its ReadOnlySpan<byte> arguments, so
    // slices of `input` are used directly with no cloning needed.
    private static bool RunQuicRetry(byte[] input)
    {
        var version = input.Length >= 4
            ? (TlsQuicVersion)BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(0, 4))
            : default;

        // Deliberately allowed to exceed TlsQuicPacketHeader.MaximumConnection
        // IdLength (20): it is TryVerify's own length check (not
        // TryReadConnectionId's) that rejects this case, and it needs a seed
        // that actually reaches it.
        var odcidLength = Math.Min(input.Length, 21);
        var odcid = input.AsSpan(0, odcidLength);

        var tagLength = Math.Min(input.Length, 16);
        var tag = input.AsSpan(input.Length - tagLength, tagLength);
        var retryPacketWithoutTag = input.AsSpan(0, input.Length - tagLength);

        // `version` here is peer-controlled per TryVerify's own contract (see
        // its doc comment) - this is the function with the documented
        // throws-on-hostile-version-field defect that review already found
        // and fixed. It is fuzzed with the input-derived version above, as
        // well as both known enum values so the real AES-GCM decrypt path
        // keeps getting exercised once a random version stops being rejected
        // immediately.
        var verified = TlsQuicRetry.TryVerify(version, odcid, retryPacketWithoutTag, tag);
        verified |= TlsQuicRetry.TryVerify(TlsQuicVersion.Version1, odcid, retryPacketWithoutTag, tag);
        verified |= TlsQuicRetry.TryVerify(TlsQuicVersion.Version2, odcid, retryPacketWithoutTag, tag);
        return verified;
    }

    // Decode is not itself Try-shaped - RFC 9000 Appendix A.3's algorithm has
    // no failure mode, and `bits` is validated by explicit design (see
    // TlsQuicPacketNumber.ValidateBits), since a real caller always derives
    // it from a PacketNumberLength this same namespace already bounds to 1-4
    // bytes. Fuzzing `bits` outside {8,16,24,32} would only re-discover that
    // documented guard, not test network input, so it stays fixed here while
    // `largestPn` and `truncated` - the values a real caller reconstructs
    // from wire bytes - vary with the fuzz input.
    private static readonly int[] QuicPacketNumberBitWidths = [8, 16, 24, 32];

    private static void RunQuicPacketNumberDecode(byte[] input)
    {
        var largestPn = ReadUInt64OrZero(input, 0);
        // A full 8 bytes, not just the 4 a real wire packet number field can
        // carry: Decode never bounds-checks `truncated` against `bits`, so an
        // over-wide value is exactly the kind of input worth throwing at it.
        var truncated = ReadUInt64OrZero(input, 8);

        foreach (var bits in QuicPacketNumberBitWidths)
        {
            _ = TlsQuicPacketNumber.Decode(largestPn, truncated, bits);
        }
    }

    private static ulong ReadUInt64OrZero(ReadOnlySpan<byte> source, int offset) =>
        source.Length >= offset + 8 ? BinaryPrimitives.ReadUInt64BigEndian(source[offset..]) : 0;

    // ---------------------------------------------------------------------
    // quic-frames.
    // ---------------------------------------------------------------------
    //
    // Same contract and same absence of a boundary helper as quic-packets
    // above: TryReadFrame and all thirteen family readers are Try-shaped and
    // must never throw for any input, so every call below is unguarded and a
    // throw fails the fuzzer. A boundary helper would hide exactly the defect
    // this target exists to find. The one exception is WriteFrame, which is not
    // a parser and whose ArgumentException is its documented contract - see
    // RunQuicFrameAcceptedFrame.
    //
    // TWO AXES, REPORTED SEPARATELY, AND THE REASON THE SECOND ONE EXISTS.
    // Payload fuzzing alone cannot reach a bounds check on an extent the reader
    // itself produced. A reviewer proved it on the ACK range decoder: it deleted
    // half of a two-comparison extent check and the whole suite stayed green,
    // because the reader always hands the decoder the very buffer it just
    // parsed, and an ArgumentOutOfRangeException escaped a Try method through
    // the hole. So each frame the reader accepts is decoded again against views
    // it did not come from - every truncated prefix of its own extent, and an
    // unrelated buffer - and against a rebuilt frame whose range bytes were
    // swapped out. A single lumped reachability number would hide precisely the
    // difference the second axis exists to expose, so the two are counted and
    // printed apart.
    //
    // WITHIN AXIS 2, THE UNRELATED-BUFFER PROBE IS ITS OWN, UNTYPED COUNTER -
    // NOT FOLDED INTO THE PREFIX SWEEP'S PER-TYPE TABLE. A review caught this
    // after it shipped folded together: RunQuicFrameResliceDecode fed both the
    // same-buffer prefix sweep and the fixed QuicFrameUnrelatedBuffer probe into
    // one _quicFrameResliceTypeAccepts array, keyed by the TYPE THE PROBE
    // DECODED - which for the unrelated buffer has nothing to do with the frame
    // that triggered the call. Ping was the extreme case (byte 0x01 at
    // QuicFrameUnrelatedBuffer's own offset 0 is a complete fieldless Ping, and
    // `start == 0` on nearly every walk's first frame), but any fixed-shape
    // frame type showed the same contamination on top of its genuine prefix
    // count. A truncated prefix of a fixed-shape frame can essentially never
    // re-parse as that same type - only the LEN-clear STREAM forms legitimately
    // survive truncation, per s19.8's implicit-length rule - so the per-type
    // table below is now the prefix sweep alone, and the unrelated-buffer probe
    // gets its own untyped total, the same way the re-hosted ACK check already
    // reports one.
    //
    // AND A HEADLINE ITERATION COUNT IS NOT A RESULT. This project's earlier
    // SOCKS5 target ran 200,000 inputs and never reached the two branches that
    // mattered. DescribeQuicFramesReachability below prints one row per wire
    // frame type for axis 1 and for axis 2's same-buffer prefix sweep - all
    // thirty-three of them since task C17 (Table 3's thirty-one wire values plus
    // RFC 9221's 0x30 and 0x31), zeros included, because a zero row is the
    // finding.
    // The unrelated-buffer and re-hosted sub-probes are untyped totals, not
    // per-type rows, for the reason above - a per-type row there would claim
    // more than the probe can honestly support.
    private const int QuicFrameWalkLimit = 512;
    private const int QuicFrameResliceBudget = 2_048;

    // Never derived from the input: the point of it is to be bytes no check in
    // this namespace has ever seen alongside the frame it is handed to. 0x01
    // upward so most of it decodes as one-byte varints and a decode driven by
    // it walks deep rather than failing on the first field.
    private static readonly byte[] QuicFrameUnrelatedBuffer = SequentialQuicSeedBytes(64, seed: 0x01);

    // RFC 9000 s12.4 Table 3's four columns, in its own order.
    private static readonly TlsQuicEncryptionLevel[] QuicFrameLegalityPacketTypes =
    [
        TlsQuicEncryptionLevel.Initial,
        TlsQuicEncryptionLevel.Handshake,
        TlsQuicEncryptionLevel.EarlyData,
        TlsQuicEncryptionLevel.Application,
    ];

    private delegate bool QuicFrameFamilyRead(
        ReadOnlyMemory<byte> payload,
        ref int offset,
        ulong rawType,
        out TlsQuicFrame frame,
        out TlsQuicTransportError error);

    // Every family reader, with every raw type its range admits. These are
    // `internal`, so this target is a second caller of each - the plan's rule
    // that an internal helper's contract is observable and should be exercised
    // directly rather than only through its production caller. Driving them
    // straight also decouples reachability from TryReadFrame's dispatch: a
    // reader whose switch arm became unreachable would still be fuzzed here,
    // and the two axes' numbers would disagree, which is the point.
    private static readonly (string Name, ulong[] RawTypes, QuicFrameFamilyRead Read)[] QuicFrameFamilyParsers =
    [
        ("TlsQuicAckFrames.TryReadAck",
            [(ulong)TlsQuicFrameType.Ack, QuicAckWithEcnFrameType],
            TlsQuicAckFrames.TryReadAck),
        ("TlsQuicStreamFrames.TryReadStream",
            BuildQuicRawTypeRange((ulong)TlsQuicFrameType.Stream, QuicMaximumStreamFrameType),
            TlsQuicStreamFrames.TryReadStream),
        ("TlsQuicStreamFrames.TryReadCrypto",
            [(ulong)TlsQuicFrameType.Crypto],
            static (ReadOnlyMemory<byte> payload, ref int offset, ulong _, out TlsQuicFrame frame, out TlsQuicTransportError error)
                => TlsQuicStreamFrames.TryReadCrypto(payload, ref offset, out frame, out error)),
        ("TlsQuicFlowControlFrames.TryReadMaximumData",
            [(ulong)TlsQuicFrameType.MaxData, (ulong)TlsQuicFrameType.DataBlocked],
            TlsQuicFlowControlFrames.TryReadMaximumData),
        ("TlsQuicFlowControlFrames.TryReadMaximumStreamData",
            [(ulong)TlsQuicFrameType.MaxStreamData, (ulong)TlsQuicFrameType.StreamDataBlocked],
            TlsQuicFlowControlFrames.TryReadMaximumStreamData),
        ("TlsQuicFlowControlFrames.TryReadMaximumStreams",
            [
                (ulong)TlsQuicFrameType.MaxStreams, QuicUnidirectionalMaxStreamsFrameType,
                (ulong)TlsQuicFrameType.StreamsBlocked, QuicUnidirectionalStreamsBlockedFrameType,
            ],
            TlsQuicFlowControlFrames.TryReadMaximumStreams),
        ("TlsQuicConnectionFrames.TryReadResetStream",
            [(ulong)TlsQuicFrameType.ResetStream],
            static (ReadOnlyMemory<byte> payload, ref int offset, ulong _, out TlsQuicFrame frame, out TlsQuicTransportError error)
                => TlsQuicConnectionFrames.TryReadResetStream(payload, ref offset, out frame, out error)),
        ("TlsQuicConnectionFrames.TryReadStopSending",
            [(ulong)TlsQuicFrameType.StopSending],
            static (ReadOnlyMemory<byte> payload, ref int offset, ulong _, out TlsQuicFrame frame, out TlsQuicTransportError error)
                => TlsQuicConnectionFrames.TryReadStopSending(payload, ref offset, out frame, out error)),
        ("TlsQuicConnectionFrames.TryReadNewToken",
            [(ulong)TlsQuicFrameType.NewToken],
            static (ReadOnlyMemory<byte> payload, ref int offset, ulong _, out TlsQuicFrame frame, out TlsQuicTransportError error)
                => TlsQuicConnectionFrames.TryReadNewToken(payload, ref offset, out frame, out error)),
        ("TlsQuicConnectionFrames.TryReadNewConnectionId",
            [(ulong)TlsQuicFrameType.NewConnectionId],
            static (ReadOnlyMemory<byte> payload, ref int offset, ulong _, out TlsQuicFrame frame, out TlsQuicTransportError error)
                => TlsQuicConnectionFrames.TryReadNewConnectionId(payload, ref offset, out frame, out error)),
        ("TlsQuicConnectionFrames.TryReadRetireConnectionId",
            [(ulong)TlsQuicFrameType.RetireConnectionId],
            static (ReadOnlyMemory<byte> payload, ref int offset, ulong _, out TlsQuicFrame frame, out TlsQuicTransportError error)
                => TlsQuicConnectionFrames.TryReadRetireConnectionId(payload, ref offset, out frame, out error)),
        ("TlsQuicConnectionFrames.TryReadPathData",
            [(ulong)TlsQuicFrameType.PathChallenge, (ulong)TlsQuicFrameType.PathResponse],
            TlsQuicConnectionFrames.TryReadPathData),
        ("TlsQuicConnectionFrames.TryReadConnectionClose",
            [(ulong)TlsQuicFrameType.ConnectionClose, QuicApplicationConnectionCloseFrameType],
            TlsQuicConnectionFrames.TryReadConnectionClose),

        // Task C17. The only entry here whose reader lives in TlsQuicFrames itself
        // rather than in a per-family file - DATAGRAM has no family file because it
        // has no writer to share one with. It is driven directly all the same, and
        // for the reason this table exists: the rawType it is handed is the axis its
        // whole behaviour turns on, and entering it with 0x30 and 0x31 against
        // arbitrary bytes is the only way to sweep the LEN bit against inputs
        // TryReadFrame's dispatch would never route this way.
        ("TlsQuicFrames.TryReadDatagram",
            BuildQuicRawTypeRange((ulong)TlsQuicFrameType.Datagram, QuicDatagramWithLengthFrameType),
            // WRAPPED, because TryReadDatagram takes a frameStart the other readers do not:
            // RFC 9221 s3 measures a DATAGRAM "including the frame type", which every other
            // family reader has no rule needing. Passing the entry offset makes EncodedLength
            // exclude the type varint, which is wrong for the wire and irrelevant here - this
            // target reads the accept/reject verdict and the final offset, never the size.
            (ReadOnlyMemory<byte> payload,
                ref int offset,
                ulong rawType,
                out TlsQuicFrame frame,
                out TlsQuicTransportError error) =>
                TlsQuicFrames.TryReadDatagram(
                    payload, offset, ref offset, rawType, out frame, out error)),
    ];

    private static ulong[] BuildQuicRawTypeRange(ulong first, ulong last)
    {
        var values = new ulong[last - first + 1];
        for (var index = 0; index < values.Length; index++)
        {
            values[index] = first + (ulong)index;
        }
        return values;
    }

    private long _quicFramesInputCount;
    private long _quicFrameWalkAcceptCount;
    private long _quicFrameWalkRejectCount;
    private long _quicFrameWalkLimitHitCount;
    private long _quicFrameResliceAttemptCount;
    private long _quicFrameResliceAcceptCount;
    private long _quicFrameResliceBudgetHitCount;
    private long _quicFrameResliceUnrelatedAttemptCount;
    private long _quicFrameResliceUnrelatedAcceptCount;
    private long _quicFrameResliceUnrelatedSkippedCount;
    private long _quicFrameRehostedAckAttemptCount;
    private long _quicFrameRehostedAckAcceptCount;
    private long _quicFrameGetRangesAttemptCount;
    private long _quicFrameGetRangesAcceptCount;
    private long _quicFrameLegalityAttemptCount;
    private long _quicFrameLegalityPermitCount;
    private long _quicFrameReencodeOkCount;
    private long _quicFrameReencodeThrewCount;
    private readonly long[] _quicFrameWalkTypeAccepts = new long[QuicRawFrameSlotCount];
    private readonly long[] _quicFrameResliceTypeAccepts = new long[QuicRawFrameSlotCount];
    private readonly long[] _quicFrameFamilyParserTrueCounts = new long[QuicFrameFamilyParsers.Length];

    // Reused across inputs rather than allocated per input: this target parses
    // millions of frames and the receive path it drives allocates nothing, so
    // the harness should not be the thing that does.
    private readonly List<TlsQuicAckRange> _quicFrameAckRanges = [];
    private readonly List<byte> _quicFrameReencodeBuffer = [];

    private void RunQuicFrames(byte[] input)
    {
        _quicFramesInputCount++;
        RunQuicFrameFamilyParsers(input);
        RunQuicFramePayloadWalk(input);
    }

    private void RunQuicFrameFamilyParsers(byte[] input)
    {
        ReadOnlyMemory<byte> payload = input;

        // Three entry offsets. 0 and input.Length are the extremes a dispatcher
        // can hand a family reader; 1 is the nonzero interior offset the plan's
        // standing rule asks for, so "offset unchanged on failure" is
        // distinguishable from "reset to zero". Offsets beyond input.Length are
        // deliberately not swept: `offset` is never wire-derived - every real
        // caller gets it from TryReadFrame, which computed it from this same
        // buffer - so an out-of-range one is a caller bug, and fuzzing it would
        // only re-discover QuicVariableLengthInteger.Read's documented
        // (uint)offset >= (uint)source.Length guard. Same provenance argument
        // RunQuicPacketNumberDecode makes for `bits`.
        Span<int> entries = [0, input.Length == 0 ? 0 : 1, input.Length];

        for (var index = 0; index < QuicFrameFamilyParsers.Length; index++)
        {
            var (_, rawTypes, read) = QuicFrameFamilyParsers[index];
            var reached = false;
            foreach (var entry in entries)
            {
                foreach (var rawType in rawTypes)
                {
                    var offset = entry;
                    // Counted once per input if ANY of the sweep's calls
                    // succeeded, not once per call - the question a reachability
                    // count answers is "how many inputs exercise this parser's
                    // success path", not "how many deterministic sweeps per
                    // input succeed". Same convention as the short-header sweep
                    // in RunQuicPackets.
                    reached |= read(payload, ref offset, rawType, out _, out _);
                }
            }
            if (reached)
            {
                _quicFrameFamilyParserTrueCounts[index]++;
            }
        }
    }

    private void RunQuicFramePayloadWalk(byte[] input)
    {
        ReadOnlyMemory<byte> payload = input;
        var offset = 0;
        var frames = 0;
        var budget = QuicFrameResliceBudget;

        while (offset < input.Length)
        {
            var start = offset;
            if (!TlsQuicFrames.TryReadFrame(payload, ref offset, out var frame, out _))
            {
                _quicFrameWalkRejectCount++;
                break;
            }

            _quicFrameWalkAcceptCount++;
            RecordQuicRawType(_quicFrameWalkTypeAccepts, frame.RawType);
            RunQuicFrameAcceptedFrame(frame);
            RunQuicFrameResliceAxis(payload, start, offset, frame, ref budget);

            // A frame that consumed nothing would spin here forever, and a hang
            // is not an exception - the same failure mode
            // RunBoundedQuicDatagramReader guards for whole packets. Every
            // accepted frame consumes at least its own type varint, so a
            // non-advancing offset is a real defect and not a cap this target
            // should absorb quietly.
            if (offset <= start)
            {
                throw new InvalidOperationException(
                    $"TlsQuicFrames.TryReadFrame accepted a frame at offset {start} without advancing " +
                    "(non-advancing loop suspected).");
            }

            if (++frames >= QuicFrameWalkLimit)
            {
                _quicFrameWalkLimitHitCount++;
                break;
            }
        }

        if (budget <= 0)
        {
            _quicFrameResliceBudgetHitCount++;
        }
    }

    private void RunQuicFrameAcceptedFrame(in TlsQuicFrame frame)
    {
        if (frame.Type == TlsQuicFrameType.Ack)
        {
            _quicFrameAckRanges.Clear();
            _quicFrameGetRangesAttemptCount++;
            if (TlsQuicAckFrames.TryGetRanges(frame, _quicFrameAckRanges, out _))
            {
                _quicFrameGetRangesAcceptCount++;
            }
        }

        // The s12.4 legality table is in this target's coverage, but only on the
        // half of its input that comes off the wire. frame.RawType and the
        // TlsQuicFrame.Type collapse over it are attacker-controlled, so Pkts'
        // twenty rows, its empty-string default and the 'i'/'h' cell that
        // compares RawType against 0x1c are all reachable from hostile bytes and
        // are all driven here. `packetType` is NOT wire-derived - a real caller
        // takes it from the packet header it has already parsed - so it is swept
        // across the four enum values and no further; going outside them would
        // only re-discover the ArgumentOutOfRangeException that
        // TlsQuicFrameLegalityTests.APacketTypeOutsideTable3sFourColumnsThrows
        // pins by design. What this does reach that no unit test can enumerate
        // is the pkts[column] index itself: a row whose string ever became
        // shorter than four characters would throw IndexOutOfRangeException for
        // every frame of that type, and Permits is not Try-shaped.
        foreach (var packetType in QuicFrameLegalityPacketTypes)
        {
            _quicFrameLegalityAttemptCount++;
            if (TlsQuicFrameLegality.Permits(frame, packetType))
            {
                _quicFrameLegalityPermitCount++;
            }
        }

        // A frame this library accepted should be re-encodable: WriteFrame's
        // bounds are on caller-supplied fields, and a frame straight out of a
        // parser is exactly such a caller - the provenance case the plan calls
        // out as where the real holes are. Counted rather than thrown on,
        // because an ArgumentException here is WriteFrame's documented contract
        // for a field out of range and is not automatically a defect; a nonzero
        // "threw" count in the report is the thing to go and look at.
        //
        // SINCE TASK C17 THAT COUNT IS NONZERO BY DESIGN, and this is the note
        // that stops the next reader chasing it. Every DATAGRAM frame this target
        // accepts throws here, because WriteFrame refuses to emit one: SharpTls
        // parses and drops DATAGRAM frames to honour an advertisement its defaults
        // make, and implements no datagram semantics to send. It is not folded
        // into a separate counter, because a "threw" total that excluded the one
        // type guaranteed to throw would be a number with a silent exception
        // carved out of it - the shape this project keeps finding defects behind.
        // Subtract the DATAGRAM rows of the axis-1 breakdown to get the count that
        // needs investigating.
        _quicFrameReencodeBuffer.Clear();
        try
        {
            TlsQuicFrames.WriteFrame(_quicFrameReencodeBuffer, frame);
            _quicFrameReencodeOkCount++;
        }
        catch (ArgumentException)
        {
            _quicFrameReencodeThrewCount++;
        }
    }

    private void RunQuicFrameResliceAxis(
        ReadOnlyMemory<byte> payload, int start, int end, in TlsQuicFrame frame, ref int budget)
    {
        // Every prefix that cuts INSIDE this frame's own extent. A cut at `end`
        // is the buffer the reader already had, which axis 1 covered; cuts below
        // `start` cannot reach this frame at all. The reader is re-entered at
        // the same offset, so it re-derives every length and bound it derived
        // the first time - against fewer bytes than those bounds were checked
        // against.
        //
        // No oracle is asserted on the outcome, deliberately. "A frame that
        // needed n bytes must be rejected by every view shorter than n" is false
        // for one wire form: RFC 9000 s19.8 gives a LEN-clear STREAM frame all
        // the remaining bytes of the packet, so a shorter view legitimately
        // yields a shorter frame. What is asserted is the Try contract - no
        // throw, ever - and what is reported is which types this axis reached.
        for (var cut = start; cut < end && budget > 0; cut++, budget--)
        {
            RunQuicFrameResliceDecode(payload[..cut], start);
        }

        // The unrelated buffer, entered at the same offset. Counted apart from
        // the prefix sweep above, and NOT broken down per type - see this
        // method's own file-header comment for why folding it into the same
        // per-type table misattributes: the decoded type here is whatever
        // QuicFrameUnrelatedBuffer happens to hold at `start`, unrelated to the
        // frame that triggered this call.
        //
        // The `start > QuicFrameUnrelatedBuffer.Length` case is a real, surfaced
        // skip, not a silent one: a review caught an earlier version of this
        // bound with no counter behind it. Budget exhaustion is reported
        // separately, once per input, by the caller's own
        // _quicFrameResliceBudgetHitCount.
        if (start > QuicFrameUnrelatedBuffer.Length)
        {
            _quicFrameResliceUnrelatedSkippedCount++;
        }
        else if (budget > 0)
        {
            budget--;
            RunQuicFrameResliceUnrelatedDecode(start);
        }

        if (frame.Type == TlsQuicFrameType.Ack)
        {
            RunQuicRehostedAckRanges(frame, ref budget);
        }
    }

    private void RunQuicFrameResliceDecode(ReadOnlyMemory<byte> view, int at)
    {
        _quicFrameResliceAttemptCount++;
        var offset = at;
        if (TlsQuicFrames.TryReadFrame(view, ref offset, out var frame, out _))
        {
            _quicFrameResliceAcceptCount++;
            RecordQuicRawType(_quicFrameResliceTypeAccepts, frame.RawType);
        }
    }

    private void RunQuicFrameResliceUnrelatedDecode(int at)
    {
        _quicFrameResliceUnrelatedAttemptCount++;
        var offset = at;
        if (TlsQuicFrames.TryReadFrame(QuicFrameUnrelatedBuffer, ref offset, out _, out _))
        {
            _quicFrameResliceUnrelatedAcceptCount++;
        }
    }

    // THE SECOND AXIS AT ITS SHARPEST, and the specific thing it was added for.
    // A2 task 3a narrowed TryGetRanges to take only the frame, whose AckRanges
    // is a self-contained ReadOnlyMemory slice, which removes the mismatch a
    // *caller* could cause - that was the shape the reviewer's deleted
    // comparison guarded, and it is no longer constructible through the API. It
    // does not remove the mismatch a *peer* can cause. LargestAcknowledged,
    // FirstAckRange and AckRangeCount still come off the wire and still describe
    // a walk over AckRanges, so a frame whose counts say one thing while its
    // range bytes say another is exactly what a hostile sender writes. Rebuilding
    // the frame with its range bytes replaced - by every prefix of themselves,
    // and by a buffer they were never sliced from - is the only way to reach
    // that state, because the reader will never hand the decoder a buffer it did
    // not itself produce.
    private void RunQuicRehostedAckRanges(in TlsQuicFrame frame, ref int budget)
    {
        for (var length = 0; length <= frame.AckRanges.Length && budget > 0; length++, budget--)
        {
            DecodeRehostedAckRanges(frame with { AckRanges = frame.AckRanges[..length] });
        }

        if (budget > 0)
        {
            budget--;
            DecodeRehostedAckRanges(frame with { AckRanges = QuicFrameUnrelatedBuffer });
        }
    }

    private void DecodeRehostedAckRanges(in TlsQuicFrame frame)
    {
        _quicFrameAckRanges.Clear();
        _quicFrameRehostedAckAttemptCount++;
        if (TlsQuicAckFrames.TryGetRanges(frame, _quicFrameAckRanges, out _))
        {
            _quicFrameRehostedAckAcceptCount++;
        }
    }

    // TryReadFrame accepts raw types 0x00-0x1e and, since task C17, RFC 9221's
    // 0x30-0x31. Both blocks have slots; everything else returns -1 and is
    // dropped. The bound therefore still never fires, and it is still here for the
    // reason it always was - so that the NEXT extension frame type shows up as a
    // missing row rather than as an IndexOutOfRangeException from the harness,
    // which would read as a parser defect. C17 is what proved that comment was
    // worth its line: it took a slot map rather than a wider array, because 0x1f
    // to 0x2f are values no reader accepts and seventeen permanently-zero rows in
    // the report would be noise where every other zero row is a finding.
    private static void RecordQuicRawType(long[] counts, ulong rawType)
    {
        var slot = QuicRawFrameTypeSlot(rawType);
        if (slot >= 0 && slot < counts.Length)
        {
            counts[slot]++;
        }
    }

    // Printed once at the end of a run (see Program.cs), null whenever the
    // quic-frames target never ran in this process.
    internal string? DescribeQuicFramesReachability()
    {
        if (_quicFramesInputCount == 0)
        {
            return null;
        }

        List<string> lines =
        [
            $"quic-frames reachability over {_quicFramesInputCount} input(s):",
            "  axis 1 (payload walk) - TlsQuicFrames.TryReadFrame walked over the input itself:",
            $"    frames accepted={_quicFrameWalkAcceptCount}, walks ending in a rejection=" +
            $"{_quicFrameWalkRejectCount}, inputs hitting the {QuicFrameWalkLimit}-frame cap=" +
            $"{_quicFrameWalkLimitHitCount}",
            "    accepts per wire frame type (RFC 9000 s12.4 Table 3):",
        ];
        AppendQuicRawTypeLines(lines, _quicFrameWalkTypeAccepts);

        lines.Add("  axis 1 (family sweep) - family readers called directly at offsets 0, 1 and");
        lines.Add("    input.Length, swept over every raw type in each reader's range:");
        for (var index = 0; index < QuicFrameFamilyParsers.Length; index++)
        {
            lines.Add(FormatQuicReachabilityLine(
                "  " + QuicFrameFamilyParsers[index].Name,
                _quicFrameFamilyParserTrueCounts[index],
                _quicFramesInputCount));
        }

        lines.Add("  axis 2 (re-sliced prefixes) - TryReadFrame re-entered at the same offset over every");
        lines.Add("    truncated prefix of each accepted frame's own extent, same buffer it came from:");
        lines.Add($"    decodes attempted={_quicFrameResliceAttemptCount}, accepted=" +
                  $"{_quicFrameResliceAcceptCount}, inputs hitting the {QuicFrameResliceBudget}-decode " +
                  $"budget={_quicFrameResliceBudgetHitCount}");
        lines.Add("    accepts per wire frame type:");
        AppendQuicRawTypeLines(lines, _quicFrameResliceTypeAccepts);

        // Untyped, deliberately: the decoded type reflects QuicFrameUnrelatedBuffer's
        // own bytes at that offset, not the triggering frame's type, so a per-type
        // row here would misattribute the same way folding this into the prefix
        // sweep's table did before a review caught it. See RunQuicFrameResliceAxis.
        lines.Add("  axis 2 (unrelated buffer) - TryReadFrame re-entered at the same offset against a");
        lines.Add("    fixed buffer the frame never came from, not broken down per type:");
        lines.Add($"    decodes attempted={_quicFrameResliceUnrelatedAttemptCount}, accepted=" +
                  $"{_quicFrameResliceUnrelatedAcceptCount}, skipped (start beyond the " +
                  $"{QuicFrameUnrelatedBuffer.Length}-byte buffer)={_quicFrameResliceUnrelatedSkippedCount}");

        lines.Add("  axis 2 (re-hosted) - TlsQuicAckFrames.TryGetRanges over an accepted ACK frame whose");
        lines.Add("    AckRanges was replaced by a prefix of itself and by a buffer it never came from:");
        lines.Add($"    decodes attempted={_quicFrameRehostedAckAttemptCount}, accepted=" +
                  $"{_quicFrameRehostedAckAcceptCount}");

        lines.Add("  driven by accepted frames:");
        lines.Add($"    TlsQuicAckFrames.TryGetRanges (as parsed): {_quicFrameGetRangesAcceptCount}/" +
                  $"{_quicFrameGetRangesAttemptCount} true");
        lines.Add($"    TlsQuicFrameLegality.Permits: {_quicFrameLegalityPermitCount}/" +
                  $"{_quicFrameLegalityAttemptCount} true");
        lines.Add($"    TlsQuicFrames.WriteFrame re-encode: {_quicFrameReencodeOkCount} ok, " +
                  $"{_quicFrameReencodeThrewCount} threw ArgumentException");

        return string.Join(Environment.NewLine, lines);
    }

    // All thirty-three rows - Table 3's thirty-one wire values plus RFC 9221's two
    // - zeros included. A breakdown that printed only the types it reached could
    // not answer the question the breakdown exists for - "did any CONNECTION_CLOSE
    // ever get here" - because an unreached type would simply be absent and look
    // like an omission rather than a gap. The row is labelled with the raw wire
    // value the slot stands for, not with the slot number, so the report keeps
    // reading as a table of frame types.
    private static void AppendQuicRawTypeLines(List<string> lines, long[] counts)
    {
        for (var slot = 0; slot < counts.Length; slot++)
        {
            var rawType = QuicRawFrameTypeForSlot(slot);
            var name = new TlsQuicFrame { RawType = rawType }.Type.ToString();
            lines.Add($"      0x{rawType:x2} {name,-18}: {counts[slot]}");
        }
    }

    private static void Deframe(byte[] input)
    {
        ProtocolBoundary(() =>
        {
            var deframer = new HandshakeDeframer(maximumMessageSize: 64 * 1024);
            var offset = 0;
            while (offset < input.Length)
            {
                var length = Math.Min(((offset * 13) % 31) + 1, input.Length - offset);
                deframer.Append(input.AsSpan(offset, length));
                while (deframer.TryRead(out _))
                {
                }
                offset += length;
            }
            deframer.EnsureEmptyAtEndOfStream();
        });
    }

    // ========================================================================
    // QPACK (RFC 9204) - the highest-value peer-controlled surface in the
    // QUIC/HTTP-3 stack, and until this target the one with no fuzzing at all.
    //
    // WHAT MAKES A QPACK TARGET VACUOUS, WHICH IS THE WHOLE DESIGN CONSTRAINT.
    // The certificate-compression target offered only zlib, so every brotli and
    // zstd input died at the "unoffered algorithm" gate: a target that appeared
    // to cover three algorithms covered one. QPACK's equivalent gate is s4.5.1's
    // field section prefix. A Required Insert Count the decoder cannot satisfy
    // is blocked or rejected BEFORE any representation is read, and a Base that
    // does not resolve rejects every dynamic reference behind it. A fuzzer fed
    // noise therefore reaches the static-only arm and nothing else: the dynamic,
    // post-base and blocked arms are dead code the campaign never sees and never
    // reports.
    //
    // THE ANSWER IS PER-ARM PROBES, NOT A BIGGER CORPUS. Each of s4.5's seven
    // representations is built here from the input's own bytes behind a prefix
    // this harness constructs to be satisfiable, so every arm is reachable BY
    // CONSTRUCTION, and DescribeQpackReachability prints how often each one
    // actually was reached. An arm reporting zero is a visibly broken target
    // rather than a quietly green one.
    // ========================================================================

    // 4096 makes s3.2.2's MaxEntries = 4096/32 = 128 and s4.5.1.1's FullRange =
    // 256, both far above any Required Insert Count these probes build, so the
    // prefix transform is never the thing that rejects a probe.
    private const int QpackProbeTableMaximumCapacity = 4096;

    // Enough live entries that a fuzz-chosen index has somewhere to land on all
    // three dynamic arms, few enough that an out-of-range index is the common
    // case rather than the rare one.
    private const int QpackProbeTableEntryCount = 4;

    private const int QpackDecodeBufferLength = 8192;
    private const int QpackMaximumFieldLines = 128;

    // RFC 9114 s4.2.2's SETTINGS_MAX_FIELD_SECTION_SIZE, applied to the
    // UNCOMPRESSED size. This is the bound a decompression bomb has to break: a
    // few hundred encoded bytes of Huffman-compressed repeats expand well past
    // it, and an accepted section above it is the finding.
    private const long QpackMaximumFieldSectionSize = 16 * 1024;

    // s3.2.3's SETTINGS_QPACK_BLOCKED_STREAMS. Small on purpose: the interesting
    // arm is the REFUSAL at the advertised bound, and a large value puts that
    // arm out of reach of anything this harness can build.
    private const ulong QpackAdvertisedBlockedStreams = 4;

    private const int QpackProbeScratchLength = 1024;

    // s4.5's seven field line representations: the pattern that selects each
    // one, the width of the integer immediately behind that pattern, and the
    // 'N' (never indexed) bit's own position, which is NOT derivable from the
    // width - s4.5.4's forms spend a bit on 'T' and s4.5.5's does not, so N sits
    // one place higher there. Kind: 0 = index only, 1 = name reference then a
    // value string literal, 2 = a name string literal then a value literal.
    private static readonly (string Name, byte Pattern, int PrefixBits, int Kind,
        bool Dynamic, bool PostBase, byte NeverIndexed)[] QpackRepresentationArms =
    [
        ("s4.5.2 indexed field line, static table  (11xxxxxx)", 0xC0, 6, 0, false, false, 0x00),
        ("s4.5.2 indexed field line, dynamic table (10xxxxxx)", 0x80, 6, 0, true, false, 0x00),
        ("s4.5.3 indexed field line, post-base     (0001xxxx)", 0x10, 4, 0, true, true, 0x00),
        ("s4.5.4 literal, name reference static    (01N1xxxx)", 0x50, 4, 1, false, false, 0x20),
        ("s4.5.4 literal, name reference dynamic   (01N0xxxx)", 0x40, 4, 1, true, false, 0x20),
        ("s4.5.5 literal, post-base name reference (0000Nxxx)", 0x00, 3, 1, true, true, 0x08),
        ("s4.5.6 literal, literal name             (001NHxxx)", 0x20, 4, 2, false, false, 0x10),
    ];

    // s4.3's four encoder stream instructions. Kind: 0 = set capacity, 1 =
    // insert with a name reference, 2 = insert with a literal name, 3 =
    // duplicate. The static/dynamic split on the name reference is a bit inside
    // the pattern, so it is two rows and not one.
    private static readonly (string Name, byte Pattern, int PrefixBits, int Kind)[]
        QpackEncoderInstructionArms =
    [
        ("s4.3.1 set dynamic table capacity   (001xxxxx)", 0x20, 5, 0),
        ("s4.3.2 insert, name ref static      (11xxxxxx)", 0xC0, 6, 1),
        ("s4.3.2 insert, name ref dynamic     (10xxxxxx)", 0x80, 6, 1),
        ("s4.3.3 insert, literal name         (01Hxxxxx)", 0x40, 6, 2),
        ("s4.3.4 duplicate                    (000xxxxx)", 0x00, 5, 3),
    ];

    // s3.2's addressing modes, swept directly. "Absolute" is here and nowhere
    // else: it is the mode the other three resolve into rather than one any
    // representation selects, so no per-representation row can report it.
    private static readonly string[] QpackTableResolvers =
    [
        "s3.2.4 absolute        TryLookupAbsolute",
        "s3.2.5 encoder-relative TryResolveEncoderRelative",
        "s3.2.5 field-relative   TryResolveFieldRelative",
        "s3.2.6 post-base        TryResolvePostBase",
    ];

    private static readonly string[] QpackErrorNames = Enum.GetNames<TlsQuicQpackError>();
    private static readonly string[] QpackEncoderStreamErrorNames =
        Enum.GetNames<TlsQuicQpackEncoderStreamError>();

    private long _qpackInputCount;
    private long _qpackSectionStaticAcceptCount;
    private long _qpackSectionStaticRejectCount;
    private long _qpackSectionTableAcceptCount;
    private long _qpackSectionTableRejectCount;
    private long _qpackSectionTableDynamicAcceptCount;
    private long _qpackSpliceAcceptCount;
    private long _qpackSpliceAttemptCount;
    private long _qpackHuffmanLiteralAcceptCount;
    private long _qpackRawLiteralAcceptCount;
    private long _qpackBlockedProbeCount;
    private long _qpackBlockedHoldCount;
    private long _qpackBlockedLimitRefusalCount;
    private long _qpackIntegerAcceptCount;
    private long _qpackIntegerAttemptCount;
    private long _qpackStringAcceptCount;
    private long _qpackStringAttemptCount;
    private long _qpackHuffmanDecodeAcceptCount;
    private long _qpackHuffmanDecodeAttemptCount;
    private long _qpackDecoderInstructionWriteCount;
    private long _qpackRawEncoderStreamAcceptCount;
    private long _qpackRawEncoderStreamInsertCount;
    private long _qpackMaximumFieldSectionBytes;
    private readonly long[] _qpackResolverTrueCounts = new long[QpackTableResolvers.Length];
    private readonly long[] _qpackArmIntactAccepts = new long[QpackRepresentationArms.Length];
    private readonly long[] _qpackArmMutatedAccepts = new long[QpackRepresentationArms.Length];
    private readonly long[] _qpackInstructionArmAccepts = new long[QpackEncoderInstructionArms.Length];
    private readonly long[] _qpackErrorCounts = new long[QpackErrorNames.Length];
    private readonly long[] _qpackEncoderStreamErrorCounts = new long[QpackEncoderStreamErrorNames.Length];

    // Allocated once. This target decodes twenty-odd field sections per input
    // and the decoder it drives allocates nothing on any path, so the harness
    // must not be the thing that does - the zero-allocation assertions below
    // would otherwise be measuring the harness.
    private readonly byte[] _qpackDecodeBuffer = new byte[QpackDecodeBufferLength];
    private readonly TlsQuicQpackDecodedFieldLine[] _qpackDecodeLines =
        new TlsQuicQpackDecodedFieldLine[QpackMaximumFieldLines];
    private readonly byte[] _qpackProbeScratch = new byte[QpackProbeScratchLength];
    private readonly byte[] _qpackSpliceScratch = new byte[QpackProbeScratchLength];
    private readonly TlsQuicQpackDynamicTable _qpackProbeTable = BuildQpackProbeTable();
    private readonly TlsQuicQpackDynamicTable _qpackInsertTable = BuildQpackProbeTable();
    private readonly TlsQuicQpackDynamicTable _qpackCapacityTable = BuildQpackProbeTable();
    private readonly TlsQuicQpackDynamicTable _qpackWalkTable = BuildQpackWalkTable();

    private readonly TlsQuicQpackBlockedStreams _qpackBlockedStreams =
        new(QpackAdvertisedBlockedStreams);
    private readonly TlsQuicQpackDecoderStream _qpackDecoderStream = new();

    private void RunQpack(byte[] input)
    {
        _qpackInputCount++;
        RunQpackFieldSection(input);
        RunQpackRepresentationArms(input);
        RunQpackTableResolvers(input);
        RunQpackEncoderStream(input);
        RunQpackBlockedDecoding(input);
        RunQpackPrimitives(input);
        RunQpackDecoderInstructions(input);
    }

    // s3.2's four addressing modes called DIRECTLY, the way the QUIC frame
    // target sweeps its family readers. The representation probes above reach
    // all four through the decoder, but only as whichever one their opcode
    // selects, and "absolute" has no representation of its own at all - s3.2.4's
    // addressing is what the other three resolve INTO, so without this row the
    // report could not name it. Both a fuzz-chosen index and a fuzz-chosen Base
    // on the two that take one, since a real Base is wire-derived.
    private void RunQpackTableResolvers(byte[] input)
    {
        var absolute = QpackByte(input, 12) | ((ulong)QpackByte(input, 13) << 8);
        var relative = QpackByte(input, 14) | ((ulong)QpackByte(input, 15) << 8);
        var baseValue = QpackByte(input, 16) | ((ulong)QpackByte(input, 17) << 8);

        var before = GC.GetAllocatedBytesForCurrentThread();
        if (_qpackProbeTable.TryLookupAbsolute(absolute, out _, out _, out _))
        {
            _qpackResolverTrueCounts[0]++;
        }
        if (_qpackProbeTable.TryResolveEncoderRelative(relative, out _, out _))
        {
            _qpackResolverTrueCounts[1]++;
        }
        if (_qpackProbeTable.TryResolveFieldRelative(baseValue, relative, out _, out _))
        {
            _qpackResolverTrueCounts[2]++;
        }
        if (_qpackProbeTable.TryResolvePostBase(baseValue, relative, out _, out _))
        {
            _qpackResolverTrueCounts[3]++;
        }

        // Four lookups against a table that is only read. There is nothing here
        // for either answer to allocate, on any index.
        RequireZeroQpackAllocation(before, "TlsQuicQpackDynamicTable resolvers");

        // Every index that resolves must land inside the live window: at or
        // above the dropping point and below the insertion point. An index that
        // resolved outside it would be a reference to an evicted entry, which
        // s2.2.3 makes a connection error precisely because reading it is a
        // read of memory the table no longer owns.
        if (_qpackProbeTable.TryLookupAbsolute(absolute, out _, out _, out _)
            && (absolute < _qpackProbeTable.DroppedCount
                || absolute >= _qpackProbeTable.InsertCount))
        {
            throw new InvalidOperationException(
                $"Absolute index {absolute} resolved outside the live window " +
                $"[{_qpackProbeTable.DroppedCount}, {_qpackProbeTable.InsertCount}).");
        }
    }

    // Axis 1: the input IS the field section, decoded on both arms - static-only
    // (a null table, what a decoder advertising zero capacity does) and against
    // a live table. Then the same decode over Appendix B's published sections
    // with the input's bytes spliced in, which is the only route by which
    // mutation reaches a dynamic reference from a corpus of noise.
    private void RunQpackFieldSection(byte[] input)
    {
        Span<byte> buffer = _qpackDecodeBuffer;
        Span<TlsQuicQpackDecodedFieldLine> lines = _qpackDecodeLines;

        var before = GC.GetAllocatedBytesForCurrentThread();
        var ok = TlsQuicQpackDecoder.TryDecodeFieldSection(
            input, buffer, lines, QpackMaximumFieldSectionSize,
            out int lineCount, out int bufferUsed, out TlsQuicQpackError error);
        RequireZeroQpackAllocation(before, "TlsQuicQpackDecoder.TryDecodeFieldSection");
        RecordQpackError(error);
        if (ok)
        {
            _qpackSectionStaticAcceptCount++;
            RequireQpackFieldSectionBound(lineCount, bufferUsed);
        }
        else
        {
            _qpackSectionStaticRejectCount++;
        }

        before = GC.GetAllocatedBytesForCurrentThread();
        var tableOk = TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
            input, buffer, lines, QpackMaximumFieldSectionSize, _qpackProbeTable,
            out lineCount, out bufferUsed, out ulong requiredInsertCount, out error);
        RequireZeroQpackAllocation(
            before, "TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable");
        RecordQpackError(error);
        if (tableOk)
        {
            _qpackSectionTableAcceptCount++;
            RequireQpackFieldSectionBound(lineCount, bufferUsed);
            if (requiredInsertCount != 0)
            {
                _qpackSectionTableDynamicAcceptCount++;
            }
        }
        else
        {
            _qpackSectionTableRejectCount++;
        }

        RunQpackSplicedSection(QuicRfcVectors.QpackB2FieldSectionHex, input);
        RunQpackSplicedSection(QuicRfcVectors.QpackB4FieldSectionHex, input);
        RunQpackSplicedSection(QuicRfcVectors.QpackB1FieldSectionHex, input);

        // THE TWO BOUNDS, DRIVEN RATHER THAN ASSUMED. RFC 9114 s4.2.2's limit
        // and the caller's own buffer are the only things standing between a
        // Huffman decompression bomb and unbounded memory, and the first
        // campaign reported both of their rejections as UNREACHED: a section
        // built from at most a few kilobytes of input never grows past a 16 KiB
        // limit, so the guard was never asked to fire. Two more decodes of the
        // same bytes - one with a one-byte size limit, one with a one-byte
        // output buffer - put both back in reach. A limit whose rejection no
        // input can reach is a limit nobody has tested.
        before = GC.GetAllocatedBytesForCurrentThread();
        _ = TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
            input, buffer, lines, 1, _qpackProbeTable, out _, out _, out _, out error);
        RequireZeroQpackAllocation(before, "TryDecodeFieldSectionAgainstTable (size-bounded)");
        RecordQpackError(error);

        before = GC.GetAllocatedBytesForCurrentThread();
        _ = TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
            input, buffer[..1], lines[..1], QpackMaximumFieldSectionSize, _qpackProbeTable,
            out _, out _, out _, out error);
        RequireZeroQpackAllocation(before, "TryDecodeFieldSectionAgainstTable (buffer-bounded)");
        RecordQpackError(error);
    }

    // One published section with a run of the input's bytes overwritten into it
    // from a fuzz-chosen offset. The prefix usually survives, so the section
    // still gets past s4.5.1 and the mutation lands on the representations
    // behind it - the arm a corpus of noise cannot reach.
    private void RunQpackSplicedSection(string vectorHex, byte[] input)
    {
        var vector = Convert.FromHexString(vectorHex);
        vector.CopyTo(_qpackSpliceScratch, 0);
        Span<byte> section = _qpackSpliceScratch.AsSpan(0, vector.Length);

        if (input.Length != 0)
        {
            var start = QpackByte(input, 0) % section.Length;
            for (var index = start; index < section.Length; index++)
            {
                section[index] = QpackByte(input, index - start + 1);
            }
        }

        _qpackSpliceAttemptCount++;
        var before = GC.GetAllocatedBytesForCurrentThread();
        var ok = TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
            section, _qpackDecodeBuffer, _qpackDecodeLines, QpackMaximumFieldSectionSize,
            _qpackProbeTable, out int lineCount, out int bufferUsed, out _,
            out TlsQuicQpackError error);
        RequireZeroQpackAllocation(before, "TryDecodeFieldSectionAgainstTable (spliced)");
        RecordQpackError(error);
        if (ok)
        {
            _qpackSpliceAcceptCount++;
            RequireQpackFieldSectionBound(lineCount, bufferUsed);
        }
    }

    // Axis 2: one probe per s4.5 representation, built from the input's own
    // bytes behind a prefix this harness constructs to be satisfiable, then the
    // same probe again with one fuzz-chosen byte disturbed.
    //
    // THE INTACT COUNT AND THE MUTATED COUNT ANSWER DIFFERENT QUESTIONS. The
    // intact one is "is this arm alive at all" - it is reachable by
    // construction, so anything below the input count means the construction
    // stopped working. The mutated one is "does the campaign explore it", and
    // it is the one that varies.
    //
    // THE MUTATION NEVER CHANGES WHICH ARM IS SELECTED. A flip in the opcode's
    // own pattern bits would turn one arm's probe into another arm's and this
    // table would misattribute exactly the way a per-type breakdown of an
    // unrelated buffer did before a review caught it, so a mutation landing on
    // the first octet is masked into that representation's index prefix.
    private void RunQpackRepresentationArms(byte[] input)
    {
        var live = _qpackProbeTable.InsertCount - _qpackProbeTable.DroppedCount;
        for (var index = 0; index < QpackRepresentationArms.Length; index++)
        {
            var arm = QpackRepresentationArms[index];

            // Post-base needs a Base below the Required Insert Count so the
            // representation's index counts UP from it; the field-relative arms
            // need Base at the insertion point so it counts DOWN. The static
            // arms need neither and take the zero/zero prefix a decoder with no
            // table sends.
            var required = arm.Dynamic ? _qpackProbeTable.InsertCount : 0;
            var baseValue = arm.PostBase ? _qpackProbeTable.DroppedCount : required;

            ulong resolvable = 0;
            if (arm.Dynamic)
            {
                resolvable = live == 0 ? 0 : QpackByte(input, index) % live;
            }
            else if (arm.Kind != 2)
            {
                // s3.1's static table is 99 entries; every index below that
                // resolves, which is what makes this half the reachable one.
                resolvable = (ulong)(QpackByte(input, index) % TlsQuicQpackStaticTable.Count);
            }

            if (!TryBuildQpackRepresentation(
                    input, arm, required, baseValue, resolvable,
                    out int prefixLength, out int length, out bool huffman))
            {
                continue;
            }

            if (DecodeQpackProbe(length, arm.Kind != 0, huffman))
            {
                _qpackArmIntactAccepts[index]++;
            }

            var body = length - prefixLength;
            if (body <= 0)
            {
                continue;
            }
            var offset = prefixLength + QpackByte(input, index + 48) % body;
            var original = _qpackProbeScratch[offset];
            var disturbance = QpackByte(input, index + 56);
            _qpackProbeScratch[offset] = offset == prefixLength
                ? (byte)(original & ~QpackPrefixMask(arm.PrefixBits)
                    | disturbance & QpackPrefixMask(arm.PrefixBits))
                : disturbance;
            if (DecodeQpackProbe(length, arm.Kind != 0, huffman))
            {
                _qpackArmMutatedAccepts[index]++;
            }
            _qpackProbeScratch[offset] = original;
        }
    }

    private static byte QpackPrefixMask(int prefixBits) => (byte)((1 << prefixBits) - 1);

    private bool TryBuildQpackRepresentation(
        byte[] input,
        (string Name, byte Pattern, int PrefixBits, int Kind, bool Dynamic, bool PostBase,
            byte NeverIndexed) arm,
        ulong requiredInsertCount,
        ulong baseValue,
        ulong index,
        out int prefixLength,
        out int length,
        out bool huffman)
    {
        length = 0;
        huffman = false;
        Span<byte> destination = _qpackProbeScratch;
        prefixLength = WriteQpackFieldSectionPrefix(requiredInsertCount, baseValue, destination);
        if (prefixLength == 0)
        {
            return false;
        }

        // s4.5.4's and s4.5.5's 'N' bit - a bit a peer chooses and nothing on
        // this side reads - driven from the input rather than pinned to zero.
        var pattern = (byte)(arm.Pattern | ((QpackByte(input, 24) & 1) != 0 ? arm.NeverIndexed : 0));
        var nameHuffman = (QpackByte(input, 25) & 1) != 0;
        var valueHuffman = (QpackByte(input, 26) & 1) != 0;

        var written = prefixLength;
        if (arm.Kind == 2)
        {
            if (!TryWriteQpackString(
                    QpackLiteralSlice(input, 0), arm.PrefixBits, pattern, nameHuffman,
                    destination[written..], out int nameLength))
            {
                return false;
            }
            written += nameLength;
            huffman |= nameHuffman;
        }
        else
        {
            if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                    index, arm.PrefixBits, pattern, destination[written..], out int indexLength))
            {
                return false;
            }
            written += indexLength;
        }

        if (arm.Kind != 0)
        {
            if (!TryWriteQpackString(
                    QpackLiteralSlice(input, 1), 8, 0, valueHuffman,
                    destination[written..], out int valueLength))
            {
                return false;
            }
            written += valueLength;
            huffman |= valueHuffman;
        }

        length = written;
        return true;
    }

    private bool DecodeQpackProbe(int length, bool literal, bool huffman)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        var ok = TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
            _qpackProbeScratch.AsSpan(0, length), _qpackDecodeBuffer, _qpackDecodeLines,
            QpackMaximumFieldSectionSize, _qpackProbeTable,
            out int lineCount, out int bufferUsed, out _, out TlsQuicQpackError error);
        RequireZeroQpackAllocation(before, "TryDecodeFieldSectionAgainstTable (arm probe)");
        RecordQpackError(error);
        if (!ok)
        {
            return false;
        }

        RequireQpackFieldSectionBound(lineCount, bufferUsed);
        if (!literal)
        {
            return true;
        }

        // Which of s4.1.2's two string encodings was decoded is known without
        // re-reading the wire, because this harness is the thing that wrote it.
        if (huffman)
        {
            _qpackHuffmanLiteralAcceptCount++;
        }
        else
        {
            _qpackRawLiteralAcceptCount++;
        }
        return true;
    }

    // Axis 3: s4.3's encoder stream. One probe per instruction, each built from
    // the input and each judged by WHAT IT DID TO THE TABLE rather than by its
    // return value - a Set Dynamic Table Capacity that parsed but changed no
    // capacity has not reached the arm its row claims. Then the raw input as an
    // encoder stream, which is the shape a real connection sees.
    private void RunQpackEncoderStream(byte[] input)
    {
        for (var index = 0; index < QpackEncoderInstructionArms.Length; index++)
        {
            var arm = QpackEncoderInstructionArms[index];
            var table = arm.Kind == 0 ? _qpackCapacityTable : _qpackInsertTable;
            if (TryBuildQpackInstruction(input, arm, table, out int length)
                && ApplyQpackInstruction(table, length, arm.Kind))
            {
                _qpackInstructionArmAccepts[index]++;
            }
            RequireQpackTableBound(table);
        }

        var before = GC.GetAllocatedBytesForCurrentThread();
        var insertsBefore = _qpackWalkTable.InsertCount;
        var ok = _qpackWalkTable.TryReadEncoderInstructions(
            input, out int consumed, out TlsQuicQpackEncoderStreamError error);
        if (!ok && _qpackWalkTable.InsertCount == insertsBefore)
        {
            // "The rejecting path allocates zero" needs both halves of its
            // subject named, and the first campaign is what pinned down which.
            //
            // s4.3 IS A STREAM AND A BATCH IS NOT TRANSACTIONAL. A run of
            // instructions is applied one at a time, so a Duplicate that
            // succeeded and a Duplicate that ran off the end four bytes later
            // return one `false` between them - and the entry the first one
            // stored is a real, correct allocation sitting on a call that
            // answered "rejected". The first mutation campaign found exactly
            // that (80 bytes: an Entry and its two arrays) and it is not a
            // defect. What the rule actually forbids is allocating for an entry
            // that was never stored, so the Insert Count is the subject and the
            // return value is not.
            RequireZeroQpackAllocation(before, "TryReadEncoderInstructions (stored nothing)");
        }
        RecordQpackEncoderStreamError(error);
        if (ok)
        {
            _qpackRawEncoderStreamAcceptCount++;
            if (_qpackWalkTable.InsertCount != insertsBefore)
            {
                _qpackRawEncoderStreamInsertCount++;
            }
        }
        if (consumed > input.Length)
        {
            throw new InvalidOperationException(
                $"TryReadEncoderInstructions consumed {consumed} of {input.Length} bytes.");
        }
        RequireQpackTableBound(_qpackWalkTable);
    }

    private bool TryBuildQpackInstruction(
        byte[] input,
        (string Name, byte Pattern, int PrefixBits, int Kind) arm,
        TlsQuicQpackDynamicTable table,
        out int length)
    {
        length = 0;
        Span<byte> destination = _qpackProbeScratch;
        var live = table.InsertCount - table.DroppedCount;

        // A dynamic name reference and a Duplicate both address entries
        // relative to the insertion point, so with nothing live there is no
        // index either can carry and the arm is genuinely unreachable - which is
        // reported as a zero rather than papered over with index 0.
        if (live == 0 && arm.Kind is 3 || live == 0 && arm.Kind == 1 && arm.Pattern == 0x80)
        {
            return false;
        }

        // Clamped for the same reason the representation probes are: an arm
        // whose only probe carries an out-of-range index is an arm this report
        // can only ever show as unreachable.
        ulong value = arm.Kind switch
        {
            0 => (ulong)(QpackByte(input, 3) % (QpackProbeTableMaximumCapacity + 1)),
            1 when arm.Pattern == 0xC0 =>
                (ulong)(QpackByte(input, 4) % TlsQuicQpackStaticTable.Count),
            1 => QpackByte(input, 5) % live,
            3 => QpackByte(input, 6) % live,
            _ => 0,
        };

        int written;
        if (arm.Kind == 2)
        {
            if (!TryWriteQpackString(
                    QpackLiteralSlice(input, 2), arm.PrefixBits, arm.Pattern,
                    (QpackByte(input, 27) & 1) != 0, destination, out written))
            {
                return false;
            }
        }
        else if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                     value, arm.PrefixBits, arm.Pattern, destination, out written))
        {
            return false;
        }

        if (arm.Kind is 1 or 2)
        {
            if (!TryWriteQpackString(
                    QpackLiteralSlice(input, 3), 8, 0,
                    (QpackByte(input, 28) & 1) != 0, destination[written..], out int valueLength))
            {
                return false;
            }
            written += valueLength;
        }

        length = written;
        return true;
    }

    private bool ApplyQpackInstruction(TlsQuicQpackDynamicTable table, int length, int kind)
    {
        var capacityBefore = table.Capacity;
        var insertsBefore = table.InsertCount;
        var before = GC.GetAllocatedBytesForCurrentThread();
        var ok = table.TryReadEncoderInstructions(
            _qpackProbeScratch.AsSpan(0, length), out int consumed,
            out TlsQuicQpackEncoderStreamError error);
        if (!ok && table.InsertCount == insertsBefore)
        {
            RequireZeroQpackAllocation(before, "TryReadEncoderInstructions (probe stored nothing)");
        }
        RecordQpackEncoderStreamError(error);
        if (!ok || consumed != length)
        {
            return false;
        }

        // The witness is the state change, not the return value. s4.3.1's
        // capacity instruction may legally set the capacity the table already
        // had, and that case is deliberately not counted - it is
        // indistinguishable from an instruction that did nothing.
        return kind == 0
            ? table.Capacity != capacityBefore
            : table.InsertCount != insertsBefore;
    }

    // Axis 4: s2.2.1's block and s2.1.2's bound. A section declaring a Required
    // Insert Count above the table's Insert Count must be reported as Blocked -
    // not rejected, which would close the connection on ordinary QUIC
    // reordering - and the number of streams parked that way must never exceed
    // the SETTINGS_QPACK_BLOCKED_STREAMS this decoder advertised.
    private void RunQpackBlockedDecoding(byte[] input)
    {
        // Above the Insert Count and below s4.5.1.1's MaxValue = InsertCount +
        // MaxEntries(128), so the prefix reconstructs and the answer that
        // follows is s2.2.1's block and not an unencodable count.
        var required = _qpackProbeTable.InsertCount + 1 + QpackByte(input, 7) % 64u;
        Span<byte> destination = _qpackProbeScratch;
        var prefix = WriteQpackFieldSectionPrefix(required, _qpackProbeTable.InsertCount, destination);
        if (prefix != 0
            && TlsQuicQpackPrimitives.TryEncodeInteger(
                0, 6, 0xC0, destination[prefix..], out int representation))
        {
            var before = GC.GetAllocatedBytesForCurrentThread();
            _ = TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
                _qpackProbeScratch.AsSpan(0, prefix + representation), _qpackDecodeBuffer,
                _qpackDecodeLines, QpackMaximumFieldSectionSize, _qpackProbeTable,
                out _, out _, out ulong reported, out TlsQuicQpackError error);
            RequireZeroQpackAllocation(before, "TryDecodeFieldSectionAgainstTable (blocked)");
            RecordQpackError(error);
            if (error == TlsQuicQpackError.Blocked)
            {
                _qpackBlockedProbeCount++;
                if (_qpackBlockedStreams.TryHold(reported, reported, out _))
                {
                    _qpackBlockedHoldCount++;
                }
                _qpackBlockedStreams.Release(reported);
            }
        }

        // One past the advertised bound, on ids the input chooses, so both the
        // hold and s2.1.2's refusal are driven rather than staged. Ids that
        // collide simply re-hold, which is why the refusal count varies.
        var holds = (int)QpackAdvertisedBlockedStreams + 1;
        for (var index = 0; index < holds; index++)
        {
            var streamId = QpackByte(input, 32 + index) | ((ulong)index << 8);
            if (_qpackBlockedStreams.TryHold(streamId, required, out TlsQuicQpackError error))
            {
                if (!_qpackBlockedStreams.IsHeld(streamId, out _))
                {
                    throw new InvalidOperationException(
                        $"TlsQuicQpackBlockedStreams held stream {streamId} but does not " +
                        "report it as held.");
                }
            }
            else if (error == TlsQuicQpackError.BlockedStreamLimitExceeded)
            {
                _qpackBlockedLimitRefusalCount++;
            }
        }

        if ((ulong)_qpackBlockedStreams.Count > QpackAdvertisedBlockedStreams)
        {
            throw new InvalidOperationException(
                $"{_qpackBlockedStreams.Count} streams are blocked, above the advertised " +
                $"{QpackAdvertisedBlockedStreams} of SETTINGS_QPACK_BLOCKED_STREAMS.");
        }

        for (var index = 0; index < holds; index++)
        {
            _qpackBlockedStreams.Release(QpackByte(input, 32 + index) | ((ulong)index << 8));
        }
        if (_qpackBlockedStreams.Count != 0)
        {
            throw new InvalidOperationException(
                $"{_qpackBlockedStreams.Count} stream(s) stayed blocked after every hold was " +
                "released.");
        }
    }

    // Axis 5: s4.1's primitives on their own, at every legal prefix width. The
    // field section arms above only ever reach the widths s4.5 happens to use;
    // s5.1's named attack - "a large number of zero values ... could be used to
    // overflow integer values" - lives at the widths they do not.
    private void RunQpackPrimitives(byte[] input)
    {
        for (var prefixBits = TlsQuicQpackPrimitives.MinimumIntegerPrefixBits;
             prefixBits <= TlsQuicQpackPrimitives.MaximumPrefixBits;
             prefixBits++)
        {
            _qpackIntegerAttemptCount++;
            var before = GC.GetAllocatedBytesForCurrentThread();
            var ok = TlsQuicQpackPrimitives.TryDecodeInteger(
                input, prefixBits, out ulong value, out int consumed,
                out TlsQuicQpackError error);
            RequireZeroQpackAllocation(before, "TlsQuicQpackPrimitives.TryDecodeInteger");
            RecordQpackError(error);
            if (!ok)
            {
                continue;
            }
            _qpackIntegerAcceptCount++;
            if (value > TlsQuicQpackPrimitives.MaximumInteger)
            {
                throw new InvalidOperationException(
                    $"TryDecodeInteger returned {value}, above RFC 9204 s4.1.1's " +
                    $"{TlsQuicQpackPrimitives.MaximumInteger}.");
            }
            if (consumed > input.Length)
            {
                throw new InvalidOperationException(
                    $"TryDecodeInteger consumed {consumed} of {input.Length} bytes.");
            }
        }

        for (var prefixBits = TlsQuicQpackPrimitives.MinimumStringPrefixBits;
             prefixBits <= TlsQuicQpackPrimitives.MaximumPrefixBits;
             prefixBits++)
        {
            _qpackStringAttemptCount++;
            var before = GC.GetAllocatedBytesForCurrentThread();
            var ok = TlsQuicQpackPrimitives.TryDecodeStringLiteral(
                input, prefixBits, out bool huffman, out ReadOnlySpan<byte> data,
                out int consumed, out TlsQuicQpackError error);
            RequireZeroQpackAllocation(before, "TlsQuicQpackPrimitives.TryDecodeStringLiteral");
            RecordQpackError(error);
            if (!ok)
            {
                continue;
            }
            _qpackStringAcceptCount++;
            if (consumed > input.Length || data.Length > input.Length)
            {
                throw new InvalidOperationException(
                    $"TryDecodeStringLiteral reported {consumed} consumed and {data.Length} " +
                    $"data byte(s) out of {input.Length}.");
            }
            if (!huffman)
            {
                continue;
            }

            // s7.3's memory bound restated as an assertion: a Huffman string can
            // expand, but never past what GetMaximumDecodedLength computes from
            // the five-bit minimum code length. A decode writing past it is the
            // unbounded allocation this campaign is looking for.
            var capacity = TlsQuicQpackHuffman.GetMaximumDecodedLength(data.Length);
            if (capacity > _qpackDecodeBuffer.Length)
            {
                continue;
            }
            _qpackHuffmanDecodeAttemptCount++;
            before = GC.GetAllocatedBytesForCurrentThread();
            var decoded = TlsQuicQpackHuffman.TryDecode(
                data, _qpackDecodeBuffer.AsSpan(0, capacity), out int written, out error);
            RequireZeroQpackAllocation(before, "TlsQuicQpackHuffman.TryDecode");
            RecordQpackError(error);
            if (!decoded)
            {
                continue;
            }
            _qpackHuffmanDecodeAcceptCount++;
            if (written > capacity)
            {
                throw new InvalidOperationException(
                    $"Huffman decode wrote {written} bytes into a {capacity}-byte bound.");
            }
        }
    }

    // Axis 6: s4.4's three decoder instructions. We WRITE these, so the input
    // drives the numbers rather than the bytes; what is being fuzzed is that a
    // peer-derived stream id or insert count cannot overrun the fixed-length
    // buffer every caller hands this class.
    private void RunQpackDecoderInstructions(byte[] input)
    {
        Span<byte> destination = _qpackProbeScratch.AsSpan(
            0, TlsQuicQpackDecoderStream.MaximumInstructionLength);
        var streamId = QpackByte(input, 40) | ((ulong)QpackByte(input, 41) << 8);

        if (_qpackDecoderStream.TryWriteSectionAcknowledgment(
                streamId, QpackByte(input, 42), destination, out int written)
            && written != 0)
        {
            _qpackDecoderInstructionWriteCount++;
        }
        RequireQpackInstructionBound(written, destination.Length);

        if (_qpackDecoderStream.TryWriteStreamCancellation(streamId, destination, out written)
            && written != 0)
        {
            _qpackDecoderInstructionWriteCount++;
        }
        RequireQpackInstructionBound(written, destination.Length);

        if (_qpackDecoderStream.TryWriteInsertCountIncrement(
                _qpackDecoderStream.KnownReceivedCount + QpackByte(input, 43), destination,
                out written)
            && written != 0)
        {
            _qpackDecoderInstructionWriteCount++;
        }
        RequireQpackInstructionBound(written, destination.Length);
    }

    private static void RequireQpackInstructionBound(int written, int capacity)
    {
        if (written > capacity)
        {
            throw new InvalidOperationException(
                $"A QPACK decoder instruction reported {written} bytes written into " +
                $"{capacity}.");
        }
    }

    private static byte QpackByte(byte[] input, int index) =>
        input.Length == 0 ? (byte)0 : input[index % input.Length];

    // A short run of the input used as a literal name or value. Bounded at 32
    // because the probe has to fit the scratch buffer beside its prefix, and
    // because a longer literal explores nothing a shorter one does not - it is
    // the declared LENGTH the decoder parses, and that is driven separately by
    // the mutation in RunQpackRepresentationArms.
    private static ReadOnlySpan<byte> QpackLiteralSlice(byte[] input, int slot)
    {
        if (input.Length == 0)
        {
            return default;
        }
        var start = slot * 7 % input.Length;
        return input.AsSpan(start, Math.Min(32, input.Length - start));
    }

    private static bool TryWriteQpackString(
        ReadOnlySpan<byte> value, int prefixBits, byte pattern, bool huffman,
        Span<byte> destination, out int written)
    {
        written = 0;

        // s4.1.2's H bit is the top bit of the string's own prefix field, so it
        // is folded into the pattern the length integer is written behind rather
        // than stamped on afterwards.
        if (!huffman)
        {
            if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                    (ulong)value.Length, prefixBits - 1, pattern, destination, out int header))
            {
                return false;
            }
            if (destination.Length - header < value.Length)
            {
                return false;
            }
            value.CopyTo(destination[header..]);
            written = header + value.Length;
            return true;
        }

        var huffmanFlag = (byte)(1 << prefixBits - 1);
        var encodedLength = TlsQuicQpackHuffman.GetEncodedLength(value);
        if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                (ulong)encodedLength, prefixBits - 1, (byte)(pattern | huffmanFlag),
                destination, out int huffmanHeader))
        {
            return false;
        }
        if (!TlsQuicQpackHuffman.TryEncode(value, destination[huffmanHeader..], out int body))
        {
            return false;
        }
        written = huffmanHeader + body;
        return true;
    }

    // s4.5.1.1's transform, encoder side: an Insert Count of zero stays zero and
    // anything else is taken modulo 2*MaxEntries and incremented, which is the
    // only form the decoder's reconstruction accepts. s4.5.1.2's Delta Base
    // carries its sign in the top bit.
    private static int WriteQpackFieldSectionPrefix(
        ulong requiredInsertCount, ulong baseValue, Span<byte> destination)
    {
        var maxEntries =
            (ulong)QpackProbeTableMaximumCapacity / TlsQuicQpackDynamicTable.EntrySizeOverhead;
        var encoded = requiredInsertCount == 0
            ? 0
            : requiredInsertCount % (2 * maxEntries) + 1;
        if (!TlsQuicQpackPrimitives.TryEncodeInteger(encoded, 8, 0, destination, out int written))
        {
            return 0;
        }

        var sign = baseValue >= requiredInsertCount ? (byte)0x00 : (byte)0x80;
        var delta = baseValue >= requiredInsertCount
            ? baseValue - requiredInsertCount
            : requiredInsertCount - baseValue - 1;
        return TlsQuicQpackPrimitives.TryEncodeInteger(
            delta, 7, sign, destination[written..], out int deltaWritten)
            ? written + deltaWritten
            : 0;
    }

    private void RecordQpackError(TlsQuicQpackError error) => _qpackErrorCounts[(int)error]++;

    private void RecordQpackEncoderStreamError(TlsQuicQpackEncoderStreamError error) =>
        _qpackEncoderStreamErrorCounts[(int)error]++;

    private void RequireQpackFieldSectionBound(int lineCount, int bufferUsed)
    {
        if (bufferUsed > _qpackDecodeBuffer.Length || lineCount > _qpackDecodeLines.Length)
        {
            throw new InvalidOperationException(
                $"An accepted field section reported {lineCount} line(s) and {bufferUsed} " +
                $"byte(s), past the {_qpackDecodeLines.Length}/{_qpackDecodeBuffer.Length} " +
                "buffers it was given.");
        }

        // RFC 9114 s4.2.2 applies the limit to the uncompressed size plus 32 per
        // field. An accepted section above it is a decompression bomb the
        // decoder let through - the unbounded allocation this campaign exists
        // to find.
        var size = bufferUsed + lineCount * 32L;
        if (size > QpackMaximumFieldSectionSize)
        {
            throw new InvalidOperationException(
                $"An accepted field section measures {size} bytes against RFC 9114 s4.2.2's " +
                $"advertised {QpackMaximumFieldSectionSize}.");
        }
        if (size > _qpackMaximumFieldSectionBytes)
        {
            _qpackMaximumFieldSectionBytes = size;
        }
    }

    private static void RequireQpackTableBound(TlsQuicQpackDynamicTable table)
    {
        if (table.Capacity > table.MaximumCapacity)
        {
            throw new InvalidOperationException(
                $"The dynamic table capacity is {table.Capacity}, above the advertised " +
                $"SETTINGS_QPACK_MAX_TABLE_CAPACITY of {table.MaximumCapacity}.");
        }
        if (table.Size > table.Capacity)
        {
            throw new InvalidOperationException(
                $"The dynamic table holds {table.Size} byte(s) in a {table.Capacity}-byte " +
                "capacity.");
        }
        if (table.DroppedCount > table.InsertCount)
        {
            throw new InvalidOperationException(
                $"The dynamic table dropped {table.DroppedCount} of {table.InsertCount} " +
                "insertion(s).");
        }
    }

    private static void RequireZeroQpackAllocation(long before, string what)
    {
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        if (allocated != 0)
        {
            throw new InvalidOperationException(
                $"{what} allocated {allocated} byte(s) on a path the QPACK decoder documents " +
                "as allocating nothing.");
        }
    }

    // WHY THIS EXISTS, AND WHAT THE FIRST RUN OF THIS TARGET FOUND.
    //
    // "The rejecting path allocates zero" is a permanent rule here, and the very
    // first mutation campaign reported 80 bytes on a REJECTED encoder stream.
    // It is not a defect: TlsQuicQpackDynamicTable keeps two Huffman scratch
    // buffers "grown on demand, never shrunk", so its own comment scopes the
    // promise to "allocation-free IN STEADY STATE" and its unit test measures a
    // table that has already reached that state. A fuzzer starts every table
    // cold and can present a larger literal at any time, so the growth shows up
    // as an allocation on a rejection and the assertion fires on correct code.
    //
    // The fix is to reach steady state before measuring anything, not to weaken
    // the assertion to a threshold. Two instructions do it: one whose NAME is a
    // Huffman literal as long as any input this harness accepts, and one whose
    // name is valid and whose VALUE is that same length - s4.3.3 carries two
    // literals and they use two separate buffers. Both are refused (their
    // payload is all-ones, which is RFC 7541 s5.2's EOS symbol), so neither
    // changes the table; both grow the buffer to its ceiling on the way. After
    // this, every rejection for the rest of the process allocates exactly zero
    // and the assertion means what it says.
    private static void WarmQpackHuffmanScratch(TlsQuicQpackDynamicTable table)
    {
        // The scratch is sized from the DECLARED length of a literal the peer
        // already had to send the bytes of, so MaximumInputLength bounds it -
        // no input this runner accepts can ask for more.
        var payload = MaximumInputLength - 16;
        var name = new byte[payload + 8];
        if (!TlsQuicQpackPrimitives.TryEncodeInteger((ulong)payload, 5, 0x60, name, out int header))
        {
            throw new InvalidOperationException("The Huffman warm-up name did not encode.");
        }
        name.AsSpan(header, payload).Fill(0xFF);
        if (table.TryReadEncoderInstructions(
                name.AsSpan(0, header + payload), out _, out var nameError))
        {
            throw new InvalidOperationException(
                $"The Huffman warm-up name was accepted rather than refused ({nameError}).");
        }

        var value = new byte[payload + 16];
        var written = 0;
        if (!TlsQuicQpackHuffman.TryEncode("a"u8, value.AsSpan(1), out int nameBody))
        {
            throw new InvalidOperationException("The Huffman warm-up literal name did not encode.");
        }
        if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                (ulong)nameBody, 5, 0x60, value, out int nameHeader)
            || nameHeader != 1)
        {
            throw new InvalidOperationException("The Huffman warm-up name header did not encode.");
        }
        written = nameHeader + nameBody;
        if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                (ulong)payload, 7, 0x80, value.AsSpan(written), out int valueHeader))
        {
            throw new InvalidOperationException("The Huffman warm-up value did not encode.");
        }
        written += valueHeader;
        value.AsSpan(written, payload).Fill(0xFF);
        if (table.TryReadEncoderInstructions(
                value.AsSpan(0, written + payload), out _, out var valueError))
        {
            throw new InvalidOperationException(
                $"The Huffman warm-up value was accepted rather than refused ({valueError}).");
        }
    }

    private static TlsQuicQpackDynamicTable BuildQpackProbeTable()
    {
        var table = new TlsQuicQpackDynamicTable(QpackProbeTableMaximumCapacity);
        var instructions = new List<byte>();
        var scratch = new byte[64];

        if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                QpackProbeTableMaximumCapacity, 5, 0x20, scratch, out int capacityLength))
        {
            throw new InvalidOperationException("The probe table's capacity did not encode.");
        }
        instructions.AddRange(scratch[..capacityLength]);

        // ABSOLUTE INDEX 0 IS ':status: 200' AND THAT IS NOT DECORATION. The
        // first campaign reported RFC 9204 s4.4.1's section acknowledgment as
        // unreached, because an acknowledgment is only emitted for a section
        // whose Required Insert Count is non-zero - which means the HTTP/3
        // response state machine has to decode a DYNAMIC reference, which in
        // turn has to produce a usable ':status' or s4.1 rejects the message
        // before any acknowledgment is queued. One dynamic entry carrying a real
        // status is what puts that arm back in reach; see Http3Scripts' dynamic
        // response.
        //
        // The name index is looked up rather than written as a number: RFC 9204
        // Appendix A's ordering is not something to transcribe from memory.
        if (!TlsQuicQpackStaticTable.TryFindName(":status"u8, out int statusNameIndex)
            || !TlsQuicQpackPrimitives.TryEncodeInteger(
                (ulong)statusNameIndex, 6, 0xC0, scratch, out int statusLength))
        {
            throw new InvalidOperationException("The probe table's ':status' entry did not encode.");
        }
        instructions.AddRange(scratch[..statusLength]);
        instructions.Add(0x03);
        instructions.AddRange("200"u8);

        // s4.3.2 Insert With Name Reference against static indices 0..2, each
        // with a distinct one-byte value so the entries are distinguishable and
        // none is anywhere near large enough to evict another.
        for (var index = 0; index < QpackProbeTableEntryCount - 1; index++)
        {
            if (!TlsQuicQpackPrimitives.TryEncodeInteger(
                    (ulong)index, 6, 0xC0, scratch, out int headerLength))
            {
                throw new InvalidOperationException("A probe table insert did not encode.");
            }
            instructions.AddRange(scratch[..headerLength]);
            instructions.Add(0x01);
            instructions.Add((byte)('a' + index));
        }

        var encoded = instructions.ToArray();
        if (!table.TryReadEncoderInstructions(encoded, out int consumed, out var error)
            || consumed != encoded.Length
            || table.InsertCount != QpackProbeTableEntryCount)
        {
            throw new InvalidOperationException(
                $"The QPACK probe table did not build: consumed={consumed} of {encoded.Length}, " +
                $"inserts={table.InsertCount}, error={error}.");
        }
        WarmQpackHuffmanScratch(table);
        return table;
    }

    // The table the raw input is replayed against as an encoder stream. It gets
    // a capacity up front - at zero, s3.2.2 makes every insert an error and the
    // whole s4.3 walk would only ever reach one arm - and the same warm-up.
    private static TlsQuicQpackDynamicTable BuildQpackWalkTable()
    {
        var table = new TlsQuicQpackDynamicTable(QpackProbeTableMaximumCapacity);
        if (!table.TrySetCapacity(QpackProbeTableMaximumCapacity, out var error))
        {
            throw new InvalidOperationException(
                $"The QPACK walk table did not take its capacity: {error}.");
        }
        WarmQpackHuffmanScratch(table);
        return table;
    }

    internal string? DescribeQpackReachability()
    {
        if (_qpackInputCount == 0)
        {
            return null;
        }

        List<string> lines =
        [
            $"qpack reachability over {_qpackInputCount} input(s):",
            "  axis 1 (the whole input as a field section) - RFC 9204 s4.5:",
            $"    static-only arm (null table): accepted={_qpackSectionStaticAcceptCount}, " +
            $"rejected={_qpackSectionStaticRejectCount}",
            $"    dynamic arm (live table): accepted={_qpackSectionTableAcceptCount}, " +
            $"rejected={_qpackSectionTableRejectCount}, of which with a non-zero Required " +
            $"Insert Count={_qpackSectionTableDynamicAcceptCount}",
            "    Appendix B sections with input bytes spliced in: accepted=" +
            $"{_qpackSpliceAcceptCount}/{_qpackSpliceAttemptCount}",
            "  axis 2 (one probe per s4.5 representation) - intact / one disturbed byte, each",
            "    behind a prefix built to be satisfiable so the arm is reachable by",
            "    construction:",
        ];
        for (var index = 0; index < QpackRepresentationArms.Length; index++)
        {
            lines.Add(
                $"    {QpackRepresentationArms[index].Name}: " +
                $"intact={_qpackArmIntactAccepts[index]}/{_qpackInputCount}, " +
                $"mutated={_qpackArmMutatedAccepts[index]}");
        }
        lines.Add(
            $"    literal encodings decoded: huffman={_qpackHuffmanLiteralAcceptCount}, " +
            $"raw={_qpackRawLiteralAcceptCount}");

        lines.Add("  axis 2 (s3.2 addressing, resolvers called directly on fuzz-chosen indices");
        lines.Add("    and a fuzz-chosen Base):");
        for (var index = 0; index < QpackTableResolvers.Length; index++)
        {
            lines.Add(
                $"    {QpackTableResolvers[index]}: " +
                $"{_qpackResolverTrueCounts[index]}/{_qpackInputCount} true");
        }

        lines.Add("  axis 3 (s4.3 encoder stream) - per instruction, counted by the table state");
        lines.Add("    change it produced and not by its return value:");
        for (var index = 0; index < QpackEncoderInstructionArms.Length; index++)
        {
            lines.Add(
                $"    {QpackEncoderInstructionArms[index].Name}: " +
                $"{_qpackInstructionArmAccepts[index]}/{_qpackInputCount}");
        }
        lines.Add(
            "    whole input as an encoder stream: accepted=" +
            $"{_qpackRawEncoderStreamAcceptCount}, of which inserted=" +
            $"{_qpackRawEncoderStreamInsertCount}");

        lines.Add("  axis 4 (s2.2.1 blocked decoding, s2.1.2's bound):");
        lines.Add(
            $"    sections reported Blocked={_qpackBlockedProbeCount}, streams parked=" +
            $"{_qpackBlockedHoldCount}, refusals at the advertised " +
            $"{QpackAdvertisedBlockedStreams}={_qpackBlockedLimitRefusalCount}");

        lines.Add("  axis 5 (s4.1 primitives, every legal prefix width):");
        lines.Add(
            $"    TryDecodeInteger: {_qpackIntegerAcceptCount}/{_qpackIntegerAttemptCount} true");
        lines.Add(
            "    TryDecodeStringLiteral: " +
            $"{_qpackStringAcceptCount}/{_qpackStringAttemptCount} true");
        lines.Add(
            "    TlsQuicQpackHuffman.TryDecode: " +
            $"{_qpackHuffmanDecodeAcceptCount}/{_qpackHuffmanDecodeAttemptCount} true");
        lines.Add(
            "  axis 6 (s4.4 decoder instructions written): " +
            $"{_qpackDecoderInstructionWriteCount}");
        lines.Add(
            $"  largest accepted field section: {_qpackMaximumFieldSectionBytes} bytes against " +
            $"the advertised {QpackMaximumFieldSectionSize}");

        lines.Add("  rejection reasons reached (s4.1/s4.5, zeros included):");
        AppendQpackCountLines(lines, QpackErrorNames, _qpackErrorCounts);
        lines.Add("  encoder stream faults reached (s4.3, zeros included):");
        AppendQpackCountLines(lines, QpackEncoderStreamErrorNames, _qpackEncoderStreamErrorCounts);

        return string.Join(Environment.NewLine, lines);
    }

    // Zeros included, for the same reason the frame-type table prints all
    // thirty-three of its rows: a breakdown that printed only what it reached
    // cannot answer the question the breakdown exists for.
    private static void AppendQpackCountLines(List<string> lines, string[] names, long[] counts)
    {
        for (var index = 0; index < names.Length; index++)
        {
            lines.Add($"    {names[index]}={counts[index]}");
        }
    }

    private void AddQpackSeeds(List<byte[]> seeds)
    {
        seeds.Add(Convert.FromHexString(QuicRfcVectors.QpackB1FieldSectionHex));
        seeds.Add(Convert.FromHexString(QuicRfcVectors.QpackB2EncoderStreamHex));
        seeds.Add(Convert.FromHexString(QuicRfcVectors.QpackB2FieldSectionHex));
        seeds.Add(Convert.FromHexString(QuicRfcVectors.QpackB3EncoderStreamHex));
        seeds.Add(Convert.FromHexString(QuicRfcVectors.QpackB4EncoderStreamHex));
        seeds.Add(Convert.FromHexString(QuicRfcVectors.QpackB4FieldSectionHex));
        seeds.Add(Convert.FromHexString(QuicRfcVectors.QpackB5EncoderStreamHex));
        seeds.Add(Convert.FromHexString(QuicRfcVectors.QpackAppendixBDecoderInstructionsHex));
        seeds.Add(QuicRfcVectors.BuildQpackAppendixBEncoderStream());
        seeds.Add(QuicRfcVectors.BuildQpackAppendixBEncoderStreamThroughB4());

        // Encoder output, both of s4.1.2's string encodings. s4.5's static arm
        // is the one a corpus of noise can already reach, so these are here for
        // the Huffman half rather than for the representations.
        seeds.Add(BuildQpackEncodedSection(huffman: TlsQuicQpackHuffmanPolicy.Never));
        seeds.Add(BuildQpackEncodedSection(huffman: TlsQuicQpackHuffmanPolicy.Always));

        // One seed per s4.5 representation, built the way the axis 2 probes are,
        // so a mutation walk starts adjacent to every arm and not only to the
        // static one.
        var probe = new byte[QpackProbeScratchLength];
        var live = (ulong)QpackProbeTableEntryCount;
        for (var index = 0; index < QpackRepresentationArms.Length; index++)
        {
            var arm = QpackRepresentationArms[index];
            var required = arm.Dynamic ? live : 0;
            var baseValue = arm.PostBase ? 0ul : required;
            var written = WriteQpackFieldSectionPrefix(required, baseValue, probe);
            if (written == 0)
            {
                continue;
            }
            if (arm.Kind == 2)
            {
                if (!TryWriteQpackString(
                        "custom-key"u8, arm.PrefixBits, arm.Pattern, huffman: false,
                        probe.AsSpan(written), out int nameLength))
                {
                    continue;
                }
                written += nameLength;
            }
            else if (TlsQuicQpackPrimitives.TryEncodeInteger(
                         0, arm.PrefixBits, arm.Pattern, probe.AsSpan(written),
                         out int indexLength))
            {
                written += indexLength;
            }
            else
            {
                continue;
            }

            if (arm.Kind != 0)
            {
                if (!TryWriteQpackString(
                        "custom-value"u8, 8, 0, index % 2 == 0, probe.AsSpan(written),
                        out int valueLength))
                {
                    continue;
                }
                written += valueLength;
            }
            seeds.Add(probe[..written]);
        }

        // A section declaring more insertions than any table here holds -
        // s2.2.1's block, the answer that is neither an accept nor a rejection.
        var blockedLength = WriteQpackFieldSectionPrefix(live + 8, live, probe);
        if (blockedLength != 0)
        {
            probe[blockedLength] = 0xC1;
            seeds.Add(probe[..(blockedLength + 1)]);
        }

        // s5.1's named integer attack: an all-ones prefix followed by a long run
        // of continuation octets carrying zero.
        var overflow = new byte[16];
        overflow[0] = 0xFF;
        for (var index = 1; index < overflow.Length - 1; index++)
        {
            overflow[index] = 0x80;
        }
        seeds.Add(overflow);

        // A Huffman literal whose declared length runs to the end of the seed,
        // which is the shape a decompression bomb takes.
        var bomb = new byte[64];
        bomb[2] = 0xFF;
        bomb[3] = (byte)(bomb.Length - 5);
        for (var index = 4; index < bomb.Length; index++)
        {
            bomb[index] = 0xFF;
        }
        seeds.Add(bomb);
    }

    private static byte[] BuildQpackEncodedSection(TlsQuicQpackHuffmanPolicy huffman)
    {
        var buffer = new byte[512];
        if (!TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(buffer, out int written))
        {
            throw new InvalidOperationException("The QPACK field section prefix did not encode.");
        }
        foreach (var (name, value) in QpackSeedFields)
        {
            if (!TlsQuicQpackEncoder.TryEncodeFieldLine(
                    name, value, huffman, preferNameReference: true,
                    buffer.AsSpan(written), out int lineLength))
            {
                throw new InvalidOperationException("A QPACK seed field line did not encode.");
            }
            written += lineLength;
        }
        return buffer[..written];
    }

    // An indexed static entry, a static name reference with a literal value, and
    // a pair that is in neither table - one field line per s4.5 form the
    // library's own encoder is able to emit.
    private static readonly (byte[] Name, byte[] Value)[] QpackSeedFields =
    [
        (":status"u8.ToArray(), "200"u8.ToArray()),
        (":path"u8.ToArray(), "/index.html"u8.ToArray()),
        ("content-type"u8.ToArray(), "text/html; charset=utf-8"u8.ToArray()),
        ("custom-key"u8.ToArray(), "custom-value"u8.ToArray()),
    ];

    // The seed corpus is the whole basis of this campaign's non-vacuity, so it
    // gets the standing guard the QUIC frame corpus has: every claim these seeds
    // make is re-derived here rather than trusted.
    internal void VerifyQpackSeeds()
    {
        var buffer = new byte[QpackDecodeBufferLength];
        var lines = new TlsQuicQpackDecodedFieldLine[QpackMaximumFieldLines];

        // Appendix B.1 decodes on the static-only arm to exactly one field line.
        if (!TlsQuicQpackDecoder.TryDecodeFieldSection(
                Convert.FromHexString(QuicRfcVectors.QpackB1FieldSectionHex), buffer, lines,
                long.MaxValue, out int lineCount, out int bufferUsed, out var error)
            || lineCount != 1)
        {
            throw new InvalidOperationException(
                $"RFC 9204 Appendix B.1 did not decode to one field line: lines={lineCount}, " +
                $"error={error}.");
        }
        var b1 = System.Text.Encoding.ASCII.GetString(buffer, 0, bufferUsed);
        if (b1 != ":path/index.html")
        {
            throw new InvalidOperationException(
                $"RFC 9204 Appendix B.1 decoded to '{b1}', not ':path' then '/index.html'.");
        }

        // B.2's field section is the only published post-base vector, and it
        // decodes only against the table B.2's own encoder stream builds.
        var table = new TlsQuicQpackDynamicTable(QpackProbeTableMaximumCapacity);
        var b2Stream = Convert.FromHexString(QuicRfcVectors.QpackB2EncoderStreamHex);
        if (!table.TryReadEncoderInstructions(b2Stream, out int consumed, out var streamError)
            || consumed != b2Stream.Length
            || table.InsertCount != 2
            || table.Capacity != 220)
        {
            throw new InvalidOperationException(
                "RFC 9204 Appendix B.2's encoder stream did not build its table: " +
                $"consumed={consumed}/{b2Stream.Length}, inserts={table.InsertCount}, " +
                $"capacity={table.Capacity}, error={streamError}.");
        }
        if (!TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
                Convert.FromHexString(QuicRfcVectors.QpackB2FieldSectionHex), buffer, lines,
                long.MaxValue, table, out lineCount, out _, out ulong required, out error)
            || lineCount != 2
            || required != 2)
        {
            throw new InvalidOperationException(
                "RFC 9204 Appendix B.2's post-base field section did not decode: " +
                $"lines={lineCount}, requiredInsertCount={required}, error={error}.");
        }

        // B.3 and B.4 continue the same table, and B.4's field section is the
        // only published field-relative vector.
        foreach (var hex in new[]
                 {
                     QuicRfcVectors.QpackB3EncoderStreamHex,
                     QuicRfcVectors.QpackB4EncoderStreamHex,
                 })
        {
            var stream = Convert.FromHexString(hex);
            if (!table.TryReadEncoderInstructions(stream, out consumed, out streamError)
                || consumed != stream.Length)
            {
                throw new InvalidOperationException(
                    $"An RFC 9204 Appendix B encoder stream stalled: consumed={consumed}/" +
                    $"{stream.Length}, error={streamError}.");
            }
        }
        if (table.InsertCount != 4)
        {
            throw new InvalidOperationException(
                $"RFC 9204 Appendix B.4 leaves four insertions, not {table.InsertCount}.");
        }
        if (!TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
                Convert.FromHexString(QuicRfcVectors.QpackB4FieldSectionHex), buffer, lines,
                long.MaxValue, table, out lineCount, out _, out required, out error)
            || lineCount != 3
            || required != 4)
        {
            throw new InvalidOperationException(
                "RFC 9204 Appendix B.4's field-relative section did not decode: " +
                $"lines={lineCount}, requiredInsertCount={required}, error={error}.");
        }

        // B.5 evicts, which is the only published eviction.
        var b5 = Convert.FromHexString(QuicRfcVectors.QpackB5EncoderStreamHex);
        var droppedBefore = table.DroppedCount;
        if (!table.TryReadEncoderInstructions(b5, out consumed, out streamError)
            || consumed != b5.Length
            || table.DroppedCount == droppedBefore)
        {
            throw new InvalidOperationException(
                $"RFC 9204 Appendix B.5 did not evict: dropped={table.DroppedCount}, " +
                $"error={streamError}.");
        }

        // The probe table every axis 2 dynamic arm depends on. If this stops
        // holding four live entries those arms silently become unreachable,
        // which is precisely the failure this whole target is built against.
        var probe = BuildQpackProbeTable();
        if (probe.InsertCount - probe.DroppedCount != QpackProbeTableEntryCount)
        {
            throw new InvalidOperationException(
                $"The QPACK probe table holds {probe.InsertCount - probe.DroppedCount} live " +
                $"entries, not {QpackProbeTableEntryCount}.");
        }
    }

    // ========================================================================
    // HTTP/3 (RFC 9114) - s7.1's frame layer, s7.2.4's SETTINGS, and the
    // response state machine every byte of which is peer-controlled.
    //
    // THE SAME VACUITY TRAP AS QPACK, ONE LAYER UP. A HEADERS frame whose
    // payload is not a decodable field section is rejected at s4.1 before the
    // state machine sees a single field, so a target fed noise reaches "frame
    // parsed, field section rejected" and never reaches the sequencing rules -
    // interim responses, trailers, content-length, end of stream - which is
    // where the state machine's own logic lives. The corpus therefore carries
    // whole encoded response scripts and the axes below re-feed them with the
    // input's bytes spliced in, and DescribeHttp3Reachability prints how often
    // each state was actually reached.
    // ========================================================================

    private const int Http3FrameWalkLimit = 256;
    private const long Http3MaximumFieldSectionSize = QpackMaximumFieldSectionSize;

    // s11.2.1's registered frame types. GREASE and every other unregistered
    // value collapses into one row - s9's whole point is that they are
    // interchangeable to a receiver - and s7.2.8's four HTTP/2 carry-overs get
    // their own, because those must be REJECTED and a row that mixed them with
    // the ignorable ones could not show the difference.
    private static readonly (string Name, ulong Type)[] Http3FrameTypes =
    [
        ("DATA         (0x00)", 0x00),
        ("HEADERS      (0x01)", 0x01),
        ("CANCEL_PUSH  (0x03)", 0x03),
        ("SETTINGS     (0x04)", 0x04),
        ("PUSH_PROMISE (0x05)", 0x05),
        ("GOAWAY       (0x07)", 0x07),
        ("MAX_PUSH_ID  (0x0d)", 0x0d),
    ];

    // Read off the response after every feed. Each is a state the state machine
    // can only be in if the bytes that got it there were themselves decodable,
    // which is what makes a zero here a broken target rather than a quiet one.
    private static readonly string[] Http3ResponseArms =
    [
        "s4.1 final header section decoded",
        "s4.1 interim 1xx header section decoded",
        "s7.2.1 DATA payload delivered",
        "s4.1 trailer section decoded",
        "s4.1 response complete at end of stream",
        "RFC 9204 s2.2.1 section blocked on the encoder stream",
        "RFC 9204 s4.4.1 section acknowledgment queued",
        "s8.1 rejected with an HTTP/3 error code",
    ];

    private static readonly string[] Http3ErrorCodeNames = Enum.GetNames<TlsQuicHttp3ErrorCode>();
    private static readonly TlsQuicHttp3ErrorCode[] Http3ErrorCodeValues =
        Enum.GetValues<TlsQuicHttp3ErrorCode>();

    private long _http3InputCount;
    private long _http3FrameWalkAcceptCount;
    private long _http3FrameWalkIncompleteCount;
    private long _http3FrameWalkErrorCount;
    private long _http3FrameWalkLimitHitCount;
    private long _http3ReservedFrameRejectCount;
    private long _http3UnknownFrameAcceptCount;
    private long _http3SettingsWholeAttemptCount;
    private long _http3SettingsWholeAcceptCount;
    private long _http3SettingsFrameAttemptCount;
    private long _http3SettingsFrameAcceptCount;
    private long _http3SettingsPairCount;
    private long _http3SettingsReservedIdentifierCount;
    private long _http3VarintPayloadAttemptCount;
    private long _http3VarintPayloadAcceptCount;
    private long _http3ResponseFeedCount;
    private long _http3ResponseAcceptCount;
    private long _http3SplicedScriptFeedCount;
    private long _http3SplicedScriptAcceptCount;
    private long _http3MaximumBodyBytes;
    private readonly long[] _http3FrameTypeAccepts = new long[Http3FrameTypes.Length];
    private readonly long[] _http3ResponseArmCounts = new long[Http3ResponseArms.Length];
    private readonly long[] _http3ErrorCodeCounts = new long[Http3ErrorCodeNames.Length];

    private byte[][]? _http3Scripts;

    private void RunHttp3(byte[] input)
    {
        _http3InputCount++;
        RunHttp3FrameWalk(input);
        RunHttp3Settings(input);
        RunHttp3ResponseStateMachine(input, input, spliced: false);
        RunHttp3SplicedScripts(input);
    }

    // Axis 1: s7.1's frame layer walked over the input itself. Every frame this
    // accepts is then handed to whichever s7.2 payload reader its type selects,
    // so a payload that parsed as a frame but is nonsense inside still reaches a
    // second parser rather than being counted and dropped.
    private void RunHttp3FrameWalk(byte[] input)
    {
        var offset = 0;
        var frames = 0;
        while (offset < input.Length)
        {
            if (frames == Http3FrameWalkLimit)
            {
                _http3FrameWalkLimitHitCount++;
                break;
            }

            var before = offset;
            var status = TlsQuicHttp3Frames.TryRead(
                input, ref offset, out ulong frameType, out ReadOnlySpan<byte> payload,
                out TlsQuicHttp3ErrorCode error);
            RecordHttp3ErrorCode(error);

            if (status == TlsQuicHttp3FrameReadStatus.Incomplete)
            {
                _http3FrameWalkIncompleteCount++;
                break;
            }
            if (status == TlsQuicHttp3FrameReadStatus.Error)
            {
                _http3FrameWalkErrorCount++;
                if (error == TlsQuicHttp3ErrorCode.H3FrameUnexpected)
                {
                    _http3ReservedFrameRejectCount++;
                }
                break;
            }
            if (offset <= before)
            {
                throw new InvalidOperationException(
                    $"TlsQuicHttp3Frames.TryRead accepted a frame without advancing past " +
                    $"offset {before}.");
            }
            if (offset > input.Length)
            {
                throw new InvalidOperationException(
                    $"TlsQuicHttp3Frames.TryRead advanced to {offset} past {input.Length}.");
            }

            _http3FrameWalkAcceptCount++;
            frames++;
            RecordHttp3FrameType(frameType);
            RunHttp3FramePayload(frameType, payload);
        }
    }

    private void RunHttp3FramePayload(ulong frameType, ReadOnlySpan<byte> payload)
    {
        if (frameType == (ulong)TlsQuicHttp3FrameType.Settings)
        {
            _http3SettingsFrameAttemptCount++;
            if (TlsQuicHttp3Settings.TryDecodePayload(
                    payload, out var settings, out TlsQuicHttp3ErrorCode error))
            {
                _http3SettingsFrameAcceptCount++;
                RecordHttp3Settings(settings);
            }
            RecordHttp3ErrorCode(error);
            return;
        }

        if (frameType is (ulong)TlsQuicHttp3FrameType.CancelPush
            or (ulong)TlsQuicHttp3FrameType.Goaway
            or (ulong)TlsQuicHttp3FrameType.MaxPushId)
        {
            _http3VarintPayloadAttemptCount++;
            if (TlsQuicHttp3Frames.TryReadSingleVarintPayload(
                    payload, out ulong value, out TlsQuicHttp3ErrorCode error))
            {
                _http3VarintPayloadAcceptCount++;
                if (value > QuicVariableLengthInteger.MaximumValue)
                {
                    throw new InvalidOperationException(
                        $"A single-varint payload decoded to {value}, above RFC 9000 s16's " +
                        $"{QuicVariableLengthInteger.MaximumValue}.");
                }
            }
            RecordHttp3ErrorCode(error);
        }
    }

    // Axis 2: s7.2.4's SETTINGS payload read straight off the input, which is
    // the shape it takes on the control stream where the length has already been
    // stripped by the frame layer.
    private void RunHttp3Settings(byte[] input)
    {
        _http3SettingsWholeAttemptCount++;
        if (TlsQuicHttp3Settings.TryDecodePayload(
                input, out var settings, out TlsQuicHttp3ErrorCode error))
        {
            _http3SettingsWholeAcceptCount++;
            RecordHttp3Settings(settings);
        }
        RecordHttp3ErrorCode(error);
    }

    private void RecordHttp3Settings(ImmutableArray<TlsQuicHttp3Setting> settings)
    {
        _http3SettingsPairCount += settings.Length;
        foreach (var setting in settings)
        {
            if (TlsQuicHttp3Frames.IsReservedIdentifier(setting.Identifier))
            {
                _http3SettingsReservedIdentifierCount++;
            }
        }
    }

    // Axis 3: the response state machine, on both QPACK arms - static-only, what
    // a decoder advertising zero table capacity does, and against a live dynamic
    // table, which is the only arm on which s2.2.1's block can happen at all.
    // Fed whole and then split at a fuzz-chosen point, because a state machine
    // that only ever sees complete frames never exercises its own reassembly.
    private void RunHttp3ResponseStateMachine(byte[] input, byte[] script, bool spliced)
    {
        var method = (QpackByte(input, 44) & 1) != 0 ? "HEAD" : "GET";

        for (var arm = 0; arm < 2; arm++)
        {
            var response = new TlsQuicHttp3Response(
                Http3MaximumFieldSectionSize, method, arm == 0 ? null : _qpackProbeTable);

            var split = script.Length == 0 ? 0 : QpackByte(input, 45) % (script.Length + 1);
            var ok = response.TryRead(script.AsSpan(0, split), endOfStream: false, out ulong code);
            RecordHttp3ResponseOutcome(response, ok, code, script.Length, spliced);
            if (ok)
            {
                ok = response.TryRead(
                    script.AsSpan(split), endOfStream: true, out code);
                RecordHttp3ResponseOutcome(response, ok, code, script.Length, spliced);
            }
        }
    }

    private void RecordHttp3ResponseOutcome(
        TlsQuicHttp3Response response, bool ok, ulong code, int fed, bool spliced)
    {
        if (spliced)
        {
            _http3SplicedScriptFeedCount++;
        }
        else
        {
            _http3ResponseFeedCount++;
        }

        if (!ok)
        {
            _http3ResponseArmCounts[7]++;
            if (code == 0)
            {
                throw new InvalidOperationException(
                    "TlsQuicHttp3Response.TryRead refused a response with error code 0.");
            }
            return;
        }

        if (spliced)
        {
            _http3SplicedScriptAcceptCount++;
        }
        else
        {
            _http3ResponseAcceptCount++;
        }

        if (response.HeaderFields.Length != 0)
        {
            _http3ResponseArmCounts[0]++;
            RequireHttp3FieldSectionBound(response.HeaderFields);
        }
        if (response.InterimHeaderSections.Count != 0)
        {
            _http3ResponseArmCounts[1]++;
        }
        if (response.Body.Length != 0)
        {
            _http3ResponseArmCounts[2]++;
            if (response.Body.Length > fed)
            {
                throw new InvalidOperationException(
                    $"An HTTP/3 response delivered {response.Body.Length} body byte(s) from " +
                    $"{fed} fed byte(s).");
            }
            if (response.Body.Length > _http3MaximumBodyBytes)
            {
                _http3MaximumBodyBytes = response.Body.Length;
            }
        }
        if (response.TrailerFields.Length != 0)
        {
            _http3ResponseArmCounts[3]++;
            RequireHttp3FieldSectionBound(response.TrailerFields);
        }
        if (response.IsComplete)
        {
            _http3ResponseArmCounts[4]++;
        }
        if (response.IsBlocked)
        {
            _http3ResponseArmCounts[5]++;
            if (response.BlockedRequiredInsertCount <= _qpackProbeTable.InsertCount)
            {
                throw new InvalidOperationException(
                    $"A response blocked on Required Insert Count " +
                    $"{response.BlockedRequiredInsertCount}, which the table's " +
                    $"{_qpackProbeTable.InsertCount} insertion(s) already cover.");
            }
        }
        if (response.SectionAcknowledgments.Count != 0)
        {
            _http3ResponseArmCounts[6]++;
        }
    }

    private static void RequireHttp3FieldSectionBound(
        ImmutableArray<TlsQuicHttp3Field> fields)
    {
        var size = 0L;
        foreach (var field in fields)
        {
            size += field.Name.Length + field.Value.Length + 32;
        }
        if (size > Http3MaximumFieldSectionSize)
        {
            throw new InvalidOperationException(
                $"An accepted field section measures {size} bytes against RFC 9114 s4.2.2's " +
                $"advertised {Http3MaximumFieldSectionSize}.");
        }
    }

    // Axis 4: the published-shape response scripts with the input's bytes
    // spliced in. This is the axis that carries the target: a corpus of noise
    // never produces a HEADERS frame whose payload decodes, so without it every
    // state above axis 1 reports zero and the target is decoration.
    private void RunHttp3SplicedScripts(byte[] input)
    {
        var scripts = _http3Scripts ??= BuildHttp3Scripts();
        var chosen = scripts[QpackByte(input, 46) % scripts.Length];
        var spliced = (byte[])chosen.Clone();

        if (input.Length != 0 && spliced.Length != 0)
        {
            // A short run rather than the whole tail: overwriting everything
            // from the splice point destroys the frame lengths behind it and the
            // walk stops at the first one, which puts the sequencing rules back
            // out of reach.
            var start = QpackByte(input, 47) % spliced.Length;
            var run = Math.Min(4, spliced.Length - start);
            for (var index = 0; index < run; index++)
            {
                spliced[start + index] = QpackByte(input, index + 60);
            }
        }

        RunHttp3ResponseStateMachine(input, spliced, spliced: true);

        var offset = 0;
        var frames = 0;
        while (offset < spliced.Length && frames < Http3FrameWalkLimit)
        {
            if (TlsQuicHttp3Frames.TryRead(
                    spliced, ref offset, out ulong frameType, out ReadOnlySpan<byte> payload,
                    out TlsQuicHttp3ErrorCode error) != TlsQuicHttp3FrameReadStatus.Complete)
            {
                RecordHttp3ErrorCode(error);
                break;
            }
            RecordHttp3ErrorCode(error);
            RecordHttp3FrameType(frameType);
            RunHttp3FramePayload(frameType, payload);
            frames++;
        }
    }

    private void RecordHttp3FrameType(ulong frameType)
    {
        for (var index = 0; index < Http3FrameTypes.Length; index++)
        {
            if (Http3FrameTypes[index].Type == frameType)
            {
                _http3FrameTypeAccepts[index]++;
                return;
            }
        }
        _http3UnknownFrameAcceptCount++;
    }

    // Compared numerically against the enum's own values rather than by name:
    // TlsQuicHttp3ErrorCode is sparse - 0x0100 upwards - so it cannot index an
    // array directly, and ToString() on an enum allocates, which this target
    // calls often enough to matter.
    private void RecordHttp3ErrorCode(TlsQuicHttp3ErrorCode error)
    {
        for (var index = 0; index < Http3ErrorCodeValues.Length; index++)
        {
            if (Http3ErrorCodeValues[index] == error)
            {
                _http3ErrorCodeCounts[index]++;
                return;
            }
        }
    }

    internal string? DescribeHttp3Reachability()
    {
        if (_http3InputCount == 0)
        {
            return null;
        }

        List<string> lines =
        [
            $"http3 reachability over {_http3InputCount} input(s):",
            "  axis 1 (s7.1 frame walk over the input itself):",
            $"    frames accepted={_http3FrameWalkAcceptCount}, walks ending Incomplete=" +
            $"{_http3FrameWalkIncompleteCount}, ending in Error={_http3FrameWalkErrorCount}, " +
            $"hitting the {Http3FrameWalkLimit}-frame cap={_http3FrameWalkLimitHitCount}",
            $"    s7.2.8 HTTP/2 carry-over types rejected={_http3ReservedFrameRejectCount}, " +
            $"s9 unregistered types accepted={_http3UnknownFrameAcceptCount}",
            "    accepts per registered frame type (s11.2.1, zeros included):",
        ];
        for (var index = 0; index < Http3FrameTypes.Length; index++)
        {
            lines.Add($"      {Http3FrameTypes[index].Name}={_http3FrameTypeAccepts[index]}");
        }

        lines.Add("  axis 2 (s7.2.4 SETTINGS):");
        lines.Add(
            "    whole input as a payload: " +
            $"{_http3SettingsWholeAcceptCount}/{_http3SettingsWholeAttemptCount} true");
        lines.Add(
            "    payload of an accepted SETTINGS frame: " +
            $"{_http3SettingsFrameAcceptCount}/{_http3SettingsFrameAttemptCount} true");
        lines.Add(
            $"    identifier/value pairs decoded={_http3SettingsPairCount}, of which s7.2.4.1 " +
            $"reserved={_http3SettingsReservedIdentifierCount}");
        lines.Add(
            "  axis 2 (single-varint payloads: CANCEL_PUSH, GOAWAY, MAX_PUSH_ID): " +
            $"{_http3VarintPayloadAcceptCount}/{_http3VarintPayloadAttemptCount} true");

        lines.Add("  axis 3 (response state machine, both QPACK arms, whole then split feeds):");
        lines.Add(
            $"    feeds={_http3ResponseFeedCount}, accepted={_http3ResponseAcceptCount}");
        lines.Add("  axis 4 (published response scripts with input bytes spliced in):");
        lines.Add(
            $"    feeds={_http3SplicedScriptFeedCount}, " +
            $"accepted={_http3SplicedScriptAcceptCount}");
        lines.Add("  states reached across both response axes:");
        for (var index = 0; index < Http3ResponseArms.Length; index++)
        {
            lines.Add($"    {Http3ResponseArms[index]}={_http3ResponseArmCounts[index]}");
        }
        lines.Add($"  largest delivered body: {_http3MaximumBodyBytes} bytes");

        lines.Add("  error codes reached (s8.1, zeros included):");
        AppendQpackCountLines(lines, Http3ErrorCodeNames, _http3ErrorCodeCounts);

        return string.Join(Environment.NewLine, lines);
    }

    // Whole encoded response scripts. THESE ARE THE TARGET'S NON-VACUITY: every
    // state above s7.1's frame walk is unreachable without a HEADERS payload
    // that decodes, and nothing a mutation walk over noise produces ever does.
    private static byte[][] BuildHttp3Scripts()
    {
        var complete = new List<byte>();
        TlsQuicHttp3Frames.Write(
            complete, (ulong)TlsQuicHttp3FrameType.Headers,
            BuildHttp3HeaderSection("200", huffman: TlsQuicQpackHuffmanPolicy.Never));
        TlsQuicHttp3Frames.Write(
            complete, (ulong)TlsQuicHttp3FrameType.Data, "hello world"u8);
        TlsQuicHttp3Frames.Write(
            complete, (ulong)TlsQuicHttp3FrameType.Headers,
            BuildHttp3TrailerSection());

        var interim = new List<byte>();
        TlsQuicHttp3Frames.Write(
            interim, (ulong)TlsQuicHttp3FrameType.Headers,
            BuildHttp3HeaderSection("103", huffman: TlsQuicQpackHuffmanPolicy.Always));
        TlsQuicHttp3Frames.Write(
            interim, (ulong)TlsQuicHttp3FrameType.Headers,
            BuildHttp3HeaderSection("200", huffman: TlsQuicQpackHuffmanPolicy.Always));
        TlsQuicHttp3Frames.Write(
            interim, (ulong)TlsQuicHttp3FrameType.Data, "second"u8);

        // A response whose header section references the dynamic table, which is
        // the only shape that reaches RFC 9204 s2.2.1's block: the declared
        // Required Insert Count is above anything the probe table holds.
        var blocked = new List<byte>();
        var blockedSection = new byte[32];
        var blockedPrefix = WriteQpackFieldSectionPrefix(
            QpackProbeTableEntryCount + 8, QpackProbeTableEntryCount, blockedSection);
        blockedSection[blockedPrefix] = 0xD9;
        TlsQuicHttp3Frames.Write(
            blocked, (ulong)TlsQuicHttp3FrameType.Headers,
            blockedSection.AsSpan(0, blockedPrefix + 1));

        // A response whose ':status' comes out of the DYNAMIC table with a
        // Required Insert Count the probe table already satisfies. This is the
        // only script that reaches RFC 9204 s4.4.1's section acknowledgment:
        // s4.4.1 emits one only "After processing an encoded field section whose
        // declared Required Insert Count is not zero", and every other script
        // here declares zero because the library's own encoder is static-only.
        var dynamic = new List<byte>();
        var dynamicSection = new byte[32];
        var dynamicPrefix = WriteQpackFieldSectionPrefix(
            QpackProbeTableEntryCount, QpackProbeTableEntryCount, dynamicSection);

        // s3.2.5's relative index counts DOWN from Base, so absolute 0 - the
        // ':status: 200' BuildQpackProbeTable inserts first - is Base - 0 - 1.
        if (dynamicPrefix == 0
            || !TlsQuicQpackPrimitives.TryEncodeInteger(
                QpackProbeTableEntryCount - 1, 6, 0x80,
                dynamicSection.AsSpan(dynamicPrefix), out int dynamicIndexLength))
        {
            throw new InvalidOperationException("The dynamic response section did not encode.");
        }
        TlsQuicHttp3Frames.Write(
            dynamic, (ulong)TlsQuicHttp3FrameType.Headers,
            dynamicSection.AsSpan(0, dynamicPrefix + dynamicIndexLength));
        TlsQuicHttp3Frames.Write(dynamic, (ulong)TlsQuicHttp3FrameType.Data, "dyn"u8);

        // s7.2.4's SETTINGS beside the control-stream frames that carry a single
        // varint, then s7.2.8's four HTTP/2 carry-overs, each of which must be a
        // connection error rather than an ignorable unknown.
        var control = new List<byte>();
        var settingsPayload = new List<byte>();
        foreach (var setting in TlsQuicHttp3Spec.CaptureSettings)
        {
            QuicVariableLengthInteger.Write(settingsPayload, setting.Identifier);
            QuicVariableLengthInteger.Write(settingsPayload, setting.Value);
        }
        TlsQuicHttp3Frames.Write(
            control, (ulong)TlsQuicHttp3FrameType.Settings,
            CollectionsToSpan(settingsPayload));
        TlsQuicHttp3Frames.Write(control, (ulong)TlsQuicHttp3FrameType.Goaway, [0x04]);
        TlsQuicHttp3Frames.Write(control, (ulong)TlsQuicHttp3FrameType.MaxPushId, [0x10]);
        TlsQuicHttp3Frames.Write(control, (ulong)TlsQuicHttp3FrameType.CancelPush, [0x02]);
        TlsQuicHttp3Frames.Write(control, TlsQuicHttp3Frames.ReservedIdentifier(1), "grease"u8);

        var reserved = new List<byte>();
        foreach (var frameType in new ulong[] { 0x02, 0x06, 0x08, 0x09 })
        {
            TlsQuicHttp3Frames.Write(reserved, frameType, []);
        }

        var pushPromise = new List<byte>();
        var promise = new List<byte> { 0x00 };
        promise.AddRange(BuildHttp3HeaderSection("200", huffman: TlsQuicQpackHuffmanPolicy.Never));
        TlsQuicHttp3Frames.Write(
            pushPromise, (ulong)TlsQuicHttp3FrameType.PushPromise, CollectionsToSpan(promise));

        // s7.1: a length that runs past the end of what was delivered. The frame
        // layer must answer Incomplete and wait, not reject and not read past.
        //
        // ONE BYTE SHORT, NOT HALF. Half of the script is not guaranteed to land
        // INSIDE a frame - it landed on a boundary here, so the walk ended
        // Complete with nothing left over and VerifyHttp3Seeds failed on its own
        // assertion. The last frame minus its last byte is short by construction.
        var truncated = complete.ToArray()[..(complete.Count - 1)];

        // A declared length above int.MaxValue, which s7.1 makes H3_FRAME_ERROR
        // rather than an allocation.
        var enormous = new List<byte> { (byte)TlsQuicHttp3FrameType.Data };
        QuicVariableLengthInteger.Write(enormous, QuicVariableLengthInteger.MaximumValue);

        return
        [
            complete.ToArray(),
            interim.ToArray(),
            blocked.ToArray(),
            control.ToArray(),
            reserved.ToArray(),
            pushPromise.ToArray(),
            truncated,
            enormous.ToArray(),
            dynamic.ToArray(),
        ];
    }

    private static ReadOnlySpan<byte> CollectionsToSpan(List<byte> value) => value.ToArray();

    private static byte[] BuildHttp3HeaderSection(
        string status, TlsQuicQpackHuffmanPolicy huffman)
    {
        var buffer = new byte[512];
        if (!TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(buffer, out int written))
        {
            throw new InvalidOperationException("The QPACK field section prefix did not encode.");
        }
        written += EncodeHttp3Field(
            ":status"u8, System.Text.Encoding.ASCII.GetBytes(status), huffman,
            buffer.AsSpan(written));
        written += EncodeHttp3Field(
            "content-type"u8, "text/plain"u8, huffman, buffer.AsSpan(written));
        return buffer[..written];
    }

    private static byte[] BuildHttp3TrailerSection()
    {
        var buffer = new byte[256];
        if (!TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(buffer, out int written))
        {
            throw new InvalidOperationException("The QPACK field section prefix did not encode.");
        }
        written += EncodeHttp3Field(
            "x-trailer"u8, "done"u8, huffman: TlsQuicQpackHuffmanPolicy.Never, buffer.AsSpan(written));
        return buffer[..written];
    }

    private static int EncodeHttp3Field(
        ReadOnlySpan<byte> name,
        ReadOnlySpan<byte> value,
        TlsQuicQpackHuffmanPolicy huffman,
        Span<byte> destination)
    {
        if (!TlsQuicQpackEncoder.TryEncodeFieldLine(
                name, value, huffman, preferNameReference: true, destination, out int written))
        {
            throw new InvalidOperationException("An HTTP/3 seed field line did not encode.");
        }
        return written;
    }

    private void AddHttp3Seeds(List<byte[]> seeds)
    {
        seeds.AddRange(BuildHttp3Scripts());

        // Every registered frame type on its own, with a payload that is legal
        // for it, so the per-type table has an anchor for each row rather than
        // only for the ones the scripts happen to carry.
        foreach (var (_, frameType) in Http3FrameTypes)
        {
            var frame = new List<byte>();
            ReadOnlySpan<byte> payload = frameType switch
            {
                (ulong)TlsQuicHttp3FrameType.Headers => BuildHttp3HeaderSection("404", TlsQuicQpackHuffmanPolicy.Never),
                (ulong)TlsQuicHttp3FrameType.Data => "body"u8,
                (ulong)TlsQuicHttp3FrameType.Settings => [0x06, 0x40, 0x00],
                (ulong)TlsQuicHttp3FrameType.PushPromise => [0x00, 0x00, 0x00],
                _ => [0x01],
            };
            TlsQuicHttp3Frames.Write(frame, frameType, payload);
            seeds.Add(frame.ToArray());
        }

        // s7.2.4.1's reserved setting identifiers and s7.2.4's own, as a bare
        // payload - the shape TryDecodePayload sees on the control stream.
        var settings = new List<byte>();
        QuicVariableLengthInteger.Write(settings, TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier);
        QuicVariableLengthInteger.Write(settings, QpackProbeTableMaximumCapacity);
        QuicVariableLengthInteger.Write(settings, TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier);
        QuicVariableLengthInteger.Write(settings, QpackAdvertisedBlockedStreams);
        QuicVariableLengthInteger.Write(settings, TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier);
        QuicVariableLengthInteger.Write(settings, Http3MaximumFieldSectionSize);
        QuicVariableLengthInteger.Write(settings, TlsQuicHttp3Frames.ReservedIdentifier(2));
        QuicVariableLengthInteger.Write(settings, 0);
        seeds.Add(settings.ToArray());

        // s7.2.4: "a frame payload that terminates before the end of the
        // identified fields" - an identifier with no value behind it.
        seeds.Add([0x01]);
    }

    // The same standing guard the QUIC frame corpus has. Everything above axis 1
    // rests on these scripts still decoding to what they claim, and a change to
    // the QPACK encoder or to any frame writer would otherwise turn this target
    // into the one the certificate lesson warns about without a single failure.
    internal void VerifyHttp3Seeds()
    {
        var scripts = BuildHttp3Scripts();

        // Script 0 is a complete response: header section, body and trailers.
        var complete = new TlsQuicHttp3Response(Http3MaximumFieldSectionSize, "GET");
        if (!complete.TryRead(scripts[0], endOfStream: true, out ulong code))
        {
            throw new InvalidOperationException(
                $"The complete HTTP/3 response script was refused with error code {code}.");
        }
        if (complete.Status != 200
            || complete.HeaderFields.Length == 0
            || complete.TrailerFields.Length == 0
            || complete.Body.Length != "hello world"u8.Length
            || !complete.IsComplete)
        {
            throw new InvalidOperationException(
                $"The complete HTTP/3 response script decoded to status={complete.Status}, " +
                $"{complete.HeaderFields.Length} header(s), {complete.TrailerFields.Length} " +
                $"trailer(s), {complete.Body.Length} body byte(s), complete={complete.IsComplete}.");
        }

        // Script 1 carries an interim 1xx section ahead of its final one.
        var interim = new TlsQuicHttp3Response(Http3MaximumFieldSectionSize, "GET");
        if (!interim.TryRead(scripts[1], endOfStream: true, out code)
            || interim.InterimHeaderSections.Count == 0
            || interim.Status != 200)
        {
            throw new InvalidOperationException(
                $"The interim HTTP/3 response script decoded to " +
                $"{interim.InterimHeaderSections.Count} interim section(s) and status " +
                $"{interim.Status} (error code {code}).");
        }

        // Script 2 must BLOCK on the dynamic arm - not be rejected. Without this
        // the whole blocked-decoding axis reports zero and nobody notices.
        var blocked = new TlsQuicHttp3Response(
            Http3MaximumFieldSectionSize, "GET", _qpackProbeTable);
        if (!blocked.TryRead(scripts[2], endOfStream: false, out code) || code != 0)
        {
            throw new InvalidOperationException(
                $"The blocking HTTP/3 response script was refused with error code {code} " +
                "instead of parking on RFC 9204 s2.2.1's block.");
        }
        if (!blocked.IsBlocked)
        {
            throw new InvalidOperationException(
                "The blocking HTTP/3 response script did not block, so the blocked-decoding " +
                "axis has no anchor.");
        }

        // Script 4's four HTTP/2 carry-overs are a connection error per s7.2.8,
        // and the frame layer must say so rather than ignore them.
        var offset = 0;
        if (TlsQuicHttp3Frames.TryRead(
                scripts[4], ref offset, out _, out _, out TlsQuicHttp3ErrorCode error)
            != TlsQuicHttp3FrameReadStatus.Error
            || error != TlsQuicHttp3ErrorCode.H3FrameUnexpected)
        {
            throw new InvalidOperationException(
                $"An RFC 9114 s7.2.8 reserved frame type was answered with {error} rather than " +
                "H3_FRAME_UNEXPECTED.");
        }

        // Script 6 is a truncated prefix of script 0: the frame layer must ask
        // for more rather than reject or read past the end.
        offset = 0;
        var status = TlsQuicHttp3FrameReadStatus.Complete;
        while (offset < scripts[6].Length && status == TlsQuicHttp3FrameReadStatus.Complete)
        {
            status = TlsQuicHttp3Frames.TryRead(scripts[6], ref offset, out _, out _, out error);
        }
        if (status != TlsQuicHttp3FrameReadStatus.Incomplete)
        {
            throw new InvalidOperationException(
                $"The truncated HTTP/3 script ended in {status}, not Incomplete.");
        }

        // Script 7 declares a payload of 2^62-1 bytes. s7.1 makes that a frame
        // error, and an implementation that instead sized a buffer from it is
        // the unbounded allocation this campaign exists to find.
        offset = 0;
        if (TlsQuicHttp3Frames.TryRead(scripts[7], ref offset, out _, out _, out error)
            != TlsQuicHttp3FrameReadStatus.Error
            || error != TlsQuicHttp3ErrorCode.H3FrameError)
        {
            throw new InvalidOperationException(
                $"A frame declaring {QuicVariableLengthInteger.MaximumValue} payload bytes was " +
                $"answered with {error} rather than H3_FRAME_ERROR.");
        }

        // Script 8 takes its ':status' out of the dynamic table, which is the
        // only way RFC 9204 s4.4.1's section acknowledgment is ever emitted. If
        // this stops holding, that arm silently reports zero forever.
        var dynamic = new TlsQuicHttp3Response(
            Http3MaximumFieldSectionSize, "GET", _qpackProbeTable);
        if (!dynamic.TryRead(scripts[8], endOfStream: true, out code)
            || dynamic.Status != 200
            || dynamic.SectionAcknowledgments.Count == 0)
        {
            throw new InvalidOperationException(
                $"The dynamic HTTP/3 response script decoded to status {dynamic.Status} with " +
                $"{dynamic.SectionAcknowledgments.Count} section acknowledgment(s) (error " +
                $"code {code}), so RFC 9204 s4.4.1's arm has no anchor.");
        }
    }

    private static void ProtocolBoundary(Action action)
    {
        try { action(); }
        catch (TlsProtocolException) { }
    }

    private static void CaptureBoundary(Action action)
    {
        try { action(); }
        catch (TlsProtocolException) { }
        catch (TlsQuicTransportException) { }
        catch (NotSupportedException) { }
    }

    private static void JsonBoundary(Action action)
    {
        try { action(); }
        catch (InvalidDataException) { }
    }

    private static void QuicBoundary(Action action)
    {
        try { action(); }
        catch (TlsQuicTransportException) { }
    }

    private static void DnsBoundary(Action action)
    {
        try { action(); }
        catch (TlsEchDnsException) { }
    }

    private static void ProxyBoundary(Action action)
    {
        try { action(); }
        catch (TlsQuicProxyException) { }
    }
}
