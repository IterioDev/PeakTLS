using System.Collections.Immutable;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Every bound on TlsQuicConnectionSpec is a guard on a caller-supplied field, and the caller
// is subsystem B populating a browser's layout by hand. Provenance therefore decides nothing
// here in our favour: there is no parser upstream narrowing the range first, so every guard
// is reachable and every one needs a witness, including the boundary values that separate a
// correct bound from an off-by-one.
//
// Where the bound has an RFC behind it the expectation is derived from the RFC extract and
// not from the code - s7.2's floor of 8, s17.2's ceiling of 20, s17.1's 1-to-4 packet number,
// s12.3's 2^62-1, s14.1's 1200 and s18.2's 65527. Where there is no external source (the
// CRYPTO split rules, the frame-order uniqueness rule) the test is a snapshot of a decision
// this file's comments state, and it is labelled as one.
public sealed class TlsQuicConnectionSpecTests
{
    [Fact]
    public void DefaultsAreTheACaptureShapeAtTheSectionFourteenFloor()
    {
        var spec = new TlsQuicConnectionSpec();

        // a captured client: "client_connection_id_length": 0, "server_connection_id_length": 8.
        Assert.Equal(0, spec.SourceConnectionIdLength);
        Assert.Equal(8, spec.DestinationConnectionIdLength);
        // RFC 9000 s14.1's smallest allowed maximum datagram size.
        Assert.Equal(1200, spec.PaddingTarget);
        // RFC 9001 A.2's client Initial: packet number 2 at an encoded length of 4, token
        // length 00. The capture does not observe either field.
        Assert.Equal(4, spec.PacketNumberEncodedLength);
        Assert.Equal(0UL, spec.InitialPacketNumber);
        Assert.True(spec.Token.IsEmpty);
        // A.2's frame order: one CRYPTO frame at offset 0, then PADDING.
        Assert.Equal(
            new[] { TlsQuicFrameType.Crypto, TlsQuicFrameType.Padding },
            spec.InitialFrameOrder);
        // RFC 9000 s16 permits a longer form; the default declines to use one.
        Assert.Equal(TlsQuicVarintWidth.Minimal, spec.HeaderLengthVarintWidth);
        Assert.Equal(TlsQuicVarintWidth.Minimal, spec.CryptoOffsetVarintWidth);
        Assert.Equal(TlsQuicVarintWidth.Minimal, spec.CryptoLengthVarintWidth);
        Assert.True(spec.InitialCryptoFrameByteCounts.IsEmpty);
        Assert.True(spec.InitialCryptoFramesPerDatagram.IsEmpty);
        // No range is invented: one observed draw is not a range.
        Assert.Null(spec.InitialRttRange);
    }

    // THE s7.2 WITNESS. RFC 9000 s7.2: "This Destination Connection ID MUST be at least 8
    // bytes in length." The expectation comes from that sentence, not from the default -
    // that client's own value of 8 sits exactly on the floor, so the capture agrees with every
    // length at or above it and proves nothing about what is below.
    //
    // 7 is the boundary case and is the row that fails against a mutant weakening the bound
    // to `< 7`; the lower rows fail against a mutant that deletes it outright, and 0 is here
    // because zero-versus-absent is the confusion this project keeps finding - zero is legal
    // for the source connection ID and illegal for this one.
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(7)]
    public void DestinationConnectionIdLengthBelowTheSectionSevenTwoFloorIsRejected(int length)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec { DestinationConnectionIdLength = length });
        Assert.Equal("DestinationConnectionIdLength", error.ParamName);
    }

    // The other half of the same boundary: 8 is legal, so a mutant tightening the floor to 9
    // fails here rather than passing everything above.
    [Theory]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(20)]
    public void DestinationConnectionIdLengthFromTheFloorToTheSectionSeventeenCeilingIsAccepted(
        int length)
    {
        Assert.Equal(
            length,
            new TlsQuicConnectionSpec { DestinationConnectionIdLength = length }
                .DestinationConnectionIdLength);
    }

    // RFC 9000 s17.2's Destination Connection ID Length field, the same ceiling
    // TlsQuicPacketHeader enforces when reading one.
    [Fact]
    public void DestinationConnectionIdLengthAboveTheSectionSeventeenCeilingIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec { DestinationConnectionIdLength = 21 });
        Assert.Equal("DestinationConnectionIdLength", error.ParamName);
    }

    // THE ASYMMETRY. s7.2's floor applies only to the connection ID the client picks for the
    // server; the one it asks the server to use back has none, and zero is what Chromium
    // uses. A guard copied from the destination field onto this one would fail here, and
    // nothing in the wire format hints that the two differ.
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(20)]
    public void SourceConnectionIdLengthHasNoFloorAndZeroIsLegal(int length)
    {
        Assert.Equal(
            length,
            new TlsQuicConnectionSpec { SourceConnectionIdLength = length }
                .SourceConnectionIdLength);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(21)]
    public void SourceConnectionIdLengthOutsideZeroToTwentyIsRejected(int length)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec { SourceConnectionIdLength = length });
        Assert.Equal("SourceConnectionIdLength", error.ParamName);
    }

    // RFC 9000 s17.1: "Packet Number: This field is 1 to 4 bytes long." Both boundaries are
    // pinned so neither a widened nor a narrowed bound survives.
    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public void PacketNumberEncodedLengthWithinSectionSeventeenOneIsAccepted(int length)
    {
        Assert.Equal(
            length,
            new TlsQuicConnectionSpec { PacketNumberEncodedLength = length }
                .PacketNumberEncodedLength);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    public void PacketNumberEncodedLengthOutsideOneToFourIsRejected(int length)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec { PacketNumberEncodedLength = length });
        Assert.Equal("PacketNumberEncodedLength", error.ParamName);
    }

    // RFC 9000 s12.3: "The packet number is an integer in the range 0 to 2^62-1." The
    // expression below is that range's top, written the way the RFC states it rather than
    // copied from QuicVariableLengthInteger, so the two are independent transcriptions.
    [Fact]
    public void InitialPacketNumberAtTheSectionTwelveThreeMaximumIsAccepted()
    {
        const ulong maximum = (1UL << 62) - 1;
        Assert.Equal(
            maximum,
            new TlsQuicConnectionSpec { InitialPacketNumber = maximum }.InitialPacketNumber);
    }

    [Fact]
    public void InitialPacketNumberAboveTheSectionTwelveThreeMaximumIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec { InitialPacketNumber = 1UL << 62 });
        Assert.Equal("InitialPacketNumber", error.ParamName);
    }

    // Token was pinned only at its empty default, so mutating the setter to discard the value
    // passed the whole gate. Task 4b's done-condition needs "a non-zero token with a
    // distinctive prefix" and task 11 reports token length and prefix, so both would have
    // inherited a knob proven only where it carries nothing. The bytes are arbitrary; what is
    // load-bearing is that they survive the setter unchanged and in order.
    [Fact]
    public void ANonEmptyTokenIsKeptByteForByte()
    {
        byte[] token = [0xc0, 0xff, 0xee, 0x00, 0x01];

        var spec = new TlsQuicConnectionSpec { Token = token };

        Assert.Equal(token, spec.Token.ToArray());
    }

    // RFC 9000 s14.1 sets the floor at 1200 and permits exceeding it: "Datagrams containing
    // Initial packets MAY exceed 1200 bytes if the sender believes that the network path and
    // peer both support the size." The ceiling is s18.2's maximum permitted UDP payload of
    // 65527 - a physical limit, deliberately NOT the advertised max_udp_payload_size of 1472
    // and NOT the transport's own ceiling. A spec is free to set 1472; it is just not
    // required to, and nothing derives it.
    [Theory]
    [InlineData(1200)]
    [InlineData(1472)]
    [InlineData(65527)]
    public void PaddingTargetFromTheSectionFourteenOneFloorToTheUdpMaximumIsAccepted(int target)
    {
        Assert.Equal(target, new TlsQuicConnectionSpec { PaddingTarget = target }.PaddingTarget);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1199)]
    [InlineData(65528)]
    public void PaddingTargetOutsideTheSectionFourteenOneRangeIsRejected(int target)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec { PaddingTarget = target });
        Assert.Equal("PaddingTarget", error.ParamName);
    }

    // RFC 9001 s6.6's confidentiality limit is a MAXIMUM - "Endpoints MUST initiate a key
    // update before sending more protected packets than the confidentiality limit for the
    // selected AEAD permits" - so lowering it is conformant and the knob does not police the
    // upper end. ONE is still the floor, and the reason is s6.1 rather than tidiness: at zero
    // the first packet's update finds the gate open, because
    // _lowestApplicationPacketNumberInWritePhase is still null and there is nothing to wait
    // for; the SECOND packet then finds that gate closed against an acknowledgment that has
    // not arrived, and s6.6's other half - "If a key update is not possible ... the endpoint
    // MUST stop using the connection" - closes the connection with AEAD_LIMIT_REACHED. A spec
    // that kills every connection on its second 1-RTT packet is worth rejecting at the
    // constructor rather than at the second packet.
    //
    // One witness per property, for the reason the varint-width trio below gives.
    [Fact]
    public void AnAesGcmConfidentialityLimitBelowOneIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec
            {
                AesGcmConfidentialityLimit = 0,
            });
        Assert.Equal("AesGcmConfidentialityLimit", error.ParamName);
    }

    [Fact]
    public void AChaCha20Poly1305ConfidentialityLimitBelowOneIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec
            {
                ChaCha20Poly1305ConfidentialityLimit = -1,
            });
        Assert.Equal("ChaCha20Poly1305ConfidentialityLimit", error.ParamName);
    }

    // RFC 9000 s16 Table 4 has four widths: 1, 2, 4 and 8 bytes. Minimal is this spec's own
    // "let the writer pick", not a wire width. 3 is the interesting rejection because it sits
    // *inside* the numeric span 0 to 8 - a range check rather than a definedness check would
    // admit it, and 3, 5, 6 and 7 are all in that hole.
    //
    // One witness per property, because one shared helper guarding three fields is a guard
    // reachable by three paths and a single test would leave two of them unpinned.
    [Fact]
    public void HeaderLengthVarintWidthOutsideTableFourIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec
            {
                HeaderLengthVarintWidth = (TlsQuicVarintWidth)3,
            });
        Assert.Equal("HeaderLengthVarintWidth", error.ParamName);
    }

    [Fact]
    public void CryptoOffsetVarintWidthOutsideTableFourIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec
            {
                CryptoOffsetVarintWidth = (TlsQuicVarintWidth)3,
            });
        Assert.Equal("CryptoOffsetVarintWidth", error.ParamName);
    }

    [Fact]
    public void CryptoLengthVarintWidthOutsideTableFourIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec
            {
                CryptoLengthVarintWidth = (TlsQuicVarintWidth)7,
            });
        Assert.Equal("CryptoLengthVarintWidth", error.ParamName);
    }

    // RFC 9000 s19.3 makes First ACK Range a mandatory field, so the smallest ACK frame that
    // exists still names one range and a limit of zero could only produce frames
    // TlsQuicAckFrames.WriteAckFrame rejects. The A2 rule this witnesses is the general one:
    // every guard on a spec field is reachable, because subsystem B populates the spec, so
    // every one of them needs a test. This guard had none - the same gap as the
    // CryptoOffsetVarintWidth family, and for the same reason: the knob is not yet read by
    // anything, so nothing exercised it by accident.
    //
    // TlsQuicAckTracker enforces the identical bound on its own constructor parameter, and
    // ARangeLimitBelowOneIsRejected witnesses THAT one. The two are separate checks on
    // separate types and one cannot stand in for the other; deleting either leaves the other's
    // test green.
    [Fact]
    public void ARangeLimitBelowOneIsRejectedBySpecTooNotOnlyByTheTracker()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec
            {
                AckRangeLimit = 0,
            });
        Assert.Equal("AckRangeLimit", error.ParamName);
    }

    // One is legal and is the smallest legal value, so the guard is off by nothing.
    [Fact]
    public void ARangeLimitOfOneIsAcceptedBySpec()
    {
        Assert.Equal(1, new TlsQuicConnectionSpec { AckRangeLimit = 1 }.AckRangeLimit);
    }

    // The knob s16 exists for: a longer-than-necessary encoding, on all three fields at once,
    // which is what a client whose Length field is not minimally encoded would set. Also pins
    // the member values to Table 4's byte counts, which the writer casts straight to a width.
    [Fact]
    public void NonMinimalVarintWidthsAreAcceptedOnAllThreeFields()
    {
        var spec = new TlsQuicConnectionSpec
        {
            HeaderLengthVarintWidth = TlsQuicVarintWidth.FourBytes,
            CryptoOffsetVarintWidth = TlsQuicVarintWidth.EightBytes,
            CryptoLengthVarintWidth = TlsQuicVarintWidth.TwoBytes,
        };

        Assert.Equal(4, (int)spec.HeaderLengthVarintWidth);
        Assert.Equal(8, (int)spec.CryptoOffsetVarintWidth);
        Assert.Equal(2, (int)spec.CryptoLengthVarintWidth);
        Assert.Equal(1, (int)TlsQuicVarintWidth.OneByte);
    }

    // SNAPSHOT, not RFC-derived: s19.6 puts no floor on a CRYPTO frame's Length, so this rule
    // is this file's own - a chunk that consumes nothing lets a flight plan declare progress
    // it does not make, and task 5 would loop.
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void CryptoChunkSizeBelowOneIsRejected(int size)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialCryptoFrameByteCounts = [1216, size],
            });
        Assert.Equal("InitialCryptoFrameByteCounts", error.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void DatagramCryptoFrameCountBelowOneIsRejected(int count)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialCryptoFramesPerDatagram = [1, count],
            });
        Assert.Equal("InitialCryptoFramesPerDatagram", error.ParamName);
    }

    // The cross-field rule, and it is reachable by two paths because an object initialiser
    // runs its setters in source order: whichever property is written second is the one that
    // sees both values. A check in only one setter passes one of these two tests and fails
    // the other, which is why both orders are here rather than one.
    [Fact]
    public void FrameCountsThatDoNotAccountForEveryChunkAreRejectedWhenTheChunksComeSecond()
    {
        var error = Assert.Throws<ArgumentException>(
            () => _ = new TlsQuicConnectionSpec
            {
                // [1] and not [1, 1]: with no byte-count list set yet the split is one frame,
                // so [1, 1] is rejected by the first setter and this test would stop
                // exercising the second-setter path it exists for.
                InitialCryptoFramesPerDatagram = [1],
                InitialCryptoFrameByteCounts = [1216, 400, 64],
            });
        Assert.Equal("InitialCryptoFrameByteCounts", error.ParamName);
    }

    [Fact]
    public void FrameCountsThatDoNotAccountForEveryChunkAreRejectedWhenTheCountsComeSecond()
    {
        var error = Assert.Throws<ArgumentException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialCryptoFrameByteCounts = [1216, 400, 64],
                InitialCryptoFramesPerDatagram = [1, 1],
            });
        Assert.Equal("InitialCryptoFramesPerDatagram", error.ParamName);
    }

    // THE OTHER SIDE OF THE SAME COMPARISON, and a mutation sweep found it missing: with only
    // the under-count rows above, weakening `planned != chunkSizes.Length` to `planned <
    // chunkSizes.Length` survived a green run. An over-count is just as reachable and just as
    // wrong - it tells a datagram to carry a CRYPTO frame the split never produced - so the
    // check is an equality and this is the row that says so.
    [Fact]
    public void FrameCountsThatClaimMoreChunksThanTheSplitProducesAreRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialCryptoFrameByteCounts = [1216, 400, 64],
                InitialCryptoFramesPerDatagram = [2, 2],
            });
        Assert.Equal("InitialCryptoFramesPerDatagram", error.ParamName);
    }

    // The two-datagram Initial a client capture forces: the X25519MLKEM768 key share is 1216
    // bytes, so a Chromium-shaped ClientHello splits, and the split and the per-datagram
    // grouping are independent choices. Here three CRYPTO frames are grouped two-then-one.
    [Fact]
    public void AFlightPlanWhoseCountsAccountForEveryChunkIsAccepted()
    {
        var spec = new TlsQuicConnectionSpec
        {
            InitialCryptoFrameByteCounts = [1216, 400, 64],
            InitialCryptoFramesPerDatagram = [2, 1],
        };

        Assert.Equal(new[] { 1216, 400, 64 }, spec.InitialCryptoFrameByteCounts);
        Assert.Equal(new[] { 2, 1 }, spec.InitialCryptoFramesPerDatagram);
    }

    // A byte-count list alone says nothing about grouping - any grouping of those frames is
    // legal - so it must not trip the cross-check. A datagram plan alone IS checked, against
    // the single frame an absent split implies, which is why [1] passes here and [1, 1] does
    // not; that half is the next test.
    [Fact]
    public void EitherHalfOfTheFlightPlanAloneIsAccepted()
    {
        Assert.Equal(
            new[] { 1216, 400 },
            new TlsQuicConnectionSpec { InitialCryptoFrameByteCounts = [1216, 400] }
                .InitialCryptoFrameByteCounts);
        Assert.Equal(
            new[] { 1 },
            new TlsQuicConnectionSpec { InitialCryptoFramesPerDatagram = [1] }
                .InitialCryptoFramesPerDatagram);
    }

    // THE ASYMMETRY BETWEEN THE TWO EMPTIES, and it was a real hole: an earlier revision
    // skipped the cross-check whenever either side was empty, so this spec was accepted while
    // the byte-count property documented an absent split as one frame. Two datagrams cannot
    // each carry a frame of a stream that was never split.
    [Fact]
    public void ADatagramPlanClaimingMoreFramesThanAnAbsentSplitImpliesIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialCryptoFramesPerDatagram = [1, 1],
            });
        Assert.Equal("InitialCryptoFramesPerDatagram", error.ParamName);
    }

    // default(ImmutableArray<T>) wraps a null array, so reading Length or an element throws
    // NullReferenceException. A hand-populated spec reaches it by leaving a field
    // uninitialised, and before these three rows the type answered with an NRE carrying no
    // ParamName - the one exception in .NET that says nothing about what the caller did.
    // Three rows because three properties take an array, and one shared helper guarding
    // three call sites is a guard reachable by three paths.
    [Fact]
    public void ADefaultValuedCryptoSplitIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialCryptoFrameByteCounts = default,
            });
        Assert.Equal("InitialCryptoFrameByteCounts", error.ParamName);
    }

    [Fact]
    public void ADefaultValuedDatagramFrameCountPlanIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialCryptoFramesPerDatagram = default,
            });
        Assert.Equal("InitialCryptoFramesPerDatagram", error.ParamName);
    }

    [Fact]
    public void ADefaultValuedFrameOrderIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialFrameOrder = default,
            });
        Assert.Equal("InitialFrameOrder", error.ParamName);
    }

    // The same reasoning the varint widths already carried, applied to this list: a C# enum
    // holds any value its underlying type can, and a cast from an arbitrary int is how a
    // hand-populated spec reaches it. 0x7fff is not a frame type RFC 9000 s19 defines.
    [Fact]
    public void AnUndefinedFrameTypeInTheOrderIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialFrameOrder = [TlsQuicFrameType.Crypto, (TlsQuicFrameType)0x7fff],
            });
        Assert.Equal("InitialFrameOrder", error.ParamName);
    }

    // SNAPSHOT: no RFC forbids naming a frame family twice in a priority list, because no RFC
    // knows about this list. A repeat makes the order it declares ambiguous, and an ambiguous
    // layout spec surfaces as a peer's complaint rather than as a local failure.
    [Fact]
    public void AFrameTypeRepeatedInTheOrderIsRejected()
    {
        var error = Assert.Throws<ArgumentException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialFrameOrder =
                [
                    TlsQuicFrameType.Crypto,
                    TlsQuicFrameType.Padding,
                    TlsQuicFrameType.Crypto,
                ],
            });
        Assert.Equal("InitialFrameOrder", error.ParamName);
    }

    [Fact]
    public void AFrameOrderWithoutRepeatsIsAccepted()
    {
        ImmutableArray<TlsQuicFrameType> order =
            [TlsQuicFrameType.Ack, TlsQuicFrameType.Crypto, TlsQuicFrameType.Padding];

        Assert.Equal(
            new[] { TlsQuicFrameType.Ack, TlsQuicFrameType.Crypto, TlsQuicFrameType.Padding },
            new TlsQuicConnectionSpec { InitialFrameOrder = order }.InitialFrameOrder);
    }

    // initial_rtt is a policy and never a pinned value; the range is what a per-connection
    // draw is taken from. Null stays legal because the repo has one observed sample and no
    // published range, and inventing bounds here would put an unsourced constant in the field
    // whose entire point is that a constant is itself a fingerprint.
    [Fact]
    public void AnInitialRttRangeIsOptionalAndKeptWhenGiven()
    {
        Assert.Null(new TlsQuicConnectionSpec().InitialRttRange);

        (TimeSpan Minimum, TimeSpan Maximum)? range =
            (TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(300));
        Assert.Equal(range, new TlsQuicConnectionSpec { InitialRttRange = range }.InitialRttRange);
    }

    [Fact]
    public void AnInitialRttRangeWithANonPositiveMinimumIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialRttRange = (TimeSpan.Zero, TimeSpan.FromMilliseconds(300)),
            });
        Assert.Equal("InitialRttRange", error.ParamName);
    }

    // A separate path from the one above: a positive minimum reaches the second comparison,
    // which the first would short-circuit if the range were inverted around zero.
    [Fact]
    public void AnInitialRttRangeWhoseMaximumIsBelowItsMinimumIsRejected()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => _ = new TlsQuicConnectionSpec
            {
                InitialRttRange = (TimeSpan.FromMilliseconds(300), TimeSpan.FromMilliseconds(100)),
            });
        Assert.Equal("InitialRttRange", error.ParamName);
    }

    // A degenerate range is a pinned value, which the field's whole documentation argues
    // against - but it is legal, and the guard must not quietly forbid it, because a spec
    // that wants a fixed initial_rtt for a deterministic test is a legitimate caller.
    [Fact]
    public void AnInitialRttRangeWithEqualBoundsIsAccepted()
    {
        // The number is the capture's single observed draw of 192859. Its UNIT IS NOT
        // STATED anywhere in the capture; microseconds is the reading that makes 192.859 ms
        // a plausible RTT, and it is an assumption, not ground truth. Nothing here depends
        // on it - the test only needs two equal TimeSpans - but do not treat this line as a
        // record of Chromium's units.
        (TimeSpan Minimum, TimeSpan Maximum)? range =
            (TimeSpan.FromMilliseconds(192.859), TimeSpan.FromMilliseconds(192.859));
        Assert.Equal(range, new TlsQuicConnectionSpec { InitialRttRange = range }.InitialRttRange);
    }

    // THE KNOB NOW HAS A CONSUMER, WHICH IS THE PART TASK B5 ADDED. This file's own standing
    // rule is that "a knob that accepts a value and ignores it is worse than an absent one",
    // and until B5 this field was accepted, validated and read by nothing. The consumer is
    // TlsQuicTransportParameterSpec.Compose, so the check is that a value set here changes a
    // byte there - asserted against the range object rather than against a literal, and with
    // a range disjoint from the parameter profile's own fallback so that an implementation
    // ignoring this field fails rather than overlapping into a pass.
    //
    // Nothing puts that composed set into a ClientHello yet; task B8 is what wires it.
    [Fact]
    public void TheInitialRttRangeIsReadByTheTransportParameterComposer()
    {
        var range = (Minimum: TimeSpan.FromMicroseconds(7000), Maximum: TimeSpan.FromMicroseconds(9000));
        var spec = new TlsQuicConnectionSpec { InitialRttRange = range };

        // THE SLOT HAS TO BE LISTED, because the library's default list no longer carries one:
        // it is RFC 9000 s7.3's single mandatory entry now that SharpTls ships no persona. What
        // this test is about is unchanged - a listed initial_rtt entry reads its range from the
        // CONNECTION spec rather than from the fallback beside it.
        var parameters = new TlsQuicTransportParameterSpec
        {
            Parameters =
            [
                TlsQuicTransportParameterSlot.Placed(
                    (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId),
                TlsQuicTransportParameterSpec.DrawnInitialRtt(
                    TlsQuicTransportParameterSpec.InitialRttIdentifier, null),
            ],
        };

        var parameter = parameters
            .Compose(spec, [])
            .Get(TlsQuicTransportParameterSpec.InitialRttIdentifier);

        Assert.NotNull(parameter);
        Assert.InRange(
            parameter.GetVariableInteger(),
            (ulong)(range.Minimum.Ticks / TimeSpan.TicksPerMicrosecond),
            (ulong)(range.Maximum.Ticks / TimeSpan.TicksPerMicrosecond));
    }

    // ---- C9's flow-control spec -------------------------------------------------------------

    // THE DEFECT ITSELF, WITNESSED DIRECTLY AND NOT THROUGH ITS FIX. Before C9 the live interop
    // test advertised exactly the two parameters below. Everything else about that ClientHello
    // was fine and the handshake completed, which is why it survived - the damage is entirely
    // in what is ABSENT, and s18.2 lines 62-64 make absent mean zero: "Transport parameters
    // have a default value of 0 if the transport parameter is absent, unless otherwise stated."
    //
    // Read through TlsQuicPeerFlowControlBudget because that is the type which answers "what
    // may the endpoint that received these do?", which is the question the defect got wrong.
    [Fact]
    public void AdvertisingOnlyTheTwoConnectionIdParametersLeavesEverySection182LimitAtZero()
    {
        var budget = TlsQuicPeerFlowControlBudget.FromPeerParameters(
            new TlsQuicTransportParameters(
            [
                TlsQuicTransportParameter.Empty(
                    TlsQuicTransportParameterId.InitialSourceConnectionId),
                TlsQuicTransportParameter.VariableInteger(
                    TlsQuicTransportParameterId.ActiveConnectionIdLimit, 2),
            ]));

        Assert.Equal(0UL, budget.InitialMaxData);
        Assert.Equal(0UL, budget.InitialMaxStreamDataBidiLocal);
        Assert.Equal(0UL, budget.InitialMaxStreamDataBidiRemote);
        Assert.Equal(0UL, budget.InitialMaxStreamDataUni);
        Assert.Equal(0UL, budget.InitialMaxStreamsBidi);
        Assert.Equal(0UL, budget.InitialMaxStreamsUni);

        // AND WHAT THAT COSTS. s18.2 line 139: "If this parameter is absent or zero, the peer
        // cannot open bidirectional streams until a MAX_STREAMS frame is sent." RFC 9114 s6.2
        // needs three unidirectional ones for HTTP/3, so a peer under these parameters cannot
        // start HTTP/3 at all - which is the failure the spike hit.
        Assert.NotNull(budget.DescribeSection62Violation(
            TlsQuicPeerFlowControlBudget.Http3RequiredUnidirectionalStreams));

        // The fix, read the same way: a spec whose six limits are SET emits six non-zero
        // values, and the violation goes.
        //
        // A BARE SPEC NO LONGER IS THAT FIX. TlsQuicLocalFlowControlSpec's six defaults are
        // s18.2's zero now that SharpTls ships no captured persona, so a bare one describes the
        // SAME violation as the two-parameter list above - which is the honest reading and the
        // reason the limits have to be named by whoever wants them.
        var fixedUp = TlsQuicPeerFlowControlBudget.FromPeerParameters(
            new TlsQuicTransportParameters(
                TestQuicSpecValues.HarnessFlowControl.ToTransportParameters()));
        Assert.Null(fixedUp.DescribeSection62Violation(
            TlsQuicPeerFlowControlBudget.Http3RequiredUnidirectionalStreams));
    }

    // The second spec-valued property on this type, and the reachability witness its guard is
    // owed. Both are here rather than in TlsQuicTransportParameterSpecTests because the guard
    // is TlsQuicConnectionSpec's.
    [Fact]
    public void TheTransportParameterListDefaultsToTheCapturePresetAndRejectsNull()
    {
        Assert.Equal(
            TlsQuicTransportParameterSpec.RfcMinimumParameters,
            new TlsQuicConnectionSpec().TransportParameters.Parameters);

        var error = Assert.Throws<ArgumentNullException>(
            () => new TlsQuicConnectionSpec { TransportParameters = null! });
        Assert.Equal("TransportParameters", error.ParamName);
    }

    // The two spec-valued properties are independent: setting one leaves the other's bytes
    // alone. A single backing field serving both would pass every test above and fail this.
    [Fact]
    public void TheTransportParameterListAndTheFlowControlSpecAreSeparateFields()
    {
        var spec = new TlsQuicConnectionSpec
        {
            LocalFlowControl = new TlsQuicLocalFlowControlSpec { InitialMaxData = 77 },
            TransportParameters = new TlsQuicTransportParameterSpec { Parameters = [] },
        };

        Assert.Equal(77UL, spec.LocalFlowControl.InitialMaxData);
        Assert.Empty(spec.TransportParameters.Parameters);
    }

    // ZERO, WHICH IS RFC 9000 s18.2's VALUE FOR AN ABSENT PARAMETER: "If this value is absent,
    // then the flow control limit is zero", and for the two counts "If this parameter is absent
    // or zero, the peer cannot open [streams] of the corresponding type."
    //
    // THESE SIX USED TO BE A CAPTURED BROWSER'S NUMBERS, shipped as the library default, which
    // meant a spec advertising none of the six still ENFORCED that browser's limits - the
    // advertise/enforce split TlsQuicLocalFlowControlSpec.AsAdvertisedBy exists to close.
    // Matching s18.2 makes the stored value and the enforced value agree by construction for a
    // spec that lists no slots, which the default parameter list now is.
    //
    // One assertion per parameter rather than one per spec, for the reason
    // TlsQuicConnectionFlowControlTests' header gives: six reads of the same shape need six
    // witnesses or a swapped pair is invisible.
    [Theory]
    [InlineData(TlsQuicTransportParameterId.InitialMaxData)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamDataUni)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamsBidi)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamsUni)]
    public void EveryFlowControlDefaultIsSectionEighteenTwosZero(TlsQuicTransportParameterId id)
    {
        var emitted = new TlsQuicTransportParameters(
            new TlsQuicConnectionSpec().LocalFlowControl.ToTransportParameters());
        Assert.Equal(0UL, emitted.Get((ulong)id)?.GetVariableInteger());
    }

    // THE REACHABILITY WITNESS PER FIELD, AND IT IS ABOUT THE BYTES. A knob that validates and
    // is then not emitted is the failure mode C9 exists to close, so the assertion is on the
    // ENCODED transport parameters and not on the property that was just set: each row changes
    // one limit, and the wire bytes must differ from the default spec's and carry the new value
    // under that row's own id. Deleting any one entry from ToTransportParameters kills exactly
    // that row.
    [Theory]
    [InlineData(TlsQuicTransportParameterId.InitialMaxData)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamDataUni)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamsBidi)]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamsUni)]
    public void ChangingOneFlowControlLimitChangesTheEmittedTransportParameterBytes(
        TlsQuicTransportParameterId id)
    {
        // 77 is below s19.11's 2^60 so it is legal for the two stream counts as well as for
        // the four byte limits, and it is not equal to any capture default, so every row is a
        // real change.
        const ulong Changed = 77;
        var baseline = new TlsQuicConnectionSpec().LocalFlowControl;
        var changed = Mutate(id, Changed);

        Assert.NotEqual(
            new TlsQuicTransportParameters(baseline.ToTransportParameters()).Encode(),
            new TlsQuicTransportParameters(changed.ToTransportParameters()).Encode());
        Assert.Equal(
            Changed,
            new TlsQuicTransportParameters(changed.ToTransportParameters())
                .Get((ulong)id)?.GetVariableInteger());
    }

    // s16's 2^62-1, which is the only bound s18.2 puts on the four byte-valued limits. Both
    // sides of it, so the guard cannot be off by one, and ParamName per row so that a guard
    // copied onto the wrong field fails rather than passes.
    [Theory]
    [InlineData(TlsQuicTransportParameterId.InitialMaxData, "InitialMaxData")]
    [InlineData(
        TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal,
        "InitialMaxStreamDataBidiLocal")]
    [InlineData(
        TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote,
        "InitialMaxStreamDataBidiRemote")]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamDataUni, "InitialMaxStreamDataUni")]
    public void AByteValuedFlowControlLimitPastTheVarintCeilingIsRejected(
        TlsQuicTransportParameterId id, string paramName)
    {
        Assert.Equal(QuicVariableLengthInteger.MaximumValue, Read(
            Mutate(id, QuicVariableLengthInteger.MaximumValue), id));

        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => Mutate(id, QuicVariableLengthInteger.MaximumValue + 1));
        Assert.Equal(paramName, error.ParamName);
    }

    // s19.11's 2^60, and "cannot exceed" makes 2^60 itself legal - the same reading
    // TlsQuicFlowControlFrames applies to the same constant, checked here so the two cannot
    // drift apart.
    [Theory]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamsBidi, "InitialMaxStreamsBidi")]
    [InlineData(TlsQuicTransportParameterId.InitialMaxStreamsUni, "InitialMaxStreamsUni")]
    public void AStreamCountLimitPastSection1911sCeilingIsRejected(
        TlsQuicTransportParameterId id, string paramName)
    {
        Assert.Equal(TlsQuicFlowControlFrames.MaximumStreamCount, Read(
            Mutate(id, TlsQuicFlowControlFrames.MaximumStreamCount), id));

        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => Mutate(id, TlsQuicFlowControlFrames.MaximumStreamCount + 1));
        Assert.Equal(paramName, error.ParamName);
    }

    // s18.2 scopes each per-stream parameter to one of s2.1's four stream types, and from the
    // SENDER's side - we send these, so they bound what arrives. The four rows are the four
    // types; getting any pair of them the wrong way round is invisible against a peer whose
    // limits are all equal, which the that client defaults are for three of the four.
    //
    // The values are distinct and each names its own parameter's id so a wrong read produces a
    // number that says where it came from, the convention TlsQuicConnectionFlowControlTests
    // set.
    [Theory]
    [InlineData(0UL, 5005UL)]
    [InlineData(1UL, 6006UL)]
    [InlineData(2UL, 0UL)]
    [InlineData(3UL, 7007UL)]
    public void ReceiveLimitForPicksTheParameterSection182ScopesToThatStreamType(
        ulong streamId, ulong expected)
    {
        // THE 0x02 ROW IS 0 AND THAT IS NOT A MISSING PARAMETER. s2.1's client-initiated
        // unidirectional stream is send-only for us, so no legal frame ever asks for its
        // receive limit; TlsQuicStreamSet refuses one with STREAM_STATE_ERROR before reaching
        // here. The row exists so the method is total rather than throwing on an id a
        // hand-built frame can carry.
        Assert.Equal(expected, new TlsQuicLocalFlowControlSpec
        {
            InitialMaxStreamDataBidiLocal = 5005,
            InitialMaxStreamDataBidiRemote = 6006,
            InitialMaxStreamDataUni = 7007,
        }.ReceiveLimitFor(streamId));
    }

    [Fact]
    public void ANullLocalFlowControlSpecIsRejectedRatherThanLeavingTheConnectionUnlimited()
    {
        // Reachable: the property is settable by subsystem B, and a null here would surface
        // much later as a NullReferenceException on the first received STREAM frame, on the
        // peer-input path TlsQuicStreams.cs keeps throw-free.
        var error = Assert.Throws<ArgumentNullException>(
            () => new TlsQuicConnectionSpec { LocalFlowControl = null! });
        Assert.Equal("LocalFlowControl", error.ParamName);
    }

    [Fact]
    public void ACallerSuppliedLocalFlowControlSpecIsTheOneTheSpecCarries()
    {
        var local = new TlsQuicLocalFlowControlSpec { InitialMaxData = 4242 };
        Assert.Same(local, new TlsQuicConnectionSpec { LocalFlowControl = local }.LocalFlowControl);
    }

    // One switch rather than six near-identical tests: every caller above needs "the same spec
    // with exactly one limit changed", and writing that out per row is where a copy-paste sets
    // the wrong field and the test still passes.
    private static TlsQuicLocalFlowControlSpec Mutate(
        TlsQuicTransportParameterId id, ulong value) => id switch
        {
            TlsQuicTransportParameterId.InitialMaxData =>
                new TlsQuicLocalFlowControlSpec { InitialMaxData = value },
            TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal =>
                new TlsQuicLocalFlowControlSpec { InitialMaxStreamDataBidiLocal = value },
            TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote =>
                new TlsQuicLocalFlowControlSpec { InitialMaxStreamDataBidiRemote = value },
            TlsQuicTransportParameterId.InitialMaxStreamDataUni =>
                new TlsQuicLocalFlowControlSpec { InitialMaxStreamDataUni = value },
            TlsQuicTransportParameterId.InitialMaxStreamsBidi =>
                new TlsQuicLocalFlowControlSpec { InitialMaxStreamsBidi = value },
            TlsQuicTransportParameterId.InitialMaxStreamsUni =>
                new TlsQuicLocalFlowControlSpec { InitialMaxStreamsUni = value },
            _ => throw new ArgumentOutOfRangeException(nameof(id), id, "Not one of the six."),
        };

    private static ulong? Read(TlsQuicLocalFlowControlSpec spec, TlsQuicTransportParameterId id) =>
        new TlsQuicTransportParameters(spec.ToTransportParameters())
            .Get((ulong)id)?.GetVariableInteger();
}
