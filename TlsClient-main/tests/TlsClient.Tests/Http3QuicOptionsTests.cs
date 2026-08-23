using System.Text;
using SharpTls;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace TlsClient.Tests;

/// <summary>
/// Covers <see cref="TlsSessionOptions.Quic"/> and <see cref="TlsSessionOptions.Http3"/>: that
/// the defaults put exactly the bytes on the wire they put before these options existed, and
/// that every knob a caller turns is witnessed by a change in those bytes.
/// </summary>
/// <remarks>
/// <para>THE DEFAULT PINS ARE THE POINT OF THIS FILE. Reachability was added on top of a
/// fingerprint that had already been measured against the reference endpoint, so the failure
/// mode that matters is not "a knob does nothing" but "adding the knob moved the default".
/// Every pin below compares against the exact expression <c>Http3Connection.CreateAsync</c>
/// used before the options existed — <c>new TlsQuicConnectionSpec { PaddingTarget = 1200 }</c>,
/// <c>new TlsQuicHttp3Spec()</c>, and the inline ClientHello lambda, restated in
/// <see cref="LegacyClientHello"/> — rather than against a number retyped from a capture.</para>
/// <para>WITNESSES ARE BYTES, NEVER PROPERTIES. A test that asserted
/// <c>options.Quic.PaddingTarget == 900</c> would pass against an implementation that stored
/// the value and never sent it, which is precisely the defect this whole change exists to fix.
/// Each knob test therefore encodes the thing the knob feeds and compares the encoding.</para>
/// </remarks>
public sealed class Http3QuicOptionsTests
{
    /// <summary>
    /// A fixed source connection ID, so a composition differs from another only where the spec
    /// says it should. Length is <c>TlsQuicConnectionSpec.SourceConnectionIdLength</c>'s default.
    /// </summary>
    private static readonly byte[] SourceConnectionId =
        [.. Enumerable.Repeat((byte)0xa7, new TlsQuicConnectionSpec().SourceConnectionIdLength)];

    /// <summary>
    /// The three Brave 151 identifiers whose values are redrawn per connection, derived rather
    /// than listed: whatever slots of the preset report <c>IsDrawn</c>. A test comparing two
    /// compositions byte for byte must skip exactly these and no others, and deriving them
    /// means a preset that starts drawing a fourth cannot silently widen the exemption.
    /// </summary>
    private static IReadOnlyList<int> DrawnIndices { get; } =
        [.. TlsQuicTransportParameterSpec.Brave151Parameters
            .Select((slot, index) => (slot, index))
            .Where(entry => entry.slot.IsDrawn)
            .Select(entry => entry.index)];

    // ------------------------------------------------------------------------------
    // The default fingerprint is byte-identical to what shipped before these options.
    // ------------------------------------------------------------------------------

    [Fact]
    public void DefaultTransportParameterSlots_AreThePresetItselfAndNotACopyOfIt()
    {
        // Slot equality compares the DRAW DELEGATE BY REFERENCE, so this passes only if the
        // three drawn slots travelled through TlsClient's option layer untouched. A layer that
        // re-created them — even from correct-looking code — would produce a different
        // delegate and fail here, which is what makes this a translation-loss check rather
        // than a value check.
        var snapshot = new TlsSessionOptions().Quic.TransportParameters.Snapshot();

        Assert.Equal<TlsQuicTransportParameterSlot>(
            [.. TlsQuicTransportParameterSpec.Brave151Parameters],
            [.. snapshot.Parameters]);

        // And the preset really does carry all three kinds, so the equality above is a claim
        // about literal, placed AND drawn slots rather than about fourteen placed ones.
        Assert.Equal(3, snapshot.Parameters.Count(slot => slot.IsDrawn));
        Assert.Equal(4, snapshot.Parameters.Count(slot => slot.HasLiteralValue));
        Assert.Equal(14, snapshot.Parameters.Length);
    }

    [Fact]
    public void DefaultComposedTransportParameters_EncodeToTheSameBytesAsTheOldHardCodedSpec()
    {
        // The old spec, exactly as Http3Connection.CreateAsync built it before TlsSessionOptions
        // could reach it.
        var legacy = new TlsQuicConnectionSpec { PaddingTarget = 1200 };
        var current = new TlsSessionOptions().Snapshot().Quic.ConnectionSpec;

        // Composed many times, because three entries redraw per composition: a single pass
        // would compare one sample of a set that differs every time. Every non-drawn entry
        // must agree on identifier, position and bytes on EVERY pass.
        for (var draw = 0; draw < 16; draw++)
        {
            var expected = legacy.TransportParameters.Compose(legacy, SourceConnectionId);
            var actual = current.TransportParameters.Compose(current, SourceConnectionId);

            Assert.Equal(expected.Parameters.Count, actual.Parameters.Count);
            for (var index = 0; index < expected.Parameters.Count; index++)
            {
                if (DrawnIndices.Contains(index))
                {
                    // Not compared by value — it is redrawn — but its LENGTH and position are
                    // still pinned, which is what the fingerprint's wire order records.
                    Assert.Equal(
                        expected.Parameters[index].Value.Length,
                        actual.Parameters[index].Value.Length);
                    continue;
                }
                Assert.Equal(expected.Parameters[index].Id, actual.Parameters[index].Id);
                Assert.Equal<byte[]>(
                    expected.Parameters[index].Value,
                    actual.Parameters[index].Value);
            }
        }
    }

    [Fact]
    public void DefaultConnectionSpec_MatchesTheOldHardCodedSpecPropertyForProperty()
    {
        var legacy = new TlsQuicConnectionSpec { PaddingTarget = 1200 };
        var current = new TlsSessionOptions().Snapshot().Quic.ConnectionSpec;

        Assert.Equal(legacy.SourceConnectionIdLength, current.SourceConnectionIdLength);
        Assert.Equal(legacy.DestinationConnectionIdLength, current.DestinationConnectionIdLength);
        Assert.Equal(legacy.InitialPacketNumber, current.InitialPacketNumber);
        Assert.Equal(legacy.PacketNumberEncodedLength, current.PacketNumberEncodedLength);
        Assert.Equal<byte>(legacy.Token.ToArray(), current.Token.ToArray());
        Assert.Equal(legacy.PaddingTarget, current.PaddingTarget);
        Assert.Equal<int>([.. legacy.InitialCryptoFrameByteCounts], [.. current.InitialCryptoFrameByteCounts]);
        Assert.Equal<int>(
            [.. legacy.InitialCryptoFramesPerDatagram],
            [.. current.InitialCryptoFramesPerDatagram]);
        Assert.Equal<TlsQuicFrameType>([.. legacy.InitialFrameOrder], [.. current.InitialFrameOrder]);
        Assert.Equal(legacy.HeaderLengthVarintWidth, current.HeaderLengthVarintWidth);
        Assert.Equal(legacy.CryptoOffsetVarintWidth, current.CryptoOffsetVarintWidth);
        Assert.Equal(legacy.CryptoLengthVarintWidth, current.CryptoLengthVarintWidth);
        Assert.Equal(legacy.InitialRttRange, current.InitialRttRange);
        Assert.Equal(legacy.AckRangeLimit, current.AckRangeLimit);
        Assert.Equal(legacy.CoalesceAscendingByLevel, current.CoalesceAscendingByLevel);
        Assert.Equal(legacy.AckLeadsInPacket, current.AckLeadsInPacket);

        // PaddingTarget is asserted above against the legacy spec, but the legacy spec's own
        // value came from a constant this change MOVED out of Http3Connection. Pin the number
        // too, so a future edit to that default is a deliberate act and not a silent one.
        Assert.Equal(1200, current.PaddingTarget);

        // The six flow-control limits reach the wire as the six Placed slots' values, so they
        // are compared through the parameters they produce rather than property by property.
        Assert.Equal<TlsQuicTransportParameter>(
            legacy.LocalFlowControl.ToTransportParameters(),
            current.LocalFlowControl.ToTransportParameters(),
            TransportParameterComparer.Instance);
    }

    [Fact]
    public void DefaultRecoverySpec_MatchesTheOldDefault()
    {
        var legacy = new TlsQuicRecoverySpec();
        var current = new TlsSessionOptions().Snapshot().Quic.ConnectionSpec.Recovery;

        Assert.Equal(legacy.InitialCongestionWindow, current.InitialCongestionWindow);
        Assert.Equal(
            legacy.MinimumCongestionWindowDatagrams,
            current.MinimumCongestionWindowDatagrams);
        Assert.Equal(legacy.LossReductionFactor, current.LossReductionFactor);
        Assert.Equal(legacy.PacketThreshold, current.PacketThreshold);
        Assert.Equal(legacy.TimeThreshold, current.TimeThreshold);
        Assert.Equal(legacy.PersistentCongestionThreshold, current.PersistentCongestionThreshold);
        Assert.Equal(legacy.PtoBackoff, current.PtoBackoff);
        Assert.Equal(legacy.ProbePacketsPerPto, current.ProbePacketsPerPto);
        Assert.Equal(legacy.ProbeContents, current.ProbeContents);
        Assert.Equal(legacy.AckPolicy, current.AckPolicy);
        Assert.Equal(legacy.PacingBurstDatagrams, current.PacingBurstDatagrams);
        Assert.Equal(legacy.PacingIntervalScale, current.PacingIntervalScale);
    }

    [Fact]
    public void DefaultHttp3Settings_EncodeToTheSameBytesAsABareSpec()
    {
        // The SETTINGS frame is the first thing HTTP/3 puts on the control stream and it is
        // fully determined by the spec — no draws — so this is an exact byte pin.
        Assert.Equal<byte>(
            EncodeSettings(new TlsQuicHttp3Spec()),
            EncodeSettings(new TlsSessionOptions().Snapshot().Quic.Http3Spec));
    }

    [Fact]
    public void DefaultHttp3Spec_MatchesTheOldDefaultOnEveryKnob()
    {
        var legacy = new TlsQuicHttp3Spec();
        var current = new TlsSessionOptions().Snapshot().Quic.Http3Spec;

        Assert.Equal<TlsQuicHttp3Setting>([.. legacy.Settings], [.. current.Settings]);
        Assert.Equal<TlsQuicHttp3StreamType>(
            [.. legacy.UnidirectionalStreamOpenOrder],
            [.. current.UnidirectionalStreamOpenOrder]);
        Assert.Equal<TlsQuicHttp3PseudoHeader>(
            [.. legacy.PseudoHeaderOrder],
            [.. current.PseudoHeaderOrder]);
        Assert.Equal(legacy.QpackHuffmanStringLiterals, current.QpackHuffmanStringLiterals);
        Assert.Equal(legacy.QpackNameMatchPolicy, current.QpackNameMatchPolicy);
        Assert.Equal(
            legacy.SendReservedFramesOnRequestStreams,
            current.SendReservedFramesOnRequestStreams);
        Assert.Equal(
            legacy.AllowDatagramSettingWithoutTransportParameter,
            current.AllowDatagramSettingWithoutTransportParameter);
    }

    [Fact]
    public void DefaultQuicClientHello_IsByteIdenticalToTheOldInlineLambda()
    {
        // BuildDeterministicForTesting removes the only source of variation a ClientHello has,
        // so two profiles that agree here agree byte for byte on the wire.
        var seed = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var configuration = new TlsSessionOptions().Snapshot().Quic;

        Assert.Equal<byte>(
            BuildHello(LegacyClientHello, seed),
            BuildHello(configuration.ConfigureClientHello, seed));

        // And the ALPN half, which the old code hard-coded to the single h3 token.
        Assert.Equal<string>(["h3"], configuration.AlpnProtocols);
    }

    // ------------------------------------------------------------------------------
    // Every knob is reachable, and the witness is a change in the bytes.
    // ------------------------------------------------------------------------------

    [Fact]
    public void ChangingAnHttp3SettingValue_ChangesTheEncodedSettingsFrame()
    {
        var options = new TlsSessionOptions();
        var before = EncodeSettings(options.Snapshot().Quic.Http3Spec);

        // MAX_FIELD_SECTION_SIZE, whose default the capture bounds. Read its current value and
        // move it, rather than asserting against a retyped number.
        var index = options.Http3.Settings
            .Select((setting, position) => (setting, position))
            .Single(entry => entry.setting.Identifier == 0x06)
            .position;
        var original = options.Http3.Settings[index];
        options.Http3.Settings[index] = original with { Value = original.Value + 1 };

        var after = EncodeSettings(options.Snapshot().Quic.Http3Spec);
        Assert.NotEqual<byte>(before, after);

        // The change is the one asked for and not merely "some difference": decode the frame
        // back and read the value out.
        Assert.Equal(
            original.Value + 1,
            DecodeSettings(after).Single(setting => setting.Identifier == 0x06).Value);
    }

    [Fact]
    public void ChangingTheHttp3SettingsOrder_ChangesTheEncodedSettingsFrame()
    {
        // The endpoint records settings sorted-or-not indistinguishably, but the BYTES still
        // differ, and it is the bytes this library promises to reproduce.
        var options = new TlsSessionOptions();
        var before = EncodeSettings(options.Snapshot().Quic.Http3Spec);

        options.Http3.Settings = [.. options.Http3.Settings.Reverse()];
        var after = EncodeSettings(options.Snapshot().Quic.Http3Spec);

        Assert.NotEqual<byte>(before, after);
        Assert.Equal(
            Enumerable.Reverse(DecodeSettings(before)),
            DecodeSettings(after));
    }

    [Fact]
    public void ChangingAnHttp3PseudoHeaderOrder_ReachesTheSpec()
    {
        var options = new TlsSessionOptions();
        options.Http3.PseudoHeaderOrder =
            [TlsHttp3PseudoHeader.Path, TlsHttp3PseudoHeader.Scheme,
             TlsHttp3PseudoHeader.Authority, TlsHttp3PseudoHeader.Method];

        Assert.Equal<TlsQuicHttp3PseudoHeader>(
            [TlsQuicHttp3PseudoHeader.Path, TlsQuicHttp3PseudoHeader.Scheme,
             TlsQuicHttp3PseudoHeader.Authority, TlsQuicHttp3PseudoHeader.Method],
            [.. options.Snapshot().Quic.Http3Spec.PseudoHeaderOrder]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void QpackKnobs_ReachTheSpec(bool flipped)
    {
        var options = new TlsSessionOptions();
        var baseline = new TlsQuicHttp3Spec();
        options.Http3.QpackHuffmanStringLiterals =
            flipped != baseline.QpackHuffmanStringLiterals;
        options.Http3.QpackNameMatchPolicy = flipped
            ? TlsQpackNameMatchPolicy.LiteralName
            : TlsQpackNameMatchPolicy.NameReference;
        options.Http3.SendReservedFramesOnRequestStreams = flipped;
        options.Http3.UnidirectionalStreamOpenOrder =
            [.. options.Http3.UnidirectionalStreamOpenOrder.Reverse()];

        var spec = options.Snapshot().Quic.Http3Spec;
        Assert.Equal(
            flipped != baseline.QpackHuffmanStringLiterals,
            spec.QpackHuffmanStringLiterals);
        Assert.Equal(
            flipped ? TlsQuicQpackNameMatchPolicy.LiteralName
                : TlsQuicQpackNameMatchPolicy.NameReference,
            spec.QpackNameMatchPolicy);
        Assert.Equal(flipped, spec.SendReservedFramesOnRequestStreams);
        Assert.Equal<TlsQuicHttp3StreamType>(
            [.. Enumerable.Reverse(baseline.UnidirectionalStreamOpenOrder)],
            [.. spec.UnidirectionalStreamOpenOrder]);
    }

    [Fact]
    public void ChangingATransportParameterValue_ChangesTheComposedBytes()
    {
        var options = new TlsSessionOptions();
        var before = ComposeComparable(options);

        // max_datagram_frame_size, one of the four literal entries. Its position is left alone
        // so this is a test about the VALUE and not about order.
        var index = options.Quic.TransportParameters.Entries
            .Select((entry, position) => (entry, position))
            .Single(candidate =>
                candidate.entry.Id ==
                    (ulong)TlsQuicTransportParameterId.MaxDatagramFrameSize)
            .position;
        options.Quic.TransportParameters.Entries[index] =
            TlsQuicTransportParameterEntry.Literal(
                (ulong)TlsQuicTransportParameterId.MaxDatagramFrameSize,
                QuicVariableLengthInteger.Encode(1337));

        var after = ComposeComparable(options);
        Assert.NotEqual(before, after);

        // Exactly those bytes, at that identifier, and the identifier ORDER is untouched.
        var composed = Compose(options);
        Assert.Equal<byte>(
            QuicVariableLengthInteger.Encode(1337),
            composed.Get((ulong)TlsQuicTransportParameterId.MaxDatagramFrameSize)!.Value);
        Assert.Equal(Identifiers(new TlsSessionOptions()), Identifiers(options));
    }

    [Fact]
    public void ReversingTheTransportParameterWireOrder_ReversesTheComposedOrder()
    {
        // WIRE ORDER IS THE HASHED PART. The reference endpoint publishes perk_hash over raw
        // wire order and perk_hash_normalized over the sorted set, so a reordering that left
        // the bytes alone would be a silent loss of the capability this API exists for.
        var options = new TlsSessionOptions();
        var before = Identifiers(options);

        options.Quic.TransportParameters.Entries =
            [.. options.Quic.TransportParameters.Entries.Reverse()];
        var after = Identifiers(options);

        Assert.Equal(Enumerable.Reverse(before), after);

        // The encoded bytes really moved, and the SET is unchanged — which is what makes this
        // a reordering rather than a different parameter set.
        Assert.NotEqual(ComposeComparable(options), ComposeComparable(new TlsSessionOptions()));
        Assert.Equal(before.Order(), after.Order());
        Assert.Equal(14, after.Length);
    }

    [Fact]
    public void AnIdentifierSharpTlsHasNeverSeen_IsEmittedVerbatimAtItsListedPosition()
    {
        // 0x4a4a4a4a is in no registry, is not one of the seven the composer places, and is not
        // reserved under RFC 9000 s18.1's "31 * N + 27" form — asserted rather than assumed, so
        // this cannot accidentally become a test about the GREASE slot.
        const ulong Unknown = 0x4a4a4a4a;
        byte[] payload = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f];
        Assert.False(TlsQuicTransportParameterSpec.IsReservedIdentifier(Unknown));

        var options = new TlsSessionOptions();
        options.Quic.TransportParameters.Entries.Insert(
            3,
            TlsQuicTransportParameterEntry.Literal(Unknown, payload));

        var composed = Compose(options);
        Assert.Equal(15, composed.Parameters.Count);
        Assert.Equal(Unknown, composed.Parameters[3].Id);
        Assert.Equal<byte>(payload, composed.Parameters[3].Value);

        // At the listed index and NOT merely somewhere: an implementation that appended it
        // would satisfy "the bytes came out" but not this.
        Assert.Equal([3], composed.Parameters
            .Select((parameter, position) => (parameter, position))
            .Where(entry => entry.parameter.Id == Unknown)
            .Select(entry => entry.position));
    }

    [Fact]
    public void AnEntryMayBeDrawnPerConnection_AndIsNeverCached()
    {
        // One options object, many compositions — a draw cached at snapshot time is exactly
        // the defect this shape exists to prevent.
        var counter = 0;
        var options = new TlsSessionOptions();
        options.Quic.TransportParameters.Entries =
        [
            TlsQuicTransportParameterEntry.Drawn(
                0x4a4a4a4a,
                () => BitConverter.GetBytes(Interlocked.Increment(ref counter))),
        ];
        var spec = options.Snapshot().Quic.ConnectionSpec;

        var first = spec.TransportParameters.Compose(spec, SourceConnectionId);
        var second = spec.TransportParameters.Compose(spec, SourceConnectionId);

        Assert.NotEqual<byte>(first.Parameters[0].Value, second.Parameters[0].Value);
        Assert.Equal(2, counter);
    }

    [Fact]
    public void ADrawnEntryReturningNull_OmitsItselfRatherThanThrowing()
    {
        var options = new TlsSessionOptions();
        options.Quic.TransportParameters.Entries =
        [
            TlsQuicTransportParameterEntry.Literal(0x4a4a4a4a, [0x01]),
            TlsQuicTransportParameterEntry.Drawn(0x4a4a4a4b, () => null),
        ];

        var composed = Compose(options);
        Assert.Equal([0x4a4a4a4aul], composed.Parameters.Select(parameter => parameter.Id));
    }

    [Fact]
    public void ChangingAFlowControlLimit_ChangesThePlacedParametersValue()
    {
        var options = new TlsSessionOptions();
        var original = options.Quic.FlowControl.InitialMaxStreamsBidi;
        options.Quic.FlowControl.InitialMaxStreamsBidi = original + 7;

        var composed = Compose(options);
        Assert.Equal(
            original + 7,
            composed.Get((ulong)TlsQuicTransportParameterId.InitialMaxStreamsBidi)!
                .GetVariableInteger());
    }

    [Fact]
    public void ChangingThePaddingTargetAndConnectionIdLength_ReachesTheConnectionSpec()
    {
        var options = new TlsSessionOptions();
        options.Quic.PaddingTarget = 1357;
        options.Quic.SourceConnectionIdLength = 12;

        var spec = options.Snapshot().Quic.ConnectionSpec;
        Assert.Equal(1357, spec.PaddingTarget);
        Assert.Equal(12, spec.SourceConnectionIdLength);

        // The connection ID length is not merely stored: it is what initial_source_connection_id
        // carries, so a 12-byte source ID must produce a 12-byte parameter value.
        var composed = spec.TransportParameters.Compose(
            spec,
            [.. Enumerable.Repeat((byte)0x5a, 12)]);
        Assert.Equal(
            12,
            composed.Get((ulong)TlsQuicTransportParameterId.InitialSourceConnectionId)!
                .Value.Length);
    }

    [Fact]
    public void ChangingRecoveryKnobs_ReachesTheRecoverySpec()
    {
        var options = new TlsSessionOptions();
        options.Quic.Recovery.PacketThreshold = 5;
        options.Quic.Recovery.ProbeContents = TlsQuicProbeContents.PingWithPadding;
        options.Quic.Recovery.AckPolicy = TlsQuicAckPolicy.DelayedToMaxAckDelay;
        options.Quic.Recovery.PacingBurstDatagrams = null;
        options.Quic.Recovery.InitialCongestionWindow = (7, 9000);

        var recovery = options.Snapshot().Quic.ConnectionSpec.Recovery;
        Assert.Equal(5, recovery.PacketThreshold);
        Assert.Equal(SharpTls.Quic.TlsQuicProbeContents.PingWithPadding, recovery.ProbeContents);
        Assert.Equal(
            SharpTls.Quic.TlsQuicAckPolicy.DelayedToMaxAckDelay,
            recovery.AckPolicy);
        Assert.Null(recovery.PacingBurstDatagrams);
        Assert.Equal((7, 9000), recovery.InitialCongestionWindow);
    }

    [Fact]
    public void ChangingTheQuicClientHello_ChangesTheClientHelloBytes()
    {
        // The TLS half of the h3 handshake, which options.Profile does not and must not drive.
        var seed = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var options = new TlsSessionOptions();
        var before = BuildHello(options.Snapshot().Quic.ConfigureClientHello, seed);

        options.Quic.ConfigureClientHello = builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsChaCha20Poly1305Sha256)
            .WithSupportedGroups(NamedGroup.X25519)
            .WithKeyShares(NamedGroup.X25519);
        var after = BuildHello(options.Snapshot().Quic.ConfigureClientHello, seed);

        Assert.NotEqual<byte>(before, after);

        // Extending rather than replacing: the documented way to keep the default and add to it.
        options.Quic.ConfigureClientHello = builder =>
        {
            TlsQuicOptions.ApplyDefaultClientHello(builder);
            builder.WithKeyShares(NamedGroup.X25519, NamedGroup.Secp256r1);
        };
        var extended = BuildHello(options.Snapshot().Quic.ConfigureClientHello, seed);
        Assert.NotEqual<byte>(before, extended);
        Assert.NotEqual<byte>(after, extended);
    }

    [Fact]
    public void ChangingTheQuicAlpn_ReachesTheConfiguration()
    {
        var options = new TlsSessionOptions();
        options.Quic.AlpnProtocols = ["h3", "h3-29"];
        Assert.Equal<string>(["h3", "h3-29"], options.Snapshot().Quic.AlpnProtocols);
    }

    // ------------------------------------------------------------------------------
    // Nothing crashes; bad input is rejected by name.
    // ------------------------------------------------------------------------------

    [Fact]
    public void ANullEntryInTheParameterList_IsRejectedByNameAndIndex()
    {
        var options = new TlsSessionOptions();
        options.Quic.TransportParameters.Entries[2] = null!;

        var error = Assert.Throws<ArgumentException>(() => options.Snapshot());
        Assert.Equal("Entries", error.ParamName);
        Assert.Contains("[2]", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(99)]
    public void AnUndeclaredEnumValue_IsRejectedByNameRatherThanCastBlindly(int value)
    {
        // 0 is Minimal and IS declared, so it must be accepted; the other two must not. One
        // theory covers both directions so a guard that always threw would fail. The rejection
        // comes from TlsQuicConnectionSpec.ValidateVarintWidth, which uses this same paramName;
        // TlsClient deliberately adds no second guard.
        var options = new TlsSessionOptions();
        options.Quic.HeaderLengthVarintWidth = (TlsQuicVarintWidth)value;

        if (Enum.IsDefined((TlsQuicVarintWidth)value))
        {
            Assert.Equal(
                (SharpTls.Quic.TlsQuicVarintWidth)value,
                options.Snapshot().Quic.ConnectionSpec.HeaderLengthVarintWidth);
            return;
        }
        var error = Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
        Assert.Equal("HeaderLengthVarintWidth", error.ParamName);
    }

    [Fact]
    public void AnOutOfRangePaddingTarget_IsRejectedRatherThanTruncated()
    {
        var options = new TlsSessionOptions();
        options.Quic.PaddingTarget = 3;
        Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
    }

    [Fact]
    public void ANullOrEmptyAlpnToken_IsRejectedByName()
    {
        var options = new TlsSessionOptions();
        options.Quic.AlpnProtocols = ["h3", ""];

        var error = Assert.Throws<ArgumentException>(() => options.Snapshot());
        Assert.Equal("AlpnProtocols", error.ParamName);
    }

    [Fact]
    public void ANullList_IsRejectedByNameRatherThanThrowingNullReference()
    {
        Assert.Equal(
            "Settings",
            Assert.Throws<ArgumentNullException>(() =>
            {
                var options = new TlsSessionOptions();
                options.Http3.Settings = null!;
                options.Snapshot();
            }).ParamName);

        Assert.Equal(
            "Entries",
            Assert.Throws<ArgumentNullException>(() =>
            {
                var options = new TlsSessionOptions();
                options.Quic.TransportParameters.Entries = null!;
                options.Snapshot();
            }).ParamName);
    }

    [Fact]
    public void ADuplicateIdentifier_IsRejectedAsRfc9000Section18Requires()
    {
        var options = new TlsSessionOptions();
        options.Quic.TransportParameters.Entries =
        [
            TlsQuicTransportParameterEntry.Literal(0x4a4a4a4a, [0x01]),
            TlsQuicTransportParameterEntry.Literal(0x4a4a4a4a, [0x02]),
        ];

        Assert.ThrowsAny<ArgumentException>(() => Compose(options));
    }

    [Fact]
    public void AnEmptyParameterList_IsAcceptedForAClientThatReallySendsNone()
    {
        var options = new TlsSessionOptions();
        options.Quic.TransportParameters.Entries = [];
        options.Http3.Settings = [];

        Assert.Empty(Compose(options).Parameters);
        Assert.Empty(options.Snapshot().Quic.Http3Spec.Settings);
    }

    [Fact]
    public void TwoSessionsOptions_DoNotShareTheirDefaultLists()
    {
        // The defaults are read from an immutable SharpTls preset, but the IList wrappers must
        // be per-instance or one session's edit would silently move another's fingerprint.
        var first = new TlsSessionOptions();
        var second = new TlsSessionOptions();
        first.Http3.Settings.Clear();
        first.Quic.TransportParameters.Entries.Clear();
        first.Quic.FlowControl.InitialMaxData = 1;

        Assert.NotEmpty(second.Http3.Settings);
        Assert.Equal(14, second.Quic.TransportParameters.Entries.Count);
        Assert.NotEqual(1ul, second.Quic.FlowControl.InitialMaxData);
    }

    [Fact]
    public void EveryConnectionSpecKnob_CarriesTheCallersValueAndNotTheDefault()
    {
        // ONE TEST FOR ALL OF THEM ON PURPOSE. Most of these are pass-throughs, and the defect
        // they share is a single one: an option that is read, stored and then dropped on the
        // way into the spec. A per-knob test would be the same assertion twenty times; what
        // matters is that EVERY knob is covered, because the one that is not is the one that
        // silently stops working. Each value below is chosen to differ from the default, and
        // the differ-from-default part is asserted rather than assumed.
        var defaults = new TlsQuicConnectionSpec();
        var options = new TlsSessionOptions();

        options.Quic.SourceConnectionIdLength = 13;
        options.Quic.DestinationConnectionIdLength = 17;
        options.Quic.InitialPacketNumber = 42;
        options.Quic.PacketNumberEncodedLength = 2;
        options.Quic.Token = new byte[] { 0x01, 0x02, 0x03 };
        options.Quic.PaddingTarget = 1301;
        options.Quic.InitialCryptoFrameByteCounts = [100, 200];
        options.Quic.InitialCryptoFramesPerDatagram = [2];
        // Reversed against the default, which really is Crypto-then-Padding — the first
        // attempt at this test used the default order by accident and its own
        // differ-from-default assertion caught it.
        options.Quic.InitialFrameOrder =
            [(ulong)TlsQuicFrameType.Padding, (ulong)TlsQuicFrameType.Crypto];
        options.Quic.HeaderLengthVarintWidth = TlsQuicVarintWidth.FourBytes;
        options.Quic.CryptoOffsetVarintWidth = TlsQuicVarintWidth.TwoBytes;
        options.Quic.CryptoLengthVarintWidth = TlsQuicVarintWidth.EightBytes;
        options.Quic.InitialRttRange = (TimeSpan.FromMilliseconds(11), TimeSpan.FromMilliseconds(97));
        options.Quic.AckRangeLimit = 7;
        options.Quic.CoalesceAscendingByLevel = !defaults.CoalesceAscendingByLevel;
        options.Quic.AckLeadsInPacket = !defaults.AckLeadsInPacket;

        var spec = options.Snapshot().Quic.ConnectionSpec;

        Assert.Equal(13, spec.SourceConnectionIdLength);
        Assert.Equal(17, spec.DestinationConnectionIdLength);
        Assert.Equal(42ul, spec.InitialPacketNumber);
        Assert.Equal(2, spec.PacketNumberEncodedLength);
        Assert.Equal<byte>([0x01, 0x02, 0x03], spec.Token.ToArray());
        Assert.Equal(1301, spec.PaddingTarget);
        Assert.Equal<int>([100, 200], [.. spec.InitialCryptoFrameByteCounts]);
        Assert.Equal<int>([2], [.. spec.InitialCryptoFramesPerDatagram]);
        Assert.Equal<TlsQuicFrameType>(
            [TlsQuicFrameType.Padding, TlsQuicFrameType.Crypto],
            [.. spec.InitialFrameOrder]);
        Assert.Equal(SharpTls.Quic.TlsQuicVarintWidth.FourBytes, spec.HeaderLengthVarintWidth);
        Assert.Equal(SharpTls.Quic.TlsQuicVarintWidth.TwoBytes, spec.CryptoOffsetVarintWidth);
        Assert.Equal(SharpTls.Quic.TlsQuicVarintWidth.EightBytes, spec.CryptoLengthVarintWidth);
        Assert.Equal(
            (TimeSpan.FromMilliseconds(11), TimeSpan.FromMilliseconds(97)),
            spec.InitialRttRange);
        Assert.Equal(7, spec.AckRangeLimit);
        Assert.Equal(!defaults.CoalesceAscendingByLevel, spec.CoalesceAscendingByLevel);
        Assert.Equal(!defaults.AckLeadsInPacket, spec.AckLeadsInPacket);

        // Every one of those really is a change. Without this, a knob whose "new" value equals
        // the default would be asserted successfully by an implementation that ignored it.
        Assert.NotEqual(defaults.SourceConnectionIdLength, spec.SourceConnectionIdLength);
        Assert.NotEqual(defaults.DestinationConnectionIdLength, spec.DestinationConnectionIdLength);
        Assert.NotEqual(defaults.InitialPacketNumber, spec.InitialPacketNumber);
        Assert.NotEqual(defaults.PacketNumberEncodedLength, spec.PacketNumberEncodedLength);
        Assert.NotEqual<byte>(defaults.Token.ToArray(), spec.Token.ToArray());
        Assert.NotEqual(defaults.PaddingTarget, spec.PaddingTarget);
        Assert.NotEqual<int>(
            [.. defaults.InitialCryptoFrameByteCounts],
            [.. spec.InitialCryptoFrameByteCounts]);
        Assert.NotEqual<int>(
            [.. defaults.InitialCryptoFramesPerDatagram],
            [.. spec.InitialCryptoFramesPerDatagram]);
        Assert.NotEqual<TlsQuicFrameType>(
            [.. defaults.InitialFrameOrder],
            [.. spec.InitialFrameOrder]);
        Assert.NotEqual(defaults.HeaderLengthVarintWidth, spec.HeaderLengthVarintWidth);
        Assert.NotEqual(defaults.CryptoOffsetVarintWidth, spec.CryptoOffsetVarintWidth);
        Assert.NotEqual(defaults.CryptoLengthVarintWidth, spec.CryptoLengthVarintWidth);
        Assert.NotEqual(defaults.InitialRttRange, spec.InitialRttRange);
        Assert.NotEqual(defaults.AckRangeLimit, spec.AckRangeLimit);
    }

    [Fact]
    public void EveryFlowControlLimit_CarriesTheCallersValueAndNotTheDefault()
    {
        var defaults = new TlsQuicLocalFlowControlSpec();
        var options = new TlsSessionOptions();
        options.Quic.FlowControl.InitialMaxData = defaults.InitialMaxData + 1;
        options.Quic.FlowControl.InitialMaxStreamDataBidiLocal =
            defaults.InitialMaxStreamDataBidiLocal + 2;
        options.Quic.FlowControl.InitialMaxStreamDataBidiRemote =
            defaults.InitialMaxStreamDataBidiRemote + 3;
        options.Quic.FlowControl.InitialMaxStreamDataUni = defaults.InitialMaxStreamDataUni + 4;
        options.Quic.FlowControl.InitialMaxStreamsBidi = defaults.InitialMaxStreamsBidi + 5;
        options.Quic.FlowControl.InitialMaxStreamsUni = defaults.InitialMaxStreamsUni + 6;

        // Read back through the transport parameters, which is how these six reach the wire.
        var composed = Compose(options);
        ulong Value(TlsQuicTransportParameterId id) =>
            composed.Get((ulong)id)!.GetVariableInteger();

        Assert.Equal(
            defaults.InitialMaxData + 1,
            Value(TlsQuicTransportParameterId.InitialMaxData));
        Assert.Equal(
            defaults.InitialMaxStreamDataBidiLocal + 2,
            Value(TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal));
        Assert.Equal(
            defaults.InitialMaxStreamDataBidiRemote + 3,
            Value(TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote));
        Assert.Equal(
            defaults.InitialMaxStreamDataUni + 4,
            Value(TlsQuicTransportParameterId.InitialMaxStreamDataUni));
        Assert.Equal(
            defaults.InitialMaxStreamsBidi + 5,
            Value(TlsQuicTransportParameterId.InitialMaxStreamsBidi));
        Assert.Equal(
            defaults.InitialMaxStreamsUni + 6,
            Value(TlsQuicTransportParameterId.InitialMaxStreamsUni));
    }

    [Fact]
    public void EveryRecoveryKnob_CarriesTheCallersValueAndNotTheDefault()
    {
        var defaults = new TlsQuicRecoverySpec();

        // DERIVED FROM THE DEFAULT RATHER THAN NAMED, which is what every numeric knob in this
        // test already does (`defaults.PacketThreshold + 1`, `defaults.TimeThreshold + 0.5`).
        // This row used to name RetransmittedData outright and went red the moment SharpTls
        // task A3-14 made RetransmittedData the shipped default: the assertions at the foot of
        // this test are that the caller's value is NOT the default, so a literal here is
        // coupled to that default for ever and this collision was only a matter of time.
        // Correct for whichever of the three members ships, and it never picks the default.
        var probeContents = defaults.ProbeContents == SharpTls.Quic.TlsQuicProbeContents.Ping
            ? TlsQuicProbeContents.RetransmittedData
            : TlsQuicProbeContents.Ping;

        var options = new TlsSessionOptions();
        options.Quic.Recovery.InitialCongestionWindow = (7, 9000);
        options.Quic.Recovery.MinimumCongestionWindowDatagrams =
            defaults.MinimumCongestionWindowDatagrams + 1;
        options.Quic.Recovery.LossReductionFactor = 0.75;
        options.Quic.Recovery.PacketThreshold = defaults.PacketThreshold + 1;
        options.Quic.Recovery.TimeThreshold = defaults.TimeThreshold + 0.5;
        options.Quic.Recovery.PersistentCongestionThreshold =
            defaults.PersistentCongestionThreshold + 1;
        options.Quic.Recovery.PtoBackoff = (3.0, TimeSpan.FromSeconds(11));
        options.Quic.Recovery.ProbePacketsPerPto = 1;
        options.Quic.Recovery.ProbeContents = probeContents;
        options.Quic.Recovery.AckPolicy = TlsQuicAckPolicy.DelayedToMaxAckDelay;
        options.Quic.Recovery.PacingBurstDatagrams = null;
        options.Quic.Recovery.PacingIntervalScale = defaults.PacingIntervalScale + 0.5;

        var recovery = options.Snapshot().Quic.ConnectionSpec.Recovery;

        Assert.Equal((7, 9000), recovery.InitialCongestionWindow);
        Assert.Equal(
            defaults.MinimumCongestionWindowDatagrams + 1,
            recovery.MinimumCongestionWindowDatagrams);
        Assert.Equal(0.75, recovery.LossReductionFactor);
        Assert.Equal(defaults.PacketThreshold + 1, recovery.PacketThreshold);
        Assert.Equal(defaults.TimeThreshold + 0.5, recovery.TimeThreshold);
        Assert.Equal(
            defaults.PersistentCongestionThreshold + 1,
            recovery.PersistentCongestionThreshold);
        Assert.Equal((3.0, (TimeSpan?)TimeSpan.FromSeconds(11)), recovery.PtoBackoff);
        Assert.Equal(1, recovery.ProbePacketsPerPto);
        Assert.Equal(
            (SharpTls.Quic.TlsQuicProbeContents)probeContents,
            recovery.ProbeContents);
        Assert.Equal(
            SharpTls.Quic.TlsQuicAckPolicy.DelayedToMaxAckDelay,
            recovery.AckPolicy);
        Assert.Null(recovery.PacingBurstDatagrams);
        Assert.Equal(defaults.PacingIntervalScale + 0.5, recovery.PacingIntervalScale);

        Assert.NotEqual(defaults.InitialCongestionWindow, recovery.InitialCongestionWindow);
        Assert.NotEqual(defaults.LossReductionFactor, recovery.LossReductionFactor);
        Assert.NotEqual(defaults.PtoBackoff, recovery.PtoBackoff);
        Assert.NotEqual(defaults.ProbePacketsPerPto, recovery.ProbePacketsPerPto);
        Assert.NotEqual(defaults.ProbeContents, recovery.ProbeContents);
        Assert.NotEqual(defaults.AckPolicy, recovery.AckPolicy);
        Assert.NotEqual(defaults.PacingBurstDatagrams, recovery.PacingBurstDatagrams);
        Assert.NotEqual(defaults.PacingIntervalScale, recovery.PacingIntervalScale);
    }

    [Fact]
    public void EveryRecoveryKnobSharpTlsDeclares_IsSettableFromTlsClient()
    {
        // THE ORDERING HAZARD THIS TEST EXISTS FOR. TlsQuicRecoveryOptions was written before
        // SharpTls task A3-11 added PacingIntervalScale, so the knob existed on the spec and
        // was unreachable from here for four commits. Enumerating the spec means the next knob
        // SharpTls adds fails this test instead of being silently invisible.
        //
        // CongestionController is the one deliberate exclusion: its type is
        // Func<ITlsQuicCongestionController>? and ITlsQuicCongestionController is internal to
        // SharpTls, so it cannot appear on a public TlsClient API until SharpTls makes the
        // interface public. TlsQuicRecoveryOptions' own remarks say so.
        var reachable = typeof(TlsQuicRecoveryOptions)
            .GetProperties()
            .Where(property => property.CanWrite)
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);

        var unreachable = typeof(TlsQuicRecoverySpec)
            .GetProperties()
            .Where(property => property.SetMethod is not null)
            .Select(property => property.Name)
            .Where(name => name != nameof(TlsQuicRecoverySpec.CongestionController))
            .Where(name => !reachable.Contains(name))
            .ToArray();

        Assert.Empty(unreachable);

        // The exclusion is asserted rather than assumed, so it stops being an exclusion the
        // moment SharpTls makes the interface public.
        Assert.False(
            typeof(TlsQuicRecoverySpec)
                .GetProperty(nameof(TlsQuicRecoverySpec.CongestionController))!
                .PropertyType.GenericTypeArguments[0]
                .IsPublic);
    }

    [Fact]
    public void TheDefaultPerkHash_IsBrave151s()
    {
        // BYTE IDENTITY, PINNED AT THE FINGERPRINT AND NOT AT THE PROPERTY. Every default on
        // TlsQuicOptions is read from a freshly constructed SharpTls spec, so a default cannot
        // drift by being re-typed - but a default can still drift by SharpTls changing, and
        // this is the assertion that notices. The string and the hash are the 2026-08-16
        // fp.impersonate.pro capture of Brave 151, reproduced in
        // SharpTls/docs/superpowers/specs/reference-captures/.
        //
        // The four segments are h3 SETTINGS, pseudo-header order, transport parameters IN WIRE
        // ORDER, and the connection-ID length pair - all four rendered from the snapshot, so a
        // reordering or a changed value moves the hash exactly as the live service would.
        var options = new TlsSessionOptions();
        var snapshot = options.Snapshot();
        var connection = snapshot.Quic.ConnectionSpec;
        var http3 = snapshot.Quic.Http3Spec;

        var settings = string.Join(
            ';',
            http3.Settings.Select(setting =>
                TlsQuicHttp3Frames.IsReservedIdentifier(setting.Identifier)
                    ? "GREASE"
                    : $"{setting.Identifier}:{setting.Value}"));

        var pseudoHeaders = string.Join(
            ',',
            http3.PseudoHeaderOrder.Select(header => header switch
            {
                TlsQuicHttp3PseudoHeader.Method => "m",
                TlsQuicHttp3PseudoHeader.Authority => "a",
                TlsQuicHttp3PseudoHeader.Scheme => "s",
                _ => "p",
            }));

        var parameters = string.Join(';', Compose(options).Parameters.Select(PerkToken));

        // SOURCE FIRST, THEN DESTINATION. Brave's source CID is zero-length and its destination
        // CID is eight bytes, so the capture's "0,8" pins the order as well as the lengths -
        // rendering them the other way round produces "8,0" and a hash the service never saw.
        var cidLengths =
            $"{connection.SourceConnectionIdLength},{connection.DestinationConnectionIdLength}";

        var perk = $"{settings}|{pseudoHeaders}|{parameters}|{cidLengths}";

        Assert.Equal(
            "1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p|12584:0x4f524947;GREASE;32:65536;" +
            "9:103;8:100;7:6291456;5:6291456;15:AUTO;17:1@GREASE,1;1:30000;6:6291456;" +
            "4:15728640;12583:AUTO;3:1472|0,8",
            perk);

#pragma warning disable CA5351 // The service hashes with MD5; reproducing it is the point.
        var hash = Convert.ToHexString(System.Security.Cryptography.MD5.HashData(
            System.Text.Encoding.ASCII.GetBytes(perk)));
#pragma warning restore CA5351

        Assert.Equal("7D726B1554D23AE0FFB3E8C533F20A2F", hash);
    }

    /// <summary>
    /// One composed transport parameter as the reference service renders it: GREASE for a
    /// reserved identifier, <c>AUTO</c> for the two the service does not hash the value of, the
    /// chosen-and-available pair for <c>version_information</c>, hex for a non-numeric payload,
    /// and the decoded varint otherwise.
    /// </summary>
    private static string PerkToken(TlsQuicTransportParameter parameter)
    {
        if (TlsQuicTransportParameterSpec.IsReservedIdentifier(parameter.Id))
        {
            return "GREASE";
        }

        if (parameter.Id == (ulong)TlsQuicTransportParameterId.VersionInformation)
        {
            var versions = new List<string>();
            for (var offset = 0; offset + 4 <= parameter.Value.Length; offset += 4)
            {
                var version = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(
                    parameter.Value.AsSpan(offset, 4));
                versions.Add(
                    TlsQuicTransportParameterSpec.IsReservedVersion(version)
                        ? "GREASE"
                        : version.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            return $"{parameter.Id}:{versions[0]}@{string.Join(',', versions.Skip(1))}";
        }

        // The two the service prints as AUTO: Google's private initial_rtt at 12583 and
        // initial_source_connection_id at 15, both per-connection draws.
        if (parameter.Id == GoogleInitialRttIdentifier ||
            parameter.Id == (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId)
        {
            return $"{parameter.Id}:AUTO";
        }

        if (parameter.Id == GoogleUserAgentIdentifier)
        {
            return $"{parameter.Id}:0x{Convert.ToHexString(parameter.Value).ToLowerInvariant()}";
        }

        return $"{parameter.Id}:{QuicVariableLengthInteger.ReadExact(parameter.Value, nameof(parameter))}";
    }

    /// <summary>Google's private <c>user_agent_id</c> identifier, whose payload is four ASCII
    /// bytes rather than a varint and is therefore rendered as hex.</summary>
    private static ulong GoogleUserAgentIdentifier { get; } = 12584;

    [Fact]
    public void TheDatagramSettingEscapeHatch_ReachesTheSpec()
    {
        // SharpTls refuses SETTINGS_H3_DATAGRAM without max_datagram_frame_size. A client that
        // really sends that pairing needs the refusal switched off, so the switch must be
        // reachable — and it is the one HTTP/3 knob no other test here turns.
        var options = new TlsSessionOptions();
        Assert.False(
            options.Snapshot().Quic.Http3Spec.AllowDatagramSettingWithoutTransportParameter);

        options.Http3.AllowDatagramSettingWithoutTransportParameter = true;
        Assert.True(
            options.Snapshot().Quic.Http3Spec.AllowDatagramSettingWithoutTransportParameter);
    }

    [Fact]
    public void AnUndefinedMirroredEnum_IsRejectedBySharpTlsUnderItsOwnPropertyName()
    {
        // TlsClient adds NO Enum.IsDefined guard of its own — every mirrored enum is validated
        // by the SharpTls property it feeds, under the same paramName. This test pins that
        // delegation, so removing SharpTls's guard or mistyping the cast is caught here.
        var pseudoHeader = new TlsSessionOptions();
        pseudoHeader.Http3.PseudoHeaderOrder = [(TlsHttp3PseudoHeader)99];
        Assert.Equal(
            "PseudoHeaderOrder",
            Assert.Throws<ArgumentOutOfRangeException>(() => pseudoHeader.Snapshot()).ParamName);

        var policy = new TlsSessionOptions();
        policy.Http3.QpackNameMatchPolicy = (TlsQpackNameMatchPolicy)99;
        Assert.Equal(
            "QpackNameMatchPolicy",
            Assert.Throws<ArgumentOutOfRangeException>(() => policy.Snapshot()).ParamName);

        var probe = new TlsSessionOptions();
        probe.Quic.Recovery.ProbeContents = (TlsQuicProbeContents)99;
        Assert.Equal(
            "ProbeContents",
            Assert.Throws<ArgumentOutOfRangeException>(() => probe.Snapshot()).ParamName);

        var streams = new TlsSessionOptions();
        streams.Http3.UnidirectionalStreamOpenOrder = [(TlsHttp3StreamType)99];
        Assert.ThrowsAny<ArgumentException>(() => streams.Snapshot());
    }

    // ------------------------------------------------------------------------------
    // The connection actually reads the configuration.
    // ------------------------------------------------------------------------------

    [Fact]
    public void Http3Connection_ConstructsNoQuicSpecOfItsOwn()
    {
        // EVERY OTHER TEST HERE STOPS AT Snapshot(). Http3Connection.CreateAsync needs DNS, a
        // UDP socket and a peer, so no unit test can watch it hand the snapshot to SharpTls —
        // which leaves exactly one unwitnessed way to break this change: reverting that method
        // to build its own spec and quietly ignoring everything a caller configured. The
        // fingerprint would still be right by default, so nothing else would fail.
        //
        // Reading the source is the only check available at this level. It is narrow on
        // purpose: it does not assert how the specs are used, only that this file constructs
        // none, so the specs it uses can only have come from the configuration.
        var source = File.ReadAllText(Http3ConnectionSourcePath());

        Assert.DoesNotContain("new TlsQuicConnectionSpec", source, StringComparison.Ordinal);
        Assert.DoesNotContain("new TlsQuicHttp3Spec", source, StringComparison.Ordinal);
        Assert.DoesNotContain("new TlsQuicRecoverySpec", source, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "new TlsQuicTransportParameterSpec",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain("new TlsQuicLocalFlowControlSpec", source, StringComparison.Ordinal);

        // And it does read them from the configuration, so the assertions above cannot be
        // satisfied by a file that dropped HTTP/3 support altogether.
        Assert.Contains("configuration.Quic.ConnectionSpec", source, StringComparison.Ordinal);
        Assert.Contains("configuration.Quic.Http3Spec", source, StringComparison.Ordinal);
        Assert.Contains("configuration.Quic.AlpnProtocols", source, StringComparison.Ordinal);
        Assert.Contains(
            "configuration.Quic.ConfigureClientHello",
            source,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// <c>MaximumConcurrentRequests</c> reports the peer's allowance and imposes none of its own.
    /// </summary>
    /// <remarks>
    /// <para>THE SAME PROBLEM AND THE SAME ANSWER AS THE TEST ABOVE. The property is an
    /// instance member of a type whose constructor is private and whose only factory needs DNS,
    /// a UDP socket and a QUIC handshake, so no offline test can hold an
    /// <see cref="Http3Connection"/> and read it. What CAN be read is the file, and the specific
    /// regression worth catching is narrow enough to name exactly: the property spent this
    /// change's whole history returning <c>Math.Min(1, RemainingRequestStreams)</c> — the peer's
    /// number read honestly and then thrown away — and restoring that cap would silently put
    /// the connection back to one request at a time while every other test still passed.</para>
    /// <para><see cref="Http3StreamMultiplexerTests"/> is where the concurrency the removed cap
    /// unlocked is actually witnessed; this is only the pin on the number the pool reads to
    /// decide whether to hand one connection to several requests at once.</para>
    /// </remarks>
    [Fact]
    public void Http3Connection_ReportsThePeersStreamAllowanceUncapped()
    {
        var source = File.ReadAllText(Http3ConnectionSourcePath());

        Assert.Contains(
            "public int MaximumConcurrentRequests => RemainingRequestStreams;",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Math.Min(1, RemainingRequestStreams)", source, StringComparison.Ordinal);

        // The allowance itself is still the peer's, taken from the transport parameter rather
        // than from a constant of ours.
        Assert.Contains(
            "connection.PeerFlowControl.InitialMaxStreamsBidi",
            source,
            StringComparison.Ordinal);
    }

    /// <summary>Walks up from the test assembly to the file this repository ships.</summary>
    private static string Http3ConnectionSourcePath()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(
                directory.FullName,
                "src",
                "TlsClient",
                "Http3Connection.cs");
            if (File.Exists(candidate))
            {
                return candidate;
            }
            directory = directory.Parent;
        }
        throw new InvalidOperationException("src/TlsClient/Http3Connection.cs was not found.");
    }

    // ------------------------------------------------------------------------------
    // Helpers.
    // ------------------------------------------------------------------------------

    /// <summary>
    /// The ClientHello configuration <c>Http3Connection.CreateAsync</c> carried inline before
    /// <see cref="TlsQuicOptions.ConfigureClientHello"/> existed, restated here so the default
    /// pin compares against the old code and not against the new code's own helper.
    /// </summary>
    private static void LegacyClientHello(ClientHelloBuilder builder) => builder
        .WithTls13()
        .WithCipherSuites(
            TlsCipherSuite.TlsAes128GcmSha256,
            TlsCipherSuite.TlsAes256GcmSha384)
        .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1)
        .WithKeyShares(NamedGroup.X25519);

    /// <summary>
    /// The ClientHello the QUIC handshake would actually send, through the same factory
    /// <c>Http3Connection.CreateAsync</c> builds. Deterministic, so two profiles that agree
    /// here agree byte for byte on the wire.
    /// </summary>
    private static byte[] BuildHello(Action<ClientHelloBuilder> configure, byte[] seed) =>
        new TlsQuicClientHelloProfileFactory
        {
            // PINNED TRANSPORT PARAMETERS, and that is the whole reason this helper exists.
            // The factory embeds the composed parameters INTO the ClientHello, and three of
            // the default preset's fourteen redraw per composition — so two profiles built
            // from the same Tls callback differ, and a byte comparison would be measuring the
            // draws instead of the TLS half. One literal entry removes that variable.
            ConnectionSpec = new TlsQuicConnectionSpec
            {
                TransportParameters = new TlsQuicTransportParameterSpec
                {
                    Parameters = [TlsQuicTransportParameterSlot.Literal(0x4a4a4a4a, [0x01])],
                },
            },
            AlpnProtocols = [TlsQuicClientHelloProfileFactory.Http3AlpnToken],
            Tls = configure,
        }
            .Create(SourceConnectionId)
            .BuildDeterministicForTesting("example.test", seed);

    private static byte[] EncodeSettings(TlsQuicHttp3Spec spec)
    {
        var destination = new List<byte>();
        TlsQuicHttp3Settings.Encode(destination, spec);
        return [.. destination];
    }

    /// <summary>Reads a SETTINGS frame back, so a witness can name what changed.</summary>
    private static TlsQuicHttp3Setting[] DecodeSettings(byte[] frame)
    {
        // Skip the frame type and length varints the encoder wrote, then decode the payload.
        var span = frame.AsSpan();
        var offset = 0;
        Assert.True(QuicVariableLengthInteger.TryRead(span, ref offset, out _));
        Assert.True(QuicVariableLengthInteger.TryRead(span, ref offset, out var length));
        Assert.True(TlsQuicHttp3Settings.TryDecodePayload(
            span.Slice(offset, (int)length),
            out var settings,
            out _));
        return [.. settings];
    }

    /// <summary>
    /// The composed identifiers in wire order, with the reserved (GREASE) one — which RFC 9000
    /// s18.1 lets a client redraw per connection, and which this preset does — folded to a
    /// sentinel. Everything else is the identifier itself, so an ORDER comparison stays an
    /// order comparison and does not become a test about randomness.
    /// </summary>
    private static string[] Identifiers(TlsSessionOptions options) =>
    [
        .. Compose(options).Parameters.Select(parameter =>
            TlsQuicTransportParameterSpec.IsReservedIdentifier(parameter.Id)
                ? "<grease>"
                : parameter.Id.ToString(System.Globalization.CultureInfo.InvariantCulture)),
    ];

    private static TlsQuicTransportParameters Compose(TlsSessionOptions options)
    {
        var spec = options.Snapshot().Quic.ConnectionSpec;
        return spec.TransportParameters.Compose(spec, SourceConnectionId);
    }

    /// <summary>
    /// The composed parameters rendered as one comparable string, with the three per-connection
    /// draws replaced by their index so a difference means a real difference and not a redraw.
    /// </summary>
    private static string ComposeComparable(TlsSessionOptions options)
    {
        var rendered = new StringBuilder();
        var composed = Compose(options);
        for (var position = 0; position < composed.Parameters.Count; position++)
        {
            var parameter = composed.Parameters[position];
            var reserved = TlsQuicTransportParameterSpec.IsReservedIdentifier(parameter.Id);
            rendered.Append(position).Append(':');
            rendered.Append(reserved ? "<grease>" : parameter.Id).Append('=');
            rendered.Append(
                reserved ||
                parameter.Id == (ulong)TlsQuicTransportParameterId.VersionInformation ||
                parameter.Id == GoogleInitialRttIdentifier
                    ? "<drawn>"
                    : Convert.ToHexString(parameter.Value));
            rendered.Append(';');
        }
        return rendered.ToString();
    }

    /// <summary>
    /// Google's private <c>initial_rtt</c> identifier. In no registry and in no SharpTls enum,
    /// which is exactly why the slot model carries it as a bare number.
    /// </summary>
    private static ulong GoogleInitialRttIdentifier { get; } = 12583;

    private sealed class TransportParameterComparer : IEqualityComparer<TlsQuicTransportParameter>
    {
        public static TransportParameterComparer Instance { get; } = new();

        public bool Equals(TlsQuicTransportParameter? x, TlsQuicTransportParameter? y) =>
            x is null
                ? y is null
                : y is not null && x.Id == y.Id && x.Value.AsSpan().SequenceEqual(y.Value);

        public int GetHashCode(TlsQuicTransportParameter obj) => obj.Id.GetHashCode();
    }
}
