namespace TlsClient.Tests;

public sealed class TlsPresetTests
{
    [Fact]
    public void FamilyAliasesPointAtCurrentVersionedPresets()
    {
        // ONE FAMILY LEFT, and the claim is the same one: the unversioned alias must point at
        // the current pinned version, so a caller who wrote TlsPresets.Spotify does not silently
        // keep an old capture when a newer one lands.
        Assert.Same(TlsPresets.Spotify917602050IOS270Http3, TlsPresets.Spotify);
    }

#pragma warning disable TLSCLIENT3
    /// <summary>
    /// The iOS 26 preset against the iOS 27 one. Two differences and no third: the profile it
    /// names, and the vendor transport parameter. Everything the two captures agree on is shared
    /// code, and this test is what notices if a later edit gives one of them a value the other
    /// did not get.
    /// </summary>
    [Fact]
    public void SpotifyIosHttp3_Ios26DiffersOnlyInProfileAndVendorParameter()
    {
        var ios26 = TlsPresets.Spotify917602050IOS260Http3.CreateOptions();
        var ios27 = TlsPresets.Spotify917602050IOS270Http3.CreateOptions();

        Assert.Same(TlsProfiles.Spotify917602050IOS260Quic, ios26.Profile);
        Assert.Equal(TlsHttpVersionPolicy.Http3Only, ios26.HttpVersionPolicy);

        // The vendor parameter is the whole transport-parameter difference: iOS 26 sends the
        // seven known ones and stops.
        Assert.Equal(
            [0x04UL, 0x05, 0x06, 0x07, 0x09, 0x0E, 0x0F],
            ios26.Quic.TransportParameters.Entries.Select(e => e.Id));
        Assert.Equal(
            [0x04UL, 0x05, 0x06, 0x07, 0x09, 0x0E, 0x0F, 0xFF08_0808],
            ios27.Quic.TransportParameters.Entries.Select(e => e.Id));

        // The rotation is INHERITED, not measured on iOS 26 - see the preset's remarks. Pinned
        // so that inheritance is a decision on the record rather than an accident.
        Assert.Equal(
            ios27.Quic.TransportParameters.CyclicRotationLength,
            ios26.Quic.TransportParameters.CyclicRotationLength);

        // Everything else the two captures agree on.
        Assert.Equal(ios27.Quic.AlpnProtocols, ios26.Quic.AlpnProtocols);
        Assert.Equal(ios27.Quic.SourceConnectionIdLength, ios26.Quic.SourceConnectionIdLength);
        Assert.Equal(
            ios27.Quic.DestinationConnectionIdLength,
            ios26.Quic.DestinationConnectionIdLength);
        Assert.Equal(ios27.Quic.PacketNumberEncodedLength, ios26.Quic.PacketNumberEncodedLength);
        Assert.Equal(ios27.Quic.PaddingTarget, ios26.Quic.PaddingTarget);
        Assert.Equal(ios27.Quic.MaximumPathMtu, ios26.Quic.MaximumPathMtu);
        Assert.Equal(
            ios27.Quic.InitialCryptoFrameByteCounts,
            ios26.Quic.InitialCryptoFrameByteCounts);
        Assert.Equal(
            ios27.Quic.FlowControl.InitialMaxData,
            ios26.Quic.FlowControl.InitialMaxData);
        Assert.Equal(ios27.Http3.PseudoHeaderOrder, ios26.Http3.PseudoHeaderOrder);
        Assert.Equal(
            ios27.Http3.UnidirectionalStreamOpenOrder,
            ios26.Http3.UnidirectionalStreamOpenOrder);
        Assert.Equal(ios27.Http3.Settings.Count, ios26.Http3.Settings.Count);
    }

    [Fact]
    public void SpotifyIosHttp3_CarriesTheCapturedQuicAndHeaderImage()
    {
        var options = TlsPresets.Spotify917602050IOS270Http3.CreateOptions();

        Assert.Same(TlsProfiles.Spotify917602050IOS270Quic, options.Profile);

        // The shape is QUIC's. A TCP dial would impersonate nothing, so the preset pins the
        // policy rather than leaving it to the caller.
        Assert.Equal(TlsHttpVersionPolicy.Http3Only, options.HttpVersionPolicy);
        Assert.Equal(["h3"], options.Quic.AlpnProtocols);

        // Packet and datagram shape, identical in all 80 captured connections.
        Assert.Equal(0, options.Quic.SourceConnectionIdLength);
        Assert.Equal(8, options.Quic.DestinationConnectionIdLength);
        Assert.Equal(1, options.Quic.PacketNumberEncodedLength);
        Assert.Equal(1200, options.Quic.PaddingTarget);
        Assert.True(options.Quic.Token.IsEmpty);
        Assert.Equal([999, 999], options.Quic.InitialCryptoFrameByteCounts);
        Assert.Equal([1, 1], options.Quic.InitialCryptoFramesPerDatagram);
        Assert.False(options.Quic.CoalesceAscendingByLevel);

        // NOT A CAPTURED VALUE — the one local-path accommodation in this preset, pinned so the
        // default cannot reach a size a tunnelled path refuses. The library default is 1472,
        // which fills a 1500-byte MTU exactly and, with Don't Fragment set, fails the send with
        // WSAEMSGSIZE on any smaller path. Asserted because it is the kind of value a later
        // "align with the library default" tidy-up would silently undo.
        Assert.Equal(1392, options.Quic.MaximumPathMtu);

        Assert.Equal(16_777_216UL, options.Quic.FlowControl.InitialMaxData);
        Assert.Equal(2_097_152UL, options.Quic.FlowControl.InitialMaxStreamDataBidiLocal);
        Assert.Equal(8UL, options.Quic.FlowControl.InitialMaxStreamsUni);

        // Eight parameters: seven known ones plus the vendor 0xff080808. Nowhere among them is
        // initial_max_streams_bidi (0x08) — a different identifier that this client omits.
        var ids = options.Quic.TransportParameters.Entries.Select(e => e.Id).ToArray();
        Assert.Equal(8, ids.Length);
        Assert.DoesNotContain(0x08UL, ids);

        // 0xff080808 is LAST, not part of the rotation. In 4 of 4 proxy captures it trailed the
        // seven regardless of where the rotation began, so asserting only "present" would let a
        // regression slide it into the rotating block and change the wire image.
        Assert.Equal(0xFF08_0808UL, ids[^1]);
        var rotated = ids[..^1];

        // Whatever rotation was drawn, it is a rotation of the captured sequence - never a
        // shuffle. Doubling the base and searching for the drawn order as a contiguous window
        // is exactly the "is a rotation of" test.
        ulong[] baseOrder = [0x04, 0x05, 0x06, 0x07, 0x09, 0x0E, 0x0F];
        var doubled = string.Join(",", baseOrder.Concat(baseOrder));
        Assert.Contains(string.Join(",", rotated), doubled);

        // QPACK capacity, blocked streams, then one RFC 9114 s7.2.4.1 reserved identifier.
        // MAX_FIELD_SECTION_SIZE is absent: this client does not send it.
        Assert.Equal(3, options.Http3.Settings.Count);
        Assert.Equal(new TlsHttp3Setting(0x01, 16_383), options.Http3.Settings[0]);
        Assert.Equal(new TlsHttp3Setting(0x07, 100), options.Http3.Settings[1]);
        // DRAWN, SO THE SHAPE IS CHECKED ON WHAT THE DRAW RETURNS. The entry itself carries
        // the (0, 0) placeholder; `0 % 0x1F` would satisfy no reserved-identifier test and
        // asserting on it would be asserting on the placeholder.
        Assert.True(options.Http3.Settings[2].IsDrawn);
        Assert.Equal(
            0x21UL % 0x1FUL,
            options.Http3.Settings[2].Draw!().Identifier % 0x1FUL);
        Assert.DoesNotContain(options.Http3.Settings, s => s.Identifier == 0x06);

        // Control, encoder, decoder — measured in 4 of 4 proxy captures. NOTE WHAT THIS CANNOT
        // DO: SharpTls's default is currently the same order, so deleting the preset's pin today
        // would NOT fail this. What it does catch is the dangerous case — a later change to the
        // library default silently moving this fingerprint, which fails here unless pinned.
        Assert.Equal(
            [
                TlsHttp3StreamType.Control,
                TlsHttp3StreamType.QpackEncoder,
                TlsHttp3StreamType.QpackDecoder,
            ],
            options.Http3.UnidirectionalStreamOpenOrder);

        // MEASURED as m,s,a,p — NOT the library default m,a,s,p, which is what this preset
        // shipped with until the proxy captures settled it. RFC 9114 section 4.3 fixes no order
        // among the pseudo-headers, so the choice is pure fingerprint.
        Assert.Equal(
            [
                TlsHttp3PseudoHeader.Method,
                TlsHttp3PseudoHeader.Scheme,
                TlsHttp3PseudoHeader.Authority,
                TlsHttp3PseudoHeader.Path,
            ],
            options.Http3.PseudoHeaderOrder);
    }



    [Fact]
    public void SpotifyIosHttp3_RedrawsTheTransportParameterRotationPerConnection()
    {
        // PER CONNECTION, NOT PER OPTIONS OBJECT, AND THE DIFFERENCE IS THE WHOLE FIX. This
        // test used to build fifty OPTIONS objects and assert their orders differed - which
        // they did, because the preset rotated the array as it was applied. But a session
        // holds ONE options object and pools many connections under it, so every connection in
        // a session shipped the same order for the session's life: one of seven rather than
        // one of one, and still a constant a server sees twice. Fifty COMPOSITIONS of one
        // spec is the assertion that would have failed then and passes now.
        var options = TlsPresets.Spotify917602050IOS270Http3.CreateOptions();
        var spec = options.Snapshot().Quic.ConnectionSpec;

        // Declared, not performed: the entries stay in the captured order and the rotation is
        // a length the composer applies.
        Assert.Equal(7, options.Quic.TransportParameters.CyclicRotationLength);
        Assert.Equal(
            new ulong[] { 0x04, 0x05, 0x06, 0x07, 0x09, 0x0E, 0x0F, 0xFF08_0808 },
            options.Quic.TransportParameters.Entries.Select(e => e.Id).ToArray());

        var seen = new HashSet<string>();
        for (var i = 0; i < 50; i++)
        {
            var composed = spec.TransportParameters.Compose(spec, []);
            var ids = composed.Parameters.Select(e => e.Id).ToArray();

            // 0xff080808 never joins the rotation: it sat last in 4 of 4 proxy captures
            // regardless of where the rotation started, and CyclicRotationLength = 7 over an
            // eight-entry list is how that is expressed.
            Assert.Equal(0xFF08_0808UL, ids[^1]);
            seen.Add(string.Join(",", ids[..^1]));
        }

        // Fifty draws over seven offsets miss all six alternatives with probability (1/7)^49.
        Assert.True(seen.Count > 1, "the transport-parameter rotation never changed");
        Assert.True(seen.Count <= 7, $"expected at most 7 rotations, saw {seen.Count}");
    }
#pragma warning restore TLSCLIENT3
}
