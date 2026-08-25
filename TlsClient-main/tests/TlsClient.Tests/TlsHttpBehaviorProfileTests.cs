using System.Text.Json;
using TlsClient.Tests.Wire;

namespace TlsClient.Tests;

public sealed class TlsHttpBehaviorProfileTests
{
    [Fact]
    public void CaptureJsonImportApply_RoundTripsThePrefaceHpackStreamIdsOrderingAndPriority()
    {
        var source = new TlsSessionOptions();
        // The vehicle used to be a preset, which brought a header order with it. The claim
        // needs one - a round trip that carries null through cannot show the order survived.
        source.HeaderOrder = ["user-agent", "accept", "accept-encoding"];
        source.Http2.HeaderPriority = new TlsHttp2Priority
        {
            StreamDependency = 1,
            Exclusive = true,
            Weight = 201,
        };
        source.Http2.InitialStreamId = 3;
        source.Http2.StreamIdStep = 4;
        source.Http2.PriorityUpdate = "u=3, i";

        var captured = TlsHttpBehaviorProfile.Capture("firefox-custom", source);
        var json = captured.ExportJson();
        var imported = TlsHttpBehaviorProfile.ImportJson(json);
        var target = new TlsSessionOptions();
        imported.ApplyTo(target);
        var recaptured = TlsHttpBehaviorProfile.Capture("firefox-custom", target);

        Assert.Equal(json, recaptured.ExportJson());
        Assert.Equal(source.HeaderOrder, imported.HeaderOrder);
        Assert.Equal("u=3, i", imported.Http2.PriorityUpdate);
        Assert.Equal(201, imported.Http2.HeaderPriority?.Weight);
        Assert.Equal(3, imported.Http2.InitialStreamId);
        Assert.Equal(4, imported.Http2.StreamIdStep);
        Assert.DoesNotContain("must-not-be-captured", json, StringComparison.Ordinal);

        // authorization now appears in the document, but only as an HPACK policy key
        // carrying its never-indexed default. The header's value is what must not travel,
        // and the assertion above is what proves it does not.
        Assert.Contains(
            "\"authorization\": \"LiteralNeverIndexed\"",
            json,
            StringComparison.Ordinal);
    }

    // WAS PARAMETERISED OVER THE CHROME, FIREFOX AND ANDROID PRESETS. Those are gone, and the
    // claim never depended on them: what is under test is that a captured behaviour profile
    // survives export, import and apply down to the wire bytes. The three shapes below are
    // hand-built and deliberately differ in preface, header order, stream numbering and
    // priority, because a round-trip that only ever sees one shape proves nothing about the
    // fields it never varies.
    [Theory]
    [InlineData("settings-only")]
    [InlineData("priority-and-odd-steps")]
    [InlineData("window-update-first")]
    public async Task CaptureImportApply_ReproducesEachShapesPrefaceAndRequestBytes(string preset)
    {
        var source = CreateOptions(preset);
        var expected = source.Http2.Snapshot();
        var json = TlsHttpBehaviorProfile.Capture(preset, source).ExportJson();

        var target = new TlsSessionOptions();
        TlsHttpBehaviorProfile.ImportJson(json).ApplyTo(target);
        var actual = target.Http2.Snapshot();

        Assert.Equal(expected.Preface.Length, actual.Preface.Length);
        for (var index = 0; index < expected.Preface.Length; index++)
        {
            // Frame by frame rather than wholesale: the payload is a byte[] inside a
            // record, so record equality compares it by reference and would pass on two
            // different payloads of the same shape.
            Assert.Equal(expected.Preface[index].Type, actual.Preface[index].Type);
            Assert.Equal(expected.Preface[index].Flags, actual.Preface[index].Flags);
            Assert.Equal(expected.Preface[index].StreamId, actual.Preface[index].StreamId);
            Assert.Equal(expected.Preface[index].Payload, actual.Preface[index].Payload);
            Assert.Equal(expected.Preface[index].FlushAfter, actual.Preface[index].FlushAfter);
        }

        // The derived receive bounds have to survive too: they are read back out of the
        // restored preface octets, not carried alongside them.
        Assert.Equal(expected.LocalMaxFrameSize, actual.LocalMaxFrameSize);
        Assert.Equal(expected.LocalInitialWindowSize, actual.LocalInitialWindowSize);
        Assert.Equal(expected.LocalHeaderTableSize, actual.LocalHeaderTableSize);
        Assert.Equal(expected.LocalEnablePush, actual.LocalEnablePush);
        Assert.Equal(expected.ConnectionReceiveWindow, actual.ConnectionReceiveWindow);

        // The frozen configuration is only the claim; the wire is the proof. Run the preset
        // and the restored profile against the same scripted server and compare what each
        // client actually wrote.
        var reference = CreateOptions(preset);
        var expectedWire = await Http2WireCapture.RunAsync(
            reference,
            (session, url, ct) => SendWithPinnedAuthority(session, url, ct));

        var restored = new TlsSessionOptions();
        TlsHttpBehaviorProfile.ImportJson(json).ApplyTo(restored);
        // A profile carries no header values and a session has no headers of its own, so both
        // sides send the same caller-supplied field. Everything that shapes the HTTP/2 image —
        // preface, HPACK policy, header order, pseudo-header composition, framing, flushes —
        // has to come from the profile, which is what this asserts.
        var actualWire = await Http2WireCapture.RunAsync(
            restored,
            (session, url, ct) => SendWithPinnedAuthority(session, url, ct));

        // The preface is written before the read loop can have seen anything from the peer,
        // so its octets are the one stretch of the stream no SETTINGS ACK can race into.
        var prefaceLength = MagicLength + expected.Preface.Sum(frame => 9 + frame.Payload.Length);
        Http2WireAssert.EqualBytes(
            expectedWire.ClientBytes[..prefaceLength],
            actualWire.ClientBytes.AsSpan(0, prefaceLength),
            $"{preset} preface octets");

        // Past the preface the ACK's position is a genuine race, so compare frames with it
        // filtered out rather than comparing the raw stream.
        Http2WireAssert.EqualFrames(
            WithoutSettingsAck(expectedWire.ClientFrames),
            WithoutSettingsAck(actualWire.ClientFrames),
            $"{preset} client frames");
    }

    [Fact]
    public void CaptureImportApply_RoundTripsTheRequestLifecycleOptions()
    {
        var source = new TlsSessionOptions();
        var declared = source.Http2;
        declared.PseudoHeaders.Order = [":method", ":path", ":scheme", ":authority", ":protocol"];
        declared.PseudoHeaders.AuthorityMode = TlsHttp2AuthorityMode.Both;
        declared.PseudoHeaders.Scheme = "http";
        declared.Data.MaxDataFrameSize = 4096;
        declared.Data.NonEmptyBody = TlsHttp2EndStreamPlacement.SeparateEmptyDataFrame;
        declared.Data.EmptyBodyEndsOnHeaders = false;
        declared.FlowControl.StreamWindowUpdateThreshold = 8192;
        declared.FlowControl.ConnectionWindowUpdateThreshold = 16384;
        declared.FlowControl.Trigger = TlsHttp2WindowUpdateTrigger.OnReceive;
        declared.FlowControl.Increment = TlsHttp2WindowUpdateIncrement.Fixed;
        declared.FlowControl.FixedIncrement = 32768;
        declared.FlowControl.Order = TlsHttp2WindowUpdateOrder.StreamFirst;
        declared.FlowControl.CoalesceConnectionAndStream = true;
        declared.FlowControl.SuppressStreamUpdateOnEndStream = false;
        declared.Shutdown.SendGoAwayOnDispose = true;
        declared.Shutdown.GoAwayErrorCode = Http2ErrorCode.EnhanceYourCalm;
        declared.Shutdown.GoAwayDebugData = [0x00, 0xff, 0x10];
        declared.Shutdown.CancellationResetCode = Http2ErrorCode.RefusedStream;
        declared.Shutdown.LocalFailureResetCode = Http2ErrorCode.ConnectError;
        declared.Shutdown.PushRejectionResetCode = Http2ErrorCode.RefusedStream;
        declared.HeaderBlockFragmentSize = 512;
        declared.FlushAfterHeaderBlock = false;
        declared.FlushAfterEveryDataFrame = false;

        var json = TlsHttpBehaviorProfile.Capture("lifecycle", source).ExportJson();
        var target = new TlsSessionOptions();
        TlsHttpBehaviorProfile.ImportJson(json).ApplyTo(target);
        var actual = target.Http2.Snapshot();

        // Every value above is non-default, so each assertion fails if its field is dropped
        // by either half of the trip. A default-only round trip would pass on an ApplyTo
        // that did nothing at all.
        Assert.Equal(
            [":method", ":path", ":scheme", ":authority", ":protocol"],
            actual.PseudoHeaders.Order);
        Assert.Equal(TlsHttp2AuthorityMode.Both, actual.PseudoHeaders.AuthorityMode);
        Assert.Equal("http", actual.PseudoHeaders.Scheme);

        Assert.Equal(4096, actual.Data.MaxDataFrameSize);
        Assert.Equal(TlsHttp2EndStreamPlacement.SeparateEmptyDataFrame, actual.Data.NonEmptyBody);
        Assert.False(actual.Data.EmptyBodyEndsOnHeaders);

        Assert.Equal(8192, actual.FlowControl.StreamWindowUpdateThreshold);
        Assert.Equal(16384, actual.FlowControl.ConnectionWindowUpdateThreshold);
        Assert.Equal(TlsHttp2WindowUpdateTrigger.OnReceive, actual.FlowControl.Trigger);
        Assert.Equal(TlsHttp2WindowUpdateIncrement.Fixed, actual.FlowControl.Increment);
        Assert.Equal(32768, actual.FlowControl.FixedIncrement);
        Assert.Equal(TlsHttp2WindowUpdateOrder.StreamFirst, actual.FlowControl.Order);
        Assert.True(actual.FlowControl.CoalesceConnectionAndStream);
        Assert.False(actual.FlowControl.SuppressStreamUpdateOnEndStream);

        Assert.True(actual.Shutdown.SendGoAwayOnDispose);
        Assert.Equal(Http2ErrorCode.EnhanceYourCalm, actual.Shutdown.GoAwayErrorCode);
        Assert.Equal<byte[]?>([0x00, 0xff, 0x10], actual.Shutdown.GoAwayDebugData);
        Assert.Equal(Http2ErrorCode.RefusedStream, actual.Shutdown.CancellationResetCode);
        Assert.Equal(Http2ErrorCode.ConnectError, actual.Shutdown.LocalFailureResetCode);
        Assert.Equal(Http2ErrorCode.RefusedStream, actual.Shutdown.PushRejectionResetCode);

        Assert.Equal(512, actual.HeaderBlockFragmentSize);
        Assert.False(actual.FlushAfterHeaderBlock);
        Assert.False(actual.FlushAfterEveryDataFrame);

        Assert.Equal(json, TlsHttpBehaviorProfile.Capture("lifecycle", target).ExportJson());
    }

    [Fact]
    public void Import_RejectsTheSupersededDocumentVersion()
    {
        var json = TlsHttpBehaviorProfile
            .Capture("chrome", new TlsSessionOptions())
            .ExportJson(writeIndented: false);
        Assert.Contains("\"version\":3", json, StringComparison.Ordinal);

        // A private fork rejects the old version rather than migrating it.
        var version2 = json.Replace("\"version\":3", "\"version\":2", StringComparison.Ordinal);
        Assert.Throws<JsonException>(() => TlsHttpBehaviorProfile.ImportJson(version2));
    }

    [Fact]
    public void Import_RejectsAnUndefinedEnumCarriedAsANumber()
    {
        var json = TlsHttpBehaviorProfile
            .Capture("chrome", new TlsSessionOptions())
            .ExportJson(writeIndented: false);
        Assert.Contains("\"authorityMode\":\"AuthorityOnly\"", json, StringComparison.Ordinal);

        // JsonStringEnumConverter accepts integers as well as names, so a document can carry
        // a value no enum member defines.
        var undefined = json.Replace(
            "\"authorityMode\":\"AuthorityOnly\"",
            "\"authorityMode\":99",
            StringComparison.Ordinal);
        Assert.Throws<JsonException>(() => TlsHttpBehaviorProfile.ImportJson(undefined));
    }

    [Fact]
    public void Import_RejectsUnknownAndDuplicateProperties()
    {
        var json = TlsHttpBehaviorProfile
            .Capture("chrome", new TlsSessionOptions())
            .ExportJson(writeIndented: false);
        // Anchored on the format string rather than the version so a format revision does
        // not silently turn this into a test that mutates nothing and can never fail.
        var unknown = json.Replace(
            "\"format\":\"tlsclient-http-behavior\",",
            "\"format\":\"tlsclient-http-behavior\",\"unknown\":true,",
            StringComparison.Ordinal);
        var duplicate = json.Replace(
            "\"name\":\"chrome\",",
            "\"name\":\"chrome\",\"name\":\"duplicate\",",
            StringComparison.Ordinal);

        Assert.Throws<JsonException>(() => TlsHttpBehaviorProfile.ImportJson(unknown));
        Assert.Throws<JsonException>(() => TlsHttpBehaviorProfile.ImportJson(duplicate));
    }

    [Fact]
    public void Import_EnforcesUtf8DocumentLimit()
    {
        var json = TlsHttpBehaviorProfile
            .Capture("chrome", new TlsSessionOptions())
            .ExportJson(writeIndented: false);

        Assert.Throws<JsonException>(() =>
            TlsHttpBehaviorProfile.ImportJson(json, maximumDocumentSize: 32));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            TlsHttpBehaviorProfile.ImportJson(json, maximumDocumentSize: 4 * 1024 * 1024 + 1));
    }

    private static TlsSessionOptions CreateOptions(string shape)
    {
        var options = new TlsSessionOptions();
        switch (shape)
        {
            case "settings-only":
                options.Http2.Preface =
                [
                    new TlsHttp2SettingsFrame { Settings = [new(0x1, 65_536), new(0x4, 6_291_456)] },
                ];
                options.HeaderOrder = ["user-agent", "accept"];
                break;

            case "priority-and-odd-steps":
                options.Http2.Preface =
                [
                    new TlsHttp2SettingsFrame { Settings = [new(0x1, 4_096), new(0x5, 16_384)] },
                ];
                options.Http2.HeaderPriority = new TlsHttp2Priority
                {
                    StreamDependency = 1,
                    Exclusive = true,
                    Weight = 201,
                };
                options.Http2.InitialStreamId = 3;
                options.Http2.StreamIdStep = 4;
                options.HeaderOrder = ["accept", "user-agent"];
                break;

            default:
                options.Http2.Preface =
                [
                    new TlsHttp2SettingsFrame { Settings = [new(0x4, 16_777_216)] },
                    new TlsHttp2WindowUpdateFrame { Increment = 983_041 },
                ];
                options.Http2.PriorityUpdate = "u=3, i";
                break;
        }
        return options;
    }

    private const int MagicLength = 24;

    /// <summary>
    /// Pins the authority the header block encodes. The harness binds an ephemeral loopback
    /// port, so two runs reach different URLs and <c>:authority</c> would differ by the port
    /// alone. Http2Connection seeds <c>:authority</c> from the request's <c>Host</c> field
    /// when it carries one, so declaring it makes the header block port-independent.
    /// </summary>
    private static Task<TlsResponse> SendWithPinnedAuthority(
        TlsSession session,
        string url,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.AddHeader("Host", "profile.example:443");
        return session.SendAsync(request, cancellationToken);
    }

    private static CapturedFrame[] WithoutSettingsAck(IEnumerable<CapturedFrame> frames) =>
        frames
            .Where(frame => !(frame.Type == Http2FrameType.Settings &&
                (frame.Flags & Http2FrameFlags.Ack) != 0))
            .ToArray();
}
