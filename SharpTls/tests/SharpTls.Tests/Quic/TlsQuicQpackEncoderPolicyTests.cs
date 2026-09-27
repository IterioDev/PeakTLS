using System.Text;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// TlsQuicQpackEncoderPolicy against the behaviour measured in
// docs/superpowers/specs/reference-captures/2026-09-26-spotify-9.1.86-ios27-pcapng.md s6:
// connection 61's requests replayed in order, with the insert sequence, the prefixes and the
// representation of every line asserted from the capture rather than from the code.
//
// WHERE A DECODER APPEARS, IT IS THE OTHER SIDE OF THE PROTOCOL, NOT THE CODE UNDER TEST.
// TlsQuicQpackDynamicTable (the decoder-side table, task C16) is fed the encoder-stream bytes
// this policy produced and TlsQuicQpackDecoder is asked to decode the section against it -
// the same pair of classes a real peer would be. A bug the encoder and decoder share would
// survive that; the hand-written byte vectors in the first tests are what catch it.
public sealed class TlsQuicQpackEncoderPolicyTests
{
    private static byte[] A(string text) => Encoding.ASCII.GetBytes(text);

    private static List<(byte[] Name, byte[] Value)> Lines(params (string Name, string Value)[] pairs) =>
        pairs.Select(pair => (A(pair.Name), A(pair.Value))).ToList();

    private static TlsQuicHttp3Spec SpotifySpec(int capacity = 4096) => new()
    {
        QpackEncoderDynamicTableCapacity = capacity,
        QpackInsertPolicy = TlsQuicQpackInsertPolicy.OnSecondUse,
    };

    private static TlsQuicQpackEncoderPolicy Spotify(int capacity = 4096) => new(SpotifySpec(capacity));

    // Connection 61, stream 0: a POST to spclient.wg.spotify.com. Credentials shortened; the
    // policy sees only lengths and equality, and the capture's insert order does not depend
    // on them.
    private static List<(byte[] Name, byte[] Value)> Request(
        string path,
        string contentLength,
        string contentType = "application/protobuf",
        string accept = "application/protobuf") => Lines(
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "spclient.wg.spotify.com"),
        (":path", path),
        ("content-type", contentType),
        ("spotify-app-version", "9.1.86.2428"),
        ("accept", accept),
        ("time-zone", "Europe/Athens"),
        ("app-platform", "iOS"),
        ("priority", "u=3, i"),
        ("accept-language", "en-GB,en;q=0.9"),
        ("accept-encoding", "gzip, deflate, br"),
        ("content-length", contentLength),
        ("user-agent", "Spotify/9.1.86 iOS/27.0 (iPhone17,2)"),
        ("x-client-id", "58bd3c95768941ea9eb4350aaa033eb3"),
        ("client-token", "AAGxl8UElUaNDsgAvOJvyJ8k71PiW3qme"));

    private static string Hex(ReadOnlyMemory<byte> bytes) => Convert.ToHexString(bytes.Span);

    // Decodes a section the way a peer would: its encoder-stream bytes into a decoder-side
    // table first, then the section against that table.
    private static List<(string Name, string Value)> DecodeAgainst(
        TlsQuicQpackDynamicTable? table, ReadOnlyMemory<byte> section)
    {
        var buffer = new byte[4096];
        var lines = new TlsQuicQpackDecodedFieldLine[64];
        Assert.True(
            TlsQuicQpackDecoder.TryDecodeFieldSectionAgainstTable(
                section.Span, buffer, lines, long.MaxValue, table,
                out int count, out _, out _, out var error),
            $"decode failed: {error}");
        var decoded = new List<(string, string)>();
        for (var i = 0; i < count; i++)
        {
            decoded.Add((
                Encoding.ASCII.GetString(buffer, lines[i].NameOffset, lines[i].NameLength),
                Encoding.ASCII.GetString(buffer, lines[i].ValueOffset, lines[i].ValueLength)));
        }

        return decoded;
    }

    private static void Feed(TlsQuicQpackDynamicTable table, ReadOnlyMemory<byte> encoderBytes)
    {
        if (encoderBytes.IsEmpty)
        {
            return;
        }

        Assert.True(table.TryReadEncoderInstructions(encoderBytes.Span, out int consumed, out var error), $"{error}");
        Assert.Equal(encoderBytes.Length, consumed);
    }

    // A peer's decoder-side table, with the capacity instruction the policy produced already
    // applied - the way the real peer sees it, on the encoder stream, before any insert.
    private static TlsQuicQpackDynamicTable Peer(TlsQuicQpackEncoderPolicy policy, ulong peerMaximum, ulong peerBlocked)
    {
        var table = new TlsQuicQpackDynamicTable((int)peerMaximum);
        Feed(table, policy.OnPeerSettings(peerMaximum, peerBlocked));
        return table;
    }

    [Fact]
    public void WithCapacityZeroEveryPlanIsAStaticOnlySectionWithNoEncoderBytes()
    {
        var policy = new TlsQuicQpackEncoderPolicy(new TlsQuicHttp3Spec());
        var request = Request("/a", "1");

        for (var i = 0; i < 3; i++)
        {
            var plan = policy.Plan(request);
            policy.Commit(plan, (ulong)(4 * i));

            Assert.True(plan.EncoderStreamBytes.IsEmpty);
            Assert.Equal(0UL, plan.RequiredInsertCount);
            Assert.Equal("0000", Hex(plan.FieldSection[..2]));
            Assert.Empty(plan.Inserts);
            Assert.Equal(request.Select(l => (Encoding.ASCII.GetString(l.Name), Encoding.ASCII.GetString(l.Value))),
                DecodeAgainst(null, plan.FieldSection));
        }

        Assert.False(policy.CapacitySent);
        Assert.True(policy.OnPeerSettings(4096, 16).IsEmpty);
        Assert.False(policy.CapacitySent);
    }

    [Fact]
    public void NothingIsDynamicBeforeThePeersSettingsArrive()
    {
        var policy = Spotify();

        for (var i = 0; i < 3; i++)
        {
            var plan = policy.Plan(Request("/a", "1"));
            policy.Commit(plan, (ulong)(4 * i));
            Assert.True(plan.EncoderStreamBytes.IsEmpty);
            Assert.Equal(0UL, plan.RequiredInsertCount);
        }

        Assert.False(policy.CapacitySent);
    }

    [Fact]
    public void ThePeersSettingsProduceACapacityBoundedByThePeer()
    {
        Assert.Equal("3FE11F", Hex(Spotify().OnPeerSettings(4096, 16)));
        Assert.Equal("3FE11F", Hex(Spotify().OnPeerSettings(16383, 100)));
        // 1000 at a 5-bit prefix: 31, then 969 = 0x49 | 0x80, 0x07.
        Assert.Equal("3FC907", Hex(Spotify().OnPeerSettings(1000, 16)));

        var zero = Spotify();
        Assert.True(zero.OnPeerSettings(0, 16).IsEmpty);
        Assert.False(zero.CapacitySent);

        var once = Spotify();
        Assert.False(once.OnPeerSettings(4096, 16).IsEmpty);
        Assert.True(once.OnPeerSettings(4096, 16).IsEmpty);
    }

    // The capture, connection 61: stream 0 before the peer's SETTINGS, stream 4 after the
    // capacity went out, stream 8 with the first inserts. Reference doc s6.
    [Fact]
    public void TheFirstRequestAfterCapacityIsStillStaticAndTheSecondInserts()
    {
        var policy = Spotify();
        policy.Commit(policy.Plan(Request("/remote-config-resolver/v3/unauth/configuration", "378")), 0);
        var peer = Peer(policy, 4096, 16);
        Assert.True(policy.CapacitySent);

        // The capture's stream 4: a form POST with accept */*, so content-type and accept are
        // exact static matches here and not the pairs stream 8 will see for the second time.
        var stream4 = policy.Plan(Request(
            "/v1/pses/screenconfig", "150", "application/x-www-form-urlencoded", "*/*"));
        policy.Commit(stream4, 4);
        Assert.True(stream4.EncoderStreamBytes.IsEmpty);
        Assert.Equal(0UL, stream4.RequiredInsertCount);
        Assert.Equal("0000", Hex(stream4.FieldSection[..2]));

        var stream8 = policy.Plan(Request("/remote-config-resolver/v3/unauth/configuration", "380"));

        Assert.Equal(
            [":authority", "spotify-app-version", "time-zone", "app-platform", "priority",
             "accept-language", "user-agent", "x-client-id", "client-token"],
            stream8.Inserts.Select(insert => Encoding.ASCII.GetString(insert.Name)));
        Assert.StartsWith("C0914564A0C5A92BF8997456749A5F4B90F4FF6E456749A5F4B0EBAD6EE5B1063D5F887D70AEF38B89A13D", Hex(stream8.EncoderStreamBytes));
        Assert.Equal(9UL, stream8.RequiredInsertCount);
        // Prefix: EncRIC 10, S = 1, Delta 8 -> Base 0, exactly the capture's `0a 88`. Then
        // :method POST and :scheme https as static indexed lines (d4, d7), then :authority as
        // post-base index 0 (10).
        Assert.StartsWith("0A88D4D710", Hex(stream8.FieldSection));
        Assert.Equal(Enumerable.Range(0, 9).Select(i => (ulong)i), stream8.ReferencedAbsoluteIndices);

        // A peer decodes it: inserts first, then the section.
        Feed(peer, stream8.EncoderStreamBytes);
        var decoded = DecodeAgainst(peer, stream8.FieldSection);
        Assert.Equal(16, decoded.Count);
        Assert.Equal(("client-token", "AAGxl8UElUaNDsgAvOJvyJ8k71PiW3qme"), decoded[15]);
        Assert.Equal(("content-length", "380"), decoded[12]);
    }

    [Fact]
    public void APairSeenOnceIsNeverInsertedAndAPairSeenTwiceIsInsertedOnItsSecondUse()
    {
        var policy = Spotify();
        policy.OnPeerSettings(4096, 16);
        policy.Commit(policy.Plan(Request("/first", "1")), 0);   // first after capacity: static
        policy.Commit(policy.Plan(Request("/second", "1")), 4);  // inserts the nine common pairs

        var third = policy.Plan(Request("/third", "1"));
        policy.Commit(third, 8);
        Assert.DoesNotContain(third.Inserts, insert => Encoding.ASCII.GetString(insert.Name) == ":path");

        // /third again: its second use, so now it inserts, and only it.
        var fourth = policy.Plan(Request("/third", "1"));
        Assert.Single(fourth.Inserts);
        Assert.Equal((":path", "/third"), (Encoding.ASCII.GetString(fourth.Inserts[0].Name), Encoding.ASCII.GetString(fourth.Inserts[0].Value)));
    }

    [Fact]
    public void AnUncommittedPlanChangesNothing()
    {
        var policy = Spotify();
        policy.OnPeerSettings(4096, 16);
        policy.Commit(policy.Plan(Request("/a", "1")), 0);

        var request = Request("/a", "1");
        var first = policy.Plan(request);
        var second = policy.Plan(request);
        Assert.Equal(Hex(first.EncoderStreamBytes), Hex(second.EncoderStreamBytes));
        Assert.Equal(Hex(first.FieldSection), Hex(second.FieldSection));
        Assert.Equal(0, policy.UseCount(A(":path"), A("/a")) - 1);

        policy.Commit(second, 4);
        var third = policy.Plan(request);
        Assert.True(third.EncoderStreamBytes.IsEmpty);          // everything is in the table now
        Assert.NotEqual(Hex(second.FieldSection), Hex(third.FieldSection));
    }

    [Fact]
    public void ALaterSectionReferencesTheTableRelativeToBase()
    {
        var policy = Spotify();
        var peer = Peer(policy, 4096, 16);
        policy.Commit(policy.Plan(Request("/a", "1")), 0);
        var inserting = policy.Plan(Request("/a", "1"));
        policy.Commit(inserting, 4);

        // Every non-exact-static pair - thirteen of the sixteen - was seen on stream 0 while
        // the table was active, so all thirteen insert here.
        Assert.Equal(13, inserting.Inserts.Count);
        Assert.Equal(13UL, inserting.RequiredInsertCount);

        var later = policy.Plan(Request("/a", "1"));
        Assert.True(later.EncoderStreamBytes.IsEmpty);
        Assert.Equal(13UL, later.RequiredInsertCount);
        // EncRIC 14, S = 0, Delta 0: Base == RIC == 13.
        Assert.StartsWith("0E00D4D7", Hex(later.FieldSection));
        // :authority is absolute 0 -> relative 12 -> `8c`.
        Assert.Equal("8C", Hex(later.FieldSection[4..5]));

        Feed(peer, inserting.EncoderStreamBytes);
        Assert.Equal(DecodeAgainst(peer, inserting.FieldSection), DecodeAgainst(peer, later.FieldSection));
    }

    // Peer maximum 16383, our capacity 4096: MaxEntries is 511, not 128, and the Required
    // Insert Count wraps modulo 1022. Three hundred inserts cross both 128 and 256; a decoder
    // built on the peer's number must recover every RIC.
    [Fact]
    public void TheRequiredInsertCountWrapsOnThePeersMaxEntries()
    {
        var policy = Spotify();
        var peer = Peer(policy, 16383, 100);
        policy.Commit(policy.Plan(Lines(("x-a", "0"))), 0);

        ulong stream = 4;
        for (var i = 0; i < 300; i++)
        {
            var pair = ("x-" + i, "v" + i);
            var seen = policy.Plan(Lines(pair));
            policy.Commit(seen, stream);
            stream += 4;
            var inserting = policy.Plan(Lines(pair));
            policy.Commit(inserting, stream);

            Assert.Single(inserting.Inserts);
            Feed(peer, inserting.EncoderStreamBytes);
            var decoded = DecodeAgainst(peer, inserting.FieldSection);
            Assert.Equal((pair.Item1, pair.Item2), decoded[0]);

            // The peer acknowledges each section, as a real one would; without that the
            // 4096-octet table fills with referenced entries after ~100 inserts and every
            // later insert is refused rather than evicting - the s2.1.1 rule, not a bug.
            Assert.True(policy.TryAcknowledgeSection(stream));
            stream += 4;
        }

        Assert.Equal(300UL, policy.Table!.InsertCount);
        Assert.Equal(511UL, policy.Table.MaxEntries);
    }

    [Fact]
    public void AnExhaustedBlockedStreamBudgetKeepsTheSectionKnownReceivedOnly()
    {
        var policy = Spotify();
        policy.OnPeerSettings(4096, peerBlockedStreams: 1);
        policy.Commit(policy.Plan(Request("/a", "1")), 0);
        var blocking = policy.Plan(Request("/a", "1"));
        policy.Commit(blocking, 4);
        Assert.NotEmpty(blocking.Inserts);
        Assert.Equal(1, policy.Table!.BlockedStreamCount);

        var starved = policy.Plan(Request("/a", "1"));
        Assert.True(starved.EncoderStreamBytes.IsEmpty);
        Assert.Equal(0UL, starved.RequiredInsertCount);
        Assert.Equal("0000", Hex(starved.FieldSection[..2]));

        Assert.True(policy.TryAcknowledgeSection(4));
        var released = policy.Plan(Request("/a", "1"));
        Assert.Equal(13UL, released.RequiredInsertCount);
    }

    [Fact]
    public void AnInsertThatWouldEvictAReferencedEntryBecomesALiteral()
    {
        // Capacity 120 holds three 35-octet entries (a/b1, a/b2, a/b3 = 105) and no fourth.
        var policy = Spotify(capacity: 120);
        policy.OnPeerSettings(4096, 16);
        var first = Lines(("a", "b1"), ("a", "b2"), ("a", "b3"));
        policy.Commit(policy.Plan(first), 0);
        var inserting = policy.Plan(first);
        policy.Commit(inserting, 4);
        Assert.Equal(3, inserting.Inserts.Count);

        // A fourth pair, seen before, cannot be inserted while stream 4's references stand.
        policy.Commit(policy.Plan(Lines(("a", "b4"))), 8);
        var refused = policy.Plan(Lines(("a", "b4")));
        Assert.Empty(refused.Inserts);
        Assert.True(refused.EncoderStreamBytes.IsEmpty);

        Assert.True(policy.TryAcknowledgeSection(4));
        var allowed = policy.Plan(Lines(("a", "b4")));
        Assert.Single(allowed.Inserts);
    }

    [Fact]
    public void UnderTheNeverPolicyACapacityIsAnnouncedAndNothingIsInserted()
    {
        var policy = new TlsQuicQpackEncoderPolicy(new TlsQuicHttp3Spec { QpackEncoderDynamicTableCapacity = 4096 });
        Assert.Equal("3FE11F", Hex(policy.OnPeerSettings(4096, 16)));
        for (var i = 0; i < 3; i++)
        {
            var plan = policy.Plan(Request("/a", "1"));
            policy.Commit(plan, (ulong)(4 * i));
            Assert.Empty(plan.Inserts);
            Assert.Equal(0UL, plan.RequiredInsertCount);
        }
    }

    [Fact]
    public void ThePeersDecoderInstructionsAreAppliedOrRefused()
    {
        var policy = Spotify();
        Assert.False(policy.TryAcknowledgeSection(4));      // no table yet
        Assert.False(policy.TryIncrementKnownReceived(1));
        policy.CancelStream(4);                             // always legal

        policy.OnPeerSettings(4096, 16);
        policy.Commit(policy.Plan(Request("/a", "1")), 0);
        var inserting = policy.Plan(Request("/a", "1"));
        policy.Commit(inserting, 4);

        Assert.False(policy.TryIncrementKnownReceived(0));
        Assert.False(policy.TryIncrementKnownReceived(14));
        Assert.True(policy.TryIncrementKnownReceived(13));
        Assert.Equal(0, policy.Table!.BlockedStreamCount);
        Assert.True(policy.TryAcknowledgeSection(4));
        Assert.False(policy.TryAcknowledgeSection(4));
    }
}
