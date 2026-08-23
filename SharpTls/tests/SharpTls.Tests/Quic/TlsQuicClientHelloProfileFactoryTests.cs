using System.Buffers.Binary;
using System.Text.RegularExpressions;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// Task B8: the h3 profile factory.
//
// ============================================================================
// EVERY ASSERTION HERE READS THE ENCODED CLIENTHELLO BACK, NOT THE BUILDER'S INPUT.
// ============================================================================
//
//   The factory's entire job is to put three things on the wire - the ALPN token, extension
//   57's body, and the caller's TLS half - so a test that asked the builder what it was told
//   would confirm only that a setter stored a value. Every test below therefore goes
//   profile -> BuildDeterministicForTesting -> ClientHelloCapture.Import, which is the
//   library's own importer parsing the same bytes a server would receive.
//
//   THE SEED IS FIXED AND SHARED. BuildDeterministicForTesting pins the client random, the
//   session id and the ECDHE key shares, so two encodings of two profiles differ in exactly
//   the bytes the two profiles differ in. That is what lets a "these two differ" assertion
//   name WHICH parameter differs instead of shrugging at a changed blob.
//
// ============================================================================
// WHY THE PER-CONNECTION WITNESS IS NOT A RANDOMISED ONE.
// ============================================================================
//
//   A caching mutant - one that memoises Create's result, or hoists the Compose call into a
//   field - is killed by "two calls differ" only if the two draws actually differ, and three
//   uniform draws can collide. TheDrawIsCalledOncePerCreateAndItsResultIsNeverReused uses a
//   COUNTER as the draw, so the two values are 0 and 1 by construction and the kill does not
//   depend on chance at all. The tests over the real preset then say WHICH parameters vary,
//   over enough compositions that a false failure needs a collision with probability below
//   one in 10^14 - and a caching mutant fails those with certainty too, because it produces
//   one distinct value where the assertion demands more than one.
public sealed class TlsQuicClientHelloProfileFactoryTests
{
    private const string Rfc9114Path =
        "docs/superpowers/specs/reference-captures/" +
        "rfc9114-section3.2-connection-establishment.txt";

    /// <summary>Enough compositions that "all equal" cannot happen by chance. The smallest
    /// support of the three draws is RFC 9368 s3's reserved-version pattern, four free nibbles
    /// = 16^4 = 65536 values, so the chance that this many draws are all equal is
    /// 65536^-(n-1) - below 10^-14 at n = 4 and far below it here.</summary>
    private const int Compositions = 8;

    private static readonly byte[] Seed = [0x2b];

    // ------------------------------------------------------------------------------
    // The token, decoded out of the encoded ClientHello.
    // ------------------------------------------------------------------------------

    /// <summary>
    /// RFC 9001 s8.4: QUIC does not use TLS compatibility mode, so legacy_session_id MUST be
    /// empty. This regressed in the field, not in a test: WithSessionId(null) reads as "empty"
    /// but means UNSPECIFIED, and the encoder then filled 32 random bytes. Every BoringSSL peer
    /// answered CRYPTO_ERROR + alert 47 (illegal_parameter) before any request; lenient peers
    /// accepted it, so nothing offline or against fp.impersonate.pro ever noticed.
    /// </summary>
    [Fact]
    public void TheSessionIdIsEmptyBecauseQuicHasNoCompatibilityMode()
    {
        // OFF THE ENCODED BYTES, NOT off ClientHelloCapture.Import. Import drops the session id
        // unless PreserveSessionId is set, so Spec.SessionId is null whatever the wire says -
        // the first version of this test asserted on it and passed with the fix reverted.
        // Walks to the field rather than assuming an offset: the record header is optional here.
        static int SessionIdLengthOf(byte[] hello)
        {
            var i = hello[0] == 0x16 ? 5 : 0;      // optional TLS record header
            i += 4;                                 // handshake type + 3-byte length
            i += 2 + TlsConstants.RandomLength;     // legacy_version + random
            return hello[i];
        }

        static int EncodedSessionIdLength(TlsQuicClientHelloProfileFactory factory)
        {
            return SessionIdLengthOf(Encode(factory));
        }

        // The caller's TLS half asks for the ILLEGAL thing, which is the point: a persona must
        // not be able to put a session id on a QUIC hello, whether by asking for one outright
        // or by leaving it unspecified and inheriting the 32-byte TCP compatibility default.
        Assert.Equal(0, EncodedSessionIdLength(new TlsQuicClientHelloProfileFactory
        {
            Tls = builder => builder.WithSessionId(new byte[32]),
        }));

        Assert.Equal(0, EncodedSessionIdLength(new TlsQuicClientHelloProfileFactory
        {
            Tls = builder => builder.WithSessionId(null),
        }));

        // Non-vacuous in the other direction: over TCP the same request DOES produce one, so
        // the assertions above are reading a real field that can hold a non-zero value.
        Assert.Equal(32, SessionIdLengthOf(
            ClientHelloProfiles.Custom(b => b.WithSessionId(new byte[32]))
                .BuildDeterministicForTesting("example.test", Seed)));
    }

    [Fact]
    public void TheShippedFactoryOffersTheTokenRfc9114Section3Point2Names()
    {
        // FROM THE EXTRACT AND NOT FROM MEMORY. The token is pulled out of the sentence in
        // the checked-in RFC extract, so the assertion compares the tree against the RFC
        // rather than against a string this file typed.
        var extract = File.ReadAllText(Path.Combine(RepositoryRoot(), Rfc9114Path));
        var quoted = Regex.Match(
            extract.ReplaceLineEndings(" "),
            @"HTTP/3 support is indicated by\s+selecting the ALPN token ""([^""]+)"" in the TLS handshake");
        Assert.True(quoted.Success, "RFC 9114 s3.2's ALPN sentence was not found in the extract.");
        var token = quoted.Groups[1].Value;

        var offered = Import(new TlsQuicClientHelloProfileFactory()).Spec.AlpnProtocols;

        Assert.Equal(new[] { token }, offered);
        Assert.Equal(TlsQuicClientHelloProfileFactory.Http3AlpnToken, token);
    }

    [Fact]
    public void TheOfferedAlpnListIsTheCallersAndNotThisTypesDefault()
    {
        // RFC 9114 s3.2, the sentence after the one above: "Support for other
        // application-layer protocols MAY be offered in the same handshake." A factory that
        // ignored this knob and always emitted h3 would pass the test above.
        var offered = Import(new TlsQuicClientHelloProfileFactory
        {
            AlpnProtocols = ["h3-29", "h3", "http/1.1"],
        }).Spec.AlpnProtocols;

        Assert.Equal(new[] { "h3-29", "h3", "http/1.1" }, offered);
    }

    [Fact]
    public void AnEmptyAlpnListIsRefusedWhileExtensionFiftySevenIsPresent()
    {
        // A KNOB WHOSE EXTREME THIS LIBRARY REFUSES, RECORDED RATHER THAN HIDDEN.
        // ClientHelloBuilder.BuildConfiguration rejects any ClientHello that carries extension
        // 57 and no ALPN. That check predates B8 and is not the factory's, and the factory does
        // not swallow it - so "a QUIC client offering no ALPN at all" is a fingerprint this
        // library cannot currently express, and this test says so instead of leaving a caller
        // to discover it from a stack trace.
        var factory = new TlsQuicClientHelloProfileFactory { AlpnProtocols = [] };

        var thrown = Assert.Throws<InvalidOperationException>(() => factory.Create([]));
        Assert.Contains("at least one ALPN protocol", thrown.Message, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------------------
    // Two connections are two draws - which parameter, not "some byte".
    // ------------------------------------------------------------------------------

    [Fact]
    public void TheDrawIsCalledOncePerCreateAndItsResultIsNeverReused()
    {
        // THE DETERMINISTIC WITNESS. See this class's header: a counter removes chance from
        // the kill, so a factory that memoised its profile, or composed once into a field,
        // fails here every single run rather than most of them.
        const ulong Identifier = 0x4242;
        var calls = 0UL;
        var factory = new TlsQuicClientHelloProfileFactory
        {
            ConnectionSpec = new TlsQuicConnectionSpec
            {
                TransportParameters = new TlsQuicTransportParameterSpec
                {
                    Parameters =
                    [
                        TlsQuicTransportParameterSlot.Drawn(_ => new TlsQuicTransportParameter(
                            Identifier, QuicVariableLengthInteger.Encode(calls++))),
                    ],
                },
            },
        };

        var first = ValueOf(Encode(factory), Identifier);
        var second = ValueOf(Encode(factory), Identifier);
        var third = ValueOf(Encode(factory), Identifier);

        Assert.Equal(3UL, calls);
        Assert.Equal(0UL, first);
        Assert.Equal(1UL, second);
        Assert.Equal(2UL, third);
    }

    [Fact]
    public void TheDefaultPresetVariesExactlyItsDrawnEntriesAcrossConnections()
    {
        // The partition is recomputed from the preset rather than written beside it, so an
        // entry changed from drawn to literal moves this test's own expectation with it.
        var preset = TlsQuicTransportParameterSpec.Brave151Parameters;
        var drawn = Enumerable.Range(0, preset.Length).Where(index => preset[index].IsDrawn);
        var expectedVarying = drawn.ToHashSet();
        Assert.Equal(
            preset.Length,
            expectedVarying.Count
                + preset.Count(slot => slot.HasLiteralValue)
                + preset.Count(slot => !slot.IsDrawn && !slot.HasLiteralValue));

        var runs = Compose(new TlsQuicClientHelloProfileFactory(), Compositions);
        foreach (var run in runs)
        {
            Assert.Equal(preset.Length, run.Count);
        }

        // POSITION AND NOT IDENTIFIER, because the reserved entry's identifier is itself part
        // of what is redrawn - there is no stable id to look it up by.
        for (var index = 0; index < preset.Length; index++)
        {
            var position = index;
            var distinct = runs
                .Select(run => Describe(run[position]))
                .Distinct(StringComparer.Ordinal)
                .Count();
            if (expectedVarying.Contains(index))
            {
                Assert.True(
                    distinct > 1,
                    $"Entry {index + 1} is drawn but emitted one value across "
                        + $"{Compositions} connections.");
            }
            else
            {
                Assert.True(
                    distinct == 1,
                    $"Entry {index + 1} is not drawn but emitted {distinct} values across "
                        + $"{Compositions} connections.");
            }
        }
    }

    [Fact]
    public void TheReservedIdentifierIsRedrawnAndItsValueIsNot()
    {
        // TASK B4's PARAMETER, on its own. What varies is the IDENTIFIER; RFC 9000 s18.1 makes
        // the value arbitrary and the capture publishes one, so a client that redrew the value
        // too would be a different client.
        var entries = Compose(new TlsQuicClientHelloProfileFactory(), Compositions)
            .Select(run => run.Single(parameter =>
                TlsQuicTransportParameterSpec.IsReservedIdentifier(parameter.Id)))
            .ToArray();

        Assert.True(entries.Select(entry => entry.Id).Distinct().Count() > 1);
        Assert.Single(entries.Select(entry => Convert.ToHexString(entry.Value)).Distinct());
    }

    [Fact]
    public void TheGreaseVersionInsideVersionInformationIsRedrawnAndTheChosenVersionIsNot()
    {
        // TASK B3's PARAMETER, on its own, read as RFC 9368 s3's Figure 2 rather than as a
        // blob: a chosen version then a list of available ones, all 32-bit big-endian. Only
        // the GREASE slot may move, and the preset lists it first.
        var values = Compose(new TlsQuicClientHelloProfileFactory(), Compositions)
            .Select(run => run
                .Single(parameter =>
                    parameter.Id == (ulong)TlsQuicTransportParameterId.VersionInformation)
                .Value)
            .ToArray();

        var chosen = values.Select(value => ReadVersion(value, 0)).ToArray();
        var grease = values.Select(value => ReadVersion(value, 1)).ToArray();
        var available = values.Select(value => ReadVersion(value, 2)).ToArray();

        Assert.Single(chosen.Distinct());
        Assert.True(grease.Distinct().Count() > 1);
        Assert.All(grease, version =>
            Assert.True(TlsQuicTransportParameterSpec.IsReservedVersion(version)));

        // The preset's available list is [GREASE, chosen], so the second entry must track the
        // chosen version and never the drawn one. Read from the emitted bytes rather than
        // compared against a number typed here - which version the preset chooses is B7's
        // claim to make against the capture, not this test's.
        Assert.Single(available.Distinct());
        Assert.Equal(chosen[0], available[0]);
        Assert.False(TlsQuicTransportParameterSpec.IsReservedVersion(chosen[0]));
    }

    [Fact]
    public void InitialRttIsRedrawnInsideTheRangeTheConnectionSpecNames()
    {
        // TASK B5's PARAMETER, on its own, and through the knob that overrides the preset's
        // fallback - so this also witnesses that the connection spec's range reaches the wire
        // rather than only the entry's own.
        var range = (TimeSpan.FromMicroseconds(700000), TimeSpan.FromMicroseconds(900000));
        var drawn = Compose(
                new TlsQuicClientHelloProfileFactory
                {
                    ConnectionSpec = new TlsQuicConnectionSpec { InitialRttRange = range },
                },
                Compositions)
            .Select(run => run
                .Single(parameter =>
                    parameter.Id == TlsQuicTransportParameterSpec.InitialRttIdentifier)
                .GetVariableInteger())
            .ToArray();

        Assert.True(drawn.Distinct().Count() > 1);
        Assert.All(drawn, microseconds => Assert.InRange(microseconds, 700000UL, 900000UL));

        // The interval asserted above is disjoint from the preset's fallback, so an
        // implementation that ignored the connection spec could not land inside it.
        Assert.True(
            TlsQuicTransportParameterSpec.Brave151InitialRttRange.Maximum <
                TimeSpan.FromMicroseconds(700000));
    }

    [Fact]
    public void OneProfileReusedForTwoConnectionsFreezesEveryDraw()
    {
        // THE DEFECT THE FACTORY EXISTS TO AVOID, pinned rather than left to a comment. A
        // ClientHelloProfile is immutable and carries the composed blob, so reuse is silent -
        // no exception, no warning, one connection's draws on every connection.
        var profile = new TlsQuicClientHelloProfileFactory().Create([]);

        var first = profile.BuildDeterministicForTesting("example.test", Seed);
        var second = profile.BuildDeterministicForTesting("example.test", Seed);

        Assert.Equal(Convert.ToHexString(first), Convert.ToHexString(second));
    }

    // ------------------------------------------------------------------------------
    // A caller's own fingerprint round-trips.
    // ------------------------------------------------------------------------------

    [Fact]
    public void AnArbitraryTransportParameterListReachesTheEncodedClientHelloUnchanged()
    {
        // THE DIRECTIVE'S ACCEPTANCE CRITERION: identifiers, values, count and ORDER, none of
        // them the preset's and none of them sorted. The identifiers are unknown to
        // TlsQuicTransportParameterId on purpose - RFC 9000 s18.1 makes a receiver ignore what
        // it does not know, and a library that could only emit the identifiers it has an enum
        // member for could not reproduce a client it has never seen.
        TlsQuicTransportParameterSlot[] listed =
        [
            TlsQuicTransportParameterSlot.Literal(0x1234, [0xde, 0xad]),
            TlsQuicTransportParameterSlot.Literal(0x1b, []),
            TlsQuicTransportParameterSlot.Literal(0x3fffffff, [0x01, 0x02, 0x03, 0x04, 0x05]),
            TlsQuicTransportParameterSlot.Literal(0x5f, [0xff]),
        ];

        var emitted = Compose(
            new TlsQuicClientHelloProfileFactory
            {
                ConnectionSpec = new TlsQuicConnectionSpec
                {
                    TransportParameters = new TlsQuicTransportParameterSpec
                    {
                        Parameters = [.. listed],
                    },
                },
            },
            1)[0];

        Assert.Equal(listed.Length, emitted.Count);
        for (var index = 0; index < listed.Length; index++)
        {
            Assert.Equal(listed[index].Id, emitted[index].Id);
        }

        Assert.Equal("DEAD", Convert.ToHexString(emitted[0].Value));
        Assert.Equal(string.Empty, Convert.ToHexString(emitted[1].Value));
        Assert.Equal("0102030405", Convert.ToHexString(emitted[2].Value));
        Assert.Equal("FF", Convert.ToHexString(emitted[3].Value));

        // ASCENDING ORDER IS A DIFFERENT BLOB, which is what makes the order assertion above
        // more than a coincidence: the four identifiers are listed in an order no sort
        // produces.
        Assert.NotEqual(
            listed.Select(slot => slot.Id).Order(),
            emitted.Select(parameter => parameter.Id));
    }

    [Fact]
    public void TheCallersTlsHalfReachesTheEncodedClientHelloUntouched()
    {
        // Finding 9 puts suites, groups and extension order in subsystem E. This test's job is
        // to prove the factory is a PASS-THROUGH for them - that nothing of a browser's TLS
        // half is baked into a subsystem B file.
        var imported = Import(new TlsQuicClientHelloProfileFactory
        {
            Tls = builder => builder
                .WithCipherSuites(
                    TlsCipherSuite.TlsChaCha20Poly1305Sha256,
                    TlsCipherSuite.TlsAes256GcmSha384)
                .WithSupportedGroups(NamedGroup.Secp384r1, NamedGroup.X25519)
                .WithKeyShares(NamedGroup.X25519),
        });

        Assert.Equal(
            new[] { TlsCipherSuite.TlsChaCha20Poly1305Sha256, TlsCipherSuite.TlsAes256GcmSha384 },
            imported.Spec.CipherSuites);
        Assert.Equal(
            new[] { NamedGroup.Secp384r1, NamedGroup.X25519 },
            imported.Spec.SupportedGroups);
        Assert.Equal(new[] { NamedGroup.X25519 }, imported.Spec.KeyShareGroups);
    }

    [Fact]
    public void TheFactorysOwnTwoCallsWinOverTheSameCallsInsideTheTlsHalf()
    {
        // THE ORDER OF APPLICATION, WITNESSED. The factory runs the caller's TLS half first
        // and its own two calls after, so a TLS half that forgets ALPN or extension 57 still
        // yields a usable profile. The cost is that one which sets them is overridden - stated
        // in the type's remarks and pinned here, because the alternative order is a one-line
        // edit that no other test on this class can see.
        var imported = Import(new TlsQuicClientHelloProfileFactory
        {
            AlpnProtocols = ["h3"],
            Tls = builder => builder
                .WithAlpn("this-is-not-what-goes-out")
                .WithQuicTransportParameters(new TlsQuicTransportParameters(
                    [TlsQuicTransportParameter.VariableInteger(
                        TlsQuicTransportParameterId.MaxIdleTimeout, 1)])),
        });

        Assert.Equal(new[] { "h3" }, imported.Spec.AlpnProtocols);
        Assert.Equal(
            TlsQuicTransportParameterSpec.Brave151Parameters.Length,
            imported.Spec.QuicTransportParameters!.Parameters.Count);
    }

    [Fact]
    public void TheAlpnListIsCopiedSoALaterMutationOfTheCallersListChangesNothing()
    {
        // IReadOnlyList<string> is a view, not a promise: a caller can hand over a List and go
        // on editing it. A factory that stored the reference would emit whatever that list said
        // at Create time, which is a fingerprint changing under a caller who never touched the
        // factory again.
        var supplied = new List<string> { "h3" };
        var factory = new TlsQuicClientHelloProfileFactory { AlpnProtocols = supplied };
        supplied[0] = "http/1.1";
        supplied.Add("h3-29");

        Assert.Equal(new[] { "h3" }, Import(factory).Spec.AlpnProtocols);
    }

    [Fact]
    public void ExtensionFiftySevensPositionIsTheProfilesAndNotThisFactorys()
    {
        // Finding 9's precise seam: the BODY is subsystem B's, the POSITION is subsystem E's.
        // Two layouts differing only in where the slot sits must both survive the factory.
        static List<ClientHelloExtensionKind?> Layout(bool transportParametersFirst) =>
            Import(new TlsQuicClientHelloProfileFactory
            {
                Tls = builder => builder.WithExtensionLayout(
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                    ClientHelloExtensionSpec.BuiltIn(
                        transportParametersFirst
                            ? ClientHelloExtensionKind.QuicTransportParameters
                            : ClientHelloExtensionKind.SupportedGroups),
                    ClientHelloExtensionSpec.BuiltIn(
                        transportParametersFirst
                            ? ClientHelloExtensionKind.SupportedGroups
                            : ClientHelloExtensionKind.QuicTransportParameters),
                    ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare)),
            }).Spec.Extensions.Select(extension => extension.BuiltInKind).ToList();

        var first = Layout(transportParametersFirst: true);
        var second = Layout(transportParametersFirst: false);

        Assert.Equal(
            first.IndexOf(ClientHelloExtensionKind.QuicTransportParameters) + 1,
            first.IndexOf(ClientHelloExtensionKind.SupportedGroups));
        Assert.Equal(
            second.IndexOf(ClientHelloExtensionKind.SupportedGroups) + 1,
            second.IndexOf(ClientHelloExtensionKind.QuicTransportParameters));
    }

    // ------------------------------------------------------------------------------
    // The options seam the connection uses.
    // ------------------------------------------------------------------------------

    [Fact]
    public async Task AFactoryBuiltProfileSatisfiesTheQuicClientOptionsThatHardRejectOne()
    {
        // CustomTlsQuicClientOptions.Snapshot demands TLS 1.3 only, semantic ALPN and a
        // semantic extension-57 slot. Before B8 nothing under src/ produced a profile that met
        // all three, which is why this assertion is the gate the task is named for.
        await using var client = new CustomTlsQuicClient(new CustomTlsQuicClientOptions
        {
            ServerName = "example.test",
            ClientHello = new TlsQuicClientHelloProfileFactory().Create([]),
        });

        Assert.False(client.IsHandshakeComplete);
    }

    [Fact]
    public void ASourceConnectionIdOfTheWrongLengthIsRefusedRatherThanTruncated()
    {
        // RFC 9000 s7.3 makes initial_source_connection_id the connection's own source
        // connection ID, so a length that disagrees with the spec is a spec disagreeing with
        // itself. The refusal lives in Compose; this asserts the factory does not swallow it.
        var factory = new TlsQuicClientHelloProfileFactory();

        var thrown = Assert.Throws<ArgumentException>(() => factory.Create([0x01, 0x02]));
        Assert.Equal("sourceConnectionId", thrown.ParamName);
    }

    [Fact]
    public void TheSourceConnectionIdReachesInitialSourceConnectionId()
    {
        var factory = new TlsQuicClientHelloProfileFactory
        {
            ConnectionSpec = new TlsQuicConnectionSpec { SourceConnectionIdLength = 4 },
        };

        var emitted = Import(factory, [0xa1, 0xb2, 0xc3, 0xd4])
            .Spec.QuicTransportParameters!
            .Get((ulong)TlsQuicTransportParameterId.InitialSourceConnectionId);

        Assert.NotNull(emitted);
        Assert.Equal("A1B2C3D4", Convert.ToHexString(emitted.Value));
    }

    // ------------------------------------------------------------------------------
    // The roller's per-origin cache, and why it cannot freeze a QUIC draw today.
    // ------------------------------------------------------------------------------

    // ------------------------------------------------------------------------------
    // Nothing on this path throws for input a caller can reach it with.
    // ------------------------------------------------------------------------------

    [Fact]
    public void TheKnobsRejectNullRatherThanFailingLaterInsideTheEncoder()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new TlsQuicClientHelloProfileFactory { ConnectionSpec = null! });
        Assert.Throws<ArgumentNullException>(() =>
            new TlsQuicClientHelloProfileFactory { AlpnProtocols = null! });
        Assert.Throws<ArgumentNullException>(() =>
            new TlsQuicClientHelloProfileFactory { Tls = null! });

        var thrown = Assert.Throws<ArgumentException>(() =>
            new TlsQuicClientHelloProfileFactory { AlpnProtocols = ["h3", null!] });
        Assert.Equal("AlpnProtocols", thrown.ParamName);
    }

    [Fact]
    public void AnEmptyParameterListProducesAProfileRatherThanAnException()
    {
        // An empty list means "a client that sends no transport parameters", which the seam
        // defines as a legal thing to say. It produces a ClientHello with an empty extension 57
        // - which CustomTlsQuicClientOptions then rejects for HTTP/3, in the one place that
        // knows the connection is meant to be HTTP/3.
        var imported = Import(new TlsQuicClientHelloProfileFactory
        {
            ConnectionSpec = new TlsQuicConnectionSpec
            {
                TransportParameters = new TlsQuicTransportParameterSpec { Parameters = [] },
            },
        });

        Assert.NotNull(imported.Spec.QuicTransportParameters);
        Assert.Empty(imported.Spec.QuicTransportParameters.Parameters);
    }

    // ------------------------------------------------------------------------------
    // Helpers.
    // ------------------------------------------------------------------------------

    /// <summary>One connection's ClientHello, encoded exactly as it would be sent.</summary>
    private static byte[] Encode(
        TlsQuicClientHelloProfileFactory factory,
        ReadOnlySpan<byte> sourceConnectionId = default) =>
        factory.Create(sourceConnectionId)
            .BuildDeterministicForTesting("example.test", Seed);

    /// <summary>The same bytes, parsed back by the library's own importer.</summary>
    private static ClientHelloCaptureResult Import(
        TlsQuicClientHelloProfileFactory factory,
        ReadOnlySpan<byte> sourceConnectionId = default) =>
        ClientHelloCapture.Import(Encode(factory, sourceConnectionId));

    /// <summary>The transport parameters of <paramref name="count"/> separate connections, each
    /// read back out of its own encoded ClientHello.</summary>
    private static IReadOnlyList<TlsQuicTransportParameter>[] Compose(
        TlsQuicClientHelloProfileFactory factory, int count) =>
        Enumerable.Range(0, count)
            .Select(_ => Import(factory).Spec.QuicTransportParameters!.Parameters)
            .ToArray();

    private static ulong ValueOf(byte[] encodedClientHello, ulong id) =>
        ClientHelloCapture.Import(encodedClientHello)
            .Spec.QuicTransportParameters!
            .Get(id)!
            .GetVariableInteger();

    /// <summary>Identifier and value together, because the reserved entry redraws both.</summary>
    private static string Describe(TlsQuicTransportParameter parameter) =>
        $"{parameter.Id}:{Convert.ToHexString(parameter.Value)}";

    /// <summary>RFC 9368 s3 Figure 2's fields are all 32-bit and big-endian; index 0 is the
    /// Chosen Version and the rest are the Available Versions in order.</summary>
    private static uint ReadVersion(byte[] value, int index) =>
        BinaryPrimitives.ReadUInt32BigEndian(value.AsSpan(sizeof(uint) * index));

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !Directory.Exists(Path.Combine(directory.FullName, "src", "SharpTls", "Quic")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory.FullName;
    }
}
