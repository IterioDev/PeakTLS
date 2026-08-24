using System.Globalization;
using System.Reflection;
using System.Text.RegularExpressions;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// WHERE THE EXPECTATIONS COME FROM, AND WHY NOT ONE OF THEM IS TYPED TWICE.
//
// Every RFC-derived default is SCRAPED OUT OF THE EXTRACT this repository holds, by a regex
// anchored on RFC 9002's own wording, and compared to the constant in the source. A test that
// wrote `Assert.Equal(3, KPacketThreshold)` would pass against any implementation that agreed
// with the test, including a wrong one - it would be scoring the test's memory of the RFC.
// TheDefaultsAreTheNumbersTheExtractStates is the one that matters most in this file for that
// reason, and it is the reason A3-0 captured the extracts at all.
//
// The knob COUNT is scraped out of the A3 plan's own table rather than written down here, for the
// same reason: a mutant that deleted a knob and a plan that grew one must both fail.
public sealed class TlsQuicRecoverySpecTests
{
    private const string SourcePath = "src/SharpTls/Quic/TlsQuicRecoverySpec.cs";

    private const string PlanPath =
        "docs/superpowers/plans/2026-08-21-quic-a3-recovery-and-congestion.md";

    private const string CaptureDirectory = "docs/superpowers/specs/reference-captures";

    // The two knobs that are NOT re-declared on the recovery spec, and the type they live on
    // instead. Both omissions are load-bearing: a second initial-RTT number would be a second
    // place to keep in step with transport parameter 12583, and AckRangeLimit is already wired
    // to TlsQuicAckTracker.
    private static readonly (int Knob, string Member)[] KnobsOnTheConnectionSpec =
    [
        (1, nameof(TlsQuicConnectionSpec.InitialRttRange)),
        (13, nameof(TlsQuicConnectionSpec.AckRangeLimit)),
    ];

    // ------------------------------------------------------------------------------
    // The knob surface: the count comes from the plan and is never written here. Task A3-11
    // added row 15 - s7.7's pacing rate scale - and this test needed no edit for it beyond the
    // round-trip value below, which is the shape the header's "a plan that grew one must fail"
    // sentence was aiming at.
    // ------------------------------------------------------------------------------

    [Fact]
    public void EveryKnobInThePlansTableIsReachableFromTheConnectionSpec()
    {
        var planned = KnobNumbersInThePlansTable();
        var declared = KnobNumbersDeclaredInTheSource();

        // The plan's table is the authority on how many knobs there are. Nothing below writes
        // the number. Union rather than Concat because knob 1 is named in both places - the
        // settable member is InitialRttRange on the connection spec, and DrawInitialRtt is the
        // accessor that reads it.
        Assert.Equal(
            planned,
            declared.Keys
                .Union(KnobsOnTheConnectionSpec.Select(knob => knob.Knob))
                .OrderBy(number => number)
                .ToArray());

        // ARITHMETIC, SHOWN. The recovery spec carries every knob except the two already on
        // the connection spec, so the count reconciles as
        // (all planned) - (on the connection spec) = (settable on the recovery spec).
        var onTheRecoverySpec = planned.Length - KnobsOnTheConnectionSpec.Length;
        var settable = typeof(TlsQuicRecoverySpec)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Assert.Equal(onTheRecoverySpec, settable.Length);

        // EVERY declared knob resolves to a member that exists, and every member is claimed by
        // exactly one knob. The second direction is what stops a property being added without
        // a knob number - which is how a knob stops being reported by task A3-12's readout.
        foreach (var (number, member) in declared)
        {
            var reached = member == nameof(TlsQuicRecoverySpec.DrawInitialRtt)
                ? (MemberInfo?)typeof(TlsQuicRecoverySpec).GetMethod(member)
                : typeof(TlsQuicRecoverySpec).GetProperty(member);
            Assert.True(reached is not null, $"Knob {number} names {member}, which does not exist.");
        }

        var claimed = declared.Values.ToHashSet(StringComparer.Ordinal);
        foreach (var property in settable)
        {
            Assert.True(
                claimed.Contains(property.Name),
                $"{property.Name} is settable but carries no knob number, so nothing renders it.");
        }

        // And each of the two on the connection spec is a settable property there.
        foreach (var (number, member) in KnobsOnTheConnectionSpec)
        {
            var property = typeof(TlsQuicConnectionSpec).GetProperty(member);
            Assert.True(property is not null, $"Knob {number} names {member}.");
            Assert.NotNull(property!.GetMethod);
            Assert.NotNull(property.SetMethod);
        }
    }

    [Fact]
    public void EveryKnobOnTheRecoverySpecIsReadableAndSettable()
    {
        // The set of names is DERIVED from the type, then compared to the round-trip table
        // below - so a knob added without a round-trip case fails here rather than shipping
        // with a setter nobody ever proved stores anything.
        var properties = typeof(TlsQuicRecoverySpec)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance);
        var values = NonDefaultValues();
        Assert.Equal(
            properties.Select(p => p.Name).OrderBy(name => name, StringComparer.Ordinal),
            values.Keys.OrderBy(name => name, StringComparer.Ordinal));

        foreach (var property in properties)
        {
            Assert.NotNull(property.GetMethod);
            Assert.NotNull(property.SetMethod);

            var wanted = values[property.Name];
            var spec = new TlsQuicRecoverySpec();
            Assert.NotEqual(wanted, property.GetValue(spec));

            // init accessors are a compiler rule, not a runtime one, so reflection sets them.
            property.SetValue(spec, wanted);
            Assert.Equal(wanted, property.GetValue(spec));
        }
    }

    [Fact]
    public void TheConnectionSpecCarriesARecoverySpecAndRejectsANullOne()
    {
        Assert.NotNull(new TlsQuicConnectionSpec().Recovery);

        var replaced = new TlsQuicRecoverySpec { PacketThreshold = 1 };
        Assert.Same(replaced, new TlsQuicConnectionSpec { Recovery = replaced }.Recovery);

        // The rejecting branch on the connection spec's own setter.
        var error = Assert.Throws<ArgumentNullException>(
            () => new TlsQuicConnectionSpec { Recovery = null! });
        Assert.Equal("Recovery", error.ParamName);
    }

    // ------------------------------------------------------------------------------
    // The defaults, recomputed from the extracts rather than restated.
    // ------------------------------------------------------------------------------

    [Fact]
    public void TheDefaultsAreTheNumbersTheExtractStates()
    {
        var loss = Extract("rfc9002-section6-loss-detection.txt");
        var pto = Extract("rfc9002-section6.2-probe-timeout.txt");
        var congestion = Extract("rfc9002-section7-congestion-control.txt");
        var appendix = Extract("rfc9002-appendix-a-and-b-pseudocode-and-constants.txt");

        var spec = new TlsQuicRecoverySpec();

        // s6.1.1's packet threshold.
        Assert.Equal(
            Scrape(loss, @"\(kPacketThreshold\) is (\S+?)[.,]"),
            (double)spec.PacketThreshold);

        // s6.1.2's time threshold, stated as a ratio - so it is recomputed as one rather
        // than compared to 1.125, which is a number the RFC never writes.
        var ratio = Regex.Match(loss, @"multiplier, is (\d+)/(\d+)\.");
        Assert.True(ratio.Success);
        Assert.Equal(
            double.Parse(ratio.Groups[1].Value, CultureInfo.InvariantCulture)
                / double.Parse(ratio.Groups[2].Value, CultureInfo.InvariantCulture),
            spec.TimeThreshold);

        // Appendix A.2's kInitialRtt, which is the FALLBACK arm and not the default arm -
        // see DrawInitialRttReadsTheSpecsRangeAndFallsBackOnlyWhenThereIsNone.
        Assert.Equal(
            TimeSpan.FromMilliseconds(Scrape(appendix, @"Section 6\.2\.2 is (\S+?) ms")),
            TlsQuicRecoverySpec.KInitialRtt);

        // s7.2's two initial-window numbers and its minimum window.
        Assert.Equal(
            Scrape(congestion, @"initial congestion window of (\S+?) times the maximum"),
            (double)spec.InitialCongestionWindow.DatagramMultiplier);
        Assert.Equal(
            Scrape(congestion, @"limiting the window to the larger of (\S+?) bytes"),
            (double)spec.InitialCongestionWindow.ByteCap);
        Assert.Equal(
            Scrape(congestion, @"RECOMMENDED value is (\S+?) \* max_datagram_size"),
            (double)spec.MinimumCongestionWindowDatagrams);

        // s7.6's persistent-congestion threshold.
        Assert.Equal(
            Scrape(congestion, @"for kPersistentCongestionThreshold is (\S+?),"),
            (double)spec.PersistentCongestionThreshold);

        // Appendix B.1's kLossReductionFactor. THE NUMERAL IS ONLY HERE: s7.3.2 words the
        // same rule as "half the value of the congestion window", which this asserts is
        // present and numberless so that the citation cannot silently move.
        Assert.Equal(
            Scrape(
                appendix,
                @"kLossReductionFactor: .*? Section 7 recommends a value of ([0-9.]+)\."),
            spec.LossReductionFactor);
        Assert.Contains(
            "half the value of the congestion window", congestion, StringComparison.Ordinal);

        // s6.2.1's backoff and s6.2.4's probe count, both stated as words.
        Assert.Equal(
            Scrape(pto, @"period being set to (\S+?) its current value"),
            spec.PtoBackoff.Factor);
        Assert.Equal(
            (double)TlsQuicRecoverySpec.MaximumProbePacketsPerPto,
            Scrape(pto, @"MAY send up to (\S+?) full-sized datagrams"));
        Assert.Equal(TlsQuicRecoverySpec.MaximumProbePacketsPerPto, spec.ProbePacketsPerPto);

        // s7.7's burst limit is the initial congestion window, so the default is derived from
        // knob 2 rather than written again.
        Assert.Contains(
            "Senders SHOULD limit bursts to the initial congestion window",
            congestion,
            StringComparison.Ordinal);
        Assert.Equal(
            spec.InitialCongestionWindow.DatagramMultiplier,
            spec.PacingBurstDatagrams!.Value);
    }

    [Fact]
    public void TheScraperWouldNoticeIfAConstantMoved()
    {
        // The mechanism above proves itself in both directions before it is trusted: a pattern
        // the extract does not contain matches nothing rather than quietly matching something,
        // and the pattern that does contain it recovers the constant the source ships.
        var loss = Extract("rfc9002-section6-loss-detection.txt");
        Assert.DoesNotMatch(@"\(kPacketThresholdThatDoesNotExist\) is (\S+?)[.,]", loss);
        Assert.Equal(
            (double)TlsQuicRecoverySpec.KPacketThreshold,
            Scrape(loss, @"\(kPacketThreshold\) is (\S+?)[.,]"));
    }

    // ------------------------------------------------------------------------------
    // Knob 1: the initial RTT comes from the connection spec, not from kInitialRtt.
    // ------------------------------------------------------------------------------

    [Fact]
    public void DrawInitialRttReadsTheSpecsRangeAndFallsBackOnlyWhenThereIsNone()
    {
        // BRANCH 1 - no range. The shipped default, and the only arm kInitialRtt reaches.
        Assert.Null(new TlsQuicConnectionSpec().InitialRttRange);
        Assert.Equal(
            TlsQuicRecoverySpec.KInitialRtt,
            TlsQuicRecoverySpec.DrawInitialRtt(new TlsQuicConnectionSpec()));

        // BRANCH 2 - a range. THIS IS THE ONE THAT KILLS THE MUTANT THE PLAN NAMES: an
        // implementation that returned kInitialRtt unconditionally would satisfy every
        // arithmetic invariant task A3-7 can state about a PTO, because 333 ms is a
        // perfectly ordinary RTT. It is caught only by a range that excludes it, and the
        // preset range - 100 to 300 ms - is exactly such a range, which is why this uses the
        // shipped preset rather than one invented for the test.
        var range = TestQuicSpecValues.SampleInitialRttRange;
        Assert.True(range.Maximum < TlsQuicRecoverySpec.KInitialRtt);
        var spec = new TlsQuicConnectionSpec { InitialRttRange = range };

        var random = new Random(Seed);
        var draws = new List<TimeSpan>();
        for (var i = 0; i < Draws; i++)
        {
            draws.Add(TlsQuicRecoverySpec.DrawInitialRtt(spec, random));
        }

        Assert.All(draws, draw => Assert.InRange(draw, range.Minimum, range.Maximum));
        Assert.DoesNotContain(TlsQuicRecoverySpec.KInitialRtt, draws);

        // A DRAW AND NOT A CONSTANT. Returning the minimum, the maximum or the midpoint would
        // pass the in-range assertion above, so both halves of the range must be hit.
        var middle = range.Minimum + ((range.Maximum - range.Minimum) / 2);
        Assert.Contains(draws, draw => draw < middle);
        Assert.Contains(draws, draw => draw > middle);
        Assert.True(draws.Distinct().Count() > 1);
    }

    [Fact]
    public void DrawInitialRttAcceptsTheWidestRangeTheSpecAllows()
    {
        // The reachability witness for the overflow branch: TimeSpan.MaxValue as the maximum
        // is a range InitialRttRange accepts, and the exclusive upper bound it would otherwise
        // compute overflows. Nothing here may throw.
        var spec = new TlsQuicConnectionSpec
        {
            InitialRttRange = (TimeSpan.FromTicks(1), TimeSpan.MaxValue),
        };
        var random = new Random(Seed);
        for (var i = 0; i < Draws; i++)
        {
            var drawn = TlsQuicRecoverySpec.DrawInitialRtt(spec, random);
            Assert.InRange(drawn, TimeSpan.FromTicks(1), TimeSpan.MaxValue);
        }

        // And the other side of the same branch: a maximum one tick below it takes the
        // ordinary arm, so the branch is a real fork rather than a condition that is always
        // true or always false.
        var justBelow = new TlsQuicConnectionSpec
        {
            InitialRttRange = (TimeSpan.FromTicks(1), TimeSpan.FromTicks(long.MaxValue - 1)),
        };
        Assert.InRange(
            TlsQuicRecoverySpec.DrawInitialRtt(justBelow, random),
            TimeSpan.FromTicks(1),
            TimeSpan.FromTicks(long.MaxValue - 1));
    }

    [Fact]
    public void DrawInitialRttDrawsAfreshAndDefaultsItsRandomSource()
    {
        var spec = new TlsQuicConnectionSpec
        {
            InitialRttRange = TestQuicSpecValues.SampleInitialRttRange,
        };

        // A null source is the shared one rather than a throw - the branch a caller with no
        // Random of its own takes.
        var shared = new List<TimeSpan>();
        for (var i = 0; i < Draws; i++)
        {
            shared.Add(TlsQuicRecoverySpec.DrawInitialRtt(spec));
        }

        Assert.True(shared.Distinct().Count() > 1);

        // AND A SUPPLIED SOURCE IS THE ONE USED. Two equally seeded generators produce the
        // same sequence, which no implementation that ignored the argument and reached for
        // Random.Shared could do - and nothing else in this file would notice that, because
        // every other assertion about the draw is about its range or its spread.
        var left = new Random(Seed);
        var right = new Random(Seed);
        for (var i = 0; i < Draws; i++)
        {
            Assert.Equal(
                TlsQuicRecoverySpec.DrawInitialRtt(spec, left),
                TlsQuicRecoverySpec.DrawInitialRtt(spec, right));
        }

        // The rejecting branch: there is no spec to read a range out of.
        var error = Assert.Throws<ArgumentNullException>(
            () => TlsQuicRecoverySpec.DrawInitialRtt(null!));
        Assert.Equal("connectionSpec", error.ParamName);
    }

    // ------------------------------------------------------------------------------
    // Knob 4: the controller is a seam, and a caller may supply one this library never wrote.
    // ------------------------------------------------------------------------------

    [Fact]
    public void ACallerSuppliedControllerIsWhatComesBack()
    {
        // THE ACCEPTANCE CRITERION FOR THIS SEAM. RFC 9002 s7 specifies NewReno and permits a
        // sender to run something else; Chromium is said to run BBR. So a controller this
        // library has never heard of must be nameable, constructible and readable - if this
        // test can be satisfied only by an implementation NewReno ships with, the seam is an
        // enum wearing an interface.
        var spec = new TlsQuicRecoverySpec
        {
            CongestionController = () => new NamedController("BBRv2", Draws),
        };

        Assert.NotNull(spec.CongestionController);
        var controller = spec.CongestionController!();
        Assert.Equal("BBRv2", controller.Name);
        Assert.Equal(Draws, controller.CongestionWindowBytes);

        // A FACTORY AND NOT AN INSTANCE: two connections from one spec get two controllers,
        // so one connection's window cannot leak into the next.
        Assert.NotSame(controller, spec.CongestionController!());

        // The shipped default is "the NewReno RFC 9002 s7 specifies, supplied by task A3-9",
        // which is null here because this task ships no behaviour.
        Assert.Null(new TlsQuicRecoverySpec().CongestionController);
    }

    // ------------------------------------------------------------------------------
    // Validation: one reachability witness per rejecting branch.
    // ------------------------------------------------------------------------------

    [Theory]
    // InitialCongestionWindow, branch 1: a multiplier of zero or less is a connection that may
    // never send its first packet.
    [InlineData(0, 1)]
    [InlineData(-1, 1)]
    // InitialCongestionWindow, branch 2: a negative byte cap. Zero is NOT rejected - s7.2
    // limits to the larger of the cap and twice the datagram size - and
    // AZeroByteCapIsAcceptedBecauseSection7Point2TakesTheLarger witnesses that.
    [InlineData(1, -1)]
    public void AnInitialCongestionWindowOutsideSection7Point2sShapeIsRejected(
        int datagramMultiplier,
        int byteCap)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec
            {
                InitialCongestionWindow = (datagramMultiplier, byteCap),
            });
        Assert.Equal(nameof(TlsQuicRecoverySpec.InitialCongestionWindow), error.ParamName);
    }

    [Fact]
    public void AZeroByteCapIsAcceptedBecauseSection7Point2TakesTheLarger()
    {
        // The non-rejecting side of the byte-cap branch, so that widening the guard to
        // ThrowIfNegativeOrZero is a change some test notices.
        var spec = new TlsQuicRecoverySpec { InitialCongestionWindow = (1, 0) };
        Assert.Equal((1, 0), spec.InitialCongestionWindow);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void AMinimumCongestionWindowOfNoDatagramsIsRejected(int datagrams)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { MinimumCongestionWindowDatagrams = datagrams });
        Assert.Equal(
            nameof(TlsQuicRecoverySpec.MinimumCongestionWindowDatagrams), error.ParamName);
    }

    [Theory]
    // Branch 1 - not finite. THE BRANCH THE COMPARISON HELPERS CANNOT COVER: every comparison
    // against NaN is false, so ThrowIfNegativeOrZero and ThrowIfGreaterThan both accept it.
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    // Branch 2 - not positive. A factor of zero collapses the window to nothing on one loss.
    [InlineData(0.0)]
    [InlineData(-0.5)]
    // Branch 3 - above one, which grows the window on loss and is therefore not a reduction.
    [InlineData(1.5)]
    public void ALossReductionFactorThatIsNotAReductionIsRejected(double factor)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { LossReductionFactor = factor });
        Assert.Equal(nameof(TlsQuicRecoverySpec.LossReductionFactor), error.ParamName);
    }

    [Fact]
    public void ALossReductionFactorOfExactlyOneIsAccepted()
    {
        // The boundary the upper guard is inclusive at: a controller that does not reduce at
        // all - BBR does not halve - must be expressible, so this is a knob value and not an
        // error.
        Assert.Equal(
            TlsQuicRecoverySpec.MaximumLossReductionFactor,
            new TlsQuicRecoverySpec
            {
                LossReductionFactor = TlsQuicRecoverySpec.MaximumLossReductionFactor,
            }.LossReductionFactor);
    }

    [Fact]
    public void APositiveNotANumberIsRejectedByEveryFloatingPointKnob()
    {
        // THE REACHABILITY WITNESS FOR ThrowIfNotFinite, AND IT IS NOT double.NaN. A MUTATION
        // SWEEP FOUND THIS: deleting the finiteness check on LossReductionFactor SURVIVED a
        // suite whose only NaN was the literal, because .NET's double.NaN has its sign bit SET
        // and ThrowIfNegativeOrZero tests the sign bit rather than a comparison - so it
        // rejected that NaN by accident. A NaN with the sign bit CLEAR is not negative, is not
        // zero, and is not greater than anything, so it passes every comparison guard and only
        // the finiteness check stops it.
        var positive = BitConverter.UInt64BitsToDouble(0x7FF8000000000000UL);
        Assert.True(double.IsNaN(positive));
        Assert.False(double.IsNegative(positive));

        // The accident spelled out, so that a future reader does not "simplify" the guard away
        // again on the grounds that the literal is already rejected.
        Assert.True(double.IsNegative(double.NaN));

        Assert.Equal(
            nameof(TlsQuicRecoverySpec.LossReductionFactor),
            Assert.Throws<ArgumentOutOfRangeException>(
                () => new TlsQuicRecoverySpec { LossReductionFactor = positive }).ParamName);
        Assert.Equal(
            nameof(TlsQuicRecoverySpec.TimeThreshold),
            Assert.Throws<ArgumentOutOfRangeException>(
                () => new TlsQuicRecoverySpec { TimeThreshold = positive }).ParamName);
        Assert.Equal(
            nameof(TlsQuicRecoverySpec.PtoBackoff),
            Assert.Throws<ArgumentOutOfRangeException>(
                () => new TlsQuicRecoverySpec { PtoBackoff = (positive, null) }).ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void APacketThresholdOfZeroIsRejected(int threshold)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { PacketThreshold = threshold });
        Assert.Equal(nameof(TlsQuicRecoverySpec.PacketThreshold), error.ParamName);
    }

    [Fact]
    public void APacketThresholdBelowThreeIsAcceptedBecauseSection6Point1Point1SaysShouldNot()
    {
        // A SHOULD NOT is not a MUST NOT, and s6.1.1 lines 67-74 name adaptive thresholds as
        // something implementations do - so 1 and 2 are knob values rather than errors. A
        // guard that enforced the recommendation would make this library unable to reproduce a
        // client that does not follow it, which is the opposite of its goal.
        Assert.Equal(1, new TlsQuicRecoverySpec { PacketThreshold = 1 }.PacketThreshold);
        Assert.True(TlsQuicRecoverySpec.KPacketThreshold > 1);
    }

    [Theory]
    // Branch 1 - not finite, for the same reason LossReductionFactor has one.
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    // Branch 2 - not positive.
    [InlineData(0.0)]
    [InlineData(-1.0)]
    public void ATimeThresholdThatIsNotAPositiveMultiplierIsRejected(double threshold)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { TimeThreshold = threshold });
        Assert.Equal(nameof(TlsQuicRecoverySpec.TimeThreshold), error.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void APersistentCongestionThresholdOfZeroIsRejected(int threshold)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { PersistentCongestionThreshold = threshold });
        Assert.Equal(
            nameof(TlsQuicRecoverySpec.PersistentCongestionThreshold), error.ParamName);
    }

    [Theory]
    // Branch 1 - a factor that is not a finite number.
    [InlineData(double.NaN, null)]
    [InlineData(double.PositiveInfinity, null)]
    // Branch 2 - a factor below one, which SHRINKS the probe timeout on each expiry. s6.2.1
    // makes the increase a MUST.
    [InlineData(0.5, null)]
    [InlineData(0.0, null)]
    // Branch 3 - a ceiling that is present and not positive. Null is the RFC's own shape and
    // ANullPtoCeilingIsTheShapeSection6Point2Point1Describes witnesses it.
    [InlineData(2.0, 0L)]
    [InlineData(2.0, -1L)]
    public void APtoBackoffThatDoesNotBackOffIsRejected(double factor, long? maximumTicks)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec
            {
                PtoBackoff = (
                    factor,
                    maximumTicks is { } ticks ? TimeSpan.FromTicks(ticks) : null),
            });
        Assert.Equal(nameof(TlsQuicRecoverySpec.PtoBackoff), error.ParamName);
    }

    [Fact]
    public void ANullPtoCeilingIsTheShapeSection6Point2Point1Describes()
    {
        // The non-rejecting side of the ceiling branch, and the shipped default: s6.2.1
        // never mentions a ceiling, so "no ceiling" is what the RFC describes and a ceiling
        // is an implementation choice.
        Assert.Null(new TlsQuicRecoverySpec().PtoBackoff.Maximum);
        Assert.Equal(
            TimeSpan.FromTicks(1),
            new TlsQuicRecoverySpec
            {
                PtoBackoff = (
                    TlsQuicRecoverySpec.MinimumPtoBackoffFactor, TimeSpan.FromTicks(1)),
            }.PtoBackoff.Maximum);
    }

    [Theory]
    // Branch 1 - fewer than the one s6.2.4 requires.
    [InlineData(0)]
    [InlineData(-1)]
    // Branch 2 - more than the two s6.2.4 permits.
    [InlineData(3)]
    public void AProbeCountOutsideSection6Point2Point4sOneOrTwoIsRejected(int packets)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { ProbePacketsPerPto = packets });
        Assert.Equal(nameof(TlsQuicRecoverySpec.ProbePacketsPerPto), error.ParamName);
    }

    [Fact]
    public void BothOfSection6Point2Point4sProbeCountsAreAccepted()
    {
        // The RFC permits either, and the plan calls the choice byte-countable, so both ends
        // of the accepted interval are knob values.
        Assert.Equal(1, new TlsQuicRecoverySpec { ProbePacketsPerPto = 1 }.ProbePacketsPerPto);
        Assert.Equal(
            TlsQuicRecoverySpec.MaximumProbePacketsPerPto,
            new TlsQuicRecoverySpec
            {
                ProbePacketsPerPto = TlsQuicRecoverySpec.MaximumProbePacketsPerPto,
            }.ProbePacketsPerPto);
    }

    [Fact]
    public void AnUndeclaredProbeContentIsRejected()
    {
        // An enum is an integer in a hat: the cast is legal and would otherwise reach task
        // A3-7's switch as a case nothing handles. The value is derived from the declared
        // members rather than written, so adding one cannot make this test vacuous.
        var undeclared = (TlsQuicProbeContents)(
            Enum.GetValues<TlsQuicProbeContents>().Select(v => (int)v).Max() + 1);
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { ProbeContents = undeclared });
        Assert.Equal(nameof(TlsQuicRecoverySpec.ProbeContents), error.ParamName);

        Assert.All(
            Enum.GetValues<TlsQuicProbeContents>(),
            declared => Assert.Equal(
                declared, new TlsQuicRecoverySpec { ProbeContents = declared }.ProbeContents));
    }

    // ========================================================================
    // KNOB 11'S SHIPPED DEFAULT, PINNED SO THAT MOVING IT AGAIN IS DELIBERATE.
    // ========================================================================
    //
    // TASK A3-14 CHANGED THIS DEFAULT FROM Ping TO RetransmittedData and this test is the
    // tripwire that makes a third change argue with something. A default nobody asserts is a
    // default anybody can edit while meaning to do something else, which is how Ping shipped
    // long enough for A3-13 to meet a server that refuses it.
    //
    // THE RFC JUSTIFICATION, WHICH IS THE PART THAT OUTLIVES THE MEASUREMENT.
    // rfc9002-section6.2-probe-timeout.txt s6.2.4 puts the three arms in an order:
    //   line 205    "An endpoint SHOULD include new data in packets that are sent on PTO
    //                expiration."
    //   line 206    "Previously sent data MAY be sent if no new data can be sent."
    //   lines 215-7 "When there is no data to send, the sender SHOULD send a PING or other
    //                ack-eliciting frame in a single packet, rearming the PTO timer."
    // The PING is scoped BY ITS OWN SENTENCE to the no-data case. Defaulting to Ping took that
    // fallback unconditionally - including while holding unacknowledged Initial CRYPTO - so it
    // satisfied neither line 205's SHOULD nor line 206's MAY, ever.
    //
    // AND A PING-ONLY CLIENT INITIAL IS LEGAL, which is why this is a default change and not a
    // deletion. s6.2.3 lines 180-183 name that exact packet as correct behaviour: "a client can
    // coalesce an Initial packet containing PING and PADDING frames with a 0-RTT data packet".
    // Ping therefore stays SELECTABLE - asserted below, and driven end to end by
    // APingOnlyProbeCarriesNoRepairAndLeavesTheServerWaiting.
    [Fact]
    public void TheShippedProbeContentsDefaultIsSection6Point2Point4sFirstChoice()
    {
        Assert.Equal(TlsQuicProbeContents.RetransmittedData, new TlsQuicRecoverySpec().ProbeContents);

        // Stated as its own assertion rather than left to follow, because "not Ping" is the
        // specific claim A3-13's live run bought and the one a regression would undo.
        Assert.NotEqual(TlsQuicProbeContents.Ping, new TlsQuicRecoverySpec().ProbeContents);

        // THE KNOB SURVIVES THE DEFAULT CHANGE. The user's standing directive is that anything
        // a real client could send stays reachable, so "fixing" this by deleting the member
        // must fail here too - hence the membership assertion and not just the round trip.
        Assert.Equal(
            [
                nameof(TlsQuicProbeContents.Ping),
                nameof(TlsQuicProbeContents.PingWithPadding),
                nameof(TlsQuicProbeContents.RetransmittedData),
            ],
            Enum.GetNames<TlsQuicProbeContents>().OrderBy(name => name, StringComparer.Ordinal));

        Assert.Equal(
            TlsQuicProbeContents.Ping,
            new TlsQuicRecoverySpec { ProbeContents = TlsQuicProbeContents.Ping }.ProbeContents);

        // AND THE DEFAULT IS REACHABLE BY NAME AS WELL AS BY OMISSION, so a spec that sets it
        // explicitly and one that leaves it alone are the same spec.
        Assert.Equal(
            new TlsQuicRecoverySpec().ProbeContents,
            new TlsQuicRecoverySpec
            {
                ProbeContents = TlsQuicProbeContents.RetransmittedData,
            }.ProbeContents);

        // NO OTHER KNOB MOVED WITH IT. A3-14's change is one initialiser; a build that reset
        // the record's other defaults while editing this one would pass every assertion above.
        var shipped = new TlsQuicRecoverySpec();
        var flipped = new TlsQuicRecoverySpec { ProbeContents = TlsQuicProbeContents.Ping };
        Assert.Equal(shipped.ProbePacketsPerPto, flipped.ProbePacketsPerPto);
        Assert.Equal(shipped.PtoBackoff, flipped.PtoBackoff);
        Assert.Equal(shipped.PacketThreshold, flipped.PacketThreshold);
        Assert.Equal(shipped.TimeThreshold, flipped.TimeThreshold);
        Assert.Equal(shipped.AckPolicy, flipped.AckPolicy);
        Assert.Equal(shipped.InitialCongestionWindow, flipped.InitialCongestionWindow);
    }

    [Fact]
    public void AnUndeclaredAckPolicyIsRejected()
    {
        var undeclared = (TlsQuicAckPolicy)(
            Enum.GetValues<TlsQuicAckPolicy>().Select(v => (int)v).Max() + 1);
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { AckPolicy = undeclared });
        Assert.Equal(nameof(TlsQuicRecoverySpec.AckPolicy), error.ParamName);

        Assert.All(
            Enum.GetValues<TlsQuicAckPolicy>(),
            declared => Assert.Equal(
                declared, new TlsQuicRecoverySpec { AckPolicy = declared }.AckPolicy));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void APacingBurstOfNoDatagramsIsRejected(int burst)
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new TlsQuicRecoverySpec { PacingBurstDatagrams = burst });
        Assert.Equal(nameof(TlsQuicRecoverySpec.PacingBurstDatagrams), error.ParamName);
    }

    [Fact]
    public void ANullPacingBurstIsTheOffSwitchAndNotAnError()
    {
        // The other side of the same branch. s7.7 makes pacing a SHOULD, so a sender that
        // does not pace must be expressible - and it is expressed as an absent burst rather
        // than as a separate boolean, which would admit "pacing off, burst 10".
        Assert.Null(new TlsQuicRecoverySpec { PacingBurstDatagrams = null }.PacingBurstDatagrams);
        Assert.NotNull(new TlsQuicRecoverySpec().PacingBurstDatagrams);
    }

    [Fact]
    public void NoKnobThrowsAnythingButAnArgumentException()
    {
        // "Nothing on these paths throws for any input" means every escape is a documented
        // Argument exception naming the member - never an overflow, a null dereference or a
        // format error. Every property is driven with the most hostile value its type has.
        var properties = typeof(TlsQuicRecoverySpec)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance);
        var failures = new List<string>();
        foreach (var property in properties)
        {
            foreach (var hostile in HostileValues(property.PropertyType))
            {
                try
                {
                    property.SetValue(new TlsQuicRecoverySpec(), hostile);
                }
                catch (TargetInvocationException invocation)
                    when (invocation.InnerException is ArgumentException)
                {
                    // A documented rejection.
                }
                catch (Exception unexpected)
                {
                    failures.Add($"{property.Name} <- {hostile}: {unexpected.GetType().Name}");
                }
            }
        }

        Assert.Empty(failures);

        // The draw is on the same footing: the widest range the spec accepts, drawn many
        // times, must not overflow.
        var widest = new TlsQuicConnectionSpec
        {
            InitialRttRange = (TimeSpan.FromTicks(1), TimeSpan.MaxValue),
        };
        var random = new Random(Seed);
        for (var i = 0; i < Draws; i++)
        {
            TlsQuicRecoverySpec.DrawInitialRtt(widest, random);
        }
    }

    // ------------------------------------------------------------------------------
    // The markers, and the plan they cite.
    // ------------------------------------------------------------------------------

    // THE MARKER'S FORM IS DEFINED HERE AND NOWHERE ELSE: the word UNVERIFIED in capitals, a
    // comma, then "settled by task A3-" and the task's number. Every occurrence of the word in
    // the source must carry one, and every number must name a task the A3 plan actually has -
    // which is what stops an unbounded choice from shipping as though it were measured, and
    // stops the citation from rotting into a reference to nothing.
    [Fact]
    public void EveryUnverifiedPresetChoiceNamesATaskThatExistsInTheAPlan()
    {
        var source = Read(SourcePath);
        var plan = Read(PlanPath);

        var markers = Regex.Matches(source, @"\bUNVERIFIED\b").Count;
        var cited = Regex.Matches(source, @"\bUNVERIFIED, settled by task A3-(\d+)\b");

        Assert.NotEqual(0, markers);
        Assert.Equal(markers, cited.Count);

        // The resolution mechanism proves itself in both directions before it is trusted: the
        // task this file implements resolves, and a task number nobody has does not.
        Assert.Contains("## Task A3-2", plan, StringComparison.Ordinal);
        Assert.DoesNotContain("## Task A3-99", plan, StringComparison.Ordinal);

        // AND THE DEFERRED ARM RESOLVES AT ITS OWN HEADING DEPTH. The plan writes A3-0 to
        // A3-13 as "## Task A3-n" and the capture arm as "### Task A3-14", so the substring
        // searched for below is found inside the deeper heading rather than as a heading of
        // its own. Every marker in the source cites A3-14, so if that heading were renamed or
        // flattened this assertion says so.
        Assert.Contains("### Task A3-14", plan, StringComparison.Ordinal);
        Assert.Contains("## Task A3-14", plan, StringComparison.Ordinal);

        foreach (Match match in cited)
        {
            Assert.Contains(
                $"## Task A3-{match.Groups[1].Value}", plan, StringComparison.Ordinal);
        }

        // AND EVERY KNOB THE PLAN CALLS UNVERIFIED CARRIES ONE. The plan marks knobs 2, 4, 12
        // and 14; the count is read out of the plan's table rather than written here, so a
        // knob whose marker was deleted fails even though the file still has four others.
        var unverifiedRows = Regex.Matches(
            plan, @"^\| (\d+) \|.*\*\*UNVERIFIED\*\*", RegexOptions.Multiline);
        Assert.NotEmpty(unverifiedRows);
        var knobs = KnobNumbersDeclaredInTheSource();
        foreach (Match row in unverifiedRows)
        {
            var number = int.Parse(row.Groups[1].Value, CultureInfo.InvariantCulture);
            if (!knobs.TryGetValue(number, out var member))
            {
                continue;
            }

            Assert.Contains(
                "UNVERIFIED, settled by task A3-14",
                DocCommentFor(source, member),
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public void NoRecoveryConstantLivesOutsideThePresetBlock()
    {
        var lines = File.ReadAllLines(Path.Combine(RepositoryRoot(), SourcePath));
        var start = Array.FindIndex(
            lines, line => line.Contains("THE PRESET BLOCK.", StringComparison.Ordinal));
        var end = Array.FindIndex(
            lines,
            line => line.Contains("END OF THE PRESET BLOCK.", StringComparison.Ordinal));
        Assert.InRange(start, 0, end - 1);

        // CODE ONLY, NOT COMMENTS. Prose outside the block quotes RFC section numbers, extract
        // line ranges and transport-parameter identifiers, and must go on being able to. The
        // rule is about values the library USES, and a value is used by code.
        //
        // OUTSIDE THE BLOCK THE ONLY LITERALS PERMITTED ARE 0 AND 1, both structural: an
        // exclusive upper bound's increment, and a floor of one. Neither carries recovery
        // meaning, and permitting exactly those two is what makes this stricter than a
        // digit-count rule - a mutant writing `_packetThreshold = 3` outside the block fails.
        var outside = lines
            .Where((_, index) => index < start || index > end)
            .Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal));
        var escaped = outside
            .SelectMany(line => Regex.Matches(line, @"(?<![\w.])\d+(?:\.\d+)?(?![\w])"))
            .Select(match => match.Value)
            .Where(literal => literal is not ("0" or "1"))
            .ToArray();
        Assert.Empty(escaped);

        // The search would find one if there were one: the block itself, searched the same
        // way, is full of them.
        var inside = lines[start..(end + 1)]
            .Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal))
            .SelectMany(line => Regex.Matches(line, @"(?<![\w.])\d+(?:\.\d+)?(?![\w])"))
            .Where(match => match.Value is not ("0" or "1"))
            .ToArray();
        Assert.NotEmpty(inside);
    }

    // ------------------------------------------------------------------------------
    // Helpers.
    // ------------------------------------------------------------------------------

    // HOW MANY DRAWS A "THESE DIFFER" CLAIM IS MADE OVER. Two would establish the claim; it is
    // 256 because these tests are also run under a mutation sweep, where a constant-returning
    // mutant that survived one lucky pair would be recorded as a survivor. The narrowest range
    // any of these tests draws over is the preset's 200 ms, which is 2,000,000 ticks, so the
    // probability of 256 draws landing on one side of its midpoint is 2^-255.
    private const int Draws = 256;

    private const int Seed = 20260821;

    // A controller this library did not write, which is the case the seam exists for. It has no
    // slow start threshold, no recovery period and no three states - which is the whole reason
    // those stayed off ITlsQuicCongestionController when A3-10 folded A3-9's six signal members
    // onto it. What it must implement is exactly what RFC 9002 s7 lines 22-27 call generic, plus
    // s7.6.2's persistent-congestion MUST, and nothing NewReno-shaped.
    private sealed class NamedController(string name, long window) : ITlsQuicCongestionController
    {
        private long _bytesInFlight;

        public string Name => name;

        public long CongestionWindowBytes => window;

        public long BytesInFlight => _bytesInFlight;

        public bool CanSend(int bytes) => _bytesInFlight + bytes <= window;

        public void OnPacketSent(in TlsQuicSentPacket sent)
        {
            if (sent.IsInFlight)
            {
                _bytesInFlight += sent.Size;
            }
        }

        public void OnPacketsAcked(IReadOnlyList<TlsQuicSentPacket>? ackedPackets) =>
            Remove(ackedPackets);

        public void OnPacketsLost(IReadOnlyList<TlsQuicSentPacket>? lostPackets) =>
            Remove(lostPackets);

        public void OnPersistentCongestion()
        {
            // A controller with a fixed window has nothing to collapse, and s7.6.2's MUST is
            // still satisfiable by a sender that never grew past the minimum. The member exists
            // on the seam so that a controller which DOES have a window to collapse can be told;
            // this one records nothing because there is nothing to record.
        }

        public void OnPacketsDiscarded(IReadOnlyList<TlsQuicSentPacket>? discardedPackets) =>
            Remove(discardedPackets);

        private void Remove(IReadOnlyList<TlsQuicSentPacket>? packets)
        {
            if (packets is null)
            {
                return;
            }

            foreach (var packet in packets)
            {
                if (packet.IsInFlight)
                {
                    _bytesInFlight = Math.Max(0, _bytesInFlight - packet.Size);
                }
            }
        }
    }

    // One valid, non-default value per knob, keyed by member name. The key set is compared to
    // the reflected property set, so this table cannot fall behind the type.
    private static Dictionary<string, object?> NonDefaultValues() => new(StringComparer.Ordinal)
    {
        [nameof(TlsQuicRecoverySpec.InitialCongestionWindow)] = (7, 9000),
        [nameof(TlsQuicRecoverySpec.MinimumCongestionWindowDatagrams)] = 4,
        [nameof(TlsQuicRecoverySpec.CongestionController)] =
            (Func<ITlsQuicCongestionController>)(() => new NamedController("CUBIC", 1)),
        [nameof(TlsQuicRecoverySpec.LossReductionFactor)] = 0.7,
        [nameof(TlsQuicRecoverySpec.PacketThreshold)] = 5,
        [nameof(TlsQuicRecoverySpec.TimeThreshold)] = 1.25,
        [nameof(TlsQuicRecoverySpec.PersistentCongestionThreshold)] = 6,
        [nameof(TlsQuicRecoverySpec.PtoBackoff)] = (3.0, (TimeSpan?)TimeSpan.FromSeconds(60)),
        [nameof(TlsQuicRecoverySpec.ProbePacketsPerPto)] = 1,
        // Ping rather than RetransmittedData SINCE TASK A3-14, because this table's contract is
        // "one valid, NON-DEFAULT value per knob" and A3-14 made RetransmittedData the shipped
        // default. EveryKnobOnTheRecoverySpecIsReadableAndSettable asserts NotEqual against a
        // fresh spec before it sets anything, so leaving the old value here would have turned
        // this row into an assertion that the default is not itself.
        [nameof(TlsQuicRecoverySpec.ProbeContents)] = TlsQuicProbeContents.Ping,
        [nameof(TlsQuicRecoverySpec.AckPolicy)] = TlsQuicAckPolicy.DelayedToMaxAckDelay,
        [nameof(TlsQuicRecoverySpec.PacingBurstDatagrams)] = (int?)null,
        [nameof(TlsQuicRecoverySpec.PacingIntervalScale)] = 2.5,
    };

    // The most hostile values each knob's type can carry.
    private static IEnumerable<object?> HostileValues(Type type)
    {
        if (type == typeof(int))
        {
            return [int.MinValue, int.MaxValue, 0];
        }

        if (type == typeof(int?))
        {
            return [int.MinValue, int.MaxValue, null];
        }

        if (type == typeof(double))
        {
            return
            [
                double.NaN,
                BitConverter.UInt64BitsToDouble(0x7FF8000000000000UL),
                double.PositiveInfinity,
                double.NegativeInfinity,
                double.MinValue,
                double.MaxValue,
                double.Epsilon,
            ];
        }

        if (type == typeof((int, int)))
        {
            return [(int.MinValue, int.MinValue), (int.MaxValue, int.MaxValue)];
        }

        if (type == typeof((double, TimeSpan?)))
        {
            return
            [
                (double.NaN, (TimeSpan?)TimeSpan.MinValue),
                (double.MaxValue, (TimeSpan?)TimeSpan.MaxValue),
                (double.NegativeInfinity, (TimeSpan?)null),
            ];
        }

        if (type.IsEnum)
        {
            return [Enum.ToObject(type, int.MinValue), Enum.ToObject(type, int.MaxValue)];
        }

        // The controller factory, whose only hostile value is absence.
        return [null];
    }

    // The knob numbers the A3 plan's table declares, read out of the table itself.
    private static int[] KnobNumbersInThePlansTable()
    {
        var plan = Read(PlanPath);
        var header = plan.IndexOf(
            "| # | Knob | Why an observer can see it |", StringComparison.Ordinal);
        Assert.InRange(header, 0, plan.Length);
        var table = plan[header..];
        var fixedTable = table.IndexOf("| # | Fixed |", StringComparison.Ordinal);
        Assert.InRange(fixedTable, 0, table.Length);

        return Regex.Matches(table[..fixedTable], @"^\| (\d+) \| ", RegexOptions.Multiline)
            .Select(match => int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture))
            .OrderBy(number => number)
            .ToArray();
    }

    // The knob numbers the source declares, and the member each is written on. Read out of
    // the source's own doc comments - "Knob N." opening a summary - so the mapping is one a
    // reader of the file sees rather than one this test invents.
    private static Dictionary<int, string> KnobNumbersDeclaredInTheSource()
    {
        var lines = File.ReadAllLines(Path.Combine(RepositoryRoot(), SourcePath));
        var knobs = new Dictionary<int, string>();
        var pending = default(int?);
        foreach (var line in lines)
        {
            var marker = Regex.Match(line, @"<summary>Knob (\d+)[.,]");
            if (marker.Success)
            {
                pending = int.Parse(marker.Groups[1].Value, CultureInfo.InvariantCulture);
                continue;
            }

            if (pending is not { } number)
            {
                continue;
            }

            var declaration = Regex.Match(
                line, @"^\s*public\s+(?:static\s+)?.*\b(\w+)\s*(?:\{|\(|$)");
            if (!declaration.Success)
            {
                continue;
            }

            knobs.Add(number, declaration.Groups[1].Value);
            pending = null;
        }

        Assert.Null(pending);
        return knobs;
    }

    // The doc-comment block immediately above a member, for the marker check.
    private static string DocCommentFor(string source, string member)
    {
        var declaration = Regex.Match(
            source, $@"^\s*(?:public|internal)\s+.*\b{Regex.Escape(member)}\s*(?:\{{|\(|$)",
            RegexOptions.Multiline);
        Assert.True(declaration.Success, $"{member} is not declared in the source.");

        var above = source[..declaration.Index];
        var comment = above
            .Split('\n')
            .Reverse()
            .SkipWhile(line => line.Trim().Length == 0)
            .TakeWhile(line => line.TrimStart().StartsWith("///", StringComparison.Ordinal));
        return string.Join('\n', comment);
    }

    // Reads a number out of an extract by RFC 9002's own wording. Words are mapped rather
    // than digits assumed, because s7.2 writes "ten times" and s6.2.4 writes "up to two".
    private static double Scrape(string extract, string pattern)
    {
        var match = Regex.Match(extract, pattern);
        Assert.True(match.Success, $"The extract does not contain {pattern}.");

        var found = match.Groups[1].Value.Replace(",", string.Empty, StringComparison.Ordinal);
        return found switch
        {
            "ten" => 10,
            "two" => 2,
            "twice" => 2,
            _ => double.Parse(found, CultureInfo.InvariantCulture),
        };
    }

    // WHITESPACE IS NORMALISED, because the extracts are the RFC's own hard-wrapped text and
    // every sentence a pattern below anchors on is split across two lines at a column the RFC
    // chose. A pattern written with single spaces against the raw text matches nothing, and a
    // scraper that matches nothing is a test that cannot fail - TheScraperWouldNoticeIfA
    // ConstantMoved is what keeps that from going unnoticed.
    private static string Extract(string name) =>
        Regex.Replace(Read(Path.Combine(CaptureDirectory, name)), @"\s+", " ");

    private static string Read(string relativePath) =>
        File.ReadAllText(Path.Combine(RepositoryRoot(), relativePath));

    // Walks up from the test assembly to the directory holding both trees, the same way
    // QuicCommentReferencesTests.RepositoryRoot does.
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
