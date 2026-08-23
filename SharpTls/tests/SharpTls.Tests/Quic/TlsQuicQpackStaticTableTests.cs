using System.Text;
using System.Text.RegularExpressions;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// RFC 9204 s3.1 and Appendix A's static table.
//
// EVERY TEST IN THIS FILE IS EXTERNALLY ANCHORED to
// reference-captures/rfc9204-appendix-a-static-table.txt. That is deliberate and it is the
// only design that can work here: an encode/decode round trip reads the SAME array in both
// directions, so a wrong row makes both halves wrong identically and every round trip still
// passes. C6's row 13 is the standing example - two swapped 28-bit Huffman codes left the
// code complete, prefix-free and Kraft-summing to 1, and all 256 round trips passed; only
// the capture witness killed it. A 99-row table has the same hazard, so the capture is
// re-parsed at test time and compared row for row.
public sealed class TlsQuicQpackStaticTableTests
{
    // THE ROW COUNT, DERIVED. Not "99 because the plan says so": the capture's body has some
    // number of lines shaped like a table row, those lines carry an index each, and the
    // indices turn out to be exactly 0..98 with no gap and no duplicate - so max - min + 1
    // reconciles with the line count, and only then is the number written down.
    [Fact]
    public void TheRowCountIsDerivedFromTheCaptureRatherThanAsserted()
    {
        List<int> indices = [.. QpackCaptures.StaticTableRows().Select(r => r.Index)];

        int lineCount = indices.Count;
        Assert.Equal(lineCount, indices.Distinct().Count());
        Assert.Equal(0, indices.Min());
        Assert.Equal(98, indices.Max());
        Assert.Equal(lineCount, indices.Max() - indices.Min() + 1);
        Assert.Equal(lineCount, TlsQuicQpackStaticTable.Count);

        Assert.Equal(99, lineCount);
    }

    // The transcription itself. Names and values, all 99 rows, against the file.
    [Fact]
    public void TheTableMatchesTheCapturedAppendixARowForRow()
    {
        int checkedRows = 0;
        foreach (QpackCaptures.StaticRow row in QpackCaptures.StaticTableRows())
        {
            Assert.Equal(row.Name, TlsQuicQpackStaticTable.NameAt(row.Index));
            Assert.Equal(row.Value, TlsQuicQpackStaticTable.ValueAt(row.Index));
            checkedRows++;
        }

        Assert.Equal(TlsQuicQpackStaticTable.Count, checkedRows);
    }

    // THE WRAPPED VALUES, and the reason this test exists at all. Twelve continuation lines
    // fall in the capture because the value column is only 21 characters wide, and rejoining
    // them is genuinely ambiguous: `text/html;` + `charset=utf-8` needs a space between and
    // `text/` + `plain;charset=utf-8` does not. Getting that wrong would produce a value that
    // looks entirely plausible and that this codebase would then encode and decode happily.
    //
    // The disambiguation is the table's own geometry, not memory of what the value "should"
    // be. The renderer breaks at the LAST opportunity that fits and takes one after a space
    // (consuming it) or after '-' or '/' (keeping it). So re-wrapping the rejoined value at
    // the captured column width must reproduce the captured lines character for character,
    // and only one of the two candidate joins can. `text/plain; charset=utf-8` would have
    // been rendered `text/plain;` + `charset=utf-8`, because `text/plain;` is 11 characters
    // and fits; the capture shows `text/` + `plain;charset=utf-8`, so there is no space.
    [Fact]
    public void TheWrappedValuesRejoinTheOnlyWayTheCaptureAllows()
    {
        int width = QpackCaptures.StaticTableValueColumnWidth();
        Assert.Equal(21, width);

        int wrapped = 0;
        foreach (QpackCaptures.StaticRow row in QpackCaptures.StaticTableRows())
        {
            List<string> rendered = QpackCaptures.GreedyWrap(TlsQuicQpackStaticTable.ValueAt(row.Index), width);
            Assert.Equal(row.Fragments, rendered);
            if (row.Fragments.Count > 1)
            {
                wrapped++;
            }
        }

        // Derived: the rows that actually wrap, and the extra lines they cost.
        Assert.Equal(10, wrapped);
        Assert.Equal(12, QpackCaptures.StaticTableRows().Sum(r => r.Fragments.Count - 1));
    }

    // The join rule is not vacuous: BOTH branches of it are exercised by real rows, so a
    // rule that always inserted a space, or never did, would fail the re-wrap above. This
    // test names the witnesses so the failure is legible when it happens.
    [Fact]
    public void BothHalvesOfTheJoinRuleHaveAWitness()
    {
        // Broken after ';' - the space was consumed by the break and comes back.
        Assert.Contains("; ", ValueOf("strict-transport-security", "max-age=31536000; includesubdomains"));

        // Broken after '/' - no space existed, and none is invented.
        Assert.Equal("text/plain;charset=utf-8", ValueOf("content-type", "text/plain;charset=utf-8"));

        // The two content-type rows that differ ONLY in that space. If the join rule were a
        // constant, these two would have come out identical.
        Assert.NotEqual(
            ValueOf("content-type", "text/html; charset=utf-8"),
            ValueOf("content-type", "text/plain;charset=utf-8"));
    }

    // ZERO VERSUS ABSENT. 21 rows have an EMPTY value. That is a value - the empty string -
    // and the count comes from the capture, not from this file.
    [Fact]
    public void TwentyOneRowsHaveAnEmptyValueAndEmptyIsNotAbsent()
    {
        List<QpackCaptures.StaticRow> empty =
            [.. QpackCaptures.StaticTableRows().Where(r => r.Value.Length == 0)];

        Assert.Equal(21, empty.Count);
        foreach (QpackCaptures.StaticRow row in empty)
        {
            string value = TlsQuicQpackStaticTable.ValueAt(row.Index);
            Assert.NotNull(value);
            Assert.Equal(string.Empty, value);

            // And it resolves as a lookup, which is the part that matters: `:authority` with
            // an empty value is row 0, not a miss.
            Assert.True(TlsQuicQpackStaticTable.TryFindNameAndValue(
                Encoding.ASCII.GetBytes(row.Name),
                [],
                out int found));
            Assert.Equal(row.Name, TlsQuicQpackStaticTable.NameAt(found));
            Assert.Equal(string.Empty, TlsQuicQpackStaticTable.ValueAt(found));
        }
    }

    // NOT A NAME-TO-VALUE MAP. Names repeat, so a name-only lookup and a name-and-value
    // lookup are different operations. The repeat counts are derived from the capture.
    [Fact]
    public void NamesRepeatSoTheTwoLookupsAreDifferentOperations()
    {
        Dictionary<string, int> byName = QpackCaptures.StaticTableRows()
            .GroupBy(r => r.Name)
            .ToDictionary(g => g.Key, g => g.Count());

        Assert.Equal(14, byName[":status"]);
        Assert.Equal(11, byName["content-type"]);
        Assert.Equal(7, byName[":method"]);

        // 99 rows but fewer distinct names - a dictionary keyed on name alone would silently
        // drop the difference.
        Assert.True(byName.Count < TlsQuicQpackStaticTable.Count);

        // The name-only lookup ignores the value column entirely and returns the LOWEST
        // matching row; the name-and-value lookup picks a different row for a value that is
        // not the one at that lowest row.
        byte[] status = Encoding.ASCII.GetBytes(":status");
        Assert.True(TlsQuicQpackStaticTable.TryFindName(status, out int nameOnly));
        Assert.True(TlsQuicQpackStaticTable.TryFindNameAndValue(status, Encoding.ASCII.GetBytes("404"), out int full));
        Assert.NotEqual(nameOnly, full);
        Assert.Equal(":status", TlsQuicQpackStaticTable.NameAt(nameOnly));
        Assert.Equal("404", TlsQuicQpackStaticTable.ValueAt(full));

        // The lowest row wins, derived from the capture rather than named.
        Assert.Equal(QpackCaptures.StaticTableRows().First(r => r.Name == ":status").Index, nameOnly);
    }

    // The index arrives off the wire, so out-of-range is a rejection and never a throw. Note
    // 99 is the FIRST index that does not exist, which is the off-by-one that matters.
    [Theory]
    [InlineData(99)]
    [InlineData(100)]
    [InlineData(int.MaxValue)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void AnIndexOutsideTheTableDoesNotResolveAndDoesNotThrow(int index)
    {
        Assert.False(TlsQuicQpackStaticTable.TryLookup(index, out ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value));
        Assert.True(name.IsEmpty);
        Assert.True(value.IsEmpty);
    }

    [Fact]
    public void TheLastIndexThatDoesResolveIsNinetyEight()
    {
        Assert.True(TlsQuicQpackStaticTable.TryLookup(98, out ReadOnlySpan<byte> name, out _));
        Assert.Equal("x-frame-options", Encoding.ASCII.GetString(name));
        Assert.False(TlsQuicQpackStaticTable.TryLookup(99, out _, out _));
    }

    // The octet view and the string view are the same rows. Cheap, but it is what makes the
    // capture comparison above - which is on strings - evidence about the byte lookups.
    [Fact]
    public void TheOctetLookupAgreesWithTheStringRows()
    {
        for (int i = 0; i < TlsQuicQpackStaticTable.Count; i++)
        {
            Assert.True(TlsQuicQpackStaticTable.TryLookup(i, out ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value));
            Assert.Equal(TlsQuicQpackStaticTable.NameAt(i), Encoding.ASCII.GetString(name));
            Assert.Equal(TlsQuicQpackStaticTable.ValueAt(i), Encoding.ASCII.GetString(value));
        }
    }

    // Every name and value in the capture is printable ASCII, which is what makes the ASCII
    // round trip above lossless. Asserted over the FILE, not over the transcription.
    [Fact]
    public void EveryCapturedNameAndValueIsPrintableAscii()
    {
        foreach (QpackCaptures.StaticRow row in QpackCaptures.StaticTableRows())
        {
            Assert.All(row.Name + row.Value, c => Assert.InRange(c, ' ', '~'));
        }
    }

    private static string ValueOf(string name, string value)
    {
        Assert.True(TlsQuicQpackStaticTable.TryFindNameAndValue(
            Encoding.ASCII.GetBytes(name),
            Encoding.ASCII.GetBytes(value),
            out int index));
        return TlsQuicQpackStaticTable.ValueAt(index);
    }
}

// The capture readers shared by the three QPACK task-C7/C8 test files. They parse the files
// in docs/superpowers/specs/reference-captures/ at test time; nothing here reads the
// production tables, which is the whole point.
internal static class QpackCaptures
{
    internal sealed record StaticRow(int Index, string Name, IReadOnlyList<string> Fragments)
    {
        // The rejoin under test. See TheWrappedValuesRejoinTheOnlyWayTheCaptureAllows.
        internal string Value
        {
            get
            {
                string joined = Fragments[0];
                foreach (string fragment in Fragments.Skip(1))
                {
                    joined += (EndsAtAKeptBreak(joined) ? string.Empty : " ") + fragment;
                }

                return joined;
            }
        }
    }

    private static readonly Regex StaticRowLine = new(
        @"^ +\| +(?<index>[0-9]+) +\|(?<name>[^|]*)\|(?<value>[^|]*)\|\s*$",
        RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly Regex StaticContinuationLine = new(
        @"^ +\| +\|(?<name>[^|]*)\|(?<value>[^|]*)\|\s*$",
        RegexOptions.Multiline | RegexOptions.Compiled);

    internal static IReadOnlyList<StaticRow> StaticTableRows()
    {
        List<StaticRow> rows = [];
        List<string> fragments = [];
        foreach (string line in File.ReadAllLines(Path("rfc9204-appendix-a-static-table.txt")))
        {
            Match row = StaticRowLine.Match(line);
            if (row.Success)
            {
                fragments = [row.Groups["value"].Value.Trim()];
                rows.Add(new StaticRow(
                    int.Parse(row.Groups["index"].Value),
                    row.Groups["name"].Value.Trim(),
                    fragments));
                continue;
            }

            Match continuation = StaticContinuationLine.Match(line);
            if (continuation.Success && rows.Count > 0)
            {
                // Names never wrap in this capture; if one ever did, the fragment below would
                // be the wrong column and this assert is where that shows up.
                Assert.Equal(string.Empty, continuation.Groups["name"].Value.Trim());
                fragments.Add(continuation.Groups["value"].Value.Trim());
            }
        }

        return rows;
    }

    // From the rule line `+=======+===...===+===...===+`, so the width is the file's and not
    // a constant this test picked.
    internal static int StaticTableValueColumnWidth()
    {
        string rule = File.ReadAllLines(Path("rfc9204-appendix-a-static-table.txt"))
            .First(l => l.TrimStart().StartsWith("+=", StringComparison.Ordinal));
        string[] columns = rule.Trim().Trim('+').Split('+');
        return columns[^1].Length - 2;
    }

    // The renderer's greedy wrap: break at the LAST opportunity that still fits. A break at a
    // space consumes it; a break after '-' or '/' keeps the character.
    internal static List<string> GreedyWrap(string text, int width)
    {
        List<string> lines = [];
        while (text.Length > width)
        {
            int cut = -1;
            for (int i = 1; i <= Math.Min(width, text.Length - 1); i++)
            {
                char c = text[i - 1];
                if (c == ' ' || c == '-' || c == '/')
                {
                    cut = i;
                }
            }

            Assert.True(cut > 0, $"no break opportunity in '{text}'");
            lines.Add(text[..cut].TrimEnd());
            text = text[cut..];
        }

        lines.Add(text);
        return lines;
    }

    private static bool EndsAtAKeptBreak(string text) =>
        text.EndsWith('-') || text.EndsWith('/');

    internal static string Path(string fileName)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null &&
               !Directory.Exists(System.IO.Path.Combine(directory.FullName, "src", "SharpTls", "Quic")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        string path = System.IO.Path.Combine(
            directory.FullName,
            "docs",
            "superpowers",
            "specs",
            "reference-captures",
            fileName);
        Assert.True(File.Exists(path), $"capture not found at {path}.");
        return path;
    }
}
