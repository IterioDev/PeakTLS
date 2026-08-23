using System.Text.RegularExpressions;

namespace SharpTls.Tests.Quic;

// Every `TlsQuic*Tests.SomeName` citation in src/SharpTls/Quic and in
// tools/SharpTls.Fuzz must name a member of that test class that exists - a test,
// or one of the class's own helpers, which are cited too. See AnyMethod.
//
// A2's mutation records cite the tests that kill each mutation by name, and those
// citations are the phase's newest mechanism for making a comment checkable rather
// than merely persuasive. Nothing enforced them: a rename or a deletion turns one
// into a comment that claims something untrue, and a citation does that more
// harmfully than prose, because it looks authoritative and a reviewer who resolves
// it by hand and finds nothing cannot tell "renamed" from "never existed".
//
// Seven comments in this phase were caught claiming something the RFC or the code
// does not say, every one by review rather than by a test. This is that thesis
// pointed at the mechanism the phase invented to defend against it.
//
// SCOPE, AND THE PART OF IT THAT CANNOT BE CLOSED. Only the qualified form,
// `TlsQuic\w*Tests.Name`, is checked. Citations of *production* members are out of
// scope - the compiler does not check those inside comments either, but a reader
// can resolve one by going to definition.
//
// The gap that matters is bare citations: a handful of comments in these sources
// name a test by method alone, usually as the second or third item of a list whose
// first item is qualified. Those are NOT checked, and no checker can check them.
// The threat is a rename, and at the moment of a rename the old bare name stops
// being a known test and becomes an ordinary CamelCase word indistinguishable from
// the surrounding prose - there is nothing left to resolve it against. Matching
// bare names that DO resolve finds only the citations that are already correct,
// which is the definition of a test that cannot fail.
//
// So the enforceable rule is: write citations qualified. That convention is what
// this test enforces, and the residual is bounded by how many bare ones exist -
// measured, small, and concentrated in list continuations. Deliberately not closed
// by rewrapping several other tasks' comment blocks to add a 25-character type
// prefix, which is churn in committed code for a case a reader resolves from the
// qualified citation two lines above.
public sealed class QuicCommentReferencesTests
{
    // The citation, with its wrapped continuation captured optionally.
    //
    // THE WRAPPED CASE IS THE WHOLE DIFFICULTY, and a naive regex under-reports
    // silently rather than failing. These comments wrap at column 80, so a long
    // test name is routinely split across two comment lines:
    //
    //     // TlsQuicFlowControlFramesTests.TryReadMaximumStreamDataCommitsNothingWhenIts
    //     // SecondFieldIsTruncated calls this directly at a nonzero offset.
    //
    // Group 2 alone is a prefix that resolves to nothing. Blanket-joining every
    // comment line to the one above it is not the fix either: it glues a citation
    // that legitimately ENDS a line onto the first word of the next sentence, so
    // `...OffsetBoundRejects` becomes `...OffsetBoundRejectsand` and a correct
    // citation is reported as broken.
    //
    // So group 3 is captured but not committed to: a citation is accepted if
    // EITHER the unjoined name or the joined one resolves. A wrapped citation
    // resolves only joined, an unwrapped one only unjoined, and a stale one
    // resolves neither way. For the joined form to mask a stale citation, the very
    // next word in the comment would have to complete some other real test name.
    //
    // The continuation's leading run is `[ \t]*` and not a single optional space,
    // because a citation inside an indented bullet list wraps to a line aligned
    // under the bullet's text rather than to one space after the slashes. The first
    // version of this test allowed one space and reported two of this file's own
    // correct citations as broken - which is how a naive version passes for the
    // wrong reason in the other direction, since the same narrowness applied to a
    // checker that skipped unmatched text would have silently checked nothing.
    // `[ \t]` rather than `\s` so the run cannot swallow a blank comment line and
    // splice two unrelated paragraphs.
    private static readonly Regex Citation = new(
        @"(TlsQuic\w*Tests)\.(\w+)(?:\r?\n[ \t]*//+[ \t]*(\w+))?", RegexOptions.Compiled);

    // A test method: an xunit attribute, then the nearest method declaration after
    // it. The gap is lazy and spans newlines because [Theory] rows sit between the
    // attribute and the method, and it cannot run past the method it belongs to
    // because the first `public ... Name(` after an attribute is that method.
    // Matching on `[^{}]` instead would fail on an InlineData row containing a
    // collection literal, of which this suite has many.
    private static readonly Regex TestMethod = new(
        @"\[(?:Fact|Theory)\][\s\S]*?\bpublic\s+[\w<>\.\[\]]+\s+(\w+)\s*\(", RegexOptions.Compiled);

    // Any method declared in a test file, whether or not it is a test.
    //
    // HELPERS ARE CITED TOO, and until tools/SharpTls.Fuzz came into scope nothing
    // revealed it. ProtocolFuzzTargets.cs cites
    // TlsQuicDatagramReaderTests.BuildVersionNegotiationBytes and
    // TlsQuicDatagramReaderTests.BuildLongHeaderBytes - both real, both private
    // helpers rather than [Fact] methods, both correct as written. Registering only
    // test methods reported them as naming tests that do not exist, which is the
    // same misdiagnosis this file exists to avoid, arriving by a third route: the
    // header's scope note anticipated citations of production members, but not of a
    // test class's own helpers.
    //
    // The anti-rot property is unchanged and the threat is if anything larger for
    // helpers, which get renamed more freely than tests. What a citation must do is
    // resolve to a real member of a real class; TestMethod above still records which
    // of those are tests, and both feed `known`.
    //
    // Anchored at a line start for the same reason TestClass is: an unanchored
    // modifier keyword can be matched inside prose. The lazy type-and-modifier run
    // stops at the first `Name(`.
    private static readonly Regex AnyMethod = new(
        @"^\s*(?:public|private|internal|protected)[\w<>\.\[\],\s]*?\s(\w+)\s*\(",
        RegexOptions.Compiled | RegexOptions.Multiline);

    // The class this file's tests belong to. Anchored to the start of a line and
    // required to begin with an access modifier, so it can only match a declaration.
    //
    // THE UNANCHORED VERSION MISDIAGNOSED, which is worse than missing. It was
    // `\bclass\s+(\w+)` against the whole file, and Match takes the FIRST hit - so
    // any prose containing the word "class" followed by a word, anywhere above the
    // declaration, won. A comment reading `// every class  of frame is covered here`
    // registered that file's tests under the class name `of`, and every citation of
    // them then failed to resolve. The report said "Comments cite tests that do not
    // exist" and listed tests that exist, sending the reader to hunt a rename that
    // never happened. A checker that fails loudly for the wrong reason spends the
    // reader's time worse than one that stays quiet.
    //
    // This was hit for real: A2 task 6's test file discusses the "character class" of
    // a Pkts cell in its header, above its declaration, and the author had to reword
    // committed prose to get a green run. That sentence has since been restored and
    // is the standing witness for this regex - see TlsQuicFrameLegalityTests' header,
    // which explains why it has to live above the declaration to be worth anything.
    //
    // Mutation checks, performed and reverted against a tree where that sentence is
    // present, and pasted rather than summarised:
    //
    //   old          failing=1  TlsQuicFrameLegality.cs: TlsQuicFrameLegalityTests.
    //                           ApplicationErrorConnectionCloseIsRejectedIn...
    //   noanchor     failing=0
    //   nomod        failing=0
    //   nomultiline  failing=1  Assert.NotEmpty() Failure:
    //   noprefix     failing=1  Assert.NotEmpty() Failure:
    //
    // Reading that: `old` is the original `\bclass\s+(\w+)` with no anchor and no
    // Multiline, and it reproduces the defect - a real test reported as nonexistent.
    // `nomultiline` drops RegexOptions.Multiline, so `^` matches only at the very
    // start of the file, no declaration is found in any file and `known` is empty.
    // `noprefix` is `^\s*\bclass`, which requires a line to begin with the keyword
    // itself and so matches no C# declaration at all; same empty-collection failure.
    //
    // TWO COMPONENTS SURVIVE INDIVIDUALLY, and the reason is worth stating because it
    // is not what it looks like. `noanchor` drops `^`; `nomod` drops
    // `(?:public|internal)`. Each passes. Neither is redundant with nothing - they
    // are redundant with EACH OTHER. What actually excludes prose is requiring
    // anything at all between a line start and `class` that a comment cannot supply:
    // `[\w\s]*` cannot cross the `/` of a `//`, so once the match must begin at a
    // line start OR must begin at a modifier keyword, comments are out. Removing
    // either one leaves the other doing the job; removing both is `old`, which fails.
    //
    // So neither survivor is unwitnessed in the usual sense - the pair is witnessed
    // and the halves are not separable. Both are kept: the anchor states the intent
    // ("this is a declaration, at a line start"), and the modifier list stops
    // `[\w\s]*` - whose `\s` matches newlines - from beginning its match on an
    // earlier line of plain words. Nothing in this suite exercises that last case,
    // which is exactly why `noanchor` survives, and it is recorded rather than
    // removed on that basis.
    private static readonly Regex TestClass = new(
        @"^\s*(?:public|internal)[\w\s]*\bclass\s+(\w+)",
        RegexOptions.Compiled | RegexOptions.Multiline);

    // Mutation checks (performed and reverted). A checker that cannot fail is the
    // same false witness as a test written for a mutation that cannot change
    // behaviour, so this one was broken deliberately in every way it is meant to
    // catch, and each mutation failed exactly this test:
    //   * renaming a test cited in the qualified form, both where the citation
    //     lives in the source file for that test's own family and where it lives in
    //     another - fails, and the message names the file and the full citation.
    //   * deleting a cited test outright - fails the same way.
    //   * editing a citation in the source so it no longer matches - fails.
    //   * dropping group 3 from Citation, so wrapped citations are checked by their
    //     first line alone - fails, listing the wrapped ones. The continuation
    //     handling is load-bearing, not decoration.
    //   * raising the checkedCount floor absurdly - fails, which is what proves the
    //     scan reaches the sources rather than an empty directory.
    //   * dropping the known.Add - fails on Assert.NotEmpty, the same guard for the
    //     test side.
    //
    // Two results worth recording because they did NOT fail this test:
    //   * removing a cited test's [Fact] attribute does not reach here - the build
    //     stops first on xUnit1013, "public method should be marked as test". So
    //     silently unmarking a test is already caught, one layer earlier.
    //   * renaming a test that is cited only in the bare form passes, which is the
    //     documented scope limit above and not a defect in the checker. It is why
    //     that limit is written down rather than assumed away.
    [Fact]
    public void EveryTestNameCitedInTheQuicSourcesResolvesToATestThatExists()
    {
        var root = RepositoryRoot();

        // Both trees that carry A2 comments. tools/SharpTls.Fuzz is included from
        // task 6 onward because task 7's fuzz target lives there and will carry
        // mutation records in the same style; adding the directory before those
        // comments exist is cheaper than discovering afterwards that none of them
        // were ever checked.
        string[] sources =
        [
            .. Directory.GetFiles(Path.Combine(root, "src", "SharpTls", "Quic"), "*.cs"),
            .. Directory.GetFiles(Path.Combine(root, "tools", "SharpTls.Fuzz"), "*.cs"),
        ];
        var testFiles = Directory.GetFiles(
            Path.Combine(root, "tests", "SharpTls.Tests", "Quic"), "*.cs");

        // Known tests as "Class.Method". The class comes from the file's own
        // declaration rather than its name, so a class renamed without its file
        // being renamed is still resolved correctly.
        HashSet<string> known = [];
        foreach (var file in testFiles)
        {
            var text = File.ReadAllText(file);
            var className = TestClass.Match(text);

            // ASSERT, DO NOT SKIP. This was `continue`, and that was the mechanism
            // behind the misdiagnosis the TestClass regex fix removed one cause of:
            // a file whose declaration the regex cannot read contributes none of its
            // tests to `known`, every citation of them is then reported as naming a
            // test that does not exist, and the reader goes hunting a rename that
            // never happened. Fixing the regex removed one way in; skipping silently
            // is the way in itself, and there are others. An inline attribute on the
            // declaration line - `[Trait("Category", "Rfc")] public sealed class X` -
            // reproduces the original failure exactly, and `static class X` and
            // `file class X` have no access modifier for the regex to anchor on.
            //
            // Assert.NotEmpty(known) below cannot catch any of these: the other
            // twenty-one files keep it non-empty.
            //
            // Mutation check (performed and reverted): injecting that Trait attribute
            // ahead of TlsQuicFrameLegalityTests' declaration fails HERE, and the
            // message is the whole point of the change -
            //
            //   TlsQuicFrameLegalityTests.cs: no class declaration matched, so none
            //   of its tests were registered and every citation of them would be
            //   reported as missing.
            //
            // - while "Comments cite tests that do not exist" appears zero times in
            // that run. Before this assertion the same injection produced only the
            // latter, naming six tests that all exist.
            Assert.True(
                className.Success,
                $"{Path.GetFileName(file)}: no class declaration matched, so none of "
                + "its tests were registered and every citation of them would be "
                + "reported as missing. Fix TestClass, not the citations.");

            // Only the first declaration in a file is read, so a file holding two
            // test classes, or a nested one, would register only the outer. No file
            // in this directory does either today; latent, and it would show up the
            // same way - citations of the second class failing to resolve.
            foreach (Match method in TestMethod.Matches(text))
            {
                known.Add($"{className.Groups[1].Value}.{method.Groups[1].Value}");
            }

            foreach (Match method in AnyMethod.Matches(text))
            {
                known.Add($"{className.Groups[1].Value}.{method.Groups[1].Value}");
            }
        }

        List<string> unresolved = [];
        var checkedCount = 0;
        foreach (var file in sources)
        {
            foreach (Match citation in Citation.Matches(File.ReadAllText(file)))
            {
                checkedCount++;
                var type = citation.Groups[1].Value;
                var unjoined = $"{type}.{citation.Groups[2].Value}";
                var joined = unjoined + citation.Groups[3].Value;
                if (!known.Contains(unjoined) && !known.Contains(joined))
                {
                    // The joined form is reported when the citation wrapped, not
                    // the unjoined one: on a wrapped citation `unjoined` is a
                    // prefix that never appeared in the source as written, and a
                    // message naming a string nobody can find sends the reader
                    // hunting. Both forms were tried; this is the fuller one.
                    unresolved.Add(
                        $"{Path.GetFileName(file)}: {(citation.Groups[3].Success ? joined : unjoined)}");
                }
            }
        }

        // A checker that scanned nothing would pass, which is the same false
        // witness as a test written for a mutation that cannot change behaviour.
        // These two assertions are what stop a wrong path, a renamed folder or an
        // over-tight regex reading as a clean run. They are lower bounds, not
        // counts: an exact number here would go stale every task, which is what the
        // standing rule against absolute test counts in comments is about.
        //
        // The floor was 20 while the real figure was over a hundred, which is a floor
        // that notices a deleted directory and nothing else - a regex regression
        // losing four citations in five would still have cleared it. It is raised to
        // a number close enough to the current figure to catch a regression and still
        // far enough below it that ordinary additions and removals do not touch this
        // line.
        //
        // Mutation check (performed and reverted): raising it to 200 fails with
        // "Only 102 citations found", which is how this floor is known to be live
        // rather than decorative. That 102 is deliberately not written into the
        // assertion - it is the figure on one commit, and a floor that has to be
        // edited whenever a comment is added is a floor nobody will keep.
        Assert.NotEmpty(known);
        Assert.True(checkedCount > 80, $"Only {checkedCount} citations found; the regex or the path is wrong.");

        Assert.True(unresolved.Count == 0, $"Comments cite tests that do not exist:{Environment.NewLine}{string.Join(Environment.NewLine, unresolved)}");
    }

    // Walks up from the test assembly to the directory holding both trees. There is
    // no repository-root property to read - PublicApiBaselineTests reads its
    // baseline out of AppContext.BaseDirectory because the file is copied to the
    // output, which is not an option for several hundred kilobytes of source.
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
