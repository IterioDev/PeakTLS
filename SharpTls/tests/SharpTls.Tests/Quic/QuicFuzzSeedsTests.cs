using SharpTls.Fuzzing;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

public sealed class QuicFuzzSeedsTests
{
    // Mirrors ManagedFuzzHarnessTests.StructuralSeedsReachSuccessfulParserAndStateMachinePaths
    // (which already calls VerifyQuicSeeds transitively through
    // VerifyStructuralSeeds), but gives the quic-packets fuzz seed corpus its
    // own named failure point under this namespace. The entire value of that
    // fuzz campaign rests on these seeds still meaning what they claim to -
    // see AddQuicPacketsSeeds and VerifyQuicSeeds in ProtocolFuzzTargets.
    [Fact]
    public void QuicPacketFuzzSeedsStillReachTheirIntendedParserOutcomes()
    {
        using var targets = new ProtocolFuzzTargets();
        targets.VerifyQuicSeeds();
    }

    // The same guard for the quic-frames corpus, and it carries more weight
    // there. quic-packets' seeds are mostly IETF hex; quic-frames' are mostly
    // encoder output, so a change to any of the eight frame writers silently
    // changes what thirty-one of its seeds mean. VerifyQuicFrameSeeds pins the
    // RFC 9001 A.2 CRYPTO frame's published offset, length and extent, the
    // PADDING run after it, one round trip per wire frame type, the ACK seeds'
    // decoded ranges, and the ascending walk over the several-frames-in-sequence
    // payload.
    [Fact]
    public void QuicFrameFuzzSeedsStillReachTheirIntendedParserOutcomes()
    {
        using var targets = new ProtocolFuzzTargets();
        targets.VerifyQuicFrameSeeds();
    }

    // A REACHABILITY REPORT IS A CLAIM, AND CLAIMS NEED WITNESSES. Nothing
    // asserted on DescribeQuicFramesReachability() or the counters behind it, so
    // a review made two mutations to the COUNTING itself and both stayed green
    // through the full gate: incrementing the walk-limit-hit counter on every
    // input (reported "cap hits=41" out of 40 inputs - arithmetically
    // impossible, unnoticed), and forcing the family-parser sweep's `reached`
    // to true unconditionally (reported a uniform 40/40 for all thirteen
    // readers, whose real rates span 1/40 to 39/40). A second review then
    // found the same gap one layer in: this test asserted the cap line and
    // the family-parser lines and NOTHING else, and two more mutations
    // survived - dropping the per-type RecordQuicRawType call inside axis 2's
    // prefix sweep (its table went to all zeros while `accepted=` kept
    // climbing), and making the re-hosted ACK accept counter increment
    // unconditionally (it stopped reflecting what TryGetRanges actually
    // returned). Every remaining line DescribeQuicFramesReachability prints is
    // now pinned below, for the same reason: an unasserted line is exactly as
    // unwitnessed as no line at all.
    [Fact]
    public void QuicFrameReachabilityOverTheSeedCorpusMatchesHandDerivedExpectations()
    {
        using var targets = new ProtocolFuzzTargets();
        var seeds = targets.CreateSeedCorpus("quic-frames");
        foreach (var seed in seeds)
        {
            targets.Run("quic-frames", seed);
        }
        var report = targets.DescribeQuicFramesReachability();
        Assert.NotNull(report);

        // Hand-derived, not read off a run: AddQuicFramesSeeds appends exactly
        // one seed whose frame count can exceed the 512-frame walk cap - the RFC
        // 9001 A.2 padded Initial payload, 1 CRYPTO frame plus
        // QuicRfcVectors.A2PaddingFrameCount (917) PADDING frames = 918 > 512.
        // Every other seed is a handful of frames at most (the longest is the
        // several-frames-in-sequence seed, 28 frames since task C17 appended a
        // DATAGRAM to it). An unconditional-increment mutation of the cap-hit
        // counter reports the corpus size (42) here instead of 1 - an upper
        // bound (<= 42) would have missed that, only an exact value catches it.
        Assert.Contains("inputs hitting the 512-frame cap=1", report);

        // REGRESSION SNAPSHOT, NOT A WITNESS - SAID EXPLICITLY, NOT IMPLIED.
        // Task 6's two-transcription discipline (an independent test expectation
        // checked against an independent implementation) works because RFC
        // 9000 s12.4's table exists outside this codebase. These eleven counts
        // have no such external source: there is no independent answer to
        // "does TryReadAck accept seed #17 at offset 1" short of tracing the
        // parser's own byte-by-byte consumption by hand, which is the same
        // operation the parser performs, done slower and less reliably. So
        // this list is a pinned observation of current behaviour, not an
        // independently derived expectation - it catches drift (a future
        // change to a writer or a seed silently altering what the corpus
        // exercises) but its correctness the day it was written rests on the
        // program run that produced it, same as any other regression pin.
        // TryReadAck and TryReadNewConnectionId are excluded here because they
        // - and only they - genuinely are independently derivable; see the
        // direct checks below instead.
        var familyParserSnapshot = new[]
        {
            "TlsQuicStreamFrames.TryReadStream: 41/42 (97.62% true)",
            "TlsQuicStreamFrames.TryReadCrypto: 12/42 (28.57% true)",
            "TlsQuicFlowControlFrames.TryReadMaximumData: 41/42 (97.62% true)",
            "TlsQuicFlowControlFrames.TryReadMaximumStreamData: 35/42 (83.33% true)",
            "TlsQuicFlowControlFrames.TryReadMaximumStreams: 41/42 (97.62% true)",
            "TlsQuicConnectionFrames.TryReadResetStream: 26/42 (61.90% true)",
            "TlsQuicConnectionFrames.TryReadStopSending: 35/42 (83.33% true)",
            "TlsQuicConnectionFrames.TryReadNewToken: 9/42 (21.43% true)",
            "TlsQuicConnectionFrames.TryReadRetireConnectionId: 41/42 (97.62% true)",
            "TlsQuicConnectionFrames.TryReadPathData: 7/42 (16.67% true)",
            "TlsQuicConnectionFrames.TryReadConnectionClose: 18/42 (42.86% true)",

            // Task C17. Re-pinned from /40 to /42 because the corpus gained the
            // two hand-built DATAGRAM seeds; the denominators moved together and
            // the numerators moved by 0, 1 or 2, which is what a corpus growing by
            // two seeds looks like and not what a behaviour change looks like.
            // TryReadDatagram's own row is asserted separately below, because its
            // value trips a guard that was written when no reader could reach it.
        };
        foreach (var line in familyParserSnapshot)
        {
            Assert.Contains(line, report);
        }
        // The two promoted counts (below) still show up in the printed report
        // via these two aggregate lines - kept as an extra regression pin on
        // top of the direct checks, not a substitute for them.
        Assert.Contains("TlsQuicAckFrames.TryReadAck: 3/42 (7.14% true)", report);
        Assert.Contains("TlsQuicConnectionFrames.TryReadNewConnectionId: 1/42 (2.38% true)", report);

        // THE ALL-ACCEPTING GUARD, AND TASK C17 PUT A REAL EXCEPTION UNDER IT.
        // It used to read Assert.DoesNotContain("40/40 (100.00% true)") - "no
        // reader accepts everything" - on the reasoning that a reader which never
        // says no is a reader whose rejection path the corpus never reached.
        //
        // TlsQuicFrames.TryReadDatagram is at 42/42 and that is RFC 9221 s4, not a
        // defect. Its LEN-clear form has NO rejecting input: "if this bit is set
        // to 0, the Length field is absent and the Datagram Data field extends to
        // the end of the packet", and s4 also says "empty (i.e., zero-length)
        // datagrams are allowed" - so every byte sequence, including none at all,
        // is a well-formed 0x30 frame body. Every other reader in this table has a
        // field that can be truncated; this one has nothing to truncate. The
        // family sweep enters each reader at three offsets with both raw types, so
        // one accepting combination per input is all 100% needs.
        //
        // The rejecting path of the LEN-PRESENT form is real and IS reached - by
        // TlsQuicFramesTests.ADatagramLengthPastTheEndOfThePayloadIsRejected,
        // which drives it with hand-built inputs rather than by this corpus.
        //
        // So the guard is SCOPED rather than deleted: exactly one line in the
        // whole report may read 100%, and it must be that one. A second reader
        // arriving at 100% - the defect the original assertion was for - still
        // fails this, and so does TryReadDatagram silently dropping out of the
        // sweep.
        var allAccepting = report!
            .Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.EndsWith("(100.00% true)", StringComparison.Ordinal))
            .ToArray();
        Assert.Equal(["TlsQuicFrames.TryReadDatagram: 42/42 (100.00% true)"], allAccepting);

        Assert.DoesNotContain("0/42 (0.00% true)", report);

        // Axis 2's per-type prefix table: the four LEN-clear STREAM forms and,
        // since task C17, the LEN-clear DATAGRAM form are the only ones a
        // truncated same-buffer prefix can legitimately re-parse as - RFC 9000
        // s19.8's implicit-length rule and RFC 9221 s4's, which are the same rule
        // in two documents - so they are the only nonzero rows. Pinning one of
        // them is what catches the dropped-RecordQuicRawType mutation -
        // attempted/accepted stay unaffected by that mutation (both counters live
        // outside the recording call), only the per-type table goes to all zeros,
        // so only a per-type assertion can see it.
        //
        // 0x30 at 3 and 0x31 at 0 is the pair that says the slot map added by C17
        // is right in both directions: a slot map that folded the two DATAGRAM
        // values together, or that mapped either of them to the wrong row, cannot
        // produce a nonzero row beside a zero one here. 0x31 IS zero for the
        // reason its own axis-1 row is not: a truncated prefix of a LEN-present
        // DATAGRAM has a Length field promising bytes the prefix no longer holds.
        Assert.Contains("decodes attempted=1330, accepted=15, inputs hitting the 2048-decode budget=0", report);
        Assert.Contains("0x08 Stream            : 3", report);
        Assert.Contains("0x09 Stream            : 3", report);
        Assert.Contains("0x0c Stream            : 3", report);
        Assert.Contains("0x0d Stream            : 3", report);
        Assert.Contains("0x30 Datagram          : 3", report);
        Assert.Contains("0x31 Datagram          : 0", report);
        Assert.Contains("0x00 Padding           : 0", report);

        // Axis 2's unrelated-buffer probe: its own untyped counters, including
        // the skip count for `start` beyond the fixed buffer's length (a bound
        // a review found unsurfaced - see RunQuicFrameResliceAxis).
        Assert.Contains(
            "decodes attempted=59, accepted=45, skipped (start beyond the 64-byte buffer)=526", report);

        // The re-hosted ACK check: accepted (8) is strictly less than attempted
        // (16), which is what an unconditional-increment mutation of the
        // accept counter cannot reproduce - that mutation reports 16/16, and
        // only an exact pin, not a bound, tells the two apart the same way the
        // walk-limit fix in the previous round needed one.
        Assert.Contains("decodes attempted=16, accepted=8", report);

        // "Driven by accepted frames": every remaining unasserted line.
        Assert.Contains("TlsQuicAckFrames.TryGetRanges (as parsed): 4/4 true", report);
        Assert.Contains("TlsQuicFrameLegality.Permits: 2228/2340 true", report);

        // "3 threw" is TASK C17 AND IS NOT A DEFECT TO CHASE. It was 0 before, and
        // the three are exactly the three DATAGRAM frames the corpus's axis-1 walk
        // accepts (0x30 once, 0x31 twice - see the per-type rows above, which is
        // where the 3 is re-derivable from rather than being a number on its own).
        // WriteFrame refuses to emit a DATAGRAM by design: SharpTls parses and
        // drops them to honour an advertisement its defaults make, and implements
        // no datagram semantics to send. Any FOURTH throw is a real finding.
        Assert.Contains("TlsQuicFrames.WriteFrame re-encode: 582 ok, 3 threw ArgumentException", report);

        // The reviewer's own example, verified directly rather than only through
        // the aggregate count above: a PING frame is one byte (type only, no
        // fields), so handed to TryReadAck as ACK's FIXED fields it reads
        // LargestAcknowledged as a 1-byte varint (consuming the frame's only
        // byte) and then truncates reading AckDelay - TryReadAck's own
        // try/catch turns that into false. True at every offset the family
        // sweep tries (0, 1, and length) and for both ACK raw types.
        List<byte> pingBytes = [];
        TlsQuicFrames.WriteFrame(pingBytes, new TlsQuicFrame { RawType = (ulong)TlsQuicFrameType.Ping });
        byte[] ping = [.. pingBytes];
        foreach (var ackRawType in new[] { (ulong)TlsQuicFrameType.Ack, (ulong)TlsQuicFrameType.Ack | TlsQuicAckFrames.EcnCountsBit })
        {
            foreach (var entry in new[] { 0, 1, ping.Length })
            {
                var offset = entry;
                Assert.False(TlsQuicAckFrames.TryReadAck(ping, ref offset, ackRawType, out _, out _));
            }
        }

        // PROMOTED WITNESS 1 of 2 - TlsQuicAckFrames.TryReadAck's 3/40 IS
        // independently derivable, and here is the derivation, not just the
        // number. Every field the encoder writes for an ACK frame is a
        // 1-byte varint (QuicFrameSeed* constants all sit in 0x20-0x3f), so
        // an ACK frame's own bytes, read from offset 1 (skipping its own
        // 1-byte type varint - every frame type here has a 1-byte type
        // varint), are exactly ACK's fixed fields in order: this is the
        // "offset that skips the type byte" pattern, the same one promoted
        // witness 2 below uses for NewConnectionId. Reading from offset 0
        // instead misreads the type byte itself as LargestAcknowledged and
        // desyncs every field after it - structurally wrong, not merely
        // unlucky, so it must fail.
        foreach (var ecnCounts in new TlsQuicEcnCounts?[] { null, new TlsQuicEcnCounts(0x35, 0x36, 0x37) })
        {
            var rawType = (ulong)TlsQuicFrameType.Ack | (ecnCounts is null ? 0 : TlsQuicAckFrames.EcnCountsBit);
            List<byte> ackBytes = [];
            TlsQuicFrames.WriteFrame(ackBytes, new TlsQuicFrame
            {
                RawType = rawType,
                LargestAcknowledged = 0x3a,
                AckDelay = 0x33,
                AckRangeCount = 1,
                FirstAckRange = 0x20,
                AckRanges = new byte[] { 0x05, 0x0a },
                EcnCounts = ecnCounts,
            });
            var ack = ackBytes.ToArray();

            var atOne = 1;
            Assert.True(TlsQuicAckFrames.TryReadAck(ack, ref atOne, rawType, out _, out _));

            var atZero = 0;
            Assert.False(TlsQuicAckFrames.TryReadAck(ack, ref atZero, rawType, out _, out _));
        }

        // The corpus's third and least obvious TryReadAck hit: CreateBoundarySeeds
        // includes a 4-byte all-zero buffer. Read as ACK fields from offset 0
        // (no type byte to skip - this buffer was never a frame), that is
        // LargestAcknowledged=0, AckDelay=0, AckRangeCount=0, FirstAckRange=0.
        // s19.3.1's own rule (FirstAckRange must not exceed LargestAcknowledged)
        // holds at 0<=0, and AckRangeCount=0 means no further range pairs to
        // read - a legal, degenerate single-range ACK acknowledging only packet
        // 0. Nothing about this is an accident of the encoder; it is the
        // all-zero corner of the format being valid.
        byte[] allZero = [0x00, 0x00, 0x00, 0x00];
        var zeroOffset = 0;
        Assert.True(TlsQuicAckFrames.TryReadAck(
            allZero, ref zeroOffset, (ulong)TlsQuicFrameType.Ack, out var zeroAck, out _));
        Assert.Equal(0UL, zeroAck.LargestAcknowledged);

        // PROMOTED WITNESS 2 of 2 - TlsQuicConnectionFrames.TryReadNewConnectionId's
        // 1/40, per the reviewer's own trace: NEW_CONNECTION_ID's wire format ends
        // in a FIXED 16-byte stateless reset token (s19.15), which is long and
        // rigid enough that only a seed deliberately built with 16 trailing bytes
        // shaped as a token can satisfy it - the four boundary seeds longer than a
        // few bytes are at most 4, and every other per-type seed is shaped for a
        // different frame's fields, not a sequence-number/retire/length/id/16-byte-
        // token layout. Same offset pattern as ACK above: correct only at 1.
        List<byte> ncidBytes = [];
        TlsQuicFrames.WriteFrame(ncidBytes, new TlsQuicFrame
        {
            RawType = (ulong)TlsQuicFrameType.NewConnectionId,
            SequenceNumber = 0x31,
            RetirePriorTo = 0x28,
            ConnectionId = new byte[] { 0x51, 0x52, 0x53, 0x54, 0x55 },
            StatelessResetToken = Enumerable.Range(0x60, 16).Select(value => (byte)value).ToArray(),
        });
        var ncid = ncidBytes.ToArray();

        var ncidAtOne = 1;
        Assert.True(TlsQuicConnectionFrames.TryReadNewConnectionId(ncid, ref ncidAtOne, out _, out _));

        var ncidAtZero = 0;
        Assert.False(TlsQuicConnectionFrames.TryReadNewConnectionId(ncid, ref ncidAtZero, out _, out _));
    }

    // THE PHASE'S ONE PERMANENT ALLOCATION TEST, and it is a denial-of-service
    // defence rather than a performance nicety. Not sizing an allocation from an
    // attacker-controlled count is what stops a peer turning a frame header into
    // a heap request; three earlier tasks each wrote a temporary version of this
    // check, confirmed 0 bytes per call and deleted it, so the property was
    // measured three times and guarded zero times. GC.GetAllocatedBytesForCurrent
    // Thread appeared in no file under src/ or tests/ before this one.
    //
    // WHY THIS NOW COVERS THE WHOLE CORPUS, NOT ONLY THE ACCEPTING HALF. Before
    // A4 task 2, QuicVariableLengthInteger exposed no TryRead, only a throwing
    // Read, and every reader in this namespace caught TlsQuicTransportException
    // to turn a truncated varint into a false return - so every malformed frame
    // allocated an exception object plus its message string, and a
    // zero-allocation assertion over rejected inputs would have been false for
    // reasons that had nothing to do with attacker-sized buffers (see the git
    // history of this file for that earlier, narrower version and its filter).
    // Task 2 added TryRead and migrated every parse-path caller in this
    // namespace off the throwing Read, closing that gap - but the corpus itself
    // does not exercise it: only one of quic-frames' own seeds is rejected by
    // TryReadFrame (asserted below as `corpusRejectedCount`, not just claimed
    // here as a number - that is exactly the fact that decayed silently once
    // already), and that seed is a zero-length buffer, TryRead's shallowest
    // exit. So widening the loop to the whole corpus alone would still leave
    // the actual flood vector this task exists to close - a truncated varint
    // inside an otherwise well-formed frame - unmeasured. A prior version of
    // this comment claimed that case was "proven over every seed"; it was not,
    // because no such seed exists here. HAND-BUILT INPUTS below close that gap:
    // one truncated-varint rejection per (frame family, encoded-width) pair
    // across MAX_DATA, ACK, CRYPTO, NEW_CONNECTION_ID and CONNECTION_CLOSE,
    // plus one unknown frame type. The corpus's own rejected-seed count is
    // asserted rather than typed as prose, so the next reader can see at a
    // glance whether the rejecting half is real coverage or one degenerate
    // seed, and a later seed added to the corpus cannot make this comment
    // silently wrong the way its predecessor was.
    //
    // Scoped to TryReadFrame alone for the same honesty as before. TryGetRanges
    // appends to a caller-supplied List and grows it; WriteFrame builds a
    // List<byte>. Both allocate by design and neither is the receive path.
    [Fact]
    public void ReadingAnyFrameInTheSeedCorpusAllocatesNothing()
    {
        using var targets = new ProtocolFuzzTargets();

        // The whole quic-frames corpus, accepted and rejected seeds alike.
        List<byte[]> allSeeds = [];
        foreach (var seed in targets.CreateSeedCorpus("quic-frames"))
        {
            allSeeds.Add(seed);
        }

        // Live, not prose: the corpus's own rejecting coverage is exactly one
        // seed (an empty buffer, TryRead's shallowest exit) - asserted here
        // instead of stated as a number in a comment, since an unchecked count
        // is precisely what let that fact decay silently before this task's
        // review caught it. If a later seed changes this, the assertion fails
        // where the claim would have gone quietly stale.
        var corpusRejectedCount = 0;
        foreach (var seed in allSeeds)
        {
            var probe = 0;
            if (!TlsQuicFrames.TryReadFrame(seed, ref probe, out _, out _))
            {
                corpusRejectedCount++;
            }
        }
        Assert.Equal(1, corpusRejectedCount);

        // Hand-built truncated-varint rejections, since the corpus's own
        // rejecting seed exercises only TryRead's empty-buffer exit and not the
        // multi-byte-width one a truncated field inside a real frame hits. One
        // per (frame family, encoded width) pair, spanning 2-, 4- and 8-byte
        // prefixes and a field missing at EOF, across five families - plus one
        // unknown frame type (0x1f, RFC 9000 s12.4 Table 3 assigns nothing
        // there), which TryReadFrame's default arm rejects with no reader
        // dispatch at all.
        byte[][] handBuiltRejections =
        [
            [0x10, 0x40], // MAX_DATA, Maximum Data: 2-byte-form prefix, second byte missing.
            [0x10], // MAX_DATA, Maximum Data: absent entirely (varint at EOF).
            [0x02, 0x80, 0x00, 0x00], // ACK, Largest Acknowledged: 4-byte-form prefix, one byte short.
            [0x02], // ACK, Largest Acknowledged: absent entirely (varint at EOF).
            [0x06, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // CRYPTO, Offset: 8-byte-form prefix, one byte short.
            [0x06], // CRYPTO, Offset: absent entirely (varint at EOF).
            [0x18, 0x40], // NEW_CONNECTION_ID, Sequence Number: 2-byte-form prefix, second byte missing.
            [0x1c, 0x80, 0x00, 0x00], // CONNECTION_CLOSE, Error Code: 4-byte-form prefix, one byte short.
            [0x1f], // Unknown frame type - no family reader is ever reached.
        ];
        foreach (var rejection in handBuiltRejections)
        {
            var probe = 0;
            Assert.False(TlsQuicFrames.TryReadFrame(rejection, ref probe, out _, out _));
            allSeeds.Add(rejection);
        }
        var inputs = allSeeds.ToArray();

        // A parse that never reached a CONNECTION_CLOSE allocates nothing for
        // uninteresting reasons. The corpus carries one accepted seed per wire
        // frame type, so this asserts the measurement below covers all of them -
        // unaffected by the rejections added above, since a false return never
        // adds to this set.
        HashSet<ulong> covered = [];
        foreach (var input in inputs)
        {
            var probe = 0;
            if (TlsQuicFrames.TryReadFrame(input, ref probe, out var frame, out _))
            {
                covered.Add(frame.RawType);
            }
        }
        // 0x1f + 2 = 33, and the two terms are named rather than the total being
        // typed: thirty-one Table 3 wire values (0x00-0x1e) plus RFC 9221's two
        // DATAGRAM values (0x30-0x31), which task C17 added to the corpus as
        // hand-built bytes since WriteFrame refuses to emit one. Written as a sum
        // so that the next extension frame extends the arithmetic instead of
        // silently changing a constant nobody can re-derive.
        Assert.Equal(0x1f + 2, covered.Count);

        // Warm up: the first call through each path jits, and jit allocations
        // land on this thread. Two passes, because tiering can recompile once.
        for (var pass = 0; pass < 2; pass++)
        {
            for (var index = 0; index < inputs.Length; index++)
            {
                var offset = 0;
                _ = TlsQuicFrames.TryReadFrame(inputs[index], ref offset, out _, out _);
            }
        }

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var index = 0; index < inputs.Length; index++)
        {
            var offset = 0;
            _ = TlsQuicFrames.TryReadFrame(inputs[index], ref offset, out _, out _);
        }
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(0L, allocated);
    }

    // The same standing guard for the QPACK corpus, and it carries the most
    // weight of any of them. quic-frames' seeds are encoder output; qpack's are
    // RFC 9204 Appendix B - the only worked QPACK vectors that exist - plus
    // hand-built one-per-representation probes, and every dynamic, post-base and
    // blocked arm of the target is unreachable without them. VerifyQpackSeeds
    // re-derives B.1's decoded field line, B.2's post-base section against the
    // table B.2's own encoder stream builds, B.4's field-relative section, B.5's
    // eviction, and the four live entries the probe table must hold.
    [Fact]
    public void QpackFuzzSeedsStillReachTheirIntendedParserOutcomes()
    {
        using var targets = new ProtocolFuzzTargets();
        targets.VerifyQpackSeeds();
    }

    // And for HTTP/3, where the seeds are whole encoded response scripts. Every
    // state above s7.1's frame walk - interim sections, trailers, completion,
    // RFC 9204 s2.2.1's block, s4.4.1's acknowledgment - exists only because
    // those scripts decode, so a change to the QPACK encoder or to any frame
    // writer would otherwise hollow the target out without a single failure.
    [Fact]
    public void Http3FuzzSeedsStillReachTheirIntendedParserOutcomes()
    {
        using var targets = new ProtocolFuzzTargets();
        targets.VerifyHttp3Seeds();
    }

    // THE CERTIFICATE LESSON, WRITTEN DOWN AS A TEST.
    //
    // The certificate-compression fuzz target was vacuous beyond zlib for a year
    // because nothing asserted that its brotli and zstd arms were ever reached:
    // it appeared to cover three algorithms, covered one, and stayed green the
    // whole time. QPACK has seven field line representations and five encoder
    // stream instructions, and all but the static-indexed ones are behind a
    // field section prefix that a corpus of noise cannot satisfy. So the
    // question this test asks is not "what did the campaign count" but "is any
    // arm reporting zero", because an arm reporting zero is a target that has
    // stopped fuzzing the thing its name says it fuzzes.
    [Fact]
    public void QpackReachabilityOverTheSeedCorpusReachesEveryArmItClaims()
    {
        using var targets = new ProtocolFuzzTargets();
        var seeds = targets.CreateSeedCorpus("qpack");
        foreach (var seed in seeds)
        {
            targets.Run("qpack", seed);
        }
        var report = targets.DescribeQpackReachability();
        Assert.NotNull(report);

        // HAND-DERIVED, NOT READ OFF A RUN. Each representation probe is built
        // behind a prefix the harness constructs to be satisfiable and with an
        // index clamped into range, so it decodes for EVERY input or the
        // construction is broken. Anything below the corpus size here means an
        // arm has quietly stopped being reachable, which is exactly the failure
        // the certificate target shipped with.
        var intactArms = 0;
        foreach (var line in report.Split(Environment.NewLine))
        {
            if (!line.Contains("intact=", StringComparison.Ordinal))
            {
                continue;
            }
            intactArms++;
            Assert.Contains($"intact={seeds.Count}/{seeds.Count}", line);

            // The disturbed-byte half is the explorer, and it is allowed to be
            // any value except zero: an arm no mutation ever gets through is an
            // arm the campaign only ever visits along one path.
            Assert.DoesNotContain("mutated=0", line);
        }
        Assert.Equal(7, intactArms);

        // The seven arm names, pinned, so that dropping one fails here rather
        // than silently shrinking the table above from seven rows to six.
        Assert.Contains("s4.5.2 indexed field line, static table", report);
        Assert.Contains("s4.5.2 indexed field line, dynamic table", report);
        Assert.Contains("s4.5.3 indexed field line, post-base", report);
        Assert.Contains("s4.5.4 literal, name reference static", report);
        Assert.Contains("s4.5.4 literal, name reference dynamic", report);
        Assert.Contains("s4.5.5 literal, post-base name reference", report);
        Assert.Contains("s4.5.6 literal, literal name", report);

        // s3.2's four addressing modes, none of them zero. TryResolvePostBase is
        // at 28/28 and that is s3.2.6, not a defect: post-base addressing is
        // Base + Index with no upper bound of its own - the bound is the
        // Required Insert Count, checked by the DECODER - so the only index it
        // refuses is one that would overflow past 2^64. Its rejecting path is
        // reached by TlsQuicQpackDynamicTableTests rather than by this corpus.
        Assert.DoesNotContain("TryLookupAbsolute: 0/", report);
        Assert.DoesNotContain("TryResolveEncoderRelative: 0/", report);
        Assert.DoesNotContain("TryResolveFieldRelative: 0/", report);
        Assert.DoesNotContain("TryResolvePostBase: 0/", report);

        // Both of RFC 9204 s4.1.2's string encodings are decoded. A target that
        // only ever saw raw literals would never enter the Huffman decoder,
        // which is the single most likely place in QPACK for a memory-safety
        // defect to be.
        Assert.DoesNotContain("huffman=0,", report);
        Assert.DoesNotContain("raw=0", report);

        // s4.3's five encoder stream arms, none of them zero. These are counted
        // by the table state change each instruction produced, so a zero here
        // means the instruction never took effect, not merely that it parsed.
        var instructionArms = 0;
        foreach (var line in report.Split(Environment.NewLine))
        {
            if (!line.Contains("s4.3.", StringComparison.Ordinal))
            {
                continue;
            }
            instructionArms++;
            Assert.DoesNotContain($": 0/{seeds.Count}", line);
        }
        Assert.Equal(5, instructionArms);

        // HAND-DERIVED. RunQpackBlockedDecoding builds a section declaring a
        // Required Insert Count above the probe table's on EVERY input and then
        // asks for one more hold than SETTINGS_QPACK_BLOCKED_STREAMS allows, so
        // all three of these are the corpus size exactly. An unconditional
        // increment on any of them would report more than the corpus size, which
        // an upper bound would miss and this does not.
        Assert.Contains(
            $"sections reported Blocked={seeds.Count}, streams parked={seeds.Count}, " +
            $"refusals at the advertised 4={seeds.Count}",
            report);

        // The two bounds that stand between a Huffman decompression bomb and
        // unbounded memory. Both were UNREACHED on the first campaign - a
        // section built from a few kilobytes never grows past a 16 KiB limit -
        // and both are now driven directly. A limit whose rejection no input can
        // reach is a limit nobody has tested.
        Assert.DoesNotContain("FieldSectionTooLarge=0", report);
        Assert.DoesNotContain("DestinationTooSmall=0", report);

        // s4.5.1's prefix rejections and s4.5's resolution failures, all reached
        // by the corpus. Named individually rather than checked as "no zeros",
        // because the two members below them legitimately are zero here:
        // BlockedStreamLimitExceeded is raised by TlsQuicQpackBlockedStreams and
        // reported on its own line above, and None counts successes.
        Assert.DoesNotContain("IntegerOverflow=0", report);
        Assert.DoesNotContain("EosSymbol=0", report);
        Assert.DoesNotContain("PaddingTooLong=0", report);
        Assert.DoesNotContain("PaddingNotEos=0", report);
        Assert.DoesNotContain("DynamicTableReference=0", report);
        Assert.DoesNotContain("StaticIndexOutOfRange=0", report);
        Assert.DoesNotContain("RequiredInsertCountNotZero=0", report);
        Assert.DoesNotContain("ReferenceAtOrAboveRequiredInsertCount=0", report);
        Assert.DoesNotContain("InvalidBase=0", report);
    }

    // The same question for HTTP/3: every registered frame type accepted at
    // least once, and every state the response machine can be in reached at
    // least once. The state rows are the ones that matter - a HEADERS payload
    // that does not decode stops at s4.1 and every row below it stays zero,
    // which is what a target fed only noise looks like.
    [Fact]
    public void Http3ReachabilityOverTheSeedCorpusReachesEveryArmItClaims()
    {
        using var targets = new ProtocolFuzzTargets();
        var seeds = targets.CreateSeedCorpus("http3");
        foreach (var seed in seeds)
        {
            targets.Run("http3", seed);
        }
        var report = targets.DescribeHttp3Reachability();
        Assert.NotNull(report);

        // RFC 9114 s11.2.1's seven registered frame types. The corpus contains
        // one frame of each on its own, so a zero row means the frame layer
        // stopped accepting a type it is required to accept.
        var frameRows = 0;
        foreach (var line in report.Split(Environment.NewLine))
        {
            if (!line.Contains("(0x", StringComparison.Ordinal))
            {
                continue;
            }
            frameRows++;
            Assert.DoesNotContain("=0", line);
        }
        Assert.Equal(7, frameRows);

        // s7.2.8's four HTTP/2 carry-overs must be REJECTED, and s9's
        // unregistered types must be accepted and ignored. One corpus, both
        // outcomes; a target reaching only one of them cannot tell them apart.
        Assert.DoesNotContain("carry-over types rejected=0,", report);
        Assert.DoesNotContain("unregistered types accepted=0", report);

        // The eight response states. Every one of them is behind a field
        // section that has to decode first, so this block is the whole
        // non-vacuity claim of this target in one assertion.
        Assert.DoesNotContain("s4.1 final header section decoded=0", report);
        Assert.DoesNotContain("s4.1 interim 1xx header section decoded=0", report);
        Assert.DoesNotContain("s7.2.1 DATA payload delivered=0", report);
        Assert.DoesNotContain("s4.1 trailer section decoded=0", report);
        Assert.DoesNotContain("s4.1 response complete at end of stream=0", report);
        Assert.DoesNotContain("s2.2.1 section blocked on the encoder stream=0", report);
        Assert.DoesNotContain("s4.4.1 section acknowledgment queued=0", report);
        Assert.DoesNotContain("s8.1 rejected with an HTTP/3 error code=0", report);

        // s8.1's error codes the corpus is built to reach. The rest of the enum
        // belongs to the connection and stream layers this target does not
        // drive, so they are legitimately zero and are not asserted on.
        Assert.DoesNotContain("H3FrameUnexpected=0", report);
        Assert.DoesNotContain("H3FrameError=0", report);
        Assert.DoesNotContain("H3SettingsError=0", report);
    }

    // NOTHING THROWS, ON EITHER TARGET, FOR ANY INPUT. The bounded runner
    // already turns an escape into a failure, but only when someone runs it;
    // this puts the two newest targets' seed corpora under the gate. Both are
    // peer-driven paths in their entirety - a field section and a frame stream
    // both arrive from the network - so an exception escaping either is an
    // unhandled exception a hostile server can drive out of the client.
    [Theory]
    [InlineData("qpack")]
    [InlineData("http3")]
    public void NeitherNewTargetThrowsOnAnySeedOrAnyTruncationOfOne(string target)
    {
        using var targets = new ProtocolFuzzTargets();
        foreach (var seed in targets.CreateSeedCorpus(target))
        {
            for (var length = 0; length <= seed.Length; length++)
            {
                targets.Run(target, seed.AsSpan(0, length));
            }
        }
    }
}
