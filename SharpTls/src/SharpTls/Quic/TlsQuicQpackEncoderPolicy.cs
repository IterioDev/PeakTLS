namespace SharpTls.Quic;

/// <summary>What <see cref="TlsQuicQpackEncoderPolicy.Plan"/> decided for one request, and
/// what <see cref="TlsQuicQpackEncoderPolicy.Commit"/> will apply.</summary>
/// <param name="EncoderStreamBytes">RFC 9204 s4.3 instructions to send on the encoder stream
/// BEFORE the request's HEADERS frame; empty when nothing is inserted.</param>
/// <param name="FieldSection">The s4.5 encoded field section: prefix and every line.</param>
/// <param name="RequiredInsertCount">s2.1.1's count for the section, 0 when it references
/// no dynamic entry.</param>
/// <param name="Inserts">The pairs the section inserts, in encoder-stream order.</param>
/// <param name="ReferencedAbsoluteIndices">Every dynamic entry the section references, planned
/// inserts included, by the absolute index each will have after Commit.</param>
/// <param name="Seen">Every line that was not an exact static match, for the use counter.</param>
internal sealed record TlsQuicQpackEncoderPlan(
    ReadOnlyMemory<byte> EncoderStreamBytes,
    ReadOnlyMemory<byte> FieldSection,
    ulong RequiredInsertCount,
    IReadOnlyList<(byte[] Name, byte[] Value)> Inserts,
    IReadOnlyList<ulong> ReferencedAbsoluteIndices,
    IReadOnlyList<(byte[] Name, byte[] Value)> Seen);

// The decision layer between a request's header list and the QPACK encoders: which lines
// get inserted, which reference the table, and what the prefix says. One per HTTP/3
// connection. Everything measured about it is in
// docs/superpowers/specs/reference-captures/2026-09-26-spotify-9.1.86-ios27-pcapng.md s6 and
// the design in docs/superpowers/specs/2026-09-27-qpack-dynamic-table-encoder-design.md.
//
// TWO PHASES, BECAUSE THE CONNECTION CAN STILL REFUSE THE REQUEST AFTER ENCODING IT.
// TlsQuicHttp3Connection.TryOpenRequest encodes first and refuses on the field-section limit
// and three credit checks afterwards. Plan therefore mutates nothing - it reads the table and
// the use counter and describes what it would do - and Commit applies it once the request
// stream is open. A refused request is never committed and leaves no trace; the peer never
// learns of inserts it did not receive.
//
// THE INSERT GATE, AS MEASURED (s6 of the capture doc, 3 of 3 connections, 36 inserts):
//   1. capacity has been sent - the peer's SETTINGS have arrived and the smaller of the two
//      capacities is non-zero;
//   2. the pair is not an exact static-table match and is not already in the table;
//   3. the pair appeared in at least one earlier request encoded WHILE THE TABLE WAS ACTIVE.
//      Requests encoded before the capacity went out do not count, which is why the first
//      request after capacity is always static-only - nothing has an active prior use yet -
//      and why a pair that appeared only before capacity is never inserted on its next use.
// Every insert in the capture and every non-insert of a repeated pair satisfies this; the
// use counter therefore starts counting when the table does. Under
// TlsQuicQpackInsertPolicy.Never nothing is ever inserted and, with a capacity, the table
// simply holds nothing.
//
// THE BLOCKED-STREAMS BUDGET IS DECIDED ONCE PER SECTION. s2.1.2: an encoder may reference an
// entry the peer has not acknowledged only while fewer than SETTINGS_QPACK_BLOCKED_STREAMS
// streams are blocked. A new request's stream is never already blocked, so the test is
// BlockedStreamCount < the peer's limit; when it fails, every planned insert and every
// reference above the Known Received Count is downgraded to the literal it would otherwise
// have been, and the section goes out with only known-received references.
//
// WITH CAPACITY 0 - the library default - every plan is today's static-only section, byte for
// byte, with an empty encoder-stream image: the same TlsQuicQpackEncoder.TryEncodeFieldLine
// writes every line, through the same Huffman and name-match knobs.
internal sealed class TlsQuicQpackEncoderPolicy
{
    private enum Kind
    {
        // An exact static-table match: s4.5.2 with T = 1. Not counted as seen.
        StaticExact,

        // Today's path: s4.5.4 or s4.5.6 by the spec's name-match policy.
        Static,

        // Already in the dynamic table: s4.5.2 with T = 0, relative to Base.
        Dynamic,

        // Inserted by this plan: s4.5.3, post-base.
        Insert,
    }

    private const int InitialBufferLength = 256;

    private readonly TlsQuicHttp3Spec _spec;
    private readonly Dictionary<string, int> _uses = new(StringComparer.Ordinal);
    private TlsQuicQpackEncoderTable? _table;
    private ulong _peerBlockedStreams;

    internal TlsQuicQpackEncoderPolicy(TlsQuicHttp3Spec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        _spec = spec;
    }

    /// <summary>Gets whether Set Dynamic Table Capacity has been produced for this
    /// connection, which is also whether a table exists.</summary>
    internal bool CapacitySent => _table is not null;

    /// <summary>Gets the encoder table, or <see langword="null"/> before the peer's
    /// SETTINGS or when either side's capacity is zero.</summary>
    internal TlsQuicQpackEncoderTable? Table => _table;

    /// <summary>Gets how many committed requests have carried this pair since the table
    /// became active; requests before that are not counted.</summary>
    internal int UseCount(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value) =>
        _uses.TryGetValue(Key(name, value), out var count) ? count : 0;

    /// <summary>Applies the peer's SETTINGS. Returns the Set Dynamic Table Capacity
    /// instruction to send, or empty when there will be no table.</summary>
    /// <remarks>s3.2.3: the capacity set "MUST NOT exceed the value of
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY" the peer advertised, so the announced capacity is
    /// the smaller of the spec's and the peer's. In every capture the two were equal at
    /// 4096, so what the imitated client does above the peer's number is unmeasured.</remarks>
    internal ReadOnlyMemory<byte> OnPeerSettings(ulong peerMaximumCapacity, ulong peerBlockedStreams)
    {
        if (_table is not null)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        _peerBlockedStreams = peerBlockedStreams;
        var capacity = Math.Min((ulong)_spec.QpackEncoderDynamicTableCapacity, peerMaximumCapacity);
        if (capacity == 0)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        _table = new TlsQuicQpackEncoderTable((int)capacity, peerMaximumCapacity);

        var buffer = new byte[TlsQuicQpackPrimitives.MaximumIntegerEncodedLength];
        if (!TlsQuicQpackEncoder.TryEncodeSetDynamicTableCapacity(capacity, buffer, out int written))
        {
            throw new InvalidOperationException(
                "Set Dynamic Table Capacity did not fit MaximumIntegerEncodedLength.");
        }

        return buffer.AsMemory(0, written);
    }

    /// <summary>Plans one request's header section without changing any state.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="lines"/> is
    /// <see langword="null"/>.</exception>
    internal TlsQuicQpackEncoderPlan Plan(List<(byte[] Name, byte[] Value)> lines)
    {
        ArgumentNullException.ThrowIfNull(lines);

        var kinds = new Kind[lines.Count];
        var absolute = new ulong[lines.Count];
        var insertOf = new int[lines.Count];
        var seen = new List<(byte[] Name, byte[] Value)>();
        var protectBelow = ulong.MaxValue;

        // Pass 1: classify. Exact static matches are outside every counter and every table;
        // everything else is "seen", and either already in our table or a candidate.
        for (var i = 0; i < lines.Count; i++)
        {
            var (name, value) = lines[i];
            if (TlsQuicQpackStaticTable.TryFindNameAndValue(name, value, out _))
            {
                kinds[i] = Kind.StaticExact;
                continue;
            }

            seen.Add(lines[i]);
            if (_table is not null && _table.TryFind(name, value, out var index))
            {
                kinds[i] = Kind.Dynamic;
                absolute[i] = index;
                protectBelow = Math.Min(protectBelow, index);
                continue;
            }

            kinds[i] = Kind.Static;
        }

        // Pass 2: the insert gate, in header order, against a budget that already counts the
        // entries this section protects and the inserts planned before it in this section.
        var inserts = new List<(byte[] Name, byte[] Value)>();
        var inserting = _table is not null
            && _spec.QpackInsertPolicy == TlsQuicQpackInsertPolicy.OnSecondUse;
        if (inserting)
        {
            var budget = _table!.Capacity - _table.Size + _table.EvictableBytes(protectBelow);
            for (var i = 0; i < lines.Count; i++)
            {
                if (kinds[i] != Kind.Static)
                {
                    continue;
                }

                var (name, value) = lines[i];
                var planned = IndexOfPair(inserts, name, value);
                if (planned >= 0)
                {
                    // The same pair twice in one request inserts once and references twice.
                    kinds[i] = Kind.Insert;
                    insertOf[i] = planned;
                    continue;
                }

                if (UseCount(name, value) < 1)
                {
                    continue;
                }

                var size = TlsQuicQpackEncoderTable.EntrySizeOverhead + name.Length + value.Length;
                if (size > budget)
                {
                    continue;
                }

                budget -= size;
                inserts.Add(lines[i]);
                kinds[i] = Kind.Insert;
                insertOf[i] = inserts.Count - 1;
            }
        }

        // Pass 3: the blocked-streams budget, once for the whole section.
        if (_table is not null)
        {
            var knownReceived = _table.KnownReceivedCount;
            var wouldBlock = inserts.Count > 0;
            for (var i = 0; i < lines.Count && !wouldBlock; i++)
            {
                wouldBlock = kinds[i] == Kind.Dynamic && absolute[i] >= knownReceived;
            }

            if (wouldBlock && (ulong)_table.BlockedStreamCount >= _peerBlockedStreams)
            {
                for (var i = 0; i < lines.Count; i++)
                {
                    if (kinds[i] == Kind.Insert || (kinds[i] == Kind.Dynamic && absolute[i] >= knownReceived))
                    {
                        kinds[i] = Kind.Static;
                    }
                }

                inserts.Clear();
            }
        }

        // The prefix numbers. Base is the table's insert count before this section's inserts,
        // so existing entries are relative to it and planned ones are post-base. A section
        // that references nothing dynamic takes Base 0: s4.5.1.2 lets it "use any value for the
        // Base", the static-only arm has always written `00 00`, and the capture's static
        // sections after capacity carry exactly that.
        var insertCount = _table?.InsertCount ?? 0;
        ulong requiredInsertCount = 0;
        var referenced = new List<ulong>();
        for (var i = 0; i < lines.Count; i++)
        {
            if (kinds[i] == Kind.Dynamic)
            {
                referenced.Add(absolute[i]);
                requiredInsertCount = Math.Max(requiredInsertCount, absolute[i] + 1);
            }
            else if (kinds[i] == Kind.Insert)
            {
                var index = insertCount + (ulong)insertOf[i];
                referenced.Add(index);
                requiredInsertCount = Math.Max(requiredInsertCount, index + 1);
            }
        }

        var @base = requiredInsertCount == 0 ? 0 : insertCount;

        var encoderBytes = inserts.Count == 0
            ? ReadOnlyMemory<byte>.Empty
            : Grow(destination => TryWriteInserts(inserts, destination, out int written) ? written : -1);
        var section = Grow(destination =>
            TryWriteSection(lines, kinds, absolute, insertOf, @base, requiredInsertCount, destination, out int written)
                ? written
                : -1);

        return new TlsQuicQpackEncoderPlan(
            encoderBytes, section, requiredInsertCount, inserts, referenced, seen);
    }

    /// <summary>Applies a plan the connection has decided to send on
    /// <paramref name="streamId"/>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="plan"/> is
    /// <see langword="null"/>.</exception>
    internal void Commit(TlsQuicQpackEncoderPlan plan, ulong streamId)
    {
        ArgumentNullException.ThrowIfNull(plan);

        // The use counter starts with the table: a request encoded before the capacity went
        // out leaves no trace, which is rule 3 of the gate in the header comment.
        if (_table is null)
        {
            return;
        }

        foreach (var (name, value) in plan.Seen)
        {
            var key = Key(name, value);
            _uses[key] = _uses.TryGetValue(key, out var count) ? count + 1 : 1;
        }

        // Existing entries this section references must survive its own inserts' evictions;
        // they are recorded only after the inserts exist, so the protection is passed down.
        var protectBelow = ulong.MaxValue;
        foreach (var index in plan.ReferencedAbsoluteIndices)
        {
            if (index < _table.InsertCount)
            {
                protectBelow = Math.Min(protectBelow, index);
            }
        }

        foreach (var (name, value) in plan.Inserts)
        {
            _table.Insert(name, value, protectBelow);
        }

        _table.RecordSection(streamId, plan.RequiredInsertCount, plan.ReferencedAbsoluteIndices);
    }

    /// <summary>The peer's s4.4.1 Section Acknowledgment.</summary>
    /// <returns><see langword="false"/> when nothing is recorded for the stream, which is the
    /// peer's QPACK_DECODER_STREAM_ERROR.</returns>
    internal bool TryAcknowledgeSection(ulong streamId) =>
        _table is not null && _table.TryAcknowledgeSection(streamId);

    /// <summary>The peer's s4.4.2 Stream Cancellation. Always legal.</summary>
    internal void CancelStream(ulong streamId) => _table?.TryCancelStream(streamId);

    /// <summary>The peer's s4.4.3 Insert Count Increment.</summary>
    /// <returns><see langword="false"/> for zero, for an increment past the Insert Count, or
    /// when there is no table to increment - all the peer's QPACK_DECODER_STREAM_ERROR.</returns>
    internal bool TryIncrementKnownReceived(ulong increment) =>
        _table is not null && _table.TryIncrementKnownReceived(increment);

    private static string Key(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value) =>
        Convert.ToHexString(name) + ":" + Convert.ToHexString(value);

    private static int IndexOfPair(List<(byte[] Name, byte[] Value)> pairs, ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    {
        for (var i = 0; i < pairs.Count; i++)
        {
            if (name.SequenceEqual(pairs[i].Name) && value.SequenceEqual(pairs[i].Value))
            {
                return i;
            }
        }

        return -1;
    }

    // The writers report "too small" by returning false; the buffer doubles until one fits.
    // The same shape as TlsQuicHttp3Request.EncodeFieldSection's loop.
    private static ReadOnlyMemory<byte> Grow(Func<byte[], int> tryWrite)
    {
        var buffer = new byte[InitialBufferLength];
        while (true)
        {
            var written = tryWrite(buffer);
            if (written >= 0)
            {
                return buffer.AsMemory(0, written);
            }

            buffer = new byte[buffer.Length * 2];
        }
    }

    private bool TryWriteInserts(List<(byte[] Name, byte[] Value)> inserts, Span<byte> destination, out int written)
    {
        written = 0;
        foreach (var (name, value) in inserts)
        {
            // s4.3.2 to the STATIC name when the static table has it, s4.3.3 otherwise. The
            // capture never references a dynamic name and never Duplicates.
            int count;
            var ok = TlsQuicQpackStaticTable.TryFindName(name, out int nameIndex)
                ? TlsQuicQpackEncoder.TryEncodeInsertWithStaticNameReference(
                    nameIndex, value, _spec.QpackHuffmanStringLiterals, destination[written..], out count)
                : TlsQuicQpackEncoder.TryEncodeInsertWithLiteralName(
                    name, value, _spec.QpackHuffmanStringLiterals, destination[written..], out count);
            if (!ok)
            {
                written = 0;
                return false;
            }

            written += count;
        }

        return true;
    }

    private bool TryWriteSection(
        List<(byte[] Name, byte[] Value)> lines,
        Kind[] kinds,
        ulong[] absolute,
        int[] insertOf,
        ulong @base,
        ulong requiredInsertCount,
        Span<byte> destination,
        out int written)
    {
        written = 0;
        var prefixOk = _table is null
            ? TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(destination, out int offset)
            : TlsQuicQpackEncoder.TryEncodeFieldSectionPrefix(
                requiredInsertCount, @base, _table.MaxEntries, destination, out offset);
        if (!prefixOk)
        {
            return false;
        }

        for (var i = 0; i < lines.Count; i++)
        {
            var (name, value) = lines[i];
            int count;
            bool ok;
            switch (kinds[i])
            {
                case Kind.Dynamic:
                    ok = TlsQuicQpackEncoder.TryEncodeIndexedDynamic(
                        @base - absolute[i] - 1, destination[offset..], out count);
                    break;
                case Kind.Insert:
                    ok = TlsQuicQpackEncoder.TryEncodeIndexedPostBase(
                        (ulong)insertOf[i], destination[offset..], out count);
                    break;
                default:
                    ok = TlsQuicQpackEncoder.TryEncodeFieldLine(
                        name,
                        value,
                        _spec.QpackHuffmanStringLiterals,
                        _spec.QpackNameMatchPolicy == TlsQuicQpackNameMatchPolicy.NameReference,
                        destination[offset..],
                        out count);
                    break;
            }

            if (!ok)
            {
                return false;
            }

            offset += count;
        }

        written = offset;
        return true;
    }
}
