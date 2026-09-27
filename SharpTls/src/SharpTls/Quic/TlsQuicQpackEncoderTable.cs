namespace SharpTls.Quic;

// RFC 9204 s3.2's dynamic table, ENCODER SIDE. See
// reference-captures/rfc9204-section3.2-dynamic-table.txt and s2.1.
//
// WHY A SECOND TABLE CLASS. TlsQuicQpackDynamicTable is the decoder's: it is driven by the
// peer's encoder instructions, resolves the three index forms for a field section that
// arrives, and holds references for sections that are still parked. This one is ours: it is
// driven by TlsQuicQpackEncoderPolicy's decisions, answers "is this pair already in the
// table" and "does this insert fit", and tracks what the PEER has told us it received -
// s2.1.4's Known Received Count and s2.1.1's "unacknowledged references". The two classes
// share the s3.2.1 size rule and nothing else, and folding the second into the first would
// have put a decoder's parked-section bookkeeping next to an encoder's acknowledgment
// bookkeeping under one set of names.
//
// s3.2.1: "The size of an entry is the sum of its name's length in bytes, its value's
// length in bytes, and 32."
//
// s2.1.1: "An encoder MUST NOT insert an entry into the dynamic table (or duplicate an
// existing entry) if doing so would evict an entry with unacknowledged references." Eviction
// is FIFO by absolute index, so the question "how much can be freed" is answered by walking
// from the oldest entry to the first one that is referenced - by a recorded section, or by
// the section the caller is planning, which is what `protectBelow` names.
//
// s4.4.1: a Section Acknowledgment "acknowledges the oldest unacknowledged field section on
// that stream" and, if that section's Required Insert Count is greater than the Known
// Received Count, raises the count to it. s4.4.3: an Insert Count Increment of zero, or one
// that takes the count past the Insert Count, is a QPACK_DECODER_STREAM_ERROR. Both are
// reported as `false` here; the stream layer chooses the code.
internal sealed class TlsQuicQpackEncoderTable
{
    /// <summary>RFC 9204 s3.2.1's per-entry overhead.</summary>
    internal const int EntrySizeOverhead = 32;

    /// <summary>RFC 9204 s6's <c>QPACK_DECODER_STREAM_ERROR</c>.</summary>
    internal const ulong QpackDecoderStreamError = 0x0202;

    private sealed class Entry(ulong absoluteIndex, byte[] name, byte[] value)
    {
        public ulong AbsoluteIndex { get; } = absoluteIndex;

        public byte[] Name { get; } = name;

        public byte[] Value { get; } = value;

        public int Size => EntrySizeOverhead + Name.Length + Value.Length;

        // Outstanding references from sections the peer has not acknowledged or cancelled.
        public int References { get; set; }
    }

    private sealed record Section(ulong StreamId, ulong RequiredInsertCount, ulong[] Referenced);

    // Oldest first. _entries[0].AbsoluteIndex == DroppedCount whenever the list is non-empty.
    private readonly List<Entry> _entries = [];

    // Unacknowledged sections in record order, which is also per-stream age order.
    private readonly List<Section> _sections = [];

    /// <summary>Creates an encoder table.</summary>
    /// <param name="capacity">The capacity this encoder will announce with Set Dynamic Table
    /// Capacity; at most <paramref name="peerMaximumCapacity"/>.</param>
    /// <param name="peerMaximumCapacity">The peer's <c>SETTINGS_QPACK_MAX_TABLE_CAPACITY</c>,
    /// from which s4.5.1.1's MaxEntries is derived.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="capacity"/> is negative
    /// or above <paramref name="peerMaximumCapacity"/>.</exception>
    internal TlsQuicQpackEncoderTable(int capacity, ulong peerMaximumCapacity)
    {
        if (capacity < 0 || (ulong)capacity > peerMaximumCapacity)
        {
            throw new ArgumentOutOfRangeException(
                nameof(capacity),
                capacity,
                "RFC 9204 s3.2.3: the capacity an encoder sets \"MUST NOT exceed the value "
                    + "of SETTINGS_QPACK_MAX_TABLE_CAPACITY\" the decoder advertised.");
        }

        Capacity = capacity;
        MaxEntries = peerMaximumCapacity / (ulong)EntrySizeOverhead;
    }

    /// <summary>Gets the announced capacity, in octets.</summary>
    internal int Capacity { get; }

    /// <summary>Gets the octets the current entries occupy, s3.2.1 sizes summed.</summary>
    internal int Size { get; private set; }

    /// <summary>Gets s3.2.4's Insert Count: entries ever inserted.</summary>
    internal ulong InsertCount { get; private set; }

    /// <summary>Gets the entries evicted so far; the oldest live entry has this absolute
    /// index.</summary>
    internal ulong DroppedCount { get; private set; }

    /// <summary>Gets s2.1.4's Known Received Count.</summary>
    internal ulong KnownReceivedCount { get; private set; }

    /// <summary>Gets s4.5.1.1's MaxEntries, from the PEER's advertised maximum.</summary>
    internal ulong MaxEntries { get; }

    /// <summary>Gets the number of streams with a recorded section whose Required Insert
    /// Count is above <see cref="KnownReceivedCount"/> - s2.1.2's blocked streams, as the
    /// peer will count them.</summary>
    internal int BlockedStreamCount
    {
        get
        {
            var blocked = new HashSet<ulong>();
            foreach (var section in _sections)
            {
                if (section.RequiredInsertCount > KnownReceivedCount)
                {
                    blocked.Add(section.StreamId);
                }
            }

            return blocked.Count;
        }
    }

    /// <summary>Finds the newest entry with exactly this name and value.</summary>
    internal bool TryFind(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value, out ulong absoluteIndex)
    {
        for (var i = _entries.Count - 1; i >= 0; i--)
        {
            var entry = _entries[i];
            if (name.SequenceEqual(entry.Name) && value.SequenceEqual(entry.Value))
            {
                absoluteIndex = entry.AbsoluteIndex;
                return true;
            }
        }

        absoluteIndex = 0;
        return false;
    }

    /// <summary>Gets whether the peer has acknowledged receiving this entry.</summary>
    internal bool IsKnownReceived(ulong absoluteIndex) => absoluteIndex < KnownReceivedCount;

    /// <summary>The octets freed by evicting the contiguous run of oldest entries that carry
    /// no reference and whose absolute index is below <paramref name="protectBelow"/>.</summary>
    internal int EvictableBytes(ulong protectBelow)
    {
        var freed = 0;
        foreach (var entry in _entries)
        {
            if (entry.References != 0 || entry.AbsoluteIndex >= protectBelow)
            {
                break;
            }

            freed += entry.Size;
        }

        return freed;
    }

    /// <summary>Gets whether <see cref="Insert"/> would succeed for this pair, evicting only
    /// unreferenced entries below <paramref name="protectBelow"/>.</summary>
    internal bool CanInsert(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value, ulong protectBelow = ulong.MaxValue)
    {
        var size = EntrySizeOverhead + name.Length + value.Length;
        return size <= Capacity - Size + EvictableBytes(protectBelow);
    }

    /// <summary>Inserts a pair, evicting from the oldest end as s3.2.2 requires, and returns
    /// its absolute index.</summary>
    /// <param name="name">The field name.</param>
    /// <param name="value">The field value.</param>
    /// <param name="protectBelow">Entries at or above this absolute index are referenced by
    /// the section being committed and are not yet recorded; eviction stops at them exactly
    /// as <see cref="EvictableBytes"/> did when the insert was planned.</param>
    /// <exception cref="InvalidOperationException">Making room would evict a referenced or
    /// protected entry, or the pair cannot fit even an empty table. The policy checks
    /// <see cref="CanInsert"/> first; reaching here is its bug.</exception>
    internal ulong Insert(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value, ulong protectBelow = ulong.MaxValue)
    {
        var size = EntrySizeOverhead + name.Length + value.Length;
        if (size > Capacity)
        {
            throw new InvalidOperationException(
                $"An entry of {size} octets cannot fit a table of capacity {Capacity}.");
        }

        while (Size + size > Capacity)
        {
            var oldest = _entries[0];
            if (oldest.References != 0 || oldest.AbsoluteIndex >= protectBelow)
            {
                throw new InvalidOperationException(
                    "RFC 9204 s2.1.1: an insert that would evict an entry with "
                        + "unacknowledged references. CanInsert was not consulted.");
            }

            _entries.RemoveAt(0);
            Size -= oldest.Size;
            DroppedCount++;
        }

        var index = InsertCount;
        _entries.Add(new Entry(index, name.ToArray(), value.ToArray()));
        Size += size;
        InsertCount++;
        return index;
    }

    /// <summary>Records a sent field section's references so that the entries it uses are
    /// not evicted before the peer acknowledges it.</summary>
    /// <remarks>A section with a Required Insert Count of 0 used no dynamic entry and, by
    /// s4.4.1, is never acknowledged - so it is not recorded, and a later acknowledgment
    /// naming its stream is correctly read as the peer's error.</remarks>
    internal void RecordSection(ulong streamId, ulong requiredInsertCount, IReadOnlyList<ulong> referenced)
    {
        ArgumentNullException.ThrowIfNull(referenced);
        if (requiredInsertCount == 0)
        {
            return;
        }

        var indices = new ulong[referenced.Count];
        for (var i = 0; i < indices.Length; i++)
        {
            indices[i] = referenced[i];
            FindEntry(indices[i]).References++;
        }

        _sections.Add(new Section(streamId, requiredInsertCount, indices));
    }

    /// <summary>Applies s4.4.1's Section Acknowledgment.</summary>
    /// <returns><see langword="false"/> if the stream has no recorded section, which s4.4.1
    /// makes a QPACK_DECODER_STREAM_ERROR.</returns>
    internal bool TryAcknowledgeSection(ulong streamId)
    {
        for (var i = 0; i < _sections.Count; i++)
        {
            var section = _sections[i];
            if (section.StreamId != streamId)
            {
                continue;
            }

            _sections.RemoveAt(i);
            Release(section);
            if (section.RequiredInsertCount > KnownReceivedCount)
            {
                KnownReceivedCount = section.RequiredInsertCount;
            }

            return true;
        }

        return false;
    }

    /// <summary>Applies s4.4.2's Stream Cancellation: every recorded section on the stream is
    /// released.</summary>
    /// <returns>Whether anything was recorded for the stream. A <see langword="false"/> is
    /// NOT an error - s4.4.2 lets a decoder cancel a stream that carried nothing dynamic.</returns>
    internal bool TryCancelStream(ulong streamId)
    {
        var any = false;
        for (var i = _sections.Count - 1; i >= 0; i--)
        {
            if (_sections[i].StreamId == streamId)
            {
                Release(_sections[i]);
                _sections.RemoveAt(i);
                any = true;
            }
        }

        return any;
    }

    /// <summary>Applies s4.4.3's Insert Count Increment.</summary>
    /// <returns><see langword="false"/> for an increment of zero or one that would take the
    /// Known Received Count past the Insert Count - both QPACK_DECODER_STREAM_ERROR.</returns>
    internal bool TryIncrementKnownReceived(ulong increment)
    {
        if (increment == 0 || increment > InsertCount - KnownReceivedCount)
        {
            return false;
        }

        KnownReceivedCount += increment;
        return true;
    }

    private void Release(Section section)
    {
        foreach (var index in section.Referenced)
        {
            FindEntry(index).References--;
        }
    }

    private Entry FindEntry(ulong absoluteIndex)
    {
        if (absoluteIndex < DroppedCount || absoluteIndex >= InsertCount)
        {
            throw new InvalidOperationException(
                $"Absolute index {absoluteIndex} is not a live entry (live range "
                    + $"{DroppedCount}..{InsertCount - 1}).");
        }

        return _entries[(int)(absoluteIndex - DroppedCount)];
    }
}
