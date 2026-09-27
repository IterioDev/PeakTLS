using System.Text;
using SharpTls.Quic;

namespace SharpTls.Tests.Quic;

// RFC 9204 s3.2's dynamic table as the ENCODER keeps it: sizes, eviction, and s2.1.4's Known
// Received Count driven by the peer's s4.4 instructions. See
// src/SharpTls/Quic/TlsQuicQpackEncoderTable.cs. Every number is computed by hand from
// s3.2.1's "32 + name length + value length" and the section rules; none is read back from
// the table and asserted against itself.
public sealed class TlsQuicQpackEncoderTableTests
{
    private static byte[] A(string text) => Encoding.ASCII.GetBytes(text);

    [Fact]
    public void EntrySizeIs32PlusNamePlusValue()
    {
        var table = new TlsQuicQpackEncoderTable(4096, 4096);

        var index = table.Insert(A("a"), A("bc"));

        Assert.Equal(0UL, index);
        Assert.Equal(35, table.Size);
        Assert.Equal(1UL, table.InsertCount);
        Assert.True(table.TryFind(A("a"), A("bc"), out var found));
        Assert.Equal(0UL, found);
        Assert.False(table.TryFind(A("a"), A("zz"), out _));
    }

    // s4.5.1.1: MaxEntries = floor(MaxTableCapacity / 32), and MaxTableCapacity is what the
    // DECODER advertised, not what this encoder chose. 16383 / 32 = 511; 4096 / 32 = 128.
    [Fact]
    public void MaxEntriesComesFromThePeerMaximumNotTheCapacity()
    {
        Assert.Equal(511UL, new TlsQuicQpackEncoderTable(4096, 16383).MaxEntries);
        Assert.Equal(128UL, new TlsQuicQpackEncoderTable(4096, 4096).MaxEntries);
    }

    [Fact]
    public void ACapacityAboveThePeerMaximumIsRefused()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicQpackEncoderTable(4097, 4096));
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsQuicQpackEncoderTable(-1, 4096));
    }

    // Three 35-octet entries into a 100-octet table: the third needs 105 and evicts the
    // oldest, leaving two entries and 70 octets. Absolute indices never renumber.
    [Fact]
    public void EvictionDropsTheOldestUntilTheNewEntryFits()
    {
        var table = new TlsQuicQpackEncoderTable(100, 4096);
        table.Insert(A("a"), A("b1"));
        table.Insert(A("a"), A("b2"));

        Assert.True(table.CanInsert(A("a"), A("b3")));
        var third = table.Insert(A("a"), A("b3"));

        Assert.Equal(2UL, third);
        Assert.Equal(1UL, table.DroppedCount);
        Assert.Equal(3UL, table.InsertCount);
        Assert.Equal(70, table.Size);
        Assert.False(table.TryFind(A("a"), A("b1"), out _));
        Assert.True(table.TryFind(A("a"), A("b2"), out var kept));
        Assert.Equal(1UL, kept);
    }

    // s2.1.1: "An encoder MUST NOT insert an entry into the dynamic table (or duplicate an
    // existing entry) if doing so would evict an entry with unacknowledged references."
    [Fact]
    public void AReferencedEntryIsNeverEvictedAndBlocksTheInsert()
    {
        var table = new TlsQuicQpackEncoderTable(100, 4096);
        table.Insert(A("a"), A("b1"));
        table.Insert(A("a"), A("b2"));
        table.RecordSection(streamId: 4, requiredInsertCount: 1, referenced: [0UL]);

        Assert.False(table.CanInsert(A("a"), A("b3")));
        Assert.Throws<InvalidOperationException>(() => table.Insert(A("a"), A("b3")));

        Assert.True(table.TryAcknowledgeSection(4));

        Assert.True(table.CanInsert(A("a"), A("b3")));
        table.Insert(A("a"), A("b3"));
        Assert.Equal(1UL, table.DroppedCount);
    }

    // The caller passes the smallest absolute index the section being planned references,
    // so an entry that section is about to reference is protected before it is recorded.
    [Fact]
    public void EvictableBytesStopBelowTheProtectedIndex()
    {
        var table = new TlsQuicQpackEncoderTable(100, 4096);
        table.Insert(A("a"), A("b1"));
        table.Insert(A("a"), A("b2"));

        Assert.Equal(70, table.EvictableBytes(ulong.MaxValue));
        Assert.Equal(35, table.EvictableBytes(1));
        Assert.Equal(0, table.EvictableBytes(0));
        Assert.False(table.CanInsert(A("a"), A("b3"), protectBelow: 0));
    }

    // s4.4.1: a Section Acknowledgment names a stream, acknowledges the OLDEST unacknowledged
    // section on it, and raises the Known Received Count to that section's RIC if larger.
    [Fact]
    public void SectionAcknowledgmentRaisesKnownReceivedToThatSectionsRic()
    {
        var table = new TlsQuicQpackEncoderTable(4096, 4096);
        table.Insert(A("a"), A("b1"));
        table.Insert(A("a"), A("b2"));
        table.Insert(A("a"), A("b3"));
        table.RecordSection(4, 3, [0UL, 1UL, 2UL]);
        table.RecordSection(8, 2, [0UL, 1UL]);

        Assert.True(table.TryAcknowledgeSection(8));
        Assert.Equal(2UL, table.KnownReceivedCount);
        Assert.True(table.TryAcknowledgeSection(4));
        Assert.Equal(3UL, table.KnownReceivedCount);
        Assert.False(table.TryAcknowledgeSection(4));
        Assert.Equal(3UL, table.KnownReceivedCount);
    }

    [Fact]
    public void TheOldestSectionOnAStreamIsTheOneAcknowledged()
    {
        var table = new TlsQuicQpackEncoderTable(4096, 4096);
        table.Insert(A("a"), A("b1"));
        table.Insert(A("a"), A("b2"));
        table.RecordSection(4, 1, [0UL]);
        table.RecordSection(4, 2, [1UL]);

        Assert.True(table.TryAcknowledgeSection(4));
        Assert.Equal(1UL, table.KnownReceivedCount);
        Assert.True(table.TryAcknowledgeSection(4));
        Assert.Equal(2UL, table.KnownReceivedCount);
    }

    // s4.4.3: "An encoder that receives an Increment field equal to zero, or one that
    // increases the Known Received Count beyond what the encoder has sent, MUST treat this
    // as a connection error of type QPACK_DECODER_STREAM_ERROR."
    [Fact]
    public void InsertCountIncrementOfZeroOrPastInsertCountIsRefused()
    {
        var table = new TlsQuicQpackEncoderTable(4096, 4096);
        table.Insert(A("a"), A("b1"));

        Assert.False(table.TryIncrementKnownReceived(0));
        Assert.False(table.TryIncrementKnownReceived(2));
        Assert.True(table.TryIncrementKnownReceived(1));
        Assert.Equal(1UL, table.KnownReceivedCount);
        Assert.False(table.TryIncrementKnownReceived(1));
    }

    [Fact]
    public void BlockedStreamCountCountsStreamsWithASectionAboveKnownReceived()
    {
        var table = new TlsQuicQpackEncoderTable(4096, 4096);
        table.Insert(A("a"), A("b1"));
        table.Insert(A("a"), A("b2"));
        table.RecordSection(4, 1, [0UL]);
        table.RecordSection(4, 2, [1UL]);
        table.RecordSection(8, 1, [0UL]);

        Assert.Equal(2, table.BlockedStreamCount);

        Assert.True(table.TryIncrementKnownReceived(1));
        Assert.Equal(1, table.BlockedStreamCount);

        Assert.True(table.TryCancelStream(4));
        Assert.Equal(0, table.BlockedStreamCount);
        Assert.False(table.TryCancelStream(4));
    }

    // s4.4.1: a section that used no dynamic entry is never acknowledged, so recording one
    // would only make a later acknowledgment for the same stream look wrong.
    [Fact]
    public void ASectionWithRicZeroIsNotRecorded()
    {
        var table = new TlsQuicQpackEncoderTable(4096, 4096);

        table.RecordSection(4, 0, []);

        Assert.False(table.TryAcknowledgeSection(4));
        Assert.False(table.TryCancelStream(4));
        Assert.Equal(0, table.BlockedStreamCount);
    }

    [Fact]
    public void KnownReceivedNeverMovesBackwards()
    {
        var table = new TlsQuicQpackEncoderTable(4096, 4096);
        table.Insert(A("a"), A("b1"));
        table.Insert(A("a"), A("b2"));
        table.RecordSection(4, 2, [1UL]);
        table.RecordSection(8, 1, [0UL]);

        Assert.True(table.TryAcknowledgeSection(4));
        Assert.Equal(2UL, table.KnownReceivedCount);
        Assert.True(table.TryAcknowledgeSection(8));
        Assert.Equal(2UL, table.KnownReceivedCount);
    }
}
