namespace TlsClient.Tests;

/// <summary>
/// The HPACK policy is validated by <c>TlsHttp2Options.Snapshot()</c> at session
/// construction, so every case here drives it through that public path rather than
/// reaching for the internal snapshot directly.
/// </summary>
public sealed class TlsHpackOptionsTests
{
    [Fact]
    public void Snapshot_RejectsMoreThanTwoTableSizeUpdates()
    {
        var options = new TlsHpackOptions { TableSizeUpdateValues = [0, 4096, 8192] };

        var failure = Assert.ThrowsAny<ArgumentException>(() => options.Snapshot());

        Assert.Contains("at most two", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Snapshot_RejectsATableSizeUpdatePairThatDoesNotStartWithTheSmallest()
    {
        // RFC 7541 section 4.2: the pair is the smallest size followed by the size that
        // will be used. The reverse tells a decoder to grow and then shrink, which is not
        // what a size that changed twice between blocks looks like.
        var options = new TlsHpackOptions { TableSizeUpdateValues = [4096, 0] };

        var failure = Assert.ThrowsAny<ArgumentException>(() => options.Snapshot());

        Assert.Contains("smallest size", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Snapshot_RejectsIndexedAsTheIndexedFallback()
    {
        var options = new TlsHttp2Options();
        options.Hpack.IndexedFallback = TlsHpackRepresentation.Indexed;

        var exception = Assert.Throws<ArgumentException>(() => options.Snapshot());

        Assert.Equal("IndexedFallback", exception.ParamName);
        Assert.Contains("IndexedFallback", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Snapshot_RejectsANameIndexPointingAtAMismatchedTableEntry()
    {
        var options = new TlsHttp2Options();

        // Static table entry 2 is ":method: GET", so index 2 does not name ":path".
        options.Hpack.PerHeaderNameIndex[":path"] = 2;

        var exception = Assert.Throws<ArgumentException>(() => options.Snapshot());

        Assert.Equal("PerHeaderNameIndex", exception.ParamName);
        Assert.Contains("PerHeaderNameIndex", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Snapshot_RejectsAnUppercasePerHeaderKey()
    {
        var options = new TlsHttp2Options();
        options.Hpack.PerHeader["Cookie"] = TlsHpackRepresentation.LiteralWithoutIndexing;

        var exception = Assert.Throws<ArgumentException>(() => options.Snapshot());

        Assert.Equal("PerHeader", exception.ParamName);
        Assert.Contains("PerHeader", exception.Message, StringComparison.Ordinal);
    }
}
