namespace TlsClient.Tests;

/// <summary>
/// Pins the bytes each <see cref="TlsHpackRepresentation"/> puts on the wire. The encoder
/// is the half of HPACK a peer can observe, and decoding is lossy about representation, so
/// a round-trip assertion proves nothing here — every case asserts emitted octets.
/// </summary>
public sealed class HpackEncoderPolicyTests
{
    /// <summary>The static table index of <c>:method</c>, whose lowest entry is GET.</summary>
    private const byte MethodNameIndex = 2;

    [Fact]
    public void Indexed_EmitsAnIndexedReferenceWhenTheTableHoldsTheExactPair()
    {
        var block = Encode(new TlsHpackOptions(), new HpackHeader(":method", "GET"));

        Assert.Equal([0x82], block);
    }

    [Fact]
    public void Indexed_FallsBackToTheDeclaredFormWhenNoExactMatchExists()
    {
        var options = new TlsHpackOptions
        {
            IndexedFallback = TlsHpackRepresentation.LiteralWithoutIndexing,
        };

        var block = Encode(options, new HpackHeader(":method", "PUT"));

        Assert.Equal(0x00 | MethodNameIndex, block[0]);
    }

    [Theory]
    [InlineData(TlsHpackRepresentation.LiteralIncrementalIndexing, 0x40)]
    [InlineData(TlsHpackRepresentation.LiteralWithoutIndexing, 0x00)]
    [InlineData(TlsHpackRepresentation.LiteralNeverIndexed, 0x10)]
    public void LiteralForms_StayLiteralEvenWhenAnExactMatchExists(
        TlsHpackRepresentation representation,
        int prefixMask)
    {
        // :method: GET is static index 1-based 2, an exact match. A declared literal form
        // is the persona's wire image, so the encoder must not collapse it to 0x82.
        var options = new TlsHpackOptions { DefaultRepresentation = representation };

        var block = Encode(options, new HpackHeader(":method", "GET"));

        Assert.Equal(prefixMask | MethodNameIndex, block[0]);
    }

    [Fact]
    public void LiteralIncrementalIndexing_InsertsSoTheSecondOccurrenceIsIndexed()
    {
        var encoder = new HpackEncoder(new TlsHpackOptions().Snapshot());

        _ = encoder.Encode([new HpackHeader("x-custom", "one")]);
        var second = encoder.Encode([new HpackHeader("x-custom", "one")]);

        // 61 static entries, so the freshest dynamic entry is index 62.
        Assert.Equal([0x80 | 62], second);
    }

    [Fact]
    public void LiteralWithoutIndexing_NeverInserts()
    {
        var options = new TlsHpackOptions
        {
            DefaultRepresentation = TlsHpackRepresentation.LiteralWithoutIndexing,
        };
        var encoder = new HpackEncoder(options.Snapshot());

        var first = encoder.Encode([new HpackHeader("x-custom", "one")]);
        var second = encoder.Encode([new HpackHeader("x-custom", "one")]);

        Assert.Equal(first, second);
        Assert.Equal(0x00, second[0]);
    }

    [Fact]
    public void PerHeaderDefaults_CarryTheFormerAuthorizationAndCookieRule()
    {
        var block = Encode(
            new TlsHpackOptions(),
            new HpackHeader("authorization", "Bearer secret"));

        // Never-indexed with a 4-bit prefix: index 23 exceeds the prefix, so 0x1F then 8.
        Assert.Equal(0x1F, block[0]);
        Assert.Equal(0x08, block[1]);
    }

    [Fact]
    public void EmptyCookie_IsANeverIndexedLiteralRatherThanStaticIndex32()
    {
        // The static table stores ("cookie", "") — an empty value, not an absent one — so
        // an exact-match encoder emits the single byte 0xA0 here. Under the never-indexed
        // default a persona that declares cookie never-indexed must not emit an indexed
        // reference for an empty one. This divergence is deliberate; see plan Task 8.
        var block = Encode(new TlsHpackOptions(), new HpackHeader("cookie", string.Empty));

        Assert.Equal([0x1F, 0x11, 0x00], block);
    }

    [Fact]
    public void Huffman_WhenShorterLeavesATieUnencoded()
    {
        // "&" is an 8-bit Huffman code: one byte either way, so it is exactly a tie.
        var options = new TlsHpackOptions
        {
            DefaultRepresentation = TlsHpackRepresentation.LiteralWithoutIndexing,
            Huffman = TlsHpackHuffman.WhenShorter,
        };

        var block = Encode(options, new HpackHeader(":method", "&"));

        Assert.Equal([0x00 | MethodNameIndex, 0x01, 0x26], block);
    }

    [Fact]
    public void Huffman_WhenNotLongerEncodesATie()
    {
        var options = new TlsHpackOptions
        {
            DefaultRepresentation = TlsHpackRepresentation.LiteralWithoutIndexing,
            Huffman = TlsHpackHuffman.WhenNotLonger,
        };

        var block = Encode(options, new HpackHeader(":method", "&"));

        Assert.Equal(3, block.Length);
        Assert.Equal(0x81, block[1]);
    }

    [Theory]
    [InlineData(TlsHpackHuffman.Always, 0x81)]
    [InlineData(TlsHpackHuffman.Never, 0x01)]
    public void Huffman_AlwaysAndNeverIgnoreLength(TlsHpackHuffman huffman, int stringHeader)
    {
        var options = new TlsHpackOptions
        {
            DefaultRepresentation = TlsHpackRepresentation.LiteralWithoutIndexing,
            Huffman = huffman,
        };

        var block = Encode(options, new HpackHeader(":method", "&"));

        Assert.Equal(stringHeader, block[1]);
    }

    [Theory]
    [InlineData(TlsHpackNameIndex.LowestStatic, 2)]
    [InlineData(TlsHpackNameIndex.HighestStatic, 3)]
    public void NameIndex_SelectsBetweenTheTwoStaticMethodEntries(
        TlsHpackNameIndex nameIndex,
        int expectedIndex)
    {
        // :method appears twice in the static table — GET at 2 and POST at 3 — so a
        // name-only reference to it is the one place the preference is observable.
        var options = new TlsHpackOptions
        {
            DefaultRepresentation = TlsHpackRepresentation.LiteralWithoutIndexing,
            NameIndex = nameIndex,
        };

        var block = Encode(options, new HpackHeader(":method", "PUT"));

        Assert.Equal(expectedIndex, block[0]);
    }

    [Fact]
    public void PerHeaderNameIndex_OverridesTheGlobalPreference()
    {
        var options = new TlsHpackOptions
        {
            DefaultRepresentation = TlsHpackRepresentation.LiteralWithoutIndexing,
            NameIndex = TlsHpackNameIndex.LowestStatic,
        };
        options.PerHeaderNameIndex[":method"] = 3;

        var block = Encode(options, new HpackHeader(":method", "PUT"));

        Assert.Equal(3, block[0]);
    }

    [Fact]
    public void PerHeaderHuffman_OverridesTheGlobalPolicy()
    {
        var options = new TlsHpackOptions
        {
            DefaultRepresentation = TlsHpackRepresentation.LiteralWithoutIndexing,
            Huffman = TlsHpackHuffman.Never,
        };
        options.PerHeaderHuffman[":method"] = TlsHpackHuffman.Always;

        var block = Encode(options, new HpackHeader(":method", "&"));

        Assert.Equal(0x81, block[1]);
    }

    [Fact]
    public void UseDynamicTableFalse_NeverInsertsAcrossManyRequests()
    {
        var options = new TlsHpackOptions { UseDynamicTable = false };
        var encoder = new HpackEncoder(options.Snapshot());

        var first = encoder.Encode([new HpackHeader("x-custom", "one")]);
        var second = encoder.Encode([new HpackHeader("x-custom", "one")]);
        var third = encoder.Encode([new HpackHeader("x-custom", "one")]);

        // An inserting encoder would answer the second occurrence with an index.
        Assert.Equal(first, second);
        Assert.Equal(first, third);
    }

    [Fact]
    public void UseDynamicTableFalse_WithLiteralFallbackIsTheStaticOnlyShape()
    {
        var options = new TlsHpackOptions
        {
            UseDynamicTable = false,
            IndexedFallback = TlsHpackRepresentation.LiteralWithoutIndexing,
        };
        var encoder = new HpackEncoder(options.Snapshot());

        var block = encoder.Encode(
        [
            new HpackHeader(":method", "GET"),
            new HpackHeader("x-custom", "one"),
        ]);

        Assert.Equal(0x82, block[0]);
        Assert.Equal(0x00, block[1]);
    }

    [Fact]
    public void TableSizeUpdateValues_EmitTheDeclaredSequenceInOrder()
    {
        // Evict everything, then resize — a real encoder signature a single value cannot
        // express. RFC 7541 section 4.2 permits the consecutive pair.
        var options = new TlsHpackOptions
        {
            TableSizeUpdate = TlsHpackTableSizeUpdate.BeforeFirstRequest,
            TableSizeUpdateValues = [0, 4096],
        };

        var block = Encode(options, new HpackHeader(":method", "GET"));

        Assert.Equal([0x20, 0x3F, 0xE1, 0x1F, 0x82], block);
    }

    [Fact]
    public void TableSizeUpdateValues_AreAppliedToTheEncodersOwnTable()
    {
        var options = new TlsHpackOptions
        {
            TableSizeUpdate = TlsHpackTableSizeUpdate.BeforeFirstRequest,
            TableSizeUpdateValues = [0],
        };
        var encoder = new HpackEncoder(options.Snapshot());

        _ = encoder.Encode([new HpackHeader("x-custom", "one")]);
        var second = encoder.Encode([new HpackHeader("x-custom", "one")]);

        // A zero-capacity table cannot hold the insertion, so the second block repeats
        // the literal rather than referencing an entry that was evicted on arrival.
        Assert.Equal(0x40, second[0]);
    }

    [Fact]
    public void TableSizeUpdate_BeforeFirstRequestEmitsOnceOnly()
    {
        var options = new TlsHpackOptions
        {
            TableSizeUpdate = TlsHpackTableSizeUpdate.BeforeFirstRequest,
            TableSizeUpdateValues = [0],
        };
        var encoder = new HpackEncoder(options.Snapshot());

        var first = encoder.Encode([new HpackHeader(":method", "GET")]);
        var second = encoder.Encode([new HpackHeader(":method", "GET")]);

        Assert.Equal([0x20, 0x82], first);
        Assert.Equal([0x82], second);
    }

    [Fact]
    public void TableSizeUpdate_NeverSuppressesEvenOnAPeerChange()
    {
        var options = new TlsHpackOptions
        {
            TableSizeUpdate = TlsHpackTableSizeUpdate.Never,
        };
        var encoder = new HpackEncoder(options.Snapshot());
        encoder.SetMaximumDynamicTableSize(0);

        var block = encoder.Encode([new HpackHeader(":method", "GET")]);

        Assert.Equal([0x82], block);
    }

    [Fact]
    public void TableSizeUpdate_OnPeerSettingsChangeStaysSilentUntilThePeerSpeaks()
    {
        var encoder = new HpackEncoder(new TlsHpackOptions().Snapshot());

        var before = encoder.Encode([new HpackHeader(":method", "GET")]);
        encoder.SetMaximumDynamicTableSize(0);
        var after = encoder.Encode([new HpackHeader(":method", "GET")]);

        Assert.Equal([0x82], before);
        Assert.Equal([0x20, 0x82], after);
    }

    [Fact]
    public void TableSizeUpdate_RejectsAValueLargerThanThePeerAllows()
    {
        var options = new TlsHpackOptions
        {
            TableSizeUpdate = TlsHpackTableSizeUpdate.BeforeFirstRequest,
            TableSizeUpdateValues = [8192],
        };
        var encoder = new HpackEncoder(options.Snapshot());
        encoder.SetMaximumDynamicTableSize(4096);

        var failure = Assert.Throws<HttpRequestException>(() =>
            encoder.Encode([new HpackHeader(":method", "GET")]));

        Assert.Contains("COMPRESSION_ERROR", failure.Message, StringComparison.Ordinal);
    }

    private static byte[] Encode(TlsHpackOptions options, params HpackHeader[] headers) =>
        new HpackEncoder(options.Snapshot()).Encode(headers);
}
