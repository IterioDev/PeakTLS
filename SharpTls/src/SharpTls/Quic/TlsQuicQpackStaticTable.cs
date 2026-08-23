namespace SharpTls.Quic;

// RFC 9204 s3.1 and Appendix A: the QPACK static table. See
// reference-captures/rfc9204-appendix-a-static-table.txt, which is where every row below
// came from - the file was PARSED, not retyped, and TlsQuicQpackStaticTableTests re-parses
// it and compares row for row. That is the only evidence that counts here, because a
// transcription error in a 99-row table is invisible to an encode/decode round trip: the
// encoder and the decoder read the same array and would agree while both were wrong.
//
// THIS IS NOT A NAME-TO-VALUE MAP, and code that treats it as one is wrong. 21 of the 99
// rows have an EMPTY value, which is a value - the empty string - and not the absence of
// one; row 0 is `:authority` with an empty value and row 1 is `:path` with `/`. Names
// repeat with different values: `:status` spans 14 rows, `content-type` 11, `:method` 7.
// So a name-only lookup and a name-and-value lookup are DIFFERENT OPERATIONS and are
// exposed separately below. Appendix A says why: "some of the entries may be inconsistent
// or appear multiple times with similar but not identical values".
//
// ON THE WRAPPED VALUES. Twelve rows in the capture continue onto a second or third line,
// because the value column is 21 characters wide. Rejoining them is NOT mechanical - the
// renderer breaks after a space and CONSUMES it, but breaks after `-` or `/` and keeps the
// character - so `text/html;` + `charset=utf-8` rejoins WITH a space while `text/` +
// `plain;charset=utf-8` rejoins WITHOUT one. Guessing would be indefensible, so the join is
// derived from the table's own geometry instead: each rejoined value is re-wrapped greedily
// at 21 columns and must reproduce the captured lines character for character. Only one of
// the two joins survives that for each row - `text/plain; charset=utf-8` would have been
// rendered `text/plain;` + `charset=utf-8`, and it was not.
// TlsQuicQpackStaticTableTests.TheWrappedValuesRejoinTheOnlyWayTheCaptureAllows runs that
// re-wrap over all 99 rows.
//
// ON THE COUNT. `Count` is `Table.Length / 2` - derived from the array, never written down
// as 99 in this file. The test derives 99 independently from the capture.
internal static class TlsQuicQpackStaticTable
{
    // Name and value interleaved, one source line per captured row, so a diff against the
    // capture's two columns is a diff against these two columns.
    private static readonly string[] Table =
    [
        ":authority",                        "",                                     // 0
        ":path",                             "/",                                    // 1
        "age",                               "0",                                    // 2
        "content-disposition",               "",                                     // 3
        "content-length",                    "0",                                    // 4
        "cookie",                            "",                                     // 5
        "date",                              "",                                     // 6
        "etag",                              "",                                     // 7
        "if-modified-since",                 "",                                     // 8
        "if-none-match",                     "",                                     // 9
        "last-modified",                     "",                                     // 10
        "link",                              "",                                     // 11
        "location",                          "",                                     // 12
        "referer",                           "",                                     // 13
        "set-cookie",                        "",                                     // 14
        ":method",                           "CONNECT",                              // 15
        ":method",                           "DELETE",                               // 16
        ":method",                           "GET",                                  // 17
        ":method",                           "HEAD",                                 // 18
        ":method",                           "OPTIONS",                              // 19
        ":method",                           "POST",                                 // 20
        ":method",                           "PUT",                                  // 21
        ":scheme",                           "http",                                 // 22
        ":scheme",                           "https",                                // 23
        ":status",                           "103",                                  // 24
        ":status",                           "200",                                  // 25
        ":status",                           "304",                                  // 26
        ":status",                           "404",                                  // 27
        ":status",                           "503",                                  // 28
        "accept",                            "*/*",                                  // 29
        "accept",                            "application/dns-message",              // 30
        "accept-encoding",                   "gzip, deflate, br",                    // 31
        "accept-ranges",                     "bytes",                                // 32
        "access-control-allow-headers",      "cache-control",                        // 33
        "access-control-allow-headers",      "content-type",                         // 34
        "access-control-allow-origin",       "*",                                    // 35
        "cache-control",                     "max-age=0",                            // 36
        "cache-control",                     "max-age=2592000",                      // 37
        "cache-control",                     "max-age=604800",                       // 38
        "cache-control",                     "no-cache",                             // 39
        "cache-control",                     "no-store",                             // 40
        "cache-control",                     "public, max-age=31536000",             // 41
        "content-encoding",                  "br",                                   // 42
        "content-encoding",                  "gzip",                                 // 43
        "content-type",                      "application/dns-message",              // 44
        "content-type",                      "application/javascript",               // 45
        "content-type",                      "application/json",                     // 46
        "content-type",                      "application/x-www-form-urlencoded",    // 47
        "content-type",                      "image/gif",                            // 48
        "content-type",                      "image/jpeg",                           // 49
        "content-type",                      "image/png",                            // 50
        "content-type",                      "text/css",                             // 51
        "content-type",                      "text/html; charset=utf-8",             // 52
        "content-type",                      "text/plain",                           // 53
        "content-type",                      "text/plain;charset=utf-8",             // 54
        "range",                             "bytes=0-",                             // 55
        "strict-transport-security",         "max-age=31536000",                     // 56
        "strict-transport-security",         "max-age=31536000; includesubdomains",  // 57
        "strict-transport-security",         "max-age=31536000; includesubdomains; preload", // 58
        "vary",                              "accept-encoding",                      // 59
        "vary",                              "origin",                               // 60
        "x-content-type-options",            "nosniff",                              // 61
        "x-xss-protection",                  "1; mode=block",                        // 62
        ":status",                           "100",                                  // 63
        ":status",                           "204",                                  // 64
        ":status",                           "206",                                  // 65
        ":status",                           "302",                                  // 66
        ":status",                           "400",                                  // 67
        ":status",                           "403",                                  // 68
        ":status",                           "421",                                  // 69
        ":status",                           "425",                                  // 70
        ":status",                           "500",                                  // 71
        "accept-language",                   "",                                     // 72
        "access-control-allow-credentials",  "FALSE",                                // 73
        "access-control-allow-credentials",  "TRUE",                                 // 74
        "access-control-allow-headers",      "*",                                    // 75
        "access-control-allow-methods",      "get",                                  // 76
        "access-control-allow-methods",      "get, post, options",                   // 77
        "access-control-allow-methods",      "options",                              // 78
        "access-control-expose-headers",     "content-length",                       // 79
        "access-control-request-headers",    "content-type",                         // 80
        "access-control-request-method",     "get",                                  // 81
        "access-control-request-method",     "post",                                 // 82
        "alt-svc",                           "clear",                                // 83
        "authorization",                     "",                                     // 84
        "content-security-policy",           "script-src 'none'; object-src 'none'; base-uri 'none'", // 85
        "early-data",                        "1",                                    // 86
        "expect-ct",                         "",                                     // 87
        "forwarded",                         "",                                     // 88
        "if-range",                          "",                                     // 89
        "origin",                            "",                                     // 90
        "purpose",                           "prefetch",                             // 91
        "server",                            "",                                     // 92
        "timing-allow-origin",               "*",                                    // 93
        "upgrade-insecure-requests",         "1",                                    // 94
        "user-agent",                        "",                                     // 95
        "x-forwarded-for",                   "",                                     // 96
        "x-frame-options",                   "deny",                                 // 97
        "x-frame-options",                   "sameorigin",                           // 98
    ];

    // The same rows as octets. Built once from `Table` rather than kept alongside it, so
    // there is exactly one place a row can be wrong. Every name and value in Appendix A is
    // printable ASCII; the test asserts that over the capture rather than trusting it here.
    private static readonly byte[][] Octets = BuildOctets();

    // Derived, not asserted. If a row were dropped or duplicated in `Table` this moves, and
    // the capture-driven test catches it.
    internal static int Count => Table.Length / 2;

    // The name at `index`, as it appears in Appendix A.
    internal static string NameAt(int index) => Table[index * 2];

    // The value at `index`. EMPTY for the 21 rows Appendix A leaves blank - empty, not null,
    // because those rows have a value and it is the empty string.
    internal static string ValueAt(int index) => Table[(index * 2) + 1];

    // The lookup a decoder does. `false` for an index at or past `Count` - RFC 9204 s3.1
    // gives the table 99 entries and nothing resolves an index beyond them - and it does not
    // throw, because `index` arrives off the wire.
    internal static bool TryLookup(int index, out ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value)
    {
        if ((uint)index >= (uint)Count)
        {
            name = default;
            value = default;
            return false;
        }

        name = Octets[index * 2];
        value = Octets[(index * 2) + 1];
        return true;
    }

    // A full match on BOTH name and value, which is what RFC 9204 s4.5.2's indexed field
    // line needs. Distinct from TryFindName on purpose; see the header.
    //
    // Lowest matching index wins. Appendix A: "The order of the entries is optimized to
    // encode the most common header fields with the smallest number of bytes", so the first
    // match is also the cheapest to encode.
    internal static bool TryFindNameAndValue(
        ReadOnlySpan<byte> name,
        ReadOnlySpan<byte> value,
        out int index)
    {
        for (int i = 0; i < Count; i++)
        {
            if (name.SequenceEqual(Octets[i * 2]) && value.SequenceEqual(Octets[(i * 2) + 1]))
            {
                index = i;
                return true;
            }
        }

        index = -1;
        return false;
    }

    // A match on the NAME ALONE, which is what RFC 9204 s4.5.4's literal with name reference
    // needs. It ignores the value column entirely, so `:status` matches at row 24 whatever
    // the value is - that is the point of the representation.
    internal static bool TryFindName(ReadOnlySpan<byte> name, out int index)
    {
        for (int i = 0; i < Count; i++)
        {
            if (name.SequenceEqual(Octets[i * 2]))
            {
                index = i;
                return true;
            }
        }

        index = -1;
        return false;
    }

    // ponytail: a linear scan over 99 rows, twice per field line at worst. A request carries
    // on the order of ten fields, so this is ~2000 span compares per request against a
    // network round trip; a lookup structure would be more code than it saves. Index it if a
    // profile ever says otherwise.
    private static byte[][] BuildOctets()
    {
        byte[][] octets = new byte[Table.Length][];
        for (int i = 0; i < Table.Length; i++)
        {
            octets[i] = System.Text.Encoding.ASCII.GetBytes(Table[i]);
        }

        return octets;
    }
}
