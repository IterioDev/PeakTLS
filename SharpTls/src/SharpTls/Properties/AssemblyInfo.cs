using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SharpTls.Tests")]
[assembly: InternalsVisibleTo("SharpTls.Fuzz")]
[assembly: InternalsVisibleTo("SharpTls.Benchmarks")]
[assembly: InternalsVisibleTo("SharpTls.CoverageFuzz")]

// TlsClient is the HTTP client built on this library and lives in the sibling checkout, wired by
// ProjectReference from TlsClient.csproj. It needs the QUIC and HTTP/3 types - TlsQuicConnection,
// TlsQuicHttp3Connection, TlsQuicHttp3Request and the spec types - to speak h3.
//
// DELIBERATELY InternalsVisibleTo RATHER THAN public. Those types are four commits old and still
// moving; a public surface is a permanent commitment and the user has not yet decided its shape.
// This makes h3 reachable now without freezing an API, and it is one line to reverse. When the
// public surface IS designed, this line should go away rather than sit alongside it.
[assembly: InternalsVisibleTo("TlsClient")]
[assembly: InternalsVisibleTo("TlsClient.Tests")]
