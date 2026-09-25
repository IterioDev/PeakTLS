using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;

[assembly: TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]
[assembly: AssemblyCompany("TlsClient contributors")]
[assembly: AssemblyCopyright("Copyright © 2026 TlsClient contributors")]
[assembly: AssemblyDescription("A pure managed, fingerprintable HTTP client powered by SharpTls.")]
[assembly: AssemblyFileVersion("0.6.0.0")]
[assembly: AssemblyInformationalVersion("0.6.0-preview.1")]
[assembly: AssemblyMetadata("RepositoryUrl", "https://github.com/danikishin/TlsClient")]
[assembly: AssemblyProduct("TlsClient")]
[assembly: AssemblyTitle("TlsClient")]
[assembly: AssemblyVersion("0.6.0.0")]

[assembly: InternalsVisibleTo("TlsClient.Tests")]
[assembly: InternalsVisibleTo("TlsClient.Fuzz")]
[assembly: InternalsVisibleTo("TlsClient.Performance")]
// MobileGen's DealerWebSocket reuses ProxyTunnel (SOCKS5 / HTTP CONNECT) to put the dealer
// websocket on the same exit as the rest of a gen.
[assembly: InternalsVisibleTo("MobileGen")]
