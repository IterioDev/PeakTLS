# PeakTLS

Managed C# HTTPS with control over every fingerprinted byte: the TLS ClientHello, HTTP/2
SETTINGS and preface, QUIC transport parameters, HTTP/3 SETTINGS, and QPACK. No
`SslStream`, no `System.Net.Quic` or MsQuic, no native TLS library, no P/Invoke.

This repository holds two projects that ship as two NuGet packages:

| Project | What it is |
|---|---|
| [SharpTls](SharpTls/) | The engine. TLS 1.3 client and server with byte-exact ClientHello control, and a QUIC v1 + HTTP/3 stack with QPACK, DATAGRAM frames, extended CONNECT, and SOCKS5 and MASQUE datagram transports. It has no HTTP client. |
| [TlsClient](TlsClient-main/) | The `HttpClient`-shaped session layer on top: HTTP/1.1, HTTP/2, and HTTP/3; presets; pooling; redirects; retries; HTTP CONNECT, SOCKS5, and MASQUE proxies; streaming; telemetry. It has no TLS of its own; every byte goes through SharpTls. |

You reference TlsClient only. SharpTls comes with it.

```text
Your application
      │
      ▼
  TlsSession ── redirects · retries · proxies · pooling · telemetry
      │
      ├── HTTP/1.1 ────┐
      ├── HTTP/2 ──────┴── SharpTls TLS 1.3 ── TCP: direct · HTTP CONNECT · SOCKS5
      │   + HPACK
      │
      └── HTTP/3 ───────── SharpTls QUIC ───── UDP: direct · SOCKS5 UDP ASSOCIATE
          + QPACK            + TLS 1.3             · MASQUE CONNECT-UDP
```

## Status

- Preview. Public APIs may change before 1.0. Certificate validation is on by default and
  is never relaxed by a fingerprint choice.
- TLS 1.3 only. The TLS 1.2 stack was removed; a ServerHello selecting 1.2 is refused
  rather than downgraded to.
- HTTP/3 works and is behind an explicit experimental opt-in (`TLSCLIENT3`).
- The QUIC and HTTP/3 types in SharpTls are internal for now and reached through TlsClient.
- The last published packages (`TlsClient 0.6.0-preview.1`, `SharpTls 0.9.0-preview.5`)
  predate HTTP/3, the QUIC options, and MASQUE. Build from source for those.

## Repository layout

| Path | Contents |
|---|---|
| `SharpTls/src/SharpTls/` | The engine: `ClientHello/`, `Handshake/`, `Records/`, `Certificates/`, `Ech/`, `Dns/`, `Quic/` (QUIC, HTTP/3, QPACK, datagram transports) |
| `SharpTls/docs/` | Protocol documentation: ClientHello specs, fingerprint knobs, QUIC-TLS, SOCKS5 and MASQUE transports, RFC conformance |
| `SharpTls/tests/`, `SharpTls/tools/` | Tests, fuzzers, API compatibility and reproducibility tools |
| `TlsClient-main/src/TlsClient/` | The session layer |
| `TlsClient-main/docs/` | Usage guide, presets, streaming, connectivity, retries, certificates, diagnostics |
| `TlsClient-main/samples/` | `TlsClient.QuickStart` and `TlsClient.SpotifyIos26` |
| `TlsClient-main/tests/` | Unit, loopback, and opt-in live tests |

## Packages

**TlsClient** is the HTTP client. It owns requests, responses, cookies, redirects, proxies,
decompression, pooling, streaming, and retries, and delegates certificate validation, TLS
state, the ClientHello, and QUIC to SharpTls. Start here unless you are building your own
protocol layer.

```shell
dotnet add package TlsClient --prerelease
```

**SharpTls** is the engine. It implements TLS 1.3 directly over a caller-owned `Socket`,
`NetworkStream`, or `Stream`, with a byte-exact ClientHello, RFC 9849 ECH, X25519MLKEM768,
resumption, 0-RTT, KeyUpdate, exporters, and a server engine. Use it directly when you
bring your own transport:

```shell
dotnet add package SharpTls --prerelease
```

```csharp
using SharpTls;

var options = new CustomTlsClientOptions
{
    ServerName = "example.com",
    ClientHello = ClientHelloProfiles.Custom(builder => builder
        .WithTls13()
        .WithAlpn("http/1.1")),
};

await using var client = new CustomTlsClient(options);
await client.ConnectAsync("example.com", 443);
await using var tls = client.OpenApplicationStream(leaveClientOpen: true);
```

## Build and test

`TlsClient-main/src/TlsClient/TlsClient.csproj` references `SharpTls/src/SharpTls/SharpTls.csproj`
by `ProjectReference`, so the two directories must stay siblings. Reference TlsClient from
your project:

```xml
<ProjectReference Include="..\PeakTLS\TlsClient-main\src\TlsClient\TlsClient.csproj" />
```

```shell
dotnet restore TlsClient-main/TlsClient.slnx -m:1
dotnet build TlsClient-main/TlsClient.slnx -c Release --no-restore
dotnet test  TlsClient-main/TlsClient.slnx -c Release --no-build

dotnet restore SharpTls/SharpTls.slnx
dotnet test    SharpTls/SharpTls.slnx -c Release
```

`-m:1` on restore avoids an intermittent parallel-restore failure (`Value cannot be null.
(Parameter 'path1')`).

## Quick start

```csharp
using TlsClient;

await using var session = new TlsSession();

var response = await session.GetAsync("https://example.com/");
response.EnsureSuccessStatusCode();

Console.WriteLine($"HTTP/{response.HttpVersion} {(int)response.StatusCode}");
Console.WriteLine($"{response.Tls.ProtocolVersion} / {response.Tls.CipherSuite} / {response.Tls.ApplicationProtocol}");
Console.WriteLine(response.Text);
```

The default session uses `TlsProfiles.Modern`, SharpTls's conservative TLS 1.3 shape, which
negotiates rather than imitates, and prefers HTTP/2. The same request with a captured
client's full HTTP/3 shape:

```csharp
using TlsClient;

await using var session = new TlsSession(TlsPresets.Spotify);   // Http3Only

using var request = new HttpRequestMessage(HttpMethod.Get, "https://fp.impersonate.pro/api/http3");
request.AddHeader("accept", "*/*");
request.AddHeader("user-agent", "Spotify/9.1.86 iOS/27.0 (iPhone17,2)");

var response = await session.SendAsync(request);
Console.WriteLine(response.HttpVersion);             // 3.0
Console.WriteLine(response.Tls.ApplicationProtocol); // h3
```

`fp.impersonate.pro/api/http3` reports the HTTP/3 SETTINGS, pseudo-header order, and QUIC
transport parameters in wire order, which makes it a direct check of what you sent.

## Presets and profiles

A preset moves the TLS ClientHello, the HTTP version policy, and the HTTP/2 or QUIC and
HTTP/3 shape as one unit. The catalogue is first-party captures of one client:

| Preset | Name | Policy | Shape |
|---|---|---|---|
| `TlsPresets.Spotify` = `Spotify918602428IOS270Http3` | `spotify-9.1.86-ios-27.0-h3` | `Http3Only` | Spotify 9.1.86.2428 on iOS 27.0: QUIC ClientHello, rotating transport parameters, HTTP/3 SETTINGS, QPACK dynamic table |
| `TlsPresets.SpotifyH2` = `Spotify918602428IOS270Http2` | `spotify-9.1.86-ios-27.0-h2` | `PreferHttp2` | The same build's TCP ClientHello and HTTP/2 shape |
| `TlsPresets.Spotify917602050IOS260Http3` | `spotify-9.1.76-ios-26.0-h3` | `Http3Only` | Spotify 9.1.76.2050 on iOS 26: the older OS build's QUIC image |

The profiles behind them are in `TlsProfiles.All`: `Modern` (`modern-tls13`, the default),
`Spotify918602428IOS270Tcp` (`spotify-9.1.86-ios-27.0-tcp`), `Spotify918602428IOS270Quic`
(`spotify-9.1.86-ios-27.0-quic`), and `Spotify917602050IOS260Quic`. The uTLS browser
catalogue, profile randomization, and the Roller were removed: a transcription of someone
else's capture ages silently, and a generated hello can be coherent and still match no real
client. Anything else you want to look like is a capture you supply.

`CreateOptions()` returns an independent copy to customize:

```csharp
var options = TlsPresets.SpotifyH2.CreateOptions();
options.Proxy = TlsProxy.Http("http://127.0.0.1:8080");
options.Timeout = TimeSpan.FromSeconds(15);

await using var session = new TlsSession(options);
```

The HTTP/3 presets draw three values per connection because the captured handset does: the
transport-parameter rotation offset, the reserved HTTP/3 SETTINGS identifier, and GREASE.
Each is an ordinary knob and can be pinned, at the cost of no longer matching the capture.
Measured values and what remains unmeasured are in
[TlsClient-main/docs/PRESETS.md](TlsClient-main/docs/PRESETS.md).

## Headers are yours

A field reaches the wire if and only if `request.AddHeader(name, value)` added it, in the
order it was added. There is no session default, no header-order setting, and no preset
supplies a field, not even `User-Agent`. `request.Headers` and `request.Content.Headers` are
not read.

```csharp
using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/api")
{
    Content = new ByteArrayContent(payload),
};
request.AddHeader("content-type", "application/x-protobuf");
request.AddHeader("accept", "*/*");
request.AddHeader("content-length", "-1");   // the slot; the value is always computed
request.AddHeader("user-agent", "my-agent/1.0");
```

Nothing is synthesised. Add `Host` yourself over HTTP/1.1 (HTTP/2 and HTTP/3 carry the
authority as `:authority`). The session records `Set-Cookie` but never sends a `Cookie`. A
request with a body must add `Content-Length` or `Transfer-Encoding` or the send throws; the
name decides the framing and the position is where it lands. Values are sent verbatim.

## Fingerprint control

**TLS ClientHello.** `ClientHelloProfiles.Custom` sets cipher suites, groups, key shares,
signature algorithms, ALPN, GREASE, padding, record fragmentation, and the exact extension
layout, with `Raw(id, bytes)` for extensions SharpTls has no semantic kind for. A capture that
repeats a signature algorithm needs `AllowDuplicateSignatureAlgorithms(true)`; without it JA3
still matches and JA4 does not.

```csharp
using SharpTls;
using SharpTls.Protocol;
using TlsClient;

var profile = TlsProfile.Create("captured", ClientHelloProfiles.Custom(builder => builder
    .WithTls13()
    .WithCipherSuites(
        TlsCipherSuite.TlsAes128GcmSha256,
        TlsCipherSuite.TlsAes256GcmSha384,
        TlsCipherSuite.TlsChaCha20Poly1305Sha256)
    .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1)
    .WithKeyShares(NamedGroup.X25519)
    .WithAlpn("h2", "http/1.1")));

var options = new TlsSessionOptions { Profile = profile };
```

`TlsClientHello.ImportCapture` turns captured ClientHello bytes into a profile,
`TlsClientHello.ExportJson` and `ImportJson` round-trip it, and
`TlsFingerprintDiagnostics.InspectHandshake` computes GREASE-aware JA3 and JA4.
`TlsClientHello.Observe` shows the exact wire image before it is sent.

**HTTP/2.** `options.Http2.Preface` is the ordered frame list written after the connection
preface, with raw `ushort` setting identifiers so unknown, duplicate, and GREASE values are
expressible; `options.Http2.PseudoHeaderOrder` is written as given.

```csharp
options.Http2.Preface =
[
    new TlsHttp2SettingsFrame { Settings = [new(0x1, 65_536), new(0x4, 6_291_456)] },
    new TlsHttp2WindowUpdateFrame { Increment = 15_663_105 },
];
options.Http2.PseudoHeaderOrder = [":method", ":authority", ":scheme", ":path"];
```

**QUIC.** `options.Quic.TransportParameters.Entries` is an ordered slot list, because wire
order is fingerprinted: `Literal` slots carry your bytes, `Placed` slots take a value the
connection derives, and `Drawn` slots are redrawn per connection. Connection-ID lengths,
Initial padding, the Initial CRYPTO split, varint widths, flow control, and loss recovery
are all settable. `options.Quic.ConfigureClientHello` builds the h3 ClientHello;
`options.Profile` does not, because RFC 9001 §8.4 forbids extensions a TCP profile carries.

**HTTP/3 and QPACK.** `options.Http3.Settings` is an ordered list, and
`PseudoHeaderOrder`, `UnidirectionalStreamOpenOrder`, the QPACK Huffman and name-match
policies, and the dynamic table (`QpackEncoderDynamicTableCapacity`, `QpackInsertPolicy`,
`UnidirectionalStreamOpening`) are all settable. The Spotify presets set the dynamic table
to what the phone does.

[SharpTls/docs/FINGERPRINT-KNOBS.md](SharpTls/docs/FINGERPRINT-KNOBS.md) catalogues every
knob, its default, what it changes on the wire, and which values are unverified.

## HTTP/3

`TlsHttpVersionPolicy.Http3Only` carries `[Experimental("TLSCLIENT3")]`, so naming it is a
compile error until you suppress the diagnostic deliberately. A preset that pins it needs no
suppression. There is no `PreferHttp3`: without a race it could only mean "try QUIC, then
retry over TCP", a silent downgrade. `Http3Only` means h3 or an error.

The default QUIC transport-parameter list is `initial_source_connection_id` alone, which
advertises no flow control, so the server cannot open its control stream and a plain default
h3 session idles out after a completed handshake. Start from a preset, or set
`Quic.FlowControl` and add a `TlsQuicTransportParameterEntry.Placed(id)` slot for each of
the six flow-control parameters (`0x04` to `0x09`). The MASQUE outer connection sets these
itself.

A handshake that reaches its deadline says why: the message lists the discard reasons and
ends with the first discarded packet in hex. The limits you will hit (body buffering, pool
accounting, what is still absent over h3) are in
[TlsClient-main/docs/USAGE.md §6](TlsClient-main/docs/USAGE.md).

## Proxies

TCP and QUIC have separate, independent proxy slots:

| Proxy | Slot | HTTP/1.1 and HTTP/2 | HTTP/3 |
|---|---|---|---|
| `TlsProxy.Http(...)` | `options.Proxy` | CONNECT tunnel | `NotSupportedException` before any dial: CONNECT carries a byte stream, not datagrams |
| `TlsProxy.Socks5(...)` | `options.Proxy` | CONNECT command, hostname sent to the proxy | UDP ASSOCIATE, where the proxy really relays UDP |
| `TlsProxy.Masque(...)` | `options.Quic.Proxy` | Refused by name | RFC 9298 CONNECT-UDP over HTTP/3 |

Many residential SOCKS5 proxies accept UDP ASSOCIATE and then write the payload into a TCP
connection to the destination. QUIC cannot cross them: the TLS server there answers the
first Initial with a TLS alert, and the dial fails at once with
`TlsQuicProxyError.RelayDeliveredTlsAlert`. Use h2 through such a proxy, or MASQUE. The same
thing happens behind some residential exits of a MASQUE proxy: the tunnel opens, the inner
Initial goes in, and a 7-byte TLS alert comes back. That is the same error, named at once
without the tunnel retries, and only a different proxy session (a different exit) helps. Over a
real SOCKS5 relay, h3 origin DNS still resolves on this host.

SOCKS5 supports no-auth and RFC 1929 username/password, and accepts an authentication reply
carrying VER `0x05` instead of `0x01`. HTTP CONNECT credentials are sent only to the proxy.
SOCKS4 was removed. `TlsRequestOptions.For(request).Proxy` overrides the session proxy for
one request.

With both slots set, h3 goes through MASQUE and h1/h2 through the TCP proxy:

```csharp
options.Proxy = TlsProxy.Socks5("socks5://proxy.example:1080", user, pass);         // h1, h2
options.Quic.Proxy = TlsProxy.Masque("https://masque.example:50000", user, pass);   // h3
```

When both carry the same username (one sticky session on the provider's side), the session is
bound through MASQUE before its first TCP proxy connect: one tunnel to the origin opens and
closes, about a second, once per session, reported as `MasqueSessionBound`. Measured against
Oxylabs residential proxies, a session first used through the SOCKS5 front lands on an exit that
cannot carry UDP and every later MASQUE tunnel dies with a TCP TLS alert, 10 sessions of 10; one
first used through MASQUE carries h3 and then h2 over SOCKS5 on the same exit IP, 8 of 8.
`options.Quic.BindSessionThroughMasque = false` turns the binding off. The outer connection the
binding dials is the one the session's h3 dials then share, so the binding costs no extra
handshake.

### MASQUE

```csharp
using SharpTls.Quic;
using TlsClient;

var options = TlsPresets.Spotify.CreateOptions();
options.Quic.Proxy = TlsProxy.Masque("https://masque.example:50000", "user", "pass");
await using var session = new TlsSession(options);

using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
request.AddHeader("accept", "*/*");
try
{
    var response = await session.SendAsync(request);
    Console.WriteLine($"{response.HttpVersion} {(int)response.StatusCode}");
}
catch (Exception e) when (ProxyFailure(e) is { } proxy)
{
    Console.WriteLine(proxy.Error switch
    {
        TlsQuicProxyError.MasqueAuthenticationRejected => "407: credentials or traffic limit",
        TlsQuicProxyError.MasqueTargetRejected => "400: the proxy refused this host and port",
        TlsQuicProxyError.MasqueNotOffered => "the proxy does not offer CONNECT-UDP",
        _ => proxy.Message,   // MasqueTunnelRefused names the dial stage
    });
}

static TlsQuicProxyException? ProxyFailure(Exception? e) =>
    e as TlsQuicProxyException ?? (e is null ? null : ProxyFailure(e.InnerException));
```

`TlsProxy.Masque(address, username, password, configureOuter)` takes an `https://` address with
an explicit UDP port other than 443. The session keeps a pool of outer QUIC connections to the
proxy per proxy session (per username). Each h3 connection is one CONNECT-UDP request stream on
an outer that has room, opened with `:protocol: connect-udp` and Basic `proxy-authorization`,
and every inner datagram travels in an HTTP/3 DATAGRAM routed by that stream's quarter stream id
(RFC 9297). An outer carries one live tunnel at a time by default
(`Quic.MasqueTunnelsPerConnection`), and an outer whose tunnel has ended is reused by the next
dial: concurrent h3 connections do not share a congestion window or queue behind each other's
traffic, and sequential ones still skip the outer handshake. A new outer is reported as
`MasqueConnectionOpened`, each tunnel as `MasqueTunnelOpened`. An outer that has ended (idle
timeout, proxy close, failure) is dropped and replaced. Disposing an inner connection ends its
own request stream and nothing else; disposing the `TlsSession` closes the outer connections.

The proxy name is resolved through the session's `DnsResolver` when it has one, and one lookup
serves every outer dial in the process for `DnsRefreshInterval`: a provider's front publishes its
addresses for seconds, so without that every dial pays a lookup inside its own deadline.
Consecutive dials lead with different addresses of the answer and each falls through the rest.

An inner handshake that runs out of `Quic.HandshakeDeadline` while traffic is coming back through
the tunnel is dialled again on a fresh tunnel, up to `Quic.MaximumAssociationAttempts` in all;
nothing of the request has been sent at that point, so this holds for every method. A handshake
deadline's message says how far the attempt got (`PROGRESS:` datagrams each way, whether TLS
finished, what loss recovery sent) and what crossed the tunnel, with the last sizes each way.

The inner connection, the one the origin sees, is unchanged: preset, transport parameters and
their rotation, QPACK, packet sizes. Only the proxy sees the outer connection, so its shape is
the RFC minimum rather than a persona's; the optional `configureOuter` hook receives its
`TlsQuicOptions` last. Inner datagrams are capped at the tunnel's ceiling: the outer path MTU
is fixed at 1392 with PMTUD off, which leaves about 1,360 bytes of frame budget per inner
datagram, and the `maxInnerDatagramPayload` argument (default 1,352, the Oxylabs guide's
number for inner packets) caps it further. The inner connection takes that ceiling from the
transport.

Failures are named on `TlsQuicProxyException.Error`, usually found as an inner exception:

| Error | Meaning |
|---|---|
| `MasqueNotOffered` | The proxy's SETTINGS or transport parameters lack extended CONNECT, HTTP/3 datagrams, or room for a 1200-byte QUIC Initial |
| `MasqueAuthenticationRejected` | 407: credentials refused or the account's traffic limit reached |
| `MasqueTargetRejected` | 400: the proxy refused the target host and port |
| `MasqueTunnelRefused` | Any other non-2xx status, or no outer connection or no tunnel within the deadline; the message names the dial stage and the proxy addresses that never answered |
| `MasqueTunnelClosed` | The tunnel stream or outer connection ended; mid-life it surfaces on the next request and is retried like any transient h3 failure. A tunnel the proxy ends during the inner handshake is dialled again by itself, up to `Quic.MaximumAssociationAttempts` tunnels. The message says how long the tunnel lived, how many datagrams crossed it each way, and what the proxy wrote on the stream before ending it; "sent into it and 0 received back" on every attempt is a residential exit that cannot carry UDP, and only a fresh proxy session helps |
| `MasqueExitSilent` | The tunnel opened and stayed open, inner datagrams went in, and nothing came back within the inner handshake deadline while the outer connection stayed alive: the exit behind this proxy session does not carry UDP to the target. Remembered for the session, like `RelayDeliveredTlsAlert` and an all-silent `MasqueTunnelClosed`: every later h3 dial on the same username fails at once with the same error and a message saying how long ago it was proved, until the session id changes. The TCP path on that session is untouched |

Verified live against Oxylabs (`masque.oxylabs.io:50000`): the tunnel comes up in under a
second and Google-hosted targets answer.
[SharpTls/docs/MASQUE-DATAGRAM-TRANSPORT.md](SharpTls/docs/MASQUE-DATAGRAM-TRANSPORT.md)
describes the dial, the framing, backpressure (delay, never drop), and the MTU arithmetic.

## Telemetry and diagnostics

`options.ConnectObserver` receives a `TlsConnectEvent` (connection ID, kind, host, port,
address, elapsed time, ALPN, exception) for every connect stage:

```csharp
options.ConnectObserver = e => Console.WriteLine(
    $"{e.ConnectionId} {e.Kind} {e.Host}:{e.Port} {e.Elapsed} {e.Exception?.Message}");
```

| Stage | `TlsConnectEventKind` |
|---|---|
| DNS | `DnsCacheHit`, `DnsResolutionStarted`, `DnsResolutionCompleted`, `DnsResolutionFailed` |
| TCP | `TcpAttemptStarted`, `TcpAttemptFailed`, `TcpConnected` |
| TCP proxy | `ProxyTunnelStarted`, `ProxyTunnelCompleted`, `ProxyTunnelFailed` |
| TLS | `TlsHandshakeStarted`, `TlsHandshakeCompleted`, `TlsHandshakeFailed` |
| SOCKS5 UDP | `Socks5AssociationGateEntered`, `Socks5AssociationRetried`, `Socks5AssociationFirstRequest`, `Socks5AssociationWentSilent` |
| MASQUE | `MasqueConnectionOpened` (a new outer connection to the proxy), `MasqueSessionBound` (the MASQUE-first binding, once per session), `MasqueTunnelOpened` (the proxy answered 2xx), `MasqueTunnelClosed` (a dial through the tunnel failed) |

`options.HandshakeObserver` reports secret-free SharpTls handshake events.
`TlsDiagnostics.ActivitySourceName` (`"TlsClient"`) exposes request attempts, connections, and
handshake metadata to `ActivityListener` and OpenTelemetry; header values, bodies,
certificates, and secrets are never recorded.

## Session features

- Pooling with per-origin and global limits; HTTP/2 and HTTP/3 multiplex. Cached DNS and
  IPv6/IPv4 Happy Eyeballs on TCP.
- Redirects (301, 302, 303, 307, 308) with Authorization and caller-supplied Cookie stripped
  on origin change.
- Explicit bounded retries by idempotency, replayability, status codes, and Retry-After;
  per-attempt policy hooks for caller-owned rate limiting and circuit breaking.
- Bounded streaming uploads and downloads, trailers, `Expect: 100-continue`, and gzip,
  deflate, and Brotli decompression with post-decompression limits.
- Certificate chain and hostname validation by default, SPKI pins, client certificates, ECH
  with HTTPS/SVCB discovery, and encrypted TLS 1.3 session-ticket export and import.

[TlsClient-main/docs/USAGE.md](TlsClient-main/docs/USAGE.md) names every `TlsSessionOptions`
member with its real default.

## Live tests

Live tests are opt-in and read their target from the environment. A live test returns rather
than skips when its variable is unset, so a green run without it proves nothing about the
network. Use placeholders in scripts; never commit a credential.

| Variable | Enables |
|---|---|
| `TLSCLIENT_LIVE_TESTS=1` | TlsClient HTTP/3 and interop tests against public endpoints |
| `TLSCLIENT_LIVE_SOCKS5=socks5://user:pass@host:port` | The SOCKS5 relay probe |
| `TLSCLIENT_LIVE_MASQUE=https://user:pass@host:port` | `MasqueLiveTests` |
| `SHARPTLS_RUN_INTEROP=1` | SharpTls public-server interoperability tests |

```shell
TLSCLIENT_LIVE_MASQUE='https://user:pass@masque.oxylabs.io:50000' \
  dotnet test TlsClient-main/tests/TlsClient.Tests --filter "FullyQualifiedName~MasqueLiveTests"
```

## Documentation

| Topic | Read |
|---|---|
| Every session option, HTTP/3 and QUIC tuning, the Spotify preset, h3 limits, reproducing a capture | [TlsClient-main/docs/USAGE.md](TlsClient-main/docs/USAGE.md) |
| Presets and what was measured | [TlsClient-main/docs/PRESETS.md](TlsClient-main/docs/PRESETS.md) |
| HTTP/3 entry gate | [TlsClient-main/docs/HTTP3-EVALUATION.md](TlsClient-main/docs/HTTP3-EVALUATION.md) |
| Streaming, connectivity, retries, certificates, diagnostics | [TlsClient-main/docs/](TlsClient-main/docs/) |
| Every fingerprint knob and its default | [SharpTls/docs/FINGERPRINT-KNOBS.md](SharpTls/docs/FINGERPRINT-KNOBS.md) |
| MASQUE CONNECT-UDP transport | [SharpTls/docs/MASQUE-DATAGRAM-TRANSPORT.md](SharpTls/docs/MASQUE-DATAGRAM-TRANSPORT.md) |
| SOCKS5 UDP transport | [SharpTls/docs/SOCKS5-DATAGRAM-TRANSPORT.md](SharpTls/docs/SOCKS5-DATAGRAM-TRANSPORT.md) |
| RFC MUST conformance audit | [SharpTls/docs/RFC-CONFORMANCE.md](SharpTls/docs/RFC-CONFORMANCE.md) |
| ClientHello specifications and capture import | [SharpTls/docs/CLIENTHELLO-SPECS.md](SharpTls/docs/CLIENTHELLO-SPECS.md), [SharpTls/docs/CLIENTHELLO-IMPORT.md](SharpTls/docs/CLIENTHELLO-IMPORT.md) |
| QUIC-TLS adapter | [SharpTls/docs/QUIC-TLS.md](SharpTls/docs/QUIC-TLS.md) |
| Threat model | [SharpTls/docs/THREAT-MODEL.md](SharpTls/docs/THREAT-MODEL.md) |

Release history: [CHANGELOG.md](CHANGELOG.md).

## Security and license

Report vulnerabilities privately, never in a public issue, and never attach live secrets,
private keys, decrypted traffic, or unredacted captures. Both projects are MIT licensed.
