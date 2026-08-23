# Using TlsClient + SharpTls

Every example below was checked against the code at TlsClient `b71d591` / SharpTls `dd61391`.
Nothing here is aspirational — where something does not work yet, it says so.

## How the two projects fit together

**SharpTls** is the TLS/QUIC engine: the ClientHello, the handshake, the record layer, and the
whole QUIC + HTTP/3 stack. It has no HTTP client.

**TlsClient** is the HTTP client: HTTP/1.1, HTTP/2 and HTTP/3, pooling, redirects, cookies,
retries. It has no TLS of its own — every byte goes through SharpTls.

**TLS 1.3 ONLY.** SharpTls negotiates nothing else. The 1.1/1.2 stack — state machine, key
schedule, PRF, AEAD record cipher, the server-flight parsers, both session caches — was removed,
and both directions now fail closed: a ServerHello selecting 1.2 is refused rather than
downgraded to, and the server refuses a ClientHello that does not offer 1.3. There is no path
left that can be talked into the weaker protocol.

`TlsProtocolVersion.Tls10`, `Tls11` and `Tls12` still exist, because they are wire constants
rather than negotiation targets: TLS 1.3 sends `legacy_record_version` 0x0303 on every record and
0x0303 as the ClientHello's `legacy_version`, and the downgrade-sentinel checks compare against
the older values. `ClientHelloBuilder.WithLegacyTls12ClientHello()` also stays — a legacy-shaped
hello can be built, imported, inspected and exported, because that is a *shape* and not a
capability. It just cannot be sent.

Consequences worth knowing before you plan around them: RFC 5929 `tls-unique` is gone from the
public surface (it is derived from the 1.2 Finished messages and TLS 1.3 has no equivalent —
RFC 9266 `tls-exporter` is the successor), and so are `Tls12SessionCache`,
`Tls12ServerSessionCache`, `Tls12ServerSessionTicketProtector` and `Tls12CipherSuites`.

They are wired by `ProjectReference` in `src/TlsClient/TlsClient.csproj`, pointing at the sibling
checkout. **You reference `TlsClient` only.** SharpTls comes with it.

```xml
<ProjectReference Include="..\..\..\TlsClient-main\src\TlsClient\TlsClient.csproj" />
```

---

## 1. The smallest thing that works

```csharp
using TlsClient;

await using var session = new TlsSession();

var response = await session.GetAsync("https://example.com/");
response.EnsureSuccessStatusCode();

Console.WriteLine($"HTTP/{response.HttpVersion} {(int)response.StatusCode} {response.ReasonPhrase}");
Console.WriteLine($"{response.Tls.ProtocolVersion} / {response.Tls.CipherSuite} / {response.Tls.ApplicationProtocol}");
Console.WriteLine(response.Text);
```

That is `samples/TlsClient.QuickStart/Program.cs` verbatim. It negotiates HTTP/2 by default.

---

## 2. Configuring the session

`TlsSessionOptions` is the single configuration surface, and this section names **every**
public member of it — 34 of them — with its real default. It was 36 before `DefaultHeaders` and
`ProfileRoller` were removed, which is the drift this doc keeps warning about, so re-derive it
rather than trusting the number here. A raw line count is wrong — overloads and the constructor
inflate it — so count distinct names:

```
grep -E "^    public " src/TlsClient/TlsSessionOptions.cs   | sed 's/^    public //; s/ *[{=].*//; s/(.*//'   | awk '{print $NF}' | sort -u | grep -v '^TlsSessionOptions$' | wc -l
```
 `ConfigureTls`, `DnsResolver`,
`EchDnsResolver` and `HandshakeObserver` are null unless you set them; the three collections are
get-only, so you add to them rather than assigning.

**Headers are yours, all of them.** There is no `DefaultHeaders` on a session or an options
object, and no preset supplies one either — not even a `User-Agent`. Whatever you put on the
request is exactly what goes on the wire. `options.HeaderOrder` decides only WHERE a field
lands when you send it; set it to `null` and your insertion order is the wire order.

```csharp
using System.Net;
using TlsClient;

var options = new TlsSessionOptions
{
    // THE TCP ClientHello. Two profiles ship: Modern (the default - SharpTls's conservative
    // TLS 1.3 shape, which negotiates honestly and imitates nothing) and
    // Spotify917602050IOS270Quic (a capture, QUIC-shaped, for the h3 preset to name).
    // The browser transcriptions are gone; anything you want to look like is a capture you
    // supply through ClientHelloProfiles.Custom. See §6a.
    Profile = TlsProfiles.Modern,

    // PROTOCOL. PreferHttp2 (default), Http11Only, Http2Only, Http3Only.
    HttpVersionPolicy = TlsHttpVersionPolicy.PreferHttp2,

    Timeout = TimeSpan.FromSeconds(30),
    Expect100ContinueTimeout = TimeSpan.FromSeconds(1),
    FollowRedirects = true,
    MaximumRedirects = 10,
    AutomaticDecompression = true,

    MaximumResponseBodyBytes = 64L * 1024 * 1024,
    MaximumRequestBodyBytes = 64L * 1024 * 1024,
    MaximumResponseHeaderBytes = 64 * 1024,
    MaximumResponseHeaderCount = 200,
    MaximumRequestHeaderBytes = 64 * 1024,

    MaximumConnectionsPerOrigin = 6,
    MaximumPooledConnections = 64,
    PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
    PooledConnectionLifetime = TimeSpan.FromMinutes(10),

    DnsRefreshInterval = TimeSpan.FromMinutes(5),
    MaximumDnsCacheEntries = 256,
    // RFC 8305 v4/v6 address racing on the TCP dial, 0 to 5 s. This is NOT the
    // "try h3, fall back to TCP" sense that section 3 rules out - different layer,
    // different question. Read by HappyEyeballsConnector via SharpTlsTransport.
    HappyEyeballsDelay = TimeSpan.FromMilliseconds(250),

    Proxy = null,
    ConnectObserver = e => Console.WriteLine($"connect: {e}"),
};

// Sub-objects rather than settable properties:
options.Http2.  // TlsHttp2Options - SETTINGS, preface, pseudo-header order, flow control, HPACK
options.Retry.  // TlsRetryOptions
options.Quic.   // TlsQuicOptions - section 3b
options.Http3.  // TlsHttp3Options - section 3a

// Get-only collections. Add to them; you cannot replace them.
options.CertificatePins.     // TlsCertificatePins - SPKI pinning per host
options.ClientCertificates.  // TlsClientCertificates - mutual TLS
options.RequestPolicies.     // IList<ITlsRequestPolicy> - runs per request

// Hooks, all null by default.
options.ConfigureTls = tls => ...;  // CustomTlsClientOptions - the TCP TLS escape hatch
options.DnsResolver = (host, ct) => ...;   // your own resolver
options.EchDnsResolver = ...;              // TlsEchDnsResolver - HTTPS/SVCB for ECH
options.HandshakeObserver = d => ...;      // TlsHandshakeDiagnostic per handshake

// Off by default, and it disables authentication rather than relaxing it. Whatever the
// server presents is accepted, so a machine-in-the-middle is indistinguishable from the
// real peer. Use CertificatePins for a private CA instead.
options.DangerouslySkipServerCertificateValidation = false;

await using var session = new TlsSession(options);
```

`new TlsSession()`, `new TlsSession(TlsPreset)` and `new TlsSession(TlsSessionOptions)` are the
three constructors.

---

## 2a. A SOCKS5 proxy for the whole session

`options.Proxy` is set once and applies to every request the session makes, for its whole life.
There is no per-session "enable proxy" call and no way to lose it midway.

```csharp
using TlsClient;

var options = new TlsSessionOptions
{
    Profile = TlsProfiles.Modern,
    Proxy = TlsProxy.Socks5("socks5://proxy.example.net:1080", "username", "password"),
};

await using var session = new TlsSession(options);

// Every request from here on goes through the proxy.
var a = await session.GetAsync("https://example.com/");
var b = await session.GetAsync("https://other.example/");
```

The address is a URI. The scheme may be `socks5://` or omitted; the port defaults to **1080**
when absent. Credentials travel as RFC 1929 username/password. The other factories are
`TlsProxy.Socks5(address)` with no auth and `TlsProxy.Http(address[, username, password])`.

**SOCKS4 is gone**, factories and all, and `TlsProxyType` keeps a hole at 1 where it was rather
than sliding `Socks5` down into it — a renumbered enum changes the meaning of every persisted
integer silently, which is worse than a gap.

Connections are pooled per `(host, port, proxy, version policy)`, so two sessions with different
proxies never share a socket.

### With HTTP/3 it must be SOCKS5

This is the part that matters if you came here from §3c. **SOCKS5 carries HTTP/3; the other two
proxy types cannot, and say so.** That is a property of the protocols and not a preference:

| Type | Over h3 | Why |
| --- | --- | --- |
| `TlsProxy.Socks5` | **Works** | RFC 1928 §7 `UDP ASSOCIATE` relays datagrams, which is exactly what QUIC needs. With or without RFC 1929 username/password. |
| `TlsProxy.Http` | `NotSupportedException` | CONNECT tunnels a TCP byte stream. RFC 9298's CONNECT-UDP would change this, but the proxy has to implement it and this client does not speak it. |

```csharp
using TlsClient;

// SOCKS5 with RFC 1929 username/password, set once for the life of the session.
var options = TlsPresets.Spotify.CreateOptions();   // Http3Only, so this MUST be SOCKS5
options.Proxy = TlsProxy.Socks5("socks5://proxy.example.net:1080", "user", "pass");
await using var session = new TlsSession(options);

// Every request this session makes goes through the relay. There is no per-request opt-in and
// no way to lose it midway. The destination is sent as a DOMAINNAME (ATYP 0x03), so the name
// resolves at the egress rather than here.
var response = await session.GetAsync("https://fp.impersonate.pro/api/http3");
Console.WriteLine($"{response.HttpVersion} {(int)response.StatusCode}");
```

The refusal for the other two names the type, and it arrives **before** any dial — never as a
silent fallback to TCP, which is the downgrade this library refuses to make anywhere:

```
NotSupportedException: HTTP/3 cannot be tunnelled through a Http proxy: QUIC is UDP and only
SOCKS5 relays datagrams, through RFC 1928 UDP ASSOCIATE. Use a SOCKS5 proxy for HTTP/3, a TCP
version policy for this one, or clear the proxy.
```

**Two things a SOCKS5 relay does not do for you.**

**DNS stays local.** The proxy carries the datagrams; this host still resolves the origin,
because `ITlsQuicDatagramTransport.SendAsync` takes an `IPEndPoint` and RFC 1928's domain-name
address type never gets a chance to be used. Your resolver sees the query and answers it from
here, not from the proxy's vantage point — which can select a different server. If you are
proxying to hide where you are, point `options.DnsResolver` somewhere that does not undo it.

**The datagram ceiling drops.** SOCKS5 prepends a header to every relayed datagram, so the QUIC
payload that fits shrinks by that much. It is handled — `MaxDatagramPayloadSize` accounts for it
and QUIC's path MTU discovery works below it — but a path that barely carried 1200 bytes
directly has less room through a relay.

Under the hood this is SharpTls's `TlsQuicSocks5Transport`, an `ITlsQuicDatagramTransport` over
a UDP association; the SharpTls repo's `docs/SOCKS5-DATAGRAM-TRANSPORT.md` covers the protocol
side. `Http3Connection` picks the relay or the direct UDP transport from `options.Proxy` — the
only thing a proxy changes on the h3 path, since everything above the transport is identical
either way.

### One option that cannot be combined with a proxy

`EchDnsResolver` — ECH bootstrap over DNS — throws `InvalidOperationException` from
`Snapshot()`, i.e. when the session is constructed. Its resolution completes before the origin
ClientHello and runs from this host, which a proxy route cannot carry.

`ProfileRoller` used to be the other half of this list. It was removed entirely: it existed to
try several ClientHellos against an origin until one was accepted, and with the browser
catalogue gone there is nothing left to roll between.

### Overriding it for one request

The session proxy stays in force unless a request opts out. `TlsRequestOptions.Proxy` overrides
it for that request only, and `UseSessionProxy()` puts it back:

```csharp
var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
TlsRequestOptions.For(request).Proxy = null;   // this one request goes direct
```

Setting `Proxy = null` there is a real override, not "unset" — it sends that request without a
proxy while the session keeps its own.

---

## 3. HTTP/3 — works today, and is deliberately awkward to opt into

`Http3Only` carries `[Experimental("TLSCLIENT3")]`. With `TreatWarningsAsErrors` on, which this
repo sets, **that is a compile error until you suppress it deliberately**. It is meant to be a
speed bump; read §6 before removing it.

```csharp
#pragma warning disable TLSCLIENT3

using TlsClient;

var options = new TlsSessionOptions
{
    HttpVersionPolicy = TlsHttpVersionPolicy.Http3Only,
    Timeout = TimeSpan.FromSeconds(30),
};

await using var session = new TlsSession(options);

var response = await session.GetAsync("https://fp.impersonate.pro/api/http3");
response.EnsureSuccessStatusCode();

Console.WriteLine(response.HttpVersion);              // 3.0
Console.WriteLine(response.Tls.ApplicationProtocol);  // h3
Console.WriteLine(response.Text);

#pragma warning restore TLSCLIENT3
```

**There is no `PreferHttp3`, and that is deliberate.** Without happy-eyeballs, "prefer h3" could
only mean "try QUIC, then silently retry over TCP" — a silent downgrade, which this project's rule
forbids. `Http3Only` means h3 or an error, in three independent layers: the factory forks to QUIC
**before** the TCP dial so there is nothing to fall back to; the QUIC dial itself fails; and
`ValidateApplicationProtocol` throws even if a perfectly good `h2` was negotiated. A test,
`NoPreferringHttp3Policy_Exists`, fails if anyone adds one.

---

## 3a. Tuning the HTTP/3 layer — `options.Http3`

Defaults reproduce **Brave 151** exactly: `perk_hash` = `7d726b1554d23ae0ffb3e8c533f20a2f`,
verified live. Every property below is settable.

```csharp
var o = new TlsSessionOptions();

// SETTINGS. A list, and ORDER IS ON THE WIRE - the endpoint hashes it.
o.Http3.Settings[0] = o.Http3.Settings[0] with { Value = 32768 };
o.Http3.Settings.Add(new TlsHttp3Setting(0x1234, 1));      // any identifier, incl. unknown
o.Http3.Settings = [.. o.Http3.Settings.Reverse()];        // reordering changes the fingerprint

// Pseudo-header order. RFC 9114 s4.3 fixes NO order among them - which is exactly why it
// fingerprints. Brave sends :method, :authority, :scheme, :path.
o.Http3.PseudoHeaderOrder =
    [TlsHttp3PseudoHeader.Path, TlsHttp3PseudoHeader.Scheme,
     TlsHttp3PseudoHeader.Authority, TlsHttp3PseudoHeader.Method];

// The order the three unidirectional streams are opened in - unobserved by any capture so far,
// and fingerprintable.
o.Http3.UnidirectionalStreamOpenOrder =
    [TlsHttp3StreamType.Control, TlsHttp3StreamType.QpackEncoder, TlsHttp3StreamType.QpackDecoder];

// QPACK encoding choices
o.Http3.QpackHuffmanStringLiterals = false;                // default true
o.Http3.QpackNameMatchPolicy = TlsQpackNameMatchPolicy.LiteralName;

// GREASE frames on request streams
o.Http3.SendReservedFramesOnRequestStreams = true;

// Escape hatch: send SETTINGS_H3_DATAGRAM without max_datagram_frame_size. Servers running
// quic-go close with H3_SETTINGS_ERROR (0x109) if you do - which is why the pairing is enforced
// by default. That rule is an implementation's, not an RFC's.
o.Http3.AllowDatagramSettingWithoutTransportParameter = true;
```

---

## 3b. Tuning the QUIC layer — `options.Quic`

### Transport parameters - `TlsQuicTransportParameterOptions`, an ordered slot model

**Wire order is fingerprinted.** The endpoint publishes a raw hash *and* a normalized one, so
sorting is detectable. That is why this is a list of slots rather than a settings object.

```csharp
// Three slot kinds:
//   Literal - you supply the bytes
//   Placed  - the connection derives the value (e.g. initial_source_connection_id)
//   Drawn   - redrawn per connection (initial_rtt, the reserved GREASE parameter, the GREASE
//             version inside version_information)

o.Quic.TransportParameters.Entries.Insert(3,
    TlsQuicTransportParameterEntry.Literal(0x4a4a4a4a, [0xde, 0xad]));   // unknown id is fine

o.Quic.TransportParameters.Entries.Add(
    TlsQuicTransportParameterEntry.Drawn(0x1234, () => RandomNumberGenerator.GetBytes(4)));

o.Quic.TransportParameters.Entries.Add(
    TlsQuicTransportParameterEntry.Drawn(() => (0x5678, MyDraw())));     // id AND value drawn

o.Quic.TransportParameters.Entries = [.. o.Quic.TransportParameters.Entries.Reverse()];
```

### Packet and datagram shape

```csharp
o.Quic.SourceConnectionIdLength = 0;         // Brave sends 0; the pair (0,8) is fingerprinted
o.Quic.DestinationConnectionIdLength = 8;
o.Quic.InitialPacketNumber = 0;
o.Quic.PacketNumberEncodedLength = 1;
o.Quic.Token = ReadOnlyMemory<byte>.Empty;
o.Quic.PaddingTarget = 1200;                 // Initial datagram padding target

// The Initial flight's CRYPTO split - how the ClientHello is cut across frames and datagrams.
// UNVERIFIED: no verification endpoint observes this, so only a packet capture of Chromium's
// opening flight settles it.
o.Quic.InitialCryptoFrameByteCounts = [1400, 112];
o.Quic.InitialCryptoFramesPerDatagram = [1, 1];
o.Quic.InitialFrameOrder = [ /* frame type order within the Initial packet */ ];

// Varint widths - a value may be encoded in more bytes than it needs, and that is observable.
o.Quic.HeaderLengthVarintWidth = TlsQuicVarintWidth.TwoBytes;
o.Quic.CryptoOffsetVarintWidth = TlsQuicVarintWidth.OneByte;
o.Quic.CryptoLengthVarintWidth = TlsQuicVarintWidth.TwoBytes;

o.Quic.CoalesceAscendingByLevel = true;      // packet coalescing order within a datagram
o.Quic.AckLeadsInPacket = false;             // whether ACK is the first frame in a packet
o.Quic.AckRangeLimit = 32;
```

### Flow control - `TlsQuicFlowControlOptions`; advertised and enforced are the same numbers

```csharp
o.Quic.FlowControl.InitialMaxData = 15_728_640;
o.Quic.FlowControl.InitialMaxStreamDataBidiLocal = 6_291_456;
o.Quic.FlowControl.InitialMaxStreamDataBidiRemote = 6_291_456;
o.Quic.FlowControl.InitialMaxStreamDataUni = 6_291_456;
o.Quic.FlowControl.InitialMaxStreamsBidi = 100;
o.Quic.FlowControl.InitialMaxStreamsUni = 103;
```

### Loss recovery and congestion control - `TlsQuicRecoveryOptions`

```csharp
o.Quic.InitialRttRange = (TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(300));

o.Quic.Recovery.InitialCongestionWindow = (DatagramMultiplier: 10, ByteCap: 14_720);
o.Quic.Recovery.MinimumCongestionWindowDatagrams = 2;
o.Quic.Recovery.LossReductionFactor = 0.5;
o.Quic.Recovery.PacketThreshold = 3;
o.Quic.Recovery.TimeThreshold = 9.0 / 8.0;
o.Quic.Recovery.PersistentCongestionThreshold = 3;
o.Quic.Recovery.PtoBackoff = (Factor: 2.0, Maximum: TimeSpan.FromSeconds(60));
o.Quic.Recovery.ProbePacketsPerPto = 2;
o.Quic.Recovery.ProbeContents = TlsQuicProbeContents.RetransmittedData;
// ^ the shipped default, and it MATTERS. A PING-only probe Initial earns
//   CONNECTION_CLOSE 0x0a PROTOCOL_VIOLATION from fp.impersonate.pro 4 attempts out of 4,
//   while tls3.peet.ws ACKs the same probe and completes 4/4. Measured under induced loss
//   in 2026-08-22-sharptls-a3-13-live-run-under-induced-loss.md, fixed in SharpTls 2195e93.
//   Ping remains selectable — a real client may send it — but it is not what ships.
o.Quic.Recovery.AckPolicy = TlsQuicAckPolicy.Immediate;
// ^ wired since SharpTls A3-13 (`b8462ac`); until then it was accepted and ignored.
//   DelayedToMaxAckDelay holds an Application-space ACK until 25 ms — s18.2's default
//   max_ack_delay, which is what this client advertises, because the max_ack_delay
//   transport parameter (0x0b) is not one of the 14 it sends. Initial and Handshake
//   always acknowledge at once: s13.2.1 requires it, so the knob cannot reach them.
//   Countable off a capture — it changes how many ACK packets leave and how they are
//   spaced. Immediate is still what ships, and is UNVERIFIED against Chromium.
o.Quic.Recovery.PacingBurstDatagrams = 10;   // null disables pacing
o.Quic.Recovery.PacingIntervalScale = 1.25;  // s7.7's N; exposed in 175d50f
```

**Not exposed: the congestion controller itself.** It is a factory over an interface internal to
SharpTls with one implementation (NewReno). Chromium runs BBR, which makes the controller the
single largest behavioural difference from a real browser — but exposing the hook today would hand
you a knob with only the default to put in it. It opens when a second controller exists.

### The QUIC TLS half — this is NOT `options.Profile`

`options.Profile` is a **TCP-shaped** `TlsProfile` and does not drive the h3 ClientHello. RFC 9001
§8.4 forbids extensions a TCP profile carries, so QUIC gets its own.

```csharp
o.Quic.AlpnProtocols = ["h3", "h3-29"];

o.Quic.ConfigureClientHello = b =>
{
    TlsQuicOptions.ApplyDefaultClientHello(b);   // extend the Brave-shaped default...
    b.WithKeyShares(NamedGroup.X25519, NamedGroup.Secp256r1);
    b.WithCipherSuites(/* ... */);
    b.WithExtensionLayout(/* exact wire order */);
};
```

Omit `ApplyDefaultClientHello` and you are building the h3 ClientHello from scratch — every cipher
suite, group, key share, extension and its wire order is yours. `docs/FINGERPRINT-KNOBS.md` in the
SharpTls repo is the full catalogue, including which values are `UNVERIFIED` and which enum members
are offer-only rather than implemented.

---

## 3c. A worked h3 client — `TlsPresets.Spotify`

The shortest path to a real, measured HTTP/3 fingerprint. Everything in this section is
reproduced by tests in `tests/TlsClient.Tests/` — copy from there when you wire your own.

```csharp
using TlsClient;

var options = TlsPresets.Spotify.CreateOptions();   // Spotify917602050IOS270Http3
await using var session = new TlsSession(options);

var request = new HttpRequestMessage(HttpMethod.Get, "https://fp.impersonate.pro/api/http3");

// ORDER MATTERS HERE. The preset declares no header order, so these reach the wire in the order
// they are added - which is why the credential fields are added in their captured slots rather
// than at the end. Leave one unset and the rest keep their relative order.
request.Headers.TryAddWithoutValidation("accept", "*/*");
if (Environment.GetEnvironmentVariable("SPOTIFY_CLIENT_ID") is { } clientId)
{
    request.Headers.TryAddWithoutValidation("x-client-id", clientId);
}

request.Headers.TryAddWithoutValidation("accept-encoding", "gzip, deflate, br");
request.Headers.TryAddWithoutValidation("priority", "u=3, i");
request.Headers.TryAddWithoutValidation("app-platform", "iOS");
request.Headers.TryAddWithoutValidation("user-agent", "Spotify/9.1.76 iOS/27.0 (iPhone17,2)");
if (Environment.GetEnvironmentVariable("SPOTIFY_BEARER") is { } bearer)
{
    request.Headers.TryAddWithoutValidation("authorization", "Bearer " + bearer);
}

request.Headers.TryAddWithoutValidation("accept-language", "en-US,en;q=0.9");
request.Headers.TryAddWithoutValidation("spotify-app-version", "9.1.76.2050");

var response = await session.SendAsync(request);
Console.WriteLine($"{response.HttpVersion} {(int)response.StatusCode}");
Console.WriteLine(response.Text);
```

That is `samples/TlsClient.SpotifyIos26/Program.cs` verbatim, and it is built and run against a
live endpoint as part of verifying this preset.

The preset pins `HttpVersionPolicy = Http3Only`: the shape it carries is QUIC's, and applying
it to a TCP dial impersonates nothing. Proxy it with **SOCKS5 and only SOCKS5** — see §2a for
why the other two types cannot carry it.

### The second header image

The same app speaks h3 on more than one host with a different header block. Same QUIC and TLS
shape, different order — and neither is a reason for a second preset. One preset covers every
endpoint, because the QUIC and TLS shape is per-connection: across 41 QUIC captures spanning
seven hostnames, every cipher, extension, group, signature algorithm and transport-parameter set
was identical. Only the rotation offset and the GREASE values differ.

Set the order per endpoint yourself, or add the headers in the order you want and set nothing:

```csharp
// Insertion order reaches the wire when no HeaderOrder is set. Nothing else needed.
request.Headers.Add("content-type", "application/x-protobuf");
request.Headers.Add("accept", "*/*");

// Or state it explicitly, per request or per session:
options.HeaderOrder = ["content-type", "accept", "priority", "accept-encoding"];
```

The measured images for each captured leg are listed in §7.

### Reserving the Content-Length slot

`Content-Length` is always recomputed from the body, so you cannot set its value — but you can
set its POSITION. Declare it with any placeholder:

```csharp
request.Headers.TryAddWithoutValidation("content-type", "application/x-protobuf");
request.Headers.TryAddWithoutValidation("content-length", "-1");   // slot, not value
```

This matters because captured clients interleave it: the login POST puts `content-length`
seventh of ten, between `cache-control` and `user-agent`. Without the placeholder the generated
field is appended, which no captured client does. `Transfer-Encoding` reserves the same slot for
a chunked body.

### The transport parameters rotate — do not "fix" this

Two connections from this preset send the QUIC transport parameters in different orders. That is
the client's own behaviour, not a bug: 91 captured connections produced exactly **7** distinct
orders and every one was a cyclic rotation of

```
initial_max_data, bidi_local, bidi_remote, uni,
max_streams_uni, active_connection_id_limit, initial_source_connection_id
```

A shuffle would draw from 7! = 5040; a fixed order would match one connection in seven.
`CreateOptions()` redraws the rotation each time.

The rotation is **per connection, not per host**. Two captures of `gew4-spclient.spotify.com`
inside one session drew rotations 1 and 0; two of `spclient.wg.spotify.com` both drew 5. Same
host, different offsets, so nothing derives the offset from the SNI.

An **eighth** parameter, the vendor `0xff080808` carrying a single byte `0x09`, sits **last** and
does **not** rotate — it trailed the seven in 4 of 4 proxy captures regardless of where the
rotation began. Its ten encoded bytes (8-byte varint identifier, length, payload) are exactly the
487 to 497 growth measured in the second Initial CRYPTO frame, which is how it was found.

**This is not a contradiction of "nothing is generated" (§6a).** The draw is not inventing a
shape — it is reproducing one the handset demonstrably makes, measured across 91 connections.
Three values in this preset are drawn per connection for exactly that reason: the rotation
offset, the reserved HTTP/3 SETTINGS identifier (a fresh one in all 10 proxy captures), and the
GREASE values, which RFC 8701 requires to vary and which become a fingerprint of their own if
pinned. All three are ordinary knobs — `TransportParameters.Entries`, `Http3.Settings` and
`WithGrease` all accept fixed values — so you can pin any of them. Doing so makes the preset stop
matching the capture, which is the whole reason it exists.

### What is measured, and what is not

Measured across 80 captured connections and pinned by
`TlsPresetTests.SpotifyIosHttp3_CarriesTheCapturedQuicAndHeaderImage`: connection-id lengths
`(0, 8)`, `PaddingTarget` 1200, `PacketNumberEncodedLength` 1, empty token, the Initial CRYPTO
budget of **999** bytes with one frame per datagram, no packet coalescing, the three varint
widths, the six flow-control limits, the seven-parameter set (no `initial_max_streams_bidi`),
and HTTP/3 SETTINGS `1:16383; 7:100` plus one reserved identifier and **no**
`MAX_FIELD_SECTION_SIZE`.

Left at library defaults because an opening-flight capture cannot see them — do not read these
as measurements:

- everything under `options.Quic.Recovery` (congestion controller, pacing, PTO, ACK policy)
- the QPACK encoding choices (Huffman policy, name-match policy)

The HTTP/3 pseudo-header order IS measured: **`m,s,a,p`**, not the library default `m,a,s,p`.
It came from proxy captures — a pcapng cannot reach 1-RTT — and the preset pins it. RFC 9114
§4.3 fixes no order among the pseudo-headers, which is exactly why the choice fingerprints.

### Verifying your own runs

```
dotnet run --project samples/TlsClient.SpotifyIos26
dotnet run --project samples/TlsClient.SpotifyIos26 -- https://tls3.peet.ws/api/all
```

`fp.impersonate.pro/api/http3` reports `header_order`, `perk_text` and the transport parameters
in wire order, and its `ja3` is directly comparable to a capture's.

**Do not judge HTTP/3 header order from `tls3.peet.ws`.** It reported a different field order run
to run for the same request. The reliable offline check is
`Http3FieldMapperTests.RequestFields_FollowTheLogin5PresetOrderIncludingContentFields`, which
asserts the bytes the mapper produces.

To compute JA4 from an endpoint that does not publish one: sorted non-GREASE cipher list hashed
to 12 hex, then sorted non-GREASE extensions minus SNI and ALPN, `_`, then signature algorithms
**in wire order**, hashed to 12 hex.

---

## 4. POST with a body, and trailers

```csharp
using System.Text;
using TlsClient;

await using var session = new TlsSession();

// Convenience helpers
var a = await session.PostAsync("https://httpbin.org/post", "field=value");
var b = await session.PostJsonAsync("https://httpbin.org/post", new { hello = "world" });

// Full control
var request = new HttpRequestMessage(HttpMethod.Post, "https://httpbin.org/post")
{
    Content = new ByteArrayContent(Encoding.UTF8.GetBytes("payload")),
};
var c = await session.SendAsync(request);
```

Bodies and trailers work over HTTP/3 as well as h1.1/h2. Trailers go through
`TlsRequestOptions.Trailers`.

**Over h3 there is a body-size ceiling — see §6.**

---

## 5. Reading the response

```csharp
response.Url                    // Uri, after redirects
response.HttpVersion            // 1.1 / 2.0 / 3.0
response.StatusCode             // HttpStatusCode
response.ReasonPhrase           // empty over h2 and h3 - neither carries one
response.Headers                // TlsHeaders
response.Trailers               // TlsHeaders
response.Body                   // ReadOnlyMemory<byte>
response.Text                   // string
response.Json<T>()              // deserialised
response.WasDecompressed
response.History                // IReadOnlyList<TlsRedirect>

response.Tls.ProtocolVersion
response.Tls.CipherSuite
response.Tls.ApplicationProtocol      // "http/1.1" | "h2" | "h3"
response.Tls.ClientHelloProfile
```

---

## 6. HTTP/3 limits you WILL hit — read before testing

Each fails with a named error rather than a hang. Rows struck through were true earlier and are
not any more.

| Limit | What happens | Why |
| --- | --- | --- |
| **`PooledConnectionLifetime = InfiniteTimeSpan` gives h3 five minutes, not forever** | The connection is evicted after ~5 min | h3 inherits QUIC's handshake deadline, which bounds the whole connection. h1 and h2 really are unbounded. |
| **The pool double-counts h3 concurrency** | You pay an extra handshake; never a failure | It compares in-flight leases against a *decaying* lifetime allowance those same leases drew down. Correct for h1 (constant 1) and h2 (fixed SETTINGS), wrong for h3. Pinned by a test, not fixed. |
| **The h3 TLS fingerprint is not driven by `options.Profile`** | You get the QUIC ClientHello from `o.Quic.ConfigureClientHello`, not your `TlsProfile` | A `TlsProfile` is TCP-shaped and carries extensions RFC 9001 §8.4 forbids over QUIC. |
| **h3 through an HTTP proxy** | `NotSupportedException` naming the type — explicit, never a silent downgrade | Neither relays UDP. **SOCKS5 works** — see §2a. |
| **Streaming request bodies are buffered whole** | Memory, not failure | The DATA path takes a complete body. |
| **DNS/ECH, telemetry, resumption, 0-RTT replay policy over h3** | Absent | Condition 5 of `docs/HTTP3-EVALUATION.md` is **four-ninths** met. **0-RTT has real security weight — replay policy is not optional if it is ever enabled.** |
| ~~One request at a time per connection~~ | **FIXED** `2ece2ae` | A background read loop multiplexes. `MaximumConcurrentRequests` returns the **peer's** allowance minus what is open. |
| ~~Packet loss fails the request~~ | **FIXED** `ebdcc89` | RFC 9000 §13.3 retransmission. A handshake now completes through induced loss three ways, including against MsQuic. |
| ~~No pooling, redirects, cookies or retries over h3~~ | **Pooling, redirects and cookies always worked** — now witnessed. **Retries were broken and are fixed** (`5e499ef`). | No h3 test had ever gone through `TlsSession`, so the integration was never exercised. The retry bug: both QUIC failure shapes were reported as `TlsHttpProtocolException`, the one type `ShouldRetryException` refuses — so an idempotent h3 GET on a dead connection failed outright where the identical h2 GET was retried. |
| ~~Request bodies above the peer's initial stream credit (~6 MB)~~ | **FIXED** at both layers — `e8ab1c3` (QUIC) and `db28cf5` (HTTP/3) | SharpTls parsed `MAX_STREAM_DATA` and `MAX_DATA` and dropped both, so send credit never grew and a body over the peer's initial allowance was refused outright. The QUIC layer now applies them, and the HTTP/3 DATA path paces the body against credit as it arrives instead of measuring it once up front. A body larger than the peer will *ever* allow still fails — but that is the peer's limit, named in the error, not ours. |

`docs/HTTP3-EVALUATION.md` scores all seven gate conditions honestly. Read it before treating h3
as production-ready.

---

## 6a. Reproducing YOUR capture — the part that is preset authoring, not library work

**Nothing here is generated.** Profile randomization and the origin-aware Roller were both
removed — `TlsProfiles.CreateRandomized`, `ClientHelloRandomizationOptions` and
`ClientHelloProfileRandomizer` no longer exist. A generated ClientHello is a shape nobody sent:
it can be internally coherent and still match no real client, and when it gets blocked you
cannot tell which of its invented choices did it. Every parameter is set deliberately, from a
capture.

**The library can express essentially any ClientHello you can capture. What it cannot do is guess
which one you want.** The browser catalogue is gone — the ~50 uTLS transcriptions were removed
deliberately, because a transcription of someone else's capture is a liability dressed as a
feature: it ages silently, and nothing tells you when the real client moved on. Two profiles
ship. `TlsProfiles.Modern` imitates nothing and says so. `Spotify917602050IOS270Quic` is a
first-party capture, and it is somebody's device — just not yours.

So this section is not a fallback for when the catalogue misses. It is the normal path.

A worked example, from a real report. A phone sent `signature_algorithms` with **ten entries and
`0x0805` twice** — confirmed across 80 of 80 captured connections. The shipped preset sent nine
unique entries, so the ClientHello was 2 bytes shorter and JA4 differed. (JA3 matched, because
JA3 does not hash that list — a good illustration of why JA3 alone is a weak check.)

**That was never a library limitation.** `ClientHelloBuilder.AllowDuplicateSignatureAlgorithms`
has always existed. The shipped Spotify capture uses it, and it is now the only profile that does
— the six uTLS profiles that also carried a repeated codepoint went with the catalogue:

```csharp
var profile = ClientHelloProfiles.Custom(b => b
    .WithSignatureAlgorithms(
        // ten entries, 0x0805 twice, in the captured order
        Ecdsa_Secp256r1_Sha256, Rsa_Pss_Rsae_Sha256, Rsa_Pkcs1_Sha256,
        Ecdsa_Secp384r1_Sha384, Rsa_Pss_Rsae_Sha384, Rsa_Pss_Rsae_Sha384,
        Rsa_Pkcs1_Sha384, Rsa_Pss_Rsae_Sha512, Rsa_Pkcs1_Sha512, Rsa_Pkcs1_Sha1)
    .AllowDuplicateSignatureAlgorithms(true)      // <-- without this, the duplicate is rejected
    .WithExtensionLayout(/* exact wire order from your capture */));
```

### Which lists genuinely forbid duplicates

Two are spec-backed; the rest were our own assumption and are quoted at each call site now.

| List | Duplicates |
| --- | --- |
| `key_share` | **Forbidden** — RFC 9846 §4.3.8 MUST NOT |
| `supported_groups` | **Forbidden** — RFC 9846 §4.3.7 MUST NOT (**new in the bis**; RFC 8446 had no such rule) |
| `signature_algorithms` | **Allowed** — order only, no uniqueness rule |
| `cipher_suites`, `supported_versions`, `signature_algorithms_cert` | **Allowed** — order only |

### The general recipe

1. **Capture the real client.** `tls.peet.ws/api/all` for TCP, `fp.impersonate.pro/api/http3` for
   h3, or a pcap.
2. **Read the exact lists and their ORDER.** Order is hashed by JA4 and by `perk`; a correct set in
   the wrong order is a different fingerprint.
3. **Build a profile** with `Custom(...)`, using `WithExtensionLayout` for exact wire order and
   `Raw(id, bytes)` for any extension SharpTls has no semantic kind for.
4. **Verify against the same endpoint** and diff the reported hashes.

`SharpTls/docs/FINGERPRINT-KNOBS.md` is the full catalogue — every knob, its default, what it
changes on the wire, and which values are `UNVERIFIED`. Its count was stale by three for three
commits and is not any more (SharpTls `29813e1`): 20 grep hits, 16 of which mark a value.
The rule that caught the drift still stands, though — trust the markers in the source, not the
number in any table, this one included.

---

## 7. What the fingerprint actually is

Over h3 the shape comes from `options.Quic` and `options.Http3`, and `options.Profile` does not
drive the ClientHello at all (§3b). Two clients are reproduced exactly and verified live against
`fp.impersonate.pro`:

- **Brave 151** — `perk_hash` `7d726b1554d23ae0ffb3e8c533f20a2f`, all four `perk` segments
  matching: HTTP/3 SETTINGS, pseudo-header order, QUIC transport parameters **in wire order**,
  and the connection-ID length pair.
- **Spotify 9.1.76.2050 on iOS 27.0** (`TlsPresets.Spotify`, §3c) — JA3
  `48d08f334704479db85d91df80039756` and JA4 `q13d0311h3_55b375c5d22e_f2a83c8e78ae`, both the
  captured handset's, decoded from QUIC Initial packets with no keylog.

  **Two images exist for this handset and the preset ships one of them.** From the same phone on
  the same build, captures taken through a proxy show cipher order `0x1302, 0x1303, 0x1301` and
  carry the vendor transport parameter `0xff080808`; 80 connections captured directly show
  `0x1302, 0x1301, 0x1303` and no such parameter. The split is real and unexplained — an
  egress-dependent remote config is the leading guess, untested. The preset takes the proxy
  values because that is the path this library dials through. Only JA3 moves between the two;
  JA4 sorts the cipher list, so it hashes to `q13d0311h3_55b375c5d22e_f2a83c8e78ae` either way.
  The direct-path JA3 was `2f9431e877b01e163774ae4ae0df9ded`.

### Header images measured, and why none of them ship as presets

Header order is per **endpoint**, not per host, so a preset carrying one is only ever right for a
single path. It is also **not needed**: when no `HeaderOrder` is set anywhere, fields reach the
wire in the order you added them (`Http11RequestWriter.Order` is a pass-through on an empty
order). A preset that declared one would silently *re-sort* the headers you supplied, which is
the opposite of useful. So the presets declare none, and the measured images live here.

Set one explicitly only if you want to reorder what you added:
`options.HeaderOrder = [...]`, or per request via `TlsRequestOptions.HeaderOrder`.

`spclient` GET, confirmed from two independent capture paths:

```
accept, x-client-id, accept-encoding, priority, app-platform, user-agent, authorization,
accept-language, spotify-app-version
```

`login5.spotify.com/v4/login` POST, and `/v3/login` on the same host — a different image, which
is why the path and not the host is what selects one:

```
content-type, accept, priority, accept-encoding, x-retry-count, cache-control, content-length,
user-agent, accept-language, client-token

accept, content-type, priority, user-agent, accept-language, content-length, accept-encoding
```

Two `gew4-spclient.spotify.com` POSTs were captured whose paths were not recorded:

```
content-type, spotify-app-version, accept, authorization, content-encoding, app-platform,
priority, accept-language, cache-control, accept-encoding, content-length, user-agent,
x-client-id, client-token

content-type, spotify-app-version, accept, authorization, app-platform, priority,
accept-encoding, accept-language, content-length, user-agent, client-token
```

Neither is a reordering of the other — each carries names the other lacks — so they are two
endpoints, not one endpoint captured twice.

Over h1.1/h2 the ClientHello comes from `options.Profile` and its JA3/JA4 are computed by
`TlsClientHelloFingerprint`. Those are still TLS 1.3 handshakes — the HTTP version and the TLS
version are independent, and only the HTTP version is negotiated over TCP here.

---

## 8. Building

```
dotnet restore TlsClient.slnx -m:1
dotnet build TlsClient.slnx -c Release --no-restore
dotnet test  TlsClient.slnx -c Release --no-build
```

`-m:1` on restore matters: parallel restore fails intermittently here with NuGet
`Value cannot be null. (Parameter 'path1')`, naming a different project each run.

Live tests are opt-in: `TLSCLIENT_LIVE_TESTS=1`.
