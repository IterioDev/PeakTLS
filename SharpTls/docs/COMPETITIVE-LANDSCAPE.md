# Competitive landscape — libraries with low-level fingerprint control

Surveyed 2026-08-27. Scope: open-source libraries that let a *caller* shape the bytes a
client puts on the wire, not tools that only *read* fingerprints server-side (p0f, Suricata,
clienthellod, read-tls-client-hello, fingerproxy) and not headless browsers (chromedp,
Camoufox), which get a real fingerprint by running a real browser.

The comparison is against the PeakTLS stack as a whole: `SharpTls` (TLS 1.3 / QUIC / HTTP/3
engine) plus `TlsClient` (HTTP/1.1 + HTTP/2 layer, `TlsHttp2Options`,
`TlsHttp2PseudoHeaderOptions`, `TlsHttp3Options`).

## The four tiers

Every project below sits in one of four tiers. The tier, not the star count, is what decides
whether a given fingerprint field is reachable.

| Tier | What the caller controls | Examples |
| --- | --- | --- |
| **A — spec-level** | Arbitrary field values and wire order, expressed as data. New fields do not need a new release | SharpTls + TlsClient, uTLS, uQUIC |
| **B — spec-level TLS, preset everything else** | A uTLS `ClientHelloSpec` passes through, but h2/h3 come from a fixed profile table | bogdanfinn/tls-client, azuretls-client, httpcloak, CycleTLS |
| **C — preset-only** | Pick a browser name from a list. No field-level access | curl-impersonate, curl_cffi, primp, rnet, noble-tls, Python-Tls-Client, Curl.Impersonate, CycleTLS-dotnet, impersonator |
| **D — adjacent** | Not impersonation-first; field order is merely *reachable* with effort | rustls, BouncyCastle |

## Main table

`Spec` = arbitrary values, caller-supplied, ordered. `Preset` = choose from a shipped list.
`—` = not addressable.

| Project | Lang | TLS ClientHello | HTTP/2 | QUIC Initial | HTTP/3 | Delivery |
| --- | --- | --- | --- | --- | --- | --- |
| **SharpTls + TlsClient** | C# / .NET | **Spec** | **Spec** | **Spec** | **Spec** | in-process |
| [utls](https://github.com/refraction-networking/utls) | Go | **Spec** | — (needs a fork of `net/http2`) | transport params only | — | in-process |
| [uquic](https://github.com/refraction-networking/uquic) | Go | Spec (via utls) | — | **Spec** | preset via quic-go | in-process |
| [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) | Go | Spec (utls) | Preset + settings map | — | — | in-process / shared lib |
| [azuretls-client](https://github.com/Noooste/azuretls-client) | Go | Spec (utls) | Preset (Akamai string) | Preset | Preset | in-process |
| [httpcloak](https://github.com/sardanioss/httpcloak) | Go | Spec (utls) | Preset | Preset | Preset | in-process |
| [CycleTLS](https://github.com/Danny-Dasilva/CycleTLS) | Go + JS | JA3 string | Preset | Preset | Preset | subprocess + JSON |
| [rquest](https://github.com/penumbra-x/rquest) / [wreq](https://github.com/0x676e67/wreq) | Rust | Preset + BoringSSL knobs | Preset | Preset | Preset | in-process |
| [curl-impersonate](https://github.com/lwthiker/curl-impersonate) | C | Preset | Preset | Preset (v0.11+) | Preset | patched binary |
| [curl_cffi](https://github.com/lexiforest/curl_cffi) | Python | Preset | Preset | Preset | Preset | FFI to the above |
| [primp](https://github.com/deedy5/primp) / rnet | Python | Preset | Preset | — | — | FFI to Rust |
| [Python-Tls-Client](https://github.com/FlorianREGAZ/Python-Tls-Client) / [noble-tls](https://github.com/rawandahmad698/noble-tls) | Python | JA3 string | Preset | — | — | FFI to Go |
| [Curl.Impersonate](https://github.com/Texnomic/Curl.Impersonate) | C# | Preset | Preset | Preset | Preset | P/Invoke |
| [CycleTLS-dotnet](https://github.com/mnickw/CycleTLS-dotnet) | C# | JA3 string | Preset | — | — | subprocess |
| [impersonator](https://github.com/zhkl0228/impersonator) | Java | Spec-ish (BC fork) | Preset | — | — | in-process |
| [rustls](https://github.com/rustls/rustls) | Rust | order reachable | — | — | — | in-process |

## Where we are alone

**Nobody else offers a spec-level HTTP/3 layer.** Every project in the table that supports h3
gets it by turning on quic-go or curl and accepting whatever that stack emits. `TlsQuicHttp3Spec`
exposes SETTINGS contents and order, unidirectional-stream open order, pseudo-header order,
QPACK Huffman literal policy, QPACK name-match policy, and reserved frames on request streams.
No comparable surface exists in Go, Rust, Python or C.

**The QUIC layer is a superset of uQUIC's**, the only other tier-A QUIC project. uQUIC's
`QUICSpec` covers connection-ID lengths, initial packet number and its encoded length, token
prefix, UDP datagram minimum, a `FrameBuilder`, plus transport-parameter shuffle and
suppression. It does not reach varint widths (`HeaderLengthVarintWidth`, `CryptoOffsetVarintWidth`,
`CryptoLengthVarintWidth`), CRYPTO-frame chunking (`InitialCryptoFrameByteCounts`,
`InitialCryptoFramesPerDatagram`), coalescing order, ACK position within a packet, or any of
loss recovery — congestion controller, pacing burst and interval scale, PTO backoff, probe
contents, ACK policy. Those are behavioural fingerprints visible across a whole connection,
not just its first flight.

**The transport-parameter slot model has no analogue.** uQUIC offers shuffle-or-don't and a
suppression list. `TlsQuicTransportParameterSpec` distinguishes `Literal` (these exact bytes),
`Placed` (this identifier, value owned by the one place that owns the number, so a second copy
cannot drift) and `Drawn` (identifier *and* value redrawn every `Compose`, with `null` meaning
"omit but keep the slot"). That is what makes a per-connection GREASE identifier and a
per-connection `initial_rtt` draw expressible as data rather than as a code path.

**Evidence discipline.** Nothing surveyed marks a value as `UNVERIFIED` when its capture cannot
bound it. Every other project ships a number and lets the caller assume it was observed.

## Where we are behind

**Profile breadth.** curl_cffi ships fingerprints for nearly every browser build across
platforms and pulls new ones with `curl-cffi update`; wreq-util carries 100+ device profiles.
Our catalog is small and hand-verified. Depth per profile is higher; coverage is lower.

**Reach.** SharpTls's QUIC and HTTP/3 types are `internal`. Tier-A control that a consumer
cannot call is tier-C control from outside the assembly. `FINGERPRINT-KNOBS.md` already tracks
this under "Knobs nothing currently reads" and "Not configurable, and should be".

**Ecosystem gravity.** uTLS is the foundation half this table is built on. Being the only
tier-A .NET option means no upstream to inherit from — every new extension is ours to write.

## Reading the tiers honestly

Tier C is not a failure mode. For "make this request look like Chrome 140", a preset is the
correct tool and a spec is a liability. The spec-level tiers matter when the target is a
fingerprint no preset covers: a mobile app, a non-browser client, a build not yet in anyone's
table, or a per-connection value a static preset cannot express. That is the segment where the
only Go answer is uTLS + uQUIC and, above the QUIC layer, there is no answer at all.
