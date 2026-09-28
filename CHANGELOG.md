# Changelog

All notable changes to both packages in this repository are documented here, SharpTls first, then TlsClient. Both follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html); during the preview period, minor releases may revise public APIs.

# SharpTls

## [Unreleased]

### Added

- RFC 9221 QUIC DATAGRAM frames: `max_datagram_frame_size` is parsed and advertised, and
  `TlsQuicConnection.TryQueueDatagram` sends through a bounded queue that delays rather than
  drops; a lost DATAGRAM is never retransmitted.
- RFC 9220 extended CONNECT (`TlsQuicHttp3Request.Protocol`,
  `SETTINGS_ENABLE_CONNECT_PROTOCOL`) and RFC 9297 HTTP/3 datagrams routed by quarter stream id.
- RFC 9298 CONNECT-UDP client transport (`TlsQuicMasqueTransport`): dials a MASQUE proxy over
  its own HTTP/3 connection and presents the tunnel as a datagram transport an inner QUIC
  connection dials through. Every failure is named through `TlsQuicProxyError.Masque*`, a
  timeout names the dial stage, and every address the proxy name resolves to is tried in turn
  before the dial is refused.
- QPACK dynamic-table encoder with per-spec capacity and insert policy.
- Handshake timeouts report what the receiver discarded and why; a SOCKS5 UDP relay that
  answers with a TLS alert fails fast as `TlsQuicProxyError.RelayDeliveredTlsAlert`.

### Changed

- `TlsQuicConnection.PeerMaxDatagramFrameSize` is `null` when the peer sent none.
- The changelog, license and third-party notices now live at the repository root.


## [0.9.0-preview.5] - 2026-07-21

### Added

- Add explicit `DangerouslySkipServerCertificateValidation` support for controlled
  testing while retaining CertificateVerify/server-key signatures, Finished and record
  authentication. Resumption caches partition validated and bypassed sessions.

### Fixed

- Soft-fail only unavailable online/offline revocation evidence by default after a second
  no-revocation PKIX build, while keeping actual revocation and every other
  certificate failure fatal. Strict revocation-availability enforcement remains opt-in.

## [0.9.0-preview.4] - 2026-07-18

### Fixed

- Classify malformed QUIC transport parameters found during ClientHello capture import as
  an expected fail-closed fuzz boundary outcome, with a focused regression test.

## [0.9.0-preview.3] - 2026-07-18

### Fixed

- Include the SharpFuzz runtime dependency closure, use the upstream framework-dependent
  libFuzzer launch contract, and defer instrumented target construction until the native
  coverage map is initialized during release qualification.

## [0.9.0-preview.2] - 2026-07-18

### Added

- GitHub-ready project presentation, contribution templates and automated tag releases.
- Reproducible NuGet package and symbol publication through GitHub Actions.

### Fixed

- Accept RFC 5746 `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` as the initial TLS 1.2 secure-
  renegotiation signal while continuing to require Extended Master Secret.
- Normalize platform-provider invalid NIST ECDH point errors to the protocol's
  `illegal_parameter` alert on every supported operating system.
- Classify custom-root chain termination failures consistently as `unknown_ca` across
  platform X.509 providers.
- Load Windows Schannel interoperability credentials through a non-ephemeral test key
  container and update hosted actions to their Node.js 24 releases.

## [0.9.0-preview.1] - 2026-07-18

### Added

- Pure managed TLS 1.3 client/server and secure TLS 1.2 subset.
- Byte-exact ClientHello builder, semantic/raw ordered extensions, GREASE,
  GREASE ECH, padding and record fragmentation.
- Forty pinned upstream uTLS wire IDs, package-bound family aliases, coherent
  randomization and bounded origin-aware Roller.
- Strict capture import, JSON v6 interchange, deterministic test snapshots and
  defensive pre-send inspection.
- RFC 9849 ECH and RFC 9848 HTTPS/SVCB bootstrap over UDP/TCP DNS, DoT and DoH.
- Session resumption, external PSK, replay-gated 0-RTT, KeyUpdate, exporters and
  post-handshake client authentication.
- Standard certificate validation, client certificates, delegated credentials,
  OCSP/SCT policy and certificate compression.
- X25519, NIST curves, X25519MLKEM768 and the historical Kyber draft group needed
  by pinned wire profiles.
- Recordless QUIC-TLS client/server adapters and an HTTP/1.1 interoperability sample.

### Security

- CBC, RC4, static RSA, SHA-1 authentication, renegotiation and TLS 1.0/1.1 are
  non-executable.
- Independent cryptographic review and hosted release evidence remain 1.0 gates.

# TlsClient

## [Unreleased]

### Added

- HTTP/3 through a MASQUE proxy: `options.Quic.Proxy = TlsProxy.Masque(address, user, pass)`
  (RFC 9298 CONNECT-UDP). The TCP proxy slot `options.Proxy` is independent; the inner QUIC
  connection and its fingerprint are unchanged. Connect events `MasqueTunnelOpened` and
  `MasqueTunnelClosed`; failures reach the caller as `TlsQuicProxyException` with a `Masque*`
  error. Live tests behind `TLSCLIENT_LIVE_MASQUE`. A tunnel the proxy ends during the inner
  handshake is dialled again, up to `Quic.MaximumAssociationAttempts` tunnels in all, and the
  final error says how long each tunnel lived, what crossed it (counts and the last sizes each
  way), and what the proxy wrote on the tunnel stream before ending it. `TlsProxy.Masque` takes
  `maxInnerDatagramPayload` (default 1352, the Oxylabs guide's inner size) to cap inner
  datagrams below the outer frame budget.
- Spotify 9.1.86 / iOS 27 presets (`spotify-9.1.86-ios-27.0-h3`, `-h2`) with the QPACK
  dynamic table, the h2 preface and HPACK policy from the capture.
- SOCKS5: the authentication reply `VER 0x05` is tolerated; CONNECT and UDP ASSOCIATE
  failures are named by status.

### Changed

- HTTP/3 through an HTTP CONNECT proxy is refused by name instead of downgrading silently.
- The changelog, license and third-party notices now live at the repository root.

## [0.6.0-preview.1] - 2026-07-21

### Added

- `TlsSessionOptions.DangerouslySkipServerCertificateValidation`, an explicit opt-in
  bridge to SharpTls's server certificate-chain and hostname validation bypass.
- Loopback coverage proving the bypass is disabled by default, reaches SharpTls through
  the session snapshot, and accepts a deliberately untrusted test certificate
  only when enabled.

### Changed

- Pinned `SharpTls 0.9.0-preview.5`, which safely soft-fails unavailable revocation
  evidence only after all non-revocation chain and hostname requirements pass. A
  certificate reported as revoked is still rejected.
- Advanced `ConfigureTls` callbacks run after the session-level bypass default is
  applied and may refine the complete SharpTls certificate validation policy.
- Version, CI package checks, lock files, profile manifest, release guidance, and public
  API baseline now describe the `0.6.0-preview.1` package line.

### Security contract

- Server certificate and hostname validation remain enabled by default.
- Enabling the dangerous bypass permits active man-in-the-middle attacks. SharpTls still
  verifies TLS `CertificateVerify`, and configured TlsClient SPKI pins still run.

## [0.5.0-preview.1] - 2026-07-21

The first complete TlsClient preview, rebuilt from the original prototype around the
managed [SharpTls](https://github.com/danikishin/SharpTls) stack.

### Highlights

- Managed HTTP/1.1 and HTTP/2 with HPACK/Huffman, flow control, multiplexing,
  CONTINUATION, PING, RST_STREAM, GOAWAY, trailers, and graceful draining.
- Coherent Chrome 133, Firefox 148, and OkHttp/Android 11 TLS + HTTP behavior presets.
- Session cookies, redirects, bounded decompression, connection pooling, DNS refresh,
  Happy Eyeballs, streaming, retries, and policy integration points.
- HTTP CONNECT, SOCKS4/SOCKS4a, and SOCKS5 proxies with per-request routing.
- ClientHello capture/import, deterministic fingerprint fixtures, JA3/JA4 diagnostics,
  profile rolling, ECH DNS discovery, protected session persistence, client
  certificates, pins, and OpenTelemetry activities.
- Public API baseline, 108 deterministic tests, parser/decompression fuzz targets,
  allocation and throughput budgets, and hostile-peer protocol review evidence.
- Deterministic NuGet and symbol packages with Source Link, SPDX 2.2 SBOM, and GitHub
  artifact attestations.

### Known boundaries

- Targets .NET 9 and pins `SharpTls 0.9.0-preview.4`.
- HTTP/3 remains deferred until a compatible complete QUIC transport exists.
- Certificate and hostname validation cannot be disabled through this release.
- Preview APIs may change before `1.0.0`.

[Unreleased]: https://github.com/danikishin/TlsClient/compare/v0.6.0-preview.1...HEAD
[0.6.0-preview.1]: https://github.com/danikishin/TlsClient/compare/v0.5.0-preview.1...v0.6.0-preview.1
[0.5.0-preview.1]: https://github.com/danikishin/TlsClient/releases/tag/v0.5.0-preview.1
