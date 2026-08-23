# HTTP/3 transport-readiness evaluation

Decision date: 2026-07-21
Decision for: TlsClient `0.6.0-preview` with SharpTls `0.9.0-preview.5`
Outcome: **deferred; HTTP/3 is not implemented or advertised**

> **Amended 2026-08-22. Read the amendment at the end of this file before acting on anything
> above it.** Everything from here to `## Amendment — 2026-08-22` is the original 2026-07-21
> record, preserved unchanged, **including premises that are now false**. The decision to defer
> and the reasoning behind it still stand; most of the facts that reasoning rested on have
> changed. Do not quote the sections below as a description of the current stack.

## Why the current components are insufficient

SharpTls provides a recordless QUIC-TLS state machine. Its package documentation and
API contract explicitly leave UDP packets, packet numbers, header/payload protection,
CRYPTO frames, Retry, loss recovery, congestion control, connection IDs, migration,
streams, and `HANDSHAKE_DONE` to a caller-owned QUIC transport. HTTP/3 and QPACK are
also outside SharpTls. TLS handshake completion therefore does not mean a QUIC
connection is usable.

`.NET 9` has a stable `System.Net.Quic` API, but it is backed by native MsQuic and takes
`SslClientAuthenticationOptions`. It does not expose a boundary for replacing its TLS
engine with `SharpTls.Quic.CustomTlsQuicClient`. Using it would violate this project's
SharpTls-only transport and byte-exact ClientHello guarantees. It would also introduce
MsQuic/OpenSSL/SChannel platform dependencies and a materially different fingerprint
surface.

No independent, complete QUIC transport compatible with the SharpTls recordless API is
pinned by this repository. Building only enough packets to pass a happy-path demo would
not meet the security, interoperability, congestion, loss, and hostile-input standards
used by the HTTP/1.1 and HTTP/2 implementations.

## Required entry gate

HTTP/3 work may start only when a candidate transport satisfies all of these conditions:

1. It accepts caller-owned SharpTls handshake bytes and traffic secrets without invoking
   platform TLS or replacing the selected ClientHello.
2. QUIC v1 packet parsing/protection, packet-number recovery, ACK/loss/PTO, congestion
   control, Retry, connection IDs, flow control, stream state, key discard/update,
   connection close, and transport-parameter validation are implemented with strict
   bounds. QUIC v2 is separately declared and tested if exposed.
3. It has independent unit/fuzz testing and interoperability evidence against at least
   two established QUIC implementations under reordering, duplication, loss, and
   malformed input—not only localhost success cases.
4. The HTTP/3 layer implements control streams, SETTINGS, request streams, QPACK,
   GOAWAY, cancellation, priorities when selected, response limits, and graceful
   draining without routing through `HttpClient`.
5. Pooling, DNS/ECH, proxy policy, retries, redirects, cookies, streaming, telemetry,
   resumption, and 0-RTT replay policy have explicit HTTP/3 semantics.
6. Linux, macOS, and Windows CI can run deterministic protocol tests, with public
   interoperability smoke tests isolated from the offline suite.
7. A focused independent security review covers packet parsing, loss recovery, stream
   state, QPACK, amplification, resource exhaustion, and 0-RTT replay behavior.

## Current API behavior

TlsClient accepts HTTP/1.1 and HTTP/2 request versions. An HTTP/3 request is rejected
with `NotSupportedException`; it is never silently downgraded and no `h3` ALPN is
advertised. This preserves the project's rule that wire behavior cannot change silently.

Relevant primary documentation:

- the SharpTls NuGet package's bundled `docs/QUIC-TLS.md` for the exact pinned adapter
  contract;
- Microsoft's [.NET QUIC overview](https://learn.microsoft.com/dotnet/fundamentals/networking/quic/quic-overview)
  for the native MsQuic implementation and platform dependencies;
- [`QuicClientConnectionOptions.ClientAuthenticationOptions`](https://learn.microsoft.com/dotnet/api/system.net.quic.quicclientconnectionoptions.clientauthenticationoptions?view=net-9.0)
  for the platform TLS configuration boundary.

The gate should be revisited when the pinned SharpTls version changes or a credible
compatible managed QUIC transport becomes available. Deferral is a protocol-integrity
decision, not a permanent rejection of HTTP/3.

---

# Amendment — 2026-08-22

Amendment date: 2026-08-22
Amends: the 2026-07-21 evaluation above, which is preserved unchanged.
Amendment outcome: **the deferral still stands. The gate is not passed. Four of its seven
conditions have moved, three of them substantially. Condition 5 has not moved at all.**

## Read this first: none of the work below is released

Everything this amendment cites lives in **one local, unpushed feature branch of SharpTls**:
`feat/quic-socks5-datagram-transport`, **318 commits ahead of `origin/main` and pushed nowhere**
(`git log origin/main..HEAD` at the time of writing; latest local commit `f2e3242`, 2026-08-22).
There is no released SharpTls containing any of it, no tag, no NuGet package, no public review.
Commit hashes below are branch-local and will change if the branch is rebased.

Correspondingly, **the pin described in the original document no longer exists.**
`src/TlsClient/TlsClient.csproj:35` now consumes SharpTls as a `ProjectReference` to the sibling
checkout, not as `SharpTls 0.9.0-preview.5`. `README.md` (lines 69, 88, 411) and `ROADMAP.md`
(line 159) still describe the exact NuGet dependency; **they are stale and were deliberately not
edited by this amendment.**

## What changed

The original document's central premise was that SharpTls provides only a recordless QUIC-TLS
state machine and leaves UDP packets, packet numbers, header/payload protection, CRYPTO frames,
Retry, loss recovery, congestion control, connection IDs, migration, streams and `HANDSHAKE_DONE`
to a caller-owned QUIC transport, with HTTP/3 and QPACK outside SharpTls entirely.

**That premise is now false.** SharpTls on this branch contains a QUIC v1 transport
(`src/SharpTls/Quic/`, ~57 files), an HTTP/3 layer, and a QPACK implementation with a dynamic
table. It has completed live HTTP/3 requests against two public endpoints. `System.Net.Quic` and
MsQuic are not on the request path; MsQuic appears only as a test peer.

The remaining question is no longer "is there a transport" but **"is the transport finished, and
is there a client around it"**. The answer to both is still no.

## Condition-by-condition status

| # | Condition | 2026-07-21 | 2026-08-22 |
| --- | --- | --- | --- |
| 1 | SharpTls bytes, no platform TLS, ClientHello preserved | not met | **met** |
| 2 | QUIC v1 transport: packets, recovery, congestion, close | not met | **partially met** |
| 3 | Fuzz + interop against two implementations under impairment | not met | **partially met** |
| 4 | HTTP/3 layer: control streams, SETTINGS, QPACK, GOAWAY, cancellation, priorities | not met | **mostly met** |
| 5 | Client semantics: pooling, DNS/ECH, proxy, retries, redirects, cookies, telemetry, 0-RTT | not met | **partially met** (pooling, redirects, cookies, retries, SOCKS5 proxy transport) |
| 6 | Three-OS CI running deterministic protocol tests | not met | **partially met** |
| 7 | Independent security review | not met | **not done** |

### 1. Caller-owned SharpTls bytes, no platform TLS, ClientHello preserved — **met**

`src/SharpTls/Quic/CustomTlsQuicClient.cs` drives the QUIC-TLS handshake; the ClientHello is
composed by `src/SharpTls/ClientHello/TlsQuicClientHelloProfileFactory.cs`. No platform TLS is
involved on the request path; `CustomTlsQuicClient.cs:931-933` rejects even the TLS `KeyUpdate`
message, per RFC 9001.

The load-bearing evidence is that the bytes on the wire come from `src/` and not from a test
fixture. The B11 live run
(`SharpTls/docs/superpowers/specs/reference-captures/2026-08-20-sharptls-b11-live-run-through-the-factory.md`,
test at `2247128`, factory seam at `f83331f`) is the first run where they did: three arms, with
`perk_hash` / `perk_hash_normalized` predictions written into the test's own header comment above
the code that ran them, read back by `fp.impersonate.pro`. Three of four `perk` segments match
Brave 151.

This matters because it was previously false in a way nobody noticed: the SharpTls handoff records
that **nothing in `src/` composed a client transport-parameter list at all** before subsystem B —
every composing call site was under `tests/`, so "we send 8 transport parameters" described a
fixture, not the library.

### 2. QUIC v1 transport — **partially met; this is the condition A3 is still failing**

Landed and reviewed:

- Packet layer (subsystem A1, 10 tasks): `TlsQuicPacketBuilder.cs`, `TlsQuicPacketProtection.cs`,
  `TlsQuicHeaderProtection.cs`, `TlsQuicPacketNumber.cs`, `TlsQuicPacketReceiver.cs`.
- Frame layer (subsystem A2, 7 tasks): all twenty frame types parse and serialise;
  RFC 9000 §12.4's legality table is encoded as data in `TlsQuicFrameLegality.cs` with all 80
  cells independently verified.
- Retry and version negotiation: `TlsQuicRetry.cs`, `TlsQuicVersionNegotiation.cs`.
- Transport parameters: `TlsQuicTransportParameters.cs`, `TlsQuicTransportParameterSpec.cs`.
- Flow control, after a defect that no handshake test could have seen — advertising no limits left
  every peer limit at 0, and `TlsQuicStreamSet`'s independent 1 MiB / 64-stream constants were
  deleted so that the enforced bound is the advertised bound (`7ee8536`, `21b025b`, `38c9580`).
- Connection close, both forms, fixed after `BuildCloseDatagram` was found walking only packet
  spaces already discarded by RFC 9001 §4.9 — meaning **no `CONNECTION_CLOSE` of either form could
  leave the client after handshake confirmation** (`9410755`).
- Key discard: `TlsQuicKeySet.DiscardKeys`, driven from `TlsQuicConnection.cs:2443-2445`.
- Loss detection and probe timeout are **wired and live** as of A3-7 (`2ade68e`): RFC 9002 A.7's
  `OnAckReceived`, A.8's `SetLossDetectionTimer` arming ladder and A.9's `OnLossDetectionTimeout`
  all run inside `TlsQuicConnection.PumpOnceAsync`, witnessed by a datagram the A3-1 impairing
  decorator really dropped.

Not landed — **do not read the above as "recovery is done"**:

- **Subsystem A3 is 10 of its 15 tasks, not 12.** Committed: A3-0 `2304698`, A3-1 `8497f60`,
  A3-2 `0e4d07c`, A3-3 `744b0ce`, A3-4 `83895b6`, A3-5 `1a17be7`, A3-6 `2d805be`, A3-7 `2ade68e`,
  A3-9 `889509c`, A3-10 `fdf1b9d`. Outstanding: **A3-8 retransmission**, A3-11 pacing,
  A3-12 the recovery fingerprint readout, A3-13 the live run under induced loss, A3-14 the timing
  capture. (The A3 table in `HANDOFF-http3-quic.md` still reads "8 of 15"; it was written at
  `1a17be7` and four A3 commits have landed since. The plan's task list is
  `SharpTls/docs/superpowers/plans/2026-08-21-quic-a3-recovery-and-congestion.md:589-1098`.)
- **A3-8 is the sharpest gap. A packet can be declared lost and nothing re-sends it.** Loss
  detection now names the loss; the response to it is not written.
- **NewReno exists but is not wired.** `TlsQuicNewRenoCongestionController`
  (`TlsQuicCongestionControl.cs:384`) is reachable only through the optional factory hook
  `TlsQuicRecoverySpec.CongestionController` (`TlsQuicRecoverySpec.cs:620`), which is a nullable
  `Func<>`. `TlsQuicConnection.cs` never constructs or consults a congestion controller — the file
  names `OnPacketsLost` as the one part of A.9 that A3-7 left unwired. **In effect the client
  currently has no congestion control on the send path.** That is the single clearest reason
  condition 2 is not met.
- **Key update (RFC 9001 §6, the 1-RTT key phase) is not implemented.** `KeyPhase` exists as a bit
  on `TlsQuicPacketBuilder` (`TlsQuicPacketBuilder.cs:111`); no key-update derivation was found.
  It belongs to subsystem A4, which is complete only in the "A4-minimal" sense — its landed pieces
  are the MsQuic loopback gate (`776bc07`) and the 1-RTT close fix (`9410755`).
- `initial_rtt` remains a **narrowed but open** divergence: `TlsQuicConnectionSpec.InitialRttRange`
  still defaults to `null`, so an unconfigured client advertises `Brave151InitialRttRange`'s
  100-300 ms as transport parameter 12583 while its own estimator starts from RFC 9002's
  `kInitialRtt` of 333 ms. A3-7 gave the knob a caller under `src/` but deliberately did not close
  the default. `Brave151InitialRttRange`'s maximum sits below 333 ms, which is what makes the
  divergence observable on the wire.

### 3. Fuzz and interop under impairment — **partially met**

Genuinely covered:

- **A foreign QUIC implementation, at handshake level only.**
  `tests/SharpTls.Tests/Interop/MsQuicLoopbackTests.cs` (`776bc07`) completes two handshakes
  against a `System.Net.Quic` listener. It is one test, it is handshake-only, and
  `MsQuicLoopbackFactAttribute` **skips rather than fails** when `QuicListener.IsSupported` is
  false — so a green CI run is not by itself evidence that it ran.
- **Two live public h3 endpoints**, `fp.impersonate.pro` and `tls3.peet.ws`
  (`QuicPublicEndpointInteropTests.cs:42`), behind `SHARPTLS_RUN_INTEROP=1`. C13 (`44e4e1e`)
  records **0 failures in 20 attempts**, every one HTTP 200 with a complete body and
  `discarded=0`, spanning three unidirectional stream headers, SETTINGS, HEADERS and a 4,955-byte
  response.
- **A real interop defect found and closed on the wire.** C16 stopped a test narrowing its
  SETTINGS, and `fp.impersonate.pro` began closing every attempt with `H3_SETTINGS_ERROR`
  (`0x0109`). C17 (`e1c3110`) isolated it across **24 whole connections, one variable per arm**:
  0/3 with `SETTINGS_H3_DATAGRAM = 1` and no RFC 9221 `max_datagram_frame_size`; 3/3 with the
  transport parameter added and nothing else changed. No such rule exists in RFC 9297 — it is
  deployed quic-go behaviour, so SharpTls now ties the two halves locally rather than learning
  about it as a remote `0x109`.
- **Deterministic impairment exists**: `tests/SharpTls.Tests/Quic/ImpairingDatagramTransport.cs`
  and its tests (A3-1, `8497f60`) drop, duplicate, reorder and delay on a fake clock. It was built
  because **zero of six existing transports could impair anything** — the prior scoping assumed
  otherwise and was wrong. It also pinned that **nothing deduplicates a received packet number**;
  A3-4's RFC 9002 §5.1 "newly acknowledged" gate handles the consequence.
- `quic-packets` and `quic-frames` fuzz targets exist and are in the default target list
  (`tools/SharpTls.Fuzz/ProtocolFuzzTargets.cs:34-35`).

Not covered — the condition asks for more than this:

- **The impairing transport has never driven a live or foreign peer.** A3-13, "the live run under
  induced loss", is not committed. All 30 live attempts on record (C13's 20, A4's 10) ran on a
  clean path on one day, on one network. The captures say so themselves.
- **CI's coverage-guided fuzz job does not run the QUIC targets.**
  `.github/workflows/ci.yml`'s `coverage-fuzz` step hardcodes
  `targets=(clienthello serverflight certificates records sessions ech-quic-dns state-machines)` —
  `quic-packets`, `quic-frames` and `socks5` are absent from it, and the job runs only on schedule,
  manual dispatch or a `v*` tag.
- **There is no QPACK or HTTP/3 fuzz target at all.** Condition 7 names QPACK explicitly.
- **The second implementation is thin.** MsQuic covers the handshake; the two public endpoints are
  servers of undeclared stack; quic-go was read as source in `e1c3110`, not run against. No
  interop matrix under reordering, duplication or loss against any foreign implementation exists.

### 4. HTTP/3 layer — **mostly met, with two named holes**

Present: control and unidirectional streams, SETTINGS, GOAWAY with the RFC 9114 §5.2 identifier
MUSTs (`TlsQuicHttp3Streams.cs:825`, `TlsQuicHttp3Connection.cs:656`), request and response
streams with H3_MESSAGE_ERROR, the §4.2 field ban and §4.1.2 (C9 `9fbfcdc`, C10 `239ea25`,
C10b `ac3a2e5`, C10c `15a9b0b`, C11 `eb7d668`), a fingerprint readout (C12 `ac43deb`), and RFC
9221 DATAGRAM parse-and-drop (C17 `e95fa3c`).

QPACK is genuinely beyond a static-table decoder: static table, Huffman, a **dynamic table the
peer's encoder drives** (C14 `e8b4976`), **§4.4 decoder-stream instructions** wired into the
decoder (C15 `bd1ed29`), and **blocked decoding** (C16 `bea2654`). C14's finding is worth carrying:
three prefix-width mutants survived the entire RFC 9204 Appendix B-anchored walk, because every
literal the RFC publishes sits below the narrower mask. **Anchoring tests to published vectors is
necessary and not sufficient.**

Holes, both verified by search rather than assumed:

- **Request cancellation has no caller.** `RESET_STREAM` and `STOP_SENDING` exist only as frame
  codec (`TlsQuicConnectionFrames.cs:207,290,896,950`; `TlsQuicFrames.cs:503,510,881,884`). Nothing
  in `TlsQuicHttp3Connection.cs`, `TlsQuicHttp3Request.cs`, `TlsQuicHttp3Streams.cs`,
  `TlsQuicStreams.cs` or `TlsQuicConnection.cs` emits either to abort a request in flight. An
  HTTP/3 client that cannot cancel a response it no longer wants is not finished.
- **Priorities are absent.** No match for RFC 9218, `PRIORITY_UPDATE` or frame type `0xF0700`
  anywhere under `src/`. The condition says "priorities when selected", so this is not
  automatically a failure — but nothing selects them and nothing could.
- Graceful draining was not verified either way. CONNECTION_CLOSE of both forms exists
  (`9410755`) and GOAWAY is honoured for new requests, but no explicit RFC 9000 §10.2 draining
  period was located. **Treat this as unknown, not as met.**

### 5. Client semantics for HTTP/3 — **four of nine features met, the rest not started**

The four that are met are **pooling, redirects, cookies and retries**, witnessed by
`Http3ClientMachineryTests`. Three of them already worked, because the machinery sits above
`IHttpConnection` and does not ask which protocol answered; what they lacked was any evidence,
since every HTTP/3 test before that file bypassed `TlsSession` entirely — `Http3LiveTests` drives
`Http3Connection.SendAsync` directly and `Http3StreamMultiplexerTests` drives the read loop. The
fourth, retries, was genuinely broken.

- **Pooling — works.** `ConnectionKey` carries the version policy, so an `Http3Only` request is
  never answered by a pooled TCP connection and the reverse cannot happen either. A second request
  to one origin reuses the first's QUIC handshake, requests overlap on one connection up to the
  peer's allowance, a spent `initial_max_streams_bidi` retires the connection rather than failing
  the request, and disposing a session with a request in flight does not deadlock.
- **Redirects — work, and stay on HTTP/3.** `BufferedRequest.Redirect` preserves
  `HttpVersionPolicy`, so every hop of a redirect chain is dialled `Http3Only`; a same-origin hop
  reuses the connection it arrived on. Asserting the *policy each hop was dialled with* is the
  point: a hop dialled `PreferHttp2` that happened to negotiate h3 would pass a weaker check and
  still be the silent downgrade this project forbids.
- **Cookies — work.** A `Set-Cookie` received over h3 is stored and returned on the next h3
  request, and `Http3FieldMapper` turns that header into RFC 9114 §4.2.1's `cookie` field. A
  cross-origin redirect does not carry the first origin's cookies to the second.
- **Retries — were broken, now fixed.** `Http3StreamMultiplexer`'s read loop meets two QUIC
  failure shapes, its deadline passing and the peer sending CONNECTION_CLOSE, and reported both as
  a `TlsHttpProtocolException` — the single type `TlsSession.ShouldRetryException` refuses to
  retry. An idempotent h3 GET whose connection died therefore failed outright where the identical
  h2 GET was retried, because `Http2Connection`'s loop wraps a dead transport in a plain
  `IOException`. HTTP/3 now draws the same line: an RFC 9114 §8.1 error code stays terminal, a dead
  transport is retryable, and `RetryNonIdempotentMethods` still defaults to false so a POST is
  reported rather than sent twice.

Three things are pinned as findings rather than fixed. **`PooledConnectionLifetime =
Timeout.InfiniteTimeSpan` does not give an unbounded HTTP/3 connection, it gives five minutes.**
`TlsSessionOptions` explicitly accepts the infinite value, and HTTP/1.1 and HTTP/2 connections then
really do live indefinitely; `Http3Connection.Bounded` falls back to `DefaultConnectionLifetime`
because a QUIC deadline must be finite and positive. That is defensible — the alternative is a
connection whose receives never time out — but it is an asymmetry a caller who set the knob would
not predict, and it is the only case in which the five-minute default is reachable at all, since
any finite setting overrides it. A pooled h3 connection carries at most **half**
its remaining stream allowance concurrently, because `TlsConnectionPool.CanAcceptRequest` compares
in-flight leases against a *lifetime* allowance those same leases have already drawn down —
correct for `Http11Connection`'s constant 1 and `Http2Connection`'s fixed
SETTINGS_MAX_CONCURRENT_STREAMS, and double-counting for HTTP/3's remainder. The cost is an extra
handshake, never a failure, and against a real server's allowance the ceiling never binds. And the
QUIC deadline and the pool's own lifetime clock **do not start together**:
`TlsQuicConnectionOptions.HandshakeDeadline` is set from `PooledConnectionLifetime` when the
handshake starts, while the pool's expiry runs from when the connection entered the pool, one
handshake later. What keeps a dead connection out of a caller's hands during that window is
`Http3Connection.IsReusable` reading `!_multiplexer.IsStopped` — the read loop observing the
deadline — and not the pool's arithmetic. The pool consumes that flag at **two independent gates**,
and a mutation sweep established which one carries the claim: deleting the `IsReusable` read from
`CanAcceptRequest` (selection) changes nothing, because `RemoveExpiredConnectionsLocked` (eviction)
runs first on every rent and disposes the entry before selection ever sees it; deleting it from the
eviction pass fails the test on its own. Selection is defence in depth here, not the mechanism.

**Proxy support landed for the only type that can carry QUIC.** Subsystem D's SOCKS5 UDP relay
(`TlsQuicSocks5Transport.cs`) had been built and left with no caller: `Http3Connection` hardcoded
the direct UDP transport, so `HttpConnectionFactory` refused every proxied h3 request. It now
selects the relay from `options.Proxy`, and the refusal is narrowed to HTTP CONNECT and SOCKS4 —
which genuinely cannot relay datagrams — and names the type it is refusing. What is still absent
is proxy POLICY rather than proxy transport: no per-origin bypass rules, no proxy
auto-configuration, and DNS is still resolved locally rather than at the proxy, so a relayed
connection does not hide the lookup.

Still not started: **DNS and ECH bootstrapping for h3, response streaming semantics, telemetry,
session resumption**, and — most sensitive of all — an **explicit 0-RTT replay policy with
HTTP/3 semantics**.

### 6. Three-OS CI running deterministic protocol tests — **partially met**

`.github/workflows/ci.yml`'s `test` job runs `dotnet test SharpTls.slnx` on `ubuntu-latest`,
`macos-latest` and `windows-latest`, so the deterministic QUIC and HTTP/3 unit tests do run on all
three. Public interoperability is correctly isolated: the `public-interop` job sets
`SHARPTLS_RUN_INTEROP=1` and runs only on schedule, dispatch or tag, and `InteropFactAttribute`
(`PublicServerInteropTests.cs:572-584`) skips those tests otherwise.

What keeps this from a tick:

- The QUIC fuzz targets are not in the coverage-fuzz job (see condition 3).
- The MsQuic loopback gate skips silently where msquic is unavailable, so "CI is green" does not
  imply "we were checked against a foreign implementation on that runner".
- The SharpTls handoff instructs contributors to gate on
  `dotnet test --filter "FullyQualifiedName~Quic"` rather than the full suite, and records that
  this filter has a **blind spot**: `PublicApiBaselineTests.ExportedApiMatchesTheReviewedBaseline`
  does not match `~Quic`, so public API drift on QUIC types passes the working gate.
- **None of this CI covers TlsClient's HTTP/3 integration, because that integration does not exist
  in a commit yet.**

### 7. Independent security review — **not done**

No security review of the QUIC or HTTP/3 code exists. SharpTls has `docs/THREAT-MODEL.md` and
`docs/RELEASE-HARDENING.md`, but neither is an independent review and neither covers packet
parsing, loss recovery, stream state, QPACK, amplification, resource exhaustion or 0-RTT replay for
this branch. The branch has not been pushed, so no external party has seen the code.

## What "available today" means

**An opt-in, compile-error-gated experiment. Not a supported transport.**

The "Current API behavior" section above — HTTP/3 rejected with `NotSupportedException`, no `h3`
ALPN — was true when this amendment's condition scoring was written and stopped being true hours
later. SharpTls `f2e3242` widened its internals so TlsClient could be wired to them, and TlsClient
`916ae61` did the wiring: `TlsHttpVersionPolicy.Http3Only` routes to QUIC, `BufferedRequest`
accepts `Version` 3.0, and ALPN offers `h3` alone and only for `Http3Only`.

**That is not the gate being passed, and the wiring says so itself.** `Http3Only` is marked
`[Experimental("TLSCLIENT3")]`, so selecting it is a compile error until a caller explicitly
acknowledges it. There is deliberately **no `PreferHttp3`**: no Happy Eyeballs, no racing, no
fallback from QUIC to TCP, because "prefer" could only mean a silent retry over another transport,
which is the silent wire change this project forbids. Proxied `h3` is refused outright — TlsClient
proxies are TCP CONNECT tunnels.

So a caller who opts in today gets `h3` over a transport with **no congestion control, no
retransmission of packets it has itself declared lost, no key update, and no request
cancellation**, with none of condition 5 around it, against a SharpTls that is not released. Every
one of those is a property a caller cannot see from the API surface, which is why the experimental
attribute and this document are the only places they are stated. If `Http3Only` ever loses the
`[Experimental]` marking, this section is the thing to re-read first.

## What is still missing before HTTP/3 is production-ready

In rough order of what a reader should worry about:

1. **The rest of condition 5.** Pooling, retries, redirects and cookies are done and witnessed;
   proxy policy, DNS/ECH, response streaming semantics, telemetry, resumption and the 0-RTT replay
   policy are not begun. The replay policy is the one to worry about, because 0-RTT is the only
   item on that list whose absence is a security question rather than a missing feature.
2. **A3-8 retransmission, and wiring NewReno into `TlsQuicConnection`.** Today a lost packet is
   detected and abandoned, and the send path is unthrottled.
3. **Request cancellation with a real caller**, and a decision on priorities.
4. **Key update** (subsystem A4), and closing the `initial_rtt` default divergence.
5. **Interop and fuzz that match the condition**: QUIC and QPACK/HTTP/3 fuzz targets in CI, and a
   run under the A3-1 impairing transport against a foreign peer (A3-13).
6. **An independent security review** — which cannot start until the branch is pushed.
7. **A released SharpTls.** Until then TlsClient's HTTP/3 support cannot be shipped to anyone who
   does not build both repositories from source.

## Standing

The 2026-07-21 deferral is **not lifted**. It remains a protocol-integrity decision rather than a
rejection of HTTP/3, exactly as originally written. Subsystem E has now begun (`916ae61`), so the
next triggers to revisit this amendment are: subsystem A3 completing, condition 5 acquiring any
implementation at all, or the SharpTls branch being pushed and reviewed. **Do not drop
`[Experimental("TLSCLIENT3")]` from `Http3Only` before at least conditions 2, 3 and 5 are met.**
