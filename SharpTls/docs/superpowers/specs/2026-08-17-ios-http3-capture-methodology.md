# Capturing an iOS app's HTTP/3 and QUIC fingerprint from Windows

Date: 2026-08-17
Status: setup plan, not yet executed
Goal: record a specific iOS app's per-host QUIC and HTTP/3 fingerprints as subsystem B targets

## Constraints this setup is built around

- **Windows host.** `rvictl`, the usual iOS capture route, is macOS only. Not available.
- **iPhone on iOS 26**, same LAN, no jailbreak.
- **The app is confirmed to use HTTP/3**, and does not pin certificates.
- **All requests must keep working**, not just the first — so this terminates and forwards
  rather than dead-ending the connection.
- **The app uses different networking stacks per API host.** Some hosts go through
  CFNetwork, others through the newer Network.framework/URLSession path.

## The per-host finding changes the target

Two networking stacks means two different fingerprints from the same app. CFNetwork and
Network.framework do not necessarily agree on ALPN, extension order, QUIC transport
parameter set and order, or HTTP/3 SETTINGS.

Consequences:

1. **Capture per host, not per app.** Record which stack served which hostname, and keep the
   readouts separate. A single merged "the app's fingerprint" would be wrong for at least one
   host.
2. **Subsystem B needs host-keyed profile selection**, not one profile per client. A single
   session must be able to present different fingerprints to different origins — the same
   shape TlsClient already uses for per-request proxy selection.
3. **Which stack is in play is itself evidence.** If one host gets CFNetwork and another gets
   Network.framework, that mapping is stable app behaviour worth recording alongside the
   fingerprints.

## Approach: mitmproxy in WireGuard mode

WireGuard mode is the reason this works on Windows without routing tricks. The phone joins a
WireGuard tunnel that mitmproxy terminates, so **all** traffic arrives at mitmproxy — TCP and
UDP, every host, no DNS override, no hotspot, no transparent-proxy OS plumbing.

That last point matters: mitmproxy's transparent mode depends on OS-level redirection that is
poorly supported on Windows, and an iOS Wi-Fi HTTP proxy does not carry UDP at all, so it
cannot see QUIC. WireGuard mode sidesteps both.

### Steps

1. **Install mitmproxy on Windows.** Needs a version with both WireGuard mode and HTTP/3.
   WireGuard mode landed in v9, HTTP/3 in v10. Use current stable.

2. **Start it in WireGuard mode with upstream forwarding and secrets logging.** Verify the
   current flag syntax against the installed version's `--help` rather than trusting any
   syntax written here — mitmproxy's QUIC and mode flags have moved between releases.
   Required behaviours: WireGuard server mode, HTTP/3 enabled, TLS secrets written to a
   keylog file.

3. **Install the WireGuard app on the iPhone** and scan the QR code mitmproxy prints. That is
   the whole client-side network setup.

4. **Install mitmproxy's CA on the iPhone.** Browse to `mitm.it` through the tunnel, install
   the profile, then **Settings → General → About → Certificate Trust Settings** and enable
   full trust. Two separate steps; the second is the one people miss.

5. **Run Wireshark on the Windows host** and point Preferences → Protocols → TLS →
   (Pre)-Master-Secret log filename at mitmproxy's keylog file.

6. **Trigger the app.**

### What one capture then yields, per host

| Layer | Fields |
| --- | --- |
| QUIC | source and destination CID lengths, initial packet number and its encoded length, token length and prefix, datagram count and sizes in the Initial flight, CRYPTO frame splitting, frame ordering, padding target |
| TLS | full ClientHello, extension wire order, JA3/JA4, key shares, and the `quic_transport_parameters` extension with its parameter order |
| HTTP/3 | SETTINGS frame in wire order, the GREASE entry, pseudo-header order, full header list, priority |

The QUIC layer needs no keys at all — Initial packets decrypt from the published salt, keyed
by the destination connection ID carried in the same packet. The keylog is only required for
Handshake and 1-RTT, which is where HTTP/3 lives.

## Capture discipline

- **Cold connections only.** A resumed session sends 0-RTT and a ticket, and its Initial
  differs from first contact — different token, different flight shape. Fresh install or
  cleared app state.
- **Record the first flight separately from any retry.** If a request fails and the app
  retries, the retry can differ: h2 fallback, different path, altered headers. Retries are
  worth recording as their own artefact, but must not be merged into the primary fingerprint.
- **Only the app-to-proxy direction is the target.** Everything downstream of mitmproxy is
  mitmproxy's fingerprint, not the app's.
- **Note the stack per host** — CFNetwork or Network.framework — beside each readout.

## Confirmed and outstanding risks

### Resolved: WireGuard mode does support HTTP/3

mitmproxy 11 (October 2024) ships HTTP/3 in reverse, local **and** WireGuard modes, built on
aioquic. `mitmproxy --mode wireguard` is the documented invocation. This was the plan's one
untested assumption and it holds.

### New top risk: user-added CAs may not be trusted for QUIC

mitmproxy's own release notes state that **Chrome does not trust user-added Certificate
Authorities for QUIC**, and falls back to HTTP/2 as a result. Their suggested workarounds do
not transfer to this situation: a publicly trusted certificate cannot be obtained for a
domain we do not own, and there is no command-line switch on iOS.

Whether CFNetwork and Network.framework impose the same restriction is **unknown and must be
tested first**. It is now the single fact that decides whether the HTTP/3 layer is reachable
at all.

Test it before building anything else: point one host through mitmproxy and check whether the
app negotiates h3 or silently drops to h2. A fallback to h2 is the failure signal.

If iOS does refuse user CAs for QUIC, the HTTP/3 layer is not obtainable by interception on
an unjailbroken device, and the honest position is QUIC-layer replication plus HTTP/3
approximated from a browser on the same engine.

### QUIC v1 only

mitmproxy supports QUIC version 1 and **not** version 2 (RFC 9369). Check which version the
app negotiates — visible in the cleartext long header, so passive capture answers it in
seconds. A v2 client cannot be intercepted by mitmproxy at all.

### mitmproxy's HTTP/3 is lightly tested outside cURL

Its documentation states HTTP/3 support has been extensively tested with cURL, and names
Firefox and Chrome among tested clients. iOS networking stacks are not mentioned. Expect
compatibility bugs and treat an unexplained failure as possibly mitmproxy's rather than the
setup's.

### ECH stripping changes what gets captured

mitmproxy strips Encrypted Client Hello keys from DNS HTTPS records so that the client cannot
encrypt its ClientHello and mitmproxy can still read the SNI to mint a certificate.

That means an intercepted capture shows the **non-ECH variant** of the ClientHello. If the app
normally uses ECH, the real-world wire image differs from what is recorded. Note which variant
each capture represents. Passive capture, which does not strip anything, is the way to see
what the app really sends when ECH is available.

## Do the passive capture first, regardless

This path needs no CA, no interception, and no cooperation from the app, and it cannot be
blocked by any of the risks above:

**Windows Mobile Hotspot**, iPhone connected to it, Windows as the gateway, Wireshark on the
hotspot adapter. Initial packets decrypt from the published salt, so this alone yields the
complete QUIC layer for every host, plus the real ClientHello including ECH if present, plus
the negotiated QUIC version.

Only the HTTP/3 layer requires the mitmproxy setup. Getting the passive capture first means a
CA-trust or compatibility failure costs the h3 layer rather than the whole exercise.

## Fallback for the HTTP/3 layer

If mitmproxy proves incompatible with the app's stacks — but user CAs *are* trusted for QUIC —
a per-host DNS override plus a local HTTP/3 server (`aioquic` or `quic-go`) forwarding upstream
gives the same result with full control over logging. More work per host, but it is close in
shape to the in-repo verification server subsystem B will eventually want anyway.

## Output format

Record each host's readout in the same shape as
`reference-captures/the preset that measured it`, one file per host, noting
the networking stack. Those files become subsystem B's acceptance targets directly.

Redact credentials before committing. A client capture had a live `cf_clearance` cookie in
it; an app capture will contain auth tokens, device identifiers and session cookies. Strip
them.
