# Reference capture: Brave 151 (Chromium 151) over HTTP/3

Source: `https://fp.impersonate.pro/api/http3`
Captured: 2026-08-16, Windows 10/11 x64
User agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36`

The `cookie` header value in the original response was a live Cloudflare `cf_clearance`
token and has been redacted. Nothing else is altered.

This is the target for subsystem B. Everything below is what a real browser puts on the
wire; anything we emit that differs is a fingerprint defect.

## QUIC layer

```json
"quic": {
  "client_connection_id_length": 0,
  "server_connection_id_length": 8
}
```

Two facts, both load-bearing:

- **The client's source connection ID is zero-length.** Chromium does not ask the server to
  route by client CID. This is uQUIC's `SrcConnIDLength = 0`.
- **The destination connection ID the client generates for the server is 8 bytes.** uQUIC's
  `DestConnIDLength = 8`. For contrast, Firefox 116 is fingerprinted three separate ways on
  this field alone at 8, 9 and 15 bytes.

Note what this service does **not** inspect: initial packet number and its encoded length,
token length and prefix, per-datagram Initial flight plans, CRYPTO frame splitting, frame
ordering, datagram padding target. Those remain unverifiable by either endpoint and need a
packet capture.

## The `perk` fingerprint format

impersonate.pro's HTTP/3 fingerprint, analogous to Akamai's HTTP/2 string. Four
pipe-separated parts:

```
<h3 settings> | <pseudo-header order> | <quic transport parameters, wire order> | <cid lengths>
```

Observed:

```
1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p|12584:0x4f524947;GREASE;32:65536;9:103;8:100;7:6291456;5:6291456;15:AUTO;17:1@GREASE,1;1:30000;6:6291456;4:15728640;12583:AUTO;3:1472|0,8
```

- `perk_hash` = `7d726b1554d23ae0ffb3e8c533f20a2f`
- `perk_hash_normalized` = `733abf232de1c065c494640332f04555`

The normalized form sorts transport parameters by ID; the raw form preserves wire order.
**Both are published, so wire order is fingerprinted and must be reproduced exactly** —
sorting the parameters would change `perk_hash` while leaving `perk_hash_normalized` intact.

The trailing `|0,8` is the connection ID length pair, confirming those two fields feed the
hash directly.

## HTTP/3 SETTINGS

| ID | Name | Value |
| --- | --- | --- |
| 1 | `SETTINGS_QPACK_MAX_TABLE_CAPACITY` | 65536 |
| 6 | `SETTINGS_MAX_FIELD_SECTION_SIZE` | 262144 |
| 7 | `SETTINGS_QPACK_BLOCKED_STREAMS` | 100 |
| 51 | `SETTINGS_H3_DATAGRAM` | 1 |
| 126585778853 | GREASE | 2585972839 |

Pseudo-header order: `:method`, `:authority`, `:scheme`, `:path` — `m,a,s,p`.

## QUIC transport parameters, in wire order

This ordering is the fingerprint. It is not sorted, and it is not the RFC's presentation
order.

| # | ID | Name | Value |
| --- | --- | --- | --- |
| 1 | 12584 | `google_connection_options` | `0x4f524947` (ASCII `ORIG`) |
| 2 | GREASE | — | `0xfb` |
| 3 | 32 | `max_datagram_frame_size` | 65536 |
| 4 | 9 | `initial_max_streams_uni` | 103 |
| 5 | 8 | `initial_max_streams_bidi` | 100 |
| 6 | 7 | `initial_max_stream_data_uni` | 6291456 |
| 7 | 5 | `initial_max_stream_data_bidi_local` | 6291456 |
| 8 | 15 | `initial_source_connection_id` | empty, consistent with a zero-length source CID |
| 9 | 17 | `version_information` | chosen 1, available `[GREASE, 1]` |
| 10 | 1 | `max_idle_timeout` | 30000 |
| 11 | 6 | `initial_max_stream_data_bidi_remote` | 6291456 |
| 12 | 4 | `initial_max_data` | 15728640 |
| 13 | 12583 | `initial_rtt` | 192859 |
| 14 | 3 | `max_udp_payload_size` | 1472 |

Three of these need comment.

**`initial_rtt` (12583) is randomised per connection.** 192859 is not a constant to copy —
uQUIC models this as `ChromeRandomInitialRTT()`. A fixed value here would itself be a
fingerprint. The `perk_text` reflects this by rendering it `12583:AUTO` rather than
embedding the number, and does the same for `initial_source_connection_id` at `15:AUTO`.

**`max_udp_payload_size` (3) is 1472**, which is 1500 − 20 (IPv4) − 8 (UDP). Chromium
advertises a path-derived value, not the RFC 9000 default of 65527. This interacts directly
with the SOCKS5 work: subsystem D reports a ceiling of 65527 − 10, but a Chrome-imitating
client must *advertise* 1472 regardless of what its transport can carry. Advertised
parameter and actual ceiling are separate concerns and must not be wired together.

**Two GREASE values appear**, one as a transport parameter (id ≈ 3.7457e18, value `0xfb`)
and one inside `version_information`'s available-versions list. Both are positional.

## TLS layer, carried inside the QUIC handshake

JA3: `771,4865-4866-4867,27-43-45-17613-65037-16-51-10-57-13-0,4588-29-23-24,`
JA3 hash: `c115e578d8176dbed83ee8c80fd78f55`
JA3N hash: `36b3da67265214a919829c5e959f7425`

Cipher suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`.

Extensions in wire order: 27 `compress_certificate` (brotli), 43 `supported_versions`
(TLS 1.3), 45 `psk_key_exchange_modes`, 17613 `alps_new` (`h3`), 65037
`encrypted_client_hello` (218 bytes, outer, HKDF-SHA256 + AES-128-GCM, config id 196),
16 `alpn` (`h3`), 51 `key_share`, 10 `supported_groups`, 57 `quic_transport_parameters`,
13 `signature_algorithms`, 0 `server_name`.

Key shares: **X25519MLKEM768 at 1216 bytes**, plus X25519 at 32 bytes.

That 1216-byte post-quantum share is why Chromium's Initial does not fit one datagram. It is
the direct cause of the two-datagram Initial flight that uQUIC models as
`InitialPackets []InitialPacketPlan` — the field neither verification endpoint can observe,
and the one most likely to be wrong without a packet capture.

Supported groups: X25519MLKEM768 (4588), X25519 (29), P-256 (23), P-384 (24).

## What this capture settles

1. Connection ID lengths are fingerprinted and published: `0` and `8`.
2. Transport parameter **wire order** is fingerprinted, and SharpTls can already express it
   through `TlsQuicTransportParameters` and `ClientHelloBuilder.WithQuicTransportParameters`.
3. `initial_rtt` must be randomised, not pinned.
4. `max_udp_payload_size` is an advertised value independent of the transport's real ceiling.
5. The post-quantum key share forces a multi-datagram Initial, so that path is required, not
   optional.
