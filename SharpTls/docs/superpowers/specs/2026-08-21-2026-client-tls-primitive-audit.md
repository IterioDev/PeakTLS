# 2026 client TLS primitive audit

**Date:** 2026-08-21
**Scope:** research and documentation only. No source changed.
**Question:** what does a 2026 mainstream browser put in its ClientHello that SharpTls
cannot express, or can express but has no profile for?

The starting premise for this audit was that SharpTls is far more complete than a
casual read suggests. That premise held. It is also, in one respect, *more* complete
than the brief that commissioned this audit claimed — see
[Corrections to the commissioning brief](#corrections-to-the-commissioning-brief).

---

## Sources

Every codepoint in this document was read from one of these. Nothing is recalled.

| Tag | Source | Fetched |
| --- | --- | --- |
| S1 | uTLS `u_common.go` @ `master` — `https://raw.githubusercontent.com/refraction-networking/utls/master/u_common.go` | 2026-08-21 |
| S2 | uTLS `u_parrots.go` @ `master` — `HelloChrome_133` L894, `HelloFirefox_148` L1469, `HelloSafari_26_3` L2242 | 2026-08-21 |
| S3 | uTLS commit history via GitHub API (`/repos/refraction-networking/utls/commits?path=u_common.go`) and `/releases` | 2026-08-21 |
| S4 | IANA **TLS Supported Groups** registry — `https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv` | 2026-08-21 |
| S5 | IANA **TLS ExtensionType Values** registry — `https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv` | 2026-08-21 |
| S6 | BoringSSL `include/openssl/tls1.h` @ `main` — `TLSEXT_TYPE_*` | 2026-08-21 |
| S7 | BoringSSL `include/openssl/ssl.h` @ `main` — `SSL_GROUP_*`, `SSL_SIGN_*` | 2026-08-21 |
| S8 | BoringSSL `ssl/ssl_key_share.cc` @ `main` — `kNamedGroups`, `DefaultSupportedGroupIds()` | 2026-08-21 |
| S9 | Chromium `net/socket/ssl_client_socket_impl.cc` @ `main` (gitiles, `?format=TEXT`) | 2026-08-21 |
| S10 | Chromium `net/base/features.cc` @ `main` | 2026-08-21 |
| S11 | Chromium commit history for `net/socket/ssl_client_socket_impl.cc` via GitHub API | 2026-08-21 |
| S12 | In-repo live capture: `docs/superpowers/specs/reference-captures/2026-08-16-brave-151-http3-impersonate-pro.md` | in tree |

SharpTls evidence is cited as `file:line` from greps I ran myself; the exact greps are
listed in [Greps run](#greps-run).

### Column key

`Sent by` — **C** = Chrome/Chromium (incl. Brave/Edge), **F** = Firefox, **S** = Safari/iOS.

`Verdict` — exactly three values, as used elsewhere in this project:

- **`supported-and-profiled`** — SharpTls can emit it *and* at least one shipped profile does.
- **`supported-but-no-profile`** — SharpTls can emit it, but nothing in `src/SharpTls/ClientHello/` does.
- **`not-supported`** — SharpTls cannot emit it correctly today.

"Offer-only" in the Notes column means the codepoint is emittable in the ClientHello but
the handshake cannot complete if the server selects it. That is the correct behaviour for
fingerprint fidelity — real browsers offer things they rarely negotiate — but it is a real
ceiling and is called out per row.

---

## 1. Cipher suites

Chrome from S2 `HelloChrome_133`; Firefox from S2 `HelloFirefox_148`; Safari from S2
`HelloSafari_26_3`. Brave 151 over QUIC (S12) offers only the three TLS 1.3 suites,
which is expected — QUIC forbids TLS 1.2 suites.

SharpTls enum: `src/SharpTls/Protocol/TlsEnums.cs:4-82` (36 members).
TLS 1.3 keying: `src/SharpTls/Cryptography/CipherSuiteInfo.cs:17-19` and
`src/SharpTls/Records/Tls13RecordCipher.cs` AEAD switch.
TLS 1.2 keying: `src/SharpTls/Cryptography/Tls12CipherSuiteInfo.cs` — **six** AEAD suites only.

| Codepoint | Name | Sent by | Source | Verdict | Notes |
| --- | --- | --- | --- | --- | --- |
| `0x1301` | TLS_AES_128_GCM_SHA256 | C F S | S2, S12 | `supported-and-profiled` | fully keyed |
| `0x1302` | TLS_AES_256_GCM_SHA384 | C F S | S2, S12 | `supported-and-profiled` | fully keyed |
| `0x1303` | TLS_CHACHA20_POLY1305_SHA256 | C F S | S2, S12 | `supported-and-profiled` | fully keyed |
| `0xC02B` | ECDHE_ECDSA_AES_128_GCM_SHA256 | C F S | S2 | `supported-and-profiled` | keyed (TLS 1.2) |
| `0xC02F` | ECDHE_RSA_AES_128_GCM_SHA256 | C F S | S2 | `supported-and-profiled` | keyed (TLS 1.2) |
| `0xC02C` | ECDHE_ECDSA_AES_256_GCM_SHA384 | C F S | S2 | `supported-and-profiled` | keyed (TLS 1.2) |
| `0xC030` | ECDHE_RSA_AES_256_GCM_SHA384 | C F S | S2 | `supported-and-profiled` | keyed (TLS 1.2) |
| `0xCCA9` | ECDHE_ECDSA_CHACHA20_POLY1305 | C F S | S2 | `supported-and-profiled` | keyed (TLS 1.2) |
| `0xCCA8` | ECDHE_RSA_CHACHA20_POLY1305 | C F S | S2 | `supported-and-profiled` | keyed (TLS 1.2) |
| `0xC013` | ECDHE_RSA_AES_128_CBC_SHA | C F S | S2 | `supported-and-profiled` | offer-only |
| `0xC014` | ECDHE_RSA_AES_256_CBC_SHA | C F S | S2 | `supported-and-profiled` | offer-only |
| `0xC009` | ECDHE_ECDSA_AES_128_CBC_SHA | F S | S2 | `supported-and-profiled` | offer-only |
| `0xC00A` | ECDHE_ECDSA_AES_256_CBC_SHA | F S | S2 | `supported-and-profiled` | offer-only |
| `0x009C` | RSA_AES_128_GCM_SHA256 | C F S | S2 | `supported-and-profiled` | offer-only |
| `0x009D` | RSA_AES_256_GCM_SHA384 | C F S | S2 | `supported-and-profiled` | offer-only |
| `0x002F` | RSA_AES_128_CBC_SHA | C F S | S2 | `supported-and-profiled` | offer-only |
| `0x0035` | RSA_AES_256_CBC_SHA | C F S | S2 | `supported-and-profiled` | offer-only |
| `0xC008` | ECDHE_ECDSA_3DES_EDE_CBC_SHA | S | S2 (`FAKE_` in uTLS) | `supported-and-profiled` | offer-only |
| `0xC012` | ECDHE_RSA_3DES_EDE_CBC_SHA | S | S2 | `supported-and-profiled` | offer-only |
| `0x000A` | RSA_3DES_EDE_CBC_SHA | S | S2 | `supported-and-profiled` | offer-only |
| 16 GREASE values | RFC 8701 cipher GREASE | C S | S2, S5 | `supported-and-profiled` | `ClientHelloGreasePolicy` slot `CipherSuite` |

**Cipher suites: 21 rows, 21 `supported-and-profiled`, zero gaps.**

The offer-only distinction is worth stating precisely because it was not in the brief:
`Tls12CipherSuiteInfo.cs` keys exactly six suites (the ECDHE AEAD ones). Every CBC, 3DES,
RC4 and static-RSA suite in `TlsCipherSuite` is wire-fidelity only. Since a 2026 browser
never actually negotiates those against a modern server, this costs nothing in practice —
but a server that *does* pick `0xC013` will fail the handshake.

---

## 2. Named groups

SharpTls enum: `src/SharpTls/Protocol/TlsEnums.cs:98-126` (8 members).
Key-share creation: `src/SharpTls/Cryptography/KeyShareFactory.cs:7-14`, falling through to
`EcdheKeyShare.Create` which handles P-256/384/521 and throws for everything else at
`src/SharpTls/Cryptography/EcdheKeyShare.cs:47-57`.

| Codepoint | Name | Sent by | Source | Verdict | Notes |
| --- | --- | --- | --- | --- | --- |
| `4588` / `0x11EC` | X25519MLKEM768 | C F S | S4 (RFC 10024), S2, S12 | `supported-and-profiled` | real ML-KEM-768; `MlKem768.cs`, `Fips202.cs` |
| `29` / `0x001D` | X25519 | C F S | S4, S2, S12 | `supported-and-profiled` | `X25519KeyShare` |
| `23` / `0x0017` | secp256r1 | C F S | S4, S2, S12 | `supported-and-profiled` | `EcdheKeyShare` |
| `24` / `0x0018` | secp384r1 | C F S | S4, S2, S12 | `supported-and-profiled` | `EcdheKeyShare` |
| `25` / `0x0019` | secp521r1 | F S | S4, S2 | `supported-and-profiled` | `EcdheKeyShare` |
| `256` / `0x0100` | ffdhe2048 | F | S4, S2 (`0x0100` in FF148 curves) | `supported-and-profiled` | **offer-only** — `EcdheKeyShare.cs:56` throws |
| `257` / `0x0101` | ffdhe3072 | F | S4, S2 | `supported-and-profiled` | **offer-only** |
| 16 GREASE values | RFC 8701 group GREASE | C S | S2, S12 | `supported-and-profiled` | slots `SupportedGroup` + `KeyShare` |

**Named groups: 8 rows, 8 `supported-and-profiled`, zero gaps.**

### The post-quantum question, answered

This was flagged as the most likely genuine gap. It is not one. The evidence:

IANA's Supported Groups registry (S4) now lists the ECDHE+ML-KEM hybrids as **standardised
by RFC 10024**, not drafts:

```
4587,SecP256r1MLKEM768,Y,N,[RFC10024],Combining secp256r1 ECDH with ML-KEM-768
4588,X25519MLKEM768,Y,Y,[RFC10024],Combining X25519 ECDH with ML-KEM-768
4589,SecP384r1MLKEM1024,Y,N,[RFC10024],Combining secp384r1 ECDH with ML-KEM-1024
25497,X25519Kyber768Draft00 (OBSOLETE),Y,D,[...][RFC10024],Pre-standards version of Kyber768.
```

Only `4588` carries the "Recommended = Y" mark. `4587` and `4589` are `N`.

BoringSSL — the TLS stack in Chrome, Edge, Brave and every Chromium derivative — implements
a **closed set of six groups** (S8, `ssl/ssl_key_share.cc`):

```c
constexpr NamedGroup kNamedGroups[] = {
    {NID_X9_62_prime256v1, SSL_GROUP_SECP256R1,   "P-256",          "prime256v1"},
    {NID_secp384r1,        SSL_GROUP_SECP384R1,   "P-384",          "secp384r1"},
    {NID_secp521r1,        SSL_GROUP_SECP521R1,   "P-521",          "secp521r1"},
    {NID_X25519,           SSL_GROUP_X25519,      "X25519",         "x25519"},
    {NID_X25519MLKEM768,   SSL_GROUP_X25519_MLKEM768, "X25519MLKEM768", ""},
    {NID_ML_KEM_1024,      SSL_GROUP_MLKEM1024,   "MLKEM1024",      ""},
};
```

`SecP256r1MLKEM768` (4587) and `SecP384r1MLKEM1024` (4589) **are not in BoringSSL at all**.
Chrome cannot offer them. `MLKEM1024` (`0x0202` = 514, S7) exists but is not in
`DefaultSupportedGroupIds()`, which begins `SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519, …`
(S8) — it is present for CNSA-2.0 / server deployments, not the browser default.

The live Brave 151 capture (S12) independently confirms this: supported_groups is
`4588-29-23-24`, key shares are X25519MLKEM768 (1216 bytes) and X25519 (32 bytes).

Firefox 148 (S2) offers `X25519MLKEM768, X25519, P-256, P-384, P-521, 0x0100, 0x0101` —
also nothing newer than 4588. Safari 26.3 (S2) offers
`GREASE, X25519MLKEM768, X25519, P-256, P-384, P-521`.

**Conclusion: X25519MLKEM768 (4588) is still the whole of browser PQ key agreement in
August 2026, on all three engines. SharpTls implements it with a real ML-KEM-768. There is
no PQ key-exchange gap.** Adding 4587/4589 would produce a fingerprint no browser emits.

---

## 3. Extensions

SharpTls emits extensions two ways, both verified:

- 20 semantic kinds — `src/SharpTls/ClientHello/ClientHelloExtensionKind.cs` (I read the
  whole file; the members are Grease, SecondaryGrease, ServerName, SupportedVersions,
  Cookie, SupportedGroups, SignatureAlgorithms, SignatureAlgorithmsCert, KeyShare,
  PskKeyExchangeModes, EarlyData, PreSharedKey, ApplicationLayerProtocolNegotiation,
  ApplicationSettings, PostHandshakeAuthentication, RecordSizeLimit, DelegatedCredential,
  QuicTransportParameters, EncryptedClientHello, Padding).
- Arbitrary raw slots — `ClientHelloExtensionSpec.Raw(ushort extensionType, byte[] data)` at
  `src/SharpTls/ClientHello/ClientHelloExtensionSpec.cs:42`. **Any** `ushort` codepoint is
  emittable, so "can we put these bytes on the wire" is essentially always yes.

Wire order is caller-controlled: `ClientHelloBuilder.WithExtensionOrder` (`:438`) and
`WithExtensionLayout` (`:451`). Chromium's `SSL_set_permute_extensions(ssl_.get(), 1)` (S9)
is matched by `.WithExtensionShuffling(true)` in the Chromium profile builder
(`UTlsClientHelloProfiles.Additional.cs:220`).

| Codepoint | Name | Sent by | Source | Verdict | SharpTls evidence |
| --- | --- | --- | --- | --- | --- |
| `0` | server_name | C F S | S5, S2, S12 | `supported-and-profiled` | `Kind.ServerName` |
| `5` | status_request | C F S | S5, S2 | `supported-and-profiled` | `Raw(5, [1,0,0,0,0])` — Additional.cs:250 |
| `10` | supported_groups | C F S | S5, S2, S12 | `supported-and-profiled` | `Kind.SupportedGroups` |
| `11` | ec_point_formats | C F S | S5, S2 | `supported-and-profiled` | `Raw(11, [1,0])` — Additional.cs:246 |
| `13` | signature_algorithms | C F S | S5, S2, S12 | `supported-and-profiled` | `Kind.SignatureAlgorithms` |
| `16` | ALPN | C F S | S5, S2, S12 | `supported-and-profiled` | `Kind.ApplicationLayerProtocolNegotiation` |
| `18` | signed_certificate_timestamp | C F S | S5, S2; S9 `SSL_enable_signed_cert_timestamps` | `supported-and-profiled` | `Raw(18, [])` |
| `21` | padding | C | S5, S2 | `supported-and-profiled` | `Kind.Padding` / `WithBoringPadding()` |
| `23` | extended_master_secret | C F S | S5, S2 | `supported-and-profiled` | `Raw(23, [])` — Additional.cs:243 |
| `27` | compress_certificate | C F S | S5 (RFC 8879), S2, S12 | `supported-and-profiled` | `Raw(27, …)`; see §5 for the payload gap |
| `28` | record_size_limit | F | S5 (RFC 8449), S2 | `supported-and-profiled` | `Kind.RecordSizeLimit` |
| `34` | delegated_credential | F | S5 (RFC 9345), S2 | `supported-and-profiled` | `Kind.DelegatedCredential` |
| `35` | session_ticket | C F | S5, S2 | `supported-and-profiled` | `Raw(35, [])` — Additional.cs:247 |
| `43` | supported_versions | C F S | S5, S2, S12 | `supported-and-profiled` | `Kind.SupportedVersions` |
| `45` | psk_key_exchange_modes | C F S | S5, S2, S12 | `supported-and-profiled` | `Kind.PskKeyExchangeModes` |
| `51` | key_share | C F S | S5, S2, S12 | `supported-and-profiled` | `Kind.KeyShare` |
| `57` | quic_transport_parameters | C (h3) | S5 (RFC 9001), S12 | `supported-and-profiled` | `Kind.QuicTransportParameters` |
| `17513` | application_settings (ALPS, old) | C (legacy) | S6 `TLSEXT_TYPE_application_settings_old` | `supported-and-profiled` | `TlsApplicationSettingsCodePoint.LegacyDraft = 17513` |
| `17613` | application_settings (ALPS, new) | C | S6 `TLSEXT_TYPE_application_settings 17613`; S10 `kUseNewAlpsCodepointHttp2` ENABLED_BY_DEFAULT; S12 | `supported-and-profiled` | `TlsApplicationSettingsCodePoint.ChromeExperiment = 17613` |
| `65037` / `0xFE0D` | encrypted_client_hello | C F | S5 (**RFC 9849**), S2, S12 | `supported-and-profiled` | `TlsEnums.cs` `EncryptedClientHello = 0xFE0D`; `src/SharpTls/Ech/*` |
| `64768` / `0xFD00` | ech_outer_extensions | C F (inner CH only) | S5 (RFC 9849), S6 | `supported-and-profiled` | `TlsEnums.cs` `EchOuterExtensions = 0xFD00` |
| `65281` / `0xFF01` | renegotiation_info | C F S | S5, S2 | `supported-and-profiled` | `Raw(0xFF01, [0])` — Additional.cs:244 |
| 16 GREASE values | RFC 8701 extension GREASE ×2 | C S | S5, S2 | `supported-and-profiled` | `Kind.Grease` + `Kind.SecondaryGrease` |
| `0xca34` (51764) | **trust_anchors** (client offer) | C | **S6** `#define TLSEXT_TYPE_trust_anchors 0xca34`; S9 L868 `SSL_set1_requested_trust_anchors` | `supported-but-no-profile` | emittable via `Raw(0xca34, …)`; nothing emits it |
| `0xca34` (51764) | **trust_anchors** negotiation (server `available_trust_anchors` → cert reselection) | C | S9 L331-344 `SSL_get0_peer_available_trust_anchors`, `ParseTlsTrustAnchorIDs` | **`not-supported`** | no parser, no reselection path; grep for `trust_anchor` in `src/` returns nothing |
| `4832` | server_padding | C (feature-guarded) | **S6** `#define TLSEXT_TYPE_server_padding 4832`; S11 commit 2026-05-29 "[Padding] Request server padding from chromium (feature-guarded)" | `supported-but-no-profile` | emittable via `Raw(4832, …)`; default-on state not sourced — see §7 |
| `62` | tls_flags | — | S5 (`draft-ietf-tls-tlsflags-14`), S6 `TLSEXT_TYPE_tls_flags 62` | `supported-but-no-profile` | defined in BoringSSL; **no evidence any browser sends it** — see §7 |
| `0x8a3b` | pake | — | S6 `#define TLSEXT_TYPE_pake 0x8a3b` | `supported-but-no-profile` | SPAKE2+; not a web-browsing extension, no browser evidence |

**Extensions: 28 rows — 23 `supported-and-profiled`, 4 `supported-but-no-profile`,
1 `not-supported`.**

One note on ECH maturity, since the brief asked: ECH is **no longer a draft**. The IANA
registry (S5) now cites **RFC 9849** for both `65037 encrypted_client_hello` and
`64768 ech_outer_extensions`. SharpTls's codepoints match, and `src/SharpTls/Ech/` contains
a real HPKE implementation, not a stub.

---

## 4. Signature algorithms — the real Chrome gap

SharpTls enum: `src/SharpTls/Protocol/TlsEnums.cs:129-178` (17 members: PKCS#1 SHA-1/256/384/512,
DSA SHA-1/256, ECDSA SHA-1 + P-256/384/521, RSA-PSS RSAE ×3, RSA-PSS PSS ×3).

Chrome 133 (S2), Firefox 148 (S2) and Safari 26.3 (S2) all send lists drawn entirely from
that set. **But Chromium `main` no longer sends the Chrome 133 list.** S9 L796-808:

```c
  // Disable SHA-1 server signatures.
  static const uint16_t kVerifyPrefs[] = {
      SSL_SIGN_ML_DSA_44,
      SSL_SIGN_ML_DSA_65,
      SSL_SIGN_ML_DSA_87,
      SSL_SIGN_ECDSA_SECP256R1_SHA256,
      SSL_SIGN_RSA_PSS_RSAE_SHA256,
      …
```

with codepoints from S7 (`include/openssl/ssl.h`):

```c
#define SSL_SIGN_ML_DSA_44 0x0904
#define SSL_SIGN_ML_DSA_65 0x0905
#define SSL_SIGN_ML_DSA_87 0x0906
#define SSL_SIGN_ED25519   0x0807
```

and S11 dates it: commit **2026-07-30, "Remove kTlsMldsaSignatures feature flag that is on
by default."** The flag is gone because it shipped on.

| Codepoint | Name | Sent by | Source | Verdict | Notes |
| --- | --- | --- | --- | --- | --- |
| `0x0403` | ecdsa_secp256r1_sha256 | C F S | S2 | `supported-and-profiled` | |
| `0x0503` | ecdsa_secp384r1_sha384 | C F S | S2 | `supported-and-profiled` | |
| `0x0603` | ecdsa_secp521r1_sha512 | F S | S2 | `supported-and-profiled` | |
| `0x0804` | rsa_pss_rsae_sha256 | C F S | S2 | `supported-and-profiled` | |
| `0x0805` | rsa_pss_rsae_sha384 | C F S | S2 | `supported-and-profiled` | |
| `0x0806` | rsa_pss_rsae_sha512 | C F S | S2 | `supported-and-profiled` | |
| `0x0401` | rsa_pkcs1_sha256 | C F S | S2 | `supported-and-profiled` | |
| `0x0501` | rsa_pkcs1_sha384 | C F S | S2 | `supported-and-profiled` | |
| `0x0601` | rsa_pkcs1_sha512 | C F S | S2 | `supported-and-profiled` | |
| `0x0203` | ecdsa_sha1 | F | S2 | `supported-and-profiled` | |
| `0x0201` | rsa_pkcs1_sha1 | F S | S2 | `supported-and-profiled` | |
| `0x0904` | **ml_dsa_44** | C (main, on by default) | **S7**, S9 L798, S11 (2026-07-30) | **`not-supported`** | no enum member; `grep 0x0904 src/` → 0 hits |
| `0x0905` | **ml_dsa_65** | C (main, on by default) | **S7**, S9 L799, S11 | **`not-supported`** | no enum member |
| `0x0906` | **ml_dsa_87** | C (main, on by default) | **S7**, S9 L800, S11 | **`not-supported`** | no enum member |
| `0x0807` | ed25519 | — | S7 (BoringSSL defines it) | **`not-supported`** | **not in Chromium's `kVerifyPrefs`** — no browser evidence; listed for completeness only |

**Signature algorithms: 15 rows — 11 `supported-and-profiled`, 0 `supported-but-no-profile`,
4 `not-supported`.**

---

## 5. Certificate compression algorithms (ext 27 payload)

Codepoints from uTLS `u_common.go` (S1):

```go
CertCompressionZlib   CertCompressionAlgo = 0x0001
CertCompressionBrotli CertCompressionAlgo = 0x0002
CertCompressionZstd   CertCompressionAlgo = 0x0003
```

| Codepoint | Name | Sent by | Source | Verdict | Notes |
| --- | --- | --- | --- | --- | --- |
| `1` | zlib | F, S | S1, S2 (`HelloSafari_26_3` sends **zlib only**) | `supported-and-profiled` | `ZLibStream` — `CompressedCertificateParser.cs:52` |
| `2` | brotli | C, F | S1, S2, S12 (Brave 151: "27 `compress_certificate` (brotli)") | `supported-and-profiled` | `BrotliStream` — `:53` |
| `3` | **zstd** | F | S1, S2 (`HelloFirefox_148`: `CertCompressionZlib, CertCompressionBrotli, CertCompressionZstd`) | **`not-supported`** | **advertised but undecodable — see below** |

**Certificate compression: 3 rows — 2 `supported-and-profiled`, 1 `not-supported`.**

### This one is a live defect, not just a missing feature

SharpTls's Firefox 148 profile **advertises zstd**:

```csharp
ClientHelloExtensionSpec.Raw(27, [6, 0, 1, 0, 2, 0, 3]),
```
— `UTlsClientHelloProfiles.Additional.cs`, in `CreateUTlsFirefox148()`: a 6-byte vector of
`0x0001, 0x0002, 0x0003`. That is correct wire fidelity to S2.

But `src/SharpTls/Certificates/CompressedCertificateParser.cs:41`:

```csharp
if (algorithm is not (Zlib or Brotli))
{
    throw BadCertificate(
        $"Certificate compression algorithm {algorithm} has no managed decompressor.");
}
```

`Zlib = 1` and `Brotli = 2` are the only constants defined (`:9-10`). A server that honours
the offer and returns a zstd-compressed `CompressedCertificate` gets a `bad_certificate`
alert and the connection dies. Every other row in this audit is a codepoint we merely don't
send; **this is a codepoint we do send and cannot honour.** It is the only such row.

---

## 6. GREASE placements

`src/SharpTls/ClientHello/ClientHelloGreasePolicy.cs:5-18` defines exactly six slots, and
`:29` pins `private const int SlotCount = 6`.

| Placement | Sent by | Source | Verdict | Notes |
| --- | --- | --- | --- | --- |
| cipher_suites leading value | C S | S2 | `supported-and-profiled` | `ClientHelloGreaseSlot.CipherSuite` |
| supported_versions leading value | C S | S2 | `supported-and-profiled` | `.SupportedVersion` |
| supported_groups leading value | C S | S2 | `supported-and-profiled` | `.SupportedGroup` |
| key_share leading entry | C S | S2 | `supported-and-profiled` | `.KeyShare` |
| empty GREASE extension (first) | C S | S2 | `supported-and-profiled` | `.Extension` |
| empty GREASE extension (second) | C | S2 | `supported-and-profiled` | `.SecondaryExtension` |
| **signature_algorithms GREASE value** | C | **S9 L212** `SSL_CTX_set_grease_sigalgs_enabled`; **S10:1004** `BASE_FEATURE(kTlsGreaseSigalgs, base::FEATURE_ENABLED_BY_DEFAULT)`; **S11** commit 2026-06-30 "Enable GREASE for signature_algorithms extension" | **`not-supported`** | seventh slot; `grep SignatureAlgorithm ClientHelloGreasePolicy.cs` → 0 hits |
| QUIC transport-parameter GREASE | C (h3) | S12 (`perk` shows a GREASE transport param and a GREASE available-version) | `supported-and-profiled` | per S12: "SharpTls can already express it through `TlsQuicTransportParameters`" |

**GREASE: 8 rows — 7 `supported-and-profiled`, 1 `not-supported`.**

---

## 7. The genuine gaps (`not-supported` rows)

Six rows. Three are real for browser mimicry; three are bookkeeping.

### G1 — ML-DSA signature algorithms `0x0904` / `0x0905` / `0x0906` — *codepoint*

**What a client sends.** Chromium's `kVerifyPrefs` now leads with ML-DSA-44/65/87 (S9
L798-800), and the gating feature flag was **deleted as on-by-default on 2026-07-30** (S11).
These appear in the `signature_algorithms` extension of every Chromium ClientHello built
from tip-of-tree.

**What implementing it involves.** *Codepoint only, for the client.* Three enum members in
`SignatureScheme` (`TlsEnums.cs:129-178`) plus the profile lists. The client advertises what
it will *verify*; it does not have to *perform* ML-DSA to send the codepoints. Actually
verifying an ML-DSA server certificate would be a primitive (FIPS 204, a large lattice
implementation) — but no public CA issues ML-DSA certificates today, so a client that
advertises and never receives one is behaviourally identical to Chrome.

**Caveat.** See §8 — I could not establish which *stable* Chrome milestone this reached.

### G2 — GREASE in `signature_algorithms` — *codepoint*

**What a client sends.** One GREASE value spliced into the sigalgs list. Enabled by default
in Chromium (S10:1004), landed 2026-06-30 (S11).

**What implementing it involves.** *Codepoint / wiring.* A seventh `ClientHelloGreaseSlot`
member and bumping `SlotCount` from 6 to 7 in `ClientHelloGreasePolicy.cs`, plus emitting it
in the sigalgs encoder. No crypto. The GREASE value generator already exists.

This is the more fingerprint-visible of G1/G2, because JA4's sigalg component and any
sigalg-aware fingerprinter will see a GREASE value that SharpTls never emits.

### G3 — zstd certificate decompression (algorithm `3`) — *primitive*

**What a client sends.** Firefox 148 offers `zlib, brotli, zstd` (S2). SharpTls's FF148
profile faithfully offers all three.

**What implementing it involves.** *Primitive.* .NET has `ZLibStream` and `BrotliStream` in
`System.IO.Compression` but **no zstd decompressor** in the BCL as of .NET 9. Options are a
managed zstd decoder (frame + FSE/Huffman entropy decoding — nontrivial), a native binding,
or a NuGet dependency. The cheap alternative is to stop advertising zstd, which trades a
live failure mode for a one-codepoint fingerprint divergence from real Firefox.

This is the only gap that can break a working connection today.

### G4 — `trust_anchors` (`0xca34`) negotiation — *codepoint + logic*

**What a client sends.** Chrome sends the extension only when
`ssl_config_.trust_anchor_ids.has_value()` (S9 L867), i.e. when a DNS HTTPS RR supplied
Trust Anchor ID hints — so it is *not* in a default ClientHello to an arbitrary host. The
harder half is the response: `SSL_get0_peer_available_trust_anchors` (S9 L334) and
`x509_util::ParseTlsTrustAnchorIDs` (S9 L344) drive certificate reselection.

**What implementing it involves.** The client offer is *a codepoint* — `Raw(0xca34, …)`
works today, which is why the offer row is `supported-but-no-profile`. The negotiation is
*logic*: parsing the server's available-anchor list and re-driving chain building. No new
crypto.

**Priority: low.** It is conditional on DNS hints SharpTls does not consume, so omitting it
matches what Chrome sends to most hosts anyway.

### G5 — `ed25519` `0x0807` — *codepoint, not needed*

Defined in BoringSSL (S7) but **absent from Chromium's `kVerifyPrefs`** (S9 L798-808) and
from all three uTLS 2026 specs (S2). No browser sends it. Listed only so the next reader
does not have to re-derive that. Implementing it would move SharpTls *away* from browser
fidelity.

### G6 — MLKEM1024 `0x0202`, SecP256r1MLKEM768 `4587`, SecP384r1MLKEM1024 `4589`

Not gaps at all, recorded so this is not re-investigated. `4587`/`4589` are RFC 10024
codepoints (S4) that **BoringSSL does not implement** (S8) and no browser offers.
`MLKEM1024` exists in BoringSSL (S7, S8) but is outside `DefaultSupportedGroupIds()`.
Adding any of them would create a fingerprint no browser produces.

---

## 8. What I could not source

Recorded honestly rather than guessed.

1. **Which *stable* Chrome milestone ships ML-DSA sigalgs and sigalg GREASE.** I read
   Chromium `main` (S9, S10) and dated the commits (S11: 2026-06-30 and 2026-07-30), and
   confirmed both features are `FEATURE_ENABLED_BY_DEFAULT` / flag-removed. I did **not**
   establish the milestone branch cut, so I cannot say whether Chrome/Brave **151** — the
   version in the in-tree capture — sends them. A feature landing on main in late June/July
   2026 typically reaches stable one to three milestones later, but that is inference, not a
   source, and I am not stating it as fact.
   **What would settle it:** a `signature_algorithms` readout from a real Chrome 151+
   ClientHello. The existing Brave 151 capture (S12) cannot settle it — its JA3
   (`771,4865-4866-4867,27-43-45-17613-65037-16-51-10-57-13-0,4588-29-23-24,`) records that
   extension `13` was *present* but not its contents. `https://tls.peet.ws/api/all` returns
   the full parsed sigalg list, as does `https://fp.impersonate.pro/api/http3` used for S12.

2. **Whether `server_padding` (4832) is on by default.** S6 gives the codepoint and S11
   dates the commit (2026-05-29) with the message explicitly saying "feature-guarded". I did
   not locate the feature's default in `net/base/features.cc`.
   **What would settle it:** the same live capture — a `4832` in the extension list.

3. **Whether any browser sends `tls_flags` (62).** IANA lists it as
   `draft-ietf-tls-tlsflags-14` (S5) and BoringSSL defines the codepoint (S6), but I found no
   Chromium call site enabling it and no uTLS parrot containing it.
   **What would settle it:** the same live capture.

4. **Firefox's NSS-side defaults directly.** I fetched `nss-dev/nss` `lib/ssl/ssl3con.c` and
   could not locate an `ssl_named_groups[]` table there — the symbol has moved or the mirror
   path differs. **All Firefox rows in this document therefore rest on uTLS's
   `HelloFirefox_148` spec (S2), which was committed 2026-02-28** ("feat: add ff 148 spec and
   impl keyshare reuse", S3), not on NSS source. uTLS parrots are derived from real captures
   and are the accepted public record, but they are second-hand.
   **What would settle it:** a live capture from Firefox 148+, or `security.tls.*` prefs from
   an actual profile.

5. **Safari / iOS beyond uTLS.** As anticipated, Apple publishes nothing. Every Safari 26.3
   row rests solely on uTLS `HelloSafari_26_3` (S2), added 2026-03-01 (S3). I found no
   independent corroboration and am not going to invent any. Notably it offers **zlib only**
   for certificate compression and **no ALPS and no session_ticket** — worth verifying before
   relying on it.

6. **Chrome 141-151 ClientHello specs.** uTLS's newest Chrome parrot is **133** (S1:
   `HelloChrome_Auto = HelloChrome_133`). No public parrot exists for Chrome 134+. The
   in-tree Brave 151 capture (S12) is the only 2026-era Chromium evidence available and it is
   QUIC-only, so it says nothing about the TCP-only extensions (`23`, `35`, `11`, `5`, `18`,
   `65281`, `21`).
   **What would settle it:** a TCP capture from Chrome/Brave 151 via `tls.peet.ws/api/all`.

**One capture settles items 1, 2, 3 and 6 at once.** If the user can run a current
Chrome/Brave against `https://tls.peet.ws/api/all` over TCP (not HTTP/3) and drop the JSON
into `docs/superpowers/specs/reference-captures/`, this audit's four largest uncertainties
close together.

---

## 9. Recommended profile list

SharpTls currently ships **49** named profiles in
`src/SharpTls/ClientHello/UTlsClientHelloProfiles*.cs` + `CapturedClientHelloProfiles.cs`
(54 `public static ClientHelloProfile` declarations across `src/SharpTls/ClientHello/*.cs`;
the extra 5 are in `ClientHelloProfile.cs` and `ClientHelloProfileRandomizer.cs`).

Its newest entries — `UTlsChrome133`, `UTlsFirefox148`, `UTlsSafari263` — are an **exact
match for uTLS master's newest** (S1, S3). SharpTls is not behind uTLS; it is at parity.
uTLS itself is what lags reality.

| Target | Worth shipping? | Closest existing profile | Why |
| --- | --- | --- | --- |
| **Brave / Chrome 151, HTTP/3** | **Yes — highest value** | `UTlsChrome133` | The capture already exists (S12) and its JA3 elements are *all* supported: suites `4865-4866-4867`, extensions `27-43-45-17613-65037-16-51-10-57-13-0`, groups `4588-29-23-24`. Nothing needs implementing — this is pure profile authoring. |
| **Brave / Chrome 151, TCP** | Yes, after a capture | `UTlsChrome133` | The TCP extension set is unverified (§8 item 6). Do not extrapolate from the h3 capture. |
| Chrome 140-150 intermediates | No | — | No public spec exists; each would be invented. |
| **Firefox 148** | Already shipped | `UTlsFirefox148` | Ships. Fix the zstd advertise-vs-decode defect (G3) rather than adding a profile. |
| Firefox 149+ | Not yet | `UTlsFirefox148` | uTLS has no newer parrot; needs a live capture first. |
| **Safari 26.3** | Already shipped | `UTlsSafari263` | Ships, at uTLS parity. |
| Edge 151 | Low priority | `UTlsChrome133` / `UTlsEdge106` | Modern Edge is Chromium; its ClientHello is Chrome's. The two shipped Edge profiles (85, 106) are historical. A "current Edge" profile is a Chrome 151 profile. |
| iOS 18/26 Safari | Not without a capture | `UTlsIOS14`, `UTlsSafari263` | The shipped iOS profiles stop at 14. `docs/superpowers/specs/2026-08-17-ios-http3-capture-methodology.md` exists in-tree and is the right route. |
| Android Chrome 151 | Low priority | `UTlsAndroid11OkHttp` | Android Chrome's TLS is desktop Chrome's; the shipped Android profile is OkHttp, a different thing. |

**Recommendation:** author exactly one new profile — Brave/Chrome 151 over HTTP/3, from
S12 — since every primitive it needs already exists and works. Hold everything else for
captures.

---

## 10. Corrections to the commissioning brief

The brief's claims were checked against the code. Most held. These did not:

1. **"48 profiles ship" — the count is 49 named, 54 declarations.**
   `grep -c 'public static ClientHelloProfile'` per file: `UTlsClientHelloProfiles.Additional.cs` 20,
   `.Legacy.cs` 15, `.cs` 7, `.Auto.cs` 6, `CapturedClientHelloProfiles.cs` 1 (= 49), plus
   `ClientHelloProfile.cs` 3 and `ClientHelloProfileRandomizer.cs` 2 (= 54 total).
   Of the 49, eight are `*Auto` aliases and one (`Spotify917201896IOS20H392`) is a captured
   app, not a browser.

2. **"Newest is Chrome 133 / Firefox 148" — incomplete. `UTlsSafari263` ships and is newer.**
   uTLS added Safari 26.3 on **2026-03-01**, one day *after* Firefox 148 (2026-02-28) (S3).
   SharpTls has it (`UTlsSafari263`). The correct statement is that SharpTls is at **exact
   uTLS master parity**, and uTLS master's newest Chrome is still 133.

3. **"Certificate compression (27) emits raw with real client-side decompression" — true but
   materially incomplete.** The decompressor covers zlib and brotli only
   (`CompressedCertificateParser.cs:41`), while the shipped Firefox 148 profile advertises
   zstd. That is gap **G3** and it is the only gap in this audit that can break a live
   connection.

4. **"GREASE covers six slots" — correct for SharpTls, but no longer sufficient for Chrome.**
   Chromium added a seventh GREASE location (signature_algorithms) on 2026-06-30, enabled by
   default (S10:1004, S11). Gap **G2**.

5. **Unstated, and worth stating: only six TLS 1.2 cipher suites are keyed.**
   `Tls12CipherSuiteInfo.cs` covers the ECDHE AEAD suites only. The other ~25 TLS 1.2 entries
   in `TlsCipherSuite` are offer-only, the same status as `ffdhe2048`/`ffdhe3072`. The brief
   called out the ffdhe ceiling but not this larger one.

Claims that **held** exactly as stated: all three TLS 1.3 suites enum'd, offered and keyed;
`KeyShareFactory` coverage; `ffdhe2048/3072` throwing at `EcdheKeyShare.cs:56`; 20 semantic
extension kinds plus arbitrary `Raw(ushort, byte[])`; ALPS 17613 and ECH 65037 wired and
reachable; caller-controlled extension order via `WithExtensionOrder` (`:438`) and
`WithExtensionLayout` (`:451`).

---

## Verdict totals

| Verdict | Count |
| --- | --- |
| `supported-and-profiled` | **72** |
| `supported-but-no-profile` | **4** |
| `not-supported` | **6** |
| **Total rows** | **82** |

Derivation:

| Table | `supported-and-profiled` | `supported-but-no-profile` | `not-supported` | Rows |
| --- | --- | --- | --- | --- |
| §1 Cipher suites | 21 | 0 | 0 | 21 |
| §2 Named groups | 8 | 0 | 0 | 8 |
| §3 Extensions | 23 | 4 | 1 | 28 |
| §4 Signature algorithms | 11 | 0 | 4 | 15 |
| §5 Cert compression | 2 | 0 | 1 | 3 |
| §6 GREASE placements | 7 | 0 | 1 | 8 |
| **Total** | **72** | **4** | **6** | **82** |

`supported-but-no-profile` (4): trust_anchors `0xca34` client offer, server_padding `4832`,
tls_flags `62`, pake `0x8a3b`.

`not-supported` (6): ml_dsa_44 `0x0904`, ml_dsa_65 `0x0905`, ml_dsa_87 `0x0906`,
ed25519 `0x0807`, zstd cert compression `3`, signature_algorithms GREASE. Plus
trust_anchors *negotiation* as a seventh row that shares a codepoint with a
`supported-but-no-profile` row — counted once in §3.

Of those six, **three matter for 2026 browser mimicry**: G1 (ML-DSA codepoints), G2 (sigalg
GREASE), G3 (zstd). G3 is the only one that can break a working handshake.

---

## Greps run

For anyone re-verifying. All run from the repo root.

```
awk '/public enum TlsCipherSuite/,/^\}/'  src/SharpTls/Protocol/TlsEnums.cs
awk '/public enum NamedGroup/,/^\}/'      src/SharpTls/Protocol/TlsEnums.cs
awk '/public enum SignatureScheme/,/^\}/' src/SharpTls/Protocol/TlsEnums.cs
awk '/public enum TlsExtensionType/,/^\}/' src/SharpTls/Protocol/TlsEnums.cs
cat src/SharpTls/Cryptography/CipherSuiteInfo.cs
cat src/SharpTls/Cryptography/KeyShareFactory.cs
sed -n '40,70p' src/SharpTls/Cryptography/EcdheKeyShare.cs
grep -oE 'TlsCipherSuite\.[A-Za-z0-9_]+' src/SharpTls/Cryptography/Tls12CipherSuiteInfo.cs | sort -u
grep -vE '^\s*///|^\s*$' src/SharpTls/ClientHello/ClientHelloExtensionKind.cs
sed -n '1,40p' src/SharpTls/ClientHello/ClientHelloGreasePolicy.cs
grep -n 'Raw(\|WithExtensionOrder\|WithExtensionLayout' \
     src/SharpTls/ClientHello/ClientHelloExtensionSpec.cs src/SharpTls/ClientHello/ClientHelloBuilder.cs
sed -n '30,60p;90,120p' src/SharpTls/Certificates/CompressedCertificateParser.cs
sed -n '/CreateUTlsChromiumAlpsProfile(/,/^    }/p' src/SharpTls/ClientHello/UTlsClientHelloProfiles.Additional.cs
awk '/CreateUTlsFirefox148/,/^    \}/' src/SharpTls/ClientHello/UTlsClientHelloProfiles.Additional.cs

# negative checks — all returned zero hits
grep -rn '0x0807\|Ed25519\|MlDsa\|0x0904\|0x0905\|0x0906\|0xca34\|51764\|trust_anchor' --include=*.cs src/
grep -rn 'SignatureAlgorithm' src/SharpTls/ClientHello/ClientHelloGreasePolicy.cs

# counts
grep -rhoE 'public static ClientHelloProfile [A-Za-z0-9_]+' src/SharpTls/ClientHello/*.cs | sort -u | wc -l   # 54
```
