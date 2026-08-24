# Fingerprint knobs

Every property a caller can tweak across the three fingerprint layers — TLS/JA3, QUIC, HTTP/3 —
with its type, its **default as read from the code**, what it changes on the wire, and whether it
is fingerprinted.

Every claim below was checked with a read or a grep, and the grep is named at the claim. Defaults
are read from field initialisers, not from prose. Where a doc-comment in `src/` disagrees with the
code, the code wins and the disagreement is recorded in
[Stale self-checks found while writing this](#stale-self-checks-found-while-writing-this).

---

## Contents

- [Read this first: five things that have each cost a defect](#read-this-first-five-things-that-have-each-cost-a-defect)
- [Reachability: the three-way split](#reachability-the-three-way-split)
- [Layer 1 — TLS / JA3](#layer-1--tls--ja3)
  - [Builder knobs](#builder-knobs)
  - [Extension order and layout](#extension-order-and-layout)
  - [GREASE](#grease)
  - [Offer-only versus implemented](#offer-only-versus-implemented)
  - [Profiles, specs and JSON round-trip](#profiles-specs-and-json-round-trip)
  - [Example — TLS layer](#example--tls-layer)
- [Layer 2 — QUIC](#layer-2--quic)
  - [`TlsQuicConnectionSpec`](#tlsquicconnectionspec)
  - [`TlsQuicLocalFlowControlSpec`](#tlsquiclocalflowcontrolspec)
  - [`TlsQuicTransportParameterSpec`](#tlsquictransportparameterspec)
  - [`TlsQuicRecoverySpec`](#tlsquicrecoveryspec)
  - [`TlsQuicClientHelloProfileFactory`](#tlsquicclienthelloprofilefactory)
  - [Example — QUIC layer](#example--quic-layer)
- [Layer 3 — HTTP/3](#layer-3--http3)
  - [`TlsQuicHttp3Spec`](#tlsquichttp3spec)
  - [Example — HTTP/3 layer](#example--http3-layer)
- [Every `UNVERIFIED` value](#every-unverified-value)
- [Knobs nothing currently reads](#knobs-nothing-currently-reads)
- [Not configurable, and should be](#not-configurable-and-should-be)
- [Stale self-checks found while writing this](#stale-self-checks-found-while-writing-this)

---

## Read this first: five things that have each cost a defect

### 1. Ordered lists are ordered *on the wire*. A named-property model is wrong here.

Three lists in this library are hashed by fingerprinting services, and their order is the
fingerprint — not their contents:

| List | Where | Why order is the fingerprint |
| --- | --- | --- |
| ClientHello extension order | `ClientHelloBuilder.WithExtensionOrder` / `WithExtensionLayout` (`src/SharpTls/ClientHello/ClientHelloBuilder.cs:467`, `:480`) | JA3/JA4 hash the extension type sequence. |
| QUIC transport parameters | `TlsQuicTransportParameterSpec.Parameters` (`src/SharpTls/Quic/TlsQuicTransportParameterSpec.cs:523`) | A client capture's table is headed *"in wire order"*: *"This ordering is the fingerprint. It is not sorted, and it is not the RFC's presentation order."* Task B11 proved it live — reordering the list moved `perk_hash` at `fp.impersonate.pro` and left `perk_hash_normalized` byte-identical over 12 attempts (`TlsQuicConnectionSpec.cs:731-737`). |
| HTTP/3 SETTINGS | `TlsQuicHttp3Spec.Settings` (`src/SharpTls/Quic/TlsQuicHttp3Spec.cs:247`) | RFC 9114 §7.2.4 fixes no order, so the sequence is a sender choice. The encoder is *forbidden to sort* (`TlsQuicHttp3Spec.cs:211-216`). |

This is why the transport-parameter and SETTINGS models are `(identifier, value)` pairs in an
`ImmutableArray` rather than named properties: a set of named properties has no order to express,
and cannot carry the Google-private identifiers 12583/12584 or a GREASE identifier at all
(`TlsQuicTransportParameterSpec.cs:10-18`, `TlsQuicHttp3Spec.cs:78-83`).

The same applies to `TlsQuicHttp3Spec.PseudoHeaderOrder` and `UnidirectionalStreamOpenOrder`, and
to `TlsQuicConnectionSpec.InitialFrameOrder`.

### 2. `UNVERIFIED` means the capture cannot bound it.

Values marked `UNVERIFIED` ship as **declared placeholders naming the task that would settle
them**, and they surface in a readout's third column,
`TlsQuicHttp3FingerprintReadout.NotYetKnown = "not-yet-known-from-the-capture"`
(`src/SharpTls/Quic/TlsQuicHttp3FingerprintReadout.cs:225`). The full list is
[below](#every-unverified-value). Do not read one as a measurement of Chromium.

The marker's form is enforced by a test:
`TlsQuicTransportParameterSpecTests.EveryUnverifiedPresetChoiceNamesATaskThatExistsInTheBPlan`
counts the markers, counts the ones carrying a task reference, and resolves each reference against
the B plan's headings (`TlsQuicTransportParameterSpec.cs:154-161`).

### 3. Offer-only versus implemented.

A cipher suite or a named group appearing in an enum is **not** necessarily negotiable. See
[Offer-only versus implemented](#offer-only-versus-implemented). In short: 6 of 31 TLS 1.2 suites
are keyed, and `Ffdhe2048`/`Ffdhe3072` are advertisable but throw if you ask for a key share.

### 4. The h3 ClientHello is not a `TlsProfile`.

RFC 9001 §8.4 forbids extensions a TCP profile carries, so the QUIC TLS half comes from
`TlsQuicClientHelloProfileFactory` — **not** from a browser `ClientHelloProfile`. The comment
stating this lives in the consumer:
`TlsClient-main/src/TlsClient/Http3Connection.cs:177-180`
> `// NOT configuration.Profile: a TlsProfile describes a TCP ClientHello ... extensions are ones`
> `// RFC 9001 section 8.4 forbids over QUIC. Making a persona drive this needs a QUIC-shaped`
> `// profile that does not exist yet.`

`grep -rn "8\.4" --include=*.cs SharpTls/src TlsClient-main/src` returns that one site.

### 5. The QUIC and HTTP/3 types are `internal`.

`TlsQuicConnectionSpec`, `TlsQuicHttp3Spec`, `TlsQuicRecoverySpec`,
`TlsQuicTransportParameterSpec`, `TlsQuicLocalFlowControlSpec`, `TlsQuicConnectionOptions` and
`TlsQuicClientHelloProfileFactory` are **all `internal sealed`**
(`grep -rnE "^(public|internal)\s+(sealed )?(class|record|struct|enum)" src/SharpTls/Quic/*.cs
src/SharpTls/ClientHello/TlsQuicClientHelloProfileFactory.cs`). They are reachable only from the
assemblies named in `src/SharpTls/Properties/AssemblyInfo.cs`:

```
:3  SharpTls.Tests        :4  SharpTls.Fuzz
:5  SharpTls.Benchmarks   :6  SharpTls.CoverageFuzz
:16 TlsClient             :17 TlsClient.Tests     (added in f2e3242)
```

That file states the intent outright (`:12-15`): *"DELIBERATELY InternalsVisibleTo RATHER THAN
public. Those types are four commits old and still moving ... When the public surface IS designed,
this line should go away rather than sit alongside it."*

**The TLS/JA3 layer is the opposite: it is fully `public`.** `ClientHelloBuilder`,
`ClientHelloProfile`, `ClientHelloProfiles`, `ClientHelloSpec`, `ClientHelloSpecJson`,
`ClientHelloGreasePolicy`, `ClientHelloExtensionSpec` and `ClientHelloExtensionKind` are all
`public` (`src/SharpTls/ClientHello/ClientHelloBuilder.cs:7`, `ClientHelloProfile.cs:7`,
`ClientHelloSpec.cs:10`, `ClientHelloSpecJson.cs:20`, `ClientHelloGreasePolicy.cs:4,:30`,
`ClientHelloExtensionSpec.cs:7`, `ClientHelloExtensionKind.cs:4`).

---

## Reachability: the three-way split

Every knob in this document falls in exactly one of three buckets. The bucket is named in each
table's **Reach** column.

| Bucket | Meaning |
| --- | --- |
| **public** | Callable from any consumer of the `SharpTls` NuGet surface. |
| **in-assembly** | `internal`. Callable from `SharpTls.Tests`, `SharpTls.Fuzz`, `SharpTls.Benchmarks`, `SharpTls.CoverageFuzz`, `TlsClient` and `TlsClient.Tests`, and from nowhere else. |
| **unwired** | The property exists and validates, but **nothing under `src/` reads it**, so setting it changes no byte. Listed separately in [Knobs nothing currently reads](#knobs-nothing-currently-reads). |

Values that are not knobs at all — baked in, unreachable, or fixed by construction — are in
[Not configurable, and should be](#not-configurable-and-should-be).

---

## Layer 1 — TLS / JA3

All of `ClientHelloBuilder` is **public**. Line numbers are
`src/SharpTls/ClientHello/ClientHelloBuilder.cs`.

### Builder knobs

Defaults are the private field initialisers at `:11-68`.

| Knob | Type | Default | Wire effect | Fingerprinted | Reach |
| --- | --- | --- | --- | --- | --- |
| `WithCipherSuites` `:116` | `params TlsCipherSuite[]` | `TlsAes128GcmSha256, TlsAes256GcmSha384, TlsChaCha20Poly1305Sha256` (`:20-25`) | `cipher_suites` vector, exact order | **Yes** — JA3 field 2 | public |
| `WithSupportedVersions` `:85` | `params TlsProtocolVersion[]` | `[Tls13]` (`:27`) | `supported_versions` (43) body; forces the extension on | **Yes** | public |
| `WithTls13` `:71` | — | — | Shorthand: TLS 1.3 only, `supported_versions` + `key_share` on | Yes | public |
| `WithLegacyTls12ClientHello` `:103` | — | — | Drops `supported_versions` and `key_share` entirely; `legacy_version` carries TLS 1.2 | **Yes** — a whole different ClientHello shape | public |
| `WithSupportedGroups` `:195` | `params NamedGroup[]` | `Secp256r1, Secp384r1` (`:31`) | `supported_groups` (10), exact order. Also mirrors into key shares unless `WithKeyShares` was called (`:199-202`) | **Yes** — JA3 field 4 | public |
| `WithKeyShares` `:208` | `params NamedGroup[]` | mirrors `supported_groups`; `null` until set (`:32-33`) | `key_share` (51) entries, exact order. **Empty list deliberately requests HelloRetryRequest** | **Yes** | public |
| `WithSignatureAlgorithms` `:217` | `params SignatureScheme[]` | 9 schemes: `EcdsaSecp256r1Sha256, EcdsaSecp384r1Sha384, EcdsaSecp521r1Sha512, RsaPssRsaeSha256/384/512, RsaPssPssSha256/384/512` (`:34-45`) | `signature_algorithms` (13), exact order | **Yes** | public |
| `AllowDuplicateSignatureAlgorithms` `:271` | `bool` | `false` (`:46`) | Permits a repeated scheme, for byte-faithful imported profiles | Enables an otherwise-rejected wire image | public |
| `WithGreaseSignatureAlgorithms` `:244` | `bool, int index` | `false`, index `0` (`:47-48`) | Splices one GREASE value into `signature_algorithms` at `index` (clamped). No-op unless GREASE is on | **Yes**. Index placement is `UNVERIFIED` (`:235`) | public |
| `WithCertificateSignatureAlgorithms` `:255` | `params SignatureScheme[]?` | `null` (`:49`) — extension absent | `signature_algorithms_cert` (50); `null` removes it | Yes | public |
| `WithRecordSizeLimit` `:336` | `int?` | `null` (`:50`) — absent | `record_size_limit` (28). Accepts 64…16385 | Yes | public |
| `WithDelegatedCredentials` `:354` | `params SignatureScheme[]?` | `null` (`:51`) — absent | `delegated_credential` (34) | Yes | public |
| `AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity` `:384` | `bool` | `false` (`:52`) | Retains legacy DC schemes in imported historical profiles | Enables an otherwise-rejected wire image | public |
| `WithQuicTransportParameters` `:369` | `TlsQuicTransportParameters?` | `null` (`:53`) — absent | Extension **57** body, exact bytes. `null` removes it | **Yes** — this is the whole QUIC parameter fingerprint | public |
| `WithAlpn` `:278` | `params string[]` | `[]` (`:55`) — absent | `application_layer_protocol_negotiation` (16), exact order. Empty removes it | **Yes** | public |
| `WithApplicationSettings` `:291` | `TlsApplicationSettingsCodePoint, params string[]` | `null` code point, `[]` protocols (`:56-57`) — absent | ALPS extension under one of two code points, **neither IANA-assigned**: `LegacyDraft = 17513` (draft-vvv-tls-alps-01 and older Chromium/uTLS) or `ChromeExperiment = 17613` (current uTLS releases) — `TlsApplicationSettingsCodePoint.cs:7-14`. Protocols must be a non-empty subset of ALPN | **Yes** — *which* code point is itself a fingerprint | public |
| `WithSessionResumption` `:313` | `bool` | off | Toggles `psk_key_exchange_modes` (45), `early_data` (42) and `pre_shared_key` (41) together. PSK slot emitted only when a usable ticket exists | Yes | public |
| `WithPostHandshakeAuthentication` `:325` | `bool` | off | `post_handshake_auth` (49) | Yes | public |
| `WithSni` `:392` | `bool` | `true` (`:67`) | `server_name` (0). Name comes from client options, not from here | Yes | public |
| `WithSessionId` `:400` | `byte[]?` | `null` (`:58`) — a fresh 32-byte compatibility ID | Exact `legacy_session_id` bytes | Yes (length is; contents usually random) | public |
| `WithPadding` `:407` | `int?` | `null` (`:59`) — absent | `padding` (21) with exactly that many zero bytes. Clears BoringSSL mode | Yes | public |
| `WithBoringPadding` `:418` | — | `false` (`:60`) | BoringSSL's 256–511-byte rule, as uTLS browser profiles use | Yes | public |
| `WithExtensionShuffling` `:430` | `bool` | `false` (`:61`) | Chrome-style per-connection shuffle. GREASE, padding and `pre_shared_key` keep their configured positions | **Yes** — a shuffling client and a fixed-order client are different clients | public |
| `WithGreaseEncryptedClientHello` `:440` / `:454` | `params int[]` / `IReadOnlyList<TlsHpkeSymmetricCipherSuite>, params int[]` | `null`/`null` (`:62-63`) — absent | GREASE `encrypted_client_hello` (0xFE0D). Payload lengths are pre-encryption; empty derives a plausible padded length. The 2-arg overload sets the exact ordered HPKE candidate set | **Yes** — the HPKE suite list and the payload length are both observable | public |
| `WithGreaseKeyShareBody` `:183` | `byte[]?` | `null` (`:65`) — one fresh random byte per connection | Exact bytes of the GREASE `key_share` entry's body | **Yes** — the body's *length* is on the wire | public |
| `WithSecondaryGreaseExtension` `:157` | `byte[]?` | `null` (`:66`) — absent | A second, independently typed GREASE extension with that exact body. Requires GREASE on and requires the policy to give the two extension slots distinct classes (`:141-148`, `:167-173`) | **Yes** | public |
| `BuildSpec` `:492` | → `ClientHelloSpec` | — | Validates and freezes | — | public |

### Extension order and layout

Two mutually exclusive ways to fix the wire order. `WithExtensionOrder` clears any layout
(`:470`); `WithExtensionLayout` supersedes the order.

| Knob | Type | Default | Wire effect |
| --- | --- | --- | --- |
| `WithExtensionOrder` `:467` | `params ClientHelloExtensionKind[]` | `ServerName, SupportedVersions, SupportedGroups, SignatureAlgorithms, KeyShare` (`:11-18`) | The exact order of every **enabled built-in** extension. Extensions turned on later by other `With…` calls are inserted by `SetExtensionEnabled`. |
| `WithExtensionLayout` `:480` | `params ClientHelloExtensionSpec[]` | `null` (`:68`) | An exact mixed layout of semantic built-ins **and opaque raw extensions**. Every enabled built-in must occur exactly once. Raw data is snapshotted (`:486`). |

`ClientHelloExtensionKind` has 20 members
(`grep -cE "^\s+[A-Za-z][A-Za-z0-9]*,?$" src/SharpTls/ClientHello/ClientHelloExtensionKind.cs`).

**`ClientHelloExtensionSpec.Raw(ushort, byte[])` is how *any* IANA extension number is emittable.**
`src/SharpTls/ClientHello/ClientHelloExtensionSpec.cs:52-64`: it takes a bare `ushort` type and an
arbitrary body up to `ushort.MaxValue` bytes, clones it, and the encoder writes it verbatim. There
is no allow-list. The stated cost, from the same file's doc comment: *"SharpTls does not implement
response semantics for raw extensions and fails if a peer requires them."* Aggregate raw extension
data is capped at 48 KiB (`ClientHelloBuilder.cs:9`, `MaxAggregateRawExtensionData`).

`ClientHelloExtensionSpec.BuiltIn(kind)` `:37` is the other constructor — a semantic slot whose
body SharpTls constructs.

### GREASE

`src/SharpTls/ClientHello/ClientHelloGreasePolicy.cs`. **The policy never fixes the GREASE code
point** — secure generation draws fresh values per connection. What the policy fixes is the
*value-equality classes*: which placements share one generated value.

Seven slots, `ClientHelloGreaseSlot` `:4-24`:

| Slot | Placement |
| --- | --- |
| `CipherSuite` | Leading `cipher_suites` value |
| `SupportedVersion` | Leading `supported_versions` value |
| `SupportedGroup` | Leading `supported_groups` value |
| `KeyShare` | Leading `key_share` entry |
| `Extension` | The empty GREASE extension type |
| `SecondaryExtension` | The optional second GREASE extension type |
| `SignatureAlgorithm` | The value spliced into `signature_algorithms`. BoringSSL gives this its own `ssl_grease_signature_algorithm` seed index, so it is an independent placement (`:18-22`). Added by commit `0cd3678`. |

| Knob | Type | Default | Wire effect | Fingerprinted | Reach |
| --- | --- | --- | --- | --- | --- |
| `WithGrease(bool)` `ClientHelloBuilder.cs:124` | `bool` | GREASE off (`:64`, `_greasePolicy = null`) | Turns GREASE on with `ClientHelloGreasePolicy.Consistent` and inserts the GREASE extension **at the start** | **Yes** | public |
| `WithGrease(policy)` `:138` | `ClientHelloGreasePolicy` | — | Same, with a caller-defined equality pattern | **Yes** | public |
| `ClientHelloGreasePolicy.Consistent` `:54` | static | `Create(0,0,0,0,0)` | **One** fresh value reused in every placement | Yes | public |
| `ClientHelloGreasePolicy.PerSlot` `:57-58` | static | `CreateWithSignatureAlgorithm(0,1,2,3,4,5,6)` | A **distinct** fresh value in every placement | Yes | public |
| `Create(…5 classes)` `:66` | 5 × `int` | — | cipher / version / group / key share / extension. The secondary-extension slot shares `extensionClass` (`:73-79`) | Yes | public |
| `CreateWithSecondaryExtension(…6)` `:87` | 6 × `int` | — | Adds an independent class for the second GREASE extension; the sigalg slot still shares `extensionClass` (`:94-100`) | Yes | public |
| `CreateWithSignatureAlgorithm(…7)` `:110` | 7 × `int` | — | All seven slots independently classed | Yes | public |

Class labels must be `0..15` (`:126-131`); they are then **normalised by first occurrence**
(`:133-144`), so `Create(5,5,9,9,9)` and `Create(0,0,1,1,1)` are the same policy.
`DistinctValueCount` `:59` reports how many independent values a policy needs.
`ValueClasses` `:161` is frozen at the original five for API compatibility and must not track new
slots (`:39-42`).

### Offer-only versus implemented

This distinction matters enormously to someone building a profile: a value in an enum is a value
you can *offer*, not necessarily one you can *complete a handshake with*.

**Named groups.** The enum has **8** members
(`awk '/^public enum NamedGroup/,/^}/' src/SharpTls/Protocol/TlsEnums.cs | grep -E "= 0x"`):

| Group | Advertisable in `supported_groups` | Usable as a key share |
| --- | --- | --- |
| `Secp256r1` (0x0017) | yes | yes |
| `Secp384r1` (0x0018) | yes | yes |
| `Secp521r1` (0x0019) | yes | yes |
| `X25519` (0x001D) | yes | yes — routed to `X25519KeyShare`, **not** to `EcdheKeyShare` |
| `X25519MlKem768` (0x11EC) | yes | yes (hybrid; reuses the classical X25519 share when both are offered — `KeyShareSet.cs:36-45`) |
| `X25519Kyber768Draft00` (0x6399) | yes | yes (hybrid, same reuse) |
| **`Ffdhe2048` (0x0100)** | **yes** | **NO — throws** |
| **`Ffdhe3072` (0x0101)** | **yes** | **NO — throws** |

Two guards enforce the asymmetry:
- `ClientHelloBuilder.EnsureAdvertisableGroup` `:1041-1050` accepts all eight.
- `ClientHelloBuilder.EnsureKeyShareGroup` `:1063-1070` accepts six, and throws
  `NotSupportedException($"Named group {group} has no implemented key-share provider.")` for the
  two FFDHE groups.

Below that, `EcdheKeyShare.Create` (`src/SharpTls/Cryptography/EcdheKeyShare.cs:47-57`) has the
final throw:
- `:54-55` — `X25519 => throw new NotSupportedException("X25519 is not advertised because .NET 9
  has no portable raw X25519 TLS primitive.")`. Unreachable in practice: `KeyShareFactory` routes
  X25519 elsewhere.
- **`:56` — `_ => throw new NotSupportedException($"Named group 0x{(ushort)group:X4} is not
  supported.")`.** This is where `Ffdhe2048`/`Ffdhe3072` land if the builder guard is bypassed.

So: put FFDHE in `WithSupportedGroups` to reproduce a capture that advertises it. Never put it in
`WithKeyShares`.

**Cipher suites.** The enum has **31** members
(`awk '/^public enum TlsCipherSuite/,/^}/' src/SharpTls/Protocol/TlsEnums.cs | grep -cE "= 0x"`).

- **3 TLS 1.3 suites, all keyed:** `TlsAes128GcmSha256` (0x1301), `TlsAes256GcmSha384` (0x1302),
  `TlsChaCha20Poly1305Sha256` (0x1303).
- **6 TLS 1.2 suites are keyed** — the entire `Tls12CipherSuiteInfo.Get` switch,
  `src/SharpTls/Cryptography/Tls12CipherSuiteInfo.cs:30-63`:
  `TlsEcdheEcdsaWithAes128GcmSha256` (0xC02B), `TlsEcdheRsaWithAes128GcmSha256` (0xC02F),
  `TlsEcdheEcdsaWithAes256GcmSha384` (0xC02C), `TlsEcdheRsaWithAes256GcmSha384` (0xC030),
  `TlsEcdheRsaWithChaCha20Poly1305Sha256` (0xCCA8),
  `TlsEcdheEcdsaWithChaCha20Poly1305Sha256` (0xCCA9).
- **The remaining 22 are offer-only.** Every CBC, 3DES, RC4, plain-RSA and DHE suite in the enum
  exists so a historical capture can be reproduced byte-for-byte. Negotiating one throws
  `Tls12CipherSuiteInfo.cs:62-63`:
  `NotSupportedException($"TLS 1.2 cipher suite 0x{…:X4} is not a supported AEAD ECDHE suite.")`.

`ClientHelloBuilder.BuildConfiguration` `:508-514` only rejects a suite that is not a *defined
enum member* — it does not require the suite be keyed. Offering an unkeyed suite is legal and
intended; completing a handshake on it is not.

**Signature schemes.** 19 enum members. `IsLegacySignatureScheme` `:1052-1053` names
`RsaPkcs1Sha1` and `EcdsaSha1` as offer-only-ish; `IsExecutableDelegatedCredentialAlgorithm`
`:1055-1061` names the six schemes a delegated credential may actually use, with
`AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity` as the escape hatch for
reproducing historical profiles.

### Profiles, specs and JSON round-trip

| Entry point | Signature | Notes |
| --- | --- | --- |
| `ClientHelloProfiles.Custom` `ClientHelloProfile.cs:83` | `Action<ClientHelloBuilder>` → `ClientHelloProfile` | Runs your configuration on a fresh builder, then `FromSpec(builder.BuildSpec())`. Validation happens here, not at send time. |
| `ClientHelloProfiles.FromSpec` `:90` | `ClientHelloSpec` → `ClientHelloProfile` | Snapshots the spec's configuration. |
| `ClientHelloProfiles.ModernTls13` `:79` | static | `Custom(b => b.WithSessionResumption())` — the default production profile. |
| `ClientHelloProfile.Spec` `:20` | → `ClientHelloSpec` | Immutable snapshot; 30 read-only members (`grep -cE "^\s+public " src/SharpTls/ClientHello/ClientHelloSpec.cs`) covering every builder knob. |
| `ClientHelloProfile.BuildDeterministicForTesting` `:25` | `(string serverName, byte[] seed)` → `byte[]` | Byte-for-byte repeatable. **Fixed test-only ECDHE keys; never send on a network.** |
| `ClientHelloSpecJson.Serialize` / `SerializeUtf8` `ClientHelloSpecJson.cs:64`, `:41` | `ClientHelloSpec` → `string` / `byte[]` | |
| `ClientHelloSpecJson.Deserialize` `:70`, `:121` | `string`/`ReadOnlySpan<byte>` → `ClientHelloSpec` | The round-trip: capture → spec → JSON → spec → profile. |

**49 shipped named profiles**, plus `ModernTls13`:
`grep -rhoE "public static ClientHelloProfile [A-Za-z0-9_]+" src/SharpTls/ClientHello/UTlsClientHelloProfiles*.cs src/SharpTls/ClientHello/CapturedClientHelloProfiles.cs` yields 49 names —
13 Chrome (`UTlsChrome58` … `UTlsChrome133`), 6 Firefox modern + 4 legacy, Edge 85/106,
Safari 16/263, iOS 11.1/12.1/13/14, Android 11 OkHttp, 360 Browser 7.5/11.0, QQ 11.1, Spotify iOS,
and 8 `…Auto` rollers. See `docs/PROFILE-CATALOG.md` and .

### Example — TLS layer

Public API; compiles against the shipped surface.

```csharp
using SharpTls;
using SharpTls.Protocol;

var profile = ClientHelloProfiles.Custom(b => b
    // --- vectors, in exact wire order ---
    .WithSupportedVersions(TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls12)
    .WithCipherSuites(
        TlsCipherSuite.TlsAes128GcmSha256,
        TlsCipherSuite.TlsAes256GcmSha384,
        TlsCipherSuite.TlsChaCha20Poly1305Sha256,
        TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256,   // keyed
        TlsCipherSuite.TlsRsaWithAes128CbcSha)             // OFFER-ONLY: cannot negotiate
    .WithSupportedGroups(
        NamedGroup.X25519MlKem768,
        NamedGroup.X25519,
        NamedGroup.Secp256r1,
        NamedGroup.Ffdhe2048)                              // advertisable, NOT key-shareable
    .WithKeyShares(NamedGroup.X25519MlKem768, NamedGroup.X25519)  // Ffdhe here would throw
    .WithSignatureAlgorithms(
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPkcs1Sha256)

    // --- GREASE: seven slots, four sharing one value, three independent ---
    .WithGrease(ClientHelloGreasePolicy.CreateWithSignatureAlgorithm(
        cipherSuiteClass: 0, supportedVersionClass: 0, supportedGroupClass: 0,
        keyShareClass: 0, extensionClass: 1, secondaryExtensionClass: 2,
        signatureAlgorithmClass: 3))
    .WithGreaseSignatureAlgorithms(enabled: true, index: 0)   // BoringSSL prepends
    .WithGreaseKeyShareBody([0x00])                           // exact body, not one random byte
    .WithSecondaryGreaseExtension([])                         // empty body, distinct type

    // --- application layer ---
    .WithAlpn("h2", "http/1.1")
    .WithApplicationSettings(TlsApplicationSettingsCodePoint.ChromeExperiment, "h2")
    .WithSessionResumption()
    .WithBoringPadding()
    .WithGreaseEncryptedClientHello()

    // --- exact wire order, mixing built-ins with an arbitrary IANA extension ---
    .WithExtensionLayout(
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ApplicationSettings),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PskKeyExchangeModes),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EncryptedClientHello),
        ClientHelloExtensionSpec.Raw(0x0012, []),          // signed_certificate_timestamp
        ClientHelloExtensionSpec.Raw(0x001B, [0x02, 0x00, 0x02]),  // compress_certificate
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SecondaryGrease),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PreSharedKey)));

// Round-trip it through JSON.
var json = ClientHelloSpecJson.Serialize(profile.Spec);
var reloaded = ClientHelloProfiles.FromSpec(ClientHelloSpecJson.Deserialize(json));
```

---

## Layer 2 — QUIC

**All types in this section are `internal`.** Reach is `in-assembly` unless a row says `unwired`.

### `TlsQuicConnectionSpec`

`src/SharpTls/Quic/TlsQuicConnectionSpec.cs:95`. Defaults are the field initialisers at
`:168-184`. Every bound is enforced **as it is set**, so a spec that exists is a spec in range
(`:91-93`); there is no separate validate step.

| Knob | Type | Default | Wire effect | Fingerprinted | Reach |
| --- | --- | --- | --- | --- | --- |
| `SourceConnectionIdLength` `:205` | `int` | **0** — the capture's `client_connection_id_length` (`:200-201`) | Long header's Source Connection ID Length + the ID itself. **No floor**: RFC 9000 §7.2 says "a value of its choosing". Ceiling `TlsQuicPacketHeader.MaximumConnectionIdLength` | **Yes** | in-assembly |
| `DestinationConnectionIdLength` `:227` | `int` | **8** — the capture's `server_connection_id_length`, sitting exactly on the floor (`:223-224`) | Destination Connection ID on pre-server-response Initials. **Floored at 8** by §7.2's MUST (`:134`); the capture cannot reveal that floor (`:112-115`) | **Yes** | in-assembly |
| `InitialPacketNumber` `:250` | `ulong` | **0** | First Initial's packet number. Capped at 2^62−1 | Not observed by the capture (`:247`) | in-assembly |
| `PacketNumberEncodedLength` `:276` | `int` 1–4 | **4** | Bytes the truncated packet number is written in, regardless of how few suffice | **Yes**, and the default is a **placeholder** — RFC 9001 A.2's non-minimal choice, *not* evidence about Chromium (`:268-273`) | in-assembly |
| `Token` `:305` | `ReadOnlyMemory<byte>` | empty | Initial packet's Token field. Documented, **not validated** — no reachable bound exists (`:296-300`). Not copied; caller keeps it alive | Yes | in-assembly |
| `PaddingTarget` `:325` | `int` 1200–65527 | **1200** (RFC 9000 §14.1's floor, `:146`) | Size every Initial-carrying UDP datagram is expanded to, with PADDING frames | **Yes** | in-assembly |
| `InitialCryptoFrameByteCounts` `:357` | `ImmutableArray<int>` | **`[]`** = one frame carrying everything (`:173`) | Where the Initial CRYPTO stream is cut. **Empty is not "unspecified"** — it pins the frame count at one (`:348-351`) | **Yes** — a 1216-byte X25519MLKEM768 share forces a split | in-assembly |
| `InitialCryptoFramesPerDatagram` `:392` | `ImmutableArray<int>` | **`[]`** = one datagram holding all frames (`:174`) | How many consecutive CRYPTO frames each datagram carries. **Empty here IS unspecified** — the asymmetry with the row above is deliberate (`:383-386`) | **Yes** | in-assembly |
| `InitialFrameOrder` `:434` | `ImmutableArray<TlsQuicFrameType>` | **`[Crypto, Padding]`** (`:175-176`), RFC 9001 A.2's order | Decides **only** whether the PADDING the datagram builder adds *itself* leads or trails (`:411-419`). Nothing reorders caller-supplied frames | Yes | in-assembly |
| `HeaderLengthVarintWidth` `:494` | `TlsQuicVarintWidth` | **`Minimal`** (`:177`) | Long header Length field's varint width. RFC 9000 §16 permits any width that holds the value | **Yes** — fingerprint field 7 | in-assembly |
| `CryptoOffsetVarintWidth` `:523` | `TlsQuicVarintWidth` | **`Minimal`** (`:178`) | CRYPTO frame Offset varint width | **Yes** | in-assembly |
| `CryptoLengthVarintWidth` `:540` | `TlsQuicVarintWidth` | **`Minimal`** (`:179`) | CRYPTO frame Length varint width | **Yes** | in-assembly |
| `InitialRttRange` `:576` | `(TimeSpan Min, TimeSpan Max)?` | **`null`** (`:180`) | **A policy, never a value.** Overrides the range `initial_rtt` (12583) is drawn from per connection. `null` falls back to the parameter entry's own declared range (`:561-568`) | **Yes** — a *pinned* value is itself a fingerprint | in-assembly |
| `AckRangeLimit` `:641` | `int` ≥ 1 | **32** (`DefaultAckRangeLimit`, `:595`) | How many ACK Ranges are retained and reported per packet-number space | **Yes**, and the default is an explicit **placeholder** — the capture says nothing about ACK ranges (`:616-621`) | in-assembly |
| `CoalesceAscendingByLevel` `:672` | `bool` | **`true`** | Whether packets coalesced into one datagram are ordered by ascending encryption level. `false` emits descending — legal, and §12.2 advises against it | **Yes** | in-assembly |
| `AckLeadsInPacket` `:694` | `bool` | **`true`** | Whether an ACK frame is written before or after the CRYPTO frames of the same packet | **Yes** — no RFC imposes a frame order, and the capture observes none (`:677-684`) | in-assembly |
| `LocalFlowControl` `:715` | `TlsQuicLocalFlowControlSpec` | `new()` (`:182`) | See below | Yes | in-assembly |
| `TransportParameters` `:747` | `TlsQuicTransportParameterSpec` | `new()` (`:183`) | See below | **Yes** | in-assembly |
| `Recovery` `:773` | `TlsQuicRecoverySpec` | `new()` (`:184`) | See below | Yes (behavioural) | in-assembly |

**Not knobs here, deliberately** — the type's header (`:60-90`) names three size numbers that must
never be derived from one another:
1. `max_udp_payload_size` (0x03, that client advertises 1472) — a **transport parameter**, so it lives in
   `TlsQuicTransportParameterSpec`, not here. Says what we are willing to *receive*.
2. `PaddingTarget` — says what we *send*.
3. `ITlsQuicDatagramTransport.MaxDatagramPayloadSize` — says what we *can* send.

The capture is explicit: *"Advertised parameter and actual ceiling are separate concerns and must
not be wired together."* There is no arithmetic between the three anywhere in the codebase.

Also absent by design: `initial_rtt` itself (a transport parameter — only its *range* lives here);
`ack_delay_exponent` (already a transport parameter, carried in `TlsQuicTransportParameters`);
`kGranularity` (a platform timer floor, not a client choice — `TlsQuicRecoverySpec.cs:477-480`);
and the coalescing route to §14.1's 1200-byte floor, because only the PADDING route is implemented
so the knob would have exactly one legal value (`:316-321`).

### `TlsQuicLocalFlowControlSpec`

`TlsQuicConnectionSpec.cs:983`. These six are the **one set of transport parameters that lives in
the connection spec**, because RFC 9000 §4.1 makes a receiver's enforced limits the ones it
advertised — the number on the wire and the number `TlsQuicStreamSet` enforces must be one number
(`:699-707`). `TlsQuicTransportParameterSpec.Compose` *places* them rather than restating them.

**Every default below is a client capture's**, rows 4, 5, 6, 7, 11 and 12 of its
"QUIC transport parameters, in wire order" table (`:970-975`). There is no placeholder among the
six.

| Knob | Type | Default | Parameter | Bound |
| --- | --- | --- | --- | --- |
| `InitialMaxData` `:1013` | `ulong` | **15728640** (`:989`) | 0x04 | ≤ 2^62−1 |
| `InitialMaxStreamDataBidiLocal` `:1025` | `ulong` | **6291456** (`:990`) | 0x05 | ≤ 2^62−1 |
| `InitialMaxStreamDataBidiRemote` `:1041` | `ulong` | **6291456** (`:991`) | 0x06 | ≤ 2^62−1 |
| `InitialMaxStreamDataUni` `:1053` | `ulong` | **6291456** (`:992`) | 0x07 | ≤ 2^62−1 |
| `InitialMaxStreamsBidi` `:1063` | `ulong` | **100** (`:993`) | 0x08 | ≤ 2^60 (§19.11) |
| `InitialMaxStreamsUni` `:1078` | `ulong` | **103** (`:994`) | 0x09 | ≤ 2^60. **Not floored at three** here — HTTP/3's §6.2 requirement is carried by `TlsQuicConnectionOptions.RequiredPeerUnidirectionalStreams`, in the direction where a violation is the peer's (`:1071-1075`) |

`ToTransportParameters()` `:1093` emits them **ascending by id, which is not the capture's order** —
matching the capture's order needs the whole 14-entry list and therefore belongs to
`TlsQuicTransportParameterSpec` (`:1086-1092`).

`ReceiveWindowUpdateDivisor = 2` (`:1007`) is a **`const`, not a knob**, and is a declared
placeholder: RFC 9000 §19.9/§19.10 never say when to send a window update, and the capture observes
a ClientHello so it cannot observe a mid-connection frame at all. See
[Not configurable, and should be](#not-configurable-and-should-be).

### `TlsQuicTransportParameterSpec`

`src/SharpTls/Quic/TlsQuicTransportParameterSpec.cs:284`.

**Wire order is fingerprinted.** This is the single most important fact in this document. The
capture's table is headed *"in wire order"* and line 74 says: *"This ordering is the fingerprint.
It is not sorted, and it is not the RFC's presentation order."* Task B11 (`2247128`) proved it live
at `fp.impersonate.pro`: reordering the list moved `perk_hash` and left `perk_hash_normalized`
byte-identical, over 12 attempts (`TlsQuicConnectionSpec.cs:731-737`).

| Knob | Type | Default | Wire effect | Fingerprinted | Reach |
| --- | --- | --- | --- | --- | --- |
| `Parameters` `:523` | `ImmutableArray<TlsQuicTransportParameterSlot>` | **`RfcMinimumParameters`** (`:514-515`, `:445-508`) — 14 entries in the capture's order | The whole extension-57 body, emitted **unchanged, in the order listed** | **Yes — position *and* contents** | in-assembly |

*Any identifier, any bytes, any order, any subset* (`:518-520`). No refusal here. The only two
remaining constraints are `TlsQuicTransportParameters`': no duplicate identifier (RFC 9000 §18), and
a cap on count and encoded length (`:270-272`).

**The slot model** — `TlsQuicTransportParameterSlot`, `:46`. Three kinds:

| Factory | Meaning |
| --- | --- |
| `Literal(ulong id, ReadOnlySpan<byte> value)` `:79` | Emit exactly these bytes under this identifier. No bound applied here; `TlsQuicTransportParameter`'s constructor already rejects id > 2^62−1 and value > 65535 bytes (`:74-78`). |
| `Placed(ulong id)` `:84` | Name an identifier **without** a value; `Compose` fills it from the one place that owns the number. Seven identifiers are placed: the six flow-control ones and `initial_source_connection_id`. A `Literal` on any of those seven is **rejected**, not silently preferred (`:19-28`, `Compose` `:846-855`). |
| `Drawn(Func<TlsQuicConnectionSpec, TlsQuicTransportParameter?>)` `:103` | Identifier *and* value produced afresh **on every `Compose`**, never cached (`:89-92`). Returning `null` **omits the parameter while keeping its position out of the list** (`:93-96`). `Id` is 0 on a drawn slot because the identifier is not known until the draw runs (`:97-99`). |

`default(TlsQuicTransportParameterSlot)` is `Placed(0)`, which `Compose` rejects with a named
message rather than throwing `NullReferenceException` (`:39-44`).

**The three per-connection draws.** Three of the fourteen are redrawn per connection because a
pinned per-connection field is itself a fingerprint:

| Draw factory | Signature | Preset use | Range drawn over |
| --- | --- | --- | --- |
| `DrawnReservedParameter` `:667` | `(ulong minimumN, ulong maximumN, byte[] value)` | Entry **2**, capture line 80. Value `0xfb`; identifier redrawn (`:451-457`) | `0 … MaximumReservedIdentifierN` `:552` — the **whole** of RFC 9000 §18.1's `31*N+27` reserved set, computed from the RFC's own form (`:547-551`) |
| `DrawnVersionInformation` `:697` | `(uint chosenVersion, IReadOnlyList<uint?> availableVersions)` | Entry **9**, capture line 87. `chosen 1, available [GREASE, 1]`; the `null` element **is** the GREASE slot (`:479-485`) | RFC 9368 §3's `0x?a?a?a?a` pattern — four free nibbles, 16^4 versions, drawn independently (`DrawReservedVersion` `:594-603`) |
| `DrawnInitialRtt` `:734` | `(ulong identifier, (TimeSpan Min, TimeSpan Max)? fallbackRange)` | Entry **13**, capture line 91, identifier **12583** (`:376`) | `TlsQuicConnectionSpec.InitialRttRange` when set, else the entry's declared fallback — the preset's is `DeclaredInitialRttRange` `:421-422` = **100 ms … 300 ms**, which is **`UNVERIFIED`** |

**`RfcMinimumParameters`** `:445-508` — the fourteen, in the capture's wire order. 4 literal +
7 placed + 3 drawn = 14 (`:431-440`):

| # | Capture line | Identifier | Kind | Value |
| --- | --- | --- | --- | --- |
| 1 | 79 | 12584 `google_connection_options` | Literal | `0x4f524947`, ASCII `ORIG` (`:364`) |
| 2 | 80 | reserved (GREASE) | **Drawn** | value `0xfb`; identifier redrawn per connection |
| 3 | 81 | 32 `max_datagram_frame_size` | Literal | 65536 |
| 4 | 82 | 9 `initial_max_streams_uni` | Placed | 103 |
| 5 | 83 | 8 `initial_max_streams_bidi` | Placed | 100 |
| 6 | 84 | 7 `initial_max_stream_data_uni` | Placed | 6291456 |
| 7 | 85 | 5 `initial_max_stream_data_bidi_local` | Placed | 6291456 |
| 8 | 86 | 15 `initial_source_connection_id` | Placed | the connection's own SCID (empty, from `SourceConnectionIdLength = 0`) |
| 9 | 87 | 17 `version_information` | **Drawn** | chosen 1, available `[GREASE, 1]` |
| 10 | 88 | 1 `max_idle_timeout` | Literal | 30000 |
| 11 | 89 | 6 `initial_max_stream_data_bidi_remote` | Placed | 6291456 |
| 12 | 90 | 4 `initial_max_data` | Placed | 15728640 |
| 13 | 91 | 12583 `initial_rtt` | **Drawn** | fresh µs draw — **not** the capture's 192859 |
| 14 | 92 | 3 `max_udp_payload_size` | Literal | 1472 — **not** `PaddingTarget`, **not** the transport ceiling |

`Compose(TlsQuicConnectionSpec, ReadOnlySpan<byte> sourceConnectionId)` `:794` runs the draws
**in place at the index they were listed at** (`:825-834`), places the seven, and rejects a source
connection ID whose length disagrees with `SourceConnectionIdLength` (`:808-814`).

### `TlsQuicRecoverySpec`

`src/SharpTls/Quic/TlsQuicRecoverySpec.cs:388`. These are behavioural rather than layout knobs —
they change *when* and *how many* packets leave, which is countable off a capture without
decrypting anything. Defaults are the field initialisers at `:536-548`; every literal is in the
preset block `:396-532`.

The A3 plan counts **fourteen** knobs. Twelve are on this type; the other two —
`InitialRttRange` (knob 1, reached through the static `DrawInitialRtt`) and `AckRangeLimit`
(knob 13) — live on `TlsQuicConnectionSpec` (`TlsQuicConnectionSpec.cs:754-757`). There is no
`// Knob 13` marker in `src/` (`grep -rn "Knob 13" --include=*.cs src/` returns nothing).

| # | Knob | Type | Default | Wire/behaviour effect | `UNVERIFIED` | Reach |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `DrawInitialRtt(spec, random?)` `:884` — **static method, not a property** | → `TimeSpan` | draws from `TlsQuicConnectionSpec.InitialRttRange`; falls back to `KInitialRtt` = **333 ms** (`:413`) only when that is `null` | The RTT the connection starts with; sets the first PTO | no | in-assembly |
| 2 | `InitialCongestionWindow` `:568` | `(int DatagramMultiplier, int ByteCap)` | **(10, 14720)** (`:536-537`, `:429`, `:439`) | RFC 9002 §7.2's `min(mult*mds, max(cap, 2*mds))`. One member for one knob so a caller cannot set half of §7.2's rule | **YES**, task A3-14, **both halves** (`:559-561`) | in-assembly |
| 3 | `MinimumCongestionWindowDatagrams` `:591` | `int` > 0 | **2** (`:538`, `:447`) | The floor the window settles at on a lossy path, i.e. the steady-state send rate | no | in-assembly |
| 4 | `CongestionController` `:620` | `Func<ITlsQuicCongestionController>?` | **`null`** = RFC 9002 NewReno | *"The largest single fingerprint in loss recovery"* (`:605`). Chromium is said to run BBR; the two produce visibly different send-rate curves in one recovery episode | **YES**, task A3-14 (`:615-618`) | **unwired** — nothing in `src/` reads it |
| 5 | `LossReductionFactor` `:631` | `double` (0, 1] | **0.5** (`:539`, `:458`) | Fraction the congestion window is scaled by on a loss event. Observable separately from the controller | no | in-assembly |
| 6 | `PacketThreshold` `:664` | `int` > 0 | **3** (`:540`, `:471`) | Reordering tolerance in packets. §6.1.1's "SHOULD NOT use less than 3" is deliberately **not** enforced (`:469-470`) | no | in-assembly |
| 7 | `TimeThreshold` `:682` | `double` > 0, finite | **9/8** (`:541`, `:481`) | Reordering tolerance as an RTT multiplier | no | in-assembly |
| 8 | `PersistentCongestionThreshold` `:700` | `int` > 0 | **3** (`:542`, `:488`) | How many PTO periods a blackout must last before the window collapses to the minimum | no | in-assembly |
| 9 | `PtoBackoff` `:727` | `(double Factor, TimeSpan? Maximum)` | **(2.0, null)** (`:543-544`, `:496`) | Exponential shape of the probe timeout. Factor ≥ 1. **The factor is cited and the ceiling is not** — §6.2.1 states the doubling as a MUST and never mentions a ceiling, so `null` is what the RFC describes (`:717-722`) | no | in-assembly |
| 10 | `ProbePacketsPerPto` `:753` | `int` 1–2 | **2** (`:545`, `:512`) | How many ack-eliciting packets leave per PTO expiry. Capped at 2 by §6.2.4's "up to two" (`:516`) | no | in-assembly |
| 11 | `ProbeContents` `:773` | `TlsQuicProbeContents` | **`RetransmittedData`** — *was `Ping` until `2195e93`, which a live endpoint answered with `PROTOCOL_VIOLATION` 4 times out of 4; RFC 9000 §6.2.4 lists `Ping` last and scopes it to "when there is no data to send"* | What a probe packet carries: `Ping`, `PingWithPadding`, `RetransmittedData`. Observable twice — the probe datagram's *size* without decrypting, its *frames* with keys | no | in-assembly |
| 12 | `AckPolicy` `:799` | `TlsQuicAckPolicy` | **`Immediate`** (`:547`) | `Immediate` or `DelayedToMaxAckDelay`. Changes how many ACK packets leave and how they are spaced — countable off a capture | **YES**, task A3-14 (`:792-795`) | **wired since A3-13** — `TlsQuicAckTracker`'s `IsWithheldAt` is its only reader. `DelayedToMaxAckDelay` holds an **Application-space** ACK until §18.2's 25 ms `max_ack_delay` — which is what this client advertises, since `max_ack_delay` 0x0B is absent from the transport parameters — and `TlsQuicConnection` gained a `DelayedAck` deadline, so a held ACK still leaves on its own |
| 13 | *(`TlsQuicConnectionSpec.AckRangeLimit`)* | `int` | 32 | see above | placeholder | in-assembly |
| 14 | `PacingBurstDatagrams` `:822` | `int?` > 0 | **10** = `KInitialWindowDatagrams` (`:548`, `:532`) | The pacer's burst allowance. **`null` is the off switch** — a sender that does not pace is exactly a sender whose burst is unlimited, so a separate boolean would admit the meaningless "pacing off, burst 10" (`:812-816`) | **YES**, task A3-14, both halves (`:817-818`) | **wired since A3-11** - `TlsQuicPacer` reads it; `TlsQuicApplicationSendPath`'s `SendGateAdmits` consults the pacer before taking 1-RTT frames |
| 15 | `PacingIntervalScale` | `double` > 0, finite | **1.25** = `DefaultPacingIntervalScale` | RFC 9002 §7.7's `N` in `rate = N * congestion_window / smoothed_rtt`. Row 14 decides how many datagrams leave together; this decides the *gap* before the next allowance arrives. Added by task A3-11, which found that a caller who can set only the burst cannot change the spacing at all - neither `congestion_window` nor `smoothed_rtt` is settable | **YES**, task A3-14 | **wired since A3-11** - `TlsQuicPacer` |

Floating-point guards check finiteness **first and explicitly** (`:636-646`): every comparison
against NaN is false, so `ThrowIfGreaterThan` never rejects one, and `ThrowIfNegativeOrZero` only
rejects NaNs whose sign bit happens to be set.

### `TlsQuicClientHelloProfileFactory`

`src/SharpTls/ClientHello/TlsQuicClientHelloProfileFactory.cs:90`. **`internal`**, and its own doc
comment says why (`:85-88`): its collaborators are internal, so a public factory over them could
not be called by anyone this assembly does not already trust.

**This — not a browser `ClientHelloProfile` — is where the QUIC ClientHello comes from.** It builds
one profile **per connection**, because three of the fourteen transport parameters are redrawn per
connection and `initial_source_connection_id` carries this connection's own SCID; a reused profile
advertises a stale one and RFC 9000 §7.3's receive-side check may close the connection over it
(`:56-65`).

| Knob | Type | Default | Wire effect | Fingerprinted | Reach |
| --- | --- | --- | --- | --- | --- |
| `ConnectionSpec` `:130` | `TlsQuicConnectionSpec` | `new()` (`:97`) | Supplies `TransportParameters` (composed into extension 57's body) and `SourceConnectionIdLength` (fixes the length `Create` accepts). **Must be the same object the connection is constructed with** (`:105-110`) | **Yes** | in-assembly |
| `AlpnProtocols` `:155` | `IReadOnlyList<string>` | `["h3"]` (`:98`, `Http3AlpnToken` `:95`) | ALPN list, wire order. A list and not a boolean because RFC 9114 §3.2 permits offering other protocols in the same handshake — `h3, h3-29` and `h3` are different clients (`:139-142`) | **Yes** | in-assembly |
| `Tls` `:184` | `Action<ClientHelloBuilder>` | no-op (`:99`) → `ClientHelloBuilder`'s own TLS-1.3 defaults | **Everything except ALPN and extension 57's body**: cipher suites, groups, key shares, extension order, ECH, ALPS. Passes through untouched (`:66-71`) | **Yes** | in-assembly |
| `Create(ReadOnlySpan<byte> sourceConnectionId)` `:203` | → `ClientHelloProfile` | — | Composes the parameters afresh and redraws every per-connection value. **Nothing is cached or memoised** (`:195-199`) | — | in-assembly |

**Order of application, and the trap in it.** `Tls` runs **first**; the factory's own `.WithAlpn`
and `.WithQuicTransportParameters` run **after** it (`:214-220`). That is deliberate — those two are
hard-required by `CustomTlsQuicClientOptions.Snapshot`, so running them last means a `Tls` that
forgets either still produces a usable profile. **The cost: a `.WithAlpn(…)` or
`.WithQuicTransportParameters(…)` inside your `Tls` delegate is silently overwritten.** Use
`AlpnProtocols` and `ConnectionSpec.TransportParameters` instead (`:72-80`).

**The extension's *position* is still the profile's.** `WithQuicTransportParameters` enables the
semantic slot; where the slot sits in the wire order is decided by `WithExtensionLayout` inside
`Tls`, exactly as for every other extension (`:81-84`).

**An empty `AlpnProtocols` is refused one layer down** (`:143-151`): `WithAlpn([])` means "remove
the extension", but `BuildConfiguration` then rejects any ClientHello carrying extension 57 with no
ALPN, so `Create` throws `InvalidOperationException`. *A QUIC client offering no ALPN is a
fingerprint this library cannot currently express.*

**The default spec does not carry an Initial flight split** (`:111-127`). A ClientHello offering the
capture's X25519MLKEM768 share spends 1216 bytes on that share alone, so its CRYPTO stream does not
fit one datagram inside the advertised `max_udp_payload_size` of 1472 — yet
`InitialCryptoFrameByteCounts` and `InitialCryptoFramesPerDatagram` default to empty, meaning one
frame in one oversized datagram. Legal under §14.1, throws nothing, and is *not what Chromium
sends*. Derive the split with
`TlsQuicDatagramBuilder.PlanInitialFlightSplit(cryptoStreamLength, cryptoStreamBytesPerDatagram)`
(`src/SharpTls/Quic/TlsQuicDatagramBuilder.cs:506`);
`CryptoStreamBytesPerInitialDatagram = 1400` (`:467`) is a **headroom calculation, not a
measurement** — the exact split point is `UNVERIFIED`, task B12 (`:427-438`).

### Example — QUIC layer

In-assembly only (`SharpTls.Tests`, `TlsClient`, …).

```csharp
using System.Collections.Immutable;
using SharpTls;
using SharpTls.Quic;

// The parameter list. ORDER IS THE FINGERPRINT — this is the capture's, reordered
// deliberately here to show that reordering is what a caller does.
var parameters = new TlsQuicTransportParameterSpec
{
    Parameters =
    [
        TlsQuicTransportParameterSlot.Literal(12584, "ORIG"u8.ToArray()),
        TlsQuicTransportParameterSpec.DrawnReservedParameter(
            minimumN: 0,
            maximumN: TlsQuicTransportParameterSpec.MaximumReservedIdentifierN,
            value: [0xfb]),
        TlsQuicTransportParameterSlot.Literal(
            (ulong)TlsQuicTransportParameterId.MaxDatagramFrameSize,
            QuicVariableLengthInteger.Encode(65536)),
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxStreamsUni),
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxStreamsBidi),
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataUni),
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiLocal),
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId),
        TlsQuicTransportParameterSpec.DrawnVersionInformation(
            chosenVersion: 1, availableVersions: [null, 1]),   // null == the GREASE slot
        TlsQuicTransportParameterSlot.Literal(
            (ulong)TlsQuicTransportParameterId.MaxIdleTimeout,
            QuicVariableLengthInteger.Encode(30000)),
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxStreamDataBidiRemote),
        TlsQuicTransportParameterSlot.Placed(
            (ulong)TlsQuicTransportParameterId.InitialMaxData),
        TlsQuicTransportParameterSpec.DrawnInitialRtt(
            TlsQuicTransportParameterSpec.InitialRttIdentifier,
            fallbackRange: (TimeSpan.FromMicroseconds(100_000),
                            TimeSpan.FromMicroseconds(300_000))),
        TlsQuicTransportParameterSlot.Literal(
            (ulong)TlsQuicTransportParameterId.MaxUdpPayloadSize,
            QuicVariableLengthInteger.Encode(1472)),
    ],
};

var spec = new TlsQuicConnectionSpec
{
    SourceConnectionIdLength = 0,          // capture's client_connection_id_length
    DestinationConnectionIdLength = 8,     // capture's; also RFC 9000 s7.2's floor
    PaddingTarget = 1200,
    PacketNumberEncodedLength = 4,
    InitialFrameOrder = [TlsQuicFrameType.Crypto, TlsQuicFrameType.Padding],
    CoalesceAscendingByLevel = true,
    AckLeadsInPacket = true,
    AckRangeLimit = 32,
    InitialRttRange = (TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(300)),
    LocalFlowControl = new TlsQuicLocalFlowControlSpec
    {
        InitialMaxData = 15_728_640,
        InitialMaxStreamDataBidiLocal = 6_291_456,
        InitialMaxStreamDataBidiRemote = 6_291_456,
        InitialMaxStreamDataUni = 6_291_456,
        InitialMaxStreamsBidi = 100,
        InitialMaxStreamsUni = 103,
    },
    TransportParameters = parameters,
    Recovery = new TlsQuicRecoverySpec
    {
        InitialCongestionWindow = (DatagramMultiplier: 10, ByteCap: 14_720),
        MinimumCongestionWindowDatagrams = 2,
        LossReductionFactor = 0.5,
        PacketThreshold = 3,
        TimeThreshold = 9.0 / 8.0,
        PersistentCongestionThreshold = 3,
        PtoBackoff = (Factor: 2.0, Maximum: null),
        ProbePacketsPerPto = 2,
        ProbeContents = TlsQuicProbeContents.Ping,
        // AckPolicy, PacingBurstDatagrams and CongestionController are accepted here
        // and read by NOTHING under src/ — see "Knobs nothing currently reads".
    },
};

// The QUIC ClientHello. NOT a browser TlsProfile: RFC 9001 s8.4 forbids extensions a
// TCP profile carries.
var factory = new TlsQuicClientHelloProfileFactory
{
    ConnectionSpec = spec,                 // the SAME object the connection gets
    AlpnProtocols = ["h3"],
    Tls = builder => builder
        .WithTls13()
        .WithCipherSuites(
            TlsCipherSuite.TlsAes128GcmSha256,
            TlsCipherSuite.TlsAes256GcmSha384,
            TlsCipherSuite.TlsChaCha20Poly1305Sha256)
        .WithSupportedGroups(NamedGroup.X25519MlKem768, NamedGroup.X25519, NamedGroup.Secp256r1)
        .WithKeyShares(NamedGroup.X25519MlKem768, NamedGroup.X25519)
        .WithGrease(ClientHelloGreasePolicy.Consistent),
        // Do NOT call .WithAlpn or .WithQuicTransportParameters here: the factory
        // overwrites both after this delegate runs.
};

// One profile per connection. Every call redraws the three drawn parameters.
var clientHello = factory.Create(sourceConnectionId: default);
```

---

## Layer 3 — HTTP/3

`src/SharpTls/Quic/TlsQuicHttp3Spec.cs:126`. **`internal sealed`.** Defaults split in two, and the
split is the point (`:116-122`): where a client capture bounds a default it is taken and the
capture line is cited; where the capture *cannot* see the choice the default is a **declared
placeholder** naming the task that would settle it.

The file carries its own wiring table (`:99-110`), produced by grep rather than by intent — task C9
wired the last four, which C1–C4 had left recording a value and changing no byte.

### `TlsQuicHttp3Spec`

| Knob | Type | Default | Wire effect | Fingerprinted | Reach |
| --- | --- | --- | --- | --- | --- |
| `Settings` `:247` | `ImmutableArray<TlsQuicHttp3Setting>` | **`CaptureSettings`** (`:142-149`, `:201`): `1:65536, 6:262144, 7:100, 51:1, 126585778853:2585972839` | The SETTINGS frame's parameters **in the order they go on the wire**. **Order is not sorted** — RFC 9114 §7.2.4 fixes no order and the encoder is forbidden to sort (`:211-216`) | **Yes**. Capture line 47's fingerprint string: `1:65536;6:262144;7:100;51:1;GREASE` | in-assembly |
| `AllowDatagramSettingWithoutTransportParameter` `:329` | `bool` | **`false`** | Permits sending `SETTINGS_H3_DATAGRAM = 1` on a connection whose ClientHello advertised no non-zero `max_datagram_frame_size` (0x20). **No RFC forbids the combination** — but quic-go's `http3/conn.go` closes with `H3_SETTINGS_ERROR` "missing QUIC Datagram support". C17 measured it live at `fp.impersonate.pro`: 0/3 without 0x20, 3/3 with it (`:301-323`) | Indirectly | in-assembly |
| `UnidirectionalStreamOpenOrder` `:352` | `ImmutableArray<TlsQuicHttp3StreamType>` | **`[Control, QpackEncoder, QpackDecoder]`** (`:180-185`, `:202-203`) | The order this client opens its unidirectional streams. §6.2 fixes the three as a **group** and leaves the order **within** the group free | **`PLACEHOLDER`** — the capture records no stream-open order at all; task C12's not-yet-known column (`:334-342`) | in-assembly |
| `PseudoHeaderOrder` `:414` | `ImmutableArray<TlsQuicHttp3PseudoHeader>` | **`[Method, Authority, Scheme, Path]`** (`:189-195`, `:204-205`) | The order request pseudo-header field lines are emitted in | **Yes** — capture line 70, rendered `m,a,s,p`. **Settled by the capture**, unlike the SETTINGS order, because the four names have no natural sort producing that sequence (`:398-401`) | in-assembly |
| `QpackHuffmanStringLiterals` `:457` | `bool` | **`true`** | Whether the QPACK encoder Huffman-codes the string literals it emits. One flag for the whole connection; RFC 9204 §4.1.2's per-string H-bit freedom is deliberately **not** modelled | **`PLACEHOLDER`** — the fingerprint string carries no QPACK bytes (`:443-449`) | in-assembly |
| `QpackNameMatchPolicy` `:473` | `TlsQuicQpackNameMatchPolicy` | **`NameReference`** (`:206-207`) | When a header's *name* matches a static entry but its *value* does not: `NameReference` = RFC 9204 §4.5.4, `LiteralName` = §4.5.6. Different bytes for the same header | **`PLACEHOLDER`** — unseen by the capture (`:462-464`) | in-assembly |
| `SendReservedFramesOnRequestStreams` `:506` | `bool` | **`false`** | Prefixes the HEADERS frame with one RFC 9114 §7.2.8 reserved (GREASE) frame. bogdanfinn exposes the same dimension as `h3SendGreaseFrames` | **`PLACEHOLDER`** — §7.2.8's frames "MAY be sent on any stream", so both answers conform (`:492-497`) | in-assembly |

**The flag is the only knob for the reserved frame.** Its N, its payload and its position before
the HEADERS frame are all placeholders declared on
`TlsQuicHttp3Request.ReservedRequestStreamFrameType`
(`src/SharpTls/Quic/TlsQuicHttp3Request.cs:446-463`): *"DECLARED PLACEHOLDER, all three of it: the
N, the payload, and the position … N = 0, an empty payload and a position before the HEADERS frame
are this project's placeholder; task C12 carries all three in the not-yet-known column."*

**The reserved (GREASE) SETTING is an ordinary element of `Settings`** — there is no separate
"emit a GREASE setting" flag and no separate "where" index, because a list already says both and a
flag plus an index would be a second, weaker way to say the same thing that could disagree with the
list (`:217-222`). Identify one by recomputation, `TlsQuicHttp3Frames.IsReservedIdentifier`.

**`Settings` guards** (`:252-292`), all reachable because subsystem B populates the spec from
outside: a default-valued array is rejected; identifier or value above 2^62−1 is rejected;
an HTTP/2-reserved identifier (RFC 9114 §11.2.2) is rejected; a duplicate identifier is rejected
(§7.2.4); and `SETTINGS_H3_DATAGRAM` (0x33 = 51) with a value other than 0 or 1 is rejected —
**stricter than RFC 9297 §2.1.1's letter, which binds the receiver** (`:269-273`).

**`UnidirectionalStreamOpenOrder` guards** (`:357-391`): undefined stream type rejected; duplicate
rejected; `Push` rejected (§6.2.2, "Only servers can push"); `Control` absent rejected (§6.2.1).

**The `51:1` decision is a decision, not a copied value** (`:223-237`). RFC 9297 §2.1.1's
RECOMMENDED is *conditioned* on supporting receipt, and this stack has no HTTP/3 datagram receive
path — `TlsQuicFrameType` has no RFC 9221 DATAGRAM member at all. So the default of 1 rests on the
capture (line 67) and on nothing else.

### Example — HTTP/3 layer

```csharp
using System.Collections.Immutable;
using SharpTls.Quic;

var http3 = new TlsQuicHttp3Spec
{
    // ORDER IS A FINGERPRINT DIMENSION. Never sorted.
    Settings =
    [
        new(TlsQuicHttp3Spec.QpackMaxTableCapacityIdentifier, 65536),  // 0x01
        new(TlsQuicHttp3Spec.MaxFieldSectionSizeIdentifier,   262144), // 0x06
        new(TlsQuicHttp3Spec.QpackBlockedStreamsIdentifier,   100),    // 0x07
        new(TlsQuicHttp3Spec.H3DatagramIdentifier,            1),      // 0x33 == 51
        new(126585778853, 2585972839),                                 // reserved (GREASE)
    ],

    // Capture line 70 — "m,a,s,p". Settled by the capture.
    PseudoHeaderOrder =
    [
        TlsQuicHttp3PseudoHeader.Method,
        TlsQuicHttp3PseudoHeader.Authority,
        TlsQuicHttp3PseudoHeader.Scheme,
        TlsQuicHttp3PseudoHeader.Path,
    ],

    // PLACEHOLDER — the capture records no stream-open order.
    UnidirectionalStreamOpenOrder =
    [
        TlsQuicHttp3StreamType.Control,
        TlsQuicHttp3StreamType.QpackEncoder,
        TlsQuicHttp3StreamType.QpackDecoder,
    ],

    QpackHuffmanStringLiterals = true,                             // PLACEHOLDER
    QpackNameMatchPolicy = TlsQuicQpackNameMatchPolicy.NameReference, // PLACEHOLDER
    SendReservedFramesOnRequestStreams = false,                    // PLACEHOLDER

    // Only if you deliberately want 51:1 without max_datagram_frame_size (0x20).
    // Measured to fail 0/3 against quic-go peers.
    AllowDatagramSettingWithoutTransportParameter = false,
};

var connection = new TlsQuicHttp3Connection(quicConnection, http3);
```

---

## Every `UNVERIFIED` value

`grep -rn "UNVERIFIED" --include=*.cs src/SharpTls` — **20 hits, of which 16 mark a value**; the
other four are `TlsQuicRecoveryReadout.cs` talking *about* the marker word rather than using it.
Each ships as a declared placeholder naming the task that would settle it.

**This table said 13 for three commits after the tree said 16**, which is why
`TlsQuicRecoveryReadout.cs:784-802` ties its third column to the **marker in the source** and
not to a row in this document, and says so in as many words. Rows 14–16 are the three
that task A3-11 added without moving the count.

| # | Value | Where | Ships as | Task that settles it |
| --- | --- | --- | --- | --- |
| 1 | `WithGreaseSignatureAlgorithms` **index placement** | `ClientHello/ClientHelloBuilder.cs:235` | `0` (BoringSSL prepends) | A capture of a non-BoringSSL client that greases `signature_algorithms` |
| 2 | **Which congestion controller Chromium runs** | `Quic/TlsQuicCongestionControl.cs:315` | NewReno | A3-14 |
| 3 | `KInitialWindowDatagrams` / `KInitialWindowByteCap` **against Chromium** | `Quic/TlsQuicCongestionControl.cs:524` | 10 / 14720 | A3-14 |
| 4 | **The exact Initial CRYPTO split point** (`CryptoStreamBytesPerInitialDatagram`) | `Quic/TlsQuicDatagramBuilder.cs:427` | **1400** — a headroom calculation from `1472 − 43 = 1429`, rounded down | B12 |
| 5 | **`initial_rtt`'s range** — *the parameter itself is sent* | `Quic/TlsQuicFingerprintReadout.cs:1297` | 100 ms … 300 ms | B12 |
| 6 | `KInitialWindowDatagrams` (the const) | `Quic/TlsQuicRecoverySpec.cs:423` | **10** | A3-14 |
| 7 | `DefaultPacingBurstDatagrams` (the const) | `Quic/TlsQuicRecoverySpec.cs:527` | **10** — *that Chromium paces at all is a widely repeated claim this project has not measured* | A3-14 |
| 8 | `InitialCongestionWindow` (the property), **both halves** | `Quic/TlsQuicRecoverySpec.cs:559` | **(10, 14720)** | A3-14 |
| 9 | `CongestionController` | `Quic/TlsQuicRecoverySpec.cs:615` | **`null`** = NewReno. *The A3 plan records that it very probably is not what Chromium runs* | A3-14 |
| 10 | `AckPolicy` | `Quic/TlsQuicRecoverySpec.cs:792` | **`Immediate`** — *the behaviour this client already has, not a measurement* | A3-14 |
| 11 | `PacingBurstDatagrams`, **both halves at once** | `Quic/TlsQuicRecoverySpec.cs:817` | **10** | A3-14 |
| 12 | `ReservedIdentifierNExample` | `Quic/TlsQuicTransportParameterSpec.cs:310` | **120829032258064516** — kept only as *evidence*; the preset draws a fresh N per connection | B12 |
| 13 | `DeclaredInitialRttRange` — *"the only genuinely invented bound in this file"* | `Quic/TlsQuicTransportParameterSpec.cs:399` | **100 ms … 300 ms**. The **width is arbitrary**; the one property the capture establishes is that the range must contain 192859 µs | B12 (uQUIC's `ChromeRandomInitialRTT()`) |
| 14 | `DefaultPacingIntervalScale` (the const) | `Quic/TlsQuicRecoverySpec.cs:571` | **1.25** | A3-14 |
| 15 | `PacingIntervalScale` (the property) | `Quic/TlsQuicRecoverySpec.cs:1004` | **1.25** | A3-14 |
| 16 | **Whether a real client delays its ACKs at all** | `Quic/TlsQuicApplicationSendPath.cs:123` | the send path never consults the pacer on an ACK-only pass, per §7.7's "packets containing only ACK frames SHOULD therefore not be paced" | A3-14 |

### And the `PLACEHOLDER`s that are not marked `UNVERIFIED`

`grep -rn "PLACEHOLDER\|declared placeholder" --include=*.cs src/SharpTls` — the same category, a
different marker word:

| Value | Where | Ships as | Task |
| --- | --- | --- | --- |
| `TlsQuicConnectionSpec.PacketNumberEncodedLength` | `Quic/TlsQuicConnectionSpec.cs:268-273` | **4** — RFC 9001 A.2's non-minimal choice, *"NOT evidence about Chromium"* | task 11 |
| `TlsQuicConnectionSpec.AckRangeLimit` | `Quic/TlsQuicConnectionSpec.cs:616` | **32** | task 9a-ii / task 11 |
| `TlsQuicLocalFlowControlSpec.ReceiveWindowUpdateDivisor` | `Quic/TlsQuicConnectionSpec.cs:999` | **2**, and it is a `const` — **not a knob** | a capture of a large response body, which this repo does not have |
| `TlsQuicHttp3Spec.UnidirectionalStreamOpenOrder` | `Quic/TlsQuicHttp3Spec.cs:334` | `[Control, QpackEncoder, QpackDecoder]` | C12 |
| `TlsQuicHttp3Spec.QpackHuffmanStringLiterals` | `Quic/TlsQuicHttp3Spec.cs:443` | `true` | C12 |
| `TlsQuicHttp3Spec.QpackNameMatchPolicy` | `Quic/TlsQuicHttp3Spec.cs:462` | `NameReference` | C12 |
| `TlsQuicHttp3Spec.SendReservedFramesOnRequestStreams` | `Quic/TlsQuicHttp3Spec.cs:492` | `false` | C12 |
| Reserved request-stream frame's **N, payload and position** | `Quic/TlsQuicHttp3Request.cs:446` | `N = 0`, empty payload, before HEADERS. **Not knobs** — only the on/off flag is | C12 |

The HTTP/3 readout renders seven rows with verdict `not-yet-known-from-the-capture`
(`Quic/TlsQuicHttp3FingerprintReadout.cs:680, 732, 738, 749, 764, 772, 781`): settings wire order,
unidirectional stream open order, QPACK Huffman flag policy, QPACK name-match policy, and the
reserved request-stream frame's N / payload / position. The QUIC readout's third column has
**exactly two** members (`Quic/TlsQuicFingerprintReadout.cs:870-895`): `initial_rtt`'s draw range
and the reserved parameter's N.

---

## Knobs nothing currently reads

This has happened repeatedly here, so it gets its own section. A knob that accepts a value and
ignores it is worse than an absent one (`TlsQuicConnectionSpec.cs:50-53`, quoting the task-4b
amendment).

**Method.** `grep -rnE "\.<Property>\b" --include=*.cs src/` with comment lines stripped —
**not** pinned to one spelling of the receiver, which is the mistake that made the previous
self-check on `TransportParameters` vacuous (see below).

> **Line anchors into `Quic/TlsQuicRecoverySpec.cs` shifted by about seventy lines when task
> A3-11 added knob 15 and its preset.** The `:NNN` references in this file were already drifting
> before that; they are names with a hint, not addresses, and the member names are what to grep.

| Knob | Type | Nothing under `src/` reads it | What it would take |
| --- | --- | --- | --- |
| `TlsQuicRecoverySpec.CongestionController` | `Func<ITlsQuicCongestionController>?` | **WIRED by task A3-8.** `TlsQuicLossDetection`'s `Congestion` property invokes the factory once per connection and falls back to NewReno when it is null | done - and A3-11 added the send gate that makes the window it reports restrict sending |
| `TlsQuicRecoverySpec.AckPolicy` `:799` | `TlsQuicAckPolicy` | **WIRED by task A3-13.** `TlsQuicAckTracker.IsWithheldAt` reads it, and `TlsQuicConnection`'s fourth `TlsQuicDeadlineKind` — `DelayedAck` — is what releases a held ACK | done — and it closed a §13.2.1 MUST this client had been knowingly violating |
| `TlsQuicRecoverySpec.PacingBurstDatagrams` | `int?` | **WIRED by task A3-11.** `TlsQuicPacer` is the pacer, and `TlsQuicApplicationSendPath`'s `SendGateAdmits` consults it before the 1-RTT frame queue is drained | done - and `PacingIntervalScale` (knob 15) arrived with it |

The doc comments on `TlsQuicConnectionSpec.AckRangeLimit`, `HeaderLengthVarintWidth`,
`CryptoOffsetVarintWidth`, `CryptoLengthVarintWidth`, `Recovery` and on
`TlsQuicTransportParameterSpec` itself **still claim** to be unwired. **All six are now wired** —
see the next section. Those are stale comments, not unwired knobs.

`TlsQuicRecoverySpec.DrawInitialRtt` — the brief's example of a knob with no caller — **now has
one**: `TlsQuicConnection.cs:1080`, `TlsQuicRecoverySpec.DrawInitialRtt(options.Spec)`, wired by
task A3-7.

**A live divergence in the shipped defaults**, recorded on `DrawInitialRtt` itself
(`TlsQuicRecoverySpec.cs:858-870`): `TlsQuicConnectionSpec.InitialRttRange` defaults to `null`,
while the transport-parameter preset advertises `initial_rtt` drawn from `DeclaredInitialRttRange`
(100–300 ms). So an unconfigured client **advertises** a number between 100 and 300 ms and
**starts from** 333 ms. Both are legal; they are two answers to one question. Setting
`InitialRttRange` makes them agree.

---

## Not configurable, and should be

The gap list. Three categories, and they need different fixes:

- **missing knob** — a value a real client could vary, baked in as a literal or a `const`.
- **unwired knob** — the property exists and is ignored (see the section above).
- **unreachable knob** — the knob exists and works, but no consumer-facing surface reaches it.
- **constraint** — a genuine protocol or implementation limitation, not a fingerprint choice.

### From the `TlsClient` consumer

`TlsClient` is the only assembly outside SharpTls that can see any of this. Read at the state of
`0573270`; another agent is actively editing `Http3Connection.cs`, so the first two rows are
**in-flight**, not permanent.

| Row | Where | Wire effect | Category | What it would take |
| --- | --- | --- | --- | --- |
| `PaddingTarget` hard-coded | `TlsClient-main/src/TlsClient/Http3Connection.cs:171` — `new TlsQuicConnectionSpec { PaddingTarget = InitialDatagramPaddingTarget }`, constant `= 1200` at `:31` | Every Initial datagram is padded to exactly 1200 | **unreachable knob** — *in flight* | A property on `TlsSessionOptions` carrying a `TlsQuicConnectionSpec`, or at minimum the padding target |
| `new TlsQuicHttp3Spec()` built bare | `TlsClient-main/src/TlsClient/Http3Connection.cs:242` | Every SETTINGS list, pseudo-header order, QPACK policy and stream-open order is the SharpTls default. **A TlsClient caller cannot change one byte of the HTTP/3 fingerprint** | **unreachable knob** — *in flight* | The same: a spec-shaped option |
| **The whole QUIC TLS half** | `TlsClient-main/src/TlsClient/Http3Connection.cs:172-188` — the factory is constructed with hard-coded TLS 1.3, suites `TlsAes128GcmSha256`/`TlsAes256GcmSha384`, groups `X25519`/`Secp256r1`, key share `X25519` | The QUIC ClientHello is one fixed fingerprint for every TlsClient user | **unreachable knob** | A **QUIC-shaped profile type**. `options.Profile` cannot be reused: it is TCP-shaped and RFC 9001 §8.4 forbids extensions it carries (`:177-180`). The comment there says so outright: *"Making a persona drive this needs a QUIC-shaped profile that does not exist yet."* |
| `TlsQuicRecoverySpec` and `TlsQuicTransportParameterSpec` never constructed | zero occurrences under `TlsClient-main/src` | Every transport parameter and every recovery knob is the SharpTls default | **unreachable knob** | Same fix as the first two rows |
| `ConfigureTls`, `ClientCertificates`, `HandshakeObserver`, `ConnectObserver`, `Proxy`, `EchDnsResolver`, `ProfileRoller`, `HappyEyeballsDelay`, `Retry`, `AutomaticDecompression`, most of `Http2` | `TlsClient-main/src/TlsClient/TlsSessionOptions.cs` | None — they do not reach the h3 path at all | **unreachable knob** (h3 only) | Per-option wiring; several are meaningless over QUIC and should be documented as TCP-only rather than wired |
| `MaximumConcurrentRequests` capped at 1 | `TlsClient-main/src/TlsClient/Http3Connection.cs:123` — `Math.Min(1, RemainingRequestStreams)` | One in-flight request per h3 connection | **constraint**, not a knob | Enforced by the single-threaded `PumpOnceAsync` design and the `SemaphoreSlim(1,1)` send gate at `:52`. Raising it is a concurrency rework, not a config change. |

### From SharpTls itself

| Row | Where | Wire/behaviour effect | Category | What it would take |
| --- | --- | --- | --- | --- |
| `TlsQuicLocalFlowControlSpec.ReceiveWindowUpdateDivisor = 2` | `Quic/TlsQuicConnectionSpec.cs:1007` — a `const` | When MAX_DATA / MAX_STREAM_DATA go out, i.e. the spacing of window updates a peer sees | **missing knob**, declared placeholder | Turn the `const` into an `init` property with a positive-value guard. Different stacks top up at different fractions. |
| **`MAX_STREAM_DATA` is parsed and dropped; send credit is static** | `Quic/TlsQuicPeerFlowControlBudget.cs:27`, `:172`, `:389-410` — *"A4-minimal sends no MAX_STREAM_DATA and handles no `*_BLOCKED` frame"*, and the budget *"NEVER GROWS"* | Our send credit is whatever the peer's initial parameters granted and can never be raised. No knob can change that | **constraint** (today), and a real limitation on large uploads | Implement the receive side of MAX_DATA/MAX_STREAM_DATA and the `*_BLOCKED` frames. Not a knob — a missing feature. |
| Reserved request-stream frame's **N, payload, position** | `Quic/TlsQuicHttp3Request.cs:446-463` — `N = 0`, empty payload, immediately before HEADERS | The exact bytes of the GREASE frame, when `SendReservedFramesOnRequestStreams` is on | **missing knob**, declared placeholder | Three properties on `TlsQuicHttp3Spec`. §7.2.8 leaves all three free. The file explicitly says *"THE FLAG IS THE ONLY KNOB"*. |
| Initial-datagram expansion route | `Quic/TlsQuicConnectionSpec.cs:316-321` | §14.1 names two legal routes to the 1200-byte floor — PADDING frames and coalescing. Only PADDING is implemented; Chromium uses PADDING | **constraint** → **missing knob** once coalescing exists | Implement the coalescing route, then add the knob. Today a knob would have exactly one legal value. |
| The `initial_rtt` divergence | `Quic/TlsQuicRecoverySpec.cs:858-870` | An unconfigured client advertises 100–300 ms and starts from 333 ms — two answers to one question | **missing default**, not a missing knob | Task A3-7 decides whether the default should agree by construction, with A3-14's capture in hand. The knob exists: set `InitialRttRange`. |
| `kGranularity` (1 ms) | `Quic/TlsQuicRecoverySpec.cs:477-480` | Floors the time threshold §6.1.2 computes | **constraint** | A platform timer-resolution floor. A knob for it would express what clock the machine has. |
| `ack_delay_exponent` | `Quic/TlsQuicConnectionOptions.cs:193` | Encoded ACK Delay field | **already a knob**, but on `TlsQuicConnectionOptions`, not the spec — deliberately, so there is one source of truth for one advertised value (`TlsQuicConnectionSpec.cs:612-615`) | nothing |
| Frame **type** varint width | `Quic/TlsQuicConnectionSpec.cs:12-14` | RFC 9000 §16 excludes the Frame Type field from the non-minimal-encoding liberty | **constraint** | Nothing. The RFC forbids it. |
| `ClientHelloExtensionKind.Cookie` | `ClientHello/ClientHelloExtensionKind.cs` — *"A server-provided HelloRetryRequest cookie; not configurable in the initial ClientHello"* | Its **position** in the extension order is settable via `WithExtensionOrder`/`WithExtensionLayout`; its **body** is the server's | **constraint** | Nothing. RFC 8446 §4.2.2 makes the body the server's. |
| A QUIC client offering **no ALPN** | `ClientHello/TlsQuicClientHelloProfileFactory.cs:143-151` | `BuildConfiguration` rejects extension 57 with no ALPN, so `Create` throws | **constraint** (stated, deliberately not swallowed) | Relaxing `ClientHelloBuilder.BuildConfiguration`. The factory refuses to hide the refusal, because *"hiding it would turn a stated limit into a silently different ClientHello."* |
| The whole QUIC/HTTP-3 surface is `internal` | `src/SharpTls/Properties/AssemblyInfo.cs:12-17` | No arbitrary consumer can set any of Layer 2 or Layer 3 | **unreachable knob**, by explicit decision | Design and freeze the public h3 surface, then delete the `InternalsVisibleTo("TlsClient")` line rather than sitting it alongside. |

---

## Stale self-checks found while writing this

Each of these doc comments asserts that a knob is unwired. **All six are now false.** They are
recorded here rather than fixed, because this document is read-only with respect to `src/`.

| Claim | Where | Reality |
| --- | --- | --- |
| "NOT YET READ BY ANYTHING UNDER `src/`, AND SAYING SO IS THE POINT" — `AckRangeLimit` | `Quic/TlsQuicConnectionSpec.cs:625` | Read at `Quic/TlsQuicConnection.cs:1079` — `options.Spec.AckRangeLimit` |
| "NOTHING IN `src/` READS THIS PROPERTY" — `HeaderLengthVarintWidth` | `Quic/TlsQuicConnectionSpec.cs:480` | Read at `Quic/TlsQuicConnection.cs:4459` — `LengthVarintWidth = _options.Spec.HeaderLengthVarintWidth` |
| "THE WRITER HAS BEEN OPEN SINCE A4 TASK 5; THIS PROPERTY IS NOT YET CONNECTED TO IT" — `CryptoOffsetVarintWidth` | `Quic/TlsQuicConnectionSpec.cs:503` | Read at `Quic/TlsQuicConnection.cs:4460` |
| "THE SAME STATE AS `CryptoOffsetVarintWidth`" — `CryptoLengthVarintWidth` | `Quic/TlsQuicConnectionSpec.cs:532` | Read at `Quic/TlsQuicConnection.cs:4461` |
| "NOTHING READS IT YET … tasks A3-3 through A3-11 wire these one at a time" — `Recovery` | `Quic/TlsQuicConnectionSpec.cs:766` | Read at `Quic/TlsQuicConnection.cs:3034`, `:3150`, `:3284`; `Quic/TlsQuicLossDetection.cs:382`, `:425`; `Quic/TlsQuicCongestionControl.cs:437`, `:541`, `:547`. Nine of the twelve are wired; three are not (see above) |
| "NOTHING READS THIS YET" — `TlsQuicTransportParameterSpec` (the type) | `Quic/TlsQuicTransportParameterSpec.cs:277` | Read at `ClientHello/TlsQuicClientHelloProfileFactory.cs:205` — `_connectionSpec.TransportParameters.Compose(...)`, wired by task B8 |

`TlsQuicConnectionSpec.TransportParameters`' own remark (`:738-744`) already documents *why* this
keeps happening, and it is the lesson worth carrying:

> The prior text here was a self-checking comment whose check decayed first. It said "NOTHING READS
> IT YET" and offered `grep -rn "spec\.TransportParameters" src/` as the proof. That grep is
> case-sensitive and never matched the actual call site, `_connectionSpec.TransportParameters` — so
> it returned nothing both before and after B8, and went on reading as confirmation while the claim
> it guarded turned false. **A grep pinned to one spelling of a receiver is not a check.**

The greps in this document are written case-insensitively on the receiver, or with no receiver at
all, for exactly that reason.
