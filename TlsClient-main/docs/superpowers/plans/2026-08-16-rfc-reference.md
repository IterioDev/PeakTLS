# RFC reference for per-request HTTP/2 wire fidelity

Research artifact for `2026-08-16-http2-request-lifecycle.md`, binding spec
`docs/superpowers/specs/2026-08-14-http2-wire-fidelity-design.md`.

Every claim below is followed by its citation. Quotations are from the authoritative
plain-text RFCs:

- RFC 9113 (HTTP/2, June 2022, obsoletes 7540/8740) — <https://www.rfc-editor.org/rfc/rfc9113.txt>
- RFC 8441 (Bootstrapping WebSockets with HTTP/2, September 2018) — <https://www.rfc-editor.org/rfc/rfc8441.txt>
- RFC 9218 (Extensible Prioritization Scheme for HTTP, June 2022) — <https://www.rfc-editor.org/rfc/rfc9218.txt>
- RFC 7540 (obsoleted, cited only where 9113 deliberately dropped a rule)

Labels used:
- **CONVENTION** — observed/common practice, not required by any RFC.
- **UNVERIFIED** — could not be confirmed from a spec or from read source.
- **AXIS** — the spec permits several behaviours; our options model must be able to express each.

---

## 1. Padding — RFC 9113 §6.1 (DATA) and §6.2 (HEADERS)

### 1.1 Wire layout

DATA frame layout, in order (RFC 9113 §6.1, Figure 3):

```
Length (24), Type (8) = 0x00,
Unused Flags (4), PADDED Flag (1), Unused Flags (2), END_STREAM Flag (1),
Reserved (1), Stream Identifier (31),
[Pad Length (8)],
Data (..),
Padding (..2040),
```

HEADERS frame layout, in order (RFC 9113 §6.2, Figure 4):

```
Length (24), Type (8) = 0x01,
Unused Flags (2), PRIORITY Flag (1), Unused Flag (1), PADDED Flag (1),
END_HEADERS Flag (1), Unused Flag (1), END_STREAM Flag (1),
Reserved (1), Stream Identifier (31),
[Pad Length (8)],
[Exclusive (1)], [Stream Dependency (31)], [Weight (8)],
Field Block Fragment (..),
Padding (..2040),
```

Ordering is load-bearing for a byte-exact writer: on HEADERS the **Pad Length octet precedes
the priority payload**, which precedes the field block fragment, which precedes the padding.
(RFC 9113 §6.2, Figure 4.)

### 1.2 Pad Length semantics and the PADDED flag

> "Pad Length: An 8-bit field containing the length of the frame padding in units of octets.
> This field is conditional and is only present if the PADDED flag is set." (RFC 9113 §6.1)

> "PADDED (0x08): When set, the PADDED flag indicates that the Pad Length field and any
> padding that it describes are present." (RFC 9113 §6.1 and §6.2 — identical wording in both)

Consequence: PADDED implies the Pad Length octet is present. It does **not** imply padding is
non-empty. RFC 9113 §6.1 and §6.2 both carry the note:

> "Note: A frame can be increased in size by one octet by including a Pad Length field with a
> value of zero."

**AXIS.** `PADDED` set with `Pad Length = 0` (one extra octet, no padding) and `PADDED` unset
(no extra octet) are distinct on the wire and are distinct emulation states. An options model
using a nullable `int?` where `null` = flag clear and `0` = flag set with zero padding covers
both; an `int` defaulting to `0` cannot.

Padding content:

> "Padding octets that contain no application semantic value. Padding octets MUST be set to
> zero when sending. A receiver is not obligated to verify padding but MAY treat non-zero
> padding as a connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.1, §6.2)

Maximum padding is 2040 octets per the frame diagrams (`Padding (..2040)`), but the Pad Length
field is 8 bits, so the maximum expressible is **255** octets. (RFC 9113 §6.1/§6.2 field
definitions; the 2040 in the diagram is the notational upper bound of the variable-length
field, not a reachable value given an 8-bit length.)

### 1.3 May pad length exceed the remaining payload, and what error

No.

> "The total number of padding octets is determined by the value of the Pad Length field. If
> the length of the padding is the length of the frame payload or greater, the recipient MUST
> treat this as a connection error (Section 5.4.1) of type PROTOCOL_ERROR."
> (RFC 9113 §6.1 for DATA; verbatim-identical sentence in §6.2 for HEADERS)

Note the comparison is against the **frame payload length**, which itself includes the Pad
Length octet. Therefore a correctly-computing sender can never violate this: payload =
1 + [5 if PRIORITY] + fragment + padding, so padding < payload always holds. The rule only
catches malformed senders. A pad length in `[0, 255]` is therefore always legal from our side.

Note also that for DATA the error is a **connection** error, even though most DATA framing
errors are stream errors — padding is the exception.

### 1.4 Padding and the frame-size budget / CONTINUATION split

The frame-size limit applies to the whole payload, padding included:

> "The size of a frame payload is limited by the maximum size that a receiver advertises in the
> SETTINGS_MAX_FRAME_SIZE setting. This setting can have any value between 2^14 (16,384) and
> 2^24-1 (16,777,215) octets, inclusive." (RFC 9113 §4.2)

> "An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds the size defined
> in SETTINGS_MAX_FRAME_SIZE, exceeds any limit defined for the frame type, or is too small to
> contain mandatory frame data. A frame size error in a frame that could alter the state of the
> entire connection MUST be treated as a connection error (Section 5.4.1); this includes any
> frame carrying a field block (Section 4.3) (that is, HEADERS, PUSH_PROMISE, and CONTINUATION),
> a SETTINGS frame, and any frame with a stream identifier of 0." (RFC 9113 §4.2)

**Therefore, for a padded HEADERS frame the usable field-block fragment size is:**

```
maxFragment = SETTINGS_MAX_FRAME_SIZE
            - (padded ? 1 : 0)        // Pad Length octet
            - (priority ? 5 : 0)      // Exclusive+StreamDep+Weight
            - padLength               // the padding itself
```

Oversizing a HEADERS frame is a **connection error** of type FRAME_SIZE_ERROR (§4.2, quoted
above), not a stream error, because HEADERS carries a field block.

CONTINUATION frames cannot be padded at all — the CONTINUATION frame has no PADDED flag and no
Pad Length field:

```
CONTINUATION Frame { Length (24), Type (8) = 0x09,
  Unused Flags (5), END_HEADERS Flag (1), Unused Flags (2),
  Reserved (1), Stream Identifier (31), Field Block Fragment (..) }
```
(RFC 9113 §6.10, Figure 12.) So padding a split header block affects the **first** frame's
budget only; every CONTINUATION frame can use the full `SETTINGS_MAX_FRAME_SIZE`.

Likewise for DATA: the padding counts against the frame size *and* against flow control:

> "DATA frames are subject to flow control and can only be sent when a stream is in the 'open'
> or 'half-closed (remote)' state. **The entire DATA frame payload is included in flow control,
> including the Pad Length and Padding fields if present.**" (RFC 9113 §6.1, emphasis added)

> "For flow-control calculations, the 9-octet frame header is not counted." (RFC 9113 §6.9.1)

So a padded DATA frame must reserve `1 + dataLen + padLen` from *both* the stream and connection
send windows, not `dataLen`. Under-reserving produces a peer FLOW_CONTROL_ERROR (§6.9.1, see §7
below).

---

## 2. Frames forbidden between HEADERS and CONTINUATION — RFC 9113 §6.2, §6.10, §4.3

### 2.1 The rule

Three independent statements of the same requirement:

> "Each field block is processed as a discrete unit. **Field blocks MUST be transmitted as a
> contiguous sequence of frames, with no interleaved frames of any other type or from any other
> stream.** The last frame in a sequence of HEADERS or CONTINUATION frames has the END_HEADERS
> flag set. […] This allows a field block to be logically equivalent to a single frame."
> (RFC 9113 §4.3)

> "A HEADERS frame without the END_HEADERS flag set MUST be followed by a CONTINUATION frame
> for the same stream. A receiver MUST treat the receipt of any other type of frame or a frame
> on a different stream as a connection error (Section 5.4.1) of type PROTOCOL_ERROR."
> (RFC 9113 §6.2, END_HEADERS flag definition)

> "If the END_HEADERS flag is not set, this frame MUST be followed by another CONTINUATION
> frame. A receiver MUST treat the receipt of any other type of frame or a frame on a different
> stream as a connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.10)

> "A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE or CONTINUATION frame
> without the END_HEADERS flag set. A recipient that observes violation of this rule MUST
> respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR." (RFC 9113 §6.10)

The prohibition is absolute — *any* frame type, *any* stream, including stream 0. So SETTINGS,
PING, WINDOW_UPDATE and PRIORITY_UPDATE are all forbidden in that gap. RFC 9113 §6.3 restates
it for PRIORITY specifically: "A PRIORITY frame cannot be sent between consecutive frames that
comprise a single field block (Section 4.3)."

END_STREAM does not end the sequence:

> "A HEADERS frame with the END_STREAM flag set signals the end of a stream. However, a HEADERS
> frame with the END_STREAM flag set can be followed by CONTINUATION frames on the same stream.
> Logically, the CONTINUATION frames are part of the HEADERS frame." (RFC 9113 §6.2)

### 2.2 What a client may interleave elsewhere

Outside a field block, HTTP/2 imposes no ordering constraint between streams — that is the
point of the protocol (RFC 9113 §2, §5). Concretely, a client may freely interleave, at any
point that is not inside a field block:

- DATA on other streams (subject to flow control and stream state, §6.1)
- HEADERS opening other streams (§6.2)
- PRIORITY, on a stream in **any** state including "idle" and "closed" (§6.3)
- RST_STREAM (§6.4), SETTINGS (§6.5), PING (§6.7), GOAWAY (§6.8), WINDOW_UPDATE (§6.9)
- PRIORITY_UPDATE (RFC 9218 §7.1), which is always on stream 0
- Unknown/extension frame types. RFC 9113 §5.5: "Implementations MUST ignore unknown or
  unsupported values in all extensible protocol elements. **Implementations MUST discard frames
  that have unknown or unsupported types.** This means that any of these extension points can be
  safely used by extensions without prior arrangement or negotiation. **However, extension frames
  that appear in the middle of a field block (Section 4.3) are not permitted; these MUST be
  treated as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.**"

**AXIS.** "Frames before HEADERS" and "frames after the complete header block" are legal and
distinguishable placements. "Frames between HEADERS and its CONTINUATIONs" is **not** an axis —
it is a connection error. A per-request frame script must serialize the entire header block
(HEADERS + all CONTINUATION) as one atomic unit under the connection write lock.

---

## 3. PING — RFC 9113 §6.7

```
PING Frame { Length (24) = 0x08, Type (8) = 0x06,
  Unused Flags (7), ACK Flag (1),
  Reserved (1), Stream Identifier (31) = 0,
  Opaque Data (64) }
```
(RFC 9113 §6.7, Figure 9.)

- **Payload length: exactly 8 octets.** "In addition to the frame header, PING frames MUST
  contain 8 octets of opaque data in the frame payload. A sender can include any value it
  chooses and use those octets in any fashion." (RFC 9113 §6.7)
- **Stream identifier: MUST be 0x00.** "PING frames are not associated with any individual
  stream. If a PING frame is received with a Stream Identifier field value other than 0x00, the
  recipient MUST respond with a connection error (Section 5.4.1) of type **PROTOCOL_ERROR**."
  (RFC 9113 §6.7)
- **Wrong length error.** "Receipt of a PING frame with a length field value other than 8 MUST
  be treated as a connection error (Section 5.4.1) of type **FRAME_SIZE_ERROR**."
  (RFC 9113 §6.7)

So the two failure modes carry *different* error codes: bad stream id → PROTOCOL_ERROR, bad
length → FRAME_SIZE_ERROR. Both are connection errors.

- ACK: "When set, the ACK flag indicates that this PING frame is a PING response. An endpoint
  MUST set this flag in PING responses. An endpoint MUST NOT respond to PING frames containing
  this flag." (RFC 9113 §6.7)
- Responding: "Receivers of a PING frame that does not include an ACK flag MUST send a PING
  frame with the ACK flag set in response, with an identical frame payload. PING responses
  SHOULD be given higher priority than any other frame." (RFC 9113 §6.7)

**AXIS.** The 8 opaque octets are free-form and are a real fingerprint (some clients send all
zeros, some send a counter, some send random). The *content* is an emulation axis; the length
and stream id are not.

---

## 4. `:authority` vs `Host` — RFC 9113 §8.3.1

This is the governing text for an `AuthorityMode` option. All quotes RFC 9113 §8.3.1.

> "The ':authority' pseudo-header field conveys the authority portion (Section 3.2 of
> [RFC3986]) of the target URI (Section 7.1 of [HTTP]). **The recipient of an HTTP/2 request
> MUST NOT use the Host header field to determine the target URI if ':authority' is present.**"

> "**Clients that generate HTTP/2 requests directly MUST use the ':authority' pseudo-header
> field to convey authority information, unless there is no authority information to convey (in
> which case it MUST NOT generate ':authority').**"

> "**Clients MUST NOT generate a request with a Host header field that differs from the
> ':authority' pseudo-header field.** A server SHOULD treat a request as malformed if it
> contains a Host header field that identifies an entity that differs from the entity in the
> ':authority' pseudo-header field. The values of fields need to be normalized to compare them
> (see Section 6.2 of [RFC3986]). An origin server can apply any normalization method, whereas
> other servers MUST perform scheme-based normalization (see Section 6.2.3 of [RFC3986]) of the
> two fields."

> "An intermediary that forwards a request over HTTP/2 MUST construct an ':authority'
> pseudo-header field using the authority information from the control data of the original
> request, unless the original request's target URI does not contain authority information (in
> which case it MUST NOT generate ':authority'). Note that the Host header field is not the sole
> source of this information; see Section 7.2 of [HTTP]."

> "An intermediary that needs to generate a Host header field (which might be necessary to
> construct an HTTP/1.1 request) MUST use the value from the ':authority' pseudo-header field as
> the value of the Host field, unless the intermediary also changes the request target. This
> replaces any existing Host field to avoid potential vulnerabilities in HTTP routing."

> "**An intermediary that forwards a request over HTTP/2 MAY retain any Host header field.**"

> "Note that request targets for CONNECT or asterisk-form OPTIONS requests never include
> authority information; see Sections 7.1 and 7.2 of [HTTP]."

> "':authority' MUST NOT include the deprecated userinfo subcomponent for 'http' or 'https'
> schemed URIs."

### Mapping onto `AuthorityMode`

| Mode | Conformance | Citation |
|---|---|---|
| `AuthorityOnly` (`:authority`, no `Host`) | **Conformant and required** for a client generating requests directly. | §8.3.1 "Clients that generate HTTP/2 requests directly MUST use the ':authority' pseudo-header field" |
| `Both` (`:authority` + `Host`) | **Conformant only if the two values are equal** (after normalization). A conformant *client* may not emit differing values; a conformant *intermediary* may retain a Host it received. | §8.3.1 "Clients MUST NOT generate a request with a Host header field that differs from the ':authority' pseudo-header field"; "An intermediary that forwards a request over HTTP/2 MAY retain any Host header field." |
| `HostHeaderOnly` (`Host`, no `:authority`) | **NOT conformant for a client** generating requests directly, unless there is genuinely no authority information to convey. Servers are additionally free to ignore Host in HTTP/2 when `:authority` is absent — behaviour is server-dependent. | §8.3.1 "MUST use the ':authority' pseudo-header field to convey authority information, unless there is no authority information to convey" |

Server-side behaviour, summarised from the same section:
- `:authority` present → server MUST NOT consult `Host` for the target URI.
- `:authority` present and `Host` present and different → server SHOULD treat as malformed
  (§8.3.1). "Malformed requests or responses that are detected MUST be treated as a stream error
  (Section 5.4.2) of type PROTOCOL_ERROR" (§8.1.1).
- `:authority` absent, `Host` present → RFC 9113 does not define a server fallback in §8.3.1.
  Real servers commonly fall back to `Host` — **CONVENTION**, not specified.

**AXIS / warning.** `HostHeaderOnly` is a deliberate MUST-violation retained because real
stacks and proxies do it. Keep it, but the model must record that it is non-conformant, and
`Both` must be constrained so the emitted `Host` equals `:authority` unless the caller
explicitly opts into divergence.

---

## 5. CONNECT — RFC 9113 §8.5 — and extended CONNECT — RFC 8441 §4

### 5.1 Plain CONNECT (RFC 9113 §8.5)

> "In HTTP/2, the CONNECT method establishes a tunnel over a single HTTP/2 stream to a remote
> host, rather than converting the entire connection to a tunnel. A CONNECT header section is
> constructed as defined in Section 8.3.1 ('Request Pseudo-Header Fields'), with a few
> differences. Specifically:
> - The ':method' pseudo-header field is set to CONNECT.
> - **The ':scheme' and ':path' pseudo-header fields MUST be omitted.**
> - The ':authority' pseudo-header field contains the host and port to connect to (equivalent to
>   the authority-form of the request-target of CONNECT requests; see Section 3.2.3 of
>   [HTTP/1.1]).
>
> A CONNECT request that does not conform to these restrictions is malformed (Section 8.1.1)."
> (RFC 9113 §8.5)

So a legal plain-CONNECT header block carries exactly `:method` and `:authority` (plus regular
fields). Malformed → stream error PROTOCOL_ERROR (§8.1.1).

Also, though we are not implementing the tunnel: "Frame types other than DATA or stream
management frames (RST_STREAM, WINDOW_UPDATE, and PRIORITY) MUST NOT be sent on a connected
stream and MUST be treated as a stream error (Section 5.4.2) if received." (RFC 9113 §8.5)

### 5.2 Extended CONNECT (RFC 8441 §4)

RFC 8441 is written against RFC 7540 section numbering; RFC 7540 §8.3 is RFC 9113 §8.5, and
RFC 7540 §8.1.2.3 is RFC 9113 §8.3.1.

> "This extension modifies the method in the following ways:
> - **A new pseudo-header field :protocol MAY be included on request HEADERS** indicating the
>   desired protocol to be spoken on the tunnel created by CONNECT. The pseudo-header field is
>   single valued and contains a value from the 'Hypertext Transfer Protocol (HTTP) Upgrade Token
>   Registry' […]
> - **On requests that contain the :protocol pseudo-header field, the :scheme and :path
>   pseudo-header fields of the target URI (see Section 5) MUST also be included.**
> - On requests bearing the :protocol pseudo-header field, the :authority pseudo-header field is
>   interpreted according to Section 8.1.2.3 of [RFC7540] instead of Section 8.3 of that
>   document. In particular, the server MUST NOT create a tunnel to the host indicated by the
>   :authority as it would with a CONNECT method request that was not modified by this
>   extension." (RFC 8441 §4)

So with `:protocol` present, the required set is `:method` (= CONNECT), `:protocol`, `:scheme`,
`:path`. `:authority` is required by the general RFC 9113 §8.3.1 client rule ("Clients that
generate HTTP/2 requests directly MUST use the ':authority' pseudo-header field"), and RFC 8441
§5 states it directly for the WebSocket case: "The Host information is conveyed as part of the
:authority pseudo-header field, which is required on every HTTP/2 transaction." Five
pseudo-headers total.

### 5.3 Negotiation gate

> "The new parameter name is SETTINGS_ENABLE_CONNECT_PROTOCOL. The value of the parameter MUST
> be 0 or 1. Upon receipt of SETTINGS_ENABLE_CONNECT_PROTOCOL with a value of 1, a client MAY
> use the Extended CONNECT as defined in this document when creating new streams. Receipt of
> this parameter by a server does not have any impact. A sender MUST NOT send a
> SETTINGS_ENABLE_CONNECT_PROTOCOL parameter with the value of 0 after previously sending a
> value of 1." (RFC 8441 §3)

> "If a client were to use the provisions of the extended CONNECT method defined in this
> document without first receiving a SETTINGS_ENABLE_CONNECT_PROTOCOL parameter, a
> non-supporting peer would detect a malformed request and generate a stream error […]"
> (RFC 8441 §3)

The setting is **server→client**. A client emitting `:protocol` before seeing it risks a stream
error but the RFC only says "MAY use" once received — it does not phrase the client side as a
MUST NOT. Emitting `:protocol` unconditionally is therefore not a spec violation per se, but it
is unsafe; gating on the received setting is the correct behaviour. `SETTINGS_ENABLE_CONNECT_PROTOCOL`
is IANA setting identifier **0x8**, initial value **0** (RFC 8441 §9.1, verbatim: "Code: 0x8 /
Name: SETTINGS_ENABLE_CONNECT_PROTOCOL / Initial Value: 0"). The Upgrade token registered for
WebSocket is the literal string `websocket` (RFC 8441 §9.2).

### 5.4 WebSocket-specific field rules (RFC 8441 §5) — relevant to header-block emission only

- "The :protocol pseudo-header field MUST be included in the CONNECT request, and it MUST have
  a value of 'websocket' to initiate a WebSocket connection on an HTTP/2 stream."
- "The scheme of the target URI […] MUST be 'https' for 'wss'-schemed WebSockets and 'http' for
  'ws'-schemed WebSockets."
- "[RFC6455] requires the use of Connection and Upgrade header fields that are not part of
  HTTP/2. **They MUST NOT be included in the CONNECT request defined here.**"
- "Implementations using this extended CONNECT to bootstrap WebSockets do not do the processing
  of the Sec-WebSocket-Key and Sec-WebSocket-Accept header fields of [RFC6455] as that
  functionality has been superseded by the :protocol pseudo-header field."
- "The Origin [RFC6454], Sec-WebSocket-Version, Sec-WebSocket-Protocol, and
  Sec-WebSocket-Extensions header fields are used in the CONNECT request and response-header
  fields as defined in [RFC6455]. Note that HTTP/1 header field names were case insensitive,
  whereas HTTP/2 requires they be encoded as lowercase."

(All RFC 8441 §5.) The §5.1 example header block, in the order the RFC prints it:
`:method`, `:protocol`, `:scheme`, `:path`, `:authority`, then `sec-websocket-protocol`,
`sec-websocket-extensions`, `sec-websocket-version`, `origin`. **CONVENTION** — the RFC's
example ordering carries no normative weight; only "all pseudo-header fields MUST appear […]
before all regular field lines" is normative (RFC 9113 §8.3).

---

## 6. Mandatory request pseudo-headers — RFC 9113 §8.3, §8.3.1

General rules (RFC 9113 §8.3):

> "Pseudo-header fields are not HTTP header fields. Endpoints MUST NOT generate pseudo-header
> fields other than those defined in this document. Note that an extension could negotiate the
> use of additional pseudo-header fields; see Section 5.5."

> "**All pseudo-header fields MUST appear in a field block before all regular field lines.** Any
> request or response that contains a pseudo-header field that appears in a field block after a
> regular field line MUST be treated as malformed (Section 8.1.1)."

> "**The same pseudo-header field name MUST NOT appear more than once in a field block.** A
> field block for an HTTP request or response that contains a repeated pseudo-header field name
> MUST be treated as malformed (Section 8.1.1)."

> "Pseudo-header fields MUST NOT appear in a trailer section." (RFC 9113 §8.3)

Mandatory set (RFC 9113 §8.3.1):

> "**All HTTP/2 requests MUST include exactly one valid value for the ':method', ':scheme', and
> ':path' pseudo-header fields, unless they are CONNECT requests (Section 8.5).** An HTTP request
> that omits mandatory pseudo-header fields is malformed (Section 8.1.1)."

Note `:authority` is **not** in that mandatory list; its requirement comes from the separate
client rule quoted in §4 above ("Clients that generate HTTP/2 requests directly MUST use the
':authority' pseudo-header field […] unless there is no authority information to convey").

`:path` and asterisk-form OPTIONS — **yes, `*` is legal and in fact required**:

> "The ':path' pseudo-header field includes the path and query parts of the target URI […] **A
> request in asterisk form (for OPTIONS) includes the value '*' for the ':path' pseudo-header
> field.**
>
> This pseudo-header field MUST NOT be empty for 'http' or 'https' URIs; 'http' or 'https' URIs
> that do not contain a path component MUST include a value of '/'. The exceptions to this rule
> are:
> - **an OPTIONS request for an 'http' or 'https' URI that does not include a path component;
>   these MUST include a ':path' pseudo-header field with a value of '*'** (see Section 7.1 of
>   [HTTP]).
> - CONNECT requests (Section 8.5), where the ':path' pseudo-header field is omitted."
> (RFC 9113 §8.3.1)

`:scheme` is not restricted to http/https:

> "':scheme' is not restricted to 'http' and 'https' schemed URIs. A proxy or gateway can
> translate requests for non-HTTP schemes, enabling the use of HTTP to interact with non-HTTP
> services." (RFC 9113 §8.3.1)

**AXIS.** `:scheme` must be settable, not hardcoded to `https`. `:path` must be passable
verbatim so `*` is expressible. Pseudo-header *order* is entirely unconstrained by the RFC
(only "before all regular field lines" is normative), so any permutation is legal — it is a
pure fingerprint axis.

### Per-method legality matrix (derived from §8.3.1 + §8.5 + RFC 8441 §4)

| Method | Required | Forbidden | Optional |
|---|---|---|---|
| Normal (GET/POST/…) | `:method`, `:scheme`, `:path` | — | `:authority` (but client MUST send it when authority info exists) |
| `OPTIONS` asterisk-form | `:method`, `:scheme`, `:path` = `*` | — | `:authority` (target has no authority info per §8.3.1 note) |
| `CONNECT` (plain) | `:method`, `:authority` | `:scheme`, `:path` | — |
| `CONNECT` + `:protocol` (RFC 8441) | `:method`, `:protocol`, `:scheme`, `:path`, `:authority` | — | — |

---

## 7. WINDOW_UPDATE and flow control — RFC 9113 §6.9, §6.9.1, §6.9.2

```
WINDOW_UPDATE Frame { Length (24) = 0x04, Type (8) = 0x08,
  Unused Flags (8), Reserved (1), Stream Identifier (31),
  Reserved (1), Window Size Increment (31) }
```
(RFC 9113 §6.9, Figure 11.)

- **Legal increment range: 1 to 2^31−1.** "The frame payload of a WINDOW_UPDATE frame is one
  reserved bit plus an unsigned 31-bit integer indicating the number of octets that the sender
  can transmit in addition to the existing flow-control window. **The legal range for the
  increment to the flow-control window is 1 to 2^31-1 (2,147,483,647) octets.**" (§6.9)
- **Zero increment is an error, and its class depends on the target.** "A receiver MUST treat
  the receipt of a WINDOW_UPDATE frame with a flow-control window increment of 0 as a **stream
  error (Section 5.4.2) of type PROTOCOL_ERROR**; **errors on the connection flow-control window
  MUST be treated as a connection error (Section 5.4.1)**." (§6.9)
- **Wrong length.** "A WINDOW_UPDATE frame with a length other than 4 octets MUST be treated as
  a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR." (§6.9)
- **Stream 0 means the connection window.** "The WINDOW_UPDATE frame can be specific to a stream
  or to the entire connection. In the former case, the frame's stream identifier indicates the
  affected stream; in the latter, the value '0' indicates that the entire connection is the
  subject of the frame." (§6.9)
- **Flow control applies to DATA only.** "Flow control only applies to frames that are identified
  as being subject to flow control. Of the frame types defined in this document, this includes
  only DATA frames." (§6.9)
- **Window maximum: 2^31−1.** "A sender MUST NOT allow a flow-control window to exceed 2^31-1
  octets. If a sender receives a WINDOW_UPDATE that causes a flow-control window to exceed this
  maximum, it MUST terminate either the stream or the connection, as appropriate. **For streams,
  the sender sends a RST_STREAM with an error code of FLOW_CONTROL_ERROR; for the connection, a
  GOAWAY frame with an error code of FLOW_CONTROL_ERROR is sent.**" (§6.9.1)
- **Exceeding the window when sending.** "The sender MUST NOT send a flow-controlled frame with
  a length that exceeds the space available in either of the flow-control windows advertised by
  the receiver. Frames with zero length with the END_STREAM flag set (that is, an empty DATA
  frame) MAY be sent if there is no available space in either flow-control window." (§6.9.1)
- **Header octets are free.** "For flow-control calculations, the 9-octet frame header is not
  counted." (§6.9.1)
- **Initial windows: 65,535 both levels.** "When an HTTP/2 connection is first established, new
  streams are created with an initial flow-control window size of 65,535 octets. The connection
  flow-control window is also 65,535 octets. Both endpoints can adjust the initial window size
  for new streams by including a value for SETTINGS_INITIAL_WINDOW_SIZE in the SETTINGS frame.
  **The connection flow-control window can only be changed using WINDOW_UPDATE frames.**"
  (§6.9.2)
- **SETTINGS_INITIAL_WINDOW_SIZE retroactively adjusts open streams and can drive a window
  negative.** "When the value of SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver MUST adjust the
  size of all stream flow-control windows that it maintains by the difference between the new
  value and the old value. […] A sender MUST track the negative flow-control window and MUST NOT
  send new flow-controlled frames until it receives WINDOW_UPDATE frames that cause the
  flow-control window to become positive." (§6.9.2)
- "An endpoint MUST treat a change to SETTINGS_INITIAL_WINDOW_SIZE that causes any flow-control
  window to exceed the maximum size as a connection error (Section 5.4.1) of type
  FLOW_CONTROL_ERROR." (§6.9.2)

### WINDOW_UPDATE on a half-closed or closed stream — explicitly legal

> "**WINDOW_UPDATE can be sent by a peer that has sent a frame with the END_STREAM flag set.
> This means that a receiver could receive a WINDOW_UPDATE frame on a stream in a 'half-closed
> (remote)' or 'closed' state. A receiver MUST NOT treat this as an error (see Section 5.1).**"
> (RFC 9113 §6.9)

This directly authorises an option that keeps sending the stream-level WINDOW_UPDATE after
END_STREAM (i.e. `SuppressStreamUpdateOnEndStream = false`).

**AXIS.** All of the following are spec-legal and produce distinguishable traces: increment
size, threshold before emitting, connection-vs-stream ordering, coalescing into one write, and
emitting-or-suppressing the final stream update after END_STREAM. The only hard bounds are:
increment ∈ [1, 2^31−1], resulting window ≤ 2^31−1, length exactly 4.

---

## 8. Error codes — RFC 9113 §7 — and their conventional client use — §5.4

### 8.1 The full table (RFC 9113 §7, verbatim definitions)

| Code | Name | RFC 9113 §7 definition |
|---|---|---|
| 0x00 | `NO_ERROR` | "The associated condition is not a result of an error. For example, a GOAWAY might include this code to indicate graceful shutdown of a connection." |
| 0x01 | `PROTOCOL_ERROR` | "The endpoint detected an unspecific protocol error. This error is for use when a more specific error code is not available." |
| 0x02 | `INTERNAL_ERROR` | "The endpoint encountered an unexpected internal error." |
| 0x03 | `FLOW_CONTROL_ERROR` | "The endpoint detected that its peer violated the flow-control protocol." |
| 0x04 | `SETTINGS_TIMEOUT` | "The endpoint sent a SETTINGS frame but did not receive a response in a timely manner." |
| 0x05 | `STREAM_CLOSED` | "The endpoint received a frame after a stream was half-closed." |
| 0x06 | `FRAME_SIZE_ERROR` | "The endpoint received a frame with an invalid size." |
| 0x07 | `REFUSED_STREAM` | "The endpoint refused the stream prior to performing any application processing (see Section 8.7 for details)." |
| 0x08 | `CANCEL` | "The endpoint uses this error code to indicate that the stream is no longer needed." |
| 0x09 | `COMPRESSION_ERROR` | "The endpoint is unable to maintain the field section compression context for the connection." |
| 0x0a | `CONNECT_ERROR` | "The connection established in response to a CONNECT request (Section 8.5) was reset or abnormally closed." |
| 0x0b | `ENHANCE_YOUR_CALM` | "The endpoint detected that its peer is exhibiting a behavior that might be generating excessive load." |
| 0x0c | `INADEQUATE_SECURITY` | "The underlying transport has properties that do not meet minimum security requirements (see Section 9.2)." |
| 0x0d | `HTTP_1_1_REQUIRED` | "The endpoint requires that HTTP/1.1 be used instead of HTTP/2." |

> "Error codes are 32-bit fields that are used in RST_STREAM and GOAWAY frames to convey the
> reasons for the stream or connection error. Error codes share a common code space. Some error
> codes apply only to either streams or the entire connection and have no defined semantics in
> the other context." (RFC 9113 §7)

> "**Unknown or unsupported error codes MUST NOT trigger any special behavior. These MAY be
> treated by an implementation as being equivalent to INTERNAL_ERROR.**" (RFC 9113 §7)

So emitting an out-of-table error code is safe on the wire — a peer must not react specially.
This makes `Http2ErrorCode` safe to model as an open `uint`-backed enum.

### 8.2 Which code to use — mostly convention

The RFC deliberately declines to bind a code to a cause:

> "If an endpoint detects multiple different errors, it MAY choose to report any one of those
> errors. If a frame causes a connection error, that error MUST be reported. **Additionally, an
> endpoint MAY use any applicable error code when it detects an error condition; a generic error
> code (such as PROTOCOL_ERROR or INTERNAL_ERROR) can always be used in place of more specific
> error codes.**" (RFC 9113 §5.4)

Therefore:

- **Cancel a stream the client no longer needs → `CANCEL` (0x08).** This is the closest thing
  to a specified use: §7 defines CANCEL as "the endpoint uses this error code to indicate that
  the stream is no longer needed". Choosing it is nevertheless permitted-not-required (§5.4).
  **CONVENTION** for the *choice*; the *meaning* is specified.
- **Report a local failure (e.g. a body reader threw) → `INTERNAL_ERROR` (0x02).**
  §7: "The endpoint encountered an unexpected internal error." §5.4 explicitly blesses
  INTERNAL_ERROR as an always-available generic. **CONVENTION** for the choice.
- **Reject a server push → RST_STREAM on the promised stream.** RFC 9113 §6.6 / §8.4 describe
  rejecting a promised stream via RST_STREAM but **do not mandate an error code**. Both `CANCEL`
  and `REFUSED_STREAM` are used in the wild. **CONVENTION.**
- **`REFUSED_STREAM` (0x07)** carries a specific retry guarantee: §8.7 uses it as the marker
  that the request definitely was not processed and is therefore safe to retry.

### 8.3 Stream error mechanics (RFC 9113 §5.4.2)

> "An endpoint that detects a stream error sends a RST_STREAM frame (Section 6.4) that contains
> the stream identifier of the stream where the error occurred."

> "**A RST_STREAM is the last frame that an endpoint can send on a stream.** The peer that sends
> the RST_STREAM frame MUST be prepared to receive any frames that were sent or enqueued for
> sending by the remote peer."

> "Normally, an endpoint SHOULD NOT send more than one RST_STREAM frame for any stream. However,
> an endpoint MAY send additional RST_STREAM frames if it receives frames on a closed stream
> after more than a round-trip time."

> "**To avoid looping, an endpoint MUST NOT send a RST_STREAM in response to a RST_STREAM
> frame.**"

---

## 9. GOAWAY — RFC 9113 §6.8

```
GOAWAY Frame { Length (24), Type (8) = 0x07,
  Unused Flags (8), Reserved (1), Stream Identifier (31) = 0,
  Reserved (1), Last-Stream-ID (31), Error Code (32), Additional Debug Data (..) }
```
(RFC 9113 §6.8, Figure 10.)

- **Stream identifier MUST be 0.** "The GOAWAY frame applies to the connection, not a specific
  stream. An endpoint MUST treat a GOAWAY frame with a stream identifier other than 0x00 as a
  connection error (Section 5.4.1) of type PROTOCOL_ERROR." (§6.8)

### Last-Stream-ID semantics — it refers to *peer-initiated* streams

> "To deal with this case, **the GOAWAY contains the stream identifier of the last
> peer-initiated stream that was or might be processed on the sending endpoint in this
> connection.** For instance, if the server sends a GOAWAY frame, the identified stream is the
> highest-numbered stream initiated by the client." (§6.8)

> "The last stream identifier in the GOAWAY frame contains the highest-numbered stream
> identifier for which the sender of the GOAWAY frame might have taken some action on or might
> yet take action on. All streams up to and including the identified stream might have been
> processed in some way. **The last stream identifier can be set to 0 if no streams were
> processed.**" (§6.8)

> "Note: In this context, 'processed' means that some data from the stream was passed to some
> higher layer of software that might have taken some action as a result." (§6.8)

**Consequence for a client's GOAWAY.** Client-initiated streams are odd; server-initiated
(pushed) streams are even (RFC 9113 §5.1.1). Since Last-Stream-ID names the last *peer*-initiated
stream, a **client's** GOAWAY must name the highest-numbered **even** (pushed) stream it
processed — which is **0** on any connection where the client accepted no server push. Putting
the client's own last odd stream id in a client GOAWAY is semantically wrong per §6.8.

### What a client's GOAWAY means

- "Once the GOAWAY is sent, the sender will ignore frames sent on streams initiated by the
  receiver if the stream has an identifier higher than the included last stream identifier.
  **Receivers of a GOAWAY frame MUST NOT open additional streams on the connection**, although a
  new connection can be established for new streams." (§6.8) — from a client, this tells the
  server not to push further.
- "Endpoints SHOULD always send a GOAWAY frame before closing a connection so that the remote
  peer can know whether a stream has been partially processed or not." (§6.8)
- "A GOAWAY frame might not immediately precede closing of the connection; **a receiver of a
  GOAWAY that has no more use for the connection SHOULD still send a GOAWAY frame before
  terminating the connection.**" (§6.8)
- "An endpoint might choose to close a connection without sending a GOAWAY for misbehaving
  peers." (§6.8)
- "An endpoint MAY send multiple GOAWAY frames if circumstances change. […] **Endpoints MUST NOT
  increase the value they send in the last stream identifier**, since the peers might already
  have retried unprocessed requests on another connection." (§6.8)
- On a connection error specifically: "An endpoint that encounters a connection error SHOULD
  first send a GOAWAY frame (Section 6.8) with the stream identifier of the last stream that it
  successfully received from its peer. […] **After sending the GOAWAY frame for an error
  condition, the endpoint MUST close the TCP connection.**" (§5.4.1)

**AXIS.** Sending a GOAWAY on clean shutdown vs. closing the socket silently are both permitted
(SHOULD, not MUST, in §6.8; §5.4.1's MUST-close only applies after an *error* GOAWAY), and real
clients differ. `SendGoAwayOnDispose` is a legitimate emulation axis.

### Debug data — essentially unconstrained

> "**Endpoints MAY append opaque data to the frame payload of any GOAWAY frame. Additional debug
> data is intended for diagnostic purposes only and carries no semantic value.** Debug information
> could contain security- or privacy-sensitive data. Logged or otherwise persistently stored
> debug data MUST have adequate safeguards to prevent unauthorized access." (§6.8)

No length limit beyond the generic frame-size rule (§4.2: payload ≤ SETTINGS_MAX_FRAME_SIZE, so
debug data ≤ `SETTINGS_MAX_FRAME_SIZE − 8`, since Last-Stream-ID and Error Code occupy 8 octets).
No content restriction. Arbitrary bytes are legal.

---

## 10. RFC 9218 — priority field value grammar and PRIORITY_UPDATE

### 10.1 Grammar

> "For both the Priority header field and the PRIORITY_UPDATE frame, the set of priority
> parameters is **encoded as a Dictionary (see Section 3.2 of [STRUCTURED-FIELDS])**."
> (RFC 9218 §4)

> "This document defines the urgency (u) and incremental (i) priority parameters. When receiving
> an HTTP request that does not carry these priority parameters, a server SHOULD act as if their
> default values were specified." (RFC 9218 §4)

> "Receivers parse the Dictionary as described in Section 4.2 of [STRUCTURED-FIELDS]. Where the
> Dictionary is successfully parsed, this document places the additional requirement that
> **unknown priority parameters, priority parameters with out-of-range values, or values of
> unexpected types MUST be ignored.**" (RFC 9218 §4)

**`u` — urgency:**

> "The urgency (u) parameter value is **Integer** (see Section 3.3.1 of [STRUCTURED-FIELDS]),
> **between 0 and 7 inclusive**, in descending order of priority. **The default is 3.**"
> (RFC 9218 §4.1)

> "The smaller the value, the higher the precedence." (§4.1)
> "A client that fetches a document that likely consists of multiple HTTP resources (e.g., HTML)
> SHOULD assign the default urgency level to the main resource." (§4.1)
> "The lowest urgency level (7) is reserved for background tasks such as delivery of software
> updates. This urgency level SHOULD NOT be used for fetching responses that have any impact on
> user interaction." (§4.1)

**`i` — incremental:**

> "The incremental (i) parameter value is **Boolean** (see Section 3.3.6 of [STRUCTURED-FIELDS]).
> It indicates if an HTTP response can be processed incrementally […] **The default value of the
> incremental parameter is false (0).**" (RFC 9218 §4.2)

Wire forms in the RFC's own examples: `priority = u=0` (§4.1) and `priority = u=5, i` (§4.2).
Note that a Structured-Fields Boolean true is written as a bare key (`i`), and false as `i=?0`.
Emitting `i=?1` is also valid Structured Fields. **AXIS** — `i`, `i=?1`, and omission-with-default
are three byte-distinct encodings of overlapping semantics; a fidelity model that stores the
literal field value string rather than parsed parameters preserves all of them.

### 10.2 PRIORITY_UPDATE frame (HTTP/2), RFC 9218 §7 and §7.1

```
HTTP/2 PRIORITY_UPDATE Frame { Length (24), Type (8) = 0x10,
  Unused Flags (8), Reserved (1), Stream Identifier (31),
  Reserved (1), Prioritized Stream ID (31), Priority Field Value (..) }
```
(RFC 9218 §7.1, Figure 1.)

- **Frame's own Stream Identifier MUST be 0.** "The Stream Identifier field […] in the
  PRIORITY_UPDATE frame header **MUST be zero (0x0)**. Receiving a PRIORITY_UPDATE frame with a
  field of any other value MUST be treated as a connection error of type PROTOCOL_ERROR."
  (§7.1)
- **Prioritized Stream ID MUST NOT be 0.** "If a PRIORITY_UPDATE frame is received with a
  prioritized stream ID of 0x0, the recipient MUST respond with a connection error of type
  PROTOCOL_ERROR." (§7.1)
- **Payload is the same text as the header field value.** "Priority Field Value: The priority
  update value in ASCII text, encoded using Structured Fields. This is the same representation as
  the Priority header field value." (§7.1)
- **A complete set, not a delta.** "A PRIORITY_UPDATE frame communicates a complete set of all
  priority parameters in the Priority Field Value field. Omitting a priority parameter is a
  signal to use its default value. Failure to parse the Priority Field Value MAY be treated as a
  connection error. In HTTP/2, the error is of type PROTOCOL_ERROR […]" (§7)
- **Clients only.** "**Servers MUST NOT send PRIORITY_UPDATE frames.** If a client receives a
  PRIORITY_UPDATE frame, it MUST respond with a connection error of type PROTOCOL_ERROR." (§7.1)

### 10.3 Placement relative to HEADERS — both sides are legal

> "PRIORITY_UPDATE frames are sent by clients on the control stream, allowing them to be sent
> independently of the stream that carries the response. This means they can be used to
> reprioritize a response or a push stream, **or to signal the initial priority of a response
> instead of the Priority header field.**" (RFC 9218 §7)

> "**A client MAY send a PRIORITY_UPDATE frame before the stream that it references is open**
> (except for HTTP/2 push streams; see Section 7.1). […] Servers SHOULD buffer the most recently
> received PRIORITY_UPDATE frame and apply it once the referenced stream is opened." (RFC 9218 §7)

> "When the PRIORITY_UPDATE frame applies to a request stream, clients SHOULD provide a
> prioritized stream ID that refers to a stream in the 'open', 'half-closed (local)', or **'idle'**
> state (i.e., streams where data might still be received)." (RFC 9218 §7.1)

**AXIS confirmed.** Emitting PRIORITY_UPDATE *before* HEADERS (referencing an idle stream) and
*after* HEADERS are both conformant. Chrome emits it before/around HEADERS; this is a real
discriminator. Note the concurrency constraint: "The number of streams that have been prioritized
but remain in the 'idle' state plus the number of active streams […] MUST NOT exceed the value of
the SETTINGS_MAX_CONCURRENT_STREAMS parameter. Servers that receive such a PRIORITY_UPDATE MUST
respond with a connection error of type PROTOCOL_ERROR." (§7.1)

### 10.4 Relationship to RFC 7540 / RFC 9113 priority signals

RFC 9113 deprecates the old scheme but keeps the wire fields:

> "This update to HTTP/2 deprecates the priority signaling defined in RFC 7540. […] The
> description of frame fields and some of the mandatory handling is retained to ensure that
> implementations of this document remain interoperable with implementations that use the
> priority signaling described in RFC 7540." (RFC 9113 §5.3.2)

> "Endpoints that receive priority signals in HEADERS or PRIORITY frames can benefit from
> applying that information." (RFC 9113 §5.3.2)

`SETTINGS_NO_RFC7540_PRIORITIES` (RFC 9218 §2.1):

> "The value of SETTINGS_NO_RFC7540_PRIORITIES MUST be 0 or 1. Any value other than 0 or 1 MUST
> be treated as a connection error […] of type PROTOCOL_ERROR. The initial value is 0."
> "If endpoints use SETTINGS_NO_RFC7540_PRIORITIES, they MUST send it in the first SETTINGS
> frame. Senders MUST NOT change the SETTINGS_NO_RFC7540_PRIORITIES value after the first
> SETTINGS frame."
> "A server that receives SETTINGS_NO_RFC7540_PRIORITIES with a value of 1 MUST ignore HTTP/2
> priority signals."

Client guidance (RFC 9218 §2.1.1), which explains why real clients send **both** the deprecated
HEADERS priority payload and PRIORITY_UPDATE:

> "Before receiving a SETTINGS frame from a server, a client does not know if the server is
> ignoring HTTP/2 priority signals. Therefore, **until the client receives the SETTINGS frame
> from the server, the client SHOULD send both the HTTP/2 priority signals and the signals of
> this prioritization scheme** (see Sections 5 and 7.1). Once the client receives the first
> SETTINGS frame that contains the SETTINGS_NO_RFC7540_PRIORITIES parameter with a value of 1, it
> SHOULD stop sending the HTTP/2 priority signals."

**AXIS.** Emitting the HEADERS PRIORITY payload and PRIORITY_UPDATE together, either alone, or
neither, are all conformant states — and the choice is expected to *change mid-connection* once
the peer's SETTINGS arrives. A per-request model must be able to express all four combinations.

### 10.5 PRIORITY frame (RFC 9113 §6.3) — for completeness

```
PRIORITY Frame { Length (24) = 0x05, Type (8) = 0x02, Unused Flags (8),
  Reserved (1), Stream Identifier (31),
  Exclusive (1), Stream Dependency (31), Weight (8) }
```

- "The PRIORITY frame always identifies a stream. If a PRIORITY frame is received with a stream
  identifier of 0x00, the recipient MUST respond with a connection error […] of type
  PROTOCOL_ERROR." (§6.3)
- "Sending or receiving a PRIORITY frame does not affect the state of any stream […] The PRIORITY
  frame can be sent on a stream in any state, including 'idle' or 'closed'." (§6.3)
- "A PRIORITY frame with a length other than 5 octets MUST be treated as a **stream error** […]
  of type FRAME_SIZE_ERROR." (§6.3)
- "A PRIORITY frame cannot be sent between consecutive frames that comprise a single field
  block." (§6.3)

**Citation correction for the implementation plan:** RFC 9113 contains **no** self-dependency
rule. The string "depend on itself" does not appear anywhere in RFC 9113. The rule "A stream
cannot depend on itself. An endpoint MUST treat this as a stream error (Section 5.4.2) of type
PROTOCOL_ERROR" is **RFC 7540 §5.3.1** and was dropped in RFC 9113 along with the rest of the
dependency-tree text. Keep the validation (peers implementing RFC 7540 still enforce it) but
cite RFC 7540 §5.3.1, not RFC 9113.

The HEADERS `Weight` field is an 8-bit integer on the wire; RFC 7540 §5.3.2 defined the
effective weight as `Weight + 1` (range 1–256). RFC 9113 §6.2 states only "Weight: An unsigned
8-bit integer." — **for byte-exact emulation, store and emit the raw 8-bit wire value, not the
+1-adjusted value.** (RFC 9113 §6.2; the +1 semantics is RFC 7540 §5.3.2.)

---

## 11. bogdanfinn/tls-client — what it does, and what it cannot express

All findings below are from source read at commit-time HEAD of `master` on
2026-08-16. HTTP/2 framing lives in the sibling repo `bogdanfinn/fhttp`, which `tls-client`
depends on; `tls-client` itself only supplies the profile.

Files read:
- `bogdanfinn/tls-client/profiles/profiles.go`
- `bogdanfinn/tls-client/profiles/internal_browser_profiles.go`
- `bogdanfinn/tls-client/cffi_src/types.go`
- `bogdanfinn/fhttp/http2/transport.go`
- `bogdanfinn/fhttp/http2/frame.go`
- `bogdanfinn/fhttp/http2/write.go`
- `bogdanfinn/fhttp/header.go`

### 11.1 The profile model — everything is connection-scoped

`profiles.ClientProfile` (`profiles/profiles.go:94-108`) holds exactly these HTTP/2 knobs:

```go
type ClientProfile struct {
    clientHelloId          tls.ClientHelloID
    headerPriority         *http2.PriorityParam
    settings               map[http2.SettingID]uint32
    settingsOrder          []http2.SettingID
    priorities             []http2.Priority
    pseudoHeaderOrder      []string
    connectionFlow         uint32
    streamID               uint32
    allowHTTP              bool
    // ... http3* fields
}
```

Every one of these is passed once into the `http2.Transport` (`fhttp/http2/transport.go:66`
`ConnectionFlow`, `:94` `HeaderPriority`, `:109` `Priorities`, `:110` `PseudoHeaderOrder`,
`:136` `SettingsOrder`) and is therefore **per-Transport, i.e. per-client**, not per-request.

### 11.2 Per-request frame ordering

`fhttp/http2/transport.go:1247` is the entire per-request frame emission entry point:

```go
werr := cc.writeHeaders(cs.ID, endStream, int(cc.maxFrameSize), hdrs)
```

`writeHeaders` (`transport.go:1417-1456`) writes HEADERS then CONTINUATION frames and flushes.
There is no hook before or after it. The only per-connection prologue is at
`transport.go:848-876`: SETTINGS (in `SettingsOrder`), then a connection WINDOW_UPDATE if
`cc.connFlow > 0`, then the profile's PRIORITY frames:

```go
for _, priority := range t.Priorities {
    cc.fr.WritePriority(priority.StreamID, priority.PriorityParam)
    cc.nextStreamID = priority.StreamID + 2
}
```
(`transport.go:873-876`.)

**Gap: PRIORITY frames are emitted exactly once, at connection setup, and never per request.**
A client that emits a PRIORITY frame alongside each new stream cannot be reproduced.

### 11.3 Pseudo-header order

`transport.go:1747-1795`, inside `encodeHeaders`:

```go
pHeaderOrder, ok := req.Header[http.PHeaderOrderKey]
if !ok {
    pHeaderOrder = cc.t.PseudoHeaderOrder
    ok = true
}
...
for _, p := range pHeaderOrder {
    switch p {
    case ":authority": f(":authority", host)
    case ":method":    f(":method", req.Method)
    case ":path":      if req.Method != "CONNECT" { f(":path", path) }
    case ":scheme":    if req.Method != "CONNECT" { f(":scheme", req.URL.Scheme) }
    // (zMrKrabz): Currently skips over unrecognized pheader fields,
    // should throw error or something but works for now.
    default: continue
    }
}
```

Findings:
- Pseudo-header order **is** overridable per request, via the magic header key
  `http.PHeaderOrderKey` = `"PHeader-Order:"` (`fhttp/header.go:38-41`) — but only in the Go API.
- The switch recognises **only four** pseudo-headers. `:protocol` hits `default: continue` and is
  **silently dropped** — the in-source comment concedes this. **RFC 8441 extended CONNECT is
  therefore unreachable.**
- `:authority` is emitted unconditionally whenever it appears in the order; there is no
  Host-header mode and no way to suppress `:authority`.
- Plain CONNECT is handled correctly (`:scheme`/`:path` suppressed).

### 11.4 Header priority on HEADERS

`transport.go:1417-1447`:

```go
func (cc *ClientConn) writeHeaders(streamID uint32, endStream bool, maxFrameSize int, hdrs []byte) error {
    first := true
    for len(hdrs) > 0 && cc.werr == nil {
        chunk := hdrs
        if len(chunk) > maxFrameSize { chunk = chunk[:maxFrameSize] }
        hdrs = hdrs[len(chunk):]
        endHeaders := len(hdrs) == 0
        if first {
            defaultHeaderPriorityParam := PriorityParam{
                Exclusive: true, Weight: 255, StreamDep: 0,
            }
            if cc.t.HeaderPriority != nil {
                defaultHeaderPriorityParam = *cc.t.HeaderPriority
            }
            cc.fr.WriteHeaders(HeadersFrameParam{
                StreamID: streamID, BlockFragment: chunk,
                EndStream: endStream, EndHeaders: endHeaders,
                Priority: defaultHeaderPriorityParam,
            })
            first = false
        } else {
            cc.fr.WriteContinuation(streamID, endHeaders, chunk)
        }
    }
    ...
}
```

Findings:
- `HeaderPriority` comes only from the Transport — **not overridable per request**.
- When the profile sets no `HeaderPriority`, fhttp **forces** `Exclusive=true, Weight=255,
  StreamDep=0` on every HEADERS frame. `Framer.WriteHeaders` sets `FlagHeadersPriority` whenever
  `!p.Priority.IsZero()` (`fhttp/http2/frame.go:1083-1085`), and that hardcoded default is
  non-zero. So **fhttp cannot emit a HEADERS frame without the PRIORITY flag** through this path.
  Clients that send a bare HEADERS (which is what RFC 9218 §2.1.1 encourages once
  `SETTINGS_NO_RFC7540_PRIORITIES=1` is seen, and what modern Chrome does) are not reproducible.
- Note the split loop: the fragment size is `maxFrameSize` with **no allowance for the 5-octet
  priority payload** it then prepends — see 11.7.

### 11.5 PRIORITY_UPDATE

**Not implemented at all.** Grepping `fhttp/http2/frame.go` for `0x10`, `PRIORITY_UPDATE`, or
`PriorityUpdate` returns nothing; the `Framer` write methods are exactly `WriteData`,
`WriteDataPadded`, `WriteSettings`, `WriteSettingsAck`, `WritePing`, `WriteGoAway`,
`WriteWindowUpdate`, `WriteHeaders`, `WritePriority`, `WriteRSTStream`, `WriteContinuation`,
`WritePushPromise`, `WriteRawFrame` (`frame.go:644,657,808,821,849,892,955,1069,1157,1195,1235,1334,1360`).
`fhttp/http2/write.go` likewise has no PRIORITY_UPDATE writer.

**Gap: RFC 9218 PRIORITY_UPDATE (frame type 0x10) cannot be emitted at all**, at any scope. This
is the single largest fidelity gap for modern-Chrome emulation, since Chrome sends
`SETTINGS_NO_RFC7540_PRIORITIES` and PRIORITY_UPDATE rather than HEADERS priority.
(`WriteRawFrame` at `frame.go:1360` exists but is not wired to any profile or request option.)

### 11.6 DATA frame sizing

`transport.go:1492-1514` and `1536-1615`:

```go
// It returns max(1, min(peer's advertised max frame size,
// Request.ContentLength+1, 512KB)).
func (cs *clientStream) frameScratchBufferLen(maxFrameSize int) int {
    const max = 512 << 10
    n := int64(maxFrameSize)
    if n > max { n = max }
    if cl := actualContentLength(cs.req); cl != -1 && cl+1 < n { n = cl + 1 }
    if n < 1 { return 1 }
    return int(n)
}
```

and in the send loop:

```go
allowed, err = cs.awaitFlowControl(len(remain))
...
data := remain[:allowed]
remain = remain[allowed:]
sentEnd = sawEOF && len(remain) == 0 && !hasTrailers
err = cc.fr.WriteData(cs.ID, sentEnd, data)
```

with `awaitFlowControl` clamping to `cc.maxFrameSize` (`transport.go:1683-1685`).

Findings:
- DATA frame size = `min(peerMaxFrameSize, availableWindow, bytesRemaining)` — i.e. **as large as
  the peer permits**. There is no self-cap knob at any scope.
- `WriteData` is called, never `WriteDataPadded` — **DATA padding is never emitted**, though
  `WriteDataPadded` exists (`frame.go:657`).
- END_STREAM placement is derived from the code path (`sentEnd = sawEOF && len(remain)==0 &&
  !hasTrailers`, `transport.go:1604`), never declarable. There is no "separate empty DATA frame
  with END_STREAM" mode for a buffered body.

### 11.7 HEADERS padding

`HeadersFrameParam.PadLength` exists (`frame.go:1052-1054`) and `WriteHeaders` honours it
(`frame.go:1074-1076, 1087-1089, 1102`), but the client transport never sets it
(`transport.go:1437-1443` constructs `HeadersFrameParam` with no `PadLength`). **HEADERS padding
is unreachable from the client path.**

Separately, the fragment-size computation at `transport.go:1421-1422` chunks at exactly
`maxFrameSize` and *then* `WriteHeaders` prepends a 5-octet priority payload, producing a HEADERS
frame of `maxFrameSize + 5` whenever a header block actually needs splitting. Per RFC 9113 §4.2
that is a FRAME_SIZE_ERROR **connection** error at the peer. In practice it is rarely hit because
header blocks under 16 KiB never split. **Do not replicate this arithmetic** — see §1.4 above for
the correct budget.

### 11.8 Summary — axes bogdanfinn/tls-client CANNOT express

| Axis | Scope available in tls-client | Gap |
|---|---|---|
| Pseudo-header order | Per-request (Go API, `PHeader-Order:`) / per-profile | Go API only; the CFFI `RequestInput` (`cffi_src/types.go:51-91`) exposes only `HeaderOrder` (`:70`) — `PseudoHeaderOrder` lives on `CustomTlsClient` (`:107`). **No per-request pseudo-header order over CFFI.** |
| `:protocol` / extended CONNECT | none | `default: continue` at `transport.go:1784-1785` silently drops it. Unreachable. |
| `Host` vs `:authority` mode | none | `:authority` always, `Host` never. No `AuthorityMode` equivalent. |
| `:path` = `*` (asterisk OPTIONS) | none observed | `path` is derived from `req.URL`; **UNVERIFIED** whether any call path yields `*`. |
| HEADERS priority (`PriorityParam`) | per-client only (`transport.go:94`, `types.go:98`) | Not per-request. And **cannot be omitted** — a non-zero hardcoded default forces the PRIORITY flag on every HEADERS (`transport.go:1427-1435`). |
| PRIORITY frames | per-connection preface only (`transport.go:873-876`, `types.go:106`) | Never emitted per request. |
| PRIORITY_UPDATE (0x10) | **none** | Frame type not implemented anywhere in `fhttp/http2`. |
| PRIORITY_UPDATE placement rel. HEADERS | **none** | Follows from the above. |
| DATA frame size cap | none | Always `min(peerMaxFrameSize, window, remaining)`. |
| DATA padding | none | `WriteDataPadded` exists but transport calls `WriteData` (`transport.go:1605`). |
| HEADERS padding | none | `PadLength` never set by the client path. |
| END_STREAM placement | none | Implicit in the code path. |
| CONTINUATION fragment size | none | Hardcoded to `cc.maxFrameSize` (`transport.go:1421`), and mis-budgeted by 5 octets. |
| WINDOW_UPDATE policy (threshold / trigger / increment mode / order / coalescing) | none | Only the one-shot preface `ConnectionFlow` value (`transport.go:786-787`). |
| GOAWAY on shutdown, reset codes | none | Reset codes hardcoded, e.g. `ErrCodeCancel` at `transport.go:1574, 1583, 1596`. |
| SETTINGS values + order | per-client (`types.go` `CustomTlsClient`) | Adequate; not a gap. |
| Regular header order | per-request (`RequestInput.HeaderOrder`, `types.go:70`; `fhttp/header.go:36`) | Adequate; not a gap. |

**The shape of the gap, stated once:** bogdanfinn binds nearly every HTTP/2 wire property to the
*connection profile*. The per-request surface is exactly two things — regular header order
(`Header-Order:`) and pseudo-header order (`PHeader-Order:`, Go-only). Everything else — priority,
padding, frame sizing, extra frames, END_STREAM placement, `:protocol`, authority mode — is either
fixed at connection setup or hardcoded. That is precisely the axis set our per-request lifecycle
work must open up.

Reference profile shape, for what a real profile looks like:
`profiles/internal_browser_profiles.go:121` (`var Chrome_150 = ClientProfile{...}`) — the file
contains 10 `headerPriority` assignments across all profiles, confirming header priority is a
per-profile constant.

---

## 12. Where the binding spec / plan appears to contradict, or under-specify against, an RFC

Ranked by consequence. `SPEC nnn` = line in
`docs/superpowers/specs/2026-08-14-http2-wire-fidelity-design.md`;
`PLAN nnn` = line in `docs/superpowers/plans/2026-08-16-http2-request-lifecycle.md`.
Both documents were read in full for this section.

### 12.1 HIGH — a plan test assertion bakes in the wrong GOAWAY Last-Stream-ID semantics

**PLAN 513** (Task 18, GOAWAY on shutdown):

> "Assert the GOAWAY frame's last-stream-id equals **the highest stream the client opened**."

**This is backwards.** RFC 9113 §6.8:

> "the GOAWAY contains the stream identifier of the last **peer-initiated** stream that was or
> might be processed on the sending endpoint in this connection. For instance, if the server
> sends a GOAWAY frame, the identified stream is the highest-numbered stream initiated by the
> client."

> "The last stream identifier can be set to 0 if no streams were processed."

Client-initiated streams are odd; server-initiated (pushed) streams are even (RFC 9113 §5.1.1).
A **client's** GOAWAY Last-Stream-ID names the highest **even** (pushed) stream the client
processed — which is **0** on every connection that accepted no server push, i.e. essentially
always for this library. The streams the client itself opened are exactly the ones the field must
*not* describe.

Writing the client's own last odd stream id tells the server "I processed your streams 1..N",
which is meaningless (the server never initiated them) and, worse, is the value real servers
parse to decide which of *their* pushes were handled.

**Action:** change the assertion and the implementation to emit Last-Stream-ID = highest
*pushed* (even) stream id the client processed, defaulting to `0`. SPEC 649-651 does not state a
value either way, so the spec needs the same sentence added.

### 12.2 HIGH — DATA padding is not reserved against the flow-control window

**PLAN 306** correctly adds pad range 0–255, and **PLAN 308-310** already fixes the HEADERS
half of this:

> "Padding consumes frame payload. The CONTINUATION split must subtract pad overhead the same way
> it subtracts the priority payload, or a padded header block overruns the peer's maximum frame
> size."

Good — that matches RFC 9113 §4.2 + §6.2. The exact budget to implement is:

```
fragment ≤ maxFrameSize − (padded ? 1 : 0) − (priority ? 5 : 0) − padLength
```

and note that overrunning it on HEADERS is a **connection** error of type FRAME_SIZE_ERROR, not a
stream error, because HEADERS carries a field block (RFC 9113 §4.2). CONTINUATION frames have no
PADDED flag at all (RFC 9113 §6.10, Figure 12), so only the first frame of a split block pays the
pad cost.

**The DATA half is missing.** PLAN 421 (Task 14) still states the effective DATA size as:

> "Effective size is `min(MaxDataFrameSize, peerMaxFrameSize, connectionWindow, streamWindow)`"

computed on payload *data* bytes, and PLAN 417 modifies only "the send-window reservation".
RFC 9113 §6.1 is explicit:

> "**The entire DATA frame payload is included in flow control, including the Pad Length and
> Padding fields if present.**"

So a padded DATA frame consumes `1 + dataLen + padLen` from **both** the stream and connection
send windows, not `dataLen`. As currently specified, enabling `DataPadding` will over-send
against the advertised window — "The sender MUST NOT send a flow-controlled frame with a length
that exceeds the space available in either of the flow-control windows advertised by the
receiver" (RFC 9113 §6.9.1) — producing a peer FLOW_CONTROL_ERROR. The same `1 + padLen`
overhead must also be subtracted before comparing against `peerMaxFrameSize`.

**Action:** Task 8 Step 2 must cover DATA as well as HEADERS; Task 14's formula becomes
`dataLen ≤ min(MaxDataFrameSize, peerMaxFrameSize, connWindow, streamWindow) − (padded ? 1 + padLength : 0)`.

### 12.3 RESOLVED IN THE PLAN — the `StreamId = 0` sentinel

**SPEC 466-469** reads as self-contradictory: "Frames targeting stream 0 are permitted in both
lists; frames targeting the request's own stream use `StreamId = 0` as a sentinel meaning 'this
request's stream'". Taken literally that makes a legal PING (stream id MUST be 0, RFC 9113 §6.7)
and a legal PRIORITY_UPDATE (frame stream id MUST be 0, RFC 9218 §7.1) inexpressible via the raw
frame type, both of which SPEC 705 lists as permitted.

**PLAN 245 already resolves it:**

> "`StreamId = 0` on a request frame means 'this request's stream' and is replaced with the
> allocated identifier when written. A frame that genuinely targets stream 0 declares
> `TlsHttp2RequestRawFrame` with the connection-level type it wants; **the sentinel only applies
> to the frame classes whose natural target is the request stream.**"

and PLAN 217 carries `TargetsRequestStream` on the internal frame record to encode exactly that.
PLAN 220-221 additionally validates PING as 8 octets on stream 0, citing RFC 9113 §6.7 correctly.

No action needed on the plan. **Action on the spec:** SPEC 466-469 should be amended to match
PLAN 245, since the spec is the binding document and currently reads as a contradiction.

### 12.4 MEDIUM — "RFC 9113 §8.3.1 permits all three" is an overstatement, in both documents

**SPEC 529-531:** `AuthorityMode` "selects `:authority` alone […], a `host` regular header alone,
or both, **which RFC 9113 section 8.3.1 permits** and which stacks differ on."
**PLAN 338:** "`AuthorityMode` selects `:authority` alone, a `host` regular header alone, or both
— **RFC 9113 section 8.3.1 permits all three** and stacks differ."

§8.3.1 does not permit all three for a client generating requests directly:

- `AuthorityOnly` — required. "Clients that generate HTTP/2 requests directly MUST use the
  ':authority' pseudo-header field to convey authority information, unless there is no authority
  information to convey (in which case it MUST NOT generate ':authority')."
- `Both` — permitted **only when the values match**: "Clients MUST NOT generate a request with a
  Host header field that differs from the ':authority' pseudo-header field." That cross-field
  constraint appears nowhere in the spec's validation list (SPEC 694-726).
- `HostHeaderOnly` — **not permitted** for a directly-generating client; it violates the MUST
  quoted above. Only an *intermediary* forwarding a request "MAY retain any Host header field",
  and even then §8.3.1 requires it to construct `:authority`.

The mode is still worth having — real stacks and proxies do emit Host-only — but the
justification is "matches observed non-conformant clients", not "RFC-permitted".

**Action:** reword both documents; add the `Host == :authority` cross-field rule for `Both`; mark
`HostHeaderOnly` as deliberately non-conformant in its XML doc so a caller knows what they are
choosing.

### 12.5 MEDIUM — Raw-frame validation enforces PING's invariants but not the other known types

**PLAN 220-221 already validates PING** ("A PING payload is exactly 8 octets (RFC 9113 section
6.7)"; "A PING must target stream 0; RFC 9113 section 6.7 makes any other stream identifier a
PROTOCOL_ERROR") — correct on both counts, though note the two violations carry *different* codes:
wrong length is FRAME_SIZE_ERROR, wrong stream id is PROTOCOL_ERROR (RFC 9113 §6.7).

SPEC 700-706 additionally permits raw `PRIORITY (0x2)`, `PRIORITY_UPDATE (0x10)`, `SETTINGS
(0x4)`, `WINDOW_UPDATE (0x8)` and unknown types with arbitrary `Flags`, `StreamId`, `Payload`;
SPEC 707 caps payload at 16384 bytes. Nothing enforces the remaining per-type invariants:

| Type | Invariant | Error if violated |
|---|---|---|
| PING 0x06 | length **exactly 8**; stream id **0** | FRAME_SIZE_ERROR / PROTOCOL_ERROR, both connection errors (RFC 9113 §6.7) |
| PRIORITY 0x02 | length **exactly 5**; stream id **≠ 0** | stream FRAME_SIZE_ERROR / connection PROTOCOL_ERROR (RFC 9113 §6.3) |
| WINDOW_UPDATE 0x08 | length **exactly 4**; increment **∈ [1, 2^31−1]** | FRAME_SIZE_ERROR (connection); increment 0 → stream PROTOCOL_ERROR, or connection PROTOCOL_ERROR on stream 0 (RFC 9113 §6.9) |
| SETTINGS 0x04 | length a **multiple of 6**; stream id **0** | FRAME_SIZE_ERROR / PROTOCOL_ERROR, connection errors (RFC 9113 §6.5) |
| PRIORITY_UPDATE 0x10 | frame stream id **0**; Prioritized Stream ID **≠ 0** | connection PROTOCOL_ERROR (RFC 9218 §7.1) |

Unknown types are genuinely unconstrained: "Implementations MUST discard frames that have unknown
or unsupported types" (RFC 9113 §5.5). So the escape hatch is only dangerous for *known* types.
**Action:** extend PLAN Task 4's validation (which today covers PING only) to PRIORITY,
WINDOW_UPDATE, SETTINGS and PRIORITY_UPDATE; leave unknown types free.

### 12.6 MEDIUM — `FixedIncrement` has no stated lower bound, and no window-ceiling check

Spec line 609-611 adds `Increment = Fixed` with `uint FixedIncrement`. RFC 9113 §6.9: increment
must be in `[1, 2^31−1]`; a zero increment is a PROTOCOL_ERROR (stream-level) or a connection
error when it targets the connection window. RFC 9113 §6.9.1: a WINDOW_UPDATE that pushes the
peer's window past `2^31−1` causes the peer to send RST_STREAM/GOAWAY with FLOW_CONTROL_ERROR.

The validation list (694-726) constrains thresholds against declared windows (line 717) but says
nothing about `FixedIncrement`. **Action:** require `FixedIncrement ∈ [1, 2^31−1]`; the same for
any preface `ConnectionWindowIncrement`.

### 12.7 NOT A CONTRADICTION — `MaxDataFrameSize` clamp and determinism

SPEC 713 allows `MaxDataFrameSize ∈ [1, 16777215]`, matching the `SETTINGS_MAX_FRAME_SIZE` range
of `[2^14, 2^24−1]` (RFC 9113 §4.2). SPEC 585 and PLAN 421 both state the effective size is
`min(MaxDataFrameSize, peerMaxFrameSize, connectionWindow, streamWindow)` "with the same
pre-SETTINGS determinism rule as header fragments", and PLAN 383 fixes the pre-SETTINGS clamp at
the RFC default 16384. All correct per RFC 9113 §4.2 ("All implementations MUST be capable of
receiving and minimally processing frames up to 2^14 octets in length"). The only gap is the
padding overhead — see §12.2.

### 12.8 LOW — Citation correction: self-dependency rule is RFC 7540, not RFC 9113

Spec line 708: "A priority frame's stream identifier may not equal its dependency." Correct as a
validation, but RFC 9113 contains no such rule — the phrase "depend on itself" does not occur in
the document. The source is **RFC 7540 §5.3.1**. See §10.5 above.

### 12.9 LOW — CONNECT pseudo-header rules in the spec are correct; recorded here as verified

Spec line 534-539 states: `:method` always required; plain CONNECT carries only `:method` and
`:authority`; CONNECT with `:protocol` requires `:method`, `:authority`, `:scheme`, `:path`,
`:protocol`; any other method requires `:method`, `:scheme`, `:path` and permits `:authority`.

**This matches RFC 9113 §8.5, RFC 8441 §4, and RFC 9113 §8.3.1 exactly.** No contradiction. One
addition worth making: the spec does not mention that `:protocol` should be gated on having
received `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (RFC 8441 §3), though line 923 does reference the
setting in the test list.

### 12.10 Verified-as-correct, for the record

- Spec line 724, padding `[0, 255]` — correct. The Pad Length field is 8 bits (RFC 9113
  §6.1/§6.2), and the "padding ≥ payload" prohibition can never be triggered by a
  correctly-computing sender because the payload includes the Pad Length octet itself.
- Spec line 639, `ConnectionWindowUpdateThreshold ≤ 65535 + Σ preface increments` — correct;
  the connection window starts at 65,535 and is changeable only by WINDOW_UPDATE (RFC 9113
  §6.9.2).
- Spec line 616, `SuppressStreamUpdateOnEndStream` as a togglable axis — correct and explicitly
  authorised: "WINDOW_UPDATE can be sent by a peer that has sent a frame with the END_STREAM flag
  set. […] A receiver MUST NOT treat this as an error" (RFC 9113 §6.9).
- Spec line 464-465 and 919, PRIORITY_UPDATE on either side of HEADERS — correct and explicitly
  authorised: "A client MAY send a PRIORITY_UPDATE frame before the stream that it references is
  open" (RFC 9218 §7).
- Spec line 694-696, SETTINGS range checks — correct per RFC 9113 §6.5.2 and §4.2
  (`MAX_FRAME_SIZE ∈ [16384, 16777215]`).
- Spec line 653-655, reset-code defaults (`Cancel` / `InternalError` / `Cancel`) — all legal.
  RFC 9113 §5.4: "an endpoint MAY use any applicable error code […] a generic error code (such as
  PROTOCOL_ERROR or INTERNAL_ERROR) can always be used in place of more specific error codes."
  **CONVENTION**, not requirement — which is exactly what makes them useful fingerprints.
- PLAN 249, "Before-frames precede HEADERS, after-frames follow the final CONTINUATION. Nothing
  may land between HEADERS and its CONTINUATION frames (RFC 9113 sections 6.2 and 6.10)" —
  correct, and correctly cited. §4.3 is a third, stronger statement of the same rule and is worth
  adding to the citation.
- PLAN 358-360, the CONNECT / extended-CONNECT pseudo-header matrix — matches RFC 9113 §8.5 and
  RFC 8441 §4 exactly. One addition: gate `:protocol` emission on having received
  `SETTINGS_ENABLE_CONNECT_PROTOCOL` (code 0x8) with value 1 (RFC 8441 §3, §9.1).
- PLAN 306, padding range 0–255 with a one-octet pad-length field — correct (RFC 9113 §6.1/§6.2).
- PLAN 476, `SuppressStreamUpdateOnEndStream` — correct; explicitly authorised by RFC 9113 §6.9
  ("WINDOW_UPDATE can be sent by a peer that has sent a frame with the END_STREAM flag set […] A
  receiver MUST NOT treat this as an error").
- PLAN 493, threshold-vs-window cross-field rule — correct per RFC 9113 §6.9.2.

### 12.11 Not a contradiction, but the highest-leverage omission

Nothing in either document expresses the RFC 9218 §2.1.1 *transition*: a client SHOULD send both
the RFC 7540 HEADERS priority payload **and** PRIORITY_UPDATE until the server's first SETTINGS
arrives, then SHOULD drop whichever the server said it ignores. That means a faithful Chrome
emulation changes its per-request framing mid-connection based on a received setting. The
per-request options model needs a way to express "priority signal set is a function of the peer's
`SETTINGS_NO_RFC7540_PRIORITIES`", or the first request on a connection will not match the
capture. (RFC 9218 §2.1, §2.1.1.)
