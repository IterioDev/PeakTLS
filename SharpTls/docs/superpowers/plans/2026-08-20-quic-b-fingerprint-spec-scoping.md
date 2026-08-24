# Subsystem B scoping: the QUIC transport-parameter fingerprint

Date: 2026-08-20
Status: scoping plan. Not a spec, not an implementation.
Parent: `docs/superpowers/specs/2026-08-16-quic-transport-scoping.md`
Model for structure and rigour: `docs/superpowers/plans/2026-08-19-quic-c-http3-scoping.md`
Target: `the preset that measured it`

**Purpose:** answer *"what closes `perk` segment 3"* with a dependency chain rather than a date, and
cost the work that closes it.

This exists because subsystem B had never been scoped. The parent scoping gives it one paragraph
(lines 296-306: *"comparatively small — roughly 8 to 10 tasks"*) and a checklist of eight items, and
nothing else. C is complete through C12 and its own readout says B owns the largest remaining gap.

**Read-only note:** this document was produced without touching `src/` or `tests/`, the index, or
history. Every claim about the tree was checked with a read or a grep, and the grep is named.

---

## The short answer

| Milestone | Tasks | Derived from |
| --- | --- | --- |
| B, enough to compose and order all fourteen parameters | **11** | tasks B0-B10 below |
| B, plus the live run that proves the hash moved | **+1** | task B11 below |
| The packet-capture arm — the knobs this endpoint cannot see | **+2** | tasks B12-B13 below |

11 + 1 = **12 tasks to move `perk_hash`.** 12 + 2 = **14 with the unverifiable arm.**
Every figure is the length of a list in this file.

**The range is 12 to 14 and the four things that drive it are named in *The estimate and its
uncertainty*.** One of them - the Initial flight plan a 1216-byte key share forces - is not bounded
by anything in this repo *or by this endpoint*, and it is the only term that can be wrong without
anything failing. It is measurable only by a packet capture, which is task B12.

**And one thing that is not an uncertainty, though it looks like the biggest one.** Three of the
seven parameters we are missing carry values the capture deliberately does not publish. The `perk`
string does not hash any of those three - see Finding 3. **An exact `perk_hash` is reachable without
ever learning a Chromium randomiser's bounds.**

---

## Findings from planning - read these before the tasks

Eleven. Each changes a task, and four of them contradict something a prior document asserts - one of
them contradicts this document's own brief. A4's plan found eight during planning and C's found ten;
both said that section was worth more than the tasks. This follows the same practice.

### Finding 1 - nothing in `src/` composes a client transport-parameter list, and the eight parameters we "send" are a test fixture's choice

`grep -rn 'WithQuicTransportParameters\|TlsQuicTransportParameters\.' src/ tests/ samples/ --include=*.cs`.
Every hit under `src/` is one of three shapes: the builder method itself
(`ClientHelloBuilder.cs:340`), a parse-and-rebuild of somebody else's blob
(`ClientHelloCapture.cs:339`, `ClientHelloSpecJson.cs:249`, `ClientHelloSpec.cs:71`), or a read
(`TlsQuicFingerprintReadout.cs:522`, `TlsQuicEvents.cs:61`). **None of them composes a list.** Every
composing call site is under `tests/`.

The live `perk` segment 3 the handoff records - `15:AUTO;14:2;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103` -
comes from `tests/SharpTls.Tests/Interop/QuicPublicEndpointInteropTests.cs:304-312`, which writes
`initial_source_connection_id`, then `active_connection_id_limit` at 2, then spreads
`localFlowControl.ToTransportParameters()`. 1 + 1 + 6 = **8**, which is the field count of that
segment.

**This is the segment-1 trap running the other way.** The handoff records, for h3 SETTINGS, *"A
test's chosen spec is not the library's capability."* There the test narrowed a capable library.
Here the library has **no** capability at this seam at all, and a test fixture made it look as
though it had one. The measurement is honest; the inference "we send 8" is a statement about
`QuicPublicEndpointInteropTests.cs`, not about SharpTls. -> task B1.

### Finding 2 - wire order needs no codec work, and this is a read rather than a trust

The capture's item 2 claims *"SharpTls can already express it through `TlsQuicTransportParameters`
and `ClientHelloBuilder.WithQuicTransportParameters`."* Checked:

`TlsQuicTransportParameters`' constructor copies the input sequence with `.Select(...).ToArray()`
and never sorts; it rejects a duplicate id, caps the count at `MaximumParameterCount`, caps the
encoding at `MaximumEncodedLength`, and calls `Encode()` once eagerly so an over-long set fails at
construction. `Encode()` (`:105`) walks `_parameters` in that stored order and appends id, length,
value. `Parameters` (`:91`) is documented *"in wire order"*.

So the capture is right, and **B7 is composition plus an anti-sort test, not an encoder.** Note also
what the constructor does *not* do: `ValidateParameter`'s `switch` ends in `default: break;`, so an
unknown identifier - 12583, 12584, a reserved GREASE id - is constructible today with no change.

One asymmetry worth carrying: `ValidateParameter` is reached only from `ValidatePeer(senderRole)`,
which is for the parameters a *peer* sent. **Nothing validates the set we build ourselves.** That is
a free done-when for B3, not a defect to fix. -> tasks B1, B3, B7.

### Finding 3 - every value the capture does not publish is a value the `perk` string does not hash

The seven missing parameters, against the capture's own rendering of segment 3 (capture line 47):

| Missing parameter | Value published? | How `perk` renders it |
| --- | --- | --- |
| 12584 `google_connection_options` | yes, `0x4f524947` | `12584:0x4f524947` - hashed |
| reserved (GREASE) parameter | **no** - id given only as *"id ≈ 3.7457e18"*, value `0xfb` | bare token `GREASE` - **not hashed** |
| 32 `max_datagram_frame_size` | yes, 65536 | `32:65536` - hashed |
| 17 `version_information` | **partly** - chosen 1; the available list's GREASE version is not published | `17:1@GREASE,1` - the GREASE half **not hashed** |
| 1 `max_idle_timeout` | yes, 30000 | `1:30000` - hashed |
| 12583 `initial_rtt` | **no**, and explicitly so: *"192859 is not a constant to copy"* | `12583:AUTO` - **not hashed** |
| 3 `max_udp_payload_size` | yes, 1472 | `3:1472` - hashed |

Four published and hashed; three unpublished and tokenised. **The two sets coincide exactly**, and
the capture says why for the one case it comments on: *"The `perk_text` reflects this by rendering
it `12583:AUTO` rather than embedding the number, and does the same for `initial_source_connection_id`
at `15:AUTO`."*

Two consequences, and they pull in opposite directions.

- **For the `perk_hash` gate this collapses the largest apparent risk.** B can reach an exact
  segment 3 while `initial_rtt`'s bounds, the GREASE parameter's identifier and the GREASE version
  in `version_information` all remain declared placeholders. What is hashed about those three is
  their **position**, which the capture publishes.
- **For a packet-capture diff it changes nothing.** Those three values are on the wire whatever the
  fingerprint service does with them, and a pinned `initial_rtt` is a fingerprint against anyone who
  looks at two connections. So B must still randomise; it just must not *block* on the range.

-> tasks B3, B4, B5, B10.

### Finding 4 - removing `active_connection_id_limit` is inert on the wire, and RFC 9000 §18.2 says so twice

From `rfc9000-section18-transport-parameters.txt`, the `active_connection_id_limit (0x0e)` entry
(extract lines 224-236), two sentences past the line wrap:

- *"If this transport parameter is absent, a default of 2 is assumed."* We send exactly 2
  (`QuicPublicEndpointInteropTests.cs:308-309`; the live segment renders `14:2`). Absent and
  present-at-2 are the same advertisement.
- *"If an endpoint issues a zero-length connection ID, it will never send a NEW_CONNECTION_ID frame
  and therefore ignores the active_connection_id_limit value received from its peer."* Chromium's
  source connection ID is zero-length - the capture's whole first section - so a Chromium client
  omitting this parameter is not carelessness, it is the parameter having no addressee.

The parameter still means something in our direction: it governs how many connection IDs the
**server** may hand **us**. Dropping it from explicit-2 to absent-defaults-to-2 leaves that number
unchanged.

And in our own code the removal is doubly inert. `TlsQuicTransportParameters.GetIntegerOrDefault`
(`:216-222`) already maps an absent `ActiveConnectionIdLimit` to 2, quoting the same sentence; and
`grep -rn 'NewConnectionId\|ActiveConnectionIdLimit' src/SharpTls/Quic/TlsQuicConnection.cs` returns
**nothing** - the connection never reads it, ours or the peer's.

**So the protocol consequence of removing an advertised parameter is, here, zero** - and B6's
done-when must *prove* that rather than assert it, because "zero consequence" is exactly the claim
that stops being true the day someone implements NEW_CONNECTION_ID. -> task B6.

### Finding 5 - the post-quantum key share is supported, the multi-datagram Initial is supported, and nothing connects the two

This is the single largest correction in this document, and it has the same shape as C's Finding 1:
a capability exists, a plan says it is covered, and the connecting line was never written.

Three reads.

1. **The key share exists on the real path.** `src/SharpTls/Cryptography/KeyShareFactory.cs` maps
   `NamedGroup.X25519MlKem768 => X25519MlKem768KeyShare.Create()` in `Create`, with the
   `CreateDeterministicForTesting` variant kept in a separate method. `UTlsClientHelloProfiles.Additional.cs:101-120`
   already pins Chrome_131 and Chrome_133 profiles with `hybridGroup: NamedGroup.X25519MlKem768`.
   `X25519MlKem768KeyShare.cs:9` defines `ClientShareSize` as a **sum of two named constants**, not a
   typed number.
2. **A two-datagram Initial is buildable.** `TlsQuicDatagramBuilder.BuildInitialFlight` (`:296`)
   returns `List<byte[]>`, one entry per datagram, and its summary records that §14.1's expansion is
   *"per datagram and not per flight, and a two-datagram Initial pads both."*
   `TlsQuicConnectionSpec` carries both halves of the plan as public knobs -
   `InitialCryptoFrameByteCounts` (`:355`) and `InitialCryptoFramesPerDatagram` (`:390`) - with a
   cross-check that the second accounts for exactly the frames the first produces.
3. **Nothing splits automatically, and nothing bounds a datagram to a path.**
   `SplitIntoFrames` (`:423`) on an empty `InitialCryptoFrameByteCounts` returns **one** frame
   carrying the whole stream; `GroupIntoDatagrams` (`:485`) on an empty
   `InitialCryptoFramesPerDatagram` returns **one** datagram; both defaults are `[]`
   (`TlsQuicConnectionSpec.cs:173-174`). The flight buffer is `new byte[MaximumUdpPayload]` where
   `MaximumUdpPayload = 65527` (`:75`), and the only rejection is `streamBytes >= MaximumUdpPayload`.
   The source states the contract in its own words: *"THE BUFFER IS THE PHYSICAL CEILING, NOT THE
   TARGET… OVERSHOOT IS ALLOWED"*, witnessed by
   `TlsQuicDatagramBuilderTests.AFlightDatagramMayExceedThePaddingTarget`. **`PaddingTarget` is a
   floor, and there is no ceiling anywhere in the flight builder.**

Put together: the day B swaps the interop fixture's `WithKeyShares(NamedGroup.X25519)` for the
capture's X25519MLKEM768, the **default** spec emits **one** oversized Initial datagram. It is legal
under §14.1, it does not throw, and it is not what Chromium sends. The capture's own conclusion 5 -
*"The post-quantum key share forces a multi-datagram Initial, so that path is required, not
optional"* - is satisfied by the builder and defeated by the defaults.

And the endpoint cannot tell us. Capture lines 30-33 list what the service does **not** inspect, and
*"per-datagram Initial flight plans, CRYPTO frame splitting"* are on it. **A wrong answer here looks
exactly like a right one.** -> task B9, and the split point is a declared placeholder settled only
by task B12.

### Finding 6 - `grep -rn '"h3"' src/ --include=*.cs` no longer returns nothing, and three comments in `src/` assert that it does

This document's brief repeats the claim, C's plan carries it as a row, and C12's readout renders a
row from it. Re-run today it returns **4** lines:

- `TlsQuicHttp3Connection.cs:70` - the comment stating the grep returns nothing
- `TlsQuicHttp3Connection.cs:71` - the comment's next line
- `TlsQuicHttp3FingerprintReadout.cs:95` - a comment citing the first comment
- `TlsQuicHttp3FingerprintReadout.cs:753` - the literal `"h3"` in the readout's **client** column
  (`:750-754`)

**The grep now finds its own citation.** Three of the four hits exist only because someone wrote the
grep's result down next to the grep.

The underlying claim still holds, and a grep that cannot decay proves it:
`grep -rn 'WithAlpn(' src/ --include=*.cs` returns **25** lines; exactly **1** of them contains the
token `h3`, and that one is `TlsQuicHttp3Connection.cs:71`, a comment.
`grep -rn 'WithAlpn("h3")' tests/ --include=*.cs`
returns **18**. So: **no profile under `src/` offers h3; eighteen call sites under `tests/` do.**

**Standing rule earned:** a grep quoted in a comment becomes a witness of itself. Cite the grep, do
not paste its emptiness into the tree it searches. -> tasks B8, B10.

### Finding 7 - `initial_rtt` has a knob already, it is `null`, and nothing consumes it

`TlsQuicConnectionSpec.InitialRttRange` (`:565`) is `(TimeSpan Minimum, TimeSpan Maximum)?`. Its
setter validates a supplied range - minimum positive, maximum not below minimum, witnessed by
`TlsQuicConnectionSpecTests.AnInitialRttRangeWhoseMaximumIsBelowItsMinimumIsRejected` - and its
default is `null`.

`grep -rn 'InitialRttRange\|12583' src/ --include=*.cs` returns the property, the file header
(`TlsQuicConnectionSpec.cs:84,88`), `TlsQuicConnection.cs:521-524` - *"ADDS NOTHING TODAY"* - and the
existing QUIC readout, which already carries an `initial_rtt` presence row
(`TlsQuicFingerprintReadout.cs:174, :615`) and states at `:785-786` that the capture *"fixes neither
bounds nor distribution, so `TlsQuicConnectionSpec.InitialRttRange` is null and nothing"* emits it.

**A4 task 1's refusal to invent a range is in the tree, as a null.** B inherits the refusal, not the
freedom. What would be needed to bound it is a **source**, not a decision: the capture names uQUIC's
`ChromeRandomInitialRTT()` as one. Reading that function and recording it under
`reference-captures/` is a source-acquisition task of exactly B0's kind. Inventing a range because a
`(min, max)` tuple looks unfinished is the thing A4 task 1 refused, and it stays refused.

Finding 3 says this does not block the gate. -> task B5.

### Finding 8 - seven of the parent scoping's eight B items already exist as knobs

`grep -cE '^    public ' src/SharpTls/Quic/TlsQuicConnectionSpec.cs` returns **17** public members.
Against the parent scoping's own B checklist (lines 300-303, **8** items):

| Parent scoping's B item | Knob | Line |
| --- | --- | --- |
| connection ID lengths | `SourceConnectionIdLength`, `DestinationConnectionIdLength` | `:203`, `:225` |
| initial packet number | `InitialPacketNumber` | `:248` |
| its encoded length | `PacketNumberEncodedLength` | `:274` |
| token length and prefix | `Token` | `:303` |
| per-datagram Initial plans | `InitialCryptoFramesPerDatagram` | `:390` |
| CRYPTO frame splitting | `InitialCryptoFrameByteCounts` | `:355` |
| datagram padding target | `PaddingTarget` | `:323` |
| **transport parameter order, GREASE parameters** | — | **absent** |

Seven present, one absent - and **the absent one is the only item on that list the endpoint can
see**, since capture lines 30-33 put the other seven's observable consequences among what the
service does not inspect.

Two things follow. **B is a composition-and-defaults job, not a build**, which is why this document's
count is smaller than a phase and why its tasks name few new files. And **the parent scoping's
"roughly 8 to 10 tasks" was right about the reason and guessed the number**; 12 here is a list
length.

While recomputing this: `_sourceConnectionIdLength` (`:168`) has no initialiser, so the shipped
default is **0** - Chromium's value - and `_destinationConnectionIdLength` (`:169`) initialises to
the §7.2 floor, which the C12 snapshot's client column gives as 8. **Segment 4 is already correct by
default**, and the readout's row 25 showing `5,8` is its harness choosing a 5-byte source CID
deliberately, per task 11's reason. See Finding 10.

### Finding 9 - the capture's TLS half is E's, and the seam that decides it already exists in the code

The capture's TLS section publishes JA3, three cipher suites, eleven extensions in wire order, two
key shares and four supported groups. Assigning it is a real scoping decision and this document
makes it: **that half is E's, except for the body of extension 57, which is B's.**

Four reasons, in descending strength.

1. **The seam is already built and already populated.** `src/SharpTls/ClientHello/` carries the
   profile machinery, and `grep -rn 'WithAlpn(' src/ --include=*.cs` alone finds **25** profile
   definitions expressing exactly this shape - cipher suites, extension order, groups, key shares.
   Chrome_131 and Chrome_133 with X25519MLKEM768 and ALPS are already among them
   (`UTlsClientHelloProfiles.Additional.cs:101-120`). Nothing in the capture's TLS half needs a new
   mechanism; it needs a profile written from the capture.
2. **The parent scoping's definition of B is the packet layer only** - lines 283-290, verbatim:
   *"What is genuinely missing is the **packet layer only**"*, followed by six bullets, none of them
   TLS.
3. **Nothing in the TLS half is per-connection**, so it needs none of the machinery B is forced to
   build for the three randomised parameters.
4. **The code has already made this call.** `TlsQuicHttp3Connection.cs:73`: *"Supplying a profile
   that offers h3 is subsystem B's."* That sentence is about the **factory**, and this document
   honours it in that narrow sense - see B8 - while the profile's **content** stays E's.

**The precise seam:** extension 57's *body* is `TlsQuicTransportParameters.Encode()` and is B's; its
*position* in the wire order - the capture puts it between 10 `supported_groups` and 13
`signature_algorithms` - is the profile's and is E's. `65037 encrypted_client_hello` and `17613
alps_new` are E's too, and the machinery for the first exists (`src/SharpTls/Ech/`).

### Finding 10 - the readout already reserves B's rows, and there are eight of them

`tests/SharpTls.Tests/Quic/quic-http3-fingerprint-readout.snapshot.txt`, rows 18-25, all labelled
`[subsystem B]`: six `match` (transport parameters 0x04, 0x05, 0x06, 0x07, 0x08, 0x09), and two
`MISMATCH` (row 24 wire order, row 25 the CID length pair). The snapshot's own verdict block reads
`rows 25 / match 15 / MISMATCH 2 / not-yet-known-from-the-capture 8`, with `15 + 2 + 8 = 25` printed
beneath it.

Two things B10 must respect.

- **Grow the table, do not replace it.** The arithmetic line is part of the artefact; C's standing
  rules require the row count to be derived from the rendered list rather than asserted beside it,
  and that must still hold after B's rows land.
- **Row 25 is not B's to fix by changing a default.** Finding 8 shows the shipped source-CID default
  is already 0 and the live run returned `0,8`. The row reads `5,8` because the readout's harness
  picks 5 on purpose. **Changing the default to make a readout row green would be scoring the
  fixture** - exactly what the readout's own comment at `:96-98` refuses to do for ALPN. The fix is
  a harness that can render the shipped default alongside the deliberate one.

### Finding 11 - advertising `max_datagram_frame_size` is a promise C17 keeps, and B must not absorb it

The capture's parameter 32 at 65536 tells the peer it may send RFC 9221 DATAGRAM frames. C's Finding
8 already established the other side of that: `grep -cE "^\s+[A-Z][A-Za-z]+ = 0x" src/SharpTls/Quic/TlsQuicFrameType.cs`
returns **20**, which is RFC 9000 §12.4 Table 3's set, and RFC 9221's frame types are not among
them - so an arriving DATAGRAM frame is an unknown frame type and closes the connection.

**B2 makes the advertisement. C17 makes it honest.** Do not fold C17 into B: it is already scoped,
already costed at one task, and already carries its own extraction. Two things B owes instead: B2's
source must point at C17 by name at the line that emits parameter 32, and B11's done-when must
record that the advertisement is live, because a server that takes the offer turns a passing run
into a connection close and the failure will present as loss.

The same is true one layer up for `SETTINGS_H3_DATAGRAM = 1`, which `TlsQuicHttp3Spec.CaptureSettings`
already emits by default (`TlsQuicHttp3Spec.cs:142-149`, `:201`). That advertisement is already live
today. B does not make it worse; it makes it worse *twice*.

---

## What B inherits, concretely

Verified against the source, not assumed.

| Concern | Where | State |
| --- | --- | --- |
| Transport parameter encoding in **caller-supplied order** | `TlsQuicTransportParameters` ctor + `Encode` `:105` | complete - Finding 2 |
| Duplicate-id, count and length rejection | same ctor | complete |
| Unknown / private / GREASE identifiers accepted | `ValidateParameter`'s `default: break;` | complete - no change needed for 12583, 12584, reserved ids |
| `version_information` (0x11) and `max_datagram_frame_size` (0x20) identifiers | `TlsQuicProtocol.cs:184`, `:186` | defined |
| `version_information` structural validation | `ValidateVersionInformation` `:331` | complete, but reachable only via `ValidatePeer` - Finding 2 |
| The six flow-control values, emitted and enforced from one object | `TlsQuicLocalFlowControlSpec.ToTransportParameters` | complete, ascending by id |
| Seven of the eight parent-scoping B knobs | `TlsQuicConnectionSpec` | present - Finding 8 |
| Multi-datagram Initial construction | `TlsQuicDatagramBuilder.BuildInitialFlight` `:296` | complete; **defaults produce one datagram** - Finding 5 |
| X25519MLKEM768 on the non-testing path | `KeyShareFactory.cs` | complete |
| A readout with B's rows already reserved | `TlsQuicHttp3FingerprintReadout` + snapshot | 8 rows - Finding 10 |
| `initial_rtt` randomisation | `InitialRttRange` `:565` | knob present, `null`, **no consumer** - Finding 7 |
| A composed client parameter list under `src/` | — | **absent** - Finding 1 |
| A profile offering ALPN `h3` under `src/` | — | **absent** - Finding 6 |
| RFC 9368 / RFC 9221 extracts | — | **absent** - `ls docs/superpowers/specs/reference-captures/` |

---

## Task B0: extract the RFC sections B needs

**Files:** new files under `docs/superpowers/specs/reference-captures/`, matching the convention of
the 46 already there (`ls docs/superpowers/specs/reference-captures/`).

**Method, unchanged from A4 task 0 and C0:** fetch from `https://www.rfc-editor.org/rfc/rfcNNNN.txt`
inside the sandbox, locate the heading in the document *body* past the table of contents, `sed` the
range, prepend a provenance header in the established shape, then **diff the committed body line by
line against an independent re-fetch of the same range**, trimming only trailing whitespace.

| Source | Needed for | Present today? |
| --- | --- | --- |
| RFC 9000 §18, §18.1 Reserved Transport Parameters, §18.2 | the `31 * N + 27` reserved form; every value definition; `active_connection_id_limit`'s two sentences | **yes** - `rfc9000-section18-transport-parameters.txt`, §18.1 at extract line 48 |
| RFC 9368 §3 (and the `version_information` parameter definition) | capture parameter 17, and the reserved-version form the unpublished GREASE version is drawn from | **no** |
| RFC 9221, the `max_datagram_frame_size` parameter definition only | capture parameter 32 - the *advertisement*, not the frame | **no**. §3 and §4, the frames, belong to C17 and are extracted there |
| RFC 9000 §14, §14.1 | B9's padding floor and the two routes §14.1 names | **yes** - `rfc9000-section14-datagram-size-and-pmtu.txt` |
| RFC 9000 §7.2, §7.3 | `initial_source_connection_id`'s meaning at zero length | **yes** - `rfc9000-section7-connection-id-negotiation.txt` |

**Two things have no RFC and must be recorded as such rather than cited.** `google_connection_options`
(12584) and `initial_rtt` (12583) are Google-private identifiers; the existing readout already says
so at `TlsQuicFingerprintReadout.cs:171-174`. Their only source is the capture. Write that down in
B1's defaults block instead of manufacturing a citation.

**Done when** every new extract diffs at zero mismatches against an independent re-fetch of the same
range; each carries a provenance header naming the exact subsections it covers; and the §18.1
reserved form is quoted in the plan record **from the extract**, so that B4's generator can be
checked by recomputation rather than against a table.

---

## Task B1: the transport-parameter spec seam

**Files:** create `TlsQuicTransportParameterSpec.cs` (or extend `TlsQuicConnectionSpec`), and tests.
No behaviour beyond composition.

Finding 1: nothing in `src/` composes a client parameter list. This task creates the one place that
does, and every later task writes into it.

Shape, following C1's precedent for the layer above:

- the parameter list **as an ordered sequence of identifier/value pairs**, not a set of named
  properties - Finding 2 makes order the fingerprint, and a named-property design cannot express it
- the six flow-control values continue to come from `TlsQuicLocalFlowControlSpec`, because RFC 9000
  §4.1 makes the advertised number and the enforced number the same number and
  `TlsQuicConnectionSpec.cs:690-700` records what happened last time they were typed twice. **This
  spec places them; it does not restate them.**
- `initial_source_connection_id` is derived from `SourceConnectionIdLength`, never typed
- ~~policy fields, not values, for the three randomised parameters: whether to emit a reserved
  parameter and where, whether to emit `version_information` and with what available list, and
  `InitialRttRange`'s existing null~~ **superseded - see the amendment below**

~~**A constant nobody can check is not allowed.** Where the capture bounds a default, take it and
cite the capture line. Where it does not - the reserved parameter's identifier, the GREASE version
inside `version_information`, `initial_rtt`'s bounds - the default is a **declared placeholder**, it
carries a doc comment naming it as one and naming the task that would settle it, and it goes in
B10's third column. This is A4 task 1's refusal and C1's restatement of it, applied a third time.~~

~~**Done when** the default spec composes a list whose identifiers and order are read back from
`TlsQuicTransportParameters.Parameters` rather than from the spec object; a test asserts the six
flow-control values in the composed list are the same objects `TlsQuicLocalFlowControlSpec` emits,
so a divergence is impossible rather than merely tested; every placeholder default carries the doc
comment above and a test asserts the comment's task reference resolves to a task in this document;
and a grep of the task's own diff finds no numeric parameter value outside the defaults block.~~

### Amendment: every varying field is a knob

**Recorded 2026-08-20 while implementing B1. This is the user's directive and it overrides the
struck text above. B2-B11 inherit the amended rule, not the original.**

> "no placeholder values, everything must be configurable if different clients/browsers/apps/systems
> could send a different value. don't forget the final goal of this library is to reproduce pretty
> much any fingerprint given, if the stack allows it."

The reconciliation, which is also the amendment to the standing rule at the end of this document:

- The standing rule *"a constant nobody can check is not allowed"* forbids **inventing a value and
  presenting it as known**. It has never forbidden **exposing a knob**. Those are different things
  and this project has been conflating them.
- **Every field a different client could vary is a settable knob.** None is refused, hard-coded or
  omitted because the capture cannot bound it. A parameter we decline to emit is a fingerprint too -
  an absence Chromium does not have - so refusing is not the safe choice it looks like.
- **Values live in a cited preset, not in library defaults.** Following
  `TlsQuicHttp3Spec.CaptureSettings`: a named `RfcMinimumParameters` preset carrying the capture's 14
  parameters in the capture's wire order, each citing its capture line. The type is constructible
  with an arbitrary list and bakes none of that client's numbers into per-property defaults.
- Where the capture cannot bound something - the reserved parameter's identifier, the GREASE version
  inside `version_information`, `initial_rtt`'s range - **the knob exists and is settable**, the
  preset's choice is marked **unverified** in its own doc comment naming the task that would settle
  it, and it goes in B10's third column. What is forbidden is refusing to emit it, or silently
  picking a number with no comment.

**The general goal is the design constraint.** The seam must express a parameter list SharpTls has
never seen: arbitrary identifiers including unknown, Google-private (12583, 12584) and reserved
ones; arbitrary bytes; arbitrary order; omission of anything. An enum-constrained or named-property
design cannot reproduce an arbitrary fingerprint and is the wrong answer. If a caller hands you a
list, you emit that list.

**Amended done-when.** The default spec composes a list whose identifiers and order are read back
from `TlsQuicTransportParameters.Parameters` rather than from the spec object; a test asserts the
six flow-control values in the composed list are the values `TlsQuicLocalFlowControlSpec` emits -
set to something other than the capture's, so a restatement fails rather than passing by
coincidence; **a caller can compose an arbitrary list - unknown identifier, arbitrary bytes,
arbitrary order - and the emitted bytes are that list, with a witness test, and this is the most
important clause**; every unverified preset choice carries a doc comment naming it unverified and
naming the task that would settle it, and a test asserts that task reference resolves to a task in
this document; a grep of the task's own diff finds no numeric parameter value outside the preset
block; nothing on these paths throws for any input, and validation rejects with a reachability
witness per rejecting branch.

**What B1 actually shipped, and what it takes off B2-B7's plates.** Because the amendment puts the
capture's fourteen values in one cited preset, B1 landed all fourteen rather than only the seam.
`src/SharpTls/Quic/TlsQuicTransportParameterSpec.cs` carries `RfcMinimumParameters` - 7 literal
entries and 7 `Placed` entries (the six flow-control identifiers plus
`initial_source_connection_id`), 7 + 7 = 14. So **B2, B3, B4, B5 and B7 no longer have to place
their values**; what remains of them is their traps, their per-connection draws, and their tests:

- **B2** keeps the `max_udp_payload_size` / `PaddingTarget` / transport-ceiling separation test and
  the C17 DATAGRAM comment. The four values are in the preset.
- **B3** keeps the per-connection GREASE-version draw. The `version_information` entry is in the
  preset with one unverified GREASE version, and the composed set already survives
  `Parse` + `ValidatePeer(Client)`, which was B3's free done-when.
- **B4** keeps the per-connection reserved-identifier draw. The preset carries one N, marked
  unverified, of RFC 9000 §18.1's `31 * N + 27` form and inside the interval the capture's
  "id ~ 3.7457e18" denotes - and the test asserts the *neighbouring* N is inside that interval too,
  so the plan cannot later be read as claiming the identifier was measured.
- **B5** keeps `initial_rtt`'s randomisation policy and `InitialRttRange`. The parameter now ships
  carrying the capture's one observed draw, marked unverified.
- **B6** is unchanged: `active_connection_id_limit` is simply not in the preset, so B6's removal is
  already the shipped default and B6 becomes the test that it stays absent.
- **B7** keeps the all-permutations anti-sort test. B1 already proves order reaches the wire across
  17 orderings (capture, sorted, reversed, and 14 rotations, of which the zero rotation repeats the
  capture's, so 17 orderings produce 16 distinct encodings).

**Where the seam lives.** `TlsQuicConnectionSpec.TransportParameters`, next to `LocalFlowControl`,
so one object carries both the six numbers and the order they go out in.
`Compose(connectionSpec, sourceConnectionId)` returns `TlsQuicTransportParameters`. Nothing reads it
yet - **B8** is the task that passes it to `ClientHelloBuilder.WithQuicTransportParameters`, and the
property's own doc comment says so.

---

## Task B2: the four parameters the capture publishes outright

**Files:** `TlsQuicTransportParameterSpec.cs`, and tests.
**Capture:** lines 79 (12584), 81 (32), 88 (1), 92 (3). **RFC:** 9000 §18.2 for 1 and 3; RFC 9221's
parameter definition for 32; **none exists for 12584** - B0 says so.

Add `google_connection_options` = `0x4f524947`, `max_datagram_frame_size` = 65536, `max_idle_timeout`
= 30000, `max_udp_payload_size` = 1472.

**Two traps, both already written down elsewhere and both re-stated at the emitting line.**

- `max_udp_payload_size` is an **advertised** value and is not `PaddingTarget` and is not the
  transport's ceiling. The capture: *"Advertised parameter and actual ceiling are separate concerns
  and must not be wired together."* A4's plan already required this comment
  (`2026-08-17-quic-a4-minimal-connection.md:382`) and `TlsQuicDatagramBuilder.cs:71-75` already
  declares its own copy of 65527 for the same reason. Three numbers, three meanings; do not alias
  any two.
- Parameter 32 promises RFC 9221 DATAGRAM support the codec does not have - Finding 11. The emitting
  line names task C17.

**Done when** each of the four round-trips through `TlsQuicTransportParameters.Encode` and `Parse` to
the same identifier and the same bytes; `12584`'s value decodes to the four ASCII characters the
capture names, checked by decoding rather than by comparing to the same hex literal twice; a test
asserts `max_udp_payload_size` and `PaddingTarget` can be set to different values and that changing
one changes no byte the other controls, with a witness per direction; and a mutant that sets
`max_udp_payload_size` from `PaddingTarget` is killed by that test rather than by inspection.

---

## Task B3: `version_information` (17)

**Files:** `TlsQuicTransportParameterSpec.cs`, and tests.
**Capture:** line 87 - *"chosen 1, available `[GREASE, 1]`"*. **RFC:** 9368 §3, extracted at B0.

Split from B2 because its value is only partly published: the chosen version is 1, the available
list's GREASE version is not published and the `perk` renders it as a bare token (Finding 3). That
GREASE version is a **per-connection draw** from RFC 9368's reserved-version form, and it is a
declared placeholder until B0's extract fixes the form.

`ValidateVersionInformation` already exists (`TlsQuicTransportParameters.cs:331`) and enforces the
length and structure rules - but Finding 2 shows it is reachable only through `ValidatePeer`, so it
has never seen a set we built.

**Done when** the emitted parameter survives a round trip through `Parse` **followed by
`ValidatePeer(TlsQuicEndpointRole.Client)`** - which is the first time our own composed set is put
through the validator that guards the peer's; the available-versions list preserves the capture's
ordering with a witness that reordering it changes the encoded bytes; two consecutive specs draw two
different GREASE versions, with the draw's form checked by recomputation against RFC 9368's rule
rather than against a table; and a mutant that emits the chosen version twice instead of chosen-plus-
available is killed - the length check alone does not catch it.

---

## Task B4: the reserved (GREASE) transport parameter

**Files:** `TlsQuicTransportParameterSpec.cs`, and tests.
**Capture:** line 80 (position 2 of 14, value `0xfb`), and line 107 - *"Two GREASE values appear…
Both are positional."*
**RFC:** 9000 §18.1, in the extract at line 48: identifiers of the form `31 * N + 27` are reserved
and *"have no semantics and can carry arbitrary values."*

The identifier is a per-connection draw and is a declared placeholder as to which N; the value
`0xfb` is published; the **position** is published and is the only part hashed (Finding 3). C3's
precedent applies directly: the reserved entry is an ordinary element of the ordered list, not a
flag plus an index, because a list already says both and a flag-plus-index is a second weaker way to
say the same thing that can disagree with the list.

**Done when** the generated identifier satisfies `(id - 27) mod 31 == 0` for a range of N **checked
by recomputation, not against a table**; two consecutive specs draw two different identifiers; the
drawn identifier never collides with a defined RFC 9000 §18.2 identifier or with 12583/12584, with a
witness at the boundary; the parameter's position in the encoded blob matches its index in the spec
list for at least three different indices, read back from `Parameters` rather than asserted from the
spec; and a mutant that appends the reserved parameter last regardless of its declared index is
killed - a done-when that only checks presence would pass it.

---

## Task B5: `initial_rtt` (12583) and its randomisation policy

**Files:** `TlsQuicTransportParameterSpec.cs`, `TlsQuicConnectionSpec.cs` (wiring `InitialRttRange`
to a consumer), and tests.
**Capture:** lines 96-99. **RFC:** none - Google-private, per B0.

Finding 7: the knob exists, is `null`, and has no consumer. This task gives it one.

**What this task does not do:** invent a range. A4 task 1 refused, the refusal is in the tree as a
null, and Finding 3 shows the gate does not need it. **What it takes to lift the placeholder is a
source**, and the capture names one: uQUIC's `ChromeRandomInitialRTT()`. Reading that function and
recording its bounds and distribution under `reference-captures/` is a B0-shaped acquisition task
and is **not in this phase** - it lands in B12's arm, alongside the packet capture, because both are
"go get an external source" rather than "go write code".

So B5 ships: the wiring, the per-connection draw, and a **declared placeholder** range whose doc
comment names `ChromeRandomInitialRTT()` as the thing that would settle it and B12 as the task.

**Done when** the parameter is emitted whenever `InitialRttRange` is non-null and **absent when it is
null**, with a witness per branch; two consecutive connections built from one spec emit two
different values, per A4's own instruction (`2026-08-17-quic-a4-minimal-connection.md:140` -
*"pin it: two consecutive connections must produce two different `initial_rtt` values"*); a spec
whose range has minimum equal to maximum emits that value and is accepted, so the degenerate case is
a decision rather than a crash; the emitted value lies inside the declared range for a large sample,
checked against the range object rather than against a literal; and a mutant that draws once and
caches is killed by the two-connections test - **a single-connection test would pass it, and a pinned
`initial_rtt` is the exact defect the capture warns about.**

---

## Task B6: stop sending `active_connection_id_limit` (0x0E)

**Files:** `TlsQuicTransportParameterSpec.cs`, `tests/SharpTls.Tests/Interop/QuicPublicEndpointInteropTests.cs`
and the other fixtures that compose it, and tests.
**RFC:** 9000 §18.2, extract lines 224-236, **both sentences, read past the wrap** - Finding 4.

Remove it from the composed list. Finding 4 shows the removal is inert on the wire (absent defaults
to 2, and we send 2) and inert in our code (`TlsQuicConnection` never reads it).

**This is the one task in this document that removes an advertisement**, and the reason it is safe is
a pair of RFC sentences rather than an absence of test failures. Write both sentences at the point of
removal, because "we stopped advertising something and nothing broke" is not evidence and will be
mistaken for evidence.

**Done when** the composed default list contains no identifier 0x0E, asserted from the encoded blob
rather than from the spec; `TlsQuicTransportParameters.GetIntegerOrDefault` returns 2 for the absent
parameter with a test naming the RFC sentence; a scripted peer that advertises a value below 2 is
still rejected with `TRANSPORT_PARAMETER_ERROR` - the *receiving* rule is untouched by this change
and a mutant that removes the receive-side check must be killed here; and the source records that
the day NEW_CONNECTION_ID is implemented, this decision is revisited, naming the RFC sentence that
makes it revisitable.

---

## Task B7: the wire order

**Files:** `TlsQuicTransportParameterSpec.cs`, and tests.
**Capture:** lines 72-92 (the fourteen, in order) and lines 53-55 - *"Both are published, so wire
order is fingerprinted and must be reproduced exactly."*

Last of the composition tasks, because it can only order parameters that exist. Finding 2 says the
encoder already preserves order, so this task is the ordered default and the tests that make sorting
detectable.

**Done when** the default spec's encoded blob parses back to fourteen parameters whose identifiers,
in order, equal the capture's table read from the extract file and not retyped into the test; the
rendered segment-3 string equals the capture's segment 3 **character for character**, with the three
tokenised fields substituted by the same rule the `perk` format uses (Finding 3); passing the same
fourteen parameters in **ascending identifier order** produces a *different* encoded blob, with a
witness - this is the property that makes sorting detectable and it is the one thing a
sorting-by-accident implementation would fail; **an all-permutations-of-a-three-element-prefix test
exists**, because C9's stated done-when was passed by a mutant that hard-coded the capture's order
and only an all-permutations test killed it; and the row count of the ordered list is derived from
the list rather than written beside it.

---

## Task B8: the h3 profile factory

**Files:** `src/SharpTls/ClientHello/` (a new QUIC profile factory), `CustomTlsQuicClientOptions.cs`,
and tests.
**RFC:** 9114 §3.2 (the ALPN token `h3`), already extracted as
`rfc9114-section3.2-connection-establishment.txt`.

Two facts force a **factory** rather than a profile.

- Transport parameters are baked into the immutable `ClientHelloProfile` via
  `ClientHelloBuilder.WithQuicTransportParameters` (`:340`), and
  `CustomTlsQuicClientOptions.Snapshot()` hard-rejects a profile without them
  (A4's plan, `:133`).
- Three parameters are per-connection draws - `initial_rtt` (B5), the reserved identifier (B4), the
  GREASE version (B3) - so A4's Finding 1 conclusion stands: **build a fresh `ClientHelloProfile`
  per connection, unconditionally.**

**Why B and not E, given Finding 9 assigns the profile's content to E.** The factory exists *because*
of the per-connection draws, which are B's; adding the ALPN token to a factory B is already forced to
write costs one string. Leaving it to E means every E caller can silently produce a non-h3 profile
and, as Finding 6 shows, **no test under `src/` would fail** - the 18 `WithAlpn("h3")` call sites are
all in `tests/`, each building its own profile inline. `TlsQuicHttp3Connection.cs:73` already made
this call; this task honours it in the narrow sense and Finding 9 states the wide sense it does not
extend to.

**Done when** the shipped factory produces a profile offering `h3`, asserted by decoding the ALPN
extension out of the **encoded ClientHello** rather than by reading the builder's input; two
successive calls produce two profiles whose transport-parameter blobs differ, with the differing
bytes traced to B3, B4 and B5's parameters individually and not merely to "some byte changed";
`grep -rn 'WithAlpn(' src/ --include=*.cs` now finds a real h3 profile and **the comments at
`TlsQuicHttp3Connection.cs:70` and `TlsQuicHttp3FingerprintReadout.cs:95` are corrected rather than
left as Finding 6 describes them**; and the readout's ALPN row (`:750-754`) moves out of the third
column with its verdict derived from the encoded ClientHello.

---

## Task B9: the Initial flight plan the post-quantum key share forces

**Files:** `TlsQuicConnectionSpec.cs` (defaults only), the QUIC profile factory from B8, and tests.
**RFC:** 9000 §14.1 (extract lines 65-68, the expansion MUST and its two routes), §12.2.
**Capture:** lines 124-129 (the 1216-byte share and the two-datagram Initial), and lines 30-33 (what
the service does **not** inspect).

Finding 5. The builder can produce a two-datagram Initial; the defaults produce one oversized
datagram; nothing throws.

Three things, in order.

1. **Establish the size.** A test asserts `X25519MlKem768KeyShare.ClientShareSize` equals the
   capture's stated 1216 - the constant is a sum of two named constants in the source
   (`X25519MlKem768KeyShare.cs:9`), so this is a genuine cross-check between the tree and the capture
   and not a restatement of either.
2. **Declare the split.** Set `InitialCryptoFrameByteCounts` and `InitialCryptoFramesPerDatagram` on
   the QUIC profile's spec so a Chrome-sized ClientHello lands in more than one datagram, each within
   the path MTU the capture's `max_udp_payload_size` names.
3. **Say the split point is UNVERIFIED.** Capture lines 30-33 put *"per-datagram Initial flight
   plans, CRYPTO frame splitting"* among what neither verification endpoint observes. **The exact
   boundary is unknowable from this capture** and is settled only by B12. uQUIC's
   `InitialPackets []InitialPacketPlan` is named in the capture as the model; it is a source to
   acquire, not a value to guess.

   ~~**and is a declared placeholder**~~ - SUPERSEDED by the B1 amendment, which strikes the
   "declared placeholder" remedy: *"The rule survives; the 'declared placeholder' remedy does not."*
   The split is a **settable knob** shipping a cited preset whose boundary is marked UNVERIFIED and
   names B12. Refusing to split is not an option.

**Done when** a ClientHello built by the B8 factory with the capture's key shares produces **more than
one** Initial datagram, counted from `BuildInitialFlight`'s returned list; **every** datagram in that
flight is at least §14.1's floor and at most the advertised `max_udp_payload_size`, checked per
datagram and not per flight - §14.1's rule is per datagram and the builder's own summary says so; a
spec with the split removed produces exactly one datagram exceeding that ceiling and **a test asserts
that this is what happens**, so Finding 5's silent failure is pinned rather than fixed-and-forgotten;
the CRYPTO stream offsets across the frames are contiguous from 0 and reassemble to the original
ClientHello byte-for-byte, read back through the frame parser; and the split point's doc comment
names it UNVERIFIED and names B12.

**AMENDED BY B9 AS BUILT (`3a7852f`), from three things the task text got wrong:**

- **"Set the two arrays on the QUIC profile's spec" is not implementable as written.**
  `InitialCryptoFrameByteCounts` and `InitialCryptoFramesPerDatagram` are **absolute** byte counts,
  and no spec is constructed knowing the ClientHello's length. A literal preset fits exactly one
  ClientHello and throws from `SplitIntoFrames` for the next. It therefore ships as a **budget plus
  a planner** (`PlanInitialFlightSplit`), and `TlsQuicConnectionSpec.cs` needed **no change at all**.
- **Finding 5's line numbers are off by one** - it cites `:355` and `:390`; at `f83331f` the
  properties are at `:356` and `:391` (those lines are closing doc tags).
- **STILL OPEN, and B13's natural home:** a live `TlsQuicConnection` still receives the empty
  defaults unless its caller builds the spec from `PlanInitialFlightSplit`. Auto-splitting inside
  `PlanInitialCryptoFrames` needs either a new spec knob or a `TlsQuicConnection.cs` change, both
  outside B9's file scope. Documented on the factory's `ConnectionSpec`. **Until it is wired, the
  split is available but not automatic.**

---

## Task B10: the fingerprint readout, segment 3

**Files:** `TlsQuicHttp3FingerprintReadout.cs`, `TlsQuicFingerprintReadout.cs`, and their snapshots.
**Model:** the existing readouts and `tests/SharpTls.Tests/Quic/quic-http3-fingerprint-readout.snapshot.txt`.

Extend the HTTP/3 readout to render `perk` segment 3 in full, from the transport parameters actually
encoded into the ClientHello we emitted, with the same three-valued verdict column.

The rows, and the count is the length of this list: one per capture parameter (**14**, counted from
the capture's table with `grep -cE '^\| [0-9]+ \|'` over lines 78-93, which returns 14), plus the
whole-segment string, plus one row reporting **parameters we send that the capture does not** so that
B6's removal cannot silently regress. **16.**

The rows whose verdict is `not-yet-known-from-the-capture`, taken from the findings and counted from
this sentence's list: the reserved parameter's identifier; the GREASE version inside
`version_information`; `initial_rtt`'s bounds and distribution; and the Initial flight split point.
**Four.**

The rows this readout **must not** report as not-yet-known, because the capture publishes them
affirmatively: the four values in B2, the fourteen identifiers, and the wire order itself.

**Done when** every rendered value is derived from the **encoded ClientHello bytes** and not from the
spec object, with a test in the shape of task 11's `TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith`
proving it cannot be a restatement; every row's verdict is one of the three values; the row count and
the verdict counts are derived from the rendered list and their arithmetic line still reconciles, as
Finding 10 requires; the segment-3 string is diffed character for character against the capture's;
the existing row 25 (CID pair) is rendered for the **shipped default** as well as the harness's
deliberate 5, so Finding 10's harness artifact stops reading as a mismatch **without any default
changing**; and the ALPN row is re-derived from `grep -rn 'WithAlpn('` rather than from
`grep -rn '"h3"'` - Finding 6.

---

## Task B11: the live run

**Files:** extend `tests/SharpTls.Tests/Interop/QuicPublicEndpointInteropTests.cs`.
`SHARPTLS_RUN_INTEROP=1`-gated, never in the gate.

`https://fp.impersonate.pro/api/http3`, with the B8 factory rather than the fixture's hand-composed
list. The fixture at `:304-312` is what Finding 1 is about; this task is where it stops being the
source of truth.

**One probe this run must include, because it is self-validating.** Emit the fourteen parameters
**sorted by identifier** on one attempt and in the capture's order on another. The capture publishes
both `perk_hash` and `perk_hash_normalized`, so the sorted attempt must change the first and leave
the second unchanged. **If it does not, the service is not reading order the way the capture says it
is**, and every claim in B7 rests on that sentence.

**Expect loss.** A3 is deferred; a single lost packet ends the attempt, and B9 doubles the Initial
datagrams that must survive. A4 task 13 measured 0/10 attempts lost with a one-datagram Initial
(handoff dependency chain); this re-measures with two.

**Done when** the returned `perk`, `perk_hash` and `perk_hash_normalized` are recorded verbatim into a
new file under `reference-captures/` alongside a client capture; segment 3 matches the capture's
character for character; the sorted-order probe changes `perk_hash` and not `perk_hash_normalized`,
recorded either way; the attempt count and datagram-loss rate are recorded with the Initial datagram
count stated; and the two segments B does **not** own - h3 SETTINGS and pseudo-header order - are
reported as C's, not re-filed as B's, exactly as C13 was told not to re-file B's.

---

## The packet-capture arm - only a real capture settles these

Capture lines 30-33 name six things `fp.impersonate.pro` does not inspect. Finding 8 shows seven of
the eight parent-scoping B knobs already exist for them. **What is missing is not code. It is a
source.** These two tasks exist because a knob with no source is where a plausible number gets
invented, and this project has already refused that once.

### Task B12: acquire the capture

**Files:** new files under `docs/superpowers/specs/reference-captures/`.

A packet capture of a captured client / Chromium 151's opening flight, plus - separately - a reading of
uQUIC's `ChromeRandomInitialRTT()` and `InitialPacketPlan`, both named by the capture as models.

**Done when** each recorded artefact carries a provenance header naming what produced it, when, and
what it does and does not settle; the Initial packet number, its encoded length, the token, the frame
order within the Initial, the padding target and the per-datagram split are each either recorded with
a value or **explicitly recorded as still unsettled**; and no value appears without one of those two
labels.

### Task B13: set the knobs from it

**Files:** `TlsQuicConnectionSpec.cs` defaults, `TlsQuicFingerprintReadout.cs` and its snapshot.
**Knobs, from Finding 8's table:** `InitialPacketNumber` `:248`, `PacketNumberEncodedLength` `:274`,
`Token` `:303`, `InitialFrameOrder` `:432`, `PaddingTarget` `:323`, plus B9's split and B5's range.

**Done when** every default set here cites the B12 artefact by line; every default *not* set here
remains a declared placeholder in the readout's third column with its own reason; the readout's
not-yet-known count **falls** by exactly the number of knobs B12 settled, with the arithmetic shown;
and the report states plainly that this arm's evidence is a capture we took, not an endpoint's
verdict.

---

## Ordering constraint

Each arrow is a hard prerequisite, and the reason is stated.

```
B0  extracts                     RFC 9368 and RFC 9221's parameter are absent; a citation
                                 with no in-repo extract is not checkable
  -> B1  the spec seam           Finding 1: nothing in src/ composes a list, and every
                                 later task writes into it
  -> B2  the four published      values need only the seam and the extract
  -> B3  version_information     needs RFC 9368's reserved-version form, which B0 fetches
  -> B4  the GREASE parameter    needs s18.1's 31*N+27 and needs B1's list to hold a position
  -> B5  initial_rtt             needs B1; its RANGE needs B12 and does not block
  -> B6  drop 0x0E               after B1, so the removal is from a composed list and not
                                 from a fixture that will be rewritten anyway
  -> B7  wire order              LAST of the composition tasks: it can only order
                                 parameters that already exist
  -> B8  the h3 profile factory  after B3, B4 and B5, because the factory exists to redraw
                                 exactly what those three randomise
  -> B9  the Initial flight plan after B8, because the 1216-byte key share arrives with
                                 the profile and not before it
  -> B10 the readout             after B7 and B9: a readout of bytes not yet emitted is a
                                 restatement of the spec, which is the failure task 11's
                                 TheQuicBlockIsUnchangedByTheSpecItIsRenderedWith prevents
  -> B11 the live run            last; the only task needing a network
```

`B12 -> B13` after B11, and B12 also retro-settles B5's range and B9's split point - which is why
both are written as placeholders that a later task lifts rather than as gaps that block.

**The single riskiest ordering assumption**, stated as A4's and C's plans state their own: **that B7
can be reached with B5's range still a placeholder.** Finding 3 is the whole argument - the `perk`
renders `12583:AUTO`, so the hash sees position and not value. If that reading is wrong, B5 becomes a
hard prerequisite of B7 and cannot be completed without B12, and the 12-task answer becomes a
14-task answer with an external dependency in the middle of it. **The mitigation is cheap and belongs
in B11: the sorted-order probe already round-trips a modified list past the service, and one attempt
with a deliberately different `initial_rtt` value settles whether the hash moves.** Do it in the same
run.

---

## The estimate and its uncertainty

**12 tasks to move `perk_hash`. 14 with the packet-capture arm.** Each figure is the length of a list
in this document: B0-B10 is 11, B11 is 1, B12-B13 is 2. 11 + 1 = 12; 12 + 2 = 14.

Four things drive the range, and only the first can be wrong without anything failing.

1. **The Initial flight plan - the widest term, and the one with no verdict available.** Finding 5:
   the split is caller-declared, the default is one datagram, the flight buffer is 65527 and not a
   path MTU, and the builder's overshoot is deliberate and documented. So a wrong split does not
   throw, does not fail a test, and is invisible to `fp.impersonate.pro` by the capture's own lines
   30-33. **What would measure it: a packet capture of Chromium's opening flight - task B12. Nothing
   else does.** Not the endpoint, not a test, not another RFC.
2. **Whether the service reads order the way the capture says.** Both hashes are published, which is
   strong, but whether the renderer strips a zero-length value or an unknown identifier is not
   stated anywhere. One probe settles it and it is already inside B11's done-when. If it does not
   behave as documented, B7's done-when needs rewriting and B10's segment-3 diff needs a different
   comparand - roughly one extra task.
3. **Whether a two-datagram Initial with a 1216-byte key share reaches this endpoint at all.** A4
   task 13 measured 0/10 attempts lost against a one-datagram Initial. B9 doubles the packets that
   must survive with A3 still deferred. If it does not complete often enough to be useful, A3 enters
   the chain ahead of B11 and the answer grows by the parent scoping's items 13-18.
4. **Whether B8's factory is a shape change to `CustomTlsQuicClientOptions`.** The profile is
   immutable and `Snapshot()` hard-rejects one without transport parameters, so "a fresh profile per
   connection" is a change to how the options type is *consumed*, not to a value inside it. A4's own
   history says the honest expectation is a fix round. If B8 splits, the number is 13 rather than 12.

**What would narrow the range fastest, in order:** run B11's sorted-order probe as soon as anything
can reach the endpoint - it needs almost no B code and it settles 2 and the riskiest ordering
assumption together; then B12, which settles 1 and retro-lifts two placeholders; then attempt B9's
two-datagram flight against the endpoint, which settles 3.

No date is offered. The parent scoping's "8 to 10 tasks" for B was an estimate over an
unenumerated list; this is 12 over an enumerated one, and every figure in this project that was
asserted rather than derived has moved at least once.

---

## What B does not own, and must not be blamed for

| Not B's | Whose | Why it will look like B's |
| --- | --- | --- |
| `perk` segment 1, the h3 SETTINGS | **C** | `TlsQuicHttp3Spec.CaptureSettings` (`:142-149`) is already the default and already emits all five of that client's pairs. It is not *usable live* until C14-C16, and that is a QPACK dependency, not a fingerprint one |
| `perk` segment 2, pseudo-header order | **C** | already an exact match, confirmed live against a server we do not control |
| `perk` segment 4, the CID pair | **already correct** | `_sourceConnectionIdLength` defaults to 0 and `_destinationConnectionIdLength` to the §7.2 floor (Finding 8); the live run returned `0,8`. The readout's `5,8` is its harness - Finding 10 |
| RFC 9221 DATAGRAM frames | **C17** | B2 advertises `max_datagram_frame_size`; C17 makes the advertisement honest - Finding 11 |
| The capture's TLS half: suites, extension wire order, groups, key shares, ECH, ALPS | **E** | it is in the same capture and the same `perk`-adjacent JA3, but the seam is `ClientHelloProfile` and it already exists with 25 profiles in it - Finding 9. Extension 57's **body** is B's; its **position** is E's |
| Publicising the spec types | **E** | `grep -nE '(public\|internal) (sealed )?(class\|record\|enum) ' src/SharpTls/Quic/TlsQuicConnectionSpec.cs` returns 3 declarations and **all 3 are `internal`**. Every knob B sets is reachable only from this assembly and its tests. That is enough for B's gate and not enough for a library |
| Retransmission of a lost Initial datagram | **A3** | B9 doubles the Initial datagrams; a loss will present as B9 being wrong |
| RFC 9218 priority, `h3PriorityParam` | **E** | the capture's `perk` does not carry it, so there is nothing to match against yet |

---

## Not in this phase

Each cut names where it lands, per A4's practice.

| Cut | Lands in | What the cut costs |
| --- | --- | --- |
| Reading uQUIC's `ChromeRandomInitialRTT()` for a real range | **B12** | B5 ships a declared placeholder. Finding 3 says the `perk` gate does not see it; a packet-capture diff does |
| Acting on `version_information` - RFC 9368's compatible version negotiation | **never, or A-complete** | we advertise a version list and do not negotiate over it. A server that offers a compatible version gets no response. Recognising that this is a cut is the point |
| Implementing NEW_CONNECTION_ID so `active_connection_id_limit` means something | **A4-complete** | B6 removes an advertisement that is currently inert; the day the frame exists, the removal is revisited. The source says so at the removal |
| A public spec surface | **E** | see the ownership table |
| Profile rolling and cross-browser randomisation | **E** | `ClientHelloProfileRandomizer.cs` and `ClientHelloProfileRoller.cs` already exist; B ships one profile matching one capture |
| Matching a second browser's transport parameters | **later B, or never** | one capture, one target. The capture's Firefox note (lines 26-28: three separate CID-length fingerprints) is a hint that this generalises, not a requirement that it does |
| Sending QUIC DATAGRAM frames | **never** | RFC 9297 §2.1.1 forbids it until the setting is sent *and* received as 1; we only advertise |

---

## Standing rules carried in

The eighteen from `2026-08-17-quic-a2-frame-layer.md`, plus A4's amendments and C's additions,
transfer whole. The six that bite hardest here:

- **Point at the extract; never restate a field layout or a constant in a plan or a prompt.** This
  document quotes no wire diagram and no field layout. The three RFC sentences it does quote are
  quoted because a task's correctness turns on reading them past their line wrap.
- **The extracts are hard-wrapped at ~72 columns.** Finding 4 turns entirely on the second sentence
  of a §18.2 entry, past the wrap. Four separate misreads in this project came from stopping at one.
- **Never write a count you cannot recompute from a list.** Every figure here names the grep or the
  list that produces it: 14 capture parameters, 8 we send, 7 shared, 7 missing, 4 hashed and 3
  tokenised, 17 public spec members, 8 parent-scoping B items of which 7 exist, 25 readout rows as
  15 + 2 + 8, 25 `WithAlpn(` lines in `src/` of which 1 mentions h3 and that one is a comment, 18
  `WithAlpn("h3")` in `tests/`, 20 frame types, 3 internal type declarations, 12 / 14 tasks.
- **A constant nobody can check is not allowed.** ~~Where the capture does not bound something - the
  reserved identifier, the GREASE version, `initial_rtt`'s range, the Initial split point - the
  default is a declared placeholder and it goes in B10's third column. A4 task 1 refused to invent a
  range for `initial_rtt`; that refusal is in the tree as `InitialRttRange = null` and it stays.~~
  **AMENDED 2026-08-20 during B1, by the user's directive - see "Amendment: every varying field is a
  knob" below.** The rule survives; the "declared placeholder" remedy does not. The rule forbids
  *presenting an invented value as measured*. It has never forbidden *exposing a knob*, and this
  project has been conflating the two. **Where the capture cannot bound something, the knob still
  exists, is settable, and is emitted**; the preset's choice for it is marked unverified in its own
  doc comment, names the task that would settle it, and goes in B10's third column. What is
  forbidden is refusing to emit the parameter, or picking a number with no comment. A4 task 1's
  `InitialRttRange = null` still stands, because a *range* nobody measured is still not a range -
  but the *parameter* ships, carrying the capture's one observed draw, marked unverified.
- **A done-when clause is a floor, not a ceiling.** A mutant that hard-coded the capture's
  pseudo-header order passed C9's stated done-when. B7's clause therefore requires an
  all-permutations test and B5's requires two connections, because the obvious wrong implementation
  of each - a hard-coded order, a cached draw - passes any weaker clause.
- **A surviving mutation is unwitnessed, unreachable by construction, or vacuous - say which.**

And three this phase adds:

- **A grep quoted in a comment becomes a witness of itself.** Finding 6: `grep -rn '"h3"' src/`
  returned nothing, three comments recorded that it returned nothing, and it now returns those
  comments. Cite the grep; do not paste its result into the tree it searches.
- **A knob that exists is not a knob that is wired.** `InitialRttRange` and `AckRangeLimit` are both
  present-but-inert and the source says so in its own words - *"a knob that accepts a value and
  ignores it is worse than an absent one."* Before scoping a knob as done, grep for its consumer.
- **A default that cannot throw is the most dangerous kind.** Finding 5's overshoot is deliberate,
  documented and correct, and it is also the mechanism by which a wrong Initial flight ships
  silently. When a plan says a capability exists, go read what its default does.
