# B12: what the Chromium packet capture must contain

Status: **request for an external input.** Nothing in this repo can produce it.
Parent: `plans/2026-08-20-quic-b-fingerprint-spec-scoping.md`, tasks B12 and B13.

## Why it is needed

Three values are currently marked UNVERIFIED in the tree, and **all three are settled by one
capture.** Each is a value a real Chromium draws or chooses that no public document states and that
neither verification endpoint observes.

| Unverified thing | Where it lives now | Why nothing else settles it |
| --- | --- | --- |
| `initial_rtt` (12583) **range width** | `Brave151InitialRttRange`, marked `UNVERIFIED, settled by task B12` | The capture publishes exactly one draw, 192859 us. One sample bounds nothing. Task 1 refused to invent a range and that refusal stands. **The uQUIC shortcut was tried at `5c0039c` and failed - see below.** |
| Reserved (GREASE) parameter's **N** in `31 * N + 27` | `Brave151ReservedIdentifierN`, kept as evidence only | The `perk` string hashes the parameter's POSITION, not its identifier - measured at `4ed90bf` - so the endpoint cannot reveal N. |
| **Initial flight split point** | B9's `[1400, 112]` budget, `3a7852f` | Capture lines 30-33: `fp.impersonate.pro` does not inspect per-datagram Initial flight plans or CRYPTO frame splitting. **No live run will ever catch a wrong split.** 1400 is `1472 - 43` rounded down for headroom - a headroom calculation, not a measurement. One-frame-per-datagram is part of the same guess. |

## What to capture

**A packet capture of Brave (or Chromium) opening an HTTP/3 connection**, from the very first
datagram. The opening Initial flight is the subject; the rest of the connection is not needed.

Any h3 origin works. `https://fp.impersonate.pro/api/http3` is convenient because the same host is
already the project's reference endpoint, but `google.com` or `cloudflare.com` are equally valid and
avoid mixing this measurement with the fingerprint runs.

### Procedure

1. Close all running Brave/Chrome instances, so the capture is not polluted by existing connections.
2. Start the capture **before** launching the browser, filtered to UDP port 443 - the Initial flight
   is the first thing on the wire and cannot be recovered afterwards.
   - Wireshark: capture filter `udp port 443`, display filter `quic`.
   - Or `tshark -i <iface> -f "udp port 443" -w chromium-initial.pcapng`.
3. Launch the browser and visit the origin **once**. Stop the capture.
4. Repeat the whole procedure **at least 10 times, as 10 separate connections**, ideally more.
   *The repetition is the point for two of the three values* - one connection bounds neither the
   `initial_rtt` range nor whether N varies.

**Wireshark decrypts QUIC Initial packets natively** - their keys derive from the Destination
Connection ID, which is in the clear - so no key log is required for the Initial flight. If you also
want the handshake and 1-RTT contents, set `SSLKEYLOGFILE` before launching the browser and point
Wireshark at the file, but that is not needed for B12.

## What to record from it

Per connection:

1. **Every datagram in the Initial flight, with its exact byte count**, in order. This settles the
   split point. Note especially whether the flight is 2 datagrams or more, and whether the last one
   is padded.
2. **The CRYPTO frames inside each Initial datagram** - how many per datagram, and each one's Offset
   and Length. This settles one-frame-per-datagram, which is currently a guess.
3. **The `initial_rtt` (12583) value** from the client's transport parameters.
4. **The reserved transport parameter's identifier**, and its position in the wire order.

Across the 10+ connections:

5. Whether `initial_rtt` **varies**, and its observed minimum and maximum.
6. Whether the reserved identifier's **N varies**, and its observed range.
7. Whether the **wire order** of transport parameters is stable across connections. The repo assumes
   it is; that assumption has never been tested against more than one capture.

## The uQUIC shortcut was tried and it FAILED - the capture is needed for all three

This section previously said that reading uQUIC's `ChromeRandomInitialRTT()` would settle
`initial_rtt` without a packet capture. **That was tried at `5c0039c` and it does not.** The source
is captured verbatim at `reference-captures/uquic-u_parrot-chrome-random-initial-rtt.txt`
(`refraction-networking/uquic`, `u_parrot.go`, master `837c7ce1`, not in any released tag).

It draws **uniformly over [1000, 20000) microseconds**. The Brave capture's observed 192859 is
**outside that range by 9.6x**, and three readings say so independently:

1. 192859 > 20000 outright.
2. The function emits a **2-byte varint**, whose maximum is 16383. 192859 requires a 4-byte varint.
   **Brave's wire encoding is not this encoding**, whatever the values.
3. uQUIC's own numbers do not close: `maxRTT` 20000 exceeds what a 2-byte varint holds, so its draws
   in [16384, 19999] silently lose their overflow bits. Its effective on-wire distribution is not its
   documented one. That is a defect in uQUIC, noted here only because it means the function cannot be
   treated as an authority even on its own terms.

**Two real-world draws now exist and they are 25x apart** - uQUIC's own doc comment records 7740 us,
and the Brave capture records 192859 us. Both are plausible *measured* RTTs. The simplest reading
consistent with both is that **Chromium reports a path-derived estimate rather than a random draw**,
in which case there is no distribution to copy and a "range" is the wrong model entirely. That is
inference from two points and is flagged as such in the capture.

**Consequence for the capture request above: it is needed for all three values, not two.** And if the
10+ connections show `initial_rtt` correlating with network path rather than varying randomly, the
knob's shape changes - from a range to draw from, to a value the caller supplies or the stack derives.
Record the RTT to the origin alongside each connection so that correlation is checkable.

## What lands afterwards - B13

- Replace the three UNVERIFIED markers with cited values, or record measured ranges where the values
  turn out to vary.
- **Wire the split so it is automatic.** B9 shipped the mechanism and said plainly that it is not on
  the live path: a `TlsQuicConnection` still receives the empty defaults unless its caller builds the
  spec from `PlanInitialFlightSplit`. Auto-splitting inside `PlanInitialCryptoFrames` needs either a
  new spec knob or a `TlsQuicConnection.cs` change, both outside B9's file scope.
- Re-run B10's readout and B11's live run; the two `not-yet-known-from-the-capture` rows should move.

**Per the user's standing directive, none of these becomes a hard-coded constant.** Each stays a
settable knob whose preset value is then cited to this capture instead of marked UNVERIFIED.
