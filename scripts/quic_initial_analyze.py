"""Decrypt QUIC Initial packets from a pcap and report the client's opening-flight shape.

Initial packets need no keylog: RFC 9001 s5.2 derives their secrets from the clear-text
Destination Connection ID. That settles the knobs mitmproxy cannot see, because mitm
terminates QUIC and never shows you the client's own datagrams:

    InitialCryptoFrameByteCounts / InitialCryptoFramesPerDatagram
    InitialFrameOrder, AckLeadsInPacket, CoalesceAscendingByLevel
    HeaderLength / CryptoOffset / CryptoLength varint widths
    Source/DestinationConnectionIdLength, PaddingTarget, Token, PacketNumberEncodedLength

Reads the captures scripts/quic_pcap.py writes, or a native pcapng from a real
capture. The native one remains ground truth for MTU-sensitive attributes: the
proxy-side capture arrives after WireGuard decryption, and the tunnel's MTU sits
under the client's path MTU.

Run:
    python scripts/quic_initial_analyze.py scripts/captures/<file>.pcap
    python scripts/quic_initial_analyze.py capture.pcapng --sni=spotify.com
    python scripts/quic_initial_analyze.py --selfcheck
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# RFC 9001 s5.2 (v1) and RFC 9369 s3.3.1 (v2).
SALTS = {
    0x00000001: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0x6B3343CF: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
FRAME_NAMES = {
    0x00: "PADDING",
    0x01: "PING",
    0x02: "ACK",
    0x03: "ACK_ECN",
    0x06: "CRYPTO",
    0x1C: "CONNECTION_CLOSE",
}


def is_grease(v: int) -> bool:
    """GREASE values are 0x0a0a, 0x1a1a, ... 0xfafa (RFC 8701)."""
    return (v & 0x0F0F) == 0x0A0A and ((v >> 8) & 0xFF) == (v & 0xFF)


def varint(b: bytes, i: int) -> tuple[int, int, int]:
    """RFC 9000 s16. Returns (value, next_index, encoded_width)."""
    width = 1 << (b[i] >> 6)
    val = b[i] & 0x3F
    for k in range(1, width):
        val = (val << 8) | b[i + k]
    return val, i + width, width


def hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def initial_keys(dcid: bytes, version: int) -> tuple[bytes, bytes, bytes]:
    salt = SALTS.get(version, SALTS[0x00000001])
    # HKDF-Extract only. The HKDF class does extract+expand, which is a different value.
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(dcid)
    secret = h.finalize()
    client = hkdf_expand_label(secret, "client in", 32)
    if version == 0x6B3343CF:
        return (
            hkdf_expand_label(client, "quicv2 key", 16),
            hkdf_expand_label(client, "quicv2 iv", 12),
            hkdf_expand_label(client, "quicv2 hp", 16),
        )
    return (
        hkdf_expand_label(client, "quic key", 16),
        hkdf_expand_label(client, "quic iv", 12),
        hkdf_expand_label(client, "quic hp", 16),
    )


@dataclass
class Packet:
    kind: str
    version: int
    dcid: bytes
    scid: bytes
    token: bytes
    length_varint_width: int
    packet_number: int
    pn_length: int
    wire_size: int
    frames: list = field(default_factory=list)
    crypto: list = field(default_factory=list)  # (offset, data, offset_width, length_width)


def parse_frames(pt: bytes, pkt: Packet) -> None:
    i = 0
    while i < len(pt):
        ftype, i, _ = varint(pt, i)
        name = FRAME_NAMES.get(ftype, "0x%02x" % ftype)
        if ftype == 0x00:  # collapse PADDING runs
            n = 1
            while i < len(pt) and pt[i] == 0:
                i += 1
                n += 1
            pkt.frames.append("PADDING x%d" % n)
            continue
        if ftype == 0x06:  # CRYPTO
            off, i, ow = varint(pt, i)
            ln, i, lw = varint(pt, i)
            pkt.crypto.append((off, pt[i : i + ln], ow, lw))
            pkt.frames.append("CRYPTO(off=%d,len=%d)" % (off, ln))
            i += ln
            continue
        if ftype in (0x02, 0x03):  # ACK
            _, i, _ = varint(pt, i)  # largest acknowledged
            _, i, _ = varint(pt, i)  # ack delay
            count, i, _ = varint(pt, i)
            _, i, _ = varint(pt, i)  # first ack range
            for _ in range(count):
                _, i, _ = varint(pt, i)
                _, i, _ = varint(pt, i)
            if ftype == 0x03:
                for _ in range(3):
                    _, i, _ = varint(pt, i)
            pkt.frames.append(name)
            continue
        pkt.frames.append(name)
        if ftype == 0x01:  # PING carries no payload
            continue
        break  # unknown frame: stop rather than guess a length


def decode_datagram(raw: bytes, original_dcid: bytes | None = None) -> list[Packet]:
    """Walk the coalesced packets in one datagram. Only Initials are decryptable here.

    `original_dcid` is the DCID of the client's FIRST Initial. RFC 9001 s5.2 pins the
    Initial secrets to it for the whole connection - the client switches DCID to the
    server's chosen CID once the server replies, but the keys do not follow.
    """
    out, i = [], 0
    while i < len(raw) and raw[i] & 0x80:  # long header
        try:
            i = _decode_long_header(raw, i, original_dcid, out)
        except (IndexError, ValueError, KeyError):
            # Truncated by a capture snaplen, or not QUIC at all. Either way, stop here
            # rather than report numbers derived from bytes that were never captured.
            out.append(Packet("malformed", 0, b"", b"", b"", 0, -1, 0, len(raw) - i))
            return out
        if i is None:
            break
    if i is not None and i < len(raw):
        out.append(Packet("1-RTT/short", 0, b"", b"", b"", 0, -1, 0, len(raw) - i))
    return out


def _decode_long_header(raw: bytes, i: int, original_dcid: bytes | None, out: list) -> int | None:
    """Decode one long-header packet at `i`. Returns the next index, or None to stop."""
    if len(raw) - i >= 7:  # first byte + version + the two connection-id length octets
        start = i
        first = raw[i]
        version = int.from_bytes(raw[i + 1 : i + 5], "big")
        if version == 0:
            out.append(Packet("VersionNegotiation", 0, b"", b"", b"", 0, -1, 0, len(raw) - start))
            return None
        j = i + 5
        dcl = raw[j]
        j += 1
        dcid = raw[j : j + dcl]
        j += dcl
        scl = raw[j]
        j += 1
        scid = raw[j : j + scl]
        j += scl
        ptype = (first & 0x30) >> 4
        kind = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}[ptype]
        token = b""
        if ptype == 0:
            tl, j, _ = varint(raw, j)
            token = raw[j : j + tl]
            j += tl
        if ptype == 3:
            out.append(Packet(kind, version, dcid, scid, token, 0, -1, 0, len(raw) - start))
            return None
        length, j, lw = varint(raw, j)
        pn_offset = j
        body_end = pn_offset + length
        if body_end > len(raw):
            raise IndexError("packet length %d runs past the captured %d bytes"
                             % (body_end, len(raw)))
        pkt = Packet(kind, version, dcid, scid, token, lw, -1, 0, body_end - start)

        if ptype == 0:
            key, iv, hp = initial_keys(original_dcid or dcid, version)
            sample = raw[pn_offset + 4 : pn_offset + 20]
            enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
            mask = enc.update(sample) + enc.finalize()
            f0 = first ^ (mask[0] & 0x0F)
            pnl = (f0 & 0x03) + 1
            pn_bytes = bytes(
                a ^ b for a, b in zip(raw[pn_offset : pn_offset + pnl], mask[1 : 1 + pnl])
            )
            pn = int.from_bytes(pn_bytes, "big")
            header = bytearray(raw[start : pn_offset + pnl])
            header[0] = f0
            header[pn_offset - start :] = pn_bytes
            nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
            ct = raw[pn_offset + pnl : body_end]
            try:
                pt = AESGCM(key).decrypt(nonce, ct, bytes(header))
                pkt.packet_number, pkt.pn_length = pn, pnl
                parse_frames(pt, pkt)
            except Exception as exc:  # noqa: BLE001
                pkt.frames.append("<undecryptable: %s>" % exc.__class__.__name__)
        out.append(pkt)
        return body_end
    return None


# --- ClientHello ----------------------------------------------------------------

TP_NAMES = {
    0x00: "original_destination_connection_id",
    0x01: "max_idle_timeout",
    0x02: "stateless_reset_token",
    0x03: "max_udp_payload_size",
    0x04: "initial_max_data",
    0x05: "initial_max_stream_data_bidi_local",
    0x06: "initial_max_stream_data_bidi_remote",
    0x07: "initial_max_stream_data_uni",
    0x08: "initial_max_streams_bidi",
    0x09: "initial_max_streams_uni",
    0x0A: "ack_delay_exponent",
    0x0B: "max_ack_delay",
    0x0C: "disable_active_migration",
    0x0D: "preferred_address",
    0x0E: "active_connection_id_limit",
    0x0F: "initial_source_connection_id",
    0x10: "retry_source_connection_id",
    0x11: "version_information",
    0x20: "max_datagram_frame_size",
    0x3127: "google_quic_version",
    0x3129: "initial_rtt",
    0x4752: "google_connection_options",
}


def parse_transport_parameters(b: bytes) -> list[dict]:
    out, i = [], 0
    while i < len(b):
        pid, i, idw = varint(b, i)
        ln, i, lnw = varint(b, i)
        val = b[i : i + ln]
        i += ln
        entry = {
            "id": "0x%x" % pid,
            "name": TP_NAMES.get(pid, "unknown"),
            "id_varint_width": idw,
            "len_varint_width": lnw,
            "raw": val.hex(),
        }
        if 0 < ln <= 8 and pid not in (0x00, 0x02, 0x0F, 0x10, 0x11):
            try:
                entry["value"] = varint(val, 0)[0]
            except Exception:  # noqa: BLE001
                pass
        out.append(entry)
    return out


def parse_client_hello(ch: bytes) -> dict:
    i = 4  # handshake type + 3-byte length
    i += 2 + 32  # legacy_version + random
    i += 1 + ch[i]  # legacy_session_id
    cl = int.from_bytes(ch[i : i + 2], "big")
    i += 2
    ciphers = ["0x%04x" % int.from_bytes(ch[i + k : i + k + 2], "big") for k in range(0, cl, 2)]
    i += cl
    i += 1 + ch[i]  # legacy_compression_methods
    el = int.from_bytes(ch[i : i + 2], "big")
    i += 2
    end = i + el
    exts, tp, sni, alpn = [], None, None, None
    while i < end:
        et = int.from_bytes(ch[i : i + 2], "big")
        ln = int.from_bytes(ch[i + 2 : i + 4], "big")
        body = ch[i + 4 : i + 4 + ln]
        exts.append({"id": "0x%04x" % et, "len": ln})
        if et in (0x0039, 0xFFA5):
            tp = parse_transport_parameters(body)
        elif et == 0x0000 and ln > 5:
            sni = body[5 : 5 + int.from_bytes(body[3:5], "big")].decode("ascii", "replace")
        elif et == 0x0010:
            alpn, k = [], 2
            while k < ln:
                alpn.append(body[k + 1 : k + 1 + body[k]].decode("ascii", "replace"))
                k += 1 + body[k]
        i += 4 + ln
    return {
        "sni": sni,
        "alpn": alpn,
        "cipher_suites": ciphers,
        "extensions_in_order": exts,
        "quic_transport_parameters_in_order": tp,
    }


# Only the opening flight matters, so stop hoarding datagrams once a flow is past it.
# Keeps a 66 MB capture of streamed audio from being read into memory.
DATAGRAMS_PER_FLOW = 12


def analyze_flow(payloads: list[bytes]) -> dict:
    report, crypto_chunks, original_dcid = [], [], None
    for index, raw in enumerate(payloads, 1):
        entry = {"datagram": index, "udp_payload_bytes": len(raw), "coalesced_packets": []}
        for pk in decode_datagram(raw, original_dcid):
            if original_dcid is None and pk.kind == "Initial":
                original_dcid = pk.dcid
            entry["coalesced_packets"].append(
                {
                    "type": pk.kind,
                    "version": "0x%08x" % pk.version,
                    "dcid_len": len(pk.dcid),
                    "scid_len": len(pk.scid),
                    "token_len": len(pk.token),
                    "length_varint_width": pk.length_varint_width,
                    "packet_number": pk.packet_number,
                    "pn_encoded_length": pk.pn_length,
                    "wire_size": pk.wire_size,
                    "frame_order": pk.frames,
                }
            )
            for off, data, ow, lw in pk.crypto:
                crypto_chunks.append((off, data, ow, lw, index))
        report.append(entry)

    ch = None
    if crypto_chunks:
        buf = bytearray()
        for off, data, _, _, _ in sorted(crypto_chunks, key=lambda c: c[0]):
            if len(buf) < off + len(data):
                buf.extend(b"\x00" * (off + len(data) - len(buf)))
            buf[off : off + len(data)] = data
        try:
            ch = parse_client_hello(bytes(buf))
        except Exception as exc:  # noqa: BLE001
            ch = {"error": "%s: %s" % (exc.__class__.__name__, exc)}

    per_dgram: dict[int, int] = {}
    for _, _, _, _, d in crypto_chunks:
        per_dgram[d] = per_dgram.get(d, 0) + 1

    return {
        "datagrams": report,
        "initial_crypto_frame_byte_counts": [len(c[1]) for c in crypto_chunks],
        "initial_crypto_frames_per_datagram": list(per_dgram.values()),
        "crypto_offset_varint_widths": sorted({c[2] for c in crypto_chunks}),
        "crypto_length_varint_widths": sorted({c[3] for c in crypto_chunks}),
        "client_hello": ch,
    }


def main(path: str, sni_filter: str | None = None) -> None:
    from scapy.all import IP, IPv6, UDP, PcapReader

    flows: dict[tuple, list[bytes]] = {}
    truncated = 0
    with PcapReader(path) as reader:
        for p in reader:
            if UDP not in p:
                continue
            raw = bytes(p[UDP].payload)
            if not raw:
                continue
            ip = p[IP] if IP in p else (p[IPv6] if IPv6 in p else None)
            if ip is None:
                continue
            # A capture snaplen silently shortens payloads, which would corrupt every byte
            # count below. The IP header still declares the real length, so compare.
            declared = (ip.len - ip.ihl * 4 - 8) if IP in p else (ip.plen - 8)
            if 0 < declared and len(raw) < declared:
                truncated += 1
            key = (ip.src, p[UDP].sport, ip.dst, p[UDP].dport)
            bucket = flows.setdefault(key, [])
            if len(bucket) < DATAGRAMS_PER_FLOW:
                bucket.append(raw)

    # A long-header Initial (0xC0 high nibble) is only a CANDIDATE: server Initials look
    # identical here. The direction test is whether it decrypts under the "client in" secret,
    # so the real filter happens after analyze_flow.
    client_flows = {k: v for k, v in flows.items() if v[0][0] & 0xF0 == 0xC0}

    connections, agg, not_client, filtered_out = [], {}, 0, 0

    def tally(bucket: str, value) -> None:
        agg.setdefault(bucket, {})
        k = json.dumps(value) if isinstance(value, (list, tuple)) else str(value)
        agg[bucket][k] = agg[bucket].get(k, 0) + 1

    for key, payloads in sorted(client_flows.items()):
        res = analyze_flow(payloads)
        ch = res.get("client_hello") or {}
        initials = [c for d in res["datagrams"] for c in d["coalesced_packets"]
                    if c["type"] == "Initial"]
        if not initials or not res["initial_crypto_frame_byte_counts"]:
            not_client += 1  # server side, or a flight this capture missed the start of
            continue
        if sni_filter and sni_filter not in (ch.get("sni") or ""):
            filtered_out += 1
            continue
        connections.append({"flow": "%s:%d > %s:%d" % key, "sni": ch.get("sni"),
                            "alpn": ch.get("alpn"), **res})
        first = initials[0]
        tally("padding_target", res["datagrams"][0]["udp_payload_bytes"])
        tally("cid_len_pair_src_dst", [first["scid_len"], first["dcid_len"]])
        tally("pn_encoded_length", first["pn_encoded_length"])
        tally("token_len", first["token_len"])
        tally("header_length_varint_width", first["length_varint_width"])
        tally("initial_crypto_frame_byte_counts", res["initial_crypto_frame_byte_counts"])
        tally("initial_crypto_frames_per_datagram", res["initial_crypto_frames_per_datagram"])
        tally("crypto_offset_varint_widths", res["crypto_offset_varint_widths"])
        tally("crypto_length_varint_widths", res["crypto_length_varint_widths"])
        tally("initial_frame_order", first["frame_order"])
        tally("packets_coalesced_in_first_datagram",
              len(res["datagrams"][0]["coalesced_packets"]))
        if ch.get("quic_transport_parameters_in_order"):
            tally("transport_parameter_order",
                  [t["name"] for t in ch["quic_transport_parameters_in_order"]])
            # GREASE ids are redrawn per connection, so the raw order is unique every time
            # and tells you nothing. Normalise to see the stable layout underneath.
            tally("extension_order_grease_normalised",
                  ["GREASE" if is_grease(int(e["id"], 16)) else e["id"]
                   for e in ch["extensions_in_order"]])
            tally("cipher_suites_grease_normalised",
                  ["GREASE" if is_grease(int(c, 16)) else c for c in ch["cipher_suites"]])

    out = {"capture": path, "sni_filter": sni_filter,
           "client_connections": len(connections),
           "flows_skipped_not_client": not_client,
           "flows_excluded_by_sni_filter": filtered_out,
           "truncated_datagrams": truncated,
           "aggregate": agg, "connections": connections}
    suffix = (".%s" % sni_filter.replace("*", "").strip(".")) if sni_filter else ""
    dest = path.rsplit(".", 1)[0] + suffix + ".analysis.json"
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps({k: v for k, v in out.items() if k != "connections"}, indent=2))
    print("\nwrote " + dest)


def _selfcheck() -> None:
    """RFC 9001 A.1 test vector: the spec's own client Initial must decrypt."""
    dcid = bytes.fromhex("8394c8f03e515708")
    key, iv, hp = initial_keys(dcid, 0x00000001)
    assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d", key.hex()
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c", iv.hex()
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2", hp.hex()
    assert varint(bytes.fromhex("c2197c5eff14e88c"), 0) == (151288809941952652, 8, 8)
    assert varint(b"\x25", 0) == (37, 1, 1)
    print("selfcheck ok")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selfcheck":
        _selfcheck()
    else:
        # usage: quic_initial_analyze.py <capture.pcap> [--sni=SUBSTRING]
        args = [a for a in sys.argv[1:] if not a.startswith("--")]
        sni = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--sni=")), None)
        if not args:
            print(__doc__)
            sys.exit(2)
        main(args[0], sni)
