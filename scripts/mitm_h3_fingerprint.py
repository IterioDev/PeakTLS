"""mitmproxy addon: QUIC / HTTP-3 client fingerprint capture.

Captures, per client connection:
  * raw TLS ClientHello (from the QUIC Initial CRYPTO frames)
  * JA3 + JA4 fingerprints
  * QUIC transport parameters (ClientHello extension 0x0039 / draft 0xffa5)
  * HTTP/3 SETTINGS frame contents (via monkeypatch on the H3 control-frame handler)

Surfaces results in mitmweb as a flow comment + marker, in the event log,
and as JSON under the `h3fp_out` directory.

Run:
    mitmweb   --mode wireguard -s scripts/mitm_h3_fingerprint.py
    mitmproxy --mode wireguard -s scripts/mitm_h3_fingerprint.py

Self-check (no mitmproxy needed):
    python scripts/mitm_h3_fingerprint.py
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger("h3fp")

# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------


def is_grease(v: int) -> bool:
    """GREASE values are 0x0a0a, 0x1a1a, ... 0xfafa (RFC 8701)."""
    return (v & 0x0F0F) == 0x0A0A and ((v >> 8) & 0xFF) == (v & 0xFF)


def qvarint(b: bytes, i: int) -> tuple[int, int]:
    """QUIC variable-length integer (RFC 9000 s16). Returns (value, next_index)."""
    first = b[i]
    length = 1 << (first >> 6)
    val = first & 0x3F
    for k in range(1, length):
        val = (val << 8) | b[i + k]
    return val, i + length


def u16(b: bytes, i: int) -> int:
    return int.from_bytes(b[i : i + 2], "big")


def sha12(items: list[str]) -> str:
    """JA4 truncated hash: first 12 hex chars of sha256, or zeros for empty."""
    if not items:
        return "000000000000"
    return hashlib.sha256(",".join(items).encode()).hexdigest()[:12]


# --------------------------------------------------------------------------
# ClientHello parsing
# --------------------------------------------------------------------------

EXT_SNI = 0x0000
EXT_STATUS_REQUEST = 0x0005
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIG_ALGS = 0x000D
EXT_ALPN = 0x0010
EXT_SCT = 0x0012
EXT_PADDING = 0x0015
EXT_ENCRYPT_THEN_MAC = 0x0016
EXT_EXTENDED_MASTER_SECRET = 0x0017
EXT_CERT_COMPRESSION = 0x001B
EXT_RECORD_SIZE_LIMIT = 0x001C
EXT_DELEGATED_CREDENTIALS = 0x0022
EXT_SESSION_TICKET = 0x0023
EXT_PSK_KEY_EXCHANGE_MODES = 0x002D
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_SIG_ALGS_CERT = 0x0032
EXT_KEY_SHARE = 0x0033
EXT_QUIC_TP = 0x0039
EXT_QUIC_TP_DRAFT = 0xFFA5
EXT_ALPS = 0x4469


def strip_prefix(raw: bytes) -> bytes:
    """Tolerate a TLS record header and/or handshake header in front of the CH body."""
    b = raw
    if b[:1] == b"\x16":  # TLS record: type(1) version(2) length(2)
        b = b[5:]
    if b[:1] == b"\x01":  # Handshake: msg_type(1) length(3)
        b = b[4:]
    return b


def parse_client_hello(raw: bytes) -> dict[str, Any]:
    record_version = u16(raw, 1) if raw[:1] == b"\x16" else None
    b = strip_prefix(raw)
    i = 0
    legacy_version = u16(b, i)
    i += 2
    client_random = b[i : i + 32]
    i += 32
    session_id = b[i + 1 : i + 1 + b[i]]
    i += 1 + b[i]
    cs_len = u16(b, i)
    i += 2
    ciphers = [u16(b, i + k) for k in range(0, cs_len, 2)]
    i += cs_len
    compression_methods = list(b[i + 1 : i + 1 + b[i]])
    i += 1 + b[i]

    exts: list[tuple[int, bytes]] = []
    if i + 2 <= len(b):
        end = i + 2 + u16(b, i)
        i += 2
        while i + 4 <= min(end, len(b)):
            et = u16(b, i)
            el = u16(b, i + 2)
            i += 4
            exts.append((et, b[i : i + el]))
            i += el

    ext_map = dict(exts)
    return {
        "legacy_version": legacy_version,
        "client_random": client_random.hex(),
        "ciphers": ciphers,
        "extensions": [e for e, _ in exts],
        # Wire order with duplicates, plus the raw body of every extension. The
        # parsers above may be wrong; these bytes are not.
        "extensions_detail": [{"id": et, "raw": body.hex()} for et, body in exts],
        "sni": parse_sni(ext_map.get(EXT_SNI)),
        "alpn": parse_alpn(ext_map.get(EXT_ALPN)),
        "supported_versions": parse_u16_list(ext_map.get(EXT_SUPPORTED_VERSIONS), 1),
        "supported_groups": parse_u16_list(ext_map.get(EXT_SUPPORTED_GROUPS), 2),
        "sig_algs": parse_u16_list(ext_map.get(EXT_SIG_ALGS), 2),
        "quic_transport_parameters": parse_transport_params(
            ext_map.get(EXT_QUIC_TP, ext_map.get(EXT_QUIC_TP_DRAFT))
        ),
        "quic_transport_parameters_list": parse_transport_params_list(
            ext_map.get(EXT_QUIC_TP, ext_map.get(EXT_QUIC_TP_DRAFT))
        ),
        "_has_quic_tp": EXT_QUIC_TP in ext_map or EXT_QUIC_TP_DRAFT in ext_map,
        "record_version": record_version,
        "session_id": session_id.hex(),
        "compression_methods": compression_methods,
        "ec_point_formats": parse_u8_list(ext_map.get(EXT_EC_POINT_FORMATS)),
        "key_share_groups": parse_key_share_groups(ext_map.get(EXT_KEY_SHARE)),
        "key_shares": parse_key_shares(ext_map.get(EXT_KEY_SHARE)),
        "psk_key_exchange_modes": parse_u8_list(ext_map.get(EXT_PSK_KEY_EXCHANGE_MODES)),
        "cert_compression_algos": parse_u16_list_u8len(ext_map.get(EXT_CERT_COMPRESSION)),
        "delegated_credentials": parse_u16_list(ext_map.get(EXT_DELEGATED_CREDENTIALS), 2),
        "sig_algs_cert": parse_u16_list(ext_map.get(EXT_SIG_ALGS_CERT), 2),
        "application_settings": parse_alpn(ext_map.get(EXT_ALPS)),
        "record_size_limit": u16(ext_map[EXT_RECORD_SIZE_LIMIT], 0)
                             if ext_map.get(EXT_RECORD_SIZE_LIMIT) else None,
        "session_ticket": EXT_SESSION_TICKET in ext_map,
        "extended_master_secret": EXT_EXTENDED_MASTER_SECRET in ext_map,
        "encrypt_then_mac": EXT_ENCRYPT_THEN_MAC in ext_map,
        "status_request": EXT_STATUS_REQUEST in ext_map,
        "signed_cert_timestamp": EXT_SCT in ext_map,
        "padding": EXT_PADDING in ext_map,
    }


def parse_u16_list(data: bytes | None, len_bytes: int) -> list[int]:
    if not data:
        return []
    body = data[len_bytes:]
    return [u16(body, k) for k in range(0, len(body) - 1, 2)]


def parse_sni(data: bytes | None) -> str | None:
    if not data or len(data) < 5:
        return None
    # SNI is carried as an A-label (ASCII); never punycode-decode, the exact
    # bytes on the wire are what the fingerprint is about.
    return data[5 : 5 + u16(data, 3)].decode("ascii", "replace")


def parse_alpn(data: bytes | None) -> list[str]:
    if not data:
        return []
    out, i = [], 2
    while i < len(data):
        n = data[i]
        out.append(data[i + 1 : i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return out


def parse_u8_list(data: bytes | None) -> list[int]:
    """Extensions 11 and 45: one length octet, then one octet per entry."""
    if not data:
        return []
    return list(data[1 : 1 + data[0]])


def parse_u16_list_u8len(data: bytes | None) -> list[int]:
    """Extensions 27 and 43: one length octet, then u16 entries."""
    if not data:
        return []
    body = data[1 : 1 + data[0]]
    return [u16(body, k) for k in range(0, len(body) - 1, 2)]


def parse_key_shares(data: bytes | None) -> list[dict[str, int]]:
    """Extension 51. Entries are (group u16, key_len u16, key), variable length,
    so this cannot use the flat list helpers. The key length is signal itself:
    it separates a bare X25519 share from a hybrid PQ one."""
    if not data or len(data) < 2:
        return []
    out, i, end = [], 2, 2 + u16(data, 0)
    while i + 4 <= min(end, len(data)):
        klen = u16(data, i + 2)
        out.append({"group": u16(data, i), "key_length": klen})
        i += 4 + klen
    return out


def parse_key_share_groups(data: bytes | None) -> list[int]:
    return [k["group"] for k in parse_key_shares(data)]


# --------------------------------------------------------------------------
# QUIC transport parameters (RFC 9000 s18.2, RFC 9221, RFC 9287, RFC 9368)
# --------------------------------------------------------------------------

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
    0x173E: "grease_quic_bit",
    0x0F739BBC1B666D05: "enable_multipath",
}
# Params whose value is a varint; everything else is reported as hex.
TP_VARINT = {0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0E, 0x20}


def parse_transport_params(data: bytes | None) -> dict[str, Any]:
    """Ordered dict of transport params. Order itself is fingerprint signal."""
    if not data:
        return {}
    out: dict[str, Any] = {}
    order: list[str] = []
    i = 0
    while i < len(data):
        pid, i = qvarint(data, i)
        plen, i = qvarint(data, i)
        val = data[i : i + plen]
        i += plen
        # Reserved GREASE params have ids of the form 31*N+27 (RFC 9000 s18.1).
        if pid % 31 == 27:
            name = f"GREASE_0x{pid:x}"
        else:
            name = TP_NAMES.get(pid, f"unknown_0x{pid:x}")
        if pid in TP_VARINT and val:
            out[name] = qvarint(val, 0)[0]
        elif plen == 0:
            out[name] = True
        else:
            out[name] = val.hex()
        order.append(name)
    out["_order"] = order
    return out


def parse_transport_params_list(data: bytes | None) -> list[dict[str, Any]]:
    """Wire order, integer ids, raw bytes -- the machine-readable twin of the
    dict form above, which cannot hold a duplicate id and puts display text in
    the name slot. `name` is None when unknown; the id is never replaced by it."""
    if not data:
        return []
    out: list[dict[str, Any]] = []
    i = 0
    while i < len(data):
        pid, i = qvarint(data, i)
        plen, i = qvarint(data, i)
        val = data[i : i + plen]
        i += plen
        out.append({
            "id": pid,
            "name": "GREASE" if pid % 31 == 27 else TP_NAMES.get(pid),
            "value": qvarint(val, 0)[0] if pid in TP_VARINT and val else None,
            "raw": val.hex(),
        })
    return out


# --------------------------------------------------------------------------
# JA3 / JA4
# --------------------------------------------------------------------------


def ja3(ch: dict[str, Any]) -> tuple[str, str]:
    parts = [
        str(ch["legacy_version"]),
        "-".join(str(c) for c in ch["ciphers"] if not is_grease(c)),
        "-".join(str(e) for e in ch["extensions"] if not is_grease(e)),
        "-".join(str(g) for g in ch["supported_groups"] if not is_grease(g)),
        "-".join(str(p) for p in ch["ec_point_formats"]),
    ]
    s = ",".join(parts)
    return s, hashlib.md5(s.encode()).hexdigest()


def ja3n(ch: dict[str, Any]) -> tuple[str, str]:
    """JA3 with the extension list sorted ascending ("JA3 normalised").

    Plain JA3 changes whenever a client re-rolls GREASE or shuffles extensions,
    which Chrome and iOS both do; this variant survives that. Only the extension
    field is touched -- ciphers, groups and point formats stay in wire order.
    """
    parts = ja3(ch)[0].split(",")
    if parts[2]:
        parts[2] = "-".join(sorted(parts[2].split("-"), key=int))
    s = ",".join(parts)
    return s, hashlib.md5(s.encode()).hexdigest()


JA4_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}


def ja4(ch: dict[str, Any], is_quic: bool) -> str:
    ciphers = [c for c in ch["ciphers"] if not is_grease(c)]
    exts = [e for e in ch["extensions"] if not is_grease(e)]
    sigs = [s for s in ch["sig_algs"] if not is_grease(s)]

    versions = [v for v in ch["supported_versions"] if not is_grease(v)]
    ver = max(versions) if versions else ch["legacy_version"]

    alpn = ch["alpn"][0] if ch["alpn"] else ""
    alpn_code = (alpn[0] + alpn[-1]) if alpn else "00"

    a = "{}{}{}{:02d}{:02d}{}".format(
        "q" if is_quic else "t",
        JA4_VERSIONS.get(ver, "00"),
        "d" if ch["sni"] else "i",
        min(len(ciphers), 99),
        min(len(exts), 99),
        alpn_code,
    )
    b = sha12(sorted(f"{c:04x}" for c in ciphers))
    # JA4_c: extensions sorted, SNI and ALPN removed; sig algs keep original order.
    c_exts = sorted(f"{e:04x}" for e in exts if e not in (EXT_SNI, EXT_ALPN))
    c_raw = ",".join(c_exts) + "_" + ",".join(f"{s:04x}" for s in sigs)
    c = hashlib.sha256(c_raw.encode()).hexdigest()[:12] if c_exts or sigs else "000000000000"
    return f"{a}_{b}_{c}"


# --------------------------------------------------------------------------
# HTTP/3 SETTINGS capture (monkeypatch - pokes library internals)
# --------------------------------------------------------------------------

H3_SETTINGS_NAMES = {
    0x01: "QPACK_MAX_TABLE_CAPACITY",
    0x06: "MAX_FIELD_SECTION_SIZE",
    0x07: "QPACK_BLOCKED_STREAMS",
    0x08: "ENABLE_CONNECT_PROTOCOL",
    0x2B603742: "H3_DATAGRAM_DRAFT",
    0x33: "H3_DATAGRAM",
}
H3_FRAME_SETTINGS = 0x04

# mitmproxy runs two H3Connections per proxied session: a server-role one facing
# the real client, and a client-role one facing the origin. Both receive SETTINGS,
# so entries are keyed by mitmproxy connection id and tagged with which peer sent
# them -- only "client" entries belong in the fingerprint.
_settings_by_conn: dict[str, dict[str, Any]] = {}
_settings_log: list[dict[str, Any]] = []
_h3_hook_state = "not attempted"


def parse_h3_settings(frame_data: bytes) -> dict[str, Any]:
    """SETTINGS payload is a sequence of (varint identifier, varint value)."""
    out: dict[str, Any] = {}
    order: list[str] = []
    i = 0
    while i < len(frame_data):
        sid, i = qvarint(frame_data, i)
        val, i = qvarint(frame_data, i)
        # Reserved GREASE settings have ids of the form 0x1f*N + 0x21.
        if sid > 0x21 and (sid - 0x21) % 0x1F == 0:
            name = f"GREASE_0x{sid:x}"
        else:
            name = H3_SETTINGS_NAMES.get(sid, f"unknown_0x{sid:x}")
        out[name] = val
        order.append(name)
    out["_order"] = order
    return out


def parse_h3_settings_list(frame_data: bytes) -> list[dict[str, Any]]:
    """Same payload as parse_h3_settings, kept as an ordered list of integer ids
    so duplicates and unknown ids survive. `name` is None when unknown."""
    out: list[dict[str, Any]] = []
    i = 0
    while i < len(frame_data):
        sid, i = qvarint(frame_data, i)
        val, i = qvarint(frame_data, i)
        grease = sid > 0x21 and (sid - 0x21) % 0x1F == 0
        out.append({"id": sid,
                    "name": "GREASE" if grease else H3_SETTINGS_NAMES.get(sid),
                    "value": val})
    return out


H3_FRAME_NAMES = {
    0x00: "DATA", 0x01: "HEADERS", 0x03: "CANCEL_PUSH", 0x04: "SETTINGS",
    0x05: "PUSH_PROMISE", 0x07: "GOAWAY", 0x0D: "MAX_PUSH_ID",
    0xF0700: "PRIORITY_UPDATE_REQUEST", 0xF0701: "PRIORITY_UPDATE_PUSH",
}
H3_UNI_STREAM_NAMES = {0: "control", 1: "push", 2: "qpack_encoder",
                       3: "qpack_decoder", 0x54: "webtransport"}


def _h3_peer_and_conn(h3conn: Any) -> tuple[str, str | None]:
    # H3Connection._is_client is True for mitmproxy's upstream connection, whose
    # *received* frames therefore come from the origin server. False means the
    # client-facing server role, receiving the real client's frames.
    peer = {True: "server", False: "client"}.get(getattr(h3conn, "_is_client", None), "unknown")
    # mitmproxy's MockQuic carries the real connection object; H3Connection stores
    # it as _quic. Gives us an exact flow correlation key instead of guessing.
    conn = getattr(getattr(h3conn, "_quic", None), "conn", None)
    return peer, getattr(conn, "id", None)


def _h3_record(h3conn: Any) -> dict[str, Any] | None:
    """Per-connection record, or None when this is not the client-facing side."""
    peer, conn_id = _h3_peer_and_conn(h3conn)
    if peer != "client" or not conn_id:
        return None
    return _settings_by_conn.setdefault(conn_id, {
        "ts": time.time(), "peer": peer, "conn_id": conn_id, "settings": None,
        "settings_list": None,
        "uni_streams": [], "control_frames": [], "pseudo_headers": None,
        "header_order": None,
    })


def _record_control_frame(h3conn: Any, frame_type: int, frame_data: bytes) -> None:
    peer, _ = _h3_peer_and_conn(h3conn)
    name = H3_FRAME_NAMES.get(frame_type, f"0x{frame_type:x}")
    if frame_type == H3_FRAME_SETTINGS:
        parsed = parse_h3_settings(frame_data)
        logger.info("h3fp: HTTP/3 SETTINGS from %s %s", peer, json.dumps(parsed))
    else:
        parsed = None
        logger.info("h3fp: HTTP/3 control frame from %s: %s", peer, name)

    rec = _h3_record(h3conn)
    if rec is None:
        return
    # MAX_PUSH_ID carries a varint the client chose; keep the value, it is signal.
    if frame_type == 0x0D and frame_data:
        name = f"MAX_PUSH_ID={qvarint(frame_data, 0)[0]}"
    if name not in rec["control_frames"]:
        rec["control_frames"].append(name)
    if parsed is not None:
        rec["settings"] = parsed
        rec["settings_list"] = parse_h3_settings_list(frame_data)
        rec["raw"] = frame_data.hex()
    _settings_log.append({"ts": time.time(), "peer": peer, "frame": name,
                          "settings": parsed})


def _record_uni_stream(h3conn: Any, stream_id: int, stream_type: int) -> None:
    rec = _h3_record(h3conn)
    if rec is None:
        return
    # aioquic calls _log_stream_type for streams WE open as well as the peer's:
    # LayeredH3Connection.__init__ opens mitmproxy's own control/qpack streams
    # (ids 3, 7, 11). Recording those produced a doubled
    # "control -> qpack_encoder -> qpack_decoder -> control -> ..." whose first
    # half described mitmproxy, not the client. Client-initiated unidirectional
    # streams are id % 4 == 2 (RFC 9000 s2.1), and this record only ever covers
    # the client-facing role, so that is the peer.
    if stream_id % 4 != 2:
        return
    name = H3_UNI_STREAM_NAMES.get(stream_type, f"0x{stream_type:x}")
    rec["uni_streams"].append(name)
    logger.info("h3fp: uni stream %s opened (id %s)", name, stream_id)


def _record_headers(h3conn: Any, headers: list) -> None:
    """First request only: the wire order of pseudo-headers and normal headers."""
    rec = _h3_record(h3conn)
    if rec is None or rec["pseudo_headers"] is not None:
        return
    names = [(n.decode("ascii", "replace") if isinstance(n, bytes) else n)
             for n, _ in headers]
    pseudo = [n for n in names if n.startswith(":")]
    if not pseudo:
        return
    rec["pseudo_headers"] = ",".join(n[1] for n in pseudo)  # Akamai style: m,a,s,p
    rec["header_order"] = [n for n in names if not n.startswith(":")]
    logger.info("h3fp: h3 pseudo-header order %s", rec["pseudo_headers"])


def _patch(cls, name: str, make_wrapper) -> str:
    """Idempotently wrap cls.name. Returns a status string."""
    orig = getattr(cls, name, None)
    if orig is None:
        return f"{cls.__name__}.{name} ABSENT"
    if getattr(orig, "_h3fp_patched", False):
        return f"{cls.__name__}.{name} already"
    wrapper = make_wrapper(orig)
    functools.update_wrapper(wrapper, orig)
    wrapper._h3fp_patched = True
    setattr(cls, name, wrapper)
    return f"{cls.__name__}.{name} ok"


def install_h3_hook() -> str:
    """Wrap the H3 control-frame, uni-stream and header-decode paths.

    mitmproxy's H3Connection subclasses aioquic's, so patching the aioquic base
    covers both.
    """
    global _h3_hook_state
    try:
        from aioquic.h3.connection import H3Connection as cls
    except Exception:
        try:
            from mitmproxy.proxy.layers.http import _http3

            cls = getattr(_http3, "H3Connection", None)
        except Exception:
            cls = None
    if cls is None:
        _h3_hook_state = "failed: no H3Connection class found"
        return _h3_hook_state

    def control(orig):
        def w(self, frame_type, frame_data, *a, **kw):
            try:
                _record_control_frame(self, frame_type, bytes(frame_data or b""))
            except Exception as e:  # never break the proxy over telemetry
                logger.warning("h3fp: control frame hook failed: %r", e)
            return orig(self, frame_type, frame_data, *a, **kw)
        return w

    def uni(orig):
        def w(self, stream_id, stream_type, *a, **kw):
            try:
                _record_uni_stream(self, stream_id, stream_type)
            except Exception as e:
                logger.warning("h3fp: uni stream hook failed: %r", e)
            return orig(self, stream_id, stream_type, *a, **kw)
        return w

    def headers(orig):
        def w(self, *a, **kw):
            out = orig(self, *a, **kw)
            try:
                _record_headers(self, out)
            except Exception as e:
                logger.warning("h3fp: header hook failed: %r", e)
            return out
        return w

    _h3_hook_state = "; ".join([
        _patch(cls, "_handle_control_frame", control),
        _patch(cls, "_log_stream_type", uni),
        _patch(cls, "_decode_headers", headers),
    ])
    return _h3_hook_state


# --------------------------------------------------------------------------
# HTTP/2 fingerprint (Akamai-style: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-headers)
# --------------------------------------------------------------------------

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_SETTINGS_NAMES = {
    1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS",
    4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE",
    8: "ENABLE_CONNECT_PROTOCOL", 9: "NO_RFC7540_PRIORITIES",
}

_h2_by_conn: dict[str, dict[str, Any]] = {}
_h2_hook_state = "not attempted"
# Ownership is stamped on the h2 object itself rather than kept in a dict keyed by
# id(): CPython reuses ids after GC, which would silently mis-attribute a
# fingerprint to the wrong connection on a long-running proxy.
_H2_OWNER_ATTR = "_h3fp_owner"


def new_h2_record() -> dict[str, Any]:
    return {"settings": [], "window_update": None, "priority": [],
            "pseudo_headers": None, "header_order": None,
            "_buf": bytearray(), "_done": False, "_got_settings": False}


def h2_scan(rec: dict[str, Any], data: bytes) -> dict[str, Any]:
    """Feed raw h2 bytes; collect the connection prelude up to the first HEADERS.

    Everything before the first HEADERS frame is the client's opening statement --
    that is what the h2 fingerprint is made of.
    """
    if rec["_done"]:
        return rec
    buf = rec["_buf"]
    buf += data
    if buf[:len(H2_PREFACE)] == H2_PREFACE:
        del buf[:len(H2_PREFACE)]
    while len(buf) >= 9:
        length = int.from_bytes(buf[0:3], "big")
        if len(buf) < 9 + length:
            break
        ftype, flags = buf[3], buf[4]
        sid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
        payload = bytes(buf[9:9 + length])
        del buf[:9 + length]

        # Only the opening SETTINGS/WINDOW_UPDATE are fingerprint material; a later
        # SETTINGS update is ordinary traffic and must not overwrite them.
        if ftype == 0x04 and not flags & 0x01 and not rec["_got_settings"]:
            rec["_got_settings"] = True
            rec["settings"] = [
                (int.from_bytes(payload[k:k + 2], "big"),
                 int.from_bytes(payload[k + 2:k + 6], "big"))
                for k in range(0, len(payload) - 5, 6)
            ]
        elif ftype == 0x08 and sid == 0 and rec["window_update"] is None:
            rec["window_update"] = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
        elif ftype == 0x02 and len(payload) >= 5:         # PRIORITY
            dep = int.from_bytes(payload[:4], "big")
            rec["priority"].append((sid, dep >> 31, dep & 0x7FFFFFFF, payload[4] + 1))
        elif ftype == 0x01:                               # HEADERS: prelude is over
            if flags & 0x20 and len(payload) >= 5:
                dep = int.from_bytes(payload[:4], "big")
                rec["priority"].append((sid, dep >> 31, dep & 0x7FFFFFFF, payload[4] + 1))
            rec["_done"] = True
            rec["_buf"] = bytearray()
            break
    return rec


def h2_fingerprint(rec: dict[str, Any]) -> str:
    """Akamai format: settings|window_update|priorities|pseudo-header order."""
    s = ";".join(f"{i}:{v}" for i, v in rec["settings"]) or "0"
    p = ",".join(f"{a}:{b}:{c}:{d}" for a, b, c, d in rec["priority"]) or "0"
    return f"{s}|{rec['window_update'] or 0}|{p}|{rec['pseudo_headers'] or ''}"


def _h2_observe(h2conn: Any, data: bytes, events: Any) -> None:
    owner = getattr(h2conn, _H2_OWNER_ATTR, None)
    if not owner:
        return
    conn_id, client_side = owner
    if client_side:      # mitmproxy's upstream socket: those frames are the origin's
        return
    rec = _h2_by_conn.setdefault(conn_id, new_h2_record())
    h2_scan(rec, data)
    if rec["pseudo_headers"] is None:
        for ev in events or ():
            hdrs = getattr(ev, "headers", None)
            if not hdrs:
                continue
            names = [(n.decode("ascii", "replace") if isinstance(n, bytes) else n)
                     for n, _ in hdrs]
            pseudo = [n for n in names if n.startswith(":")]
            if pseudo:
                rec["pseudo_headers"] = ",".join(n[1] for n in pseudo)
                rec["header_order"] = [n for n in names if not n.startswith(":")]
                logger.info("h3fp: h2 fingerprint %s", h2_fingerprint(rec))
                break


def install_h2_hook() -> str:
    """Wrap h2's receive_data, plus mitmproxy's Http2Connection to learn ownership.

    The h2 connection object has no back-reference to the mitmproxy connection, so
    the ownership map is what makes exact flow correlation possible.
    """
    global _h2_hook_state
    try:
        import h2.connection
        from mitmproxy.proxy.layers.http import _http2
    except Exception as e:
        _h2_hook_state = f"failed: {e!r}"
        return _h2_hook_state

    def own(orig):
        def w(self, context, conn, *a, **kw):
            out = orig(self, context, conn, *a, **kw)
            try:
                setattr(self.h2_conn, _H2_OWNER_ATTR,
                        (conn.id, self.h2_conn.config.client_side))
            except Exception as e:
                logger.warning("h3fp: h2 ownership hook failed: %r", e)
            return out
        return w

    def recv(orig):
        def w(self, data, *a, **kw):
            events = orig(self, data, *a, **kw)
            try:
                _h2_observe(self, bytes(data), events)
            except Exception as e:
                logger.warning("h3fp: h2 observe failed: %r", e)
            return events
        return w

    _h2_hook_state = "; ".join([
        _patch(_http2.Http2Connection, "__init__", own),
        _patch(h2.connection.H2Connection, "receive_data", recv),
    ])
    return _h2_hook_state


# --------------------------------------------------------------------------
# human-readable report
# --------------------------------------------------------------------------

# Default beside the script, NOT beside mitmweb's cwd -- an elevated shell starts
# in C:\Windows\System32 and a relative default quietly writes there.
DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fingerprints")

_SAFE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"


def safe_host(host: str | None) -> str:
    """Filesystem-safe host name for <host>.h3fp.txt."""
    h = (host or "no-sni").strip().rstrip(".")
    return "".join(c if c in _SAFE else "_" for c in h)[:120] or "no-sni"


# Per-connection randomness that is NOT fingerprint identity. Left in the report,
# stripped from the signature -- otherwise every connection looks "new" and the
# dedupe never fires.
TP_VOLATILE = {
    "original_destination_connection_id",
    "initial_source_connection_id",
    "retry_source_connection_id",
    "stateless_reset_token",
    "preferred_address",
}


def fingerprint_is_complete(fp: dict[str, Any]) -> bool:
    """True once a fingerprint carries protocol-layer data, not just the hello.

    tls_clienthello fires the moment the ClientHello is parsed, long before any
    HEADERS frame exists, so its snapshot has no h3/h2 block. This distinguishes
    those partial records from finished ones.
    """
    return bool(fp.get("h3") or fp.get("h2") or fp.get("h3_settings"))


def degrease(items: list[str]) -> list[str]:
    """Collapse GREASE entries to a placeholder, keeping their position."""
    out = []
    for s in items:
        if isinstance(s, str) and s.startswith("GREASE_"):
            out.append("GREASE")
        elif isinstance(s, str) and s.startswith("0x") and is_grease(int(s, 16)):
            out.append("GREASE")
        else:
            out.append(s)
    return out


def _stable(d: dict[str, Any], volatile: set[str] = frozenset()) -> dict[str, Any]:
    """Params that identify the client, minus GREASE and per-connection values.

    Deliberately NOT keyed on wire order: iOS reshuffles its QUIC transport
    parameters on every connection, so order is noise for this client even though
    it is stable signal for others. The report still shows the real wire order.
    """
    return {k: v for k, v in sorted(d.items())
            if not k.startswith(("_", "GREASE_")) and k not in volatile}


def fp_signature(fp: dict[str, Any], with_h3: bool = True) -> str:
    """Identity of a fingerprint. Repeats of the same one are not appended.

    GREASE ids/values and per-connection identifiers are normalised away; GREASE
    *positions* in the cipher/extension lists are kept, since where a client
    injects GREASE is real signal.
    """
    h3 = fp.get("h3_settings") or {}
    sig = [
        fp["ja4"],
        fp["ja3"],
        fp["alpn"],
        degrease(fp["ciphers"]),
        degrease(fp["extensions"]),
        degrease(fp["supported_groups"]),
        fp["sig_algs"],
        _stable(fp["quic_transport_parameters"], TP_VOLATILE),
    ]
    # The h2 prelude is a separate protocol layer, but it belongs to the same
    # client: a change there is a different fingerprint even if the TLS half matches.
    sig.append((fp.get("h2") or {}).get("fingerprint"))
    if with_h3:
        h3x = fp.get("h3") or {}
        sig += [_stable(h3), h3x.get("uni_streams"), h3x.get("control_frames"),
                h3x.get("pseudo_headers"), h3x.get("header_order")]
    return json.dumps(sig, sort_keys=True)


def _ordered(d: dict[str, Any], indent: str = "    ") -> list[str]:
    """Render a parsed param/settings dict in wire order."""
    if not d:
        return [indent + "(none)"]
    order = d.get("_order") or [k for k in d if not k.startswith("_")]
    width = max(len(k) for k in order)
    return [f"{indent}{k:<{width}} = {d.get(k)}" for k in order]


def format_report(fp: dict[str, Any]) -> str:
    L = ["=" * 78,
         "{}  {}  {}  via {}".format(
             time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(fp["ts"])),
             fp["sni"] or "(no SNI)", fp["peername"], fp["transport"]),
         "-" * 78,
         f"JA4   {fp['ja4']}",
         f"JA3   {fp['ja3']}",
         f"ALPN  {', '.join(fp['alpn']) or '(none)'}",
         f"TLS   {', '.join(fp['supported_versions']) or '(none)'}",
         "",
         "Cipher suites (wire order)",
         "    " + " ".join(fp["ciphers"]),
         "Extensions (wire order)",
         "    " + " ".join(fp["extensions"]),
         "Supported groups (wire order)",
         "    " + " ".join(fp["supported_groups"]) or "    (none)",
         "Signature algorithms (wire order)",
         "    " + " ".join(fp["sig_algs"]) or "    (none)",
         "",
         "QUIC transport parameters (wire order)"]
    L += _ordered(fp["quic_transport_parameters"])
    L += ["", "HTTP/3 SETTINGS (wire order)"]
    L += _ordered(fp.get("h3_settings") or {})

    h3 = fp.get("h3") or {}
    if any(h3.values()):
        L += ["", "HTTP/3 streams and frames",
              "    uni streams opened  " + (" -> ".join(h3.get("uni_streams") or []) or "(none)"),
              "    control frames      " + (" -> ".join(h3.get("control_frames") or []) or "(none)"),
              "    pseudo-header order " + (h3.get("pseudo_headers") or "(none)"),
              "    header order        " + (", ".join(h3.get("header_order") or []) or "(none)")]

    h2 = fp.get("h2") or {}
    if h2:
        L += ["", "HTTP/2 fingerprint (Akamai format)", "    " + h2["fingerprint"], "",
              "    settings (wire order)"]
        L += [f"        {n} = {v}" for n, v in h2["settings_named"]] or ["        (none)"]
        L += [f"    window_update       {h2['window_update']}",
              "    priority frames     " + (str(h2["priority"]) if h2["priority"] else "(none)"),
              "    pseudo-header order " + (h2["pseudo_headers"] or "(none)"),
              "    header order        " + (", ".join(h2["header_order"] or []) or "(none)")]

    L += ["", "JA3 string", "    " + fp["ja3_string"],
          "Raw ClientHello", "    " + fp["raw_client_hello"], ""]
    return "\n".join(L)


# --------------------------------------------------------------------------
# addon
# --------------------------------------------------------------------------


class H3Fingerprint:
    def __init__(self) -> None:
        self.by_client: dict[str, dict[str, Any]] = {}
        self.seen: set[str] = set()       # signatures already appended
        self.seen_with_h3: set[str] = set()  # of those, the ones that had SETTINGS
        # Whether latest.json currently holds a finished fingerprint. Guards it
        # against being overwritten by a later connection's bare ClientHello.
        self._latest_complete = False

    def load(self, loader):
        loader.add_option(
            "h3fp_out", str, DEFAULT_OUT,
            "Output directory for fingerprints. Relative paths resolve against "
            "the current working directory.",
        )
        loader.add_option(
            "h3fp_comment", bool, True,
            "Attach a fingerprint summary as a mitmweb flow comment.",
        )

    def running(self):
        logger.info("h3fp: h3 hooks %s", install_h3_hook())
        logger.info("h3fp: h2 hooks %s", install_h2_hook())
        logger.info("h3fp: writing to %s", self._outdir())

    # -- ClientHello -------------------------------------------------------

    def tls_clienthello(self, data):
        try:
            raw = data.client_hello.raw_bytes
            if callable(raw):
                raw = raw()
        except Exception:
            raw = getattr(getattr(data, "client_hello", None), "_raw_bytes", None)
        if not raw:
            logger.warning("h3fp: could not obtain raw ClientHello bytes")
            return

        try:
            ch = parse_client_hello(bytes(raw))
        except Exception as e:
            logger.warning("h3fp: ClientHello parse failed: %r", e)
            return

        client = data.context.client
        is_quic = ch.pop("_has_quic_tp") or getattr(client, "transport_protocol", "tcp") == "udp"
        ja3_str, ja3_hash = ja3(ch)

        fp = {
            "ts": time.time(),
            "client_id": client.id,
            "peername": str(getattr(client, "peername", None)),
            "transport": "quic" if is_quic else "tcp",
            "sni": ch["sni"],
            "alpn": ch["alpn"],
            "ja4": ja4(ch, is_quic),
            "ja3": ja3_hash,
            "ja3_string": ja3_str,
            "ja3n": ja3n(ch)[1],
            "ciphers": [f"0x{c:04x}" for c in ch["ciphers"]],
            "extensions": [f"0x{e:04x}" for e in ch["extensions"]],
            "extensions_detail": ch["extensions_detail"],
            "supported_versions": [f"0x{v:04x}" for v in ch["supported_versions"]],
            "supported_groups": [f"0x{g:04x}" for g in ch["supported_groups"]],
            "sig_algs": [f"0x{s:04x}" for s in ch["sig_algs"]],
            "legacy_version": ch["legacy_version"],
            "record_version": ch["record_version"],
            "session_id": ch["session_id"],
            "compression_methods": ch["compression_methods"],
            "ec_point_formats": ch["ec_point_formats"],
            "key_share_groups": [f"0x{g:04x}" for g in ch["key_share_groups"]],
            "key_shares": ch["key_shares"],
            "psk_key_exchange_modes": ch["psk_key_exchange_modes"],
            "cert_compression_algos": [f"0x{a:04x}" for a in ch["cert_compression_algos"]],
            "delegated_credentials": [f"0x{d:04x}" for d in ch["delegated_credentials"]],
            "sig_algs_cert": [f"0x{s:04x}" for s in ch["sig_algs_cert"]],
            "application_settings": ch["application_settings"],
            "record_size_limit": ch["record_size_limit"],
            "session_ticket": ch["session_ticket"],
            "extended_master_secret": ch["extended_master_secret"],
            "encrypt_then_mac": ch["encrypt_then_mac"],
            "status_request": ch["status_request"],
            "signed_cert_timestamp": ch["signed_cert_timestamp"],
            "padding": ch["padding"],
            "quic_transport_parameters": ch["quic_transport_parameters"],
            "quic_transport_parameters_list": ch["quic_transport_parameters_list"],
            "client_random": ch["client_random"],
            "raw_client_hello": bytes(raw).hex(),
        }
        self.by_client[client.id] = fp
        logger.info("h3fp: %s JA4=%s alpn=%s", fp["sni"], fp["ja4"], ",".join(fp["alpn"]))
        self._write(fp)

    # -- attach to flows so mitmweb shows something ------------------------

    # The client's SETTINGS frame usually lands *after* requestheaders, so attach
    # on both hooks; the second pass fills in H3 once it has arrived.
    def requestheaders(self, flow):
        self._attach(flow)

    def response(self, flow):
        self._attach(flow, final=True)

    def error(self, flow):
        self._attach(flow, final=True)

    def done(self):
        # Flush anything that never reached a response (connection errors, etc).
        for fp in self.by_client.values():
            self._write_txt(fp)

    def _attach(self, flow, final: bool = False):
        fp = self.by_client.get(flow.client_conn.id)
        if not fp:
            return
        entry = _settings_by_conn.get(flow.client_conn.id)
        h2rec = _h2_by_conn.get(flow.client_conn.id)
        before = (fp.get("h3_settings"), fp.get("h3"), fp.get("h2"))
        if entry and entry["peer"] == "client":
            fp["h3_settings"] = entry["settings"]
            fp["h3"] = {k: entry[k] for k in
                        ("uni_streams", "control_frames", "pseudo_headers",
                         "header_order", "settings_list")}
        if h2rec:
            fp["h2"] = {"fingerprint": h2_fingerprint(h2rec),
                        "settings": [[i, v] for i, v in h2rec["settings"]],
                        "settings_named": [[H2_SETTINGS_NAMES.get(i, f"0x{i:x}"), v]
                                           for i, v in h2rec["settings"]],
                        "window_update": h2rec["window_update"],
                        "priority": [list(p) for p in h2rec["priority"]],
                        "pseudo_headers": h2rec["pseudo_headers"],
                        "header_order": h2rec["header_order"]}
        if (fp.get("h3_settings"), fp.get("h3"), fp.get("h2")) != before:
            self._write(fp)

        if final:
            self._write_txt(fp)

        from mitmproxy import ctx

        if not getattr(ctx.options, "h3fp_comment", True):
            return
        tp = fp["quic_transport_parameters"]
        summary = [f"JA4={fp['ja4']}", f"JA3={fp['ja3']}", f"ALPN={','.join(fp['alpn']) or '-'}"]
        if tp:
            summary.append("TP=" + ";".join(
                f"{k}={v}" for k, v in tp.items() if not k.startswith("_")
            ))
        if fp.get("h3_settings"):
            summary.append("H3=" + ";".join(
                f"{k}={v}" for k, v in fp["h3_settings"].items() if not k.startswith("_")
            ))
        flow.comment = " | ".join(summary)
        flow.marked = ":mag:"

    # -- output ------------------------------------------------------------

    @staticmethod
    def _outdir() -> str:
        try:
            from mitmproxy import ctx

            out = ctx.options.h3fp_out
        except Exception:
            out = DEFAULT_OUT
        out = os.path.abspath(out)
        os.makedirs(out, exist_ok=True)
        return out

    def _write_txt(self, fp: dict[str, Any]) -> None:
        """Append to <host>.h3fp.txt and archive the JSON, once per distinct
        fingerprint. Repeat connections to the same host are pure noise."""
        base = fp_signature(fp, with_h3=False)
        has_h3 = bool(fp.get("h3_settings"))
        # A block whose SETTINGS never arrived (connection died early) carries no
        # information a richer block for the same client doesn't already have.
        if not has_h3 and base in self.seen_with_h3:
            return
        sig = fp_signature(fp) if has_h3 else base
        if sig in self.seen:
            return
        self.seen.add(sig)
        if has_h3:
            self.seen_with_h3.add(base)
        path = os.path.join(self._outdir(), f"{safe_host(fp['sni'])}.h3fp.txt")
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(format_report(fp))
        except OSError as e:
            logger.warning("h3fp: could not write %s: %r", path, e)
            return
        self._write(fp, archive=True)
        logger.info("h3fp: new fingerprint for %s -> %s", fp["sni"], path)

    def _write(self, fp: dict[str, Any], archive: bool = False) -> None:
        out = self._outdir()
        blob = json.dumps(fp, indent=2, sort_keys=False)
        paths = []
        # latest.json is a single last-write-wins file, and every newly opened
        # connection writes one from tls_clienthello before it has any h3/h2
        # data. Left ungated, a phone opening connections constantly meant the
        # finished fingerprint was almost never the one on disk. Partial records
        # still get written while nothing better has been captured, so a fresh
        # run does not look dead.
        complete = fingerprint_is_complete(fp)
        if complete or not self._latest_complete:
            paths.append(os.path.join(out, "latest.json"))
            self._latest_complete = self._latest_complete or complete
        if archive:
            paths.append(
                os.path.join(out, f"{int(fp['ts'])}_{fp['client_id'][:8]}.json")
            )
        for path in paths:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(blob)
            except OSError as e:
                logger.warning("h3fp: could not write %s: %r", path, e)


addons = [H3Fingerprint()]


# --------------------------------------------------------------------------
# self-check
# --------------------------------------------------------------------------


def _demo() -> None:
    def ext(t: int, body: bytes) -> bytes:
        return t.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body

    alpn_body = b"\x02h3"
    # Extensions the JS parser has and this addon did not: 1-byte and 2-byte
    # length prefixes both represented, so an off-by-one shows up here.
    exts = (
        ext(0x0A0A, b"")                                     # GREASE ext
        + ext(EXT_SNI, b"\x00\x0e\x00\x00\x0bexample.com")   # server_name
        + ext(EXT_ALPN, len(alpn_body).to_bytes(2, "big") + alpn_body)
        + ext(EXT_SUPPORTED_VERSIONS, b"\x02\x03\x04")
        + ext(EXT_SIG_ALGS, b"\x00\x06\x04\x03\x08\x04\x04\x03")  # 0x0403 twice
        + ext(EXT_SUPPORTED_GROUPS, b"\x00\x02\x00\x1d")
        + ext(EXT_EC_POINT_FORMATS, b"\x01\x00")             # 1-byte len: [0]
        + ext(EXT_KEY_SHARE, b"\x00\x24\x00\x1d\x00\x20" + b"\x11" * 32)
        + ext(EXT_PSK_KEY_EXCHANGE_MODES, b"\x01\x01")       # 1-byte len: [1]
        + ext(EXT_CERT_COMPRESSION, b"\x02\x00\x02")         # 1-byte len: [2]
        + ext(EXT_RECORD_SIZE_LIMIT, b"\x40\x01")            # 16385
        + ext(EXT_SIG_ALGS_CERT, b"\x00\x02\x04\x03")
        + ext(EXT_DELEGATED_CREDENTIALS, b"\x00\x02\x04\x03")
        + ext(EXT_ALPS, b"\x00\x03\x02h2")
        + ext(EXT_SESSION_TICKET, b"")
        + ext(EXT_EXTENDED_MASTER_SECRET, b"")
        + ext(EXT_ENCRYPT_THEN_MAC, b"")
        + ext(EXT_STATUS_REQUEST, b"")
        + ext(EXT_SCT, b"")
        + ext(EXT_PADDING, b"\x00\x00")
        + ext(EXT_QUIC_TP, b"\x01\x04\x80\x00\x75\x30" b"\x0e\x01\x02"
                           b"\x57\x3e\x00" b"\x3a\x00"
                           b"\x40\x99\x02\xab\xcd")           # unknown id 0x99
        + ext(0x0A0A, b"\x00")                                # 2nd ext, same id
    )
    ciphers = [0x1A1A, 0x1301, 0x1302, 0x1303]  # first is GREASE
    cs = b"".join(c.to_bytes(2, "big") for c in ciphers)
    body = (
        b"\x03\x03" + b"\xab" * 32 + b"\x00"
        + len(cs).to_bytes(2, "big") + cs
        + b"\x01\x00"
        + len(exts).to_bytes(2, "big") + exts
    )
    raw = b"\x01" + len(body).to_bytes(3, "big") + body

    ch = parse_client_hello(raw)
    assert ch["sni"] == "example.com", ch["sni"]
    assert ch["alpn"] == ["h3"], ch["alpn"]
    assert ch["supported_versions"] == [0x0304]
    assert ch["ec_point_formats"] == [0], ch["ec_point_formats"]
    assert ch["key_share_groups"] == [0x001D], ch["key_share_groups"]
    assert ch["psk_key_exchange_modes"] == [1], ch["psk_key_exchange_modes"]
    assert ch["cert_compression_algos"] == [2], ch["cert_compression_algos"]
    assert ch["record_size_limit"] == 16385, ch["record_size_limit"]
    assert ch["sig_algs_cert"] == [0x0403], ch["sig_algs_cert"]
    assert ch["delegated_credentials"] == [0x0403], ch["delegated_credentials"]
    assert ch["application_settings"] == ["h2"], ch["application_settings"]
    assert ch["session_ticket"] is True
    assert ch["extended_master_secret"] is True
    assert ch["encrypt_then_mac"] is True
    assert ch["status_request"] is True
    assert ch["signed_cert_timestamp"] is True
    assert ch["padding"] is True
    assert ch["compression_methods"] == [0], ch["compression_methods"]
    assert ch["session_id"] == "", ch["session_id"]
    # No TLS record header on this synthetic hello, and QUIC never has one.
    assert ch["record_version"] is None, ch["record_version"]

    tp = ch["quic_transport_parameters"]
    assert tp["max_idle_timeout"] == 30000, tp
    assert tp["active_connection_id_limit"] == 2, tp
    assert tp["grease_quic_bit"] is True, tp
    assert any(k.startswith("GREASE_") for k in tp["_order"]), tp["_order"]

    # -- machine-readable forms: wire order, duplicates, raw bytes ------------
    # A dict cannot hold this; real clients do send the same codepoint twice.
    assert ch["sig_algs"] == [0x0403, 0x0804, 0x0403], ch["sig_algs"]

    detail = ch["extensions_detail"]
    assert [d["id"] for d in detail] == ch["extensions"], detail
    assert [d["id"] for d in detail[:4]] ==         [0x0A0A, EXT_SNI, EXT_ALPN, EXT_SUPPORTED_VERSIONS], detail[:4]
    dup = [d for d in detail if d["id"] == 0x0A0A]
    assert len(dup) == 2 and [d["raw"] for d in dup] == ["", "00"], dup
    # Raw bodies round-trip: exactly the bytes that went into the hello.
    assert next(d for d in detail if d["id"] == EXT_SIG_ALGS)["raw"] ==         "000604030804" + "0403", detail

    assert ch["key_shares"] == [{"group": 0x001D, "key_length": 32}], ch["key_shares"]
    assert ch["key_share_groups"] == [k["group"] for k in ch["key_shares"]]

    tpl = ch["quic_transport_parameters_list"]
    assert [p["id"] for p in tpl] == [0x01, 0x0E, 0x173E, 0x3A, 0x99], tpl
    assert tpl[0] == {"id": 1, "name": "max_idle_timeout",
                      "value": 30000, "raw": "80007530"}, tpl[0]
    assert tpl[1] == {"id": 0x0E, "name": "active_connection_id_limit",
                      "value": 2, "raw": "02"}, tpl[1]
    assert tpl[2] == {"id": 0x173E, "name": "grease_quic_bit",
                      "value": None, "raw": ""}, tpl[2]
    # Reserved GREASE keeps its real id; only the name is normalised.
    assert tpl[3] == {"id": 0x3A, "name": "GREASE", "value": None, "raw": ""}, tpl[3]
    # Unknown ids get name None -- never an "unknown_0x.." display placeholder.
    assert tpl[4] == {"id": 0x99, "name": None, "value": None, "raw": "abcd"}, tpl[4]
    assert parse_transport_params_list(None) == []

    j3s, j3h = ja3(ch)
    j3ns, j3nh = ja3n(ch)
    assert (j3ns, j3nh) != (j3s, j3h), "extensions are not ascending, ja3n must differ"
    assert ja3n(ch) == (j3ns, j3nh), "ja3n must be stable"
    n_exts = j3ns.split(",")[2].split("-")
    assert n_exts == sorted(n_exts, key=int), n_exts
    # Only the extension field is reordered; everything else stays in wire order.
    assert j3ns.split(",")[:2] == j3s.split(",")[:2], j3ns
    assert j3ns.split(",")[3:] == j3s.split(",")[3:], j3ns

    sl = parse_h3_settings_list(b"@d3@@	")
    assert [e["id"] for e in sl] == [0x01, 0x07, 0x33, 0x40, 0x09], sl
    assert sl[0] == {"id": 1, "name": "QPACK_MAX_TABLE_CAPACITY", "value": 100}, sl[0]
    assert sl[3] == {"id": 0x40, "name": "GREASE", "value": 1}, sl[3]
    assert sl[4] == {"id": 0x09, "name": None, "value": 5}, sl[4]

    fp = ja4(ch, is_quic=True)
    # q=quic, 13=TLS1.3, d=SNI present, 03 ciphers + 20 extensions after GREASE
    # removal, h3=first/last char of ALPN.
    assert fp.startswith("q13d0320h3_"), fp
    assert len(fp.split("_")) == 3 and all(len(p) == 12 for p in fp.split("_")[1:]), fp

    # GREASE must not leak into JA3 either.
    assert "6666" not in ja3(ch)[0]  # 0x1a1a == 6682, 0x0a0a == 2570
    assert "2570" not in ja3(ch)[0]

    s = parse_h3_settings(b"\x01\x40\x64\x07\x10\x33\x01")
    assert s["QPACK_MAX_TABLE_CAPACITY"] == 100, s
    assert s["QPACK_BLOCKED_STREAMS"] == 16, s
    assert s["H3_DATAGRAM"] == 1, s

    # SETTINGS role split: mitmproxy's upstream (client-role) connection receives
    # the ORIGIN's settings; those must never land in the client fingerprint.
    class _Stub:
        def __init__(self, is_client, cid):
            self._is_client = is_client
            self._quic = type("Q", (), {"conn": type("C", (), {"id": cid})()})()

    assert _h3_peer_and_conn(_Stub(False, "cid-client")) == ("client", "cid-client")
    assert _h3_peer_and_conn(_Stub(True, "cid-server")) == ("server", "cid-server")
    assert _h3_peer_and_conn(object()) == ("unknown", None)

    _record_control_frame(_Stub(False, "cid-client"), 0x04, b"\x01\x40\x64")
    _record_control_frame(_Stub(True, "cid-server"), 0x04, b"\x01\x40\x64")
    assert "cid-server" not in _settings_by_conn, "origin settings leaked into fingerprint"
    assert _settings_by_conn["cid-client"]["settings"]["QPACK_MAX_TABLE_CAPACITY"] == 100
    assert _settings_by_conn["cid-client"]["settings_list"] ==         [{"id": 1, "name": "QPACK_MAX_TABLE_CAPACITY", "value": 100}],         _settings_by_conn["cid-client"]["settings_list"]

    _record_control_frame(_Stub(False, "cid-client"), 0x0D, b"\x08")
    # Client-initiated unidirectional stream ids (% 4 == 2). Streams mitmproxy
    # opens itself are % 4 == 3 and must be ignored, or the client's open order
    # is prefixed with three entries describing the proxy.
    _record_uni_stream(_Stub(False, "cid-client"), 2, 2)
    _record_uni_stream(_Stub(False, "cid-client"), 6, 0)
    _record_uni_stream(_Stub(False, "cid-client"), 3, 0)   # ours, must be ignored
    _record_uni_stream(_Stub(False, "cid-client"), 11, 3)  # ours, must be ignored
    _record_headers(_Stub(False, "cid-client"),
                    [(b":method", b"GET"), (b":scheme", b"https"),
                     (b":authority", b"x"), (b":path", b"/"), (b"user-agent", b"x")])
    cli = _settings_by_conn["cid-client"]
    assert cli["control_frames"] == ["SETTINGS", "MAX_PUSH_ID=8"], cli["control_frames"]
    assert cli["uni_streams"] == ["qpack_encoder", "control"], cli["uni_streams"]
    assert cli["pseudo_headers"] == "m,s,a,p", cli["pseudo_headers"]
    assert cli["header_order"] == ["user-agent"], cli["header_order"]

    # -- HTTP/2 prelude parsing, fed in awkward chunks like a real socket would --
    def h2f(length, ftype, flags, sid, payload):
        return (length.to_bytes(3, "big") + bytes([ftype, flags])
                + sid.to_bytes(4, "big") + payload)

    settings_payload = b"".join(i.to_bytes(2, "big") + v.to_bytes(4, "big")
                                for i, v in [(1, 65536), (2, 0), (4, 6291456), (6, 262144)])
    stream = (H2_PREFACE
              + h2f(len(settings_payload), 0x04, 0, 0, settings_payload)
              + h2f(4, 0x08, 0, 0, (15663105).to_bytes(4, "big"))
              + h2f(5, 0x02, 0, 3, (0x80000000 | 0).to_bytes(4, "big") + bytes([200]))
              + h2f(0, 0x04, 0, 0, b"")            # later SETTINGS must not clobber
              + h2f(0, 0x01, 0x04, 1, b"")          # HEADERS ends the prelude
              + h2f(4, 0x08, 0, 0, (999).to_bytes(4, "big")))  # must be ignored

    rec = new_h2_record()
    for k in range(0, len(stream), 7):              # deliberately ragged chunks
        h2_scan(rec, stream[k:k + 7])
    rec["pseudo_headers"] = "m,a,s,p"
    assert rec["_done"], "HEADERS frame must end the prelude"
    assert rec["window_update"] == 15663105, rec     # the post-HEADERS one ignored
    assert rec["priority"] == [(3, 1, 0, 201)], rec  # weight is payload+1
    assert h2_fingerprint(rec) == \
        "1:65536;2:0;4:6291456;6:262144|15663105|3:1:0:201|m,a,s,p", h2_fingerprint(rec)

    empty = new_h2_record()
    assert h2_fingerprint(empty) == "0|0|0|", h2_fingerprint(empty)

    assert safe_host("gew1-spclient.spotify.com") == "gew1-spclient.spotify.com"
    assert safe_host(None) == "no-sni"
    assert safe_host("../../etc/passwd") == ".._.._etc_passwd"  # no path traversal
    assert os.path.isabs(DEFAULT_OUT), "default output dir must not depend on cwd"

    report_fp = {
        "ts": 0, "sni": "example.com", "peername": "10.0.0.1:1", "transport": "quic",
        "ja4": fp, "ja3": "deadbeef", "ja3_string": "x", "alpn": ch["alpn"],
        "ciphers": [f"0x{c:04x}" for c in ch["ciphers"]],
        "extensions": [f"0x{e:04x}" for e in ch["extensions"]],
        "supported_versions": ["0x0304"], "supported_groups": ["0x001d"],
        "sig_algs": ["0x0403"], "quic_transport_parameters": tp,
        "h3_settings": s, "raw_client_hello": raw.hex(),
    }
    rpt = format_report(report_fp)
    flat = " ".join(rpt.split())  # keys are column-aligned; ignore the padding
    assert "max_idle_timeout = 30000" in flat, rpt
    assert "QPACK_BLOCKED_STREAMS = 16" in flat, rpt
    assert "_order" not in rpt, "internal key leaked into report"
    # Signature must change when SETTINGS arrive, so the later report is not deduped.
    assert fp_signature(report_fp) != fp_signature({**report_fp, "h3_settings": None})

    # ...but must NOT change when only per-connection randomness differs, or every
    # single connection appends another identical block.
    def _conn(g_cipher, g_ext, g_tp, g_h3, g_h3val, cid):
        """Same client, another connection: fresh GREASE and a fresh source CID."""
        stable_tp = {k: v for k, v in tp.items()
                     if k != "_order" and not k.startswith("GREASE_")}
        return {
            **report_fp,
            "ciphers": [g_cipher] + report_fp["ciphers"],
            "extensions": [g_ext] + report_fp["extensions"],
            "quic_transport_parameters": {
                **stable_tp, g_tp: True, "initial_source_connection_id": cid,
                "_order": [x for x in tp["_order"] if not x.startswith("GREASE_")]
                          + [g_tp, "initial_source_connection_id"],
            },
            "h3_settings": {**{k: v for k, v in s.items() if k != "_order"},
                            g_h3: g_h3val, "_order": s["_order"] + [g_h3]},
            "raw_client_hello": cid,
        }

    a = _conn("0x6a6a", "0xbaba", "GREASE_0x1f3b", "GREASE_0x9c1", 12345, "ff" * 8)
    b = _conn("0xcaca", "0xeaea", "GREASE_0x3a", "GREASE_0xb4f14a807", 99, "aa" * 8)
    assert fp_signature(a) == fp_signature(b), "GREASE re-roll defeats dedupe"

    # iOS reshuffles its transport parameters every connection; that must not read
    # as a new fingerprint.
    shuffled = {**b, "quic_transport_parameters": {
        **b["quic_transport_parameters"],
        "_order": list(reversed(b["quic_transport_parameters"]["_order"]))}}
    assert fp_signature(shuffled) == fp_signature(b), "TP reshuffle defeats dedupe"

    # A real change (one extra non-GREASE extension) must still register.
    assert fp_signature({**b, "extensions": b["extensions"] + ["0x001b"]}) != fp_signature(b)
    # An h2 prelude change is a new fingerprint even when the TLS half is identical.
    assert fp_signature({**b, "h2": {"fingerprint": "x"}}) != \
        fp_signature({**b, "h2": {"fingerprint": "y"}})
    # ...as is a different HTTP/3 pseudo-header order.
    assert fp_signature({**b, "h3": {"pseudo_headers": "m,a,s,p"}}) != \
        fp_signature({**b, "h3": {"pseudo_headers": "m,s,a,p"}})
    # ...as must a changed parameter value.
    assert fp_signature({**b, "quic_transport_parameters": {
        **b["quic_transport_parameters"], "max_idle_timeout": 1}}) != fp_signature(b)

    # The one real coupling to mitmproxy: raw_bytes() wraps the ClientHello in a
    # synthetic TLS record. Verify strip_prefix() survives that round-trip.
    try:
        from mitmproxy import tls as _mtls
    except ImportError:
        print("skip: mitmproxy not installed, raw_bytes round-trip unchecked")
    else:
        wrapped = _mtls.ClientHello(body).raw_bytes()
        assert wrapped[:1] == b"\x16", wrapped[:8]
        assert parse_client_hello(wrapped)["sni"] == "example.com"
        assert ja4(parse_client_hello(wrapped), is_quic=True) == fp

    # -- latest.json must survive a later connection's ClientHello -------------
    # Regression: tls_clienthello writes the fingerprint the moment the hello is
    # parsed, long before any HEADERS frame exists, so that snapshot carries no
    # h3/h2 block at all. With a single shared latest.json, every newly opened
    # connection wiped the completed fingerprint of the previous one. On a phone,
    # connections open constantly, so pseudo-header order looked unmeasured in
    # the one file anybody actually opens -- while the archived JSON had it.
    import tempfile

    complete = {**report_fp, "h3": {"pseudo_headers": "m,a,s,p"}}
    bare = {k: v for k, v in report_fp.items() if k != "h3_settings"}
    bare["sni"] = "audio.spotify.com"
    assert fingerprint_is_complete(complete)
    assert not fingerprint_is_complete(bare), "a ClientHello-only fp is not complete"

    saved_outdir = H3Fingerprint._outdir
    try:
        tmp = tempfile.mkdtemp()
        H3Fingerprint._outdir = staticmethod(lambda: tmp)
        addon = H3Fingerprint()

        addon._write(complete)
        latest = json.load(open(os.path.join(tmp, "latest.json"), encoding="utf-8"))
        assert latest["h3"]["pseudo_headers"] == "m,a,s,p", latest

        addon._write(bare)  # a second connection's ClientHello arrives
        latest = json.load(open(os.path.join(tmp, "latest.json"), encoding="utf-8"))
        assert latest.get("h3", {}).get("pseudo_headers") == "m,a,s,p", \
            "a bare ClientHello clobbered a completed fingerprint"

        # ...but a bare fingerprint is still worth showing while nothing better
        # has been captured, otherwise a fresh run looks dead.
        tmp2 = tempfile.mkdtemp()
        H3Fingerprint._outdir = staticmethod(lambda: tmp2)
        fresh = H3Fingerprint()
        fresh._write(bare)
        first = json.load(open(os.path.join(tmp2, "latest.json"), encoding="utf-8"))
        assert first["sni"] == "audio.spotify.com", first
    finally:
        H3Fingerprint._outdir = saved_outdir

    print("ok:", fp)
    print("tp:", {k: v for k, v in tp.items() if k != "_order"})
    print("h3 settings:", {k: v for k, v in s.items() if k != "_order"})


if __name__ == "__main__":
    _demo()
