"""mitmproxy addon: write the client's raw QUIC datagrams to a pcap.

mitmproxy terminates QUIC, so mitm_h3_fingerprint.py can only describe what is
*inside* the handshake. Packet shape is destroyed by termination and lives only
in the datagrams themselves:

    coalescing, connection-id lengths, padding target, packet-number encoded
    length, CRYPTO frame splits and byte counts, varint widths, token, frame
    order

Those datagrams do still arrive here intact, so this writes them out for offline
analysis. scripts/quic_initial_analyze.py reads the result unchanged -- Initial
packets need no keys, RFC 9001 s5.2 derives their secrets from the clear-text
Destination Connection ID.

Run:
    mitmdump --mode wireguard -s scripts/quic_pcap.py

Self-check (no mitmproxy needed):
    python scripts/quic_pcap.py

FIDELITY CAVEAT. These are the datagrams as they arrive at the proxy, which on
WireGuard means after tunnel decryption. Everything below the UDP payload is the
tunnel's, not the phone's: no original IP TTL, DF, ECN or fragmentation, and
timestamps are arrival-at-proxy rather than wire time. WireGuard's MTU (~1420)
also sits under the client's path MTU, so a client that would size larger
datagrams natively may size them smaller here. Initial padding to 1200 is a QUIC
constant and survives. For MTU-sensitive work a native capture is still the
ground truth; this is the automatic, always-on companion to it.
"""

from __future__ import annotations

import functools
import logging
import os
import struct
import time
from typing import Any

logger = logging.getLogger("quicpcap")

# LINKTYPE_RAW: each record is a bare IP packet, no link layer to invent.
LINKTYPE_RAW = 101
PCAP_MAGIC = 0xA1B2C3D4

_hook_state = "not attempted"


# --------------------------------------------------------------------------
# pcap writing
# --------------------------------------------------------------------------


def pcap_global_header() -> bytes:
    return struct.pack(
        "<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 262144, LINKTYPE_RAW
    )


def pcap_record(ts: float, packet: bytes) -> bytes:
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack("<IIII", sec, usec, len(packet), len(packet)) + packet


def ip_checksum(header: bytes) -> int:
    """RFC 1071 one's-complement sum. Required on IPv4; readers reject bad ones."""
    if len(header) % 2:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip4(addr: str) -> bytes:
    try:
        parts = [int(p) for p in addr.split(".")]
        if len(parts) == 4 and all(0 <= p <= 255 for p in parts):
            return bytes(parts)
    except (ValueError, AttributeError):
        pass
    # IPv6 or a name: synthesise a stable placeholder rather than dropping the
    # datagram. The QUIC payload is the point; the address only has to keep
    # flows distinguishable.
    return b"\x0a" + (abs(hash(addr)) % 0xFFFFFF).to_bytes(3, "big")


def udp_datagram(src: str, sport: int, dst: str, dport: int, payload: bytes) -> bytes:
    """One IPv4 + UDP packet wrapping payload. UDP checksum 0 is legal on IPv4."""
    udp = struct.pack("!HHHH", sport & 0xFFFF, dport & 0xFFFF, 8 + len(payload), 0) + payload
    total_len = 20 + len(udp)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0x4000, 64, 17, 0, _ip4(src), _ip4(dst),
    )
    checksum = ip_checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:] + udp


class PcapWriter:
    """Append-only pcap. Opened lazily so a run with no QUIC leaves no file."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._fh = None
        self.datagrams = 0
        self.bytes = 0

    def write(self, ts: float, packet: bytes) -> None:
        if self._fh is None:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            self._fh = open(self.path, "wb")
            self._fh.write(pcap_global_header())
        self._fh.write(pcap_record(ts, packet))
        self._fh.flush()  # a killed proxy must still leave a readable capture
        self.datagrams += 1
        self.bytes += len(packet)

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


# --------------------------------------------------------------------------
# hooks
# --------------------------------------------------------------------------


def _patch(cls, name: str, make_wrapper) -> str:
    """Idempotently wrap cls.name. Returns a status string."""
    orig = getattr(cls, name, None)
    if orig is None:
        return f"{cls.__name__}.{name} ABSENT"
    if getattr(orig, "_quicpcap_patched", False):
        return f"{cls.__name__}.{name} already"
    wrapper = make_wrapper(orig)
    functools.update_wrapper(wrapper, orig)
    wrapper._quicpcap_patched = True
    setattr(cls, name, wrapper)
    return f"{cls.__name__}.{name} ok"


def install_hooks(sink) -> str:
    """Capture datagrams where they ARRIVE, not where they are fed to aioquic.

    aioquic's QuicConnection.receive_datagram looks like the obvious target and
    is the wrong one: mitmproxy buffers handshake datagrams in
    handshake_datagram_buf and replays them into it, so every Initial would be
    counted twice. The layer's receive methods are each called once per arriving
    datagram, and the replay bypasses them.
    """
    global _hook_state
    try:
        from mitmproxy.proxy.layers.quic import _stream_layers as sl
    except Exception as e:
        _hook_state = f"failed: {e!r}"
        return _hook_state

    def capture(is_handshake):
        def make(orig):
            def w(self, data, *a, **kw):
                try:
                    sink(self, bytes(data or b""), is_handshake)
                except Exception as e:  # telemetry must never break the proxy
                    logger.warning("quicpcap: capture failed: %r", e)
                return orig(self, data, *a, **kw)
            return w
        return make

    _hook_state = "; ".join([
        # ClientQuicLayer overrides this; QuicLayer.receive_data is shared with
        # the upstream layer and filtered by connection identity in the sink.
        _patch(sl.ClientQuicLayer, "receive_handshake_data", capture(True)),
        _patch(sl.QuicLayer, "receive_data", capture(False)),
    ])
    return _hook_state


DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")


class QuicPcap:
    def __init__(self) -> None:
        self.writers: dict[str, PcapWriter] = {}
        self._started = time.time()

    def load(self, loader):
        loader.add_option(
            "quic_pcap_out", str, DEFAULT_OUT,
            "Directory for raw QUIC datagram captures.",
        )
        loader.add_option(
            "quic_pcap_handshake_only", bool, True,
            "Capture only handshake datagrams. Post-handshake traffic is mostly "
            "ACKs and carries little fingerprint value, but grows the file fast.",
        )

    def running(self):
        logger.info("quicpcap: hooks %s", install_hooks(self._on_datagram))
        logger.info("quicpcap: writing to %s", self._outdir())

    # -- capture -----------------------------------------------------------

    def _on_datagram(self, layer: Any, data: bytes, is_handshake: bool) -> None:
        if not data:
            return
        conn = getattr(layer, "conn", None)
        context = getattr(layer, "context", None)
        # Only the client's own datagrams describe the client. QuicLayer.receive_data
        # is shared with the upstream-facing layer, whose data is the origin's.
        if conn is None or context is None or conn is not getattr(context, "client", None):
            return
        if not is_handshake and self._option("quic_pcap_handshake_only", True):
            return

        peer = getattr(conn, "peername", None) or ("10.0.0.2", 0)
        sock = getattr(conn, "sockname", None) or ("10.0.0.1", 443)
        packet = udp_datagram(str(peer[0]), int(peer[1]), str(sock[0]), int(sock[1]), data)
        self._writer(conn).write(time.time(), packet)

    def _writer(self, conn) -> PcapWriter:
        cid = getattr(conn, "id", "unknown")
        w = self.writers.get(cid)
        if w is None:
            name = f"{int(self._started)}_{str(cid)[:8]}.pcap"
            w = PcapWriter(os.path.join(self._outdir(), name))
            self.writers[cid] = w
        return w

    def done(self):
        total = sum(w.datagrams for w in self.writers.values())
        for w in self.writers.values():
            w.close()
        if total:
            logger.info("quicpcap: wrote %d datagrams across %d connection(s) to %s",
                        total, len(self.writers), self._outdir())

    # -- options -----------------------------------------------------------

    @staticmethod
    def _option(name: str, default):
        try:
            from mitmproxy import ctx
            return getattr(ctx.options, name, default)
        except Exception:
            return default

    def _outdir(self) -> str:
        out = os.path.abspath(self._option("quic_pcap_out", DEFAULT_OUT))
        os.makedirs(out, exist_ok=True)
        return out


addons = [QuicPcap()]


# --------------------------------------------------------------------------
# self-check
# --------------------------------------------------------------------------


def _demo() -> None:
    import tempfile

    # A realistic client Initial: long header, version 1, 8-byte DCID, padded.
    payload = (
        b"\xc0\x00\x00\x00\x01\x08" + b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
        + b"\x00\x00\x41\x03" + b"\xab" * 1180
    )
    packet = udp_datagram("10.0.0.2", 54321, "10.0.0.1", 443, payload)

    # IPv4 header must be exactly 20 bytes and self-consistent, or readers drop it.
    assert packet[0] == 0x45, packet[:4]
    total_len = int.from_bytes(packet[2:4], "big")
    assert total_len == len(packet) == 20 + 8 + len(payload), (total_len, len(packet))
    assert packet[9] == 17, "protocol must be UDP"
    # Checksum over the header including the stored sum must come out zero.
    assert ip_checksum(packet[:20]) == 0, "IPv4 header checksum invalid"
    assert int.from_bytes(packet[24:26], "big") == 8 + len(payload), "UDP length"
    assert packet[28:] == payload, "payload must survive byte-for-byte"

    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "t.pcap")
    w = PcapWriter(path)
    assert not os.path.exists(path), "file must not be created until something is written"
    w.write(1_700_000_000.5, packet)
    w.write(1_700_000_001.0, packet)
    w.close()
    assert w.datagrams == 2

    blob = open(path, "rb").read()
    magic, vmaj, _, _, _, snap, link = struct.unpack("<IHHiIII", blob[:24])
    assert magic == PCAP_MAGIC and vmaj == 2, (hex(magic), vmaj)
    assert link == LINKTYPE_RAW, link

    # The real acceptance test: the reader quic_initial_analyze.py uses must see
    # the datagrams, and the QUIC payload must come back untouched.
    try:
        from scapy.all import IP, UDP, PcapReader
    except ImportError:
        print("skip: scapy not installed, pcap round-trip unchecked")
    else:
        with PcapReader(path) as r:
            pkts = list(r)
        assert len(pkts) == 2, len(pkts)
        p = pkts[0]
        assert IP in p and UDP in p, p.summary()
        assert p[IP].src == "10.0.0.2" and p[IP].dst == "10.0.0.1"
        assert p[UDP].sport == 54321 and p[UDP].dport == 443
        assert bytes(p[UDP].payload) == payload, "QUIC payload altered in transit"
        # quic_initial_analyze.py checks this to detect a truncating snaplen.
        declared = p[IP].len - p[IP].ihl * 4 - 8
        assert declared == len(payload), (declared, len(payload))
        # And the Initial must still be recognisable as one.
        assert bytes(p[UDP].payload)[0] & 0xF0 == 0xC0, "not a long-header Initial"

    # Non-dotted addresses (IPv6, hostnames) must degrade, not explode.
    v6 = udp_datagram("fe80::1", 1, "fe80::2", 2, b"\x00")
    assert ip_checksum(v6[:20]) == 0 and v6[12:16] != v6[16:20], "flows must stay distinct"

    print("ok: pcap writer, LINKTYPE_RAW, %d-byte packet" % len(packet))


if __name__ == "__main__":
    _demo()
