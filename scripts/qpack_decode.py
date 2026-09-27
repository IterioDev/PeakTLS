"""Decode QPACK encoder-stream instructions and request field sections from tshark dumps.

Inputs (tab-separated, produced by tshark -T fields):
  quic_streams_spotify.tsv : conn, frame, pn, stream_id, fin, hex(stream_data)
Prints, per connection: the encoder instruction list with decoded names/values, then
for every client request stream its HEADERS prefix and field-line kinds.
"""
import sys
from collections import defaultdict

try:
    from hpack.huffman_table import decode_huffman  # hpack >= 4
except ImportError:  # pragma: no cover
    from hpack.huffman import HuffmanDecoder
    from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
    _dec = HuffmanDecoder(REQUEST_CODES, REQUEST_CODES_LENGTH)
    def decode_huffman(b):
        return _dec.decode(b)

# RFC 9204 Appendix A static table (name, value).
STATIC = [
 (":authority",""),(":path","/"),("age","0"),("content-disposition",""),("content-length","0"),
 ("cookie",""),("date",""),("etag",""),("if-modified-since",""),("if-none-match",""),
 ("last-modified",""),("link",""),("location",""),("referer",""),("set-cookie",""),
 (":method","CONNECT"),(":method","DELETE"),(":method","GET"),(":method","HEAD"),(":method","OPTIONS"),
 (":method","POST"),(":method","PUT"),(":scheme","http"),(":scheme","https"),(":status","103"),
 (":status","200"),(":status","304"),(":status","404"),(":status","503"),("accept","*/*"),
 ("accept","application/dns-message"),("accept-encoding","gzip, deflate, br"),("accept-ranges","bytes"),
 ("access-control-allow-headers","cache-control"),("access-control-allow-headers","content-type"),
 ("access-control-allow-origin","*"),("cache-control","max-age=0"),("cache-control","max-age=2592000"),
 ("cache-control","max-age=604800"),("cache-control","no-cache"),("cache-control","no-store"),
 ("cache-control","public, max-age=31536000"),("content-encoding","br"),("content-encoding","gzip"),
 ("content-type","application/dns-message"),("content-type","application/javascript"),
 ("content-type","application/json"),("content-type","application/x-www-form-urlencoded"),
 ("content-type","image/gif"),("content-type","image/jpeg"),("content-type","image/png"),
 ("content-type","text/css"),("content-type","text/html; charset=utf-8"),("content-type","text/plain"),
 ("content-type","text/plain;charset=utf-8"),("range","bytes=0-"),
 ("strict-transport-security","max-age=31536000"),
 ("strict-transport-security","max-age=31536000; includesubdomains"),
 ("strict-transport-security","max-age=31536000; includesubdomains; preload"),
 ("vary","accept-encoding"),("vary","origin"),("x-content-type-options","nosniff"),
 ("x-xss-protection","1; mode=block"),(":status","100"),(":status","204"),(":status","206"),
 (":status","302"),(":status","400"),(":status","403"),(":status","421"),(":status","425"),
 (":status","500"),("accept-language",""),("access-control-allow-credentials","FALSE"),
 ("access-control-allow-credentials","TRUE"),("access-control-allow-headers","*"),
 ("access-control-allow-methods","get"),("access-control-allow-methods","get, post, options"),
 ("access-control-allow-methods","options"),("access-control-expose-headers","content-length"),
 ("access-control-request-headers","content-type"),("access-control-request-method","get"),
 ("access-control-request-method","post"),("alt-svc","clear"),("authorization",""),
 ("content-security-policy","script-src 'none'; object-src 'none'; base-uri 'none'"),
 ("early-data","1"),("expect-ct",""),("forwarded",""),("if-range",""),("origin",""),
 ("purpose","prefetch"),("server",""),("timing-allow-origin","*"),("upgrade-insecure-requests","1"),
 ("user-agent",""),("x-forwarded-for",""),("x-frame-options","deny"),("x-frame-options","sameorigin"),
]
assert len(STATIC) == 99


def read_int(buf, pos, prefix_bits):
    """RFC 7541 s5.1 integer with an N-bit prefix at buf[pos]. Returns (value, new_pos)."""
    mask = (1 << prefix_bits) - 1
    value = buf[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    m = 0
    while True:
        b = buf[pos]
        pos += 1
        value += (b & 0x7F) << m
        m += 7
        if not b & 0x80:
            return value, pos


def read_string(buf, pos, prefix_bits):
    huff = bool(buf[pos] & (1 << prefix_bits))
    length, pos = read_int(buf, pos, prefix_bits)
    raw = buf[pos:pos + length]
    pos += length
    text = decode_huffman(raw) if huff else raw
    if isinstance(text, bytes):
        text = text.decode("latin-1")
    return text, huff, length, pos


def show(v, n=48):
    return v if len(v) <= n else v[:n] + f"...({len(v)})"


def decode_encoder_stream(hexdata):
    buf = bytes.fromhex(hexdata)
    pos = 0
    table = []  # absolute index -> (name, value)
    out = []
    if buf[0] != 0x02:
        out.append(f"!! stream type {buf[0]:#x}, expected 0x02")
    pos = 1
    while pos < len(buf):
        b = buf[pos]
        if b & 0x80:  # Insert With Name Reference
            static = bool(b & 0x40)
            idx, pos = read_int(buf, pos, 6)
            if static:
                name = STATIC[idx][0]
                ref = f"static[{idx}]"
            else:
                abs_i = len(table) - 1 - idx
                name = table[abs_i][0]
                ref = f"dyn[rel {idx} = abs {abs_i}]"
            value, vh, vlen, pos = read_string(buf, pos, 7)
            table.append((name, value))
            out.append(f"  #{len(table)-1:<3} INSERT name-ref {ref:<14} {name} = {show(value)}  [value H={int(vh)} len={vlen}]")
        elif b & 0x40:  # Insert With Literal Name
            name, nh, nlen, pos = read_string(buf, pos, 5)
            value, vh, vlen, pos = read_string(buf, pos, 7)
            table.append((name, value))
            out.append(f"  #{len(table)-1:<3} INSERT literal-name          {name} = {show(value)}  [name H={int(nh)} len={nlen}; value H={int(vh)} len={vlen}]")
        elif b & 0x20:  # Set Dynamic Table Capacity
            cap, pos = read_int(buf, pos, 5)
            out.append(f"  SET CAPACITY {cap}")
        else:  # Duplicate
            idx, pos = read_int(buf, pos, 5)
            abs_i = len(table) - 1 - idx
            table.append(table[abs_i])
            out.append(f"  #{len(table)-1:<3} DUPLICATE dyn[rel {idx} = abs {abs_i}] {table[abs_i][0]}")
    return table, out


def decode_field_section(buf, pos, end, table, max_entries):
    """Decode one HEADERS payload buf[pos:end]. Returns list of description lines."""
    lines = []
    enc_ric, pos = read_int(buf, pos, 8)
    if enc_ric == 0:
        ric = 0
    else:
        full = 2 * max_entries
        ric = enc_ric - 1  # caller-side reconstruction is lossy without TotalInserts; fine for a dump
    sign = bool(buf[pos] & 0x80)
    delta, pos = read_int(buf, pos, 7)
    base = ric - delta - 1 if sign else ric + delta
    lines.append(f"    prefix: EncRIC={enc_ric} (RIC~{ric}) S={int(sign)} Delta={delta} -> Base={base}")
    while pos < end:
        b = buf[pos]
        if b & 0x80:  # Indexed Field Line
            static = bool(b & 0x40)
            idx, pos = read_int(buf, pos, 6)
            if static:
                n, v = STATIC[idx]
                lines.append(f"    indexed static[{idx}]      {n}: {show(v)}")
            else:
                abs_i = base - 1 - idx
                n, v = table[abs_i] if 0 <= abs_i < len(table) else ("?", "?")
                lines.append(f"    indexed dyn[abs {abs_i}]     {n}: {show(v)}")
        elif b & 0x40:  # Literal With Name Reference
            never = bool(b & 0x20)
            static = bool(b & 0x10)
            idx, pos = read_int(buf, pos, 4)
            value, vh, vlen, pos = read_string(buf, pos, 7)
            if static:
                n = STATIC[idx][0]
                lines.append(f"    literal name-ref static[{idx}] {n}: {show(value)}  [H={int(vh)} len={vlen} N={int(never)}]")
            else:
                abs_i = base - 1 - idx
                n = table[abs_i][0] if 0 <= abs_i < len(table) else "?"
                lines.append(f"    literal name-ref dyn[abs {abs_i}] {n}: {show(value)}  [H={int(vh)} len={vlen} N={int(never)}]")
        elif b & 0x20:  # Literal With Literal Name
            never = bool(b & 0x10)
            name, nh, nlen, pos = read_string(buf, pos, 3)
            value, vh, vlen, pos = read_string(buf, pos, 7)
            lines.append(f"    literal literal-name        {name}: {show(value)}  [name H={int(nh)} len={nlen}; value H={int(vh)} len={vlen} N={int(never)}]")
        elif b & 0x10:  # Indexed With Post-Base Index
            idx, pos = read_int(buf, pos, 4)
            abs_i = base + idx
            n, v = table[abs_i] if 0 <= abs_i < len(table) else ("?", "?")
            lines.append(f"    indexed post-base[{idx}] abs {abs_i}  {n}: {show(v)}")
        else:  # Literal With Post-Base Name Reference
            never = bool(b & 0x08)
            idx, pos = read_int(buf, pos, 3)
            value, vh, vlen, pos = read_string(buf, pos, 7)
            abs_i = base + idx
            n = table[abs_i][0] if 0 <= abs_i < len(table) else "?"
            lines.append(f"    literal post-base-name[{idx}] abs {abs_i} {n}: {show(value)}  [H={int(vh)} len={vlen} N={int(never)}]")
    return lines


def decode_request_stream(hexdata, table, max_entries):
    buf = bytes.fromhex(hexdata)
    pos = 0
    lines = []
    while pos < len(buf):
        ftype, pos = read_varint(buf, pos)
        flen, pos = read_varint(buf, pos)
        end = pos + flen
        if end > len(buf):
            lines.append(f"    frame type {ftype:#x} len {flen} TRUNCATED (have {len(buf)-pos})")
            break
        if ftype == 0x1:
            lines.append(f"  HEADERS len={flen}")
            lines.extend(decode_field_section(buf, pos, end, table, max_entries))
        elif ftype == 0x0:
            lines.append(f"  DATA len={flen}")
        else:
            lines.append(f"  frame type {ftype:#x} len={flen}")
        pos = end
    return lines


def read_varint(buf, pos):
    first = buf[pos]
    length = 1 << (first >> 6)
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | buf[pos + i]
    return value, pos + length


def main(path):
    per_conn_streams = defaultdict(lambda: defaultdict(list))  # conn -> sid -> [(frame, hex)]
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6 or not parts[5]:
                continue
            conn, frame, pn, sid, fin, data = parts[:6]
            # tshark joins several STREAM frames of one packet with commas
            sids = sid.split(",")
            datas = data.split(",")
            for s, d in zip(sids, datas):
                per_conn_streams[conn][int(s)].append((int(frame), d))
    for conn in sorted(per_conn_streams, key=int):
        streams = per_conn_streams[conn]
        print(f"=== connection {conn} ===")
        enc_hex = "".join(d for _, d in sorted(streams.get(6, [])))
        table, enc_lines = decode_encoder_stream(enc_hex) if enc_hex else ([], ["  (no encoder stream)"])
        print(f"encoder stream: {len(enc_hex)//2} bytes, {len(table)} inserts")
        print("\n".join(enc_lines))
        dec_hex = "".join(d for _, d in sorted(streams.get(10, [])))
        print(f"decoder stream hex: {dec_hex}")
        ctrl_hex = "".join(d for _, d in sorted(streams.get(2, [])))
        print(f"control stream hex: {ctrl_hex}")
        max_entries = 4096 // 32
        for sid in sorted(s for s in streams if s % 4 == 0):
            data = "".join(d for _, d in sorted(streams[sid]))
            first_frame = min(fr for fr, _ in streams[sid])
            print(f"-- request stream {sid} (first frame {first_frame}, {len(data)//2} bytes)")
            try:
                print("\n".join(decode_request_stream(data, table, max_entries)))
            except Exception as e:  # keep going on partial captures
                print(f"    decode error: {e!r}")


if __name__ == "__main__":
    main(sys.argv[1])
