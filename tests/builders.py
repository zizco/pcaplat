"""Small hand-built frames and capture files shared by the regression tests."""
import struct

from pcaplat.match import KeySpec, match, packet_keys
from pcaplat.reader import read_capture

SRC, DST = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])


def udp(payload=b"X", sport=123, dport=456, length=None):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload) if length is None else length, 0) + payload


def eth(ip, etype=0x0800):
    return bytes.fromhex("020000000002020000000001") + struct.pack("!H", etype) + ip


def ipv4(l4, proto=17, ident=1, frag=0, ihl_byte=0x45, total=None):
    t = 20 + len(l4) if total is None else total
    return eth(struct.pack("!BBHHHBBH4s4s", ihl_byte, 0, t, ident, frag, 64, proto, 0, SRC, DST) + l4)


def ipv6(raw, nh=17):
    return eth(struct.pack("!IHBB16s16s", 6 << 28, len(raw), nh, 64, b"\x01" * 16, b"\x02" * 16) + raw, 0x86DD)


def write_pcap(path, recs, link=1, nano=True):
    out = struct.pack("<IHHIIII", 0xA1B23C4D if nano else 0xA1B2C3D4, 2, 4, 0, 0, 65535, link)
    for r in recs:
        ts, frame = r[:2]
        orig = r[2] if len(r) > 2 else len(frame)
        sec, frac = divmod(ts, 10 ** 9)
        out += struct.pack("<IIII", sec, frac if nano else frac // 1000, len(frame), orig) + frame
    path.write_bytes(out)
    return read_capture(str(path))


def block(btype, body, e="<"):
    body += b"\0" * ((-len(body)) % 4)
    size = 12 + len(body)
    return struct.pack(e + "II", btype, size) + body + struct.pack(e + "I", size)


def shb(e="<"):
    return block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1), e)


def idb(res=9, offset=0, e="<"):
    opts = struct.pack(e + "HHB3x", 9, 1, res) + struct.pack(e + "HHq", 14, 8, offset) + bytes(4)
    return block(1, struct.pack(e + "HHI", 1, 0, 65535) + opts, e)


def epb(t, frame, iface=0, e="<", caplen=None):
    cl = len(frame) if caplen is None else caplen
    return block(6, struct.pack(e + "IIIII", iface, t >> 32, t & 0xFFFFFFFF, cl, len(frame)) + frame, e)


def pair(tmp_path, a, b, **kw):
    ca, cb = write_pcap(tmp_path / "a.pcap", a), write_pcap(tmp_path / "b.pcap", b)
    return match(packet_keys(ca, KeySpec()), packet_keys(cb, KeySpec()), **kw)


F = ipv4(udp(b"X"))
