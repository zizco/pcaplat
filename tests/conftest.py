import struct

import pytest

from pcaplat.synth import udp_frame


def ipv6_udp_frame(payload: bytes, src: bytes, dst: bytes, sport: int, dport: int) -> bytes:
    eth = b"\x33\x33\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x86\xdd"
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    ip6 = struct.pack("!IHBB", 6 << 28, len(udp) + len(payload), 17, 64) + src + dst
    return eth + ip6 + udp + payload


def tcp_frame(payload: bytes) -> bytes:
    eth = b"\x02" * 6 + b"\x02\x00\x00\x00\x00\x03" + b"\x08\x00"
    tcp = struct.pack("!HHIIBBHHH", 40000, 9000, 1, 0, 5 << 4, 0x18, 1024, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0, bytes([10, 1, 1, 1]), bytes([10, 1, 1, 2]))
    return eth + ip + tcp + payload


def fragment_frame() -> bytes:
    eth = b"\x02" * 6 + b"\x02\x00\x00\x00\x00\x04" + b"\x08\x00"
    payload = b"FRAGMENT-TAIL-BYTES"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 7, 185, 64, 17, 0,
                     bytes([10, 2, 2, 2]), bytes([10, 2, 2, 3]))
    return eth + ip + payload


def arp_frame() -> bytes:
    return b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x05" + b"\x08\x06" + bytes(28)


@pytest.fixture
def mixed_frames():
    src, dst = bytes([10, 0, 0, 1]), bytes([233, 54, 12, 1])
    v6s, v6d = bytes(range(16)), bytes(range(16, 32))
    return [
        udp_frame(b"PLAIN-UDP-PAYLOAD", src, dst, 30001, 31001),
        udp_frame(b"VLAN-UDP-PAYLOAD", src, dst, 30001, 31001, vlan=100),
        udp_frame(b"ab", src, dst, 30001, 31001),                       # padded to 60 bytes
        udp_frame(b"TRAILER", src, dst, 30001, 31001) + b"\xee" * 12,   # vendor trailer after IP
        ipv6_udp_frame(b"IPV6-UDP-PAYLOAD", v6s, v6d, 1111, 2222),
        tcp_frame(b"TCP-PAYLOAD-BYTES"),
        fragment_frame(),
        arp_frame(),
    ]
