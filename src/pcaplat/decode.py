"""Minimal, allocation-light decoding of Ethernet / VLAN / IPv4 / IPv6 / UDP / TCP.

Every length is bounded by the IP header's own length field, not by the
captured frame length. That keeps Ethernet minimum-size padding and any
vendor timestamp trailer appended after the IP packet out of the payload,
so the same packet hashes identically at both capture points.

Invalid headers make the packet undecodable rather than being read as if
they were valid: IPv4 header length below 20 bytes or above the total length,
UDP length below 8 or beyond the declared IP payload, TCP data offset below 5
or beyond the declared IP payload, an IPv6 extension header running past the
declared payload. "Declared" matters: a header that fits the declared IP
length but was cut by the snap length is truncated, not malformed. A non-first
fragment carries no transport header: its ports are left at zero and it is
flagged, so that matching can refuse to key it on payload alone.
"""
from __future__ import annotations

from dataclasses import dataclass

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

_VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)
_IPV6_EXT = (0, 43, 60)          # hop-by-hop, routing, destination options
_IPV6_FRAG, _IPV6_AH = 44, 51


@dataclass(slots=True)
class Decoded:
    proto: int          # IP protocol number (17 UDP, 6 TCP, ...)
    src: bytes
    dst: bytes
    sport: int
    dport: int
    l3_off: int         # offset of the IP header in the frame
    l3_end: int         # offset just past the IP packet (bounded by caplen)
    pay_off: int        # offset of the L4 payload
    pay_end: int        # offset just past the L4 payload (bounded by caplen)
    truncated: bool     # snaplen cut the IP packet short
    fragment: bool = False   # part of a fragmented datagram (first or later)


def _u16(b: memoryview, o: int) -> int:
    return (b[o] << 8) | b[o + 1]


def decode(frame: memoryview, linktype: int) -> Decoded | None:
    """Return the IP/L4 layout of a frame, or None if it is not valid IP."""
    n = len(frame)
    if linktype == LINKTYPE_ETHERNET:
        if n < 14:
            return None
        etype, o = _u16(frame, 12), 14
        while etype in _VLAN_TPIDS and o + 4 <= n:
            etype, o = _u16(frame, o + 2), o + 4
    elif linktype == LINKTYPE_LINUX_SLL:
        if n < 16:
            return None
        etype, o = _u16(frame, 14), 16
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if n < 1:
            return None
        etype, o = (0x0800 if frame[0] >> 4 == 4 else 0x86DD), 0
    else:
        return None

    if etype == 0x0800:
        return _ipv4(frame, o, n)
    if etype == 0x86DD:
        return _ipv6(frame, o, n)
    return None


def _ipv4(b: memoryview, o: int, n: int) -> Decoded | None:
    if o + 20 > n or b[o] >> 4 != 4:
        return None
    ihl = (b[o] & 0x0F) * 4
    total = _u16(b, o + 2)
    if ihl < 20 or total < ihl:
        return None
    proto = b[o + 9]
    flags_frag = _u16(b, o + 6)
    offset, more = flags_frag & 0x1FFF, bool(flags_frag & 0x2000)
    l3_end_true = o + total
    l3_end = min(l3_end_true, n)
    l4 = o + ihl
    src, dst = bytes(b[o + 12: o + 16]), bytes(b[o + 16: o + 20])
    truncated = l3_end_true > n
    if offset:          # non-first fragment: no transport header to read
        return Decoded(proto, src, dst, 0, 0, o, l3_end, min(l4, l3_end), l3_end, truncated, True)
    return _l4(b, proto, src, dst, o, l4, l3_end, l3_end_true, truncated, more)


def _ipv6(b: memoryview, o: int, n: int) -> Decoded | None:
    if o + 40 > n or b[o] >> 4 != 6:
        return None
    l3_end_true = o + 40 + _u16(b, o + 4)
    l3_end = min(l3_end_true, n)
    truncated = l3_end_true > n
    nh, l4 = b[o + 6], o + 40
    src, dst = bytes(b[o + 8: o + 24]), bytes(b[o + 24: o + 40])
    fragment = False
    while nh in _IPV6_EXT or nh in (_IPV6_FRAG, _IPV6_AH):
        if l4 + 8 > l3_end_true:        # extension header past the declared payload: malformed
            return None
        if l4 + 8 > l3_end:             # cut by the snap length
            return Decoded(nh, src, dst, 0, 0, o, l3_end, l3_end, l3_end, True, fragment)
        if nh == _IPV6_FRAG:            # fixed 8 bytes: next header, reserved, offset/flags, id
            off_flags = _u16(b, l4 + 2)
            offset, more = off_flags >> 3, bool(off_flags & 1)
            nh, nxt = b[l4], l4 + 8
            if offset or more:
                fragment = True
            if offset:                  # non-first fragment: what follows is not a transport header
                return Decoded(nh, src, dst, 0, 0, o, l3_end, nxt, l3_end, truncated, True)
        elif nh == _IPV6_AH:            # length in 32-bit words, minus 2
            nh, nxt = b[l4], l4 + (b[l4 + 1] + 2) * 4
        else:
            nh, nxt = b[l4], l4 + (b[l4 + 1] + 1) * 8
        if nxt > l3_end_true:
            return None
        l4 = nxt
    return _l4(b, nh, src, dst, o, l4, l3_end, l3_end_true, truncated, fragment)


def _l4(b, proto, src, dst, l3_off, l4, l3_end, l3_end_true, truncated, fragment) -> Decoded | None:
    """Transport layer. ``l3_end`` is bounded by the captured bytes, ``l3_end_true``
    is where the IP header says the packet ends."""
    sport = dport = 0
    if proto in (17, 6):
        need = 8 if proto == 17 else 20
        if l4 + need > l3_end_true and not fragment:
            return None                 # the IP packet is too short for this header: malformed
        if l4 + need > l3_end:          # cut by snaplen, or carried in a later fragment
            return Decoded(proto, src, dst, 0, 0, l3_off, l3_end, l3_end, l3_end, truncated, fragment)
        sport, dport = _u16(b, l4), _u16(b, l4 + 2)
        if proto == 17:
            ulen = _u16(b, l4 + 4)
            if ulen < 8 or (l4 + ulen > l3_end_true and not fragment):
                return None
            pay_off, pay_end = l4 + 8, min(l4 + ulen, l3_end)
        else:
            doff = (b[l4 + 12] >> 4) * 4
            if doff < 20 or (l4 + doff > l3_end_true and not fragment):
                return None
            pay_off, pay_end = min(l4 + doff, l3_end), l3_end
    else:
        pay_off, pay_end = min(l4, l3_end), l3_end
    return Decoded(proto, src, dst, sport, dport, l3_off, l3_end, pay_off, max(pay_off, pay_end),
                   truncated, fragment)
