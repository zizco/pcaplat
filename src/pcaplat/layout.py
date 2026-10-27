"""Vectorized packet layout and hashing.

Fast path: Ethernet (up to two VLAN tags) + IPv4, including IPv4 fragments,
is decoded for all packets at once with numpy. Everything else (IPv6, Linux
SLL, raw IP, three or more VLAN tags, malformed headers) goes through the
scalar decoder in decode.py. Both paths produce the same layout,
and a single vectorized hash is applied afterwards, so keys are identical
whichever path a packet took. tests/test_layout.py checks that equivalence.

All offsets here are absolute offsets into the capture buffer.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .decode import LINKTYPE_ETHERNET, decode
from .reader import Capture

_FNV_OFFSET = np.uint64(0xCBF29CE484222325)
_FNV_PRIME = np.uint64(0x100000001B3)
_V4_MAPPED = np.array([0] * 10 + [0xFF, 0xFF], dtype=np.uint8)


@dataclass
class Layout:
    ok: np.ndarray          # bool, packet is IP and was decoded
    proto: np.ndarray       # uint8
    addr: np.ndarray        # uint8 (n, 32): src(16) + dst(16), IPv4 as v4-mapped IPv6
    sport: np.ndarray       # uint16
    dport: np.ndarray       # uint16
    frame_start: np.ndarray  # int64
    l3_end: np.ndarray      # int64
    pay_off: np.ndarray     # int64
    pay_end: np.ndarray     # int64
    truncated: np.ndarray   # bool
    fragment: np.ndarray    # bool, part of a fragmented datagram
    fast: np.ndarray        # bool, decoded by the vectorized path


def _u16(B, idx):
    return (B[idx].astype(np.uint16) << 8) | B[idx + 1]


def compute_layout(cap: Capture, select: np.ndarray | None = None, force_scalar: bool = False) -> Layout:
    """Decode every selected packet. ``force_scalar`` disables the fast path (used by tests)."""
    n = len(cap)
    B = np.frombuffer(cap.buf, dtype=np.uint8) if n else np.zeros(1, np.uint8)
    last = len(B) - 1
    base = cap.data_off.astype(np.int64)
    end = base + cap.cap_len.astype(np.int64)
    sel = np.ones(n, dtype=bool) if select is None else np.asarray(select, dtype=bool)

    def at(idx):                       # safe gather: out-of-range indices read a dummy byte
        return B[np.clip(idx, 0, last)]

    def u16(idx):
        return (at(idx).astype(np.uint16) << 8) | at(idx + 1)

    lay = Layout(
        ok=np.zeros(n, bool), proto=np.zeros(n, np.uint8), addr=np.zeros((n, 32), np.uint8),
        sport=np.zeros(n, np.uint16), dport=np.zeros(n, np.uint16), frame_start=base.copy(),
        l3_end=base.copy(), pay_off=base.copy(), pay_end=base.copy(),
        truncated=np.zeros(n, bool), fragment=np.zeros(n, bool), fast=np.zeros(n, bool))

    # ---- vectorized Ethernet / VLAN / IPv4
    eth = sel & (cap.linktype == LINKTYPE_ETHERNET) & (cap.cap_len >= 14)
    et = u16(base + 12)
    o = np.full(n, 14, dtype=np.int64)
    for _ in range(2):
        tag = eth & np.isin(et, (0x8100, 0x88A8, 0x9100)) & (base + o + 4 <= end)
        et = np.where(tag, u16(base + o + 2), et)
        o = np.where(tag, o + 4, o)
    l3 = base + o
    v4 = eth & (et == 0x0800) & (l3 + 20 <= end) & ((at(l3) >> 4) == 4)
    ihl = (at(l3) & 0x0F).astype(np.int64) * 4
    total = u16(l3 + 2).astype(np.int64)
    proto = at(l3 + 9)
    flags_frag = u16(l3 + 6)
    nonfirst = (flags_frag & 0x1FFF) != 0
    fragment = nonfirst | ((flags_frag & 0x2000) != 0)
    l3_end_true = l3 + total
    l3_end = np.minimum(l3_end_true, end)
    truncated = l3_end_true > end
    l4 = l3 + ihl
    is_udp, is_tcp = proto == 17, proto == 6
    transport = ~nonfirst & (is_udp | is_tcp)
    need = np.where(is_udp, 8, 20)
    hdr_fits = l4 + need <= l3_end                 # within the captured bytes
    hdr_fits_declared = l4 + need <= l3_end_true   # within the length the IP header declares
    udp = transport & is_udp & hdr_fits
    tcp = transport & is_tcp & hdr_fits
    ulen = u16(l4 + 4).astype(np.int64)
    doff = (at(l4 + 12) >> 4).astype(np.int64) * 4
    # Same rules as decode.py: invalid headers are not decoded at all. Upper
    # bounds are checked against the declared IP length; a first fragment is
    # exempt because the rest of its datagram is carried by later fragments.
    malformed = ((ihl < 20) | (total < ihl)
                 | (transport & ~hdr_fits_declared & ~fragment)
                 | (udp & ((ulen < 8) | ((l4 + ulen > l3_end_true) & ~fragment)))
                 | (tcp & ((doff < 20) | ((l4 + doff > l3_end_true) & ~fragment))))
    v4 &= ~malformed                       # malformed rows go to the scalar decoder, which rejects them
    if force_scalar:
        v4 = np.zeros(n, dtype=bool)
    pay_off = np.minimum(l4, l3_end)
    pay_end = l3_end.copy()
    cut = transport & ~hdr_fits            # transport header cut by snaplen or in a later fragment
    pay_off = np.where(cut, l3_end, pay_off)
    pay_off = np.where(udp, l4 + 8, pay_off)
    pay_end = np.where(udp, np.minimum(l4 + ulen, l3_end), pay_end)
    pay_off = np.where(tcp, np.minimum(l4 + doff, l3_end), pay_off)
    pay_end = np.maximum(pay_off, pay_end)
    ports = udp | tcp

    idx = np.nonzero(v4)[0]
    lay.ok[idx] = True
    lay.fast[idx] = True
    lay.proto[idx] = proto[idx]
    lay.addr[idx, 0:12] = _V4_MAPPED
    lay.addr[idx, 16:28] = _V4_MAPPED
    for k in range(4):
        lay.addr[idx, 12 + k] = at(l3[idx] + 12 + k)
        lay.addr[idx, 28 + k] = at(l3[idx] + 16 + k)
    pidx = np.nonzero(ports & v4)[0]
    lay.sport[pidx] = u16(l4[pidx])
    lay.dport[pidx] = u16(l4[pidx] + 2)
    lay.l3_end[idx] = l3_end[idx]
    lay.pay_off[idx] = pay_off[idx]
    lay.pay_end[idx] = pay_end[idx]
    lay.truncated[idx] = truncated[idx]
    lay.fragment[idx] = fragment[idx]

    # ---- scalar fallback for everything the fast path did not take
    mv = memoryview(cap.buf) if n else None
    for i in np.nonzero(sel & ~v4)[0]:
        b0, e0 = int(base[i]), int(end[i])
        d = decode(mv[b0:e0], int(cap.linktype[i]))
        if d is None:
            continue
        lay.ok[i] = True
        lay.proto[i] = d.proto & 0xFF
        lay.addr[i, :16] = np.frombuffer(_to16(d.src), np.uint8)
        lay.addr[i, 16:] = np.frombuffer(_to16(d.dst), np.uint8)
        lay.sport[i], lay.dport[i] = d.sport, d.dport
        lay.l3_end[i] = b0 + d.l3_end
        lay.pay_off[i] = b0 + d.pay_off
        lay.pay_end[i] = b0 + d.pay_end
        lay.fragment[i] = d.fragment
        lay.truncated[i] = d.truncated
    return lay


def _to16(a: bytes) -> bytes:
    return bytes(_V4_MAPPED) + a if len(a) == 4 else a


def _mix(h: np.ndarray) -> np.ndarray:
    """splitmix64 finalizer, to spread FNV's weak low bits."""
    h = h ^ (h >> np.uint64(30))
    h = h * np.uint64(0xBF58476D1CE4E5B9)
    h = h ^ (h >> np.uint64(27))
    h = h * np.uint64(0x94D049BB133111EB)
    return h ^ (h >> np.uint64(31))


def hash_rows(B: np.ndarray, header: np.ndarray | None, starts: np.ndarray, lengths: np.ndarray) -> np.ndarray:
    """FNV-1a 64 over (header row bytes, then B[start : start + length]) for every row."""
    n = len(starts)
    h = np.full(n, _FNV_OFFSET, dtype=np.uint64)
    with np.errstate(over="ignore"):
        if header is not None:
            for j in range(header.shape[1]):
                h = (h ^ header[:, j].astype(np.uint64)) * _FNV_PRIME
        if n:
            order = np.argsort(-lengths, kind="stable")      # longest first: shrink the active set
            s, L = starts[order], lengths[order]
            hh = h[order]
            maxlen = int(L[0]) if n else 0
            negL = -L
            for j in range(maxlen):
                active = int(np.searchsorted(negL, -j, side="left"))   # rows with length > j
                if not active:
                    break
                hh[:active] = (hh[:active] ^ B[s[:active] + j].astype(np.uint64)) * _FNV_PRIME
            h[order] = hh
        return _mix(h)
