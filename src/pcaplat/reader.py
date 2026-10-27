"""Read pcap and pcapng files into integer-nanosecond arrays.

Timestamps are kept as int64 nanoseconds since the epoch, never as float
seconds: a float64 holding an epoch time in seconds has a resolution of
roughly 240 ns, which silently destroys nanosecond captures.

Interfaces get a global index across pcapng sections (each section restarts
its own interface numbering), and every packet carries the resolution and
FCS length of the interface that captured it.
"""
from __future__ import annotations

import mmap
import os
import struct
from dataclasses import dataclass, field

import numpy as np

# magic as read little-endian -> (file byte order, nanoseconds per fractional unit)
_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1_000),  # microsecond resolution
    0xD4C3B2A1: (">", 1_000),
    0xA1B23C4D: ("<", 1),      # nanosecond resolution
    0x4D3CB2A1: (">", 1),
}
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_BOM = 0x1A2B3C4D
_PCAPNG_BOM_SWAPPED = 0x4D3C2B1A       # the same magic, written big-endian, read little-endian
_EPB_FIXED = 20             # interface id, ts high, ts low, captured length, original length
_SHB_MIN = 28               # type, length, byte-order magic, major, minor, section length, length


@dataclass
class Interface:
    index: int              # global index in this file
    section: int
    local_id: int           # interface id inside its pcapng section
    linktype: int
    resolution_ns: float
    resolution: str
    tsoffset_s: int = 0
    fcs_bytes: int = 0      # FCS bytes at the end of each captured frame (0 if absent)
    tsresol_code: int = 6   # pcapng if_tsresol byte


@dataclass
class Capture:
    """Packets of one capture file, as parallel arrays.

    Packet bytes are not copied: ``data_off`` and ``cap_len`` index into ``buf``.
    """
    path: str
    fmt: str                      # "pcap" or "pcapng"
    ts_ns: np.ndarray             # int64, ns since epoch
    orig_len: np.ndarray          # int32, length on the wire as recorded
    cap_len: np.ndarray           # int32, captured length
    data_off: np.ndarray          # int64, offset of packet bytes in buf
    linktype: np.ndarray          # int32, link-layer type per packet
    iface: np.ndarray             # int32, global interface index (0 for pcap)
    res_ns: np.ndarray            # float64, timestamp resolution of each packet, in ns
    fcs_bytes: np.ndarray         # int16, FCS bytes included at the end of each frame
    interfaces: list = field(default_factory=list)
    issues: list = field(default_factory=list)   # malformed or incomplete data that was skipped
    buf: object = field(default=None, repr=False)

    def __len__(self) -> int:
        return len(self.ts_ns)

    def packet(self, i: int) -> memoryview:
        off = int(self.data_off[i])
        return memoryview(self.buf)[off: off + int(self.cap_len[i])]

    @property
    def duration_ns(self) -> int:
        return int(self.ts_ns.max() - self.ts_ns.min()) if len(self) else 0

    @property
    def ts_resolution(self) -> str:
        used = sorted({int(i) for i in np.unique(self.iface)}) if len(self) else []
        names = [self.interfaces[i].resolution for i in used] if used else \
            [itf.resolution for itf in self.interfaces]
        return ", ".join(dict.fromkeys(names)) or "unknown"


def read_capture(path: str) -> Capture:
    """Open a pcap or pcapng file (format detected from its magic number)."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) if size else b""
    if len(buf) < 4:
        raise ValueError(f"{path}: file too short to be a capture")
    magic = struct.unpack_from("<I", buf, 0)[0]
    if magic in _PCAP_MAGICS:
        return _read_pcap(path, buf, *_PCAP_MAGICS[magic])
    if magic == _PCAPNG_SHB:
        return _read_pcapng(path, buf)
    raise ValueError(f"{path}: unknown capture format (magic 0x{magic:08x})")


def _capture(path, fmt, cols, interfaces, issues, buf, fcs_override=None) -> Capture:
    """``fcs_override`` holds a per-packet FCS length in bytes, or -1 to use the interface's."""
    ts, ol, cl, do, ifc = cols
    ifc = np.asarray(ifc, dtype=np.int32)
    lt = np.array([interfaces[i].linktype for i in range(len(interfaces))], dtype=np.int32)
    res = np.array([interfaces[i].resolution_ns for i in range(len(interfaces))], dtype=np.float64)
    fcs = np.array([interfaces[i].fcs_bytes for i in range(len(interfaces))], dtype=np.int16)
    fcs_pkt = fcs[ifc] if len(ifc) else np.zeros(0, np.int16)
    if fcs_override is not None and len(ifc):
        ov = np.asarray(fcs_override, dtype=np.int16)
        fcs_pkt = np.where(ov >= 0, ov, fcs_pkt).astype(np.int16)
    return Capture(
        path=path, fmt=fmt,
        ts_ns=np.asarray(ts, dtype=np.int64),
        orig_len=np.asarray(ol, dtype=np.int32),
        cap_len=np.asarray(cl, dtype=np.int32),
        data_off=np.asarray(do, dtype=np.int64),
        linktype=lt[ifc] if len(ifc) else np.zeros(0, np.int32),
        iface=ifc,
        res_ns=res[ifc] if len(ifc) else np.zeros(0, np.float64),
        fcs_bytes=fcs_pkt,
        interfaces=interfaces, issues=issues, buf=buf,
    )


def _read_pcap(path, buf, endian, frac_to_ns) -> Capture:
    if len(buf) < 24:
        raise ValueError(f"{path}: truncated pcap global header")
    # The 32-bit "LinkType and additional information" field: the link type is
    # in the low 16 bits; bit 26 (F) says the FCS length in bits 28-31 is valid,
    # counted in 16-bit words.
    field_ = struct.unpack_from(endian + "I", buf, 20)[0]
    linktype = field_ & 0xFFFF
    fcs_bytes = ((field_ >> 28) & 0xF) * 2 if field_ & (1 << 26) else 0
    itf = Interface(0, 0, 0, linktype, float(frac_to_ns), "1 ns" if frac_to_ns == 1 else "1 us",
                    fcs_bytes=fcs_bytes)
    rec = struct.Struct(endian + "IIII")
    n = len(buf)
    off = 24
    ts, ol, cl, do = [], [], [], []
    issues = []
    short_orig = [0, 0]                   # [count, first offset] of records with orig_len < incl_len
    while off + 16 <= n:
        sec, frac, incl, orig = rec.unpack_from(buf, off)
        if off + 16 + incl > n:
            issues.append(f"incomplete last record at byte {off} was ignored")
            break
        if orig < incl:
            if not short_orig[0]:
                short_orig[1] = off
            short_orig[0] += 1
            orig = incl
        off += 16
        ts.append(sec * 1_000_000_000 + frac * frac_to_ns)
        ol.append(orig)
        cl.append(incl)
        do.append(off)
        off += incl
    if off < n and not issues:
        issues.append(f"{n - off} trailing bytes after the last record were ignored")
    if short_orig[0]:
        issues.append(_SHORT_ORIG.format(count=short_orig[0], first=short_orig[1]))
    return _capture(path, "pcap", (ts, ol, cl, do, [0] * len(ts)), [itf], issues, buf)


_SHORT_ORIG = ("packets whose original length is below their captured length (captured length used as "
               "original length): {count:,} (first at byte {first})")


def _tsresol_to_ns(value: int, code: int) -> int:
    """Convert a raw pcapng timestamp to ns, given the if_tsresol byte."""
    exp = code & 0x7F
    if code & 0x80:                       # resolution 2^-exp seconds
        return (value * 1_000_000_000) >> exp
    if exp <= 9:                          # resolution 10^-exp seconds
        return value * 10 ** (9 - exp)
    return value // 10 ** (exp - 9)


def _tsresol_info(code: int) -> tuple[float, str]:
    exp = code & 0x7F
    if code & 0x80:
        return 1e9 / (2 ** exp), f"2^-{exp} s"
    return 1e9 / (10 ** exp), {6: "1 us", 9: "1 ns", 3: "1 ms"}.get(exp, f"1e-{exp} s")


def _read_pcapng(path, buf) -> Capture:
    """Read a pcapng file.

    Structural problems (bad section headers, mismatched block lengths, unreadable
    or contradictory interface options, packets that do not fit their block) go to
    ``Capture.issues``; packet-level ones are counted by kind. A malformed
    if_tsresol or if_tsoffset makes the interface unreadable instead of guessed.
    if_fcslen is in bits; the epb_flags FCS length is in octets and overrides it.
    """
    n = len(buf)
    off = 0
    endian = "<"
    section = -1
    interfaces: list[Interface] = []
    local: dict[int, int] = {}            # local interface id -> global index (-1: unreadable IDB)
    ts, ol, cl, do, ifc, fcs_ov = [], [], [], [], [], []
    issues: list[str] = []
    counted: dict[str, list] = {}         # packet-level problem -> [count, first byte offset, packet dropped]
    stopped = False

    def skip(reason: str, at: int, dropped: bool = True) -> None:
        entry = counted.setdefault(reason, [0, at, dropped])
        entry[0] += 1

    while off + 12 <= n:
        btype = struct.unpack_from(endian + "I", buf, off)[0]
        if btype == _PCAPNG_SHB:
            bom_le = struct.unpack_from("<I", buf, off + 8)[0]
            if bom_le == _PCAPNG_BOM:
                endian = "<"
            elif bom_le == _PCAPNG_BOM_SWAPPED:
                endian = ">"
            else:
                if off == 0:
                    raise ValueError(f"{path}: section header has an invalid byte-order magic "
                                     f"0x{bom_le:08x}; not a pcapng file")
                issues.append(f"section header at byte {off} has an invalid byte-order magic "
                              f"0x{bom_le:08x}; rest of file ignored")
                stopped = True
                break
            section += 1
            local = {}                        # interface numbering restarts in each section
        blen = struct.unpack_from(endian + "I", buf, off + 4)[0]
        if blen < 12 or blen % 4 or off + blen > n:
            issues.append(f"malformed or incomplete block at byte {off}; rest of file ignored")
            stopped = True
            break
        trailer = struct.unpack_from(endian + "I", buf, off + blen - 4)[0]
        if trailer != blen:
            issues.append(f"block at byte {off} has leading length {blen} but trailing length {trailer}; "
                          f"this block and the rest of the file were ignored")
            stopped = True
            break
        body, body_end = off + 8, off + blen - 4
        if btype == _PCAPNG_SHB:
            if blen < _SHB_MIN:                              # magic, versions and section length are mandatory
                msg = f"section header at byte {off} is {blen} bytes long, below the minimum of {_SHB_MIN}"
                if off == 0:
                    raise ValueError(f"{path}: {msg}; not a valid pcapng file")
                issues.append(f"{msg}; rest of file ignored")
                stopped = True
                break
            major = struct.unpack_from(endian + "H", buf, body + 4)[0]
            if major != 1:
                issues.append(f"section header at byte {off} has major version {major}, not 1; "
                              f"rest of file ignored")
                stopped = True
                break
        elif btype == 1:                                     # Interface Description Block
            problem = None
            if body + 8 > body_end:
                problem = "is too short to read"
            else:
                linktype = struct.unpack_from(endian + "H", buf, body)[0]
                opts, problem, notes = _idb_options(buf, endian, body + 8, body_end)
                issues.extend(f"interface description block at byte {off}: {note}" for note in notes)
            if problem:
                local[len(local)] = -1                       # keep later interface ids aligned
                issues.append(f"interface description block at byte {off} {problem}; "
                              f"packets on that interface are skipped")
            else:
                code = opts.get("tsresol", 6)                # absent: microseconds, per the specification
                res_ns, res_txt = _tsresol_info(code)
                g = len(interfaces)
                interfaces.append(Interface(g, section, len(local), linktype, res_ns, res_txt,
                                            opts.get("tsoffset", 0), opts.get("fcs", 0), code))
                local[len(local)] = g
        elif btype == 6:                                     # Enhanced Packet Block
            if body + _EPB_FIXED > body_end:
                skip("enhanced packet blocks too short to hold a packet header", off)
            else:
                iid, th, tl, caplen, origlen = struct.unpack_from(endian + "IIIII", buf, body)
                data = body + _EPB_FIXED
                if iid not in local:
                    skip(f"packets referring to unknown interface {iid}", off)
                elif local[iid] < 0:
                    skip(f"packets referring to interface {iid}, whose description block is unreadable", off)
                elif data + caplen > body_end:
                    skip("packets declaring more captured bytes than their block holds", off)
                else:
                    itf = interfaces[local[iid]]
                    if origlen < caplen:
                        skip("packets whose original length is below their captured length "
                             "(captured length used as original length)", off, dropped=False)
                        origlen = caplen
                    fcs, bad_opts = _epb_fcs(buf, endian, data + ((caplen + 3) & ~3), body_end)
                    if bad_opts:
                        skip("packets with malformed options (options ignored, packets kept)", off, dropped=False)
                    ts.append(_tsresol_to_ns((th << 32) | tl, itf.tsresol_code)
                              + itf.tsoffset_s * 1_000_000_000)
                    ol.append(origlen)
                    cl.append(caplen)
                    do.append(data)
                    ifc.append(itf.index)
                    fcs_ov.append(fcs)
        elif btype == 3:
            skip("simple packet blocks, which carry no timestamp", off)
        elif btype == 2:
            skip("obsolete packet blocks (type 2), not read", off)
        # Other block types (name resolution, statistics, decryption secrets,
        # custom) carry no packets and are skipped by design.
        off += blen
    if not stopped and off < n:
        issues.append(f"{n - off} bytes after the last complete block (an incomplete block) were ignored")
    for reason, (count, first, dropped) in counted.items():
        issues.append(f"{reason}: {count:,}{' skipped' if dropped else ''} (first at byte {first})")
    if not interfaces:
        interfaces.append(Interface(0, 0, 0, 0, float("nan"), "unknown"))
    return _capture(path, "pcapng", (ts, ol, cl, do, ifc), interfaces, issues, buf, fcs_ov)


# Interface options with a fixed length: code -> (name, length in bytes)
_IDB_FIXED = {9: ("if_tsresol", 1), 13: ("if_fcslen", 1), 14: ("if_tsoffset", 8)}


def _idb_options(buf, endian: str, o: int, end: int):
    """Parse IDB options -> (options, problem, notes).

    ``problem``: the timestamp metadata cannot be trusted (overrun, wrong length,
    conflicting repeats). ``notes``: issues that leave the interface usable.
    """
    values: dict[int, bytes] = {}
    notes: list[str] = []
    fcs_bad = False
    while o + 4 <= end:
        ocode, olen = struct.unpack_from(endian + "HH", buf, o)
        if ocode == 0:
            break
        if o + 4 + olen > end:
            return {}, f"has option {ocode} declaring {olen} bytes past the end of the block", notes
        if ocode in _IDB_FIXED:
            name, want = _IDB_FIXED[ocode]
            if olen != want:
                if ocode != 13:
                    return {}, f"has {name} of length {olen}, not {want}: its timestamps cannot be trusted", notes
                notes.append(f"{name} has length {olen}, not {want}; FCS length ignored")
                fcs_bad = True
            else:
                raw = bytes(buf[o + 4: o + 4 + want])
                if ocode in values and values[ocode] != raw:
                    if ocode != 13:
                        return {}, (f"has conflicting {name} options ({_opt_text(ocode, values[ocode], endian)} "
                                    f"and {_opt_text(ocode, raw, endian)}): its timestamps cannot be trusted"), notes
                    notes.append(f"conflicting {name} options; FCS length ignored")
                    fcs_bad = True
                elif ocode in values:
                    notes.append(f"{name} appears more than once (same value); the specification allows it once")
                values[ocode] = raw
        o += 4 + ((olen + 3) & ~3)
    opts: dict = {}
    if 9 in values:
        opts["tsresol"] = values[9][0]
    if 14 in values:
        opts["tsoffset"] = struct.unpack(endian + "q", values[14])[0]
    if 13 in values and not fcs_bad:
        bits = values[13][0]
        if bits % 8:
            notes.append(f"if_fcslen of {bits} bits is not a whole number of bytes; FCS length ignored")
        else:
            opts["fcs"] = bits // 8
    return opts, None, notes


def _opt_text(code: int, raw: bytes, endian: str) -> str:
    if code == 14:
        return f"{struct.unpack(endian + 'q', raw)[0]} s"
    if code == 9:
        return _tsresol_info(raw[0])[1]
    return str(raw[0])


def _epb_fcs(buf, endian: str, o: int, end: int) -> tuple[int, bool]:
    """(FCS length in octets from epb_flags bits 5-8, or -1 if not stated; options malformed)."""
    fcs = -1
    while o + 4 <= end:
        ocode, olen = struct.unpack_from(endian + "HH", buf, o)
        if ocode == 0:
            break
        if o + 4 + olen > end or (ocode == 2 and olen != 4):
            return -1, True
        if ocode == 2:
            flags = struct.unpack_from(endian + "I", buf, o + 4)[0]
            v = (flags >> 5) & 0xF
            fcs = v if v else -1              # 0 means "not available": keep the interface value
        o += 4 + ((olen + 3) & ~3)
    return fcs, False
