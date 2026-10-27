"""Cohort accounting, header length bounds, FCS metadata, pcapng structure,
negative latencies on the CCDF and burst scaling.
"""
import json
import struct
import time

import numpy as np
import pytest

from builders import block, epb, idb, ipv4, ipv6, pair, shb, udp, write_pcap
from pcaplat.bursts import burst_profile
from pcaplat.cli import main
from pcaplat.decode import decode
from pcaplat.layout import compute_layout
from pcaplat.match import KeySpec, packet_keys
from pcaplat.reader import read_capture
from pcaplat.stats import summarize


def tcp(payload=b"", offset_words=5):
    return struct.pack("!HHIIBBHHH", 123, 456, 1, 0, offset_words << 4, 0x10, 1024, 0, 0) + payload


def idb_fcs(bits=None, res=9):
    opts = struct.pack("<HHB3x", 9, 1, res)
    if bits is not None:
        opts += struct.pack("<HHB3x", 13, 1, bits)
    return block(1, struct.pack("<HHI", 1, 0, 65535) + opts + bytes(4))


def epb_opts(t, frame, opts=b"", iface=0):
    pad = bytes((-len(frame)) % 4)
    return block(6, struct.pack("<IIIII", iface, t >> 32, t & 0xFFFFFFFF, len(frame), len(frame)) + frame + pad + opts)


def epb_flags(fcs_octets):
    return struct.pack("<HHI", 2, 4, fcs_octets << 5) + bytes(4)        # epb_flags, then end of options


def ng(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return read_capture(str(p))


FRAME60 = ipv4(udp(b"X")) + bytes(60 - len(ipv4(udp(b"X"))))       # minimum Ethernet frame, no FCS
FRAME64 = FRAME60 + bytes(4)                                       # the same frame with its FCS


# ---------------------------------------------------------------- cohort accounting
def _negative_cohort(tmp_path):
    a = [(0, ipv4(udp(b"S"))), (1000, ipv4(udp(b"P"))), (2000, ipv4(udp(b"N"))),
         (3000, ipv4(udp(b"L"))), (10000, ipv4(udp(b"E")))]
    b = [(100, ipv4(udp(b"S"))), (1100, ipv4(udp(b"P"))), (1500, ipv4(udp(b"N"))),
         (10100, ipv4(udp(b"E")))]
    return a, b


def test_clock_invalid_members_stay_in_the_cohort(tmp_path):
    a, b = _negative_cohort(tmp_path)
    r = pair(tmp_path, a, b, max_latency_ns=1000)
    c = r.counts
    assert (c["cohort"], c["matched_in_cohort"], c["clock_invalid_in_cohort"], c["lost"]) == (3, 1, 1, 1)
    s = summarize(r.matched["latency_ns"].to_numpy(), lost=c["lost"], late=c["late_in_cohort"],
                  cohort_latency_ns=r.loss_aware_latencies())
    assert s["cohort"] == c["cohort"] == 3
    assert s["loss_rate"] == pytest.approx(c["loss_rate"]) == pytest.approx(1 / 3)
    assert s["clock_invalid"] == 1 and s["ranked_in_loss_aware"] == 2


def test_cli_reports_one_cohort_and_explains_clock_invalid_members(tmp_path):
    a, b = _negative_cohort(tmp_path)
    write_pcap(tmp_path / "a.pcap", a)
    write_pcap(tmp_path / "b.pcap", b)
    out = tmp_path / "rep"
    assert main(["latency", str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap"),
                 "--max-latency", "1us", "--out", str(out)]) == 0
    s = json.loads((out / "summary.json").read_text())
    assert s["counts"]["cohort"] == s["summary"]["cohort"] == 3
    assert s["counts"]["loss_rate"] == pytest.approx(s["summary"]["loss_rate"])
    md = (out / "report.md").read_text()
    assert "clock-invalid" in md and "| **Cohort** | **3** |" in md


def test_late_packets_outside_the_cohort_are_not_claimed_in_the_table(tmp_path):
    # One packet, two milliseconds late: it is late, but no B packet brackets it, so it is not in the cohort.
    write_pcap(tmp_path / "a.pcap", [(100, ipv4(udp(b"Q")))])
    write_pcap(tmp_path / "b.pcap", [(2_000_000, ipv4(udp(b"Q")))])
    out = tmp_path / "rep"
    assert main(["latency", str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap"), "--out", str(out)]) == 0
    s = json.loads((out / "summary.json").read_text())
    assert s["counts"]["late_beyond_window"] == 1 and s["summary"]["late"] == 0
    md = (out / "report.md").read_text()
    assert "counted as infinitely late in the loss-aware table" not in md
    assert "outside the loss cohort" in md


# ---------------------------------------------------------------- header upper bounds
@pytest.mark.parametrize("frame", [
    ipv4(udp(b"X", length=100)),                    # UDP length 100 inside a 9-byte IP payload
    ipv4(tcp(offset_words=15), proto=6),            # TCP header length 60 inside a 20-byte segment
    ipv6(bytes([59, 255]) + bytes(6), nh=0),        # hop-by-hop header of 2048 bytes in an 8-byte payload
    ipv6(bytes([17, 4]) + bytes(6), nh=51),         # AH of 24 bytes in an 8-byte payload
], ids=["udp-length", "tcp-offset", "ipv6-hop-by-hop", "ipv6-ah"])
def test_headers_longer_than_the_declared_ip_packet_are_rejected(tmp_path, frame):
    cap = write_pcap(tmp_path / "bad.pcap", [(100, frame)])
    assert decode(memoryview(frame), 1) is None
    assert not compute_layout(cap).ok[0] and not compute_layout(cap, force_scalar=True).ok[0]
    assert len(packet_keys(cap, KeySpec())) == 0


def test_malformed_packet_does_not_match_a_valid_one(tmp_path):
    bad, good = ipv4(udp(b"X", length=100)), ipv4(udp(b"X"))
    assert pair(tmp_path, [(100, bad)], [(200, good)]).counts["matched"] == 0


@pytest.mark.parametrize("cut", [38, 46], ids=["in-udp-header", "in-payload"])
def test_snaplen_cut_is_truncation_not_malformation(tmp_path, cut):
    full = ipv4(udp(b"PAYLOAD-" * 4))
    cap = write_pcap(tmp_path / "t.pcap", [(100, full[:cut], len(full))])
    d = decode(memoryview(full[:cut]), 1)
    assert d is not None and d.truncated
    for lay in (compute_layout(cap), compute_layout(cap, force_scalar=True)):
        assert lay.ok[0] and lay.truncated[0]
    skipped = packet_keys(cap, KeySpec()).attrs["skipped"]
    assert skipped["truncated"] == 1 and skipped["not_ip_or_malformed"] == 0


def test_first_fragment_may_declare_a_longer_datagram(tmp_path):
    first = ipv4(struct.pack("!HHHH", 123, 456, 100, 0) + b"ABCDEFGH", frag=0x2000)   # more fragments
    cap = write_pcap(tmp_path / "f.pcap", [(100, first)])
    for lay in (compute_layout(cap), compute_layout(cap, force_scalar=True)):
        assert lay.ok[0] and lay.fragment[0] and lay.sport[0] == 123


# ---------------------------------------------------------------- FCS metadata
def test_if_fcslen_is_in_bits(tmp_path):
    assert ng(tmp_path, "a.pcapng", shb() + idb_fcs(32) + epb(0, FRAME64)).fcs_bytes.tolist() == [4]
    odd = ng(tmp_path, "b.pcapng", shb() + idb_fcs(4) + epb(0, FRAME60))
    assert odd.fcs_bytes.tolist() == [0] and any("4 bits" in i for i in odd.issues)


def test_epb_flags_fcs_length_overrides_the_interface(tmp_path):
    data = shb() + idb_fcs() + epb_opts(0, FRAME64, epb_flags(4)) + epb_opts(10_000, FRAME64, epb_flags(4))
    cap = ng(tmp_path, "o.pcapng", data)
    assert cap.fcs_bytes.tolist() == [4, 4]
    r = burst_profile(cap.ts_ns, cap.orig_len, 1e9, (1000,), fcs_in_capture=cap.fcs_bytes > 0)[0]
    assert r["peak_bits"] == 672                    # 64 + 8 + 12 bytes, FCS counted once
    # epb_flags without an FCS length keeps the interface value
    keep = ng(tmp_path, "k.pcapng", shb() + idb_fcs(32) + epb_opts(0, FRAME64, epb_flags(0)))
    assert keep.fcs_bytes.tolist() == [4]


def test_bursts_cli_uses_per_packet_fcs(tmp_path):
    p = tmp_path / "o.pcapng"
    p.write_bytes(shb() + idb_fcs() + epb_opts(0, FRAME64, epb_flags(4)) + epb_opts(10_000, FRAME64, epb_flags(4)))
    out = tmp_path / "rep"
    assert main(["bursts", str(p), "--line-rate", "1G", "--windows", "1us", "--out", str(out)]) == 0
    assert json.loads((out / "bursts.json").read_text())["windows"][0]["peak_bits"] == 672


def test_latency_load_uses_each_packets_fcs(tmp_path):
    # Interface 0 frames exclude the FCS, interface 1 frames include it: 672 wire bits each.
    other = ipv4(udp(b"Y")) + bytes(60 - len(ipv4(udp(b"Y"))))
    last = ipv4(udp(b"Z")) + bytes(60 - len(ipv4(udp(b"Z"))))
    p = tmp_path / "m.pcapng"
    p.write_bytes(shb() + idb_fcs(0) + idb_fcs(32) + epb(0, FRAME60, 0) + epb(10_000, other + bytes(4), 1)
                  + epb(20_000, last, 0))
    out = tmp_path / "rep"
    assert main(["latency", str(p), str(p), "--out", str(out)]) == 0
    load = json.loads((out / "summary.json").read_text())["load"]
    # The first two frames open the two intervals: 1344 bits over 20 us. A capture-wide
    # FCS decision would count 1376 bits instead.
    assert load["gbps"] == pytest.approx(1344 / 20_000)


# ---------------------------------------------------------------- pcapng structure
def test_trailing_block_length_mismatch_is_reported(tmp_path):
    bad = bytearray(epb(100, FRAME60))
    bad[-4:] = struct.pack("<I", 12)
    cap = ng(tmp_path, "t.pcapng", shb() + idb() + epb(50, FRAME60) + bytes(bad))
    assert len(cap) == 1 and any("trailing length 12" in i for i in cap.issues)


def test_incomplete_block_at_end_is_reported(tmp_path):
    cap = ng(tmp_path, "p.pcapng", shb() + idb() + epb(100, FRAME60) + b"\x06\0\0\0\x50\0\0\0")
    assert len(cap) == 1 and any("8 bytes after the last complete block" in i for i in cap.issues)


def test_short_interface_block_is_reported_and_keeps_numbering(tmp_path):
    cap = ng(tmp_path, "s.pcapng", shb() + block(1, bytes(4)) + idb(9) + epb(100, FRAME60, 0) + epb(200, FRAME60, 1))
    assert cap.ts_ns.tolist() == [200]               # interface 1 is still the second description block
    assert any("too short to read" in i for i in cap.issues)
    assert any("description block is unreadable: 1 skipped" in i for i in cap.issues)


def test_packet_problems_are_counted_not_listed_one_by_one(tmp_path):
    data = shb() + idb() + b"".join(epb(t, FRAME60, iface=7) for t in range(1000))
    cap = ng(tmp_path, "u.pcapng", data)
    assert len(cap) == 0 and len(cap.issues) == 1 and "1,000 skipped" in cap.issues[0]


# ---------------------------------------------------------------- negative-latency plot
def test_ccdf_keeps_negative_latencies_visible(tmp_path, monkeypatch):
    import matplotlib.figure
    seen = {}
    orig = matplotlib.figure.Figure.savefig

    def spy(self, *a, **kw):
        ax = self.axes[0]
        seen["scale"], seen["xlim"] = ax.get_xscale(), ax.get_xlim()
        seen["x"] = ax.lines[0].get_xdata()
        return orig(self, *a, **kw)

    monkeypatch.setattr(matplotlib.figure.Figure, "savefig", spy)
    write_pcap(tmp_path / "a.pcap", [(1000 * i, ipv4(udp(bytes([i])))) for i in range(1, 4)])
    write_pcap(tmp_path / "b.pcap", [(1000 * i - 100 * i, ipv4(udp(bytes([i])))) for i in range(1, 4)])
    assert main(["latency", str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap"),
                 "--allow-negative", "1us", "--out", str(tmp_path / "rep")]) == 0
    assert seen["scale"] == "symlog"
    lo, hi = seen["xlim"]
    assert all(lo <= x <= hi for x in seen["x"]) and min(seen["x"]) < 0


# ---------------------------------------------------------------- bursts: exactness and scaling
def _brute(ts, lens, rate, w, fcs):
    bits = (lens + 20 + np.where(fcs, 0, 4)) * 8
    rel = ts - ts.min()
    end = rel + bits * 1e9 / rate
    if w > end.max():
        return None
    return max(int(bits[(rel >= s) & (end <= s + w)].sum()) for s in rel)


def test_burst_windows_match_brute_force():
    rng = np.random.default_rng(20261026)
    for _ in range(400):
        n = int(rng.integers(1, 60))
        ts = rng.integers(0, int(rng.choice([1, 100, 5000, 50000])), n).astype(np.int64)
        lens = rng.integers(40, 9000 if rng.random() < 0.2 else 1515, n).astype(np.int64)
        rate = float(rng.choice([1e9, 10e9, 25e9]))
        fcs = rng.random(n) < 0.3
        wins = (50, 500, 672, 1000, 10_000, 100_000)
        for w, r in zip(wins, burst_profile(ts, lens, rate, wins, fcs_in_capture=fcs)):
            assert r["peak_bits"] == _brute(ts, lens, rate, w, fcs)


def test_dense_equal_timestamps_scale_linearly():
    n = 200_000
    t = time.perf_counter()
    r = burst_profile(np.zeros(n, dtype=np.int64), np.full(n, 60), 1e9, (500,))[0]
    assert r["peak_bits"] == 0                       # no 672 ns frame fits in 500 ns
    assert time.perf_counter() - t < 5               # the previous algorithm was quadratic here


def test_fast_and_scalar_decoders_agree_on_fuzzed_headers(tmp_path):
    rnd = np.random.default_rng(5)
    recs = []
    for i in range(3000):
        pay = rnd.integers(0, 256, int(rnd.integers(0, 40)), dtype=np.uint8).tobytes()
        if rnd.random() < 0.5:
            ulen = int(rnd.choice([0, 7, 8, 8 + len(pay), 8 + len(pay) + 9, int(rnd.integers(0, 65536))]))
            l4, proto = struct.pack("!HHHH", 1, 2, ulen, 0) + pay, 17
        else:
            off = int(rnd.choice([0, 0x40, 0x50, 0x60, 0xF0, int(rnd.integers(0, 256))]))
            l4, proto = struct.pack("!HHIIBBHHH", 1, 2, 3, 4, off, 0x10, 1, 0, 0) + pay, 6
        if rnd.random() < 0.2:
            l4 = l4[:int(rnd.integers(0, len(l4) + 1))]
        total = [None, 20 + len(l4) + int(rnd.integers(-25, 25)), int(rnd.integers(0, 200))][int(rnd.integers(0, 3))]
        total = None if total is None else max(0, total)
        f = ipv4(l4, proto=proto, frag=int(rnd.choice([0, 0x2000, 1, 0x2003])),
                 ihl_byte=int(rnd.choice([0x45, 0x46, 0x44, 0x4F])), total=total)
        cut = len(f) if rnd.random() < 0.7 else int(rnd.integers(14, len(f) + 1))
        recs.append((i * 100, f[:cut], len(f)))
    cap = write_pcap(tmp_path / "fuzz.pcap", recs)
    fast, scalar = compute_layout(cap), compute_layout(cap, force_scalar=True)
    assert (fast.ok == scalar.ok).all() and 0 < fast.ok.sum() < len(cap)
    ok = fast.ok
    for name in ("proto", "sport", "dport", "l3_end", "pay_off", "pay_end", "truncated", "fragment"):
        assert (getattr(fast, name)[ok] == getattr(scalar, name)[ok]).all(), name
