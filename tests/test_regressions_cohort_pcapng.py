"""Loss-cohort bounds, pcapng metadata validation, CCDF shape and small
synthetic captures.
"""
import json
import struct

import numpy as np
import pytest

from builders import block, epb, idb, ipv4, pair, shb, udp, write_pcap
from pcaplat.bursts import burst_profile
from pcaplat.cli import main
from pcaplat.match import KeySpec, match, packet_keys
from pcaplat import plot
from pcaplat.reader import read_capture
from pcaplat.synth import generate

F = ipv4(udp(b"X"))
F60 = F + bytes(60 - len(F))


def ng(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return read_capture(str(p))


def idb_opts(opts, e="<"):
    return block(1, struct.pack(e + "HHI", 1, 0, 65535) + opts, e)


def opt(code, value, e="<", length=None):
    n = len(value) if length is None else length
    return struct.pack(e + "HH", code, n) + value + bytes((-len(value)) % 4)


END = bytes(4)                                         # opt_endofopt


# ---------------------------------------------------------------- loss cohort bounds
def test_loss_cohort_survives_a_b_capture_with_only_ambiguous_keys(tmp_path):
    hb = ipv4(udp(b"HEARTBEAT"))
    r = pair(tmp_path, [(2000, ipv4(udp(b"A"))), (3000, ipv4(udp(b"B")))], [(0, hb), (10_000, hb)],
             max_latency_ns=1000)
    assert (r.counts["cohort"], r.counts["lost"]) == (2, 2)
    assert r.counts["loss_rate"] == pytest.approx(1.0)


def test_unkeyable_packets_at_b_still_bound_its_observation_window(tmp_path):
    arp = bytes.fromhex("ffffffffffff020000000001") + b"\x08\x06" + bytes(46)
    write_pcap(tmp_path / "a.pcap", [(2000, ipv4(udp(b"A"))), (3000, ipv4(udp(b"B")))])
    write_pcap(tmp_path / "b.pcap", [(0, arp), (2100, ipv4(udp(b"A"))), (10_000, arp)])
    out = tmp_path / "rep"
    assert main(["latency", str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap"),
                 "--max-latency", "1us", "--out", str(out)]) == 0
    s = json.loads((out / "summary.json").read_text())
    assert (s["counts"]["cohort"], s["counts"]["lost"], s["summary"]["cohort"]) == (2, 1, 2)


def test_filtered_out_traffic_still_shows_when_b_was_capturing(tmp_path):
    other = ipv4(udp(b"OTHER", dport=999))
    ca = write_pcap(tmp_path / "a.pcap", [(2000, ipv4(udp(b"A"))), (3000, ipv4(udp(b"B")))])
    cb = write_pcap(tmp_path / "b.pcap", [(0, other), (2100, ipv4(udp(b"A"))), (10_000, other)])
    from pcaplat.match import PacketFilter
    flt = PacketFilter(dst_port=456)
    r = match(packet_keys(ca, KeySpec(), flt), packet_keys(cb, KeySpec(), flt), max_latency_ns=1000)
    assert (r.counts["cohort"], r.counts["lost"], r.counts["matched"]) == (2, 1, 1)


def test_an_empty_capture_still_defines_no_cohort(tmp_path):
    r = pair(tmp_path, [(2000, F)], [])
    assert r.counts["cohort"] == 0 and r.counts["lost"] == 0


def test_dataframes_without_span_fall_back_to_their_own_timestamps():
    import pandas as pd
    a = pd.DataFrame({"key": np.array([1, 2], np.uint64), "ts_ns": [2000, 3000], "orig_len": [60, 60],
                      "fcs_bytes": [0, 0]})
    b = pd.DataFrame({"key": np.array([1, 9], np.uint64), "ts_ns": [2100, 10_000], "orig_len": [60, 60],
                      "fcs_bytes": [0, 0]})
    assert match(a, b, max_latency_ns=1000).counts["lost"] == 1


# ---------------------------------------------------------------- pcapng metadata
def test_tsresol_option_running_past_its_block_is_not_trusted(tmp_path):
    bad = idb_opts(struct.pack("<HHB3x", 9, 8, 9))     # declares 8 bytes, only 4 remain
    cap = ng(tmp_path, "t.pcapng", shb() + bad + epb(1_000_000, F))
    assert len(cap) == 0
    assert any("past the end of the block" in i for i in cap.issues)
    assert any("description block is unreadable: 1 skipped" in i for i in cap.issues)


@pytest.mark.parametrize("bad", [opt(9, b"\x09\x00", length=2), opt(14, bytes(4))], ids=["tsresol", "tsoffset"])
def test_timestamp_options_of_the_wrong_length_are_not_trusted(tmp_path, bad):
    cap = ng(tmp_path, "t.pcapng", shb() + idb_opts(bad + END) + epb(1_000_000, F))
    assert len(cap) == 0 and any("cannot be trusted" in i for i in cap.issues)


def test_missing_tsresol_means_microseconds_without_complaint(tmp_path):
    cap = ng(tmp_path, "t.pcapng", shb() + idb_opts(b"") + epb(1_000_000, F))
    assert cap.ts_ns.tolist() == [1_000_000_000] and cap.ts_resolution == "1 us" and cap.issues == []


def test_malformed_fcslen_is_reported_but_the_interface_stays_usable(tmp_path):
    bad = opt(13, struct.pack("<H", 32), length=2)
    cap = ng(tmp_path, "t.pcapng", shb() + idb_opts(opt(9, b"\x09") + bad + END) + epb(100, F))
    assert cap.ts_ns.tolist() == [100] and cap.fcs_bytes.tolist() == [0]
    assert any("if_fcslen has length 2" in i for i in cap.issues)


def test_invalid_byte_order_magic_is_rejected(tmp_path):
    bad = bytearray(shb(">"))
    bad[8:12] = b"BAD!"
    with pytest.raises(ValueError, match="byte-order magic"):
        ng(tmp_path, "first.pcapng", bytes(bad) + idb(e=">") + epb(100, F, e=">"))
    cap = ng(tmp_path, "later.pcapng", shb() + idb() + epb(100, F) + bytes(bad) + idb(e=">") + epb(200, F, e=">"))
    assert cap.ts_ns.tolist() == [100] and any("invalid byte-order magic" in i for i in cap.issues)


def test_unsupported_major_version_is_reported(tmp_path):
    v2 = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 2, 0, -1))
    cap = ng(tmp_path, "v.pcapng", shb() + idb() + epb(100, F) + v2 + idb() + epb(200, F))
    assert cap.ts_ns.tolist() == [100] and any("major version 2" in i for i in cap.issues)


def test_malformed_packet_options_are_reported_and_the_packet_kept(tmp_path):
    body = struct.pack("<IIIII", 0, 0, 100, len(F), len(F)) + F + bytes((-len(F)) % 4)
    bad = block(6, body + struct.pack("<HHI", 2, 40, 4 << 5))       # epb_flags claiming 40 bytes
    cap = ng(tmp_path, "o.pcapng", shb() + idb() + bad)
    assert cap.ts_ns.tolist() == [100] and cap.fcs_bytes.tolist() == [0]
    assert any("malformed options" in i and "kept" in i for i in cap.issues)


def test_packet_blocks_that_are_not_read_are_reported(tmp_path):
    spb = block(3, struct.pack("<I", len(F)) + F)
    cap = ng(tmp_path, "s.pcapng", shb() + idb() + spb + spb + epb(100, F))
    assert len(cap) == 1 and any("simple packet blocks" in i and "2 skipped" in i for i in cap.issues)


def test_original_length_below_captured_length_is_reported_and_corrected(tmp_path):
    cap = write_pcap(tmp_path / "s.pcap", [(0, F60, 1), (10_000, F60, 1)])
    assert cap.orig_len.tolist() == [60, 60]
    assert any("original length is below" in i for i in cap.issues)
    assert burst_profile(cap.ts_ns, cap.orig_len, 1e9, (1000,))[0]["peak_bits"] == 672
    body = struct.pack("<IIIII", 0, 0, 100, len(F60), 1) + F60
    ng_cap = ng(tmp_path, "s.pcapng", shb() + idb() + block(6, body))
    assert ng_cap.orig_len.tolist() == [60] and any("original length is below" in i for i in ng_cap.issues)


# ---------------------------------------------------------------- CCDF
def test_ccdf_keeps_the_plateau_up_to_the_maximum(tmp_path, monkeypatch):
    import matplotlib.figure
    seen = {}
    orig = matplotlib.figure.Figure.savefig

    def spy(self, *a, **kw):
        line = self.axes[0].lines[0]
        seen["x"], seen["y"] = line.get_xdata(), line.get_ydata()
        return orig(self, *a, **kw)

    monkeypatch.setattr(matplotlib.figure.Figure, "savefig", spy)
    plot.ccdf_plot(np.r_[np.full(999, 1000.0), 1e8], str(tmp_path / "c.png"), [])
    x, y = np.asarray(seen["x"]), np.asarray(seen["y"])
    assert x.max() == pytest.approx(1e5)                       # 100 ms, in microseconds
    assert y[-1] == pytest.approx(0.001) and y[x == 1e5].min() == pytest.approx(0.001)


def test_ccdf_ties_step_once_to_the_exact_level():
    xs, ys, last = plot.ccdf_points(np.array([1.0, 2.0, 2.0, 3.0]))
    assert xs.tolist() == [1.0, 1.0, 2.0, 3.0] and ys.tolist() == [1.0, 0.75, 0.25, 0.25] and last == 0.25
    xs, ys, last = plot.ccdf_points(np.full(10, 5.0))
    assert set(xs.tolist()) == {5.0} and last == 1.0


def test_thinned_ccdf_points_are_exact_survival_levels():
    x = np.sort(np.random.default_rng(3).lognormal(6, 0.7, 300_000))     # 300,000 distinct values
    xs, ys, last = plot.ccdf_points(x)
    assert len(xs) < 10_000 and xs[-1] == x[-1]
    exact = (len(x) - np.searchsorted(x, xs[1:-1], side="right")) / len(x)
    assert np.allclose(ys[1:-1], exact)
    assert last == pytest.approx((x == x[-1]).sum() / len(x))


# ---------------------------------------------------------------- synth
@pytest.mark.parametrize("packets", [1, 9, 50])
def test_synth_handles_small_captures(tmp_path, packets):
    truth = generate(str(tmp_path), packets=packets, seed=3)
    assert truth["packets"] == packets and truth["heartbeats"] == packets // 10
    a, b = read_capture(str(tmp_path / "a.pcap")), read_capture(str(tmp_path / "b.pcap"))
    assert len(a) == packets
    r = match(packet_keys(a, KeySpec()), packet_keys(b, KeySpec()))
    assert r.counts["matched"] == truth["delivered"]


def test_synth_rejects_an_empty_request(tmp_path):
    with pytest.raises(ValueError):
        generate(str(tmp_path), packets=0)
    with pytest.raises(SystemExit):
        main(["synth", "--packets", "0", "--out", str(tmp_path)])
