"""Edge cases in statistics, matching, header decoding, readers and bursts.

Each test builds a small capture by hand and checks one behaviour that was
once wrong.
"""
import json
import math
import struct

import numpy as np
import pytest

from pcaplat.bursts import burst_profile
from pcaplat.cli import main
from pcaplat.decode import decode
from pcaplat.layout import compute_layout
from pcaplat.match import KeySpec, match, packet_keys
from pcaplat.reader import read_capture
from pcaplat.stats import percentile_table, quantile_ci_ranks, summarize

from builders import F, SRC, DST, block, epb, eth, idb, ipv4, ipv6, pair, shb, udp, write_pcap  # noqa: F401


# ---------------------------------------------------------------- statistics
def test_extreme_tail_interval_is_unbounded_not_falsely_narrow():
    r = percentile_table(np.arange(1, 1001, dtype=float), (99.99,))[0]
    assert r.ci_high_unbounded and math.isinf(r.ci_high_ns)
    lo, hi = quantile_ci_ranks(1000, 99.99)
    n, q = 1000, 0.9999
    coverage = sum(math.comb(n, k) * q ** k * (1 - q) ** (n - k) for k in range(lo, min(hi, n + 1)))
    assert coverage >= 0.95


@pytest.mark.parametrize("n,p", [(200, 50), (5_000, 99), (100_000, 99.9), (2_000, 99.99), (50, 90)])
def test_interval_ranks_reach_nominal_coverage(n, p):
    lo, hi = quantile_ci_ranks(n, p)
    q = p / 100
    from scipy.stats import binom
    coverage = binom.cdf(hi - 1, n, q) - binom.cdf(lo - 1, n, q)
    assert coverage >= 0.95 - 1e-12


def test_loss_rate_uses_the_same_cohort_as_the_losses(tmp_path):
    a = [(0, ipv4(udp(b"A"))), (100, ipv4(udp(b"B"))), (5000, ipv4(udp(b"LOST"))), (10000, ipv4(udp(b"C")))]
    b = [(100, ipv4(udp(b"A"))), (200, ipv4(udp(b"B"))), (10100, ipv4(udp(b"C")))]
    r = pair(tmp_path, a, b, max_latency_ns=1000)
    assert r.counts["cohort"] == 2 and r.counts["lost"] == 1
    assert r.counts["loss_rate"] == pytest.approx(0.5)
    s = summarize(r.matched["latency_ns"].to_numpy(), lost=r.counts["lost"],
                  late=r.counts["late_in_cohort"], cohort_latency_ns=r.loss_aware_latencies())
    assert s["loss_rate"] == pytest.approx(0.5)


# ---------------------------------------------------------------- matching
def test_duplicate_on_one_side_is_not_a_false_loss_or_extra(tmp_path):
    a = [(0, ipv4(udp(b"0"))), (2000, F), (10000, ipv4(udp(b"Z")))]
    b = [(100, ipv4(udp(b"0"))), (2100, F), (2200, F), (10100, ipv4(udp(b"Z")))]
    r = pair(tmp_path, a, b, max_latency_ns=1000)
    assert r.counts["lost"] == 0 and r.counts["ambiguous_a"] == 1 and r.counts["ambiguous_b"] == 2
    r = pair(tmp_path, b, a, max_latency_ns=1000)
    assert r.counts["extra_b"] == 0


def test_snaplen_truncated_payloads_are_not_keyed(tmp_path):
    fa, fb = ipv4(udp(b"AAAA1111")), ipv4(udp(b"AAAA2222"))
    r = pair(tmp_path, [(100, fa[:46], len(fa))], [(200, fb[:46], len(fb))])
    assert r.counts["matched"] == 0
    cap = write_pcap(tmp_path / "t.pcap", [(100, fa[:46], len(fa))])
    assert packet_keys(cap, KeySpec()).attrs["skipped"]["truncated"] == 1


def test_fragments_do_not_create_false_matches(tmp_path):
    f4a = ipv4(b"FRAGMENT", ident=100, frag=1)
    f4b = ipv4(b"FRAGMENT", ident=200, frag=2)
    assert pair(tmp_path, [(100, f4a)], [(200, f4b)]).counts["matched"] == 0
    f6a = ipv6(struct.pack("!BBHI", 17, 0, 8, 100) + udp(b"X"), 44)
    f6b = ipv6(struct.pack("!BBHI", 17, 0, 16, 200) + udp(b"X"), 44)
    d = decode(memoryview(f6a), 1)
    assert (d.sport, d.dport, d.fragment) == (0, 0, True)
    assert pair(tmp_path, [(100, f6a)], [(200, f6b)]).counts["matched"] == 0
    # the frame key includes IP identification and offset, so it can key fragments safely
    ca = write_pcap(tmp_path / "fa.pcap", [(100, f4a)])
    assert len(packet_keys(ca, KeySpec.parse("frame"))) == 1


def test_first_and_atomic_fragments_keep_their_ports():
    first = ipv4(struct.pack("!HHHH", 123, 456, 100, 0) + b"ABCDEFGH", frag=0x2000)
    atomic = ipv6(struct.pack("!BBHI", 17, 0, 0, 100) + udp(b"X"), 44)
    assert (decode(memoryview(first), 1).sport, decode(memoryview(atomic), 1).sport) == (123, 123)
    assert decode(memoryview(first), 1).fragment and not decode(memoryview(atomic), 1).fragment


def test_ipv6_authentication_header_is_skipped():
    ah = bytes([17, 4]) + bytes(22) + udp(b"ABC")
    d = decode(memoryview(ipv6(ah, 51)), 1)
    assert (d.proto, d.sport, d.dport) == (17, 123, 456)


def test_empty_capture_on_one_side_does_not_crash(tmp_path):
    r = pair(tmp_path, [], [(100, F)])
    assert r.counts["matched"] == 0 and r.counts["lost"] == 0 and r.counts["extra_b"] == 0


@pytest.mark.parametrize("spec", ["bytes:-1:1", "bytes:0:-1", "bytes:-10000:8", "bytes:0:0", "bytes:x:2"])
def test_invalid_byte_keys_are_rejected(spec):
    with pytest.raises(ValueError):
        KeySpec.parse(spec)


# ---------------------------------------------------------------- headers
@pytest.mark.parametrize("frame", [
    ipv4(udp(b"X"), ihl_byte=0x40),                        # IHL 0
    ipv4(udp(b"", length=7)),                              # UDP length below 8
    ipv4(struct.pack("!HHIIBBHHH", 123, 456, 1, 0, 0, 0x10, 1024, 0, 0), proto=6),   # TCP offset 0
])
def test_invalid_headers_are_rejected_on_both_paths(tmp_path, frame):
    cap = write_pcap(tmp_path / "bad.pcap", [(100, frame)])
    assert decode(memoryview(frame), 1) is None
    assert not compute_layout(cap).ok[0] and not compute_layout(cap, force_scalar=True).ok[0]
    assert len(packet_keys(cap, KeySpec())) == 0


# ---------------------------------------------------------------- readers
def test_pcap_fcs_bits_do_not_change_the_link_type(tmp_path):
    cap = write_pcap(tmp_path / "fcs.pcap", [(100, F + bytes(4))], link=1 | (1 << 26) | (2 << 28))
    assert int(cap.linktype[0]) == 1 and int(cap.fcs_bytes[0]) == 4
    assert len(packet_keys(cap, KeySpec())) == 1


def test_pcapng_timestamp_offset_is_applied(tmp_path):
    p = tmp_path / "o.pcapng"
    p.write_bytes(shb() + idb(9, 5) + epb(100, F))
    assert read_capture(str(p)).ts_ns.tolist() == [5_000_000_100]


def test_pcapng_sections_keep_distinct_interfaces(tmp_path):
    p = tmp_path / "s.pcapng"
    p.write_bytes(shb() + idb(6) + epb(100, F) + shb(">") + idb(9, e=">") + epb(200, F, e=">"))
    cap = read_capture(str(p))
    assert cap.ts_ns.tolist() == [100_000, 200]
    assert cap.iface.tolist() == [0, 1]
    assert cap.res_ns.tolist() == [1000.0, 1.0]
    assert cap.ts_resolution == "1 us, 1 ns"


def test_pcapng_packet_longer_than_its_block_is_rejected(tmp_path):
    p = tmp_path / "bad.pcapng"
    p.write_bytes(shb() + idb() + epb(100, F, caplen=10_000) + epb(300, F))
    cap = read_capture(str(p))
    assert len(cap) == 1 and cap.ts_ns.tolist() == [300]
    assert any("more captured bytes" in i for i in cap.issues)


def test_mixed_resolution_warning_follows_the_selected_interface(tmp_path):
    p = tmp_path / "two.pcapng"
    p.write_bytes(shb() + idb(6) + idb(9) + epb(1000, F, 0) + epb(1_000_100, F, 1))
    out = tmp_path / "rep"
    assert main(["latency", str(p), "--iface-a", "0", "--iface-b", "1", "--out", str(out)]) == 0
    md = (out / "report.md").read_text()
    assert "capture A has timestamps no finer than 1.00 µs" in md
    assert "capture B has timestamps" not in md


# ---------------------------------------------------------------- bursts
def test_fan_in_short_frame_finishing_first_is_counted():
    r = burst_profile(np.array([0, 100, 20_000]), np.array([1226, 60, 1226]), 1e9, (1000,))[0]
    assert r["peak_bits"] == 672


def test_rounded_single_link_stays_within_the_rounding_allowance():
    r = burst_profile(np.array([1, 27, 54, 1000]), np.array([60] * 4), 25e9, (80,))[0]
    assert r["peak_utilization"] > 1.0                  # rounding can push slightly above
    assert not r["beyond_line_rate"]                    # but it is not reported as fan-in


def test_average_uses_first_start_to_last_finish():
    r = burst_profile(np.array([0, 1000]), np.array([1226, 1226]), 10e9, (1000,))[0]
    assert r["average_utilization"] == pytest.approx(1.0)


def test_cli_reports_unbounded_intervals(tmp_path):
    recs_a = [(i * 1000, ipv4(udp(struct.pack("!I", i)))) for i in range(500)]
    recs_b = [(t + 300 + (i % 5), f) for i, (t, f) in enumerate(recs_a)]
    write_pcap(tmp_path / "a.pcap", recs_a)
    write_pcap(tmp_path / "b.pcap", recs_b)
    out = tmp_path / "rep"
    assert main(["latency", str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap"), "--out", str(out)]) == 0
    s = json.loads((out / "summary.json").read_text())["summary"]
    p9999 = [r for r in s["percentiles"] if r["percentile"] == 99.99][0]
    assert p9999["ci_high_unbounded"] is True
    assert "unbounded" in (out / "report.md").read_text()
