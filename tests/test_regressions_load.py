"""The latency-report load counts the same frames as the interval it divides by.
"""
import json

import numpy as np
import pytest

from builders import ipv4, udp, write_pcap
from pcaplat import cli
from pcaplat.cli import main


def strict_load(path):
    def refuse(name):
        raise ValueError(f"non-JSON constant {name}")
    return json.loads(path.read_text(), parse_constant=refuse)


def test_latency_load_counts_the_same_frames_as_its_interval(tmp_path):
    # Two 1,226-byte frames back to back at 10G: 10,000 wire bits each, starts 1,000 ns apart.
    a = [(0, ipv4(udp(b"A" * 1184))), (1000, ipv4(udp(b"B" * 1184)))]
    write_pcap(tmp_path / "a.pcap", a)
    write_pcap(tmp_path / "b.pcap", [(t + 100, f) for t, f in a])
    out = tmp_path / "rep"
    assert main(["latency", str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap"), "--out", str(out)]) == 0
    load = strict_load(out / "summary.json")["load"]
    assert load["gbps"] == pytest.approx(10.0) and load["pps"] == pytest.approx(1e6)
    assert "n-1" in load["estimator"]


@pytest.mark.parametrize("starts", [[0], [500, 500]], ids=["one-packet", "tied-starts"])
def test_latency_load_is_unavailable_without_two_distinct_starts(tmp_path, starts):
    a = [(t, ipv4(udp(bytes([i])))) for i, t in enumerate(starts)]
    write_pcap(tmp_path / "a.pcap", a)
    write_pcap(tmp_path / "b.pcap", [(t + 100, f) for t, f in a])
    out = tmp_path / "rep"
    assert main(["latency", str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap"), "--out", str(out)]) == 0
    load = strict_load(out / "summary.json")["load"]
    assert load["available"] is False and load["gbps"] is None and load["pps"] is None
    assert "average load not available" in (out / "report.md").read_text()


def test_load_estimate_with_regular_frames_is_exact():
    # n equal frames every 1,000 ns, 10,000 wire bits each: 10 Gb/s whatever n is.
    for n in (2, 3, 10, 1000):
        ts = np.arange(n, dtype=np.int64) * 1000
        est = cli.load_estimate(ts, np.full(n, 1226), np.zeros(n, dtype=np.int16))
        assert est["gbps"] == pytest.approx(10.0) and est["pps"] == pytest.approx(1e6)
