"""Strict JSON output, repeated pcapng options, short section headers, the
synthetic ground truth at small sizes and command-line percentiles.
"""
import json
import math
import struct

import numpy as np
import pytest

from builders import block, epb, idb, ipv4, shb, udp, write_pcap
from pcaplat import report
from pcaplat.cli import main
from pcaplat.match import KeySpec, match, packet_keys
from pcaplat.reader import read_capture
from pcaplat.synth import generate

F = ipv4(udp(b"X"))


def strict_load(path):
    """Parse like a strict RFC 8259 consumer (JavaScript's JSON.parse): no Infinity or NaN."""
    def refuse(name):
        raise ValueError(f"non-JSON constant {name}")
    return json.loads(path.read_text(), parse_constant=refuse)


def ng(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return read_capture(str(p))


def idb_opts(opts):
    return block(1, struct.pack("<HHI", 1, 0, 65535) + opts + bytes(4))


def tsresol(code):
    return struct.pack("<HHB3x", 9, 1, code)


def tsoffset(seconds):
    return struct.pack("<HHq", 14, 8, seconds)


def fcslen(bits):
    return struct.pack("<HHB3x", 13, 1, bits)


# ---------------------------------------------------------------- strict JSON
def test_latency_summary_is_strict_json_with_explicit_non_finite_values(tmp_path):
    # 500 packets, one lost: loss-aware p99.9 is +inf, and p99.99 has an unbounded interval.
    a = [(i * 1000, ipv4(udp(struct.pack("!I", i)))) for i in range(500)]
    b = [(t + 300, f) for i, (t, f) in enumerate(a) if i != 250] + [(600_000, ipv4(udp(b"END")))]
    write_pcap(tmp_path / "a.pcap", a + [(599_000, ipv4(udp(b"END")))])
    write_pcap(tmp_path / "b.pcap", b)
    out = tmp_path / "rep"
    assert main(["latency", str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap"),
                 "--max-latency", "1us", "--out", str(out)]) == 0
    s = strict_load(out / "summary.json")
    assert "json_encoding" in s
    loss = {r["percentile"]: r for r in s["summary"]["percentiles_loss_aware"]}
    assert loss[99.9]["value_ns"] is None and loss[99.9]["value_ns_nonfinite"] == "+inf"
    top = {r["percentile"]: r for r in s["summary"]["percentiles"]}[99.99]
    assert top["ci_high_unbounded"] is True and top["ci_high_ns_nonfinite"] == "+inf"


def test_empty_match_summary_is_strict_json(tmp_path):
    write_pcap(tmp_path / "a.pcap", [(2000, ipv4(udp(b"A")))])
    write_pcap(tmp_path / "b.pcap", [(0, ipv4(udp(b"Z"))), (10_000, ipv4(udp(b"Y")))])
    out = tmp_path / "rep"
    assert main(["latency", str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap"),
                 "--max-latency", "1us", "--out", str(out)]) == 0
    s = strict_load(out / "summary.json")["summary"]
    assert s["min_ns"] is None and s["min_ns_nonfinite"] == "nan" and s["samples"] == 0


def test_bursts_json_is_strict_when_a_window_does_not_apply(tmp_path):
    write_pcap(tmp_path / "a.pcap", [(0, F), (1000, F)])
    out = tmp_path / "rep"
    assert main(["bursts", str(tmp_path / "a.pcap"), "--line-rate", "1G", "--windows", "1us,1s",
                 "--out", str(out)]) == 0
    rows = strict_load(out / "bursts.json")["windows"]
    assert rows[1]["applicable"] is False and rows[1]["peak_utilization_nonfinite"] == "nan"


def test_json_safe_handles_lists_and_numpy_scalars():
    out = report.json_safe({"a": [1.0, float("inf"), np.float64("nan")], "b": np.float32(-np.inf),
                            "c": np.int64(3), "d": np.bool_(True)})
    assert out == {"a": [1.0, None, None], "b": None, "b_nonfinite": "-inf", "c": 3, "d": True}
    json.dumps(out, allow_nan=False)


# ---------------------------------------------------------------- repeated interface options
@pytest.mark.parametrize("opts", [tsresol(6) + tsresol(9), tsresol(9) + tsresol(6),
                                  tsresol(9) + tsoffset(0) + tsoffset(5)],
                         ids=["tsresol-6-9", "tsresol-9-6", "tsoffset"])
def test_conflicting_timestamp_options_are_not_trusted(tmp_path, opts):
    cap = ng(tmp_path, "c.pcapng", shb() + idb_opts(opts) + epb(1_000_000, F))
    assert len(cap) == 0
    assert any("conflicting" in i and "cannot be trusted" in i for i in cap.issues)


def test_identical_repeated_options_are_reported_but_harmless(tmp_path):
    cap = ng(tmp_path, "c.pcapng", shb() + idb_opts(tsresol(9) + tsresol(9)) + epb(1_000_000, F))
    assert cap.ts_ns.tolist() == [1_000_000]
    assert any("appears more than once" in i for i in cap.issues)


def test_conflicting_fcslen_is_ignored_and_reported(tmp_path):
    cap = ng(tmp_path, "c.pcapng", shb() + idb_opts(tsresol(9) + fcslen(32) + fcslen(0)) + epb(100, F))
    assert cap.ts_ns.tolist() == [100] and cap.fcs_bytes.tolist() == [0]
    assert any("conflicting if_fcslen" in i for i in cap.issues)


# ---------------------------------------------------------------- section header length
def test_section_header_shorter_than_28_bytes_is_rejected(tmp_path):
    short = block(0x0A0D0D0A, struct.pack("<IHH", 0x1A2B3C4D, 1, 0))        # no section length
    with pytest.raises(ValueError, match="below the minimum of 28"):
        ng(tmp_path, "first.pcapng", short + idb() + epb(100, F))
    cap = ng(tmp_path, "later.pcapng", shb() + idb() + epb(100, F) + short + idb() + epb(200, F))
    assert cap.ts_ns.tolist() == [100] and any("below the minimum of 28" in i for i in cap.issues)


# ---------------------------------------------------------------- synth oracle
def test_synth_ground_truth_accounts_for_every_match_at_small_sizes(tmp_path):
    for n in range(1, 41):
        d = tmp_path / str(n)
        truth = generate(str(d), packets=n, seed=3)
        assert truth["heartbeats"] != 1, n
        a, b = read_capture(str(d / "a.pcap")), read_capture(str(d / "b.pcap"))
        m = match(packet_keys(a, KeySpec()), packet_keys(b, KeySpec())).matched.sort_values("ts_a")
        assert len(m) == truth["delivered"] == len(np.load(d / "truth_latency.npy")), n
        assert np.array_equal(m["latency_ns"].to_numpy(), np.load(d / "truth_latency.npy")[
            np.argsort(np.load(d / "truth_ts_a.npy"), kind="stable")]), n


# ---------------------------------------------------------------- percentile arguments
@pytest.mark.parametrize("arg", ["-1", "101", "50,abc"])
def test_out_of_range_percentiles_are_rejected_cleanly(tmp_path, arg, capsys):
    write_pcap(tmp_path / "a.pcap", [(0, F)])
    with pytest.raises(SystemExit) as e:
        main(["latency", str(tmp_path / "a.pcap"), str(tmp_path / "a.pcap"), "--percentiles", arg,
              "--out", str(tmp_path / "rep")])
    assert e.value.code == 2 and "--percentiles" in capsys.readouterr().err


def test_percentile_endpoints_are_accepted(tmp_path):
    a = [(i * 1000, ipv4(udp(struct.pack("!I", i)))) for i in range(10)]
    write_pcap(tmp_path / "a.pcap", a)
    write_pcap(tmp_path / "b.pcap", [(t + 100, f) for t, f in a])
    out = tmp_path / "rep"
    assert main(["latency", str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap"), "--percentiles", "0,100",
                 "--out", str(out)]) == 0
    rows = strict_load(out / "summary.json")["summary"]["percentiles"]
    assert [r["value_ns"] for r in rows] == [100.0, 100.0] and not any(
        isinstance(r["value_ns"], float) and math.isnan(r["value_ns"]) for r in rows)

