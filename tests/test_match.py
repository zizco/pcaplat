import json

import numpy as np
import pytest

from pcaplat.cli import main
from pcaplat.match import KeySpec, match, packet_keys
from pcaplat.reader import read_capture
from pcaplat.synth import generate, udp_frame


@pytest.fixture(scope="module")
def synthetic(tmp_path_factory):
    d = tmp_path_factory.mktemp("synth")
    truth = generate(str(d), packets=60_000, burst_every=20_000, burst_len=1_500, seed=11)
    return d, truth


def _run(d, spec="l4payload"):
    a, b = read_capture(str(d / "a.pcap")), read_capture(str(d / "b.pcap"))
    s = KeySpec.parse(spec)
    return match(packet_keys(a, s), packet_keys(b, s))


def test_recovers_injected_latencies_exactly(synthetic):
    d, truth = synthetic
    res = _run(d)
    want = np.sort(np.load(d / "truth_latency.npy"))
    got = np.sort(res.matched["latency_ns"].to_numpy())
    assert len(got) == truth["delivered"]
    assert np.array_equal(got, want)


def test_recovers_each_packets_latency(synthetic):
    # Packet by packet, not only as a distribution: arrival gaps are at least one
    # serialization time, so the timestamp at A identifies each data packet.
    d, truth = synthetic
    m = _run(d).matched.sort_values("ts_a")
    ts_a, lat = np.load(d / "truth_ts_a.npy"), np.load(d / "truth_latency.npy")
    assert len(np.unique(ts_a)) == len(ts_a)
    order = np.argsort(ts_a, kind="stable")
    assert np.array_equal(m["ts_a"].to_numpy(), ts_a[order])
    assert np.array_equal(m["latency_ns"].to_numpy(), lat[order])


def test_counts_losses_inside_the_common_window(synthetic):
    d, truth = synthetic
    res = _run(d)
    b = read_capture(str(d / "b.pcap"))
    lo, hi = int(b.ts_ns.min()), int(b.ts_ns.max()) - 1_000_000
    dropped = np.load(d / "truth_dropped_ts_a.npy")
    assert res.counts["lost"] == int(((dropped >= lo) & (dropped <= hi)).sum())
    assert truth["overflow_drops"] > 0


def test_ambiguous_and_extra_traffic_are_reported(synthetic):
    d, truth = synthetic
    c = _run(d).counts
    assert c["ambiguous_a"] == truth["heartbeats"] and c["ambiguous_b"] == truth["heartbeats_delivered"]
    assert 0 < c["extra_b"] <= truth["cross_traffic_b"]
    assert c["negative_latency"] == 0 and c["out_of_window"] == 0


def test_sequence_number_key_gives_same_matches(synthetic):
    d, truth = synthetic
    assert _run(d, "bytes:0:8").counts["matched"] == truth["delivered"]


def test_single_pcapng_with_two_interfaces(tmp_path):
    # Same device timestamps both points: interface 0 = A, interface 1 = B.
    src, dst = bytes([10, 0, 0, 1]), bytes([233, 54, 12, 1])
    frames = [udp_frame(i.to_bytes(8, "big") + b"MD", src, dst, 30001, 31001) for i in range(1000)]
    t0 = 1_760_000_000_000_000_000
    path = tmp_path / "two.pcapng"
    _write_two_iface_pcapng(path, [(t0 + 1000 * i, 0, f) for i, f in enumerate(frames)] +
                            [(t0 + 1000 * i + 300 + (i % 7), 1, f) for i, f in enumerate(frames)])
    out = tmp_path / "rep"
    assert main(["latency", str(path), "--iface-a", "0", "--iface-b", "1", "--out", str(out)]) == 0
    s = json.loads((out / "summary.json").read_text())
    assert s["summary"]["samples"] == 1000
    assert s["summary"]["min_ns"] == 300 and s["summary"]["max_ns"] == 306
    # one file does not prove one clock: the user has to say so
    assert s["meta"]["same_clock"] is False
    assert "does not prove they share a clock" in (out / "report.md").read_text()
    out2 = tmp_path / "rep2"
    assert main(["latency", str(path), "--iface-a", "0", "--iface-b", "1", "--same-clock",
                 "--out", str(out2)]) == 0
    assert json.loads((out2 / "summary.json").read_text())["meta"]["same_clock"] is True


def _write_two_iface_pcapng(path, recs):
    import struct

    def block(btype, body):
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        n = 12 + len(body)
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

    opt = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)
    with open(path, "wb") as f:
        f.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        f.write(block(1, struct.pack("<HHI", 1, 0, 65535) + opt))
        f.write(block(1, struct.pack("<HHI", 1, 0, 65535) + opt))
        for ts, iface, frame in sorted(recs, key=lambda r: r[0]):
            body = struct.pack("<IIIII", iface, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame
            f.write(block(6, body))


def test_cli_end_to_end(synthetic, tmp_path):
    d, truth = synthetic
    out = tmp_path / "rep"
    rc = main(["latency", str(d / "a.pcap"), str(d / "b.pcap"), "--out", str(out),
               "--clock-error", "2ns", "--label", "test path"])
    assert rc == 0
    for f in ("report.md", "summary.json", "latencies.parquet", "ccdf.png"):
        assert (out / f).exists(), f
    md = (out / "report.md").read_text()
    assert "Loss-aware" in md and "test path" in md and "20 ns" in md
    import pyarrow.parquet as pq
    assert pq.read_table(out / "latencies.parquet").num_rows == truth["delivered"]


def test_pairs_outside_the_window_are_late_or_offset_not_lost():
    import pandas as pd
    t0 = 1_760_000_000_000_000_000
    keys = np.arange(1, 7, dtype=np.uint64)
    ts_a = t0 + np.arange(6, dtype=np.int64) * 1_000_000
    lat = np.array([100, 200, 300, 5_000_000, -50, 400], dtype=np.int64)   # one late, one negative
    a = pd.DataFrame({"key": keys, "ts_ns": ts_a, "orig_len": 100, "truncated": False})
    b = pd.DataFrame({"key": keys[:5], "ts_ns": (ts_a + lat)[:5], "orig_len": 100, "truncated": False})
    b = pd.concat([b, pd.DataFrame({"key": [np.uint64(99)], "ts_ns": [t0 + 2_500_000],
                                    "orig_len": [100], "truncated": [False]})])   # inside A's span
    r = match(a, b, max_latency_ns=1_000_000)
    c = r.counts
    assert c["matched"] == 3
    assert c["late_beyond_window"] == 1 and c["latest_ns"] == 5_000_000
    assert c["negative_beyond_allowance"] == 1
    assert c["lost"] == 1                # key 6 never reached B
    assert c["extra_b"] == 1             # key 99 only exists at B
    from pcaplat.stats import summarize
    s = summarize(r.matched["latency_ns"].to_numpy(), lost=c["lost"], late=c["late_beyond_window"],
                  percentiles=(50,))
    assert s["late"] == 1 and len(s["percentiles_loss_aware"]) == 1
