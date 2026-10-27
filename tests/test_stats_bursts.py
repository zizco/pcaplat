import math

import numpy as np
import pytest

from pcaplat.bursts import burst_profile, parse_duration, parse_rate
from pcaplat.stats import percentile_table, samples_needed, summarize


def test_samples_needed_matches_the_rule_of_thumb():
    assert samples_needed(99.99) == 1_000_000
    assert samples_needed(99.9) == 100_000
    assert samples_needed(99.999, min_tail=10) == 1_000_000


def test_nearest_rank_and_beyond_counts():
    x = np.arange(1, 1001, dtype=float)          # 1..1000
    rows = {r.percentile: r for r in percentile_table(x, (50, 99, 99.9))}
    assert rows[50].value_ns == 500 and rows[50].beyond == 500
    assert rows[99].value_ns == 990 and rows[99].beyond == 10 and not rows[99].reliable
    assert rows[99.9].value_ns == 999 and rows[99.9].beyond == 1


def test_confidence_interval_covers_true_quantile():
    rng = np.random.default_rng(3)
    true_p99 = 2.3263478740408408               # standard normal 0.99 quantile
    hits = 0
    for _ in range(200):
        x = np.sort(rng.standard_normal(5_000))
        r = percentile_table(x, (99,))[0]
        hits += r.ci_low_ns <= true_p99 <= r.ci_high_ns
    assert 180 <= hits <= 200                     # ~95% coverage, slightly conservative


def test_loss_aware_tail_reports_loss():
    # 10,000 packets, 20 lost: rank of p99.9 is 9,990, beyond the 9,980 delivered.
    lat = np.full(9_980, 500.0)
    s = summarize(lat, lost=20, percentiles=(99, 99.9))
    la = {r["percentile"]: r["value_ns"] for r in s["percentiles_loss_aware"]}
    assert la[99] == 500.0 and math.isinf(la[99.9])
    assert s["loss_rate"] == pytest.approx(0.002)
    # exactly at the boundary: 10 lost, p99.9 is still the last delivered packet
    s = summarize(np.full(9_990, 500.0), lost=10, percentiles=(99.9,))
    assert s["percentiles_loss_aware"][0]["value_ns"] == 500.0


def test_parsers():
    assert parse_duration("10us") == 10_000 and parse_duration("1ms") == 1_000_000
    assert parse_duration("2ns") == 2 and parse_duration("1s") == 1_000_000_000
    assert parse_rate("10G") == 10e9 and parse_rate("25Gbps") == 25e9


def test_burst_profile_sees_microbursts_that_averages_hide():
    # 1,226-byte frames: (1226 + 24) * 8 = 10,000 bits = exactly 1 us at 10 Gb/s
    frame = 1226
    background = np.arange(0, 1_200_000_000, 200_000, dtype=np.int64)       # 0.5% load over 1.2 s
    burst = 500_000_000 + np.arange(200, dtype=np.int64) * 1_000             # 200 us at line rate
    ts = np.sort(np.concatenate([background, burst]))
    lengths = np.full(len(ts), frame)
    rows = {r["window"]: r for r in burst_profile(ts, lengths, 10e9, (100_000, 1_000_000_000))}
    assert rows["100 us"]["peak_utilization"] == pytest.approx(1.0, abs=0.011)
    assert rows["1 s"]["peak_utilization"] < 0.01
    assert rows["100 us"]["episodes_above_threshold"] == 1


def test_single_link_never_exceeds_line_rate_and_long_windows_are_flagged():
    frame = 1226                                       # 1 us per frame at 10 Gb/s
    ts = np.arange(5_000, dtype=np.int64) * 1_000      # 5 ms back to back at line rate
    rows = {r["window"]: r for r in burst_profile(ts, np.full(len(ts), frame), 10e9,
                                                  (10_000, 1_000_000, 1_000_000_000))}
    assert rows["10 us"]["peak_utilization"] == pytest.approx(1.0)
    assert rows["1 ms"]["peak_utilization"] == pytest.approx(1.0)
    assert rows["1 s"]["applicable"] is False


def test_fan_in_capture_can_exceed_line_rate():
    frame = 1226
    ts = np.repeat(np.arange(1_000, dtype=np.int64) * 1_000, 2)   # two links merged at one tap
    rows = burst_profile(ts, np.full(len(ts), frame), 10e9, (100_000,))
    assert rows[0]["peak_utilization"] > 1.9


def test_epoch_scale_timestamps_keep_nanosecond_precision():
    # Back-to-back 102-byte frames at 25G (40.32 ns apart) at a realistic epoch
    # offset. A float64 epoch time in ns is quantized to 256 ns; the first version
    # of this function did that and reported 102.8% of line rate on one link.
    gaps = np.full(20_000, 1008 / 25e9 * 1e9)
    ts = 1_760_000_000_000_012_345 + np.round(np.cumsum(gaps)).astype(np.int64)
    rows = burst_profile(ts, np.full(len(ts), 102), 25e9, (10_000, 100_000))
    for r in rows:
        assert r["peak_utilization"] <= 1.0 + 1e-9
        assert r["peak_utilization"] > 0.99
