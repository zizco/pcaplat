# Latency report: synthetic: 25G ingress to 10G egress, 64 KB buffer

## 1. What was measured

| Field | Value |
|---|---|
| Path | synthetic: 25G ingress to 10G egress, 64 KB buffer |
| Timestamp source at A | synthetic, exact ns |
| Timestamp source at B | synthetic, exact ns |
| Clock | synthetic (perfect) |
| Estimated clock error | 1 ns |
| Matching key | `l4payload` |

| Capture | File | SHA-256 (12) | Format | Resolution | Packets | Duration |
|---|---|---|---|---|---:|---:|
| A | a.pcap | `de09a2adedfc` | pcap | 1 ns | 1,000,000 | 1.621 s |
| B | b.pcap | `0ca28709c774` | pcap | 1 ns | 992,718 | 1.621 s |

## 2. Load at A

1,000,000 packets over 1.621 s: 617,082 packets/s, 0.622 Gb/s on the wire on average. Estimated from start timestamps: the n-1 intervals between the first and last packet, and the n-1 packets that open them.

## 3. Results

Matched samples: **992,468**.

Loss cohort: the **999,382** packets seen at A while B was capturing and early enough for B to see them. Lost (never seen at B): **7,482** (0.7487% of the cohort).

| Cohort member | Packets |
|---|---:|
| Matched within the window | 991,900 |
| Seen at B after the window (late) | 0 |
| Seen at B before A beyond the allowed margin (clock-invalid) | 0 |
| Lost | 7,482 |
| **Cohort** | **999,382** |

The other 568 matched samples were sent outside the cohort: they are in the matched table, not in the loss accounting.

Min 553 ns, max 53.55 µs. Mean 1.26 µs (shown for reference; the mean is a poor summary of a tail).

### Matched packets

| Percentile | Value | 95% CI | Samples ranked beyond | Reliable |
|---:|---:|---|---:|:---:|
| p50 | 572 ns | 572 ns to 572 ns | 496,234 | yes |
| p90 | 600 ns | 600 ns to 600 ns | 99,246 | yes |
| p99 | 36.55 µs | 35.95 µs to 37.15 µs | 9,924 | yes |
| p99.9 | 51.76 µs | 51.76 µs to 51.76 µs | 992 | yes |
| p99.99 | 51.79 µs | 51.78 µs to 51.79 µs | 99 | NO |
| p99.999 | 51.82 µs | 51.81 µs to 51.84 µs | 9 | NO |

### Loss-aware (each lost or late cohort packet counted as infinitely late)

| Percentile | Value | 95% CI | Samples ranked beyond | Reliable |
|---:|---:|---|---:|:---:|
| p50 | 572 ns | 572 ns to 572 ns | 499,691 | yes |
| p90 | 602 ns | 602 ns to 602 ns | 99,938 | yes |
| p99 | 51.75 µs | 51.75 µs to 51.75 µs | 9,993 | yes |
| p99.9 | lost | lost to lost | 999 | yes |
| p99.99 | lost | lost to lost | 99 | NO |
| p99.999 | lost | lost to lost | 9 | NO |

A percentile is marked unreliable when fewer than 100 samples are ranked beyond it. Confidence intervals are distribution-free (binomial order statistics; ties only make them conservative); "unbounded" means the sample is too small for a finite limit. They assume independent, identically distributed samples: latencies measured during a burst are positively correlated, which usually makes the real uncertainty larger.

![CCDF](ccdf.png)

## 4. Sanity checks

- INFO: 50 packets at A and 50 at B share their key with another packet (heartbeats, retransmissions) and were excluded.
- INFO: 200 packets at B have no match at A (other traffic, or traffic that does not cross point A).
- RULE: with a clock error of about 1 ns, differences smaller than about 10 ns between two configurations should not be read as real.
- CHECK: p99.99 and above have too few samples beyond them to be stable.

## 5. Versions

- pcaplat: 0.1.0
- python: 3.13.16
- numpy: 2.5.3
- pandas: 3.0.5
- pyarrow: 26.0.0
- generated_utc: 2026-10-27 00:49:02
