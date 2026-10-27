"""Look at the same traffic at several time scales.

A link that averages a few percent over one second can be saturated for
tens of microseconds. For each window size W, this computes the busiest
W-long window in the capture (sliding, anchored on every packet) and
expresses it as a fraction of line rate.

Bits on the wire per frame = (captured original length + FCS + preamble/SFD
+ inter-frame gap) x 8. Captures usually exclude the 4-byte FCS, so it is
added back by default.

Only frames that start and finish serializing inside the window are counted,
each with its own completion time. On a single link, the busiest window can
then only exceed 100% by timestamp rounding: at most about two timestamp
resolutions over the window length, which is reported as an allowance. A peak
above 100% plus that allowance means the capture point aggregates several links
(a fan-in tap): it measures what one egress port fed by those links would have
had to absorb. This assumes timestamps mark the start of each frame; captures
that timestamp the end of the frame, or in software, shift every window.

The average is taken over the time the traffic actually occupied, from the
first frame's start to the last frame's end. Windows longer than the capture
are reported as not applicable.
"""
from __future__ import annotations

import numpy as np

PREAMBLE_SFD_IFG = 8 + 12
FCS = 4

_UNITS = {"ns": 1, "us": 1_000, "ms": 1_000_000, "s": 1_000_000_000}
_RATES = {"k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}


def parse_duration(text: str) -> int:
    t = text.strip().lower()
    for unit in ("ns", "us", "ms", "s"):
        if t.endswith(unit):
            return int(float(t[: -len(unit)]) * _UNITS[unit])
    return int(float(t))


def parse_rate(text: str) -> float:
    t = text.strip().lower().removesuffix("bps").removesuffix("b/s")
    if t and t[-1] in _RATES:
        return float(t[:-1]) * _RATES[t[-1]]
    return float(t)


def fmt_duration(ns: int) -> str:
    for unit, mult in (("s", 1_000_000_000), ("ms", 1_000_000), ("us", 1_000)):
        if ns >= mult and ns % mult == 0:
            return f"{ns // mult} {unit}"
    return f"{ns} ns"


def burst_profile(ts_ns: np.ndarray, orig_len: np.ndarray, line_rate_bps: float,
                  windows_ns=(10_000, 100_000, 1_000_000, 10_000_000, 1_000_000_000),
                  fcs_in_capture=False, threshold: float = 0.9,
                  resolution_ns: float = 1.0) -> list[dict]:
    """Busiest window per time scale.

    ``fcs_in_capture`` is a bool for the whole capture, or a per-packet boolean
    array (pcapng interfaces can differ).
    """
    order = np.argsort(ts_ns, kind="stable")
    ts = np.asarray(ts_ns, dtype=np.int64)[order]
    n = len(ts)
    fcs_in = np.broadcast_to(np.asarray(fcs_in_capture, dtype=bool), (len(order),))[order] if n else \
        np.zeros(0, dtype=bool)
    overhead = PREAMBLE_SFD_IFG + np.where(fcs_in, 0, FCS)
    bits = (np.asarray(orig_len, dtype=np.int64)[order] + overhead) * 8
    cum = np.concatenate(([0], np.cumsum(bits)))
    # Relative times: adding a float to an epoch timestamp in ns would round it
    # to a multiple of 256 ns.
    rel = ts - ts[0] if n else ts
    end = rel + bits * 1e9 / line_rate_bps            # each frame's own completion time
    span = float(end.max()) if n else 0.0             # first start to last finish
    first = np.searchsorted(rel, rel, side="left")    # equal starts share one window
    by_end = np.argsort(end, kind="stable")
    end_sorted = end[by_end]
    cum_end = np.concatenate(([0], np.cumsum(bits[by_end])))
    rows = []
    for w in windows_ns:
        capacity = line_rate_bps * w / 1e9
        allowance = 2 * resolution_ns / w
        if n == 0 or w > span:
            rows.append({"window_ns": int(w), "window": fmt_duration(int(w)), "peak_bits": None,
                         "peak_utilization": float("nan"), "peak_start_ns": None,
                         "episodes_above_threshold": None, "applicable": False,
                         "allowance": allowance, "beyond_line_rate": False})
            continue
        # Bits of the frames that start at or after the window start and finish
        # by its end, S(i) = E(stop_i) - T(i), where E(x) is the bits of all
        # frames finished by x and T(i) the bits of frames that started before
        # rel_i but finished by stop_i. T(i) = cum[first_i] - U(i), where U(i) is
        # the bits of frames that started before rel_i and finish after stop_i.
        # Because both first_i and stop_i grow with i, the windows a frame j
        # straddles that way form one contiguous range [p_j, q_j), so U is a
        # range sum built with a difference array. Exact, O(n log n), and
        # independent of how many frames share a timestamp.
        stop = (rel + w).astype(np.float64)
        e_all = np.searchsorted(end_sorted, stop, side="right")
        E = cum_end[e_all]
        p = np.searchsorted(rel, rel, side="right")        # first window starting after frame j
        q = np.searchsorted(stop, end, side="left")        # first window that ends at or after end_j
        live = p < q
        diff = np.zeros(n + 1, dtype=np.int64)
        np.add.at(diff, p[live], bits[live])
        np.add.at(diff, q[live], -bits[live])
        U = np.cumsum(diff[:n])
        win_bits = E - (cum[first] - U)
        i = int(np.argmax(win_bits))
        hot = win_bits >= threshold * capacity
        episodes = int(np.count_nonzero(hot[1:] & ~hot[:-1]) + (1 if hot[0] else 0))
        peak = float(win_bits[i] / capacity)
        rows.append({
            "window_ns": int(w),
            "window": fmt_duration(int(w)),
            "peak_bits": int(win_bits[i]),
            "peak_utilization": peak,
            "peak_start_ns": int(ts[i]),
            "episodes_above_threshold": episodes,
            "applicable": True,
            "allowance": allowance,
            "beyond_line_rate": peak > 1 + allowance,
        })
    avg = float(cum[-1] / (line_rate_bps * span / 1e9)) if span else float("nan")
    for r in rows:
        r["average_utilization"] = avg
    return rows
