"""Write measurement reports.

The report states the three things a latency number needs before it means
anything: the distribution (with sample counts beyond each percentile), where
the timestamps were taken, and which clock took them.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import platform
from datetime import datetime, timezone

import numpy as np

from . import __version__


def fmt_ns(v: float) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "n/a"
    if math.isinf(v):
        return "lost"
    a = abs(v)
    if a < 1_000:
        return f"{v:.0f} ns"
    if a < 1_000_000:
        return f"{v / 1_000:.2f} µs"
    if a < 1_000_000_000:
        return f"{v / 1_000_000:.3f} ms"
    return f"{v / 1e9:.3f} s"


def file_info(path: str, cap) -> dict:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return {
        "file": os.path.basename(path),
        "sha256_12": h.hexdigest()[:12],
        "format": cap.fmt,
        "timestamp_resolution": cap.ts_resolution,
        "packets": len(cap),
        "duration_ns": cap.duration_ns,
    }


def versions() -> dict:
    import pandas
    import pyarrow
    return {
        "pcaplat": __version__,
        "python": platform.python_version(),
        "numpy": np.__version__,
        "pandas": pandas.__version__,
        "pyarrow": pyarrow.__version__,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    }


def _ptable(rows: list[dict]) -> list[str]:
    out = ["| Percentile | Value | 95% CI | Samples ranked beyond | Reliable |",
           "|---:|---:|---|---:|:---:|"]
    for r in rows:
        lo = "unbounded" if r.get("ci_low_unbounded") else fmt_ns(r["ci_low_ns"])
        hi = "unbounded" if r.get("ci_high_unbounded") else fmt_ns(r["ci_high_ns"])
        out.append(f"| p{r['percentile']:g} | {fmt_ns(r['value_ns'])} | {lo} to {hi} | {r['beyond']:,} | "
                   f"{'yes' if r['reliable'] else 'NO'} |")
    return out


def _cohort_breakdown(summary: dict, counts: dict) -> list[str]:
    """Every cohort member, accounted for once."""
    matched = summary.get("ranked_in_loss_aware", summary["cohort"]) - summary["lost"] - summary.get("late", 0)
    rows = [("Matched within the window", matched),
            ("Seen at B after the window (late)", summary.get("late", 0)),
            ("Seen at B before A beyond the allowed margin (clock-invalid)", summary.get("clock_invalid", 0)),
            ("Lost", summary["lost"])]
    out = ["| Cohort member | Packets |", "|---|---:|"]
    out += [f"| {name} | {v:,} |" for name, v in rows]
    out.append(f"| **Cohort** | **{summary['cohort']:,}** |")
    outside = summary["samples"] - matched
    if outside > 0:
        out.append("")
        out.append(f"The other {outside:,} matched samples were sent outside the cohort: they are in the "
                   "matched table, not in the loss accounting.")
    if summary.get("clock_invalid"):
        out.append("")
        out.append(f"The {summary['clock_invalid']:,} clock-invalid packets stay in the cohort and in the loss-rate "
                   "denominator (they did reach B), but they have no meaningful latency, so the loss-aware table "
                   f"ranks the other {summary.get('ranked_in_loss_aware', 0):,}. Fix the clock offset and rerun.")
    return out


def _late_sentence(late_in: int, late_out: int, table: bool) -> str:
    parts = []
    if late_in:
        parts.append(f"{late_in:,} belong to the loss cohort" + (
            " and are counted as infinitely late in the loss-aware table." if table else "."))
    if late_out:
        parts.append(f"{late_out:,} were sent outside the loss cohort, so they enter neither the loss rate "
                     "nor the loss-aware table.")
    return " ".join(parts)


def latency_markdown(summary: dict, meta: dict, counts: dict, files: list[dict],
                     load: dict, ccdf_png: str | None) -> str:
    L: list[str] = []
    L.append(f"# Latency report: {meta.get('label') or 'A to B'}")
    L.append("")
    L.append("## 1. What was measured")
    L.append("")
    L.append("| Field | Value |")
    L.append("|---|---|")
    L.append(f"| Path | {meta.get('label') or 'point A to point B'} |")
    L.append(f"| Timestamp source at A | {meta.get('ts_source_a') or 'not stated'} |")
    L.append(f"| Timestamp source at B | {meta.get('ts_source_b') or 'not stated'} |")
    L.append(f"| Clock | {meta.get('clock') or 'not stated'} |")
    ce = meta.get("clock_error_ns")
    L.append(f"| Estimated clock error | {fmt_ns(ce) if ce is not None else 'not stated'} |")
    L.append(f"| Matching key | `{meta.get('key')}` |")
    if meta.get("filter"):
        L.append(f"| Filter | {meta['filter']} |")
    L.append("")
    L.append("| Capture | File | SHA-256 (12) | Format | Resolution | Packets | Duration |")
    L.append("|---|---|---|---|---|---:|---:|")
    for name, f in zip(("A", "B"), files):
        L.append(f"| {name} | {f['file']} | `{f['sha256_12']}` | {f['format']} | "
                 f"{f['timestamp_resolution']} | {f['packets']:,} | {fmt_ns(f['duration_ns'])} |")
    L.append("")
    L.append("## 2. Load at A")
    L.append("")
    if load.get("available", load.get("gbps") is not None):
        L.append(f"{load['packets']:,} packets over {fmt_ns(load['duration_ns'])}: "
                 f"{load['pps']:,.0f} packets/s, {load['gbps']:.3f} Gb/s on the wire on average. "
                 "Estimated from start timestamps: the n-1 intervals between the first and last packet, "
                 "and the n-1 packets that open them.")
    else:
        L.append(f"{load['packets']:,} packets: average load not available "
                 "(it needs at least two distinct start timestamps).")
    L.append("")
    L.append("## 3. Results")
    L.append("")
    L.append(f"Matched samples: **{summary['samples']:,}**.")
    L.append("")
    L.append(f"Loss cohort: the **{summary['cohort']:,}** packets seen at A while B was capturing and early "
             f"enough for B to see them. Lost (never seen at B): **{summary['lost']:,}** "
             f"({100 * summary['loss_rate']:.4f}% of the cohort).")
    L.append("")
    L.extend(_cohort_breakdown(summary, counts))
    late_total = counts.get("late_beyond_window", 0)
    if late_total:
        late_in = summary.get("late", 0)
        L.append("")
        L.append(f"Later than the matching window: **{late_total:,}** (seen at both points; "
                 f"latest {fmt_ns(counts.get('latest_ns', 0))}). They are excluded from the matched table. "
                 + _late_sentence(late_in, late_total - late_in, "percentiles_loss_aware" in summary))
    L.append("")
    L.append(f"Min {fmt_ns(summary['min_ns'])}, max {fmt_ns(summary['max_ns'])}. "
             f"Mean {fmt_ns(summary['mean_ns'])} (shown for reference; the mean is a poor summary of a tail).")
    L.append("")
    L.append("### Matched packets")
    L.append("")
    L.extend(_ptable(summary["percentiles"]))
    if "percentiles_loss_aware" in summary:
        L.append("")
        L.append("### Loss-aware (each lost or late cohort packet counted as infinitely late)")
        L.append("")
        L.extend(_ptable(summary["percentiles_loss_aware"]))
    L.append("")
    L.append(f"A percentile is marked unreliable when fewer than {meta.get('min_tail', 100)} samples are ranked "
             "beyond it. Confidence intervals are distribution-free (binomial order statistics; ties only make "
             "them conservative); \"unbounded\" means the sample is too small for a finite limit. They assume "
             "independent, identically distributed samples: latencies measured during a burst are positively "
             "correlated, which usually makes the real uncertainty larger.")
    if ccdf_png:
        L.append("")
        L.append(f"![CCDF]({ccdf_png})")
    L.append("")
    L.append("## 4. Sanity checks")
    L.append("")
    L.extend(f"- {c}" for c in sanity_checks(summary, meta, counts, files))
    L.append("")
    L.append("## 5. Versions")
    L.append("")
    L.extend(f"- {k}: {v}" for k, v in meta["versions"].items())
    L.append("")
    return "\n".join(L)


def sanity_checks(summary: dict, meta: dict, counts: dict, files: list[dict]) -> list[str]:
    c: list[str] = []
    if meta.get("same_clock"):
        c.append("OK: stated by the user that one clock timestamped both points; inter-clock error does not apply.")
    else:
        if meta.get("single_file"):
            c.append("CHECK: both points come from one file, which does not prove they share a clock "
                     "(captures can be merged). Use --same-clock only if one device timestamped both.")
        if meta.get("clock_error_ns") is None:
            c.append("CHECK: no clock error stated. Two clocks add their offset to every sample.")
    if counts.get("negative_latency"):
        c.append(f"CHECK: {counts['negative_latency']:,} negative latencies. The B clock is behind the A clock "
                 "by at least that much, or the key matched the wrong packets.")
    if counts.get("late_beyond_window"):
        c.append(f"CHECK: {counts['late_beyond_window']:,} packets reached B later than --max-latency "
                 f"(latest {fmt_ns(counts.get('latest_ns', 0))}). If they are real, rerun with a larger window.")
    if counts.get("negative_beyond_allowance"):
        c.append(f"CHECK: {counts['negative_beyond_allowance']:,} packets reached B before A beyond the allowed "
                 "margin: a clock offset between the two capture points, not a network effect.")
    amb = counts.get("ambiguous_a", 0) + counts.get("ambiguous_b", 0)
    if amb:
        c.append(f"INFO: {counts.get('ambiguous_a', 0):,} packets at A and {counts.get('ambiguous_b', 0):,} at B "
                 "share their key with another packet (heartbeats, retransmissions) and were excluded.")
    if counts.get("extra_b"):
        c.append(f"INFO: {counts['extra_b']:,} packets at B have no match at A (other traffic, or traffic "
                 "that does not cross point A).")
    for side in ("a", "b"):
        sk = counts.get(f"skipped_{side}", {})
        parts = [f"{sk[k]:,} {label}" for k, label in (
            ("truncated", "cut by the snap length"), ("fragments", "IP fragments"),
            ("not_ip_or_malformed", "not IP or with invalid headers"),
            ("field_absent", "without the key field")) if sk.get(k)]
        if parts:
            c.append(f"INFO: at {side.upper()}, packets not keyed: " + ", ".join(parts) + ".")
    for side in ("a", "b"):
        res = meta.get(f"resolution_{side}_ns")
        if res is not None and res >= 1_000:
            c.append(f"CHECK: capture {side.upper()} has timestamps no finer than {fmt_ns(res)}; "
                     "results below that resolution are not meaningful.")
    for issue in meta.get("issues", []):
        c.append(f"CHECK: {issue}")
    ce = meta.get("clock_error_ns")
    if ce:
        c.append(f"RULE: with a clock error of about {fmt_ns(ce)}, differences smaller than about "
                 f"{fmt_ns(10 * ce)} between two configurations should not be read as real.")
    unreliable = [r for r in summary["percentiles"] if not r["reliable"]]
    if unreliable:
        worst = unreliable[0]["percentile"]
        c.append(f"CHECK: p{worst:g} and above have too few samples beyond them to be stable.")
    if not c:
        c.append("OK: no issue detected.")
    return c


NONFINITE_BASE = ("non-finite numbers are written as null, with a sibling field '<name>_nonfinite' "
                  "set to '+inf', '-inf' or 'nan'.")
NONFINITE_NOTE = (NONFINITE_BASE + " In percentile rows, '+inf' is a lost or late packet "
                  "ranked as infinitely late, and an unbounded interval end also has its "
                  "ci_low_unbounded / ci_high_unbounded flag; 'nan' is a statistic of an empty sample.")


def _nonfinite_tag(v: float) -> str:
    return "nan" if math.isnan(v) else ("+inf" if v > 0 else "-inf")


def json_safe(obj):
    """Copy of ``obj`` that is valid JSON: a non-finite float under a key becomes
    null plus ``<key>_nonfinite`` ("+inf", "-inf" or "nan"); in a list, null.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            v = json_safe_scalar(v)
            if isinstance(v, float) and not math.isfinite(v):
                out[k] = None
                out[f"{k}_nonfinite"] = _nonfinite_tag(v)
            else:
                out[k] = json_safe(v)
        return out
    if isinstance(obj, (list, tuple)):
        items = [json_safe_scalar(v) for v in obj]
        return [None if isinstance(v, float) and not math.isfinite(v) else json_safe(v) for v in items]
    return json_safe_scalar(obj)


def json_safe_scalar(v):
    if isinstance(v, np.bool_):
        return bool(v)
    if isinstance(v, np.integer):
        return int(v)
    if isinstance(v, np.floating):
        return float(v)
    return v


def write_json(path: str, obj: dict, note: str = NONFINITE_NOTE) -> None:
    """Write strict JSON: non-finite values are encoded as described in ``note``."""
    safe = json_safe(obj)
    if isinstance(safe, dict):
        safe = {"json_encoding": note, **safe}
    with open(path, "w") as f:
        json.dump(safe, f, indent=2, default=str, allow_nan=False)


def bursts_markdown(rows: list[dict], meta: dict, info: dict, png: str | None) -> str:
    L = [f"# Burst profile: {info['file']}", ""]
    L.append(f"Line rate {meta['line_rate']}, {info['packets']:,} packets over {fmt_ns(info['duration_ns'])}, "
             f"timestamp resolution {info['timestamp_resolution']}.")
    L.append("")
    L.append("| Window | Busiest window (% of line rate) | Starts at (ns) | Windows above "
             f"{int(100 * meta['threshold'])}% |")
    L.append("|---:|---:|---:|---:|")
    for r in rows:
        if not r.get("applicable", True):
            L.append(f"| {r['window']} | longer than the capture | | |")
            continue
        L.append(f"| {r['window']} | {100 * r['peak_utilization']:.2f}% | {r['peak_start_ns']} | "
                 f"{r['episodes_above_threshold']:,} |")
    L.append("")
    if rows:
        L.append(f"Average from the first frame's start to the last frame's end: "
                 f"{100 * rows[0]['average_utilization']:.3f}% of line rate.")
    L.append("")
    L.append("Only frames that start and finish serializing inside a window are counted. On one link, a peak can "
             "exceed 100% only by timestamp rounding, about two timestamp resolutions over the window length; "
             "a peak beyond line rate plus that allowance means the capture aggregates several links (fan-in). Timestamps are assumed to mark "
             "the start of each frame.")
    flagged = [r for r in rows if r.get("beyond_line_rate")]
    if flagged:
        L.append("")
        L.append("Beyond line rate plus rounding allowance (fan-in): " + ", ".join(
            f"{r['window']} ({100 * r['peak_utilization']:.2f}%, allowance {100 * r['allowance']:.3f}%)"
            for r in flagged) + ".")
    for issue in meta.get("issues", []):
        L.append("")
        L.append(f"Note: {issue}")
    if png:
        L += ["", f"![Burst profile]({png})"]
    L.append("")
    return "\n".join(L)
