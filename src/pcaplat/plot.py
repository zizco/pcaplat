"""Figures: latency CCDF and burst profile."""
from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ACCENT = "#1F4E79"


def ccdf_plot(latency_ns: np.ndarray, path: str, percentile_rows: list[dict],
              min_tail: int = 100, title: str = "One-way latency, CCDF") -> None:
    """CCDF with a log probability axis and the tail-sufficiency line. The latency
    axis is log, or symmetric-log with a marked zero when some latencies are <= 0.
    """
    x = np.sort(np.asarray(latency_ns, dtype=np.float64)) / 1_000.0     # microseconds
    n = len(x)
    fig, ax = plt.subplots(figsize=(8, 4.8), dpi=150)
    if n >= 1:
        cx, cy, last = ccdf_points(x)
        ax.step(cx, cy, where="post", color=ACCENT, lw=1.4)
        # P(latency > max) is 0, which a log axis cannot show: draw the final
        # drop at the maximum down to the bottom of the axis.
        floor = max(1.0 / n, 1e-9) * 0.5
        ax.vlines([x[-1]], floor, last, color=ACCENT, lw=1.4)
        if x[0] > 0:
            ax.set_xscale("log")
        else:
            nonzero = np.abs(x[x != 0])
            linthresh = 10.0 ** np.floor(np.log10(nonzero.min())) if len(nonzero) else 0.001
            ax.set_xscale("symlog", linthresh=linthresh)
            ax.axvline(0, color="0.3", lw=0.8)
            neg = int((x < 0).sum())
            if neg:
                ax.text(0.01, 0.02, f"{neg:,} negative latencies: clock offset between the capture points",
                        transform=ax.transAxes, color="0.35", fontsize=7.5)
            lo, hi = x[0], x[-1]
            pad = max(abs(lo), abs(hi), linthresh) * 0.5
            ax.set_xlim(lo - pad, hi + pad)
        ax.set_yscale("log")
        ax.set_ylim(floor, 1.2)
        if min_tail < n:
            ax.axhline(min_tail / n, color="0.45", ls=":", lw=1)
            ax.text(0.01, min_tail / n * 1.15, f"below this line: fewer than {min_tail} samples, read with care",
                    transform=ax.get_yaxis_transform(), color="0.35", fontsize=7.5)
        else:
            ax.text(0.99, 0.97, f"only {n:,} samples: the whole curve has fewer than {min_tail}, read with care",
                    transform=ax.transAxes, ha="right", va="top", color="0.35", fontsize=7.5)
        marks = [(r["value_ns"] / 1_000.0, 1 - r["percentile"] / 100.0, r["percentile"]) for r in percentile_rows
                 if np.isfinite(r["value_ns"]) and r["percentile"] >= 99 and 1 - r["percentile"] / 100.0 >= 1.0 / n]
        for vx, vy, _ in marks:                    # mark each percentile on the curve itself
            ax.plot([vx], [vy], "o", color="0.25", ms=3.5)
        ax.autoscale_view()
        to_axes = ax.transAxes.inverted()
        for vx, vy, p in marks:                    # label to the left, unless that runs off the axes
            left = to_axes.transform(ax.transData.transform((vx, vy)))[0] > 0.2
            ax.annotate(f"p{p:g}  {vx:.2f} \u00b5s", (vx, vy), xytext=(-8 if left else 8, 0),
                        textcoords="offset points", ha="right" if left else "left", va="center",
                        fontsize=7.5, color="0.25")
    ax.set_xlabel("one-way latency (µs)")
    ax.set_ylabel("P(latency > x)")
    ax.set_title(title, fontsize=10)
    ax.grid(True, which="both", color="0.92", lw=0.6)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def ccdf_points(x: np.ndarray, body_points: int = 4000, tail_samples: int = 2000):
    """(xs, ys, last) for a post-step CCDF of a sorted array.

    P(X > v) is exact at distinct values, so ties make one step. The curve starts
    at (min, 1) and ends on the plateau that reaches the maximum. The body is
    thinned to about ``body_points`` levels; the top ``tail_samples`` are kept.
    """
    n = len(x)
    vals, counts = np.unique(x, return_counts=True)
    surv = (n - np.cumsum(counts)) / n                 # P(X > vals[j]); the last one is 0
    k = len(vals)
    pos = np.arange(k - 1)                             # levels above zero
    if k - 1 > body_points:
        targets = np.logspace(np.log10(1.0 / n), 0, body_points)
        pick = np.searchsorted(-surv[:-1], -targets, side="left")
        tail = pos[surv[:-1] * n <= tail_samples]
        pos = np.unique(np.concatenate([pick[pick < k - 1], tail, [0, k - 2]]))
    last = float(surv[k - 2]) if k > 1 else 1.0        # level of the plateau that ends at the maximum
    xs = np.concatenate([[vals[0]], vals[pos], [vals[-1]]])
    ys = np.concatenate([[1.0], surv[pos], [last]])
    return xs, ys, last


def burst_plot(rows: list[dict], path: str, title: str = "Peak utilization by time scale") -> None:
    rows = [r for r in rows if r.get("applicable", True)]
    labels = [r["window"].replace(" us", " \u00b5s") for r in rows]
    peaks = [100 * r["peak_utilization"] for r in rows]
    avg = 100 * rows[0]["average_utilization"] if rows else 0
    fig, ax = plt.subplots(figsize=(8, 4.2), dpi=150)
    bars = ax.bar(labels, peaks, color=ACCENT, width=0.6)
    ax.axhline(100, color="0.3", ls="-", lw=0.8)
    ax.axhline(avg, color="0.5", ls=":", lw=1, label=f"average over the whole capture: {avg:.2f}%")
    ax.legend(loc="upper right", frameon=False, fontsize=8)
    for b, p in zip(bars, peaks):
        ax.text(b.get_x() + b.get_width() / 2, p, f"{p:.1f}%", ha="center", va="bottom", fontsize=8)
    ax.set_ylim(0, max(115, max(peaks, default=0) * 1.12))
    ax.set_ylabel("busiest window, % of line rate")
    ax.set_xlabel("window length")
    ax.set_title(title, fontsize=10)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
