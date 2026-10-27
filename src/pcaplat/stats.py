"""Tail statistics with honest uncertainty.

Percentiles use the nearest-rank definition, with ranks computed in exact
rational arithmetic (in binary floating point, 99.9 / 100 is
0.9990000000000001, and 1000 times that rounds up to rank 1000).

Confidence intervals are distribution-free and exact: if B is the number of
samples below the true q-quantile, B ~ Binomial(n, q), and the interval
[x_(l), x_(u)] covers the quantile with probability P(l <= B <= u - 1). The
ranks are chosen so that this probability is at least the requested
confidence. When the sample is too small for that, an end of the interval is
unbounded (-inf or +inf) rather than falsely narrow: with 1,000 samples, a
p99.99 has no finite upper bound.

These intervals assume independent, identically distributed samples. Latency
samples taken during a burst are correlated, so the real uncertainty is
larger than reported; the intervals are a lower bound on it.

Each percentile also reports how many samples are ranked above it (ties
included). Below a minimum (100 by default) the value is flagged: with only a
handful of points in the tail, a p99.99 is closer to an anecdote than to a
statistic.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from fractions import Fraction

import numpy as np
from scipy.stats import binom

DEFAULT_PERCENTILES = (50.0, 90.0, 99.0, 99.9, 99.99, 99.999)


@dataclass
class PercentileRow:
    percentile: float
    value_ns: float          # math.inf means "beyond this rank, packets were lost or late"
    ci_low_ns: float         # -inf when no finite lower bound exists at this sample size
    ci_high_ns: float        # +inf when no finite upper bound exists at this sample size
    beyond: int              # samples ranked above this percentile's rank (ties included)
    reliable: bool
    ci_low_unbounded: bool = False    # too few samples for a finite lower bound
    ci_high_unbounded: bool = False   # too few samples for a finite upper bound


def _exact_q(percentile: float) -> Fraction:
    """99.9 -> 999/1000 exactly."""
    return Fraction(str(percentile)) / 100


def _rank(n: int, percentile: float) -> int:
    return min(n, max(1, math.ceil(n * _exact_q(percentile))))


def quantile_ci_ranks(n: int, percentile: float, confidence: float = 0.95) -> tuple[int, int]:
    """1-based ranks (l, u) of an exact distribution-free interval [x_(l), x_(u)].

    l == 0 means no finite lower bound; u == n + 1 means no finite upper bound.
    """
    q = float(_exact_q(percentile))
    alpha = 1.0 - confidence
    lo = int(binom.ppf(alpha / 2, n, q))           # P(B <= lo - 1) < alpha / 2
    hi = int(binom.ppf(1 - alpha / 2, n, q)) + 1   # P(B >= hi) <= alpha / 2
    return max(lo, 0), min(hi, n + 1)


def percentile_table(sorted_values: np.ndarray, percentiles=DEFAULT_PERCENTILES,
                     confidence: float = 0.95, min_tail: int = 100) -> list[PercentileRow]:
    """Percentiles of an ascending array (may end with +inf entries for losses)."""
    n = len(sorted_values)
    rows: list[PercentileRow] = []
    if n == 0:
        return rows
    for p in percentiles:
        k = _rank(n, p)
        lo, hi = quantile_ci_ranks(n, p, confidence)
        rows.append(PercentileRow(
            percentile=p,
            value_ns=float(sorted_values[k - 1]),
            ci_low_ns=float(sorted_values[lo - 1]) if lo >= 1 else -math.inf,
            ci_high_ns=float(sorted_values[hi - 1]) if hi <= n else math.inf,
            beyond=n - k,
            reliable=(n - k) >= min_tail,
            ci_low_unbounded=lo < 1,
            ci_high_unbounded=hi > n,
        ))
    return rows


def samples_needed(percentile: float, min_tail: int = 100) -> int:
    """Smallest sample size that leaves ``min_tail`` samples beyond a percentile."""
    return math.ceil(min_tail / (1 - _exact_q(percentile)))


def summarize(latency_ns: np.ndarray, lost: int = 0, percentiles=DEFAULT_PERCENTILES,
              min_tail: int = 100, late: int = 0, cohort_latency_ns: np.ndarray | None = None) -> dict:
    """Matched-only and loss-aware percentile summaries.

    Lost and late cohort packets rank as infinitely late. NaN entries in
    ``cohort_latency_ns`` are clock-invalid members: counted in the cohort and
    in the loss-rate denominator, not ranked.
    """
    x = np.sort(np.asarray(latency_ns, dtype=np.float64))
    c = x if cohort_latency_ns is None else np.asarray(cohort_latency_ns, dtype=np.float64)
    invalid = np.isnan(c)
    clock_invalid = int(invalid.sum())
    c = np.sort(c[~invalid])
    ranked = len(c) + lost + late
    cohort = ranked + clock_invalid
    out = {
        "samples": int(len(x)),
        "lost": int(lost),
        "late": int(late),
        "clock_invalid": clock_invalid,
        "cohort": int(cohort),
        "ranked_in_loss_aware": int(ranked),
        "loss_rate": (lost / cohort) if cohort else 0.0,
        "min_ns": float(x[0]) if len(x) else math.nan,
        "mean_ns": float(x.mean()) if len(x) else math.nan,
        "std_ns": float(x.std()) if len(x) else math.nan,
        "max_ns": float(x[-1]) if len(x) else math.nan,
        "percentiles": [asdict(r) for r in percentile_table(x, percentiles, min_tail=min_tail)],
    }
    if lost or late:
        xl = np.concatenate([c, np.full(lost + late, np.inf)])
        out["percentiles_loss_aware"] = [asdict(r) for r in percentile_table(xl, percentiles, min_tail=min_tail)]
    return out
