"""Match the same packets seen at two capture points and compute one-way latency.

A packet is identified by a 64-bit hash of fields that do not change between
the two points. Which fields are safe depends on the device in between:

  l4payload   IP addresses, protocol, ports and L4 payload (default).
              Survives routing: TTL, IP checksum and MAC addresses are excluded.
  frame       every byte up to the end of the IP packet.
              Only for devices that do not rewrite anything (L1 / L2 switching).
  bytes:O:L   IP addresses, protocol, ports and L bytes of payload starting at
              offset O, e.g. the sequence-number field of a market-data header.

Packets whose identity cannot be established are not keyed, and are counted:
  * truncated by the snap length (l4payload and frame keys): two different
    packets can share the same captured prefix;
  * fragments (l4payload and bytes keys): a fragment's payload is not the
    datagram's payload, and later fragments carry no transport header.
    The frame key, which includes the IP identification and fragment offset,
    still keys them.

A key that occurs more than once in either capture (heartbeats,
retransmissions) is ambiguous. It is excluded from both captures, so that a
duplicate on one side does not turn into a false loss or false extra packet
on the other.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .layout import _to16, compute_layout, hash_rows
from .reader import Capture


@dataclass
class KeySpec:
    mode: str = "l4payload"
    offset: int = 0
    length: int = 0

    @classmethod
    def parse(cls, text: str) -> "KeySpec":
        if text in ("l4payload", "frame"):
            return cls(text)
        if text.startswith("bytes:"):
            try:
                _, o, l = text.split(":")
                o, l = int(o), int(l)
            except ValueError:
                o = l = -1
            if o >= 0 and l >= 1:
                return cls("bytes", o, l)
        raise ValueError(f"invalid key spec {text!r} (use l4payload, frame or bytes:OFFSET:LENGTH "
                         "with OFFSET >= 0 and LENGTH >= 1)")

    def __str__(self) -> str:
        return f"bytes:{self.offset}:{self.length}" if self.mode == "bytes" else self.mode


@dataclass
class PacketFilter:
    dst_ip: bytes | None = None
    dst_port: int | None = None
    proto: int | None = None


def packet_keys(cap: Capture, spec: KeySpec, flt: PacketFilter | None = None,
                select: np.ndarray | None = None) -> pd.DataFrame:
    """One row per keyable packet: key, ts_ns, orig_len, fcs_bytes.

    ``select`` restricts to some packets (one interface of a pcapng). Unkeyed
    packets are counted in ``attrs["skipped"]``. ``attrs["span"]`` is the time
    range of all selected packets, keyed or not; it bounds the loss cohort.
    """
    lay = compute_layout(cap, select)
    sel = np.ones(len(cap), dtype=bool) if select is None else np.asarray(select, dtype=bool)
    keep = lay.ok.copy()
    skipped = {"selected": int(sel.sum()), "not_ip_or_malformed": int((sel & ~lay.ok).sum())}
    if flt is not None:
        if flt.dst_ip is not None:
            want = np.frombuffer(_to16(flt.dst_ip), np.uint8)
            keep &= (lay.addr[:, 16:] == want).all(axis=1)
        if flt.dst_port is not None:
            keep &= lay.dport == flt.dst_port
        if flt.proto is not None:
            keep &= lay.proto == flt.proto
    skipped["filtered_out"] = int((sel & lay.ok & ~keep).sum())
    if spec.mode in ("l4payload", "frame"):
        skipped["truncated"] = int((keep & lay.truncated).sum())
        keep &= ~lay.truncated
    else:
        skipped["truncated"] = 0
    if spec.mode in ("l4payload", "bytes"):
        skipped["fragments"] = int((keep & lay.fragment).sum())
        keep &= ~lay.fragment
    else:
        skipped["fragments"] = 0

    if spec.mode == "frame":
        starts, ends, header = lay.frame_start, lay.l3_end, None
    else:
        header = np.concatenate([
            lay.proto[:, None],
            lay.addr,
            (lay.sport >> 8).astype(np.uint8)[:, None], (lay.sport & 0xFF).astype(np.uint8)[:, None],
            (lay.dport >> 8).astype(np.uint8)[:, None], (lay.dport & 0xFF).astype(np.uint8)[:, None],
        ], axis=1)
        if spec.mode == "l4payload":
            starts, ends = lay.pay_off, lay.pay_end
        else:
            starts = lay.pay_off + spec.offset
            ends = starts + spec.length
            absent = keep & (ends > lay.pay_end)       # field not (fully) present in the payload
            skipped["field_absent"] = int(absent.sum())
            keep &= ~absent
    idx = np.nonzero(keep)[0]
    B = np.frombuffer(cap.buf, dtype=np.uint8) if len(cap) else np.zeros(1, np.uint8)
    keys = hash_rows(B, header[idx] if header is not None else None, starts[idx], (ends - starts)[idx])
    df = pd.DataFrame({
        "key": keys,
        "ts_ns": cap.ts_ns[idx],
        "orig_len": cap.orig_len[idx],
        "fcs_bytes": cap.fcs_bytes[idx],
    })
    df.attrs["skipped"] = skipped
    sel_ts = cap.ts_ns[sel] if len(cap) else cap.ts_ns
    df.attrs["span"] = (int(sel_ts.min()), int(sel_ts.max())) if len(sel_ts) else None
    return df


def _span(df: pd.DataFrame) -> tuple[int, int] | None:
    """Observation span of a capture point: from packet_keys, else from its keyed packets."""
    span = df.attrs.get("span")
    if span is not None:
        return int(span[0]), int(span[1])
    return (int(df["ts_ns"].min()), int(df["ts_ns"].max())) if len(df) else None


@dataclass
class MatchResult:
    matched: pd.DataFrame                 # key, ts_a, ts_b, latency_ns, orig_len, in_cohort
    counts: dict = field(default_factory=dict)

    def loss_aware_latencies(self) -> np.ndarray:
        """Latencies of matched cohort members, plus NaN for each clock-invalid
        member (counted in the cohort but not ranked, see stats.summarize).
        """
        lat = self.matched.loc[self.matched["in_cohort"], "latency_ns"].to_numpy(np.float64)
        invalid = int(self.counts.get("clock_invalid_in_cohort", 0))
        return np.concatenate([lat, np.full(invalid, np.nan)]) if invalid else lat


def _isin(values: np.ndarray, pool: np.ndarray) -> np.ndarray:
    return np.isin(values, pool, assume_unique=False)


def match(a: pd.DataFrame, b: pd.DataFrame, max_latency_ns: int = 1_000_000,
          max_negative_ns: int = 0) -> MatchResult:
    """Join packets seen at A and B by key.

    Keys are unique on both sides, so a pair outside the window is still the
    same packet: late beyond ``max_latency_ns``, clock-invalid before
    ``-max_negative_ns``. Neither counts as loss or extra traffic.

    The loss cohort is the A packets sent while B was observing and early enough
    for B to see them. Each member is matched, late, clock-invalid or lost;
    ``counts["cohort"]`` is their sum and the loss rate is lost / cohort.
    """
    counts: dict[str, int] = {"packets_a": len(a), "packets_b": len(b)}
    ka = a["key"].to_numpy(np.uint64)
    kb = b["key"].to_numpy(np.uint64)
    dup_a = a["key"].duplicated(keep=False).to_numpy()
    dup_b = b["key"].duplicated(keep=False).to_numpy()
    ambiguous = np.union1d(ka[dup_a], kb[dup_b])
    amb_a, amb_b = _isin(ka, ambiguous), _isin(kb, ambiguous)
    counts["ambiguous_a"] = int(amb_a.sum())
    counts["ambiguous_b"] = int(amb_b.sum())
    a1, b1 = a.loc[~amb_a], b.loc[~amb_b]

    m = a1.merge(b1[["key", "ts_ns"]], on="key", how="inner", suffixes=("_a", "_b"))
    m = m.rename(columns={"ts_ns_a": "ts_a", "ts_ns_b": "ts_b"})
    m["latency_ns"] = m["ts_b"] - m["ts_a"]
    late = (m["latency_ns"] > max_latency_ns).to_numpy()
    too_negative = (m["latency_ns"] < -max_negative_ns).to_numpy()
    counts["late_beyond_window"] = int(late.sum())
    counts["latest_ns"] = int(m.loc[late, "latency_ns"].max()) if late.any() else 0
    counts["negative_beyond_allowance"] = int(too_negative.sum())
    counts["out_of_window"] = counts["late_beyond_window"] + counts["negative_beyond_allowance"]
    counts["negative_latency"] = int((m["latency_ns"] < 0).sum())
    paired = np.sort(m["key"].to_numpy(np.uint64))       # same packet seen at both points

    # Loss cohort: needs B to have observed something, keyed or not.
    span_a, span_b = _span(a), _span(b)
    m["in_cohort"] = False
    counts["cohort"] = counts["lost"] = counts["late_in_cohort"] = counts["extra_b"] = 0
    counts["clock_invalid_in_cohort"] = 0
    if span_b is not None and len(a1):
        lo, hi = span_b[0], span_b[1] - max_latency_ns
        ts_a1 = a1["ts_ns"].to_numpy()
        cohort = (ts_a1 >= lo) & (ts_a1 <= hi)
        seen = _isin(a1["key"].to_numpy(np.uint64), paired)
        counts["cohort"] = int(cohort.sum())
        counts["lost"] = int((cohort & ~seen).sum())
        m["in_cohort"] = (m["ts_a"] >= lo) & (m["ts_a"] <= hi)
        counts["late_in_cohort"] = int((late & m["in_cohort"].to_numpy()).sum())
        counts["clock_invalid_in_cohort"] = int((too_negative & m["in_cohort"].to_numpy()).sum())
    # Extra traffic at B: the mirror image, bounded by A's observation window.
    if span_a is not None and len(b1):
        lo_a, hi_a = span_a[0] + max_latency_ns, span_a[1]
        ts_b1 = b1["ts_ns"].to_numpy()
        b_overlap = (ts_b1 >= lo_a) & (ts_b1 <= hi_a)
        counts["extra_b"] = int((b_overlap & ~_isin(b1["key"].to_numpy(np.uint64), paired)).sum())
    counts["a_in_overlap"] = counts["cohort"]            # name kept for older reports
    counts["loss_rate"] = counts["lost"] / counts["cohort"] if counts["cohort"] else 0.0
    m = m.loc[~late & ~too_negative].sort_values("ts_a", kind="stable").reset_index(drop=True)
    counts["matched"] = len(m)
    counts["matched_in_cohort"] = int(m["in_cohort"].sum())
    assert counts["cohort"] == (counts["matched_in_cohort"] + counts["late_in_cohort"]
                                + counts["clock_invalid_in_cohort"] + counts["lost"])
    cols = ["key", "ts_a", "ts_b", "latency_ns", "orig_len", "fcs_bytes", "in_cohort"]
    return MatchResult(m[[c for c in cols if c in m.columns]], counts)
