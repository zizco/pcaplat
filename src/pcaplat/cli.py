"""Command-line interface: pcaplat doctor | capture | info | latency | bursts | synth."""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys

import numpy as np

from . import __version__
from .bursts import burst_profile, parse_duration, parse_rate
from .capture import load_sidecar, pair_issues, sidecar_issues, sidecar_summary
from .match import KeySpec, PacketFilter, match, packet_keys
from .reader import read_capture
from .report import (bursts_markdown, file_info, fmt_ns, latency_markdown, versions,
                     write_json)
from .stats import DEFAULT_PERCENTILES, summarize


def _positive_int(text: str) -> int:
    v = int(text)
    if v < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {v}")
    return v


def _percentiles(text: str):
    if not text:
        return DEFAULT_PERCENTILES
    try:
        values = tuple(float(x) for x in text.split(","))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a comma-separated list of numbers: {text!r}") from None
    bad = [v for v in values if not 0 <= v <= 100]
    if bad:
        raise argparse.ArgumentTypeError(f"percentiles must be between 0 and 100, got {bad[0]:g}")
    return values


def cmd_info(args) -> int:
    for path in args.files:
        cap = read_capture(path)
        print(f"{path}: {cap.fmt}, {len(cap):,} packets, duration {fmt_ns(cap.duration_ns)}")
        for itf in cap.interfaces:
            count = int((cap.iface == itf.index).sum())
            print(f"  interface {itf.index} (section {itf.section}, id {itf.local_id}): link type {itf.linktype}, "
                  f"resolution {itf.resolution}, FCS bytes {itf.fcs_bytes}, offset {itf.tsoffset_s} s, "
                  f"{count:,} packets")
        for issue in cap.issues:
            print(f"  warning: {issue}")
        meta = load_sidecar(path)
        if meta:
            print(f"  captured with pcaplat capture: {sidecar_summary(meta)}")
            for issue in sidecar_issues("this file", meta):
                print(f"  warning: {issue}")
    return 0


def load_estimate(ts_ns: np.ndarray, orig_len: np.ndarray, fcs_bytes: np.ndarray) -> dict:
    """Average load at A from start timestamps alone.

    Without a line rate the last frame's duration is unknown, so this uses the
    n - 1 frames that open the n - 1 intervals between the first and last start.
    Wire size adds 20 bytes, plus 4 for the FCS when it was not captured.
    Unavailable with fewer than two distinct start times.
    """
    n = len(ts_ns)
    order = np.argsort(ts_ns, kind="stable")
    ts = ts_ns[order]
    wire = (orig_len[order] + 20 + np.where(fcs_bytes[order] > 0, 0, 4)) * 8
    dur = int(ts[-1] - ts[0]) if n else 0
    out = {"packets": n, "duration_ns": dur,
           "estimator": "n-1 frames over the n-1 intervals between the first and last start timestamps"}
    if n < 2 or dur <= 0:
        out.update(pps=None, gbps=None, available=False)
        return out
    out.update(pps=(n - 1) / (dur / 1e9), gbps=float(wire[:-1].sum()) / dur, available=True)
    return out


def _clock_from_captures(side_a, side_b) -> str | None:
    """What the capture metadata says about the clocks, when the user did not say."""
    from .capture import _clock_words
    if not (side_a or side_b):
        return None
    parts = [f"{name}: {_clock_words(m) if m else 'unknown'}" for name, m in (("A", side_a), ("B", side_b))]
    return "; ".join(parts) + " (from capture metadata; offsets from the master do not show a constant bias)"


def _resolution(cap, sel) -> float | None:
    r = cap.res_ns if sel is None else cap.res_ns[sel]
    return float(np.nanmax(r)) if len(r) else None


def cmd_latency(args) -> int:
    os.makedirs(args.out, exist_ok=True)
    spec = KeySpec.parse(args.key)
    flt = PacketFilter(
        dst_ip=ipaddress.ip_address(args.dst_ip).packed if args.dst_ip else None,
        dst_port=args.dst_port, proto=args.proto)
    filt_txt = ", ".join(f"{k}={v}" for k, v in
                         (("dst_ip", args.dst_ip), ("dst_port", args.dst_port), ("proto", args.proto)) if v is not None)

    cap_a = read_capture(args.a)
    single_file = args.b is None
    if single_file:
        if args.iface_a is None or args.iface_b is None:
            print("error: with a single file, give --iface-a and --iface-b", file=sys.stderr)
            return 2
        cap_b = cap_a
        sel_a, sel_b = cap_a.iface == args.iface_a, cap_a.iface == args.iface_b
    else:
        cap_b = read_capture(args.b)
        sel_a = sel_b = None

    ka = packet_keys(cap_a, spec, flt, sel_a)
    kb = packet_keys(cap_b, spec, flt, sel_b)
    res = match(ka, kb, max_latency_ns=parse_duration(args.max_latency),
                max_negative_ns=parse_duration(args.allow_negative))
    lat = res.matched["latency_ns"].to_numpy()
    res.counts["skipped_a"] = ka.attrs.get("skipped", {})
    res.counts["skipped_b"] = kb.attrs.get("skipped", {})
    summary = summarize(lat, lost=res.counts["lost"], percentiles=args.percentiles,
                        min_tail=args.min_tail, late=res.counts["late_in_cohort"],
                        cohort_latency_ns=res.loss_aware_latencies())

    from .plot import ccdf_plot
    ccdf_png = "ccdf.png"
    ccdf_plot(lat, os.path.join(args.out, ccdf_png), summary["percentiles"], args.min_tail,
              title=f"One-way latency, CCDF ({args.label or 'A to B'})")

    import pyarrow as pa
    import pyarrow.parquet as pq
    pq.write_table(pa.Table.from_pandas(res.matched, preserve_index=False),
                   os.path.join(args.out, "latencies.parquet"), compression="zstd")

    files = [file_info(args.a, cap_a), file_info(args.b or args.a, cap_b)]
    if single_file:
        files[0]["file"] += f" (iface {args.iface_a})"
        files[1]["file"] += f" (iface {args.iface_b})"
    load = load_estimate(ka["ts_ns"].to_numpy(np.int64), ka["orig_len"].to_numpy(np.int64),
                         ka["fcs_bytes"].to_numpy())
    side_a = load_sidecar(args.a)
    side_b = None if single_file else load_sidecar(args.b)
    capture_issues = (sidecar_issues("A", side_a) + sidecar_issues("B", side_b)
                      + pair_issues(side_a, side_b))
    meta = {
        "label": args.label,
        "ts_source_a": args.ts_source_a or (side_a or {}).get("timestamp_source"),
        "ts_source_b": args.ts_source_b or (side_b or {}).get("timestamp_source"),
        "capture_a": side_a, "capture_b": side_b,
        "clock": args.clock or ("single device (stated with --same-clock)" if args.same_clock else None)
                 or _clock_from_captures(side_a, side_b),
        "clock_error_ns": parse_duration(args.clock_error) if args.clock_error else None,
        "same_clock": bool(args.same_clock), "single_file": single_file,
        "resolution_a_ns": _resolution(cap_a, sel_a), "resolution_b_ns": _resolution(cap_b, sel_b),
        "issues": ([f"A: {i}" for i in cap_a.issues] + ([] if single_file else [f"B: {i}" for i in cap_b.issues])
                   + capture_issues),
        "key": str(spec), "filter": filt_txt, "min_tail": args.min_tail,
        "versions": versions(),
    }
    md = latency_markdown(summary, meta, res.counts, files, load, ccdf_png)
    with open(os.path.join(args.out, "report.md"), "w") as f:
        f.write(md)
    write_json(os.path.join(args.out, "summary.json"),
               {"meta": meta, "files": files, "load": load, "counts": res.counts, "summary": summary})
    p = {r["percentile"]: r for r in summary["percentiles"]}
    print(f"matched {summary['samples']:,}, lost {summary['lost']:,}; "
          f"p50 {fmt_ns(p.get(50.0, {}).get('value_ns', float('nan')))}, "
          f"p99.99 {fmt_ns(p.get(99.99, {}).get('value_ns', float('nan')))}; report in {args.out}/report.md")
    return 0


def cmd_bursts(args) -> int:
    os.makedirs(args.out, exist_ok=True)
    cap = read_capture(args.file)
    sel = cap.iface == args.iface if args.iface is not None else np.ones(len(cap), dtype=bool)
    windows = [parse_duration(w) for w in args.windows.split(",")]
    fcs_in = np.ones(int(sel.sum()), dtype=bool) if args.fcs_included else cap.fcs_bytes[sel] > 0
    rows = burst_profile(cap.ts_ns[sel], cap.orig_len[sel], parse_rate(args.line_rate), windows,
                         fcs_in_capture=fcs_in, threshold=args.threshold,
                         resolution_ns=_resolution(cap, sel) or 1.0)
    issues = list(cap.issues)
    if sel.any() and (cap.linktype[sel] != 1).any():
        issues.append("some packets are not Ethernet frames; the wire-overhead formula assumes Ethernet")
    from .plot import burst_plot
    burst_plot(rows, os.path.join(args.out, "bursts.png"),
               title=f"Busiest window by time scale, {os.path.basename(args.file)} at {args.line_rate}")
    info = file_info(args.file, cap)
    meta = {"line_rate": args.line_rate, "threshold": args.threshold, "issues": issues}
    with open(os.path.join(args.out, "bursts.md"), "w") as f:
        f.write(bursts_markdown(rows, meta, info, "bursts.png"))
    write_json(os.path.join(args.out, "bursts.json"), {"file": info, "meta": meta, "windows": rows})
    for r in rows:
        if not r.get("applicable", True):
            print(f"{r['window']:>7}: longer than the capture")
            continue
        flag = "  (beyond line rate: fan-in)" if r.get("beyond_line_rate") else ""
        print(f"{r['window']:>7}: busiest window {100 * r['peak_utilization']:7.2f}% of line rate{flag}")
    if rows:
        print(f"average from first start to last finish: {100 * rows[0]['average_utilization']:.3f}%")
    for issue in issues:
        print(f"warning: {issue}")
    return 0


def cmd_doctor(args) -> int:
    from .capture import diagnose, inspect
    info = inspect(args.interface, args.ptp_uds, args.ptp_domain, args.samples)
    worst = "OK"
    for level, msg in diagnose(info):
        print(f"{level:5s} {msg}")
        if level == "FAIL" or (level == "WARN" and worst != "FAIL"):
            worst = level
    print()
    print("Capture command for this host, for example:")
    print(f"  sudo pcaplat capture -i {args.interface} -w a.pcap --filter 'udp and dst port 31001' --duration 60s")
    return 1 if worst == "FAIL" else 0


def cmd_capture(args) -> int:
    from .capture import run_capture, sidecar_path, sidecar_summary
    try:
        meta = run_capture(args.interface, args.write, bpf=args.filter,
                           duration_s=parse_duration(args.duration) / 1e9 if args.duration else None,
                           count=args.count, snaplen=args.snaplen, requested_tstamp=args.timestamp,
                           buffer_mb=args.buffer_mb, uds=args.ptp_uds, domain=args.ptp_domain)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"wrote {args.write} and {sidecar_path(args.write)}: {sidecar_summary(meta)}")
    for issue in sidecar_issues("this file", meta):
        print(f"warning: {issue}")
    if meta["status"] != "complete":
        print(f"error: the capture did not complete normally (exit code {meta['exit_code']}). "
              f"tcpdump said: {meta['stderr_tail'] or 'nothing'}", file=sys.stderr)
        return 1
    return 0


def cmd_synth(args) -> int:
    from .synth import generate
    t = generate(args.out, packets=args.packets, seed=args.seed, rate_pps=args.rate_pps)
    print(f"wrote {args.out}/a.pcap and b.pcap: {t['packets']:,} packet{'s' if t['packets'] != 1 else ''}, "
          f"{t['dropped']:,} dropped "
          f"({t['overflow_drops']:,} buffer overflow, {t['random_drops']:,} random)")
    return 0


def _ptp_args(s) -> None:
    s.add_argument("--ptp-uds", help="ptp4l management socket, when not the default /var/run/ptp4l")
    s.add_argument("--ptp-domain", type=int, help="PTP domain number, when not 0")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pcaplat", description="Two-point latency and burst analysis from packet captures.")
    p.add_argument("--version", action="version", version=f"pcaplat {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("info", help="summarize capture files")
    s.add_argument("files", nargs="+")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("latency", help="match packets between two capture points and report one-way latency")
    s.add_argument("a", help="capture at point A (or a pcapng holding both points)")
    s.add_argument("b", nargs="?", help="capture at point B (omit when A holds both interfaces)")
    s.add_argument("--iface-a", type=int, help="interface id of point A in a single pcapng")
    s.add_argument("--iface-b", type=int, help="interface id of point B in a single pcapng")
    s.add_argument("--out", default="pcaplat-report")
    s.add_argument("--key", default="l4payload", help="l4payload | frame | bytes:OFFSET:LENGTH")
    s.add_argument("--dst-ip")
    s.add_argument("--dst-port", type=int)
    s.add_argument("--proto", type=int, help="IP protocol number, e.g. 17 for UDP")
    s.add_argument("--max-latency", default="1ms", help="discard matches later than this (default 1ms)")
    s.add_argument("--allow-negative", default="0", help="keep negative latencies down to -this (clock offset)")
    s.add_argument("--percentiles", type=_percentiles, default="",
                   help="comma list between 0 and 100, default 50,90,99,99.9,99.99,99.999")
    s.add_argument("--min-tail", type=int, default=100, help="samples beyond a percentile to call it reliable")
    s.add_argument("--label", help="name of the path, e.g. 'feed handler NIC to order gateway NIC'")
    s.add_argument("--ts-source-a", help="e.g. 'optical tap + capture card, hardware'")
    s.add_argument("--ts-source-b")
    s.add_argument("--clock", help="e.g. 'PTP from grandmaster X, boundary clock Y'")
    s.add_argument("--clock-error", help="estimated clock error, e.g. 5ns")
    s.add_argument("--same-clock", action="store_true",
                   help="state that one device timestamped both points (not assumed from a single file)")
    s.set_defaults(func=cmd_latency)

    s = sub.add_parser("bursts", help="busiest windows at several time scales")
    s.add_argument("file")
    s.add_argument("--line-rate", required=True, help="e.g. 10G, 25G, 100G")
    s.add_argument("--windows", default="10us,100us,1ms,10ms,1s")
    s.add_argument("--threshold", type=float, default=0.9)
    s.add_argument("--fcs-included", action="store_true", help="captured lengths already include the FCS")
    s.add_argument("--iface", type=int)
    s.add_argument("--out", default="pcaplat-bursts")
    s.set_defaults(func=cmd_bursts)

    s = sub.add_parser("doctor", help="check that this host can capture with good timestamps")
    s.add_argument("interface", help="network interface to capture on, e.g. eth1")
    s.add_argument("--samples", type=_positive_int, default=5, help="PTP offset samples, half a second apart")
    _ptp_args(s)
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("capture", help="capture with tcpdump, the right options, and a metadata file")
    s.add_argument("-i", "--interface", required=True, help="network interface, e.g. eth1")
    s.add_argument("-w", "--write", required=True, help="output pcap file")
    s.add_argument("--filter", help="tcpdump filter, e.g. 'udp and dst port 31001'")
    s.add_argument("--duration", help="stop after this long, e.g. 60s or 300s (default: until Ctrl-C or --count)")
    s.add_argument("--count", type=_positive_int, help="stop after this many packets")
    s.add_argument("--snaplen", type=int, default=0, help="bytes kept per packet (default 0: whole packet)")
    s.add_argument("--timestamp", choices=("auto", "hardware", "host"), default="auto",
                   help="auto: NIC hardware clock when available, else host (default)")
    s.add_argument("--buffer-mb", type=_positive_int, default=256, help="kernel capture buffer (default 256 MB)")
    _ptp_args(s)
    s.set_defaults(func=cmd_capture)

    s = sub.add_parser("synth", help="write synthetic two-point captures with known latency")
    s.add_argument("--out", default="synthetic")
    s.add_argument("--packets", type=_positive_int, default=500_000)
    s.add_argument("--seed", type=int, default=7)
    s.add_argument("--rate-pps", type=float, default=2_000_000, help="average market-data rate at A")
    s.set_defaults(func=cmd_synth)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
