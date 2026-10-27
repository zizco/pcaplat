"""Capture on a production Linux host, and check that the host can do it well.

pcaplat does not capture packets itself: tcpdump does, as it already does in
production everywhere. This module picks the right tcpdump options
(nanosecond files, the NIC hardware clock when the NIC has one, a large
buffer), checks the host first, and writes a small JSON file next to each
capture that records how it was taken: interface, timestamp source, PTP state,
and the packets the capture path itself dropped. ``pcaplat latency`` reads
that file, so the report states the timestamp source and warns about capture
drops without anyone having to remember them.

Everything here shells out to standard tools (tcpdump, ethtool, pmc from
linuxptp) and parses their text output; the parsers are tested on recorded
outputs.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import time
from datetime import datetime, timezone

SIDECAR_SUFFIX = ".json"
SIDECAR_MARK = "pcaplat_capture"


# ---------------------------------------------------------------- running tools
def _text(x) -> str:
    """subprocess output as text: TimeoutExpired keeps bytes even with text=True."""
    if x is None:
        return ""
    return x.decode(errors="replace") if isinstance(x, bytes) else x


def run(cmd: list[str], timeout: float = 10.0) -> tuple[int, str]:
    """Run a command, return (exit code, stdout + stderr). 127 if not installed, 124 on timeout."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired as e:
        return 124, _text(e.stdout) + _text(e.stderr)
    return p.returncode, _text(p.stdout) + _text(p.stderr)


def _running(name: str) -> bool:
    """True if a process with this exact name is running (reads /proc, no procps needed)."""
    try:
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    with open(f"/proc/{pid}/comm") as f:
                        if f.read().strip() == name:
                            return True
                except OSError:
                    continue
    except OSError:
        pass
    return False


# ---------------------------------------------------------------- parsers
def parse_ethtool_ts(text: str) -> dict:
    """Parse ``ethtool -T IFACE`` (old and new ethtool formats)."""
    caps = set(re.findall(r"^\s+(hardware-receive|hardware-transmit|hardware-raw-clock|software-receive)\b",
                          text, re.M))
    phc = re.search(r"PTP Hardware Clock:\s*(\S+)", text)
    rx_modes = []
    m = re.search(r"Hardware Receive Filter Modes:(.*?)(?:\n\S|\Z)", text, re.S)
    if m:
        rx_modes = [w.split()[0] for w in m.group(1).strip().splitlines() if w.strip() and w.split()[0] != "none"]
    return {
        "hw_receive": "hardware-receive" in caps,
        "hw_raw_clock": "hardware-raw-clock" in caps,
        "phc": int(phc.group(1)) if phc and phc.group(1).isdigit() else None,
        "rx_filter_all": "all" in rx_modes,
        "rx_filters": rx_modes,
    }


def parse_tstamp_types(text: str) -> list[str]:
    """Parse ``tcpdump -J -i IFACE``: the timestamp types this interface offers."""
    return re.findall(r"^\s+([a-z_]+)\s+\(", text, re.M)


def parse_tcpdump_stats(text: str) -> dict:
    """Parse the statistics tcpdump prints when it stops."""
    out = {}
    for key, pat in (("captured", r"(\d+) packets? captured"),
                     ("received_by_filter", r"(\d+) packets? received by filter"),
                     ("dropped_by_kernel", r"(\d+) packets? dropped by kernel"),
                     ("dropped_by_interface", r"(\d+) packets? dropped by interface")):
        m = re.search(pat, text)
        if m:
            out[key] = int(m.group(1))
    return out


def parse_pmc_offset(text: str) -> float | None:
    """offsetFromMaster in ns from ``pmc -u -b 0 'GET CURRENT_DATA_SET'``, if ptp4l answered."""
    m = re.search(r"offsetFromMaster\s+(-?[\d.]+(?:e[-+]?\d+)?)", text)
    return float(m.group(1)) if m else None


def parse_pmc_ports(text: str) -> list[dict]:
    """Ports from ``pmc ... 'GET PORT_PROPERTIES_NP'`` (linuxptp 2.0 or later)."""
    return [{"state": st, "timestamping": ts, "interface": itf}
            for st, ts, itf in re.findall(r"portState\s+(\w+)\s+timestamping\s+(\w+)\s+interface\s+(\S+)", text)]


def parse_pmc_gm_present(text: str) -> bool | None:
    """gmPresent from ``pmc ... 'GET TIME_STATUS_NP'``."""
    m = re.search(r"gmPresent\s+(true|false)", text)
    return (m.group(1) == "true") if m else None


def parse_rx_usecs(text: str) -> int | None:
    """rx-usecs from ``ethtool -c IFACE`` (interrupt coalescing delay)."""
    m = re.search(r"^rx-usecs:\s*(\d+)", text, re.M)
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------- host checks
HW_TIMESTAMPING = {"HARDWARE", "ONESTEP", "P2P1STEP", "LEGACY_HW"}
SUB_US_OFFSET_NS = 100          # offset samples this small: sub-microsecond work is plausible
US_OFFSET_NS = 1_000


def ptp_status(phc: int | None = None, uds: str | None = None, domain: int | None = None,
               samples: int = 5, interval_s: float = 0.5) -> dict:
    """Is the clock /dev/ptp<phc> disciplined by ptp4l right now, and how closely?

    A running ptp4l proves nothing on its own. This asks ptp4l (through pmc)
    which interfaces its ports use and in which state, keeps the port whose
    NIC has this PHC, and requires: state SLAVE, hardware timestamping, a
    grandmaster present, and offset samples. ``synchronized`` is True only
    when all of that was seen, False when something contradicts it, and None
    when it could not be checked. Offsets from the master show variation
    only: a constant bias such as path asymmetry is invisible to them.
    """
    st = {"ptp4l_running": _running("ptp4l"), "phc2sys_running": _running("phc2sys"), "phc": phc,
          "port": None, "port_state": None, "port_timestamping": None, "gm_present": None,
          "offsets_ns": [], "max_abs_offset_ns": None, "synchronized": None, "reason": None}

    def done(value, reason):
        st["synchronized"], st["reason"] = value, reason
        return st

    if phc is None:
        return done(None, "the interface has no PTP hardware clock")
    if not st["ptp4l_running"]:
        return done(None, "no ptp4l process on this host")
    if not shutil.which("pmc"):
        return done(None, "pmc (linuxptp) is not installed, so ptp4l cannot be queried")
    base = ["pmc", "-u", "-b", "0"] + (["-s", uds] if uds else []) + (["-d", str(domain)] if domain is not None else [])
    _, out = run(base + ["GET PORT_PROPERTIES_NP"], timeout=5)
    ports = parse_pmc_ports(out)
    if not ports:
        return done(None, "ptp4l did not answer pmc (run as root; with several ptp4l instances or a non-zero "
                          "domain, pass --ptp-uds and --ptp-domain; linuxptp 2.0 or later is needed)")
    for port in ports:
        rc, eth = run(["ethtool", "-T", port["interface"]])
        port["phc"] = parse_ethtool_ts(eth)["phc"] if rc == 0 else None
    # Several ports can share one clock (a boundary clock: one SLAVE port
    # upstream, MASTER ports downstream). The clock is disciplined through its
    # hardware SLAVE port, whatever order pmc lists the ports in.
    mine = sorted((p for p in ports if p["phc"] == phc), key=lambda p: p["interface"])
    if not mine:
        used = ", ".join(f"{p['interface']} (/dev/ptp{p['phc']})" for p in ports)
        return done(False, f"the ptp4l instance queried does not use /dev/ptp{phc}; its ports: {used}")
    hw = [p for p in mine if p["timestamping"] in HW_TIMESTAMPING]
    if not hw:
        p = mine[0]
        st.update(port=p["interface"], port_state=p["state"], port_timestamping=p["timestamping"])
        return done(False, f"ptp4l runs on {p['interface']} with {p['timestamping']} timestamping, "
                           "so it does not discipline the NIC clock")
    slaves = [p for p in hw if p["state"] == "SLAVE"]
    if not slaves:
        states = ", ".join(f"{p['interface']} {p['state']}" for p in hw)
        p = hw[0]
        st.update(port=p["interface"], port_state=p["state"], port_timestamping=p["timestamping"])
        return done(False, f"no ptp4l port on /dev/ptp{phc} is SLAVE ({states}): this clock is not following a master")
    port = slaves[0]
    st.update(port=port["interface"], port_state=port["state"], port_timestamping=port["timestamping"])
    _, out = run(base + ["GET TIME_STATUS_NP"], timeout=5)
    st["gm_present"] = parse_pmc_gm_present(out)
    if st["gm_present"] is None:
        return done(None, "ptp4l did not report whether a grandmaster is present (no TIME_STATUS_NP answer)")
    if st["gm_present"] is False:
        return done(False, "ptp4l reports no grandmaster present")
    for i in range(max(1, samples)):
        _, out = run(base + ["GET CURRENT_DATA_SET"], timeout=5)
        off = parse_pmc_offset(out)
        if off is not None:
            st["offsets_ns"].append(off)
        if i + 1 < samples:
            time.sleep(interval_s)
    if not st["offsets_ns"]:
        return done(None, "ptp4l gave no offset from its master")
    st["max_abs_offset_ns"] = max(abs(o) for o in st["offsets_ns"])
    return done(True, None)


def inspect(iface: str, uds: str | None = None, domain: int | None = None, samples: int = 5) -> dict:
    """Everything doctor and capture need to know about one interface."""
    info: dict = {"interface": iface, "root": os.geteuid() == 0}
    rc, out = run(["tcpdump", "--version"])
    info["tcpdump"] = out.splitlines()[0] if rc != 127 and out else None
    rc, out = run(["tcpdump", "-J", "-i", iface])
    info["tstamp_types"] = parse_tstamp_types(out) if rc == 0 else []
    info["tstamp_types_error"] = None if rc == 0 or rc == 127 else out.strip()
    rc, out = run(["ethtool", "-T", iface])
    info["ethtool"] = parse_ethtool_ts(out) if rc == 0 else None
    rc, out = run(["ethtool", "-c", iface])
    info["rx_usecs"] = parse_rx_usecs(out) if rc == 0 else None
    phc = (info["ethtool"] or {}).get("phc")
    info["ptp"] = ptp_status(phc, uds, domain, samples)
    return info


def clock_verdict(ptp: dict | None) -> tuple[str, str]:
    """(level, text) on the NIC clock's synchronization, from ptp_status()."""
    ptp = ptp or {}
    sync, worst = ptp.get("synchronized"), ptp.get("max_abs_offset_ns")
    if sync is True and worst is not None:
        n = len(ptp.get("offsets_ns") or [])
        text = (f"ptp4l disciplines this NIC clock: port {ptp.get('port')} is SLAVE with hardware timestamping; "
                f"offset from master up to {worst:.0f} ns over {n} sample{'s' if n != 1 else ''}")
        if worst <= SUB_US_OFFSET_NS:
            return "OK", text + "."
        if worst <= US_OFFSET_NS:
            return "WARN", text + ": microsecond-level, not sub-microsecond."
        return "WARN", text + ": too far from the master for latency work until it settles."
    if sync is False:
        return "WARN", f"this NIC clock is not PTP-synchronized: {ptp.get('reason')}."
    return "WARN", f"PTP synchronization of this NIC clock is not verified: {ptp.get('reason') or 'no evidence'}."


def diagnose(info: dict) -> list[tuple[str, str]]:
    """(level, message) lines for ``pcaplat doctor``. Levels: OK, WARN, FAIL, INFO."""
    out: list[tuple[str, str]] = []
    iface = info["interface"]
    if not info.get("tcpdump"):
        out.append(("FAIL", "tcpdump is not installed (Debian/Ubuntu: apt install tcpdump; RHEL: dnf install tcpdump)."))
    else:
        out.append(("OK", info["tcpdump"]))
    if not info.get("root"):
        out.append(("WARN", "not running as root: capturing, enabling NIC hardware timestamps and querying ptp4l "
                            "need root, or CAP_NET_RAW + CAP_NET_ADMIN."))
    eth = info.get("ethtool")
    hw = "adapter_unsynced" in (info.get("tstamp_types") or [])
    if eth is None:
        out.append(("WARN", f"ethtool -T {iface} failed or ethtool is missing: cannot check hardware timestamping."))
    elif eth["hw_receive"] and eth["hw_raw_clock"]:
        phc = f"/dev/ptp{eth['phc']}" if eth["phc"] is not None else "unknown"
        out.append(("OK", f"{iface} timestamps received packets in hardware (PTP hardware clock {phc})."))
        if not eth["rx_filter_all"]:
            out.append(("WARN", f"{iface} offers no 'all' receive filter (only {', '.join(eth['rx_filters']) or 'none'}): "
                                "it may timestamp PTP packets only. Check the NIC documentation."))
    else:
        out.append(("WARN", f"{iface} has no hardware receive timestamps: the kernel will timestamp packets in "
                            "software, after the NIC and the interrupt path."))
    if info.get("tstamp_types_error"):
        out.append(("WARN", f"tcpdump -J -i {iface}: {info['tstamp_types_error']}"))
    elif info.get("tcpdump"):
        out.append(("OK" if hw else "INFO",
                    f"tcpdump timestamp types on {iface}: {', '.join(info.get('tstamp_types') or []) or 'none listed'}"
                    + ("" if hw else " (no hardware type: captures will use host timestamps)")))
    if not hw and info.get("rx_usecs"):
        out.append(("WARN", f"interrupt coalescing rx-usecs = {info['rx_usecs']} on {iface}: software timestamps "
                            f"can be up to about {info['rx_usecs']} us late. For a test, "
                            f"'ethtool -C {iface} rx-usecs 0' removes it, at a CPU cost."))
    ptp = info.get("ptp") or {}
    if hw:
        level, text = clock_verdict(ptp)
        out.append((level, text))
        if ptp.get("synchronized") is True and (ptp.get("max_abs_offset_ns") or 0) <= SUB_US_OFFSET_NS:
            verdict = ("hardware timestamps on a NIC clock that ptp4l keeps close to its master. Sub-microsecond "
                       "work is possible. These offsets show variation only: a constant bias, such as path "
                       "asymmetry, is invisible here and must be bounded separately (docs/MEASURING.md, section 3).")
        elif ptp.get("synchronized") is True:
            verdict = "hardware timestamps, but the clock is not close enough to its master for sub-microsecond work."
        else:
            verdict = ("hardware timestamps, synchronization not verified: no accuracy claim between two hosts. "
                       "Two points captured on this one NIC clock remain comparable.")
    else:
        out.append(("INFO", "Host timestamps follow the system clock (NTP, chrony, or PTP through phc2sys); "
                            "pcaplat does not verify it. Check your time daemon, e.g. 'chronyc tracking'."))
        verdict = "software timestamps. Fine for millisecond-scale questions; do not read differences of a few microseconds."
    out.append(("INFO", "Verdict: " + verdict))
    return out


# ---------------------------------------------------------------- capture
def choose_tstamp(requested: str, types: list[str]) -> tuple[str, str | None]:
    """Return (tcpdump -j value, warning). requested: auto | hardware | host."""
    if requested == "host":
        return "host", None
    if "adapter_unsynced" in types:
        return "adapter_unsynced", None
    if requested == "hardware":
        raise RuntimeError("this interface offers no hardware timestamps to tcpdump (see pcaplat doctor)")
    return "host", "no hardware timestamps on this interface: falling back to host (software) timestamps"


def build_command(iface: str, out: str, tstamp: str, snaplen: int = 0, buffer_mb: int = 256,
                  count: int | None = None, bpf: str | None = None, as_root: bool = False) -> list[str]:
    cmd = ["tcpdump", "-i", iface, "-n", "-s", str(snaplen), "-B", str(buffer_mb * 1024),
           "--time-stamp-precision=nano", "-w", out]
    if tstamp != "host":                 # host is tcpdump's default; some drivers refuse an explicit -j
        cmd += ["-j", tstamp]
    if count:
        cmd += ["-c", str(count)]
    if as_root:
        cmd += ["-Z", "root"]            # keep root, so tcpdump can write wherever we were asked to
    if bpf:
        cmd.append(bpf)
    return cmd


def sidecar_path(capture_path: str) -> str:
    return capture_path + SIDECAR_SUFFIX


def load_sidecar(capture_path: str) -> dict | None:
    """The metadata pcaplat capture wrote next to a capture file, if any."""
    import json
    p = sidecar_path(capture_path)
    try:
        with open(p) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get(SIDECAR_MARK) else None


def timestamp_source(tstamp: str, info: dict) -> str:
    if tstamp == "adapter_unsynced":
        phc = (info.get("ethtool") or {}).get("phc")
        return ("NIC hardware clock" + (f" (/dev/ptp{phc})" if phc is not None else "")
                + f" on {socket.gethostname()}:{info['interface']}")
    return f"host software clock (kernel) on {socket.gethostname()}:{info['interface']}"


def run_capture(iface: str, out: str, bpf: str | None = None, duration_s: float | None = None,
                count: int | None = None, snaplen: int = 0, requested_tstamp: str = "auto",
                buffer_mb: int = 256, echo=print, uds: str | None = None, domain: int | None = None) -> dict:
    """Capture with tcpdump and write the sidecar, whatever happens. Returns the sidecar.

    ``status`` is "complete" only when tcpdump exited normally: on its own
    (``count`` reached) or after the SIGINT this function sent at the end of
    ``duration_s`` or on Ctrl-C. Any other exit is "failed", a tcpdump that
    had to be killed is "killed", and the sidecar keeps the exit code and
    the end of tcpdump's error output.
    """
    from .report import NONFINITE_BASE, write_json
    info = inspect(iface, uds, domain, samples=3)
    if not info["tcpdump"]:
        raise RuntimeError("tcpdump is not installed")
    tstamp, warning = choose_tstamp(requested_tstamp, info["tstamp_types"])
    if warning:
        echo(f"warning: {warning}")
    cmd = build_command(iface, out, tstamp, snaplen, buffer_mb, count, bpf, info["root"])
    echo("running: " + shlex.join(cmd))
    started = datetime.now(timezone.utc)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    requested_stop = False
    try:
        proc.wait(timeout=duration_s)
    except subprocess.TimeoutExpired:
        requested_stop = True
        proc.send_signal(signal.SIGINT)                  # tcpdump prints its statistics on SIGINT
    except KeyboardInterrupt:
        requested_stop = True
        proc.send_signal(signal.SIGINT)
    killed = False
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        killed = True
    stopped = datetime.now(timezone.utc)
    err = _text(proc.stderr.read()) if proc.stderr else ""
    rc = proc.returncode
    if killed:
        status = "killed"
    elif rc == 0 or (requested_stop and rc in (-signal.SIGINT, 128 + signal.SIGINT)):
        status = "complete"
    else:
        status = "failed"
    ptp_end = ptp_status((info.get("ethtool") or {}).get("phc"), uds, domain, samples=3) \
        if tstamp == "adapter_unsynced" else None
    meta = {
        SIDECAR_MARK: 1,
        "status": status,
        "exit_code": rc,
        "stderr_tail": "\n".join(err.strip().splitlines()[-20:]),
        "file": os.path.basename(out),
        "host": socket.gethostname(),
        "interface": iface,
        "timestamp_type": tstamp,
        "timestamp_source": timestamp_source(tstamp, info),
        "precision": "nanosecond file",
        "snaplen": snaplen or "tcpdump default (full packets)",
        "filter": bpf or "",
        "command": cmd,
        "started_utc": started.isoformat(timespec="seconds"),
        "stopped_utc": stopped.isoformat(timespec="seconds"),
        "tcpdump_stats": parse_tcpdump_stats(err),
        "ptp": info["ptp"],
        "ptp_end": ptp_end,
        "rx_usecs": info["rx_usecs"],
        "tcpdump_version": info["tcpdump"],
    }
    write_json(sidecar_path(out), meta, note=NONFINITE_BASE)     # no percentile rows here
    return meta


def _clock_words(meta: dict) -> str:
    if meta.get("timestamp_type") != "adapter_unsynced":
        return "system clock, not verified by pcaplat"
    ptp = meta.get("ptp") or {}
    if ptp.get("synchronized") is True:
        return f"PTP verified, offset samples up to {ptp.get('max_abs_offset_ns', 0):.0f} ns"
    if ptp.get("synchronized") is False:
        return "NIC clock not PTP-synchronized"
    return "PTP synchronization not verified"


def sidecar_summary(meta: dict) -> str:
    st = meta.get("tcpdump_stats", {})
    drops = st.get("dropped_by_kernel", 0) + st.get("dropped_by_interface", 0)
    return (f"{meta.get('timestamp_source')}; {_clock_words(meta)}; {st.get('captured', '?')} captured, "
            f"{drops} dropped by the capture path; capture {meta.get('status', 'complete')}")


def sidecar_issues(name: str, meta: dict | None) -> list[str]:
    """CHECK lines for the latency report, from one capture's sidecar."""
    if not meta:
        return []
    out = []
    status = meta.get("status", "complete")
    if status != "complete":
        tail = (meta.get("stderr_tail") or "").strip().splitlines()
        why = f": {tail[0]}" if tail else ""
        out.append(f"capture {name} did not complete normally (status {status}, tcpdump exit code "
                   f"{meta.get('exit_code')}){why}. The file may be partial.")
    st = meta.get("tcpdump_stats", {})
    drops = st.get("dropped_by_kernel", 0) + st.get("dropped_by_interface", 0)
    if drops:
        out.append(f"capture {name} dropped {drops:,} packets in the capture path itself (tcpdump statistics): "
                   f"up to that many 'lost' packets may be capture losses, not network losses. Use a larger "
                   f"--buffer-mb, a tighter --filter, or a capture card.")
    if meta.get("timestamp_type") == "host" and meta.get("rx_usecs"):
        out.append(f"capture {name} used software timestamps with interrupt coalescing rx-usecs = "
                   f"{meta['rx_usecs']}: timestamps can be up to about {meta['rx_usecs']} us late.")
    if meta.get("timestamp_type") == "adapter_unsynced":
        for when, ptp in (("start", meta.get("ptp")), ("end", meta.get("ptp_end"))):
            if ptp is None:
                continue
            level, text = clock_verdict(ptp)
            if level != "OK":
                out.append(f"capture {name}, at the {when} of the capture: {text} Unless both points were captured "
                           f"on that same clock, the clock error between A and B is unknown.")
    return out


def pair_issues(meta_a: dict | None, meta_b: dict | None) -> list[str]:
    if not (meta_a and meta_b):
        return []
    out = []
    if meta_a.get("timestamp_type") != meta_b.get("timestamp_type"):
        out.append(f"A and B were captured with different timestamp types ({meta_a.get('timestamp_type')} and "
                   f"{meta_b.get('timestamp_type')}). A PTP-disciplined NIC clock usually runs on TAI, 37 s "
                   f"ahead of the UTC system clock: use the same type at both points.")
    return out
